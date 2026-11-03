"""SOC Orchestrator — the entry point for every alert."""
from __future__ import annotations

import json
import logging
import math
from pathlib import Path
from typing import Any, Optional

from ..api_abuse.agent import APIAbuseAgent
from ..auth.agent import AuthAgent
from ..cloud_controlplane.agent import CloudControlPlaneAgent
from ..deception.honeytoken_monitor import HoneytokenMonitor
from .control_plane import control_plane_chain, is_control_plane_fact
from ..dlp.agent import DLPAgent
from ..edr.agent import EDRAgent
from ..email.agent import EmailAgent
from ..mobile.agent import MobileAgent
from ..perimeter.agent import PerimeterAgent
from ..transaction.agent import TransactionAgent
from ..wireless.agent import WirelessAgent
from ..shared.targets import resolve_action_targets
from .adaptive import adaptive_attacker_chain, is_adaptive_attacker
from .auth_abuse import auth_burst_chain, is_auth_burst
from .low_and_slow import is_low_and_slow, low_and_slow_chain
from .bola import is_object_walk, object_walk_chain
from .egress import egress_chain, is_egress_finding
from .model_pull import is_dealigned_model_pull, model_pull_chain
from .netops import is_network_fault, network_fault_chain
from .privileged import is_privileged_event, privileged_chain
from .treasury import is_treasury_outflow, treasury_outflow_chain
from .spoofed_client import is_spoofed_client, spoofed_client_chain
from .host_endpoint import host_route
from .pxe_firmware import is_pxe_firmware_finding, pxe_firmware_chain
from ..shared.audit import AuditLog
from ..shared.evidence_chain import (
    EvidenceChain,
    EvidenceItem,
    ReasoningStep,
    RecommendedAction,
)
from ..shared.injection_defense import SYSTEM_PROMPT_PREAMBLE, wrap_untrusted
from ..shared.llm_client import LLMClient, complete_for_json, parse_json
from .voting import vote_best
from ...dataset import capture as dataset_capture


logger = logging.getLogger("aegis.orchestrator")

_SYSTEM_PROMPT_FILE = Path(__file__).parent / "system_prompt.md"


def _build_system_prompt() -> str:
    return SYSTEM_PROMPT_PREAMBLE + "\n\n" + _SYSTEM_PROMPT_FILE.read_text(encoding="utf-8")


_VERDICT_LABELS = ("benign", "suspicious", "malicious", "uncertain")
_NEXT_BY_VERDICT = {"auto_close": "benign", "respond": "malicious"}


def guard_triage(triage: dict) -> dict:
    """Refuse the triage shortcuts when the triage answer cannot be trusted.

    ``auto_close`` (close with no specialist) and ``respond`` (act with no specialist / voter) skip every
    later check, so they are refused when the alert carried prompt-injection text — the answer may be the
    attacker's — and ``auto_close`` is refused while the mock LLM is standing in for a real one."""
    from ..shared.llm_client import mock_fallback_active
    md = dict(triage.get("_triage_metadata") or {})
    nxt = triage.get("next")
    why = ""
    if nxt == "auto_close" and mock_fallback_active():
        why = "no real LLM configured — the mock's auto-close is not trusted"
    elif md.get("injection_detected") and nxt in ("auto_close", "respond"):
        why = f"prompt-injection patterns in the alert ({', '.join(md.get('injection_patterns', [])[:3])})"
    if not why:
        return triage
    md["overridden"] = f"{nxt} → dispatch_perimeter ({why})"
    return {**triage, "next": "dispatch_perimeter", "reason": f"{why}; triage shortcut refused, investigating",
            "_triage_metadata": md}


def _normalise_triage(decision: dict) -> dict:
    """Make a live model's triage JSON safe to act on.

    Measured on the historical eval with a live model (2026-10-21): the
    model routinely put its one-sentence rationale in ``verdict`` and left
    ``reason`` out ("verdict": "Low-severity F5 ASM alert, internal IP …").
    ``EvidenceChain`` then coerced that sentence to ``uncertain`` — every
    clearly-benign alert escalated to a human and the eval counted a miss.
    Here a non-label ``verdict`` becomes the ``reason`` and the verdict is
    what the routing decision already implies (``auto_close`` → benign,
    ``respond`` → malicious); an unknown ``next`` falls back to the
    perimeter specialist (investigate rather than close-and-miss).
    """
    if not isinstance(decision, dict):
        return {"next": "dispatch_perimeter", "reason": "Triage returned a non-object; investigating"}
    nxt = str(decision.get("next") or "").strip().lower()
    verdict = decision.get("verdict")
    label = str(verdict).strip().lower() if isinstance(verdict, str) else ""
    if verdict is not None and label not in _VERDICT_LABELS:
        if not decision.get("reason") and isinstance(verdict, str) and verdict.strip():
            decision["reason"] = verdict.strip()
        decision.pop("verdict", None)
        label = ""
    if nxt in _NEXT_BY_VERDICT and not label:
        decision["verdict"] = _NEXT_BY_VERDICT[nxt]
    elif label:
        decision["verdict"] = label
    if nxt and not (nxt == "auto_close" or nxt == "respond" or nxt.startswith("dispatch_")):
        decision["reason"] = f"Unknown triage step {nxt!r}: {decision.get('reason', '')}".strip()
        decision["next"] = "dispatch_perimeter"
    elif not nxt:
        decision["next"] = "dispatch_perimeter"
        decision.setdefault("reason", "Triage gave no next step; investigating")
    try:
        c = float(decision.get("confidence"))
        if not math.isfinite(c):
            raise ValueError("non-finite")           # max(0, min(1, nan)) is 1.0 (review round 4 O4-10)
        decision["confidence"] = max(0.0, min(1.0, c))
    except (TypeError, ValueError):
        decision.pop("confidence", None)
    return decision



_SCAN_CHUNK, _SCAN_MAX = 200_000, 4_000_000


def _alert_carries_injection(alert: Any) -> bool:
    """Injection text or hidden / bidi characters anywhere in the alert. It used to read only the first 200 KB
    and only ``injection_detected``: an RLO file name (``invoice\u202etxt.exe``) or text after 200 KB of padding
    left the host-route (Sysmon → EDR) chain unflagged (review round 4 O4-7). An alert too large to scan whole
    counts as flagged."""
    try:
        text = json.dumps(alert, default=str)
    except Exception:  # noqa: BLE001
        return True
    if len(text) > _SCAN_MAX:
        return True
    for i in range(0, max(1, len(text)), _SCAN_CHUNK - 2_000):        # overlapping windows: no phrase split
        try:
            w = wrap_untrusted("alert", text[i:i + _SCAN_CHUNK])
        except Exception:  # noqa: BLE001 — a scan that cannot run is not a clean scan
            return True
        if w.injection_detected or w.obfuscation_findings:
            return True
    return False


def _carry_injection(chain: Any, alert: dict, triage: dict) -> None:
    """Every chain says whether its alert carried prompt-injection text. Only three specialists recorded
    injection evidence, and triage's flag never reached a specialist's chain, so `injection_flagged()` — the
    "nothing unattended" check — was blind for the other nine (review round 3 G1-4)."""
    tm = triage.get("_triage_metadata") if isinstance(triage, dict) else None
    flagged = bool(isinstance(tm, dict) and (tm.get("injection_detected") or tm.get("obfuscation_findings")))
    if not flagged:
        flagged = _alert_carries_injection(alert)
    if flagged:
        md = chain.metadata
        md["injection_detected"] = True
        md.setdefault("_triage_metadata", {}).update({"injection_detected": True})

def _auto_close_context(alert: Any, triage: dict) -> str:
    """What the reviewer needs to judge an auto-close: there is no specialist evidence, so it sees the alert
    (redacted, inside the untrusted wrapper) and triage's own reason (review round 4 O4-4)."""
    from ..shared.redact import redact
    try:
        body = json.dumps(redact(alert), default=str)
    except Exception:  # noqa: BLE001
        body = "(alert could not be serialised)"
    if len(body) > 6000:
        body = body[:3000] + " … " + body[-2900:]
    return f"triage reason: {str(triage.get('reason', ''))[:300]} | alert: {body}"


class SOCOrchestrator:
    name = "soc_orchestrator"

    def __init__(
        self,
        primary_llm: LLMClient,
        voter_llm: LLMClient,
        perimeter: PerimeterAgent,
        honeytoken: HoneytokenMonitor,
        audit: AuditLog,
        auth: Optional[AuthAgent] = None,
        edr: Optional[EDRAgent] = None,
        api_abuse: Optional[APIAbuseAgent] = None,
        transaction: Optional[TransactionAgent] = None,
        cloud_controlplane: Optional[CloudControlPlaneAgent] = None,
        dlp: Optional[DLPAgent] = None,
        email: Optional[EmailAgent] = None,
        mobile: Optional[MobileAgent] = None,
        wireless: Optional[WirelessAgent] = None,
        extra_voters: Optional[list[LLMClient]] = None,
    ):
        self._primary = primary_llm
        self._voter = voter_llm
        # Extra reviewers (ideally different model families) beyond the primary
        # voter. The full panel is built live at vote time as [self._voter, *extras]
        # so a voter swapped in after construction (tests, fault injection) is
        # honored. vote_best() runs the ensemble only when AEGIS_ENSEMBLE_VOTE is on
        # and >=2 live voters remain; otherwise the single-voter path runs.
        self._extra_voters = [v for v in list(extra_voters or []) if v is not None]
        self._perimeter = perimeter
        self._auth = auth
        self._edr = edr
        self._api_abuse = api_abuse
        self._transaction = transaction
        self._cloud_controlplane = cloud_controlplane
        self._dlp = dlp
        self._email = email
        self._mobile = mobile
        self._wireless = wireless
        self._honeytoken = honeytoken
        self._audit = audit
        self._system = _build_system_prompt()

    def is_fast_path(self, alert: dict) -> bool:
        """True when ``handle()`` would reach a verdict deterministically (no model call). The service uses this
        in storm mode: fast paths keep flowing at full speed, model-bound alerts are deferred, not dropped."""
        try:
            return bool(self._honeytoken.alert_touches_decoy(alert) or is_control_plane_fact(alert) or is_network_fault(alert)
                        or is_privileged_event(alert) or is_treasury_outflow(alert) or is_adaptive_attacker(alert)
                        or is_low_and_slow(alert) or is_object_walk(alert) or is_dealigned_model_pull(alert)
                        or is_egress_finding(alert) or is_pxe_firmware_finding(alert) or is_auth_burst(alert) or is_spoofed_client(alert))
        except Exception:  # noqa: BLE001 — a predicate that chokes on an odd alert means "not a fast path"
            return False

    def handle(self, alert: dict) -> EvidenceChain:
        from ..shared import observability as obs

        from .walkers.campaign import ORCH_DERIVED_KEYS, TRUSTED_CONTEXT
        if isinstance(alert, dict) and any(k in alert for k in ORCH_DERIVED_KEYS) and TRUSTED_CONTEXT.get() is not alert:
            # campaign_context / tls_client are AEGIS's own findings; on an alert that did not just come through the
            # swarm's attach step they were written by the sender (forged retry_ips became unattended blocks)
            alert = {k: v for k, v in alert.items() if k not in ORCH_DERIVED_KEYS}
        with obs.span("aegis.orchestrator.handle", alert_id=alert.get("id", "?")) as sp:
            try:
                chain = self._route(alert, sp)
            except Exception as exc:  # noqa: BLE001 — an LLM / specialist outage, or a fast-path builder choking on an
                chain = self._degraded_chain(alert, exc)   # odd alert shape, must not drop the alert: it gets an uncertain chain + HITL
                sp.attributes["specialist"] = "degraded"
                sp.attributes["verdict"] = chain.verdict
            return self.record(alert, chain)

    def _route(self, alert: dict, sp: Any) -> EvidenceChain:
        """Fast paths first (deterministic builders), then the LLM-backed inner pipeline."""
        from ..shared import observability as obs
        if True:
            # Fast-path: honeytoken bypass.
            if self._honeytoken.alert_touches_decoy(alert):
                chain = self._honeytoken.build_chain(alert)
                obs.record_alert_processed("deception")
                obs.record_verdict(chain.verdict, "deception")
                sp.attributes["specialist"] = "deception"
                sp.attributes["verdict"] = chain.verdict
            # Fast-path: ACP control-plane facts (Q37 block, pause, CRITICAL rogue) — no LLM verdict needed.
            elif is_control_plane_fact(alert):
                chain = control_plane_chain(alert)
                obs.record_alert_processed("control_plane")
                obs.record_verdict(chain.verdict, "control_plane")
                sp.attributes["specialist"] = "control_plane"
                sp.attributes["verdict"] = chain.verdict
            # Fast-path: one network root cause from the assurance detector (link down with its downstream
            # folded in, flap, adjacency loss, bad config push, drift, errors, congestion, silent device).
            elif is_network_fault(alert):
                chain = network_fault_chain(alert)
                obs.record_alert_processed("netops")
                obs.record_verdict(chain.verdict, "netops")
                sp.attributes["specialist"] = "netops"
                sp.attributes["verdict"] = chain.verdict
            # Fast-path: an engineer with production reach, or a crown jewel they can touch (DevOps laptop
            # compromise, interactive access to the payment signer, a signer policy change).
            elif is_privileged_event(alert):
                chain = privileged_chain(alert)
                obs.record_alert_processed("privileged")
                obs.record_verdict(chain.verdict, "privileged")
                sp.attributes["specialist"] = "privileged"
                sp.attributes["verdict"] = chain.verdict
            # Fast-path: a high-value transfer to a new beneficiary, and the burst that is a drain.
            elif is_treasury_outflow(alert):
                chain = treasury_outflow_chain(alert)
                obs.record_alert_processed("treasury")
                obs.record_verdict(chain.verdict, "treasury")
                sp.attributes["specialist"] = "treasury"
                sp.attributes["verdict"] = chain.verdict
            # Fast-path: a client that retries at machine speed after every stop (campaign context).
            elif is_adaptive_attacker(alert):
                chain = adaptive_attacker_chain(alert)
                obs.record_alert_processed("adaptive_attacker")
                obs.record_verdict(chain.verdict, "adaptive_attacker")
                sp.attributes["specialist"] = "adaptive_attacker"
                sp.attributes["verdict"] = chain.verdict
            # Fast-path: one client mutating against a single endpoint, low and slow (campaign context).
            elif is_low_and_slow(alert):
                chain = low_and_slow_chain(alert)
                obs.record_alert_processed("low_and_slow")
                obs.record_verdict(chain.verdict, "low_and_slow")
                sp.attributes["specialist"] = "low_and_slow"
                sp.attributes["verdict"] = chain.verdict
            # Fast-path: an object-walk (BOLA) alert from the API-gateway detector.
            elif is_object_walk(alert):
                chain = object_walk_chain(alert)
                obs.record_alert_processed("object_walk")
                obs.record_verdict(chain.verdict, "object_walk")
                sp.attributes["specialist"] = "object_walk"
                sp.attributes["verdict"] = chain.verdict
            # Fast-path: a web-proxy record of an "uncensored" / abliterated model pulled from Hugging Face.
            elif is_dealigned_model_pull(alert):
                chain = model_pull_chain(alert)
                obs.record_alert_processed("model_pull")
                obs.record_verdict(chain.verdict, "model_pull")
                sp.attributes["specialist"] = "model_pull"
                sp.attributes["verdict"] = chain.verdict
            # Fast-path: an egress finding from the network sensor (beacon, exfiltration, known-bad TLS, shadow AI).
            elif is_egress_finding(alert):
                chain = egress_chain(alert)
                obs.record_alert_processed("egress")
                obs.record_verdict(chain.verdict, "egress")
                sp.attributes["specialist"] = "egress"
                sp.attributes["verdict"] = chain.verdict
            # Fast-path: hostile ICMP during a PXE network boot (CVE-2026-97631 firmware vector).
            elif is_pxe_firmware_finding(alert):
                chain = pxe_firmware_chain(alert)
                obs.record_alert_processed("pxe_firmware")
                obs.record_verdict(chain.verdict, "pxe_firmware")
                sp.attributes["specialist"] = "pxe_firmware"
                sp.attributes["verdict"] = chain.verdict
            # Fast-path: one client submitting an auth form at machine rate (credential stuffing).
            elif is_auth_burst(alert):
                chain = auth_burst_chain(alert)
                obs.record_alert_processed("auth_burst")
                obs.record_verdict(chain.verdict, "auth_burst")
                sp.attributes["specialist"] = "auth_burst"
                sp.attributes["verdict"] = chain.verdict
            # Fast-path: automation claiming to be a browser its TLS handshake cannot be, attacking or logging in.
            elif is_spoofed_client(alert):
                chain = spoofed_client_chain(alert)
                obs.record_alert_processed("spoofed_client")
                obs.record_verdict(chain.verdict, "spoofed_client")
                sp.attributes["specialist"] = "spoofed_client"
                sp.attributes["verdict"] = chain.verdict
            else:
                return self._handle_inner(alert, sp)
            # A deterministic builder decided this, with no model in the loop, so there is no vote to take.
            # Autonomy and the outflow breaker require `vote_concur is True` OR this marker (review round 3 G1-15:
            # a missing vote used to count as consent for any chain).
            chain.metadata["deterministic"] = True
            return chain

    def _degraded_chain(self, alert: dict, exc: Exception) -> EvidenceChain:
        """When the brain cannot run (LLM outage, specialist crash) the alert still reaches a
        human: verdict ``uncertain``, confidence 0, one ``escalate`` action under HITL, and the
        failure recorded in the chain + log. Nothing is auto-closed on a broken model."""
        logger.error("[orchestrator] alert %s could not be investigated (%s: %s); escalating as uncertain",
                     alert.get("id", "?"), type(exc).__name__, str(exc)[:200], exc_info=True)
        chain = EvidenceChain(alert_id=str(alert.get("id", "unknown")), investigated_by="orchestrator",
                              verdict="uncertain", confidence=0.0)
        chain.reasoning.append(ReasoningStep(step=1, action="Investigate",
                                             observation=f"DEGRADED: {type(exc).__name__}: {str(exc)[:200]}"))
        chain.recommended_actions.append(RecommendedAction(
            action_type="escalate", target=str(alert.get("id", "unknown")),
            reasoning="Automated investigation failed; a human must triage this alert", requires_hitl=True, confidence=0.0))
        chain.metadata["degraded"] = {"error": f"{type(exc).__name__}: {str(exc)[:200]}"}
        return chain.finalize()

    def record(self, alert: dict, chain: EvidenceChain) -> EvidenceChain:
        """Seal a chain: attach the scrubbed alert snapshot (dataset capture,
        roadmap 3.2) and append it to the hash-chained audit log. The swarm
        calls this again after enrichment, so the persisted chain is the one
        the ResponseAgent acted on. Symbolic action targets (``block -> source_ip``) are
        resolved to the alert's values first, so the audit row, the HITL card and the
        connector all carry the same concrete target."""
        try:
            resolve_action_targets(chain, alert)
        except Exception as e:  # noqa: BLE001 — an unresolved target parks for a human; never drop the chain
            logger.warning("[orchestrator] target resolution failed for %s: %s", chain.alert_id, str(e)[:120])
        dataset_capture.attach(chain, alert)
        return self._audit.append(chain)

    def _handle_inner(self, alert: dict, span_record) -> EvidenceChain:
        from ..shared import observability as obs

        # Deterministic route: host/endpoint telemetry (Sysmon / osquery, or the host
        # scorers' own signal fields) goes to the EDR specialist without spending an LLM
        # triage call. The verdict + independent-voter check still run below.
        deterministic = host_route(alert, self._edr is not None)
        if deterministic:
            triage = {"next": deterministic,
                      "reason": "Host/endpoint telemetry routed to EDR specialist",
                      "_triage_metadata": {"route": "deterministic:host_endpoint"}}
        else:
            # Triage with primary LLM.
            triage = self._triage(alert)
            triage = guard_triage(triage)

        if triage["next"] == "auto_close":
            chain = self._build_auto_close_chain(alert, triage)
            # Closing is the one decision that skips every specialist, so it is the one an injected
            # `{"next": "auto_close"}` wants. It had no second opinion (review round 3 G2-2): now the
            # independent reviewer must concur, or the alert goes to the perimeter specialist instead.
            v = vote_best([self._voter, *self._extra_voters], chain, context=_auto_close_context(alert, triage))
            chain.metadata["vote_concur"] = v.concur
            chain.metadata["vote_reason"] = v.reason
            chain.metadata["vote_tally"] = f"{v.n_concur}/{v.n_voters}"
            chain.metadata["vote_unanimous"] = v.unanimous
            if not v.unanimous:
                md = dict(triage.get("_triage_metadata") or {})
                md["overridden"] = f"auto_close → dispatch_perimeter (reviewer did not concur: {v.reason[:160]})"
                triage = {**triage, "next": "dispatch_perimeter", "verdict": None,
                          "reason": "Reviewer did not concur with auto-close; investigating", "_triage_metadata": md}
        if triage["next"] == "auto_close":
            obs.record_alert_processed("orchestrator")
            obs.record_verdict(chain.verdict, "orchestrator")
            span_record.attributes["specialist"] = "orchestrator"
            span_record.attributes["verdict"] = chain.verdict
            return chain

        specialist = self._select_specialist(triage["next"])
        if specialist is not None:
            with obs.span("aegis.specialist.investigate",
                          specialist=specialist.name,
                          alert_id=alert.get("id", "?")):
                chain = specialist.investigate(alert)
            chain.specialist_invocations.append(specialist.name)
            _carry_injection(chain, alert, triage)
            obs.record_alert_processed(specialist.name)
            obs.record_verdict(chain.verdict, specialist.name)
            span_record.attributes["specialist"] = specialist.name
            span_record.attributes["verdict"] = chain.verdict
            # Multi-agent vote on the specialist's verdict. vote_best() runs the
            # majority-vote panel when AEGIS_ENSEMBLE_VOTE is on and >=2 voters are
            # configured, else the single reviewer. Unanimity (single concur, or all
            # ensemble reviewers concur) keeps confidence and skips forced HITL; any
            # split or dissent caps confidence and routes the irreversible actions to
            # an analyst.
            v = vote_best([self._voter, *self._extra_voters], chain)
            chain.metadata["vote_concur"] = v.concur
            chain.metadata["vote_reason"] = v.reason
            chain.metadata["vote_tally"] = f"{v.n_concur}/{v.n_voters}"
            chain.metadata["vote_unanimous"] = v.unanimous
            chain.confidence = v.final_confidence
            if not v.unanimous:
                chain.reasoning.append(
                    ReasoningStep(
                        step=len(chain.reasoning) + 1,
                        action=("Independent reviewer dissented" if v.n_voters <= 1
                                else f"Reviewer panel split ({v.n_concur}/{v.n_voters} concur)"),
                        observation=v.reason,
                        conclusion="Confidence capped; HITL forced on any high-impact action.",
                    )
                )
                # Force HITL on non-monitor/non-allow actions when voter dissents.
                for a in chain.recommended_actions:
                    if a.action_type not in ("allow", "monitor"):
                        a.requires_hitl = True
                if chain.verdict in ("benign", "uncertain") and v.disputed:
                    # A dissent on a benign verdict is the case injection aims for (the specialist talked into
                    # "benign"); capping confidence and gating non-allow actions did nothing there, and the alert
                    # closed with nobody looking (review round 4 O4-2). It goes to an analyst instead.
                    chain.verdict = "uncertain"
                    if not any(a.action_type == "escalate" for a in chain.recommended_actions):
                        chain.recommended_actions.append(RecommendedAction(
                            action_type="escalate", target=str(alert.get("id", chain.alert_id)), requires_hitl=True,
                            confidence=chain.confidence,
                            reasoning=f"Independent reviewer disputed a benign verdict: {str(v.reason)[:200]}"))
            return chain

        if triage["next"] == "respond":
            chain = self._build_direct_response_chain(alert, triage)
            return chain

        # Fallback: unsupported next step (specialist not registered)
        return self._build_unsupported_chain(alert, triage)

    def _select_specialist(self, next_step: str):
        if next_step == "dispatch_perimeter" and self._perimeter is not None:
            return self._perimeter
        if next_step == "dispatch_auth" and self._auth is not None:
            return self._auth
        if next_step == "dispatch_edr" and self._edr is not None:
            return self._edr
        if next_step == "dispatch_api_abuse" and self._api_abuse is not None:
            return self._api_abuse
        if next_step == "dispatch_transaction" and self._transaction is not None:
            return self._transaction
        if next_step == "dispatch_cloud_controlplane" and self._cloud_controlplane is not None:
            return self._cloud_controlplane
        if next_step == "dispatch_dlp" and self._dlp is not None:
            return self._dlp
        if next_step == "dispatch_email" and self._email is not None:
            return self._email
        if next_step == "dispatch_mobile" and self._mobile is not None:
            return self._mobile
        if next_step == "dispatch_wireless" and self._wireless is not None:
            return self._wireless
        return None

    # ---- triage helpers --------------------------------------------------

    def _triage(self, alert: dict) -> dict:
        wrapped = wrap_untrusted("alert", json.dumps(alert))
        user_msg = (
            "Triage this alert. Return only the JSON object per the schema.\n\n"
            f"{wrapped.wrapped}"
        )
        resp = complete_for_json(self._primary, self._system, user_msg, max_tokens=1024, want=("next",))
        try:
            decision = _normalise_triage(parse_json(resp.text))
        except Exception as e:  # noqa: BLE001
            logger.warning("[orchestrator] triage response for alert %s did not parse (%s: %s) — routing to perimeter",
                           alert.get("id", "?"), type(e).__name__, str(e)[:120])
            decision = {
                "next": "dispatch_perimeter",
                "reason": "Triage parse failed; default to deeper investigation",
            }
        decision["_triage_metadata"] = {
            "model": resp.model,
            "in_tokens": resp.input_tokens,
            "out_tokens": resp.output_tokens,
            # hidden characters (U+3000 padding, RLO, zero-width) are an attack on the reader as much as an
            # "ignore previous instructions" is — count them, or they unlock the shortcuts (round 3 G2-2)
            "injection_detected": wrapped.injection_detected or bool(wrapped.obfuscation_findings),
            "injection_patterns": wrapped.matched_patterns + [f"obfuscation: {f}" for f in wrapped.obfuscation_findings],
        }
        return decision

    # ---- chain builders --------------------------------------------------

    def _build_auto_close_chain(self, alert: dict, triage: dict) -> EvidenceChain:
        # Closing means benign: a model that said `auto_close` with verdict "malicious" used to leave a
        # malicious chain whose only action was `allow` (review round 3 G2-9).
        chain = EvidenceChain(
            alert_id=alert.get("id", "unknown"),
            investigated_by=self.name,
            verdict="benign",
            confidence=float(triage.get("confidence", 0.85)),
        )
        chain.reasoning.append(
            ReasoningStep(
                step=1,
                action="Triage decision: auto_close",
                observation=triage.get("reason", ""),
                conclusion="No specialist needed.",
            )
        )
        chain.recommended_actions.append(
            RecommendedAction(
                action_type="allow",
                target=str(alert.get("id", "unknown")),
                reasoning=triage.get("reason", "auto_close"),
                requires_hitl=False,
                confidence=float(triage.get("confidence", 0.85)),
            )
        )
        chain.metadata.update(triage.get("_triage_metadata", {}))
        return chain.finalize()

    def _build_direct_response_chain(self, alert: dict, triage: dict) -> EvidenceChain:
        chain = EvidenceChain(
            alert_id=alert.get("id", "unknown"),
            investigated_by=self.name,
            verdict=triage.get("verdict", "malicious"),
            confidence=float(triage.get("confidence", 0.95)),
        )
        chain.evidence.append(
            EvidenceItem(
                source="orchestrator",
                signal="High-confidence alert routed directly to response",
                weight="high",
                raw_data={"reason": triage.get("reason", "")},
            )
        )
        chain.reasoning.append(
            ReasoningStep(
                step=1,
                action="Triage decision: respond",
                observation=triage.get("reason", ""),
                conclusion="Skip specialist; route to Response Agent for HITL.",
            )
        )
        chain.recommended_actions.append(
            RecommendedAction(
                action_type="block",
                target=str(alert.get("source_ip") or "unknown"),
                reasoning="Direct response based on high-confidence triage",
                requires_hitl=True,
                confidence=chain.confidence,
            )
        )
        chain.metadata.update(triage.get("_triage_metadata", {}))
        return chain.finalize()

    def _build_unsupported_chain(self, alert: dict, triage: dict) -> EvidenceChain:
        chain = EvidenceChain(
            alert_id=alert.get("id", "unknown"),
            investigated_by=self.name,
            verdict="uncertain",
            confidence=0.5,
        )
        chain.reasoning.append(
            ReasoningStep(
                step=1,
                action=f"Triage decision: {triage.get('next', 'unknown')}",
                observation="Specialist not available in MVP scope",
                conclusion="Escalating to human analyst.",
            )
        )
        chain.recommended_actions.append(
            RecommendedAction(
                action_type="escalate",
                target=alert.get("id", "unknown"),
                reasoning="Unsupported triage path in MVP",
                requires_hitl=True,
                confidence=0.5,
            )
        )
        chain.metadata.update(triage.get("_triage_metadata", {}))
        return chain.finalize()
