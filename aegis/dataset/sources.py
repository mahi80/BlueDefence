"""Where dataset records come from.

- ``eval_records``          — the curated eval corpora (37 historical + 9 injection
                              cases) run through the orchestrator; ground-truth
                              labels; **held out as the test split by default**
                              (they are the CI gate — training on them would make
                              3.3's "fewer misses than baseline" meaningless)
- ``local_audit_records``   — the agent host's hash-chained ``_audit_log.jsonl``
- ``dashboard_records``     — ``GET /api/soc/dataset`` (chains + the analysts'
                              approve/reject decisions joined server-side), paged
- ``proposal_records``      — ``GET /api/soc/proposals`` (meta-agent proposals and
                              their human decisions — the rule-proposal loop's data)
- ``attack_profile_records``— CVE / advisory text (dashboard threat-intel library or
                              the repo seed), red-team scenario profiles, and the
                              ATT&CK / ATLAS technique catalogue
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator, Optional

from .attack_map import catalogue
from .schema import HumanDecision, TriageRecord, fingerprint, record_from_chain
from .scrub import Scrubber

logger = logging.getLogger("aegis.dataset")

#: transport(method, url, json_body, headers, timeout) -> dict
Transport = Callable[[str, str, Optional[dict], dict, float], dict]

_EVAL_DIR = Path(__file__).resolve().parent.parent / "eval"
# Offline fallback seed, vendored into the SOC package (BlueDefence is standalone;
# the live path still reads the dashboard's threat-intel library over HTTP first).
_SEED_INTEL = Path(__file__).resolve().parent / "seed" / "ai_threat_intel.json"


def _httpx_transport(method: str, url: str, json_body: Optional[dict], headers: dict, timeout: float) -> dict:
    import httpx

    resp = httpx.request(method, url, json=json_body, headers=headers, timeout=timeout)
    resp.raise_for_status()
    data = resp.json()
    return data if isinstance(data, dict) else {"_raw": data}


def _headers(api_key: str) -> dict:
    h = {"Accept": "application/json"}
    if api_key:
        h["X-API-Key"] = api_key
    return h


# ---------------------------------------------------------------- eval --

def eval_records(orch: Any, scrubber: Scrubber, *, split: str = "test",
                 historical: bool = True, injection: bool = True) -> list[TriageRecord]:
    """Run the eval corpora through ``orch`` and label with the curated expectations."""
    out: list[TriageRecord] = []
    if historical:
        cases = json.loads((_EVAL_DIR / "historical_alerts" / "cases.json").read_text(encoding="utf-8"))
        for case in cases:
            chain = orch.handle(case["alert"])
            out.append(record_from_chain(
                _dump(chain), alert=case["alert"], origin="eval_historical", scrubber=scrubber,
                expected_verdict=case["expected_verdict"], split=split,
                tags=[t for t in [case.get("label", "")] if t],
                extra_meta={"eval_case": case["alert"].get("id"),
                            "model_agrees": chain.verdict == case["expected_verdict"]},
            ))
    if injection:
        cases = json.loads((_EVAL_DIR / "injection_corpus" / "cases.json").read_text(encoding="utf-8"))
        for case in cases:
            chain = orch.handle(case["alert"])
            leaked = any(a.action_type == "allow" for a in chain.recommended_actions)
            out.append(record_from_chain(
                _dump(chain), alert=case["alert"], origin="eval_injection", scrubber=scrubber,
                expected_verdict=chain.verdict if chain.verdict != "benign" else "suspicious",
                constraint=f"no_{case.get('expected_no_action', 'allow')}", split=split,
                tags=[t for t in [case.get("label", ""), "prompt_injection"] if t],
                extra_meta={"eval_case": case["alert"].get("id"), "model_leaked": leaked},
            ))
    return out


def _dump(chain: Any) -> dict:
    if isinstance(chain, dict):
        return chain
    return chain.model_dump(mode="json")


# ----------------------------------------------------------- local jsonl --

def local_audit_records(path: Path | str, scrubber: Scrubber, *, origin: str = "local_audit") -> list[TriageRecord]:
    """Every chain in an ``AuditLog`` JSONL; the latest entry per alert wins (swarm re-append)."""
    p = Path(path)
    if not p.exists():
        return []
    latest: dict[str, dict] = {}
    order: list[str] = []
    with p.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                chain = json.loads(line)
            except json.JSONDecodeError:
                continue
            aid = str(chain.get("alert_id") or chain.get("integrity_hash") or len(order))
            if aid not in latest:
                order.append(aid)
            latest[aid] = chain
    return [record_from_chain(latest[a], alert=None, origin=origin, scrubber=scrubber) for a in order]


# -------------------------------------------------------------- dashboard --

def _human_decisions(raw: Iterable[dict]) -> list[HumanDecision]:
    out = []
    for h in raw or []:
        if not isinstance(h, dict):
            continue
        out.append(HumanDecision(
            approval_id=str(h.get("approval_id") or h.get("id") or ""),
            action_type=str(h.get("action_type") or h.get("action") or ""),
            target=str(h.get("target") or "")[:200],
            decision=str(h.get("decision") or h.get("status") or "pending").lower(),
            decided_by_role=str(h.get("decided_by_role") or h.get("role") or ""),
            rationale=str(h.get("rationale") or "")[:500],
            decided_at=h.get("decided_at"),
            corrected_verdict=str(h.get("corrected_verdict") or "")[:20],
        ))
    return out


def iter_dashboard_pages(dashboard_url: str, api_key: str, *, since: Optional[str] = None,
                         page_size: int = 200, transport: Optional[Transport] = None,
                         timeout: float = 30.0, max_pages: int = 10_000) -> Iterator[dict]:
    """Yield ``{"chain": ..., "human": [...]}`` entries from ``GET /api/soc/dataset``, following cursors."""
    tr = transport or _httpx_transport
    base = dashboard_url.rstrip("/")
    cursor: Optional[str] = None
    for _ in range(max_pages):
        q = f"limit={int(page_size)}"
        if since:
            q += f"&since={since}"
        if cursor:
            q += f"&cursor={cursor}"
        data = tr("GET", f"{base}/api/soc/dataset?{q}", None, _headers(api_key), timeout)
        if data.get("error"):
            raise RuntimeError(f"dashboard refused: {data['error']}")
        for entry in data.get("records") or []:
            if isinstance(entry, dict):
                yield entry
        cursor = data.get("next_cursor")
        if not cursor:
            return


def dashboard_records(dashboard_url: str, api_key: str, scrubber: Scrubber, *, since: Optional[str] = None,
                      transport: Optional[Transport] = None, page_size: int = 200) -> list[TriageRecord]:
    """Persisted chains + analyst decisions → records; the latest chain per alert wins."""
    latest: dict[str, dict] = {}
    order: list[str] = []
    for entry in iter_dashboard_pages(dashboard_url, api_key, since=since, page_size=page_size, transport=transport):
        row = entry.get("chain") if isinstance(entry.get("chain"), dict) else {}
        chain = row.get("chain") if isinstance(row.get("chain"), dict) else None
        if not chain:
            continue
        aid = str(chain.get("alert_id") or row.get("alert_id") or row.get("integrity_hash") or len(order))
        if aid not in latest:
            order.append(aid)
        latest[aid] = {"row": row, "chain": chain, "human": entry.get("human") or []}
    out: list[TriageRecord] = []
    for aid in order:
        e = latest[aid]
        row, chain = e["row"], e["chain"]
        out.append(record_from_chain(
            chain, alert=None, origin="dashboard_chain", scrubber=scrubber,
            human=_human_decisions(e["human"]),
            created_at=row.get("created_at"),
            extra_meta={"dashboard_row": row.get("id"), "agent_id": row.get("agent_id"), "bu": row.get("bu"),
                        "governance_blocked": row.get("governance_blocked")},
        ))
    return out


def proposal_records(dashboard_url: str, api_key: str, scrubber: Scrubber, *,
                     transport: Optional[Transport] = None, limit: int = 500, timeout: float = 30.0) -> list[TriageRecord]:
    """Meta-agent proposals with their human decisions (``kind="proposal"``)."""
    tr = transport or _httpx_transport
    data = tr("GET", f"{dashboard_url.rstrip('/')}/api/soc/proposals?include_payload=true&limit={int(limit)}",
              None, _headers(api_key), timeout)
    if data.get("error"):
        raise RuntimeError(f"dashboard refused: {data['error']}")
    out: list[TriageRecord] = []
    for p in data.get("proposals") or []:
        if not isinstance(p, dict):
            continue
        proposal = scrubber.scrub(p.get("proposal") if isinstance(p.get("proposal"), dict) else {})
        validation = p.get("validation") if isinstance(p.get("validation"), dict) else {}
        status = str(p.get("status") or "pending_hitl")
        label_source = "human_confirmed" if status in ("accepted", "applied") else (
            "human_disputed" if status == "rejected" else "model")
        seed = json.dumps(proposal, sort_keys=True, default=str)
        out.append(TriageRecord(
            record_id=_sha(f"proposal|{p.get('integrity_hash') or seed}")[:16],
            kind="proposal", origin="dashboard_proposal", split="",
            fingerprint=_sha(seed),
            alert=None,
            label={"verdict": status, "source": label_source, "model_verdict": status,
                   "confidence": float((validation or {}).get("score") or 0.0),
                   "needs_review": status == "rejected"},
            chain={"proposal": proposal, "validation": validation,
                   "title": scrubber.scrub_text(str(p.get("title") or "")), "target": p.get("target")},
            rationale=scrubber.scrub_text(str(p.get("rationale") or "")),
            techniques=[],
            human=[{"approval_id": p.get("id"), "action_type": "proposal", "target": str(p.get("target") or ""),
                    "decision": "approved" if status in ("accepted", "applied") else
                    ("rejected" if status == "rejected" else "pending"),
                    "decided_by_role": "", "rationale": scrubber.scrub_text(str(p.get("rationale") or ""))[:500],
                    "decided_at": p.get("decided_at")}],
            source_system="meta_agent",
            tags=[str(p.get("target") or "")] if p.get("target") else [],
            created_at=str(p.get("created_at") or datetime.now(timezone.utc).isoformat()),
            meta={"proposal_id": p.get("proposal_id"), "dashboard_row": p.get("id"),
                  "validation_passed": p.get("validation_passed")},
        ))
    return out


# --------------------------------------------------------- attack profiles --

def _advisories(dashboard_url: Optional[str], api_key: str, transport: Optional[Transport],
                seed_path: Optional[Path]) -> list[dict]:
    if dashboard_url:
        tr = transport or _httpx_transport
        try:
            data = tr("GET", f"{dashboard_url.rstrip('/')}/api/cyber-risk/threat-intel", None, _headers(api_key), 30.0)
            adv = data.get("advisories")
            if isinstance(adv, list):
                return [a for a in adv if isinstance(a, dict)]
        except Exception as e:  # noqa: BLE001 — fall back to the seed
            logger.warning("[dataset] threat-intel fetch failed: %s", str(e)[:160])
    p = seed_path or _SEED_INTEL
    if p and Path(p).exists():
        try:
            data = json.loads(Path(p).read_text(encoding="utf-8"))
            return [a for a in data.get("advisories", []) if isinstance(a, dict)]
        except Exception as e:  # noqa: BLE001
            logger.warning("[dataset] threat-intel seed unreadable: %s", str(e)[:160])
    return []


def attack_profile_records(*, dashboard_url: Optional[str] = None, api_key: str = "",
                           transport: Optional[Transport] = None, seed_path: Optional[Path] = None,
                           include_red_team: bool = True) -> list[TriageRecord]:
    """Text records: advisories (CVE / OWASP / supply-chain), red-team attack profiles, technique catalogue."""
    out: list[TriageRecord] = []
    now = datetime.now(timezone.utc).isoformat()
    for a in _advisories(dashboard_url, api_key, transport, seed_path):
        text = " ".join(str(a.get(k) or "") for k in ("title", "summary")).strip()
        out.append(TriageRecord(
            record_id=_sha(f"advisory|{a.get('id')}")[:16], kind="attack_profile", origin="threat_intel",
            split="", fingerprint=_sha(text), alert=None,
            label={"verdict": "", "source": "ground_truth", "model_verdict": "", "confidence": 1.0, "needs_review": False},
            chain={"id": a.get("id"), "title": a.get("title"), "text": text, "cve": a.get("cve"),
                   "severity": a.get("severity"), "category": a.get("category"), "source": a.get("source"),
                   "url": a.get("url"), "published": a.get("published"), "acp_control": a.get("acp_control"),
                   "affects_frameworks": a.get("affects_frameworks") or [],
                   "affects_mcp_servers": a.get("affects_mcp_servers") or []},
            rationale="", techniques=[], source_system=str(a.get("source") or ""),
            tags=[t for t in [a.get("category"), a.get("severity")] if t], created_at=str(a.get("published") or now),
            meta={"advisory_id": a.get("id")},
        ))
    if include_red_team:
        try:
            from aegis.eval.ai_red_team.attacker import SCENARIOS
        except Exception:  # noqa: BLE001
            SCENARIOS = []
        for s in SCENARIOS:
            text = f"{s.description}. {s.user_prompt}"
            out.append(TriageRecord(
                record_id=_sha(f"redteam|{s.name}")[:16], kind="attack_profile", origin="red_team_scenario",
                split="", fingerprint=_sha(text), alert=None,
                label={"verdict": s.expected_verdict, "source": "ground_truth", "model_verdict": "",
                       "confidence": 1.0, "needs_review": False},
                chain={"id": s.name, "title": s.description, "text": text, "expected_verdict": s.expected_verdict},
                rationale="", techniques=[], source_system="ai_red_team", tags=[s.name], created_at=now,
                meta={"scenario": s.name},
            ))
    for t in catalogue():
        text = f"{t['id']} {t['name']} ({t['framework']}): {t['about']}"
        out.append(TriageRecord(
            record_id=_sha(f"technique|{t['id']}")[:16], kind="attack_profile", origin="technique_catalogue",
            split="", fingerprint=_sha(text), alert=None,
            label={"verdict": "", "source": "ground_truth", "model_verdict": "", "confidence": 1.0, "needs_review": False},
            chain={"id": t["id"], "title": t["name"], "text": text, "framework": t["framework"]},
            rationale="", techniques=[{"id": t["id"], "name": t["name"], "framework": t["framework"], "basis": "catalogue"}],
            source_system="mitre", tags=[t["framework"]], created_at=now, meta={},
        ))
    return out


def _sha(text: str) -> str:
    import hashlib
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def env_dashboard() -> tuple[str, str]:
    return os.environ.get("ACP_DASHBOARD_URL", "").strip(), os.environ.get("ACP_API_KEY", "")


__all__ = [
    "Transport", "eval_records", "local_audit_records", "dashboard_records", "iter_dashboard_pages",
    "proposal_records", "attack_profile_records", "env_dashboard", "fingerprint",
]
