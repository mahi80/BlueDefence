"""Threat Intel agent — a hybrid service + LLM analyst.

Service surface (no LLM, called from any agent):
  - lookup_ioc(value, kind=None) -> IOC | None
  - refresh_from_feeds() -> stats
  - distribute_to_perimeter() / distribute_to_edr() -> count merged

LLM surface (advisory analyst):
  - analyze_advisory(text) -> structured indicators + proposed detection
"""
from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Optional

from ..shared.evidence_chain import (
    EvidenceChain,
    EvidenceItem,
    ReasoningStep,
    RecommendedAction,
)
from ..shared.injection_defense import SYSTEM_PROMPT_PREAMBLE, wrap_untrusted
from ..shared.llm_client import LLMClient, parse_json

from . import feeds
from .store import IOC, LLM_TAG, IOCStore

logger = logging.getLogger("aegis.threat_intel")


_SYSTEM_PROMPT_FILE = Path(__file__).parent / "system_prompt.md"


def _build_system_prompt() -> str:
    return SYSTEM_PROMPT_PREAMBLE + "\n\n" + _SYSTEM_PROMPT_FILE.read_text(encoding="utf-8")


class ThreatIntelAgent:
    name = "threat_intel"

    def __init__(self, llm: Optional[LLMClient] = None,
                 store: Optional[IOCStore] = None,
                 cve_intel: Optional[object] = None):
        self._llm = llm
        self._store = store or IOCStore()
        self._system = _build_system_prompt()
        self.cve_intel = cve_intel          # cve_feeds.CveIntel (KEV + NVD + EPSS); shared with vuln_discovery

    # ---- Service surface --------------------------------------------

    @property
    def store(self) -> IOCStore:
        return self._store

    def lookup_ioc(self, value: str, kind=None) -> Optional[IOC]:
        return self._store.lookup(value, kind)

    def refresh_from_feeds(self, *, include_mock: bool = True,
                           stix_urls: Optional[list[str]] = None,
                           include_kev: bool = False,
                           include_misp: bool = False,
                           misp_since: Optional[str] = None,
                           include_rf: bool = False,
                           rf_entity_types: Optional[list[str]] = None,
                           include_tenable: bool = False,
                           tenable_severity: str = "medium",
                           include_nvd: bool = False,
                           nvd_days: int = 7,
                           publish: bool = False) -> dict:
        """Pull from configured feeds and merge into the store. Returns
        per-source counts plus the resulting store stats.
        """
        results: dict[str, int] = {}
        if include_mock:
            n = self._store.add_many(feeds.pull_mock_seed())
            results["mock_feed"] = n
        for url in stix_urls or []:
            iocs = feeds.pull_stix_feed(url)
            n = self._store.add_many(iocs)
            results[f"stix:{url}"] = n
        if include_kev:
            iocs = feeds.pull_cisa_kev(self.cve_intel)
            n = self._store.add_many(iocs)
            results["cisa.kev"] = n
        if include_nvd:
            results["nvd"] = int(feeds.pull_nvd(self.cve_intel, days=nvd_days).get("nvd_updated", 0))
        if publish and self.cve_intel is not None:
            from .publish import publish_to_dashboard
            results["published_to_dashboard"] = int(publish_to_dashboard(self.cve_intel).get("published", 0))
        if include_misp:
            iocs = feeds.pull_misp(since=misp_since)
            n = self._store.add_many(iocs)
            results["misp"] = n
        if include_rf:
            iocs = feeds.pull_recorded_future(entity_types=rf_entity_types)
            n = self._store.add_many(iocs)
            results["recorded_future"] = n
        if include_tenable:
            iocs = feeds.pull_tenable(severity_threshold=tenable_severity)
            n = self._store.add_many(iocs)
            results["tenable"] = n
        return {
            "added": results,
            "total_active": self._store.stats().total,
            "by_kind": self._store.stats().by_kind,
        }

    def distribute_to_perimeter(self) -> int:
        return self._store.merge_into_perimeter()

    def distribute_to_edr(self) -> int:
        return self._store.merge_into_edr()

    # ---- LLM surface (advisory analysis) ---------------------------

    def analyze_advisory(self, advisory_text: str,
                         advisory_id: str = "ADV-UNKNOWN") -> EvidenceChain:
        chain = EvidenceChain(
            alert_id=advisory_id,
            investigated_by=self.name,
            verdict="suspicious",
            confidence=0.5,
        )
        if self._llm is None:
            chain.reasoning.append(ReasoningStep(
                step=1,
                action="Threat-intel analysis requested but no LLM configured",
                observation="Skipping LLM pass; service-mode lookup_ioc still available",
                conclusion="Configure an LLMClient to enable advisory analysis",
            ))
            return chain.finalize()

        wrapped = wrap_untrusted("advisory", advisory_text)
        if wrapped.injection_detected or wrapped.obfuscation_char_count > 0:
            chain.evidence.append(EvidenceItem(
                source="injection_defense",
                signal=(
                    f"Threat-intel feed poisoning attempt: "
                    f"injection_patterns={wrapped.matched_patterns}, "
                    f"obfuscation={wrapped.obfuscation_findings}"
                ),
                weight="high",
                raw_data={
                    "injection_patterns": wrapped.matched_patterns,
                    "obfuscation": wrapped.obfuscation_findings,
                },
            ))
            chain.reasoning.append(ReasoningStep(
                step=1,
                action="Detected injection / obfuscation in threat-intel feed",
                observation="Treating feed content as adversarial; will analyze but not act on instructions",
            ))

        user_msg = (
            "Threat-intel advisory analysis (Mode 1).\n\n"
            f"Advisory (untrusted feed content):\n{wrapped.wrapped}\n\n"
            "Extract indicators + propose ONE detection update. JSON only."
        )
        resp = self._llm.complete(self._system, user_msg, max_tokens=2048)
        chain.metadata.update(
            llm_model=resp.model,
            llm_input_tokens=resp.input_tokens,
            llm_output_tokens=resp.output_tokens,
        )
        try:
            parsed = parse_json(resp.text)
        except Exception as exc:  # noqa: BLE001 — recorded as a reasoning step + logged, never a crash
            logger.warning("[%s] LLM advisory analysis unparsable for %s (%s: %s)", self.name, advisory_id, type(exc).__name__, str(exc)[:120])
            chain.reasoning.append(ReasoningStep(
                step=len(chain.reasoning) + 1,
                action="Parse LLM verdict",
                observation="Failed to parse JSON output",
                conclusion="Analyst should review the advisory manually",
            ))
            return chain.finalize()

        # Merge extracted indicators into the store. They come from an LLM reading untrusted advisory text, so
        # they are validated (no own / private ranges, no unknown kinds — IOCStore.add), confidence-capped,
        # short-lived and tagged: the store keeps them as evidence, but they reach the blocklist-style matchers
        # only if the operator opts in (AEGIS_TI_MERGE_LLM_IOCS=1).
        added = rejected = 0
        cap = float(os.environ.get("AEGIS_TI_LLM_MAX_CONFIDENCE", "0.6"))
        indicators = parsed.get("indicators", []) or []
        for ind in indicators[:200] if isinstance(indicators, list) else []:
            try:
                tags = tuple(str(t)[:40] for t in (ind.get("tags") or ())[:8]) + (LLM_TAG,)
                ioc = IOC(
                    kind=str(ind.get("kind") or ""),
                    value=str(ind.get("value", "")),
                    confidence=min(cap, float(ind.get("confidence", 0.5))),
                    source=f"advisory:{advisory_id}",
                    tags=tags,
                    ttl_seconds=int(os.environ.get("AEGIS_TI_LLM_TTL_SEC", str(3 * 86400))),
                )
                if self._store.add(ioc):
                    added += 1
                else:
                    rejected += 1
            except Exception as exc:  # noqa: BLE001 — one malformed IOC from the LLM is skipped, the rest are kept
                logger.debug("[threat_intel] skipped malformed IOC from LLM: %s", exc)
                continue
        chain.reasoning.append(ReasoningStep(
            step=len(chain.reasoning) + 1,
            action="LLM extracted indicators",
            observation=f"{added} indicator(s) merged into IOC store as unconfirmed ({rejected} rejected)",
            conclusion=parsed.get("classification", "unclassified"),
        ))

        proposed = parsed.get("proposed_detection") or {}
        if proposed:
            chain.recommended_actions.append(RecommendedAction(
                action_type="escalate",
                target=advisory_id,
                reasoning=(
                    f"Proposed detection: {proposed.get('type','?')}: "
                    f"{proposed.get('details','')}"[:200]
                ),
                requires_hitl=True,
                confidence=0.85,
            ))
        chain.metadata["summary"] = parsed.get("summary", "")
        return chain.finalize()
