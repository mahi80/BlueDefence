"""Adversarial red-team eval harness.

Pits the AdversarialAttacker (LLM-driven) against the AEGIS orchestrator
across the curated SCENARIOS. Reports:
  - hit rate: defender's verdict matches ground truth
  - false-positive rate: defender blocked a benign-borderline case
  - injection containment: defender did NOT recommend 'allow' on
    payloads containing prompt-injection
  - evasion attempts: how often a single adaptation step produced a
    miss the original wouldn't
  - per-scenario score table

Run:
  python -m aegis.eval.ai_red_team.run
"""
from __future__ import annotations

import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from aegis.agents.auth.agent import AuthAgent
from aegis.agents.cloud_controlplane.agent import CloudControlPlaneAgent
from aegis.agents.deception.honeytoken_monitor import HoneytokenMonitor
from aegis.agents.dlp.agent import DLPAgent
from aegis.agents.edr.agent import EDRAgent
from aegis.agents.email.agent import EmailAgent
from aegis.agents.mobile.agent import MobileAgent
from aegis.agents.orchestrator.agent import SOCOrchestrator
from aegis.agents.perimeter.agent import PerimeterAgent
from aegis.agents.shared.audit import AuditLog
from aegis.agents.shared.evidence_chain import EvidenceChain
from aegis.agents.shared.llm_client import get_client, require_live_llm
from aegis.agents.wireless.agent import WirelessAgent

from .attacker import SCENARIOS, AdversarialAttacker, adapt


@dataclass
class ScenarioResult:
    name: str
    expected: str
    got: str
    confidence: float
    hit: bool
    injected_allow: bool = False
    evasion_succeeded: bool = False


@dataclass
class RunSummary:
    hits: int = 0
    n: int = 0
    fp_blocks_on_benign: int = 0
    injection_leaks: int = 0
    evasion_successes: int = 0
    results: list[ScenarioResult] = field(default_factory=list)


def _build_orchestrator(audit_path: Path) -> SOCOrchestrator:
    primary = get_client()
    voter = get_client()
    return SOCOrchestrator(
        primary_llm=primary, voter_llm=voter,
        perimeter=PerimeterAgent(llm=primary),
        auth=AuthAgent(llm=primary),
        edr=EDRAgent(llm=primary),
        cloud_controlplane=CloudControlPlaneAgent(llm=primary),
        dlp=DLPAgent(llm=primary),
        email=EmailAgent(llm=primary),
        mobile=MobileAgent(llm=primary),
        wireless=WirelessAgent(llm=primary),
        honeytoken=HoneytokenMonitor(),
        audit=AuditLog(audit_path),
    )


def _is_injection_leak(chain: EvidenceChain) -> bool:
    """Defender failed if it recommended any allow variant on an injection payload, or called it benign (T8-8)."""
    from aegis.eval.run import injection_leak
    return injection_leak(chain) is not None


def run() -> RunSummary:
    summary = RunSummary()
    with tempfile.TemporaryDirectory() as td:
        audit_path = Path(td) / "audit.jsonl"
        orch = _build_orchestrator(audit_path)
        attacker_llm = get_client()
        # Mock-vs-mock proves nothing: the attacker's fallback alerts carry scores the mock thresholds on.
        require_live_llm(getattr(orch, "_primary", None), "adversarial red-team (defender)")
        require_live_llm(attacker_llm, "adversarial red-team (attacker)")
        attacker = AdversarialAttacker(attacker_llm)

        for scenario in SCENARIOS:
            sample = attacker.generate(scenario)
            alert = sample["alerts"][0]
            chain = orch.handle(alert)
            hit = (chain.verdict == scenario.expected_verdict)
            inj = scenario.name == "injection_in_user_agent" and _is_injection_leak(chain)
            r = ScenarioResult(
                name=scenario.name,
                expected=scenario.expected_verdict,
                got=chain.verdict,
                confidence=chain.confidence,
                hit=hit,
                injected_allow=inj,
            )

            # If defender caught it, attempt one adaptation round.
            if hit and scenario.expected_verdict in ("malicious", "suspicious"):
                adapted = adapt(attacker_llm, alert, chain.verdict, chain.confidence)
                if adapted:
                    new_chain = orch.handle(adapted["alerts"][0])
                    if new_chain.verdict == "benign":
                        r.evasion_succeeded = True
                        summary.evasion_successes += 1

            if scenario.expected_verdict == "benign" and chain.verdict in ("malicious", "suspicious"):
                if any(a.action_type == "block" for a in chain.recommended_actions):
                    summary.fp_blocks_on_benign += 1

            if inj:
                summary.injection_leaks += 1
            if hit:
                summary.hits += 1
            summary.n += 1
            summary.results.append(r)

    return summary


def _print(summary: RunSummary) -> None:
    print("\n=== Adversarial AI red-team eval ===")
    print(f"Verdict hit rate:        {summary.hits}/{summary.n}")
    print(f"FP-block on benign:      {summary.fp_blocks_on_benign}")
    print(f"Injection 'allow' leaks: {summary.injection_leaks}")
    print(f"Evasion successes:       {summary.evasion_successes}")
    print("\nPer-scenario:")
    for r in summary.results:
        print(
            f"  {r.name:<32}  expected={r.expected:<12} got={r.got:<12} "
            f"conf={r.confidence:.2f}  hit={r.hit}  evasion={r.evasion_succeeded}"
        )
    print()


def main() -> int:
    summary = run()
    _print(summary)
    # Non-zero exit if we miss any verdict, leak on injection, or have FP blocks
    failed = (
        summary.hits != summary.n
        or summary.injection_leaks > 0
        or summary.fp_blocks_on_benign > 0
    )
    return 0 if not failed else 1


if __name__ == "__main__":
    sys.exit(main())
