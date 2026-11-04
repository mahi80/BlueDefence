"""Observer — runs the AEGIS eval suites and emits failure patterns.

Failures are tuples of (case_id, expected_verdict, actual_verdict,
alert, suite). The proposer consumes these to generate hypotheses;
the validator uses them as the baseline to measure against.

Optional `patches` parameter monkey-patches modules before running —
used by the meta-agent main loop to (a) seed deliberate eval gaps for
the demo and (b) apply proposed fixes during validation.
"""
from __future__ import annotations

import contextlib
import json
import tempfile
from dataclasses import dataclass
from importlib import import_module
from pathlib import Path
from typing import Any, Callable, Iterable

from aegis.agents.api_abuse.agent import APIAbuseAgent
from aegis.agents.auth.agent import AuthAgent
from aegis.agents.cloud_controlplane.agent import CloudControlPlaneAgent
from aegis.agents.deception.honeytoken_monitor import HoneytokenMonitor
from aegis.agents.dlp.agent import DLPAgent
from aegis.agents.edr.agent import EDRAgent
from aegis.agents.email.agent import EmailAgent
from aegis.agents.mobile.agent import MobileAgent
from aegis.agents.orchestrator.agent import SOCOrchestrator
from aegis.agents.perimeter.agent import PerimeterAgent
from aegis.agents.transaction.agent import TransactionAgent
from aegis.agents.wireless.agent import WirelessAgent
from aegis.agents.shared.audit import AuditLog
from aegis.agents.shared.llm_client import get_client


@dataclass
class FailurePattern:
    case_id: str
    suite: str            # "historical" | "ai_red_team" | "injection_corpus"
    expected: str         # "malicious" | "suspicious" | "benign" | injection-leak marker
    got: str
    confidence: float
    alert: dict


@dataclass
class Patch:
    """In-memory monkey-patch description.

    `target` is a dotted path like "aegis.agents.perimeter.tools._SQLI_PRIMITIVES";
    `mutate` receives the current value and returns the replacement.
    """
    target: str
    mutate: Callable[[Any], Any]
    description: str = ""


@contextlib.contextmanager
def _apply_patches(patches: Iterable[Patch]):
    saved: list[tuple[Any, str, Any]] = []
    try:
        for p in patches:
            mod_path, _, attr = p.target.rpartition(".")
            module = import_module(mod_path)
            current = getattr(module, attr)
            saved.append((module, attr, current))
            setattr(module, attr, p.mutate(current))
        yield
    finally:
        for module, attr, original in saved:
            setattr(module, attr, original)


def _build_orchestrator(audit_path: Path) -> SOCOrchestrator:
    primary = get_client()
    return SOCOrchestrator(
        primary_llm=primary,
        voter_llm=get_client(),
        perimeter=PerimeterAgent(llm=primary),
        auth=AuthAgent(llm=primary),
        edr=EDRAgent(llm=primary),
        api_abuse=APIAbuseAgent(llm=primary),
        transaction=TransactionAgent(llm=primary),
        cloud_controlplane=CloudControlPlaneAgent(llm=primary),
        dlp=DLPAgent(llm=primary),
        email=EmailAgent(llm=primary),
        mobile=MobileAgent(llm=primary),
        wireless=WirelessAgent(llm=primary),
        honeytoken=HoneytokenMonitor(),
        audit=AuditLog(audit_path),
    )


def _run_historical(orch: SOCOrchestrator) -> list[FailurePattern]:
    cases_path = (
        Path(__file__).parent.parent / "eval" / "historical_alerts" / "cases.json"
    )
    cases = json.loads(cases_path.read_text(encoding="utf-8"))
    failures: list[FailurePattern] = []
    for case in cases:
        chain = orch.handle(case["alert"])
        if chain.verdict != case["expected_verdict"]:
            failures.append(FailurePattern(
                case_id=case["alert"]["id"],
                suite="historical",
                expected=case["expected_verdict"],
                got=chain.verdict,
                confidence=chain.confidence,
                alert=case["alert"],
            ))
    return failures


def _run_injection(orch: SOCOrchestrator) -> list[FailurePattern]:
    cases_path = (
        Path(__file__).parent.parent / "eval" / "injection_corpus" / "cases.json"
    )
    cases = json.loads(cases_path.read_text(encoding="utf-8"))
    failures: list[FailurePattern] = []
    for case in cases:
        chain = orch.handle(case["alert"])
        # The defender fails if it recommends 'allow' on an injection case or calls it benign (round 7 T-9)
        from aegis.eval.run import injection_leak
        how = injection_leak(chain)
        if how:
            failures.append(FailurePattern(
                case_id=case["alert"]["id"],
                suite="injection_corpus",
                expected="not_allow_not_benign",
                got=how,
                confidence=chain.confidence,
                alert=case["alert"],
            ))
    return failures


def _run_red_team(orch: SOCOrchestrator) -> list[FailurePattern]:
    # Lazy import — red_team has runtime dependencies on the LLM client
    from aegis.eval.ai_red_team.attacker import SCENARIOS, AdversarialAttacker

    attacker = AdversarialAttacker(get_client())
    failures: list[FailurePattern] = []
    for scenario in SCENARIOS:
        sample = attacker.generate(scenario)
        alert = sample["alerts"][0]
        chain = orch.handle(alert)
        if chain.verdict != scenario.expected_verdict:
            failures.append(FailurePattern(
                case_id=alert.get("id", scenario.name),
                suite="ai_red_team",
                expected=scenario.expected_verdict,
                got=chain.verdict,
                confidence=chain.confidence,
                alert=alert,
            ))
    return failures


def observe(patches: list[Patch] | None = None) -> list[FailurePattern]:
    """Run all eval suites under optional patches; return failures."""
    failures: list[FailurePattern] = []
    with tempfile.TemporaryDirectory() as td:
        audit_path = Path(td) / "audit.jsonl"
        with _apply_patches(patches or []):
            orch = _build_orchestrator(audit_path)
            failures.extend(_run_historical(orch))
            failures.extend(_run_injection(orch))
            failures.extend(_run_red_team(orch))
    return failures
