"""Phase 2.1 — swarm fan-out: parallel workers, merged evidence, governed, capped."""

from __future__ import annotations

import json
import tempfile
import time
from pathlib import Path

import pytest

from aegis.agents.orchestrator.swarm import (
    DEFAULT_WORKERS, SwarmOrchestrator, WorkerResult, swarm_from_env,
)
from aegis.agents.shared.evidence_chain import EvidenceItem
from aegis.agents.threat_intel.store import IOC, IOCStore
from aegis.eval.run import HERE, _build_orchestrator, run_historical, run_injection

CASES = {c["alert"]["id"]: c for c in json.loads((HERE / "historical_alerts" / "cases.json").read_text(encoding="utf-8"))}


@pytest.fixture(autouse=True)
def _stub_llm(monkeypatch):
    for k in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "LLM_BACKEND"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("ACP_HOME", tempfile.mkdtemp())


@pytest.fixture
def orch():
    with tempfile.TemporaryDirectory() as td:
        yield _build_orchestrator(Path(td) / "audit.jsonl")


def _malicious_case():
    return next(c["alert"] for c in CASES.values() if c["expected_verdict"] == "malicious" and c["alert"].get("source") == "Okta")


def _benign_case():
    return next(c["alert"] for c in CASES.values() if c["expected_verdict"] == "benign")


def test_swarm_only_fans_out_on_verdicts_worth_it(orch):
    swarm = SwarmOrchestrator(orch)
    benign = swarm.handle(_benign_case())
    assert "swarm" not in benign.metadata and not any(s.startswith("swarm.") for s in benign.specialist_invocations)
    chain = swarm.handle(_malicious_case())
    run = chain.metadata["swarm"]
    assert set(run["workers"]) == set(DEFAULT_WORKERS)
    assert run["evidence_added"] >= 2 and run["elapsed_ms"] >= 0
    assert any(e.source == "swarm.blast_radius" for e in chain.evidence)
    assert any(e.source == "swarm.log_hunt" for e in chain.evidence)
    assert chain.reasoning[-1].action == "swarm_fan_out"
    assert run["verdict_after"] == "malicious"  # never lowered
    assert swarm.runs and swarm.runs[0]["alert_id"] == chain.alert_id


def test_swarm_keeps_every_eval_verdict_and_holds_the_line(orch):
    swarm = SwarmOrchestrator(orch)
    c, n, diss = run_historical(swarm)
    assert (c, n) == (37, 37), diss
    s, n2, leaks = run_injection(swarm)
    assert (s, n2) == (9, 9), leaks
    assert len(swarm.runs) >= 20  # most non-benign cases fanned out


def test_intel_enrichment_and_deception_raise_evidence(orch):
    store = IOCStore()
    store.add(IOC(kind="ip", value="185.220.101.7", confidence=0.92, source="misp", first_seen=time.time(),
                  last_seen=time.time(), tags=("tor-exit",)))

    class Decoy:
        def alert_touches_decoy(self, alert):
            return alert.get("id") == "DECOY-1"

    swarm = SwarmOrchestrator(orch, ioc_store=store)
    alert = dict(_malicious_case(), id="DECOY-1", source_ip="185.220.101.7", note="tor exit 185.220.101.7")
    first_pass = swarm._orch.handle(alert)            # normal triage first …
    swarm._orch._honeytoken = Decoy()                 # … then the swarm's deception worker sees the decoy
    chain = swarm.fan_out(alert, first_pass)
    sources = {e.source for e in chain.evidence}
    assert "swarm.intel_enrich" in sources and "swarm.deception_check" in sources
    hit = next(e for e in chain.evidence if e.source == "swarm.intel_enrich")
    assert hit.weight == "high" and hit.raw_data["hits"][0]["value"] == "185.220.101.7"
    assert any(a.action_type == "escalate" and a.requires_hitl for a in chain.recommended_actions)
    assert chain.verdict == "malicious"


def test_worker_crash_and_timeout_are_recorded_not_fatal(orch):
    def boom(alert, chain, ctx):
        raise RuntimeError("worker exploded")

    def slow(alert, chain, ctx):
        time.sleep(1.0)
        return WorkerResult("slow", evidence=[EvidenceItem(source="swarm.slow", weight="low", signal="late")])

    swarm = SwarmOrchestrator(orch, workers={"boom": boom, "slow": slow, "blast_radius": DEFAULT_WORKERS["blast_radius"]},
                              max_seconds=0.3)
    chain = swarm.handle(_malicious_case())
    w = chain.metadata["swarm"]["workers"]
    assert "worker exploded" in w["boom"]["error"]
    assert "timed out" in w["slow"]["error"]
    assert w["blast_radius"]["ok"] is True
    assert not any(e.source == "swarm.slow" for e in chain.evidence)  # a timed-out worker contributes nothing


def test_swarm_workers_are_governed_tool_calls_and_pause_stops_them(orch):
    from aegis.governance import govern_soc, tool_allowlist
    import os
    os.environ["ACP_GOVERN"] = "1"
    try:
        governed = govern_soc(orch)
    finally:
        os.environ.pop("ACP_GOVERN", None)
    assert governed is not None
    assert {f"swarm.{n}" for n in DEFAULT_WORKERS} <= set(tool_allowlist(orch))
    swarm = SwarmOrchestrator(orch, guard=governed.guard)
    chain = swarm.handle(_malicious_case())
    tools = [e.data["tool"] for e in governed.guard.state.events if e.event_type == "tool_call_start"]
    assert sum(1 for t in tools if t.startswith("swarm.")) == len(DEFAULT_WORKERS)
    assert chain.metadata["swarm"]["evidence_added"] >= 2

    governed.guard._paused = True  # dashboard pause-gate
    chain2 = swarm._orch.handle(_malicious_case())  # governed first pass → escalate chain
    chain2.verdict = "malicious"  # force a fan-out to prove the workers themselves are gated
    chain2 = swarm.fan_out(_malicious_case(), chain2)
    w = chain2.metadata["swarm"]["workers"]
    assert all(v["skipped"] and "governance" in v["note"] for v in w.values())
    assert chain2.metadata["swarm"]["evidence_added"] == 0


def test_swarm_from_env_off_by_default(orch, monkeypatch):
    monkeypatch.delenv("AEGIS_SWARM", raising=False)
    # swarm off: still wrapped for campaign context only — no workers, never fans out
    ctx_only = swarm_from_env(orch)
    assert ctx_only._workers == {} and ctx_only.trigger_verdicts == frozenset() and ctx_only._events is not None
    monkeypatch.setenv("AEGIS_CAMPAIGN_CONTEXT", "0")
    assert swarm_from_env(orch) is orch
    monkeypatch.delenv("AEGIS_CAMPAIGN_CONTEXT")
    monkeypatch.setenv("AEGIS_SWARM", "1")
    monkeypatch.setenv("AEGIS_SWARM_MAX_WORKERS", "3")
    s = swarm_from_env(orch)
    assert isinstance(s, SwarmOrchestrator) and s.max_workers == 3
    assert s.name == "swarm_orchestrator" and s._honeytoken is orch._honeytoken  # passthrough


def test_governed_swarm_over_the_whole_eval_set_is_never_rate_limited(orch):
    """Regression: ~9 governed calls per alert used to trip Q33's 100/min default
    after a dozen alerts and block the orchestrator itself (ACP-733)."""
    from aegis.governance import govern_soc
    import os
    os.environ["ACP_GOVERN"] = "1"
    try:
        governed = govern_soc(orch)
    finally:
        os.environ.pop("ACP_GOVERN", None)
    swarm = SwarmOrchestrator(orch, guard=governed.guard)
    c, n, diss = run_historical(swarm)
    s, n2, leaks = run_injection(swarm)
    assert (c, n, s, n2) == (37, 37, 9, 9), (diss, leaks)
    ev = governed.guard.state.events
    assert sum(1 for e in ev if e.event_type == "tool_call_start") > 300
    assert not any(e.event_type == "tool_call_end" and e.data.get("success") is False for e in ev)
    assert governed.guard.config.rate_limiter.global_limit >= 1000



def test_live_model_triage_shapes_are_normalised():
    """A live model puts its rationale in `verdict` and omits `reason` — that used to
    coerce every auto_close to `uncertain` (the bulk of the July live-eval misses)."""
    from aegis.agents.orchestrator.agent import _normalise_triage
    d = _normalise_triage({"next": "auto_close", "verdict": "Low-severity alert, internal IP, baseline user.", "confidence": 0.82})
    assert d == {"next": "auto_close", "verdict": "benign", "reason": "Low-severity alert, internal IP, baseline user.", "confidence": 0.82}
    d = _normalise_triage({"next": "respond", "reason": "honeytoken", "verdict": "MALICIOUS "})
    assert d["verdict"] == "malicious" and d["reason"] == "honeytoken"
    d = _normalise_triage({"next": "respond"})
    assert d["verdict"] == "malicious"
    d = _normalise_triage({"next": "dispatch_auth", "reason": "impossible travel", "verdict": "suspicious"})
    assert d["verdict"] == "suspicious" and d["next"] == "dispatch_auth"
    d = _normalise_triage({"next": "close_it", "reason": "x", "confidence": "high"})
    assert d["next"] == "dispatch_perimeter" and "close_it" in d["reason"] and "confidence" not in d
    assert _normalise_triage("garbage")["next"] == "dispatch_perimeter"
    assert _normalise_triage({"next": "auto_close", "confidence": 7})["confidence"] == 1.0


def test_chain_assignment_is_validated_like_construction():
    """Specialists assign `chain.verdict` / `chain.confidence` after the LLM call;
    those assignments must be coerced exactly like construction is."""
    from aegis.agents.shared.evidence_chain import EvidenceChain, RecommendedAction
    c = EvidenceChain(alert_id="A", investigated_by="perimeter", verdict="suspicious", confidence=0.5)
    c.verdict = "Clearly a SQL injection attempt from a known-bad IP."
    assert c.verdict == "uncertain"
    c.verdict = " Malicious "
    assert c.verdict == "malicious"
    for raw, want in ((93, 0.93), ("0.7", 0.7), ("85%", 0.85), (1.5, 0.015), (250, 1.0), ("n/a", 0.5), (-1, 0.0)):
        c.confidence = raw
        assert c.confidence == want, (raw, c.confidence)
    a = RecommendedAction(action_type="block", target="t", reasoning="r", requires_hitl=True, confidence="90%")
    assert a.confidence == 0.9
    a.confidence = 42
    assert a.confidence == 0.42
    assert c.finalize().completed_at is not None          # finalize still works with validate_assignment


def test_parse_json_prefers_the_verdict_object_and_survives_prose_and_truncation():
    from aegis.agents.shared.llm_client import parse_json
    # prose + inner tool echo + the real object + trailing analysis
    text = ('Looking at the tool results {"ip_verdict": "known_malicious", "abuse_score": 96} I conclude:\n'
            '```json\n{"verdict": "malicious", "confidence": 0.93, "summary": "s", "actions": []}\n```\n'
            'Further notes: {"unrelated": true}')
    assert parse_json(text)["verdict"] == "malicious"
    # truncated at max_tokens mid-way through the trailing analysis → the complete verdict object still wins
    assert parse_json('{"verdict": "benign", "confidence": 0.9} and then the model kept wri {"partial": ')["verdict"] == "benign"
    # old behaviour kept: a bare object parses; garbage raises
    assert parse_json('  {"a": 1}  ') == {"a": 1}
    import pytest as _pt
    with _pt.raises(Exception):
        parse_json("no json here")


def test_complete_for_json_retries_once_with_a_json_only_nudge():
    from aegis.agents.shared.llm_client import LLMResponse, complete_for_json, JSON_ONLY_NUDGE

    class Chatty:
        name, model = "chatty", "m"
        def __init__(self):
            self.calls = []
        def complete(self, system, user, max_tokens=2048):
            self.calls.append((user, max_tokens))
            if len(self.calls) == 1:   # analysis that ran into the cap: no usable object
                return LLMResponse(text="Let me think... {\"ip_verdict\": \"bad\"} and the", model="m", input_tokens=100, output_tokens=max_tokens, cost_cents=1.0)
            return LLMResponse(text='{"verdict": "malicious", "confidence": 0.9}', model="m", input_tokens=120, output_tokens=20, cost_cents=1.5)

    llm = Chatty()
    resp = complete_for_json(llm, "sys", "user msg", max_tokens=4096)
    assert len(llm.calls) == 2 and llm.calls[1][0].endswith(JSON_ONLY_NUDGE) and llm.calls[0][1] == 4096
    assert resp.text == '{"verdict": "malicious", "confidence": 0.9}'
    assert (resp.input_tokens, resp.output_tokens, resp.cost_cents, resp.retries) == (220, 4116, 2.5, 1)

    class Clean:
        name, model = "clean", "m"
        calls = 0
        def complete(self, system, user, max_tokens=2048):
            Clean.calls += 1
            return LLMResponse(text='prose {"verdict": "benign", "confidence": 0.8} prose', model="m", input_tokens=1, output_tokens=1)
    resp = complete_for_json(Clean(), "s", "u")
    assert Clean.calls == 1 and resp.text == '{"verdict": "benign", "confidence": 0.8}'
