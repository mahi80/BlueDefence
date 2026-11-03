"""Round-3 review, G5-9: the rule feed (evolve) — what a feed rule may change, and taking it back."""

from __future__ import annotations

import pytest

from aegis.evolve.applier import RuleApplier, plan_change
from aegis.evolve.registry import validate_regex

SQLI = "aegis.agents.perimeter.tools._SQLI_PRIMITIVES"
EDR = "aegis.agents.edr.tools._SUSPICIOUS_CMDLINE_PATTERNS"


def _rule(rid, target, add):
    return {"id": rid, "change_type": "heuristic_primitive", "target_module": target, "change": {"add": add}}


@pytest.mark.parametrize("add", ["e", "or", "get", "http"])
def test_a_tiny_or_everyday_primitive_is_refused(add):
    assert isinstance(plan_change(_rule("r", SQLI, add)), str)


@pytest.mark.parametrize("rx", [r"(a+)+$", r"(\w+\s?)*$", r"(a|aa)+b", r"((ab)*c)+", r"(x{1,})*y", r"(\d+)-\1"])
def test_redos_shapes_are_refused(rx):
    assert validate_regex(rx, 300) is not None


@pytest.mark.parametrize("rx", [r"union\s+all\s+select", r"(?:cmd|powershell)\.exe\s+-enc", r"\bxp_cmdshell\b"])
def test_ordinary_detection_regexes_pass(rx):
    assert validate_regex(rx, 300) is None


def test_a_regex_that_matches_everything_is_refused():
    assert "ordinary traffic" in (validate_regex(r".{0,3}", 300) or "")


def test_a_withdrawn_rule_is_reverted():
    from aegis.agents.perimeter import tools as perim
    before = tuple(perim._SQLI_PRIMITIVES)
    ap = RuleApplier()
    try:
        r1 = ap.apply([_rule("r1", SQLI, "waitfor delay '0:0:9'"), _rule("r2", SQLI, "pg_sleep(9)")], version="v1")
        assert r1.ok and "pg_sleep(9)" in perim._SQLI_PRIMITIVES
        r2 = ap.apply([_rule("r1", SQLI, "waitfor delay '0:0:9'")], version="v2")
        assert r2.withdrawn == ["r2"] and "pg_sleep(9)" not in perim._SQLI_PRIMITIVES
        assert "waitfor delay '0:0:9'" in perim._SQLI_PRIMITIVES
    finally:
        ap.revert_all()
    assert tuple(perim._SQLI_PRIMITIVES) == before


def test_validator_measures_exactly_what_the_applier_applies():
    from aegis.meta_agent.proposer import Proposal
    from aegis.meta_agent.validator import _proposal_to_patch
    p = Proposal(id="p", target_module=SQLI, change_type="heuristic_primitive", change={"add": "WAITFOR DELAY"}, rationale="r")
    patch = _proposal_to_patch(p)
    assert patch is not None and patch.mutate(("x",))[-1] == "waitfor delay"   # lower-cased, as the applier does
    outside = Proposal(**{**p.__dict__, "target_module": "aegis.service._FORGEABLE"})
    assert _proposal_to_patch(outside) is None                                 # not in the allowlist: not validated
