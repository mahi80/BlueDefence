"""Phase 3.1 — accepted proposals become live rules the specialists apply at runtime."""

from __future__ import annotations

import re

import pytest

from aegis.evolve import PATCHABLE, RuleApplier, RuleFeed, sync_from_env
from aegis.evolve.registry import validate_regex


@pytest.fixture(autouse=True)
def _clean_state():
    """Every test starts and ends with the detection primitives untouched."""
    import aegis.agents.api_abuse.tools as api_tools
    import aegis.agents.edr.tools as edr_tools
    import aegis.agents.perimeter.tools as perim
    saved = (perim._SQLI_PRIMITIVES, perim._XSS_PRIMITIVES, edr_tools._SUSPICIOUS_CMDLINE_PATTERNS,
             edr_tools._CMDLINE_RX, list(api_tools._RISKY_QUERY_PATTERNS))
    yield
    perim._SQLI_PRIMITIVES, perim._XSS_PRIMITIVES = saved[0], saved[1]
    edr_tools._SUSPICIOUS_CMDLINE_PATTERNS, edr_tools._CMDLINE_RX = saved[2], saved[3]
    api_tools._RISKY_QUERY_PATTERNS[:] = saved[4]


def _rule(rid="SP-1", target="aegis.agents.perimeter.tools._SQLI_PRIMITIVES", add="waitfor delay", **kw):
    r = {"id": rid, "proposal_id": "PROP-X", "change_type": "heuristic_primitive",
         "target_module": target, "change": {"add": add}, "title": f"add {add}"}
    r.update(kw)
    return r


def test_accepted_primitive_changes_a_perimeter_verdict():
    from aegis.agents.perimeter.tools import decode_payload
    payload = "GET /api/x?q=1; WAITFOR DELAY '0:0:5'-- HTTP/1.1"
    sqli = lambda res: res.data["primitives"]["sqli"]  # noqa: E731
    assert "waitfor delay" not in sqli(decode_payload(payload))
    applier = RuleApplier()
    report = applier.apply([_rule()], version="v1")
    assert report.applied == ["SP-1"] and report.ok and applier.version == "v1"
    assert "waitfor delay" in sqli(decode_payload(payload))  # the new definition is live, no redeploy
    assert applier.revert_all() == 1
    assert "waitfor delay" not in sqli(decode_payload(payload))


def test_apply_is_idempotent_and_duplicates_are_not_added():
    import aegis.agents.perimeter.tools as perim
    n = len(perim._SQLI_PRIMITIVES)
    applier = RuleApplier()
    applier.apply([_rule(add="@@version")])              # already a primitive → no growth
    assert len(perim._SQLI_PRIMITIVES) == n
    applier.apply([_rule(rid="SP-2", add="xp_cmdshell")])
    assert len(perim._SQLI_PRIMITIVES) == n + 1
    rep = applier.apply([_rule(rid="SP-2", add="xp_cmdshell")])
    assert rep.already == ["SP-2"] and rep.applied == [] and len(perim._SQLI_PRIMITIVES) == n + 1


def test_edr_regex_rule_recompiles_the_union():
    from aegis.agents.edr.tools import parent_process_tree
    import aegis.agents.edr.tools as edr_tools
    cmd = "rundll32.exe comsvcs.dll MiniDump 624 C:\\\\lsass.dmp full"
    assert not edr_tools._CMDLINE_RX.search(cmd)
    applier = RuleApplier()
    rep = applier.apply([_rule(rid="SP-3", target="aegis.agents.edr.tools._SUSPICIOUS_CMDLINE_PATTERNS",
                               add=r"comsvcs\.dll\s+MiniDump")])
    assert rep.ok
    assert edr_tools._CMDLINE_RX.search(cmd)   # derived regex rebuilt by the post-apply hook
    res = parent_process_tree("cmd.exe", "rundll32.exe", cmd)
    assert res is not None
    applier.revert_all()
    assert not edr_tools._CMDLINE_RX.search(cmd)


def test_api_abuse_compiled_regex_rule():
    import aegis.agents.api_abuse.tools as api_tools
    n = len(api_tools._RISKY_QUERY_PATTERNS)
    rep = RuleApplier().apply([_rule(rid="SP-4", target="aegis.agents.api_abuse.tools._RISKY_QUERY_PATTERNS",
                                     add=r"\bpg_read_file\b")])
    assert rep.ok and len(api_tools._RISKY_QUERY_PATTERNS) == n + 1
    assert isinstance(api_tools._RISKY_QUERY_PATTERNS[-1], re.Pattern)


def test_rejections_never_touch_code():
    import aegis.agents.perimeter.tools as perim
    before = perim._SQLI_PRIMITIVES
    applier = RuleApplier()
    rep = applier.apply([
        _rule(rid="bad-target", target="aegis.agents.response.agent._ALWAYS_HITL_ACTIONS", add="block"),
        _rule(rid="bad-type", change_type="prompt_addendum"),
        _rule(rid="bad-value", add=""),
        _rule(rid="too-long", add="x" * 500),
        _rule(rid="bad-regex", target="aegis.agents.edr.tools._SUSPICIOUS_CMDLINE_PATTERNS", add="(unclosed"),
        _rule(rid="redos", target="aegis.agents.edr.tools._SUSPICIOUS_CMDLINE_PATTERNS", add=r"(a+)+$"),
        _rule(rid="thresh", change_type="threshold_adjustment", change={"new_value": 3}),
        {"change_type": "heuristic_primitive"},
    ])
    assert rep.applied == [] and len(rep.rejected) == 8
    reasons = dict(rep.rejected)
    assert "allowlist" in reasons["bad-target"] and "prompt_addendum" in reasons["bad-type"]
    assert "ReDoS" in reasons["redos"] and "does not compile" in reasons["bad-regex"]
    assert "threshold_adjustment not valid" in reasons["thresh"]
    assert perim._SQLI_PRIMITIVES is before and applier.applied_rules == []


def test_validate_regex_guard():
    assert validate_regex(r"\bselect\b", 100) is None
    assert "ReDoS" in validate_regex(r"(x*)*y", 100)
    assert "longer" in validate_regex("a" * 101, 100)
    assert "non-empty" in validate_regex("   ", 100)


def test_patchable_allowlist_is_explicit_and_resolvable():
    from aegis.evolve.registry import resolve
    assert len(PATCHABLE) == 6
    for target in PATCHABLE:
        module, attr = resolve(target)
        assert hasattr(module, attr)
    assert "aegis.agents.response.agent._ALWAYS_HITL_ACTIONS" not in PATCHABLE  # policy is never feed-mutable


class FakeFeedServer:
    def __init__(self, version="v1", rules=None, *, fail=False):
        self.version, self.rules, self.fail = version, rules if rules is not None else [_rule()], fail
        self.calls = 0

    def __call__(self, method, url, body, headers, timeout):
        self.calls += 1
        assert method == "GET" and url.endswith("/api/soc/rules") and headers.get("X-API-Key") == "k3y"
        if self.fail:
            raise ConnectionError("down")
        return {"version": self.version, "count": len(self.rules), "rules": self.rules}


def test_feed_sync_applies_once_per_version_and_survives_outages():
    import aegis.agents.perimeter.tools as perim
    srv = FakeFeedServer()
    feed = RuleFeed("https://dash.test", "k3y", transport=srv)
    rep = feed.sync()
    assert rep.applied == ["SP-1"] and "waitfor delay" in perim._SQLI_PRIMITIVES
    rep2 = feed.sync()
    assert rep2.applied == [] and rep2.already == ["SP-1"]        # same version → no work
    srv.version, srv.rules = "v2", [_rule(), _rule(rid="SP-9", add="xp_dirtree")]
    rep3 = feed.sync()
    assert rep3.applied == ["SP-9"] and rep3.already == ["SP-1"] and feed.applier.version == "v2"
    srv.fail = True
    assert feed.sync() is None and feed.last_error.startswith("ConnectionError")
    assert "xp_dirtree" in perim._SQLI_PRIMITIVES                 # last good rules stay in force
    feed.applier.revert_all()


def test_sync_from_env(monkeypatch):
    monkeypatch.delenv("ACP_DASHBOARD_URL", raising=False)
    assert sync_from_env() is None
    monkeypatch.setenv("ACP_DASHBOARD_URL", "https://dash.test")
    monkeypatch.setenv("ACP_API_KEY", "k3y")
    monkeypatch.setenv("AEGIS_RULE_FEED", "0")
    assert sync_from_env() is None
    monkeypatch.setenv("AEGIS_RULE_FEED", "1")
    import aegis.evolve.feed as feedmod
    monkeypatch.setattr(feedmod, "_shared_feed", None)
    rep = sync_from_env(transport=FakeFeedServer(rules=[_rule(rid="SP-env", add="xp_regread")]))
    assert rep is not None and rep.applied == ["SP-env"]
    feedmod._shared_feed.applier.revert_all()
