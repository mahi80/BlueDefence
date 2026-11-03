"""Round-4 review, group H2: human decisions land, bind to the right action, and are never overruled by the timer."""

from __future__ import annotations

import io
import json
import time
from urllib.parse import quote

import pytest

from aegis.agents.response.agent import ResponseAgent
from aegis.agents.response.autonomy import AutonomyPolicy
from aegis.agents.response.breaker import OutflowBreaker
from aegis.agents.response.connectors.base import ConnectorRegistry, LoggingConnector
from aegis.agents.response.hitl_timeout import HitlTimeoutPolicy
from aegis.agents.shared.evidence_chain import EvidenceChain, RecommendedAction
from aegis.hitl.base import BaseHITL


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.setenv("AEGIS_HITL_STATE", "off")
    monkeypatch.setenv("AEGIS_CONSOLE_TOKEN", "tok-for-tests")
    monkeypatch.delenv("AEGIS_ENFORCEMENT_MODE", raising=False)


def _chain(aid="A1", verdict="malicious", conf=0.92, by="perimeter", **md):
    c = EvidenceChain(alert_id=aid, investigated_by=by, verdict=verdict, confidence=conf)
    c.metadata.update(md)
    return c


def _act(t, target, hitl=False, conf=0.95):
    return RecommendedAction(action_type=t, target=target, reasoning="r", requires_hitl=hitl, confidence=conf)


def _agent(**kw):
    kw.setdefault("connectors", ConnectorRegistry([], fallback=LoggingConnector(dry_run=False)))
    kw.setdefault("hitl_stream", io.StringIO())
    kw.setdefault("autonomy", AutonomyPolicy(mode="off"))
    kw.setdefault("breaker", OutflowBreaker(mode="off"))
    kw.setdefault("hitl_timeout", HitlTimeoutPolicy(mode="off"))
    return ResponseAgent(**kw)


# ---- R4-2: a decision on a long target binds to the full action, and a mismatched one holds the card -----------------

def test_reject_on_a_long_target_lands_and_the_timer_never_runs_it(tmp_path):
    from aegis.hitl.filequeue import FileHITL
    from aegis.ingest.console_api import ConsoleAPI
    h = FileHITL(tmp_path, state_path="off")
    ra = _agent(hitl=h, hitl_timeout=HitlTimeoutPolicy(mode="live", wait_sec=120))
    ua = "python-requests/2.31.0 (" + "x" * 300 + ")"
    target = f"fp:ja4:t13d1516h2_8daaf6152771_02713d6af862;ua:{quote(ua)}"
    c = _chain(vote_concur=True)
    c.recommended_actions.append(_act("block", target))
    ra.execute(c, {"id": "A1", "src_ip": "198.51.100.7", "ja4": "t13d1516h2_8daaf6152771_02713d6af862", "user_agent": ua})
    p = h.pending[0]
    assert len(target) > 256
    assert ConsoleAPI(None, tmp_path).decide(p.approval_id, "rejected", decided_by="analyst:alice")[0] == 200
    (d,) = ra.sync_hitl()
    assert d.status == "rejected" and d.decided_by == "analyst:alice"


def test_a_decision_naming_another_action_holds_the_card(tmp_path):
    from aegis.hitl.filequeue import FileHITL
    from aegis.hitl.signing import sign
    h = FileHITL(tmp_path, state_path="off")
    ra = _agent(hitl=h, hitl_timeout=HitlTimeoutPolicy(mode="live", wait_sec=120))
    c = _chain(vote_concur=True)
    c.recommended_actions.append(_act("block", "198.51.100.7"))
    ra.execute(c, {"id": "A1", "src_ip": "198.51.100.7"})
    p = h.pending[0]
    with (tmp_path / "decisions.jsonl").open("a") as f:
        f.write(json.dumps(sign({"approval_id": p.approval_id, "status": "rejected", "decided_by": "analyst:alice",
                                 "ts": time.time(), "action": "block -> 198.51.100.8"})) + "\n")
    assert ra.sync_hitl() == []
    p.requested_at -= 600
    assert ra.sync_hitl() == [] and h.pending and not h.pending[0].timeout_ok


# ---- R4-6: one ServiceNow user is not two people ----------------------------------------------------------------------

def _snow(state, user="svc_aegis"):
    from aegis.hitl.servicenow import ServiceNowHITL

    def transport(method, url, body, headers, timeout):
        if method == "POST":
            return 201, {"result": {"sys_id": "abc123", "sys_created_by": user}}
        if method == "GET":
            return 200, {"result": dict(state)}
        state["sys_updated_by"] = user
        return 200, {"result": {"sys_updated_by": user}}
    return ServiceNowHITL("https://bank.service-now.com", user=user, password="x", transport=transport, state_path="off")


def test_servicenow_free_text_decider_does_not_make_a_second_approver():
    state = {"u_aegis_decision": "", "u_aegis_decided_by": "", "sys_updated_by": ""}
    h = _snow(state)
    ra = _agent(hitl=h, protected_targets=["db-core*"])
    c = _chain(by="edr", conf=0.9)
    c.recommended_actions.append(_act("isolate", "host:db-core-01", hitl=True))
    ra.execute(c, {"id": "A1", "host": "db-core-01"})
    state.update(u_aegis_decision="approved", u_aegis_decided_by="mallory", sys_updated_by="mallory")
    assert ra.sync_hitl() == [] and h.pending[0].first_approver == "mallory"
    state.update(u_aegis_decided_by="ravi.ciso", sys_updated_by="mallory")
    assert ra.sync_hitl() == []
    h.attach_investigation("A1", {"plan": {"steps": []}})          # our own work note: AEGIS is not an approver
    assert state["sys_updated_by"] == "svc_aegis" and ra.sync_hitl() == []
    state.update(sys_updated_by="ravi.ciso")
    (d,) = ra.sync_hitl()
    assert d.decided_by == "mallory+ravi.ciso"


# ---- R4-7: an approval that has not run yet can still be rejected --------------------------------------------------------

def test_reject_after_an_approval_that_hit_the_rate_cap(tmp_path, monkeypatch):
    from aegis.hitl.filequeue import FileHITL
    from aegis.ingest.console_api import ConsoleAPI
    monkeypatch.setenv("AEGIS_HIGH_IMPACT_MAX", "0")
    h = FileHITL(tmp_path, state_path="off")
    ra = _agent(hitl=h)
    c = _chain(conf=0.8)
    c.recommended_actions.append(_act("block", "198.51.100.7", hitl=True))
    ra.execute(c, {"id": "A1", "src_ip": "198.51.100.7"})
    aid = h.pending[0].approval_id
    con = ConsoleAPI(None, tmp_path)
    con.decide(aid, "approved", decided_by="analyst:alice")
    assert ra.sync_hitl() == [] and h.pending[0].approved_by == "analyst:alice"
    assert con.decide(aid, "rejected", decided_by="analyst:alice", reason="false positive")[0] == 200
    ra._high_impact_max = 10
    (d,) = ra.sync_hitl()
    assert d.status == "rejected" and not ra.connectors.active_receipts


# ---- R4-9: the wait window starts when the card reaches people -------------------------------------------------------------

def test_refiled_card_gets_a_fresh_wait_window():
    class Flaky(BaseHITL):
        name, up = "flaky", False

        def _file(self, card):
            if not self.up:
                raise ConnectionError("dashboard down")
            return card["id"]

        def _poll(self, p):
            return None
    h = Flaky(state_path="off")
    ra = _agent(hitl=h, hitl_timeout=HitlTimeoutPolicy(mode="live", wait_sec=120))
    c = _chain(vote_concur=True)
    c.recommended_actions.append(_act("block", "198.51.100.7"))
    ra.execute(c, {"id": "A1", "src_ip": "198.51.100.7"})
    h.pending[0].requested_at -= 600
    h.up = True
    assert ra.sync_hitl() == [] and not h.pending[0].unfiled
    assert ra.sync_hitl() == []                                        # just filed: nobody has had 120 s yet


# ---- R4-10: allow / monitor in live mode are not approval cards ----------------------------------------------------------

def test_live_mode_allow_and_monitor_do_not_file_cards(tmp_path, monkeypatch):
    from aegis.hitl.filequeue import FileHITL
    monkeypatch.setenv("AEGIS_ENFORCEMENT_MODE", "live")
    h = FileHITL(tmp_path, state_path="off")
    ra = _agent(hitl=h)
    for i, t in enumerate(("allow", "monitor")):
        c = _chain(aid=f"B{i}", verdict="benign", conf=0.95)
        c.recommended_actions.append(_act(t, "198.51.100.7"))
        s = ra.execute(c, {"id": f"B{i}", "src_ip": "198.51.100.7"})
        assert len(s.executed) == 1 and not s.hitl_queue
    assert h.pending == []
    from aegis.agents.response.connectors.base import STATUS_UNSUPPORTED
    assert ConnectorRegistry([]).apply(_act("disable_account", "u_1")).status == STATUS_UNSUPPORTED


# ---- R4-12: an expired dashboard card is settled, never timed out into a run ------------------------------------------------

@pytest.mark.parametrize("mode", ["off", "live"])
def test_dashboard_expired_settles(mode):
    from aegis.hitl.dashboard import DashboardHITL

    def transport(method, url, body, headers, timeout):
        return {"approval_id": body["id"]} if url.endswith("/create") else {"status": "expired"}
    h = DashboardHITL("https://dash", api_key="k", transport=transport, state_path="off")
    ra = _agent(hitl=h, hitl_timeout=HitlTimeoutPolicy(mode=mode, wait_sec=120))
    c = _chain(vote_concur=True)
    c.recommended_actions.append(_act("block", "198.51.100.7"))
    ra.execute(c, {"id": "A1", "src_ip": "198.51.100.7"})
    h.pending[0].requested_at -= 86400
    (d,) = ra.sync_hitl()
    assert d.status == "expired" and h.pending == []


# ---- R4-13: pending approvals age out, and a slow channel cannot hold the service thread ------------------------------------

def test_pending_approvals_expire_by_default(monkeypatch):
    class Quiet(BaseHITL):
        name = "quiet"

        def _file(self, card):
            return card["id"]

        def _poll(self, p):
            return None
    h = Quiet(state_path="off")
    ra = _agent(hitl=h)
    c = _chain(conf=0.8)
    c.recommended_actions.append(_act("block", "198.51.100.7", hitl=True))
    ra.execute(c, {"id": "A1", "src_ip": "198.51.100.7"})
    assert ra.sync_hitl() == []
    h.pending[0].requested_at -= 8 * 86400
    (d,) = ra.sync_hitl()
    assert d.status == "expired"
    monkeypatch.setenv("AEGIS_HITL_MAX_AGE_S", "off")
    from aegis.agents.response.agent import _hitl_max_age_s
    assert _hitl_max_age_s() is None


def test_sync_stops_at_its_budget_and_rotates(monkeypatch):
    monkeypatch.setenv("AEGIS_HITL_SYNC_BUDGET_S", "0.05")
    polled = []

    class Slow(BaseHITL):
        name = "slow"

        def _file(self, card):
            return card["id"]

        def _poll(self, p):
            polled.append(p.approval_id)
            time.sleep(0.03)
    h = Slow(state_path="off")
    ra = _agent(hitl=h)
    for i in range(10):
        c = _chain(aid=f"A{i}", conf=0.8)
        c.recommended_actions.append(_act("block", f"198.51.100.{i + 1}", hitl=True))
        ra.execute(c, {"id": f"A{i}", "src_ip": f"198.51.100.{i + 1}"})
    ra.sync_hitl()
    first = list(polled)
    assert 1 <= len(first) < 10
    polled.clear()
    ra.sync_hitl()
    assert not set(first) & set(polled)                                # the next sync starts with the ones skipped
