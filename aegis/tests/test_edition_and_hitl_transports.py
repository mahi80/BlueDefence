"""Editions (external | soc | full) and the HITL transports that make the external edition dashboard-free."""

import json

import pytest

from aegis.agents.shared.evidence_chain import EvidenceChain, RecommendedAction
from aegis.edition import EditionError, apply_edition, current, feature_matrix, validate, warnings
from aegis.hitl import FileHITL, ServiceNowHITL, hitl_from_env


def _chain(aid="web-1"):
    c = EvidenceChain(alert_id=aid, investigated_by="perimeter", verdict="malicious", confidence=0.91)
    c.recommended_actions.append(RecommendedAction(action_type="block", target="203.0.113.7", reasoning="stuffing", requires_hitl=True, confidence=0.9))
    return c.finalize()


class Resp:
    def __init__(self):
        self.approved = []

    def approve(self, action, approver, source_alert_id):
        self.approved.append((action.action_type, approver, source_alert_id)); return {"status": "executed"}


# ---- editions

def test_edition_defaults_and_contradictions():
    env = {"AEGIS_EDITION": "external"}
    ed = apply_edition(env)
    assert ed.name == "external" and env["ACP_GOVERN"] == "0" and env["AEGIS_PERSIST"] == "0" and env["AEGIS_HITL_TRANSPORT"] == "file"
    assert "AEGIS_SOURCES" not in env                                                  # the registry default (sample) is kept
    for bad in ({"AEGIS_EDITION": "external", "ACP_DASHBOARD_URL": "https://d"}, {"AEGIS_EDITION": "external", "ACP_GOVERN": "1"},
                {"AEGIS_EDITION": "external", "AEGIS_SOURCES": "waf,acp"}, {"AEGIS_EDITION": "soc", "ACP_GOVERN": "1", "ACP_DASHBOARD_URL": "https://d"},
                {"AEGIS_EDITION": "external", "AEGIS_HITL_TRANSPORT": "dashboard"}, {"AEGIS_EDITION": "external", "AEGIS_HITL_TRANSPORT": "servicenow"},
                {"AEGIS_EDITION": "nope"}):
        with pytest.raises(EditionError):
            apply_edition(dict(bad))
    env = {"AEGIS_EDITION": "full", "ACP_DASHBOARD_URL": "https://d"}
    assert apply_edition(env).bridge and env["ACP_GOVERN"] == "1" and env["AEGIS_HITL_TRANSPORT"] == "dashboard"
    env = {"AEGIS_EDITION": "soc"}
    assert validate(env) == [] and warnings(env) and "stdout card" in warnings(env)[0]   # allowed, degraded, logged
    assert apply_edition(env, strict=False).name == "soc"
    assert current({}).name == "external"                                   # standalone by default
    assert current({"ACP_DASHBOARD_URL": "https://d"}).name == "full"     # an integrated install keeps full
    rows = feature_matrix()
    assert [r["edition"] for r in rows] == ["external", "soc", "full"] and not rows[0]["sdk_in_customer_agents"] and rows[2]["bridge_q_to_aegis"]
    assert all(r["local_audit_jsonl"] and r["connectors_waf_soar"] for r in rows)


# ---- servicenow

class SNow:
    def __init__(self):
        self.calls = []; self.records = {}; self.fail = False

    def __call__(self, method, url, body, headers, timeout):
        self.calls.append((method, url, body, headers))
        if self.fail:
            raise ConnectionError("instance down")
        if method == "POST":
            sid = f"sys{len(self.records) + 1}"; self.records[sid] = {"sys_id": sid, "state": {"display_value": "New"}, **body}
            return 201, {"result": self.records[sid]}
        sid = url.split("/incident/")[1].split("?")[0]
        if method == "PATCH":
            self.records[sid].update(body); return 200, {"result": self.records[sid]}
        return 200, {"result": self.records[sid]}


def test_servicenow_files_polls_and_annotates():
    sn = SNow(); h = ServiceNowHITL("https://bank.service-now.com", user="svc", password="p", transport=sn, assignment_group="SOC L2")
    assert h.enabled and h.name == "servicenow"
    c = _chain(); aid = h.request(c.recommended_actions[0], c)
    assert aid and aid.startswith("aegis_web-1_block_") and h.pending[0].external_id == "sys1"
    m, url, body, headers = sn.calls[0]
    assert m == "POST" and url.endswith("/api/now/table/incident") and headers["Authorization"].startswith("Basic ")
    assert body["urgency"] == "1" and body["u_aegis_approval_id"] == aid and body["assignment_group"] == "SOC L2" and "203.0.113.7" in body["short_description"]
    assert h.request(c.recommended_actions[0], c) == aid                                   # idempotent per (alert, action, target)
    r = Resp()
    assert h.sync(r) == [] and r.approved == []                                             # still New
    assert h.attach_investigation("web-1", {"blast_radius": {"nodes_reached": 4, "critical": [{"id": "cbs-db"}]},
                                            "plan": {"steps": [{"n": 1, "action": "block", "target": "203.0.113.7", "hitl": True, "why": "w"}]},
                                            "twin": {"exposure": 0.7, "with_plan": 0.1, "plan_effectiveness": 0.86}}) == 1
    assert "cbs-db" in sn.records["sys1"]["work_notes"] and "plan stops 86 %" in sn.records["sys1"]["work_notes"]
    # the analyst decides in ServiceNow via the custom field
    sn.records["sys1"]["u_aegis_decision"] = "approved"; sn.records["sys1"]["u_aegis_decided_by"] = {"display_value": "Priya (SOC L2)"}
    d = h.sync(r)
    assert len(d) == 1 and d[0].status == "approved" and d[0].decided_by == "Priya (SOC L2)" and r.approved[0] == ("block", "Priya (SOC L2)", "web-1")
    assert h.pending == [] and h.decisions[-1].executed == {"status": "executed"}
    # ...or by resolving the record with a close code
    c2 = _chain("web-2"); h.request(c2.recommended_actions[0], c2)
    sn.records["sys2"].update({"state": {"display_value": "Closed"}, "close_code": {"display_value": "Rejected - not an incident"}, "close_notes": "pen-test window",
                               "closed_by": {"display_value": "Arun"}})
    d = h.sync(r)
    assert d[0].status == "rejected" and d[0].decided_by == "Arun" and d[0].reason == "pen-test window"


def test_servicenow_outage_falls_back_to_stdout_card_and_keeps_pending():
    sn = SNow(); h = ServiceNowHITL("https://bank.service-now.com", token="t", transport=sn)
    c = _chain(); aid = h.request(c.recommended_actions[0], c)
    sn.fail = True
    assert h.sync(Resp()) == [] and len(h.pending) == 1                                     # poll failure keeps the card pending
    c3 = _chain("web-3")
    assert h.request(c3.recommended_actions[0], c3) is None                                 # file failure → stdout card fallback, no crash
    assert not ServiceNowHITL("", transport=sn).enabled


# ---- file queue

def test_file_transport_round_trip_with_slack_notify(tmp_path):
    posts = []
    h = FileHITL(tmp_path / "hitl", slack_webhook="https://hooks.slack.test/x", slack_post=lambda url, payload, t: posts.append(payload))
    c = _chain(); aid = h.request(c.recommended_actions[0], c)
    cards = [json.loads(l) for l in (tmp_path / "hitl" / "cards.jsonl").read_text().splitlines()]
    assert cards[0]["kind"] == "approval" and cards[0]["id"] == aid and cards[0]["args"]["verdict"] == "malicious"
    assert posts and aid in posts[0]["text"]
    r = Resp()
    assert h.sync(r) == []
    with (tmp_path / "hitl" / "decisions.jsonl").open("a") as f:
        f.write("not json\n")
        f.write(json.dumps({"approval_id": "someone-else", "status": "approved"}) + "\n")
        f.write(json.dumps({"approval_id": aid, "status": "weird"}) + "\n")
    assert h.sync(r) == []                                                                  # malformed / unknown ignored, card stays pending
    with (tmp_path / "hitl" / "decisions.jsonl").open("a") as f:
        f.write(json.dumps({"approval_id": aid, "status": "approved", "decided_by": "ops@bank", "reason": ""}) + "\n")
    d = h.sync(r)
    assert d[0].status == "approved" and d[0].decided_by == "ops@bank" and r.approved[0][0] == "block"
    assert h.attach_investigation("web-1", {"plan": {}}) == 0                                # nothing pending any more
    c2 = _chain("web-2"); h.request(c2.recommended_actions[0], c2)
    assert h.attach_investigation("web-2", {"plan": {"steps": []}}) == 1
    assert any(json.loads(l)["kind"] == "investigation" for l in (tmp_path / "hitl" / "cards.jsonl").read_text().splitlines())
    # slack down is notify-only
    h2 = FileHITL(tmp_path / "hitl2", slack_webhook="https://hooks.slack.test/x", slack_post=lambda *a: (_ for _ in ()).throw(ConnectionError("x")))
    assert h2.request(c.recommended_actions[0], c)


def test_hitl_from_env_dispatch(monkeypatch, tmp_path):
    for k in ("AEGIS_HITL_TRANSPORT", "ACP_DASHBOARD_URL", "AEGIS_SERVICENOW_URL", "AEGIS_HITL_DIR"):
        monkeypatch.delenv(k, raising=False)
    assert hitl_from_env() is None
    monkeypatch.setenv("ACP_DASHBOARD_URL", "https://d"); assert hitl_from_env().name == "dashboard"
    monkeypatch.setenv("AEGIS_HITL_TRANSPORT", "file"); monkeypatch.setenv("AEGIS_HITL_DIR", str(tmp_path)); assert hitl_from_env().name == "file"
    monkeypatch.setenv("AEGIS_HITL_TRANSPORT", "servicenow"); assert hitl_from_env() is None          # no URL → stdout
    monkeypatch.setenv("AEGIS_SERVICENOW_URL", "https://s"); assert hitl_from_env().name == "servicenow"
    monkeypatch.setenv("AEGIS_HITL_TRANSPORT", "stdout"); assert hitl_from_env() is None
    monkeypatch.setenv("AEGIS_HITL_TRANSPORT", "bogus"); assert hitl_from_env() is None


def test_external_edition_pipeline_runs_without_dashboard_or_sdk(tmp_path, monkeypatch):
    """The product boundary: AEGIS External handles alerts end to end with nothing of ours outside the SOC host."""
    import io
    from aegis.service import build_pipeline, run_cycle
    for k in ("ACP_DASHBOARD_URL", "ACP_API_KEY", "ACP_GOVERN", "AEGIS_HITL_TRANSPORT", "AEGIS_SOURCES", "AEGIS_PERSIST", "AEGIS_RULE_FEED"):
        monkeypatch.delenv(k, raising=False)
    for k, v in {"AEGIS_EDITION": "external", "LLM_BACKEND": "mock", "AEGIS_SWARM": "1", "AEGIS_INVESTIGATE": "1", "AEGIS_TWIN": "0",
                 "AEGIS_HITL_DIR": str(tmp_path / "hitl"), "AEGIS_INTEL_MOCK": "1", "AEGIS_PII_TOKENIZATION": "0",
                 "AEGIS_WAF_VENDOR": "mock", "AEGIS_SOAR_VENDOR": "mock"}.items():
        monkeypatch.setenv(k, v)
    p = build_pipeline(tmp_path / "audit.jsonl", include_mock_intel=True)
    p.response._hitl_stream = io.StringIO()
    assert p.edition == "external" and p.governed is None and p.persist_sink is None and p.rules_report is None
    assert p.response._hitl.name == "file" and p.banner().startswith("[external]") and "ungoverned brain" in p.banner()
    from aegis.eval.fault_injection import _eval_alerts
    stats = run_cycle(p, iter(_eval_alerts(20)), sweep=True); p.investigator.drain(30)
    assert stats.errors == 0 and sum(stats.verdicts.values()) == 20 and stats.hitl_queued >= 1
    cards = (tmp_path / "hitl" / "cards.jsonl").read_text().splitlines()
    assert any(json.loads(l)["kind"] == "approval" for l in cards) and any(json.loads(l)["kind"] == "investigation" for l in cards)
    assert (tmp_path / "audit.jsonl").exists()
