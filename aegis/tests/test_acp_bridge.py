"""Q ↔ AEGIS bridge: governance events become SOC alerts; KEV/NVD becomes dashboard advisories."""

import json
import os

from aegis.agents.threat_intel.publish import advisories_from_intel, advisory_from, publish_to_dashboard
from aegis.ingest.acp import AcpGovernanceConsumer
from aegis.ingest.base import AlertCheckpoint

EVENTS_PAGE1 = {"events": [
    {"id": "rogue:ma_1", "kind": "rogue_alert", "ts": "2026-10-22T06:00:00", "severity": "CRITICAL", "issue_type": "infra_attack",
     "title": "Agent attacked infra", "message": "link-local metadata endpoint probed 14 times", "context": {"destination": "169.254.169.254", "count": 14},
     "agent_id": "ag_1", "agent_code": "LEN-LOA-01", "agent_name": "loan originator", "framework": "langgraph", "bu": "Lending",
     "endpoint": "https://loan.acpgovernance.com", "paused": True},
    {"id": "block:au_1", "kind": "governance_block", "ts": "2026-10-22T06:00:10", "severity": "CRITICAL", "control_code": "ACP-737",
     "tool_name": "http.get", "reason": "Q37_INFRA_GUARD (ACP-737): cloud metadata endpoint denied", "args": {"url": "http://169.254.169.254/latest/meta-data/"},
     "agent_id": "ag_1", "agent_code": "LEN-LOA-01", "framework": "langgraph", "bu": "Lending", "endpoint": "https://loan.acpgovernance.com"},
], "count": 2, "next_since": "2026-10-22T06:00:10"}
EVENTS_PAGE2 = {"events": [
    {"id": "pause:ag_1:2026-10-22T06:00:11", "kind": "agent_paused", "ts": "2026-10-22T06:00:11", "severity": "CRITICAL",
     "reason": "infra_attack: metadata endpoint", "paused_by": "rogue_auto_pause", "agent_id": "ag_1", "agent_code": "LEN-LOA-01",
     "framework": "langgraph", "bu": "Lending", "endpoint": "https://loan.acpgovernance.com", "paused": True},
], "count": 1, "next_since": "2026-10-22T06:00:11"}


class Dash:
    def __init__(self, fail=False):
        self.calls = []; self.fail = fail

    def __call__(self, method, url, body, headers, timeout):
        self.calls.append((method, url, headers))
        if self.fail:
            raise ConnectionError("down")
        if "since=2026-10-22T06%3A00%3A10" in url:
            return 200, json.dumps(EVENTS_PAGE2)
        if "since=2026-10-22T06%3A00%3A11" in url:
            return 200, json.dumps({"events": [], "count": 0, "next_since": "2026-10-22T06:00:11"})
        return 200, json.dumps(EVENTS_PAGE1)


def test_consumer_pages_normalises_and_dedups(tmp_path):
    d = Dash(); cp = AlertCheckpoint(tmp_path / "cp.json")
    c = AcpGovernanceConsumer("https://dash.test", "k", checkpoint=cp, transport=d)
    alerts = list(c.iter_alerts())
    assert [a["id"] for a in alerts] == ["ACP-rogue-ma_1", "ACP-block-au_1", "ACP-pause-ag_1-2026-10-22T06-00-11"]
    assert all(h["X-API-Key"] == "k" for _, _, h in d.calls) and len(d.calls) == 3          # two pages + the empty tail
    rogue, block, pause = alerts
    assert rogue["source"] == "ACP/rogue_alert" and rogue["severity"] == "critical" and rogue["anomaly_score"] > 0.9
    assert rogue["destination"] == "169.254.169.254" and rogue["suggested_specialist"] == "cloud_controlplane" and rogue["techniques"] == ["T1552.005"]
    assert rogue["host"] == "loan.acpgovernance.com" and rogue["agent_framework"] == "langgraph" and rogue["governed_agent"] and rogue["agent_paused"]
    assert block["control_code"] == "ACP-737" and block["blocked"] and block["url"].startswith("http://169.254") and "Q37" in block["title"]
    assert pause["paused_by"] == "rogue_auto_pause" and pause["techniques"] == ["T1562.001"]
    assert "message" not in rogue["raw"] and "payload" in rogue and "note" in rogue
    # watermark persisted; a second poll yields nothing new
    assert cp.watermark("acp") == "2026-10-22T06:00:11"
    c2 = AcpGovernanceConsumer("https://dash.test", "k", checkpoint=AlertCheckpoint(tmp_path / "cp.json"), transport=Dash())
    assert list(c2.iter_alerts()) == []


def test_consumer_outage_and_refusal_are_loud(tmp_path):
    """Review E13: an outage / 401 is a failed source the cycle counts, not a clean empty poll."""
    import pytest

    from aegis.ingest.acp import AcpFeedError
    c = AcpGovernanceConsumer("https://dash.test", "k", checkpoint=AlertCheckpoint(), transport=Dash(fail=True))
    with pytest.raises(AcpFeedError):
        list(c.iter_alerts())
    assert c.last_error.startswith("ConnectionError")
    refuse = lambda m, u, b, h, t: (401, '{"error":"bad api key"}')     # noqa: E731
    c = AcpGovernanceConsumer("https://dash.test", "k", checkpoint=AlertCheckpoint(), transport=refuse)
    with pytest.raises(AcpFeedError, match="401"):
        list(c.iter_alerts())
    assert not AcpGovernanceConsumer("", "", checkpoint=AlertCheckpoint()).configured


def test_registry_wires_acp_source(monkeypatch, tmp_path):
    from aegis.ingest.registry import sources_from_env
    monkeypatch.setenv("AEGIS_SOURCES", "acp"); monkeypatch.setenv("AEGIS_CHECKPOINT", str(tmp_path / "c.json"))
    monkeypatch.delenv("ACP_DASHBOARD_URL", raising=False)
    assert sources_from_env() == []                                                  # unconfigured → skipped with a warning
    monkeypatch.setenv("ACP_DASHBOARD_URL", "https://dash.test")
    out = sources_from_env()
    assert len(out) == 1 and out[0][0] == "acp"


def test_rogue_agent_event_runs_through_the_whole_pipeline(tmp_path, monkeypatch):
    """The point of the bridge: a paused LangGraph agent gets a verdict, a blast radius, a plan and a HITL card."""
    from aegis.service import build_pipeline, run_cycle
    for k, v in {"LLM_BACKEND": "mock", "AEGIS_SWARM": "1", "AEGIS_INVESTIGATE": "1", "AEGIS_TWIN": "0", "AEGIS_CAMPAIGN_CONTEXT": "1",
                 "AEGIS_ENFORCEMENT_MODE": "shadow", "AEGIS_INTEL_MOCK": "1", "ACP_GOVERN": "0", "AEGIS_PII_TOKENIZATION": "0"}.items():
        monkeypatch.setenv(k, v)
    monkeypatch.delenv("ACP_DASHBOARD_URL", raising=False)
    import io
    p = build_pipeline(tmp_path / "audit.jsonl", include_mock_intel=True)
    p.response._hitl_stream = io.StringIO()
    c = AcpGovernanceConsumer("https://dash.test", "k", checkpoint=AlertCheckpoint(), transport=Dash())
    alerts = list(c.iter_alerts())
    stats = run_cycle(p, iter(alerts), sweep=True)
    p.investigator.drain(30)
    assert stats.alerts == 3 and stats.errors == 0 and sum(stats.verdicts.values()) == 3
    rows = [json.loads(l) for l in (tmp_path / "audit.jsonl").read_text().splitlines() if l.strip()]
    chains = {r.get("chain", r)["alert_id"]: r.get("chain", r) for r in rows}
    rogue, block, pause = chains["ACP-rogue-ma_1"], chains["ACP-block-au_1"], chains["ACP-pause-ag_1-2026-10-22T06-00-11"]
    assert rogue["verdict"] == "malicious" and block["verdict"] == "malicious" and pause["verdict"] == "malicious"   # control-plane facts, not LLM opinions
    assert all(c["investigated_by"] == "control_plane" and c["metadata"]["control_plane"]["confirmed"] for c in (rogue, block, pause))
    assert any(a["action_type"] == "rotate_credential" and a["requires_hitl"] for a in rogue["recommended_actions"])
    assert not any(a["action_type"] == "isolate" for a in rogue["recommended_actions"])                               # already paused
    assert p.investigator.status("ACP-rogue-ma_1")["state"] == "done"
    assert "blast_graph" in rogue["metadata"] and "mitigation_plan" in rogue["metadata"]
    assert any(a["requires_hitl"] for a in rogue["recommended_actions"]) or stats.hitl_queued >= 1


# ---- publisher

class _Kev:
    def __init__(self, cve, product, vendor="x", ransomware=False):
        self.cve_id, self.product, self.vendor, self.name, self.date_added, self.due_date, self.ransomware, self.cwes, self.action = \
            cve, product, vendor, f"{product} RCE", "2026-10-20", "2026-11-10", ransomware, ("CWE-94",), "Patch."


class _Aff:
    def __init__(self, product): self.product = product; self.vendor = "v"


class _Rec:
    def __init__(self, cve, products, cvss=None, kev=None, cwes=(), desc="d", published="2026-10-01"):
        self.cve_id, self.affected, self.cvss, self.kev, self.cwes, self.description, self.published, self.epss = \
            cve, tuple(_Aff(p) for p in products), cvss, kev, cwes, desc, published, 0.5


class _Intel:
    def __init__(self, cves, kev_only=()):
        self.cves = {r.cve_id: r for r in cves}
        self.kev = {k.cve_id: k for k in kev_only}
        self._kev_only = {k.cve_id: k for k in kev_only}

    def get(self, cid):
        if cid in self.cves:
            return self.cves[cid]
        k = self._kev_only.get(cid)
        return _Rec(cid, [k.product], kev=k, published=k.date_added) if k else None


def test_advisories_only_for_agent_runtime_products_and_shape():
    intel = _Intel([
        _Rec("CVE-2026-0001", ["langchain-core"], cvss=9.8, cwes=("CWE-502",), kev=_Kev("CVE-2026-0001", "langchain", ransomware=True)),
        _Rec("CVE-2026-0002", ["fastapi"], cvss=5.3, cwes=("CWE-918",)),
        _Rec("CVE-2026-0003", ["some_random_router"], cvss=9.9),                       # not an agent-runtime product → not published
        _Rec("CVE-2026-0004", ["model_context_protocol_sdk"], cvss=7.5),
    ], kev_only=[_Kev("CVE-2025-0009", "LlamaIndex")])
    advs = advisories_from_intel(intel)
    ids = [a["id"] for a in advs]
    assert set(ids[:2]) == {"KEV-CVE-2026-0001", "KEV-CVE-2025-0009"} and "NVD-CVE-2026-0003" not in ids      # KEV first
    a = next(x for x in advs if x["id"] == "KEV-CVE-2026-0001")
    assert a["severity"] == "CRITICAL" and a["affects_frameworks"] == ["langchain"] and a["category"] == "supply_chain" and a["ransomware"]
    assert a["summary"].startswith("[CISA KEV since 2026-10-20, remediate by 2026-11-10, ransomware") and a["url"].endswith("CVE-2026-0001")
    mcp = next(x for x in advs if x["id"] == "NVD-CVE-2026-0004")
    assert mcp["affects_frameworks"] == ["mcp"] and mcp["affects_mcp_servers"] == ["*"] and mcp["severity"] == "HIGH"
    fast = next(x for x in advs if x["id"] == "NVD-CVE-2026-0002")
    assert fast["category"] == "ssrf" and fast["acp_control"] == "Q37" and fast["severity"] == "MEDIUM"
    assert advisory_from(_Rec("CVE-1", ["nothing"])) is None


def test_publish_posts_with_api_key_and_survives_failure(monkeypatch):
    intel = _Intel([_Rec("CVE-2026-0002", ["fastapi"], cvss=5.3)])
    sent = []
    res = publish_to_dashboard(intel, dashboard_url="https://dash.test", api_key="k",
                               transport=lambda url, body, headers, t: sent.append((url, body, headers)) or {"status": "ok", "created": 1, "updated": 0, "rejected": 0})
    assert res["published"] == 1 and res["created"] == 1
    url, body, headers = sent[0]
    assert url.endswith("/api/cyber-risk/threat-intel/ingest") and headers["X-API-Key"] == "k" and body["advisories"][0]["id"] == "NVD-CVE-2026-0002"
    bad = publish_to_dashboard(intel, dashboard_url="https://dash.test", api_key="k", transport=lambda *a: (_ for _ in ()).throw(ConnectionError("down")))
    assert bad["published"] == 0 and "ConnectionError" in bad["error"]
    monkeypatch.delenv("ACP_DASHBOARD_URL", raising=False)
    assert publish_to_dashboard(intel, dashboard_url="")["skipped"] == "no ACP_DASHBOARD_URL"


def test_control_plane_fast_path_rules():
    from aegis.agents.orchestrator.control_plane import control_plane_chain, is_control_plane_fact
    assert not is_control_plane_fact({"alert_type": "governance_block"})                                   # not from a governed agent → normal triage
    assert is_control_plane_fact({"governed_agent": True, "alert_type": "governance_block", "control_code": "ACP-730"})
    assert not is_control_plane_fact({"governed_agent": True, "alert_type": "rogue_alert", "severity": "medium", "issue_type": "budget_runaway"})
    assert is_control_plane_fact({"governed_agent": True, "alert_type": "rogue_alert", "severity": "high", "issue_type": "undeclared_subagent"})
    c = control_plane_chain({"id": "x", "governed_agent": True, "alert_type": "governance_block", "control_code": "ACP-730", "agent_id": "A", "tool_name": "shell.exec"})
    assert c.verdict == "suspicious" and c.confidence == 0.75 and [a.action_type for a in c.recommended_actions] == ["escalate"]
    c = control_plane_chain({"id": "y", "governed_agent": True, "alert_type": "governance_block", "control_code": "ACP-737", "agent_id": "A", "destination": "169.254.169.254"})
    assert c.verdict == "malicious" and [a.action_type for a in c.recommended_actions] == ["escalate", "isolate", "rotate_credential"]
    assert all(a.requires_hitl for a in c.recommended_actions) and c.completed_at is not None
