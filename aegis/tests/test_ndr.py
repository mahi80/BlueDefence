"""Network sensor (NDR) egress detection: Zeek / Suricata TLS metadata → beacons, exfiltration,
known-bad TLS, shadow AI → the egress fast path.

All data is invented: RFC 1918 hosts, RFC 5737 servers, ``.example`` names, made-up hashes.
"""

from __future__ import annotations

import gzip
import json
import tempfile
import urllib.request
from pathlib import Path

import pytest

from aegis.agents.ndr import (
    AiRegister,
    AiUsageRegister,
    EgressDetector,
    TlsIntel,
    ai_service,
    beacon_stats,
    cert_flags,
    client_shape,
)
from aegis.agents.ndr.tls_intel import TlsIndicator
from aegis.agents.orchestrator.egress import (
    egress_chain,
    egress_verdict,
    is_egress_finding,
)
from aegis.agents.threat_intel.store import IOC, IOCStore
from aegis.ingest import AlertCheckpoint
from aegis.ingest.base import CONSUMED, BaseConsumer
from aegis.ingest.ndr import NdrConsumer, normalize, reset_shared_detector
from aegis.ingest.stream import StreamConsumer, StreamQueue, reset_stream

FIX = Path(__file__).resolve().parents[1] / "ingest" / "fixtures" / "ndr"
T = 1_792_648_800.0          # 2026-10-22T06:00:00Z
IMPLANT = "t12d0807h1_00000000000c_000000000a0c"
BROWSER = "t13d1516h2_000000000001_000000000a01"


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    for k in ("AEGIS_TLS_IOC_FILE", "AEGIS_AI_REGISTER", "AEGIS_SHADOW_AI_REGISTER", "AEGIS_INTERNAL_NETS", "AEGIS_NDR_ALLOW_DOMAINS",
              "AEGIS_NDR_ALLOW_HOSTS", "AEGIS_AI_PROVIDERS_EXTRA", "ANTHROPIC_API_KEY", "OPENAI_API_KEY", "AEGIS_INGEST_TOKEN",
              "AEGIS_SOURCES", "NDR_EVENT_FILE"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("LLM_BACKEND", "mock")
    monkeypatch.setenv("ACP_HOME", tempfile.mkdtemp())
    reset_shared_detector()
    reset_stream()
    from aegis.agents.ndr.ai_usage import reset_extra_providers
    reset_extra_providers()
    yield
    reset_shared_detector()
    reset_stream()


def tls(src, sni, t, *, dst="203.0.113.66", ja4=IMPLANT, uid="", **kw):
    return {"kind": "tls", "sensor": "zeek", "ts": t, "uid": uid, "src": src, "dst": dst, "dport": 443, "sni": sni, "ja4": ja4, **kw}


def conn(src, t, out_b, in_b, *, dst="203.0.113.66", uid="", sni=""):
    return {"kind": "conn", "sensor": "zeek", "ts": t, "uid": uid, "src": src, "dst": dst, "dport": 443, "bytes_out": out_b,
            "bytes_in": in_b, "tls": True, "sni": sni}


def feed(det, events):
    out = []
    for ev in events:
        out += det.observe(ev)
    return out


# ------------------------------------------------------------ normalise --

def test_zeek_ssl_conn_x509_and_nested_ids_and_iso_timestamps():
    ssl = {"_path": "ssl", "ts": T, "uid": "Cabc", "id.orig_h": "10.20.0.17", "id.orig_p": 50000, "id.resp_h": "203.0.113.66",
           "id.resp_p": 443, "version": "TLSv12", "server_name": "c2.example", "ja4": IMPLANT, "ja3": "abc",
           "cert_chain_fps": ["f" * 64], "validation_status": "self signed certificate"}
    ev = normalize(ssl)
    assert (ev["kind"], ev["src"], ev["dst"], ev["dport"], ev["sni"], ev["cert_fps"]) == ("tls", "10.20.0.17", "203.0.113.66", 443,
                                                                                           "c2.example", ["f" * 64])
    nested = {"ts": "2026-10-22T06:00:05Z", "uid": "Cabc", "id": {"orig_h": "10.20.0.17", "orig_p": 1, "resp_h": "203.0.113.66",
              "resp_p": 443}, "proto": "tcp", "service": "ssl", "orig_bytes": 700, "resp_bytes": 300, "conn_state": "SF"}
    ev = normalize(nested)
    assert ev["kind"] == "conn" and ev["ts"] == pytest.approx(T + 5) and ev["bytes_out"] == 700 and ev["tls"] is True
    x509 = {"_path": "x509", "ts": T, "fingerprint": "f" * 64, "certificate.subject": "CN=c2.example", "certificate.issuer": "CN=c2.example",
            "certificate.not_valid_before": T - 86400, "certificate.not_valid_after": T + 86400 * 3650, "san.dns": ["c2.example"]}
    ev = normalize(x509)
    assert ev["kind"] == "x509" and ev["sha256"] == "f" * 64 and ev["san"] == ["c2.example"]
    assert normalize({"_path": "dns", "ts": T, "id.orig_h": "10.0.0.1", "id.resp_h": "10.0.0.2", "query": "x"}) is None


def test_suricata_tls_and_flow_events_and_generic_proxy_records():
    t = {"timestamp": "2026-10-22T06:00:00.000000+0000", "flow_id": 42, "event_type": "tls", "src_ip": "10.20.0.17", "src_port": 5,
         "dest_ip": "203.0.113.66", "dest_port": 443, "tls": {"sni": "c2.example", "fingerprint": "aa:bb:cc", "ja3": {"hash": "j3"},
                                                              "ja4": IMPLANT, "subject": "CN=x", "issuerdn": "CN=x",
                                                              "notbefore": "2026-10-20T00:00:00"}}
    ev = normalize(t)
    assert ev["kind"] == "tls" and ev["ts"] == pytest.approx(T) and ev["cert_sha1"] == "aa:bb:cc" and ev["ja3"] == "j3"
    assert ev["not_before"] is not None
    f = {"timestamp": "2026-10-22T06:00:01.000000+0000", "flow_id": 42, "event_type": "flow", "src_ip": "10.20.0.17", "dest_ip": "203.0.113.66",
         "dest_port": 443, "app_proto": "tls", "flow": {"bytes_toserver": 900, "bytes_toclient": 100, "start": "2026-10-22T06:00:00.000000+0000",
                                                         "end": "2026-10-22T06:00:01.000000+0000"}}
    ev = normalize(f)
    assert ev["kind"] == "conn" and ev["uid"] == "42" and ev["bytes_out"] == 900 and ev["duration"] == pytest.approx(1.0)
    assert normalize({**f, "event_type": "alert"}) is None
    proxy = {"timestamp": "2026-10-22T06:00:00Z", "src_ip": "10.20.0.33", "dst_ip": "198.51.100.50", "host": "api.openai.com",
             "bytes_out": 500000, "bytes_in": 9000}
    ev = normalize(proxy)
    assert ev["kind"] == "flow" and ev["sni"] == "api.openai.com" and ev["bytes_out"] == 500000


# ------------------------------------------------------------- building --

def test_beacon_stats_separate_a_timer_from_a_person():
    reg = beacon_stats([T + 60 * i + (i % 3) for i in range(15)])
    assert reg["median_interval_s"] == pytest.approx(60, abs=2) and reg["jitter"] < 0.05
    irr = beacon_stats([T + x for x in (0, 7, 95, 130, 400, 410, 1300, 1320, 2000)])
    assert irr["jitter"] > 0.5
    assert beacon_stats([T]) is None


def test_certificate_oddities_and_wildcards():
    flags = {n for n, _, _ in cert_flags({"subject": "CN=c2.example,O=Internet Widgits Pty Ltd", "issuer": "CN=c2.example,O=Internet Widgits Pty Ltd",
                                          "not_before": T - 2 * 86400, "not_after": T + 3650 * 86400}, ts=T, sni="other.example")}
    assert {"default_subject", "self_signed", "fresh_cert", "name_mismatch"} <= flags and "long_validity" not in flags
    ok = cert_flags({"subject": "CN=*.bank.example", "issuer": "CN=Sample CA", "san": ["*.bank.example"], "not_before": T - 30 * 86400,
                     "not_after": T + 300 * 86400, "validation": "ok"}, ts=T, sni="api.bank.example")
    assert ok == []
    deep = cert_flags({"subject": "CN=*.bank.example", "issuer": "CN=Sample CA", "validation": "ok"}, ts=T, sni="a.b.bank.example")
    assert [n for n, _, _ in deep] == ["name_mismatch"]                          # a wildcard covers one label only


def test_client_shape_from_ja4():
    assert client_shape(BROWSER) == "browser" and client_shape(IMPLANT) == "library" and client_shape("junk") == "unknown"


def test_tls_intel_formats_and_match_priority(tmp_path):
    intel = TlsIntel()
    assert intel.load(FIX / "tls_ioc.sample.jsonl") == 3
    sslbl = TlsIntel()
    assert sslbl.load(FIX / "sslbl.sample.csv") == 1
    sha1 = next(iter(json.loads(ln) for ln in (FIX / "tls_ioc.sample.jsonl").read_text().splitlines() if ln.startswith("{")))["value"]
    colon = ":".join(sha1[i:i + 2] for i in range(0, 40, 2)).upper()
    hit = sslbl.match(cert_sha1=colon)                                        # Suricata writes SHA1 with colons
    assert hit and hit.kind == "cert_sha1" and hit.confirming and "SSLBL" in hit.source
    assert intel.match(sni="login.phish-kit.example").kind == "domain"         # parent domain
    assert intel.match(ja3="00000000000000000000000000000BAD").confirming is False
    ja3csv = tmp_path / "ja3.csv"
    ja3csv.write_text("# ja3_md5,Firstseen,Lastseen,Listingreason\nabcabcabcabcabcabcabcabcabcabcab,2026-01-01,2026-02-01,Sample\n")
    assert TlsIntel().load(ja3csv) == 1
    both = TlsIntel([TlsIndicator("ja4", IMPLANT, "x"), TlsIndicator("cert_sha256", "f" * 64, "y")])
    assert both.match(ja4=IMPLANT, cert_sha256="F" * 64).kind == "cert_sha256"   # the certificate outranks the client stack
    assert TlsIntel().match(sni="anything.example") is None


def test_ai_catalogue_and_register_statuses(tmp_path):
    for host, provider in (("api.openai.com", "openai"), ("bank-dev.openai.azure.com", "azure-openai"), ("claude.ai", "anthropic"),
                           ("bedrock-runtime.ap-south-1.amazonaws.com", "aws-bedrock"),
                           ("us-central1-aiplatform.googleapis.com", "google-vertex")):
        assert ai_service(host).provider == provider
    assert ai_service("www.bank.example") is None and ai_service("") is None
    reg = AiRegister.load(FIX / "ai_register.sample.csv")
    assert reg.status("10.20.0.99", "acmebank-prod.openai.azure.com") == ("approved", "AcmeBank enterprise Azure OpenAI tenant")
    assert reg.status("10.30.0.6", "api.anthropic.com") == ("unapproved", "LEN-LOA-01")
    assert reg.status("10.20.0.33", "api.openai.com") == ("unregistered", "")
    jl = tmp_path / "reg.jsonl"
    jl.write_text(json.dumps({"host": "10.40.0.0/24", "system": "fraud-scoring", "endpoints": [".openai.azure.com"]}) + "\n")
    r = AiRegister.load(jl)
    assert r.status("10.40.0.7", "fraud-eu.openai.azure.com") == ("registered", "fraud-scoring")
    assert r.status("10.40.0.7", "api.openai.com") == ("unapproved", "fraud-scoring")


# ------------------------------------------------------------- detector --

def _beacon(src, sni, n, every, *, dst="203.0.113.66", ja4=IMPLANT, start=0.0):
    return [tls(src, sni, T + start + every * i + (i % 2), dst=dst, ja4=ja4) for i in range(n)]


def test_a_rare_timer_is_a_beacon_and_a_popular_one_is_not():
    det = EgressDetector()
    alerts = feed(det, _beacon("10.20.0.17", "cdn-sync.example", 14, 60))
    assert [a["alert_type"] for a in alerts] == ["tls_beacon"]
    e = alerts[0]["egress"]
    assert e["rare"] and e["prevalence"] == 1 and e["beacon"]["jitter"] < 0.05 and e["client_shape"] == "library"
    assert alerts[0]["id"].startswith("ndr-tls_beacon-") and alerts[0]["severity"] == "medium"
    # the same timer on five hosts is an agent everyone runs
    det = EgressDetector()
    events = [ev for h in range(5) for ev in _beacon(f"10.20.0.{20 + h}", "telemetry.vendor.example", 14, 60, start=h)]
    assert feed(det, sorted(events, key=lambda e: e["ts"])) == []


def test_allowlists_direction_and_dedupe(monkeypatch):
    monkeypatch.setenv("AEGIS_NDR_ALLOW_DOMAINS", "vendor.example")
    monkeypatch.setenv("AEGIS_NDR_ALLOW_HOSTS", "10.20.0.99")
    det = EgressDetector()
    assert feed(det, _beacon("10.20.0.17", "cdn.vendor.example", 14, 60)) == []
    assert feed(det, _beacon("10.20.0.99", "rare.example", 14, 60)) == []
    assert feed(det, [tls("203.0.113.5", "x.example", T, dst="10.20.0.17")]) == []       # inbound
    assert feed(det, [tls("10.20.0.17", "x.example", T, dst="10.30.0.5")]) == []         # east-west
    assert det.snapshot()["skipped"] == 14 + 2                                   # the allow-listed host's 14, then the two
    once = feed(det, _beacon("10.20.0.18", "rare.example", 30, 60))
    assert len(once) == 1                                                       # raised once, not per connection


def test_exfil_to_a_rare_host_but_not_to_the_corporate_share_or_downloads():
    det = EgressDetector()
    ev = []
    for i in range(16):
        uid = f"U{i}"
        ev += [tls("10.20.0.25", "backup-store.example", T + 180 * i + (i * 37) % 100, uid=uid, dst="203.0.113.68"),
               conn("10.20.0.25", T + 180 * i + (i * 37) % 100, 4_000_000, 20_000, uid=uid, dst="203.0.113.68")]
    alerts = [a for a in feed(det, ev) if a["alert_type"] == "tls_exfil"]
    assert len(alerts) == 1 and alerts[0]["egress"]["exfil"]["bytes_out"] >= 50_000_000
    assert "MB to backup-store.example" in alerts[0]["note"]
    det = EgressDetector()
    share = []
    for h in range(6):
        for i in range(4):
            uid = f"S{h}-{i}"
            share += [tls(f"10.20.0.{30 + h}", "files.corp-share.example", T + 600 * i + h, uid=uid, dst="198.51.100.23"),
                      conn(f"10.20.0.{30 + h}", T + 600 * i + h, 20_000_000, 50_000, uid=uid, dst="198.51.100.23")]
    assert feed(det, sorted(share, key=lambda e: e["ts"])) == []
    det = EgressDetector()
    dl = []
    for i in range(10):
        dl += [tls("10.20.0.40", "mirror.example", T + 300 * i * 7 % 3000 + i, uid=f"D{i}"),
               conn("10.20.0.40", T + 300 * i * 7 % 3000 + i, 6_000_000, 30_000_000, uid=f"D{i}")]
    assert not [a for a in feed(det, dl) if a["alert_type"] == "tls_exfil"]     # downloads dominate: not exfil


def test_known_bad_certificate_via_x509_join_and_ioc_store_domain():
    sha1, sha256 = "1" * 40, "2" * 64
    det = EgressDetector(intel=TlsIntel([TlsIndicator("cert_sha1", sha1, "sample C2", 0.95)]))
    det.observe({"kind": "x509", "sensor": "zeek", "ts": T, "fingerprint": sha256, "sha256": sha256, "sha1": sha1,
                 "subject": "CN=c2.example", "issuer": "CN=c2.example"})
    (a,) = det.observe(tls("10.20.0.29", "login-verify.example", T + 1, cert_fps=[sha256], validation="self signed certificate"))
    assert a["alert_type"] == "tls_known_bad" and a["severity"] == "high"
    assert a["egress"]["intel"]["confirming"] and a["egress"]["cert"]["sha1"] == sha1
    store = IOCStore()
    # round 7 D-5: parent-label matching is opt-in per IOC — a feed's "*.evil-feed.example" opts in
    store.add(IOC(kind="domain", value="*.evil-feed.example", confidence=0.9, source="feed", tags=("c2",)))
    det = EgressDetector(ioc_store=store)
    (b,) = det.observe(tls("10.20.0.30", "x.evil-feed.example", T))
    assert b["egress"]["intel"]["kind"] == "domain" and b["egress"]["intel"]["source"] == "feed"


def test_shadow_ai_use_then_upload_and_registered_use_is_quiet(tmp_path):
    reg = AiRegister.load(FIX / "ai_register.sample.csv")
    usage = AiUsageRegister(path=tmp_path / "shadow.json", write_every_s=0)
    det = EgressDetector(ai=reg, usage=usage)
    first = det.observe(tls("10.20.0.33", "api.openai.com", T, dst="198.51.100.50", uid="A0"))
    assert [x["alert_type"] for x in first] == ["shadow_ai"] and first[0]["egress"]["shadow_ai"]["status"] == "unregistered"
    ups = []
    for i in range(1, 25):
        ups += det.observe(tls("10.20.0.33", "api.openai.com", T + 120 * i, dst="198.51.100.50", uid=f"A{i}"))
        ups += det.observe(conn("10.20.0.33", T + 120 * i, 500_000, 9_000, dst="198.51.100.50", uid=f"A{i}"))
    # round 7 D-6: the SNI is still judged as AI use, but the destination IP's own fixed cadence is reported too —
    # a C2 naming api.openai.com on its own IP used to hide behind "shadow AI, low"
    beacons = [x for x in ups if x["alert_type"] == "tls_beacon"]
    ups = [x for x in ups if x["alert_type"] != "tls_beacon"]
    assert [x["egress"]["level"] for x in ups] == [2] and ups[0]["severity"] == "medium"
    assert ups[0]["egress"]["shadow_ai"]["uploaded_last_hour"] >= 10_000_000
    assert len(beacons) <= 1 and all(b["severity"] in ("low", "medium") for b in beacons)
    quiet = feed(det, [tls("10.30.0.5", "acmebank-prod.openai.azure.com", T + i, dst="198.51.100.40") for i in range(5)])
    quiet += feed(det, [tls("10.20.0.12", "acmebank-prod.openai.azure.com", T + 9, dst="198.51.100.40")])
    assert quiet == []
    usage.write()
    doc = json.loads((tmp_path / "shadow.json").read_text())
    assert doc["summary"]["by_status"] == {"unregistered": 1, "registered": 1, "approved": 1}


def test_no_handshake_logged_still_counts_beats_by_ip():
    det = EgressDetector()
    alerts = feed(det, [conn("10.20.0.50", T + 60 * i, 700, 300, uid=f"E{i}", dst="203.0.113.90") for i in range(14)])
    assert [a["alert_type"] for a in alerts] == ["tls_beacon"] and alerts[0]["egress"]["destination"] == "203.0.113.90"


def test_state_is_bounded():
    det = EgressDetector(max_pairs=50, max_keys=60)
    for i in range(500):
        det.observe(tls(f"10.20.{i // 250}.{i % 250}", f"site-{i}.example", T + i))
    snap = det.snapshot()
    assert snap["pairs"] == 50 and snap["destinations"] == 60


def test_internal_networks_are_configurable(monkeypatch):
    monkeypatch.setenv("AEGIS_INTERNAL_NETS", "172.31.0.0/16")
    det = EgressDetector()
    assert det.observe(tls("10.20.0.17", "x.example", T)) == [] and det.snapshot()["skipped"] == 1
    assert det.snapshot()["tls"] == 0
    det.observe(tls("172.31.4.4", "x.example", T))
    assert det.snapshot()["tls"] == 1


# ------------------------------------------------------------ verdicts --

def _e(*signals, finding="tls_beacon", **kw):
    return {"finding": finding, "signals": [{"name": n, "weight": w, "detail": "d"} for n, w in signals], **kw}


def test_corroboration_rule():
    assert egress_verdict(_e(("intel", "confirmed"), intel={"confidence": 0.95}))[:2] == ("malicious", 0.95)
    assert egress_verdict(_e(("beacon", "strong"), ("default_subject", "strong")))[:2] == ("malicious", 0.90)
    assert egress_verdict(_e(("beacon", "strong"), ("self_signed", "medium"), ("fresh_cert", "weak")))[:2] == ("malicious", 0.85)
    assert egress_verdict(_e(("beacon", "strong")))[:2] == ("suspicious", 0.70)
    assert egress_verdict(_e(("beacon", "strong"), ("fresh_cert", "weak")))[:2] == ("suspicious", 0.75)
    v, c, why = egress_verdict(_e(("beacon", "strong"), client_shape="browser"))
    assert (v, c) == ("suspicious", 0.60) and "polling tab" in why
    assert egress_verdict(_e(finding="shadow_ai", level=1))[:2] == ("suspicious", 0.55)
    assert egress_verdict(_e(finding="shadow_ai", level=2))[:2] == ("suspicious", 0.70)


def test_chains_isolate_only_under_a_human_and_monitor_otherwise():
    mal = {"id": "ndr-x", "alert_type": "tls_beacon", "source_ip": "10.20.0.17", "note": "n",
           "egress": {**_e(("beacon", "strong"), ("default_subject", "strong")), "destination": "c2.example", "dst_ips": ["203.0.113.66"],
                      "prevalence": 1, "rare": True}}
    assert is_egress_finding(mal)
    c = egress_chain(mal)
    acts = {(a.action_type, a.target, a.requires_hitl) for a in c.recommended_actions}
    assert ("isolate", "10.20.0.17", True) in acts and ("block_egress", "c2.example", True) in acts
    assert all(a.requires_hitl for a in c.recommended_actions) and c.investigated_by == "egress"
    sus = {**mal, "egress": {**mal["egress"], "signals": [{"name": "beacon", "weight": "strong", "detail": "d"}]}}
    acts = {(a.action_type, a.requires_hitl) for a in egress_chain(sus).recommended_actions}
    assert acts == {("monitor", False), ("escalate", True)}
    ai = {**mal, "alert_type": "shadow_ai", "egress": {**_e(finding="shadow_ai", level=2), "destination": "api.openai.com",
                                                       "shadow_ai": {"service": "OpenAI API", "status": "unregistered"}}}
    c = egress_chain(ai)
    assert {a.action_type for a in c.recommended_actions} == {"escalate", "block_egress"} and c.metadata["shadow_ai"]["status"] == "unregistered"
    assert "AI inventory" in c.recommended_actions[0].reasoning


def test_response_agent_never_runs_block_egress_itself():
    from aegis.agents.response.agent import _ALWAYS_HITL_ACTIONS
    assert {"block_egress", "isolate"} <= _ALWAYS_HITL_ACTIONS


# --------------------------------------------------------- end to end --

def _fixture_env(monkeypatch, tmp_path):
    monkeypatch.setenv("AEGIS_TLS_IOC_FILE", str(FIX / "tls_ioc.sample.jsonl"))
    monkeypatch.setenv("AEGIS_AI_REGISTER", str(FIX / "ai_register.sample.csv"))
    monkeypatch.setenv("AEGIS_SHADOW_AI_REGISTER", str(tmp_path / "shadow.json"))


def _findings(alerts):
    return sorted({(a["source_ip"], a["egress"]["destination"], a["alert_type"]) for a in alerts})


def test_zeek_and_suricata_samples_give_the_same_findings(monkeypatch, tmp_path):
    _fixture_env(monkeypatch, tmp_path)
    zeek = list(NdrConsumer(detector=EgressDetector.from_env(), checkpoint=AlertCheckpoint()).iter_alerts(path=FIX / "zeek_tls.sample.jsonl"))
    eve = list(NdrConsumer(detector=EgressDetector.from_env(), checkpoint=AlertCheckpoint()).iter_alerts(path=FIX / "suricata_eve.sample.jsonl"))
    assert _findings(zeek) == _findings(eve)
    kinds = {(d, k) for _, d, k in _findings(zeek)}
    for want in (("cdn-sync.update-check.example", "tls_beacon"), ("api.metrics-cloud.example", "tls_beacon"),
                 ("backup-store.example", "tls_exfil"), ("login-verify.example", "tls_known_bad"),
                 ("api.openai.com", "shadow_ai"), ("api.anthropic.com", "shadow_ai")):
        assert want in kinds, want
    # nothing on the vendor beacons every host runs, the corporate share, or the approved AI tenant
    for d in ("update.os-vendor.example", "telemetry.edr-vendor.example", "presence.collab.example", "files.corp-share.example",
              "acmebank-prod.openai.azure.com"):
        assert not any(dest == d for dest, _ in kinds), d


def test_sample_findings_through_the_brain(monkeypatch, tmp_path):
    _fixture_env(monkeypatch, tmp_path)
    from aegis.agents.orchestrator.swarm import SwarmOrchestrator
    from aegis.agents.orchestrator.walkers.campaign import EventStore
    from aegis.eval.run import _build_orchestrator
    swarm = SwarmOrchestrator(_build_orchestrator(tmp_path / "audit.jsonl"), event_store=EventStore())
    verdicts = {}
    for a in NdrConsumer(detector=EgressDetector.from_env(), checkpoint=AlertCheckpoint()).iter_alerts(path=FIX / "zeek_tls.sample.jsonl"):
        c = swarm.handle(a)
        assert c.investigated_by == "egress"
        key = a["egress"]["destination"]
        verdicts[key] = max(verdicts.get(key, ("", 0.0)), (c.verdict, c.confidence), key=lambda v: ({"suspicious": 1, "malicious": 2}.get(v[0], 0), v[1]))
    assert verdicts["cdn-sync.update-check.example"] == ("malicious", 0.90)       # beacon + tool-default certificate
    assert verdicts["login-verify.example"][0] == "malicious"
    assert verdicts["api.metrics-cloud.example"] == ("suspicious", 0.70)
    assert verdicts["quotes.niche-market.example"] == ("suspicious", 0.60)       # the trader's polling tab


def test_list_returning_consumers_yield_each_and_treat_empty_as_consumed():
    class Two(BaseConsumer):
        name = "two"

        def fetch(self, **kw):
            yield from ([{"id": "a"}, {"id": "b"}], [], CONSUMED, [{"id": "a"}])

        def normalize(self, record):
            return record

    c = Two(checkpoint=AlertCheckpoint())
    assert [a["id"] for a in c.iter_alerts()] == ["a", "b"] and c.skipped_duplicates == 1 and c.skipped_invalid == 0


def test_push_route_and_stream_and_registry(monkeypatch, tmp_path):
    _fixture_env(monkeypatch, tmp_path)
    from aegis.ingest.http_push import PushServer
    q = StreamQueue(capacity=5000)
    srv = PushServer(token="tok", bind="127.0.0.1:0", queue=q).start()
    try:
        lines = [ln for ln in (FIX / "zeek_tls.sample.jsonl").read_text().splitlines() if ln.startswith("{")]
        req = urllib.request.Request(f"{srv.url}/ingest/ndr?sensor=zeek", data=gzip.compress("\n".join(lines).encode()),
                                     headers={"Authorization": "Bearer tok", "Content-Encoding": "gzip"}, method="POST")
        with urllib.request.urlopen(req, timeout=10) as r:
            assert r.status == 200 and json.loads(r.read())["accepted"] == len(lines)
    finally:
        srv.stop()
    alerts = list(StreamConsumer(queue=q, checkpoint=AlertCheckpoint()).iter_alerts())
    assert alerts and all(a["ingest_source"] == "ndr-zeek" and a["alert_type"].startswith(("tls_", "shadow_")) for a in alerts)
    assert {a["egress"]["destination"] for a in alerts} >= {"cdn-sync.update-check.example", "login-verify.example"}
    from aegis.ingest import sources_from_env
    reset_shared_detector()
    monkeypatch.setenv("AEGIS_SOURCES", "ndr")
    monkeypatch.setenv("NDR_EVENT_FILE", str(FIX / "suricata_eve.sample.jsonl"))
    monkeypatch.setenv("AEGIS_CHECKPOINT", str(tmp_path / "cp.json"))
    (name, it), *_ = sources_from_env()
    assert name == "ndr" and any(a["alert_type"] == "tls_known_bad" for a in it)


def test_egress_benchmark_fixture_preset_passes():
    from aegis.eval.egress_bench import run
    rep = run("fixture")
    assert rep["pass"], rep
    assert rep["benign"]["malicious"] == 0 and rep["benign"]["containment_proposals"] == 0


def test_usage_register_ships_only_changed_rows_to_the_dashboard():
    shipped: list[list[dict]] = []

    class Sink:
        def ship_ai_usage(self, rows):
            shipped.append(rows)

    usage = AiUsageRegister(sink=Sink(), write_every_s=0)
    det = EgressDetector(ai=AiRegister.load(FIX / "ai_register.sample.csv"), usage=usage)
    det.observe(tls("10.20.0.33", "api.openai.com", T, dst="198.51.100.50"))
    assert len(shipped) == 1 and shipped[0][0]["status"] == "unregistered" and shipped[0][0]["endpoint"] == "api.openai.com"
    usage.write()                                                              # nothing changed since: nothing shipped
    assert len(shipped) == 1
    det.observe(tls("10.30.0.5", "acmebank-prod.openai.azure.com", T + 1, dst="198.51.100.40"))
    assert [(r["host"], r["status"]) for r in shipped[-1]] == [("10.30.0.5", "registered")]


def test_dashboard_sink_batches_ai_usage_rows():
    from aegis.persist.dashboard import DashboardSink
    calls: list[tuple[str, int]] = []

    def transport(method, url, json_body, headers, timeout):
        calls.append((url, len(json_body["rows"])))
        return {"status": "ok"}

    sink = DashboardSink(dashboard_url="https://dashboard.bank.example", api_key="k", sync=True, transport=transport)
    sink.ship_ai_usage([{"host": f"10.0.0.{i % 250}", "endpoint": f"e{i}.example", "status": "unregistered"} for i in range(1200)])
    assert calls == [("https://dashboard.bank.example/api/soc/ai-usage", 500)] * 2 + [("https://dashboard.bank.example/api/soc/ai-usage", 200)]


# ------------------------------------------------------------- hardening --

def test_bad_files_and_a_dead_dashboard_degrade_loudly_not_fatally(tmp_path, caplog):
    import logging
    caplog.set_level(logging.WARNING)
    assert TlsIntel().load(tmp_path / "missing.jsonl") == 0
    assert AiRegister.load(tmp_path / "missing.csv").rows == []
    blocker = tmp_path / "a-file"
    blocker.write_text("x")

    class DeadSink:
        def ship_ai_usage(self, rows):
            raise ConnectionError("dashboard down")

    usage = AiUsageRegister(path=blocker / "sub" / "shadow.json", write_every_s=0, sink=DeadSink())   # parent is a file
    det = EgressDetector(usage=usage)
    assert [a["alert_type"] for a in det.observe(tls("10.20.0.33", "api.openai.com", T, dst="198.51.100.50"))] == ["shadow_ai"]
    text = caplog.text
    assert "unreadable" in text and "shipping 1 AI-usage rows failed" in text and "register write" in text


def test_malformed_sensor_records_are_bounded_or_skipped():
    huge = "x" * 100_000
    lines = ["not json", "[]", '"str"', "42", json.dumps({"id.orig_h": 5, "id.resp_h": None, "ts": "yesterday"}),
             json.dumps({"_path": "conn", "ts": 1e30, "uid": "u", "id.orig_h": "10.0.0.5", "id.resp_h": "203.0.113.5",
                         "id.resp_p": "443", "orig_bytes": "1e400", "service": "ssl"}),
             json.dumps({"event_type": "tls", "src_ip": "10.0.0.5", "dest_ip": "203.0.113.5", "tls": "oops"}),
             json.dumps({"records": [{"_path": "ssl", "ts": T, "uid": "u2", "id.orig_h": "10.0.0.5", "id.resp_h": "203.0.113.5",
                                      "server_name": huge}]})]
    det = EgressDetector()
    c = NdrConsumer(detector=det, checkpoint=AlertCheckpoint())
    assert list(c.iter_alerts(lines=lines)) == [] and c.stats["invalid"] == 1
    ev = normalize({"_path": "ssl", "ts": T, "id.orig_h": "10.0.0.5", "id.resp_h": "203.0.113.5", "server_name": huge,
                    "cert_chain_fps": [huge] * 40})
    assert len(ev["sni"]) == 255 and len(ev["cert_fps"]) == 16 and all(len(f) == 255 for f in ev["cert_fps"])
    assert normalize({"_path": "conn", "ts": 1e30, "uid": "u", "id.orig_h": "10.0.0.5", "id.resp_h": "203.0.113.5",
                      "orig_bytes": -9})["bytes_out"] == 0
    assert all(len(k) <= 255 for k in det._prev)                                # nothing unbounded reached state


def test_a_malformed_egress_alert_still_gets_a_chain():
    for egress in ({}, {"finding": "shadow_ai", "level": "x"}, {"signals": [{"weight": "strong"}, "junk", {"weight": "bogus"}]},
                   {"signals": [{"name": "intel", "weight": "confirmed"}], "intel": {"confidence": "NaN"}}, {"dst_ips": "x"}):
        for kind in ("tls_beacon", "tls_exfil", "tls_known_bad", "shadow_ai"):
            c = egress_chain({"id": "a", "alert_type": kind, "source_ip": "10.0.0.5", "egress": egress})
            assert c.verdict in ("suspicious", "malicious") and 0.0 <= c.confidence <= 1.0 and c.recommended_actions
