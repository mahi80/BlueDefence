"""The live SOC backend correlates the demo bank's traffic into console incidents. These pin the
hardened behaviour: it sees the allowed stream (so edge-evasions are caught), correlates by
(ip, fingerprint) not ip alone, binds loopback, and authenticates ingest. Mostly headless."""

from __future__ import annotations

import sys
import threading
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
import soc_live as L  # noqa: E402

_CHAIN_KEYS = {"chain_id", "alert_id", "source", "verdict", "confidence", "specialists", "action_types",
               "evidence_count", "governance_blocked", "started_at", "integrity_hash", "recommended_actions"}


def _blocked(src="203.0.113.66", severity="critical", rule="WEBSHELL_UPLOAD", rules=None,
             ts="2026-10-23T05:42:00Z", ua="Go-http-client/2.0"):
    return {"action": "blocked", "src_ip": src, "severity": severity, "rule": rule,
            "rules": rules or [rule], "ts": ts, "user_agent": ua}


def _allowed(src="203.0.113.66", query="", body="", ua="", ja3=""):
    return {"action": "allowed", "severity": "info", "src_ip": src, "query": query, "body": body,
            "user_agent": ua, "ja3": ja3, "ts": "2026-10-23T05:42:10Z"}


def _live(s):
    return [c for c in s.chains() if c["chain_id"].startswith("chn_live_")]


# --- baseline correlation --------------------------------------------------- #

def test_blocked_source_becomes_one_malicious_chain():
    s = L.LiveSoc()
    s.ingest(_blocked(rule="SQLI", rules=["SQLI", "SCANNER_UA"], severity="critical"))
    s.ingest(_blocked(rule="PROMPT_INJECTION", rules=["PROMPT_INJECTION"], severity="high"))
    live = _live(s)
    assert len(live) == 1
    c = live[0]
    assert c["verdict"] == "malicious" and c["confidence"] >= 0.9
    assert "ignore your rules" in c["note"]


def test_chain_shape_matches_console_contract():
    s = L.LiveSoc()
    s.ingest(_blocked())
    for c in s.chains():
        assert _CHAIN_KEYS <= set(c)
        for n in c["investigation"]["blast_radius"]["nodes"]:
            assert {"id", "label", "kind"} <= set(n)


def test_blast_radius_targets_the_crown_jewel_ledger():
    s = L.LiveSoc()
    s.ingest(_blocked())
    c = _live(s)[0]
    br = c["investigation"]["blast_radius"]
    assert "db-core" in br["critical"] and ["app-ledger-07", "db-core"] in br["choke_edges"]


def test_two_hitl_approvals_and_approve_contains():
    s = L.LiveSoc()
    s.ingest(_blocked(src="198.51.100.5"))
    appr = s.approvals()
    assert {a["action_type"] for a in appr} == {"isolate", "block_egress"}
    assert any(a["target"] == "198.51.100.5" for a in appr)
    iso = next(a for a in appr if a["action_type"] == "isolate")
    assert s.decide(iso["id"], "approve", rationale="go", by="ciso") is True
    c = _live(s)[0]
    assert "CONTAINED" in c["note"] and c["investigation"]["blast_radius"]["choke_edges"] == []
    assert next(a for a in s.approvals() if a["id"] == iso["id"])["decided_by"] == "ciso"


def test_scanner_noise_stays_suspicious_with_no_approval():
    s = L.LiveSoc()
    for _ in range(2):
        s.ingest(_blocked(src="192.0.2.9", severity="high", rule="SCANNER_UA", rules=["SCANNER_UA"]))
    assert _live(s)[0]["verdict"] == "suspicious" and s.approvals() == []


def test_baseline_and_unknown_approval():
    s = L.LiveSoc()
    assert {"chn_base_01", "chn_base_02"} <= {c["chain_id"] for c in s.chains()}
    assert s.decide("nope", "approve") is False


# --- the blind-spot fix: the SOC sees the allowed stream -------------------- #

def test_sqli_in_a_post_body_evades_the_edge_but_the_soc_catches_it():
    s = L.LiveSoc()
    # allowed by the edge (no rules), SQLi lives in the body — the edge's qs-only rule missed it
    s.ingest(_allowed(body="acct=AC-1001' UNION SELECT username,password FROM users--", ua="Go-http-client/2.0"))
    c = _live(s)[0]
    assert c["verdict"] == "malicious" and c["edge_evaded"] == 1 and c["edge_blocked"] == 0
    assert "bypassed the edge WAF" in c["note"] and "SQLI" in c["note"]


def test_union_across_a_newline_is_caught():
    s = L.LiveSoc()
    s.ingest(_allowed(body="x=1 UNION\nSELECT 1,2,3-- evading a single-line regex", ua="curl/8"))
    assert _live(s)[0]["edge_evaded"] == 1


def test_empty_user_agent_evasion_is_noted():
    s = L.LiveSoc()
    s.ingest(_allowed(body="id=1; cat /etc/passwd", ua=""))     # empty UA + cmd injection in body
    c = _live(s)[0]
    assert "empty User-Agent" in c["note"]


def test_benign_allowed_traffic_raises_no_incident():
    s = L.LiveSoc()
    s.ingest(_allowed(query="id=AC-1001", body="", ua="Mozilla/5.0"))
    assert _live(s) == []                       # nothing but baseline
    assert s.stats()["benign_allowed"] == 1


# --- fingerprint-aware correlation ----------------------------------------- #

def test_distinct_fingerprints_behind_one_ip_split_into_separate_campaigns():
    s = L.LiveSoc()
    s.ingest(_blocked(src="127.0.0.1", ua="agent-A/1.0"))
    s.ingest(_blocked(src="127.0.0.1", ua="agent-B/1.0"))
    live = _live(s)
    assert len({c["chain_id"] for c in live}) == 2            # two agents, not merged
    assert all(c["distinct_clients_from_ip"] == 2 for c in live)
    assert any("distinct client fingerprints" in c["note"] for c in live)


def test_same_fingerprint_same_ip_is_one_campaign():
    s = L.LiveSoc()
    s.ingest(_blocked(src="127.0.0.1", ua="agent-A/1.0"))
    s.ingest(_blocked(src="127.0.0.1", ua="agent-A/1.0", rule="SQLI", rules=["SQLI"]))
    assert len(_live(s)) == 1


def test_fingerprint_prefers_ja3_then_ua_then_empty():
    assert L.fingerprint({"ja3": "abc"}).startswith("ja3:")
    assert L.fingerprint({"user_agent": "x"}).startswith("ua:")
    assert L.fingerprint({}) == "ua:empty"


def test_deep_inspect_is_multiline_and_body_aware():
    assert any(r == "SQLI" for r, _ in L.deep_inspect({"body": "a UNION\nSELECT b"}))
    assert any(r == "PATH_TRAVERSAL" for r, _ in L.deep_inspect({"query": "f=../../etc/passwd"}))
    assert L.deep_inspect({"query": "id=AC-1001", "body": ""}) == []


# --- security: loopback bind + ingest auth --------------------------------- #

def test_main_refuses_nonloopback_without_token():
    assert L.main(["--bind", "0.0.0.0", "--port", "0"]) == 2


def _serve(token=""):
    L._Handler.soc = L.LiveSoc()
    L._Handler.ingest_token = token
    from http.server import ThreadingHTTPServer
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), L._Handler)
    httpd.daemon_threads = True
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd, f"http://127.0.0.1:{httpd.server_address[1]}"


def _post(url, data, token=None):
    req = urllib.request.Request(url, data=data.encode(), method="POST",
                                 headers={"Content-Type": "application/x-ndjson"})
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        r = urllib.request.urlopen(req, timeout=5)
        return r.status
    except urllib.error.HTTPError as e:
        return e.code


# --- behavioral detection: authorized abuse the WAF cannot see --------------- #

def _op(action, op, principal="admin", amount=None, src="127.0.0.1", ua="agent/1"):
    e = {"action": action, "op": op, "principal": principal, "src_ip": src, "user_agent": ua,
         "ts": "2026-10-23T05:42:20Z"}
    if amount is not None:
        e["amount"] = amount
    return e


def test_ledger_harvest_is_caught_behaviorally():
    s = L.LiveSoc()
    s.ingest(_op("allowed", "ledger_read_all"))     # a clean, authorized full-ledger read — no signature
    c = _live(s)[0]
    assert c["verdict"] == "malicious" and "LEDGER_HARVEST" in c["behavioral_rules"]
    assert "behavioral detection" in c["note"] and "admin" in c["note"]


def test_authz_violation_is_caught():
    s = L.LiveSoc()
    s.ingest(_op("denied", "ledger_read_all", principal="teller"))
    c = _live(s)[0]
    assert "AUTHZ_VIOLATION" in c["behavioral_rules"] and c["verdict"] == "malicious"


def test_a_single_transfer_is_suspicious_not_malicious():
    s = L.LiveSoc()
    s.ingest(_op("allowed", "transfer", amount=1000))
    c = _live(s)[0]
    assert "FUNDS_MOVEMENT" in c["behavioral_rules"] and c["verdict"] == "suspicious"


def test_large_transfer_scores_high():
    assert any(sev == "high" for _, sev in L.behavioral_inspect({"action": "allowed", "op": "transfer", "amount": 250000}))


def test_behavioral_inspect_reads_the_operation_not_a_payload():
    assert L.behavioral_inspect({"action": "allowed", "op": "ledger_read_all"}) == [("LEDGER_HARVEST", "high")]
    assert L.behavioral_inspect({"action": "denied", "op": "x"}) == [("AUTHZ_VIOLATION", "high")]
    assert L.behavioral_inspect({"action": "allowed", "op": "page_view"}) == []


def test_harvest_plus_transfer_from_one_principal_is_one_incident():
    s = L.LiveSoc()
    s.ingest(_op("allowed", "ledger_read_all"))
    s.ingest(_op("allowed", "transfer", amount=1000))
    live = _live(s)
    assert len(live) == 1 and live[0]["behavioral"] == 2
    assert {"LEDGER_HARVEST", "FUNDS_MOVEMENT"} <= set(live[0]["behavioral_rules"])


def test_ingest_rejects_unauthenticated_post_when_token_set():
    httpd, base = _serve(token="s3cret")
    try:
        alert = '{"action":"blocked","src_ip":"203.0.113.66","severity":"critical","rules":["SQLI"]}'
        assert _post(base + "/ingest/alerts", alert) == 401                 # no token → rejected
        assert _post(base + "/ingest/alerts", alert, token="wrong") == 401  # wrong token → rejected
        assert _post(base + "/ingest/alerts", alert, token="s3cret") == 200 # good token → accepted
        # the rejected posts minted nothing; only the authorized one did
        assert L._Handler.soc.stats()["malicious"] == 1
    finally:
        httpd.shutdown()


# --- the real brain: the live swarm triages each campaign ------------------- #

class _FakeBrain:
    """Stands in for aegis.service's real swarm: records the alert it was handed and returns a
    canned EvidenceChain-shaped verdict. The real Brain runs orch.handle() + model_dump; this pins
    the overlay contract (verdict/specialists/actions/source/triage) without the heavy pipeline."""

    def __init__(self, verdict="malicious", confidence=0.91, specialists=None, actions=None, fail=False):
        self.verdict, self.confidence = verdict, confidence
        self.specialists = specialists if specialists is not None else ["perimeter", "ioc_extract", "blast_radius"]
        self.actions = actions
        self.fail = fail
        self.seen = []

    def triage(self, alert):
        self.seen.append(alert)
        if self.fail:
            return None                     # a dead/failed brain → heuristic stands
        acts = self.actions if self.actions is not None else [
            {"action_type": "isolate", "target": "app-ledger-07", "requires_hitl": True,
             "confidence": self.confidence, "reasoning": "swarm says sever the ledger path"}]
        return {"verdict": self.verdict, "confidence": self.confidence, "specialists": list(self.specialists),
                "evidence_count": 7, "integrity_hash": "brainhash0000beef", "recommended_actions": acts,
                "investigated_by": "SwarmOrchestrator", "reasoning": "campaign matches known TTPs",
                "governance_blocked": False}


def _wait_brain(s, key_prefix="chn_live_", timeout=5.0):
    import time as _t
    end = _t.time() + timeout
    while _t.time() < end:
        live = _live(s)
        if live and all(c.get("triage") == "swarm" for c in live):
            return live
        _t.sleep(0.02)
    return _live(s)


def test_brain_overlay_replaces_the_heuristic_verdict():
    b = _FakeBrain(verdict="malicious", confidence=0.93, specialists=["perimeter", "log_hunt"])
    s = L.LiveSoc(brain=b)
    s.ingest(_blocked(rule="SQLI", rules=["SQLI"], severity="critical"))
    live = _wait_brain(s)
    assert b.seen, "the swarm was handed the representative alert"
    c = live[0]
    assert c["triage"] == "swarm" and c["source"] == "AEGIS swarm (live)"
    assert c["verdict"] == "malicious" and c["confidence"] == 0.93
    assert c["specialists"] == ["perimeter", "log_hunt"] and c["integrity_hash"] == "brainhash0000beef"
    assert c["evidence_count"] == 7
    assert "Triaged live by the AEGIS swarm" in c["note"] and "log_hunt" in c["note"]


def test_brain_verdict_can_downgrade_a_heuristic_malicious():
    # heuristic would call 5+ events malicious; the swarm says suspicious and wins
    b = _FakeBrain(verdict="suspicious", confidence=0.55)
    s = L.LiveSoc(brain=b)
    for i in range(6):
        s.ingest(_blocked(src="198.51.100.9", rule="SCANNER_UA", rules=["SCANNER_UA"], severity="high"))
    live = _wait_brain(s)
    c = live[0]
    assert c["verdict"] == "suspicious" and c["triage"] == "swarm"


def test_brain_failure_falls_back_to_heuristic():
    b = _FakeBrain(fail=True)
    s = L.LiveSoc(brain=b)
    s.ingest(_blocked(rule="SQLI", rules=["SQLI"], severity="critical"))
    # give the background thread a moment; it returns None, so no overlay
    import time as _t
    _t.sleep(0.2)
    c = _live(s)[0]
    assert c["triage"] == "heuristic" and c["verdict"] == "malicious"   # heuristic still correct
    assert c["source"] == "Ledger Demo Bank SOC"


def test_brain_is_not_called_for_behavioral_only_campaigns():
    # a clean authorized ledger-harvest has no WAF/signature alert — nothing for the brain to triage
    b = _FakeBrain()
    s = L.LiveSoc(brain=b)
    s.ingest(_op("allowed", "ledger_read_all"))
    import time as _t
    _t.sleep(0.2)
    assert b.seen == []                          # representative_alert() returned None
    assert _live(s)[0]["triage"] == "heuristic"  # behavioral verdict stands on its own


def test_heuristic_mode_has_no_brain_and_sets_triage_heuristic():
    s = L.LiveSoc()                              # no brain
    s.ingest(_blocked())
    c = _live(s)[0]
    assert c["triage"] == "heuristic" and "chn_live_" in c["chain_id"]


# --- cookie / session layer: what a payload-only WAF cannot see --------------- #

def _cookie_evt(cookie="", sid="", principal="anon", role="anon", src="203.0.113.66", ua="agent/1"):
    return {"action": "allowed", "severity": "info", "src_ip": src, "query": "", "body": "",
            "user_agent": ua, "cookie": cookie, "sid": sid, "principal": principal, "role": role,
            "ts": "2026-10-23T05:42:30Z"}


def test_payload_smuggled_in_a_cookie_is_caught_by_reinspection():
    s = L.LiveSoc()
    s.ingest(_cookie_evt(cookie="sid=abc; pref=1' UNION SELECT card_pan FROM cards--"))
    c = _live(s)[0]
    assert "SQLI" in c["note"] and c["edge_evaded"] == 1       # WAF saw no query/body payload; SOC did

def test_forged_privilege_in_a_cookie_from_a_nonadmin_is_tamper():
    s = L.LiveSoc()
    s.ingest(_cookie_evt(cookie="sid=xyz; role=admin", principal="teller", role="teller"))
    c = _live(s)[0]
    assert "COOKIE_TAMPER" in str(c) and c["verdict"] == "malicious"

def test_a_real_admin_cookie_is_not_flagged():
    # the bank's own admin session carries only sid=...; no privilege claim, role really is admin
    s = L.LiveSoc()
    s.ingest(_cookie_evt(cookie="sid=realadmintoken", principal="admin", role="admin"))
    assert _live(s) == [] and s.stats()["benign_allowed"] == 1

def test_unsigned_token_in_cookie_is_forgery():
    assert ("TOKEN_FORGERY", "critical") in L.cookie_inspect(
        {"cookie": 'jwt={"alg":"none"}.body.', "role": "anon"})

def test_cookie_inspect_is_a_pure_signal_check():
    assert L.cookie_inspect({"cookie": "role=admin", "role": "teller"}) == [("COOKIE_TAMPER", "high")]
    assert L.cookie_inspect({"cookie": "role=admin", "role": "admin"}) == []   # the real admin
    assert L.cookie_inspect({"cookie": "sid=ordinary"}) == []
    assert L.cookie_inspect({}) == []

def test_session_fixation_when_an_anon_sid_reappears_authenticated():
    s = L.LiveSoc()
    s.ingest(_cookie_evt(cookie="sid=FIXED123", sid="FIXED123", principal="anon", role="anon"))
    s.ingest(_cookie_evt(cookie="sid=FIXED123", sid="FIXED123", principal="teller", role="teller"))
    assert any("SESSION_FIXATION" in str(c) for c in _live(s))

def test_a_freshly_issued_authenticated_sid_is_not_fixation():
    # normal login flow: the authed sid was issued at login, never seen anon → no flag
    s = L.LiveSoc()
    s.ingest(_cookie_evt(cookie="sid=NEWTOKEN", sid="NEWTOKEN", principal="admin", role="admin"))
    assert not any("SESSION_FIXATION" in str(c) for c in _live(s))


# --- Postgres persistence sink (durable audit log beside the in-memory console) --- #

def test_pg_sink_disables_gracefully_on_a_bad_dsn():
    sink = L._PgSink("postgresql://nope:nope@127.0.0.1:1/none")   # unreachable / or no driver
    sink.upsert({"chain_id": "c1", "verdict": "malicious"}, src_ip="203.0.113.66", enforced=False)
    assert sink._dead is True                                     # it never raises; it disables itself


def test_livesoc_without_dsn_is_in_memory_only():
    s = L.LiveSoc()
    assert s._pg is None
    s.ingest(_blocked())                                          # works with no sink
    assert _live(s)


class _FakeSink:
    def __init__(self): self.rows = []
    def upsert(self, chain, *, src_ip, enforced): self.rows.append((chain["chain_id"], src_ip, chain["verdict"], enforced))


def test_incidents_are_persisted_and_throttled_to_changes():
    s = L.LiveSoc()
    fake = _FakeSink(); s._pg = fake
    s.ingest(_blocked(src="203.0.113.66", rule="SQLI", rules=["SQLI"]))
    assert fake.rows and fake.rows[-1][1] == "203.0.113.66" and fake.rows[-1][2] == "malicious"
    n = len(fake.rows)
    s.ingest(_blocked(src="203.0.113.66", rule="SQLI", rules=["SQLI"]))   # count changed → re-persist
    assert len(fake.rows) > n


def test_enforcement_is_persisted():
    s = L.LiveSoc(enforce_url="http://127.0.0.1:0/control/enforce", enforce_token="t")
    fake = _FakeSink(); s._pg = fake
    s._post_control = lambda payload: {"blocked_ips": ["203.0.113.66"], "revoked_sessions": 0}
    s.ingest(_blocked(src="203.0.113.66"))
    iso = next(a for a in s.approvals() if a["id"].endswith("_iso"))
    s.decide(iso["id"], "approve")
    assert any(enforced for (_cid, _ip, _v, enforced) in fake.rows)   # a row recorded with enforced=True


# --- real enforcement: an approved isolate blocks the source at the target ---- #

def test_approve_pushes_a_real_block_when_control_url_is_set():
    s = L.LiveSoc(enforce_url="http://127.0.0.1:0/control/enforce", enforce_token="tok")
    calls = []
    s._post_control = lambda payload: (calls.append(payload) or
                                       {"blocked_ips": ["203.0.113.66"], "revoked_sessions": 1})
    s.ingest(_blocked(src="203.0.113.66"))
    iso = next(a for a in s.approvals() if a["id"].endswith("_iso"))
    assert s.decide(iso["id"], "approve", by="ciso") is True
    assert any(p.get("action") == "isolate" and p.get("target") == "203.0.113.66" for p in calls)
    c = _live(s)[0]
    assert "CONTAINED (enforced)" in c["note"] and "403ing 203.0.113.66" in c["note"]


def test_approve_stays_shadow_when_no_control_url():
    s = L.LiveSoc()                                  # no enforce_url
    pushed = []
    s._post_control = lambda payload: pushed.append(payload)   # must never be called
    s.ingest(_blocked(src="198.51.100.5"))
    iso = next(a for a in s.approvals() if a["id"].endswith("_iso"))
    assert s.decide(iso["id"], "approve") is True
    assert pushed == []
    c = _live(s)[0]
    assert "CONTAINED (shadow)" in c["note"] and "enforced" not in c["note"]


def test_enforcement_failure_falls_back_to_shadow():
    s = L.LiveSoc(enforce_url="http://127.0.0.1:0/control/enforce", enforce_token="tok")
    def boom(_payload): raise OSError("target unreachable")
    s._post_control = boom
    s.ingest(_blocked(src="203.0.113.66"))
    iso = next(a for a in s.approvals() if a["id"].endswith("_iso"))
    assert s.decide(iso["id"], "approve") is True    # never raises
    c = _live(s)[0]
    assert "CONTAINED (shadow)" in c["note"]          # enforcement failed → honest shadow wording


def test_representative_alert_picks_the_worst_severity():
    c = L.Campaign("203.0.113.66", "ua:x")
    c.add(_blocked(rule="SCANNER_UA", rules=["SCANNER_UA"], severity="low"),
          edge_blocked=True, deep=[], behavioral=[])
    c.add(_blocked(rule="WEBSHELL_UPLOAD", rules=["WEBSHELL_UPLOAD"], severity="critical"),
          edge_blocked=True, deep=[], behavioral=[])
    rep = c.representative_alert()
    assert rep is not None and rep["severity"] == "critical"


def test_decisions_need_the_token_and_refuse_cross_site_pages():
    """An approve can push real enforcement; any web page the presenter opened used to be able to POST it."""
    httpd, base = _serve(token="t0k")
    try:
        url = f"{base}/api/approvals/appr_x_iso/approve"
        assert _post(url, "{}") == 403                          # no token
        req = urllib.request.Request(url, data=b"{}", method="POST",
                                     headers={"Authorization": "Bearer t0k", "Origin": "https://evil.example"})
        try:
            code = urllib.request.urlopen(req, timeout=5).status
        except urllib.error.HTTPError as e:
            code = e.code
        assert code == 403                                       # browser cross-site request, even with a token
        assert _post(url, "{}", token="t0k") == 404             # authorised, unknown id
    finally:
        httpd.shutdown()
