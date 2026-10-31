"""The licence service handler against an in-memory store and an injected key — no AWS."""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parents[1]
ROOT = HERE.parent
shutil.copy(ROOT / "aegis" / "license.py", HERE / "app" / "aegis_license.py")
sys.path.insert(0, str(HERE / "app"))

import aegis_license as L  # noqa: E402
import app  # noqa: E402

NOW = 1_793_253_600.0


@pytest.fixture(scope="module")
def cfg(tmp_path_factory):
    d = tmp_path_factory.mktemp("k")
    _, priv = L.write_keypair(d, "srv-kid", bits=1024)
    return app.Config(signing_key=json.loads(priv.read_text()), admin_key="adm-secret", extra_pubkeys=[])


def _ev(method: str, path: str, body: dict | None = None, admin: bool = False) -> dict:
    return {"requestContext": {"http": {"method": method, "path": path}},
            "headers": ({"x-admin-key": "adm-secret"} if admin else {}),
            "body": json.dumps(body) if body is not None else ""}


def _call(cfg, store, method, path, body=None, admin=False, now=NOW):
    r = app.handle(_ev(method, path, body, admin), cfg=cfg, store=store, now=now)
    return r["statusCode"], json.loads(r["body"])


def test_health_and_pubkeys(cfg):
    s = app.MemoryStore()
    assert _call(cfg, s, "GET", "/health")[0] == 200
    code, b = _call(cfg, s, "GET", "/pubkeys")
    assert code == 200 and b["keys"][0]["kid"] == "srv-kid" and "d" not in b["keys"][0]


def test_admin_required_and_validated(cfg):
    s = app.MemoryStore()
    assert _call(cfg, s, "POST", "/orders", {"customer": "X"})[0] == 401
    assert _call(cfg, s, "POST", "/orders", {}, admin=True) == (400, {"error": "customer is required"})
    assert _call(cfg, s, "POST", "/orders", {"customer": "X", "tier": "gold"}, admin=True)[0] == 400
    assert _call(cfg, s, "POST", "/orders", {"customer": "X", "features": ["teleport"]}, admin=True)[0] == 400
    assert _call(cfg, s, "GET", "/nope", admin=True)[0] == 404


def test_order_then_activate_binds_once_and_verifies(cfg):
    s = app.MemoryStore()
    code, o = _call(cfg, s, "POST", "/orders", {"customer": "Bank X", "edition": "soc", "tier": "standard", "days": 365,
                                                  "features": ["kafka_bridge"]}, admin=True)
    assert code == 201 and o["code"].startswith("BD-") and len(o["code"]) == 17
    # operator redeems from installation A
    code, a = _call(cfg, s, "POST", "/activate", {"code": o["code"], "installation_id": "bd-aaaa"})
    assert code == 200 and a["installation_id"] == "bd-aaaa" and "kafka_bridge" in a["features"] and a["limits"] == {"devices": 2000, "eps": 50}
    lic, why = L.decode(a["token"], {k["kid"]: (int(k["n"], 16), int(k["e"])) for k in cfg.pubkeys()})
    assert lic is not None and why == "" and lic.customer == "Bank X" and lic.installation_id == "bd-aaaa"
    st = L.check({"AEGIS_INSTALL_ID": "bd-aaaa", "AEGIS_LICENSE": a["token"], "AEGIS_LICENSE_ENFORCE": "1"}, now=NOW,
                 keys={"srv-kid": (int(cfg.signing_key["n"], 16), 65537)})
    assert st.status == "valid" and st.effective_edition == "soc"
    # same installation again → same licence (lost file); another installation → refused
    code2, again = _call(cfg, s, "POST", "/activate", {"code": o["code"], "installation_id": "bd-aaaa"})
    assert code2 == 200 and again["reissued"] and again["lic"] == a["lic"]
    assert _call(cfg, s, "POST", "/activate", {"code": o["code"], "installation_id": "bd-bbbb"})[0] == 409
    assert _call(cfg, s, "POST", "/activate", {"code": "BD-NOPE-NOPE-NOPE", "installation_id": "bd-bbbb"})[0] == 404
    # records
    assert _call(cfg, s, "GET", f"/orders/{o['code']}", admin=True)[1]["status"] == "redeemed"
    assert _call(cfg, s, "GET", f"/licenses/{a['lic']}", admin=True)[1]["installation_id"] == "bd-aaaa"
    inst = _call(cfg, s, "GET", "/installations/bd-aaaa", admin=True)[1]
    assert len(inst["licenses"]) == 1


def test_code_expiry_and_revoke(cfg):
    s = app.MemoryStore()
    _, o = _call(cfg, s, "POST", "/orders", {"customer": "Bank Y", "tier": "pilot", "days": 90}, admin=True)
    assert _call(cfg, s, "POST", "/activate", {"code": o["code"], "installation_id": "bd-c"}, now=NOW + 31 * 86400)[0] == 410
    _, o2 = _call(cfg, s, "POST", "/orders", {"customer": "Bank Y", "tier": "pilot", "days": 90}, admin=True)
    _, a = _call(cfg, s, "POST", "/activate", {"code": o2["code"], "installation_id": "bd-c"})
    assert _call(cfg, s, "POST", f"/licenses/{a['lic']}/revoke", {"reason": "non-payment"}, admin=True)[1]["status"] == "revoked"
    assert _call(cfg, s, "POST", "/activate", {"code": o2["code"], "installation_id": "bd-c"})[0] == 409     # no re-issue of a revoked licence


def test_direct_issue_and_usage(cfg):
    s = app.MemoryStore()
    code, a = _call(cfg, s, "POST", "/licenses", {"customer": "Bank Z", "installation_id": "*", "tier": "pilot", "days": 30}, admin=True)
    assert code == 201 and a["installation_id"] == ""
    assert _call(cfg, s, "POST", "/licenses", {"customer": "Bank Z", "tier": "pilot"}, admin=True)[0] == 400
    # /usage needs the licence token (F14); a floating token must name a valid, unclaimed installation (F4);
    # a float in the report must not 500 (F2 — DynamoDB refuses float, the MemoryStore round-trips the real serializer)
    assert _call(cfg, s, "POST", "/usage", {"report": {"installation_id": "bd-z", "usage": {"peak_eps_24h": 1.5}}})[0] == 401
    ev = {"requestContext": {"http": {"method": "POST", "path": "/usage"}}, "headers": {"authorization": f"Bearer {a['token']}"},
          "body": json.dumps({"report": {"installation_id": "bd-z", "usage": {"peak_eps_24h": 1.5}}})}
    assert app.handle(ev, cfg=cfg, store=s, now=NOW)["statusCode"] == 202
    ev["body"] = json.dumps({"report": {"installation_id": "../x", "usage": {}}})
    assert app.handle(ev, cfg=cfg, store=s, now=NOW)["statusCode"] == 403
    ev["body"] = json.dumps({"report": {}})
    assert app.handle(ev, cfg=cfg, store=s, now=NOW)["statusCode"] == 403
    got = _call(cfg, s, "GET", "/installations/bd-z", admin=True)[1]
    assert len(got["usage"]) == 1 and got["usage"][0]["report"]["usage"]["peak_eps_24h"] == 1.5
    # a second floating licence cannot write under bd-z
    _, a2 = _call(cfg, s, "POST", "/licenses", {"customer": "Bank Q", "installation_id": "*", "tier": "pilot", "days": 30}, admin=True)
    ev["headers"]["authorization"] = f"Bearer {a2['token']}"
    ev["body"] = json.dumps({"report": {"installation_id": "bd-z", "usage": {}}})
    assert app.handle(ev, cfg=cfg, store=s, now=NOW)["statusCode"] == 403


def test_bad_bodies(cfg):
    s = app.MemoryStore()
    r = app.handle({"requestContext": {"http": {"method": "POST", "path": "/activate"}}, "body": "[1,2]"}, cfg=cfg, store=s, now=NOW)
    assert r["statusCode"] == 400
    r = app.handle({"requestContext": {"http": {"method": "POST", "path": "/activate"}}, "body": "x" * (app.MAX_BODY + 1)}, cfg=cfg, store=s, now=NOW)
    assert r["statusCode"] == 400


def test_stage_prefix_is_stripped(cfg):
    s = app.MemoryStore()
    ev = {"requestContext": {"stage": "prod", "http": {"method": "GET", "path": "/prod/health"}}, "rawPath": "/prod/health", "headers": {}, "body": ""}
    assert app.handle(ev, cfg=cfg, store=s, now=NOW)["statusCode"] == 200
    ev["requestContext"]["stage"] = "$default"; ev["requestContext"]["http"]["path"] = "/health"
    assert app.handle(ev, cfg=cfg, store=s, now=NOW)["statusCode"] == 200


# ------------------------------------------------------------ community --

def _bearer(token: str) -> dict:
    return {"authorization": f"Bearer {token}"}


def _hb(cfg, store, token, *, inst, chains, fp="relfp", now, flags=None):
    ev = {"requestContext": {"http": {"method": "POST", "path": "/heartbeat"}}, "headers": _bearer(token),
          "body": json.dumps({"installation_id": inst, "chains_total": chains, "audit_tail_hash": "h", "code_fingerprint": fp,
                              "flags": flags or {"AEGIS_DATASET_CAPTURE": "1", "AEGIS_CONTRIB": "1"}, "counters": {"alerts": chains}})}
    r = app.handle(ev, cfg=cfg, store=store, now=now)
    return r["statusCode"], json.loads(r["body"])


def _contrib(cfg, store, token, *, inst, n, now, pii=False):
    recs = [{"record_id": f"r{i}", "kind": "triage", "origin": "community_contrib", "split": "", "fingerprint": "f" * 64,
             "alert": {"id": f"a{i}", "src_ip": "ip-aabbccdd0011", "user": "email-0011223344aa"}, "label": {"verdict": "suspicious", "source": "model"},
             "chain": {"integrity_hash": f"{i:064x}"}, "rationale": "x", "techniques": [],
             "human": ([{"decision": "approved"}] if i % 2 == 0 else [])} for i in range(n)]
    if pii:
        recs[0]["alert"]["user"] = "real.person@somebank.com"
    bundle = {"schema": "aegis-contrib/1", "installation_id": inst, "generated_at": int(now), "scrubbed": True, "salted": True,
              "counts": {"records": n}, "records": recs}
    import gzip
    body = base64.b64encode(gzip.compress(json.dumps(bundle).encode())).decode()
    ev = {"requestContext": {"http": {"method": "POST", "path": "/contrib"}}, "headers": {**_bearer(token), "content-encoding": "gzip"},
          "body": body, "isBase64Encoded": True}
    r = app.handle(ev, cfg=cfg, store=store, now=now)
    return r["statusCode"], json.loads(r["body"])


import base64  # noqa: E402


def _cfg2(keys_dir) -> "app.Config":
    priv = json.loads((keys_dir / "srv-kid.key.json").read_text())
    return app.Config(signing_key=priv, admin_key="adm-secret", extra_pubkeys=[], known_fingerprints=["relfp"])


@pytest.fixture(scope="module")
def cfg2(tmp_path_factory):
    d = tmp_path_factory.mktemp("k2")
    L.write_keypair(d, "srv-kid", bits=1024)
    return _cfg2(d)


def test_signup_issues_a_rolling_community_token(cfg2):
    s = app.MemoryStore()
    code, b = _call(cfg2, s, "POST", "/signup", {"org": "Sandbox Bank", "email": "ciso@sandboxbank.in", "installation_id": "bd-c1", "accept_terms": True})
    assert code == 201, b
    assert b["tier"] == "community" and "data_sharing" in b["features"] and "kafka_bridge" in b["features"]
    assert b["expires"] - NOW == pytest.approx(30 * 86400, abs=5) and b["entitlement_until"] - NOW == pytest.approx(730 * 86400, abs=5)
    st = L.check({"AEGIS_INSTALL_ID": "bd-c1", "AEGIS_LICENSE": b["token"], "AEGIS_LICENSE_ENFORCE": "1", "AEGIS_DATASET_CAPTURE": "0"},
                 now=NOW, keys={"srv-kid": (int(cfg2.signing_key["n"], 16), 65537)})
    assert st.status == "valid" and st.license.entitlement_until > 0
    env = {"AEGIS_INSTALL_ID": "bd-c1", "AEGIS_LICENSE": b["token"], "AEGIS_LICENSE_ENFORCE": "1", "AEGIS_DATASET_CAPTURE": "0"}
    L.apply(st, env)
    assert env["AEGIS_DATASET_CAPTURE"] == "1" and env["AEGIS_CONTRIB"] == "1"           # data sharing forced on
    # guards
    assert _call(cfg2, s, "POST", "/signup", {"org": "X", "email": "me@gmail.com", "installation_id": "bd-c2", "accept_terms": True})[0] == 400
    assert _call(cfg2, s, "POST", "/signup", {"org": "X", "email": "me@mailinator.com", "installation_id": "bd-c2", "accept_terms": True})[0] == 400
    assert _call(cfg2, s, "POST", "/signup", {"org": "X", "email": "a@sandboxbank.in", "installation_id": "bd-c1", "accept_terms": True})[0] == 409
    for i in range(2, 4):
        assert _call(cfg2, s, "POST", "/signup", {"org": "X", "email": "a@sandboxbank.in", "installation_id": f"bd-c{i}", "accept_terms": True})[0] == 201
    assert _call(cfg2, s, "POST", "/signup", {"org": "X", "email": "a@sandboxbank.in", "installation_id": "bd-c9", "accept_terms": True})[0] == 429


def test_contributing_installation_renews_and_a_silent_one_is_refused(cfg2):
    s = app.MemoryStore()
    _, b = _call(cfg2, s, "POST", "/signup", {"org": "Good Bank", "email": "soc@goodbank.in", "installation_id": "bd-good", "accept_terms": True})
    tok = b["token"]
    # day 0 heartbeat, then 20 days of 100 chains/day with ~all contributed
    assert _hb(cfg2, s, tok, inst="bd-good", chains=0, now=NOW)[1]["standing"] == "good"
    for d in range(1, 21):
        t = NOW + d * 86400
        assert _hb(cfg2, s, tok, inst="bd-good", chains=100 * d, now=t)[0] == 200
        code, c = _contrib(cfg2, s, tok, inst="bd-good", n=95, now=t)
        assert code == 202 and c["records"] == 95 and c["decided"] == 48, c
    assert len(s.objects) == 20 and next(iter(s.objects)).startswith("contrib/bd-good/")
    h = _call(cfg2, s, "GET", "/installations/bd-good/health", admin=True, now=NOW + 20 * 86400)[1]
    assert h["standing"] == "good" and h["ratio"] >= 0.9 and h["attestation"] == "ok" and h["contrib_records_total"] == 1900
    # renew at day 25 (the service heartbeats first, then renews) → fresh 30-day token, same lic id
    _hb(cfg2, s, tok, inst="bd-good", chains=2500, now=NOW + 25 * 86400)
    _contrib(cfg2, s, tok, inst="bd-good", n=480, now=NOW + 25 * 86400)
    ev = {"requestContext": {"http": {"method": "POST", "path": "/renew"}}, "headers": _bearer(tok), "body": ""}
    r = app.handle(ev, cfg=cfg2, store=s, now=NOW + 25 * 86400)
    rb = json.loads(r["body"])
    assert r["statusCode"] == 200 and rb["lic"] == b["lic"] and rb["expires"] - (NOW + 25 * 86400) == pytest.approx(30 * 86400, abs=5)
    lic2, _ = L.decode(rb["token"], {"srv-kid": (int(cfg2.signing_key["n"], 16), 65537)})
    assert lic2.license_id == b["lic"] and lic2.entitlement_until == pytest.approx(NOW + 730 * 86400, abs=5)

    # a second installation that writes chains but stops contributing
    _, b2 = _call(cfg2, s, "POST", "/signup", {"org": "Quiet Bank", "email": "soc@quietbank.in", "installation_id": "bd-quiet", "accept_terms": True})
    tok2 = b2["token"]
    _hb(cfg2, s, tok2, inst="bd-quiet", chains=0, now=NOW)
    for d in range(1, 21):
        _hb(cfg2, s, tok2, inst="bd-quiet", chains=100 * d, now=NOW + d * 86400)
        if d <= 3:
            _contrib(cfg2, s, tok2, inst="bd-quiet", n=100, now=NOW + d * 86400)
    h2 = _call(cfg2, s, "GET", "/installations/bd-quiet/health", admin=True, now=NOW + 20 * 86400)[1]
    assert h2["standing"] == "bad" and h2["ratio"] < 0.5 and any("no contribution for" in i for i in h2["issues"])
    _hb(cfg2, s, tok2, inst="bd-quiet", chains=2500, now=NOW + 25 * 86400)
    r2 = app.handle({"requestContext": {"http": {"method": "POST", "path": "/renew"}}, "headers": _bearer(tok2), "body": ""},
                    cfg=cfg2, store=s, now=NOW + 25 * 86400)
    assert r2["statusCode"] == 402 and "renewal refused" in json.loads(r2["body"])["error"]
    # ...so its token lapses (30 d + 14 d grace) and the product drops to evaluation mode
    st = L.check({"AEGIS_INSTALL_ID": "bd-quiet", "AEGIS_LICENSE": tok2, "AEGIS_LICENSE_ENFORCE": "1"}, now=NOW + 45 * 86400,
                 keys={"srv-kid": (int(cfg2.signing_key["n"], 16), 65537)})
    assert st.status == "expired"

    # fleet view + scheduled scan notifies about the quiet one only
    fleet = _call(cfg2, s, "GET", "/fleet", admin=True, now=NOW + 20 * 86400)[1]
    assert {r["installation_id"]: r["standing"] for r in fleet["installations"]} == {"bd-good": "good", "bd-quiet": "bad"}
    res = app.fleet_scan(cfg2, s, NOW + 20 * 86400, notify=True)
    assert res["alerts"] == 1 and len(s.notices) == 1 and "bd-quiet" in s.notices[0][1] and "bd-good" not in s.notices[0][1]


def test_modified_install_and_disabled_capture_are_flagged(cfg2):
    s = app.MemoryStore()
    _, b = _call(cfg2, s, "POST", "/signup", {"org": "Tamper Bank", "email": "x@tamperbank.in", "installation_id": "bd-t", "accept_terms": True})
    code, hb = _hb(cfg2, s, b["token"], inst="bd-t", chains=10, fp="deadbeef", now=NOW)
    assert hb["attestation"] == "unknown" and hb["standing"] == "bad" and "not a published release" in hb["reason"]
    code, hb = _hb(cfg2, s, b["token"], inst="bd-t", chains=10, fp="relfp", now=NOW + 60, flags={"AEGIS_DATASET_CAPTURE": "0", "AEGIS_CONTRIB": "0"})
    assert hb["standing"] == "bad" and "switched off" in hb["reason"]


def test_contrib_refuses_pii_and_wrong_installation(cfg2):
    s = app.MemoryStore()
    _, b = _call(cfg2, s, "POST", "/signup", {"org": "Leaky Bank", "email": "x@leakybank.in", "installation_id": "bd-l", "accept_terms": True})
    code, c = _contrib(cfg2, s, b["token"], inst="bd-l", n=3, now=NOW, pii=True)
    assert code == 422 and c["findings"][0]["kind"] == "email" and not s.objects
    code, c = _contrib(cfg2, s, b["token"], inst="bd-other", n=3, now=NOW)
    assert code == 403
    assert app.handle({"requestContext": {"http": {"method": "POST", "path": "/contrib"}}, "headers": {}, "body": "{}"}, cfg=cfg2, store=s, now=NOW)["statusCode"] == 401


# ------------------------------------------------------------- releases --

def test_release_publish_and_updates_feed(cfg2):
    s = app.MemoryStore()
    _, b = _call(cfg2, s, "POST", "/signup", {"org": "Bank R", "email": "x@bankr.in", "installation_id": "bd-r", "accept_terms": True})
    tok = b["token"]
    sha = "ab" * 32
    # register → upload url → publish
    code, reg = _call(cfg2, s, "POST", "/releases", {"version": "2026.11.1", "channel": "stable", "base_model": "Qwen/Qwen3-8B",
                                                      "sha256": sha, "size": 12345, "rollout_pct": 100, "notes": "first"}, admin=True)
    assert code == 201 and reg["key"] == "releases/stable/2026.11.1/adapter.tar.gz" and reg["upload_url"].startswith("mem://put_object/")
    assert _call(cfg2, s, "POST", "/releases", {"version": "bad", "sha256": sha, "size": 1}, admin=True)[0] == 400
    assert _call(cfg2, s, "POST", "/releases", {"version": "2026.11.1", "sha256": sha, "size": 1}, admin=True)[0] == 409
    # not published yet → nothing offered
    ev = {"requestContext": {"http": {"method": "GET", "path": "/updates"}}, "headers": _bearer(tok),
          "queryStringParameters": {"channel": "stable", "base": "Qwen/Qwen3-8B", "current": ""}, "body": ""}
    assert app.handle(ev, cfg=cfg2, store=s, now=NOW)["statusCode"] == 204
    code, pub = _call(cfg2, s, "POST", "/releases/2026.11.1/publish", {}, admin=True)
    assert code == 200 and pub["status"] == "published" and pub["kid"] == "srv-kid"
    r = app.handle(ev, cfg=cfg2, store=s, now=NOW)
    assert r["statusCode"] == 200
    body = json.loads(r["body"])
    assert body["release"]["version"] == "2026.11.1" and body["url"].startswith("mem://get_object/releases/stable/2026.11.1/")
    # the manifest verifies against the issuer key and carries the sha the installation will check the download against
    sys.path.insert(0, str(ROOT))
    from aegis import model_updates as mu
    rel, why = mu.verify_manifest(body["manifest_token"], {"srv-kid": (int(cfg2.signing_key["n"], 16), 65537)})
    assert rel is not None and why == "" and rel["sha256"] == sha and rel["size"] == 12345
    assert mu.verify_manifest(body["manifest_token"][:-4] + "AAAA", {"srv-kid": (int(cfg2.signing_key["n"], 16), 65537)})[0] is None
    # a licence token is not a release manifest
    assert mu.verify_manifest(tok, {"srv-kid": (int(cfg2.signing_key["n"], 16), 65537)})[1] == "not a model-release manifest"
    # already on that version → 204; a wrong base → 204; beta channel → 204
    ev["queryStringParameters"]["current"] = "2026.11.1"
    assert app.handle(ev, cfg=cfg2, store=s, now=NOW)["statusCode"] == 204
    ev["queryStringParameters"] = {"channel": "stable", "base": "mistralai/Mistral-7B", "current": ""}
    assert app.handle(ev, cfg=cfg2, store=s, now=NOW)["statusCode"] == 204
    # staged rollout + withdraw
    assert _call(cfg2, s, "POST", "/releases/2026.11.1/rollout", {"pct": 10}, admin=True)[1]["rollout_pct"] == 10
    ev["queryStringParameters"] = {"channel": "stable", "base": "Qwen/Qwen3-8B", "current": ""}
    assert json.loads(app.handle(ev, cfg=cfg2, store=s, now=NOW)["body"])["release"]["rollout_pct"] == 10
    assert _call(cfg2, s, "POST", "/releases/2026.11.1/withdraw", {"reason": "regression"}, admin=True)[1]["status"] == "withdrawn"
    assert app.handle(ev, cfg=cfg2, store=s, now=NOW)["statusCode"] == 204
    assert _call(cfg2, s, "GET", "/releases", admin=True)[1]["releases"][0]["status"] == "withdrawn"
    # no bearer → 401
    assert app.handle({**ev, "headers": {}}, cfg=cfg2, store=s, now=NOW)["statusCode"] == 401


# ------------------------------------------------------- review round 1 regressions --

def test_decimal_and_float_round_trips_do_not_break_responses(cfg2):
    """F1/F2/F20: DynamoDB hands back Decimal and refuses float. publish/rollout must sign plain ints,
    responses must be JSON, and a float in a heartbeat counter must not 500."""
    s = app.MemoryStore()
    _, b = _call(cfg2, s, "POST", "/signup", {"org": "Bank D", "email": "x@bankd.in", "installation_id": "bd-d", "accept_terms": True})
    assert isinstance(b["expires"], int) and isinstance(b["entitlement_until"], int)
    sha = "cd" * 32
    assert _call(cfg2, s, "POST", "/releases", {"version": "2026.11.2", "sha256": sha, "size": 10, "rollout_pct": 50}, admin=True)[0] == 201
    code, pub = _call(cfg2, s, "POST", "/releases/2026.11.2/publish", {}, admin=True)
    assert code == 200 and pub["size"] == 10 and pub["rollout_pct"] == 50 and isinstance(pub["published_at"], int)
    assert _call(cfg2, s, "POST", "/releases/2026.11.2/rollout", {"pct": 75}, admin=True)[0] == 200
    ev = {"requestContext": {"http": {"method": "POST", "path": "/heartbeat"}}, "headers": _bearer(b["token"]),
          "body": json.dumps({"chains_total": 5, "counters": {"eps": 1.75, "ok": True}})}
    assert app.handle(ev, cfg=cfg2, store=s, now=NOW)["statusCode"] == 200
    h = _call(cfg2, s, "GET", "/installations/bd-d/health", admin=True)[1]
    assert h["chains_total"] == 5 and isinstance(h["renewals"], int)
    # the stored heartbeat row carries a ttl
    assert all("ttl" in r for r in s.query("INST#bd-d", "HB#"))


def test_standing_hardens_after_the_first_week(cfg2):
    """F3: a licence that never heartbeats or contributes must not renew forever."""
    s = app.MemoryStore()
    _, b = _call(cfg2, s, "POST", "/signup", {"org": "Silent Bank", "email": "x@silentbank.in", "installation_id": "bd-s", "accept_terms": True})
    ren = lambda t: app.handle({"requestContext": {"http": {"method": "POST", "path": "/renew"}}, "headers": _bearer(b["token"]), "body": ""},
                               cfg=cfg2, store=s, now=t)
    assert ren(NOW + 2 * 86400)["statusCode"] == 200          # inside the first week: warn only, renews
    r = ren(NOW + 9 * 86400)
    assert r["statusCode"] == 402 and "no heartbeat" in json.loads(r["body"])["error"]
    # heartbeating but never contributing is also hard after the week
    _hb(cfg2, s, b["token"], inst="bd-s", chains=3, now=NOW + 9 * 86400)
    r = ren(NOW + 9 * 86400 + 1)
    assert r["statusCode"] == 402 and "no contribution in the last 30 days" in json.loads(r["body"])["error"]


def test_counter_reset_is_flagged_not_blinding(cfg2):
    """F8: chains_total going backwards (audit rotation) must not make the ratio look perfect."""
    s = app.MemoryStore()
    _, b = _call(cfg2, s, "POST", "/signup", {"org": "Rot Bank", "email": "x@rotbank.in", "installation_id": "bd-rot", "accept_terms": True})
    tok = b["token"]
    _hb(cfg2, s, tok, inst="bd-rot", chains=0, now=NOW)
    for d in range(1, 10):
        _hb(cfg2, s, tok, inst="bd-rot", chains=1000 * d, now=NOW + d * 86400)
        _contrib(cfg2, s, tok, inst="bd-rot", n=10, now=NOW + d * 86400)        # 1%
    h = _call(cfg2, s, "GET", "/installations/bd-rot/health", admin=True, now=NOW + 9 * 86400)[1]
    assert h["standing"] == "bad"
    _hb(cfg2, s, tok, inst="bd-rot", chains=200, now=NOW + 10 * 86400)         # "rotated"
    h = _call(cfg2, s, "GET", "/installations/bd-rot/health", admin=True, now=NOW + 10 * 86400)[1]
    assert h["counter_reset"] and h["standing"] == "bad" and any("backwards" in i for i in h["issues"])


def test_signup_cap_is_per_registrable_domain_and_rejects_junk(cfg2):
    """F9: subdomains and tricks must not multiply the per-org cap."""
    s = app.MemoryStore()
    assert app._registrable_domain("a@soc.mumbai.sbi.co.in") == "sbi.co.in"
    assert app._registrable_domain("a@s1.bank.com") == "bank.com"
    for i, dom in enumerate(["bank.com", "soc.bank.com", "a.b.bank.com"]):
        assert _call(cfg2, s, "POST", "/signup", {"org": "B", "email": f"x@{dom}", "installation_id": f"bd-n{i}", "accept_terms": True})[0] == 201
    assert _call(cfg2, s, "POST", "/signup", {"org": "B", "email": "x@z.bank.com", "installation_id": "bd-n9", "accept_terms": True})[0] == 429
    assert _call(cfg2, s, "POST", "/signup", {"org": "B", "email": "x@outlook.in", "installation_id": "bd-n8", "accept_terms": True})[0] == 400
    assert _call(cfg2, s, "POST", "/signup", {"org": "B", "email": "x@bank2.com", "installation_id": "*", "accept_terms": True})[0] == 400
    assert _call(cfg2, s, "POST", "/signup", {"org": "B", "email": "x@bank2.com", "installation_id": "../etc", "accept_terms": True})[0] == 400
    assert _call(cfg2, s, "POST", "/signup", {"org": "B", "email": "x@bank2.com", "installation_id": "a/b", "accept_terms": True})[0] == 400


def test_revoked_licence_is_refused_on_bearer_routes_and_renew_rejects_fixed_term(cfg2):
    """F13 / F12."""
    s = app.MemoryStore()
    _, b = _call(cfg2, s, "POST", "/signup", {"org": "Rev Bank", "email": "x@revbank.in", "installation_id": "bd-rev", "accept_terms": True})
    assert _hb(cfg2, s, b["token"], inst="bd-rev", chains=1, now=NOW)[0] == 200
    _call(cfg2, s, "POST", f"/licenses/{b['lic']}/revoke", {"reason": "abuse"}, admin=True)
    code, body = _hb(cfg2, s, b["token"], inst="bd-rev", chains=2, now=NOW + 1)
    assert code == 401 and "revoked" in body["error"]
    assert _contrib(cfg2, s, b["token"], inst="bd-rev", n=1, now=NOW + 1)[0] == 401
    # a fixed-term (non-rolling) licence cannot be shortened by /renew
    _, o = _call(cfg2, s, "POST", "/orders", {"customer": "Fixed Bank", "tier": "standard", "days": 365}, admin=True)
    _, a = _call(cfg2, s, "POST", "/activate", {"code": o["code"], "installation_id": "bd-fix"})
    r = app.handle({"requestContext": {"http": {"method": "POST", "path": "/renew"}}, "headers": _bearer(a["token"]), "body": ""}, cfg=cfg2, store=s, now=NOW)
    assert r["statusCode"] == 400 and "not a rolling" in json.loads(r["body"])["error"]
    assert _call(cfg2, s, "GET", f"/licenses/{a['lic']}", admin=True)[1]["expires"] == a["expires"]


def test_contrib_body_handling(cfg2):
    """F7 / F10 / F16: text-mode gzip gets a clear 400, a gzip bomb is refused, malformed records are 400 not 500."""
    import gzip
    s = app.MemoryStore()
    _, b = _call(cfg2, s, "POST", "/signup", {"org": "Body Bank", "email": "x@bodybank.in", "installation_id": "bd-body", "accept_terms": True})
    hdr = {**_bearer(b["token"]), "content-type": "application/json"}
    mk = lambda body, b64: {"requestContext": {"http": {"method": "POST", "path": "/contrib"}}, "headers": hdr, "body": body, "isBase64Encoded": b64}
    raw = gzip.compress(json.dumps({"schema": "aegis-contrib/1", "installation_id": "bd-body", "salted": True, "records": []}).encode())
    r = app.handle(mk(raw.decode("latin-1"), False), cfg=cfg2, store=s, now=NOW)
    assert r["statusCode"] == 400 and "application/gzip" in json.loads(r["body"])["error"]
    bomb = gzip.compress(b"0" * (app.MAX_CONTRIB_INFLATED + 1024), compresslevel=9)
    assert len(bomb) < app.MAX_CONTRIB_BODY
    r = app.handle(mk(base64.b64encode(bomb).decode(), True), cfg=cfg2, store=s, now=NOW)
    assert r["statusCode"] == 400 and "inflates" in json.loads(r["body"])["error"]
    bad = gzip.compress(json.dumps({"schema": "aegis-contrib/1", "installation_id": "bd-body", "salted": True, "records": [{"human": "yes"}]}).encode())
    r = app.handle(mk(base64.b64encode(bad).decode(), True), cfg=cfg2, store=s, now=NOW)
    assert r["statusCode"] == 400 and "records[0]" in json.loads(r["body"])["error"]
    plain = json.dumps({"schema": "aegis-contrib/1", "installation_id": "bd-body", "salted": True, "records": []})
    assert app.handle(mk(plain, False), cfg=cfg2, store=s, now=NOW)["statusCode"] == 202      # uncompressed JSON still fine
    unsalted = json.dumps({"schema": "aegis-contrib/1", "installation_id": "bd-body", "salted": False, "records": []})
    assert app.handle(mk(unsalted, False), cfg=cfg2, store=s, now=NOW)["statusCode"] == 422   # F3: reversible pseudonyms refused


def test_activation_is_atomic_and_updates_match_base(cfg2):
    """F11 / F19."""
    s = app.MemoryStore()
    _, o = _call(cfg2, s, "POST", "/orders", {"customer": "Race Bank", "tier": "standard"}, admin=True)
    assert _call(cfg2, s, "POST", "/activate", {"code": o["code"].lower(), "installation_id": "bd-r1"})[0] == 200
    assert _call(cfg2, s, "POST", "/activate", {"code": "nope", "installation_id": "bd-r1"})[0] == 400
    # a code stuck in "redeeming" (crash between claim and issue) is not open any more
    s.update(f"ORDER#{o['code']}", "META", status="redeeming")
    assert _call(cfg2, s, "POST", "/activate", {"code": o["code"], "installation_id": "bd-r2"})[0] == 410
    # base=any only sees releases marked any
    _, b = _call(cfg2, s, "POST", "/signup", {"org": "Race Bank", "email": "x@racebank.in", "installation_id": "bd-r3", "accept_terms": True})
    _call(cfg2, s, "POST", "/releases", {"version": "2026.11.3", "base_model": "Qwen/Qwen3-8B", "sha256": "ef" * 32, "size": 1}, admin=True)
    _call(cfg2, s, "POST", "/releases/2026.11.3/publish", {}, admin=True)
    ev = {"requestContext": {"http": {"method": "GET", "path": "/updates"}}, "headers": _bearer(b["token"]),
          "queryStringParameters": {"channel": "stable", "base": "any"}, "body": ""}
    assert app.handle(ev, cfg=cfg2, store=s, now=NOW)["statusCode"] == 204
    ev["queryStringParameters"]["base"] = "Qwen/Qwen3-8B"
    assert app.handle(ev, cfg=cfg2, store=s, now=NOW)["statusCode"] == 200


def test_admin_migrate_from_first_schema(cfg2):
    s = app.MemoryStore()
    s.put({"PK": "INST#bd-old", "SK": "META", "installation_id": "bd-old", "customer": "Old Bank", "tier": "community", "created": 1})
    s.put({"PK": "INST#bd-old", "SK": "LIC#L-1", "lic": "L-1"})
    s.put({"PK": "LIC#L-1", "SK": "META", "lic": "L-1", "status": "active", "customer": "Old Bank", "tier": "community", "features": ["data_sharing"],
           "installation_id": "bd-old", "issued": 1, "expires": 10 ** 10, "entitlement_until": 10 ** 10})
    s.put({"PK": "REL#2026.10.1", "SK": "META", "version": "2026.10.1", "channel": "stable", "base_model": "any", "status": "published",
           "sha256": "ab" * 32, "size": 5, "rollout_pct": 100, "key": "releases/stable/2026.10.1/adapter.tar.gz", "manifest_token": "x.y.z"})
    assert _call(cfg2, s, "GET", "/fleet", admin=True)[1]["installations"] == []
    code, r = _call(cfg2, s, "POST", "/admin/migrate", {}, admin=True)
    assert code == 200 and r == {"fleet_pointers_added": 1, "releases_moved": 1}
    assert [x["installation_id"] for x in _call(cfg2, s, "GET", "/fleet", admin=True)[1]["installations"]] == ["bd-old"]
    assert _call(cfg2, s, "GET", "/releases", admin=True)[1]["releases"][0]["version"] == "2026.10.1"
    assert _call(cfg2, s, "POST", "/admin/migrate", {}, admin=True)[1] == {"fleet_pointers_added": 0, "releases_moved": 0}
