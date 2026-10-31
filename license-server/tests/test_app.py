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
    assert _call(cfg, s, "POST", "/usage", {"report": {"installation_id": "bd-z", "usage": {"peak_eps_24h": 1.5}}})[0] == 202
    assert _call(cfg, s, "POST", "/usage", {"report": {}})[0] == 400
    assert len(_call(cfg, s, "GET", "/installations/bd-z", admin=True)[1]["usage"]) == 1


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
