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
