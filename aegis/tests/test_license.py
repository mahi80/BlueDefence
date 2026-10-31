"""Per-installation licensing: signing, binding, expiry + grace, evaluation mode, feature gates, metering,
the /ingest/license endpoint, and that an unlicensed dev/CI run (AEGIS_LICENSE_ENFORCE=0) changes nothing."""

from __future__ import annotations

import json
import time
import urllib.request
from pathlib import Path

import pytest

from aegis import license as L

NOW = 1_793_253_600.0


@pytest.fixture(scope="module")
def keys(tmp_path_factory):
    d = tmp_path_factory.mktemp("keys")
    pub, priv = L.write_keypair(d, "test-kid", bits=1024)       # small for test speed; verify is bit-length agnostic
    key = json.loads(priv.read_text())
    return {"dir": d, "pub": L.load_public_keys(d), "n": int(key["n"], 16), "d": int(key["d"], 16), "kid": "test-kid"}


def _lic(inst: str, **kw) -> L.License:
    base = dict(customer="Sandbox Bank", installation_id=inst, edition="soc", tier="standard", issued=NOW - 86400,
                expires=NOW + 300 * 86400, grace_days=30, devices=2000, eps=50,
                features=list(L.TIER_DEFAULTS["standard"]["features"]))
    base.update(kw)
    return L.License(**base)


def _env(tmp_path, token: str | None, **extra) -> dict:
    env = {"AEGIS_INSTALL_ID": "bd-test-install", "AEGIS_LICENSE_ENFORCE": "1", **extra}
    if token is not None:
        p = tmp_path / "license.jwt"
        p.write_text(token)
        env["AEGIS_LICENSE"] = str(p)
    return env


def test_rsa_sign_verify_roundtrip_and_tamper(keys):
    msg = b"the quick brown fox"
    sig = L.rsa_sign(msg, keys["n"], keys["d"])
    n, e = keys["pub"]["test-kid"]
    assert L.rsa_verify(msg, sig, n, e)
    assert not L.rsa_verify(msg + b"!", sig, n, e)
    assert not L.rsa_verify(msg, bytes([sig[0] ^ 1]) + sig[1:], n, e)
    assert not L.rsa_verify(msg, sig[:-1], n, e)


def test_issue_decode_and_bad_inputs(keys):
    tok = L.issue(_lic("bd-x"), n=keys["n"], d=keys["d"], kid=keys["kid"])
    lic, why = L.decode(tok, keys["pub"])
    assert lic is not None and why == "" and lic.customer == "Sandbox Bank" and lic.kid == "test-kid" and lic.license_id.startswith("L-")
    # tampered payload
    h, b, s = tok.split(".")
    bad = json.loads(L._unb64u(b)); bad["tier"] = "enterprise"; bad["limits"] = {"devices": 0, "eps": 0}
    forged = f"{h}.{L._b64u(json.dumps(bad, sort_keys=True, separators=(',', ':')).encode())}.{s}"
    assert L.decode(forged, keys["pub"]) == (None, "signature does not verify")
    assert L.decode(tok, {})[1].startswith("unknown signing key")
    assert L.decode("not.a.token", keys["pub"])[0] is None
    assert L.decode("garbage", keys["pub"])[0] is None


def test_valid_licence_binds_to_the_installation(tmp_path, keys):
    tok = L.issue(_lic("bd-test-install"), n=keys["n"], d=keys["d"], kid=keys["kid"])
    st = L.check(_env(tmp_path, tok), now=NOW, keys=keys["pub"])
    assert st.status == "valid" and st.licensed and st.runs and st.effective_edition == "soc"
    assert st.devices_limit == 2000 and st.eps_limit == 50 and "live_enforcement" in st.effective_features
    assert 299 < st.days_left < 301
    other = L.check(_env(tmp_path, tok, AEGIS_INSTALL_ID="bd-someone-else"), now=NOW, keys=keys["pub"])
    assert other.status == "invalid" and "bound to installation" in other.reason and not other.licensed
    floating = L.issue(_lic(""), n=keys["n"], d=keys["d"], kid=keys["kid"])          # '*' pilot: any installation
    assert L.check(_env(tmp_path, floating, AEGIS_INSTALL_ID="bd-anyone"), now=NOW, keys=keys["pub"]).status == "valid"


def test_expiry_grace_then_stop(tmp_path, keys):
    tok = L.issue(_lic("bd-test-install", expires=NOW - 10 * 86400, grace_days=30), n=keys["n"], d=keys["d"], kid=keys["kid"])
    st = L.check(_env(tmp_path, tok), now=NOW, keys=keys["pub"])
    assert st.status == "grace" and st.licensed and st.runs and "20 days of grace left" in st.reason
    env = _env(tmp_path, tok)
    L.apply(st, env)                                                  # grace runs with its features
    assert env.get("AEGIS_ENFORCEMENT_MODE") is None
    late = L.check(_env(tmp_path, tok), now=NOW + 25 * 86400, keys=keys["pub"])
    assert late.status == "expired" and not late.runs
    with pytest.raises(L.LicenseError, match="Renew the licence"):
        L.apply(late, _env(tmp_path, tok))
    # the same expired licence with enforcement OFF (dev/CI) does not stop anything
    off = L.check(_env(tmp_path, tok, AEGIS_LICENSE_ENFORCE="0"), now=NOW + 25 * 86400, keys=keys["pub"])
    assert off.status == "expired" and L.apply(off, {}) is off


def test_missing_or_invalid_is_evaluation_mode_when_enforced(tmp_path, keys):
    env = _env(tmp_path, None, AEGIS_EDITION="full", AEGIS_ENFORCEMENT_MODE="live", AEGIS_SWARM="1", AEGIS_AUTO_BLOCK="live")
    st = L.check(env, now=NOW, keys=keys["pub"])
    assert st.status == "missing" and st.runs and not st.licensed and st.devices_limit == 100 and st.eps_limit == 5
    L.apply(st, env)
    assert env["AEGIS_EDITION"] == "external" and env["AEGIS_ENFORCEMENT_MODE"] == "shadow" and env["AEGIS_SWARM"] == "0"
    assert env["AEGIS_AUTO_BLOCK"] == "shadow" and env["AEGIS_ENSEMBLE_VOTE"] == "off" and env["AEGIS_NETOPS"] == "0"
    # garbage file → invalid, same treatment
    env2 = _env(tmp_path, "nope", AEGIS_ENFORCEMENT_MODE="live")
    st2 = L.check(env2, now=NOW, keys=keys["pub"])
    assert st2.status == "invalid"
    L.apply(st2, env2)
    assert env2["AEGIS_ENFORCEMENT_MODE"] == "shadow"


def test_unenforced_changes_nothing(tmp_path, keys):
    env = _env(tmp_path, None, AEGIS_LICENSE_ENFORCE="0", AEGIS_EDITION="full", AEGIS_ENFORCEMENT_MODE="live", AEGIS_SWARM="1")
    before = dict(env)
    st = L.check(env, now=NOW, keys=keys["pub"])
    L.apply(st, env)
    assert env == before and not st.enforce and L.allows("kafka_bridge", st)


def test_edition_cap_and_feature_gates(tmp_path, keys):
    tok = L.issue(_lic("bd-test-install", edition="soc", tier="pilot", features=["swarm", "netops"]), n=keys["n"], d=keys["d"], kid=keys["kid"])
    env = _env(tmp_path, tok, AEGIS_EDITION="full")
    st = L.check(env, now=NOW, keys=keys["pub"])
    with pytest.raises(L.LicenseError, match="covers 'soc'"):
        L.apply(st, env)
    env = _env(tmp_path, tok, AEGIS_EDITION="soc", AEGIS_ENFORCEMENT_MODE="live", AEGIS_ENSEMBLE_VOTE="live", AEGIS_SWARM="1")
    L.apply(L.check(env, now=NOW, keys=keys["pub"]), env)
    assert env["AEGIS_SWARM"] == "1"                                   # licensed
    assert env["AEGIS_ENSEMBLE_VOTE"] == "off" and env["AEGIS_ENFORCEMENT_MODE"] == "shadow"   # not licensed on pilot
    assert env["AEGIS_KAFKA_BRIDGE"] == "0" and not L.allows("kafka_bridge", L.check(env, now=NOW, keys=keys["pub"]))
    assert L.allows("netops", L.check(env, now=NOW, keys=keys["pub"]))


def test_meter_over_limit_only_after_the_allowance():
    m = L.LicenseMeter(eps_limit=5, devices_limit=100, allowance_s=7 * 86400)
    t = NOW
    assert m.observe(3600 * 4, t) is False and m.peak_eps_24h == 4.0 and m.over_since is None
    assert m.observe(3600 * 20, t + 3600) is False and m.over_since == t + 3600       # over, but inside the allowance
    assert m.observe(3600 * 20, t + 3600 + 6 * 86400) is False
    assert m.observe(3600 * 20, t + 3600 + 8 * 86400) is True                          # 8 days over → over_limit
    m2 = L.LicenseMeter(eps_limit=0, devices_limit=100, allowance_s=10)
    assert m2.observe(0, t, devices=150) is False and m2.observe(0, t + 11, devices=150) is True
    assert m2.observe(0, t + 12, devices=90) is False and m2.over_since is None     # back under: resets
    assert L.LicenseMeter().observe(10**7, t) is False                                 # unlimited never trips


def test_over_limit_state_forces_shadow(tmp_path, keys):
    tok = L.issue(_lic("bd-test-install"), n=keys["n"], d=keys["d"], kid=keys["kid"])
    env = _env(tmp_path, tok, AEGIS_ENFORCEMENT_MODE="live")
    st = L.check(env, now=NOW, keys=keys["pub"], over_limit=True)
    assert st.status == "over_limit" and st.licensed
    L.apply(st, env)
    assert env["AEGIS_ENFORCEMENT_MODE"] == "shadow" and env.get("AEGIS_SWARM") != "0"      # licensed features stay


def test_pipeline_banner_and_license_endpoint(tmp_path, keys, monkeypatch):
    from aegis.eval.fault_injection import _env as env_ctx
    from aegis.eval.network_fault_bench import _env as bench_env
    from aegis.ingest.http_push import PushServer
    from aegis.ingest.stream import StreamQueue
    tok = L.issue(_lic("bd-test-install", tier="enterprise", devices=0, eps=0, features=list(L.ALL_FEATURES)), n=keys["n"], d=keys["d"], kid=keys["kid"])
    (tmp_path / "license.jwt").write_text(tok)
    over = dict(bench_env(tmp_path))
    over.update({"AEGIS_LICENSE": str(tmp_path / "license.jwt"), "AEGIS_LICENSE_PUBKEYS": str(keys["dir"]),
                 "AEGIS_INSTALL_ID": "bd-test-install", "AEGIS_LICENSE_ENFORCE": "1", "AEGIS_EDITION": "external"})
    with env_ctx(over):
        from aegis.service import build_pipeline
        p = build_pipeline(tmp_path / "audit.jsonl", fresh=True)
        assert p.license.status == "valid" and p.license.enforce and "Sandbox Bank" in p.banner() and "bd-test-install" in p.banner()
        assert p.license_meter.eps_limit == 0
        srv = PushServer(token="tok", bind="127.0.0.1:0", queue=StreamQueue(10), license=lambda: p.license).start()
        try:
            rq = urllib.request.Request(f"{srv.url}/ingest/license", headers={"Authorization": "Bearer tok"})
            with urllib.request.urlopen(rq, timeout=10) as r:
                body = json.loads(r.read())
            assert body["status"] == "valid" and body["tier"] == "enterprise" and "kafka_bridge" in body["features"]
            with urllib.request.urlopen(f"{srv.url}/healthz", timeout=10) as r:
                assert json.loads(r.read())["license"]["installation_id"] == "bd-test-install"
        finally:
            srv.stop()


def test_cli_roundtrip(tmp_path, capsys):
    assert L.main(["keygen", "--out", str(tmp_path / "k"), "--kid", "cli-kid", "--bits", "1024"]) == 0
    assert L.main(["install-id"]) == 0
    inst = capsys.readouterr().out.strip().splitlines()[-1]
    assert L.main(["issue", "--key", str(tmp_path / "k" / "cli-kid.key.json"), "--customer", "Bank", "--installation", inst,
                   "--tier", "pilot", "--days", "30", "--feature", "kafka_bridge", "--out", str(tmp_path / "l.jwt")]) == 0
    assert "issued L-" in capsys.readouterr().out
    assert L.main(["verify", "--license", str(tmp_path / "l.jwt"), "--pubkeys", str(tmp_path / "k"), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["tier"] == "pilot"
    assert L.main(["verify", "--license", str(tmp_path / "l.jwt"), "--pubkeys", str(tmp_path / "k")]) == 0
    text = capsys.readouterr().out
    assert "licence valid: Bank · pilot" in text and "kafka_bridge" in text
    assert L.main(["verify", "--license", str(tmp_path / "l.jwt"), "--pubkeys", str(tmp_path)]) == 1      # no keys there → invalid
    assert L.main(["report", "--audit", str(tmp_path / "none.jsonl"), "--out", str(tmp_path / "u.json")]) == 0
    rep = json.loads((tmp_path / "u.json").read_text())
    assert rep["audit_chains"] == 0 and len(rep["digest"]) == 64
