"""IDOR / object-id enumeration detection and the shim's caller-identity enrichment.

The shim derives a privacy-preserving `principal` (HMAC of the session cookie / bearer) so the
SOC can tell authenticated callers apart even behind one IP — which is what makes id-enumeration
meaningful in a loopback lab where every source IP is 127.0.0.1.
"""

from __future__ import annotations

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "scripts"))
import aegis_edge as E  # noqa: E402

from aegis.agents.perimeter import tools  # noqa: E402


# --------------------------------------------------- shim: caller identity (_principal) -- #

def test_principal_from_session_cookie_is_stable_and_hashed():
    hl = {"cookie": "theme=dark; PHPSESSID=abc123secret; csrf=z"}
    p1, p2 = E._principal(hl), E._principal(hl)
    assert p1.startswith("p:") and p1 == p2
    assert "abc123secret" not in p1            # the raw secret is never stored


def test_principal_from_bearer_token():
    assert E._principal({"authorization": "Bearer eyJhbGciOi.tok"}).startswith("p:")


def test_different_sessions_get_different_principals():
    assert E._principal({"cookie": "session=aaa"}) != E._principal({"cookie": "session=bbb"})


def test_anonymous_request_has_no_principal():
    assert E._principal({"cookie": "theme=dark"}) == ""
    assert E._principal({}) == ""


def test_principal_salt_changes_the_fingerprint(monkeypatch):
    base = E._principal({"cookie": "session=same"})
    monkeypatch.setattr(E, "_PRINCIPAL_SALT", b"a-different-salt")
    assert E._principal({"cookie": "session=same"}) != base


# ------------------------------------------------------- perimeter: id_enumeration -- #

def test_id_enumeration_flags_walking_ids():
    t, r = 7_000_000.0, None
    for i in range(16):
        r = tools.id_enumeration("127.0.0.1", {"url": f"/account?id={i}", "principal": "p:aaa"}, now=t + i)
    assert r.weight == "high" and r.data["distinct_ids"] >= tools._IDENUM_HIGH and r.data["param"] == "id"


def test_id_enumeration_medium_band():
    t, r = 7_100_000.0, None
    for i in range(7):
        r = tools.id_enumeration("127.0.0.1", {"url": f"/doc?doc_id={i}", "principal": "p:bbb"}, now=t + i)
    assert r.weight == "medium"


def test_id_enumeration_is_per_principal_even_behind_one_ip():
    t = 7_200_000.0
    for i in range(16):
        tools.id_enumeration("127.0.0.1", {"url": f"/account?id={i}", "principal": "p:walker"}, now=t + i)
    # a different session on the SAME ip making one lookup is clean — this is why principal matters
    r = tools.id_enumeration("127.0.0.1", {"url": "/account?id=5", "principal": "p:victim"}, now=t)
    assert r.weight == "low" and r.data["distinct_ids"] == 1


def test_id_enumeration_falls_back_to_source_ip_without_principal():
    t, r = 9_000_000.0, None
    for i in range(16):
        r = tools.id_enumeration("203.0.113.50", {"url": f"/invoice?invoice_id={i}"}, now=t + i)
    assert r.weight == "high"


def test_id_enumeration_window_expiry():
    t = 9_500_000.0
    for i in range(16):
        tools.id_enumeration("203.0.113.51", {"url": f"/a?id={i}"}, now=t + i)
    r = tools.id_enumeration("203.0.113.51", {"url": "/a?id=1"}, now=t + tools._IDENUM_WINDOW_SEC + 100)
    assert r.weight == "low"


def test_id_enumeration_ignores_non_id_params():
    r = tools.id_enumeration("127.0.0.1", {"url": "/search?q=hello&page=2", "principal": "p:x"}, now=8e6)
    assert r.data.get("applicable") is False


def test_id_enumeration_reads_body_params():
    t, r = 9_800_000.0, None
    for i in range(16):
        r = tools.id_enumeration("127.0.0.1",
                                 {"url": "/transfer", "body_params": {"account_id": str(i)}, "principal": "p:b"},
                                 now=t + i)
    assert r.weight == "high" and r.data["param"] == "account_id"


def test_run_all_tools_includes_id_enumeration():
    names = {r.name for r in tools.run_all_tools(
        "id=1", "203.0.113.9", None, alert={"url": "/", "request_headers": {}})}
    assert "id_enumeration" in names
