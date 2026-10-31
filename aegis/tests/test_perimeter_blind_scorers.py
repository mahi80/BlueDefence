"""Perimeter scorers for the web-layer classes that were blind in the 2026-10-27 purple-team
run and are detectable from the shim's enriched telemetry: SQLi variants (boolean-blind,
ORDER BY, LIKE, sub-select, comment terminators, newline-evaded body), header/cookie injection,
empty/scanner User-Agent, and per-source reconnaissance sweeps.
"""

from __future__ import annotations

import pytest

from aegis.agents.perimeter import tools


# --------------------------------------------------- SQLi variants (decode_payload) -- #

@pytest.mark.parametrize("payload,prim", [
    ("id=1' and 1=1-- ", "' and 1=1"),          # boolean-blind
    ("id=1' and 1=2", "' and 1=2"),             # boolean-blind false probe
    ("id=1 order by 5", "order by "),           # ORDER BY enumeration
    ("name=admin' like '%", "' like '"),        # LIKE injection
    ("id=(select 1)", "(select "),              # nested sub-select
    ("id=1'#", "'#"),                           # MySQL hash comment terminator
    ("id=1') or 1=1", ") or 1=1"),              # paren-close boolean break
])
def test_sqli_variants_now_detected(payload, prim):
    r = tools.decode_payload(payload)
    assert prim in r.data["primitives"]["sqli"]
    assert r.weight in ("medium", "high")


def test_newline_evaded_sqli_body_is_caught_via_collapse():
    # the whitespace-collapse layer normalises "1'\nAND\n1=1" to "1' and 1=1"
    r = tools.decode_payload("id=1'\nAND\n1=1")
    assert r.data["primitives"]["sqli"]            # non-empty


def test_plain_union_still_detected_no_regression():
    r = tools.decode_payload("id=1 UNION SELECT user,pass FROM users")
    assert "union select" in r.data["primitives"]["sqli"]


def test_benign_query_stays_low():
    r = tools.decode_payload("q=interest+rates&page=2")
    assert r.weight == "low" and not r.data["primitives"]["sqli"]


# ------------------------------------------------------------- header / cookie injection -- #

def test_crlf_in_a_header_is_high():
    r = tools.header_injection({"request_headers": {"X-Forwarded-For": "1.1.1.1\r\nSet-Cookie: evil=1"}})
    assert r.weight == "high"
    assert any(h["kind"] == "crlf" for h in r.data["hits"])


def test_sqli_in_a_trusted_header():
    r = tools.header_injection({"request_headers": {"X-Forwarded-For": "' or 1=1-- "}})
    assert r.weight in ("medium", "high")
    assert any(h["header"] == "x-forwarded-for" and h["kind"] == "payload" for h in r.data["hits"])


def test_sqli_in_cookie_is_high_and_flagged():
    r = tools.header_injection({"request_headers": {"Cookie": "sid=abc' union select 1,2-- "}})
    assert r.weight == "high" and r.data["cookie_injection"] is True


def test_clean_headers_stay_low():
    r = tools.header_injection({"request_headers": {"User-Agent": "Mozilla/5.0", "Accept": "*/*"}})
    assert r.weight == "low"


def test_header_injection_no_headers_is_low():
    assert tools.header_injection({}).weight == "low"


# ------------------------------------------------------------------- scanner signature -- #

def test_empty_user_agent_is_a_tell():
    r = tools.scanner_signature({"user_agent": ""})
    assert r.weight == "medium" and "empty" in r.data["reason"]


@pytest.mark.parametrize("ua", ["sqlmap/1.7#stable", "Nikto/2.5", "Nuclei - Open-source"])
def test_known_scanner_ua_is_high(ua):
    assert tools.scanner_signature({"user_agent": ua}).weight == "high"


@pytest.mark.parametrize("ua", ["python-requests/2.31", "curl/8.4.0", "Go-http-client/1.1"])
def test_bare_http_library_is_medium(ua):
    assert tools.scanner_signature({"user_agent": ua}).weight == "medium"


def test_real_browser_ua_is_low():
    ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120 Safari/537.36"
    assert tools.scanner_signature({"user_agent": ua}).weight == "low"


def test_scanner_ua_read_from_request_headers():
    assert tools.scanner_signature({"request_headers": {"User-Agent": "Nikto/2.5"}}).weight == "high"


# -------------------------------------------------------------------- recon sweep (stateful) -- #

def test_recon_sweep_flags_a_path_sweep():
    ip, t = "198.51.100.11", 1_000_000.0
    r = None
    for i in range(25):
        r = tools.recon_sweep(ip, {"url": f"/admin/p{i}"}, now=t + i * 0.1)
    assert r.weight == "high" and r.data["distinct_paths"] >= tools._RECON_PATHS_HIGH


def test_recon_sweep_medium_band():
    ip, t = "198.51.100.12", 2_000_000.0
    r = None
    for i in range(12):
        r = tools.recon_sweep(ip, {"url": f"/x{i}"}, now=t + i)
    assert r.weight == "medium"


def test_recon_sweep_low_for_a_few_paths():
    ip, t = "198.51.100.13", 3_000_000.0
    tools.recon_sweep(ip, {"url": "/"}, now=t)
    r = tools.recon_sweep(ip, {"url": "/login"}, now=t + 1)
    assert r.weight == "low"


def test_recon_sweep_window_expiry_prunes_old_paths():
    ip, t = "198.51.100.14", 4_000_000.0
    for i in range(25):
        tools.recon_sweep(ip, {"url": f"/p{i}"}, now=t + i * 0.1)
    r = tools.recon_sweep(ip, {"url": "/only"}, now=t + tools._RECON_WINDOW_SEC + 100)
    assert r.weight == "low" and r.data["distinct_paths"] == 1


def test_recon_sweep_is_per_source():
    for i in range(25):
        tools.recon_sweep("198.51.100.15", {"url": f"/sweep{i}"}, now=5_000_000.0 + i * 0.1)  # IP A sweeps
    r = tools.recon_sweep("198.51.100.16", {"url": "/home"}, now=5_000_000.0)                 # IP B: one hit
    assert r.weight == "low" and r.data["distinct_paths"] == 1


# ----------------------------------------------------------------------------- wiring -- #

def test_run_all_tools_includes_the_new_scorers():
    names = {r.name for r in tools.run_all_tools(
        "id=1", "203.0.113.9", None, alert={"url": "/", "request_headers": {}})}
    assert {"header_injection", "scanner_signature", "recon_sweep"} <= names
