"""Perimeter scorer batch — detection for the signatureless / structural web-layer
classes the range flagged as blind: XXE, SSRF (resolved-destination), CORS credential
reflection, mass-assignment, host-header injection.

Each detector degrades to low weight when its telemetry field is absent, so adding them
never destabilises an alert that lacks response headers / form schema / Host.
"""
from aegis.agents.perimeter import tools


# ---- XXE (folded into the layered payload scan) ------------------------

def test_xxe_doctype_entity_system_flagged_high():
    payload = '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>'
    r = tools.decode_payload(payload)
    assert r.data["primitives"]["xxe"], "XXE primitives should be detected"
    assert r.weight == "high"  # DOCTYPE + ENTITY + SYSTEM file: → ≥2 hits


def test_xxe_php_filter_base64_flagged():
    r = tools.decode_payload("php://filter/convert.base64-encode/resource=/var/www/html/inc/config.inc")
    assert r.data["primitives"]["xxe"]


def test_benign_xml_not_flagged_as_xxe():
    r = tools.decode_payload('<?xml version="1.0"?><card><pan>4111</pan></card>')
    assert not r.data["primitives"]["xxe"]


# ---- SSRF (resolved-destination aware) ---------------------------------

def test_ssrf_metadata_ip():
    r = tools.ssrf_probe("url=http://169.254.169.254/latest/meta-data/iam/")
    assert r.weight == "high" and r.data["n"] == 1
    assert r.data["targets"][0]["host"] == "169.254.169.254"


def test_ssrf_internal_service_name_with_scheme():
    r = tools.ssrf_probe("url=http://meta:8000/token")
    assert r.weight == "high" and r.data["targets"][0]["host"] == "meta"


def test_ssrf_scheme_less_service_ref():
    # the exact gap: fetch.php reaching meta:8000, which a three-literal blocklist misses
    r = tools.ssrf_probe("target=meta:8000")
    assert r.weight == "high" and any(t["host"] == "meta" for t in r.data["targets"])


def test_ssrf_rfc1918_and_loopback():
    assert tools.ssrf_probe("u=http://10.0.0.5/admin").weight == "high"
    assert tools.ssrf_probe("u=http://127.0.0.1:9000/").weight == "high"


def test_ssrf_dangerous_scheme_only_is_medium():
    r = tools.ssrf_probe("doc=file:///etc/hostname")
    assert r.weight == "medium"  # empty host → no target, but file:// scheme is still flagged
    assert "file://" in r.data["dangerous_schemes"]


def test_ssrf_public_url_is_clean():
    r = tools.ssrf_probe("url=https://api.partner-bank.example.com/v1/rates")
    assert r.weight == "low" and r.data["n"] == 0


# ---- CORS reflection ---------------------------------------------------

def test_cors_reflects_origin_with_credentials_high():
    alert = {"origin": "https://evil.example",
             "response_headers": {"Access-Control-Allow-Origin": "https://evil.example",
                                  "Access-Control-Allow-Credentials": "true"}}
    r = tools.cors_reflection(alert)
    assert r.weight == "high" and r.data["allow_credentials"] is True


def test_cors_wildcard_with_credentials_high():
    alert = {"response_headers": {"Access-Control-Allow-Origin": "*",
                                  "Access-Control-Allow-Credentials": "true"}}
    assert tools.cors_reflection(alert).weight == "high"


def test_cors_reflected_without_credentials_medium():
    alert = {"origin": "https://evil.example",
             "response_headers": {"Access-Control-Allow-Origin": "https://evil.example"}}
    assert tools.cors_reflection(alert).weight == "medium"


def test_cors_no_headers_graceful_low():
    assert tools.cors_reflection({}).weight == "low"


# ---- Mass assignment ---------------------------------------------------

def test_mass_assignment_sensitive_extra_param_high():
    alert = {"form_fields": ["name", "email", "phone", "address"]}
    r = tools.mass_assignment(alert, "name=Mahi&email=m%40x.io&credit_score=999&kyc_status=verified")
    assert r.weight == "high"
    assert "credit_score" in r.data["sensitive"] and "kyc_status" in r.data["sensitive"]


def test_mass_assignment_extra_nonsensitive_medium():
    alert = {"form_fields": ["name", "email"]}
    r = tools.mass_assignment(alert, "name=Mahi&email=m%40x.io&nickname=mb")
    assert r.weight == "medium" and r.data["extra_params"] == ["nickname"]


def test_mass_assignment_no_schema_denylist_fallback():
    r = tools.mass_assignment({}, "name=Mahi&role=admin")
    assert r.weight == "medium" and "role" in r.data["sensitive_params_posted"]


def test_mass_assignment_clean_post_low():
    alert = {"form_fields": ["name", "email"]}
    assert tools.mass_assignment(alert, "name=Mahi&email=m%40x.io").weight == "low"


# ---- Host-header anomaly -----------------------------------------------

def test_host_header_crlf_high():
    r = tools.host_header_anomaly({"host": "bank.example\r\nX-Injected: 1"})
    assert r.weight == "high" and "crlf in host header" in r.data["reasons"]


def test_host_header_multiple_hosts_high():
    assert tools.host_header_anomaly({"host": "bank.example evil.example"}).weight == "high"


def test_host_header_off_allowlist_medium(monkeypatch):
    monkeypatch.setenv("AEGIS_EXPECTED_HOSTS", "bank.example,api.bank.example")
    assert tools.host_header_anomaly({"host": "attacker.example"}).weight == "medium"


def test_host_header_known_host_low(monkeypatch):
    monkeypatch.setenv("AEGIS_EXPECTED_HOSTS", "bank.example")
    assert tools.host_header_anomaly({"host": "bank.example:8444"}).weight == "low"


def test_host_header_absent_graceful_low():
    assert tools.host_header_anomaly({}).weight == "low"


# ---- Runner wiring + backward compatibility ----------------------------

def test_run_all_tools_includes_new_scorers():
    names = {r.name for r in tools.run_all_tools("x=1", "1.2.3.4", None)}
    assert {"ssrf_probe", "cors_reflection", "mass_assignment", "host_header_anomaly"} <= names


def test_run_all_tools_backward_compatible_without_alert():
    # old 3-arg call site must still work (alert defaults to {})
    results = tools.run_all_tools("x=1", "1.2.3.4", "u_42891")
    assert len(results) == 14


def test_newline_payload_does_not_crash():
    # CRLF in a body is a measured non-vuln on PHP 7.4; detectors must handle it without error
    for fn_payload in ("a=1\r\nb=2", "<!DOCTYPE x\n>", "url=http://10.0.0.1\n/x"):
        tools.decode_payload(fn_payload)
        tools.ssrf_probe(fn_payload)
        tools.mass_assignment({}, fn_payload)
