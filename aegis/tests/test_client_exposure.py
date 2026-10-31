"""2.8c client-exposure scan + 2.8d stack canaries."""

from aegis.agents.deception.honeytoken_monitor import HoneytokenMonitor, registry_with_stacks
from aegis.agents.vuln_discovery.client_exposure import CANARY_PACK, CHECKS, canaries_for, client_exposure_scan


def _ids(findings):
    return {f.id.split(":")[0] for f in findings}


def test_react_leaky_build_fires_expected_checks():
    scope = {
        "name": "netbanking-web", "stack": "react",
        "build_files": ["main.3f2.js", "main.3f2.js.map"],
        "env_in_bundle": ["REACT_APP_API_KEY", "REACT_APP_THEME"],
        "routes": ["/asset-manifest.json", "/admin/"],
        "graphql": {"introspection": True},
        "security_headers": {},
        "sri_on_scripts": False,
    }
    f = client_exposure_scan(scope)
    assert {"CX-001", "CX-002", "CX-003", "CX-007", "CX-011", "CX-012", "CX-013"} <= _ids(f)
    assert "CX-004" not in _ids(f)                      # django-only check must not fire for react
    crit = [x for x in f if x.id.startswith("CX-002")]
    assert crit and crit[0].severity == "critical" and crit[0].risk_score is not None
    assert all(x.category == "misconfig" for x in f)


def test_bundle_text_secret_shapes():
    f = client_exposure_scan({"stack": "vue", "bundle_text": "const k='AKIAABCDEFGHIJKLMNOP';"})
    assert "CX-002" in _ids(f)
    f2 = client_exposure_scan({"stack": "vue", "bundle_text": "const theme='dark';"})
    assert "CX-002" not in _ids(f2)


def test_django_debug_and_browsable_api():
    f = client_exposure_scan({"stack": "django", "settings": {"DEBUG": "True"}, "routes": ["/api/schema/", "/__debug__/"],
                              "security_headers": {"content-security-policy": "default-src 'self'"}})
    assert {"CX-003", "CX-004", "CX-006"} <= _ids(f)
    assert "CX-011" not in _ids(f)


def test_laravel_php_symfony_debug_flags():
    assert "CX-005" in _ids(client_exposure_scan({"stack": "laravel", "settings": {"APP_DEBUG": "true"}}))
    assert "CX-005" in _ids(client_exposure_scan({"stack": "php", "settings": {"display_errors": "On"}}))
    assert "CX-005" not in _ids(client_exposure_scan({"stack": "symfony", "settings": {"APP_DEBUG": "false"}}))


def test_mobile_pinning_and_embedded_keys():
    f = client_exposure_scan({"stack": "mobile", "mobile": {"cert_pinning": False, "keys_in_app": ["k1"]},
                              "routes": ["/api/v1/internal/x"]})
    assert {"CX-009", "CX-010", "CX-003"} <= _ids(f)
    assert "CX-009" not in _ids(client_exposure_scan({"stack": "mobile", "mobile": {"cert_pinning": True}}))


def test_clean_deployable_yields_nothing():
    f = client_exposure_scan({"stack": "nextjs", "build_files": ["app.js"], "routes": ["/"],
                              "security_headers": {"content-security-policy": "x"}, "sri_on_scripts": True,
                              "admin_ip_restricted": True})
    assert f == []


def test_malformed_scope_does_not_abort():
    f = client_exposure_scan({"stack": "angular", "mobile": "oops", "graphql": 5, "routes": None or [],
                              "security_headers": {"content-security-policy": "x"}, "sri_on_scripts": True})
    assert isinstance(f, list)


def test_every_check_has_unique_id_and_remediation():
    ids = [c.id for c in CHECKS]
    assert len(ids) == len(set(ids))
    assert all(c.remediation for c in CHECKS)


def test_agent_scan_includes_deployables():
    from aegis.agents.vuln_discovery.agent import VulnDiscoveryAgent

    class L:
        def complete(self, *a, **k):
            class R: text = '{"summary": "ok"}'
            return R()

    chain, findings = VulnDiscoveryAgent(L()).scan({"scan_id": "S1", "deployables": [
        {"name": "web", "stack": "react", "build_files": ["a.js.map"], "security_headers": {"content-security-policy": "x"}, "sri_on_scripts": True}]})
    assert any(f.id.startswith("CX-001") for f in findings)
    assert chain.verdict == "suspicious" and chain.recommended_actions[0].requires_hitl


# ---- 2.8d canaries

def test_canaries_cover_every_stack_and_are_decoys():
    for stack in CANARY_PACK:
        toks = canaries_for(stack)
        assert toks and all(t.id.startswith(f"cx_{stack}_") for t in toks)
        assert any(t.kind == "url" for t in toks)
    assert all(("DECOY" in t.value or "old" in t.value or "internal" in t.value or "staging" in t.value or "legacy" in t.value
                or t.kind != "api_key") for s in CANARY_PACK for t in canaries_for(s))


def test_registry_with_stacks_dedups_and_monitor_matches(monkeypatch):
    reg = registry_with_stacks(["react", "django", "react"])
    vals = [t.value for t in reg]
    assert len(vals) == len(set(vals)) and any(v == "/admin-old/" for v in vals)
    mon = HoneytokenMonitor(reg)
    assert mon.alert_touches_decoy({"url": "/static/js/vendor.a1b2.js.map"})
    assert mon.alert_touches_decoy({"raw": "GET /api/v1/admin/export HTTP/1.1"})
    assert not mon.alert_touches_decoy({"url": "/static/js/main.js"})
    chain = mon.build_chain({"id": "A1", "url": "/admin-old/"})
    assert chain.verdict == "malicious"
    monkeypatch.setenv("AEGIS_STACKS", "laravel")
    assert any(t.value == "/telescope-old" for t in HoneytokenMonitor()._registry)
    monkeypatch.delenv("AEGIS_STACKS")
    assert not any(t.value == "/telescope-old" for t in HoneytokenMonitor()._registry)
