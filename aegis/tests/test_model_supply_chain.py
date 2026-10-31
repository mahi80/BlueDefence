"""Model supply-chain governance policy + its host-IOC wiring (HF loader campaign)."""
from __future__ import annotations

from aegis.agents.vuln_discovery.model_supply_chain import (
    evaluate_model_load, scan_models, is_allowlisted, iocs_host,
    ADVISORY_HF_LOADER_CAMPAIGN as ADV)
from aegis.agents.edr import tools as edr_tools


def _controls(reqs):
    return {f.control for f in evaluate_model_load(reqs)}


def test_known_malicious_repo_is_critical():
    f = evaluate_model_load({"model": "MENXIANGYU/qwen2-tiny"})
    assert any(x.control == "KNOWN_MALICIOUS_REPO" and x.severity == "critical" for x in f)


def test_known_malicious_loader_filename_flags():
    f = evaluate_model_load({"model": "someone/clean-looking",
                             "loader_files": [{"name": "modeling_evil2.py", "tokens": []}]})
    assert any(x.control == "KNOWN_MALICIOUS_REPO" for x in f)


def test_unvetted_publisher_flagged_but_allowlisted_is_not():
    assert "UNVETTED_PUBLISHER" in _controls({"model": "randomuser/model", "revision": "abc"})
    assert "UNVETTED_PUBLISHER" not in _controls({"model": "Qwen/Qwen3-8B", "revision": "abc"})


def test_allowlist_is_case_insensitive():
    assert is_allowlisted("Qwen/Qwen3-8B") and is_allowlisted("meta-llama/Llama-3.1-8B")
    assert not is_allowlisted("menxiangyu/qwen2-tiny")


def test_unpinned_revision_flagged():
    assert "UNPINNED_REVISION" in _controls({"model": "Qwen/x", "revision": "main"})
    assert "UNPINNED_REVISION" in _controls({"model": "Qwen/x"})            # absent revision
    assert "UNPINNED_REVISION" not in _controls({"model": "Qwen/x", "revision": "9af1c2e"})


def test_unreviewed_remote_code_escalates_with_auto_map():
    low = evaluate_model_load({"model": "Qwen/x", "revision": "9af1", "trust_remote_code": True})
    assert any(x.control == "UNREVIEWED_REMOTE_CODE" and x.severity == "high" for x in low)
    hi = evaluate_model_load({"model": "Qwen/x", "revision": "9af1", "trust_remote_code": True, "auto_map": True})
    assert any(x.control == "UNREVIEWED_REMOTE_CODE" and x.severity == "critical" for x in hi)


def test_reviewed_remote_code_is_allowed():
    f = evaluate_model_load({"model": "Qwen/x", "revision": "9af1",
                             "trust_remote_code": True, "auto_map": True, "reviewed": True})
    assert "UNREVIEWED_REMOTE_CODE" not in {x.control for x in f}


def test_decoy_weights_is_critical():
    f = evaluate_model_load({"model": "x/y", "revision": "9af1", "auto_map": True, "weights_bytes": 42})
    assert any(x.control == "DECOY_WEIGHTS" and x.severity == "critical" for x in f)


def test_normal_weights_not_flagged_decoy():
    f = evaluate_model_load({"model": "x/y", "revision": "9af1", "auto_map": True, "weights_bytes": 5_000_000})
    assert "DECOY_WEIGHTS" not in {x.control for x in f}


def test_risky_loader_imports_flagged():
    f = evaluate_model_load({"model": "Qwen/x", "revision": "9af1",
                             "loader_files": [{"name": "modeling_x.py", "tokens": ["subprocess", "socket", "numpy"]}]})
    assert any(x.control == "RISKY_LOADER_IMPORTS" for x in f)


def test_clean_allowlisted_pinned_reviewed_load_is_clean():
    f = evaluate_model_load({"model": "Qwen/Qwen3-8B", "revision": "9af1c2e",
                             "trust_remote_code": False, "reviewed": True,
                             "auto_map": False, "weights_bytes": 5_000_000, "loader_files": []})
    assert f == []


def test_scan_models_returns_dicts():
    rows = scan_models([{"model": "MENXIANGYU/qwen2-tiny"}])
    assert rows and isinstance(rows[0], dict) and rows[0]["control"] == "KNOWN_MALICIOUS_REPO"


def test_host_iocs_feed_edr_ioc_match():
    # a load that slips the policy is still caught by the host layer on its C2/exfil IPs
    for ip in iocs_host(ADV)["ips"]:
        r = edr_tools.ioc_match(None, None, ip)
        assert r.weight == "high" and r.data["n"] == 1
