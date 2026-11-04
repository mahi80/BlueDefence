"""Integration plan #8b/#8d: the OpenShell sandbox policy for AEGIS itself, generated from its configuration."""

from __future__ import annotations

from pathlib import Path

import yaml

from aegis.ops.openshell_policy import build_policy, collect, main

ENV = {"AEGIS_EDR_VENDOR": "defender", "AEGIS_IDP_VENDOR": "entra", "AEGIS_FW_VENDOR": "panos",
       "AEGIS_FW_URL": "https://fw.bank.internal", "AEGIS_FW_TOKEN": "pan-secret-key",
       "ANTHROPIC_API_KEY": "sk-ant-secret", "ACP_DASHBOARD_URL": "https://dashboard.acpgovernance.com",
       "AEGIS_KAFKA_BOOTSTRAP": "k1.bank:9093,k2.bank:9093", "AEGIS_INDEX_URL": "duckdb:///var/aegis/index.db",
       "AEGIS_CVE_INTEL": "1", "AEGIS_HITL_DIR": "/var/lib/aegis/hitl", "AEGIS_AUDIT_PATH": "/var/lib/aegis/audit.jsonl",
       "AEGIS_PAM_URL": "https://pvwa.bank.internal", "AEGIS_AD_URL": "ldaps://dc1.bank.local"}


def _hosts(pol):
    return {(e["host"], e["port"]) for p in pol["network_policies"].values() for e in p["endpoints"]}


def test_hosts_come_from_config_and_vendor_defaults():
    hosts = _hosts(build_policy(ENV, python="/usr/bin/python3"))
    assert ("fw.bank.internal", 443) in hosts and ("pvwa.bank.internal", 443) in hosts
    assert ("dc1.bank.local", 636) in hosts                                      # ldaps default port
    assert ("api.securitycenter.microsoft.com", 443) in hosts and ("graph.microsoft.com", 443) in hosts
    assert ("login.microsoftonline.com", 443) in hosts and ("api.anthropic.com", 443) in hosts
    assert {("k1.bank", 9093), ("k2.bank", 9093)} <= hosts
    assert ("services.nvd.nist.gov", 443) in hosts
    assert not any("duckdb" in h or h == "var" for h, _ in hosts)               # a local index file is not a host


def test_no_secret_ever_lands_in_the_policy():
    text = yaml.safe_dump(build_policy(ENV))
    for secret in ("pan-secret-key", "sk-ant-secret"):
        assert secret not in text


def test_explicit_url_replaces_the_vendor_default_and_off_means_off():
    env = {"AEGIS_EDR_VENDOR": "crowdstrike", "AEGIS_EDR_URL": "https://api.eu-1.crowdstrike.com", "AEGIS_CVE_INTEL": "0"}
    hosts = {hp for v in collect(env).values() for hp in v}
    assert hosts == {("api.eu-1.crowdstrike.com", 443)}


def test_protocols_filesystem_and_shape():
    pol = build_policy(ENV, extra=["siem.bank.internal:6514"], state_dirs=["/data"])
    assert pol["version"] == 1 and pol["landlock"] == {"compatibility": "best_effort"}
    assert set(pol["filesystem_policy"]["read_write"]) == {"/data", "/var/lib/aegis/hitl", "/var/lib/aegis"}
    kafka = pol["network_policies"]["kafka"]["endpoints"]
    assert all("protocol" not in e for e in kafka)                               # L4 for Kafka
    assert pol["network_policies"]["fw"]["endpoints"][0]["protocol"] == "rest"
    assert ("siem.bank.internal", 6514) in _hosts(pol)


def test_cli_and_range_sample(tmp_path, monkeypatch, capsys):
    for k in list(ENV):
        monkeypatch.setenv(k, ENV[k])
    out = tmp_path / "p.yaml"
    assert main(["--out", str(out)]) == 0
    text = out.read_text()
    assert text.startswith("# OpenShell policy for AEGIS") and "fw.bank.internal" in text
    assert yaml.safe_load(text)["network_policies"]
    rng = Path(__file__).resolve().parents[2] / "deploy" / "openshell" / "attack-range-policy.yaml"
    assert yaml.safe_load(rng.read_text())["network_policies"]["range_targets"]["endpoints"]
