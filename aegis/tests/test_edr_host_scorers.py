"""Host-layer EDR scorers + the Sysmon/osquery normalizer.

Covers the five additions that extend EDR from process/IOC to the full
endpoint/host artifact checklist: persistence, web-shell drop, C2 beaconing,
macOS TCC grants, and SSH-key additions — plus the collector normalizer.
"""
from __future__ import annotations

import pytest

from aegis.agents.edr import tools, normalize


# ------------------------------------------------------- autostart_persistence
def test_autostart_new_hot_path_is_high():
    r = tools.autostart_persistence([{"name": "Updater", "path": "C:\\Users\\Public\\u.exe", "source": "Run"}])
    assert r.weight == "high" and r.data["n"] == 1 and r.data["hot_path"] is True


def test_autostart_new_normal_path_is_medium():
    r = tools.autostart_persistence([{"name": "X", "path": "C:\\Program Files\\X\\x.exe", "source": "Run"}])
    assert r.weight == "medium" and r.data["hot_path"] is False


def test_autostart_baselined_entry_is_low():
    known = next(iter(tools._AUTOSTART_BASELINE))
    r = tools.autostart_persistence([{"name": known[0], "path": known[1], "source": "Run"}])
    assert r.weight == "low" and r.data["n"] == 0


def test_autostart_no_data_is_low():
    assert tools.autostart_persistence(None).weight == "low"


# --------------------------------------------------------------- webshell_drop
def test_webshell_with_tokens_is_high():
    r = tools.webshell_drop("/var/www/html/up/shell.php", ["eval", "base64_decode"])
    assert r.weight == "high" and "eval" in r.data["webshell_tokens"]


def test_webshell_script_without_tokens_is_medium():
    r = tools.webshell_drop("/inetpub/wwwroot/x.aspx", [])
    assert r.weight == "medium" and r.data["in_webroot"] is True


def test_script_outside_webroot_is_low():
    assert tools.webshell_drop("/home/mahi/notes.php", ["eval"]).weight == "low"


def test_webshell_no_path_is_low():
    assert tools.webshell_drop(None).weight == "low"


# ----------------------------------------------------------- beacon_periodicity
def test_regular_beacon_is_high():
    times = [1_700_000_000.0 + 60 * i for i in range(6)]
    r = tools.beacon_periodicity(times, dest="203.0.113.9:4444")
    assert r.weight == "high" and r.data["regular"] is True and r.data["mean_interval_s"] == 60.0


def test_jittery_egress_is_low():
    times = [0.0, 5.0, 100.0, 101.0, 500.0, 503.0]
    assert tools.beacon_periodicity(times, dest="x").weight == "low"


def test_too_few_connects_is_low():
    assert tools.beacon_periodicity([1.0, 2.0, 3.0], dest="x").data["verdict"] == "insufficient_data"


# ------------------------------------------------------------------- tcc_grant
def test_tcc_sensitive_untrusted_is_high():
    r = tools.tcc_grant("kTCCServiceMicrophone", "/Applications/Weather.app", allowed=1)
    assert r.weight == "high" and r.data["trusted"] is False


def test_tcc_trusted_client_is_low():
    # round 7 D-12: a "com.apple." bundle id is a name anyone can pick — trusted only with Apple's signing authority
    assert tools.tcc_grant("kTCCServiceCamera", "com.apple.FaceTime", allowed=1, authority="Software Signing").weight == "low"
    assert tools.tcc_grant("kTCCServiceCamera", "com.apple.FaceTime", allowed=1).weight == "medium"


def test_tcc_non_sensitive_service_is_low():
    r = tools.tcc_grant("kTCCServiceAddressBook", "/Applications/x.app", allowed=1)
    assert r.weight == "low" and r.data["applicable"] is False


# --------------------------------------------------------------- ssh_key_added
def test_new_ssh_key_is_high():
    r = tools.ssh_key_added("SHA256:deadbeef", uid="1000")
    assert r.weight == "high" and r.data["known"] is False


def test_known_ssh_key_is_low():
    r = tools.ssh_key_added("SHA256:known", baseline={"SHA256:known"})
    assert r.weight == "low" and r.data["known"] is True


# ----------------------------------------------------------------------- wiring
def test_run_all_tools_includes_host_scorers():
    names = {r.name for r in tools.run_all_tools({})}
    assert {"autostart_persistence", "webshell_drop", "beacon_periodicity",
            "tcc_grant", "ssh_key_added"} <= names


def test_run_all_tools_on_empty_alert_is_all_low():
    # every scorer degrades gracefully to low/no_data when its fields are absent
    assert all(r.weight == "low" for r in tools.run_all_tools({}))


# ------------------------------------------------------------- sysmon normalize
def test_from_sysmon_process_create():
    a = normalize.from_sysmon({"event_id": 1, "host": "h1",
                               "ParentImage": "C:\\Office\\WINWORD.EXE",
                               "Image": "C:\\Windows\\System32\\cmd.exe",
                               "CommandLine": "cmd /c whoami"})
    assert a["parent_process"] == "WINWORD.EXE" and a["child_process"] == "cmd.exe"


def test_from_sysmon_network_and_file_and_reg():
    net = normalize.from_sysmon({"event_id": 3, "host": "h", "DestinationIp": "1.2.3.4",
                                 "DestinationPort": "4444", "ts": "1000"})
    assert net["dest_ip"] == "1.2.3.4" and net["dst_port"] == 4444 and net["egress_ts"] == 1000.0
    f = normalize.from_sysmon({"event_id": 11, "host": "h", "TargetFilename": "/var/www/x.php"})
    assert f["file_path"] == "/var/www/x.php"
    reg = normalize.from_sysmon({"event_id": 13, "host": "h",
                                 "TargetObject": "HKLM\\...\\CurrentVersion\\Run\\Evil",
                                 "Details": "C:\\Users\\Public\\u.exe"})
    assert reg["autostart_entries"][0]["name"] == "Evil"


# ------------------------------------------------------------ osquery normalize
def test_from_osquery_persistence_and_tcc_and_ssh():
    p = normalize.from_osquery("persistence_crontab", {"command": "/tmp/evil.sh", "_host": "h"})
    assert p["autostart_entries"][0]["path"] == "/tmp/evil.sh"
    t = normalize.from_osquery("macos_tcc_grants",
                               {"service": "kTCCServiceMicrophone", "client": "/Applications/x.app", "allowed": "1"})
    assert t["tcc_service"] == "kTCCServiceMicrophone" and t["tcc_allowed"] == 1
    s = normalize.from_osquery("persistence_authorized_keys",
                               {"key": "ssh-ed25519 AAAAC3NzaC1lZDI1 user@h", "uid": "1000"})
    assert s["ssh_key_fingerprint"].startswith("SHA256:") and s["ssh_key_uid"] == "1000"


# ------------------------------------------------- beacon aggregator end-to-end
def test_beacon_aggregator_builds_series_then_scores_high():
    agg = normalize.BeaconAggregator()
    alert = {}
    for i in range(6):
        alert = agg.enrich(normalize.from_sysmon(
            {"event_id": 3, "host": "h", "DestinationIp": "9.9.9.9", "DestinationPort": "443",
             "ts": str(1_700_000_000 + 300 * i)}))
    assert len(alert["egress_connect_times"]) == 6
    r = tools.beacon_periodicity(alert["egress_connect_times"], alert["dest_ip"])
    assert r.weight == "high" and r.data["mean_interval_s"] == 300.0
