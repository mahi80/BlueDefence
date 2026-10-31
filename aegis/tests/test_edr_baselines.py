"""Per-host-class baselines + host_class-aware EDR scoring."""
from __future__ import annotations

from aegis.agents.edr import tools
from aegis.agents.edr.baselines import HOST_BASELINES, norm_autostart


def test_norm_autostart_collapses_per_user_path():
    a = norm_autostart("OneDrive", "C:\\Users\\alice\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe")
    b = norm_autostart("OneDrive", "C:\\Users\\bob\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe")
    assert a == b  # one baseline entry matches every user


def test_profiles_merge_default_into_class():
    tcc = HOST_BASELINES.tcc_allowlist("macos-workstation")
    assert "com.apple." in tcc                       # from _default
    assert "/Applications/zoom.us.app" in tcc        # from the class


def test_unknown_class_falls_back_to_default():
    assert HOST_BASELINES.autostart("no-such-class") == HOST_BASELINES.autostart(None)
    assert "com.apple." in HOST_BASELINES.tcc_allowlist("no-such-class")


def test_known_windows_autostart_is_low_across_users():
    entry = [{"name": "OneDrive", "source": "Run",
              "path": "C:\\Users\\carol\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe"}]
    assert tools.autostart_persistence(entry, HOST_BASELINES.autostart("windows-workstation")).weight == "low"


def test_new_linux_unit_is_flagged_against_web_baseline():
    r = tools.autostart_persistence(
        [{"name": "evil.service", "source": "persistence_systemd", "path": "/etc/systemd/system/evil.service"}],
        HOST_BASELINES.autostart("linux-web"))
    assert r.weight in ("medium", "high") and r.data["n"] == 1


def test_known_nginx_unit_is_low_against_web_baseline():
    r = tools.autostart_persistence(
        [{"name": "nginx.service", "source": "persistence_systemd", "path": "/lib/systemd/system/nginx.service"}],
        HOST_BASELINES.autostart("linux-web"))
    assert r.weight == "low"


def test_tcc_trusted_on_macos_class_is_low():
    r = tools.tcc_grant("kTCCServiceMicrophone", "/Applications/zoom.us.app", allowed=1,
                        allowlist=HOST_BASELINES.tcc_allowlist("macos-workstation"))
    assert r.weight == "low"


def test_tcc_unknown_app_on_macos_class_is_high():
    r = tools.tcc_grant("kTCCServiceCamera", "/Applications/Spyware.app", allowed=1,
                        allowlist=HOST_BASELINES.tcc_allowlist("macos-workstation"))
    assert r.weight == "high"


def test_deploy_key_known_on_web_class_is_low():
    fpr = next(iter(HOST_BASELINES.ssh_keys("linux-web")))
    assert tools.ssh_key_added(fpr, baseline=HOST_BASELINES.ssh_keys("linux-web")).weight == "low"


def test_run_all_tools_uses_host_class():
    flagged = {r.name: r for r in tools.run_all_tools({
        "host_class": "linux-web",
        "autostart_entries": [{"name": "evil.service", "path": "/etc/systemd/system/evil.service",
                               "source": "persistence_systemd"}]})}
    assert flagged["autostart_persistence"].weight in ("medium", "high")
    clean = {r.name: r for r in tools.run_all_tools({
        "host_class": "linux-web",
        "autostart_entries": [{"name": "nginx.service", "path": "/lib/systemd/system/nginx.service",
                               "source": "persistence_systemd"}]})}
    assert clean["autostart_persistence"].weight == "low"


# ---- inventory-agent feed ---------------------------------------------------
def test_update_extends_profile_additively():
    from aegis.agents.edr.baselines import HostBaselines, norm_autostart
    hb = HostBaselines({"linux-web": {"autostart": [["nginx.service", "/lib/systemd/system/nginx.service"]]}})
    hb.update({"linux-web": {"autostart": [["myapp.service", "/opt/myapp.service"]]}})
    aset = hb.autostart("linux-web")
    assert norm_autostart("nginx.service", "/lib/systemd/system/nginx.service") in aset
    assert norm_autostart("myapp.service", "/opt/myapp.service") in aset  # both kept


def test_feed_inventory_baselines_hook(monkeypatch):
    from aegis.agents.edr import baselines as B
    fresh = B.HostBaselines({"linux-web": {"autostart": []}})
    monkeypatch.setattr(B, "HOST_BASELINES", fresh)   # don't mutate the shared singleton
    B.feed_inventory_baselines({"linux-web": {"ssh_keys": ["SHA256:fed-in-deploy-key"]}})
    assert "SHA256:fed-in-deploy-key" in B.HOST_BASELINES.ssh_keys("linux-web")
