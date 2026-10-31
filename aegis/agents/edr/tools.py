"""Tools for the EDR/Host specialist."""
from __future__ import annotations

import re
from dataclasses import dataclass

from .baselines import HOST_BASELINES, norm_autostart


@dataclass
class ToolResult:
    name: str
    data: dict
    weight: str


# ---- Suspicious process patterns --------------------------------------

_SUSPICIOUS_PROCESS_PARENTS = {
    # office binaries spawning script interpreters → classic macro abuse
    "winword.exe":     {"powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe"},
    "excel.exe":       {"powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe"},
    "outlook.exe":     {"powershell.exe", "cmd.exe", "rundll32.exe"},
    # web servers spawning shells → webshell / RCE
    "w3wp.exe":        {"cmd.exe", "powershell.exe", "bash"},
    "nginx":           {"sh", "bash", "python", "perl"},
    "apache2":         {"sh", "bash"},
    # lsass dumping
    "rundll32.exe":    {"comsvcs.dll"},
}

_SUSPICIOUS_CMDLINE_PATTERNS = [
    r"-enc[odedcommand]*\s+[A-Za-z0-9+/=]{40,}",       # base64 PowerShell
    r"DownloadString\(",                                 # PS download
    r"IEX\s*\(",                                          # PS in-memory exec
    r"\bnc\b.*-e\s+/?bin/sh",                            # netcat reverse shell
    r"bash\s+-i\s+>&\s+/dev/tcp/",                       # bash reverse shell
    r"mimikatz",
    r"procdump.*lsass",
    r"vssadmin\s+delete\s+shadows",                      # ransomware indicator
]
_CMDLINE_RX = re.compile("|".join(_SUSPICIOUS_CMDLINE_PATTERNS), re.IGNORECASE)


def parent_process_tree(parent: str | None, child: str | None, cmdline: str | None) -> ToolResult:
    parent_l = (parent or "").lower()
    child_l = (child or "").lower()
    cmdline_v = cmdline or ""
    suspicious_parent_child = False
    if parent_l in _SUSPICIOUS_PROCESS_PARENTS:
        if any(c in child_l for c in _SUSPICIOUS_PROCESS_PARENTS[parent_l]):
            suspicious_parent_child = True
    cmdline_match = bool(_CMDLINE_RX.search(cmdline_v))
    weight = "high" if (suspicious_parent_child or cmdline_match) else "low"
    return ToolResult(
        name="parent_process_tree",
        data={
            "parent": parent,
            "child": child,
            "suspicious_pair": suspicious_parent_child,
            "cmdline_indicators": cmdline_match,
            "cmdline": cmdline_v[:200],
        },
        weight=weight,
    )


# ---- Lateral movement check -------------------------------------------

# Known east-west "good" patterns: client -> app, app -> db, app -> redis, etc.
_KNOWN_GOOD_FLOWS = {
    ("app_tier", "db_tier"),
    ("app_tier", "cache_tier"),
    ("frontend_tier", "app_tier"),
    ("ci_runner", "artifact_store"),
}


def lateral_movement_check(src_zone: str | None, dst_zone: str | None, port: int | None,
                           uses_smb_or_winrm: bool = False) -> ToolResult:
    if not (src_zone and dst_zone):
        return ToolResult(name="lateral_movement", data={"verdict": "insufficient_data"}, weight="low")
    flow_known = (src_zone, dst_zone) in _KNOWN_GOOD_FLOWS
    smb_winrm = uses_smb_or_winrm or port in (445, 5985, 5986, 3389)
    cross_zone_admin = (not flow_known) and smb_winrm
    return ToolResult(
        name="lateral_movement",
        data={
            "src_zone": src_zone,
            "dst_zone": dst_zone,
            "port": port,
            "flow_known": flow_known,
            "admin_protocol": smb_winrm,
            "cross_zone_admin": cross_zone_admin,
        },
        weight="high" if cross_zone_admin else "medium" if not flow_known else "low",
    )


# ---- IOC match --------------------------------------------------------

# Stand-in IOC list. Production: pulled by Threat Intel agent.
_IOC_HASHES = {
    "44d88612fea8a8f36de82e1278abb02f": "EICAR test (training)",
    "9b8c1bdc1f3f3e6c9e4b8c1bdc1f3f3e": "Cobalt Strike beacon (sample)",
}
_IOC_DOMAINS = {"evil.example.com", "c2.attacker.test"}
_IOC_IPS = {"203.0.113.66", "198.51.100.99",
            # HF/ModelScope model-loader cryptominer campaign (AEGIS-TI-2026-HF-LOADER):
            # reverse shell, exfil, and wave-1 C2 — catches post-exploitation of a slipped model load.
            "212.32.253.3", "2.28.9.199", "8.137.187.63"}


def ioc_match(file_hash: str | None, dest_domain: str | None, dest_ip: str | None) -> ToolResult:
    matches: list[str] = []
    if file_hash and file_hash in _IOC_HASHES:
        matches.append(f"hash:{file_hash}={_IOC_HASHES[file_hash]}")
    if dest_domain and dest_domain in _IOC_DOMAINS:
        matches.append(f"domain:{dest_domain}")
    if dest_ip and dest_ip in _IOC_IPS:
        matches.append(f"ip:{dest_ip}")
    return ToolResult(
        name="ioc_match",
        data={"matches": matches, "n": len(matches)},
        weight="high" if matches else "low",
    )


# ---- File integrity diff ----------------------------------------------

# Stand-in: known-good hashes for sensitive paths.
_BASELINE_HASHES = {
    "/etc/passwd": "baseline_hash_passwd",
    "/etc/shadow": "baseline_hash_shadow",
    "/etc/sudoers": "baseline_hash_sudoers",
    "C:\\Windows\\System32\\drivers\\etc\\hosts": "baseline_hash_hosts",
}


def file_integrity_diff(path: str | None, current_hash: str | None) -> ToolResult:
    if not path or path not in _BASELINE_HASHES:
        return ToolResult(name="file_integrity", data={"path": path, "tracked": False}, weight="low")
    expected = _BASELINE_HASHES[path]
    drifted = current_hash != expected
    return ToolResult(
        name="file_integrity",
        data={"path": path, "tracked": True, "drifted": drifted, "expected": expected, "actual": current_hash},
        weight="high" if drifted else "low",
    )


# ---- DNS exfiltration / tunneling check -----------------------------

# Heuristics: long-label DNS queries, high-entropy subdomain content,
# burst frequency to a single second-level domain. Real DNS exfil
# scenarios (Iodine, dnscat2, custom) exhibit at least two of these.
def _entropy(s: str) -> float:
    from math import log2
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for c in s:
        counts[c] = counts.get(c, 0) + 1
    n = len(s)
    return -sum((c / n) * log2(c / n) for c in counts.values() if c > 0)


def dns_exfil_check(dns_queries: list[str] | None,
                    dns_query_count_5min: int | None = None) -> ToolResult:
    if not dns_queries:
        return ToolResult(name="dns_exfil", data={"verdict": "no_data"}, weight="low")
    long_label_count = 0
    high_entropy_count = 0
    domains_seen: dict[str, int] = {}
    for q in dns_queries:
        labels = q.lower().rstrip(".").split(".")
        if labels and len(labels[0]) >= 40:
            long_label_count += 1
        if labels and _entropy(labels[0]) >= 4.0:
            high_entropy_count += 1
        # Count by registered second-level + TLD
        if len(labels) >= 2:
            sld = ".".join(labels[-2:])
            domains_seen[sld] = domains_seen.get(sld, 0) + 1
    top_domain, top_count = (max(domains_seen.items(), key=lambda kv: kv[1])
                              if domains_seen else (None, 0))
    burst = bool(dns_query_count_5min and dns_query_count_5min >= 200)
    high_concentration = top_count >= 50

    severity = sum([
        long_label_count >= 5,
        high_entropy_count >= 5,
        burst,
        high_concentration,
    ])
    if severity >= 3:
        weight = "high"
    elif severity >= 1:
        weight = "medium"
    else:
        weight = "low"

    return ToolResult(name="dns_exfil", data={
        "queries_count": len(dns_queries),
        "long_label_count": long_label_count,
        "high_entropy_count": high_entropy_count,
        "top_domain": top_domain, "top_count": top_count,
        "burst": burst, "high_concentration": high_concentration,
        "exfil_likely": severity >= 2,
    }, weight=weight)


# ---- Persistence: new autostart entry ---------------------------------

# Stand-in baseline of known-good autostart entries (name, path). Production:
# seeded per golden image by the Inventory agent, refreshed on change-control.
_AUTOSTART_BASELINE = {
    ("OneDrive", "C:\\Users\\mahi\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe"),
}
_HOT_AUTOSTART_DIRS = ("\\temp", "/tmp", "public", "programdata",
                       "appdata\\local\\temp", "/users/shared")


def autostart_persistence(entries: list[dict] | None,
                          baseline: set | None = None) -> ToolResult:
    """New autostart/persistence entry not in the host baseline — Run keys, services,
    launchd, cron, systemd, login items (T1547 / T1543 / T1053)."""
    if not entries:
        return ToolResult(name="autostart_persistence", data={"verdict": "no_data"}, weight="low")
    base_raw = baseline if baseline is not None else _AUTOSTART_BASELINE
    base = {norm_autostart(n, p) for (n, p) in base_raw}
    new_entries, hot = [], False
    for e in entries:
        raw_path = e.get("path", "") or ""
        if norm_autostart(e.get("name", ""), raw_path) in base:
            continue
        is_hot = any(d in raw_path.lower() for d in _HOT_AUTOSTART_DIRS)
        hot = hot or is_hot
        new_entries.append({"name": e.get("name"), "path": e.get("path"),
                            "source": e.get("source"), "hot_path": is_hot})
    if not new_entries:
        return ToolResult(name="autostart_persistence", data={"new_entries": [], "n": 0}, weight="low")
    return ToolResult(
        name="autostart_persistence",
        data={"new_entries": new_entries, "n": len(new_entries), "hot_path": hot},
        weight="high" if hot else "medium",
    )


# ---- Webshell drop in a web root --------------------------------------

_WEBROOTS = ("/var/www/", "/inetpub/wwwroot/", "\\inetpub\\wwwroot\\",
             "/usr/share/nginx/", "/srv/www/")
_WEBSHELL_EXT = (".php", ".phtml", ".jsp", ".jspx", ".aspx", ".asp", ".cfm")
_WEBSHELL_TOKENS = {"eval", "base64_decode", "system", "shell_exec", "passthru",
                    "assert", "proc_open", "popen", "runtime.getruntime",
                    "processbuilder", "request.getparameter", "cmd.exe", "/bin/sh"}


def webshell_drop(file_path: str | None,
                  content_tokens: list[str] | None = None) -> ToolResult:
    """New server-side script written into a web root — confirms a landed webshell
    after the perimeter catches the upload/RCE attempt (T1505.003)."""
    if not file_path:
        return ToolResult(name="webshell_drop", data={"verdict": "no_data"}, weight="low")
    low = file_path.lower()
    in_webroot = any(r in low for r in _WEBROOTS)
    is_script = low.endswith(_WEBSHELL_EXT)
    if not (in_webroot and is_script):
        return ToolResult(name="webshell_drop",
                          data={"path": file_path, "in_webroot": in_webroot, "is_script": is_script},
                          weight="low")
    hit = sorted({t.lower() for t in (content_tokens or [])} & _WEBSHELL_TOKENS)
    return ToolResult(
        name="webshell_drop",
        data={"path": file_path, "in_webroot": True, "is_script": True, "webshell_tokens": hit},
        weight="high" if hit else "medium",
    )


# ---- Egress beacon periodicity ----------------------------------------

def beacon_periodicity(connect_times: list[float] | None, dest: str | None = None,
                       min_hits: int = 6, max_jitter: float = 0.25) -> ToolResult:
    """Regular-interval outbound connections to one destination — C2 beaconing
    (T1071). Stateless: callers pass the connect timestamps for one (host, dest)."""
    times = sorted(t for t in (connect_times or []) if t is not None)
    if len(times) < min_hits:
        return ToolResult(name="beacon_periodicity",
                          data={"dest": dest, "hits": len(times), "verdict": "insufficient_data"},
                          weight="low")
    gaps = [b - a for a, b in zip(times, times[1:])]
    mean = sum(gaps) / len(gaps)
    if mean <= 0:
        return ToolResult(name="beacon_periodicity", data={"dest": dest, "verdict": "degenerate"}, weight="low")
    jitter = (max(gaps) - min(gaps)) / mean
    regular = jitter <= max_jitter
    return ToolResult(
        name="beacon_periodicity",
        data={"dest": dest, "hits": len(times), "mean_interval_s": round(mean, 1),
              "jitter": round(jitter, 3), "regular": regular},
        weight="high" if regular else "low",
    )


# ---- macOS TCC sensitive grant ----------------------------------------

_TCC_SENSITIVE = {"kTCCServiceCamera", "kTCCServiceMicrophone", "kTCCServiceScreenCapture",
                  "kTCCServiceSystemPolicyAllFiles", "kTCCServiceAccessibility"}
# Production: allowlist of expected clients per service, seeded per golden image.
_TCC_ALLOWLIST = ("com.apple.", "/System/", "/Applications/zoom.us.app",
                  "/Applications/Microsoft Teams.app")


def tcc_grant(service: str | None, client: str | None, allowed: object = None,
              allowlist=None) -> ToolResult:
    """Sensitive macOS privacy grant (mic/camera/screen/full-disk/accessibility) to a
    non-allowlisted client — a surveillance/spyware tell (T1123 / T1113)."""
    if not service or service not in _TCC_SENSITIVE or not allowed:
        return ToolResult(name="tcc_grant", data={"service": service, "applicable": False}, weight="low")
    al = allowlist if allowlist is not None else _TCC_ALLOWLIST
    trusted = any((client or "").startswith(p) for p in al)
    return ToolResult(
        name="tcc_grant",
        data={"service": service, "client": client, "trusted": trusted},
        weight="low" if trusted else "high",
    )


# ---- New SSH authorized key -------------------------------------------

# Stand-in baseline of known key fingerprints. Production: per-host inventory.
_SSH_KEY_BASELINE: set = set()


def ssh_key_added(fingerprint: str | None, uid: str | None = None,
                  baseline: set | None = None) -> ToolResult:
    """SSH authorized_keys entry not in the host baseline — persistence / lateral
    access (T1098.004)."""
    if not fingerprint:
        return ToolResult(name="ssh_key_added", data={"verdict": "no_data"}, weight="low")
    base = baseline if baseline is not None else _SSH_KEY_BASELINE
    if fingerprint in base:
        return ToolResult(name="ssh_key_added", data={"fingerprint": fingerprint, "known": True}, weight="low")
    return ToolResult(
        name="ssh_key_added",
        data={"fingerprint": fingerprint, "uid": uid, "known": False},
        weight="high",
    )


def run_all_tools(alert: dict) -> list[ToolResult]:
    hc = alert.get("host_class")  # per-host-class baseline / allowlist; None -> safe default
    return [
        parent_process_tree(alert.get("parent_process"), alert.get("child_process"), alert.get("cmdline")),
        lateral_movement_check(
            alert.get("src_zone"),
            alert.get("dst_zone"),
            alert.get("dst_port"),
            alert.get("uses_smb_or_winrm", False),
        ),
        ioc_match(alert.get("file_hash"), alert.get("dest_domain"), alert.get("dest_ip")),
        file_integrity_diff(alert.get("file_path"), alert.get("file_hash_current")),
        dns_exfil_check(alert.get("dns_queries"), alert.get("dns_query_count_5min")),
        autostart_persistence(alert.get("autostart_entries"), HOST_BASELINES.autostart(hc)),
        webshell_drop(alert.get("file_path"), alert.get("file_content_tokens")),
        beacon_periodicity(alert.get("egress_connect_times"), alert.get("dest_ip")),
        tcc_grant(alert.get("tcc_service"), alert.get("tcc_client"), alert.get("tcc_allowed"),
                  HOST_BASELINES.tcc_allowlist(hc)),
        ssh_key_added(alert.get("ssh_key_fingerprint"), alert.get("ssh_key_uid"),
                      HOST_BASELINES.ssh_keys(hc)),
    ]
