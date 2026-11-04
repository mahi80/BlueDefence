"""Tools for the EDR/Host specialist."""
from __future__ import annotations

import ipaddress
import itertools
import re
from dataclasses import dataclass

from ..shared.tool_guard import isolated
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
    # lsass dumping through comsvcs.dll is a rundll32 COMMAND LINE, not a child process: it is a cmdline
    # pattern below (the parent→child rule here could never fire; review round 3 G7-8)
}


def _base(p: str) -> str:
    """``C:\\Program Files\\Microsoft Office\\WINWORD.EXE`` → ``winword.exe``: telemetry carries full paths."""
    return str(p or "").replace("\\", "/").rsplit("/", 1)[-1].strip().strip('"').lower()

_SUSPICIOUS_CMDLINE_PATTERNS = [
    # base64 PowerShell: PowerShell takes any prefix of -EncodedCommand (-e, -ec, -en, -enco …) and / for -
    r"(?:^|\s)[-/\u2013]e(?:c|n[a-z]{0,12})?\s+[A-Za-z0-9+/=]{40,}",
    r"DownloadString\(",                                 # PS download
    r"\b(?:iex|invoke-expression)\b",                     # PS in-memory exec: `| iex`, `iex $x`, IEX(…)
    r"\bnc\b.{0,200}?-e\s+/?bin/sh",                     # netcat reverse shell (bounded: no quadratic scan)
    r"bash\s+-i\s+>&\s+/dev/tcp/",                       # bash reverse shell
    r"mimikatz",
    r"procdump.{0,200}?lsass",
    r"comsvcs(?:\.dll)?[\s,]+#?(?:minidump|24)\b",        # rundll32 comsvcs.dll MiniDump <lsass pid>
    r"vssadmin\s+delete\s+shadows",                      # ransomware indicator
]
_CMDLINE_RX = re.compile("|".join(_SUSPICIOUS_CMDLINE_PATTERNS), re.IGNORECASE)


# Suspicious spawns by the parent's ROLE (review round 5): a server or document process that starts a shell or a
# living-off-the-land binary. The table above matched a few exact names by substring (`sh` in `ssh-agent`), and
# `w3wp.exe → /bin/sh`, `sqlservr.exe → cmd.exe`, `httpd → sh`, `postgres → sh` (COPY … FROM PROGRAM) and
# `java → bash` (Log4Shell) all scored low — and since the EDR pre-filter (round 4 S4-8) a low row never reaches
# the model, so a web shell was dropped outright.
_SERVER_PARENTS = frozenset({
    "w3wp", "httpd", "apache", "apache2", "nginx", "lighttpd", "php-fpm", "php-cgi", "php", "tomcat", "tomcat8",
    "tomcat9", "tomcat10", "jboss", "weblogic", "websphere", "iisexpress", "caddy", "haproxy", "envoy",
    "sqlservr", "mysqld", "mariadbd", "postgres", "postmaster", "oracle", "mongod", "redis-server", "exchange",
    "umworkerprocess", "msexchangeowaapppool", "ews"})
_DOCUMENT_PARENTS = frozenset({
    "winword", "excel", "powerpnt", "outlook", "onenote", "msaccess", "mspub", "visio", "acrord32", "acrobat",
    "foxitreader", "foxitpdfreader", "hwp", "wps", "et", "wpp"})
# runtimes that host web apps (Log4Shell, Spring4Shell, prototype-pollution RCE) but also run build tooling: medium
_RUNTIME_PARENTS = frozenset({"java", "javaw", "node", "dotnet"})
_SHELL_CHILDREN = frozenset({
    "cmd", "powershell", "pwsh", "wscript", "cscript", "mshta", "rundll32", "regsvr32", "certutil", "bitsadmin",
    "msbuild", "installutil", "regasm", "regsvcs", "wmic", "schtasks", "net", "net1", "whoami", "nltest",
    "sh", "bash", "dash", "zsh", "ksh", "ash", "busybox", "nc", "ncat", "netcat", "socat", "curl", "wget",
    "python", "python2", "python3", "perl", "ruby", "lua", "telnet", "id", "uname"})


def _stem(name: str) -> str:
    n = _base(name)
    for ext in (".exe", ".com", ".bat", ".cmd", ".bin"):
        if n.endswith(ext):
            n = n[: -len(ext)]
            break
    # python3.11 / perl5.36 / tomcat9w → python3 / perl / tomcat9
    return re.sub(r"(?<=[a-z])(\d+(?:\.\d+)+)$", "", n)


def suspicious_spawn(parent: str, child: str) -> str:
    """'high' (server / document process → shell or LOLBin), 'medium' (an app runtime → shell), or ''."""
    p, c = _stem(parent), _stem(child)
    if not p or not c or c not in _SHELL_CHILDREN:
        return ""
    if p in _SERVER_PARENTS or p in _DOCUMENT_PARENTS:
        return "high"
    if p in _RUNTIME_PARENTS:
        return "medium"
    return ""


def parent_process_tree(parent: str | None, child: str | None, cmdline: str | None) -> ToolResult:
    parent_l = _base(parent or "")
    child_l = _base(child or "")
    cmdline_v = cmdline or ""
    suspicious_parent_child = False
    if parent_l in _SUSPICIOUS_PROCESS_PARENTS:
        if any(c == child_l or c == _stem(child_l) for c in _SUSPICIOUS_PROCESS_PARENTS[parent_l]):
            suspicious_parent_child = True
    spawn = suspicious_spawn(parent_l, child_l)
    if spawn == "high":
        suspicious_parent_child = True
    cmdline_match = bool(_CMDLINE_RX.search(cmdline_v))
    weight = "high" if (suspicious_parent_child or cmdline_match) else "medium" if spawn == "medium" else "low"
    return ToolResult(
        name="parent_process_tree",
        data={
            "parent": parent,
            "child": child,
            "suspicious_pair": suspicious_parent_child,
            "spawn_role": spawn or None,
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
_IOC_SHA256: dict[str, str] = {}
_IOC_SHA1: dict[str, str] = {}
_IOC_DOMAINS = {"evil.example.com", "c2.attacker.test"}
_IOC_IPS = {"203.0.113.66", "198.51.100.99",
            # HF/ModelScope model-loader cryptominer campaign (AEGIS-TI-2026-HF-LOADER):
            # reverse shell, exfil, and wave-1 C2 — catches post-exploitation of a slipped model load.
            "212.32.253.3", "2.28.9.199", "8.137.187.63"}


def _canon_ip(v: str) -> str:
    """``::ffff:203.0.113.66`` / ``[2001:db8::1]`` / ``203.0.113.66:443`` → one spelling."""
    t = str(v or "").strip().strip("[]")
    try:
        ip = ipaddress.ip_address(t)
    except ValueError:
        host, _, port = t.rpartition(":")
        if port.isdigit() and host.count(":") == 0:
            try:
                ip = ipaddress.ip_address(host)
            except ValueError:
                return t
        else:
            return t
    if ip.version == 6 and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return str(ip)


def _hash_hit(fh: str) -> tuple[str, str] | None:
    """md5 / sha1 / sha256 — every length the feeds distribute (only md5 used to reach the EDR, round 7 D-12)."""
    for table in (_IOC_HASHES, _IOC_SHA256, _IOC_SHA1):
        if fh in table:
            return fh, table[fh]
    return None


def ioc_match(file_hash: str | None, dest_domain: str | None, dest_ip: str | None,
              *, hashes: dict | None = None) -> ToolResult:
    matches: list[str] = []
    # case-insensitive: Sysmon writes hashes upper-case, DNS names arrive with any case and a trailing dot
    cands = [str(file_hash or "").strip().lower()]
    if isinstance(hashes, dict):                         # Sysmon Hashes / OCSF: every algorithm the event carries
        cands += [str(v).strip().lower() for v in hashes.values() if v]
    for fh in dict.fromkeys(c for c in cands if c):
        hit = _hash_hit(fh)
        if hit:
            matches.append(f"hash:{hit[0]}={hit[1]}")
    dom = str(dest_domain or "").strip().lower().rstrip(".")
    if dom:
        # suffix match on whole labels: `x7f3a.c2.attacker.test` is the IOC `c2.attacker.test` (D-12)
        labels = dom.split(".")
        for i in range(len(labels) - 1):
            parent = ".".join(labels[i:])
            if parent in _IOC_DOMAINS:
                matches.append(f"domain:{dom}" + (f" (under {parent})" if parent != dom else ""))
                break
    ip = _canon_ip(dest_ip) if dest_ip else ""
    if ip and ip in {_canon_ip(x) for x in _IOC_IPS}:
        matches.append(f"ip:{ip}")
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


#: two-label public suffixes (a small, sector-relevant slice of the PSL — production: the full list)
_TWO_LABEL_SUFFIXES = frozenset({
    "co.in", "net.in", "org.in", "gov.in", "nic.in", "ac.in", "edu.in", "res.in", "firm.in", "gen.in", "ind.in",
    "mil.in", "bank.in", "fin.in", "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "com.sg",
    "co.jp", "ne.jp", "com.br", "com.cn", "com.hk", "co.za", "co.nz", "com.my", "co.id", "com.ae",
    "s3.amazonaws.com", "cloudfront.net", "azurewebsites.net", "blob.core.windows.net", "appspot.com",
    "herokuapp.com", "github.io", "workers.dev", "pages.dev", "vercel.app", "netlify.app", "ngrok.io",
    "duckdns.org", "no-ip.com", "trycloudflare.com",
})


def _registrable(labels: list[str]) -> str:
    labels = [x for x in labels if x]
    for n in (3, 2):
        if len(labels) > n and ".".join(labels[-n:]) in _TWO_LABEL_SUFFIXES:
            return ".".join(labels[-(n + 1):])
    if len(labels) >= 2 and ".".join(labels[-2:]) in _TWO_LABEL_SUFFIXES:
        return ".".join(labels[-2:])
    return ".".join(labels[-2:]) if len(labels) >= 2 else ""


def dns_exfil_check(dns_queries: list[str] | None,
                    dns_query_count_5min: int | None = None) -> ToolResult:
    if not dns_queries:
        return ToolResult(name="dns_exfil", data={"verdict": "no_data"}, weight="low")
    long_label_count = 0
    high_entropy_count = 0
    domains_seen: dict[str, set[str]] = {}
    for q in dns_queries:
        labels = q.lower().rstrip(".").split(".")
        if labels and len(labels[0]) >= 40:
            long_label_count += 1
        if labels and _entropy(labels[0]) >= 4.0:
            high_entropy_count += 1
        # Count by registrable domain: "co.in" is a suffix, so 60 lookups across seven banks under it were one
        # "concentrated" domain (round 7 D-15). Repeats of one name are a cache miss, not a tunnel: concentration
        # counts the distinct names under the domain.
        reg = _registrable(labels)
        if reg:
            domains_seen.setdefault(reg, set()).add(".".join(labels))
    top_domain, top_names = (max(domains_seen.items(), key=lambda kv: len(kv[1]))
                             if domains_seen else (None, set()))
    top_count = len(top_names)
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
    if _internal_dest(dest):
        # a 60 s poll to the bank's own server is a health check, not C2 (round 4 S4-8)
        return ToolResult(name="beacon_periodicity", data={"dest": dest, "hits": len(times), "verdict": "internal"},
                          weight="low")
    gaps = sorted(b - a for a, b in itertools.pairwise(times))
    mean = sum(gaps) / len(gaps)
    med = gaps[len(gaps) // 2]
    if mean <= 0 or med <= 0:
        return ToolResult(name="beacon_periodicity", data={"dest": dest, "verdict": "degenerate"}, weight="low")
    # median absolute deviation over the median gap: robust to one long sleep, and a 30% uniform jitter (Cobalt
    # Strike's default) stays near 0.15 — max-min / mean read it as irregular (round 4 S4-8)
    dev = sorted(abs(g - med) for g in gaps)
    jitter = dev[len(dev) // 2] / med
    regular = jitter <= max_jitter
    return ToolResult(
        name="beacon_periodicity",
        data={"dest": dest, "hits": len(times), "mean_interval_s": round(mean, 1), "median_interval_s": round(med, 1),
              "jitter": round(jitter, 3), "regular": regular},
        weight="high" if regular else "low",
    )


def _internal_dest(dest: str | None) -> bool:
    import ipaddress
    try:
        ip = ipaddress.ip_address(str(dest or "").strip())
    except ValueError:
        return False
    # RFC 1918 / CGNAT / ULA / loopback / link-local only (is_private also covers the documentation ranges)
    return ip.is_loopback or ip.is_link_local or any(ip in ipaddress.ip_network(n) for n in _INTERNAL_NETS
                                                     if ipaddress.ip_network(n).version == ip.version)


_INTERNAL_NETS = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "fc00::/7")


# ---- macOS TCC sensitive grant ----------------------------------------

_TCC_SENSITIVE = {"kTCCServiceCamera", "kTCCServiceMicrophone", "kTCCServiceScreenCapture",
                  "kTCCServiceSystemPolicyAllFiles", "kTCCServiceAccessibility"}
# Production: allowlist of expected clients per service, seeded per golden image.
_TCC_ALLOWLIST = ("com.apple.", "/System/", "/Applications/zoom.us.app",
                  "/Applications/Microsoft Teams.app")


# code-signing authority that vouches for a bundle-id namespace (osquery's signature table / the TCC csreq)
_NAMESPACE_SIGNERS = {"com.apple.": ("apple", "software signing", "apple inc.", "apple code signing certification authority")}


def tcc_grant(service: str | None, client: str | None, allowed: object = None,
              allowlist=None, authority: str | None = None) -> ToolResult:
    """Sensitive macOS privacy grant (mic/camera/screen/full-disk/accessibility) to a
    non-allowlisted client — a surveillance/spyware tell (T1123 / T1113)."""
    if not service or service not in _TCC_SENSITIVE or not allowed:
        return ToolResult(name="tcc_grant", data={"service": service, "applicable": False}, weight="low")
    al = allowlist if allowlist is not None else _TCC_ALLOWLIST
    c = str(client or "").strip()
    trusted = False
    namespace_only = False
    for entry in al:
        e = str(entry)
        if e.startswith("/"):
            # a path: the bundle itself or something inside it — `/Applications/zoom.us.app.evil/…` used to pass
            # a raw prefix check (review round 7 D-12)
            root = e.rstrip("/")
            if c == root or c.startswith(root + "/"):
                trusted = True
        elif e.endswith("."):
            # a bundle-id namespace (`com.apple.`): anyone can declare `com.apple.evil-updater`, so without a
            # code-signing authority it is only "unverified", never trusted
            if c.startswith(e):
                if authority and str(authority).strip().lower() in _NAMESPACE_SIGNERS.get(e, ()):
                    trusted = True
                else:
                    namespace_only = True
        elif c == e:
            trusted = True                               # an exact bundle id
    weight = "low" if trusted else ("medium" if namespace_only else "high")
    return ToolResult(
        name="tcc_grant",
        data={"service": service, "client": client, "trusted": trusted,
              "unverified_namespace": namespace_only and not trusted},
        weight=weight,
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
        isolated(lambda: parent_process_tree(alert.get("parent_process"), alert.get("child_process"), alert.get("cmdline")), "parent_process_tree", ToolResult),
        isolated(lambda: lateral_movement_check(
            alert.get("src_zone"),
            alert.get("dst_zone"),
            alert.get("dst_port"),
            alert.get("uses_smb_or_winrm", False),
        ), "lateral_movement_check", ToolResult),
        isolated(lambda: ioc_match(alert.get("file_hash"), alert.get("dest_domain"), alert.get("dest_ip"),
                                   hashes=alert.get("file_hashes") if isinstance(alert.get("file_hashes"), dict) else None),
                 "ioc_match", ToolResult),
        isolated(lambda: file_integrity_diff(alert.get("file_path"), alert.get("file_hash_current")), "file_integrity_diff", ToolResult),
        isolated(lambda: dns_exfil_check(alert.get("dns_queries"), alert.get("dns_query_count_5min")), "dns_exfil_check", ToolResult),
        isolated(lambda: autostart_persistence(alert.get("autostart_entries"), HOST_BASELINES.autostart(hc)), "autostart_persistence", ToolResult),
        isolated(lambda: webshell_drop(alert.get("file_path"), alert.get("file_content_tokens")), "webshell_drop", ToolResult),
        isolated(lambda: beacon_periodicity(alert.get("egress_connect_times"), alert.get("dest_ip")), "beacon_periodicity", ToolResult),
        isolated(lambda: tcc_grant(alert.get("tcc_service"), alert.get("tcc_client"), alert.get("tcc_allowed"),
                  HOST_BASELINES.tcc_allowlist(hc), authority=alert.get("tcc_authority")), "tcc_grant", ToolResult),
        isolated(lambda: ssh_key_added(alert.get("ssh_key_fingerprint"), alert.get("ssh_key_uid"),
                      HOST_BASELINES.ssh_keys(hc)), "ssh_key_added", ToolResult),
    ]
