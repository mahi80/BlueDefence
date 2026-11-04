"""Run AEGIS itself inside an NVIDIA OpenShell sandbox — the egress allowlist, generated from its own config
(integration plan #8b).

The swarm's specialists read attacker-written text all day. Prompt-injection defences catch most of it, but the
backstop is the network: a specialist that was talked into "send this to evil.example" must have nowhere to send
it. OpenShell (github.com/NVIDIA/OpenShell) runs a process in a sandbox whose outbound traffic is default-deny and
whose credentials are injected only into requests the policy admits. This module writes that policy for *this*
AEGIS deployment: the hosts it can see the configuration talking to (model API, vendor connectors, ticketing, intel
feeds, Kafka, the ACP dashboard, the licence service) and nothing else. It fails closed: an integration it does not
recognise is blocked inside the sandbox until it is added with ``--extra host:port``.

    python -m aegis.ops.openshell_policy                 # print the policy for the current environment
    python -m aegis.ops.openshell_policy --out aegis-sandbox.yaml
    openshell sandbox create --name aegis --policy aegis-sandbox.yaml -- python -m aegis.service

Only host names and ports are read from the environment — never a token, key or password — so the file is safe to
review and commit. Hosts come from ``AEGIS_*_URL`` / ``ACP_*_URL``, ``AEGIS_KAFKA_BOOTSTRAP``,
``AEGIS_LICENSE_SERVER``, ``SPLUNK_URL``, ``MISP_URL``, ``TENABLE_URL``, ``RF_BASE_URL``, ``SENTINEL_API_BASE``,
and each configured vendor's public API host when its URL is implied (CrowdStrike, Defender, Entra, Cloudflare,
Tenable, Recorded Future …); Entra-authenticated vendors keep ``login.microsoftonline.com`` even with an explicit
URL. Writable paths are resolved to absolute directories (audit log and its siblings, HITL queue, ACP_HOME, the
threat-intel cache). ``--python`` names the interpreter inside the sandbox (default ``/usr/bin/python3``). Review
the list before use. OpenShell is alpha; the policy follows its documented example format.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from urllib.parse import urlsplit

_DEFAULT_PORTS = {"https": 443, "http": 80, "ldaps": 636, "postgresql": 5432, "postgres": 5432, "mssql": 1433,
                  "kafka": 9093}
_LOGIN = ("login.microsoftonline.com", 443)
#: (env var, value or "*") → hosts its vendor talks to when no explicit URL is configured
_VENDOR_HOSTS: dict[tuple[str, str], list[tuple[str, int]]] = {   # group name = <vendor value> (or _NAMES below)
    ("AEGIS_EDR_VENDOR", "crowdstrike"): [("api.crowdstrike.com", 443)],
    ("AEGIS_EDR_VENDOR", "falcon"): [("api.crowdstrike.com", 443)],
    ("AEGIS_EDR_VENDOR", "defender"): [("api.securitycenter.microsoft.com", 443), _LOGIN],
    ("AEGIS_EDR_VENDOR", "mde"): [("api.securitycenter.microsoft.com", 443), _LOGIN],
    ("AEGIS_IDP_VENDOR", "entra"): [("graph.microsoft.com", 443), _LOGIN],
    ("AEGIS_WAF_VENDOR", "cloudflare"): [("api.cloudflare.com", 443)],
    ("AEGIS_WAF_VENDOR", "imperva"): [("my.imperva.com", 443), ("api.imperva.com", 443)],
    ("AEGIS_WAF_VENDOR", "azure"): [("management.azure.com", 443), _LOGIN],
    ("AEGIS_SOAR_VENDOR", "sentinel"): [("management.azure.com", 443), _LOGIN],
    ("AEGIS_SOURCES", "sentinel"): [("api.loganalytics.io", 443), _LOGIN],
    ("AEGIS_CVE_INTEL", "*"): [("services.nvd.nist.gov", 443), ("api.first.org", 443), ("www.cisa.gov", 443)],
    ("AEGIS_SLACK_WEBHOOK", "*"): [("hooks.slack.com", 443)],
    ("ANTHROPIC_API_KEY", "*"): [("api.anthropic.com", 443)],
}
_NAMES = {"AEGIS_CVE_INTEL": "threat_intel", "AEGIS_SLACK_WEBHOOK": "slack", "ANTHROPIC_API_KEY": "anthropic",
          "AEGIS_SOURCES": "sentinel_logs", "TENABLE_ACCESS_KEY": "tenable", "RF_API_TOKEN": "recorded_future"}
# vendors that authenticate through Entra: the login host stays allowed even when an explicit API URL is set
# (a regional Defender / Sentinel URL used to drop login.microsoftonline.com — review round 6 P-1)
_MS_LOGIN_VENDORS = {("AEGIS_EDR_VENDOR", "defender"), ("AEGIS_EDR_VENDOR", "mde"), ("AEGIS_IDP_VENDOR", "entra"),
                     ("AEGIS_WAF_VENDOR", "azure"), ("AEGIS_SOAR_VENDOR", "sentinel")}
#: URL variables outside the AEGIS_* / ACP_* *_URL pattern, with the default the code uses when the feature is on
_OTHER_URLS: dict[str, tuple[str, str | None]] = {
    # var: (group, default used when the feature's credential is set but the URL is not)
    "AEGIS_LICENSE_SERVER": ("licence", None),
    "SPLUNK_URL": ("splunk", None),
    "MISP_URL": ("misp", None),
    "TENABLE_URL": ("tenable", None),
    "RF_BASE_URL": ("recorded_future", None),
    "SENTINEL_API_BASE": ("sentinel_logs", None),
}
_VENDOR_HOSTS[("TENABLE_ACCESS_KEY", "*")] = [("cloud.tenable.com", 443)]
_VENDOR_HOSTS[("RF_API_TOKEN", "*")] = [("api.recordedfuture.com", 443)]
_OFF = {"", "0", "off", "false", "none", "no"}
_SKIP_URL_VARS = {"AEGIS_INDEX_URL"}          # a local DuckDB / SQLite file unless it names a server (handled below)


def _ok_host(host: str) -> bool:
    """A real network host: dotted name, IP literal or localhost — never a bare word (a userinfo fragment that
    urlsplit mistook for a host when a token contained '/' — round 6 P-3)."""
    import ipaddress
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return host == "localhost" or ("." in host and all(part for part in host.split(".")))


def _host_port(url: str) -> tuple[str, int] | None:
    u = urlsplit(url.strip())
    scheme = u.scheme.split("+", 1)[0].lower()
    if not u.hostname or scheme in ("file", "duckdb", "sqlite"):
        return None
    if "@" not in u.netloc and "@" in (u.path + "?" + u.query):
        return None               # userinfo with an unencoded '/': the 'host' would be part of a secret (P-3)
    try:
        port = u.port
    except ValueError:
        return None
    host = u.hostname.lower()
    if not _ok_host(host):
        return None
    return host, port or _DEFAULT_PORTS.get(scheme, 443)


def _bootstrap(part: str) -> tuple[str, int] | None:
    """One Kafka bootstrap entry: ``host:port``, ``[v6]:port`` or ``SASL_SSL://host:port`` (round 6 P-1)."""
    p = part.strip()
    if "://" in p:
        p = p.split("://", 1)[1]
    host, _, port = p.rpartition(":")
    host = host.strip().strip("[]").lower()
    if not host or not port.isdigit() or not _ok_host(host):
        return None
    return host, int(port)


def collect(env: dict[str, str] | None = None) -> dict[str, list[tuple[str, int]]]:
    """Integration name → (host, port) list, from the configuration only (never a secret value)."""
    e = os.environ if env is None else env
    out: dict[str, list[tuple[str, int]]] = {}

    def add(name: str, hp: tuple[str, int] | None) -> None:
        if hp and hp not in out.setdefault(name, []):
            out[name].append(hp)

    for var, val in sorted(e.items()):
        if not (var.startswith(("AEGIS_", "ACP_")) and var.endswith("_URL")) or not val.strip():
            continue
        if var in _SKIP_URL_VARS and "://" in val and val.split("://", 1)[0].split("+", 1)[0] in ("duckdb", "sqlite"):
            continue
        add(var.removeprefix("AEGIS_").removeprefix("ACP_").removesuffix("_URL").lower(), _host_port(val))
    if e.get("ACP_DASHBOARD_URL"):
        add("acp_dashboard", _host_port(e["ACP_DASHBOARD_URL"]))
    for part in (e.get("AEGIS_KAFKA_BOOTSTRAP") or "").split(","):
        add("kafka", _bootstrap(part))
    for var, (group, _default) in _OTHER_URLS.items():
        if (e.get(var) or "").strip():
            add(group, _host_port(e[var]))
    sources = {s.strip().lower() for s in (e.get("AEGIS_SOURCES") or "").split(",")}
    for (var, val), hosts in _VENDOR_HOSTS.items():
        v = (e.get(var) or "").strip().lower()
        if var == "AEGIS_SOURCES":
            hit = val in sources
        else:
            hit = (val == "*" and v not in _OFF) or (val != "*" and v == val)
        explicit_url = val != "*" and var.endswith("_VENDOR") and e.get(var.replace("_VENDOR", "_URL"))
        if var == "TENABLE_ACCESS_KEY" and e.get("TENABLE_URL"):
            explicit_url = True
        if var == "RF_API_TOKEN" and e.get("RF_BASE_URL"):
            explicit_url = True
        if hit and not explicit_url:
            for hp in hosts:
                add(_NAMES.get(var) or val, hp)
        elif hit and (var, val) in _MS_LOGIN_VENDORS:
            add(val, _LOGIN)
    return out


def _state_dirs(e: dict[str, str]) -> set[str]:
    """Directories the service writes, as absolute paths (round 6 P-2): the audit log and what lives beside it
    (receipts, deferred actions — their defaults are the audit file's directory), the HITL queue, ACP_HOME, the
    threat-intel cache, and any explicit receipts / deferred paths."""
    pkg = Path(__file__).resolve().parents[1]                 # the service's default: <aegis package>/_audit_log.jsonl
    audit = (e.get("AEGIS_AUDIT_PATH") or "").strip() or str(pkg / "_audit_log.jsonl")
    dirs = {Path(audit).parent}
    for var in ("AEGIS_RECEIPTS_PATH", "AEGIS_DEFERRED_PATH", "AEGIS_AUDIT_ANCHOR", "AEGIS_STREAM_JOURNAL",
                "AEGIS_DEAD_LETTER", "AEGIS_CHECKPOINT"):
        if (e.get(var) or "").strip():
            dirs.add(Path(e[var]).parent)
    for var in ("AEGIS_HITL_DIR", "ACP_HOME"):
        if (e.get(var) or "").strip():
            dirs.add(Path(e[var]))
    dirs.add(Path((e.get("AEGIS_TI_CACHE") or "").strip() or Path(e.get("HOME") or Path.home()) / ".cache" / "aegis-threat-intel"))
    return {str(d.expanduser().resolve()) for d in dirs}


def build_policy(env: dict[str, str] | None = None, *, extra: list[str] = (), workdir: str = "/app",
                 state_dirs: list[str] = (), python: str = "/usr/bin/python3") -> dict:
    e = os.environ if env is None else env
    groups = collect(e)
    for item in extra:                               # --extra is the operator's own word: dotless hosts allowed
        host, _, port = item.strip().rpartition(":")
        host = host.strip("[]").lower()
        if host and port.isdigit():
            groups.setdefault("extra", []).append((host, int(port)))
    rw = sorted(_state_dirs(e) | {str(Path(d).expanduser().resolve()) for d in state_dirs})
    binary = python
    policies = {}
    for name, hosts in sorted(groups.items()):
        key = "".join(c if c.isalnum() else "_" for c in name)[:60] or "integration"
        # HTTP APIs get OpenShell's L7 (rest) enforcement; Kafka / LDAPS / databases are plain TCP endpoints
        eps = [{"host": h, "port": p, **({"protocol": "rest"} if p in (80, 443, 8443) and key != "kafka" else {}),
                "enforcement": "enforce"} for h, p in hosts]
        policies[key] = {"name": key, "endpoints": eps,
                         "binaries": [{"path": binary}]}
    return {"version": 1,
            "filesystem_policy": {"include_workdir": True, "read_only": sorted({"/usr", "/lib", "/etc", workdir}),
                                  "read_write": rw},
            "landlock": {"compatibility": "best_effort"},
            "network_policies": policies}


def main(argv: list[str] | None = None) -> int:
    import yaml
    ap = argparse.ArgumentParser(prog="python -m aegis.ops.openshell_policy",
                                 description="OpenShell sandbox policy (egress allowlist) for this AEGIS configuration")
    ap.add_argument("--out", help="write here instead of stdout")
    ap.add_argument("--extra", action="append", default=[], help="host:port to allow as well (repeatable)")
    ap.add_argument("--workdir", default="/app")
    ap.add_argument("--state-dir", action="append", default=[], help="writable directory (repeatable)")
    ap.add_argument("--python", default="/usr/bin/python3",
                    help="the interpreter INSIDE the sandbox that runs AEGIS (default /usr/bin/python3)")
    a = ap.parse_args(argv)
    pol = build_policy(extra=a.extra, workdir=a.workdir, state_dirs=a.state_dir, python=a.python)
    hosts = sorted({f"{ep['host']}:{ep['port']}" for p in pol["network_policies"].values() for ep in p["endpoints"]})
    header = ("# OpenShell policy for AEGIS — generated by `python -m aegis.ops.openshell_policy`.\n"
              f"# {len(hosts)} allowed destination(s): {', '.join(hosts) or 'none'}\n"
              "# Everything else is denied. Review before use; add a missing integration with --extra host:port.\n")
    text = header + yaml.safe_dump(pol, sort_keys=False)
    if a.out:
        Path(a.out).write_text(text, encoding="utf-8")
        print(f"wrote {a.out}: {len(hosts)} destination(s)", file=sys.stderr)
    else:
        sys.stdout.write(text)
    if not hosts:
        print("warning: no outbound integrations found in the environment — the sandbox would allow nothing out",
              file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())


__all__ = ["build_policy", "collect", "main"]
