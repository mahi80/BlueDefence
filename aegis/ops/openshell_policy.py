"""Run AEGIS itself inside an NVIDIA OpenShell sandbox — the egress allowlist, generated from its own config
(integration plan #8b).

The swarm's specialists read attacker-written text all day. Prompt-injection defences catch most of it, but the
backstop is the network: a specialist that was talked into "send this to evil.example" must have nowhere to send
it. OpenShell (github.com/NVIDIA/OpenShell) runs a process in a sandbox whose outbound traffic is default-deny and
whose credentials are injected only into requests the policy admits. This module writes that policy for *this*
AEGIS deployment: every host the configuration actually talks to (model API, vendor connectors, ticketing, intel
feeds, Kafka, the ACP dashboard) and nothing else.

    python -m aegis.ops.openshell_policy                 # print the policy for the current environment
    python -m aegis.ops.openshell_policy --out aegis-sandbox.yaml
    openshell sandbox create --name aegis --policy aegis-sandbox.yaml -- python -m aegis.service

Only host names and ports are read from the environment — never a token, key or password — so the file is safe to
review and commit. Hosts come from ``*_URL`` variables, ``AEGIS_KAFKA_BOOTSTRAP``, and each configured vendor's
public API host when its URL is implied (CrowdStrike, Defender, Entra, Cloudflare …). Review the list before use:
an integration configured in a way this module does not know about will be blocked until it is added (``--extra
host:port``). OpenShell is alpha; the policy follows its documented example format.
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
          "AEGIS_SOURCES": "sentinel_logs"}
_OFF = {"", "0", "off", "false", "none", "no"}
_SKIP_URL_VARS = {"AEGIS_INDEX_URL"}          # a local DuckDB / SQLite file unless it names a server (handled below)


def _host_port(url: str) -> tuple[str, int] | None:
    u = urlsplit(url.strip())
    scheme = u.scheme.split("+", 1)[0].lower()
    if not u.hostname or scheme in ("file", "duckdb", "sqlite"):
        return None
    try:
        port = u.port
    except ValueError:
        return None
    return u.hostname.lower(), port or _DEFAULT_PORTS.get(scheme, 443)


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
        host, _, port = part.strip().rpartition(":")
        if host and port.isdigit():
            add("kafka", (host.lower(), int(port)))
    sources = {s.strip().lower() for s in (e.get("AEGIS_SOURCES") or "").split(",")}
    for (var, val), hosts in _VENDOR_HOSTS.items():
        v = (e.get(var) or "").strip().lower()
        if var == "AEGIS_SOURCES":
            hit = val in sources
        else:
            hit = (val == "*" and v not in _OFF) or (val != "*" and v == val)
        explicit_url = val != "*" and var.endswith("_VENDOR") and e.get(var.replace("_VENDOR", "_URL"))
        if hit and not explicit_url:
            for hp in hosts:
                add(_NAMES.get(var) or val, hp)
    return out


def build_policy(env: dict[str, str] | None = None, *, extra: list[str] = (), workdir: str = "/app",
                 state_dirs: list[str] = (), python: str = "") -> dict:
    e = os.environ if env is None else env
    groups = collect(e)
    for item in extra:
        host, _, port = item.rpartition(":")
        if host and port.isdigit():
            groups.setdefault("extra", []).append((host.lower(), int(port)))
    rw = sorted({*state_dirs, *(p for p in (e.get("AEGIS_HITL_DIR"), e.get("ACP_HOME"),
                                            str(Path(e["AEGIS_AUDIT_PATH"]).parent) if e.get("AEGIS_AUDIT_PATH") else "")
                                if p)} or {"/sandbox"})
    binary = python or sys.executable
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
    a = ap.parse_args(argv)
    pol = build_policy(extra=a.extra, workdir=a.workdir, state_dirs=a.state_dir)
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
