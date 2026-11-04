"""WAF / virtual-patch coverage — what actually stands in front of each asset, and whether it blocks.

One vendor-neutral file (``waf_coverage.json``) describes every protection::

    {"protections": [
      {"name": "netbanking.bank.example", "vendor": "imperva", "mode": "block",      # or "monitor"
       "fronts": [{"host": "10.0.1.10", "port": 443}, {"host": "alb-netbanking"}],   # origin IPs / hostnames / LB names
       "virtual_patches": ["CVE-2021-44228"],                                        # CVE-specific blocking rules
       "ports": [8080]}                  # HTTP(S) ports proxied for a front with no port, beyond 80 / 443
    ]}

The exposure engine reads it: a protection in **block** mode in front of a web port is a WAF (``partial``);
a CVE in its ``virtual_patches`` makes that CVE ``full``-ly defended on the assets it fronts. A
protection in **monitor** mode logs and lets the attack through, so it never counts as a defence — and
the reason chain says so, because "we have a WAF" is the most common false comfort in a SOC.

Exporters (read-only API calls; same environment variables as the response connectors):

    python -m aegis.exposure.coverage --vendor edge --edge-url http://127.0.0.1:9000 --out cov.json
    python -m aegis.exposure.coverage --vendor cloudflare --zone ZONE_ID --out cov.json       # CLOUDFLARE_API_TOKEN
    python -m aegis.exposure.coverage --vendor imperva --out cov.json                         # AEGIS_WAF_API_ID / _KEY
    python -m aegis.exposure.coverage --vendor f5 --out cov.json                              # AEGIS_WAF_URL / _USER / _PASS

Vendor field names follow the public API documentation (mid-2026), like the response connectors; a real
tenant may need a field renamed. Virtual patches are recognised by a CVE id in the rule's name,
description or references — the naming convention every bank's WAF team already uses.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from ..agents.response.connectors.base import ConnectorError
from ..agents.response.connectors.http import Transport, call, httpx_transport
from ..posture.sources import PostureSourceError

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
#: what a WAF proxies for a front that names no port
DEFAULT_PROXIED_PORTS = (80, 443)


@dataclass
class Protection:
    name: str
    vendor: str
    mode: str                                   # "block" | "monitor"
    fronts: list[dict] = field(default_factory=list)   # {"host": str, "port": int | None}
    virtual_patches: list[str] = field(default_factory=list)
    #: HTTP(S) ports the WAF proxies for a front with no port, beyond 80 / 443 (an exporter or the coverage file
    #: declares them). A front with port None used to cover EVERY port of the host: Cloudflare in front of 443
    #: credited an admin console on :8080 and Elasticsearch on :9200 reached straight on the origin IP (round 8 G8-11).
    ports: list[int] = field(default_factory=list)

    def proxied_ports(self) -> set[int]:
        return set(DEFAULT_PROXIED_PORTS) | {int(p) for p in self.ports if str(p).isdigit()}

    def covers(self, keys: set[str], port: int | None, entry: int | None = None) -> bool:
        """``entry``: the port the internet actually hits when it is not ``port`` (a load balancer listener in front
        of the target port) — that is what a WAF in front of the load balancer proxies."""
        low = {k.lower() for k in keys}
        hits = {port} | ({entry} if entry is not None else set())
        for f in self.fronts:
            if str(f.get("host", "")).lower() not in low:
                continue
            fp = f.get("port")
            if port in (None, -1) or fp in hits:
                return True
            if fp is None and hits & self.proxied_ports():
                return True
        return False


def cves_in(*texts: Any) -> list[str]:
    return sorted({m.upper() for t in texts if t for m in CVE_RE.findall(str(t))})


def load_coverage(path: str | Path) -> list[Protection]:
    try:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError as e:
        raise PostureSourceError(f"WAF coverage file not found: {path}") from e
    except json.JSONDecodeError as e:
        raise PostureSourceError(f"WAF coverage file {path} is not JSON: {e}") from e
    out = []
    for i, p in enumerate(raw.get("protections") or [], 1):
        mode = str(p.get("mode", "")).lower()
        if mode not in ("block", "monitor") or not p.get("fronts"):
            raise PostureSourceError(f"protection #{i} in {path} needs mode block|monitor and at least one front")
        out.append(Protection(name=str(p.get("name", f"protection-{i}")), vendor=str(p.get("vendor", "?")), mode=mode,
                              fronts=[{"host": str(f["host"]), "port": f.get("port")} for f in p["fronts"] if f.get("host")],
                              virtual_patches=[c.upper() for c in p.get("virtual_patches") or []],
                              ports=[int(x) for x in p.get("ports") or [] if str(x).isdigit()]))
    return out


def dump(protections: list[Protection], source: str) -> str:
    return json.dumps({"source": source, "protections": [asdict(p) for p in protections]}, indent=1)


# ---- exporters ------------------------------------------------------------------------------------

def from_edge(urls: list[str], transport: Transport = httpx_transport) -> list[Protection]:
    """The BlueDefence edge shim: blocking only in live mode with the inline WAF on."""
    out = []
    for u in urls:
        h = call(transport, "GET", u.rstrip("/") + "/__edge/health", timeout=10).json()
        up = urlsplit(str(h.get("upstream", "")))
        port = up.port or (443 if up.scheme == "https" else 80)
        blocking = h.get("mode") == "live" and bool(h.get("inline_waf"))
        out.append(Protection(name=f"edge shim {h.get('asset') or u}", vendor="bluedefence-edge",
                              mode="block" if blocking else "monitor",
                              fronts=[{"host": up.hostname or "", "port": port}]))
    return out


def from_cloudflare(zones: list[str], token: str, transport: Transport = httpx_transport,
                    base: str = "https://api.cloudflare.com/client/v4") -> list[Protection]:
    """Proxied DNS records are fronted; a deployed managed ruleset = blocking WAF; custom block rules
    naming a CVE are virtual patches."""
    hdr = {"Authorization": f"Bearer {token}"}
    out = []
    for z in zones:
        recs = call(transport, "GET", f"{base}/zones/{z}/dns_records?per_page=500", headers=hdr).json().get("result") or []
        proxied = [r for r in recs if r.get("proxied") and r.get("type") in ("A", "AAAA", "CNAME")]
        if not proxied:
            continue

        def phase(name: str, z: str = z) -> list[dict]:
            res = call(transport, "GET", f"{base}/zones/{z}/rulesets/phases/{name}/entrypoint", headers=hdr, expect=(404,))
            return [] if res.status == 404 else ((res.json().get("result") or {}).get("rules") or [])  # 404: no ruleset in this phase

        managed = [r for r in phase("http_request_firewall_managed") if r.get("enabled", True) and r.get("action") == "execute"]
        # a managed ruleset deployed with a non-blocking override (``overrides.action: "log"`` — how Cloudflare runs
        # it in monitor mode — or per-rule / per-category overrides to log / skip, or disabled) only logs: it used
        # to export as blocking and every finding behind it lost its ACT NOW (round 8 G8-5)
        blocking = bool(managed) and all(_cf_blocking(r) for r in managed)
        vps = cves_in(*[f"{r.get('description', '')} {r.get('expression', '')}" for r in phase("http_request_firewall_custom")
                        if r.get("enabled", True) and r.get("action") == "block"])
        fronts = [{"host": r.get("content"), "port": None} for r in proxied] + [{"host": r.get("name"), "port": None} for r in proxied]
        out.append(Protection(name=f"cloudflare zone {z}", vendor="cloudflare", mode="block" if blocking else "monitor",
                              fronts=fronts, virtual_patches=vps))
    return out


_CF_BLOCKING_ACTIONS = {"block", "challenge", "js_challenge", "managed_challenge"}


def _cf_blocking(rule: dict) -> bool:
    """Does a managed-ruleset ``execute`` rule block? Not when its overrides set a non-blocking action or disable
    rules — at the ruleset level, per category or per rule."""
    ov = (rule.get("action_parameters") or {}).get("overrides") or {}
    if not isinstance(ov, dict):
        return True
    if ov.get("enabled") is False:
        return False
    if ov.get("action") is not None and str(ov["action"]).lower() not in _CF_BLOCKING_ACTIONS:
        return False
    for sub in list(ov.get("categories") or []) + list(ov.get("rules") or []):
        if not isinstance(sub, dict):
            continue
        if sub.get("enabled") is False:
            return False
        if sub.get("action") is not None and str(sub["action"]).lower() not in _CF_BLOCKING_ACTIONS:
            return False
    return True


def from_imperva(api_id: str, api_key: str, transport: Transport = httpx_transport,
                 base: str = "https://my.imperva.com") -> list[Protection]:
    """Imperva Cloud WAF sites: origin IPs are fronted; blocking when the core WAF rules block; custom
    rules that block and name a CVE are virtual patches."""
    hdr = {"x-API-Id": api_id, "x-API-Key": api_key}
    sites = call(transport, "POST", f"{base}/api/prov/v1/sites/list", json_body={"page_size": 100, "page_num": 0},
                 headers=hdr).json().get("sites") or []
    out = []
    for s in sites:
        rules = ((s.get("security") or {}).get("waf") or {}).get("rules") or []
        blocking = any("block" in str(r.get("action", "")).lower() for r in rules)
        custom = call(transport, "GET", f"{base}/api/prov/v2/sites/{s.get('site_id')}/rules", headers=hdr).json()
        custom = custom.get("data") or custom.get("rules") or []
        vps = cves_in(*[r.get("name") for r in custom if "BLOCK" in str(r.get("action", "")).upper() and r.get("enabled", True)])
        fronts = [{"host": ip, "port": None} for ip in s.get("ips") or []] + [{"host": s.get("domain"), "port": None}]
        out.append(Protection(name=str(s.get("domain") or s.get("site_id")), vendor="imperva",
                              mode="block" if blocking else "monitor", fronts=[f for f in fronts if f["host"]],
                              virtual_patches=vps))
    return out


def from_f5(base: str, transport: Transport = httpx_transport, *, username: str = "", password: str = "",
            token: str = "") -> list[Protection]:
    """F5 BIG-IP Advanced WAF: each ASM policy's virtual servers → pool members are fronted; blocking
    when the policy's enforcement mode is "blocking"; a user-defined signature naming a CVE is a virtual patch
    only on the blocking policies it is assigned to, enabled, out of staging and set to block."""
    hdr: dict[str, str] = {}
    if token:
        hdr["X-F5-Auth-Token"] = token
    elif username:
        import base64
        hdr["Authorization"] = "Basic " + base64.b64encode(f"{username}:{password}".encode()).decode()
    get = lambda path: call(transport, "GET", base.rstrip("/") + path, headers=hdr).json().get("items") or []
    sigs = get("/mgmt/tm/asm/signatures?$filter=isUserDefined%20eq%20true")
    # user-defined library signatures that name a CVE, by signature id and by name
    lib: dict[str, str] = {}
    for sg in sigs:
        text = f"{sg.get('name', '')} {json.dumps(sg.get('references') or sg.get('signatureReferences') or '')}"
        if cves_in(text):
            for k in (sg.get("signatureId"), sg.get("id"), sg.get("name")):
                if k not in (None, ""):
                    lib[str(k)] = text

    def policy_patches(pol: dict) -> list[str]:
        """CVEs virtually patched by THIS policy: only signatures assigned to it, enabled, out of staging and set to
        block. A library signature naming a CVE used to count on every blocking policy, staged or not (round 7 G-7)."""
        pid = pol.get("id")
        if not pid or not lib:
            return []
        try:
            rows = get(f"/mgmt/tm/asm/policies/{pid}/signatures?$expand=signatureReference"
                       "&$filter=enabled%20eq%20true%20and%20performStaging%20eq%20false")
        except ConnectorError:
            return []                                     # unreadable: no virtual-patch credit (never assume)
        texts = []
        for r in rows:
            if r.get("enabled") is False or r.get("performStaging") is True or r.get("block") is False:
                continue
            ref = r.get("signatureReference") or {}
            for k in (ref.get("signatureId"), ref.get("id"), ref.get("name")):
                if k not in (None, "") and str(k) in lib:
                    texts.append(lib[str(k)])
                    break
        return cves_in(*texts) if texts else []
    virtuals = {v.get("fullPath"): v for v in get("/mgmt/tm/ltm/virtual")}
    out = []
    for pol in get("/mgmt/tm/asm/policies"):
        blocking = str(pol.get("enforcementMode", "")).lower() == "blocking"
        fronts: list[dict] = []
        for vs_path in pol.get("virtualServers") or []:
            vs = virtuals.get(vs_path) or {}
            dest = str(vs.get("destination", "")).rsplit("/", 1)[-1]          # "/Common/203.0.113.10:443"
            if ":" in dest:
                h, _, p = dest.rpartition(":")
                fronts.append({"host": h, "port": int(p) if p.isdigit() else None})
            pool = str(vs.get("pool") or "")
            if pool:
                for m in get(f"/mgmt/tm/ltm/pool/{pool.replace('/', '~')}/members"):
                    p = str(m.get("name", "")).rsplit(":", 1)[-1]
                    fronts.append({"host": m.get("address"), "port": int(p) if p.isdigit() else None})
        if fronts:
            out.append(Protection(name=f"F5 policy {pol.get('name')}", vendor="f5", mode="block" if blocking else "monitor",
                                  fronts=[f for f in fronts if f["host"]], virtual_patches=policy_patches(pol) if blocking else []))
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m aegis.exposure.coverage", description="Export WAF / virtual-patch coverage (read-only)")
    ap.add_argument("--vendor", required=True, choices=["edge", "cloudflare", "imperva", "f5"])
    ap.add_argument("--out", required=True)
    ap.add_argument("--edge-url", action="append", default=[], help="edge shim base URL (repeatable)")
    ap.add_argument("--zone", action="append", default=[], help="Cloudflare zone id (repeatable)")
    args = ap.parse_args(argv)
    env = os.environ.get
    try:
        if args.vendor == "edge":
            prots = from_edge(args.edge_url or ["http://127.0.0.1:9000"])
        elif args.vendor == "cloudflare":
            prots = from_cloudflare(args.zone or [env("CLOUDFLARE_ZONE_ID", "")], env("CLOUDFLARE_API_TOKEN", ""))
        elif args.vendor == "imperva":
            prots = from_imperva(env("AEGIS_WAF_API_ID", ""), env("AEGIS_WAF_API_KEY", ""),
                                 base=env("AEGIS_WAF_URL", "https://my.imperva.com"))
        else:
            prots = from_f5(env("AEGIS_WAF_URL", ""), username=env("AEGIS_WAF_USER", ""), password=env("AEGIS_WAF_PASS", ""),
                            token=env("AEGIS_WAF_TOKEN", ""))
    except ConnectorError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    Path(args.out).write_text(dump(prots, args.vendor), encoding="utf-8")
    blocking = sum(p.mode == "block" for p in prots)
    print(f"wrote {args.out}: {len(prots)} protections ({blocking} blocking, {len(prots) - blocking} monitor-only), "
          f"{sum(len(p.virtual_patches) for p in prots)} virtual patches")
    return 0


if __name__ == "__main__":
    sys.exit(main())
