"""Public suffixes and shared-hosting bases, multi-label (review round 8 D8-6 / D8-16).

A sector-relevant slice of the Public Suffix List (ICANN country second levels plus the PSL "private" section for the
clouds, CDNs and free-hosting platforms a bank's own traffic and an attacker's infrastructure both ride on). Under
each of these, every label to the left is a different customer: ``acct1.blob.core.windows.net`` and
``acct2.blob.core.windows.net`` are two registrable names, not one ``windows.net``.

Production: load the full PSL (``publicsuffix2`` / ``tldextract`` with a pinned snapshot); this list is the fallback
that keeps the matchers honest without a network fetch.
"""
from __future__ import annotations

import re

SUFFIXES: frozenset[str] = frozenset({
    # ICANN second levels the bank sees most
    "co.in", "net.in", "org.in", "gov.in", "nic.in", "ac.in", "edu.in", "res.in", "firm.in", "gen.in", "ind.in",
    "mil.in", "bank.in", "fin.in", "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "com.sg",
    "co.jp", "ne.jp", "com.br", "com.cn", "com.hk", "co.za", "co.nz", "com.my", "co.id", "com.ae",
    # AWS
    "s3.amazonaws.com", "s3-website.amazonaws.com", "cloudfront.net", "elasticbeanstalk.com",
    "execute-api.amazonaws.com", "lambda-url.amazonaws.com", "amplifyapp.com", "awsapprunner.com",
    "compute.amazonaws.com", "elb.amazonaws.com",
    # Azure
    "blob.core.windows.net", "web.core.windows.net", "file.core.windows.net", "queue.core.windows.net",
    "table.core.windows.net", "dfs.core.windows.net", "servicebus.windows.net", "database.windows.net",
    "vault.azure.net", "azurewebsites.net", "scm.azurewebsites.net", "cloudapp.net", "cloudapp.azure.com",
    "azureedge.net", "azurefd.net", "trafficmanager.net", "azure-api.net", "azurecr.io", "azurestaticapps.net",
    "sharepoint.com", "onmicrosoft.com",
    # Google
    "appspot.com", "r.appspot.com", "firebaseapp.com", "web.app", "run.app", "cloudfunctions.net",
    "firebaseio.com", "blogspot.com",
    # free / developer hosting, tunnels, dynamic DNS
    "github.io", "gitlab.io", "herokuapp.com", "workers.dev", "pages.dev", "vercel.app", "netlify.app",
    "ngrok.io", "ngrok-free.app", "ngrok.app", "trycloudflare.com", "onrender.com", "glitch.me", "repl.co",
    "replit.dev", "fly.dev", "railway.app", "deno.dev", "surge.sh", "r2.dev", "b-cdn.net", "ondigitalocean.app",
    "digitaloceanspaces.com", "wixsite.com", "myshopify.com", "duckdns.org", "no-ip.com", "ddns.net",
    "hopto.org", "zapto.org", "serveo.net", "loca.lt",
    # SaaS tenants
    "my.salesforce.com", "force.com", "atlassian.net", "zendesk.com", "okta.com", "oktapreview.com", "auth0.com",
})

#: suffixes with a variable label: ``<region>.cloudapp.azure.com``, ``z29.web.core.windows.net``,
#: ``s3.ap-south-1.amazonaws.com``, ``<region>.elb.amazonaws.com`` …
_PATTERNS = (
    re.compile(r"^z\d+\.web\.core\.windows\.net$"),
    re.compile(r"^[a-z0-9-]+\.cloudapp\.azure\.com$"),
    re.compile(r"^(?:s3|s3-website|s3-accesspoint|execute-api|lambda-url|elb|compute)[.-][a-z]{2}(?:-gov)?-[a-z]+-\d"
               r"\.amazonaws\.com(?:\.cn)?$"),
    re.compile(r"^[a-z]{2}(?:-gov)?-[a-z]+-\d\.(?:elb|compute)\.amazonaws\.com$"),
)
_MAX_LABELS = 5


def is_public_suffix(domain: str) -> bool:
    d = str(domain or "").strip().lower().rstrip(".")
    return d in SUFFIXES or any(p.match(d) for p in _PATTERNS)


def registrable(labels: list[str] | str) -> str:
    """The registrable name of a host: the longest listed suffix plus one label. A host that IS a suffix (or a
    listed suffix returns itself; a single label (or nothing) returns ``""``."""
    if isinstance(labels, str):
        labels = labels.strip().lower().rstrip(".").split(".")
    labels = [x for x in labels if x]
    if not labels:
        return ""
    for n in range(min(_MAX_LABELS, len(labels)), 1, -1):          # longest suffix first
        suf = ".".join(labels[-n:])
        if is_public_suffix(suf):
            return ".".join(labels[-(n + 1):]) if len(labels) > n else suf
    return ".".join(labels[-2:]) if len(labels) >= 2 else ""


__all__ = ["SUFFIXES", "is_public_suffix", "registrable"]
