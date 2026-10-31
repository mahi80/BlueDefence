"""Purple-team campaigns — scripted AI-agent attackers, abstract by construction.

Every campaign is a list of *goals* an attacker agent pursues in order (recon, probe,
exploit, enumerate, exfil…). The harness turns each attempt into a Cloudflare-shaped WAF log
record, feeds it through the real ingest → verdict → response path, and lets the attacker
*adapt* the way the detectors expect an agent to: when a request is stopped it comes back
after ``retry_gap_s`` from the next IP in its proxy pool, with the next payload variant, and
(for some agents) a new user agent.

Two things stop a request:
- the bank's **existing WAF** catches signature-shaped payloads (``waf_catches`` per variant —
  the first variants trip a managed rule, later mutations evade it); and
- **AEGIS enforcement** — once the attacker's IP or client fingerprint is on the active
  enforcement set, its next request is denied before it reaches the application.

What counts, per campaign: when AEGIS first called the client malicious (step and simulated
seconds), when the client was first *contained* (its next request denied by AEGIS, not by
the WAF rule it is mutating around), how many requests reached the application before and
after that, and whether any benign customer in the same traffic was touched.

No real payloads or CVE identifiers anywhere here: payloads are opaque markers such as
``sqli-variant-2``; the WAF "catch" is a flag on the variant, not pattern matching.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

AGENT_JA4 = "t13d1312h2_e8f1e7e78f70_0aaa1111bbbb"      # a Python TLS stack (HTTP/2-capable: browser-shaped)
HEADLESS_JA4 = "t13d1516h2_8daaf6152771_02713d6af862"   # the Chromium build the customers also use
# made-up values (not real fingerprints): a scripting client that offers http/1.1 before h2, and a
# corporate TLS-inspection proxy that re-originates every employee's handshake the same way
SPOOF_JA4 = "t13d1810h1_5c2a8e7d1f3b_9e4b6a0c2d71"
MIDDLEBOX_JA4 = "t13d2214h1_7d3f0b9a6e21_1a8c4e2f9b05"
NAT_IP = "198.51.100.200"                                 # the bank's biggest branch, behind one NAT
PROXY_EGRESS = "198.51.100.230"                           # a corporate customer's TLS-inspection proxy
ATTACKER_PRINCIPAL = "cust-1000"                          # a real (or stolen) customer login; owns account 1000 only
CUSTOMER_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/130 Safari/537.36"
PARTNER_UA = "partner-sync/3.2 (python-httpx/0.27)"


@dataclass(frozen=True)
class Goal:
    name: str
    path: str
    method: str = "GET"
    variants: tuple[str, ...] = ("v0",)        # payload markers the attacker cycles through on retry
    waf_catches: tuple[bool, ...] = (False,)   # per variant: does the bank's existing WAF stop it?
    description: str = ""                      # the WAF rule description when caught (abstract)
    sensitive: bool = False                    # reaching the app here is a real loss (data / money)
    repeat: int = 1                            # enumeration goals repeat with an incremented object id


@dataclass(frozen=True)
class Campaign:
    name: str
    goals: tuple[Goal, ...]
    ip_pool: tuple[str, ...]
    user_agents: tuple[str, ...]
    ja4: Optional[str]
    gap_s: float = 4.0                 # simulated seconds between requests when not stopped
    retry_gap_s: float = 3.0           # how fast the agent comes back after being stopped
    max_retries: int = 4               # per goal
    notes: str = ""
    gate: Optional["Gate"] = None       # None → reported only (a known gap), else asserted in CI
    benign_traffic: bool = True        # interleave customers (collateral measurement)
    channel: str = "waf"               # waf: Cloudflare WAF log per request · apigw: API-gateway log (authenticated)
    principal: Optional[str] = None    # the attacker's authenticated identity (apigw channel)


@dataclass(frozen=True)
class Gate:
    detect_within_steps: int           # first malicious verdict no later than this attacker step
    max_successes: int                 # requests that reached the app before containment (live auto-block)
    contain: bool = True               # the client must end the run contained
    zero_collateral: bool = True


def _pool(prefix: str, n: int) -> tuple[str, ...]:
    return tuple(f"{prefix}.{10 + i}" for i in range(n))


_SQLI = Goal("sqli-probe", "/api/v1/accounts", variants=("sqli-v0", "sqli-v1", "sqli-v2", "sqli-v3", "sqli-v4"),
             waf_catches=(True, True, True, False, False), description="SQL injection (managed rule)", sensitive=True)
_TRAVERSAL = Goal("path-traversal", "/download", variants=("lfi-v0", "lfi-v1", "lfi-v2", "lfi-v3"),
                  waf_catches=(True, True, False, False), description="Path traversal (managed rule)", sensitive=True)
_EXFIL = Goal("statement-export", "/api/v1/statements/export", variants=("exfil-v0",), waf_catches=(False,), sensitive=True)
_RECON = (
    Goal("recon-sourcemap", "/static/app.js.map"),
    Goal("recon-env", "/.env", variants=("env-v0",), waf_catches=(True,), description="Sensitive file access"),
    Goal("recon-openapi", "/api/openapi.json"),
)


CAMPAIGNS: tuple[Campaign, ...] = (
    Campaign(
        "rotating_sqli_agent",
        goals=_RECON + (_SQLI, _TRAVERSAL, _EXFIL),
        ip_pool=_pool("203.0.113", 8), user_agents=("python-httpx/0.27",), ja4=AGENT_JA4,
        notes="proxy-pool rotation, one TLS stack, one UA; mutates until the WAF misses",
        gate=Gate(detect_within_steps=8, max_successes=4),
    ),
    Campaign(
        "ua_rotating_scanner",
        goals=_RECON + (_SQLI, _EXFIL),
        ip_pool=_pool("192.0.2", 6), user_agents=tuple(f"scanner-client/{i}" for i in range(6)), ja4=AGENT_JA4,
        notes="rotates user agents as well as IPs — a bare TLS fingerprint can only be challenged",
        gate=Gate(detect_within_steps=8, max_successes=4),
    ),
    Campaign(
        "browser_driven_agent",
        goals=_RECON + (_SQLI, _EXFIL),
        ip_pool=_pool("203.0.113", 6), user_agents=("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/130 Safari/537.36",),
        ja4=HEADLESS_JA4,
        notes="drives a real browser: shares its fingerprint with customers, so AEGIS may act on IPs only",
        gate=Gate(detect_within_steps=8, max_successes=6),
    ),
    Campaign(
        "honeytoken_touch",
        goals=(Goal("recon-admin", "/admin-internal-debug"), _SQLI, _EXFIL),
        ip_pool=_pool("198.51.100", 4), user_agents=("python-httpx/0.27",), ja4=AGENT_JA4,
        notes="touches a planted decoy first — deception fast path, no model needed",
        gate=Gate(detect_within_steps=1, max_successes=2),
    ),
    Campaign(
        "credential_stuffing",
        goals=(Goal("login-spray", "/login", method="POST", variants=tuple(f"cred-v{i}" for i in range(12)),
                    waf_catches=(False,) * 12, repeat=12, sensitive=True),),
        ip_pool=_pool("203.0.113", 3), user_agents=("okhttp/4.12",), ja4=AGENT_JA4, gap_s=1.0,
        notes="no WAF signature at all — stopped by the auth-burst fast path (challenge + throttle, no block)",
        gate=Gate(detect_within_steps=9, max_successes=9),
    ),
    Campaign(
        "bola_object_walker",
        goals=(Goal("walk-accounts", "/api/v1/accounts/{id}", variants=("read",), waf_catches=(False,), repeat=12, sensitive=True),),
        ip_pool=_pool("203.0.113", 2), user_agents=("python-httpx/0.27",), ja4=AGENT_JA4, gap_s=2.0,
        channel="apigw", principal=ATTACKER_PRINCIPAL,
        notes="an authenticated customer token walking account ids it does not own — API-gateway log + ownership map; "
              "IP containment lags one rotation, revoking the token (human) is the real stop",
        gate=Gate(detect_within_steps=3, max_successes=4),
    ),
    Campaign(
        "bola_waf_logs_only",
        goals=(Goal("walk-accounts", "/api/v1/accounts/{id}", variants=("read",), waf_catches=(False,), repeat=12, sensitive=True),),
        ip_pool=_pool("203.0.113", 2), user_agents=("python-httpx/0.27",), ja4=AGENT_JA4, gap_s=2.0,
        notes="the same walk seen only through WAF logs (no principal, no ownership) — why gateway logs are required",
        gate=None,
    ),
    Campaign(
        "spoofed_browser_agent",
        goals=_RECON + (_SQLI, _EXFIL),
        ip_pool=_pool("203.0.113", 8), user_agents=(CUSTOMER_UA,), ja4=SPOOF_JA4,
        notes="copies the customers' Chrome user agent onto a scripting TLS stack (http/1.1 first) — "
              "challenged on the exact pair the first time the WAF stops it",
        gate=Gate(detect_within_steps=8, max_successes=2),
    ),
    Campaign(
        "spoofed_browser_http2",
        goals=_RECON + (_SQLI, _EXFIL),
        ip_pool=_pool("192.0.2", 8), user_agents=(CUSTOMER_UA,), ja4=AGENT_JA4,
        notes="Chrome user agent on an HTTP/2-capable library — structurally browser-shaped; caught because "
              "a partner's integration introduces that TLS stack honestly as python-httpx",
        gate=Gate(detect_within_steps=8, max_successes=2),
    ),
    Campaign(
        "slow_spoofed_stuffing",
        goals=(Goal("login-spray", "/login", method="POST", variants=tuple(f"cred-v{i}" for i in range(12)),
                    waf_catches=(False,) * 12, repeat=12, sensitive=True),),
        ip_pool=_pool("203.0.113", 4), user_agents=(CUSTOMER_UA,), ja4=SPOOF_JA4, gap_s=20.0, retry_gap_s=20.0,
        notes="three logins a minute — under the auth-burst rate — behind a copied Chrome user agent; "
              "the TLS lie gets it challenged on its first attempt",
        gate=Gate(detect_within_steps=6, max_successes=1),
    ),
    Campaign(
        "low_and_slow",
        goals=(_SQLI, _TRAVERSAL, _EXFIL),
        ip_pool=_pool("203.0.113", 1), user_agents=("python-httpx/0.27",), ja4=AGENT_JA4, gap_s=150.0, retry_gap_s=150.0,
        notes="one request every 2.5 min from one IP — below the retry-after-stop cadence; caught by the long-window "
              "count of attack-shaped stops mutating against one endpoint (orchestrator/low_and_slow.py)",
        gate=Gate(detect_within_steps=4, max_successes=1),
    ),
    Campaign(
        "benign_customers",
        goals=(),
        ip_pool=(), user_agents=(), ja4=None,
        notes="customers only: shared browser build, shared branch NAT, a few WAF false positives — zero enforcement expected",
        gate=Gate(detect_within_steps=0, max_successes=0, contain=False, zero_collateral=True),
    ),
)


@dataclass
class BenignClient:
    ip: str
    ja4: str
    user_agent: str
    # "POST /login" entries are form submissions; everything else is a GET
    paths: tuple[str, ...] = ("/", "/login", "POST /login", "/api/v1/accounts/me", "/api/v1/statements", "/logout")
    false_positive_every: int = 0        # every Nth request trips a WAF rule (a real-world false positive)
    requests: int = field(default=0)
    principal: str = ""                  # apigw channel: the customer's own identity
    accounts: tuple[str, ...] = ()       # apigw channel: the account ids this customer owns
    history_s: float = 0.0               # warm-up: last seen this long before the attack (0 = just before)


MIDDLEBOX_UAS = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/130 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/129 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/130 Safari/537.36 Edg/130",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:131.0) Gecko/20100101 Firefox/131.0",
)


def benign_crowd(n: int = 12) -> list[BenignClient]:
    """Who else is on the bank's edge while the attacker works:
    - ``n`` customers on the Chromium build whose JA4 the browser-driven agent shares, three of
      them behind the branch NAT, one whose client trips a managed rule now and then;
    - a partner's integration on the same Python TLS stack as the agents, introducing itself
      honestly (two IPs), whose last sync ran 45 minutes ago — outside the campaign window, so
      only the estate's longer memory knows a bare-fingerprint action on that stack would break it;
    - four employees of a corporate customer behind a TLS-inspecting proxy: one egress IP, the
      proxy's own handshake (http/1.1 first, like a script) under four different browsers,
      one of which trips a managed rule — a middlebox must never read as a spoofer."""
    out = [BenignClient(ip=f"198.51.100.{60 + i}", ja4=HEADLESS_JA4, user_agent=CUSTOMER_UA) for i in range(n)]
    for c in out[:3]:
        c.ip = NAT_IP
    out[4].false_positive_every = 5
    for i, c in enumerate(out):
        c.principal = f"cust-{2000 + i}"
        c.accounts = tuple(str(2000 + 10 * i + k) for k in range(1 + i % 3))     # one to three accounts each
    out[7].accounts = tuple(str(3000 + k) for k in range(12))                  # a corporate customer with twelve
    out += [BenignClient(ip=f"198.51.100.{150 + i}", ja4=AGENT_JA4, user_agent=PARTNER_UA, history_s=2700.0,
                         paths=("/api/v1/partner/sync", "/api/v1/partner/positions")) for i in range(2)]
    staff = [BenignClient(ip=PROXY_EGRESS, ja4=MIDDLEBOX_JA4, user_agent=ua) for ua in MIDDLEBOX_UAS]
    staff[-1].false_positive_every = 4
    return out + staff


def ownership_map(crowd: list[BenignClient]) -> dict[tuple[str, str], str]:
    """Who owns which account in the harness bank: the attacker owns one, every customer their own."""
    owners: dict[tuple[str, str], str] = {("account", str(1000 + k)): f"cust-{1000 + k}" for k in range(200)}
    for c in crowd:
        for a in c.accounts:
            owners[("account", a)] = c.principal
    return owners


__all__ = ["Goal", "Campaign", "Gate", "CAMPAIGNS", "BenignClient", "benign_crowd", "ownership_map", "AGENT_JA4", "HEADLESS_JA4",
           "SPOOF_JA4", "MIDDLEBOX_JA4", "NAT_IP", "PROXY_EGRESS", "ATTACKER_PRINCIPAL", "CUSTOMER_UA", "PARTNER_UA", "MIDDLEBOX_UAS"]
