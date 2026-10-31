"""TLS / key identity signals — "fake keys hitting our endpoint", as they actually look at the edge.

Nothing here judges cryptography (a handshake validates or fails); it grades **who presents the
keys and how**, which is where forged identity shows up:

    tls_fingerprint   the ClientHello (JA4) does not match the client the User-Agent claims, or
                      matches a known tooling fingerprint — the single best "agent in disguise" tell
    client_cert       mTLS cert not chained to our CA / revoked / expired / subject≠account /
                      one cert from many IPs
    token             JWT signature failures in volume, alg outside policy (none, RS→HS confusion),
                      unknown or injected kid, iat in the future
    protocol          TLS 1.0/1.1 or weak ciphers offered, SNI ≠ Host, renegotiation storm
    ct_log            (not at the endpoint) a certificate for our domain or a lookalike issued by a
                      CA we do not use, or our serial seen on a host we do not own

Context that explains a mismatch without malice: a known TLS-inspection proxy (Zscaler, a
corporate egress), an allow-listed monitor, a key-rotation window (old-kid tokens fail for a few
minutes). Each neutralises only what it can explain.

Shared by the WAF profile, the agentic campaign rows and two dedicated profiles (token forgery,
CT-log watch). Returns plain tuples ``(text, strength, technique)`` so each caller wraps them in
its own signal type.
"""

from __future__ import annotations

import random

_KNOWN_FP = {   # family -> plausible JA4 shapes (synthetic, structure only)
    "chrome": "t13d1516h2_8daaf6152771_e5627efa2ab1", "firefox": "t13d1715h2_5b57614c22b0_3d5424432f57",
    "safari": "t13d2014h2_a09f3c656075_14788d8d241b", "okhttp": "t13d1211h2_2b2d5f1c9e3a_7c1b0d7f6a2e",
    "python-requests": "t13d1012h1_d2f6b9a1c0e4_09a7c3b2d1e5", "go-http": "t13d1109h2_93a1d6b2e0c4_1f2e3d4c5b6a",
    "curl": "t13d1310h1_e8f1a2b3c4d5_6a7b8c9d0e1f", "headless-chrome": "t13d1516h2_8daaf6152771_a1b2c3d4e5f6",
    "inspection-proxy": "t12d1407h1_0a1b2c3d4e5f_f6e5d4c3b2a1", "known-tooling": "t12d0608h1_deadbeef0000_c0ffee000000",
}
_UA_FAMILY = {
    "Mozilla/5.0 (Windows NT 10.0; Win64) Chrome/130": "chrome", "Mozilla/5.0 (Macintosh) Chrome/129": "chrome",
    "Mozilla/5.0 (Linux) Firefox/115": "firefox", "Mozilla/5.0 (iPhone) Safari/17": "safari",
    "okhttp/4.12 (Android 14)": "okhttp", "okhttp/4.12": "okhttp", "python-requests/2.32": "python-requests", "curl/8.4.0": "curl",
    "Mozilla/5.0 (X11; Linux x86_64) HeadlessChrome/129": "headless-chrome", "Datadog Synthetics": "chrome",
}
_ALGS = ("RS256", "RS256", "RS256", "ES256", "HS256", "none")


def tls_block(r: random.Random, *, user_agent: str = "", mtls: bool | None = None, tokens: bool | None = None,
              context: dict | None = None) -> tuple[dict, list[tuple[str, str, str]]]:
    """Build a ``tls_identity`` section for an alert plus graded ``(text, strength, technique)`` signals.

    ``context`` may carry ``known_inspection_proxy`` / ``monitor_allowlisted`` / ``key_rotation_window``;
    the signals those explain are returned with strength ``none`` and an explanatory text.
    """
    ctx = context or {}
    claimed = _UA_FAMILY.get(user_agent, r.choice(("chrome", "firefox", "safari", "okhttp")))
    actual = claimed if r.random() < .6 else r.choice(list(_KNOWN_FP))
    sig: list[tuple[str, str, str]] = []
    blk: dict = {"ja4": _KNOWN_FP[actual], "ja4_family": actual, "ua_claims_family": claimed,
                 "tls_version_offered": r.choice(("1.3", "1.3", "1.2", "1.0")), "sni_matches_host": r.random() < .93,
                 "weak_ciphers_offered": r.random() < .08, "renegotiations_per_min": r.choice((0, 0, 0, r.randint(20, 300)))}
    # --- fingerprint vs claimed client
    if actual == "known-tooling":
        sig.append(("JA4 matches a known attack-tooling fingerprint", "strong", "T1588.002"))
    elif actual == "inspection-proxy":
        if ctx.get("known_inspection_proxy"):
            sig.append((f"JA4 is the corporate inspection proxy ({ctx['known_inspection_proxy']}) — expected for employees", "none", ""))
        else:
            sig.append(("TLS terminated by an unknown interception proxy", "strong", "T1557"))
    elif actual != claimed and actual != "headless-chrome":
        if ctx.get("monitor_allowlisted"):
            sig.append((f"UA says {claimed} but TLS stack is {actual} — the allow-listed monitor's scripted client", "none", ""))
        else:
            sig.append((f"UA claims {claimed} but the TLS ClientHello is {actual} — the client is lying about what it is", "strong", "T1036"))
    elif actual == "headless-chrome" and claimed == "chrome":
        sig.append(("headless Chrome presenting a desktop Chrome UA", "weak", ""))
    else:
        sig.append(("TLS fingerprint consistent with the claimed client", "none", ""))
    # --- protocol hygiene
    if blk["tls_version_offered"] == "1.0" or blk["weak_ciphers_offered"]:
        sig.append(("offers TLS 1.0 / weak ciphers (downgrade attempt)", "weak", "T1557"))
    if not blk["sni_matches_host"]:
        sig.append(("SNI does not match the Host header", "weak", ""))
    if blk["renegotiations_per_min"] >= 20:
        sig.append((f"{blk['renegotiations_per_min']} renegotiations/min", "weak", "T1499"))
    # --- mTLS client certificate
    if mtls if mtls is not None else r.random() < .35:
        chain_ok = r.random() < .7; revoked = (not chain_ok) and r.random() < .3; expired = r.random() < .15
        subj_match = r.random() < .85; ips = r.choice((1, 1, 1, r.randint(6, 60)))
        blk["client_cert"] = {"presented": True, "issuer": "BankIN-Internal-CA-2" if chain_ok else r.choice(("self-signed", "Example-Public-CA", "unknown")),
                              "chain_valid": chain_ok, "revoked": revoked, "expired": expired,
                              "subject_matches_account": subj_match, "distinct_ips_using_cert_24h": ips}
        if revoked:
            sig.append(("client certificate is revoked", "strong", "T1552.004"))
        elif not chain_ok:
            sig.append((f"client certificate not issued by our CA ({blk['client_cert']['issuer']})", "strong", "T1552.004"))
        if not subj_match:
            sig.append(("certificate subject does not match the account using it", "strong", "T1550"))
        if ips >= 6:
            sig.append((f"one client certificate used from {ips} IPs in 24 h", "weak", ""))
        if expired and chain_ok:
            sig.append(("client certificate expired", "weak", ""))
        if chain_ok and not revoked and subj_match and ips < 6:
            sig.append(("client certificate valid, ours, matches the account", "none", ""))
    # --- bearer tokens
    if tokens if tokens is not None else r.random() < .4:
        failures = r.choice((0, 0, r.randint(1, 4), r.randint(50, 3000))); alg = r.choice(_ALGS); kid_known = r.random() < .8
        kid = r.choice(("k-2026-09", "k-2026-10")) if kid_known else r.choice(("../../etc/keys", "k-0000' OR 1=1", "jwks-remote", "k-2024-01"))
        iat_future = r.random() < .08
        blk["tokens"] = {"signature_failures_15m": failures, "alg": alg, "kid": kid, "kid_in_jwks": kid_known, "iat_in_future": iat_future}
        if alg == "none":
            sig.append(("token with alg=none — signature bypass attempt", "strong", "T1550.001"))
        elif alg == "HS256":
            sig.append(("HS256 token where the API issues RS256 — key-confusion attempt", "strong", "T1550.001"))
        if not kid_known:
            sig.append((f"token kid not in JWKS ({kid})" + (" — injection shape" if any(c in kid for c in "./'") else ""), "strong", "T1550.001"))
        if failures >= 50:
            if ctx.get("key_rotation_window"):
                sig.append((f"{failures} signature failures during the key-rotation window — cached old kid", "none", ""))
            else:
                sig.append((f"{failures} signature failures in 15 min from one source", "strong", "T1550.001"))
        elif failures >= 1:
            sig.append((f"{failures} signature failure(s)", "weak", ""))
        if iat_future:
            sig.append(("token iat in the future", "weak", ""))
        if alg in ("RS256", "ES256") and kid_known and failures == 0 and not iat_future:
            sig.append(("tokens verify against our JWKS", "none", ""))
    return blk, sig


def ct_event(r: random.Random) -> tuple[dict, list[tuple[str, str, str]], str]:
    """A Certificate-Transparency / key-impersonation observation (not at the endpoint). Returns
    (alert, signals, actor)."""
    our = ("bank.in", "netbanking.bank.in", "api.bank.in"); look = ("bank-in.com", "netbanking-bank.in", "bankin-secure.net", "api-bank.in")
    kind = r.choice(("our_domain_unknown_ca", "lookalike", "serial_elsewhere", "planned_renewal", "planned_renewal"))
    our_cas = ("DigiCert", "Sectigo"); ca = r.choice(our_cas) if kind == "planned_renewal" else r.choice(("Let's Encrypt", "ZeroSSL", "Unknown-CA"))
    domain = r.choice(our) if kind != "lookalike" else r.choice(look)
    a = {"source": "Certificate Transparency Monitor", "event": "precert_logged" if kind != "serial_elsewhere" else "cert_seen_on_host",
         "domain": domain, "issuer": ca, "issuer_in_our_ca_list": ca in our_cas, "acme_account_known": kind == "planned_renewal",
         "matches_renewal_schedule": kind == "planned_renewal", "ct_log": r.choice(("Argon2026", "Xenon2026", "Nimbus2026")),
         "serial_seen_on_ip": None if kind != "serial_elsewhere" else {"ip": f"203.0.113.{r.randint(2, 250)}", "asn_ours": False},
         "levenshtein_to_our_domain": 0 if domain in our else r.randint(1, 3),
         "serial": f"{r.getrandbits(64):016x}", "not_before": f"2026-{r.randint(1, 12):02d}-{r.randint(1, 28):02d}",
         "san_count": r.randint(1, 12), "key_type": r.choice(("RSA-2048", "ECDSA-P256", "RSA-4096"))}
    s: list[tuple[str, str, str]] = []
    if kind == "our_domain_unknown_ca":
        s.append((f"certificate for {domain} issued by {ca}, which is not in our CA list", "strong", "T1588.004"))
        s.append(("ACME account unknown, outside the renewal schedule", "strong", "T1588.004"))
    elif kind == "lookalike":
        s.append((f"certificate issued for lookalike {domain} (edit distance {a['levenshtein_to_our_domain']})", "strong", "T1583.001"))
        s.append((f"issuer {ca} — free CA typical of phishing kits", "weak", ""))
    elif kind == "serial_elsewhere":
        s.append((f"our certificate serial presented by {a['serial_seen_on_ip']['ip']} outside our ASN", "strong", "T1552.004"))
        s.append(("private key may be compromised", "strong", "T1552.004"))
    else:
        s.append(("issued by our CA from our ACME account on the renewal schedule", "none", ""))
    return a, s, domain


__all__ = ["ct_event", "tls_block"]
