"""Per-installation licensing for the BlueDefence SOC.

A bank's AEGIS runs behind its own firewall, often with no egress, so the licence is an **offline
signed file** bound to **that installation**, checked at startup and once per cycle — never a call
home. One licence per installation; a second site is a second licence.

    python -m aegis.license keygen  --out keys/                       issuer: RSA-3072 keypair (private key stays offline)
    python -m aegis.license install-id                                operator: prints this installation's id for the order
    python -m aegis.license issue   --key keys/license.key --customer "Bank X" --installation <id>
                                    --edition soc --tier standard --days 365 [--devices 2000 --eps 50]
                                    [--feature netops --feature kafka_bridge …] --out license.jwt
    python -m aegis.license verify  [--license license.jwt]           operator: what the running service will conclude
    python -m aegis.license report  [--out usage.json]                operator: signed usage snapshot (counts only) for true-up

The verifier is **stdlib only** (RSASSA-PKCS1-v1_5 / SHA-256 is modular exponentiation and a
byte comparison), so the service gains no dependency; ``keygen`` uses ``cryptography`` when it
is installed and pure-Python Miller–Rabin otherwise.

Enforcement (``AEGIS_LICENSE_ENFORCE=1`` — off in dev/CI so tests and evals run unlicensed):

    valid        features/limits applied: unlicensed features are switched off in the environment
    grace        expired < grace_days ago — runs as valid, warns every cycle
    over_limit   24 h peak above devices/eps for > AEGIS_LICENSE_OVERLIMIT_DAYS (7) — enforcement forced to shadow
    expired      past the grace window — the service refuses to START; audit/verify/export tools still work
    missing /    no file or bad signature / wrong installation — **evaluation mode**: external edition, shadow
    invalid      enforcement, swarm/ensemble/netops/bridge off, 100 devices / 5 eps. Nothing is ever deleted.

The licence can require an edition no higher than it names (a ``soc`` licence cannot run ``full``).
Public keys: ``aegis/keys/*.pub.json`` ship in the image (``kid`` → key); ``AEGIS_LICENSE_PUBKEYS``
(a directory or a file) overrides for a bank that rotates to its own issuer. Rotation = add the new
public key, issue with the new ``kid``, retire the old file.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import logging
import os
import platform
import secrets
import socket
import sys
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, MutableMapping

logger = logging.getLogger("aegis.license")

KEYS_DIR = Path(__file__).resolve().parent / "keys"
EDITION_RANK = {"external": 0, "soc": 1, "full": 2}
TIERS = ("evaluation", "pilot", "standard", "enterprise")
ALL_FEATURES = ("swarm", "ensemble", "investigate", "netops", "kafka_bridge", "dpo", "auto_block_live", "live_enforcement", "compliance_pack")
TIER_DEFAULTS: dict[str, dict] = {
    "evaluation": {"devices": 100, "eps": 5, "features": []},
    "pilot":      {"devices": 100, "eps": 5, "features": ["swarm", "investigate", "netops"]},
    "standard":   {"devices": 2000, "eps": 50, "features": ["swarm", "investigate", "netops", "ensemble", "live_enforcement", "auto_block_live"]},
    "enterprise": {"devices": 0, "eps": 0, "features": list(ALL_FEATURES)},        # 0 = unlimited
}
# what each feature flips off in the environment when it is NOT licensed (enforce mode only)
FEATURE_ENV_OFF: dict[str, dict[str, str]] = {
    "swarm": {"AEGIS_SWARM": "0"},
    "ensemble": {"AEGIS_ENSEMBLE_VOTE": "off"},
    "investigate": {"AEGIS_INVESTIGATE": "0", "AEGIS_TWIN": "0"},
    "netops": {"AEGIS_NETOPS": "0"},
    "kafka_bridge": {"AEGIS_KAFKA_BRIDGE": "0"},
    "dpo": {"AEGIS_DPO": "0"},
    "auto_block_live": {"AEGIS_AUTO_BLOCK": "shadow"},
    "live_enforcement": {"AEGIS_ENFORCEMENT_MODE": "shadow", "AEGIS_OUTFLOW_BREAKER": "shadow", "AEGIS_HITL_TIMEOUT": "shadow"},
}
SHADOW_ENV = FEATURE_ENV_OFF["live_enforcement"] | FEATURE_ENV_OFF["auto_block_live"]


class LicenseError(RuntimeError):
    """Raised at startup when the licence forbids running at all (past grace, or edition too high)."""


# ------------------------------------------------------------------ RSA (stdlib) --

def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _unb64u(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _i2b(n: int, length: int) -> bytes:
    return n.to_bytes(length, "big")


def _b2i(b: bytes) -> int:
    return int.from_bytes(b, "big")


# DigestInfo prefix for SHA-256 (RFC 8017 §9.2 note 1)
_SHA256_DIGESTINFO = bytes.fromhex("3031300d060960864801650304020105000420")


def _emsa_pkcs1_v15(msg: bytes, k: int) -> bytes:
    t = _SHA256_DIGESTINFO + hashlib.sha256(msg).digest()
    if k < len(t) + 11:
        raise ValueError("key too short")
    return b"\x00\x01" + b"\xff" * (k - len(t) - 3) + b"\x00" + t


def rsa_sign(msg: bytes, n: int, d: int) -> bytes:
    k = (n.bit_length() + 7) // 8
    return _i2b(pow(_b2i(_emsa_pkcs1_v15(msg, k)), d, n), k)


def rsa_verify(msg: bytes, sig: bytes, n: int, e: int) -> bool:
    k = (n.bit_length() + 7) // 8
    if len(sig) != k:
        return False
    try:
        em = _i2b(pow(_b2i(sig), e, n), k)
        return secrets.compare_digest(em, _emsa_pkcs1_v15(msg, k))
    except (ValueError, OverflowError):
        return False


def _is_probable_prime(n: int, rounds: int = 40) -> bool:
    if n < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % p == 0:
            return n == p
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _gen_prime(bits: int) -> int:
    while True:
        c = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if _is_probable_prime(c):
            return c


def rsa_keygen(bits: int = 3072) -> tuple[int, int, int]:
    """(n, e, d). Uses ``cryptography`` when present (fast), else pure Python (a minute for 3072)."""
    e = 65537
    try:
        from cryptography.hazmat.primitives.asymmetric import rsa  # type: ignore
        key = rsa.generate_private_key(public_exponent=e, key_size=bits)
        nums = key.private_numbers()
        return nums.public_numbers.n, e, nums.d
    except ImportError:
        pass
    while True:
        p, q = _gen_prime(bits // 2), _gen_prime(bits // 2)
        if p == q:
            continue
        n = p * q
        phi = (p - 1) * (q - 1)
        if n.bit_length() == bits and phi % e:
            return n, e, pow(e, -1, phi)


# --------------------------------------------------------------------- keys --

def load_public_keys(where: str | Path | None = None) -> dict[str, tuple[int, int]]:
    """``kid`` → (n, e) from ``*.pub.json`` files in a directory, or one file. Order of precedence:
    the argument, ``AEGIS_LICENSE_PUBKEYS``, the keys shipped in the package."""
    src = Path(where) if where else Path(os.environ.get("AEGIS_LICENSE_PUBKEYS", "").strip() or KEYS_DIR)
    files = sorted(src.glob("*.pub.json")) if src.is_dir() else ([src] if src.is_file() else [])
    out: dict[str, tuple[int, int]] = {}
    for f in files:
        try:
            k = json.loads(f.read_text())
            out[str(k["kid"])] = (int(k["n"], 16), int(k["e"]))
        except (OSError, ValueError, KeyError) as exc:
            logger.warning("[license] public key %s unreadable: %s", f, exc)
    return out


def write_keypair(out_dir: Path, kid: str, bits: int = 3072) -> tuple[Path, Path]:
    n, e, d = rsa_keygen(bits)
    out_dir.mkdir(parents=True, exist_ok=True)
    pub, priv = out_dir / f"{kid}.pub.json", out_dir / f"{kid}.key.json"
    pub.write_text(json.dumps({"kid": kid, "alg": "RS256", "n": f"{n:x}", "e": e}, indent=1) + "\n")
    priv.write_text(json.dumps({"kid": kid, "alg": "RS256", "n": f"{n:x}", "e": e, "d": f"{d:x}"}) + "\n")
    try:
        os.chmod(priv, 0o600)
    except OSError:
        pass
    return pub, priv


# -------------------------------------------------------------- installation --

def installation_id(env: MutableMapping[str, str] | None = None) -> str:
    """Stable per-installation id: ``AEGIS_INSTALL_ID`` if the operator pins one (clusters), else
    sha256(machine-id | hostname | salt)[:20]. Printed in the banner and ``/healthz``; the order to
    the issuer carries it; the licence is bound to it, so one file does not run five sites."""
    env = os.environ if env is None else env
    pinned = env.get("AEGIS_INSTALL_ID", "").strip()
    if pinned:
        return pinned
    parts = []
    for p in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
        try:
            parts.append(Path(p).read_text().strip())
            break
        except OSError:
            continue
    if not parts:
        parts.append(f"{uuid.getnode():x}")
    parts += [socket.gethostname(), platform.machine(), env.get("AEGIS_INSTALL_SALT", "")]
    return "bd-" + hashlib.sha256("|".join(parts).encode()).hexdigest()[:20]


# ------------------------------------------------------------------ licence --

@dataclass
class License:
    customer: str
    installation_id: str
    edition: str
    tier: str
    issued: float
    expires: float
    grace_days: int = 30
    devices: int = 0            # 0 = unlimited
    eps: int = 0
    features: list[str] = field(default_factory=list)
    kid: str = ""
    license_id: str = ""
    notes: str = ""

    def payload(self) -> dict:
        return {"v": 1, "lic": self.license_id, "customer": self.customer, "installation_id": self.installation_id,
                "edition": self.edition, "tier": self.tier, "issued": int(self.issued), "expires": int(self.expires),
                "grace_days": self.grace_days, "limits": {"devices": self.devices, "eps": self.eps},
                "features": sorted(set(self.features)), "notes": self.notes}

    @classmethod
    def from_payload(cls, p: dict, kid: str = "") -> "License":
        lim = p.get("limits") or {}
        return cls(customer=str(p.get("customer", "")), installation_id=str(p.get("installation_id", "")),
                   edition=str(p.get("edition", "external")), tier=str(p.get("tier", "evaluation")),
                   issued=float(p.get("issued", 0)), expires=float(p.get("expires", 0)), grace_days=int(p.get("grace_days", 30)),
                   devices=int(lim.get("devices", 0)), eps=int(lim.get("eps", 0)), features=list(p.get("features") or []),
                   kid=kid, license_id=str(p.get("lic", "")), notes=str(p.get("notes", "")))


def issue(lic: License, *, n: int, d: int, kid: str) -> str:
    """Compact token: ``<b64url header>.<b64url payload>.<b64url signature>`` (JWS-shaped, RS256)."""
    lic.kid = kid
    lic.license_id = lic.license_id or f"L-{int(time.time())}-{secrets.token_hex(3)}"
    header = _b64u(json.dumps({"alg": "RS256", "typ": "AEGIS-LICENSE", "kid": kid}, separators=(",", ":")).encode())
    body = _b64u(json.dumps(lic.payload(), sort_keys=True, separators=(",", ":")).encode())
    sig = rsa_sign(f"{header}.{body}".encode(), n, d)
    return f"{header}.{body}.{_b64u(sig)}"


def decode(token: str, keys: dict[str, tuple[int, int]]) -> tuple[License | None, str]:
    """(licence, "") on a good signature; (None, reason) otherwise. Never raises."""
    try:
        h, b, s = token.strip().split(".")
        header = json.loads(_unb64u(h))
        kid = str(header.get("kid", ""))
        if header.get("alg") != "RS256" or header.get("typ") != "AEGIS-LICENSE":
            return None, "unsupported licence format"
        if kid not in keys:
            return None, f"unknown signing key '{kid}'"
        n, e = keys[kid]
        if not rsa_verify(f"{h}.{b}".encode(), _unb64u(s), n, e):
            return None, "signature does not verify"
        p = json.loads(_unb64u(b))
        if int(p.get("v", 0)) != 1:
            return None, f"unsupported licence version {p.get('v')}"
        return License.from_payload(p, kid), ""
    except (ValueError, TypeError, KeyError) as exc:
        return None, f"malformed licence ({type(exc).__name__})"


# -------------------------------------------------------------------- state --

@dataclass
class LicenseState:
    status: str                         # valid | grace | over_limit | expired | missing | invalid
    reason: str = ""
    license: License | None = None
    installation_id: str = ""
    enforce: bool = False
    effective_edition: str = "external"
    effective_features: set[str] = field(default_factory=set)
    devices_limit: int = 100
    eps_limit: int = 5
    days_left: float | None = None

    @property
    def runs(self) -> bool:
        return self.status in ("valid", "grace", "over_limit", "missing", "invalid")

    @property
    def licensed(self) -> bool:
        return self.status in ("valid", "grace", "over_limit")

    def describe(self) -> str:
        lic = self.license
        if not self.licensed:
            return f"licence {self.status}: {self.reason} — evaluation mode" + (" (enforced)" if self.enforce else " (not enforced: AEGIS_LICENSE_ENFORCE=0)")
        assert lic is not None
        left = f"{self.days_left:.0f} d left" if self.days_left is not None else ""
        lim = f"{lic.devices or '∞'} devices / {lic.eps or '∞'} eps"
        return (f"licence {self.status}: {lic.customer} · {lic.tier} · {lic.edition} · {lim} · {left} · "
                f"features {','.join(sorted(self.effective_features)) or 'none'}" + ("" if self.enforce else " (not enforced)"))

    def to_dict(self) -> dict:
        lic = self.license
        return {"status": self.status, "reason": self.reason, "enforce": self.enforce, "installation_id": self.installation_id,
                "customer": lic.customer if lic else None, "tier": lic.tier if lic else "evaluation", "edition": self.effective_edition,
                "expires": int(lic.expires) if lic else None, "days_left": round(self.days_left, 1) if self.days_left is not None else None,
                "features": sorted(self.effective_features), "limits": {"devices": self.devices_limit, "eps": self.eps_limit},
                "license_id": lic.license_id if lic else None}


def _read_token(env: MutableMapping[str, str]) -> tuple[str, str]:
    raw = env.get("AEGIS_LICENSE", "").strip()
    if not raw:
        for cand in ("/etc/aegis/license.jwt", "./license.jwt"):
            if Path(cand).is_file():
                raw = cand
                break
    if not raw:
        return "", "no licence (AEGIS_LICENSE unset, no /etc/aegis/license.jwt)"
    if raw.count(".") == 2 and not Path(raw).exists():
        return raw, ""                                          # inline token
    try:
        return Path(raw).read_text().strip(), ""
    except OSError as exc:
        return "", f"licence file {raw} unreadable: {exc}"


def check(env: MutableMapping[str, str] | None = None, *, now: float | None = None, keys: dict | None = None,
          over_limit: bool = False) -> LicenseState:
    """Evaluate the licence for this installation. Pure: reads env/files, mutates nothing."""
    env = os.environ if env is None else env
    now = time.time() if now is None else now
    enforce = env.get("AEGIS_LICENSE_ENFORCE", "0").strip().lower() in ("1", "true", "yes", "on")
    inst = installation_id(env)
    ev = TIER_DEFAULTS["evaluation"]
    st = LicenseState(status="missing", installation_id=inst, enforce=enforce, effective_edition="external",
                      effective_features=set(ev["features"]), devices_limit=ev["devices"], eps_limit=ev["eps"])
    token, why = _read_token(env)
    if not token:
        st.reason = why
        return st
    lic, bad = decode(token, keys if keys is not None else load_public_keys())
    if lic is None:
        st.status, st.reason = "invalid", bad
        return st
    if lic.installation_id and lic.installation_id != inst:
        st.status, st.reason = "invalid", f"licence is bound to installation {lic.installation_id}, this is {inst}"
        return st
    st.license = lic
    st.days_left = (lic.expires - now) / 86400.0
    st.effective_edition = lic.edition if lic.edition in EDITION_RANK else "external"
    st.effective_features = set(lic.features)
    st.devices_limit, st.eps_limit = lic.devices, lic.eps
    if now > lic.expires + lic.grace_days * 86400:
        st.status, st.reason = "expired", f"expired {-st.days_left:.0f} days ago; grace of {lic.grace_days} days is over"
        return st
    if now > lic.expires:
        st.status, st.reason = "grace", f"expired {-st.days_left:.0f} days ago; {lic.grace_days + st.days_left:.0f} days of grace left — renew"
        return st
    if over_limit:
        st.status, st.reason = "over_limit", "24 h peak above the licensed devices/eps for longer than the allowance — enforcement in shadow"
        return st
    st.status = "valid"
    return st


def apply(state: LicenseState, env: MutableMapping[str, str] | None = None) -> LicenseState:
    """Make the environment honour the licence (enforce mode only). Called before ``apply_edition``
    so the edition check then sees the licensed edition. Raises ``LicenseError`` when the service
    must not start."""
    env = os.environ if env is None else env
    if not state.enforce:
        return state
    if state.status == "expired":
        raise LicenseError(f"[license] {state.reason}. Renew the licence (installation {state.installation_id}); "
                           f"audit/verify/export tools keep working: python -m aegis.license verify")
    wanted = env.get("AEGIS_EDITION", "").strip().lower() or "external"
    if EDITION_RANK.get(wanted, 0) > EDITION_RANK[state.effective_edition]:
        if state.licensed:
            raise LicenseError(f"[license] AEGIS_EDITION={wanted} but the licence covers '{state.effective_edition}' — "
                               f"set AEGIS_EDITION={state.effective_edition} or upgrade the licence")
        logger.warning("[license] evaluation mode: AEGIS_EDITION=%s downgraded to external", wanted)
        env["AEGIS_EDITION"] = "external"
    forced: dict[str, str] = {}
    for feat, offs in FEATURE_ENV_OFF.items():
        if feat not in state.effective_features:
            forced.update(offs)
    if state.status == "over_limit" or not state.licensed:
        forced.update(SHADOW_ENV)
    for k, v in forced.items():
        if env.get(k, "") != v:
            env[k] = v
    if forced:
        logger.warning("[license] %s — forced: %s", state.describe(), ", ".join(f"{k}={v}" for k, v in sorted(forced.items())))
    return state


def allows(feature: str, state: LicenseState | None = None) -> bool:
    """Feature gate for code paths that are not env-driven (the Kafka bridge endpoint, compliance pack)."""
    st = state or check()
    return (not st.enforce) or feature in st.effective_features


# -------------------------------------------------------------------- meter --

@dataclass
class LicenseMeter:
    """24 h rolling peak of events/s and the device count against the licence; over the limit for
    longer than the allowance → ``over_limit`` (shadow), never a stop. Counts only — no event data."""
    eps_limit: int = 0
    devices_limit: int = 0
    allowance_s: float = 7 * 86400.0
    buckets: dict[int, int] = field(default_factory=dict)        # hour-epoch → events
    over_since: float | None = None
    peak_eps_24h: float = 0.0
    devices_seen: int = 0

    def observe(self, events: int, now: float, devices: int | None = None) -> bool:
        hour = int(now // 3600)
        self.buckets[hour] = self.buckets.get(hour, 0) + max(0, events)
        for h in [h for h in self.buckets if h < hour - 24]:
            del self.buckets[h]
        self.peak_eps_24h = max(self.buckets.values(), default=0) / 3600.0
        if devices is not None:
            self.devices_seen = devices
        over = (self.eps_limit and self.peak_eps_24h > self.eps_limit) or (self.devices_limit and self.devices_seen > self.devices_limit)
        if over:
            self.over_since = self.over_since or now
        else:
            self.over_since = None
        return bool(self.over_since is not None and now - self.over_since > self.allowance_s)

    def to_dict(self) -> dict:
        return {"peak_eps_24h": round(self.peak_eps_24h, 3), "devices_seen": self.devices_seen,
                "eps_limit": self.eps_limit, "devices_limit": self.devices_limit,
                "over_limit_for_s": int(time.time() - self.over_since) if self.over_since else 0}


def usage_report(state: LicenseState, meter: LicenseMeter | None, *, audit_path: Path | None = None) -> dict:
    """Counts only — what a bank can e-mail across an air gap for the annual true-up."""
    chains = 0
    if audit_path and audit_path.exists():
        with audit_path.open("rb") as fh:
            chains = sum(1 for ln in fh if ln.strip())
    rep = {"generated_at": int(time.time()), "installation_id": state.installation_id, "license": state.to_dict(),
           "usage": (meter.to_dict() if meter else {}), "audit_chains": chains, "host": platform.node()}
    rep["digest"] = hashlib.sha256(json.dumps(rep, sort_keys=True).encode()).hexdigest()
    return rep


# ---------------------------------------------------------------------- CLI --

def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m aegis.license", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    k = sub.add_parser("keygen", help="issuer: create a signing keypair (keep the .key.json offline)")
    k.add_argument("--out", default="keys")
    k.add_argument("--kid", default=f"bd-{time.strftime('%Y-%m')}")
    k.add_argument("--bits", type=int, default=3072)
    sub.add_parser("install-id", help="operator: this installation's id, for the licence order")
    i = sub.add_parser("issue", help="issuer: sign a licence for one installation")
    i.add_argument("--key", required=True, help="the .key.json from keygen")
    i.add_argument("--customer", required=True)
    i.add_argument("--installation", required=True, help="the installation id the operator sent (or '*' for a floating pilot)")
    i.add_argument("--edition", choices=tuple(EDITION_RANK), default="soc")
    i.add_argument("--tier", choices=TIERS[1:], default="standard")
    i.add_argument("--days", type=int, default=365)
    i.add_argument("--grace-days", type=int, default=30)
    i.add_argument("--devices", type=int, help="override the tier default (0 = unlimited)")
    i.add_argument("--eps", type=int, help="override the tier default (0 = unlimited)")
    i.add_argument("--feature", action="append", default=[], help=f"add a feature beyond the tier default: {', '.join(ALL_FEATURES)}")
    i.add_argument("--notes", default="")
    i.add_argument("--out", default="license.jwt")
    v = sub.add_parser("verify", help="operator: what the service will conclude from the licence")
    v.add_argument("--license", help="path or token (default: AEGIS_LICENSE / /etc/aegis/license.jwt)")
    v.add_argument("--pubkeys", help="directory or file of *.pub.json (default: AEGIS_LICENSE_PUBKEYS / shipped keys)")
    v.add_argument("--json", action="store_true")
    r = sub.add_parser("report", help="operator: signed usage snapshot (counts only) for the true-up")
    r.add_argument("--audit", default=os.environ.get("AEGIS_AUDIT_PATH", "aegis/_audit_log.jsonl"))
    r.add_argument("--out", default="")
    a = ap.parse_args(argv)

    if a.cmd == "keygen":
        pub, priv = write_keypair(Path(a.out), a.kid, a.bits)
        print(f"public key  {pub}   → ship in the image (aegis/keys/) or AEGIS_LICENSE_PUBKEYS")
        print(f"private key {priv}   → OFFLINE. Never in the repo, never in an image. Password manager / HSM.")
        return 0
    if a.cmd == "install-id":
        print(installation_id())
        return 0
    if a.cmd == "issue":
        key = json.loads(Path(a.key).read_text())
        tier = TIER_DEFAULTS[a.tier]
        feats = sorted(set(tier["features"]) | set(a.feature))
        bad = [f for f in feats if f not in ALL_FEATURES]
        if bad:
            ap.error(f"unknown feature(s): {bad}")
        now = time.time()
        lic = License(customer=a.customer, installation_id="" if a.installation == "*" else a.installation, edition=a.edition,
                      tier=a.tier, issued=now, expires=now + a.days * 86400, grace_days=a.grace_days,
                      devices=tier["devices"] if a.devices is None else a.devices, eps=tier["eps"] if a.eps is None else a.eps,
                      features=feats, notes=a.notes)
        tok = issue(lic, n=int(key["n"], 16), d=int(key["d"], 16), kid=str(key["kid"]))
        Path(a.out).write_text(tok + "\n")
        print(f"issued {lic.license_id} for {a.customer} / {a.installation}: {a.edition} · {a.tier} · {a.days} d · "
              f"{lic.devices or '∞'} devices / {lic.eps or '∞'} eps · {','.join(feats)} → {a.out}")
        return 0
    if a.cmd == "verify":
        env = dict(os.environ)
        if a.license:
            env["AEGIS_LICENSE"] = a.license
        st = check(env, keys=load_public_keys(a.pubkeys) if a.pubkeys else None)
        if a.json:
            print(json.dumps(st.to_dict(), indent=1))
        else:
            print(f"installation {st.installation_id}")
            print(st.describe())
        return 0 if st.licensed else 1
    if a.cmd == "report":
        st = check()
        rep = usage_report(st, None, audit_path=Path(a.audit))
        text = json.dumps(rep, indent=1)
        if a.out:
            Path(a.out).write_text(text + "\n")
            print(f"usage report → {a.out} (digest {rep['digest'][:16]}…)")
        else:
            print(text)
        return 0
    return 2


__all__ = ["License", "LicenseState", "LicenseMeter", "LicenseError", "check", "apply", "allows", "issue", "decode",
           "installation_id", "load_public_keys", "write_keypair", "usage_report", "rsa_keygen", "rsa_sign", "rsa_verify",
           "ALL_FEATURES", "TIERS", "TIER_DEFAULTS"]

if __name__ == "__main__":
    raise SystemExit(main())
