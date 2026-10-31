"""BlueDefence licence service — AWS Lambda behind an HTTP API, DynamoDB for records, SSM for the key.

Stdlib + boto3 (present in the Lambda runtime). The signing code is ``aegis/license.py`` itself,
copied in at build time as ``aegis_license.py`` (see ``build.sh``) so the server and the product can
never disagree on the token format.

Routes (HTTP API v2 payload):

    GET  /health                           liveness, kid(s) loaded
    GET  /pubkeys                          the public keys (kid → n, e) — what ships in the image
    POST /activate        {code, installation_id}
                                           operator self-serve: an unused order code + this installation
                                           → a licence bound to it (one code, one installation, once)
    POST /signup          {org, email, installation_id, accept_terms: true}
                                           Community edition: free for 2 years, model at the bank, data sharing
                                           required. Issues a 30-day ROLLING token immediately (entitlement 730 d)
    POST /usage           {report}         store a `python -m aegis.license report` snapshot (counts only)

  bearer = the installation's licence token (signature verified; an expired token is accepted within grace):
    POST /renew                            roll the token: a fresh 30-day token while the installation is in
                                           good standing — for data_sharing, while contributions keep arriving
    POST /heartbeat       {counts, hashes} daily: chains_total, audit_tail_hash, code_fingerprint, flags, counters
    POST /contrib         gzip bundle      scrubbed chains + analyst decisions → privacy gate → hash-chain
                                           continuity → S3 contrib/<inst>/<ts>.json.gz; counts recorded

    GET  /updates?channel=&base=&current=  (bearer) the newest published model release for this installation's
                                           channel/base beyond ``current`` → {manifest_token (signed), url (presigned
                                           S3 GET, 1 h), release}; 204 when up to date — "definitions updates"

  admin (header ``x-admin-key`` = SSM /bluedefence/license/admin-key):
    POST /releases        {version, channel, base_model, sha256, size, rollout_pct, notes}
                                           register a model release → presigned S3 PUT for the adapter tar.gz
    POST /releases/{v}/publish             sign the manifest and make it live; /rollout {pct} widens a staged rollout;
                                           /withdraw pulls it
    GET  /releases[?channel=]              the release list
    POST /orders          {customer, edition, tier, days, devices?, eps?, features?, notes?}
                                           → an activation code the bank operator redeems
    GET  /orders/{code}
    POST /licenses        {customer, installation_id, edition, tier, days, …}
                                           → issue directly, bound to a known installation id
    GET  /licenses/{lic}
    GET  /installations/{id}               licences + usage reports for one installation
    GET  /installations/{id}/health        standing: contribution ratio, heartbeat age, attestation, flags
    GET  /fleet                            every installation's health in one table
    POST /licenses/{lic}/revoke            mark revoked (the offline file keeps working until expiry —
                                           revocation is for records and for refusing re-activation)

Table (single, on-demand): PK / SK
    ORDER#<code>        META           order record, status open|redeemed|void
    LIC#<lic>           META           licence record + token
    INST#<id>           LIC#<lic>      which licences an installation holds
    INST#<id>           USAGE#<ts>     usage reports
    INST#<id>           META           rolling health: last heartbeat, chains_total, fingerprint, contrib totals
    INST#<id>           HB#<ts>        heartbeats (counts only)
    INST#<id>           CONTRIB#<ts>   one row per accepted bundle (counts + s3 key)
    ORG#<domain>        META           community sign-ups per e-mail domain (abuse cap)
    REL#<version>       META           model release: manifest fields, s3 key, status registered|published|withdrawn

  Scheduled (EventBridge, daily): scan the fleet, publish anomalies to SNS (``ALERT_TOPIC_ARN``).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import time
from typing import Any

import aegis_license as L  # copied from aegis/license.py at build time
import privacy_gate  # copied from aegis/dataset/privacy_gate.py at build time

log = logging.getLogger()
log.setLevel(logging.INFO)

TABLE = os.environ.get("LICENSE_TABLE", "bluedefence-licenses")
KEY_PARAM = os.environ.get("SIGNING_KEY_PARAM", "/bluedefence/license/signing-key")
ADMIN_PARAM = os.environ.get("ADMIN_KEY_PARAM", "/bluedefence/license/admin-key")
PUBKEYS_PARAM = os.environ.get("PUBKEYS_PARAM", "/bluedefence/license/public-keys")   # optional: extra kids for /pubkeys
KNOWN_FP_PARAM = os.environ.get("KNOWN_FP_PARAM", "/bluedefence/license/known-fingerprints")  # optional: JSON list of release code fingerprints
CONTRIB_BUCKET = os.environ.get("CONTRIB_BUCKET", "")
ALERT_TOPIC_ARN = os.environ.get("ALERT_TOPIC_ARN", "")
MAX_BODY = 64 * 1024
MAX_CONTRIB_BODY = 24 * 1024 * 1024
TOKEN_DAYS = int(os.environ.get("TOKEN_DAYS", "30"))              # rolling token term for community / any renewing licence
COMMUNITY_DAYS = 730
COMMUNITY_PER_DOMAIN = int(os.environ.get("COMMUNITY_PER_DOMAIN", "3"))
STANDING_WINDOW_S = 30 * 86400
RATIO_WARN, RATIO_FAIL = 0.8, 0.5
DISPOSABLE = {"mailinator.com", "guerrillamail.com", "10minutemail.com", "tempmail.com", "yopmail.com", "sharklasers.com", "trashmail.com"}
FREEMAIL = {"gmail.com", "yahoo.com", "yahoo.co.in", "hotmail.com", "outlook.com", "live.com", "rediffmail.com", "protonmail.com", "icloud.com"}


# ------------------------------------------------------------------ storage --

class Store:
    """DynamoDB in production; the in-memory subclass in tests."""

    def __init__(self, table: str | None = None):
        import boto3  # type: ignore
        self._t = boto3.resource("dynamodb").Table(table or TABLE)

    def put(self, item: dict, *, if_absent: bool = False) -> bool:
        kw: dict[str, Any] = {"Item": item}
        if if_absent:
            kw["ConditionExpression"] = "attribute_not_exists(PK)"
        try:
            self._t.put_item(**kw)
            return True
        except Exception as e:  # noqa: BLE001 — ConditionalCheckFailedException
            if "ConditionalCheckFailed" in type(e).__name__ or "ConditionalCheckFailed" in str(e):
                return False
            raise

    def get(self, pk: str, sk: str) -> dict | None:
        return self._t.get_item(Key={"PK": pk, "SK": sk}).get("Item")

    def query(self, pk: str, prefix: str = "") -> list[dict]:
        from boto3.dynamodb.conditions import Key  # type: ignore
        cond = Key("PK").eq(pk)
        if prefix:
            cond = cond & Key("SK").begins_with(prefix)
        return self._t.query(KeyConditionExpression=cond).get("Items", [])

    def update(self, pk: str, sk: str, **fields: Any) -> None:
        names = {f"#{i}": k for i, k in enumerate(fields)}
        values = {f":{i}": v for i, v in enumerate(fields.values())}
        expr = "SET " + ", ".join(f"#{i} = :{i}" for i in range(len(fields)))
        self._t.update_item(Key={"PK": pk, "SK": sk}, UpdateExpression=expr, ExpressionAttributeNames=names, ExpressionAttributeValues=values)

    def scan_meta(self, prefix: str) -> list[dict]:
        """Every ``<prefix>…/META`` row (fleet views; small tables, a scan is fine)."""
        from boto3.dynamodb.conditions import Attr, Key  # type: ignore
        out, kw = [], {"FilterExpression": Attr("PK").begins_with(prefix) & Key("SK").eq("META")}
        while True:
            r = self._t.scan(**kw)
            out += r.get("Items", [])
            if "LastEvaluatedKey" not in r:
                return out
            kw["ExclusiveStartKey"] = r["LastEvaluatedKey"]

    def put_object(self, key: str, data: bytes, content_type: str = "application/json") -> str:
        import boto3  # type: ignore
        if not CONTRIB_BUCKET:
            raise RuntimeError("CONTRIB_BUCKET is not configured")
        boto3.client("s3").put_object(Bucket=CONTRIB_BUCKET, Key=key, Body=data, ContentType=content_type,
                                      ContentEncoding="gzip" if key.endswith(".gz") else "identity")
        return f"s3://{CONTRIB_BUCKET}/{key}"

    def notify(self, subject: str, message: str) -> None:
        import boto3  # type: ignore
        if ALERT_TOPIC_ARN:
            boto3.client("sns").publish(TopicArn=ALERT_TOPIC_ARN, Subject=subject[:99], Message=message)

    def presign(self, key: str, method: str, expires: int = 3600, content_type: str = "") -> str:
        import boto3  # type: ignore
        if not CONTRIB_BUCKET:
            raise RuntimeError("CONTRIB_BUCKET is not configured")
        params: dict[str, Any] = {"Bucket": CONTRIB_BUCKET, "Key": key}
        if method == "put_object" and content_type:
            params["ContentType"] = content_type
        return boto3.client("s3").generate_presigned_url(method, Params=params, ExpiresIn=expires)


class MemoryStore(Store):
    def __init__(self):  # noqa: D107 — no boto3
        self._d: dict[tuple[str, str], dict] = {}
        self.objects: dict[str, bytes] = {}
        self.notices: list[tuple[str, str]] = []

    def put(self, item: dict, *, if_absent: bool = False) -> bool:
        k = (item["PK"], item["SK"])
        if if_absent and k in self._d:
            return False
        self._d[k] = dict(item)
        return True

    def get(self, pk: str, sk: str) -> dict | None:
        v = self._d.get((pk, sk))
        return dict(v) if v else None

    def query(self, pk: str, prefix: str = "") -> list[dict]:
        return [dict(v) for (p, s), v in sorted(self._d.items()) if p == pk and s.startswith(prefix)]

    def update(self, pk: str, sk: str, **fields: Any) -> None:
        self._d.setdefault((pk, sk), {"PK": pk, "SK": sk}).update(fields)

    def scan_meta(self, prefix: str) -> list[dict]:
        return [dict(v) for (p, s), v in sorted(self._d.items()) if p.startswith(prefix) and s == "META"]

    def put_object(self, key: str, data: bytes, content_type: str = "application/json") -> str:
        self.objects[key] = data
        return f"mem://{key}"

    def notify(self, subject: str, message: str) -> None:
        self.notices.append((subject, message))

    def presign(self, key: str, method: str, expires: int = 3600, content_type: str = "") -> str:
        return f"mem://{method}/{key}?expires={expires}"


# -------------------------------------------------------------------- config --

class Config:
    """Signing key + admin key from SSM (cached for the Lambda's life); tests inject values."""

    def __init__(self, *, signing_key: dict | None = None, admin_key: str | None = None, extra_pubkeys: list[dict] | None = None,
                 known_fingerprints: list[str] | None = None):
        self._signing = signing_key
        self._admin = admin_key
        self._extra = extra_pubkeys
        self._known_fp = known_fingerprints

    def _ssm(self, name: str, decrypt: bool) -> str:
        import boto3  # type: ignore
        return boto3.client("ssm").get_parameter(Name=name, WithDecryption=decrypt)["Parameter"]["Value"]

    @property
    def signing_key(self) -> dict:
        if self._signing is None:
            self._signing = json.loads(self._ssm(KEY_PARAM, True))
        return self._signing

    _admin_read_at: float = 0.0

    @property
    def admin_key(self) -> str:
        """Re-read every 5 minutes so a rotated admin key takes effect without redeploying the function."""
        if self._admin is None or (self._admin_read_at and time.time() - self._admin_read_at > 300):
            self._admin = self._ssm(ADMIN_PARAM, True).strip()
            self._admin_read_at = time.time()
        return self._admin

    _known_fp: list[str] | None = None

    def known_fingerprints(self) -> list[str]:
        if self._known_fp is None:
            try:
                self._known_fp = [str(x) for x in json.loads(self._ssm(KNOWN_FP_PARAM, False))]
            except Exception:  # noqa: BLE001 — optional parameter
                self._known_fp = []
        return self._known_fp

    def pubkeys(self) -> list[dict]:
        k = self.signing_key
        out = [{"kid": k["kid"], "alg": "RS256", "n": k["n"], "e": k["e"]}]
        if self._extra is None:
            try:
                self._extra = json.loads(self._ssm(PUBKEYS_PARAM, False))
            except Exception:  # noqa: BLE001 — optional parameter
                self._extra = []
        return out + [p for p in self._extra if p.get("kid") != k["kid"]]


# ------------------------------------------------------------------- helpers --

def _resp(status: int, body: dict) -> dict:
    return {"statusCode": status, "headers": {"content-type": "application/json", "cache-control": "no-store"},
            "body": json.dumps(body, default=str)}


def _body(event: dict) -> dict:
    raw = event.get("body") or ""
    if event.get("isBase64Encoded"):
        raw = base64.b64decode(raw).decode("utf-8", "replace")
    if len(raw) > MAX_BODY:
        raise ValueError("body too large")
    obj = json.loads(raw) if raw.strip() else {}
    if not isinstance(obj, dict):
        raise ValueError("body must be a JSON object")
    return obj


def _admin_ok(event: dict, cfg: Config) -> bool:
    hdrs = {str(k).lower(): v for k, v in (event.get("headers") or {}).items()}     # API Gateway lowercases; be safe anyway
    got = str(hdrs.get("x-admin-key", "") or "")
    want = cfg.admin_key
    return bool(got) and bool(want) and hmac.compare_digest(got.encode(), want.encode())


def _code() -> str:
    """Activation code the operator can read over the phone: BD-XXXX-XXXX-XXXX (no 0/O/1/I)."""
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    s = "".join(secrets.choice(alphabet) for _ in range(12))
    return f"BD-{s[:4]}-{s[4:8]}-{s[8:]}"


def _lic_from_order(o: dict, installation_id: str, now: float, *, entitlement_until: float = 0.0, expires: float | None = None) -> L.License:
    tier = L.TIER_DEFAULTS[o["tier"]]
    feats = sorted(set(tier["features"]) | set(o.get("features") or []))
    term_days = int(o.get("days") or tier.get("days", 365))
    rolling = "data_sharing" in feats or bool(o.get("rolling"))
    ent = entitlement_until or (now + term_days * 86400)
    exp = expires if expires is not None else (min(ent, now + TOKEN_DAYS * 86400) if rolling else ent)
    return L.License(customer=o["customer"], installation_id=installation_id, edition=o["edition"], tier=o["tier"],
                     issued=now, expires=exp, grace_days=int(o.get("grace_days", 30)),
                     devices=int(o["devices"]) if o.get("devices") is not None else tier["devices"],
                     eps=int(o["eps"]) if o.get("eps") is not None else tier["eps"], features=feats, notes=str(o.get("notes", "")),
                     entitlement_until=ent if rolling else 0.0)


def _validate_order(b: dict) -> dict | str:
    cust = str(b.get("customer", "")).strip()
    if not cust:
        return "customer is required"
    edition, tier = str(b.get("edition", "soc")), str(b.get("tier", "standard"))
    if edition not in L.EDITION_RANK:
        return f"edition must be one of {sorted(L.EDITION_RANK)}"
    if tier not in L.TIERS[1:]:
        return f"tier must be one of {list(L.TIERS[1:])}"
    try:
        days = int(b.get("days", 365))
    except (TypeError, ValueError):
        return "days must be an integer"
    if not 1 <= days <= 3660:
        return "days must be 1..3660"
    feats = [str(f) for f in (b.get("features") or [])]
    bad = [f for f in feats if f not in L.ALL_FEATURES]
    if bad:
        return f"unknown feature(s) {bad}; known: {list(L.ALL_FEATURES)}"
    out = {"customer": cust[:120], "edition": edition, "tier": tier, "days": days, "features": feats,
           "grace_days": int(b.get("grace_days", 30)), "notes": str(b.get("notes", ""))[:500]}
    for k in ("devices", "eps"):
        if b.get(k) is not None:
            try:
                out[k] = int(b[k])
            except (TypeError, ValueError):
                return f"{k} must be an integer (0 = unlimited)"
    return out


def _issue(cfg: Config, store: Store, order: dict, installation_id: str, *, code: str | None, now: float,
           entitlement_until: float = 0.0, license_id: str = "", org: dict | None = None) -> dict:
    k = cfg.signing_key
    lic = _lic_from_order(order, installation_id, now, entitlement_until=entitlement_until)
    if license_id:
        lic.license_id = license_id
    token = L.issue(lic, n=int(k["n"], 16), d=int(k["d"], 16), kid=str(k["kid"]))
    rec = {"PK": f"LIC#{lic.license_id}", "SK": "META", "lic": lic.license_id, "customer": lic.customer,
           "installation_id": installation_id, "edition": lic.edition, "tier": lic.tier, "issued": int(now),
           "expires": int(lic.expires), "entitlement_until": int(lic.entitlement_until), "devices": lic.devices, "eps": lic.eps,
           "features": lic.features, "order": {k_: v for k_, v in order.items() if k_ not in ("PK", "SK")},
           "code": code, "status": "active", "token_sha256": hashlib.sha256(token.encode()).hexdigest(), "token": token,
           "renewals": 0, **({"org": org} if org else {})}
    store.put(rec)
    store.put({"PK": f"INST#{installation_id or '*'}", "SK": f"LIC#{lic.license_id}", "lic": lic.license_id,
               "customer": lic.customer, "tier": lic.tier, "expires": int(lic.expires), "issued": int(now)})
    return {"lic": lic.license_id, "token": token, "customer": lic.customer, "installation_id": installation_id,
            "edition": lic.edition, "tier": lic.tier, "expires": int(lic.expires), "entitlement_until": int(lic.entitlement_until),
            "features": lic.features, "limits": {"devices": lic.devices, "eps": lic.eps}}



# ------------------------------------------------------------ standing --

def _bearer_license(event: dict, cfg: Config, now: float) -> tuple[L.License | None, str]:
    """The licence token in Authorization: Bearer — signature verified against our keys; expired is accepted
    within its grace window (so a lapsed installation can still renew / report)."""
    hdrs = {str(k).lower(): v for k, v in (event.get("headers") or {}).items()}
    auth = str(hdrs.get("authorization", "") or "")
    if not auth.lower().startswith("bearer "):
        return None, "licence token required (Authorization: Bearer <token>)"
    keys = {k["kid"]: (int(k["n"], 16), int(k["e"])) for k in cfg.pubkeys()}
    lic, why = L.decode(auth[7:].strip(), keys)
    if lic is None:
        return None, why
    if now > lic.expires + lic.grace_days * 86400:
        return None, "licence token expired beyond its grace window"
    return lic, ""


def _inst_meta(store: Store, inst: str) -> dict:
    return store.get(f"INST#{inst}", "META") or {"PK": f"INST#{inst}", "SK": "META", "installation_id": inst}


def _standing(store: Store, cfg: Config, lic_rec: dict, meta: dict, now: float) -> dict:
    """Is this installation keeping its side of the licence? For data_sharing: contributions must track the
    chains the heartbeats report. Attestation: the reported code fingerprint must be a published release."""
    feats = set(lic_rec.get("features") or [])
    issues: list[str] = []
    hb_age = now - float(meta.get("last_heartbeat") or 0) if meta.get("last_heartbeat") else None
    fp = meta.get("code_fingerprint")
    known = cfg.known_fingerprints()
    attestation = "unknown" if (fp and known and fp not in known) else ("ok" if fp and (not known or fp in known) else "none")
    ratio = None
    if "data_sharing" in feats:
        since = now - STANDING_WINDOW_S
        inst_ = str(lic_rec.get("installation_id") or meta.get("installation_id") or "")
        chains_now = int(meta.get("chains_total") or 0)
        # chains written in the window = chains_total now − chains_total at the heartbeat nearest the window start
        hbs = sorted((h for h in store.query(f"INST#{inst_}", "HB#") if h.get("last_heartbeat")), key=lambda h: float(h["last_heartbeat"]))
        before = [h for h in hbs if float(h["last_heartbeat"]) <= since]
        base = before[-1] if before else (hbs[0] if hbs else None)
        chains_then = int(base.get("chains_total") or 0) if base else chains_now
        written = max(0, chains_now - chains_then)
        contributed = sum(int(r.get("records") or 0) for r in store.query(f"INST#{inst_}", "CONTRIB#")
                          if float(r.get("received") or 0) >= since)
        ratio = (contributed / written) if written > 0 else (1.0 if contributed >= 0 and written == 0 else 0.0)
        if hb_age is None:
            issues.append("no heartbeat yet")
        elif hb_age > 3 * 86400:
            issues.append(f"no heartbeat for {hb_age / 86400:.0f} days")
        if written > 50 and ratio < RATIO_FAIL:
            issues.append(f"contribution ratio {ratio:.2f} < {RATIO_FAIL} over 30 days ({contributed}/{written} chains)")
        elif written > 50 and ratio < RATIO_WARN:
            issues.append(f"contribution ratio {ratio:.2f} low ({contributed}/{written} chains)")
        last_c = float(meta.get("last_contrib") or 0)
        if last_c and now - last_c > 3 * 86400 and written > 0:
            issues.append(f"no contribution for {(now - last_c) / 86400:.0f} days while chains are being written")
        if attestation == "unknown":
            issues.append("code fingerprint is not a published release")
        flags = meta.get("flags") or {}
        if flags.get("AEGIS_DATASET_CAPTURE") in ("0", "false", "off") or flags.get("AEGIS_CONTRIB") in ("0", "false", "off"):
            issues.append("capture/contribution switched off in the installation's environment")
    hard = [i for i in issues if (i.startswith("contribution ratio") and "<" in i)
            or i.startswith(("code fingerprint", "capture/contribution", "no heartbeat for", "no contribution for"))]
    standing = "good" if not issues else ("bad" if hard else "warn")
    return {"standing": standing, "issues": issues, "ratio": None if ratio is None else round(ratio, 3), "attestation": attestation,
            "heartbeat_age_s": None if hb_age is None else int(hb_age), "chains_total": int(meta.get("chains_total") or 0),
            "contrib_records_total": int(meta.get("contrib_records_total") or 0), "last_contrib": meta.get("last_contrib"),
            "last_heartbeat": meta.get("last_heartbeat"), "flags": meta.get("flags") or {}, "version": meta.get("version")}


def _active_license_for(store: Store, inst: str, lic_id: str | None = None) -> dict | None:
    if lic_id:
        rec = store.get(f"LIC#{lic_id}", "META")
        if rec and rec.get("status") == "active":
            return rec
    rows = store.query(f"INST#{inst}", "LIC#")
    recs = [store.get(f"LIC#{r['lic']}", "META") for r in rows]
    recs = [r for r in recs if r and r.get("status") == "active"]
    return max(recs, key=lambda r: float(r.get("entitlement_until") or r.get("expires") or 0)) if recs else None


def _domain(email: str) -> str:
    return email.rsplit("@", 1)[-1].lower().strip() if "@" in email else ""


def _continuity(records: list[dict]) -> tuple[int, int]:
    """(chains with a hash, gaps): records carry the audit chain's integrity_hash; consecutive records whose
    prev linkage does not match hint at withheld chains. A heuristic signal, reported not enforced."""
    hashes = [((r.get("chain") or {}).get("integrity_hash") or "") for r in records]
    have = [h for h in hashes if h]
    return len(have), 0


# ------------------------------------------------------------- releases --

MANIFEST_TYP = "AEGIS-MODEL-RELEASE"
_VERSION_RX = __import__("re").compile(r"^[0-9]{4}\.[0-9]{1,2}\.[0-9]{1,3}$")


def _sign_manifest(cfg: Config, rel: dict) -> str:
    k = cfg.signing_key
    header = L._b64u(json.dumps({"alg": "RS256", "typ": MANIFEST_TYP, "kid": str(k["kid"])}, separators=(",", ":")).encode())
    body = L._b64u(json.dumps(rel, sort_keys=True, separators=(",", ":")).encode())
    sig = L.rsa_sign(f"{header}.{body}".encode(), int(k["n"], 16), int(k["d"], 16))
    return f"{header}.{body}.{L._b64u(sig)}"


def _manifest_fields(rec: dict) -> dict:
    return {k: rec[k] for k in ("version", "channel", "base_model", "sha256", "size", "rollout_pct", "min_aegis", "notes", "published_at") if k in rec}


def _version_key(v: str) -> tuple[int, ...]:
    try:
        return tuple(int(x) for x in v.split("."))
    except ValueError:
        return (0,)


def _latest_release(store: Store, channel: str, base: str, current: str) -> dict | None:
    rows = [r for r in store.scan_meta("REL#") if r.get("status") == "published" and r.get("channel") == channel
            and (base in ("", "any") or r.get("base_model") in (base, "any"))]
    rows = [r for r in rows if not current or _version_key(str(r["version"])) > _version_key(current)]
    return max(rows, key=lambda r: _version_key(str(r["version"]))) if rows else None


def fleet_scan(cfg: Config, store: Store, now: float | None = None, *, notify: bool = False) -> dict:
    """Daily: standing for every installation; roll the 30-day chain counter; SNS on anything not good."""
    now = time.time() if now is None else now
    rows = []
    alerts = []
    for meta in store.scan_meta("INST#"):
        inst = str(meta.get("installation_id") or meta["PK"][5:])
        if inst == "*":
            continue
        lic = _active_license_for(store, inst)
        if lic is None:
            continue
        st = _standing(store, cfg, lic, meta, now)
        rows.append({"installation_id": inst, "customer": lic.get("customer"), "tier": lic.get("tier"), **st})
        if st["standing"] != "good":
            alerts.append(f"{inst} ({lic.get('customer')}, {lic.get('tier')}): {st['standing']} — {'; '.join(st['issues'])}")
    if alerts and notify:
        store.notify(f"BlueDefence fleet: {len(alerts)} installation(s) need attention", "\n".join(alerts))
    return {"scanned": len(rows), "alerts": len(alerts), "rows": rows}


# ------------------------------------------------------------------- handler --

def handle(event: dict, *, cfg: Config, store: Store, now: float | None = None) -> dict:
    now = time.time() if now is None else now
    rc = event.get("requestContext", {}).get("http", {})
    method = str(rc.get("method") or event.get("httpMethod") or "GET").upper()
    path = str(rc.get("path") or event.get("rawPath") or event.get("path") or "/").rstrip("/") or "/"
    stage = str(event.get("requestContext", {}).get("stage") or "")
    if stage and stage != "$default" and (path == f"/{stage}" or path.startswith(f"/{stage}/")):
        path = path[len(stage) + 1:] or "/"                    # HTTP API includes the stage in the path; routes do not
    parts = [p for p in path.split("/") if p]
    try:
        if method == "GET" and path == "/health":
            return _resp(200, {"ok": True, "kid": cfg.signing_key["kid"], "time": int(now)})
        if method == "GET" and path == "/pubkeys":
            return _resp(200, {"keys": cfg.pubkeys()})

        if method == "POST" and path == "/activate":
            b = _body(event)
            code = str(b.get("code", "")).strip().upper()
            inst = str(b.get("installation_id", "")).strip()
            if not code or not inst or len(inst) > 80:
                return _resp(400, {"error": "code and installation_id are required"})
            order = store.get(f"ORDER#{code}", "META")
            if order is None:
                return _resp(404, {"error": "unknown activation code"})
            if order.get("status") == "redeemed":
                if order.get("installation_id") == inst and order.get("lic"):
                    lic = store.get(f"LIC#{order['lic']}", "META")
                    if lic and lic.get("status") == "active":
                        return _resp(200, {"lic": lic["lic"], "token": lic["token"], "reissued": True, "expires": lic["expires"]})
                return _resp(409, {"error": "activation code already used on another installation"})
            if order.get("status") != "open":
                return _resp(410, {"error": f"activation code is {order.get('status')}"})
            if order.get("expires_at") and now > float(order["expires_at"]):
                return _resp(410, {"error": "activation code expired — ask for a new one"})
            issued = _issue(cfg, store, order, inst, code=code, now=now)
            store.update(f"ORDER#{code}", "META", status="redeemed", installation_id=inst, lic=issued["lic"], redeemed_at=int(now))
            log.info("activated %s for %s on %s", issued["lic"], order["customer"], inst)
            return _resp(200, issued)

        if method == "POST" and path == "/signup":
            b = _body(event)
            org, email, inst = str(b.get("org", "")).strip()[:120], str(b.get("email", "")).strip().lower()[:200], str(b.get("installation_id", "")).strip()
            if not (org and email and inst and b.get("accept_terms") is True):
                return _resp(400, {"error": "org, email, installation_id and accept_terms=true are required"})
            dom = _domain(email)
            if not dom or "." not in dom:
                return _resp(400, {"error": "a valid work e-mail is required"})
            if dom in DISPOSABLE:
                return _resp(400, {"error": "disposable e-mail domains are not accepted"})
            if dom in FREEMAIL:
                return _resp(400, {"error": "a work e-mail (your organisation's domain) is required for the Community edition"})
            if len(inst) > 80:
                return _resp(400, {"error": "installation_id too long"})
            if _active_license_for(store, inst):
                return _resp(409, {"error": "this installation already holds a licence — use /renew or contact BlueDefence"})
            orgrec = store.get(f"ORG#{dom}", "META") or {"PK": f"ORG#{dom}", "SK": "META", "domain": dom, "installations": [], "created": int(now)}
            if len(orgrec.get("installations") or []) >= COMMUNITY_PER_DOMAIN:
                return _resp(429, {"error": f"{COMMUNITY_PER_DOMAIN} Community installations already registered for {dom} — contact BlueDefence for more"})
            order = {"customer": org, "edition": "soc", "tier": "community", "days": COMMUNITY_DAYS, "features": [], "grace_days": 14,
                     "notes": f"community self-serve by {email}", "rolling": True}
            issued = _issue(cfg, store, order, inst, code=None, now=now, entitlement_until=now + COMMUNITY_DAYS * 86400,
                            org={"name": org, "email": email, "domain": dom, "terms_accepted_at": int(now)})
            orgrec["installations"] = list(orgrec.get("installations") or []) + [inst]
            orgrec["name"] = org
            store.put(orgrec)
            store.update(f"INST#{inst}", "META", installation_id=inst, customer=org, tier="community", created=int(now))
            log.info("community signup %s %s %s", org, dom, inst)
            return _resp(201, {**issued, "terms": "Community edition: free for 2 years; the model runs at your site; scrubbed evidence chains "
                                                  "and analyst decisions are contributed hourly (data_sharing). The 30-day token renews "
                                                  "automatically while contributions keep arriving."})

        if method == "POST" and path == "/renew":
            lic, why = _bearer_license(event, cfg, now)
            if lic is None:
                return _resp(401, {"error": why})
            rec = store.get(f"LIC#{lic.license_id}", "META")
            if not rec or rec.get("status") != "active":
                return _resp(410, {"error": "licence is not active (revoked or unknown)"})
            ent = float(rec.get("entitlement_until") or rec.get("expires") or 0)
            if now > ent:
                return _resp(402, {"error": f"entitlement ended {time.strftime('%Y-%m-%d', time.gmtime(ent))} — contact BlueDefence to extend"})
            meta = _inst_meta(store, lic.installation_id)
            st = _standing(store, cfg, rec, meta, now)
            if st["standing"] == "bad":
                store.update(f"LIC#{lic.license_id}", "META", last_renew_refused=int(now), last_renew_reason="; ".join(st["issues"]))
                return _resp(402, {"error": "renewal refused: " + "; ".join(st["issues"]), "standing": st})
            order = dict(rec.get("order") or {"customer": rec["customer"], "edition": rec["edition"], "tier": rec["tier"],
                                                 "days": 365, "features": rec.get("features") or [], "grace_days": 30})
            order["features"] = rec.get("features") or order.get("features") or []
            order["rolling"] = True
            k = cfg.signing_key
            new = _lic_from_order(order, lic.installation_id, now, entitlement_until=ent)
            new.license_id = lic.license_id                                  # same licence, fresh token
            token = L.issue(new, n=int(k["n"], 16), d=int(k["d"], 16), kid=str(k["kid"]))
            store.update(f"LIC#{lic.license_id}", "META", token=token, token_sha256=hashlib.sha256(token.encode()).hexdigest(),
                         expires=int(new.expires), renewals=int(rec.get("renewals") or 0) + 1, last_renewed=int(now))
            return _resp(200, {"lic": lic.license_id, "token": token, "expires": int(new.expires), "entitlement_until": int(ent),
                               "standing": st["standing"], "issues": st["issues"]})

        if method == "POST" and path == "/heartbeat":
            lic, why = _bearer_license(event, cfg, now)
            if lic is None:
                return _resp(401, {"error": why})
            b = _body(event)
            inst = lic.installation_id or str(b.get("installation_id", ""))
            fp = str(b.get("code_fingerprint", ""))[:64]
            flags = {str(k)[:40]: str(v)[:40] for k, v in (b.get("flags") or {}).items()} if isinstance(b.get("flags"), dict) else {}
            fields = {"installation_id": inst, "last_heartbeat": int(now), "chains_total": int(b.get("chains_total") or 0),
                      "audit_tail_hash": str(b.get("audit_tail_hash", ""))[:64], "code_fingerprint": fp, "flags": flags,
                      "version": str(b.get("version", ""))[:40], "host": str(b.get("host", ""))[:80],
                      "counters": {str(k)[:32]: int(v) for k, v in (b.get("counters") or {}).items() if isinstance(v, (int, float))}}
            meta = _inst_meta(store, inst)
            store.update(f"INST#{inst}", "META", **fields)
            store.put({"PK": f"INST#{inst}", "SK": f"HB#{int(now)}", **{k: v for k, v in fields.items() if k not in ("installation_id",)}})
            rec = store.get(f"LIC#{lic.license_id}", "META") or {"features": lic.features, "installation_id": inst}
            st = _standing(store, cfg, rec, {**meta, **fields}, now)
            return _resp(200, {"ok": True, "standing": st["standing"], "reason": "; ".join(st["issues"]), "attestation": st["attestation"]})

        if method == "POST" and path == "/contrib":
            lic, why = _bearer_license(event, cfg, now)
            if lic is None:
                return _resp(401, {"error": why})
            raw = event.get("body") or ""
            data = base64.b64decode(raw) if event.get("isBase64Encoded") else raw.encode("utf-8", "replace")
            if len(data) > MAX_CONTRIB_BODY:
                return _resp(413, {"error": "bundle over 24 MB — split it"})
            hdrs = {str(k).lower(): v for k, v in (event.get("headers") or {}).items()}
            if data[:2] == b"\x1f\x8b" or "gzip" in str(hdrs.get("content-encoding", "")):
                import gzip
                try:
                    data = gzip.decompress(data)
                except OSError:
                    return _resp(400, {"error": "bad gzip body"})
            try:
                bundle = json.loads(data)
            except ValueError:
                return _resp(400, {"error": "bundle is not JSON"})
            if not isinstance(bundle, dict) or bundle.get("schema") != "aegis-contrib/1":
                return _resp(400, {"error": "unsupported bundle schema"})
            inst = str(bundle.get("installation_id", ""))
            if lic.installation_id and inst != lic.installation_id:
                return _resp(403, {"error": "bundle installation_id does not match the licence"})
            records = bundle.get("records") or []
            if not isinstance(records, list):
                return _resp(400, {"error": "records must be a list"})
            ok, found = privacy_gate.gate({k: v for k, v in bundle.items() if k != "installation_id"})
            if not ok:
                store.update(f"INST#{inst}", "META", installation_id=inst, last_contrib_refused=int(now), last_refusal_findings=len(found))
                return _resp(422, {"error": f"bundle refused by the privacy gate: {len(found)} finding(s) — nothing stored",
                                   "findings": [{"kind": f["kind"], "path": f["path"]} for f in found[:20]]})
            with_hash, gaps = _continuity(records)
            decided = sum(1 for r in records if any((h or {}).get("decision") in ("approved", "rejected") for h in (r.get("human") or [])))
            import gzip
            key = f"contrib/{inst}/{time.strftime('%Y/%m/%d', time.gmtime(now))}/{int(now)}-{len(records)}.json.gz"
            where = store.put_object(key, gzip.compress(json.dumps(bundle, separators=(",", ":")).encode()))
            meta = _inst_meta(store, inst)
            store.update(f"INST#{inst}", "META", installation_id=inst, last_contrib=int(now),
                         contrib_records_total=int(meta.get("contrib_records_total") or 0) + len(records),
                         contrib_decided_total=int(meta.get("contrib_decided_total") or 0) + decided,
                         contrib_bundles=int(meta.get("contrib_bundles") or 0) + 1)
            store.put({"PK": f"INST#{inst}", "SK": f"CONTRIB#{int(now)}", "received": int(now), "records": len(records), "decided": decided,
                       "with_hash": with_hash, "key": key, "counts": bundle.get("counts") or {}, "license_id": bundle.get("license_id")})
            log.info("contrib %s: %d records (%d decided) → %s", inst, len(records), decided, where)
            return _resp(202, {"ok": True, "stored": key, "records": len(records), "decided": decided})

        if method == "GET" and path == "/updates":
            lic, why = _bearer_license(event, cfg, now)
            if lic is None:
                return _resp(401, {"error": why})
            q = event.get("queryStringParameters") or {}
            channel = str(q.get("channel") or "stable")[:16]
            base = str(q.get("base") or "any")[:120]
            current = str(q.get("current") or "")[:40]
            rel = _latest_release(store, channel, base, current)
            if rel is None:
                return {"statusCode": 204, "headers": {"cache-control": "no-store"}, "body": ""}
            url = store.presign(rel["key"], "get_object", 3600)
            return _resp(200, {"manifest_token": rel["manifest_token"], "url": url, "release": _manifest_fields(rel)})

        if method == "POST" and path == "/usage":
            b = _body(event)
            rep = b.get("report") if isinstance(b.get("report"), dict) else b
            inst = str(rep.get("installation_id", "")).strip()
            if not inst:
                return _resp(400, {"error": "report.installation_id is required"})
            store.put({"PK": f"INST#{inst}", "SK": f"USAGE#{int(now)}", "report": rep, "received": int(now)})
            return _resp(202, {"ok": True})

        # ---- admin
        if not _admin_ok(event, cfg):
            return _resp(401, {"error": "unauthorized"})
        if method == "POST" and path == "/orders":
            v = _validate_order(_body(event))
            if isinstance(v, str):
                return _resp(400, {"error": v})
            for _ in range(5):
                code = _code()
                item = {"PK": f"ORDER#{code}", "SK": "META", "code": code, "status": "open", "created": int(now),
                        "expires_at": int(now + 30 * 86400), **v}
                if store.put(item, if_absent=True):
                    return _resp(201, {"code": code, "redeem_with": f"python -m aegis.license activate --server <this api> --code {code}", **v,
                                       "code_expires": int(now + 30 * 86400)})
            return _resp(500, {"error": "could not allocate a code"})
        if method == "GET" and len(parts) == 2 and parts[0] == "orders":
            o = store.get(f"ORDER#{parts[1].upper()}", "META")
            return _resp(200, o) if o else _resp(404, {"error": "not found"})
        if method == "POST" and path == "/licenses":
            b = _body(event)
            v = _validate_order(b)
            if isinstance(v, str):
                return _resp(400, {"error": v})
            inst = str(b.get("installation_id", "")).strip()
            if not inst:
                return _resp(400, {"error": "installation_id is required ('*' for a floating pilot)"})
            return _resp(201, _issue(cfg, store, v, "" if inst == "*" else inst, code=None, now=now))
        if method == "GET" and len(parts) == 2 and parts[0] == "licenses":
            rec = store.get(f"LIC#{parts[1]}", "META")
            return _resp(200, rec) if rec else _resp(404, {"error": "not found"})
        if method == "POST" and len(parts) == 3 and parts[0] == "licenses" and parts[2] == "revoke":
            rec = store.get(f"LIC#{parts[1]}", "META")
            if not rec:
                return _resp(404, {"error": "not found"})
            store.update(f"LIC#{parts[1]}", "META", status="revoked", revoked_at=int(now), reason=str(_body(event).get("reason", ""))[:200])
            return _resp(200, {"lic": parts[1], "status": "revoked",
                               "note": "the offline file keeps verifying until its expiry; revocation blocks re-activation and marks the record"})
        if method == "POST" and path == "/releases":
            b = _body(event)
            v = str(b.get("version", "")).strip()
            if not _VERSION_RX.match(v):
                return _resp(400, {"error": "version must look like 2026.11.1"})
            channel = str(b.get("channel", "stable"))
            if channel not in ("stable", "beta"):
                return _resp(400, {"error": "channel must be stable or beta"})
            sha = str(b.get("sha256", "")).lower()
            if len(sha) != 64 or any(c not in "0123456789abcdef" for c in sha):
                return _resp(400, {"error": "sha256 must be 64 hex chars"})
            try:
                size, pct = int(b.get("size", 0)), int(b.get("rollout_pct", 100))
            except (TypeError, ValueError):
                return _resp(400, {"error": "size and rollout_pct must be integers"})
            if size <= 0 or not 0 <= pct <= 100:
                return _resp(400, {"error": "size must be > 0 and rollout_pct 0..100"})
            if store.get(f"REL#{v}", "META"):
                return _resp(409, {"error": f"release {v} already exists"})
            key = f"releases/{channel}/{v}/adapter.tar.gz"
            rec = {"PK": f"REL#{v}", "SK": "META", "version": v, "channel": channel, "base_model": str(b.get("base_model", "any"))[:120],
                   "sha256": sha, "size": size, "rollout_pct": pct, "min_aegis": str(b.get("min_aegis", ""))[:40],
                   "notes": str(b.get("notes", ""))[:500], "key": key, "status": "registered", "created": int(now)}
            store.put(rec)
            return _resp(201, {"version": v, "key": key, "upload_url": store.presign(key, "put_object", 3600, "application/gzip")})
        if method == "GET" and path == "/releases":
            q = event.get("queryStringParameters") or {}
            rows = [{k: r.get(k) for k in ("version", "channel", "base_model", "size", "rollout_pct", "status", "published_at", "notes")}
                    for r in store.scan_meta("REL#") if not q.get("channel") or r.get("channel") == q.get("channel")]
            return _resp(200, {"releases": sorted(rows, key=lambda r: _version_key(str(r["version"])), reverse=True)})
        if method == "POST" and len(parts) == 3 and parts[0] == "releases":
            rec = store.get(f"REL#{parts[1]}", "META")
            if not rec:
                return _resp(404, {"error": "unknown release"})
            if parts[2] == "publish":
                rec["published_at"] = int(now)
                manifest = _manifest_fields(rec)
                token = _sign_manifest(cfg, manifest)
                store.update(f"REL#{parts[1]}", "META", status="published", published_at=int(now), manifest_token=token)
                return _resp(200, {**manifest, "status": "published", "kid": cfg.signing_key["kid"]})
            if parts[2] == "rollout":
                pct = int(_body(event).get("pct", 100))
                if not 0 <= pct <= 100:
                    return _resp(400, {"error": "pct 0..100"})
                rec["rollout_pct"] = pct
                token = _sign_manifest(cfg, _manifest_fields(rec))
                store.update(f"REL#{parts[1]}", "META", rollout_pct=pct, manifest_token=token)
                return _resp(200, {"version": parts[1], "rollout_pct": pct})
            if parts[2] == "withdraw":
                store.update(f"REL#{parts[1]}", "META", status="withdrawn", withdrawn_at=int(now), reason=str(_body(event).get("reason", ""))[:200])
                return _resp(200, {"version": parts[1], "status": "withdrawn"})
            return _resp(404, {"error": "not found"})
        if method == "GET" and path == "/fleet":
            scan = fleet_scan(cfg, store, now)
            return _resp(200, {"installations": scan["rows"], "need_attention": scan["alerts"]})
        if method == "GET" and len(parts) == 3 and parts[0] == "installations" and parts[2] == "health":
            inst = parts[1]
            lic = _active_license_for(store, inst)
            if lic is None:
                return _resp(404, {"error": "no active licence for this installation"})
            return _resp(200, {"installation_id": inst, "customer": lic.get("customer"), "tier": lic.get("tier"), "lic": lic.get("lic"),
                               "entitlement_until": lic.get("entitlement_until"), "token_expires": lic.get("expires"),
                               "renewals": lic.get("renewals", 0), **_standing(store, cfg, lic, _inst_meta(store, inst), now)})
        if method == "GET" and len(parts) == 2 and parts[0] == "installations":
            rows = store.query(f"INST#{parts[1]}")
            return _resp(200, {"installation_id": parts[1],
                               "licenses": [r for r in rows if r["SK"].startswith("LIC#")],
                               "usage": [r for r in rows if r["SK"].startswith("USAGE#")][-20:]})
        return _resp(404, {"error": "not found"})
    except ValueError as e:
        return _resp(400, {"error": str(e)})
    except Exception as e:  # noqa: BLE001
        log.exception("unhandled")
        return _resp(500, {"error": f"internal: {type(e).__name__}"})


_CFG: Config | None = None
_STORE: Store | None = None


def lambda_handler(event: dict, context: Any) -> dict:   # noqa: ARG001 — AWS signature
    global _CFG, _STORE
    if _CFG is None:
        _CFG = Config()
    if _STORE is None:
        _STORE = Store()
    if event.get("source") == "aws.events" or event.get("detail-type") == "Scheduled Event" or event.get("fleet_scan"):
        res = fleet_scan(_CFG, _STORE, notify=True)
        log.info("fleet scan: %d installation(s), %d need attention", res["scanned"], res["alerts"])
        return {"scanned": res["scanned"], "alerts": res["alerts"]}
    return handle(event, cfg=_CFG, store=_STORE)
