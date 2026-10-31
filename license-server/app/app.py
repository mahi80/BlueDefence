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

  bearer = the installation's licence token (signature verified, status active; an expired token is accepted
  within its grace window so a lapsed installation can still renew / report):
    POST /renew                            roll the token: a fresh 30-day token while the installation is in
                                           good standing — for data_sharing, while contributions keep arriving
    POST /heartbeat       {counts, hashes} daily: chains_total, audit_tail_hash, code_fingerprint, flags, counters
    POST /contrib         gzip bundle      scrubbed chains + analyst decisions → privacy gate → S3
                                           contrib/<inst>/<date>/<ts>-<n>.json.gz; counts recorded
    POST /usage           {report}         a `python -m aegis.license report` snapshot (counts only)
    GET  /updates?channel=&base=&current=  the newest published model release for this installation's channel/base
                                           beyond ``current`` → {manifest_token (signed), url (presigned S3 GET, 1 h),
                                           release}; 204 when up to date — "definitions updates"

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
                                           → issue directly, bound to a known installation id ('*' = floating pilot)
    GET  /licenses/{lic}
    GET  /installations/{id}               licences + usage reports for one installation
    GET  /installations/{id}/health        standing: contribution ratio, heartbeat age, attestation, flags
    GET  /fleet                            every installation's health in one table
    POST /licenses/{lic}/revoke            revoke: bearer routes refuse the token at once (no renewals, no model
                                           updates, no contributions); the offline file verifies until its expiry

Table (single, on-demand, TTL attribute ``ttl``): PK / SK
    ORDER#<code>        META           order record, status open|redeemed|void
    LIC#<lic>           META           licence record + token
    INST#<id>           META           rolling health: last heartbeat, chains_total, fingerprint, contrib totals
    INST#<id>           LIC#<lic>      which licences an installation holds
    INST#<id>           HB#<ts>        heartbeats (counts only; ttl 400 d)
    INST#<id>           CONTRIB#<ts>   one row per accepted bundle (counts + s3 key; ttl 400 d)
    INST#<id>           USAGE#<ts>     usage reports (ttl 400 d)
    FLEET               INST#<id>      pointer row per installation (the fleet view is a query, never a scan)
    ORG#<domain>        META           community sign-ups per registrable e-mail domain (abuse cap)
    RELEASES            REL#<version>  model release: manifest fields, s3 key, status registered|published|withdrawn

  Scheduled (EventBridge, daily): scan the fleet, publish anomalies to SNS (``ALERT_TOPIC_ARN``).

DynamoDB types: the resource API returns ``Decimal`` and refuses ``float``. Every read goes through ``_from_ddb``
(integral Decimal → int, else float) and every write through ``_to_ddb`` (float → Decimal), so the handler
code and the signed manifests only ever see plain ints/floats. Tests run the same conversions.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import time
import zlib
from decimal import Decimal
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
MAX_USAGE_BODY = 8 * 1024
MAX_CONTRIB_BODY = 6 * 1024 * 1024          # the Lambda sync-invoke ceiling; HTTP API itself stops at 10 MB
MAX_CONTRIB_INFLATED = 64 * 1024 * 1024     # bounded gzip inflation (a 6 MB bomb inflates to ~6 GB otherwise)
MAX_CONTRIB_RECORDS = 5000
TOKEN_DAYS = int(os.environ.get("TOKEN_DAYS", "30"))              # rolling token term for community / any renewing licence
COMMUNITY_DAYS = 730
COMMUNITY_PER_DOMAIN = int(os.environ.get("COMMUNITY_PER_DOMAIN", "3"))
STANDING_WINDOW_S = 30 * 86400
STANDING_GRACE_S = 7 * 86400                # a new installation has a week to start heartbeating / contributing
ROW_TTL_S = 400 * 86400
RATIO_WARN, RATIO_FAIL = 0.8, 0.5
DISPOSABLE = {"mailinator.com", "guerrillamail.com", "10minutemail.com", "tempmail.com", "yopmail.com", "sharklasers.com", "trashmail.com",
              "temp-mail.org", "dispostable.com", "getnada.com", "maildrop.cc", "fakeinbox.com", "throwawaymail.com"}
FREEMAIL = {"gmail.com", "googlemail.com", "yahoo.com", "yahoo.co.in", "yahoo.in", "ymail.com", "hotmail.com", "hotmail.co.uk", "hotmail.co.in",
            "outlook.com", "outlook.in", "live.com", "live.in", "msn.com", "rediffmail.com", "rediff.com", "protonmail.com", "proton.me",
            "pm.me", "icloud.com", "me.com", "mac.com", "aol.com", "zoho.com", "zohomail.in", "gmx.com", "gmx.net", "mail.com", "yandex.com",
            "yandex.ru", "fastmail.com", "tutanota.com", "tuta.io", "hey.com", "sify.com", "indiatimes.com"}
# second-level suffixes under which the registrable domain is three labels (sbi.co.in → co.in is not an org)
_SLD = {"co", "com", "org", "net", "ac", "gov", "edu", "nic", "res", "firm", "gen", "ind", "ltd", "plc", "me"}

_INST_RX = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$")
_CODE_RX = re.compile(r"^BD-[A-Z2-9]{4}-[A-Z2-9]{4}-[A-Z2-9]{4}$")
_VERSION_RX = re.compile(r"^[0-9]{4}\.[0-9]{1,2}\.[0-9]{1,3}$")
_HEX_RX = re.compile(r"^[0-9a-f]{64}$")
MANIFEST_TYP = "AEGIS-MODEL-RELEASE"


# ------------------------------------------------------------------ dynamo types --

def _from_ddb(obj: Any) -> Any:
    """Decimal → int when integral else float, recursively. Applied to everything read from DynamoDB."""
    if isinstance(obj, Decimal):
        return int(obj) if obj == obj.to_integral_value() else float(obj)
    if isinstance(obj, dict):
        return {k: _from_ddb(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_from_ddb(v) for v in obj]
    if isinstance(obj, set):
        return {_from_ddb(v) for v in obj}
    return obj


def _to_ddb(obj: Any) -> Any:
    """float → Decimal (DynamoDB refuses float), recursively. Applied to everything written."""
    if isinstance(obj, bool):
        return obj
    if isinstance(obj, float):
        return Decimal(str(obj))
    if isinstance(obj, dict):
        return {k: _to_ddb(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_to_ddb(v) for v in obj]
    return obj


def _valid_inst(inst: str) -> bool:
    return bool(_INST_RX.match(inst)) and ".." not in inst


# ------------------------------------------------------------------ storage --

class Store:
    """DynamoDB in production; the in-memory subclasses in tests share the exact same conversions."""

    def __init__(self, table: str | None = None):
        import boto3  # type: ignore
        self._t = boto3.resource("dynamodb").Table(table or TABLE)

    def put(self, item: dict, *, if_absent: bool = False) -> bool:
        kw: dict[str, Any] = {"Item": _to_ddb(item)}
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
        item = self._t.get_item(Key={"PK": pk, "SK": sk}).get("Item")
        return _from_ddb(item) if item else None

    def query(self, pk: str, prefix: str = "", *, sk_from: str | None = None) -> list[dict]:
        """All rows (paginated) with ``SK`` under ``prefix``; ``sk_from`` bounds the range from below
        (``HB#<ts>`` rows sort by timestamp, so the 30-day window is a key range, not a full read)."""
        from boto3.dynamodb.conditions import Key  # type: ignore
        cond = Key("PK").eq(pk)
        if sk_from is not None and prefix:
            cond = cond & Key("SK").between(sk_from, prefix + "~")
        elif prefix:
            cond = cond & Key("SK").begins_with(prefix)
        out, kw = [], {"KeyConditionExpression": cond}
        while True:
            r = self._t.query(**kw)
            out += r.get("Items", [])
            if "LastEvaluatedKey" not in r:
                return _from_ddb(out)
            kw["ExclusiveStartKey"] = r["LastEvaluatedKey"]

    def update(self, pk: str, sk: str, **fields: Any) -> None:
        names = {f"#{i}": k for i, k in enumerate(fields)}
        values = {f":{i}": _to_ddb(v) for i, v in enumerate(fields.values())}
        expr = "SET " + ", ".join(f"#{i} = :{i}" for i in range(len(fields)))
        self._t.update_item(Key={"PK": pk, "SK": sk}, UpdateExpression=expr, ExpressionAttributeNames=names, ExpressionAttributeValues=values)

    def update_if(self, pk: str, sk: str, cond_field: str, expected: Any, **fields: Any) -> bool:
        """``SET …`` only when ``cond_field == expected`` — the one-redemption guarantee for activation codes."""
        names = {f"#{i}": k for i, k in enumerate(fields)}
        names["#c"] = cond_field
        values = {f":{i}": _to_ddb(v) for i, v in enumerate(fields.values())}
        values[":c"] = _to_ddb(expected)
        expr = "SET " + ", ".join(f"#{i} = :{i}" for i in range(len(fields)))
        try:
            self._t.update_item(Key={"PK": pk, "SK": sk}, UpdateExpression=expr, ConditionExpression="#c = :c",
                                ExpressionAttributeNames=names, ExpressionAttributeValues=values)
            return True
        except Exception as e:  # noqa: BLE001
            if "ConditionalCheckFailed" in type(e).__name__ or "ConditionalCheckFailed" in str(e):
                return False
            raise

    def scan_meta(self, prefix: str) -> list[dict]:
        """Full-table scan for ``PK begins_with prefix`` + ``SK = META``. Only the one-off ``/admin/migrate`` uses it."""
        from boto3.dynamodb.conditions import Attr  # type: ignore
        out, kw = [], {"FilterExpression": Attr("PK").begins_with(prefix) & Attr("SK").eq("META")}
        while True:
            r = self._t.scan(**kw)
            out += r.get("Items", [])
            if "LastEvaluatedKey" not in r:
                return _from_ddb(out)
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
    """In-memory store that round-trips every item through the DynamoDB type conversions, so a float
    that would be refused or a Decimal that would break JSON shows up in tests exactly as in production."""

    def __init__(self):  # noqa: D107 — no boto3
        self._d: dict[tuple[str, str], dict] = {}
        self.objects: dict[str, bytes] = {}
        self.notices: list[tuple[str, str]] = []

    @staticmethod
    def _roundtrip(item: dict) -> dict:
        try:
            from boto3.dynamodb.types import TypeDeserializer, TypeSerializer  # type: ignore
            ser, de = TypeSerializer(), TypeDeserializer()
            return {k: de.deserialize(ser.serialize(v)) for k, v in _to_ddb(item).items()}   # raises on float, like prod
        except ImportError:
            return _to_ddb(item)

    def put(self, item: dict, *, if_absent: bool = False) -> bool:
        k = (item["PK"], item["SK"])
        if if_absent and k in self._d:
            return False
        self._d[k] = self._roundtrip(item)
        return True

    def get(self, pk: str, sk: str) -> dict | None:
        v = self._d.get((pk, sk))
        return _from_ddb(dict(v)) if v else None

    def query(self, pk: str, prefix: str = "", *, sk_from: str | None = None) -> list[dict]:
        rows = [dict(v) for (p, s), v in sorted(self._d.items()) if p == pk and s.startswith(prefix) and (sk_from is None or s >= sk_from)]
        return _from_ddb(rows)

    def update(self, pk: str, sk: str, **fields: Any) -> None:
        cur = self._d.setdefault((pk, sk), {"PK": pk, "SK": sk})
        cur.update(self._roundtrip(fields))

    def update_if(self, pk: str, sk: str, cond_field: str, expected: Any, **fields: Any) -> bool:
        cur = self._d.get((pk, sk))
        if cur is None or _from_ddb(cur.get(cond_field)) != expected:
            return False
        cur.update(self._roundtrip(fields))
        return True

    def scan_meta(self, prefix: str) -> list[dict]:
        return _from_ddb([dict(v) for (p, s), v in sorted(self._d.items()) if p.startswith(prefix) and s == "META"])

    def put_object(self, key: str, data: bytes, content_type: str = "application/json") -> str:
        self.objects[key] = data
        return f"mem://{key}"

    def notify(self, subject: str, message: str) -> None:
        self.notices.append((subject, message))

    def presign(self, key: str, method: str, expires: int = 3600, content_type: str = "") -> str:
        return f"mem://{method}/{key}?expires={expires}"


# -------------------------------------------------------------------- config --

class Config:
    """Signing key from SSM (cached for the Lambda's life); admin key, extra public keys and known fingerprints
    re-read every 5 minutes so rotation and new releases take effect without a cold start. Tests inject values."""

    TTL_S = 300

    def __init__(self, *, signing_key: dict | None = None, admin_key: str | None = None, extra_pubkeys: list[dict] | None = None,
                 known_fingerprints: list[str] | None = None):
        self._signing = signing_key
        self._admin = admin_key
        self._extra = extra_pubkeys
        self._known_fp = known_fingerprints
        self._injected = {"admin": admin_key is not None, "extra": extra_pubkeys is not None, "fp": known_fingerprints is not None}
        self._read_at: dict[str, float] = {}

    def _ssm(self, name: str, decrypt: bool) -> str:
        import boto3  # type: ignore
        return boto3.client("ssm").get_parameter(Name=name, WithDecryption=decrypt)["Parameter"]["Value"]

    def _stale(self, what: str) -> bool:
        return not self._injected[what] and time.time() - self._read_at.get(what, 0.0) > self.TTL_S

    @property
    def signing_key(self) -> dict:
        if self._signing is None:
            self._signing = json.loads(self._ssm(KEY_PARAM, True))
        return self._signing

    @property
    def admin_key(self) -> str:
        if self._admin is None or self._stale("admin"):
            self._admin = self._ssm(ADMIN_PARAM, True).strip()
            self._read_at["admin"] = time.time()
        return self._admin

    def known_fingerprints(self) -> list[str]:
        if self._known_fp is None or self._stale("fp"):
            try:
                self._known_fp = [str(x) for x in json.loads(self._ssm(KNOWN_FP_PARAM, False))]
            except Exception:  # noqa: BLE001 — optional parameter
                self._known_fp = []
            self._read_at["fp"] = time.time()
        return self._known_fp

    def pubkeys(self) -> list[dict]:
        k = self.signing_key
        out = [{"kid": k["kid"], "alg": "RS256", "n": k["n"], "e": k["e"]}]
        if self._extra is None or self._stale("extra"):
            try:
                self._extra = json.loads(self._ssm(PUBKEYS_PARAM, False))
            except Exception:  # noqa: BLE001 — optional parameter
                self._extra = []
            self._read_at["extra"] = time.time()
        return out + [p for p in self._extra if p.get("kid") != k["kid"]]


# ------------------------------------------------------------------- helpers --

def _json_default(o: Any) -> Any:
    if isinstance(o, Decimal):
        return int(o) if o == o.to_integral_value() else float(o)
    return str(o)


def _resp(status: int, body: dict) -> dict:
    return {"statusCode": status, "headers": {"content-type": "application/json", "cache-control": "no-store"},
            "body": json.dumps(body, default=_json_default)}


def _headers(event: dict) -> dict[str, str]:
    return {str(k).lower(): str(v) for k, v in (event.get("headers") or {}).items()}


def _body(event: dict, limit: int = MAX_BODY) -> dict:
    raw = event.get("body") or ""
    if event.get("isBase64Encoded"):
        raw = base64.b64decode(raw).decode("utf-8", "replace")
    if len(raw) > limit:
        raise ValueError(f"body over {limit} bytes")
    obj = json.loads(raw) if raw.strip() else {}
    if not isinstance(obj, dict):
        raise ValueError("body must be a JSON object")
    return obj


def _admin_ok(event: dict, cfg: Config) -> bool:
    got = _headers(event).get("x-admin-key", "")
    want = cfg.admin_key
    return bool(got) and bool(want) and hmac.compare_digest(got.encode(), want.encode())


def _code() -> str:
    """Activation code the operator can read over the phone: BD-XXXX-XXXX-XXXX (no 0/O/1/I)."""
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    s = "".join(secrets.choice(alphabet) for _ in range(12))
    return f"BD-{s[:4]}-{s[4:8]}-{s[8:]}"


def _int(v: Any, default: int = 0, lo: int = -(1 << 53), hi: int = 1 << 53) -> int:
    try:
        n = int(v)
    except (TypeError, ValueError, OverflowError):
        return default
    return min(max(n, lo), hi)


def _registrable_domain(email: str) -> str:
    """ciso@soc.mumbai.sbi.co.in → sbi.co.in; a@s1.bank.com → bank.com. The per-org cap keys on this."""
    dom = email.rsplit("@", 1)[-1].lower().strip() if "@" in email else ""
    labels = [x for x in dom.split(".") if x]
    if len(labels) < 2:
        return ""
    if len(labels) >= 3 and labels[-2] in _SLD and len(labels[-1]) == 2:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


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
           "grace_days": _int(b.get("grace_days", 30), 30, 0, 90), "notes": str(b.get("notes", ""))[:500]}
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
    if installation_id:
        store.put({"PK": "FLEET", "SK": f"INST#{installation_id}", "installation_id": installation_id, "customer": lic.customer,
                   "tier": lic.tier, "since": int(now)})
    return {"lic": lic.license_id, "token": token, "customer": lic.customer, "installation_id": installation_id,
            "edition": lic.edition, "tier": lic.tier, "expires": int(lic.expires), "entitlement_until": int(lic.entitlement_until),
            "features": lic.features, "limits": {"devices": lic.devices, "eps": lic.eps}}


# ------------------------------------------------------------ bearer / standing --

def _bearer_license(event: dict, cfg: Config, store: Store, now: float) -> tuple[L.License | None, dict | None, str]:
    """The licence token in Authorization: Bearer — signature verified against our keys, record active (a revoked
    licence is refused at once), expired accepted within its grace window. Returns (licence, record, reason)."""
    auth = _headers(event).get("authorization", "")
    if not auth.lower().startswith("bearer "):
        return None, None, "licence token required (Authorization: Bearer <token>)"
    keys = {k["kid"]: (int(k["n"], 16), int(k["e"])) for k in cfg.pubkeys()}
    lic, why = L.decode(auth[7:].strip(), keys)
    if lic is None:
        return None, None, why
    if now > lic.expires + lic.grace_days * 86400:
        return None, None, "licence token expired beyond its grace window"
    rec = store.get(f"LIC#{lic.license_id}", "META")
    if rec is None:
        return None, None, "unknown licence"
    if rec.get("status") != "active":
        return None, None, f"licence is {rec.get('status')}"
    return lic, rec, ""


def _resolve_inst(store: Store, lic: L.License, claimed: str) -> tuple[str, str]:
    """Which installation a bearer call acts on. A bound token acts only on its own installation. A floating
    (pilot) token must name a valid id that no OTHER licence has claimed — it can never write another
    customer's state. Returns (installation_id, error)."""
    if lic.installation_id:
        return lic.installation_id, ""
    inst = str(claimed or "").strip()
    if not _valid_inst(inst):
        return "", "a floating licence must name a valid installation_id ([A-Za-z0-9][A-Za-z0-9._-]{0,79})"
    owners = {r.get("lic") for r in store.query(f"INST#{inst}", "LIC#")}
    if owners and lic.license_id not in owners:
        return "", "installation_id belongs to another licence"
    if not owners:
        store.put({"PK": f"INST#{inst}", "SK": f"LIC#{lic.license_id}", "lic": lic.license_id, "customer": lic.customer,
                   "tier": lic.tier, "expires": int(lic.expires), "issued": int(lic.issued)})
        store.put({"PK": "FLEET", "SK": f"INST#{inst}", "installation_id": inst, "customer": lic.customer, "tier": lic.tier, "since": int(time.time())})
    return inst, ""


def _inst_meta(store: Store, inst: str) -> dict:
    return store.get(f"INST#{inst}", "META") or {"PK": f"INST#{inst}", "SK": "META", "installation_id": inst}


def _standing(store: Store, cfg: Config, lic_rec: dict, meta: dict, now: float) -> dict:
    """Is this installation keeping its side of the licence? For data_sharing: contributions must track the
    chains the heartbeats report, and after the first week there must BE heartbeats and contributions.
    Attestation: the reported code fingerprint must be a published release (when a list is published)."""
    feats = set(lic_rec.get("features") or [])
    issues: list[str] = []
    hard: list[str] = []
    age = now - float(lic_rec.get("issued") or now)
    settled = age > STANDING_GRACE_S
    hb_age = now - float(meta.get("last_heartbeat") or 0) if meta.get("last_heartbeat") else None
    fp = meta.get("code_fingerprint")
    known = cfg.known_fingerprints()
    attestation = "unknown" if (fp and known and fp not in known) else ("ok" if fp and (not known or fp in known) else "none")
    ratio = None
    reset = False
    if "data_sharing" in feats:
        since = now - STANDING_WINDOW_S
        inst_ = str(lic_rec.get("installation_id") or meta.get("installation_id") or "")
        chains_now = int(meta.get("chains_total") or 0)
        # chains written in the window = chains_total now − chains_total at the heartbeat nearest the window start;
        # a smaller counter than before is an audit rotation (or a lie): count from zero and say so
        hbs = store.query(f"INST#{inst_}", "HB#", sk_from=f"HB#{int(since) - 2 * 86400}")
        before = [h for h in hbs if float(h.get("last_heartbeat") or 0) <= since]
        base = max(before, key=lambda h: float(h["last_heartbeat"])) if before else (min(hbs, key=lambda h: h["SK"]) if hbs else None)
        chains_then = int(base.get("chains_total") or 0) if base else chains_now
        peak = max([int(h.get("chains_total") or 0) for h in hbs] + [chains_then])
        if chains_now < peak:
            reset = True
            written = chains_now
            issues.append("chains counter went backwards (audit rotation?) — window counted from zero")
        else:
            written = chains_now - chains_then
        contributed = sum(int(r.get("records") or 0) for r in store.query(f"INST#{inst_}", "CONTRIB#", sk_from=f"CONTRIB#{int(since)}"))
        ratio = (contributed / written) if written > 0 else (1.0 if written == 0 else 0.0)
        if hb_age is None:
            (hard if settled else issues).append("no heartbeat yet" + (" — a week after issue" if settled else ""))
        elif hb_age > 3 * 86400:
            hard.append(f"no heartbeat for {hb_age / 86400:.0f} days")
        if settled and contributed == 0:
            hard.append("no contribution in the last 30 days")
        elif written > 50 and ratio < RATIO_FAIL:
            hard.append(f"contribution ratio {ratio:.2f} < {RATIO_FAIL} over 30 days ({contributed}/{written} chains)")
        elif written > 50 and ratio < RATIO_WARN:
            issues.append(f"contribution ratio {ratio:.2f} low ({contributed}/{written} chains)")
        last_c = float(meta.get("last_contrib") or 0)
        if last_c and now - last_c > 3 * 86400 and written > 0:
            hard.append(f"no contribution for {(now - last_c) / 86400:.0f} days while chains are being written")
        if attestation == "unknown":
            hard.append("code fingerprint is not a published release")
        flags = meta.get("flags") or {}
        if flags.get("AEGIS_DATASET_CAPTURE") in ("0", "false", "off") or flags.get("AEGIS_CONTRIB") in ("0", "false", "off"):
            hard.append("capture/contribution switched off in the installation's environment")
    all_issues = hard + issues
    standing = "good" if not all_issues else ("bad" if hard else "warn")
    return {"standing": standing, "issues": all_issues, "ratio": None if ratio is None else round(ratio, 3), "attestation": attestation,
            "counter_reset": reset, "heartbeat_age_s": None if hb_age is None else int(hb_age), "chains_total": int(meta.get("chains_total") or 0),
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


def _inflate(data: bytes, limit: int) -> bytes:
    """gzip-inflate with a hard output cap (a bomb raises ValueError instead of eating the Lambda's memory)."""
    d = zlib.decompressobj(16 + zlib.MAX_WBITS)
    out = d.decompress(data, limit + 1)
    if len(out) > limit or d.unconsumed_tail:
        raise ValueError(f"bundle inflates past {limit // (1024 * 1024)} MB — split it")
    return out + d.flush()


def _check_record(r: Any) -> str:
    if not isinstance(r, dict):
        return "record is not an object"
    if r.get("human") is not None and (not isinstance(r["human"], list) or not all(isinstance(h, dict) for h in r["human"])):
        return "record.human must be a list of objects"
    for k in ("chain", "alert", "label"):
        if r.get(k) is not None and not isinstance(r[k], dict):
            return f"record.{k} must be an object"
    return ""


# ------------------------------------------------------------- releases --

def _sign_manifest(cfg: Config, rel: dict) -> str:
    k = cfg.signing_key
    header = L._b64u(json.dumps({"alg": "RS256", "typ": MANIFEST_TYP, "kid": str(k["kid"])}, separators=(",", ":")).encode())
    body = L._b64u(json.dumps(rel, sort_keys=True, separators=(",", ":")).encode())
    sig = L.rsa_sign(f"{header}.{body}".encode(), int(k["n"], 16), int(k["d"], 16))
    return f"{header}.{body}.{L._b64u(sig)}"


def _manifest_fields(rec: dict) -> dict:
    """The signed part of a release — plain ints and strings only (never a Decimal, never a float)."""
    out: dict[str, Any] = {}
    for k in ("version", "channel", "base_model", "sha256", "min_aegis", "notes"):
        if k in rec:
            out[k] = str(rec[k])
    for k in ("size", "rollout_pct", "published_at"):
        if k in rec and rec[k] is not None:
            out[k] = int(rec[k])
    return out


def _version_key(v: str) -> tuple[int, ...]:
    try:
        return tuple(int(x) for x in v.split("."))
    except ValueError:
        return (0,)


def _releases(store: Store) -> list[dict]:
    return store.query("RELEASES", "REL#")


def _latest_release(store: Store, channel: str, base: str, current: str) -> dict | None:
    """The newest published release for this channel whose base matches: a base-specific adapter is never offered to
    an installation that did not say which base it runs (``base=any`` only gets releases marked ``any``)."""
    rows = [r for r in _releases(store) if r.get("status") == "published" and r.get("channel") == channel
            and (r.get("base_model") == "any" or (base not in ("", "any") and r.get("base_model") == base))]
    rows = [r for r in rows if not current or _version_key(str(r["version"])) > _version_key(current)]
    return max(rows, key=lambda r: _version_key(str(r["version"]))) if rows else None


def fleet_scan(cfg: Config, store: Store, now: float | None = None, *, notify: bool = False) -> dict:
    """Daily: standing for every installation (a query over the FLEET partition, never a table scan); SNS on
    anything not good."""
    now = time.time() if now is None else now
    rows = []
    alerts = []
    for ptr in store.query("FLEET", "INST#"):
        inst = str(ptr.get("installation_id") or ptr["SK"][5:])
        lic = _active_license_for(store, inst)
        if lic is None:
            continue
        st = _standing(store, cfg, lic, _inst_meta(store, inst), now)
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
    ttl = int(now + ROW_TTL_S)
    try:
        if method == "GET" and path == "/health":
            return _resp(200, {"ok": True, "kid": cfg.signing_key["kid"], "time": int(now)})
        if method == "GET" and path == "/pubkeys":
            return _resp(200, {"keys": cfg.pubkeys()})

        if method == "POST" and path == "/activate":
            b = _body(event)
            code = str(b.get("code", "")).strip().upper()[:40]
            inst = str(b.get("installation_id", "")).strip()
            if not _CODE_RX.match(code):
                return _resp(400, {"error": "code must look like BD-XXXX-XXXX-XXXX"})
            if not _valid_inst(inst):
                return _resp(400, {"error": "installation_id must match [A-Za-z0-9][A-Za-z0-9._-]{0,79}"})
            order = store.get(f"ORDER#{code}", "META")
            if order is None:
                return _resp(404, {"error": "unknown activation code"})
            if order.get("status") == "redeemed":
                if order.get("installation_id") == inst and order.get("lic"):
                    lic = store.get(f"LIC#{order['lic']}", "META")
                    if lic and lic.get("status") == "active":
                        return _resp(200, {"lic": lic["lic"], "token": lic["token"], "reissued": True, "expires": int(lic["expires"])})
                return _resp(409, {"error": "activation code already used on another installation"})
            if order.get("status") != "open":
                return _resp(410, {"error": f"activation code is {order.get('status')}"})
            if order.get("expires_at") and now > float(order["expires_at"]):
                return _resp(410, {"error": "activation code expired — ask for a new one"})
            # claim the code first (conditional on it still being open) so two racing redemptions cannot both win
            if not store.update_if(f"ORDER#{code}", "META", "status", "open", status="redeeming", installation_id=inst, redeemed_at=int(now)):
                return _resp(409, {"error": "activation code already used"})
            issued = _issue(cfg, store, order, inst, code=code, now=now)
            store.update(f"ORDER#{code}", "META", status="redeemed", lic=issued["lic"])
            log.info("activated %s for %s on %s", issued["lic"], order["customer"], inst)
            return _resp(200, issued)

        if method == "POST" and path == "/signup":
            b = _body(event)
            org, email, inst = str(b.get("org", "")).strip()[:120], str(b.get("email", "")).strip().lower()[:200], str(b.get("installation_id", "")).strip()
            if not (org and email and inst and b.get("accept_terms") is True):
                return _resp(400, {"error": "org, email, installation_id and accept_terms=true are required"})
            if not _valid_inst(inst):
                return _resp(400, {"error": "installation_id must match [A-Za-z0-9][A-Za-z0-9._-]{0,79}"})
            if not re.match(r"^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$", email):
                return _resp(400, {"error": "a valid work e-mail is required"})
            dom = _registrable_domain(email)
            full = email.rsplit("@", 1)[-1]
            if full in DISPOSABLE or dom in DISPOSABLE:
                return _resp(400, {"error": "disposable e-mail domains are not accepted"})
            if full in FREEMAIL or dom in FREEMAIL:
                return _resp(400, {"error": "a work e-mail (your organisation's domain) is required for the Community edition"})
            if _active_license_for(store, inst):
                return _resp(409, {"error": "this installation already holds a licence — use /renew or contact BlueDefence"})
            orgrec = store.get(f"ORG#{dom}", "META") or {"PK": f"ORG#{dom}", "SK": "META", "domain": dom, "installations": [], "created": int(now)}
            if len(orgrec.get("installations") or []) >= COMMUNITY_PER_DOMAIN:
                return _resp(429, {"error": f"{COMMUNITY_PER_DOMAIN} Community installations already registered for {dom} — contact BlueDefence for more"})
            # reserve the slot atomically on the org record (count == what we read) before issuing
            n_before = len(orgrec.get("installations") or [])
            new_list = list(orgrec.get("installations") or []) + [inst]
            if n_before == 0:
                if not store.put({**orgrec, "installations": new_list, "name": org}, if_absent=True):
                    return _resp(409, {"error": "concurrent signup for this organisation — retry"})
            elif not store.update_if(f"ORG#{dom}", "META", "installations", orgrec.get("installations") or [], installations=new_list, name=org):
                return _resp(409, {"error": "concurrent signup for this organisation — retry"})
            order = {"customer": org, "edition": "soc", "tier": "community", "days": COMMUNITY_DAYS, "features": [], "grace_days": 14,
                     "notes": f"community self-serve by {email}", "rolling": True}
            issued = _issue(cfg, store, order, inst, code=None, now=now, entitlement_until=now + COMMUNITY_DAYS * 86400,
                            org={"name": org, "email": email, "domain": dom, "terms_accepted_at": int(now)})
            store.update(f"INST#{inst}", "META", installation_id=inst, customer=org, tier="community", created=int(now))
            log.info("community signup %s %s %s", org, dom, inst)
            return _resp(201, {**issued, "terms": "Community edition: free for 2 years; the model runs at your site; scrubbed evidence chains "
                                                  "and analyst decisions are contributed hourly (data_sharing). The 30-day token renews "
                                                  "automatically while contributions keep arriving."})

        if method == "POST" and path == "/renew":
            lic, rec, why = _bearer_license(event, cfg, store, now)
            if lic is None or rec is None:
                return _resp(401, {"error": why})
            ent = float(rec.get("entitlement_until") or 0)
            if not ent:
                return _resp(400, {"error": "this licence is not a rolling licence — it runs to its expiry; contact BlueDefence to extend"})
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
            lic, rec, why = _bearer_license(event, cfg, store, now)
            if lic is None or rec is None:
                return _resp(401, {"error": why})
            b = _body(event)
            inst, err = _resolve_inst(store, lic, str(b.get("installation_id", "")))
            if err:
                return _resp(403, {"error": err})
            fp = str(b.get("code_fingerprint", ""))[:64]
            flags = {str(k)[:40]: str(v)[:40] for k, v in list((b.get("flags") or {}).items())[:32]} if isinstance(b.get("flags"), dict) else {}
            counters = {str(k)[:32]: _int(v) for k, v in list((b.get("counters") or {}).items())[:32]
                        if isinstance(v, (int, float)) and not isinstance(v, bool)} if isinstance(b.get("counters"), dict) else {}
            fields = {"installation_id": inst, "last_heartbeat": int(now), "chains_total": _int(b.get("chains_total"), 0, 0),
                      "audit_tail_hash": str(b.get("audit_tail_hash", ""))[:64], "code_fingerprint": fp, "flags": flags,
                      "version": str(b.get("version", ""))[:40], "host": str(b.get("host", ""))[:80], "counters": counters,
                      "machine_hash": str(b.get("machine_hash", ""))[:40], "pinned": bool(b.get("pinned"))}
            meta = _inst_meta(store, inst)
            machines = set(meta.get("machines") or [])
            if fields["machine_hash"]:
                machines.add(fields["machine_hash"])
            fields["machines"] = sorted(machines)[:16]
            store.update(f"INST#{inst}", "META", **fields)
            store.put({"PK": f"INST#{inst}", "SK": f"HB#{int(now)}", "ttl": ttl, **{k: v for k, v in fields.items() if k not in ("installation_id", "machines")}})
            st = _standing(store, cfg, rec, {**meta, **fields}, now)
            if len(machines) > 1:
                st["issues"].append(f"{len(machines)} distinct machines report under this installation id")
            return _resp(200, {"ok": True, "standing": st["standing"], "reason": "; ".join(st["issues"]), "attestation": st["attestation"]})

        if method == "POST" and path == "/contrib":
            lic, rec, why = _bearer_license(event, cfg, store, now)
            if lic is None or rec is None:
                return _resp(401, {"error": why})
            raw = event.get("body") or ""
            hdrs = _headers(event)
            if event.get("isBase64Encoded"):
                data = base64.b64decode(raw)
            else:
                data = raw.encode("utf-8", "replace")
                if "gzip" in hdrs.get("content-encoding", "") or raw[:1] == "\x1f":
                    return _resp(400, {"error": "gzip body arrived as text — send it with Content-Type: application/gzip (binary), not application/json"})
            if len(data) > MAX_CONTRIB_BODY:
                return _resp(413, {"error": f"bundle over {MAX_CONTRIB_BODY // (1024 * 1024)} MB — split it"})
            if data[:2] == b"\x1f\x8b":
                try:
                    data = _inflate(data, MAX_CONTRIB_INFLATED)
                except (zlib.error, OSError):
                    return _resp(400, {"error": "bad gzip body"})
            try:
                bundle = json.loads(data)
            except ValueError:
                return _resp(400, {"error": "bundle is not JSON"})
            if not isinstance(bundle, dict) or bundle.get("schema") != "aegis-contrib/1":
                return _resp(400, {"error": "unsupported bundle schema"})
            if bundle.get("salted") is not True:
                return _resp(422, {"error": "bundle is not salted (AEGIS_DATASET_SALT unset on the installation) — pseudonyms would be "
                                            "reversible; nothing stored"})
            inst, err = _resolve_inst(store, lic, str(bundle.get("installation_id", "")))
            if err:
                return _resp(403, {"error": err})
            if str(bundle.get("installation_id", "")) != inst:
                return _resp(403, {"error": "bundle installation_id does not match the licence"})
            records = bundle.get("records")
            if not isinstance(records, list):
                return _resp(400, {"error": "records must be a list"})
            if len(records) > MAX_CONTRIB_RECORDS:
                return _resp(413, {"error": f"over {MAX_CONTRIB_RECORDS} records — split it"})
            for i, r in enumerate(records):
                bad = _check_record(r)
                if bad:
                    return _resp(400, {"error": f"records[{i}]: {bad}"})
            ok, found = privacy_gate.gate({k: v for k, v in bundle.items() if k != "installation_id"})
            if not ok:
                store.update(f"INST#{inst}", "META", installation_id=inst, last_contrib_refused=int(now), last_refusal_findings=len(found))
                return _resp(422, {"error": f"bundle refused by the privacy gate: {len(found)} finding(s) — nothing stored",
                                   "findings": [{"kind": f["kind"], "path": f["path"]} for f in found[:20]]})
            decided = sum(1 for r in records if any(h.get("decision") in ("approved", "rejected") for h in (r.get("human") or [])))
            with_hash = sum(1 for r in records if (r.get("chain") or {}).get("integrity_hash"))
            import gzip
            key = f"contrib/{inst}/{time.strftime('%Y/%m/%d', time.gmtime(now))}/{int(now)}-{len(records)}.json.gz"
            where = store.put_object(key, gzip.compress(json.dumps(bundle, separators=(",", ":")).encode()))
            counts = bundle.get("counts") if isinstance(bundle.get("counts"), dict) else {}
            # the CONTRIB row first (it is what standing counts), then the running totals
            store.put({"PK": f"INST#{inst}", "SK": f"CONTRIB#{int(now)}", "ttl": ttl, "received": int(now), "records": len(records),
                       "decided": decided, "with_hash": with_hash, "key": key, "counts": counts, "license_id": str(bundle.get("license_id", ""))[:40]})
            meta = _inst_meta(store, inst)
            store.update(f"INST#{inst}", "META", installation_id=inst, last_contrib=int(now),
                         contrib_records_total=int(meta.get("contrib_records_total") or 0) + len(records),
                         contrib_decided_total=int(meta.get("contrib_decided_total") or 0) + decided,
                         contrib_bundles=int(meta.get("contrib_bundles") or 0) + 1)
            log.info("contrib %s: %d records (%d decided) → %s", inst, len(records), decided, where)
            return _resp(202, {"ok": True, "stored": key, "records": len(records), "decided": decided})

        if method == "GET" and path == "/updates":
            lic, rec, why = _bearer_license(event, cfg, store, now)
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
            lic, rec, why = _bearer_license(event, cfg, store, now)
            if lic is None:
                return _resp(401, {"error": why})
            b = _body(event, MAX_USAGE_BODY)
            rep = b.get("report") if isinstance(b.get("report"), dict) else b
            inst, err = _resolve_inst(store, lic, str(rep.get("installation_id", "")))
            if err:
                return _resp(403, {"error": err})
            store.put({"PK": f"INST#{inst}", "SK": f"USAGE#{int(now)}", "ttl": ttl, "report": rep, "received": int(now)})
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
            o = store.get(f"ORDER#{parts[1].upper()[:40]}", "META")
            return _resp(200, o) if o else _resp(404, {"error": "not found"})
        if method == "POST" and path == "/licenses":
            b = _body(event)
            v = _validate_order(b)
            if isinstance(v, str):
                return _resp(400, {"error": v})
            inst = str(b.get("installation_id", "")).strip()
            if not inst:
                return _resp(400, {"error": "installation_id is required ('*' for a floating pilot)"})
            if inst != "*" and not _valid_inst(inst):
                return _resp(400, {"error": "installation_id must match [A-Za-z0-9][A-Za-z0-9._-]{0,79} (or '*')"})
            return _resp(201, _issue(cfg, store, v, "" if inst == "*" else inst, code=None, now=now))
        if method == "GET" and len(parts) == 2 and parts[0] == "licenses":
            rec = store.get(f"LIC#{parts[1][:60]}", "META")
            return _resp(200, rec) if rec else _resp(404, {"error": "not found"})
        if method == "POST" and len(parts) == 3 and parts[0] == "licenses" and parts[2] == "revoke":
            rec = store.get(f"LIC#{parts[1][:60]}", "META")
            if not rec:
                return _resp(404, {"error": "not found"})
            store.update(f"LIC#{parts[1][:60]}", "META", status="revoked", revoked_at=int(now), reason=str(_body(event).get("reason", ""))[:200])
            return _resp(200, {"lic": parts[1], "status": "revoked",
                               "note": "bearer calls (renew, heartbeat, contrib, model updates) are refused from now; the offline file "
                                       "verifies until its expiry"})
        if method == "POST" and path == "/releases":
            b = _body(event)
            v = str(b.get("version", "")).strip()
            if not _VERSION_RX.match(v):
                return _resp(400, {"error": "version must look like 2026.11.1"})
            channel = str(b.get("channel", "stable"))
            if channel not in ("stable", "beta"):
                return _resp(400, {"error": "channel must be stable or beta"})
            sha = str(b.get("sha256", "")).lower()
            if not _HEX_RX.match(sha):
                return _resp(400, {"error": "sha256 must be 64 hex chars"})
            try:
                size, pct = int(b.get("size", 0)), int(b.get("rollout_pct", 100))
            except (TypeError, ValueError):
                return _resp(400, {"error": "size and rollout_pct must be integers"})
            if size <= 0 or not 0 <= pct <= 100:
                return _resp(400, {"error": "size must be > 0 and rollout_pct 0..100"})
            key = f"releases/{channel}/{v}/adapter.tar.gz"
            rec = {"PK": "RELEASES", "SK": f"REL#{v}", "version": v, "channel": channel, "base_model": str(b.get("base_model", "any"))[:120],
                   "sha256": sha, "size": size, "rollout_pct": pct, "min_aegis": str(b.get("min_aegis", ""))[:40],
                   "notes": str(b.get("notes", ""))[:500], "key": key, "status": "registered", "created": int(now)}
            if not store.put(rec, if_absent=True):
                return _resp(409, {"error": f"release {v} already exists"})
            return _resp(201, {"version": v, "key": key, "upload_url": store.presign(key, "put_object", 3600, "application/gzip")})
        if method == "GET" and path == "/releases":
            q = event.get("queryStringParameters") or {}
            rows = [{k: r.get(k) for k in ("version", "channel", "base_model", "size", "rollout_pct", "status", "published_at", "notes")}
                    for r in _releases(store) if not q.get("channel") or r.get("channel") == q.get("channel")]
            return _resp(200, {"releases": sorted(rows, key=lambda r: _version_key(str(r["version"])), reverse=True)})
        if method == "POST" and len(parts) == 3 and parts[0] == "releases":
            ver = parts[1][:40]
            rec = store.get("RELEASES", f"REL#{ver}")
            if not rec:
                return _resp(404, {"error": "unknown release"})
            if parts[2] == "publish":
                rec["published_at"] = int(now)
                manifest = _manifest_fields(rec)
                token = _sign_manifest(cfg, manifest)
                store.update("RELEASES", f"REL#{ver}", status="published", published_at=int(now), manifest_token=token)
                return _resp(200, {**manifest, "status": "published", "kid": cfg.signing_key["kid"]})
            if parts[2] == "rollout":
                pct = _int(_body(event).get("pct", 100), -1)
                if not 0 <= pct <= 100:
                    return _resp(400, {"error": "pct 0..100"})
                rec["rollout_pct"] = pct
                token = _sign_manifest(cfg, _manifest_fields(rec))
                store.update("RELEASES", f"REL#{ver}", rollout_pct=pct, manifest_token=token)
                return _resp(200, {"version": ver, "rollout_pct": pct})
            if parts[2] == "withdraw":
                store.update("RELEASES", f"REL#{ver}", status="withdrawn", withdrawn_at=int(now), reason=str(_body(event).get("reason", ""))[:200])
                return _resp(200, {"version": ver, "status": "withdrawn"})
            return _resp(404, {"error": "not found"})
        if method == "POST" and path == "/admin/migrate":
            # one-off after upgrading from the first release: INST# rows get FLEET pointers, REL#<v>/META rows move
            # under the RELEASES partition. Idempotent; safe to run again.
            moved = ptrs = 0
            for meta in store.scan_meta("INST#"):
                inst = str(meta.get("installation_id") or meta["PK"][5:])
                if inst and inst != "*" and store.get("FLEET", f"INST#{inst}") is None:
                    store.put({"PK": "FLEET", "SK": f"INST#{inst}", "installation_id": inst, "customer": meta.get("customer"),
                               "tier": meta.get("tier"), "since": int(meta.get("created") or now)})
                    ptrs += 1
            for rel in store.scan_meta("REL#"):
                v = str(rel.get("version") or rel["PK"][4:])
                if store.get("RELEASES", f"REL#{v}") is None:
                    store.put({**rel, "PK": "RELEASES", "SK": f"REL#{v}"})
                    moved += 1
            return _resp(200, {"fleet_pointers_added": ptrs, "releases_moved": moved})
        if method == "GET" and path == "/fleet":
            scan = fleet_scan(cfg, store, now)
            return _resp(200, {"installations": scan["rows"], "need_attention": scan["alerts"]})
        if method == "GET" and len(parts) == 3 and parts[0] == "installations" and parts[2] == "health":
            inst = parts[1][:80]
            lic = _active_license_for(store, inst)
            if lic is None:
                return _resp(404, {"error": "no active licence for this installation"})
            meta = _inst_meta(store, inst)
            return _resp(200, {"installation_id": inst, "customer": lic.get("customer"), "tier": lic.get("tier"), "lic": lic.get("lic"),
                               "entitlement_until": lic.get("entitlement_until"), "token_expires": lic.get("expires"),
                               "renewals": lic.get("renewals", 0), "machines": meta.get("machines") or [], **_standing(store, cfg, lic, meta, now)})
        if method == "GET" and len(parts) == 2 and parts[0] == "installations":
            inst = parts[1][:80]
            rows = store.query(f"INST#{inst}")
            return _resp(200, {"installation_id": inst,
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
