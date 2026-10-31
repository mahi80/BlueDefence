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
    POST /usage           {report}         store a `python -m aegis.license report` snapshot (counts only)

  admin (header ``x-admin-key`` = SSM /bluedefence/license/admin-key):
    POST /orders          {customer, edition, tier, days, devices?, eps?, features?, notes?}
                                           → an activation code the bank operator redeems
    GET  /orders/{code}
    POST /licenses        {customer, installation_id, edition, tier, days, …}
                                           → issue directly, bound to a known installation id
    GET  /licenses/{lic}
    GET  /installations/{id}               licences + usage reports for one installation
    POST /licenses/{lic}/revoke            mark revoked (the offline file keeps working until expiry —
                                           revocation is for records and for refusing re-activation)

Table (single, on-demand): PK / SK
    ORDER#<code>        META           order record, status open|redeemed|void
    LIC#<lic>           META           licence record + token
    INST#<id>           LIC#<lic>      which licences an installation holds
    INST#<id>           USAGE#<ts>     usage reports
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

log = logging.getLogger()
log.setLevel(logging.INFO)

TABLE = os.environ.get("LICENSE_TABLE", "bluedefence-licenses")
KEY_PARAM = os.environ.get("SIGNING_KEY_PARAM", "/bluedefence/license/signing-key")
ADMIN_PARAM = os.environ.get("ADMIN_KEY_PARAM", "/bluedefence/license/admin-key")
PUBKEYS_PARAM = os.environ.get("PUBKEYS_PARAM", "/bluedefence/license/public-keys")   # optional: extra kids for /pubkeys
MAX_BODY = 64 * 1024


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


class MemoryStore(Store):
    def __init__(self):  # noqa: D107 — no boto3
        self._d: dict[tuple[str, str], dict] = {}

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
        self._d[(pk, sk)].update(fields)


# -------------------------------------------------------------------- config --

class Config:
    """Signing key + admin key from SSM (cached for the Lambda's life); tests inject values."""

    def __init__(self, *, signing_key: dict | None = None, admin_key: str | None = None, extra_pubkeys: list[dict] | None = None):
        self._signing = signing_key
        self._admin = admin_key
        self._extra = extra_pubkeys

    def _ssm(self, name: str, decrypt: bool) -> str:
        import boto3  # type: ignore
        return boto3.client("ssm").get_parameter(Name=name, WithDecryption=decrypt)["Parameter"]["Value"]

    @property
    def signing_key(self) -> dict:
        if self._signing is None:
            self._signing = json.loads(self._ssm(KEY_PARAM, True))
        return self._signing

    @property
    def admin_key(self) -> str:
        if self._admin is None:
            self._admin = self._ssm(ADMIN_PARAM, True).strip()
        return self._admin

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


def _lic_from_order(o: dict, installation_id: str, now: float) -> L.License:
    tier = L.TIER_DEFAULTS[o["tier"]]
    feats = sorted(set(tier["features"]) | set(o.get("features") or []))
    return L.License(customer=o["customer"], installation_id=installation_id, edition=o["edition"], tier=o["tier"],
                     issued=now, expires=now + int(o["days"]) * 86400, grace_days=int(o.get("grace_days", 30)),
                     devices=int(o["devices"]) if o.get("devices") is not None else tier["devices"],
                     eps=int(o["eps"]) if o.get("eps") is not None else tier["eps"], features=feats, notes=str(o.get("notes", "")))


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


def _issue(cfg: Config, store: Store, order: dict, installation_id: str, *, code: str | None, now: float) -> dict:
    k = cfg.signing_key
    lic = _lic_from_order(order, installation_id, now)
    token = L.issue(lic, n=int(k["n"], 16), d=int(k["d"], 16), kid=str(k["kid"]))
    rec = {"PK": f"LIC#{lic.license_id}", "SK": "META", "lic": lic.license_id, "customer": lic.customer,
           "installation_id": installation_id, "edition": lic.edition, "tier": lic.tier, "issued": int(now),
           "expires": int(lic.expires), "devices": lic.devices, "eps": lic.eps, "features": lic.features,
           "code": code, "status": "active", "token_sha256": hashlib.sha256(token.encode()).hexdigest(), "token": token}
    store.put(rec)
    store.put({"PK": f"INST#{installation_id or '*'}", "SK": f"LIC#{lic.license_id}", "lic": lic.license_id,
               "customer": lic.customer, "tier": lic.tier, "expires": int(lic.expires), "issued": int(now)})
    return {"lic": lic.license_id, "token": token, "customer": lic.customer, "installation_id": installation_id,
            "edition": lic.edition, "tier": lic.tier, "expires": int(lic.expires), "features": lic.features,
            "limits": {"devices": lic.devices, "eps": lic.eps}}


# ------------------------------------------------------------------- handler --

def handle(event: dict, *, cfg: Config, store: Store, now: float | None = None) -> dict:
    now = time.time() if now is None else now
    rc = event.get("requestContext", {}).get("http", {})
    method = str(rc.get("method") or event.get("httpMethod") or "GET").upper()
    path = str(rc.get("path") or event.get("rawPath") or event.get("path") or "/").rstrip("/") or "/"
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
    return handle(event, cfg=_CFG, store=_STORE)
