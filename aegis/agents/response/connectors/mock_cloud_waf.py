"""In-process fake cloud WAF tenants — Cloudflare, AWS WAFv2, Azure WAF policy.

Same idea as ``mock_vendor.py``: stateful transports implementing exactly the
endpoints ``cloud_waf.py`` calls, with the vendors' own concurrency and error
shapes (Cloudflare's ``success: false`` envelope and duplicate code 10009,
AWS ``LockToken`` + ``WAFOptimisticLockException`` and a SigV4 check, Azure
``etag`` / ``If-Match`` → 412 and the IPMatch-needs-values rule). Failure
injection comes from ``_MockBase`` (``fail_next``, ``drop_next``), and each mock
can simulate a concurrent writer (``race_next``) to exercise the retry paths.

They prove our plumbing against our reading of the public API docs, not the
vendors' behaviour.
"""

from __future__ import annotations

import base64
import copy
import datetime as _dt
import itertools
import re
from typing import Optional

from .cloud_auth import AwsCredentials, sigv4_headers
from .http import HttpResult, RawBody
from .mock_vendor import _MockBase

CF_BASE = "https://cloudflare.mock/client/v4"
AWS_ENDPOINT = "https://wafv2.mock.amazonaws.com/"
AWS_KEY, AWS_SECRET = "AKIAMOCKAEGIS", "mock/secret+key"
AZ_ARM, AZ_SUB, AZ_RG, AZ_POLICY, AZ_TOKEN = "https://arm.mock", "sub-mock", "rg-mock", "aegispolicy", "az-mock-token"


def _cf(result, status: int = 200) -> HttpResult:
    return HttpResult(status, {"success": True, "errors": [], "messages": [], "result": result})


def _cf_err(status: int, code: int, message: str) -> HttpResult:
    return HttpResult(status, {"success": False, "errors": [{"code": code, "message": message}], "result": None})


class MockCloudflare(_MockBase):
    """Cloudflare v4: IP Access Rules (zone + account) and the http_ratelimit phase ruleset."""

    _ACCESS = re.compile(r"/client/v4/(?P<scope>zones|accounts)/(?P<sid>[^/]+)/firewall/access_rules/rules(?:/(?P<rid>[^/?]+))?$")
    _ENTRY = re.compile(r"/client/v4/zones/(?P<zone>[^/]+)/rulesets/phases/(?P<phase>[^/]+)/entrypoint$")
    _RULESETS = re.compile(r"/client/v4/zones/(?P<zone>[^/]+)/rulesets$")
    _RULES = re.compile(r"/client/v4/zones/(?P<zone>[^/]+)/rulesets/(?P<rs>[^/]+)/rules(?:/(?P<rule>[^/?]+))?$")

    def __init__(self, token: str = "mock", plan_period: Optional[int] = None):
        super().__init__()
        self.token = token
        self.plan_period = plan_period          # e.g. 10 on Free/Pro: other periods are refused
        self.access_rules: dict[str, dict] = {}
        self.rulesets: dict[str, dict] = {}
        self._hex = itertools.count(0xA000)

    def _id(self) -> str:
        return f"{next(self._hex):032x}"

    def handle(self, method: str, url: str, body: dict, headers: dict) -> HttpResult:
        if headers.get("Authorization") != f"Bearer {self.token}":
            return _cf_err(403, 10000, "Authentication error")
        path = url.split("?", 1)[0]
        m = self._ACCESS.search(path)
        if m:
            return self._access(method, m.group("scope"), m.group("sid"), m.group("rid"), body)
        m = self._ENTRY.search(path)
        if m and method == "GET":
            rs = next((r for r in self.rulesets.values()
                       if r["zone"] == m.group("zone") and r["phase"] == m.group("phase")), None)
            return _cf(self._public(rs)) if rs else _cf_err(404, 10003, "could not find entrypoint ruleset")
        m = self._RULESETS.search(path)
        if m and method == "POST":
            if body.get("kind") != "zone" or not body.get("phase"):
                return _cf_err(400, 20021, "invalid ruleset")
            rid = self._id()
            self.rulesets[rid] = {"id": rid, "zone": m.group("zone"), "phase": body["phase"], "rules": []}
            return _cf(self._public(self.rulesets[rid]))
        m = self._RULES.search(path)
        if m:
            rs = self.rulesets.get(m.group("rs"))
            if rs is None:
                return _cf_err(404, 10003, "ruleset not found")
            if method == "POST" and not m.group("rule"):
                rl = body.get("ratelimit") or {}
                if rs["phase"] == "http_ratelimit" and not {"characteristics", "period", "requests_per_period"} <= set(rl):
                    return _cf_err(400, 20120, "ratelimit requires characteristics, period, requests_per_period")
                if self.plan_period is not None and rl.get("period") != self.plan_period:
                    return _cf_err(400, 20120, f"period must be {self.plan_period} on this plan")
                expr = str(body.get("expression", ""))
                ok = expr.startswith("(ip.src") or (rs["phase"] == "http_request_firewall_custom"
                                                    and expr.startswith("(cf.bot_management.") and expr.count('"') % 2 == 0)
                if not ok:
                    return _cf_err(400, 20101, "filter parsing error")
                if rs["phase"] == "http_request_firewall_custom" and body.get("action") not in (
                        "block", "managed_challenge", "js_challenge", "challenge", "log", "skip"):
                    return _cf_err(400, 20021, "invalid action")
                rs["rules"].append({"id": self._id(), **body})
                return _cf(self._public(rs))
            if method == "DELETE" and m.group("rule"):
                before = len(rs["rules"])
                rs["rules"] = [r for r in rs["rules"] if r["id"] != m.group("rule")]
                if len(rs["rules"]) == before:
                    return _cf_err(404, 10003, "rule not found")
                return _cf(self._public(rs))
        return _cf_err(404, 7003, "Could not route to " + path)

    def _access(self, method: str, scope: str, sid: str, rid: Optional[str], body: dict) -> HttpResult:
        if method == "POST" and not rid:
            conf = body.get("configuration") or {}
            if body.get("mode") not in {"block", "challenge", "js_challenge", "managed_challenge", "whitelist"}:
                return _cf_err(400, 10001, "invalid mode")
            if conf.get("target") not in {"ip", "ip6", "ip_range", "asn", "country"}:
                return _cf_err(400, 10001, "invalid configuration target")
            if conf.get("target") == "ip_range":
                prefix = int(str(conf.get("value", "")).rsplit("/", 1)[-1] or 0)
                v6 = ":" in str(conf.get("value"))
                if prefix not in ({32, 48, 64} if v6 else {16, 24}):
                    return _cf_err(400, 10010, "ip_range only supports /16 and /24 (IPv4)")
            for r in self.access_rules.values():
                if r["scope"] == (scope, sid) and r["configuration"] == conf:
                    return _cf_err(400, 10009, "firewallaccessrules.api.duplicate_of_existing")
            new = self._id()
            self.access_rules[new] = {"id": new, "scope": (scope, sid), **body}
            return _cf({"id": new, "mode": body["mode"], "configuration": conf})
        if method == "DELETE" and rid:
            if self.access_rules.pop(rid, None) is None:
                return _cf_err(404, 10007, "rule not found")
            return _cf({"id": rid})
        return _cf_err(405, 10000, "method not allowed")

    @staticmethod
    def _public(rs: Optional[dict]) -> Optional[dict]:
        return None if rs is None else {"id": rs["id"], "phase": rs["phase"], "kind": "zone", "rules": list(rs["rules"])}

    def blocked(self) -> set[str]:
        return {r["configuration"]["value"] for r in self.access_rules.values() if r["mode"] == "block"}

    def challenged(self) -> set[str]:
        return {r["configuration"]["value"] for r in self.access_rules.values() if "challenge" in r["mode"]}

    def rate_rules(self) -> list[dict]:
        return [r for rs in self.rulesets.values() if rs["phase"] == "http_ratelimit" for r in rs["rules"]]

    def custom_rules(self) -> list[dict]:
        return [r for rs in self.rulesets.values() if rs["phase"] == "http_request_firewall_custom" for r in rs["rules"]]


class MockAwsWaf(_MockBase):
    """WAFv2 JSON-RPC: GetIPSet / UpdateIPSet with LockToken, SigV4 verified against the known secret."""

    def __init__(self, access_key: str = AWS_KEY, secret_key: str = AWS_SECRET, region: str = "ap-south-1"):
        super().__init__()
        self.creds = AwsCredentials(access_key, secret_key)
        self.region = region
        self.ip_sets: dict[str, dict] = {}
        self.rule_groups: dict[str, dict] = {}
        self.race_next = 0                       # bump the lock token behind the caller's back N times
        self._lock = itertools.count(1)

    def create_ip_set(self, name: str, addresses: Optional[list[str]] = None, version: str = "IPV4") -> str:
        sid = f"{next(self._ids):08d}-aaaa-bbbb-cccc-{len(self.ip_sets):012d}"
        self.ip_sets[sid] = {"Name": name, "Id": sid, "IPAddressVersion": version,
                             "Addresses": list(addresses or []), "Description": "wired by the bank",
                             "LockToken": f"lock-{next(self._lock)}"}
        return sid

    def create_rule_group(self, name: str, capacity: int = 500) -> str:
        gid = f"{next(self._ids):08d}-rg00-0000-0000-{len(self.rule_groups):012d}"
        self.rule_groups[gid] = {"Name": name, "Id": gid, "Capacity": capacity, "Rules": [],
                                 "VisibilityConfig": {"SampledRequestsEnabled": True, "CloudWatchMetricsEnabled": True,
                                                      "MetricName": name},
                                 "LockToken": f"lock-{next(self._lock)}"}
        return gid

    def _rule_group(self, op: str, payload: dict) -> HttpResult:
        g = self.rule_groups.get(str(payload.get("Id")))
        if g is None or g["Name"] != payload.get("Name"):
            return HttpResult(400, {"__type": "WAFNonexistentItemException", "message": "rule group not found"})
        if op == "GetRuleGroup":
            return HttpResult(200, {"RuleGroup": copy.deepcopy({k: v for k, v in g.items() if k != "LockToken"}),
                                    "LockToken": g["LockToken"]})
        if self.race_next > 0:
            self.race_next -= 1
            g["LockToken"] = f"lock-{next(self._lock)}"
        if payload.get("LockToken") != g["LockToken"]:
            return HttpResult(400, {"__type": "WAFOptimisticLockException", "message": "changed underneath"})
        rules = payload.get("Rules") or []
        if not payload.get("VisibilityConfig"):
            return HttpResult(400, {"__type": "WAFInvalidParameterException", "message": "VisibilityConfig"})
        if len({r.get("Name") for r in rules}) != len(rules) or len({r.get("Priority") for r in rules}) != len(rules):
            return HttpResult(400, {"__type": "WAFDuplicateItemException", "message": "duplicate rule name or priority"})
        if len(rules) * 2 > g["Capacity"]:
            return HttpResult(400, {"__type": "WAFLimitsExceededException", "message": "capacity"})
        for r in rules:
            if not all(k in r for k in ("Name", "Priority", "Statement", "Action", "VisibilityConfig")):
                return HttpResult(400, {"__type": "WAFInvalidParameterException", "message": f"rule {r.get('Name')}"})
            for bm in _byte_matches(r["Statement"]):
                try:
                    base64.b64decode(bm["SearchString"], validate=True)
                except Exception:  # noqa: BLE001
                    return HttpResult(400, {"__type": "SerializationException", "message": "SearchString must be base64"})
        g["Rules"] = copy.deepcopy(rules)
        g["LockToken"] = f"lock-{next(self._lock)}"
        return HttpResult(200, {"NextLockToken": g["LockToken"]})

    def fingerprint_rules(self) -> list[dict]:
        return [r for g in self.rule_groups.values() for r in g["Rules"]]

    def _signature_ok(self, url: str, body: bytes, headers: dict) -> bool:
        auth = headers.get("Authorization", "")
        if f"Credential={self.creds.access_key}/" not in auth:
            return False
        try:
            when = _dt.datetime.strptime(headers["x-amz-date"], "%Y%m%dT%H%M%SZ").replace(tzinfo=_dt.timezone.utc)
        except (KeyError, ValueError):
            return False
        unsigned = {k: v for k, v in headers.items() if k not in ("Authorization", "x-amz-date", "x-amz-security-token")}
        expect = sigv4_headers("POST", url, body, unsigned, creds=self.creds, region=self.region,
                               service="wafv2", now=when)["Authorization"]
        return expect == auth

    def handle(self, method: str, url: str, body, headers: dict) -> HttpResult:
        raw = bytes(body) if isinstance(body, RawBody) else b""
        if method != "POST" or not isinstance(body, RawBody):
            return HttpResult(400, {"__type": "SerializationException", "message": "expected a JSON-RPC POST"})
        if not self._signature_ok(url, raw, headers):
            return HttpResult(403, {"__type": "InvalidSignatureException",
                                    "message": "The request signature we calculated does not match the signature you provided."})
        payload = body.json()
        op = str(headers.get("X-Amz-Target", "")).rsplit(".", 1)[-1]
        if payload.get("Scope") not in ("REGIONAL", "CLOUDFRONT"):
            return HttpResult(400, {"__type": "WAFInvalidParameterException", "message": "Scope"})
        if op in ("GetRuleGroup", "UpdateRuleGroup"):
            return self._rule_group(op, payload)
        s = self.ip_sets.get(str(payload.get("Id")))
        if s is None or s["Name"] != payload.get("Name"):
            return HttpResult(400, {"__type": "WAFNonexistentItemException", "message": "IP set not found"})
        if op == "GetIPSet":
            ipset = {k: v for k, v in s.items() if k != "LockToken"}
            return HttpResult(200, {"IPSet": copy.deepcopy(ipset), "LockToken": s["LockToken"]})
        if op == "UpdateIPSet":
            if self.race_next > 0:
                self.race_next -= 1
                s["LockToken"] = f"lock-{next(self._lock)}"
            if payload.get("LockToken") != s["LockToken"]:
                return HttpResult(400, {"__type": "WAFOptimisticLockException",
                                        "message": "AWS WAF couldn't save your changes because someone changed the resource after you started to edit it."})
            for a in payload.get("Addresses") or []:
                if ("." in a) != (s["IPAddressVersion"] == "IPV4") or "/" not in a:
                    return HttpResult(400, {"__type": "WAFInvalidParameterException", "message": f"bad address {a}"})
            s["Addresses"] = list(payload["Addresses"])
            s["LockToken"] = f"lock-{next(self._lock)}"
            return HttpResult(200, {"NextLockToken": s["LockToken"]})
        return HttpResult(400, {"__type": "UnknownOperationException", "message": op})

    def addresses(self, name: str) -> list[str]:
        return next(s["Addresses"] for s in self.ip_sets.values() if s["Name"] == name)


def _byte_matches(stmt: dict) -> list[dict]:
    if "ByteMatchStatement" in stmt:
        return [stmt["ByteMatchStatement"]]
    if "AndStatement" in stmt:
        return [b for s in stmt["AndStatement"]["Statements"] for b in _byte_matches(s)]
    return []


class MockAzureWaf(_MockBase):
    """ARM WAF policy: GET returns policy + etag; PUT needs a matching If-Match, validates custom rules."""

    _POLICY = re.compile(r"/subscriptions/(?P<sub>[^/]+)/resourceGroups/(?P<rg>[^/]+)/providers/Microsoft\.Network/"
                         r"(?P<kind>FrontDoorWebApplicationFirewallPolicies|ApplicationGatewayWebApplicationFirewallPolicies)/(?P<name>[^/?]+)$")

    def __init__(self, token: str = AZ_TOKEN, flavor: str = "frontdoor", existing_rules: Optional[list] = None):
        super().__init__()
        self.token = token
        self.flavor = flavor
        self.race_next = 0
        self._etag = itertools.count(1)
        rules = list(existing_rules or [])
        props = ({"customRules": {"rules": rules}, "managedRules": {"managedRuleSets": []},
                  "policySettings": {"enabledState": "Enabled", "mode": "Prevention"}}
                 if flavor == "frontdoor" else
                 {"customRules": rules, "managedRules": {"managedRuleSets": []},
                  "policySettings": {"state": "Enabled", "mode": "Prevention"}})
        self.policy = {"name": AZ_POLICY, "location": "Global", "properties": props, "etag": self._new_etag()}
        self.tokens_issued = 0

    def _new_etag(self) -> str:
        return f'W/"{next(self._etag)}"'

    def rules(self) -> list[dict]:
        cr = self.policy["properties"]["customRules"]
        return cr["rules"] if self.flavor == "frontdoor" else cr

    def values(self, rule_name: str) -> list[str]:
        r = next((r for r in self.rules() if r["name"] == rule_name), None)
        if r is None:
            return []
        c = r["matchConditions"][0]
        return list(c.get("matchValue") or c.get("matchValues") or [])

    def handle(self, method: str, url: str, body, headers: dict) -> HttpResult:
        path = url.split("?", 1)[0]
        if "/oauth2/v2.0/token" in path and isinstance(body, RawBody):
            form = body.form()
            if form.get("grant_type") != "client_credentials" or form.get("client_secret") != "mock-secret":
                return HttpResult(401, {"error": "invalid_client", "error_description": "bad secret"})
            self.tokens_issued += 1
            return HttpResult(200, {"access_token": self.token, "expires_in": 3599, "token_type": "Bearer"})
        if headers.get("Authorization") != f"Bearer {self.token}":
            return HttpResult(401, {"error": {"code": "InvalidAuthenticationToken", "message": "token invalid"}})
        m = self._POLICY.search(path)
        if not m or m.group("name") != AZ_POLICY:
            return HttpResult(404, {"error": {"code": "ResourceNotFound", "message": "policy not found"}})
        want_kind = "FrontDoor" if self.flavor == "frontdoor" else "ApplicationGateway"
        if not m.group("kind").startswith(want_kind):
            return HttpResult(404, {"error": {"code": "ResourceNotFound", "message": "wrong resource type"}})
        if method == "GET":
            return HttpResult(200, copy.deepcopy(self.policy))
        if method == "PUT":
            if self.race_next > 0:
                self.race_next -= 1
                self.policy["etag"] = self._new_etag()
            if headers.get("If-Match") and headers["If-Match"] != self.policy["etag"]:
                return HttpResult(412, {"error": {"code": "PreconditionFailed", "message": "etag mismatch"}})
            err = self._validate(body)
            if err:
                return HttpResult(400, {"error": {"code": "BadRequest", "message": err}})
            self.policy = copy.deepcopy(body)
            self.policy["etag"] = self._new_etag()
            return HttpResult(200 if self.flavor == "appgw" else 202, copy.deepcopy(self.policy))
        return HttpResult(405, {"error": {"code": "MethodNotAllowed", "message": method}})

    def _validate(self, policy: dict) -> str:
        cr = (policy.get("properties") or {}).get("customRules")
        rules = (cr or {}).get("rules") if self.flavor == "frontdoor" else cr
        if not isinstance(rules, list):
            return "customRules malformed"
        prios = [r.get("priority") for r in rules]
        if len(prios) != len(set(prios)):
            return "custom rule priorities must be unique"
        for r in rules:
            if not re.fullmatch(r"[A-Za-z][A-Za-z0-9]{0,127}", str(r.get("name", ""))):
                return f"invalid rule name {r.get('name')!r}"
            for c in r.get("matchConditions") or []:
                vals = c.get("matchValue") if self.flavor == "frontdoor" else c.get("matchValues")
                if not vals:
                    return f"rule {r['name']}: matchValue must not be empty"
            if r.get("ruleType") == "RateLimitRule" and not r.get("rateLimitThreshold"):
                return f"rule {r['name']}: rateLimitThreshold required"
        return ""


__all__ = ["MockCloudflare", "MockAwsWaf", "MockAzureWaf", "CF_BASE", "AWS_ENDPOINT", "AWS_KEY", "AWS_SECRET",
           "AZ_ARM", "AZ_SUB", "AZ_RG", "AZ_POLICY", "AZ_TOKEN"]
