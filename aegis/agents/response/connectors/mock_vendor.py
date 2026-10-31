"""In-process fake vendor tenants (roadmap 1.2 — "mock the tenant on our knowledge of the API").

Each mock is a ``transport`` implementing the exact endpoints the real
connector calls, **with state** (rules, exceptions, incidents, runs) and
switchable failure modes (bad credentials, 429 with Retry-After, 5xx, a
dropped connection). ``AEGIS_WAF_VENDOR=mock`` / ``AEGIS_SOAR_VENDOR=mock``
run the *real* connector classes against these, so the whole chain —
ResponseAgent → connector → receipt → dashboard → shadow report — can be
exercised before a tenant exists, and the day the tenant arrives only the
credentials change.

They prove our plumbing, not vendor behaviour: field names follow the public
docs as of mid-2026 and may need a one-line adjustment against a real tenant.
"""

from __future__ import annotations

import itertools
import re
from typing import Optional
from urllib.parse import parse_qsl

from .http import HttpResult


class _MockBase:
    def __init__(self):
        self.calls: list[tuple[str, str, Optional[dict]]] = []
        self.fail_next: list[int] = []      # HTTP statuses to answer with before behaving
        self.drop_next: int = 0             # raise ConnectionError this many times first
        self._ids = itertools.count(1001)

    def _gate(self) -> Optional[HttpResult]:
        if self.drop_next > 0:
            self.drop_next -= 1
            raise ConnectionError("mock vendor: connection reset")
        if self.fail_next:
            status = self.fail_next.pop(0)
            headers = {"Retry-After": "0"} if status == 429 else {}
            return HttpResult(status, {"message": f"mock vendor injected HTTP {status}"}, headers)
        return None

    def __call__(self, method: str, url: str, body: Optional[dict], headers: dict, timeout: float) -> HttpResult:
        self.calls.append((method, url, body))
        gated = self._gate()
        if gated is not None:
            return gated
        return self.handle(method, url, body or {}, headers or {})

    def handle(self, method: str, url: str, body: dict, headers: dict) -> HttpResult:  # pragma: no cover
        raise NotImplementedError


class MockImperva(_MockBase):
    """Imperva Cloud WAF Rules API v2: POST/DELETE /api/prov/v2/sites/{site}/rules[/{id}]."""

    _RULES = re.compile(r"/api/prov/v2/sites/(?P<site>[^/]+)/rules(?:/(?P<rule>[^/?]+))?$")

    def __init__(self, api_id: str = "mock", api_key: str = "mock"):
        super().__init__()
        self.api_id, self.api_key = api_id, api_key
        self.rules: dict[str, dict] = {}

    def handle(self, method: str, url: str, body: dict, headers: dict) -> HttpResult:
        if headers.get("x-API-Id") != self.api_id or headers.get("x-API-Key") != self.api_key:
            return HttpResult(401, {"res": 9413, "res_message": "Authentication missing or invalid"})
        m = self._RULES.search(url.split("?", 1)[0])
        if not m:
            return HttpResult(404, {"message": "unknown endpoint"})
        site, rule = m.group("site"), m.group("rule")
        if method == "POST" and not rule:
            if not body.get("filter") or body.get("action") not in {
                "RULE_ACTION_ALERT", "RULE_ACTION_BLOCK", "RULE_ACTION_BLOCK_USER", "RULE_ACTION_BLOCK_IP",
                "RULE_ACTION_CAPTCHA", "RULE_ACTION_RATE", "RULE_ACTION_RETRY", "RULE_ACTION_INTRUSIVE_HTML",
            }:
                return HttpResult(400, {"message": "invalid rule", "errors": [{"field": "action"}]})
            if body.get("action") == "RULE_ACTION_RATE" and not all(k in body for k in ("rate_context", "rate_interval", "rate_limit")):
                return HttpResult(400, {"message": "rate rule needs rate_context, rate_interval, rate_limit"})
            rid = str(next(self._ids))
            self.rules[rid] = {"site_id": site, **body}
            return HttpResult(200, {"rule_id": int(rid), "name": body.get("name"), "enabled": True})
        if method == "DELETE" and rule:
            if self.rules.pop(rule, None) is None:
                return HttpResult(404, {"message": "rule not found"})
            return HttpResult(200, {"res": 0, "res_message": "OK"})
        if method == "GET" and not rule:
            return HttpResult(200, {"rules": [{"rule_id": int(k), **v} for k, v in self.rules.items() if v["site_id"] == site]})
        return HttpResult(405, {"message": "method not allowed"})

    def blocked_ips(self) -> set[str]:
        out = set()
        for r in self.rules.values():
            if r.get("action") == "RULE_ACTION_BLOCK_IP":
                out.add(r["filter"].split("==", 1)[1].strip())
        return out


class MockF5(_MockBase):
    """BIG-IP iControl REST: token login + ASM policy IP-address exceptions."""

    _IPS = re.compile(r"/mgmt/tm/asm/policies/(?P<policy>[^/]+)/whitelist-ips(?:/(?P<entry>[^/?]+))?$")

    def __init__(self, username: str = "admin", password: str = "secret", token_ttl_calls: int = 10_000):
        super().__init__()
        self.username, self.password = username, password
        self.tokens: dict[str, int] = {}      # token → remaining calls (expiry simulation)
        self.token_ttl_calls = token_ttl_calls
        self.entries: dict[str, dict] = {}

    def handle(self, method: str, url: str, body: dict, headers: dict) -> HttpResult:
        path = url.split("?", 1)[0]
        if path.endswith("/mgmt/shared/authn/login") and method == "POST":
            if body.get("username") != self.username or body.get("password") != self.password:
                return HttpResult(401, {"message": "Authentication failed"})
            tok = f"tok-{next(self._ids)}"
            self.tokens[tok] = self.token_ttl_calls
            return HttpResult(200, {"token": {"token": tok, "timeout": 1200}})
        tok = headers.get("X-F5-Auth-Token", "")
        if tok not in self.tokens or self.tokens[tok] <= 0:
            self.tokens.pop(tok, None)
            return HttpResult(401, {"message": "X-F5-Auth-Token does not exist or has expired"})
        self.tokens[tok] -= 1
        m = self._IPS.search(path)
        if not m:
            return HttpResult(404, {"message": "unknown endpoint"})
        policy, entry = m.group("policy"), m.group("entry")
        if method == "POST" and not entry:
            if not body.get("ipAddress"):
                return HttpResult(400, {"message": "ipAddress is required"})
            eid = str(next(self._ids))
            self.entries[eid] = {"policy": policy, **body}
            return HttpResult(201, {"id": eid, "ipAddress": body["ipAddress"], "ipMask": body.get("ipMask"),
                                    "blockRequests": body.get("blockRequests", "policy-default")})
        if method == "DELETE" and entry:
            if self.entries.pop(entry, None) is None:
                return HttpResult(404, {"message": "not found"})
            return HttpResult(200, {})
        return HttpResult(405, {"message": "method not allowed"})

    def blocked_ips(self) -> set[str]:
        return {e["ipAddress"] for e in self.entries.values() if e.get("blockRequests") == "always"}


class MockXsoar(_MockBase):
    """Cortex XSOAR: POST /incident creates an incident and 'runs' its playbook."""

    def __init__(self, api_key: str = "mock", known_playbooks: Optional[set[str]] = None):
        super().__init__()
        self.api_key = api_key
        self.known_playbooks = known_playbooks
        self.incidents: dict[str, dict] = {}

    def handle(self, method: str, url: str, body: dict, headers: dict) -> HttpResult:
        if headers.get("Authorization") != self.api_key:
            return HttpResult(401, {"error": "Unauthorized", "detail": "invalid API key"})
        path = url.split("?", 1)[0]
        if path.endswith("/incident") and method == "POST":
            pb = body.get("playbookId")
            if self.known_playbooks is not None and pb not in self.known_playbooks:
                return HttpResult(400, {"error": f"playbook {pb!r} not found"})
            iid = str(next(self._ids))
            self.incidents[iid] = {**body, "status": "running" if pb else "pending", "id": iid}
            return HttpResult(201, {"id": iid, "name": body.get("name"), "playbookId": pb, "status": 1})
        return HttpResult(404, {"error": "unknown endpoint"})

    def runs_of(self, playbook: str) -> list[dict]:
        return [i for i in self.incidents.values() if i.get("playbookId") == playbook]


class MockLogicApp(_MockBase):
    """A Sentinel playbook's HTTP trigger: POST → 202 + x-ms-workflow-run-id."""

    def __init__(self, valid_sig: str = "sig=ok"):
        super().__init__()
        self.valid_sig = valid_sig
        self.runs: list[dict] = []

    def handle(self, method: str, url: str, body: dict, headers: dict) -> HttpResult:
        if method != "POST":
            return HttpResult(405, {"message": "method not allowed"})
        if self.valid_sig and self.valid_sig not in url:
            return HttpResult(401, {"error": {"code": "DirectApiAuthorizationRequired", "message": "missing or invalid signature"}})
        run_id = f"0858{next(self._ids):012d}"
        self.runs.append({"run_id": run_id, "url": url.split("?", 1)[0], **body})
        return HttpResult(202, "", {"x-ms-workflow-run-id": run_id})


class MockZscaler(_MockBase):
    """Zscaler ZIA: PUT /zia/api/v1/urlCategories/{id}?action=ADD_TO_LIST|REMOVE_FROM_LIST."""

    _CAT = re.compile(r"/zia/api/v1/urlCategories/(?P<cat>[^/?]+)$")

    def __init__(self, token: str = "mock"):
        super().__init__()
        self.token = token
        self.categories: dict[str, set[str]] = {}

    def handle(self, method: str, url: str, body: dict, headers: dict) -> HttpResult:
        if headers.get("Authorization") != f"Bearer {self.token}":
            return HttpResult(401, {"message": "authentication failed"})
        path, _, q = url.partition("?")
        m = self._CAT.search(path)
        if not m:
            return HttpResult(404, {"message": "unknown endpoint"})
        action = dict(parse_qsl(q)).get("action", "")
        cur = self.categories.setdefault(m.group("cat"), set())
        urls = [str(u) for u in (body.get("urls") or [])]
        if method == "PUT" and action == "ADD_TO_LIST":
            cur.update(urls)
            return HttpResult(200, {"id": m.group("cat"), "configuredName": body.get("configuredName"), "urls": sorted(cur)})
        if method == "PUT" and action == "REMOVE_FROM_LIST":
            cur.difference_update(urls)
            return HttpResult(200, {"id": m.group("cat"), "urls": sorted(cur)})
        return HttpResult(400, {"message": "action must be ADD_TO_LIST or REMOVE_FROM_LIST"})

    def blocked(self) -> set[str]:
        out: set[str] = set()
        for s in self.categories.values():
            out |= s
        return out


class MockCrowdStrike(_MockBase):
    """CrowdStrike Falcon: OAuth token, hostname→device query, contain/lift, RTR kill."""

    def __init__(self, token: str = "mock-cs-token", hosts: Optional[dict[str, str]] = None):
        super().__init__()
        self.token = token
        self.hosts = hosts or {"app-ledger-07": "a" * 32, "db-core": "b" * 32}   # hostname → aid
        self.contained: set[str] = set()
        self.kills: list[dict] = []

    def handle(self, method: str, url: str, body: dict, headers: dict) -> HttpResult:
        path, _, q = url.partition("?")
        params = dict(parse_qsl(q))
        if path.endswith("/oauth2/token") and method == "POST":
            return HttpResult(201, {"access_token": self.token, "expires_in": 1799})
        if headers.get("Authorization") != f"Bearer {self.token}":
            return HttpResult(401, {"errors": [{"message": "access denied"}]})
        if path.endswith("/devices/queries/devices/v1") and method == "GET":
            host = params.get("filter", "").split("hostname:'")[-1].rstrip("'")
            aid = self.hosts.get(host)
            return HttpResult(200, {"resources": [aid] if aid else []})
        if path.endswith("/devices/entities/devices-actions/v2") and method == "POST":
            ids = body.get("ids") or []
            action = params.get("action_name")
            if action == "contain":
                self.contained.update(ids)
            elif action == "lift_containment":
                self.contained.difference_update(ids)
            else:
                return HttpResult(400, {"errors": [{"message": f"unknown action_name {action!r}"}]})
            return HttpResult(202, {"resources": [{"id": i} for i in ids]})
        if path.endswith("/real-time-response/combined/batch-init-session/v1") and method == "POST":
            bid = f"batch-{next(self._ids)}"
            return HttpResult(201, {"batch_id": bid, "resources": {h: {"session_id": f"sess-{next(self._ids)}"}
                                                                   for h in (body.get("host_ids") or [])}})
        if path.endswith("/real-time-response/combined/batch-command/v1") and method == "POST":
            self.kills.append(body)
            return HttpResult(201, {"batch_id": body.get("batch_id"), "combined": {"resources": {}}})
        return HttpResult(404, {"errors": [{"message": "unknown endpoint"}]})


__all__ = ["MockImperva", "MockF5", "MockXsoar", "MockLogicApp", "MockZscaler", "MockCrowdStrike"]
