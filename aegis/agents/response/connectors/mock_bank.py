"""In-process fakes of the bank-stack vendors (integration plan #5), behind the real connector classes.

Stateful, auth-checking, shaped like the public APIs: PAN-OS XML API (User-ID DAG tags), FortiGate REST (banned
IPs), Defender for Endpoint (machines / machine actions), SentinelOne (agents / actions), Microsoft Graph (users),
CyberArk PVWA (logon / accounts / change). ``AEGIS_*_VENDOR=mock…`` and the tests use them.
"""

from __future__ import annotations

import re
import time
from urllib.parse import parse_qsl, unquote

from .http import HttpResult, RawBody
from .mock_vendor import _MockBase


def _form(body: object) -> dict:
    return body.form() if isinstance(body, RawBody) else (body if isinstance(body, dict) else {})


class MockPanos(_MockBase):
    def __init__(self, key: str = "mock-pan-key"):
        super().__init__()
        self.key = key
        self.tags: dict[str, dict[str, int]] = {}            # ip -> {tag: timeout}

    def handle(self, method: str, url: str, body: dict, headers: dict) -> HttpResult:
        if headers.get("X-PAN-KEY") != self.key:
            return HttpResult(403, '<response status="error" code="403"><result><msg>Invalid credentials.</msg></result></response>')
        if not url.endswith("/api/") or method != "POST":
            return HttpResult(404, "")
        f = _form(body)
        cmd = f.get("cmd", "")
        if f.get("type") == "user-id":
            for op, ip, inner in re.findall(r"<(register|unregister)><entry ip=\"([^\"]+)\"[^>]*><tag>(.*?)</tag>", cmd):
                for timeout, tag in re.findall(r"<member(?: timeout=\"(\d+)\")?>([^<]+)</member>", inner):
                    if op == "register":
                        self.tags.setdefault(ip, {})[tag] = int(timeout or 0)
                    else:
                        self.tags.get(ip, {}).pop(tag, None)
            return HttpResult(200, '<response status="success"><result><uid-response><payload/></uid-response></result></response>')
        if f.get("type") == "op" and "<registered-ip>" in cmd:
            ip = re.search(r"<ip>([^<]+)</ip>", cmd).group(1)
            members = "".join(f"<member>{t}</member>" for t in self.tags.get(ip, {}))
            return HttpResult(200, f'<response status="success"><result><entry ip="{ip}"><tag>{members}</tag></entry></result></response>')
        return HttpResult(200, '<response status="error"><msg>unsupported</msg></response>')


class MockFortiGate(_MockBase):
    def __init__(self, token: str = "mock-fgt-token"):
        super().__init__()
        self.token = token
        self.banned: dict[str, int] = {}

    def handle(self, method: str, url: str, body: dict, headers: dict) -> HttpResult:
        if headers.get("Authorization") != f"Bearer {self.token}":
            return HttpResult(401, {"status": "error", "http_status": 401})
        path = url.split("?", 1)[0]
        if path.endswith("/user/banned/add_users") and method == "POST":
            for ip in body.get("ip_addresses") or []:
                self.banned[ip] = int(body.get("expiry") or 0)
            return HttpResult(200, {"status": "success"})
        if path.endswith("/user/banned/clear_users") and method == "POST":
            for ip in body.get("ip_addresses") or []:
                self.banned.pop(ip, None)
            return HttpResult(200, {"status": "success"})
        if path.endswith("/user/banned") and method == "GET":
            return HttpResult(200, {"status": "success", "results": [
                {("ipv6_address" if ":" in ip else "ipv4_address"): ip, "expires": e} for ip, e in self.banned.items()]})
        return HttpResult(404, {"status": "error"})


class MockDefender(_MockBase):
    def __init__(self, token: str = "mock-mde-token", machines: dict[str, str] | None = None):
        super().__init__()
        self.token = token
        self.machines = machines or {"app-ledger-07.bank.local": "a1" * 20, "db-core.bank.local": "b2" * 20}
        self.actions: list[dict] = []

    def _isolated(self, mid: str) -> bool:
        acts = [a for a in self.actions if a["machineId"] == mid]
        return bool(acts) and acts[-1]["type"] == "Isolate"

    def handle(self, method: str, url: str, body: dict, headers: dict) -> HttpResult:
        if headers.get("Authorization") != f"Bearer {self.token}":
            return HttpResult(401, {"error": {"code": "Unauthorized"}})
        path, _, q = url.partition("?")
        flt = unquote(dict(parse_qsl(q)).get("$filter", ""))
        if path.endswith("/api/machines") and method == "GET":
            m = re.search(r"computerDnsName eq '([^']+)'", flt)
            if m:
                return HttpResult(200, {"value": [{"id": i, "computerDnsName": n} for n, i in self.machines.items() if n == m.group(1)]})
            m = re.search(r"startswith\(computerDnsName,'([^']+)'\)", flt)
            pre = m.group(1) if m else "\0"
            return HttpResult(200, {"value": [{"id": i, "computerDnsName": n} for n, i in self.machines.items() if n.startswith(pre)]})
        m = re.search(r"/api/machines/([0-9a-f]{40})/(isolate|unisolate)$", path)
        if m and method == "POST":
            mid, what = m.groups()
            if mid not in self.machines.values():
                return HttpResult(404, {"error": {"code": "ResourceNotFound"}})
            if what == "isolate" and self._isolated(mid):
                return HttpResult(400, {"error": {"code": "ActiveRequestAlreadyExists", "message": "Action is already in progress"}})
            act = {"id": f"act-{next(self._ids)}", "machineId": mid, "type": "Isolate" if what == "isolate" else "Unisolate",
                   "status": "Succeeded", "creationDateTimeUtc": f"2026-11-04T00:{len(self.actions):02d}:00Z"}
            self.actions.append(act)
            return HttpResult(201, act)
        if path.endswith("/api/machineactions") and method == "GET":
            m = re.search(r"machineId eq '([0-9a-f]{40})'", flt)
            return HttpResult(200, {"value": [a for a in self.actions if m and a["machineId"] == m.group(1)]})
        return HttpResult(404, {"error": {"code": "NotFound"}})


class MockSentinelOne(_MockBase):
    def __init__(self, token: str = "mock-s1-token", agents: dict[str, str] | None = None):
        super().__init__()
        self.token = token
        self.agents = agents or {"app-ledger-07": "1001", "db-core": "1002"}
        self.disconnected: set[str] = set()

    def handle(self, method: str, url: str, body: dict, headers: dict) -> HttpResult:
        if headers.get("Authorization") != f"ApiToken {self.token}":
            return HttpResult(401, {"errors": [{"title": "Authentication Failed"}]})
        path, _, q = url.partition("?")
        params = dict(parse_qsl(q))
        if path.endswith("/agents") and method == "GET":
            if "computerName" in params:
                return HttpResult(200, {"data": [{"id": i, "computerName": n} for n, i in self.agents.items() if n == params["computerName"]]})
            ids = params.get("ids", "")
            return HttpResult(200, {"data": [{"id": i, "networkStatus": "disconnected" if i in self.disconnected else "connected"}
                                             for i in self.agents.values() if i == ids]})
        m = re.search(r"/agents/actions/(disconnect|connect)$", path)
        if m and method == "POST":
            ids = [i for i in ((body.get("filter") or {}).get("ids") or []) if i in self.agents.values()]
            (self.disconnected.update if m.group(1) == "disconnect" else self.disconnected.difference_update)(ids)
            return HttpResult(200, {"data": {"affected": len(ids)}})
        return HttpResult(404, {"errors": [{"title": "Not Found"}]})


class MockEntra(_MockBase):
    def __init__(self, token: str = "mock-graph-token", users: dict[str, dict] | None = None):
        super().__init__()
        self.token = token
        self.users = users or {
            "priya.sharma@bank.in": {"id": "u-1001", "accountEnabled": True},
            "svc_loan@bank.in": {"id": "u-1002", "accountEnabled": True},
            "breakglass@bank.in": {"id": "u-1003", "accountEnabled": True},
            "old.leaver@bank.in": {"id": "u-1004", "accountEnabled": False}}
        self.revoked: list[str] = []

    def _by(self, ref: str) -> tuple[str, dict] | None:
        ref = unquote(ref).lower()
        for upn, u in self.users.items():
            if upn == ref or u["id"] == ref:
                return upn, u
        return None

    def handle(self, method: str, url: str, body: dict, headers: dict) -> HttpResult:
        if headers.get("Authorization") != f"Bearer {self.token}":
            return HttpResult(401, {"error": {"code": "InvalidAuthenticationToken"}})
        path = url.split("?", 1)[0]
        m = re.search(r"/users/([^/]+)(/revokeSignInSessions)?$", path)
        if not m:
            return HttpResult(404, {"error": {"code": "Request_ResourceNotFound"}})
        found = self._by(m.group(1))
        if found is None:
            return HttpResult(404, {"error": {"code": "Request_ResourceNotFound"}})
        upn, u = found
        if m.group(2) and method == "POST":
            self.revoked.append(upn)
            return HttpResult(200, {"value": True})
        if method == "GET":
            return HttpResult(200, {"id": u["id"], "userPrincipalName": upn, "accountEnabled": u["accountEnabled"]})
        if method == "PATCH":
            if "accountEnabled" in body:
                u["accountEnabled"] = bool(body["accountEnabled"])
            return HttpResult(204, None)
        return HttpResult(405, {"error": {"code": "MethodNotAllowed"}})


class MockCyberArk(_MockBase):
    def __init__(self, username: str = "aegis", password: str = "mock"):
        super().__init__()
        self._user, self._pw = username, password
        self.token = "mock-pvwa-session"
        self.accounts = [
            {"id": "12_3", "userName": "svc_loan", "address": "db-core.bank.local", "platformId": "WinDomain"},
            {"id": "12_4", "userName": "svc_batch", "address": "app-ledger-07.bank.local", "platformId": "UnixSSH"},
            {"id": "12_5", "userName": "svc_batch", "address": "db-core.bank.local", "platformId": "UnixSSH"}]
        self.changed: dict[str, float] = {}
        self.logons = 0

    def handle(self, method: str, url: str, body: dict, headers: dict) -> HttpResult:
        path, _, q = url.partition("?")
        if path.endswith("/auth/CyberArk/Logon") and method == "POST":
            if body.get("username") != self._user or body.get("password") != self._pw:
                return HttpResult(403, {"ErrorCode": "PASWS013E", "ErrorMessage": "Authentication failure"})
            self.logons += 1
            return HttpResult(200, self.token)
        if headers.get("Authorization") != self.token:
            return HttpResult(401, {"ErrorCode": "PASWS006E"})
        if path.endswith("/API/Accounts") and method == "GET":
            s = dict(parse_qsl(q)).get("search", "").lower()
            rows = [a for a in self.accounts if s in a["userName"].lower()]
            return HttpResult(200, {"value": rows, "count": len(rows)})
        m = re.search(r"/API/Accounts/([^/]+)(/Change)?$", path)
        if m:
            acct = next((a for a in self.accounts if a["id"] == unquote(m.group(1))), None)
            if acct is None:
                return HttpResult(404, {"ErrorCode": "PASWS165E"})
            if m.group(2) and method == "POST":
                self.changed[acct["id"]] = time.time()
                return HttpResult(200, None)
            if method == "GET":
                return HttpResult(200, {**acct, "secretManagement": {"automaticManagementEnabled": True, "status": "success",
                                                                     "lastModifiedTime": int(self.changed.get(acct["id"], 1_700_000_000))}})
        return HttpResult(404, {"ErrorCode": "PASWS000E"})


class MockTrend(_MockBase):
    def __init__(self, token: str = "mock-trend-token", endpoints: dict[str, str] | None = None):
        super().__init__()
        self.token = token
        self.endpoints = endpoints or {"app-ledger-07": "11111111-2222-3333-4444-555555555555",
                                       "db-core": "66666666-7777-8888-9999-000000000000"}
        self.isolated: set[str] = set()
        self.tasks: dict[str, str] = {}

    def handle(self, method: str, url: str, body: object, headers: dict) -> HttpResult:
        if headers.get("Authorization") != f"Bearer {self.token}":
            return HttpResult(401, {"error": {"code": "NotAuthenticated"}})
        path = url.split("?", 1)[0]
        if path.endswith("/v3.0/endpointSecurity/endpoints") and method == "GET":
            m = re.search(r"endpointName eq '([^']+)'", headers.get("TMV1-Query", ""))
            name = m.group(1) if m else ""
            return HttpResult(200, {"items": [{"agentGuid": g, "endpointName": n} for n, g in self.endpoints.items() if n == name]})
        m = re.search(r"/v3.0/response/endpoints/(isolate|restore)$", path)
        if m and method == "POST":
            out = []
            for item in body if isinstance(body, list) else []:
                g = item.get("agentGuid")
                if g not in self.endpoints.values():
                    out.append({"status": 400, "body": {"error": {"code": "InvalidAgent"}}})
                    continue
                (self.isolated.add if m.group(1) == "isolate" else self.isolated.discard)(g)
                tid = f"00000{next(self._ids)}"
                self.tasks[tid] = "succeeded"
                out.append({"status": 202, "headers": [{"name": "Operation-Location",
                                                        "value": f"https://trend.mock/v3.0/response/tasks/{tid}"}]})
            return HttpResult(207, out)
        m = re.search(r"/v3.0/response/tasks/([^/]+)$", path)
        if m and method == "GET":
            st = self.tasks.get(m.group(1))
            return HttpResult(200, {"id": m.group(1), "status": st}) if st else HttpResult(404, {"error": {"code": "NotFound"}})
        return HttpResult(404, {"error": {"code": "NotFound"}})


class MockDirectory:
    """Stands in for ``identity.Directory`` (LDAP search / replace) over an in-memory user set."""

    def __init__(self):
        self.users = {
            "CN=Priya Sharma,OU=Staff,DC=bank,DC=local": {"sAMAccountName": "priya.sharma", "userPrincipalName": "priya.sharma@bank.local", "userAccountControl": 512},
            "CN=svc_loan,OU=Service,DC=bank,DC=local": {"sAMAccountName": "svc_loan", "userPrincipalName": "svc_loan@bank.local", "userAccountControl": 66048},
            "CN=Old Leaver,OU=Staff,DC=bank,DC=local": {"sAMAccountName": "old.leaver", "userPrincipalName": "old.leaver@bank.local", "userAccountControl": 514},
            "CN=Administrator,CN=Users,DC=bank,DC=local": {"sAMAccountName": "Administrator", "userPrincipalName": "", "userAccountControl": 512},
        }
        self.filters: list[str] = []

    def search(self, base: str, flt: str, attrs: list[str]) -> list[tuple[str, dict]]:
        self.filters.append(flt)
        m = re.search(r"\(sAMAccountName=([^)]*)\)", flt)
        want = (m.group(1) if m else "").lower()
        return [(dn, {a: u.get(a) for a in attrs}) for dn, u in self.users.items()
                if want and want in (u["sAMAccountName"].lower(), u["userPrincipalName"].lower())]

    def replace(self, dn: str, attr: str, value: object) -> None:
        self.users[dn][attr] = value


class MockPaymentHub(_MockBase):
    """A bank's adapter for the AEGIS Payment Hold API: checks the bearer token and the request signature, holds
    accounts / transfers, refuses transfers that already settled."""

    def __init__(self, token: str = "mock-payhub-token", key: bytes = b"mock-payhub-signing-key-0123456789"):
        super().__init__()
        self.token, self.key = token, key
        self.holds: dict[str, dict] = {}
        self.settled = {"TXN-SETTLED-1"}
        self.rejected_signatures = 0

    def __call__(self, method: str, url: str, body: object, headers: dict, timeout: float) -> HttpResult:
        from .payhold import verify_signature
        raw = bytes(body) if isinstance(body, (bytes, bytearray)) else b""
        if headers.get("Authorization") != f"Bearer {self.token}":
            return HttpResult(401, {"error": "unauthorized"})
        if not verify_signature(self.key, headers.get("X-AEGIS-Timestamp", ""), raw, headers.get("X-AEGIS-Signature", "")):
            self.rejected_signatures += 1
            return HttpResult(401, {"error": "bad signature"})
        return super().__call__(method, url, body.json() if isinstance(body, RawBody) else None, headers, timeout)

    def handle(self, method: str, url: str, body: dict, headers: dict) -> HttpResult:
        path = url.split("?", 1)[0]
        if path.endswith("/holds") and method == "POST":
            if body.get("scope") == "transaction" and body.get("ref") in self.settled:
                return HttpResult(409, {"state": "settled"})
            for hid, h in self.holds.items():
                if h["idempotency_key"] == body.get("idempotency_key") and h["state"] == "active":
                    h["expires_at"] = body.get("expires_at")
                    return HttpResult(200, {"hold_id": hid, "state": "active"})
            hid = f"H{next(self._ids)}"
            self.holds[hid] = {**body, "state": "active"}
            return HttpResult(201, {"hold_id": hid, "state": "active"})
        m = re.search(r"/holds/([^/]+)$", path)
        if m:
            h = self.holds.get(unquote(m.group(1)))
            if h is None:
                return HttpResult(404, {"error": "unknown hold"})
            if method == "DELETE":
                h["state"] = "released"
                return HttpResult(200, {"state": "released"})
            if method == "GET":
                return HttpResult(200, {"hold_id": m.group(1), "state": h["state"]})
        return HttpResult(404, {"error": "not found"})


__all__ = ["MockCyberArk", "MockDefender", "MockDirectory", "MockEntra", "MockFortiGate", "MockPanos", "MockPaymentHub", "MockSentinelOne",
           "MockTrend"]
