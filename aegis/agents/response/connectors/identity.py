"""Identity and privileged-access connectors — Microsoft Entra ID and CyberArk (integration plan #5).

A stolen credential works from anywhere, so the control point that stops it is the identity provider, not a host.

**Entra ID** (Microsoft Graph, application permissions ``User.RevokeSessions.All`` + ``User.EnableDisableAccount.All``):

* ``revoke_sessions`` / ``force_logout`` — ``POST /users/{upn}/revokeSignInSessions``: every refresh token and
  session cookie is invalidated, so the attacker must sign in again (and meet MFA / Conditional Access). One-shot:
  nothing to undo.
* ``lock_account`` — ``PATCH /users/{id} {"accountEnabled": false}``, then a session revoke (a disabled account's
  live tokens otherwise keep working until they expire). The state before is saved: undo re-enables the account
  only if AEGIS disabled it. Read-back: ``accountEnabled`` is false.

**CyberArk PVWA** (``rotate_credential``) — ``POST /PasswordVault/API/Accounts/{id}/Change``: the CPM rotates a
vaulted service / privileged account password at once, so a leaked secret stops working. Irreversible by nature
(the old password is gone), so the receipt is permanent; the action is two-person in the response agent. The
account must resolve to exactly one vault account (``account:<user>`` or ``account:<user>@<address>``), never a
guess. Read-back: the account's last-modified time moved past the request (``None`` while the CPM is still working).

Both refuse principals on ``AEGIS_IDP_PROTECTED`` (break-glass / emergency-access accounts, comma list): locking
those out is how an attacker turns a defence into an outage. Mock tenants: ``mock_bank.MockEntra`` /
``MockCyberArk`` (``AEGIS_IDP_VENDOR=mock``, ``AEGIS_PAM_VENDOR=mock``).
"""

from __future__ import annotations

import logging
import os
import re
import threading
import time
from collections.abc import Callable
from typing import Any
from urllib.parse import quote, urlencode

from .base import CannotUndo, Connector, ConnectorError, Receipt
from .http import Transport, call, httpx_transport

logger = logging.getLogger("aegis.connectors.identity")

GRAPH = "https://graph.microsoft.com/v1.0"
GRAPH_SCOPE = "https://graph.microsoft.com/.default"
_PRINCIPAL = re.compile(r"^[A-Za-z0-9._%+'-]{1,64}(@[A-Za-z0-9.-]{1,190})?$")
_PREFIXES = ("user:", "principal:", "account:", "upn:")


def _principal(target: str) -> str:
    t = str(target).strip()
    for p in _PREFIXES:
        if t.lower().startswith(p):
            t = t[len(p):].strip()
            break
    if not _PRINCIPAL.match(t):
        raise ConnectorError(f"not a user principal: {target!r}")
    return t


def _protected() -> set[str]:
    return {x.strip().lower() for x in os.environ.get("AEGIS_IDP_PROTECTED", "").split(",") if x.strip()}


def _refuse_protected(who: str) -> None:
    low = who.lower()
    if low in _protected() or low.split("@", 1)[0] in _protected():
        raise ConnectorError(f"{who} is a protected (break-glass) principal on AEGIS_IDP_PROTECTED; a person acts on it")


class EntraConnector(Connector):
    """Microsoft Entra ID: revoke sessions, disable / re-enable an account."""

    name = "entra"
    actions = frozenset({"revoke_sessions", "force_logout", "lock_account"})

    def __init__(self, *, token_provider: Callable[[], str], base_url: str = GRAPH,
                 transport: Transport | None = None, **kw: Any):
        super().__init__(**kw)
        self.base_url = base_url.rstrip("/")
        self._token = token_provider
        self._transport = transport or httpx_transport

    def supports_target(self, target: str) -> bool:
        try:
            _principal(target)
            return True
        except ConnectorError:
            return False

    def apply(self, action: Any, **kw: Any) -> Receipt:
        if action.action_type in ("revoke_sessions", "force_logout"):
            kw["ttl_sec"] = 0                   # one-shot: permanent receipt, no TTL auto-rollback
        return super().apply(action, **kw)

    def _h(self) -> dict:
        return {"Authorization": f"Bearer {self._token()}", "Content-Type": "application/json"}

    def _user(self, upn: str) -> dict:
        res = call(self._transport, "GET",
                   f"{self.base_url}/users/{quote(upn, safe='@')}?$select=id,userPrincipalName,accountEnabled",
                   headers=self._h(), expect=(200, 404))
        if res.status == 404 or not res.json().get("id"):
            raise ConnectorError(f"no Entra user {upn}")
        return res.json()

    def _revoke(self, uid: str) -> None:
        call(self._transport, "POST", f"{self.base_url}/users/{quote(uid, safe='@')}/revokeSignInSessions",
             json_body={}, headers=self._h())

    def _do_apply(self, action: Any, key: str, ttl_sec: int | None) -> tuple[str, str, str]:
        upn = _principal(action.target)
        _refuse_protected(upn)
        user = self._user(upn)
        uid = str(user["id"])
        if action.action_type in ("revoke_sessions", "force_logout"):
            self._revoke(uid)
            return uid, f"[entra] revoked every sign-in session of {upn}: it must sign in again (MFA / CA apply)", ""
        was = "enabled" if user.get("accountEnabled", True) else "disabled"
        if was == "enabled":
            call(self._transport, "PATCH", f"{self.base_url}/users/{uid}", json_body={"accountEnabled": False},
                 headers=self._h(), expect=(200, 204))
        self._revoke(uid)                       # live tokens of a disabled account otherwise keep working
        note = "disabled" if was == "enabled" else "was already disabled"
        return uid, f"[entra] {upn} {note}; sessions revoked", was

    def _do_rollback(self, receipt: Receipt) -> str:
        if receipt.action_type != "lock_account":
            raise CannotUndo("a session revoke cannot be undone — the user simply signs in again")
        if receipt.rollback_token != "enabled":
            return f"[entra] {receipt.target} was already disabled before AEGIS acted; left disabled"
        call(self._transport, "PATCH", f"{self.base_url}/users/{receipt.vendor_ref}", json_body={"accountEnabled": True},
             headers=self._h(), expect=(200, 204))
        return f"[entra] re-enabled {receipt.target}"

    def _do_verify(self, receipt: Receipt) -> bool | None:
        if receipt.action_type != "lock_account":
            return None
        return self._user(receipt.vendor_ref or _principal(receipt.target)).get("accountEnabled") is False

    def _do_renew(self, receipt: Receipt, ttl_sec: int) -> str:
        if receipt.action_type == "lock_account":
            return f"[entra] {receipt.target} still disabled"
        return f"[entra] sessions of {receipt.target} already revoked; nothing to renew"


class _CyberArkSession:
    """PVWA logon token, reused for ten minutes."""

    def __init__(self, base_url: str, username: str, password: str, transport: Transport,
                 clock: Callable[[], float] = time.time):
        self.base_url, self._user, self._pw, self._t, self._clock = base_url, username, password, transport, clock
        self._tok, self._at = "", 0.0
        self._lock = threading.Lock()

    def __call__(self) -> str:
        with self._lock:
            if self._tok and self._clock() - self._at < 600:
                return self._tok
            res = call(self._t, "POST", f"{self.base_url}/PasswordVault/API/auth/CyberArk/Logon",
                       json_body={"username": self._user, "password": self._pw, "concurrentSession": True},
                       headers={"Content-Type": "application/json"}, retries=1)
            tok = res.body if isinstance(res.body, str) else ""
            if not tok:
                raise ConnectorError("CyberArk logon returned no session token")
            self._tok, self._at = tok.strip().strip('"'), self._clock()
            return self._tok


class CyberArkConnector(Connector):
    """CyberArk PVWA: immediate CPM password change of one vaulted account."""

    name = "cyberark"
    actions = frozenset({"rotate_credential"})

    def __init__(self, *, base_url: str, session: Callable[[], str], transport: Transport | None = None, **kw: Any):
        super().__init__(**kw)
        self.base_url = base_url.rstrip("/")
        self._session = session
        self._transport = transport or httpx_transport

    def supports_target(self, target: str) -> bool:
        t = str(target).strip()
        for p in _PREFIXES:
            if t.lower().startswith(p):
                t = t[len(p):]
                break
        return bool(re.match(r"^[A-Za-z0-9._%+$'-]{1,128}(@[A-Za-z0-9.-]{1,190})?$", t.strip()))

    def apply(self, action: Any, **kw: Any) -> Receipt:
        kw["ttl_sec"] = 0                         # a rotation is permanent: the old secret is gone
        return super().apply(action, **kw)

    def _h(self) -> dict:
        return {"Authorization": self._session(), "Content-Type": "application/json"}

    def _account(self, target: str) -> dict:
        t = str(target).strip()
        for p in _PREFIXES:
            if t.lower().startswith(p):
                t = t[len(p):].strip()
                break
        user, _, address = t.partition("@")
        res = call(self._transport, "GET",
                   f"{self.base_url}/PasswordVault/API/Accounts?{urlencode({'search': user, 'limit': 50})}",
                   headers=self._h())
        rows = [r for r in (res.json().get("value") or []) if isinstance(r, dict)
                and str(r.get("userName", "")).lower() == user.lower()
                and (not address or str(r.get("address", "")).lower() == address.lower())]
        if not rows:
            raise ConnectorError(f"no CyberArk account {t!r}")
        if len(rows) > 1:
            raise ConnectorError(f"{len(rows)} CyberArk accounts named {user!r}; say which: account:{user}@<address>")
        return rows[0]

    def _do_apply(self, action: Any, key: str, ttl_sec: int | None) -> tuple[str, str, str]:
        acct = self._account(action.target)
        who = f"{acct.get('userName')}@{acct.get('address')}"
        _refuse_protected(str(acct.get("userName", "")))
        aid = str(acct["id"])
        call(self._transport, "POST", f"{self.base_url}/PasswordVault/API/Accounts/{quote(aid, safe='')}/Change",
             json_body={"ChangeEntireGroup": False}, headers=self._h())
        return aid, f"[cyberark] immediate CPM password change requested for {who} (account {aid})", ""

    def _do_rollback(self, receipt: Receipt) -> str:
        raise CannotUndo("a password rotation cannot be undone — the old secret is gone; retrieve the new one from the vault")

    def _do_verify(self, receipt: Receipt) -> bool | None:
        res = call(self._transport, "GET",
                   f"{self.base_url}/PasswordVault/API/Accounts/{quote(receipt.vendor_ref, safe='')}", headers=self._h())
        sm = res.json().get("secretManagement") or {}
        if str(sm.get("status", "")).lower() == "failure":
            return False
        try:
            changed = float(sm.get("lastModifiedTime") or 0)
        except (TypeError, ValueError):
            return None
        return True if changed >= float(receipt.applied_at or 0) - 5 else None

    def _do_renew(self, receipt: Receipt, ttl_sec: int) -> str:
        return f"[cyberark] {receipt.target} already rotated; nothing to renew"


_UAC_DISABLED = 0x2


def _ldap_escape(v: str) -> str:
    """RFC 4515 filter escaping."""
    return "".join({"\\": r"\5c", "*": r"\2a", "(": r"\28", ")": r"\29", "\0": r"\00"}.get(c, c) for c in v)


class Directory:
    """The two LDAP operations the AD connector needs; the default speaks LDAPS through ``ldap3`` (optional)."""

    def __init__(self, url: str, bind_dn: str, password: str, *, timeout: int = 15):
        if not url.lower().startswith("ldaps://"):
            raise ValueError("AEGIS_AD_URL must be ldaps:// (account changes never go over cleartext LDAP)")
        self.url, self._dn, self._pw, self.timeout = url, bind_dn, password, timeout

    def _conn(self) -> Any:
        try:
            import ldap3  # type: ignore
        except ImportError:
            raise ConnectorError("ldap3 is not installed: pip install 'aegis[ad]'") from None
        server = ldap3.Server(self.url, use_ssl=True, connect_timeout=self.timeout)
        return ldap3.Connection(server, user=self._dn, password=self._pw, auto_bind=True, receive_timeout=self.timeout)

    def search(self, base: str, flt: str, attrs: list[str]) -> list[tuple[str, dict]]:
        c = self._conn()
        try:
            c.search(base, flt, attributes=attrs, size_limit=3)
            return [(e.entry_dn, {a: e[a].value for a in attrs if a in e}) for e in c.entries]
        finally:
            c.unbind()

    def replace(self, dn: str, attr: str, value: Any) -> None:
        import ldap3  # type: ignore
        c = self._conn()
        try:
            if not c.modify(dn, {attr: [(ldap3.MODIFY_REPLACE, [value])]}):
                raise ConnectorError(f"AD refused the change: {c.result.get('description')} {c.result.get('message', '')[:120]}")
        finally:
            c.unbind()


class ActiveDirectoryConnector(Connector):
    """On-prem Active Directory: disable / re-enable an account (``userAccountControl`` ACCOUNTDISABLE bit) over LDAPS.

    ``lock_account`` only. AD has no session revoke: Kerberos tickets already issued stay valid until they expire
    (10 h by default), so pair a lock with ``rotate_credential`` (CyberArk) or an EDR isolate when that matters. The
    state before is saved; undo re-enables only an account AEGIS disabled. The account must resolve to exactly one
    user (``sAMAccountName`` or ``userPrincipalName``); ``AEGIS_IDP_PROTECTED`` and well-known privileged accounts
    (``Administrator``, ``krbtgt``) are refused. Bind with a delegated account that may only write
    ``userAccountControl`` on the user OUs.
    """

    name = "ad"
    actions = frozenset({"lock_account"})
    _NEVER = frozenset({"administrator", "krbtgt", "guest"})

    def __init__(self, *, directory: Any, base_dn: str, **kw: Any):
        super().__init__(**kw)
        self.dir, self.base_dn = directory, base_dn

    def supports_target(self, target: str) -> bool:
        try:
            _principal(target)
            return True
        except ConnectorError:
            return False

    def _find(self, who: str) -> tuple[str, int]:
        e = _ldap_escape(who)
        flt = f"(&(objectCategory=person)(objectClass=user)(|(sAMAccountName={e})(userPrincipalName={e})))"
        rows = self.dir.search(self.base_dn, flt, ["userAccountControl", "sAMAccountName"])
        if len(rows) != 1:
            raise ConnectorError(f"{len(rows)} AD accounts match {who!r}; give the sAMAccountName or UPN")
        dn, attrs = rows[0]
        if str(attrs.get("sAMAccountName", "")).lower() in self._NEVER:
            raise ConnectorError(f"{who} is a built-in privileged account; a person acts on it")
        return dn, int(attrs.get("userAccountControl") or 512)

    def _do_apply(self, action: Any, key: str, ttl_sec: int | None) -> tuple[str, str, str]:
        who = _principal(action.target)
        _refuse_protected(who)
        if who.lower().split("@", 1)[0] in self._NEVER:
            raise ConnectorError(f"{who} is a built-in privileged account; a person acts on it")
        dn, uac = self._find(who)
        if uac & _UAC_DISABLED:
            return dn, f"[ad] {who} was already disabled", "disabled"
        self.dir.replace(dn, "userAccountControl", uac | _UAC_DISABLED)
        return dn, (f"[ad] disabled {who} ({dn}); Kerberos tickets already issued stay valid until they expire"), "enabled"

    def _do_rollback(self, receipt: Receipt) -> str:
        if receipt.rollback_token != "enabled":
            return f"[ad] {receipt.target} was already disabled before AEGIS acted; left disabled"
        _, uac = self._find(_principal(receipt.target))
        self.dir.replace(receipt.vendor_ref, "userAccountControl", uac & ~_UAC_DISABLED)
        return f"[ad] re-enabled {receipt.target}"

    def _do_verify(self, receipt: Receipt) -> bool | None:
        _, uac = self._find(_principal(receipt.target))
        return bool(uac & _UAC_DISABLED)

    def _do_renew(self, receipt: Receipt, ttl_sec: int) -> str:
        return f"[ad] {receipt.target} still disabled"


def _graph_token(transport: Transport | None) -> Callable[[], str]:
    from .cloud_auth import AzureToken
    return AzureToken(tenant_id=os.environ.get("AEGIS_IDP_TENANT_ID", ""), client_id=os.environ.get("AEGIS_IDP_CLIENT_ID", ""),
                      client_secret=os.environ.get("AEGIS_IDP_CLIENT_SECRET", ""), transport=transport, scope=GRAPH_SCOPE)


def idp_from_env(transport: Transport | None = None) -> Connector | None:
    """``AEGIS_IDP_VENDOR = entra | ad | mock | mock-ad`` (default off). Entra: ``AEGIS_IDP_TENANT_ID``,
    ``AEGIS_IDP_CLIENT_ID``, ``AEGIS_IDP_CLIENT_SECRET`` (or a managed identity with azure-identity installed).
    AD: ``AEGIS_AD_URL`` (ldaps://), ``AEGIS_AD_BASE_DN``, ``AEGIS_AD_BIND_DN``, ``AEGIS_AD_BIND_PASSWORD``."""
    vendor = os.environ.get("AEGIS_IDP_VENDOR", "off").strip().lower()
    if vendor in ("", "off", "0", "none"):
        return None
    if vendor == "mock":
        from .mock_bank import MockEntra
        return EntraConnector(base_url="https://graph.mock/v1.0", token_provider=lambda: "mock-graph-token",
                              transport=transport or MockEntra())
    if vendor in ("entra", "azuread", "aad"):
        return EntraConnector(token_provider=_graph_token(transport), transport=transport)
    if vendor == "mock-ad":
        from .mock_bank import MockDirectory
        return ActiveDirectoryConnector(directory=MockDirectory(), base_dn="DC=bank,DC=local")
    if vendor in ("ad", "activedirectory", "ldap"):
        url, base = os.environ.get("AEGIS_AD_URL", "").strip(), os.environ.get("AEGIS_AD_BASE_DN", "").strip()
        dn, pw = os.environ.get("AEGIS_AD_BIND_DN", ""), os.environ.get("AEGIS_AD_BIND_PASSWORD", "")
        if not (url and base and dn and pw):
            logger.warning("[identity] ad needs AEGIS_AD_URL (ldaps://), AEGIS_AD_BASE_DN, AEGIS_AD_BIND_DN, AEGIS_AD_BIND_PASSWORD")
            return None
        return ActiveDirectoryConnector(directory=Directory(url, dn, pw), base_dn=base)
    logger.warning("[identity] unknown AEGIS_IDP_VENDOR=%r (entra | mock)", vendor)
    return None


def pam_from_env(transport: Transport | None = None) -> Connector | None:
    """``AEGIS_PAM_VENDOR = cyberark | mock`` (default off). Live: ``AEGIS_PAM_URL`` (https PVWA),
    ``AEGIS_PAM_USERNAME``, ``AEGIS_PAM_PASSWORD`` (a CyberArk user allowed to initiate CPM changes only)."""
    vendor = os.environ.get("AEGIS_PAM_VENDOR", "off").strip().lower()
    if vendor in ("", "off", "0", "none"):
        return None
    if vendor == "mock":
        from .mock_bank import MockCyberArk
        t = transport or MockCyberArk()
        return CyberArkConnector(base_url="https://pvwa.mock", transport=t,
                                 session=_CyberArkSession("https://pvwa.mock", "aegis", "mock", t))
    if vendor == "cyberark":
        base = os.environ.get("AEGIS_PAM_URL", "").strip().rstrip("/")
        user, pw = os.environ.get("AEGIS_PAM_USERNAME", ""), os.environ.get("AEGIS_PAM_PASSWORD", "")
        if not (base.startswith("https://") and user and pw):
            logger.warning("[pam] cyberark needs AEGIS_PAM_URL (https), AEGIS_PAM_USERNAME, AEGIS_PAM_PASSWORD")
            return None
        t = transport or httpx_transport
        return CyberArkConnector(base_url=base, transport=t, session=_CyberArkSession(base, user, pw, t))
    logger.warning("[pam] unknown AEGIS_PAM_VENDOR=%r (cyberark | mock)", vendor)
    return None


__all__ = ["ActiveDirectoryConnector", "CyberArkConnector", "Directory", "EntraConnector", "idp_from_env", "pam_from_env"]
