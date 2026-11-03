"""Cloud WAF connectors — Cloudflare, AWS WAF (WAFv2), Azure WAF (Front Door / Application Gateway).

Same contract as ``waf.py``: a ``RecommendedAction`` on a client IP / CIDR
becomes a vendor-side rule, the rollback token names exactly what AEGIS added,
TTL lives in ``Connector``. Shadow mode (the default) never calls the vendor.

Two designs, chosen per vendor by what its API makes safe:

Cloudflare — AEGIS owns individual objects.
    block / challenge → IP Access Rule (zone, or account-wide when only an account id is set)
        POST   /client/v4/{zones|accounts}/{id}/firewall/access_rules/rules
               {"mode": "block"|"managed_challenge", "configuration": {"target", "value"}, "notes"}
        DELETE …/rules/{rule_id}
        targets: ip, ip6, ip_range (IPv4 /16 /24, IPv6 /32 /48 /64 — Cloudflare's own limit)
    throttle → a rule in the zone's ``http_ratelimit`` phase entrypoint ruleset
        GET    /client/v4/zones/{zone}/rulesets/phases/http_ratelimit/entrypoint   (404 → POST /rulesets creates it)
        POST   /client/v4/zones/{zone}/rulesets/{ruleset}/rules
        DELETE /client/v4/zones/{zone}/rulesets/{ruleset}/rules/{rule}
    rollback tokens: ``ar:<id>`` (access rule), ``rl:<ruleset>:<rule>`` (rate rule),
    ``keep:<ip>`` when Cloudflare said the rule already existed (someone else's — never deleted).

AWS WAF and Azure WAF — AEGIS edits membership of a list the bank wired.
    Neither has a cheap per-IP object, and editing a bank's WebACL / policy
    rules is change-controlled. So the bank creates the rule once (block /
    challenge / rate-based, scoped to an IP set or an IPMatch condition) and
    AEGIS only adds or removes addresses in it.

    AWS   GetIPSet → UpdateIPSet (JSON-RPC ``AWSWAF_20190729.*``, SigV4, LockToken; a
          ``WAFOptimisticLockException`` re-reads and retries). One IP set per action:
          ``AEGIS_AWS_WAF_IPSETS="block=<name>/<id>,challenge=<name>/<id>,throttle=<name>/<id>"``.
    Azure GET policy → edit the custom rule → PUT with ``If-Match: <etag>`` (412 re-reads
          and retries). AEGIS creates its own rule (``aegisblock`` / ``aegischallenge`` /
          ``aegisthrottle``) the first time if the bank has not, at the configured priority,
          and deletes it again when its last address is rolled back. Front Door
          (``FrontDoorWebApplicationFirewallPolicies``) and Application Gateway
          (``ApplicationGatewayWebApplicationFirewallPolicies``) differ in field names only.

    Rollback tokens: ``<cidr>`` for an address AEGIS added, ``keep:<cidr>`` when the
    address was already in the list — rollback leaves an analyst's entry alone.

Field names follow the public API docs as of mid-2026; ``mock_cloud_waf.py`` implements
exactly these so the day a tenant exists only credentials change.
"""

from __future__ import annotations

import base64
import ipaddress
import json
import logging
import os
import time
from typing import Any, Callable, Optional

from ...shared.fingerprint import is_fingerprint_target, parse_target
from .base import Connector, ConnectorError, Receipt
from .cloud_auth import AwsCredentials, AzureToken, aws_credentials, sigv4_headers
from .http import RawBody, Transport, call, httpx_transport

logger = logging.getLogger("aegis.connectors.cloud_waf")

KEEP = "keep:"


def _enforceable_fp(target: str) -> bool:
    """A TLS fingerprint target (ja4 / ja3); header-order fingerprints are never enforced."""
    try:
        return parse_target(target)[0] in ("ja4", "ja3")
    except ValueError:
        return False


def _is_ip(target: str) -> bool:
    try:
        ipaddress.ip_network(str(target).strip(), strict=False)
        return True
    except ValueError:
        return False


def _cf_string(v: str) -> str:
    return '"' + v.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _network(target: str) -> ipaddress._BaseNetwork:
    t = str(target).strip()
    try:
        return ipaddress.ip_network(t, strict=False)
    except ValueError:
        raise ConnectorError(f"WAF target must be an IP address or CIDR, got {t!r}") from None


def _cidr(net: ipaddress._BaseNetwork) -> str:
    return f"{net.network_address}/{net.prefixlen}"


def _host_or_cidr(net: ipaddress._BaseNetwork) -> str:
    return str(net.network_address) if net.prefixlen == net.max_prefixlen else _cidr(net)


# ============================================================ Cloudflare ===

CF_DEFAULT_BASE = "https://api.cloudflare.com/client/v4"
CF_MODES = {"block": "block", "challenge": "managed_challenge"}
CF_DUPLICATE_CODES = {10009}            # "firewallaccessrules.api.duplicate_of_existing"
_CF_RANGE_PREFIXES = {4: {16, 24}, 6: {32, 48, 64}}


class CloudflareWafConnector(Connector):
    """Cloudflare — IP Access Rules for block / challenge, a rate-limit rule for throttle,
    custom rules (``http_request_firewall_custom``) for client-fingerprint targets."""

    name = "cloudflare"
    actions = frozenset({"block", "challenge", "throttle"})

    def __init__(self, *, api_token: str, zone_id: str = "", account_id: str = "", base_url: str = CF_DEFAULT_BASE,
                 rate_limit_per_period: int = 60, rate_period_s: int = 60, mitigation_timeout_s: int = 600,
                 transport: Optional[Transport] = None, **kw: Any):
        super().__init__(**kw)
        if not (zone_id or account_id):
            raise ConnectorError("Cloudflare connector needs a zone id or an account id")
        self.zone_id, self.account_id = zone_id, account_id
        self.base_url = base_url.rstrip("/")
        self._headers = {"Authorization": f"Bearer {api_token}", "Content-Type": "application/json"}
        self.rate_limit_per_period = max(1, int(rate_limit_per_period))
        self.rate_period_s = int(rate_period_s)
        self.mitigation_timeout_s = int(mitigation_timeout_s)
        self._transport = transport or httpx_transport
        self._entrypoints: dict[str, str] = {}

    def supports_target(self, target: str) -> bool:
        return _is_ip(target) or _enforceable_fp(target)

    # -- urls
    def _access_rules_url(self, rule_id: str = "") -> str:
        scope = f"zones/{self.zone_id}" if self.zone_id else f"accounts/{self.account_id}"
        return f"{self.base_url}/{scope}/firewall/access_rules/rules" + (f"/{rule_id}" if rule_id else "")

    def _call(self, method: str, url: str, body: Optional[dict] = None, expect: tuple[int, ...] = ()):
        res = call(self._transport, method, url, json_body=body, headers=self._headers, expect=expect)
        b = res.json()
        if res.ok and b and b.get("success") is False:
            # Cloudflare can answer 200 with success:false
            raise ConnectorError(f"Cloudflare refused {method}: {b.get('errors')}"[:200])
        return res

    # -- apply
    def _do_apply(self, action: Any, key: str, ttl_sec: Optional[int]) -> tuple[str, str, str]:
        ttl = f" (TTL {ttl_sec}s)" if ttl_sec else " (permanent)"
        if is_fingerprint_target(action.target):
            return self._apply_fingerprint(action, key, ttl)
        net = _network(action.target)
        if action.action_type == "throttle":
            return self._apply_ratelimit(net, key, ttl)
        if net.prefixlen == net.max_prefixlen:
            target, value = ("ip" if net.version == 4 else "ip6"), str(net.network_address)
        elif net.prefixlen in _CF_RANGE_PREFIXES[net.version]:
            target, value = "ip_range", _cidr(net)
        else:
            raise ConnectorError(f"Cloudflare IP Access Rules take IPv4 /16 or /24 and IPv6 /32 /48 /64 ranges; "
                                 f"{_cidr(net)} needs a custom rule (route it through SOAR)")
        mode = CF_MODES[action.action_type]
        body = {"mode": mode, "configuration": {"target": target, "value": value},
                "notes": f"aegis {action.action_type} {key[:8]}"}
        try:
            res = self._call("POST", self._access_rules_url(), body)
        except ConnectorError as e:
            if any(str(c) in str(e) for c in CF_DUPLICATE_CODES):
                return (f"{KEEP}{value}", f"[cloudflare] {value} already has an access rule — left as is{ttl}",
                        f"{KEEP}{value}")
            raise
        rule_id = str((res.json().get("result") or {}).get("id") or "")
        if not rule_id:
            raise ConnectorError(f"Cloudflare returned no access-rule id: {str(res.body)[:160]}")
        where = f"zone {self.zone_id}" if self.zone_id else f"account {self.account_id}"
        return rule_id, f"[cloudflare] {mode} access rule {rule_id} on {where} for {value}{ttl}", f"ar:{rule_id}"

    def _entrypoint(self, phase: str) -> str:
        if phase in self._entrypoints:
            return self._entrypoints[phase]
        if not self.zone_id:
            raise ConnectorError(f"Cloudflare {phase} rules are per zone — set a zone id")
        url = f"{self.base_url}/zones/{self.zone_id}/rulesets/phases/{phase}/entrypoint"
        res = self._call("GET", url, expect=(404,))
        rs = str((res.json().get("result") or {}).get("id") or "") if res.ok else ""
        if not rs:
            created = self._call("POST", f"{self.base_url}/zones/{self.zone_id}/rulesets",
                                 {"name": "default", "kind": "zone", "phase": phase, "rules": []})
            rs = str((created.json().get("result") or {}).get("id") or "")
        if not rs:
            raise ConnectorError(f"Cloudflare returned no {phase} ruleset id")
        self._entrypoints[phase] = rs
        return rs

    def _add_rule(self, phase: str, body: dict) -> tuple[str, str]:
        rs = self._entrypoint(phase)
        res = self._call("POST", f"{self.base_url}/zones/{self.zone_id}/rulesets/{rs}/rules", body)
        rules = (res.json().get("result") or {}).get("rules") or []
        rule_id = next((str(r.get("id")) for r in rules if r.get("description") == body["description"]), "")
        if not rule_id:
            raise ConnectorError(f"Cloudflare accepted the {phase} rule but it is not in the returned ruleset")
        return rs, rule_id

    def _apply_fingerprint(self, action: Any, key: str, ttl: str) -> tuple[str, str, str]:
        kind, value, ua = parse_target(action.target)
        if kind not in ("ja4", "ja3"):
            raise ConnectorError(f"{kind} fingerprints correlate only; no WAF can match them")
        if action.action_type not in ("block", "challenge"):
            raise ConnectorError(f"Cloudflare fingerprint rules support block / challenge, not {action.action_type}")
        field = "cf.bot_management.ja4" if kind == "ja4" else "cf.bot_management.ja3_hash"
        expr = f"({field} eq {_cf_string(value)}" + (f" and http.user_agent eq {_cf_string(ua)})" if ua else ")")
        cf_action = "block" if action.action_type == "block" else "managed_challenge"
        rs, rule_id = self._add_rule("http_request_firewall_custom",
                                     {"description": f"aegis {action.action_type} fp {key[:8]}", "expression": expr,
                                      "action": cf_action, "enabled": True})
        what = f"{kind} {value[:24]}" + (" + exact user agent" if ua else "")
        return rule_id, f"[cloudflare] {cf_action} custom rule {rule_id} on {what}{ttl}", f"cr:{rs}:{rule_id}"

    def _apply_ratelimit(self, net, key: str, ttl: str) -> tuple[str, str, str]:
        rs = self._entrypoint("http_ratelimit")
        expr = (f"(ip.src eq {net.network_address})" if net.prefixlen == net.max_prefixlen
                else f"(ip.src in {{{_cidr(net)}}})")
        marker = f"aegis throttle {key[:8]}"
        body = {"description": marker, "expression": expr, "action": "block", "enabled": True,
                "ratelimit": {"characteristics": ["ip.src", "cf.colo.id"], "period": self.rate_period_s,
                              "requests_per_period": self.rate_limit_per_period,
                              "mitigation_timeout": self.mitigation_timeout_s}}
        res = self._call("POST", f"{self.base_url}/zones/{self.zone_id}/rulesets/{rs}/rules", body)
        rules = (res.json().get("result") or {}).get("rules") or []
        rule_id = next((str(r.get("id")) for r in rules if r.get("description") == marker), "")
        if not rule_id:
            raise ConnectorError("Cloudflare accepted the rate rule but it is not in the returned ruleset")
        detail = (f"[cloudflare] rate limit {self.rate_limit_per_period}/{self.rate_period_s}s on "
                  f"{_host_or_cidr(net)} (ruleset {rs}, rule {rule_id}){ttl}")
        return rule_id, detail, f"rl:{rs}:{rule_id}"

    # -- rollback
    def _do_rollback(self, receipt: Receipt) -> str:
        tok = receipt.rollback_token
        if tok.startswith(KEEP):
            return f"[cloudflare] {tok[len(KEEP):]} left in place (rule was there before AEGIS)"
        if tok.startswith(("rl:", "cr:")):
            kind, rs, rule = tok.split(":", 2)
            self._call("DELETE", f"{self.base_url}/zones/{self.zone_id}/rulesets/{rs}/rules/{rule}", expect=(404,))
            return f"[cloudflare] {'rate' if kind == 'rl' else 'custom'} rule {rule} deleted"
        rule_id = tok[3:] if tok.startswith("ar:") else (tok or receipt.vendor_ref)
        if not rule_id:
            raise ConnectorError("no Cloudflare rule id on the receipt")
        self._call("DELETE", self._access_rules_url(rule_id), expect=(404,))
        return f"[cloudflare] access rule {rule_id} deleted"

    def _do_renew(self, receipt: Receipt, ttl_sec: int) -> str:
        return f"[cloudflare] {receipt.vendor_ref} kept for another {ttl_sec}s"


# ================================================ list-membership WAFs ===

class _MembershipConnector(Connector):
    """Shared logic for WAFs where AEGIS adds/removes addresses in a bank-owned list."""

    vendor_label = "waf"

    def supports_target(self, target: str) -> bool:
        return _is_ip(target)

    def _lists(self) -> dict[str, str]:  # action → human label of the list
        raise NotImplementedError

    def _mutate(self, action_type: str, fn: Callable[[list[str]], tuple[list[str], Any]]) -> Any:
        """Read the list for ``action_type``, apply ``fn(addresses) -> (new_addresses, result)``,
        write it back with optimistic concurrency. Returns ``result``."""
        raise NotImplementedError

    def _check_version(self, action_type: str, net) -> None:
        return None

    def _do_apply(self, action: Any, key: str, ttl_sec: Optional[int]) -> tuple[str, str, str]:
        net = _network(action.target)
        self._check_version(action.action_type, net)
        cidr = _cidr(net)

        def add(addrs: list[str]) -> tuple[list[str], bool]:
            present = {_cidr(_network(a)) for a in addrs}
            if cidr in present:
                return addrs, False
            return addrs + [self._format(net)], True

        added = self._mutate(action.action_type, add)
        ttl = f" (TTL {ttl_sec}s)" if ttl_sec else " (permanent)"
        where = self._lists()[action.action_type]
        if not added:
            return f"{KEEP}{cidr}", f"[{self.name}] {cidr} already in {where} — left as is{ttl}", f"{KEEP}{cidr}"
        return cidr, f"[{self.name}] added {cidr} to {where}{ttl}", cidr

    def _do_rollback(self, receipt: Receipt) -> str:
        tok = receipt.rollback_token or receipt.vendor_ref
        if not tok:
            raise ConnectorError(f"no {self.name} address on the receipt")
        if tok.startswith(KEEP):
            return f"[{self.name}] {tok[len(KEEP):]} left in place (was there before AEGIS)"
        cidr = _cidr(_network(tok))

        def remove(addrs: list[str]) -> tuple[list[str], bool]:
            kept = [a for a in addrs if _cidr(_network(a)) != cidr]
            return kept, len(kept) != len(addrs)

        removed = self._mutate(receipt.action_type, remove)
        where = self._lists()[receipt.action_type]
        return f"[{self.name}] removed {cidr} from {where}" if removed else f"[{self.name}] {cidr} was already gone from {where}"

    def _do_renew(self, receipt: Receipt, ttl_sec: int) -> str:
        return f"[{self.name}] {receipt.vendor_ref} kept for another {ttl_sec}s"

    def _read(self, action_type: str) -> list[str] | None:
        """The list's current addresses, or None when this vendor connector cannot read it back."""
        return None

    def _do_verify(self, receipt: Receipt) -> bool | None:
        tok = receipt.rollback_token or receipt.vendor_ref
        if not tok:
            return None
        addrs = self._read(receipt.action_type)
        if addrs is None:
            return None
        cidr = _cidr(_network(tok.removeprefix(KEEP)))
        return cidr in {_cidr(_network(a)) for a in addrs}

    @staticmethod
    def _format(net) -> str:
        return _cidr(net)


# ================================================================ AWS WAF ===

AWS_TARGET_PREFIX = "AWSWAF_20190729"
AWS_LOCK_RETRIES = 3


def parse_ipset_map(spec: str) -> dict[str, tuple[str, str]]:
    """``"block=aegis-block/1234-abcd,throttle=aegis-rl/5678"`` → {"block": ("aegis-block", "1234-abcd"), …}."""
    out: dict[str, tuple[str, str]] = {}
    for part in (spec or "").split(","):
        if not part.strip():
            continue
        action, _, ref = part.partition("=")
        name, _, set_id = ref.strip().partition("/")
        if not (action.strip() and name and set_id):
            raise ConnectorError(f"bad AEGIS_AWS_WAF_IPSETS entry {part!r} (want action=<name>/<id>)")
        out[action.strip().lower()] = (name.strip(), set_id.strip())
    return out


class AwsWafConnector(_MembershipConnector):
    """AWS WAFv2 — add / remove addresses in bank-wired IP sets (one per action); client
    fingerprints as rules in an AEGIS-owned rule group the bank references from its WebACL
    (``rule_group``): JA4 / JA3 ``ByteMatch``, AND the exact ``user-agent`` header when given."""

    name = "aws-waf"

    def __init__(self, *, ip_sets: dict[str, tuple[str, str]], region: str, scope: str = "REGIONAL",
                 credentials: Optional[AwsCredentials] = None, endpoint: str = "",
                 rule_group: Optional[tuple[str, str]] = None,
                 transport: Optional[Transport] = None, sleep: Callable[[float], None] = time.sleep, **kw: Any):
        super().__init__(**kw)
        unknown = set(ip_sets) - {"block", "challenge", "throttle"}
        if unknown or not (ip_sets or rule_group):
            raise ConnectorError(f"AWS WAF ip_sets must map block/challenge/throttle, got {sorted(ip_sets) or 'nothing'}")
        self.ip_sets = dict(ip_sets)
        self.rule_group = rule_group
        self.actions = frozenset(ip_sets) | (frozenset({"block", "challenge"}) if rule_group else frozenset())
        self.scope = scope.upper()
        if self.scope not in ("REGIONAL", "CLOUDFRONT"):
            raise ConnectorError(f"AWS WAF scope must be REGIONAL or CLOUDFRONT, got {scope!r}")
        # CloudFront-scoped resources are managed through us-east-1
        self.region = "us-east-1" if self.scope == "CLOUDFRONT" else region
        self.endpoint = (endpoint or f"https://wafv2.{self.region}.amazonaws.com").rstrip("/") + "/"
        self._creds = credentials
        self._transport = transport or httpx_transport
        self._versions: dict[str, str] = {}
        self._sleep = sleep

    def _lists(self) -> dict[str, str]:
        return {a: f"IP set {n}" for a, (n, _) in self.ip_sets.items()}

    def supports_target(self, target: str) -> bool:
        return _is_ip(target) or (self.rule_group is not None and _enforceable_fp(target))

    # -- fingerprint rules in the AEGIS rule group
    def _do_apply(self, action: Any, key: str, ttl_sec: Optional[int]) -> tuple[str, str, str]:
        if not is_fingerprint_target(action.target):
            if action.action_type not in self.ip_sets:
                raise ConnectorError(f"no IP set wired for {action.action_type} (AEGIS_AWS_WAF_IPSETS)")
            return super()._do_apply(action, key, ttl_sec)
        kind, value, ua = parse_target(action.target)
        if kind not in ("ja4", "ja3") or action.action_type not in ("block", "challenge"):
            raise ConnectorError(f"AWS fingerprint rules take ja4/ja3 with block/challenge, got {kind}/{action.action_type}")
        if self.rule_group is None:
            raise ConnectorError("no AEGIS rule group wired (AEGIS_AWS_WAF_RULE_GROUP)")
        name = f"aegis-{action.action_type}-{key[:12]}"

        def match(field: dict, text: str) -> dict:
            return {"ByteMatchStatement": {"SearchString": base64.b64encode(text.encode()).decode(), "FieldToMatch": field,
                                           "PositionalConstraint": "EXACTLY",
                                           "TextTransformations": [{"Priority": 0, "Type": "NONE"}]}}
        fp_field = {"JA4Fingerprint" if kind == "ja4" else "JA3Fingerprint": {"FallbackBehavior": "NO_MATCH"}}
        stmt = match(fp_field, value)
        if ua:
            stmt = {"AndStatement": {"Statements": [stmt, match({"SingleHeader": {"Name": "user-agent"}}, ua)]}}

        def add(rules: list[dict]) -> tuple[list[dict], bool]:
            if any(r.get("Name") == name for r in rules):
                return rules, False
            prio = max((int(r.get("Priority", 0)) for r in rules), default=-1) + 1
            return rules + [{"Name": name, "Priority": prio, "Statement": stmt,
                             "Action": {"Block": {}} if action.action_type == "block" else {"Challenge": {}},
                             "VisibilityConfig": {"SampledRequestsEnabled": True, "CloudWatchMetricsEnabled": True,
                                                  "MetricName": name}}], True
        self._mutate_rules(add)
        ttl = f" (TTL {ttl_sec}s)" if ttl_sec else " (permanent)"
        what = f"{kind} {value[:24]}" + (" + exact user agent" if ua else "")
        return name, f"[aws-waf] {action.action_type} rule {name} in rule group {self.rule_group[0]} on {what}{ttl}", f"rule:{name}"

    def _do_rollback(self, receipt: Receipt) -> str:
        tok = receipt.rollback_token
        if not tok.startswith("rule:"):
            return super()._do_rollback(receipt)
        name = tok[5:]

        def remove(rules: list[dict]) -> tuple[list[dict], bool]:
            kept = [r for r in rules if r.get("Name") != name]
            return kept, len(kept) != len(rules)
        gone = self._mutate_rules(remove)
        return f"[aws-waf] rule {name} removed" if gone else f"[aws-waf] rule {name} was already gone"

    def _mutate_rules(self, fn):
        gname, gid = self.rule_group  # type: ignore[misc]
        last: Optional[Exception] = None
        for _ in range(AWS_LOCK_RETRIES + 1):
            out = self._rpc("GetRuleGroup", {"Name": gname, "Scope": self.scope, "Id": gid})
            rg, lock = out.get("RuleGroup") or {}, out.get("LockToken")
            if not lock:
                raise ConnectorError(f"AWS GetRuleGroup {gname} returned no LockToken")
            rules = list(rg.get("Rules") or [])
            new, result = fn(rules)
            if new == rules:
                return result
            payload = {"Name": gname, "Scope": self.scope, "Id": gid, "Rules": new, "LockToken": lock,
                       "VisibilityConfig": rg.get("VisibilityConfig") or {"SampledRequestsEnabled": True,
                                                                          "CloudWatchMetricsEnabled": True, "MetricName": gname}}
            if rg.get("Description"):
                payload["Description"] = rg["Description"]
            try:
                self._rpc("UpdateRuleGroup", payload)
                return result
            except ConnectorError as e:
                if "WAFOptimisticLockException" not in str(e):
                    raise
                last = e
        raise ConnectorError(f"AWS rule group {gname} kept changing: {str(last)[:160]}")

    def _rpc(self, op: str, payload: dict, attempts: int = 3) -> dict:
        body = RawBody(json.dumps(payload, separators=(",", ":")).encode())
        for n in range(attempts):
            # re-sign every attempt: the signature carries x-amz-date and expires
            creds = self._creds or aws_credentials()
            headers = sigv4_headers("POST", self.endpoint, bytes(body),
                                    {"Content-Type": "application/x-amz-json-1.1",
                                     "X-Amz-Target": f"{AWS_TARGET_PREFIX}.{op}"},
                                    creds=creds, region=self.region, service="wafv2")
            try:
                return call(self._transport, "POST", self.endpoint, json_body=body, headers=headers, retries=0).json()
            except ConnectorError as e:
                transient = any(t in str(e) for t in ("HTTP 429", "HTTP 50", "Error on POST", "Exception on POST",
                                                      "WAFInternalErrorException", "ThrottlingException"))
                if not transient or n == attempts - 1:
                    raise
                logger.info("[aws-waf] %s transient failure (%s); retrying", op, str(e)[:80])
                self._sleep(0.5 * (2 ** n))
        raise ConnectorError(f"AWS {op} failed")  # pragma: no cover — loop always returns or raises

    def _read(self, action_type: str) -> list[str] | None:
        if action_type not in self.ip_sets:
            return None
        return self._get(action_type)[0]

    def _get(self, action_type: str) -> tuple[list[str], str, str]:
        name, set_id = self.ip_sets[action_type]
        out = self._rpc("GetIPSet", {"Name": name, "Scope": self.scope, "Id": set_id})
        ipset = out.get("IPSet") or {}
        if not out.get("LockToken"):
            raise ConnectorError(f"AWS GetIPSet {name} returned no LockToken")
        self._versions[action_type] = str(ipset.get("IPAddressVersion") or "IPV4")
        return list(ipset.get("Addresses") or []), str(out["LockToken"]), str(ipset.get("Description") or "")

    def _check_version(self, action_type: str, net) -> None:
        if action_type not in self.ip_sets:
            return
        if action_type not in self._versions:
            self._get(action_type)
        want = "IPV6" if net.version == 6 else "IPV4"
        if self._versions[action_type] != want:
            raise ConnectorError(f"IP set {self.ip_sets[action_type][0]} is {self._versions[action_type]}; "
                                 f"{_cidr(net)} is {want} — wire a second set for {want}")

    def _mutate(self, action_type: str, fn):
        name, set_id = self.ip_sets[action_type]
        last: Optional[Exception] = None
        for _ in range(AWS_LOCK_RETRIES + 1):
            addrs, lock, desc = self._get(action_type)
            new, result = fn(addrs)
            if new == addrs:
                return result
            payload = {"Name": name, "Scope": self.scope, "Id": set_id, "Addresses": new, "LockToken": lock}
            if desc:
                payload["Description"] = desc
            try:
                self._rpc("UpdateIPSet", payload)
                return result
            except ConnectorError as e:
                if "WAFOptimisticLockException" not in str(e) and "HTTP 5" not in str(e) and "HTTP 429" not in str(e):
                    raise
                last = e
                logger.info("[aws-waf] %s changed underneath us (%s); re-reading", name, str(e)[:80])
        raise ConnectorError(f"AWS IP set {name} kept changing: {str(last)[:160]}")


# ============================================================== Azure WAF ===

AZURE_ARM = "https://management.azure.com"
AZURE_FLAVORS = {
    "frontdoor": ("Microsoft.Network/FrontDoorWebApplicationFirewallPolicies", "2024-02-01"),
    "appgw": ("Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies", "2024-05-01"),
}
AZURE_ACTIONS = {"block": "Block", "challenge": "JSChallenge", "throttle": "Block"}
AZURE_RULE_NAMES = {"block": "aegisblock", "challenge": "aegischallenge", "throttle": "aegisthrottle"}
AZURE_MAX_VALUES = 600                  # Front Door's per-condition cap; App Gateway allows fewer per rule in practice
AZURE_ETAG_RETRIES = 3


class AzureWafConnector(_MembershipConnector):
    """Azure WAF policy (Front Door or Application Gateway) — AEGIS-owned custom rules, IPMatch on RemoteAddr."""

    name = "azure-waf"
    actions = frozenset(AZURE_ACTIONS)

    def __init__(self, *, subscription_id: str, resource_group: str, policy_name: str, flavor: str = "frontdoor",
                 token: Optional[Callable[[], str]] = None, priority_base: int = 10, rate_limit_per_min: int = 100,
                 actions: Optional[set[str]] = None, arm_url: str = AZURE_ARM,
                 transport: Optional[Transport] = None, **kw: Any):
        super().__init__(**kw)
        flavor = flavor.lower()
        if flavor not in AZURE_FLAVORS:
            raise ConnectorError(f"Azure WAF flavor must be frontdoor or appgw, got {flavor!r}")
        self.flavor = flavor
        provider, self.api_version = AZURE_FLAVORS[flavor]
        self.policy_url = (f"{arm_url.rstrip('/')}/subscriptions/{subscription_id}/resourceGroups/{resource_group}"
                           f"/providers/{provider}/{policy_name}")
        self.policy_name = policy_name
        self._token = token or AzureToken()
        self.priority_base = int(priority_base)
        self.rate_limit_per_min = max(1, int(rate_limit_per_min))
        if actions is not None:
            self.actions = frozenset(a for a in actions if a in AZURE_ACTIONS)
        self._transport = transport or httpx_transport

    def _lists(self) -> dict[str, str]:
        return {a: f"rule {AZURE_RULE_NAMES[a]} of policy {self.policy_name}" for a in AZURE_ACTIONS}

    @staticmethod
    def _format(net) -> str:
        return _host_or_cidr(net)

    def _req(self, method: str, body: Optional[dict] = None, etag: str = "", expect: tuple[int, ...] = ()):
        headers = {"Authorization": f"Bearer {self._token()}", "Content-Type": "application/json"}
        if etag:
            headers["If-Match"] = etag
        url = f"{self.policy_url}?api-version={self.api_version}"
        try:
            return call(self._transport, method, url, json_body=body, headers=headers, expect=expect)
        except ConnectorError as e:
            if "HTTP 401" in str(e) and isinstance(self._token, AzureToken):
                self._token.invalidate()
                headers["Authorization"] = f"Bearer {self._token()}"
                return call(self._transport, method, url, json_body=body, headers=headers, expect=expect)
            raise

    # -- the two policy shapes
    def _rules(self, policy: dict) -> list[dict]:
        props = policy.setdefault("properties", {})
        if self.flavor == "frontdoor":
            return props.setdefault("customRules", {}).setdefault("rules", [])
        return props.setdefault("customRules", [])

    def _values(self, rule: dict) -> list[str]:
        cond = (rule.get("matchConditions") or [{}])[0]
        return list(cond.get("matchValue" if self.flavor == "frontdoor" else "matchValues") or [])

    def _set_values(self, rule: dict, values: list[str]) -> None:
        key = "matchValue" if self.flavor == "frontdoor" else "matchValues"
        rule["matchConditions"][0][key] = values

    def _new_rule(self, action_type: str, priority: int) -> dict:
        name = AZURE_RULE_NAMES[action_type]
        if self.flavor == "frontdoor":
            rule = {"name": name, "priority": priority, "enabledState": "Enabled", "ruleType": "MatchRule",
                    "action": AZURE_ACTIONS[action_type],
                    "matchConditions": [{"matchVariable": "RemoteAddr", "operator": "IPMatch",
                                         "negateCondition": False, "matchValue": []}]}
            if action_type == "throttle":
                rule.update({"ruleType": "RateLimitRule", "rateLimitDurationInMinutes": 1,
                             "rateLimitThreshold": self.rate_limit_per_min})
        else:
            rule = {"name": name, "priority": priority, "state": "Enabled", "ruleType": "MatchRule",
                    "action": AZURE_ACTIONS[action_type],
                    "matchConditions": [{"matchVariables": [{"variableName": "RemoteAddr"}], "operator": "IPMatch",
                                         "matchValues": []}]}
            if action_type == "throttle":
                rule.update({"ruleType": "RateLimitRule", "rateLimitDuration": "OneMin",
                             "rateLimitThreshold": self.rate_limit_per_min,
                             "groupByUserSession": [{"groupByVariables": [{"variableName": "ClientAddr"}]}]})
        return rule

    def _free_priority(self, rules: list[dict], offset: int) -> int:
        taken = {int(r.get("priority", -1)) for r in rules}
        p = self.priority_base + offset
        while p in taken:
            p += 1
        return p

    def _mutate(self, action_type: str, fn):
        name = AZURE_RULE_NAMES[action_type]
        last: Optional[Exception] = None
        for _ in range(AZURE_ETAG_RETRIES + 1):
            policy = self._req("GET").json()
            if not policy:
                raise ConnectorError(f"Azure returned an empty policy for {self.policy_name}")
            etag = str(policy.get("etag") or "")
            rules = self._rules(policy)
            rule = next((r for r in rules if r.get("name") == name), None)
            current = self._values(rule) if rule else []
            new, result = fn(current)
            if new == current:
                return result
            if len(new) > AZURE_MAX_VALUES:
                raise ConnectorError(f"rule {name} would hold {len(new)} addresses (cap {AZURE_MAX_VALUES})")
            if rule is None:
                rule = self._new_rule(action_type, self._free_priority(rules, list(AZURE_RULE_NAMES).index(action_type)))
                rules.append(rule)
            if new:
                self._set_values(rule, new)
            else:
                rules.remove(rule)          # Azure rejects an IPMatch with no values — drop our rule
            try:
                self._req("PUT", policy, etag=etag)
                return result
            except ConnectorError as e:
                if "HTTP 412" not in str(e):
                    raise
                last = e
                logger.info("[azure-waf] policy %s changed underneath us; re-reading", self.policy_name)
        raise ConnectorError(f"Azure policy {self.policy_name} kept changing: {str(last)[:160]}")


# ================================================================== env ===

def cloud_waf_from_env(vendor: str, transport: Optional[Transport] = None) -> Optional[Connector]:
    """Build a cloud WAF connector for ``AEGIS_WAF_VENDOR`` = cloudflare | aws | azure
    (and ``mock-cloudflare`` / ``mock-aws`` / ``mock-azure`` against the in-process fakes)."""
    env = os.environ.get
    if vendor in ("mock-cloudflare", "mock-aws", "mock-azure"):
        from . import mock_cloud_waf as m
        if vendor == "mock-cloudflare":
            return CloudflareWafConnector(api_token="mock", zone_id="mock-zone", base_url=m.CF_BASE,
                                          transport=transport or m.MockCloudflare())
        if vendor == "mock-aws":
            srv = m.MockAwsWaf()
            ids = {a: srv.create_ip_set(f"aegis-{a}") for a in ("block", "challenge", "throttle")}
            return AwsWafConnector(ip_sets={a: (f"aegis-{a}", i) for a, i in ids.items()}, region="ap-south-1",
                                   rule_group=("aegis-fingerprints", srv.create_rule_group("aegis-fingerprints")),
                                   credentials=AwsCredentials(m.AWS_KEY, m.AWS_SECRET), endpoint=m.AWS_ENDPOINT,
                                   transport=transport or srv)
        srv = m.MockAzureWaf()
        return AzureWafConnector(subscription_id=m.AZ_SUB, resource_group=m.AZ_RG, policy_name=m.AZ_POLICY,
                                 token=lambda: m.AZ_TOKEN, arm_url=m.AZ_ARM, transport=transport or srv)
    if vendor == "cloudflare":
        token = env("AEGIS_CF_API_TOKEN", "")
        zone, account = env("AEGIS_CF_ZONE_ID", ""), env("AEGIS_CF_ACCOUNT_ID", "")
        if not token or not (zone or account):
            logger.warning("[waf] AEGIS_WAF_VENDOR=cloudflare needs AEGIS_CF_API_TOKEN and AEGIS_CF_ZONE_ID (or AEGIS_CF_ACCOUNT_ID)")
            return None
        return CloudflareWafConnector(api_token=token, zone_id=zone, account_id=account,
                                      rate_limit_per_period=int(env("AEGIS_WAF_RATE_LIMIT", "60")),
                                      rate_period_s=int(env("AEGIS_CF_RATE_PERIOD", "60")),
                                      mitigation_timeout_s=int(env("AEGIS_CF_MITIGATION_TIMEOUT", "600")),
                                      transport=transport)
    if vendor == "aws":
        spec, region = env("AEGIS_AWS_WAF_IPSETS", ""), env("AEGIS_AWS_REGION", env("AWS_REGION", ""))
        if not (spec or env("AEGIS_AWS_WAF_RULE_GROUP")) or not region:
            logger.warning("[waf] AEGIS_WAF_VENDOR=aws needs AEGIS_AWS_REGION and AEGIS_AWS_WAF_IPSETS and/or AEGIS_AWS_WAF_RULE_GROUP")
            return None
        creds = None
        if env("AEGIS_AWS_ACCESS_KEY_ID") and env("AEGIS_AWS_SECRET_ACCESS_KEY"):
            creds = AwsCredentials(env("AEGIS_AWS_ACCESS_KEY_ID", ""), env("AEGIS_AWS_SECRET_ACCESS_KEY", ""),
                                   env("AEGIS_AWS_SESSION_TOKEN", ""))
        rg_spec = env("AEGIS_AWS_WAF_RULE_GROUP", "")
        rule_group = None
        if rg_spec:
            rg_name, _, rg_id = rg_spec.partition("/")
            if not (rg_name and rg_id):
                raise ConnectorError(f"bad AEGIS_AWS_WAF_RULE_GROUP {rg_spec!r} (want <name>/<id>)")
            rule_group = (rg_name, rg_id)
        return AwsWafConnector(ip_sets=parse_ipset_map(spec), region=region, rule_group=rule_group,
                               scope=env("AEGIS_AWS_WAF_SCOPE", "REGIONAL"), credentials=creds, transport=transport)
    if vendor == "azure":
        sub, rg, pol = env("AEGIS_AZURE_SUBSCRIPTION_ID", ""), env("AEGIS_AZURE_RESOURCE_GROUP", ""), env("AEGIS_AZURE_WAF_POLICY", "")
        if not (sub and rg and pol):
            logger.warning("[waf] AEGIS_WAF_VENDOR=azure needs AEGIS_AZURE_SUBSCRIPTION_ID, "
                           "AEGIS_AZURE_RESOURCE_GROUP and AEGIS_AZURE_WAF_POLICY")
            return None
        token = AzureToken(token=env("AEGIS_AZURE_TOKEN", ""), tenant_id=env("AEGIS_AZURE_TENANT_ID", ""),
                           client_id=env("AEGIS_AZURE_CLIENT_ID", ""), client_secret=env("AEGIS_AZURE_CLIENT_SECRET", ""),
                           transport=transport)
        acts = {a.strip() for a in env("AEGIS_AZURE_WAF_ACTIONS", "block,challenge,throttle").split(",") if a.strip()}
        return AzureWafConnector(subscription_id=sub, resource_group=rg, policy_name=pol,
                                 flavor=env("AEGIS_AZURE_WAF_FLAVOR", "frontdoor"), token=token,
                                 priority_base=int(env("AEGIS_AZURE_WAF_PRIORITY", "10")),
                                 rate_limit_per_min=int(env("AEGIS_WAF_RATE_LIMIT", "100")),
                                 actions=acts, transport=transport)
    return None


__all__ = ["CloudflareWafConnector", "AwsWafConnector", "AzureWafConnector", "parse_ipset_map", "cloud_waf_from_env"]
