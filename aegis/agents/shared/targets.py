"""Resolve symbolic action targets to the alert's concrete values.

Specialists (and live LLMs) often recommend an action on a *field* —
``block -> source_ip``, ``challenge -> session`` — rather than the value. The
connectors act on values: a WAF needs ``203.0.113.10``, not ``"source_ip"``.
Shadow mode hid this ("would block source_ip"); in live mode every WAF call
failed. ``resolve_action_targets`` runs where the chain is sealed
(``SOCOrchestrator.record``), so the audit log, the HITL card and the
connector all see the same concrete target.

Rules, deliberately narrow:
- a target that is already a value (not a known field name) is left alone;
- a field name is replaced by the alert's value for it (aliases below);
- ``session`` on a WAF action (block / challenge / throttle) resolves to the
  session's client IP — WAFs act per IP — and the substitution is recorded;
- nothing usable in the alert → the target is left as is and flagged
  ``unresolved``; the connector then refuses it and the action parks for a human.
Every substitution is written to ``chain.metadata["target_resolution"]``.
"""

from __future__ import annotations

from typing import Any

_ALIASES: dict[str, tuple[str, ...]] = {
    "source_ip": ("source_ip", "src_ip", "client_ip", "ip", "remote_ip"),
    "src_ip": ("source_ip", "src_ip", "client_ip", "ip"),
    "client_ip": ("source_ip", "client_ip", "src_ip", "ip"),
    "attacker_ip": ("source_ip", "src_ip", "client_ip", "ip"),
    "remote_ip": ("source_ip", "remote_ip", "src_ip", "ip"),
    "ip": ("source_ip", "ip", "src_ip", "client_ip"),
    "dest_ip": ("dest_ip", "destination_ip", "dst_ip"),
    "session": ("session_id", "session"),
    "session_id": ("session_id", "session"),
    "user": ("user_id", "user", "username", "upn"),
    "user_id": ("user_id", "user", "username", "upn"),
    "username": ("user_id", "username", "user", "upn"),
    "account": ("account_id", "account", "user_id"),
    "account_id": ("account_id", "account"),
    "host": ("host", "hostname", "device", "computer"),
    "hostname": ("hostname", "host", "device", "computer"),
    "device": ("device", "host", "hostname"),
    "url": ("url",),
    "endpoint": ("url", "endpoint", "path"),
    "domain": ("domain", "sender_domain", "host"),
    "sender": ("sender", "from"),
    "process": ("process", "process_name"),
    "hash": ("hash", "sha256", "file_hash"),
    "token": ("token_id", "token"),
    "agent": ("agent_id", "agent"),
}
_IP_FIELDS = ("source_ip", "src_ip", "client_ip", "ip", "remote_ip")
_WAF_ACTIONS = frozenset({"block", "challenge", "throttle"})
_EMPTY = frozenset({"", "?", "unknown", "anonymous", "none", "null", "n/a", "-"})


def _value(alert: dict, keys: tuple[str, ...]) -> tuple[str, str]:
    for k in keys:
        v = alert.get(k)
        if isinstance(v, (str, int)) and str(v).strip().lower() not in _EMPTY:
            return k, str(v).strip()
    return "", ""


def resolve_action_targets(chain: Any, alert: dict) -> list[dict]:
    """Rewrite symbolic targets on ``chain.recommended_actions`` in place. Returns what changed."""
    if not isinstance(alert, dict):
        return []
    changes: list[dict] = []
    for action in getattr(chain, "recommended_actions", None) or []:
        field = str(action.target or "").strip()
        key = field.lower()
        if key not in _ALIASES:
            continue
        src, value = "", ""
        if key in ("session", "session_id") and action.action_type in _WAF_ACTIONS:
            src, value = _value(alert, _IP_FIELDS)
            note = "session acted on at its client IP (WAFs act per IP)"
        else:
            src, value = _value(alert, _ALIASES[key])
            note = ""
        row = {"action": action.action_type, "field": field}
        if value:
            action.target = value
            row.update({"resolved_from": src, "value": value})
            if note:
                row["note"] = note
        else:
            row["unresolved"] = True
        changes.append(row)
    if changes:
        meta = getattr(chain, "metadata", None)
        if isinstance(meta, dict):
            seen = meta.setdefault("target_resolution", [])
            seen.extend(c for c in changes if c not in seen)
    return changes


__all__ = ["resolve_action_targets"]
