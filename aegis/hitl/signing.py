"""Signed decisions: an approval row counts only if the console wrote it for a signed-in analyst.

Idea taken from AiSOC's separation of duties (MIT): the approver is the authenticated identity, never a
free-text field the caller picks. Before this, anyone or anything that could append a line to
``decisions.jsonl`` was an approver, and ``decided_by`` — the name the two-person rule compares — was
whatever that line said (code review 2026-11-02 response #7).

The console API (``ingest/console_api.py``) is the identity boundary: it is reached only with the console
token, and the console server fills ``X-AEGIS-User`` from the analyst's session. It now signs every row it
writes with an HMAC over the fields that matter. The service executes a row only when the signature
checks. The key is ``AEGIS_DECISION_KEY``, or derived from ``AEGIS_CONSOLE_TOKEN`` when that is not set —
so every install made by ``install.sh`` signs from day one. With neither (a lab), rows are accepted unsigned
and a warning says so.

Decisions made outside the console (an operator on the box) are signed with
``python -m aegis.hitl decide <approval_id> approve --by <name> [--reason …]``.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
from typing import Any

logger = logging.getLogger("aegis.hitl.signing")

_FIELDS = ("approval_id", "proposal_id", "status", "decision", "decided_by", "reason", "rationale",
           "corrected_verdict", "ts", "action")   # `action` ("type -> target") binds the decision to what it approves
_warned = False


def _key() -> bytes | None:
    explicit = os.environ.get("AEGIS_DECISION_KEY", "").strip()
    if explicit:
        return explicit.encode()
    token = os.environ.get("AEGIS_CONSOLE_TOKEN", "").strip()
    if token:
        return hmac.new(token.encode(), b"aegis-decision-signing-v1", hashlib.sha256).digest()
    return None


def enabled() -> bool:
    return _key() is not None


def _payload(row: dict) -> bytes:
    return json.dumps({k: row[k] for k in _FIELDS if k in row}, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, default=str).encode()


def sign(row: dict) -> dict:
    """``row`` with a ``sig`` field (unchanged when no key is configured)."""
    k = _key()
    if k is None:
        return row
    return {**row, "sig": hmac.new(k, _payload(row), hashlib.sha256).hexdigest()}


def verify(row: dict) -> tuple[bool, str]:
    """(trusted, why-not). With no key configured every row is trusted (and one warning is logged)."""
    global _warned
    k = _key()
    if k is None:
        if not _warned:
            _warned = True
            logger.warning("[hitl] decisions are NOT signed (set AEGIS_CONSOLE_TOKEN or AEGIS_DECISION_KEY): anything "
                           "that can write the HITL directory can approve actions")
        return True, ""
    sig = str(row.get("sig") or "")
    if not sig:
        return False, "unsigned decision row"
    want = hmac.new(k, _payload(row), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, want):
        return False, "decision signature does not match"
    return True, ""


def same_person(a: Any, b: Any) -> bool:
    """One person, whatever role prefix or case they decided under (``ciso:Alice`` == ``admin:alice``). The
    two-person rule compared whole strings, so a role change counted as a second person (review round 3 G1-16)."""
    def who(x: Any) -> str:
        return str(x or "").split(":", 1)[-1].strip().lower()
    return bool(who(a)) and who(a) == who(b)


def trusted_approver(decided_by: Any) -> tuple[bool, str]:
    """A human decision cannot claim to be the service itself (``aegis:hitl-timeout`` and friends)."""
    who = str(decided_by or "")
    if who.lower().startswith("aegis:"):
        return False, f"decided_by {who!r} is reserved for the service"
    return True, ""


__all__ = ["enabled", "same_person", "sign", "trusted_approver", "verify"]
