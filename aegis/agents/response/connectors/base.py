"""Connector contract, receipts, registry (roadmap Phase 1.1).

Rules every connector inherits — vendor code never re-implements them:

* **Idempotent.** ``apply()`` derives a key from (connector, action type,
  target); a second apply of the same key while a receipt is active renews
  that receipt instead of acting twice.
* **TTL'd.** Every receipt carries ``expires_at`` (default 60 min, renewable;
  ``ttl_sec=0`` means permanent and must be asked for explicitly). The
  registry's ``sweep_expired()`` rolls expired receipts back, so a block
  that nobody renewed disappears on its own.
* **Dry-run aware.** In shadow mode (``AEGIS_ENFORCEMENT_MODE=shadow``, the
  default) no vendor call is made; the receipt records what *would* have
  happened, which is what the 2-week shadow comparison needs.
* **Never raises into the agent.** A vendor failure becomes a ``failed``
  receipt; the ResponseAgent turns that into a skipped / HITL-queued
  action, never a crash and never a silent success.
* **Auditable.** Receipts are plain dataclasses the ResponseAgent hands to
  the ACP guard (``post_tool_call`` result) and keeps on the response
  summary; ``Receipt.to_dict()`` is what lands in the audit chain.
"""

from __future__ import annotations

import collections
import hashlib
import logging
import os
import threading
import time
import uuid
from dataclasses import asdict, dataclass
from typing import Any, Callable, Iterable, Optional

from aegis.agents.shared.netguard import enforcement_refused

logger = logging.getLogger("aegis.connectors")

DEFAULT_TTL_SEC = 3600
MODE_SHADOW = "shadow"
MODE_LIVE = "live"

STATUS_APPLIED = "applied"
STATUS_DRY_RUN = "dry_run"
STATUS_RENEWED = "renewed"
STATUS_ROLLED_BACK = "rolled_back"
STATUS_EXPIRED = "expired"
STATUS_FAILED = "failed"
STATUS_UNSUPPORTED = "unsupported"
STATUS_REFUSED = "refused"           # never-block guard: enforcing this would risk own/lab infra
STATUS_SUPERSEDED = "superseded"     # replaced by a fresh apply (live after shadow, or a human re-approval)
STATUS_DRIFTED = "drifted"           # the vendor no longer enforces it (released or removed outside AEGIS)
STATUS_ROLLBACK_FAILED = "rollback_failed"   # the undo failed: the vendor still enforces it; retried by the sweep
ACTIVE_STATUSES = (STATUS_APPLIED, STATUS_DRY_RUN, STATUS_RENEWED)


class ConnectorError(RuntimeError):
    """Raised by ``_do_apply`` / ``_do_rollback`` when the vendor refused."""


class CannotUndo(ConnectorError):
    """``_do_rollback`` for an action with no undo (a killed process, a playbook with no reverse): retrying is pointless."""


MAX_ROLLBACK_ATTEMPTS = 10


@dataclass
class Receipt:
    receipt_id: str
    connector: str
    action_type: str
    target: str
    idempotency_key: str
    status: str
    dry_run: bool
    applied_at: float
    expires_at: Optional[float]            # None → permanent
    vendor_ref: str = ""
    detail: str = ""
    rollback_token: str = ""
    alert_id: str = ""
    approver: str = ""
    renewals: int = 0
    error: str = ""
    rolled_back_at: Optional[float] = None
    verified: bool | None = None        # read back at the vendor: True present, False absent, None not checked
    verified_at: float | None = None
    rollback_attempts: int = 0
    retry_rollback_at: float | None = None
    misses: int = 0                     # consecutive read-backs that did not show it (drift needs two)

    @property
    def active(self) -> bool:
        return self.status in ACTIVE_STATUSES

    def expired(self, now: float) -> bool:
        return self.active and self.expires_at is not None and now >= self.expires_at

    def to_dict(self) -> dict:
        return asdict(self)


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, "") or default)
    except ValueError:
        return default


def enforcement_mode() -> str:
    mode = os.environ.get("AEGIS_ENFORCEMENT_MODE", MODE_SHADOW).strip().lower()
    return MODE_LIVE if mode == MODE_LIVE else MODE_SHADOW


def canonical_target(target: str) -> str:
    """One spelling per target for the idempotency key: ``198.18.7.4``, ``198.18.7.4/32`` and
    ``::ffff:198.18.7.4`` are one address, and a host is case- and trailing-dot-insensitive. Two spellings used to
    get two keys over ONE vendor entry, so the first one's TTL deleted the entry the other still reported active
    (review W6)."""
    import ipaddress

    from aegis.agents.shared.netguard import unwrap
    t = str(target).strip().lower()
    try:
        net = unwrap(ipaddress.ip_network(t.strip("[]"), strict=False))
        return str(net.network_address) if net.prefixlen == net.max_prefixlen else str(net)
    except ValueError:
        return t.rstrip(".")


class Connector:
    """Base class. Subclasses set ``name`` + ``actions`` and implement
    ``_do_apply`` / ``_do_rollback``; everything else is inherited."""

    name: str = "base"
    actions: frozenset[str] = frozenset()
    # A permanent action a person can undo at the vendor (lift containment, re-enable an account) leaves our
    # receipt "active" while the vendor no longer enforces it. For these connectors a human re-approval of an
    # active permanent receipt calls the vendor again instead of a no-op renewal. Set where the vendor call is
    # idempotent or re-running it is the point (EDR contain, SOAR playbooks, SWG category add).
    reapply_on_human_approval: bool = False
    fallback: bool = False               # set on the registry's catch-all connector

    def __init__(self, *, dry_run: Optional[bool] = None, default_ttl_sec: int = DEFAULT_TTL_SEC,
                 clock: Callable[[], float] = time.time):
        self._dry_run_override = None if dry_run is None else bool(dry_run)
        self.default_ttl_sec = default_ttl_sec
        self._clock = clock
        self._lock = threading.Lock()
        self._active: dict[str, Receipt] = {}
        self.history: list[Receipt] = []
        # receipts an apply() changed besides the one it returns (an expired one rolled back inline, a shadow one
        # superseded by a live apply): the registry emits them, so the receipt log records their end too and a
        # restart does not re-adopt them (review round 5 Y5-3)
        self._side_events: collections.deque[tuple[str, Receipt]] = collections.deque(maxlen=256)

    @property
    def dry_run(self) -> bool:
        """Shadow unless ``AEGIS_ENFORCEMENT_MODE=live`` — read per call, so a licence that drops to over-limit
        or evaluation mid-run (which forces the variable back to shadow) takes effect without a restart."""
        return (enforcement_mode() == MODE_SHADOW) if self._dry_run_override is None else self._dry_run_override

    @dry_run.setter
    def dry_run(self, value: bool) -> None:
        self._dry_run_override = bool(value)

    # ---------------------------------------------------------- vendor --

    def _do_apply(self, action: Any, key: str, ttl_sec: Optional[int]) -> tuple[str, str, str]:
        """Vendor call. Returns (vendor_ref, detail, rollback_token). Raise ConnectorError on refusal."""
        raise NotImplementedError

    def _do_rollback(self, receipt: Receipt) -> str:
        """Vendor undo. Returns detail. Raise ConnectorError on refusal."""
        raise NotImplementedError

    def _do_verify(self, receipt: Receipt) -> bool | None:
        """Vendor read-back: is this enforcement in place right now? None = this connector cannot tell."""
        return None

    def verify(self, receipt: Receipt) -> bool | None:
        """Read the enforcement back at the vendor (idea from AiSOC: every unattended containment is verified,
        the gap counted rather than hidden). A dry-run or inactive receipt is not checked; a vendor error is
        "cannot tell" (None), never "present"."""
        if receipt.dry_run or not receipt.active:
            return None
        try:
            v = self._do_verify(receipt)
        except Exception as e:  # noqa: BLE001 — a failed read-back is unknown, not success
            logger.warning("[connector:%s] verify %s %s failed: %s", self.name, receipt.action_type, receipt.target,
                           str(e)[:160])
            v = None
        receipt.verified, receipt.verified_at = v, self._clock()
        return v

    def forget(self, receipt: Receipt, why: str) -> None:
        """The vendor does not show this receipt's enforcement: undo whatever of it may still be there, then mark
        it ``drifted`` and drop it from the active set.

        It used to be dropped with no undo (review round 3 G3-1). A read-back can miss a rule that IS there
        (read-after-write lag, a vendor that rewrites the entry), and the next approval then created a second rule
        and the first was orphaned for good. The undo is best effort; one that fails keeps the receipt as
        ``rollback_failed`` so the sweep retries it, exactly like a failed TTL rollback."""
        # Only where an apply creates a NEW vendor object (a WAF rule id) can a missed read-back orphan one. Where
        # the vendor call is idempotent (contain a host, add to a category: `reapply_on_human_approval`), an undo
        # on a misread would lift a containment that is in fact in force, so nothing is undone there.
        undo = not receipt.dry_run and not self.reapply_on_human_approval
        rb = self.rollback(receipt, reason="read-back did not show it") if undo else receipt
        if rb.status == STATUS_ROLLBACK_FAILED:
            rb.error = f"{why}; {rb.error}"
            return
        receipt.status, receipt.error = STATUS_DRIFTED, why
        with self._lock:
            if self._active.get(receipt.idempotency_key) is receipt:
                self._active.pop(receipt.idempotency_key, None)

    def check_drift(self) -> list[Receipt]:
        """Re-verify every active live receipt; one the vendor no longer enforces (released or removed outside
        AEGIS) is marked ``drifted`` and dropped from the active set, so the next approval applies it afresh
        and nothing reports it as still in force.

        A receipt younger than ``AEGIS_VERIFY_GRACE_S`` (default 60 s) is not judged — vendors propagate rules
        with a lag — and it takes two consecutive misses, not one, to call it drifted (review round 3 G3-1)."""
        now = self._clock()
        grace = _env_float("AEGIS_VERIFY_GRACE_S", 60.0)
        with self._lock:
            live = [r for r in self._active.values() if not r.dry_run and r.active and now - r.applied_at >= grace]
        out = []
        for r in live:
            v = self.verify(r)
            if v is True:
                r.misses = 0
            elif v is False:
                r.misses += 1
                if r.misses < 2:
                    logger.warning("[connector:%s] %s %s not visible on read-back (1st miss; confirming next check)",
                                   self.name, r.action_type, r.target)
                    continue
                self.forget(r, "vendor no longer enforces this action (released or removed outside AEGIS)")
                logger.error("[connector:%s] %s %s is no longer in force at the vendor (receipt %s)", self.name,
                             r.action_type, r.target, r.receipt_id)
                out.append(r)
        return out

    def _do_renew(self, receipt: Receipt, ttl_sec: int) -> str:
        """Vendor extend; default re-applies. Returns detail."""
        ref, detail, _ = self._do_apply(_ActionView(receipt.action_type, receipt.target), receipt.idempotency_key, ttl_sec)
        return detail or f"renewed {ref}"

    # ------------------------------------------------------------ api --

    def supports(self, action_type: str) -> bool:
        return action_type in self.actions

    def supports_target(self, target: str) -> bool:
        """Whether this connector can act on this *kind* of target (an IP, a client
        fingerprint ``fp:…``, a host name …). Vendor connectors narrow it; the registry
        routes an action to the first connector that supports both its type and its target."""
        return True

    def idempotency_key(self, action: Any) -> str:
        raw = f"{self.name}:{action.action_type}:{canonical_target(str(action.target))}"
        return hashlib.sha256(raw.encode()).hexdigest()[:24]

    def apply(self, action: Any, *, alert_id: str = "", approver: str = "",
              ttl_sec: Optional[int] = None) -> Receipt:
        now = self._clock()
        ttl = self.default_ttl_sec if ttl_sec is None else int(ttl_sec)
        key = self.idempotency_key(action)
        if self.supports(action.action_type) and not self.supports_target(str(action.target)):
            return self._record(Receipt(
                receipt_id=_rid(), connector=self.name, action_type=action.action_type,
                target=str(action.target), idempotency_key=key, status=STATUS_UNSUPPORTED,
                dry_run=self.dry_run, applied_at=now, expires_at=None, alert_id=alert_id,
                approver=approver, error=f"{self.name} cannot {action.action_type} this kind of target",
            ))
        if not self.supports(action.action_type):
            return self._record(Receipt(
                receipt_id=_rid(), connector=self.name, action_type=action.action_type,
                target=str(action.target), idempotency_key=key, status=STATUS_UNSUPPORTED,
                dry_run=self.dry_run, applied_at=now, expires_at=None, alert_id=alert_id,
                approver=approver, error=f"{self.name} does not support {action.action_type}",
            ))
        with self._lock:
            stale = self._active.get(key)
        if stale is not None and stale.expired(now):
            # expired but not swept yet: undo it before replacing it. It used to be dropped on the floor and the
            # vendor kept the rule (Imperva) or a TTL'd entry nothing would ever remove (review round 3 G3-2).
            self.rollback(stale, reason="expired; replaced by a new apply")
            if stale.status == STATUS_ROLLED_BACK:
                stale.status = STATUS_EXPIRED
            self._side_events.append(("expired", stale))
        with self._lock:
            existing = self._active.get(key)
            still_there = existing is not None and existing.status == STATUS_ROLLBACK_FAILED
            if still_there:
                # the undo failed, so the vendor still enforces it: this apply keeps that rule instead of creating a
                # second one and orphaning the first (review W5)
                existing.status, existing.retry_rollback_at = (STATUS_DRY_RUN if existing.dry_run else STATUS_APPLIED), None
                existing.error, existing.rollback_attempts = "", 0
            if existing is not None and existing.active and (still_there or not existing.expired(now)):
                human = bool(approver) and not approver.startswith("aegis:")
                fresh = ((existing.dry_run and not self.dry_run)          # shadow receipt, now live: enforce it
                         or (self.reapply_on_human_approval and human and not existing.dry_run
                             and existing.expires_at is None))
                if not fresh:
                    return self._renew_locked(existing, ttl, now, approver=approver)
                existing.status = STATUS_SUPERSEDED
                self._active.pop(key, None)
                self._side_events.append(("superseded", existing))
        expires = None if ttl <= 0 else now + ttl
        receipt = Receipt(
            receipt_id=_rid(), connector=self.name, action_type=action.action_type,
            target=str(action.target), idempotency_key=key, status=STATUS_DRY_RUN if self.dry_run else STATUS_APPLIED,
            dry_run=self.dry_run, applied_at=now, expires_at=expires, alert_id=alert_id, approver=approver,
        )
        if self.dry_run:
            receipt.detail = f"[shadow] would {action.action_type} {action.target} via {self.name}" + (
                f" for {ttl}s" if expires else " permanently")
        else:
            try:
                ref, detail, token = self._do_apply(action, key, ttl if expires else None)
                receipt.vendor_ref, receipt.detail, receipt.rollback_token = str(ref), str(detail), str(token)
            except Exception as e:  # noqa: BLE001 — a vendor failure is a receipt, never a crash
                receipt.status = STATUS_FAILED
                receipt.error = f"{type(e).__name__}: {str(e)[:200]}"
                logger.warning("[connector:%s] apply %s %s failed: %s", self.name, action.action_type, action.target, receipt.error)
        with self._lock:
            if receipt.active:
                self._active[key] = receipt
        return self._record(receipt)

    def preview(self, action: Any, *, alert_id: str = "", approver: str = "", ttl_sec: Optional[int] = None,
                note: str = "") -> Receipt:
        """A dry-run receipt for what ``apply`` would do — never calls the vendor and never
        becomes an active enforcement (used to score a policy before it acts, e.g. auto-block)."""
        now = self._clock()
        ttl = self.default_ttl_sec if ttl_sec is None else int(ttl_sec)
        target_ok = self.supports(action.action_type) and self.supports_target(str(action.target))
        receipt = Receipt(
            receipt_id=_rid(), connector=self.name, action_type=action.action_type, target=str(action.target),
            idempotency_key=self.idempotency_key(action), status=STATUS_DRY_RUN if target_ok else STATUS_UNSUPPORTED,
            dry_run=True, applied_at=now, expires_at=now + ttl if ttl > 0 else None, alert_id=alert_id, approver=approver,
            detail=f"[{note or 'preview'}] would {action.action_type} {action.target} via {self.name}" + (f" for {ttl}s" if ttl > 0 else ""),
            error="" if target_ok else f"{self.name} cannot {action.action_type} this target")
        return self._record(receipt)

    def renew(self, receipt: Receipt, ttl_sec: Optional[int] = None) -> Receipt:
        with self._lock:
            return self._renew_locked(receipt, self.default_ttl_sec if ttl_sec is None else int(ttl_sec), self._clock())

    def rollback(self, receipt: Receipt, *, reason: str = "") -> Receipt:
        now = self._clock()
        if not (receipt.active or receipt.status == STATUS_ROLLBACK_FAILED):
            return receipt
        if not receipt.dry_run:
            try:
                receipt.detail = str(self._do_rollback(receipt)) or receipt.detail
            except CannotUndo as e:
                receipt.status = STATUS_FAILED
                receipt.error = f"rollback {type(e).__name__}: {str(e)[:200]}"
                logger.error("[connector:%s] %s %s cannot be rolled back: %s", self.name, receipt.action_type,
                             receipt.target, receipt.error)
                return self._record(receipt)
            except Exception as e:  # noqa: BLE001
                # The rule is still at the vendor. It used to become `failed` — inactive, never retried, and the next
                # apply orphaned it (an Imperva 503 on DELETE left rule 1001 in place for good — review W5). Keep it
                # tracked and retry with backoff (1 min, 2, 4 … capped at 1 h).
                receipt.status = STATUS_ROLLBACK_FAILED
                receipt.rollback_attempts += 1
                if receipt.rollback_attempts >= MAX_ROLLBACK_ATTEMPTS:
                    receipt.retry_rollback_at = None            # stop retrying; it stays listed for a human
                    receipt.error = f"rollback gave up after {receipt.rollback_attempts} attempts: {type(e).__name__}: {str(e)[:160]}"
                    logger.error("[connector:%s] rollback of %s %s abandoned after %d attempts — remove it at the vendor: %s",
                                 self.name, receipt.action_type, receipt.target, receipt.rollback_attempts, receipt.error)
                    with self._lock:
                        self._active[receipt.idempotency_key] = receipt
                    return self._record(receipt)
                receipt.retry_rollback_at = now + min(3600.0, 60.0 * 2 ** (receipt.rollback_attempts - 1))
                receipt.error = f"rollback {type(e).__name__}: {str(e)[:200]}"
                logger.error("[connector:%s] rollback of %s %s failed (attempt %d, next in %.0fs): %s", self.name,
                             receipt.action_type, receipt.target, receipt.rollback_attempts,
                             receipt.retry_rollback_at - now, receipt.error)
                with self._lock:
                    self._active[receipt.idempotency_key] = receipt
                return self._record(receipt)
        else:
            receipt.detail = f"[shadow] would roll back {receipt.action_type} {receipt.target}"
        receipt.status = STATUS_ROLLED_BACK
        receipt.rolled_back_at = now
        if reason:
            receipt.detail = f"{receipt.detail} ({reason})"
        with self._lock:
            self._active.pop(receipt.idempotency_key, None)
        return self._record(receipt)

    def sweep_expired(self) -> list[Receipt]:
        now = self._clock()
        with self._lock:
            due = [r for r in self._active.values() if r.expired(now) or (
                r.status == STATUS_ROLLBACK_FAILED and r.retry_rollback_at is not None and now >= r.retry_rollback_at)]
        out = []
        for r in due:
            rb = self.rollback(r, reason="ttl expired")
            if rb.status == STATUS_ROLLED_BACK:
                rb.status = STATUS_EXPIRED
            out.append(rb)
        return out

    @property
    def active_receipts(self) -> list[Receipt]:
        with self._lock:
            return list(self._active.values())

    # ------------------------------------------------------- internals --

    def _renew_locked(self, receipt: Receipt, ttl: int, now: float, *, approver: str = "") -> Receipt:
        receipt.renewals += 1
        # a renewal only ever extends: a later automated re-apply (1 h TTL) must not put an expiry back on
        # an action a human approved permanently, or pull a longer expiry in
        if receipt.expires_at is not None:
            receipt.expires_at = None if ttl <= 0 else max(receipt.expires_at, now + ttl)
        if approver and not approver.startswith("aegis:") and receipt.approver != approver:
            receipt.approver = approver if not receipt.approver else f"{receipt.approver}; {approver}"
        receipt.status = STATUS_DRY_RUN if receipt.dry_run else STATUS_RENEWED
        if not receipt.dry_run:
            try:
                left = 0 if receipt.expires_at is None else max(1, int(receipt.expires_at - now))
                receipt.detail = str(self._do_renew(receipt, left))
            except Exception as e:  # noqa: BLE001
                receipt.error = f"renew {type(e).__name__}: {str(e)[:200]}"
        else:
            receipt.detail = f"[shadow] would renew {receipt.action_type} {receipt.target}"
        self._active[receipt.idempotency_key] = receipt
        self.history.append(receipt)
        return receipt

    def _record(self, receipt: Receipt) -> Receipt:
        self.history.append(receipt)
        return receipt


@dataclass
class _ActionView:
    action_type: str
    target: str


def _rid() -> str:
    return f"rcpt_{uuid.uuid4().hex[:12]}"


def _nothing_to_enforce(action_type: str) -> bool:
    """allow / monitor change nothing at any vendor: recording them IS doing them. In live mode they used to come
    back ``unsupported`` from the fallback and every benign verdict filed an approval card (review round 4 R4-10).
    Hand-offs (escalate) are not in this set: they still reach a person."""
    from ..contracts import Impact, contract
    c = contract(str(action_type))
    return c is not None and c.impact == Impact.READ_ONLY and not c.hand_off


class LoggingConnector(Connector):
    """Default connector: records the action, touches nothing. This is the
    walking-skeleton ``[mock]`` behaviour, now expressed as a receipt so it
    is auditable and so swapping in a vendor connector changes nothing
    else. Accepts every action type."""

    name = "log"

    def supports(self, action_type: str) -> bool:
        return True

    def apply(self, action: Any, *, alert_id: str = "", approver: str = "",
              ttl_sec: int | None = None) -> Receipt:
        # As the registry's fallback in LIVE mode, "applied" here meant "enforced" to everyone downstream while
        # no vendor was called at all (review round 3 G3-3). Live mode with no connector for the action is
        # "unsupported": it parks for a human. Shadow and log-only labs keep the walking-skeleton receipt.
        if self.fallback and enforcement_mode() == MODE_LIVE and not _nothing_to_enforce(action.action_type):
            return self._record(Receipt(
                receipt_id=_rid(), connector=self.name, action_type=str(action.action_type), target=str(action.target),
                idempotency_key=self.idempotency_key(action), status=STATUS_UNSUPPORTED, dry_run=False,
                applied_at=self._clock(), expires_at=None, alert_id=alert_id, approver=approver,
                error=f"live mode, but no vendor connector enforces {action.action_type}; a human must do it"))
        return super().apply(action, alert_id=alert_id, approver=approver, ttl_sec=ttl_sec)

    def _do_apply(self, action: Any, key: str, ttl_sec: Optional[int]) -> tuple[str, str, str]:
        return f"log-{key[:8]}", f"[log] {action.action_type} on {action.target}", key

    def _do_rollback(self, receipt: Receipt) -> str:
        return f"[log] undo {receipt.action_type} on {receipt.target}"


class ConnectorRegistry:
    """Routes an action type to the first connector that supports it;
    ``fallback`` (the LoggingConnector by default) catches the rest."""

    def __init__(self, connectors: Iterable[Connector] = (), *, fallback: Optional[Connector] = None,
                 on_receipt: Iterable[Callable[[str, Receipt], Any]] = ()):
        self._connectors: list[Connector] = list(connectors)
        self.fallback = fallback if fallback is not None else LoggingConnector(dry_run=False)
        self.fallback.fallback = True
        self._subscribers: list[Callable[[str, Receipt], Any]] = list(on_receipt)

    def register(self, connector: Connector) -> None:
        self._connectors.append(connector)

    def subscribe(self, fn: Callable[[str, Receipt], Any]) -> None:
        """``fn(event, receipt)`` is called for every receipt the registry produces
        (events: ``apply``, ``rollback``, ``expired``). Used by the receipt log /
        dashboard sink (roadmap 1.5 shadow comparison). Subscriber errors are logged, never raised."""
        self._subscribers.append(fn)

    def _emit(self, event: str, receipt: Receipt) -> Receipt:
        for fn in self._subscribers:
            try:
                fn(event, receipt)
            except Exception as e:  # noqa: BLE001 — bookkeeping must never block enforcement
                logger.warning("[connectors] receipt subscriber failed on %s: %s", event, str(e)[:120])
        return receipt

    @property
    def connectors(self) -> list[Connector]:
        return list(self._connectors) + [self.fallback]

    def restore(self, entries: Iterable[dict]) -> int:
        """Re-adopt the receipts that were active when the process stopped, from the receipt log's events in the
        order they were written. ``_active`` lived only in memory: after a restart TTL rollback, drift checks and
        the edge blocklist forgot every enforcement in force (review round 4 R4-1).

        Per (connector, idempotency key) the LAST event wins, so a shadow receipt superseded by a live one, or an
        expired one replaced inside apply(), is never re-adopted over its successor; preview events (auto-block /
        breaker shadow scoring) never become enforcement (review round 5 Y5-3). Expired ones are rolled back by
        the next sweep. Returns how many were restored."""
        from dataclasses import fields
        names = {f.name for f in fields(Receipt)}
        by_name = {c.name: c for c in self.connectors}
        last: dict[tuple[str, str], dict] = {}
        rows = [e for e in entries if isinstance(e, dict)]
        if any("recorded_at" in e for e in rows):
            rows.sort(key=lambda e: float(e.get("recorded_at") or 0.0))      # stable: ties keep log order
        for e in rows:
            if e.get("event") == "preview":
                continue
            key = (str(e.get("connector", "")), str(e.get("idempotency_key") or ""))
            if key[1]:
                last[key] = e
        n = 0
        for (cname, ikey), e in last.items():
            c = by_name.get(cname)
            if c is None or e.get("status") not in ACTIVE_STATUSES:
                continue
            try:
                r = Receipt(**{k: v for k, v in e.items() if k in names})
            except TypeError:
                continue
            with c._lock:
                if ikey not in c._active:
                    c._active[ikey] = r
                    n += 1
        if n:
            logger.warning("[connectors] restored %d active receipt(s) from the receipt log — expired ones are rolled "
                           "back on the next sweep", n)
        return n

    def route(self, action_type: str) -> Connector:
        for c in self._connectors:
            if c.supports(action_type):
                return c
        return self.fallback

    def route_action(self, action: Any) -> Connector:
        """First connector supporting the action type *and* its target kind. When some
        connector takes the type but none can act on the target (a fingerprint on an
        IP-only WAF) that connector is returned, and its receipt says ``unsupported`` —
        the action parks for a human instead of being "done" by the logging fallback."""
        target = str(action.target)
        typed = [c for c in self._connectors if c.supports(action.action_type)]
        for c in typed:
            if c.supports_target(target):
                return c
        return typed[0] if typed else self.fallback

    def apply(self, action: Any, **ctx: Any) -> Receipt:
        # Never-block guard: a connectivity-severing action against loopback / reserved /
        # operator-listed space is refused before any vendor call — auto, auto-approved or
        # human-approved alike. In a loopback lab every source is 127.0.0.1 (the SOC's own
        # ingest, the shim's sink, every agent), so an un-gated block would blind the SOC.
        refuse, why = enforcement_refused(str(action.action_type), str(action.target))
        if refuse:
            return self._emit("apply", Receipt(
                receipt_id=_rid(), connector="never-block-guard",
                action_type=str(action.action_type), target=str(action.target),
                idempotency_key="never-block", status=STATUS_REFUSED, dry_run=True,
                applied_at=time.time(), expires_at=None,
                alert_id=str(ctx.get("alert_id", "")), approver=str(ctx.get("approver", "")),
                error=why, detail=f"never-block guard refused {action.action_type} on {action.target}"))
        c = self.route_action(action)
        receipt = c.apply(action, **ctx)
        side = getattr(c, "_side_events", None)
        while side:
            ev, r = side.popleft()
            self._emit(ev, r)
        return self._emit("apply", receipt)

    def preview(self, action: Any, **ctx: Any) -> Receipt:
        return self._emit("preview", self.route_action(action).preview(action, **ctx))

    def rollback(self, receipt: Receipt, *, reason: str = "") -> Receipt:
        for c in self.connectors:
            if c.name == receipt.connector:
                return self._emit("rollback", c.rollback(receipt, reason=reason))
        receipt.error = f"no connector named {receipt.connector}"
        return receipt

    def sweep_expired(self) -> list[Receipt]:
        out: list[Receipt] = []
        for c in self.connectors:
            out.extend(self._emit("expired", r) for r in c.sweep_expired())
        return out

    def verify(self, receipt: Receipt) -> bool | None:
        for c in self.connectors:
            if c.name == receipt.connector:
                return c.verify(receipt)
        return None

    def forget(self, receipt: Receipt, why: str) -> None:
        for c in self.connectors:
            if c.name == receipt.connector:
                c.forget(receipt, why)
                self._emit("drifted", receipt)
                return

    def check_drift(self) -> list[Receipt]:
        out: list[Receipt] = []
        for c in self.connectors:
            out.extend(self._emit("drifted", r) for r in c.check_drift())
        return out

    @property
    def active_receipts(self) -> list[Receipt]:
        return [r for c in self.connectors for r in c.active_receipts]

    @property
    def mode(self) -> str:
        return MODE_SHADOW if all(c.dry_run for c in self._connectors) and self._connectors else (
            MODE_LIVE if self._connectors else "log-only")


def registry_from_env(on_receipt: Iterable[Callable[[str, Receipt], Any]] = ()) -> ConnectorRegistry:
    """Build the registry from env (roadmap 1.2):

    - ``AEGIS_WAF_VENDOR``  = imperva | f5 | cloudflare | aws | azure | mock | mock-<cloud> → WAF connector (block / challenge / throttle on IPs)
    - ``AEGIS_SOAR_VENDOR`` = xsoar | sentinel | mock → playbook connector for the actions in ``AEGIS_SOAR_PLAYBOOKS``
    - ``AEGIS_EDR_VENDOR``  = crowdstrike | defender | sentinelone | mock[-defender|-sentinelone] → host isolate
      (+ Falcon RTR kill_process); all HITL
    - ``AEGIS_SWG_VENDOR``  = zscaler | mock → ZIA egress block (block_egress on a destination URL/IP)
    - ``AEGIS_FW_VENDOR``   = panos | fortigate | mock-panos | mock-fortigate → firewall block / block_egress of one IP
    - ``AEGIS_IDP_VENDOR``  = entra | mock → revoke_sessions / force_logout / lock_account on a user principal
    - ``AEGIS_PAM_VENDOR``  = cyberark | mock → rotate_credential of one vaulted account
    - ``AEGIS_AGENT_SANDBOX`` = openshell | mock → NVIDIA OpenShell network quarantine of an AI agent (isolate agent:<sandbox>)
    - ``AEGIS_ENFORCEMENT_MODE`` = shadow (default) | live — shadow makes every vendor connector dry-run

    Registration order (OpenShell, WAF, SOAR, EDR, SWG, firewall, IdP, PAM) gives the SOAR playbook connector priority for
    ``isolate`` when a playbook is configured; the direct EDR connector catches it otherwise.

    Anything not routed falls to the logging connector. ``mock`` vendors are the in-process
    fakes (``mock_vendor.py``) behind the real connector classes."""
    connectors: list[Connector] = []
    try:
        # first: it claims only agent:/sandbox: targets, so a rogue AI agent's isolate never falls to the host EDR
        from .openshell import openshell_from_env
        osh = openshell_from_env()
        if osh is not None:
            connectors.append(osh)
    except Exception as e:  # noqa: BLE001
        logger.warning("[connectors] OpenShell connector not built: %s", str(e)[:160])
    try:
        from .waf import waf_from_env
        waf = waf_from_env()
        if waf is not None:
            connectors.append(waf)
    except Exception as e:  # noqa: BLE001 — a bad env block must not take the response agent down
        logger.warning("[connectors] WAF connector not built: %s", str(e)[:160])
    try:
        from .soar import soar_from_env
        soar = soar_from_env()
        if soar is not None:
            connectors.append(soar)
    except Exception as e:  # noqa: BLE001
        logger.warning("[connectors] SOAR connector not built: %s", str(e)[:160])
    try:
        from .edr import crowdstrike_from_env
        edr = crowdstrike_from_env()
        if edr is not None:
            connectors.append(edr)
    except Exception as e:  # noqa: BLE001
        logger.warning("[connectors] EDR connector not built: %s", str(e)[:160])
    try:
        from .swg import zscaler_from_env
        swg = zscaler_from_env()
        if swg is not None:
            connectors.append(swg)
    except Exception as e:  # noqa: BLE001
        logger.warning("[connectors] SWG connector not built: %s", str(e)[:160])
    for label, mod, fn in (("firewall", ".firewall", "firewall_from_env"), ("identity", ".identity", "idp_from_env"),
                           ("PAM", ".identity", "pam_from_env")):
        try:
            import importlib
            c = getattr(importlib.import_module(mod, __package__), fn)()
            if c is not None:
                connectors.append(c)
        except Exception as e:  # noqa: BLE001
            logger.warning("[connectors] %s connector not built: %s", label, str(e)[:160])
    reg = ConnectorRegistry(connectors, on_receipt=on_receipt)
    if connectors:
        logger.info("[connectors] %s mode: %s", reg.mode, ", ".join(f"{c.name}({'dry-run' if c.dry_run else 'LIVE'})" for c in connectors))
    return reg
