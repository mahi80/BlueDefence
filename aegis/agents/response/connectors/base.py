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
ACTIVE_STATUSES = (STATUS_APPLIED, STATUS_DRY_RUN, STATUS_RENEWED)


class ConnectorError(RuntimeError):
    """Raised by ``_do_apply`` / ``_do_rollback`` when the vendor refused."""


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

    @property
    def active(self) -> bool:
        return self.status in ACTIVE_STATUSES

    def expired(self, now: float) -> bool:
        return self.active and self.expires_at is not None and now >= self.expires_at

    def to_dict(self) -> dict:
        return asdict(self)


def enforcement_mode() -> str:
    mode = os.environ.get("AEGIS_ENFORCEMENT_MODE", MODE_SHADOW).strip().lower()
    return MODE_LIVE if mode == MODE_LIVE else MODE_SHADOW


class Connector:
    """Base class. Subclasses set ``name`` + ``actions`` and implement
    ``_do_apply`` / ``_do_rollback``; everything else is inherited."""

    name: str = "base"
    actions: frozenset[str] = frozenset()

    def __init__(self, *, dry_run: Optional[bool] = None, default_ttl_sec: int = DEFAULT_TTL_SEC,
                 clock: Callable[[], float] = time.time):
        self.dry_run = (enforcement_mode() == MODE_SHADOW) if dry_run is None else bool(dry_run)
        self.default_ttl_sec = default_ttl_sec
        self._clock = clock
        self._lock = threading.Lock()
        self._active: dict[str, Receipt] = {}
        self.history: list[Receipt] = []

    # ---------------------------------------------------------- vendor --

    def _do_apply(self, action: Any, key: str, ttl_sec: Optional[int]) -> tuple[str, str, str]:
        """Vendor call. Returns (vendor_ref, detail, rollback_token). Raise ConnectorError on refusal."""
        raise NotImplementedError

    def _do_rollback(self, receipt: Receipt) -> str:
        """Vendor undo. Returns detail. Raise ConnectorError on refusal."""
        raise NotImplementedError

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
        raw = f"{self.name}:{action.action_type}:{str(action.target).strip().lower()}"
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
            existing = self._active.get(key)
            if existing is not None and existing.active and not existing.expired(now):
                return self._renew_locked(existing, ttl, now)
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
        if not receipt.active:
            return receipt
        if not receipt.dry_run:
            try:
                receipt.detail = str(self._do_rollback(receipt)) or receipt.detail
            except Exception as e:  # noqa: BLE001
                receipt.status = STATUS_FAILED
                receipt.error = f"rollback {type(e).__name__}: {str(e)[:200]}"
                logger.error("[connector:%s] rollback of %s failed: %s", self.name, receipt.receipt_id, receipt.error, exc_info=True)
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
            due = [r for r in self._active.values() if r.expired(now)]
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

    def _renew_locked(self, receipt: Receipt, ttl: int, now: float) -> Receipt:
        receipt.renewals += 1
        receipt.expires_at = None if ttl <= 0 else now + ttl
        receipt.status = STATUS_DRY_RUN if receipt.dry_run else STATUS_RENEWED
        if not receipt.dry_run:
            try:
                receipt.detail = str(self._do_renew(receipt, ttl))
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


class LoggingConnector(Connector):
    """Default connector: records the action, touches nothing. This is the
    walking-skeleton ``[mock]`` behaviour, now expressed as a receipt so it
    is auditable and so swapping in a vendor connector changes nothing
    else. Accepts every action type."""

    name = "log"

    def supports(self, action_type: str) -> bool:
        return True

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
        return self._emit("apply", self.route_action(action).apply(action, **ctx))

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
    - ``AEGIS_EDR_VENDOR``  = crowdstrike | mock → Falcon host contain (isolate) + RTR kill_process (both HITL)
    - ``AEGIS_SWG_VENDOR``  = zscaler | mock → ZIA egress block (block_egress on a destination URL/IP)
    - ``AEGIS_ENFORCEMENT_MODE`` = shadow (default) | live — shadow makes every vendor connector dry-run

    Registration order (WAF, SOAR, EDR, SWG) gives the SOAR playbook connector priority for
    ``isolate`` when a playbook is configured; the direct EDR connector catches it otherwise.

    Anything not routed falls to the logging connector. ``mock`` vendors are the in-process
    fakes (``mock_vendor.py``) behind the real connector classes."""
    connectors: list[Connector] = []
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
    reg = ConnectorRegistry(connectors, on_receipt=on_receipt)
    if connectors:
        logger.info("[connectors] %s mode: %s", reg.mode, ", ".join(f"{c.name}({'dry-run' if c.dry_run else 'LIVE'})" for c in connectors))
    return reg
