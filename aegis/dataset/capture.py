"""Capture the (scrubbed) alert into the evidence chain so the loop keeps its own training data.

A persisted chain used to carry only ``alert_id``: verdict, evidence and
reasoning survived, the *input* did not — and a triage dataset without
inputs is worthless. ``SOCOrchestrator.handle`` now calls
:func:`capture_alert` before the chain is hashed and audited, so the
snapshot is covered by the integrity hash, lands in the local JSONL and in
the dashboard's ``soc_evidence_chains`` row, and the exporter
(``aegis.dataset.export``) reads it back from either.

The snapshot is scrubbed **on the agent host** (``scrub.Scrubber``) and
capped (``ALERT_SNAPSHOT_CAP``); ``AEGIS_DATASET_CAPTURE=0`` turns it off.
"""

from __future__ import annotations

import logging
import json
import os
from datetime import datetime, timezone
from typing import Any

from .scrub import Scrubber, scrubber_from_env

logger = logging.getLogger("aegis.dataset.capture")

SNAPSHOT_SCHEMA = "aegis.alert-snapshot/1"
ALERT_SNAPSHOT_CAP = 16 * 1024   # bytes of JSON per captured alert
METADATA_KEY = "alert"

_shared_scrubber: Scrubber | None = None


def capture_enabled() -> bool:
    return os.environ.get("AEGIS_DATASET_CAPTURE", "1").strip().lower() not in {"0", "false", "no", "off"}


def _scrubber() -> Scrubber:
    global _shared_scrubber
    if _shared_scrubber is None:
        _shared_scrubber = scrubber_from_env()
    return _shared_scrubber


def reset_shared_scrubber() -> None:
    """Tests change ``AEGIS_DATASET_SALT``; drop the cached scrubber."""
    global _shared_scrubber
    _shared_scrubber = None


def _shrink(obj: Any, budget: int) -> tuple[Any, bool]:
    """Truncate long strings (longest first) until the JSON fits ``budget``."""
    text = json.dumps(obj, default=str, sort_keys=True, separators=(",", ":"))
    if len(text) <= budget:
        return obj, False
    strings: list[tuple[int, list, Any]] = []   # (len, container, key)

    def walk(o: Any):
        if isinstance(o, dict):
            for k, v in o.items():
                if isinstance(v, str):
                    strings.append((len(v), o, k))
                else:
                    walk(v)
        elif isinstance(o, list):
            for i, v in enumerate(o):
                if isinstance(v, str):
                    strings.append((len(v), o, i))
                else:
                    walk(v)
    walk(obj)
    strings.sort(key=lambda t: t[0], reverse=True)
    for _, container, key in strings:
        container[key] = container[key][:256] + "…[truncated]"
        text = json.dumps(obj, default=str, sort_keys=True, separators=(",", ":"))
        if len(text) <= budget:
            break
    if len(text) > budget:  # still too big (huge nesting): keep scalar top-level fields only
        if isinstance(obj, dict):
            obj = {k: v for k, v in obj.items() if not isinstance(v, (dict, list))}
    return obj, True


def capture_alert(alert: dict, scrubber: Scrubber | None = None, *,
                  cap: int = ALERT_SNAPSHOT_CAP) -> dict:
    """Scrubbed, capped, fingerprinted snapshot of one alert."""
    from .schema import fingerprint   # local import: schema imports scrub, not capture

    sc = scrubber or _scrubber()
    before = sc.replacements
    data = sc.scrub(alert if isinstance(alert, dict) else {"value": alert})
    data, truncated = _shrink(json.loads(json.dumps(data, default=str)), cap)
    return {
        "schema": SNAPSHOT_SCHEMA,
        "fingerprint": fingerprint(alert if isinstance(alert, dict) else {"value": alert}),
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "scrubbed": sc.replacements - before,
        "salted": sc.salted,
        "truncated": truncated,
        "data": data,
    }


def capture_chain(chain: Any, scrubber: Scrubber | None = None) -> dict:
    """Scrubbed compact copy of the chain's trainer-facing text (evidence signals, action
    targets, reasoning). Taken with the scrubber that just learned the alert's identity
    literals, so a user id that is ``u_<token>`` in the alert snapshot is the same token here —
    the live chain stays raw for the analyst; only the dataset copy is pseudonymised."""
    from .schema import compact_chain   # local import: schema imports scrub, not capture

    sc = scrubber or _scrubber()
    raw = dict(chain.model_dump(mode="json") if hasattr(chain, "model_dump") else chain)
    # keep the metadata compact_chain reads (swarm, vote, model …) but never nest the snapshot in itself
    raw["metadata"] = {k: v for k, v in (raw.get("metadata") or {}).items() if k != METADATA_KEY}
    return sc.scrub(json.loads(json.dumps(compact_chain(raw), default=str)))


def attach(chain: Any, alert: dict) -> None:
    """Put the snapshot on ``chain.metadata["alert"]`` when capture is on (never raises).
    The snapshot carries the scrubbed alert and a scrubbed compact chain; the orchestrator
    calls this again after swarm enrichment, so the chain copy is the one that was acted on."""
    if not capture_enabled():
        return
    try:
        meta = getattr(chain, "metadata", None)
        if isinstance(meta, dict):
            snap = capture_alert(alert)       # learns the alert's identity literals first
            snap["chain"] = capture_chain(chain)
            meta[METADATA_KEY] = snap
    except Exception as exc:  # noqa: BLE001 — a capture failure must never cost a verdict
        logger.warning("[dataset] alert snapshot not captured for %s (%s: %s)", getattr(chain, "alert_id", "?"), type(exc).__name__, str(exc)[:120])
