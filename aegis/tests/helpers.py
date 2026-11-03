"""Shared test helpers."""

from __future__ import annotations

from typing import Any


def alert_for(chain: Any, **extra: Any) -> dict:
    """The raw alert a chain's actions came from, as the service passes it to ResponseAgent.execute: every
    recommended action's target appears in it (unattended actions must be grounded in the alert)."""
    targets = [str(a.target) for a in getattr(chain, "recommended_actions", []) or []]
    return {"id": getattr(chain, "alert_id", ""), "entities": targets, **extra}
