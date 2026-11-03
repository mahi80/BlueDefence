"""One specialist tool that chokes on an odd field must not cost the chain every other tool's signal.

Each specialist builds its evidence from ``run_all_tools(alert)``: a list of tool calls. A number sent as a string,
``None`` inside a list, a dict ``payload`` or a string ``requestParameters`` raised inside ONE tool, the whole list
was lost and the chain fell back to an uncertain escalation (review round 3 S3-22). ``isolated`` runs one tool and
turns a crash into a low-weight result that says which tool failed and why.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any

logger = logging.getLogger("aegis.tools")


def isolated(call: Callable[[], Any], name: str, result_type: type) -> Any:
    try:
        return call()
    except Exception as e:  # noqa: BLE001 — the point: one tool's crash is one tool's problem
        logger.warning("[tools] %s failed on this alert (%s: %s) — its signal is missing, the others stand",
                       name, type(e).__name__, str(e)[:160])
        return result_type(name=name, data={"error": f"{type(e).__name__}: {str(e)[:160]}", "tool_failed": True},
                           weight="low")


__all__ = ["isolated"]
