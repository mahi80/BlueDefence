"""Ship evidence chains + meta-agent proposals to the ACP dashboard (Phase 0.3).

The walking skeleton keeps both artifacts in hash-chained JSONL files on
the agent host (``aegis/agents/shared/audit.py``, ``aegis/meta_agent/queue.py``).
Those files stay — they are the local WORM record and the export. This
sink additionally POSTs every entry to the dashboard
(``/api/soc/chains``, ``/api/soc/proposals`` — rbi #102; receipts, and the network sensor's
discovered AI usage ``/api/soc/ai-usage``) so investigations
survive agent restarts, are queryable per alert / verdict / agent, carry
HITL decisions, and become the dataset for the self-evolving loop.

Properties
- **Never on the hot path**: entries go on a bounded in-process queue and
  a daemon thread ships them; ``append()`` returns immediately. ``flush()``
  waits for the queue to drain (used at shutdown and in tests).
- **Fail-quiet**: a dashboard outage drops to a warning + a counter; the
  JSONL file is still the source of truth and the agent keeps working.
  Retried POSTs are harmless — ingestion is idempotent on
  ``integrity_hash``.
- **No secrets, no payloads beyond the chain itself**: the chain already
  excludes raw alert payloads by construction of the specialists.
- ``sync=True`` ships inline (tests / one-shot CLI runs).
"""

from __future__ import annotations

import logging
import os
import queue
import threading
import time
from dataclasses import asdict, is_dataclass
from typing import Any, Callable, Optional

logger = logging.getLogger("aegis.persist")

AGENT_NAME_DEFAULT = "aegis-soc-orchestrator"
AGENT_CODE_DEFAULT = "SOC-AGENTQ-01"
BU_DEFAULT = "Security"

#: transport(method, url, json_body, headers, timeout) -> dict
Transport = Callable[[str, str, Optional[dict], dict, float], dict]


def _httpx_transport(method: str, url: str, json_body: Optional[dict], headers: dict, timeout: float) -> dict:
    import httpx

    resp = httpx.request(method, url, json=json_body, headers=headers, timeout=timeout)
    resp.raise_for_status()
    data = resp.json()
    return data if isinstance(data, dict) else {"_raw": data}


def sink_from_env(**overrides: Any) -> Optional["DashboardSink"]:
    """A DashboardSink when ACP_DASHBOARD_URL is set (and AEGIS_PERSIST != 0), else None."""
    url = os.environ.get("ACP_DASHBOARD_URL", "").strip()
    if not url or os.environ.get("AEGIS_PERSIST", "1").strip().lower() in {"0", "false", "no", "off"}:
        return None
    return DashboardSink(dashboard_url=url, **overrides)


class DashboardSink:
    def __init__(
        self,
        dashboard_url: Optional[str] = None,
        api_key: Optional[str] = None,
        *,
        agent_name: Optional[str] = None,
        agent_code: Optional[str] = None,
        bu: Optional[str] = None,
        timeout: float = 5.0,
        sync: bool = False,
        max_queue: int = 1000,
        transport: Optional[Transport] = None,
    ):
        self.dashboard_url = (dashboard_url or os.environ.get("ACP_DASHBOARD_URL", "")).rstrip("/")
        self.api_key = api_key if api_key is not None else os.environ.get("ACP_API_KEY", "")
        self.agent_name = agent_name or os.environ.get("ACP_AGENT_NAME", AGENT_NAME_DEFAULT)
        self.agent_code = agent_code or os.environ.get("ACP_AGENT_CODE", AGENT_CODE_DEFAULT)
        self.bu = bu or os.environ.get("ACP_BU", BU_DEFAULT)
        self.timeout = timeout
        self.sync = sync
        self._transport: Transport = transport or _httpx_transport
        self._q: "queue.Queue[tuple[str, dict]]" = queue.Queue(maxsize=max_queue)
        self._worker: Optional[threading.Thread] = None
        self.shipped = 0
        self.failed = 0
        self.dropped = 0
        self.last_error = ""

    # ----------------------------------------------------------------- api --

    @property
    def enabled(self) -> bool:
        return bool(self.dashboard_url)

    def ship_chain(self, chain: Any, prev_hash: Optional[str] = None) -> Optional[dict]:
        """Queue (or send, when sync) one finalised EvidenceChain."""
        payload = chain.model_dump(mode="json") if hasattr(chain, "model_dump") else dict(chain)
        body = {
            "chain": payload,
            "prev_hash": prev_hash or "",
            "agent_name": self.agent_name,
            "agent_code": self.agent_code,
            "bu": self.bu,
            "source": "aegis",
        }
        return self._submit("/api/soc/chains", body)

    def ship_proposal(self, proposal: Any, validation: Any, integrity_hash: str,
                      prev_hash: Optional[str] = None, status: str = "pending_hitl") -> Optional[dict]:
        """Queue (or send, when sync) one queued meta-agent proposal entry."""
        p = asdict(proposal) if is_dataclass(proposal) else dict(proposal)
        v = asdict(validation) if is_dataclass(validation) else dict(validation or {})
        p.setdefault("title", f"{p.get('change_type', 'change')}: {str(p.get('rationale', ''))[:120]}")
        p.setdefault("target", p.get("target_module", ""))
        if "passed" not in v and "recommend_accept" in v:
            v["passed"] = bool(v["recommend_accept"])
        body = {
            "proposal": p,
            "validation": v,
            "status": status,
            "integrity_hash": integrity_hash,
            "prev_hash": prev_hash or "",
            "agent_name": self.agent_name,
            "agent_code": self.agent_code,
            "bu": self.bu,
            "source": "aegis",
        }
        return self._submit("/api/soc/proposals", body)

    def ship_receipt(self, receipt: Any, event: str = "apply") -> Optional[dict]:
        """Queue (or send, when sync) one enforcement receipt event (roadmap 1.5)."""
        r = receipt.to_dict() if hasattr(receipt, "to_dict") else (asdict(receipt) if is_dataclass(receipt) else dict(receipt))
        body = {
            "receipt": r,
            "event": str(event),
            "agent_name": self.agent_name,
            "agent_code": self.agent_code,
            "bu": self.bu,
            "source": "aegis",
        }
        return self._submit("/api/soc/receipts", body)

    def ship_ai_usage(self, rows: list[dict]) -> Optional[dict]:
        """Queue (or send, when sync) changed rows of the discovered-AI-usage register (RBI FREE-AI
        Rec 23, ``/ai-registry``) — in batches the dashboard accepts."""
        out: Optional[dict] = None
        for i in range(0, len(rows), 500):
            body = {"rows": rows[i:i + 500], "agent_name": self.agent_name, "agent_code": self.agent_code,
                    "bu": self.bu, "source": "aegis"}
            out = self._submit("/api/soc/ai-usage", body)
        return out

    def flush(self, timeout: float = 10.0) -> bool:
        """Wait for the background queue to drain. True when empty."""
        if self.sync or self._worker is None:
            return True
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self._q.unfinished_tasks == 0:
                return True
            time.sleep(0.05)
        return self._q.unfinished_tasks == 0

    # ------------------------------------------------------------- internals --

    def _submit(self, path: str, body: dict) -> Optional[dict]:
        if not self.enabled:
            return None
        if self.sync:
            return self._send(path, body)
        self._ensure_worker()
        try:
            self._q.put_nowait((path, body))
        except queue.Full:
            self.dropped += 1
            logger.warning("[persist] queue full (%d); dropped %s entry — JSONL file still has it",
                           self._q.maxsize, path)
        return None

    def _ensure_worker(self) -> None:
        if self._worker is None or not self._worker.is_alive():
            self._worker = threading.Thread(target=self._run, name="aegis-persist", daemon=True)
            self._worker.start()

    def _run(self) -> None:
        while True:
            path, body = self._q.get()
            try:
                self._send(path, body)
            finally:
                self._q.task_done()

    def _warn_throttled(self, msg: str, *args: Any) -> None:
        """A dashboard outage fails every call; log the first at WARNING, then one summary line per
        minute (with the count since), the rest at DEBUG — ``failed`` / ``last_error`` keep the truth."""
        now = time.time()
        last = getattr(self, "_last_warn", 0.0)
        if now - last >= 60.0:
            since = self.failed - getattr(self, "_failed_at_warn", 0)
            logger.warning(msg + (f" ({since} failures since last notice)" if since > 1 else ""), *args)
            self._last_warn, self._failed_at_warn = now, self.failed
        else:
            logger.debug(msg, *args)

    def _send(self, path: str, body: dict) -> Optional[dict]:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["X-API-Key"] = self.api_key
        try:
            data = self._transport("POST", f"{self.dashboard_url}{path}", body, headers, self.timeout)
        except Exception as e:  # noqa: BLE001 — outage is a runtime condition, not a crash
            self.failed += 1
            self.last_error = f"{type(e).__name__}: {str(e)[:160]}"
            self._warn_throttled("[persist] %s failed: %s", path, self.last_error)
            return None
        if data.get("error"):
            self.failed += 1
            self.last_error = str(data["error"])[:200]
            self._warn_throttled("[persist] %s refused: %s", path, self.last_error)
            return None
        self.shipped += 1
        return data
