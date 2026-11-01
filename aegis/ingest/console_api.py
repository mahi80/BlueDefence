"""Read API for the analyst console, served by the push receiver from the host's own files.

The console (``soc-console/``) was written against the ACP dashboard's ``/api/soc/*`` + ``/api/approvals``.
On-prem and in the pilot there is no dashboard — only this host — so the same four reads and two writes
are answered here from what AEGIS already keeps:

    GET  /api/soc/chains                  summaries, newest first         ← audit.jsonl (one sealed EvidenceChain per line)
    GET  /api/soc/chains/{id}             the full chain                  ← same file; id = integrity_hash (or alert_id)
    GET  /api/approvals                   HITL cards + their decisions    ← <hitl dir>/cards.jsonl + decisions.jsonl
    GET  /api/soc/proposals               model-loop proposals            ← <hitl dir>/proposals.jsonl (optional)
    POST /api/approvals/{id}/approve      {"rationale"}                   → appends to decisions.jsonl — the file the
    POST /api/approvals/{id}/reject       {"reason", "corrected_verdict"}   service already executes from next cycle
    POST /api/soc/proposals/{id}/decide   {"decision": accept|reject, "rationale"} → proposal-decisions.jsonl

Reads are gated by the read token; writes need ``AEGIS_CONSOLE_TOKEN`` (set it and the console's
``AEGIS_API_KEY`` to the same value). ``decided_by`` comes from the ``X-AEGIS-User`` header the console's
server-side route sets from the signed-in session — the receiver never trusts a browser for identity.

Stdlib only. The audit file is re-read on each call but capped (``MAX_SCAN_BYTES`` from the tail), which is
fine for a console that polls every few seconds against a file that rotates at 512 MB.
"""

from __future__ import annotations

import json
import logging
import os
import re
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger("aegis.console_api")

MAX_SCAN_BYTES = 64 * 1024 * 1024          # read at most the last 64 MB of the audit file
DEFAULT_LIMIT = 200
_ID_RX = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")
_VERDICTS = ("benign", "suspicious", "malicious", "uncertain")


def _num(v: Any) -> float:
    try:
        f = float(v or 0.0)
    except (TypeError, ValueError):
        return 0.0
    return f if f == f else 0.0


def _iso(ts: Any) -> str:
    if isinstance(ts, (int, float)):
        return datetime.fromtimestamp(float(ts), tz=timezone.utc).isoformat()
    return str(ts or "")


def _tail_lines(path: Path, max_bytes: int = MAX_SCAN_BYTES) -> list[str]:
    """Complete lines from the tail of ``path`` (a partial first line after a seek is dropped)."""
    if not path.exists():
        return []
    size = path.stat().st_size
    with path.open("rb") as fh:
        if size > max_bytes:
            fh.seek(size - max_bytes)
            fh.readline()                      # discard the cut line
        raw = fh.read()
    lines = raw.decode("utf-8", "replace").split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    elif lines:
        lines.pop()                            # a row still being written
    return lines


def _chain_id(c: dict) -> str:
    return str(c.get("integrity_hash") or c.get("alert_id") or "")


def _source(c: dict) -> str:
    meta = c.get("metadata") or {}
    alert = meta.get("alert") or {}
    for cand in (alert.get("source"), meta.get("source"), (c.get("evidence") or [{}])[0].get("source") if c.get("evidence") else None):
        if cand:
            return str(cand)
    return str(c.get("investigated_by") or "aegis")


def _summary(c: dict) -> dict:
    meta = c.get("metadata") or {}
    actions = c.get("recommended_actions") or []
    verdict = str(c.get("verdict") or "uncertain")
    return {
        "chain_id": _chain_id(c),
        "alert_id": str(c.get("alert_id") or ""),
        "source": _source(c),
        "verdict": verdict if verdict in _VERDICTS else "uncertain",
        "confidence": _num(c.get("confidence")),
        "specialists": list(c.get("specialist_invocations") or [])[:20],
        "action_types": [str(a.get("action_type", "")) for a in actions if isinstance(a, dict)],
        "evidence_count": len(c.get("evidence") or []),
        "governance_blocked": bool(meta.get("governance_block")),
        "started_at": _iso(c.get("started_at")),
        "completed_at": _iso(c.get("completed_at")) or None,
        "note": str(meta.get("summary") or "")[:400] or None,
        "triage": "swarm" if meta.get("swarm") else "heuristic",
    }


def _investigation(meta: dict) -> Optional[dict]:
    """Blast radius + plan in the console's shape, from whatever the async tier stored."""
    inv = meta.get("investigation") if isinstance(meta.get("investigation"), dict) else {}
    graph = meta.get("blast_graph") or inv.get("blast_radius")
    plan = meta.get("mitigation_plan") or inv.get("plan")
    swarm = meta.get("swarm")
    campaign = meta.get("campaign_context")
    if not (graph or plan or swarm or campaign):
        return None
    out: dict[str, Any] = {"blast_radius": {"nodes": [], "edges": []}}
    if isinstance(graph, dict):
        out["blast_radius"] = {
            "nodes": [n for n in graph.get("nodes") or [] if isinstance(n, dict)],
            "edges": [e for e in graph.get("edges") or [] if isinstance(e, dict)],
            "critical": list(graph.get("critical") or []),
            "choke_edges": list(graph.get("choke_edges") or []),
        }
    if isinstance(plan, dict) and plan.get("steps"):
        out["plan"] = {"steps": [s for s in plan["steps"] if isinstance(s, dict)]}
    elif isinstance(plan, list):
        out["plan"] = {"steps": [s for s in plan if isinstance(s, dict)]}
    if isinstance(swarm, (list, dict)):
        out["swarm"] = list(swarm.keys()) if isinstance(swarm, dict) else [str(w) for w in swarm]
    if isinstance(campaign, dict):
        out["campaign"] = {"id": campaign.get("id") or campaign.get("campaign_id"),
                           "related_alerts": campaign.get("related_alerts") or campaign.get("count")}
    return out


def _full(c: dict) -> dict:
    meta = c.get("metadata") or {}
    out = _summary(c)
    out["recommended_actions"] = [
        {"action_type": str(a.get("action_type", "")), "target": str(a.get("target", "")),
         "requires_hitl": bool(a.get("requires_hitl", True)), "confidence": a.get("confidence"),
         "reasoning": str(a.get("reasoning") or "")[:2000]}
        for a in (c.get("recommended_actions") or []) if isinstance(a, dict)
    ]
    out["evidence"] = [
        {"source": str(e.get("source", "")), "signal": str(e.get("signal", ""))[:2000],
         "weight": e.get("weight") if e.get("weight") in ("low", "medium", "high") else "medium",
         "raw_data": e.get("raw_data") if isinstance(e.get("raw_data"), dict) else {}}
        for e in (c.get("evidence") or []) if isinstance(e, dict)
    ]
    out["reasoning"] = [r for r in (c.get("reasoning") or []) if isinstance(r, dict)][:50]
    inv = _investigation(meta)
    if inv:
        out["investigation"] = inv
    out["integrity_hash"] = str(c.get("integrity_hash") or "")
    return out


class ConsoleAPI:
    def __init__(self, audit_path: Optional[Path], hitl_dir: Optional[Path], index: Any = None):
        self.audit_path = Path(audit_path) if audit_path else None
        self.hitl_dir = Path(hitl_dir) if hitl_dir else None
        self.index = index                      # aegis.store.IndexStore when configured: SQL instead of a file scan

    # ---------- chains ----------
    # The audit file is parsed once and then only the appended delta: a console polling every few seconds
    # must not re-parse 64 MB per request. Keyed on (inode, size); a rotation or truncation reparses.
    _lock = threading.Lock()

    def _chains(self) -> list[dict]:
        if self.audit_path is None:
            return []
        with self._lock:
            try:
                st = self.audit_path.stat()
            except OSError:
                self._cache = None
                return []
            cache = getattr(self, "_cache", None)
            if cache and cache["ino"] == st.st_ino and cache["size"] == st.st_size:
                return cache["rows"]
            if cache and cache["ino"] == st.st_ino and st.st_size > cache["size"]:
                start, rows, by_id = cache["offset"], list(cache["rows"]), dict(cache["by_id"])
            else:
                start, rows, by_id = 0, [], {}
                if st.st_size > MAX_SCAN_BYTES:
                    start = st.st_size - MAX_SCAN_BYTES
            with self.audit_path.open("rb") as fh:
                fh.seek(start)
                if start and not rows:
                    fh.readline()                       # discard the cut line
                    start = fh.tell()
                raw = fh.read()
            cut = raw.rfind(b"\n")
            offset = start + (cut + 1 if cut >= 0 else 0)
            if cut >= 0:
                for line in raw[:cut].decode("utf-8", "replace").split("\n"):
                    if not line.strip():
                        continue
                    try:
                        c = json.loads(line)
                    except (json.JSONDecodeError, RecursionError):
                        continue
                    if isinstance(c, dict) and c.get("alert_id") is not None and "verdict" in c:
                        rows.insert(0, c)                # newest first
                        by_id[_chain_id(c)] = c
            self._cache = {"ino": st.st_ino, "size": st.st_size, "offset": offset, "rows": rows, "by_id": by_id}
            return rows

    def _by_id(self, chain_id: str) -> Optional[dict]:
        self._chains()
        cache = getattr(self, "_cache", None)
        return (cache or {}).get("by_id", {}).get(chain_id)

    def chains(self, limit: int = DEFAULT_LIMIT) -> dict:
        if self.index is not None and not self.index.stale:
            rows = self.index.recent(limit)
            if rows:
                return {"chains": rows, "count": len(rows), "from": "index"}
        rows = [_summary(c) for c in self._chains()[: max(1, min(int(limit), 1000))]]
        return {"chains": rows, "count": len(rows)}

    def chain(self, chain_id: str) -> Optional[dict]:
        if not _ID_RX.match(chain_id):
            return None
        if self.index is not None and not self.index.stale:
            c = self.index.get(chain_id)
            if c is not None:
                return _full(c)
        c = self._by_id(chain_id)
        if c is None:
            for row in self._chains():
                if str(row.get("alert_id")) == chain_id:
                    c = row
                    break
        return _full(c) if c is not None else None

    # ---------- approvals ----------
    def _decisions(self) -> dict[str, dict]:
        out: dict[str, dict] = {}
        if self.hitl_dir is None:
            return out
        for line in _tail_lines(self.hitl_dir / "decisions.jsonl"):
            try:
                d = json.loads(line)
            except (json.JSONDecodeError, RecursionError):
                continue
            if isinstance(d, dict) and d.get("approval_id"):
                out[str(d["approval_id"])] = d
        return out

    def approvals(self) -> dict:
        if self.hitl_dir is None:
            return {"approvals": []}
        decisions = self._decisions()
        settled: dict[str, dict] = {}
        cards: list[dict] = []
        for line in _tail_lines(self.hitl_dir / "cards.jsonl"):
            try:
                card = json.loads(line)
            except (json.JSONDecodeError, RecursionError):
                continue
            if not isinstance(card, dict):
                continue
            if card.get("kind") == "settled" and card.get("approval_id"):
                settled[str(card["approval_id"])] = card      # expired / timed out / decided by the service itself
            elif card.get("kind") == "approval":
                cards.append(card)
        rows: list[dict] = []
        for card in cards:
            args = card.get("args") or {}
            cid = str(card.get("id"))
            d = decisions.get(cid)
            st = settled.get(cid)
            if st and not d:
                d = {"status": st.get("status"), "decided_by": st.get("decided_by") or "aegis", "reason": st.get("reason"), "ts": st.get("ts")}
            status = str(d.get("status", "")).lower() if d else "pending"
            rows.append({
                "id": cid,
                "status": status if status in ("approved", "rejected", "expired") else "pending",
                "created_at": _iso(card.get("ts")),
                "action_type": str(args.get("action_type") or str(card.get("action", "")).split(" -> ")[0]),
                "target": str(args.get("target") or ""),
                "alert_id": str(card.get("alert_id") or args.get("alert_id") or ""),
                "integrity_hash": str(args.get("integrity_hash") or ""),
                "reasoning": str(args.get("reasoning") or "")[:2000],
                "agent_id": str(args.get("investigated_by") or "aegis"),
                "decided_by": str(d.get("decided_by") or "") if d else None,
                "decided_at": _iso(d.get("ts")) if d and d.get("ts") else None,
                "rationale": str(d.get("reason") or "")[:500] if d else None,
            })
        rows.reverse()
        return {"approvals": rows}

    _decide_lock = threading.Lock()

    def decide(self, approval_id: str, status: str, *, decided_by: str, reason: str = "",
               corrected_verdict: str = "") -> tuple[int, dict]:
        with self._decide_lock:
            return self._decide(approval_id, status, decided_by=decided_by, reason=reason, corrected_verdict=corrected_verdict)

    def _decide(self, approval_id: str, status: str, *, decided_by: str, reason: str,
                corrected_verdict: str) -> tuple[int, dict]:
        if self.hitl_dir is None:
            return 503, {"error": "no HITL directory on this host"}
        if not _ID_RX.match(approval_id):
            return 400, {"error": "bad approval id"}
        if status not in ("approved", "rejected"):
            return 400, {"error": "status must be approved or rejected"}
        state = {a["id"]: a["status"] for a in self.approvals()["approvals"]}
        if approval_id not in state:
            return 404, {"error": "unknown approval"}
        if state[approval_id] != "pending":
            return 409, {"error": f"already {state[approval_id]}"}
        row = {"approval_id": approval_id, "status": status, "decided_by": decided_by[:120] or "console",
               "reason": reason[:500], "ts": time.time(), "via": "console"}
        if corrected_verdict in _VERDICTS:
            row["corrected_verdict"] = corrected_verdict
        self.hitl_dir.mkdir(parents=True, exist_ok=True)
        with (self.hitl_dir / "decisions.jsonl").open("a", encoding="utf-8") as f:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")
        logger.info("[console] %s %s by %s", status, approval_id, row["decided_by"])
        if self.index is not None:
            card = next((a for a in self.approvals()["approvals"] if a["id"] == approval_id), {})
            self.index.record_decision(approval_id=approval_id, alert_id=str(card.get("alert_id") or ""),
                                       action_type=str(card.get("action_type") or ""), target=str(card.get("target") or ""),
                                       status=status, decided_by=row["decided_by"], rationale=reason[:500], via="console",
                                       decided_at=row["ts"])
        return 200, {"ok": True, "approval_id": approval_id, "status": status}

    # ---------- proposals (model loop) ----------
    def proposals(self) -> dict:
        if self.hitl_dir is None:
            return {"proposals": []}
        decided: dict[str, dict] = {}
        for line in _tail_lines(self.hitl_dir / "proposal-decisions.jsonl"):
            try:
                d = json.loads(line)
            except (json.JSONDecodeError, RecursionError):
                continue
            if isinstance(d, dict) and d.get("proposal_id"):
                decided[str(d["proposal_id"])] = d
        rows: list[dict] = []
        for line in _tail_lines(self.hitl_dir / "proposals.jsonl"):
            try:
                p = json.loads(line)
            except (json.JSONDecodeError, RecursionError):
                continue
            if not isinstance(p, dict) or not p.get("id"):
                continue
            d = decided.get(str(p["id"]))
            rows.append({
                "id": str(p["id"]),
                "change_type": str(p.get("change_type") or "rule"),
                "status": ("accepted" if d and d.get("decision") == "accept" else "rejected" if d else str(p.get("status") or "pending")),
                "summary": str(p.get("summary") or "")[:400],
                "validation_passed": p.get("validation_passed"),
                "rationale": str((d or {}).get("rationale") or p.get("rationale") or "")[:500] or None,
                "decided_by": (d or {}).get("decided_by"),
                "decided_at": _iso(d.get("ts")) if d and d.get("ts") else None,
                "created_at": _iso(p.get("ts") or p.get("created_at")),
            })
        rows.reverse()
        return {"proposals": rows}

    def decide_proposal(self, proposal_id: str, decision: str, *, decided_by: str, rationale: str = "") -> tuple[int, dict]:
        if self.hitl_dir is None:
            return 503, {"error": "no HITL directory on this host"}
        if not _ID_RX.match(proposal_id) or decision not in ("accept", "reject"):
            return 400, {"error": "bad proposal id or decision"}
        row = {"proposal_id": proposal_id, "decision": decision, "decided_by": decided_by[:120] or "console",
               "rationale": rationale[:500], "ts": time.time(), "via": "console"}
        self.hitl_dir.mkdir(parents=True, exist_ok=True)
        with (self.hitl_dir / "proposal-decisions.jsonl").open("a", encoding="utf-8") as f:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")
        return 200, {"ok": True, "proposal_id": proposal_id, "decision": decision}


def console_api_from_env(audit_path: Optional[Path], index: Any = None) -> ConsoleAPI:
    hitl = os.environ.get("AEGIS_HITL_DIR", "").strip()
    return ConsoleAPI(audit_path, Path(hitl) if hitl else None, index=index)


__all__ = ["ConsoleAPI", "console_api_from_env"]
