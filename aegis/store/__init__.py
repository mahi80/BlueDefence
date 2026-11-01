"""Derived index of the evidence record — the queryable side of the audit chain.

``audit.jsonl`` (hash-chained, append-only, fsynced) is and stays the record a regulator verifies. The console,
the shadow report and ad-hoc questions ("every malicious chain for host X in the last 30 days") need a
database, so every chain is *also* inserted here after its JSONL append is durable. The index is derived:
``integrity_hash`` is UNIQUE (replay-safe), a failure to index never raises into the service (it marks the
store ``stale`` and logs once), and ``reindex()`` rebuilds everything from the JSONL segments — backups are the
JSONL set, the database is disposable.

One ORM (SQLAlchemy 2), four databases, chosen by URL — nothing else changes:

    AEGIS_INDEX_URL=duckdb:////var/lib/aegis/index.duckdb      (default: embedded, zero setup)
    AEGIS_INDEX_URL=sqlite:////var/lib/aegis/index.sqlite
    AEGIS_INDEX_URL=postgresql+psycopg2://aegis:…@db.bank.internal/aegis
    AEGIS_INDEX_URL=mssql+pyodbc://aegis:…@sql.bank.internal/aegis?driver=ODBC+Driver+18+for+SQL+Server
    AEGIS_INDEX=0                                              (off: the console falls back to scanning the file)

Append-only in the database too: this module exposes no update or delete. On PostgreSQL / MSSQL give the
service a role with INSERT + SELECT only; retention is by dropping whole audit segments with their rows.
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator, Optional

logger = logging.getLogger("aegis.store")

try:
    import sqlalchemy as sa
    from sqlalchemy.exc import IntegrityError, SQLAlchemyError
    from sqlalchemy.orm import Session
    from .models import SCHEMA_VERSION, Base, ChainRow, CursorRow, DecisionRow, MetaRow
    HAVE_SQLALCHEMY = True
except ImportError:  # pragma: no cover — stdlib-only hosts run without an index
    HAVE_SQLALCHEMY = False


def _dt(v: Any) -> Optional[datetime]:
    """ISO string / epoch → naive UTC datetime (the portable DATETIME every dialect has)."""
    if v is None or v == "":
        return None
    try:
        if isinstance(v, (int, float)):
            return datetime.fromtimestamp(float(v), tz=timezone.utc).replace(tzinfo=None)
        d = datetime.fromisoformat(str(v).replace("Z", "+00:00"))
        return (d.astimezone(timezone.utc) if d.tzinfo else d).replace(tzinfo=None)
    except (ValueError, OverflowError, OSError):
        return None


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _iso(d: Optional[datetime]) -> Optional[str]:
    return d.replace(tzinfo=timezone.utc).isoformat() if d else None


def _source(c: dict) -> str:
    meta = c.get("metadata") or {}
    alert = meta.get("alert") or {}
    for cand in (alert.get("source"), meta.get("source")):
        if cand:
            return str(cand)[:128]
    ev = c.get("evidence") or []
    if ev and isinstance(ev[0], dict) and ev[0].get("source"):
        return str(ev[0]["source"])[:128]
    return str(c.get("investigated_by") or "aegis")[:128]


def default_url(audit_path: Optional[Path]) -> str:
    base = Path(audit_path).parent if audit_path else Path(".")
    return f"duckdb:///{(base / 'index.duckdb').as_posix()}"


class IndexStore:
    """Thread-safe, never-raising facade over the ORM. One instance per process."""

    def __init__(self, url: str):
        if not HAVE_SQLALCHEMY:
            raise RuntimeError("the index needs SQLAlchemy: pip install 'bluedefence[index]'")
        self.url = url
        self.dialect = url.split(":", 1)[0].split("+", 1)[0]
        kw: dict[str, Any] = {"future": True}
        if self.dialect == "sqlite":
            kw["connect_args"] = {"check_same_thread": False, "timeout": 30}
        self.engine = sa.create_engine(url, **kw)
        self._lock = threading.Lock()
        self.stale = False                    # an insert failed: rows may be missing until `reindex`
        self._stale_logged = 0.0
        self.failures = 0
        Base.metadata.create_all(self.engine)
        with Session(self.engine) as s:
            if s.get(MetaRow, "schema_version") is None:
                s.add(MetaRow(key="schema_version", value=str(SCHEMA_VERSION)))
                s.commit()
        if self.dialect == "sqlite":
            with self.engine.begin() as c:
                c.exec_driver_sql("PRAGMA journal_mode=WAL")      # readers (console) never block the writer
                c.exec_driver_sql("PRAGMA synchronous=NORMAL")    # the JSONL is already fsynced; the index is derived

    # ------------------------------------------------------------------ write --
    def index_chain(self, chain: dict, *, prev_hash: str = "", segment: str = "", offset: int = 0) -> bool:
        """Insert one sealed chain. Idempotent on ``integrity_hash``; returns False (and marks stale) on error."""
        return self._index(chain, prev_hash=prev_hash, segment=segment, offset=offset) != "error"

    def _index(self, chain: dict, *, prev_hash: str, segment: str, offset: int) -> str:
        """``inserted`` | ``duplicate`` | ``error``."""
        h = str(chain.get("integrity_hash") or "")
        if not h:
            return "error"
        actions = ",".join(str(a.get("action_type", "")) for a in (chain.get("recommended_actions") or []) if isinstance(a, dict))
        row = ChainRow(
            integrity_hash=h, prev_hash=str(prev_hash or "")[:64],
            alert_id=str(chain.get("alert_id") or "")[:256],
            verdict=str(chain.get("verdict") or "uncertain")[:16],
            confidence=self._num(chain.get("confidence")),
            investigated_by=str(chain.get("investigated_by") or "")[:64],
            source=_source(chain),
            started_at=_dt(chain.get("started_at")), completed_at=_dt(chain.get("completed_at")),
            governance_blocked=1 if (chain.get("metadata") or {}).get("governance_block") else 0,
            evidence_count=len(chain.get("evidence") or []),
            action_types=actions[:512], segment=str(segment)[:64], offset=int(offset or 0),
            body=json.dumps(chain, separators=(",", ":"), default=str),
        )
        try:
            with self._lock, Session(self.engine) as s:
                s.add(row)
                try:
                    s.commit()
                    out = "inserted"
                except IntegrityError:
                    s.rollback()                                  # already indexed (replay / reindex): fine
                    out = "duplicate"
            if self.stale:
                self.stale = False
                logger.info("[store] index writable again")
            return out
        except SQLAlchemyError as e:
            self._fail("index_chain", e)
            return "error"

    def record_decision(self, *, approval_id: str, alert_id: str, action_type: str, target: str, status: str,
                        decided_by: str, rationale: str = "", via: str = "", decided_at: Any = None) -> bool:
        try:
            with self._lock, Session(self.engine) as s:
                if s.get(DecisionRow, approval_id[:128]) is not None:
                    return True                                  # append-only: the first decision stands
                s.add(DecisionRow(approval_id=approval_id[:128], alert_id=alert_id[:256], action_type=action_type[:64],
                                  target=target[:256], status=status[:16], decided_by=decided_by[:128],
                                  decided_at=_dt(decided_at) or _now(), rationale=rationale[:1024], via=via[:32]))
                s.commit()
            return True
        except SQLAlchemyError as e:
            self._fail("record_decision", e)
            return False

    def set_cursor(self, consumer: str, segment: str, offset: int) -> bool:
        """Cursors are the one thing that legitimately moves forward; still a single row per consumer."""
        try:
            with self._lock, Session(self.engine) as s:
                row = s.get(CursorRow, consumer[:64])
                if row is None:
                    s.add(CursorRow(consumer=consumer[:64], segment=segment[:64], offset=int(offset), updated_at=_now()))
                else:
                    row.segment, row.offset, row.updated_at = segment[:64], int(offset), _now()
                s.commit()
            return True
        except SQLAlchemyError as e:
            self._fail("set_cursor", e)
            return False

    # ------------------------------------------------------------------- read --
    def get_cursor(self, consumer: str) -> Optional[dict]:
        try:
            with Session(self.engine) as s:
                row = s.get(CursorRow, consumer[:64])
                return {"segment": row.segment, "offset": row.offset} if row else None
        except SQLAlchemyError as e:
            self._fail("get_cursor", e)
            return None

    def recent(self, limit: int = 200, *, verdict: Optional[str] = None, since: Any = None, alert_id: Optional[str] = None) -> list[dict]:
        """Newest first, as the console's summary rows (the same shape ``console_api._summary`` produces)."""
        q = sa.select(ChainRow).order_by(ChainRow.seq.desc()).limit(max(1, min(int(limit), 5000)))
        if verdict:
            q = q.where(ChainRow.verdict == verdict)
        if alert_id:
            q = q.where(ChainRow.alert_id == alert_id)
        if since is not None and _dt(since):
            q = q.where(ChainRow.completed_at >= _dt(since))
        try:
            with Session(self.engine) as s:
                return [self._summary(r) for r in s.scalars(q)]
        except SQLAlchemyError as e:
            self._fail("recent", e)
            return []

    def get(self, chain_id: str) -> Optional[dict]:
        """The full chain by ``integrity_hash`` (or the newest for an ``alert_id``)."""
        try:
            with Session(self.engine) as s:
                r = s.scalars(sa.select(ChainRow).where(ChainRow.integrity_hash == chain_id)).first()
                if r is None:
                    r = s.scalars(sa.select(ChainRow).where(ChainRow.alert_id == chain_id).order_by(ChainRow.seq.desc())).first()
                if r is None:
                    return None
                return json.loads(r.body)
        except (SQLAlchemyError, ValueError) as e:
            self._fail("get", e)
            return None

    def decisions(self, limit: int = 500) -> list[dict]:
        try:
            with Session(self.engine) as s:
                rows = s.scalars(sa.select(DecisionRow).order_by(DecisionRow.decided_at.desc()).limit(limit))
                return [{"approval_id": d.approval_id, "alert_id": d.alert_id, "action_type": d.action_type, "target": d.target,
                         "status": d.status, "decided_by": d.decided_by, "decided_at": _iso(d.decided_at),
                         "rationale": d.rationale, "via": d.via} for d in rows]
        except SQLAlchemyError as e:
            self._fail("decisions", e)
            return []

    def verdict_counts(self, since: Any = None) -> dict[str, int]:
        """The shadow report's headline: how many chains per verdict (optionally since a time)."""
        q = sa.select(ChainRow.verdict, sa.func.count()).group_by(ChainRow.verdict)
        if since is not None and _dt(since):
            q = q.where(ChainRow.completed_at >= _dt(since))
        try:
            with Session(self.engine) as s:
                return {v: int(n) for v, n in s.execute(q)}
        except SQLAlchemyError as e:
            self._fail("verdict_counts", e)
            return {}

    def stats(self) -> dict:
        try:
            with Session(self.engine) as s:
                chains = s.scalar(sa.select(sa.func.count()).select_from(ChainRow)) or 0
                decisions = s.scalar(sa.select(sa.func.count()).select_from(DecisionRow)) or 0
                newest = s.scalar(sa.select(sa.func.max(ChainRow.completed_at)))
            return {"dialect": self.dialect, "chains": int(chains), "decisions": int(decisions), "newest": _iso(newest),
                    "stale": self.stale, "failures": self.failures}
        except SQLAlchemyError as e:
            self._fail("stats", e)
            return {"dialect": self.dialect, "stale": True, "failures": self.failures, "error": str(e)[:120]}

    # ---------------------------------------------------------------- rebuild --
    def reindex(self, audit_path: Path, *, hitl_dir: Optional[Path] = None) -> dict:
        """Rebuild from the JSONL segments (oldest first, then the live file). Existing rows are kept
        (UNIQUE hash), so this is safe to run on a live index and after a restore from backup."""
        audit = Path(audit_path)
        segments = sorted((p for p in audit.parent.glob(audit.name + ".*") if p.name[len(audit.name) + 1:].isdigit()),
                          key=lambda p: p.name) + [audit]
        added, seen, prev = 0, 0, "0" * 64
        for seg in segments:
            if not seg.exists():
                continue
            try:
                ino = str(seg.stat().st_ino)
            except OSError:
                ino = seg.name
            with seg.open("rb") as fh:
                while True:
                    pos = fh.tell()
                    line = fh.readline()
                    if not line or not line.endswith(b"\n"):
                        break
                    if not line.strip():
                        continue
                    try:
                        chain = json.loads(line)
                    except ValueError:
                        continue
                    if not isinstance(chain, dict) or not chain.get("integrity_hash"):
                        continue
                    seen += 1
                    if self._index(chain, prev_hash=prev, segment=ino, offset=pos) == "inserted":
                        added += 1
                    prev = str(chain.get("integrity_hash") or prev)
        dec = 0
        if hitl_dir:
            for line in self._lines(Path(hitl_dir) / "decisions.jsonl"):
                try:
                    d = json.loads(line)
                except ValueError:
                    continue
                if isinstance(d, dict) and d.get("approval_id"):
                    if self.record_decision(approval_id=str(d["approval_id"]), alert_id=str(d.get("alert_id") or ""),
                                            action_type=str(d.get("action_type") or ""), target=str(d.get("target") or ""),
                                            status=str(d.get("status") or ""), decided_by=str(d.get("decided_by") or ""),
                                            rationale=str(d.get("reason") or d.get("rationale") or ""), via=str(d.get("via") or "file"),
                                            decided_at=d.get("ts")):
                        dec += 1
        self.stale = False
        return {"segments": len(segments), "chains_seen": seen, "chains_added": added, "decisions": dec}

    # ---------------------------------------------------------------- helpers --
    @staticmethod
    def _lines(path: Path) -> Iterator[str]:
        if not path.exists():
            return
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if line.strip():
                    yield line

    @staticmethod
    def _num(v: Any) -> float:
        try:
            f = float(v or 0.0)
            return f if f == f else 0.0
        except (TypeError, ValueError):
            return 0.0

    @staticmethod
    def _summary(r: "ChainRow") -> dict:
        try:
            body = json.loads(r.body)
        except ValueError:
            body = {}
        meta = body.get("metadata") or {}
        return {
            "chain_id": r.integrity_hash, "alert_id": r.alert_id, "source": r.source, "verdict": r.verdict,
            "confidence": r.confidence, "specialists": list(body.get("specialist_invocations") or [])[:20],
            "action_types": [a for a in r.action_types.split(",") if a],
            "evidence_count": r.evidence_count, "governance_blocked": bool(r.governance_blocked),
            "started_at": _iso(r.started_at) or "", "completed_at": _iso(r.completed_at),
            "note": str(meta.get("summary") or "")[:400] or None,
            "triage": "swarm" if meta.get("swarm") else "heuristic", "seq": r.seq,
        }

    def _fail(self, op: str, e: Exception) -> None:
        self.failures += 1
        self.stale = True
        now = time.time()
        if now - self._stale_logged > 300:                      # one line per 5 min, not one per chain
            self._stale_logged = now
            logger.error("[store] %s failed on %s (%d failure(s) so far): %s — the index is stale until `python -m aegis.store reindex`",
                         op, self.dialect, self.failures, str(e)[:200])


def store_from_env(audit_path: Optional[Path], env: Optional[dict] = None) -> Optional[IndexStore]:
    """``None`` when disabled (``AEGIS_INDEX=0``) or when SQLAlchemy / the dialect driver is missing (logged once)."""
    env = env if env is not None else os.environ
    if str(env.get("AEGIS_INDEX", "1")).strip().lower() in ("0", "false", "no", "off"):
        return None
    url = str(env.get("AEGIS_INDEX_URL", "")).strip() or default_url(audit_path)
    if not HAVE_SQLALCHEMY:
        logger.warning("[store] index disabled: SQLAlchemy not installed (pip install 'bluedefence[index]')")
        return None
    try:
        store = IndexStore(url)
    except Exception as e:  # noqa: BLE001 — a missing driver or an unreachable database must not stop the SOC
        logger.error("[store] index disabled: cannot open %s: %s", url.split("@")[-1] if "@" in url else url, str(e)[:200])
        return None
    logger.info("[store] index on %s (%s)", store.dialect, url.split("@")[-1] if "@" in url else url)
    return store


__all__ = ["IndexStore", "store_from_env", "default_url", "HAVE_SQLALCHEMY"]
