"""ORM models for the derived index. Portable on purpose: integer keys with explicit sequences, VARCHAR/TEXT,
DATETIME (naive UTC) and FLOAT only — no JSON columns, arrays or dialect types — so the same models run on
DuckDB (embedded default), SQLite, PostgreSQL and Microsoft SQL Server unchanged.

The hash-chained ``audit.jsonl`` stays the evidence record; these tables are a *derived* view of it that can be
dropped and rebuilt (``python -m aegis.store reindex``). ``chains.integrity_hash`` is UNIQUE so re-indexing and
retries are idempotent. Nothing here is ever updated or deleted by AEGIS; retention is by dropping whole
audit segments and their rows together.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, Float, Index, Integer, Sequence, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

SCHEMA_VERSION = 1


class Base(DeclarativeBase):
    pass


class ChainRow(Base):
    __tablename__ = "aegis_chains"

    seq: Mapped[int] = mapped_column(Integer, Sequence("aegis_chains_seq"), primary_key=True)
    integrity_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    prev_hash: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    alert_id: Mapped[str] = mapped_column(String(256), nullable=False, index=True)
    verdict: Mapped[str] = mapped_column(String(16), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    investigated_by: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    source: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    governance_blocked: Mapped[int] = mapped_column(Integer, nullable=False, default=0)   # bool as 0/1: MSSQL has no BOOLEAN literal
    evidence_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    action_types: Mapped[str] = mapped_column(String(512), nullable=False, default="")   # comma-separated
    segment: Mapped[str] = mapped_column(String(64), nullable=False, default="")        # audit segment identity (inode or name)
    offset: Mapped[int] = mapped_column(Integer, nullable=False, default=0)             # byte offset of the row in that segment
    body: Mapped[str] = mapped_column(Text, nullable=False)                             # the full sealed chain, JSON text

    __table_args__ = (
        Index("ix_aegis_chains_completed", "completed_at"),
        Index("ix_aegis_chains_verdict_completed", "verdict", "completed_at"),
    )


class DecisionRow(Base):
    __tablename__ = "aegis_decisions"

    approval_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    alert_id: Mapped[str] = mapped_column(String(256), nullable=False, index=True)
    action_type: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    target: Mapped[str] = mapped_column(String(256), nullable=False, default="")
    status: Mapped[str] = mapped_column(String(16), nullable=False)                     # approved | rejected | expired
    decided_by: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    decided_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    rationale: Mapped[str] = mapped_column(String(1024), nullable=False, default="")
    via: Mapped[str] = mapped_column(String(32), nullable=False, default="")             # console | file | servicenow | timeout


class CursorRow(Base):
    """One row per consumer (``contrib``, ``console``, …): which segment and offset it has processed."""
    __tablename__ = "aegis_cursors"

    consumer: Mapped[str] = mapped_column(String(64), primary_key=True)
    segment: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    offset: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    updated_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class MetaRow(Base):
    __tablename__ = "aegis_meta"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[str] = mapped_column(String(512), nullable=False, default="")


__all__ = ["Base", "ChainRow", "DecisionRow", "CursorRow", "MetaRow", "SCHEMA_VERSION"]
