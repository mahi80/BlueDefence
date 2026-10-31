"""Load and format ``sft/triage.jsonl`` for QLoRA training.

A row is ``{"id","split","label_source","origin","messages":[system,user,assistant]}`` — the
shape both ``aegis.dataset export`` and ``aegis.dataset synth`` write. This module turns those
into ``{"prompt","response","split","id"}`` pairs and enforces one safety rule: **synthetic rows
are refused unless explicitly allowed**, so no one fine-tunes a "bank model" on scaffold data by
accident.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

SYNTHETIC_SOURCES = {"synthetic"}          # plus any "public:*" source — see is_non_analyst()


def is_non_analyst(src: str) -> bool:
    """Rows that are not analyst-labelled: synthetic, public corpora, and injections planted on either."""
    return src in SYNTHETIC_SOURCES or src.startswith("public:") or src.startswith("synthetic")


class DataError(RuntimeError):
    pass


@dataclass
class Example:
    id: str
    split: str
    label_source: str
    origin: str
    system: str
    user: str
    assistant: str

    @property
    def prompt(self) -> str:
        return f"{self.system}\n\n---\n\n{self.user}"

    @property
    def response(self) -> str:
        return self.assistant


def _iter_jsonl(path: Path) -> Iterable[dict]:
    with path.open("r", encoding="utf-8") as fh:
        for ln in fh:
            ln = ln.strip()
            if ln:
                yield json.loads(ln)


def load_sft(path: str | Path, *, allow_synthetic: bool = False,
             splits: tuple[str, ...] | None = None) -> list[Example]:
    """Load rows from one ``sft/triage.jsonl`` (or a dataset dir containing ``sft/triage.jsonl``).

    Refuses synthetic rows unless ``allow_synthetic``. ``splits`` keeps only those splits
    (default: train + val; never test — the eval set is the gate, never training input).
    """
    p = Path(path)
    if p.is_dir():
        p = p / "sft" / "triage.jsonl"
    if not p.exists():
        raise DataError(f"no sft/triage.jsonl at {p}")
    keep = splits or ("train", "val")
    out: list[Example] = []
    synthetic = 0
    for row in _iter_jsonl(p):
        src = row.get("label_source") or (row.get("label") or {}).get("source") or "unknown"
        if is_non_analyst(src):
            synthetic += 1
            if not allow_synthetic:
                continue
        if row.get("split") not in keep:
            continue
        msgs = row.get("messages") or []
        if len(msgs) != 3 or [m.get("role") for m in msgs] != ["system", "user", "assistant"]:
            raise DataError(f"row {row.get('id')} is not system/user/assistant")
        # assistant content must be the JSON triage object the model is trained to emit
        try:
            json.loads(msgs[2]["content"])
        except Exception as e:
            raise DataError(f"row {row.get('id')} assistant is not JSON: {e}") from e
        out.append(Example(id=row.get("id", ""), split=row["split"], label_source=src,
                           origin=row.get("origin", ""), system=msgs[0]["content"],
                           user=msgs[1]["content"], assistant=msgs[2]["content"]))
    if not out:
        if synthetic and not allow_synthetic:
            raise DataError(f"{p}: all {synthetic} row(s) are synthetic — pass allow_synthetic=True to train on them "
                            "(scaffold only; the real run uses human-labelled rows)")
        raise DataError(f"{p}: no usable rows for splits {keep}")
    return out


def split_rows(rows: list[Example]) -> tuple[list[Example], list[Example]]:
    """(train, val) by each row's recorded split; val falls back to a 10% tail if none is marked."""
    train = [r for r in rows if r.split == "train"]
    val = [r for r in rows if r.split == "val"]
    if not val and train:
        cut = max(1, len(train) // 10)
        val, train = train[:cut], train[cut:]
    return train, val
