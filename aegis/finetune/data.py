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


def _eval_guard() -> set[str]:
    from aegis.dataset.importers.mix import _eval_fps
    return _eval_fps()


def _alert_fp(user_content: str) -> str | None:
    from aegis.dataset.schema import fingerprint
    try:
        alert = json.loads(user_content)
    except (TypeError, ValueError):
        return None
    return fingerprint(alert if isinstance(alert, dict) else {"value": alert})


def load_sft(path: str | Path, *, allow_synthetic: bool = False,
             splits: tuple[str, ...] | None = None, eval_guard: bool = True) -> list[Example]:
    """Load rows from one ``sft/triage.jsonl`` (or a dataset dir containing ``sft/triage.jsonl``).

    Refuses synthetic rows unless ``allow_synthetic``. ``splits`` keeps only those splits
    (default: train + val; never test — the eval set is the gate, never training input).

    The held-out eval alerts are refused here too, by a fingerprint recomputed from each row's alert: the export
    guard is best-effort and a hand-built or merged file never went through it, and a row's own split is whatever
    its producer wrote (review round 7 T-8). An empty guard set (eval cases missing / unreadable) refuses the load
    rather than training blind; ``eval_guard=False`` is for tests and tooling that never train.
    """
    p = Path(path)
    if p.is_dir():
        p = p / "sft" / "triage.jsonl"
    if not p.exists():
        raise DataError(f"no sft/triage.jsonl at {p}")
    keep = splits or ("train", "val")
    guard: set[str] = set()
    if eval_guard and "test" not in keep:
        guard = _eval_guard()
        if not guard:
            raise DataError("eval fingerprint guard is empty (aegis/eval cases missing or unreadable) — refusing to "
                            "load training rows that could contain the held-out eval alerts")
    out: list[Example] = []
    synthetic = 0
    leaked = 0
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
        if guard and _alert_fp(msgs[1]["content"]) in guard:
            leaked += 1                  # a held-out eval alert in training input: dropped, never memorised
            continue
        out.append(Example(id=row.get("id", ""), split=row["split"], label_source=src,
                           origin=row.get("origin", ""), system=msgs[0]["content"],
                           user=msgs[1]["content"], assistant=msgs[2]["content"]))
    if leaked:
        import logging
        logging.getLogger("aegis.finetune.data").warning(
            "%s: dropped %d row(s) whose alert is a held-out eval case", p, leaked)
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
