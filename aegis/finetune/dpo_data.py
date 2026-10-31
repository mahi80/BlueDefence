"""Load ``dpo/preferences.jsonl`` for preference tuning (DPO) of the triage judge.

A row is ``{"id","split","label_source","origin","prompt":[system,user],"chosen","rejected"}``
— the shape ``aegis.dataset export --dpo`` writes from analyst decisions that overruled the
model at the HITL card. ``chosen`` is the human-aligned triage JSON; ``rejected`` is the
verdict/action the analyst overruled. This module turns those into
``{"prompt","chosen","rejected","split","id"}`` tuples and enforces the same safety rule as
``load_sft``: **non-analyst rows are refused unless explicitly allowed**, so no one preference-
tunes a bank model on scaffold data by accident. (In practice every DPO pair is analyst-sourced
by construction; the guard stays for symmetry and defence in depth.)
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from .data import DataError, is_non_analyst

_VERDICTS = ("benign", "suspicious", "malicious", "uncertain")


@dataclass
class Preference:
    id: str
    split: str
    label_source: str
    origin: str
    system: str
    user: str
    chosen: str
    rejected: str

    @property
    def prompt(self) -> str:
        return f"{self.system}\n\n---\n\n{self.user}"


def _iter_jsonl(path: Path) -> Iterable[dict]:
    with path.open("r", encoding="utf-8") as fh:
        for ln in fh:
            ln = ln.strip()
            if ln:
                yield json.loads(ln)


def load_dpo(path: str | Path, *, allow_synthetic: bool = False,
             splits: tuple[str, ...] | None = None) -> list[Preference]:
    """Load rows from one ``dpo/preferences.jsonl`` (or a dataset dir containing it).

    Refuses non-analyst rows unless ``allow_synthetic``. ``splits`` keeps only those splits
    (default: train + val; never test — the eval set is the gate, never training input).
    """
    p = Path(path)
    if p.is_dir():
        p = p / "dpo" / "preferences.jsonl"
    if not p.exists():
        raise DataError(f"no dpo/preferences.jsonl at {p}")
    keep = splits or ("train", "val")
    out: list[Preference] = []
    non_analyst = 0
    for row in _iter_jsonl(p):
        src = row.get("label_source") or "unknown"
        if is_non_analyst(src):
            non_analyst += 1
            if not allow_synthetic:
                continue
        if row.get("split") not in keep:
            continue
        prompt = row.get("prompt") or []
        if len(prompt) != 2 or [m.get("role") for m in prompt] != ["system", "user"]:
            raise DataError(f"row {row.get('id')} prompt is not [system, user]")
        chosen, rejected = row.get("chosen"), row.get("rejected")
        if not isinstance(chosen, str) or not isinstance(rejected, str):
            raise DataError(f"row {row.get('id')} chosen/rejected must be JSON strings")
        if chosen == rejected:
            raise DataError(f"row {row.get('id')} has identical chosen and rejected (no preference)")
        try:
            cj = json.loads(chosen)
            json.loads(rejected)
        except Exception as e:  # noqa: BLE001
            raise DataError(f"row {row.get('id')} chosen/rejected is not JSON: {e}") from e
        if cj.get("verdict") not in _VERDICTS:
            raise DataError(f"row {row.get('id')} chosen verdict {cj.get('verdict')!r} not in {_VERDICTS}")
        out.append(Preference(id=row.get("id", ""), split=row["split"], label_source=src,
                              origin=row.get("origin", ""), system=prompt[0]["content"],
                              user=prompt[1]["content"], chosen=chosen, rejected=rejected))
    if not out:
        if non_analyst and not allow_synthetic:
            raise DataError(f"{p}: all {non_analyst} row(s) are non-analyst — pass allow_synthetic=True to use them")
        raise DataError(f"{p}: no usable preference pairs for splits {keep}")
    return out


def split_prefs(rows: list[Preference]) -> tuple[list[Preference], list[Preference]]:
    """(train, val) by each row's recorded split; val falls back to a 10% tail if none is marked."""
    train = [r for r in rows if r.split == "train"]
    val = [r for r in rows if r.split == "val"]
    if not val and train:
        cut = max(1, len(train) // 10)
        val, train = train[:cut], train[cut:]
    return train, val
