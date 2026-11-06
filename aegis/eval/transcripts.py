"""Recorded model transcripts, so a CI gate can grade a real model without an API key.

The problem this solves
-----------------------
``aegis.eval.run`` builds its orchestrator with ``get_client()``. With no
``ANTHROPIC_API_KEY`` (which is how CI runs) that returns ``MockClient`` — a
keyword router. The mock's keyword lists were written against the same
corpus the gate scores, so the gate reports 37/37 while a real model scores
32/37 (see ``aegis/eval/results/live-2026-10-21-sonnet-4-6-hardened.json``).
A gate that only ever sees the mock measures the mock.

What this module does
---------------------
* ``RecordingClient`` wraps any ``LLMClient`` and appends every
  prompt/response pair to a JSONL transcript.
* ``TranscriptClient`` answers from that file. The key is a hash of the
  exact prompt, so a prompt edit is a *miss*, not a silently different
  answer.
* A miss is never silent: it is counted, printed, and ``--gate`` fails the
  run. There is no fallback to the mock.

Recording (once, with a real key; costs about $1 for the 46-case corpus)::

    AEGIS_EVAL_RECORD=aegis/eval/transcripts/historical.jsonl \
        python -m aegis.eval.run

Replaying (CI, offline, deterministic)::

    AEGIS_EVAL_TRANSCRIPT=aegis/eval/transcripts/historical.jsonl \
        python -m aegis.eval.run --gate

Inspect a transcript::

    python -m aegis.eval.transcripts stats aegis/eval/transcripts/historical.jsonl
"""
from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from pathlib import Path
from typing import Any, Optional

from aegis.agents.shared.llm_client import LLMClient, LLMResponse

SCHEMA = "aegis-eval-transcript/1"


def prompt_key(system: str, user: str, max_tokens: int) -> str:
    """Stable key for one call. No timestamps, no process state: the same
    prompt in CI and on the recorder's laptop must hash identically."""
    blob = json.dumps(
        {"v": 1, "system": system, "user": user, "max_tokens": int(max_tokens)},
        sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    )
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def is_mock(client: Any) -> bool:
    """True for ``MockClient`` and wrappers around it (``tokenizing(mock)``).

    A wrapper that wraps a real client does not match: ``degraded(anthropic)``
    and ``tokenizing(anthropic)`` are real backends.
    """
    name = str(getattr(client, "name", "") or "").lower()
    return "mock" in name


class TranscriptClient(LLMClient):
    """Replay recorded responses. A miss is recorded, never substituted."""

    name = "transcript"
    model = "transcript"

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self._by_key: dict[str, dict] = {}
        self.misses: list[dict] = []
        self.hits = 0
        header: dict | None = None
        with self.path.open(encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                rec = json.loads(line)
                if rec.get("type") == "header":
                    header = rec
                    continue
                key = rec.get("key")
                if not key:
                    continue
                # first record wins: a re-record appended to the same file
                # must not change a committed gate's answers silently
                self._by_key.setdefault(key, rec)
        self.header = header or {}
        self.model = str(self.header.get("model") or "transcript")
        self.backend = str(self.header.get("backend") or "unknown")
        self.corpus = str(self.header.get("corpus") or "")
        # A transcript recorded from the mock is just the mock with extra steps.
        # The header carries the backend name for exactly this reason.
        self.credible = "mock" not in f"{self.backend} {self.model}".lower()

    def complete(self, system: str, user: str, max_tokens: int = 2048) -> LLMResponse:
        key = prompt_key(system, user, max_tokens)
        rec = self._by_key.get(key)
        if rec is None:
            self.misses.append({
                "key": key,
                "system_chars": len(system),
                "user_chars": len(user),
                "max_tokens": int(max_tokens),
                "head": user[:160].replace("\n", " "),
            })
            # A conservative placeholder: it keeps the pipeline running so
            # one miss does not abort a 46-case run, but it is never benign
            # and ``--gate`` fails the run.
            return LLMResponse(
                text=json.dumps({
                    "verdict": "uncertain",
                    "confidence": 0.0,
                    "summary": "[transcript-miss] this prompt is not in the recorded transcript",
                    "next": "dispatch_perimeter",
                    "actions": [],
                }),
                model="transcript-miss",
                input_tokens=0,
                output_tokens=0,
            )
        self.hits += 1
        return LLMResponse(
            text=str(rec.get("text", "")),
            model=str(rec.get("model") or self.model),
            input_tokens=int(rec.get("input_tokens") or 0),
            output_tokens=int(rec.get("output_tokens") or 0),
        )

    def summary(self) -> dict:
        return {
            "replay": True,
            "backend": self.backend,
            "model": self.model,
            "hits": self.hits,
            "misses": len(self.misses),
            "path": str(self.path),
            "credible": self.credible,
        }


class RecordingClient(LLMClient):
    """Wrap a live client and append every call to a transcript."""

    name = "recording"

    def __init__(self, inner: LLMClient, path: str | Path, *, corpus: str = ""):
        self._inner = inner
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.model = inner.model
        self.name = f"recording({inner.name})"
        self.calls = 0
        self._lock = threading.Lock()
        if not self.path.exists():
            with self.path.open("w", encoding="utf-8") as fh:
                fh.write(json.dumps({
                    "type": "header",
                    "schema": SCHEMA,
                    "backend": inner.name,
                    "model": inner.model,
                    "corpus": corpus,
                    "recorded_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                }) + "\n")

    def complete(self, system: str, user: str, max_tokens: int = 2048) -> LLMResponse:
        resp = self._inner.complete(system, user, max_tokens=max_tokens)
        key = prompt_key(system, user, max_tokens)
        rec = {
            "type": "response",
            "key": key,
            "max_tokens": int(max_tokens),
            "text": resp.text,
            "model": resp.model,
            "input_tokens": int(resp.input_tokens or 0),
            "output_tokens": int(resp.output_tokens or 0),
        }
        with self._lock:
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
            self.calls += 1
        return resp


def open_eval_client(*, model: Optional[str] = None, budget: Any = None) -> tuple[LLMClient, dict]:
    """Build the client an eval should use, and describe how credible it is.

    Order: replay file > live client (optionally recording) > mock.
    ``meta["credible"]`` is False only for the mock. Callers that gate must
    refuse a non-credible run.
    """
    transcript = os.environ.get("AEGIS_EVAL_TRANSCRIPT", "").strip()
    record = os.environ.get("AEGIS_EVAL_RECORD", "").strip()

    if transcript:
        client = TranscriptClient(transcript)
        meta = client.summary()          # credible comes from the recorded backend, not from "it is a file"
        return client, meta

    from aegis.agents.shared.llm_client import get_client  # local: avoids a cycle at import

    client = get_client(budget=budget, model=model)
    if record:
        if is_mock(client):
            raise RuntimeError(
                "refusing to record a transcript from the mock client — a recorded mock is still the mock. "
                "Set ANTHROPIC_API_KEY (or LLM_BACKEND=vllm) and record against a real backend."
            )
        client = RecordingClient(client, record)
    meta = {
        "replay": False,
        "backend": getattr(client, "name", "unknown"),
        "model": getattr(client, "model", "unknown"),
        "credible": not is_mock(client),
        "recording": bool(record),
    }
    return client, meta


def describe(meta: dict) -> str:
    if meta.get("replay"):
        return f"replay {meta.get('backend')} ({meta.get('model')}) from {meta.get('path')}"
    return f"live {meta.get('backend')} ({meta.get('model')})"


def _stats(path: str) -> int:
    p = Path(path)
    header = None
    n = 0
    keys: set[str] = set()
    dupes = 0
    with p.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            if rec.get("type") == "header":
                header = rec
                continue
            n += 1
            k = rec.get("key")
            if k in keys:
                dupes += 1
            keys.add(k)
    print(json.dumps({
        "path": str(p),
        "header": header,
        "responses": n,
        "unique_keys": len(keys),
        "duplicate_keys": dupes,
        "size_bytes": p.stat().st_size,
    }, indent=2))
    return 0 if n and dupes == 0 else 1


def main(argv: list[str] | None = None) -> int:
    import argparse

    ap = argparse.ArgumentParser(prog="python -m aegis.eval.transcripts")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("stats", help="validate and summarise a transcript file")
    s.add_argument("path")
    a = ap.parse_args(argv)
    if a.cmd == "stats":
        return _stats(a.path)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
