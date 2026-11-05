# Recorded eval transcripts

The historical and injection gates must grade a **model**, not the mock.

`aegis.eval.run` used to build its client with `get_client()`. In CI there is no
`ANTHROPIC_API_KEY`, so `get_client()` returned `MockClient` — a keyword router
whose keyword lists were written against the same 37-case corpus. The gate
reported 37/37; a real model scores 32/37
(`../results/live-2026-10-21-sonnet-4-6-hardened.json`). A gate that only ever
sees the mock measures the mock.

## Record once (needs a real backend)

```bash
AEGIS_EVAL_RECORD=aegis/eval/transcripts/historical.jsonl \
    python -m aegis.eval.run
```

About $1 and a couple of minutes for the 46-case corpus. A run against the mock
is refused on purpose: a recorded mock is still the mock, and the transcript
header carries the backend name so a replay of one is marked not credible.

Commit the resulting file. Treat it like a golden file: if a prompt changes, the
gate reports transcript misses and fails — re-record deliberately, in the same
PR that changed the prompt, and let the reviewer see the diff in answers.

## Replay (CI offline, deterministic)

```bash
AEGIS_EVAL_TRANSCRIPT=aegis/eval/transcripts/historical.jsonl \
    python -m aegis.eval.run --gate
```

The key is `sha256(system, user, max_tokens)`: no timestamps, no process state,
so the same prompt replays anywhere. A miss is never substituted — it is counted,
printed, and `--gate` exits **2** (not credible) rather than 0 or 1.

## Exit codes

| code | meaning |
| --- | --- |
| 0 | gate passed: every case matched and the run was credible |
| 1 | the run was credible but a verdict disagreed or an injection leaked |
| 2 | the run is not credible: mock backend, or a transcript miss under `--gate` |

Inspect a transcript:

```bash
python -m aegis.eval.transcripts stats aegis/eval/transcripts/historical.jsonl
```
