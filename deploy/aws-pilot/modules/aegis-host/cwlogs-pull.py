#!/opt/aegis/venv/bin/python
"""Pull new AWS WAF log events from a CloudWatch Logs group into the local AEGIS push receiver.

Runs from a systemd timer every 30 s. Stdlib + boto3 (instance role; no keys on disk). FilterLogEvents filters on
the event's own timestamp, not on when CloudWatch received it, so a record that lands late would be missed by a
plain "newer than last time" cursor. Each run therefore re-scans an overlap window behind the checkpoint and
skips events whose eventId it already pushed (the ids from the overlap window are kept in the checkpoint file).
A push failure mid-run saves the progress made so far, so earlier batches are not re-sent. Each CloudWatch event is one WAF log record (JSON),
which /ingest/waf already understands (``httpRequest`` / ``terminatingRuleId`` → the AWS WAF parser).

    AEGIS_CWLOGS_GROUP      log group name (us-east-1 for a CloudFront web ACL)
    AEGIS_CWLOGS_REGION     default us-east-1
    AEGIS_INGEST_URL        default http://127.0.0.1:8787
    AEGIS_INGEST_TOKEN      push token
    AEGIS_CWLOGS_CHECKPOINT default /var/lib/aegis/cwlogs-checkpoint.json
"""

from __future__ import annotations

import gzip
import json
import os
import sys
import time
import urllib.request

import boto3

GROUP = os.environ["AEGIS_CWLOGS_GROUP"]
REGION = os.environ.get("AEGIS_CWLOGS_REGION", "us-east-1")
URL = os.environ.get("AEGIS_INGEST_URL", "http://127.0.0.1:8787").rstrip("/") + "/ingest/waf?source=aws-waf"
TOKEN = os.environ["AEGIS_INGEST_TOKEN"]
CKPT = os.environ.get("AEGIS_CWLOGS_CHECKPOINT", "/var/lib/aegis/cwlogs-checkpoint.json")
LOOKBACK_MS = 15 * 60 * 1000          # first run: last 15 minutes only
LAG_MS = 10 * 1000                    # never read the newest 10 s (ingestion in flight)
OVERLAP_MS = 10 * 60 * 1000           # re-scan this far behind the checkpoint for late-arriving events
BATCH = 500


def _load() -> tuple[int, dict[str, int]]:
    try:
        with open(CKPT) as f:
            d = json.load(f)
        seen = d.get("seen") or {}
        return int(d.get("start_ms", 0)), {str(k): int(v) for k, v in seen.items()} if isinstance(seen, dict) else {}
    except (OSError, ValueError, TypeError, AttributeError):
        return 0, {}


def _save(start_ms: int, seen: dict[str, int]) -> None:
    """Checkpoint = how far the window has been scanned + the ids pushed inside the overlap (older ones can no
    longer be re-fetched, so they are dropped)."""
    floor = start_ms - OVERLAP_MS
    keep = {k: v for k, v in seen.items() if v >= floor}
    tmp = CKPT + ".tmp"
    with open(tmp, "w") as f:
        json.dump({"start_ms": start_ms, "seen": keep, "saved_at": int(time.time())}, f)
        f.flush(); os.fsync(f.fileno())
    os.replace(tmp, CKPT)


def _push(lines: list[str]) -> None:
    body = gzip.compress(("\n".join(lines) + "\n").encode())
    req = urllib.request.Request(URL, data=body, method="POST",
                                 headers={"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/x-ndjson",
                                          "Content-Encoding": "gzip"})
    with urllib.request.urlopen(req, timeout=30):   # urlopen raises HTTPError for 4xx/5xx
        pass


def main() -> int:
    now = int(time.time() * 1000)
    ckpt, seen = _load()
    end = now - LAG_MS
    start = max(0, (ckpt or now - LOOKBACK_MS) - (OVERLAP_MS if ckpt else 0))
    if end <= start:
        return 0
    logs = boto3.client("logs", region_name=REGION)
    kw = {"logGroupName": GROUP, "startTime": start, "endTime": end, "limit": 10000}
    total, newest = 0, ckpt
    buf: list[str] = []
    buf_ids: list[tuple[str, int]] = []
    pushed: dict[str, int] = {}        # eventId → ts delivered this run; kept so a later failure still records them

    def flush() -> None:
        nonlocal total, buf, buf_ids
        if not buf:
            return
        _push(buf)
        total += len(buf)
        for eid, ts in buf_ids:
            if eid:
                pushed[eid] = ts
        buf, buf_ids = [], []

    try:
        while True:
            try:
                page = logs.filter_log_events(**kw)
            except logs.exceptions.ResourceNotFoundException:
                print(f"log group {GROUP} not found yet", file=sys.stderr)
                return 0
            for ev in page.get("events", []):
                eid = str(ev.get("eventId") or "")
                if eid and (eid in seen or eid in pushed):
                    continue
                msg = str(ev.get("message", "")).strip()
                if not msg:
                    continue
                buf.append(msg); buf_ids.append((eid, int(ev.get("timestamp", 0))))
                newest = max(newest, int(ev.get("timestamp", 0)))
                if len(buf) >= BATCH:
                    flush()
            token = page.get("nextToken")
            if not token:
                break
            kw["nextToken"] = token
        flush()
    except Exception as e:  # noqa: BLE001 — keep what was delivered; the next run re-scans the rest
        _save(ckpt, {**seen, **pushed})
        print(f"pull interrupted after {total} events: {str(e)[:200]}", file=sys.stderr)
        return 1
    _save(end, {**seen, **pushed})
    if total:
        print(f"pushed {total} WAF events (newest ts {newest})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
