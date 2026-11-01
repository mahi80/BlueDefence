#!/opt/aegis/venv/bin/python
"""Pull new AWS WAF log events from a CloudWatch Logs group into the local AEGIS push receiver.

Runs from a systemd timer every 30 s. Stdlib + boto3 (instance role; no keys on disk). Keeps a checkpoint of
the last event timestamp so a restart re-reads nothing. Each CloudWatch event is one WAF log record (JSON),
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
LAG_MS = 10 * 1000                    # CloudWatch ingestion lag: never read the newest 10 s
BATCH = 500


def _load() -> int:
    try:
        with open(CKPT) as f:
            return int(json.load(f).get("start_ms", 0))
    except (OSError, ValueError):
        return 0


def _save(start_ms: int) -> None:
    tmp = CKPT + ".tmp"
    with open(tmp, "w") as f:
        json.dump({"start_ms": start_ms, "saved_at": int(time.time())}, f)
    os.replace(tmp, CKPT)


def _push(lines: list[str]) -> None:
    body = gzip.compress(("\n".join(lines) + "\n").encode())
    req = urllib.request.Request(URL, data=body, method="POST",
                                 headers={"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/x-ndjson",
                                          "Content-Encoding": "gzip"})
    with urllib.request.urlopen(req, timeout=30) as r:
        if r.status != 200:
            raise RuntimeError(f"ingest {r.status}")


def main() -> int:
    now = int(time.time() * 1000)
    start = _load() or now - LOOKBACK_MS
    end = now - LAG_MS
    if end <= start:
        return 0
    logs = boto3.client("logs", region_name=REGION)
    kw = {"logGroupName": GROUP, "startTime": start + 1, "endTime": end, "limit": 10000}
    total, newest = 0, start
    buf: list[str] = []
    while True:
        try:
            page = logs.filter_log_events(**kw)
        except logs.exceptions.ResourceNotFoundException:
            print(f"log group {GROUP} not found yet", file=sys.stderr)
            return 0
        for ev in page.get("events", []):
            msg = ev.get("message", "").strip()
            if not msg:
                continue
            buf.append(msg)
            newest = max(newest, int(ev.get("timestamp", 0)))
            if len(buf) >= BATCH:
                _push(buf); total += len(buf); buf = []
        token = page.get("nextToken")
        if not token:
            break
        kw["nextToken"] = token
    if buf:
        _push(buf); total += len(buf)
    _save(end)   # LAG_MS already covers CloudWatch's ingestion delay, so everything up to `end` is final
    if total:
        print(f"pushed {total} WAF events (through {newest})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
