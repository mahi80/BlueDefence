"""Seed the (mock) Splunk with the same sample alerts the in-memory
source uses, then optionally generate a few extra noise events so SPL
filtering has something to do.

Used by aegis/infra/splunk_demo.py to bootstrap a working Splunk-shaped
data source for the demo. Also runnable standalone against any Splunk
HEC endpoint:

  SPLUNK_URL=https://splunk.bank.internal:8088 SPLUNK_TOKEN=hec-... \\
    python -m aegis.infra.seed_splunk
"""
from __future__ import annotations

import json
import logging
import os
import time
import urllib.error
import urllib.request
from typing import Iterable

from .siem_source import iter_sample_alerts


_log = logging.getLogger("aegis.seed")


def _post_hec(base_url: str, token: str, events: Iterable[dict],
              *, index: str = "aegis_security",
              sourcetype: str = "aegis:notable") -> int:
    url = base_url.rstrip("/") + "/services/collector/event"
    body_lines = []
    for ev in events:
        envelope = {
            "time": time.time(),
            "host": "aegis-soc",
            "source": "aegis-mock-seed",
            "sourcetype": sourcetype,
            "index": index,
            "event": ev,
        }
        body_lines.append(json.dumps(envelope))
    body = "\n".join(body_lines).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={
            "Authorization": f"Splunk {token}",
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"HEC POST failed: {exc.code} {exc.reason}") from exc
    return int(payload.get("ackId", 0))


def seed(base_url: str | None = None, token: str | None = None) -> int:
    base_url = base_url or os.environ.get("SPLUNK_URL", "http://localhost:8089")
    token = token or os.environ.get("SPLUNK_TOKEN", "mock-hec-token")
    n = _post_hec(base_url, token, list(iter_sample_alerts()))
    _log.info("seeded %d AEGIS sample events into Splunk at %s", n, base_url)
    return n


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    n = seed()
    print(f"Seeded {n} events.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
