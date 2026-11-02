"""Posture scanning — the standing state of the estate, next to the runtime specialist agents.

The runtime agents (cloud_controlplane, edr, perimeter, ...) judge *events* as they happen. Posture
scanners judge a *snapshot*: every identity, bucket, cluster and template as it stands right now, so
a misconfiguration that predates AEGIS — or that no event ever touched — is still found.

Every scanner reads its input one of two ways (see ``sources.py``):

* **offline** (default) — a file the bank exports with its own tooling, e.g.
  ``aws iam get-account-authorization-details``. AEGIS holds no cloud credentials; works air-gapped.
* **live** — read-only API calls, only when ``AEGIS_POSTURE_LIVE=1`` and the cloud SDK is installed.

Findings are ``PostureFinding`` (a ``vuln_discovery.Finding`` plus the benchmark control it maps to),
so they flow into the same patch / HITL pipeline as every other vulnerability finding.

Run: ``python -m aegis.posture iam --auth-details auth.json --credential-report report.csv``
"""

from .base import SEVERITY_ORDER, PostureFinding, summarize

__all__ = ["SEVERITY_ORDER", "PostureFinding", "summarize"]
