"""Where posture scanners get their snapshot: an offline export file, or live read-only APIs.

Offline is the default and the recommended pilot mode — the bank runs its own export command and
hands AEGIS a file, so AEGIS never holds cloud credentials. Live mode is opt-in
(``AEGIS_POSTURE_LIVE=1``) and only ever calls read-only List/Get/Describe APIs.
"""

from __future__ import annotations

import base64
import csv
import io
import json
import os
import time
from pathlib import Path
from typing import Any


class PostureSourceError(RuntimeError):
    pass


def live_enabled() -> bool:
    return os.environ.get("AEGIS_POSTURE_LIVE", "").strip() == "1"


def load_json(path: str | Path) -> Any:
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError as e:
        raise PostureSourceError(f"export not found: {path}") from e
    except json.JSONDecodeError as e:
        raise PostureSourceError(f"{path} is not valid JSON: {e}") from e


def parse_credential_report(raw: str | bytes) -> list[dict[str, str]]:
    """The IAM credential report is a CSV; ``aws iam get-credential-report`` returns it base64'd in
    a JSON envelope. Accept the CSV text, the base64 blob, or the whole JSON envelope."""
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8")
    text = raw.strip()
    if text.startswith("{"):
        text = json.loads(text).get("Content", "")
    if not text.startswith("user,"):
        try:
            text = base64.b64decode(text).decode("utf-8")
        except Exception as e:
            raise PostureSourceError("credential report is neither CSV nor base64 CSV") from e
    return list(csv.DictReader(io.StringIO(text)))


def load_credential_report(path: str | Path) -> list[dict[str, str]]:
    try:
        return parse_credential_report(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError as e:
        raise PostureSourceError(f"credential report not found: {path}") from e


# ---- live (opt-in) --------------------------------------------------------------------------------

def _boto3_client(service: str, **kw: Any) -> Any:
    if not live_enabled():
        raise PostureSourceError("live posture collection is off; set AEGIS_POSTURE_LIVE=1 or pass an export file")
    try:
        import boto3
    except ImportError as e:
        raise PostureSourceError("live AWS collection needs boto3: pip install 'bluedefence[posture-aws]'") from e
    return boto3.client(service, **kw)


def live_aws_iam(wait_s: float = 30.0) -> tuple[dict, list[dict[str, str]]]:
    """Collect the same two inputs as the offline export, via read-only IAM calls.

    Needs only ``iam:GetAccountAuthorizationDetails``, ``iam:GenerateCredentialReport`` and
    ``iam:GetCredentialReport`` (the AWS-managed ``SecurityAudit`` policy covers all three).
    """
    iam = _boto3_client("iam")
    details: dict[str, list] = {"UserDetailList": [], "GroupDetailList": [], "RoleDetailList": [], "Policies": []}
    for page in iam.get_paginator("get_account_authorization_details").paginate():
        for k, acc in details.items():
            acc.extend(page.get(k, []))

    deadline = time.monotonic() + wait_s
    while iam.generate_credential_report().get("State") != "COMPLETE":
        if time.monotonic() > deadline:
            raise PostureSourceError("credential report not ready in time; retry or use an export")
        time.sleep(2)
    content = iam.get_credential_report()["Content"]
    return details, parse_credential_report(content)
