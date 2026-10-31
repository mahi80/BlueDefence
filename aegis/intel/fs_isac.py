"""FS-ISAC (and IBA peer-bank) IOC sharing.

Pushes high-confidence indicators of compromise from confirmed AEGIS
verdicts to the FS-ISAC intelligence-sharing platform (or a local
IBA-coordinated peer exchange) using a STIX 2.1-shaped JSON bundle.

Walking-skeleton transport prints to stdout. Production replaces ._send
with a TAXII 2.1 collection POST or the regulator's preferred channel.
"""
from __future__ import annotations

import json
import sys
import time
import uuid
from typing import Iterable

from ..agents.shared.evidence_chain import EvidenceChain


_MIN_CONFIDENCE_FOR_SHARING = 0.85


def build_stix_bundle(chains: Iterable[EvidenceChain], *, organization_id: str = "identity--acme-bank") -> dict:
    """Build a STIX 2.1-shaped bundle of high-confidence IOCs."""
    objects: list[dict] = []
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    for chain in chains:
        if chain.confidence < _MIN_CONFIDENCE_FOR_SHARING or chain.verdict != "malicious":
            continue
        for e in chain.evidence:
            rd = e.raw_data or {}
            if "ip" in rd and rd.get("verdict") == "known_malicious":
                objects.append(_indicator_ip(rd["ip"], chain, now))
            if "matches" in rd:
                for m in rd.get("matches", []):
                    objects.append(_indicator_raw(m, chain, now))
            if e.source == "honeytoken_monitor":
                objects.append(_indicator_honeytoken(rd.get("token_id", "?"), chain, now))
    if not objects:
        return {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": []}
    return {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": [{
            "type": "identity",
            "id": organization_id,
            "spec_version": "2.1",
            "name": "ACME Bank AEGIS",
            "identity_class": "organization",
            "created": now, "modified": now,
        }] + objects,
    }


def _indicator_ip(ip: str, chain: EvidenceChain, now: str) -> dict:
    return {
        "type": "indicator",
        "spec_version": "2.1",
        "id": f"indicator--{uuid.uuid4()}",
        "created": now, "modified": now,
        "name": f"Malicious IP from AEGIS verdict {chain.alert_id}",
        "pattern": f"[ipv4-addr:value = '{ip}']",
        "pattern_type": "stix",
        "valid_from": now,
        "labels": ["malicious-activity"],
        "confidence": int(chain.confidence * 100),
    }


def _indicator_raw(raw_value: str, chain: EvidenceChain, now: str) -> dict:
    return {
        "type": "indicator",
        "spec_version": "2.1",
        "id": f"indicator--{uuid.uuid4()}",
        "created": now, "modified": now,
        "name": f"AEGIS IOC {chain.alert_id}",
        "description": raw_value,
        "pattern": "[x-aegis:opaque = 'true']",  # opaque IOC, see description
        "pattern_type": "stix",
        "valid_from": now,
        "labels": ["malicious-activity"],
        "confidence": int(chain.confidence * 100),
    }


def _indicator_honeytoken(token_id: str, chain: EvidenceChain, now: str) -> dict:
    return {
        "type": "indicator",
        "spec_version": "2.1",
        "id": f"indicator--{uuid.uuid4()}",
        "created": now, "modified": now,
        "name": f"Honeytoken touch — {token_id}",
        "description": (
            "Honeytoken access observed. Other banks: search for any access to your equivalent "
            "decoys with similar fingerprint."
        ),
        "pattern": "[x-aegis:honeytoken_id = '{}']".format(token_id),
        "pattern_type": "stix",
        "valid_from": now,
        "labels": ["malicious-activity", "anomalous-activity"],
        "confidence": int(chain.confidence * 100),
    }


def push(chains: Iterable[EvidenceChain], stream=sys.stdout, **kwargs) -> dict:
    bundle = build_stix_bundle(chains, **kwargs)
    if not bundle.get("objects"):
        print("\n[FS-ISAC] no indicators above sharing threshold", file=stream)
        return bundle
    print("\n[FS-ISAC push (STIX 2.1 bundle)]", file=stream)
    print(json.dumps(bundle, indent=2), file=stream)
    return bundle
