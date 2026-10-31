"""Community contribution — the data a free licence pays with.

A Community licence (``data_sharing`` feature) ships the installation's **derived** security
telemetry back to BlueDefence so the next model release is trained on real SOC traffic:

    what goes            scrubbed evidence chains (verdict, confidence, evidence types/weights, action
                         types, timing, fault/attack class), the captured alert *shape* with every
                         identity pseudonymised, and the analysts' approve / reject / correction decisions
    what never goes      raw logs or payloads, real IPs / hostnames / users / accounts, customer names,
                         device configs, anything that fails ``privacy_gate``

Flow on the AEGIS host::

    audit.jsonl ──┐
                  ├─► TriageRecords (Scrubber, salted) ─► privacy gate ─► bundle.json.gz ─► POST /contrib
    hitl/*.jsonl ─┘                                            │ (refused → nothing leaves; findings logged)

A cursor file remembers how far into the audit log the last bundle reached, so each push carries
only new chains. ``python -m aegis.dataset contrib`` runs it by hand (``--out`` for air-gapped
hosts: the operator e-mails the file); the service runs it hourly when ``AEGIS_CONTRIB=1``.

On the BlueDefence side ``python -m aegis.dataset import-contrib <dir>`` turns a folder of bundles
into a versioned dataset (``records.jsonl``, SFT and DPO views) for ``aegis.finetune``.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import logging
import os
import re
import time
from dataclasses import asdict
from pathlib import Path
from typing import Any, Iterable, Optional

from . import privacy_gate
from .schema import SCHEMA_VERSION, HumanDecision, TriageRecord, record_from_chain
from .scrub import Scrubber, scrubber_from_env

logger = logging.getLogger("aegis.dataset.contrib")

BUNDLE_SCHEMA = "aegis-contrib/1"
MAX_RECORDS = 5000


# ----------------------------------------------------------------- redact --

_EMAIL_RX = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_IPV4_RX = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
_HOSTLIKE_RX = re.compile(r"\b(?=[a-z0-9-]{1,63}\.)(?:[a-z0-9-]{1,63}\.)+(?:bank|internal|local|corp|lan|in|co\.in|com|net|org)\b", re.I)


def _h(salt: str, kind: str, value: str) -> str:
    return hashlib.sha256(f"{salt}|{kind}|{value}".encode()).hexdigest()[:12]


def redact_for_contrib(obj: Any, salt: str) -> Any:
    """What the Scrubber leaves (it keeps e-mail domains and, by default, public IPs — useful inside the
    bank, not outside it) is replaced with salted tokens before anything leaves: ``email-…``, ``ip-…``,
    ``host-…``. Consistent within one installation, so correlation survives; unlinkable across installations."""
    if isinstance(obj, dict):
        return {k: redact_for_contrib(v, salt) for k, v in obj.items()}
    if isinstance(obj, list):
        return [redact_for_contrib(v, salt) for v in obj]
    if isinstance(obj, str):
        s = _EMAIL_RX.sub(lambda m: f"email-{_h(salt, 'email', m.group(0).lower())}", obj)
        s = _IPV4_RX.sub(lambda m: f"ip-{_h(salt, 'ip', m.group(0))}", s)
        s = _HOSTLIKE_RX.sub(lambda m: f"host-{_h(salt, 'host', m.group(0).lower())}", s)
        return s
    return obj


# ------------------------------------------------------------------ local --

def _decisions(hitl_dir: Path | None) -> dict[str, list[HumanDecision]]:
    """alert_id → analyst decisions, from the file transport's cards + decisions journals."""
    out: dict[str, list[HumanDecision]] = {}
    if not hitl_dir or not Path(hitl_dir).is_dir():
        return out
    cards: dict[str, dict] = {}
    cf, df = Path(hitl_dir) / "cards.jsonl", Path(hitl_dir) / "decisions.jsonl"
    if cf.exists():
        for line in cf.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                c = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(c, dict) and c.get("id") and c.get("kind") != "investigation":
                cards[str(c["id"])] = c
    if df.exists():
        for line in df.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                d = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(d, dict) or not d.get("approval_id"):
                continue
            card = cards.get(str(d["approval_id"]), {})
            args = card.get("args") or {}
            aid = str(args.get("alert_id") or d.get("alert_id") or "")
            if not aid:
                continue
            out.setdefault(aid, []).append(HumanDecision(
                approval_id=str(d["approval_id"]), action_type=str(card.get("action") or d.get("action_type") or ""),
                target=str(args.get("target") or d.get("target") or "")[:200],
                decision=str(d.get("status") or d.get("decision") or "pending").lower(),
                decided_by_role=str(d.get("decided_by_role") or d.get("role") or "analyst"),
                rationale=str(d.get("reason") or d.get("rationale") or "")[:500],
                decided_at=d.get("decided_at") or (time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(float(d["ts"]))) if d.get("ts") else None),
                corrected_verdict=str(d.get("corrected_verdict") or d.get("verdict") or ""),
            ))
    return out


def read_cursor(path: Path | None) -> int:
    try:
        return int(Path(path).read_text().strip()) if path and Path(path).exists() else 0
    except (OSError, ValueError):
        return 0


def write_cursor(path: Path | None, value: int) -> None:
    if path:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_text(str(value))


def build_bundle(audit_path: Path | str, *, installation_id: str, license_id: str = "", hitl_dir: Path | str | None = None,
                 scrubber: Scrubber | None = None, cursor: int = 0, max_records: int = MAX_RECORDS) -> tuple[dict, int]:
    """Records for every chain past ``cursor`` (a byte offset into the audit log) → ``(bundle, new_cursor)``.
    The scrubber pseudonymises public IPs too — a contribution never carries a real address."""
    sc = scrubber or scrubber_from_env(scrub_ips=True)
    sc.scrub_ips = True
    decisions = _decisions(Path(hitl_dir) if hitl_dir else None)
    p = Path(audit_path)
    latest: dict[str, dict] = {}
    order: list[str] = []
    new_cursor = cursor
    if p.exists():
        with p.open("rb") as fh:
            fh.seek(cursor)
            while True:
                pos = fh.tell()
                line = fh.readline()
                if not line:
                    break
                if not line.endswith(b"\n"):
                    break                                   # a chain still being written: next time
                new_cursor = pos + len(line)
                if not line.strip():
                    continue
                try:
                    chain = json.loads(line)
                except json.JSONDecodeError:
                    continue
                aid = str(chain.get("alert_id") or chain.get("integrity_hash") or len(order))
                if aid not in latest:
                    order.append(aid)
                latest[aid] = chain
                if len(order) >= max_records:
                    break
    records: list[TriageRecord] = []
    for aid in order:
        try:
            records.append(record_from_chain(latest[aid], alert=None, origin="community_contrib", scrubber=sc,
                                             human=decisions.get(aid) or [], source_system=installation_id))
        except Exception as e:  # noqa: BLE001 — one odd chain must not stop the batch
            logger.warning("[contrib] chain %s skipped: %s", aid, str(e)[:120])
    salt = os.environ.get("AEGIS_DATASET_SALT", "") or installation_id
    rows = [redact_for_contrib(asdict(r), salt) for r in records]
    for r in rows:
        r["source_system"] = installation_id                 # the only identity the bundle carries: the installation's
    counts = {
        "records": len(rows),
        "with_alert": sum(1 for r in rows if r.get("alert")),
        "human_decided": sum(1 for r in rows if any(h.get("decision") in ("approved", "rejected") for h in r.get("human") or [])),
        "human_corrected": sum(1 for r in rows if (r.get("label") or {}).get("source") == "human_corrected"),
        "by_verdict": _count(rows, lambda r: (r.get("label") or {}).get("verdict", "")),
        "by_alert_type": _count(rows, lambda r: ((r.get("alert") or {}).get("alert_type") or (r.get("alert") or {}).get("source") or "unknown")),
    }
    bundle = {"schema": BUNDLE_SCHEMA, "record_schema": SCHEMA_VERSION, "installation_id": installation_id, "license_id": license_id,
              "generated_at": int(time.time()), "scrubbed": True, "salted": sc.salted, "counts": counts, "records": rows}
    return bundle, new_cursor


def _count(rows: list[dict], key) -> dict[str, int]:
    out: dict[str, int] = {}
    for r in rows:
        k = str(key(r) or "")
        out[k] = out.get(k, 0) + 1
    return dict(sorted(out.items()))


def check_bundle(bundle: dict) -> tuple[bool, list[dict]]:
    """The privacy gate over everything but the installation id."""
    body = {k: v for k, v in bundle.items() if k != "installation_id"}
    return privacy_gate.gate(body)


def write_bundle(bundle: dict, out: Path | str) -> Path:
    out = Path(out)
    out.parent.mkdir(parents=True, exist_ok=True)
    data = json.dumps(bundle, separators=(",", ":")).encode()
    if out.suffix == ".gz":
        out.write_bytes(gzip.compress(data))
    else:
        out.write_bytes(data)
    return out


def push_bundle(server: str, bundle: dict, license_token: str, *, timeout: float = 60.0) -> dict:
    """POST the bundle (gzip) to the licence service; the licence token is the bearer — the service
    verifies it and binds the upload to the installation it names."""
    import urllib.error
    import urllib.request
    data = gzip.compress(json.dumps(bundle, separators=(",", ":")).encode())
    req = urllib.request.Request(server.rstrip("/") + "/contrib", data=data, method="POST",
                                 headers={"Content-Type": "application/json", "Content-Encoding": "gzip",
                                          "Authorization": "Bearer " + license_token.strip(), "User-Agent": "aegis-contrib/1"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        try:
            msg = json.loads(e.read()).get("error", "")
        except Exception:  # noqa: BLE001
            msg = ""
        raise RuntimeError(f"contribution refused ({e.code}): {msg or e.reason}") from None


def contribute(*, audit_path: Path | str, installation_id: str, license_token: str = "", license_id: str = "",
               hitl_dir: Path | str | None = None, cursor_path: Path | str | None = None, server: str = "",
               out: Path | str | None = None, min_records: int = 1) -> dict:
    """One contribution run: build → gate → (push | write). Returns a summary; raises nothing on 'nothing new'."""
    cursor = read_cursor(Path(cursor_path) if cursor_path else None)
    bundle, new_cursor = build_bundle(audit_path, installation_id=installation_id, license_id=license_id, hitl_dir=hitl_dir, cursor=cursor)
    n = bundle["counts"]["records"]
    if n < min_records:
        return {"sent": False, "records": n, "reason": "nothing new"}
    ok, found = check_bundle(bundle)
    if not ok:
        logger.error("[contrib] bundle refused by the privacy gate: %d finding(s) e.g. %s — nothing left this host; "
                     "set AEGIS_DATASET_SALT and check what the capture is storing", len(found), found[:3])
        return {"sent": False, "records": n, "reason": "privacy gate", "findings": found[:20]}
    result: dict[str, Any] = {"sent": False, "records": n, "counts": bundle["counts"]}
    if out:
        result["file"] = str(write_bundle(bundle, out))
    if server:
        if not license_token:
            raise RuntimeError("a licence token is required to push a contribution (AEGIS_LICENSE)")
        result["server"] = push_bundle(server, bundle, license_token)
        result["sent"] = True
    if out or server:
        write_cursor(Path(cursor_path) if cursor_path else None, new_cursor)
    return result


# ----------------------------------------------------------- import side --

def iter_bundles(folder: Path | str) -> Iterable[tuple[Path, dict]]:
    for p in sorted(Path(folder).rglob("*")):
        if p.suffix == ".gz" and p.name.endswith(".json.gz"):
            yield p, json.loads(gzip.decompress(p.read_bytes()))
        elif p.suffix == ".json":
            yield p, json.loads(p.read_text(encoding="utf-8"))


def records_from_bundles(folder: Path | str, *, gate: bool = True) -> tuple[list[TriageRecord], dict]:
    """Every record from every bundle under ``folder``; bundles failing the gate are skipped and reported."""
    recs: list[TriageRecord] = []
    report: dict[str, Any] = {"bundles": 0, "skipped_gate": [], "by_installation": {}}
    for path, b in iter_bundles(folder):
        if b.get("schema") != BUNDLE_SCHEMA:
            continue
        if gate:
            ok, found = check_bundle(b)
            if not ok:
                report["skipped_gate"].append({"file": str(path), "findings": found[:5]})
                continue
        report["bundles"] += 1
        inst = str(b.get("installation_id") or "unknown")
        for row in b.get("records") or []:
            try:
                row = dict(row)
                row.setdefault("tags", [])
                row["tags"] = list(row["tags"]) + [f"inst:{inst[:12]}"]
                recs.append(TriageRecord(**{k: row.get(k) for k in TriageRecord.__dataclass_fields__ if k in row}))
            except TypeError as e:
                logger.warning("[contrib] record skipped (%s)", e)
        report["by_installation"][inst] = report["by_installation"].get(inst, 0) + len(b.get("records") or [])
    return recs, report


__all__ = ["BUNDLE_SCHEMA", "redact_for_contrib", "build_bundle", "check_bundle", "write_bundle", "push_bundle", "contribute",
           "records_from_bundles", "iter_bundles", "read_cursor", "write_cursor"]
