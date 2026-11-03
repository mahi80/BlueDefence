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
MAX_RECORDS = int(os.environ.get("AEGIS_CONTRIB_MAX_RECORDS", "2000") or 2000)   # ~1 MB compressed at typical chain size


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
            from ..hitl.signing import trusted_approver, verify
            if not verify(d)[0] or not trusted_approver(d.get("decided_by"))[0]:
                continue                  # an unsigned / forged row is not an analyst's label either
            card = cards.get(str(d["approval_id"]), {})
            args = card.get("args") or {}
            aid = str(args.get("alert_id") or d.get("alert_id") or "")
            if not aid:
                continue
            out.setdefault(aid, []).append(HumanDecision(
                approval_id=str(d["approval_id"]),
                action_type=str(args.get("action_type") or d.get("action_type") or str(card.get("action") or "").split(" -> ")[0]),
                target=str(args.get("target") or d.get("target") or "")[:200],
                decision=str(d.get("status") or d.get("decision") or "pending").lower(),
                decided_by_role=str(d.get("decided_by_role") or d.get("role") or "analyst"),
                rationale=str(d.get("reason") or d.get("rationale") or "")[:500],
                decided_at=d.get("decided_at") or (time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(float(d["ts"]))) if d.get("ts") else None),
                corrected_verdict=str(d.get("corrected_verdict") or d.get("verdict") or ""),
                decided_by=str(d.get("decided_by") or "")[:120],
            ))
    return out


MAX_PUSH_BYTES = 5 * 1024 * 1024
MAX_INFLATED_BYTES = 64 * 1024 * 1024


def _write_quarantine(cursor_path: Path | str | None, items: list[dict]) -> None:
    """Keep a local note of what the gate held back (ids + finding kinds/paths only, never the values)."""
    if not cursor_path:
        return
    try:
        q = Path(cursor_path).with_suffix(".quarantine.jsonl")
        with q.open("a", encoding="utf-8") as fh:
            for it in items:
                fh.write(json.dumps({"ts": int(time.time()), **it}, separators=(",", ":")) + "\n")
    except OSError as e:
        logger.warning("[contrib] could not write quarantine note: %s", e)


def read_cursor_state(path: Path | None) -> dict:
    """``{"ino": <inode of the segment>, "offset": <bytes>}``; a legacy bare-integer cursor is an offset with no
    segment identity (treated as the live file). Missing/corrupt → start of the live file."""
    try:
        if not path or not Path(path).exists():
            return {"ino": 0, "offset": 0}
        raw = Path(path).read_text().strip()
        if raw.startswith("{"):
            d = json.loads(raw)
            return {"ino": int(d.get("ino", 0)), "offset": int(d.get("offset", 0))}
        return {"ino": 0, "offset": int(raw)}
    except (OSError, ValueError, TypeError):
        return {"ino": 0, "offset": 0}


def read_cursor(path: Path | None) -> int:
    """Byte offset into the current segment (what the heartbeat reports)."""
    return read_cursor_state(path)["offset"]


def write_cursor(path: Path | None, value: int | dict) -> None:
    """Atomic: a crash mid-write must not leave an empty cursor that re-sends everything."""
    if not path:
        return
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    state = value if isinstance(value, dict) else {"ino": 0, "offset": int(value)}
    tmp = p.with_name(p.name + ".tmp")
    with tmp.open("w") as fh:
        fh.write(json.dumps(state, separators=(",", ":")))
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, p)


def _segments_from(audit: Path, cursor: dict) -> list[tuple[Path, int]]:
    """The files to read and where to start in each: the segment the cursor points at from its offset, every
    newer rotated segment from 0, then the live file from 0. A cursor on the live file is just (live, offset)."""
    rotated = sorted((q for q in audit.parent.glob(audit.name + ".*") if q.name[len(audit.name) + 1:].isdigit()),
                     key=lambda q: q.name)
    try:
        live_ino = audit.stat().st_ino if audit.exists() else 0
    except OSError:
        live_ino = 0
    ino, off = cursor.get("ino", 0), cursor.get("offset", 0)
    if not ino or ino == live_ino:
        return [(audit, off)]
    out: list[tuple[Path, int]] = []
    found = False
    for q in rotated:
        try:
            if q.stat().st_ino == ino:
                found = True
                out.append((q, off))
                continue
        except OSError:
            continue
        if found:
            out.append((q, 0))
    if not found:
        logger.warning("[contrib] cursor segment (inode %d) no longer exists — reading from the start of the live file", ino)
        return [(audit, 0)]
    out.append((audit, 0))
    return out


def build_bundle(audit_path: Path | str, *, installation_id: str, license_id: str = "", hitl_dir: Path | str | None = None,
                 scrubber: Scrubber | None = None, cursor: int | dict = 0, max_records: int = MAX_RECORDS) -> tuple[dict, dict]:
    """Records for every chain past ``cursor`` (``{"ino", "offset"}`` — segment-aware, so a rotation between
    contributions loses nothing; a bare int is an offset into the live file) → ``(bundle, new_cursor)``.
    The scrubber pseudonymises public IPs too — a contribution never carries a real address."""
    sc = scrubber or scrubber_from_env(scrub_ips=True)
    sc.scrub_ips = True
    decisions = _decisions(Path(hitl_dir) if hitl_dir else None)
    p = Path(audit_path)
    latest: dict[str, dict] = {}
    order: list[str] = []
    cur = cursor if isinstance(cursor, dict) else {"ino": 0, "offset": int(cursor)}
    new_cursor = dict(cur)
    if p.exists():
        for seg, start in _segments_from(p, cur):
            try:
                st = seg.stat()
            except OSError:
                continue
            if start > st.st_size:
                logger.warning("[contrib] %s is shorter than the cursor (%d > %d) — truncated; reading it from the start",
                               seg.name, start, st.st_size)
                start = 0
            with seg.open("rb") as fh:
                fh.seek(start)
                if start:
                    # an offset that does not sit on a row boundary (legacy cursor, hand edit) is realigned, loudly
                    fh.seek(start - 1)
                    if fh.read(1) != b"\n":
                        skipped = fh.readline()
                        logger.warning("[contrib] cursor was mid-row in %s; skipped %d byte(s) to the next row", seg.name, len(skipped))
                        start = fh.tell()
                new_cursor = {"ino": st.st_ino, "offset": start}
                while True:
                    pos = fh.tell()
                    line = fh.readline()
                    if not line:
                        break
                    if not line.endswith(b"\n"):
                        break                                   # a chain still being written: next time
                    new_cursor = {"ino": st.st_ino, "offset": pos + len(line)}
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
            if len(order) >= max_records:
                break
    records: list[TriageRecord] = []
    for aid in order:
        try:
            records.append(record_from_chain(latest[aid], alert=None, origin="community_contrib", scrubber=sc,
                                             human=decisions.get(aid) or [], source_system=installation_id))
        except Exception as e:  # noqa: BLE001 — one odd chain must not stop the batch
            logger.warning("[contrib] chain %s skipped: %s", aid, str(e)[:120])
    salt = os.environ.get("AEGIS_DATASET_SALT", "")
    if not salt:
        # the installation id is in the same bundle, so a key derived from it protects nothing; mark the bundle
        # unsalted — contribute() refuses to send it and the service refuses to store it
        salt = "unsalted|" + installation_id
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
              "generated_at": int(time.time()), "scrubbed": True, "salted": bool(sc.salted and os.environ.get("AEGIS_DATASET_SALT")),
              "counts": counts, "records": rows}
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
    from aegis.license import _require_https
    _require_https(server)                                   # the licence token rides on this request
    data = gzip.compress(json.dumps(bundle, separators=(",", ":")).encode())
    if len(data) > MAX_PUSH_BYTES:
        raise RuntimeError(f"bundle is {len(data) // 1024} KB compressed — over the {MAX_PUSH_BYTES // (1024 * 1024)} MB limit; "
                           "lower AEGIS_CONTRIB_MAX_RECORDS")
    # application/gzip: the HTTP API base64-encodes binary media types; as application/json it would be mangled as text
    req = urllib.request.Request(server.rstrip("/") + "/contrib", data=data, method="POST",
                                 headers={"Content-Type": "application/gzip", "Content-Encoding": "gzip",
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
    cursor = read_cursor_state(Path(cursor_path) if cursor_path else None)
    bundle, new_cursor = build_bundle(audit_path, installation_id=installation_id, license_id=license_id, hitl_dir=hitl_dir, cursor=cursor)
    n = bundle["counts"]["records"]
    if n < min_records:
        return {"sent": False, "records": n, "reason": "nothing new"}
    if not bundle.get("salted"):
        logger.error("[contrib] AEGIS_DATASET_SALT is not set — pseudonyms would be reversible from the bundle itself; nothing sent")
        return {"sent": False, "records": n, "reason": "unsalted (set AEGIS_DATASET_SALT)"}
    # gate per record: one leaky record is quarantined and reported, the rest still go, and the cursor advances
    clean, bad = privacy_gate.gate_records(bundle["records"])
    quarantined: list[dict] = []
    if bad:
        for i, found in bad.items():
            quarantined.append({"record_id": bundle["records"][i].get("record_id"),
                                "findings": [{"kind": f.get("kind"), "path": f.get("path")} for f in found[:5]]})   # never the value, not even masked
        logger.error("[contrib] privacy gate quarantined %d of %d record(s) e.g. %s — check what the capture is storing",
                     len(bad), n, quarantined[0]["findings"][:2])
        bundle["records"] = [bundle["records"][i] for i in clean]
        bundle["counts"]["records"] = len(bundle["records"])
        bundle["counts"]["quarantined"] = len(bad)
        _write_quarantine(cursor_path, quarantined)
    ok, found = check_bundle(bundle)                           # the envelope itself (counts, ids) must be clean too
    if not ok:
        logger.error("[contrib] bundle envelope refused by the privacy gate: %s", found[:3])
        return {"sent": False, "records": n, "reason": "privacy gate", "findings": found[:20]}
    if not bundle["records"]:
        write_cursor(Path(cursor_path) if cursor_path else None, new_cursor)
        return {"sent": False, "records": 0, "quarantined": len(bad), "reason": "all records quarantined"}
    result: dict[str, Any] = {"sent": False, "records": len(bundle["records"]), "quarantined": len(bad), "counts": bundle["counts"]}
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
            with gzip.open(p, "rb") as fh:
                data = fh.read(MAX_INFLATED_BYTES + 1)
            if len(data) > MAX_INFLATED_BYTES:
                logger.warning("[contrib] %s inflates past %d MB — skipped", p, MAX_INFLATED_BYTES // (1024 * 1024))
                continue
            yield p, json.loads(data)
        elif p.suffix == ".json":
            yield p, json.loads(p.read_text(encoding="utf-8"))


def records_from_bundles(folder: Path | str, *, gate: bool = True,
                         max_per_installation: int | None = None) -> tuple[list[TriageRecord], dict]:
    """Every usable record from every bundle under ``folder``; bundles failing the gate are skipped and reported."""
    cap = max_per_installation if max_per_installation is not None else int(
        os.environ.get("AEGIS_CONTRIB_MAX_PER_INSTALL", "1000") or 1000)
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
        kept = report["by_installation"].get(inst, 0)
        for row in b.get("records") or []:
            if kept >= cap:
                report["capped"] = report.get("capped", 0) + 1
                continue
            try:
                rec = _community_record(dict(row), inst)
            except (TypeError, ValueError, KeyError, AttributeError) as e:
                report["invalid"] = report.get("invalid", 0) + 1
                logger.warning("[contrib] record skipped (%s: %s)", type(e).__name__, str(e)[:120])
                continue
            if rec is None:
                report["unlabelled"] = report.get("unlabelled", 0) + 1
                continue
            recs.append(rec)
            kept += 1
        report["by_installation"][inst] = kept
    return recs, report


_COMMUNITY_VERDICTS = ("benign", "suspicious", "malicious", "uncertain")


def _community_record(row: dict, inst: str) -> TriageRecord | None:
    """One contributed record, with nothing the contributor asserted taken on trust (review round 3 G5-1).

    A bundle used to be imported with its own ``label`` (``ground_truth``!), ``split`` and ``origin``, so one
    Community install could label 30 SQLi alerts benign and push them into the fleet model's training set. Now
    the label is re-derived from the bundled analyst decisions (no decision → not imported: a model's own verdict
    teaches nothing), never ``ground_truth``; the split is re-derived from the fingerprint; the origin is always
    ``community_contrib``; and each installation is capped (``AEGIS_CONTRIB_MAX_PER_INSTALL``)."""
    from .schema import _label_from_human
    rec = TriageRecord(**{k: row.get(k) for k in TriageRecord.__dataclass_fields__ if k in row})
    chain = rec.chain if isinstance(rec.chain, dict) else {}
    model_verdict = str(chain.get("verdict") or "").lower()
    if model_verdict not in _COMMUNITY_VERDICTS:
        return None
    human = []
    for h in rec.human or []:
        if isinstance(h, dict):
            human.append(HumanDecision(**{k: h.get(k) for k in HumanDecision.__dataclass_fields__ if k in h}))
    verdict, source, disputed = _label_from_human(model_verdict, human)
    if source == "model" or verdict not in _COMMUNITY_VERDICTS:
        return None
    rec.label = {"verdict": verdict, "source": source, **({"disputed": True} if disputed else {})}
    rec.origin = "community_contrib"
    rec.split = ""                                    # assigned by the builder from the fingerprint
    rec.tags = [t for t in (rec.tags or []) if isinstance(t, str) and not t.startswith(("inst:", "eval"))][:20] + [
        f"inst:{inst[:12]}", "community"]
    return rec


__all__ = ["BUNDLE_SCHEMA", "redact_for_contrib", "build_bundle", "check_bundle", "write_bundle", "push_bundle", "contribute",
           "records_from_bundles", "iter_bundles", "read_cursor", "write_cursor"]
