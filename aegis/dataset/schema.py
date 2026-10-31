"""Record format of the AEGIS triage dataset (``aegis.triage/1``).

One record per (alert, evidence chain) pair — the input the SOC brain saw
and what it concluded — plus the human signal when there is one. Records
are plain JSON (one per line in ``records.jsonl``); the SFT views in
``export.py`` are derived from them.

Label provenance (``label.source``), strongest first:
- ``ground_truth`` — curated eval / red-team case with a known verdict
- ``human_corrected`` — an analyst rejected the action AND gave the verdict it
  should have been; that corrected verdict becomes the label (a strong signal —
  the loop learns the right answer, not just that the model was wrong)
- ``human_confirmed`` — a SOC analyst approved an action the chain asked
  for (dashboard approvals, roadmap 0.2) and rejected none
- ``human_disputed`` — an analyst rejected a requested action with no
  correction; the model verdict is suspect → ``needs_review``, excluded from
  SFT by default
- ``model`` — the agent's own verdict, nobody checked (weak label)
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

from .attack_map import MITRE_SOURCE, techniques_for
from .scrub import IDENTITY_KEYS, VOLATILE_KEYS, Scrubber

SCHEMA_VERSION = "aegis.triage/1"

KINDS = ("triage", "injection", "verdict_only", "proposal", "attack_profile")
LABEL_SOURCES = ("ground_truth", "human_corrected", "human_confirmed", "human_disputed", "model")
SPLITS = ("train", "val", "test")

_RAW_STR_CAP = 240
_EVIDENCE_RAW_CAP = 600        # chars of raw_data JSON kept per evidence item
_RATIONALE_CAP = 1200
_SIGNAL_CAP = 240

_fp_scrubber = Scrubber(salt="aegis-fingerprint", scrub_ips=False)


def _strip_for_fingerprint(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {str(k): _strip_for_fingerprint(v) for k, v in obj.items()
                if str(k).lower() not in VOLATILE_KEYS and str(k).lower() not in IDENTITY_KEYS}
    if isinstance(obj, list):
        return [_strip_for_fingerprint(v) for v in obj]
    return obj


def fingerprint(alert: dict) -> str:
    """Identity- and salt-independent content hash of an alert.

    Drops volatile keys (ids, timestamps) and identity keys, scrubs the
    remaining free text with a *fixed* salt, then hashes the canonical
    JSON. Two alerts with the same payload from different users share a
    fingerprint — that is what the split leakage check needs.
    """
    stripped = _fp_scrubber.scrub(_strip_for_fingerprint(alert if isinstance(alert, dict) else {"value": alert}))
    text = json.dumps(stripped, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _cap_raw(raw: Any) -> Any:
    """Cap raw evidence WITHOUT cutting tokens in half: long strings are shortened at a whitespace boundary
    (an e-mail or id is either kept whole or dropped, so the scrubber that runs afterwards still sees it),
    big lists/dicts are trimmed, and only then is the serialised size checked."""
    def trim(o: Any, depth: int) -> Any:
        if depth > 6:
            return "…"
        if isinstance(o, dict):
            return {str(k): trim(v, depth + 1) for k, v in list(o.items())[:40]}
        if isinstance(o, (list, tuple)):
            return [trim(v, depth + 1) for v in list(o)[:20]]
        if isinstance(o, str) and len(o) > _RAW_STR_CAP:
            cut = o.rfind(" ", 0, _RAW_STR_CAP)
            return o[: cut if cut > _RAW_STR_CAP // 2 else _RAW_STR_CAP] + " …"
        return o
    try:
        slim = trim(raw, 0)
        text = json.dumps(slim, default=str, sort_keys=True)
    except Exception:  # noqa: BLE001
        return {}
    if len(text) <= _EVIDENCE_RAW_CAP:
        return slim
    return {"_truncated": True, "keys": sorted(str(k) for k in raw)[:40] if isinstance(raw, dict) else []}


def compact_chain(chain: dict) -> dict:
    """The parts of a chain a trainer needs; raw evidence payloads capped."""
    md = chain.get("metadata") or {}
    swarm = md.get("swarm") if isinstance(md.get("swarm"), dict) else None
    return {
        "investigated_by": chain.get("investigated_by", ""),
        "specialists": list(chain.get("specialist_invocations") or []),
        "verdict": chain.get("verdict", ""),
        "confidence": float(chain.get("confidence") or 0.0),
        "evidence": [
            {
                "source": str(e.get("source", ""))[:120],
                "weight": str(e.get("weight", "")),
                "signal": str(e.get("signal", ""))[:_SIGNAL_CAP],
                "raw": _cap_raw(e.get("raw_data") if isinstance(e.get("raw_data"), dict) else {}),
            }
            for e in (chain.get("evidence") or []) if isinstance(e, dict)
        ],
        "reasoning": [
            {"step": r.get("step"), "action": str(r.get("action", ""))[:200],
             "observation": str(r.get("observation", ""))[:600],
             "conclusion": str(r.get("conclusion") or "")[:400]}
            for r in (chain.get("reasoning") or []) if isinstance(r, dict)
        ],
        "recommended_actions": [
            {"action_type": a.get("action_type"), "target": str(a.get("target", ""))[:200],
             "requires_hitl": bool(a.get("requires_hitl")),
             "confidence": float(a.get("confidence") or 0.0),
             "reasoning": str(a.get("reasoning", ""))[:400]}
            for a in (chain.get("recommended_actions") or []) if isinstance(a, dict)
        ],
        "vote_concur": md.get("vote_concur"),
        "injection_detected": bool(md.get("injection_detected", False)),
        "governance_block": md.get("governance_block"),
        "model": md.get("model"),
        "swarm": {
            "evidence_added": swarm.get("evidence_added"),
            "verdict_before": swarm.get("verdict_before"), "verdict_after": swarm.get("verdict_after"),
            "workers_ok": sum(1 for w in (swarm.get("workers") or {}).values() if isinstance(w, dict) and w.get("ok")),
        } if swarm else None,
        "integrity_hash": chain.get("integrity_hash"),
    }


_CAPTURED_TEXT_KEYS = {
    "evidence": ("signal", "raw"),
    "reasoning": ("action", "observation", "conclusion"),
    "recommended_actions": ("target", "reasoning"),
}


def _overlay_captured_text(live: dict, captured: dict) -> None:
    """Replace the PII-bearing text of a live compact chain with the copy captured (and
    scrubbed) on the agent host, matched by index. Everything structural — verdict,
    confidence, weights, action types, swarm / vote / governance metadata — stays live, so
    metadata written after capture is never lost. A list the live chain has grown past the
    snapshot keeps its extra items; those fall to the export scrubber's best effort."""
    for key, text_keys in _CAPTURED_TEXT_KEYS.items():
        live_items, cap_items = live.get(key) or [], captured.get(key) or []
        for l_item, c_item in zip(live_items, cap_items):
            if isinstance(l_item, dict) and isinstance(c_item, dict):
                for tk in text_keys:
                    if tk in c_item:
                        l_item[tk] = c_item[tk]


def rationale_from_chain(chain: dict) -> str:
    """One analyst-readable paragraph: conclusions first, then the strongest signals."""
    parts: list[str] = []
    for r in chain.get("reasoning") or []:
        if isinstance(r, dict):
            c = str(r.get("conclusion") or "").strip()
            if c:
                parts.append(c)
    strong = [e for e in (chain.get("evidence") or []) if isinstance(e, dict) and e.get("weight") == "high"]
    medium = [e for e in (chain.get("evidence") or []) if isinstance(e, dict) and e.get("weight") == "medium"]
    for e in (strong + medium)[:5]:
        sig = str(e.get("signal", "")).strip()
        if sig:
            parts.append(f"{e.get('source', 'signal')}: {sig}")
    text = " ".join(parts).strip()
    return text[:_RATIONALE_CAP]


@dataclass
class HumanDecision:
    approval_id: str
    action_type: str
    target: str
    decision: str                 # approved | rejected | pending
    decided_by_role: str = ""
    rationale: str = ""
    decided_at: Optional[str] = None
    corrected_verdict: str = ""    # on a reject: the verdict the analyst says it should have been


@dataclass
class TriageRecord:
    record_id: str
    kind: str
    origin: str
    split: str
    fingerprint: str
    alert: Optional[dict]
    label: dict
    chain: Optional[dict]
    rationale: str
    techniques: list[dict]
    human: list[dict] = field(default_factory=list)
    source_system: str = ""
    tags: list[str] = field(default_factory=list)
    created_at: str = ""
    schema: str = SCHEMA_VERSION
    meta: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


def _label_from_human(model_verdict: str, human: list[HumanDecision]) -> tuple[str, str, bool]:
    decided = [h for h in human if h.decision in ("approved", "rejected")]
    if not decided:
        return model_verdict, "model", False
    rejected = [h for h in decided if h.decision == "rejected"]
    if rejected:
        # A reject that carries the verdict it SHOULD have been teaches the right answer;
        # a bare reject only says "not this", so the model verdict stays suspect.
        corrected = next((h.corrected_verdict for h in rejected if h.corrected_verdict), "")
        if corrected:
            return corrected, "human_corrected", False
        return model_verdict, "human_disputed", True
    return model_verdict, "human_confirmed", False


def record_from_chain(chain: dict, *, alert: Optional[dict], origin: str, scrubber: Scrubber,
                      expected_verdict: Optional[str] = None, constraint: Optional[str] = None,
                      human: Optional[list[HumanDecision]] = None, split: Optional[str] = None,
                      kind: Optional[str] = None, source_system: str = "", tags: Optional[list[str]] = None,
                      created_at: Optional[str] = None, extra_meta: Optional[dict] = None) -> TriageRecord:
    """Build one record. ``alert`` may be ``None`` for a chain whose input was not captured."""
    human = human or []
    snapshot = (chain.get("metadata") or {}).get("alert") if isinstance(chain.get("metadata"), dict) else None
    if alert is None and isinstance(snapshot, dict) and isinstance(snapshot.get("data"), dict):
        alert_scrubbed = scrubber.scrub(snapshot["data"])          # captured pseudonyms re-keyed into this export's space
        fp = str(snapshot.get("fingerprint") or fingerprint(snapshot["data"]))
    elif alert is not None:
        alert_scrubbed = scrubber.scrub(alert)
        fp = fingerprint(alert)
    else:
        alert_scrubbed = None
        fp = hashlib.sha256(f"chain:{chain.get('integrity_hash') or chain.get('alert_id')}".encode()).hexdigest()

    # Which recommended actions did an analyst reject? Decide on the RAW chain, by index,
    # before anything is scrubbed: both the chain and the decisions carry the target as the
    # analyst saw it, so raw-vs-raw matches on the local and the dashboard path alike. Matching
    # after scrubbing silently fails whenever the target is an identity (user id, email) —
    # exactly the account-level disputes the learning loop most needs.
    def _hget(h, k):
        return getattr(h, k, None) if isinstance(h, HumanDecision) else (h or {}).get(k)
    rejected_keys = {(_hget(h, "action_type"), str(_hget(h, "target") or ""))
                     for h in human if _hget(h, "decision") == "rejected"}
    rejected_idx = {i for i, a in enumerate(chain.get("recommended_actions") or [])
                    if isinstance(a, dict) and (a.get("action_type"), str(a.get("target", ""))) in rejected_keys}

    # Dashboard chains are persisted raw (the alert snapshot is the only thing scrubbed at
    # capture), so at export the scrubber knows the captured pseudonyms but not the raw ids the
    # chain's signals and targets still carry. Prefer the compact chain captured alongside the
    # alert — scrubbed on the agent host with the scrubber that knew those ids — and re-key its
    # pseudonyms into this export's space, exactly as the alert snapshot is.
    captured_chain = snapshot.get("chain") if isinstance(snapshot, dict) else None
    chain_src = compact_chain(chain)
    if alert is None and isinstance(captured_chain, dict):
        _overlay_captured_text(chain_src, captured_chain)
    chain_scrubbed = scrubber.scrub(chain_src)
    for i in rejected_idx:
        acts = chain_scrubbed.get("recommended_actions") or []
        if i < len(acts) and isinstance(acts[i], dict):
            acts[i]["human_rejected"] = True
    model_verdict = str(chain.get("verdict", "") or "uncertain")
    if expected_verdict:
        verdict, label_source, needs_review = expected_verdict, "ground_truth", False
    else:
        verdict, label_source, needs_review = _label_from_human(model_verdict, human)

    if kind is None:
        kind = "injection" if constraint else ("triage" if alert_scrubbed is not None else "verdict_only")
    label = {
        "verdict": verdict,
        "source": label_source,
        "model_verdict": model_verdict,
        "confidence": float(chain.get("confidence") or 0.0),
        "needs_review": needs_review,
    }
    if constraint:
        label["constraint"] = constraint
    # a benign verdict carries no technique tag — the map keys on evidence *sources*, which exist on benign alerts too
    techniques = techniques_for(alert_scrubbed, chain_scrubbed) if (alert_scrubbed is not None and verdict != "benign") else []
    # stable across re-exports: the same alert judged again gets the same id (dedup is per origin+fingerprint)
    rid_seed = f"{origin}|{chain.get('alert_id') or ''}|{fp}"
    record = TriageRecord(
        record_id=hashlib.sha256(rid_seed.encode()).hexdigest()[:16],
        kind=kind, origin=origin, split=split or "",
        fingerprint=fp,
        alert=alert_scrubbed,
        label=label,
        chain=chain_scrubbed,
        rationale=scrubber.scrub_text(rationale_from_chain(chain_src)),
        techniques=techniques,
        # decisions are scrubbed too: a raw user id / email in a decision's target or rationale
        # would otherwise ride into records.jsonl unpseudonymised
        human=[scrubber.scrub(asdict(h) if isinstance(h, HumanDecision) else dict(h)) for h in human],
        source_system=str(source_system or (alert_scrubbed or {}).get("source", "") or ""),
        tags=list(tags or []),
        created_at=created_at or str(chain.get("completed_at") or chain.get("started_at")
                                     or datetime.now(timezone.utc).isoformat()),
        meta={"alert_id": chain.get("alert_id"), "mitre_source": MITRE_SOURCE, **(extra_meta or {})},
    )
    return record


def split_for(fp: str, val_pct: int) -> str:
    """Deterministic train/val assignment by fingerprint (stable across exports)."""
    bucket = int(fp[:8], 16) % 100
    return "val" if bucket < max(0, min(100, int(val_pct))) else "train"
