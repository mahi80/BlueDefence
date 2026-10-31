"""OTRF Security-Datasets ("Mordor") → labelled Sentinel incidents.

Security-Datasets is a public library of **real adversary-emulation telemetry** (Windows, Linux,
AWS), each scenario documented with its ATT&CK techniques and tactics. We use the scenario
metadata (`datasets/atomic/_metadata/*.yaml`) as ground truth: every scenario is a confirmed
attack, so its rows are ``malicious`` with the technique chain as the label.

We deliberately do **not** copy the adversary's command transcript (``adversary_view``) into the
training rows — that would put working attack commands in the dataset for no triage benefit.
The alert carries what a SIEM correlation would surface: platform, log sources involved,
tactic/technique chain, event-volume features, and the scenario's title/description.

When the scenario zip is available locally we add real volume features (event count, distinct
event IDs, hosts, time span); otherwise those fields are sampled from plausible ranges and the
row says so in ``provenance.telemetry``.
"""

from __future__ import annotations

import logging
import json
import random
import zipfile
from pathlib import Path

from ..attack_map import TECHNIQUES
from ..export import TRIAGE_SYSTEM_PROMPT
from ..schema import fingerprint, split_for
from ..synth import ALWAYS_HITL
from . import _products as P
from .sigma import _TACTIC_ACTIONS, _targets

logger = logging.getLogger("aegis.dataset.mordor")

LABEL_SOURCE = "public:mordor"
ORIGIN = "security-datasets"

_TACTIC_NAMES = {
    "TA0001": "initial_access", "TA0002": "execution", "TA0003": "persistence", "TA0004": "privilege_escalation",
    "TA0005": "defense_evasion", "TA0006": "credential_access", "TA0007": "discovery", "TA0008": "lateral_movement",
    "TA0009": "collection", "TA0010": "exfiltration", "TA0011": "command_and_control", "TA0040": "impact",
    "TA0043": "reconnaissance", "TA0042": "resource_development",
}


def load_scenarios(root: str | Path) -> list[dict]:
    """Parse ``datasets/atomic/_metadata/*.yaml`` under a Security-Datasets checkout."""
    import yaml
    root = Path(root)
    meta = root / "datasets" / "atomic" / "_metadata"
    if not meta.is_dir():
        meta = root
    out = []
    for p in sorted(meta.glob("*.yaml")):
        try:
            d = yaml.safe_load(p.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001, S112 — one unreadable community file is skipped; counts are reported by the importer
            continue
        if not isinstance(d, dict) or not d.get("attack_mappings"):
            continue
        techs, tactics = [], []
        for m in d["attack_mappings"]:
            t = str(m.get("technique", "")).upper()
            sub = m.get("sub-technique")
            if t:
                techs.append(f"{t}.{sub}" if sub else t)
            for ta in (m.get("tactics") or []):
                tactics.append(_TACTIC_NAMES.get(str(ta).upper(), str(ta).lower()))
        files = [f.get("link", "") for f in (d.get("files") or []) if isinstance(f, dict)]
        out.append({
            "id": str(d.get("id", p.stem)), "title": str(d.get("title", p.stem)), "description": str(d.get("description", "")).strip(),
            "platform": [str(x) for x in (d.get("platform") or [])], "tags": [str(x) for x in (d.get("tags") or [])],
            "techniques": techs, "tactics": list(dict.fromkeys(tactics)), "files": files,
            "file_types": [f.get("type", "") for f in (d.get("files") or []) if isinstance(f, dict)],
            "zip": next((root / "datasets" / "atomic" / l.split("datasets/atomic/", 1)[1] for l in files if "datasets/atomic/" in l), None),
        })
    return out


def _telemetry(zpath: Path | None, r: random.Random) -> tuple[dict, str]:
    """Real volume features from the scenario zip when present; otherwise plausible samples."""
    if zpath and zpath.exists():
        try:
            with zipfile.ZipFile(zpath) as z:
                name = next(n for n in z.namelist() if n.endswith(".json"))
                events = hosts = 0; ids: set = set(); srcs: set = set(); ts: list = []
                with z.open(name) as fh:
                    for line in fh:
                        events += 1
                        if events > 200000:
                            break
                        try:
                            e = json.loads(line)
                        except Exception:  # noqa: BLE001, S112 — a bad JSONL line in a 200k-line dump is skipped
                            continue
                        eid = e.get("EventID") or e.get("eventName") or e.get("event_id")
                        if eid is not None:
                            ids.add(str(eid))
                        src = e.get("Channel") or e.get("eventSource") or e.get("SourceName")
                        if src:
                            srcs.add(str(src))
                        h = e.get("Hostname") or e.get("host") or e.get("Computer")
                        if h:
                            hosts = max(hosts, len({h}))
                        t = e.get("@timestamp") or e.get("eventTime")
                        if t:
                            ts.append(str(t))
                span = ""
                if len(ts) >= 2:
                    span = f"{min(ts)[:19]} .. {max(ts)[:19]}"
                return ({"event_count": events, "distinct_event_ids": len(ids), "log_channels": sorted(srcs)[:8],
                         "time_span": span}, "real")
        except Exception as exc:  # noqa: BLE001 — unreadable scenario file → synthetic volume stats
            logger.debug("[dataset] mordor scenario stats unavailable: %s", exc)
    return ({"event_count": r.randint(80, 9000), "distinct_event_ids": r.randint(3, 40),
             "log_channels": r.sample(("Microsoft-Windows-Sysmon/Operational", "Security", "Microsoft-Windows-PowerShell/Operational",
                                       "aws.cloudtrail", "auditd", "System"), r.randint(1, 3)),
             "time_span": ""}, "sampled")


def scenario_to_rows(sc: dict, r: random.Random, *, variants: int = 4, val_pct: int = 15, xsoar_pct: int = 20) -> list[dict]:
    rows = []
    tactic = (sc["tactics"] or ["unknown"])[0]
    techs = sc["techniques"]
    tnames = [TECHNIQUES.get(t, {}).get("name", t) for t in techs]
    for _ in range(variants):
        tele, kind = _telemetry(sc["zip"], r)
        product = "aws" if "AWS" in sc["platform"] else ("linux" if "Linux" in sc["platform"] else "windows")
        event = {"hostname": P._host(r), "user": P._user(r), "scenario": sc["title"], "summary": sc["description"][:300], "platform": sc["platform"],
                 "technique_chain": techs, "tactic_chain": sc["tactics"], "telemetry": tele,
                 "correlated_over": f"{r.randint(2, 45)} min", "hosts_involved": r.randint(1, 4)}
        alert = P.sentinel(r, "malicious", event, product=product, service=",".join(sc["file_types"]) or "host",
                           tactic=tactic.replace("_", " ").title(), technique_id=techs[0] if techs else "",
                           title=(f"Multi-stage activity: {sc['title']}" if len(sc["tactics"]) > 1 else sc["title"]),
                           rule_name=("Fusion: multi-stage attack chain" if len(sc["tactics"]) > 1 else "Scheduled: behaviour analytics"))
        if r.random() < xsoar_pct / 100.0:
            alert = P.xsoar(r, alert, title=sc["title"])
        alert = {"id": f"MRD-{r.getrandbits(24):06X}", **alert}
        tg = _targets(alert)
        # calibration: a scenario that is ONLY discovery/recon is a single weak-signal class in a bank's
        # SOC (admins enumerate too) — hold and verify rather than contain
        single_weak = len(sc["tactics"]) <= 1 and tactic in ("discovery", "reconnaissance")
        verdict = "suspicious" if single_weak else "malicious"
        acts = _TACTIC_ACTIONS.get(tactic, _TACTIC_ACTIONS["unknown"])[1 if single_weak else 0]
        target = {
            "verdict": verdict, "confidence": round(r.uniform(.58, .74) if single_weak else r.uniform(.86, .97), 2),
            "key_signals": [(f"correlated multi-stage chain: {' → '.join(sc['tactics'][:4])}" if not single_weak
                             else f"single-tactic activity: {tactic}"),
                            f"techniques: {', '.join(tnames[:4])}",
                            f"{tele['event_count']} events across {len(tele['log_channels']) or 1} log channel(s)"],
            "recommended_actions": [{"action_type": a, "target": tg.get(t, t), "requires_hitl": a in ALWAYS_HITL} for a, t in acts],
            "techniques": techs,
            "rationale": ((f"Activity matching the documented behaviour '{sc['title']}' — {sc['description'][:160].rstrip('.')}. "
                           "On its own this is enumeration, which administrators also do; verify the operator before escalating.")
                          if single_weak else
                          (f"A correlated chain matching the documented adversary behaviour '{sc['title']}' — "
                           f"{sc['description'][:180].rstrip('.')}. Several tactics appear in sequence on the same assets, "
                           "which single-event noise does not produce. Contain and preserve evidence; containment needs analyst approval.")),
        }
        fp = fingerprint(alert)
        rows.append({
            "id": f"mordor-{fp[:16]}", "split": split_for(fp, val_pct), "label_source": LABEL_SOURCE, "origin": ORIGIN,
            "provenance": {"scenario_id": sc["id"], "telemetry": kind},
            "messages": [
                {"role": "system", "content": TRIAGE_SYSTEM_PROMPT},
                {"role": "user", "content": json.dumps(alert, sort_keys=True, ensure_ascii=False)},
                {"role": "assistant", "content": json.dumps(target, ensure_ascii=False)},
            ],
        })
    return rows


def generate_mordor(scenarios: list[dict], *, seed: int = 7, variants: int = 4, val_pct: int = 15, xsoar_pct: int = 20) -> list[dict]:
    r = random.Random(seed)
    rows: list[dict] = []
    for sc in scenarios:
        rows.extend(scenario_to_rows(sc, r, variants=variants, val_pct=val_pct, xsoar_pct=xsoar_pct))
    return rows


__all__ = ["LABEL_SOURCE", "ORIGIN", "generate_mordor", "load_scenarios"]
