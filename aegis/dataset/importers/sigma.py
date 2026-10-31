"""SigmaHQ rules → realistic, labelled triage rows.

Why Sigma: 3,000+ community detection rules, each one a *shape* of a real attack (the fields and
values a SIEM matches on), with ATT&CK tags, a confidence level and a list of known false
positives. That is exactly the knowledge a triage first-pass needs, and it is maintained by the
people who run SOCs — not by us.

How a rule becomes rows::

    rule  ──materialise──▶ event (satisfies the rule's selection, honours its filters)
          ──envelope─────▶ CrowdStrike / Sophos / Defender / Sentinel / Zscaler / Imperva / F5 alert
          ──label────────▶ verdict from the rule (level + match kind), actions from the tactic

Three match kinds per rule:
  * ``positive``   — the event fully matches; verdict from the rule level
                     (critical/high → malicious, medium/low/informational → suspicious)
  * ``filter_hit`` — the event matches the selection AND one of the rule's own exclusion
                     filters (the rule author's known-good case) → benign
  * ``near_miss``  — one required field carries an ordinary value; the rule fired on a loose
                     correlation → benign

Rows carry ``label_source="public:sigma"`` and the rule id in ``provenance`` so a bad rule can be
traced and excluded. Nothing is copied from the eval corpora (fingerprint guard in the mixer).
"""

from __future__ import annotations

import json
import random
import re
from dataclasses import dataclass, field
from pathlib import Path

from ..attack_map import TECHNIQUES
from ..export import TRIAGE_SYSTEM_PROMPT
from ..schema import SCHEMA_VERSION, fingerprint, split_for
from ..synth import ALWAYS_HITL
from . import _products as P

LABEL_SOURCE = "public:sigma"
ORIGIN = "sigma"

_SKIP_MODIFIERS = ("re", "fieldref", "base64offset", "base64", "expand", "exists", "lt", "lte", "gt", "gte")


@dataclass
class SigmaRule:
    id: str
    title: str
    level: str
    tags: list[str]
    product: str | None
    category: str | None
    service: str | None
    detection: dict
    falsepositives: list[str]
    description: str
    path: str = ""

    @property
    def technique_ids(self) -> list[str]:
        out = []
        for t in self.tags:
            m = re.fullmatch(r"attack\.(t\d{4}(?:\.\d{3})?)", t.lower())
            if m:
                out.append(m.group(1).upper())
        return out

    @property
    def tactic(self) -> str:
        for t in self.tags:
            t = t.lower()
            if t.startswith("attack.") and not re.fullmatch(r"attack\.[tgs]\d{4}.*", t):
                return t.split(".", 1)[1].replace("-", "_")
        return "unknown"


@dataclass
class Materialised:
    event: dict
    kind: str                                  # positive | filter_hit | near_miss
    notes: list[str] = field(default_factory=list)


# --------------------------------------------------------------------------- loading

def load_rules(root: str | Path) -> list[SigmaRule]:
    """Load every usable rule under ``root`` (a SigmaHQ checkout or its ``rules/`` dir)."""
    import yaml
    root = Path(root)
    base = root / "rules" if (root / "rules").is_dir() else root
    out: list[SigmaRule] = []
    for p in sorted(base.rglob("*.yml")):
        try:
            d = yaml.safe_load(p.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001, S112 — a malformed community file is skipped, not fatal
            continue
        if not isinstance(d, dict) or not isinstance(d.get("detection"), dict) or "condition" not in d["detection"]:
            continue
        if d.get("status") in ("deprecated", "unsupported"):
            continue
        ls = d.get("logsource") or {}
        out.append(SigmaRule(
            id=str(d.get("id", p.stem)), title=str(d.get("title", p.stem)), level=str(d.get("level", "medium")).lower(),
            tags=[str(t) for t in (d.get("tags") or [])], product=ls.get("product"), category=ls.get("category"),
            service=ls.get("service"), detection=d["detection"],
            falsepositives=[str(x) for x in (d.get("falsepositives") or []) if str(x).lower() not in ("unknown", "unlikely", "none")],
            description=str(d.get("description", "")).strip(), path=str(p.relative_to(root)),
        ))
    return out


# --------------------------------------------------------------------------- condition handling

def _blocks(rule: SigmaRule) -> tuple[dict[str, object], dict[str, object]]:
    """Split detection blocks into (selections, filters) by the Sigma naming convention."""
    sel, flt = {}, {}
    for name, body in rule.detection.items():
        if name in ("condition", "timeframe"):
            continue
        (flt if re.search(r"filter|exclu|allowlist|whitelist", name, re.I) else sel)[name] = body
    return sel, flt


def _required_selections(rule: SigmaRule, sel: dict, r: random.Random) -> list[str]:
    """Which selection blocks a positive event must satisfy, from the condition string.
    ``1 of selection*`` / ``or`` → one block; ``all of`` / ``and`` / bare name → all named blocks."""
    cond = str(rule.detection.get("condition", "")).lower()
    names = list(sel)
    if not names:
        return []
    if re.search(r"\b1 of\b", cond) and not re.search(r"\ball of\b", cond):
        return [r.choice(names)]
    if " or " in cond and " and " not in cond:
        return [r.choice(names)]
    return names


_PLACEHOLDER_HOST = ("files.example-cdn.net", "cdn.example.org", "updates.example.com", "share.example-storage.io")


def _value(r: random.Random, fieldname: str, mod: str, raw) -> str | int | None:
    """Realise one field value that satisfies ``field|mod: raw``."""
    v = raw if not isinstance(raw, list) else r.choice(raw)
    if v is None:
        return None
    if isinstance(v, bool | int | float) and not mod:
        return v
    s = str(v)
    mods = [m for m in mod.split("|") if m] if mod else []
    if any(m in _SKIP_MODIFIERS for m in mods):
        return None
    if "cidr" in mods:
        net = s.split("/")[0].rsplit(".", 1)[0]
        return f"{net}.{r.randint(1, 254)}"
    if "all" in mods and isinstance(raw, list):
        s = " ".join(str(x) for x in raw)
        mods = [m for m in mods if m != "all"] or ["contains"]
    if "windash" in mods:
        s = s.replace("/", "-") if r.random() < .5 else s
        mods = [m for m in mods if m != "windash"] or ["contains"]
    if "*" in s or "?" in s:
        parts = s.split("*")
        s = "".join(p_ + (r.choice(("C", "svc_app", "tmp", "data", "x1", "Public")) if i < len(parts) - 1 else "")
                    for i, p_ in enumerate(parts))[:200].replace("?", "a")
    f = fieldname.lower()
    if not mods or mods == ["contains"] and s and s == str(v):
        pre = suf = ""
        if mods == ["contains"]:
            if "command" in f or "cmdline" in f or "script" in f:
                pre, suf = r.choice(("", "cmd.exe /c ", "powershell.exe ", "/bin/sh -c ")), r.choice(("", " --quiet", " > out.txt", ""))
            elif "image" in f or "path" in f or "file" in f:
                pre = r.choice(("C:\\Users\\Public\\", "C:\\Windows\\Temp\\", "/tmp/", "C:\\ProgramData\\"))
            elif "url" in f or "uri" in f or "query" in f:
                pre, suf = r.choice(("/api/v1", "/portal", "")), r.choice(("", "?id=1", ""))
            else:
                pre, suf = r.choice(("", "x-", "")), r.choice(("", "-01", ""))
        return f"{pre}{s}{suf}"
    if "endswith" in mods:
        if s.startswith(("\\", "/")):
            pre = r.choice(("C:\\Windows\\System32", "C:\\Program Files\\Common", "C:\\Users\\Public\\Downloads", "/usr/local/bin"))
        elif "agent" in f:
            pre = r.choice(("Mozilla/5.0 (Windows NT 10.0; Win64) ", "curl/8.4.0 ", "python-requests/2.32 "))
        else:
            pre = r.choice(("svc", "x", "update", "app-"))
        return f"{pre}{s}"
    if "startswith" in mods:
        return f"{s}{r.choice(('', '.tmp', '-01', '/x', ' /q'))}"
    return s


_BENIGN_SWAP = {
    "image": ("C:\\Windows\\explorer.exe", "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
              "C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE", "/usr/bin/python3"),
    "commandline": ("explorer.exe", "chrome.exe --type=renderer", "OUTLOOK.EXE /recycle", "python3 report.py --quiet"),
    "parentimage": ("C:\\Windows\\explorer.exe", "C:\\Windows\\System32\\services.exe"),
    "eventname": ("DescribeInstances", "ListBuckets", "GetCallerIdentity"),
    "operationname": ("Sign-in activity", "Read user", "List groups"),
    "targetfilename": ("C:\\Users\\Public\\Documents\\report.docx", "/home/svc/app.log"),
    "destinationhostname": ("login.microsoftonline.com", "update.bank.in"),
}


def _benign_value(r: random.Random, fieldname: str):
    f = fieldname.lower()
    for k, vals in _BENIGN_SWAP.items():
        if k in f:
            return r.choice(vals)
    return r.choice(("none", "", "default", "0"))


def materialise(rule: SigmaRule, r: random.Random, kind: str = "positive") -> Materialised | None:
    """Build one event for ``rule`` of the given kind, or ``None`` if the rule needs unsupported logic."""
    sel, flt = _blocks(rule)
    required = _required_selections(rule, sel, r)
    if not required:
        return None
    event: dict = {}
    for name in required:
        body = sel[name]
        if isinstance(body, dict):
            for fk, raw in body.items():
                fieldname, _, mod = fk.partition("|")
                val = _value(r, fieldname, mod, raw)
                if val is None:
                    return None
                event[fieldname] = val
        elif isinstance(body, list):                     # keyword list or list of maps
            maps = [b for b in body if isinstance(b, dict)]
            if maps:
                for fk, raw in r.choice(maps).items():
                    fieldname, _, mod = fk.partition("|")
                    val = _value(r, fieldname, mod, raw)
                    if val is None:
                        return None
                    event[fieldname] = val
            else:
                event["message"] = str(r.choice(body))
        else:
            return None
    notes: list[str] = []
    if kind == "filter_hit":
        usable = [(n, b) for n, b in flt.items() if isinstance(b, dict)]
        if not usable:
            return None
        n, b = r.choice(usable)
        for fk, raw in b.items():
            fieldname, _, mod = fk.partition("|")
            val = _value(r, fieldname, mod, raw)
            if val is None:
                return None
            event[fieldname] = val
        notes.append(f"matches exclusion '{n}' of the rule")
    elif kind == "near_miss":
        if not event:
            return None
        f = r.choice(list(event))
        event[f] = _benign_value(r, f)
        notes.append(f"the '{f}' condition matched on an everyday value, so the rule fired on a loose correlation")
    return Materialised(event=event, kind=kind, notes=notes)


# --------------------------------------------------------------------------- labelling

_TACTIC_ACTIONS = {   # tactic -> (malicious actions, suspicious actions); host/user/ip placeholders filled below
    "credential_access":    ([("lock_account", "user"), ("revoke_sessions", "user"), ("isolate", "host")], [("challenge", "user"), ("monitor", "host")]),
    "initial_access":       ([("isolate", "host"), ("block", "ip"), ("snapshot_forensic", "host")], [("monitor", "host"), ("notify_user", "user")]),
    "persistence":          ([("isolate", "host"), ("kill_process", "host"), ("snapshot_forensic", "host")], [("monitor", "host"), ("notify_user", "user")]),
    "privilege_escalation": ([("isolate", "host"), ("revoke_sessions", "user"), ("snapshot_forensic", "host")], [("monitor", "host"), ("challenge", "user")]),
    "defense_evasion":      ([("isolate", "host"), ("kill_process", "host"), ("snapshot_forensic", "host")], [("monitor", "host")]),
    "execution":            ([("kill_process", "host"), ("isolate", "host"), ("snapshot_forensic", "host")], [("monitor", "host"), ("notify_user", "user")]),
    "discovery":            ([("isolate", "host"), ("revoke_sessions", "user")], [("monitor", "host"), ("throttle", "ip")]),
    "lateral_movement":     ([("isolate", "host"), ("revoke_sessions", "user"), ("snapshot_forensic", "host")], [("monitor", "host"), ("challenge", "user")]),
    "collection":           ([("isolate", "host"), ("block_export", "user"), ("snapshot_forensic", "host")], [("monitor", "host"), ("notify_user", "user")]),
    "command_and_control":  ([("isolate", "host"), ("block", "ip"), ("snapshot_forensic", "host")], [("monitor", "host"), ("throttle", "ip")]),
    "exfiltration":         ([("block_export", "user"), ("isolate", "host"), ("block", "ip")], [("monitor", "user"), ("notify_user", "user")]),
    "impact":               ([("isolate", "host"), ("escalate", "soc-lead"), ("snapshot_forensic", "host")], [("monitor", "host"), ("hold", "host")]),
    "reconnaissance":       ([("block", "ip"), ("throttle", "ip")], [("throttle", "ip"), ("monitor", "ip")]),
    "resource_development": ([("block", "ip"), ("monitor", "ip")], [("monitor", "ip")]),
    "unknown":              ([("isolate", "host"), ("snapshot_forensic", "host")], [("monitor", "host")]),
}


def _targets(alert: dict) -> dict[str, str]:
    host = next((v for k in ("hostname", "DeviceName", "location", "HostName") for v in [_find(alert, k)] if v), "host")
    user = next((v for k in ("user_name", "user_id", "AccountName", "user", "Name") for v in [_find(alert, k)] if v), "user")
    ip = next((v for k in ("client_ip", "ip_client", "clientIP", "serverIP", "local_ip", "Address") for v in [_find(alert, k)] if v), "ip")
    return {"host": str(host), "user": str(user), "ip": str(ip), "soc-lead": "soc-lead"}


def _find(d, key):
    if isinstance(d, dict):
        if key in d and isinstance(d[key], str | int):
            return d[key]
        for v in d.values():
            f = _find(v, key)
            if f:
                return f
    elif isinstance(d, list):
        for v in d:
            f = _find(v, key)
            if f:
                return f
    return None


def label(rule: SigmaRule, m: Materialised, alert: dict, r: random.Random) -> dict:
    tactic = rule.tactic
    techs = rule.technique_ids
    tnames = [TECHNIQUES.get(t, {}).get("name", t) for t in techs]
    tg = _targets(alert)
    if m.kind == "positive":
        if rule.level in ("critical", "high"):
            verdict, conf = "malicious", r.uniform(.84, .96)
            acts = _TACTIC_ACTIONS.get(tactic, _TACTIC_ACTIONS["unknown"])[0]
            rationale = (f"The event fully matches '{rule.title}' ({rule.level}-confidence detection: {rule.description[:160].rstrip('.')}). "
                         f"{'Tactic ' + tactic.replace('_', ' ') + '; ' if tactic != 'unknown' else ''}"
                         f"{'techniques ' + ', '.join(tnames) + '. ' if tnames else ''}"
                         "Contain first, then confirm — the containment actions need an analyst's approval.")
        else:
            verdict, conf = "suspicious", r.uniform(.55, .74)
            acts = _TACTIC_ACTIONS.get(tactic, _TACTIC_ACTIONS["unknown"])[1]
            fp = f" Known benign causes: {'; '.join(rule.falsepositives[:2])}." if rule.falsepositives else ""
            rationale = (f"The event matches '{rule.title}', a {rule.level}-confidence detection ({rule.description[:140].rstrip('.')}).{fp} "
                         "One signal of this strength warrants watching and a check with the owner, not containment.")
        signals = [f"rule match: {rule.title}"] + [f"{k} = {str(v)[:60]}" for k, v in list(m.event.items())[:3]]
    elif m.kind == "filter_hit":
        verdict, conf = "benign", r.uniform(.78, .9)
        acts = [("allow", "host"), ("monitor", "host")]
        signals = [f"rule match: {rule.title}", m.notes[0]] + ([f"documented false positive: {rule.falsepositives[0]}"] if rule.falsepositives else [])
        rationale = (f"'{rule.title}' fired, but the event also {m.notes[0]} — the rule author's own known-good case"
                     f"{' (' + rule.falsepositives[0] + ')' if rule.falsepositives else ''}. Treat as a tuning signal, not an incident.")
    else:  # near_miss
        verdict, conf = "benign", r.uniform(.7, .86)
        acts = [("allow", "host"), ("monitor", "host")]
        signals = [f"rule match: {rule.title}", m.notes[0]]
        rationale = (f"'{rule.title}' fired, but {m.notes[0]}. Nothing else in the alert supports the technique; "
                     "allow and flag the rule for tuning.")
    actions = [{"action_type": a, "target": tg.get(t, t), "requires_hitl": a in ALWAYS_HITL} for a, t in acts]
    return {"verdict": verdict, "confidence": round(conf, 2), "key_signals": signals, "recommended_actions": actions,
            "techniques": techs if verdict != "benign" else [], "rationale": rationale}


# --------------------------------------------------------------------------- envelope + rows

_WEB_ATTACK = ("SQL Injection", "Cross Site Scripting", "Remote File Inclusion", "Illegal Resource Access",
               "Bot Access Control", "DDoS", "Path Traversal", "Command Injection")


def envelope(rule: SigmaRule, m: Materialised, verdict: str, r: random.Random, *, xsoar_pct: int = 20) -> dict:
    fam = P.family_for_logsource(rule.product, rule.category or rule.service)
    tid = rule.technique_ids[0] if rule.technique_ids else ""
    tname = TECHNIQUES.get(tid, {}).get("name", tid)
    tactic = rule.tactic.replace("_", " ").title()
    kw = {"tactic": tactic, "technique_id": tid, "technique_name": tname, "title": rule.title}
    if fam == "edr":
        alert = {"crowdstrike": P.crowdstrike, "sophos": P.sophos, "defender": P.defender}[r.choice(P.EDR_PRODUCTS)](r, verdict, m.event, **kw)
    elif fam == "proxy":
        alert = P.zscaler(r, verdict, m.event, title=rule.title)
    elif fam == "waf":
        alert = (P.imperva if r.random() < .5 else P.f5_asm)(r, verdict, m.event, title=rule.title, attack_type=r.choice(_WEB_ATTACK))
    else:
        alert = P.sentinel(r, verdict, m.event, product=rule.product, service=rule.service or rule.category,
                           tactic=tactic, technique_id=tid, title=rule.title, rule_name=f"Sigma: {rule.title}")
    if r.random() < xsoar_pct / 100.0:
        alert = P.xsoar(r, alert, title=rule.title)
    return alert


def rule_to_rows(rule: SigmaRule, r: random.Random, *, variants: int = 3, benign_pct: int = 45, val_pct: int = 15,
                 xsoar_pct: int = 20) -> list[dict]:
    """``variants`` rows for one rule: positives plus ``benign_pct`` % filter-hit / near-miss rows."""
    rows = []
    for _ in range(variants):
        if r.random() * 100 < benign_pct:
            kind = "filter_hit" if r.random() < .75 else "near_miss"     # near-miss kept rare: its phrasing is easy to over-learn
        else:
            kind = "positive"
        m = materialise(rule, r, kind)
        if m is None:
            m = materialise(rule, r, "positive")
            if m is None:
                return rows
        verdict_guess = "benign" if m.kind != "positive" else ("malicious" if rule.level in ("critical", "high") else "suspicious")
        alert = envelope(rule, m, verdict_guess, r, xsoar_pct=xsoar_pct)
        target = label(rule, m, alert, r)
        alert = {"id": f"SIG-{r.getrandbits(24):06X}", **alert}
        fp = fingerprint(alert)
        rows.append({
            "id": f"sigma-{fp[:16]}", "split": split_for(fp, val_pct), "label_source": LABEL_SOURCE, "origin": ORIGIN,
            "provenance": {"rule_id": rule.id, "rule_path": rule.path, "level": rule.level, "kind": m.kind},
            "messages": [
                {"role": "system", "content": TRIAGE_SYSTEM_PROMPT},
                {"role": "user", "content": json.dumps(alert, sort_keys=True, ensure_ascii=False)},
                {"role": "assistant", "content": json.dumps(target, ensure_ascii=False)},
            ],
        })
    return rows


def generate_sigma(rules: list[SigmaRule], *, seed: int = 7, variants: int = 3, benign_pct: int = 45,
                   val_pct: int = 15, xsoar_pct: int = 20, max_rows: int | None = None) -> list[dict]:
    r = random.Random(seed)
    rows: list[dict] = []
    for rule in rules:
        rows.extend(rule_to_rows(rule, r, variants=variants, benign_pct=benign_pct, val_pct=val_pct, xsoar_pct=xsoar_pct))
        if max_rows and len(rows) >= max_rows:
            break
    return rows[:max_rows] if max_rows else rows


__all__ = ["LABEL_SOURCE", "ORIGIN", "SCHEMA_VERSION", "SigmaRule", "generate_sigma", "load_rules", "materialise", "label"]
