"""Remediation proposals for ACT NOW exposures — proposed through the approval queue, verified by the next run.

The exposure engine says *which* findings are exploitable, reachable and undefended. This module turns each
ACT NOW finding into a concrete proposal a human can approve, and then **checks on the next run whether the
path really closed** — an approved change that never landed is the commonest way a "fixed" finding stays
open.

For every ACT NOW finding the proposal lists up to three options, built from the facts the engine recorded
(``extra.path``: the security group / NSG that opens the port, the load balancer in front, the WAF that
covers it):

* **virtual patch** — a blocking WAF rule for the CVE on the protection that already fronts the asset (or
  switching a monitor-mode protection to block). Closes when the next run sees the CVE ``full``-y defended.
* **cut the path** — revoke the internet rule on the exact security group (AWS), add a deny rule on the
  exact NSG (Azure), take the Service off the internet (Kubernetes) or a firewall change request (on-prem).
  Closes when the next run no longer finds the port reachable from the internet.
* **patch** — the fix. Closes when the scanner stops reporting the CVE on that asset.

Nothing here changes infrastructure. Approval records a commitment (who approved, when, which proposal);
the change is made by the owning team through their own change process. The scanners stay read-only, and
the WAF connectors can only block IPs, so there is no connector that could apply a virtual patch or a
security-group change even by mistake.

Lifecycle (``<store>/proposals.json``, keyed by the finding's fingerprint)::

    proposed ──(filed to HITL)──► awaiting_approval ──► approved ──(next run)──► verified_closed
                                                  │              └──────────────► approved_still_open
                                                  └──► rejected / expired
    any open state ──(finding left ACT NOW without a decision)──► closed_before_decision
    any state ──(finding waived)──► accepted_risk

The approval channel is the deployment's HITL transport (``AEGIS_HITL_TRANSPORT`` — the dashboard, so the
SOC console can approve it, ServiceNow, or the file queue). With no channel configured the proposals are
still written and shown, marked ``proposed``.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .engine import WEB_PORTS

logger = logging.getLogger("aegis.exposure.remediation")

OPEN_STATES = ("proposed", "awaiting_approval", "approved", "approved_still_open")
ALERT_PREFIX = "exposure:"


def _iso(t: datetime) -> str:
    return t.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse(s: str) -> datetime:
    return datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)


def _arm(rid: str) -> tuple[str, str]:
    """Azure resource id → (resource group, name)."""
    parts = rid.strip("/").split("/")
    low = [p.lower() for p in parts]
    rg = parts[low.index("resourcegroups") + 1] if "resourcegroups" in low else "RESOURCE_GROUP"
    return rg, parts[-1]


# ---- building the options -------------------------------------------------------------------------

def build_options(row: dict) -> list[dict]:
    """The concrete ways to close this exposure, most immediate first."""
    x = row.get("extra") or {}
    path = x.get("path") or {}
    cve = row.get("id") if str(row.get("id", "")).upper().startswith("CVE-") else None
    port = x.get("port")
    port_ok = isinstance(port, int) and port > 0
    asset = row.get("resource") or ""
    name = (row.get("affected_component") or asset).rsplit(":", 1)[0]
    opts: list[dict] = []

    prots = path.get("protections") or []
    web = port in WEB_PORTS or bool(prots)   # a WAF only stops HTTP: no virtual patch for SSH, RDP, SMB …
    if cve and x.get("defended") != "full" and web:
        blocking = [p for p in prots if p.get("mode") == "block"]
        monitor = [p for p in prots if p.get("mode") == "monitor"]
        if blocking:
            p = blocking[0]
            steps = [(f"Add a blocking rule for {cve} on {p['vendor']} {p['name']} (name it with the CVE id so the "
                      "coverage export recognises it as a virtual patch).")]
            owner = f"WAF team ({p['vendor']})"
        elif monitor:
            p = monitor[0]
            steps = [f"Switch {p['vendor']} {p['name']} from monitor to block mode, or at least its rules for {cve}.",
                     f"Add a blocking rule for {cve} named with the CVE id."]
            owner = f"WAF team ({p['vendor']})"
        else:
            steps = [(f"Nothing blocking fronts {name}: put it behind the bank's WAF (or the BlueDefence edge shim in "
                      f"live mode) and add a blocking rule for {cve}.")]
            owner = "WAF team"
        steps.append("Re-export WAF coverage (python -m aegis.exposure.coverage) before the next run.")
        opts.append({"kind": "virtual_patch", "title": f"Virtual-patch {cve} at the WAF", "owner": owner,
                     "steps": steps, "commands": [], "closes_when": f"the next run shows {cve} virtual-patched in blocking mode"})

    if x.get("reach") == "internet" and port_ok:
        src = path.get("source")
        via = path.get("via")
        opened = path.get("opened_by") or []
        cmds: list[str] = []
        steps: list[str] = []
        if src == "aws" and opened:
            for g in opened:
                cmds += [f"aws ec2 revoke-security-group-ingress --group-id {g} --protocol tcp --port {port} --cidr 0.0.0.0/0",
                         (f"aws ec2 revoke-security-group-ingress --group-id {g} --ip-permissions "
                          f"'IpProtocol=tcp,FromPort={port},ToPort={port},Ipv6Ranges=[{{CidrIpv6=::/0}}]'")]
            rng = path.get("range") or [port, port]
            if rng[0] != rng[1]:
                steps.append(f"The open rule covers ports {rng[0]}-{rng[1]}: revoke that range rule and re-add only the "
                             "ports the service needs (the commands above assume a single-port rule).")
            steps.insert(0, f"Remove the internet rule for port {port} on {', '.join(opened)}"
                         + (f" (it admits the internet {via})" if via else "") + "; allow only the partner / admin CIDRs that need it.")
        elif src == "azure" and opened:
            for nsg in opened:
                rg, n = _arm(nsg)
                cmds.append(f"az network nsg rule create -g {rg} --nsg-name {n} -n aegis-deny-internet-{port} "
                            f"--priority 100 --direction Inbound --access Deny --protocol Tcp "
                            f"--source-address-prefixes Internet --destination-port-ranges {port}")
            steps.append(f"Deny port {port} from the internet on the NSG(s) in front of {name}; priority 100 must be lower than "
                         "the allow rule's priority (check with az network nsg rule list). Better still, delete the allow rule.")
        elif src == "k8s":
            steps.append(f"Take {name} off the internet {via or ''}: make the Service ClusterIP or internal "
                         "(internal load-balancer annotation), or put the Ingress behind the WAF.".replace("  ", " "))
        else:
            steps.append(f"Firewall change request: deny inbound tcp/{port} from the internet to {name}"
                         + (f" ({via})" if via else "") + ".")
        if via and src in ("aws", "azure"):
            steps.append(f"The path runs {via}: removing the listener / rule there closes it too.")
        opts.append({"kind": "cut_path", "title": f"Close port {port} to the internet", "owner": "network / cloud team",
                     "steps": steps, "commands": cmds,
                     "closes_when": f"the next run no longer finds port {port} on {name} reachable from the internet"})

    target = f"{cve or row.get('id')} on {name}"
    opts.append({"kind": "patch", "title": f"Patch {target}", "owner": "asset owner",
                 "steps": [f"Patch or upgrade {target}, then let the scanner re-scan the host."], "commands": [],
                 "closes_when": "the scanner stops reporting it on this asset"})
    return opts


def _summary(row: dict, options: list[dict]) -> str:
    x = row.get("extra") or {}
    reasons = x.get("reasons") or []
    lines = [f"ACT NOW: {row.get('id')} on {row.get('affected_component')} — {x.get('title', '')}".strip(" —"),
             *(f"- {r}" for r in reasons),
             "Options (approve = commit to one of these; nothing is applied automatically):",
             *(f"{i}. {o['title']} — owner: {o['owner']}" for i, o in enumerate(options, 1)),
             "The next posture run re-tests the path and marks this verified closed or still open."]
    return "\n".join(lines)


# ---- the HITL side --------------------------------------------------------------------------------

@dataclass
class _Card:
    """The real RecommendedAction / EvidenceChain models, so the HITL journal can restore the card after a restart."""
    action: Any
    chain: Any


def _card(fp: str, row: dict, options: list[dict]) -> _Card:
    from ..agents.shared.evidence_chain import EvidenceChain, RecommendedAction
    action = RecommendedAction(action_type="escalate", target=f"{row.get('id')} on {row.get('affected_component')}"[:256],
                               reasoning=_summary(row, options), requires_hitl=True, confidence=0.9)
    chain = EvidenceChain(alert_id=f"{ALERT_PREFIX}{fp}", investigated_by="exposure-engine", verdict="suspicious",
                          confidence=0.9)
    chain.metadata["exposure"] = {"fingerprint": fp, "tier": "ACT_NOW", "scan": row.get("scan")}
    return _Card(action, chain)


class _CommitmentRecorder:
    """The ``response_agent`` handed to ``BaseHITL.sync``: an approval records a commitment, never a change."""

    def approve(self, action: Any, *, approver: str = "", source_alert_id: str = "") -> dict:
        return {"recorded": True, "applied": False, "approver": approver, "alert_id": source_alert_id,
                "note": "remediation approved; the owning team applies it — the next run verifies"}


# ---- the lifecycle --------------------------------------------------------------------------------

def load(store: Path) -> dict[str, dict]:
    try:
        data = json.loads((store / "proposals.json").read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def _event(p: dict, now: datetime, status: str, note: str = "") -> None:
    if p.get("status") != status:
        p.setdefault("history", []).append({"at": _iso(now), "status": status, **({"note": note} if note else {})})
    p["status"] = status
    p["updated_at"] = _iso(now)


def reconcile(store: Path, record: dict, *, hitl: Any = None, now: datetime | None = None,
              tiers: tuple[str, ...] = ("ACT_NOW",)) -> dict:
    """Bring every proposal up to date with this run, file new ones, pull decisions, verify closure.

    ``record`` is the runner's run record (open / resolved / waived rows). Returns the remediation section
    that goes into the record; ``proposals.json`` is written by the caller with ``save``."""
    now = now or datetime.now(UTC)
    props = load(store)
    open_rows = {r["fingerprint"]: r for r in record.get("open", []) if r.get("scanner") == "exposure" and r.get("extra")}
    resolved = {r["fingerprint"] for r in record.get("resolved", [])}
    waived = {w["fingerprint"] for w in record.get("waived", [])}
    notes: list[str] = []

    # 1) new proposals for findings in the proposal tiers
    for fp, row in open_rows.items():
        if row["extra"].get("tier") not in tiers or row.get("stale"):
            continue
        p = props.get(fp)
        if p and p.get("status") in OPEN_STATES:
            continue
        if p and p.get("status") in ("rejected", "expired") and row["extra"].get("tier") in tiers:
            # a rejected proposal is not re-filed every run; a new decision needs a new proposal id
            continue
        options = build_options(row)
        props[fp] = p = {"fingerprint": fp, "id": row.get("id"), "asset": row.get("resource"),
                         "component": row.get("affected_component"), "scan": row.get("scan"),
                         "title": (row.get("extra") or {}).get("title"), "created_at": _iso(now),
                         "options": options, "approval_id": None, "transport": None, "history": []}
        _event(p, now, "proposed")

    # 2) file proposals that have no card yet
    if hitl is not None:
        for fp, p in props.items():
            if p.get("status") != "proposed" or fp not in open_rows:
                continue
            card = _card(fp, open_rows[fp], p["options"])
            try:
                aid = hitl.request(card.action, card.chain)
            except Exception as e:  # noqa: BLE001 — a channel outage leaves the proposal visible and retried next run
                aid = None
                notes.append(f"could not file remediation proposal for {p['id']} on {p['component']}: {str(e)[:120]}")
            if aid:
                p["approval_id"], p["transport"] = aid, getattr(hitl, "name", "hitl")
                _event(p, now, "awaiting_approval", f"filed to {p['transport']} as {aid}")

        # 3) decisions
        by_aid = {p["approval_id"]: p for p in props.values() if p.get("approval_id")}
        try:
            decisions = hitl.sync(_CommitmentRecorder())
        except Exception as e:  # noqa: BLE001
            decisions = []
            notes.append(f"could not read remediation decisions: {str(e)[:120]}")
        for d in decisions:
            p = by_aid.get(d.approval_id)
            if p is None:
                continue
            p["decided_by"], p["decided_at"] = d.decided_by, _iso(now)
            if d.status == "approved":
                p["approved_at"] = _iso(now)
                _event(p, now, "approved", f"approved by {d.decided_by or '?'}")
            else:
                _event(p, now, d.status, d.reason or "")

    # 4) verification against this run
    for fp, p in props.items():
        st = p.get("status")
        if st not in OPEN_STATES:
            continue
        row = open_rows.get(fp)
        if fp in waived:
            _event(p, now, "accepted_risk", "the finding was waived in the risk register")
            continue
        if row is not None and row.get("stale"):
            p["verification"] = "not re-tested: the scan failed this run"
            continue
        if row is None or row["extra"].get("tier") not in tiers:
            if fp in resolved or row is None:
                why = "The scanner no longer reports it on this asset (patched or removed)"
            else:
                x = row["extra"]
                why = (f"Now in {x['tier'].replace('_', ' ').title().replace('Act Now', 'Act now')}: " +
                       (x["reasons"][2] if x.get("defended") != "none" else x["reasons"][1]))
            p["verification"] = why
            _event(p, now, "verified_closed" if st in ("approved", "approved_still_open") else "closed_before_decision", why)
            p["closed_at"] = _iso(now)
            continue
        if st == "approved" and p.get("approved_at") == _iso(now):
            p["verification"] = "approved this run; the path is re-tested on the next run"
            continue
        if st in ("approved", "approved_still_open"):
            days = (now - _parse(p.get("approved_at") or p["updated_at"])).days
            p["verification"] = (f"approved {days} day(s) ago but the path is still open: "
                                 + row["extra"]["reasons"][1])
            _event(p, now, "approved_still_open")
        else:
            p["verification"] = None

    rows = sorted(props.values(), key=lambda p: (p.get("status") not in OPEN_STATES, p.get("created_at", "")))
    counts: dict[str, int] = {}
    for p in rows:
        counts[p["status"]] = counts.get(p["status"], 0) + 1
    return {"proposals": rows, "counts": counts, "notes": notes, "channel": getattr(hitl, "name", None)}


def save(store: Path, section: dict) -> None:
    props = {p["fingerprint"]: p for p in section.get("proposals", [])}
    tmp = store / "proposals.json.tmp"
    store.mkdir(parents=True, exist_ok=True)
    tmp.write_text(json.dumps(props, indent=1), encoding="utf-8")
    tmp.replace(store / "proposals.json")


def markdown(section: dict) -> list[str]:
    rows = section.get("proposals") or []
    if not rows:
        return []
    label = {"proposed": "proposed (no approval channel)", "awaiting_approval": "awaiting approval",
             "approved": "approved — re-test next run", "approved_still_open": "APPROVED, STILL OPEN",
             "verified_closed": "verified closed", "closed_before_decision": "closed before a decision",
             "rejected": "rejected", "expired": "expired", "accepted_risk": "accepted risk"}
    L = ["", "## Remediation proposals (ACT NOW)", "",
         "| Finding | Asset | Status | Verification |", "|---|---|---|---|"]
    for p in rows:
        L.append(f"| {p['id']} | {p.get('component', '')} | {label.get(p['status'], p['status'])} | "
                 f"{(p.get('verification') or '').replace('|', '/')} |")
    return L
