"""Editions — the one switch that separates the external SOC from the internal agent governance.

    AEGIS_EDITION=external   the SOC agent only: the bank's SIEM/WAF/EDR feeds in, WAF/SOAR connectors out,
                             approvals via ServiceNow or a file queue, local hash-chained audit. **No ACP
                             dashboard, no acp-sdk, nothing of ours in the customer's code.**
    AEGIS_EDITION=soc        external + the ACP dashboard in SOC mode (cards, chains, receipts, shadow report,
                             retrain loop). Still no SDK in the customer's agents.
    AEGIS_EDITION=full       everything: the SOC brain is itself a governed ACP agent, Q ↔ AEGIS bridge on,
                             live intel published to the agent threat-impact scan.

Default: ``external`` (standalone — the SOC console talks to this host's own API: chains from the local
audit log, approvals through the local queue). A host with ``ACP_DASHBOARD_URL`` set and no
``AEGIS_EDITION`` keeps ``full``, so existing integrated installs are unchanged.

``apply_edition()`` runs first in ``build_pipeline``: it fills in the edition's defaults for anything
unset, and **refuses** configuration that contradicts the edition — an "external" deployment that
points at a dashboard or asks for governance is a packaging mistake and fails fast with the exact
variable named, rather than quietly running the wrong product.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from typing import Mapping, MutableMapping

_log = logging.getLogger("aegis.edition")

EDITIONS = ("external", "soc", "full")

_ON = {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Edition:
    name: str
    governed_brain: bool            # SOC brain runs under ACPGuard (needs acp-sdk)
    dashboard: bool                 # ACP dashboard reachable (HITL cards, persistence, rule feed, promotion queue)
    bridge: bool                    # Q ↔ AEGIS: consume governance events, publish intel to the threat-impact scan
    hitl_default: str               # transport when AEGIS_HITL_TRANSPORT is unset
    defaults: Mapping[str, str] = field(default_factory=dict)
    forbidden: Mapping[str, str] = field(default_factory=dict)   # var → why it contradicts the edition

    def describe(self) -> str:
        return (f"edition={self.name} (governed brain {'on' if self.governed_brain else 'off'}, dashboard {'on' if self.dashboard else 'off'}, "
                f"bridge {'on' if self.bridge else 'off'})")


_EXTERNAL = Edition(
    "external", governed_brain=False, dashboard=False, bridge=False, hitl_default="file",
    defaults={"ACP_GOVERN": "0", "AEGIS_PERSIST": "0", "AEGIS_RULE_FEED": "0",
              "AEGIS_ENFORCEMENT_MODE": "shadow", "AEGIS_RECEIPTS": "1", "AEGIS_DATASET_CAPTURE": "1"},
    # AEGIS_MODEL_POINTER is allowed here: it is how signed model releases from the BlueDefence licence
    # service (aegis.model_updates) take effect in an installation that has no dashboard.
    forbidden={"ACP_DASHBOARD_URL": "the external edition has no ACP dashboard — use AEGIS_EDITION=soc for the console",
               "ACP_GOVERN": "the external edition does not run acp-sdk — the SOC brain is ungoverned by design"},
)
_SOC = Edition(
    "soc", governed_brain=False, dashboard=True, bridge=False, hitl_default="dashboard",
    defaults={"ACP_GOVERN": "0", "AEGIS_PERSIST": "1", "AEGIS_RULE_FEED": "1",
              "AEGIS_ENFORCEMENT_MODE": "shadow", "AEGIS_RECEIPTS": "1", "AEGIS_DATASET_CAPTURE": "1"},
    forbidden={"ACP_GOVERN": "governing the SOC brain needs the full edition (acp-sdk + Q)"},
)
_FULL = Edition(
    "full", governed_brain=True, dashboard=True, bridge=True, hitl_default="dashboard",
    defaults={"ACP_GOVERN": "1", "AEGIS_PERSIST": "1", "AEGIS_RULE_FEED": "1",
              "AEGIS_ENFORCEMENT_MODE": "shadow", "AEGIS_RECEIPTS": "1", "AEGIS_DATASET_CAPTURE": "1"},
)
_BY_NAME = {e.name: e for e in (_EXTERNAL, _SOC, _FULL)}


class EditionError(ValueError):
    """Configuration contradicts the chosen edition (named variable, named reason)."""


def default_edition(env: Mapping[str, str]) -> str:
    """BlueDefence is standalone by default: its own console + this host's API, no ACP dashboard
    (``external``). A host that already points at an ACP dashboard (``ACP_DASHBOARD_URL`` set) and names no
    edition keeps the integrated ``full`` behaviour it was installed with."""
    return "full" if str(env.get("ACP_DASHBOARD_URL", "")).strip() else "external"


def current(env: Mapping[str, str] | None = None) -> Edition:
    env = os.environ if env is None else env
    name = str(env.get("AEGIS_EDITION", "")).strip().lower() or default_edition(env)
    if name not in _BY_NAME:
        raise EditionError(f"AEGIS_EDITION={name!r} is not one of {EDITIONS}")
    return _BY_NAME[name]


def validate(env: Mapping[str, str] | None = None) -> list[str]:
    """Contradictions between the edition and the rest of the environment (empty = consistent)."""
    env = os.environ if env is None else env
    ed = current(env)
    problems: list[str] = []
    for var, why in ed.forbidden.items():
        val = str(env.get(var, "")).strip()
        if var == "ACP_GOVERN":
            if val.lower() in _ON:
                problems.append(f"{var}={val}: {why}")
        elif val:
            problems.append(f"{var} is set: {why}")
    if not ed.bridge and "acp" in [s.strip().lower() for s in str(env.get("AEGIS_SOURCES", "")).split(",")]:
        problems.append(f"AEGIS_SOURCES includes 'acp': governance events need the full edition")
    transport = str(env.get("AEGIS_HITL_TRANSPORT", "")).strip().lower()
    if transport == "dashboard" and not ed.dashboard:
        problems.append("AEGIS_HITL_TRANSPORT=dashboard: this edition has no dashboard — use servicenow or file")
    if transport == "servicenow" and not env.get("AEGIS_SERVICENOW_URL"):
        problems.append("AEGIS_HITL_TRANSPORT=servicenow but AEGIS_SERVICENOW_URL is unset")
    return problems


def warnings(env: Mapping[str, str] | None = None) -> list[str]:
    """Degraded-but-allowed states (logged, never refused): a console edition running without its console."""
    env = os.environ if env is None else env
    ed = current(env)
    out: list[str] = []
    if ed.dashboard and not str(env.get("ACP_DASHBOARD_URL", "")).strip():
        out.append(f"edition {ed.name} expects ACP_DASHBOARD_URL — running with the stdout card, no persistence, no rule feed "
                   f"(a dashboard-less deployment should set AEGIS_EDITION=external)")
    return out


def apply_edition(env: MutableMapping[str, str] | None = None, *, strict: bool = True) -> Edition:
    """Fill the edition's defaults for unset variables, then validate. Raises ``EditionError`` when
    ``strict`` and the environment contradicts the edition."""
    env = os.environ if env is None else env
    ed = current(env)
    for k, v in ed.defaults.items():
        if not str(env.get(k, "")).strip():
            env[k] = v
    if not str(env.get("AEGIS_HITL_TRANSPORT", "")).strip():
        env["AEGIS_HITL_TRANSPORT"] = ed.hitl_default
    problems = validate(env)
    if problems and strict:
        raise EditionError("AEGIS_EDITION=" + ed.name + " contradicts the environment:\n  - " + "\n  - ".join(problems))
    for w in warnings(env):
        _log.warning("[edition] %s", w)
    return ed


def feature_matrix() -> list[dict]:
    rows = []
    for e in (_EXTERNAL, _SOC, _FULL):
        rows.append({"edition": e.name, "sdk_in_customer_agents": e.governed_brain, "governed_soc_brain": e.governed_brain,
                     "dashboard": e.dashboard, "hitl": e.hitl_default + ("|servicenow|file" if e.dashboard else "|servicenow"),
                     "bridge_q_to_aegis": e.bridge, "intel_to_threat_impact_scan": e.bridge, "retrain_promotion_queue": e.dashboard,
                     "local_audit_jsonl": True, "connectors_waf_soar": True})
    return rows


__all__ = ["EDITIONS", "Edition", "EditionError", "apply_edition", "current", "feature_matrix", "validate", "warnings"]
