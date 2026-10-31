"""Agent identity manifest — CIEM-shaped self-inventory.

The VentureBeat 2026-04-30 piece on AI-coding-agent exploits made the
diagnosis explicit: "Most CISOs inventory every human identity and
have zero inventory of the AI agents running with equivalent
credentials." This module emits AEGIS' own agent manifest in a form
the bank's CIEM (CyberArk / Delinea / SailPoint / homegrown) can
ingest.

The manifest enumerates every internal agent — its workload identity,
the model family it runs on, the scopes it would hold in production,
the rotation policy, and the HITL gates that govern its actions. It
is generated programmatically from the live code (so it can't drift)
and checked in (so reviewers see changes in PRs).

Two entry points:

  python -m aegis.agents.shared.agent_identity --regenerate
        rewrites aegis/_manifest.json from the current code state

  python -m aegis.agents.shared.agent_identity --verify
        rebuilds the manifest in memory and diffs against the checked-
        in copy; non-zero exit on drift (CI-able)
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class AgentEntry:
    id: str
    module: str                         # dotted Python path
    description: str
    workload_identity: str              # SPIFFE-shaped id
    model_family: str                   # llm backend the agent runs on
    permissions: dict[str, list[str]]   # {"read": [...], "write": [...], "invoke": [...]}
    credentials: dict[str, str]         # {"type":..., "rotation_policy":..., "scope":...}
    hitl_gated_actions: list[str] = field(default_factory=list)
    always_hitl_actions: list[str] = field(default_factory=list)


@dataclass
class Manifest:
    system: str = "AEGIS"
    version: str = "0.1.0"
    generated_at: str = ""
    spec_url: str = (
        "https://github.com/mahi80/rbi/tree/Agentic_Endpoint_AEGIS/aegis"
    )
    agents: list[AgentEntry] = field(default_factory=list)
    high_impact_actions: list[str] = field(default_factory=list)
    audit: dict[str, Any] = field(default_factory=dict)
    privacy: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["agents"] = [asdict(a) for a in self.agents]
        return d

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, sort_keys=False) + "\n"


# ---- Builder ---------------------------------------------------------

_DEFAULT_CRED = {
    "type": "workload_identity",
    "rotation_policy": "JIT 5-minute TTL via Vault/HSM (per project plan)",
    "scope": "scoped per-action via OPA gates",
}


def build_manifest() -> Manifest:
    """Construct the manifest from live code state.

    Authoritative sources:
      - Always-HITL action list -> aegis.agents.response.agent
      - Auto-safe action list   -> aegis.agents.response.agent
      - LLM backend selection   -> aegis.agents.shared.llm_client.get_client
    """
    # Pull the always-HITL list from the response module so the manifest
    # can never drift from the running code.
    from aegis.agents.response import agent as response_mod

    high_impact = sorted(response_mod._ALWAYS_HITL_ACTIONS)  # type: ignore[attr-defined]

    agents = [
        AgentEntry(
            id="soc_orchestrator",
            module="aegis.agents.orchestrator.agent",
            description=(
                "Entry point for every alert. Triages and dispatches to a "
                "specialist; runs multi-agent voting on high-impact verdicts."
            ),
            workload_identity="spiffe://aegis.bank/agents/orchestrator",
            model_family="claude-sonnet-4-6 (primary) + claude-sonnet-4-6 (voter on different family in prod)",
            permissions={
                "read":   ["siem.notable_events", "audit.log", "honeytokens.registry"],
                "write":  ["audit.log", "evidence_chain"],
                "invoke": ["perimeter", "auth", "edr", "deception", "voter_llm"],
            },
            credentials=_DEFAULT_CRED,
            always_hitl_actions=[],
        ),
        AgentEntry(
            id="perimeter",
            module="aegis.agents.perimeter.agent",
            description="Web/L7 specialist — payload decode, IP rep, similar-request retrieval, user baseline.",
            workload_identity="spiffe://aegis.bank/agents/perimeter",
            model_family="claude-sonnet-4-6",
            permissions={
                "read":   ["ip_reputation.*", "similar_incidents.*", "user_baseline.*"],
                "write":  ["evidence_chain"],
                "invoke": [],
            },
            credentials=_DEFAULT_CRED,
        ),
        AgentEntry(
            id="auth",
            module="aegis.agents.auth.agent",
            description="Auth/IAM specialist — impossible travel, device fingerprint, MFA pattern, peer baseline.",
            workload_identity="spiffe://aegis.bank/agents/auth",
            model_family="claude-sonnet-4-6",
            permissions={
                "read":   ["okta.events", "device_fingerprints.*", "peer_baselines.*"],
                "write":  ["evidence_chain"],
                "invoke": [],
            },
            credentials=_DEFAULT_CRED,
        ),
        AgentEntry(
            id="edr",
            module="aegis.agents.edr.agent",
            description="EDR/Host specialist — process tree, lateral movement, IOC match, file integrity.",
            workload_identity="spiffe://aegis.bank/agents/edr",
            model_family="claude-sonnet-4-6",
            permissions={
                "read":   ["edr.detections", "ioc.feed", "file_integrity.baseline"],
                "write":  ["evidence_chain"],
                "invoke": [],
            },
            credentials=_DEFAULT_CRED,
        ),
        AgentEntry(
            id="deception",
            module="aegis.agents.deception.honeytoken_monitor",
            description="Honeytoken / decoy fast-path. Touching a decoy = high-confidence intrusion.",
            workload_identity="spiffe://aegis.bank/agents/deception",
            model_family="(no LLM; deterministic registry match)",
            permissions={
                "read":   ["honeytokens.registry"],
                "write":  ["evidence_chain"],
                "invoke": [],
            },
            credentials={"type": "workload_identity", "rotation_policy": "n/a (no external creds)", "scope": "read-only registry"},
        ),
        AgentEntry(
            id="vuln_discovery",
            module="aegis.agents.vuln_discovery.agent",
            description=(
                "Glasswing-style internal red team. Static scans for dependency CVEs, "
                "config misconfigs, code logic flaws, supply-chain anomalies. "
                "EPSS+KEV+PoC weighted prioritization."
            ),
            workload_identity="spiffe://aegis.bank/agents/vuln_discovery",
            model_family="claude-sonnet-4-6",
            permissions={
                "read":   ["repo.manifests", "repo.configs", "repo.code", "first_org.epss", "cisa.kev"],
                "write":  ["evidence_chain"],
                "invoke": [],
            },
            credentials=_DEFAULT_CRED,
        ),
        AgentEntry(
            id="patch",
            module="aegis.agents.patch.agent",
            description="Finding -> dev -> canary -> HITL -> prod pipeline. HITL gate on prod always.",
            workload_identity="spiffe://aegis.bank/agents/patch",
            model_family="(no LLM; pipeline orchestration)",
            permissions={
                "read":   ["vuln_discovery.findings"],
                "write":  ["build_pipeline.dev", "deploy.canary"],
                "invoke": ["build", "test", "canary_deploy"],
            },
            credentials={"type": "workload_identity", "rotation_policy": "JIT per-deploy", "scope": "scoped to deployment pipeline"},
            always_hitl_actions=["deploy_prod"],
        ),
        AgentEntry(
            id="response",
            module="aegis.agents.response.agent",
            description=(
                "Actuator + HITL gate. Auto-safe actions execute; high-impact "
                "actions queue for human approval. Rate-limited blast cap."
            ),
            workload_identity="spiffe://aegis.bank/agents/response",
            model_family="(no LLM; deterministic policy)",
            permissions={
                "read":   ["evidence_chain"],
                "write":  ["audit.log"],
                "invoke": ["firewall.api", "iam.api", "edr.isolate", "self_healing"],
            },
            credentials={
                "type": "hardware_backed_signing_key",
                "rotation_policy": "HSM-resident; signing operations only",
                "scope": "scoped per action_type via OPA",
            },
            always_hitl_actions=high_impact,
        ),
        AgentEntry(
            id="api_abuse",
            module="aegis.agents.api_abuse.agent",
            description=(
                "API Abuse specialist — BOLA/IDOR, schema drift, volumetric "
                "anomaly, auth-boundary violations. Reasons about authorization "
                "context, which signature defenses miss."
            ),
            workload_identity="spiffe://aegis.bank/agents/api_abuse",
            model_family="claude-sonnet-4-6",
            permissions={
                "read":   ["api_gateway.events", "rbac.policies", "schema_registry.*"],
                "write":  ["evidence_chain"],
                "invoke": [],
            },
            credentials=_DEFAULT_CRED,
        ),
        AgentEntry(
            id="transaction",
            module="aegis.agents.transaction.agent",
            description=(
                "Transaction/Fraud specialist — mule patterns, beneficiary "
                "risk, velocity, payment-rail anomaly, AML structuring. "
                "Indian context (UPI/NEFT/RTGS/IMPS rails, Aadhaar/IFSC "
                "identifiers, RBI Master Direction reporting thresholds)."
            ),
            workload_identity="spiffe://aegis.bank/agents/transaction",
            model_family="claude-sonnet-4-6",
            permissions={
                "read":   ["core_banking.txn_stream", "account_graph", "beneficiary_risk", "rail_baselines.*"],
                "write":  ["evidence_chain"],
                "invoke": [],
            },
            credentials=_DEFAULT_CRED,
        ),
        AgentEntry(
            id="dlp",
            module="aegis.agents.dlp.agent",
            description=(
                "DLP / data-exfiltration specialist — reasons over bulk reads, "
                "sensitive-data egress, external-recipient mail with attachments, "
                "HR-context-aware insider-threat scoring. Covers BOTH compromised-"
                "admin smash-grab AND intentional insider with valid creds."
            ),
            workload_identity="spiffe://aegis.bank/agents/dlp",
            model_family="claude-sonnet-4-6",
            permissions={
                "read": ["dlp.events", "db.audit_stream", "object_storage.access_logs",
                         "email_gateway.attachments", "hr_system.risk_signals"],
                "write": ["evidence_chain"],
                "invoke": [],
            },
            credentials=_DEFAULT_CRED,
        ),
        AgentEntry(
            id="email",
            module="aegis.agents.email.agent",
            description=(
                "Email / phishing specialist — consumes M365 Defender / Mimecast / "
                "Proofpoint detections. Reasons over header-auth fails, display-name "
                "spoof, lookalike domains, attachment risk, body lexical patterns, "
                "and reply-chain anomaly indicating compromised-sender mass-blast."
            ),
            workload_identity="spiffe://aegis.bank/agents/email",
            model_family="claude-sonnet-4-6",
            permissions={
                "read": ["m365.defender", "mimecast.*", "proofpoint.*",
                         "exchange.message_trace"],
                "write": ["evidence_chain"],
                "invoke": [],
            },
            credentials=_DEFAULT_CRED,
        ),
        AgentEntry(
            id="mobile",
            module="aegis.agents.mobile.agent",
            description=(
                "Mobile-app specialist — jailbreak/root, SDK integrity, SSL pinning "
                "bypass, SIM-swap correlation, mobile session anomaly. Catches the "
                "mobile-ATO chain (tampered device + recent SIM swap)."
            ),
            workload_identity="spiffe://aegis.bank/agents/mobile",
            model_family="claude-sonnet-4-6",
            permissions={
                "read": ["mobile_sdk.events", "mno.sim_swap_signals",
                         "mobile_session.*"],
                "write": ["evidence_chain"],
                "invoke": [],
            },
            credentials=_DEFAULT_CRED,
        ),
        AgentEntry(
            id="wireless",
            module="aegis.agents.wireless.agent",
            description=(
                "Wireless specialist — rogue AP detection, evil-twin SSIDs (esp. "
                "PoS-Wi-Fi targeting), deauth bursts, WPA-handshake / PMKID capture, "
                "KRACK indicators. Reads from Aruba ClearPass / Cisco WLC / Meraki / Mist."
            ),
            workload_identity="spiffe://aegis.bank/agents/wireless",
            model_family="claude-sonnet-4-6",
            permissions={
                "read": ["aruba.clearpass", "cisco.wlc", "meraki.*", "mist.*"],
                "write": ["evidence_chain"],
                "invoke": [],
            },
            credentials=_DEFAULT_CRED,
        ),
        AgentEntry(
            id="cloud_controlplane",
            module="aegis.agents.cloud_controlplane.agent",
            description=(
                "Cloud control-plane specialist — reasons about admin actions "
                "in CloudTrail / Azure Activity Logs / GCP Audit / network device "
                "audit (Panorama, Checkpoint, Juniper). Posture-weakening detection: "
                "wildcard IAM, public S3, internet-open NSG, KMS disable, log-disable, "
                "ANY-ANY firewall rules."
            ),
            workload_identity="spiffe://aegis.bank/agents/cloud_controlplane",
            model_family="claude-sonnet-4-6",
            permissions={
                "read":   ["cloudtrail.events", "azure.activity_log", "gcp.audit_log",
                           "panorama.audit_log", "checkpoint.smartconsole_audit",
                           "juniper.space_audit"],
                "write":  ["evidence_chain"],
                "invoke": [],
            },
            credentials=_DEFAULT_CRED,
        ),
        AgentEntry(
            id="threat_intel",
            module="aegis.agents.threat_intel.agent",
            description=(
                "Pull-side IOC service + LLM advisory analyst. Maintains "
                "in-memory IOC store; pulls STIX 2.1 feeds, mock seed, and "
                "CISA KEV; distributes fresh IOCs into perimeter/edr matchers."
            ),
            workload_identity="spiffe://aegis.bank/agents/threat_intel",
            model_family="claude-sonnet-4-6 (advisory analysis only; lookup is no-LLM)",
            permissions={
                "read":   ["external_feeds.stix", "cisa.kev", "fs_isac.shares"],
                "write":  ["perimeter._KNOWN_BAD", "edr._IOC_HASHES", "edr._IOC_DOMAINS", "edr._IOC_IPS"],
                "invoke": [],
            },
            credentials=_DEFAULT_CRED,
        ),
        AgentEntry(
            id="meta_agent",
            module="aegis.meta_agent.main",
            description=(
                "Observes eval failures, proposes heuristic / threshold / "
                "prompt fixes, validates in simulation, queues for HITL. "
                "Never auto-deploys."
            ),
            workload_identity="spiffe://aegis.bank/agents/meta_agent",
            model_family="claude-sonnet-4-6 (or self-hosted Gemma-class)",
            permissions={
                "read":   ["audit.log", "eval.cases", "eval.results"],
                "write":  ["meta_agent._proposals.jsonl"],
                "invoke": [],
            },
            credentials={"type": "workload_identity", "rotation_policy": "JIT", "scope": "read-only on repo, write only to proposals queue"},
            always_hitl_actions=["apply_proposal_to_repo"],
        ),
        AgentEntry(
            id="meta_agent.rl_generator",
            module="aegis.meta_agent.rl_generator.main",
            description=(
                "Gemma-class RL component generator. Proposes RewardSpec / "
                "PPOHyperparams adjustments based on threat patterns. "
                "Schema-bounded values only — never arbitrary code."
            ),
            workload_identity="spiffe://aegis.bank/agents/meta_agent_rl",
            model_family="google/gemma-2-9b-it (self-hosted, on-prem GPU)",
            permissions={
                "read":   ["threat_observations", "current_reward_spec", "current_hyperparameters"],
                "write":  ["meta_agent._proposals.jsonl"],
                "invoke": [],
            },
            credentials={"type": "workload_identity", "rotation_policy": "JIT", "scope": "schema-bounded numeric proposals only"},
            always_hitl_actions=["apply_reward_spec_to_prod", "apply_hyperparams_to_prod"],
        ),
    ]

    # Detect whether PII tokenization is enabled (default ON per plan).
    import os
    pii_active = os.environ.get("AEGIS_PII_TOKENIZATION", "1") != "0"

    return Manifest(
        generated_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        agents=agents,
        high_impact_actions=high_impact,
        audit={
            "log_format": "hash-chained JSONL (SHA-256)",
            "log_path": "aegis/_audit_log.jsonl",
            "tamper_evident": True,
            "retention_years": 7,
            "verifier": "aegis.agents.shared.audit.AuditLog.verify",
        },
        privacy={
            "causal_inference_module": "aegis.agents.shared.causal",
            "causal_networks": ["ato (Account Takeover SCM, 5 nodes)"],
            "observability_module": "aegis.agents.shared.observability",
            "observability_format": "Prometheus exposition + optional OpenTelemetry SDK",
            "pii_tokenization_enabled": pii_active,
            "tokenizer_module": "aegis.agents.shared.pii_tokenizer",
            "wrapper_module": "aegis.agents.shared.pii_tokenizing_client",
            "covered_pii_kinds": [
                "AADHAAR", "PAN_IN", "IFSC", "ACCOUNT",
                "PAN_CC", "EMAIL", "PHONE", "SSN_US",
            ],
            "regulations_addressed": [
                "DPDP Act 2023", "PCI-DSS scope reduction", "RBI Master Direction (data residency)"
            ],
            "production_substitutes": [
                "Vault Transit", "Voltage SecureData", "Protegrity (HSM-backed FPE)"
            ],
        },
    )


# ---- Verify / regenerate --------------------------------------------

_MANIFEST_PATH = Path(__file__).parent.parent.parent / "_manifest.json"


def _load_checked_in() -> dict | None:
    if not _MANIFEST_PATH.exists():
        return None
    return json.loads(_MANIFEST_PATH.read_text(encoding="utf-8"))


def _strip_volatile(d: dict) -> dict:
    """Remove fields that change every run (timestamps) so verify can
    do a stable structural comparison.
    """
    out = dict(d)
    out.pop("generated_at", None)
    return out


def regenerate(out_path: Path = _MANIFEST_PATH) -> Path:
    manifest = build_manifest()
    out_path.write_text(manifest.to_json(), encoding="utf-8")
    return out_path


def verify() -> tuple[bool, str]:
    """Compare live-code-derived manifest vs checked-in copy. Returns
    (ok, message). Stable across runs — timestamps are stripped.
    """
    live = _strip_volatile(build_manifest().to_dict())
    on_disk = _load_checked_in()
    if on_disk is None:
        return False, f"no checked-in manifest at {_MANIFEST_PATH}"
    on_disk_stable = _strip_volatile(on_disk)
    if live == on_disk_stable:
        return True, f"manifest matches live code ({len(live['agents'])} agents)"
    # Compute a small human-readable diff
    diffs = []
    if len(live.get("agents", [])) != len(on_disk_stable.get("agents", [])):
        diffs.append(f"agent count differs: live={len(live['agents'])} disk={len(on_disk_stable['agents'])}")
    live_ids = {a["id"] for a in live.get("agents", [])}
    disk_ids = {a["id"] for a in on_disk_stable.get("agents", [])}
    if live_ids - disk_ids:
        diffs.append(f"agents in live but not on disk: {sorted(live_ids - disk_ids)}")
    if disk_ids - live_ids:
        diffs.append(f"agents on disk but not in live: {sorted(disk_ids - live_ids)}")
    live_hi = sorted(live.get("high_impact_actions", []))
    disk_hi = sorted(on_disk_stable.get("high_impact_actions", []))
    if live_hi != disk_hi:
        diffs.append(f"high_impact_actions differ: live={live_hi} disk={disk_hi}")
    if not diffs:
        diffs = ["structural drift in agent details"]
    return False, "; ".join(diffs)


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--regenerate", action="store_true",
                   help="rewrite the checked-in manifest from live code")
    p.add_argument("--verify", action="store_true",
                   help="diff live code vs checked-in manifest (default)")
    args = p.parse_args()

    if args.regenerate:
        path = regenerate()
        print(f"manifest regenerated -> {path}")
        return 0

    ok, msg = verify()
    print(f"agent identity manifest: {'OK' if ok else 'DRIFT'}  {msg}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
