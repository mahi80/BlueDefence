"""End-to-end walking skeleton — full AEGIS architecture demo.

Phases:
  A. Stream sample alerts -> Orchestrator -> specialist -> Response agent
     (HITL gates printed; auto-safe actions executed)
  B. Vulnerability Discovery scan -> Patch pipeline
  C. Moving Target Defense step
  D. High-confidence chains -> CERT-In draft + FS-ISAC IOC push
  E. Audit log integrity verify

Run:
    pip install -r aegis/requirements.txt
    python -m aegis.main

ANTHROPIC_API_KEY (optional) switches LLMClient to real Claude;
otherwise the deterministic MockClient runs the demo offline.

RL training pipeline is separate:
    pip install -r aegis/requirements-rl.txt
    python -m aegis.rl.train --steps 50000
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

# Force UTF-8 stdout on Windows consoles that default to cp1252.
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from aegis.agents.patch.agent import PatchAgent
from aegis.agents.response.connectors import registry_from_env
from aegis.agents.response.receipts import receipt_log_from_env
from aegis.agents.shared.llm_client import get_client
from aegis.agents.vuln_discovery.agent import VulnDiscoveryAgent
from aegis.infra.servicenow_writer import write_ticket
from aegis.infra.siem_source import iter_sample_alerts
from aegis.infra.slack_notifier import notify
from aegis.intel import certin, fs_isac
from aegis.mtd.policy import Asset, MTDController
from aegis.service import build_pipeline

__all__ = ["main", "receipt_log_from_env", "registry_from_env"]  # wiring names tests import from here


def _section(title: str) -> None:
    print(f"\n\n{'#' * 76}\n# {title}\n{'#' * 76}")


def _alert_source():
    """Alert sources from env (roadmap 0.5).

    AEGIS_SOURCES=sample,splunk,sentinel,waf picks the consumers
    (aegis.ingest.sources_from_env); the legacy SPLUNK_URL switch still
    selects Splunk alone. Default: the in-memory sample stream.
    """
    if os.environ.get("AEGIS_SOURCES"):
        from aegis.ingest import sources_from_env
        sources = sources_from_env()
        print("  sources=" + ", ".join(name for name, _ in sources))
        return (alert for _, it in sources for alert in it)
    if os.environ.get("SPLUNK_URL"):
        from aegis.infra.splunk_source import SplunkConfig, SplunkConsumer
        cfg = SplunkConfig.from_env()
        consumer = SplunkConsumer(cfg)
        search = os.environ.get(
            "AEGIS_SPLUNK_SEARCH",
            'search index=aegis_security sourcetype=aegis:notable',
        )
        print(f"  source=splunk url={cfg.base_url} search={search!r}")
        return consumer.iter_alerts(search=search)
    print("  source=in-memory (set AEGIS_SOURCES=sample,sentinel,waf or SPLUNK_URL)")
    return iter_sample_alerts()


def _phase_alerts(orch, response):
    _section("Phase A — alert stream through orchestrator + response")
    chains = []
    for alert in _alert_source():
        chain = orch.handle(alert)
        write_ticket(chain)
        notify(chain)
        summary = response.execute(chain)
        print(
            f"  Response: executed={len(summary.executed)}  hitl_queued={len(summary.hitl_queue)}"
        )
        chains.append(chain)
    return chains


def _phase_vuln_patch():
    _section("Phase B — Vulnerability Discovery + Patch pipeline")
    vuln = VulnDiscoveryAgent(llm=get_client())
    patch = PatchAgent()
    scope = {
        "scan_id": "VULN-SCAN-DEMO",
        "dependency_manifest": {
            "litellm": "1.82.7",          # caught CVE
            "openssl": "1.1.1k",          # caught CVE
            "fastapi": "0.110.0",         # clean
        },
        "configs": [{
            "service": "core-api",
            "debug_endpoint_exposed": True,
            "tls_min_version": "TLS1.0",
            "iam_role_permissions": ["s3:Get*", "*:*"],
            "iam_role_name": "core-api-role",
        }],
        "code_paths": [{
            "path": "src/handlers/profile.py",
            "snippet": "user_id = request.args.get('user_id')\nreturn db.query(User, user_id)",
        }, {
            "path": "src/legacy/admin.py",
            "snippet": "api_key = \"ak_live_4F2X9Q8N\"",
        }],
        "supply_chain_events": [{
            "package": "shiny-new-thing",
            "publish_age_seconds": 240,
            "major_version_bump": True,
        }],
    }
    chain, findings = vuln.scan(scope)
    write_ticket(chain)
    print(f"\n  Vuln Discovery found {len(findings)} issues; running Patch pipeline...")
    for f in findings:
        plan = patch.run_pipeline(f, hitl_approver="soc-lead@bank")
        print(
            f"  PATCH {plan.finding_id}: stage={plan.stage} "
            f"({len(plan.history)} steps)  proposal={plan.proposal[:80]}..."
        )
    return chain


def _phase_mtd():
    _section("Phase C — Moving Target Defense step")
    mtd = MTDController()
    mtd.register(Asset(id="api-svc-1", kind="service",
                       current_coords={"ip": "10.1.2.30", "port": 8080}))
    mtd.register(Asset(id="cache-svc-1", kind="service",
                       current_coords={"ip": "10.1.2.45", "port": 6379}))
    mtd.register(Asset(id="decoy-admin", kind="decoy",
                       current_coords={"path": "/admin-internal-debug"}))
    mtd.register(Asset(id="pci-billing", kind="service",
                       current_coords={"ip": "10.9.9.10", "port": 8443},
                       in_compliance_scope=True))   # safety: never auto-rotate

    obs = {"recon_intensity": 0.7, "suspicious_alert_count_5min": 2,
           "days_since_last_rotation": 14, "current_load_pct": 35}
    actions = mtd.step(obs)
    print(f"  Observation: {obs}")
    print(f"  Approved {len(actions)} rotations:")
    for a in actions:
        print(f"    {a.asset_id} -> {a.new_coords}  ({a.reason})")
    print("  Note: pci-billing rotated by SAC -> blocked by compliance-scope safety constraint.")


def _phase_intel(chains):
    _section("Phase D — CERT-In + FS-ISAC sharing")
    high_conf = [c for c in chains if c.verdict == "malicious" and c.confidence >= 0.85]
    print(f"  {len(high_conf)} high-confidence chain(s) eligible for sharing")
    for chain in high_conf:
        certin.submit(chain)
    fs_isac.push(high_conf)


def _phase_audit(audit, audit_path):
    from aegis.agents.shared import observability as obs

    _section("Phase E — audit log + observability")
    integrity_ok = audit.verify()
    obs.record_audit_integrity(integrity_ok)
    print(f"  Path:      {audit_path}")
    print(f"  Integrity: {'PASS' if integrity_ok else 'FAIL'}")
    print()
    obs.dump_summary(stream=__import__('sys').stdout)


def main() -> int:
    audit_path = Path(__file__).parent / "_audit_log.jsonl"
    # One wiring for the demo and the long-running service (aegis.service):
    # specialists → orchestrator (→ swarm) → response, governance, HITL, sinks.
    # fresh=True: the demo starts from an empty audit log; the service never truncates.
    p = build_pipeline(audit_path, fresh=True, include_mock_intel=True)
    orch, response, audit = p.orch, p.response, p.audit
    receipt_log, connectors, persist_sink, governed = p.receipt_log, p.connectors, p.persist_sink, p.governed
    if p.rules_report is not None:
        r = p.rules_report
        print(f"  Rule feed {r.version}: {len(r.applied)} applied, {len(r.already)} already, {len(r.rejected)} rejected")
        for rid, why in r.rejected:
            print(f"    rejected {rid}: {why}")
    swarm_on = p.swarm_on

    print(f"AEGIS walking skeleton (full) — LLM backend: {p.primary_name} ({p.primary_model})"
          + (f" — governed by ACP as {governed.agent_code}" if governed else "")
          + (f" — swarm on ({orch.max_workers} workers, {orch.max_seconds:.0f}s cap)" if swarm_on else ""))

    chains = _phase_alerts(orch, response)
    if swarm_on and orch.runs:
        ms = [r["elapsed_ms"] for r in orch.runs]
        print(f"  Swarm: {len(orch.runs)} fan-outs, +{sum(r['evidence_added'] for r in orch.runs)} evidence, "
              f"median {sorted(ms)[len(ms) // 2]} ms, max {max(ms)} ms")
    decisions = response.sync_hitl()
    if decisions:
        print(f"  HITL decisions from dashboard: {len(decisions)} "
              f"({sum(1 for d in decisions if d.status == 'approved')} approved)")
    _phase_vuln_patch()
    _phase_mtd()
    _phase_intel(chains)
    _phase_audit(audit, audit_path)
    if receipt_log is not None:
        print(f"  Receipts:  {receipt_log.path} ({receipt_log.events} events, connectors in "
              f"{connectors.mode} mode) — compare with analyst decisions: python -m aegis.shadow report "
              + ("--dashboard" if persist_sink is not None else f"--receipts {receipt_log.path} --audit {audit_path}"))
    if persist_sink is not None:
        persist_sink.flush()
        print(f"  Persisted to dashboard: {persist_sink.shipped} items (chains + receipts) "
              f"({persist_sink.failed} failed, {persist_sink.dropped} dropped)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
