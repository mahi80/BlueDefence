"""End-to-end Splunk-mode demo.

Stands up the mock Splunk server in-process, seeds it with the AEGIS
sample alerts, then runs the same orchestrator-driven pipeline as
`python -m aegis.main` but consuming from Splunk REST instead of the
in-memory list.

This is the integration test for the Splunk consumer. Production
deployment swaps the mock server for real Splunk by setting
SPLUNK_URL + SPLUNK_TOKEN — the consumer code does not change.

Run:
  python -m aegis.infra.splunk_demo
"""
from __future__ import annotations

import logging
import sys
from pathlib import Path

# Force UTF-8 stdout on Windows consoles
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from aegis.agents.auth.agent import AuthAgent
from aegis.agents.deception.honeytoken_monitor import HoneytokenMonitor
from aegis.agents.edr.agent import EDRAgent
from aegis.agents.orchestrator.agent import SOCOrchestrator
from aegis.agents.perimeter.agent import PerimeterAgent
from aegis.agents.response.agent import ResponseAgent
from aegis.agents.shared.audit import AuditLog
from aegis.agents.shared.llm_client import get_client
from aegis.healing.pipeline import SelfHealingPipeline
from aegis.infra.mock_splunk_server import MockSplunkd
from aegis.infra.seed_splunk import seed
from aegis.infra.servicenow_writer import write_ticket
from aegis.infra.slack_notifier import notify
from aegis.infra.splunk_source import SplunkConfig, SplunkConsumer


def _build_orchestrator(audit_path: Path) -> tuple[SOCOrchestrator, ResponseAgent]:
    primary = get_client()
    voter = get_client()
    perimeter = PerimeterAgent(llm=primary)
    auth = AuthAgent(llm=primary)
    edr = EDRAgent(llm=primary)
    honeytoken = HoneytokenMonitor()
    audit = AuditLog(audit_path)
    self_healing = SelfHealingPipeline()
    from aegis.hitl import hitl_from_env
    response = ResponseAgent(self_healing=self_healing, hitl=hitl_from_env())
    orch = SOCOrchestrator(
        primary_llm=primary, voter_llm=voter,
        perimeter=perimeter, auth=auth, edr=edr,
        honeytoken=honeytoken, audit=audit,
    )
    return orch, response


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    audit_path = Path(__file__).parent.parent / "_audit_log.jsonl"
    if audit_path.exists():
        audit_path.unlink()

    # 1. Start mock Splunk
    splunk = MockSplunkd(port=0)   # ephemeral port to avoid collisions
    splunk.start()
    print(f"\n[demo] Mock Splunk up at {splunk.url}")

    # 2. Seed it
    n_seeded = seed(splunk.url, token="mock-hec-token-demo")
    print(f"[demo] Seeded {n_seeded} events into Splunk")

    # 3. Build orchestrator
    orch, response = _build_orchestrator(audit_path)
    primary = orch._primary  # for the model-name banner only
    print(f"[demo] Orchestrator ready  (LLM backend: {primary.name} / {primary.model})")

    # 4. Consume from Splunk
    cfg = SplunkConfig(base_url=splunk.url, token="mock-bearer-demo", verify_tls=False)
    consumer = SplunkConsumer(cfg)

    print("\n[demo] Consuming alerts from Splunk REST export endpoint...\n")
    seen = 0
    for alert in consumer.iter_alerts(
        search='search index=aegis_security sourcetype=aegis:notable',
        earliest_time="-1h",
        latest_time="now",
    ):
        chain = orch.handle(alert)
        write_ticket(chain)
        notify(chain)
        summary = response.execute(chain)
        print(f"  [splunk-demo] response: executed={len(summary.executed)}  hitl_queued={len(summary.hitl_queue)}")
        seen += 1

    print(f"\n[demo] Processed {seen} Splunk-sourced alerts")
    print(f"[demo] Audit log:    {audit_path}")
    # The Audit object inside orch can verify integrity; cheaper to just tail-verify here
    from aegis.agents.shared.audit import AuditLog as _AL
    print(f"[demo] Audit verify: {'PASS' if _AL(audit_path).verify() else 'FAIL'}")

    splunk.stop()
    return 0 if seen == n_seeded else 1


if __name__ == "__main__":
    sys.exit(main())
