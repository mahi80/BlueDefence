"""InventorySource — a real TelemetrySource backed by an estate export, the swappable sibling of
MockTenant. Tests confirm it answers the walker contract from the estate file, honours executed
containment, is selected by env, and that the walkers reach a crown-jewel asset over it."""

from __future__ import annotations

from pathlib import Path

import pytest

from aegis.agents.orchestrator.walkers.sources import InventorySource, MockTenant, tenant_from_env
from aegis.agents.orchestrator.walkers.walk import run_walkers

FIXTURE = Path(__file__).resolve().parents[2] / "aegis" / "ingest" / "fixtures" / "estate.sample.json"


def test_inventory_answers_the_contract_from_the_estate():
    src = InventorySource(str(FIXTURE))
    assert src.name == "inventory"
    lat = src.lateral_from("host-ws-14", 120)
    assert [e.b for e in lat] == ["SRV-finance-02"] and lat[0].b_type == "server"
    assert [e.b for e in src.sessions_for_user("u-alice", 120)] == ["sess-9001"]
    assert [e.b for e in src.groups_and_roles("u-alice")] == ["role-cloud-admin"]
    assert [e.b for e in src.resources_touched("svc-deploy", 120)] == ["bucket-kyc"]
    assert [e.b for e in src.beneficiaries("acct-1000", 120)] == ["mule-77"]
    assert src.flows_from("no-such-host", 120) == []            # unknown subject → no edges


def test_accepts_a_parsed_dict_and_honours_containment():
    doc = {"edges": [
        {"a": "h1", "relation": "lateral_to", "b": "SRV-9", "b_type": "server"},
        {"a": "h1", "relation": "connected_to", "b": "cbs", "b_type": "core_banking_db"},
    ]}
    src = InventorySource(doc)
    assert len(src.lateral_from("h1", 120)) == 1 and len(src.flows_from("h1", 120)) == 1
    src.mark_contained("isolate", "h1")                          # executed containment severs h1's edges
    assert src.lateral_from("h1", 120) == [] and src.flows_from("h1", 120) == []


def test_malformed_rows_are_skipped_not_fatal():
    src = InventorySource({"edges": [{"a": "h1", "relation": "lateral_to"},          # missing b
                                     {"a": "h1", "relation": "lateral_to", "b": "SRV-9", "b_type": "server"}]})
    assert [e.b for e in src.lateral_from("h1", 120)] == ["SRV-9"]


def test_tenant_from_env_selects_the_source(monkeypatch):
    for k in ("AEGIS_TENANT", "AEGIS_TENANT_FILE", "AEGIS_MOCK_SPREAD"):
        monkeypatch.delenv(k, raising=False)
    assert isinstance(tenant_from_env(), MockTenant)             # default is unchanged
    monkeypatch.setenv("AEGIS_TENANT", "inventory")
    with pytest.raises(ValueError):
        tenant_from_env()                                        # inventory needs a file
    monkeypatch.setenv("AEGIS_TENANT_FILE", str(FIXTURE))
    src = tenant_from_env()
    assert src.name == "inventory"
    assert [e.b for e in src.lateral_from("host-ws-14", 120)] == ["SRV-finance-02"]


def test_walkers_reach_a_crown_jewel_over_the_real_estate():
    src = InventorySource(str(FIXTURE))
    report = run_walkers({"id": "a1", "host": "host-ws-14", "user_id": "u-alice"}, src, max_seconds=5.0)
    reached = {n.id for n in report.graph.nodes.values()}
    assert "host-ws-14" in reached                               # seeded and expanded
    crit = [n for n in report.graph.nodes.values() if n.critical]
    assert crit, "walk reached no critical asset over the estate"
    assert any(n.id in ("cbs-db-01", "DC-01") for n in crit)     # core-banking DB / domain controller
