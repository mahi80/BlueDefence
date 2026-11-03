"""Round-3 review, group G7 (high items): specialist detectors."""

from __future__ import annotations

import json

import pytest

from aegis.agents.api_abuse.object_walk import ObjectWalkDetector, objects_in
from aegis.agents.cloud_controlplane.tools import (
    iam_change_check,
    k8s_audit_check,
    logging_disable_check,
    network_change_check,
    resource_burst_check,
)
from aegis.agents.threat_intel.store import IOC, LLM_TAG, IOCStore
from aegis.ingest.apigw import normalize

# ---- G7-1: an APIM subscription is an app, not a person -----------------------------------------------------------


def test_apim_subscription_is_not_the_principal():
    rec = {"category": "GatewayLogs", "properties": {"apimSubscriptionId": "mobile-app", "callerIpAddress": "203.0.113.9",
                                                       "method": "GET", "url": "/accounts/1002", "responseCode": 200}}
    ev = normalize(rec)
    assert not ev.get("principal") and ev.get("subscription") == "mobile-app"


def test_customers_of_one_app_are_not_one_walker():
    det = ObjectWalkDetector(distinct_min=5)
    out = [det.observe({"principal": "", "client_ip": f"198.51.100.{i}", "path": f"/accounts/{1000 + i}", "status": 200,
                        "ts": 1000.0 + i}) for i in range(20)]
    assert not any(out)                                    # 20 customers, one account each


# ---- G7-2: object-walk spellings and UA rotation ------------------------------------------------------------------

@pytest.mark.parametrize("path", ["/accounts/1002;x=1", "/accounts/1002.json", "/accounts/%31%30%30%32", "/accounts/%25310%2530%2532"])
def test_one_object_one_template(path):
    tmpl, objs = objects_in(path)
    assert tmpl == "/accounts/{id}" and objs[-1] == ("account", "1002")


def test_rotating_user_agent_does_not_reset_an_anonymous_walk():
    det = ObjectWalkDetector(distinct_min=8)
    hits = [det.observe({"client_ip": "203.0.113.5", "user_agent": f"ua-{i}", "path": f"/accounts/{5000 + i}",
                         "status": 404 if i % 2 else 200, "ts": 1000.0 + i}) for i in range(30)]
    assert any(hits)


# ---- G7-3: IOC lookups and shared infrastructure ------------------------------------------------------------------

def test_llm_extracted_iocs_are_not_returned_by_lookup(monkeypatch):
    monkeypatch.delenv("AEGIS_TI_MERGE_LLM_IOCS", raising=False)
    s = IOCStore()
    assert s.add(IOC(kind="domain", value="payroll-update.example", source="advisory", tags=(LLM_TAG,)))
    assert s.lookup("payroll-update.example", "domain") is None
    assert s.lookup("payroll-update.example", "domain", include_llm=True) is not None


@pytest.mark.parametrize("kind,value", [("domain", "co.in"), ("domain", "amazonaws.com"), ("ip", "8.8.8.8"),
                                        ("domain", "github.com")])
def test_shared_infrastructure_is_never_an_ioc(kind, value):
    assert IOCStore().add(IOC(kind=kind, value=value, source="feed")) is False


def test_a_host_under_a_provider_is_still_an_ioc():
    assert IOCStore().add(IOC(kind="domain", value="evil-bucket.s3.amazonaws.com", source="feed")) is True


# ---- G7-4: security-group and NSG shapes --------------------------------------------------------------------------

def test_cloudtrail_items_shape_ssh_to_the_world_is_high():
    ev = {"eventName": "AuthorizeSecurityGroupIngress", "requestParameters": {"ipPermissions": {"items": [
        {"ipProtocol": "tcp", "fromPort": 22, "toPort": 22, "ipRanges": {"items": [{"cidrIp": "0.0.0.0/0"}]}}]}}}
    assert network_change_check(ev).weight == "high"


def test_all_ports_rule_covers_sensitive_ports():
    ev = {"eventName": "AuthorizeSecurityGroupIngress", "requestParameters": {"ipPermissions": {"items": [
        {"ipProtocol": "-1", "ipv6Ranges": {"items": [{"cidrIpv6": "::/0"}]}}]}}}
    assert network_change_check(ev).weight == "high"


@pytest.mark.parametrize("src", ["*", "Any", "Internet"])
def test_azure_any_source_and_port_range(src):
    ev = {"operationName": "Microsoft.Network/networkSecurityGroups/securityRules/write",
          "properties": {"sourceAddressPrefix": src, "destinationPortRange": "3380-3390", "direction": "Inbound", "access": "Allow"}}
    assert network_change_check(ev).weight == "high"


def test_a_closed_port_range_from_a_known_range_is_low():
    ev = {"eventName": "AuthorizeSecurityGroupIngress", "requestParameters": {"ipPermissions": {"items": [
        {"ipProtocol": "tcp", "fromPort": 443, "toPort": 443, "ipRanges": {"items": [{"cidrIp": "10.20.0.0/16"}]}}]}}}
    assert network_change_check(ev).weight == "low"


# ---- G7-5: operation names --------------------------------------------------------------------------------------------

def test_upper_case_azure_role_grant_with_the_id_in_requestbody():
    body = json.dumps({"properties": {"principalId": "p1", "roleDefinitionId":
                       "/subscriptions/s/providers/Microsoft.Authorization/roleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635"}})
    ev = {"operationName": {"value": "MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE", "localizedValue": "Create role assignment"},
          "properties": {"requestbody": body}}
    r = iam_change_check(ev)
    assert r.data["has_dangerous_role_grant"] is True


def test_dict_operation_name_does_not_crash_any_tool():
    ev = {"operationName": {"value": "Microsoft.Compute/virtualMachines/write"}, "recent_creates_5min": 60}
    assert resource_burst_check(ev).weight == "high"
    assert logging_disable_check({"operationName": {"value": "microsoft.insights/diagnosticsettings/delete"}}).weight == "high"


# ---- G7-6: more log-disable actions, privileged containers, exec over WebSocket ---------------------------------------

@pytest.mark.parametrize("name", ["DeleteDetector", "StopConfigurationRecorder", "DeleteFlowLogs", "DisableSecurityHub"])
def test_detective_controls_switched_off(name):
    assert logging_disable_check({"eventName": name}).weight == "high"


def test_privileged_container_in_a_deployment():
    ev = {"verb": "create", "objectRef": {"resource": "deployments"}, "requestObject": {"spec": {"template": {"spec": {
        "containers": [{"name": "x", "securityContext": {"privileged": True}}]}}}}}
    assert "privileged" in k8s_audit_check(ev).data["dangerous_pod_features"]


def test_exec_over_websocket_is_exec():
    ev = {"verb": "get", "objectRef": {"resource": "pods", "subresource": "exec"}}
    assert k8s_audit_check(ev).data["exec_or_portforward"] is True
