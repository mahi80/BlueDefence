"""Exposure-engine fixes from the 2026-11-02 code review and the Floci CI run.

The dangerous direction for this engine is a false "isolated": an internet-reachable host scored as if
nothing could reach it. Each test below is one way that used to happen (or one way a broken input used to
look like a clean estate), reproduced and fixed.
"""

from __future__ import annotations

import json
import shutil
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import yaml

from aegis.exposure import assess, loaders, remediation
from aegis.exposure.azure_reach import assets_from_azure, nsg_allowed
from aegis.exposure.engine import Vuln
from aegis.exposure.scan import to_finding
from aegis.posture import cspm, runner
from aegis.posture.sources import PostureSourceError, load_json

S = Path(__file__).resolve().parents[1] / "exposure" / "samples"
R = S / "reach"
T0 = datetime(2026, 11, 2, 9, 0, tzinfo=UTC)


def _sg(gid, *perms):
    return {"GroupId": gid, "GroupName": gid, "VpcId": "vpc-1", "IpPermissions": list(perms)}


def _perm(proto, lo, hi, *, cidr=None, v6=None, groups=()):
    p = {"IpProtocol": proto, "FromPort": lo, "ToPort": hi, "IpRanges": [], "Ipv6Ranges": [], "UserIdGroupPairs": []}
    if cidr:
        p["IpRanges"].append({"CidrIp": cidr})
    if v6:
        p["Ipv6Ranges"].append({"CidrIpv6": v6})
    p["UserIdGroupPairs"] = [{"GroupId": g} for g in groups]
    return p


def _inst(iid, sgs, *, public_ip=None, ipv6=None, private="10.0.1.5", name=None):
    i = {"InstanceId": iid, "State": {"Name": "running"}, "VpcId": "vpc-1", "PrivateIpAddress": private,
         "SecurityGroups": [{"GroupId": g} for g in sgs], "Tags": [{"Key": "Name", "Value": name or iid}]}
    if public_ip:
        i["PublicIpAddress"] = public_ip
    if ipv6:
        i["NetworkInterfaces"] = [{"Ipv6Addresses": [{"Ipv6Address": ipv6}]}]
    return i


def _tiers(bundle, vulns):
    ex, _ = assess(vulns, loaders.assets_from_aws(bundle))
    return {(e.asset_name, e.port): e for e in ex}


def _v(asset, port, cve="CVE-2024-6387"):
    return Vuln(asset=asset, cve=cve, title="t", port=port, kev=True)


# ---- AWS security-group evaluation ---------------------------------------------------------------

def test_icmp_rule_is_not_every_port():
    b = {"security_groups": [_sg("sg-mgmt", _perm("icmp", -1, -1, cidr="0.0.0.0/0"))],
         "instances": [_inst("i-mgmt", ["sg-mgmt"], public_ip="203.0.113.9")]}
    e = _tiers(b, [_v("i-mgmt", 8443)])[("i-mgmt", 8443)]
    assert e.reach != "internet" and e.tier != "ACT_NOW"
    assert not [f for f in cspm.scan(b) if f.id == "CSPM-SG-ALL-PORTS-OPEN"]


def test_world_open_rule_is_open_inside_the_vpc_too():
    b = {"security_groups": [_sg("sg-web", _perm("tcp", 443, 443, cidr="0.0.0.0/0")),
                             _sg("sg-db", _perm("tcp", 6379, 6379, cidr="0.0.0.0/0"))],
         "instances": [_inst("i-web", ["sg-web"], public_ip="203.0.113.10", private="10.0.1.10"),
                       _inst("i-db", ["sg-db"], private="10.0.2.20")]}
    e = _tiers(b, [_v("i-db", 6379, "CVE-2022-0543")])[("i-db", 6379)]
    assert e.reach == "one_hop"                      # was "isolated": a wider rule scored lower than a 10/8 one


def test_ipv6_only_instance_is_internet_facing():
    b = {"security_groups": [_sg("sg-v6", _perm("tcp", 443, 443, v6="::/0"))],
         "instances": [_inst("i-v6", ["sg-v6"], ipv6="2600:1f18::10")]}
    e = _tiers(b, [_v("i-v6", 443, "CVE-2021-44228")])[("i-v6", 443)]
    assert e.reach == "internet"


def test_reused_private_ip_does_not_attach_a_finding_to_the_wrong_host():
    b = {"security_groups": [_sg("sg-dmz", _perm("tcp", 1521, 1521, cidr="0.0.0.0/0")), _sg("sg-cbs")],
         "instances": [_inst("i-dmz", ["sg-dmz"], public_ip="203.0.113.11", private="10.0.1.5"),
                       {**_inst("i-cbs", ["sg-cbs"], private="10.0.1.5"), "VpcId": "vpc-2"}]}
    vuln = Vuln(asset="i-cbs", asset_alt=["10.0.1.5"], cve="CVE-2012-1675", title="t", port=1521, kev=True)
    (e,) = _tiers(b, [vuln]).values()
    assert e.asset == "i-cbs" and e.tier != "ACT_NOW"
    # an IP alone that names two machines identifies neither: round 8 G8-6 scores it on every candidate (fail-closed)
    # and marks each one unverifiable, instead of dropping it (which let remediation call an approved fix verified)
    ex, notes = assess([Vuln(asset="10.0.1.5", cve="CVE-2012-1675", title="t", port=1521, kev=True)],
                       loaders.assets_from_aws(b))
    assert sorted(e.asset for e in ex) == ["i-cbs", "i-dmz"] and all("ambiguous asset" in e.unverifiable for e in ex)
    assert "names several assets" in notes[0]


def test_tenable_record_prefers_the_instance_id_over_the_ip():
    rec = {"asset": {"hostname": "web01", "ipv4": ["10.0.1.5"], "aws_ec2_instance_id": "i-cbs"},
           "plugin": {"id": 1, "name": "x", "cve": ["CVE-2012-1675"]}, "port": {"port": 1521}, "severity": "high"}
    (v,) = loaders._from_tenable(rec)
    assert v.asset == "i-cbs" and v.asset_alt[-1] == "10.0.1.5"


def test_alb_revoke_command_targets_the_listener_port():
    b = load_json(R / "aws_lb_bundle.json")
    ex, _ = assess([Vuln(asset="i-app", cve="CVE-2021-44228", title="log4j", port=8080, kev=True)], loaders.assets_from_aws(b))
    (e,) = ex
    row = {**to_finding(e).as_dict(), "fingerprint": "fp", "scan": "t"}
    cut = next(o for o in remediation.build_options(row) if o["kind"] == "cut_path")
    assert all("--port 443" in c or "FromPort=443" in c for c in cut["commands"])
    assert any("listener port 443" in s for s in cut["steps"])


# ---- Azure NSG evaluation -------------------------------------------------------------------------

def _rule(name, prio, access, port, *, proto="*", src="Internet", dest=None):
    r = {"name": name, "priority": prio, "direction": "Inbound", "access": access, "protocol": proto,
         "sourceAddressPrefix": src, "destinationPortRange": port}
    if dest:
        r["destinationAddressPrefix"] = dest
    return r


def test_icmp_or_udp_deny_does_not_close_tcp():
    nsg = {"securityRules": [_rule("deny-icmp", 100, "Deny", "*", proto="Icmp"),
                             _rule("deny-udp", 110, "Deny", "3389", proto="Udp"),
                             _rule("allow-rdp", 200, "Allow", "3389", proto="Tcp")]}
    assert nsg_allowed(nsg, "internet") == [(3389, 3389)]


def test_udp_allow_does_not_open_tcp():
    assert nsg_allowed({"securityRules": [_rule("dns", 100, "Allow", "53", proto="Udp")]}, "internet") == []


def test_deny_scoped_to_another_vm_does_not_hide_this_one():
    nsg = {"securityRules": [_rule("deny-vm2", 100, "Deny", "3389", dest="10.1.1.20/32"),
                             _rule("allow-rdp", 200, "Allow", "3389")]}
    assert nsg_allowed(nsg, "internet", ["10.1.1.10"]) == [(3389, 3389)]     # vm1 still exposed
    assert nsg_allowed(nsg, "internet", ["10.1.1.20"]) == []                 # vm2 denied
    assert nsg_allowed(nsg, "internet") == [(3389, 3389)]                    # unknown NIC: err toward reachable


def test_world_open_source_includes_the_vnet():
    nsg = {"securityRules": [_rule("allow-22", 100, "Allow", "22", src="0.0.0.0/0"), _rule("deny", 200, "Deny", "*", src="*")]}
    assert (22, 22) in nsg_allowed(nsg, "vnet")


def test_lb_inbound_nat_rule_exposes_the_backend():
    b = load_json(R / "azure_bundle.json")
    lb = b["load_balancers"][0]
    fe = lb["frontendIPConfigurations"][0]["id"]
    nic = next(n for n in b["network_interfaces"] if n["name"] == "nic-web")
    lb["loadBalancingRules"] = []
    lb["inboundNatRules"] = [{"frontendIPConfiguration": {"id": fe}, "frontendPort": 50001, "backendPort": 22,
                              "backendIPConfiguration": {"id": nic["ipConfigurations"][0]["id"]}}]
    for n in b["network_security_groups"]:                    # admit 22 from the internet on both NSGs
        n.setdefault("securityRules", []).insert(0, _rule("ssh", 90, "Allow", "22"))
    for vm in b["virtual_machines"]:
        if vm["name"] == "vm-web":
            vm["publicIps"] = ""                               # reachable only through the NAT rule
    (web,) = [a for a in assets_from_azure(b) if a.name == "vm-web"]
    assert web.public and (22, 22) in web.internet_ports and "NAT rule" in web.internet_via[(22, 22)]


# ---- broken inputs never look like a clean estate -------------------------------------------------

@pytest.fixture
def ws(tmp_path):
    d = tmp_path / "s"
    shutil.copytree(S, d)
    cfg = yaml.safe_load((d / "posture_exposure.yaml").read_text())
    cfg["store"] = str(tmp_path / "store")
    (d / "posture_exposure.yaml").write_text(yaml.safe_dump(cfg))
    return d


def test_empty_vulnerability_export_fails_the_scan_and_carries_findings(ws):
    cfg = runner.load_config(ws / "posture_exposure.yaml")
    r1 = runner.run_once(cfg, now=T0, hitl=None)
    (ws / "tenable_vulns.json").write_text("[]")
    r2 = runner.run_once(cfg, now=T0 + timedelta(days=1), hitl=None)
    assert r2["scans"][0]["status"] == "error" and "no findings" in r2["scans"][0]["error"]
    assert r2["counts"]["resolved"] == 0 and r2["counts"]["open"] == r1["counts"]["open"]
    assert all(o["stale"] for o in r2["open"])
    assert {p["status"] for p in r2["remediation"]["proposals"]} <= {"proposed"}   # nothing "verified closed"


def test_allow_empty_accepts_a_truly_clean_estate(ws):
    cfg = runner.load_config(ws / "posture_exposure.yaml")
    cfg.scans[0].opts["allow_empty"] = True
    (ws / "tenable_vulns.json").write_text("[]")
    assert runner.run_once(cfg, now=T0, hitl=None)["scans"][0]["status"] == "ok"


def test_unread_cspm_section_carries_its_findings_forward(tmp_path):
    bundle = load_json(Path(__file__).resolve().parents[1] / "posture" / "samples" / "aws_cspm_bundle.json")
    bpath = tmp_path / "b.json"
    bpath.write_text(json.dumps(bundle))
    cfg = runner.RunnerConfig(store=tmp_path / "store", scans=[runner.ScanConfig("aws", "cspm", {"bundle": bpath})])
    r1 = runner.run_once(cfg, now=T0)
    sg_before = {o["fingerprint"] for o in r1["open"] if o["id"].startswith("CSPM-SG-")}
    assert sg_before
    del bundle["security_groups"]
    bundle["collection_errors"] = {"security_groups": "AccessDenied: explicit deny in SCP"}
    bpath.write_text(json.dumps(bundle))
    r2 = runner.run_once(cfg, now=T0 + timedelta(days=1))
    sg_after = {o["fingerprint"] for o in r2["open"] if o["id"].startswith("CSPM-SG-")}
    assert sg_after == sg_before and all(o["stale"] for o in r2["open"] if o["fingerprint"] in sg_after)
    assert not [x for x in r2["resolved"] if x["id"].startswith("CSPM-SG-")]


def test_collector_records_an_unreachable_endpoint_instead_of_crashing(monkeypatch):
    from aegis.posture import sources

    class EndpointConnectionError(Exception):
        pass
    EndpointConnectionError.__module__ = "botocore.exceptions"

    class Client:
        def __init__(self, svc):
            self.svc = svc
            self.meta = type("M", (), {"region_name": "ap-south-1"})()

        def get_caller_identity(self):
            return {"Account": "111122223333"}

        def __getattr__(self, name):
            if name.startswith("_"):
                raise AttributeError(name)

            def call(*a, **k):
                raise EndpointConnectionError(f"Could not connect to the endpoint URL for {self.svc}")
            return call

    monkeypatch.setenv("AEGIS_POSTURE_LIVE", "1")
    monkeypatch.setattr(sources, "_boto3_client", lambda svc, **kw: Client(svc))
    b = sources.collect_aws_cspm("ap-south-1")
    assert b["account_id"] == "111122223333"
    assert b["collection_errors"] and all("EndpointConnectionError" in v for v in b["collection_errors"].values())


def test_csv_without_asset_column_is_refused(tmp_path):
    p = tmp_path / "custom.csv"
    p.write_text("Host,Finding,Rating\n10.0.0.1,1,x\n")
    with pytest.raises(PostureSourceError, match="no 'asset' column"):
        loaders.load_vulns(p)
    q = tmp_path / "qualys.csv"                    # a Qualys report is now read natively (integration plan #6)
    q.write_text("IP,QID,Title\n10.0.0.1,1,x\n")
    assert [v.asset for v in loaders.load_vulns(q)] == ["10.0.0.1"]


# ---- remediation proposals are never silenced for good ------------------------------------------

def _decide(d, aid, status):
    with (d / "decisions.jsonl").open("a", encoding="utf-8") as f:
        f.write(json.dumps({"approval_id": aid, "status": status, "decided_by": "ciso"}) + "\n")


def test_rejected_proposal_is_refiled_after_its_review_period(ws, tmp_path):
    from aegis.hitl import FileHITL
    d = tmp_path / "hitl"
    cfg = runner.load_config(ws / "posture_exposure.yaml")
    r1 = runner.run_once(cfg, now=T0, hitl=FileHITL(d))
    p = next(x for x in r1["remediation"]["proposals"] if x["component"] == "ops-bastion:22")
    _decide(d, p["approval_id"], "rejected")
    runner.run_once(cfg, now=T0 + timedelta(hours=1), hitl=FileHITL(d))
    r3 = runner.run_once(cfg, now=T0 + timedelta(days=10), hitl=FileHITL(d))
    assert next(x for x in r3["remediation"]["proposals"] if x["component"] == "ops-bastion:22")["status"] == "rejected"
    r4 = runner.run_once(cfg, now=T0 + timedelta(days=31), hitl=FileHITL(d))
    again = next(x for x in r4["remediation"]["proposals"] if x["component"] == "ops-bastion:22")
    assert again["status"] == "awaiting_approval" and again["approval_id"] != p["approval_id"]
    assert again["previous"]["status"] == "rejected"


def test_expired_proposal_is_refiled_on_the_next_run():
    props = {"fp": {"fingerprint": "fp", "status": "expired", "approval_id": "old", "updated_at": "2026-11-01T00:00:00Z",
                    "created_at": "2026-10-01T00:00:00Z"}}
    row = {"fingerprint": "fp", "id": "CVE-2024-6387", "resource": "i-1", "affected_component": "bastion:22",
           "scanner": "exposure", "scan": "x", "stale": False,
           "extra": {"tier": "ACT_NOW", "reach": "internet", "defended": "none", "port": 22, "title": "t",
                     "reasons": ["a", "b", "c", "d"], "path": {}}}
    import tempfile
    store = Path(tempfile.mkdtemp())
    (store / "proposals.json").write_text(json.dumps(props))
    sec = remediation.reconcile(store, {"open": [row], "resolved": [], "waived": []}, hitl=None, now=T0)
    (p,) = sec["proposals"]
    assert p["status"] == "proposed" and p["previous"]["status"] == "expired"
