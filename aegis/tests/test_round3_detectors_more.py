"""Round-3 review, group G7 (medium items): EDR, perimeter, DLP, wireless, email, TI, treasury, NDR, audit."""

from __future__ import annotations

import json
import time

import pytest

from aegis.agents.shared.bounded import BoundedDict

# ---- G7-9: eviction is O(1) ------------------------------------------------------------------------------------------

def test_bounded_dict_insert_past_the_cap_is_fast():
    d: BoundedDict = BoundedDict(20_000)
    for i in range(20_000):
        d[i] = i
    t = time.perf_counter()
    for i in range(20_000, 30_000):
        d[i] = i
    assert (time.perf_counter() - t) / 10_000 < 50e-6 and len(d) == 20_000 and 0 not in d


def test_bounded_dict_keeps_pinned_and_established_semantics():
    d: BoundedDict = BoundedDict(3, pinned=lambda k: k == "p")
    for k in ("p", "a", "b", "c"):
        d[k] = 1
    assert list(d) == ["p", "b", "c"]
    e: BoundedDict = BoundedDict(2, keep_established=True)
    for k in ("x", "y", "z"):
        e[k] = 1
    assert list(e) == ["x", "z"]


# ---- G7-8: EDR --------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("parent,child,cmd", [
    (r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE", r"C:\Windows\System32\cmd.exe", "cmd /c whoami"),
    ("explorer.exe", "rundll32.exe", r"rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 624 C:\t\l.dmp full"),
    ("explorer.exe", "powershell.exe", "powershell -nop -w hidden -e " + "SQBFAFgA" * 8),
    ("explorer.exe", "powershell.exe", "powershell -c \"$s = (New-Object Net.WebClient).DownloadData($u); $s | iex\""),
])
def test_edr_rules_fire(parent, child, cmd):
    from aegis.agents.edr.tools import parent_process_tree
    assert parent_process_tree(parent, child, cmd).weight == "high"


def test_edr_ordinary_powershell_is_quiet():
    from aegis.agents.edr.tools import parent_process_tree
    assert parent_process_tree("explorer.exe", "powershell.exe", "powershell -ExecutionPolicy Bypass -File backup.ps1").weight == "low"


# ---- G7-10: perimeter decoding ----------------------------------------------------------------------------------------

@pytest.mark.parametrize("payload", ["id=1 UNION ALL SELECT pass FROM users", "id=%2527%2520or%25201%253D1",
                                     "q=&#39; or 1=1--", "q=\uff07 \uff2f\uff32 \uff11\uff1d\uff11--"])
def test_encoded_sqli_is_decoded(payload):
    from aegis.agents.perimeter.tools import decode_payload
    assert decode_payload(payload).data["primitives"]["sqli"]


def test_unclosed_comments_do_not_stall_the_scan():
    from aegis.agents.perimeter.tools import decode_payload
    t = time.perf_counter()
    decode_payload("/*" * 50_000)
    assert time.perf_counter() - t < 1.0


def test_user_agent_and_upper_case_crlf_are_scanned():
    from aegis.agents.perimeter.tools import header_injection
    assert header_injection({"user_agent": "x' or 1=1-- <script>"}).weight != "low"
    assert header_injection({"request_headers": {"X-Test": "a%0D%0ASet-Cookie: s=1"}}).weight == "high"


def test_statement_export_is_not_a_secret_file_but_a_dump_is():
    from aegis.agents.perimeter.tools import secret_file_probe
    assert secret_file_probe({"url": "/api/v1/statements/export/pdf", "status": 200}).weight == "low"
    assert secret_file_probe({"url": "/backup/core.sql.gz", "status": 200}).weight == "high"


def test_padding_does_not_push_the_attack_out():
    from aegis.ingest.waf import WafConsumer
    line = json.dumps({"id": "x", "client_ip": "203.0.113.5", "uri": "/search?q=" + "A" * 9000 + "' OR 1=1--"})
    a = WafConsumer().normalize(line)
    assert "' OR 1=1--" in a["url"] and "' OR 1=1--" in a["payload"]


# ---- G7-11: DLP --------------------------------------------------------------------------------------------------------

def test_dlp_counts_only_real_card_and_aadhaar_numbers():
    from aegis.agents.dlp.tools import sensitive_data_pattern_check
    orders = "\n".join(f"ORD{n},1234567812345678,1234 5678 1234 5678" for n in range(60))   # 16 digits, not Luhn
    assert "credit_card" not in sensitive_data_pattern_check(orders).data.get("findings", {})
    assert sensitive_data_pattern_check("card 4111 1111 1111 1111").data["findings"]["credit_card"] == 1
    assert sensitive_data_pattern_check("aadhaar 4991-1866-5246, pan abcpe1234f").data["findings"].keys() >= {"aadhaar", "pan_in"}


def test_schema_qualified_table_is_known():
    from aegis.agents.dlp.tools import bulk_read_check
    assert bulk_read_check("core.public.CUSTOMERS", 5000).data["sensitivity"] == "high"


# ---- G7-12 / G7-13 / G7-14 / G7-15 -----------------------------------------------------------------------------------

@pytest.mark.parametrize("bssid", ["b4:99:ba:01:02:03", "B4-99-BA-01-02-03", "b499.ba01.0203", "b499ba010203"])
def test_authorised_ap_in_any_mac_format(bssid):
    from aegis.agents.wireless.tools import rogue_ap_check
    assert rogue_ap_check({"bssid": bssid, "ssid": "BankWiFi-PoS"}).data["oui_authorized"] is True


def test_db_application_name_is_not_identity(monkeypatch):
    from aegis.agents.api_abuse.tools import db_direct_query_check
    monkeypatch.setenv("AEGIS_DB_APP_HOSTS", "10.8.0.0/24")
    q = "select * from customers"
    assert db_direct_query_check("app:ledger", q, 10, "198.51.100.7").weight == "high"     # claimed, wrong host
    assert db_direct_query_check("app:ledger", q, 10, "10.8.0.21").weight == "medium"


def test_peer_ioc_with_infinite_last_seen_still_expires():
    from aegis.agents.threat_intel.store import IOC, IOCStore
    s = IOCStore()
    s.add(IOC(kind="ip", value="198.51.100.200", source="peer", last_seen=float("inf"), ttl_seconds=60))
    ioc = s.lookup("198.51.100.200", "ip")
    assert ioc is not None and ioc.last_seen <= time.time() + 1


def test_a_sender_written_dkim_signature_is_not_a_pass():
    from aegis.agents.email.tools import attachment_risk_check, header_auth_check
    assert header_auth_check({"DKIM-Signature": "v=1; d=evil.example", "Authentication-Results": "mx; spf=pass"}).data["dkim_fail"]
    assert not header_auth_check({"Authentication-Results": "mx.bank; dkim=pass header.d=bank.in; spf=pass"}).data["dkim_fail"]
    for name in ("invoice\u202efdp.exe", "report.one", "payload.svg", "x.ps1", "stmt.html", "a.exe. "):
        assert attachment_risk_check([{"filename": name}]).weight == "high", name


# ---- G7-16: treasury ----------------------------------------------------------------------------------------------------

def test_a_drain_split_below_the_line_is_caught(monkeypatch):
    from aegis.agents.orchestrator.treasury import BOOK, is_treasury_outflow
    monkeypatch.setenv("AEGIS_HIGH_VALUE_INR", "10000000")
    BOOK.reset()
    hits = [is_treasury_outflow({"user_id": "svc_treasury", "amount_inr": 900_000 + i, "new_beneficiary": True,
                                 "timestamp": f"2026-11-03T10:{i:02d}:00Z", "beneficiary_account": f"B{i}"})
            for i in range(12)]
    assert not any(hits[:11]) and hits[11]                      # the 12th crosses INR 1 crore in the window


def test_id_less_transfers_are_not_one_transfer():
    from aegis.agents.orchestrator.treasury import _txn_id
    a = {"user_id": "u", "amount_inr": 1e7, "beneficiary_account": "B1", "timestamp": "2026-11-03T10:00:00Z"}
    b = {**a, "beneficiary_account": "B2"}
    assert _txn_id(a) != _txn_id(b) and _txn_id(a) != "unknown"


# ---- G7-7: NDR -----------------------------------------------------------------------------------------------------------

def test_exfil_split_across_snis_is_counted_per_destination_ip(monkeypatch):
    from aegis.agents.ndr.egress import EgressDetector
    monkeypatch.setenv("AEGIS_NDR_EXFIL_MIN_MB", "50")
    det = EgressDetector.from_env()
    t0, out = 1_762_160_000.0, []
    for i in range(40):                                          # 40 x 2 MB = 80 MB, never 50 MB on one name
        out += det.observe({"kind": "conn", "src": "10.1.2.3", "dst": "203.0.113.50", "dport": 443, "ts": t0 + i * 60,
                            "sni": f"a{i}.cdn-sync.example", "bytes_out": 2_000_000, "bytes_in": 2_000, "tls": True})
    assert any((a.get("egress") or {}).get("finding") == "tls_exfil" for a in out)


# ---- G7-17: the audit anchor ---------------------------------------------------------------------------------------------

def test_truncating_the_audit_tail_is_detected_with_an_anchor(tmp_path, monkeypatch):
    from aegis.agents.shared.audit import AuditLog
    from aegis.agents.shared.evidence_chain import EvidenceChain
    monkeypatch.setenv("AEGIS_AUDIT_ANCHOR", str(tmp_path / "anchor" / "a.jsonl"))
    monkeypatch.setenv("AEGIS_AUDIT_ANCHOR_EVERY", "2")
    log = AuditLog(tmp_path / "audit.jsonl")
    for i in range(5):
        log.append(EvidenceChain(alert_id=f"A{i}", investigated_by="t", verdict="benign", confidence=0.9))
    assert AuditLog(tmp_path / "audit.jsonl", repair=False).verify_report(all_files=True)["ok"]
    rows = (tmp_path / "audit.jsonl").read_text().splitlines()
    (tmp_path / "audit.jsonl").write_text("\n".join(rows[:2]) + "\n")
    rep = AuditLog(tmp_path / "audit.jsonl", repair=False).verify_report(all_files=True)
    assert not rep["ok"] and rep["broken_at"][0] == "<anchor>"
