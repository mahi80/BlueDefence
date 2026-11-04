"""Integration plan #7: Sigma rules executed over OCSF events."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from aegis.detect import sigma
from aegis.detect.sigma import SigmaEngine, Unsupported, compile_rule, enrich
from aegis.ingest.ocsf import to_alert
from aegis.ingest.stream import StreamConsumer, StreamQueue

RULES = Path(__file__).resolve().parents[1] / "detect" / "samples" / "rules"


@pytest.fixture(scope="module")
def eng():
    return SigmaEngine.from_dir(RULES)


def _proc(image, cmd, parent):
    return {"class_uid": 1007, "time": 1762200000000, "severity_id": 2, "device": {"hostname": "web-01"},
            "process": {"file": {"path": image}, "cmd_line": cmd, "parent_process": {"file": {"path": parent}}},
            "metadata": {"uid": "p1", "product": {"name": "Sysmon"}}}


def _ids(rules):
    return {r.id[-4:] for r in rules}


def test_loads_supported_and_counts_skipped(eng):
    assert len(eng.rules) == 6
    assert eng.skipped == {"aggregation / near": 1, "unsupported modifier": 1}


def test_web_shell_all_of_and_filter(eng):
    hit = _proc("C:\\Windows\\System32\\cmd.exe", "cmd /c whoami", "C:\\Windows\\System32\\inetsrv\\w3wp.exe")
    assert "0001" in _ids(eng.match(hit))
    filtered = _proc("C:\\Windows\\System32\\cmd.exe", "powershell -f healthcheck.ps1", "C:\\x\\W3WP.EXE")
    assert "0001" not in _ids(eng.match(filtered))                       # the rule's own filter
    other_parent = _proc("C:\\Windows\\System32\\cmd.exe", "cmd /c dir", "C:\\Windows\\explorer.exe")
    assert "0001" not in _ids(eng.match(other_parent))


def test_regex_modifier(eng):
    ev = _proc("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
               "powershell.exe -nop -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA=", "C:\\Windows\\explorer.exe")
    assert "0002" in _ids(eng.match(ev))
    ev["process"]["cmd_line"] = "powershell.exe -File backup.ps1"
    assert "0002" not in _ids(eng.match(ev))


def test_http_rules_by_class(eng):
    proxy = {"class_uid": 4002, "time": 1, "http_request": {"user_agent": "python-requests/2.32", "url": {"query_string": "id=1"}}}
    sqli = {"class_uid": 4002, "time": 1, "http_request": {"user_agent": "Mozilla/5.0",
                                                            "url": {"query_string": "id=1' OR 1=1--"}}}
    assert _ids(eng.match(proxy)) == {"0003"}
    assert _ids(eng.match(sqli)) == {"0004"}                               # case-insensitive contains
    assert eng.match({"class_uid": 1007, "time": 1, "http_request": {"user_agent": "curl/8"}}) == []   # class gate


def test_cloudtrail_and_cidr(eng):
    ct = {"class_uid": 6003, "time": 1, "api": {"operation": "StopLogging", "service": {"name": "cloudtrail.amazonaws.com"}}}
    assert _ids(eng.match(ct)) == {"0005"}
    ct["api"]["operation"] = "LookupEvents"
    assert eng.match(ct) == []
    imds = {"class_uid": 4001, "time": 1, "dst_endpoint": {"ip": "169.254.169.254", "port": 80},
            "process": {"file": {"path": "/usr/bin/python3"}}}
    assert _ids(eng.match(imds)) == {"0006"}
    imds["process"]["file"]["path"] = "/usr/bin/amazon-ssm-agent"
    assert eng.match(imds) == []


def test_missing_field_never_matches_and_unmapped_fallback():
    r = compile_rule({"title": "t", "id": "x", "logsource": {"category": "process_creation"},
                      "detection": {"sel": {"LogonId": "0x3e7"}, "condition": "sel"}})
    assert not r.match({"class_uid": 1007})
    assert r.match({"class_uid": 1007, "unmapped": {"LogonId": "0x3E7"}})


def test_condition_grammar():
    doc = {"title": "t", "id": "x", "logsource": {"category": "process_creation"},
           "detection": {"a": {"CommandLine|contains": "aa"}, "b": {"CommandLine|contains": "bb"},
                         "c": {"CommandLine|contains": "cc"}, "condition": "(a or b) and not c"}}
    r = compile_rule(doc)
    ev = lambda s: {"process": {"cmd_line": s}}
    assert r.match(ev("xx bb")) and not r.match(ev("bb cc")) and not r.match(ev("zz"))
    doc["detection"]["condition"] = "1 of them"
    assert compile_rule(doc).match(ev("cc"))
    doc["detection"]["condition"] = "all of them"
    assert compile_rule(doc).match(ev("aa bb cc")) and not compile_rule(doc).match(ev("aa bb"))
    for bad in ("a near b", "a | count() > 3", "a and zz", "(a or b"):
        doc["detection"]["condition"] = bad
        with pytest.raises(Unsupported):
            compile_rule(doc)


def test_keywords_all_null_and_windash():
    kw = compile_rule({"title": "t", "id": "k", "logsource": {"category": "process_creation"},
                       "detection": {"keywords": ["mimikatz", "sekurlsa::"], "condition": "keywords"}})
    assert kw.match({"process": {"cmd_line": "x.exe sekurlsa::logonpasswords"}})
    allm = compile_rule({"title": "t", "id": "a", "logsource": {"category": "process_creation"},
                         "detection": {"s": {"CommandLine|contains|all": ["net", "user", "/add"]}, "condition": "s"}})
    assert allm.match({"process": {"cmd_line": "net user bob P@ss /add"}})
    assert not allm.match({"process": {"cmd_line": "net user bob"}})
    nul = compile_rule({"title": "t", "id": "n", "logsource": {"category": "process_creation"},
                        "detection": {"s": {"CommandLine|contains": "x"}, "f": {"ParentImage": None},
                                      "condition": "s and f"}})
    assert nul.match({"process": {"cmd_line": "x"}}) and not nul.match({"process": {"cmd_line": "x", "parent_process": {"file": {"path": "p"}}}})
    wd = compile_rule({"title": "t", "id": "w", "logsource": {"category": "process_creation"},
                       "detection": {"s": {"CommandLine|windash|contains": " -decode "}, "condition": "s"}})
    assert wd.match({"process": {"cmd_line": "certutil /decode a b"}})


def test_enrich_raises_severity_and_adds_techniques(eng):
    ev = _proc("C:\\Windows\\System32\\cmd.exe", "cmd /c whoami", "C:\\inetpub\\w3wp.exe")
    alert = to_alert(ev)
    assert alert["severity"] == "low"
    enrich(alert, ev, eng)
    assert alert["severity"] == "high" and alert["anomaly_score"] >= 0.8
    assert alert["sigma"][0]["title"] == "Web server worker spawns a shell" and "T1505.003" in alert["techniques"]


def test_stream_ocsf_path_uses_env_rules(monkeypatch):
    monkeypatch.setenv("AEGIS_SIGMA_RULES", str(RULES))
    monkeypatch.setattr(sigma, "_ENGINE", None)
    q = StreamQueue(capacity=10)
    ev = {"class_uid": 6003, "time": 1762200000000, "api": {"operation": "DeleteTrail",
                                                             "service": {"name": "cloudtrail.amazonaws.com"}},
          "metadata": {"uid": "ct-1", "product": {"name": "CloudTrail"}}}
    q.put("ocsf", json.dumps(ev))
    out = StreamConsumer(queue=q).normalize(q.drain()[0])
    a = out[0] if isinstance(out, list) else out
    assert a["severity"] == "critical" and a["sigma"][0]["level"] == "critical"
    monkeypatch.delenv("AEGIS_SIGMA_RULES")
    assert sigma.engine_from_env() is None


def test_cli(capsys):
    assert sigma.main(["--rules", str(RULES)]) == 0
    assert '"loaded": 6' in capsys.readouterr().out
