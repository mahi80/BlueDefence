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


def test_powershell_event_log_auditd_and_av_logsources_map():
    script = compile_rule({"title": "t", "id": "ps", "logsource": {"product": "windows", "category": "ps_script"},
                           "detection": {"s": {"ScriptBlockText|contains": "Invoke-Mimikatz"}, "condition": "s"}})
    assert script.classes == (1009,) and script.match({"script": {"script_content": "x; Invoke-Mimikatz -DumpCreds"}})
    svc = compile_rule({"title": "t", "id": "svc", "logsource": {"product": "windows", "service": "system"},
                        "detection": {"s": {"EventID": 7045, "ServiceName": "PSEXESVC"}, "condition": "s"}})
    assert svc.classes == (1008,)
    assert svc.match({"metadata": {"event_code": "7045"}, "unmapped": {"ServiceName": "PSEXESVC"}})
    aud = compile_rule({"title": "t", "id": "au", "logsource": {"product": "linux", "service": "auditd"},
                        "detection": {"s": {"type": "EXECVE", "a0": "nc", "a1": "-e"}, "condition": "s"}})
    assert 1007 in aud.classes and aud.match({"unmapped": {"type": "EXECVE", "a0": "nc", "a1": "-e"}})
    av = compile_rule({"title": "t", "id": "av", "logsource": {"category": "antivirus"},
                       "detection": {"s": {"Signature|contains": "Mimikatz"}, "condition": "s"}})
    assert av.classes == (2004,) and av.match({"malware": {"name": "HackTool:Win64/Mimikatz.D"}})
    k8s = compile_rule({"title": "t", "id": "k", "logsource": {"product": "kubernetes", "service": "audit"},
                        "detection": {"s": {"verb": "create", "objectRef.resource": "pods/exec"}, "condition": "s"}})
    assert 6003 in k8s.classes
    with pytest.raises(Unsupported):
        compile_rule({"title": "t", "id": "x", "logsource": {"product": "exotic", "service": "thing"},
                      "detection": {"s": {"a": 1}, "condition": "s"}})


def test_fast_string_path_agrees_with_the_regex_path():
    import re as _re

    from aegis.detect.sigma import _value_test

    def _glob_rx(value, *, contains=False, start=False, end=False):      # the old regex path, kept as a reference
        out, i = [], 0
        while i < len(value):
            c = value[i]
            if c == "\\" and i + 1 < len(value) and value[i + 1] in "*?\\":
                out.append(_re.escape(value[i + 1]))
                i += 2
                continue
            out.append(".*" if c == "*" else "." if c == "?" else _re.escape(c))
            i += 1
        body = "".join(out)
        if contains or end:
            body = ".*" + body
        if contains or start:
            body = body + ".*"
        return _re.compile(f"(?s){body}\\Z", _re.IGNORECASE)
    values = ["\\cmd.exe", "Invoke-Mimikatz", "C:\\Windows\\Temp\\", "-enc", "net user", "ADMIN$", "a.b"]
    samples = ["C:\\Windows\\System32\\CMD.EXE", "powershell invoke-mimikatz -x", "c:\\windows\\temp\\x.dll",
               "PS -ENC abc", "NET USER bob /add", "\\\\host\\admin$", "axb", "a.b", "", "cmd.exe"]
    for v in values:
        for mods, kw in (((), {}), (("contains",), {"contains": True}), (("startswith",), {"start": True}),
                         (("endswith",), {"end": True})):
            (fast,) = _value_test(v, mods)
            rx = _glob_rx(v, **kw)
            for s in samples:
                assert fast(s) == bool(rx.match(s)), (v, mods, s)


def test_lookup_cache_is_per_event(eng):
    a = _proc("C:\\Windows\\System32\\cmd.exe", "cmd /c whoami", "C:\\inetpub\\w3wp.exe")
    b = _proc("C:\\Windows\\System32\\cmd.exe", "cmd /c whoami", "C:\\Windows\\explorer.exe")
    assert "0001" in _ids(eng.match(a)) and "0001" not in _ids(eng.match(b))
    assert sigma._LOCAL.cache is None


# ---------------------------------------------------------------------------------------------------- round 6 --

def _r(det, ls=None, level="high"):
    return compile_rule({"id": "x", "title": "t", "level": level, "logsource": ls or {"category": "process_creation"},
                         "detection": det})


def test_glob_matching_is_linear_on_adversarial_input():
    """S-1: the crackmapexec-shaped wildcard value on 32 KB of near-misses must not backtrack (was minutes)."""
    import time as _t
    r = _r({"s": {"CommandLine": "cmd.exe /C * > \\\\\\\\*\\\\*\\\\* 2>&1"}, "condition": "s"})
    cmd = "cmd.exe /Q /c " + ("x 1> \\\\a\\b\\" * 3000)[:32000]
    t0 = _t.perf_counter()
    assert not r.match({"process": {"cmd_line": cmd}})
    assert _t.perf_counter() - t0 < 0.5
    kw = compile_rule({"id": "k", "title": "t", "logsource": {"category": "process_creation"},
                       "detection": {"k": ["whoami*|*find"], "condition": "k"}})
    t0 = _t.perf_counter()
    kw.match({"process": {"cmd_line": "whoami|" * 4000}})
    assert _t.perf_counter() - t0 < 0.5


def test_glob_semantics_with_wildcards_match_the_regex_reference():
    import re as _re

    from aegis.detect.sigma import _Glob

    def ref(v, **kw):
        body = "".join(".*" if c == "*" else "." if c == "?" else _re.escape(c) for c in v)
        if kw.get("contains") or kw.get("end"):
            body = ".*" + body
        if kw.get("contains") or kw.get("start"):
            body += ".*"
        return _re.compile(f"(?s){body}\\Z", _re.IGNORECASE)
    for v in ("a*b", "*.exe", "c?d*e", "x*y*z", "ab?", "*", "?", "a**b", "abc"):
        for kw in ({}, {"contains": True}, {"start": True}, {"end": True}):
            g, rx = _Glob(v, **kw), ref(v, **kw)
            for s in ("", "ab", "aXb", "AYYB", "cXdZe", "x1y2z", "abc", "abcd", "file.EXE", "zab", "aab", "ba"):
                assert g(s) == bool(rx.match(s)), (v, kw, s)


def test_actor_process_fields_outside_process_activity():
    """S-2: Image / CommandLine come from actor.process in network / file / DNS events, so filters apply."""
    r = _r({"sel": {"DestinationPort": 587}, "filter": {"Image|endswith": "\\outlook.exe"},
            "condition": "sel and not filter"}, ls={"category": "network_connection"})
    ev = {"class_uid": 4001, "dst_endpoint": {"port": 587},
          "actor": {"process": {"file": {"path": "C:\\Program Files\\Office\\OUTLOOK.EXE"}}}}
    assert not r.match(ev)
    ev["actor"]["process"]["file"]["path"] = "C:\\Users\\a\\evil.exe"
    assert r.match(ev)
    proc = _r({"sel": {"Image|endswith": "\\cmd.exe"}, "condition": "sel"})
    assert proc.match({"class_uid": 1007, "process": {"file": {"path": "C:\\w\\cmd.exe"}}})


def test_activity_id_gates_categories():
    """S-3: a process_creation rule does not fire on a Terminate / Open event (it still does with no activity_id)."""
    eng = SigmaEngine(rules=[_r({"s": {"Image|endswith": "\\whoami.exe"}, "condition": "s"})])
    ev = {"class_uid": 1007, "process": {"file": {"path": "C:\\w\\whoami.exe"}}}
    assert eng.match({**ev, "activity_id": 1}) and eng.match(ev)
    assert not eng.match({**ev, "activity_id": 2}) and not eng.match({**ev, "activity_id": 3})
    fd = SigmaEngine(rules=[_r({"s": {"TargetFilename|endswith": ".log"}, "condition": "s"}, ls={"category": "file_delete"})])
    assert fd.match({"class_uid": 1001, "activity_id": 4, "file": {"path": "a.log"}})
    assert not fd.match({"class_uid": 1001, "activity_id": 1, "file": {"path": "a.log"}})


def test_long_values_are_matched_whole():
    """S-4: an 8 KB+ padded command line no longer hides the tail."""
    r = _r({"s": {"CommandLine|endswith": "-enc"}, "condition": "s"})
    assert r.match({"process": {"cmd_line": "powershell " + " " * 20000 + "-enc"}})
    c = _r({"s": {"CommandLine|contains": "mimikatz"}, "condition": "s"})
    assert c.match({"process": {"cmd_line": "cmd /c " + "A" * 20000 + " mimikatz"}})


def test_windash_mixed_flags_and_unicode_dashes():
    """S-5."""
    r = _r({"s": {"CommandLine|windash|contains": " -s -i cmd"}, "condition": "s"})
    for cmd in ("svc.exe -s -i cmd", "svc.exe /s /i cmd", "svc.exe -s /i cmd", "svc.exe /s -i cmd",
                "svc.exe \u2014s \u2013i cmd", "svc.exe \u2015s -i cmd"):
        assert r.match({"process": {"cmd_line": cmd}}), cmd
    assert not r.match({"process": {"cmd_line": "svc.exe -x -i cmd"}})
    word = _r({"s": {"CommandLine|windash|contains": "Invoke-Expression"}, "condition": "s"})
    assert word.match({"process": {"cmd_line": "Invoke-Expression $x"}})


def test_fieldless_all_keywords_and_unknown_modifiers():
    """S-6 / S-7."""
    kw = compile_rule({"id": "k", "title": "t", "logsource": {"product": "linux", "service": "syslog"},
                       "detection": {"k": {"|all": ["foo", "bar"]}, "condition": "k"}})
    assert kw.match({"class_uid": 1008, "message": "x foo y bar"}) and not kw.match({"class_uid": 1008, "message": "foo"})
    cased = _r({"s": {"CommandLine|cased": "ABC"}, "condition": "s"})
    assert cased.match({"process": {"cmd_line": "ABC"}}) and not cased.match({"process": {"cmd_line": "abc"}})
    with pytest.raises(Unsupported):
        _r({"s": {"CommandLine|minute": 5}, "condition": "s"})
    with pytest.raises(Unsupported):
        _r({"s": {"CommandLine|contians": "x"}, "condition": "s"})


def test_null_alternatives_and_empty_strings():
    """S-8."""
    r = _r({"s": {"CommandLine": [None, "x"]}, "condition": "s"})
    assert r.match({"process": {}}) and r.match({"process": {"cmd_line": "x"}}) and not r.match({"process": {"cmd_line": "y"}})
    empty = compile_rule({"id": "e", "title": "t", "logsource": {"category": "proxy"},
                          "detection": {"s": {"c-useragent": ""}, "condition": "s"}})
    assert empty.match({"http_request": {"user_agent": ""}}) and not empty.match({"http_request": {"user_agent": "curl"}})
    assert not empty.match({"http_request": {}})


def test_field_map_fixes():
    """S-9 / S-10."""
    from aegis.detect.sigma import field_values
    assert field_values({"api": {"operation": "repo.delete"}}, "auditType.action") == ["repo.delete"]
    ext = compile_rule({"id": "x", "title": "t", "logsource": {"category": "proxy"},
                        "detection": {"s": {"c-uri-extension": ["exe", "vbs"]}, "condition": "s"}})
    assert ext.match({"http_request": {"url": {"path": "/a/b.exe"}}})
    assert not ext.match({"http_request": {"url": {"path": "/a/b.exe.txt"}}})
    h = _r({"s": {"Hashes|contains": "SHA256=ABCD"}, "condition": "s"})
    assert h.match({"class_uid": 1007, "process": {"file": {"hashes": [{"algorithm": "SHA-256", "value": "abcd"},
                                                                      {"algorithm_id": 1, "value": "ff"}]}}})
    port = _r({"s": {"DestinationPort|startswith": 44}, "condition": "s"}, ls={"category": "network_connection"})
    assert port.match({"class_uid": 4001, "dst_endpoint": {"port": 443}})


def test_engine_cache_keys_on_level_and_warns_on_missing_path(monkeypatch, caplog):
    """S-11."""
    monkeypatch.setattr(sigma, "_ENGINE", None)
    monkeypatch.setenv("AEGIS_SIGMA_RULES", str(RULES))
    monkeypatch.setenv("AEGIS_SIGMA_MIN_LEVEL", "low")
    low = sigma.engine_from_env()
    assert sigma.engine_from_env() is low
    monkeypatch.setenv("AEGIS_SIGMA_MIN_LEVEL", "critical")
    crit = sigma.engine_from_env()
    assert crit is not low and len(crit.rules) < len(low.rules)
    monkeypatch.setenv("AEGIS_SIGMA_RULES", "/nonexistent/sigma/rules")
    with caplog.at_level("ERROR", logger="aegis.detect.sigma"):
        sigma.engine_from_env()
    assert "not a directory" in caplog.text
    monkeypatch.setattr(sigma, "_ENGINE", None)
