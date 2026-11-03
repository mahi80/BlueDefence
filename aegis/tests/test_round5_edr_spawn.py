"""Round 5: suspicious spawns by parent role, so the EDR pre-filter (round 4 S4-8) never drops a web shell."""

from __future__ import annotations

import pytest

from aegis.agents.edr.normalize import to_alert
from aegis.agents.edr.tools import parent_process_tree


@pytest.mark.parametrize("parent,child,weight", [
    ("w3wp.exe", "sh", "high"),                                           # IIS web shell
    ("C:\\Windows\\System32\\inetsrv\\w3wp.exe", "C:\\Windows\\System32\\cmd.exe", "high"),
    ("httpd", "/bin/sh", "high"),
    ("/usr/lib/postgresql/16/bin/postgres", "sh", "high"),               # COPY … FROM PROGRAM
    ("sqlservr.exe", "cmd.exe", "high"),                                 # xp_cmdshell
    ("winword.exe", "mshta.exe", "high"),
    ("java", "bash", "medium"),                                          # Log4Shell — also build tooling
    ("nginx", "ssh-agent", "low"),                                       # no substring matches
    ("explorer.exe", "cmd.exe", "low"),                                  # a person opening a prompt
    ("code.exe", "node.exe", "low"),
])
def test_spawn_by_role(parent, child, weight):
    assert parent_process_tree(parent, child, "").weight == weight


def _sysmon(parent, image):
    return {"EventID": 1, "Computer": "web-01", "ParentImage": parent, "Image": image, "CommandLine": "id"}


def test_web_shell_reaches_the_specialist():
    a = to_alert(_sysmon("C:\\Windows\\System32\\inetsrv\\w3wp.exe", "C:\\Windows\\System32\\cmd.exe"))
    assert a is not None and a["alert_type"] == "host_endpoint"
    assert to_alert(_sysmon("/usr/sbin/httpd", "/bin/sh")) is not None


def test_ordinary_launch_is_still_dropped_unless_the_filter_is_off(monkeypatch):
    row = _sysmon("C:\\Windows\\explorer.exe", "C:\\Windows\\notepad.exe")
    assert to_alert(row) is None
    monkeypatch.setenv("AEGIS_EDR_PREFILTER", "0")
    assert to_alert(row) is not None
