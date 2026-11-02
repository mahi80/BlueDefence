"""Perimeter scorers for credential disclosure + exfiltration — the CVE_DOTENV_DISCLOSURE,
CVE_LARAVEL_LOG_DISCLOSURE and edge-/export/-alias classes that were blind in the coverage matrix.

Two halves: secret_file_probe scores the *attempt* (a request for a dev-left secret, a VCS dir, a
config, a key or a backup), and secret_exfil_probe scores the *success* by the shape of the secret in
the response body — path-independent, so a novel leak vector is still caught.
"""

from __future__ import annotations

import pytest

from aegis.agents.perimeter import tools


# ----------------------------------------------------- secret_file_probe (attempt) -- #

@pytest.mark.parametrize("path", [
    "/.env", "/.env.production", "/public/.git/config", "/wp-config.php",
    "/storage/logs/laravel.log", "/app/config/settings.py", "/.aws/credentials",
    "/id_rsa", "/backup/db.sql", "/export/", "/.htpasswd", "/appsettings.json",
])
def test_secret_paths_flagged(path):
    r = tools.secret_file_probe({"url": f"https://bank.example{path}"})
    assert r.weight in ("medium", "high")
    assert r.data["signature"]


def test_backup_suffix_flagged():
    r = tools.secret_file_probe({"url": "https://bank.example/index.php.bak"})
    assert r.weight in ("medium", "high") and r.data["signature"].startswith("*")


def test_traversal_encoded_dotenv_collapses():
    # %2e%2e%2f%2e%2e%2f.env double-decodes to ../../.env and still lands on the .env signature
    r = tools.secret_file_probe({"url": "https://bank.example/%2e%2e%2f%2e%2e%2f.env"})
    assert r.data["signature"] == ".env"


def test_served_200_is_high_disclosure():
    r = tools.secret_file_probe({
        "url": "https://bank.example/.env", "status": 200,
        "response_headers": {"Content-Type": "text/plain; charset=utf-8"}})
    assert r.weight == "high" and r.data.get("disclosure") is True


def test_blocked_attempt_is_medium_not_breach():
    r = tools.secret_file_probe({
        "url": "https://bank.example/.env", "status": 403})
    assert r.weight == "medium" and r.data.get("blocked") is True


def test_attempt_without_outcome_still_high():
    r = tools.secret_file_probe({"url": "https://bank.example/.git/config"})
    assert r.weight == "high"


def test_benign_path_stays_low():
    r = tools.secret_file_probe({"url": "https://bank.example/accounts/summary?page=2", "status": 200})
    assert r.weight == "low" and not r.data.get("signature")


# ---------------------------------------------------- secret_exfil_probe (success) -- #

@pytest.mark.parametrize("body,kind", [
    ("DB_PASSWORD=S3cr3t_prod_pw\nAPP_KEY=base64:abc", "env_secret_assign"),
    ("-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAK", "private_key"),
    ("aws_access_key_id = AKIAIOSFODNN7EXAMPLE", "aws_access_key_id"),
    ("DATABASE_URL=postgres://app:hunter2@db.internal:5432/bank", "db_dsn"),
    ('{"type": "service_account", "project_id": "x"}', "gcp_sa_key"),
    ("slack=xoxb-2410384otheroheohtoehunot", "slack_token"),
])
def test_secret_shapes_in_body_flagged(body, kind):
    r = tools.secret_exfil_probe({"url": "https://bank.example/download", "status": 200,
                                  "response_body": body})
    assert r.weight == "high" and kind in r.data["secret_kinds"]


def test_benign_body_stays_low():
    r = tools.secret_exfil_probe({"response_body": "<html><body>Welcome to the bank</body></html>"})
    assert r.weight == "low"


def test_no_body_not_applicable():
    r = tools.secret_exfil_probe({"url": "https://bank.example/.env"})
    assert r.data.get("applicable") is False and r.weight == "low"


def test_body_under_response_dict_is_read():
    r = tools.secret_exfil_probe({"response": {"body": "JWT_SECRET=deadbeefcafe"}})
    assert r.weight == "high" and "env_secret_assign" in r.data["secret_kinds"]


# ------------------------------------------------------------------- registration -- #

def test_both_tools_run_in_the_battery():
    results = tools.run_all_tools("", "203.0.113.9", None,
                                  alert={"url": "https://bank.example/.env", "status": 200,
                                         "response_body": "DB_PASSWORD=x",
                                         "response_headers": {"Content-Type": "text/plain"}})
    names = {r.name for r in results}
    assert {"secret_file_probe", "secret_exfil_probe"} <= names
    by = {r.name: r for r in results}
    assert by["secret_file_probe"].weight == "high"
    assert by["secret_exfil_probe"].weight == "high"
