"""Tests that could not fail, and the slow regex (code review 2026-11-03, group F: T4, T8, T13)."""

from __future__ import annotations

import importlib.util
import json
import time
from pathlib import Path

import pytest

from aegis.agents.perimeter.tools import ssrf_probe

ROOT = Path(__file__).resolve().parents[2]


# ---- T4: the URL scan is linear ---------------------------------------------------------------------

@pytest.mark.parametrize("payload", ["a" * 300_000, "x." * 150_000, "a" * 150_000 + "://" + "b" * 150_000,
                                     ":/" * 150_000, ("ab" * 40 + "://h ") * 3_000])
def test_ssrf_scan_of_a_300kb_payload_is_fast(payload):
    t = time.perf_counter()
    ssrf_probe(payload)
    assert time.perf_counter() - t < 2.0          # was minutes: the scheme part retried from every letter


@pytest.mark.parametrize("payload", ["u=http://169.254.169.254/latest/meta-data", "u=1http://169.254.169.254/",
                                     "u=" + "z" * 100 + "http://169.254.169.254/", "gopher://127.0.0.1:6379/_x"])
def test_bounded_scheme_still_finds_internal_urls(payload):
    assert ssrf_probe(payload).data.get("targets"), payload


# ---- T8 / mutation M17: a block that never expires --------------------------------------------------

def _edge():
    spec = importlib.util.spec_from_file_location("aegis_edge_f", ROOT / "scripts" / "aegis_edge.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.mark.parametrize("value", [float("inf"), float("-inf"), float("nan"), "inf", "nan"])
def test_edge_refuses_a_non_finite_expiry(value):
    edge = _edge()
    with pytest.raises(edge._BadExpiry):
        edge._expiry(value)


def test_edge_accepts_finite_expiry():
    edge = _edge()
    assert edge._expiry(1_800_000_000) == 1_800_000_000.0 and edge._expiry(None) is None
    assert edge._expiry("2026-11-02T12:00:00Z") == pytest.approx(1793620800.0)


# ---- T13: the corroboration alerts carry no label --------------------------------------------------

_LABEL_KEYS = {"detection", "detection_name", "rule_id", "rule_title", "signature", "alert_name", "verdict",
               "label", "severity_label", "techniques", "mitre", "rationale"}


def test_corroboration_alerts_carry_no_detection_label():
    """The old check was `"detection" not in json or a["source"]` — always true because source is set."""
    from aegis.dataset.importers.corroboration import generate_corroboration
    for row in generate_corroboration(400, seed=3):
        alert = json.loads(row["messages"][1]["content"])
        leaked = _LABEL_KEYS & {k.lower() for k in alert}
        assert not leaked, (row["id"], leaked)


def test_swarm_run_history_is_bounded_by_behaviour():
    """Replaces a check on the source text of swarm.py."""
    from aegis.agents.orchestrator.swarm import SwarmOrchestrator

    class _Orch:
        def handle(self, alert):
            raise AssertionError("not used")
    sw = SwarmOrchestrator(_Orch(), max_workers=1, workers={})
    try:
        for i in range(sw.runs.maxlen + 50):
            sw.runs.append({"alert_id": f"a{i}"})
        assert len(sw.runs) == sw.runs.maxlen and sw.runs[0]["alert_id"] == "a50"
    finally:
        sw._pool.shutdown(wait=False)


def test_onnx_roundtrip_runs_when_its_deps_are_installed():
    """aegis/rl/test_onnx_roundtrip.py sits outside testpaths and was never collected."""
    for dep in ("sklearn", "skl2onnx", "onnxruntime", "numpy"):
        pytest.importorskip(dep)
    from aegis.rl.test_onnx_roundtrip import main
    assert main() == 0


# ---- T11: `dataset verify` on a synth dataset (CI ran it with `|| true` because it always failed) ----

def test_dataset_verify_accepts_synth_and_catches_tampering(tmp_path):
    import subprocess
    import sys
    out = tmp_path / "synth"
    run = lambda *a: subprocess.run([sys.executable, "-m", "aegis.dataset", *a], cwd=ROOT,
                                    capture_output=True, text=True, timeout=120, check=False)
    assert run("synth", "--out", str(out), "--n", "40", "--seed", "7").returncode == 0
    assert run("verify", str(out)).returncode == 0
    p = out / "sft" / "triage.jsonl"
    lines = p.read_text(encoding="utf-8").splitlines()
    lines[0] = lines[0].replace("malicious", "benign").replace("suspicious", "benign")
    p.write_text("\n".join(lines[:-1]) + "\n", encoding="utf-8")       # changed row and one row dropped
    r = run("verify", str(out))
    assert r.returncode == 1 and "sft/triage.jsonl" in r.stdout
