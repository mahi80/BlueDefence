"""Review round 6: MCP gateway (M-1…M-4), judge data / gate / pointers (J-1…J-5), swarm shutdown (W-1)."""

from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from aegis.mcp.gateway import Gateway, RemoteBackend, _untrusted

ROOT = Path(__file__).resolve().parents[2]


def _serve(handler) -> HTTPServer:
    srv = HTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


# ------------------------------------------------------------------------------------------------- MCP --

def test_m1_redirect_is_never_followed_and_no_token_leaves(monkeypatch):
    seen: list = []

    class Evil(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            seen.append(self.headers.get("Authorization"))
            self.send_response(200); self.send_header("Content-Length", "2"); self.end_headers(); self.wfile.write(b"{}")
        do_POST = do_GET

    evil = _serve(Evil)

    class Redir(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _r(self):
            self.rfile.read(int(self.headers.get("Content-Length") or 0))
            self.send_response(302); self.send_header("Location", f"http://127.0.0.1:{evil.server_port}/steal")
            self.send_header("Content-Length", "0"); self.end_headers()
        do_GET = do_POST = _r

    red = _serve(Redir)
    try:
        rb = RemoteBackend(f"http://127.0.0.1:{red.server_port}", "READTOKEN", "CONSOLETOKEN")
        with pytest.raises(RuntimeError, match="redirect"):
            rb.approvals()
        text, err = Gateway(rb, allow_reject=True, user="alice").call(
            "aegis_reject_action", {"approval_id": "abc", "reason": "false positive, scanner"})
        assert err and "redirect" in text
        assert seen == []                                            # neither token reached the other host
    finally:
        evil.shutdown(); red.shutdown()


def test_m1_a_bare_200_is_not_a_rejection():
    class Fake(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_POST(self):
            self.rfile.read(int(self.headers.get("Content-Length") or 0))
            b = b'{"approvals": []}'
            self.send_response(200); self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)

    srv = _serve(Fake)
    try:
        status, out = RemoteBackend(f"http://127.0.0.1:{srv.server_port}", "r", "c").reject(
            "abc", decided_by="mcp:a", reason="x" * 12)
        assert status == 502 and "without confirming" in out["error"]
    finally:
        srv.shutdown()


def test_m2_bad_params_deep_nesting_and_handler_errors_never_kill_the_server():
    class Boom:
        def chains(self, limit):
            raise KeyError("x")
    gw = Gateway(Boom())
    lines = [json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": [1, 2]}),
             "[" * 200_000,
             json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "aegis_recent_verdicts"}}),
             "[]",
             json.dumps({"jsonrpc": "2.0", "id": 3, "method": "ping"})]
    out = io.StringIO()
    gw.serve(io.StringIO("\n".join(lines) + "\n"), out)
    replies = [json.loads(x) for x in out.getvalue().splitlines()]
    assert replies[0]["error"]["code"] == -32602
    assert replies[1]["error"]["code"] == -32700
    assert replies[2]["result"]["isError"] is True                  # backend failure is a tool error
    assert replies[3]["error"]["code"] == -32600                    # M-4: empty batch answered
    assert replies[4]["result"] == {}                               # still alive


def test_m2_unexpected_exception_is_internal_error_without_traceback(monkeypatch):
    gw = Gateway(object())
    monkeypatch.setattr(gw, "handle", lambda m: (_ for _ in ()).throw(RuntimeError("secret path /etc/x")))
    out = io.StringIO()
    gw.serve(io.StringIO(json.dumps({"jsonrpc": "2.0", "id": 9, "method": "ping"}) + "\n"), out)
    r = json.loads(out.getvalue())
    assert r["id"] == 9 and r["error"]["code"] == -32603 and "secret" not in out.getvalue()


def test_m3_a_secret_across_the_cut_is_still_redacted():
    from aegis.mcp import gateway as g
    for key in ("password", "api_key", "authorization"):
        pad = "x" * (g.MAX_RESULT_CHARS - 40)
        text = _untrusted("t", {"a": pad, key: "Sup3rS3cretValue-0123456789-ABCDEF"})
        assert "Sup3rS3cret" not in text and "0123456789-ABCDEF" not in text


def test_m4_a_trickling_server_hits_the_total_deadline():
    class Slow(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            self.send_response(200); self.send_header("Content-Length", "100000"); self.end_headers()
            for _ in range(100):
                try:
                    self.wfile.write(b" "); self.wfile.flush()
                except OSError:
                    return
                time.sleep(0.05)

    srv = _serve(Slow)
    try:
        rb = RemoteBackend(f"http://127.0.0.1:{srv.server_port}", "r", timeout=0.6)
        t = time.monotonic()
        with pytest.raises(RuntimeError):
            rb.approvals()
        assert time.monotonic() - t < 3
    finally:
        srv.shutdown()


# ------------------------------------------------------------------------------------------------ judge --

def test_j1_surface_shortcut_fails_the_gate_and_the_eval_pool_is_held_out():
    from aegis.dataset import judge as J
    from aegis.finetune.judge_gate import _shortcut_judge, _stub_judge, evaluate
    assert not evaluate(_shortcut_judge).passes()
    assert evaluate(_stub_judge).passes()
    assert not set(J._RATIONALES["train"]) & set(J._RATIONALES["eval"])
    assert not set(J._INJECTIONS["train"]) & set(J._INJECTIONS["eval"])
    assert not set(J._PLANTS["train"]) & set(J._PLANTS["eval"])
    import random
    rng = random.Random(3)
    train_ips = {J._own_infra(rng, "train", "") for _ in range(200)}
    eval_ips = {J._own_infra(rng, "eval", "") for _ in range(200)}
    assert len(train_ips) > 100 and not train_ips & eval_ips


def test_j1_training_rows_are_not_separable_by_template_text():
    import random

    from aegis.dataset.judge import build_judge_rows
    from aegis.finetune.judge_gate import _shortcut_judge
    rr = random.Random(1)
    src = []
    for i in range(300):
        v = rr.choice(["malicious", "suspicious", "benign"])
        alert = {"id": f"a{i}", "source_ip": f"203.0.113.{i % 250}", "waf_rule": "sqli"}
        tgt = {"verdict": v, "confidence": round(rr.uniform(.6, .99), 2), "key_signals": ["sig"],
               "rationale": "because evidence", "recommended_actions": []}
        src.append({"id": f"s{i}", "split": "train", "label_source": "human", "messages": [
            {"role": "system", "content": ""}, {"role": "user", "content": json.dumps(alert)},
            {"role": "assistant", "content": json.dumps(tgt)}]})
    rows = build_judge_rows(src)
    ok = sum(json.loads(_shortcut_judge("", r["messages"][1]["content"]))["concur"]
             == json.loads(r["messages"][2]["content"])["concur"] for r in rows)
    assert ok / len(rows) < 0.75                                     # was 800/800 before round 6


def test_j4_injection_and_wrong_buckets_are_scored_separately():
    from aegis.finetune.judge_gate import JudgeGateResult, evaluate
    items = [{"id": f"w{i}", "variant": "flipped", "concur": False, "chain": None} for i in range(10)]
    res = JudgeGateResult()
    res.agree_total = res.agree_ok = 10
    res.dissent_total, res.dissent_ok = 10, 8                      # 80 % on wrong
    res.injection_total = res.injection_ok = 100                   # perfect on injections
    assert not res.passes()
    assert callable(evaluate) and items


def _adapter(d: Path):
    from aegis.finetune.digest import adapter_digest
    d.mkdir(parents=True)
    (d / "adapter_config.json").write_text('{"base_model_name_or_path": "x"}')
    (d / "adapter_model.safetensors").write_bytes(b"w")
    return str(d), adapter_digest(d)


def test_j2_role_mismatch_is_refused(tmp_path, monkeypatch):
    from aegis.agents.shared import llm_client as lc
    monkeypatch.delenv("AEGIS_DECISION_KEY", raising=False)
    monkeypatch.delenv("AEGIS_CONSOLE_TOKEN", raising=False)
    jud, jsha = _adapter(tmp_path / "judge")
    jp = tmp_path / "j.json"; jp.write_text(json.dumps({"run": "j", "role": "judge", "adapter": jud, "sha256": jsha}))
    monkeypatch.setenv("AEGIS_MODEL_POINTER", str(jp))
    assert lc._promoted_model() is None                               # a judge never loads as triage
    monkeypatch.setenv("AEGIS_VOTER_POINTER", str(jp))
    assert lc._promoted_model("AEGIS_VOTER_POINTER") == jud
    tp = tmp_path / "t.json"; tp.write_text(json.dumps({"run": "t", "adapter": jud, "sha256": jsha}))
    monkeypatch.setenv("AEGIS_VOTER_POINTER", str(tp))
    assert lc._promoted_model("AEGIS_VOTER_POINTER") is None          # a triage pointer never loads as the voter


def test_j2_judge_run_refuses_a_triage_runs_dir(tmp_path, capsys):
    from aegis.finetune import retrain as rt
    runs = tmp_path / "runs"
    st = rt.State.load(runs)
    st.runs["retrain-2026-11-01"] = {"role": "triage", "stage": "gated"}
    st.current = {"run": "retrain-2026-11-01", "role": "triage", "adapter": "/x", "sha256": "y"}
    st.save()
    assert rt.main(["run", "--runs", str(runs), "--role", "judge", "--dry-run"]) == 2
    assert "separate --runs" in capsys.readouterr().out


def test_j3_signed_pointer_required_when_a_key_is_set(tmp_path, monkeypatch):
    from aegis.agents.shared import llm_client as lc
    monkeypatch.setenv("AEGIS_DECISION_KEY", "k" * 32)
    monkeypatch.delenv("AEGIS_ALLOW_UNVERIFIED_MODEL", raising=False)
    tri, tsha = _adapter(tmp_path / "tri")
    cur = {"run": "t", "role": "triage", "adapter": tri, "sha256": tsha, "approved_by": "ciso", "promoted_at": "now"}
    p = tmp_path / "current.json"
    p.write_text(json.dumps(cur))
    monkeypatch.setenv("AEGIS_MODEL_POINTER", str(p))
    assert lc._promoted_model() is None                               # unsigned: refused
    p.write_text(json.dumps({**cur, "sig": lc.pointer_signature(cur)}))
    assert lc._promoted_model() == tri
    p.write_text(json.dumps({**cur, "approved_by": "attacker", "sig": lc.pointer_signature(cur)}))
    assert lc._promoted_model() is None                               # altered after signing


def test_j3_retrain_state_save_signs_the_pointer(tmp_path, monkeypatch):
    from aegis.agents.shared import llm_client as lc
    from aegis.finetune import retrain as rt
    monkeypatch.setenv("AEGIS_DECISION_KEY", "k" * 32)
    st = rt.State.load(tmp_path)
    st.current = {"run": "r", "role": "triage", "adapter": "/a", "sha256": "s", "approved_by": "x", "promoted_at": "t"}
    st.save()
    cur = json.loads((tmp_path / "retrain" / "current.json").read_text())
    assert cur["sig"] == lc.pointer_signature(cur)


def test_j3_j5_voter_pointer_must_be_local_and_under_the_root(tmp_path, monkeypatch):
    from aegis.agents.shared import llm_client as lc
    monkeypatch.delenv("AEGIS_DECISION_KEY", raising=False)
    monkeypatch.delenv("AEGIS_CONSOLE_TOKEN", raising=False)
    jud, jsha = _adapter(tmp_path / "root" / "judge")
    jp = tmp_path / "root" / "j.json"; jp.write_text(json.dumps({"run": "j", "role": "judge", "adapter": jud, "sha256": jsha}))
    outside = tmp_path / "elsewhere.json"; outside.write_text(jp.read_text())
    got = []
    monkeypatch.setattr(lc, "get_client", lambda prefer=None, budget=None, model=None, stream=False: got.append((prefer, model)) or object())
    monkeypatch.setenv("AEGIS_POINTER_ROOT", str(tmp_path / "root"))
    monkeypatch.setenv("AEGIS_VOTER_MODELS", f"anthropic:@{jp},vllm:@{jp},local:@{outside},local:@{jp}")
    lc.get_extra_voter_clients()
    assert got == [("local", jud)]


# ------------------------------------------------------------------------------------------------ swarm --

def test_w1_a_hung_worker_does_not_hold_process_exit():
    code = (
        "import time\n"
        "from aegis.agents.orchestrator.swarm import SwarmOrchestrator\n"
        "from aegis.agents.shared.evidence_chain import EvidenceChain\n"
        "class O:\n"
        "    _voter=None\n"
        "    def handle(self, alert): return EvidenceChain(alert_id='a1', investigated_by='perimeter', verdict='malicious', confidence=0.9)\n"
        "def stuck(alert, chain, ctx): time.sleep(30)\n"
        "s = SwarmOrchestrator(O(), workers={'hang': stuck}, max_seconds=0.3)\n"
        "s.handle({'id':'a1'})\n"
        "s.close()\n"
    )
    env = {**os.environ, "PYTHONPATH": os.pathsep.join([str(ROOT), os.environ.get("PYTHONPATH", "")]), "AEGIS_SWARM": "1"}
    t = time.monotonic()
    subprocess.run([sys.executable, "-c", code], env=env, check=True, timeout=25, capture_output=True)
    assert time.monotonic() - t < 10


def test_w1_daemon_pool_semantics():
    from concurrent.futures import wait

    from aegis.agents.orchestrator.swarm import _DaemonPool
    p = _DaemonPool(2)
    fs = [p.submit(lambda x: x * 2, i) for i in range(6)]
    done, _ = wait(fs, timeout=5)
    assert sorted(f.result() for f in done) == [0, 2, 4, 6, 8, 10]
    boom = p.submit(lambda: 1 / 0)
    assert isinstance(boom.exception(timeout=5), ZeroDivisionError)
    ev = threading.Event()
    p.submit(ev.wait, 5); p.submit(ev.wait, 5)
    queued = p.submit(lambda: "late")
    p.shutdown(wait=False, cancel_futures=True)
    assert queued.cancelled()
    ev.set()
    with pytest.raises(RuntimeError):
        p.submit(lambda: 1)
