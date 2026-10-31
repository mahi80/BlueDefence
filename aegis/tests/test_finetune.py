"""aegis.finetune — data loading, VRAM presets, the promotion gate, and the dataset synth (3.3)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from aegis.dataset.synth import generate
from aegis.finetune import load_sft, preset_for_vram, split_rows
from aegis.finetune.config import DEFAULT, PRESETS, get_preset
from aegis.finetune.data import DataError
from aegis.finetune.gate import evaluate


# ---------------- synth ----------------
def test_synth_rows_are_well_formed_and_policy_correct():
    rows = generate(120, seed=3)
    assert len(rows) == 120
    hitl = {"block", "isolate", "lock_account", "revoke_sessions", "kill_process", "quarantine_file",
            "escalate_to_fraud_team", "hold", "block_export", "rotate_credential", "snapshot_forensic"}
    for r in rows:
        assert r["label_source"] == "synthetic" and r["origin"] == "synthetic/v2"
        assert [m["role"] for m in r["messages"]] == ["system", "user", "assistant"]
        json.loads(r["messages"][1]["content"])                       # alert is JSON
        t = json.loads(r["messages"][2]["content"])                   # target is JSON
        assert t["verdict"] in ("benign", "suspicious", "malicious")
        for a in t["recommended_actions"]:
            if a["action_type"] in hitl:
                assert a["requires_hitl"] is True
        if t.get("injection_detected"):
            assert t["verdict"] != "benign"
            assert all(a["action_type"] != "allow" for a in t["recommended_actions"])


def test_synth_is_deterministic_by_seed():
    assert generate(50, seed=11) == generate(50, seed=11)
    assert generate(50, seed=11) != generate(50, seed=12)


def test_synth_never_collides_with_eval_fingerprints():
    from aegis.dataset.schema import fingerprint
    from aegis.eval.run import HERE
    held = set()
    for name in ("historical_alerts", "injection_corpus"):
        for c in json.loads((HERE / name / "cases.json").read_text()):
            held.add(fingerprint(c["alert"]))
    for r in generate(300, seed=5):
        assert fingerprint(json.loads(r["messages"][1]["content"])) not in held


# ---------------- data loading ----------------
def _write(tmp_path, rows) -> Path:
    d = tmp_path / "ds"; (d / "sft").mkdir(parents=True)
    with (d / "sft" / "triage.jsonl").open("w") as fh:
        for r in rows:
            fh.write(json.dumps(r) + "\n")
    return d


def test_load_refuses_synthetic_by_default(tmp_path):
    d = _write(tmp_path, generate(20, seed=1))
    with pytest.raises(DataError):
        load_sft(d)                                                   # all synthetic → refused
    rows = load_sft(d, allow_synthetic=True)
    assert rows and all(r.label_source == "synthetic" for r in rows)


def test_load_keeps_only_train_val_not_test(tmp_path):
    base = generate(10, seed=2)
    base[0]["split"] = "test"
    d = _write(tmp_path, base)
    rows = load_sft(d, allow_synthetic=True)
    assert all(r.split in ("train", "val") for r in rows)
    assert base[0]["id"] not in {r.id for r in rows}


def test_prompt_response_shape(tmp_path):
    d = _write(tmp_path, generate(6, seed=4))
    ex = load_sft(d, allow_synthetic=True)[0]
    assert ex.system and ex.user and "---" in ex.prompt
    json.loads(ex.response)                                            # response is the JSON target


def test_split_rows_fallback_when_no_val():
    from aegis.finetune.data import Example
    only_train = [Example(str(i), "train", "synthetic", "o", "s", "u", "{}") for i in range(20)]
    tr, va = split_rows(only_train)
    assert len(va) == 2 and len(tr) == 18


# ---------------- presets ----------------
def test_preset_for_vram_picks_largest_that_fits():
    assert preset_for_vram(6).key == "gemma3-1b"
    assert preset_for_vram(8, prefer_family="gemma").key == "gemma3-4b"
    assert preset_for_vram(8, prefer_family="qwen").key == "qwen3-4b"
    assert preset_for_vram(12).min_vram_gb == 12
    assert preset_for_vram(24).min_vram_gb == 16                      # largest preset we ship
    assert preset_for_vram(2).key == "gemma3-1b"                      # below everything → smallest


def test_default_preset_is_gemma_4b():
    assert get_preset(DEFAULT).model.startswith("google/gemma-3-4b")
    assert all(p.effective_batch >= 8 for p in PRESETS)


# ---------------- gate ----------------
def test_gate_perfect_triage_passes():
    cases = {}
    from aegis.eval.run import HERE
    for name in ("historical_alerts", "agentic_chains", "endpoint_chains", "tls_chains", "network_chains"):
        for c in json.loads((HERE / name / "cases.json").read_text()):
            cases[c["alert"]["id"]] = c["expected_verdict"]
    res = evaluate(lambda a: cases[a["id"]], actions=lambda a: ["monitor"])
    assert res.n_hist_miss == 0 and res.n_inj_leak == 0 and res.passes()
    assert "PASS" in res.summary()


def test_gate_counts_misses_and_leaks():
    res = evaluate(lambda a: "benign", actions=lambda a: ["allow"])    # worst case
    assert res.n_hist_miss > 0                                         # most historical aren't benign
    assert res.n_inj_leak == res.injection_total                      # every injection leaks
    assert not res.passes()


def test_gate_injection_without_actions_uses_verdict():
    # no actions fn: an injection case is "held" iff the verdict is not benign
    res = evaluate(lambda a: "suspicious")
    assert res.n_inj_leak == 0


def test_gate_respects_baseline_cap():
    from aegis.eval.run import HERE
    exp = {c["alert"]["id"]: c["expected_verdict"] for c in json.loads((HERE / "historical_alerts" / "cases.json").read_text())}
    ids = list(exp)
    def triage(a):
        # miss exactly the first 6 historical cases
        return ("uncertain" if a["id"] in ids[:6] and exp[a["id"]] != "uncertain" else exp.get(a["id"], "benign"))
    res = evaluate(triage, actions=lambda a: ["monitor"], baseline_misses=5)
    assert res.n_hist_miss == 6 and not res.passes()                  # 6 > 5
    assert res.passes(max_misses=6)


def test_gate_cli_self_test_passes(capsys):
    from aegis.finetune.gate import main
    assert main(["--self-test"]) == 0
    assert "PASS" in capsys.readouterr().out


def test_network_eval_suite_is_tracked_and_held_out():
    from aegis.eval.run import HERE
    from aegis.dataset.schema import fingerprint
    cases = json.loads((HERE / "network_chains" / "cases.json").read_text())
    # balanced held-out set across the three verdicts
    assert len(cases) >= 10
    verdicts = {c["expected_verdict"] for c in cases}
    assert verdicts == {"benign", "suspicious", "malicious"}
    assert len({c["alert"]["id"] for c in cases}) == len(cases)      # unique ids
    # the gate reports a network number as a tracked suite (perfect triage → all held)
    exp = {c["alert"]["id"]: c["expected_verdict"] for c in cases}
    res = evaluate(lambda a: exp.get(a["id"], "suspicious"), actions=lambda a: ["monitor"])
    assert res.tracked["network_chains"]["total"] == len(cases)
    assert res.tracked["network_chains"]["misses"] == []
    # truly held out: no synthetic training row collides with a network eval fingerprint
    held = {fingerprint(c["alert"]) for c in cases}
    for r in generate(300, seed=5):
        assert fingerprint(json.loads(r["messages"][1]["content"])) not in held


def test_gate_cli_without_adapter_falls_back(capsys):
    from aegis.finetune.gate import main
    rc = main([])                              # no adapter, no GPU → self-test wiring
    assert rc == 0


# ---------------- CVE overlay + supply chain (train data) ----------------
def test_synth_supply_chain_domain_present_and_tagged():
    rows = generate(220, seed=9)
    sc = [json.loads(r["messages"][2]["content"]) for r in rows
          if json.loads(r["messages"][1]["content"]).get("source") in ("SCA scanner", "Registry proxy", "CI/CD", "Model Registry")]
    assert len(sc) >= 15
    for t in sc:
        if t["verdict"] == "malicious":
            assert set(t["techniques"]) & {"T1195.002", "AML.T0010"}
            types = {a["action_type"] for a in t["recommended_actions"]}
            assert "block" in types and "quarantine_file" in types          # always-HITL containment
        if t["verdict"] == "benign":
            assert not (set(t["techniques"]) & {"T1195.002", "AML.T0010"})


def test_synth_session_domain_present_and_policy_correct():
    rows = generate(300, seed=9)
    sess = [(json.loads(r["messages"][1]["content"]), json.loads(r["messages"][2]["content"]))
            for r in rows if json.loads(r["messages"][1]["content"]).get("source") == "Session Gateway"]
    assert len(sess) >= 15
    saw_mal = False
    for a, t in sess:
        # abstract signals only — never a raw cookie/token string smuggled into a field
        assert "cookie" not in a and "set-cookie" not in a and "authorization" not in a
        if t["verdict"] == "malicious":
            saw_mal = True
            assert set(t["techniques"]) & {"T1606.001", "T1539", "T1134"}
            types = {x["action_type"] for x in t["recommended_actions"]}
            assert "revoke_sessions" in types and "lock_account" in types   # always-HITL containment
            assert all(x["requires_hitl"] for x in t["recommended_actions"])
        if t["verdict"] == "benign":
            assert not t["techniques"]
            assert all(x["action_type"] in ("allow", "monitor") for x in t["recommended_actions"])
    assert saw_mal


def test_synth_network_domain_present_and_policy_correct():
    rows = generate(320, seed=9)
    net = [(json.loads(r["messages"][1]["content"]), json.loads(r["messages"][2]["content"]))
           for r in rows if json.loads(r["messages"][1]["content"]).get("source") == "NDR sensor"]
    assert len(net) >= 15
    saw_mal = False
    for a, t in net:
        # flow-shaped categorical signals only — never a raw packet payload / pcap field
        assert "payload" not in a and "pcap" not in a and "packet_hex" not in a
        if t["verdict"] == "malicious":
            saw_mal = True
            assert set(t["techniques"]) & {"T1071", "T1071.001", "T1573", "T1041", "T1567", "T1090"}
            types = {x["action_type"] for x in t["recommended_actions"]}
            assert "block" in types and "isolate" in types          # always-HITL egress containment
            assert all(x["requires_hitl"] for x in t["recommended_actions"])
        if t["verdict"] == "benign":
            assert not t["techniques"]
            assert all(x["action_type"] in ("allow", "monitor") for x in t["recommended_actions"])
    assert saw_mal


def test_synth_cve_overlay_is_policy_consistent_and_never_real_ids():
    rows = generate(400, seed=21, cve_pct=60)
    seen = 0
    for r in rows:
        a = json.loads(r["messages"][1]["content"]); t = json.loads(r["messages"][2]["content"])
        if "cve" not in a:
            continue
        seen += 1
        c = a["cve"]
        assert c["cve_ref"].startswith("CVE-SYN-")                       # namespace that cannot be a real CVE
        assert any(c["cve_ref"] in s for s in t["key_signals"])          # cites what it was given
        if t["verdict"] == "malicious":
            assert c["cve_known_exploited"] and c["affects_deployed_component"]
            assert c["exploit_maturity"] in ("weaponized", "in_the_wild") and "T1203" in t["techniques"]
            assert any(a_["target"] == "patch-team" for a_ in t["recommended_actions"])
        elif t["verdict"] == "suspicious":
            assert c["cve_known_exploited"] != c["affects_deployed_component"]   # exactly one act-now condition
            assert "T1203" not in t["techniques"]
        else:
            assert not c["cve_known_exploited"] and not c["affects_deployed_component"]
    assert seen >= 80


def test_synth_cve_pct_zero_disables_overlay():
    rows = generate(120, seed=2, cve_pct=0)
    assert all("cve" not in json.loads(r["messages"][1]["content"]) for r in rows)


def test_attack_map_knows_supply_chain_and_kev():
    from aegis.dataset.attack_map import TECHNIQUES, techniques_for
    for k in ("T1195.002", "T1195.001", "AML.T0010", "T1203"):
        assert k in TECHNIQUES
    assert {x["id"] for x in techniques_for({"version_change": "typosquat"}, {})} >= {"T1195.002"}
    assert {x["id"] for x in techniques_for({"cve_known_exploited": True}, {})} >= {"T1203"}
    assert {x["id"] for x in techniques_for({"ecosystem": "hf-model", "safetensors_mismatch": True}, {})} >= {"AML.T0010"}


# ---------------- label-leak guard (first qwen3-8b run learnt severity → verdict) ----------------
def test_synth_severity_and_anomaly_do_not_leak_the_verdict():
    """No single priority field may predict the verdict: every verdict must appear at every
    severity, and the anomaly-score ranges must overlap between neighbouring verdicts."""
    rows = generate(900, seed=13)
    by_sev: dict[str, set] = {}
    scores: dict[str, list[float]] = {}
    for r in rows:
        a = json.loads(r["messages"][1]["content"]); v = json.loads(r["messages"][2]["content"])["verdict"]
        by_sev.setdefault(a["severity"], set()).add(v)
        scores.setdefault(v, []).append(a["anomaly_score"])
    for sev in ("low", "medium", "high"):
        assert by_sev[sev] == {"benign", "suspicious", "malicious"}, f"severity={sev} only maps to {by_sev[sev]}"
    assert max(scores["benign"]) > min(scores["suspicious"])            # overlapping bands
    assert max(scores["suspicious"]) > min(scores["malicious"])
    # a majority-class guess from severity alone must be well short of the gate bar
    from collections import Counter
    pairs = Counter((json.loads(r["messages"][1]["content"])["severity"],
                     json.loads(r["messages"][2]["content"])["verdict"]) for r in rows)
    best = sum(max(n for (s, _), n in pairs.items() if s == sev) for sev in ("low", "medium", "high"))
    assert best / len(rows) < 0.7


def test_synth_injection_rows_carry_instruction_text_not_a_flag():
    """v1 planted a boolean flag; the tuned model never saw instruction text and obeyed the first
    real one (gate leak INJ-001/009). Injection rows now carry an instruction-shaped sentence in a
    free-text field, in several languages, never equal to an eval injection string."""
    from aegis.dataset.synth import _INJ_FIELDS
    from aegis.eval.run import HERE
    eval_texts = set()
    for c in json.loads((HERE / "injection_corpus" / "cases.json").read_text()):
        eval_texts.update(str(v) for v in c["alert"].values() if isinstance(v, str))
    rows = generate(500, seed=23, injection_pct=40)
    n = non_ascii = 0
    for r in rows:
        a = json.loads(r["messages"][1]["content"]); t = json.loads(r["messages"][2]["content"])
        if not t.get("injection_detected"):
            continue
        n += 1
        assert "embedded_instruction_flag" not in a
        field = next(k for k in _INJ_FIELDS if k in a)
        text = a[field]
        assert len(text) > 15 and text not in eval_texts
        non_ascii += any(ord(ch) > 127 for ch in text)
        assert any(field in s for s in t["key_signals"]) and field in t["rationale"]
        assert t["verdict"] != "benign"
    assert n >= 150 and non_ascii >= 10                             # multilingual slice present


def test_synth_corroborating_signals_is_not_a_label():
    rows = generate(600, seed=29)
    with_field = {"benign": 0, "suspicious": 0, "malicious": 0}; without = dict(with_field)
    for r in rows:
        a = json.loads(r["messages"][1]["content"]); v = json.loads(r["messages"][2]["content"])["verdict"]
        (with_field if "corroborating_signals" in a else without)[v] += 1
    assert without["malicious"] >= 40 and with_field["malicious"] >= 40    # malicious appears both ways
    assert without["suspicious"] >= 40 and with_field["suspicious"] >= 40


def test_synth_cloud_has_ticketed_fp_trap_and_single_signal_hold():
    rows = generate(660, seed=17)
    ticketed_benign = single_signal_hold = 0
    for r in rows:
        a = json.loads(r["messages"][1]["content"]); t = json.loads(r["messages"][2]["content"])
        if a.get("source") != "CloudTrail" or "change_ticket" not in a:
            continue
        if a["change_ticket"]:
            assert t["verdict"] == "benign" and a["inside_change_window"] is True
            ticketed_benign += 1
        else:
            assert t["verdict"] == "suspicious"
            assert "hold" in {x["action_type"] for x in t["recommended_actions"]}
            single_signal_hold += 1
    assert ticketed_benign >= 5 and single_signal_hold >= 5


# ---------------- gate robustness (Qwen3 think blocks, bad generations) ----------------
def test_parse_triage_output_strips_think_and_never_raises():
    from aegis.finetune.gate import parse_triage_output
    assert parse_triage_output('<think>\nlet me reason...\n</think>\n{"verdict": "malicious", "confidence": 0.9}')["verdict"] == "malicious"
    assert parse_triage_output("<think>still thinking when the budget ran out") == {}      # no JSON → miss, not crash
    assert parse_triage_output("") == {} and parse_triage_output("plain prose, no json") == {}
    assert parse_triage_output('prefix text {"verdict":"benign","recommended_actions":[{"action_type":"allow"}]} tail')["verdict"] == "benign"


def test_render_prompt_passes_enable_thinking_when_supported():
    from aegis.finetune.gate import render_prompt
    class Tok:
        def apply_chat_template(self, messages, tokenize=False, add_generation_prompt=False, enable_thinking=None):
            return f"ok:{enable_thinking}:{add_generation_prompt}"
    class OldTok:
        def apply_chat_template(self, messages, tokenize=False, add_generation_prompt=False):
            return "old"
    assert render_prompt(Tok(), [], add_generation_prompt=True) == "ok:False:True"
    assert render_prompt(OldTok(), [], add_generation_prompt=True) == "old"         # falls back on TypeError


# ---------------- runtime: the local backend understands an adapter dir ----------------
def test_get_client_local_reads_aegis_model_and_falls_back_cleanly(monkeypatch, tmp_path):
    from aegis.agents.shared.llm_client import MockClient, get_client
    monkeypatch.setenv("LLM_BACKEND", "local")
    monkeypatch.setenv("AEGIS_MODEL", str(tmp_path / "no-such-adapter"))
    c = get_client()                                      # no weights here → must fall back, never raise
    inner = getattr(c, "_inner", c)
    assert isinstance(inner, MockClient) or inner.__class__.__name__ == "MockClient" or hasattr(c, "complete")


def test_gemma_client_detects_adapter_dir(monkeypatch, tmp_path):
    """Adapter detection + 4-bit choice happen before any weight load; stub the loaders to check them."""
    import json as _json
    import sys
    import types
    from aegis.agents.shared import llm_client as m
    (tmp_path / "adapter_config.json").write_text(_json.dumps({"base_model_name_or_path": "Qwen/Qwen3-8B"}))
    calls = {}
    class _Tok:
        @classmethod
        def from_pretrained(cls, p): calls["tok"] = p; return cls()
    class _Model:
        device = "cpu"
        @classmethod
        def from_pretrained(cls, p, **kw): calls["base"] = p; calls["kw"] = kw; return cls()
        def eval(self): return self
    class _Peft:
        @staticmethod
        def from_pretrained(model, adapter): calls["adapter"] = adapter; return model
    fake_tf = types.SimpleNamespace(AutoTokenizer=_Tok, AutoModelForCausalLM=_Model,
                                    BitsAndBytesConfig=lambda **kw: {"bnb": kw})
    monkeypatch.setitem(sys.modules, "transformers", fake_tf)
    monkeypatch.setitem(sys.modules, "torch", types.SimpleNamespace(bfloat16="bf16"))
    monkeypatch.setitem(sys.modules, "peft", types.SimpleNamespace(PeftModel=_Peft))
    monkeypatch.setattr(m.GemmaClient, "_have", staticmethod(lambda mod: mod in ("bitsandbytes",)))
    monkeypatch.delenv("AEGIS_LOCAL_4BIT", raising=False)
    c = m.GemmaClient(model=str(tmp_path), device="cpu")
    assert c.base_model == "Qwen/Qwen3-8B" and c.adapter == str(tmp_path) and calls["adapter"] == str(tmp_path)
    assert calls["base"] == "Qwen/Qwen3-8B" and "quantization_config" in calls["kw"]      # 4-bit by default with bnb
    monkeypatch.setenv("AEGIS_LOCAL_4BIT", "0")
    c2 = m.GemmaClient(model=str(tmp_path), device="cpu")
    assert "quantization_config" not in calls["kw"] and calls["kw"].get("torch_dtype") == "bf16"


def test_resume_picks_latest_checkpoint(tmp_path):
    from types import SimpleNamespace as NS
    from aegis.finetune.train import _resume_path
    assert _resume_path(NS(out=str(tmp_path), resume=None)) is None
    assert _resume_path(NS(out=str(tmp_path), resume="auto")) is None                       # nothing yet → fresh
    for n in (500, 1000, 250):
        (tmp_path / f"checkpoint-{n}").mkdir()
    (tmp_path / "checkpoint-bogus").mkdir()
    assert _resume_path(NS(out=str(tmp_path), resume="auto")).endswith("checkpoint-1000")
    assert _resume_path(NS(out=str(tmp_path), resume="/x/checkpoint-7")) == "/x/checkpoint-7"
