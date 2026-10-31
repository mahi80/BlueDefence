"""Parallel trainer daemon: the retrain loop on two cadences, driven without a GPU or a subprocess.

The subprocess runner is injected, so these tests never spawn `python -m aegis.finetune.retrain`."""

from __future__ import annotations

from aegis.finetune.trainer_loop import CycleReport, TrainerConfig, TrainerLoop


class FakeRunner:
    """Scripts (rc, out) per retrain subcommand and records every call."""
    def __init__(self, responses=None):
        self.responses = responses or {}
        self.calls: list[list[str]] = []

    def __call__(self, args):
        self.calls.append(list(args))
        r = self.responses.get(args[0], (0, ""))
        return r(args) if callable(r) else r

    def subs(self):
        return [c[0] for c in self.calls]


class Clock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t

    def sleep(self, dt):
        self.t += dt


def _loop(responses=None, cfg=None, runner=None):
    clk = Clock()
    runner = runner or FakeRunner(responses)
    loop = TrainerLoop(cfg or TrainerConfig(runs_dir="/runs"), runner=runner, clock=clk, sleep=clk.sleep)
    return loop, runner, clk


# -- one train cycle: run → shadow → propose --------------------------------

def test_train_cycle_happy_path_proposes():
    loop, runner, _ = _loop({"run": (0, "gate PASS"), "shadow": (0, "ready"), "propose": (0, "proposed")})
    rep = loop.run_once()
    assert rep.stage == "proposed" and rep.proposed is True
    assert rep.run_rc == 0 and rep.shadow_rc == 0 and rep.propose_rc == 0
    assert runner.subs() == ["run", "shadow", "propose"]


def test_train_cycle_skips_when_too_few_new_rows():
    loop, runner, _ = _loop({"run": (0, "  skipped: 3 new analyst rows < 50; nothing to learn yet")})
    rep = loop.run_once()
    assert rep.stage == "skipped_no_rows" and rep.proposed is False
    assert runner.subs() == ["run"]          # no shadow / propose when there's nothing new


def test_train_cycle_stops_on_run_failure():
    loop, runner, _ = _loop({"run": (1, "export failed")})
    rep = loop.run_once()
    assert rep.stage == "run_failed" and runner.subs() == ["run"]


def test_train_cycle_stops_when_candidate_not_better():
    loop, runner, _ = _loop({"run": (0, "gate PASS"), "shadow": (1, "worse")})
    rep = loop.run_once()
    assert rep.stage == "shadow_not_ready" and runner.subs() == ["run", "shadow"]


def test_train_cycle_propose_failure():
    loop, runner, _ = _loop({"run": (0, "gate PASS"), "shadow": (0, "ready"), "propose": (1, "nothing to propose")})
    rep = loop.run_once()
    assert rep.stage == "propose_failed" and rep.proposed is False


def test_train_cycle_error_is_isolated():
    def boom(args):
        raise RuntimeError("subprocess vanished")
    loop, _, _ = _loop({"run": boom})
    rep = loop.run_once()
    assert rep.stage == "error" and "subprocess vanished" in rep.error
    assert loop.train_cycles == 1            # still counted; the daemon survives


# -- arg assembly ------------------------------------------------------------

def test_run_args_include_base_data_and_dashboard_when_set():
    loop, runner, _ = _loop(cfg=TrainerConfig(runs_dir="/runs", base_data="/base", dashboard=True,
                                              preset="qwen3-8b", epochs=2, min_new_rows=50))
    loop.run_once()
    run_args = runner.calls[0]
    assert run_args[:1] == ["run"]
    for flag in ("--runs", "/runs", "--dashboard", "--preset", "qwen3-8b", "--base-data", "/base",
                 "--min-new-rows", "50", "--epochs", "2"):
        assert flag in run_args


def test_run_args_omit_optional_flags_when_unset():
    loop, runner, _ = _loop(cfg=TrainerConfig(runs_dir="/runs", base_data="", dashboard=False))
    loop.run_once()
    run_args = runner.calls[0]
    assert "--dashboard" not in run_args and "--base-data" not in run_args


# -- sync cadence ------------------------------------------------------------

def test_sync_once_ok_and_fail():
    loop, _, _ = _loop({"sync": (0, "promoted retrain-1")})
    assert loop.sync_once().stage == "synced"
    loop2, _, _ = _loop({"sync": (1, "boom")})
    assert loop2.sync_once().stage == "sync_failed"


# -- the daemon loop ---------------------------------------------------------

def test_run_forever_once_runs_single_train_cycle():
    loop, runner, _ = _loop({"run": (0, "gate PASS"), "shadow": (0, "ready"), "propose": (0, "proposed")})
    assert loop.run_forever(once=True) == 0
    assert loop.train_cycles == 1 and loop.sync_cycles == 0


def test_run_forever_schedules_both_cadences_and_stops_at_max():
    cfg = TrainerConfig(runs_dir="/runs", train_interval_s=20.0, sync_interval_s=5.0)
    loop, runner, _ = _loop({"run": (0, "gate PASS"), "shadow": (0, "ready"), "propose": (0, "proposed"),
                             "sync": (0, "ok")}, cfg=cfg)
    loop.run_forever(max_cycles=2)
    assert loop.train_cycles == 2                    # stopped at max_cycles
    assert loop.sync_cycles >= 1                     # sync fired between trains
    assert "run" in runner.subs() and "sync" in runner.subs()


def test_run_forever_survives_a_crashing_cycle():
    def boom(args):
        raise RuntimeError("gpu gone")
    cfg = TrainerConfig(runs_dir="/runs", train_interval_s=1.0, sync_interval_s=100.0)
    loop, _, _ = _loop({"run": boom}, cfg=cfg)
    loop.run_forever(max_cycles=2)                   # two crashing train cycles, loop keeps going
    assert loop.train_cycles == 2
    assert all(h.stage == "error" for h in loop.history if h.kind == "train")


# -- config ------------------------------------------------------------------

def test_from_env_disabled_by_default():
    assert TrainerConfig.from_env(environ={}).enabled is False


def test_from_env_parses():
    cfg = TrainerConfig.from_env(environ={
        "AEGIS_TRAINER_LOOP": "1", "AEGIS_TRAINER_RUNS": "/srv/runs", "AEGIS_TRAINER_BASE_DATA": "/srv/base",
        "AEGIS_TRAINER_PRESET": "qwen3-4b", "AEGIS_TRAINER_EPOCHS": "3", "AEGIS_TRAINER_MIN_ROWS": "100",
        "AEGIS_TRAINER_INTERVAL": "43200", "AEGIS_TRAINER_SYNC_INTERVAL": "120", "AEGIS_TRAINER_DASHBOARD": "0",
    })
    assert cfg.enabled and cfg.runs_dir == "/srv/runs" and cfg.base_data == "/srv/base"
    assert cfg.preset == "qwen3-4b" and cfg.epochs == 3 and cfg.min_new_rows == 100
    assert cfg.train_interval_s == 43200.0 and cfg.sync_interval_s == 120.0 and cfg.dashboard is False


def test_main_refuses_to_daemonize_when_disabled():
    from aegis.finetune.trainer_loop import main
    # not enabled and not --once → refuse (return 2) without spawning anything
    assert main(["--interval", "10"]) == 2


def test_cycle_report_defaults():
    assert CycleReport().kind == "train" and CycleReport().proposed is False


# -- vLLM registration after sync -------------------------------------------

class FakeRegister:
    def __init__(self, ok=True, action="loaded", raises=False):
        self.calls: list[bool] = []
        self.ok, self.action, self.raises = ok, action, raises

    def __call__(self, *, force):
        self.calls.append(force)
        if self.raises:
            raise RuntimeError("vllm down")
        return type("R", (), {"ok": self.ok, "action": self.action})()


def _reg_loop(register_fn, *, vllm_register=True, sync=(0, "ok")):
    clk = Clock()
    cfg = TrainerConfig(runs_dir="/runs", vllm_register=vllm_register)
    loop = TrainerLoop(cfg, runner=FakeRunner({"sync": sync}), register_fn=register_fn,
                       clock=clk, sleep=clk.sleep)
    return loop


def test_sync_registers_promoted_adapter_forcing_first_time():
    fake = FakeRegister()
    loop = _reg_loop(fake)
    assert loop.sync_once().registered == "loaded"
    assert loop.sync_once().registered == "loaded"
    assert fake.calls == [True, False]          # force once on start, then idempotent


def test_sync_does_not_register_when_disabled():
    fake = FakeRegister()
    _reg_loop(fake, vllm_register=False).sync_once()
    assert fake.calls == []


def test_sync_failure_skips_registration():
    fake = FakeRegister()
    rep = _reg_loop(fake, sync=(1, "boom")).sync_once()
    assert rep.stage == "sync_failed" and fake.calls == []


def test_registration_error_does_not_fail_sync():
    fake = FakeRegister(raises=True)
    rep = _reg_loop(fake).sync_once()
    assert rep.stage == "synced" and rep.registered == "error"   # sync still succeeded
