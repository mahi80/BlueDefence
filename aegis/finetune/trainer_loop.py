"""Parallel self-evolving trainer daemon — run the retrain loop beside the SOC, not by hand.

``retrain.py`` is a one-shot CLI (export→build→train→gate→shadow→propose→sync). Until now the
only "scheduler" was a documented weekly cron line, and nothing applied an approval to the live
model between restarts. This daemon closes both: it runs as its OWN process (a GPU fine-tune
must never block the triage loop), on TWO independent cadences —

  * **train cadence** (slow, default daily): ``run`` → ``shadow`` → ``propose``. Produces a new
    ``model_promotion`` proposal in the dashboard approvals queue when a freshly trained candidate
    passes the gate and beats the current model in shadow. Skips cleanly when there aren't enough
    new analyst rows to learn from (retrain's own ``--min-new-rows`` guard).
  * **sync cadence** (fast, default 5 min): ``sync``. Applies an analyst-approved promotion to the
    promotion pointer (``current.json``) promptly, so the SOC's hot-reload (AEGIS_HOT_RELOAD) picks
    it up on its next cycle — approve in the dashboard, live within minutes, no restart.

Each retrain step runs as a SUBPROCESS (``python -m aegis.finetune.retrain …``) for process
isolation: a GPU OOM or a crash in training kills that subprocess, not the daemon. The subprocess
runner is injectable, so the whole loop — cadences, the skip/fail/ready branches, error isolation
— is unit-tested with no GPU, no subprocess and no network.

Run it:  ``python -m aegis.finetune.trainer_loop``  (or ``--once`` for a single train cycle).
Config is env-driven (``AEGIS_TRAINER_*``); it runs on the GPU host next to the vLLM server.
"""

from __future__ import annotations

import argparse
import logging
import os
import signal
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional

logger = logging.getLogger("aegis.finetune.trainer")

#: runner(args) -> (returncode, combined_output). Injectable so tests never spawn a process.
Runner = Callable[[list[str]], "tuple[int, str]"]

DEFAULT_TRAIN_INTERVAL = 86400.0     # daily
DEFAULT_SYNC_INTERVAL = 300.0        # 5 min
_SKIP_MARKER = "skipped:"            # cmd_run prints this (rc 0) when there are too few new rows


def _truthy(v: str) -> bool:
    return v.strip().lower() in ("1", "true", "yes", "on")


@dataclass
class TrainerConfig:
    runs_dir: str = "~/aegis-runs"
    base_data: str = ""
    preset: str = "qwen3-8b"
    epochs: int = 2
    min_new_rows: int = 50
    dashboard: bool = True
    vllm_register: bool = False                    # after sync, load the promoted LoRA into vLLM so set_model resolves
    train_interval_s: float = DEFAULT_TRAIN_INTERVAL
    sync_interval_s: float = DEFAULT_SYNC_INTERVAL
    subprocess_timeout_s: float = 6 * 3600.0      # a train run can be long; cap it anyway
    enabled: bool = False

    @classmethod
    def from_env(cls, environ: Optional[dict] = None) -> "TrainerConfig":
        env = dict(os.environ if environ is None else environ)

        def _f(name: str, default: float) -> float:
            try:
                return float(env.get(name, "").strip() or default)
            except (TypeError, ValueError):
                return default

        def _i(name: str, default: int) -> int:
            return int(_f(name, float(default)))

        return cls(
            runs_dir=env.get("AEGIS_TRAINER_RUNS", "").strip() or "~/aegis-runs",
            base_data=env.get("AEGIS_TRAINER_BASE_DATA", "").strip(),
            preset=env.get("AEGIS_TRAINER_PRESET", "").strip() or "qwen3-8b",
            epochs=_i("AEGIS_TRAINER_EPOCHS", 2),
            min_new_rows=_i("AEGIS_TRAINER_MIN_ROWS", 50),
            dashboard=_truthy(env.get("AEGIS_TRAINER_DASHBOARD", "1")),
            vllm_register=_truthy(env.get("AEGIS_VLLM_REGISTER", "0")),
            train_interval_s=_f("AEGIS_TRAINER_INTERVAL", DEFAULT_TRAIN_INTERVAL),
            sync_interval_s=_f("AEGIS_TRAINER_SYNC_INTERVAL", DEFAULT_SYNC_INTERVAL),
            subprocess_timeout_s=_f("AEGIS_TRAINER_TIMEOUT", 6 * 3600.0),
            enabled=_truthy(env.get("AEGIS_TRAINER_LOOP", "0")),
        )


@dataclass
class CycleReport:
    """Outcome of one train cycle. ``stage`` is where it stopped; ``proposed`` means a proposal shipped."""
    kind: str = "train"
    stage: str = ""              # run_failed | skipped_no_rows | shadow_not_ready | propose_failed | proposed
    run_rc: Optional[int] = None
    shadow_rc: Optional[int] = None
    propose_rc: Optional[int] = None
    proposed: bool = False
    registered: str = ""         # on a sync cycle: the vLLM-register action (loaded|already|skipped|error)
    error: str = ""
    seconds: float = 0.0


class TrainerLoop:
    def __init__(self, config: TrainerConfig, *, runner: Optional[Runner] = None,
                 register_fn: Optional[Callable[..., Any]] = None,
                 clock: Callable[[], float] = time.monotonic, sleep: Callable[[float], None] = time.sleep):
        self.config = config
        self._runner = runner or self._subprocess_runner
        self._register_fn = register_fn            # inject to test registration without a server
        self._registry = None
        self._registered_once = False
        self._clock = clock
        self._sleep = sleep
        self._stop = False
        self.train_cycles = 0
        self.sync_cycles = 0
        self.history: list[Any] = []

    # -- CLI arg assembly
    def _common(self) -> list[str]:
        args = ["--runs", self.config.runs_dir]
        if self.config.dashboard:
            args.append("--dashboard")
        return args

    def _run_args(self) -> list[str]:
        args = ["run", *self._common(), "--preset", self.config.preset,
                "--epochs", str(self.config.epochs), "--min-new-rows", str(self.config.min_new_rows)]
        if self.config.base_data:
            args += ["--base-data", self.config.base_data]
        return args

    def _shadow_args(self) -> list[str]:
        return ["shadow", *self._common()]

    def _propose_args(self) -> list[str]:
        return ["propose", *self._common()]

    def _sync_args(self) -> list[str]:
        return ["sync", *self._common()]

    # -- the two units of work
    def run_once(self) -> CycleReport:
        """One train cycle: run → shadow → propose, stopping at the first stage that has nothing to pass on."""
        t0 = self._clock()
        rep = CycleReport(kind="train")
        try:
            rep.run_rc, out = self._runner(self._run_args())
            if rep.run_rc != 0:
                rep.stage = "run_failed"
                return rep
            if _SKIP_MARKER in (out or ""):
                rep.stage = "skipped_no_rows"      # retrain found too few new analyst rows — nothing to learn yet
                return rep
            rep.shadow_rc, _ = self._runner(self._shadow_args())
            if rep.shadow_rc != 0:
                rep.stage = "shadow_not_ready"      # candidate did not beat the current model
                return rep
            rep.propose_rc, _ = self._runner(self._propose_args())
            rep.proposed = rep.propose_rc == 0
            rep.stage = "proposed" if rep.proposed else "propose_failed"
            return rep
        except Exception as exc:  # noqa: BLE001 — one bad cycle must not kill the daemon
            rep.error = str(exc)[:200]
            rep.stage = "error"
            logger.warning("[trainer] train cycle error: %s", rep.error)
            return rep
        finally:
            rep.seconds = self._clock() - t0
            self.train_cycles += 1
            self.history.append(rep)
            del self.history[:-200]
            logger.info("[trainer] train cycle %d: stage=%s proposed=%s (%.0fs)",
                        self.train_cycles, rep.stage, rep.proposed, rep.seconds)

    def sync_once(self) -> CycleReport:
        """Apply any analyst-approved promotion to the pointer, then (opt-in) load the promoted
        adapter into vLLM so the SOC's set_model resolves it. Cheap; no GPU work here."""
        rep = CycleReport(kind="sync")
        try:
            rc, _ = self._runner(self._sync_args())
            rep.run_rc = rc
            rep.stage = "synced" if rc == 0 else "sync_failed"
            if rc == 0 and self.config.vllm_register:
                rep.registered = self._register_promoted()
        except Exception as exc:  # noqa: BLE001
            rep.error = str(exc)[:200]
            rep.stage = "error"
            logger.warning("[trainer] sync error: %s", rep.error)
        finally:
            self.sync_cycles += 1
            self.history.append(rep)
            del self.history[:-200]
        return rep

    def _register_promoted(self) -> str:
        """Register the just-promoted LoRA with vLLM (force once on start — a vLLM restart loses
        loaded adapters). Never fails the sync: a registration hiccup is logged and retried next cycle."""
        try:
            fn = self._register_fn or self._default_register
            res = fn(force=not self._registered_once)
            if getattr(res, "ok", False):
                self._registered_once = True
            return getattr(res, "action", "error")
        except Exception as exc:  # noqa: BLE001
            logger.warning("[trainer] vLLM register failed: %s", str(exc)[:200])
            return "error"

    def _default_register(self, *, force: bool):
        from aegis.finetune.vllm_registry import VLLMAdapterRegistry, register_promoted_adapter
        if self._registry is None:
            self._registry = VLLMAdapterRegistry()
        return register_promoted_adapter(self._registry, force=force)

    def stop(self, *_: Any) -> None:
        self._stop = True

    def run_forever(self, *, once: bool = False, max_cycles: int = 0) -> int:
        """Schedule train + sync on their own cadences until stopped. ``once`` runs a single train
        cycle and returns (the smoke-test path)."""
        for sig in (signal.SIGTERM, signal.SIGINT):
            try:
                signal.signal(sig, self.stop)
            except (ValueError, OSError):      # not the main thread (tests)
                pass
        logger.info("[trainer] daemon up — train every %.0fs, sync every %.0fs, runs=%s preset=%s",
                    self.config.train_interval_s, self.config.sync_interval_s, self.config.runs_dir, self.config.preset)
        if once:
            self.run_once()
            return 0
        now = self._clock()
        next_train = now                       # train immediately on start, then on cadence
        next_sync = now + self.config.sync_interval_s
        while not self._stop:
            now = self._clock()
            if now >= next_sync:
                self.sync_once()
                next_sync = now + self.config.sync_interval_s
            if now >= next_train:
                self.run_once()
                next_train = now + self.config.train_interval_s
                if max_cycles and self.train_cycles >= max_cycles:
                    break
            # wake at the next due task, but not for so long that stop is slow to take
            delay = max(0.0, min(next_sync, next_train) - self._clock())
            self._sleep(min(delay, 5.0) if delay else 0.0)
        logger.info("[trainer] daemon stopped after %d train / %d sync cycle(s)", self.train_cycles, self.sync_cycles)
        return 0

    # -- default transport: an isolated subprocess per retrain step
    def _subprocess_runner(self, args: list[str]) -> "tuple[int, str]":
        cmd = [sys.executable, "-m", "aegis.finetune.retrain", *args]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True,
                                  timeout=self.config.subprocess_timeout_s, check=False)
            out = (proc.stdout or "") + (proc.stderr or "")
            if proc.returncode != 0:
                logger.warning("[trainer] %s exited %d: %s", args[0], proc.returncode, out[-300:])
            return proc.returncode, out
        except subprocess.TimeoutExpired:
            logger.error("[trainer] %s timed out after %.0fs", args[0], self.config.subprocess_timeout_s)
            return 124, "timeout"
        except Exception as exc:  # noqa: BLE001 — a spawn failure is a cycle failure, not a daemon crash
            logger.error("[trainer] %s could not run: %s", args[0], str(exc)[:200])
            return 1, str(exc)[:200]


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="AEGIS parallel self-evolving trainer daemon (roadmap C3.2).")
    ap.add_argument("--once", action="store_true", help="run a single train cycle and exit (smoke test)")
    ap.add_argument("--interval", type=float, default=None, help="override the train cadence (seconds)")
    ap.add_argument("--sync-interval", type=float, default=None, help="override the sync cadence (seconds)")
    a = ap.parse_args(argv)
    cfg = TrainerConfig.from_env()
    if a.interval is not None:
        cfg.train_interval_s = a.interval
    if a.sync_interval is not None:
        cfg.sync_interval_s = a.sync_interval
    if not cfg.enabled and not a.once:
        logger.error("[trainer] AEGIS_TRAINER_LOOP is not set — refusing to run the daemon (pass --once to force one cycle)")
        return 2
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    return TrainerLoop(cfg).run_forever(once=a.once)


if __name__ == "__main__":
    sys.exit(main())
