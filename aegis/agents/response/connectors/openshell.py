"""NVIDIA OpenShell — network quarantine for a rogue AI agent running in an OpenShell sandbox.

OpenShell (github.com/NVIDIA/OpenShell, Apache-2.0, alpha) runs AI agents in sandboxes whose outbound traffic is
default-deny and governed by a YAML policy (``network_policies``); credentials are injected only into requests the
policy admits, and the network policy of a RUNNING sandbox can be replaced. That makes it a quarantine control for
AI agents that needs no host isolation: empty the sandbox's ``network_policies`` and the agent can reach nothing —
and, since credentials only ride on admitted requests, it can no longer use them either. Undo restores the saved
policy.

Action: ``isolate`` on a target ``agent:<sandbox-name>`` (or ``sandbox:<name>``). ``isolate`` is SEVERE in the action
contracts, so it never runs unattended: a person approves the quarantine. The connector only ever changes
``network_policies``; filesystem / Landlock / process settings are kept exactly as they were (``openshell policy set``
rejects a file that drops a filesystem path the running sandbox already has).

Talks to the gateway through the ``openshell`` CLI (``policy get`` / ``policy set --wait``) — the documented,
stable surface while the project is alpha. ``AEGIS_AGENT_SANDBOX=openshell`` (binary from ``AEGIS_OPENSHELL_BIN``,
default ``openshell``) or ``mock`` (an in-process fake gateway). The pre-quarantine policy is saved privately (0600)
for the undo; the read-back confirms ``network_policies`` is empty.
"""

from __future__ import annotations

import contextlib
import logging
import os
import re
import subprocess
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

from .base import Connector, ConnectorError, Receipt

logger = logging.getLogger("aegis.connectors.openshell")

#: runner(args) -> (returncode, stdout, stderr); args exclude the binary
Runner = Callable[[list[str]], tuple[int, str, str]]
_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$")
_PREFIXES = ("agent:", "sandbox:")


def _sandbox(target: str) -> str:
    t = str(target).strip()
    for p in _PREFIXES:
        if t.lower().startswith(p):
            t = t[len(p):].strip()
            break
    if not _NAME.match(t):
        raise ConnectorError(f"not an OpenShell sandbox name: {target!r}")
    return t


def cli_runner(binary: str | None = None, timeout: float = 60.0) -> Runner:
    exe = binary or os.environ.get("AEGIS_OPENSHELL_BIN", "openshell")

    def run(args: list[str]) -> tuple[int, str, str]:
        p = subprocess.run([exe, *args], capture_output=True, text=True, timeout=timeout, check=False)  # fixed argv, no shell
        return p.returncode, p.stdout, p.stderr
    return run


class OpenShellConnector(Connector):
    """Quarantine (empty the network policy of) an AI agent's OpenShell sandbox; undo restores it."""

    name = "openshell"
    actions = frozenset({"isolate"})
    # a read-back that sees endpoints back on the policy only REPORTS drift: restoring the saved pre-quarantine policy
    # would re-open endpoints an operator had deliberately left closed (round 6 C-9); a re-approval re-quarantines
    reapply_on_human_approval = True

    def __init__(self, *, runner: Runner | None = None, state_dir: str | Path | None = None, **kw: Any):
        super().__init__(**kw)
        self._run = runner or cli_runner()
        if state_dir is None:
            from aegis.ops.deferred import _private_state_dir
            state_dir = _private_state_dir() / "openshell-policies"
        self._state = Path(state_dir)

    def supports_target(self, target: str) -> bool:
        return str(target).strip().lower().startswith(_PREFIXES)

    # -- gateway
    def _get(self, name: str) -> dict:
        import yaml
        rc, out, err = self._run(["policy", "get", name])
        if rc != 0:
            raise ConnectorError(f"openshell policy get {name} failed: {(err or out).strip()[:200]}")
        try:
            pol = yaml.safe_load(out)
        except yaml.YAMLError as e:
            raise ConnectorError(f"openshell policy get {name}: unreadable policy ({e})") from None
        if not isinstance(pol, dict) or "version" not in pol:
            raise ConnectorError(f"openshell policy get {name}: not a policy document")
        return pol

    def _set(self, name: str, policy: dict) -> None:
        import yaml
        self._state.mkdir(parents=True, exist_ok=True)
        fd, path = tempfile.mkstemp(prefix=f"{name}-", suffix=".yaml", dir=self._state)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                yaml.safe_dump(policy, fh, sort_keys=False)
            rc, out, err = self._run(["policy", "set", name, "--policy", path, "--wait"])
            if rc != 0:
                raise ConnectorError(f"openshell policy set {name} failed: {(err or out).strip()[:200]}")
        finally:
            with contextlib.suppress(OSError):
                os.unlink(path)

    def _save(self, name: str, key: str, policy: dict) -> Path:
        import yaml
        self._state.mkdir(parents=True, exist_ok=True)
        with contextlib.suppress(OSError):
            os.chmod(self._state, 0o700)
        p = self._state / f"{name}.{key[:16]}.pre-quarantine.yaml"
        if p.is_file() and not (policy.get("network_policies") or {}):
            return p                    # re-apply on an already-quarantined sandbox: keep the real original
        fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            yaml.safe_dump(policy, fh, sort_keys=False)
        return p

    # -- connector
    def _do_apply(self, action: Any, key: str, ttl_sec: int | None) -> tuple[str, str, str]:
        name = _sandbox(action.target)
        before = self._get(name)
        allowed = sorted((before.get("network_policies") or {}).keys())
        saved = self._save(name, key, before)
        quarantined = {**before, "network_policies": {}}          # filesystem / landlock / process untouched
        self._set(name, quarantined)
        detail = (f"[openshell] quarantined sandbox {name}: network policy emptied "
                  f"(was {len(allowed)} rule(s): {', '.join(allowed[:6]) or 'none'}); credentials no longer injected")
        return name, detail, str(saved)

    def _do_rollback(self, receipt: Receipt) -> str:
        import yaml
        name = _sandbox(receipt.target)
        p = Path(receipt.rollback_token or "")
        if not p.is_file():
            raise ConnectorError(f"saved pre-quarantine policy for {name} is missing ({p}); restore it by hand")
        before = yaml.safe_load(p.read_text(encoding="utf-8"))
        self._set(name, before)
        with contextlib.suppress(OSError):
            p.unlink()
        return f"[openshell] restored the pre-quarantine network policy of sandbox {name}"

    def _do_verify(self, receipt: Receipt) -> bool | None:
        return not (self._get(_sandbox(receipt.target)).get("network_policies") or {})


class MockOpenShell:
    """In-process fake gateway: ``runner`` for :class:`OpenShellConnector` (tests, ``AEGIS_AGENT_SANDBOX=mock``)."""

    def __init__(self) -> None:
        self.policies: dict[str, dict] = {
            "loan-agent": {"version": 1,
                           "filesystem_policy": {"include_workdir": True, "read_only": ["/usr"], "read_write": ["/sandbox"]},
                           "network_policies": {"llm": {"name": "llm", "endpoints": [{"host": "api.anthropic.com", "port": 443}]},
                                                "core_banking": {"name": "cbs", "endpoints": [{"host": "cbs.bank.internal", "port": 443}]}}}}
        self.calls: list[list[str]] = []

    def __call__(self, args: list[str]) -> tuple[int, str, str]:
        import yaml
        self.calls.append(list(args))
        if args[:2] == ["policy", "get"]:
            pol = self.policies.get(args[2])
            return (0, yaml.safe_dump(pol), "") if pol is not None else (1, "", f"sandbox {args[2]} not found")
        if args[:2] == ["policy", "set"]:
            name, path = args[2], args[args.index("--policy") + 1]
            new = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
            old = self.policies.get(name)
            if old is None:
                return 1, "", f"sandbox {name} not found"
            if set((old.get("filesystem_policy") or {}).get("read_write", [])) - set((new.get("filesystem_policy") or {}).get("read_write", [])):
                return 1, "", "policy drops a filesystem path the running sandbox already has"
            self.policies[name] = new
            return 0, "policy applied", ""
        return 2, "", "unknown command"


def openshell_from_env(runner: Runner | None = None) -> OpenShellConnector | None:
    """``AEGIS_AGENT_SANDBOX=openshell | mock`` (default off)."""
    vendor = os.environ.get("AEGIS_AGENT_SANDBOX", "off").strip().lower()
    if vendor in ("", "off", "0", "none"):
        return None
    if vendor == "mock":
        return OpenShellConnector(runner=runner or MockOpenShell())
    if vendor == "openshell":
        return OpenShellConnector(runner=runner)
    logger.warning("[openshell] unknown AEGIS_AGENT_SANDBOX=%r (openshell | mock)", vendor)
    return None


__all__ = ["MockOpenShell", "OpenShellConnector", "cli_runner", "openshell_from_env"]
