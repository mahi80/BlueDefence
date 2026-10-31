"""Per-host-class baselines / allowlists for the EDR host scorers.

``autostart_persistence``, ``ssh_key_added`` and ``tcc_grant`` compare observed
state against a known-good baseline — and that baseline is host-class specific:
a Linux web node, a Windows workstation and a macOS laptop have different
legitimate autostart entries, deploy keys and privacy grants. An alert carries
``host_class`` and ``run_all_tools`` looks the profile up here.

Profiles are seeded (``host_baselines.json``) with realistic starter
values; production extends them per golden image under change control, ideally
fed by the Inventory agent. Until a class is baselined, it falls back to
``_default`` (empty allow — everything new is flagged), which is the safe
shadow-mode posture.
"""
from __future__ import annotations

import json
import os
import pathlib
import re

_DATA = pathlib.Path(__file__).parent / "host_baselines.json"
_DEFAULT_CLASS = "_default"
_USER_SEG = re.compile(r"\\users\\[^\\]+\\")


def _merge_profiles(base: dict, extra: dict) -> dict:
    """Additive merge of per-host-class profiles: autostart / tcc_allow / ssh_keys lists are
    extended, not replaced."""
    out = {k: dict(v) for k, v in base.items() if isinstance(v, dict)}
    for host_class, prof in (extra or {}).items():
        if not isinstance(prof, dict):
            continue
        dst = out.setdefault(host_class, {})
        for key in ("autostart", "tcc_allow", "ssh_keys"):
            if key in prof:
                dst[key] = list(dst.get(key, [])) + list(prof[key])
    return out


def norm_autostart(name: str | None, path: str | None) -> tuple[str, str]:
    """Normalise an autostart key for comparison: lowercase, backslashes, and the
    per-user Windows segment collapsed (``\\Users\\alice\\`` -> ``\\users\\*\\``)
    so one baseline entry matches every user. Idempotent."""
    p = (path or "").lower().replace("/", "\\")
    p = _USER_SEG.sub(r"\\users\\*\\", p)
    return ((name or "").lower(), p)


class HostBaselines:
    def __init__(self, data: dict):
        self._data = data

    @classmethod
    def load(cls) -> "HostBaselines":
        try:
            data = json.loads(_DATA.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            data = {}
        inst = cls(data)
        # Optional override exported by the Inventory agent (path in AEGIS_HOST_BASELINES).
        override = os.environ.get("AEGIS_HOST_BASELINES")
        if override:
            try:
                inst.update(json.loads(pathlib.Path(override).read_text(encoding="utf-8")))
            except (OSError, ValueError):
                pass
        return inst

    def update(self, profiles: dict) -> None:
        """Merge inventory-provided per-host-class profiles over the loaded baselines."""
        self._data = _merge_profiles(self._data, profiles or {})

    def _profile(self, host_class: str | None) -> dict:
        base = self._data.get(_DEFAULT_CLASS, {})
        cp = self._data.get(host_class or "", {})
        return {
            "autostart": list(base.get("autostart", [])) + list(cp.get("autostart", [])),
            "tcc_allow": tuple(base.get("tcc_allow", [])) + tuple(cp.get("tcc_allow", [])),
            "ssh_keys": list(base.get("ssh_keys", [])) + list(cp.get("ssh_keys", [])),
        }

    def autostart(self, host_class: str | None) -> set:
        return {norm_autostart(n, p) for n, p in self._profile(host_class)["autostart"]}

    def tcc_allowlist(self, host_class: str | None) -> tuple:
        return self._profile(host_class)["tcc_allow"]

    def ssh_keys(self, host_class: str | None) -> set:
        return set(self._profile(host_class)["ssh_keys"])

    def classes(self) -> list[str]:
        return [k for k in self._data if k != _DEFAULT_CLASS]


HOST_BASELINES = HostBaselines.load()


def feed_inventory_baselines(profiles: dict) -> None:
    """Inventory-agent hook: merge per-host-class known-good profiles into the live baseline at
    runtime. ``profiles`` = ``{host_class: {autostart: [[name, path], ...], tcc_allow: [...],
    ssh_keys: [...]}}`` — the agent's current export. Extends, never replaces."""
    HOST_BASELINES.update(profiles)
