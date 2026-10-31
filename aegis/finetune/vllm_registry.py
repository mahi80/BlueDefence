"""Register a promoted LoRA adapter with the running vLLM server — the last step to "live".

The loop now produces an approved promotion and writes the pointer (``current.json`` → adapter
PATH), and the SOC hot-reload swaps the live model by served NAME (``set_model(name)``). The
missing link on a real GPU box is between the two: vLLM resolves ``set_model(name)`` only if that
LoRA has been *loaded* under that name. vLLM exposes a runtime LoRA admin API for exactly this
(enabled server-side with ``VLLM_ALLOW_RUNTIME_LORA_UPDATING=1``):

    POST {base}/load_lora_adapter    {"lora_name": <name>, "lora_path": <adapter dir>}
    POST {base}/unload_lora_adapter  {"lora_name": <name>}

``register_promoted_adapter`` reads the promotion pointer, loads the adapter into vLLM under the
run name, and stamps ``served_model`` back into the pointer so hot-reload resolves it. The trainer
daemon calls this right after ``retrain sync``, so an approved promotion becomes servable within
one sync cycle — no restart, no manual vLLM poke.

stdlib ``urllib`` only (same rule as the vLLM inference client); the HTTP transport is injectable,
so load/unload/registration are unit-tested with no server and no GPU.
"""

from __future__ import annotations

import json
import logging
import os
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Callable, Optional

from aegis.agents.shared.vllm_client import VLLMConfig
from aegis.finetune.hot_reload import read_pointer

logger = logging.getLogger("aegis.finetune.vllm_registry")

#: transport(path, body) -> (status, text); injectable so tests never hit a server
Transport = Callable[[str, dict], "tuple[int, str]"]


@dataclass
class RegisterResult:
    ok: bool
    action: str = "noop"          # loaded | already | skipped | error | noop
    served_model: str = ""
    adapter: str = ""
    detail: str = ""


class VLLMAdapterRegistry:
    """Thin client for vLLM's runtime LoRA load/unload endpoints."""

    def __init__(self, *, base_url: str = "", api_key: str = "", timeout_s: float = 30.0,
                 transport: Optional[Transport] = None):
        cfg = VLLMConfig.from_env()
        self.base_url = (base_url or cfg.base_url).rstrip("/")
        self.api_key = api_key or cfg.api_key
        self.timeout_s = timeout_s
        self._transport = transport or self._http

    def load(self, name: str, path: str) -> tuple[bool, str]:
        """Load (or confirm already-loaded) a LoRA adapter. Returns (ok, 'loaded'|'already'|'error')."""
        status, text = self._transport("/load_lora_adapter", {"lora_name": name, "lora_path": path})
        if status == 200:
            return True, "loaded"
        # vLLM answers an already-registered name with 400 + a message — that's success for us
        if status == 400 and "already" in (text or "").lower():
            return True, "already"
        logger.warning("[vllm_registry] load %s failed: HTTP %s %s", name, status, (text or "")[:160])
        return False, "error"

    def unload(self, name: str) -> bool:
        status, _ = self._transport("/unload_lora_adapter", {"lora_name": name})
        return status == 200

    def _http(self, path: str, body: dict) -> tuple[int, str]:
        url = self.base_url + path
        raw = json.dumps(body).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        req = urllib.request.Request(url, data=raw, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout_s) as resp:  # noqa: S310 — operator-configured host
                return resp.status, resp.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as exc:
            detail = ""
            try:
                detail = exc.read().decode("utf-8", "replace")
            except Exception:  # noqa: BLE001
                pass
            return int(getattr(exc, "code", 0) or 0), detail
        except urllib.error.URLError as exc:
            return 0, f"connection error: {exc.reason}"


def _write_pointer(path: str, ptr: dict) -> bool:
    try:
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(ptr, fh)
        os.replace(tmp, path)
        return True
    except Exception as exc:  # noqa: BLE001 — a failed stamp just means we re-register next cycle
        logger.warning("[vllm_registry] could not stamp served_model into %s: %s", path, str(exc)[:160])
        return False


def register_promoted_adapter(registry: VLLMAdapterRegistry, *, pointer_path: Optional[str] = None,
                              force: bool = False) -> RegisterResult:
    """Load the currently-promoted adapter into vLLM and stamp ``served_model`` into the pointer.

    Idempotent: when the pointer already names the served adapter it just registered, this is a
    no-op — unless ``force`` (used once on daemon start, since a vLLM restart loses loaded LoRAs).
    """
    path = pointer_path if pointer_path is not None else os.environ.get("AEGIS_MODEL_POINTER", "")
    if not path:
        return RegisterResult(ok=True, action="noop", detail="no promotion pointer")
    ptr = read_pointer(path)
    if not ptr:
        return RegisterResult(ok=True, action="noop", detail="pointer unreadable/empty")
    name = str(ptr.get("served_model") or ptr.get("run") or "")
    adapter = str(ptr.get("adapter") or "")
    if not name or not adapter:
        return RegisterResult(ok=False, action="error", detail="pointer has no run/adapter")
    if ptr.get("served_model") == name and not force:
        return RegisterResult(ok=True, action="skipped", served_model=name, adapter=adapter,
                              detail="already registered")
    ok, how = registry.load(name, adapter)
    if not ok:
        return RegisterResult(ok=False, action="error", served_model=name, adapter=adapter,
                              detail=f"vLLM load {how}")
    if ptr.get("served_model") != name:
        ptr["served_model"] = name
        _write_pointer(path, ptr)
    logger.info("[vllm_registry] adapter '%s' registered with vLLM (%s) → servable, set_model will resolve", name, how)
    return RegisterResult(ok=True, action=how, served_model=name, adapter=adapter)


__all__ = ["VLLMAdapterRegistry", "RegisterResult", "register_promoted_adapter"]
