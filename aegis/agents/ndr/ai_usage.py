"""Shadow AI: which internal hosts talk to which AI services, and is any of it registered?

RBI's FREE-AI framework (Rec 23) and the EU AI Act both expect an inventory of the AI systems an
institution runs. The ACP registry lists the systems that were onboarded. What it cannot list is
the desktop pasting customer data into a public chatbot, or the team script calling a model API
on a personal key. The TLS handshake names the service (SNI), so every connection to a known AI
endpoint is checked against the bank's register:

    registered     the host belongs to a registered AI system, and the endpoint
                   is one that system is approved to call                           → recorded
    approved       the endpoint is approved for everyone (the bank's own tenant)   → recorded
    unapproved     a registered system calling an endpoint outside its approval     → finding
    unregistered   a host with no registration calling an AI service                → finding

``AEGIS_AI_REGISTER`` (CSV ``host,system,endpoints`` or JSONL ``{"host", "system",
"endpoints"}``). ``host`` is an IP, CIDR or hostname, and an empty host approves the endpoints
for everyone. ``endpoints`` is a ``;``-separated list of hostnames, where a leading ``.``
approves a suffix. Every sighting is kept in a register of discovered usage. That register is
written as JSON to ``AEGIS_SHADOW_AI_REGISTER`` and handed to the CISO as evidence of the
inventory's coverage. With the dashboard connected, the rows that changed are also shipped to
``/api/soc/ai-usage``, and ``/ai-registry`` shows them beside the onboarded register.

The provider list covers public, well-known API and chat hostnames. It is extendable with
``AEGIS_AI_PROVIDERS_EXTRA`` (JSONL ``{"host", "provider", "label", "kind"}``). It sees only
what the handshake names: ECH hides the SNI, and a TLS-inspecting proxy in front of the sensor
hides everything behind it. Feed that proxy's own logs (generic JSON with ``host``) instead.
"""

from __future__ import annotations

import csv
import io
import ipaddress
import json
import logging
import os
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger("aegis.ndr.ai")

#: (host or ".suffix", provider id, label, kind) — public endpoints, most specific first
PROVIDERS: tuple[tuple[str, str, str, str], ...] = (
    ("api.openai.com", "openai", "OpenAI API", "api"),
    ("chatgpt.com", "openai", "ChatGPT", "web"),
    ("chat.openai.com", "openai", "ChatGPT", "web"),
    ("api.anthropic.com", "anthropic", "Anthropic API", "api"),
    ("claude.ai", "anthropic", "Claude", "web"),
    ("generativelanguage.googleapis.com", "google", "Gemini API", "api"),
    ("gemini.google.com", "google", "Gemini", "web"),
    ("-aiplatform.googleapis.com", "google-vertex", "Vertex AI", "api"),       # regional: us-central1-aiplatform…
    ("aiplatform.googleapis.com", "google-vertex", "Vertex AI", "api"),
    (".openai.azure.com", "azure-openai", "Azure OpenAI", "api"),
    (".services.ai.azure.com", "azure-ai", "Azure AI Foundry", "api"),
    ("api.mistral.ai", "mistral", "Mistral API", "api"),
    ("chat.mistral.ai", "mistral", "Le Chat", "web"),
    ("api.cohere.com", "cohere", "Cohere API", "api"),
    ("api.cohere.ai", "cohere", "Cohere API", "api"),
    ("api.groq.com", "groq", "Groq API", "api"),
    ("openrouter.ai", "openrouter", "OpenRouter", "api"),
    ("api.together.xyz", "together", "Together API", "api"),
    ("api.deepseek.com", "deepseek", "DeepSeek API", "api"),
    ("chat.deepseek.com", "deepseek", "DeepSeek chat", "web"),
    ("api.perplexity.ai", "perplexity", "Perplexity API", "api"),
    ("perplexity.ai", "perplexity", "Perplexity", "web"),
    ("api.x.ai", "xai", "xAI API", "api"),
    ("grok.com", "xai", "Grok", "web"),
    ("api-inference.huggingface.co", "huggingface", "Hugging Face Inference", "api"),
    ("api.replicate.com", "replicate", "Replicate API", "api"),
    ("api.fireworks.ai", "fireworks", "Fireworks API", "api"),
    ("copilot.microsoft.com", "microsoft-copilot", "Microsoft Copilot", "web"),
)


@dataclass(frozen=True)
class AiService:
    provider: str
    label: str
    kind: str          # api | web
    endpoint: str      # the SNI that matched


def _host_matches(host: str, pattern: str) -> bool:
    if pattern.startswith((".", "-")):                 # a raw suffix (".openai.azure.com", "-aiplatform…")
        return host.endswith(pattern) or host == pattern[1:]
    return host == pattern or host.endswith("." + pattern)


def _extra_providers() -> list[tuple[str, str, str, str]]:
    path = os.environ.get("AEGIS_AI_PROVIDERS_EXTRA", "").strip()
    out: list[tuple[str, str, str, str]] = []
    if not path:
        return out
    try:
        for line in Path(path).read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                r = json.loads(line)
                out.append((str(r["host"]).lower(), str(r.get("provider") or r["host"]), str(r.get("label") or r["host"]),
                             str(r.get("kind") or "api")))
    except (OSError, ValueError, KeyError) as e:
        logger.warning("[ndr:ai] AEGIS_AI_PROVIDERS_EXTRA unreadable (%s); built-in list only", str(e)[:80])
    return out


_EXTRA: list[tuple[str, str, str, str]] | None = None


def ai_service(sni: str) -> AiService | None:
    """The AI service a TLS server name belongs to, or ``None``."""
    global _EXTRA
    host = str(sni or "").strip().lower().strip(".")
    if not host:
        return None
    if _EXTRA is None:
        _EXTRA = _extra_providers()
    for pattern, provider, label, kind in list(_EXTRA) + list(PROVIDERS):
        if _host_matches(host, pattern):
            return AiService(provider, label, kind, host)
    if host.startswith("bedrock-runtime.") and host.endswith(".amazonaws.com"):
        return AiService("aws-bedrock", "Amazon Bedrock", "api", host)
    return None


def reset_extra_providers() -> None:
    global _EXTRA
    _EXTRA = None


# -------------------------------------------------------------- register --

@dataclass(frozen=True)
class AiRegistration:
    system: str
    hosts: tuple[Any, ...]              # ip_network objects and / or lower-case hostnames
    endpoints: tuple[str, ...]          # hostnames, or ".suffix"

    def covers_host(self, host: str) -> bool:
        try:
            addr = ipaddress.ip_address(host)
        except ValueError:
            addr = None
        for h in self.hosts:
            if isinstance(h, str):
                if h == host.lower():
                    return True
            elif addr is not None and addr.version == h.version and addr in h:
                return True
        return False

    def allows(self, endpoint: str) -> bool:
        return any(_host_matches(endpoint, e) for e in self.endpoints)


def _split_hosts(raw: str) -> tuple[Any, ...]:
    out: list[Any] = []
    for h in [x.strip() for x in str(raw or "").replace(";", ",").split(",") if x.strip()]:
        try:
            out.append(ipaddress.ip_network(h, strict=False))
        except ValueError:
            out.append(h.lower())
    return tuple(out)


def _split_endpoints(raw: Any) -> tuple[str, ...]:
    if isinstance(raw, list):
        return tuple(str(e).strip().lower() for e in raw if str(e).strip())
    return tuple(e.strip().lower() for e in str(raw or "").replace(",", ";").split(";") if e.strip())


class AiRegister:
    """The bank's register of AI systems and the AI endpoints each may call."""

    def __init__(self, rows: list[AiRegistration] | None = None):
        self.rows = list(rows or [])

    @classmethod
    def from_env(cls) -> AiRegister:
        path = os.environ.get("AEGIS_AI_REGISTER", "").strip()
        return cls.load(path) if path else cls()

    @classmethod
    def load(cls, path: str | Path) -> AiRegister:
        p = Path(path)
        try:
            text = p.read_text(encoding="utf-8")
        except OSError as e:
            logger.warning("[ndr:ai] register %s unreadable (%s); every AI connection will read as unregistered", p, e)
            return cls()
        rows: list[AiRegistration] = []
        lines = [ln for ln in text.splitlines() if ln.strip() and not ln.lstrip().startswith("#")]
        if lines and lines[0].lstrip().startswith("{"):
            for ln in lines:
                try:
                    r = json.loads(ln)
                    rows.append(AiRegistration(str(r.get("system") or "?"), _split_hosts(r.get("host") or r.get("hosts") or ""),
                                               _split_endpoints(r.get("endpoints") or r.get("endpoint") or "")))
                except ValueError:
                    logger.warning("[ndr:ai] register line skipped: %s", ln[:80])
        else:
            for r in csv.DictReader(io.StringIO("\n".join(lines))):
                rows.append(AiRegistration(str(r.get("system") or "?"), _split_hosts(r.get("host") or ""),
                                           _split_endpoints(r.get("endpoints") or "")))
        logger.info("[ndr:ai] %d AI registrations from %s", len(rows), p)
        return cls(rows)

    def status(self, host: str, endpoint: str) -> tuple[str, str]:
        """(``registered`` | ``approved`` | ``unapproved`` | ``unregistered``, system) — the most
        specific first: a registered system on its own approved endpoint, then an endpoint the bank
        approved for everyone, then a registered system off its approval, then nobody's."""
        mine = [r for r in self.rows if r.hosts and r.covers_host(host)]
        for r in mine:
            if r.allows(endpoint):
                return "registered", r.system
        for r in self.rows:
            if not r.hosts and r.allows(endpoint):
                return "approved", r.system
        if mine:
            return "unapproved", mine[0].system
        return "unregistered", ""


@dataclass
class _Usage:
    host: str
    endpoint: str
    provider: str
    label: str
    kind: str
    status: str
    system: str
    first_seen: float
    last_seen: float
    connections: int = 0
    bytes_out: int = 0
    window: list = field(default_factory=list)      # (ts, bytes_out) for the upload window

    def to_dict(self) -> dict:
        return {"host": self.host, "endpoint": self.endpoint, "provider": self.provider, "service": self.label,
                "kind": self.kind, "status": self.status, "system": self.system,
                "first_seen": self.first_seen, "last_seen": self.last_seen, "connections": self.connections,
                "bytes_out": self.bytes_out}


class AiUsageRegister:
    """Every (host, AI endpoint) pair seen. Bounded; written as JSON for the CISO and the regulator."""

    def __init__(self, *, path: str | Path | None = None, max_rows: int = 20_000, write_every_s: float = 30.0,
                 sink: Any = None):
        self.path = Path(path) if path else None
        self.max_rows = max_rows
        self.write_every_s = write_every_s
        self.sink = sink                     # DashboardSink-like: ship_ai_usage(rows) → /api/soc/ai-usage
        self._rows: dict[tuple[str, str], _Usage] = {}
        self._lock = threading.Lock()
        self._dirty = False
        self._changed: set[tuple[str, str]] = set()
        self._last_write = 0.0

    @classmethod
    def from_env(cls) -> AiUsageRegister:
        path = os.environ.get("AEGIS_SHADOW_AI_REGISTER", "").strip()
        return cls(path=path or None)

    def touch(self, host: str, svc: AiService, status: str, system: str, ts: float) -> tuple[_Usage, bool]:
        with self._lock:
            key = (host, svc.endpoint)
            u = self._rows.get(key)
            new = u is None
            if u is None:
                if len(self._rows) >= self.max_rows:
                    oldest = min(self._rows, key=lambda k: self._rows[k].last_seen)
                    del self._rows[oldest]
                u = self._rows[key] = _Usage(host, svc.endpoint, svc.provider, svc.label, svc.kind, status, system, ts, ts)
            u.connections += 1
            u.last_seen = max(u.last_seen, ts)
            u.status, u.system = status, system
            self._dirty = True
            self._changed.add(key)
        self._maybe_write(ts)
        return u, new

    def add_bytes(self, host: str, endpoint: str, ts: float, out_bytes: int, window_s: float) -> int:
        """Bytes uploaded by ``host`` to ``endpoint`` in the last ``window_s`` (this one included)."""
        with self._lock:
            u = self._rows.get((host, endpoint))
            if u is None:
                return 0
            u.bytes_out += max(0, int(out_bytes))
            u.window.append((ts, max(0, int(out_bytes))))
            u.window = [(t, b) for t, b in u.window if ts - t <= window_s][-4096:]
            self._dirty = True
            self._changed.add((host, endpoint))
            total = sum(b for _, b in u.window)
        self._maybe_write(ts)
        return total

    def rows(self) -> list[dict]:
        with self._lock:
            return sorted((u.to_dict() for u in self._rows.values()), key=lambda r: (r["status"] == "approved", r["host"], r["endpoint"]))

    def _maybe_write(self, ts: float) -> None:
        if (self.path is None and self.sink is None) or not self._dirty or time.time() - self._last_write < self.write_every_s:
            return
        self.write()

    def write(self) -> None:
        """Write the register file and ship the rows that changed since the last write."""
        with self._lock:
            changed = [self._rows[k].to_dict() for k in self._changed if k in self._rows]
            self._changed.clear()
        if self.sink is not None and changed:
            try:
                self.sink.ship_ai_usage(changed)
            except Exception as e:  # noqa: BLE001 — the dashboard is a mirror; the file stays the record
                logger.warning("[ndr:ai] shipping %d AI-usage rows failed: %s", len(changed), str(e)[:120])
        self._last_write = time.time()
        self._dirty = False
        if self.path is None:
            return
        rows = self.rows()
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(self.path.suffix + ".tmp")
            tmp.write_text(json.dumps({"generated_at": time.time(), "rows": rows,
                                       "summary": _summary(rows)}, indent=1), encoding="utf-8")
            tmp.replace(self.path)
            self._dirty = False
            self._last_write = time.time()
        except OSError as e:
            logger.warning("[ndr:ai] register write to %s failed: %s", self.path, e)


def _summary(rows: list[dict]) -> dict:
    out: dict[str, Any] = {"hosts": len({r["host"] for r in rows}), "by_status": {}}
    for r in rows:
        out["by_status"][r["status"]] = out["by_status"].get(r["status"], 0) + 1
    return out


__all__ = [
    "PROVIDERS",
    "AiRegister",
    "AiRegistration",
    "AiService",
    "AiUsageRegister",
    "ai_service",
    "reset_extra_providers",
]
