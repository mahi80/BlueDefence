"""Publish AEGIS CVE knowledge (KEV / NVD / EPSS) into the dashboard's advisory library.

The dashboard's hourly threat-impact scan matches ``advisory.affects_frameworks`` against each
governed agent's framework. Its library was six hand-written advisories. This turns the live
``CveIntel`` cache into advisories with ``affects_frameworks`` derived from NVD CPE products, so
"a KEV CVE in the framework your loan agent runs on" becomes an alert (and, with
``ACP_THREAT_AUTO_PAUSE``, a pause) without anyone writing it up.

Volume is bounded: only records whose affected products match the agent-runtime vocabulary, or
that are KEV-listed and match at all, are published (≤ ``max_items``), newest / most severe first.
"""

from __future__ import annotations

import json
import logging
import os
import re
from typing import Any, Iterable, Optional

logger = logging.getLogger("aegis.threat_intel.publish")

# CPE product name (normalised) → framework label the dashboard stores on agents
FRAMEWORK_VOCAB: dict[str, str] = {
    "langchain": "langchain", "langchaincore": "langchain", "langgraph": "langgraph", "langchaincommunity": "langchain",
    "llamaindex": "llama_index", "llama_index": "llama_index", "crewai": "crewai", "autogen": "autogen", "pyautogen": "autogen",
    "semantickernel": "semantic_kernel", "openaiagents": "openai", "openai": "openai", "anthropic": "anthropic",
    "litellm": "litellm", "vllm": "vllm", "ollama": "ollama", "huggingface": "huggingface", "transformers": "huggingface",
    "gradio": "gradio", "streamlit": "streamlit", "fastapi": "fastapi", "flask": "flask", "django": "django",
    "mcp": "mcp", "modelcontextprotocol": "mcp", "copilotstudio": "copilot", "bedrock": "bedrock", "azureai": "azure",
    "databricks": "databricks", "mlflow": "mlflow", "jupyter": "jupyter", "pickle": "python", "pytorch": "pytorch", "torch": "pytorch",
}
_CATEGORY_BY_CWE = {
    "CWE-502": "supply_chain", "CWE-94": "code_execution", "CWE-78": "code_execution", "CWE-77": "code_execution",
    "CWE-918": "ssrf", "CWE-22": "path_traversal", "CWE-79": "injection", "CWE-89": "injection", "CWE-287": "auth",
    "CWE-862": "auth", "CWE-200": "data_exposure", "CWE-400": "dos",
}


def _norm(s: str) -> str:
    return re.sub(r"[^a-z0-9]", "", s.lower())


def _frameworks_for(rec: Any) -> list[str]:
    out: set[str] = set()
    for a in getattr(rec, "affected", ()) or ():
        key = _norm(a.product)
        if key in FRAMEWORK_VOCAB:
            out.add(FRAMEWORK_VOCAB[key])
        else:
            for k, v in FRAMEWORK_VOCAB.items():
                if len(k) >= 6 and k in key:
                    out.add(v)
    return sorted(out)


def _severity(rec: Any) -> str:
    if getattr(rec, "kev", None) is not None:
        return "CRITICAL"
    c = getattr(rec, "cvss", None)
    if c is None:
        return "MEDIUM"
    return "CRITICAL" if c >= 9.0 else "HIGH" if c >= 7.0 else "MEDIUM" if c >= 4.0 else "LOW"


def advisory_from(rec: Any) -> Optional[dict]:
    """One dashboard advisory from a ``CveRecord``; None when it touches no agent-runtime product."""
    fws = _frameworks_for(rec)
    if not fws:
        return None
    kev = getattr(rec, "kev", None)
    cat = next((_CATEGORY_BY_CWE[c] for c in (rec.cwes or ()) if c in _CATEGORY_BY_CWE), "framework_vulnerability")
    title = (kev.name if kev and kev.name else f"{rec.cve_id} in {', '.join(fws)}")[:200]
    summary = (rec.description or (kev.name if kev else "") or "")[:600]
    if kev:
        summary = f"[CISA KEV since {kev.date_added}, remediate by {kev.due_date}{', ransomware campaign use' if kev.ransomware else ''}] " + summary
    return {
        "id": f"{'KEV' if kev else 'NVD'}-{rec.cve_id}",
        "category": cat,
        "title": title,
        "severity": _severity(rec),
        "summary": summary[:800],
        "source": "cisa.kev" if kev else "nvd",
        "url": f"https://nvd.nist.gov/vuln/detail/{rec.cve_id}",
        "acp_control": "Q37" if cat in ("ssrf", "code_execution") else "Q30",
        "published": (rec.published or (kev.date_added if kev else ""))[:10],
        "affects_frameworks": fws,
        "affects_mcp_servers": ["*"] if "mcp" in fws else [],
        "cve_ids": [rec.cve_id],
        "cvss": rec.cvss, "epss": rec.epss, "kev": bool(kev), "ransomware": bool(kev and kev.ransomware),
    }


def advisories_from_intel(intel: Any, *, max_items: int = 500) -> list[dict]:
    recs: Iterable[Any] = list(getattr(intel, "cves", {}).values())
    # KEV-only records (not yet in the NVD cache) still carry vendor/product from the catalog
    seen = {r.cve_id for r in recs}
    recs = list(recs) + [intel.get(cid) for cid in getattr(intel, "kev", {}) if cid not in seen]
    out = []
    for r in recs:
        if r is None:
            continue
        adv = advisory_from(r)
        if adv:
            out.append(adv)
    rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    out.sort(key=lambda a: (0 if a["kev"] else 1, rank.get(a["severity"], 9), a["published"] and -int(a["published"].replace("-", "") or 0)))
    return out[:max_items]


def publish_to_dashboard(intel: Any, *, dashboard_url: Optional[str] = None, api_key: Optional[str] = None,
                         transport: Any = None, max_items: int = 500, timeout: float = 15.0) -> dict:
    """POST the advisories to ``/api/cyber-risk/threat-intel/ingest``. Returns the dashboard's counts
    (or ``{"error": …}``); a failure is logged and never raised — the next refresh retries."""
    url = (dashboard_url or os.environ.get("ACP_DASHBOARD_URL", "")).rstrip("/")
    key = api_key if api_key is not None else os.environ.get("ACP_API_KEY", "")
    advs = advisories_from_intel(intel, max_items=max_items)
    if not url:
        return {"published": 0, "skipped": "no ACP_DASHBOARD_URL", "candidates": len(advs)}
    if not advs:
        return {"published": 0, "candidates": 0}
    body = {"advisories": advs, "source": "aegis_cve_feeds", "ttl_days": 14}
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    if key:
        headers["X-API-Key"] = key
    send = transport or _httpx_post
    try:
        data = send(f"{url}/api/cyber-risk/threat-intel/ingest", body, headers, timeout)
    except Exception as e:  # noqa: BLE001 — the library keeps its last state; the next refresh retries
        logger.warning("[threat_intel] publish to dashboard failed: %s: %s", type(e).__name__, str(e)[:160])
        return {"published": 0, "candidates": len(advs), "error": f"{type(e).__name__}: {str(e)[:160]}"}
    if not isinstance(data, dict) or data.get("error"):
        logger.warning("[threat_intel] dashboard refused advisories: %s", (data or {}).get("error") if isinstance(data, dict) else data)
        return {"published": 0, "candidates": len(advs), "error": str((data or {}).get("error") if isinstance(data, dict) else data)[:200]}
    logger.info("[threat_intel] published %d advisories to the dashboard (%s new, %s updated)", len(advs), data.get("created"), data.get("updated"))
    return {"published": len(advs), **{k: data.get(k) for k in ("created", "updated", "rejected")}}


def _httpx_post(url: str, body: dict, headers: dict, timeout: float) -> dict:
    import httpx
    resp = httpx.post(url, json=body, headers=headers, timeout=timeout)
    resp.raise_for_status()
    data = resp.json()
    return data if isinstance(data, dict) else {"_raw": data}


__all__ = ["FRAMEWORK_VOCAB", "advisories_from_intel", "advisory_from", "publish_to_dashboard"]
