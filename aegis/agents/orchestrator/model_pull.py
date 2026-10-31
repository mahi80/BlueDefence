"""Dealigned-model pull fast path: a web-proxy record of someone fetching an "uncensored" model.

Abliterated / uncensored repacks of open models spread through social media as "free, run it
locally". Inside a bank that is shadow AI with three extra problems: the model obeys what it
should refuse (including instructions planted in data it reads), its weights are modified on
purpose so they cannot be checked against the upstream release for a backdoor, and running it
without a model-risk sign-off fails RBI FREE-AI governance.

The TLS handshake only names ``huggingface.co`` — the repository is in the URL path, which the
egress web proxy logs. So this path reads proxy records (generic JSON with a ``url``, or
``host`` + ``path``) and fires when the repo id or its publisher carries a dealignment marker
(``aegis.agents.vuln_discovery.model_supply_chain``). Ordinary model pulls are not this path's
concern — that would flood a team that downloads models all day.

Verdict: ``suspicious`` — a governance and insider-risk finding, not an attack on the bank —
at high severity: 0.85 when weights or loader code were downloaded, 0.65 for a page view or
an API lookup. Everything waits for a human except ``monitor``:

    escalate        confirm who and why; remove it, or onboard it as a reviewed sandboxed exception
    block_egress    a proxy URL rule for THAT repo path — never all of huggingface.co
    monitor         watch the host for a local inference server or the loader calling out
"""

from __future__ import annotations

from ..shared.evidence_chain import EvidenceChain, EvidenceItem, ReasoningStep, RecommendedAction
from ..vuln_discovery.model_supply_chain import dealigned_markers, evaluate_model_load, model_from_hf_url

_URL_KEYS = ("url", "request_url", "full_url", "http_url", "uri")
_HOST_KEYS = ("host", "dest_host", "http_host", "sni", "server_name")
_PATH_KEYS = ("path", "uri_path", "url_path")
_SRC_KEYS = ("source_ip", "src_ip", "client_ip")
_USER_KEYS = ("user", "username", "user_name", "principal")


def _first(alert: dict, keys: tuple[str, ...]) -> str:
    for k in keys:
        v = alert.get(k)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return ""


def _alert_url(alert: dict) -> str:
    """The requested URL as the proxy logged it — a full URL, or host + path split across fields."""
    url = _first(alert, _URL_KEYS)
    if url and ("://" in url or not url.startswith("/")):
        return url
    host = _first(alert, _HOST_KEYS)
    path = url or _first(alert, _PATH_KEYS)
    return f"{host}{path if path.startswith('/') else '/' + path}" if host and path else ""


def _pull(alert: dict) -> dict | None:
    if not isinstance(alert, dict):
        return None
    pull = model_from_hf_url(_alert_url(alert))
    if not pull:
        return None
    markers = dealigned_markers(pull["model"], alert.get("tags") if isinstance(alert.get("tags"), list) else ())
    return {**pull, "markers": markers} if markers else None


def is_dealigned_model_pull(alert: dict) -> bool:
    return _pull(alert) is not None


def model_pull_chain(alert: dict) -> EvidenceChain:
    pull = _pull(alert) or {"model": "unknown", "revision": "", "file": "", "kind": "page", "markers": []}
    model, kind, markers = pull["model"][:200], pull["kind"], pull["markers"]
    host, user = _first(alert, _SRC_KEYS), _first(alert, _USER_KEYS)
    who = f"{host} ({user})" if host and user else (host or user or "an internal client")
    fetched = kind in ("weights", "code")
    conf = 0.85 if fetched else 0.65
    what = {"weights": "downloaded model weights", "code": "downloaded the repo's loader code",
            "file": "downloaded a repo file", "api": "queried the model's metadata", "page": "opened the model page"}[kind]

    chain = EvidenceChain(alert_id=str(alert.get("id", "unknown")), investigated_by="model_pull",
                          verdict="suspicious", confidence=conf)
    chain.evidence.append(EvidenceItem(
        source=str(alert.get("source") or "web_proxy"), weight="high" if fetched else "medium",
        signal=f"{who} {what} from dealigned model {model} ({', '.join(markers)})",
        raw_data={"model": model, "revision": pull["revision"], "file": pull["file"][:200], "kind": kind,
                  "markers": markers, "url": _alert_url(alert)[:300]}))
    if kind == "code":
        chain.evidence.append(EvidenceItem(
            source="model_supply_chain", weight="high",
            signal=f"loader code {pull['file'][:120]} fetched — loading it with trust_remote_code runs the publisher's code on the host"))
    supply = evaluate_model_load({"model": model, "revision": pull["revision"]})
    for f in supply:
        chain.evidence.append(EvidenceItem(source="model_supply_chain", weight="high" if f.severity in ("critical", "high") else "medium",
                                           signal=f"{f.control} ({f.severity}): {f.detail}"[:600]))
    why = (f"dealigned model ({', '.join(markers)}) {'pulled' if fetched else 'browsed'} from an internal host — "
           "shadow AI with its safety behaviour removed")
    chain.reasoning.append(ReasoningStep(step=1, action="Dealigned-model pull fast path (no LLM verdict)",
                                         observation=why, conclusion="suspicious"))

    target = str(alert.get("id", "unknown"))
    chain.recommended_actions.append(RecommendedAction(
        action_type="escalate", target=target, requires_hitl=True, confidence=conf,
        reasoning=(f"{who} {what} from {model}, a model with its refusal / safety behaviour removed. Confirm who and why. "
                   "If there is no approved need, remove it from the host. If there is (red-team research), onboard it in "
                   "the AI registry as a reviewed, sandboxed exception (RBI FREE-AI Rec 23). It must never judge alerts or "
                   "read customer data.")))
    chain.recommended_actions.append(RecommendedAction(
        action_type="block_egress", target=f"huggingface.co/{model}", requires_hitl=True, confidence=conf,
        reasoning=f"Proxy URL rule for huggingface.co/{model} (and hf.co/{model}) only — the rest of Hugging Face stays reachable"))
    if host:
        chain.recommended_actions.append(RecommendedAction(
            action_type="monitor", target=host, requires_hitl=False, confidence=conf,
            reasoning=f"Watch {host} for a local inference server, a GPU-heavy process, or the model loader calling out"))

    sev = "high"
    chain.metadata["shadow_ai"] = {"service": "Hugging Face model download", "status": "dealigned_model", "severity": sev,
                                   "model": model, "markers": markers, "kind": kind, "host": host, "user": user}
    chain.metadata["model_supply_chain"] = [f.as_dict() for f in supply]
    return chain.finalize()


__all__ = ["is_dealigned_model_pull", "model_pull_chain"]
