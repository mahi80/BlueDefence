"""Model supply-chain governance — policy-as-code for loading third-party models.

Defensive posture control for the malicious model-loader class seen in the Oct 2026
Hugging Face / ModelScope cryptominer campaign (and its kin): a model repo can ship
executable loader code that runs on load via ``trust_remote_code`` while the declared
weights file is a decoy. Tensor-scanning tools miss it because the payload is loader
code, not weights — so the control is **structural + policy**, evaluated before the
pipeline ever loads anything:

  1. load only from an allowlisted publisher, pinned to a reviewed revision;
  2. ``trust_remote_code`` is a reviewed exception, never a default;
  3. flag the structural tells a static check can see without running anything — an
     ``auto_map`` that points at an executable module, an implausibly small "weights"
     file (a decoy), risky imports / raw-IP literals in a referenced loader file;
  4. match known campaign indicators.

Pure evaluation: it reads a model-load request + a policy and returns findings. It runs
nothing, downloads nothing, takes no action. A finding gates the model-onboarding
pipeline (block, or allow under HITL); if a load still slips through, the EDR host
scorers catch the post-exploitation.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, asdict
from urllib.parse import unquote, urlsplit


# Publishers whose repos may be loaded without a reviewed exception (official orgs).
_ALLOWLISTED_ORGS = frozenset({
    "qwen", "deepseek-ai", "meta-llama", "mistralai", "google", "microsoft",
    "openai", "bigscience", "huggingfaceh4", "nvidia", "sentence-transformers",
    "intfloat", "baai", "allenai",
})
# A real set of weights is far larger than this; a tiny declared "weights" file is a decoy tell.
_MIN_PLAUSIBLE_WEIGHTS_BYTES = 10_000
# Imports / calls a model's loader file should not need — flagged when found by a static pass.
_RISKY_LOADER_TOKENS = frozenset({
    "subprocess", "os.system", "pty.spawn", "ctypes", "socket", "memfd_create",
    "/tmp/", "base64.b64decode", "urllib.request", "requests.get", "eval(", "exec(",
})


# Published indicators for the Oct 2026 campaign (Pluto Security / BleepingComputer, 2026-10-29).
ADVISORY_HF_LOADER_CAMPAIGN = {
    "id": "AEGIS-TI-2026-HF-LOADER",
    "name": "Hugging Face / ModelScope malicious model-loader cryptominer campaign",
    "disclosed": "2026-10-29",
    "technique": "trust_remote_code auto_map -> executable loader; decoy weights; fileless miner + backdoors",
    "references": ["Pluto Security", "BleepingComputer 2026-10-29"],
    "iocs": {
        "repos": {"menxiangyu/qwen2-tiny"},
        "files": {"modeling_evil2.py", "syscore.bin", "/tmp/.cch/svc.py"},
        "process": {"[kworker/u20:1]"},          # a kworker WITH command-line args = the miner
        "ips": {"212.32.253.3", "2.28.9.199", "8.137.187.63"},
        "ports": {443, 9443, 7000},
    },
    "mitigation": ("allowlisted org + pinned reviewed revision; review auto_map files before enabling "
                   "trust_remote_code; sandbox model loading — least privilege, egress-restricted, no prod secrets"),
}


# Dealigned ("uncensored") models: a repack of an open model with its refusal / safety
# behaviour removed — by abliteration (the refusal direction projected out of the weights),
# by fine-tuning on jailbreak data, or by tools like Heretic. Matched as stems against the repo
# id with separators removed, and against the repo's tags. A publisher whose name carries a
# stem (e.g. ``dealignai``) is caught for every repo it ships, including ones without a marker.
_DEALIGNED_STEMS: tuple[tuple[str, str], ...] = (
    ("abliterat", "abliterated"),
    ("uncensor", "uncensored"),
    ("dealign", "dealigned"),
    ("unaligned", "unaligned"),
    ("jailbreak", "jailbreak"),
    ("jailbroken", "jailbroken"),
    ("noguardrail", "no-guardrails"),
    ("norefusal", "no-refusal"),
    ("refusalremoved", "refusal-removed"),
    ("heretic", "heretic"),
)
_SEP_RX = re.compile(r"[\s_.\-/]+")


def dealigned_markers(model: str | None, tags: object = ()) -> list[str]:
    """The dealignment markers a repo id (or its tags) carries — ``[]`` for an ordinary model."""
    hay = [_SEP_RX.sub("", str(model or "").lower())]
    if isinstance(tags, (list, tuple, set, frozenset)):
        hay += [_SEP_RX.sub("", str(t).lower()) for t in tags]
    return sorted({label for stem, label in _DEALIGNED_STEMS for h in hay if stem in h})


# First path segments on huggingface.co that are not a user/org namespace.
_HF_RESERVED = frozenset({
    "datasets", "spaces", "docs", "blog", "settings", "login", "join", "pricing", "papers", "collections",
    "organizations", "posts", "tasks", "learn", "chat", "models", "new", "enterprise", "search",
    "static-proxy", "front", "avatars", "oauth", "auth", "notifications", "inference-endpoints",
})
_HF_HOSTS = frozenset({"huggingface.co", "hf.co"})
_WEIGHT_EXT = (".safetensors", ".bin", ".gguf", ".pt", ".pth", ".onnx", ".ckpt", ".h5", ".msgpack")


def model_from_hf_url(url: str | None) -> dict | None:
    """``{"model": "org/name", "revision", "file", "kind"}`` for a Hugging Face model URL as a web
    proxy logs it, else ``None``. ``kind`` is ``weights`` | ``code`` | ``file`` | ``page`` | ``api``.

    Datasets, Spaces and site pages are not models; the LFS / Xet CDN hosts carry only content
    hashes, so a pull is identified from the ``huggingface.co/<org>/<repo>/resolve/...`` request
    that precedes the CDN redirect."""
    raw = str(url or "").strip()
    if not raw:
        return None
    if "://" not in raw:
        raw = "https://" + raw.lstrip("/")
    try:
        parts = urlsplit(raw)
    except ValueError:
        return None
    host = (parts.hostname or "").lower()
    if host.startswith("www."):
        host = host[4:]
    if host not in _HF_HOSTS:
        return None
    seg = [unquote(s) for s in parts.path.split("/") if s]
    if not seg:
        return None
    if seg[0] == "api":                       # /api/models/<org>/<name>[/revision/<rev>|/tree/<rev>/...]
        if len(seg) < 4 or seg[1] != "models":
            return None
        org, name, rest = seg[2], seg[3], seg[4:]
        rev = rest[1] if len(rest) >= 2 and rest[0] in ("revision", "tree") else ""
        return {"model": f"{org}/{name}", "revision": rev, "file": "", "kind": "api"}
    if seg[0].lower() in _HF_RESERVED or len(seg) < 2:
        return None
    org, name, rest = seg[0], seg[1], seg[2:]
    rev, file, kind = "", "", "page"
    if len(rest) >= 2 and rest[0] in ("resolve", "blob", "raw", "tree"):
        rev = rest[1]
        file = "/".join(rest[2:])
        low = file.lower()
        kind = ("weights" if low.endswith(_WEIGHT_EXT) else "code" if low.endswith(".py")
                else "file" if file else "page")
    return {"model": f"{org}/{name}", "revision": rev, "file": file, "kind": kind}


@dataclass
class ModelLoadFinding:
    control: str
    severity: str          # critical | high | medium
    model: str
    detail: str

    def as_dict(self) -> dict:
        return asdict(self)


def _org_of(model: str | None) -> str:
    return str(model or "").split("/", 1)[0].strip().lower()


def is_allowlisted(model: str | None) -> bool:
    return _org_of(model) in _ALLOWLISTED_ORGS


def _unpinned(revision: object) -> bool:
    rev = str(revision or "").strip().lower()
    return rev in ("", "main", "master", "head", "latest")


def iocs_host(advisory: dict = ADVISORY_HF_LOADER_CAMPAIGN) -> dict:
    """The host-observable indicators (IPs, file paths, process tell) for the EDR / threat-intel
    layer — so a load that slips the policy is still caught post-exploitation."""
    i = advisory.get("iocs", {})
    return {"ips": set(i.get("ips", set())), "files": set(i.get("files", set())),
            "process": set(i.get("process", set()))}


def evaluate_model_load(request: dict, advisory: dict = ADVISORY_HF_LOADER_CAMPAIGN) -> list[ModelLoadFinding]:
    """Policy findings for one model-load request (static signals only).

    ``request`` =
      ``model``             "org/name"
      ``revision``          commit sha or tag; absent / "main" / "latest" = unpinned
      ``trust_remote_code`` bool
      ``reviewed``          bool — a human reviewed & approved THIS exact revision
      ``auto_map``          bool — config.json has an auto_map that maps to a module
      ``weights_bytes``     int  — size of the declared weights file(s)
      ``loader_files``      [{"name": str, "tokens": [str]}] — static features of referenced .py files
      ``tags``              [str] — the repo's Hub tags (``uncensored``, ``abliterated`` …)
    """
    model = str(request.get("model") or "unknown")
    reviewed = bool(request.get("reviewed"))
    trc = bool(request.get("trust_remote_code"))
    auto_map = bool(request.get("auto_map"))
    out: list[ModelLoadFinding] = []

    iocs = advisory.get("iocs", {})
    # Known-bad repo, or a referenced loader file name on the IOC list.
    loader_files = request.get("loader_files") if isinstance(request.get("loader_files"), list) else []
    loader_names = {str(f.get("name", "")).lower() for f in loader_files if isinstance(f, dict)}
    if model.lower() in {r.lower() for r in iocs.get("repos", set())} or (loader_names & {f.lower() for f in iocs.get("files", set())}):
        out.append(ModelLoadFinding("KNOWN_MALICIOUS_REPO", "critical", model,
                                    f"Matches {advisory.get('id')} — {advisory.get('name')}. Do not load."))

    # Dealigned model — safety behaviour deliberately removed. Flagged even from an allowlisted org
    # and even when reviewed (then medium: an approved, sandboxed red-team exception is legitimate).
    markers = dealigned_markers(model, request.get("tags") or ())
    if markers:
        out.append(ModelLoadFinding(
            "DEALIGNED_MODEL", "medium" if reviewed else "high", model,
            f"Refusal / safety behaviour removed ({', '.join(markers)}). It follows instructions it should "
            "refuse — including ones planted in the data it reads, so it must never judge alerts or touch "
            "customer data; its weights are modified on purpose, so they cannot be verified against the "
            "upstream release to rule out a backdoor; and an unsanctioned dealigned model fails model-risk "
            "governance (RBI FREE-AI). " + ("Approved exception: keep it sandboxed and off production paths."
                                           if reviewed else "Do not load outside an approved, sandboxed red-team exception.")))

    # Unvetted publisher.
    if not is_allowlisted(model) and not reviewed:
        out.append(ModelLoadFinding("UNVETTED_PUBLISHER", "high", model,
                                    f"Publisher '{_org_of(model)}' is not on the allowlist and the revision is not reviewed"))

    # Unpinned revision — can be swapped under you after review (the campaign's second wave used new pushes).
    if _unpinned(request.get("revision")):
        out.append(ModelLoadFinding("UNPINNED_REVISION", "high", model,
                                    "No pinned commit/tag — pin a reviewed revision so the loaded code can't change under you"))

    # Executable-on-load code without a reviewed exception.
    if trc and not reviewed:
        sev = "critical" if auto_map else "high"
        out.append(ModelLoadFinding("UNREVIEWED_REMOTE_CODE", sev, model,
                                    "trust_remote_code runs repo code on load; " +
                                    ("auto_map maps to an executable module — " if auto_map else "") +
                                    "review the referenced file and approve the revision first"))

    # Decoy weights — a tiny "weights" file beside auto_map loader code is the campaign's structural tell.
    wb = request.get("weights_bytes")
    if auto_map and isinstance(wb, int) and 0 <= wb < _MIN_PLAUSIBLE_WEIGHTS_BYTES:
        out.append(ModelLoadFinding("DECOY_WEIGHTS", "critical", model,
                                    f"Declared weights are {wb} B (< {_MIN_PLAUSIBLE_WEIGHTS_BYTES} B) beside auto_map loader code — decoy pattern"))

    # Risky imports in a referenced loader file (static features from an upload-time scan).
    for f in loader_files:
        if not isinstance(f, dict):
            continue
        hit = sorted({t for t in (f.get("tokens") or []) if t in _RISKY_LOADER_TOKENS})
        if hit:
            out.append(ModelLoadFinding("RISKY_LOADER_IMPORTS", "critical", model,
                                        f"{f.get('name', 'loader')} references {hit} — process/network/decode calls a model loader does not need"))
    return out


def scan_models(requests: list[dict], advisory: dict = ADVISORY_HF_LOADER_CAMPAIGN) -> list[dict]:
    """Evaluate every model-load request; return findings as plain dicts for the governance report."""
    findings: list[dict] = []
    for r in requests or []:
        if isinstance(r, dict):
            findings.extend(f.as_dict() for f in evaluate_model_load(r, advisory))
    return findings


__all__ = ["ModelLoadFinding", "ADVISORY_HF_LOADER_CAMPAIGN", "is_allowlisted",
           "evaluate_model_load", "scan_models", "iocs_host", "dealigned_markers", "model_from_hf_url"]
