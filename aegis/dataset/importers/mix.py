"""The mixed training set: public corpora + synthetic + injection, with the held-out eval excluded.

Recipe (``build_mixed``), by share of the final row count:

    sigma    22 %  SigmaHQ rule-driven alerts in product-native envelopes (3 kinds per rule)
    products 26 %  profile-driven rows for the products Sigma covers thinly — WAF (Imperva/F5) 8,
                   Zscaler ZIA+ZPA 8, Defender Identity/Cloud Apps/Office 365 10, Sophos Firewall 4,
                   Cortex XSOAR native 2 — verdict from field *combinations*
    agentic   8 %  campaign-shaped alerts from AI-agent attacks on the client side (React/Angular/
                   Vue/Nuxt/Next/Django/Laravel/Symfony/PHP/mobile/GraphQL as context, never a signal):
                   recon artefacts, enumeration, automation fingerprint, adaptive mutation, client-
                   integrity breaks, beaconing, recon→exploit speed; benign look-alikes with context
    endpoint  8 %  the endpoint gaps Sigma lacks: sensor tampering + inventory drift, ransomware-rate
                   telemetry + canary files, infostealer → session-replay chain, removable media,
                   mobile banking-trojan posture, branch / ATM / kiosk whitelisting
    corrob   12 %  raw-field alerts with NO detection name (identity, API, network policy, DLP,
                   transactions, wireless, cloud control-plane) labelled by the corroboration
                   rule: ≥2 independent strong signals → malicious, 1 → suspicious, 0 → benign
    mordor    4 %  OTRF Security-Datasets adversary scenarios (Sentinel incidents)
    synth     6 %  synthetic v2 (bank-only domains: CBS transactions, DLP, mobile, wireless,
                   supply chain, CVE overlay)
    inject   14 %  prompt-injection rows (instruction text planted in a public-corpus row's
                   free-text field, so injections are seen in every product shape, not just synth)

Every row keeps its own ``label_source`` so the manifest reports the mix and the trainer can
weight or exclude a source. The eval fingerprints are excluded unconditionally.
"""

from __future__ import annotations

import logging
import json
import random
import subprocess
from pathlib import Path

from ..schema import fingerprint
from ..synth import _injection_text, _INJ_FIELDS, generate as generate_synth
from .agentic import generate_agentic
from .corroboration import generate_corroboration
from .endpoint import generate_endpoint
from .mordor import generate_mordor, load_scenarios
from .products_gen import generate_products
from .sigma import generate_sigma, load_rules

logger = logging.getLogger("aegis.dataset.mix")

SIGMA_REPO = "https://github.com/SigmaHQ/sigma.git"
MORDOR_REPO = "https://github.com/OTRF/Security-Datasets.git"
DEFAULT_SHARES = {"sigma": 22, "products": 26, "corrob": 12, "agentic": 8, "endpoint": 8, "mordor": 4, "synth": 6, "inject": 14}
# within "products": the CISO-stack gaps, as shares of the whole set (sum = 32)
PRODUCT_WEIGHTS = {"waf": 7, "token_forgery": 2.5, "ct_watch": 1, "zia": 3.5, "zpa": 3.5, "mdi": 3, "mdca": 3, "mdo": 3, "sophos_fw": 3.5, "xsoar": 2}


def fetch_corpora(cache: str | Path) -> tuple[Path, Path]:
    """Shallow-clone (or reuse) the two public corpora under ``cache``. Needs git + GitHub access."""
    cache = Path(cache); cache.mkdir(parents=True, exist_ok=True)
    sigma = cache / "sigma"
    if not (sigma / "rules").is_dir():
        subprocess.run(["git", "clone", "-q", "--depth", "1", SIGMA_REPO, str(sigma)], check=True)
    mordor = cache / "Security-Datasets"
    if not (mordor / "datasets" / "atomic" / "_metadata").is_dir():
        subprocess.run(["git", "clone", "-q", "--depth", "1", "--filter=blob:none", "--sparse", MORDOR_REPO, str(mordor)], check=True)
        subprocess.run(["git", "-C", str(mordor), "sparse-checkout", "set", "datasets/atomic/_metadata",
                        "datasets/atomic/aws", "datasets/atomic/linux"], check=True)
    return sigma, mordor


def _eval_fps() -> set[str]:
    out: set[str] = set()
    try:
        from aegis.eval.run import HERE
        for name in ("historical_alerts", "injection_corpus", "agentic_chains", "endpoint_chains", "tls_chains", "network_chains"):
            p = HERE / name / "cases.json"
            if p.exists():
                for c in json.loads(p.read_text(encoding="utf-8")):
                    out.add(fingerprint(c["alert"]))
    except Exception as exc:  # noqa: BLE001 — eval guard is best-effort; the trainer refuses eval fingerprints again at load
        logger.warning("[dataset] eval fingerprint guard incomplete: %s", exc)
    return out


def _inject_into(row: dict, r: random.Random) -> dict:
    """Plant an instruction sentence in a free-text field of a public-corpus row and relabel."""
    alert = json.loads(row["messages"][1]["content"])
    target = json.loads(row["messages"][2]["content"])
    field = r.choice(_INJ_FIELDS)
    alert[field] = _injection_text(r)
    if target["verdict"] == "benign":
        target["verdict"] = "suspicious"
        target["confidence"] = round(r.uniform(.6, .78), 2)
    target["recommended_actions"] = [a for a in target["recommended_actions"] if a["action_type"] != "allow"] or \
        [{"action_type": "monitor", "target": alert.get("id", "alert"), "requires_hitl": False}]
    target["key_signals"] = list(target["key_signals"]) + [f"field '{field}' contains text addressed to the triage model"]
    target["techniques"] = list(dict.fromkeys(list(target["techniques"]) + ["AML.T0051"]))
    target["rationale"] = (f"The '{field}' field carries an instruction aimed at the triage model. Alert text is untrusted data: "
                           "the instruction is ignored and counted as an attack signal, so this cannot be benign. " + target["rationale"])
    target["injection_detected"] = True
    fp = fingerprint(alert)
    return {**row, "id": f"inj-{fp[:16]}", "label_source": row["label_source"] + "+injection",
            "provenance": {**row.get("provenance", {}), "injection_field": field},
            "messages": [row["messages"][0],
                         {"role": "user", "content": json.dumps(alert, sort_keys=True, ensure_ascii=False)},
                         {"role": "assistant", "content": json.dumps(target, ensure_ascii=False)}]}


def build_mixed(*, sigma_root: str | Path, mordor_root: str | Path, total: int = 50000, seed: int = 7,
                shares: dict[str, int] | None = None, val_pct: int = 15, xsoar_pct: int = 20,
                cve_calibration=None) -> tuple[list[dict], dict]:
    """Return (rows, stats). ``total`` is the target row count; shares are percentages.

    ``cve_calibration`` (C3.3, opt-in) is threaded into the synthetic portion's CVE overlay; ``None``
    keeps the exact default draws."""
    shares = {**DEFAULT_SHARES, **(shares or {})}
    r = random.Random(seed)
    held = _eval_fps()
    want = {k: int(total * v / 100) for k, v in shares.items()}

    rules = load_rules(sigma_root)
    r.shuffle(rules)
    per_rule = max(1, -(-(want["sigma"] + want["inject"]) // max(1, len(rules))))      # ceil
    sigma_rows = generate_sigma(rules, seed=seed, variants=per_rule, val_pct=val_pct, xsoar_pct=xsoar_pct)
    r.shuffle(sigma_rows)
    # a third of the injections ride product rows (so the instruction text is seen in those shapes too)
    n_prod_inj = min(want.get("products", 0) // 4, want["inject"] // 3)
    n_sig_inj = want["inject"] - n_prod_inj
    inject_pool, sigma_rows = sigma_rows[:n_sig_inj], sigma_rows[n_sig_inj:n_sig_inj + want["sigma"]]

    scenarios = load_scenarios(mordor_root)
    per_sc = max(1, -(-want["mordor"] // max(1, len(scenarios))))
    mordor_rows = generate_mordor(scenarios, seed=seed, variants=per_sc, val_pct=val_pct, xsoar_pct=xsoar_pct)[:want["mordor"]]

    synth_rows = generate_synth(want["synth"], seed=seed, injection_pct=0, val_pct=val_pct, cve_calibration=cve_calibration)
    product_rows = generate_products(want.get("products", 0) + n_prod_inj, seed=seed, val_pct=val_pct, weights=PRODUCT_WEIGHTS)
    r.shuffle(product_rows)
    inject_rows = [_inject_into(row, r) for row in inject_pool] + [_inject_into(row, r) for row in product_rows[:n_prod_inj]]
    product_rows = product_rows[n_prod_inj:]

    corrob_rows = generate_corroboration(want.get("corrob", 0), seed=seed, val_pct=val_pct)
    agentic_rows = generate_agentic(want.get("agentic", 0), seed=seed, val_pct=val_pct)
    endpoint_rows = generate_endpoint(want.get("endpoint", 0), seed=seed, val_pct=val_pct)

    rows = sigma_rows + mordor_rows + synth_rows + product_rows + corrob_rows + agentic_rows + endpoint_rows + inject_rows
    rows = [row for row in rows if fingerprint(json.loads(row["messages"][1]["content"])) not in held]
    # de-duplicate on alert fingerprint (a rule with few value choices can repeat)
    seen: set[str] = set(); uniq = []
    for row in rows:
        fp = fingerprint(json.loads(row["messages"][1]["content"]))
        if fp in seen:
            continue
        seen.add(fp); uniq.append(row)
    r.shuffle(uniq)
    stats = {"rules": len(rules), "scenarios": len(scenarios), "requested": want,
             "by_source": _count(uniq, lambda x: x["label_source"]),
             "by_verdict": _count(uniq, lambda x: json.loads(x["messages"][2]["content"])["verdict"]),
             "by_product": _count(uniq, lambda x: json.loads(x["messages"][1]["content"]).get("source")),
             "by_split": _count(uniq, lambda x: x["split"]), "deduped": len(rows) - len(uniq), "rows": len(uniq)}
    return uniq, stats


def _count(rows, key) -> dict:
    out: dict = {}
    for x in rows:
        k = str(key(x)); out[k] = out.get(k, 0) + 1
    return dict(sorted(out.items(), key=lambda kv: -kv[1]))


__all__ = ["DEFAULT_SHARES", "PRODUCT_WEIGHTS", "build_mixed", "fetch_corpora"]
