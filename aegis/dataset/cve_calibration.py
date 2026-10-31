"""Calibrate the synthetic CVE overlay to the REAL world (roadmap C3.3, option a).

The CVE overlay in ``synth.py`` teaches the triage model a *reaction policy* — actively-exploited
+ affects a deployed component → act now; high CVSS but not in our estate → watch. The policy is
right; the PROPORTIONS behind it (how often a high-severity CVE is actually known-exploited, how
CVSS bands are really distributed, how exploit maturity tracks with EPSS) were hand-guessed.

This module replaces the guesses with statistics measured from the real feeds AEGIS already pulls
(CISA-KEV + NVD + EPSS, via ``cve_feeds.CveIntel``). Crucially it extracts only AGGREGATE NUMBERS —
band weights, rates, maturity mix — never a real CVE id, vector, or product. The training rows stay
abstract (``CVE-SYN-NNNN`` placeholders); only the *distribution* they're sampled from becomes real,
so the model's instincts are calibrated to reality while the facts still come from live enrichment
at inference. The real CVE id/payload never enters the weights (the standing data rule holds).

It is opt-in (``AEGIS_CVE_CALIBRATE=1``): with it off, ``synth.generate`` runs its exact previous
path, so the default seeded dataset is byte-identical and nothing in CI or the gate shifts.

    python -m aegis.dataset.cve_calibration        # print the calibration derived from the local cache
"""

from __future__ import annotations

import logging
import os
import random
from dataclasses import dataclass, field
from typing import Any, Iterable, Optional

logger = logging.getLogger("aegis.dataset.cve_calibration")

VERDICTS = ("benign", "suspicious", "malicious")
# the two exploit-maturity buckets each verdict samples from, matching _cve_overlay's policy
MATURITY_PAIRS = {
    "benign": ("none", "poc"),
    "suspicious": ("poc", "weaponized"),
    "malicious": ("weaponized", "in_the_wild"),
}


def band_of(cvss: Optional[float]) -> Optional[str]:
    """CVSS base score → severity band (v3). None/0 → None (excluded from weighting)."""
    if cvss is None:
        return None
    if cvss <= 0:
        return None
    if cvss < 4.0:
        return "low"
    if cvss < 7.0:
        return "medium"
    if cvss < 9.0:
        return "high"
    return "critical"


def maturity_of(exploited: bool, epss: Optional[float]) -> str:
    """How far along the exploit is, from the real signals: KEV → in the wild; else by EPSS."""
    if exploited:
        return "in_the_wild"
    e = epss or 0.0
    if e >= 0.5:
        return "weaponized"
    if e >= 0.1:
        return "poc"
    return "none"


def _is_network(vector: str) -> bool:
    return "AV:N" in (vector or "")


def _wpick(r: random.Random, weights: dict[str, float]) -> str:
    """Deterministic weighted choice over {label: weight}; falls back to equal if all zero."""
    items = [(k, max(0.0, float(v))) for k, v in weights.items()]
    total = sum(w for _, w in items)
    if total <= 0:
        return r.choice([k for k, _ in items]) if items else ""
    x = r.random() * total
    acc = 0.0
    for k, w in items:
        acc += w
        if x < acc:
            return k
    return items[-1][0]


@dataclass
class CveCalibration:
    low_band_weights: dict[str, float] = field(default_factory=lambda: {"low": 1.0, "medium": 1.0})
    high_band_weights: dict[str, float] = field(default_factory=lambda: {"high": 1.0, "critical": 1.0})
    maturity_weights: dict[str, dict[str, float]] = field(default_factory=lambda: {
        "benign": {"none": 1.0, "poc": 1.0},
        "suspicious": {"poc": 1.0, "weaponized": 1.0},
        "malicious": {"weaponized": 1.0, "in_the_wild": 1.0},
    })
    kev_rate_suspicious: float = 0.5          # P(present act-now condition is "actively exploited")
    patch_rate: dict[str, float] = field(default_factory=lambda: {"suspicious": 0.7, "malicious": 0.6})
    remote_rate: float = 0.6                  # fraction network-exploitable (reported; not yet wired into rows)
    source: str = "default"
    sample_size: int = 0

    # -- samplers the overlay calls
    def pick_band(self, r: random.Random, verdict: str) -> str:
        return _wpick(r, self.low_band_weights if verdict == "benign" else self.high_band_weights)

    def pick_maturity(self, r: random.Random, verdict: str) -> str:
        return _wpick(r, self.maturity_weights.get(verdict, {}))

    def kev_present(self, r: random.Random) -> bool:
        return r.random() < self.kev_rate_suspicious

    def patch(self, r: random.Random, verdict: str) -> bool:
        return r.random() < self.patch_rate.get(verdict, 0.65)

    def summary(self) -> str:
        return (f"CVE calibration [{self.source}, n={self.sample_size}]: "
                f"bands low/med={_fmt(self.low_band_weights)} high/crit={_fmt(self.high_band_weights)}; "
                f"kev-rate(high-sev)={self.kev_rate_suspicious:.2f}; remote={self.remote_rate:.2f}; "
                f"maturity={{" + ", ".join(f'{v}:{_fmt(self.maturity_weights[v])}' for v in VERDICTS) + "}}")


def _fmt(w: dict[str, float]) -> str:
    total = sum(w.values()) or 1.0
    return "/".join(f"{k}={w[k] / total:.2f}" for k in w)


def _norm(counts: dict[str, int], keys: tuple[str, ...]) -> dict[str, float]:
    sub = {k: float(counts.get(k, 0)) for k in keys}
    return sub if sum(sub.values()) > 0 else {k: 1.0 for k in keys}


def from_records(records: Iterable[Any]) -> CveCalibration:
    """Derive calibration from CveRecord-like objects (``.cvss``, ``.cvss_vector``, ``.epss``,
    ``.exploited``). Only aggregate counts are read — no id, vector string, or product is retained."""
    band_counts: dict[str, int] = {}
    maturity_counts: dict[str, int] = {}
    high_sev = 0
    high_sev_kev = 0
    net = 0
    n = 0
    for rec in records:
        cvss = getattr(rec, "cvss", None)
        band = band_of(cvss)
        if band is None:
            continue
        n += 1
        band_counts[band] = band_counts.get(band, 0) + 1
        exploited = bool(getattr(rec, "exploited", False))
        mat = maturity_of(exploited, getattr(rec, "epss", None))
        maturity_counts[mat] = maturity_counts.get(mat, 0) + 1
        if _is_network(getattr(rec, "cvss_vector", "")):
            net += 1
        if band in ("high", "critical"):
            high_sev += 1
            if exploited:
                high_sev_kev += 1
    if n == 0:
        return CveCalibration()        # no usable records → defaults

    maturity_weights = {
        v: _norm(maturity_counts, MATURITY_PAIRS[v]) for v in VERDICTS
    }
    return CveCalibration(
        low_band_weights=_norm(band_counts, ("low", "medium")),
        high_band_weights=_norm(band_counts, ("high", "critical")),
        maturity_weights=maturity_weights,
        kev_rate_suspicious=round(high_sev_kev / high_sev, 4) if high_sev else 0.5,
        remote_rate=round(net / n, 4),
        source="real",
        sample_size=n,
    )


def from_intel(intel: Any) -> CveCalibration:
    return from_records(list(getattr(intel, "cves", {}).values()))


def calibration_from_env(*, enabled: Optional[bool] = None, intel: Any = None) -> Optional[CveCalibration]:
    """Return a calibration when AEGIS_CVE_CALIBRATE is on, else None (so synth keeps its exact
    default path). With it on but no real data cached, returns the DEFAULT calibration values."""
    if enabled is None:
        enabled = os.environ.get("AEGIS_CVE_CALIBRATE", "0").strip().lower() in ("1", "true", "yes", "on")
    if not enabled:
        return None
    if intel is None:
        try:
            from aegis.agents.threat_intel.cve_feeds import CveIntel
            intel = CveIntel()
        except Exception as exc:  # noqa: BLE001 — never let calibration setup break dataset generation
            logger.warning("[cve_calibration] CveIntel unavailable (%s); using default proportions", str(exc)[:160])
            return CveCalibration()
    cal = from_intel(intel)
    if cal.source == "real":
        logger.info("[cve_calibration] %s", cal.summary())
    else:
        logger.info("[cve_calibration] no cached KEV/NVD records; using default proportions "
                    "(run `python -m aegis.agents.threat_intel.cve_feeds refresh` on a box with feed access)")
    return cal


def main(argv: Optional[list[str]] = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    cal = calibration_from_env(enabled=True)
    print((cal or CveCalibration()).summary())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["CveCalibration", "from_records", "from_intel", "calibration_from_env", "band_of", "maturity_of"]
