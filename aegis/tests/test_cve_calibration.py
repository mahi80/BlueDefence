"""CVE calibration (C3.3): the synthetic overlay's proportions come from real KEV/NVD/EPSS
statistics, while the training rows stay abstract (CVE-SYN, never a real id). Opt-in, so the
default seeded dataset is unchanged. No network, no real feeds — fake records throughout."""

from __future__ import annotations

import json
import random

from aegis.dataset.cve_calibration import (
    CveCalibration, band_of, calibration_from_env, from_intel, from_records, maturity_of,
)
from aegis.dataset.synth import generate


class Rec:
    """A CveRecord-like stand-in — fabricated, never a real CVE."""
    def __init__(self, cvss=None, vector="", epss=None, kev=False):
        self.cvss = cvss
        self.cvss_vector = vector
        self.epss = epss
        self.exploited = kev


# -- primitives --------------------------------------------------------------

def test_band_of_boundaries():
    assert band_of(None) is None and band_of(0) is None
    assert band_of(3.9) == "low" and band_of(4.0) == "medium" and band_of(6.9) == "medium"
    assert band_of(7.0) == "high" and band_of(8.9) == "high"
    assert band_of(9.0) == "critical" and band_of(10.0) == "critical"


def test_maturity_of():
    assert maturity_of(True, 0.0) == "in_the_wild"       # KEV wins
    assert maturity_of(False, 0.6) == "weaponized"
    assert maturity_of(False, 0.2) == "poc"
    assert maturity_of(False, 0.01) == "none"
    assert maturity_of(False, None) == "none"


# -- derivation from real-shaped records -------------------------------------

def test_from_records_derives_real_proportions():
    recs = (
        [Rec(cvss=9.5, vector="CVSS:3.1/AV:N/AC:L", epss=0.9, kev=True)] * 3 +    # critical, in_the_wild, net
        [Rec(cvss=8.0, vector="AV:N", epss=0.3)] * 1 +                            # high, poc, net
        [Rec(cvss=5.0, vector="AV:L", epss=0.02)] * 4 +                           # medium, none, local
        [Rec(cvss=2.0, epss=0.0)] * 2 +                                           # low, none
        [Rec(cvss=None)]                                                          # skipped
    )
    cal = from_records(recs)
    assert cal.source == "real" and cal.sample_size == 10          # the None record is excluded
    # bands: low=2 medium=4 → low 1/3 ; high=1 critical=3 → critical 3/4
    assert round(cal.low_band_weights["low"] / sum(cal.low_band_weights.values()), 2) == 0.33
    assert round(cal.high_band_weights["critical"] / sum(cal.high_band_weights.values()), 2) == 0.75
    # of the 4 high-severity records, 3 are KEV
    assert cal.kev_rate_suspicious == 0.75
    # 4 of 10 carry AV:N
    assert cal.remote_rate == 0.4


def test_from_records_empty_falls_back_to_default():
    cal = from_records([])
    assert cal.source == "default" and cal.sample_size == 0


def test_from_intel_reads_cves():
    intel = type("I", (), {"cves": {"a": Rec(cvss=9.0, kev=True), "b": Rec(cvss=5.0)}})()
    assert from_intel(intel).source == "real"


# -- samplers ----------------------------------------------------------------

def test_weighted_samplers_respect_zero_weight():
    cal = CveCalibration(high_band_weights={"high": 0.0, "critical": 1.0})
    r = random.Random(0)
    assert all(cal.pick_band(r, "malicious") == "critical" for _ in range(50))


def test_samplers_return_valid_values():
    cal = CveCalibration()
    r = random.Random(1)
    assert cal.pick_band(r, "benign") in ("low", "medium")
    assert cal.pick_maturity(r, "suspicious") in ("poc", "weaponized")
    assert isinstance(cal.kev_present(r), bool) and isinstance(cal.patch(r, "malicious"), bool)


# -- env wiring --------------------------------------------------------------

def test_calibration_from_env_off_returns_none():
    assert calibration_from_env(enabled=False) is None


def test_calibration_from_env_on_uses_intel():
    intel = type("I", (), {"cves": {"a": Rec(cvss=9.1, kev=True)}})()
    assert calibration_from_env(enabled=True, intel=intel).source == "real"
    empty = type("I", (), {"cves": {}})()
    assert calibration_from_env(enabled=True, intel=empty).source == "default"


# -- synth integration: default unchanged, calibrated steers, constraint holds

def _cves(rows):
    out = []
    for row in rows:
        alert = json.loads(row["messages"][1]["content"])
        if isinstance(alert.get("cve"), dict):
            out.append((json.loads(row["messages"][2]["content"]).get("verdict"), alert["cve"]))
    return out


def test_default_generation_is_deterministic_and_unchanged():
    # the opt-in param defaults to None → identical to calling generate without it
    assert generate(80, seed=3) == generate(80, seed=3)
    assert generate(80, seed=3) == generate(80, seed=3, cve_calibration=None)


def test_all_refs_are_synthetic_never_a_real_cve():
    for _, cve in _cves(generate(120, seed=5, cve_pct=100)):
        assert cve["cve_ref"].startswith("CVE-SYN-")        # never a real CVE id, calibrated or not


def test_calibration_steers_the_distribution():
    cal = CveCalibration(
        low_band_weights={"low": 0.0, "medium": 1.0},
        high_band_weights={"high": 0.0, "critical": 1.0},
        maturity_weights={"benign": {"none": 1.0, "poc": 0.0},
                          "suspicious": {"poc": 1.0, "weaponized": 0.0},
                          "malicious": {"weaponized": 0.0, "in_the_wild": 1.0}},
        kev_rate_suspicious=1.0,
        patch_rate={"suspicious": 1.0, "malicious": 0.0},
    )
    cves = _cves(generate(200, seed=5, cve_pct=100, cve_calibration=cal))
    assert cves, "expected some CVE-overlaid rows"
    for verdict, cve in cves:
        assert cve["cve_ref"].startswith("CVE-SYN-")
        if verdict == "benign":
            assert cve["cvss_band"] == "medium" and cve["exploit_maturity"] == "none"
        elif verdict == "suspicious":
            assert cve["cvss_band"] == "critical" and cve["cve_known_exploited"] is True
        else:
            assert cve["cvss_band"] == "critical" and cve["exploit_maturity"] == "in_the_wild"
            assert cve["patch_available"] is False
