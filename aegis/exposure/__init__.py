"""Exposure prioritisation — which vulnerabilities are exploitable, reachable and undefended, and why.

    python -m aegis.exposure --vulns tenable.json --aws-bundle bundle.json --inventory assets.csv \\
        --kev known_exploited_vulnerabilities.json --epss epss_scores.csv [--settings exposure.yaml]

See ``engine.py`` for the model and tiers, ``loaders.py`` for the input formats.
"""

from .engine import TIERS, Asset, Exposure, Settings, Vuln, assess, funnel, summarize

__all__ = ["TIERS", "Asset", "Exposure", "Settings", "Vuln", "assess", "funnel", "summarize"]
