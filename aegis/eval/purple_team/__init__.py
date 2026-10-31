"""Purple-team benchmark: scripted adaptive AI-agent attackers against the real AEGIS pipeline.

    python -m aegis.eval.purple_team                 # all campaigns, auto-block and human@300s, table + gate
    python -m aegis.eval.purple_team --mode auto --only rotating_sqli_agent --verbose
    python -m aegis.eval.purple_team --json out.json --approval-latency 120
    LLM_BACKEND=local AEGIS_LOCAL_4BIT=1 AEGIS_MODEL=<adapter> python -m aegis.eval.purple_team --mode auto
                                                     # measure a fine-tuned first-pass model (default: mock)

Reports, per campaign and response mode: when the attacker was first called malicious, when
it was contained, how many requests reached the application (and how many after detection),
sensitive endpoints reached, collateral on benign customers, and pipeline cost per event.
Gated campaigns fail the process (CI) when a threshold in ``scenarios.Gate`` is missed; the
remaining known-gap campaign (the same BOLA walk seen through WAF logs only, with no principal
or ownership map) is reported only — the case for why API-gateway logs are required.
"""

from .harness import Attacker, Attempt, CampaignResult, Harness, render, run_all
from .scenarios import CAMPAIGNS, Campaign, Gate, Goal

__all__ = ["Harness", "CampaignResult", "Attacker", "Attempt", "run_all", "render", "CAMPAIGNS", "Campaign", "Gate", "Goal"]
