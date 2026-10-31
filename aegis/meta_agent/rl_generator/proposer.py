"""LLM-driven proposer for reward specs and PPO hyperparameters.

Default backend is whatever get_client() returns (Gemma if configured,
else Anthropic, else MockClient for offline demos). The mock provides
deterministic canned responses so the demo runs without API access.
"""
from __future__ import annotations

import logging
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal, Optional

from aegis.agents.shared.injection_defense import wrap_untrusted
from aegis.agents.shared.llm_client import LLMClient, parse_json

from .hyperparams import PPOHyperparams, parse_hyperparams_json
from .reward_spec import RewardSpec, parse_spec_json

logger = logging.getLogger("aegis.rl_generator")


_SYSTEM_FILE = Path(__file__).parent / "prompts" / "proposer_system.md"


ChangeType = Literal["reward_spec", "hyperparameters", "no_change"]


@dataclass
class RLProposal:
    id: str
    change_type: ChangeType
    spec: dict
    rationale: str
    expected_effect: str = ""
    metadata: dict = field(default_factory=dict)


def _system_prompt() -> str:
    return _SYSTEM_FILE.read_text(encoding="utf-8")


def _build_user_prompt(threat_observation: dict, current: dict) -> str:
    payload = json.dumps({
        "threat_observation": threat_observation,
        "current_reward_spec": current.get("reward_spec"),
        "current_hyperparameters": current.get("hyperparameters"),
        "recent_eval_metrics": current.get("recent_eval_metrics"),
    }, indent=2)
    wrapped = wrap_untrusted("rl_generator_input", payload)
    return (
        "Propose ONE adjustment to the RL setup based on the threat observation "
        "and current state below. Output JSON only per the schema.\n\n"
        f"{wrapped.wrapped}\n\n"
        "Remember: schema-bounded numeric values only; stay within safety bounds."
    )


# ---- Mock fallback ---------------------------------------------------

def _mock_proposal(threat_observation: dict, current: dict) -> RLProposal:
    """Deterministic canned response — used when MockClient is in play
    so the demo flows without an LLM. Real production runs use Gemma
    (or Claude) via the LLM proposer.
    """
    desc = (threat_observation.get("description") or "").lower()

    if "credential stuffing" in desc or "ato" in desc or "burst" in desc:
        # Campaign-mode policy: route ATTACK traffic to LLM escalation instead
        # of straight block so Tier 2 can apply behavioral biometrics + step-up
        # auth. Means escalate_malicious must exceed block_malicious so the
        # optimal policy under this spec actually shifts.
        current_spec = current.get("reward_spec") or {}
        new = dict(RewardSpec().as_dict())
        new.update(current_spec)
        new["escalate_malicious"] = 14.0         # > block_malicious so policy shifts
        new["block_malicious"] = 10.0
        new["allow_malicious"] = -100.0          # missed-attack much costlier
        new["confidence_calibration_bonus"] = 0.5
        return RLProposal(
            id="RL-PROP-CREDSTUFFING",
            change_type="reward_spec",
            spec=new,
            rationale=(
                "Credential-stuffing campaigns produce many borderline events. "
                "Make escalate_malicious dominate block_malicious so the policy "
                "routes attacks to Tier-2 LLM triage (with step-up auth) rather "
                "than hard-blocking, which both stops the attack AND captures "
                "behavioral signal for the Auth/IAM specialist."
            ),
            expected_effect=(
                "Detection rate on attack class up; escalation rate up (more LLM "
                "tier-2 cost while campaign is active); FP rate roughly stable."
            ),
            metadata={"source": "mock_canned"},
        )

    if "false positive" in desc or "false-positive" in desc or "fp spike" in desc or "fp-spike" in desc:
        current_spec = current.get("reward_spec") or {}
        new = dict(RewardSpec().as_dict())
        new.update(current_spec)
        new["block_benign"] = -6.0          # less harsh -> agent more conservative on FPs
        new["allow_benign"] = 2.0           # boost correct-allow reward
        return RLProposal(
            id="RL-PROP-FP-SPIKE",
            change_type="reward_spec",
            spec=new,
            rationale=(
                "False-positive spike observed; reducing block_benign penalty and "
                "boosting allow_benign reclaims ground on legitimate traffic."
            ),
            expected_effect="FP rate down; small uptick in missed-attack risk on borderline.",
            metadata={"source": "mock_canned"},
        )

    if "unstable" in desc or "exploration" in desc:
        new = dict(PPOHyperparams().as_dict())
        new["ent_coef"] = 0.01
        new["learning_rate"] = 1e-4
        return RLProposal(
            id="RL-PROP-EXPLORE",
            change_type="hyperparameters",
            spec=new,
            rationale=(
                "Training is unstable / exploration is shallow. Bumping ent_coef and "
                "lowering learning_rate stabilizes."
            ),
            expected_effect="Slower convergence, broader policy, more reliable end-state.",
            metadata={"source": "mock_canned"},
        )

    return RLProposal(
        id="RL-PROP-NOOP",
        change_type="no_change",
        spec={},
        rationale="No clear signal from threat observation; current setup likely fine.",
        expected_effect="N/A",
        metadata={"source": "mock_canned"},
    )


# ---- LLM path --------------------------------------------------------

def propose(threat_observation: dict, *,
            current: Optional[dict] = None,
            llm: Optional[LLMClient] = None) -> RLProposal:
    """Generate one RL proposal. Falls back to mock for offline demos."""
    current = current or {
        "reward_spec": RewardSpec().as_dict(),
        "hyperparameters": PPOHyperparams().as_dict(),
    }

    if llm is None or llm.name == "mock":
        return _mock_proposal(threat_observation, current)

    system = _system_prompt()
    user = _build_user_prompt(threat_observation, current)
    try:
        resp = llm.complete(system, user, max_tokens=1024)
        obj = parse_json(resp.text)
    except Exception as exc:  # noqa: BLE001
        logger.warning("[rl_generator] LLM proposal failed (%s: %s); using mock proposal", type(exc).__name__, str(exc)[:120])
        return _mock_proposal(threat_observation, current)

    change_type = obj.get("change_type", "no_change")
    spec_data = obj.get("spec") or {}
    rationale = str(obj.get("rationale", ""))
    effect = str(obj.get("expected_effect", ""))

    if change_type == "reward_spec":
        try:
            spec = parse_spec_json(spec_data).as_dict()
        except Exception:  # noqa: BLE001
            return _mock_proposal(threat_observation, current)
    elif change_type == "hyperparameters":
        try:
            spec = parse_hyperparams_json(spec_data).as_dict()
        except Exception:  # noqa: BLE001
            return _mock_proposal(threat_observation, current)
    else:
        spec = {}

    return RLProposal(
        id=f"RL-PROP-{abs(hash(rationale)) % 10000:04d}",
        change_type=change_type,
        spec=spec,
        rationale=rationale,
        expected_effect=effect,
        metadata={"source": llm.name, "model": llm.model},
    )
