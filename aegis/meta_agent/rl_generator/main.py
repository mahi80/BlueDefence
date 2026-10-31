"""RL-component generator main loop.

Demo: takes a synthetic threat observation, asks the proposer (Gemma /
Claude / mock) to suggest a reward-spec or hyperparameter adjustment,
trains a baseline classifier under the proposed spec, measures policy
quality vs the baseline, and queues the proposal for HITL if the
validator's gates pass.

Run:
  python -m aegis.meta_agent.rl_generator.main --threat credential-stuffing
  python -m aegis.meta_agent.rl_generator.main --threat fp-spike
  python -m aegis.meta_agent.rl_generator.main --threat exploration-stall
  python -m aegis.meta_agent.rl_generator.main --threat steady-state

Set LLM_BACKEND=gemma (with the model weights pre-pulled) for the
production-shape data-residency path; default is mock for offline demo.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from aegis.agents.shared.llm_client import get_client

from ..proposer import Proposal as MetaProposal
from ..queue import ProposalQueue
from ..validator import ValidationResult as MetaValidationResult
from .hyperparams import PPOHyperparams, parse_hyperparams_json
from .proposer import RLProposal, propose
from .reward_spec import RewardSpec, diff, parse_spec_json
from .validator import validate as validate_reward_spec


_QUEUE_PATH = Path(__file__).parent.parent / "_proposals.jsonl"


# Hand-built threat observations for the demo. Production replaces with
# a streaming summary of recent SIEM/EDR/auth signals.
_THREATS: dict[str, dict] = {
    "credential-stuffing": {
        "description": "Credential stuffing campaign on /api/login over the last 6 hours.",
        "signals": [
            "auth: 4x normal MFA failure rate",
            "perimeter: rising borderline payloads (single primitive, unknown IP)",
            "few outright malicious requests; many sub-threshold ones",
        ],
        "current_top_failure_mode": "agent allows borderline traffic that turns out to be real ATO",
    },
    "fp-spike": {
        "description": "False-positive spike: legit users getting blocked in the last 12 hours.",
        "signals": [
            "ServiceNow: 18 'falsely blocked' tickets in 12h vs 0-2 baseline",
            "perimeter: block_rate up 3x with no corresponding attack-traffic increase",
            "common pattern: lone primitive in a known-good user's request",
        ],
        "current_top_failure_mode": "agent over-blocks borderline traffic from baseline-matching users",
    },
    "exploration-stall": {
        "description": "Training stalled — policy collapses to 'allow' on most traffic.",
        "signals": [
            "TensorBoard: entropy near 0 by step 10000",
            "eval reward plateau below baseline",
            "gradient norms swinging between high and zero",
        ],
        "current_top_failure_mode": "training is unstable; exploration is too narrow",
    },
    "steady-state": {
        "description": "No notable threat patterns; baseline traffic and detection metrics.",
        "signals": [
            "all eval metrics within 1 SD of weekly baseline",
            "no campaigns flagged by Threat Intel agent",
            "FP and miss rates stable",
        ],
        "current_top_failure_mode": "none observed",
    },
}


def _summarize_proposal(prop: RLProposal) -> str:
    if prop.change_type == "no_change":
        return "  no_change (proposer chose not to adjust)"
    if prop.change_type == "reward_spec":
        baseline = RewardSpec()
        proposed = parse_spec_json(prop.spec)
        d = diff(baseline, proposed)
        if not d:
            return "  reward_spec (no fields differ from default)"
        lines = [f"  reward_spec changes vs default:"]
        for k, (a, b) in d.items():
            lines.append(f"    {k}: {a:+.2f} -> {b:+.2f}")
        return "\n".join(lines)
    if prop.change_type == "hyperparameters":
        proposed = parse_hyperparams_json(prop.spec)
        baseline = PPOHyperparams()
        lines = ["  hyperparameter changes vs default:"]
        for k, v in proposed.as_dict().items():
            bv = baseline.as_dict()[k]
            if v != bv:
                lines.append(f"    {k}: {bv} -> {v}")
        return "\n".join(lines)
    return f"  unknown change_type: {prop.change_type}"


def _to_meta_proposal(rl: RLProposal) -> MetaProposal:
    """Wrap an RLProposal in the existing meta-agent Proposal envelope so
    it lands in the same HITL queue as the heuristic-class proposals.
    """
    return MetaProposal(
        id=rl.id,
        target_module=(
            "aegis.meta_agent.rl_generator.reward_spec.RewardSpec"
            if rl.change_type == "reward_spec"
            else "aegis.meta_agent.rl_generator.hyperparams.PPOHyperparams"
            if rl.change_type == "hyperparameters"
            else "n/a"
        ),
        change_type=f"rl_{rl.change_type}",
        change=rl.spec,
        rationale=rl.rationale,
        evidence_case_ids=[],
        metadata={**rl.metadata, "expected_effect": rl.expected_effect},
    )


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--threat", default="credential-stuffing",
                   choices=list(_THREATS.keys()),
                   help="Synthetic threat observation to drive the demo")
    p.add_argument("--queue", default=str(_QUEUE_PATH))
    p.add_argument("--samples", type=int, default=4000,
                   help="Training-set size for the validator's baseline classifier")
    args = p.parse_args()

    threat = _THREATS[args.threat]
    print(f"\n[rl-gen] threat: {args.threat}")
    print(f"  {threat['description']}")
    for s in threat.get("signals", []):
        print(f"  - {s}")

    print(f"\n[rl-gen] phase 1: propose")
    llm = get_client()
    print(f"  LLM backend: {llm.name} ({llm.model})")
    rl = propose(threat, llm=llm)
    print(f"  proposal: {rl.id}  change_type={rl.change_type}")
    print(_summarize_proposal(rl))
    print(f"  rationale: {rl.rationale}")
    if rl.expected_effect:
        print(f"  expected:  {rl.expected_effect}")

    if rl.change_type == "no_change":
        print("\n[rl-gen] no proposal to validate. Exiting.")
        return 0

    print(f"\n[rl-gen] phase 2: validate (in simulation, sklearn baseline)")
    if rl.change_type == "reward_spec":
        proposed_spec = parse_spec_json(rl.spec)
        result = validate_reward_spec(
            proposed_spec, proposal_id=rl.id, samples=args.samples,
        )
        print(
            f"  baseline:  avg_reward={result.metric_baseline:+.3f}  "
            f"fp_rate={result.fp_rate_baseline:.3f}  miss_rate={result.miss_rate_baseline:.3f}"
        )
        print(
            f"  proposed:  avg_reward={result.metric_proposed:+.3f}  "
            f"fp_rate={result.fp_rate_proposed:.3f}  miss_rate={result.miss_rate_proposed:.3f}"
        )
        print(f"  delta:     {result.delta:+.3f}")
        print(f"  verdict:   {'ACCEPT' if result.recommend_accept else 'REJECT'}  ({result.notes})")
    else:
        # Hyperparameter validation requires real PPO training (torch).
        # Walking-skeleton stub: surface the proposal but mark as not
        # validatable in this lightweight runtime.
        print("  hyperparameter validation requires torch + sb3; skipping in lightweight mode")
        print("  to validate, run: python -m aegis.rl.train + observe convergence delta")
        result = MetaValidationResult(
            proposal_id=rl.id,
            failures_before=0, failures_after=0, regressions=0,
            recommend_accept=False,
            notes="hyperparameter validation deferred — needs full PPO training pipeline",
        )

    print(f"\n[rl-gen] phase 3: queue")
    queue = ProposalQueue(Path(args.queue))
    if rl.change_type == "reward_spec":
        # Adapt the rl validator's result into the meta-agent queue's shape.
        adapted = MetaValidationResult(
            proposal_id=result.proposal_id,
            failures_before=0, failures_after=0, regressions=0,
            recommend_accept=result.recommend_accept,
            notes=(
                f"avg_reward {result.metric_baseline:+.3f} -> {result.metric_proposed:+.3f} "
                f"(delta {result.delta:+.3f}), fp {result.fp_rate_baseline:.3f}->{result.fp_rate_proposed:.3f}, "
                f"miss {result.miss_rate_baseline:.3f}->{result.miss_rate_proposed:.3f}; {result.notes}"
            ),
        )
        if adapted.recommend_accept:
            queue.append(_to_meta_proposal(rl), adapted)
            print(f"  queued at {args.queue} (integrity: {'PASS' if queue.verify() else 'FAIL'})")
        else:
            print("  rejected; not queued")
    else:
        print("  hyperparameter proposals not auto-queued in lightweight mode")

    return 0


if __name__ == "__main__":
    sys.exit(main())
