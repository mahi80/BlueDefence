"""Self-evolving loop, runtime half (roadmap Phase 3.1).

The meta-agent proposes → a human accepts in the dashboard (audited) → the
dashboard serves the accepted set as a versioned rule feed → every SOC
agent pulls it and applies the rules in-process, no code change, no
redeploy. The "antivirus definitions" update.

    RuleFeed      GET /api/soc/rules (version, rules[])
    RuleApplier   validates each rule against the PATCHABLE allowlist and
                  applies it; idempotent per version; revert_all()
    sync_from_env  one call at startup (and whenever you want a refresh)
"""

from .applier import ApplyReport, RuleApplier
from .feed import FeedSnapshot, RuleFeed, sync_from_env
from .registry import PATCHABLE, PatchSpec

__all__ = ["ApplyReport", "RuleApplier", "FeedSnapshot", "RuleFeed", "sync_from_env", "PATCHABLE", "PatchSpec"]
