"""Phase 3.2 — the dataset the self-evolving loop produces (roadmap `docs/plans/aegis-production-roadmap.md`).

Three pieces:

- **capture** (`capture.py`): every chain the orchestrator finalises carries a
  scrubbed snapshot of the alert it judged (`metadata.alert`), so the local
  audit JSONL and the dashboard's `soc_evidence_chains` rows hold both input
  and outcome. `AEGIS_DATASET_CAPTURE=0` turns it off; `AEGIS_DATASET_SALT`
  keys the pseudonyms.
- **sources** (`sources.py`): eval corpora (held-out test set), local audit
  log, dashboard chains joined with the analysts' approve/reject decisions,
  meta-agent proposals with their decisions, advisory / scenario / technique
  text.
- **export** (`export.py`, CLI `python -m aegis.dataset export`): versioned
  directory with `records.jsonl`, chat-format SFT views, `manifest.json`
  (counts, provenance, file hashes) and `verify` for lineage checks.
"""

from .capture import attach, capture_alert, capture_enabled
from .export import BuildOptions, DatasetBuilder, verify_dataset
from .schema import SCHEMA_VERSION, HumanDecision, TriageRecord, fingerprint, record_from_chain
from .scrub import Scrubber, scrubber_from_env

__all__ = [
    "SCHEMA_VERSION", "Scrubber", "scrubber_from_env", "attach", "capture_alert", "capture_enabled",
    "BuildOptions", "DatasetBuilder", "verify_dataset", "HumanDecision", "TriageRecord", "fingerprint",
    "record_from_chain",
]
