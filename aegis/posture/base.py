"""Shared finding type for the posture scanners."""

from __future__ import annotations

from collections import Counter
from dataclasses import asdict, dataclass

from ..agents.vuln_discovery.tools import Finding

SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")

# Posture findings are misconfigurations, not CVEs: there is no EPSS/KEV signal to weight, so the
# severity is set by the check itself and the risk score follows from it (keeps the shared queue's
# risk-sorted ordering meaningful next to CVE findings).
_RISK_FOR_SEVERITY = {"critical": 0.95, "high": 0.8, "medium": 0.55, "low": 0.3, "info": 0.1}


@dataclass
class PostureFinding(Finding):
    control: str | None = None   # benchmark control, e.g. "CIS AWS Foundations v2.0 1.4"
    resource: str | None = None  # ARN / object reference the finding is about
    scanner: str = ""            # iam_review | cspm | k8s_posture | iac_policy | exposure
    extra: dict | None = None    # scanner-specific detail (exposure: tier, reach, defended, reasons)

    def __post_init__(self) -> None:
        if self.severity not in _RISK_FOR_SEVERITY:
            raise ValueError(f"unknown severity {self.severity!r}")
        if self.risk_score is None:
            self.risk_score = _RISK_FOR_SEVERITY[self.severity]

    def as_dict(self) -> dict:
        return asdict(self)


def sort_findings(findings: list[PostureFinding]) -> list[PostureFinding]:
    """Most severe first, then by resource so the output is stable."""
    return sorted(findings, key=lambda f: (SEVERITY_ORDER.index(f.severity), f.id, f.resource or ""))


def summarize(findings: list[PostureFinding]) -> dict[str, int]:
    c = Counter(f.severity for f in findings)
    return {s: c.get(s, 0) for s in SEVERITY_ORDER}
