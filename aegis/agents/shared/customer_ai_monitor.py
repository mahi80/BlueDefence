"""Customer-facing AI input monitor.

The bank may run its own customer-facing AI agents (chatbot, fraud-
explainer, KYC bot). Those agents' inputs are attacker-controlled
in the same way HTTP traffic is — they need the same injection-
detection scaffolding AEGIS uses internally. This module provides:

  - `pre_check(message)` -> CustomerAIVerdict
    Runs injection-defense scan + jailbreak-prompt detection +
    sensitive-data leakage detection on the inbound message before it
    reaches the customer-facing model. Designed for a sub-millisecond
    hot path (no LLM call) so it can sit in front of every prompt.

  - `post_check(model_output)` -> CustomerAIVerdict
    Scans the model's response for accidentally-disclosed sensitive
    data (PII, internal URLs, system-prompt fragments) before the
    response is returned to the customer.

This is a pre/post FILTER, not a specialist. The bank's existing
customer-facing AI app calls these hooks; if either trips the threshold
the request is reject/redact/escalated. Findings are also logged into
the AEGIS audit log so the SOC sees the trend.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Literal

from .injection_defense import _scan_obfuscation, _INJECTION_HEURISTICS

_INJECTION_PATTERNS = [re.compile(p, re.IGNORECASE) for p in _INJECTION_HEURISTICS]


CustomerAIVerdict_Type = Literal["allow", "redact", "block", "escalate"]


@dataclass
class CustomerAIVerdict:
    decision: CustomerAIVerdict_Type
    confidence: float
    reason: str
    matched_patterns: list[str] = field(default_factory=list)
    obfuscation_findings: list[str] = field(default_factory=list)
    redacted_text: str = ""


# ---- Jailbreak / role-override patterns ------------------------------

# Specific to customer-facing AI: phrases that try to convince the
# model to abandon its system prompt or expose its instructions.
# Distinct from the broader _INJECTION_PATTERNS in injection_defense
# (those target AEGIS's own agents).
_JAILBREAK_PATTERNS = [
    re.compile(r"\bDAN mode\b", re.IGNORECASE),
    re.compile(r"\b(?:do anything now|developer mode)\b", re.IGNORECASE),
    re.compile(r"\bpretend\s+you\s+are\s+(?:not|no longer)\b", re.IGNORECASE),
    re.compile(r"\b(?:reveal|show|print)\s+(?:your\s+)?system prompt\b", re.IGNORECASE),
    re.compile(r"\bignore\s+(?:your|the)\s+(?:safety|ethical)\s+(?:rules|guidelines)\b", re.IGNORECASE),
    re.compile(r"\boutput\s+the\s+initial\s+instructions\b", re.IGNORECASE),
    re.compile(r"\bbypass\s+(?:your\s+)?(?:filter|content policy)\b", re.IGNORECASE),
    # Indian-bank-specific bait
    re.compile(r"\bact\s+as\s+(?:the\s+)?(?:rbi|reserve bank)\b", re.IGNORECASE),
    re.compile(r"\bshow\s+me\s+(?:the\s+)?(?:other|another)\s+customer", re.IGNORECASE),
]


# ---- Sensitive-output patterns --------------------------------------

# What the model must NOT emit to a customer.
_SENSITIVE_OUTPUT_RX = {
    "aadhaar":           re.compile(r"\b\d{4}\s\d{4}\s\d{4}\b"),
    "pan_in":            re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b"),
    "credit_card":       re.compile(r"\b(?:\d[ -]*?){13,19}\b"),
    "internal_hostname": re.compile(r"\b[a-z0-9-]+\.(?:internal|corp|prod)\.bank\.in\b"),
    "system_prompt_leak": re.compile(
        r"(?:You are\s+(?:the\s+)?(?:bank|customer)|system prompt|my instructions are)",
        re.IGNORECASE,
    ),
    "private_key":       re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"),
    "aws_key":           re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
}


def pre_check(message: str, *, max_message_length: int = 8000) -> CustomerAIVerdict:
    """Inbound check: runs before the customer's message hits the model.
    Decisions:
      - allow: no concerns
      - redact: minor injection signal, redact the offending fragments
        and let the model handle the rest
      - block: jailbreak attempt or oversized payload — return generic
        error to customer, log for SOC review
      - escalate: high-confidence prompt-injection that warrants SOC
        eyeballs (multiple jailbreak patterns + obfuscation)
    """
    if not isinstance(message, str):
        return CustomerAIVerdict(decision="block", confidence=1.0, reason="non-string input")

    if len(message) > max_message_length:
        return CustomerAIVerdict(
            decision="block", confidence=0.95,
            reason=f"oversized input ({len(message)} > {max_message_length})",
        )

    matched = [p.pattern for p in _INJECTION_PATTERNS if p.search(message)]
    jailbreak = [p.pattern for p in _JAILBREAK_PATTERNS if p.search(message)]
    findings, _ = _scan_obfuscation(message)

    if jailbreak and (len(matched) >= 1 or findings):
        return CustomerAIVerdict(
            decision="escalate",
            confidence=0.92,
            reason="jailbreak phrasing + injection / obfuscation co-occurrence",
            matched_patterns=matched + jailbreak,
            obfuscation_findings=findings,
        )
    if jailbreak:
        return CustomerAIVerdict(
            decision="block",
            confidence=0.85,
            reason="jailbreak phrasing detected",
            matched_patterns=jailbreak,
        )
    if matched and findings:
        return CustomerAIVerdict(
            decision="block",
            confidence=0.8,
            reason="injection patterns + obfuscation chars co-occurrence",
            matched_patterns=matched,
            obfuscation_findings=findings,
        )
    if findings or len(matched) >= 1:
        # Redact the matched fragments rather than block entirely.
        redacted = message
        for pat in (matched or []):
            redacted = re.sub(pat, "[REDACTED]", redacted, flags=re.IGNORECASE)
        return CustomerAIVerdict(
            decision="redact",
            confidence=0.65,
            reason="single signal — redacting and continuing",
            matched_patterns=matched,
            obfuscation_findings=findings,
            redacted_text=redacted,
        )
    return CustomerAIVerdict(decision="allow", confidence=0.95, reason="clean")


def post_check(model_output: str) -> CustomerAIVerdict:
    """Outbound check: runs on the model's response before delivering
    to the customer. Catches accidental sensitive-data disclosure or
    system-prompt regurgitation.
    """
    if not isinstance(model_output, str):
        return CustomerAIVerdict(decision="block", confidence=1.0, reason="non-string model output")

    findings: list[str] = []
    redacted = model_output
    for kind, rx in _SENSITIVE_OUTPUT_RX.items():
        if rx.search(model_output):
            findings.append(kind)
            redacted = rx.sub(f"[REDACTED:{kind}]", redacted)

    if any(k in findings for k in ("private_key", "aws_key", "system_prompt_leak")):
        return CustomerAIVerdict(
            decision="block", confidence=0.97,
            reason=f"high-severity output disclosure: {findings}",
            matched_patterns=findings,
            redacted_text=redacted,
        )
    if findings:
        return CustomerAIVerdict(
            decision="redact", confidence=0.85,
            reason=f"output sensitive-data redaction: {findings}",
            matched_patterns=findings,
            redacted_text=redacted,
        )
    return CustomerAIVerdict(decision="allow", confidence=0.95, reason="clean")
