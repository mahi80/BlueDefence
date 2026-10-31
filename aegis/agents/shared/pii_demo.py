"""Demo: PII tokenization roundtrip.

Shows the same alert before tokenization, what the LLM sees, and the
detokenized response. Demonstrates the contract: PII never reaches the
LLM call; the agent's structured output is detokenized so audit logs
retain real values.

Run:
  python -m aegis.agents.shared.pii_demo
"""
from __future__ import annotations

import json
import sys

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from .pii_tokenizer import PIITokenizer


_SAMPLE = """\
ALERT  Okta auth event
  user_email:    alice.kumar@acmebank.example
  alt_email:     alice.kumar@acmebank.example
  user_name:     Alice Kumar
  account:       ACC-000123456789
  aadhaar:       2345 6789 1011
  pan_card:      AAACA1234L
  ifsc:          HDFC0001234
  phone:         +91-98765-43210
  mfa_failures:  4 in 90s
  device:        new (UA mismatch)
  geo:           IN-MH -> RU-MO in 12 min
"""


def main() -> int:
    print("=" * 70)
    print("PII tokenization roundtrip demo")
    print("=" * 70)
    print("\n[1] Original alert (sees PII):")
    print(_SAMPLE)

    t = PIITokenizer()
    tokenized, mapping = t.tokenize(_SAMPLE)
    print("[2] Tokenized version (this is what the LLM sees):")
    print(tokenized)

    print(f"[3] Token map ({len(mapping.by_token)} tokens, {sum(t.stats(mapping).values())} replacements):")
    for token, value in mapping.by_token.items():
        print(f"  {token:<20} -> {value}")

    print(f"\n[4] Stats by kind: {t.stats(mapping)}")

    # Simulate an LLM verdict that references the tokens
    fake_llm_output = (
        '{"verdict": "malicious", "confidence": 0.92, '
        '"summary": "Impossible-travel for <PII:EMAIL:1> from <PII:AADHAAR:1>; '
        'recommend lock_account on <PII:ACCOUNT:1>.", '
        '"actions": [{"type": "lock_account", "target": "<PII:ACCOUNT:1>", '
        '"hitl": true, "confidence": 0.92}]}'
    )
    print("\n[5] Simulated LLM output (uses only tokens):")
    print(json.dumps(json.loads(fake_llm_output), indent=2))

    detok = t.detokenize(fake_llm_output, mapping)
    print("\n[6] Detokenized output (this is what the audit log + ServiceNow see):")
    print(json.dumps(json.loads(detok), indent=2))

    # Roundtrip safety check
    re_tok, re_map = t.tokenize(detok)
    if re_tok == fake_llm_output:
        print("\n[7] Roundtrip integrity: PASS (re-tokenize matches original)")
    else:
        print("\n[7] Roundtrip integrity: FAIL")
        print(f"    expected: {fake_llm_output[:120]}...")
        print(f"    got:      {re_tok[:120]}...")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
