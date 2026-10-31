"""Public-data importers for the triage training set (roadmap 3.3 "realistic data").

Each importer turns a public, labelled security corpus into the exact SFT shape
``DatasetBuilder`` writes, tagged ``label_source="public:<name>"`` so the trainer and the manifest
can always tell it apart from analyst-labelled rows and from ``synthetic`` rows.

- :mod:`.sigma`  — SigmaHQ detection rules (3,000+): each rule's logic is the *alert shape*, its
  ATT&CK tags and level are the label; emitted in the native alert format of the products the
  CISO assessment names (CrowdStrike Falcon, Sophos Central, Microsoft Defender for Endpoint,
  Microsoft Sentinel, Zscaler ZIA, Imperva Cloud WAF, F5 ASM, Cortex XSOAR envelope).
- :mod:`.mordor` — OTRF Security-Datasets: real adversary-emulation scenarios with ATT&CK
  mappings, emitted as Sentinel incidents.
- :mod:`.products_gen` — profile-driven rows for the products Sigma covers thinly: Imperva/F5 WAF,
  Zscaler ZIA + ZPA, Defender for Identity / Cloud Apps / Office 365, Sophos Firewall, native
  Cortex XSOAR incidents — verdict from field combinations, never one field.
- :mod:`.corroboration` — raw-field alerts with no detection name, labelled by the corroboration
  rule (≥2 independent strong signals → malicious; 1 → suspicious; 0 → benign; an approved change
  neutralises change-related signals only). The policy the model kept missing on the gate.
- :mod:`.agentic` — campaign-shaped alerts from AI-agent attacks on the client side; the stack
  (React … PHP, mobile, GraphQL) is a context field that varies and is never a signal; signals are
  behavioural (recon artefacts, enumeration without a page-load chain, automation fingerprint,
  adaptive mutation, client-integrity breaks, beaconing, recon→exploit speed).
- :mod:`.endpoint` — the endpoint-security gaps Sigma does not cover: sensor tampering and inventory
  drift, ransomware-rate telemetry with canary files, the infostealer → session-replay chain,
  removable media, mobile banking-trojan posture, branch / ATM / kiosk whitelisting.
- :mod:`.mix`    — the recipe that combines public + synthetic + injection rows into one dataset.

Nothing here is committed as data: the corpora are cloned at build time and the output lands in
the dataset directory you choose.
"""

from .agentic import generate_agentic
from .corroboration import generate_corroboration
from .endpoint import generate_endpoint
from .mix import build_mixed, fetch_corpora
from .mordor import generate_mordor, load_scenarios
from .products_gen import generate_products
from .sigma import generate_sigma, load_rules

__all__ = ["build_mixed", "fetch_corpora", "generate_agentic", "generate_corroboration", "generate_endpoint", "generate_mordor", "generate_products", "generate_sigma", "load_rules", "load_scenarios"]
