# BlueDefence · AEGIS — walkthrough video

`BlueDefence-AEGIS-walkthrough.mp4` — 1920×1080, 7m24s, narrated throughout.

| Section | Time | Content |
|---|---|---|
| How it works | 0:00–5:10 | Product intro |
| Architecture | 5:10–5:55 | `architecture.png` — edge shim → deterministic detection → Agent Q triage → governed containment → learning loop |
| Live demo | 5:55–7:24 | Weakbank range: valid-login break-in, 25-record harvest, 100k-agent swarm → 40 incidents, Agent Q min-cut, analyst approval, edge denial |

Demo footage was captured from the local range (`pentestingtool` weakbank + `soc_live.py` + `soc-console`); see the live-demo runbook.
The architecture slide is `architecture.html` rendered at 1920×1080 — edit and re-screenshot to change it.

## Narration (5:10 onward)

- **How it works** — Before the demo, here is how AEGIS is built.
- **Architecture** — Thousands of endpoints sit behind an edge shim that mirrors every request. Stage one, detection: deterministic scorers, no language model, catch SQL injection, path traversal, SSRF, secret exfiltration and authorization abuse. Stage two, triage: Agent Q, our fine-tuned model, correlates raw alerts into incidents, maps the blast radius to the crown jewels, and proposes the minimum containment cut. Stage three, containment: the swarm executes, every step gated by ACP governance and a human approval. Every decision becomes training data for the next one.
- **Title** — Now, let's watch an AI agent try to rob a bank.
- **The target** — An internet bank with twenty thousand accounts, and real money moving.
- **The break-in** — An AI agent signs in with a valid username and password. To a firewall, this looks like a legitimate customer.
- **Data theft** — But it isn't. From one logged-in session it harvests twenty-five other customers' records: names, emails, credit scores.
- **The attack swarm** — Thousands of AI agents attacking at once: SQL injection, path traversal, SSRF, credential theft, and authenticated abuse with stolen sessions.
- **100,000 attackers** — AEGIS correlates them into forty incidents, not a hundred thousand alerts for a human to read.
- **Agent Q decides** — The fine-tuned model maps the blast radius to the core ledger and proposes the exact containment.
- **Human in the loop** — One analyst reviews the evidence and approves. Every decision is audited, and trains the model.
- **Contained** — The attacking source is denied at the edge. Clean customers keep banking, and its next attempts fold into the same incident. No new noise.
- **Close** — Valid login or not, the data does not leave. AEGIS. Autonomous SOC.
