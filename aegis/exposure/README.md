# Exposure prioritisation

Turns "thousands of CVEs" into "these few are exploitable, reachable and undefended" — with the reason
for every decision, so an analyst or auditor can check it.

```bash
python -m aegis.exposure \
  --vulns tenable_vulns.json \            # Tenable vulns export (JSON / JSONL) or a simple CSV
  --aws-bundle bundle.json \              # python -m aegis.posture export-aws (repeatable)
  --inventory assets.csv \                # on-prem assets, zones, roles, WAF / EDR coverage
  --kev known_exploited_vulnerabilities.json --epss epss_scores.csv \
  --settings exposure.yaml                # epss_threshold, virtual_patches {CVE: [asset | "*"]}
```

Try it on the sample bank: `S=aegis/exposure/samples; python -m aegis.exposure --vulns $S/tenable_vulns.json
--aws-bundle $S/aws_bundle.json --inventory $S/inventory.csv --kev $S/kev_sample.json --epss $S/epss_sample.csv
--settings $S/exposure.yaml` → `14 findings → 10 exploitable → 7 reachable → 5 undefended → 3 ACT NOW`.

## The four questions

| Question | Answer | From |
|---|---|---|
| Exploitable? | CISA KEV, EPSS ≥ threshold (default 0.1), or public exploit | scanner + KEV / EPSS feeds |
| Reachable? | `internet` · `one_hop` (an internet-facing asset in the same VPC / zone is **allowed** to reach it — security-group references are honoured) · `local` (no port: needs a foothold) · `isolated` | AWS posture bundle, inventory |
| Defended? | `full` = virtual patch / IPS rule for this CVE · `partial` = WAF on a web port · `none`. **EDR is reported but never lowers the tier** — it detects post-exploitation, it does not block the exploit | inventory / tags, `exposure.yaml` |
| Crown-jewel distance | 0 = the asset is a crown jewel (blast-graph sensitivity ≥ 0.85: core banking, SWIFT, KMS, payment API, jump host …), 1 = shares a zone with one | role from tags (`aegis:role`) or inventory |

| Tier | Rule |
|---|---|
| **ACT_NOW** | exploitable ∧ internet-reachable ∧ no blocking control |
| **ACT** | exploitable ∧ internet-reachable behind a WAF; or exploitable ∧ one hop ∧ undefended; or one hop next to a crown jewel |
| **SCHEDULE** | exploitable but isolated, local-only or virtually patched; or an unexploited critical facing the internet |
| **MONITOR** | everything else |

## Inventory CSV

`asset,name,ips,hostname,zone,role,public,internet_ports,lateral_ports,waf,edr` — ports as `443;8443`,
`8000-8100`, `all` or empty (internet: none, lateral: all). The inventory overrides what the cloud
collector inferred (role, WAF / EDR coverage). AWS instances can carry the same facts as tags:
`aegis:role`, `aegis:waf`, `aegis:edr`.

## Limits

Reachability is reasoned from network configuration, not proven by packets. No application-level
reachability (whether the vulnerable code path is called). Azure and Kubernetes reachability, load
balancers, WAF coverage from the connectors and the console view come in the next PRs (see the scope
doc).
