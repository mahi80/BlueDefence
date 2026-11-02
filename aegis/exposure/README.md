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

## Reachability sources

| Source | Internet path | Lateral (one hop) |
|---|---|---|
| **AWS** (`--aws-bundle`) | public IP + security group open to the world; **internet-facing ALB / NLB** listener → target port (ALB listeners must be open in the LB's SGs; an NLB without SGs passes every listener). AWS WAF web ACL on the ALB = WAF in front | SG rules from private CIDRs (any host) or from **referenced security groups** (only members) |
| **Azure** (`--azure-bundle`) | public IP and the **subnet NSG ∩ NIC NSG** admit Internet sources — rules evaluated in priority order with Azure's default rules; **public load-balancer rules** → backend port, only if the backend's NSGs admit it. No NSG + Standard public IP = closed | VirtualNetwork / private-CIDR sources, same evaluation |
| **Kubernetes** (`--k8s-export [name=]file`) | `LoadBalancer` Service (not internal-annotated) → target port; `Ingress` (not internal) → backend Service → target port, WAF annotation (AWS WAFv2, ModSecurity, App Gateway) = WAF; `NodePort` only with `--public-nodes` | any pod in the cluster, unless the namespace has a NetworkPolicy (treated as restricting; rules not yet evaluated) |
| **On-prem** (`--inventory`) | `public` + `internet_ports` | `lateral_ports` within the zone |

Container image findings (Trivy `trivy image -f json`) attach to the workloads running that image and are
judged by what the workload exposes; they are capped at **ACT** because a package CVE is not proven to be on
the exposed path. The collectors export what this needs: `export-aws` now includes load balancers,
listeners, targets and WAF associations; `export-azure` includes VMs, NICs, VNets and load balancers; the
kubectl export command includes Services and Ingresses.

## WAF / virtual-patch coverage

"We have a WAF" is the most common false comfort in a SOC — many sit in **monitor mode** for months.
Coverage comes from the vendors, not from tags:

```bash
python -m aegis.exposure.coverage --vendor imperva    --out imperva.json   # AEGIS_WAF_API_ID / AEGIS_WAF_API_KEY
python -m aegis.exposure.coverage --vendor f5         --out f5.json        # AEGIS_WAF_URL / _USER / _PASS (or _TOKEN)
python -m aegis.exposure.coverage --vendor cloudflare --zone ZONE --out cf.json   # CLOUDFLARE_API_TOKEN
python -m aegis.exposure.coverage --vendor edge --edge-url http://edge-01:9000 --out edge.json
python -m aegis.exposure ... --waf-coverage imperva.json --waf-coverage f5.json
```

| Vendor | Fronts | Blocking when | Virtual patches |
|---|---|---|---|
| Imperva Cloud WAF | site origin IPs + domain | core WAF rules set to block | custom rules that block and name a CVE |
| F5 BIG-IP Advanced WAF | ASM policy → virtual server VIP + pool members | policy enforcement mode `blocking` | user-defined signatures naming a CVE (blocking policies only) |
| Cloudflare | proxied DNS records (origin + hostname) | a managed ruleset is deployed | enabled custom `block` rules naming a CVE |
| BlueDefence edge shim | its upstream host:port | `--mode live` with `--inline-waf` | — |

A **monitor-mode** protection never counts as a defence; the reason chain names it ("imperva
reports.bank.example in front but in MONITOR mode: it logs the attack and lets it through"). A blocking
protection is a WAF on web ports (`partial`); a matching virtual patch makes that CVE `full`. Fronts match
asset IPs / hostnames and also load-balancer names / DNS names and Ingress hosts, so a Cloudflare record
pointing at an ALB credits the instances behind it. All exporters are read-only (GET, plus Imperva's
POST *list* endpoint); field names follow the public API docs, so a tenant may need a field renamed.

## In the VAPT loop and the console

Add a `type: exposure` scan to `posture.yaml` (sample: `samples/posture_exposure.yaml`) and the runner
tracks exposures like every other finding: the tier becomes the severity (ACT_NOW → critical, ACT → high,
SCHEDULE → medium, MONITOR → low), so the remediation SLA, new / resolved tracking and the waiver register
apply. The finding id is the CVE and the component is `asset:port`, so when a finding changes tier (a WAF
goes to blocking mode, a CVE lands in KEV) it keeps its first-seen date instead of looking new. Each run's
report carries the funnel, and the SOC console's **Exposures** tab shows it with every exposure's four
answers colour-coded and the reason behind each.

```yaml
  - name: exposure-prod
    type: exposure
    vulns: [exports/tenable.json, exports/trivy]          # files or directories
    aws_bundles: [exports/aws-prod.json]
    azure_bundles: [exports/azure-prod.json]
    k8s_exports: [eks-payments=exports/eks-payments.json]
    inventory: exports/onprem-assets.csv
    kev: feeds/known_exploited_vulnerabilities.json
    epss: feeds/epss_scores.csv
    waf_coverage: [exports/imperva.json, exports/edge.json]
    settings: exposure.yaml
```

## Inventory CSV

`asset,name,ips,hostname,zone,role,public,internet_ports,lateral_ports,waf,edr` — ports as `443;8443`,
`8000-8100`, `all` or empty (internet: none, lateral: all). The inventory overrides what the cloud
collector inferred (role, WAF / EDR coverage). AWS instances can carry the same facts as tags:
`aegis:role`, `aegis:waf`, `aegis:edr`.

## Limits

Reachability is reasoned from network configuration, not proven by packets. No application-level
reachability (whether the vulnerable code path is called). Not yet modelled: Azure Application Gateway /
Front Door, AWS classic ELB and CloudFront, Kubernetes NetworkPolicy rule evaluation, NACLs; Cloudflare
managed-rule CVE coverage beyond "managed ruleset deployed". Proposing the compensating control through
the HITL queue and re-testing closure is the next PR (see the scope doc).
