# All-AWS shadow pilot

One `terraform apply` stands up a real, internet-facing shadow deployment of BlueDefence with its own
attack traffic — no bank, no vendor tenant, no Azure. It exists to answer the question every CISO asks
before a pilot: *"what would AEGIS have said about traffic my WAF already judged?"*

```
                     us-east-1 (CloudFront edge)                        ap-southeast-2 (Sydney)
   internet ──► CloudFront ──► AWS WAF ──► S3 decoy page           ┌──────────────────────────────┐
   scanners        │          (managed rules,                       │ aegis-host  t4g.large         │
   bots            │           rate rule)                           │  nginx :443 (Let's Encrypt)   │
   you             │                                                │   ├ /ingest/*  → AEGIS :8787  │
                   └── every evaluated request ──► Firehose ──────► │   ├ /healthz                  │
                       (gzip JSON, X-Amz-Firehose-Access-Key)       │   └ /          → console :3000│
                                                                    │  aegis-soc.service  (shadow)  │
                                                                    │  aegis-console.service        │
                                                                    └──────────────────────────────┘
```

AEGIS runs in **shadow** mode with a **Community** licence: it proposes, audits and would-have-blocked;
it never touches the WAF. The WAF's own `action` field on every record is the baseline the shadow report
compares against (`python -m aegis.service --status`, and the per-connector shadow comparison in
`aegis/README.md`).

## Cost (on-demand, ap-southeast-2 + us-east-1, light traffic)

| Item | Monthly |
|---|---|
| EC2 t4g.large (2 vCPU / 8 GB, Graviton) | ~$49 |
| 50 GB gp3 root volume | ~$4 |
| AWS WAF: 1 web ACL + 5 rules + requests | ~$11 |
| CloudFront + S3 decoy (a few GB) | < $2 |
| Firehose (HTTP endpoint delivery) | < $1 |
| Route 53 hosted zone (if used) | $0.50 |
| Elastic IP (attached) | $0 |
| **Total** | **≈ $65–75** |

A `.click` domain is $3/year on Route 53. Stop the instance when idle (`aws ec2 stop-instances`) and the
EC2 line drops to the volume only; the Elastic IP then costs $3.60/month while detached from a running
instance.

## Before you apply

1. **Terraform** ≥ 1.6 on your PC (`winget install Hashicorp.Terraform`) and the AWS CLI signed in to the
   account (a paid plan — the Free Tier plan blocks Route 53 Domains and will close the account when its
   credits end). If you sign in with `aws login`, the Terraform provider cannot read that session yet:
   `pilot.ps1` runs `aws configure export-credentials --format powershell | Invoke-Expression` for you
   (do the same by hand before a bare `terraform` command). **Region**: accounts created under an AWS
   organisation often carry a service control policy that denies some regions — `terraform plan` shows
   `explicit deny in a service control policy` if so. Sydney (`ap-southeast-2`) is the default; set
   `region = "ap-south-1"` only if the plan goes through there.
2. **A domain** that will point at the host. Firehose only delivers to a public HTTPS endpoint with a
   certificate a public CA issued, so `https://<ip>` is not an option.
   - Route 53: `aws route53domains register-domain --region us-east-1 …` (registration creates the
     hosted zone; its id goes into `route53_zone_id` and the A record is managed for you), or
   - any registrar: leave `route53_zone_id` empty and create the A record yourself after the first apply.
3. **Session Manager plugin** for `.\pilot.ps1 shell`
   (https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager-working-with-install-plugin.html).
   No SSH port is opened unless you set `admin_cidr`.

## Apply

```powershell
cd deploy\aws-pilot
copy terraform.tfvars.example terraform.tfvars      # edit: domain, community_org, community_email, route53_zone_id
.\pilot.ps1 up                                       # ~4 min; CloudFront takes a few more to deploy
```

What the first boot does on the host (log: `/var/log/bluedefence-bootstrap.log`):

| Step | Detail |
|---|---|
| `install.sh --community --non-interactive` | signs up a Community licence for `community_org`, writes `/etc/aegis/aegis.env` with `AEGIS_ENFORCEMENT_MODE=shadow`, `AEGIS_SOURCES=stream`, the ingest token, starts `aegis-soc` (systemd `Type=notify`, watchdog, rollback — see the on-prem guide) |
| console | `soc-console` built from the same checkout, `AEGIS_AUTH_MODE=local`, one `admin` account (password: `terraform output -raw console_admin_password`) |
| nginx | `:80` immediately; `:443` + redirect the moment the domain resolves here (a 5-minute timer retries certbot until it succeeds) |
| backup | `/etc/cron.daily/aegis-backup` → `/var/backups/aegis`, 14 days kept |

Then:

```powershell
.\pilot.ps1 status          # outputs, /healthz, Firehose destination
```

If `route53_zone_id` was empty: create `A  <domain>  → aegis_host_ip` at your registrar now. TLS is issued
within 5 minutes of the record propagating; `status` shows `/healthz` answering over https once it has.

## Verify the chain end to end

```powershell
$decoy = terraform output -raw decoy_url
# 1. ordinary traffic — allowed by the WAF, still logged
1..20 | % { Invoke-WebRequest -UseBasicParsing $decoy | Out-Null }
# 2. something the managed rules block (SQLi in the query string) — WAF says BLOCK; AEGIS sees the same record
Invoke-WebRequest -UseBasicParsing "$($decoy)login.html?user=admin'%20OR%201=1--" -SkipHttpErrorCheck | Select StatusCode
# 3. a burst past the rate rule
1..400 | % { Invoke-WebRequest -UseBasicParsing "$($decoy)robots.txt" -SkipHttpErrorCheck | Out-Null }
```

Within ~60 s (Firehose buffering) the host shows them:

```powershell
.\pilot.ps1 shell
sudo journalctl -u aegis-soc -n 30 --no-pager            # cycles with firehose: N
sudo -u aegis /opt/aegis/venv/bin/python -m aegis.service --status
sudo -u aegis /opt/aegis/venv/bin/python -m aegis.audit verify --all
```

Firehose's own view (deliveries, HTTP codes from the host) is in CloudWatch
`/aws/kinesisfirehose/<name>-waf`; anything AEGIS refused (503 during a storm, 401 on a token mismatch)
lands in the `-waf-undelivered-` bucket for 14 days.

## What the pilot proves — and what it does not

| Proves | Does not |
|---|---|
| the whole path a bank would run: WAF log → push receiver → swarm → audit chain → console, on a public host | anything about *a bank's* traffic mix — the decoy sees scanners and your own tests |
| shadow verdicts vs. a real vendor baseline (AWS WAF managed rules), per record | Imperva / F5 parsing on live tenants (fixtures only until a tenant is available) |
| licence lifecycle on a real installation (heartbeat, standing, Community caps) | SOAR execution — add XSOAR CE on a second instance when the pilot needs actions, not just verdicts |
| operability: watchdog, storm mode, rollback, backup, `--status` | GPU triage — this host runs the deterministic layer; point `LLM_BACKEND` at a model host to add it |

## Tear down

```powershell
.\pilot.ps1 down
```

Everything is destroyed, buckets included (`force_destroy`). The Community licence row stays on the
licence service and is reusable; the Route 53 hosted zone and the domain registration are outside this
stack and remain.
