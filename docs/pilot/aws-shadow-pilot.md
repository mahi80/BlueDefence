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
                   └── every evaluated request ──► CloudWatch Logs  │   ├ /healthz                  │
                                                   (aws-waf-logs-…) │   └ /          → console :3000│
                                                        ▲           │  aegis-soc.service  (shadow)  │
                                                        └── pull ── │  aegis-cwlogs.timer (30 s)    │
                                                     FilterLogEvents│  aegis-console.service        │
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
| CloudWatch Logs (WAF records, 14-day retention) + the host's FilterLogEvents calls | < $2 |
| Route 53 hosted zone (if used) | $0.50 |
| Elastic IP (attached) | $0 |
| **Total** | **≈ $65–75** |

**Pausing to save money.** `.\pilot.ps1 stop` stops the host; `.\pilot.ps1 start` brings it back with
the same IP, DNS and certificate, services restart on their own and the WAF puller resumes from its
checkpoint (the log group keeps 14 days, so nothing is lost). While stopped you pay ~$8/month for the host
side (root disk + the idle Elastic IP) plus the WAF/CloudFront/log group (~$13) — about **$20/month**
instead of ~$70. The `down` command removes everything and `up` rebuilds it (new Community signup,
new console password; Route 53/GoDaddy records untouched).

## Before you apply

1. **Terraform** ≥ 1.6 on your PC (`winget install Hashicorp.Terraform`) and the AWS CLI signed in to the
   account (a paid plan — the Free Tier plan blocks Route 53 Domains and will close the account when its
   credits end). If you sign in with `aws login`, the Terraform provider cannot read that session yet:
   `pilot.ps1` runs `aws configure export-credentials --format powershell | Invoke-Expression` for you
   (do the same by hand before a bare `terraform` command). **Region**: accounts created under an AWS
   organisation often carry a service control policy that denies some regions — `terraform plan` shows
   `explicit deny in a service control policy` if so. Sydney (`ap-southeast-2`) is the default; set
   `region = "ap-south-1"` only if the plan goes through there.
2. **A domain** that will point at the host — one subdomain at whatever registrar already holds a domain of
   yours (e.g. `pilot.vajra.ink` at GoDaddy) is the cheapest option: an A record, nothing to buy.
   - Route 53: `aws route53domains register-domain --region us-east-1 …` (registration creates the
     hosted zone; its id goes into `route53_zone_id` and the A record is managed for you), or
   - any registrar: leave `route53_zone_id` empty and create the A record yourself after the first apply.
3. **A work e-mail** for the Community licence (`community_email`): the licence service refuses gmail/yahoo/…
   by design; any address on your own domain works (it is not verified by mail).
4. **Session Manager plugin** for `.\pilot.ps1 shell`
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
| WAF puller | `aegis-cwlogs.timer` runs `/usr/local/bin/aegis-cwlogs-pull` every 30 s: `FilterLogEvents` on the WAF log group (instance role, read-only) → gzip NDJSON → `POST /ingest/waf?source=aws-waf` on loopback; checkpoint in `/var/lib/aegis/cwlogs-checkpoint.json` |
| console | `soc-console` built from the same checkout, `AEGIS_AUTH_MODE=local`, one `admin` account (password: `terraform output -raw console_admin_password`); reads live incidents from the host's own `/api/soc/*` (`AEGIS_CONSOLE_TOKEN`), approvals land in `/var/lib/aegis/hitl/decisions.jsonl` |
| nginx | `:80` immediately; `:443` + redirect the moment the domain resolves here (a 5-minute timer retries certbot until it succeeds) |
| backup | `/etc/cron.daily/aegis-backup` → `/var/backups/aegis`, 14 days kept |

Then:

```powershell
.\pilot.ps1 status          # outputs, /healthz, last WAF event seen
```

If `route53_zone_id` was empty: create `A  <domain>  → aegis_host_ip` at your registrar now. TLS is issued
within 5 minutes of the record propagating; `status` shows `/healthz` answering over https once it has.
WAF events flow regardless of DNS — the puller works over the instance role, not the domain.

## Update the host after a merge

Code-only changes (console, brain) do not change the bootstrap, so Terraform sees "no changes". Pull and
rebuild in place over SSM:

```powershell
.\pilot.ps1 update      # git pull on the host, pip install, console rebuild, restart both services
```

A change to `user-data.sh.tftpl` itself is different: `.\pilot.ps1 up` then replaces the host (same
Elastic IP, DNS untouched, new console password).

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

Within ~45 s (CloudWatch ingestion + the 30 s timer) the host shows them:

```powershell
.\pilot.ps1 shell
sudo journalctl -u aegis-cwlogs -n 5 --no-pager          # "pushed N WAF events"
sudo journalctl -u aegis-soc -n 30 --no-pager            # cycles with aws-waf: N
sudo -u aegis /opt/aegis/venv/bin/python -m aegis.service --status
sudo -u aegis /opt/aegis/venv/bin/python -m aegis.audit verify --all
```

The raw WAF records stay in the `aws-waf-logs-<name>` log group (us-east-1) for 14 days, so anything the
host missed while down is re-pulled from its checkpoint; if the puller itself fails (`journalctl -u
aegis-cwlogs`) the checkpoint does not advance.

Why not Firehose straight into `/ingest/firehose`? Banks will use it (the receiver supports it), but a
CloudFront web ACL can only log to us-east-1, and organisation SCPs on new AWS accounts frequently deny
Firehose and S3 there — this pilot hit exactly that. CloudWatch Logs is allowed wherever the web ACL is.

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

Everything is destroyed, bucket and log group included (`force_destroy`). The Community licence row stays on the
licence service and is reusable; the Route 53 hosted zone and the domain registration are outside this
stack and remain.
