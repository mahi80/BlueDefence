# BlueDefence licence service (AWS, free tier)

Issues and activates per-installation licences for the SOC. Serverless: **Lambda + HTTP API +
DynamoDB (on-demand) + SSM Parameter Store** — all inside the AWS always-free / 12-month free tier
at licence-API volumes (a few calls a day). No EC2, nothing to patch.

```
 bank operator ──POST /activate {code, installation_id}──►  Lambda ── sign (key from SSM) ──► DynamoDB
 you (admin)   ──POST /orders  {customer, tier, days}  ──►  activation code  BD-XXXX-XXXX-XXXX
 AEGIS image   ◄── aegis/keys/*.pub.json (same kid)        GET /pubkeys serves the same keys
```

The signing code **is** `aegis/license.py` (copied in by `build.sh`), so the server and the product can
never disagree on the token.

## Deploy from Windows with only the AWS CLI (what we actually use)

```powershell
aws login                                                   # browser sign-in; region ap-southeast-2
git clone -b main https://github.com/mahi80/BlueDefence.git ; cd BlueDefence\license-server
.\deploy.ps1 -SigningKeyFile C:\secure\bd-2026-10-bootstrap.key.json   # first time: writes the SSM secrets, creates the artifact bucket, deploys
.\deploy.ps1                                                # later: redeploy after a change
```

`deploy.ps1` = copy `aegis/license.py` into the function → zip → S3 → `aws cloudformation package` → `aws cloudformation deploy`
(Serverless transform, `CAPABILITY_IAM`). It prints the API URL and the three commands you need next.

## Deploy with SAM (alternative: CloudShell, macOS, Linux)

```bash
# 0. keys — ONCE, on your own machine, never in a repo
python -m aegis.license keygen --out keys/ --kid bd-2026-11
#    commit keys/bd-2026-11.pub.json into aegis/keys/ ; keep keys/bd-2026-11.key.json offline

# 1. secrets into SSM (SecureString = free standard tier; Secrets Manager would cost $0.40/secret/month)
aws ssm put-parameter --name /bluedefence/license/signing-key --type SecureString --value "$(cat keys/bd-2026-11.key.json)"
aws ssm put-parameter --name /bluedefence/license/admin-key   --type SecureString --value "$(openssl rand -hex 24)"
aws ssm get-parameter --name /bluedefence/license/admin-key --with-decryption --query Parameter.Value --output text   # keep this: x-admin-key

# 2. deploy
cd license-server && ./build.sh --deploy          # accept defaults; note the ApiUrl output
```

CloudShell has `sam`, `aws` and Python preinstalled; clone the repo there with a read-only PAT
(`git clone https://<PAT>@github.com/mahi80/BlueDefence.git`). Redeploy after changes: `./build.sh && sam deploy`.

## Community edition (free 2 years, data sharing) and fleet monitoring

| Call | Who | What |
|---|---|---|
| `POST /signup {org, email, installation_id, accept_terms:true}` | bank operator (self-serve) | 30-day rolling token, 730-day entitlement, tier `community`; work e-mail only, ≤ 3 installations per domain |
| `POST /renew` (bearer = current token) | AEGIS service, automatically 7 days before expiry | fresh 30-day token **only in good standing**; 402 with the reasons otherwise |
| `POST /heartbeat` (bearer) | AEGIS service, daily | `chains_total`, audit tail hash, code fingerprint, effective flags, counters — never event data |
| `POST /contrib` (bearer, gzip bundle) | AEGIS service, hourly | privacy gate → `s3://<ContribBucket>/contrib/<inst>/<y>/<m>/<d>/<ts>-<n>.json.gz`; counts recorded |
| `GET /installations/{id}/health` | you | standing, contribution ratio, heartbeat age, attestation, flags |
| `GET /fleet` | you | every installation's standing in one table |
| daily scan (EventBridge 08:00 IST) | automatic | anomalies → SNS → `-AlertEmail` |

**Standing** is computed from what the installation itself reports, cross-checked: chains written (from
heartbeats) vs records contributed (from bundles) over 30 days; code fingerprint vs the published list in SSM
`/bluedefence/license/known-fingerprints` (`python -m aegis.license fingerprint` on each release, JSON list);
`AEGIS_DATASET_CAPTURE` / `AEGIS_CONTRIB` not switched off. `bad` standing refuses renewal → the token lapses
→ evaluation mode. An on-prem install can always be modified; this makes it visible within days and self-penalising.

**Training on the pool:** `aws s3 sync s3://<ContribBucket>/contrib ./contrib` then
`python -m aegis.dataset import-contrib ./contrib --out datasets/community-v1` (re-runs the privacy gate, builds
`records.jsonl`, `sft/triage.jsonl`, `dpo/preferences.jsonl`), then `python -m aegis.finetune.train --data …` /
`python -m aegis.finetune.dpo --data …`. Terms: `TERMS-COMMUNITY.md`.

## Operate

| You want | Call |
|---|---|
| Sell a licence → give the bank a code | `curl -X POST $API/orders -H "x-admin-key: $ADMIN" -d '{"customer":"Bank X","edition":"soc","tier":"standard","days":365,"features":["kafka_bridge"]}'` → `{"code":"BD-…"}` (code valid 30 days, one redemption) |
| Bank operator activates | `python -m aegis.license activate --server $API --code BD-… --out /etc/aegis/license.jwt` (sends only the installation id) |
| Issue directly for a known installation | `POST /licenses` with `installation_id` (or `"*"` for a floating pilot) |
| Look up | `GET /orders/{code}`, `GET /licenses/{lic}`, `GET /installations/{id}` (licences + usage reports) |
| Revoke | `POST /licenses/{lic}/revoke` — marks the record and blocks re-activation; the offline file still verifies until its expiry (that is the trade-off of an offline licence; keep terms ≤ 1 year) |
| True-up | bank runs `python -m aegis.license report --out usage.json` and either e-mails it or `POST /usage` if they have egress |
| Rotate the issuer key | `keygen --kid bd-2027-01`; put the new key.json in SSM; add the new `.pub.json` to `aegis/keys/` (old one stays until its licences expire); optional `/bluedefence/license/public-keys` SSM String lists extra public keys for `/pubkeys` |

Re-activating with the same code **from the same installation** returns the same licence (lost-file
recovery); from another installation it is refused with 409.

## Cost

| Service | Monthly at ~1,000 calls | Free tier |
|---|---|---|
| Lambda (arm64, 256 MB) | $0 | 1M requests + 400k GB-s, always free |
| HTTP API | $0 (year 1), then ≈ $0.001 | 1M calls/month for 12 months |
| DynamoDB on-demand | $0 | 25 GB storage + 25 RCU/WCU always free |
| SSM Parameter Store standard | $0 | always free |
| CloudWatch Logs (90-day retention) | $0 | 5 GB ingest free |

The API is throttled to 5 req/s (burst 20) so even a misbehaving client cannot leave the free tier.

## Test locally (no AWS)

```bash
cd license-server && cp ../aegis/license.py app/aegis_license.py && python -m pytest tests -q
```
