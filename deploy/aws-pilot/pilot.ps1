# BlueDefence all-AWS shadow pilot — Windows wrapper around terraform
#   .\pilot.ps1 up        plan + apply (asks for confirmation)
#   .\pilot.ps1 status    outputs + host health + WAF log group state
#   .\pilot.ps1 shell     SSM session onto the host (needs the Session Manager plugin)
#   .\pilot.ps1 update    pull main on the host, rebuild the console, restart both services (no Terraform change)
#   .\pilot.ps1 down      destroy everything (the Community licence record stays on the licence service)
param([Parameter(Position = 0)][ValidateSet("up", "status", "shell", "update", "down", "plan")][string]$cmd = "status")
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
if (-not (Test-Path terraform.tfvars)) { throw "copy terraform.tfvars.example to terraform.tfvars and fill it in" }
# `aws login` sessions are not understood by the Terraform AWS provider yet — hand it the short-lived keys as env vars
# (stale exported keys shadow the profile, so drop them first — the CLI reads env vars before ~/.aws)
Remove-Item Env:AWS_ACCESS_KEY_ID, Env:AWS_SECRET_ACCESS_KEY, Env:AWS_SESSION_TOKEN, Env:AWS_CREDENTIAL_EXPIRATION -ErrorAction SilentlyContinue
aws sts get-caller-identity --query Arn --output text 2>$null | Out-Null; if ($LASTEXITCODE -ne 0) { aws login }
aws configure export-credentials --format powershell | Invoke-Expression
$region = (Select-String -Path terraform.tfvars -Pattern '^\s*region\s*=\s*"([^"]+)"' | % { $_.Matches[0].Groups[1].Value }); if (-not $region) { $region = "ap-south-1" }

switch ($cmd) {
  "plan"   { terraform init -upgrade; terraform plan }
  "up"     { terraform init -upgrade; terraform apply
             Write-Host "`nNext: point the domain at $(terraform output -raw aegis_host_ip) if Route 53 is not managing it, then .\pilot.ps1 status" }
  "status" {
    terraform output
    $domain = terraform output -raw console_url
    Write-Host "`nhost health:"; try { (Invoke-WebRequest -UseBasicParsing "$($domain)healthz" -TimeoutSec 10).Content } catch { Write-Host "  not answering yet: $($_.Exception.Message)" }
    Write-Host "`nWAF log group, last event (epoch ms):"; aws logs describe-log-streams --region us-east-1 --log-group-name (terraform output -raw waf_log_group) --order-by LastEventTime --descending --max-items 1 --query 'logStreams[0].lastEventTimestamp' --output text
    Write-Host "`nconsole admin password: terraform output -raw console_admin_password"
  }
  "shell"  { aws ssm start-session --region $region --target (terraform output -raw aegis_instance_id) }
  "update" {
    $iid = terraform output -raw aegis_instance_id
    $cmdline = "cd /opt/aegis/app && sudo -u aegis git pull -q && /opt/aegis/venv/bin/pip install -q -e . && cd soc-console && sudo -u aegis -H npm ci --no-audit --no-fund && sudo -u aegis -H npm run build && systemctl restart aegis-console aegis-soc && sleep 5 && systemctl is-active aegis-console aegis-soc"
    $params = @{ commands = @($cmdline); executionTimeout = @("900") } | ConvertTo-Json -Compress
    $pfile = Join-Path $env:TEMP "bd-update.json"; Set-Content -Path $pfile -Value $params -Encoding ascii
    $cid = aws ssm send-command --region $region --instance-ids $iid --document-name AWS-RunShellScript --parameters "file://$pfile" --query Command.CommandId --output text
    Write-Host "updating host $iid (command $cid) — this takes 2-3 minutes"
    do { Start-Sleep 15; $st = aws ssm get-command-invocation --region $region --command-id $cid --instance-id $iid --query Status --output text } while ($st -eq "InProgress" -or $st -eq "Pending")
    aws ssm get-command-invocation --region $region --command-id $cid --instance-id $iid --query '[Status,StandardOutputContent,StandardErrorContent]' --output text
  }
  "down"   { terraform destroy }
}
