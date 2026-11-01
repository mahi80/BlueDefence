# BlueDefence all-AWS shadow pilot - Windows wrapper around terraform
#   .\pilot.ps1 up        plan + apply (asks for confirmation)
#   .\pilot.ps1 status    outputs + host health + WAF log group state
#   .\pilot.ps1 shell     SSM session onto the host (needs the Session Manager plugin)
#   .\pilot.ps1 update    pull main on the host, rebuild the console, restart both services (no Terraform change)
#   .\pilot.ps1 stop      stop the EC2 host to save money (~$49/mo -> ~$8/mo: disk + idle Elastic IP); everything else stays
#   .\pilot.ps1 start     start it again - same IP, same DNS, same certificate; services come back by themselves
#   .\pilot.ps1 user <name> <role>   add a console account (analyst | bu_head | ciso | cio | admin); prints its password once
#   .\pilot.ps1 user list            list console accounts
#   .\pilot.ps1 user disable <name>  lock an account
#   .\pilot.ps1 down      destroy everything (the Community licence record stays on the licence service)
param([Parameter(Position = 0)][ValidateSet("up", "status", "shell", "update", "stop", "start", "user", "down", "plan")][string]$cmd = "status",
      [Parameter(Position = 1)][string]$a1, [Parameter(Position = 2)][string]$a2)
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
if (-not (Test-Path terraform.tfvars)) { throw "copy terraform.tfvars.example to terraform.tfvars and fill it in" }
# `aws login` sessions are not understood by the Terraform AWS provider yet - hand it the short-lived keys as env vars
# (stale exported keys shadow the profile, so drop them first - the CLI reads env vars before ~/.aws)
Remove-Item Env:AWS_ACCESS_KEY_ID, Env:AWS_SECRET_ACCESS_KEY, Env:AWS_SESSION_TOKEN, Env:AWS_CREDENTIAL_EXPIRATION -ErrorAction SilentlyContinue
# Windows PowerShell 5.1 turns a native command's stderr into a terminating error under "Stop": relax it for the probe
$eap = $ErrorActionPreference; $ErrorActionPreference = "Continue"
$null = (aws sts get-caller-identity --query Arn --output text 2>&1 | Out-String)
$loggedIn = ($LASTEXITCODE -eq 0)
$ErrorActionPreference = $eap
if (-not $loggedIn) { aws login }
aws configure export-credentials --format powershell | Invoke-Expression
$region = (Select-String -Path terraform.tfvars -Pattern '^\s*region\s*=\s*"([^"]+)"' | % { $_.Matches[0].Groups[1].Value }); if (-not $region) { $region = "ap-southeast-2" }

switch ($cmd) {
  "plan"   { terraform init -upgrade; terraform plan }
  "up"     { terraform init -upgrade; terraform apply
             Write-Host "`nNext: point the domain at $(terraform output -raw aegis_host_ip) if Route 53 is not managing it, then .\pilot.ps1 status" }
  "status" {
    terraform output
    $domain = terraform output -raw console_url
    Write-Host "`nhost health:"; try { (Invoke-WebRequest -UseBasicParsing "$($domain)healthz" -TimeoutSec 10).Content } catch { Write-Host "  not answering yet: $($_.Exception.Message)" }
    Write-Host "`nWAF log group, last event (epoch ms):"; aws logs describe-log-streams --region us-east-1 --log-group-name (terraform output -raw waf_log_group) --order-by LastEventTime --descending --max-items 1 --query 'logStreams[0].lastEventTimestamp' --output text
    Write-Host "`nsecrets live in SSM Parameter Store (generated on the host): terraform output secrets"
  }
  "shell"  { aws ssm start-session --region $region --target (terraform output -raw aegis_instance_id) }
  "update" {
    $iid = terraform output -raw aegis_instance_id
    # the checkout is root-owned (install.sh); build as root, hand .next back to the service user
    $cmdline = "cd /opt/aegis/app && git pull -q && /opt/aegis/venv/bin/pip install -q -e .[index] && cd soc-console && npm ci --no-audit --no-fund && npm run build && chown -R aegis:aegis .next && systemctl restart aegis-console aegis-soc && sleep 5 && systemctl is-active aegis-console aegis-soc"
    $params = @{ commands = @($cmdline); executionTimeout = @("900") } | ConvertTo-Json -Compress
    $pfile = Join-Path $env:TEMP "bd-update.json"; Set-Content -Path $pfile -Value $params -Encoding ascii
    $cid = aws ssm send-command --region $region --instance-ids $iid --document-name AWS-RunShellScript --parameters "file://$pfile" --query Command.CommandId --output text
    Write-Host "updating host $iid (command $cid) - this takes 2-3 minutes"
    do { Start-Sleep 15; $st = aws ssm get-command-invocation --region $region --command-id $cid --instance-id $iid --query Status --output text } while ($st -eq "InProgress" -or $st -eq "Pending")
    aws ssm get-command-invocation --region $region --command-id $cid --instance-id $iid --query '[Status,StandardOutputContent,StandardErrorContent]' --output text
  }
  "user"   {
    $iid = terraform output -raw aegis_instance_id
    $users = "/var/lib/aegis/console/users.json"
    switch ($a1) {
      "list"    { $cmdline = "sudo -u aegis AEGIS_CONSOLE_USERS=$users node /opt/aegis/app/soc-console/scripts/users.mjs list" }
      "disable" { if (-not $a2) { throw "usage: .\pilot.ps1 user disable <name>" }; $cmdline = "sudo -u aegis AEGIS_CONSOLE_USERS=$users node /opt/aegis/app/soc-console/scripts/users.mjs disable $a2" }
      default   {
        if (-not $a1 -or -not $a2) { throw "usage: .\pilot.ps1 user <name> <analyst|bu_head|ciso|cio|admin>" }
        if ($a1 -notmatch '^[a-z0-9._-]{2,32}$' -or $a2 -notmatch '^(analyst|bu_head|ciso|cio|admin)$') { throw "bad name or role" }
        # the password is generated on the host and printed once; SSM keeps command output for 30 days, so change it after
        # the demo if that matters (.\pilot.ps1 shell -> npm run user -- add <name> <role>)
        $cmdline = "pw=`$(head -c 18 /dev/urandom | base64 | tr -d '/+=' | cut -c1-18); sudo -u aegis AEGIS_CONSOLE_USERS=$users AEGIS_USER_PASSWORD=`$pw node /opt/aegis/app/soc-console/scripts/users.mjs add $a1 $a2 && echo `"password for ${a1}: `$pw`""
      }
    }
    $params = @{ commands = @($cmdline) } | ConvertTo-Json -Compress
    $pfile = Join-Path $env:TEMP "bd-user.json"; Set-Content -Path $pfile -Value $params -Encoding ascii
    $cid = aws ssm send-command --region $region --instance-ids $iid --document-name AWS-RunShellScript --parameters "file://$pfile" --query Command.CommandId --output text
    do { Start-Sleep 3; $st = aws ssm get-command-invocation --region $region --command-id $cid --instance-id $iid --query Status --output text } while ($st -eq "InProgress" -or $st -eq "Pending")
    aws ssm get-command-invocation --region $region --command-id $cid --instance-id $iid --query '[Status,StandardOutputContent,StandardErrorContent]' --output text
  }
  "stop"   {
    $iid = terraform output -raw aegis_instance_id
    aws ec2 stop-instances --region $region --instance-ids $iid --query 'StoppingInstances[0].CurrentState.Name' --output text
    aws ec2 wait instance-stopped --region $region --instance-ids $iid
    Write-Host "host stopped. Billing now: root disk (~`$4/mo) + Elastic IP while detached from a running host (~`$3.60/mo); WAF/CloudFront/log group unchanged (~`$13/mo). .\pilot.ps1 start to resume."
  }
  "start"  {
    $iid = terraform output -raw aegis_instance_id
    aws ec2 start-instances --region $region --instance-ids $iid --query 'StartingInstances[0].CurrentState.Name' --output text
    aws ec2 wait instance-running --region $region --instance-ids $iid
    Write-Host "host starting; services need ~60 s. The WAF puller resumes from its checkpoint (up to 14 days of log group retention), so nothing was missed."
    Start-Sleep 60
    try { (Invoke-WebRequest -UseBasicParsing (terraform output -raw healthz_url) -TimeoutSec 15).Content } catch { Write-Host "  not answering yet: $($_.Exception.Message) - try .\pilot.ps1 status in a minute" }
  }
  "down"   { terraform destroy }
}
