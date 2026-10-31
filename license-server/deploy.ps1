<#
.SYNOPSIS
  Deploy the BlueDefence licence service with nothing but AWS CLI v2 (no SAM CLI, no Docker).

  .\deploy.ps1 -SigningKeyFile C:\secure\bd-2026-10-bootstrap.key.json          # first time: also writes the SSM secrets
  .\deploy.ps1                                                                   # redeploy after a code change

  Steps: copy aegis/license.py into the function -> zip -> upload to an S3 bucket (created if missing) ->
  `aws cloudformation package` rewrites CodeUri -> `aws cloudformation deploy` with the Serverless transform.
  Everything stays inside the free tier (Lambda / HTTP API / DynamoDB on-demand / SSM standard params / S3 < 5 GB).
#>
param(
  [string]$Stack = "bluedefence-license",
  [string]$AlertEmail = "",
  [string]$Region = $(aws configure get region),
  [string]$SigningKeyFile = "",
  [string]$AdminKey = "",
  [string]$Profile = ""
)
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
$p = @(); if ($Profile) { $p = @("--profile", $Profile) }
if (-not $Region) { throw "No region: pass -Region ap-southeast-2 or run 'aws configure set region ap-southeast-2'" }

$account = aws sts get-caller-identity --query Account --output text @p
if (-not $account) { throw "not signed in - run 'aws login' first" }
Write-Host "account $account | region $Region | stack $Stack"

# --- secrets (first time, or when rotating) ------------------------------------------------
if ($SigningKeyFile) {
  if (-not (Test-Path $SigningKeyFile)) { throw "signing key file not found: $SigningKeyFile" }
  $key = Get-Content $SigningKeyFile -Raw
  if ($key -notmatch '"d"') { throw "$SigningKeyFile is not a PRIVATE key (.key.json from 'python -m aegis.license keygen')" }
  # pass the JSON via file:// - the Windows CLI strips the quotes out of an inline JSON argument
  $abs = (Resolve-Path $SigningKeyFile).Path -replace '\\', '/'
  aws ssm put-parameter --name /bluedefence/license/signing-key --type SecureString --overwrite --value "file://$abs" --region $Region @p | Out-Null
  $check = aws ssm get-parameter --name /bluedefence/license/signing-key --with-decryption --query Parameter.Value --output text --region $Region @p
  if ($check -notmatch '"kid"') { throw "signing key did not round-trip through SSM intact; stored value starts: $($check.Substring(0, [Math]::Min(40, $check.Length)))" }
  Write-Host "signing key -> SSM /bluedefence/license/signing-key"
  $eap2 = $ErrorActionPreference; $ErrorActionPreference = "SilentlyContinue"
  $haveAdmin = aws ssm get-parameter --name /bluedefence/license/admin-key --query Parameter.Name --output text --region $Region @p 2>$null
  $ErrorActionPreference = $eap2
  if ($AdminKey -or -not $haveAdmin) {
    # generate only when there is none yet (or one was given): re-running with -SigningKeyFile must not rotate the admin key
    if (-not $AdminKey) { $AdminKey = -join ((1..48) | ForEach-Object { '{0:x}' -f (Get-Random -Maximum 16) }) }
    aws ssm put-parameter --name /bluedefence/license/admin-key --type SecureString --overwrite --value $AdminKey --region $Region @p | Out-Null
    Write-Host "admin key   -> SSM /bluedefence/license/admin-key   (read it back: aws ssm get-parameter --name /bluedefence/license/admin-key --with-decryption --query Parameter.Value --output text)"
  } else {
    Write-Host "admin key   : kept (pass -AdminKey to rotate)"
  }
}

# --- package --------------------------------------------------------------------------------
Copy-Item ..\aegis\license.py app\aegis_license.py -Force
Copy-Item ..\aegis\dataset\privacy_gate.py app\privacy_gate.py -Force
$bucket = "bluedefence-license-artifacts-$account-$Region"
$eap = $ErrorActionPreference; $ErrorActionPreference = "SilentlyContinue"      # head-bucket writes to stderr when the bucket is missing; that is not an error
aws s3api head-bucket --bucket $bucket --region $Region @p 2>$null | Out-Null
$missing = ($LASTEXITCODE -ne 0)
$ErrorActionPreference = $eap
if ($missing) {
  Write-Host "creating artifact bucket $bucket"
  if ($Region -eq "us-east-1") { aws s3api create-bucket --bucket $bucket --region $Region @p | Out-Null }
  else { aws s3api create-bucket --bucket $bucket --region $Region --create-bucket-configuration LocationConstraint=$Region @p | Out-Null }
  aws s3api put-public-access-block --bucket $bucket --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true --region $Region @p | Out-Null
}
New-Item -ItemType Directory -Force .build | Out-Null
$zip = ".build\app.zip"
if (Test-Path $zip) { Remove-Item $zip }
Compress-Archive -Path app\app.py, app\aegis_license.py, app\privacy_gate.py -DestinationPath $zip
# the template's CodeUri points at app/ (for SAM); point it at the zip for plain CloudFormation
# CodeUri is resolved relative to the template's own folder (.build/), so the zip is referenced by bare name
(Get-Content template.yaml -Raw) -replace 'CodeUri: app/', "CodeUri: app.zip" | Set-Content .build\template.src.yaml
aws cloudformation package --template-file .build\template.src.yaml --s3-bucket $bucket --s3-prefix $Stack --output-template-file .build\template.packaged.yaml --region $Region @p | Out-Null
if ($LASTEXITCODE -ne 0) { throw "cloudformation package failed" }

# --- deploy ---------------------------------------------------------------------------------
$overrides = @()
if ($AlertEmail) { $overrides = @("--parameter-overrides", "AlertEmail=$AlertEmail") }
aws cloudformation deploy --template-file .build\template.packaged.yaml --stack-name $Stack --capabilities CAPABILITY_IAM CAPABILITY_AUTO_EXPAND --region $Region --no-fail-on-empty-changeset @overrides @p
if ($LASTEXITCODE -ne 0) { throw "cloudformation deploy failed - see the events: aws cloudformation describe-stack-events --stack-name $Stack --region $Region --max-items 10" }
$api = aws cloudformation describe-stacks --stack-name $Stack --query "Stacks[0].Outputs[?OutputKey=='ApiUrl'].OutputValue" --output text --region $Region @p
Write-Host ""
$bucket2 = aws cloudformation describe-stacks --stack-name $Stack --query "Stacks[0].Outputs[?OutputKey=='ContribBucket'].OutputValue" --output text --region $Region @p
Write-Host "deployed. API: $api"
Write-Host "contrib bucket: $bucket2   (aws s3 sync s3://$bucket2/contrib .\contrib ; python -m aegis.dataset import-contrib .\contrib --out datasets\community-v1)"
Write-Host "  health : curl $api/health"
Write-Host ('  order  : curl -X POST ' + $api + '/orders -H "x-admin-key: ADMINKEY" -H "content-type: application/json" -d "{\"customer\":\"Bank X\",\"edition\":\"soc\",\"tier\":\"pilot\",\"days\":90}"')
Write-Host ('  bank   : python -m aegis.license activate --server ' + $api + ' --code BD-XXXX-XXXX-XXXX')
