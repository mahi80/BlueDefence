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
  aws ssm put-parameter --name /bluedefence/license/signing-key --type SecureString --overwrite --value $key --region $Region @p | Out-Null
  Write-Host "signing key -> SSM /bluedefence/license/signing-key"
  if (-not $AdminKey) { $AdminKey = -join ((1..48) | ForEach-Object { '{0:x}' -f (Get-Random -Maximum 16) }) }
  aws ssm put-parameter --name /bluedefence/license/admin-key --type SecureString --overwrite --value $AdminKey --region $Region @p | Out-Null
  Write-Host "admin key   -> SSM /bluedefence/license/admin-key   (read it back: aws ssm get-parameter --name /bluedefence/license/admin-key --with-decryption --query Parameter.Value --output text)"
}

# --- package --------------------------------------------------------------------------------
Copy-Item ..\aegis\license.py app\aegis_license.py -Force
$bucket = "bluedefence-license-artifacts-$account-$Region"
$exists = aws s3api head-bucket --bucket $bucket --region $Region @p 2>&1
if ($LASTEXITCODE -ne 0) {
  Write-Host "creating artifact bucket $bucket"
  if ($Region -eq "us-east-1") { aws s3api create-bucket --bucket $bucket --region $Region @p | Out-Null }
  else { aws s3api create-bucket --bucket $bucket --region $Region --create-bucket-configuration LocationConstraint=$Region @p | Out-Null }
  aws s3api put-public-access-block --bucket $bucket --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true --region $Region @p | Out-Null
}
New-Item -ItemType Directory -Force .build | Out-Null
$zip = ".build\app.zip"
if (Test-Path $zip) { Remove-Item $zip }
Compress-Archive -Path app\app.py, app\aegis_license.py -DestinationPath $zip
# the template's CodeUri points at app/ (for SAM); point it at the zip for plain CloudFormation
(Get-Content template.yaml -Raw) -replace 'CodeUri: app/', "CodeUri: $($zip -replace '\\','/')" | Set-Content .build\template.src.yaml
aws cloudformation package --template-file .build\template.src.yaml --s3-bucket $bucket --s3-prefix $Stack --output-template-file .build\template.packaged.yaml --region $Region @p | Out-Null

# --- deploy ---------------------------------------------------------------------------------
aws cloudformation deploy --template-file .build\template.packaged.yaml --stack-name $Stack --capabilities CAPABILITY_IAM --region $Region --no-fail-on-empty-changeset @p
$api = aws cloudformation describe-stacks --stack-name $Stack --query "Stacks[0].Outputs[?OutputKey=='ApiUrl'].OutputValue" --output text --region $Region @p
Write-Host ""
Write-Host "deployed. API: $api"
Write-Host "  health : curl $api/health"
Write-Host ('  order  : curl -X POST ' + $api + '/orders -H "x-admin-key: ADMINKEY" -H "content-type: application/json" -d "{\"customer\":\"Bank X\",\"edition\":\"soc\",\"tier\":\"pilot\",\"days\":90}"')
Write-Host ('  bank   : python -m aegis.license activate --server ' + $api + ' --code BD-XXXX-XXXX-XXXX')
