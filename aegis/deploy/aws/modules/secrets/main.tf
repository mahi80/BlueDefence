# Secrets — Anthropic API key, Splunk token, BioCatch + Castle + Onfido
# credentials, ServiceNow + Slack webhooks, FS-ISAC + CERT-In submission
# tokens. ALL stored in Secrets Manager; AEGIS workloads access via
# IRSA (IAM Roles for Service Accounts) so no static env vars at runtime.

variable "tenant_id"  { type = string }
variable "kms_key_id" { type = string }

# Single secret with a structured payload — versioned, rotatable,
# audit-trailed via CloudTrail. Production banks may split per-vendor
# for stricter access scoping.
resource "aws_secretsmanager_secret" "aegis" {
  name                    = "aegis/${var.tenant_id}/credentials"
  description             = "AEGIS runtime credentials — vendor APIs + LLM keys"
  recovery_window_in_days = 30
  kms_key_id              = var.kms_key_id

  replica {
    region     = "ap-southeast-1"   # cross-region replica for DR
    kms_key_id = var.kms_key_id
  }
}

# Initial secret value — operators rotate by overwriting via console
# or CI pipeline with proper change-control approval.
# IMPORTANT: ignore_changes on this resource means terraform won't
# clobber operator-rotated values on subsequent applies.
resource "aws_secretsmanager_secret_version" "initial" {
  secret_id = aws_secretsmanager_secret.aegis.id
  secret_string = jsonencode({
    anthropic_api_key   = ""
    splunk_token        = ""
    biocatch_api_key    = ""
    castle_api_secret   = ""
    onfido_api_token    = ""
    servicenow_user     = ""
    servicenow_password = ""
    slack_webhook_url   = ""
    fs_isac_token       = ""
    certin_submit_url   = ""
    certin_submit_token = ""
  })
  lifecycle {
    ignore_changes = [secret_string]
  }
}

# Automatic rotation — Secrets Manager rotates the secret on a
# schedule, calling a Lambda that orchestrates rotation with each
# vendor. The Lambda itself isn't provisioned here (vendor-specific);
# the rotation_rules block declares the cadence the bank should adhere to.
resource "aws_secretsmanager_secret_rotation" "aegis" {
  count               = 0   # enable when the rotation Lambda is in place
  secret_id           = aws_secretsmanager_secret.aegis.id
  rotation_lambda_arn = ""  # populate in production
  rotation_rules {
    automatically_after_days = 90
  }
}

output "secrets_path" {
  value = aws_secretsmanager_secret.aegis.name
}

output "secrets_arn" {
  value = aws_secretsmanager_secret.aegis.arn
}
