#
# BlueDefence — all-AWS shadow pilot
#
#   var.region (Sydney)      aegis-host: one EC2 (Ubuntu 24.04 arm64) running install.sh in shadow mode with a
#                            Community licence, the analyst console (local sign-in), nginx + Let's Encrypt on :443
#   us-east-1 (CloudFront)   decoy-waf: S3 static decoy → CloudFront → AWS WAF (managed rule groups + rate rule)
#                            → CloudWatch Logs; the host pulls new events every 30 s into /ingest/waf
#
# Nothing here is live-enforcing: AEGIS_ENFORCEMENT_MODE=shadow, and the WAF's own verdicts are the baseline the
# shadow report is compared against (docs/pilot/aws-shadow-pilot.md).
#
terraform {
  required_version = ">= 1.6"
  required_providers {
    aws    = { source = "hashicorp/aws", version = "~> 5.70" }
  }
}

provider "aws" {
  region = var.region
  default_tags { tags = local.tags }
}

# CloudFront-scoped WAF and its log group have to live in us-east-1
provider "aws" {
  alias  = "us_east_1"
  region = "us-east-1"
  default_tags { tags = local.tags }
}

locals {
  tags = { project = "bluedefence-pilot", mode = "shadow", managed_by = "terraform" }
}

# evidence backups (audit chain, HITL files, licence) leave the host daily; the bucket outlives the instance
resource "aws_s3_bucket" "backups" {
  bucket        = "${var.name}-backups-${data.aws_caller_identity.me.account_id}"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "backups" {
  bucket                  = aws_s3_bucket.backups.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "backups" {
  bucket = aws_s3_bucket.backups.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_lifecycle_configuration" "backups" {
  bucket = aws_s3_bucket.backups.id
  rule {
    id     = "keep-90-days"
    status = "Enabled"
    filter {}
    expiration { days = 90 }
    noncurrent_version_expiration { noncurrent_days = 30 }
  }
}

data "aws_caller_identity" "me" {}

module "aegis_host" {
  source = "./modules/aegis-host"

  domain                 = var.domain
  route53_zone_id        = var.route53_zone_id
  instance_type          = var.instance_type
  admin_cidr             = var.admin_cidr
  key_name               = var.key_name
  license_server         = var.license_server
  community_org          = var.community_org
  community_email        = var.community_email
  letsencrypt_email      = coalesce(var.letsencrypt_email, var.community_email)
  name                   = var.name
  backup_bucket_arn      = aws_s3_bucket.backups.arn
  aegis_branch           = var.aegis_branch
  waf_log_group_arn      = module.decoy_waf.log_group_arn
  waf_log_group_name     = module.decoy_waf.log_group_name
}

module "decoy_waf" {
  source = "./modules/decoy-waf"
  providers = { aws = aws.us_east_1, aws.home = aws }

  name        = var.name
  rate_limit  = var.waf_rate_limit
  decoy_title = var.decoy_title
}
