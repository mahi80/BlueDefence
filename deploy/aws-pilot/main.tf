#
# BlueDefence — all-AWS shadow pilot
#
#   var.region (Sydney)      aegis-host: one EC2 (Ubuntu 24.04 arm64) running install.sh in shadow mode with a
#                            Community licence, the analyst console (local sign-in), nginx + Let's Encrypt on :443
#   us-east-1 (CloudFront)   decoy-waf: S3 static decoy → CloudFront → AWS WAF (managed rule groups + rate rule)
#                            → Kinesis Data Firehose HTTP endpoint → https://<domain>/ingest/firehose
#
# Nothing here is live-enforcing: AEGIS_ENFORCEMENT_MODE=shadow, and the WAF's own verdicts are the baseline the
# shadow report is compared against (docs/pilot/aws-shadow-pilot.md).
#
terraform {
  required_version = ">= 1.6"
  required_providers {
    aws    = { source = "hashicorp/aws", version = "~> 5.70" }
    random = { source = "hashicorp/random", version = "~> 3.6" }
  }
}

provider "aws" {
  region = var.region
  default_tags { tags = local.tags }
}

# CloudFront-scoped WAF, its logging Firehose and the decoy bucket all have to live in us-east-1
provider "aws" {
  alias  = "us_east_1"
  region = "us-east-1"
  default_tags { tags = local.tags }
}

# Firehose without default tags: some organisation SCPs deny firehose:TagDeliveryStream even where CreateDeliveryStream is allowed
provider "aws" {
  alias  = "us_east_1_untagged"
  region = "us-east-1"
}

locals {
  tags = { project = "bluedefence-pilot", mode = "shadow", managed_by = "terraform" }
}

# one ingest token for the host and the Firehose delivery; never printed
resource "random_password" "ingest_token" {
  length  = 48
  special = false
}

resource "random_password" "console_admin" {
  length  = 20
  special = false
}

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
  ingest_token           = coalesce(var.aegis_ingest_token, random_password.ingest_token.result)
  console_admin_password = random_password.console_admin.result
  aegis_branch           = var.aegis_branch
}

module "decoy_waf" {
  source = "./modules/decoy-waf"
  providers = { aws = aws.us_east_1, aws.home = aws, aws.untagged = aws.us_east_1_untagged }

  name          = var.name
  aegis_url     = "https://${var.domain}"
  ingest_token  = coalesce(var.aegis_ingest_token, random_password.ingest_token.result)
  rate_limit    = var.waf_rate_limit
  decoy_title   = var.decoy_title
}
