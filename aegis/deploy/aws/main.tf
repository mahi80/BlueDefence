# AEGIS — AWS deployment (Terraform).
#
# Walking-skeleton infra-as-code for deploying AEGIS to a bank's AWS
# account. Lays down the four production-shaped seams the project plan
# calls out:
#
#   1. EKS cluster for the agent layer + Self-Healing chart + OTel
#      collector chart
#   2. Audit storage as an S3 bucket with Object Lock (compliance
#      WORM mode) for tamper-evidence on the hash-chained log
#   3. Secrets via AWS Secrets Manager + IAM-bound access (no static
#      env vars in agent runtime; consistent with the JIT pattern)
#   4. Bedrock VPC endpoint for Claude API access without leaving
#      the bank's VPC (data-residency story)
#
# This is NOT a turnkey production stack — it's the canonical IaC
# scaffold a bank's platform team would extend with their own VPC
# topology, organization-wide IAM baselines, KMS key policies, etc.
#
# Run:
#   cd aegis/deploy/aws
#   terraform init
#   terraform plan
#   terraform apply

terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.40" }
  }

  # Production: replace with the bank's S3 backend + DynamoDB lock table.
  # backend "s3" {
  #   bucket         = "bank-terraform-state"
  #   key            = "aegis/terraform.tfstate"
  #   region         = "ap-south-1"
  #   dynamodb_table = "bank-terraform-locks"
  #   encrypt        = true
  # }
}

provider "aws" {
  region = var.region
  default_tags {
    tags = merge(var.common_tags, {
      Project     = "AEGIS"
      ManagedBy   = "terraform"
      Compliance  = "RBI-CSF,DPDP-Act-2023,PCI-DSS"
    })
  }
}

# ---- Variables -----------------------------------------------------

variable "region" {
  type        = string
  description = "AWS region for the deployment"
  default     = "ap-south-1"
}

variable "tenant_id" {
  type        = string
  description = "Per-tenant identifier (matches Tenant.id in the agent layer)"
  default     = "default"
}

variable "vpc_id" {
  type        = string
  description = "Existing VPC to deploy into (bank's standard VPC)"
}

variable "private_subnet_ids" {
  type        = list(string)
  description = "Private subnet IDs for the EKS workers + endpoints"
}

variable "common_tags" {
  type        = map(string)
  description = "Tags applied to every taggable resource"
  default     = {
    DataClassification = "high-restricted"
    Owner              = "soc-platform"
  }
}

variable "audit_retention_years" {
  type        = number
  description = "WORM retention period for the audit log bucket"
  default     = 7   # SOX / RBI / DPDP defaults
}

# ---- KMS key for cross-resource encryption -------------------------

resource "aws_kms_key" "aegis" {
  description             = "AEGIS — encrypts audit log, secrets, EKS secrets envelope"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "EnableRootPermissions"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" }
        Action    = "kms:*"
        Resource  = "*"
      },
      {
        Sid       = "AllowS3UseForAuditBucket"
        Effect    = "Allow"
        Principal = { Service = "s3.amazonaws.com" }
        Action    = ["kms:Decrypt", "kms:GenerateDataKey"]
        Resource  = "*"
      }
    ]
  })
}

resource "aws_kms_alias" "aegis" {
  name          = "alias/aegis-${var.tenant_id}"
  target_key_id = aws_kms_key.aegis.key_id
}

data "aws_caller_identity" "current" {}

# ---- Modules -------------------------------------------------------

module "audit_storage" {
  source                = "./modules/audit-storage"
  tenant_id             = var.tenant_id
  kms_key_arn           = aws_kms_key.aegis.arn
  retention_years       = var.audit_retention_years
}

module "secrets" {
  source       = "./modules/secrets"
  tenant_id    = var.tenant_id
  kms_key_id   = aws_kms_key.aegis.id
}

module "bedrock_endpoint" {
  source             = "./modules/bedrock-endpoint"
  vpc_id             = var.vpc_id
  private_subnet_ids = var.private_subnet_ids
  region             = var.region
}

module "eks" {
  source             = "./modules/eks"
  tenant_id          = var.tenant_id
  vpc_id             = var.vpc_id
  private_subnet_ids = var.private_subnet_ids
  kms_key_arn        = aws_kms_key.aegis.arn
}

# ---- Outputs -------------------------------------------------------

output "cluster_name" {
  value       = module.eks.cluster_name
  description = "EKS cluster name; pass to kubectl/helm for chart deployment"
}

output "audit_bucket" {
  value       = module.audit_storage.bucket_name
  description = "S3 bucket holding the WORM audit log"
}

output "secrets_path" {
  value       = module.secrets.secrets_path
  description = "Secrets Manager path prefix for AEGIS credentials"
}

output "bedrock_endpoint_id" {
  value       = module.bedrock_endpoint.endpoint_id
  description = "VPC endpoint for Bedrock — Claude API stays in-VPC"
}
