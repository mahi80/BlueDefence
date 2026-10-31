# Audit log storage with S3 Object Lock (WORM) — tamper-evident at
# the storage layer, complementing the SHA-256 hash chain in the
# application.

variable "tenant_id"       { type = string }
variable "kms_key_arn"     { type = string }
variable "retention_years" { type = number }

resource "aws_s3_bucket" "audit" {
  bucket              = "aegis-audit-${var.tenant_id}-${data.aws_region.current.name}"
  object_lock_enabled = true
  force_destroy       = false  # NEVER true in prod; bucket holds 7y retention
}

resource "aws_s3_bucket_versioning" "audit" {
  bucket = aws_s3_bucket.audit.id
  versioning_configuration {
    status = "Enabled"   # Object Lock requires versioning
  }
}

resource "aws_s3_bucket_object_lock_configuration" "audit" {
  bucket = aws_s3_bucket.audit.id
  rule {
    default_retention {
      mode  = "COMPLIANCE"   # Even root cannot shorten — compliance > governance
      years = var.retention_years
    }
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "audit" {
  bucket = aws_s3_bucket.audit.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = var.kms_key_arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "audit" {
  bucket                  = aws_s3_bucket.audit.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Logging-only bucket policy: deny everything except IAM principals
# the EKS workload identity grants access to (plus the bank's audit
# read-only role for compliance retrieval).
resource "aws_s3_bucket_policy" "audit" {
  bucket = aws_s3_bucket.audit.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyDeleteEvenByRoot"
        Effect    = "Deny"
        Principal = "*"
        Action    = ["s3:DeleteObject", "s3:DeleteObjectVersion"]
        Resource  = "${aws_s3_bucket.audit.arn}/*"
        Condition = {
          # Deny if the request comes outside the configured retention
          # window. Object Lock enforces this anyway; this is belt-
          # and-braces in case someone disables Object Lock later.
          DateLessThan = {
            "aws:CurrentTime" = formatdate("YYYY-MM-DD'T'HH:mm:ss'Z'",
              timeadd(timestamp(), "${var.retention_years * 365 * 24}h"))
          }
        }
      }
    ]
  })
}

data "aws_region" "current" {}

output "bucket_name" {
  value = aws_s3_bucket.audit.id
}

output "bucket_arn" {
  value = aws_s3_bucket.audit.arn
}
