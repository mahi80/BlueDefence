#
# Decoy target behind AWS WAF, every evaluated request streamed to AEGIS via Firehose.
# Provider `aws` must be us-east-1 (CloudFront-scoped WAF + its logging stream live there); `aws.home` is the
# host's region and holds the two S3 buckets — organisation SCPs often deny S3 outside the approved regions,
# and CloudFront / Firehose are happy with a bucket anywhere.
#
terraform {
  required_providers {
    aws = { source = "hashicorp/aws", configuration_aliases = [aws.home] }
  }
}

variable "name" { type = string }
variable "aegis_url" { type = string }
variable "rate_limit" { type = number }
variable "decoy_title" { type = string }
variable "ingest_token" {
  type      = string
  sensitive = true
}

data "aws_caller_identity" "me" {}

# ---------- decoy site: private S3 bucket served only through CloudFront ----------
resource "aws_s3_bucket" "decoy" {
  provider      = aws.home
  bucket        = "${var.name}-decoy-${data.aws_caller_identity.me.account_id}"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "decoy" {
  provider                = aws.home
  bucket                  = aws_s3_bucket.decoy.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

locals {
  # Deliberately plain and clearly labelled: a scan target, not a bank. Several "interesting" paths exist only
  # so scanners have something to probe; every request is logged whatever the path.
  decoy_pages = {
    "index.html" = templatefile("${path.module}/decoy/index.html.tftpl", { title = var.decoy_title })
    "login.html" = templatefile("${path.module}/decoy/login.html.tftpl", { title = var.decoy_title })
    "robots.txt" = "User-agent: *\nDisallow: /admin/\nDisallow: /api/\nDisallow: /backup/\n"
  }
}

resource "aws_s3_object" "decoy" {
  provider     = aws.home
  for_each     = local.decoy_pages
  bucket       = aws_s3_bucket.decoy.id
  key          = each.key
  content      = each.value
  content_type = endswith(each.key, ".html") ? "text/html; charset=utf-8" : "text/plain"
  etag         = md5(each.value)
}

resource "aws_cloudfront_origin_access_control" "decoy" {
  name                              = "${var.name}-decoy"
  origin_access_control_origin_type = "s3"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}

resource "aws_s3_bucket_policy" "decoy" {
  provider = aws.home
  bucket = aws_s3_bucket.decoy.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "cloudfront.amazonaws.com" }
      Action    = "s3:GetObject"
      Resource  = "${aws_s3_bucket.decoy.arn}/*"
      Condition = { StringEquals = { "AWS:SourceArn" = aws_cloudfront_distribution.decoy.arn } }
    }]
  })
}

# ---------- WAF: managed rule groups + rate rule, logging everything ----------
resource "aws_wafv2_web_acl" "decoy" {
  name  = "${var.name}-decoy"
  scope = "CLOUDFRONT"

  default_action {
    allow {}
  }

  rule {
    name     = "rate-limit"
    priority = 0
    action {
      block {}
    }
    statement {
      rate_based_statement {
        limit              = var.rate_limit
        aggregate_key_type = "IP"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "rate-limit"
      sampled_requests_enabled   = true
    }
  }

  dynamic "rule" {
    for_each = {
      1 = "AWSManagedRulesAmazonIpReputationList"
      2 = "AWSManagedRulesCommonRuleSet"
      3 = "AWSManagedRulesKnownBadInputsRuleSet"
      4 = "AWSManagedRulesSQLiRuleSet"
    }
    content {
      name     = rule.value
      priority = rule.key
      override_action {
        none {}
      }
      statement {
        managed_rule_group_statement {
          name        = rule.value
          vendor_name = "AWS"
        }
      }
      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = rule.value
        sampled_requests_enabled   = true
      }
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${var.name}-decoy"
    sampled_requests_enabled   = true
  }
}

resource "aws_cloudfront_distribution" "decoy" {
  enabled             = true
  comment             = "BlueDefence shadow-pilot decoy"
  default_root_object = "index.html"
  price_class         = "PriceClass_200" # includes India
  web_acl_id          = aws_wafv2_web_acl.decoy.arn

  origin {
    domain_name              = aws_s3_bucket.decoy.bucket_regional_domain_name
    origin_id                = "s3-decoy"
    origin_access_control_id = aws_cloudfront_origin_access_control.decoy.id
  }

  default_cache_behavior {
    target_origin_id       = "s3-decoy"
    viewer_protocol_policy = "allow-all" # http probes are part of the signal
    allowed_methods        = ["GET", "HEAD", "OPTIONS", "PUT", "POST", "PATCH", "DELETE"]
    cached_methods         = ["GET", "HEAD"]
    cache_policy_id        = "4135ea2d-6df8-44a3-9df3-4b5a84be39ad" # CachingDisabled: every request reaches WAF logging with its full query
  }

  custom_error_response {
    error_code         = 403
    response_code      = 404
    response_page_path = "/index.html"
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    cloudfront_default_certificate = true
  }
}

# ---------- Firehose HTTP endpoint → AEGIS /ingest/firehose ----------
resource "aws_s3_bucket" "firehose_backup" {
  provider      = aws.home
  bucket        = "${var.name}-waf-undelivered-${data.aws_caller_identity.me.account_id}"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "firehose_backup" {
  provider                = aws.home
  bucket                  = aws_s3_bucket.firehose_backup.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "firehose_backup" {
  provider = aws.home
  bucket = aws_s3_bucket.firehose_backup.id
  rule {
    id     = "expire-undelivered"
    status = "Enabled"
    filter {}
    expiration {
      days = 14
    }
  }
}

resource "aws_iam_role" "firehose" {
  name = "${var.name}-waf-firehose"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "firehose.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
}

resource "aws_iam_role_policy" "firehose" {
  role = aws_iam_role.firehose.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["s3:AbortMultipartUpload", "s3:GetBucketLocation", "s3:GetObject", "s3:ListBucket", "s3:ListBucketMultipartUploads", "s3:PutObject"]
        Resource = [aws_s3_bucket.firehose_backup.arn, "${aws_s3_bucket.firehose_backup.arn}/*"]
      },
      {
        Effect   = "Allow"
        Action   = ["logs:PutLogEvents"]
        Resource = "${aws_cloudwatch_log_group.firehose.arn}:*"
      }
    ]
  })
}

resource "aws_cloudwatch_log_group" "firehose" {
  name              = "/aws/kinesisfirehose/${var.name}-waf"
  retention_in_days = 14
}

resource "aws_cloudwatch_log_stream" "firehose" {
  name           = "HttpEndpointDelivery"
  log_group_name = aws_cloudwatch_log_group.firehose.name
}

# WAF only logs to streams whose name starts with aws-waf-logs-
resource "aws_kinesis_firehose_delivery_stream" "waf" {
  name        = "aws-waf-logs-${var.name}"
  destination = "http_endpoint"

  http_endpoint_configuration {
    url                = "${var.aegis_url}/ingest/firehose"
    name               = "BlueDefence AEGIS"
    access_key         = var.ingest_token # sent as X-Amz-Firehose-Access-Key; the receiver compares it in constant time
    buffering_size     = 1  # MB
    buffering_interval = 60 # seconds — the shadow report does not need sub-minute delivery
    role_arn           = aws_iam_role.firehose.arn
    s3_backup_mode     = "FailedDataOnly"
    retry_duration     = 300

    request_configuration {
      content_encoding = "GZIP"
    }

    s3_configuration {
      role_arn           = aws_iam_role.firehose.arn
      bucket_arn         = aws_s3_bucket.firehose_backup.arn
      buffering_size     = 5
      buffering_interval = 300
      compression_format = "GZIP"
    }

    cloudwatch_logging_options {
      enabled         = true
      log_group_name  = aws_cloudwatch_log_group.firehose.name
      log_stream_name = aws_cloudwatch_log_stream.firehose.name
    }
  }
}

resource "aws_wafv2_web_acl_logging_configuration" "decoy" {
  resource_arn            = aws_wafv2_web_acl.decoy.arn
  log_destination_configs = [aws_kinesis_firehose_delivery_stream.waf.arn]

  redacted_fields {
    single_header {
      name = "authorization"
    }
  }
  redacted_fields {
    single_header {
      name = "cookie"
    }
  }
}

output "decoy_url" { value = "https://${aws_cloudfront_distribution.decoy.domain_name}/" }
output "firehose_name" { value = aws_kinesis_firehose_delivery_stream.waf.name }
output "web_acl_arn" { value = aws_wafv2_web_acl.decoy.arn }
