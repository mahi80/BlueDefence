#
# Decoy target behind AWS WAF, every evaluated request logged for the AEGIS host to pull.
# Provider `aws` must be us-east-1 (CloudFront-scoped WAF + its log group live there); `aws.home` is the
# host's region and holds the decoy bucket — organisation SCPs often deny S3 outside the approved regions,
# and CloudFront is happy with an origin bucket anywhere.
#
terraform {
  required_providers {
    aws = { source = "hashicorp/aws", configuration_aliases = [aws.home] }
  }
}

variable "name" { type = string }
variable "rate_limit" { type = number }
variable "decoy_title" { type = string }

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

# ---------- WAF logging → CloudWatch Logs (the AEGIS host pulls from here) ----------
# Firehose would deliver straight to /ingest/firehose, but organisation SCPs often deny Firehose in us-east-1
# — and a CloudFront-scoped web ACL can only log to us-east-1. CloudWatch Logs is allowed wherever the
# web ACL is; the host polls it every 30 s with FilterLogEvents (see aegis-host/cwlogs-pull.py).
resource "aws_cloudwatch_log_group" "waf" {
  name              = "aws-waf-logs-${var.name}" # WAF insists on this prefix
  retention_in_days = 14
}

resource "aws_wafv2_web_acl_logging_configuration" "decoy" {
  resource_arn            = aws_wafv2_web_acl.decoy.arn
  log_destination_configs = [aws_cloudwatch_log_group.waf.arn]

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
output "log_group_name" { value = aws_cloudwatch_log_group.waf.name }
output "log_group_arn" { value = aws_cloudwatch_log_group.waf.arn }
output "web_acl_arn" { value = aws_wafv2_web_acl.decoy.arn }
