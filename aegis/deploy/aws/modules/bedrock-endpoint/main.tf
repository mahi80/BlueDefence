# VPC endpoint for Bedrock — Claude API access without traversing the
# public internet. Per the project plan: "no PII over public internet"
# is the data-residency invariant; Bedrock + PrivateLink (or
# equivalent in Azure / on-prem) is the canonical production path.

variable "vpc_id"             { type = string }
variable "private_subnet_ids" { type = list(string) }
variable "region"             { type = string }

# Bedrock runtime endpoint — used by AnthropicClient when configured
# via Bedrock provider (Anthropic SDK supports both direct and
# Bedrock-hosted Claude).
resource "aws_vpc_endpoint" "bedrock_runtime" {
  vpc_id              = var.vpc_id
  service_name        = "com.amazonaws.${var.region}.bedrock-runtime"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = var.private_subnet_ids
  private_dns_enabled = true
  security_group_ids  = [aws_security_group.bedrock_endpoint.id]

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowAEGISInvocations"
        Effect    = "Allow"
        Principal = "*"
        Action    = ["bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream"]
        Resource = [
          "arn:aws:bedrock:${var.region}::foundation-model/anthropic.claude-sonnet-4-6",
          "arn:aws:bedrock:${var.region}::foundation-model/anthropic.claude-opus-4-7"
        ]
        Condition = {
          StringEquals = {
            # Only AEGIS workloads — IRSA role principal must match
            "aws:PrincipalTag/Project" = "AEGIS"
          }
        }
      }
    ]
  })
}

# The endpoint's Bedrock control-plane sibling — needed for batch
# job submission (used by aegis/agents/shared/batch_client.py).
resource "aws_vpc_endpoint" "bedrock" {
  vpc_id              = var.vpc_id
  service_name        = "com.amazonaws.${var.region}.bedrock"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = var.private_subnet_ids
  private_dns_enabled = true
  security_group_ids  = [aws_security_group.bedrock_endpoint.id]
}

resource "aws_security_group" "bedrock_endpoint" {
  name_prefix = "aegis-bedrock-ep-"
  vpc_id      = var.vpc_id
  description = "Allow AEGIS pods to reach Bedrock VPC endpoint"

  # Tighten to just the EKS cluster's pod CIDR in production.
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
    description = "HTTPS from in-VPC"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Endpoint return traffic (managed by VPC endpoint service)"
  }
}

output "endpoint_id" {
  value = aws_vpc_endpoint.bedrock_runtime.id
}

output "endpoint_dns" {
  value = aws_vpc_endpoint.bedrock_runtime.dns_entry[0].dns_name
}
