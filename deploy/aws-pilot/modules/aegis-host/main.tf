terraform {
  required_providers {
    aws = { source = "hashicorp/aws" }
  }
}

variable "domain" { type = string }
variable "route53_zone_id" { type = string }
variable "instance_type" { type = string }
variable "admin_cidr" { type = string }
variable "key_name" { type = string }
variable "license_server" { type = string }
variable "community_org" { type = string }
variable "community_email" { type = string }
variable "letsencrypt_email" { type = string }
variable "aegis_branch" { type = string }
variable "waf_log_group_arn" { type = string }
variable "waf_log_group_name" { type = string }
variable "ingest_token" {
  type      = string
  sensitive = true
}
variable "console_admin_password" {
  type      = string
  sensitive = true
}

data "aws_vpc" "default" {
  default = true
}

data "aws_subnets" "default" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.default.id]
  }
}

# Canonical's current Ubuntu 24.04 arm64 image, resolved at apply time
data "aws_ssm_parameter" "ubuntu" {
  name = "/aws/service/canonical/ubuntu/server/24.04/stable/current/arm64/hvm/ebs-gp3/ami-id"
}

resource "aws_security_group" "host" {
  name        = "bluedefence-aegis-host"
  description = "AEGIS pilot host: 80/443 public (ACME + ingest + console), optional SSH"
  vpc_id      = data.aws_vpc.default.id

  ingress {
    description = "ACME http-01 + redirect"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    description = "Firehose delivery, console, verdict feed"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  dynamic "ingress" {
    for_each = var.admin_cidr == "" ? [] : [var.admin_cidr]
    content {
      description = "admin SSH"
      from_port   = 22
      to_port     = 22
      protocol    = "tcp"
      cidr_blocks = [ingress.value]
    }
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# SSM Session Manager instead of SSH: no inbound port, every session is in CloudTrail
resource "aws_iam_role" "host" {
  name = "bluedefence-aegis-host"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "ec2.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
}

resource "aws_iam_role_policy_attachment" "ssm" {
  role       = aws_iam_role.host.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

# read-only on the WAF log group: the puller's only AWS permission
resource "aws_iam_role_policy" "cwlogs" {
  name = "waf-log-pull"
  role = aws_iam_role.host.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["logs:FilterLogEvents", "logs:GetLogEvents", "logs:DescribeLogStreams"]
      Resource = [var.waf_log_group_arn, "${var.waf_log_group_arn}:*"]
    }]
  })
}

resource "aws_iam_instance_profile" "host" {
  name = "bluedefence-aegis-host"
  role = aws_iam_role.host.name
}

resource "aws_instance" "host" {
  ami                         = data.aws_ssm_parameter.ubuntu.value
  instance_type               = var.instance_type
  subnet_id                   = data.aws_subnets.default.ids[0]
  vpc_security_group_ids      = [aws_security_group.host.id]
  iam_instance_profile        = aws_iam_instance_profile.host.name
  key_name                    = var.admin_cidr == "" ? null : var.key_name
  associate_public_ip_address = true
  user_data_replace_on_change = true # the bootstrap only runs on first boot; a changed bootstrap means a new host

  metadata_options {
    http_tokens = "required" # IMDSv2 only
  }

  root_block_device {
    volume_type           = "gp3"
    volume_size           = 50
    encrypted             = true
    delete_on_termination = true
  }

  user_data = templatefile("${path.module}/user-data.sh.tftpl", {
    domain                 = var.domain
    license_server         = var.license_server
    community_org          = var.community_org
    community_email        = var.community_email
    letsencrypt_email      = var.letsencrypt_email
    ingest_token           = var.ingest_token
    console_admin_password = var.console_admin_password
    aegis_branch           = var.aegis_branch
    waf_log_group          = var.waf_log_group_name
    cwlogs_pull_py         = file("${path.module}/cwlogs-pull.py")
  })

  tags = { Name = "bluedefence-aegis-host" }

  lifecycle {
    ignore_changes = [ami] # a new Canonical image must not recreate a running pilot
  }
}

resource "aws_eip" "host" {
  instance = aws_instance.host.id
  domain   = "vpc"
  tags     = { Name = "bluedefence-aegis-host" }
}

resource "aws_route53_record" "host" {
  count   = var.route53_zone_id == "" ? 0 : 1
  zone_id = var.route53_zone_id
  name    = var.domain
  type    = "A"
  ttl     = 300
  records = [aws_eip.host.public_ip]
}

output "public_ip" { value = aws_eip.host.public_ip }
output "instance_id" { value = aws_instance.host.id }
