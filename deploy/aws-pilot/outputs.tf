output "aegis_host_ip" {
  description = "Elastic IP of the AEGIS host — point the domain's A record here if Route 53 is not managing it."
  value       = module.aegis_host.public_ip
}

output "aegis_instance_id" {
  description = "For `aws ssm start-session --target <id> --region <region>`."
  value       = module.aegis_host.instance_id
}

output "console_url" {
  value = "https://${var.domain}/"
}

output "healthz_url" {
  value = "https://${var.domain}/healthz"
}

output "decoy_url" {
  description = "The CloudFront URL attackers (and your own scanners) hit; every request is WAF-evaluated and pulled into AEGIS."
  value       = module.decoy_waf.decoy_url
}

output "waf_log_group" {
  description = "CloudWatch log group (us-east-1) the WAF writes to and the host pulls from."
  value       = module.decoy_waf.log_group_name
}

output "secrets" {
  description = "Where the host put the secrets it generated (SSM Parameter Store, SecureString)."
  value = {
    console_admin_password = "aws ssm get-parameter --with-decryption --region ${var.region} --name /bluedefence/${var.name}/console-admin-password --query Parameter.Value --output text"
    ingest_token           = "aws ssm get-parameter --with-decryption --region ${var.region} --name /bluedefence/${var.name}/ingest-token --query Parameter.Value --output text"
  }
}

output "backup_bucket" {
  value = aws_s3_bucket.backups.bucket
}
