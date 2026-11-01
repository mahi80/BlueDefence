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

output "console_admin_password" {
  description = "Initial password for the console `admin` account (change it after first sign-in: npm run user -- add …)."
  value       = random_password.console_admin.result
  sensitive   = true
}

output "ingest_token" {
  description = "Push token, if you need it for an extra forwarder."
  value       = coalesce(var.aegis_ingest_token, random_password.ingest_token.result)
  sensitive   = true
}
