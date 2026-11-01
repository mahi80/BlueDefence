variable "name" {
  description = "Short name used for AWS resources (bucket, WAF, Firehose)."
  type        = string
  default     = "bluedefence-pilot"
}

variable "region" {
  description = "Region for the AEGIS host. Mumbai keeps the pilot's data in India."
  type        = string
  default     = "ap-south-1"
}

variable "domain" {
  description = "FQDN the host answers on, e.g. pilot.bluedefence.click. Firehose only delivers to a public HTTPS endpoint with a trusted certificate, so this must resolve to the host's Elastic IP."
  type        = string
}

variable "route53_zone_id" {
  description = "Hosted zone that owns `domain` — set it and the A record is managed here. Leave empty if the domain lives at another registrar: create the A record there from the `aegis_host_ip` output."
  type        = string
  default     = ""
}

variable "instance_type" {
  description = "Graviton instance for the AEGIS host. t4g.large (2 vCPU / 8 GB) runs the deterministic layer + console; use m7g.xlarge if you add a local model."
  type        = string
  default     = "t4g.large"
}

variable "admin_cidr" {
  description = "CIDR allowed to SSH (port 22). Empty = no SSH at all; use `aws ssm start-session` instead (always enabled)."
  type        = string
  default     = ""
}

variable "key_name" {
  description = "EC2 key pair name, only used when admin_cidr is set."
  type        = string
  default     = ""
}

variable "license_server" {
  description = "BlueDefence licence service base URL."
  type        = string
  default     = "https://ctlh8b2hzk.execute-api.ap-southeast-2.amazonaws.com/prod"
}

variable "community_org" {
  description = "Organisation name for the Community self-serve licence."
  type        = string
}

variable "community_email" {
  description = "Work e-mail for the Community licence (also the Let's Encrypt contact unless letsencrypt_email is set)."
  type        = string
}

variable "letsencrypt_email" {
  description = "Contact e-mail for the TLS certificate."
  type        = string
  default     = null
}

variable "aegis_ingest_token" {
  description = "Push token shared by the host and the Firehose delivery. Leave null to generate one (recommended)."
  type        = string
  default     = null
  sensitive   = true
}

variable "aegis_branch" {
  description = "BlueDefence git ref install.sh checks out."
  type        = string
  default     = "main"
}

variable "waf_rate_limit" {
  description = "Requests per 5 minutes from one IP before the rate rule fires."
  type        = number
  default     = 300
}

variable "decoy_title" {
  description = "Title of the decoy page. Keep it clearly labelled as a test target — it must not imitate a real organisation."
  type        = string
  default     = "BlueDefence shadow-pilot test target"
}
