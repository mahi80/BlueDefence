"""Cloud control-plane specialist — CloudTrail + Azure Activity Logs.

Reasons about admin actions in cloud control planes (IAM policy edits,
S3 bucket policy changes, security-group additions, VPN endpoint
changes, NSG flow-log disables). These are the actions a real cloud
admin (per the CV that prompted this module) generates daily, and the
ones an attacker uses for privilege escalation, exfiltration setup,
and policy weakening.
"""
