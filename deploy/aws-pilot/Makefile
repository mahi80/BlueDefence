# Linux/macOS equivalent of pilot.ps1
REGION ?= ap-south-1
.PHONY: up plan status shell update stop start down
plan:   ; terraform init -upgrade && terraform plan
up:     ; terraform init -upgrade && terraform apply
status: ; terraform output && curl -fsS "$$(terraform output -raw healthz_url)" | python3 -m json.tool || true
shell:  ; aws ssm start-session --region $(REGION) --target "$$(terraform output -raw aegis_instance_id)"
stop:   ; aws ec2 stop-instances --region $(REGION) --instance-ids "$$(terraform output -raw aegis_instance_id)" && aws ec2 wait instance-stopped --region $(REGION) --instance-ids "$$(terraform output -raw aegis_instance_id)"
start:  ; aws ec2 start-instances --region $(REGION) --instance-ids "$$(terraform output -raw aegis_instance_id)" && aws ec2 wait instance-running --region $(REGION) --instance-ids "$$(terraform output -raw aegis_instance_id)"
down:   ; terraform destroy
