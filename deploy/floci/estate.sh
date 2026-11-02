#!/usr/bin/env bash
# "Mini bank" AWS estate for the Floci integration spike, provisioned with plain `aws` CLI calls
# against $AWS_ENDPOINT_URL (Floci, LocalStack or moto_server). Plain CLI rather than Terraform:
# every call is best-effort and recorded, so an API the emulator does not implement shows up as a
# line in estate-errors.tsv instead of aborting the plan.
#
#   VPC 10.20.0.0/16 (+ an Amazon-provided IPv6 block if the emulator models it)
#   ├── public subnets a/b (MapPublicIpOnLaunch) ── bank-web   SG web:  22, 8080 from 0.0.0.0/0
#   │                                            ├─ bank-mgmt  SG mgmt: ICMP only, from 0.0.0.0/0
#   │                                            └─ bank-alb   internet-facing ALB, SG alb: 443 from 0.0.0.0/0
#   │                                                         listener 443 → target group :8080 → bank-app
#   └── private subnet (no public IPv4) ─────────── bank-db    SG db:  5432 from SG web; 6379 from 0.0.0.0/0
#                                                   bank-app   SG app: 8080 from SG alb
#                                                   bank-ipv6  SG v6:  443 from ::/0 (IPv6-only public API)
#
# Usage: estate.sh OUTDIR   → OUTDIR/estate.env (resource ids), OUTDIR/estate-errors.tsv
set -uo pipefail

OUT=${1:?usage: estate.sh OUTDIR}
E=${AWS_ENDPOINT_URL:?set AWS_ENDPOINT_URL to the emulator endpoint}
REGION=${AWS_DEFAULT_REGION:-us-east-1}
mkdir -p "$OUT"
ERR="$OUT/estate-errors.tsv"
ENVF="$OUT/estate.env"
: > "$ERR"; : > "$ENVF"

a() { aws --endpoint-url "$E" --region "$REGION" --output text "$@"; }

# try NAME CMD... — run, print stdout; on failure record "NAME<TAB>first line of stderr" and print nothing.
try() {
  local name=$1; shift
  local o e rc
  e=$(mktemp)
  o=$("$@" 2>"$e"); rc=$?
  if [ $rc -ne 0 ]; then
    printf '%s\t%s\n' "$name" "$(tr '\n' ' ' <"$e" | sed 's/  */ /g' | cut -c1-300)" >>"$ERR"
    echo "  ! $name failed: $(head -c 300 "$e")" >&2
    o=""
  else
    echo "  ok $name" >&2
  fi
  rm -f "$e"
  [ "$o" = "None" ] && o=""
  printf '%s' "$o"
  return 0
}
keep() { printf '%s=%q\n' "$1" "$2" >>"$ENVF"; }
tag() { [ -n "$1" ] && try "tag-$2" a ec2 create-tags --resources "$1" --tags "Key=Name,Value=$2" "${@:3}" >/dev/null; }

echo "== provisioning mini-bank estate against $E ($REGION)" >&2

# ---- network --------------------------------------------------------------------------------------
VPC=$(try create-vpc a ec2 create-vpc --cidr-block 10.20.0.0/16 --query Vpc.VpcId)
tag "$VPC" minibank-vpc
try vpc-ipv6-block a ec2 associate-vpc-cidr-block --vpc-id "$VPC" --amazon-provided-ipv6-cidr-block --query Ipv6CidrBlockAssociation.Ipv6CidrBlock >/dev/null
IGW=$(try create-igw a ec2 create-internet-gateway --query InternetGateway.InternetGatewayId)
[ -n "$IGW" ] && try attach-igw a ec2 attach-internet-gateway --internet-gateway-id "$IGW" --vpc-id "$VPC" >/dev/null

PUB_A=$(try subnet-public-a a ec2 create-subnet --vpc-id "$VPC" --cidr-block 10.20.1.0/24 --availability-zone "${REGION}a" --query Subnet.SubnetId)
PUB_B=$(try subnet-public-b a ec2 create-subnet --vpc-id "$VPC" --cidr-block 10.20.3.0/24 --availability-zone "${REGION}b" --query Subnet.SubnetId)
PRIV=$(try subnet-private a ec2 create-subnet --vpc-id "$VPC" --cidr-block 10.20.2.0/24 --availability-zone "${REGION}a" --query Subnet.SubnetId)
for s in "$PUB_A" "$PUB_B"; do
  [ -n "$s" ] && try "map-public-ip-$s" a ec2 modify-subnet-attribute --subnet-id "$s" --map-public-ip-on-launch >/dev/null
done
RT=$(try route-table a ec2 create-route-table --vpc-id "$VPC" --query RouteTable.RouteTableId)
if [ -n "$RT" ] && [ -n "$IGW" ]; then
  try default-route a ec2 create-route --route-table-id "$RT" --destination-cidr-block 0.0.0.0/0 --gateway-id "$IGW" >/dev/null
  for s in "$PUB_A" "$PUB_B"; do [ -n "$s" ] && try "rt-assoc-$s" a ec2 associate-route-table --route-table-id "$RT" --subnet-id "$s" >/dev/null; done
fi

# ---- security groups ------------------------------------------------------------------------------
sg() { try "sg-$1" a ec2 create-security-group --group-name "$1" --description "$2" --vpc-id "$VPC" --query GroupId; }
SG_WEB=$(sg bank-web-sg "web tier: ssh + app port open to the world")
SG_MGMT=$(sg bank-mgmt-sg "mgmt host: ping only")
SG_DB=$(sg bank-db-sg "db tier: postgres from web only, redis open")
SG_ALB=$(sg bank-alb-sg "alb: https from the world")
SG_APP=$(sg bank-app-sg "app tier: 8080 from the alb only")
SG_V6=$(sg bank-ipv6-sg "ipv6-only public api: 443 from ::/0")

ingress() { local name=$1 gid=$2; shift 2; [ -n "$gid" ] && try "ingress-$name" a ec2 authorize-security-group-ingress --group-id "$gid" "$@" >/dev/null; }
ingress web-22     "$SG_WEB" --protocol tcp --port 22 --cidr 0.0.0.0/0
ingress web-8080   "$SG_WEB" --protocol tcp --port 8080 --cidr 0.0.0.0/0
ingress mgmt-icmp  "$SG_MGMT" --ip-permissions 'IpProtocol=icmp,FromPort=-1,ToPort=-1,IpRanges=[{CidrIp=0.0.0.0/0,Description=ping}]'
ingress db-5432    "$SG_DB"  --ip-permissions "IpProtocol=tcp,FromPort=5432,ToPort=5432,UserIdGroupPairs=[{GroupId=$SG_WEB}]"
ingress db-6379    "$SG_DB"  --protocol tcp --port 6379 --cidr 0.0.0.0/0
ingress alb-443    "$SG_ALB" --protocol tcp --port 443 --cidr 0.0.0.0/0
ingress app-8080   "$SG_APP" --ip-permissions "IpProtocol=tcp,FromPort=8080,ToPort=8080,UserIdGroupPairs=[{GroupId=$SG_ALB}]"
ingress ipv6-443   "$SG_V6"  --ip-permissions 'IpProtocol=tcp,FromPort=443,ToPort=443,Ipv6Ranges=[{CidrIpv6=::/0}]'

# ---- instances ------------------------------------------------------------------------------------
# Floci maps ami-amazonlinux2023 to a Docker image (or skips Docker in mock mode); other emulators
# get the first image they list.
AMI=${ESTATE_AMI:-}
if [ -z "$AMI" ]; then
  AMI=$(try ami-lookup a ec2 describe-images --image-ids ami-amazonlinux2023 --query 'Images[0].ImageId')
  [ -z "$AMI" ] && AMI=$(try ami-first a ec2 describe-images --query 'Images[0].ImageId')
  [ -z "$AMI" ] && AMI=ami-amazonlinux2023
fi
run() {  # run NAME SUBNET SG ROLE [extra args]
  local name=$1 subnet=$2 sgid=$3 role=$4; shift 4
  try "run-$name" a ec2 run-instances --image-id "$AMI" --instance-type t3.micro --count 1 \
      --subnet-id "$subnet" --security-group-ids "$sgid" "$@" \
      --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=$name},{Key=aegis:role,Value=$role}]" \
      --query 'Instances[0].InstanceId'
}
I_WEB=$(run bank-web "$PUB_A" "$SG_WEB" server)
I_MGMT=$(run bank-mgmt "$PUB_A" "$SG_MGMT" server)
I_DB=$(run bank-db "$PRIV" "$SG_DB" core_banking_db)
I_APP=$(run bank-app "$PRIV" "$SG_APP" payment_api)
I_V6=$(run bank-ipv6 "$PRIV" "$SG_V6" server --ipv6-address-count 1)
[ -z "$I_V6" ] && I_V6=$(run bank-ipv6 "$PRIV" "$SG_V6" server)   # emulator without IPv6 addressing

ids=$(printf '%s ' $I_WEB $I_MGMT $I_DB $I_APP $I_V6)
if [ -n "${ids// /}" ]; then
  for _ in $(seq 1 30); do
    pending=$(a ec2 describe-instances --instance-ids $ids --query 'Reservations[].Instances[?State.Name!=`running`].InstanceId' 2>/dev/null | tr -s '\t\n' ' ')
    [ -z "${pending// /}" ] && break
    sleep 2
  done
fi

# ---- load balancer --------------------------------------------------------------------------------
ALB=$(try alb a elbv2 create-load-balancer --name bank-alb --type application --scheme internet-facing \
      --subnets $PUB_A $PUB_B --security-groups "$SG_ALB" --query 'LoadBalancers[0].LoadBalancerArn')
TG=$(try target-group a elbv2 create-target-group --name bank-app-tg --protocol HTTP --port 8080 \
     --vpc-id "$VPC" --target-type instance --query 'TargetGroups[0].TargetGroupArn')
[ -n "$TG" ] && [ -n "$I_APP" ] && try register-target a elbv2 register-targets --target-group-arn "$TG" --targets "Id=$I_APP,Port=8080" >/dev/null
LST=""
if [ -n "$ALB" ] && [ -n "$TG" ]; then
  CERT=$(try acm-cert a acm request-certificate --domain-name bank.example.test --validation-method DNS --query CertificateArn)
  [ -n "$CERT" ] && LST=$(try listener-https a elbv2 create-listener --load-balancer-arn "$ALB" --protocol HTTPS --port 443 \
      --certificates "CertificateArn=$CERT" --default-actions "Type=forward,TargetGroupArn=$TG" --query 'Listeners[0].ListenerArn')
  # fallback: plain HTTP on 443 (valid on AWS) when the emulator refuses the certificate
  [ -z "$LST" ] && LST=$(try listener-http-443 a elbv2 create-listener --load-balancer-arn "$ALB" --protocol HTTP --port 443 \
      --default-actions "Type=forward,TargetGroupArn=$TG" --query 'Listeners[0].ListenerArn')
fi

for kv in VPC=$VPC PUB_A=$PUB_A PUB_B=$PUB_B PRIV=$PRIV SG_WEB=$SG_WEB SG_MGMT=$SG_MGMT SG_DB=$SG_DB SG_ALB=$SG_ALB SG_APP=$SG_APP \
          SG_V6=$SG_V6 AMI=$AMI I_WEB=$I_WEB I_MGMT=$I_MGMT I_DB=$I_DB I_APP=$I_APP I_V6=$I_V6 ALB=$ALB TG=$TG LISTENER=$LST; do
  keep "${kv%%=*}" "${kv#*=}"
done
echo "== estate: $(grep -c . "$ENVF") ids recorded, $(grep -c . "$ERR") provisioning calls failed" >&2
cat "$ENVF" >&2
exit 0
