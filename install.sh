#!/usr/bin/env bash
# BlueDefence / AEGIS installer — one command from a fresh Ubuntu 22.04/24.04 or RHEL 9 host to a running,
# licensed SOC service under systemd.
#
#   curl -fsSL https://raw.githubusercontent.com/mahi80/BlueDefence/main/install.sh | sudo bash
#   sudo ./install.sh                                            # interactive
#   sudo ./install.sh --community --org "Bank X" --email ciso@bankx.in --server https://…/prod
#   sudo ./install.sh --code BD-XXXX-XXXX-XXXX --server https://…/prod --llm vllm --vllm-url http://gpu-host:8000/v1
#   sudo ./install.sh --no-license                               # evaluation mode (shadow, 100 devices)
#
# What it does (idempotent — re-run to change the answers):
#   1. checks python ≥ 3.11, git; installs python3-venv/pip if the package manager has them
#   2. system user `aegis`, /opt/aegis (code + venv), /etc/aegis (config), /var/lib/aegis (audit, HITL, models, state)
#   3. clones or updates the repo, pip installs the brain into the venv
#   4. licence: Community self-serve signup, an activation code, an existing license.jwt, or evaluation mode
#   5. writes /etc/aegis/aegis.env (edition, enforcement=shadow, LLM backend, sources, ingest port, licence server)
#   6. systemd unit aegis-soc, enabled + started; verifies /healthz and the licence; prints what to wire next
set -euo pipefail

REPO_URL="${AEGIS_REPO_URL:-https://github.com/mahi80/BlueDefence.git}"
BRANCH="${AEGIS_BRANCH:-main}"
PREFIX=/opt/aegis
ETC=/etc/aegis
VAR=/var/lib/aegis
ENV_FILE="$ETC/aegis.env"
LIC_FILE="$ETC/license.jwt"
UNIT=/etc/systemd/system/aegis-soc.service
DEFAULT_SERVER="${AEGIS_LICENSE_SERVER:-}"

MODE=""; ORG=""; EMAIL=""; CODE=""; SERVER="$DEFAULT_SERVER"; LICENSE_PATH=""
LLM="deterministic"; VLLM_URL=""; VLLM_MODEL=""; LOCAL_MODEL=""
SOURCES="stream"; INGEST_BIND="0.0.0.0:8787"; INGEST_TOKEN=""
HITL="file"; EDITION="external"; NONINTERACTIVE=0; YES=0

usage() { sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }
say()  { printf '\033[1;36m▸ %s\033[0m\n' "$*"; }
ok()   { printf '\033[1;32m✓ %s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m! %s\033[0m\n' "$*"; }
die()  { printf '\033[1;31m✗ %s\033[0m\n' "$*" >&2; exit 1; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --community) MODE=community; shift;;
    --code) MODE=code; CODE="$2"; shift 2;;
    --license) MODE=file; LICENSE_PATH="$2"; shift 2;;
    --no-license) MODE=none; shift;;
    --org) ORG="$2"; shift 2;;
    --email) EMAIL="$2"; shift 2;;
    --server) SERVER="$2"; shift 2;;
    --llm) LLM="$2"; shift 2;;                       # deterministic | vllm | local | anthropic
    --vllm-url) VLLM_URL="$2"; shift 2;;
    --vllm-model) VLLM_MODEL="$2"; shift 2;;
    --local-model) LOCAL_MODEL="$2"; shift 2;;
    --sources) SOURCES="$2"; shift 2;;              # e.g. waf,netops  (push receiver is always on)
    --ingest-bind) INGEST_BIND="$2"; shift 2;;
    --ingest-token) INGEST_TOKEN="$2"; shift 2;;
    --hitl) HITL="$2"; shift 2;;                    # file | servicenow
    --edition) EDITION="$2"; shift 2;;
    --branch) BRANCH="$2"; shift 2;;
    --yes|-y) YES=1; shift;;
    --non-interactive) NONINTERACTIVE=1; shift;;
    -h|--help) usage 0;;
    *) die "unknown flag $1 (see --help)";;
  esac
done

[[ $EUID -eq 0 ]] || die "run as root (sudo)"
ask() {  # ask VAR "prompt" "default"
  local var="$1" prompt="$2" dflt="${3:-}"
  if [[ $NONINTERACTIVE -eq 1 ]]; then printf -v "$var" '%s' "${!var:-$dflt}"; return; fi
  local cur="${!var:-$dflt}"
  read -r -p "$prompt${cur:+ [$cur]}: " ans </dev/tty || true
  printf -v "$var" '%s' "${ans:-$cur}"
}

echo
echo "  ____  _            ____        __                      "
echo " | __ )| |_   _  ___|  _ \\  ___ / _| ___ _ __   ___ ___  "
echo " |  _ \\| | | | |/ _ \\ | | |/ _ \\ |_ / _ \\ '_ \\ / __/ _ \\ "
echo " | |_) | | |_| |  __/ |_| |  __/  _|  __/ | | | (_|  __/ "
echo " |____/|_|\\__,_|\\___|____/ \\___|_|  \\___|_| |_|\\___\\___|   AEGIS installer"
echo

# ------------------------------------------------------------------ 1. prerequisites
say "checking prerequisites"
if command -v apt-get >/dev/null; then PM=apt; elif command -v dnf >/dev/null; then PM=dnf; else PM=none; fi
PY=""
for c in python3.12 python3.11 python3; do
  if command -v "$c" >/dev/null && "$c" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)'; then PY="$(command -v "$c")"; break; fi
done
if [[ -z "$PY" ]]; then
  case $PM in
    apt) apt-get update -qq && apt-get install -y -qq python3 python3-venv python3-pip git >/dev/null;;
    dnf) dnf install -y -q python3.12 python3.12-pip git >/dev/null || dnf install -y -q python3 python3-pip git >/dev/null;;
    *) die "need Python >= 3.11 and git; install them and re-run";;
  esac
  for c in python3.12 python3.11 python3; do command -v "$c" >/dev/null && PY="$(command -v "$c")" && break; done
fi
"$PY" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)' || die "Python >= 3.11 required (found $("$PY" --version))"
command -v git >/dev/null || { [[ $PM == apt ]] && apt-get install -y -qq git >/dev/null || dnf install -y -q git >/dev/null; }
"$PY" -m venv --help >/dev/null 2>&1 || { [[ $PM == apt ]] && apt-get install -y -qq python3-venv >/dev/null; }
ok "$("$PY" --version), git $(git --version | awk '{print $3}')"

# ------------------------------------------------------------------ 2. user + dirs
say "user and directories"
id aegis >/dev/null 2>&1 || useradd --system --home "$VAR" --shell /usr/sbin/nologin aegis
mkdir -p "$PREFIX" "$ETC" "$VAR"/{hitl,models,contrib}
chmod 750 "$ETC"; chown -R aegis:aegis "$VAR"
ok "aegis user, $PREFIX $ETC $VAR"

# ------------------------------------------------------------------ 3. code + venv
say "code"
git config --global --add safe.directory "$PREFIX/app" >/dev/null 2>&1 || true     # the tree is owned by the aegis user after install
if [[ -d "$PREFIX/app/.git" ]]; then
  if ! { git -C "$PREFIX/app" remote set-url origin "$REPO_URL" \
      && git -C "$PREFIX/app" fetch -q --depth 1 origin "+refs/heads/$BRANCH:refs/remotes/origin/$BRANCH" \
      && git -C "$PREFIX/app" checkout -q -B "$BRANCH" "origin/$BRANCH"; }; then
    die "could not update $PREFIX/app to $BRANCH"
  fi
else
  git clone -q --depth 1 -b "$BRANCH" "$REPO_URL" "$PREFIX/app" || die "clone failed"
fi
[[ -d "$PREFIX/venv" ]] || "$PY" -m venv "$PREFIX/venv"
"$PREFIX/venv/bin/pip" install -q --upgrade pip >/dev/null
"$PREFIX/venv/bin/pip" install -q -e "$PREFIX/app" >/dev/null
VERSION_SHA=$(git -C "$PREFIX/app" rev-parse --short HEAD)
ok "BlueDefence $BRANCH@$VERSION_SHA installed into $PREFIX/venv"
AEGIS="$PREFIX/venv/bin/python -m"

# ------------------------------------------------------------------ 4. licence
say "licence"
INSTALL_ID=$(cd "$PREFIX/app" && $AEGIS aegis.license install-id)
echo "   installation id: $INSTALL_ID"
if [[ -z "$MODE" ]]; then
  if [[ -f "$LIC_FILE" ]]; then MODE=keep
  elif [[ $NONINTERACTIVE -eq 1 ]]; then MODE=none
  else
    echo "   1) Community edition — free for 2 years, model runs here, scrubbed verdicts + analyst decisions contributed back"
    echo "   2) I have an activation code (BD-XXXX-XXXX-XXXX)"
    echo "   3) I have a license.jwt file"
    echo "   4) No licence — evaluation mode (shadow enforcement, 100 devices)"
    choice=""; ask choice "choose" "1"
    case $choice in 1) MODE=community;; 2) MODE=code;; 3) MODE=file;; *) MODE=none;; esac
  fi
fi
if [[ $MODE == community || $MODE == code ]]; then
  ask SERVER "BlueDefence licence service URL" "$SERVER"
  [[ -n "$SERVER" ]] || die "a licence service URL is required for this option"
fi
case $MODE in
  community)
    ask ORG "organisation name" "$ORG"; ask EMAIL "work e-mail (no gmail/yahoo)" "$EMAIL"
    [[ -n "$ORG" && -n "$EMAIL" ]] || die "org and e-mail are required"
    echo "   Terms: Community edition is free for 2 years; the model runs on this host; scrubbed evidence chains and analyst"
    echo "   decisions (never raw logs or identities) are contributed hourly. Full text: $PREFIX/app/license-server/TERMS-COMMUNITY.md"
    if [[ $YES -ne 1 && $NONINTERACTIVE -ne 1 ]]; then a=""; ask a "accept the Community terms? (yes/no)" "yes"; [[ $a == yes ]] || die "terms not accepted"; fi
    body=$(printf '{"org":"%s","email":"%s","installation_id":"%s","accept_terms":true}' "$ORG" "$EMAIL" "$INSTALL_ID")
    resp=$(curl -fsS -X POST "$SERVER/signup" -H 'content-type: application/json' -d "$body") || die "signup failed: $(curl -sS -X POST "$SERVER/signup" -H 'content-type: application/json' -d "$body" || true)"
    "$PY" - "$resp" "$LIC_FILE" <<'PYEOF'
import json, sys, pathlib
r = json.loads(sys.argv[1]); pathlib.Path(sys.argv[2]).write_text(r["token"] + "\n")
print(f"   licence {r['lic']} · {r['tier']} · entitled until {__import__('time').strftime('%Y-%m-%d', __import__('time').gmtime(r['entitlement_until']))}")
PYEOF
    ;;
  code)
    ask CODE "activation code" "$CODE"
    (cd "$PREFIX/app" && AEGIS_INSTALL_ID="$INSTALL_ID" $AEGIS aegis.license activate --server "$SERVER" --code "$CODE" --out "$LIC_FILE") || die "activation failed"
    ;;
  file)
    ask LICENSE_PATH "path to license.jwt" "$LICENSE_PATH"
    [[ -f "$LICENSE_PATH" ]] || die "$LICENSE_PATH not found"
    cp "$LICENSE_PATH" "$LIC_FILE"
    ;;
  keep) echo "   keeping existing $LIC_FILE";;
  none) warn "no licence — evaluation mode (shadow enforcement, 100 devices / 5 eps). Add one later: python -m aegis.license activate …";;
esac
[[ -f "$LIC_FILE" ]] && { chown aegis:aegis "$LIC_FILE"; chmod 640 "$LIC_FILE"; }

# ------------------------------------------------------------------ 5. config
say "configuration"
if [[ $NONINTERACTIVE -ne 1 && $LLM == deterministic ]]; then
  echo "   LLM triage backend: 1) none yet — deterministic verdicts only (add a model later)  2) vLLM / OpenAI-compatible endpoint  3) local HF model on this host (GPU)  4) Anthropic API"
  c=""; ask c "choose" "1"
  case $c in 2) LLM=vllm;; 3) LLM=local;; 4) LLM=anthropic;; *) LLM=deterministic;; esac
fi
case $LLM in
  vllm)  ask VLLM_URL "vLLM base URL (http://gpu-host:8000/v1)" "$VLLM_URL"; ask VLLM_MODEL "served model / adapter name" "${VLLM_MODEL:-aegis-triage}";;
  local) ask LOCAL_MODEL "HF model id or adapter dir" "${LOCAL_MODEL:-Qwen/Qwen3-8B}";;
  anthropic) : "${ANTHROPIC_API_KEY:?set ANTHROPIC_API_KEY in the environment when choosing the anthropic backend}";;
esac
ask SOURCES "poll sources (comma: stream | waf | sentinel | splunk | ndr | netops; 'sample' adds demo alerts — not for production)" "$SOURCES"
ask INGEST_BIND "ingest receiver bind (host:port) for WAF/syslog/Kafka-bridge pushes" "$INGEST_BIND"
[[ -n "$INGEST_TOKEN" ]] || INGEST_TOKEN=$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')
SALT=$( { grep -s '^AEGIS_DATASET_SALT=' "$ENV_FILE" || true; } | cut -d= -f2- | cut -d' ' -f1); [[ -n "$SALT" ]] || SALT=$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')
HOST_IP=$( { hostname -I 2>/dev/null || echo 127.0.0.1; } | awk '{print $1}')

{
  echo "# BlueDefence / AEGIS — written by install.sh on $(date -u +%FT%TZ); edit and 'systemctl restart aegis-soc'"
  echo "AEGIS_EDITION=$EDITION"
  echo "AEGIS_ENFORCEMENT_MODE=shadow            # flip to live per connector once the shadow report says so"
  echo "AEGIS_HITL_TRANSPORT=$HITL"
  echo "AEGIS_HITL_DIR=$VAR/hitl"
  echo "AEGIS_AUDIT_PATH=$VAR/audit.jsonl"
  echo "AEGIS_SOURCES=$SOURCES                    # stream = only what is pushed to the receiver; add waf/sentinel/splunk/netops to poll"
  echo "AEGIS_CHECKPOINT=$VAR/ingest-checkpoint.json"
  echo "AEGIS_INGEST_HTTP=1"
  echo "AEGIS_INGEST_BIND=$INGEST_BIND"
  echo "AEGIS_INGEST_TOKEN=$INGEST_TOKEN"
  echo "AEGIS_DATASET_SALT=$SALT                   # keys the pseudonyms; never change it after go-live"
  echo "AEGIS_MODEL_DIR=$VAR/models"
  echo "AEGIS_MODEL_POINTER=$VAR/models/current.json"
  case $LLM in
    vllm)  echo "LLM_BACKEND=vllm"; echo "AEGIS_VLLM_URL=$VLLM_URL"; echo "AEGIS_VLLM_MODEL=$VLLM_MODEL"; echo "AEGIS_MODEL_BASE=$VLLM_MODEL"; echo "AEGIS_HOT_RELOAD=1";;
    local) echo "LLM_BACKEND=local"; echo "AEGIS_MODEL=$LOCAL_MODEL"; echo "AEGIS_MODEL_BASE=$LOCAL_MODEL";;
    anthropic) echo "LLM_BACKEND=anthropic"; echo "ANTHROPIC_API_KEY=$ANTHROPIC_API_KEY";;
    *) echo "LLM_BACKEND=mock                       # deterministic layer only until a model backend is configured";;
  esac
  if [[ -f "$LIC_FILE" ]]; then
    echo "AEGIS_LICENSE=$LIC_FILE"
    echo "AEGIS_LICENSE_ENFORCE=1"
    [[ -n "$SERVER" ]] && echo "AEGIS_LICENSE_SERVER=$SERVER         # heartbeat, renewal, contribution, model updates"
  fi
} > "$ENV_FILE"
chmod 640 "$ENV_FILE"; chown root:aegis "$ENV_FILE"
ok "$ENV_FILE"

# ------------------------------------------------------------------ 6. systemd
say "service"
cat > "$UNIT" <<EOF
[Unit]
Description=BlueDefence AEGIS autonomous SOC
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=aegis
Group=aegis
WorkingDirectory=$PREFIX/app
EnvironmentFile=$ENV_FILE
ExecStart=$PREFIX/venv/bin/python -m aegis.service --audit $VAR/audit.jsonl
Restart=always
RestartSec=5
NoNewPrivileges=true
ProtectSystem=full
ReadWritePaths=$VAR
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF
chown -R aegis:aegis "$PREFIX/app" 2>/dev/null || true
HAVE_SYSTEMD=0; [[ -d /run/systemd/system ]] && command -v systemctl >/dev/null && HAVE_SYSTEMD=1
if [[ $HAVE_SYSTEMD -eq 1 ]]; then
  systemctl daemon-reload
  systemctl enable -q aegis-soc
  systemctl restart aegis-soc
  sleep 4
  if systemctl is-active -q aegis-soc; then ok "aegis-soc running"; else journalctl -u aegis-soc -n 30 --no-pager; die "service failed to start — see the log above"; fi
else
  warn "no systemd here (container?) — unit written to $UNIT; running one smoke cycle instead"
  (cd "$PREFIX/app" && set -a && . "$ENV_FILE" && set +a && AEGIS_INGEST_HTTP=0 timeout 300 "$PREFIX/venv/bin/python" -m aegis.service --once --audit "$VAR/audit.jsonl" 2>&1 | tail -5) || die "smoke cycle failed"
  ok "one service cycle completed"
fi

# ------------------------------------------------------------------ 7. verify
say "verification"
PORT=${INGEST_BIND##*:}
if [[ $HAVE_SYSTEMD -eq 1 ]]; then
  for i in 1 2 3 4 5 6; do curl -fsS "http://127.0.0.1:$PORT/healthz" >/dev/null 2>&1 && break; sleep 2; done
  if curl -fsS "http://127.0.0.1:$PORT/healthz" >/dev/null 2>&1; then ok "ingest receiver answering on :$PORT"; else warn "ingest receiver not answering yet on :$PORT (journalctl -u aegis-soc -f)"; fi
fi
(cd "$PREFIX/app" && set -a && . "$ENV_FILE" && set +a && $AEGIS aegis.license verify) || true
FP=$(cd "$PREFIX/app" && $AEGIS aegis.license fingerprint)

cat <<EOF

$(printf '\033[1;32m')BlueDefence AEGIS is installed.$(printf '\033[0m')

  service        systemctl status aegis-soc · journalctl -u aegis-soc -f
  config         $ENV_FILE   (edit, then systemctl restart aegis-soc)
  audit log      $VAR/audit.jsonl (append-only, hash-chained)
  approvals      $VAR/hitl/cards.jsonl → append decisions to $VAR/hitl/decisions.jsonl   (HITL transport: $HITL)
  installation   $INSTALL_ID   code fingerprint $FP
  ingest token   $INGEST_TOKEN   (Authorization: Bearer … on every push to http://$HOST_IP:$PORT/ingest/*)

Wire a feed (any one proves the install):
  WAF / CDN       POST http://$HOST_IP:$PORT/ingest/waf          NDJSON / CEF, gzip ok
  network syslog  POST http://$HOST_IP:$PORT/ingest/netops?feed=syslog   raw lines; LLDP as JSON rows
  Kafka           kafka-bridge/ (Java) → AEGIS_URL=http://$HOST_IP:$PORT AEGIS_INGEST_TOKEN=$INGEST_TOKEN
  Zeek / Suricata POST http://$HOST_IP:$PORT/ingest/ndr?sensor=zeek
  runbook         $PREFIX/app/docs/runbooks/wiring-feeds.md

Smoke test now:   cd $PREFIX/app && sudo -u aegis $PREFIX/venv/bin/python -m aegis.service --once
Re-run this installer any time to change the answers; it keeps the licence, salt and audit log.
EOF
