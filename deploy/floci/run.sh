#!/usr/bin/env bash
# Floci integration spike: BlueDefence's AWS posture collector + exposure engine against an emulated estate.
#
#   1. provision the mini-bank estate (estate.sh) against $AWS_ENDPOINT_URL
#   2. python -m aegis.posture export-aws        → bundle-before.json; collection_errors = what the emulator lacks
#   3. python -m aegis.posture cspm --bundle      (smoke: the CSPM rules run on an emulator-shaped bundle)
#   4. python -m aegis.exposure --aws-bundle      → exposure-before.json (tiers)
#   5. execute the generated revoke commands for bank-web:22 (ACT NOW) and bank-app:8080 (ALB target)
#   6. collector + exposure again                 → exposure-after.json: did the tier drop (verified closure)?
#   7. report.py summary                          → summary.md (support matrix, tiers before/after, bug checks)
#
# Exit status is non-zero only when BlueDefence itself fails (a crash or a non-zero exit from its CLIs).
# Emulator gaps — refused provisioning calls, sections in collection_errors — are recorded, not fatal.
#
# Usage: AWS_ENDPOINT_URL=http://localhost:4566 deploy/floci/run.sh [OUTDIR]
set -uo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
OUT=${1:-${FLOCI_OUT:-$ROOT/floci-out}}
PY=${PYTHON:-python}
export AWS_DEFAULT_REGION=${AWS_DEFAULT_REGION:-us-east-1}
export AWS_REGION=$AWS_DEFAULT_REGION
export AWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY_ID:-test}
export AWS_SECRET_ACCESS_KEY=${AWS_SECRET_ACCESS_KEY:-test}
export AWS_EC2_METADATA_DISABLED=true
# NOTE: s3control's endpoint rules put the account id in front of the host even for a custom endpoint
# (http://000000000000.localhost:4566/...). That name must resolve to the emulator — the workflow adds
# an /etc/hosts entry. If it does not, export-aws dies on its first section with EndpointConnectionError,
# because the collector only tolerates AWS *API* errors per section (recorded as a BlueDefence finding).
: "${AWS_ENDPOINT_URL:?set AWS_ENDPOINT_URL (e.g. http://localhost:4566)}"
export AWS_ENDPOINT_URL

# This script executes security-group changes. Refuse anything that is not obviously an emulator.
host=$(printf '%s' "$AWS_ENDPOINT_URL" | sed -E 's#^[a-z]+://##; s#[:/].*$##')
case "$host" in
  localhost|127.0.0.1|floci|localstack|moto|host.docker.internal|*.localhost) ;;
  *) [ "${FLOCI_ALLOW_ANY_ENDPOINT:-}" = 1 ] || { echo "refusing: $AWS_ENDPOINT_URL does not look like a local emulator" >&2; exit 2; } ;;
esac

mkdir -p "$OUT"
rm -f "$OUT"/{bundle,exposure}-*.json "$OUT"/crashes.txt "$OUT"/revoke.log "$OUT"/summary.md
CRASHES="$OUT/crashes.txt"; : > "$CRASHES"
SAMPLES="$ROOT/aegis/exposure/samples"

# bd NAME OUTFILE CMD... — run a BlueDefence CLI; a non-zero exit or a traceback is a BlueDefence failure.
bd() {
  local name=$1 outfile=$2; shift 2
  local rc
  echo "+ $*" >&2
  "$@" >"$outfile" 2>"$OUT/$name.stderr"; rc=$?
  cat "$OUT/$name.stderr" >&2
  if [ $rc -ne 0 ] || grep -q '^Traceback' "$OUT/$name.stderr"; then
    echo "$name: exit $rc — $(grep -v '^ ' "$OUT/$name.stderr" | tail -1 | cut -c1-240)" >>"$CRASHES"
    echo "!! BlueDefence $name failed (exit $rc)" >&2
    return 1
  fi
  return 0
}

collect_and_score() {  # collect_and_score before|after
  local phase=$1
  echo; echo "==== [$phase] export-aws (BlueDefence collector)"
  if bd "export-aws-$phase" "$OUT/export-aws-$phase.out" $PY -m aegis.posture export-aws --out "$OUT/bundle-$phase.json" --region "$AWS_DEFAULT_REGION"; then
    cat "$OUT/export-aws-$phase.out"
    echo "---- collector support matrix ($phase)"
    $PY "$HERE/report.py" matrix "$OUT/bundle-$phase.json" | tee "$OUT/matrix-$phase.txt"
  else
    echo "export-aws crashed; no bundle for the $phase run"
    return 0
  fi
  if [ "$phase" = before ]; then
    echo; echo "==== [$phase] cspm scan on the collected bundle"
    bd "cspm-$phase" "$OUT/cspm-$phase.txt" $PY -m aegis.posture cspm --bundle "$OUT/bundle-$phase.json" && tail -3 "$OUT/cspm-$phase.txt"
  fi
  echo; echo "==== [$phase] exposure engine"
  if bd "exposure-$phase" "$OUT/exposure-$phase.json" $PY -m aegis.exposure --vulns "$HERE/vulns.json" \
        --aws-bundle "$OUT/bundle-$phase.json" --kev "$SAMPLES/kev_sample.json" --epss "$SAMPLES/epss_sample.csv" --json; then
    $PY "$HERE/report.py" tiers "$OUT/exposure-$phase.json" | tee "$OUT/tiers-$phase.txt"
  fi
}

echo "==== provisioning"
bash "$HERE/estate.sh" "$OUT"

acct=$(aws sts get-caller-identity --query Account --output text 2>/dev/null || true)
if [ -n "$acct" ] && ! getent hosts "$acct.$host" >/dev/null 2>&1; then
  echo "WARNING: $acct.$host does not resolve; s3control (account Block Public Access) will fail to connect." \
       "Add '127.0.0.1 $acct.$host' to /etc/hosts." >&2
fi

collect_and_score before

echo; echo "==== executing the generated revoke commands (remediation.build_options → cut_path)"
: > "$OUT/revoke.log"
if [ -s "$OUT/exposure-before.json" ]; then
  for target in "bank-web 22" "bank-app 8080"; do
    set -- $target
    tier=$($PY -c "import json,sys; d=json.load(open(sys.argv[1])); print(next((e['tier'] for e in d['exposures'] if e['asset_name']==sys.argv[2] and e['port']==int(sys.argv[3])), '-'))" \
           "$OUT/exposure-before.json" "$1" "$2")
    echo "# $1:$2 (tier before: $tier)" >>"$OUT/revoke.log"
    cmds=$($PY "$HERE/report.py" revoke-cmds "$OUT/exposure-before.json" "$1" "$2")
    [ -z "$cmds" ] && echo "  (no cut_path commands generated)" >>"$OUT/revoke.log"
    while IFS= read -r cmd; do
      [ -z "$cmd" ] && continue
      res=$(bash -c "$cmd" 2>&1); rc=$?
      printf '$ %s\n  -> rc=%s %s\n' "$cmd" "$rc" "$(printf '%s' "$res" | tr '\n' ' ' | cut -c1-200)" >>"$OUT/revoke.log"
    done <<<"$cmds"
  done
fi
cat "$OUT/revoke.log"

collect_and_score after

echo; echo "==== summary"
$PY "$HERE/report.py" summary "$OUT"

if [ -s "$CRASHES" ]; then
  echo "BlueDefence failures:" >&2; cat "$CRASHES" >&2
  exit 1
fi
exit 0
