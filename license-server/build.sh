#!/usr/bin/env bash
# Copy the product's own licence module into the function so server and product share one token format,
# then build + deploy with SAM. Run from license-server/.
set -euo pipefail
cd "$(dirname "$0")"
cp ../aegis/license.py app/aegis_license.py
sam build
if [[ "${1:-}" == "--deploy" ]]; then
  sam deploy --guided --stack-name bluedefence-license --capabilities CAPABILITY_IAM
fi
