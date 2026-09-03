#!/usr/bin/env bash
# Creates a Cloudflare Access Application for admin.frontporcheconomics.org
# gated to a single email address only.
#
# Prerequisites:
#   export CLOUDFLARE_API_TOKEN=<token with Access:Edit permission>
#
# Usage:
#   bash scripts/setup-access.sh

set -euo pipefail

ACCOUNT_ID="6d42189fc4724a2d0ad8650b53814692"
ADMIN_DOMAIN="admin.frontporcheconomics.org"
ALLOWED_EMAIL="asialakaygrady@gmail.com"
API="https://api.cloudflare.com/client/v4"

if [[ -z "${CLOUDFLARE_API_TOKEN:-}" ]]; then
  echo "Error: CLOUDFLARE_API_TOKEN is not set." >&2
  exit 1
fi

AUTH_HEADER="Authorization: Bearer ${CLOUDFLARE_API_TOKEN}"

echo "Creating Access Application for ${ADMIN_DOMAIN}..."

APP_RESPONSE=$(curl -s -X POST "${API}/accounts/${ACCOUNT_ID}/access/apps" \
  -H "${AUTH_HEADER}" \
  -H "Content-Type: application/json" \
  -d "{
    \"name\": \"Front Porch Economics Admin\",
    \"domain\": \"${ADMIN_DOMAIN}\",
    \"type\": \"self_hosted\",
    \"session_duration\": \"24h\",
    \"auto_redirect_to_identity\": false
  }")

APP_SUCCESS=$(echo "$APP_RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('success',''))")
if [[ "$APP_SUCCESS" != "True" ]]; then
  echo "Failed to create Access Application:" >&2
  echo "$APP_RESPONSE" | python3 -m json.tool >&2
  exit 1
fi

APP_UUID=$(echo "$APP_RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin)['result']['uid'])")
echo "Access Application created: ${APP_UUID}"

echo "Attaching email-allowlist policy..."

POLICY_RESPONSE=$(curl -s -X POST "${API}/accounts/${ACCOUNT_ID}/access/apps/${APP_UUID}/policies" \
  -H "${AUTH_HEADER}" \
  -H "Content-Type: application/json" \
  -d "{
    \"name\": \"Allow owner\",
    \"precedence\": 1,
    \"decision\": \"allow\",
    \"include\": [
      { \"email\": { \"email\": \"${ALLOWED_EMAIL}\" } }
    ]
  }")

POLICY_SUCCESS=$(echo "$POLICY_RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('success',''))")
if [[ "$POLICY_SUCCESS" != "True" ]]; then
  echo "Failed to create Access Policy:" >&2
  echo "$POLICY_RESPONSE" | python3 -m json.tool >&2
  exit 1
fi

POLICY_ID=$(echo "$POLICY_RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin)['result']['id'])")
echo "Access Policy created: ${POLICY_ID}"

echo ""
echo "Done. Next steps:"
echo "  1. In Cloudflare DNS, add a record for ${ADMIN_DOMAIN} (orange-clouded)"
echo "     CNAME -> front-porch-economics.pages.dev  (or a Worker route)"
echo "  2. Visit https://${ADMIN_DOMAIN} — Access will challenge for ${ALLOWED_EMAIL}"
