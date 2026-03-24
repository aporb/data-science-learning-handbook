#!/usr/bin/env bash
# test_connection.sh — Smoke test Qlik platform connectivity.
#
# Usage: ./test_connection.sh [--auth]

set -euo pipefail

AUTH_TEST=false
[[ "${1:-}" == "--auth" ]] && AUTH_TEST=true

pass() { echo "  [PASS] $*"; }
fail() { echo "  [FAIL] $*"; }
warn() { echo "  [WARN] $*"; }

echo "=== Qlik Connection Test ==="

# 1. Required env vars
echo ""
echo "--- Environment Variables ---"
required_vars=(QLIK_TENANT_URL QLIK_TENANT_ID QLIK_API_KEY)
all_present=true
for var in "${required_vars[@]}"; do
  if [[ -n "${!var:-}" ]]; then
    pass "$var is set"
  else
    fail "$var is not set"
    all_present=false
  fi
done

# 2. PKCS11 / CAC
echo ""
echo "--- PKCS11 / CAC Reader ---"
if [[ -n "${PKCS11_LIB_PATH:-}" && -f "$PKCS11_LIB_PATH" ]]; then
  pass "PKCS11_LIB_PATH exists: $PKCS11_LIB_PATH"
else
  fail "PKCS11_LIB_PATH not set or missing"
fi

# 3. Network reachability
echo ""
echo "--- Network Reachability ---"
if [[ -n "${QLIK_TENANT_URL:-}" ]]; then
  host=$(echo "$QLIK_TENANT_URL" | awk -F/ '{print $3}')
  if curl -s --max-time 5 --head "https://$host" >/dev/null 2>&1; then
    pass "Reachable: $host"
  else
    fail "Cannot reach $host — check network/proxy"
  fi
else
  warn "QLIK_TENANT_URL not set — skipping reachability check"
fi

# 4. Qlik REST API check
if $AUTH_TEST && $all_present; then
  echo ""
  echo "--- Qlik REST API ---"
  api_resp=$(curl -s --max-time 10 \
    -H "Authorization: ApiKey ${QLIK_API_KEY}" \
    -H "Accept: application/json" \
    "${QLIK_TENANT_URL}/api/v1/items?limit=1" 2>&1)
  if echo "$api_resp" | grep -q '"data"'; then
    pass "Qlik REST API responded with data"
  else
    fail "Unexpected Qlik API response: $(echo "$api_resp" | head -1)"
  fi
fi

# 5. Python SDK
echo ""
echo "--- Python SDK ---"
if python3 -c "import qlik_sdk" 2>/dev/null; then
  pass "qlik-sdk importable"
else
  warn "qlik-sdk not importable (pip install qlik-sdk)"
fi

echo ""
echo "=== Test complete ==="
