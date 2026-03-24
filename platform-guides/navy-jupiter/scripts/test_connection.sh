#!/usr/bin/env bash
# test_connection.sh — Smoke test Navy Jupiter platform connectivity.
#
# Usage: ./test_connection.sh [--auth]

set -euo pipefail

AUTH_TEST=false
[[ "${1:-}" == "--auth" ]] && AUTH_TEST=true

pass() { echo "  [PASS] $*"; }
fail() { echo "  [FAIL] $*"; }
warn() { echo "  [WARN] $*"; }

echo "=== Navy Jupiter Connection Test ==="

# 1. Required env vars
echo ""
echo "--- Environment Variables ---"
required_vars=(NAVY_JUPITER_BASE_URL NAVY_JUPITER_CLIENT_ID NAVY_JUPITER_AUTH_ENDPOINT)
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

if systemctl is-active --quiet pcscd 2>/dev/null; then
  pass "pcscd service is running"
else
  warn "pcscd service not running — start with: sudo systemctl start pcscd"
fi

if command -v opensc-tool >/dev/null 2>&1; then
  readers=$(opensc-tool --list-readers 2>/dev/null | grep -c "Reader" || echo 0)
  if [[ "$readers" -gt 0 ]]; then
    pass "CAC readers detected: $readers"
  else
    warn "No CAC readers detected"
  fi
else
  warn "opensc-tool not found"
fi

# 3. Network reachability
echo ""
echo "--- Network Reachability ---"
if [[ -n "${NAVY_JUPITER_BASE_URL:-}" ]]; then
  host=$(echo "$NAVY_JUPITER_BASE_URL" | awk -F/ '{print $3}')
  if curl -s --max-time 5 --head "https://$host" >/dev/null 2>&1; then
    pass "Reachable: $host"
  else
    fail "Cannot reach $host — verify VPN/network connectivity"
  fi
else
  warn "NAVY_JUPITER_BASE_URL not set — skipping reachability check"
fi

# 4. CA bundle
echo ""
echo "--- DoD CA Bundle ---"
if [[ -n "${CAC_CA_BUNDLE_PATH:-}" && -f "$CAC_CA_BUNDLE_PATH" ]]; then
  count=$(grep -c "BEGIN CERTIFICATE" "$CAC_CA_BUNDLE_PATH" 2>/dev/null || echo 0)
  pass "CA bundle: $count certificate(s) at $CAC_CA_BUNDLE_PATH"
else
  fail "CAC_CA_BUNDLE_PATH not set or file missing (required for Navy Jupiter)"
fi

echo ""
echo "=== Test complete ==="
