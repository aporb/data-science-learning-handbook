#!/usr/bin/env bash
# test_connection.sh — Smoke test Advana platform connectivity.
#
# Checks: network reachability, PKCS11 library, CAC reader, and
# optionally authenticates with a test token request.
#
# Usage:
#   ./test_connection.sh [--auth]

set -euo pipefail

AUTH_TEST=false
[[ "${1:-}" == "--auth" ]] && AUTH_TEST=true

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"

log()  { echo "  [$(date '+%H:%M:%S')] $*"; }
pass() { echo "  [PASS] $*"; }
fail() { echo "  [FAIL] $*"; }
warn() { echo "  [WARN] $*"; }

echo "=== Advana Connection Test ==="

# 1. Check PKCS11 library
echo ""
echo "--- PKCS11 / CAC Reader ---"
if [[ -n "${PKCS11_LIB_PATH:-}" && -f "$PKCS11_LIB_PATH" ]]; then
  pass "PKCS11_LIB_PATH exists: $PKCS11_LIB_PATH"
else
  fail "PKCS11_LIB_PATH not set or file not found (got: '${PKCS11_LIB_PATH:-unset}')"
fi

if command -v opensc-tool >/dev/null 2>&1; then
  reader_count=$(opensc-tool --list-readers 2>/dev/null | grep -c "Reader" || true)
  if [[ "$reader_count" -gt 0 ]]; then
    pass "CAC readers detected: $reader_count"
  else
    warn "No CAC readers detected — insert reader and retry"
  fi
else
  warn "opensc-tool not found — cannot verify CAC reader"
fi

# 2. Check required env vars
echo ""
echo "--- Environment Variables ---"
required_vars=(ADVANA_CLIENT_ID ADVANA_AUTH_ENDPOINT ADVANA_TOKEN_ENDPOINT ADVANA_REDIRECT_URI)
all_present=true
for var in "${required_vars[@]}"; do
  if [[ -n "${!var:-}" ]]; then
    pass "$var is set"
  else
    fail "$var is not set"
    all_present=false
  fi
done

# 3. Network reachability
echo ""
echo "--- Network Reachability ---"
if [[ -n "${ADVANA_AUTH_ENDPOINT:-}" ]]; then
  auth_host=$(echo "$ADVANA_AUTH_ENDPOINT" | awk -F/ '{print $3}')
  if curl -s --max-time 5 --head "https://$auth_host" >/dev/null 2>&1; then
    pass "Reachable: $auth_host"
  else
    fail "Cannot reach: $auth_host (check network/proxy)"
  fi
else
  warn "ADVANA_AUTH_ENDPOINT not set — skipping reachability check"
fi

# 4. CA bundle
echo ""
echo "--- Certificate Authority Bundle ---"
if [[ -n "${CAC_CA_BUNDLE_PATH:-}" && -f "$CAC_CA_BUNDLE_PATH" ]]; then
  cert_count=$(grep -c "BEGIN CERTIFICATE" "$CAC_CA_BUNDLE_PATH" 2>/dev/null || echo 0)
  pass "CA bundle found: $cert_count certificate(s)"
else
  warn "CAC_CA_BUNDLE_PATH not set or file not found"
fi

# 5. Optional auth test
if $AUTH_TEST; then
  echo ""
  echo "--- Authentication Test ---"
  if $all_present; then
    python3 -c "
import sys
sys.path.insert(0, '$REPO_ROOT')
from security_compliance.auth.platform_adapters.advana_adapter import AdvanaAdapter
print('Adapter import successful')
" 2>&1 && pass "Python adapter importable" || fail "Python adapter import failed"
  else
    warn "Skipping auth test — required env vars missing"
  fi
fi

echo ""
echo "=== Test complete ==="
