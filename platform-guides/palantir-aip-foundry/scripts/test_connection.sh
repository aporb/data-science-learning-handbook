#!/usr/bin/env bash
# test_connection.sh — Smoke test Palantir Foundry connectivity.
#
# Usage: ./test_connection.sh [--auth]

set -euo pipefail

AUTH_TEST=false
[[ "${1:-}" == "--auth" ]] && AUTH_TEST=true

pass() { echo "  [PASS] $*"; }
fail() { echo "  [FAIL] $*"; }
warn() { echo "  [WARN] $*"; }

echo "=== Palantir Foundry Connection Test ==="

# 1. Required env vars
echo ""
echo "--- Environment Variables ---"
required_vars=(FOUNDRY_HOSTNAME FOUNDRY_TOKEN)
all_present=true
for var in "${required_vars[@]}"; do
  if [[ -n "${!var:-}" ]]; then
    pass "$var is set"
  else
    fail "$var is not set"
    all_present=false
  fi
done

# 2. Python SDK
echo ""
echo "--- Python SDK ---"
if python3 -c "import foundry" 2>/dev/null; then
  pass "foundry-platform-sdk importable"
else
  warn "foundry-platform-sdk not importable (pip install foundry-platform-sdk)"
fi

if python3 -c "import palantir_models" 2>/dev/null; then
  pass "palantir-models importable"
else
  warn "palantir-models not importable (pip install palantir-models)"
fi

# 3. Network reachability
echo ""
echo "--- Network Reachability ---"
if [[ -n "${FOUNDRY_HOSTNAME:-}" ]]; then
  if curl -s --max-time 5 --head "https://${FOUNDRY_HOSTNAME}" >/dev/null 2>&1; then
    pass "Reachable: ${FOUNDRY_HOSTNAME}"
  else
    fail "Cannot reach ${FOUNDRY_HOSTNAME} — check network/VPN"
  fi
else
  warn "FOUNDRY_HOSTNAME not set — skipping reachability check"
fi

# 4. Auth test
if $AUTH_TEST && $all_present; then
  echo ""
  echo "--- Authentication Test ---"
  python3 - <<EOF
import os
try:
    from foundry import FoundryClient
    from foundry.auth import UserTokenAuth
    client = FoundryClient(
        auth=UserTokenAuth(token=os.environ["FOUNDRY_TOKEN"]),
        hostname=os.environ["FOUNDRY_HOSTNAME"],
    )
    print("  [PASS] Foundry client created successfully")
except Exception as e:
    print(f"  [FAIL] {e}")
EOF
fi

echo ""
echo "=== Test complete ==="
