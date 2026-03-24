#!/usr/bin/env bash
# test_connection.sh — Smoke test Databricks platform connectivity.
#
# Usage: ./test_connection.sh [--auth]

set -euo pipefail

AUTH_TEST=false
[[ "${1:-}" == "--auth" ]] && AUTH_TEST=true

log()  { echo "  [$(date '+%H:%M:%S')] $*"; }
pass() { echo "  [PASS] $*"; }
fail() { echo "  [FAIL] $*"; }
warn() { echo "  [WARN] $*"; }

echo "=== Databricks Connection Test ==="

# 1. Required env vars
echo ""
echo "--- Environment Variables ---"
required_vars=(DATABRICKS_HOST DATABRICKS_TOKEN DATABRICKS_CLUSTER_ID)
all_present=true
for var in "${required_vars[@]}"; do
  if [[ -n "${!var:-}" ]]; then
    pass "$var is set"
  else
    fail "$var is not set"
    all_present=false
  fi
done

# 2. Databricks CLI
echo ""
echo "--- CLI ---"
if command -v databricks >/dev/null 2>&1; then
  version=$(databricks --version 2>&1 | head -1)
  pass "databricks CLI found: $version"
else
  warn "databricks CLI not found (pip install databricks-sdk)"
fi

# 3. Network reachability
echo ""
echo "--- Network Reachability ---"
if [[ -n "${DATABRICKS_HOST:-}" ]]; then
  host=$(echo "$DATABRICKS_HOST" | awk -F/ '{print $3}')
  if curl -s --max-time 5 --head "https://$host" >/dev/null 2>&1; then
    pass "Reachable: $host"
  else
    fail "Cannot reach: $host (check network/proxy)"
  fi
else
  warn "DATABRICKS_HOST not set — skipping reachability check"
fi

# 4. Python SDK check
echo ""
echo "--- Python SDK ---"
if python3 -c "import databricks.sdk" 2>/dev/null; then
  pass "databricks-sdk importable"
else
  warn "databricks-sdk not importable (pip install databricks-sdk)"
fi

if $AUTH_TEST && $all_present; then
  echo ""
  echo "--- Cluster Status ---"
  python3 - <<'EOF'
import os, json
from databricks.sdk import WorkspaceClient
client = WorkspaceClient(host=os.environ["DATABRICKS_HOST"], token=os.environ["DATABRICKS_TOKEN"])
cluster = client.clusters.get(os.environ["DATABRICKS_CLUSTER_ID"])
print(f"  Cluster: {cluster.cluster_name} [{cluster.state}]")
EOF
fi

echo ""
echo "=== Test complete ==="
