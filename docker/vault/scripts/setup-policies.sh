#!/bin/bash
# Vault Policy Setup Script
# Creates least-privilege access policies for different application components

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

VAULT_ADDR=${VAULT_ADDR:-"https://vault:8200"}
POLICIES_DIR="/vault/policies"

echo -e "${GREEN}Setting up Vault policies...${NC}"

# Ensure we have a valid token
if [ -z "$VAULT_TOKEN" ]; then
    if [ -f "/vault/data/root-token" ]; then
        export VAULT_TOKEN=$(cat /vault/data/root-token)
    else
        echo -e "${RED}No Vault token available. Please authenticate first.${NC}"
        exit 1
    fi
fi

# Create policies directory
mkdir -p "$POLICIES_DIR"

echo -e "${YELLOW}Creating application policies...${NC}"

# MLflow Service Policy
cat > "$POLICIES_DIR/mlflow-policy.hcl" << 'EOF'
# MLflow service policy - database credentials and model storage
path "database/creds/mlflow-role" {
  capabilities = ["read"]
}

path "kv/data/mlflow/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

path "kv/metadata/mlflow/*" {
  capabilities = ["list"]
}

path "transit/encrypt/data-science-handbook" {
  capabilities = ["update"]
}

path "transit/decrypt/data-science-handbook" {
  capabilities = ["update"]
}
EOF

# Jupyter Service Policy
cat > "$POLICIES_DIR/jupyter-policy.hcl" << 'EOF'
# Jupyter service policy - notebook secrets and API keys
path "kv/data/jupyter/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

path "kv/data/api-keys/*" {
  capabilities = ["read", "list"]
}

path "transit/encrypt/data-science-handbook" {
  capabilities = ["update"]
}

path "transit/decrypt/data-science-handbook" {
  capabilities = ["update"]
}

path "database/creds/readonly-role" {
  capabilities = ["read"]
}
EOF

# Security Scanner Policy
cat > "$POLICIES_DIR/security-scanner-policy.hcl" << 'EOF'
# Security scanner policy - audit access and secret scanning
path "kv/data/security/*" {
  capabilities = ["create", "read", "update", "list"]
}

path "kv/data/api-keys/*" {
  capabilities = ["read", "list"]
}

path "sys/audit" {
  capabilities = ["read", "list"]
}

path "sys/health" {
  capabilities = ["read"]
}
EOF

# Monitoring Policy (Prometheus/Grafana)
cat > "$POLICIES_DIR/monitoring-policy.hcl" << 'EOF'
# Monitoring service policy - metrics and dashboards
path "kv/data/monitoring/*" {
  capabilities = ["read", "list"]
}

path "sys/metrics" {
  capabilities = ["read"]
}

path "sys/health" {
  capabilities = ["read"]
}
EOF

# Admin Policy (for break-glass access)
cat > "$POLICIES_DIR/admin-policy.hcl" << 'EOF'
# Admin emergency access policy
path "*" {
  capabilities = ["create", "read", "update", "delete", "list", "sudo"]
}
EOF

# Read-only Database Role Policy
cat > "$POLICIES_DIR/readonly-database-policy.hcl" << 'EOF'
# Read-only database access for analytics
path "database/creds/readonly-role" {
  capabilities = ["read"]
}
EOF

echo -e "${YELLOW}Applying policies to Vault...${NC}"

# Apply all policies
vault policy write mlflow-policy "$POLICIES_DIR/mlflow-policy.hcl"
vault policy write jupyter-policy "$POLICIES_DIR/jupyter-policy.hcl"
vault policy write security-scanner-policy "$POLICIES_DIR/security-scanner-policy.hcl"
vault policy write monitoring-policy "$POLICIES_DIR/monitoring-policy.hcl"
vault policy write admin-policy "$POLICIES_DIR/admin-policy.hcl"
vault policy write readonly-database-policy "$POLICIES_DIR/readonly-database-policy.hcl"

echo -e "${YELLOW}Creating service tokens...${NC}"

# Create service tokens
MLFLOW_TOKEN=$(vault write -field=token auth/token/create policies="mlflow-policy" ttl=8760h renewable=true)
JUPYTER_TOKEN=$(vault write -field=token auth/token/create policies="jupyter-policy" ttl=8760h renewable=true)
SECURITY_TOKEN=$(vault write -field=token auth/token/create policies="security-scanner-policy" ttl=8760h renewable=true)
MONITORING_TOKEN=$(vault write -field=token auth/token/create policies="monitoring-policy" ttl=8760h renewable=true)

# Store service tokens securely
echo "$MLFLOW_TOKEN" > /vault/data/mlflow-token
echo "$JUPYTER_TOKEN" > /vault/data/jupyter-token
echo "$SECURITY_TOKEN" > /vault/data/security-token
echo "$MONITORING_TOKEN" > /vault/data/monitoring-token

# Set secure permissions
chmod 600 /vault/data/*-token

echo -e "${YELLOW}Creating database roles...${NC}"

# Create read-only database role
vault write database/roles/readonly-role \
    db_name=postgresql \
    creation_statements="CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}'; GRANT SELECT ON ALL TABLES IN SCHEMA public TO \"{{name}}\";" \
    default_ttl="8h" \
    max_ttl="24h"

echo -e "${YELLOW}Setting up initial secrets...${NC}"

# Store initial application secrets
vault kv put kv/mlflow/config \
    database_url="postgresql://mlflow:mlflow@postgres:5432/mlflow" \
    artifact_store="/app/mlartifacts" \
    tracking_uri="http://mlflow:5000"

vault kv put kv/jupyter/config \
    enable_lab="yes" \
    notebook_dir="/workspace" \
    ip="0.0.0.0" \
    port="8888"

vault kv put kv/monitoring/config \
    prometheus_url="http://prometheus:9090" \
    grafana_url="http://grafana:3000" \
    admin_password="admin"

echo -e "${GREEN}Policy setup completed successfully!${NC}"
echo -e "${YELLOW}Service tokens created and stored in /vault/data/${NC}"
echo -e "${RED}MLflow Token: $MLFLOW_TOKEN${NC}"
echo -e "${RED}Jupyter Token: $JUPYTER_TOKEN${NC}"
echo -e "${RED}Security Token: $SECURITY_TOKEN${NC}"
echo -e "${RED}Monitoring Token: $MONITORING_TOKEN${NC}"

echo -e "${GREEN}Vault is now configured with least-privilege policies!${NC}"