#!/bin/bash
# Vault Initialization Script
# Initializes Vault cluster and configures basic security policies

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
VAULT_ADDR=${VAULT_ADDR:-"https://vault:8200"}
VAULT_CONFIG_DIR=${VAULT_CONFIG_DIR:-"/vault/config"}
VAULT_KEYS_FILE="/vault/data/vault-keys.json"
VAULT_ROOT_TOKEN_FILE="/vault/data/root-token"

echo -e "${GREEN}Starting Vault initialization...${NC}"

# Wait for Vault to be ready
echo -e "${YELLOW}Waiting for Vault to be ready...${NC}"
until vault status > /dev/null 2>&1 || [ $? -eq 2 ]; do
    echo "Waiting for Vault..."
    sleep 5
done

# Check if Vault is already initialized
if vault status | grep -q "Initialized.*true"; then
    echo -e "${GREEN}Vault is already initialized${NC}"
    exit 0
fi

echo -e "${YELLOW}Initializing Vault...${NC}"

# Initialize Vault
vault operator init \
    -key-shares=5 \
    -key-threshold=3 \
    -format=json > "$VAULT_KEYS_FILE"

# Extract root token
ROOT_TOKEN=$(cat "$VAULT_KEYS_FILE" | jq -r '.root_token')
echo "$ROOT_TOKEN" > "$VAULT_ROOT_TOKEN_FILE"

# Extract unseal keys
UNSEAL_KEY_1=$(cat "$VAULT_KEYS_FILE" | jq -r '.unseal_keys_b64[0]')
UNSEAL_KEY_2=$(cat "$VAULT_KEYS_FILE" | jq -r '.unseal_keys_b64[1]')
UNSEAL_KEY_3=$(cat "$VAULT_KEYS_FILE" | jq -r '.unseal_keys_b64[2]')

echo -e "${YELLOW}Unsealing Vault...${NC}"

# Unseal Vault
vault operator unseal "$UNSEAL_KEY_1"
vault operator unseal "$UNSEAL_KEY_2"
vault operator unseal "$UNSEAL_KEY_3"

# Authenticate with root token
export VAULT_TOKEN="$ROOT_TOKEN"

echo -e "${YELLOW}Configuring Vault...${NC}"

# Enable audit logging
vault audit enable file file_path=/vault/logs/audit.log

# Enable auth methods
vault auth enable userpass
vault auth enable ldap

# Enable secret engines
vault secrets enable -path=kv/ kv-v2
vault secrets enable -path=database/ database
vault secrets enable -path=pki/ pki
vault secrets enable -path=transit/ transit

# Configure PKI secret engine
vault secrets tune -max-lease-ttl=8760h pki/
vault write pki/root/generate/internal \
    common_name="Data Science Handbook Root CA" \
    ttl=8760h

vault write pki/config/urls \
    issuing_certificates="$VAULT_ADDR/v1/pki/ca" \
    crl_distribution_points="$VAULT_ADDR/v1/pki/crl"

# Create intermediate CA
vault secrets enable -path=pki_int/ pki
vault secrets tune -max-lease-ttl=4380h pki_int/

vault write -format=json pki_int/intermediate/generate/internal \
    common_name="Data Science Handbook Intermediate CA" \
    | jq -r '.data.csr' > /tmp/pki_intermediate.csr

vault write -format=json pki/root/sign-intermediate \
    csr=@/tmp/pki_intermediate.csr \
    format=pem_bundle ttl="4380h" \
    | jq -r '.data.certificate' > /tmp/intermediate.cert.pem

vault write pki_int/intermediate/set-signed certificate=@/tmp/intermediate.cert.pem

# Configure database secret engine for PostgreSQL
vault write database/config/postgresql \
    plugin_name=postgresql-database-plugin \
    connection_url="postgresql://{{username}}:{{password}}@postgres:5432/mlflow?sslmode=disable" \
    allowed_roles="mlflow-role" \
    username="mlflow" \
    password="mlflow"

# Create database role
vault write database/roles/mlflow-role \
    db_name=postgresql \
    creation_statements="CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}'; GRANT SELECT ON ALL TABLES IN SCHEMA public TO \"{{name}}\";" \
    default_ttl="1h" \
    max_ttl="24h"

# Create transit key for encryption
vault write -f transit/keys/data-science-handbook

echo -e "${GREEN}Vault initialization completed successfully!${NC}"
echo -e "${YELLOW}Important: Securely store the unseal keys and root token!${NC}"
echo -e "${RED}Root Token: $ROOT_TOKEN${NC}"
echo -e "${YELLOW}Keys stored in: $VAULT_KEYS_FILE${NC}"

# Set secure permissions
chmod 600 "$VAULT_KEYS_FILE" "$VAULT_ROOT_TOKEN_FILE"

echo -e "${GREEN}Vault is ready for use!${NC}"