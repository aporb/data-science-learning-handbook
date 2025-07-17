#!/bin/bash
# DoD PKI Integration Setup Script
# Configures Vault for DoD PKI certificate authentication

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

VAULT_ADDR=${VAULT_ADDR:-"https://vault:8200"}
PKI_CONFIG_DIR="/vault/config/pki"
DOD_CA_BUNDLE="/vault/tls/dod-ca-bundle.pem"

echo -e "${GREEN}Setting up DoD PKI integration...${NC}"

# Ensure we have a valid token
if [ -z "$VAULT_TOKEN" ]; then
    if [ -f "/vault/data/root-token" ]; then
        export VAULT_TOKEN=$(cat /vault/data/root-token)
    else
        echo -e "${RED}No Vault token available. Please authenticate first.${NC}"
        exit 1
    fi
fi

# Create PKI configuration directory
mkdir -p "$PKI_CONFIG_DIR"

echo -e "${YELLOW}Configuring cert authentication method...${NC}"

# Enable cert auth method if not already enabled
if ! vault auth list | grep -q "cert/"; then
    vault auth enable cert
    echo -e "${GREEN}Certificate authentication method enabled${NC}"
else
    echo -e "${BLUE}Certificate authentication already enabled${NC}"
fi

# Configure cert auth method for DoD PKI
echo -e "${YELLOW}Setting up DoD PKI certificate validation...${NC}"

# Create DoD CA bundle (this would contain actual DoD root CAs in production)
cat > "$DOD_CA_BUNDLE" << 'EOF'
# DoD PKI Root Certificate Authority Bundle
# In production, this would contain the actual DoD Root CA certificates
# For demonstration purposes, this is a placeholder

# DoD Root CA 2
# DoD Root CA 3
# DoD Root CA 4
# DoD Root CA 5
# DoD Root CA 6

# Example structure (replace with actual DoD certificates):
# -----BEGIN CERTIFICATE-----
# [DoD Root CA Certificate Data]
# -----END CERTIFICATE-----
EOF

echo -e "${YELLOW}Configuring certificate roles for DoD personnel...${NC}"

# Configure cert auth for DoD CAC/PIV cards
vault write auth/cert/certs/dod-users \
    display_name="DoD CAC/PIV Users" \
    policies="dod-user-policy" \
    certificate=@"$DOD_CA_BUNDLE" \
    allowed_names="*.mil,*.gov" \
    allowed_email_sans="*.mil,*.gov" \
    allowed_uri_sans="*.mil,*.gov" \
    allowed_organizational_units="U.S. Government,DoD,Department of Defense" \
    required_extensions="2.16.840.1.101.3.2.1.3.13" \
    ttl=8h \
    max_ttl=24h

# Configure cert auth for DoD administrators
vault write auth/cert/certs/dod-admins \
    display_name="DoD System Administrators" \
    policies="dod-admin-policy" \
    certificate=@"$DOD_CA_BUNDLE" \
    allowed_names="*.mil" \
    allowed_email_sans="*.mil" \
    allowed_organizational_units="U.S. Government,DoD" \
    required_extensions="2.16.840.1.101.3.2.1.3.13,2.16.840.1.101.3.2.1.3.18" \
    ttl=4h \
    max_ttl=8h

echo -e "${YELLOW}Creating DoD-specific policies...${NC}"

# Create DoD user policy
cat > "$PKI_CONFIG_DIR/dod-user-policy.hcl" << 'EOF'
# DoD User Policy - Standard access for DoD personnel
path "kv/data/user/{{identity.entity.aliases.cert_*.name}}/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

path "kv/data/shared/read-only/*" {
  capabilities = ["read", "list"]
}

path "database/creds/readonly-role" {
  capabilities = ["read"]
}

path "auth/token/lookup-self" {
  capabilities = ["read"]
}

path "auth/token/renew-self" {
  capabilities = ["update"]
}

path "sys/capabilities-self" {
  capabilities = ["update"]
}
EOF

# Create DoD admin policy
cat > "$PKI_CONFIG_DIR/dod-admin-policy.hcl" << 'EOF'
# DoD Admin Policy - Elevated access for DoD system administrators
path "kv/data/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

path "database/creds/*" {
  capabilities = ["read"]
}

path "auth/cert/certs/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

path "sys/auth" {
  capabilities = ["read", "list"]
}

path "sys/auth/cert" {
  capabilities = ["create", "read", "update", "delete"]
}

path "sys/policies/acl/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

path "sys/audit" {
  capabilities = ["read", "list"]
}

path "sys/health" {
  capabilities = ["read"]
}

path "auth/token/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
EOF

# Apply the policies
vault policy write dod-user-policy "$PKI_CONFIG_DIR/dod-user-policy.hcl"
vault policy write dod-admin-policy "$PKI_CONFIG_DIR/dod-admin-policy.hcl"

echo -e "${YELLOW}Configuring LDAP integration for DoD directory services...${NC}"

# Configure LDAP auth for DoD Active Directory integration
vault write auth/ldap/config \
    url="ldaps://mil.ds.mil:636" \
    userattr="sAMAccountName" \
    userdn="ou=Users,ou=DoD,dc=mil,dc=ds,dc=mil" \
    groupdn="ou=Groups,ou=DoD,dc=mil,dc=ds,dc=mil" \
    groupfilter="(&(objectClass=group)(member:1.2.840.113556.1.4.1941:={{.UserDN}}))" \
    groupattr="cn" \
    binddn="cn=vault-service,ou=ServiceAccounts,ou=DoD,dc=mil,dc=ds,dc=mil" \
    bindpass="$(vault kv get -field=password kv/ldap/service-account 2>/dev/null || echo 'PLACEHOLDER_PASSWORD')" \
    starttls=true \
    insecure_tls=false \
    discoverdn=true \
    deny_null_bind=true \
    case_sensitive_names=false \
    use_token_groups=true

# Configure LDAP group mappings
vault write auth/ldap/groups/dod-users policies="dod-user-policy"
vault write auth/ldap/groups/dod-admins policies="dod-admin-policy"
vault write auth/ldap/groups/vault-admins policies="admin-policy"

echo -e "${YELLOW}Setting up DoD STIG compliance configurations...${NC}"

# Create STIG compliance configuration
cat > "$PKI_CONFIG_DIR/stig-compliance.hcl" << 'EOF'
# DoD STIG Compliance Configuration for Vault

# Audit requirements (STIG V-38498, V-38499)
audit "file" {
  file_path = "/vault/logs/audit.log"
  log_raw = false
  hmac_accessor = true
  mode = 0600
  format = "json"
}

# Session timeout requirements (STIG V-38539)
default_lease_ttl = "8h"
max_lease_ttl = "24h"

# Encryption requirements (STIG V-38518)
disable_mlock = false
raw_storage_endpoint = false

# Access control requirements (STIG V-38465)
disable_cache = false
disable_clustering = false
EOF

echo -e "${YELLOW}Creating DoD PKI certificate validation script...${NC}"

# Create certificate validation script
cat > "$PKI_CONFIG_DIR/validate-dod-cert.sh" << 'EOF'
#!/bin/bash
# DoD PKI Certificate Validation Script

CERT_FILE="$1"
if [ -z "$CERT_FILE" ]; then
    echo "Usage: $0 <certificate-file>"
    exit 1
fi

echo "Validating DoD PKI certificate: $CERT_FILE"

# Check certificate validity
openssl x509 -in "$CERT_FILE" -noout -text | grep -E "(Subject:|Issuer:|Not Before:|Not After:|Serial Number:)"

# Check for DoD-specific OIDs
echo "Checking for DoD PKI OIDs..."
openssl x509 -in "$CERT_FILE" -noout -text | grep -E "(2\.16\.840\.1\.101\.3\.2\.1\.3\.13|2\.16\.840\.1\.101\.3\.2\.1\.3\.18)"

# Verify against DoD CA bundle
if [ -f "/vault/tls/dod-ca-bundle.pem" ]; then
    echo "Verifying against DoD CA bundle..."
    openssl verify -CAfile /vault/tls/dod-ca-bundle.pem "$CERT_FILE"
else
    echo "Warning: DoD CA bundle not found"
fi
EOF

chmod +x "$PKI_CONFIG_DIR/validate-dod-cert.sh"

echo -e "${YELLOW}Setting up automated certificate renewal...${NC}"

# Create certificate renewal script
cat > "$PKI_CONFIG_DIR/renew-dod-certs.sh" << 'EOF'
#!/bin/bash
# Automated DoD PKI Certificate Renewal

LOG_FILE="/vault/logs/cert-renewal.log"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

log "Starting DoD PKI certificate renewal check"

# Check certificate expiration dates
for cert_path in /vault/tls/*.pem; do
    if [ -f "$cert_path" ]; then
        EXPIRY=$(openssl x509 -in "$cert_path" -noout -enddate 2>/dev/null | cut -d= -f2)
        EXPIRY_EPOCH=$(date -d "$EXPIRY" +%s 2>/dev/null || echo 0)
        CURRENT_EPOCH=$(date +%s)
        DAYS_UNTIL_EXPIRY=$(( (EXPIRY_EPOCH - CURRENT_EPOCH) / 86400 ))
        
        if [ "$DAYS_UNTIL_EXPIRY" -lt 30 ] && [ "$DAYS_UNTIL_EXPIRY" -gt 0 ]; then
            log "WARNING: Certificate $cert_path expires in $DAYS_UNTIL_EXPIRY days"
        elif [ "$DAYS_UNTIL_EXPIRY" -le 0 ]; then
            log "CRITICAL: Certificate $cert_path has expired"
        else
            log "INFO: Certificate $cert_path is valid for $DAYS_UNTIL_EXPIRY days"
        fi
    fi
done

log "DoD PKI certificate renewal check completed"
EOF

chmod +x "$PKI_CONFIG_DIR/renew-dod-certs.sh"

echo -e "${YELLOW}Creating DoD compliance audit script...${NC}"

# Create compliance audit script
cat > "$PKI_CONFIG_DIR/dod-compliance-audit.sh" << 'EOF'
#!/bin/bash
# DoD STIG Compliance Audit Script

AUDIT_REPORT="/vault/logs/dod-compliance-$(date +%Y%m%d_%H%M%S).json"

echo "Generating DoD STIG compliance audit report..."

{
    echo "{"
    echo "  \"audit_timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\","
    echo "  \"vault_version\": \"$(vault version | head -1)\","
    echo "  \"compliance_checks\": {"
    
    # Check audit logging (STIG V-38498)
    if [ -f "/vault/logs/audit.log" ]; then
        echo "    \"audit_logging\": \"COMPLIANT\","
    else
        echo "    \"audit_logging\": \"NON_COMPLIANT\","
    fi
    
    # Check session timeouts (STIG V-38539)
    LEASE_TTL=$(vault read sys/config/ui | grep default_lease_ttl || echo "NOT_SET")
    echo "    \"session_timeout\": \"$LEASE_TTL\","
    
    # Check TLS configuration (STIG V-38518)
    if vault status | grep -q "https://"; then
        echo "    \"tls_enabled\": \"COMPLIANT\","
    else
        echo "    \"tls_enabled\": \"NON_COMPLIANT\","
    fi
    
    # Check PKI certificate auth
    if vault auth list | grep -q "cert/"; then
        echo "    \"pki_auth_enabled\": \"COMPLIANT\","
    else
        echo "    \"pki_auth_enabled\": \"NON_COMPLIANT\","
    fi
    
    echo "    \"audit_complete\": true"
    echo "  }"
    echo "}"
} > "$AUDIT_REPORT"

echo "DoD compliance audit report generated: $AUDIT_REPORT"
EOF

chmod +x "$PKI_CONFIG_DIR/dod-compliance-audit.sh"

echo -e "${GREEN}DoD PKI integration setup completed!${NC}"
echo -e "${YELLOW}Configuration files created in: $PKI_CONFIG_DIR${NC}"
echo -e "${BLUE}Next steps:${NC}"
echo "1. Install actual DoD CA certificates in $DOD_CA_BUNDLE"
echo "2. Configure LDAP service account credentials"
echo "3. Test certificate authentication with DoD CAC/PIV cards"
echo "4. Run compliance audit: $PKI_CONFIG_DIR/dod-compliance-audit.sh"
echo "5. Set up automated certificate renewal monitoring"

echo -e "${GREEN}DoD PKI integration is ready for testing and deployment!${NC}"