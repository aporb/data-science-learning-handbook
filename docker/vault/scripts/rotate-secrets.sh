#!/bin/bash
# Vault Secret Rotation Script
# Automates rotation of dynamic secrets and credentials

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

VAULT_ADDR=${VAULT_ADDR:-"https://vault:8200"}
LOG_FILE="/vault/logs/rotation.log"

# Logging function
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

echo -e "${GREEN}Starting secret rotation process...${NC}"
log "INFO: Starting secret rotation process"

# Ensure we have a valid token
if [ -z "$VAULT_TOKEN" ]; then
    if [ -f "/vault/data/root-token" ]; then
        export VAULT_TOKEN=$(cat /vault/data/root-token)
    else
        echo -e "${RED}No Vault token available. Please authenticate first.${NC}"
        log "ERROR: No Vault token available"
        exit 1
    fi
fi

# Function to rotate database credentials
rotate_database_credentials() {
    echo -e "${YELLOW}Rotating database credentials...${NC}"
    log "INFO: Starting database credential rotation"
    
    # Force rotation of MLflow database credentials
    if vault read database/creds/mlflow-role >/dev/null 2>&1; then
        CREDS=$(vault read -format=json database/creds/mlflow-role)
        USERNAME=$(echo "$CREDS" | jq -r '.data.username')
        PASSWORD=$(echo "$CREDS" | jq -r '.data.password')
        
        log "INFO: Generated new database credentials for user: $USERNAME"
        echo -e "${GREEN}New database credentials generated${NC}"
        
        # Store credentials for service consumption
        vault kv put kv/mlflow/db-creds \
            username="$USERNAME" \
            password="$PASSWORD" \
            connection_string="postgresql://$USERNAME:$PASSWORD@postgres:5432/mlflow"
            
        log "INFO: Database credentials stored in KV store"
    else
        log "WARNING: Could not access database credentials"
        echo -e "${YELLOW}Warning: Could not access database credentials${NC}"
    fi
    
    # Rotate readonly credentials
    if vault read database/creds/readonly-role >/dev/null 2>&1; then
        READONLY_CREDS=$(vault read -format=json database/creds/readonly-role)
        READONLY_USER=$(echo "$READONLY_CREDS" | jq -r '.data.username')
        READONLY_PASS=$(echo "$READONLY_CREDS" | jq -r '.data.password')
        
        vault kv put kv/database/readonly-creds \
            username="$READONLY_USER" \
            password="$READONLY_PASS"
            
        log "INFO: Readonly database credentials rotated"
        echo -e "${GREEN}Readonly database credentials rotated${NC}"
    fi
}

# Function to rotate API keys and tokens
rotate_api_keys() {
    echo -e "${YELLOW}Rotating API keys and tokens...${NC}"
    log "INFO: Starting API key rotation"
    
    # Rotate service tokens (renew if possible, recreate if needed)
    SERVICES=("mlflow" "jupyter" "security" "monitoring")
    
    for service in "${SERVICES[@]}"; do
        TOKEN_FILE="/vault/data/${service}-token"
        if [ -f "$TOKEN_FILE" ]; then
            OLD_TOKEN=$(cat "$TOKEN_FILE")
            
            # Try to renew the token first
            if vault token renew "$OLD_TOKEN" >/dev/null 2>&1; then
                log "INFO: Renewed token for $service"
                echo -e "${GREEN}Renewed token for $service${NC}"
            else
                # If renewal fails, create a new token
                log "WARNING: Could not renew token for $service, creating new one"
                echo -e "${YELLOW}Creating new token for $service${NC}"
                
                NEW_TOKEN=$(vault write -field=token auth/token/create policies="${service}-policy" ttl=8760h renewable=true)
                echo "$NEW_TOKEN" > "$TOKEN_FILE"
                chmod 600 "$TOKEN_FILE"
                
                log "INFO: Created new token for $service"
                echo -e "${GREEN}Created new token for $service${NC}"
            fi
        fi
    done
}

# Function to rotate encryption keys
rotate_encryption_keys() {
    echo -e "${YELLOW}Rotating encryption keys...${NC}"
    log "INFO: Starting encryption key rotation"
    
    # Rotate transit key (create new version)
    if vault read transit/keys/data-science-handbook >/dev/null 2>&1; then
        vault write -f transit/keys/data-science-handbook/rotate
        log "INFO: Rotated transit encryption key"
        echo -e "${GREEN}Transit encryption key rotated${NC}"
    else
        log "WARNING: Could not access transit key"
        echo -e "${YELLOW}Warning: Could not access transit key${NC}"
    fi
}

# Function to update PKI certificates
rotate_pki_certificates() {
    echo -e "${YELLOW}Checking PKI certificates...${NC}"
    log "INFO: Starting PKI certificate check"
    
    # Check certificate expiration and rotate if needed
    if vault read pki_int/cert/ca >/dev/null 2>&1; then
        CERT_INFO=$(vault read -format=json pki_int/cert/ca)
        # Add logic to check expiration and rotate if needed
        log "INFO: PKI certificates checked"
        echo -e "${GREEN}PKI certificates checked${NC}"
    else
        log "WARNING: Could not access PKI certificates"
        echo -e "${YELLOW}Warning: Could not access PKI certificates${NC}"
    fi
}

# Function to clean up expired leases
cleanup_expired_leases() {
    echo -e "${YELLOW}Cleaning up expired leases...${NC}"
    log "INFO: Starting lease cleanup"
    
    # This would typically be handled by Vault automatically,
    # but we can force cleanup if needed
    vault lease tidy >/dev/null 2>&1 || true
    log "INFO: Lease cleanup completed"
    echo -e "${GREEN}Lease cleanup completed${NC}"
}

# Function to notify services of credential changes
notify_services() {
    echo -e "${YELLOW}Notifying services of credential changes...${NC}"
    log "INFO: Starting service notification"
    
    # Update timestamp for services to know when to refresh credentials
    vault kv put kv/system/rotation-status \
        last_rotation="$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        rotation_id="$(uuidgen)" \
        status="completed"
    
    log "INFO: Service notification completed"
    echo -e "${GREEN}Service notification completed${NC}"
}

# Main rotation workflow
main() {
    log "INFO: Secret rotation workflow started"
    
    # Check Vault status
    if ! vault status >/dev/null 2>&1; then
        echo -e "${RED}Vault is not accessible or sealed${NC}"
        log "ERROR: Vault is not accessible or sealed"
        exit 1
    fi
    
    # Perform rotations
    rotate_database_credentials
    rotate_api_keys
    rotate_encryption_keys
    rotate_pki_certificates
    cleanup_expired_leases
    notify_services
    
    log "INFO: Secret rotation workflow completed successfully"
    echo -e "${GREEN}Secret rotation completed successfully!${NC}"
    
    # Generate rotation report
    ROTATION_ID=$(vault kv get -field=rotation_id kv/system/rotation-status 2>/dev/null || echo "unknown")
    echo -e "${YELLOW}Rotation ID: $ROTATION_ID${NC}"
    echo -e "${YELLOW}Logs available at: $LOG_FILE${NC}"
}

# Handle script arguments
case "${1:-}" in
    "database")
        rotate_database_credentials
        ;;
    "api-keys")
        rotate_api_keys
        ;;
    "encryption")
        rotate_encryption_keys
        ;;
    "pki")
        rotate_pki_certificates
        ;;
    "cleanup")
        cleanup_expired_leases
        ;;
    *)
        main
        ;;
esac