#!/bin/bash
# Vault Break-Glass Emergency Access Script
# Provides emergency access procedures for critical situations

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

VAULT_ADDR=${VAULT_ADDR:-"https://vault:8200"}
EMERGENCY_LOG="/vault/logs/emergency-access.log"
BREAK_GLASS_TOKEN_FILE="/vault/data/break-glass-token"

# Logging function with emergency context
emergency_log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] EMERGENCY: $1" | tee -a "$EMERGENCY_LOG"
}

# Display warning banner
display_warning() {
    echo -e "${RED}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${RED}║                     ⚠️  BREAK-GLASS PROCEDURE ⚠️              ║${NC}"
    echo -e "${RED}║                                                              ║${NC}"
    echo -e "${RED}║  This procedure provides emergency access to Vault secrets  ║${NC}"
    echo -e "${RED}║  and should ONLY be used in critical situations.            ║${NC}"
    echo -e "${RED}║                                                              ║${NC}"
    echo -e "${RED}║  All actions are logged and audited.                        ║${NC}"
    echo -e "${RED}║  Unauthorized use is prohibited.                            ║${NC}"
    echo -e "${RED}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo
}

# Function to prompt for justification
get_justification() {
    echo -e "${YELLOW}Emergency access requires justification.${NC}"
    echo -e "${YELLOW}Please provide the reason for this break-glass access:${NC}"
    read -r JUSTIFICATION
    
    if [ -z "$JUSTIFICATION" ]; then
        echo -e "${RED}Justification is required for emergency access.${NC}"
        exit 1
    fi
    
    emergency_log "Break-glass access initiated. Justification: $JUSTIFICATION"
}

# Function to authenticate using unseal keys
emergency_auth() {
    echo -e "${YELLOW}Attempting emergency authentication...${NC}"
    
    # Check if Vault is sealed
    if vault status | grep -q "Sealed.*true"; then
        echo -e "${RED}Vault is sealed. Emergency unseal required.${NC}"
        emergency_log "Vault found sealed during emergency access attempt"
        
        if [ -f "/vault/data/vault-keys.json" ]; then
            echo -e "${YELLOW}Using stored unseal keys for emergency access...${NC}"
            
            # Extract unseal keys
            UNSEAL_KEY_1=$(cat /vault/data/vault-keys.json | jq -r '.unseal_keys_b64[0]')
            UNSEAL_KEY_2=$(cat /vault/data/vault-keys.json | jq -r '.unseal_keys_b64[1]')
            UNSEAL_KEY_3=$(cat /vault/data/vault-keys.json | jq -r '.unseal_keys_b64[2]')
            
            # Unseal Vault
            vault operator unseal "$UNSEAL_KEY_1"
            vault operator unseal "$UNSEAL_KEY_2"
            vault operator unseal "$UNSEAL_KEY_3"
            
            emergency_log "Vault unsealed during emergency procedure"
            echo -e "${GREEN}Vault unsealed successfully${NC}"
        else
            echo -e "${RED}Unseal keys not available. Manual intervention required.${NC}"
            emergency_log "ERROR: Unseal keys not available for emergency access"
            exit 1
        fi
    fi
    
    # Use root token for emergency access
    if [ -f "/vault/data/root-token" ]; then
        export VAULT_TOKEN=$(cat /vault/data/root-token)
        emergency_log "Root token loaded for emergency access"
    else
        echo -e "${RED}Root token not available. Cannot proceed with emergency access.${NC}"
        emergency_log "ERROR: Root token not available for emergency access"
        exit 1
    fi
    
    # Verify authentication
    if vault token lookup >/dev/null 2>&1; then
        echo -e "${GREEN}Emergency authentication successful${NC}"
        emergency_log "Emergency authentication successful"
    else
        echo -e "${RED}Emergency authentication failed${NC}"
        emergency_log "ERROR: Emergency authentication failed"
        exit 1
    fi
}

# Function to create temporary break-glass token
create_break_glass_token() {
    echo -e "${YELLOW}Creating temporary break-glass access token...${NC}"
    
    # Create a temporary policy with broad access
    cat > /tmp/break-glass-policy.hcl << 'EOF'
# Emergency break-glass policy - broad access for critical situations
path "*" {
  capabilities = ["create", "read", "update", "delete", "list", "sudo"]
}
EOF
    
    # Apply the policy
    vault policy write break-glass-emergency /tmp/break-glass-policy.hcl
    
    # Create a time-limited token (4 hours max)
    BREAK_GLASS_TOKEN=$(vault write -field=token auth/token/create \
        policies="break-glass-emergency" \
        ttl=4h \
        num_uses=50 \
        renewable=false \
        explicit_max_ttl=4h)
    
    echo "$BREAK_GLASS_TOKEN" > "$BREAK_GLASS_TOKEN_FILE"
    chmod 600 "$BREAK_GLASS_TOKEN_FILE"
    
    emergency_log "Break-glass token created with 4-hour TTL and 50 use limit"
    echo -e "${GREEN}Break-glass token created: $BREAK_GLASS_TOKEN${NC}"
    echo -e "${YELLOW}Token valid for 4 hours with 50 use limit${NC}"
    
    # Clean up temporary policy file
    rm -f /tmp/break-glass-policy.hcl
}

# Function to retrieve critical secrets
get_critical_secrets() {
    echo -e "${YELLOW}Retrieving critical system secrets...${NC}"
    emergency_log "Critical secrets retrieval initiated"
    
    echo -e "${BLUE}Available secret paths:${NC}"
    echo "1. Database credentials (kv/mlflow/db-creds)"
    echo "2. Service tokens"
    echo "3. API keys (kv/api-keys/*)"
    echo "4. System configuration (kv/system/*)"
    echo "5. All secrets (list all paths)"
    echo
    
    read -p "Select option (1-5): " OPTION
    
    case $OPTION in
        1)
            echo -e "${YELLOW}Database credentials:${NC}"
            vault kv get kv/mlflow/db-creds || echo "No database credentials found"
            emergency_log "Database credentials accessed"
            ;;
        2)
            echo -e "${YELLOW}Service tokens:${NC}"
            for service in mlflow jupyter security monitoring; do
                if [ -f "/vault/data/${service}-token" ]; then
                    echo "${service}: $(cat /vault/data/${service}-token)"
                fi
            done
            emergency_log "Service tokens accessed"
            ;;
        3)
            echo -e "${YELLOW}API keys:${NC}"
            vault kv list kv/api-keys/ || echo "No API keys found"
            emergency_log "API keys listed"
            ;;
        4)
            echo -e "${YELLOW}System configuration:${NC}"
            vault kv get kv/system/rotation-status || echo "No system config found"
            emergency_log "System configuration accessed"
            ;;
        5)
            echo -e "${YELLOW}All secret paths:${NC}"
            vault secrets list
            emergency_log "All secret paths listed"
            ;;
        *)
            echo -e "${RED}Invalid option${NC}"
            ;;
    esac
}

# Function to perform emergency operations
emergency_operations() {
    echo -e "${YELLOW}Emergency operations menu:${NC}"
    echo "1. Reset service credentials"
    echo "2. Disable compromised tokens"
    echo "3. Force secret rotation"
    echo "4. Backup critical data"
    echo "5. View audit logs"
    echo
    
    read -p "Select operation (1-5): " OP_OPTION
    
    case $OP_OPTION in
        1)
            echo -e "${YELLOW}Resetting service credentials...${NC}"
            /vault/scripts/setup-policies.sh
            emergency_log "Service credentials reset"
            ;;
        2)
            echo -e "${YELLOW}Listing active tokens for review...${NC}"
            vault auth list-accessors
            emergency_log "Token accessors listed for review"
            ;;
        3)
            echo -e "${YELLOW}Forcing secret rotation...${NC}"
            /vault/scripts/rotate-secrets.sh
            emergency_log "Emergency secret rotation performed"
            ;;
        4)
            echo -e "${YELLOW}Creating emergency backup...${NC}"
            vault operator raft snapshot save /vault/data/emergency-backup-$(date +%Y%m%d_%H%M%S).snap
            emergency_log "Emergency backup created"
            ;;
        5)
            echo -e "${YELLOW}Recent audit log entries:${NC}"
            tail -50 /vault/logs/audit.log || echo "Audit log not available"
            emergency_log "Audit log accessed"
            ;;
        *)
            echo -e "${RED}Invalid operation${NC}"
            ;;
    esac
}

# Function to cleanup after break-glass access
cleanup_break_glass() {
    echo -e "${YELLOW}Cleaning up break-glass access...${NC}"
    
    # Revoke break-glass token if it exists
    if [ -f "$BREAK_GLASS_TOKEN_FILE" ]; then
        BREAK_GLASS_TOKEN=$(cat "$BREAK_GLASS_TOKEN_FILE")
        vault token revoke "$BREAK_GLASS_TOKEN" >/dev/null 2>&1 || true
        rm -f "$BREAK_GLASS_TOKEN_FILE"
        emergency_log "Break-glass token revoked and cleaned up"
    fi
    
    # Remove break-glass policy
    vault policy delete break-glass-emergency >/dev/null 2>&1 || true
    emergency_log "Break-glass policy removed"
    
    echo -e "${GREEN}Break-glass cleanup completed${NC}"
    emergency_log "Break-glass procedure cleanup completed"
}

# Main break-glass procedure
main() {
    display_warning
    
    # Require user confirmation
    echo -e "${YELLOW}Do you understand the implications and wish to proceed? (yes/no):${NC}"
    read -r CONFIRM
    
    if [ "$CONFIRM" != "yes" ]; then
        echo -e "${RED}Break-glass procedure cancelled${NC}"
        exit 0
    fi
    
    get_justification
    emergency_auth
    create_break_glass_token
    
    # Interactive menu
    while true; do
        echo
        echo -e "${BLUE}Break-glass emergency menu:${NC}"
        echo "1. Retrieve critical secrets"
        echo "2. Perform emergency operations"
        echo "3. Exit and cleanup"
        echo
        
        read -p "Select option (1-3): " MENU_OPTION
        
        case $MENU_OPTION in
            1)
                get_critical_secrets
                ;;
            2)
                emergency_operations
                ;;
            3)
                cleanup_break_glass
                echo -e "${GREEN}Break-glass procedure completed${NC}"
                emergency_log "Break-glass procedure completed normally"
                exit 0
                ;;
            *)
                echo -e "${RED}Invalid option${NC}"
                ;;
        esac
    done
}

# Handle script termination
trap cleanup_break_glass EXIT

# Run main procedure
main "$@"