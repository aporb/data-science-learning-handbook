# HashiCorp Vault - Secure Credential Management System

This directory contains a complete HashiCorp Vault deployment for the Data Science Learning Handbook project, implementing enterprise-grade credential management with DoD security controls.

## Overview

The Vault system provides:
- **Centralized secret management** for all application credentials
- **High-availability configuration** using Consul backend
- **Dynamic secret generation** for database and API credentials
- **Least-privilege access policies** for different service roles
- **Automatic secret rotation** with configurable schedules
- **Break-glass emergency procedures** for critical situations
- **DoD PKI integration** for CAC/PIV authentication compliance

## Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Applications  │    │      Vault      │    │     Consul      │
│   (MLflow,      │◄──►│   (Primary)     │◄──►│   (HA Backend)  │
│   Jupyter, etc) │    │                 │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                              │
                              ▼
                       ┌─────────────────┐
                       │   PostgreSQL    │
                       │  (Credentials)  │
                       └─────────────────┘
```

## Quick Start

### 1. Deploy the Stack

```bash
# Start Vault and supporting services
docker-compose up -d consul vault

# Wait for services to be healthy
docker-compose ps

# Initialize Vault (one-time setup)
docker-compose up vault-init
```

### 2. Configure Policies and Secrets

```bash
# Set up access policies
docker exec -it vault /vault/scripts/setup-policies.sh

# Configure DoD PKI integration
docker exec -it vault /vault/scripts/setup-dod-pki.sh
```

### 3. Test Access

```bash
# Access Vault UI
open https://localhost:8200

# CLI access
export VAULT_ADDR="https://localhost:8200"
export VAULT_TOKEN="$(cat docker/vault/data/root-token)"
vault status
```

## File Structure

```
vault/
├── README.md                 # This documentation
├── vault.hcl                # Main Vault configuration
├── consul.hcl               # Consul HA backend config
├── scripts/                 # Operational scripts
│   ├── init-vault.sh        # Initial setup
│   ├── setup-policies.sh    # Access control policies
│   ├── rotate-secrets.sh    # Automated rotation
│   ├── break-glass.sh       # Emergency access
│   └── setup-dod-pki.sh     # DoD PKI integration
└── policies/                # Generated policy files
    ├── mlflow-policy.hcl
    ├── jupyter-policy.hcl
    ├── security-scanner-policy.hcl
    └── dod-*-policy.hcl
```

## Key Features

### 1. High Availability

- **Consul backend** for distributed consensus
- **Auto-unseal** capability (cloud KMS integration ready)
- **Health checks** and automatic failover
- **Backup and recovery** procedures

### 2. Security Controls

- **TLS encryption** for all communications
- **Audit logging** with structured JSON format
- **DoD STIG compliance** configurations
- **Role-based access control** (RBAC)
- **Time-limited tokens** with automatic expiration

### 3. Secret Engines

| Engine | Purpose | Path |
|--------|---------|------|
| KV v2 | Application secrets | `kv/` |
| Database | Dynamic DB credentials | `database/` |
| PKI | Certificate management | `pki/`, `pki_int/` |
| Transit | Encryption as a service | `transit/` |

### 4. Authentication Methods

| Method | Use Case | Configuration |
|--------|----------|---------------|
| Token | Service authentication | Default |
| Certificate | DoD CAC/PIV cards | `auth/cert/` |
| LDAP | DoD Active Directory | `auth/ldap/` |
| Userpass | Local accounts | `auth/userpass/` |

## Service Integration

### Application Configuration

Each service uses dedicated tokens with minimal required permissions:

```bash
# MLflow service
VAULT_TOKEN=$(cat /vault/data/mlflow-token)
DB_CREDS=$(vault kv get -format=json kv/mlflow/db-creds)

# Jupyter service  
VAULT_TOKEN=$(cat /vault/data/jupyter-token)
API_KEYS=$(vault kv get -format=json kv/api-keys/jupyter)
```

### Dynamic Database Credentials

```bash
# Generate temporary database credentials
vault read database/creds/mlflow-role
# Returns: username, password (auto-expires)

vault read database/creds/readonly-role  
# Returns: read-only username, password
```

## Operational Procedures

### Daily Operations

```bash
# Check system health
vault status
consul members

# View recent audit events
tail -f /vault/logs/audit.log

# Monitor secret expiration
vault list sys/leases/lookup/database/creds/mlflow-role
```

### Secret Rotation

```bash
# Automatic rotation (scheduled)
/vault/scripts/rotate-secrets.sh

# Manual rotation of specific secrets
/vault/scripts/rotate-secrets.sh database
/vault/scripts/rotate-secrets.sh api-keys
```

### Emergency Procedures

```bash
# Break-glass access (logged and audited)
/vault/scripts/break-glass.sh

# Emergency backup
vault operator raft snapshot save backup.snap

# Emergency unseal (if needed)
vault operator unseal <key1>
vault operator unseal <key2>  
vault operator unseal <key3>
```

## DoD Compliance

### STIG Requirements

- ✅ **V-38498**: Audit logging enabled
- ✅ **V-38499**: Audit log protection
- ✅ **V-38518**: Encryption in transit
- ✅ **V-38539**: Session timeout controls
- ✅ **V-38465**: Access control enforcement

### PKI Integration

```bash
# Configure DoD CA certificates
cp dod-root-ca.pem /vault/tls/dod-ca-bundle.pem

# Test CAC/PIV authentication
vault write auth/cert/login name=dod-users

# Validate certificate compliance
/vault/scripts/validate-dod-cert.sh user.crt
```

### Compliance Auditing

```bash
# Generate compliance report
/vault/scripts/dod-compliance-audit.sh

# Review audit logs
grep "CERTIFICATE_AUTH" /vault/logs/audit.log
```

## Security Considerations

### Production Deployment

1. **Auto-unseal**: Configure AWS KMS or Azure Key Vault
2. **TLS certificates**: Use proper CA-signed certificates  
3. **Network isolation**: Deploy in private subnets
4. **Backup strategy**: Regular snapshots to secure storage
5. **Monitoring**: Integration with SIEM systems

### Credential Lifecycle

```
Creation → Distribution → Rotation → Revocation → Cleanup
    ↓           ↓           ↓          ↓         ↓
  Policy    Service     Automated   Emergency   Audit
  Check     Token       Schedule    Revoke      Trail
```

### Access Patterns

```
User Request → Authentication → Authorization → Secret Access → Audit Log
     ↓              ↓              ↓              ↓            ↓
  CAC/PIV      DoD PKI       Policy Check    Dynamic Cred   JSON Log
```

## Troubleshooting

### Common Issues

**Vault sealed**: Use unseal keys or check auto-unseal configuration
```bash
vault operator unseal
```

**Permission denied**: Check token policies and TTL
```bash
vault token lookup
vault token capabilities <path>
```

**Service connectivity**: Verify network and DNS resolution
```bash
vault status -address=https://vault:8200
```

### Log Analysis

```bash
# Vault logs
docker logs vault

# Audit logs
jq '.type' /vault/logs/audit.log | sort | uniq -c

# Consul logs  
docker logs consul
```

## Monitoring and Alerting

### Health Endpoints

- Vault: `https://vault:8200/v1/sys/health`
- Consul: `http://consul:8500/v1/status/leader`

### Metrics Integration

```bash
# Prometheus metrics
curl https://vault:8200/v1/sys/metrics

# Custom alerting rules
vault read sys/policies/acl/monitoring-policy
```

## Backup and Recovery

### Backup Procedures

```bash
# Raft storage backup
vault operator raft snapshot save backup-$(date +%Y%m%d).snap

# Configuration backup
tar -czf vault-config-backup.tar.gz /vault/config /vault/policies
```

### Recovery Procedures

```bash
# Restore from snapshot
vault operator raft snapshot restore backup.snap

# Rebuild from configuration
docker-compose down vault
docker-compose up -d vault
/vault/scripts/init-vault.sh
```

## Support and Documentation

- **Vault Documentation**: https://www.vaultproject.io/docs
- **DoD PKI Resources**: https://public.cyber.mil/pki-pke/
- **Security Guidelines**: See `security-compliance/policies/`

For operational support, contact the platform security team.