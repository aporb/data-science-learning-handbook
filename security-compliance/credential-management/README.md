# Vault Credential Management System

A comprehensive, enterprise-grade credential management system built on HashiCorp Vault with DoD compliance, platform-specific integrations, automated rotation, disaster recovery, and monitoring capabilities.

## Overview

This system completes the remaining 20% of the HashiCorp Vault infrastructure by providing:

- **Platform-Specific Secret Generation & Rotation** for Qlik, Databricks, Advana, and Navy Jupiter
- **Zero-Downtime Credential Rotation** with automated scheduling
- **Comprehensive Monitoring** integration with Prometheus/Grafana
- **Automated Disaster Recovery** with encrypted backups and recovery plans
- **DoD Compliance Reporting** for NIST 800-53, DISA STIG, FISMA standards
- **CAC/PIV Integration** for all platform authentications

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                 Integrated Credential Management                 │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐  │
│  │ Vault Credential│  │ Platform Secret │  │ Metrics Export  │  │
│  │    Manager      │  │    Manager      │  │      System     │  │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘  │
│  ┌─────────────────┐  ┌─────────────────┐                       │
│  │ Disaster Recovery│  │ Compliance      │                       │
│  │    Manager      │  │   Reporter      │                       │
│  └─────────────────┘  └─────────────────┘                       │
├─────────────────────────────────────────────────────────────────┤
│                    Platform Adapters                            │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ │
│  │    Qlik     │ │ Databricks  │ │   Advana    │ │Navy Jupiter │ │
│  │   Adapter   │ │   Adapter   │ │   Adapter   │ │   Adapter   │ │
│  └─────────────┘ └─────────────┘ └─────────────┘ └─────────────┘ │
├─────────────────────────────────────────────────────────────────┤
│                   Existing Infrastructure                       │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ │
│  │   Vault     │ │   Consul    │ │ Prometheus  │ │   Grafana   │ │
│  │   Cluster   │ │  (HA Store) │ │ Monitoring  │ │ Dashboard   │ │
│  └─────────────┘ └─────────────┘ └─────────────┘ └─────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

## Components

### 1. Vault Credential Manager (`vault_credential_manager.py`)

Core credential management service that integrates with existing HashiCorp Vault infrastructure.

**Key Features:**
- Dynamic secret generation for multiple platforms
- Automated rotation scheduling with configurable intervals  
- Lease management and cleanup
- Integration with existing Vault secret engines
- Comprehensive audit logging

**Usage:**
```python
from credential_management import VaultCredentialManager

vault_manager = VaultCredentialManager(vault_config)
await vault_manager.initialize()

# Create dynamic secret
secret_id = await vault_manager.create_dynamic_secret(
    platform="qlik",
    secret_type=SecretType.API_KEY,
    user_context={"user_id": "john.doe@mil"},
    metadata={"compliance_level": "SECRET"}
)

# Rotate secret
success = await vault_manager.rotate_secret(secret_id)
```

### 2. Platform Secret Manager (`platform_secret_manager.py`)

Manages platform-specific credentials with zero-downtime rotation capabilities.

**Key Features:**
- Platform adapter integration (Qlik, Databricks, Advana, Navy Jupiter)
- Zero-downtime credential rotation with overlap periods
- Platform connectivity monitoring
- Credential health status tracking
- Automatic cleanup of expired credentials

**Usage:**
```python
from credential_management import PlatformSecretManager

platform_manager = PlatformSecretManager(vault_config, platform_configs)
await platform_manager.initialize()

# Create platform credential
credential = await platform_manager.create_platform_credential(
    platform="databricks",
    credential_type="service_account",
    user_context={"user_id": "admin", "clearance": "SECRET"}
)

# Zero-downtime rotation
success = await platform_manager.rotate_platform_credential(
    credential["credential_id"], 
    zero_downtime=True
)
```

### 3. Platform Adapters

#### Qlik Adapter (`qlik_adapter.py`)
- Qlik Sense Enterprise integration
- JWT token generation and validation
- Session ticket management
- App-specific access control

#### Databricks Adapter (`databricks_adapter.py`)
- Personal access token management
- Cluster access control
- SCIM user management
- Workspace integration

#### Advana Adapter (`advana_adapter.py`)
- DoD Advana platform integration
- Classification level enforcement
- EDIPI validation
- Data fabric access management

#### Navy Jupiter Adapter (`navy_jupiter_adapter.py`)
- Navy Jupiter analytics platform
- NEC code validation
- Fleet/ship context management
- Jupyter Hub integration

### 4. Vault Metrics Exporter (`vault_metrics_exporter.py`)

Prometheus metrics exporter for comprehensive monitoring integration.

**Key Metrics:**
- Vault cluster health and performance
- Credential lifecycle metrics
- Platform authentication success/failure rates
- Zero-downtime rotation statistics
- Security event tracking
- Compliance violation alerts

**Integration:**
- Exports to Prometheus on port 8080
- Integrates with existing Grafana dashboards
- Provides 60+ specialized metrics
- Custom alerting rules for Vault-specific events

### 5. Disaster Recovery Manager (`vault_disaster_recovery.py`)

Automated backup, encryption, and recovery system for Vault.

**Key Features:**
- Automated Raft snapshot backups
- Multi-cloud storage (AWS S3, Azure Blob, GCS)
- Backup encryption with FIPS 140-2 compliance
- Recovery plan generation and testing
- RTO/RPO monitoring and alerting

**Usage:**
```python
from credential_management import VaultDisasterRecoveryManager

dr_manager = VaultDisasterRecoveryManager(vault_config, dr_config)
await dr_manager.initialize()

# Create backup
backup_id = await dr_manager.create_backup("snapshot")

# Create recovery plan
plan_id = await dr_manager.create_recovery_plan(
    "Emergency Recovery",
    backup_id,
    "production",
    {"recovery_type": "point_in_time"}
)

# Execute recovery (with approval)
success = await dr_manager.execute_recovery(plan_id, approval_token)
```

### 6. Compliance Reporter (`compliance_reporter.py`)

DoD standards compliance reporting system.

**Supported Standards:**
- NIST 800-53 (Low/Moderate/High baselines)
- DISA STIG compliance checklists
- FISMA compliance reporting
- DoD 8570 requirements
- FIPS 140-2 validation
- Common Criteria evaluations

**Features:**
- Automated evidence collection
- Control assessment and scoring
- Executive summary generation
- Multiple report formats (JSON, HTML, CSV, PDF)
- STIG checklist generation
- Scheduled compliance reporting

## Installation

### Prerequisites

1. **Existing Infrastructure** (already deployed):
   - HashiCorp Vault cluster with Consul backend
   - Prometheus monitoring
   - Docker environment

2. **Python Dependencies**:
```bash
pip install hvac prometheus-client cryptography boto3 azure-storage-blob jinja2 aiofiles
```

### Configuration

1. **Update Docker Compose** to include new services:
```yaml
# Add to existing docker-compose.yml
  vault-credential-manager:
    build: ./security-compliance/credential-management
    ports:
      - "8080:8080"
    environment:
      - VAULT_ADDR=https://vault:8200
      - VAULT_TOKEN_FILE=/vault/data/credential-manager-token
    volumes:
      - vault-data:/vault/data
      - vault-backups:/vault/backups
    depends_on:
      - vault
      - consul
```

2. **Update Prometheus Configuration**:
The system automatically updates `/docker/prometheus/prometheus.yml` to include:
- Vault metrics scraping
- Credential management metrics
- Platform authentication metrics
- Consul backend monitoring

3. **Environment Variables**:
```bash
# Vault Configuration
export VAULT_ADDR="https://vault:8200"
export VAULT_TOKEN="$(cat /vault/data/root-token)"

# AWS S3 for Backups (optional)
export AWS_ACCESS_KEY_ID="your-access-key"
export AWS_SECRET_ACCESS_KEY="your-secret-key"

# Azure Blob Storage (optional)
export AZURE_STORAGE_ACCOUNT="your-account"
export AZURE_STORAGE_KEY="your-key"
```

## Usage

### Quick Start

```python
import asyncio
from credential_management import IntegratedCredentialManagementSystem, EXAMPLE_CONFIG

async def main():
    # Initialize system
    system = IntegratedCredentialManagementSystem(EXAMPLE_CONFIG)
    await system.initialize()
    
    # Create platform credential
    credential_id = await system.create_platform_credential(
        platform="qlik",
        credential_type="api_key",
        user_context={"user_id": "analyst@mil", "clearance": "SECRET"}
    )
    
    # Rotate with zero downtime
    await system.rotate_credential(credential_id, zero_downtime=True)
    
    # Create backup
    backup_id = await system.create_backup("snapshot")
    
    # Generate compliance report
    report_id = await system.generate_compliance_report(["nist_800_53"])
    
    # Get system status
    status = await system.get_system_status()
    print(f"System Status: {status}")

if __name__ == "__main__":
    asyncio.run(main())
```

### Platform-Specific Examples

#### Qlik Integration
```python
# Create Qlik session with CAC authentication
qlik_credential = await system.create_platform_credential(
    platform="qlik",
    credential_type="platform_token",
    user_context={
        "user_id": "john.doe@mil",
        "certificate_data": cac_cert_bytes,
        "signature": digital_signature,
        "challenge": auth_challenge
    },
    metadata={
        "compliance_level": "SECRET",
        "auto_rotate": True,
        "rotation_interval": 28800  # 8 hours
    }
)
```

#### Databricks Integration
```python
# Create Databricks personal access token
databricks_credential = await system.create_platform_credential(
    platform="databricks",
    credential_type="service_account", 
    user_context={
        "user_id": "data.scientist@mil",
        "workspace": "analytics-workspace"
    },
    metadata={
        "permissions": ["cluster:create", "workspace:read"],
        "cluster_policy_id": "policy-123"
    }
)
```

### Disaster Recovery

```python
# Create automated backup
backup_id = await system.dr_manager.create_backup(
    backup_type="snapshot",
    metadata={
        "compliance_level": "SECRET",
        "retention_days": 90
    }
)

# Test recovery readiness
readiness = await system.dr_manager.test_recovery_readiness(backup_id)
print(f"Recovery Ready: {readiness['ready']}")
print(f"Estimated RTO: {readiness['estimated_rto']} minutes")
```

### Compliance Reporting

```python
# Generate NIST 800-53 assessment
report_id = await system.compliance_reporter.generate_nist_assessment("moderate")

# Generate STIG checklist
checklist_file = await system.compliance_reporter.generate_stig_checklist("latest")

# Get compliance dashboard data
dashboard_data = await system.compliance_reporter.get_compliance_dashboard_data()
```

## Monitoring and Alerting

### Prometheus Metrics

The system exports 60+ specialized metrics including:

```prometheus
# Vault Status
vault_status                          # Overall Vault health
vault_sealed                          # Seal status
vault_credential_expiry_seconds       # Time until credential expiry

# Platform Authentication  
vault_platform_auth_requests_total   # Authentication request count
vault_platform_connectivity          # Platform connectivity status

# Zero-Downtime Rotation
vault_zero_downtime_rotations_total  # Zero-downtime rotation count
vault_rotation_overlap_duration_seconds # Overlap duration

# Security Events
vault_security_events_total          # Security event count
vault_compliance_violations_total    # Compliance violations
```

### Grafana Dashboards

Pre-configured dashboards for:
- **Vault Cluster Overview**: Health, performance, capacity
- **Credential Lifecycle**: Creation, rotation, expiration tracking  
- **Platform Authentication**: Success rates, latency, failures
- **Security Monitoring**: Events, violations, threat detection
- **Compliance Status**: Standard adherence, findings, trends

### Alert Rules

Critical alerts include:
- Vault sealed or down
- High authentication failure rates  
- Credential rotation failures
- Expired credentials detected
- Compliance violations
- Platform connectivity loss
- Disaster recovery failures

## Security Features

### DoD Compliance

- **NIST 800-53 Controls**: AC-2, AC-3, AU-2, AU-3, IA-2, SC-8, SC-13
- **DISA STIG Requirements**: Authentication, encryption, auditing
- **FISMA Compliance**: Risk management and continuous monitoring
- **FIPS 140-2**: Cryptographic module validation

### CAC/PIV Integration

- **Certificate Validation**: DoD PKI certificate chain validation
- **EDIPI Extraction**: Electronic Data Interchange Personal Identifier
- **Digital Signatures**: Challenge-response authentication
- **Smart Card Removal**: Session termination on card removal

### Encryption Standards

- **Data at Rest**: AES-256 encryption for all stored secrets
- **Data in Transit**: TLS 1.2+ for all communications  
- **Backup Encryption**: FIPS 140-2 approved algorithms
- **Key Management**: HSM integration ready

## Disaster Recovery

### Backup Strategy

- **Automated Backups**: Daily Raft snapshots at 2 AM UTC
- **Multi-Cloud Storage**: AWS S3, Azure Blob, Google Cloud Storage
- **Encryption**: All backups encrypted with unique keys
- **Retention**: 90-day default retention with compliance controls

### Recovery Procedures

- **RTO Target**: 60 minutes maximum downtime
- **RPO Target**: 15 minutes maximum data loss
- **Recovery Testing**: Automated readiness validation
- **Rollback Plans**: Automated rollback on recovery failure

### Business Continuity

- **Cross-Region Replication**: Backup replication across regions
- **Standby Environments**: Hot standby Vault clusters
- **Network Failover**: Automatic DNS failover capabilities
- **Communication Plans**: Automated stakeholder notification

## Production Deployment

### Infrastructure Requirements

- **CPU**: 4+ cores per Vault node
- **Memory**: 8GB+ RAM per Vault node  
- **Storage**: 100GB+ SSD for Vault data
- **Network**: 1Gbps+ with low latency to Consul
- **Backup Storage**: 1TB+ for backup retention

### Scaling Considerations

- **Horizontal Scaling**: Add Vault nodes to cluster
- **Vertical Scaling**: Increase node resources
- **Geographic Distribution**: Multi-region deployment
- **Load Balancing**: HAProxy or cloud load balancers

### Security Hardening

- **Network Isolation**: Private subnets and security groups
- **Access Control**: Minimal required permissions
- **Monitoring**: SIEM integration and 24/7 monitoring
- **Patch Management**: Regular security updates
- **Vulnerability Scanning**: Automated security scans

## Troubleshooting

### Common Issues

**Vault Sealed**:
```bash
# Check seal status
vault status

# Unseal if needed (requires threshold keys)
vault operator unseal <key1>
vault operator unseal <key2>
vault operator unseal <key3>
```

**Platform Authentication Failures**:
```bash
# Check platform adapter logs
docker logs vault-credential-manager

# Test platform connectivity
curl -k https://platform.example.com/health

# Verify certificates
openssl x509 -in /certs/platform.crt -text -noout
```

**Backup Failures**:
```bash
# Check backup status
python -c "
from credential_management import VaultDisasterRecoveryManager
import asyncio
dr = VaultDisasterRecoveryManager(config, dr_config)
status = asyncio.run(dr.list_backups())
print(status)
"
```

### Support

For operational support:
1. Check system logs: `docker logs vault-credential-manager`
2. Review Prometheus metrics in Grafana
3. Examine audit logs: `/vault/logs/audit.log`
4. Contact platform security team

## Contributing

This system is designed to integrate seamlessly with the existing 80% of Vault infrastructure while providing the critical remaining 20% of functionality. When contributing:

1. Maintain DoD compliance requirements
2. Follow existing code patterns and security standards
3. Add comprehensive tests for new features
4. Update documentation for any changes
5. Ensure integration with existing monitoring and alerting

## License

This system is designed for DoD and government use with appropriate security clearance and access controls.