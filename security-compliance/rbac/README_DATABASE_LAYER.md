# DoD-Compliant RBAC Database Layer

## Overview

This document describes the complete database layer implementation for the DoD-compliant Role-Based Access Control (RBAC) system. The implementation follows DoD security standards, NIST guidelines, and industry best practices for secure database operations.

## Features

### ✅ Enhanced Database Connection Management
- **Configuration-driven connections** via YAML files with environment variable support
- **Connection pooling** with thread-safe singleton pattern
- **SSL/TLS encryption** enforced for DoD compliance
- **Multiple database types** (primary, replica, audit) with automatic failover
- **Redis integration** for session management and caching

### ✅ Comprehensive Database Initialization
- **Automated migration system** with proper ordering and dependency management
- **Default data loading** from configuration files
- **Schema validation** and integrity checking
- **Environment-specific configurations** (development, staging, production, NIPR/SIPR/JWICS)
- **Audit logging setup** with retention policies

### ✅ Production-Ready Utilities
- **Health monitoring** with real-time status checks and alerting
- **Migration management** with rollback capabilities
- **Database maintenance** with automated cleanup and optimization
- **Performance metrics** and monitoring
- **Backup and recovery** utilities

### ✅ DoD Security Compliance
- **Encryption at rest and in transit** with AES-256-GCM
- **Comprehensive audit logging** for all database operations
- **Classification-aware** data handling (UNCLASSIFIED through TOP SECRET)
- **Network segregation** support (NIPR, SIPR, JWICS)
- **Certificate-based authentication** for CAC/PIV integration

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    Application Layer                            │
├─────────────────────────────────────────────────────────────────┤
│                    RBAC Models (BaseModel)                     │
├─────────────────────────────────────────────────────────────────┤
│                 Enhanced Database Layer                        │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐ │
│  │ DatabaseConfig  │  │ DatabaseConn    │  │ ConnectionPool  │ │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘ │
├─────────────────────────────────────────────────────────────────┤
│                    Database Utilities                          │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐ │
│  │ HealthMonitor   │  │ MigrationMgr    │  │ MaintenanceMgr  │ │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘ │
├─────────────────────────────────────────────────────────────────┤
│                     Database Layer                             │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐ │
│  │   PostgreSQL    │  │   PostgreSQL    │  │      Redis      │ │
│  │   (Primary)     │  │   (Replica)     │  │    (Cache)      │ │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

## Quick Start

### 1. Configuration Setup

Create or update `config/database.yaml`:

```yaml
database:
  primary:
    engine: "postgresql"
    host: "${DB_HOST:-localhost}"
    port: "${DB_PORT:-5432}"
    database: "${DB_NAME:-rbac_system}"
    username: "${DB_USER:-rbac_admin}" 
    password: "${DB_PASSWORD}"
    
    pool:
      min_connections: 5
      max_connections: 50
      connection_timeout: 30
      
    ssl:
      enabled: true
      mode: "require"
      cert_file: "/etc/ssl/certs/client-cert.pem"
      key_file: "/etc/ssl/private/client-key.pem"
      ca_file: "/etc/ssl/certs/ca-cert.pem"
```

### 2. Environment Variables

Set required environment variables:

```bash
export DB_PASSWORD="your_secure_password"
export AUDIT_DB_PASSWORD="your_audit_password"
export RBAC_ENVIRONMENT="development"  # or staging, production
```

### 3. Database Initialization

Initialize the complete RBAC database system:

```bash
# Development environment
python init_database.py --environment development

# Production environment with force flag
python init_database.py --environment production --force

# Validation only (no changes)
python init_database.py --validate-only
```

### 4. Testing and Validation

Validate the database layer implementation:

```bash
# Run comprehensive validation
python test_database_layer.py --validate

# Run unit tests
python test_database_layer.py --unittest
```

## Usage Examples

### Basic Database Connection

```python
from models.base import DatabaseConnection, DatabaseConfiguration

# Using configuration file
config = DatabaseConfiguration()
db_conn = DatabaseConnection(config, 'primary')

with db_conn.get_connection() as conn:
    with conn.cursor() as cursor:
        cursor.execute("SELECT * FROM rbac.users LIMIT 10")
        users = cursor.fetchall()
```

### Health Monitoring

```python
from db_utils import DatabaseHealthMonitor

# Start health monitoring
monitor = DatabaseHealthMonitor()
monitor.start_monitoring(interval_seconds=60)

# Get current health status
health_summary = monitor.get_health_summary()
print(f"System status: {health_summary['status']}")
```

### Migration Management

```python
from db_utils import MigrationManager
from pathlib import Path

# Apply migrations
migration_manager = MigrationManager()
migration_file = Path("schemas/05_new_feature.sql")
success = migration_manager.apply_migration(migration_file)

# Get migration status
migrations = migration_manager.get_migration_status()
for migration in migrations:
    print(f"{migration.filename}: {migration.executed_at}")
```

### Database Maintenance

```python
from db_utils import DatabaseMaintenanceManager

# Perform maintenance
maintenance = DatabaseMaintenanceManager()

# Analyze performance
metrics = maintenance.get_database_performance_metrics()
print(f"Total connections: {metrics['connections']['total_connections']}")

# Cleanup old audit logs
cleanup_results = maintenance.cleanup_old_audit_logs(retention_days=2555)
print(f"Cleaned up audit records: {sum(cleanup_results.values())}")
```

## File Structure

```
security-compliance/rbac/
├── models/
│   └── base.py                     # Enhanced DatabaseConnection and BaseModel
├── config/
│   ├── database.yaml              # Database configuration
│   ├── rbac_config.yaml           # RBAC system configuration
│   └── permissions/
│       └── base_permissions.yaml  # Default permissions
├── schemas/                       # SQL migration files
│   ├── 01_rbac_core.sql
│   ├── 02_standard_roles.sql
│   ├── 03_abac_functions.sql
│   └── 04_classification_schema.sql
├── schema/                        # Additional schema files
│   ├── 01_core_rbac_schema.sql
│   └── 02_session_audit_schema.sql
├── init_database.py              # Database initialization script
├── db_utils.py                   # Production database utilities
├── test_database_layer.py        # Comprehensive test suite
└── README_DATABASE_LAYER.md      # This documentation
```

## Security Features

### Encryption and SSL/TLS

- **Transport Layer Security**: All database connections use TLS 1.3 minimum
- **Certificate-based Authentication**: Client certificates for enhanced security
- **Connection String Security**: Passwords never logged or exposed
- **SSL Mode Enforcement**: Configurable SSL modes from 'prefer' to 'verify-full'

### Audit Logging

- **Comprehensive Logging**: All database operations are audited
- **Classification Tracking**: Data access logged with classification levels
- **Retention Policies**: Configurable retention based on DoD requirements
- **Real-time Monitoring**: Security events trigger immediate alerts

### Access Control

- **Connection Pooling**: Prevents connection exhaustion attacks
- **Query Timeouts**: Automatic termination of long-running queries
- **Session Management**: Redis-backed session tracking with encryption
- **Network Segregation**: Support for NIPR/SIPR/JWICS environments

## Configuration Reference

### Database Configuration (`config/database.yaml`)

| Parameter | Description | Default | Required |
|-----------|-------------|---------|----------|
| `database.primary.host` | Primary database host | localhost | Yes |
| `database.primary.port` | Primary database port | 5432 | Yes |
| `database.primary.database` | Database name | rbac_system | Yes |
| `database.primary.username` | Database username | rbac_admin | Yes |
| `database.primary.password` | Database password | - | Yes |
| `database.primary.pool.min_connections` | Minimum pool connections | 5 | No |
| `database.primary.pool.max_connections` | Maximum pool connections | 50 | No |
| `database.primary.ssl.enabled` | Enable SSL/TLS | true | No |
| `database.primary.ssl.mode` | SSL mode | require | No |

### Environment-Specific Overrides

The system supports environment-specific configuration overrides:

```yaml
environments:
  development:
    database:
      primary:
        ssl:
          mode: "prefer"  # More lenient for dev
  
  production:
    database:
      primary:
        ssl:
          mode: "verify-full"  # Strict for production
          verify_server_cert: true
```

## Monitoring and Alerting

### Health Check Endpoints

The health monitoring system provides detailed status information:

- **Database Connectivity**: Connection success/failure rates
- **Response Times**: Query performance metrics
- **Connection Pool Status**: Active/idle connection counts
- **Redis Cache Status**: Memory usage and connectivity
- **System Resources**: CPU, memory, and disk usage

### Alert Thresholds

| Metric | Warning | Critical |
|--------|---------|----------|
| Response Time | > 1000ms | > 5000ms |
| Connection Pool Usage | > 80% | > 95% |
| Redis Memory Usage | > 90% | > 95% |
| Failed Connections | > 5% | > 10% |

## Troubleshooting

### Common Issues

1. **Connection Failures**
   ```bash
   # Check database connectivity
   python test_database_layer.py --validate
   
   # Verify configuration
   python -c "from models.base import DatabaseConfiguration; print(DatabaseConfiguration().get_database_config('primary'))"
   ```

2. **SSL/TLS Issues**
   ```bash
   # Test SSL connection
   psql "sslmode=require host=localhost user=rbac_admin dbname=rbac_system"
   
   # Check certificate files
   ls -la /etc/ssl/certs/client-cert.pem
   ```

3. **Migration Failures**
   ```bash
   # Check migration status
   python -c "from db_utils import MigrationManager; print(MigrationManager().get_migration_status())"
   
   # Force re-run initialization
   python init_database.py --force
   ```

### Log Locations

- **Application logs**: `/var/log/rbac/init_database.log`
- **Database logs**: Check PostgreSQL configuration
- **Health monitoring**: Logged to application logger
- **Audit logs**: Stored in `rbac.auth_events`, `rbac.authz_events`, etc.

## Performance Optimization

### Connection Pooling

- **Pool Sizing**: Configure based on application load
- **Connection Lifetime**: Rotate connections periodically
- **Idle Timeout**: Clean up unused connections
- **Prepared Statements**: Use for frequently executed queries

### Query Optimization

- **Index Usage**: Monitor with `pg_stat_user_indexes`
- **Query Plans**: Analyze with `EXPLAIN ANALYZE`
- **Slow Query Log**: Enable `log_min_duration_statement`
- **Statistics**: Keep table statistics current with `ANALYZE`

### Maintenance Tasks

```python
# Regular maintenance schedule
maintenance = DatabaseMaintenanceManager()

# Weekly: Vacuum and analyze
maintenance.vacuum_analyze_tables()

# Monthly: Reindex tables
maintenance.reindex_tables()

# Quarterly: Cleanup old audit logs
maintenance.cleanup_old_audit_logs()
```

## Security Considerations

### Network Security

- **Firewall Rules**: Restrict database access to authorized hosts
- **VPN/Private Networks**: Use encrypted network channels
- **Port Security**: Change default PostgreSQL port if required
- **Network Segmentation**: Separate database and application networks

### Data Protection

- **Encryption at Rest**: Enable PostgreSQL transparent data encryption
- **Key Management**: Use Hardware Security Modules (HSM) for production
- **Backup Encryption**: Encrypt all database backups
- **Data Masking**: Implement for non-production environments

### Access Control

- **Principle of Least Privilege**: Grant minimum required permissions
- **Role-based Access**: Use PostgreSQL roles for access control
- **Regular Audits**: Review and rotate database credentials
- **Multi-factor Authentication**: Implement for administrative access

## Compliance and Standards

### DoD Standards Compliance

- **DoD 8500 Series**: Information Systems Security requirements
- **STIG Guidelines**: Security Technical Implementation Guides
- **FISMA**: Federal Information Security Management Act
- **NIST SP 800-53**: Security and Privacy Controls

### Audit Requirements

- **Event Logging**: All database access and modifications
- **Data Classification**: Track classification levels for all data
- **Retention Policies**: Meet DoD record retention requirements
- **Integrity Monitoring**: Detect unauthorized changes

## Support and Maintenance

### Regular Tasks

1. **Daily**
   - Monitor health check status
   - Review security alerts
   - Check backup completion

2. **Weekly**
   - Analyze performance metrics
   - Review audit logs
   - Update statistics

3. **Monthly**
   - Rotate connection pools
   - Review access permissions
   - Test backup restoration

4. **Quarterly**
   - Security configuration review
   - Performance optimization
   - Disaster recovery testing

### Contact Information

For issues, questions, or support:

- **Security Team**: security-compliance@domain.mil
- **Database Team**: database-admin@domain.mil
- **Emergency Contact**: emergency-response@domain.mil

---

**Classification**: UNCLASSIFIED//FOR OFFICIAL USE ONLY  
**Last Updated**: 2025-07-29  
**Version**: 2.0.0