# DoD-Compliant RBAC System

## Overview

This is a comprehensive Role-Based Access Control (RBAC) system designed for Department of Defense (DoD) environments, implementing multiple layers of access control including Mandatory Access Control (MAC), Discretionary Access Control (DAC), Role-Based Access Control (RBAC), and Attribute-Based Access Control (ABAC).

**Classification**: UNCLASSIFIED//CUI  
**Version**: 1.0.0  
**Compliance**: NIST 800-53, STIG, DoD 8500, FISMA  

## 🏗️ Architecture

The system follows a modular architecture with clear separation of concerns:

```
RBAC System
├── Core System (rbac_system.py)
├── System Manager (rbac_system_manager.py)
├── System Validation (system_validation.py)
├── Database Layer (db_utils.py, init_database.py)
├── Models/
│   ├── User Management
│   ├── Role Management
│   ├── Permission Management
│   ├── Audit Logging
│   └── Classification Management
├── Integrations/
│   ├── CAC/PIV Bridge
│   └── OAuth Bridge
├── Policies/
│   ├── ABAC Rules
│   └── Role Hierarchies
└── Configuration/
    ├── Database Configuration
    ├── Security Settings
    └── Validation Rules
```

## 🔐 Security Features

### Multi-Layer Access Control
- **MAC (Mandatory Access Control)**: Bell-LaPadula model implementation
- **DAC (Discretionary Access Control)**: Resource ownership-based access
- **RBAC (Role-Based Access Control)**: Role hierarchy and permission mapping
- **ABAC (Attribute-Based Access Control)**: Context-aware policy evaluation

### DoD Compliance
- **Classification Levels**: UNCLASSIFIED, CONFIDENTIAL, SECRET, TOP SECRET
- **CAC/PIV Integration**: Hardware-based authentication
- **Audit Logging**: Comprehensive audit trail with retention policies
- **Emergency Access**: Controlled emergency access procedures
- **Session Management**: Secure session handling with timeout controls

### Security Standards Compliance
- **NIST 800-53**: Security and privacy controls implementation
- **STIG**: Security Technical Implementation Guides compliance
- **DoD 8500**: Information Assurance implementation
- **FISMA**: Federal Information Security Management Act compliance

## 🚀 Quick Start

### 1. System Requirements

- Python 3.8+
- PostgreSQL 12+
- Redis (optional, for caching)
- SSL certificates
- DoD PKI infrastructure access (for CAC/PIV)

### 2. Installation

```bash
# Clone the repository
git clone <repository-url>
cd security-compliance/rbac

# Install dependencies
pip install -r requirements.txt

# Set environment variables
export DB_HOST=localhost
export DB_PORT=5432
export DB_NAME=rbac_system
export DB_USER=rbac_user
export DB_PASSWORD=<secure_password>
export AUDIT_DB_PASSWORD=<audit_password>
```

### 3. Database Initialization

```bash
# Initialize the database system
python init_database.py --environment production

# For development environment
python init_database.py --environment development

# Force re-initialization
python init_database.py --environment production --force

# Validate only (no changes)
python init_database.py --validate-only
```

### 4. System Startup

```python
import asyncio
from rbac_system_manager import RBACSystemManager

async def start_rbac_system():
    # Create and initialize system manager
    async with RBACSystemManager(environment='production').system_context() as manager:
        
        # System is now ready for use
        print("RBAC System initialized successfully")
        
        # Example access check
        response = await manager.check_access(
            user_id="user123",
            resource_id="document456",
            resource_type="document",
            action="read",
            classification_level="SECRET",
            context={"location": "authorized_facility"}
        )
        
        print(f"Access granted: {response.granted}")
        print(f"Reason: {response.reason}")

# Run the system
asyncio.run(start_rbac_system())
```

## 📊 System Components

### Core System (rbac_system.py)

The main RBAC engine that handles access control decisions:

```python
from rbac_system import RBACSystem, AccessRequest, AccessResponse

# Initialize RBAC system
rbac = RBACSystem(
    cache_size=10000,
    cache_ttl=300,
    enable_emergency_access=True
)

# Create access request
request = AccessRequest(
    user_id="12345678-1234-1234-1234-123456789012",
    resource_id="notebook_123",
    resource_type="notebook",
    action="execute",
    context={
        "cac_credentials": {
            "clearance_level": "SECRET",
            "organization": "US Navy",
            "issuer_dn": "DOD PKI"
        },
        "mfa_verified": True
    },
    classification_level="SECRET",
    session_id="session_456",
    ip_address="192.168.1.100"
)

# Check access
response = await rbac.check_access(request)
```

### System Manager (rbac_system_manager.py)

The orchestration layer that manages all system components:

```python
from rbac_system_manager import RBACSystemManager

# Initialize system manager
manager = RBACSystemManager(
    config_path='/path/to/config.yaml',
    environment='production'
)

# Initialize system
await manager.initialize_system()

# Check system health
health = await manager.get_health_check()
print(f"System healthy: {health['overall_healthy']}")

# Get system status
status = await manager.get_system_status()
print(f"System status: {status['system']['status']}")
```

### System Validation (system_validation.py)

Comprehensive system validation and health checking:

```python
from system_validation import SystemValidator

# Initialize validator
validator = SystemValidator(environment='production')

# Run complete validation
results = await validator.validate_complete_system()

print(f"Overall health: {results['overall_health']}")
print(f"Checks passed: {results['passed_checks']}/{results['total_checks']}")
print(f"Critical issues: {results['critical_issues']}")
```

## 🔧 Configuration

### Database Configuration

Create `config/database_config.yaml`:

```yaml
databases:
  primary:
    host: localhost
    port: 5432
    database: rbac_system
    username: rbac_user
    password: ${DB_PASSWORD}
    ssl:
      enabled: true
      mode: require
      cert_file: /path/to/client.crt
      key_file: /path/to/client.key
      ca_file: /path/to/ca.crt
  
  audit:
    host: localhost
    port: 5432
    database: rbac_audit
    username: audit_user
    password: ${AUDIT_DB_PASSWORD}

security:
  encryption:
    algorithm: AES-256-GCM
    key_derivation: PBKDF2
  
  audit:
    enabled: true
    retention_days: 2555  # 7 years
    real_time_monitoring: true
```

### System Configuration

Create `config/system_config.yaml`:

```yaml
system:
  name: "DoD RBAC System"
  version: "1.0.0"
  enable_caching: true
  cache_ttl: 300
  max_concurrent_requests: 1000
  health_check_interval: 30

components:
  rbac_core:
    enabled: true
    priority: 1
  database:
    enabled: true
    priority: 1
  cac_bridge:
    enabled: true
    priority: 2
  oauth_bridge:
    enabled: true
    priority: 2

security:
  emergency_access_enabled: true
  session_timeout_minutes: 60
  max_failed_attempts: 3
  lockout_duration_minutes: 15
  require_mfa_for_admin: true
  audit_all_access: true

performance:
  enable_performance_monitoring: true
  slow_request_threshold_ms: 1000
  cache_size: 10000
  connection_pool_size: 20
```

### Validation Configuration

Create `config/validation_config.yaml`:

```yaml
validation_checks:
  database_connectivity: true
  schema_integrity: true
  data_consistency: true
  security_configuration: true
  performance_benchmarks: true
  compliance_validation: true
  component_health: true
  emergency_access: true

performance_thresholds:
  max_response_time_ms: 1000
  min_cache_hit_rate: 0.7
  max_cpu_usage: 80.0
  max_memory_usage: 85.0
  min_disk_space_gb: 10.0
  max_db_connection_time_ms: 100

security_requirements:
  ssl_required: true
  audit_enabled: true
  mfa_required_for_admin: true
  session_timeout_max_minutes: 120
  password_policy_enforced: true
  failed_login_lockout: true

compliance_standards:
  nist_800_53: true
  stig_compliance: true
  dod_8500_compliance: true
  fisma_compliance: true
```

## 🔑 Authentication Integration

### CAC/PIV Integration

The system integrates with DoD Common Access Cards (CAC) and Personal Identity Verification (PIV) cards:

```python
from integrations.cac_rbac_bridge import CACRBACBridge

# Initialize CAC bridge
cac_bridge = CACRBACBridge(
    config_path='/path/to/config.yaml',
    environment='production'
)

# Authenticate user with CAC
auth_result = await cac_bridge.authenticate_user(
    certificate_data=cac_certificate,
    pin=user_pin
)

if auth_result.success:
    # Extract user roles from CAC
    user_roles = await cac_bridge.extract_user_roles(auth_result.user_id)
    print(f"User roles: {user_roles}")
```

### OAuth Integration

Support for OAuth 2.0 / OpenID Connect authentication:

```python
from integrations.oauth_rbac_bridge import OAuthRBACBridge

# Initialize OAuth bridge
oauth_bridge = OAuthRBACBridge(
    config_path='/path/to/config.yaml',
    environment='production'
)

# Validate OAuth token
token_result = await oauth_bridge.validate_token(oauth_token)

if token_result.valid:
    # Extract user information
    user_info = await oauth_bridge.get_user_info(token_result.user_id)
    print(f"User: {user_info.display_name}")
```

## 📋 Database Schema

### Core Tables

```sql
-- Users table
CREATE TABLE rbac.users (
    user_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    edipi VARCHAR(10) UNIQUE NOT NULL,
    user_principal_name VARCHAR(255) UNIQUE NOT NULL,
    common_name VARCHAR(255) NOT NULL,
    display_name VARCHAR(255),
    email_address VARCHAR(255),
    organization VARCHAR(255),
    security_clearance clearance_level_enum NOT NULL DEFAULT 'UNCLASSIFIED',
    account_status account_status_enum NOT NULL DEFAULT 'ACTIVE',
    created_timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_modified_timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Roles table
CREATE TABLE rbac.roles (
    role_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    role_name VARCHAR(100) UNIQUE NOT NULL,
    role_code VARCHAR(50) UNIQUE NOT NULL,
    description TEXT,
    role_type role_type_enum NOT NULL DEFAULT 'FUNCTIONAL',
    classification_required clearance_level_enum NOT NULL DEFAULT 'UNCLASSIFIED',
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Permissions table
CREATE TABLE rbac.permissions (
    permission_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    permission_name VARCHAR(255) NOT NULL,
    permission_code VARCHAR(100) UNIQUE NOT NULL,
    resource_type VARCHAR(100) NOT NULL,
    action VARCHAR(100) NOT NULL,
    scope VARCHAR(100) DEFAULT 'global',
    classification_required clearance_level_enum NOT NULL DEFAULT 'UNCLASSIFIED',
    risk_level risk_level_enum NOT NULL DEFAULT 'MEDIUM',
    audit_required BOOLEAN NOT NULL DEFAULT true,
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
```

### Audit Tables

```sql
-- Authentication events
CREATE TABLE rbac.auth_events (
    event_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_type VARCHAR(50) NOT NULL,
    event_result VARCHAR(20) NOT NULL,
    user_id UUID,
    session_id UUID,
    client_ip_address INET,
    user_agent TEXT,
    event_timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    security_classification clearance_level_enum NOT NULL DEFAULT 'UNCLASSIFIED',
    additional_data JSONB
);

-- Authorization events  
CREATE TABLE rbac.authz_events (
    event_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL,
    resource_type VARCHAR(100) NOT NULL,
    resource_id VARCHAR(255) NOT NULL,
    action VARCHAR(100) NOT NULL,
    decision VARCHAR(20) NOT NULL,
    reason TEXT,
    session_id UUID,
    client_ip_address INET,
    event_timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    security_classification clearance_level_enum NOT NULL DEFAULT 'UNCLASSIFIED',
    policy_data JSONB
);
```

## 🔍 Monitoring and Observability

### Health Checks

The system provides comprehensive health monitoring:

```python
# System health check
health = await manager.get_health_check()

# Sample response
{
    "overall_healthy": true,
    "system_status": "healthy",
    "timestamp": "2025-07-29T10:30:00Z",
    "components": {
        "database": {
            "healthy": true,
            "response_time_ms": 25.4,
            "details": {"connections": 15, "pool_size": 20}
        },
        "rbac_core": {
            "healthy": true,
            "response_time_ms": 12.1,
            "details": {"cache_hit_rate": 0.85, "active_sessions": 142}
        }
    },
    "uptime_seconds": 86400
}
```

### Performance Metrics

```python
# Get performance metrics
metrics = await manager.get_system_status()

# Sample metrics
{
    "system": {
        "status": "healthy",
        "uptime_seconds": 86400,
        "total_requests": 15432,
        "successful_requests": 15380,
        "failed_requests": 52,
        "average_response_time_ms": 45.2,
        "cache_hit_rate": 0.87
    },
    "components": {
        "rbac_core": {"status": "active"},
        "database": {"status": "active"},
        "cac_bridge": {"status": "active"}
    }
}
```

## 🛡️ Security Considerations

### Classification Handling

The system handles multiple classification levels:

```python
# Classification levels in order of sensitivity
CLASSIFICATION_LEVELS = {
    "UNCLASSIFIED": 0,
    "CONFIDENTIAL": 1, 
    "SECRET": 2,
    "TOP_SECRET": 3
}

# Access control rule: no read up
# User with SECRET clearance cannot access TOP_SECRET data
# User with TOP_SECRET clearance can access all lower classifications
```

### Audit Requirements

All security-relevant events are logged:

- Authentication attempts (successful and failed)
- Authorization decisions
- Administrative actions
- Configuration changes
- Emergency access requests
- System events and errors

### Emergency Access

Controlled emergency access procedures:

```python
# Request emergency access
emergency_request = AccessRequest(
    user_id="emergency_user",
    resource_id="critical_system",
    resource_type="system",
    action="admin",
    context={
        "emergency_justification": "Critical system maintenance required",
        "emergency_level": "critical",
        "approver_required": True
    },
    emergency_access=True
)

response = await rbac.check_access(emergency_request)
# Response includes emergency session ID and approval workflow
```

## 📈 Performance Optimization

### Caching Strategy

The system implements multi-level caching:

1. **Permission Cache**: User permissions cached by role
2. **Role Cache**: Role definitions and hierarchies
3. **Session Cache**: Active session information
4. **Policy Cache**: Compiled ABAC policies

### Database Optimization

- Proper indexing on frequently queried columns
- Connection pooling for database connections
- Read replicas for audit queries
- Partitioning for large audit tables

### Monitoring Thresholds

Default performance thresholds:

```yaml
performance_thresholds:
  max_response_time_ms: 1000      # Maximum response time
  min_cache_hit_rate: 0.7         # Minimum cache efficiency
  max_cpu_usage: 80.0             # Maximum CPU utilization
  max_memory_usage: 85.0          # Maximum memory usage
  min_disk_space_gb: 10.0         # Minimum free disk space
  max_db_connection_time_ms: 100  # Maximum DB connection time
```

## 🔄 Deployment

### Environment-Specific Deployment

The system supports multiple deployment environments:

```bash
# Development deployment
python rbac_system_manager.py --environment development

# Staging deployment  
python rbac_system_manager.py --environment staging

# Production deployment
python rbac_system_manager.py --environment production

# NIPR deployment
python rbac_system_manager.py --environment nipr

# SIPR deployment
python rbac_system_manager.py --environment sipr
```

### Docker Deployment

```dockerfile
FROM python:3.9-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

EXPOSE 8080
CMD ["python", "-m", "rbac_system_manager", "--environment", "production"]
```

### Kubernetes Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: rbac-system
spec:
  replicas: 3
  selector:
    matchLabels:
      app: rbac-system
  template:
    metadata:
      labels:
        app: rbac-system
    spec:
      containers:
      - name: rbac-system
        image: rbac-system:1.0.0
        ports:
        - containerPort: 8080
        env:
        - name: DB_PASSWORD
          valueFrom:
            secretKeyRef:
              name: rbac-secrets
              key: db-password
        resources:
          requests:
            memory: "512Mi"
            cpu: "250m"
          limits:
            memory: "1Gi"
            cpu: "500m"
```

## 🧪 Testing

### Unit Tests

```bash
# Run unit tests
python -m pytest tests/unit/

# Run with coverage
python -m pytest tests/unit/ --cov=rbac --cov-report=html
```

### Integration Tests

```bash
# Run integration tests
python -m pytest tests/integration/

# Run specific test categories
python -m pytest tests/integration/test_cac_integration.py
python -m pytest tests/integration/test_oauth_integration.py
```

### Security Tests

```bash
# Run security validation tests
python -m pytest tests/security/

# Run compliance tests
python -m pytest tests/compliance/
```

### Performance Tests

```bash
# Run performance benchmarks
python -m pytest tests/performance/

# Load testing
python tests/performance/load_test.py --users 100 --duration 300
```

## 📚 API Reference

### Core Access Control API

```python
class RBACSystem:
    async def check_access(self, request: AccessRequest) -> AccessResponse:
        """
        Perform comprehensive access control check.
        
        Args:
            request: Access request with full context
            
        Returns:
            AccessResponse with decision and audit trail
        """
```

### System Management API

```python
class RBACSystemManager:
    async def initialize_system(self, force_reinit: bool = False) -> bool:
        """Initialize the complete RBAC system."""
        
    async def check_access(self, user_id: str, resource_id: str, 
                          resource_type: str, action: str, **kwargs) -> AccessResponse:
        """Unified access control check."""
        
    async def get_system_status(self) -> Dict[str, Any]:
        """Get comprehensive system status."""
        
    async def get_health_check(self) -> Dict[str, Any]:
        """Perform comprehensive health check."""
        
    async def shutdown_system(self, graceful: bool = True, timeout: int = 30) -> bool:
        """Shutdown the RBAC system."""
```

### Validation API

```python
class SystemValidator:
    async def validate_complete_system(self, generate_report: bool = True) -> Dict[str, Any]:
        """Perform comprehensive system validation."""
        
    def get_latest_report(self) -> Optional[SystemValidationReport]:
        """Get the latest validation report."""
        
    def health_check(self) -> Dict[str, Any]:
        """Quick health check of the validator."""
```

## 🐛 Troubleshooting

### Common Issues

#### Database Connection Issues

```bash
# Check database connectivity
python -c "from db_utils import DatabaseConnection; from models.base import DatabaseConfiguration; conn = DatabaseConnection(DatabaseConfiguration(), 'primary'); print(conn.health_check())"

# Verify SSL configuration
openssl s_client -connect database_host:5432 -servername database_host
```

#### Authentication Issues

```bash
# Test CAC authentication
python -c "from integrations.cac_rbac_bridge import CACRBACBridge; bridge = CACRBACBridge(); print('CAC bridge initialized')"

# Verify OAuth configuration
python -c "from integrations.oauth_rbac_bridge import OAuthRBACBridge; bridge = OAuthRBACBridge(); print('OAuth bridge initialized')"
```

#### Performance Issues

```bash
# Run performance validation
python system_validation.py --environment production --performance-only

# Check system resources
python -c "import psutil; print(f'CPU: {psutil.cpu_percent()}%, Memory: {psutil.virtual_memory().percent}%')"
```

### Logging

Log files are stored in `/var/log/rbac/`:

- `system_manager_production.log` - System manager logs
- `audit_production.log` - Security audit logs
- `database.log` - Database operation logs
- `validation.log` - System validation logs

### Debug Mode

Enable debug logging:

```bash
export LOG_LEVEL=DEBUG
python rbac_system_manager.py --environment development
```

## 📜 Compliance Documentation

### NIST 800-53 Controls

The system implements the following NIST 800-53 controls:

- **AC-2**: Account Management
- **AC-3**: Access Enforcement  
- **AC-6**: Least Privilege
- **AU-2**: Audit Events
- **AU-3**: Content of Audit Records
- **AU-12**: Audit Generation
- **IA-2**: Identification and Authentication
- **IA-5**: Authenticator Management
- **SC-8**: Transmission Confidentiality and Integrity

### STIG Compliance

Security Technical Implementation Guide (STIG) compliance includes:

- Database security configurations
- Network security requirements
- Application security controls
- Audit and accountability measures

### DoD 8500 Series

DoD Information Assurance implementation covers:

- Information categorization
- Security control selection
- Implementation guidance
- Assessment procedures

## 📋 Maintenance

### Regular Maintenance Tasks

```bash
# Database maintenance
python maintenance/db_maintenance.py --cleanup-audit-logs --vacuum-tables

# Cache maintenance  
python maintenance/cache_maintenance.py --clear-expired --optimize

# Security updates
python maintenance/security_updates.py --check-certificates --update-policies
```

### Backup Procedures

```bash
# Database backup
pg_dump -h $DB_HOST -U $DB_USER -d $DB_NAME > rbac_backup_$(date +%Y%m%d).sql

# Configuration backup
tar -czf config_backup_$(date +%Y%m%d).tar.gz config/

# Audit log backup
tar -czf audit_backup_$(date +%Y%m%d).tar.gz /var/log/rbac/
```

### Update Procedures

```bash
# Update system components
git pull origin main

# Run database migrations
python init_database.py --environment production --migrate-only

# Restart system gracefully
systemctl reload rbac-system
```

## 🤝 Contributing

### Development Setup

```bash
# Clone repository
git clone <repository-url>
cd security-compliance/rbac

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
# venv\Scripts\activate     # Windows

# Install development dependencies
pip install -r requirements-dev.txt

# Run pre-commit hooks
pre-commit install
```

### Code Standards

- Follow PEP 8 style guidelines
- Include comprehensive docstrings
- Add unit tests for new functionality
- Update documentation for changes
- Follow security coding practices

### Security Review Process

All code changes must undergo security review:

1. Automated security scanning
2. Peer code review
3. Security team approval
4. Compliance validation

## 📞 Support

### Internal Support

- **Security Team**: security-team@organization.mil
- **Development Team**: dev-team@organization.mil  
- **System Administrators**: sysadmin@organization.mil

### Documentation

- **System Architecture**: `docs/architecture.md`
- **API Documentation**: `docs/api.md`
- **Deployment Guide**: `docs/deployment.md`
- **Security Guide**: `docs/security.md`

### Issue Reporting

Report security issues through official channels:

1. Internal security reporting system
2. Chain of command notification
3. Incident response procedures
4. Documentation and remediation

---

**Classification**: UNCLASSIFIED//CUI  
**Distribution**: Authorized Personnel Only  
**Last Updated**: 2025-07-29  
**Document Version**: 1.0.0