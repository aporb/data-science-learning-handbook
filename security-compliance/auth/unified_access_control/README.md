# Unified Access Control System

Enterprise-grade unified access control across CAC/PIV authentication, RBAC permissions, OAuth platform integrations, and comprehensive audit logging for DoD and enterprise environments.

## Overview

The Unified Access Control System provides comprehensive access control by integrating:

- **Existing RBAC Infrastructure** - PermissionResolver with caching, ABAC policy engine, and comprehensive audit logging
- **OAuth 2.0 Platform Integrations** - Complete OAuth client with DoD platform support (Qlik, Databricks, Advana, Navy Jupiter)
- **CAC/PIV Authentication** - Certificate-based authentication and credential validation
- **Cross-Platform Session Management** - Unified session handling with synchronized state
- **Comprehensive Audit Integration** - Unified audit logging combining RBAC decisions with platform-specific access logs
- **Vault-Based Secure Credential Management** - HashiCorp Vault integration for secure secrets

## Architecture

### Core Components

1. **UnifiedAccessController** - Central access control interface
2. **CrossPlatformPermissionResolver** - Advanced permission resolution engine  
3. **UnifiedUserContext** - Multi-platform user profile and context management
4. **PlatformSessionManager** - Cross-platform session synchronization
5. **AuditIntegrationManager** - Comprehensive audit logging across all platforms
6. **EnhancedPlatformAdapter** - Enhanced platform integration with health monitoring

### Key Features

- **Sub-50ms Access Decisions** - Intelligent caching with targeted invalidation
- **Zero-Trust Architecture** - Continuous verification across all platforms
- **Emergency Access Procedures** - Full audit trails with compliance reporting
- **Real-Time Permission Updates** - Cache invalidation and synchronization
- **Multi-Classification Support** - Bell-LaPadula enforcement with clearance verification
- **Graceful Degradation** - Failover handling and circuit breakers

## Quick Start

### Installation

```bash
# Install dependencies
pip install -r requirements.txt

# Set up database
psql -c "CREATE DATABASE unified_access_control;"
python -m alembic upgrade head
```

### Basic Configuration

```python
from unified_access_control.config import UnifiedAccessConfig, PlatformConfig, OAuthPlatformConfig

# Create configuration
config = UnifiedAccessConfig(environment="production")

# Configure platform
qlik_oauth = OAuthPlatformConfig(
    client_id="your-qlik-client-id",
    client_secret="your-qlik-client-secret",
    authorization_url="https://qlik.example.com/oauth/authorize",
    token_url="https://qlik.example.com/oauth/token",
    redirect_uri="https://app.example.com/callback",
    scopes=["qlik:read", "qlik:write"]
)

qlik_platform = PlatformConfig(
    name="qlik",
    enabled=True,
    base_url="https://qlik.example.com",
    oauth=qlik_oauth
)

config.add_platform_config(qlik_platform)
```

### Basic Usage

```python
import asyncio
from unified_access_control.controller import UnifiedAccessController, UnifiedAccessRequest

async def main():
    # Initialize controller
    controller = UnifiedAccessController(config)
    
    # Start services
    await controller.session_manager.start()
    await controller.audit_manager.start()
    
    try:
        # Create access request
        request = UnifiedAccessRequest(
            user_id=user_id,
            resource_type="dashboard",
            action="read",
            platform="qlik",
            oauth_scopes=["qlik:read"],
            session_id=session_id,
            ip_address="192.168.1.100"
        )
        
        # Check access
        response = await controller.check_access(request)
        
        if response.decision.value == "PERMIT":
            print(f"Access granted: {response.reason}")
        else:
            print(f"Access denied: {response.reason}")
            
    finally:
        await controller.shutdown()

asyncio.run(main())
```

## Configuration

### Environment Variables

```bash
# Database
export UAC_DB_HOST="localhost"
export UAC_DB_PORT="5432"
export UAC_DB_NAME="unified_access_control"
export UAC_DB_USER="postgres"
export UAC_DB_PASSWORD="password"

# Cache
export UAC_REDIS_HOST="localhost"
export UAC_REDIS_PORT="6379"

# Vault
export UAC_VAULT_URL="https://vault.example.com"
export UAC_VAULT_TOKEN="your-vault-token"

# Security
export UAC_ENABLE_CAC_PIV="true"
export UAC_ENABLE_EMERGENCY_ACCESS="true"

# Performance
export UAC_MAX_WORKER_THREADS="10"
export UAC_RESPONSE_TIME_SLA_MS="50"
```

### Configuration File

```json
{
  "database": {
    "host": "localhost",
    "port": 5432,
    "database": "unified_access_control",
    "username": "postgres",
    "password": "password",
    "ssl_mode": "require",
    "pool_size": 20
  },
  "security": {
    "enable_cac_piv": true,
    "enable_emergency_access": true,
    "session_timeout_hours": 8,
    "max_concurrent_sessions": 5
  },
  "performance": {
    "max_worker_threads": 10,
    "response_time_sla_ms": 50,
    "cache_optimization_enabled": true
  },
  "platforms": {
    "qlik": {
      "name": "qlik",
      "enabled": true,
      "base_url": "https://qlik.example.com",
      "oauth": {
        "client_id": "qlik-client-id",
        "client_secret": "qlik-client-secret",
        "authorization_url": "https://qlik.example.com/oauth/authorize",
        "token_url": "https://qlik.example.com/oauth/token",
        "redirect_uri": "https://app.example.com/callback",
        "scopes": ["qlik:read", "qlik:write"]
      }
    }
  }
}
```

## Platform Integration

### Supported Platforms

- **Qlik Sense** - Analytics platform with OAuth 2.0
- **Databricks** - Data analytics platform
- **Advana** - DoD data analytics platform
- **Navy Jupiter** - Navy's cloud analytics platform

### Adding New Platforms

```python
from unified_access_control.adapters import EnhancedPlatformAdapter

class CustomPlatformAdapter(EnhancedPlatformAdapter):
    async def _fetch_user_permissions(self, user_id):
        # Implement platform-specific permission fetching
        pass
    
    async def _fetch_available_scopes(self, user_id):
        # Implement OAuth scope fetching
        pass
    
    async def platform_health_check(self):
        # Implement health check
        return {"status": "healthy"}

# Register adapter
adapter = CustomPlatformAdapter("custom_platform", config)
controller.cross_platform_resolver.register_platform_adapter("custom_platform", adapter)
```

## Security Features

### CAC/PIV Authentication

```python
# Configure CAC/PIV
config.security.enable_cac_piv = True
config.security.require_cac_for_admin = True

# Certificate validation in requests
request = UnifiedAccessRequest(
    user_id=user_id,
    resource_type="admin",
    action="configure",
    client_certificate="-----BEGIN CERTIFICATE-----...",
    # ... other parameters
)
```

### Emergency Access

```python
# Emergency access request
emergency_request = UnifiedAccessRequest(
    user_id=user_id,
    resource_type="system",
    action="emergency_repair",
    emergency_access=True,
    additional_attributes={
        "emergency_reason": "Critical system failure - production down"
    }
)

response = await controller.check_access(emergency_request)
# Automatically audited with high priority
```

### Multi-Classification Support

```python
# Classified resource access
classified_request = UnifiedAccessRequest(
    user_id=user_id,
    resource_type="intelligence_report",
    action="read",
    classification_level="TS_SCI",  # Top Secret/SCI
    # ... other parameters
)
```

## Session Management

### Unified Sessions

```python
# Create unified session
session_id = await controller.session_manager.create_unified_session(
    user_id=user_id,
    ip_address="192.168.1.100",
    user_agent="Mozilla/5.0...",
    authentication_methods=["CAC", "PIV"]
)

# Add platform session
await controller.session_manager.add_platform_session(
    unified_session_id=session_id,
    platform="qlik",
    platform_session_id="qlik-session-123",
    oauth_token="access-token",
    oauth_expires_at=expiry_time
)
```

### Session Synchronization

```python
# Update session activity
await controller.session_manager.update_session_access(
    unified_session_id=session_id,
    platform="qlik",
    resource_type="dashboard",
    action="view"
)

# Get session information
session_info = await controller.session_manager.get_session_info(session_id)
active_platforms = session_info['active_platforms']
```

## Audit and Compliance

### Audit Logging

```python
# Access decisions are automatically audited
response = await controller.check_access(request)
# Audit event automatically created

# Manual audit events
await controller.audit_manager.log_security_violation(
    violation_type="Brute Force Attack",
    user_id=user_id,
    ip_address="192.168.1.100",
    details={"failed_attempts": 5}
)
```

### Compliance Reporting

```python
from unified_access_control.audit import ComplianceStandard

# Generate DoD compliance report
report = await controller.audit_manager.generate_compliance_report(
    standard=ComplianceStandard.DOD_8500,
    start_date=start_date,
    end_date=end_date
)
```

### Security Event Detection

```python
# Real-time security monitoring
# - Brute force attack detection
# - Privilege escalation attempts
# - Unusual access patterns
# - Emergency access abuse
# Automatically generates alerts and audit events
```

## Performance and Monitoring

### Performance Metrics

```python
# Get comprehensive metrics
metrics = controller.get_performance_metrics()

print(f"Cache hit rate: {metrics['unified_access']['cache_hit_rate']:.2%}")
print(f"Average response time: {metrics['rbac_resolver']['avg_response_time_ms']:.2f}ms")
```

### Health Monitoring

```python
# System health check
health = await controller.health_check()

if health['status'] == 'healthy':
    print("System operational")
else:
    print(f"System issues: {health['failed_components']}")
```

### Performance Tuning

```python
# Configuration for high performance
config.performance.max_worker_threads = 20
config.performance.connection_pool_size = 50
config.performance.cache_optimization_enabled = True
config.performance.response_time_sla_ms = 25  # 25ms SLA
```

## Deployment

### Docker Deployment

```dockerfile
FROM python:3.9-slim

WORKDIR /app
COPY . .
RUN pip install -r requirements.txt

EXPOSE 8080 9090
CMD ["python", "-m", "unified_access_control.server"]
```

### Kubernetes Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: unified-access-control
spec:
  replicas: 3
  selector:
    matchLabels:
      app: unified-access-control
  template:
    metadata:
      labels:
        app: unified-access-control
    spec:
      containers:
      - name: uac
        image: unified-access-control:latest
        ports:
        - containerPort: 8080
        - containerPort: 9090
        env:
        - name: UAC_DB_HOST
          value: "postgres-service"
        - name: UAC_REDIS_HOST
          value: "redis-service"
        resources:
          requests:
            cpu: 100m
            memory: 256Mi
          limits:
            cpu: 500m
            memory: 512Mi
```

## API Reference

### Core Classes

- `UnifiedAccessController` - Main access control interface
- `UnifiedAccessRequest` - Access request structure
- `UnifiedAccessResponse` - Access response with decision
- `UnifiedUserContext` - Comprehensive user context
- `PlatformSessionManager` - Session management
- `AuditIntegrationManager` - Audit logging

### Configuration Classes

- `UnifiedAccessConfig` - Main configuration
- `PlatformConfig` - Platform-specific configuration
- `SecurityConfig` - Security settings
- `PerformanceConfig` - Performance tuning

## Examples

See `examples/example_usage.py` for comprehensive usage examples including:

- System initialization
- User authentication and context building
- Cross-platform access control decisions
- Session management and synchronization
- Audit logging and compliance reporting
- Performance monitoring and health checks

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Run the test suite
6. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Security Considerations

- All secrets should be stored in HashiCorp Vault
- CAC/PIV certificates must be validated against DoD PKI
- Audit logs are tamper-proof and encrypted
- All communications use TLS 1.3
- Regular security updates and vulnerability scanning
- Compliance with DoD 8500 and NIST SP 800-53

## Support

For support and questions:

- Documentation: [Internal Wiki]
- Issues: [GitHub Issues]
- Security Issues: [Security Contact]

---

**Classification: UNCLASSIFIED//FOR OFFICIAL USE ONLY**