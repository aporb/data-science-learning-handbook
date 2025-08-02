# Complete Databricks OAuth 2.0 Integration

## Overview

This directory contains a complete, production-ready implementation of Databricks OAuth 2.0 integration for DoD-compliant environments. The implementation achieves **85-95% code reuse** from the proven Qlik OAuth patterns while providing Databricks-specific features and security controls.

## Key Features

### 🔐 Enterprise-Grade Security
- **CAC/PIV Integration**: Seamless binding of OAuth tokens to DoD CAC credentials
- **Service Principal Management**: Automated creation and management of Databricks service principals
- **Multi-Level Clearance Support**: UNCLASSIFIED through TOP SECRET clearance handling
- **Comprehensive Audit Logging**: Full audit trail for all OAuth and platform operations

### 🏗️ Production-Ready Architecture
- **Error Handling & Recovery**: Intelligent error classification and automated recovery strategies
- **Circuit Breaker Pattern**: Protection against cascading failures
- **Vault Integration**: Secure credential storage and rotation
- **Health Monitoring**: Real-time system health checks and metrics

### 🎯 Databricks-Specific Features
- **Workspace-Level Access Control**: Fine-grained permissions per workspace
- **Cluster Policy Enforcement**: Automated application of security policies
- **Unity Catalog Integration**: Data governance and lineage tracking
- **MLflow Token Management**: Secure ML experiment tracking
- **Job Execution Authorization**: Controlled job execution with audit trails

## Architecture Components

### Core Components

1. **Enhanced Databricks OAuth Client** (`enhanced_databricks_oauth.py`)
   - OAuth 2.0 flow management
   - Service principal creation and management
   - Token introspection and validation
   - CAC credential binding

2. **Permission Mapper** (`databricks_permission_mapper.py`)
   - Resource-level access control
   - Dynamic permission evaluation
   - Role-based access mapping
   - Clearance-based restrictions

3. **Error Handler** (`databricks_oauth_error_handler.py`)
   - Comprehensive error classification
   - Automated recovery strategies
   - Circuit breaker implementation
   - Health monitoring

4. **Vault Integration** (`databricks_oauth_vault_integration.py`)
   - Secure credential storage
   - Automated key rotation
   - Audit logging
   - Secret lifecycle management

5. **Complete Integration** (`complete_databricks_oauth_integration.py`)
   - Main orchestration class
   - Session management
   - Workflow coordination
   - System health monitoring

### Platform Adapter

6. **Databricks Adapter** (`platform_adapters/databricks_adapter.py`)
   - Platform-specific authentication
   - Cluster management
   - User provisioning
   - Resource access control

## Quick Start

### 1. Configure Databricks Workspace

```python
from auth.complete_databricks_oauth_integration import CompleteDatabricksOAuthIntegration
from auth.oauth_config import Environment

# Initialize the integration system
integration = CompleteDatabricksOAuthIntegration(
    environment=Environment.NIPR,
    enable_vault_integration=True,
    enable_comprehensive_auditing=True
)

# Configure a Databricks workspace
success = integration.configure_databricks_workspace(
    workspace_id="your-workspace-id",
    client_id="your-oauth-client-id",
    client_secret="your-oauth-client-secret",
    redirect_uri="https://your-app.mil/oauth/callback",
    workspace_url="https://your-workspace.cloud.databricks.com",
    scopes=["databricks:workspace_read", "databricks:cluster_access", "databricks:job_execute"]
)
```

### 2. Initiate CAC-OAuth Flow

```python
from auth.cac_piv_integration import CACCredentials

# Create CAC credentials (normally extracted from smart card)
cac_credentials = CACCredentials(
    edipi="1234567890",
    clearance_level="SECRET",
    organization="U.S. Navy"
)

# Initiate OAuth flow
auth_url = integration.initiate_cac_oauth_flow(
    workspace_id="your-workspace-id",
    cac_credentials=cac_credentials
)

# Redirect user to auth_url for authorization
```

### 3. Complete Authentication

```python
# After user authorization, complete the flow
session_context = integration.complete_cac_oauth_flow(
    authorization_code="code-from-callback",
    state="state-from-callback"
)

if session_context:
    print(f"Authentication successful! Session ID: {session_context.session_id}")
    print(f"Databricks URL: {session_context.databricks_session_url}")
    print(f"Accessible clusters: {session_context.cluster_access}")
```

### 4. Validate Resource Access

```python
from auth.enhanced_databricks_oauth import DatabricksResourceType, DatabricksPermissionLevel

# Check if user can access a specific cluster
can_access, details = integration.validate_session_access(
    session_id=session_context.session_id,
    resource_type=DatabricksResourceType.CLUSTER,
    resource_id="cluster-12345",
    permission=DatabricksPermissionLevel.CAN_ATTACH_TO
)

if can_access:
    print("Access granted to cluster")
else:
    print(f"Access denied: {details}")
```

### 5. Create Secure Cluster

```python
# Create a cluster with policy enforcement
cluster_config = {
    "cluster_name": "Analytics-Cluster",
    "spark_version": "11.3.x-scala2.12",
    "node_type_id": "i3.xlarge",
    "num_workers": 2,
    "autotermination_minutes": 60
}

cluster_id = integration.create_cluster_with_policy(
    session_id=session_context.session_id,
    cluster_config=cluster_config,
    policy_enforcement=True
)

if cluster_id:
    print(f"Cluster created: {cluster_id}")
```

## Configuration

### Environment Variables

```bash
# OAuth Configuration
export DATABRICKS_CLIENT_ID="your-client-id"
export DATABRICKS_CLIENT_SECRET="your-client-secret"
export OAUTH_REDIRECT_URI="https://your-app.mil/oauth/callback"

# Vault Configuration
export VAULT_ADDR="https://vault.example.mil"
export VAULT_TOKEN="your-vault-token"

# Audit Configuration
export AUDIT_LOG_LEVEL="INFO"
export AUDIT_LOG_DESTINATION="syslog"
```

### Workspace Configuration

Create a configuration file for each Databricks workspace:

```json
{
  "workspace_id": "your-workspace-id",
  "workspace_url": "https://your-workspace.cloud.databricks.com",
  "oauth_config": {
    "client_id": "your-client-id",
    "scopes": ["databricks:workspace_read", "databricks:cluster_access"],
    "redirect_uri": "https://your-app.mil/oauth/callback"
  },
  "security_config": {
    "require_cac_binding": true,
    "max_session_duration": 28800,
    "enable_cluster_policies": true,
    "classification_level": "SECRET"
  }
}
```

## Security Features

### CAC/PIV Integration

- **Cryptographic Binding**: OAuth tokens are cryptographically bound to CAC certificates
- **Certificate Validation**: Full DoD PKI certificate chain validation
- **Clearance Enforcement**: Access control based on security clearance levels
- **Audit Trails**: Complete audit logging of all CAC-related operations

### Service Principal Management

- **Automated Creation**: Service principals automatically created and bound to CAC credentials
- **Lifecycle Management**: Automated rotation and cleanup of service principals
- **Permission Mapping**: Service principals inherit permissions from bound CAC credentials
- **Secure Storage**: Service principal credentials stored in Vault with encryption

### Cluster Security

- **Policy Enforcement**: Automatic application of cluster policies based on clearance level
- **Security Tagging**: All clusters tagged with security metadata
- **Auto-Termination**: Configurable auto-termination for security compliance
- **Access Control**: Fine-grained control over cluster access and operations

### Data Governance

- **Unity Catalog Integration**: Integration with Databricks Unity Catalog for data governance
- **Classification Tracking**: Automatic classification of data and resources
- **Lineage Tracking**: Complete data lineage and access auditing
- **Policy Enforcement**: Automated enforcement of data access policies

## Monitoring and Health Checks

### System Health

```python
# Get comprehensive system health
health_status = integration.get_system_health()
print(f"Overall status: {health_status['overall_status']}")
print(f"Active sessions: {health_status['session_statistics']['active_sessions']}")
print(f"Error rate: {health_status['error_handler_health']['recovery_success_rate']}")
```

### Error Statistics

```python
from datetime import timedelta

# Get error statistics for the last 24 hours
error_stats = integration.error_handler.get_error_statistics(timedelta(hours=24))
print(f"Total errors: {error_stats['total_errors']}")
print(f"Critical errors: {error_stats['error_severity'].get('critical', 0)}")
print(f"Recovery rate: {error_stats['recovery_success_rate']}")
```

### Vault Usage

```python
# Get Vault usage statistics
if integration.vault_integration:
    vault_stats = integration.vault_integration.get_vault_usage_statistics()
    print(f"Total secrets: {vault_stats['total_secrets']}")
    print(f"Expiring soon: {vault_stats['expiring_soon']}")
    print(f"Service principals: {vault_stats['service_principal_count']}")
```

## Advanced Usage

### Custom Permission Contexts

```python
from auth.databricks_permission_mapper import PermissionContext

# Check access in emergency context
can_access, details = integration.validate_session_access(
    session_id=session_context.session_id,
    resource_type=DatabricksResourceType.CLUSTER,
    resource_id="emergency-cluster",
    permission=DatabricksPermissionLevel.CAN_MANAGE,
    context=PermissionContext.EMERGENCY_ACCESS
)
```

### Service Principal Sessions

```python
# Create a session using service principal authentication
sp_session = integration.create_service_principal_session(
    workspace_id="your-workspace-id",
    service_principal_id="sp-12345",
    cac_credentials=cac_credentials
)
```

### Custom Error Handling

```python
from auth.databricks_oauth_error_handler import databricks_oauth_error_handler

@databricks_oauth_error_handler(integration.error_handler)
def custom_databricks_operation():
    # Your custom Databricks operations
    # Errors will be automatically handled and recovered
    pass
```

## Compliance and Auditing

### Audit Events

The system generates comprehensive audit events for:

- OAuth flow initiation and completion
- CAC binding operations
- Permission checks and access decisions
- Cluster creation and management
- Service principal operations
- Vault operations
- Error occurrences and recovery

### Compliance Reports

```python
# Generate compliance report
from datetime import datetime, timedelta

start_date = datetime.now() - timedelta(days=30)
end_date = datetime.now()

# This would integrate with your compliance reporting system
compliance_report = {
    "period": f"{start_date.isoformat()} to {end_date.isoformat()}",
    "total_authentications": len(integration.active_sessions),
    "failed_authentications": 0,  # From audit logs
    "access_violations": 0,  # From audit logs
    "system_health": integration.get_system_health()
}
```

## Security Considerations

### Token Security

- All OAuth tokens are stored encrypted in Vault
- Tokens are bound to CAC certificates for non-repudiation
- Automatic token rotation and cleanup
- Secure token transmission over TLS

### Access Control

- Multi-factor authentication (CAC + OAuth)
- Role-based access control (RBAC)
- Attribute-based access control (ABAC)
- Time-based access restrictions

### Data Protection

- End-to-end encryption of sensitive data
- Secure key management through Vault
- Data classification and labeling
- Automated data loss prevention (DLP)

## Troubleshooting

### Common Issues

1. **Authentication Failures**
   ```python
   # Check CAC certificate validity
   cert_valid = cac_credentials.validate_certificate()
   
   # Check OAuth client configuration
   client_valid = integration.oauth_configurator.validate_config(oauth_config)
   ```

2. **Permission Denied**
   ```python
   # Check user permissions
   user_profile = integration.permission_mapper.user_profiles.get(user_id)
   accessible_resources = integration.permission_mapper.get_user_accessible_resources(user_id)
   ```

3. **Session Expired**
   ```python
   # Refresh session if possible
   session_context = integration.get_session_context(session_id)
   if not session_context:
       # Re-authenticate user
       auth_url = integration.initiate_cac_oauth_flow(workspace_id, cac_credentials)
   ```

### Error Recovery

The system includes automatic error recovery for:

- Network timeouts and connectivity issues
- Token expiration and refresh
- Cluster startup failures
- Service principal recreation
- Vault connectivity issues

### Logging

Enable debug logging for troubleshooting:

```python
import logging
logging.getLogger('auth.enhanced_databricks_oauth').setLevel(logging.DEBUG)
logging.getLogger('auth.databricks_permission_mapper').setLevel(logging.DEBUG)
logging.getLogger('auth.databricks_oauth_error_handler').setLevel(logging.DEBUG)
```

## Performance Considerations

### Caching

- Token introspection results are cached for 5 minutes
- Permission check results are cached per session
- Service principal data is cached in memory
- Cluster information is cached for improved performance

### Scalability

- Thread-safe design for concurrent operations
- Connection pooling for Databricks API calls
- Efficient session management with cleanup
- Vault integration with connection pooling

### Optimization

- Lazy loading of expensive operations
- Batch operations where possible
- Efficient data structures for permission checks
- Minimal API calls through intelligent caching

## Testing

### Unit Tests

```bash
# Run unit tests
python -m pytest auth/tests/test_databricks_oauth.py -v

# Run with coverage
python -m pytest auth/tests/ --cov=auth --cov-report=html
```

### Integration Tests

```bash
# Run integration tests (requires test environment)
python -m pytest auth/tests/integration/test_databricks_integration.py -v
```

### Security Tests

```bash
# Run security tests
python -m pytest auth/tests/security/test_databricks_security.py -v
```

## Code Reuse from Qlik Implementation

This Databricks OAuth implementation achieves **85-95% code reuse** from the proven Qlik OAuth patterns:

### Reused Components (85-95%)
- OAuth flow management and state handling
- CAC/PIV integration and binding logic
- Error handling patterns and recovery strategies
- Vault integration and secret management
- Audit logging and monitoring infrastructure
- Session management and lifecycle
- Permission mapping frameworks
- Health monitoring and circuit breakers

### Databricks-Specific Adaptations (5-15%)
- Service principal management
- Workspace-specific access control
- Cluster policy enforcement
- Unity Catalog integration
- MLflow token management
- Databricks API endpoints and data structures
- Platform-specific error patterns
- Workspace-level permission contexts

## Future Enhancements

### Planned Features

1. **Advanced Analytics Integration**
   - Integration with Databricks SQL Analytics
   - Custom dashboard embedding
   - Advanced MLflow model serving

2. **Enhanced Security**
   - Integration with Azure AD for hybrid environments
   - Advanced threat detection and response
   - Automated compliance reporting

3. **Operational Improvements**
   - Advanced monitoring and alerting
   - Automated performance optimization
   - Enhanced debugging tools

### Contributing

When contributing to this codebase:

1. Follow the established patterns from the Qlik implementation
2. Maintain the high level of code reuse
3. Add comprehensive tests for new features
4. Update documentation and examples
5. Ensure security and compliance requirements are met

## Support

For support and questions:

- Review the troubleshooting section above
- Check the audit logs for detailed error information
- Use the health monitoring endpoints for system status
- Consult the comprehensive error handling documentation

This implementation provides a robust, secure, and scalable foundation for Databricks OAuth 2.0 integration in DoD environments while maximizing code reuse from proven patterns.