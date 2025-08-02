# Advana CAC/PIV Integration Guide

## Overview

This guide provides comprehensive instructions for integrating CAC/PIV authentication with the CDAO Advana platform. The integration enables secure, certificate-based authentication for DoD users accessing Advana's data analytics capabilities.

## Prerequisites

### System Requirements
- Python 3.11+
- OpenSC PKCS#11 library
- Smart card reader (for hardware CAC cards)
- Network access to Advana platform
- Valid DoD PKI certificates

### Software Dependencies
```bash
pip install PyKCS11 cryptography requests pyyaml
```

### Configuration Requirements
- Advana tenant ID
- Environment configuration (dev/test/prod)
- Classification level clearance
- Network access credentials

## Quick Start

### 1. Basic Configuration

Create an Advana platform configuration:

```python
from security_compliance.auth.platform_adapters import PlatformConfig
from security_compliance.auth.platform_adapters import AdvanaAuthAdapter

# Configure Advana connection
config = PlatformConfig(
    platform_name="advana",
    base_url="https://advana.data.mil",
    api_version="v1",
    authentication_endpoint="/api/v1/auth/cac",
    token_endpoint="/api/v1/auth/token",
    user_info_endpoint="/api/v1/user/profile",
    timeout=30,
    max_retries=3,
    verify_ssl=True,
    additional_config={
        "tenant_id": "your-tenant-id",
        "environment": "prod",
        "classification_level": "UNCLASSIFIED"
    }
)

# Initialize adapter
adapter = AdvanaAuthAdapter(config)
```

### 2. Authentication Flow

```python
import base64
from security_compliance.auth.cac_piv_integration import CACAuthenticationManager

# Initialize authentication manager
auth_manager = CACAuthenticationManager()

# Authenticate user (PIN would come from secure input)
credentials = auth_manager.authenticate_user("user_pin")

if credentials:
    print(f"Authentication successful for EDIPI: {credentials.edipi}")
    
    # Get certificate data for Advana
    certificate_data = credentials.certificate.public_bytes(serialization.Encoding.DER)
    
    # Generate challenge and sign it
    challenge = adapter._generate_challenge()
    signature = auth_manager.authenticator.sign_data(challenge)
    
    # Authenticate with Advana
    result = adapter.authenticate_with_cac(
        certificate_data=certificate_data,
        signature=signature,
        challenge=challenge,
        additional_params={
            "tenant_id": "your-tenant-id"
        }
    )
    
    if result.status == AuthenticationStatus.SUCCESS:
        print(f"Advana authentication successful!")
        print(f"Session token: {result.session_token}")
        print(f"User roles: {result.roles}")
        
        # Use the session for Advana API calls
        user_info = adapter.get_user_info(result.session_token)
        print(f"User info: {user_info}")
    else:
        print(f"Authentication failed: {result.error_message}")
```

## Platform-Specific Features

### Advana Dataset Access

```python
# Get available datasets
datasets = adapter.get_advana_datasets(
    session_token=result.session_token,
    classification_level="UNCLASSIFIED"
)

for dataset in datasets:
    print(f"Dataset: {dataset['name']} - {dataset['description']}")
```

### Query Creation

```python
# Create a new query in Advana
query_config = {
    "name": "Sample Analysis Query",
    "description": "Analysis of operational data",
    "sql": "SELECT * FROM operational_data WHERE date >= '2024-01-01'",
    "classification": "UNCLASSIFIED",
    "output_format": "csv"
}

query_id = adapter.create_advana_query(
    session_token=result.session_token,
    query_config=query_config
)

if query_id:
    print(f"Query created with ID: {query_id}")
```

## Advanced Configuration

### Environment-Specific Settings

```python
# Development environment
dev_config = config.copy()
dev_config.base_url = "https://advana-dev.data.mil"
dev_config.verify_ssl = False
dev_config.additional_config["environment"] = "dev"

# Production environment with enhanced security
prod_config = config.copy()
prod_config.additional_config.update({
    "environment": "prod",
    "classification_level": "SECRET",
    "enable_audit_logging": True,
    "session_timeout": 7200  # 2 hours
})
```

### Multi-Tenant Configuration

```python
# Configure for multiple tenants
tenant_configs = {
    "army": {
        "tenant_id": "army-tenant-id",
        "classification_level": "SECRET",
        "custom_endpoints": {
            "auth": "/army/api/v1/auth/cac"
        }
    },
    "navy": {
        "tenant_id": "navy-tenant-id", 
        "classification_level": "UNCLASSIFIED",
        "custom_endpoints": {
            "auth": "/navy/api/v1/auth/cac"
        }
    }
}

# Initialize adapters for each tenant
adapters = {}
for tenant, tenant_config in tenant_configs.items():
    config.additional_config.update(tenant_config)
    adapters[tenant] = AdvanaAuthAdapter(config)
```

## API Integration

### RESTful API Usage

```python
import requests

# Using the REST API directly
api_base_url = "http://localhost:8001"

# Generate challenge
challenge_response = requests.post(f"{api_base_url}/api/v1/auth/challenge", 
                                  json={"platform": "advana"})
challenge_data = challenge_response.json()

# Authenticate
auth_request = {
    "certificate_data": base64.b64encode(certificate_data).decode(),
    "signature": base64.b64encode(signature).decode(), 
    "challenge": challenge_data["challenge"],
    "platform": "advana",
    "environment": "production",
    "additional_params": {
        "tenant_id": "your-tenant-id"
    }
}

auth_response = requests.post(f"{api_base_url}/api/v1/auth/authenticate",
                             json=auth_request)
auth_result = auth_response.json()

if auth_result["status"] == "success":
    session_token = auth_result["session_token"]
    
    # Use session token for subsequent requests
    headers = {"Authorization": f"Bearer {session_token}"}
    
    # Get user info
    user_response = requests.post(f"{api_base_url}/api/v1/user/info",
                                 json={"session_token": session_token, "platform": "advana"},
                                 headers=headers)
```

## Security Considerations

### Certificate Validation

```python
# Enhanced certificate validation
validation_config = {
    "require_certificate_validation": True,
    "enable_revocation_checking": True,
    "allowed_certificate_authorities": [
        "DoD Root CA 3",
        "DoD Root CA 4"
    ],
    "minimum_key_size": 2048
}

# Apply validation configuration
adapter.config.additional_config.update(validation_config)
```

### Session Management

```python
# Configure session security
session_config = {
    "session_timeout": 3600,  # 1 hour
    "max_concurrent_sessions": 1,
    "require_session_refresh": True,
    "session_encryption": True
}

# Implement session refresh
def refresh_session_if_needed(adapter, session_token):
    if not adapter.validate_session(session_token):
        refresh_result = adapter.refresh_token(session_token)
        if refresh_result.status == AuthenticationStatus.SUCCESS:
            return refresh_result.session_token
        else:
            # Re-authentication required
            return None
    return session_token
```

## Error Handling

### Common Error Scenarios

```python
from security_compliance.auth.platform_adapters import AuthenticationStatus

def handle_auth_result(result):
    if result.status == AuthenticationStatus.SUCCESS:
        return result.session_token
    elif result.status == AuthenticationStatus.INVALID_CERTIFICATE:
        print("Certificate validation failed. Check certificate validity.")
        return None
    elif result.status == AuthenticationStatus.NETWORK_ERROR:
        print("Network error. Check Advana connectivity.")
        return None
    elif result.status == AuthenticationStatus.EXPIRED:
        print("Session expired. Re-authentication required.")
        return None
    else:
        print(f"Authentication failed: {result.error_message}")
        return None
```

### Retry Logic

```python
import time
from functools import wraps

def retry_auth(max_retries=3, delay=1):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            for attempt in range(max_retries):
                try:
                    result = func(*args, **kwargs)
                    if result.status == AuthenticationStatus.SUCCESS:
                        return result
                    elif result.status == AuthenticationStatus.NETWORK_ERROR:
                        if attempt < max_retries - 1:
                            time.sleep(delay * (2 ** attempt))  # Exponential backoff
                            continue
                    return result
                except Exception as e:
                    if attempt < max_retries - 1:
                        time.sleep(delay)
                        continue
                    raise
            return result
        return wrapper
    return decorator

@retry_auth(max_retries=3, delay=2)
def authenticate_with_retry(adapter, *args, **kwargs):
    return adapter.authenticate_with_cac(*args, **kwargs)
```

## Monitoring and Logging

### Audit Logging

```python
from security_compliance.auth.security_managers import AuditLogger

# Configure audit logging
audit_logger = AuditLogger.instance()

# Log authentication events
audit_logger.log_authentication_attempt(
    user_id=credentials.edipi,
    platform="advana",
    success=True,
    additional_details={
        "tenant_id": "your-tenant-id",
        "classification_level": "UNCLASSIFIED",
        "session_duration": 3600
    }
)
```

### Health Monitoring

```python
def check_advana_health(adapter):
    """Check Advana platform health"""
    try:
        platform_info = adapter.get_platform_info()
        return {
            "status": "healthy",
            "platform": platform_info["platform_name"],
            "api_version": platform_info["api_version"],
            "supports_cac": platform_info["supports_cac"],
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
    except Exception as e:
        return {
            "status": "unhealthy",
            "error": str(e),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
```

## Troubleshooting

### Common Issues

1. **Certificate Not Found**
   ```python
   # Check smart card connection
   slots = auth_manager.authenticator.get_available_slots()
   if not slots:
       print("No smart cards detected. Check card reader connection.")
   ```

2. **Authentication Timeout**
   ```python
   # Increase timeout for slow networks
   config.timeout = 60
   config.max_retries = 5
   ```

3. **Invalid Tenant ID**
   ```python
   # Verify tenant configuration
   if "tenant_id" not in config.additional_config:
       raise ValueError("Tenant ID is required for Advana authentication")
   ```

4. **Classification Level Mismatch**
   ```python
   # Check user clearance vs. data classification
   user_clearance = credentials.clearance_level
   data_classification = "SECRET"
   
   if not is_clearance_sufficient(user_clearance, data_classification):
       raise ValueError(f"Insufficient clearance: {user_clearance} < {data_classification}")
   ```

## Testing

### Unit Tests

```python
import unittest
from unittest.mock import Mock, patch

class TestAdvanaIntegration(unittest.TestCase):
    def setUp(self):
        self.config = PlatformConfig(
            platform_name="advana",
            base_url="https://test.advana.mil",
            api_version="v1",
            verify_ssl=False
        )
        self.adapter = AdvanaAuthAdapter(self.config)
    
    @patch('requests.Session.request')
    def test_successful_authentication(self, mock_request):
        mock_response = Mock()
        mock_response.json.return_value = {
            "status": "success",
            "access_token": "test_token"
        }
        mock_request.return_value = mock_response
        
        # Test authentication logic
        # ... implementation
```

### Integration Tests

```python
# Run integration tests against test environment
def test_advana_integration():
    """Test complete Advana integration flow"""
    # Use test certificates and test Advana environment
    # ... implementation
```

## Best Practices

1. **Security**
   - Always validate certificates against DoD CAs
   - Use HTTPS in production
   - Implement proper session management
   - Enable audit logging

2. **Performance**
   - Cache platform configurations
   - Implement connection pooling
   - Use appropriate timeouts
   - Handle rate limiting

3. **Reliability**
   - Implement retry logic
   - Monitor authentication health
   - Handle network failures gracefully
   - Log all authentication events

4. **Compliance**
   - Follow DoD security guidelines
   - Implement proper data classification handling
   - Maintain audit trails
   - Regular security assessments

## Support

For additional support:
- Check Advana platform documentation
- Review DoD PKI certificate guidelines
- Contact system administrators for tenant-specific configuration
- Refer to security compliance documentation