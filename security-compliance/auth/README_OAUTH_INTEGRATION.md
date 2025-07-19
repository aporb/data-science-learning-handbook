# OAuth 2.0 Client Implementation Framework for DoD Platforms

## Overview

This comprehensive OAuth 2.0 implementation provides secure, DoD-compliant authentication for multiple platforms including Advana, Qlik Sense, Databricks, and Navy Jupiter. The framework integrates with CAC/PIV smart card authentication and includes advanced security features required for DoD environments.

## Key Features

### Core OAuth 2.0 Capabilities
- **Complete OAuth 2.0 Implementation**: Authorization Code Flow with PKCE (RFC 7636)
- **Multiple Grant Types**: authorization_code, client_credentials, refresh_token
- **Platform Support**: Advana, Qlik Sense, Databricks, Navy Jupiter
- **Environment Support**: NIPR, SIPR, JWICS with appropriate security controls

### Security Features
- **AES-256 Token Encryption**: Secure token storage with encryption at rest
- **CAC/PIV Integration**: Smart card authentication with OAuth binding
- **PKCE Implementation**: Proof Key for Code Exchange for enhanced security
- **State Parameter Validation**: CSRF protection for OAuth flows
- **Comprehensive Audit Logging**: DoD-compliant audit trail for all operations

### Advanced Capabilities
- **Concurrent Request Management**: Rate limiting and throttling
- **Automated Token Lifecycle**: Refresh, cleanup, and revocation
- **Real-time Threat Detection**: Suspicious activity monitoring
- **Compliance Reporting**: Automated compliance and metrics reporting

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    OAuth 2.0 Framework Architecture            │
├─────────────────────────────────────────────────────────────────┤
│  Application Layer                                              │
│  ├── Web Applications                                           │
│  ├── Desktop Applications                                       │
│  └── Mobile Applications                                        │
├─────────────────────────────────────────────────────────────────┤
│  Integration Layer                                              │
│  ├── OAuth-CAC Bridge        ├── Lifecycle Manager             │
│  ├── Concurrent Manager      ├── Audit Logger                  │
│  └── Token Storage Manager   └── Compliance Checker            │
├─────────────────────────────────────────────────────────────────┤
│  Core OAuth Layer                                              │
│  ├── DoD OAuth Client        ├── OAuth Config Manager          │
│  ├── Platform Configs        ├── Security Validators           │
│  └── Token Management        └── Flow Handlers                 │
├─────────────────────────────────────────────────────────────────┤
│  Security Layer                                                │
│  ├── CAC/PIV Authentication  ├── Token Encryption              │
│  ├── Certificate Validation  ├── Audit Logging                 │
│  └── Threat Detection        └── Compliance Monitoring         │
├─────────────────────────────────────────────────────────────────┤
│  Storage Layer                                                 │
│  ├── Encrypted Token Store   ├── Audit Database               │
│  ├── Certificate Store       ├── Configuration Store          │
│  └── Metrics Database        └── Archive Storage              │
└─────────────────────────────────────────────────────────────────┘
```

## Quick Start

### 1. Basic OAuth Configuration

```python
from security_compliance.auth.oauth_config import DoD_OAuth_Configurator, Environment
from security_compliance.auth.oauth_client import DoD_OAuth_Client, Platform

# Initialize configurator for your environment
configurator = DoD_OAuth_Configurator(Environment.NIPR)

# Create platform configuration
config = configurator.create_config(
    platform=Platform.ADVANA,
    client_id="your_client_id",
    client_secret="your_client_secret",
    redirect_uri="https://your-app.com/callback",
    scopes=["openid", "profile", "advana:read"]
)

# Create OAuth client
oauth_client = DoD_OAuth_Client(config)
```

### 2. CAC-Enhanced Authentication

```python
from security_compliance.auth.oauth_cac_bridge import IntegratedAuthenticationManager

# Initialize integrated authentication
auth_manager = IntegratedAuthenticationManager(Environment.NIPR)

# Configure platforms from environment variables
auth_manager.configure_all_platforms_from_env()

# Start CAC-then-OAuth flow
result, oauth_url, state = auth_manager.start_cac_oauth_flow(
    pin="your_cac_pin",
    platform=Platform.ADVANA,
    required_clearance="SECRET"
)

if result == AuthenticationResult.SUCCESS:
    print(f"Redirect user to: {oauth_url}")
    # Handle OAuth callback to complete flow
```

### 3. Secure Token Management

```python
from security_compliance.auth.secure_token_storage import TokenStorageManager
from security_compliance.auth.token_lifecycle_manager import TokenLifecycleManager

# Get token storage manager (singleton)
token_storage = TokenStorageManager.instance()

# Create lifecycle manager for automated token management
lifecycle_manager = TokenLifecycleManager()

# Register token for lifecycle management
tracking_id = lifecycle_manager.register_token(
    user_id="user@mil.gov",
    platform=Platform.QLIK,
    token=oauth_token,
    metadata={"clearance": "SECRET", "organization": "DoD"}
)

# Token will be automatically refreshed and cleaned up
```

## Detailed Usage Examples

### Complete OAuth Authorization Code Flow

```python
import secrets
from security_compliance.auth.oauth_client import DoD_OAuth_Client, Platform
from security_compliance.auth.oauth_config import create_advana_config

# 1. Create OAuth configuration
config = create_advana_config(
    client_id="advana_client_id",
    client_secret="advana_client_secret",
    redirect_uri="https://myapp.com/oauth/callback"
)

# 2. Initialize OAuth client
with DoD_OAuth_Client(config) as oauth_client:
    
    # 3. Get authorization URL
    auth_url, state = oauth_client.get_authorization_url()
    
    print(f"Redirect user to: {auth_url}")
    print(f"Store state parameter: {state}")
    
    # 4. Handle callback (in your web application)
    # authorization_code = request.args.get('code')
    # returned_state = request.args.get('state')
    
    # 5. Validate state parameter
    # if returned_state != stored_state:
    #     raise SecurityError("Invalid state parameter")
    
    # 6. Exchange code for tokens
    # token = oauth_client.exchange_code_for_token(
    #     authorization_code, returned_state
    # )
    
    # 7. Use access token for API calls
    # api_response = requests.get(
    #     "https://advana.data.mil/api/user/profile",
    #     headers={"Authorization": f"Bearer {token.access_token}"}
    # )
```

### CAC-Integrated Authentication Flow

```python
from security_compliance.auth.oauth_cac_bridge import OAuthCACBridge, AuthenticationMode
from security_compliance.auth.cac_piv_integration import CACAuthenticationManager

# 1. Initialize components
cac_manager = CACAuthenticationManager()
oauth_bridge = OAuthCACBridge(
    environment=Environment.SIPR,
    default_mode=AuthenticationMode.DUAL_FACTOR
)

# 2. Configure OAuth platforms
oauth_bridge.configure_platform(
    platform=Platform.DATABRICKS,
    client_id="databricks_client",
    client_secret="databricks_secret",
    redirect_uri="https://myapp.mil/callback"
)

# 3. Perform CAC authentication
result, credentials = oauth_bridge.authenticate_with_cac(
    pin=input("Enter CAC PIN: "),
    platform=Platform.DATABRICKS,
    required_clearance="SECRET"
)

if result == AuthenticationResult.SUCCESS:
    print(f"CAC authentication successful for EDIPI: {credentials.effective_user_id}")
    
    # 4. Get OAuth authorization URL with CAC binding
    oauth_url, state = oauth_bridge.get_oauth_authorization_url(
        platform=Platform.DATABRICKS,
        cac_credentials=credentials.cac_credentials
    )
    
    print(f"Complete OAuth flow at: {oauth_url}")
    
    # 5. After OAuth callback, bind the tokens
    # oauth_result, final_credentials = oauth_bridge.authenticate_with_oauth(
    #     platform=Platform.DATABRICKS,
    #     authorization_code=callback_code,
    #     state=callback_state,
    #     cac_credentials=credentials.cac_credentials
    # )
```

### Advanced Token Management

```python
from security_compliance.auth.concurrent_token_manager import ConcurrentTokenManager, RateLimitConfig
from security_compliance.auth.token_lifecycle_manager import TokenLifecyclePolicy

# 1. Configure advanced rate limiting
rate_config = RateLimitConfig(
    max_requests_per_minute=30,
    max_requests_per_hour=500,
    max_concurrent_requests=5,
    platform_limits={
        "databricks": {"max_requests_per_minute": 20},
        "qlik": {"max_concurrent": 3}
    }
)

# 2. Initialize concurrent token manager
token_manager = ConcurrentTokenManager(rate_config)

# 3. Configure lifecycle management
lifecycle_policy = TokenLifecyclePolicy(
    refresh_threshold_minutes=10,
    auto_refresh_enabled=True,
    max_refresh_attempts=3,
    cleanup_delay_hours=24,
    max_token_age_days=30
)

lifecycle_manager = TokenLifecycleManager(lifecycle_policy)

# 4. Submit concurrent token requests
request_ids = []
for user in ["user1@mil.gov", "user2@mil.gov", "user3@mil.gov"]:
    request_id = token_manager.request_token_async(
        user_id=user,
        platform=Platform.QLIK,
        oauth_client=oauth_client,
        request_type="client_credentials",
        scopes=["qlik:read", "qlik:write"]
    )
    request_ids.append(request_id)

# 5. Wait for all requests to complete
tokens = []
for request_id in request_ids:
    token = token_manager.wait_for_request(request_id, timeout=30)
    if token:
        tokens.append(token)
        
        # Register for lifecycle management
        lifecycle_manager.register_token(
            user_id=token.user_id,
            platform=Platform.QLIK,
            token=token
        )

print(f"Successfully obtained {len(tokens)} tokens")
```

### Comprehensive Audit Logging

```python
from security_compliance.auth.oauth_audit_logger import EnhancedOAuthAuditLogger
from datetime import datetime, timezone, timedelta

# 1. Get audit logger instance
audit_logger = EnhancedOAuthAuditLogger.instance()

# 2. Log OAuth operations
audit_logger.log_oauth_authorization_request(
    user_id="user@mil.gov",
    platform=Platform.ADVANA,
    client_id="advana_client",
    scopes=["openid", "profile", "data:read"],
    state="secure_state_123",
    source_ip="192.168.1.100"
)

audit_logger.log_token_exchange(
    user_id="user@mil.gov",
    platform=Platform.ADVANA,
    authorization_code="auth_code_hash",
    success=True,
    token_id="token_abc123"
)

# 3. Log CAC-OAuth binding
audit_logger.log_cac_oauth_binding(
    user_id="user@mil.gov",
    edipi="1234567890",
    platform=Platform.ADVANA,
    clearance_level="SECRET",
    certificate_subject="CN=John Doe,OU=DoD",
    success=True
)

# 4. Generate compliance report
start_date = datetime.now(timezone.utc) - timedelta(days=30)
end_date = datetime.now(timezone.utc)

report = audit_logger.generate_compliance_report(start_date, end_date)
print(json.dumps(report, indent=2))
```

## Environment Configuration

### Environment Variables

Set these environment variables for each platform:

```bash
# Advana Platform
export ADVANA_CLIENT_ID="your_advana_client_id"
export ADVANA_CLIENT_SECRET="your_advana_client_secret"
export ADVANA_REDIRECT_URI="https://your-app.com/callback/advana"
export ADVANA_SCOPES="openid,profile,advana:read,advana:write"

# Qlik Platform
export QLIK_CLIENT_ID="your_qlik_client_id"
export QLIK_CLIENT_SECRET="your_qlik_client_secret"
export QLIK_REDIRECT_URI="https://your-app.com/callback/qlik"
export QLIK_SCOPES="openid,profile,qlik:read,qlik:write"

# Databricks Platform
export DATABRICKS_CLIENT_ID="your_databricks_client_id"
export DATABRICKS_CLIENT_SECRET="your_databricks_client_secret"
export DATABRICKS_REDIRECT_URI="https://your-app.com/callback/databricks"

# Navy Jupiter Platform
export NAVY_JUPITER_CLIENT_ID="your_jupiter_client_id"
export NAVY_JUPITER_CLIENT_SECRET="your_jupiter_client_secret"
export NAVY_JUPITER_REDIRECT_URI="https://your-app.com/callback/jupiter"

# Network Classification
export NETWORK_CLASSIFICATION="NIPR"  # or SIPR, JWICS

# CAC Configuration
export CAC_PKCS11_LIB_PATH="/usr/lib/opensc-pkcs11.so"
export CAC_DEBUG="false"
export CAC_OCSP_VALIDATION="true"
```

### Configuration Files

Create a configuration file for your application:

```json
{
  "oauth": {
    "environment": "NIPR",
    "default_scopes": ["openid", "profile"],
    "session_timeout": 3600,
    "enable_pkce": true,
    "require_state": true
  },
  "security": {
    "token_encryption": {
      "algorithm": "AES-256-GCM",
      "key_rotation_days": 90
    },
    "audit_logging": {
      "enable_realtime_monitoring": true,
      "threat_detection": true,
      "compliance_reporting": true
    },
    "rate_limiting": {
      "max_requests_per_minute": 60,
      "max_concurrent_requests": 10,
      "adaptive_limiting": true
    }
  },
  "platforms": {
    "advana": {
      "base_url": "https://advana.data.mil",
      "max_token_lifetime": 3600,
      "required_scopes": ["openid", "profile", "advana:read"]
    },
    "qlik": {
      "base_url": "https://qlik.advana.data.mil",
      "max_token_lifetime": 7200,
      "required_scopes": ["openid", "profile", "qlik:read"]
    }
  }
}
```

## Security Considerations

### Token Security
- **Encryption at Rest**: All tokens are encrypted using AES-256-GCM
- **Secure Storage**: Tokens stored in encrypted database with secure permissions
- **Automatic Cleanup**: Expired tokens automatically removed after configurable delay
- **Revocation Support**: Immediate token revocation capability

### CAC/PIV Integration
- **Certificate Validation**: Full DoD certificate chain validation
- **Revocation Checking**: OCSP and CRL validation support
- **PIN Security**: Secure PIN caching with encryption and timeout
- **Audit Trail**: Complete audit log of all CAC operations

### Network Security
- **TLS Required**: All communications use TLS 1.2 or higher
- **Certificate Pinning**: Optional certificate pinning for enhanced security
- **PKCE Implementation**: Proof Key for Code Exchange prevents code interception
- **State Validation**: CSRF protection through state parameter validation

### Compliance Features
- **DoD Standards**: Complies with DoD security standards and policies
- **Classification Support**: Handles UNCLASSIFIED through TOP SECRET data
- **Audit Logging**: Comprehensive audit trail for compliance reporting
- **Threat Detection**: Real-time monitoring for suspicious activities

## Error Handling

### Common Error Scenarios

```python
from security_compliance.auth.oauth_client import DoD_OAuth_Client
from security_compliance.auth.secure_token_storage import TokenStorageError
import requests

try:
    # OAuth operations
    token = oauth_client.exchange_code_for_token(auth_code, state)
    
except requests.RequestException as e:
    # Network or HTTP errors
    if e.response:
        if e.response.status_code == 400:
            print("Invalid request - check parameters")
        elif e.response.status_code == 401:
            print("Authentication failed - check credentials")
        elif e.response.status_code == 403:
            print("Access denied - insufficient permissions")
        elif e.response.status_code == 429:
            print("Rate limit exceeded - retry after delay")
    else:
        print(f"Network error: {e}")

except TokenStorageError as e:
    # Token storage errors
    print(f"Token storage error: {e}")
    
except ValueError as e:
    # Configuration or parameter errors
    print(f"Configuration error: {e}")

except Exception as e:
    # Unexpected errors
    print(f"Unexpected error: {e}")
    # Log for investigation
    audit_logger.log_oauth_failure(
        user_id="current_user",
        platform=Platform.ADVANA,
        event_type="oauth_token_exchange",
        error_message=str(e)
    )
```

### Retry Logic

```python
import time
from functools import wraps

def retry_with_backoff(max_retries=3, base_delay=1, max_delay=60):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            for attempt in range(max_retries):
                try:
                    return func(*args, **kwargs)
                except requests.RequestException as e:
                    if attempt == max_retries - 1:
                        raise
                    
                    delay = min(base_delay * (2 ** attempt), max_delay)
                    print(f"Attempt {attempt + 1} failed, retrying in {delay}s")
                    time.sleep(delay)
            
            return None
        return wrapper
    return decorator

# Usage
@retry_with_backoff(max_retries=3)
def get_oauth_token():
    return oauth_client.get_client_credentials_token()
```

## Performance Optimization

### Connection Pooling

```python
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Configure session with connection pooling
session = requests.Session()

# Retry strategy
retry_strategy = Retry(
    total=3,
    backoff_factor=1,
    status_forcelist=[429, 500, 502, 503, 504],
)

# Mount adapter with retry strategy
adapter = HTTPAdapter(
    pool_connections=10,
    pool_maxsize=20,
    max_retries=retry_strategy
)

session.mount("http://", adapter)
session.mount("https://", adapter)

# Use session with OAuth client
oauth_client = DoD_OAuth_Client(config, session=session)
```

### Caching Strategies

```python
from functools import lru_cache
import time

class TokenCache:
    def __init__(self, ttl=300):  # 5 minutes
        self.ttl = ttl
        self._cache = {}
    
    def get(self, key):
        if key in self._cache:
            token, timestamp = self._cache[key]
            if time.time() - timestamp < self.ttl:
                return token
            else:
                del self._cache[key]
        return None
    
    def set(self, key, token):
        self._cache[key] = (token, time.time())
    
    def clear(self):
        self._cache.clear()

# Usage
token_cache = TokenCache(ttl=300)

def get_cached_token(platform, user_id):
    cache_key = f"{platform.value}:{user_id}"
    
    # Try cache first
    token = token_cache.get(cache_key)
    if token and not token.is_expired:
        return token
    
    # Get new token
    token = oauth_client.get_client_credentials_token()
    token_cache.set(cache_key, token)
    
    return token
```

## Monitoring and Metrics

### Metrics Collection

```python
from security_compliance.auth.token_lifecycle_manager import TokenLifecycleManager

# Get lifecycle manager
lifecycle_manager = TokenLifecycleManager()

# Collect metrics
metrics = lifecycle_manager.get_metrics()

print(f"Total tokens: {metrics.total_tokens}")
print(f"Active tokens: {metrics.active_tokens}")
print(f"Refresh success rate: {metrics.refresh_success_rate:.2f}%")
print(f"Average token lifetime: {metrics.average_token_lifetime:.2f} hours")
```

### Health Checks

```python
def oauth_health_check():
    """Perform OAuth system health check."""
    checks = {
        "token_storage": False,
        "oauth_clients": False,
        "cac_integration": False,
        "audit_logging": False
    }
    
    try:
        # Test token storage
        storage = TokenStorageManager.instance()
        test_tokens = storage.get_platform_tokens(Platform.ADVANA)
        checks["token_storage"] = True
    except Exception as e:
        print(f"Token storage check failed: {e}")
    
    try:
        # Test OAuth clients
        oauth_manager = DoD_OAuth_Manager()
        client = oauth_manager.get_client(Platform.ADVANA)
        checks["oauth_clients"] = client is not None
    except Exception as e:
        print(f"OAuth client check failed: {e}")
    
    try:
        # Test CAC integration
        cac_manager = CACAuthenticationManager()
        # Basic initialization check
        checks["cac_integration"] = True
    except Exception as e:
        print(f"CAC integration check failed: {e}")
    
    try:
        # Test audit logging
        audit_logger = EnhancedOAuthAuditLogger.instance()
        checks["audit_logging"] = True
    except Exception as e:
        print(f"Audit logging check failed: {e}")
    
    return checks

# Run health check
health = oauth_health_check()
print(f"System health: {health}")
```

## Troubleshooting

### Common Issues

1. **CAC Authentication Failures**
   - Verify CAC reader is connected and working
   - Check PKCS#11 library path
   - Ensure DoD certificates are installed
   - Verify PIN is correct

2. **OAuth Token Exchange Failures**
   - Check client credentials
   - Verify redirect URI matches registered URI
   - Ensure PKCE parameters are correct
   - Check network connectivity

3. **Token Storage Issues**
   - Verify database permissions
   - Check encryption key availability
   - Ensure adequate disk space
   - Review log files for errors

4. **Rate Limiting**
   - Monitor request patterns
   - Implement exponential backoff
   - Use concurrent request manager
   - Configure appropriate limits

### Debug Logging

```python
import logging

# Enable debug logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

# Enable specific loggers
logging.getLogger('security_compliance.auth.oauth_client').setLevel(logging.DEBUG)
logging.getLogger('security_compliance.auth.secure_token_storage').setLevel(logging.DEBUG)
logging.getLogger('security_compliance.auth.oauth_cac_bridge').setLevel(logging.DEBUG)
```

### Testing

```python
# Run comprehensive tests
pytest security_compliance/auth/test_enhanced_oauth.py -v

# Run specific test categories
pytest security_compliance/auth/test_enhanced_oauth.py::TestSecureTokenStorage -v
pytest security_compliance/auth/test_enhanced_oauth.py::TestOAuthCACBridge -v
```

## Support and Documentation

### Additional Resources
- DoD OAuth Implementation Guidelines
- CAC/PIV Integration Documentation
- Security Compliance Requirements
- Platform-Specific API Documentation

### Contact Information
For questions or support regarding this OAuth implementation framework, contact your local security officer or system administrator.

## License and Compliance

This implementation is designed for use within DoD networks and complies with applicable DoD security policies and regulations. Ensure proper authorization before deploying in production environments.