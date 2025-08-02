# Qlik Sense Enterprise CAC/PIV Integration Guide

## Overview

This guide provides step-by-step instructions for integrating CAC/PIV authentication with Qlik Sense Enterprise. The integration enables seamless, certificate-based authentication for DoD users accessing Qlik analytics applications.

## Prerequisites

### System Requirements
- Qlik Sense Enterprise Server
- Qlik Proxy Service configured for custom authentication
- Valid DoD PKI certificates
- Network access to Qlik environment

### Qlik Configuration Requirements
- Custom authentication module support
- Virtual proxy configuration
- JWT or session ticket support
- HTTPS enabled

## Architecture Overview

```
[CAC Card] -> [Smart Card Reader] -> [CAC Auth Service] -> [Qlik Proxy] -> [Qlik Engine]
                                                        |
                                                    [Session Ticket]
                                                        |
                                                   [Qlik Hub/Apps]
```

## Quick Start

### 1. Basic Configuration

```python
from security_compliance.auth.platform_adapters import PlatformConfig
from security_compliance.auth.platform_adapters import QlikAuthAdapter

# Configure Qlik connection
config = PlatformConfig(
    platform_name="qlik",
    base_url="https://qlik-server.mil",
    api_version="v1",
    authentication_endpoint="/api/v1/auth/certificate",
    token_endpoint="/api/v1/auth/jwt",
    user_info_endpoint="/api/v1/users/me",
    timeout=30,
    verify_ssl=True,
    additional_config={
        "qlik_domain": "qlik.mil",
        "virtual_proxy": "cac",
        "app_access_point": "/hub",
        "certificate_header": "X-Qlik-User",
        "jwt_secret": "your-jwt-secret-key",
        "jwt_algorithm": "HS256"
    }
)

# Initialize adapter
adapter = QlikAuthAdapter(config)
```

### 2. Authentication Flow

```python
from security_compliance.auth.cac_piv_integration import CACAuthenticationManager
from cryptography.hazmat.primitives import serialization

# Initialize authentication
auth_manager = CACAuthenticationManager()

# Authenticate user with CAC
credentials = auth_manager.authenticate_user("user_pin")

if credentials:
    # Get certificate data for Qlik
    certificate_data = credentials.certificate.public_bytes(serialization.Encoding.DER)
    
    # Generate challenge and signature
    challenge = adapter._generate_challenge()
    signature = auth_manager.authenticator.sign_data(challenge)
    
    # Authenticate with Qlik
    result = adapter.authenticate_with_cac(
        certificate_data=certificate_data,
        signature=signature,
        challenge=challenge,
        additional_params={
            "virtual_proxy": "cac",
            "target_app": "data-analytics-app"
        }
    )
    
    if result.status == AuthenticationStatus.SUCCESS:
        print(f"Qlik authentication successful!")
        
        # Create Qlik session URL
        session_url = adapter.create_qlik_session_url(
            session_token=result.platform_token,
            app_id="your-app-id"
        )
        
        print(f"Access Qlik at: {session_url}")
        
        # Get available apps
        apps = adapter.get_qlik_apps(result.session_token)
        for app in apps:
            print(f"App: {app['name']} - {app['id']}")
```

## Qlik-Specific Features

### Virtual Proxy Configuration

```python
# Configure virtual proxy for CAC authentication
virtual_proxy_config = {
    "prefix": "cac",
    "description": "CAC/PIV Authentication Proxy",
    "sessionCookieHeaderName": "X-Qlik-Session-CAC",
    "authenticationModuleRedirectUri": "https://cac-auth.mil/auth/qlik",
    "websocketCrossOriginWhiteList": ["https://cac-auth.mil"],
    "additionalResponseHeaders": "X-Frame-Options: SAMEORIGIN"
}

# Apply configuration
adapter.config.additional_config["virtual_proxy_config"] = virtual_proxy_config
```

### User Attribute Mapping

```python
def map_cac_to_qlik_attributes(certificate):
    """Map CAC certificate attributes to Qlik user attributes"""
    from cryptography import x509
    
    attributes = {}
    
    # Extract attributes from certificate
    for attr in certificate.subject:
        if attr.oid == x509.oid.NameOID.COMMON_NAME:
            attributes['name'] = attr.value
        elif attr.oid == x509.oid.NameOID.ORGANIZATION_NAME:
            attributes['organization'] = attr.value
            
    # Extract email from SAN
    try:
        san_ext = certificate.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )
        for name in san_ext.value:
            if isinstance(name, x509.RFC822Name):
                attributes['email'] = name.value
                break
    except x509.ExtensionNotFound:
        pass
    
    # Map to Qlik groups based on organization
    groups = ['qlik_users']
    if 'organization' in attributes:
        org = attributes['organization'].lower()
        if 'army' in org:
            groups.append('army_users')
        elif 'navy' in org:
            groups.append('navy_users')
        elif 'air force' in org:
            groups.append('af_users')
    
    attributes['groups'] = groups
    return attributes
```

### JWT Token Creation

```python
import jwt
from datetime import datetime, timezone, timedelta

def create_qlik_jwt(user_attributes, secret_key):
    """Create JWT token for Qlik authentication"""
    payload = {
        'sub': user_attributes.get('email', 'unknown'),
        'name': user_attributes.get('name', 'Unknown User'),
        'email': user_attributes.get('email', ''),
        'groups': user_attributes.get('groups', []),
        'iat': datetime.now(timezone.utc),
        'exp': datetime.now(timezone.utc) + timedelta(hours=8),
        'iss': 'cac-auth-service',
        'aud': 'qlik-sense'
    }
    
    return jwt.encode(payload, secret_key, algorithm='HS256')
```

## Advanced Configuration

### Multi-Node Qlik Environment

```python
# Configure for multi-node Qlik cluster
cluster_config = {
    "load_balancer": "https://qlik-lb.mil",
    "nodes": [
        "https://qlik-node1.mil",
        "https://qlik-node2.mil", 
        "https://qlik-node3.mil"
    ],
    "session_affinity": True,
    "health_check_interval": 30
}

# Initialize adapters for each node
node_adapters = {}
for i, node_url in enumerate(cluster_config["nodes"]):
    node_config = config.copy()
    node_config.base_url = node_url
    node_adapters[f"node_{i+1}"] = QlikAuthAdapter(node_config)
```

### Custom Authentication Module

```python
class QlikCACAuthModule:
    """Custom Qlik authentication module for CAC/PIV"""
    
    def __init__(self, config):
        self.config = config
        self.adapter = QlikAuthAdapter(config)
    
    def authenticate(self, request):
        """Handle Qlik authentication request"""
        try:
            # Extract certificate from request headers
            cert_header = request.headers.get(
                self.config.additional_config["certificate_header"]
            )
            
            if not cert_header:
                return self._create_error_response("No certificate found")
            
            # Decode certificate
            certificate_data = base64.b64decode(cert_header)
            
            # Extract user attributes
            user_attrs = self.adapter._extract_qlik_user_attributes(certificate_data)
            
            # Create session ticket
            ticket_data = {
                'UserDirectory': user_attrs.get('domain', self.config.additional_config["qlik_domain"]),
                'UserId': user_attrs.get('email', 'unknown'),
                'Attributes': []
            }
            
            # Add user attributes to ticket
            for key, value in user_attrs.items():
                if key not in ['domain', 'email']:
                    ticket_data['Attributes'].append({
                        'Name': key,
                        'Value': str(value)
                    })
            
            # Create session ticket
            response = self._create_session_ticket(ticket_data)
            
            return response
            
        except Exception as e:
            return self._create_error_response(f"Authentication failed: {str(e)}")
    
    def _create_session_ticket(self, ticket_data):
        """Create Qlik session ticket"""
        # Implementation depends on Qlik Proxy Service API
        pass
    
    def _create_error_response(self, error_message):
        """Create error response"""
        return {
            'success': False,
            'error': error_message,
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
```

## Qlik Proxy Service Integration

### Configuration Template

```javascript
// Qlik Proxy Service custom authentication configuration
{
    "virtualProxies": [{
        "prefix": "cac",
        "description": "CAC/PIV Authentication",
        "authenticationModuleRedirectUri": "https://cac-auth.mil/qlik/auth",
        "loadBalancingServerNodes": [],
        "websocketCrossOriginWhiteList": [
            "https://cac-auth.mil"
        ],
        "additionalResponseHeaders": "X-Frame-Options: SAMEORIGIN",
        "sessionCookieHeaderName": "X-Qlik-Session-CAC",
        "sessionCookieDomain": ".mil",
        "anonymousAccessMode": 0,
        "windowsAuthenticationEnabledDevicePattern": "",
        "loadBalancingPolicy": 0,
        "magicLinkHostUri": "",
        "magicLinkFriendlyName": "",
        "samlHostUri": "",
        "samlEntityId": "",
        "samlAttributeUserId": "",
        "samlAttributeUserDirectory": "",
        "samlAttributeSigningAlgorithm": 0
    }]
}
```

### Custom Authentication Handler

```python
from flask import Flask, request, jsonify, redirect
import base64

app = Flask(__name__)

@app.route('/qlik/auth', methods=['GET', 'POST'])
def qlik_auth_handler():
    """Handle Qlik authentication requests"""
    try:
        # Extract target URL from Qlik
        target_id = request.args.get('targetId')
        
        # Get certificate from environment or headers
        certificate_data = get_certificate_from_request(request)
        
        if not certificate_data:
            return jsonify({'error': 'No certificate provided'}), 401
        
        # Authenticate with CAC service
        auth_result = authenticate_with_cac_service(certificate_data)
        
        if auth_result['success']:
            # Create session ticket for Qlik
            ticket = create_qlik_session_ticket(auth_result['user_attrs'])
            
            # Redirect to Qlik with ticket
            qlik_url = f"https://qlik-server.mil/cac/hub?qlikTicket={ticket}"
            if target_id:
                qlik_url += f"&targetId={target_id}"
            
            return redirect(qlik_url)
        else:
            return jsonify({'error': 'Authentication failed'}), 401
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

def get_certificate_from_request(request):
    """Extract certificate from request"""
    # Check various sources for certificate
    cert_header = request.headers.get('X-Client-Cert')
    if cert_header:
        return base64.b64decode(cert_header)
    
    # Check for other certificate sources
    return None

def authenticate_with_cac_service(certificate_data):
    """Authenticate with CAC service"""
    # Call CAC authentication service
    import requests
    
    response = requests.post('http://cac-auth:8000/api/v1/auth/authenticate', 
                           json={
                               'certificate_data': base64.b64encode(certificate_data).decode(),
                               'platform': 'qlik'
                           })
    
    return response.json()

def create_qlik_session_ticket(user_attrs):
    """Create Qlik session ticket"""
    # Call Qlik Proxy Service to create ticket
    import requests
    
    ticket_data = {
        'UserDirectory': user_attrs.get('domain', 'MIL'),
        'UserId': user_attrs.get('email', 'unknown'),
        'Attributes': [
            {'Name': 'Group', 'Value': group}
            for group in user_attrs.get('groups', [])
        ]
    }
    
    response = requests.post('https://qlik-server.mil:4243/qps/ticket',
                           json=ticket_data,
                           headers={'X-Qlik-User': 'internal\\service'})
    
    return response.json().get('Ticket')
```

## Security Configuration

### SSL/TLS Setup

```python
# Configure SSL certificates for secure communication
ssl_config = {
    "cert_file": "/path/to/qlik-cert.pem",
    "key_file": "/path/to/qlik-key.pem",
    "ca_file": "/path/to/ca-bundle.pem",
    "verify_mode": "CERT_REQUIRED",
    "ciphers": "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256"
}

# Apply SSL configuration
adapter.config.additional_config["ssl_config"] = ssl_config
```

### Access Control

```python
def check_qlik_access_permissions(user_attrs, app_id):
    """Check if user has access to specific Qlik app"""
    user_groups = user_attrs.get('groups', [])
    organization = user_attrs.get('organization', '').lower()
    
    # Define access rules
    access_rules = {
        'army-analytics': ['army_users', 'army_analysts'],
        'navy-dashboard': ['navy_users', 'navy_commanders'],
        'joint-operations': ['army_users', 'navy_users', 'af_users']
    }
    
    allowed_groups = access_rules.get(app_id, [])
    
    # Check if user has required group membership
    for group in user_groups:
        if group in allowed_groups:
            return True
    
    # Check organization-based access
    if organization and f"{organization}_users" in allowed_groups:
        return True
    
    return False
```

## Monitoring and Troubleshooting

### Health Checks

```python
def check_qlik_connectivity():
    """Check Qlik server connectivity and health"""
    try:
        response = requests.get(f"{adapter.config.base_url}/hub/about",
                              timeout=10,
                              verify=adapter.config.verify_ssl)
        
        return {
            'status': 'healthy' if response.status_code == 200 else 'unhealthy',
            'response_time': response.elapsed.total_seconds(),
            'version': response.headers.get('X-Qlik-Version', 'unknown')
        }
    except Exception as e:
        return {
            'status': 'unhealthy',
            'error': str(e)
        }
```

### Logging Configuration

```python
import logging

# Configure Qlik-specific logging
qlik_logger = logging.getLogger('qlik_cac_integration')
qlik_logger.setLevel(logging.INFO)

# Create file handler
handler = logging.FileHandler('/var/log/qlik-cac-auth.log')
formatter = logging.Formatter(
    '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
handler.setFormatter(formatter)
qlik_logger.addHandler(handler)

# Log authentication events
def log_qlik_auth_event(user_id, app_id, success, details=None):
    """Log Qlik authentication events"""
    log_data = {
        'user_id': user_id,
        'app_id': app_id,
        'success': success,
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'details': details or {}
    }
    
    if success:
        qlik_logger.info(f"Qlik auth success: {json.dumps(log_data)}")
    else:
        qlik_logger.warning(f"Qlik auth failed: {json.dumps(log_data)}")
```

## Testing and Validation

### Unit Tests

```python
import unittest
from unittest.mock import Mock, patch

class TestQlikCACIntegration(unittest.TestCase):
    
    def setUp(self):
        self.config = PlatformConfig(
            platform_name="qlik",
            base_url="https://test-qlik.mil",
            verify_ssl=False
        )
        self.adapter = QlikAuthAdapter(self.config)
    
    def test_user_attribute_extraction(self):
        """Test extraction of user attributes from certificate"""
        # Mock certificate
        mock_cert = Mock()
        
        # Test attribute extraction
        attrs = self.adapter._extract_qlik_user_attributes(mock_cert)
        
        self.assertIn('domain', attrs)
        self.assertIn('groups', attrs)
    
    @patch('requests.post')
    def test_session_ticket_creation(self, mock_post):
        """Test Qlik session ticket creation"""
        mock_response = Mock()
        mock_response.json.return_value = {'Ticket': 'test_ticket_123'}
        mock_post.return_value = mock_response
        
        # Test ticket creation
        # Implementation would go here
```

### Integration Tests

```python
def test_end_to_end_qlik_integration():
    """Test complete Qlik integration flow"""
    # 1. Authenticate with CAC
    # 2. Get session ticket
    # 3. Access Qlik application
    # 4. Verify user permissions
    # 5. Log out
    pass
```

## Best Practices

1. **Security**
   - Use HTTPS for all communications
   - Validate certificates against DoD CAs
   - Implement proper session management
   - Regular security audits

2. **Performance**
   - Cache session tickets appropriately
   - Implement connection pooling
   - Monitor response times
   - Use load balancing for high availability

3. **User Experience**
   - Seamless single sign-on
   - Clear error messages
   - Proper session timeout handling
   - Mobile device support

4. **Maintenance**
   - Regular certificate updates
   - Monitor authentication logs
   - Performance monitoring
   - Automated health checks

## Troubleshooting Guide

### Common Issues

1. **Session Ticket Invalid**
   ```
   Error: Session ticket expired or invalid
   Solution: Check ticket creation time and expiration, verify user attributes
   ```

2. **Certificate Not Trusted**
   ```
   Error: Certificate chain validation failed
   Solution: Verify DoD CA certificates are installed and current
   ```

3. **Virtual Proxy Configuration**
   ```
   Error: Authentication module not responding
   Solution: Check virtual proxy configuration and network connectivity
   ```

4. **User Access Denied**
   ```
   Error: User does not have permission to access application
   Solution: Verify user group memberships and access rules
   ```

## Support Resources

- Qlik Sense Enterprise documentation
- DoD PKI certificate management guides
- Virtual proxy configuration examples
- Community forums and support channels