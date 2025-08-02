# Navy Jupiter Platform CAC/PIV Integration Guide

## Overview

This guide provides comprehensive instructions for integrating CAC/PIV authentication with the Navy Jupiter platform. The integration enables secure, certificate-based authentication for Navy personnel accessing analytical capabilities across NIPR and SIPR networks.

## Prerequisites

### System Requirements
- Access to Navy Jupiter platform
- Valid Navy/DoD PKI certificates
- Network connectivity (NIPR/SIPR)
- Command/facility codes for access control

### Navy Jupiter Configuration Requirements
- Proper network classification level
- Command authorization
- Facility security clearance
- Dual authentication capability (SIPR)

## Architecture Overview

```
[CAC Card] -> [CAC Auth Service] -> [Navy Jupiter Gateway] -> [Network Services]
                    |                        |                      |
             [Certificate Validation]   [Classification Check]  [Command Access]
                    |                        |                      |
             [EDIPI Extraction]        [Network Routing]      [Audit Logging]
```

## Quick Start

### 1. Basic Configuration

```python
from security_compliance.auth.platform_adapters import PlatformConfig
from security_compliance.auth.platform_adapters import NavyJupiterAuthAdapter

# Configure Navy Jupiter connection
config = PlatformConfig(
    platform_name="navy_jupiter",
    base_url="https://navy-jupiter.navy.mil",
    api_version="v1",
    authentication_endpoint="/api/v1/auth/cac",
    token_endpoint="/api/v1/auth/token",
    user_info_endpoint="/api/v1/user/profile",
    timeout=30,
    max_retries=3,
    verify_ssl=True,
    additional_config={
        "navy_network": "NIPR",  # or "SIPR"
        "classification_level": "UNCLASSIFIED",
        "command_code": "NAVWAR",  # Your command code
        "facility_code": "SD001",  # Your facility code
        "enclave_id": "SPAWAR-SD",
        "require_dual_auth": False,  # Set True for SIPR
        "session_timeout": 3600,
        "max_concurrent_sessions": 1
    }
)

# Initialize adapter
adapter = NavyJupiterAuthAdapter(config)
```

### 2. Authentication Flow

```python
from security_compliance.auth.cac_piv_integration import CACAuthenticationManager
from cryptography.hazmat.primitives import serialization

# Initialize authentication manager
auth_manager = CACAuthenticationManager()

# Authenticate user with CAC
credentials = auth_manager.authenticate_user("user_pin")

if credentials:
    # Verify Navy affiliation
    if not credentials.organization or 'NAVY' not in credentials.organization.upper():
        print("Warning: Non-Navy certificate detected")
    
    # Get certificate data for Navy Jupiter
    certificate_data = credentials.certificate.public_bytes(serialization.Encoding.DER)
    
    # Generate challenge and signature
    challenge = adapter._generate_challenge()
    signature = auth_manager.authenticator.sign_data(challenge)
    
    # Prepare additional parameters for Navy Jupiter
    additional_params = {
        "command_code": "NAVWAR",
        "facility_code": "SD001",
        "client_ip": "192.168.1.100",
        "workstation_id": "NAVWS001",
        "user_agent": "Navy-CAC-Client/1.0"
    }
    
    # For SIPR networks, dual authentication might be required
    if adapter.navy_network == "SIPR":
        additional_params["secondary_auth"] = {
            "method": "token",
            "token": "secondary_auth_token"  # From secondary auth system
        }
    
    # Authenticate with Navy Jupiter
    result = adapter.authenticate_with_cac(
        certificate_data=certificate_data,
        signature=signature,
        challenge=challenge,
        additional_params=additional_params
    )
    
    if result.status == AuthenticationStatus.SUCCESS:
        print(f"Navy Jupiter authentication successful!")
        print(f"Session token: {result.session_token}")
        print(f"Navy session token: {result.platform_token}")
        print(f"Security context: {result.metadata.get('security_context')}")
        
        # Get available Navy systems
        systems = adapter.get_navy_systems(result.session_token)
        for system in systems:
            print(f"System: {system['name']} - {system['classification']}")
        
        # Get security context
        security_ctx = adapter.get_security_context(result.session_token)
        print(f"Current security context: {security_ctx}")
        
    elif result.status == AuthenticationStatus.PENDING:
        print("Dual authentication required for SIPR access")
        print("Please complete secondary authentication")
    else:
        print(f"Authentication failed: {result.error_message}")
```

## Navy-Specific Features

### Command and Facility Access Control

```python
def setup_command_access(adapter, user_attrs, command_permissions):
    """Set up command-specific access controls"""
    
    # Extract command affiliation from certificate
    user_command = extract_command_from_certificate(user_attrs)
    
    # Define command access matrix
    command_access_matrix = {
        "NAVWAR": {
            "systems": ["intel-analysis", "cyber-ops", "comms"],
            "classifications": ["UNCLASSIFIED", "CONFIDENTIAL", "SECRET"],
            "networks": ["NIPR", "SIPR"]
        },
        "NAVSEA": {
            "systems": ["ship-design", "weapons-systems", "testing"],
            "classifications": ["UNCLASSIFIED", "CONFIDENTIAL"],
            "networks": ["NIPR"]
        },
        "NAVAIR": {
            "systems": ["flight-ops", "aircraft-maint", "training"],
            "classifications": ["UNCLASSIFIED", "CONFIDENTIAL", "SECRET"],
            "networks": ["NIPR", "SIPR"]
        }
    }
    
    # Get access permissions for user's command
    access_perms = command_access_matrix.get(user_command, {})
    
    return {
        "command": user_command,
        "allowed_systems": access_perms.get("systems", []),
        "max_classification": max(access_perms.get("classifications", ["UNCLASSIFIED"])),
        "allowed_networks": access_perms.get("networks", ["NIPR"])
    }

def extract_command_from_certificate(user_attrs):
    """Extract Navy command from certificate attributes"""
    
    # Check organization field
    org = user_attrs.get('organization', '').upper()
    
    # Common Navy command patterns
    if 'NAVWAR' in org or 'SPAWAR' in org:
        return 'NAVWAR'
    elif 'NAVSEA' in org:
        return 'NAVSEA'
    elif 'NAVAIR' in org:
        return 'NAVAIR'
    elif 'USMC' in org:
        return 'USMC'
    
    # Check organizational unit
    ou = user_attrs.get('organizational_unit', '').upper()
    for command in ['NAVWAR', 'NAVSEA', 'NAVAIR', 'USMC']:
        if command in ou:
            return command
    
    # Default to general Navy
    return 'NAVY'
```

### Network Classification Management

```python
def validate_network_access(adapter, user_attrs, requested_network, requested_classification):
    """Validate user access to specific network and classification level"""
    
    # Get user's clearance level
    user_clearance = user_attrs.get('clearance_level', 'UNCLASSIFIED')
    
    # Network access rules
    network_rules = {
        "NIPR": {
            "max_classification": "CONFIDENTIAL",
            "required_clearance": "CONFIDENTIAL"
        },
        "SIPR": {
            "max_classification": "SECRET",
            "required_clearance": "SECRET",
            "requires_dual_auth": True
        },
        "JWICS": {
            "max_classification": "TOP_SECRET",
            "required_clearance": "TOP_SECRET", 
            "requires_dual_auth": True,
            "special_access_required": True
        }
    }
    
    network_config = network_rules.get(requested_network)
    if not network_config:
        return False, "Invalid network specified"
    
    # Check clearance level
    clearance_levels = ["UNCLASSIFIED", "CONFIDENTIAL", "SECRET", "TOP_SECRET"]
    
    user_level_idx = clearance_levels.index(user_clearance) if user_clearance in clearance_levels else 0
    required_level_idx = clearance_levels.index(network_config["required_clearance"])
    
    if user_level_idx < required_level_idx:
        return False, f"Insufficient clearance: {user_clearance} < {network_config['required_clearance']}"
    
    # Check classification level
    requested_level_idx = clearance_levels.index(requested_classification)
    max_level_idx = clearance_levels.index(network_config["max_classification"])
    
    if requested_level_idx > max_level_idx:
        return False, f"Classification too high for network: {requested_classification} > {network_config['max_classification']}"
    
    return True, "Access authorized"

def setup_network_isolation(adapter, network, classification):
    """Set up network isolation based on classification"""
    
    isolation_config = {
        "network_segmentation": True,
        "traffic_filtering": True,
        "content_inspection": True,
        "data_loss_prevention": True
    }
    
    if classification in ["SECRET", "TOP_SECRET"]:
        isolation_config.update({
            "encrypted_storage": True,
            "secure_delete": True,
            "print_restrictions": True,
            "usb_restrictions": True,
            "screen_capture_blocking": True
        })
    
    if network == "SIPR":
        isolation_config.update({
            "air_gap_enforcement": True,
            "cross_domain_prevention": True,
            "enhanced_monitoring": True
        })
    
    return isolation_config
```

### Dual Authentication for SIPR

```python
def implement_dual_authentication(adapter, primary_result, secondary_auth_method="token"):
    """Implement dual authentication for SIPR access"""
    
    if not primary_result.metadata.get("requires_dual_auth"):
        return primary_result
    
    secondary_auth_config = {
        "token": {
            "source": "rsa_securid",
            "validation_endpoint": "/api/v1/auth/token/validate",
            "timeout": 60
        },
        "biometric": {
            "source": "fingerprint_scanner",
            "validation_endpoint": "/api/v1/auth/biometric/validate",
            "timeout": 30
        },
        "smart_card": {
            "source": "secondary_cac",
            "validation_endpoint": "/api/v1/auth/cac/secondary",
            "timeout": 120
        }
    }
    
    auth_config = secondary_auth_config.get(secondary_auth_method)
    if not auth_config:
        raise ValueError(f"Unsupported secondary auth method: {secondary_auth_method}")
    
    # Prompt for secondary authentication
    print(f"Secondary authentication required: {secondary_auth_method}")
    
    if secondary_auth_method == "token":
        token = input("Enter RSA SecurID token: ")
        secondary_result = validate_rsa_token(adapter, token, auth_config)
    elif secondary_auth_method == "biometric":
        secondary_result = capture_biometric(adapter, auth_config)
    elif secondary_auth_method == "smart_card":
        secondary_result = validate_secondary_cac(adapter, auth_config)
    
    if secondary_result["valid"]:
        # Update primary result with dual auth completion
        primary_result.status = AuthenticationStatus.SUCCESS
        primary_result.metadata["dual_auth_completed"] = True
        primary_result.metadata["secondary_auth_method"] = secondary_auth_method
        primary_result.metadata["secondary_auth_time"] = datetime.now(timezone.utc).isoformat()
        
        return primary_result
    else:
        primary_result.status = AuthenticationStatus.FAILED
        primary_result.error_message = f"Secondary authentication failed: {secondary_result.get('error')}"
        return primary_result

def validate_rsa_token(adapter, token, auth_config):
    """Validate RSA SecurID token"""
    import requests
    
    validation_data = {
        "token": token,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
    
    try:
        response = requests.post(
            f"{adapter.config.base_url}{auth_config['validation_endpoint']}",
            json=validation_data,
            timeout=auth_config["timeout"]
        )
        
        if response.status_code == 200:
            result = response.json()
            return {"valid": result.get("valid", False)}
        else:
            return {"valid": False, "error": "Token validation service unavailable"}
            
    except Exception as e:
        return {"valid": False, "error": str(e)}
```

## Advanced Security Features

### Enhanced Audit Logging

```python
def setup_navy_audit_logging(adapter, session_token, user_attrs, security_context):
    """Set up Navy-specific audit logging"""
    
    audit_config = {
        "user_edipi": user_attrs.get('edipi'),
        "command_code": adapter.command_code,
        "facility_code": adapter.facility_code,
        "network": adapter.navy_network,
        "classification": adapter.classification_level,
        "session_start": datetime.now(timezone.utc).isoformat(),
        "client_info": {
            "ip_address": security_context.get('client_ip'),
            "workstation_id": security_context.get('workstation_id'),
            "user_agent": security_context.get('user_agent')
        },
        "security_context": security_context
    }
    
    # Send to Navy audit system
    send_to_navy_audit_system(audit_config)
    
    # Set up continuous monitoring
    setup_session_monitoring(adapter, session_token, audit_config)

def send_to_navy_audit_system(audit_data):
    """Send audit data to Navy centralized audit system"""
    import requests
    
    navy_audit_endpoints = {
        "NIPR": "https://audit-nipr.navy.mil/api/v1/events",
        "SIPR": "https://audit-sipr.navy.mil/api/v1/events"
    }
    
    endpoint = navy_audit_endpoints.get(audit_data.get('network', 'NIPR'))
    
    try:
        response = requests.post(
            endpoint,
            json={
                "event_type": "navy_jupiter_access",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "data": audit_data
            },
            timeout=30,
            verify=True
        )
        
        if response.status_code == 200:
            print("Audit event logged to Navy system")
        else:
            print(f"Failed to log audit event: {response.status_code}")
            
    except Exception as e:
        print(f"Audit logging error: {e}")
        # Implement fallback logging mechanism

def setup_session_monitoring(adapter, session_token, audit_config):
    """Set up continuous session monitoring"""
    
    monitoring_config = {
        "session_token": session_token,
        "user_edipi": audit_config["user_edipi"],
        "monitoring_interval": 300,  # 5 minutes
        "inactivity_timeout": 1800,  # 30 minutes
        "security_events": [
            "data_access",
            "system_command",
            "file_transfer",
            "network_connection",
            "privilege_escalation"
        ]
    }
    
    # Start monitoring thread/service
    start_session_monitor(monitoring_config)

def start_session_monitor(config):
    """Start session monitoring service"""
    import threading
    import time
    
    def monitor_session():
        while True:
            try:
                # Check session activity
                session_active = check_session_activity(config["session_token"])
                
                if not session_active:
                    log_session_event("session_inactive", config)
                    break
                
                # Check for security events
                security_events = check_security_events(config["session_token"])
                for event in security_events:
                    log_security_event(event, config)
                
                time.sleep(config["monitoring_interval"])
                
            except Exception as e:
                log_monitoring_error(e, config)
                break
    
    monitor_thread = threading.Thread(target=monitor_session, daemon=True)
    monitor_thread.start()
```

### Data Classification and Handling

```python
def setup_data_classification_controls(adapter, classification_level):
    """Set up data classification controls for Navy Jupiter"""
    
    classification_controls = {
        "UNCLASSIFIED": {
            "marking_required": True,
            "encryption_required": False,
            "export_allowed": True,
            "sharing_restrictions": [],
            "retention_period": "indefinite"
        },
        "CONFIDENTIAL": {
            "marking_required": True,
            "encryption_required": True,
            "export_allowed": False,
            "sharing_restrictions": ["need_to_know"],
            "retention_period": "20_years",
            "handling_instructions": "FOR OFFICIAL USE ONLY"
        },
        "SECRET": {
            "marking_required": True,
            "encryption_required": True,
            "export_allowed": False,
            "sharing_restrictions": ["need_to_know", "cleared_personnel"],
            "retention_period": "75_years",
            "handling_instructions": "SECRET//NOFORN",
            "special_handling": True
        },
        "TOP_SECRET": {
            "marking_required": True,
            "encryption_required": True,
            "export_allowed": False,
            "sharing_restrictions": ["need_to_know", "cleared_personnel", "compartmented"],
            "retention_period": "permanent",
            "handling_instructions": "TOP SECRET//SI//NOFORN",
            "special_handling": True,
            "compartment_controls": True
        }
    }
    
    controls = classification_controls.get(classification_level, classification_controls["UNCLASSIFIED"])
    
    # Apply classification controls
    apply_data_controls(adapter, controls)
    
    return controls

def apply_data_controls(adapter, controls):
    """Apply data classification controls"""
    
    # Set up automatic data marking
    if controls["marking_required"]:
        setup_automatic_marking(adapter, controls)
    
    # Configure encryption
    if controls["encryption_required"]:
        setup_data_encryption(adapter, controls)
    
    # Set up access restrictions
    setup_access_restrictions(adapter, controls["sharing_restrictions"])
    
    # Configure retention policies
    setup_retention_policies(adapter, controls["retention_period"])

def setup_automatic_marking(adapter, controls):
    """Set up automatic data marking for classification"""
    
    marking_config = {
        "header_marking": controls["handling_instructions"],
        "footer_marking": f"Classified By: Navy Jupiter System\\nDerived From: Multiple Sources\\nDeclassify On: {get_declassification_date(controls)}",
        "page_marking": True,
        "watermark": True
    }
    
    # Apply marking configuration
    adapter.config.additional_config["data_marking"] = marking_config

def get_declassification_date(controls):
    """Calculate declassification date based on retention period"""
    from datetime import datetime, timedelta
    
    retention = controls["retention_period"]
    current_date = datetime.now()
    
    if retention == "indefinite" or retention == "permanent":
        return "Manual Review Required"
    elif retention == "20_years":
        return (current_date + timedelta(days=365*20)).strftime("%Y%m%d")
    elif retention == "75_years":
        return (current_date + timedelta(days=365*75)).strftime("%Y%m%d")
    else:
        return "Manual Review Required"
```

## Integration with Navy Systems

### NMCI Integration

```python
def setup_nmci_integration(adapter, user_attrs):
    """Set up integration with Navy Marine Corps Intranet"""
    
    nmci_config = {
        "domain": "nmci.navy.mil",
        "authentication_server": "https://auth.nmci.navy.mil",
        "directory_service": "ldap://directory.nmci.navy.mil",
        "proxy_settings": {
            "http_proxy": "proxy.nmci.navy.mil:8080",
            "https_proxy": "proxy.nmci.navy.mil:8080",
            "no_proxy": "localhost,127.0.0.1,*.navy.mil"
        }
    }
    
    # Configure NMCI integration
    adapter.config.additional_config["nmci"] = nmci_config
    
    # Set up NMCI user lookup
    nmci_user = lookup_nmci_user(user_attrs["edipi"])
    if nmci_user:
        adapter.config.additional_config["nmci_user"] = nmci_user

def lookup_nmci_user(edipi):
    """Look up user in NMCI directory"""
    import ldap3
    
    try:
        server = ldap3.Server('ldap://directory.nmci.navy.mil')
        conn = ldap3.Connection(server, auto_bind=True)
        
        search_filter = f"(edipiNumber={edipi})"
        search_base = "ou=People,o=U.S. Government,c=US"
        
        conn.search(search_base, search_filter, attributes=['cn', 'mail', 'ou', 'title'])
        
        if conn.entries:
            entry = conn.entries[0]
            return {
                "name": str(entry.cn),
                "email": str(entry.mail),
                "organization": str(entry.ou),
                "title": str(entry.title)
            }
        
        return None
        
    except Exception as e:
        print(f"NMCI lookup failed: {e}")
        return None
```

### GCCS-M Integration

```python
def setup_gccs_integration(adapter, user_attrs, command_code):
    """Set up integration with Global Command and Control System - Maritime"""
    
    gccs_config = {
        "system_designation": "GCCS-M",
        "classification": "SECRET",
        "network": "SIPR",
        "command_node": command_code,
        "encryption_level": "Type 1",
        "message_handling": "AUTODIN"
    }
    
    # Verify user authorization for GCCS-M access
    if not verify_gccs_authorization(user_attrs, command_code):
        raise ValueError("User not authorized for GCCS-M access")
    
    # Set up secure communication channels
    setup_secure_channels(adapter, gccs_config)
    
    return gccs_config

def verify_gccs_authorization(user_attrs, command_code):
    """Verify user authorization for GCCS-M access"""
    
    # Check clearance level
    clearance = user_attrs.get('clearance_level', 'UNCLASSIFIED')
    if clearance not in ['SECRET', 'TOP_SECRET']:
        return False
    
    # Check command authorization
    authorized_commands = ['NAVWAR', 'FLEET', 'NAVCENT', 'PACFLT']
    if command_code not in authorized_commands:
        return False
    
    # Check for special access programs if needed
    return True

def setup_secure_channels(adapter, gccs_config):
    """Set up secure communication channels for GCCS-M"""
    
    channel_config = {
        "encryption": "AES-256",
        "key_management": "PKI",
        "authentication": "mutual_tls",
        "message_integrity": "HMAC-SHA256"
    }
    
    adapter.config.additional_config["secure_channels"] = channel_config
```

## Testing and Validation

### Navy-Specific Tests

```python
import unittest
from unittest.mock import Mock, patch

class TestNavyJupiterIntegration(unittest.TestCase):
    
    def setUp(self):
        self.config = PlatformConfig(
            platform_name="navy_jupiter",
            base_url="https://test-navy-jupiter.navy.mil",
            verify_ssl=False,
            additional_config={
                "navy_network": "NIPR",
                "classification_level": "UNCLASSIFIED",
                "command_code": "TEST_CMD"
            }
        )
        self.adapter = NavyJupiterAuthAdapter(self.config)
    
    def test_navy_certificate_validation(self):
        """Test Navy-specific certificate validation"""
        
        # Test with Navy certificate
        navy_attrs = {
            "email_domain": "navy.mil",
            "organization": "U.S. Navy",
            "is_navy_cert": True,
            "is_dod_cert": True
        }
        
        validation = self.adapter._validate_navy_certificate(navy_attrs)
        self.assertTrue(validation["valid"])
    
    def test_dual_authentication_requirement(self):
        """Test dual authentication for SIPR"""
        
        # Configure for SIPR
        self.adapter.navy_network = "SIPR"
        self.adapter.require_dual_auth = True
        
        # Test authentication without secondary auth
        result = self.adapter.authenticate_with_cac(
            certificate_data=b"test_cert",
            signature=b"test_sig", 
            challenge=b"test_challenge"
        )
        
        self.assertEqual(result.status, AuthenticationStatus.PENDING)
        self.assertIn("Secondary authentication required", result.error_message)
    
    def test_command_access_control(self):
        """Test command-based access control"""
        
        test_cases = [
            ("NAVWAR", ["intel-analysis", "cyber-ops"], True),
            ("NAVSEA", ["ship-design"], True),
            ("INVALID", [], False)
        ]
        
        for command, expected_systems, should_have_access in test_cases:
            user_attrs = {"organization": f"U.S. Navy {command}"}
            access_perms = setup_command_access(self.adapter, user_attrs, {})
            
            if should_have_access:
                self.assertEqual(access_perms["command"], command)
                for system in expected_systems:
                    self.assertIn(system, access_perms["allowed_systems"])
```

## Best Practices

1. **Security**
   - Always validate Navy affiliation from certificates
   - Implement proper classification handling
   - Use dual authentication for SIPR access
   - Regular security assessments

2. **Network Management**
   - Maintain proper network isolation
   - Monitor cross-domain attempts
   - Implement traffic filtering
   - Regular network security audits

3. **Audit and Compliance**
   - Comprehensive audit logging
   - Regular access reviews
   - Compliance with Navy security policies
   - Incident response procedures

4. **User Management**
   - Command-based access control
   - Regular user account reviews
   - Proper onboarding/offboarding
   - Training and awareness programs

## Troubleshooting

### Common Issues

1. **SIPR Access Denied**
   ```
   Error: Dual authentication failed
   Solution: Verify secondary authentication system connectivity
   ```

2. **Command Authorization Failed**
   ```
   Error: Command code not recognized
   Solution: Verify command code configuration and authorization
   ```

3. **Classification Level Mismatch**
   ```
   Error: Classification exceeds user clearance
   Solution: Review user clearance and requested classification
   ```

4. **Network Connectivity Issues**
   ```
   Error: Cannot reach Navy Jupiter on SIPR
   Solution: Check network routing and VPN connections
   ```

## Support and Resources

- Navy Jupiter platform documentation
- NMCI support channels
- DoD PKI certificate management
- Navy cybersecurity guidance
- Command-specific support contacts