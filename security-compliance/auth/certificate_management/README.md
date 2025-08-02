# Certificate Management Module for CAC/PIV Smart Cards

This module provides comprehensive certificate management functionality for CAC/PIV smart cards with special focus on DoD PKI compliance and security requirements.

## Overview

The Certificate Management Module integrates seamlessly with the existing CAC/PIV authentication infrastructure to provide:

- **Certificate Extraction**: Enhanced extraction from CAC/PIV cards via PKCS#11
- **DoD PKI Validation**: Comprehensive certificate chain validation against DoD PKI standards
- **Trust Store Management**: Automated management of DoD root and intermediate CA certificates
- **Certificate Parsing**: Advanced parsing and metadata extraction with DoD-specific identifiers
- **Expiration Monitoring**: Automated monitoring and alerting for certificate expiration
- **Unified Management**: Single interface for all certificate operations

## Architecture

```
Certificate Management Module
├── Certificate Extractor        # PKCS#11-based extraction from smart cards
├── DoD PKI Validator           # Certificate chain validation engine
├── Trust Store Manager         # CA certificate management
├── Certificate Parser          # Metadata extraction and analysis
├── Expiration Monitor          # Automated expiration monitoring
└── Certificate Manager         # Unified management interface
```

## Components

### 1. Certificate Extractor (`certificate_extractor.py`)

Enhanced certificate extraction from CAC/PIV smart cards using PKCS#11 interface.

**Key Features:**
- Auto-detection of PKCS#11 libraries
- Enhanced metadata extraction for DoD certificates
- Certificate type classification (Authentication, Signing, Encryption, Card Auth)
- DoD-specific identifier extraction (EDIPI, FASC-N, PIV GUID)
- Comprehensive error handling and logging

**Usage Example:**
```python
from certificate_management import CertificateExtractor

extractor = CertificateExtractor(enable_enhanced_extraction=True)
certificates = extractor.extract_all_certificates(include_metadata=True)

for cert_info in certificates:
    print(f"Type: {cert_info.certificate_type}")
    print(f"EDIPI: {cert_info.edipi}")
    print(f"Subject: {cert_info.subject_dn}")
```

### 2. DoD PKI Validator (`dod_pki_validator.py`)

Comprehensive certificate validation engine implementing DoD PKI standards.

**Key Features:**
- Multiple validation levels (Basic, Standard, Strict, Maximum)
- DoD certificate policy validation
- Certificate chain path validation
- Key usage and extension validation
- Policy enforcement modes
- Detailed validation reporting

**Usage Example:**
```python
from certificate_management import DoDPKIValidator, ValidationLevel, ValidationContext

validator = DoDPKIValidator()
context = ValidationContext(
    validation_level=ValidationLevel.STRICT,
    require_dod_policies=True,
    check_revocation=True
)

result = validator.validate_certificate_chain(certificate, context=context)
print(f"Valid: {result.is_valid}")
print(f"DoD Compliance: {result.dod_compliance_level}")
```

### 3. Trust Store Manager (`trust_store_manager.py`)

Automated management of trusted CA certificates with DoD PKI support.

**Key Features:**
- Automated DoD PKI certificate updates
- Secure certificate storage with SQLite database
- Certificate validation and metadata tracking
- Trust store statistics and monitoring
- Export capabilities for various formats

**Usage Example:**
```python
from certificate_management import TrustStoreManager

trust_manager = TrustStoreManager(enable_auto_update=True)

# Add certificate to trust store
with open('ca_cert.pem', 'rb') as f:
    cert_data = f.read()

trust_info = trust_manager.add_certificate(cert_data)
print(f"Added CA: {trust_info.subject_dn}")

# Update from DoD PKI
stats = trust_manager.update_from_dod_pki()
print(f"Updated {stats['downloaded']} certificates")
```

### 4. Certificate Parser (`certificate_parser.py`)

Advanced certificate parsing and metadata extraction with DoD-specific support.

**Key Features:**
- Comprehensive certificate metadata extraction
- DoD identifier parsing (EDIPI, FASC-N, PIV GUID, Agency codes)
- Certificate categorization and classification
- Security assessment and compliance checking
- Detailed parsing with error handling

**Usage Example:**
```python
from certificate_management import CertificateParser

parser = CertificateParser(enable_enhanced_parsing=True)
metadata = parser.parse_certificate(certificate)

print(f"Category: {metadata.category}")
print(f"EDIPI: {metadata.dod_identifiers.edipi}")
print(f"Assurance Level: {metadata.assurance_level}")
print(f"Security Warnings: {len(metadata.security_warnings)}")
```

### 5. Expiration Monitor (`expiration_monitor.py`)

Automated certificate expiration monitoring with alerting capabilities.

**Key Features:**
- Background monitoring with configurable intervals
- Multi-level alerting (Info, Warning, Critical, Emergency)
- Email and webhook notifications
- Renewal instruction generation
- Impact assessment and compliance tracking

**Usage Example:**
```python
from certificate_management import ExpirationMonitor, MonitoringConfiguration

config = MonitoringConfiguration(
    critical_threshold=7,
    warning_threshold=30,
    enable_email_alerts=True,
    smtp_server="mail.example.com"
)

monitor = ExpirationMonitor(config)
monitor.start_monitoring()

# Add certificate for monitoring
cert_id = monitor.add_certificate_for_monitoring(certificate)

# Check for alerts
alerts = monitor.get_active_alerts()
for alert in alerts:
    print(f"Certificate {alert.subject_dn} expires in {alert.days_until_expiry} days")
```

### 6. Certificate Manager (`certificate_manager.py`)

Unified interface providing comprehensive certificate management capabilities.

**Key Features:**
- Single interface for all certificate operations
- Integrated validation, parsing, and monitoring
- Smart card certificate extraction
- Trust store integration
- Comprehensive reporting and statistics

**Usage Example:**
```python
from certificate_management import CertificateManager, CertificateManagementConfig

config = CertificateManagementConfig(
    validation_level=ValidationLevel.STRICT,
    enable_expiration_monitoring=True,
    enable_dod_compliance_checking=True
)

manager = CertificateManager(config)

# Extract from smart card
smart_card_certs = manager.extract_smart_card_certificates(validate=True)

# Load from file
managed_cert = manager.load_certificate_file('cert.pem', validate=True)

# Comprehensive check
results = manager.perform_comprehensive_check()
print(f"Checked {results['certificates_checked']} certificates")

# Get statistics
stats = manager.get_management_statistics()
print(f"Total certificates: {stats['total_certificates']}")
print(f"DoD certificates: {stats['dod_certificates']}")
```

## Integration with Existing System

The Certificate Management Module integrates seamlessly with the existing CAC/PIV authentication system:

### Integration Points

1. **PKCS#11 Layer Integration**
   - Uses existing PKCS#11 infrastructure from `cac_piv_integration.py`
   - Extends functionality with enhanced metadata extraction
   - Compatible with existing middleware detection

2. **Certificate Validation Enhancement**
   - Enhances existing `certificate_validators.py` with DoD-specific validation
   - Provides detailed compliance reporting
   - Integrates with existing CRL and OCSP checking

3. **Trust Store Integration**
   - Extends trust store capabilities beyond basic certificate storage
   - Automated updates and maintenance
   - Integration with existing CA certificate management

4. **Monitoring Integration**
   - Integrates with existing audit logging from `security_managers.py`
   - Provides detailed certificate lifecycle tracking
   - Automated alerting for certificate events

### Code Integration Example

```python
# Enhanced CAC authentication with certificate management
from security_compliance.auth.cac_piv_integration import CACAuthenticationManager
from security_compliance.auth.certificate_management import CertificateManager

class EnhancedCACAuthenticator:
    def __init__(self):
        self.cac_auth = CACAuthenticationManager()
        self.cert_manager = CertificateManager()
    
    def authenticate_with_monitoring(self, pin: str, user_id: str = None):
        # Perform CAC authentication
        credentials = self.cac_auth.authenticate_user(pin, user_id)
        
        if credentials:
            # Extract and manage certificates
            certs = self.cert_manager.extract_smart_card_certificates(
                validate=True, monitor=True
            )
            
            # Enhanced validation
            for cert in certs:
                if cert.validation_result and not cert.validation_result.is_valid:
                    print(f"Certificate validation warning: {cert.validation_result.error_message}")
            
            return credentials, certs
        
        return None, []
```

## Configuration

### Environment Variables

```bash
# PKCS#11 Library Path (optional - auto-detected if not set)
export PKCS11_LIBRARY_PATH="/usr/lib/opensc-pkcs11.so"

# Trust Store Path (optional - uses default if not set)
export CAC_TRUST_STORE_PATH="/etc/ssl/certs/dod-pki"

# Monitoring Database Path (optional)
export CAC_MONITORING_DB_PATH="/var/lib/cac/monitoring.db"

# Email Configuration for Alerts
export SMTP_SERVER="mail.example.com"
export SMTP_USERNAME="alerts@example.com"
export SMTP_PASSWORD="password"
```

### Configuration Files

**Certificate Management Configuration:**
```python
config = CertificateManagementConfig(
    # PKCS#11 Configuration
    pkcs11_library_path="/usr/lib/opensc-pkcs11.so",
    enable_pkcs11_auto_detect=True,
    
    # Validation Configuration
    validation_level=ValidationLevel.STRICT,
    enable_revocation_checking=True,
    enable_ocsp=True,
    enable_crl=True,
    
    # Trust Store Configuration
    trust_store_path="/etc/ssl/certs/dod-pki",
    enable_auto_update=True,
    update_interval_hours=24,
    
    # Monitoring Configuration
    enable_expiration_monitoring=True,
    
    # Enhanced Features
    enable_enhanced_parsing=True,
    enable_dod_compliance_checking=True
)
```

**Monitoring Configuration:**
```python
monitoring_config = MonitoringConfiguration(
    # Alert Thresholds
    critical_threshold=7,      # days
    warning_threshold=30,      # days
    info_threshold=90,         # days
    
    # Check Intervals
    check_interval_hours=24,
    urgent_check_interval_hours=6,
    
    # Notification Settings
    enable_email_alerts=True,
    smtp_server="mail.example.com",
    smtp_port=587,
    smtp_username="alerts@example.com",
    smtp_password="password",
    
    # Recipients
    default_recipients=["admin@example.com"],
    critical_recipients=["security@example.com", "admin@example.com"],
    
    # Filtering
    monitor_ca_certificates=True,
    monitor_end_entity_certificates=True,
    prioritize_dod_certificates=True
)
```

## DoD Compliance Features

### Certificate Policy Validation

The module implements comprehensive DoD certificate policy validation:

- **DoD Basic** (2.16.840.1.101.3.2.1.3.1)
- **DoD Medium Software** (2.16.840.1.101.3.2.1.3.6)
- **DoD Medium Hardware** (2.16.840.1.101.3.2.1.3.7)
- **DoD Medium Hardware PIV-Auth** (2.16.840.1.101.3.2.1.3.13)
- **DoD Medium CBP** (2.16.840.1.101.3.2.1.3.15)
- **DoD High Hardware** (2.16.840.1.101.3.2.1.3.16)

### DoD Identifier Extraction

Automatic extraction of DoD-specific identifiers:

- **EDIPI** (Electronic Data Interchange Personal Identifier)
- **FASC-N** (Federal Agency Smart Card Number)
- **PIV GUID** (Personal Identity Verification Globally Unique Identifier)
- **DoD ID** (Department of Defense Identifier)
- **Agency Codes** (Organizational affiliation codes)

### Compliance Reporting

Detailed compliance reporting includes:

- Certificate policy compliance status
- Key usage validation against DoD requirements
- Hardware protection verification
- Assurance level determination
- Renewal instruction generation

## Security Features

### Certificate Validation

- **Multi-level validation** with configurable strictness
- **Certificate chain validation** against DoD PKI hierarchy
- **Revocation checking** via CRL and OCSP
- **Policy enforcement** with multiple modes
- **Extension validation** for required and optional extensions

### Secure Storage

- **Encrypted database storage** for certificate metadata
- **Integrity protection** for trust store certificates
- **Secure key management** for cached credentials
- **Audit logging** for all certificate operations

### Monitoring and Alerting

- **Real-time monitoring** with background processing
- **Multi-channel alerting** via email, webhook, and syslog
- **Escalation policies** based on certificate criticality
- **Impact assessment** for certificate expiration

## Performance Considerations

### Caching

- **Validation result caching** to improve performance
- **Certificate metadata caching** for repeated operations
- **Trust store caching** with automatic refresh
- **Configurable cache timeouts** for different components

### Scalability

- **Concurrent processing** support for multiple certificates
- **Database indexing** for efficient queries
- **Batch operations** for bulk certificate management
- **Resource monitoring** and cleanup

### Optimization

- **Lazy loading** of certificate components
- **Efficient PKCS#11 operations** with connection pooling
- **Background processing** for non-critical operations
- **Memory management** with automatic cleanup

## Troubleshooting

### Common Issues

1. **PKCS#11 Library Not Found**
   ```
   Error: PKCS#11 library not found
   Solution: Install OpenSC or specify library path in configuration
   ```

2. **Smart Card Not Detected**
   ```
   Error: No smart cards detected
   Solution: Check card reader connection and driver installation
   ```

3. **Certificate Validation Failures**
   ```
   Error: Certificate validation failed
   Solution: Check trust store configuration and network connectivity for CRL/OCSP
   ```

4. **Monitoring Database Issues**
   ```
   Error: Failed to initialize monitoring database
   Solution: Check database permissions and disk space
   ```

### Debug Mode

Enable debug logging for troubleshooting:

```python
import logging
logging.basicConfig(level=logging.DEBUG)

# Component-specific debugging
logger = logging.getLogger('certificate_management')
logger.setLevel(logging.DEBUG)
```

### Log Analysis

Key log messages to monitor:

- `Certificate extraction successful` - Normal operation
- `Certificate validation failed` - Validation issues
- `Trust store update completed` - Maintenance operations
- `Expiration alert generated` - Monitoring alerts
- `PKCS#11 operation failed` - Smart card issues

## API Reference

### Core Classes

- **CertificateExtractor**: PKCS#11-based certificate extraction
- **DoDPKIValidator**: DoD PKI compliant validation engine
- **TrustStoreManager**: Automated CA certificate management
- **CertificateParser**: Advanced certificate parsing and analysis
- **ExpirationMonitor**: Automated expiration monitoring and alerting
- **CertificateManager**: Unified certificate management interface

### Data Classes

- **CertificateInfo**: Complete certificate extraction results
- **ValidationResult**: Detailed validation outcome
- **TrustedCAInfo**: Trust store certificate information
- **CertificateMetadata**: Comprehensive certificate metadata
- **ExpirationAlert**: Certificate expiration alert details
- **ManagedCertificate**: Unified certificate management object

For detailed API documentation, see the individual module docstrings and type hints.

## Testing

The module includes comprehensive tests covering all functionality:

```bash
# Run all tests
python -m pytest security-compliance/auth/certificate_management/

# Run specific test module
python -m pytest security-compliance/auth/certificate_management/test_certificate_management.py

# Run with coverage
python -m pytest --cov=certificate_management

# Run integration tests only
python -m pytest -k "integration"
```

## License

This module is part of the Data Science Learning Handbook Security Compliance system and follows the same licensing terms as the parent project.

## Contributing

When contributing to this module:

1. Ensure all tests pass
2. Add tests for new functionality
3. Update documentation for API changes
4. Follow DoD security guidelines
5. Test with actual CAC/PIV cards when possible

## Support

For support and questions:

- Check the troubleshooting section above
- Review existing test cases for usage examples
- Consult the main project documentation
- Submit issues through the project's issue tracking system