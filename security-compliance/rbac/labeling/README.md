# Data Labeling System with Mandatory Access Control

**Classification:** UNCLASSIFIED//FOR OFFICIAL USE ONLY  
**Version:** 1.0.0  
**Author:** Security Compliance Team  
**Date:** 2025-07-17

## Executive Summary

The Data Labeling System provides comprehensive mandatory access control (MAC) enforcement for multi-classification data handling across NIPR, SIPR, and JWICS networks. The system implements the Bell-LaPadula security model, automated label validation, inheritance mechanisms, and complete audit trails for DoD compliance.

## System Architecture

### Core Components

1. **Database Schema** (`schema/`)
   - Comprehensive PostgreSQL schema with mandatory access controls
   - Support for classification levels, compartments, and caveats
   - Complete audit trail and compliance tracking
   - Performance optimizations and materialized views

2. **Label Models** (`models/`)
   - Core data label models with validation
   - Inheritance and propagation mechanisms
   - Validation rules and compliance checking
   - Integration with existing RBAC/ABAC systems

3. **Enforcement Engines** (`engines/`)
   - MAC enforcement with Bell-LaPadula model
   - Label validation and verification
   - Access control decision making
   - Audit and compliance tracking

4. **RESTful API** (`api/`)
   - Complete API for label management
   - Authentication and authorization
   - Validation and compliance endpoints
   - Statistics and reporting

## Features

### 🔐 Security Features

- **Mandatory Access Control (MAC)**: Bell-LaPadula "no read up, no write down" enforcement
- **Classification Levels**: Support for UNCLASSIFIED, CUI, CONFIDENTIAL, SECRET, TOP SECRET, TOP SECRET//SCI
- **Network Domain Enforcement**: NIPRNET, SIPRNET, JWICS domain restrictions
- **Compartment Support**: SCI compartments (SI, TK, G, HCS, etc.)
- **Caveat Handling**: NOFORN, ORCON, PROPIN, FISA, RSEN
- **Emergency Override**: Controlled emergency access with enhanced auditing

### 📊 Label Management

- **Automated Classification**: ML-based content analysis for classification recommendations
- **Manual Override**: Human-in-the-loop classification with authority validation
- **Label Inheritance**: Automatic propagation of labels to derived data
- **Validation Engine**: Comprehensive validation with DoD compliance rules
- **Lifecycle Management**: Automated expiration and review scheduling

### 🔍 Audit and Compliance

- **Complete Audit Trail**: Every label operation logged with metadata
- **Compliance Reporting**: DoD 5200.01, NIST SP 800-53 compliance
- **Cross-Domain Tracking**: Audit trail for data transfers between domains
- **Violation Detection**: Automatic detection of policy violations
- **Metrics Collection**: Performance and usage statistics

### 🌐 Integration

- **ABAC Integration**: Seamless integration with existing ABAC policy engine
- **RBAC Compatibility**: Works with existing role-based access control
- **Database Integration**: PostgreSQL with existing RBAC schema
- **API Integration**: RESTful APIs for system integration

## Quick Start

### 1. Database Setup

```sql
-- Deploy the schema
\i schema/03_data_labeling_schema.sql

-- Run migrations
\i schema/04_data_labeling_migrations.sql

-- Verify deployment
SELECT * FROM data_labeling.verify_deployment();
```

### 2. Python Environment Setup

```bash
# Install dependencies
pip install -r requirements.txt

# Set up database connection
export DATABASE_URL="postgresql://user:password@localhost/database"

# Initialize the system
python -c "from models.label_models import DataLabel; print('System ready')"
```

### 3. API Deployment

```bash
# Start the API server
cd api/
python label_management_api.py

# Test API health
curl http://localhost:5000/health
```

### 4. Basic Usage

```python
from models.label_models import DataLabel, ClassificationLevel
from engines.mac_enforcement_engine import MACEnforcementEngine
from models.validation_models import LabelValidator

# Create a label
label = DataLabel(
    data_object_id="dataset-001",
    data_object_type="dataset",
    classification_level="SECRET",
    network_domain="SIPRNET"
)

# Validate the label
validator = LabelValidator()
validation_result = validator.validate_label(label)

# Check access
mac_engine = MACEnforcementEngine()
access_result = mac_engine.enforce_access(
    user_id=user_id,
    label_id=label.label_id,
    action="read"
)
```

## API Reference

### Label Management

- `GET /api/v1/labels` - List accessible labels
- `POST /api/v1/labels` - Create new label
- `GET /api/v1/labels/{id}` - Get label details
- `PUT /api/v1/labels/{id}` - Update label
- `DELETE /api/v1/labels/{id}` - Delete label

### Validation and Compliance

- `POST /api/v1/labels/{id}/validate` - Validate label
- `POST /api/v1/labels/{id}/compliance` - Check compliance
- `GET /api/v1/labels/{id}/inheritance` - Get inheritance info
- `POST /api/v1/labels/{id}/access` - Check access permissions

### Statistics and Reporting

- `GET /api/v1/labels/statistics` - Get label statistics
- `GET /api/v1/audit/reports` - Generate compliance reports
- `GET /api/v1/metrics` - Get system metrics

## Configuration

### Database Configuration

The system requires PostgreSQL 12+ with the following extensions:
- `uuid-ossp` for UUID generation
- `pgcrypto` for cryptographic functions
- `pg_trgm` for text search
- `hstore` for key-value storage

### Environment Variables

```bash
# Database connection
DATABASE_URL=postgresql://user:password@localhost/database

# API configuration
FLASK_ENV=production
FLASK_SECRET_KEY=your-secret-key-here

# Security settings
ENABLE_EMERGENCY_OVERRIDE=true
AUDIT_ALL_DECISIONS=true
STRICT_BELL_LAPADULA=true

# Performance settings
CACHE_TTL_MINUTES=5
MAX_LABELS_PER_QUERY=1000
```

### Security Configuration

```python
# MAC enforcement settings
mac_engine = MACEnforcementEngine()
mac_engine.strict_mode = True  # Strict Bell-LaPadula
mac_engine.audit_all_decisions = True  # Audit everything
mac_engine.emergency_bypass_enabled = True  # Allow emergency access
```

## Classification Guidelines

### Classification Levels

| Level | Code | Description | Network |
|-------|------|-------------|---------|
| UNCLASSIFIED | U | Public information | NIPRNET |
| CUI | CUI | Controlled Unclassified Information | NIPRNET |
| CONFIDENTIAL | C | Confidential information | SIPRNET |
| SECRET | S | Secret information | SIPRNET |
| TOP SECRET | TS | Top Secret information | JWICS |
| TOP SECRET//SCI | TS_SCI | Top Secret with SCI | JWICS |

### Compartments

| Code | Name | Description |
|------|------|-------------|
| SI | Special Intelligence | Communications intelligence |
| TK | Talent Keyhole | Imagery intelligence |
| G | Gamma | Extremely sensitive sources |
| HCS | HUMINT Control System | Human intelligence |
| KV | Klondike | Geospatial intelligence |
| B | Bravo | Measurement and signature intelligence |
| ECI | Extremely Sensitive Information | Extremely sensitive compartmented information |

### Caveats

| Code | Name | Description |
|------|------|-------------|
| NOFORN | No Foreign Nationals | Not releasable to foreign nationals |
| ORCON | Originator Controlled | Controlled by originator |
| PROPIN | Proprietary Information | Contains proprietary information |
| FISA | Foreign Intelligence Surveillance Act | Derived from FISA sources |
| RSEN | Releasable to Specific Nations | Releasable to specific allied nations |

## Deployment Guide

### Production Deployment

1. **Database Setup**
   ```sql
   -- Create database and user
   CREATE DATABASE data_labeling_prod;
   CREATE USER label_app WITH PASSWORD 'secure_password';
   GRANT ALL PRIVILEGES ON DATABASE data_labeling_prod TO label_app;
   
   -- Deploy schema
   \c data_labeling_prod
   \i schema/03_data_labeling_schema.sql
   \i schema/04_data_labeling_migrations.sql
   ```

2. **Application Deployment**
   ```bash
   # Clone repository
   git clone <repository-url>
   cd data-science-learning-handbook/security-compliance/rbac/labeling
   
   # Install dependencies
   pip install -r requirements.txt
   
   # Configure environment
   cp .env.example .env
   # Edit .env with production settings
   
   # Start application
   gunicorn -w 4 -b 0.0.0.0:5000 api.label_management_api:app
   ```

3. **Monitoring Setup**
   ```bash
   # Set up log monitoring
   tail -f /var/log/label_system.log
   
   # Set up metrics collection
   python scripts/collect_metrics.py
   ```

### Scheduled Tasks

Set up the following scheduled tasks:

```bash
# Refresh materialized views (hourly)
0 * * * * psql -d data_labeling_prod -c "SELECT data_labeling.refresh_materialized_views();"

# Cleanup old audit logs (daily)
0 2 * * * psql -d data_labeling_prod -c "SELECT data_labeling.cleanup_old_audit_logs();"

# Database consistency check (weekly)
0 3 * * 0 psql -d data_labeling_prod -c "SELECT * FROM data_labeling.validate_database_consistency();"

# Label lifecycle management (daily)
0 4 * * * python scripts/process_label_lifecycle.py
```

## Testing

### Unit Tests

```bash
# Run all tests
python -m pytest tests/

# Run specific test modules
python -m pytest tests/test_label_models.py
python -m pytest tests/test_mac_enforcement.py
python -m pytest tests/test_validation.py
```

### Integration Tests

```bash
# Test API endpoints
python -m pytest tests/test_api.py

# Test database operations
python -m pytest tests/test_database.py

# Test end-to-end workflows
python -m pytest tests/test_e2e.py
```

### Performance Tests

```bash
# Load testing
python tests/load_test.py

# Stress testing
python tests/stress_test.py
```

## Troubleshooting

### Common Issues

1. **Database Connection Issues**
   ```bash
   # Check database connectivity
   psql -h localhost -U label_app -d data_labeling_prod -c "SELECT 1;"
   
   # Check for missing extensions
   psql -d data_labeling_prod -c "SELECT * FROM pg_extension;"
   ```

2. **Permission Errors**
   ```sql
   -- Check user permissions
   SELECT * FROM information_schema.table_privileges 
   WHERE grantee = 'label_app';
   
   -- Grant missing permissions
   GRANT USAGE ON SCHEMA data_labeling TO label_app;
   GRANT ALL ON ALL TABLES IN SCHEMA data_labeling TO label_app;
   ```

3. **Validation Failures**
   ```python
   # Debug validation issues
   from models.validation_models import LabelValidator
   validator = LabelValidator()
   result = validator.validate_label(label)
   print(result.to_dict())
   ```

### Performance Issues

1. **Slow Query Performance**
   ```sql
   -- Check query performance
   EXPLAIN ANALYZE SELECT * FROM data_labeling.data_labels WHERE classification_level = 'SECRET';
   
   -- Refresh materialized views
   SELECT data_labeling.refresh_materialized_views();
   ```

2. **High Memory Usage**
   ```bash
   # Monitor memory usage
   ps aux | grep python
   
   # Check database memory
   psql -c "SELECT * FROM pg_stat_activity;"
   ```

## Security Considerations

### Access Control

- All API endpoints require authentication
- Role-based access control for administrative functions
- Audit trail for all operations
- Rate limiting on API endpoints

### Data Protection

- Encryption at rest and in transit
- Secure key management
- Regular security assessments
- Compliance with DoD standards

### Monitoring

- Real-time security monitoring
- Automated threat detection
- Incident response procedures
- Regular security audits

## Compliance

### DoD Standards

- **DoD 5200.01**: Information Security Program
- **DoD 8570.01**: IA Workforce Improvement Program
- **DoD 8500.01**: Information Assurance (IA)

### NIST Standards

- **NIST SP 800-53**: Security and Privacy Controls
- **NIST SP 800-162**: ABAC Guidelines

### Audit Requirements

- Complete audit trail for all operations
- Quarterly compliance reviews
- Annual security assessments
- Incident reporting procedures

## Support

### Documentation

- API documentation: `/docs/api/`
- Database schema: `/docs/schema/`
- User guides: `/docs/user/`
- Administrator guides: `/docs/admin/`

### Contact Information

- **Technical Support**: security-compliance@company.mil
- **Security Issues**: security-incident@company.mil
- **General Questions**: data-labeling-support@company.mil

### Contributing

1. Fork the repository
2. Create a feature branch
3. Make changes with tests
4. Submit a pull request
5. Security review required

## License

This software is developed for the U.S. Government and is subject to government use rights. See LICENSE file for details.

## Version History

- **1.0.0** (2025-07-17): Initial release with full MAC enforcement
- **1.0.1** (TBD): Bug fixes and performance improvements
- **1.1.0** (TBD): Enhanced ML classification capabilities
- **2.0.0** (TBD): Multi-domain support and advanced analytics

---

**Classification:** UNCLASSIFIED//FOR OFFICIAL USE ONLY  
**Distribution:** Authorized Personnel Only  
**Last Updated:** 2025-07-17