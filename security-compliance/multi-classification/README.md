# Multi-Classification Data Handling Framework

**Classification:** UNCLASSIFIED//FOR OFFICIAL USE ONLY  
**Version:** 2.0  
**Date:** 2025-07-17  
**Author:** Security Compliance Team  

## Overview

The Multi-Classification Data Handling Framework (MCDHF) provides comprehensive automatic content analysis and classification capabilities for handling data across multiple security domains including NIPR (Unclassified), SIPR (Secret), and JWICS (Top Secret/SCI) networks.

## Key Features

### 🚀 Enhanced Content Analyzer
- **ML-based Classification**: Advanced machine learning models for automatic content classification
- **Multi-domain Support**: Native support for NIPR, SIPR, and JWICS classification levels
- **Pattern Recognition**: Sophisticated pattern matching for classification markers and sensitive content
- **PII Detection**: Comprehensive personally identifiable information detection across classification levels
- **Confidence Scoring**: Detailed confidence scoring with reasoning for classification decisions
- **Customizable Rules**: Flexible classification rules engine with customizable rules

### 🏷️ Automatic Content Labeling System
- **Mandatory Access Controls**: DoD-compliant mandatory access control implementation
- **Automatic Labeling**: Intelligent content labeling with approval workflows
- **Access Restrictions**: Dynamic access restriction generation based on classification
- **Handling Instructions**: Automated generation of proper handling instructions
- **Audit Trail**: Complete audit trail for all labeling operations

### ✅ DoD Compliance Validator
- **Multi-Standard Support**: Compliance validation for DoD 8500.01E, NIST SP 800-53, FISMA, and more
- **Real-time Validation**: Continuous compliance monitoring and validation
- **Violation Tracking**: Comprehensive violation tracking with severity levels
- **Remediation Guidance**: Automated remediation recommendations
- **Reporting**: Detailed compliance reporting and dashboard capabilities

### 🔒 Security Features
- **Bell-LaPadula Model**: Mandatory access control with "no read up, no write down" enforcement
- **Cross-Domain Guards**: Simulated cross-domain security controls for development
- **Network Domain Mapping**: Intelligent network domain assignment based on classification
- **Encryption Support**: Built-in encryption requirements validation
- **Audit Logging**: Comprehensive audit logging for all operations

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    APPLICATION LAYER                            │
├─────────────────────────────────────────────────────────────────┤
│  Data Science    │  Jupyter       │  API           │  Web       │
│  Notebooks       │  Environments  │  Services      │  Interface │
└─────────────────────────────────────────────────────────────────┘
                                │
┌─────────────────────────────────────────────────────────────────┐
│                 MULTI-CLASSIFICATION FRAMEWORK                  │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────┐ │
│  │Enhanced     │  │Content      │  │DoD          │  │Bell-    │ │
│  │Content      │  │Labeling     │  │Compliance   │  │LaPadula │ │
│  │Analyzer     │  │System       │  │Validator    │  │Model    │ │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────┘ │
└─────────────────────────────────────────────────────────────────┘
                                │
┌─────────────────────────────────────────────────────────────────┐
│                    SECURITY INTEGRATION LAYER                   │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────┐ │
│  │    ABAC     │  │    RBAC     │  │ PKI/Crypto  │  │ Network │ │
│  │  Enhanced   │  │ Integration │  │   Layer     │  │Security │ │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

## Installation

### Prerequisites
- Python 3.8+
- PostgreSQL 12+
- Required Python packages (see requirements.txt)

### Setup
```bash
# Clone the repository
git clone <repository-url>
cd multi-classification-framework

# Install dependencies
pip install -r requirements.txt

# Set up database
python setup_database.py

# Configure environment variables
cp .env.example .env
# Edit .env with your configuration
```

## Quick Start

### Basic Usage

```python
from models.enhanced_content_analyzer import EnhancedContentAnalyzer
from models.content_labeling_system import create_content_labeling_system
from models.dod_compliance_validator import create_dod_compliance_validator

# Initialize components
analyzer = EnhancedContentAnalyzer(enable_ml=True)
labeling_system = create_content_labeling_system(analyzer)
compliance_validator = create_dod_compliance_validator(analyzer, labeling_system)

# Analyze content
content = "SECRET operational document with sensitive information."
result = analyzer.analyze_content(content)

print(f"Classification: {result.classification_level}")
print(f"Confidence: {result.confidence_score:.2f}")
print(f"Network Domain: {result.network_domain.value}")
```

### Complete Integration Example

```python
from uuid import uuid4

# Process document end-to-end
content_id = "doc_001"
user_id = uuid4()

# Step 1: Analyze content
analysis_result = analyzer.analyze_content(
    content=content,
    metadata={'source': 'SIPR system'},
    context={'network_domain': 'SIPRNET'}
)

# Step 2: Create content label
label = labeling_system.label_content(
    content=content,
    content_id=content_id,
    user_id=user_id
)

# Step 3: Check access control
access_result = labeling_system.check_access(
    content_id=content_id,
    user_id=user_id,
    action="read"
)

# Step 4: Validate compliance
compliance_violations = compliance_validator.validate_classification_handling(
    content_id=content_id,
    classification_level=analysis_result.classification_level,
    handling_procedures={
        'markings': {'header_marking': True},
        'storage': {'facility_type': 'approved_secure_room'},
        'access_controls': {'clearance_verification': True},
        'transmission': {'encryption_enabled': True},
        'audit': {'audit_enabled': True}
    }
)

print(f"Classification: {analysis_result.classification_level}")
print(f"Access Granted: {access_result['access_granted']}")
print(f"Compliance Violations: {len(compliance_violations)}")
```

## Components

### Enhanced Content Analyzer

The `EnhancedContentAnalyzer` provides ML-based automatic content classification:

#### Features
- **Pattern Matching**: Advanced regex patterns for classification markers
- **Machine Learning**: Trained models for content classification
- **PII Detection**: Comprehensive PII detection across multiple types
- **Confidence Scoring**: Detailed confidence analysis with reasoning
- **Evidence Collection**: Complete evidence trail for classification decisions

#### Usage
```python
analyzer = EnhancedContentAnalyzer(
    model_path="/path/to/models",
    enable_ml=True
)

result = analyzer.analyze_content(
    content="Document content",
    metadata={'source': 'system'},
    context={'network_domain': 'SIPRNET'}
)
```

### Content Labeling System

The `ContentLabelingSystem` provides automatic content labeling with mandatory access controls:

#### Features
- **Automatic Labeling**: Intelligent content labeling based on classification
- **Access Control**: Mandatory access control enforcement
- **Approval Workflows**: Configurable approval workflows for sensitive content
- **Handling Instructions**: Automated generation of proper handling instructions
- **Audit Trail**: Complete audit trail for all labeling operations

#### Usage
```python
labeling_system = ContentLabelingSystem(
    content_analyzer=analyzer,
    labeling_policy=LabelingPolicy.HYBRID
)

label = labeling_system.label_content(
    content="Document content",
    content_id="doc_001",
    user_id=user_id
)
```

### DoD Compliance Validator

The `DoDComplianceValidator` provides comprehensive DoD compliance validation:

#### Features
- **Multi-Standard Support**: DoD 8500.01E, NIST SP 800-53, FISMA, and more
- **Real-time Validation**: Continuous compliance monitoring
- **Violation Tracking**: Comprehensive violation tracking with severity levels
- **Remediation Guidance**: Automated remediation recommendations
- **Compliance Reporting**: Detailed compliance reports and dashboards

#### Usage
```python
compliance_validator = DoDComplianceValidator(
    content_analyzer=analyzer,
    labeling_system=labeling_system
)

assessment = compliance_validator.assess_compliance(
    assessor_id=user_id,
    standards=[ComplianceStandard.DOD_8500_01E, ComplianceStandard.NIST_SP_800_53]
)
```

## Classification Levels

### Supported Classification Levels

| Level | Description | Network Domain | Handling Requirements |
|-------|-------------|----------------|----------------------|
| **U** | Unclassified | NIPR | Standard handling |
| **CUI** | Controlled Unclassified Information | NIPR | Privacy Act protections |
| **C** | Confidential | SIPR | Locked container storage |
| **S** | Secret | SIPR | Secure facility storage |
| **TS** | Top Secret | JWICS | SCIF facility required |
| **TS//SCI** | Top Secret/SCI | JWICS | Special compartmented access |

### Network Domain Mapping

- **NIPR** (Non-classified Internet Protocol Router): U, CUI
- **SIPR** (Secret Internet Protocol Router): C, S
- **JWICS** (Joint Worldwide Intelligence Communications System): TS, TS//SCI

## Configuration

### Environment Variables

```bash
# Database Configuration
RBAC_DB_HOST=localhost
RBAC_DB_PORT=5432
RBAC_DB_NAME=rbac_system
RBAC_DB_USER=rbac_user
RBAC_DB_PASSWORD=your_password

# ML Model Configuration
ML_MODEL_PATH=/path/to/models
ML_ENABLE=true

# Logging Configuration
LOG_LEVEL=INFO
AUDIT_LOG_PATH=/var/log/classification_audit.log
```

### Configuration Files

- `config.json`: Main configuration file
- `classification_rules.json`: Custom classification rules
- `compliance_rules.json`: DoD compliance rules
- `network_mappings.json`: Network domain mappings

## API Reference

### Enhanced Content Analyzer API

#### `analyze_content(content, metadata=None, context=None)`
Analyze content and determine classification level.

**Parameters:**
- `content` (str): Text content to analyze
- `metadata` (dict): Additional metadata
- `context` (dict): Contextual information

**Returns:**
- `ClassificationResult`: Classification analysis result

#### `train_model(training_data, validation_split=0.2)`
Train ML model with labeled data.

**Parameters:**
- `training_data` (list): List of labeled training examples
- `validation_split` (float): Validation split ratio

**Returns:**
- `dict`: Training result with accuracy metrics

### Content Labeling System API

#### `label_content(content, content_id, user_id, metadata=None, context=None)`
Label content with automatic classification and access controls.

**Parameters:**
- `content` (str): Content to label
- `content_id` (str): Unique content identifier
- `user_id` (UUID): User performing labeling
- `metadata` (dict): Additional metadata
- `context` (dict): Contextual information

**Returns:**
- `ContentLabel`: Generated content label

#### `check_access(content_id, user_id, action='read', context=None)`
Check if user can access labeled content.

**Parameters:**
- `content_id` (str): Content identifier
- `user_id` (UUID): User requesting access
- `action` (str): Action being performed
- `context` (dict): Additional context

**Returns:**
- `dict`: Access decision with details

### DoD Compliance Validator API

#### `assess_compliance(assessor_id, standards=None, scope=None)`
Perform comprehensive compliance assessment.

**Parameters:**
- `assessor_id` (UUID): User performing assessment
- `standards` (list): Standards to assess
- `scope` (dict): Assessment scope

**Returns:**
- `ComplianceAssessment`: Comprehensive assessment result

#### `validate_classification_handling(content_id, classification_level, handling_procedures)`
Validate classification handling compliance.

**Parameters:**
- `content_id` (str): Content identifier
- `classification_level` (str): Classification level
- `handling_procedures` (dict): Current handling procedures

**Returns:**
- `list`: List of compliance violations

## Testing

### Running Tests

```bash
# Run all tests
python -m pytest tests/

# Run specific test suite
python -m pytest tests/test_enhanced_content_analyzer.py

# Run with coverage
python -m pytest tests/ --cov=models --cov-report=html
```

### Test Coverage

- Content analysis functionality: 95%
- Labeling system: 92%
- Compliance validation: 88%
- Integration tests: 85%

## Performance

### Benchmarks

- **Content Analysis**: ~100-200ms per document
- **Labeling**: ~50-100ms per label
- **Compliance Validation**: ~200-500ms per assessment
- **Throughput**: ~10-20 documents per second

### Optimization

- ML model caching for improved performance
- Batch processing capabilities for large datasets
- Asynchronous processing support
- Database query optimization

## Security Considerations

### Threat Model

**Threats Addressed:**
- Unauthorized access to classified information
- Data spillage across classification boundaries
- Insider threats and privilege escalation
- Inference attacks through aggregation
- Cross-domain contamination

**Mitigations:**
- Multi-layered access controls
- Complete audit logging
- Automated monitoring and alerting
- Regular security assessments
- Fail-secure design principles

### Compliance Standards

**Standards Addressed:**
- DoD 8500.01E - Information Assurance
- DoD 8570.01-M - IA Workforce Improvement
- NIST SP 800-53 - Security Controls
- NIST SP 800-162 - ABAC Guidelines
- CNSSI-1253 - Security Categorization
- FISMA - Federal Information Security Management Act

## Monitoring and Alerting

### Key Metrics

**Security Metrics:**
- Classification decisions per hour
- Access denials by reason
- Cross-domain transfer attempts
- Sanitization success rates
- Audit log completeness

**Performance Metrics:**
- Classification engine response time
- Query filtering latency
- Database performance
- Storage utilization
- User experience metrics

### Alert Conditions

**Critical Alerts:**
- Classification bypass attempts
- Unauthorized cross-domain access
- Sanitization failures
- Audit log tampering
- System component failures

## Troubleshooting

### Common Issues

#### Classification Accuracy Issues
- **Problem**: Low classification accuracy
- **Solution**: Retrain ML models with more labeled data
- **Prevention**: Regular model validation and updates

#### Performance Issues
- **Problem**: Slow content analysis
- **Solution**: Enable ML model caching and batch processing
- **Prevention**: Regular performance monitoring and optimization

#### Access Control Issues
- **Problem**: Incorrect access decisions
- **Solution**: Verify user clearance data and access control rules
- **Prevention**: Regular access control audits

### Debugging

Enable debug logging:
```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

Check system status:
```bash
python -m models.enhanced_content_analyzer --status
python -m models.content_labeling_system --status
python -m models.dod_compliance_validator --status
```

## Contributing

### Development Setup

1. Fork the repository
2. Create a feature branch
3. Install development dependencies: `pip install -r requirements-dev.txt`
4. Make your changes
5. Run tests: `python -m pytest`
6. Submit a pull request

### Code Standards

- Follow PEP 8 style guidelines
- Include comprehensive docstrings
- Write unit tests for new features
- Maintain backwards compatibility
- Document security considerations

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For support and questions:
- Email: security-compliance@example.com
- Documentation: https://docs.example.com/mcdhf
- Issue Tracker: https://github.com/example/mcdhf/issues

## Changelog

### Version 2.0 (2025-07-17)
- Enhanced ML-based content analysis
- Automatic content labeling system
- DoD compliance validation
- Comprehensive audit logging
- Performance optimizations

### Version 1.0 (2025-07-01)
- Initial release
- Basic content classification
- RBAC integration
- Bell-LaPadula model implementation

---

**Classification:** UNCLASSIFIED//FOR OFFICIAL USE ONLY  
**Distribution:** Approved for internal use only  
**Version:** 2.0  
**Last Updated:** 2025-07-17