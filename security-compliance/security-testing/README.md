# Security Testing Framework

## Overview

Enterprise-grade security testing framework designed for DoD and federal environments. Provides comprehensive automated security testing capabilities including SAST, DAST, vulnerability assessment, penetration testing, and continuous security monitoring.

## Architecture

The Security Testing Framework consists of several integrated components:

### Core Components

1. **Security Test Engine** (`security_test_engine.py`)
   - Core security testing orchestration
   - SAST and DAST engines
   - Vulnerability scanning and assessment
   - Integration with existing audit infrastructure

2. **Automated Scanning Pipeline** (`security_scanning_pipeline.py`)
   - CI/CD integration for continuous security testing
   - Automated SAST/DAST pipeline orchestration
   - Quality gates and deployment controls
   - Real-time security monitoring

3. **Vulnerability Assessment Framework** (`vulnerability_assessment_framework.py`)
   - Intelligent vulnerability prioritization using CVSS, EPSS, and SSVC
   - Risk-based remediation planning
   - SLA-based tracking and compliance reporting
   - Business impact assessment

4. **Penetration Testing Framework** (`penetration_testing_framework.py`)
   - Automated penetration testing capabilities
   - Web application, network, and service testing
   - Exploit execution and post-exploitation analysis
   - Comprehensive reporting and remediation guidance

## Key Features

### Security Testing Capabilities
- **Static Application Security Testing (SAST)**
  - Multi-language support (Python, JavaScript, Java, C#, C++, Go, PHP, Ruby)
  - Pattern-based vulnerability detection
  - Integration with development workflows

- **Dynamic Application Security Testing (DAST)**
  - Automated web application testing
  - XSS, SQL injection, command injection detection
  - API security testing

- **Vulnerability Assessment**
  - CVSS 3.1 scoring and prioritization
  - EPSS (Exploit Prediction Scoring System) integration
  - Custom enterprise and DoD risk scoring models
  - Automated remediation planning

- **Penetration Testing**
  - Automated reconnaissance and scanning
  - Service enumeration and exploitation
  - Privilege escalation testing
  - Comprehensive reporting

### Enterprise Integration
- **CI/CD Pipeline Integration**
  - GitHub Actions, Jenkins, GitLab CI support
  - Automated security gates
  - Real-time vulnerability feedback

- **Compliance and Governance**
  - DoD STIGs and NIST SP 800-53 compliance
  - OWASP ASVS alignment
  - Automated compliance reporting

- **Audit and Monitoring**
  - Integration with existing audit infrastructure
  - Real-time security event correlation
  - Tamper-proof audit storage

## Installation and Setup

### Prerequisites

```bash
# Python dependencies
pip install aiohttp aiofiles numpy pathlib asyncio
pip install nmap python-nmap paramiko pymongo redis psycopg2 pymysql
pip install cryptography requests beautifulsoup4

# System dependencies (Ubuntu/Debian)
sudo apt-get update
sudo apt-get install nmap masscan nikto sqlmap

# Docker (optional, for containerized testing)
sudo apt-get install docker.io docker-compose
```

### Configuration

1. **Database Setup**
```python
# Initialize vulnerability assessment database
from security_testing.vulnerability_assessment_framework import create_vulnerability_assessment_framework

# Database will be automatically created on first run
```

2. **Pipeline Configuration**
```python
# Configure security scanning pipeline
pipeline_config = {
    "pipeline_name": "production_security_pipeline",
    "enabled": True,
    "stages_enabled": {
        "sast": True,
        "dast": True,
        "dependency_scan": True,
        "vulnerability_assessment": True,
        "compliance_check": True
    },
    "quality_gates": {
        "block_on_critical": True,
        "block_on_high_threshold": 5,
        "security_score_threshold": 70
    }
}
```

## Usage Examples

### Basic Security Testing

```python
import asyncio
from security_testing.security_test_engine import SecurityTestEngine, SecurityTestType

async def run_security_test():
    # Initialize security test engine
    security_engine = SecurityTestEngine(
        audit_validator=audit_validator,
        audit_logger=audit_logger,
        monitoring_system=monitoring_system,
        real_time_alerting=alerting_system
    )
    
    # Run comprehensive security assessment
    report = await security_engine.run_comprehensive_security_assessment(
        target_path="/path/to/source/code",
        target_url="https://example.com",
        test_types=[
            SecurityTestType.SAST,
            SecurityTestType.DAST,
            SecurityTestType.VULNERABILITY_SCAN
        ]
    )
    
    print(f"Security assessment completed: {len(report.security_findings)} findings")
    print(f"Critical: {report.critical_findings}, High: {report.high_findings}")

# Run the test
asyncio.run(run_security_test())
```

### Automated Pipeline Integration

```python
from security_testing.security_scanning_pipeline import SecurityScanningPipeline, ScanTrigger

async def setup_ci_cd_pipeline():
    # Create pipeline
    pipeline = SecurityScanningPipeline(
        security_test_engine=security_engine,
        audit_logger=audit_logger,
        monitoring_system=monitoring_system,
        real_time_alerting=alerting_system
    )
    
    # Initialize pipeline
    await pipeline.initialize()
    
    # Create pipeline configuration
    config_id = await pipeline.create_pipeline_config({
        "pipeline_name": "ci_cd_security_pipeline",
        "source_path": "./src",
        "target_url": "https://staging.example.com",
        "triggers": [ScanTrigger.CODE_COMMIT, ScanTrigger.PULL_REQUEST],
        "notifications": {
            "slack_webhook": "https://hooks.slack.com/...",
            "email_recipients": ["security@company.com"]
        }
    })
    
    # Trigger pipeline execution
    execution_id = await pipeline.trigger_pipeline(
        config_id, 
        ScanTrigger.MANUAL,
        "security_team"
    )
    
    print(f"Pipeline execution started: {execution_id}")
```

### Vulnerability Assessment and Prioritization

```python
from security_testing.vulnerability_assessment_framework import (
    VulnerabilityAssessmentFramework, VulnerabilityContext, AssetCriticality
)

async def assess_vulnerabilities():
    # Create assessment framework
    vuln_framework = VulnerabilityAssessmentFramework(
        audit_logger=audit_logger,
        monitoring_system=monitoring_system,
        real_time_alerting=alerting_system
    )
    
    # Define vulnerability context
    context = VulnerabilityContext(
        asset_id="web-server-01",
        asset_name="Production Web Server",
        asset_criticality=AssetCriticality.CRITICAL,
        network_exposure="external",
        business_impact_score=9.0
    )
    
    # Assess vulnerability
    assessment = await vuln_framework.assess_vulnerability(
        security_finding=finding,
        context=context
    )
    
    print(f"Vulnerability Priority: {assessment.priority_level}")
    print(f"CVSS Score: {assessment.cvss_v3_score}")
    print(f"Enterprise Risk Score: {assessment.enterprise_risk_score}")
    print(f"Due Date: {assessment.due_date}")
    
    # Create remediation plan
    plan = await vuln_framework.create_remediation_plan(
        vulnerability_ids=[assessment.vulnerability_id],
        plan_name="Critical Infrastructure Remediation"
    )
    
    print(f"Remediation Plan: {plan.plan_name}")
    print(f"Estimated Effort: {plan.estimated_effort_hours} hours")
    print(f"Estimated Cost: ${plan.estimated_cost:,.2f}")
```

### Penetration Testing

```python
from security_testing.penetration_testing_framework import (
    PenetrationTestingFramework, PenetrationTestTarget, TestScope
)

async def run_penetration_test():
    # Create penetration testing framework
    pentest_framework = PenetrationTestingFramework(
        audit_logger=audit_logger,
        monitoring_system=monitoring_system,
        real_time_alerting=alerting_system
    )
    
    # Define test targets
    targets = [
        PenetrationTestTarget(
            hostname="test.example.com",
            ip_address="192.168.1.100",
            application_name="Web Application",
            authorized_by="CISO",
            poc_contact="security@company.com"
        )
    ]
    
    # Execute penetration test
    report = await pentest_framework.execute_penetration_test(
        targets=targets,
        test_scope=TestScope.WEB_APPLICATION
    )
    
    print(f"Penetration Test Results:")
    print(f"Vulnerabilities: {report.total_vulnerabilities}")
    print(f"Successful Exploits: {report.successful_exploits}")
    print(f"Systems Compromised: {report.systems_compromised}")
    print(f"Overall Risk: {report.overall_risk_rating}")
```

## Security Controls and Compliance

### DoD Compliance Features
- **Classification Handling**: Support for UNCLASSIFIED, CUI, CONFIDENTIAL, SECRET, TOP SECRET
- **STIGs Compliance**: Automated STIG compliance checking
- **CAC/PIV Integration**: DoD PKI certificate validation
- **Network Segmentation**: NIPR/SIPR/JWICS network awareness

### NIST Framework Alignment
- **NIST SP 800-53**: Security control verification
- **NIST SP 800-115**: Technical security testing methodology
- **Cybersecurity Framework**: Risk assessment and management

### OWASP Integration
- **OWASP Top 10**: Automated testing for top web application risks
- **OWASP ASVS**: Application Security Verification Standard compliance
- **OWASP Testing Guide**: Comprehensive testing methodology

## Reporting and Analytics

### Executive Reporting
- Risk-based executive summaries
- Compliance dashboards
- Trend analysis and metrics
- Business impact assessments

### Technical Reporting
- Detailed vulnerability analysis
- Exploit proof-of-concepts
- Remediation guidance
- Technical evidence and artifacts

### Compliance Reporting
- Regulatory compliance status
- Audit trail documentation
- Exception tracking
- Risk acceptance workflows

## API Reference

### Security Test Engine
```python
# Core testing methods
await security_engine.run_comprehensive_security_assessment(target_path, target_url, test_types)
await security_engine.health_check()
security_engine.get_security_metrics()
```

### Scanning Pipeline
```python
# Pipeline management
await pipeline.create_pipeline_config(config_data)
await pipeline.trigger_pipeline(pipeline_id, trigger_type, user)
await pipeline.get_execution_status(execution_id)
await pipeline.cancel_execution(execution_id)
```

### Vulnerability Assessment
```python
# Assessment methods
await framework.assess_vulnerability(finding, context)
await framework.create_remediation_plan(vulnerability_ids, plan_name)
await framework.get_vulnerability_metrics()
await framework.generate_vulnerability_report(start_date, end_date)
```

### Penetration Testing
```python
# Testing methods
await framework.execute_penetration_test(targets, test_scope, phases)
await framework.health_check()
```

## Performance and Scalability

### Performance Characteristics
- **SAST Scanning**: ~1,000 lines of code per second
- **DAST Testing**: ~50 endpoints per minute
- **Vulnerability Assessment**: Sub-second prioritization
- **Concurrent Operations**: Up to 10 simultaneous scans

### Scalability Features
- Horizontal scaling support
- Distributed scanning capabilities
- Cloud-native architecture
- Container orchestration ready

## Security Considerations

### Framework Security
- Encrypted credential storage
- Secure communication channels
- Access control and authorization
- Audit logging and monitoring

### Test Environment Isolation
- Sandboxed execution environments
- Network segmentation
- Resource limitations
- Cleanup procedures

## Troubleshooting

### Common Issues

1. **Permission Errors**
   ```bash
   # Ensure proper permissions for scanning
   sudo chown -R $(whoami):$(whoami) /path/to/scan
   ```

2. **Network Connectivity**
   ```bash
   # Test network connectivity
   ping target-host
   nmap -sn target-network/24
   ```

3. **Database Issues**
   ```python
   # Reset vulnerability database
   framework._init_database()
   ```

### Debug Mode
```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

## Contributing

### Development Setup
```bash
git clone https://github.com/company/security-testing-framework
cd security-testing-framework
pip install -r requirements-dev.txt
python -m pytest tests/
```

### Code Standards
- PEP 8 compliance
- Type hints required
- Comprehensive testing
- Security review process

## License

This Security Testing Framework is proprietary software developed for DoD and federal government use. Unauthorized distribution is prohibited.

## Support

For technical support and questions:
- Email: security-framework-support@company.com
- Internal Wiki: https://wiki.company.com/security-testing
- Issue Tracker: https://issues.company.com/security-testing

## Changelog

### Version 1.0 (2025-07-28)
- Initial release
- Core SAST/DAST engines
- Vulnerability assessment framework
- Penetration testing capabilities
- CI/CD pipeline integration
- DoD compliance features

---

**Classification**: UNCLASSIFIED//FOR OFFICIAL USE ONLY  
**Security Contact**: security@company.com  
**Last Updated**: 2025-07-28