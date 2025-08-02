# Security Scanning Pipeline - CI/CD Integration

## Overview

The Enhanced Security Scanning Pipeline provides comprehensive CI/CD integration with quality gates and deployment controls for enterprise environments. This system integrates with major CI/CD platforms and implements automated security gates to ensure secure software delivery.

## Key Features

### 🔄 CI/CD Platform Integration
- **GitHub Actions** - Native webhook integration with status checks
- **Jenkins** - Build completion triggers and job-based scanning  
- **GitLab CI** - Push/merge request triggers with pipeline status updates
- **Azure DevOps** - Build and deployment event integration

### 🚪 Security Quality Gates
- **Configurable Thresholds** - Custom vulnerability and risk thresholds
- **Automated Blocking** - Prevent deployments based on security findings
- **Environment-Specific Policies** - Different rules for dev/staging/production
- **Real-time Evaluation** - Immediate feedback on security status

### 📊 Deployment Controls
- **Multi-Environment Support** - Production, staging, development policies
- **Approval Workflows** - Required approvals for high-risk deployments
- **Compliance Validation** - OWASP, NIST, DoD framework compliance
- **Rollback Mechanisms** - Automated rollback on security failures

## Quick Start

### 1. Initialize the Pipeline

```python
from security_compliance.security_testing.security_scanning_pipeline import (
    SecurityScanningPipeline, CICDIntegration, SecurityQualityGate
)

# Create pipeline components
pipeline = SecurityScanningPipeline(
    security_test_engine=security_test_engine,
    audit_logger=audit_logger, 
    monitoring_system=monitoring_system,
    real_time_alerting=real_time_alerting
)

# Initialize CI/CD integration
ci_cd_integration = CICDIntegration(pipeline)
quality_gate = SecurityQualityGate()

await pipeline.initialize()
```

### 2. Configure Webhooks

#### GitHub Actions Setup
```yaml
# .github/workflows/security.yml
name: Security Scanning Pipeline

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main, develop ]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Trigger Security Scan
        run: |
          curl -X POST "${{ secrets.SECURITY_PIPELINE_URL }}/webhooks/github" \
            -H "X-GitHub-Event: push" \
            -H "Content-Type: application/json" \
            -d @webhook_payload.json
```

#### Jenkins Integration
```groovy
pipeline {
    agent any
    stages {
        stage('Security Scan') {
            steps {
                script {
                    // Trigger security scan via webhook
                    sh """
                        curl -X POST "${SECURITY_PIPELINE_URL}/webhooks/jenkins" \
                            -H "Content-Type: application/json" \
                            -d '{"name": "${JOB_NAME}", "build": {"number": ${BUILD_NUMBER}, "status": "SUCCESS"}}'
                    """
                }
            }
        }
    }
}
```

### 3. Create Pipeline Configuration

```python
# Example configuration for GitHub repository
config_data = {
    "pipeline_name": "my_app_security_pipeline",
    "source_path": "./src",
    "target_url": "https://staging.myapp.com",
    "ci_cd_system": "github",
    "triggers": [ScanTrigger.CODE_COMMIT, ScanTrigger.PULL_REQUEST],
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
    },
    "notifications": {
        "slack_webhook": "https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK",
        "email_recipients": ["security-team@company.com"]
    }
}

config_id = await pipeline.create_pipeline_config(config_data)
```

## Quality Gates Configuration

### Built-in Quality Gates

The system includes several pre-configured quality gates:

```python
quality_gates = {
    "critical_vulnerability_gate": {
        "enabled": True,
        "threshold": 0,
        "action": "block"  # Block deployment if any critical vulnerabilities
    },
    "high_vulnerability_gate": {
        "enabled": True, 
        "threshold": 5,
        "action": "block"  # Block if more than 5 high-severity vulnerabilities
    },
    "security_score_gate": {
        "enabled": True,
        "threshold": 70,
        "action": "block"  # Block if security score > 70 (higher = more risk)
    },
    "compliance_gate": {
        "enabled": True,
        "threshold": 85,
        "action": "warn"   # Warn if compliance score < 85%
    }
}
```

### Custom Quality Gates

Create custom gates for specific requirements:

```python
# DoD Compliance Gate
dod_gate = {
    "name": "DoD Compliance Gate",
    "description": "Strict DoD security requirements",
    "enabled": True,
    "rules": [
        {
            "condition": "critical_vulnerabilities > 0",
            "action": "block",
            "message": "DoD policy: Zero tolerance for critical vulnerabilities"
        },
        {
            "condition": "compliance_score < 95",
            "action": "block", 
            "message": "DoD policy: Minimum 95% compliance score required"
        }
    ]
}

await quality_gate.create_custom_gate("dod_compliance", dod_gate)
```

## Deployment Policies

### Environment-Specific Policies

Different environments have different security requirements:

```python
deployment_policies = {
    "production": {
        "require_approval": True,
        "require_security_scan": True,
        "require_penetration_test": True,
        "max_critical_vulnerabilities": 0,
        "max_high_vulnerabilities": 2,
        "min_security_score": 85,
        "min_compliance_score": 90
    },
    "staging": {
        "require_approval": False,
        "require_security_scan": True,
        "require_penetration_test": False,
        "max_critical_vulnerabilities": 1,
        "max_high_vulnerabilities": 10,
        "min_security_score": 70,
        "min_compliance_score": 80
    },
    "development": {
        "require_approval": False,
        "require_security_scan": True,
        "require_penetration_test": False,
        "max_critical_vulnerabilities": 5,
        "max_high_vulnerabilities": 20,
        "min_security_score": 60,
        "min_compliance_score": 70
    }
}
```

### Evaluating Deployment Policies

```python
# Evaluate if deployment is approved for production
deployment_evaluation = await ci_cd_integration.evaluate_deployment_policy(
    execution, "production"
)

if deployment_evaluation["approved"]:
    print("Production deployment approved")
else:
    print(f"Production deployment blocked: {deployment_evaluation['reasons']}")
```

## Pipeline Execution Flow

### 1. Trigger Events
- **Code Commit** - Automatic scan on push to main/develop branches
- **Pull Request** - Scan on PR creation/update
- **Scheduled** - Daily/weekly automated scans
- **Manual** - On-demand security scans
- **Deployment** - Pre-deployment security validation

### 2. Security Scanning Stages
1. **Initialization** - Setup and dependency validation
2. **Source Analysis** - Code structure and language detection
3. **Dependency Scan** - Third-party vulnerability detection
4. **SAST Execution** - Static application security testing
5. **Build Validation** - Build process security checks
6. **DAST Execution** - Dynamic application security testing
7. **Vulnerability Assessment** - Risk scoring and prioritization
8. **Compliance Check** - Framework compliance validation
9. **Reporting** - Comprehensive security report generation
10. **Deployment Gate** - Final approval/blocking decision

### 3. Quality Gate Evaluation
- Evaluate each configured gate against scan results
- Determine overall pass/fail status
- Generate blocking reasons for failed gates
- Create actionable recommendations

### 4. Deployment Decision
- Apply environment-specific policies
- Check approval requirements
- Validate compliance scores
- Make final deployment approval/blocking decision

## Real-time Monitoring

### Execution Status Tracking

```python
# Get real-time execution status
execution = await pipeline.get_execution_status(execution_id)

print(f"Status: {execution.status.value}")
print(f"Current Stage: {execution.current_stage.value}")
print(f"Findings: {execution.findings_count}")
print(f"Security Score: {execution.security_score}")
print(f"Deployment Approved: {execution.deployment_approved}")
```

### Webhook Status Updates

The system provides real-time status updates via webhooks:

```bash
# GitHub status check
POST /repos/owner/repo/statuses/sha
{
  "state": "success",
  "description": "Security scan passed (12 findings, score: 45.2)",
  "context": "security/automated-scan"
}
```

## API Endpoints

### Webhook Endpoints
- `POST /webhooks/github` - GitHub Actions webhook
- `POST /webhooks/jenkins` - Jenkins webhook  
- `POST /webhooks/gitlab` - GitLab CI webhook
- `POST /webhooks/azure` - Azure DevOps webhook

### Management Endpoints
- `GET /health` - System health check
- `GET /metrics` - Pipeline metrics and statistics
- `POST /trigger-scan` - Manual scan trigger
- `GET /execution/{id}` - Execution status
- `POST /execution/{id}/cancel` - Cancel execution

### Quality Gate Endpoints
- `GET /quality-gates` - List configured gates
- `POST /quality-gates` - Create custom gate
- `GET /quality-gates/statistics` - Gate evaluation statistics

## Configuration Examples

### GitHub Actions Configuration

```yaml
# Complete GitHub Actions workflow
name: Secure Deployment Pipeline

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main, develop ]

env:
  SECURITY_PIPELINE_URL: ${{ secrets.SECURITY_PIPELINE_URL }}
  SECURITY_API_TOKEN: ${{ secrets.SECURITY_API_TOKEN }}

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Trigger Security Scan
        id: security-scan
        run: |
          # Trigger security pipeline
          response=$(curl -X POST "$SECURITY_PIPELINE_URL/trigger-scan" \
            -H "Authorization: Bearer $SECURITY_API_TOKEN" \
            -H "Content-Type: application/json" \
            -d '{
              "pipeline_id": "${{ vars.PIPELINE_ID }}",
              "user": "${{ github.actor }}",
              "context": {
                "repository": "${{ github.repository }}",
                "ref": "${{ github.ref }}",
                "sha": "${{ github.sha }}"
              }
            }')
          
          execution_id=$(echo $response | jq -r '.execution_id')
          echo "execution_id=$execution_id" >> $GITHUB_OUTPUT
      
      - name: Wait for Scan Completion
        run: |
          # Poll for completion
          while true; do
            status=$(curl -s "$SECURITY_PIPELINE_URL/execution/${{ steps.security-scan.outputs.execution_id }}" \
              -H "Authorization: Bearer $SECURITY_API_TOKEN" | jq -r '.status')
            
            if [[ "$status" == "completed" ]]; then
              break
            elif [[ "$status" == "failed" || "$status" == "blocked" ]]; then
              echo "Security scan failed or blocked"
              exit 1
            fi
            
            sleep 30
          done

  deploy:
    needs: security-scan
    runs-on: ubuntu-latest
    if: github.ref == 'refs/heads/main'
    environment: production
    
    steps:
      - name: Deploy to Production
        run: |
          echo "Deploying to production..."
```

### Jenkins Pipeline Configuration

```groovy
pipeline {
    agent any
    
    environment {
        SECURITY_PIPELINE_URL = credentials('security-pipeline-url')
        SECURITY_API_TOKEN = credentials('security-api-token')
    }
    
    stages {
        stage('Security Scan') {
            steps {
                script {
                    // Trigger security scan
                    def response = sh(
                        script: """
                            curl -X POST "\$SECURITY_PIPELINE_URL/trigger-scan" \
                                -H "Authorization: Bearer \$SECURITY_API_TOKEN" \
                                -H "Content-Type: application/json" \
                                -d '{"pipeline_id": "jenkins-pipeline", "user": "jenkins"}'
                        """,
                        returnStdout: true
                    ).trim()
                    
                    def json = readJSON text: response
                    env.EXECUTION_ID = json.execution_id
                }
                
                // Wait for completion
                script {
                    timeout(time: 60, unit: 'MINUTES') {
                        waitUntil {
                            script {
                                def response = sh(
                                    script: """
                                        curl -s "\$SECURITY_PIPELINE_URL/execution/\$EXECUTION_ID" \
                                            -H "Authorization: Bearer \$SECURITY_API_TOKEN"
                                    """,
                                    returnStdout: true
                                ).trim()
                                
                                def json = readJSON text: response
                                return json.status == 'completed'
                            }
                        }
                    }
                }
            }
        }
        
        stage('Deploy') {
            when { branch 'main' }
            steps {
                sh 'make deploy'
            }
        }
    }
}
```

## Security Considerations

### Authentication & Authorization
- API tokens for webhook authentication
- Role-based access control for pipeline management
- Secure credential storage and rotation

### Data Protection
- Encrypted communication (TLS 1.3)
- Secure audit logging
- PII data handling compliance

### Network Security
- IP allowlisting for webhook sources
- Rate limiting and DDoS protection
- Network segmentation for sensitive environments

## Compliance & Standards

### Supported Frameworks
- **OWASP ASVS** - Application Security Verification Standard
- **NIST Cybersecurity Framework** - Risk management framework
- **DoD Security Requirements Guide** - Department of Defense standards
- **ISO 27001** - Information security management
- **SOC 2** - Service organization controls

### Audit & Reporting
- Comprehensive audit trails
- Compliance dashboard and reporting
- Automated compliance validation
- Evidence collection for audits

## Troubleshooting

### Common Issues

**Pipeline Not Triggering**
- Verify webhook URL configuration
- Check API token permissions
- Validate pipeline configuration exists

**Quality Gates Failing**
- Review gate threshold configuration
- Check vulnerability scan results
- Verify compliance framework settings

**Deployment Blocked**
- Review deployment policy requirements
- Check security scan findings
- Validate approval workflows

### Debug Mode

Enable debug logging for troubleshooting:

```python
import logging
logging.getLogger('security_scanning_pipeline').setLevel(logging.DEBUG)
```

### Health Checks

Monitor system health:

```bash
curl -X GET "$SECURITY_PIPELINE_URL/health"
```

## Performance Optimization

### Parallel Execution
- Configure `max_concurrent_scans` based on resources
- Enable `parallel_execution` for faster scanning
- Optimize scan timeouts for your environment

### Caching Strategies
- Cache SAST analysis results for unchanged code
- Reuse dependency scan results
- Implement incremental scanning

### Resource Management
- Monitor memory and CPU usage
- Scale horizontally for high-volume environments
- Implement graceful degradation

## Support & Documentation

### Additional Resources
- [Security Test Engine Documentation](./security_test_engine.py)
- [Vulnerability Assessment Framework](./vulnerability_assessment_framework.py)
- [Penetration Testing Framework](./penetration_testing_framework.py)
- [Complete Examples](./ci_cd_integration_examples.py)

### Getting Help
- Review logs for detailed error information
- Check system health endpoints
- Consult metrics for performance insights

---

**Classification**: UNCLASSIFIED//FOR OFFICIAL USE ONLY  
**Version**: 1.0 - CI/CD Integration Documentation  
**Last Updated**: 2025-07-28