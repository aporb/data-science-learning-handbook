"""
CI/CD Integration Examples and Usage Guide
==========================================

This file provides comprehensive examples of how to use the enhanced security
scanning pipeline with CI/CD integration, quality gates, and deployment controls.

Key Features Demonstrated:
- Setting up CI/CD webhooks for GitHub, Jenkins, GitLab, and Azure DevOps
- Configuring quality gates with custom thresholds
- Implementing deployment policies for different environments
- Real-time security monitoring and alerting
- Automated security gate evaluation and blocking

Classification: UNCLASSIFIED//FOR OFFICIAL USE ONLY
Version: 1.0 - CI/CD Integration Examples
Author: Security Engineering Team
Date: 2025-07-28
"""

import asyncio
import json
import logging
from typing import Dict, Any
from aiohttp import web
from datetime import datetime, timezone

# Import security pipeline components
from .security_scanning_pipeline import (
    SecurityScanningPipeline, CICDIntegration, SecurityQualityGate,
    PipelineConfig, ScanTrigger, PipelineStatus
)
from .security_test_engine import SecurityTestEngine
from ..audits.audit_logger import AuditLogger
from ..audits.enhanced_monitoring_system import EnhancedMonitoringSystem
from ..audits.real_time_alerting import RealTimeAlerting

logger = logging.getLogger(__name__)


class CICDPipelineOrchestrator:
    """
    Complete CI/CD Pipeline Orchestrator
    
    Demonstrates how to integrate the security scanning pipeline
    with multiple CI/CD platforms and implement comprehensive
    security quality gates.
    """
    
    def __init__(self):
        """Initialize CI/CD pipeline orchestrator."""
        self.pipeline = None
        self.ci_cd_integration = None
        self.quality_gate = None
        self.web_app = None
        
    async def initialize(self):
        """Initialize all components."""
        # Initialize core components (would be injected in real implementation)
        security_test_engine = await self._create_security_test_engine()
        audit_logger = await self._create_audit_logger()
        monitoring_system = await self._create_monitoring_system()
        real_time_alerting = await self._create_real_time_alerting()
        
        # Create security scanning pipeline
        self.pipeline = SecurityScanningPipeline(
            security_test_engine=security_test_engine,
            audit_logger=audit_logger,
            monitoring_system=monitoring_system,
            real_time_alerting=real_time_alerting
        )
        
        await self.pipeline.initialize()
        
        # Create CI/CD integration
        self.ci_cd_integration = CICDIntegration(self.pipeline)
        
        # Create quality gate system
        self.quality_gate = SecurityQualityGate()
        
        # Setup web application for webhooks
        self.web_app = web.Application()
        await self.ci_cd_integration.setup_webhook_handlers(self.web_app)
        
        # Add custom routes
        self.web_app.router.add_get('/health', self.health_check)
        self.web_app.router.add_get('/metrics', self.get_metrics)
        self.web_app.router.add_post('/trigger-scan', self.trigger_manual_scan)
        self.web_app.router.add_get('/execution/{execution_id}', self.get_execution_status)
        
        logger.info("CI/CD Pipeline Orchestrator initialized")
    
    async def setup_github_integration_example(self):
        """Example: Setup GitHub Actions integration."""
        # Create pipeline configuration for GitHub repository
        github_config = {
            "pipeline_name": "github_security_pipeline",
            "source_path": ".",
            "ci_cd_system": "github",
            "triggers": [ScanTrigger.CODE_COMMIT, ScanTrigger.PULL_REQUEST],
            "quality_gates": {
                "block_on_critical": True,
                "block_on_high_threshold": 3,
                "security_score_threshold": 75
            },
            "notifications": {
                "slack_webhook": "https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK",
                "email_recipients": ["security-team@company.com"]
            }
        }
        
        config_id = await self.pipeline.create_pipeline_config(github_config)
        logger.info(f"Created GitHub pipeline configuration: {config_id}")
        
        return config_id
    
    async def setup_jenkins_integration_example(self):
        """Example: Setup Jenkins integration."""
        # Create pipeline configuration for Jenkins
        jenkins_config = {
            "pipeline_name": "jenkins_security_pipeline",
            "source_path": "/var/jenkins_home/workspace",
            "ci_cd_system": "jenkins",
            "triggers": [ScanTrigger.DEPLOYMENT],
            "quality_gates": {
                "block_on_critical": True,
                "block_on_high_threshold": 5,
                "security_score_threshold": 80
            },
            "stages_enabled": {
                "sast": True,
                "dast": False,  # Skip DAST for Jenkins builds
                "dependency_scan": True,
                "compliance_check": True
            }
        }
        
        config_id = await self.pipeline.create_pipeline_config(jenkins_config)
        logger.info(f"Created Jenkins pipeline configuration: {config_id}")
        
        return config_id
    
    async def setup_custom_quality_gates_example(self):
        """Example: Setup custom quality gates."""
        # Create custom quality gate for DoD compliance
        dod_compliance_gate = {
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
                    "condition": "high_vulnerabilities > 2",
                    "action": "block",
                    "message": "DoD policy: Maximum 2 high-severity vulnerabilities allowed"
                },
                {
                    "condition": "compliance_score < 95",
                    "action": "block",
                    "message": "DoD policy: Minimum 95% compliance score required"
                },
                {
                    "condition": "code_coverage < 90",
                    "action": "warn",
                    "message": "DoD recommendation: 90% code coverage target"
                }
            ]
        }
        
        success = await self.quality_gate.create_custom_gate(
            "dod_compliance_gate", 
            dod_compliance_gate
        )
        
        if success:
            logger.info("Created DoD compliance quality gate")
        
        # Create custom gate for financial services
        finserv_gate = {
            "name": "Financial Services Compliance Gate",
            "description": "Financial industry security requirements",
            "enabled": True,
            "rules": [
                {
                    "condition": "critical_vulnerabilities > 0",
                    "action": "block",
                    "message": "Critical vulnerabilities violate financial security standards"
                },
                {
                    "condition": "security_score > 70",
                    "action": "block",
                    "message": "Security score exceeds acceptable risk threshold"
                },
                {
                    "condition": "vulnerable_dependencies > 0",
                    "action": "block",
                    "message": "Vulnerable dependencies must be patched for compliance"
                }
            ]
        }
        
        success = await self.quality_gate.create_custom_gate(
            "financial_services_gate", 
            finserv_gate
        )
        
        if success:
            logger.info("Created Financial Services compliance quality gate")
    
    async def demonstrate_deployment_pipeline(self):
        """Example: Complete deployment pipeline with security gates."""
        # Step 1: Create pipeline configuration
        deployment_config = {
            "pipeline_name": "production_deployment_pipeline",
            "source_path": "./application",
            "target_url": "https://staging.company.com",
            "triggers": [ScanTrigger.DEPLOYMENT],
            "stages_enabled": {
                "sast": True,
                "dast": True,
                "dependency_scan": True,
                "vulnerability_assessment": True,
                "compliance_check": True
            },
            "compliance_frameworks": ["OWASP", "NIST", "DoD"]
        }
        
        config_id = await self.pipeline.create_pipeline_config(deployment_config)
        
        # Step 2: Trigger security scan
        execution_id = await self.pipeline.trigger_pipeline(
            config_id,
            ScanTrigger.DEPLOYMENT,
            "deployment-system",
            {
                "deployment_target": "production",
                "release_version": "v1.2.3",
                "deployment_timestamp": datetime.now(timezone.utc).isoformat()
            }
        )
        
        logger.info(f"Triggered deployment security scan: {execution_id}")
        
        # Step 3: Wait for completion and evaluate gates
        execution = await self._wait_for_execution_completion(execution_id)
        
        if execution:
            # Step 4: Evaluate quality gates
            gate_evaluation = await self.quality_gate.evaluate_gates(execution, "production")
            
            # Step 5: Evaluate deployment policies
            deployment_evaluation = await self.ci_cd_integration.evaluate_deployment_policy(
                execution, "production"
            )
            
            # Step 6: Generate comprehensive report
            ci_cd_report = await self.ci_cd_integration.generate_ci_cd_report(execution)
            
            # Step 7: Make deployment decision
            deployment_approved = (
                gate_evaluation["overall_status"] == "PASSED" and
                deployment_evaluation["approved"]
            )
            
            logger.info(f"Deployment decision: {'APPROVED' if deployment_approved else 'BLOCKED'}")
            
            return {
                "execution_id": execution_id,
                "deployment_approved": deployment_approved,
                "gate_evaluation": gate_evaluation,
                "deployment_evaluation": deployment_evaluation,
                "ci_cd_report": ci_cd_report
            }
        
        return {"error": "Execution did not complete successfully"}
    
    async def health_check(self, request):
        """Health check endpoint."""
        health_status = await self.pipeline.health_check()
        return web.json_response(health_status)
    
    async def get_metrics(self, request):
        """Metrics endpoint."""
        metrics = {
            "pipeline_metrics": self.pipeline.get_pipeline_metrics(),
            "quality_gate_statistics": self.quality_gate.get_gate_statistics()
        }
        return web.json_response(metrics)
    
    async def trigger_manual_scan(self, request):
        """Manual scan trigger endpoint."""
        try:
            data = await request.json()
            pipeline_id = data.get('pipeline_id')
            trigger_user = data.get('user', 'manual')
            trigger_context = data.get('context', {})
            
            execution_id = await self.pipeline.trigger_pipeline(
                pipeline_id,
                ScanTrigger.MANUAL,
                trigger_user,
                trigger_context
            )
            
            return web.json_response({
                "status": "triggered",
                "execution_id": execution_id
            })
            
        except Exception as e:
            return web.json_response({
                "status": "error",
                "message": str(e)
            }, status=400)
    
    async def get_execution_status(self, request):
        """Get execution status endpoint."""
        execution_id = request.match_info['execution_id']
        execution = await self.pipeline.get_execution_status(execution_id)
        
        if execution:
            return web.json_response({
                "execution_id": execution.execution_id,
                "status": execution.status.value,
                "current_stage": execution.current_stage.value if execution.current_stage else None,
                "findings_count": execution.findings_count,
                "security_score": execution.security_score,
                "deployment_approved": execution.deployment_approved
            })
        else:
            return web.json_response({
                "error": "Execution not found"
            }, status=404)
    
    async def _wait_for_execution_completion(self, execution_id: str, timeout_seconds: int = 3600):
        """Wait for pipeline execution to complete."""
        start_time = datetime.now(timezone.utc)
        
        while True:
            execution = await self.pipeline.get_execution_status(execution_id)
            if not execution:
                return None
            
            if execution.status in [PipelineStatus.COMPLETED, PipelineStatus.FAILED, PipelineStatus.BLOCKED]:
                return execution
            
            # Check timeout
            elapsed = (datetime.now(timezone.utc) - start_time).total_seconds()
            if elapsed > timeout_seconds:
                logger.warning(f"Execution {execution_id} timed out after {timeout_seconds} seconds")
                return None
            
            await asyncio.sleep(10)  # Check every 10 seconds
    
    async def _create_security_test_engine(self):
        """Create security test engine (placeholder)."""
        # In real implementation, this would create actual SecurityTestEngine
        return SecurityTestEngine()
    
    async def _create_audit_logger(self):
        """Create audit logger (placeholder)."""
        # In real implementation, this would create actual AuditLogger
        return AuditLogger()
    
    async def _create_monitoring_system(self):
        """Create monitoring system (placeholder)."""
        # In real implementation, this would create actual EnhancedMonitoringSystem
        return EnhancedMonitoringSystem()
    
    async def _create_real_time_alerting(self):
        """Create real-time alerting (placeholder)."""
        # In real implementation, this would create actual RealTimeAlerting
        return RealTimeAlerting()


class GitHubActionsYamlGenerator:
    """Generate GitHub Actions YAML for security integration."""
    
    @staticmethod
    def generate_security_workflow():
        """Generate complete GitHub Actions workflow with security integration."""
        return """
name: Security Scanning Pipeline

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main, develop ]
  schedule:
    - cron: '0 2 * * *'  # Daily security scan
  workflow_dispatch:
    inputs:
      scan_type:
        description: 'Type of security scan'
        required: true
        default: 'full'
        type: choice
        options:
        - full
        - sast_only
        - dast_only

env:
  SECURITY_PIPELINE_URL: ${{ secrets.SECURITY_PIPELINE_URL }}
  SECURITY_API_TOKEN: ${{ secrets.SECURITY_API_TOKEN }}

jobs:
  security-scan:
    runs-on: ubuntu-latest
    outputs:
      execution_id: ${{ steps.trigger-scan.outputs.execution_id }}
      scan_status: ${{ steps.wait-completion.outputs.scan_status }}
    
    steps:
      - uses: actions/checkout@v4
      
      - name: Trigger Security Scan
        id: trigger-scan
        run: |
          RESPONSE=$(curl -X POST "$SECURITY_PIPELINE_URL/trigger-scan" \\
            -H "Authorization: Bearer $SECURITY_API_TOKEN" \\
            -H "Content-Type: application/json" \\
            -d '{
              "pipeline_id": "${{ vars.SECURITY_PIPELINE_ID }}",
              "user": "${{ github.actor }}",
              "context": {
                "repository": "${{ github.repository }}",
                "ref": "${{ github.ref }}",
                "sha": "${{ github.sha }}",
                "workflow": "${{ github.workflow }}",
                "run_id": "${{ github.run_id }}"
              }
            }')
          
          EXECUTION_ID=$(echo $RESPONSE | jq -r '.execution_id')
          echo "execution_id=$EXECUTION_ID" >> $GITHUB_OUTPUT
          echo "Triggered security scan: $EXECUTION_ID"
      
      - name: Wait for Scan Completion
        id: wait-completion
        timeout-minutes: 60
        run: |
          EXECUTION_ID="${{ steps.trigger-scan.outputs.execution_id }}"
          
          while true; do
            RESPONSE=$(curl -s "$SECURITY_PIPELINE_URL/execution/$EXECUTION_ID" \\
              -H "Authorization: Bearer $SECURITY_API_TOKEN")
            
            STATUS=$(echo $RESPONSE | jq -r '.status')
            echo "Current status: $STATUS"
            
            if [[ "$STATUS" == "completed" || "$STATUS" == "failed" || "$STATUS" == "blocked" ]]; then
              echo "scan_status=$STATUS" >> $GITHUB_OUTPUT
              break
            fi
            
            sleep 30
          done
      
      - name: Check Security Gates
        if: steps.wait-completion.outputs.scan_status != 'completed'
        run: |
          echo "Security scan did not complete successfully"
          echo "Status: ${{ steps.wait-completion.outputs.scan_status }}"
          exit 1
      
      - name: Get Scan Results
        id: scan-results
        run: |
          EXECUTION_ID="${{ steps.trigger-scan.outputs.execution_id }}"
          RESPONSE=$(curl -s "$SECURITY_PIPELINE_URL/execution/$EXECUTION_ID" \\
            -H "Authorization: Bearer $SECURITY_API_TOKEN")
          
          FINDINGS=$(echo $RESPONSE | jq -r '.findings_count')
          SECURITY_SCORE=$(echo $RESPONSE | jq -r '.security_score')
          DEPLOYMENT_APPROVED=$(echo $RESPONSE | jq -r '.deployment_approved')
          
          echo "Security findings: $FINDINGS"
          echo "Security score: $SECURITY_SCORE"
          echo "Deployment approved: $DEPLOYMENT_APPROVED"
          
          if [[ "$DEPLOYMENT_APPROVED" != "true" ]]; then
            echo "::error::Deployment blocked by security quality gates"
            exit 1
          fi

  build-and-test:
    needs: security-scan
    runs-on: ubuntu-latest
    if: needs.security-scan.outputs.scan_status == 'completed'
    
    steps:
      - uses: actions/checkout@v4
      
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      
      - name: Install dependencies
        run: |
          python -m pip install --upgrade pip
          pip install -r requirements.txt
          pip install pytest pytest-cov
      
      - name: Run tests
        run: pytest tests/ --cov=./ --cov-report=xml
      
      - name: Build application
        run: |
          # Build commands here
          echo "Building application..."

  deploy-staging:
    needs: [security-scan, build-and-test]
    runs-on: ubuntu-latest
    if: github.ref == 'refs/heads/develop' && needs.security-scan.outputs.scan_status == 'completed'
    environment: staging
    
    steps:
      - name: Deploy to Staging
        run: |
          echo "Deploying to staging environment..."
          # Deployment commands here

  deploy-production:
    needs: [security-scan, build-and-test]
    runs-on: ubuntu-latest
    if: github.ref == 'refs/heads/main' && needs.security-scan.outputs.scan_status == 'completed'
    environment: production
    
    steps:
      - name: Final Security Gate Check
        run: |
          # Additional production security checks
          EXECUTION_ID="${{ needs.security-scan.outputs.execution_id }}"
          
          # Check deployment policy for production
          RESPONSE=$(curl -s "$SECURITY_PIPELINE_URL/deployment-policy/production/$EXECUTION_ID" \\
            -H "Authorization: Bearer $SECURITY_API_TOKEN")
          
          APPROVED=$(echo $RESPONSE | jq -r '.approved')
          if [[ "$APPROVED" != "true" ]]; then
            echo "::error::Production deployment blocked by security policy"
            exit 1
          fi
      
      - name: Deploy to Production
        run: |
          echo "Deploying to production environment..."
          # Production deployment commands here
"""

    @staticmethod
    def generate_jenkins_pipeline():
        """Generate Jenkins pipeline with security integration."""
        return """
pipeline {
    agent any
    
    environment {
        SECURITY_PIPELINE_URL = credentials('security-pipeline-url')
        SECURITY_API_TOKEN = credentials('security-api-token')
        SECURITY_PIPELINE_ID = credentials('security-pipeline-id')
    }
    
    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }
        
        stage('Security Scan') {
            steps {
                script {
                    def response = sh(
                        script: '''
                            curl -X POST "$SECURITY_PIPELINE_URL/trigger-scan" \\
                                -H "Authorization: Bearer $SECURITY_API_TOKEN" \\
                                -H "Content-Type: application/json" \\
                                -d "{\\"pipeline_id\\": \\"$SECURITY_PIPELINE_ID\\", \\"user\\": \\"jenkins\\", \\"context\\": {\\"job\\": \\"$JOB_NAME\\", \\"build\\": \\"$BUILD_NUMBER\\"}}"
                        ''',
                        returnStdout: true
                    ).trim()
                    
                    def json = readJSON text: response
                    env.EXECUTION_ID = json.execution_id
                    
                    echo "Triggered security scan: ${env.EXECUTION_ID}"
                }
            }
        }
        
        stage('Wait for Security Scan') {
            steps {
                script {
                    timeout(time: 60, unit: 'MINUTES') {
                        waitUntil {
                            script {
                                def response = sh(
                                    script: '''
                                        curl -s "$SECURITY_PIPELINE_URL/execution/$EXECUTION_ID" \\
                                            -H "Authorization: Bearer $SECURITY_API_TOKEN"
                                    ''',
                                    returnStdout: true
                                ).trim()
                                
                                def json = readJSON text: response
                                def status = json.status
                                
                                echo "Security scan status: $status"
                                
                                if (status == 'failed' || status == 'blocked') {
                                    error("Security scan failed or blocked")
                                }
                                
                                return status == 'completed'
                            }
                        }
                    }
                }
            }
        }
        
        stage('Check Security Gates') {
            steps {
                script {
                    def response = sh(
                        script: '''
                            curl -s "$SECURITY_PIPELINE_URL/execution/$EXECUTION_ID" \\
                                -H "Authorization: Bearer $SECURITY_API_TOKEN"
                        ''',
                        returnStdout: true
                    ).trim()
                    
                    def json = readJSON text: response
                    
                    if (!json.deployment_approved) {
                        error("Deployment blocked by security quality gates")
                    }
                    
                    echo "Security scan results:"
                    echo "  Findings: ${json.findings_count}"
                    echo "  Security Score: ${json.security_score}"
                    echo "  Deployment Approved: ${json.deployment_approved}"
                }
            }
        }
        
        stage('Build') {
            steps {
                sh 'make build'
            }
        }
        
        stage('Test') {
            steps {
                sh 'make test'
            }
        }
        
        stage('Deploy') {
            when {
                branch 'main'
            }
            steps {
                sh 'make deploy'
            }
        }
    }
    
    post {
        always {
            script {
                if (env.EXECUTION_ID) {
                    // Send notification with scan results
                    sh '''
                        curl -X POST "$SECURITY_PIPELINE_URL/notify" \\
                            -H "Authorization: Bearer $SECURITY_API_TOKEN" \\
                            -H "Content-Type: application/json" \\
                            -d "{\\"execution_id\\": \\"$EXECUTION_ID\\", \\"jenkins_build\\": \\"$BUILD_URL\\"}"
                    '''
                }
            }
        }
    }
}
"""


async def main():
    """Example main function demonstrating complete setup."""
    # Initialize orchestrator
    orchestrator = CICDPipelineOrchestrator()
    await orchestrator.initialize()
    
    # Setup integrations
    await orchestrator.setup_github_integration_example()
    await orchestrator.setup_jenkins_integration_example()
    await orchestrator.setup_custom_quality_gates_example()
    
    # Demonstrate deployment pipeline
    deployment_result = await orchestrator.demonstrate_deployment_pipeline()
    print(f"Deployment pipeline result: {deployment_result}")
    
    # Start web server for webhooks
    runner = web.AppRunner(orchestrator.web_app)
    await runner.setup()
    site = web.TCPSite(runner, 'localhost', 8080)
    await site.start()
    
    print("Security scanning pipeline with CI/CD integration started on http://localhost:8080")
    print("Webhook endpoints:")
    print("  GitHub: POST /webhooks/github")
    print("  Jenkins: POST /webhooks/jenkins")
    print("  GitLab: POST /webhooks/gitlab")
    print("  Azure DevOps: POST /webhooks/azure")
    print("  Health Check: GET /health")
    print("  Metrics: GET /metrics")
    
    # Keep running
    try:
        await asyncio.Future()  # Run forever
    except KeyboardInterrupt:
        pass
    finally:
        await orchestrator.pipeline.shutdown()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(main())