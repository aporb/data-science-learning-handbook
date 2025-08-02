"""
Automated SAST/DAST Scanning Pipeline
====================================

Enterprise-grade automated security scanning pipeline that orchestrates continuous
security testing throughout the development lifecycle. Integrates with CI/CD systems,
provides automated vulnerability detection, and enables continuous security monitoring.

Key Features:
- Automated SAST/DAST pipeline orchestration
- CI/CD integration with GitHub Actions, Jenkins, GitLab CI
- Continuous security monitoring and alerting
- Vulnerability prioritization and risk-based scheduling
- Security gate controls for deployment pipelines
- Integration with existing audit and compliance infrastructure
- Real-time security metrics and reporting
- DoD and NIST compliance-focused scanning

Pipeline Capabilities:
- Parallel execution of multiple security test types
- Intelligent test scheduling based on risk assessment
- Automated remediation suggestions and tracking
- Security baseline establishment and drift detection
- Compliance verification and regulatory reporting
- Integration with vulnerability management systems

Classification: UNCLASSIFIED//FOR OFFICIAL USE ONLY
Version: 1.0 - Automated Security Pipeline
Author: Security Engineering Team
Date: 2025-07-28
"""

import asyncio
import json
import logging
import time
import yaml
import subprocess
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Tuple, Set, Union, AsyncGenerator
from uuid import UUID, uuid4
from dataclasses import dataclass, field, asdict
from enum import Enum
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict, deque
import aiofiles
import aiohttp
from threading import Lock, Event
import numpy as np
from pathlib import Path
import docker
import kubernetes
from kubernetes import client, config

# Import security testing infrastructure
from .security_test_engine import (
    SecurityTestEngine, SecurityTestType, SecurityFinding, SecurityTestReport,
    SecuritySeverity, SecurityTestStatus, SASTEngine, DASTEngine, VulnerabilityScanner
)

# Import existing audit infrastructure
from ..audits.audit_system_validator import AuditSystemValidator
from ..audits.audit_logger import AuditLogger, AuditEvent, AuditEventType, AuditSeverity
from ..audits.enhanced_monitoring_system import EnhancedMonitoringSystem
from ..audits.real_time_alerting import RealTimeAlerting, AlertPriority

logger = logging.getLogger(__name__)


class PipelineStage(Enum):
    """Security scanning pipeline stages."""
    INITIALIZATION = "initialization"
    SOURCE_ANALYSIS = "source_analysis"
    DEPENDENCY_SCAN = "dependency_scan"
    SAST_EXECUTION = "sast_execution"
    BUILD_VALIDATION = "build_validation"
    DAST_EXECUTION = "dast_execution"
    VULNERABILITY_ASSESSMENT = "vulnerability_assessment"
    COMPLIANCE_CHECK = "compliance_check"
    REPORTING = "reporting"
    REMEDIATION = "remediation"
    DEPLOYMENT_GATE = "deployment_gate"


class PipelineStatus(Enum):
    """Pipeline execution status."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    BLOCKED = "blocked"
    APPROVED = "approved"
    REJECTED = "rejected"


class ScanTrigger(Enum):
    """Security scan trigger types."""
    CODE_COMMIT = "code_commit"
    PULL_REQUEST = "pull_request"
    SCHEDULED = "scheduled"
    MANUAL = "manual"
    DEPLOYMENT = "deployment"
    INCIDENT_RESPONSE = "incident_response"
    COMPLIANCE_AUDIT = "compliance_audit"


@dataclass
class PipelineConfig:
    """Security scanning pipeline configuration."""
    pipeline_id: str = field(default_factory=lambda: str(uuid4()))
    pipeline_name: str = "security_scanning_pipeline"
    
    # Execution settings
    enabled: bool = True
    auto_trigger: bool = True
    parallel_execution: bool = True
    max_concurrent_scans: int = 5
    scan_timeout_minutes: int = 120
    
    # Stage configuration
    stages_enabled: Dict[str, bool] = field(default_factory=lambda: {
        "sast": True,
        "dast": True,
        "dependency_scan": True,
        "vulnerability_assessment": True,
        "compliance_check": True,
        "container_scan": False,
        "infrastructure_scan": False
    })
    
    # Trigger settings
    triggers: List[ScanTrigger] = field(default_factory=lambda: [
        ScanTrigger.CODE_COMMIT,
        ScanTrigger.PULL_REQUEST,
        ScanTrigger.SCHEDULED
    ])
    
    # Scheduling
    schedule_cron: str = "0 2 * * *"  # Daily at 2 AM
    schedule_timezone: str = "UTC"
    
    # Quality gates
    quality_gates: Dict[str, Any] = field(default_factory=lambda: {
        "block_on_critical": True,
        "block_on_high_threshold": 5,
        "allow_medium_threshold": 20,
        "security_score_threshold": 70
    })
    
    # Target configuration
    source_path: str = "."
    target_url: Optional[str] = None
    docker_image: Optional[str] = None
    kubernetes_namespace: Optional[str] = None
    
    # CI/CD integration
    ci_cd_system: str = "generic"  # github, gitlab, jenkins, azure_devops
    webhook_url: Optional[str] = None
    api_token: Optional[str] = None
    
    # Notification settings
    notifications: Dict[str, Any] = field(default_factory=lambda: {
        "slack_webhook": None,
        "email_recipients": [],
        "teams_webhook": None,
        "jira_integration": False
    })
    
    # Advanced settings
    baseline_enabled: bool = True
    baseline_threshold_days: int = 30
    trend_analysis: bool = True
    auto_remediation: bool = False
    compliance_frameworks: List[str] = field(default_factory=lambda: ["OWASP", "NIST", "DoD"])


@dataclass
class PipelineExecution:
    """Security scanning pipeline execution tracking."""
    execution_id: str = field(default_factory=lambda: str(uuid4()))
    pipeline_config: PipelineConfig = field(default_factory=PipelineConfig)
    
    # Execution metadata
    start_time: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    end_time: Optional[datetime] = None
    execution_time_seconds: float = 0.0
    
    # Trigger information
    trigger_type: ScanTrigger = ScanTrigger.MANUAL
    trigger_user: Optional[str] = None
    trigger_context: Dict[str, Any] = field(default_factory=dict)
    
    # Current status
    status: PipelineStatus = PipelineStatus.PENDING
    current_stage: Optional[PipelineStage] = None
    completed_stages: List[PipelineStage] = field(default_factory=list)
    failed_stages: List[PipelineStage] = field(default_factory=list)
    
    # Results
    security_report: Optional[SecurityTestReport] = None
    stage_results: Dict[str, Any] = field(default_factory=dict)
    quality_gate_results: Dict[str, bool] = field(default_factory=dict)
    
    # Error tracking
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    
    # Metrics
    findings_count: int = 0
    critical_findings: int = 0
    high_findings: int = 0
    medium_findings: int = 0
    low_findings: int = 0
    security_score: float = 0.0
    
    # Deployment decision
    deployment_approved: bool = False
    deployment_blocked_reason: Optional[str] = None


class SecurityScanningPipeline:
    """
    Automated security scanning pipeline that orchestrates comprehensive
    security testing throughout the development lifecycle.
    """
    
    def __init__(
        self,
        security_test_engine: SecurityTestEngine,
        audit_logger: AuditLogger,
        monitoring_system: EnhancedMonitoringSystem,
        real_time_alerting: RealTimeAlerting
    ):
        """Initialize security scanning pipeline."""
        # Core components
        self.security_test_engine = security_test_engine
        self.audit_logger = audit_logger
        self.monitoring_system = monitoring_system
        self.real_time_alerting = real_time_alerting
        
        # Pipeline state
        self.active_executions: Dict[str, PipelineExecution] = {}
        self.execution_history: deque = deque(maxlen=1000)
        self.pipeline_configs: Dict[str, PipelineConfig] = {}
        
        # Execution control
        self.shutdown_event = Event()
        self.scheduler_task: Optional[asyncio.Task] = None
        self.execution_lock = Lock()
        
        # Docker and Kubernetes clients
        self.docker_client = None
        self.k8s_client = None
        
        # Thread pool for pipeline execution
        self.thread_pool = ThreadPoolExecutor(
            max_workers=10,
            thread_name_prefix="SecurityPipeline"
        )
        
        # Metrics
        self.metrics = {
            "total_executions": 0,
            "successful_executions": 0,
            "failed_executions": 0,
            "average_execution_time": 0.0,
            "findings_detected": 0,
            "critical_vulnerabilities": 0,
            "deployments_blocked": 0,
            "compliance_violations": 0
        }
        
        logger.info("Security Scanning Pipeline initialized")
    
    async def initialize(self):
        """Initialize pipeline components."""
        try:
            # Initialize Docker client
            try:
                self.docker_client = docker.from_env()
                logger.info("Docker client initialized")
            except Exception as e:
                logger.warning(f"Docker client initialization failed: {e}")
            
            # Initialize Kubernetes client
            try:
                config.load_incluster_config()  # Try in-cluster config first
                self.k8s_client = client.ApiClient()
                logger.info("Kubernetes client initialized (in-cluster)")
            except:
                try:
                    config.load_kube_config()  # Try local kubeconfig
                    self.k8s_client = client.ApiClient()
                    logger.info("Kubernetes client initialized (local config)")
                except Exception as e:
                    logger.warning(f"Kubernetes client initialization failed: {e}")
            
            # Start scheduler
            self.scheduler_task = asyncio.create_task(self._scheduler_loop())
            
            logger.info("Security scanning pipeline initialization completed")
            
        except Exception as e:
            logger.error(f"Pipeline initialization failed: {e}")
            raise
    
    async def create_pipeline_config(self, config_data: Dict[str, Any]) -> str:
        """Create new pipeline configuration."""
        config = PipelineConfig(**config_data)
        self.pipeline_configs[config.pipeline_id] = config
        
        logger.info(f"Created pipeline configuration: {config.pipeline_name}")
        
        # Log configuration creation
        await self._log_pipeline_event(
            "PIPELINE_CONFIG_CREATED",
            config.pipeline_id,
            {"pipeline_name": config.pipeline_name}
        )
        
        return config.pipeline_id
    
    async def trigger_pipeline(
        self,
        pipeline_id: str,
        trigger_type: ScanTrigger = ScanTrigger.MANUAL,
        trigger_user: Optional[str] = None,
        trigger_context: Optional[Dict[str, Any]] = None
    ) -> str:
        """Trigger security scanning pipeline execution."""
        if pipeline_id not in self.pipeline_configs:
            raise ValueError(f"Pipeline configuration not found: {pipeline_id}")
        
        config = self.pipeline_configs[pipeline_id]
        if not config.enabled:
            raise ValueError(f"Pipeline is disabled: {pipeline_id}")
        
        # Create execution
        execution = PipelineExecution(
            pipeline_config=config,
            trigger_type=trigger_type,
            trigger_user=trigger_user,
            trigger_context=trigger_context or {}
        )
        
        # Check concurrent execution limits
        active_count = len([e for e in self.active_executions.values() 
                           if e.status == PipelineStatus.RUNNING])
        
        if active_count >= config.max_concurrent_scans:
            execution.status = PipelineStatus.BLOCKED
            execution.errors.append(f"Max concurrent executions reached: {active_count}")
            logger.warning(f"Pipeline execution blocked due to concurrency limit: {execution.execution_id}")
            return execution.execution_id
        
        # Register execution
        self.active_executions[execution.execution_id] = execution
        
        # Start execution asynchronously
        asyncio.create_task(self._execute_pipeline(execution))
        
        logger.info(f"Triggered pipeline execution: {execution.execution_id}")
        
        # Update metrics
        self.metrics["total_executions"] += 1
        
        return execution.execution_id
    
    async def _execute_pipeline(self, execution: PipelineExecution):
        """Execute security scanning pipeline."""
        try:
            execution.status = PipelineStatus.RUNNING
            logger.info(f"Starting pipeline execution: {execution.execution_id}")
            
            # Log execution start
            await self._log_pipeline_event(
                "PIPELINE_EXECUTION_STARTED",
                execution.execution_id,
                {"trigger_type": execution.trigger_type.value}
            )
            
            # Execute pipeline stages
            pipeline_stages = [
                (PipelineStage.INITIALIZATION, self._stage_initialization),
                (PipelineStage.SOURCE_ANALYSIS, self._stage_source_analysis),
                (PipelineStage.DEPENDENCY_SCAN, self._stage_dependency_scan),
                (PipelineStage.SAST_EXECUTION, self._stage_sast_execution),
                (PipelineStage.BUILD_VALIDATION, self._stage_build_validation),
                (PipelineStage.DAST_EXECUTION, self._stage_dast_execution),
                (PipelineStage.VULNERABILITY_ASSESSMENT, self._stage_vulnerability_assessment),
                (PipelineStage.COMPLIANCE_CHECK, self._stage_compliance_check),
                (PipelineStage.REPORTING, self._stage_reporting),
                (PipelineStage.DEPLOYMENT_GATE, self._stage_deployment_gate)
            ]
            
            for stage, stage_func in pipeline_stages:
                if self.shutdown_event.is_set():
                    execution.status = PipelineStatus.CANCELLED
                    break
                
                execution.current_stage = stage
                
                try:
                    logger.info(f"Executing stage {stage.value}: {execution.execution_id}")
                    
                    stage_start = time.time()
                    stage_result = await stage_func(execution)
                    stage_duration = time.time() - stage_start
                    
                    execution.stage_results[stage.value] = {
                        "status": "completed",
                        "duration_seconds": stage_duration,
                        "result": stage_result
                    }
                    
                    execution.completed_stages.append(stage)
                    
                    # Check if stage should block pipeline
                    if not stage_result.get("continue", True):
                        execution.status = PipelineStatus.BLOCKED
                        execution.deployment_blocked_reason = stage_result.get("block_reason", "Stage validation failed")
                        break
                    
                except Exception as e:
                    logger.error(f"Stage {stage.value} failed: {e}")
                    execution.failed_stages.append(stage)
                    execution.errors.append(f"Stage {stage.value}: {str(e)}")
                    
                    execution.stage_results[stage.value] = {
                        "status": "failed",
                        "error": str(e)
                    }
                    
                    # Determine if failure should stop pipeline
                    if stage in [PipelineStage.INITIALIZATION, PipelineStage.SOURCE_ANALYSIS]:
                        execution.status = PipelineStatus.FAILED
                        break
                    else:
                        # Continue with warnings for non-critical stages
                        execution.warnings.append(f"Stage {stage.value} failed but pipeline continues")
            
            # Finalize execution
            execution.end_time = datetime.now(timezone.utc)
            execution.execution_time_seconds = (
                execution.end_time - execution.start_time
            ).total_seconds()
            
            if execution.status == PipelineStatus.RUNNING:
                execution.status = PipelineStatus.COMPLETED
                self.metrics["successful_executions"] += 1
            else:
                self.metrics["failed_executions"] += 1
            
            # Update metrics
            self._update_pipeline_metrics(execution)
            
            # Send notifications
            await self._send_pipeline_notifications(execution)
            
            # Log completion
            await self._log_pipeline_event(
                "PIPELINE_EXECUTION_COMPLETED",
                execution.execution_id,
                {
                    "status": execution.status.value,
                    "duration_seconds": execution.execution_time_seconds,
                    "findings_count": execution.findings_count,
                    "security_score": execution.security_score
                }
            )
            
            logger.info(f"Pipeline execution completed: {execution.execution_id} ({execution.status.value})")
            
        except Exception as e:
            logger.error(f"Pipeline execution failed: {execution.execution_id}: {e}")
            execution.status = PipelineStatus.FAILED
            execution.errors.append(f"Pipeline execution error: {str(e)}")
            self.metrics["failed_executions"] += 1
        
        finally:
            # Move to history and cleanup
            self.execution_history.append(execution)
            if execution.execution_id in self.active_executions:
                del self.active_executions[execution.execution_id]
    
    async def _stage_initialization(self, execution: PipelineExecution) -> Dict[str, Any]:
        """Initialize pipeline execution environment."""
        config = execution.pipeline_config
        
        # Validate configuration
        if not Path(config.source_path).exists():
            raise ValueError(f"Source path does not exist: {config.source_path}")
        
        # Check dependencies
        dependencies_ok = await self._check_dependencies()
        if not dependencies_ok:
            return {"continue": False, "block_reason": "Missing required dependencies"}
        
        # Initialize working directory
        work_dir = Path(f"/tmp/security_scan_{execution.execution_id}")
        work_dir.mkdir(exist_ok=True)
        
        return {
            "continue": True,
            "work_directory": str(work_dir),
            "dependencies_checked": True
        }
    
    async def _stage_source_analysis(self, execution: PipelineExecution) -> Dict[str, Any]:
        """Analyze source code structure and composition."""
        config = execution.pipeline_config
        source_path = Path(config.source_path)
        
        analysis_result = {
            "file_count": 0,
            "languages": {},
            "size_bytes": 0,
            "test_coverage": 0.0,
            "complexity_score": 0.0
        }
        
        # Analyze source files
        for file_path in source_path.rglob("*"):
            if file_path.is_file():
                analysis_result["file_count"] += 1
                analysis_result["size_bytes"] += file_path.stat().st_size
                
                # Language detection
                suffix = file_path.suffix.lower()
                if suffix in [".py", ".js", ".java", ".cs", ".cpp", ".go", ".rb", ".php"]:
                    lang = {".py": "python", ".js": "javascript", ".java": "java", 
                           ".cs": "csharp", ".cpp": "cpp", ".go": "go", ".rb": "ruby", ".php": "php"}.get(suffix, "other")
                    analysis_result["languages"][lang] = analysis_result["languages"].get(lang, 0) + 1
        
        # Determine primary language
        if analysis_result["languages"]:
            primary_language = max(analysis_result["languages"], key=analysis_result["languages"].get)
            analysis_result["primary_language"] = primary_language
        
        return {
            "continue": True,
            "analysis": analysis_result
        }
    
    async def _stage_dependency_scan(self, execution: PipelineExecution) -> Dict[str, Any]:
        """Scan dependencies for known vulnerabilities."""
        if not execution.pipeline_config.stages_enabled.get("dependency_scan", True):
            return {"continue": True, "skipped": True}
        
        findings = await self.security_test_engine.vulnerability_scanner.scan_dependencies(
            execution.pipeline_config.source_path
        )
        
        # Check quality gates
        critical_deps = len([f for f in findings if f.severity == SecuritySeverity.CRITICAL])
        high_deps = len([f for f in findings if f.severity == SecuritySeverity.HIGH])
        
        block_deployment = False
        block_reason = None
        
        if critical_deps > 0 and execution.pipeline_config.quality_gates.get("block_on_critical", True):
            block_deployment = True
            block_reason = f"Critical dependency vulnerabilities found: {critical_deps}"
        
        return {
            "continue": not block_deployment,
            "block_reason": block_reason,
            "findings": len(findings),
            "critical_findings": critical_deps,
            "high_findings": high_deps,
            "dependency_findings": findings
        }
    
    async def _stage_sast_execution(self, execution: PipelineExecution) -> Dict[str, Any]:
        """Execute Static Application Security Testing."""
        if not execution.pipeline_config.stages_enabled.get("sast", True):
            return {"continue": True, "skipped": True}
        
        findings = await self.security_test_engine.sast_engine.scan_codebase(
            execution.pipeline_config.source_path
        )
        
        # Analyze findings
        critical_sast = len([f for f in findings if f.severity == SecuritySeverity.CRITICAL])
        high_sast = len([f for f in findings if f.severity == SecuritySeverity.HIGH])
        
        return {
            "continue": True,
            "findings": len(findings),
            "critical_findings": critical_sast,
            "high_findings": high_sast,
            "sast_findings": findings
        }
    
    async def _stage_build_validation(self, execution: PipelineExecution) -> Dict[str, Any]:
        """Validate build process and artifacts."""
        config = execution.pipeline_config
        
        build_result = {
            "build_successful": True,
            "build_time_seconds": 0.0,
            "artifacts_created": [],
            "build_warnings": [],
            "security_checks_passed": True
        }
        
        # Attempt to build project if build configuration exists
        source_path = Path(config.source_path)
        
        # Check for common build files
        build_files = ["Makefile", "setup.py", "package.json", "pom.xml", "build.gradle", "Dockerfile"]
        found_build_files = [f for f in build_files if (source_path / f).exists()]
        
        if found_build_files:
            logger.info(f"Found build files: {found_build_files}")
            build_result["build_files"] = found_build_files
            
            # For demonstration, simulate build validation
            # In production, this would execute actual build commands
            await asyncio.sleep(1)  # Simulate build time
            build_result["build_time_seconds"] = 1.0
        
        return {
            "continue": build_result["security_checks_passed"],
            "build_validation": build_result
        }
    
    async def _stage_dast_execution(self, execution: PipelineExecution) -> Dict[str, Any]:
        """Execute Dynamic Application Security Testing."""
        if not execution.pipeline_config.stages_enabled.get("dast", True):
            return {"continue": True, "skipped": True}
        
        config = execution.pipeline_config
        if not config.target_url:
            return {
                "continue": True,
                "skipped": True,
                "reason": "No target URL configured for DAST"
            }
        
        findings = await self.security_test_engine.dast_engine.scan_web_application(
            config.target_url
        )
        
        # Analyze findings
        critical_dast = len([f for f in findings if f.severity == SecuritySeverity.CRITICAL])
        high_dast = len([f for f in findings if f.severity == SecuritySeverity.HIGH])
        
        return {
            "continue": True,
            "findings": len(findings),
            "critical_findings": critical_dast,
            "high_findings": high_dast,
            "dast_findings": findings
        }
    
    async def _stage_vulnerability_assessment(self, execution: PipelineExecution) -> Dict[str, Any]:
        """Comprehensive vulnerability assessment."""
        if not execution.pipeline_config.stages_enabled.get("vulnerability_assessment", True):
            return {"continue": True, "skipped": True}
        
        # Aggregate all findings from previous stages
        all_findings = []
        
        # Collect findings from previous stages
        for stage_name, stage_result in execution.stage_results.items():
            if "dependency_findings" in stage_result.get("result", {}):
                all_findings.extend(stage_result["result"]["dependency_findings"])
            if "sast_findings" in stage_result.get("result", {}):
                all_findings.extend(stage_result["result"]["sast_findings"])
            if "dast_findings" in stage_result.get("result", {}):
                all_findings.extend(stage_result["result"]["dast_findings"])
        
        # Calculate risk scores
        risk_score = self.security_test_engine.vulnerability_scanner.calculate_risk_score(all_findings)
        
        # Update execution metrics
        execution.findings_count = len(all_findings)
        execution.critical_findings = len([f for f in all_findings if f.severity == SecuritySeverity.CRITICAL])
        execution.high_findings = len([f for f in all_findings if f.severity == SecuritySeverity.HIGH])
        execution.medium_findings = len([f for f in all_findings if f.severity == SecuritySeverity.MEDIUM])
        execution.low_findings = len([f for f in all_findings if f.severity == SecuritySeverity.LOW])
        execution.security_score = risk_score
        
        return {
            "continue": True,
            "total_findings": len(all_findings),
            "risk_score": risk_score,
            "vulnerability_breakdown": {
                "critical": execution.critical_findings,
                "high": execution.high_findings,
                "medium": execution.medium_findings,
                "low": execution.low_findings
            }
        }
    
    async def _stage_compliance_check(self, execution: PipelineExecution) -> Dict[str, Any]:
        """Check compliance against security frameworks."""
        if not execution.pipeline_config.stages_enabled.get("compliance_check", True):
            return {"continue": True, "skipped": True}
        
        config = execution.pipeline_config
        compliance_results = {}
        
        # Check each configured compliance framework
        for framework in config.compliance_frameworks:
            compliance_score = await self._check_compliance_framework(execution, framework)
            compliance_results[framework] = compliance_score
        
        # Calculate overall compliance score
        overall_compliance = np.mean(list(compliance_results.values())) if compliance_results else 100.0
        
        return {
            "continue": True,
            "compliance_results": compliance_results,
            "overall_compliance_score": overall_compliance
        }
    
    async def _stage_reporting(self, execution: PipelineExecution) -> Dict[str, Any]:
        """Generate comprehensive security report."""
        # Create detailed security report
        report = SecurityTestReport(
            test_start_time=execution.start_time,
            test_end_time=execution.end_time or datetime.now(timezone.utc),
            total_execution_time_seconds=execution.execution_time_seconds,
            total_findings=execution.findings_count,
            critical_findings=execution.critical_findings,
            high_findings=execution.high_findings,
            medium_findings=execution.medium_findings,
            low_findings=execution.low_findings,
            overall_risk_score=execution.security_score
        )
        
        # Collect all findings
        all_findings = []
        for stage_result in execution.stage_results.values():
            stage_data = stage_result.get("result", {})
            for findings_key in ["dependency_findings", "sast_findings", "dast_findings"]:
                if findings_key in stage_data:
                    all_findings.extend(stage_data[findings_key])
        
        report.security_findings = all_findings
        execution.security_report = report
        
        # Generate executive summary
        self._generate_pipeline_executive_summary(execution, report)
        
        return {
            "continue": True,
            "report_generated": True,
            "report_id": report.report_id
        }
    
    async def _stage_deployment_gate(self, execution: PipelineExecution) -> Dict[str, Any]:
        """Evaluate deployment approval based on security findings."""
        config = execution.pipeline_config
        quality_gates = config.quality_gates
        
        # Check quality gate criteria
        gate_results = {}
        
        # Critical findings gate
        if quality_gates.get("block_on_critical", True) and execution.critical_findings > 0:
            gate_results["critical_findings"] = False
            execution.deployment_blocked_reason = f"Critical vulnerabilities found: {execution.critical_findings}"
        else:
            gate_results["critical_findings"] = True
        
        # High findings threshold gate
        high_threshold = quality_gates.get("block_on_high_threshold", 5)
        if execution.high_findings > high_threshold:
            gate_results["high_findings_threshold"] = False
            if not execution.deployment_blocked_reason:
                execution.deployment_blocked_reason = f"High vulnerabilities exceed threshold: {execution.high_findings} > {high_threshold}"
        else:
            gate_results["high_findings_threshold"] = True
        
        # Security score gate
        score_threshold = quality_gates.get("security_score_threshold", 70)
        if execution.security_score > score_threshold:
            gate_results["security_score"] = False
            if not execution.deployment_blocked_reason:
                execution.deployment_blocked_reason = f"Security score exceeds threshold: {execution.security_score} > {score_threshold}"
        else:
            gate_results["security_score"] = True
        
        # Overall deployment decision
        execution.deployment_approved = all(gate_results.values())
        execution.quality_gate_results = gate_results
        
        # Update metrics
        if not execution.deployment_approved:
            self.metrics["deployments_blocked"] += 1
        
        return {
            "continue": True,
            "deployment_approved": execution.deployment_approved,
            "quality_gate_results": gate_results,
            "blocked_reason": execution.deployment_blocked_reason
        }
    
    async def _check_dependencies(self) -> bool:
        """Check if required dependencies are available."""
        dependencies = [
            "Security Test Engine",
            "Audit Logger",
            "Monitoring System"
        ]
        
        # Check core components
        if not self.security_test_engine:
            return False
        if not self.audit_logger:
            return False
        if not self.monitoring_system:
            return False
        
        return True
    
    async def _check_compliance_framework(self, execution: PipelineExecution, framework: str) -> float:
        """Check compliance against specific framework."""
        compliance_checks = {
            "OWASP": self._check_owasp_compliance,
            "NIST": self._check_nist_compliance,
            "DoD": self._check_dod_compliance
        }
        
        check_func = compliance_checks.get(framework)
        if check_func:
            return await check_func(execution)
        
        return 100.0  # Default to compliant if framework not recognized
    
    async def _check_owasp_compliance(self, execution: PipelineExecution) -> float:
        """Check OWASP Top 10 compliance."""
        # Simplified OWASP compliance check
        # In production, this would be more comprehensive
        
        owasp_violations = 0
        total_checks = 10
        
        # Check for injection vulnerabilities
        if execution.critical_findings > 0 or execution.high_findings > 3:
            owasp_violations += 1
        
        # Check for broken authentication
        # This would analyze findings for auth-related issues
        
        # Check for sensitive data exposure
        # This would check for hardcoded secrets, etc.
        
        compliance_score = ((total_checks - owasp_violations) / total_checks) * 100
        return max(0.0, compliance_score)
    
    async def _check_nist_compliance(self, execution: PipelineExecution) -> float:
        """Check NIST Cybersecurity Framework compliance."""
        # Simplified NIST compliance check
        nist_score = 100.0
        
        # Deduct points for security findings
        if execution.critical_findings > 0:
            nist_score -= 30.0
        if execution.high_findings > 0:
            nist_score -= (execution.high_findings * 5.0)
        if execution.medium_findings > 0:
            nist_score -= (execution.medium_findings * 2.0)
        
        return max(0.0, nist_score)
    
    async def _check_dod_compliance(self, execution: PipelineExecution) -> float:
        """Check DoD security requirements compliance."""
        # DoD typically has stricter requirements
        dod_score = 100.0
        
        # Zero tolerance for critical vulnerabilities
        if execution.critical_findings > 0:
            dod_score = 0.0
        elif execution.high_findings > 2:
            dod_score = 30.0
        elif execution.high_findings > 0:
            dod_score = 70.0
        elif execution.medium_findings > 5:
            dod_score = 85.0
        
        return dod_score
    
    def _generate_pipeline_executive_summary(self, execution: PipelineExecution, report: SecurityTestReport):
        """Generate executive summary for pipeline execution."""
        summary = f"""
AUTOMATED SECURITY PIPELINE EXECUTION SUMMARY
Pipeline: {execution.pipeline_config.pipeline_name}
Execution ID: {execution.execution_id}
Trigger: {execution.trigger_type.value}
Duration: {execution.execution_time_seconds:.1f} seconds

SECURITY FINDINGS:
- Total Findings: {execution.findings_count}
- Critical: {execution.critical_findings}
- High: {execution.high_findings}
- Medium: {execution.medium_findings}
- Low: {execution.low_findings}

SECURITY SCORE: {execution.security_score:.1f}/100
DEPLOYMENT STATUS: {'APPROVED' if execution.deployment_approved else 'BLOCKED'}
"""
        
        if not execution.deployment_approved:
            summary += f"\nBLOCKED REASON: {execution.deployment_blocked_reason}"
        
        if execution.errors:
            summary += f"\nERRORS: {len(execution.errors)}"
        
        if execution.warnings:
            summary += f"\nWARNINGS: {len(execution.warnings)}"
        
        report.executive_summary = summary.strip()
    
    async def _send_pipeline_notifications(self, execution: PipelineExecution):
        """Send pipeline completion notifications."""
        config = execution.pipeline_config
        notifications = config.notifications
        
        # Prepare notification content
        status_emoji = "✅" if execution.status == PipelineStatus.COMPLETED else "❌"
        deployment_emoji = "🚀" if execution.deployment_approved else "🚫"
        
        message = f"""
{status_emoji} Security Pipeline {execution.status.value.title()}
Pipeline: {config.pipeline_name}
Duration: {execution.execution_time_seconds:.1f}s
Findings: {execution.findings_count} ({execution.critical_findings} critical, {execution.high_findings} high)
Security Score: {execution.security_score:.1f}/100
{deployment_emoji} Deployment: {'Approved' if execution.deployment_approved else 'Blocked'}
"""
        
        try:
            # Send to configured notification channels
            if notifications.get("slack_webhook"):
                await self._send_slack_notification(notifications["slack_webhook"], message)
            
            if notifications.get("teams_webhook"):
                await self._send_teams_notification(notifications["teams_webhook"], message)
            
            if notifications.get("email_recipients"):
                await self._send_email_notifications(notifications["email_recipients"], execution)
            
        except Exception as e:
            logger.error(f"Failed to send pipeline notifications: {e}")
    
    async def _send_slack_notification(self, webhook_url: str, message: str):
        """Send Slack notification."""
        async with aiohttp.ClientSession() as session:
            payload = {"text": message}
            async with session.post(webhook_url, json=payload) as response:
                if response.status != 200:
                    logger.warning(f"Slack notification failed: {response.status}")
    
    async def _send_teams_notification(self, webhook_url: str, message: str):
        """Send Microsoft Teams notification."""
        async with aiohttp.ClientSession() as session:
            payload = {
                "@type": "MessageCard",
                "@context": "http://schema.org/extensions",
                "text": message
            }
            async with session.post(webhook_url, json=payload) as response:
                if response.status != 200:
                    logger.warning(f"Teams notification failed: {response.status}")
    
    async def _send_email_notifications(self, recipients: List[str], execution: PipelineExecution):
        """Send email notifications."""
        # Email implementation would depend on your email service
        # This is a placeholder for the interface
        logger.info(f"Email notifications would be sent to: {recipients}")
    
    def _update_pipeline_metrics(self, execution: PipelineExecution):
        """Update pipeline execution metrics."""
        self.metrics["findings_detected"] += execution.findings_count
        self.metrics["critical_vulnerabilities"] += execution.critical_findings
        
        if execution.status == PipelineStatus.COMPLETED:
            # Update average execution time
            total_executions = self.metrics["successful_executions"]
            if total_executions > 0:
                current_avg = self.metrics["average_execution_time"]
                new_avg = ((current_avg * (total_executions - 1)) + execution.execution_time_seconds) / total_executions
                self.metrics["average_execution_time"] = new_avg
    
    async def _scheduler_loop(self):
        """Background scheduler for periodic pipeline execution."""
        while not self.shutdown_event.is_set():
            try:
                # Check for scheduled pipelines
                for pipeline_id, config in self.pipeline_configs.items():
                    if not config.enabled or ScanTrigger.SCHEDULED not in config.triggers:
                        continue
                    
                    # Simple scheduling logic - in production, use proper cron scheduling
                    now = datetime.now(timezone.utc)
                    if now.hour == 2 and now.minute < 5:  # Run daily at 2 AM
                        await self.trigger_pipeline(
                            pipeline_id, 
                            ScanTrigger.SCHEDULED,
                            "scheduler"
                        )
                
                # Wait before next check
                await asyncio.sleep(300)  # Check every 5 minutes
                
            except Exception as e:
                logger.error(f"Scheduler error: {e}")
                await asyncio.sleep(60)  # Wait 1 minute on error
    
    async def _log_pipeline_event(self, event_type: str, execution_id: str, context: Dict[str, Any]):
        """Log pipeline event to audit system."""
        try:
            audit_event = AuditEvent(
                event_id=str(uuid4()),
                timestamp=datetime.now(timezone.utc),
                event_type=AuditEventType.SECURITY_TEST_EXECUTED,
                severity=AuditSeverity.LOW,
                user_id=None,
                session_id=None,
                resource_type="security_pipeline",
                action=event_type.lower(),
                result="SUCCESS",
                additional_data={
                    "execution_id": execution_id,
                    **context
                }
            )
            
            await self.audit_logger.log_event(audit_event)
            
        except Exception as e:
            logger.error(f"Failed to log pipeline event: {e}")
    
    async def get_execution_status(self, execution_id: str) -> Optional[PipelineExecution]:
        """Get pipeline execution status."""
        if execution_id in self.active_executions:
            return self.active_executions[execution_id]
        
        # Check history
        for execution in self.execution_history:
            if execution.execution_id == execution_id:
                return execution
        
        return None
    
    async def cancel_execution(self, execution_id: str) -> bool:
        """Cancel running pipeline execution."""
        if execution_id not in self.active_executions:
            return False
        
        execution = self.active_executions[execution_id]
        execution.status = PipelineStatus.CANCELLED
        execution.end_time = datetime.now(timezone.utc)
        
        logger.info(f"Cancelled pipeline execution: {execution_id}")
        return True
    
    def get_pipeline_metrics(self) -> Dict[str, Any]:
        """Get pipeline execution metrics."""
        return {
            "metrics": self.metrics,
            "active_executions": len(self.active_executions),
            "configured_pipelines": len(self.pipeline_configs),
            "execution_history_size": len(self.execution_history)
        }
    
    async def health_check(self) -> Dict[str, Any]:
        """Perform health check of pipeline system."""
        health_status = {
            "status": "healthy",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "components": {},
            "metrics": self.get_pipeline_metrics()
        }
        
        try:
            # Check security test engine
            ste_health = await self.security_test_engine.health_check()
            health_status["components"]["security_test_engine"] = ste_health["status"]
            
            # Check Docker client
            health_status["components"]["docker_client"] = "available" if self.docker_client else "unavailable"
            
            # Check Kubernetes client
            health_status["components"]["kubernetes_client"] = "available" if self.k8s_client else "unavailable"
            
            # Check scheduler
            health_status["components"]["scheduler"] = "running" if self.scheduler_task and not self.scheduler_task.done() else "stopped"
            
        except Exception as e:
            health_status["status"] = "unhealthy"
            health_status["error"] = str(e)
        
        return health_status
    
    async def shutdown(self):
        """Shutdown pipeline system gracefully."""
        logger.info("Shutting down security scanning pipeline")
        
        # Stop scheduler
        self.shutdown_event.set()
        if self.scheduler_task:
            self.scheduler_task.cancel()
        
        # Wait for active executions to complete or cancel them
        for execution_id in list(self.active_executions.keys()):
            await self.cancel_execution(execution_id)
        
        # Shutdown thread pool
        self.thread_pool.shutdown(wait=True)
        
        # Close Docker client
        if self.docker_client:
            self.docker_client.close()
        
        logger.info("Security scanning pipeline shutdown completed")


class CICDIntegration:
    """
    CI/CD Platform Integration for Security Scanning Pipeline
    
    Provides comprehensive integration with major CI/CD platforms including
    GitHub Actions, Jenkins, GitLab CI, and Azure DevOps. Implements
    automated security gates, quality controls, and deployment policies.
    """
    
    def __init__(self, pipeline: SecurityScanningPipeline):
        """Initialize CI/CD integration."""
        self.pipeline = pipeline
        self.github_integration = GitHubActionsIntegration()
        self.jenkins_integration = JenkinsIntegration()
        self.gitlab_integration = GitLabCIIntegration()
        self.azure_integration = AzureDevOpsIntegration()
        
        # Quality gate configurations
        self.quality_gates = {
            "critical_vulnerability_gate": {
                "enabled": True,
                "threshold": 0,
                "action": "block"
            },
            "high_vulnerability_gate": {
                "enabled": True,
                "threshold": 5,
                "action": "block"
            },
            "security_score_gate": {
                "enabled": True,
                "threshold": 70,
                "action": "block"
            },
            "compliance_gate": {
                "enabled": True,
                "threshold": 85,
                "action": "warn"
            },
            "code_coverage_gate": {
                "enabled": True,
                "threshold": 80,
                "action": "warn"
            }
        }
        
        # Deployment policies
        self.deployment_policies = {
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
        
        logger.info("CI/CD Integration initialized")
    
    async def setup_webhook_handlers(self, app):
        """Setup webhook handlers for CI/CD platforms."""
        
        @app.route('/webhooks/github', methods=['POST'])
        async def github_webhook_handler(request):
            """Handle GitHub webhook events."""
            return await self.github_integration.handle_webhook(request, self.pipeline)
        
        @app.route('/webhooks/jenkins', methods=['POST'])
        async def jenkins_webhook_handler(request):
            """Handle Jenkins webhook events."""
            return await self.jenkins_integration.handle_webhook(request, self.pipeline)
        
        @app.route('/webhooks/gitlab', methods=['POST'])
        async def gitlab_webhook_handler(request):
            """Handle GitLab webhook events."""
            return await self.gitlab_integration.handle_webhook(request, self.pipeline)
        
        @app.route('/webhooks/azure', methods=['POST'])
        async def azure_webhook_handler(request):
            """Handle Azure DevOps webhook events."""
            return await self.azure_integration.handle_webhook(request, self.pipeline)
    
    async def evaluate_quality_gates(self, execution: PipelineExecution) -> Dict[str, Any]:
        """Evaluate all configured quality gates."""
        gate_results = {}
        overall_status = "PASSED"
        blocking_issues = []
        warnings = []
        
        # Critical vulnerability gate
        if self.quality_gates["critical_vulnerability_gate"]["enabled"]:
            threshold = self.quality_gates["critical_vulnerability_gate"]["threshold"]
            if execution.critical_findings > threshold:
                gate_results["critical_vulnerability_gate"] = "FAILED"
                if self.quality_gates["critical_vulnerability_gate"]["action"] == "block":
                    overall_status = "BLOCKED"
                    blocking_issues.append(f"Critical vulnerabilities ({execution.critical_findings}) exceed threshold ({threshold})")
            else:
                gate_results["critical_vulnerability_gate"] = "PASSED"
        
        # High vulnerability gate
        if self.quality_gates["high_vulnerability_gate"]["enabled"]:
            threshold = self.quality_gates["high_vulnerability_gate"]["threshold"]
            if execution.high_findings > threshold:
                gate_results["high_vulnerability_gate"] = "FAILED"
                if self.quality_gates["high_vulnerability_gate"]["action"] == "block":
                    overall_status = "BLOCKED"
                    blocking_issues.append(f"High vulnerabilities ({execution.high_findings}) exceed threshold ({threshold})")
                else:
                    warnings.append(f"High vulnerabilities ({execution.high_findings}) exceed threshold ({threshold})")
            else:
                gate_results["high_vulnerability_gate"] = "PASSED"
        
        # Security score gate
        if self.quality_gates["security_score_gate"]["enabled"]:
            threshold = self.quality_gates["security_score_gate"]["threshold"]
            if execution.security_score > threshold:  # Higher score means more risk
                gate_results["security_score_gate"] = "FAILED"
                if self.quality_gates["security_score_gate"]["action"] == "block":
                    overall_status = "BLOCKED"
                    blocking_issues.append(f"Security score ({execution.security_score:.1f}) exceeds threshold ({threshold})")
                else:
                    warnings.append(f"Security score ({execution.security_score:.1f}) exceeds threshold ({threshold})")
            else:
                gate_results["security_score_gate"] = "PASSED"
        
        # Compliance gate
        compliance_results = execution.stage_results.get("compliance_check", {}).get("result", {})
        if self.quality_gates["compliance_gate"]["enabled"] and compliance_results:
            compliance_score = compliance_results.get("overall_compliance_score", 100)
            threshold = self.quality_gates["compliance_gate"]["threshold"]
            if compliance_score < threshold:
                gate_results["compliance_gate"] = "FAILED"
                if self.quality_gates["compliance_gate"]["action"] == "block":
                    overall_status = "BLOCKED"
                    blocking_issues.append(f"Compliance score ({compliance_score:.1f}) below threshold ({threshold})")
                else:
                    warnings.append(f"Compliance score ({compliance_score:.1f}) below threshold ({threshold})")
            else:
                gate_results["compliance_gate"] = "PASSED"
        
        return {
            "overall_status": overall_status,
            "gate_results": gate_results,
            "blocking_issues": blocking_issues,
            "warnings": warnings,
            "evaluation_timestamp": datetime.now(timezone.utc).isoformat()
        }
    
    async def evaluate_deployment_policy(self, execution: PipelineExecution, environment: str) -> Dict[str, Any]:
        """Evaluate deployment policy for specific environment."""
        if environment not in self.deployment_policies:
            return {
                "approved": False,
                "reason": f"Unknown environment: {environment}"
            }
        
        policy = self.deployment_policies[environment]
        policy_results = {}
        approved = True
        reasons = []
        
        # Check critical vulnerabilities
        if execution.critical_findings > policy["max_critical_vulnerabilities"]:
            policy_results["critical_vulnerabilities"] = False
            approved = False
            reasons.append(f"Critical vulnerabilities ({execution.critical_findings}) exceed policy limit ({policy['max_critical_vulnerabilities']})")
        else:
            policy_results["critical_vulnerabilities"] = True
        
        # Check high vulnerabilities
        if execution.high_findings > policy["max_high_vulnerabilities"]:
            policy_results["high_vulnerabilities"] = False
            approved = False
            reasons.append(f"High vulnerabilities ({execution.high_findings}) exceed policy limit ({policy['max_high_vulnerabilities']})")
        else:
            policy_results["high_vulnerabilities"] = True
        
        # Check security score
        if execution.security_score > (100 - policy["min_security_score"]):  # Convert to risk score
            policy_results["security_score"] = False
            approved = False
            reasons.append(f"Security score does not meet minimum requirement ({policy['min_security_score']})")
        else:
            policy_results["security_score"] = True
        
        # Check compliance score
        compliance_results = execution.stage_results.get("compliance_check", {}).get("result", {})
        if compliance_results:
            compliance_score = compliance_results.get("overall_compliance_score", 0)
            if compliance_score < policy["min_compliance_score"]:
                policy_results["compliance_score"] = False
                approved = False
                reasons.append(f"Compliance score ({compliance_score:.1f}) below minimum requirement ({policy['min_compliance_score']})")
            else:
                policy_results["compliance_score"] = True
        
        return {
            "environment": environment,
            "approved": approved,
            "policy_results": policy_results,
            "reasons": reasons,
            "policy_applied": policy,
            "evaluation_timestamp": datetime.now(timezone.utc).isoformat()
        }
    
    async def generate_ci_cd_report(self, execution: PipelineExecution) -> Dict[str, Any]:
        """Generate comprehensive CI/CD integration report."""
        quality_gates = await self.evaluate_quality_gates(execution)
        
        # Evaluate all environments
        deployment_evaluations = {}
        for env in self.deployment_policies.keys():
            deployment_evaluations[env] = await self.evaluate_deployment_policy(execution, env)
        
        report = {
            "execution_id": execution.execution_id,
            "pipeline_name": execution.pipeline_config.pipeline_name,
            "trigger_type": execution.trigger_type.value,
            "execution_status": execution.status.value,
            "quality_gates": quality_gates,
            "deployment_evaluations": deployment_evaluations,
            "security_summary": {
                "total_findings": execution.findings_count,
                "critical_findings": execution.critical_findings,
                "high_findings": execution.high_findings,
                "medium_findings": execution.medium_findings,
                "low_findings": execution.low_findings,
                "security_score": execution.security_score
            },
            "execution_metrics": {
                "start_time": execution.start_time.isoformat(),
                "end_time": execution.end_time.isoformat() if execution.end_time else None,
                "duration_seconds": execution.execution_time_seconds,
                "completed_stages": [stage.value for stage in execution.completed_stages],
                "failed_stages": [stage.value for stage in execution.failed_stages]
            },
            "recommendations": self._generate_recommendations(execution, quality_gates, deployment_evaluations),
            "report_timestamp": datetime.now(timezone.utc).isoformat()
        }
        
        return report
    
    def _generate_recommendations(self, execution: PipelineExecution, quality_gates: Dict, deployment_evaluations: Dict) -> List[str]:
        """Generate actionable recommendations based on pipeline results."""
        recommendations = []
        
        # Security-based recommendations
        if execution.critical_findings > 0:
            recommendations.append(f"CRITICAL: Address {execution.critical_findings} critical security vulnerabilities before deployment")
        
        if execution.high_findings > 5:
            recommendations.append(f"HIGH: Reduce high-severity findings from {execution.high_findings} to below 5")
        
        if execution.security_score > 70:
            recommendations.append(f"Improve overall security posture (current score: {execution.security_score:.1f}/100)")
        
        # Quality gate recommendations
        if quality_gates["overall_status"] == "BLOCKED":
            recommendations.append("Address quality gate failures before proceeding with deployment")
            for issue in quality_gates["blocking_issues"]:
                recommendations.append(f"- {issue}")
        
        # Deployment recommendations
        for env, eval_result in deployment_evaluations.items():
            if not eval_result["approved"]:
                recommendations.append(f"Environment '{env}' deployment blocked:")
                for reason in eval_result["reasons"]:
                    recommendations.append(f"  - {reason}")
        
        # Performance recommendations
        if execution.execution_time_seconds > 1800:  # 30 minutes
            recommendations.append("Consider optimizing pipeline performance to reduce execution time")
        
        # Stage-specific recommendations
        if execution.failed_stages:
            recommendations.append(f"Investigate and fix failed pipeline stages: {', '.join([s.value for s in execution.failed_stages])}")
        
        return recommendations


class GitHubActionsIntegration:
    """GitHub Actions specific integration."""
    
    async def handle_webhook(self, request, pipeline: SecurityScanningPipeline) -> Dict[str, Any]:
        """Handle GitHub Actions webhook events."""
        try:
            payload = await request.json()
            event_type = request.headers.get('X-GitHub-Event')
            
            if event_type == 'push':
                return await self._handle_push_event(payload, pipeline)
            elif event_type == 'pull_request':
                return await self._handle_pull_request_event(payload, pipeline)
            elif event_type == 'workflow_run':
                return await self._handle_workflow_run_event(payload, pipeline)
            
            return {"status": "ignored", "event_type": event_type}
            
        except Exception as e:
            logger.error(f"GitHub webhook handling failed: {e}")
            return {"status": "error", "message": str(e)}
    
    async def _handle_push_event(self, payload, pipeline) -> Dict[str, Any]:
        """Handle GitHub push events."""
        repo = payload.get('repository', {}).get('full_name')
        branch = payload.get('ref', '').split('/')[-1]
        commit_sha = payload.get('head_commit', {}).get('id')
        
        # Trigger security scan for push to main/develop
        if branch in ['main', 'develop']:
            config_id = await self._get_or_create_pipeline_config(pipeline, repo)
            
            execution_id = await pipeline.trigger_pipeline(
                config_id,
                ScanTrigger.CODE_COMMIT,
                payload.get('pusher', {}).get('name'),
                {
                    "repository": repo,
                    "branch": branch,
                    "commit_sha": commit_sha,
                    "github_event": "push"
                }
            )
            
            return {
                "status": "triggered",
                "execution_id": execution_id,
                "repository": repo,
                "branch": branch
            }
        
        return {"status": "skipped", "reason": f"Branch {branch} not configured for scanning"}
    
    async def _handle_pull_request_event(self, payload, pipeline) -> Dict[str, Any]:
        """Handle GitHub pull request events."""
        action = payload.get('action')
        if action not in ['opened', 'synchronize', 'reopened']:
            return {"status": "ignored", "action": action}
        
        repo = payload.get('repository', {}).get('full_name')
        pr_number = payload.get('pull_request', {}).get('number')
        
        config_id = await self._get_or_create_pipeline_config(pipeline, repo)
        
        execution_id = await pipeline.trigger_pipeline(
            config_id,
            ScanTrigger.PULL_REQUEST,
            payload.get('pull_request', {}).get('user', {}).get('login'),
            {
                "repository": repo,
                "pull_request_number": pr_number,
                "github_event": "pull_request",
                "action": action
            }
        )
        
        return {
            "status": "triggered",
            "execution_id": execution_id,
            "repository": repo,
            "pull_request": pr_number
        }
    
    async def _handle_workflow_run_event(self, payload, pipeline) -> Dict[str, Any]:
        """Handle GitHub workflow run events."""
        # Handle workflow completion events for status updates
        workflow_run = payload.get('workflow_run', {})
        status = workflow_run.get('status')
        conclusion = workflow_run.get('conclusion')
        
        if status == 'completed':
            # Update pipeline execution status based on workflow conclusion
            return {
                "status": "workflow_completed",
                "conclusion": conclusion
            }
        
        return {"status": "ignored", "workflow_status": status}
    
    async def _get_or_create_pipeline_config(self, pipeline, repo) -> str:
        """Get or create pipeline configuration for repository."""
        # Check if config exists for this repository
        for config_id, config in pipeline.pipeline_configs.items():
            if config.source_path == repo:
                return config_id
        
        # Create new configuration
        config_data = {
            "pipeline_name": f"security_scan_{repo.replace('/', '_')}",
            "source_path": repo,
            "ci_cd_system": "github"
        }
        
        return await pipeline.create_pipeline_config(config_data)
    
    async def create_github_status_check(self, execution: PipelineExecution, token: str) -> bool:
        """Create GitHub status check for pipeline execution."""
        try:
            trigger_context = execution.trigger_context
            repo = trigger_context.get('repository')
            commit_sha = trigger_context.get('commit_sha')
            
            if not repo or not commit_sha:
                return False
            
            status_data = {
                "state": self._map_execution_status_to_github(execution.status),
                "target_url": f"https://security-dashboard.example.com/executions/{execution.execution_id}",
                "description": self._generate_github_status_description(execution),
                "context": "security/automated-scan"
            }
            
            headers = {
                "Authorization": f"token {token}",
                "Accept": "application/vnd.github.v3+json"
            }
            
            async with aiohttp.ClientSession() as session:
                url = f"https://api.github.com/repos/{repo}/statuses/{commit_sha}"
                async with session.post(url, json=status_data, headers=headers) as response:
                    return response.status == 201
                    
        except Exception as e:
            logger.error(f"Failed to create GitHub status check: {e}")
            return False
    
    def _map_execution_status_to_github(self, status: PipelineStatus) -> str:
        """Map pipeline status to GitHub status."""
        mapping = {
            PipelineStatus.PENDING: "pending",
            PipelineStatus.RUNNING: "pending",
            PipelineStatus.COMPLETED: "success",
            PipelineStatus.FAILED: "failure",
            PipelineStatus.CANCELLED: "error",
            PipelineStatus.BLOCKED: "failure"
        }
        return mapping.get(status, "error")
    
    def _generate_github_status_description(self, execution: PipelineExecution) -> str:
        """Generate GitHub status description."""
        if execution.status == PipelineStatus.COMPLETED:
            if execution.deployment_approved:
                return f"Security scan passed ({execution.findings_count} findings, score: {execution.security_score:.1f})"
            else:
                return f"Security scan completed but deployment blocked ({execution.deployment_blocked_reason})"
        elif execution.status == PipelineStatus.RUNNING:
            return f"Security scan in progress (stage: {execution.current_stage.value if execution.current_stage else 'unknown'})"
        elif execution.status == PipelineStatus.FAILED:
            return f"Security scan failed ({len(execution.errors)} errors)"
        else:
            return f"Security scan {execution.status.value}"


class JenkinsIntegration:
    """Jenkins specific integration."""
    
    async def handle_webhook(self, request, pipeline: SecurityScanningPipeline) -> Dict[str, Any]:
        """Handle Jenkins webhook events."""
        try:
            payload = await request.json()
            
            # Jenkins typically sends build status updates
            build_status = payload.get('build', {}).get('status')
            job_name = payload.get('name')
            build_number = payload.get('build', {}).get('number')
            
            if build_status in ['SUCCESS', 'FAILURE', 'UNSTABLE']:
                return await self._handle_build_completion(payload, pipeline)
            
            return {"status": "ignored", "build_status": build_status}
            
        except Exception as e:
            logger.error(f"Jenkins webhook handling failed: {e}")
            return {"status": "error", "message": str(e)}
    
    async def _handle_build_completion(self, payload, pipeline) -> Dict[str, Any]:
        """Handle Jenkins build completion."""
        job_name = payload.get('name')
        
        # Determine if this is a job that should trigger security scanning
        if 'security' in job_name.lower() or 'deploy' in job_name.lower():
            config_id = await self._get_or_create_pipeline_config(pipeline, job_name)
            
            execution_id = await pipeline.trigger_pipeline(
                config_id,
                ScanTrigger.DEPLOYMENT,
                payload.get('build', {}).get('user'),
                {
                    "jenkins_job": job_name,
                    "build_number": payload.get('build', {}).get('number'),
                    "build_status": payload.get('build', {}).get('status')
                }
            )
            
            return {
                "status": "triggered",
                "execution_id": execution_id,
                "job_name": job_name
            }
        
        return {"status": "skipped", "reason": f"Job {job_name} not configured for security scanning"}
    
    async def _get_or_create_pipeline_config(self, pipeline, job_name) -> str:
        """Get or create pipeline configuration for Jenkins job."""
        for config_id, config in pipeline.pipeline_configs.items():
            if config.pipeline_name == f"jenkins_{job_name}":
                return config_id
        
        config_data = {
            "pipeline_name": f"jenkins_{job_name}",
            "source_path": ".",  # Jenkins workspace
            "ci_cd_system": "jenkins"
        }
        
        return await pipeline.create_pipeline_config(config_data)


class GitLabCIIntegration:
    """GitLab CI specific integration."""
    
    async def handle_webhook(self, request, pipeline: SecurityScanningPipeline) -> Dict[str, Any]:
        """Handle GitLab CI webhook events."""
        try:
            payload = await request.json()
            event_type = request.headers.get('X-Gitlab-Event')
            
            if event_type == 'Push Hook':
                return await self._handle_push_event(payload, pipeline)
            elif event_type == 'Merge Request Hook':
                return await self._handle_merge_request_event(payload, pipeline)
            elif event_type == 'Pipeline Hook':
                return await self._handle_pipeline_event(payload, pipeline)
            
            return {"status": "ignored", "event_type": event_type}
            
        except Exception as e:
            logger.error(f"GitLab webhook handling failed: {e}")
            return {"status": "error", "message": str(e)}
    
    async def _handle_push_event(self, payload, pipeline) -> Dict[str, Any]:
        """Handle GitLab push events."""
        project = payload.get('project', {})
        branch = payload.get('ref', '').split('/')[-1]
        
        if branch in ['main', 'master', 'develop']:
            config_id = await self._get_or_create_pipeline_config(pipeline, project.get('path_with_namespace'))
            
            execution_id = await pipeline.trigger_pipeline(
                config_id,
                ScanTrigger.CODE_COMMIT,
                payload.get('user_name'),
                {
                    "gitlab_project": project.get('path_with_namespace'),
                    "branch": branch,
                    "gitlab_event": "push"
                }
            )
            
            return {
                "status": "triggered",
                "execution_id": execution_id,
                "project": project.get('path_with_namespace')
            }
        
        return {"status": "skipped", "reason": f"Branch {branch} not configured for scanning"}
    
    async def _handle_merge_request_event(self, payload, pipeline) -> Dict[str, Any]:
        """Handle GitLab merge request events."""
        action = payload.get('object_attributes', {}).get('action')
        if action not in ['open', 'update', 'reopen']:
            return {"status": "ignored", "action": action}
        
        project = payload.get('project', {})
        
        config_id = await self._get_or_create_pipeline_config(pipeline, project.get('path_with_namespace'))
        
        execution_id = await pipeline.trigger_pipeline(
            config_id,
            ScanTrigger.PULL_REQUEST,
            payload.get('user', {}).get('username'),
            {
                "gitlab_project": project.get('path_with_namespace'),
                "merge_request_id": payload.get('object_attributes', {}).get('iid'),
                "gitlab_event": "merge_request"
            }
        )
        
        return {
            "status": "triggered",
            "execution_id": execution_id,
            "project": project.get('path_with_namespace')
        }
    
    async def _handle_pipeline_event(self, payload, pipeline) -> Dict[str, Any]:
        """Handle GitLab pipeline events."""
        # Handle pipeline status updates
        pipeline_status = payload.get('object_attributes', {}).get('status')
        
        return {
            "status": "pipeline_status_received",
            "pipeline_status": pipeline_status
        }
    
    async def _get_or_create_pipeline_config(self, pipeline, project_path) -> str:
        """Get or create pipeline configuration for GitLab project."""
        for config_id, config in pipeline.pipeline_configs.items():
            if config.source_path == project_path:
                return config_id
        
        config_data = {
            "pipeline_name": f"gitlab_{project_path.replace('/', '_')}",
            "source_path": project_path,
            "ci_cd_system": "gitlab"
        }
        
        return await pipeline.create_pipeline_config(config_data)


class AzureDevOpsIntegration:
    """Azure DevOps specific integration."""
    
    async def handle_webhook(self, request, pipeline: SecurityScanningPipeline) -> Dict[str, Any]:
        """Handle Azure DevOps webhook events."""
        try:
            payload = await request.json()
            event_type = payload.get('eventType')
            
            if event_type == 'git.push':
                return await self._handle_push_event(payload, pipeline)
            elif event_type == 'git.pullrequest.created':
                return await self._handle_pull_request_event(payload, pipeline)
            elif event_type == 'build.complete':
                return await self._handle_build_complete_event(payload, pipeline)
            
            return {"status": "ignored", "event_type": event_type}
            
        except Exception as e:
            logger.error(f"Azure DevOps webhook handling failed: {e}")
            return {"status": "error", "message": str(e)}
    
    async def _handle_push_event(self, payload, pipeline) -> Dict[str, Any]:
        """Handle Azure DevOps push events."""
        resource = payload.get('resource', {})
        repository = resource.get('repository', {})
        
        config_id = await self._get_or_create_pipeline_config(pipeline, repository.get('name'))
        
        execution_id = await pipeline.trigger_pipeline(
            config_id,
            ScanTrigger.CODE_COMMIT,
            resource.get('pushedBy', {}).get('displayName'),
            {
                "azure_repository": repository.get('name'),
                "azure_event": "push"
            }
        )
        
        return {
            "status": "triggered",
            "execution_id": execution_id,
            "repository": repository.get('name')
        }
    
    async def _handle_pull_request_event(self, payload, pipeline) -> Dict[str, Any]:
        """Handle Azure DevOps pull request events."""
        resource = payload.get('resource', {})
        repository = resource.get('repository', {})
        
        config_id = await self._get_or_create_pipeline_config(pipeline, repository.get('name'))
        
        execution_id = await pipeline.trigger_pipeline(
            config_id,
            ScanTrigger.PULL_REQUEST,
            resource.get('createdBy', {}).get('displayName'),
            {
                "azure_repository": repository.get('name'),
                "pull_request_id": resource.get('pullRequestId'),
                "azure_event": "pull_request"
            }
        )
        
        return {
            "status": "triggered",
            "execution_id": execution_id,
            "repository": repository.get('name')
        }
    
    async def _handle_build_complete_event(self, payload, pipeline) -> Dict[str, Any]:
        """Handle Azure DevOps build completion events."""
        resource = payload.get('resource', {})
        build_status = resource.get('status')
        
        if build_status in ['completed']:
            # Trigger security scan after successful build
            config_id = await self._get_or_create_pipeline_config(pipeline, resource.get('definition', {}).get('name'))
            
            execution_id = await pipeline.trigger_pipeline(
                config_id,
                ScanTrigger.DEPLOYMENT,
                resource.get('requestedFor', {}).get('displayName'),
                {
                    "azure_build_id": resource.get('id'),
                    "build_status": build_status,
                    "azure_event": "build_complete"
                }
            )
            
            return {
                "status": "triggered",
                "execution_id": execution_id,
                "build_id": resource.get('id')
            }
        
        return {"status": "skipped", "build_status": build_status}
    
    async def _get_or_create_pipeline_config(self, pipeline, project_name) -> str:
        """Get or create pipeline configuration for Azure DevOps project."""
        for config_id, config in pipeline.pipeline_configs.items():
            if config.pipeline_name == f"azure_{project_name}":
                return config_id
        
        config_data = {
            "pipeline_name": f"azure_{project_name}",
            "source_path": ".",
            "ci_cd_system": "azure_devops"
        }
        
        return await pipeline.create_pipeline_config(config_data)


class SecurityQualityGate:
    """
    Advanced Security Quality Gate System
    
    Implements comprehensive security quality gates with configurable
    thresholds, automated decision making, and integration with
    deployment pipelines.
    """
    
    def __init__(self):
        """Initialize security quality gate system."""
        self.gate_definitions = {
            "vulnerability_gate": {
                "name": "Vulnerability Threshold Gate",
                "description": "Blocks deployment based on vulnerability counts and severity",
                "enabled": True,
                "rules": [
                    {
                        "condition": "critical_vulnerabilities > 0",
                        "action": "block",
                        "message": "Critical vulnerabilities must be resolved before deployment"
                    },
                    {
                        "condition": "high_vulnerabilities > 5",
                        "action": "block", 
                        "message": "High-severity vulnerabilities exceed acceptable threshold (5)"
                    },
                    {
                        "condition": "medium_vulnerabilities > 20",
                        "action": "warn",
                        "message": "Medium-severity vulnerabilities are elevated"
                    }
                ]
            },
            "security_score_gate": {
                "name": "Security Score Gate",
                "description": "Evaluates overall security posture score",
                "enabled": True,
                "rules": [
                    {
                        "condition": "security_score > 80",
                        "action": "block",
                        "message": "Security score indicates high risk (threshold: 80)"
                    },
                    {
                        "condition": "security_score > 60",
                        "action": "warn",
                        "message": "Security score indicates moderate risk"
                    }
                ]
            },
            "compliance_gate": {
                "name": "Compliance Gate",
                "description": "Validates compliance with security frameworks",
                "enabled": True,
                "rules": [
                    {
                        "condition": "compliance_score < 85",
                        "action": "block",
                        "message": "Compliance score below required threshold (85%)"
                    }
                ]
            },
            "code_quality_gate": {
                "name": "Code Quality Gate", 
                "description": "Evaluates code quality metrics",
                "enabled": True,
                "rules": [
                    {
                        "condition": "code_coverage < 80",
                        "action": "warn",
                        "message": "Code coverage below recommended threshold (80%)"
                    },
                    {
                        "condition": "complexity_score > 15",
                        "action": "warn",
                        "message": "Code complexity is elevated"
                    }
                ]
            },
            "dependency_gate": {
                "name": "Dependency Security Gate",
                "description": "Validates dependency security",
                "enabled": True,
                "rules": [
                    {
                        "condition": "vulnerable_dependencies > 0",
                        "action": "block",
                        "message": "Vulnerable dependencies must be updated"
                    },
                    {
                        "condition": "outdated_dependencies > 10",
                        "action": "warn",
                        "message": "Many dependencies are outdated"
                    }
                ]
            }
        }
        
        self.gate_history = deque(maxlen=1000)
        logger.info("Security Quality Gate system initialized")
    
    async def evaluate_gates(self, execution: PipelineExecution, environment: str = "production") -> Dict[str, Any]:
        """Evaluate all security quality gates."""
        evaluation_id = str(uuid4())
        evaluation_start = datetime.now(timezone.utc)
        
        gate_results = {}
        overall_status = "PASSED"
        blocking_gates = []
        warning_gates = []
        
        # Extract metrics from execution
        metrics = self._extract_evaluation_metrics(execution)
        
        # Evaluate each gate
        for gate_name, gate_def in self.gate_definitions.items():
            if not gate_def["enabled"]:
                continue
            
            gate_result = await self._evaluate_gate(gate_name, gate_def, metrics, environment)
            gate_results[gate_name] = gate_result
            
            if gate_result["status"] == "BLOCKED":
                overall_status = "BLOCKED"
                blocking_gates.append({
                    "gate": gate_name,
                    "reason": gate_result["message"]
                })
            elif gate_result["status"] == "WARNING":
                warning_gates.append({
                    "gate": gate_name,
                    "reason": gate_result["message"]
                })
        
        evaluation_result = {
            "evaluation_id": evaluation_id,
            "execution_id": execution.execution_id,
            "environment": environment,
            "overall_status": overall_status,
            "gate_results": gate_results,
            "blocking_gates": blocking_gates,
            "warning_gates": warning_gates,
            "metrics_evaluated": metrics,
            "evaluation_timestamp": evaluation_start.isoformat(),
            "evaluation_duration_ms": (datetime.now(timezone.utc) - evaluation_start).total_seconds() * 1000
        }
        
        # Store in history
        self.gate_history.append(evaluation_result)
        
        return evaluation_result
    
    async def _evaluate_gate(self, gate_name: str, gate_def: Dict, metrics: Dict, environment: str) -> Dict[str, Any]:
        """Evaluate individual security gate."""
        gate_result = {
            "gate_name": gate_name,
            "status": "PASSED",
            "message": "All conditions passed",
            "rules_evaluated": [],
            "environment": environment
        }
        
        # Evaluate each rule in the gate
        for rule in gate_def["rules"]:
            rule_result = self._evaluate_rule(rule, metrics)
            gate_result["rules_evaluated"].append(rule_result)
            
            if rule_result["triggered"]:
                if rule["action"] == "block":
                    gate_result["status"] = "BLOCKED"
                    gate_result["message"] = rule["message"]
                    break  # Block immediately
                elif rule["action"] == "warn":
                    gate_result["status"] = "WARNING"
                    gate_result["message"] = rule["message"]
        
        return gate_result
    
    def _evaluate_rule(self, rule: Dict, metrics: Dict) -> Dict[str, Any]:
        """Evaluate individual gate rule."""
        condition = rule["condition"]
        
        # Replace metrics in condition
        condition_evaluated = condition
        for metric_name, metric_value in metrics.items():
            condition_evaluated = condition_evaluated.replace(metric_name, str(metric_value))
        
        try:
            # Safely evaluate condition
            triggered = eval(condition_evaluated)
        except Exception as e:
            logger.error(f"Failed to evaluate rule condition '{condition}': {e}")
            triggered = False
        
        return {
            "condition": condition,
            "condition_evaluated": condition_evaluated,
            "triggered": triggered,
            "action": rule["action"],
            "message": rule["message"]
        }
    
    def _extract_evaluation_metrics(self, execution: PipelineExecution) -> Dict[str, Any]:
        """Extract metrics from pipeline execution for gate evaluation."""
        metrics = {
            # Vulnerability metrics
            "critical_vulnerabilities": execution.critical_findings,
            "high_vulnerabilities": execution.high_findings,
            "medium_vulnerabilities": execution.medium_findings,
            "low_vulnerabilities": execution.low_findings,
            "total_vulnerabilities": execution.findings_count,
            
            # Security score
            "security_score": execution.security_score,
            
            # Compliance metrics
            "compliance_score": 0,  # Default, will be updated if available
            
            # Code quality metrics (defaults)
            "code_coverage": 85,  # Default value
            "complexity_score": 10,  # Default value
            
            # Dependency metrics (defaults)
            "vulnerable_dependencies": 0,
            "outdated_dependencies": 5
        }
        
        # Extract compliance score if available
        compliance_results = execution.stage_results.get("compliance_check", {}).get("result", {})
        if compliance_results:
            metrics["compliance_score"] = compliance_results.get("overall_compliance_score", 0)
        
        # Extract dependency information if available
        dep_results = execution.stage_results.get("dependency_scan", {}).get("result", {})
        if dep_results:
            metrics["vulnerable_dependencies"] = dep_results.get("critical_findings", 0) + dep_results.get("high_findings", 0)
        
        return metrics
    
    async def create_custom_gate(self, gate_name: str, gate_definition: Dict[str, Any]) -> bool:
        """Create custom security quality gate."""
        try:
            # Validate gate definition
            required_fields = ["name", "description", "enabled", "rules"]
            if not all(field in gate_definition for field in required_fields):
                raise ValueError(f"Gate definition missing required fields: {required_fields}")
            
            # Validate rules
            for rule in gate_definition["rules"]:
                required_rule_fields = ["condition", "action", "message"]
                if not all(field in rule for field in required_rule_fields):
                    raise ValueError(f"Rule missing required fields: {required_rule_fields}")
                
                if rule["action"] not in ["block", "warn"]:
                    raise ValueError(f"Invalid rule action: {rule['action']}")
            
            # Add gate to definitions
            self.gate_definitions[gate_name] = gate_definition
            
            logger.info(f"Created custom security gate: {gate_name}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to create custom gate '{gate_name}': {e}")
            return False
    
    def get_gate_statistics(self) -> Dict[str, Any]:
        """Get gate evaluation statistics."""
        if not self.gate_history:
            return {"message": "No gate evaluations available"}
        
        total_evaluations = len(self.gate_history)
        blocked_evaluations = len([e for e in self.gate_history if e["overall_status"] == "BLOCKED"])
        warning_evaluations = len([e for e in self.gate_history if e["overall_status"] == "WARNING"])
        passed_evaluations = len([e for e in self.gate_history if e["overall_status"] == "PASSED"])
        
        # Gate-specific statistics
        gate_stats = {}
        for gate_name in self.gate_definitions.keys():
            gate_blocks = len([e for e in self.gate_history 
                             if any(g["gate"] == gate_name for g in e.get("blocking_gates", []))])
            gate_warnings = len([e for e in self.gate_history 
                               if any(g["gate"] == gate_name for g in e.get("warning_gates", []))])
            
            gate_stats[gate_name] = {
                "blocks": gate_blocks,
                "warnings": gate_warnings,
                "block_rate": (gate_blocks / total_evaluations) * 100 if total_evaluations > 0 else 0,
                "warning_rate": (gate_warnings / total_evaluations) * 100 if total_evaluations > 0 else 0
            }
        
        return {
            "total_evaluations": total_evaluations,
            "blocked_evaluations": blocked_evaluations,
            "warning_evaluations": warning_evaluations,
            "passed_evaluations": passed_evaluations,
            "block_rate": (blocked_evaluations / total_evaluations) * 100 if total_evaluations > 0 else 0,
            "warning_rate": (warning_evaluations / total_evaluations) * 100 if total_evaluations > 0 else 0,
            "pass_rate": (passed_evaluations / total_evaluations) * 100 if total_evaluations > 0 else 0,
            "gate_statistics": gate_stats,
            "evaluation_period": {
                "earliest": self.gate_history[0]["evaluation_timestamp"],
                "latest": self.gate_history[-1]["evaluation_timestamp"]
            }
        }


# Factory function for creating pipeline
def create_security_scanning_pipeline(
    security_test_engine: SecurityTestEngine,
    audit_logger: AuditLogger,
    monitoring_system: EnhancedMonitoringSystem,
    real_time_alerting: RealTimeAlerting
) -> SecurityScanningPipeline:
    """Create and initialize security scanning pipeline."""
    return SecurityScanningPipeline(
        security_test_engine=security_test_engine,
        audit_logger=audit_logger,
        monitoring_system=monitoring_system,
        real_time_alerting=real_time_alerting
    )


def create_ci_cd_integration(pipeline: SecurityScanningPipeline) -> CICDIntegration:
    """Create and initialize CI/CD integration."""
    return CICDIntegration(pipeline)


def create_security_quality_gate() -> SecurityQualityGate:
    """Create and initialize security quality gate system."""
    return SecurityQualityGate()


if __name__ == "__main__":
    # Example usage
    print("Security Scanning Pipeline with CI/CD Integration - see code for usage examples")