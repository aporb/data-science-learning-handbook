#!/usr/bin/env python3
"""
DoD Compliance Reporting System for CAC/PIV Security Monitoring

This module provides comprehensive compliance reporting capabilities for DoD security
requirements, including automated report generation, compliance metrics tracking,
and regulatory audit support for CAC/PIV smart card systems.

Key Features:
- Automated DoD compliance report generation
- NIST SP 800-53 control implementation tracking
- FISMA compliance monitoring and reporting
- CJCSI 6510.01F compliance verification
- Real-time compliance metrics dashboard
- Automated evidence collection and documentation
- Audit trail generation and preservation
- Risk assessment and vulnerability reporting

Compliance Standards Supported:
- DoD 8500.01E - Information Assurance Policy
- DoD 8570.01-M - IA Workforce Improvement Program
- NIST SP 800-53 - Security and Privacy Controls
- FISMA - Federal Information Security Management Act
- CJCSI 6510.01F - Information Assurance and Support
- Common Criteria - Security Evaluation Standards
- FIPS 140-2 - Cryptographic Module Validation

Report Types:
- Daily security posture reports
- Weekly compliance summaries
- Monthly risk assessments
- Quarterly audit reports
- Annual compliance certifications
- Incident-driven compliance reports
- Real-time compliance dashboards

Author: Compliance and Audit Team
Version: 1.0.0
"""

import os
import sys
import threading
import time
import logging
import json
import sqlite3
from typing import Dict, List, Optional, Set, Callable, Any, Union, Tuple
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone, timedelta
from enum import Enum, IntEnum
from collections import defaultdict, deque
import csv
import xml.etree.ElementTree as ET
from pathlib import Path
import hashlib
import base64

# Import monitoring components
try:
    from .cac_piv_security_monitor import SecurityEvent, SecurityEventCategory, SecurityThreatLevel
    from .failover_detector import FailoverEvent, HealthStatus, ComponentHealth
    from .security_alerting import Alert, AlertStatus, AlertSeverity
    from ..audits.audit_logger import AuditLogger, AuditEvent, AuditEventType
except ImportError:
    # Minimal implementations for standalone operation
    logger = logging.getLogger(__name__)


class ComplianceFramework(Enum):
    """Supported compliance frameworks."""
    DOD_8500_01E = "dod_8500_01e"
    DOD_8570_01M = "dod_8570_01m"
    NIST_SP_800_53 = "nist_sp_800_53"
    FISMA = "fisma"
    CJCSI_6510_01F = "cjcsi_6510_01f"
    COMMON_CRITERIA = "common_criteria"
    FIPS_140_2 = "fips_140_2"


class ComplianceStatus(Enum):
    """Compliance status levels."""
    COMPLIANT = "compliant"
    NON_COMPLIANT = "non_compliant"
    PARTIALLY_COMPLIANT = "partially_compliant"
    NOT_APPLICABLE = "not_applicable"
    UNDER_REVIEW = "under_review"
    PENDING_REMEDIATION = "pending_remediation"


class RiskLevel(IntEnum):
    """Risk assessment levels."""
    VERY_LOW = 1
    LOW = 2
    MODERATE = 3
    HIGH = 4
    VERY_HIGH = 5


class ReportType(Enum):
    """Types of compliance reports."""
    DAILY_POSTURE = "daily_posture"
    WEEKLY_SUMMARY = "weekly_summary"
    MONTHLY_ASSESSMENT = "monthly_assessment"
    QUARTERLY_AUDIT = "quarterly_audit"
    ANNUAL_CERTIFICATION = "annual_certification"
    INCIDENT_RESPONSE = "incident_response"
    REAL_TIME_DASHBOARD = "real_time_dashboard"
    CUSTOM_REPORT = "custom_report"


@dataclass
class ComplianceControl:
    """Individual compliance control definition."""
    control_id: str
    framework: ComplianceFramework
    title: str
    description: str
    
    # Implementation details
    implementation_status: ComplianceStatus = ComplianceStatus.NOT_APPLICABLE
    implementation_description: str = ""
    responsible_party: str = ""
    
    # Assessment details
    assessment_method: str = ""
    assessment_frequency: str = ""
    last_assessment_date: Optional[datetime] = None
    next_assessment_date: Optional[datetime] = None
    
    # Evidence and documentation
    evidence_locations: List[str] = field(default_factory=list)
    documentation_references: List[str] = field(default_factory=list)
    
    # Risk and compliance
    risk_level: RiskLevel = RiskLevel.MODERATE
    compliance_percentage: float = 0.0
    findings: List[str] = field(default_factory=list)
    remediation_actions: List[str] = field(default_factory=list)
    
    # Metadata
    created_date: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_date: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class ComplianceMetric:
    """Compliance metric definition."""
    metric_id: str
    metric_name: str
    framework: ComplianceFramework
    control_id: str
    
    # Metric details
    current_value: Union[int, float, str] = 0
    target_value: Union[int, float, str] = 0
    measurement_unit: str = ""
    
    # Thresholds
    warning_threshold: Optional[float] = None
    critical_threshold: Optional[float] = None
    
    # Collection info
    collection_method: str = ""
    collection_frequency: str = ""
    last_collected: Optional[datetime] = None
    
    # Compliance calculation
    compliance_percentage: float = 0.0
    trend: str = "stable"  # "improving", "stable", "degrading"
    
    # Historical data
    historical_values: List[Tuple[datetime, float]] = field(default_factory=list)


@dataclass
class ComplianceReport:
    """Generated compliance report."""
    report_id: str
    report_type: ReportType
    framework: ComplianceFramework
    
    # Report metadata
    title: str
    description: str
    generated_date: datetime
    reporting_period_start: datetime
    reporting_period_end: datetime
    
    # Report content
    executive_summary: str = ""
    overall_compliance_score: float = 0.0
    total_controls: int = 0
    compliant_controls: int = 0
    non_compliant_controls: int = 0
    
    # Detailed findings
    control_assessments: List[ComplianceControl] = field(default_factory=list)
    key_findings: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    risk_assessment: Dict[str, Any] = field(default_factory=dict)
    
    # Supporting data
    metrics_summary: Dict[str, Any] = field(default_factory=dict)
    evidence_inventory: List[str] = field(default_factory=list)
    audit_trail_summary: Dict[str, Any] = field(default_factory=dict)
    
    # Report generation details
    generated_by: str = "CAC/PIV Security Monitoring System"
    report_version: str = "1.0"
    classification: str = "UNCLASSIFIED"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert report to dictionary."""
        data = asdict(self)
        data['generated_date'] = self.generated_date.isoformat()
        data['reporting_period_start'] = self.reporting_period_start.isoformat()
        data['reporting_period_end'] = self.reporting_period_end.isoformat()
        data['report_type'] = self.report_type.value
        data['framework'] = self.framework.value
        return data


class ComplianceReportingConfiguration:
    """Configuration for compliance reporting system."""
    
    def __init__(self):
        # Report generation settings
        self.auto_generation_enabled = True
        self.daily_report_time = "06:00"
        self.weekly_report_day = "monday"
        self.monthly_report_day = 1
        self.quarterly_report_day = 1
        
        # Report storage settings
        self.reports_directory = "/var/reports/compliance"
        self.archive_reports = True
        self.archive_after_days = 365
        self.retention_years = 7
        
        # Output formats
        self.supported_formats = ["json", "pdf", "html", "csv", "xml"]
        self.default_format = "json"
        self.include_charts = True
        self.include_executive_summary = True
        
        # Compliance frameworks
        self.enabled_frameworks = [
            ComplianceFramework.DOD_8500_01E,
            ComplianceFramework.NIST_SP_800_53,
            ComplianceFramework.FISMA
        ]
        
        # Assessment settings
        self.assessment_automation = True
        self.evidence_collection_automated = True
        self.risk_calculation_method = "weighted_average"
        
        # Notification settings
        self.notify_on_non_compliance = True
        self.notify_stakeholders = True
        self.compliance_threshold = 90.0  # Minimum compliance percentage
        
        # Security settings
        self.encrypt_reports = True
        self.digital_signatures = True
        self.audit_report_access = True
        
        # Load from environment
        self._load_from_environment()
    
    def _load_from_environment(self):
        """Load configuration from environment variables."""
        try:
            self.auto_generation_enabled = os.getenv('COMPLIANCE_AUTO_REPORTS', 'true').lower() == 'true'
            self.reports_directory = os.getenv('COMPLIANCE_REPORTS_DIR', self.reports_directory)
            self.compliance_threshold = float(os.getenv('COMPLIANCE_THRESHOLD', '90.0'))
            self.retention_years = int(os.getenv('COMPLIANCE_RETENTION_YEARS', '7'))
            
        except Exception as e:
            logging.getLogger(__name__).warning(f"Failed to load compliance config: {e}")


class ComplianceReporting:
    """
    Comprehensive DoD Compliance Reporting System
    
    Provides automated compliance reporting and monitoring for:
    - DoD security requirements and standards
    - NIST cybersecurity framework controls
    - FISMA compliance requirements
    - Real-time compliance metrics
    - Automated evidence collection
    - Risk assessment and reporting
    """
    
    def __init__(self,
                 config: Optional[ComplianceReportingConfiguration] = None,
                 security_monitor=None,
                 failover_detector=None,
                 alerting_system=None,
                 audit_logger: Optional[AuditLogger] = None):
        """
        Initialize compliance reporting system.
        
        Args:
            config: Compliance reporting configuration
            security_monitor: Security monitoring system
            failover_detector: Failover detection system
            alerting_system: Security alerting system
            audit_logger: Audit logging system
        """
        self.config = config or ComplianceReportingConfiguration()
        self.security_monitor = security_monitor
        self.failover_detector = failover_detector
        self.alerting_system = alerting_system
        self.audit_logger = audit_logger
        
        # Initialize database
        self._init_database()
        
        # Load compliance controls and metrics
        self.compliance_controls: Dict[str, ComplianceControl] = {}
        self.compliance_metrics: Dict[str, ComplianceMetric] = {}
        self.generated_reports: Dict[str, ComplianceReport] = {}
        
        # State management
        self.is_running = False
        self._shutdown_event = threading.Event()
        self.reporting_threads: List[threading.Thread] = []
        
        # Performance tracking
        self.reporting_stats = {
            'reports_generated': 0,
            'assessments_completed': 0,
            'controls_evaluated': 0,
            'compliance_violations': 0,
            'last_full_assessment': None
        }
        
        # Initialize compliance framework
        self._initialize_compliance_controls()
        self._initialize_compliance_metrics()
        
        logger.info("DoD Compliance Reporting System initialized")
    
    def _init_database(self):
        """Initialize compliance reporting database."""
        try:
            self.db_path = "/tmp/compliance_reporting.db"
            conn = sqlite3.connect(self.db_path)
            
            # Compliance controls table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS compliance_controls (
                    control_id TEXT PRIMARY KEY,
                    framework TEXT NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT,
                    implementation_status TEXT,
                    implementation_description TEXT,
                    responsible_party TEXT,
                    assessment_method TEXT,
                    last_assessment_date TEXT,
                    next_assessment_date TEXT,
                    risk_level INTEGER,
                    compliance_percentage REAL,
                    findings TEXT,
                    remediation_actions TEXT,
                    evidence_locations TEXT,
                    created_date TEXT,
                    updated_date TEXT
                )
            """)
            
            # Compliance metrics table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS compliance_metrics (
                    metric_id TEXT PRIMARY KEY,
                    metric_name TEXT NOT NULL,
                    framework TEXT NOT NULL,
                    control_id TEXT,
                    current_value TEXT,
                    target_value TEXT,
                    measurement_unit TEXT,
                    compliance_percentage REAL,
                    trend TEXT,
                    last_collected TEXT,
                    collection_method TEXT,
                    created_date TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Generated reports table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS compliance_reports (
                    report_id TEXT PRIMARY KEY,
                    report_type TEXT NOT NULL,
                    framework TEXT NOT NULL,
                    title TEXT NOT NULL,
                    generated_date TEXT NOT NULL,
                    reporting_period_start TEXT NOT NULL,
                    reporting_period_end TEXT NOT NULL,
                    overall_compliance_score REAL,
                    total_controls INTEGER,
                    compliant_controls INTEGER,
                    non_compliant_controls INTEGER,
                    report_data TEXT,
                    classification TEXT,
                    generated_by TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Compliance assessments table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS compliance_assessments (
                    assessment_id TEXT PRIMARY KEY,
                    control_id TEXT NOT NULL,
                    assessment_date TEXT NOT NULL,
                    assessor TEXT,
                    status TEXT NOT NULL,
                    findings TEXT,
                    evidence TEXT,
                    recommendations TEXT,
                    risk_score REAL,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Create indexes
            indexes = [
                "CREATE INDEX IF NOT EXISTS idx_controls_framework ON compliance_controls(framework)",
                "CREATE INDEX IF NOT EXISTS idx_controls_status ON compliance_controls(implementation_status)",
                "CREATE INDEX IF NOT EXISTS idx_metrics_framework ON compliance_metrics(framework)",
                "CREATE INDEX IF NOT EXISTS idx_reports_type ON compliance_reports(report_type)",
                "CREATE INDEX IF NOT EXISTS idx_reports_date ON compliance_reports(generated_date)",
                "CREATE INDEX IF NOT EXISTS idx_assessments_control ON compliance_assessments(control_id)",
                "CREATE INDEX IF NOT EXISTS idx_assessments_date ON compliance_assessments(assessment_date)"
            ]
            
            for index_sql in indexes:
                conn.execute(index_sql)
            
            conn.commit()
            conn.close()
            
            logger.info("Compliance reporting database initialized")
            
        except Exception as e:
            logger.error(f"Failed to initialize compliance database: {e}")
            raise
    
    def _initialize_compliance_controls(self):
        """Initialize DoD compliance controls."""
        try:
            # DoD 8500.01E Controls
            dod_controls = [
                ComplianceControl(
                    control_id="DOD-8500-AC-1",
                    framework=ComplianceFramework.DOD_8500_01E,
                    title="Access Control Policy and Procedures",
                    description="Develop, document, and disseminate access control policy and procedures",
                    implementation_status=ComplianceStatus.COMPLIANT,
                    responsible_party="Security Team",
                    assessment_method="Document Review and Testing",
                    assessment_frequency="Annual"
                ),
                ComplianceControl(
                    control_id="DOD-8500-IA-2",
                    framework=ComplianceFramework.DOD_8500_01E,
                    title="Identification and Authentication",
                    description="Uniquely identify and authenticate organizational users",
                    implementation_status=ComplianceStatus.COMPLIANT,
                    responsible_party="Identity Management Team",
                    assessment_method="Technical Testing",
                    assessment_frequency="Quarterly"
                ),
                ComplianceControl(
                    control_id="DOD-8500-SC-8",
                    framework=ComplianceFramework.DOD_8500_01E,
                    title="Transmission Confidentiality and Integrity",
                    description="Protect the confidentiality and integrity of transmitted information",
                    implementation_status=ComplianceStatus.COMPLIANT,
                    responsible_party="Network Security Team",
                    assessment_method="Technical Testing",
                    assessment_frequency="Quarterly"
                )
            ]
            
            # NIST SP 800-53 Controls
            nist_controls = [
                ComplianceControl(
                    control_id="NIST-AC-2",
                    framework=ComplianceFramework.NIST_SP_800_53,
                    title="Account Management",
                    description="Manage information system accounts",
                    implementation_status=ComplianceStatus.COMPLIANT,
                    responsible_party="Identity Management Team",
                    assessment_method="Automated Monitoring",
                    assessment_frequency="Continuous"
                ),
                ComplianceControl(
                    control_id="NIST-AU-2",
                    framework=ComplianceFramework.NIST_SP_800_53,
                    title="Audit Events",
                    description="Determine audit events that are to be audited",
                    implementation_status=ComplianceStatus.COMPLIANT,
                    responsible_party="Audit Team",
                    assessment_method="Automated Analysis",
                    assessment_frequency="Continuous"
                ),
                ComplianceControl(
                    control_id="NIST-IA-2",
                    framework=ComplianceFramework.NIST_SP_800_53,
                    title="Identification and Authentication",
                    description="Uniquely identify and authenticate organizational users",
                    implementation_status=ComplianceStatus.COMPLIANT,
                    responsible_party="CAC/PIV Authentication System",
                    assessment_method="Technical Testing",
                    assessment_frequency="Monthly"
                )
            ]
            
            # FISMA Controls
            fisma_controls = [
                ComplianceControl(
                    control_id="FISMA-SC-1",
                    framework=ComplianceFramework.FISMA,
                    title="System and Communications Protection Policy",
                    description="Develop and implement system and communications protection policy",
                    implementation_status=ComplianceStatus.COMPLIANT,
                    responsible_party="CISO Office",
                    assessment_method="Document Review",
                    assessment_frequency="Annual"
                ),
                ComplianceControl(
                    control_id="FISMA-IR-1",
                    framework=ComplianceFramework.FISMA,
                    title="Incident Response Policy and Procedures",
                    description="Develop and implement incident response policy and procedures",
                    implementation_status=ComplianceStatus.COMPLIANT,
                    responsible_party="Incident Response Team",
                    assessment_method="Tabletop Exercise",
                    assessment_frequency="Bi-Annual"
                )
            ]
            
            # Add all controls to registry
            for control in dod_controls + nist_controls + fisma_controls:
                self.compliance_controls[control.control_id] = control
            
            logger.info(f"Initialized {len(self.compliance_controls)} compliance controls")
            
        except Exception as e:
            logger.error(f"Failed to initialize compliance controls: {e}")
    
    def _initialize_compliance_metrics(self):
        """Initialize compliance metrics."""
        try:
            # Authentication metrics
            auth_metrics = [
                ComplianceMetric(
                    metric_id="auth_success_rate",
                    metric_name="Authentication Success Rate",
                    framework=ComplianceFramework.NIST_SP_800_53,
                    control_id="NIST-IA-2",
                    target_value=95.0,
                    measurement_unit="percentage",
                    collection_method="Automated",
                    collection_frequency="Real-time"
                ),
                ComplianceMetric(
                    metric_id="failed_auth_incidents",
                    metric_name="Failed Authentication Incidents",
                    framework=ComplianceFramework.DOD_8500_01E,
                    control_id="DOD-8500-IA-2",
                    target_value=10,
                    measurement_unit="count_per_day",
                    warning_threshold=15,
                    critical_threshold=25,
                    collection_method="Automated",
                    collection_frequency="Daily"
                )
            ]
            
            # Security event metrics
            security_metrics = [
                ComplianceMetric(
                    metric_id="security_events_resolved",
                    metric_name="Security Events Resolution Rate",
                    framework=ComplianceFramework.FISMA,
                    control_id="FISMA-IR-1",
                    target_value=98.0,
                    measurement_unit="percentage",
                    collection_method="Automated",
                    collection_frequency="Daily"
                ),
                ComplianceMetric(
                    metric_id="critical_alerts_response_time",
                    metric_name="Critical Alert Response Time",
                    framework=ComplianceFramework.DOD_8500_01E,
                    control_id="DOD-8500-IR-1",
                    target_value=15.0,
                    measurement_unit="minutes",
                    warning_threshold=20.0,
                    critical_threshold=30.0,
                    collection_method="Automated",
                    collection_frequency="Real-time"
                )
            ]
            
            # System availability metrics
            availability_metrics = [
                ComplianceMetric(
                    metric_id="system_availability",
                    metric_name="System Availability",
                    framework=ComplianceFramework.FISMA,
                    control_id="FISMA-SC-1",
                    target_value=99.9,
                    measurement_unit="percentage",
                    warning_threshold=99.0,
                    critical_threshold=98.0,
                    collection_method="Automated",
                    collection_frequency="Real-time"
                )
            ]
            
            # Add all metrics to registry
            for metric in auth_metrics + security_metrics + availability_metrics:
                self.compliance_metrics[metric.metric_id] = metric
            
            logger.info(f"Initialized {len(self.compliance_metrics)} compliance metrics")
            
        except Exception as e:
            logger.error(f"Failed to initialize compliance metrics: {e}")
    
    def start(self) -> bool:
        """Start compliance reporting system."""
        if self.is_running:
            logger.warning("Compliance reporting already running")
            return False
        
        try:
            logger.info("Starting DoD Compliance Reporting System...")
            
            # Clear shutdown event
            self._shutdown_event.clear()
            
            # Create reports directory
            Path(self.config.reports_directory).mkdir(parents=True, exist_ok=True)
            
            # Start background reporting threads
            self._start_reporting_threads()
            
            # Perform initial assessment
            self._perform_initial_assessment()
            
            self.is_running = True
            logger.info("DoD Compliance Reporting System started successfully")
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to start compliance reporting: {e}")
            return False
    
    def stop(self, timeout: float = 30.0) -> bool:
        """Stop compliance reporting system."""
        if not self.is_running:
            return True
        
        try:
            logger.info("Stopping DoD Compliance Reporting System...")
            
            # Signal shutdown
            self._shutdown_event.set()
            self.is_running = False
            
            # Stop reporting threads
            self._stop_reporting_threads(timeout)
            
            # Generate final reports
            self._generate_shutdown_reports()
            
            # Save final statistics
            self._save_reporting_statistics()
            
            logger.info("DoD Compliance Reporting System stopped successfully")
            return True
            
        except Exception as e:
            logger.error(f"Error stopping compliance reporting: {e}")
            return False
    
    def _start_reporting_threads(self):
        """Start background reporting threads."""
        if self.config.auto_generation_enabled:
            thread_configs = [
                ("MetricsCollector", self._metrics_collection_loop),
                ("AssessmentProcessor", self._assessment_processing_loop),
                ("ReportGenerator", self._report_generation_loop),
                ("ComplianceMonitor", self._compliance_monitoring_loop)
            ]
            
            for name, target in thread_configs:
                thread = threading.Thread(
                    target=target,
                    name=f"ComplianceReporting-{name}",
                    daemon=True
                )
                thread.start()
                self.reporting_threads.append(thread)
            
            logger.debug(f"Started {len(self.reporting_threads)} reporting threads")
    
    def _stop_reporting_threads(self, timeout: float):
        """Stop reporting threads."""
        for thread in self.reporting_threads:
            if thread.is_alive():
                thread.join(timeout / len(self.reporting_threads))
        
        self.reporting_threads.clear()
        logger.debug("Reporting threads stopped")
    
    def _metrics_collection_loop(self):
        """Metrics collection loop."""
        logger.debug("Compliance metrics collection loop started")
        
        while not self._shutdown_event.is_set():
            try:
                # Collect compliance metrics
                self._collect_compliance_metrics()
                
                # Sleep for collection interval
                self._shutdown_event.wait(300)  # 5 minutes
                
            except Exception as e:
                logger.error(f"Error in metrics collection loop: {e}")
                self._shutdown_event.wait(300)
        
        logger.debug("Compliance metrics collection loop stopped")
    
    def _assessment_processing_loop(self):
        """Assessment processing loop."""
        logger.debug("Compliance assessment processing loop started")
        
        while not self._shutdown_event.is_set():
            try:
                # Perform periodic assessments
                self._perform_periodic_assessments()
                
                # Sleep for assessment interval
                self._shutdown_event.wait(3600)  # 1 hour
                
            except Exception as e:
                logger.error(f"Error in assessment processing loop: {e}")
                self._shutdown_event.wait(3600)
        
        logger.debug("Compliance assessment processing loop stopped")
    
    def _report_generation_loop(self):
        """Report generation loop."""
        logger.debug("Compliance report generation loop started")
        
        while not self._shutdown_event.is_set():
            try:
                # Check for scheduled reports
                self._check_scheduled_reports()
                
                # Sleep for check interval
                self._shutdown_event.wait(1800)  # 30 minutes
                
            except Exception as e:
                logger.error(f"Error in report generation loop: {e}")
                self._shutdown_event.wait(1800)
        
        logger.debug("Compliance report generation loop stopped")
    
    def _compliance_monitoring_loop(self):
        """Compliance monitoring loop."""
        logger.debug("Compliance monitoring loop started")
        
        while not self._shutdown_event.is_set():
            try:
                # Monitor compliance status
                self._monitor_compliance_status()
                
                # Check for violations
                self._check_compliance_violations()
                
                # Sleep for monitoring interval
                self._shutdown_event.wait(600)  # 10 minutes
                
            except Exception as e:
                logger.error(f"Error in compliance monitoring loop: {e}")
                self._shutdown_event.wait(600)
        
        logger.debug("Compliance monitoring loop stopped")
    
    def _perform_initial_assessment(self):
        """Perform initial compliance assessment."""
        try:
            logger.info("Performing initial compliance assessment...")
            
            # Assess all controls
            for control in self.compliance_controls.values():
                self._assess_control(control)
            
            # Update statistics
            self.reporting_stats['last_full_assessment'] = datetime.now(timezone.utc)
            self.reporting_stats['controls_evaluated'] = len(self.compliance_controls)
            
            logger.info("Initial compliance assessment completed")
            
        except Exception as e:
            logger.error(f"Failed to perform initial assessment: {e}")
    
    def _collect_compliance_metrics(self):
        """Collect current compliance metrics."""
        try:
            for metric in self.compliance_metrics.values():
                current_value = self._calculate_metric_value(metric)
                
                if current_value is not None:
                    # Update metric
                    metric.current_value = current_value
                    metric.last_collected = datetime.now(timezone.utc)
                    
                    # Calculate compliance percentage
                    metric.compliance_percentage = self._calculate_metric_compliance(metric)
                    
                    # Update historical data
                    metric.historical_values.append((datetime.now(timezone.utc), float(current_value)))
                    
                    # Keep only recent history
                    if len(metric.historical_values) > 1000:
                        metric.historical_values = metric.historical_values[-1000:]
                    
                    # Store in database
                    self._store_metric_in_database(metric)
            
        except Exception as e:
            logger.error(f"Failed to collect compliance metrics: {e}")
    
    def _calculate_metric_value(self, metric: ComplianceMetric) -> Optional[float]:
        """Calculate current value for compliance metric."""
        try:
            if metric.metric_id == "auth_success_rate":
                # Calculate authentication success rate
                if self.security_monitor:
                    # This would calculate actual success rate from monitoring data
                    return 97.5  # Simulated value
            
            elif metric.metric_id == "failed_auth_incidents":
                # Count failed authentication incidents today
                if self.security_monitor:
                    # This would count actual failed auth events
                    return 3  # Simulated value
            
            elif metric.metric_id == "security_events_resolved":
                # Calculate security event resolution rate
                if self.alerting_system:
                    # This would calculate actual resolution rate
                    return 98.2  # Simulated value
            
            elif metric.metric_id == "critical_alerts_response_time":
                # Calculate average response time for critical alerts
                if self.alerting_system:
                    # This would calculate actual response times
                    return 12.5  # Simulated value in minutes
            
            elif metric.metric_id == "system_availability":
                # Calculate system availability
                if self.failover_detector:
                    # This would calculate actual availability
                    return 99.95  # Simulated value
            
            return None
            
        except Exception as e:
            logger.error(f"Failed to calculate metric value for {metric.metric_id}: {e}")
            return None
    
    def _calculate_metric_compliance(self, metric: ComplianceMetric) -> float:
        """Calculate compliance percentage for metric."""
        try:
            if not isinstance(metric.current_value, (int, float)):
                return 0.0
            
            if not isinstance(metric.target_value, (int, float)):
                return 0.0
            
            current = float(metric.current_value)
            target = float(metric.target_value)
            
            # Calculate compliance based on metric type
            if metric.measurement_unit == "percentage":
                # For percentage metrics, compliance is current/target
                return min(100.0, (current / target) * 100.0)
            
            elif "count" in metric.measurement_unit:
                # For count metrics, lower is often better
                if current <= target:
                    return 100.0
                else:
                    # Diminishing compliance as count exceeds target
                    return max(0.0, 100.0 - ((current - target) / target) * 50.0)
            
            elif metric.measurement_unit == "minutes":
                # For time metrics, lower is better
                if current <= target:
                    return 100.0
                else:
                    return max(0.0, 100.0 - ((current - target) / target) * 100.0)
            
            else:
                # Default calculation
                return min(100.0, (current / target) * 100.0)
                
        except Exception as e:
            logger.error(f"Failed to calculate compliance for metric {metric.metric_id}: {e}")
            return 0.0
    
    def _perform_periodic_assessments(self):
        """Perform periodic compliance assessments."""
        try:
            now = datetime.now(timezone.utc)
            
            for control in self.compliance_controls.values():
                # Check if assessment is due
                if self._is_assessment_due(control, now):
                    self._assess_control(control)
                    self.reporting_stats['assessments_completed'] += 1
            
        except Exception as e:
            logger.error(f"Failed to perform periodic assessments: {e}")
    
    def _is_assessment_due(self, control: ComplianceControl, current_time: datetime) -> bool:
        """Check if control assessment is due."""
        try:
            if not control.last_assessment_date:
                return True  # Never assessed
            
            if control.next_assessment_date and current_time >= control.next_assessment_date:
                return True  # Assessment overdue
            
            # Check based on frequency
            if control.assessment_frequency == "Daily":
                return (current_time - control.last_assessment_date).days >= 1
            elif control.assessment_frequency == "Weekly":
                return (current_time - control.last_assessment_date).days >= 7
            elif control.assessment_frequency == "Monthly":
                return (current_time - control.last_assessment_date).days >= 30
            elif control.assessment_frequency == "Quarterly":
                return (current_time - control.last_assessment_date).days >= 90
            elif control.assessment_frequency == "Annual":
                return (current_time - control.last_assessment_date).days >= 365
            
            return False
            
        except Exception as e:
            logger.error(f"Failed to check assessment due date for {control.control_id}: {e}")
            return False
    
    def _assess_control(self, control: ComplianceControl):
        """Assess individual compliance control."""
        try:
            # Perform automated assessment based on control type
            assessment_result = self._perform_control_assessment(control)
            
            # Update control status
            control.last_assessment_date = datetime.now(timezone.utc)
            control.compliance_percentage = assessment_result.get('compliance_percentage', 0.0)
            control.findings = assessment_result.get('findings', [])
            control.implementation_status = assessment_result.get('status', ComplianceStatus.UNDER_REVIEW)
            
            # Calculate next assessment date
            control.next_assessment_date = self._calculate_next_assessment_date(control)
            
            # Store assessment in database
            self._store_assessment_in_database(control, assessment_result)
            
            # Update control in database
            self._update_control_in_database(control)
            
        except Exception as e:
            logger.error(f"Failed to assess control {control.control_id}: {e}")
    
    def _perform_control_assessment(self, control: ComplianceControl) -> Dict[str, Any]:
        """Perform automated assessment of compliance control."""
        try:
            # This would implement actual assessment logic based on control type
            # For now, return simulated assessment results
            
            findings = []
            compliance_percentage = 95.0
            status = ComplianceStatus.COMPLIANT
            
            # Simulate different assessment results based on control
            if "IA-2" in control.control_id:
                # Identity and Authentication control
                if self.security_monitor:
                    # Check authentication metrics
                    auth_metric = self.compliance_metrics.get("auth_success_rate")
                    if auth_metric and auth_metric.compliance_percentage < 95.0:
                        findings.append("Authentication success rate below target")
                        compliance_percentage = auth_metric.compliance_percentage
                        status = ComplianceStatus.PARTIALLY_COMPLIANT
            
            elif "AC" in control.control_id:
                # Access Control
                if self.failover_detector:
                    # Check system availability
                    availability_metric = self.compliance_metrics.get("system_availability")
                    if availability_metric and availability_metric.compliance_percentage < 99.0:
                        findings.append("System availability below target")
                        compliance_percentage = availability_metric.compliance_percentage
                        status = ComplianceStatus.PARTIALLY_COMPLIANT
            
            return {
                'status': status,
                'compliance_percentage': compliance_percentage,
                'findings': findings,
                'evidence': ['Automated assessment', 'System monitoring data'],
                'recommendations': ['Continue monitoring', 'Regular review'],
                'assessor': 'Automated Assessment System',
                'assessment_date': datetime.now(timezone.utc)
            }
            
        except Exception as e:
            logger.error(f"Failed to perform assessment for {control.control_id}: {e}")
            return {
                'status': ComplianceStatus.UNDER_REVIEW,
                'compliance_percentage': 0.0,
                'findings': [f"Assessment error: {str(e)}"],
                'evidence': [],
                'recommendations': ['Manual review required'],
                'assessor': 'Error',
                'assessment_date': datetime.now(timezone.utc)
            }
    
    def _calculate_next_assessment_date(self, control: ComplianceControl) -> Optional[datetime]:
        """Calculate next assessment date for control."""
        try:
            if not control.last_assessment_date:
                return None
            
            if control.assessment_frequency == "Daily":
                return control.last_assessment_date + timedelta(days=1)
            elif control.assessment_frequency == "Weekly":
                return control.last_assessment_date + timedelta(weeks=1)
            elif control.assessment_frequency == "Monthly":
                return control.last_assessment_date + timedelta(days=30)
            elif control.assessment_frequency == "Quarterly":
                return control.last_assessment_date + timedelta(days=90)
            elif control.assessment_frequency == "Annual":
                return control.last_assessment_date + timedelta(days=365)
            elif control.assessment_frequency == "Continuous":
                return control.last_assessment_date + timedelta(hours=1)
            
            return None
            
        except Exception as e:
            logger.error(f"Failed to calculate next assessment date: {e}")
            return None
    
    def generate_compliance_report(self, 
                                 report_type: ReportType,
                                 framework: ComplianceFramework,
                                 start_date: Optional[datetime] = None,
                                 end_date: Optional[datetime] = None) -> Optional[str]:
        """Generate compliance report."""
        try:
            if not end_date:
                end_date = datetime.now(timezone.utc)
            
            if not start_date:
                if report_type == ReportType.DAILY_POSTURE:
                    start_date = end_date - timedelta(days=1)
                elif report_type == ReportType.WEEKLY_SUMMARY:
                    start_date = end_date - timedelta(weeks=1)
                elif report_type == ReportType.MONTHLY_ASSESSMENT:
                    start_date = end_date - timedelta(days=30)
                elif report_type == ReportType.QUARTERLY_AUDIT:
                    start_date = end_date - timedelta(days=90)
                elif report_type == ReportType.ANNUAL_CERTIFICATION:
                    start_date = end_date - timedelta(days=365)
                else:
                    start_date = end_date - timedelta(days=7)
            
            # Generate report
            report = self._create_compliance_report(report_type, framework, start_date, end_date)
            
            # Store report
            self._store_report_in_database(report)
            self.generated_reports[report.report_id] = report
            
            # Save report to file
            report_file_path = self._save_report_to_file(report)
            
            # Update statistics
            self.reporting_stats['reports_generated'] += 1
            
            logger.info(f"Generated compliance report {report.report_id}")
            
            return report.report_id
            
        except Exception as e:
            logger.error(f"Failed to generate compliance report: {e}")
            return None
    
    def _create_compliance_report(self, 
                                report_type: ReportType,
                                framework: ComplianceFramework,
                                start_date: datetime,
                                end_date: datetime) -> ComplianceReport:
        """Create compliance report object."""
        try:
            report_id = f"compliance_{framework.value}_{report_type.value}_{int(end_date.timestamp())}"
            
            # Filter controls for framework
            framework_controls = [
                control for control in self.compliance_controls.values()
                if control.framework == framework
            ]
            
            # Calculate compliance statistics
            total_controls = len(framework_controls)
            compliant_controls = len([
                c for c in framework_controls 
                if c.implementation_status == ComplianceStatus.COMPLIANT
            ])
            non_compliant_controls = len([
                c for c in framework_controls 
                if c.implementation_status == ComplianceStatus.NON_COMPLIANT
            ])
            
            overall_compliance_score = (
                (compliant_controls / total_controls) * 100.0 
                if total_controls > 0 else 0.0
            )
            
            # Generate executive summary
            executive_summary = self._generate_executive_summary(
                framework, overall_compliance_score, framework_controls
            )
            
            # Generate key findings
            key_findings = self._generate_key_findings(framework_controls)
            
            # Generate recommendations
            recommendations = self._generate_recommendations(framework_controls)
            
            # Create report
            report = ComplianceReport(
                report_id=report_id,
                report_type=report_type,
                framework=framework,
                title=f"{framework.value.upper()} Compliance Report - {report_type.value.replace('_', ' ').title()}",
                description=f"Compliance assessment report for {framework.value} framework",
                generated_date=datetime.now(timezone.utc),
                reporting_period_start=start_date,
                reporting_period_end=end_date,
                executive_summary=executive_summary,
                overall_compliance_score=overall_compliance_score,
                total_controls=total_controls,
                compliant_controls=compliant_controls,
                non_compliant_controls=non_compliant_controls,
                control_assessments=framework_controls,
                key_findings=key_findings,
                recommendations=recommendations,
                metrics_summary=self._generate_metrics_summary(framework),
                risk_assessment=self._generate_risk_assessment(framework_controls)
            )
            
            return report
            
        except Exception as e:
            logger.error(f"Failed to create compliance report: {e}")
            raise
    
    def _generate_executive_summary(self, 
                                  framework: ComplianceFramework,
                                  compliance_score: float,
                                  controls: List[ComplianceControl]) -> str:
        """Generate executive summary for compliance report."""
        try:
            summary = f"""
EXECUTIVE SUMMARY

This report presents the compliance status for {framework.value.upper()} framework controls 
for the CAC/PIV Smart Card Security Monitoring System.

OVERALL COMPLIANCE: {compliance_score:.1f}%

KEY HIGHLIGHTS:
- Total Controls Assessed: {len(controls)}
- Compliant Controls: {len([c for c in controls if c.implementation_status == ComplianceStatus.COMPLIANT])}
- Non-Compliant Controls: {len([c for c in controls if c.implementation_status == ComplianceStatus.NON_COMPLIANT])}
- Partially Compliant: {len([c for c in controls if c.implementation_status == ComplianceStatus.PARTIALLY_COMPLIANT])}

COMPLIANCE STATUS:
{'SATISFACTORY' if compliance_score >= 90.0 else 'NEEDS IMPROVEMENT' if compliance_score >= 75.0 else 'CRITICAL'}

The CAC/PIV security monitoring system demonstrates {'strong' if compliance_score >= 90.0 else 'adequate' if compliance_score >= 75.0 else 'insufficient'} 
compliance with {framework.value.upper()} requirements. {'No immediate action required.' if compliance_score >= 90.0 else 'Remediation actions recommended.' if compliance_score >= 75.0 else 'Immediate attention required.'}
"""
            return summary.strip()
            
        except Exception as e:
            logger.error(f"Failed to generate executive summary: {e}")
            return "Executive summary generation failed."
    
    def _generate_key_findings(self, controls: List[ComplianceControl]) -> List[str]:
        """Generate key findings from control assessments."""
        try:
            findings = []
            
            # High-level findings
            non_compliant = [c for c in controls if c.implementation_status == ComplianceStatus.NON_COMPLIANT]
            if non_compliant:
                findings.append(f"{len(non_compliant)} controls are currently non-compliant and require immediate attention")
            
            partially_compliant = [c for c in controls if c.implementation_status == ComplianceStatus.PARTIALLY_COMPLIANT]
            if partially_compliant:
                findings.append(f"{len(partially_compliant)} controls are partially compliant and need improvement")
            
            # Control-specific findings
            for control in controls:
                if control.findings:
                    findings.extend([f"{control.control_id}: {finding}" for finding in control.findings])
            
            # Limit to most critical findings
            return findings[:10]
            
        except Exception as e:
            logger.error(f"Failed to generate key findings: {e}")
            return ["Key findings generation failed"]
    
    def _generate_recommendations(self, controls: List[ComplianceControl]) -> List[str]:
        """Generate recommendations from control assessments."""
        try:
            recommendations = []
            
            # High-priority recommendations
            non_compliant = [c for c in controls if c.implementation_status == ComplianceStatus.NON_COMPLIANT]
            if non_compliant:
                recommendations.append("Prioritize remediation of non-compliant controls")
                recommendations.append("Conduct detailed risk assessment for non-compliant areas")
            
            # Control-specific recommendations
            for control in controls:
                if control.remediation_actions:
                    recommendations.extend([
                        f"{control.control_id}: {action}" 
                        for action in control.remediation_actions
                    ])
            
            # General recommendations
            if any(c.compliance_percentage < 100.0 for c in controls):
                recommendations.append("Enhance automated compliance monitoring")
                recommendations.append("Increase assessment frequency for critical controls")
            
            return recommendations[:10]
            
        except Exception as e:
            logger.error(f"Failed to generate recommendations: {e}")
            return ["Recommendations generation failed"]
    
    def _generate_metrics_summary(self, framework: ComplianceFramework) -> Dict[str, Any]:
        """Generate metrics summary for framework."""
        try:
            framework_metrics = [
                metric for metric in self.compliance_metrics.values()
                if metric.framework == framework
            ]
            
            summary = {
                'total_metrics': len(framework_metrics),
                'metrics_in_compliance': len([
                    m for m in framework_metrics 
                    if m.compliance_percentage >= 90.0
                ]),
                'average_compliance': sum(
                    m.compliance_percentage for m in framework_metrics
                ) / len(framework_metrics) if framework_metrics else 0.0,
                'metrics_details': [
                    {
                        'metric_id': m.metric_id,
                        'metric_name': m.metric_name,
                        'current_value': m.current_value,
                        'target_value': m.target_value,
                        'compliance_percentage': m.compliance_percentage,
                        'trend': m.trend
                    }
                    for m in framework_metrics
                ]
            }
            
            return summary
            
        except Exception as e:
            logger.error(f"Failed to generate metrics summary: {e}")
            return {'error': str(e)}
    
    def _generate_risk_assessment(self, controls: List[ComplianceControl]) -> Dict[str, Any]:
        """Generate risk assessment summary."""
        try:
            # Calculate risk distribution
            risk_distribution = defaultdict(int)
            for control in controls:
                risk_distribution[control.risk_level.name] += 1
            
            # Calculate overall risk score
            risk_scores = [control.risk_level.value for control in controls]
            overall_risk = sum(risk_scores) / len(risk_scores) if risk_scores else 0.0
            
            # Identify high-risk areas
            high_risk_controls = [
                c for c in controls 
                if c.risk_level >= RiskLevel.HIGH and c.implementation_status != ComplianceStatus.COMPLIANT
            ]
            
            assessment = {
                'overall_risk_level': overall_risk,
                'risk_distribution': dict(risk_distribution),
                'high_risk_controls_count': len(high_risk_controls),
                'high_risk_controls': [
                    {
                        'control_id': c.control_id,
                        'title': c.title,
                        'risk_level': c.risk_level.name,
                        'status': c.implementation_status.value
                    }
                    for c in high_risk_controls
                ],
                'risk_trends': 'stable',  # Would calculate from historical data
                'mitigation_priorities': [
                    f"Address {c.control_id} - {c.title}"
                    for c in high_risk_controls[:5]
                ]
            }
            
            return assessment
            
        except Exception as e:
            logger.error(f"Failed to generate risk assessment: {e}")
            return {'error': str(e)}
    
    def _check_scheduled_reports(self):
        """Check for scheduled report generation."""
        try:
            now = datetime.now(timezone.utc)
            
            # Check for daily reports
            if self._should_generate_daily_report(now):
                for framework in self.config.enabled_frameworks:
                    self.generate_compliance_report(ReportType.DAILY_POSTURE, framework)
            
            # Check for weekly reports
            if self._should_generate_weekly_report(now):
                for framework in self.config.enabled_frameworks:
                    self.generate_compliance_report(ReportType.WEEKLY_SUMMARY, framework)
            
            # Check for monthly reports
            if self._should_generate_monthly_report(now):
                for framework in self.config.enabled_frameworks:
                    self.generate_compliance_report(ReportType.MONTHLY_ASSESSMENT, framework)
            
        except Exception as e:
            logger.error(f"Failed to check scheduled reports: {e}")
    
    def _should_generate_daily_report(self, current_time: datetime) -> bool:
        """Check if daily report should be generated."""
        try:
            # Check if it's time for daily report
            target_time = current_time.replace(
                hour=int(self.config.daily_report_time.split(':')[0]),
                minute=int(self.config.daily_report_time.split(':')[1]),
                second=0,
                microsecond=0
            )
            
            # Check if we're within 30 minutes of target time
            time_diff = abs((current_time - target_time).total_seconds())
            return time_diff <= 1800  # 30 minutes
            
        except Exception as e:
            logger.error(f"Failed to check daily report schedule: {e}")
            return False
    
    def _should_generate_weekly_report(self, current_time: datetime) -> bool:
        """Check if weekly report should be generated."""
        try:
            # Check if it's the right day of week
            weekday_map = {
                'monday': 0, 'tuesday': 1, 'wednesday': 2, 'thursday': 3,
                'friday': 4, 'saturday': 5, 'sunday': 6
            }
            
            target_weekday = weekday_map.get(self.config.weekly_report_day.lower(), 0)
            return current_time.weekday() == target_weekday
            
        except Exception as e:
            logger.error(f"Failed to check weekly report schedule: {e}")
            return False
    
    def _should_generate_monthly_report(self, current_time: datetime) -> bool:
        """Check if monthly report should be generated."""
        try:
            return current_time.day == self.config.monthly_report_day
            
        except Exception as e:
            logger.error(f"Failed to check monthly report schedule: {e}")
            return False
    
    def _monitor_compliance_status(self):
        """Monitor overall compliance status."""
        try:
            for framework in self.config.enabled_frameworks:
                framework_controls = [
                    c for c in self.compliance_controls.values()
                    if c.framework == framework
                ]
                
                if framework_controls:
                    compliant_count = len([
                        c for c in framework_controls
                        if c.implementation_status == ComplianceStatus.COMPLIANT
                    ])
                    
                    compliance_percentage = (compliant_count / len(framework_controls)) * 100.0
                    
                    # Check compliance threshold
                    if compliance_percentage < self.config.compliance_threshold:
                        self._handle_compliance_violation(framework, compliance_percentage)
            
        except Exception as e:
            logger.error(f"Failed to monitor compliance status: {e}")
    
    def _check_compliance_violations(self):
        """Check for compliance violations."""
        try:
            for control in self.compliance_controls.values():
                if control.implementation_status == ComplianceStatus.NON_COMPLIANT:
                    if control.risk_level >= RiskLevel.HIGH:
                        self._handle_high_risk_violation(control)
            
        except Exception as e:
            logger.error(f"Failed to check compliance violations: {e}")
    
    def _handle_compliance_violation(self, framework: ComplianceFramework, compliance_percentage: float):
        """Handle compliance threshold violation."""
        try:
            if self.config.notify_on_non_compliance:
                logger.warning(f"Compliance violation: {framework.value} at {compliance_percentage:.1f}% (threshold: {self.config.compliance_threshold}%)")
                
                # This would trigger notifications to stakeholders
                self.reporting_stats['compliance_violations'] += 1
            
        except Exception as e:
            logger.error(f"Failed to handle compliance violation: {e}")
    
    def _handle_high_risk_violation(self, control: ComplianceControl):
        """Handle high-risk compliance violation."""
        try:
            logger.critical(f"High-risk compliance violation: {control.control_id} - {control.title}")
            
            # This would trigger immediate notifications and response procedures
            
        except Exception as e:
            logger.error(f"Failed to handle high-risk violation: {e}")
    
    def _store_metric_in_database(self, metric: ComplianceMetric):
        """Store compliance metric in database."""
        try:
            conn = sqlite3.connect(self.db_path)
            
            conn.execute("""
                INSERT OR REPLACE INTO compliance_metrics (
                    metric_id, metric_name, framework, control_id, current_value,
                    target_value, measurement_unit, compliance_percentage, trend,
                    last_collected, collection_method
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                metric.metric_id,
                metric.metric_name,
                metric.framework.value,
                metric.control_id,
                str(metric.current_value),
                str(metric.target_value),
                metric.measurement_unit,
                metric.compliance_percentage,
                metric.trend,
                metric.last_collected.isoformat() if metric.last_collected else None,
                metric.collection_method
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"Failed to store metric in database: {e}")
    
    def _store_assessment_in_database(self, control: ComplianceControl, assessment_result: Dict[str, Any]):
        """Store control assessment in database."""
        try:
            conn = sqlite3.connect(self.db_path)
            
            assessment_id = f"assessment_{control.control_id}_{int(time.time())}"
            
            conn.execute("""
                INSERT INTO compliance_assessments (
                    assessment_id, control_id, assessment_date, assessor, status,
                    findings, evidence, recommendations, risk_score
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                assessment_id,
                control.control_id,
                assessment_result['assessment_date'].isoformat(),
                assessment_result.get('assessor', 'Unknown'),
                assessment_result['status'].value,
                json.dumps(assessment_result.get('findings', [])),
                json.dumps(assessment_result.get('evidence', [])),
                json.dumps(assessment_result.get('recommendations', [])),
                assessment_result.get('compliance_percentage', 0.0)
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"Failed to store assessment in database: {e}")
    
    def _update_control_in_database(self, control: ComplianceControl):
        """Update compliance control in database."""
        try:
            conn = sqlite3.connect(self.db_path)
            
            conn.execute("""
                INSERT OR REPLACE INTO compliance_controls (
                    control_id, framework, title, description, implementation_status,
                    implementation_description, responsible_party, assessment_method,
                    last_assessment_date, next_assessment_date, risk_level,
                    compliance_percentage, findings, remediation_actions,
                    evidence_locations, created_date, updated_date
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                control.control_id,
                control.framework.value,
                control.title,
                control.description,
                control.implementation_status.value,
                control.implementation_description,
                control.responsible_party,
                control.assessment_method,
                control.last_assessment_date.isoformat() if control.last_assessment_date else None,
                control.next_assessment_date.isoformat() if control.next_assessment_date else None,
                control.risk_level.value,
                control.compliance_percentage,
                json.dumps(control.findings),
                json.dumps(control.remediation_actions),
                json.dumps(control.evidence_locations),
                control.created_date.isoformat(),
                control.updated_date.isoformat()
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"Failed to update control in database: {e}")
    
    def _store_report_in_database(self, report: ComplianceReport):
        """Store compliance report in database."""
        try:
            conn = sqlite3.connect(self.db_path)
            
            conn.execute("""
                INSERT INTO compliance_reports (
                    report_id, report_type, framework, title, generated_date,
                    reporting_period_start, reporting_period_end, overall_compliance_score,
                    total_controls, compliant_controls, non_compliant_controls,
                    report_data, classification, generated_by
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                report.report_id,
                report.report_type.value,
                report.framework.value,
                report.title,
                report.generated_date.isoformat(),
                report.reporting_period_start.isoformat(),
                report.reporting_period_end.isoformat(),
                report.overall_compliance_score,
                report.total_controls,
                report.compliant_controls,
                report.non_compliant_controls,
                json.dumps(report.to_dict()),
                report.classification,
                report.generated_by
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"Failed to store report in database: {e}")
    
    def _save_report_to_file(self, report: ComplianceReport) -> str:
        """Save compliance report to file."""
        try:
            report_dir = Path(self.config.reports_directory) / report.framework.value
            report_dir.mkdir(parents=True, exist_ok=True)
            
            filename = f"{report.report_id}.json"
            file_path = report_dir / filename
            
            with open(file_path, 'w') as f:
                json.dump(report.to_dict(), f, indent=2, default=str)
            
            logger.debug(f"Saved compliance report to {file_path}")
            return str(file_path)
            
        except Exception as e:
            logger.error(f"Failed to save report to file: {e}")
            return ""
    
    def _generate_shutdown_reports(self):
        """Generate final reports before shutdown."""
        try:
            logger.info("Generating shutdown compliance reports...")
            
            for framework in self.config.enabled_frameworks:
                self.generate_compliance_report(ReportType.CUSTOM_REPORT, framework)
            
        except Exception as e:
            logger.error(f"Failed to generate shutdown reports: {e}")
    
    def _save_reporting_statistics(self):
        """Save final reporting statistics."""
        try:
            logger.info("Compliance Reporting Statistics:")
            logger.info(f"  Reports Generated: {self.reporting_stats['reports_generated']}")
            logger.info(f"  Assessments Completed: {self.reporting_stats['assessments_completed']}")
            logger.info(f"  Controls Evaluated: {self.reporting_stats['controls_evaluated']}")
            logger.info(f"  Compliance Violations: {self.reporting_stats['compliance_violations']}")
            
        except Exception as e:
            logger.error(f"Failed to save reporting statistics: {e}")
    
    def get_compliance_status(self, framework: Optional[ComplianceFramework] = None) -> Dict[str, Any]:
        """Get current compliance status."""
        try:
            if framework:
                # Status for specific framework
                controls = [
                    c for c in self.compliance_controls.values()
                    if c.framework == framework
                ]
                
                total = len(controls)
                compliant = len([c for c in controls if c.implementation_status == ComplianceStatus.COMPLIANT])
                
                return {
                    'framework': framework.value,
                    'total_controls': total,
                    'compliant_controls': compliant,
                    'compliance_percentage': (compliant / total * 100.0) if total > 0 else 0.0,
                    'last_assessment': max([c.last_assessment_date for c in controls if c.last_assessment_date], default=None)
                }
            else:
                # Overall status
                status_by_framework = {}
                
                for fw in self.config.enabled_frameworks:
                    status_by_framework[fw.value] = self.get_compliance_status(fw)
                
                return {
                    'overall_status': status_by_framework,
                    'system_status': {
                        'is_running': self.is_running,
                        'total_controls': len(self.compliance_controls),
                        'total_metrics': len(self.compliance_metrics),
                        'reports_generated': self.reporting_stats['reports_generated']
                    }
                }
                
        except Exception as e:
            logger.error(f"Failed to get compliance status: {e}")
            return {'error': str(e)}


# Global logger
logger = logging.getLogger(__name__)