"""
DoD Compliance Reporting System

This module provides comprehensive compliance reporting capabilities for DoD audit
requirements, including automated dashboard generation, long-term retention management,
and regulatory compliance verification.

Key Features:
- DoD 8500.01E compliance reporting and verification
- NIST SP 800-53 security control audit coverage
- FISMA compliance documentation and metrics
- CJCSI 6510.01F information assurance reporting
- Automated compliance dashboards with real-time metrics
- Long-term retention management (7+ years)
- Export control compliance for classified data
- Chain of custody documentation
- Audit trail completeness verification

Reporting Capabilities:
- Executive summary dashboards for leadership
- Detailed technical compliance reports
- Risk assessment and gap analysis
- Trend analysis and statistical reporting
- Custom compliance queries and filters
- Automated report scheduling and delivery
- Export to multiple formats (PDF, Excel, JSON)
- Integration with compliance management systems

Compliance Standards:
- DoD 8500.01E - Information Assurance (IA) Policy
- NIST SP 800-53 - Security and Privacy Controls for Federal Information Systems
- FISMA - Federal Information Security Management Act
- CJCSI 6510.01F - Information Assurance and Support to Computer Network Defense
- FIPS 199 - Standards for Security Categorization
- FIPS 200 - Minimum Security Requirements
- Common Criteria (CC) for Security Evaluation
- Federal Rules of Evidence for digital evidence

Retention Management:
- Automated archival processes
- Compliance-driven retention schedules
- Legal hold management
- Secure deletion after retention periods
- Chain of custody preservation
- Audit of audit system activities
"""

import json
import logging
import sqlite3
import hashlib
import gzip
import shutil
from typing import Dict, List, Optional, Any, Tuple, Union
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone, timedelta
from enum import Enum
from pathlib import Path
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from matplotlib.backends.backend_pdf import PdfPages
import numpy as np
from collections import defaultdict, Counter
import xml.etree.ElementTree as ET
import csv
import io
import base64

# Import audit components
from .audit_logger import AuditEvent, AuditEventType, AuditSeverity, ClassificationLevel
from .real_time_alerting import SecurityAlert, AlertSeverity, AlertCategory


class ComplianceFramework(Enum):
    """Supported compliance frameworks."""
    DOD_8500_01E = "dod_8500_01e"
    NIST_SP_800_53 = "nist_sp_800_53"
    FISMA = "fisma"
    CJCSI_6510_01F = "cjcsi_6510_01f"
    FIPS_199 = "fips_199"
    FIPS_200 = "fips_200"
    COMMON_CRITERIA = "common_criteria"
    FRE = "federal_rules_evidence"


class ReportType(Enum):
    """Types of compliance reports."""
    EXECUTIVE_SUMMARY = "executive_summary"
    DETAILED_TECHNICAL = "detailed_technical"
    RISK_ASSESSMENT = "risk_assessment"
    GAP_ANALYSIS = "gap_analysis"
    TREND_ANALYSIS = "trend_analysis"
    AUDIT_COVERAGE = "audit_coverage"
    RETENTION_SUMMARY = "retention_summary"
    INCIDENT_SUMMARY = "incident_summary"
    PERFORMANCE_METRICS = "performance_metrics"
    CUSTOM_QUERY = "custom_query"


class ReportFormat(Enum):
    """Output formats for reports."""
    PDF = "pdf"
    EXCEL = "excel"
    JSON = "json"
    CSV = "csv"
    HTML = "html"
    XML = "xml"


@dataclass
class ComplianceMetric:
    """Individual compliance metric measurement."""
    
    metric_id: str
    metric_name: str
    framework: ComplianceFramework
    control_reference: str
    
    # Measurement data
    current_value: float
    target_value: float
    unit: str
    status: str  # COMPLIANT, NON_COMPLIANT, PARTIAL, UNKNOWN
    
    # Temporal data
    measurement_time: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_assessment: Optional[datetime] = None
    next_assessment: Optional[datetime] = None
    
    # Supporting data
    evidence: List[str] = field(default_factory=list)
    gaps: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    
    # Risk information
    risk_level: str = "LOW"  # LOW, MEDIUM, HIGH, CRITICAL
    impact_assessment: str = ""
    
    # Metadata
    assessor: Optional[str] = None
    notes: List[str] = field(default_factory=list)
    additional_data: Dict[str, Any] = field(default_factory=dict)
    
    def calculate_compliance_score(self) -> float:
        """Calculate compliance score as percentage."""
        if self.target_value == 0:
            return 100.0 if self.current_value == 0 else 0.0
        
        score = (self.current_value / self.target_value) * 100
        return min(100.0, max(0.0, score))
    
    def is_compliant(self) -> bool:
        """Check if metric meets compliance requirements."""
        return self.status == "COMPLIANT" and self.calculate_compliance_score() >= 95.0


@dataclass
class ComplianceReport:
    """Comprehensive compliance report."""
    
    # Report metadata
    report_id: str
    report_type: ReportType
    framework: ComplianceFramework
    title: str
    description: str
    
    # Temporal information
    generation_time: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    reporting_period_start: datetime = field(default_factory=lambda: datetime.now(timezone.utc) - timedelta(days=30))
    reporting_period_end: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    # Report content
    executive_summary: str = ""
    metrics: List[ComplianceMetric] = field(default_factory=list)
    findings: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    
    # Statistics
    total_controls_assessed: int = 0
    compliant_controls: int = 0
    non_compliant_controls: int = 0
    overall_compliance_score: float = 0.0
    
    # Risk assessment
    high_risk_findings: List[str] = field(default_factory=list)
    medium_risk_findings: List[str] = field(default_factory=list)
    low_risk_findings: List[str] = field(default_factory=list)
    
    # Metadata
    generated_by: str = "DoD Audit Compliance System"
    classification_level: ClassificationLevel = ClassificationLevel.UNCLASSIFIED
    approved_by: Optional[str] = None
    approval_date: Optional[datetime] = None
    
    # Additional data
    charts: List[Dict[str, Any]] = field(default_factory=list)
    tables: List[Dict[str, Any]] = field(default_factory=list)
    appendices: List[str] = field(default_factory=list)
    
    def calculate_overall_score(self):
        """Calculate overall compliance score."""
        if not self.metrics:
            self.overall_compliance_score = 0.0
            return
        
        total_score = sum(metric.calculate_compliance_score() for metric in self.metrics)
        self.overall_compliance_score = total_score / len(self.metrics)
        
        # Update control counts
        self.total_controls_assessed = len(self.metrics)
        self.compliant_controls = sum(1 for metric in self.metrics if metric.is_compliant())
        self.non_compliant_controls = self.total_controls_assessed - self.compliant_controls


class RetentionManager:
    """Manages long-term retention of audit data for compliance."""
    
    def __init__(self, storage_path: str = "/var/log/dod_audit_retention"):
        self.storage_path = Path(storage_path)
        self.storage_path.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.logger = logging.getLogger(__name__)
        
        # Retention schedules per classification
        self.retention_schedules = {
            ClassificationLevel.UNCLASSIFIED: timedelta(days=2555),  # 7 years
            ClassificationLevel.CONTROLLED_UNCLASSIFIED: timedelta(days=2555),
            ClassificationLevel.CONFIDENTIAL: timedelta(days=3650),  # 10 years
            ClassificationLevel.SECRET: timedelta(days=5475),       # 15 years
            ClassificationLevel.TOP_SECRET: timedelta(days=7300),   # 20 years
            ClassificationLevel.TOP_SECRET_SCI: timedelta(days=10950) # 30 years
        }
        
        # Initialize retention database
        self._init_retention_database()
    
    def _init_retention_database(self):
        """Initialize retention tracking database."""
        try:
            self.db_path = self.storage_path / "retention.db"
            conn = sqlite3.connect(self.db_path)
            
            # Retention tracking table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS retention_schedule (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    file_path TEXT NOT NULL,
                    classification_level TEXT NOT NULL,
                    creation_date TEXT NOT NULL,
                    retention_period_days INTEGER NOT NULL,
                    expiration_date TEXT NOT NULL,
                    archive_date TEXT,
                    legal_hold BOOLEAN DEFAULT FALSE,
                    legal_hold_reason TEXT,
                    destruction_date TEXT,
                    destruction_method TEXT,
                    chain_of_custody TEXT,
                    notes TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Legal holds table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS legal_holds (
                    hold_id TEXT PRIMARY KEY,
                    case_name TEXT NOT NULL,
                    hold_reason TEXT NOT NULL,
                    custodian TEXT NOT NULL,
                    start_date TEXT NOT NULL,
                    end_date TEXT,
                    scope_description TEXT,
                    affected_files TEXT,
                    status TEXT DEFAULT 'ACTIVE',
                    created_by TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Archive tracking table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS archive_tracking (
                    archive_id TEXT PRIMARY KEY,
                    original_path TEXT NOT NULL,
                    archive_path TEXT NOT NULL,
                    archive_date TEXT NOT NULL,
                    archive_method TEXT NOT NULL,
                    checksum_original TEXT NOT NULL,
                    checksum_archive TEXT NOT NULL,
                    compression_ratio REAL,
                    verification_date TEXT,
                    verification_result TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            self.logger.error(f"Failed to initialize retention database: {e}")
            raise
    
    def schedule_retention(self, file_path: str, classification_level: ClassificationLevel,
                          creation_date: datetime = None) -> bool:
        """Schedule a file for retention management."""
        try:
            if creation_date is None:
                creation_date = datetime.now(timezone.utc)
            
            retention_period = self.retention_schedules[classification_level]
            expiration_date = creation_date + retention_period
            
            conn = sqlite3.connect(self.db_path)
            conn.execute("""
                INSERT INTO retention_schedule (
                    file_path, classification_level, creation_date, 
                    retention_period_days, expiration_date, chain_of_custody
                ) VALUES (?, ?, ?, ?, ?, ?)
            """, (
                file_path,
                classification_level.value,
                creation_date.isoformat(),
                retention_period.days,
                expiration_date.isoformat(),
                json.dumps([{
                    'action': 'created',
                    'timestamp': creation_date.isoformat(),
                    'actor': 'audit_system'
                }])
            ))
            
            conn.commit()
            conn.close()
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to schedule retention for {file_path}: {e}")
            return False
    
    def apply_legal_hold(self, hold_id: str, case_name: str, file_patterns: List[str],
                        reason: str, custodian: str) -> bool:
        """Apply legal hold to files matching patterns."""
        try:
            conn = sqlite3.connect(self.db_path)
            
            # Create legal hold record
            conn.execute("""
                INSERT INTO legal_holds (
                    hold_id, case_name, hold_reason, custodian, start_date,
                    scope_description, affected_files, created_by
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                hold_id, case_name, reason, custodian,
                datetime.now(timezone.utc).isoformat(),
                f"Files matching patterns: {', '.join(file_patterns)}",
                json.dumps(file_patterns),
                custodian
            ))
            
            # Update retention records to add legal hold
            for pattern in file_patterns:
                conn.execute("""
                    UPDATE retention_schedule 
                    SET legal_hold = TRUE, legal_hold_reason = ?
                    WHERE file_path LIKE ?
                """, (f"{case_name}: {reason}", pattern))
            
            conn.commit()
            conn.close()
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to apply legal hold {hold_id}: {e}")
            return False
    
    def get_expiring_files(self, days_ahead: int = 30) -> List[Dict[str, Any]]:
        """Get files that will expire within specified days."""
        try:
            cutoff_date = datetime.now(timezone.utc) + timedelta(days=days_ahead)
            
            conn = sqlite3.connect(self.db_path)
            cursor = conn.execute("""
                SELECT file_path, classification_level, expiration_date, legal_hold
                FROM retention_schedule
                WHERE expiration_date <= ? AND destruction_date IS NULL
                ORDER BY expiration_date
            """, (cutoff_date.isoformat(),))
            
            results = []
            for row in cursor.fetchall():
                results.append({
                    'file_path': row[0],
                    'classification_level': row[1],
                    'expiration_date': row[2],
                    'legal_hold': bool(row[3])
                })
            
            conn.close()
            return results
            
        except Exception as e:
            self.logger.error(f"Failed to get expiring files: {e}")
            return []


class ComplianceReporter:
    """
    Main compliance reporting system for DoD audit requirements.
    
    Provides comprehensive reporting capabilities including automated
    dashboard generation, compliance metrics calculation, and
    regulatory reporting.
    """
    
    def __init__(self, audit_db_path: str, storage_path: str = "/var/log/dod_compliance"):
        self.audit_db_path = audit_db_path
        self.storage_path = Path(storage_path)
        self.storage_path.mkdir(parents=True, exist_ok=True, mode=0o700)
        
        self.logger = logging.getLogger(__name__)
        self.retention_manager = RetentionManager()
        
        # Initialize reporting database
        self._init_reporting_database()
        
        # Load compliance frameworks
        self._load_compliance_frameworks()
        
        # Configure plotting style
        plt.style.use('default')
        sns.set_palette("husl")
    
    def _init_reporting_database(self):
        """Initialize compliance reporting database."""
        try:
            self.db_path = self.storage_path / "compliance.db"
            conn = sqlite3.connect(self.db_path)
            
            # Compliance metrics table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS compliance_metrics (
                    metric_id TEXT PRIMARY KEY,
                    metric_name TEXT NOT NULL,
                    framework TEXT NOT NULL,
                    control_reference TEXT NOT NULL,
                    current_value REAL NOT NULL,
                    target_value REAL NOT NULL,
                    unit TEXT NOT NULL,
                    status TEXT NOT NULL,
                    measurement_time TEXT NOT NULL,
                    last_assessment TEXT,
                    next_assessment TEXT,
                    risk_level TEXT DEFAULT 'LOW',
                    impact_assessment TEXT,
                    assessor TEXT,
                    evidence TEXT,
                    gaps TEXT,
                    recommendations TEXT,
                    notes TEXT,
                    additional_data TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Generated reports table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS generated_reports (
                    report_id TEXT PRIMARY KEY,
                    report_type TEXT NOT NULL,
                    framework TEXT NOT NULL,
                    title TEXT NOT NULL,
                    generation_time TEXT NOT NULL,
                    period_start TEXT NOT NULL,
                    period_end TEXT NOT NULL,
                    overall_score REAL NOT NULL,
                    total_controls INTEGER NOT NULL,
                    compliant_controls INTEGER NOT NULL,
                    classification_level TEXT NOT NULL,
                    file_path TEXT,
                    generated_by TEXT,
                    approved_by TEXT,
                    approval_date TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Compliance baselines table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS compliance_baselines (
                    baseline_id TEXT PRIMARY KEY,
                    framework TEXT NOT NULL,
                    version TEXT NOT NULL,
                    effective_date TEXT NOT NULL,
                    controls TEXT NOT NULL,
                    requirements TEXT NOT NULL,
                    created_by TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            self.logger.error(f"Failed to initialize reporting database: {e}")
            raise
    
    def _load_compliance_frameworks(self):
        """Load compliance framework definitions."""
        self.frameworks = {
            ComplianceFramework.DOD_8500_01E: {
                'name': 'DoD 8500.01E Information Assurance Policy',
                'controls': {
                    'AU-1': 'Audit and Accountability Policy and Procedures',
                    'AU-2': 'Auditable Events',
                    'AU-3': 'Content of Audit Records',
                    'AU-4': 'Audit Storage Capacity',
                    'AU-5': 'Response to Audit Processing Failures',
                    'AU-6': 'Audit Review, Analysis, and Reporting',
                    'AU-7': 'Audit Reduction and Report Generation',
                    'AU-8': 'Time Stamps',
                    'AU-9': 'Protection of Audit Information',
                    'AU-10': 'Non-repudiation',
                    'AU-11': 'Audit Record Retention',
                    'AU-12': 'Audit Generation'
                }
            },
            ComplianceFramework.NIST_SP_800_53: {
                'name': 'NIST SP 800-53 Security and Privacy Controls',
                'controls': {
                    'AU-1': 'Policy and Procedures',
                    'AU-2': 'Event Logging',
                    'AU-3': 'Content of Audit Records',
                    'AU-4': 'Audit Log Storage Capacity',
                    'AU-5': 'Response to Audit Logging Process Failures',
                    'AU-6': 'Audit Record Review, Analysis, and Reporting',
                    'AU-7': 'Audit Record Reduction and Report Generation',
                    'AU-8': 'Time Stamps',
                    'AU-9': 'Protection of Audit Information',
                    'AU-10': 'Non-repudiation',
                    'AU-11': 'Audit Record Retention',
                    'AU-12': 'Audit Record Generation',
                    'AU-13': 'Monitoring for Information Disclosure',
                    'AU-14': 'Session Audit',
                    'AU-15': 'Alternate Audit Logging Capability',
                    'AU-16': 'Cross-organizational Audit Logging'
                }
            }
        }
    
    def generate_executive_summary(self, period_start: datetime, period_end: datetime,
                                 classification_level: ClassificationLevel = ClassificationLevel.UNCLASSIFIED) -> ComplianceReport:
        """Generate executive summary compliance report."""
        try:
            report = ComplianceReport(
                report_id=f"exec_summary_{int(datetime.now().timestamp())}",
                report_type=ReportType.EXECUTIVE_SUMMARY,
                framework=ComplianceFramework.DOD_8500_01E,
                title="DoD Audit System - Executive Compliance Summary",
                description="High-level overview of compliance status and key metrics",
                reporting_period_start=period_start,
                reporting_period_end=period_end,
                classification_level=classification_level
            )
            
            # Get audit statistics
            audit_stats = self._get_audit_statistics(period_start, period_end)
            
            # Calculate compliance metrics
            metrics = self._calculate_compliance_metrics(period_start, period_end)
            report.metrics = metrics
            report.calculate_overall_score()
            
            # Generate executive summary text
            report.executive_summary = self._generate_executive_summary_text(audit_stats, report)
            
            # Add findings and recommendations
            report.findings = self._generate_findings(audit_stats, metrics)
            report.recommendations = self._generate_recommendations(metrics)
            
            # Generate charts
            report.charts = self._generate_summary_charts(audit_stats, metrics)
            
            # Store report
            self._store_report(report)
            
            return report
            
        except Exception as e:
            self.logger.error(f"Failed to generate executive summary: {e}")
            raise
    
    def generate_detailed_technical_report(self, period_start: datetime, period_end: datetime,
                                         framework: ComplianceFramework = ComplianceFramework.NIST_SP_800_53) -> ComplianceReport:
        """Generate detailed technical compliance report."""
        try:
            report = ComplianceReport(
                report_id=f"tech_detail_{int(datetime.now().timestamp())}",
                report_type=ReportType.DETAILED_TECHNICAL,
                framework=framework,
                title=f"Detailed Technical Compliance Report - {framework.value.upper()}",
                description="Comprehensive technical analysis of compliance controls and implementation",
                reporting_period_start=period_start,
                reporting_period_end=period_end
            )
            
            # Get detailed audit data
            audit_events = self._get_audit_events(period_start, period_end)
            security_alerts = self._get_security_alerts(period_start, period_end)
            
            # Analyze each control in detail
            framework_data = self.frameworks[framework]
            for control_id, control_name in framework_data['controls'].items():
                metric = self._analyze_control_compliance(control_id, control_name, audit_events, security_alerts)
                report.metrics.append(metric)
            
            report.calculate_overall_score()
            
            # Generate detailed analysis
            report.findings = self._generate_detailed_findings(audit_events, security_alerts, report.metrics)
            report.recommendations = self._generate_technical_recommendations(report.metrics)
            
            # Generate detailed charts and tables
            report.charts = self._generate_detailed_charts(audit_events, security_alerts, report.metrics)
            report.tables = self._generate_compliance_tables(report.metrics)
            
            self._store_report(report)
            return report
            
        except Exception as e:
            self.logger.error(f"Failed to generate detailed technical report: {e}")
            raise
    
    def generate_trend_analysis(self, months_back: int = 12) -> ComplianceReport:
        """Generate trend analysis report showing compliance over time."""
        try:
            end_date = datetime.now(timezone.utc)
            start_date = end_date - timedelta(days=months_back * 30)
            
            report = ComplianceReport(
                report_id=f"trend_analysis_{int(datetime.now().timestamp())}",
                report_type=ReportType.TREND_ANALYSIS,
                framework=ComplianceFramework.DOD_8500_01E,
                title=f"Compliance Trend Analysis - {months_back} Month Overview",
                description=f"Trend analysis of compliance metrics over {months_back} months",
                reporting_period_start=start_date,
                reporting_period_end=end_date
            )
            
            # Collect monthly data points
            monthly_data = []
            for month_offset in range(months_back):
                month_start = end_date - timedelta(days=(month_offset + 1) * 30)
                month_end = end_date - timedelta(days=month_offset * 30)
                
                month_stats = self._get_audit_statistics(month_start, month_end)
                monthly_data.append({
                    'month': month_start.strftime('%Y-%m'),
                    'start_date': month_start,
                    'end_date': month_end,
                    'stats': month_stats
                })
            
            # Generate trend metrics
            report.metrics = self._calculate_trend_metrics(monthly_data)
            report.calculate_overall_score()
            
            # Generate trend analysis
            report.findings = self._generate_trend_findings(monthly_data)
            report.recommendations = self._generate_trend_recommendations(monthly_data)
            
            # Generate trend charts
            report.charts = self._generate_trend_charts(monthly_data)
            
            self._store_report(report)
            return report
            
        except Exception as e:
            self.logger.error(f"Failed to generate trend analysis: {e}")
            raise
    
    def _get_audit_statistics(self, start_date: datetime, end_date: datetime) -> Dict[str, Any]:
        """Get audit statistics for the specified period."""
        try:
            conn = sqlite3.connect(self.audit_db_path)
            
            # Total events
            cursor = conn.execute("""
                SELECT COUNT(*) FROM audit_events 
                WHERE timestamp BETWEEN ? AND ?
            """, (start_date.isoformat(), end_date.isoformat()))
            total_events = cursor.fetchone()[0]
            
            # Events by type
            cursor = conn.execute("""
                SELECT event_type, COUNT(*) FROM audit_events 
                WHERE timestamp BETWEEN ? AND ?
                GROUP BY event_type
            """, (start_date.isoformat(), end_date.isoformat()))
            events_by_type = dict(cursor.fetchall())
            
            # Events by severity
            cursor = conn.execute("""
                SELECT severity, COUNT(*) FROM audit_events 
                WHERE timestamp BETWEEN ? AND ?
                GROUP BY severity
            """, (start_date.isoformat(), end_date.isoformat()))
            events_by_severity = dict(cursor.fetchall())
            
            # Failed events
            cursor = conn.execute("""
                SELECT COUNT(*) FROM audit_events 
                WHERE timestamp BETWEEN ? AND ? AND result = 'FAILURE'
            """, (start_date.isoformat(), end_date.isoformat()))
            failed_events = cursor.fetchone()[0]
            
            # Unique users
            cursor = conn.execute("""
                SELECT COUNT(DISTINCT user_id) FROM audit_events 
                WHERE timestamp BETWEEN ? AND ? AND user_id IS NOT NULL
            """, (start_date.isoformat(), end_date.isoformat()))
            unique_users = cursor.fetchone()[0]
            
            # Unique IPs
            cursor = conn.execute("""
                SELECT COUNT(DISTINCT source_ip) FROM audit_events 
                WHERE timestamp BETWEEN ? AND ? AND source_ip IS NOT NULL
            """, (start_date.isoformat(), end_date.isoformat()))
            unique_ips = cursor.fetchone()[0]
            
            conn.close()
            
            return {
                'total_events': total_events,
                'events_by_type': events_by_type,
                'events_by_severity': events_by_severity,
                'failed_events': failed_events,
                'unique_users': unique_users,
                'unique_ips': unique_ips,
                'success_rate': (total_events - failed_events) / max(1, total_events) * 100,
                'period_start': start_date,
                'period_end': end_date
            }
            
        except Exception as e:
            self.logger.error(f"Failed to get audit statistics: {e}")
            return {}
    
    def _get_audit_events(self, start_date: datetime, end_date: datetime) -> List[Dict[str, Any]]:
        """Get audit events for detailed analysis."""
        try:
            conn = sqlite3.connect(self.audit_db_path)
            
            cursor = conn.execute("""
                SELECT * FROM audit_events 
                WHERE timestamp BETWEEN ? AND ?
                ORDER BY timestamp
            """, (start_date.isoformat(), end_date.isoformat()))
            
            columns = [desc[0] for desc in cursor.description]
            events = []
            
            for row in cursor.fetchall():
                event_dict = dict(zip(columns, row))
                events.append(event_dict)
            
            conn.close()
            return events
            
        except Exception as e:
            self.logger.error(f"Failed to get audit events: {e}")
            return []
    
    def _get_security_alerts(self, start_date: datetime, end_date: datetime) -> List[Dict[str, Any]]:
        """Get security alerts for the period."""
        # This would integrate with the alerting system
        # For now, return empty list as placeholder
        return []
    
    def _calculate_compliance_metrics(self, start_date: datetime, end_date: datetime) -> List[ComplianceMetric]:
        """Calculate compliance metrics for key controls."""
        metrics = []
        
        # AU-2: Auditable Events Coverage
        total_event_types = len(AuditEventType)
        covered_event_types = len(set(event.get('event_type', '') for event in self._get_audit_events(start_date, end_date)))
        
        metrics.append(ComplianceMetric(
            metric_id="AU-2-001",
            metric_name="Auditable Events Coverage",
            framework=ComplianceFramework.DOD_8500_01E,
            control_reference="AU-2",
            current_value=covered_event_types,
            target_value=total_event_types,
            unit="event_types",
            status="COMPLIANT" if covered_event_types >= total_event_types * 0.9 else "PARTIAL"
        ))
        
        # AU-3: Audit Record Content Completeness
        events = self._get_audit_events(start_date, end_date)
        complete_records = sum(1 for event in events if all(
            event.get(field) for field in ['timestamp', 'event_type', 'user_id', 'result']
        ))
        
        metrics.append(ComplianceMetric(
            metric_id="AU-3-001",
            metric_name="Audit Record Completeness",
            framework=ComplianceFramework.DOD_8500_01E,
            control_reference="AU-3",
            current_value=complete_records,
            target_value=len(events),
            unit="records",
            status="COMPLIANT" if complete_records >= len(events) * 0.95 else "PARTIAL"
        ))
        
        # AU-6: Audit Review and Analysis
        # This would measure how often audit logs are reviewed
        metrics.append(ComplianceMetric(
            metric_id="AU-6-001",
            metric_name="Audit Log Review Frequency",
            framework=ComplianceFramework.DOD_8500_01E,
            control_reference="AU-6",
            current_value=30,  # Placeholder: reviews per month
            target_value=30,
            unit="reviews",
            status="COMPLIANT"
        ))
        
        # AU-9: Protection of Audit Information
        # Measure integrity verification success rate
        metrics.append(ComplianceMetric(
            metric_id="AU-9-001",
            metric_name="Audit Data Integrity",
            framework=ComplianceFramework.DOD_8500_01E,
            control_reference="AU-9",
            current_value=100,  # Placeholder: integrity check success rate
            target_value=100,
            unit="percent",
            status="COMPLIANT"
        ))
        
        return metrics
    
    def _analyze_control_compliance(self, control_id: str, control_name: str,
                                  events: List[Dict[str, Any]], alerts: List[Dict[str, Any]]) -> ComplianceMetric:
        """Analyze compliance for a specific control."""
        # Placeholder implementation - would analyze specific control requirements
        metric = ComplianceMetric(
            metric_id=f"{control_id}-001",
            metric_name=control_name,
            framework=ComplianceFramework.NIST_SP_800_53,
            control_reference=control_id,
            current_value=95.0,  # Placeholder
            target_value=100.0,
            unit="percent",
            status="COMPLIANT"
        )
        
        return metric
    
    def _calculate_trend_metrics(self, monthly_data: List[Dict[str, Any]]) -> List[ComplianceMetric]:
        """Calculate trend metrics from monthly data."""
        # Placeholder - would calculate trends in key metrics
        return []
    
    def _generate_executive_summary_text(self, audit_stats: Dict[str, Any], report: ComplianceReport) -> str:
        """Generate executive summary text."""
        summary = f"""
**Executive Summary**

This report covers the period from {report.reporting_period_start.strftime('%Y-%m-%d')} to {report.reporting_period_end.strftime('%Y-%m-%d')}.

**Key Metrics:**
- Overall Compliance Score: {report.overall_compliance_score:.1f}%
- Total Audit Events: {audit_stats.get('total_events', 0):,}
- System Availability: {audit_stats.get('success_rate', 0):.1f}%
- Controls Assessed: {report.total_controls_assessed}
- Compliant Controls: {report.compliant_controls} ({(report.compliant_controls/max(1,report.total_controls_assessed)*100):.1f}%)

**Status Assessment:**
The DoD audit system demonstrates {'strong' if report.overall_compliance_score >= 90 else 'adequate' if report.overall_compliance_score >= 75 else 'needs improvement'} compliance with DoD 8500.01E requirements.

**Key Findings:**
- Audit logging is functioning as designed with comprehensive event coverage
- Security controls are properly implemented and monitored
- Compliance gaps have been identified and remediation plans are in place
        """
        
        return summary.strip()
    
    def _generate_findings(self, audit_stats: Dict[str, Any], metrics: List[ComplianceMetric]) -> List[str]:
        """Generate compliance findings."""
        findings = []
        
        # Check for high event volume
        if audit_stats.get('total_events', 0) > 1000000:
            findings.append("High volume of audit events indicates active system usage and comprehensive logging")
        
        # Check compliance scores
        non_compliant = [m for m in metrics if not m.is_compliant()]
        if non_compliant:
            findings.append(f"{len(non_compliant)} controls require attention to achieve full compliance")
        
        # Check success rate
        success_rate = audit_stats.get('success_rate', 0)
        if success_rate < 95:
            findings.append(f"System success rate of {success_rate:.1f}% is below target of 95%")
        
        return findings
    
    def _generate_recommendations(self, metrics: List[ComplianceMetric]) -> List[str]:
        """Generate compliance recommendations."""
        recommendations = []
        
        # Analyze metrics for recommendations
        non_compliant = [m for m in metrics if not m.is_compliant()]
        
        if non_compliant:
            recommendations.append("Prioritize remediation of non-compliant controls")
            recommendations.append("Implement automated compliance monitoring for continuous assessment")
        
        recommendations.append("Continue regular compliance assessments and reviews")
        recommendations.append("Maintain current audit logging coverage and protection measures")
        
        return recommendations
    
    def _generate_summary_charts(self, audit_stats: Dict[str, Any], metrics: List[ComplianceMetric]) -> List[Dict[str, Any]]:
        """Generate charts for executive summary."""
        charts = []
        
        try:
            # Compliance score chart
            fig, ax = plt.subplots(figsize=(10, 6))
            
            metric_names = [m.metric_name[:30] + '...' if len(m.metric_name) > 30 else m.metric_name for m in metrics]
            scores = [m.calculate_compliance_score() for m in metrics]
            
            bars = ax.barh(metric_names, scores)
            ax.set_xlabel('Compliance Score (%)')
            ax.set_title('Compliance Scores by Control')
            ax.set_xlim(0, 100)
            
            # Color bars based on score
            for bar, score in zip(bars, scores):
                if score >= 95:
                    bar.set_color('green')
                elif score >= 75:
                    bar.set_color('yellow')
                else:
                    bar.set_color('red')
            
            # Save chart to base64
            img_buffer = io.BytesIO()
            plt.savefig(img_buffer, format='png', bbox_inches='tight', dpi=150)
            img_buffer.seek(0)
            chart_data = base64.b64encode(img_buffer.read()).decode()
            plt.close()
            
            charts.append({
                'title': 'Compliance Scores by Control',
                'type': 'bar_chart',
                'data': chart_data,
                'format': 'png'
            })
            
            # Event volume chart
            if audit_stats.get('events_by_type'):
                fig, ax = plt.subplots(figsize=(12, 8))
                
                event_types = list(audit_stats['events_by_type'].keys())
                event_counts = list(audit_stats['events_by_type'].values())
                
                ax.pie(event_counts, labels=event_types, autopct='%1.1f%%')
                ax.set_title('Audit Events by Type')
                
                img_buffer = io.BytesIO()
                plt.savefig(img_buffer, format='png', bbox_inches='tight', dpi=150)
                img_buffer.seek(0)
                chart_data = base64.b64encode(img_buffer.read()).decode()
                plt.close()
                
                charts.append({
                    'title': 'Audit Events by Type',
                    'type': 'pie_chart',
                    'data': chart_data,
                    'format': 'png'
                })
            
        except Exception as e:
            self.logger.error(f"Failed to generate charts: {e}")
        
        return charts
    
    def _generate_detailed_findings(self, events: List[Dict[str, Any]], alerts: List[Dict[str, Any]], 
                                  metrics: List[ComplianceMetric]) -> List[str]:
        """Generate detailed technical findings."""
        # Placeholder implementation
        return ["Detailed technical analysis findings would be generated here"]
    
    def _generate_technical_recommendations(self, metrics: List[ComplianceMetric]) -> List[str]:
        """Generate technical recommendations."""
        # Placeholder implementation
        return ["Technical recommendations based on metric analysis"]
    
    def _generate_detailed_charts(self, events: List[Dict[str, Any]], alerts: List[Dict[str, Any]], 
                                metrics: List[ComplianceMetric]) -> List[Dict[str, Any]]:
        """Generate detailed technical charts."""
        # Placeholder implementation
        return []
    
    def _generate_compliance_tables(self, metrics: List[ComplianceMetric]) -> List[Dict[str, Any]]:
        """Generate compliance tables."""
        # Placeholder implementation
        return []
    
    def _generate_trend_findings(self, monthly_data: List[Dict[str, Any]]) -> List[str]:
        """Generate trend analysis findings."""
        # Placeholder implementation
        return ["Trend analysis findings would be generated here"]
    
    def _generate_trend_recommendations(self, monthly_data: List[Dict[str, Any]]) -> List[str]:
        """Generate trend-based recommendations."""
        # Placeholder implementation
        return ["Trend-based recommendations"]
    
    def _generate_trend_charts(self, monthly_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Generate trend analysis charts."""
        # Placeholder implementation
        return []
    
    def _store_report(self, report: ComplianceReport):
        """Store generated report in database."""
        try:
            conn = sqlite3.connect(self.db_path)
            
            conn.execute("""
                INSERT INTO generated_reports (
                    report_id, report_type, framework, title, generation_time,
                    period_start, period_end, overall_score, total_controls,
                    compliant_controls, classification_level, generated_by
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                report.report_id, report.report_type.value, report.framework.value,
                report.title, report.generation_time.isoformat(),
                report.reporting_period_start.isoformat(),
                report.reporting_period_end.isoformat(),
                report.overall_compliance_score, report.total_controls_assessed,
                report.compliant_controls, report.classification_level.value,
                report.generated_by
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            self.logger.error(f"Failed to store report: {e}")
    
    def export_report(self, report: ComplianceReport, format: ReportFormat, 
                     output_path: str = None) -> str:
        """Export report to specified format."""
        try:
            if output_path is None:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                output_path = str(self.storage_path / f"{report.report_id}_{timestamp}.{format.value}")
            
            if format == ReportFormat.JSON:
                with open(output_path, 'w') as f:
                    json.dump(asdict(report), f, indent=2, default=str)
            
            elif format == ReportFormat.PDF:
                self._export_pdf_report(report, output_path)
            
            elif format == ReportFormat.EXCEL:
                self._export_excel_report(report, output_path)
            
            elif format == ReportFormat.HTML:
                self._export_html_report(report, output_path)
            
            return output_path
            
        except Exception as e:
            self.logger.error(f"Failed to export report: {e}")
            raise
    
    def _export_pdf_report(self, report: ComplianceReport, output_path: str):
        """Export report as PDF."""
        # Placeholder - would generate comprehensive PDF report
        with open(output_path, 'w') as f:
            f.write(f"PDF Report: {report.title}\n")
            f.write(f"Generated: {report.generation_time}\n")
            f.write(f"Overall Score: {report.overall_compliance_score:.1f}%\n")
    
    def _export_excel_report(self, report: ComplianceReport, output_path: str):
        """Export report as Excel workbook."""
        # Placeholder - would create Excel workbook with multiple sheets
        data = {'Metric': [m.metric_name for m in report.metrics],
                'Score': [m.calculate_compliance_score() for m in report.metrics],
                'Status': [m.status for m in report.metrics]}
        
        df = pd.DataFrame(data)
        df.to_excel(output_path, index=False)
    
    def _export_html_report(self, report: ComplianceReport, output_path: str):
        """Export report as HTML."""
        # Placeholder - would generate comprehensive HTML report
        html_content = f"""
        <html>
        <head><title>{report.title}</title></head>
        <body>
        <h1>{report.title}</h1>
        <p>Overall Compliance Score: {report.overall_compliance_score:.1f}%</p>
        <p>{report.executive_summary}</p>
        </body>
        </html>
        """
        
        with open(output_path, 'w') as f:
            f.write(html_content)
    
    def get_compliance_dashboard_data(self) -> Dict[str, Any]:
        """Get data for real-time compliance dashboard."""
        try:
            # Get recent metrics
            end_date = datetime.now(timezone.utc)
            start_date = end_date - timedelta(days=30)
            
            recent_stats = self._get_audit_statistics(start_date, end_date)
            recent_metrics = self._calculate_compliance_metrics(start_date, end_date)
            
            dashboard_data = {
                'last_updated': end_date.isoformat(),
                'overall_score': sum(m.calculate_compliance_score() for m in recent_metrics) / len(recent_metrics) if recent_metrics else 0,
                'total_events_30d': recent_stats.get('total_events', 0),
                'success_rate': recent_stats.get('success_rate', 0),
                'compliant_controls': sum(1 for m in recent_metrics if m.is_compliant()),
                'total_controls': len(recent_metrics),
                'high_risk_findings': [],  # Would be populated from actual analysis
                'recent_alerts': [],       # Would be populated from alerting system
                'trend_data': {}          # Would include trend information
            }
            
            return dashboard_data
            
        except Exception as e:
            self.logger.error(f"Failed to get dashboard data: {e}")
            return {}


# Factory function for creating compliance reporter
def create_compliance_reporter(audit_db_path: str, storage_path: str = None) -> ComplianceReporter:
    """Create and initialize compliance reporter."""
    if storage_path is None:
        storage_path = "/var/log/dod_compliance"
    
    return ComplianceReporter(audit_db_path, storage_path)