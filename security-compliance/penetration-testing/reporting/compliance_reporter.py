"""
Compliance Reporter
===================

Advanced compliance reporting engine that generates comprehensive reports on
vulnerability remediation status, compliance posture, and audit trail information
for various regulatory frameworks and organizational requirements.

Features:
- Multi-framework compliance reporting (NIST, DoD STIG, FISMA, etc.)
- Automated remediation status reporting
- Compliance dashboard integration
- Audit trail generation for all remediation activities
- Metrics and KPI tracking
- Executive summary and technical detail reports
- Customizable report templates
- Real-time compliance monitoring
"""

import asyncio
import json
import logging
import sqlite3
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from pathlib import Path
from enum import Enum
import pandas as pd
import numpy as np
from jinja2 import Template
import matplotlib.pyplot as plt
import seaborn as sns
from io import BytesIO
import base64

logger = logging.getLogger(__name__)

class ComplianceFramework(Enum):
    """Supported compliance frameworks"""
    NIST_800_53 = "nist_800_53"
    DOD_STIG = "dod_stig"
    FISMA = "fisma"
    SOX = "sox"
    PCI_DSS = "pci_dss"
    ISO_27001 = "iso_27001"
    CISA_KEV = "cisa_kev"
    CUSTOM = "custom"

class ReportType(Enum):
    """Types of compliance reports"""
    EXECUTIVE_SUMMARY = "executive_summary"
    DETAILED_TECHNICAL = "detailed_technical"
    COMPLIANCE_STATUS = "compliance_status"
    REMEDIATION_PROGRESS = "remediation_progress"
    AUDIT_TRAIL = "audit_trail"
    METRICS_DASHBOARD = "metrics_dashboard"
    RISK_ASSESSMENT = "risk_assessment"
    SLA_PERFORMANCE = "sla_performance"

class ReportFormat(Enum):
    """Report output formats"""
    HTML = "html"
    PDF = "pdf"
    JSON = "json"
    CSV = "csv"
    EXCEL = "excel"

@dataclass
class ComplianceControl:
    """Compliance control mapping"""
    control_id: str
    framework: ComplianceFramework
    control_name: str
    description: str
    implementation_status: str
    remediation_status: str
    risk_level: str
    related_vulnerabilities: List[str] = field(default_factory=list)
    evidence: List[str] = field(default_factory=list)
    last_assessed: Optional[datetime] = None
    next_assessment: Optional[datetime] = None

@dataclass
class ComplianceReport:
    """Generated compliance report"""
    report_id: str
    report_type: ReportType
    framework: ComplianceFramework
    report_format: ReportFormat
    generated_at: datetime
    generated_by: str
    report_period: Dict[str, datetime]
    summary_metrics: Dict[str, Any]
    detailed_findings: List[Dict[str, Any]]
    recommendations: List[str]
    compliance_gaps: List[Dict[str, Any]]
    remediation_status: Dict[str, Any]
    audit_trail: List[Dict[str, Any]]
    content: str
    metadata: Dict[str, Any] = field(default_factory=dict)

class ComplianceReporter:
    """
    Advanced compliance reporting engine
    
    Generates comprehensive compliance reports with audit trails, metrics,
    and detailed analysis of vulnerability remediation status.
    """
    
    def __init__(self, 
                 db_path: str = "compliance_reports.db",
                 discovery_db_path: str = "../discovery/vulnerability_discovery.db",
                 assessment_db_path: str = "../assessment/risk_assessment.db",
                 remediation_db_path: str = "../remediation/remediation_workflows.db"):
        
        self.db_path = Path(db_path)
        self.discovery_db_path = Path(discovery_db_path)
        self.assessment_db_path = Path(assessment_db_path)
        self.remediation_db_path = Path(remediation_db_path)
        
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        
        # Initialize database
        self._initialize_database()
        
        # Load compliance frameworks and control mappings
        self.frameworks = {}
        self.control_mappings = {}
        self._load_compliance_frameworks()
        
        # Report templates
        self.report_templates = {}
        self._load_report_templates()
        
        # Metrics calculators
        self.metrics_cache = {}
        self.cache_ttl = 1800  # 30 minutes
    
    def _initialize_database(self):
        """Initialize compliance reporting database"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS compliance_reports (
                    report_id TEXT PRIMARY KEY,
                    report_type TEXT NOT NULL,
                    framework TEXT NOT NULL,
                    report_format TEXT NOT NULL,
                    generated_at TEXT NOT NULL,
                    generated_by TEXT,
                    report_period_start TEXT,
                    report_period_end TEXT,
                    summary_metrics TEXT,    -- JSON
                    detailed_findings TEXT,  -- JSON
                    recommendations TEXT,    -- JSON
                    compliance_gaps TEXT,    -- JSON
                    remediation_status TEXT, -- JSON
                    audit_trail TEXT,        -- JSON
                    content TEXT,
                    metadata TEXT,           -- JSON
                    created_at TEXT
                )
            """)
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS compliance_controls (
                    control_id TEXT PRIMARY KEY,
                    framework TEXT NOT NULL,
                    control_name TEXT NOT NULL,
                    description TEXT,
                    implementation_status TEXT,
                    remediation_status TEXT,
                    risk_level TEXT,
                    related_vulnerabilities TEXT, -- JSON
                    evidence TEXT,               -- JSON
                    last_assessed TEXT,
                    next_assessment TEXT,
                    created_at TEXT,
                    updated_at TEXT
                )
            """)
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS compliance_metrics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    framework TEXT NOT NULL,
                    metric_name TEXT NOT NULL,
                    metric_value REAL NOT NULL,
                    metric_type TEXT,
                    calculation_date TEXT NOT NULL,
                    period_start TEXT,
                    period_end TEXT,
                    metadata TEXT,           -- JSON
                    created_at TEXT
                )
            """)
            
            # Create indexes
            conn.execute("CREATE INDEX IF NOT EXISTS idx_reports_type ON compliance_reports(report_type)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_reports_framework ON compliance_reports(framework)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_controls_framework ON compliance_controls(framework)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_metrics_framework ON compliance_metrics(framework)")
    
    def _load_compliance_frameworks(self):
        """Load compliance framework definitions"""
        
        # NIST 800-53 framework
        self.frameworks[ComplianceFramework.NIST_800_53] = {
            'name': 'NIST SP 800-53',
            'description': 'Security and Privacy Controls for Federal Information Systems',
            'controls': {
                'AC-2': 'Account Management',
                'AC-3': 'Access Enforcement', 
                'AC-6': 'Least Privilege',
                'AU-2': 'Audit Events',
                'AU-3': 'Content of Audit Records',
                'AU-12': 'Audit Generation',
                'CA-7': 'Continuous Monitoring',
                'CM-2': 'Baseline Configuration',
                'CM-6': 'Configuration Settings',
                'IA-2': 'Identification and Authentication',
                'IA-5': 'Authenticator Management',
                'RA-5': 'Vulnerability Scanning',
                'SA-11': 'Developer Security Testing',
                'SC-7': 'Boundary Protection',
                'SC-8': 'Transmission Confidentiality',
                'SC-13': 'Cryptographic Protection',
                'SC-28': 'Protection of Information at Rest',
                'SI-2': 'Flaw Remediation',
                'SI-4': 'Information System Monitoring'
            }
        }
        
        # DoD STIG framework
        self.frameworks[ComplianceFramework.DOD_STIG] = {
            'name': 'DoD Security Technical Implementation Guide',
            'description': 'Department of Defense Security Requirements',
            'controls': {
                'APSC-DV-001330': 'Application must protect against SQL injection',
                'APSC-DV-001340': 'Application must protect against XSS',
                'APSC-DV-001350': 'Application must implement proper authentication',
                'APSC-DV-001360': 'Application must enforce authorization',
                'APSC-DV-001370': 'Application must use approved cryptography',
                'RHEL-07-010010': 'Password policy requirements',
                'RHEL-07-020010': 'File permission requirements',
                'RHEL-07-030010': 'Audit logging requirements',
                'RHEL-07-040010': 'Network security requirements'
            }
        }
        
        # CISA KEV framework
        self.frameworks[ComplianceFramework.CISA_KEV] = {
            'name': 'CISA Known Exploited Vulnerabilities',
            'description': 'Critical vulnerabilities with known exploitation',
            'controls': {
                'KEV-001': 'Remediate known exploited vulnerabilities within 15 days',
                'KEV-002': 'Monitor for new KEV additions',
                'KEV-003': 'Maintain KEV remediation tracking'
            }
        }
    
    def _load_report_templates(self):
        """Load report templates"""
        
        # Executive Summary Template
        self.report_templates[ReportType.EXECUTIVE_SUMMARY] = Template("""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Vulnerability Remediation Executive Summary</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 40px; }
                .header { background-color: #f0f0f0; padding: 20px; border-left: 5px solid #007acc; }
                .metric { display: inline-block; margin: 20px; padding: 15px; background-color: #f9f9f9; border-radius: 5px; }
                .metric-value { font-size: 2em; font-weight: bold; color: #007acc; }
                .section { margin: 30px 0; }
                .risk-critical { color: #d32f2f; }
                .risk-high { color: #f57c00; }
                .risk-medium { color: #fbc02d; }
                .risk-low { color: #388e3c; }
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Vulnerability Remediation Executive Summary</h1>
                <p>Report Period: {{ report_period_start }} to {{ report_period_end }}</p>
                <p>Generated: {{ generated_at }}</p>
            </div>
            
            <div class="section">
                <h2>Key Metrics</h2>
                <div class="metric">
                    <div class="metric-value">{{ total_vulnerabilities }}</div>
                    <div>Total Vulnerabilities</div>
                </div>
                <div class="metric">
                    <div class="metric-value">{{ remediated_count }}</div>
                    <div>Remediated</div>
                </div>
                <div class="metric">
                    <div class="metric-value">{{ compliance_percentage }}%</div>
                    <div>Compliance Rate</div>
                </div>
                <div class="metric">
                    <div class="metric-value">{{ avg_remediation_time }}</div>
                    <div>Avg Remediation Time</div>
                </div>
            </div>
            
            <div class="section">
                <h2>Risk Distribution</h2>
                <ul>
                    <li class="risk-critical">Critical: {{ risk_distribution.critical }} vulnerabilities</li>
                    <li class="risk-high">High: {{ risk_distribution.high }} vulnerabilities</li>
                    <li class="risk-medium">Medium: {{ risk_distribution.medium }} vulnerabilities</li>
                    <li class="risk-low">Low: {{ risk_distribution.low }} vulnerabilities</li>
                </ul>
            </div>
            
            <div class="section">
                <h2>Compliance Status</h2>
                {% for framework, status in compliance_status.items() %}
                <h3>{{ framework }}</h3>
                <p>Compliance Rate: {{ status.compliance_rate }}%</p>
                <p>Controls Implemented: {{ status.implemented_controls }}/{{ status.total_controls }}</p>
                {% endfor %}
            </div>
            
            <div class="section">
                <h2>Key Recommendations</h2>
                <ol>
                    {% for recommendation in recommendations %}
                    <li>{{ recommendation }}</li>
                    {% endfor %}
                </ol>
            </div>
        </body>
        </html>
        """)
        
        # Detailed Technical Template
        self.report_templates[ReportType.DETAILED_TECHNICAL] = Template("""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Detailed Technical Vulnerability Report</title>
            <style>
                body { font-family: 'Courier New', monospace; margin: 20px; font-size: 12px; }
                .vulnerability { border: 1px solid #ccc; margin: 10px 0; padding: 15px; }
                .vuln-header { background-color: #f5f5f5; padding: 10px; font-weight: bold; }
                .vuln-details { padding: 10px; }
                .severity-critical { border-left: 5px solid #d32f2f; }
                .severity-high { border-left: 5px solid #f57c00; }
                .severity-medium { border-left: 5px solid #fbc02d; }
                .severity-low { border-left: 5px solid #388e3c; }
                table { width: 100%; border-collapse: collapse; margin: 10px 0; }
                th, td { border: 1px solid #ccc; padding: 8px; text-align: left; }
                th { background-color: #f5f5f5; }
            </style>
        </head>
        <body>
            <h1>Detailed Technical Vulnerability Report</h1>
            <p>Generated: {{ generated_at }}</p>
            <p>Total Vulnerabilities: {{ total_vulnerabilities }}</p>
            
            {% for vuln in vulnerabilities %}
            <div class="vulnerability severity-{{ vuln.severity }}">
                <div class="vuln-header">
                    {{ vuln.title }} ({{ vuln.cve_id or 'No CVE' }})
                </div>
                <div class="vuln-details">
                    <table>
                        <tr><th>Severity</th><td>{{ vuln.severity.title() }}</td></tr>
                        <tr><th>CVSS Score</th><td>{{ vuln.cvss_score }}</td></tr>
                        <tr><th>Risk Level</th><td>{{ vuln.risk_level }}</td></tr>
                        <tr><th>Affected Assets</th><td>{{ vuln.affected_assets | join(', ') }}</td></tr>
                        <tr><th>Discovery Date</th><td>{{ vuln.discovery_date }}</td></tr>
                        <tr><th>Remediation Status</th><td>{{ vuln.remediation_status }}</td></tr>
                        <tr><th>Assigned Team</th><td>{{ vuln.assigned_team or 'Unassigned' }}</td></tr>
                    </table>
                    
                    <h4>Description</h4>
                    <p>{{ vuln.description }}</p>
                    
                    <h4>Remediation Recommendation</h4>
                    <p>{{ vuln.remediation_recommendation }}</p>
                    
                    {% if vuln.compliance_mappings %}
                    <h4>Compliance Mappings</h4>
                    <ul>
                        {% for framework, controls in vuln.compliance_mappings.items() %}
                        <li>{{ framework }}: {{ controls | join(', ') }}</li>
                        {% endfor %}
                    </ul>
                    {% endif %}
                </div>
            </div>
            {% endfor %}
        </body>
        </html>
        """)
    
    async def generate_compliance_report(self,
                                       framework: ComplianceFramework,
                                       report_type: ReportType,
                                       report_format: ReportFormat = ReportFormat.HTML,
                                       period_days: int = 30,
                                       generated_by: str = "system") -> ComplianceReport:
        """Generate a comprehensive compliance report"""
        
        report_id = f"report_{int(datetime.now(timezone.utc).timestamp())}"
        
        try:
            self.logger.info(f"Generating {report_type.value} report for {framework.value}")
            
            # Define report period
            end_date = datetime.now(timezone.utc)
            start_date = end_date - timedelta(days=period_days)
            report_period = {'start': start_date, 'end': end_date}
            
            # Gather data from all databases
            vulnerability_data = await self._gather_vulnerability_data(start_date, end_date)
            assessment_data = await self._gather_assessment_data(start_date, end_date)
            remediation_data = await self._gather_remediation_data(start_date, end_date)
            
            # Calculate summary metrics
            summary_metrics = await self._calculate_summary_metrics(
                vulnerability_data, assessment_data, remediation_data, framework
            )
            
            # Identify detailed findings
            detailed_findings = await self._analyze_detailed_findings(
                vulnerability_data, assessment_data, remediation_data, framework
            )
            
            # Generate recommendations
            recommendations = await self._generate_recommendations(
                summary_metrics, detailed_findings, framework
            )
            
            # Identify compliance gaps
            compliance_gaps = await self._identify_compliance_gaps(
                vulnerability_data, assessment_data, framework
            )
            
            # Get remediation status
            remediation_status = await self._analyze_remediation_status(
                remediation_data, framework
            )
            
            # Generate audit trail
            audit_trail = await self._generate_audit_trail(
                vulnerability_data, remediation_data, start_date, end_date
            )
            
            # Generate report content
            content = await self._generate_report_content(
                report_type, report_format, {
                    'framework': framework,
                    'report_period': report_period,
                    'summary_metrics': summary_metrics,
                    'detailed_findings': detailed_findings,
                    'recommendations': recommendations,
                    'compliance_gaps': compliance_gaps,
                    'remediation_status': remediation_status,
                    'vulnerability_data': vulnerability_data,
                    'assessment_data': assessment_data,
                    'remediation_data': remediation_data
                }
            )
            
            # Create report object
            report = ComplianceReport(
                report_id=report_id,
                report_type=report_type,
                framework=framework,
                report_format=report_format,
                generated_at=datetime.now(timezone.utc),
                generated_by=generated_by,
                report_period=report_period,
                summary_metrics=summary_metrics,
                detailed_findings=detailed_findings,
                recommendations=recommendations,
                compliance_gaps=compliance_gaps,
                remediation_status=remediation_status,
                audit_trail=audit_trail,
                content=content,
                metadata={
                    'period_days': period_days,
                    'data_sources': ['discovery', 'assessment', 'remediation'],
                    'generation_time': datetime.now(timezone.utc).isoformat()
                }
            )
            
            # Save report
            await self._save_report(report)
            
            self.logger.info(f"Generated compliance report {report_id}")
            return report
            
        except Exception as e:
            self.logger.error(f"Failed to generate compliance report: {e}")
            raise
    
    async def _gather_vulnerability_data(self, start_date: datetime, end_date: datetime) -> List[Dict[str, Any]]:
        """Gather vulnerability data from discovery database"""
        
        vulnerabilities = []
        
        try:
            if self.discovery_db_path.exists():
                with sqlite3.connect(self.discovery_db_path) as conn:
                    cursor = conn.execute("""
                        SELECT * FROM enriched_vulnerabilities
                        WHERE discovery_timestamp BETWEEN ? AND ?
                        ORDER BY discovery_timestamp DESC
                    """, (start_date.isoformat(), end_date.isoformat()))
                    
                    for row in cursor.fetchall():
                        vuln_data = {
                            'id': row[0],
                            'base_vulnerability_id': row[1],
                            'discovery_source': row[2],
                            'discovery_timestamp': row[3],
                            'confidence_score': row[4],
                            'threat_intelligence': json.loads(row[5]) if row[5] else {},
                            'exploit_information': json.loads(row[6]) if row[6] else {},
                            'business_context': json.loads(row[7]) if row[7] else {},
                            'correlation_ids': json.loads(row[8]) if row[8] else [],
                            'enrichment_metadata': json.loads(row[9]) if row[9] else {}
                        }
                        vulnerabilities.append(vuln_data)
        
        except Exception as e:
            self.logger.warning(f"Could not gather vulnerability data: {e}")
        
        return vulnerabilities
    
    async def _gather_assessment_data(self, start_date: datetime, end_date: datetime) -> List[Dict[str, Any]]:
        """Gather risk assessment data"""
        
        assessments = []
        
        try:
            if self.assessment_db_path.exists():
                with sqlite3.connect(self.assessment_db_path) as conn:
                    cursor = conn.execute("""
                        SELECT * FROM risk_assessments
                        WHERE assessment_timestamp BETWEEN ? AND ?
                        ORDER BY overall_risk_score DESC
                    """, (start_date.isoformat(), end_date.isoformat()))
                    
                    for row in cursor.fetchall():
                        assessment_data = {
                            'assessment_id': row[0],
                            'vulnerability_id': row[1],
                            'assessment_timestamp': row[2],
                            'risk_level': row[3],
                            'overall_risk_score': row[4],
                            'priority_rank': row[5],
                            'score_components': json.loads(row[6]) if row[6] else {},
                            'asset_context': json.loads(row[7]) if row[7] else None,
                            'threat_context': json.loads(row[8]) if row[8] else None,
                            'remediation_urgency': row[9],
                            'business_justification': row[10],
                            'confidence_level': row[12],
                            'assessment_method': row[13]
                        }
                        assessments.append(assessment_data)
        
        except Exception as e:
            self.logger.warning(f"Could not gather assessment data: {e}")
        
        return assessments
    
    async def _gather_remediation_data(self, start_date: datetime, end_date: datetime) -> List[Dict[str, Any]]:
        """Gather remediation workflow data"""
        
        workflows = []
        
        try:
            if self.remediation_db_path.exists():
                with sqlite3.connect(self.remediation_db_path) as conn:
                    cursor = conn.execute("""
                        SELECT * FROM remediation_workflows
                        WHERE created_at BETWEEN ? AND ?
                        ORDER BY created_at DESC
                    """, (start_date.isoformat(), end_date.isoformat()))
                    
                    for row in cursor.fetchall():
                        workflow_data = {
                            'workflow_id': row[0],
                            'vulnerability_id': row[1],
                            'workflow_name': row[2],
                            'workflow_type': row[3],
                            'status': row[4],
                            'priority': row[5],
                            'created_by': row[6],
                            'assigned_team': row[7],
                            'estimated_completion': row[8],
                            'actual_completion': row[9],
                            'sla_requirements': json.loads(row[10]) if row[10] else {},
                            'business_justification': row[11],
                            'created_at': row[18],
                            'updated_at': row[19]
                        }
                        
                        # Get tasks for this workflow
                        task_cursor = conn.execute("""
                            SELECT * FROM remediation_tasks WHERE workflow_id = ?
                        """, (row[0],))
                        
                        tasks = []
                        for task_row in task_cursor.fetchall():
                            task_data = {
                                'task_id': task_row[0],
                                'task_type': task_row[2],
                                'title': task_row[3],
                                'status': task_row[6],
                                'assigned_to': task_row[7],
                                'created_at': task_row[24],
                                'updated_at': task_row[25]
                            }
                            tasks.append(task_data)
                        
                        workflow_data['tasks'] = tasks
                        workflows.append(workflow_data)
        
        except Exception as e:
            self.logger.warning(f"Could not gather remediation data: {e}")
        
        return workflows
    
    async def _calculate_summary_metrics(self, 
                                       vulnerability_data: List[Dict],
                                       assessment_data: List[Dict],
                                       remediation_data: List[Dict],
                                       framework: ComplianceFramework) -> Dict[str, Any]:
        """Calculate summary metrics for the report"""
        
        # Basic counts
        total_vulnerabilities = len(vulnerability_data)
        total_assessments = len(assessment_data)
        total_workflows = len(remediation_data)
        
        # Risk level distribution
        risk_distribution = {}
        for assessment in assessment_data:
            risk_level = assessment.get('risk_level', 'unknown')
            risk_distribution[risk_level] = risk_distribution.get(risk_level, 0) + 1
        
        # Remediation status
        completed_workflows = len([w for w in remediation_data if w.get('status') == 'completed'])
        remediation_rate = (completed_workflows / total_workflows * 100) if total_workflows > 0 else 0
        
        # Average remediation time
        avg_remediation_time = 0
        completed_with_times = [
            w for w in remediation_data 
            if w.get('status') == 'completed' and w.get('actual_completion') and w.get('created_at')
        ]
        
        if completed_with_times:
            total_time = 0
            for workflow in completed_with_times:
                start = datetime.fromisoformat(workflow['created_at'])
                end = datetime.fromisoformat(workflow['actual_completion'])
                total_time += (end - start).total_seconds() / 3600  # Convert to hours
            
            avg_remediation_time = total_time / len(completed_with_times)
        
        # Framework-specific compliance rate
        compliance_rate = await self._calculate_framework_compliance(
            vulnerability_data, assessment_data, framework
        )
        
        # SLA compliance
        sla_compliant = 0
        sla_total = 0
        for workflow in remediation_data:
            if workflow.get('sla_requirements') and workflow.get('actual_completion'):
                sla_total += 1
                sla_hours = workflow['sla_requirements'].get('resolution_time', 72)
                start = datetime.fromisoformat(workflow['created_at'])
                end = datetime.fromisoformat(workflow['actual_completion'])
                actual_hours = (end - start).total_seconds() / 3600
                
                if actual_hours <= sla_hours:
                    sla_compliant += 1
        
        sla_compliance_rate = (sla_compliant / sla_total * 100) if sla_total > 0 else 0
        
        return {
            'total_vulnerabilities': total_vulnerabilities,
            'total_assessments': total_assessments,
            'total_workflows': total_workflows,
            'risk_distribution': risk_distribution,
            'completed_workflows': completed_workflows,
            'remediation_rate': round(remediation_rate, 2),
            'average_remediation_time_hours': round(avg_remediation_time, 2),
            'compliance_rate': round(compliance_rate, 2),
            'sla_compliance_rate': round(sla_compliance_rate, 2),
            'critical_vulnerabilities': risk_distribution.get('critical', 0),
            'high_vulnerabilities': risk_distribution.get('high', 0),
            'exploited_vulnerabilities': len([
                v for v in vulnerability_data 
                if v.get('exploit_information', {}).get('exploit_available', False)
            ])
        }
    
    async def _calculate_framework_compliance(self, 
                                            vulnerability_data: List[Dict],
                                            assessment_data: List[Dict],
                                            framework: ComplianceFramework) -> float:
        """Calculate compliance rate for specific framework"""
        
        if framework not in self.frameworks:
            return 0.0
        
        framework_controls = self.frameworks[framework]['controls']
        total_controls = len(framework_controls)
        
        # Simplified compliance calculation
        # In reality, this would map vulnerabilities to specific controls
        remediated_count = len([a for a in assessment_data if a.get('remediation_urgency') == 'completed'])
        total_assessed = len(assessment_data)
        
        if total_assessed == 0:
            return 0.0
        
        return (remediated_count / total_assessed) * 100
    
    async def _analyze_detailed_findings(self, 
                                       vulnerability_data: List[Dict],
                                       assessment_data: List[Dict],
                                       remediation_data: List[Dict],
                                       framework: ComplianceFramework) -> List[Dict[str, Any]]:
        """Analyze detailed findings for the report"""
        
        findings = []
        
        # Top vulnerabilities by risk score
        top_vulnerabilities = sorted(
            assessment_data, 
            key=lambda x: x.get('overall_risk_score', 0), 
            reverse=True
        )[:10]
        
        for vuln in top_vulnerabilities:
            finding = {
                'type': 'high_risk_vulnerability',
                'vulnerability_id': vuln.get('vulnerability_id'),
                'risk_score': vuln.get('overall_risk_score'),
                'risk_level': vuln.get('risk_level'),
                'business_justification': vuln.get('business_justification'),
                'remediation_urgency': vuln.get('remediation_urgency'),
                'assessment_method': vuln.get('assessment_method')
            }
            findings.append(finding)
        
        # Overdue remediation workflows
        overdue_workflows = []
        for workflow in remediation_data:
            if (workflow.get('status') not in ['completed', 'cancelled'] and 
                workflow.get('estimated_completion')):
                
                estimated = datetime.fromisoformat(workflow['estimated_completion'])
                if estimated < datetime.now(timezone.utc):
                    overdue_workflows.append(workflow)
        
        if overdue_workflows:
            findings.append({
                'type': 'overdue_remediation',
                'count': len(overdue_workflows),
                'workflows': [w['workflow_id'] for w in overdue_workflows]
            })
        
        # Exploited vulnerabilities
        exploited_vulns = [
            v for v in vulnerability_data 
            if v.get('exploit_information', {}).get('exploit_available', False)
        ]
        
        if exploited_vulns:
            findings.append({
                'type': 'exploited_vulnerabilities',
                'count': len(exploited_vulns),
                'vulnerability_ids': [v['id'] for v in exploited_vulns]
            })
        
        return findings
    
    async def _generate_recommendations(self, 
                                      summary_metrics: Dict[str, Any],
                                      detailed_findings: List[Dict[str, Any]],
                                      framework: ComplianceFramework) -> List[str]:
        """Generate recommendations based on analysis"""
        
        recommendations = []
        
        # Low remediation rate
        if summary_metrics.get('remediation_rate', 0) < 80:
            recommendations.append(
                "Improve remediation processes to achieve target 80% completion rate. "
                "Consider automation and additional resources."
            )
        
        # High critical vulnerabilities
        if summary_metrics.get('critical_vulnerabilities', 0) > 10:
            recommendations.append(
                "Prioritize immediate remediation of critical vulnerabilities. "
                "Implement emergency response procedures for critical findings."
            )
        
        # Low SLA compliance
        if summary_metrics.get('sla_compliance_rate', 0) < 90:
            recommendations.append(
                "Review and optimize SLA compliance processes. "
                "Consider adjusting SLA targets or improving workflow efficiency."
            )
        
        # Framework-specific recommendations
        if framework == ComplianceFramework.CISA_KEV:
            exploited_count = summary_metrics.get('exploited_vulnerabilities', 0)
            if exploited_count > 0:
                recommendations.append(
                    f"Immediately address {exploited_count} known exploited vulnerabilities "
                    "per CISA KEV requirements."
                )
        
        # Long remediation times
        avg_time = summary_metrics.get('average_remediation_time_hours', 0)
        if avg_time > 168:  # More than 1 week
            recommendations.append(
                f"Average remediation time of {avg_time:.1f} hours exceeds target. "
                "Streamline remediation workflows and improve automation."
            )
        
        return recommendations
    
    async def _identify_compliance_gaps(self, 
                                      vulnerability_data: List[Dict],
                                      assessment_data: List[Dict],
                                      framework: ComplianceFramework) -> List[Dict[str, Any]]:
        """Identify compliance gaps"""
        
        gaps = []
        
        # Missing assessments
        vuln_ids_with_assessments = set(a.get('vulnerability_id') for a in assessment_data)
        vuln_ids_discovered = set(v.get('base_vulnerability_id') for v in vulnerability_data)
        
        missing_assessments = vuln_ids_discovered - vuln_ids_with_assessments
        if missing_assessments:
            gaps.append({
                'type': 'missing_risk_assessments',
                'count': len(missing_assessments),
                'description': f'{len(missing_assessments)} vulnerabilities lack risk assessments'
            })
        
        # High-risk vulnerabilities without remediation
        high_risk_unremediated = [
            a for a in assessment_data 
            if a.get('risk_level') in ['critical', 'high'] and 
               a.get('remediation_urgency') not in ['completed', 'remediated']
        ]
        
        if high_risk_unremediated:
            gaps.append({
                'type': 'high_risk_unremediated',
                'count': len(high_risk_unremediated),
                'description': f'{len(high_risk_unremediated)} high/critical risk vulnerabilities lack remediation'
            })
        
        return gaps
    
    async def _analyze_remediation_status(self, 
                                        remediation_data: List[Dict],
                                        framework: ComplianceFramework) -> Dict[str, Any]:
        """Analyze remediation status"""
        
        status_counts = {}
        for workflow in remediation_data:
            status = workflow.get('status', 'unknown')
            status_counts[status] = status_counts.get(status, 0) + 1
        
        # Task completion analysis
        total_tasks = 0
        completed_tasks = 0
        
        for workflow in remediation_data:
            for task in workflow.get('tasks', []):
                total_tasks += 1
                if task.get('status') == 'completed':
                    completed_tasks += 1
        
        task_completion_rate = (completed_tasks / total_tasks * 100) if total_tasks > 0 else 0
        
        return {
            'workflow_status_distribution': status_counts,
            'total_tasks': total_tasks,
            'completed_tasks': completed_tasks,
            'task_completion_rate': round(task_completion_rate, 2),
            'active_workflows': status_counts.get('active', 0) + status_counts.get('in_progress', 0)
        }
    
    async def _generate_audit_trail(self, 
                                  vulnerability_data: List[Dict],
                                  remediation_data: List[Dict],
                                  start_date: datetime,
                                  end_date: datetime) -> List[Dict[str, Any]]:
        """Generate audit trail for the report period"""
        
        audit_events = []
        
        # Vulnerability discovery events
        for vuln in vulnerability_data:
            audit_events.append({
                'timestamp': vuln.get('discovery_timestamp'),
                'event_type': 'vulnerability_discovered',
                'vulnerability_id': vuln.get('base_vulnerability_id'),
                'source': vuln.get('discovery_source'),
                'details': {
                    'confidence_score': vuln.get('confidence_score'),
                    'threat_intelligence': bool(vuln.get('threat_intelligence'))
                }
            })
        
        # Workflow events
        for workflow in remediation_data:
            audit_events.append({
                'timestamp': workflow.get('created_at'),
                'event_type': 'workflow_created',
                'workflow_id': workflow.get('workflow_id'),
                'vulnerability_id': workflow.get('vulnerability_id'),
                'details': {
                    'priority': workflow.get('priority'),
                    'assigned_team': workflow.get('assigned_team')
                }
            })
            
            if workflow.get('actual_completion'):
                audit_events.append({
                    'timestamp': workflow.get('actual_completion'),
                    'event_type': 'workflow_completed',
                    'workflow_id': workflow.get('workflow_id'),
                    'details': {
                        'status': workflow.get('status')
                    }
                })
        
        # Sort by timestamp
        audit_events.sort(key=lambda x: x.get('timestamp', ''))
        
        return audit_events
    
    async def _generate_report_content(self, 
                                     report_type: ReportType,
                                     report_format: ReportFormat,
                                     data: Dict[str, Any]) -> str:
        """Generate report content based on type and format"""
        
        if report_format == ReportFormat.JSON:
            return json.dumps(data, indent=2, default=str)
        
        elif report_format == ReportFormat.HTML:
            if report_type in self.report_templates:
                template = self.report_templates[report_type]
                
                # Prepare template data
                template_data = {
                    'generated_at': datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC'),
                    'report_period_start': data['report_period']['start'].strftime('%Y-%m-%d'),
                    'report_period_end': data['report_period']['end'].strftime('%Y-%m-%d'),
                    'total_vulnerabilities': data['summary_metrics'].get('total_vulnerabilities', 0),
                    'remediated_count': data['summary_metrics'].get('completed_workflows', 0),
                    'compliance_percentage': data['summary_metrics'].get('compliance_rate', 0),
                    'avg_remediation_time': f"{data['summary_metrics'].get('average_remediation_time_hours', 0):.1f} hours",
                    'risk_distribution': data['summary_metrics'].get('risk_distribution', {}),
                    'compliance_status': {
                        data['framework'].value: {
                            'compliance_rate': data['summary_metrics'].get('compliance_rate', 0),
                            'implemented_controls': 'N/A',
                            'total_controls': 'N/A'
                        }
                    },
                    'recommendations': data.get('recommendations', []),
                    'vulnerabilities': []
                }
                
                # Add detailed vulnerability data for technical reports
                if report_type == ReportType.DETAILED_TECHNICAL:
                    for assessment in data.get('assessment_data', [])[:20]:  # Limit to top 20
                        vuln_detail = {
                            'title': f"Vulnerability {assessment.get('vulnerability_id', 'Unknown')[:8]}",
                            'cve_id': None,  # Would need to correlate with vulnerability data
                            'severity': assessment.get('risk_level', 'unknown'),
                            'cvss_score': assessment.get('overall_risk_score', 0),
                            'risk_level': assessment.get('risk_level', 'unknown'),
                            'affected_assets': [],  # Would need asset context
                            'discovery_date': assessment.get('assessment_timestamp', ''),
                            'remediation_status': assessment.get('remediation_urgency', 'unknown'),
                            'assigned_team': 'N/A',
                            'description': assessment.get('business_justification', ''),
                            'remediation_recommendation': 'See detailed remediation workflow',
                            'compliance_mappings': {}
                        }
                        template_data['vulnerabilities'].append(vuln_detail)
                
                return template.render(**template_data)
            
            else:
                # Fallback HTML template
                return f"""
                <html>
                <head><title>Compliance Report</title></head>
                <body>
                    <h1>{report_type.value.replace('_', ' ').title()} Report</h1>
                    <p>Generated: {datetime.now(timezone.utc).isoformat()}</p>
                    <pre>{json.dumps(data, indent=2, default=str)}</pre>
                </body>
                </html>
                """
        
        else:
            # Fallback to JSON
            return json.dumps(data, indent=2, default=str)
    
    async def _save_report(self, report: ComplianceReport):
        """Save report to database"""
        
        with sqlite3.connect(self.db_path) as conn:
            now = datetime.now(timezone.utc).isoformat()
            
            conn.execute("""
                INSERT OR REPLACE INTO compliance_reports (
                    report_id, report_type, framework, report_format, generated_at,
                    generated_by, report_period_start, report_period_end,
                    summary_metrics, detailed_findings, recommendations,
                    compliance_gaps, remediation_status, audit_trail,
                    content, metadata, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                report.report_id,
                report.report_type.value,
                report.framework.value,
                report.report_format.value,
                report.generated_at.isoformat(),
                report.generated_by,
                report.report_period['start'].isoformat(),
                report.report_period['end'].isoformat(),
                json.dumps(report.summary_metrics),
                json.dumps(report.detailed_findings),
                json.dumps(report.recommendations),
                json.dumps(report.compliance_gaps),
                json.dumps(report.remediation_status),
                json.dumps(report.audit_trail),
                report.content,
                json.dumps(report.metadata),
                now
            ))
    
    async def get_compliance_dashboard_data(self, 
                                          framework: ComplianceFramework,
                                          days: int = 30) -> Dict[str, Any]:
        """Get compliance dashboard data"""
        
        end_date = datetime.now(timezone.utc)
        start_date = end_date - timedelta(days=days)
        
        # Gather all data
        vulnerability_data = await self._gather_vulnerability_data(start_date, end_date)
        assessment_data = await self._gather_assessment_data(start_date, end_date)
        remediation_data = await self._gather_remediation_data(start_date, end_date)
        
        # Calculate metrics
        summary_metrics = await self._calculate_summary_metrics(
            vulnerability_data, assessment_data, remediation_data, framework
        )
        
        # Get historical compliance trends
        compliance_trends = await self._get_compliance_trends(framework, days)
        
        return {
            'framework': framework.value,
            'period_days': days,
            'summary_metrics': summary_metrics,
            'compliance_trends': compliance_trends,
            'recent_activities': {
                'new_vulnerabilities': len(vulnerability_data),
                'completed_assessments': len(assessment_data),  
                'active_workflows': len([w for w in remediation_data if w.get('status') == 'active'])
            }
        }
    
    async def _get_compliance_trends(self, framework: ComplianceFramework, days: int) -> List[Dict[str, Any]]:
        """Get compliance trends over time"""
        
        trends = []
        
        # Get historical metrics from database
        with sqlite3.connect(self.db_path) as conn:
            since_date = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
            
            cursor = conn.execute("""
                SELECT metric_name, metric_value, calculation_date
                FROM compliance_metrics
                WHERE framework = ? AND calculation_date > ?
                ORDER BY calculation_date
            """, (framework.value, since_date))
            
            metrics_by_date = {}
            for row in cursor.fetchall():
                date_key = row[2][:10]  # Extract date part
                if date_key not in metrics_by_date:
                    metrics_by_date[date_key] = {}
                metrics_by_date[date_key][row[0]] = row[1]
            
            for date, metrics in metrics_by_date.items():
                trends.append({
                    'date': date,
                    'metrics': metrics
                })
        
        return trends
    
    async def save_compliance_metrics(self, 
                                    framework: ComplianceFramework,
                                    metrics: Dict[str, float],
                                    period_start: Optional[datetime] = None,
                                    period_end: Optional[datetime] = None):
        """Save compliance metrics to database for trend analysis"""
        
        with sqlite3.connect(self.db_path) as conn:
            now = datetime.now(timezone.utc)
            
            for metric_name, metric_value in metrics.items():
                conn.execute("""
                    INSERT INTO compliance_metrics (
                        framework, metric_name, metric_value, metric_type,
                        calculation_date, period_start, period_end, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    framework.value,
                    metric_name,
                    metric_value,
                    'calculated',
                    now.isoformat(),
                    period_start.isoformat() if period_start else None,
                    period_end.isoformat() if period_end else None,
                    now.isoformat()
                ))
    
    async def get_available_reports(self, 
                                  framework: Optional[ComplianceFramework] = None,
                                  limit: int = 50) -> List[Dict[str, Any]]:
        """Get list of available reports"""
        
        with sqlite3.connect(self.db_path) as conn:
            if framework:
                cursor = conn.execute("""
                    SELECT report_id, report_type, framework, generated_at, generated_by
                    FROM compliance_reports
                    WHERE framework = ?
                    ORDER BY generated_at DESC
                    LIMIT ?
                """, (framework.value, limit))
            else:
                cursor = conn.execute("""
                    SELECT report_id, report_type, framework, generated_at, generated_by
                    FROM compliance_reports
                    ORDER BY generated_at DESC
                    LIMIT ?
                """, (limit,))
            
            reports = []
            for row in cursor.fetchall():
                reports.append({
                    'report_id': row[0],
                    'report_type': row[1],
                    'framework': row[2],
                    'generated_at': row[3],
                    'generated_by': row[4]
                })
            
            return reports
    
    async def get_report_content(self, report_id: str) -> Optional[str]:
        """Get report content by ID"""
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("""
                SELECT content FROM compliance_reports WHERE report_id = ?
            """, (report_id,))
            
            row = cursor.fetchone()
            return row[0] if row else None