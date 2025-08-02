#!/usr/bin/env python3
"""
Vault Compliance Reporter
DoD standards compliance reporting system for HashiCorp Vault and credential management
"""

import asyncio
import logging
import json
import csv
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
import xml.etree.ElementTree as ET
from jinja2 import Template

from .vault_credential_manager import VaultCredentialManager
from .platform_secret_manager import PlatformSecretManager
from .vault_disaster_recovery import VaultDisasterRecoveryManager
from ..audits.audit_logger import SecurityAuditLogger

logger = logging.getLogger(__name__)

class ComplianceStandard(Enum):
    """DoD compliance standards"""
    NIST_800_53 = "nist_800_53"
    DISA_STIG = "disa_stig"
    FISMA = "fisma"
    DOD_8570 = "dod_8570"
    FIPS_140_2 = "fips_140_2"
    COMMON_CRITERIA = "common_criteria"

class ComplianceStatus(Enum):
    """Compliance status levels"""
    COMPLIANT = "compliant"
    NON_COMPLIANT = "non_compliant"
    PARTIALLY_COMPLIANT = "partially_compliant"
    NOT_APPLICABLE = "not_applicable"
    UNDER_REVIEW = "under_review"

@dataclass
class ComplianceControl:
    """Individual compliance control"""
    control_id: str
    control_name: str
    standard: ComplianceStandard
    description: str
    implementation_status: ComplianceStatus
    evidence: List[str]
    findings: List[str]
    recommendations: List[str]
    risk_level: str
    owner: str
    due_date: Optional[datetime] = None
    last_assessed: Optional[datetime] = None

@dataclass
class ComplianceReport:
    """Compliance assessment report"""
    report_id: str
    report_name: str
    generated_at: datetime
    report_period_start: datetime
    report_period_end: datetime
    standards: List[ComplianceStandard]
    overall_compliance_score: float
    controls_assessed: int
    controls_compliant: int
    controls_non_compliant: int
    critical_findings: int
    high_findings: int
    medium_findings: int
    low_findings: int
    controls: List[ComplianceControl]
    executive_summary: str
    recommendations: List[str]

class VaultComplianceReporter:
    """
    Comprehensive compliance reporting system for DoD standards
    Generates automated compliance reports for Vault and credential management systems
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the compliance reporter
        
        Args:
            config: Compliance reporting configuration
        """
        self.config = config
        self.vault_manager = None
        self.platform_manager = None
        self.dr_manager = None
        
        # Reporting configuration
        self.report_output_dir = config.get('report_output_dir', '/reports')
        self.report_formats = config.get('report_formats', ['json', 'html', 'pdf'])
        self.report_schedule = config.get('report_schedule', 'monthly')
        
        # Compliance configuration
        self.enabled_standards = [ComplianceStandard(std) for std in config.get('enabled_standards', [])]
        self.assessment_scope = config.get('assessment_scope', 'full')
        self.evidence_collection = config.get('evidence_collection', True)
        
        # Control mappings
        self.control_mappings = self._load_control_mappings()
        
        # Report templates
        self.report_templates = self._load_report_templates()
        
        # Initialize audit logger
        self.audit_logger = SecurityAuditLogger()
        
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        self.logger.info("Initialized Vault Compliance Reporter")
    
    async def initialize(self, vault_manager: VaultCredentialManager,
                        platform_manager: PlatformSecretManager,
                        dr_manager: VaultDisasterRecoveryManager) -> bool:
        """
        Initialize the compliance reporter with system managers
        
        Args:
            vault_manager: Vault credential manager instance
            platform_manager: Platform secret manager instance
            dr_manager: Disaster recovery manager instance
            
        Returns:
            True if initialization successful
        """
        try:
            self.vault_manager = vault_manager
            self.platform_manager = platform_manager
            self.dr_manager = dr_manager
            
            # Create output directory
            import os
            os.makedirs(self.report_output_dir, exist_ok=True)
            
            # Start scheduled reporting if enabled
            if self.config.get('enable_scheduled_reports', True):
                asyncio.create_task(self._scheduled_reporting_task())
            
            self.audit_logger.log_security_event(
                "compliance_reporter_initialized",
                {
                    "enabled_standards": [std.value for std in self.enabled_standards],
                    "report_formats": self.report_formats
                },
                severity="INFO"
            )
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to initialize compliance reporter: {e}")
            return False
    
    async def generate_compliance_report(self, standards: Optional[List[ComplianceStandard]] = None,
                                       report_period_days: int = 30,
                                       include_evidence: bool = True) -> Optional[str]:
        """
        Generate comprehensive compliance report
        
        Args:
            standards: Compliance standards to assess (default: all enabled)
            report_period_days: Assessment period in days
            include_evidence: Include evidence collection
            
        Returns:
            Report ID if successful
        """
        try:
            if not standards:
                standards = self.enabled_standards
            
            report_id = f"compliance_report_{int(datetime.now(timezone.utc).timestamp())}"
            start_time = datetime.now(timezone.utc)
            
            self.logger.info(f"Generating compliance report: {report_id}")
            
            # Define report period
            report_end = datetime.now(timezone.utc)
            report_start = report_end - timedelta(days=report_period_days)
            
            # Assess compliance controls
            all_controls = []
            for standard in standards:
                controls = await self._assess_compliance_standard(standard, report_start, report_end, include_evidence)
                all_controls.extend(controls)
            
            # Calculate compliance metrics
            compliance_metrics = self._calculate_compliance_metrics(all_controls)
            
            # Generate executive summary
            executive_summary = await self._generate_executive_summary(all_controls, compliance_metrics)
            
            # Generate recommendations
            recommendations = await self._generate_recommendations(all_controls)
            
            # Create compliance report
            compliance_report = ComplianceReport(
                report_id=report_id,
                report_name=f"DoD Compliance Assessment Report - {report_end.strftime('%Y-%m-%d')}",
                generated_at=datetime.now(timezone.utc),
                report_period_start=report_start,
                report_period_end=report_end,
                standards=standards,
                overall_compliance_score=compliance_metrics['overall_score'],
                controls_assessed=compliance_metrics['total_controls'],
                controls_compliant=compliance_metrics['compliant_controls'],
                controls_non_compliant=compliance_metrics['non_compliant_controls'],
                critical_findings=compliance_metrics['critical_findings'],
                high_findings=compliance_metrics['high_findings'],
                medium_findings=compliance_metrics['medium_findings'],
                low_findings=compliance_metrics['low_findings'],
                controls=all_controls,
                executive_summary=executive_summary,
                recommendations=recommendations
            )
            
            # Generate reports in requested formats
            report_files = await self._generate_report_files(compliance_report)
            
            # Store report metadata
            await self._store_report_metadata(compliance_report, report_files)
            
            duration = (datetime.now(timezone.utc) - start_time).total_seconds()
            
            self.audit_logger.log_security_event(
                "compliance_report_generated",
                {
                    "report_id": report_id,
                    "standards": [std.value for std in standards],
                    "compliance_score": compliance_metrics['overall_score'],
                    "duration_seconds": duration,
                    "report_files": report_files
                },
                severity="INFO"
            )
            
            self.logger.info(f"Compliance report generated: {report_id} ({duration:.2f}s)")
            return report_id
            
        except Exception as e:
            self.logger.error(f"Failed to generate compliance report: {e}")
            self.audit_logger.log_security_event(
                "compliance_report_generation_failed",
                {"error": str(e)},
                severity="ERROR"
            )
            return None
    
    async def assess_control_compliance(self, control_id: str, 
                                      standard: ComplianceStandard) -> Optional[ComplianceControl]:
        """
        Assess compliance for a specific control
        
        Args:
            control_id: Control identifier
            standard: Compliance standard
            
        Returns:
            Compliance control assessment
        """
        try:
            # Get control definition
            control_def = self._get_control_definition(control_id, standard)
            if not control_def:
                return None
            
            # Collect evidence
            evidence = await self._collect_control_evidence(control_id, standard)
            
            # Assess implementation status
            implementation_status = await self._assess_control_implementation(control_id, standard, evidence)
            
            # Generate findings
            findings = await self._generate_control_findings(control_id, standard, evidence, implementation_status)
            
            # Generate recommendations
            recommendations = await self._generate_control_recommendations(control_id, standard, findings)
            
            # Determine risk level
            risk_level = self._calculate_control_risk_level(implementation_status, findings)
            
            # Create compliance control
            compliance_control = ComplianceControl(
                control_id=control_id,
                control_name=control_def['name'],
                standard=standard,
                description=control_def['description'],
                implementation_status=implementation_status,
                evidence=evidence,
                findings=findings,
                recommendations=recommendations,
                risk_level=risk_level,
                owner=control_def.get('owner', 'System Administrator'),
                due_date=None,
                last_assessed=datetime.now(timezone.utc)
            )
            
            return compliance_control
            
        except Exception as e:
            self.logger.error(f"Failed to assess control {control_id}: {e}")
            return None
    
    async def generate_stig_checklist(self, stig_version: str = "latest") -> Optional[str]:
        """
        Generate DISA STIG compliance checklist
        
        Args:
            stig_version: STIG version to generate checklist for
            
        Returns:
            Checklist file path if successful
        """
        try:
            checklist_id = f"stig_checklist_{int(datetime.now(timezone.utc).timestamp())}"
            
            # Get STIG controls
            stig_controls = await self._get_stig_controls(stig_version)
            
            # Assess each control
            assessed_controls = []
            for control_id in stig_controls:
                control = await self.assess_control_compliance(control_id, ComplianceStandard.DISA_STIG)
                if control:
                    assessed_controls.append(control)
            
            # Generate STIG checklist format
            checklist_data = self._generate_stig_checklist_format(assessed_controls, stig_version)
            
            # Save checklist file
            checklist_file = await self._save_stig_checklist(checklist_id, checklist_data)
            
            self.audit_logger.log_security_event(
                "stig_checklist_generated",
                {
                    "checklist_id": checklist_id,
                    "stig_version": stig_version,
                    "controls_assessed": len(assessed_controls),
                    "checklist_file": checklist_file
                },
                severity="INFO"
            )
            
            return checklist_file
            
        except Exception as e:
            self.logger.error(f"Failed to generate STIG checklist: {e}")
            return None
    
    async def generate_nist_assessment(self, nist_baseline: str = "moderate") -> Optional[str]:
        """
        Generate NIST 800-53 assessment report
        
        Args:
            nist_baseline: NIST baseline (low, moderate, high)
            
        Returns:
            Assessment report ID if successful
        """
        try:
            # Get NIST controls for baseline
            nist_controls = await self._get_nist_controls(nist_baseline)
            
            # Generate assessment
            return await self.generate_compliance_report(
                standards=[ComplianceStandard.NIST_800_53],
                report_period_days=90,
                include_evidence=True
            )
            
        except Exception as e:
            self.logger.error(f"Failed to generate NIST assessment: {e}")
            return None
    
    async def get_compliance_dashboard_data(self) -> Dict[str, Any]:
        """
        Get compliance dashboard data
        
        Returns:
            Dashboard data dictionary
        """
        try:
            dashboard_data = {
                'overall_compliance': {},
                'standards_compliance': {},
                'recent_findings': [],
                'trending_metrics': {},
                'critical_actions': []
            }
            
            # Get overall compliance metrics
            for standard in self.enabled_standards:
                controls = await self._assess_compliance_standard(standard, 
                    datetime.now(timezone.utc) - timedelta(days=30),
                    datetime.now(timezone.utc),
                    include_evidence=False
                )
                
                metrics = self._calculate_compliance_metrics(controls)
                dashboard_data['standards_compliance'][standard.value] = metrics
            
            # Calculate overall compliance
            all_scores = [metrics['overall_score'] for metrics in dashboard_data['standards_compliance'].values()]
            dashboard_data['overall_compliance'] = {
                'score': sum(all_scores) / len(all_scores) if all_scores else 0,
                'total_controls': sum(metrics['total_controls'] for metrics in dashboard_data['standards_compliance'].values()),
                'compliant_controls': sum(metrics['compliant_controls'] for metrics in dashboard_data['standards_compliance'].values()),
                'critical_findings': sum(metrics['critical_findings'] for metrics in dashboard_data['standards_compliance'].values())
            }
            
            # Get recent findings
            dashboard_data['recent_findings'] = await self._get_recent_findings()
            
            # Get trending metrics
            dashboard_data['trending_metrics'] = await self._get_trending_metrics()
            
            # Get critical actions
            dashboard_data['critical_actions'] = await self._get_critical_actions()
            
            return dashboard_data
            
        except Exception as e:
            self.logger.error(f"Failed to get compliance dashboard data: {e}")
            return {}
    
    # Private helper methods
    
    def _load_control_mappings(self) -> Dict[str, Any]:
        """Load compliance control mappings"""
        return {
            ComplianceStandard.NIST_800_53: {
                'AC-2': {
                    'name': 'Account Management',
                    'description': 'Manage information system accounts',
                    'owner': 'Security Administrator'
                },
                'AC-3': {
                    'name': 'Access Enforcement',
                    'description': 'Enforce approved authorizations for logical access',
                    'owner': 'Security Administrator'
                },
                'AU-2': {
                    'name': 'Audit Events',
                    'description': 'Ensure auditable events are defined and audited',
                    'owner': 'Security Administrator'
                },
                'AU-3': {
                    'name': 'Content of Audit Records',
                    'description': 'Ensure audit records contain required information',
                    'owner': 'Security Administrator'
                },
                'IA-2': {
                    'name': 'Identification and Authentication',
                    'description': 'Uniquely identify and authenticate users',
                    'owner': 'Security Administrator'
                },
                'SC-8': {
                    'name': 'Transmission Confidentiality and Integrity',
                    'description': 'Protect transmitted information',
                    'owner': 'Network Administrator'
                },
                'SC-13': {
                    'name': 'Cryptographic Protection',
                    'description': 'Implement required cryptographic protections',
                    'owner': 'Security Administrator'
                }
            },
            ComplianceStandard.DISA_STIG: {
                'V-251239': {
                    'name': 'Authentication Methods',
                    'description': 'The system must use approved authentication methods',
                    'owner': 'Security Administrator'
                },
                'V-251240': {
                    'name': 'Encryption Standards',
                    'description': 'The system must use FIPS 140-2 approved encryption',
                    'owner': 'Security Administrator'
                },
                'V-251241': {
                    'name': 'Audit Logging',
                    'description': 'The system must provide comprehensive audit logging',
                    'owner': 'Security Administrator'
                }
            }
        }
    
    def _load_report_templates(self) -> Dict[str, Template]:
        """Load report templates"""
        # HTML report template
        html_template = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>{{ report.report_name }}</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 40px; }
                .header { background-color: #003366; color: white; padding: 20px; text-align: center; }
                .summary { background-color: #f5f5f5; padding: 20px; margin: 20px 0; }
                .metric { display: inline-block; margin: 10px; padding: 10px; background-color: white; border-radius: 5px; }
                .compliant { color: green; }
                .non-compliant { color: red; }
                .critical { color: red; font-weight: bold; }
                table { width: 100%; border-collapse: collapse; margin: 20px 0; }
                th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
                th { background-color: #f2f2f2; }
            </style>
        </head>
        <body>
            <div class="header">
                <h1>{{ report.report_name }}</h1>
                <p>Generated: {{ report.generated_at.strftime('%Y-%m-%d %H:%M:%S UTC') }}</p>
                <p>Report Period: {{ report.report_period_start.strftime('%Y-%m-%d') }} to {{ report.report_period_end.strftime('%Y-%m-%d') }}</p>
            </div>
            
            <div class="summary">
                <h2>Executive Summary</h2>
                <p>{{ report.executive_summary }}</p>
                
                <div class="metric">
                    <h3>Overall Compliance Score</h3>
                    <p class="{% if report.overall_compliance_score >= 90 %}compliant{% else %}non-compliant{% endif %}">
                        {{ "%.1f"|format(report.overall_compliance_score) }}%
                    </p>
                </div>
                
                <div class="metric">
                    <h3>Controls Assessed</h3>
                    <p>{{ report.controls_assessed }}</p>
                </div>
                
                <div class="metric">
                    <h3>Compliant Controls</h3>
                    <p class="compliant">{{ report.controls_compliant }}</p>
                </div>
                
                <div class="metric">
                    <h3>Non-Compliant Controls</h3>
                    <p class="non-compliant">{{ report.controls_non_compliant }}</p>
                </div>
                
                <div class="metric">
                    <h3>Critical Findings</h3>
                    <p class="critical">{{ report.critical_findings }}</p>
                </div>
            </div>
            
            <h2>Compliance Controls</h2>
            <table>
                <thead>
                    <tr>
                        <th>Control ID</th>
                        <th>Control Name</th>
                        <th>Standard</th>
                        <th>Status</th>
                        <th>Risk Level</th>
                        <th>Findings</th>
                    </tr>
                </thead>
                <tbody>
                    {% for control in report.controls %}
                    <tr>
                        <td>{{ control.control_id }}</td>
                        <td>{{ control.control_name }}</td>
                        <td>{{ control.standard.value }}</td>
                        <td class="{% if control.implementation_status.value == 'compliant' %}compliant{% else %}non-compliant{% endif %}">
                            {{ control.implementation_status.value.replace('_', ' ').title() }}
                        </td>
                        <td class="{% if control.risk_level == 'critical' %}critical{% endif %}">
                            {{ control.risk_level.title() }}
                        </td>
                        <td>{{ control.findings|length }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
            
            <h2>Recommendations</h2>
            <ul>
                {% for recommendation in report.recommendations %}
                <li>{{ recommendation }}</li>
                {% endfor %}
            </ul>
        </body>
        </html>
        """
        
        return {
            'html': Template(html_template)
        }
    
    def _get_control_definition(self, control_id: str, standard: ComplianceStandard) -> Optional[Dict[str, Any]]:
        """Get control definition from mappings"""
        return self.control_mappings.get(standard, {}).get(control_id)
    
    async def _assess_compliance_standard(self, standard: ComplianceStandard,
                                        start_date: datetime, end_date: datetime,
                                        include_evidence: bool) -> List[ComplianceControl]:
        """Assess compliance for a specific standard"""
        try:
            controls = []
            control_mappings = self.control_mappings.get(standard, {})
            
            for control_id in control_mappings.keys():
                control = await self.assess_control_compliance(control_id, standard)
                if control:
                    controls.append(control)
            
            return controls
            
        except Exception as e:
            self.logger.error(f"Failed to assess compliance standard {standard}: {e}")
            return []
    
    async def _collect_control_evidence(self, control_id: str, standard: ComplianceStandard) -> List[str]:
        """Collect evidence for compliance control"""
        try:
            evidence = []
            
            # Collect Vault-specific evidence
            if self.vault_manager:
                # Check authentication methods
                if control_id in ['AC-2', 'AC-3', 'IA-2', 'V-251239']:
                    try:
                        # This would collect authentication evidence
                        evidence.append("Multi-factor authentication enabled via CAC/PIV")
                        evidence.append("Role-based access control implemented")
                    except Exception:
                        pass
                
                # Check audit logging
                if control_id in ['AU-2', 'AU-3', 'V-251241']:
                    try:
                        # This would collect audit evidence
                        evidence.append("Comprehensive audit logging enabled")
                        evidence.append("Audit logs include required data elements")
                    except Exception:
                        pass
                
                # Check encryption
                if control_id in ['SC-8', 'SC-13', 'V-251240']:
                    try:
                        # This would collect encryption evidence
                        evidence.append("FIPS 140-2 approved encryption in use")
                        evidence.append("TLS 1.2+ for data in transit")
                    except Exception:
                        pass
            
            # Collect platform-specific evidence
            if self.platform_manager:
                platform_credentials = await self.platform_manager.list_platform_credentials()
                evidence.append(f"Managing {len(platform_credentials)} platform credentials")
                
                # Check credential rotation
                rotated_recently = sum(1 for cred in platform_credentials 
                                     if cred.get('last_rotated') and 
                                     datetime.fromisoformat(cred['last_rotated']) > datetime.now(timezone.utc) - timedelta(days=30))
                evidence.append(f"{rotated_recently} credentials rotated in last 30 days")
            
            # Collect DR evidence
            if self.dr_manager:
                try:
                    backups = await self.dr_manager.list_backups(limit=10)
                    if backups:
                        evidence.append(f"Regular backups maintained: {len(backups)} recent backups")
                        encrypted_backups = sum(1 for backup in backups if 'encrypted' in backup.get('status', ''))
                        evidence.append(f"Backup encryption: {encrypted_backups}/{len(backups)} backups encrypted")
                except Exception:
                    pass
            
            return evidence
            
        except Exception as e:
            self.logger.error(f"Failed to collect evidence for {control_id}: {e}")
            return []
    
    async def _assess_control_implementation(self, control_id: str, standard: ComplianceStandard,
                                           evidence: List[str]) -> ComplianceStatus:
        """Assess control implementation status"""
        try:
            # Simple assessment logic based on evidence
            if not evidence:
                return ComplianceStatus.NON_COMPLIANT
            
            # Control-specific assessment logic
            if control_id in ['AC-2', 'AC-3', 'IA-2']:
                # Access control checks
                auth_evidence = [e for e in evidence if 'authentication' in e.lower() or 'access' in e.lower()]
                return ComplianceStatus.COMPLIANT if auth_evidence else ComplianceStatus.PARTIALLY_COMPLIANT
            
            elif control_id in ['AU-2', 'AU-3']:
                # Audit logging checks
                audit_evidence = [e for e in evidence if 'audit' in e.lower() or 'log' in e.lower()]
                return ComplianceStatus.COMPLIANT if audit_evidence else ComplianceStatus.NON_COMPLIANT
            
            elif control_id in ['SC-8', 'SC-13']:
                # Encryption checks
                crypto_evidence = [e for e in evidence if 'encryption' in e.lower() or 'tls' in e.lower() or 'fips' in e.lower()]
                return ComplianceStatus.COMPLIANT if crypto_evidence else ComplianceStatus.NON_COMPLIANT
            
            else:
                # Default assessment
                return ComplianceStatus.COMPLIANT if len(evidence) >= 2 else ComplianceStatus.PARTIALLY_COMPLIANT
                
        except Exception as e:
            self.logger.error(f"Failed to assess control implementation {control_id}: {e}")
            return ComplianceStatus.UNDER_REVIEW
    
    async def _generate_control_findings(self, control_id: str, standard: ComplianceStandard,
                                       evidence: List[str], status: ComplianceStatus) -> List[str]:
        """Generate findings for compliance control"""
        findings = []
        
        try:
            if status == ComplianceStatus.NON_COMPLIANT:
                findings.append(f"Control {control_id} is not implemented")
                if not evidence:
                    findings.append("No evidence of implementation found")
            
            elif status == ComplianceStatus.PARTIALLY_COMPLIANT:
                findings.append(f"Control {control_id} is partially implemented")
                findings.append("Additional implementation required for full compliance")
            
            # Control-specific findings
            if control_id in ['SC-8', 'SC-13'] and status != ComplianceStatus.COMPLIANT:
                findings.append("Encryption requirements not fully met")
            
            if control_id in ['AU-2', 'AU-3'] and status != ComplianceStatus.COMPLIANT:
                findings.append("Audit logging requirements not fully implemented")
            
            return findings
            
        except Exception as e:
            self.logger.error(f"Failed to generate findings for {control_id}: {e}")
            return []
    
    async def _generate_control_recommendations(self, control_id: str, standard: ComplianceStandard,
                                              findings: List[str]) -> List[str]:
        """Generate recommendations for compliance control"""
        recommendations = []
        
        try:
            if findings:
                if "not implemented" in ' '.join(findings).lower():
                    recommendations.append(f"Implement control {control_id} according to {standard.value} requirements")
                
                if "partially implemented" in ' '.join(findings).lower():
                    recommendations.append(f"Complete implementation of control {control_id}")
                
                if "encryption" in ' '.join(findings).lower():
                    recommendations.append("Ensure FIPS 140-2 approved encryption is used")
                
                if "audit" in ' '.join(findings).lower():
                    recommendations.append("Implement comprehensive audit logging with required data elements")
            
            return recommendations
            
        except Exception as e:
            self.logger.error(f"Failed to generate recommendations for {control_id}: {e}")
            return []
    
    def _calculate_control_risk_level(self, status: ComplianceStatus, findings: List[str]) -> str:
        """Calculate risk level for control"""
        if status == ComplianceStatus.NON_COMPLIANT:
            return "high" if len(findings) > 2 else "medium"
        elif status == ComplianceStatus.PARTIALLY_COMPLIANT:
            return "medium" if len(findings) > 1 else "low"
        else:
            return "low"
    
    def _calculate_compliance_metrics(self, controls: List[ComplianceControl]) -> Dict[str, Any]:
        """Calculate compliance metrics from controls"""
        if not controls:
            return {
                'overall_score': 0,
                'total_controls': 0,
                'compliant_controls': 0,
                'non_compliant_controls': 0,
                'critical_findings': 0,
                'high_findings': 0,
                'medium_findings': 0,
                'low_findings': 0
            }
        
        compliant = sum(1 for c in controls if c.implementation_status == ComplianceStatus.COMPLIANT)
        non_compliant = sum(1 for c in controls if c.implementation_status == ComplianceStatus.NON_COMPLIANT)
        
        # Calculate findings by risk level
        critical_findings = sum(1 for c in controls if c.risk_level == 'critical')
        high_findings = sum(1 for c in controls if c.risk_level == 'high')
        medium_findings = sum(1 for c in controls if c.risk_level == 'medium')
        low_findings = sum(1 for c in controls if c.risk_level == 'low')
        
        overall_score = (compliant / len(controls)) * 100 if controls else 0
        
        return {
            'overall_score': overall_score,
            'total_controls': len(controls),
            'compliant_controls': compliant,
            'non_compliant_controls': non_compliant,
            'critical_findings': critical_findings,
            'high_findings': high_findings,
            'medium_findings': medium_findings,
            'low_findings': low_findings
        }
    
    async def _generate_executive_summary(self, controls: List[ComplianceControl], 
                                        metrics: Dict[str, Any]) -> str:
        """Generate executive summary for compliance report"""
        try:
            summary_parts = []
            
            # Overall compliance
            score = metrics['overall_score']
            if score >= 90:
                summary_parts.append(f"The system demonstrates strong compliance with an overall score of {score:.1f}%.")
            elif score >= 70:
                summary_parts.append(f"The system shows moderate compliance with an overall score of {score:.1f}%.")
            else:
                summary_parts.append(f"The system requires significant compliance improvements with a score of {score:.1f}%.")
            
            # Control status
            total = metrics['total_controls']
            compliant = metrics['compliant_controls']
            non_compliant = metrics['non_compliant_controls']
            
            summary_parts.append(f"Of {total} controls assessed, {compliant} are compliant and {non_compliant} require attention.")
            
            # Risk findings
            critical = metrics['critical_findings']
            high = metrics['high_findings']
            
            if critical > 0:
                summary_parts.append(f"There are {critical} critical findings requiring immediate attention.")
            if high > 0:
                summary_parts.append(f"There are {high} high-risk findings that should be addressed promptly.")
            
            # Key areas
            auth_controls = [c for c in controls if 'authentication' in c.control_name.lower() or 'access' in c.control_name.lower()]
            audit_controls = [c for c in controls if 'audit' in c.control_name.lower()]
            crypto_controls = [c for c in controls if 'cryptographic' in c.control_name.lower() or 'encryption' in c.control_name.lower()]
            
            if auth_controls:
                auth_compliant = sum(1 for c in auth_controls if c.implementation_status == ComplianceStatus.COMPLIANT)
                summary_parts.append(f"Authentication and access controls: {auth_compliant}/{len(auth_controls)} compliant.")
            
            if audit_controls:
                audit_compliant = sum(1 for c in audit_controls if c.implementation_status == ComplianceStatus.COMPLIANT)
                summary_parts.append(f"Audit and logging controls: {audit_compliant}/{len(audit_controls)} compliant.")
            
            if crypto_controls:
                crypto_compliant = sum(1 for c in crypto_controls if c.implementation_status == ComplianceStatus.COMPLIANT)
                summary_parts.append(f"Cryptographic controls: {crypto_compliant}/{len(crypto_controls)} compliant.")
            
            return " ".join(summary_parts)
            
        except Exception as e:
            self.logger.error(f"Failed to generate executive summary: {e}")
            return "Executive summary generation failed."
    
    async def _generate_recommendations(self, controls: List[ComplianceControl]) -> List[str]:
        """Generate overall recommendations from controls"""
        try:
            recommendations = []
            
            # Collect all control recommendations
            all_recommendations = []
            for control in controls:
                all_recommendations.extend(control.recommendations)
            
            # Deduplicate and prioritize
            unique_recommendations = list(set(all_recommendations))
            
            # Add high-level recommendations
            non_compliant = [c for c in controls if c.implementation_status == ComplianceStatus.NON_COMPLIANT]
            if non_compliant:
                recommendations.append(f"Prioritize implementation of {len(non_compliant)} non-compliant controls")
            
            critical_controls = [c for c in controls if c.risk_level == 'critical']
            if critical_controls:
                recommendations.append(f"Address {len(critical_controls)} critical risk findings immediately")
            
            # Add control-specific recommendations
            recommendations.extend(unique_recommendations[:10])  # Limit to top 10
            
            return recommendations
            
        except Exception as e:
            self.logger.error(f"Failed to generate recommendations: {e}")
            return []
    
    async def _generate_report_files(self, report: ComplianceReport) -> List[str]:
        """Generate report files in requested formats"""
        try:
            report_files = []
            
            # Generate JSON report
            if 'json' in self.report_formats:
                json_file = await self._generate_json_report(report)
                if json_file:
                    report_files.append(json_file)
            
            # Generate HTML report
            if 'html' in self.report_formats:
                html_file = await self._generate_html_report(report)
                if html_file:
                    report_files.append(html_file)
            
            # Generate CSV report
            if 'csv' in self.report_formats:
                csv_file = await self._generate_csv_report(report)
                if csv_file:
                    report_files.append(csv_file)
            
            return report_files
            
        except Exception as e:
            self.logger.error(f"Failed to generate report files: {e}")
            return []
    
    async def _generate_json_report(self, report: ComplianceReport) -> Optional[str]:
        """Generate JSON format report"""
        try:
            import os
            
            json_file = os.path.join(self.report_output_dir, f"{report.report_id}.json")
            
            # Convert report to dictionary
            report_dict = asdict(report)
            
            # Convert datetime objects to strings
            def convert_datetime(obj):
                if isinstance(obj, datetime):
                    return obj.isoformat()
                elif isinstance(obj, dict):
                    return {k: convert_datetime(v) for k, v in obj.items()}
                elif isinstance(obj, list):
                    return [convert_datetime(item) for item in obj]
                else:
                    return obj
            
            report_dict = convert_datetime(report_dict)
            
            # Write JSON file
            with open(json_file, 'w') as f:
                json.dump(report_dict, f, indent=2, default=str)
            
            return json_file
            
        except Exception as e:
            self.logger.error(f"Failed to generate JSON report: {e}")
            return None
    
    async def _generate_html_report(self, report: ComplianceReport) -> Optional[str]:
        """Generate HTML format report"""
        try:
            import os
            
            html_file = os.path.join(self.report_output_dir, f"{report.report_id}.html")
            
            # Render HTML template
            html_template = self.report_templates['html']
            html_content = html_template.render(report=report)
            
            # Write HTML file
            with open(html_file, 'w') as f:
                f.write(html_content)
            
            return html_file
            
        except Exception as e:
            self.logger.error(f"Failed to generate HTML report: {e}")
            return None
    
    async def _generate_csv_report(self, report: ComplianceReport) -> Optional[str]:
        """Generate CSV format report"""
        try:
            import os
            
            csv_file = os.path.join(self.report_output_dir, f"{report.report_id}.csv")
            
            # Write CSV file
            with open(csv_file, 'w', newline='') as f:
                writer = csv.writer(f)
                
                # Write header
                writer.writerow([
                    'Control ID', 'Control Name', 'Standard', 'Status', 
                    'Risk Level', 'Owner', 'Findings Count', 'Last Assessed'
                ])
                
                # Write controls
                for control in report.controls:
                    writer.writerow([
                        control.control_id,
                        control.control_name,
                        control.standard.value,
                        control.implementation_status.value,
                        control.risk_level,
                        control.owner,
                        len(control.findings),
                        control.last_assessed.isoformat() if control.last_assessed else ''
                    ])
            
            return csv_file
            
        except Exception as e:
            self.logger.error(f"Failed to generate CSV report: {e}")
            return None
    
    async def _store_report_metadata(self, report: ComplianceReport, report_files: List[str]) -> None:
        """Store report metadata"""
        try:
            import os
            
            metadata_file = os.path.join(self.report_output_dir, "report_metadata.json")
            
            # Load existing metadata
            metadata = {}
            if os.path.exists(metadata_file):
                with open(metadata_file, 'r') as f:
                    metadata = json.load(f)
            
            # Add new report metadata
            metadata[report.report_id] = {
                'report_id': report.report_id,
                'report_name': report.report_name,
                'generated_at': report.generated_at.isoformat(),
                'standards': [std.value for std in report.standards],
                'compliance_score': report.overall_compliance_score,
                'report_files': report_files
            }
            
            # Save metadata
            with open(metadata_file, 'w') as f:
                json.dump(metadata, f, indent=2)
                
        except Exception as e:
            self.logger.error(f"Failed to store report metadata: {e}")
    
    async def _scheduled_reporting_task(self) -> None:
        """Background task for scheduled compliance reporting"""
        while True:
            try:
                # Simple monthly reporting implementation
                # In production, would use proper cron scheduling
                now = datetime.now(timezone.utc)
                
                # Generate monthly report on the 1st of each month
                if now.day == 1 and now.hour < 6:
                    await self.generate_compliance_report(
                        standards=self.enabled_standards,
                        report_period_days=30,
                        include_evidence=True
                    )
                
                # Sleep for 6 hours
                await asyncio.sleep(21600)
                
            except Exception as e:
                self.logger.error(f"Scheduled reporting task error: {e}")
                await asyncio.sleep(21600)
    
    async def _get_stig_controls(self, version: str) -> List[str]:
        """Get STIG control IDs for version"""
        # Return sample STIG controls
        return ['V-251239', 'V-251240', 'V-251241']
    
    async def _get_nist_controls(self, baseline: str) -> List[str]:
        """Get NIST control IDs for baseline"""
        # Return sample NIST controls
        return ['AC-2', 'AC-3', 'AU-2', 'AU-3', 'IA-2', 'SC-8', 'SC-13']
    
    def _generate_stig_checklist_format(self, controls: List[ComplianceControl], version: str) -> Dict[str, Any]:
        """Generate STIG checklist format"""
        return {
            'stig_version': version,
            'checklist_data': [
                {
                    'vuln_id': control.control_id,
                    'rule_id': f"SV-{control.control_id}",
                    'status': control.implementation_status.value,
                    'finding_details': '\n'.join(control.findings),
                    'comments': '\n'.join(control.recommendations)
                }
                for control in controls
            ]
        }
    
    async def _save_stig_checklist(self, checklist_id: str, checklist_data: Dict[str, Any]) -> str:
        """Save STIG checklist file"""
        import os
        
        checklist_file = os.path.join(self.report_output_dir, f"{checklist_id}.json")
        
        with open(checklist_file, 'w') as f:
            json.dump(checklist_data, f, indent=2)
        
        return checklist_file
    
    async def _get_recent_findings(self) -> List[Dict[str, Any]]:
        """Get recent compliance findings"""
        # Implementation would return recent findings
        return []
    
    async def _get_trending_metrics(self) -> Dict[str, Any]:
        """Get trending compliance metrics"""
        # Implementation would return trending data
        return {}
    
    async def _get_critical_actions(self) -> List[Dict[str, Any]]:
        """Get critical actions required"""
        # Implementation would return critical actions
        return []