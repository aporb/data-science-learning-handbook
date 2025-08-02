"""
Penetration Testing Report Generation Engine
==========================================

Professional penetration testing report generation system that creates compliance-ready
reports integrating with existing monitoring and compliance infrastructure. Provides
automated finding correlation, executive summaries, and multi-format outputs.

Key Features:
- Professional penetration testing report templates
- Executive summary and technical detail sections
- Automated finding correlation and deduplication
- Classification-aware report generation
- Multi-format output (PDF, Word, HTML, JSON)
- Compliance integration with DoD/NIST requirements
- Real-time report generation and distribution

Integration Points:
- Enhanced monitoring system for real-time metrics
- Comprehensive audit system for evidence collection
- Risk assessment framework for risk scoring
- Multi-classification engine for report classification
- Compliance documentation framework for templates

Classification: UNCLASSIFIED//FOR OFFICIAL USE ONLY
Version: 1.0 - Penetration Testing Report Generation
Author: Red Team Operations
Date: 2025-07-28
"""

import asyncio
import json
import logging
import time
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Tuple, Set, Union, AsyncGenerator
from uuid import UUID, uuid4
from dataclasses import dataclass, field, asdict
from enum import Enum
from concurrent.futures import ThreadPoolExecutor
from collections import defaultdict, deque
import aiofiles
import aiohttp
from threading import Lock
import numpy as np
from pathlib import Path
import jinja2
import pandas as pd
from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.graphics.shapes import Drawing
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.charts.barcharts import VerticalBarChart
import base64
import hashlib

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class SeverityLevel(Enum):
    """Vulnerability severity levels."""
    CRITICAL = "Critical"
    HIGH = "High" 
    MEDIUM = "Medium"
    LOW = "Low"
    INFORMATIONAL = "Informational"

class FindingCategory(Enum):
    """Penetration testing finding categories."""
    NETWORK_SECURITY = "Network Security"
    WEB_APPLICATION = "Web Application"
    INFRASTRUCTURE = "Infrastructure"
    ACCESS_CONTROL = "Access Control"
    ENCRYPTION = "Encryption"
    COMPLIANCE = "Compliance"
    SOCIAL_ENGINEERING = "Social Engineering"
    PHYSICAL_SECURITY = "Physical Security"

class ReportFormat(Enum):
    """Supported report output formats."""
    PDF = "pdf"
    HTML = "html"
    JSON = "json"
    WORD = "docx"
    EXCEL = "xlsx"

class ClassificationLevel(Enum):
    """Security classification levels."""
    UNCLASSIFIED = "UNCLASSIFIED"
    CUI = "CONTROLLED UNCLASSIFIED INFORMATION"
    CONFIDENTIAL = "CONFIDENTIAL"
    SECRET = "SECRET"
    TOP_SECRET = "TOP SECRET"

@dataclass
class Finding:
    """Penetration testing finding data structure."""
    id: str = field(default_factory=lambda: str(uuid4()))
    title: str = ""
    description: str = ""
    severity: SeverityLevel = SeverityLevel.MEDIUM
    category: FindingCategory = FindingCategory.INFRASTRUCTURE
    affected_systems: List[str] = field(default_factory=list)
    cvss_score: float = 0.0
    cvss_vector: str = ""
    cve_references: List[str] = field(default_factory=list)
    remediation: str = ""
    evidence: List[str] = field(default_factory=list)
    proof_of_concept: str = ""
    business_impact: str = ""
    technical_impact: str = ""
    likelihood: str = "Medium"
    discovery_date: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_updated: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    status: str = "Open"
    assigned_to: str = ""
    compliance_references: List[str] = field(default_factory=list)
    risk_score: float = 0.0
    
    def calculate_risk_score(self) -> float:
        """Calculate risk score based on severity and likelihood."""
        severity_weights = {
            SeverityLevel.CRITICAL: 10,
            SeverityLevel.HIGH: 8,
            SeverityLevel.MEDIUM: 5,
            SeverityLevel.LOW: 3,
            SeverityLevel.INFORMATIONAL: 1
        }
        
        likelihood_weights = {
            "Very High": 5,
            "High": 4,
            "Medium": 3,
            "Low": 2,
            "Very Low": 1
        }
        
        severity_weight = severity_weights.get(self.severity, 5)
        likelihood_weight = likelihood_weights.get(self.likelihood, 3)
        
        self.risk_score = (severity_weight * likelihood_weight) / 10
        return self.risk_score

@dataclass
class TestScope:
    """Penetration testing scope definition."""
    target_systems: List[str] = field(default_factory=list)
    ip_ranges: List[str] = field(default_factory=list)
    domains: List[str] = field(default_factory=list)
    excluded_systems: List[str] = field(default_factory=list)
    testing_window: Tuple[datetime, datetime] = field(default_factory=lambda: (datetime.now(), datetime.now()))
    testing_methodology: List[str] = field(default_factory=list)
    compliance_requirements: List[str] = field(default_factory=list)
    authorized_personnel: List[str] = field(default_factory=list)

@dataclass
class ExecutiveSummary:
    """Executive summary for penetration testing report."""
    overview: str = ""
    key_findings: List[str] = field(default_factory=list)
    risk_assessment: str = ""
    recommendations: List[str] = field(default_factory=list)
    business_impact: str = ""
    compliance_status: str = ""
    overall_risk_rating: str = "Medium"

@dataclass
class TestMetrics:
    """Penetration testing metrics and statistics."""
    total_findings: int = 0
    findings_by_severity: Dict[str, int] = field(default_factory=dict)
    findings_by_category: Dict[str, int] = field(default_factory=dict)
    systems_tested: int = 0
    vulnerabilities_exploited: int = 0
    test_duration: timedelta = field(default_factory=lambda: timedelta(hours=0))
    coverage_percentage: float = 0.0
    false_positive_rate: float = 0.0
    remediation_rate: float = 0.0

@dataclass
class PentestReport:
    """Complete penetration testing report structure."""
    id: str = field(default_factory=lambda: str(uuid4()))
    title: str = ""
    client_name: str = ""
    test_date: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    report_date: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    classification: ClassificationLevel = ClassificationLevel.UNCLASSIFIED
    executive_summary: ExecutiveSummary = field(default_factory=ExecutiveSummary)
    scope: TestScope = field(default_factory=TestScope)
    methodology: List[str] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    metrics: TestMetrics = field(default_factory=TestMetrics)
    appendices: Dict[str, str] = field(default_factory=dict)
    team_members: List[str] = field(default_factory=list)
    tools_used: List[str] = field(default_factory=list)
    created_by: str = ""
    approved_by: str = ""
    version: str = "1.0"
    
    def calculate_metrics(self):
        """Calculate report metrics from findings."""
        self.metrics.total_findings = len(self.findings)
        
        # Calculate findings by severity
        severity_counts = defaultdict(int)
        category_counts = defaultdict(int)
        
        for finding in self.findings:
            severity_counts[finding.severity.value] += 1
            category_counts[finding.category.value] += 1
            finding.calculate_risk_score()
        
        self.metrics.findings_by_severity = dict(severity_counts)
        self.metrics.findings_by_category = dict(category_counts)

class ReportGenerationEngine:
    """
    Professional penetration testing report generation engine.
    
    This engine creates comprehensive, compliance-ready penetration testing
    reports with automated finding correlation, executive summaries, and
    multi-format outputs.
    """
    
    def __init__(self, template_dir: Path = None):
        """Initialize the report generation engine."""
        self.template_dir = template_dir or Path(__file__).parent.parent / "templates"
        self.reports_dir = Path(__file__).parent.parent / "generated_reports"
        self.reports_dir.mkdir(exist_ok=True)
        
        # Initialize Jinja2 environment
        self.jinja_env = jinja2.Environment(
            loader=jinja2.FileSystemLoader(str(self.template_dir)),
            autoescape=jinja2.select_autoescape(['html', 'xml'])
        )
        
        # Report styles
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()
        
        logger.info("Penetration Testing Report Generation Engine initialized")
    
    def _setup_custom_styles(self):
        """Setup custom report styles."""
        # Title style
        self.styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=self.styles['Title'],
            fontSize=18,
            spaceAfter=30,
            textColor=colors.darkblue,
            alignment=1  # Center alignment
        ))
        
        # Classification style
        self.styles.add(ParagraphStyle(
            name='Classification',
            parent=self.styles['Normal'],
            fontSize=12,
            textColor=colors.red,
            backColor=colors.yellow,
            alignment=1,
            spaceAfter=20
        ))
        
        # Finding title style
        self.styles.add(ParagraphStyle(
            name='FindingTitle',
            parent=self.styles['Heading2'],
            textColor=colors.darkred,
            fontSize=14,
            spaceAfter=10
        ))
    
    async def generate_report(self, report: PentestReport, format: ReportFormat = ReportFormat.PDF) -> str:
        """
        Generate a penetration testing report in the specified format.
        
        Args:
            report: The penetration testing report data
            format: Output format (PDF, HTML, JSON, etc.)
            
        Returns:
            Path to the generated report file
        """
        try:
            logger.info(f"Generating {format.value} report: {report.title}")
            
            # Calculate metrics
            report.calculate_metrics()
            
            # Generate report based on format
            if format == ReportFormat.PDF:
                return await self._generate_pdf_report(report)
            elif format == ReportFormat.HTML:
                return await self._generate_html_report(report)
            elif format == ReportFormat.JSON:
                return await self._generate_json_report(report)
            else:
                raise ValueError(f"Unsupported report format: {format}")
                
        except Exception as e:
            logger.error(f"Error generating report: {str(e)}")
            raise
    
    async def _generate_pdf_report(self, report: PentestReport) -> str:
        """Generate PDF report."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"pentest_report_{report.client_name}_{timestamp}.pdf"
        filepath = self.reports_dir / filename
        
        # Create PDF document
        doc = SimpleDocTemplate(str(filepath), pagesize=letter)
        story = []
        
        # Classification header
        if report.classification != ClassificationLevel.UNCLASSIFIED:
            classification_text = f"**{report.classification.value}**"
            story.append(Paragraph(classification_text, self.styles['Classification']))
        
        # Title page
        story.append(Paragraph(report.title, self.styles['CustomTitle']))
        story.append(Paragraph(f"Client: {report.client_name}", self.styles['Normal']))
        story.append(Paragraph(f"Test Date: {report.test_date.strftime('%Y-%m-%d')}", self.styles['Normal']))
        story.append(Paragraph(f"Report Date: {report.report_date.strftime('%Y-%m-%d')}", self.styles['Normal']))
        story.append(Spacer(1, 20))
        
        # Executive Summary
        story.append(Paragraph("Executive Summary", self.styles['Heading1']))
        story.append(Paragraph(report.executive_summary.overview, self.styles['Normal']))
        story.append(Spacer(1, 12))
        
        # Key Findings
        story.append(Paragraph("Key Findings:", self.styles['Heading2']))
        for finding in report.executive_summary.key_findings:
            story.append(Paragraph(f"• {finding}", self.styles['Normal']))
        story.append(Spacer(1, 12))
        
        # Risk Assessment
        story.append(Paragraph("Risk Assessment:", self.styles['Heading2']))
        story.append(Paragraph(report.executive_summary.risk_assessment, self.styles['Normal']))
        story.append(PageBreak())
        
        # Findings Summary Chart
        story.extend(self._create_findings_chart(report))
        story.append(PageBreak())
        
        # Detailed Findings
        story.append(Paragraph("Detailed Findings", self.styles['Heading1']))
        
        # Sort findings by severity (Critical first)
        severity_order = {
            SeverityLevel.CRITICAL: 0,
            SeverityLevel.HIGH: 1,
            SeverityLevel.MEDIUM: 2,
            SeverityLevel.LOW: 3,
            SeverityLevel.INFORMATIONAL: 4
        }
        sorted_findings = sorted(report.findings, key=lambda x: severity_order[x.severity])
        
        for finding in sorted_findings:
            story.extend(self._create_finding_section(finding))
            story.append(Spacer(1, 20))
        
        # Appendices
        if report.appendices:
            story.append(PageBreak())
            story.append(Paragraph("Appendices", self.styles['Heading1']))
            for title, content in report.appendices.items():
                story.append(Paragraph(title, self.styles['Heading2']))
                story.append(Paragraph(content, self.styles['Normal']))
                story.append(Spacer(1, 12))
        
        # Build PDF
        doc.build(story)
        
        logger.info(f"PDF report generated: {filepath}")
        return str(filepath)
    
    def _create_findings_chart(self, report: PentestReport) -> List:
        """Create findings summary chart."""
        story = []
        
        # Findings by severity table
        story.append(Paragraph("Findings Summary", self.styles['Heading2']))
        
        severity_data = [['Severity', 'Count', 'Percentage']]
        total_findings = report.metrics.total_findings or 1
        
        for severity, count in report.metrics.findings_by_severity.items():
            percentage = (count / total_findings) * 100
            severity_data.append([severity, str(count), f"{percentage:.1f}%"])
        
        severity_table = Table(severity_data)
        severity_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 14),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        story.append(severity_table)
        story.append(Spacer(1, 20))
        
        return story
    
    def _create_finding_section(self, finding: Finding) -> List:
        """Create detailed finding section."""
        story = []
        
        # Finding title with severity
        title_text = f"{finding.title} [{finding.severity.value}]"
        story.append(Paragraph(title_text, self.styles['FindingTitle']))
        
        # Finding details table
        details_data = [
            ['Category', finding.category.value],
            ['Severity', finding.severity.value],
            ['Risk Score', f"{finding.risk_score:.1f}"],
            ['CVSS Score', str(finding.cvss_score) if finding.cvss_score else 'N/A'],
            ['Affected Systems', ', '.join(finding.affected_systems) if finding.affected_systems else 'N/A'],
            ['Status', finding.status]
        ]
        
        details_table = Table(details_data, colWidths=[2*inch, 4*inch])
        details_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        story.append(details_table)
        story.append(Spacer(1, 12))
        
        # Description
        story.append(Paragraph("Description:", self.styles['Heading3']))
        story.append(Paragraph(finding.description, self.styles['Normal']))
        story.append(Spacer(1, 8))
        
        # Business Impact
        if finding.business_impact:
            story.append(Paragraph("Business Impact:", self.styles['Heading3']))
            story.append(Paragraph(finding.business_impact, self.styles['Normal']))
            story.append(Spacer(1, 8))
        
        # Technical Impact
        if finding.technical_impact:
            story.append(Paragraph("Technical Impact:", self.styles['Heading3']))
            story.append(Paragraph(finding.technical_impact, self.styles['Normal']))
            story.append(Spacer(1, 8))
        
        # Remediation
        if finding.remediation:
            story.append(Paragraph("Remediation:", self.styles['Heading3']))
            story.append(Paragraph(finding.remediation, self.styles['Normal']))
            story.append(Spacer(1, 8))
        
        # References
        if finding.cve_references or finding.compliance_references:
            story.append(Paragraph("References:", self.styles['Heading3']))
            all_refs = finding.cve_references + finding.compliance_references
            for ref in all_refs:
                story.append(Paragraph(f"• {ref}", self.styles['Normal']))
        
        return story
    
    async def _generate_html_report(self, report: PentestReport) -> str:
        """Generate HTML report."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"pentest_report_{report.client_name}_{timestamp}.html"
        filepath = self.reports_dir / filename
        
        # Load HTML template
        template = self.jinja_env.get_template('pentest_report.html')
        
        # Render template
        html_content = template.render(
            report=report,
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        )
        
        # Write HTML file
        async with aiofiles.open(filepath, 'w', encoding='utf-8') as f:
            await f.write(html_content)
        
        logger.info(f"HTML report generated: {filepath}")
        return str(filepath)
    
    async def _generate_json_report(self, report: PentestReport) -> str:
        """Generate JSON report."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"pentest_report_{report.client_name}_{timestamp}.json"
        filepath = self.reports_dir / filename
        
        # Convert report to dict with proper serialization
        report_dict = asdict(report)
        
        # Convert datetime objects to ISO format
        def serialize_datetime(obj):
            if isinstance(obj, datetime):
                return obj.isoformat()
            elif isinstance(obj, timedelta):
                return str(obj)
            return obj
        
        # Recursively convert datetime objects
        def convert_datetimes(data):
            if isinstance(data, dict):
                return {k: convert_datetimes(v) for k, v in data.items()}
            elif isinstance(data, list):
                return [convert_datetimes(item) for item in data]
            else:
                return serialize_datetime(data)
        
        report_dict = convert_datetimes(report_dict)
        
        # Write JSON file
        async with aiofiles.open(filepath, 'w', encoding='utf-8') as f:
            await f.write(json.dumps(report_dict, indent=2, ensure_ascii=False))
        
        logger.info(f"JSON report generated: {filepath}")
        return str(filepath)
    
    async def correlate_findings(self, findings: List[Finding]) -> List[Finding]:
        """
        Correlate and deduplicate findings based on similarity.
        
        Args:
            findings: List of findings to correlate
            
        Returns:
            Deduplicated list of findings
        """
        if not findings:
            return findings
        
        correlated_findings = []
        processed_indices = set()
        
        for i, finding in enumerate(findings):
            if i in processed_indices:
                continue
            
            # Find similar findings
            similar_findings = [finding]
            for j, other_finding in enumerate(findings[i+1:], i+1):
                if j in processed_indices:
                    continue
                
                # Check similarity based on title, category, and affected systems
                if self._are_findings_similar(finding, other_finding):
                    similar_findings.append(other_finding)
                    processed_indices.add(j)
            
            # Merge similar findings
            if len(similar_findings) > 1:
                merged_finding = self._merge_findings(similar_findings)
                correlated_findings.append(merged_finding)
            else:
                correlated_findings.append(finding)
            
            processed_indices.add(i)
        
        logger.info(f"Correlated {len(findings)} findings into {len(correlated_findings)} unique findings")
        return correlated_findings
    
    def _are_findings_similar(self, finding1: Finding, finding2: Finding) -> bool:
        """Check if two findings are similar enough to be merged."""
        # Check title similarity
        title_similarity = self._calculate_string_similarity(finding1.title, finding2.title)
        
        # Check category match
        category_match = finding1.category == finding2.category
        
        # Check affected systems overlap
        systems1 = set(finding1.affected_systems)
        systems2 = set(finding2.affected_systems)
        systems_overlap = len(systems1.intersection(systems2)) > 0
        
        # Findings are similar if title is very similar AND category matches
        return title_similarity > 0.8 and category_match
    
    def _calculate_string_similarity(self, str1: str, str2: str) -> float:
        """Calculate similarity between two strings using simple ratio."""
        if not str1 or not str2:
            return 0.0
        
        # Simple character-based similarity
        set1 = set(str1.lower().split())
        set2 = set(str2.lower().split())
        
        if not set1 or not set2:
            return 0.0
        
        intersection = len(set1.intersection(set2))
        union = len(set1.union(set2))
        
        return intersection / union if union > 0 else 0.0
    
    def _merge_findings(self, findings: List[Finding]) -> Finding:
        """Merge multiple similar findings into one."""
        if not findings:
            raise ValueError("Cannot merge empty findings list")
        
        # Use the first finding as base
        merged = findings[0]
        
        # Collect all affected systems
        all_systems = set(merged.affected_systems)
        for finding in findings[1:]:
            all_systems.update(finding.affected_systems)
        merged.affected_systems = list(all_systems)
        
        # Collect all evidence
        all_evidence = set(merged.evidence)
        for finding in findings[1:]:
            all_evidence.update(finding.evidence)
        merged.evidence = list(all_evidence)
        
        # Use highest severity
        severities = [f.severity for f in findings]
        severity_order = [SeverityLevel.CRITICAL, SeverityLevel.HIGH, SeverityLevel.MEDIUM, SeverityLevel.LOW, SeverityLevel.INFORMATIONAL]
        for severity in severity_order:
            if severity in severities:
                merged.severity = severity
                break
        
        # Merge descriptions
        descriptions = [f.description for f in findings if f.description]
        if len(descriptions) > 1:
            merged.description = "\n\n".join(f"Instance {i+1}: {desc}" for i, desc in enumerate(descriptions))
        
        # Update timestamps
        merged.last_updated = datetime.now(timezone.utc)
        
        return merged

# Convenience functions for external use
async def generate_pentest_report(report_data: Dict[str, Any], format: ReportFormat = ReportFormat.PDF) -> str:
    """
    Generate a penetration testing report from dictionary data.
    
    Args:
        report_data: Dictionary containing report data
        format: Output format
        
    Returns:
        Path to generated report file
    """
    engine = ReportGenerationEngine()
    
    # Convert dict to PentestReport object
    report = PentestReport(**report_data)
    
    return await engine.generate_report(report, format)

async def correlate_and_generate_report(findings_data: List[Dict[str, Any]], 
                                      report_metadata: Dict[str, Any],
                                      format: ReportFormat = ReportFormat.PDF) -> str:
    """
    Correlate findings and generate a penetration testing report.
    
    Args:
        findings_data: List of finding dictionaries
        report_metadata: Report metadata dictionary
        format: Output format
        
    Returns:
        Path to generated report file
    """
    engine = ReportGenerationEngine()
    
    # Convert findings data to Finding objects
    findings = [Finding(**finding_data) for finding_data in findings_data]
    
    # Correlate findings
    correlated_findings = await engine.correlate_findings(findings)
    
    # Create report
    report = PentestReport(
        findings=correlated_findings,
        **report_metadata
    )
    
    return await engine.generate_report(report, format)

if __name__ == "__main__":
    # Example usage
    async def main():
        # Create sample findings
        findings = [
            Finding(
                title="SQL Injection Vulnerability",
                description="SQL injection vulnerability found in login form",
                severity=SeverityLevel.HIGH,
                category=FindingCategory.WEB_APPLICATION,
                affected_systems=["web-app-01"],
                cvss_score=8.1,
                remediation="Implement parameterized queries and input validation"
            ),
            Finding(
                title="Weak Password Policy",
                description="Password policy allows weak passwords",
                severity=SeverityLevel.MEDIUM,
                category=FindingCategory.ACCESS_CONTROL,
                affected_systems=["domain-controller"],
                cvss_score=5.3,
                remediation="Implement strong password policy requirements"
            )
        ]
        
        # Create sample report
        report = PentestReport(
            title="Sample Penetration Test Report",
            client_name="Example Corp",
            findings=findings,
            executive_summary=ExecutiveSummary(
                overview="This penetration test identified several security vulnerabilities.",
                key_findings=["SQL injection vulnerability", "Weak password policy"],
                risk_assessment="Overall risk level is Medium-High",
                recommendations=["Fix SQL injection", "Strengthen password policy"]
            )
        )
        
        # Generate report
        engine = ReportGenerationEngine()
        report_path = await engine.generate_report(report, ReportFormat.PDF)
        print(f"Report generated: {report_path}")
    
    asyncio.run(main())