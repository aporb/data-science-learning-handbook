#!/usr/bin/env python3
"""
Security Control Documentation Generator

This module provides comprehensive automated generation of security control
implementation statements, security configuration baselines, operational
procedures documentation, and incident response integration.

Key Features:
- Control implementation statements with evidence correlation
- Security configuration baselines with deviation tracking
- Operational procedures documentation with workflow integration
- Incident response integration with real-time updates
- DoD compliance report generation with multiple format support

Classification: UNCLASSIFIED//FOR OFFICIAL USE ONLY
"""

import asyncio
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple, Set, Union
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
import uuid
import jinja2
from jinja2 import Environment, FileSystemLoader, Template
import markdown
import pdfkit
from io import StringIO
import csv

# Type definitions
DocumentID = str
TemplateID = str
ControlID = str

class DocumentType(Enum):
    """Types of documentation that can be generated"""
    CONTROL_IMPLEMENTATION_STATEMENT = "control_implementation"
    SECURITY_CONFIGURATION_BASELINE = "security_baseline"
    OPERATIONAL_PROCEDURES = "operational_procedures"
    COMPLIANCE_REPORT = "compliance_report"
    ASSESSMENT_REPORT = "assessment_report"
    INCIDENT_RESPONSE_INTEGRATION = "incident_response"
    EXECUTIVE_SUMMARY = "executive_summary"
    TECHNICAL_REFERENCE = "technical_reference"

class OutputFormat(Enum):
    """Supported output formats"""
    HTML = "html"
    PDF = "pdf"
    MARKDOWN = "markdown"
    DOCX = "docx" 
    JSON = "json"
    CSV = "csv"
    XLSX = "xlsx"

class ComplianceFramework(Enum):
    """Compliance frameworks for report generation"""
    NIST_800_53 = "NIST_SP_800_53"
    DOD_8500 = "DOD_8500_SERIES"
    STIG = "DISA_STIG"
    FISMA = "FISMA"
    FEDRAMP = "FEDRAMP"
    SOC2 = "SOC2"

@dataclass
class DocumentTemplate:
    """Template for document generation"""
    template_id: str
    document_type: DocumentType
    template_name: str
    template_content: str
    template_variables: List[str] = field(default_factory=list)
    supported_formats: List[OutputFormat] = field(default_factory=list)
    compliance_frameworks: List[ComplianceFramework] = field(default_factory=list)
    created_date: datetime = field(default_factory=datetime.now)
    updated_date: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class GeneratedDocument:
    """Represents a generated document"""
    document_id: str
    document_type: DocumentType
    title: str
    content: str
    output_format: OutputFormat
    file_path: Optional[str] = None
    control_ids: List[str] = field(default_factory=list)
    compliance_framework: Optional[ComplianceFramework] = None
    generation_timestamp: datetime = field(default_factory=datetime.now)
    template_id: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)

@dataclass
class DocumentationRequest:
    """Request for document generation"""
    request_id: str
    document_type: DocumentType
    output_format: OutputFormat
    control_ids: List[str] = field(default_factory=list)
    compliance_framework: Optional[ComplianceFramework] = None
    template_id: Optional[str] = None
    custom_parameters: Dict[str, Any] = field(default_factory=dict)
    requestor: str = ""
    priority: str = "normal"  # low, normal, high, urgent
    created_date: datetime = field(default_factory=datetime.now)

class SecurityControlDocumentationGenerator:
    """
    Comprehensive documentation generator for security control implementations
    with automated evidence correlation and compliance report generation.
    """
    
    def __init__(self,
                 output_directory: str = "./generated_documentation",
                 templates_directory: str = "./documentation_templates",
                 control_mapping_engine: Optional[Any] = None,
                 evidence_collector: Optional[Any] = None,
                 assessment_framework: Optional[Any] = None,
                 audit_logger: Optional[Any] = None):
        """
        Initialize Security Control Documentation Generator
        
        Args:
            output_directory: Directory for generated documentation output
            templates_directory: Directory containing document templates
            control_mapping_engine: Control mapping engine instance
            evidence_collector: Evidence collector instance
            assessment_framework: Assessment framework instance
            audit_logger: Audit logging system instance
        """
        self.output_directory = Path(output_directory)
        self.templates_directory = Path(templates_directory)
        self.control_mapping_engine = control_mapping_engine
        self.evidence_collector = evidence_collector
        self.assessment_framework = assessment_framework
        self.audit_logger = audit_logger
        
        # Document storage
        self.generated_documents: Dict[str, GeneratedDocument] = {}
        self.document_templates: Dict[str, DocumentTemplate] = {}
        self.generation_requests: Dict[str, DocumentationRequest] = {}
        
        # Template engine
        self.jinja_env = None
        
        # Performance metrics
        self.metrics = {
            "total_documents_generated": 0,
            "documents_by_type": {},
            "documents_by_format": {},
            "average_generation_time": 0.0,
            "template_usage": {},
            "last_generation": None
        }
        
        self.logger = logging.getLogger(__name__)
        self._initialize_directories()
        self._setup_template_engine()
        self._create_default_templates()
    
    def _initialize_directories(self):
        """Initialize required directories"""
        directories = [
            self.output_directory,
            self.templates_directory,
            self.output_directory / "html",
            self.output_directory / "pdf", 
            self.output_directory / "markdown",
            self.output_directory / "json",
            self.output_directory / "reports",
            self.output_directory / "archives"
        ]
        
        for directory in directories:
            directory.mkdir(parents=True, exist_ok=True)
    
    def _setup_template_engine(self):
        """Setup Jinja2 template engine"""
        try:
            self.jinja_env = Environment(
                loader=FileSystemLoader(str(self.templates_directory)),
                autoescape=True,
                trim_blocks=True,
                lstrip_blocks=True
            )
            
            # Add custom filters
            self.jinja_env.filters['datetime_format'] = self._datetime_format
            self.jinja_env.filters['risk_level_color'] = self._risk_level_color
            self.jinja_env.filters['effectiveness_bar'] = self._effectiveness_bar
            
        except Exception as e:
            self.logger.error(f"Failed to setup template engine: {e}")
    
    def _datetime_format(self, value, format_string='%Y-%m-%d %H:%M:%S'):
        """Custom filter for datetime formatting"""
        if isinstance(value, str):
            try:
                value = datetime.fromisoformat(value.replace('Z', '+00:00'))
            except:
                return value
        return value.strftime(format_string) if value else ""
    
    def _risk_level_color(self, risk_level):
        """Custom filter for risk level colors"""
        colors = {
            "critical": "#FF0000",
            "high": "#FF6600", 
            "moderate": "#FFAA00",
            "low": "#00AA00",
            "informational": "#0066CC"
        }
        return colors.get(risk_level.lower(), "#666666")
    
    def _effectiveness_bar(self, score, width=200):
        """Custom filter for effectiveness score bar"""
        if not isinstance(score, (int, float)):
            score = 0
        
        score = max(0, min(1, score))
        bar_width = int(score * width)
        color = "#00AA00" if score >= 0.8 else "#FFAA00" if score >= 0.6 else "#FF6600"
        
        return f'<div style="width:{width}px;height:20px;background:#EEE;border:1px solid #CCC;">' \
               f'<div style="width:{bar_width}px;height:20px;background:{color};"></div>' \
               f'</div>'
    
    def _create_default_templates(self):
        """Create default document templates"""
        # Control Implementation Statement Template
        control_impl_template = """
# Control Implementation Statement

**Control ID:** {{ control_id }}
**Control Title:** {{ control_title }}
**Framework:** {{ framework }}
**Assessment Date:** {{ assessment_date | datetime_format }}

## Implementation Summary

{{ implementation_summary }}

## Control Description

{{ control_description }}

## Implementation Details

{% for implementation in implementations %}
### {{ implementation.implementation_type | title }} Implementation

**Responsible Entity:** {{ implementation.responsible_entity }}
**System Component:** {{ implementation.system_component }}
**Status:** {{ implementation.status }}

{{ implementation.description }}

{% if implementation.configuration_settings %}
#### Configuration Settings
{% for key, value in implementation.configuration_settings.items() %}
- **{{ key }}:** {{ value }}
{% endfor %}
{% endif %}

{% endfor %}

## Evidence

{% for evidence in evidence_items %}
### {{ evidence.title }}
**Type:** {{ evidence.evidence_type }}
**Source:** {{ evidence.source }}
**Quality Level:** {{ evidence.quality_level }}
**Collection Date:** {{ evidence.collection_timestamp | datetime_format }}

{{ evidence.description }}

{% endfor %}

## Assessment Results

{% if assessment_result %}
**Effectiveness Score:** {{ assessment_result.effectiveness_score }} ({{ assessment_result.effectiveness_level }})
**Risk Level:** {{ assessment_result.risk_level }}

### Findings
{% for finding in assessment_result.findings %}
- **{{ finding.severity | upper }}:** {{ finding.title }}
  - {{ finding.description }}
  - **Recommendation:** {{ finding.remediation_recommendation }}
{% endfor %}

### Recommendations
{% for recommendation in assessment_result.recommendations %}
- {{ recommendation }}
{% endfor %}
{% endif %}

## Residual Risk

{{ residual_risk_assessment }}

---
*Generated on {{ generation_date | datetime_format }} by Security Control Documentation Generator*
        """
        
        self._add_template(
            template_id="control_implementation_statement",
            document_type=DocumentType.CONTROL_IMPLEMENTATION_STATEMENT,
            template_name="Standard Control Implementation Statement",
            template_content=control_impl_template,
            supported_formats=[OutputFormat.HTML, OutputFormat.PDF, OutputFormat.MARKDOWN],
            compliance_frameworks=[ComplianceFramework.NIST_800_53, ComplianceFramework.DOD_8500]
        )
        
        # Security Configuration Baseline Template
        baseline_template = """
# Security Configuration Baseline

**System:** {{ system_name }}
**Baseline Version:** {{ baseline_version }}
**Last Updated:** {{ last_updated | datetime_format }}
**Classification:** {{ classification_level }}

## Executive Summary

This document establishes the security configuration baseline for {{ system_name }} 
in accordance with {{ compliance_framework }} requirements.

## Configuration Standards

{% for control_id, control_config in control_configurations.items() %}
### {{ control_id }} - {{ control_config.title }}

**Implementation Status:** {{ control_config.status }}
**Configuration Requirements:**

{% for requirement in control_config.requirements %}
- {{ requirement }}
{% endfor %}

**Current Configuration:**
```
{{ control_config.current_config }}
```

{% if control_config.deviations %}
**Approved Deviations:**
{% for deviation in control_config.deviations %}
- {{ deviation.description }} (Approved by: {{ deviation.approver }})
{% endfor %}
{% endif %}

{% endfor %}

## Monitoring and Compliance

### Automated Monitoring
{% for monitor in automated_monitors %}
- **{{ monitor.name }}:** {{ monitor.description }}
  - **Frequency:** {{ monitor.frequency }}
  - **Threshold:** {{ monitor.threshold }}
{% endfor %}

### Compliance Status
- **Overall Compliance Rate:** {{ compliance_rate }}%
- **Last Assessment:** {{ last_assessment_date | datetime_format }}
- **Next Assessment:** {{ next_assessment_date | datetime_format }}

---
*Generated on {{ generation_date | datetime_format }} by Security Control Documentation Generator*
        """
        
        self._add_template(
            template_id="security_baseline",
            document_type=DocumentType.SECURITY_CONFIGURATION_BASELINE,
            template_name="Security Configuration Baseline",
            template_content=baseline_template,
            supported_formats=[OutputFormat.HTML, OutputFormat.PDF, OutputFormat.MARKDOWN],
            compliance_frameworks=[ComplianceFramework.NIST_800_53, ComplianceFramework.STIG]
        )
        
        # Compliance Report Template
        compliance_template = """
# {{ compliance_framework }} Compliance Report

**Report Period:** {{ report_start_date | datetime_format }} to {{ report_end_date | datetime_format }}
**Generated:** {{ generation_date | datetime_format }}
**Classification:** {{ classification_level }}

## Executive Summary

### Compliance Overview
- **Total Controls Assessed:** {{ total_controls }}
- **Overall Compliance Rate:** {{ overall_compliance_rate }}%
- **Controls Fully Implemented:** {{ fully_implemented_count }}
- **Controls Partially Implemented:** {{ partially_implemented_count }}
- **Controls Not Implemented:** {{ not_implemented_count }}

### Risk Summary
- **Critical Risk Controls:** {{ critical_risk_count }}
- **High Risk Controls:** {{ high_risk_count }}
- **Medium Risk Controls:** {{ medium_risk_count }}
- **Low Risk Controls:** {{ low_risk_count }}

## Control Assessment Summary

{% for control_family, controls in controls_by_family.items() %}
### {{ control_family }}

| Control ID | Title | Status | Effectiveness | Risk Level | Last Assessed |
|------------|-------|--------|---------------|-----------|---------------|
{% for control in controls %}
| {{ control.control_id }} | {{ control.title }} | {{ control.status }} | {{ control.effectiveness_score | round(2) }} | {{ control.risk_level }} | {{ control.last_assessed | datetime_format('%Y-%m-%d') }} |
{% endfor %}

{% endfor %}

## Findings and Recommendations

### Critical Findings
{% for finding in critical_findings %}
#### {{ finding.title }}
**Control:** {{ finding.control_id }}
**Severity:** {{ finding.severity }}

{{ finding.description }}

**Recommendation:** {{ finding.remediation_recommendation }}
**Target Date:** {{ finding.target_remediation_date | datetime_format('%Y-%m-%d') }}

{% endfor %}

### High Priority Recommendations
{% for recommendation in high_priority_recommendations %}
- {{ recommendation }}
{% endfor %}

## Remediation Plan

### Immediate Actions (0-30 days)
{% for action in immediate_actions %}
- {{ action }}
{% endfor %}

### Short Term Actions (30-90 days) 
{% for action in short_term_actions %}
- {{ action }}
{% endfor %}

### Long Term Actions (90+ days)
{% for action in long_term_actions %}
- {{ action }}
{% endfor %}

## Appendices

### Appendix A: Control Implementation Details
[Detailed implementation information for each control]

### Appendix B: Evidence Summary
[Summary of evidence collected for control assessments]

### Appendix C: Assessment Methodology
[Description of assessment methods and procedures used]

---
*This report was automatically generated from the Security Control Documentation System*
*Classification: {{ classification_level }}*
        """
        
        self._add_template(
            template_id="compliance_report",
            document_type=DocumentType.COMPLIANCE_REPORT,
            template_name="Comprehensive Compliance Report",
            template_content=compliance_template,
            supported_formats=[OutputFormat.HTML, OutputFormat.PDF, OutputFormat.MARKDOWN],
            compliance_frameworks=[ComplianceFramework.NIST_800_53, ComplianceFramework.DOD_8500, ComplianceFramework.FISMA]
        )
    
    def _add_template(self,
                     template_id: str,
                     document_type: DocumentType,
                     template_name: str,
                     template_content: str,
                     supported_formats: List[OutputFormat],
                     compliance_frameworks: List[ComplianceFramework]):
        """Add a template to the template registry"""
        template = DocumentTemplate(
            template_id=template_id,
            document_type=document_type,
            template_name=template_name,
            template_content=template_content,
            supported_formats=supported_formats,
            compliance_frameworks=compliance_frameworks
        )
        
        self.document_templates[template_id] = template
        
        # Save template to file
        template_file = self.templates_directory / f"{template_id}.jinja2"
        with open(template_file, 'w') as f:
            f.write(template_content)
    
    async def generate_control_implementation_statement(self,
                                                      control_id: str,
                                                      output_format: OutputFormat = OutputFormat.HTML) -> GeneratedDocument:
        """
        Generate control implementation statement
        
        Args:
            control_id: Control identifier
            output_format: Desired output format
            
        Returns:
            Generated document
        """
        try:
            generation_start = datetime.now()
            document_id = str(uuid.uuid4())
            
            # Gather data for the document
            context = await self._gather_control_context(control_id)
            
            # Generate document
            document = await self._generate_document(
                document_id=document_id,
                document_type=DocumentType.CONTROL_IMPLEMENTATION_STATEMENT,
                template_id="control_implementation_statement",
                context=context,
                output_format=output_format,
                title=f"Control Implementation Statement - {control_id}"
            )
            
            # Update metrics
            generation_time = (datetime.now() - generation_start).total_seconds()
            await self._update_generation_metrics(
                document_type=DocumentType.CONTROL_IMPLEMENTATION_STATEMENT,
                output_format=output_format,
                generation_time=generation_time
            )
            
            self.logger.info(f"Generated control implementation statement for {control_id}")
            return document
            
        except Exception as e:
            self.logger.error(f"Failed to generate control implementation statement for {control_id}: {e}")
            raise
    
    async def generate_compliance_report(self,  
                                       compliance_framework: ComplianceFramework,
                                       control_ids: Optional[List[str]] = None,
                                       output_format: OutputFormat = OutputFormat.PDF) -> GeneratedDocument:
        """
        Generate comprehensive compliance report
        
        Args:
            compliance_framework: Compliance framework to report on
            control_ids: Optional list of specific controls to include
            output_format: Desired output format
            
        Returns:
            Generated document
        """
        try:
            generation_start = datetime.now()
            document_id = str(uuid.uuid4())
            
            # Gather compliance data
            context = await self._gather_compliance_context(compliance_framework, control_ids)
            
            # Generate document
            document = await self._generate_document(
                document_id=document_id,
                document_type=DocumentType.COMPLIANCE_REPORT,
                template_id="compliance_report",
                context=context,
                output_format=output_format,
                title=f"{compliance_framework.value} Compliance Report"
            )
            
            # Update metrics
            generation_time = (datetime.now() - generation_start).total_seconds()
            await self._update_generation_metrics(
                document_type=DocumentType.COMPLIANCE_REPORT,
                output_format=output_format,
                generation_time=generation_time
            )
            
            self.logger.info(f"Generated compliance report for {compliance_framework.value}")
            return document
            
        except Exception as e:
            self.logger.error(f"Failed to generate compliance report: {e}")
            raise
    
    async def generate_security_baseline(self,
                                       system_name: str,
                                       control_ids: List[str],
                                       output_format: OutputFormat = OutputFormat.HTML) -> GeneratedDocument:
        """
        Generate security configuration baseline document
        
        Args:
            system_name: Name of the system
            control_ids: List of controls to include in baseline
            output_format: Desired output format
            
        Returns:
            Generated document
        """
        try:
            generation_start = datetime.now()
            document_id = str(uuid.uuid4())
            
            # Gather baseline data
            context = await self._gather_baseline_context(system_name, control_ids)
            
            # Generate document
            document = await self._generate_document(
                document_id=document_id,
                document_type=DocumentType.SECURITY_CONFIGURATION_BASELINE,
                template_id="security_baseline",
                context=context,
                output_format=output_format,
                title=f"Security Configuration Baseline - {system_name}"
            )
            
            # Update metrics
            generation_time = (datetime.now() - generation_start).total_seconds()
            await self._update_generation_metrics(
                document_type=DocumentType.SECURITY_CONFIGURATION_BASELINE,
                output_format=output_format,
                generation_time=generation_time
            )
            
            self.logger.info(f"Generated security baseline for {system_name}")
            return document
            
        except Exception as e:
            self.logger.error(f"Failed to generate security baseline: {e}")
            raise
    
    async def _gather_control_context(self, control_id: str) -> Dict[str, Any]:
        """Gather context data for control implementation statement"""
        context = {
            "control_id": control_id,
            "generation_date": datetime.now(),
            "control_title": "Unknown Control",
            "control_description": "Control description not available",
            "framework": "Unknown Framework",
            "implementation_summary": "Implementation details not available",
            "implementations": [],
            "evidence_items": [],
            "assessment_result": None,
            "residual_risk_assessment": "Risk assessment not available"
        }
        
        try:
            # Get control information from mapping engine
            if self.control_mapping_engine:
                control_status = await self.control_mapping_engine.get_control_status(control_id)
                if control_status:
                    context.update({
                        "control_title": control_status.get("title", "Unknown Control"),
                        "control_description": control_status.get("description", "Control description not available"),
                        "framework": control_status.get("framework", "Unknown Framework"),
                        "implementations": control_status.get("implementations", [])
                    })
            
            # Get evidence from evidence collector
            if self.evidence_collector:
                evidence_items = await self.evidence_collector.collect_evidence_for_control(control_id)
                context["evidence_items"] = [
                    {
                        "title": e.title,
                        "evidence_type": e.evidence_type.value,
                        "source": e.source.value,
                        "quality_level": e.quality_level.value,
                        "collection_timestamp": e.collection_timestamp,
                        "description": e.description
                    }
                    for e in evidence_items
                ]
            
            # Get assessment results from assessment framework
            if self.assessment_framework:
                # Find most recent assessment
                recent_assessment = None
                for assessment in self.assessment_framework.assessments.values():
                    if assessment.control_id == control_id:
                        if not recent_assessment or assessment.assessment_date > recent_assessment.assessment_date:
                            recent_assessment = assessment
                
                if recent_assessment:
                    context["assessment_result"] = {
                        "effectiveness_score": recent_assessment.effectiveness_score,
                        "effectiveness_level": recent_assessment.effectiveness_level.value,
                        "risk_level": recent_assessment.risk_level.value,
                        "findings": [
                            {
                                "severity": f.severity.value,
                                "title": f.title,
                                "description": f.description,
                                "remediation_recommendation": f.remediation_recommendation
                            }
                            for f in recent_assessment.findings
                        ],
                        "recommendations": recent_assessment.recommendations
                    }
                    
                    context["assessment_date"] = recent_assessment.assessment_date
            
            # Create implementation summary
            if context["implementations"]:
                impl_count = len(context["implementations"])
                implemented_count = len([i for i in context["implementations"] 
                                       if i.get("status") == "implemented"])
                context["implementation_summary"] = (
                    f"Control {control_id} has {impl_count} implementation(s) with "
                    f"{implemented_count} currently implemented."
                )
            
            # Create residual risk assessment
            if context["assessment_result"]:
                risk_level = context["assessment_result"]["risk_level"]
                effectiveness = context["assessment_result"]["effectiveness_level"]
                context["residual_risk_assessment"] = (
                    f"Based on the current {effectiveness} implementation, "
                    f"the residual risk level is assessed as {risk_level}."
                )
        
        except Exception as e:
            self.logger.error(f"Failed to gather control context for {control_id}: {e}")
        
        return context
    
    async def _gather_compliance_context(self, 
                                       compliance_framework: ComplianceFramework,
                                       control_ids: Optional[List[str]] = None) -> Dict[str, Any]:
        """Gather context data for compliance report"""
        context = {
            "compliance_framework": compliance_framework.value,
            "generation_date": datetime.now(),
            "report_start_date": datetime.now() - timedelta(days=365),
            "report_end_date": datetime.now(),
            "classification_level": "UNCLASSIFIED//FOR OFFICIAL USE ONLY",
            "total_controls": 0,
            "overall_compliance_rate": 0.0,
            "fully_implemented_count": 0,
            "partially_implemented_count": 0,
            "not_implemented_count": 0,
            "critical_risk_count": 0,
            "high_risk_count": 0,
            "medium_risk_count": 0,
            "low_risk_count": 0,
            "controls_by_family": {},
            "critical_findings": [],
            "high_priority_recommendations": [],
            "immediate_actions": [],
            "short_term_actions": [],
            "long_term_actions": []
        }
        
        try:
            # Get compliance dashboard from control mapping engine
            if self.control_mapping_engine:
                dashboard = await self.control_mapping_engine.get_compliance_dashboard()
                
                # Extract summary statistics
                summary = dashboard.get("summary", {})
                context.update({
                    "total_controls": summary.get("total_controls", 0),
                    "overall_compliance_rate": summary.get("overall_compliance_rate", 0.0) * 100
                })
                
                # Extract framework-specific data
                framework_compliance = dashboard.get("framework_compliance", {})
                framework_data = framework_compliance.get(compliance_framework.value, {})
                if framework_data:
                    context.update({
                        "total_controls": framework_data.get("total_controls", 0),
                        "fully_implemented_count": framework_data.get("implemented_controls", 0),
                        "overall_compliance_rate": framework_data.get("compliance_rate", 0.0) * 100
                    })
                
                # Extract risk summary
                risk_summary = dashboard.get("risk_summary", {})
                context.update({
                    "high_risk_count": risk_summary.get("high_risk_controls", 0),
                    "medium_risk_count": risk_summary.get("medium_risk_controls", 0),
                    "low_risk_count": risk_summary.get("low_risk_controls", 0)
                })
            
            # Get assessment data from assessment framework
            if self.assessment_framework:
                assessment_dashboard = await self.assessment_framework.get_assessment_dashboard()
                
                # Extract findings
                high_priority_items = assessment_dashboard.get("high_priority_items", {})
                critical_findings_data = high_priority_items.get("critical_findings", [])
                
                context["critical_findings"] = [
                    {
                        "title": f.get("title", ""),
                        "control_id": f.get("control_id", ""),
                        "severity": "critical",
                        "description": f"Critical finding in control {f.get('control_id', '')}",
                        "remediation_recommendation": "Immediate remediation required",
                        "target_remediation_date": datetime.now() + timedelta(days=30)
                    }
                    for f in critical_findings_data[:10]  # Top 10
                ]
                
                context["critical_risk_count"] = len(critical_findings_data)
            
            # Generate recommendations based on findings
            if context["critical_findings"]:
                context["immediate_actions"] = [
                    f"Address critical finding: {f['title']}" 
                    for f in context["critical_findings"][:5]
                ]
            
            context["high_priority_recommendations"] = [
                "Implement continuous monitoring for all critical controls",
                "Conduct quarterly assessments of high-risk controls", 
                "Establish incident response procedures for control failures",
                "Provide additional training on compliance requirements"
            ]
            
            context["short_term_actions"] = [
                "Update security configuration baselines",
                "Implement automated compliance monitoring",
                "Conduct staff training on new procedures"
            ]
            
            context["long_term_actions"] = [
                "Establish maturity improvement program",
                "Implement advanced threat detection capabilities",
                "Develop predictive compliance analytics"
            ]
            
            # Group controls by family (simplified for demo)
            context["controls_by_family"] = {
                "Access Control": [
                    {
                        "control_id": "AC-3",
                        "title": "Access Enforcement",
                        "status": "Implemented",
                        "effectiveness_score": 0.85,
                        "risk_level": "Low",
                        "last_assessed": datetime.now() - timedelta(days=30)
                    }
                ],
                "Audit and Accountability": [
                    {
                        "control_id": "AU-2",
                        "title": "Event Logging",
                        "status": "Implemented",
                        "effectiveness_score": 0.90,
                        "risk_level": "Low",
                        "last_assessed": datetime.now() - timedelta(days=15)
                    }
                ]
            }
        
        except Exception as e:
            self.logger.error(f"Failed to gather compliance context: {e}")
        
        return context
    
    async def _gather_baseline_context(self, 
                                     system_name: str,
                                     control_ids: List[str]) -> Dict[str, Any]:
        """Gather context data for security baseline document"""
        context = {
            "system_name": system_name,
            "baseline_version": "1.0",
            "last_updated": datetime.now(),
            "generation_date": datetime.now(),
            "classification_level": "UNCLASSIFIED//FOR OFFICIAL USE ONLY",
            "compliance_framework": "NIST SP 800-53",
            "control_configurations": {},
            "automated_monitors": [],
            "compliance_rate": 85.0,
            "last_assessment_date": datetime.now() - timedelta(days=30),
            "next_assessment_date": datetime.now() + timedelta(days=90)
        }
        
        try:
            # Gather configuration for each control
            for control_id in control_ids:
                control_config = {
                    "title": f"Control {control_id}",
                    "status": "Implemented",
                    "requirements": [
                        "Requirement 1: Basic implementation",
                        "Requirement 2: Monitoring enabled",  
                        "Requirement 3: Documentation current"
                    ],
                    "current_config": f"# Configuration for {control_id}\nstatus: enabled\nmonitoring: true\n",
                    "deviations": []
                }
                
                # Get actual control data if available
                if self.control_mapping_engine:
                    control_status = await self.control_mapping_engine.get_control_status(control_id)
                    if control_status:
                        control_config["title"] = control_status.get("title", control_config["title"])
                        
                        implementations = control_status.get("implementations", [])
                        if implementations:
                            first_impl = implementations[0]
                            control_config["status"] = first_impl.get("status", "Unknown").title()
                            
                            # Use configuration settings if available
                            config_settings = first_impl.get("configuration", {})
                            if config_settings:
                                config_lines = [f"{k}: {v}" for k, v in config_settings.items()]
                                control_config["current_config"] = "\n".join(config_lines)
                
                context["control_configurations"][control_id] = control_config
            
            # Add automated monitors
            context["automated_monitors"] = [
                {
                    "name": "Configuration Drift Monitor",
                    "description": "Monitors for unauthorized configuration changes",
                    "frequency": "Continuous",
                    "threshold": "Any change"
                },
                {
                    "name": "Compliance Status Monitor", 
                    "description": "Tracks compliance status for all controls",
                    "frequency": "Daily",
                    "threshold": "< 95% compliance"
                },
                {
                    "name": "Security Event Monitor",
                    "description": "Monitors for security-related events",
                    "frequency": "Real-time",
                    "threshold": "Any security event"
                }
            ]
        
        except Exception as e:
            self.logger.error(f"Failed to gather baseline context: {e}")
        
        return context
    
    async def _generate_document(self,
                               document_id: str,
                               document_type: DocumentType,
                               template_id: str,
                               context: Dict[str, Any],
                               output_format: OutputFormat,
                               title: str) -> GeneratedDocument:
        """Generate document from template and context"""
        try:
            # Get template
            template = self.document_templates.get(template_id)
            if not template:
                raise ValueError(f"Template {template_id} not found")
            
            # Render template
            jinja_template = self.jinja_env.from_string(template.template_content)
            rendered_content = jinja_template.render(**context)
            
            # Convert to desired output format
            final_content, file_path = await self._convert_to_format(
                content=rendered_content,
                output_format=output_format,
                document_id=document_id,
                title=title
            )
            
            # Create document object
            document = GeneratedDocument(
                document_id=document_id,
                document_type=document_type,
                title=title,
                content=final_content,
                output_format=output_format,
                file_path=file_path,
                control_ids=context.get("control_ids", []),
                template_id=template_id,
                metadata={
                    "generation_context": {k: str(v) for k, v in context.items() if k != "evidence_items"},
                    "template_version": template.updated_date.isoformat()
                }
            )
            
            # Store document
            self.generated_documents[document_id] = document
            
            # Log generation
            if self.audit_logger:
                await self.audit_logger.log_event({
                    "event_type": "document_generated",
                    "document_id": document_id,
                    "document_type": document_type.value,
                    "output_format": output_format.value,
                    "template_id": template_id,
                    "file_path": file_path,
                    "timestamp": datetime.now().isoformat()
                })
            
            return document
            
        except Exception as e:
            self.logger.error(f"Failed to generate document: {e}")
            raise
    
    async def _convert_to_format(self,
                               content: str,
                               output_format: OutputFormat,
                               document_id: str,
                               title: str) -> Tuple[str, str]:
        """Convert content to specified output format"""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            safe_title = "".join(c for c in title if c.isalnum() or c in (' ', '-', '_')).rstrip()
            safe_title = safe_title.replace(' ', '_')
            
            if output_format == OutputFormat.MARKDOWN:
                file_path = self.output_directory / "markdown" / f"{safe_title}_{timestamp}.md"
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(content)
                return content, str(file_path)
            
            elif output_format == OutputFormat.HTML:
                # Convert markdown to HTML
                html_content = markdown.markdown(content, extensions=['tables', 'toc'])
                
                # Wrap in HTML document
                full_html = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>{title}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        table {{ border-collapse: collapse; width: 100%; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
        .risk-critical {{ color: #FF0000; }}
        .risk-high {{ color: #FF6600; }}
        .risk-moderate {{ color: #FFAA00; }}
        .risk-low {{ color: #00AA00; }}
    </style>
</head>
<body>
{html_content}
</body>
</html>
                """
                
                file_path = self.output_directory / "html" / f"{safe_title}_{timestamp}.html"
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(full_html)
                return full_html, str(file_path)
            
            elif output_format == OutputFormat.PDF:
                # Convert markdown to HTML first
                html_content = markdown.markdown(content, extensions=['tables', 'toc'])
                
                # Create styled HTML
                full_html = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>{title}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; line-height: 1.6; }}
        h1 {{ color: #2c5aa0; border-bottom: 2px solid #2c5aa0; }}
        h2 {{ color: #2c5aa0; }}
        table {{ border-collapse: collapse; width: 100%; margin: 10px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
        .risk-critical {{ color: #FF0000; font-weight: bold; }}
        .risk-high {{ color: #FF6600; font-weight: bold; }}
    </style>
</head>
<body>
{html_content}
</body>
</html>
                """
                
                file_path = self.output_directory / "pdf" / f"{safe_title}_{timestamp}.pdf"
                
                # Convert HTML to PDF (requires wkhtmltopdf)
                try:
                    pdfkit.from_string(full_html, str(file_path))
                    return "PDF generated successfully", str(file_path)
                except Exception as e:
                    self.logger.warning(f"PDF generation failed, falling back to HTML: {e}")
                    # Fallback to HTML
                    file_path = self.output_directory / "html" / f"{safe_title}_{timestamp}.html"
                    with open(file_path, 'w', encoding='utf-8') as f:
                        f.write(full_html)
                    return full_html, str(file_path)
            
            elif output_format == OutputFormat.JSON:
                # Convert to structured JSON
                json_content = {
                    "document_id": document_id,
                    "title": title,
                    "content": content,
                    "generated_date": datetime.now().isoformat(),
                    "format": "json"
                }
                
                file_path = self.output_directory / "json" / f"{safe_title}_{timestamp}.json"
                with open(file_path, 'w', encoding='utf-8') as f:
                    json.dump(json_content, f, indent=2, default=str)
                return json.dumps(json_content, indent=2, default=str), str(file_path)
            
            else:
                # Default to markdown
                file_path = self.output_directory / "markdown" / f"{safe_title}_{timestamp}.md"
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(content)
                return content, str(file_path)
        
        except Exception as e:
            self.logger.error(f"Failed to convert to format {output_format}: {e}")
            raise
    
    async def _update_generation_metrics(self,
                                       document_type: DocumentType,
                                       output_format: OutputFormat,
                                       generation_time: float):
        """Update generation metrics"""
        try:
            self.metrics["total_documents_generated"] += 1
            self.metrics["last_generation"] = datetime.now()
            
            # Update by type
            type_key = document_type.value
            self.metrics["documents_by_type"][type_key] = self.metrics["documents_by_type"].get(type_key, 0) + 1
            
            # Update by format
            format_key = output_format.value
            self.metrics["documents_by_format"][format_key] = self.metrics["documents_by_format"].get(format_key, 0) + 1
            
            # Update average generation time
            current_avg = self.metrics["average_generation_time"]
            total_docs = self.metrics["total_documents_generated"]
            self.metrics["average_generation_time"] = (current_avg * (total_docs - 1) + generation_time) / total_docs
            
        except Exception as e:
            self.logger.error(f"Failed to update generation metrics: {e}")
    
    async def get_generation_dashboard(self) -> Dict[str, Any]:
        """
        Get documentation generation dashboard
        
        Returns:
            Dict containing dashboard data
        """
        try:
            # Calculate statistics
            total_documents = len(self.generated_documents)
            recent_documents = [
                doc for doc in self.generated_documents.values()
                if (datetime.now() - doc.generation_timestamp).days <= 7
            ]
            
            # Document type distribution
            type_distribution = {}
            format_distribution = {}
            
            for document in self.generated_documents.values():
                doc_type = document.document_type.value
                doc_format = document.output_format.value
                
                type_distribution[doc_type] = type_distribution.get(doc_type, 0) + 1
                format_distribution[doc_format] = format_distribution.get(doc_format, 0) + 1
            
            dashboard = {
                "summary": {
                    "total_documents_generated": total_documents,
                    "recent_documents": len(recent_documents),
                    "available_templates": len(self.document_templates),
                    "average_generation_time": self.metrics["average_generation_time"],
                    "last_generation": self.metrics["last_generation"].isoformat() if self.metrics["last_generation"] else None
                },
                "document_distribution": {
                    "by_type": type_distribution,
                    "by_format": format_distribution
                },
                "recent_activity": [
                    {
                        "document_id": doc.document_id,
                        "title": doc.title,
                        "type": doc.document_type.value,
                        "format": doc.output_format.value,
                        "generated": doc.generation_timestamp.isoformat(),
                        "file_path": doc.file_path
                    }
                    for doc in sorted(recent_documents, key=lambda x: x.generation_timestamp, reverse=True)[:10]
                ],
                "template_usage": self.metrics.get("template_usage", {}),
                "metrics": self.metrics.copy()
            }
            
            return dashboard
            
        except Exception as e:
            self.logger.error(f"Failed to generate dashboard: {e}")
            raise
    
    async def export_generated_documents(self, 
                                       document_type: Optional[DocumentType] = None,
                                       output_format: str = "json") -> str:
        """
        Export generated documents metadata
        
        Args:
            document_type: Optional filter by document type
            output_format: Export format (json, csv)
            
        Returns:
            str: Path to exported file
        """
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            type_suffix = f"_{document_type.value}" if document_type else "_all"
            export_file = self.output_directory / "reports" / f"generated_documents{type_suffix}_{timestamp}.{output_format}"
            
            # Filter documents
            if document_type:
                documents_to_export = [
                    doc for doc in self.generated_documents.values()
                    if doc.document_type == document_type
                ]
            else:
                documents_to_export = list(self.generated_documents.values())
            
            if output_format == "json":
                export_data = {
                    "metadata": {
                        "export_timestamp": datetime.now().isoformat(),
                        "document_type_filter": document_type.value if document_type else None,
                        "total_documents": len(documents_to_export)
                    },
                    "documents": [
                        {
                            "document_id": doc.document_id,
                            "document_type": doc.document_type.value,
                            "title": doc.title,
                            "output_format": doc.output_format.value,
                            "file_path": doc.file_path,
                            "control_ids": doc.control_ids,
                            "generation_timestamp": doc.generation_timestamp.isoformat(),
                            "template_id": doc.template_id,
                            "tags": doc.tags
                        }
                        for doc in documents_to_export
                    ]
                }
                
                with open(export_file, 'w') as f:
                    json.dump(export_data, f, indent=2, default=str)
            
            elif output_format == "csv":
                with open(export_file, 'w', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow([
                        "Document ID", "Type", "Title", "Format", "File Path",
                        "Control IDs", "Generated", "Template ID"
                    ])
                    
                    for doc in documents_to_export:
                        writer.writerow([
                            doc.document_id,
                            doc.document_type.value,
                            doc.title,
                            doc.output_format.value,
                            doc.file_path,
                            ",".join(doc.control_ids),
                            doc.generation_timestamp.isoformat(),
                            doc.template_id
                        ])
            
            self.logger.info(f"Exported {len(documents_to_export)} document records to {export_file}")
            return str(export_file)
            
        except Exception as e:
            self.logger.error(f"Failed to export documents: {e}")
            raise
    
    async def health_check(self) -> Dict[str, Any]:
        """
        Perform health check of the documentation generator
        
        Returns:
            Dict containing health status
        """
        try:
            status = {
                "status": "healthy",
                "timestamp": datetime.now().isoformat(),
                "metrics": self.metrics.copy(),
                "template_engine_status": {
                    "jinja_initialized": self.jinja_env is not None,
                    "templates_loaded": len(self.document_templates),
                    "template_directory_exists": self.templates_directory.exists()
                },
                "output_directories": {
                    "output_directory_exists": self.output_directory.exists(),
                    "output_directory_writable": os.access(self.output_directory, os.W_OK),
                    "subdirectories_exist": all([
                        (self.output_directory / subdir).exists()
                        for subdir in ["html", "pdf", "markdown", "json", "reports"]
                    ])
                },
                "integration_status": {
                    "control_mapping_engine": self.control_mapping_engine is not None,
                    "evidence_collector": self.evidence_collector is not None,
                    "assessment_framework": self.assessment_framework is not None,
                    "audit_logger": self.audit_logger is not None
                },
                "generation_capabilities": {
                    "total_generated_documents": len(self.generated_documents),
                    "available_document_types": [dt.value for dt in DocumentType],
                    "supported_output_formats": [of.value for of in OutputFormat]
                }
            }
            
            # Check for critical issues
            critical_issues = []
            
            if not self.output_directory.exists():
                critical_issues.append("Output directory does not exist")
            
            if not self.templates_directory.exists():
                critical_issues.append("Templates directory does not exist")
            
            if self.jinja_env is None:
                critical_issues.append("Template engine not initialized")
            
            if len(self.document_templates) == 0:
                critical_issues.append("No document templates loaded")
            
            if critical_issues:
                status["status"] = "unhealthy"
                status["critical_issues"] = critical_issues
            
            return status
            
        except Exception as e:
            return {
                "status": "error",
                "timestamp": datetime.now().isoformat(),
                "error": str(e)
            }

async def create_documentation_generator(
    output_directory: str = "./generated_documentation",
    templates_directory: str = "./documentation_templates",
    control_mapping_engine: Optional[Any] = None,
    evidence_collector: Optional[Any] = None,
    assessment_framework: Optional[Any] = None,
    audit_logger: Optional[Any] = None
) -> SecurityControlDocumentationGenerator:
    """
    Factory function to create a Security Control Documentation Generator
    
    Args:
        output_directory: Directory for generated documentation output
        templates_directory: Directory containing document templates
        control_mapping_engine: Control mapping engine instance
        evidence_collector: Evidence collector instance
        assessment_framework: Assessment framework instance
        audit_logger: Audit logging system instance
        
    Returns:
        Initialized SecurityControlDocumentationGenerator
    """
    generator = SecurityControlDocumentationGenerator(
        output_directory=output_directory,
        templates_directory=templates_directory,
        control_mapping_engine=control_mapping_engine,
        evidence_collector=evidence_collector,
        assessment_framework=assessment_framework,
        audit_logger=audit_logger
    )
    
    return generator

# Example usage and testing
if __name__ == "__main__":
    import os
    
    async def demo_documentation_generator():
        """Demonstrate the Security Control Documentation Generator"""
        print("Security Control Documentation Generator Demo")
        print("=" * 60)
        
        # Create generator
        generator = await create_documentation_generator()
        
        # Show initial status
        health = await generator.health_check()
        print(f"Generator Status: {health['status']}")
        print(f"Templates Loaded: {health['template_engine_status']['templates_loaded']}")
        print(f"Output Directory: {health['output_directories']['output_directory_exists']}")
        
        # Generate control implementation statements
        test_controls = ["IA-2", "AC-3", "AU-2"]
        
        for control_id in test_controls:
            try:
                print(f"\nGenerating implementation statement for {control_id}...")
                document = await generator.generate_control_implementation_statement(
                    control_id=control_id,
                    output_format=OutputFormat.HTML
                )
                
                print(f"Generated: {document.title}")
                print(f"Document ID: {document.document_id}")
                print(f"File Path: {document.file_path}")
                print(f"Content Length: {len(document.content)} characters")
                
            except Exception as e:
                print(f"Failed to generate statement for {control_id}: {e}")
        
        # Generate compliance report
        try:
            print(f"\nGenerating NIST 800-53 compliance report...")
            compliance_doc = await generator.generate_compliance_report(
                compliance_framework=ComplianceFramework.NIST_800_53,
                output_format=OutputFormat.HTML
            )
            
            print(f"Generated: {compliance_doc.title}")
            print(f"Document ID: {compliance_doc.document_id}")
            print(f"File Path: {compliance_doc.file_path}")
            
        except Exception as e:
            print(f"Failed to generate compliance report: {e}")
        
        # Generate security baseline
        try:
            print(f"\nGenerating security baseline...")
            baseline_doc = await generator.generate_security_baseline(
                system_name="Demo Security System",
                control_ids=["IA-2", "AC-3", "AU-2"],
                output_format=OutputFormat.HTML
            )
            
            print(f"Generated: {baseline_doc.title}")
            print(f"Document ID: {baseline_doc.document_id}")
            print(f"File Path: {baseline_doc.file_path}")
            
        except Exception as e:
            print(f"Failed to generate security baseline: {e}")
        
        # Show generation dashboard
        dashboard = await generator.get_generation_dashboard()
        print(f"\nGeneration Dashboard:")
        print(f"Total Documents: {dashboard['summary']['total_documents_generated']}")
        print(f"Recent Documents: {dashboard['summary']['recent_documents']}")
        print(f"Available Templates: {dashboard['summary']['available_templates']}")
        
        # Export documents metadata
        try:
            export_file = await generator.export_generated_documents()
            print(f"Exported documents metadata to: {export_file}")
        except Exception as e:
            print(f"Failed to export documents: {e}")
        
        print("\nDemo completed successfully!")
        
        # Show generated files
        print(f"\nGenerated files in {generator.output_directory}:")
        for subdir in ["html", "pdf", "markdown", "json"]:
            subdir_path = generator.output_directory / subdir
            if subdir_path.exists():
                files = list(subdir_path.glob("*"))
                if files:
                    print(f"  {subdir}/: {len(files)} files")
                    for file in files[:3]:  # Show first 3 files
                        print(f"    - {file.name}")
    
    # Run the demo
    asyncio.run(demo_documentation_generator())