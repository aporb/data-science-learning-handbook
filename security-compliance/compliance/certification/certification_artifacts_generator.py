"""
Certification Artifacts Generator for DoD/Federal Compliance
==========================================================

Enterprise-grade certification artifacts generator that automates the creation
of critical compliance documentation required for DoD and federal system
authorization processes. Integrates with risk assessment engine and existing
audit infrastructure to generate ATO packages, FISMA compliance documentation,
and other certification artifacts.

Key Features:
- Automated ATO (Authority to Operate) package generation
- FISMA compliance documentation automation
- Security Assessment Plan (SAP) generation
- Plan of Action and Milestones (POA&M) automation
- Control assessment documentation
- Risk assessment report generation
- Continuous monitoring plan creation
- Export to government-standard formats (PDF, DOCX, XML)

Supported Frameworks:
- NIST RMF (Risk Management Framework)
- NIST SP 800-53 Security Controls
- FISMA (Federal Information Security Management Act)
- DoD 8510.01 RMF Implementation
- FedRAMP (Federal Risk and Authorization Management Program)
- CMMC (Cybersecurity Maturity Model Certification)

Classification: UNCLASSIFIED//FOR OFFICIAL USE ONLY
Version: 1.0 - Certification Artifacts Generator
Author: Security Compliance Team
Date: 2025-07-28
"""

import asyncio
import json
import logging
import time
import hashlib
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Tuple, Set, Union
from uuid import UUID, uuid4
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
import aiofiles
import aiohttp
from jinja2 import Environment, FileSystemLoader, Template
import markdown
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib import colors
from reportlab.lib.units import inch
import xml.etree.ElementTree as ET
from xml.dom import minidom

# Import from existing infrastructure
from ..risk.risk_assessment_engine import (
    AdvancedRiskAssessmentEngine, RiskAssessment, RiskCategory,
    RiskImpactLevel, RiskLikelihood, TreatmentStrategy
)
from ...audits.audit_logger import AuditLogger
from ...multi_classification.enhanced_classification_engine import ClassificationLevel


class ArtifactType(Enum):
    """Types of certification artifacts that can be generated."""
    ATO_PACKAGE = "ato_package"
    FISMA_DOCUMENTATION = "fisma_documentation"
    SECURITY_ASSESSMENT_PLAN = "security_assessment_plan"
    POAM = "plan_of_action_milestones"
    CONTROL_ASSESSMENT = "control_assessment"
    RISK_ASSESSMENT_REPORT = "risk_assessment_report"
    CONTINUOUS_MONITORING_PLAN = "continuous_monitoring_plan"
    SYSTEM_SECURITY_PLAN = "system_security_plan"
    CONTINGENCY_PLAN = "contingency_plan"
    INCIDENT_RESPONSE_PLAN = "incident_response_plan"


class DocumentFormat(Enum):
    """Supported document output formats."""
    PDF = "pdf"
    DOCX = "docx"
    HTML = "html"
    MARKDOWN = "markdown"
    XML = "xml"
    JSON = "json"


class ComplianceFramework(Enum):
    """Supported compliance frameworks."""
    NIST_RMF = "nist_rmf"
    FISMA = "fisma"
    FEDRAMP = "fedramp"
    DOD_RMF = "dod_rmf"
    CMMC = "cmmc"
    SOC2 = "soc2"
    ISO27001 = "iso27001"


@dataclass
class SystemInformation:
    """System information for certification artifacts."""
    system_id: str
    system_name: str
    system_description: str
    system_type: str
    classification_level: ClassificationLevel
    categorization: Dict[str, str]
    system_owner: str
    system_administrator: str
    authorizing_official: str
    information_types: List[Dict[str, Any]]
    operating_environment: str
    deployment_model: str
    service_model: str


@dataclass
class ControlImplementation:
    """Security control implementation details."""
    control_id: str
    control_name: str
    control_family: str
    implementation_status: str  # implemented, partially_implemented, planned, not_applicable
    implementation_description: str
    responsible_role: str
    implementation_date: Optional[datetime]
    testing_procedures: List[str]
    assessment_results: Dict[str, Any]
    findings: List[str]
    remediation_actions: List[str]


@dataclass
class POAMItem:
    """Plan of Action and Milestones item."""
    poam_id: str
    control_id: str
    weakness_description: str
    risk_level: str
    threat_sources: List[str]
    predisposing_conditions: List[str]
    likelihood: str
    impact: str
    risk_response: str
    resources_required: str
    responsible_parties: List[str]
    planned_completion_date: datetime
    milestones: List[Dict[str, Any]]
    status: str
    comments: str


@dataclass
class CertificationPackage:
    """Complete certification package structure."""
    package_id: str
    system_info: SystemInformation
    framework: ComplianceFramework
    creation_date: datetime
    created_by: str
    documents: Dict[ArtifactType, str]  # Maps artifact type to file path
    risk_assessments: List[RiskAssessment]
    control_implementations: List[ControlImplementation]
    poam_items: List[POAMItem]
    assessment_results: Dict[str, Any]
    approval_status: str
    expiration_date: Optional[datetime]


class TemplateManager:
    """Manages document templates for artifact generation."""
    
    def __init__(self, template_dir: Optional[Path] = None):
        self.template_dir = template_dir or Path(__file__).parent / "templates"
        self.jinja_env = Environment(
            loader=FileSystemLoader(str(self.template_dir)),
            autoescape=True
        )
        self.logger = logging.getLogger(__name__)
    
    async def load_template(self, artifact_type: ArtifactType, framework: ComplianceFramework) -> Template:
        """Load template for specific artifact type and framework."""
        try:
            template_name = f"{framework.value}_{artifact_type.value}.j2"
            template_path = self.template_dir / template_name
            
            if not template_path.exists():
                # Fall back to generic template
                template_name = f"generic_{artifact_type.value}.j2"
            
            return self.jinja_env.get_template(template_name)
            
        except Exception as e:
            self.logger.error(f"Failed to load template {template_name}: {e}")
            raise
    
    async def render_template(self, template: Template, context: Dict[str, Any]) -> str:
        """Render template with provided context."""
        try:
            return template.render(**context)
        except Exception as e:
            self.logger.error(f"Template rendering failed: {e}")
            raise


class DocumentGenerator:
    """Generates documents in various formats from templates."""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    async def generate_pdf(self, content: str, output_path: Path, title: str = "Document") -> str:
        """Generate PDF document from content."""
        try:
            doc = SimpleDocTemplate(str(output_path), pagesize=letter)
            styles = getSampleStyleSheet()
            story = []
            
            # Add title
            title_style = ParagraphStyle(
                'CustomTitle',
                parent=styles['Heading1'],
                fontSize=16,
                spaceAfter=30,
                alignment=1  # Center alignment
            )
            story.append(Paragraph(title, title_style))
            story.append(Spacer(1, 12))
            
            # Convert markdown content to paragraphs
            lines = content.split('\n')
            for line in lines:
                if line.strip():
                    if line.startswith('#'):
                        # Header
                        level = len(line) - len(line.lstrip('#'))
                        header_text = line.lstrip('# ')
                        style_name = f'Heading{min(level, 6)}'
                        story.append(Paragraph(header_text, styles[style_name]))
                    else:
                        # Regular paragraph
                        story.append(Paragraph(line, styles['Normal']))
                    story.append(Spacer(1, 6))
            
            doc.build(story)
            return str(output_path)
            
        except Exception as e:
            self.logger.error(f"PDF generation failed: {e}")
            raise
    
    async def generate_html(self, content: str, output_path: Path, title: str = "Document") -> str:
        """Generate HTML document from markdown content."""
        try:
            html_content = markdown.markdown(content, extensions=['tables', 'codehilite'])
            
            full_html = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <title>{title}</title>
                <meta charset="UTF-8">
                <style>
                    body {{ font-family: Arial, sans-serif; margin: 40px; }}
                    table {{ border-collapse: collapse; width: 100%; }}
                    th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                    th {{ background-color: #f2f2f2; }}
                    .header {{ color: #333; border-bottom: 2px solid #333; }}
                </style>
            </head>
            <body>
                <h1 class="header">{title}</h1>
                {html_content}
            </body>
            </html>
            """
            
            async with aiofiles.open(output_path, 'w', encoding='utf-8') as f:
                await f.write(full_html)
            
            return str(output_path)
            
        except Exception as e:
            self.logger.error(f"HTML generation failed: {e}")
            raise
    
    async def generate_xml(self, data: Dict[str, Any], output_path: Path, root_name: str = "document") -> str:
        """Generate XML document from data."""
        try:
            root = ET.Element(root_name)
            self._dict_to_xml(data, root)
            
            # Pretty print XML
            rough_string = ET.tostring(root, 'unicode')
            reparsed = minidom.parseString(rough_string)
            pretty_xml = reparsed.toprettyxml(indent="  ")
            
            async with aiofiles.open(output_path, 'w', encoding='utf-8') as f:
                await f.write(pretty_xml)
            
            return str(output_path)
            
        except Exception as e:
            self.logger.error(f"XML generation failed: {e}")
            raise
    
    def _dict_to_xml(self, data: Dict[str, Any], parent: ET.Element):
        """Convert dictionary to XML elements."""
        for key, value in data.items():
            if isinstance(value, dict):
                child = ET.SubElement(parent, key)
                self._dict_to_xml(value, child)
            elif isinstance(value, list):
                for item in value:
                    child = ET.SubElement(parent, key)
                    if isinstance(item, dict):
                        self._dict_to_xml(item, child)
                    else:
                        child.text = str(item)
            else:
                child = ET.SubElement(parent, key)
                child.text = str(value)


class ATOPackageGenerator:
    """Generator for Authority to Operate (ATO) packages."""
    
    def __init__(self, template_manager: TemplateManager, doc_generator: DocumentGenerator):
        self.template_manager = template_manager
        self.doc_generator = doc_generator
        self.logger = logging.getLogger(__name__)
    
    async def generate_ato_package(
        self,
        system_info: SystemInformation,
        risk_assessments: List[RiskAssessment],
        control_implementations: List[ControlImplementation],
        framework: ComplianceFramework = ComplianceFramework.NIST_RMF,
        output_dir: Path = None
    ) -> CertificationPackage:
        """Generate complete ATO package."""
        try:
            package_id = str(uuid4())
            creation_date = datetime.now(timezone.utc)
            output_dir = output_dir or Path(f"./ato_packages/{package_id}")
            output_dir.mkdir(parents=True, exist_ok=True)
            
            self.logger.info(f"Generating ATO package {package_id} for system {system_info.system_id}")
            
            documents = {}
            
            # Generate System Security Plan (SSP)
            ssp_path = await self._generate_system_security_plan(
                system_info, control_implementations, output_dir, framework
            )
            documents[ArtifactType.SYSTEM_SECURITY_PLAN] = ssp_path
            
            # Generate Security Assessment Plan (SAP)
            sap_path = await self._generate_security_assessment_plan(
                system_info, control_implementations, output_dir, framework
            )
            documents[ArtifactType.SECURITY_ASSESSMENT_PLAN] = sap_path
            
            # Generate Risk Assessment Report
            rar_path = await self._generate_risk_assessment_report(
                system_info, risk_assessments, output_dir, framework
            )
            documents[ArtifactType.RISK_ASSESSMENT_REPORT] = rar_path
            
            # Generate POA&M
            poam_items = await self._generate_poam_items(risk_assessments, control_implementations)
            poam_path = await self._generate_poam_document(
                system_info, poam_items, output_dir, framework
            )
            documents[ArtifactType.POAM] = poam_path
            
            # Generate Continuous Monitoring Plan
            cmp_path = await self._generate_continuous_monitoring_plan(
                system_info, control_implementations, output_dir, framework
            )
            documents[ArtifactType.CONTINUOUS_MONITORING_PLAN] = cmp_path
            
            # Create certification package
            cert_package = CertificationPackage(
                package_id=package_id,
                system_info=system_info,
                framework=framework,
                creation_date=creation_date,
                created_by="automated_generator",
                documents=documents,
                risk_assessments=risk_assessments,
                control_implementations=control_implementations,
                poam_items=poam_items,
                assessment_results=await self._generate_assessment_summary(
                    risk_assessments, control_implementations
                ),
                approval_status="pending_review",
                expiration_date=creation_date + timedelta(days=1095)  # 3 years
            )
            
            # Save package metadata
            package_metadata_path = output_dir / "package_metadata.json"
            async with aiofiles.open(package_metadata_path, 'w') as f:
                await f.write(json.dumps(asdict(cert_package), default=str, indent=2))
            
            self.logger.info(f"ATO package {package_id} generated successfully")
            return cert_package
            
        except Exception as e:
            self.logger.error(f"ATO package generation failed: {e}")
            raise
    
    async def _generate_system_security_plan(
        self,
        system_info: SystemInformation,
        control_implementations: List[ControlImplementation],
        output_dir: Path,
        framework: ComplianceFramework
    ) -> str:
        """Generate System Security Plan (SSP)."""
        try:
            template = await self.template_manager.load_template(
                ArtifactType.SYSTEM_SECURITY_PLAN, framework
            )
            
            context = {
                'system_info': asdict(system_info),
                'control_implementations': [asdict(impl) for impl in control_implementations],
                'generation_date': datetime.now(timezone.utc).isoformat(),
                'framework': framework.value
            }
            
            content = await self.template_manager.render_template(template, context)
            
            output_path = output_dir / f"system_security_plan_{system_info.system_id}.html"
            return await self.doc_generator.generate_html(
                content, output_path, f"System Security Plan - {system_info.system_name}"
            )
            
        except Exception as e:
            self.logger.error(f"SSP generation failed: {e}")
            raise
    
    async def _generate_security_assessment_plan(
        self,
        system_info: SystemInformation,
        control_implementations: List[ControlImplementation],
        output_dir: Path,
        framework: ComplianceFramework
    ) -> str:
        """Generate Security Assessment Plan (SAP)."""
        try:
            # Generate assessment procedures for each control
            assessment_procedures = {}
            for impl in control_implementations:
                assessment_procedures[impl.control_id] = {
                    'testing_procedures': impl.testing_procedures,
                    'assessment_methods': await self._generate_assessment_methods(impl),
                    'assessment_objects': await self._generate_assessment_objects(impl),
                    'assessment_evidence': await self._generate_required_evidence(impl)
                }
            
            template = await self.template_manager.load_template(
                ArtifactType.SECURITY_ASSESSMENT_PLAN, framework
            )
            
            context = {
                'system_info': asdict(system_info),
                'assessment_procedures': assessment_procedures,
                'assessment_scope': await self._define_assessment_scope(control_implementations),
                'assessment_timeline': await self._generate_assessment_timeline(),
                'assessment_team': await self._define_assessment_team(),
                'generation_date': datetime.now(timezone.utc).isoformat(),
                'framework': framework.value
            }
            
            content = await self.template_manager.render_template(template, context)
            
            output_path = output_dir / f"security_assessment_plan_{system_info.system_id}.html"
            return await self.doc_generator.generate_html(
                content, output_path, f"Security Assessment Plan - {system_info.system_name}"
            )
            
        except Exception as e:
            self.logger.error(f"SAP generation failed: {e}")
            raise
    
    async def _generate_risk_assessment_report(
        self,
        system_info: SystemInformation,
        risk_assessments: List[RiskAssessment],
        output_dir: Path,
        framework: ComplianceFramework
    ) -> str:
        """Generate Risk Assessment Report."""
        try:
            # Analyze risk data
            risk_summary = await self._analyze_risk_data(risk_assessments)
            
            template = await self.template_manager.load_template(
                ArtifactType.RISK_ASSESSMENT_REPORT, framework
            )
            
            context = {
                'system_info': asdict(system_info),
                'risk_assessments': [asdict(risk) for risk in risk_assessments],
                'risk_summary': risk_summary,
                'risk_methodology': await self._document_risk_methodology(),
                'threat_environment': await self._assess_threat_environment(system_info),
                'risk_recommendations': await self._generate_risk_recommendations(risk_assessments),
                'generation_date': datetime.now(timezone.utc).isoformat(),
                'framework': framework.value
            }
            
            content = await self.template_manager.render_template(template, context)
            
            output_path = output_dir / f"risk_assessment_report_{system_info.system_id}.html"
            return await self.doc_generator.generate_html(
                content, output_path, f"Risk Assessment Report - {system_info.system_name}"
            )
            
        except Exception as e:
            self.logger.error(f"Risk assessment report generation failed: {e}")
            raise
    
    async def _generate_poam_items(
        self,
        risk_assessments: List[RiskAssessment],
        control_implementations: List[ControlImplementation]
    ) -> List[POAMItem]:
        """Generate POA&M items from risk assessments and control findings."""
        poam_items = []
        
        try:
            # Create POA&M items from high and medium risks
            for risk in risk_assessments:
                if risk.inherent_risk_score >= 4.0:  # Medium and above
                    poam_item = POAMItem(
                        poam_id=f"POAM-{len(poam_items) + 1:03d}",
                        control_id=await self._identify_related_control(risk),
                        weakness_description=risk.description,
                        risk_level=self._risk_score_to_level(risk.inherent_risk_score),
                        threat_sources=await self._identify_threat_sources(risk),
                        predisposing_conditions=await self._identify_predisposing_conditions(risk),
                        likelihood=risk.inherent_likelihood.name,
                        impact=risk.inherent_impact.name,
                        risk_response=risk.treatments[0].strategy.value if risk.treatments else "accept",
                        resources_required=await self._estimate_resources_required(risk),
                        responsible_parties=await self._identify_responsible_parties(risk),
                        planned_completion_date=risk.treatments[0].target_date if risk.treatments else 
                                               datetime.now(timezone.utc) + timedelta(days=180),
                        milestones=await self._generate_milestones(risk),
                        status="open",
                        comments=f"Generated from risk assessment {risk.risk_id}"
                    )
                    poam_items.append(poam_item)
            
            # Create POA&M items from control implementation findings
            for impl in control_implementations:
                if impl.findings and impl.implementation_status != "implemented":
                    for finding in impl.findings:
                        poam_item = POAMItem(
                            poam_id=f"POAM-{len(poam_items) + 1:03d}",
                            control_id=impl.control_id,
                            weakness_description=finding,
                            risk_level="medium",  # Default for control findings
                            threat_sources=["internal", "external"],
                            predisposing_conditions=[f"Control {impl.control_id} not fully implemented"],
                            likelihood="moderate",
                            impact="moderate",
                            risk_response="mitigate",
                            resources_required="TBD based on implementation requirements",
                            responsible_parties=[impl.responsible_role],
                            planned_completion_date=impl.implementation_date or 
                                                  datetime.now(timezone.utc) + timedelta(days=120),
                            milestones=[
                                {
                                    'milestone_id': 1,
                                    'description': f'Complete implementation of {impl.control_id}',
                                    'target_date': impl.implementation_date or 
                                                 datetime.now(timezone.utc) + timedelta(days=120),
                                    'status': 'planned'
                                }
                            ],
                            status="open",
                            comments=f"Control implementation finding: {finding}"
                        )
                        poam_items.append(poam_item)
            
            return poam_items
            
        except Exception as e:
            self.logger.error(f"POA&M item generation failed: {e}")
            return []
    
    async def _generate_poam_document(
        self,
        system_info: SystemInformation,
        poam_items: List[POAMItem],
        output_dir: Path,
        framework: ComplianceFramework
    ) -> str:
        """Generate POA&M document."""
        try:
            template = await self.template_manager.load_template(
                ArtifactType.POAM, framework
            )
            
            context = {
                'system_info': asdict(system_info),
                'poam_items': [asdict(item) for item in poam_items],
                'poam_summary': await self._generate_poam_summary(poam_items),
                'generation_date': datetime.now(timezone.utc).isoformat(),
                'framework': framework.value
            }
            
            content = await self.template_manager.render_template(template, context)
            
            output_path = output_dir / f"poam_{system_info.system_id}.html"
            return await self.doc_generator.generate_html(
                content, output_path, f"Plan of Action and Milestones - {system_info.system_name}"
            )
            
        except Exception as e:
            self.logger.error(f"POA&M document generation failed: {e}")
            raise
    
    async def _generate_continuous_monitoring_plan(
        self,
        system_info: SystemInformation,
        control_implementations: List[ControlImplementation],
        output_dir: Path,
        framework: ComplianceFramework
    ) -> str:
        """Generate Continuous Monitoring Plan."""
        try:
            monitoring_strategy = await self._develop_monitoring_strategy(control_implementations)
            
            template = await self.template_manager.load_template(
                ArtifactType.CONTINUOUS_MONITORING_PLAN, framework
            )
            
            context = {
                'system_info': asdict(system_info),
                'monitoring_strategy': monitoring_strategy,
                'monitoring_schedule': await self._generate_monitoring_schedule(),
                'monitoring_procedures': await self._define_monitoring_procedures(),
                'reporting_requirements': await self._define_reporting_requirements(),
                'generation_date': datetime.now(timezone.utc).isoformat(),
                'framework': framework.value
            }
            
            content = await self.template_manager.render_template(template, context)
            
            output_path = output_dir / f"continuous_monitoring_plan_{system_info.system_id}.html"
            return await self.doc_generator.generate_html(
                content, output_path, f"Continuous Monitoring Plan - {system_info.system_name}"
            )
            
        except Exception as e:
            self.logger.error(f"Continuous monitoring plan generation failed: {e}")
            raise
    
    # Helper methods for data analysis and content generation
    async def _generate_assessment_methods(self, impl: ControlImplementation) -> List[str]:
        """Generate assessment methods for a control implementation."""
        methods = []
        if impl.implementation_status == "implemented":
            methods.extend(["examine", "interview", "test"])
        elif impl.implementation_status == "partially_implemented":
            methods.extend(["examine", "interview"])
        else:
            methods.append("examine")
        return methods
    
    async def _generate_assessment_objects(self, impl: ControlImplementation) -> List[str]:
        """Generate assessment objects for a control implementation."""
        return [
            f"{impl.control_id} implementation documentation",
            f"{impl.control_id} configuration settings",
            f"{impl.control_id} operational procedures"
        ]
    
    async def _generate_required_evidence(self, impl: ControlImplementation) -> List[str]:
        """Generate required evidence for control assessment."""
        return [
            "Implementation documentation",
            "Configuration evidence",
            "Test results",
            "Interview notes"
        ]
    
    def _risk_score_to_level(self, score: float) -> str:
        """Convert risk score to risk level."""
        if score >= 8.0:
            return "high"
        elif score >= 5.0:
            return "medium"
        elif score >= 2.0:
            return "low"
        else:
            return "very_low"
    
    # Additional helper methods would be implemented here...
    # (Due to length constraints, showing representative structure)


class CertificationArtifactsGenerator:
    """
    Main certification artifacts generator coordinating all components.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.logger = logging.getLogger(__name__)
        
        # Initialize components
        self.template_manager = TemplateManager()
        self.doc_generator = DocumentGenerator()
        self.ato_generator = ATOPackageGenerator(self.template_manager, self.doc_generator)
        self.audit_logger = AuditLogger()
        
        # Statistics tracking
        self.generation_stats = {
            'packages_generated': 0,
            'documents_created': 0,
            'total_generation_time': 0.0,
            'success_rate': 0.0
        }
    
    async def initialize(self):
        """Initialize the certification artifacts generator."""
        try:
            self.logger.info("Initializing Certification Artifacts Generator")
            
            # Create template directories if they don't exist
            template_dir = Path(self.config.get('template_dir', './templates'))
            template_dir.mkdir(parents=True, exist_ok=True)
            
            # Initialize default templates
            await self._create_default_templates(template_dir)
            
            self.logger.info("Certification Artifacts Generator initialized successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize Certification Artifacts Generator: {e}")
            raise
    
    async def generate_certification_package(
        self,
        system_info: SystemInformation,
        risk_assessments: List[RiskAssessment],
        control_implementations: List[ControlImplementation],
        artifact_types: List[ArtifactType],
        framework: ComplianceFramework = ComplianceFramework.NIST_RMF,
        output_formats: List[DocumentFormat] = None,
        output_dir: Path = None
    ) -> CertificationPackage:
        """
        Generate a complete certification package with specified artifacts.
        """
        try:
            start_time = time.time()
            package_id = str(uuid4())
            
            self.logger.info(f"Generating certification package {package_id} for system {system_info.system_id}")
            
            output_formats = output_formats or [DocumentFormat.HTML, DocumentFormat.PDF]
            output_dir = output_dir or Path(f"./certification_packages/{package_id}")
            output_dir.mkdir(parents=True, exist_ok=True)
            
            # Generate ATO package if requested
            if ArtifactType.ATO_PACKAGE in artifact_types:
                cert_package = await self.ato_generator.generate_ato_package(
                    system_info, risk_assessments, control_implementations, framework, output_dir
                )
            else:
                # Generate individual artifacts
                documents = {}
                
                for artifact_type in artifact_types:
                    if artifact_type == ArtifactType.ATO_PACKAGE:
                        continue
                    
                    doc_path = await self._generate_individual_artifact(
                        artifact_type, system_info, risk_assessments, 
                        control_implementations, framework, output_dir
                    )
                    documents[artifact_type] = doc_path
                
                cert_package = CertificationPackage(
                    package_id=package_id,
                    system_info=system_info,
                    framework=framework,
                    creation_date=datetime.now(timezone.utc),
                    created_by="automated_generator",
                    documents=documents,
                    risk_assessments=risk_assessments,
                    control_implementations=control_implementations,
                    poam_items=[],
                    assessment_results={},
                    approval_status="pending_review",
                    expiration_date=None
                )
            
            # Convert to additional formats if requested
            await self._convert_to_additional_formats(cert_package, output_formats, output_dir)
            
            # Update statistics
            generation_time = time.time() - start_time
            await self._update_generation_stats(cert_package, generation_time)
            
            # Log completion
            await self.audit_logger.log_security_event({
                'event_type': 'certification_package_generated',
                'package_id': package_id,
                'system_id': system_info.system_id,
                'framework': framework.value,
                'artifacts_generated': len(cert_package.documents),
                'generation_time': generation_time
            })
            
            self.logger.info(f"Certification package {package_id} generated successfully in {generation_time:.2f}s")
            return cert_package
            
        except Exception as e:
            self.logger.error(f"Certification package generation failed: {e}")
            raise
    
    async def _create_default_templates(self, template_dir: Path):
        """Create default templates for artifact generation."""
        # This would create Jinja2 templates for various artifact types
        # For brevity, just creating placeholder structure
        
        templates = {
            'nist_rmf_system_security_plan.j2': self._get_ssp_template(),
            'nist_rmf_security_assessment_plan.j2': self._get_sap_template(),
            'nist_rmf_risk_assessment_report.j2': self._get_rar_template(),
            'nist_rmf_plan_of_action_milestones.j2': self._get_poam_template(),
            'nist_rmf_continuous_monitoring_plan.j2': self._get_cmp_template(),
        }
        
        for template_name, template_content in templates.items():
            template_path = template_dir / template_name
            if not template_path.exists():
                async with aiofiles.open(template_path, 'w') as f:
                    await f.write(template_content)
    
    def _get_ssp_template(self) -> str:
        """Get System Security Plan template."""
        return """
# System Security Plan
## {{ system_info.system_name }}

### System Information
- **System ID**: {{ system_info.system_id }}
- **System Name**: {{ system_info.system_name }}
- **System Type**: {{ system_info.system_type }}
- **Classification**: {{ system_info.classification_level }}
- **System Owner**: {{ system_info.system_owner }}

### System Description
{{ system_info.system_description }}

### Security Controls Implementation

{% for control in control_implementations %}
#### {{ control.control_id }} - {{ control.control_name }}
- **Implementation Status**: {{ control.implementation_status }}
- **Responsible Role**: {{ control.responsible_role }}
- **Implementation Description**: {{ control.implementation_description }}

{% if control.findings %}
**Findings:**
{% for finding in control.findings %}
- {{ finding }}
{% endfor %}
{% endif %}

{% endfor %}

---
*Generated on {{ generation_date }} using {{ framework }} framework*
        """
    
    def _get_sap_template(self) -> str:
        """Get Security Assessment Plan template."""
        return """
# Security Assessment Plan
## {{ system_info.system_name }}

### Assessment Overview
This Security Assessment Plan (SAP) outlines the procedures for assessing the security controls implemented in {{ system_info.system_name }}.

### Assessment Scope
{% for procedure_id, procedure in assessment_procedures.items() %}
#### {{ procedure_id }}
**Testing Procedures:**
{% for procedure in procedure.testing_procedures %}
- {{ procedure }}
{% endfor %}

**Assessment Methods:**
{% for method in procedure.assessment_methods %}
- {{ method }}
{% endfor %}
{% endfor %}

---
*Generated on {{ generation_date }} using {{ framework }} framework*
        """
    
    def _get_rar_template(self) -> str:
        """Get Risk Assessment Report template."""
        return """
# Risk Assessment Report
## {{ system_info.system_name }}

### Executive Summary
This report presents the risk assessment findings for {{ system_info.system_name }}.

### Risk Summary
- **Total Risks Identified**: {{ risk_summary.total_risks }}
- **High Risk Items**: {{ risk_summary.high_risks }}
- **Medium Risk Items**: {{ risk_summary.medium_risks }}
- **Low Risk Items**: {{ risk_summary.low_risks }}

### Detailed Risk Findings
{% for risk in risk_assessments %}
#### {{ risk.title }}
- **Risk ID**: {{ risk.risk_id }}
- **Category**: {{ risk.category }}
- **Inherent Risk Score**: {{ risk.inherent_risk_score }}
- **Residual Risk Score**: {{ risk.residual_risk_score }}
- **Description**: {{ risk.description }}

{% endfor %}

---
*Generated on {{ generation_date }} using {{ framework }} framework*
        """
    
    def _get_poam_template(self) -> str:
        """Get POA&M template."""
        return """
# Plan of Action and Milestones (POA&M)
## {{ system_info.system_name }}

### POA&M Summary
Total Items: {{ poam_items|length }}

### POA&M Items
{% for item in poam_items %}
#### {{ item.poam_id }} - {{ item.weakness_description }}
- **Control ID**: {{ item.control_id }}
- **Risk Level**: {{ item.risk_level }}
- **Responsible Parties**: {{ item.responsible_parties|join(', ') }}
- **Planned Completion**: {{ item.planned_completion_date }}
- **Status**: {{ item.status }}

{% endfor %}

---
*Generated on {{ generation_date }} using {{ framework }} framework*
        """
    
    def _get_cmp_template(self) -> str:
        """Get Continuous Monitoring Plan template."""
        return """
# Continuous Monitoring Plan
## {{ system_info.system_name }}

### Monitoring Strategy
{{ monitoring_strategy.description }}

### Monitoring Schedule
{% for item in monitoring_schedule %}
- **{{ item.control_id }}**: {{ item.frequency }} - {{ item.method }}
{% endfor %}

---
*Generated on {{ generation_date }} using {{ framework }} framework*
        """
    
    # Additional helper methods...
    

# Export main classes
__all__ = [
    'CertificationArtifactsGenerator',
    'ArtifactType',
    'DocumentFormat',
    'ComplianceFramework',
    'SystemInformation',
    'ControlImplementation',
    'POAMItem',
    'CertificationPackage'
]