#!/usr/bin/env python3
"""
Compliance Template Engine
==========================

Automated compliance documentation template system leveraging existing CMS infrastructure.
Provides DoD compliance document templates with automated population from audit data,
multi-classification level support, and version control integration.

Key Features:
- DoD compliance document templates (NIST 800-53, FISMA, STIG)  
- Automated template population from audit data
- Multi-classification level support (U, C, S, TS)
- Version control and change tracking
- Integration with existing CMS template manager
- Digital signature support for approval workflows

DoD Standards Supported:
- NIST SP 800-53 - Security and Privacy Controls
- FISMA - Federal Information Security Management Act
- STIG - Security Technical Implementation Guides
- DoD 8500.01E - Information Assurance Policy
- DoD 8510.01 - Risk Management Framework (RMF)
- CNSSI-1253 - Security Categorization and Control Selection

Classification: UNCLASSIFIED//FOR OFFICIAL USE ONLY
Version: 1.0
Author: Security Compliance Team
Date: 2025-07-28
"""

import os
import json
import logging
import hashlib
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any, Union, Tuple
from enum import Enum
from dataclasses import dataclass, asdict
from jinja2 import Environment, FileSystemLoader, Template, TemplateError

# Import existing CMS infrastructure
import sys
sys.path.append(str(Path(__file__).parent.parent.parent.parent / "content-management" / "core"))

try:
    from template_manager import TemplateManager as CMSTemplateManager
    from workflow_manager import WorkflowManager as CMSWorkflowManager
except ImportError:
    # Fallback if imports fail
    CMSTemplateManager = None
    CMSWorkflowManager = None

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class TemplateType(Enum):
    """Supported compliance document template types"""
    SSP = "system_security_plan"
    SAR = "security_assessment_report"  
    RAR = "risk_assessment_report"
    POAM = "plan_of_action_milestones"
    ATO = "authority_to_operate"
    STIG_CHECKLIST = "stig_checklist"
    NIST_CONTROLS = "nist_controls_matrix"
    FISMA_REPORT = "fisma_compliance_report"
    ICD_503 = "icd_503_categorization"
    CONTINUOUS_MONITORING = "continuous_monitoring_report"


class ClassificationLevel(Enum):
    """DoD classification levels"""
    UNCLASSIFIED = "U"
    CONFIDENTIAL = "C" 
    SECRET = "S"
    TOP_SECRET = "TS"
    CUI = "CUI"  # Controlled Unclassified Information
    FOUO = "FOUO"  # For Official Use Only


@dataclass
class ComplianceMetadata:
    """Metadata for compliance documents"""
    template_type: TemplateType
    classification: ClassificationLevel
    version: str
    created_date: datetime
    last_modified: datetime
    author: str
    system_name: str
    system_id: str
    organization: str
    compliance_standards: List[str]
    control_families: List[str]
    review_cycle: int  # days
    next_review_date: datetime
    digital_signature: Optional[str] = None
    approval_status: str = "draft"
    change_log: List[Dict[str, Any]] = None
    
    def __post_init__(self):
        if self.change_log is None:
            self.change_log = []


class ComplianceTemplateEngine:
    """
    Compliance Template Engine
    
    Leverages existing CMS infrastructure to provide automated compliance 
    documentation generation with DoD standards support.
    """
    
    def __init__(self, 
                 templates_path: Path,
                 output_path: Path,
                 config: Optional[Dict[str, Any]] = None):
        """
        Initialize Compliance Template Engine
        
        Args:
            templates_path: Path to compliance templates
            output_path: Path for generated documents
            config: Configuration dictionary
        """
        self.templates_path = Path(templates_path)
        self.output_path = Path(output_path)
        self.config = config or {}
        
        # Ensure directories exist
        self.templates_path.mkdir(parents=True, exist_ok=True)
        self.output_path.mkdir(parents=True, exist_ok=True)
        
        # Initialize Jinja2 environment
        self.env = Environment(
            loader=FileSystemLoader(str(self.templates_path)),
            trim_blocks=True,
            lstrip_blocks=True,
            autoescape=True
        )
        
        # Add custom filters
        self._register_custom_filters()
        
        # Initialize CMS integration if available
        self.cms_template_manager = None
        self.cms_workflow_manager = None
        if CMSTemplateManager:
            try:
                self.cms_template_manager = CMSTemplateManager(
                    self.templates_path.parent.parent,
                    self.config
                )
            except Exception as e:
                logger.warning(f"Could not initialize CMS template manager: {e}")
                
        # Template registry
        self.template_registry = {}
        self._load_template_registry()
        
        logger.info(f"Compliance Template Engine initialized")
        logger.info(f"Templates path: {self.templates_path}")
        logger.info(f"Output path: {self.output_path}")
    
    def _register_custom_filters(self):
        """Register custom Jinja2 filters for compliance documents"""
        
        def format_classification(classification: Union[str, ClassificationLevel]) -> str:
            """Format classification marking"""
            if isinstance(classification, ClassificationLevel):
                classification = classification.value
            return f"CLASSIFICATION: {classification}"
        
        def format_date(date_obj: datetime, format_str: str = "%Y-%m-%d") -> str:
            """Format datetime objects"""
            if isinstance(date_obj, str):
                return date_obj
            return date_obj.strftime(format_str)
        
        def format_control_id(control_id: str) -> str:
            """Format NIST control IDs"""
            return control_id.upper().replace("_", "-")
        
        def generate_toc(sections: List[Dict[str, Any]]) -> str:
            """Generate table of contents"""
            toc_lines = []
            for i, section in enumerate(sections, 1):
                title = section.get('title', f'Section {i}')
                page = section.get('page', i)
                toc_lines.append(f"{i}. {title} .................. {page}")
            return "\n".join(toc_lines)
        
        def hash_content(content: str) -> str:
            """Generate content hash for integrity verification"""
            return hashlib.sha256(content.encode()).hexdigest()[:16]
        
        # Register filters
        self.env.filters['format_classification'] = format_classification
        self.env.filters['format_date'] = format_date
        self.env.filters['format_control_id'] = format_control_id
        self.env.filters['generate_toc'] = generate_toc
        self.env.filters['hash_content'] = hash_content
    
    def _load_template_registry(self):
        """Load template registry with available templates"""
        registry_file = self.templates_path / "template_registry.json"
        
        if registry_file.exists():
            try:
                with open(registry_file, 'r') as f:
                    self.template_registry = json.load(f)
                logger.info(f"Loaded template registry with {len(self.template_registry)} templates")
            except Exception as e:
                logger.error(f"Error loading template registry: {e}")
                self.template_registry = {}
        else:
            # Create default registry
            self._create_default_template_registry()
    
    def _create_default_template_registry(self):
        """Create default template registry"""
        self.template_registry = {
            TemplateType.SSP.value: {
                "name": "System Security Plan",
                "template_file": "nist/ssp_template.html",
                "classification_levels": ["U", "C", "S", "TS"],
                "standards": ["NIST SP 800-53", "FISMA", "DoD 8500.01E"],
                "required_data": ["system_info", "controls_matrix", "risk_assessment"]
            },
            TemplateType.SAR.value: {
                "name": "Security Assessment Report", 
                "template_file": "nist/sar_template.html",
                "classification_levels": ["U", "C", "S", "TS"],
                "standards": ["NIST SP 800-53A", "DoD 8510.01"],
                "required_data": ["test_results", "vulnerability_scan", "control_assessment"]
            },
            TemplateType.RAR.value: {
                "name": "Risk Assessment Report",
                "template_file": "nist/rar_template.html", 
                "classification_levels": ["U", "C", "S", "TS"],
                "standards": ["NIST SP 800-30", "DoD 8500.01E"],
                "required_data": ["threat_analysis", "vulnerability_assessment", "risk_matrix"]
            },
            TemplateType.STIG_CHECKLIST.value: {
                "name": "STIG Compliance Checklist",
                "template_file": "dod/stig_checklist_template.html",
                "classification_levels": ["U", "C", "S", "TS"],
                "standards": ["DISA STIG", "DoD 8500.01E"],
                "required_data": ["stig_findings", "remediation_status", "evidence"]
            },
            TemplateType.FISMA_REPORT.value: {
                "name": "FISMA Compliance Report",
                "template_file": "fisma/fisma_report_template.html",
                "classification_levels": ["U", "CUI"],
                "standards": ["FISMA", "NIST SP 800-53", "OMB Circulars"],
                "required_data": ["system_inventory", "controls_status", "incidents"]
            }
        }
        
        # Save registry
        registry_file = self.templates_path / "template_registry.json"
        try:
            with open(registry_file, 'w') as f:
                json.dump(self.template_registry, f, indent=2)
            logger.info("Created default template registry")
        except Exception as e:
            logger.error(f"Error saving template registry: {e}")
    
    def get_available_templates(self) -> Dict[str, Any]:
        """Get list of available compliance templates"""
        return self.template_registry.copy()
    
    def validate_template_data(self, 
                             template_type: TemplateType,
                             data: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """
        Validate data against template requirements
        
        Args:
            template_type: Type of template
            data: Data to validate
            
        Returns:
            Tuple of (is_valid, error_messages)
        """
        template_info = self.template_registry.get(template_type.value, {})
        required_data = template_info.get('required_data', [])
        
        errors = []
        
        # Check required data fields
        for field in required_data:
            if field not in data:
                errors.append(f"Missing required field: {field}")
            elif not data[field]:
                errors.append(f"Empty required field: {field}")
        
        # Validate classification level
        classification = data.get('metadata', {}).get('classification')
        if classification:
            valid_levels = template_info.get('classification_levels', [])
            if classification not in valid_levels:
                errors.append(f"Invalid classification level: {classification}")
        
        return len(errors) == 0, errors
    
    def generate_document(self,
                         template_type: TemplateType,
                         data: Dict[str, Any],
                         metadata: ComplianceMetadata,
                         output_format: str = "html") -> Tuple[bool, str, Optional[str]]:
        """
        Generate compliance document from template
        
        Args:
            template_type: Type of document to generate
            data: Data to populate template
            metadata: Document metadata
            output_format: Output format (html, pdf, docx)
            
        Returns:
            Tuple of (success, message, output_file_path)
        """
        try:
            # Validate input data
            is_valid, errors = self.validate_template_data(template_type, data)
            if not is_valid:
                return False, f"Data validation failed: {'; '.join(errors)}", None
            
            # Get template info
            template_info = self.template_registry.get(template_type.value)
            if not template_info:
                return False, f"Template type not found: {template_type.value}", None
            
            template_file = template_info['template_file']
            
            # Load template
            try:
                template = self.env.get_template(template_file)
            except TemplateError as e:
                logger.error(f"Template loading error: {e}")
                return False, f"Template loading failed: {e}", None
            
            # Prepare context data
            context = {
                'metadata': asdict(metadata),
                'data': data,
                'generated_date': datetime.now(timezone.utc),
                'template_version': template_info.get('version', '1.0'),
                'standards': template_info.get('standards', [])
            }
            
            # Generate document content
            try:
                content = template.render(**context)
            except TemplateError as e:
                logger.error(f"Template rendering error: {e}")
                return False, f"Template rendering failed: {e}", None
            
            # Generate output filename
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"{metadata.system_id}_{template_type.value}_{timestamp}.{output_format}"
            output_path = self.output_path / filename
            
            # Save document
            try:
                with open(output_path, 'w', encoding='utf-8') as f:
                    f.write(content)
                
                # Create metadata file
                metadata_file = output_path.with_suffix(f'.{output_format}.meta.json')
                with open(metadata_file, 'w') as f:
                    json.dump({
                        'metadata': asdict(metadata),
                        'template_info': template_info,
                        'generation_date': datetime.now(timezone.utc).isoformat(),
                        'content_hash': hashlib.sha256(content.encode()).hexdigest()
                    }, f, indent=2, default=str)
                
                logger.info(f"Generated compliance document: {output_path}")
                return True, f"Document generated successfully: {filename}", str(output_path)
                
            except Exception as e:
                logger.error(f"Error saving document: {e}")
                return False, f"Error saving document: {e}", None
                
        except Exception as e:
            logger.error(f"Unexpected error in document generation: {e}")
            return False, f"Document generation failed: {e}", None
    
    def update_template(self,
                       template_type: TemplateType, 
                       template_content: str,
                       version: str = None) -> Tuple[bool, str]:
        """
        Update or create compliance template
        
        Args:
            template_type: Type of template
            template_content: Template content (Jinja2 format)
            version: Template version
            
        Returns:
            Tuple of (success, message)
        """
        try:
            template_info = self.template_registry.get(template_type.value, {})
            template_file = template_info.get('template_file')
            
            if not template_file:
                return False, f"Template file not configured for {template_type.value}"
            
            template_path = self.templates_path / template_file
            template_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Backup existing template
            if template_path.exists():
                backup_path = template_path.with_suffix(f".backup.{datetime.now().strftime('%Y%m%d_%H%M%S')}")
                template_path.rename(backup_path)
                logger.info(f"Backed up existing template to: {backup_path}")
            
            # Save new template
            with open(template_path, 'w', encoding='utf-8') as f:
                f.write(template_content)
            
            # Update registry
            if version:
                self.template_registry[template_type.value]['version'] = version
                self.template_registry[template_type.value]['last_updated'] = datetime.now(timezone.utc).isoformat()
                
                registry_file = self.templates_path / "template_registry.json"
                with open(registry_file, 'w') as f:
                    json.dump(self.template_registry, f, indent=2, default=str)
            
            logger.info(f"Updated template: {template_file}")
            return True, f"Template updated successfully: {template_file}"
            
        except Exception as e:
            logger.error(f"Error updating template: {e}")
            return False, f"Template update failed: {e}"
    
    def get_template_status(self, template_type: TemplateType) -> Dict[str, Any]:
        """Get status information for a template"""
        template_info = self.template_registry.get(template_type.value, {})
        template_file = template_info.get('template_file')
        
        status = {
            'template_type': template_type.value,
            'template_file': template_file,
            'exists': False,
            'size': 0,
            'last_modified': None,
            'version': template_info.get('version', 'Unknown')
        }
        
        if template_file:
            template_path = self.templates_path / template_file
            if template_path.exists():
                stat = template_path.stat()
                status.update({
                    'exists': True,
                    'size': stat.st_size,
                    'last_modified': datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat()
                })
        
        return status
    
    def list_generated_documents(self, 
                                system_id: Optional[str] = None,
                                template_type: Optional[TemplateType] = None) -> List[Dict[str, Any]]:
        """
        List generated compliance documents
        
        Args:
            system_id: Filter by system ID
            template_type: Filter by template type
            
        Returns:
            List of document information
        """
        documents = []
        
        try:
            for doc_file in self.output_path.glob("*.html"):
                # Parse filename to extract information
                parts = doc_file.stem.split('_')
                if len(parts) >= 3:
                    doc_system_id = parts[0]
                    doc_template_type = parts[1]
                    doc_timestamp = parts[2] if len(parts) > 2 else "unknown"
                    
                    # Apply filters
                    if system_id and doc_system_id != system_id:
                        continue
                    if template_type and doc_template_type != template_type.value:
                        continue
                    
                    # Get metadata if available
                    meta_file = doc_file.with_suffix('.html.meta.json')
                    metadata = {}
                    if meta_file.exists():
                        try:
                            with open(meta_file, 'r') as f:
                                metadata = json.load(f)
                        except Exception as e:
                            logger.warning(f"Could not read metadata for {doc_file}: {e}")
                    
                    stat = doc_file.stat()
                    documents.append({
                        'filename': doc_file.name,
                        'path': str(doc_file),
                        'system_id': doc_system_id,
                        'template_type': doc_template_type,
                        'timestamp': doc_timestamp,
                        'size': stat.st_size,
                        'created': datetime.fromtimestamp(stat.st_ctime, timezone.utc).isoformat(),
                        'modified': datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat(),
                        'metadata': metadata
                    })
            
            # Sort by creation time (newest first)
            documents.sort(key=lambda x: x['created'], reverse=True)
            
        except Exception as e:
            logger.error(f"Error listing documents: {e}")
        
        return documents


def create_sample_metadata(system_name: str = "Sample System") -> ComplianceMetadata:
    """Create sample compliance metadata for testing"""
    return ComplianceMetadata(
        template_type=TemplateType.SSP,
        classification=ClassificationLevel.UNCLASSIFIED,
        version="1.0",
        created_date=datetime.now(timezone.utc),
        last_modified=datetime.now(timezone.utc),
        author="Security Team",
        system_name=system_name,
        system_id=system_name.lower().replace(" ", "_"),
        organization="Department of Defense",
        compliance_standards=["NIST SP 800-53", "FISMA", "DoD 8500.01E"],
        control_families=["AC", "AU", "SC", "SI"],
        review_cycle=365,
        next_review_date=datetime.now(timezone.utc).replace(year=datetime.now().year + 1),
        approval_status="draft"
    )


if __name__ == "__main__":
    # Example usage
    import tempfile
    
    with tempfile.TemporaryDirectory() as temp_dir:
        templates_path = Path(temp_dir) / "templates"
        output_path = Path(temp_dir) / "output"
        
        engine = ComplianceTemplateEngine(templates_path, output_path)
        
        # List available templates
        templates = engine.get_available_templates()
        logger.info(f"Available templates: {list(templates.keys())}")
        
        # Get template status
        for template_type in TemplateType:
            status = engine.get_template_status(template_type)
            logger.info(f"Template {template_type.value}: {status}")