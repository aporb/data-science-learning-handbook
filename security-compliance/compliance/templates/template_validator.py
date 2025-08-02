#!/usr/bin/env python3
"""
Template Validator
==================

Validation engine for compliance document templates ensuring DoD standards compliance,
data integrity, and security requirements adherence.

Key Features:
- Template syntax validation
- DoD compliance standards verification
- Data schema validation
- Security classification validation
- Content integrity checks
- Multi-format support validation

Classification: UNCLASSIFIED//FOR OFFICIAL USE ONLY
Version: 1.0
Author: Security Compliance Team
Date: 2025-07-28
"""

import json
import logging
import re
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple, Union
from datetime import datetime
from jinja2 import Environment, TemplateSyntaxError, meta
from jsonschema import validate, ValidationError, Draft7Validator
from dataclasses import dataclass

from .compliance_template_engine import TemplateType, ClassificationLevel, ComplianceMetadata

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@dataclass
class ValidationResult:
    """Template validation result"""
    is_valid: bool
    template_type: str
    validation_date: datetime
    errors: List[str]
    warnings: List[str] 
    recommendations: List[str]
    compliance_score: float  # 0.0 to 1.0
    security_issues: List[str]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'is_valid': self.is_valid,
            'template_type': self.template_type,
            'validation_date': self.validation_date.isoformat(),
            'errors': self.errors,
            'warnings': self.warnings,
            'recommendations': self.recommendations,
            'compliance_score': self.compliance_score,
            'security_issues': self.security_issues
        }


class TemplateValidator:
    """
    Template Validator for Compliance Documents
    
    Validates compliance document templates against DoD standards and security requirements.
    """
    
    def __init__(self, schemas_path: Optional[Path] = None):
        """
        Initialize Template Validator
        
        Args:
            schemas_path: Path to validation schemas directory
        """
        self.schemas_path = schemas_path or Path(__file__).parent / "schemas"
        self.schemas_path.mkdir(parents=True, exist_ok=True)
        
        # Load validation schemas
        self.schemas = {}
        self._load_validation_schemas()
        
        # DoD compliance requirements
        self.dod_requirements = self._load_dod_requirements()
        
        # Security patterns
        self.security_patterns = self._load_security_patterns()
        
        logger.info("Template Validator initialized")
    
    def _load_validation_schemas(self):
        """Load JSON schemas for template validation"""
        
        # Default schemas for common template types
        default_schemas = {
            'ssp': {
                "type": "object",
                "required": ["system_info", "controls_matrix", "risk_assessment"],
                "properties": {
                    "system_info": {
                        "type": "object",
                        "required": ["name", "id", "description", "classification"],
                        "properties": {
                            "name": {"type": "string", "minLength": 1},
                            "id": {"type": "string", "minLength": 1},
                            "description": {"type": "string", "minLength": 10},
                            "classification": {"type": "string", "enum": ["U", "C", "S", "TS", "CUI", "FOUO"]}
                        }
                    },
                    "controls_matrix": {
                        "type": "object",
                        "patternProperties": {
                            "^[A-Z]{2}-[0-9]+$": {
                                "type": "object",
                                "required": ["status", "implementation"],
                                "properties": {
                                    "status": {"type": "string", "enum": ["implemented", "planned", "not_applicable"]},
                                    "implementation": {"type": "string", "minLength": 10}
                                }
                            }
                        }
                    },
                    "risk_assessment": {
                        "type": "object",
                        "required": ["overall_risk", "threats", "vulnerabilities"],
                        "properties": {
                            "overall_risk": {"type": "string", "enum": ["low", "moderate", "high"]},
                            "threats": {"type": "array", "minItems": 1},
                            "vulnerabilities": {"type": "array", "minItems": 0}
                        }
                    }
                }
            },
            'sar': {
                "type": "object", 
                "required": ["test_results", "vulnerability_scan", "control_assessment"],
                "properties": {
                    "test_results": {
                        "type": "object",
                        "required": ["passed", "failed", "total"],
                        "properties": {
                            "passed": {"type": "integer", "minimum": 0},
                            "failed": {"type": "integer", "minimum": 0},
                            "total": {"type": "integer", "minimum": 1}
                        }
                    },
                    "vulnerability_scan": {
                        "type": "object",
                        "required": ["critical", "high", "medium", "low"],
                        "properties": {
                            "critical": {"type": "integer", "minimum": 0},
                            "high": {"type": "integer", "minimum": 0},
                            "medium": {"type": "integer", "minimum": 0},
                            "low": {"type": "integer", "minimum": 0}
                        }
                    }
                }
            }
        }
        
        # Load schemas from files if they exist
        for schema_name, default_schema in default_schemas.items():
            schema_file = self.schemas_path / f"{schema_name}_schema.json"
            
            if schema_file.exists():
                try:
                    with open(schema_file, 'r') as f:
                        self.schemas[schema_name] = json.load(f)
                    logger.info(f"Loaded schema: {schema_name}")
                except Exception as e:
                    logger.warning(f"Error loading schema {schema_name}: {e}, using default")
                    self.schemas[schema_name] = default_schema
            else:
                # Save default schema
                self.schemas[schema_name] = default_schema
                try:
                    with open(schema_file, 'w') as f:
                        json.dump(default_schema, f, indent=2)
                    logger.info(f"Created default schema: {schema_name}")
                except Exception as e:
                    logger.warning(f"Could not save default schema {schema_name}: {e}")
    
    def _load_dod_requirements(self) -> Dict[str, Any]:
        """Load DoD compliance requirements"""
        return {
            'classification_markings': {
                'required': True,
                'patterns': [
                    r'CLASSIFICATION:\s*(U|UNCLASSIFIED|C|CONFIDENTIAL|S|SECRET|TS|TOP SECRET)',
                    r'(U|C|S|TS)//.*',
                    r'CUI|FOUO'
                ]
            },
            'control_families': {
                'nist_800_53': [
                    'AC', 'AT', 'AU', 'CA', 'CM', 'CP', 'IA', 'IR', 'MA', 'MP',
                    'PE', 'PL', 'PS', 'RA', 'SA', 'SC', 'SI', 'SR'
                ]
            },
            'mandatory_sections': {
                'ssp': [
                    'system_identification',
                    'system_categorization', 
                    'system_description',
                    'control_implementation',
                    'risk_assessment',
                    'security_authorization'
                ],
                'sar': [
                    'assessment_objectives',
                    'assessment_methods',
                    'assessment_findings',
                    'recommendations'
                ]
            },
            'security_markings': {
                'required_headers': [
                    'system_name',
                    'classification',
                    'date',
                    'version'
                ],
                'footer_requirements': [
                    'page_numbering',
                    'classification_marking'
                ]
            }
        }
    
    def _load_security_patterns(self) -> Dict[str, List[str]]:
        """Load security validation patterns"""
        return {
            'sensitive_data': [
                r'SSN|Social Security',
                r'\b\d{3}-\d{2}-\d{4}\b',  # SSN pattern
                r'password\s*=\s*["\'][^"\']*["\']',  # Password in code
                r'api[_-]?key\s*[=:]',  # API keys
                r'secret\s*[=:]'  # Secrets
            ],
            'classification_violations': [
                r'(CONFIDENTIAL|SECRET|TOP SECRET).*?(unclassified|public)',
                r'downgrade|declassify',
                r'remove.*classification'
            ],
            'security_controls': [
                r'AC-\d+',  # Access Control
                r'AU-\d+',  # Audit and Accountability
                r'SC-\d+',  # System and Communications Protection
                r'SI-\d+'   # System and Information Integrity
            ]
        }
    
    def validate_template_syntax(self, template_content: str) -> Tuple[bool, List[str]]:
        """
        Validate Jinja2 template syntax
        
        Args:
            template_content: Template content to validate
            
        Returns:
            Tuple of (is_valid, error_messages)
        """
        errors = []
        
        try:
            # Create temporary environment
            env = Environment()
            
            # Parse template to check syntax
            try:
                ast = env.parse(template_content)
                
                # Check for undefined variables
                undefined_vars = meta.find_undeclared_variables(ast)
                if undefined_vars:
                    errors.append(f"Undefined variables found: {', '.join(undefined_vars)}")
                
            except TemplateSyntaxError as e:
                errors.append(f"Template syntax error at line {e.lineno}: {e.message}")
            
        except Exception as e:
            errors.append(f"Template parsing failed: {str(e)}")
        
        return len(errors) == 0, errors
    
    def validate_data_schema(self, 
                           template_type: TemplateType,
                           data: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """
        Validate data against template schema
        
        Args:
            template_type: Type of template
            data: Data to validate
            
        Returns:
            Tuple of (is_valid, error_messages)
        """
        errors = []
        
        # Get schema for template type
        schema_key = template_type.value.replace('_', '')
        if schema_key in ['systemsecurityplan']:
            schema_key = 'ssp'
        elif schema_key in ['securityassessmentreport']:
            schema_key = 'sar'
        
        schema = self.schemas.get(schema_key)
        if not schema:
            errors.append(f"No validation schema found for template type: {template_type.value}")
            return False, errors
        
        try:
            # Validate against schema
            validator = Draft7Validator(schema)
            validation_errors = list(validator.iter_errors(data))
            
            for error in validation_errors:
                path = " -> ".join(str(p) for p in error.path) if error.path else "root"
                errors.append(f"Schema validation error at {path}: {error.message}")
                
        except Exception as e:
            errors.append(f"Schema validation failed: {str(e)}")
        
        return len(errors) == 0, errors
    
    def validate_dod_compliance(self, 
                               template_content: str,
                               template_type: TemplateType,
                               metadata: ComplianceMetadata) -> Tuple[float, List[str], List[str]]:
        """
        Validate DoD compliance requirements
        
        Args:
            template_content: Template content
            template_type: Template type
            metadata: Template metadata
            
        Returns:
            Tuple of (compliance_score, errors, warnings)
        """
        errors = []
        warnings = []
        score_components = {}
        
        # Check classification markings
        has_classification = False
        for pattern in self.dod_requirements['classification_markings']['patterns']:
            if re.search(pattern, template_content, re.IGNORECASE):
                has_classification = True
                break
        
        if not has_classification:
            errors.append("Missing required classification markings")
        score_components['classification'] = 1.0 if has_classification else 0.0
        
        # Check mandatory sections
        template_key = template_type.value.split('_')[0]  # Get base type (ssp, sar, etc.)
        required_sections = self.dod_requirements['mandatory_sections'].get(template_key, [])
        
        sections_found = 0
        for section in required_sections:
            # Look for section in template (various formats)
            section_patterns = [
                section.replace('_', ' '),
                section.replace('_', '-'),
                section.upper(),
                section.title()
            ]
            
            found = False
            for pattern in section_patterns:
                if pattern in template_content:
                    found = True
                    break
            
            if found:
                sections_found += 1
            else:
                warnings.append(f"Missing recommended section: {section}")
        
        sections_score = sections_found / len(required_sections) if required_sections else 1.0
        score_components['sections'] = sections_score
        
        # Check security markings
        header_score = 0.0
        required_headers = self.dod_requirements['security_markings']['required_headers']
        headers_found = 0
        
        for header in required_headers:
            header_patterns = [
                f"{{{{{header}}}}}",  # Jinja2 variable
                header.replace('_', ' ').title(),
                header.upper()
            ]
            
            for pattern in header_patterns:
                if pattern in template_content:
                    headers_found += 1
                    break
        
        header_score = headers_found / len(required_headers)
        score_components['headers'] = header_score
        
        # Check for NIST control references
        control_patterns = self.security_patterns['security_controls']
        controls_found = 0
        for pattern in control_patterns:
            matches = re.findall(pattern, template_content)
            controls_found += len(matches)
        
        controls_score = min(1.0, controls_found / 10)  # Expect at least 10 control references
        score_components['controls'] = controls_score
        
        if controls_found < 5:
            warnings.append("Few security control references found, consider adding more NIST controls")
        
        # Calculate overall compliance score
        weights = {
            'classification': 0.3,
            'sections': 0.3,
            'headers': 0.2,
            'controls': 0.2
        }
        
        compliance_score = sum(score_components[key] * weights[key] for key in weights)
        
        return compliance_score, errors, warnings
    
    def check_security_issues(self, template_content: str) -> List[str]:
        """
        Check for security issues in template content
        
        Args:
            template_content: Template content to check
            
        Returns:
            List of security issues found
        """
        issues = []
        
        # Check for sensitive data patterns
        for pattern in self.security_patterns['sensitive_data']:
            matches = re.findall(pattern, template_content, re.IGNORECASE)
            if matches:
                issues.append(f"Potential sensitive data found: {pattern}")
        
        # Check for classification violations
        for pattern in self.security_patterns['classification_violations']:
            matches = re.findall(pattern, template_content, re.IGNORECASE)
            if matches:
                issues.append(f"Potential classification violation: {pattern}")
        
        # Check for hardcoded credentials or secrets
        dangerous_patterns = [
            (r'password\s*=\s*["\'][^"\']+["\']', "Hardcoded password detected"),
            (r'api[_-]?key\s*=\s*["\'][^"\']+["\']', "Hardcoded API key detected"),
            (r'secret\s*=\s*["\'][^"\']+["\']', "Hardcoded secret detected"),
            (r'token\s*=\s*["\'][^"\']+["\']', "Hardcoded token detected")
        ]
        
        for pattern, message in dangerous_patterns:
            if re.search(pattern, template_content, re.IGNORECASE):
                issues.append(message)
        
        return issues
    
    def validate_template(self,
                         template_content: str,
                         template_type: TemplateType, 
                         metadata: ComplianceMetadata,
                         data: Optional[Dict[str, Any]] = None) -> ValidationResult:
        """
        Comprehensive template validation
        
        Args:
            template_content: Template content to validate
            template_type: Type of template
            metadata: Template metadata
            data: Optional sample data for validation
            
        Returns:
            ValidationResult object
        """
        errors = []
        warnings = []
        recommendations = []
        security_issues = []
        
        # 1. Validate template syntax
        syntax_valid, syntax_errors = self.validate_template_syntax(template_content)
        if not syntax_valid:
            errors.extend(syntax_errors)
        
        # 2. Validate data schema if data provided
        if data:
            schema_valid, schema_errors = self.validate_data_schema(template_type, data)
            if not schema_valid:
                errors.extend(schema_errors)
        
        # 3. Validate DoD compliance
        compliance_score, compliance_errors, compliance_warnings = self.validate_dod_compliance(
            template_content, template_type, metadata
        )
        errors.extend(compliance_errors)
        warnings.extend(compliance_warnings)
        
        # 4. Check security issues
        security_issues = self.check_security_issues(template_content)
        
        # 5. Generate recommendations
        if compliance_score < 0.8:
            recommendations.append("Consider improving DoD compliance by adding required sections and markings")
        
        if len(security_issues) > 0:
            recommendations.append("Review and address security issues before deploying template")
        
        if not re.search(r'version\s*[=:]', template_content, re.IGNORECASE):
            recommendations.append("Consider adding version information to template")
        
        # Determine overall validity
        is_valid = (len(errors) == 0 and 
                   len(security_issues) == 0 and 
                   compliance_score >= 0.7)
        
        return ValidationResult(
            is_valid=is_valid,
            template_type=template_type.value,
            validation_date=datetime.now(),
            errors=errors,
            warnings=warnings,
            recommendations=recommendations,
            compliance_score=compliance_score,
            security_issues=security_issues
        )
    
    def validate_template_file(self, template_path: Path) -> ValidationResult:
        """
        Validate template from file
        
        Args:
            template_path: Path to template file
            
        Returns:
            ValidationResult object
        """
        try:
            with open(template_path, 'r', encoding='utf-8') as f:
                template_content = f.read()
            
            # Try to determine template type from filename
            template_type = TemplateType.SSP  # Default
            filename_lower = template_path.name.lower()
            
            if 'ssp' in filename_lower:
                template_type = TemplateType.SSP
            elif 'sar' in filename_lower:
                template_type = TemplateType.SAR
            elif 'rar' in filename_lower:
                template_type = TemplateType.RAR
            elif 'stig' in filename_lower:
                template_type = TemplateType.STIG_CHECKLIST
            elif 'fisma' in filename_lower:
                template_type = TemplateType.FISMA_REPORT
            
            # Create basic metadata
            from .compliance_template_engine import create_sample_metadata
            metadata = create_sample_metadata("Template Validation")
            metadata.template_type = template_type
            
            return self.validate_template(template_content, template_type, metadata)
            
        except Exception as e:
            return ValidationResult(
                is_valid=False,
                template_type="unknown",
                validation_date=datetime.now(),
                errors=[f"Error reading template file: {str(e)}"],
                warnings=[],
                recommendations=[],
                compliance_score=0.0,
                security_issues=[]
            )


if __name__ == "__main__":
    # Example usage
    validator = TemplateValidator()
    
    # Sample template content for testing
    sample_template = """
<!DOCTYPE html>
<html>
<head>
    <title>System Security Plan - {{metadata.system_name}}</title>
    <meta name="classification" content="{{metadata.classification}}">
</head>
<body>
    <h1>CLASSIFICATION: {{metadata.classification|format_classification}}</h1>
    
    <h2>System Information</h2>
    <p>System Name: {{data.system_info.name}}</p>
    <p>System ID: {{data.system_info.id}}</p>
    <p>Description: {{data.system_info.description}}</p>
    
    <h2>Control Implementation</h2>
    {% for control_id, control in data.controls_matrix.items() %}
    <h3>{{control_id|format_control_id}}</h3>
    <p>Status: {{control.status}}</p>
    <p>Implementation: {{control.implementation}}</p>
    {% endfor %}
    
    <h2>Risk Assessment</h2>
    <p>Overall Risk: {{data.risk_assessment.overall_risk}}</p>
    
    <footer>
        <p>Page {{metadata.version}} - {{metadata.classification|format_classification}}</p>
    </footer>
</body>
</html>
    """
    
    # Sample data
    sample_data = {
        "system_info": {
            "name": "Test System",
            "id": "TEST-001",
            "description": "Test system for demonstration purposes",
            "classification": "U"
        },
        "controls_matrix": {
            "AC-1": {
                "status": "implemented",
                "implementation": "Access control policy implemented"
            },
            "AU-1": {
                "status": "implemented", 
                "implementation": "Audit policy implemented"
            }
        },
        "risk_assessment": {
            "overall_risk": "low",
            "threats": ["External threats"],
            "vulnerabilities": []
        }
    }
    
    from .compliance_template_engine import create_sample_metadata, TemplateType
    metadata = create_sample_metadata("Test System")
    
    # Validate template
    result = validator.validate_template(sample_template, TemplateType.SSP, metadata, sample_data)
    
    print("Validation Result:")
    print(f"Valid: {result.is_valid}")
    print(f"Compliance Score: {result.compliance_score:.2f}")
    print(f"Errors: {len(result.errors)}")
    print(f"Warnings: {len(result.warnings)}")
    print(f"Security Issues: {len(result.security_issues)}")
    
    if result.errors:
        print("\nErrors:")
        for error in result.errors:
            print(f"  - {error}")
    
    if result.warnings:
        print("\nWarnings:")
        for warning in result.warnings:
            print(f"  - {warning}")