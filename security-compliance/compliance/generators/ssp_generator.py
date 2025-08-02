#!/usr/bin/env python3
"""
System Security Plan (SSP) Generator
====================================

Automated SSP generation leveraging existing audit and security testing infrastructure.
Generates comprehensive System Security Plans compliant with NIST SP 800-53 and DoD standards.

Key Features:
- Automated control implementation documentation
- Real-time evidence collection from audit systems
- Security testing results integration
- Risk assessment automation
- NIST 800-53 control mapping
- Multi-classification level support

Classification: UNCLASSIFIED//FOR OFFICIAL USE ONLY
Version: 1.0
Author: Security Compliance Team
Date: 2025-07-28
"""

import logging
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any

from .document_generator import DocumentGenerator, GenerationContext
from ..templates.compliance_template_engine import TemplateType, ClassificationLevel

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class SSPGenerator(DocumentGenerator):
    """
    System Security Plan Generator
    
    Generates comprehensive SSPs with automated control implementation documentation,
    evidence collection, and risk assessment integration.
    """
    
    def __init__(self, 
                 templates_path: Path,
                 output_path: Path,
                 config: Optional[Dict[str, Any]] = None):
        """
        Initialize SSP Generator
        
        Args:
            templates_path: Path to compliance templates
            output_path: Path for generated documents
            config: Configuration dictionary
        """
        super().__init__(templates_path, output_path, config)
        
        # NIST 800-53 control families mapping
        self.nist_control_families = {
            'AC': 'Access Control',
            'AT': 'Awareness and Training',
            'AU': 'Audit and Accountability',
            'CA': 'Security Assessment and Authorization',
            'CM': 'Configuration Management',
            'CP': 'Contingency Planning',
            'IA': 'Identification and Authentication',
            'IR': 'Incident Response',
            'MA': 'Maintenance',
            'MP': 'Media Protection',
            'PE': 'Physical and Environmental Protection',
            'PL': 'Planning',
            'PS': 'Personnel Security',
            'RA': 'Risk Assessment',
            'SA': 'System and Services Acquisition',
            'SC': 'System and Communications Protection',
            'SI': 'System and Information Integrity',
            'SR': 'Supply Chain Risk Management'
        }
        
        # Risk assessment categories
        self.risk_categories = {
            'confidentiality': ['AC', 'PE', 'PS', 'SC'],
            'integrity': ['AU', 'CM', 'SI', 'SC'],
            'availability': ['CP', 'MA', 'PE', 'SC']
        }
        
        logger.info("SSP Generator initialized")
    
    def get_template_type(self) -> TemplateType:
        """Get the template type for SSP generation"""
        return TemplateType.SSP
    
    def _determine_system_categorization(self, 
                                       audit_data: Dict[str, Any],
                                       context: GenerationContext) -> Dict[str, Any]:
        """
        Determine FIPS 199 system categorization based on data and classification
        
        Args:
            audit_data: Collected audit data
            context: Generation context
            
        Returns:
            System categorization information
        """
        # Base categorization on classification level
        base_impact = {
            ClassificationLevel.UNCLASSIFIED: 'low',
            ClassificationLevel.CUI: 'moderate', 
            ClassificationLevel.FOUO: 'moderate',
            ClassificationLevel.CONFIDENTIAL: 'moderate',
            ClassificationLevel.SECRET: 'high',
            ClassificationLevel.TOP_SECRET: 'high'
        }
        
        default_impact = base_impact.get(context.classification, 'moderate')
        
        # Analyze audit findings to adjust impact levels
        findings = audit_data.get('findings', [])
        high_severity_count = sum(1 for f in findings if f.get('severity') == 'high')
        critical_findings = sum(1 for f in findings if f.get('severity') == 'critical')
        
        # Adjust impact based on findings
        confidentiality_impact = default_impact
        integrity_impact = default_impact
        availability_impact = default_impact
        
        if critical_findings > 0:
            integrity_impact = 'high'
            if context.classification in [ClassificationLevel.SECRET, ClassificationLevel.TOP_SECRET]:
                confidentiality_impact = 'high'
        elif high_severity_count > 5:
            if integrity_impact == 'low':
                integrity_impact = 'moderate'
            if availability_impact == 'low':
                availability_impact = 'moderate'
        
        return {
            'confidentiality': {
                'impact_level': confidentiality_impact,
                'rationale': f'Based on {context.classification.value} data handling requirements'
            },
            'integrity': {
                'impact_level': integrity_impact,
                'rationale': f'Based on system criticality and {len(findings)} security findings'
            },
            'availability': {
                'impact_level': availability_impact,
                'rationale': 'Based on system operational requirements'
            },
            'overall_categorization': max(confidentiality_impact, integrity_impact, availability_impact, key=lambda x: ['low', 'moderate', 'high'].index(x))
        }
    
    def _generate_control_implementation_details(self,
                                               audit_data: Dict[str, Any],
                                               testing_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate detailed control implementation information
        
        Args:
            audit_data: Collected audit data
            testing_data: Security testing data
            
        Returns:
            Control implementation details
        """
        control_assessments = audit_data.get('control_assessments', {})
        control_tests = testing_data.get('control_tests', {})
        
        controls_matrix = {}
        
        # Process each control family
        for family_code, family_name in self.nist_control_families.items():
            family_controls = {}
            
            # Find controls for this family
            for control_id in control_assessments.keys():
                if control_id.startswith(family_code + '-'):
                    assessment = control_assessments[control_id]
                    test_result = control_tests.get(control_id, {})
                    
                    implementation_status = assessment.get('status', 'not_implemented')
                    assessment_score = assessment.get('score', 0)
                    test_score = test_result.get('score', 0)
                    
                    # Determine overall status
                    if implementation_status == 'implemented' and test_score >= 80:
                        overall_status = 'fully_implemented'
                    elif implementation_status == 'implemented':
                        overall_status = 'implemented_needs_improvement'
                    elif implementation_status == 'planned':
                        overall_status = 'planned'
                    else:
                        overall_status = 'not_implemented'
                    
                    family_controls[control_id] = {
                        'name': f'{control_id} - Control Name', # Would be looked up from control catalog
                        'implementation_status': overall_status,
                        'assessment_score': assessment_score,
                        'test_score': test_score,
                        'implementation_description': self._generate_control_description(control_id, assessment, test_result),
                        'responsible_role': assessment.get('responsible_role', 'System Administrator'),
                        'assessment_date': assessment.get('assessment_date', datetime.now(timezone.utc).isoformat()),
                        'next_review_date': assessment.get('next_review_date', ''),
                        'evidence_references': assessment.get('evidence', [])
                    }
            
            if family_controls:
                controls_matrix[family_code] = {
                    'family_name': family_name,
                    'controls': family_controls,
                    'family_implementation_rate': self._calculate_family_implementation_rate(family_controls)
                }
        
        return controls_matrix
    
    def _generate_control_description(self,
                                    control_id: str,
                                    assessment: Dict[str, Any],
                                    test_result: Dict[str, Any]) -> str:
        """
        Generate detailed control implementation description
        
        Args:
            control_id: NIST control identifier
            assessment: Control assessment data
            test_result: Control test result
            
        Returns:
            Detailed implementation description
        """
        base_description = assessment.get('implementation', f'{control_id} control implementation')
        
        # Add test results context
        if test_result.get('result') == 'pass':
            test_context = f" Testing confirms proper implementation with {test_result.get('score', 0)}% compliance."
        elif test_result.get('result') == 'fail':
            test_context = f" Testing identified implementation gaps requiring remediation ({test_result.get('score', 0)}% compliance)."
        else:
            test_context = " Implementation testing pending."
        
        # Add evidence context
        evidence_count = len(assessment.get('evidence', []))
        if evidence_count > 0:
            evidence_context = f" Supported by {evidence_count} evidence artifacts."
        else:
            evidence_context = " Evidence collection in progress."
        
        return base_description + test_context + evidence_context
    
    def _calculate_family_implementation_rate(self, family_controls: Dict[str, Any]) -> float:
        """
        Calculate implementation rate for a control family
        
        Args:
            family_controls: Controls in the family
            
        Returns:
            Implementation rate (0.0 to 1.0)
        """
        if not family_controls:
            return 0.0
        
        implemented_count = 0
        for control in family_controls.values():
            status = control.get('implementation_status', 'not_implemented')
            if status in ['fully_implemented', 'implemented_needs_improvement']:
                implemented_count += 1
        
        return implemented_count / len(family_controls)
    
    def _generate_risk_assessment_summary(self,
                                        audit_data: Dict[str, Any],
                                        testing_data: Dict[str, Any],
                                        monitoring_data: Dict[str, Any],
                                        categorization: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate risk assessment summary
        
        Args:
            audit_data: Audit data
            testing_data: Security testing data  
            monitoring_data: Monitoring data
            categorization: System categorization
            
        Returns:
            Risk assessment summary
        """
        # Analyze vulnerabilities
        vuln_scans = testing_data.get('vulnerability_scans', [])
        total_vulns = 0
        critical_vulns = 0
        high_vulns = 0
        
        for scan in vuln_scans:
            total_vulns += scan.get('critical', 0) + scan.get('high', 0) + scan.get('medium', 0) + scan.get('low', 0)
            critical_vulns += scan.get('critical', 0)
            high_vulns += scan.get('high', 0)
        
        # Analyze security incidents
        incidents = monitoring_data.get('incidents', [])
        security_incidents = [i for i in incidents if 'security' in i.get('description', '').lower()]
        
        # Determine overall risk level
        if critical_vulns > 0 or len(security_incidents) > 3:
            overall_risk = 'high'
        elif high_vulns > 5 or len(security_incidents) > 1:
            overall_risk = 'moderate'
        else:
            overall_risk = 'low'
        
        # Generate threat analysis
        threats = [
            {
                'name': 'External Network Attack',
                'likelihood': 'moderate',
                'impact': categorization['confidentiality']['impact_level'],
                'risk_level': self._calculate_threat_risk('moderate', categorization['confidentiality']['impact_level'])
            },
            {
                'name': 'Insider Threat',
                'likelihood': 'low',
                'impact': categorization['integrity']['impact_level'], 
                'risk_level': self._calculate_threat_risk('low', categorization['integrity']['impact_level'])
            },
            {
                'name': 'Malware/Ransomware',
                'likelihood': 'moderate',
                'impact': categorization['availability']['impact_level'],
                'risk_level': self._calculate_threat_risk('moderate', categorization['availability']['impact_level'])
            }
        ]
        
        return {
            'overall_risk_level': overall_risk,
            'risk_rationale': f'Based on {total_vulns} vulnerabilities, {len(security_incidents)} security incidents, and system categorization',
            'vulnerability_summary': {
                'total_vulnerabilities': total_vulns,
                'critical': critical_vulns,
                'high': high_vulns,
                'last_scan_date': vuln_scans[0].get('date', '') if vuln_scans else ''
            },
            'threat_analysis': threats,
            'security_incidents_summary': {
                'total_incidents': len(incidents),
                'security_related': len(security_incidents),
                'avg_resolution_time': sum(i.get('resolution_time', 0) for i in incidents) / len(incidents) if incidents else 0
            },
            'risk_treatment_plan': self._generate_risk_treatment_plan(overall_risk, critical_vulns, high_vulns)
        }
    
    def _calculate_threat_risk(self, likelihood: str, impact: str) -> str:
        """Calculate threat risk level based on likelihood and impact"""
        risk_matrix = {
            ('low', 'low'): 'low',
            ('low', 'moderate'): 'low',
            ('low', 'high'): 'moderate',
            ('moderate', 'low'): 'low',
            ('moderate', 'moderate'): 'moderate',
            ('moderate', 'high'): 'high',
            ('high', 'low'): 'moderate',
            ('high', 'moderate'): 'high',
            ('high', 'high'): 'high'
        }
        return risk_matrix.get((likelihood, impact), 'moderate')
    
    def _generate_risk_treatment_plan(self, overall_risk: str, critical_vulns: int, high_vulns: int) -> List[Dict[str, Any]]:
        """Generate risk treatment plan based on current risk profile"""
        treatments = []
        
        if overall_risk == 'high':
            treatments.append({
                'risk': 'High vulnerability exposure',
                'treatment': 'Immediate remediation of critical and high vulnerabilities',
                'timeline': '30 days',
                'responsible_party': 'Security Team'
            })
        
        if critical_vulns > 0:
            treatments.append({
                'risk': f'{critical_vulns} critical vulnerabilities',
                'treatment': 'Emergency patching and system hardening',
                'timeline': '7 days',
                'responsible_party': 'System Administrator'
            })
        
        if high_vulns > 5:
            treatments.append({
                'risk': f'{high_vulns} high-severity vulnerabilities',
                'treatment': 'Scheduled vulnerability remediation',
                'timeline': '30 days',
                'responsible_party': 'Security Team'
            })
        
        # Always include continuous monitoring
        treatments.append({
            'risk': 'Ongoing security threats',
            'treatment': 'Continuous security monitoring and assessment',
            'timeline': 'Ongoing',
            'responsible_party': 'SOC Team'
        })
        
        return treatments
    
    async def generate_document_data(self,
                                   context: GenerationContext,
                                   audit_data: Dict[str, Any],
                                   testing_data: Dict[str, Any],
                                   monitoring_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate SSP-specific data structure
        
        Args:
            context: Generation context
            audit_data: Collected audit data
            testing_data: Collected security testing data
            monitoring_data: Collected monitoring data
            
        Returns:
            SSP document data structure
        """
        logger.info("Generating SSP document data")
        
        # Generate system categorization
        categorization = self._determine_system_categorization(audit_data, context)
        
        # Generate control implementation matrix
        controls_matrix = self._generate_control_implementation_details(audit_data, testing_data)
        
        # Generate risk assessment
        risk_assessment = self._generate_risk_assessment_summary(
            audit_data, testing_data, monitoring_data, categorization
        )
        
        # Calculate overall compliance metrics
        compliance_status = audit_data.get('compliance_status', {})
        overall_compliance_score = compliance_status.get('overall_score', 0)
        
        # Generate system information
        system_info = {
            'name': context.system_name,
            'id': context.system_id,
            'description': f'Automated SSP for {context.system_name}',
            'classification': context.classification.value,
            'organization': context.organization,
            'system_type': 'Information System',
            'operational_status': 'Operational',
            'system_owner': 'System Owner',
            'information_owner': 'Information Owner',
            'system_security_officer': 'System Security Officer'
        }
        
        # Generate authorization information
        authorization_info = {
            'authorization_date': datetime.now(timezone.utc).strftime('%Y-%m-%d'),
            'authorization_termination_date': datetime.now(timezone.utc).replace(year=datetime.now().year + 3).strftime('%Y-%m-%d'),
            'authorizing_official': 'Authorizing Official',
            'authorization_status': 'ATO Pending' if overall_compliance_score < 80 else 'ATO Granted',
            'continuous_monitoring': True
        }
        
        # Generate evidence summary
        evidence = audit_data.get('evidence', [])
        evidence_summary = {
            'total_artifacts': len(evidence),
            'artifact_types': list(set(e.get('type', 'unknown') for e in evidence)),
            'last_updated': max([e.get('date', '') for e in evidence], default='') if evidence else ''
        }
        
        ssp_data = {
            'system_info': system_info,
            'system_categorization': categorization,
            'controls_matrix': controls_matrix,
            'risk_assessment': risk_assessment,
            'authorization_info': authorization_info,
            'compliance_status': {
                'overall_score': overall_compliance_score,
                'implemented_controls': compliance_status.get('implemented_controls', 0),
                'total_controls': compliance_status.get('total_controls', 100),
                'assessment_date': compliance_status.get('last_assessment', datetime.now(timezone.utc).isoformat())
            },
            'evidence_summary': evidence_summary,
            'system_environment': {
                'hardware_inventory': 'Hardware inventory maintained separately',
                'software_inventory': 'Software inventory maintained separately',
                'network_architecture': 'Network diagrams maintained separately',
                'data_flows': 'Data flow diagrams maintained separately'
            },
            'incident_response': {
                'contact_information': 'IR Team: security@organization.mil',
                'escalation_procedures': 'Follow organization IR procedures',
                'recent_incidents': len(monitoring_data.get('incidents', []))
            },
            'maintenance': {
                'maintenance_policy': 'System maintenance follows organizational procedures',
                'maintenance_personnel': 'Authorized maintenance personnel only',
                'maintenance_tools': 'Approved maintenance tools and procedures'
            }
        }
        
        logger.info(f"Generated SSP data with {len(controls_matrix)} control families and {overall_compliance_score}% compliance")
        
        return ssp_data


if __name__ == "__main__":
    # Example usage
    import asyncio
    import tempfile
    
    async def main():
        with tempfile.TemporaryDirectory() as temp_dir:
            templates_path = Path(temp_dir) / "templates"
            output_path = Path(temp_dir) / "output"
            
            generator = SSPGenerator(templates_path, output_path)
            
            context = GenerationContext(
                system_name="Test Security System",
                system_id="TSS-001",
                classification=ClassificationLevel.UNCLASSIFIED,
                organization="Department of Defense",
                template_type=TemplateType.SSP,
                include_evidence=True,
                include_metrics=True
            )
            
            result = await generator.generate(context)
            
            print(f"SSP Generation Result:")
            print(f"Success: {result.success}")
            print(f"Document Path: {result.document_path}")
            print(f"Generation Time: {result.generation_time:.2f}s")
            print(f"Control Coverage: {result.control_coverage:.1%}")
            print(f"Evidence Count: {result.evidence_count}")
    
    asyncio.run(main())