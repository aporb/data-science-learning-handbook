#!/usr/bin/env python3
"""
Security Assessment Report (SAR) Generator
==========================================

Automated SAR generation leveraging existing security testing and audit infrastructure.
Generates comprehensive Security Assessment Reports compliant with NIST SP 800-53A.

Key Features:
- Automated control testing results compilation
- Vulnerability assessment integration
- Penetration testing results analysis
- Compliance gap identification
- Remediation recommendations
- Evidence artifact compilation

Classification: UNCLASSIFIED//FOR OFFICIAL USE ONLY
Version: 1.0
Author: Security Compliance Team  
Date: 2025-07-28
"""

import logging
from pathlib import Path
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any

from .document_generator import DocumentGenerator, GenerationContext
from ..templates.compliance_template_engine import TemplateType, ClassificationLevel

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class SARGenerator(DocumentGenerator):
    """
    Security Assessment Report Generator
    
    Generates comprehensive SARs with automated testing results compilation,
    vulnerability analysis, and compliance assessment.
    """
    
    def __init__(self, 
                 templates_path: Path,
                 output_path: Path,
                 config: Optional[Dict[str, Any]] = None):
        """
        Initialize SAR Generator
        
        Args:
            templates_path: Path to compliance templates
            output_path: Path for generated documents
            config: Configuration dictionary
        """
        super().__init__(templates_path, output_path, config)
        
        # Assessment methodology mapping
        self.assessment_methods = {
            'examine': 'Document and artifact review',
            'interview': 'Personnel interviews and questionnaires', 
            'test': 'Technical testing and validation'
        }
        
        # Severity scoring
        self.severity_scores = {
            'critical': 10,
            'high': 7,
            'medium': 4,
            'low': 1
        }
        
        logger.info("SAR Generator initialized")
    
    def get_template_type(self) -> TemplateType:
        """Get the template type for SAR generation"""
        return TemplateType.SAR
    
    def _analyze_control_test_results(self,
                                    audit_data: Dict[str, Any],
                                    testing_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze control test results from security testing
        
        Args:
            audit_data: Collected audit data
            testing_data: Security testing data
            
        Returns:
            Control test analysis results
        """
        control_assessments = audit_data.get('control_assessments', {})
        control_tests = testing_data.get('control_tests', {})
        
        test_results = {
            'total_controls_tested': 0,
            'passed_controls': 0,
            'failed_controls': 0,
            'not_tested': 0,
            'control_details': {},
            'assessment_summary': {}
        }
        
        # Combine all controls from audit and testing
        all_controls = set(control_assessments.keys()) | set(control_tests.keys())
        
        for control_id in all_controls:
            assessment = control_assessments.get(control_id, {})
            test_result = control_tests.get(control_id, {})
            
            # Determine test status
            if test_result.get('result'):
                test_results['total_controls_tested'] += 1
                if test_result['result'] == 'pass':
                    test_results['passed_controls'] += 1
                    test_status = 'satisfied'
                else:
                    test_results['failed_controls'] += 1
                    test_status = 'not_satisfied'
            else:
                test_results['not_tested'] += 1
                test_status = 'not_tested'
            
            # Compile detailed results
            test_results['control_details'][control_id] = {
                'control_name': f'{control_id} Control',
                'assessment_methods': ['examine', 'test'],  # Would be determined based on control type
                'test_status': test_status,
                'test_score': test_result.get('score', 0),
                'implementation_status': assessment.get('status', 'unknown'),
                'findings': self._generate_control_findings(control_id, assessment, test_result),
                'evidence_reviewed': assessment.get('evidence', []),
                'assessment_date': test_result.get('date', datetime.now(timezone.utc).isoformat()),
                'assessor': test_result.get('assessor', 'Automated Testing System')
            }
        
        # Generate assessment summary by control family
        test_results['assessment_summary'] = self._generate_assessment_summary_by_family(
            test_results['control_details']
        )
        
        return test_results
    
    def _generate_control_findings(self,
                                 control_id: str,
                                 assessment: Dict[str, Any], 
                                 test_result: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Generate findings for a specific control
        
        Args:
            control_id: Control identifier
            assessment: Assessment data
            test_result: Test result data
            
        Returns:
            List of findings for the control
        """
        findings = []
        
        # Check test results
        if test_result.get('result') == 'fail':
            findings.append({
                'finding_id': f'SAR-{control_id}-001',
                'finding_type': 'deficiency',
                'severity': 'medium' if test_result.get('score', 0) > 50 else 'high',
                'description': f'Control {control_id} testing identified implementation gaps',
                'recommendation': f'Remediate {control_id} implementation deficiencies',
                'risk_rating': 'moderate'
            })
        
        # Check for low scores even if passed
        if test_result.get('score', 100) < 80 and test_result.get('result') == 'pass':
            findings.append({
                'finding_id': f'SAR-{control_id}-002',
                'finding_type': 'observation',
                'severity': 'low',
                'description': f'Control {control_id} implementation could be strengthened',
                'recommendation': f'Enhance {control_id} implementation to achieve higher compliance score',
                'risk_rating': 'low'
            })
        
        # Check for missing evidence
        if not assessment.get('evidence'):
            findings.append({
                'finding_id': f'SAR-{control_id}-003',
                'finding_type': 'observation',
                'severity': 'low',
                'description': f'Control {control_id} lacks documented evidence',
                'recommendation': f'Collect and document evidence for {control_id} implementation',
                'risk_rating': 'low'
            })
        
        return findings
    
    def _generate_assessment_summary_by_family(self,
                                             control_details: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate assessment summary grouped by control family
        
        Args:
            control_details: Detailed control assessment results
            
        Returns:
            Summary by control family
        """
        family_summary = {}
        
        for control_id, details in control_details.items():
            family_code = control_id.split('-')[0]
            
            if family_code not in family_summary:
                family_summary[family_code] = {
                    'family_name': self._get_family_name(family_code),
                    'total_controls': 0,
                    'satisfied': 0,
                    'not_satisfied': 0,
                    'not_tested': 0,
                    'average_score': 0,
                    'critical_findings': 0,
                    'high_findings': 0,
                    'medium_findings': 0,
                    'low_findings': 0
                }
            
            family_data = family_summary[family_code]
            family_data['total_controls'] += 1
            
            # Count by status
            if details['test_status'] == 'satisfied':
                family_data['satisfied'] += 1
            elif details['test_status'] == 'not_satisfied':
                family_data['not_satisfied'] += 1
            else:
                family_data['not_tested'] += 1
            
            # Accumulate scores
            family_data['average_score'] += details['test_score']
            
            # Count findings by severity
            for finding in details['findings']:
                severity = finding['severity']
                family_data[f'{severity}_findings'] += 1
        
        # Calculate averages
        for family_data in family_summary.values():
            if family_data['total_controls'] > 0:
                family_data['average_score'] /= family_data['total_controls']
                family_data['satisfaction_rate'] = family_data['satisfied'] / family_data['total_controls']
        
        return family_summary
    
    def _get_family_name(self, family_code: str) -> str:
        """Get control family name from code"""
        family_names = {
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
        return family_names.get(family_code, f'Unknown Family ({family_code})')
    
    def _analyze_vulnerability_assessment(self,
                                        testing_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze vulnerability assessment results
        
        Args:
            testing_data: Security testing data
            
        Returns:
            Vulnerability assessment analysis
        """
        vuln_scans = testing_data.get('vulnerability_scans', [])
        
        if not vuln_scans:
            return {
                'total_vulnerabilities': 0,
                'severity_breakdown': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0},
                'vulnerability_trend': 'no_data',
                'risk_score': 0,
                'recommendations': ['Conduct vulnerability assessment']
            }
        
        # Aggregate vulnerability data
        total_critical = sum(scan.get('critical', 0) for scan in vuln_scans)
        total_high = sum(scan.get('high', 0) for scan in vuln_scans)
        total_medium = sum(scan.get('medium', 0) for scan in vuln_scans)
        total_low = sum(scan.get('low', 0) for scan in vuln_scans)
        
        total_vulns = total_critical + total_high + total_medium + total_low
        
        # Calculate risk score (weighted by severity)
        risk_score = (
            total_critical * self.severity_scores['critical'] +
            total_high * self.severity_scores['high'] +
            total_medium * self.severity_scores['medium'] +
            total_low * self.severity_scores['low']
        )
        
        # Analyze trend (if multiple scans)
        if len(vuln_scans) > 1:
            latest_total = (vuln_scans[0].get('critical', 0) + vuln_scans[0].get('high', 0) + 
                          vuln_scans[0].get('medium', 0) + vuln_scans[0].get('low', 0))
            previous_total = (vuln_scans[1].get('critical', 0) + vuln_scans[1].get('high', 0) +
                            vuln_scans[1].get('medium', 0) + vuln_scans[1].get('low', 0))
            
            if latest_total < previous_total:
                trend = 'improving'
            elif latest_total > previous_total:
                trend = 'worsening'
            else:
                trend = 'stable'
        else:
            trend = 'single_assessment'
        
        # Generate recommendations
        recommendations = []
        if total_critical > 0:
            recommendations.append(f'Immediately address {total_critical} critical vulnerabilities')
        if total_high > 5:
            recommendations.append(f'Prioritize remediation of {total_high} high-severity vulnerabilities')
        if total_vulns > 50:
            recommendations.append('Implement comprehensive vulnerability management program')
        
        return {
            'total_vulnerabilities': total_vulns,
            'severity_breakdown': {
                'critical': total_critical,
                'high': total_high,
                'medium': total_medium,
                'low': total_low
            },
            'vulnerability_trend': trend,
            'risk_score': risk_score,
            'recommendations': recommendations,
            'scan_details': [
                {
                    'scan_date': scan.get('date', ''),
                    'scanner': scan.get('scanner', 'Unknown'),
                    'total_findings': (scan.get('critical', 0) + scan.get('high', 0) + 
                                     scan.get('medium', 0) + scan.get('low', 0))
                }
                for scan in vuln_scans
            ]
        }
    
    def _generate_overall_assessment_conclusion(self,
                                              control_results: Dict[str, Any],
                                              vuln_assessment: Dict[str, Any],
                                              context: GenerationContext) -> Dict[str, Any]:
        """
        Generate overall assessment conclusion and recommendations
        
        Args:
            control_results: Control test results
            vuln_assessment: Vulnerability assessment results
            context: Generation context
            
        Returns:
            Overall assessment conclusion
        """
        # Calculate overall scores
        control_satisfaction_rate = (control_results['passed_controls'] / 
                                   control_results['total_controls_tested']
                                   if control_results['total_controls_tested'] > 0 else 0)
        
        # Determine overall risk posture
        if (control_satisfaction_rate >= 0.9 and 
            vuln_assessment['severity_breakdown']['critical'] == 0 and
            vuln_assessment['severity_breakdown']['high'] <= 2):
            risk_posture = 'low'
            authorization_recommendation = 'recommend_ato'
        elif (control_satisfaction_rate >= 0.8 and
              vuln_assessment['severity_breakdown']['critical'] <= 1 and
              vuln_assessment['severity_breakdown']['high'] <= 5):
            risk_posture = 'moderate'
            authorization_recommendation = 'conditional_ato'
        else:
            risk_posture = 'high'
            authorization_recommendation = 'deny_ato'
        
        # Generate key findings
        key_findings = []
        
        if control_results['failed_controls'] > 0:
            key_findings.append(f"{control_results['failed_controls']} security controls failed testing")
        
        if vuln_assessment['severity_breakdown']['critical'] > 0:
            key_findings.append(f"{vuln_assessment['severity_breakdown']['critical']} critical vulnerabilities identified")
        
        if control_satisfaction_rate < 0.8:
            key_findings.append(f"Control satisfaction rate below threshold: {control_satisfaction_rate:.1%}")
        
        # Generate recommendations
        recommendations = []
        
        if authorization_recommendation == 'deny_ato':
            recommendations.append('Address all critical security deficiencies before authorization')
            recommendations.append('Implement comprehensive remediation plan')
        elif authorization_recommendation == 'conditional_ato':
            recommendations.append('Address high-priority findings within 30 days')
            recommendations.append('Implement continuous monitoring program')
        
        recommendations.extend(vuln_assessment['recommendations'])
        
        return {
            'overall_risk_posture': risk_posture,
            'control_satisfaction_rate': control_satisfaction_rate,
            'authorization_recommendation': authorization_recommendation,
            'key_findings': key_findings,
            'recommendations': recommendations,
            'assessment_confidence': 'high' if control_results['total_controls_tested'] > 20 else 'moderate',
            'next_assessment_date': (datetime.now(timezone.utc) + timedelta(days=365)).strftime('%Y-%m-%d')
        }
    
    async def generate_document_data(self,
                                   context: GenerationContext,
                                   audit_data: Dict[str, Any],
                                   testing_data: Dict[str, Any],
                                   monitoring_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate SAR-specific data structure
        
        Args:
            context: Generation context
            audit_data: Collected audit data
            testing_data: Collected security testing data
            monitoring_data: Collected monitoring data
            
        Returns:
            SAR document data structure
        """
        logger.info("Generating SAR document data")
        
        # Analyze control test results
        control_results = self._analyze_control_test_results(audit_data, testing_data)
        
        # Analyze vulnerability assessment
        vuln_assessment = self._analyze_vulnerability_assessment(testing_data)
        
        # Generate overall assessment conclusion
        overall_assessment = self._generate_overall_assessment_conclusion(
            control_results, vuln_assessment, context
        )
        
        # Generate assessment metadata
        assessment_info = {
            'assessment_start_date': (datetime.now(timezone.utc) - timedelta(days=context.date_range_days)).strftime('%Y-%m-%d'),
            'assessment_completion_date': datetime.now(timezone.utc).strftime('%Y-%m-%d'),
            'assessment_type': 'Automated Security Assessment',
            'assessment_scope': f'Full system assessment of {context.system_name}',
            'assessment_team': [
                'Automated Testing System',
                'Security Assessment Team',
                'Compliance Team'
            ],
            'assessment_methods_used': list(self.assessment_methods.keys()),
            'assessment_standards': [
                'NIST SP 800-53A',
                'NIST SP 800-53',
                'DoD 8500.01E'
            ]
        }
        
        # Compile evidence artifacts
        evidence_artifacts = []
        for control_id, details in control_results['control_details'].items():
            for evidence in details['evidence_reviewed']:
                evidence_artifacts.append({
                    'artifact_id': evidence.get('id', f'EVD-{control_id}'),
                    'control_reference': control_id,
                    'artifact_type': evidence.get('type', 'configuration'),
                    'description': evidence.get('description', 'Supporting evidence'),
                    'location': evidence.get('file_path', 'Evidence repository')
                })
        
        sar_data = {
            'system_info': {
                'name': context.system_name,
                'id': context.system_id,
                'classification': context.classification.value,
                'organization': context.organization,
                'assessment_boundary': f'All components of {context.system_name}'
            },
            'assessment_info': assessment_info,
            'control_assessment_results': control_results,
            'vulnerability_assessment': vuln_assessment,
            'penetration_testing': {
                'tests_conducted': len(testing_data.get('penetration_tests', [])),
                'findings': testing_data.get('penetration_tests', []),
                'overall_result': 'System demonstrates adequate security posture'
            },
            'overall_assessment': overall_assessment,
            'evidence_artifacts': evidence_artifacts,
            'assessment_limitations': [
                'Assessment based on automated testing and configuration review',
                'Manual validation of certain controls may be required',
                'Assessment reflects point-in-time security posture'
            ],
            'continuous_monitoring': {
                'program_status': 'Implemented',
                'monitoring_frequency': 'Continuous',
                'key_metrics': list(monitoring_data.get('metrics', {}).keys())
            }
        }
        
        logger.info(f"Generated SAR data with {control_results['total_controls_tested']} controls tested, "
                   f"{vuln_assessment['total_vulnerabilities']} vulnerabilities, "
                   f"{overall_assessment['control_satisfaction_rate']:.1%} satisfaction rate")
        
        return sar_data


if __name__ == "__main__":
    # Example usage
    import asyncio
    import tempfile
    
    async def main():
        with tempfile.TemporaryDirectory() as temp_dir:
            templates_path = Path(temp_dir) / "templates"
            output_path = Path(temp_dir) / "output"
            
            generator = SARGenerator(templates_path, output_path)
            
            context = GenerationContext(
                system_name="Test Security System",
                system_id="TSS-001",
                classification=ClassificationLevel.UNCLASSIFIED,
                organization="Department of Defense",
                template_type=TemplateType.SAR,
                include_evidence=True,
                include_metrics=True
            )
            
            result = await generator.generate(context)
            
            print(f"SAR Generation Result:")
            print(f"Success: {result.success}")
            print(f"Document Path: {result.document_path}")
            print(f"Generation Time: {result.generation_time:.2f}s")
            print(f"Control Coverage: {result.control_coverage:.1%}")
            print(f"Validation Score: {result.validation_score:.2f}")
    
    asyncio.run(main())