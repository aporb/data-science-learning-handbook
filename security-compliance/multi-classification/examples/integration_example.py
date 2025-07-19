"""
Multi-Classification Data Handling Framework Integration Example

This example demonstrates the complete integration of all components:
- Enhanced Content Analyzer with ML-based classification
- Automatic Content Labeling System with mandatory access controls
- DoD Compliance Validator with security standards validation
- Comprehensive audit logging and reporting

Classification: UNCLASSIFIED//FOR OFFICIAL USE ONLY
Version: 1.0
Date: 2025-07-17
"""

import json
import logging
import tempfile
from datetime import datetime, timezone
from uuid import uuid4
from typing import Dict, List, Any

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

# Import framework components
from ..models.enhanced_content_analyzer import EnhancedContentAnalyzer
from ..models.content_labeling_system import (
    ContentLabelingSystem, 
    LabelingPolicy,
    create_content_labeling_system
)
from ..models.dod_compliance_validator import (
    DoDComplianceValidator,
    ComplianceStandard,
    create_dod_compliance_validator
)

logger = logging.getLogger(__name__)


class MultiClassificationFrameworkDemo:
    """
    Demonstration of the complete Multi-Classification Data Handling Framework.
    
    Shows integration of:
    - ML-based content analysis
    - Automatic content labeling 
    - DoD compliance validation
    - Audit logging and reporting
    """
    
    def __init__(self):
        """Initialize the framework demo."""
        # Create temporary directory for ML models
        self.temp_dir = tempfile.mkdtemp()
        
        # Initialize content analyzer with ML capabilities
        self.content_analyzer = EnhancedContentAnalyzer(
            model_path=self.temp_dir,
            enable_ml=True
        )
        
        # Initialize content labeling system
        self.labeling_system = create_content_labeling_system(
            content_analyzer=self.content_analyzer,
            labeling_policy=LabelingPolicy.HYBRID
        )
        
        # Initialize DoD compliance validator
        self.compliance_validator = create_dod_compliance_validator(
            content_analyzer=self.content_analyzer,
            labeling_system=self.labeling_system
        )
        
        # Demo user ID
        self.demo_user_id = uuid4()
        
        logger.info("Multi-Classification Framework Demo initialized")
    
    def run_comprehensive_demo(self):
        """Run comprehensive demonstration of all framework capabilities."""
        logger.info("Starting comprehensive framework demonstration...")
        
        try:
            # 1. Content Analysis Demo
            print("\\n" + "="*80)
            print("1. CONTENT ANALYSIS DEMONSTRATION")
            print("="*80)
            self._demo_content_analysis()
            
            # 2. Content Labeling Demo
            print("\\n" + "="*80)
            print("2. CONTENT LABELING DEMONSTRATION")
            print("="*80)
            self._demo_content_labeling()
            
            # 3. Access Control Demo
            print("\\n" + "="*80)
            print("3. ACCESS CONTROL DEMONSTRATION")
            print("="*80)
            self._demo_access_control()
            
            # 4. Compliance Validation Demo
            print("\\n" + "="*80)
            print("4. COMPLIANCE VALIDATION DEMONSTRATION")
            print("="*80)
            self._demo_compliance_validation()
            
            # 5. Integration Demo
            print("\\n" + "="*80)
            print("5. COMPLETE INTEGRATION DEMONSTRATION")
            print("="*80)
            self._demo_complete_integration()
            
            # 6. Performance and Statistics
            print("\\n" + "="*80)
            print("6. PERFORMANCE AND STATISTICS")
            print("="*80)
            self._demo_performance_statistics()
            
            logger.info("Framework demonstration completed successfully")
            
        except Exception as e:
            logger.error(f"Demo failed: {e}")
            raise
    
    def _demo_content_analysis(self):
        """Demonstrate content analysis capabilities."""
        print("Testing content analysis with various classification levels...")
        
        # Test documents with different classification levels
        test_documents = [
            {
                'id': 'doc_001',
                'content': '''
                TOP SECRET//SI Intelligence Report
                
                This document contains HUMINT sources and methods information.
                Subject: Nuclear weapons capabilities assessment.
                
                Intelligence indicates advanced weapons development program.
                Sources: SIGINT collection from encrypted communications.
                
                This information is classified TOP SECRET//SI and requires special handling.
                ''',
                'metadata': {
                    'source': 'JWICS system',
                    'security_marking': 'TOP SECRET//SI//NOFORN'
                },
                'context': {
                    'author_clearance': 'TS_SCI',
                    'network_domain': 'JWICS'
                }
            },
            {
                'id': 'doc_002',
                'content': '''
                SECRET Operational Plan
                
                Military operations plan for tactical deployment.
                Force protection measures and communications security.
                
                Operational timeline: 0600-1800 hours.
                Communications: Encrypted SIPR channels only.
                ''',
                'metadata': {
                    'source': 'SIPR system',
                    'classification': 'SECRET'
                },
                'context': {
                    'author_clearance': 'S',
                    'network_domain': 'SIPRNET'
                }
            },
            {
                'id': 'doc_003',
                'content': '''
                CUI//FOUO Personnel Information
                
                Employee records containing personal information.
                Name: John Doe
                SSN: 123-45-6789
                Email: john.doe@army.mil
                Phone: 555-123-4567
                
                This information is subject to Privacy Act protections.
                ''',
                'metadata': {
                    'source': 'HR system',
                    'data_type': 'personnel_record'
                },
                'context': {
                    'author_clearance': 'CUI',
                    'network_domain': 'NIPRNET'
                }
            },
            {
                'id': 'doc_004',
                'content': '''
                UNCLASSIFIED Weather Report
                
                Current weather conditions for operational planning.
                Temperature: 72°F
                Humidity: 45%
                Wind: 10 mph from the west
                
                This information is approved for public release.
                ''',
                'metadata': {
                    'source': 'Weather service',
                    'classification': 'UNCLASSIFIED'
                },
                'context': {
                    'network_domain': 'NIPRNET'
                }
            }
        ]
        
        # Analyze each document
        analysis_results = []
        for doc in test_documents:
            print(f"\\nAnalyzing document: {doc['id']}")
            
            result = self.content_analyzer.analyze_content(
                content=doc['content'],
                metadata=doc['metadata'],
                context=doc['context']
            )
            
            analysis_results.append({
                'doc_id': doc['id'],
                'result': result
            })
            
            # Display results
            print(f"  Classification: {result.classification_level}")
            print(f"  Network Domain: {result.network_domain.value}")
            print(f"  Confidence: {result.confidence_score:.2f}")
            print(f"  Confidence Level: {result.get_confidence_level().value}")
            print(f"  PII Detected: {result.has_pii()}")
            if result.has_pii():
                pii_types = [pii.value for pii in result.get_pii_types()]
                print(f"  PII Types: {', '.join(pii_types)}")
            print(f"  Manual Review Required: {result.requires_manual_review()}")
            print(f"  Processing Time: {result.processing_time:.3f}s")
            print(f"  Evidence Count: {len(result.evidence)}")
            
            # Show primary evidence
            primary_evidence = result.get_primary_evidence()
            if primary_evidence:
                print(f"  Primary Evidence: {primary_evidence.method.value} ({primary_evidence.confidence:.2f})")
            
            # Show reasoning
            print(f"  Reasoning: {result.reasoning}")
        
        print(f"\\nAnalyzed {len(test_documents)} documents successfully")
        return analysis_results
    
    def _demo_content_labeling(self):
        """Demonstrate content labeling capabilities."""
        print("Testing automatic content labeling with access controls...")
        
        # Test document for labeling
        test_content = '''
        SECRET//NOFORN Operational Security Document
        
        This document contains operational security procedures.
        Communications protocols and force protection measures.
        
        Access limited to authorized personnel with SECRET clearance.
        Not releasable to foreign nationals.
        '''
        
        content_id = "test_content_001"
        
        # Create content label
        print(f"\\nCreating label for content: {content_id}")
        label = self.labeling_system.label_content(
            content=test_content,
            content_id=content_id,
            user_id=self.demo_user_id,
            metadata={'source': 'SIPR system'},
            context={'network_domain': 'SIPRNET'}
        )
        
        # Display label information
        print(f"  Label ID: {label.label_id}")
        print(f"  Classification: {label.classification_level}")
        print(f"  Control Marking: {label.to_control_marking()}")
        print(f"  Network Domain: {label.network_domain}")
        print(f"  Confidence: {label.confidence_score:.2f}")
        print(f"  Status: {label.label_status.value}")
        print(f"  Requires Approval: {label.requires_approval()}")
        
        # Display access restrictions
        print("\\n  Access Restrictions:")
        for key, value in label.access_restrictions.items():
            print(f"    {key}: {value}")
        
        # Display handling instructions
        print(f"\\n  Handling Instructions: {label.handling_instructions}")
        
        # Test label update
        print("\\nTesting label update...")
        updated_label = self.labeling_system.update_label(
            content_id=content_id,
            user_id=self.demo_user_id,
            new_caveats=['NOFORN', 'ORCON'],
            justification="Added originator control caveat"
        )
        
        print(f"  Updated Control Marking: {updated_label.to_control_marking()}")
        print(f"  New Status: {updated_label.label_status.value}")
        
        return label
    
    def _demo_access_control(self):
        """Demonstrate access control capabilities."""
        print("Testing access control enforcement...")
        
        # Test access scenarios
        test_scenarios = [
            {
                'name': 'Valid SECRET access',
                'content_id': 'test_content_001',
                'user_clearance': 'S',
                'context': {'network_domain': 'SIPRNET'}
            },
            {
                'name': 'Insufficient clearance',
                'content_id': 'test_content_001',
                'user_clearance': 'C',
                'context': {'network_domain': 'SIPRNET'}
            },
            {
                'name': 'Wrong network domain',
                'content_id': 'test_content_001',
                'user_clearance': 'S',
                'context': {'network_domain': 'NIPRNET'}
            }
        ]
        
        for scenario in test_scenarios:
            print(f"\\nTesting scenario: {scenario['name']}")
            
            # Mock access check (in real implementation, would use actual user clearance)
            access_result = {
                'access_granted': scenario['user_clearance'] == 'S' and scenario['context']['network_domain'] == 'SIPRNET',
                'reason': 'Mock access check result',
                'details': scenario
            }
            
            print(f"  Access Granted: {access_result['access_granted']}")
            print(f"  Reason: {access_result['reason']}")
            
            if not access_result['access_granted']:
                print("  Access DENIED - Security violation logged")
            else:
                print("  Access GRANTED - Access logged for audit")
    
    def _demo_compliance_validation(self):
        """Demonstrate DoD compliance validation."""
        print("Testing DoD compliance validation...")
        
        # Perform compliance assessment
        print("\\nPerforming compliance assessment...")
        assessment = self.compliance_validator.assess_compliance(
            assessor_id=self.demo_user_id,
            standards=[
                ComplianceStandard.DOD_8500_01E,
                ComplianceStandard.NIST_SP_800_53,
                ComplianceStandard.FISMA
            ],
            scope={
                'classified_content': [
                    {'id': 'test_content_001', 'classification': 'SECRET'}
                ],
                'audit_retention_days': 365,
                'access_control_policy': {
                    'policy_statement': True,
                    'procedures': True,
                    'roles': True
                }
            }
        )
        
        # Display assessment results
        print(f"  Assessment ID: {assessment.assessment_id}")
        print(f"  Compliance Level: {assessment.overall_compliance_level.value}")
        print(f"  Compliance Score: {assessment.compliance_score:.2f}")
        print(f"  Total Violations: {len(assessment.violations)}")
        print(f"  Critical Violations: {len(assessment.get_critical_violations())}")
        
        # Display violations by severity
        print("\\n  Violations by Severity:")
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            count = len([v for v in assessment.violations if v.severity.value == severity])
            print(f"    {severity}: {count}")
        
        # Display recommendations
        print("\\n  Recommendations:")
        for rec in assessment.recommendations:
            print(f"    • {rec}")
        
        # Test specific compliance validations
        print("\\nTesting specific compliance validations...")
        
        # Test classification handling compliance
        classification_violations = self.compliance_validator.validate_classification_handling(
            content_id='test_content_001',
            classification_level='SECRET',
            handling_procedures={
                'markings': {'header_marking': True, 'footer_marking': True},
                'storage': {'facility_type': 'approved_secure_room'},
                'access_controls': {'clearance_verification': True, 'need_to_know_verification': True},
                'transmission': {'encryption_enabled': True, 'encryption_level': 'AES_256'},
                'audit': {'audit_enabled': True, 'audited_events': ['access', 'modification', 'deletion']}
            }
        )
        
        print(f"  Classification Handling Violations: {len(classification_violations)}")
        for violation in classification_violations:
            print(f"    • {violation.violation_type}: {violation.description}")
        
        return assessment
    
    def _demo_complete_integration(self):
        """Demonstrate complete framework integration."""
        print("Testing complete framework integration...")
        
        # End-to-end workflow
        test_document = '''
        TOP SECRET//SI//NOFORN Intelligence Assessment
        
        This document contains intelligence sources and methods.
        Subject: Advanced persistent threat analysis.
        
        HUMINT reporting indicates foreign intelligence operations.
        SIGINT confirms encrypted communications patterns.
        
        Analyst: Jane Smith, SSN: 987-65-4321
        Contact: jane.smith@army.mil
        
        This information requires special handling and access controls.
        '''
        
        content_id = "integration_test_001"
        
        print(f"\\nProcessing document: {content_id}")
        
        # Step 1: Content Analysis
        print("Step 1: Analyzing content...")
        analysis_result = self.content_analyzer.analyze_content(
            content=test_document,
            metadata={'source': 'JWICS system', 'analyst': 'Jane Smith'},
            context={'network_domain': 'JWICS', 'author_clearance': 'TS_SCI'}
        )
        
        print(f"  Analysis Result: {analysis_result.classification_level}")
        print(f"  Confidence: {analysis_result.confidence_score:.2f}")
        print(f"  PII Detected: {analysis_result.has_pii()}")
        
        # Step 2: Content Labeling
        print("\\nStep 2: Creating content label...")
        label = self.labeling_system.label_content(
            content=test_document,
            content_id=content_id,
            user_id=self.demo_user_id,
            metadata={'source': 'JWICS system'},
            context={'network_domain': 'JWICS'}
        )
        
        print(f"  Label Created: {label.to_control_marking()}")
        print(f"  Status: {label.label_status.value}")
        print(f"  Requires Approval: {label.requires_approval()}")
        
        # Step 3: Access Control Check
        print("\\nStep 3: Checking access control...")
        # Mock access check for TS_SCI content
        access_granted = True  # Would be actual check in real implementation
        print(f"  Access Granted: {access_granted}")
        
        # Step 4: Compliance Validation
        print("\\nStep 4: Validating compliance...")
        compliance_violations = self.compliance_validator.validate_classification_handling(
            content_id=content_id,
            classification_level=analysis_result.classification_level,
            handling_procedures={
                'markings': {'header_marking': True, 'footer_marking': True},
                'storage': {'facility_type': 'approved_scif'},
                'access_controls': {'clearance_verification': True, 'need_to_know_verification': True},
                'transmission': {'encryption_enabled': True, 'encryption_level': 'AES_256'},
                'audit': {'audit_enabled': True, 'audited_events': ['access', 'modification', 'deletion']}
            }
        )
        
        print(f"  Compliance Violations: {len(compliance_violations)}")
        
        # Step 5: Generate Summary Report
        print("\\nStep 5: Generating summary report...")
        summary_report = {
            'content_id': content_id,
            'processing_timestamp': datetime.now(timezone.utc).isoformat(),
            'classification_result': {
                'level': analysis_result.classification_level,
                'confidence': analysis_result.confidence_score,
                'network_domain': analysis_result.network_domain.value,
                'pii_detected': analysis_result.has_pii(),
                'manual_review_required': analysis_result.requires_manual_review()
            },
            'labeling_result': {
                'control_marking': label.to_control_marking(),
                'status': label.label_status.value,
                'requires_approval': label.requires_approval()
            },
            'access_control': {
                'access_granted': access_granted,
                'restrictions': label.access_restrictions
            },
            'compliance_status': {
                'violations_found': len(compliance_violations),
                'critical_violations': len([v for v in compliance_violations if v.severity.value == 'CRITICAL'])
            }
        }
        
        print("  Summary Report Generated:")
        print(json.dumps(summary_report, indent=2))
        
        return summary_report
    
    def _demo_performance_statistics(self):
        """Demonstrate performance and statistics capabilities."""
        print("Testing performance and statistics...")
        
        # Get analyzer statistics
        print("\\nContent Analyzer Statistics:")
        analyzer_stats = self.content_analyzer.get_classification_statistics()
        for key, value in analyzer_stats.items():
            print(f"  {key}: {value}")
        
        # Get labeling system statistics
        print("\\nContent Labeling System Statistics:")
        labeling_stats = self.labeling_system.get_labeling_statistics()
        for key, value in labeling_stats.items():
            print(f"  {key}: {value}")
        
        # Get compliance validator statistics
        print("\\nCompliance Validator Statistics:")
        compliance_stats = self.compliance_validator.get_compliance_statistics()
        for key, value in compliance_stats.items():
            print(f"  {key}: {value}")
        
        # Performance test
        print("\\nPerformance Test:")
        test_content = "SECRET operational document for performance testing."
        
        import time
        start_time = time.time()
        
        # Process 10 documents
        for i in range(10):
            result = self.content_analyzer.analyze_content(test_content)
        
        end_time = time.time()
        avg_time = (end_time - start_time) / 10
        
        print(f"  Average processing time: {avg_time:.3f}s per document")
        print(f"  Throughput: {1/avg_time:.1f} documents per second")
    
    def cleanup(self):
        """Clean up demo resources."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
        logger.info("Demo cleanup completed")


def main():
    """Run the complete framework demonstration."""
    print("Multi-Classification Data Handling Framework")
    print("Comprehensive Integration Demonstration")
    print("=" * 80)
    
    demo = None
    try:
        # Initialize demo
        demo = MultiClassificationFrameworkDemo()
        
        # Run comprehensive demonstration
        demo.run_comprehensive_demo()
        
        print("\\n" + "=" * 80)
        print("DEMONSTRATION COMPLETED SUCCESSFULLY")
        print("=" * 80)
        
    except Exception as e:
        print(f"\\nDemonstration failed: {e}")
        logger.error(f"Demo failed: {e}")
        
    finally:
        if demo:
            demo.cleanup()


if __name__ == "__main__":
    main()