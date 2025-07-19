"""
Test Suite for Enhanced Content Analyzer

Tests the automatic content analysis module for multi-classification
data handling framework with ML-based classification scanning.

Classification: UNCLASSIFIED//FOR OFFICIAL USE ONLY
Version: 1.0
Date: 2025-07-17
"""

import unittest
import tempfile
import os
import json
from datetime import datetime
from unittest.mock import patch, MagicMock

# Import the enhanced content analyzer
from ..models.enhanced_content_analyzer import (
    EnhancedContentAnalyzer, 
    NetworkDomain, 
    DataSensitivity, 
    ClassificationReason,
    AnalysisMethod,
    ConfidenceLevel,
    PIIType,
    ClassificationRule,
    PIIDetectionResult,
    ClassificationEvidence,
    ClassificationResult
)


class TestEnhancedContentAnalyzer(unittest.TestCase):
    """Test suite for EnhancedContentAnalyzer."""
    
    def setUp(self):
        """Set up test environment."""
        self.temp_dir = tempfile.mkdtemp()
        self.analyzer = EnhancedContentAnalyzer(
            model_path=self.temp_dir,
            enable_ml=True
        )
        
    def tearDown(self):
        """Clean up test environment."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_initialization(self):
        """Test analyzer initialization."""
        self.assertIsNotNone(self.analyzer)
        self.assertTrue(self.analyzer.enable_ml)
        self.assertEqual(self.analyzer.model_path, self.temp_dir)
        self.assertIsNotNone(self.analyzer._classification_patterns)
        self.assertIsNotNone(self.analyzer._pii_patterns)
        self.assertIsNotNone(self.analyzer._keyword_weights)
        self.assertIsNotNone(self.analyzer._classification_rules)
    
    def test_top_secret_sci_classification(self):
        """Test TOP SECRET//SCI classification detection."""
        test_content = "This document contains TOP SECRET//SI intelligence sources and methods."
        
        result = self.analyzer.analyze_content(test_content)
        
        self.assertEqual(result.classification_level, 'TS_SCI')
        self.assertEqual(result.network_domain, NetworkDomain.JWICS)
        self.assertEqual(result.sensitivity_level, DataSensitivity.TOP_SECRET)
        self.assertGreater(result.confidence_score, 0.5)
        self.assertTrue(result.requires_manual_review())
    
    def test_secret_classification(self):
        """Test SECRET classification detection."""
        test_content = "SECRET military operations plan for tactical deployment."
        
        result = self.analyzer.analyze_content(test_content)
        
        self.assertEqual(result.classification_level, 'S')
        self.assertEqual(result.network_domain, NetworkDomain.SIPRNET)
        self.assertEqual(result.sensitivity_level, DataSensitivity.SECRET)
        self.assertGreater(result.confidence_score, 0.3)
    
    def test_confidential_classification(self):
        """Test CONFIDENTIAL classification detection."""
        test_content = "CONFIDENTIAL personnel records and administrative data."
        
        result = self.analyzer.analyze_content(test_content)
        
        self.assertEqual(result.classification_level, 'C')
        self.assertEqual(result.network_domain, NetworkDomain.SIPRNET)
        self.assertEqual(result.sensitivity_level, DataSensitivity.CONFIDENTIAL)
        self.assertGreater(result.confidence_score, 0.3)
    
    def test_cui_classification(self):
        """Test CUI classification detection."""
        test_content = "CUI//FOUO - Personal information subject to privacy act."
        
        result = self.analyzer.analyze_content(test_content)
        
        self.assertEqual(result.classification_level, 'CUI')
        self.assertEqual(result.network_domain, NetworkDomain.NIPRNET)
        self.assertEqual(result.sensitivity_level, DataSensitivity.INTERNAL)
        self.assertGreater(result.confidence_score, 0.3)
    
    def test_unclassified_classification(self):
        """Test UNCLASSIFIED classification detection."""
        test_content = "UNCLASSIFIED public information about weather conditions."
        
        result = self.analyzer.analyze_content(test_content)
        
        self.assertEqual(result.classification_level, 'U')
        self.assertEqual(result.network_domain, NetworkDomain.NIPRNET)
        self.assertEqual(result.sensitivity_level, DataSensitivity.PUBLIC)
    
    def test_pii_detection_ssn(self):
        """Test PII detection for SSN."""
        test_content = "Employee SSN: 123-45-6789 requires protection."
        
        result = self.analyzer.analyze_content(test_content)
        
        self.assertTrue(result.has_pii())
        self.assertIn(PIIType.SSN, result.get_pii_types())
        self.assertEqual(result.classification_level, 'CUI')
        self.assertTrue(result.requires_manual_review())
    
    def test_pii_detection_dod_id(self):
        """Test PII detection for DoD ID."""
        test_content = "DoD ID: 1234567890 assigned to service member."
        
        result = self.analyzer.analyze_content(test_content)
        
        self.assertTrue(result.has_pii())
        self.assertIn(PIIType.DOD_ID, result.get_pii_types())
        self.assertEqual(result.classification_level, 'CUI')
    
    def test_pii_detection_email(self):
        """Test PII detection for email addresses."""
        test_content = "Contact john.doe@army.mil for more information."
        
        result = self.analyzer.analyze_content(test_content)
        
        self.assertTrue(result.has_pii())
        self.assertIn(PIIType.EMAIL, result.get_pii_types())
    
    def test_multiple_pii_detection(self):
        """Test detection of multiple PII types."""
        test_content = "John Doe, SSN: 123-45-6789, Email: john.doe@army.mil, Phone: 555-123-4567"
        
        result = self.analyzer.analyze_content(test_content)
        
        self.assertTrue(result.has_pii())
        detected_types = result.get_pii_types()
        self.assertIn(PIIType.SSN, detected_types)
        self.assertIn(PIIType.EMAIL, detected_types)
        self.assertIn(PIIType.PHONE, detected_types)
        self.assertEqual(result.classification_level, 'CUI')
    
    def test_keyword_analysis(self):
        """Test keyword-based classification analysis."""
        test_content = "Nuclear weapons capabilities and strategic defense systems."
        
        result = self.analyzer.analyze_content(test_content)
        
        # Should detect TS keywords
        self.assertIn(result.classification_level, ['TS', 'TS_SCI'])
        self.assertGreater(result.confidence_score, 0.0)
    
    def test_intelligence_keywords(self):
        """Test intelligence-related keyword detection."""
        test_content = "HUMINT sources and SIGINT collection methods are classified."
        
        result = self.analyzer.analyze_content(test_content)
        
        self.assertEqual(result.classification_level, 'TS_SCI')
        self.assertEqual(result.network_domain, NetworkDomain.JWICS)
    
    def test_metadata_analysis(self):
        """Test metadata-based classification."""
        test_content = "Regular document content."
        metadata = {
            'classification': 'SECRET',
            'source': 'SIPR system',
            'security_marking': 'SECRET//NOFORN'
        }
        
        result = self.analyzer.analyze_content(test_content, metadata=metadata)
        
        self.assertEqual(result.classification_level, 'S')
        self.assertEqual(result.network_domain, NetworkDomain.SIPRNET)
    
    def test_context_analysis(self):
        """Test context-based classification."""
        test_content = "Standard operational procedures document."
        context = {
            'author_clearance': 'TS',
            'project_classification': 'SECRET',
            'network_domain': 'SIPRNET'
        }
        
        result = self.analyzer.analyze_content(test_content, context=context)
        
        self.assertEqual(result.classification_level, 'S')
        self.assertEqual(result.network_domain, NetworkDomain.SIPRNET)
    
    def test_classification_rules_engine(self):
        """Test classification rules engine."""
        # Test that rules are properly applied
        test_content = "Nuclear weapons development program details."
        
        result = self.analyzer.analyze_content(test_content)
        
        # Should trigger nuclear weapons rule
        self.assertIn(result.classification_level, ['TS', 'TS_SCI'])
        self.assertGreater(result.confidence_score, 0.0)
    
    def test_ml_classification_disabled(self):
        """Test analyzer with ML disabled."""
        analyzer_no_ml = EnhancedContentAnalyzer(enable_ml=False)
        test_content = "This is a test document with no explicit classification."
        
        result = analyzer_no_ml.analyze_content(test_content)
        
        self.assertIsNotNone(result)
        self.assertIsInstance(result, ClassificationResult)
    
    def test_confidence_levels(self):
        """Test confidence level calculation."""
        # High confidence case
        test_content = "TOP SECRET//SI intelligence document."
        result = self.analyzer.analyze_content(test_content)
        self.assertIn(result.get_confidence_level(), [ConfidenceLevel.HIGH, ConfidenceLevel.VERY_HIGH])
        
        # Low confidence case
        test_content = "Ambiguous document with mixed signals."
        result = self.analyzer.analyze_content(test_content)
        self.assertIsNotNone(result.get_confidence_level())
    
    def test_evidence_collection(self):
        """Test evidence collection and reasoning."""
        test_content = "SECRET operational plans with SSN: 123-45-6789"
        
        result = self.analyzer.analyze_content(test_content)
        
        self.assertGreater(len(result.evidence), 0)
        self.assertIsNotNone(result.get_primary_evidence())
        self.assertIsNotNone(result.reasoning)
    
    def test_risk_assessment(self):
        """Test risk assessment generation."""
        test_content = "TOP SECRET//SI nuclear weapons information."
        
        result = self.analyzer.analyze_content(test_content)
        
        self.assertIsNotNone(result.risk_assessment)
        self.assertIn('risk_level', result.risk_assessment)
        self.assertIn('risk_factors', result.risk_assessment)
        self.assertTrue(result.risk_assessment['mitigation_required'])
    
    def test_recommendations_generation(self):
        """Test recommendations generation."""
        test_content = "TOP SECRET document with PII: 123-45-6789"
        
        result = self.analyzer.analyze_content(test_content)
        
        self.assertGreater(len(result.recommendations), 0)
        self.assertTrue(any('manual review' in rec.lower() for rec in result.recommendations))
    
    def test_network_domain_mapping(self):
        """Test network domain mapping for different classification levels."""
        test_cases = [
            ("UNCLASSIFIED document", NetworkDomain.NIPRNET),
            ("CUI//FOUO information", NetworkDomain.NIPRNET),
            ("SECRET operational data", NetworkDomain.SIPRNET),
            ("CONFIDENTIAL personnel info", NetworkDomain.SIPRNET),
            ("TOP SECRET intelligence", NetworkDomain.JWICS),
            ("TOP SECRET//SI sources", NetworkDomain.JWICS)
        ]
        
        for content, expected_domain in test_cases:
            result = self.analyzer.analyze_content(content)
            self.assertEqual(result.network_domain, expected_domain)
    
    def test_processing_time_tracking(self):
        """Test processing time tracking."""
        test_content = "Test document for timing analysis."
        
        result = self.analyzer.analyze_content(test_content)
        
        self.assertGreater(result.processing_time, 0.0)
        self.assertLess(result.processing_time, 10.0)  # Should be reasonable
    
    def test_audit_logging(self):
        """Test audit logging functionality."""
        test_content = "SECRET document requiring audit trail."
        
        with patch.object(self.analyzer._audit_logger, 'info') as mock_logger:
            result = self.analyzer.analyze_content(test_content)
            
            # Verify audit logging was called
            mock_logger.assert_called_once()
            audit_data = mock_logger.call_args[0][0]
            self.assertIn('Classification audit:', audit_data)
    
    def test_error_handling(self):
        """Test error handling and safe defaults."""
        # Test with problematic content
        test_content = None
        
        result = self.analyzer.analyze_content(test_content)
        
        self.assertIsNotNone(result)
        self.assertEqual(result.classification_level, 'CUI')  # Safe default
        self.assertEqual(result.confidence_score, 0.0)
    
    def test_add_classification_rule(self):
        """Test adding custom classification rules."""
        new_rule = ClassificationRule(
            id="test_rule",
            name="Test Rule",
            description="Test rule for unit testing",
            pattern=r"\\btest_pattern\\b",
            classification_level="C",
            confidence_weight=0.8
        )
        
        success = self.analyzer.add_classification_rule(new_rule)
        self.assertTrue(success)
        
        # Test rule application
        test_content = "Document with test_pattern keyword."
        result = self.analyzer.analyze_content(test_content)
        
        # Should be influenced by new rule
        self.assertIsNotNone(result)
    
    def test_remove_classification_rule(self):
        """Test removing classification rules."""
        # First add a rule
        rule_id = "test_rule_remove"
        new_rule = ClassificationRule(
            id=rule_id,
            name="Test Rule to Remove",
            description="Test rule for removal testing",
            pattern=r"\\bremove_test\\b",
            classification_level="C",
            confidence_weight=0.8
        )
        
        self.analyzer.add_classification_rule(new_rule)
        success = self.analyzer.remove_classification_rule(rule_id)
        self.assertTrue(success)
    
    def test_classification_statistics(self):
        """Test classification statistics generation."""
        stats = self.analyzer.get_classification_statistics()
        
        self.assertIsInstance(stats, dict)
        self.assertIn('ml_enabled', stats)
        self.assertIn('classification_rules_count', stats)
        self.assertIn('pii_patterns_count', stats)
        self.assertIn('classification_patterns_count', stats)
        self.assertIn('keyword_weights_count', stats)
    
    def test_model_training(self):
        """Test ML model training functionality."""
        training_data = [
            {'text': 'TOP SECRET intelligence report', 'classification': 'TS'},
            {'text': 'SECRET operational plan', 'classification': 'S'},
            {'text': 'CONFIDENTIAL personnel data', 'classification': 'C'},
            {'text': 'UNCLASSIFIED public information', 'classification': 'U'},
            {'text': 'CUI personal information', 'classification': 'CUI'}
        ]
        
        result = self.analyzer.train_model(training_data)
        
        self.assertIsInstance(result, dict)
        self.assertIn('success', result)
        if result['success']:
            self.assertIn('accuracy', result)
            self.assertIn('model_path', result)
    
    def test_comprehensive_analysis(self):
        """Test comprehensive analysis with multiple detection methods."""
        test_content = """
        TOP SECRET//SI Intelligence Report
        
        This document contains HUMINT sources and methods information.
        Subject: John Doe, SSN: 123-45-6789, Email: john.doe@army.mil
        
        Nuclear weapons capabilities assessment for strategic planning.
        SIGINT collection methods and communication security protocols.
        
        This information is classified TOP SECRET and requires special handling.
        """
        
        metadata = {
            'source': 'JWICS system',
            'security_marking': 'TOP SECRET//SI//NOFORN'
        }
        
        context = {
            'author_clearance': 'TS_SCI',
            'project_classification': 'TS',
            'network_domain': 'JWICS'
        }
        
        result = self.analyzer.analyze_content(test_content, metadata=metadata, context=context)
        
        # Should detect highest classification
        self.assertEqual(result.classification_level, 'TS_SCI')
        self.assertEqual(result.network_domain, NetworkDomain.JWICS)
        self.assertEqual(result.sensitivity_level, DataSensitivity.TOP_SECRET)
        
        # Should detect PII
        self.assertTrue(result.has_pii())
        self.assertIn(PIIType.SSN, result.get_pii_types())
        self.assertIn(PIIType.EMAIL, result.get_pii_types())
        
        # Should have high confidence
        self.assertGreater(result.confidence_score, 0.5)
        
        # Should require manual review
        self.assertTrue(result.requires_manual_review())
        
        # Should have comprehensive evidence
        self.assertGreater(len(result.evidence), 3)
        
        # Should have risk assessment
        self.assertEqual(result.risk_assessment['risk_level'], 'HIGH')
        
        # Should have recommendations
        self.assertGreater(len(result.recommendations), 0)
    
    def test_batch_processing(self):
        """Test batch processing capabilities."""
        test_documents = [
            "TOP SECRET intelligence document",
            "SECRET operational plan",
            "CONFIDENTIAL personnel record",
            "UNCLASSIFIED public information",
            "CUI personal data with SSN: 123-45-6789"
        ]
        
        results = []
        for doc in test_documents:
            result = self.analyzer.analyze_content(doc)
            results.append(result)
        
        self.assertEqual(len(results), 5)
        
        # Check that different classification levels were detected
        classifications = [r.classification_level for r in results]
        self.assertIn('TS', classifications)
        self.assertIn('S', classifications)
        self.assertIn('C', classifications)
        self.assertIn('U', classifications)
        self.assertIn('CUI', classifications)
    
    def test_performance_benchmarking(self):
        """Test performance benchmarking."""
        test_content = "SECRET operational document for performance testing."
        
        import time
        start_time = time.time()
        
        # Process multiple documents
        for _ in range(10):
            result = self.analyzer.analyze_content(test_content)
        
        end_time = time.time()
        avg_time = (end_time - start_time) / 10
        
        # Should process reasonably quickly
        self.assertLess(avg_time, 1.0)  # Less than 1 second per document
    
    def test_edge_cases(self):
        """Test edge cases and boundary conditions."""
        edge_cases = [
            "",  # Empty string
            "   ",  # Whitespace only
            "a" * 10000,  # Very long string
            "Mixed CASE classification MARKINGS",
            "Classification: SECRET but also CONFIDENTIAL",
            "123-45-6789 SSN 987-65-4321 multiple SSNs"
        ]
        
        for content in edge_cases:
            result = self.analyzer.analyze_content(content)
            self.assertIsNotNone(result)
            self.assertIsInstance(result, ClassificationResult)


class TestClassificationRules(unittest.TestCase):
    """Test classification rules functionality."""
    
    def test_rule_creation(self):
        """Test classification rule creation."""
        rule = ClassificationRule(
            id="test_001",
            name="Test Rule",
            description="Test rule description",
            pattern=r"\\btest\\b",
            classification_level="C",
            confidence_weight=0.7
        )
        
        self.assertEqual(rule.id, "test_001")
        self.assertEqual(rule.name, "Test Rule")
        self.assertEqual(rule.classification_level, "C")
        self.assertEqual(rule.confidence_weight, 0.7)
        self.assertTrue(rule.active)
    
    def test_rule_metadata(self):
        """Test rule metadata handling."""
        rule = ClassificationRule(
            id="test_002",
            name="Test Rule with Metadata",
            description="Test rule with metadata",
            pattern=r"\\bmetadata\\b",
            classification_level="S",
            confidence_weight=0.8,
            metadata={"source": "test", "priority": "high"}
        )
        
        self.assertEqual(rule.metadata["source"], "test")
        self.assertEqual(rule.metadata["priority"], "high")


class TestPIIDetection(unittest.TestCase):
    """Test PII detection functionality."""
    
    def test_pii_result_creation(self):
        """Test PII detection result creation."""
        result = PIIDetectionResult(
            pii_type=PIIType.SSN,
            matches=["123-45-6789"],
            confidence=0.9,
            sensitivity_impact="CUI",
            mitigation_required=True
        )
        
        self.assertEqual(result.pii_type, PIIType.SSN)
        self.assertEqual(result.matches, ["123-45-6789"])
        self.assertEqual(result.confidence, 0.9)
        self.assertTrue(result.mitigation_required)
    
    def test_pii_location_tracking(self):
        """Test PII location tracking."""
        result = PIIDetectionResult(
            pii_type=PIIType.EMAIL,
            matches=["test@example.com"],
            confidence=0.8,
            sensitivity_impact="CUI",
            mitigation_required=False,
            location_info=[{"start": 10, "end": 25, "text": "test@example.com"}]
        )
        
        self.assertEqual(len(result.location_info), 1)
        self.assertEqual(result.location_info[0]["start"], 10)
        self.assertEqual(result.location_info[0]["end"], 25)


class TestEvidence(unittest.TestCase):
    """Test evidence collection and reasoning."""
    
    def test_evidence_creation(self):
        """Test evidence creation."""
        evidence = ClassificationEvidence(
            method=AnalysisMethod.PATTERN_MATCHING,
            confidence=0.8,
            evidence_type="pattern_match",
            evidence_data={"matches": ["SECRET"]},
            weight=0.3,
            reasoning="Pattern matching detected SECRET marking"
        )
        
        self.assertEqual(evidence.method, AnalysisMethod.PATTERN_MATCHING)
        self.assertEqual(evidence.confidence, 0.8)
        self.assertEqual(evidence.weight, 0.3)
        self.assertIn("SECRET", evidence.reasoning)
    
    def test_evidence_metadata(self):
        """Test evidence metadata handling."""
        evidence = ClassificationEvidence(
            method=AnalysisMethod.MACHINE_LEARNING,
            confidence=0.9,
            evidence_type="ml_prediction",
            evidence_data={"prediction": "TS", "probabilities": {"TS": 0.9, "S": 0.1}},
            weight=0.25,
            reasoning="ML model predicts TS with 90% confidence",
            metadata={"model_version": "1.0", "accuracy": 0.85}
        )
        
        self.assertEqual(evidence.metadata["model_version"], "1.0")
        self.assertEqual(evidence.metadata["accuracy"], 0.85)


if __name__ == '__main__':
    # Set up test environment
    import sys
    import os
    
    # Add parent directory to path for imports
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    
    # Run tests
    unittest.main(verbosity=2)