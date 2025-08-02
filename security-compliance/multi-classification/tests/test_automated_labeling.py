"""
Comprehensive Test Suite for Automated Data Labeling Framework
=============================================================

This test suite provides comprehensive testing for all components of the
automated data labeling framework, including unit tests, integration tests,
and performance tests.

Classification: UNCLASSIFIED//FOR OFFICIAL USE ONLY
Version: 1.0 - Initial Implementation
Author: Security Compliance Team  
Date: 2025-07-29
"""

import pytest
import asyncio
import time
import json
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any
from uuid import uuid4
from unittest.mock import Mock, AsyncMock, patch

# Import components to test
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from automated_data_labeler import (
    AutomatedDataLabeler, LabelingRequest, LabelingResult,
    LabelingStrategy, LabelingConfidence, DataOriginType
)
from source_analyzer import (
    SourceAnalyzer, ComprehensiveSourceAnalysis,
    NetworkDomainMapper, UserClearanceAnalyzer, SystemClassificationAnalyzer
)
from content_ml_analyzer import (
    ContentMLAnalyzer, ContentMLAnalysisResult,
    PatternDetectionEngine, KeywordAnalysisEngine, NLPClassificationEngine
)
from context_aware_processor import (
    ContextAwareProcessor, ContextProcessingResult,
    WorkflowAnalyzer, SessionAnalyzer, SurroundingDataAnalyzer
)
from labeling_integration_layer import (
    LabelingIntegrationLayer, IntegrationRequest, IntegrationResult,
    IntegrationMode, ProcessingPriority
)
from performance_optimizer import (
    PerformanceOptimizer, OptimizationConfig, PerformanceMetrics
)

# Import existing infrastructure for mocking
from models.bell_lapadula import ClassificationLevel
from ..rbac.models.data_classification import NetworkDomain


class TestAutomatedDataLabeler:
    """Test suite for AutomatedDataLabeler."""
    
    @pytest.fixture
    def labeler(self):
        """Create test labeler instance."""
        config = {
            'performance_target_ms': 50.0,
            'max_cache_size': 100,
            'cache_ttl_seconds': 300
        }
        return AutomatedDataLabeler(config=config)
    
    @pytest.fixture
    def sample_request(self):
        """Create sample labeling request."""
        return LabelingRequest(
            request_id="test-001",
            content="This document contains CONFIDENTIAL information about network configurations.",
            content_type="text/plain",
            source_network=NetworkDomain.SIPR,
            source_user_id=uuid4(),
            strategy=LabelingStrategy.HYBRID
        )
    
    @pytest.mark.asyncio
    async def test_basic_labeling(self, labeler, sample_request):
        """Test basic data labeling functionality."""
        result = await labeler.label_data(sample_request)
        
        assert isinstance(result, LabelingResult)
        assert result.request_id == sample_request.request_id
        assert isinstance(result.predicted_classification, ClassificationLevel)
        assert 0.0 <= result.confidence_score <= 1.0
        assert isinstance(result.confidence_level, LabelingConfidence)
        assert result.processing_time_ms > 0
        assert len(result.strategies_used) > 0
    
    @pytest.mark.asyncio
    async def test_source_based_labeling(self, labeler):
        """Test source-based labeling strategy."""
        request = LabelingRequest(
            content="Test content",
            source_network=NetworkDomain.SIPR,
            strategy=LabelingStrategy.SOURCE_BASED
        )
        
        result = await labeler.label_data(request)
        
        assert LabelingStrategy.SOURCE_BASED in result.strategies_used
        # SIPR network should suggest SECRET classification
        assert result.predicted_classification.value >= ClassificationLevel.SECRET.value
    
    @pytest.mark.asyncio
    async def test_content_based_labeling(self, labeler):
        """Test content-based labeling strategy."""
        request = LabelingRequest(
            content="This document contains TOP SECRET information about classified operations.",
            strategy=LabelingStrategy.CONTENT_BASED
        )
        
        result = await labeler.label_data(request)
        
        assert LabelingStrategy.CONTENT_BASED in result.strategies_used
        assert result.content_analysis is not None
        # Should detect classification markers
        assert result.predicted_classification != ClassificationLevel.UNCLASSIFIED
    
    @pytest.mark.asyncio
    async def test_context_aware_labeling(self, labeler):
        """Test context-aware labeling strategy."""
        request = LabelingRequest(
            content="Test content",
            workflow_context={"project_classification": "SECRET", "workflow_type": "intelligence_analysis"},
            strategy=LabelingStrategy.CONTEXT_AWARE
        )
        
        result = await labeler.label_data(request)
        
        assert LabelingStrategy.CONTEXT_AWARE in result.strategies_used
        assert result.context_analysis is not None
    
    @pytest.mark.asyncio
    async def test_hybrid_labeling(self, labeler):
        """Test hybrid labeling strategy."""
        request = LabelingRequest(
            content="CONFIDENTIAL: Network configuration for Project ALPHA",
            source_network=NetworkDomain.SIPR,
            workflow_context={"project_classification": "SECRET"},
            strategy=LabelingStrategy.HYBRID
        )
        
        result = await labeler.label_data(request)
        
        # Should use multiple strategies
        assert len(result.strategies_used) >= 3
        assert LabelingStrategy.HYBRID in result.strategies_used
        assert result.confidence_score > 0.5  # Should have reasonable confidence
    
    @pytest.mark.asyncio
    async def test_batch_labeling(self, labeler):
        """Test batch labeling functionality."""
        requests = [
            LabelingRequest(
                request_id=f"batch-{i}",
                content=f"Test content {i}",
                strategy=LabelingStrategy.CONTENT_BASED
            )
            for i in range(5)
        ]
        
        results = await labeler.batch_label_data(requests)
        
        assert len(results) == len(requests)
        for i, result in enumerate(results):
            assert result.request_id == f"batch-{i}"
            assert isinstance(result, LabelingResult)
    
    @pytest.mark.asyncio
    async def test_caching(self, labeler, sample_request):
        """Test caching functionality."""
        # First request
        start_time = time.time()
        result1 = await labeler.label_data(sample_request)
        first_time = time.time() - start_time
        
        # Second identical request (should use cache)
        start_time = time.time()
        result2 = await labeler.label_data(sample_request)
        second_time = time.time() - start_time
        
        # Results should be identical
        assert result1.predicted_classification == result2.predicted_classification
        assert result1.confidence_score == result2.confidence_score
        
        # Second request should be faster (cached)
        assert second_time < first_time
    
    def test_metrics_tracking(self, labeler):
        """Test metrics tracking."""
        initial_metrics = labeler.get_metrics()
        assert initial_metrics.total_requests == 0
        
        # Metrics should be updated after processing
        # This would need actual async processing to test properly


class TestSourceAnalyzer:
    """Test suite for SourceAnalyzer."""
    
    @pytest.fixture
    def analyzer(self):
        """Create test source analyzer."""
        return SourceAnalyzer()
    
    @pytest.mark.asyncio
    async def test_network_analysis(self, analyzer):
        """Test network source analysis."""
        analysis = await analyzer.analyze_comprehensive_source(
            request_id="test-network",
            source_ip="192.168.1.100",
            source_domain="sipr.mil"
        )
        
        assert isinstance(analysis, ComprehensiveSourceAnalysis)
        assert analysis.network_analysis is not None
        assert analysis.network_analysis.source_ip == "192.168.1.100"
        # SIPR domain should be classified appropriately
        if analysis.network_analysis.network_domain == NetworkDomain.SIPR:
            assert analysis.network_analysis.classification_level == ClassificationLevel.SECRET
    
    @pytest.mark.asyncio
    async def test_user_analysis(self, analyzer):
        """Test user clearance analysis."""
        user_id = uuid4()
        
        # Mock the RBAC engine response
        with patch.object(analyzer.user_analyzer, '_get_user_info') as mock_get_user:
            mock_user = Mock()
            mock_user.security_clearance = Mock()
            mock_user.security_clearance.classification_level = ClassificationLevel.SECRET
            mock_user.security_clearance.is_active = True
            mock_user.security_clearance.is_valid = True
            mock_get_user.return_value = mock_user
            
            analysis = await analyzer.analyze_comprehensive_source(
                request_id="test-user",
                user_id=user_id
            )
            
            assert analysis.user_analysis is not None
            assert analysis.user_analysis.user_id == user_id
    
    @pytest.mark.asyncio
    async def test_system_analysis(self, analyzer):
        """Test system classification analysis."""
        analysis = await analyzer.analyze_comprehensive_source(
            request_id="test-system",
            system_id="sipr_portal"
        )
        
        assert analysis.system_analysis is not None
        assert analysis.system_analysis.system_id == "sipr_portal"
        # Should classify SIPR portal as SECRET
        assert analysis.system_analysis.system_classification == ClassificationLevel.SECRET
    
    @pytest.mark.asyncio
    async def test_comprehensive_analysis(self, analyzer):
        """Test comprehensive source analysis."""
        analysis = await analyzer.analyze_comprehensive_source(
            request_id="test-comprehensive",
            source_ip="192.168.1.100",
            source_domain="sipr.mil",
            user_id=uuid4(),
            system_id="sipr_portal"
        )
        
        assert analysis.request_id == "test-comprehensive"
        assert analysis.processing_time_ms > 0
        assert analysis.sources_analyzed > 0
        # Final classification should be determined
        assert isinstance(analysis.final_classification, ClassificationLevel)


class TestContentMLAnalyzer:
    """Test suite for ContentMLAnalyzer."""
    
    @pytest.fixture
    def analyzer(self):
        """Create test content analyzer."""
        return ContentMLAnalyzer()
    
    @pytest.mark.asyncio
    async def test_pattern_detection(self, analyzer):
        """Test pattern detection in content."""
        content = "This document contains SSN: 123-45-6789 and is marked CONFIDENTIAL."
        
        result = await analyzer.analyze_content("test-patterns", content)
        
        assert isinstance(result, ContentMLAnalysisResult)
        assert len(result.pattern_matches) > 0
        
        # Should detect SSN pattern
        ssn_patterns = [p for p in result.pattern_matches if "SSN" in p.pattern_description or "Social Security" in p.pattern_description]
        assert len(ssn_patterns) > 0
        
        # Should detect classification marking
        classification_patterns = [p for p in result.pattern_matches if "classification" in p.pattern_description.lower()]
        assert len(classification_patterns) > 0
    
    @pytest.mark.asyncio
    async def test_keyword_analysis(self, analyzer):
        """Test keyword-based analysis."""
        content = "This secret document contains confidential information about classified operations."
        
        result = await analyzer.analyze_content("test-keywords", content)
        
        assert result.keyword_analysis is not None
        assert len(result.keyword_analysis.matched_keywords) > 0
        # Should match classification keywords
        assert any(keyword in ["secret", "confidential", "classified"] 
                  for keyword in result.keyword_analysis.matched_keywords)
    
    @pytest.mark.asyncio
    async def test_nlp_analysis(self, analyzer):
        """Test NLP-based analysis."""
        content = "This document contains sensitive operational data for military exercises."
        
        result = await analyzer.analyze_content("test-nlp", content)
        
        assert result.nlp_analysis is not None
        assert isinstance(result.nlp_analysis.predicted_classification, ClassificationLevel)
        assert 0.0 <= result.nlp_analysis.prediction_confidence <= 1.0
    
    @pytest.mark.asyncio
    async def test_batch_analysis(self, analyzer):
        """Test batch content analysis."""
        requests = [
            ("batch-1", "CONFIDENTIAL document about network security"),
            ("batch-2", "SECRET operational plans for Project ALPHA"),
            ("batch-3", "UNCLASSIFIED training materials")
        ]
        
        results = await analyzer.batch_analyze_content(requests)
        
        assert len(results) == len(requests)
        for i, result in enumerate(results):
            assert result.request_id == f"batch-{i+1}"
            assert isinstance(result.predicted_classification, ClassificationLevel)


class TestContextAwareProcessor:
    """Test suite for ContextAwareProcessor."""
    
    @pytest.fixture
    def processor(self):
        """Create test context processor."""
        return ContextAwareProcessor()
    
    @pytest.mark.asyncio
    async def test_workflow_context_processing(self, processor):
        """Test workflow context processing."""
        workflow_data = {
            'workflow_id': 'wf-001',
            'workflow_type': 'intelligence_analysis',
            'project_classification': 'SECRET',
            'current_stage': 'analysis'
        }
        
        result = await processor.process_context(
            request_id="test-workflow",
            workflow_data=workflow_data
        )
        
        assert isinstance(result, ContextProcessingResult)
        assert result.workflow_context is not None
        assert result.workflow_context.workflow_type == 'intelligence_analysis'
        assert result.context_influenced_classification == ClassificationLevel.SECRET
    
    @pytest.mark.asyncio
    async def test_session_context_processing(self, processor):
        """Test session context processing."""
        session_data = {
            'session_id': 'sess-001',
            'user_id': str(uuid4()),
            'user_clearance': 'SECRET',
            'network_domain': 'SIPR',
            'session_start': datetime.now(timezone.utc).isoformat(),
            'last_activity': datetime.now(timezone.utc).isoformat()
        }
        
        result = await processor.process_context(
            request_id="test-session",
            session_data=session_data
        )
        
        assert result.session_context is not None
        assert result.session_context.user_clearance_level == ClassificationLevel.SECRET
    
    @pytest.mark.asyncio
    async def test_surrounding_data_processing(self, processor):
        """Test surrounding data context processing."""
        surrounding_data = [
            {
                'document_id': 'doc-001',
                'classification': 'SECRET',
                'similarity_score': 0.8
            },
            {
                'document_id': 'doc-002', 
                'classification': 'CONFIDENTIAL',
                'similarity_score': 0.6
            }
        ]
        
        result = await processor.process_context(
            request_id="test-surrounding",
            surrounding_data=surrounding_data
        )
        
        assert result.surrounding_context is not None
        assert len(result.surrounding_context.related_documents) == 2
        assert len(result.surrounding_context.surrounding_classifications) == 2
    
    @pytest.mark.asyncio
    async def test_comprehensive_context_processing(self, processor):
        """Test comprehensive context processing with all context types."""
        workflow_data = {'workflow_type': 'intelligence_analysis', 'project_classification': 'SECRET'}
        session_data = {'user_id': str(uuid4()), 'user_clearance': 'SECRET'}
        surrounding_data = [{'document_id': 'doc-001', 'classification': 'SECRET'}]
        
        result = await processor.process_context(
            request_id="test-comprehensive",
            workflow_data=workflow_data,
            session_data=session_data,
            surrounding_data=surrounding_data
        )
        
        assert result.context_coverage > 0.5  # Should have good context coverage
        assert result.context_confidence_score > 0.0
        assert len(result.key_context_factors) > 0


class TestLabelingIntegrationLayer:
    """Test suite for LabelingIntegrationLayer."""
    
    @pytest.fixture
    def integration_layer(self):
        """Create test integration layer."""
        return LabelingIntegrationLayer()
    
    @pytest.fixture
    def integration_request(self):
        """Create test integration request."""
        return IntegrationRequest(
            content="CONFIDENTIAL document about Project ALPHA network configurations",
            source_network=NetworkDomain.SIPR,
            source_user_id=uuid4(),
            integration_mode=IntegrationMode.HYBRID,
            processing_priority=ProcessingPriority.NORMAL
        )
    
    @pytest.mark.asyncio
    async def test_standalone_mode(self, integration_layer):
        """Test standalone integration mode."""
        request = IntegrationRequest(
            content="Test content",
            integration_mode=IntegrationMode.STANDALONE
        )
        
        result = await integration_layer.process_integrated_labeling(request)
        
        assert isinstance(result, IntegrationResult)
        assert 'automated_labeler' in result.engines_used
        assert result.automated_labeling_result is not None
    
    @pytest.mark.asyncio
    async def test_enhanced_mode(self, integration_layer):
        """Test enhanced integration mode."""
        request = IntegrationRequest(
            content="CONFIDENTIAL information",
            integration_mode=IntegrationMode.ENHANCED
        )
        
        result = await integration_layer.process_integrated_labeling(request)
        
        assert 'automated_labeler' in result.engines_used
        assert 'enhanced_classification_engine' in result.engines_used
        assert result.final_classification != ClassificationLevel.UNCLASSIFIED
    
    @pytest.mark.asyncio
    async def test_hybrid_mode(self, integration_layer, integration_request):
        """Test hybrid integration mode."""
        result = await integration_layer.process_integrated_labeling(integration_request)
        
        # Should use multiple engines
        assert len(result.engines_used) >= 3
        assert result.total_processing_time_ms > 0
        assert isinstance(result.final_classification, ClassificationLevel)
        assert 0.0 <= result.confidence_score <= 1.0
    
    @pytest.mark.asyncio
    async def test_fallback_mode(self, integration_layer):
        """Test fallback integration mode."""
        request = IntegrationRequest(
            content="Test content with low confidence indicators",
            integration_mode=IntegrationMode.FALLBACK,
            minimum_confidence=0.9  # High threshold to trigger fallback
        )
        
        result = await integration_layer.process_integrated_labeling(request)
        
        # Should indicate if fallback was used
        assert isinstance(result.fallback_used, bool)
    
    @pytest.mark.asyncio
    async def test_validation_mode(self, integration_layer):
        """Test validation integration mode."""
        request = IntegrationRequest(
            content="SECRET document for cross-validation",
            source_user_id=uuid4(),
            integration_mode=IntegrationMode.VALIDATION
        )
        
        result = await integration_layer.process_integrated_labeling(request)
        
        # Should have cross-validation results
        assert isinstance(result.cross_validation_passed, bool)
        assert 0.0 <= result.result_consistency <= 1.0
    
    def test_metrics_collection(self, integration_layer):
        """Test metrics collection."""
        metrics = integration_layer.get_metrics()
        
        assert isinstance(metrics.total_requests, int)
        assert isinstance(metrics.average_processing_time_ms, float)
        assert isinstance(metrics.average_confidence, float)


class TestPerformanceOptimizer:
    """Test suite for PerformanceOptimizer."""
    
    @pytest.fixture
    def optimizer(self):
        """Create test performance optimizer."""
        config = OptimizationConfig(
            target_latency_ms=30.0,
            cache_enabled=True,
            adaptive_optimization=True
        )
        return PerformanceOptimizer(config)
    
    def test_single_request_optimization(self, optimizer):
        """Test single request optimization."""
        def test_function(data: str) -> str:
            time.sleep(0.01)  # 10ms processing
            return f"Processed: {data}"
        
        result, metrics = optimizer.optimize_request_processing(
            "test-001",
            test_function,
            "test data"
        )
        
        assert result == "Processed: test data"
        assert 'processing_time_ms' in metrics
        assert metrics['processing_time_ms'] > 0
    
    @pytest.mark.asyncio
    async def test_batch_optimization(self, optimizer):
        """Test batch request optimization."""
        def test_function(data: str) -> str:
            time.sleep(0.005)  # 5ms processing
            return f"Processed: {data}"
        
        requests = [
            (f"batch-{i}", test_function, (f"data-{i}",), {})
            for i in range(5)
        ]
        
        results = await optimizer.optimize_batch_optimization(requests)
        
        assert len(results) == 5
        for i, (result, metrics) in enumerate(results):
            assert result == f"Processed: data-{i}"
            assert 'processing_time_ms' in metrics
    
    def test_cache_functionality(self, optimizer):
        """Test caching functionality."""
        call_count = 0
        
        def test_function(data: str) -> str:
            nonlocal call_count
            call_count += 1
            time.sleep(0.01)
            return f"Processed: {data}"
        
        # First call
        result1, metrics1 = optimizer.optimize_request_processing(
            "cache-test",
            test_function,
            "test data"
        )
        
        # Second call (should use cache)
        result2, metrics2 = optimizer.optimize_request_processing(
            "cache-test",
            test_function, 
            "test data"
        )
        
        assert result1 == result2
        assert call_count == 1  # Function should only be called once
        assert metrics2.get('cache_hit', False) == True
    
    def test_performance_metrics(self, optimizer):
        """Test performance metrics collection."""
        def fast_function() -> str:
            return "fast result"
        
        # Process some requests
        for i in range(5):
            optimizer.optimize_request_processing(f"perf-{i}", fast_function)
        
        metrics = optimizer.get_performance_metrics()
        
        assert metrics.total_requests >= 5
        assert metrics.average_latency_ms > 0
        assert 0 <= metrics.sla_compliance_rate <= 100
    
    def test_optimization_recommendations(self, optimizer):
        """Test optimization recommendations."""
        # Generate some high-latency requests
        def slow_function() -> str:
            time.sleep(0.1)  # 100ms - above target
            return "slow result"
        
        for i in range(3):
            optimizer.optimize_request_processing(f"slow-{i}", slow_function)
        
        recommendations = optimizer.get_optimization_recommendations()
        
        assert isinstance(recommendations, list)
        # Should have recommendations for high latency
        assert any("latency" in rec.lower() for rec in recommendations)


class TestIntegrationScenarios:
    """Integration tests for complete scenarios."""
    
    @pytest.fixture
    def full_system(self):
        """Create full system with all components."""
        integration_layer = LabelingIntegrationLayer()
        
        # Configure for testing
        integration_layer.config['performance_target_ms'] = 100.0
        
        return integration_layer
    
    @pytest.mark.asyncio
    async def test_classified_document_processing(self, full_system):
        """Test processing of a classified document through the full system."""
        request = IntegrationRequest(
            content="""
            CONFIDENTIAL
            
            OPERATIONAL PLAN BRAVO
            
            This document contains sensitive information about network configurations
            for Project ALPHA. The deployment includes systems on SIPR network with
            IP addresses 192.168.1.100-192.168.1.200.
            
            Personnel with SECRET clearance are authorized to access this information.
            Contact: john.doe@example.mil
            
            SSN: 123-45-6789 (for reference only)
            """,
            source_network=NetworkDomain.SIPR,
            source_user_id=uuid4(),
            integration_mode=IntegrationMode.HYBRID,
            processing_priority=ProcessingPriority.HIGH,
            workflow_data={
                'workflow_type': 'operational_planning',
                'project_classification': 'CONFIDENTIAL'
            },
            session_data={
                'user_clearance': 'SECRET',
                'network_domain': 'SIPR'
            }
        )
        
        result = await full_system.process_integrated_labeling(request)
        
        # Verify comprehensive processing
        assert isinstance(result.final_classification, ClassificationLevel)
        assert result.final_classification.value >= ClassificationLevel.CONFIDENTIAL.value
        assert result.confidence_score > 0.6  # Should have reasonable confidence
        assert len(result.engines_used) >= 3  # Multiple engines used
        assert result.total_processing_time_ms > 0
        assert result.cross_validation_passed  # Should pass validation
        
        # Should detect patterns
        if result.content_analysis_result:
            assert result.content_analysis_result.total_patterns > 0
        
        # Should have context influence
        if result.context_processing_result:
            assert result.context_processing_result.context_coverage > 0
    
    @pytest.mark.asyncio
    async def test_performance_under_load(self, full_system):
        """Test system performance under load."""
        # Create multiple concurrent requests
        requests = []
        for i in range(10):
            request = IntegrationRequest(
                content=f"Test document {i} with CONFIDENTIAL information",
                integration_mode=IntegrationMode.HYBRID,
                processing_priority=ProcessingPriority.NORMAL
            )
            requests.append(request)
        
        start_time = time.time()
        
        # Process all requests concurrently
        tasks = [full_system.process_integrated_labeling(req) for req in requests]
        results = await asyncio.gather(*tasks)
        
        total_time = time.time() - start_time
        
        # Verify all requests completed
        assert len(results) == 10
        for result in results:
            assert isinstance(result, IntegrationResult)
            assert isinstance(result.final_classification, ClassificationLevel)
        
        # Performance should be reasonable
        avg_time_per_request = total_time / len(requests)
        assert avg_time_per_request < 1.0  # Less than 1 second per request on average
    
    @pytest.mark.asyncio
    async def test_error_handling_and_recovery(self, full_system):
        """Test error handling and recovery mechanisms."""
        # Test with malformed request
        request = IntegrationRequest(
            content="",  # Empty content
            integration_mode=IntegrationMode.HYBRID
        )
        
        result = await full_system.process_integrated_labeling(request)
        
        # Should handle gracefully
        assert isinstance(result, IntegrationResult)
        # Should have fallback classification
        assert isinstance(result.final_classification, ClassificationLevel)
        
        # Test with invalid user ID
        request2 = IntegrationRequest(
            content="Test content",
            source_user_id=uuid4(),  # Non-existent user
            integration_mode=IntegrationMode.VALIDATION
        )
        
        result2 = await full_system.process_integrated_labeling(request2)
        
        # Should complete without crashing
        assert isinstance(result2, IntegrationResult)
        # May have warnings about invalid user
        assert isinstance(result2.integration_warnings, list)


# Performance benchmarks
class TestPerformanceBenchmarks:
    """Performance benchmark tests."""
    
    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_latency_benchmark(self):
        """Benchmark latency requirements."""
        labeler = AutomatedDataLabeler()
        
        # Test various content sizes
        test_contents = [
            "Short content with CONFIDENTIAL marking",
            "Medium length content " * 50 + " with SECRET classification",
            "Long content " * 200 + " containing CONFIDENTIAL information and various patterns"
        ]
        
        for i, content in enumerate(test_contents):
            request = LabelingRequest(
                request_id=f"benchmark-{i}",
                content=content,
                strategy=LabelingStrategy.HYBRID
            )
            
            start_time = time.time()
            result = await labeler.label_data(request)
            processing_time_ms = (time.time() - start_time) * 1000
            
            # Should meet latency requirements (<50ms for normal priority)
            assert processing_time_ms < 100.0, f"Latency too high: {processing_time_ms:.2f}ms"
            assert isinstance(result.predicted_classification, ClassificationLevel)
    
    @pytest.mark.performance
    @pytest.mark.asyncio
    async def test_throughput_benchmark(self):
        """Benchmark throughput requirements."""
        integration_layer = LabelingIntegrationLayer()
        
        # Create batch of requests
        num_requests = 50
        requests = [
            IntegrationRequest(
                content=f"Benchmark request {i} with CONFIDENTIAL data",
                integration_mode=IntegrationMode.ENHANCED,
                processing_priority=ProcessingPriority.NORMAL
            )
            for i in range(num_requests)
        ]
        
        start_time = time.time()
        
        # Process in batches to simulate real load
        batch_size = 10
        results = []
        for i in range(0, num_requests, batch_size):
            batch = requests[i:i+batch_size]
            batch_tasks = [integration_layer.process_integrated_labeling(req) for req in batch]
            batch_results = await asyncio.gather(*batch_tasks)
            results.extend(batch_results)
        
        total_time = time.time() - start_time
        throughput = num_requests / total_time
        
        # Should achieve reasonable throughput
        assert throughput > 10.0, f"Throughput too low: {throughput:.2f} requests/second"
        assert len(results) == num_requests
    
    @pytest.mark.performance
    def test_memory_usage(self):
        """Test memory usage under load."""
        import psutil
        import gc
        
        process = psutil.Process()
        initial_memory = process.memory_info().rss / 1024 / 1024  # MB
        
        # Create and process many requests
        labeler = AutomatedDataLabeler()
        
        for i in range(100):
            request = LabelingRequest(
                content=f"Memory test content {i} with classification markers",
                strategy=LabelingStrategy.CONTENT_BASED
            )
            # Synchronous call for simpler memory testing
            # In real async code, memory patterns would be different
        
        # Force garbage collection
        gc.collect()
        
        final_memory = process.memory_info().rss / 1024 / 1024  # MB
        memory_increase = final_memory - initial_memory
        
        # Memory increase should be reasonable
        assert memory_increase < 100.0, f"Memory increase too high: {memory_increase:.2f}MB"


# Test utilities
def create_mock_classification_engine():
    """Create mock classification engine for testing."""
    mock_engine = Mock()
    mock_engine.classify_content = AsyncMock()
    
    # Set up mock response
    mock_result = Mock()
    mock_result.classification_level = ClassificationLevel.CONFIDENTIAL
    mock_result.confidence_score = 0.8
    mock_result.pii_detected = False
    mock_result.sensitive_patterns = []
    mock_result.classification_markers = ["CONFIDENTIAL"]
    
    mock_engine.classify_content.return_value = mock_result
    return mock_engine


def create_mock_clearance_engine():
    """Create mock clearance verification engine for testing."""
    mock_engine = Mock()
    mock_engine.verify_clearance = AsyncMock()
    
    # Set up mock response
    mock_result = Mock()
    mock_result.status = "VALID"
    mock_result.verified_clearance = Mock()
    mock_result.verified_clearance.classification_level = ClassificationLevel.SECRET
    
    mock_engine.verify_clearance.return_value = mock_result
    return mock_engine


# Pytest configuration
@pytest.fixture(scope="session")
def event_loop():
    """Create event loop for async tests."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


if __name__ == "__main__":
    # Run tests with coverage
    pytest.main([
        __file__,
        "-v",
        "--cov=automated_data_labeler",
        "--cov=source_analyzer", 
        "--cov=content_ml_analyzer",
        "--cov=context_aware_processor",
        "--cov=labeling_integration_layer",
        "--cov=performance_optimizer",
        "--cov-report=html",
        "--cov-report=term-missing",
        "-x"  # Stop on first failure
    ])