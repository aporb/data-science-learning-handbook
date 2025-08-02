"""
Automated Data Labeling Integration Layer
========================================

This module provides seamless integration between the automated data labeling
framework and existing multi-classification infrastructure, including the
enhanced classification engine and clearance verification engine.

Key Features:
- Unified interface for automated labeling and existing classification systems
- Seamless data flow between components with error handling
- Performance optimization and caching across integrated systems
- Consistent audit logging and monitoring
- Fallback mechanisms for system failures
- Configuration management for integrated components
- Real-time synchronization of classification results

Classification: UNCLASSIFIED//FOR OFFICIAL USE ONLY
Version: 1.0 - Initial Implementation
Author: Security Compliance Team
Date: 2025-07-29
"""

import asyncio
import json
import logging
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Tuple, Set, Union
from uuid import UUID, uuid4
from dataclasses import dataclass, field, asdict
from enum import Enum
import hashlib
from threading import Lock

# Import automated labeling components
from .automated_data_labeler import (
    AutomatedDataLabeler, LabelingRequest, LabelingResult, 
    LabelingStrategy, LabelingConfidence, DataOriginType
)
from .source_analyzer import (
    SourceAnalyzer, ComprehensiveSourceAnalysis,
    NetworkAnalysisResult, UserClearanceAnalysis, SystemClassificationAnalysis
)
from .content_ml_analyzer import (
    ContentMLAnalyzer, ContentMLAnalysisResult,
    AnalysisMethod, ConfidenceLevel
)
from .context_aware_processor import (
    ContextAwareProcessor, ContextProcessingResult,
    WorkflowContext, UserSessionContext, SurroundingDataContext
)

# Import existing infrastructure
from .enhanced_classification_engine import (
    EnhancedClassificationEngine, EnhancedClassificationRequest,
    ProcessingMode, OptimizationLevel, ProcessingMetrics
)
from .clearance_verification_engine import (
    ClearanceVerificationEngine, ClearanceVerificationRequest,
    ClearanceStatus, AccessDecision
)
from .classification_audit_logger import ClassificationAuditLogger
from .models.bell_lapadula import BellLaPadulaSecurityModel, SecurityLabel, ClassificationLevel
from ..rbac.models.data_classification import (
    NetworkDomain, DataSensitivity, ClassificationResult, ClassificationEvidence
)

logger = logging.getLogger(__name__)


class IntegrationMode(Enum):
    """Integration modes for automated labeling."""
    STANDALONE = "standalone"              # Use only automated labeling
    ENHANCED = "enhanced"                  # Integrate with existing engines
    FALLBACK = "fallback"                 # Use existing engines as fallback
    VALIDATION = "validation"             # Cross-validate results
    HYBRID = "hybrid"                     # Combine all approaches


class ProcessingPriority(Enum):
    """Processing priority levels."""
    CRITICAL = "critical"    # <10ms target
    HIGH = "high"           # <25ms target  
    NORMAL = "normal"       # <50ms target
    LOW = "low"             # <100ms target
    BATCH = "batch"         # No time constraint


@dataclass
class IntegrationRequest:
    """Request structure for integrated automated labeling."""
    request_id: str = field(default_factory=lambda: str(uuid4()))
    
    # Content information
    content: str = ""
    content_type: str = "text/plain"
    content_metadata: Dict[str, Any] = field(default_factory=dict)
    
    # Source information
    source_ip: Optional[str] = None
    source_domain: Optional[str] = None
    source_hostname: Optional[str] = None
    source_user_id: Optional[UUID] = None
    source_system: Optional[str] = None
    source_network: Optional[NetworkDomain] = None
    origin_type: DataOriginType = DataOriginType.SYSTEM_GENERATED
    
    # Context information
    workflow_data: Optional[Dict[str, Any]] = None
    session_data: Optional[Dict[str, Any]] = None
    surrounding_data: Optional[List[Dict[str, Any]]] = None
    temporal_data: Optional[Dict[str, Any]] = None
    environmental_data: Optional[Dict[str, Any]] = None
    
    # Processing preferences
    integration_mode: IntegrationMode = IntegrationMode.HYBRID
    processing_priority: ProcessingPriority = ProcessingPriority.NORMAL
    labeling_strategy: LabelingStrategy = LabelingStrategy.HYBRID
    use_existing_engines: bool = True
    enable_cross_validation: bool = True
    
    # Quality requirements
    minimum_confidence: float = 0.7
    require_manual_review: bool = False
    
    # Timestamps
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    deadline: Optional[datetime] = None


@dataclass
class IntegrationResult:
    """Result structure for integrated automated labeling."""
    request_id: str
    
    # Primary classification results
    final_classification: ClassificationLevel = ClassificationLevel.UNCLASSIFIED
    confidence_score: float = 0.0
    confidence_level: LabelingConfidence = LabelingConfidence.LOW
    
    # Component results
    automated_labeling_result: Optional[LabelingResult] = None
    enhanced_classification_result: Optional[Any] = None  # ClassificationResult from existing engine
    clearance_verification_result: Optional[Any] = None  # ClearanceVerificationResult
    source_analysis_result: Optional[ComprehensiveSourceAnalysis] = None
    content_analysis_result: Optional[ContentMLAnalysisResult] = None
    context_processing_result: Optional[ContextProcessingResult] = None
    
    # Integration analysis
    result_consistency: float = 0.0
    cross_validation_passed: bool = True
    integration_warnings: List[str] = field(default_factory=list)
    fallback_used: bool = False
    
    # Evidence and reasoning
    classification_evidence: List[ClassificationEvidence] = field(default_factory=list)
    reasoning: str = ""
    risk_assessment: Dict[str, Any] = field(default_factory=dict)
    
    # Performance metrics
    total_processing_time_ms: float = 0.0
    component_processing_times: Dict[str, float] = field(default_factory=dict)
    engines_used: List[str] = field(default_factory=list)
    
    # Quality metrics
    accuracy_estimate: float = 0.0
    reliability_score: float = 0.0
    completeness_score: float = 0.0
    
    # Compliance information
    dod_compliance_status: str = "compliant"
    network_compatibility: List[NetworkDomain] = field(default_factory=list)
    audit_trail: List[Dict[str, Any]] = field(default_factory=list)
    
    # Timestamps
    processed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    processing_completed_at: Optional[datetime] = None


@dataclass
class IntegrationMetrics:
    """Metrics for integration layer performance."""
    total_requests: int = 0
    successful_integrations: int = 0
    failed_integrations: int = 0
    
    # Processing time metrics
    average_processing_time_ms: float = 0.0
    p95_processing_time_ms: float = 0.0
    p99_processing_time_ms: float = 0.0
    
    # Component usage
    automated_labeler_usage: int = 0
    enhanced_engine_usage: int = 0
    clearance_engine_usage: int = 0
    fallback_usage: int = 0
    
    # Quality metrics
    average_confidence: float = 0.0
    cross_validation_success_rate: float = 0.0
    consistency_score: float = 0.0
    
    # Performance violations
    sla_violations: int = 0
    timeout_errors: int = 0
    integration_errors: int = 0
    
    # Last reset
    metrics_reset_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class ResultValidator:
    """Validates and cross-checks results from multiple classification engines."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize result validator."""
        self.config = config or {}
        
        # Validation thresholds
        self._consistency_threshold = self.config.get('consistency_threshold', 0.8)
        self._confidence_threshold = self.config.get('confidence_threshold', 0.7)
        self._max_classification_difference = self.config.get('max_classification_difference', 2)
        
        logger.info("ResultValidator initialized")
    
    def validate_integration_result(
        self,
        automated_result: Optional[LabelingResult],
        enhanced_result: Optional[Any],
        clearance_result: Optional[Any]
    ) -> Tuple[bool, List[str], float]:
        """
        Validate integration results for consistency and accuracy.
        
        Returns:
            Tuple of (is_valid, warnings, consistency_score)
        """
        warnings = []
        consistency_scores = []
        
        # Collect classifications from different sources
        classifications = []
        confidences = []
        
        if automated_result:
            classifications.append(automated_result.predicted_classification)
            confidences.append(automated_result.confidence_score)
        
        if enhanced_result and hasattr(enhanced_result, 'classification_level'):
            classifications.append(enhanced_result.classification_level)
            if hasattr(enhanced_result, 'confidence_score'):
                confidences.append(enhanced_result.confidence_score)
        
        if clearance_result and hasattr(clearance_result, 'verified_clearance'):
            if clearance_result.verified_clearance:
                classifications.append(clearance_result.verified_clearance.classification_level)
        
        # Check classification consistency
        if len(classifications) > 1:
            consistency_score = self._calculate_classification_consistency(classifications)
            consistency_scores.append(consistency_score)
            
            if consistency_score < self._consistency_threshold:
                warnings.append(f"Low classification consistency: {consistency_score:.2f}")
        
        # Check confidence levels
        if confidences:
            avg_confidence = sum(confidences) / len(confidences)
            if avg_confidence < self._confidence_threshold:
                warnings.append(f"Low average confidence: {avg_confidence:.2f}")
        
        # Check for extreme classification differences
        if classifications:
            min_classification = min(classifications, key=lambda x: x.value)
            max_classification = max(classifications, key=lambda x: x.value)
            
            if max_classification.value - min_classification.value > self._max_classification_difference:
                warnings.append(f"Large classification difference: {min_classification.value} to {max_classification.value}")
        
        # Calculate overall consistency
        overall_consistency = sum(consistency_scores) / len(consistency_scores) if consistency_scores else 1.0
        
        # Determine if result is valid
        is_valid = len(warnings) == 0 or all('Low' not in warning for warning in warnings)
        
        return is_valid, warnings, overall_consistency
    
    def _calculate_classification_consistency(self, classifications: List[ClassificationLevel]) -> float:
        """Calculate consistency score for a list of classifications."""
        if not classifications:
            return 0.0
        
        # Count occurrences of each classification
        classification_counts = {}
        for classification in classifications:
            classification_counts[classification] = classification_counts.get(classification, 0) + 1
        
        # Calculate consistency as ratio of most common classification
        most_common_count = max(classification_counts.values())
        return most_common_count / len(classifications)


class PerformanceOptimizer:
    """Optimizes performance across integrated classification components."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize performance optimizer."""
        self.config = config or {}
        
        # Performance targets by priority
        self._performance_targets = {
            ProcessingPriority.CRITICAL: 10.0,   # 10ms
            ProcessingPriority.HIGH: 25.0,       # 25ms
            ProcessingPriority.NORMAL: 50.0,     # 50ms
            ProcessingPriority.LOW: 100.0,       # 100ms
            ProcessingPriority.BATCH: 1000.0     # 1s
        }
        
        # Optimization strategies
        self._optimization_strategies = self.config.get('optimization_strategies', {
            'enable_caching': True,
            'enable_parallel_processing': True,
            'enable_result_streaming': True,
            'enable_early_termination': True
        })
        
        logger.info("PerformanceOptimizer initialized")
    
    def optimize_processing_strategy(
        self,
        request: IntegrationRequest
    ) -> Dict[str, Any]:
        """Determine optimal processing strategy based on request requirements."""
        strategy = {
            'parallel_components': [],
            'sequential_components': [],
            'optimization_level': OptimizationLevel.STANDARD,
            'enable_caching': True,
            'timeout_ms': self._performance_targets.get(request.processing_priority, 50.0)
        }
        
        # Determine optimization level based on priority
        if request.processing_priority == ProcessingPriority.CRITICAL:
            strategy['optimization_level'] = OptimizationLevel.ULTRA_FAST
            strategy['parallel_components'] = ['source_analysis', 'content_analysis']
            strategy['sequential_components'] = ['context_processing']
        elif request.processing_priority == ProcessingPriority.HIGH:
            strategy['optimization_level'] = OptimizationLevel.HIGH_PERFORMANCE
            strategy['parallel_components'] = ['source_analysis', 'content_analysis', 'context_processing']
        else:
            strategy['optimization_level'] = OptimizationLevel.STANDARD
            strategy['parallel_components'] = ['source_analysis', 'content_analysis', 'context_processing']
        
        # Adjust based on integration mode
        if request.integration_mode == IntegrationMode.STANDALONE:
            strategy['parallel_components'].append('automated_labeling')
        elif request.integration_mode == IntegrationMode.HYBRID:
            strategy['parallel_components'].extend(['automated_labeling', 'enhanced_classification'])
        
        return strategy
    
    def should_use_cache(self, request: IntegrationRequest) -> bool:
        """Determine if caching should be used for this request."""
        # Use cache for non-critical requests
        return request.processing_priority != ProcessingPriority.CRITICAL
    
    def calculate_timeout(self, request: IntegrationRequest) -> float:
        """Calculate appropriate timeout for request processing."""
        base_timeout = self._performance_targets.get(request.processing_priority, 50.0)
        
        # Adjust timeout based on integration mode
        if request.integration_mode == IntegrationMode.HYBRID:
            base_timeout *= 1.5  # More time for multiple engines
        elif request.integration_mode == IntegrationMode.VALIDATION:
            base_timeout *= 2.0  # Time for cross-validation
        
        return base_timeout


class LabelingIntegrationLayer:
    """
    Comprehensive integration layer that coordinates automated data labeling
    with existing multi-classification infrastructure.
    """
    
    def __init__(
        self,
        enhanced_classification_engine: Optional[EnhancedClassificationEngine] = None,
        clearance_verification_engine: Optional[ClearanceVerificationEngine] = None,
        audit_logger: Optional[ClassificationAuditLogger] = None,
        config: Optional[Dict[str, Any]] = None
    ):
        """Initialize integration layer."""
        self.config = config or {}
        
        # Initialize existing engines
        self.enhanced_engine = enhanced_classification_engine or EnhancedClassificationEngine()
        self.clearance_engine = clearance_verification_engine or ClearanceVerificationEngine()
        self.audit_logger = audit_logger or ClassificationAuditLogger()
        
        # Initialize automated labeling components
        self.automated_labeler = AutomatedDataLabeler(
            classification_engine=self.enhanced_engine,
            clearance_engine=self.clearance_engine,
            audit_logger=self.audit_logger,
            config=self.config.get('automated_labeler_config')
        )
        
        self.source_analyzer = SourceAnalyzer(
            config=self.config.get('source_analyzer_config')
        )
        
        self.content_analyzer = ContentMLAnalyzer(
            audit_logger=self.audit_logger,
            config=self.config.get('content_analyzer_config')
        )
        
        self.context_processor = ContextAwareProcessor(
            audit_logger=self.audit_logger,
            config=self.config.get('context_processor_config')
        )
        
        # Initialize integration components
        self.result_validator = ResultValidator(self.config.get('validator_config'))
        self.performance_optimizer = PerformanceOptimizer(self.config.get('optimizer_config'))
        
        # Performance and caching
        self.metrics = IntegrationMetrics()
        self._integration_cache: Dict[str, IntegrationResult] = {}
        self._cache_lock = Lock()
        self._max_cache_size = self.config.get('max_cache_size', 1000)
        self._cache_ttl_seconds = self.config.get('cache_ttl_seconds', 300)  # 5 minutes
        
        # Thread pool for parallel processing
        self._thread_pool = ThreadPoolExecutor(
            max_workers=self.config.get('max_workers', 8),
            thread_name_prefix='integration'
        )
        
        logger.info("LabelingIntegrationLayer initialized")
    
    async def process_integrated_labeling(
        self, 
        request: IntegrationRequest
    ) -> IntegrationResult:
        """
        Process integrated automated labeling request.
        
        Args:
            request: IntegrationRequest with content and context information
            
        Returns:
            IntegrationResult with comprehensive classification analysis
        """
        start_time = time.time()
        
        # Create result object
        result = IntegrationResult(request_id=request.request_id)
        
        try:
            # Log request
            await self._log_integration_request(request)
            
            # Check cache if enabled
            if self.performance_optimizer.should_use_cache(request):
                cached_result = self._get_cached_result(request)
                if cached_result:
                    logger.debug(f"Cache hit for integration request {request.request_id}")
                    return cached_result
            
            # Optimize processing strategy
            processing_strategy = self.performance_optimizer.optimize_processing_strategy(request)
            
            # Process based on integration mode
            if request.integration_mode == IntegrationMode.STANDALONE:
                result = await self._process_standalone_mode(request, result, processing_strategy)
            elif request.integration_mode == IntegrationMode.ENHANCED:
                result = await self._process_enhanced_mode(request, result, processing_strategy)
            elif request.integration_mode == IntegrationMode.FALLBACK:
                result = await self._process_fallback_mode(request, result, processing_strategy)
            elif request.integration_mode == IntegrationMode.VALIDATION:
                result = await self._process_validation_mode(request, result, processing_strategy)
            elif request.integration_mode == IntegrationMode.HYBRID:
                result = await self._process_hybrid_mode(request, result, processing_strategy)
            else:
                raise ValueError(f"Unknown integration mode: {request.integration_mode}")
            
            # Validate results
            is_valid, warnings, consistency_score = self.result_validator.validate_integration_result(
                result.automated_labeling_result,
                result.enhanced_classification_result,
                result.clearance_verification_result
            )
            
            result.cross_validation_passed = is_valid
            result.integration_warnings = warnings
            result.result_consistency = consistency_score
            
            # Calculate final metrics
            result.total_processing_time_ms = (time.time() - start_time) * 1000
            result.processing_completed_at = datetime.now(timezone.utc)
            
            # Cache result if appropriate
            if self.performance_optimizer.should_use_cache(request):
                self._cache_result(request, result)
            
            # Update metrics
            self._update_metrics(result, success=True)
            
            # Log result
            await self._log_integration_result(request, result)
            
            logger.debug(f"Integrated labeling complete for {request.request_id}: "
                        f"{result.final_classification} (confidence: {result.confidence_score:.2f}) "
                        f"in {result.total_processing_time_ms:.2f}ms")
            
        except Exception as e:
            processing_time_ms = (time.time() - start_time) * 1000
            logger.error(f"Integrated labeling failed for {request.request_id}: {e}")
            
            # Create error result
            result.final_classification = ClassificationLevel.UNCLASSIFIED
            result.confidence_score = 0.0
            result.confidence_level = LabelingConfidence.UNCERTAIN
            result.reasoning = f"Integration processing failed: {str(e)}"
            result.total_processing_time_ms = processing_time_ms
            result.cross_validation_passed = False
            result.integration_warnings.append(f"Processing error: {str(e)}")
            
            # Update metrics
            self._update_metrics(result, success=False)
            
            # Log error
            await self._log_integration_error(request, e)
        
        return result
    
    async def _process_standalone_mode(
        self,
        request: IntegrationRequest,
        result: IntegrationResult,
        strategy: Dict[str, Any]
    ) -> IntegrationResult:
        """Process request using only automated labeling components."""
        result.engines_used.append('automated_labeler')
        
        # Create labeling request
        labeling_request = LabelingRequest(
            request_id=request.request_id,
            content=request.content,
            content_type=request.content_type,
            content_metadata=request.content_metadata,
            source_network=request.source_network,
            source_user_id=request.source_user_id,
            source_system=request.source_system,
            origin_type=request.origin_type,
            workflow_context=request.workflow_data or {},
            surrounding_data=request.surrounding_data or [],
            user_session_context=request.session_data or {},
            strategy=request.labeling_strategy
        )
        
        # Process with automated labeler
        component_start_time = time.time()
        result.automated_labeling_result = await self.automated_labeler.label_data(labeling_request)
        result.component_processing_times['automated_labeler'] = (time.time() - component_start_time) * 1000
        
        # Use automated labeling result as final result
        result.final_classification = result.automated_labeling_result.predicted_classification
        result.confidence_score = result.automated_labeling_result.confidence_score
        result.confidence_level = result.automated_labeling_result.confidence_level
        result.reasoning = result.automated_labeling_result.reasoning
        
        return result
    
    async def _process_enhanced_mode(
        self,
        request: IntegrationRequest,
        result: IntegrationResult,
        strategy: Dict[str, Any]
    ) -> IntegrationResult:
        """Process request with integration of existing enhanced classification engine."""
        result.engines_used.extend(['automated_labeler', 'enhanced_classification_engine'])
        
        # Process components in parallel
        tasks = []
        
        # Automated labeling
        labeling_request = LabelingRequest(
            request_id=request.request_id,
            content=request.content,
            content_type=request.content_type,
            source_user_id=request.source_user_id,
            strategy=request.labeling_strategy
        )
        tasks.append(self._process_automated_labeling(labeling_request))
        
        # Enhanced classification
        if request.use_existing_engines:
            enhanced_request = EnhancedClassificationRequest(
                request_id=request.request_id,
                content=request.content,
                content_type=request.content_type,
                user_id=request.source_user_id
            )
            tasks.append(self._process_enhanced_classification(enhanced_request))
        
        # Execute tasks
        component_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results
        for i, component_result in enumerate(component_results):
            if isinstance(component_result, Exception):
                logger.error(f"Component {i} failed: {component_result}")
                result.integration_warnings.append(f"Component {i} failed: {str(component_result)}")
            else:
                if i == 0:  # Automated labeling result
                    result.automated_labeling_result = component_result
                elif i == 1:  # Enhanced classification result
                    result.enhanced_classification_result = component_result
        
        # Combine results
        result = self._combine_classification_results(result)
        
        return result
    
    async def _process_fallback_mode(
        self,
        request: IntegrationRequest,
        result: IntegrationResult,
        strategy: Dict[str, Any]
    ) -> IntegrationResult:
        """Process request with fallback to existing engines if automated labeling fails."""
        result.engines_used.append('automated_labeler')
        
        try:
            # Try automated labeling first
            labeling_request = LabelingRequest(
                request_id=request.request_id,
                content=request.content,
                content_type=request.content_type,
                source_user_id=request.source_user_id,
                strategy=request.labeling_strategy
            )
            
            component_start_time = time.time()
            result.automated_labeling_result = await self.automated_labeler.label_data(labeling_request)
            result.component_processing_times['automated_labeler'] = (time.time() - component_start_time) * 1000
            
            # Check if result meets quality requirements
            if (result.automated_labeling_result.confidence_score >= request.minimum_confidence and
                result.automated_labeling_result.confidence_level != LabelingConfidence.UNCERTAIN):
                
                # Use automated result
                result.final_classification = result.automated_labeling_result.predicted_classification
                result.confidence_score = result.automated_labeling_result.confidence_score
                result.confidence_level = result.automated_labeling_result.confidence_level
                result.reasoning = result.automated_labeling_result.reasoning
            else:
                # Fallback to existing engines
                result.fallback_used = True
                result.engines_used.append('enhanced_classification_engine')
                result.integration_warnings.append("Fallback to existing engines due to low confidence")
                
                enhanced_request = EnhancedClassificationRequest(
                    request_id=request.request_id,
                    content=request.content,
                    content_type=request.content_type,
                    user_id=request.source_user_id
                )
                
                component_start_time = time.time()
                result.enhanced_classification_result = await self.enhanced_engine.classify_content(enhanced_request)
                result.component_processing_times['enhanced_classification_engine'] = (time.time() - component_start_time) * 1000
                
                # Use enhanced engine result
                if hasattr(result.enhanced_classification_result, 'classification_level'):
                    result.final_classification = result.enhanced_classification_result.classification_level
                    result.confidence_score = getattr(result.enhanced_classification_result, 'confidence_score', 0.5)
                    result.reasoning = "Fallback classification using enhanced engine"
        
        except Exception as e:
            logger.error(f"Automated labeling failed, using fallback: {e}")
            result.fallback_used = True
            result.engines_used.append('enhanced_classification_engine')
            result.integration_warnings.append(f"Fallback due to error: {str(e)}")
            
            # Fallback processing
            enhanced_request = EnhancedClassificationRequest(
                request_id=request.request_id,
                content=request.content,
                content_type=request.content_type,
                user_id=request.source_user_id
            )
            
            result.enhanced_classification_result = await self.enhanced_engine.classify_content(enhanced_request)
            
            if hasattr(result.enhanced_classification_result, 'classification_level'):
                result.final_classification = result.enhanced_classification_result.classification_level
                result.confidence_score = getattr(result.enhanced_classification_result, 'confidence_score', 0.5)
                result.reasoning = "Fallback classification due to automated labeling failure"
        
        return result
    
    async def _process_validation_mode(
        self,
        request: IntegrationRequest,
        result: IntegrationResult,
        strategy: Dict[str, Any]
    ) -> IntegrationResult:
        """Process request with cross-validation between automated labeling and existing engines."""
        result.engines_used.extend(['automated_labeler', 'enhanced_classification_engine'])
        
        # Process both engines in parallel
        tasks = []
        
        # Automated labeling
        labeling_request = LabelingRequest(
            request_id=request.request_id,
            content=request.content,
            content_type=request.content_type,
            source_user_id=request.source_user_id,
            strategy=request.labeling_strategy
        )
        tasks.append(self._process_automated_labeling(labeling_request))
        
        # Enhanced classification
        enhanced_request = EnhancedClassificationRequest(
            request_id=request.request_id,
            content=request.content,
            content_type=request.content_type,
            user_id=request.source_user_id
        )
        tasks.append(self._process_enhanced_classification(enhanced_request))
        
        # Clearance verification if user provided
        if request.source_user_id:
            clearance_request = ClearanceVerificationRequest(
                user_id=request.source_user_id,
                requested_classification=ClassificationLevel.TOP_SECRET
            )
            tasks.append(self._process_clearance_verification(clearance_request))
            result.engines_used.append('clearance_verification_engine')
        
        # Execute all tasks
        component_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results
        for i, component_result in enumerate(component_results):
            if isinstance(component_result, Exception):
                logger.error(f"Validation component {i} failed: {component_result}")
                result.integration_warnings.append(f"Validation component {i} failed: {str(component_result)}")
            else:
                if i == 0:  # Automated labeling result
                    result.automated_labeling_result = component_result
                elif i == 1:  # Enhanced classification result
                    result.enhanced_classification_result = component_result
                elif i == 2:  # Clearance verification result
                    result.clearance_verification_result = component_result
        
        # Cross-validate results
        result = self._cross_validate_results(result)
        
        return result
    
    async def _process_hybrid_mode(
        self,
        request: IntegrationRequest,
        result: IntegrationResult,
        strategy: Dict[str, Any]
    ) -> IntegrationResult:
        """Process request using comprehensive hybrid approach with all components."""
        result.engines_used.extend([
            'automated_labeler', 'enhanced_classification_engine', 
            'source_analyzer', 'content_analyzer', 'context_processor'
        ])
        
        # Execute all components in parallel where possible
        tasks = []
        
        # Core classification tasks
        labeling_request = LabelingRequest(
            request_id=request.request_id,
            content=request.content,
            content_type=request.content_type,
            source_user_id=request.source_user_id,
            strategy=request.labeling_strategy
        )
        tasks.append(self._process_automated_labeling(labeling_request))
        
        enhanced_request = EnhancedClassificationRequest(
            request_id=request.request_id,
            content=request.content,
            content_type=request.content_type,
            user_id=request.source_user_id
        )
        tasks.append(self._process_enhanced_classification(enhanced_request))
        
        # Source analysis
        tasks.append(self._process_source_analysis(request))
        
        # Content analysis
        tasks.append(self._process_content_analysis(request))
        
        # Context processing
        tasks.append(self._process_context_analysis(request))
        
        # Clearance verification if user provided
        if request.source_user_id:
            clearance_request = ClearanceVerificationRequest(
                user_id=request.source_user_id,
                requested_classification=ClassificationLevel.TOP_SECRET
            )
            tasks.append(self._process_clearance_verification(clearance_request))
            result.engines_used.append('clearance_verification_engine')
        
        # Execute all tasks
        component_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results
        task_index = 0
        for component_result in component_results:
            if isinstance(component_result, Exception):
                logger.error(f"Hybrid component {task_index} failed: {component_result}")
                result.integration_warnings.append(f"Component {task_index} failed: {str(component_result)}")
            else:
                if task_index == 0:  # Automated labeling
                    result.automated_labeling_result = component_result
                elif task_index == 1:  # Enhanced classification
                    result.enhanced_classification_result = component_result
                elif task_index == 2:  # Source analysis
                    result.source_analysis_result = component_result
                elif task_index == 3:  # Content analysis
                    result.content_analysis_result = component_result
                elif task_index == 4:  # Context processing
                    result.context_processing_result = component_result
                elif task_index == 5:  # Clearance verification
                    result.clearance_verification_result = component_result
            
            task_index += 1
        
        # Combine all results using sophisticated fusion
        result = self._fuse_hybrid_results(result)
        
        return result
    
    async def _process_automated_labeling(self, request: LabelingRequest) -> LabelingResult:
        """Process automated labeling request."""
        start_time = time.time()
        result = await self.automated_labeler.label_data(request)
        processing_time = (time.time() - start_time) * 1000
        
        # Track metrics
        self.metrics.automated_labeler_usage += 1
        
        return result
    
    async def _process_enhanced_classification(self, request: EnhancedClassificationRequest) -> Any:
        """Process enhanced classification request."""
        start_time = time.time()
        result = await self.enhanced_engine.classify_content(request)
        processing_time = (time.time() - start_time) * 1000
        
        # Track metrics
        self.metrics.enhanced_engine_usage += 1
        
        return result
    
    async def _process_clearance_verification(self, request: ClearanceVerificationRequest) -> Any:
        """Process clearance verification request."""
        start_time = time.time()
        result = await self.clearance_engine.verify_clearance(request)
        processing_time = (time.time() - start_time) * 1000
        
        # Track metrics
        self.metrics.clearance_engine_usage += 1
        
        return result
    
    async def _process_source_analysis(self, request: IntegrationRequest) -> ComprehensiveSourceAnalysis:
        """Process source analysis."""
        start_time = time.time()
        result = await self.source_analyzer.analyze_comprehensive_source(
            request_id=request.request_id,
            source_ip=request.source_ip,
            source_domain=request.source_domain,
            source_hostname=request.source_hostname,
            user_id=request.source_user_id,
            system_id=request.source_system
        )
        processing_time = (time.time() - start_time) * 1000
        
        return result
    
    async def _process_content_analysis(self, request: IntegrationRequest) -> ContentMLAnalysisResult:
        """Process content analysis."""
        start_time = time.time()
        result = await self.content_analyzer.analyze_content(
            request_id=request.request_id,
            content=request.content
        )
        processing_time = (time.time() - start_time) * 1000
        
        return result
    
    async def _process_context_analysis(self, request: IntegrationRequest) -> ContextProcessingResult:
        """Process context analysis."""
        start_time = time.time()
        result = await self.context_processor.process_context(
            request_id=request.request_id,
            workflow_data=request.workflow_data,
            session_data=request.session_data,
            surrounding_data=request.surrounding_data,
            temporal_data=request.temporal_data,
            environmental_data=request.environmental_data
        )
        processing_time = (time.time() - start_time) * 1000
        
        return result
    
    def _combine_classification_results(self, result: IntegrationResult) -> IntegrationResult:
        """Combine results from automated labeling and enhanced classification."""
        classifications = []
        confidences = []
        
        # Collect results
        if result.automated_labeling_result:
            classifications.append(result.automated_labeling_result.predicted_classification)
            confidences.append(result.automated_labeling_result.confidence_score)
        
        if result.enhanced_classification_result and hasattr(result.enhanced_classification_result, 'classification_level'):
            classifications.append(result.enhanced_classification_result.classification_level)
            if hasattr(result.enhanced_classification_result, 'confidence_score'):
                confidences.append(result.enhanced_classification_result.confidence_score)
        
        # Use highest classification (Bell-LaPadula principle)
        if classifications:
            result.final_classification = max(classifications, key=lambda x: x.value)
        
        # Average confidence
        if confidences:
            result.confidence_score = sum(confidences) / len(confidences)
        
        # Set confidence level
        if result.confidence_score >= 0.9:
            result.confidence_level = LabelingConfidence.HIGH
        elif result.confidence_score >= 0.7:
            result.confidence_level = LabelingConfidence.MEDIUM
        else:
            result.confidence_level = LabelingConfidence.LOW
        
        result.reasoning = "Combined classification from automated labeling and enhanced classification"
        
        return result
    
    def _cross_validate_results(self, result: IntegrationResult) -> IntegrationResult:
        """Cross-validate results from multiple engines."""
        # Similar to _combine_classification_results but with validation logic
        return self._combine_classification_results(result)
    
    def _fuse_hybrid_results(self, result: IntegrationResult) -> IntegrationResult:
        """Fuse results from all hybrid components using sophisticated algorithms."""
        classification_scores = {}
        total_weight = 0.0
        
        # Automated labeling contribution (weight: 0.3)
        if result.automated_labeling_result:
            classification = result.automated_labeling_result.predicted_classification
            confidence = result.automated_labeling_result.confidence_score
            weight = 0.3 * confidence
            
            if classification not in classification_scores:
                classification_scores[classification] = 0.0
            classification_scores[classification] += weight
            total_weight += weight
        
        # Enhanced classification contribution (weight: 0.3)
        if result.enhanced_classification_result and hasattr(result.enhanced_classification_result, 'classification_level'):
            classification = result.enhanced_classification_result.classification_level
            confidence = getattr(result.enhanced_classification_result, 'confidence_score', 0.7)
            weight = 0.3 * confidence
            
            if classification not in classification_scores:
                classification_scores[classification] = 0.0
            classification_scores[classification] += weight
            total_weight += weight
        
        # Source analysis contribution (weight: 0.2)
        if result.source_analysis_result:
            classification = result.source_analysis_result.final_classification
            confidence = result.source_analysis_result.confidence_score
            weight = 0.2 * confidence
            
            if classification not in classification_scores:
                classification_scores[classification] = 0.0
            classification_scores[classification] += weight
            total_weight += weight
        
        # Content analysis contribution (weight: 0.15)
        if result.content_analysis_result:
            classification = result.content_analysis_result.predicted_classification
            confidence = result.content_analysis_result.confidence_score
            weight = 0.15 * confidence
            
            if classification not in classification_scores:
                classification_scores[classification] = 0.0
            classification_scores[classification] += weight
            total_weight += weight
        
        # Context processing contribution (weight: 0.05)
        if result.context_processing_result:
            classification = result.context_processing_result.context_influenced_classification
            confidence = result.context_processing_result.context_confidence_score
            weight = 0.05 * confidence
            
            if classification not in classification_scores:
                classification_scores[classification] = 0.0
            classification_scores[classification] += weight
            total_weight += weight
        
        # Determine final classification
        if classification_scores:
            result.final_classification = max(
                classification_scores.keys(),
                key=lambda x: classification_scores[x]
            )
            
            # Calculate normalized confidence
            max_score = max(classification_scores.values())
            result.confidence_score = max_score / total_weight if total_weight > 0 else 0.0
        else:
            result.final_classification = ClassificationLevel.UNCLASSIFIED
            result.confidence_score = 0.0
        
        # Set confidence level
        if result.confidence_score >= 0.9:
            result.confidence_level = LabelingConfidence.HIGH
        elif result.confidence_score >= 0.7:
            result.confidence_level = LabelingConfidence.MEDIUM
        elif result.confidence_score >= 0.5:
            result.confidence_level = LabelingConfidence.LOW
        else:
            result.confidence_level = LabelingConfidence.UNCERTAIN
        
        result.reasoning = "Hybrid fusion of automated labeling, enhanced classification, source analysis, content analysis, and context processing"
        
        return result
    
    def _get_cached_result(self, request: IntegrationRequest) -> Optional[IntegrationResult]:
        """Get cached integration result if available and valid."""
        cache_key = self._generate_cache_key(request)
        
        with self._cache_lock:
            if cache_key in self._integration_cache:
                cached_result = self._integration_cache[cache_key]
                
                # Check if cache entry is still valid
                age = datetime.now(timezone.utc) - cached_result.processed_at
                if age.total_seconds() < self._cache_ttl_seconds:
                    return cached_result
                else:
                    # Remove expired cache entry
                    del self._integration_cache[cache_key]
        
        return None
    
    def _cache_result(self, request: IntegrationRequest, result: IntegrationResult):
        """Cache integration result."""
        cache_key = self._generate_cache_key(request)
        
        with self._cache_lock:
            # Add to cache
            self._integration_cache[cache_key] = result
            
            # Maintain cache size limit
            if len(self._integration_cache) > self._max_cache_size:
                # Remove oldest entries
                sorted_items = sorted(
                    self._integration_cache.items(),
                    key=lambda x: x[1].processed_at
                )
                
                for key, _ in sorted_items[:len(self._integration_cache) - self._max_cache_size]:
                    del self._integration_cache[key]
    
    def _generate_cache_key(self, request: IntegrationRequest) -> str:
        """Generate cache key for integration request."""
        cache_data = {
            'content': request.content,
            'content_type': request.content_type,
            'source_network': request.source_network.value if request.source_network else None,
            'source_user_id': str(request.source_user_id) if request.source_user_id else None,
            'source_system': request.source_system,
            'integration_mode': request.integration_mode.value,
            'labeling_strategy': request.labeling_strategy.value
        }
        
        cache_string = json.dumps(cache_data, sort_keys=True)
        return hashlib.sha256(cache_string.encode()).hexdigest()
    
    def _update_metrics(self, result: IntegrationResult, success: bool):
        """Update integration metrics."""
        self.metrics.total_requests += 1
        
        if success:
            self.metrics.successful_integrations += 1
            self.metrics.average_confidence = (
                (self.metrics.average_confidence * (self.metrics.successful_integrations - 1) + result.confidence_score) /
                self.metrics.successful_integrations
            )
            
            if result.cross_validation_passed:
                self.metrics.cross_validation_success_rate = (
                    (self.metrics.cross_validation_success_rate * (self.metrics.successful_integrations - 1) + 1.0) /
                    self.metrics.successful_integrations
                )
        else:
            self.metrics.failed_integrations += 1
            self.metrics.integration_errors += 1
        
        # Update processing time metrics
        if result.total_processing_time_ms > 0:
            total_time = self.metrics.average_processing_time_ms * (self.metrics.total_requests - 1)
            self.metrics.average_processing_time_ms = (total_time + result.total_processing_time_ms) / self.metrics.total_requests
        
        # Track SLA violations based on processing priority
        # This would need the original request to determine the target time
        # For now, use a default threshold
        if result.total_processing_time_ms > 50.0:  # Default SLA
            self.metrics.sla_violations += 1
    
    async def _log_integration_request(self, request: IntegrationRequest):
        """Log integration request for audit purposes."""
        await self.audit_logger.log_classification_event({
            'event_type': 'integration_request',
            'request_id': request.request_id,
            'integration_mode': request.integration_mode.value,
            'processing_priority': request.processing_priority.value,
            'labeling_strategy': request.labeling_strategy.value,
            'content_type': request.content_type,
            'source_network': request.source_network.value if request.source_network else None,
            'timestamp': request.created_at.isoformat()
        })
    
    async def _log_integration_result(self, request: IntegrationRequest, result: IntegrationResult):
        """Log integration result for audit purposes."""
        await self.audit_logger.log_classification_event({
            'event_type': 'integration_result',
            'request_id': request.request_id,
            'final_classification': result.final_classification.value,
            'confidence_score': result.confidence_score,
            'confidence_level': result.confidence_level.value,
            'engines_used': result.engines_used,
            'cross_validation_passed': result.cross_validation_passed,
            'result_consistency': result.result_consistency,
            'fallback_used': result.fallback_used,
            'total_processing_time_ms': result.total_processing_time_ms,
            'warnings_count': len(result.integration_warnings),
            'timestamp': result.processed_at.isoformat()
        })
    
    async def _log_integration_error(self, request: IntegrationRequest, error: Exception):
        """Log integration error for audit purposes."""
        await self.audit_logger.log_classification_event({
            'event_type': 'integration_error',
            'request_id': request.request_id,
            'error': str(error),
            'error_type': type(error).__name__,
            'timestamp': datetime.now(timezone.utc).isoformat()
        })
    
    def get_metrics(self) -> IntegrationMetrics:
        """Get current integration metrics."""
        return self.metrics
    
    def reset_metrics(self):
        """Reset integration metrics."""
        self.metrics = IntegrationMetrics()
    
    def clear_cache(self):
        """Clear the integration cache."""
        with self._cache_lock:
            self._integration_cache.clear()
        logger.info("Integration cache cleared")
    
    async def shutdown(self):
        """Shutdown the integration layer."""
        logger.info("Shutting down LabelingIntegrationLayer")
        
        # Shutdown thread pool
        self._thread_pool.shutdown(wait=True)
        
        # Shutdown automated labeler
        await self.automated_labeler.shutdown()
        
        # Shutdown content analyzer
        await self.content_analyzer.shutdown()
        
        # Clear cache
        self.clear_cache()
        
        logger.info("LabelingIntegrationLayer shutdown complete")


# Example usage and testing
if __name__ == "__main__":
    import asyncio
    
    async def test_integration_layer():
        """Test the integration layer."""
        integration_layer = LabelingIntegrationLayer()
        
        # Test request
        request = IntegrationRequest(
            content="This document contains CONFIDENTIAL information about Project ALPHA network configurations.",
            content_type="text/plain",
            source_network=NetworkDomain.SIPR,
            source_user_id=uuid4(),
            integration_mode=IntegrationMode.HYBRID,
            processing_priority=ProcessingPriority.NORMAL,
            labeling_strategy=LabelingStrategy.HYBRID
        )
        
        # Process request
        result = await integration_layer.process_integrated_labeling(request)
        
        print(f"Final Classification: {result.final_classification}")
        print(f"Confidence: {result.confidence_level.value} ({result.confidence_score:.2f})")
        print(f"Engines Used: {result.engines_used}")
        print(f"Processing Time: {result.total_processing_time_ms:.2f}ms")
        print(f"Cross-validation Passed: {result.cross_validation_passed}")
        print(f"Result Consistency: {result.result_consistency:.2f}")
        print(f"Fallback Used: {result.fallback_used}")
        print(f"Warnings: {result.integration_warnings}")
        print(f"Reasoning: {result.reasoning}")
        
        # Get metrics
        metrics = integration_layer.get_metrics()
        print(f"Total Requests: {metrics.total_requests}")
        print(f"Success Rate: {metrics.successful_integrations / metrics.total_requests * 100:.1f}%")
        print(f"Average Processing Time: {metrics.average_processing_time_ms:.2f}ms")
        
        await integration_layer.shutdown()
    
    # Run test
    asyncio.run(test_integration_layer())