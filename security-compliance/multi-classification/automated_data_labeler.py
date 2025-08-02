"""
Automated Data Labeling Framework for Multi-Classification Systems
================================================================

This module provides comprehensive automated data labeling capabilities that integrate
with the existing multi-classification framework, offering source-based, content-based,
and context-aware labeling for DoD and enterprise environments.

Key Features:
- Source-based labeling from network domain, user clearance, and system classification
- ML-powered content analysis for sensitive patterns and classification markers
- Context-aware processing considering surrounding data and workflow patterns
- Real-time processing with <50ms per document performance targets
- Full integration with enhanced_classification_engine.py and clearance_verification_engine.py
- DoD compliance with NIPR, SIPR, and JWICS network requirements
- Comprehensive audit logging and monitoring

Classification: UNCLASSIFIED//FOR OFFICIAL USE ONLY
Version: 1.0 - Initial Implementation
Author: Security Compliance Team
Date: 2025-07-29
"""

import asyncio
import json
import logging
import time
import hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Tuple, Set, Union, AsyncGenerator
from uuid import UUID, uuid4
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
import numpy as np
from threading import Lock
import aiofiles
import aiohttp
from collections import defaultdict, deque

# Import existing infrastructure
from .enhanced_classification_engine import (
    EnhancedClassificationEngine, ProcessingMode, OptimizationLevel,
    EnhancedClassificationRequest, ProcessingMetrics
)
from .clearance_verification_engine import (
    ClearanceVerificationEngine, ClearanceStatus, AccessDecision,
    ClearanceVerificationRequest
)
from .classification_audit_logger import ClassificationAuditLogger
from .models.bell_lapadula import BellLaPadulaSecurityModel, SecurityLabel, ClassificationLevel
from ..rbac.models.classification import SecurityClearance
from ..rbac.models.data_classification import (
    NetworkDomain, DataSensitivity, ClassificationResult, 
    PIIDetectionResult, ClassificationEvidence
)

logger = logging.getLogger(__name__)


class LabelingStrategy(Enum):
    """Automated labeling strategies."""
    SOURCE_BASED = "source_based"
    CONTENT_BASED = "content_based" 
    CONTEXT_AWARE = "context_aware"
    HYBRID = "hybrid"
    ML_ENHANCED = "ml_enhanced"


class LabelingConfidence(Enum):
    """Confidence levels for automated labeling."""
    HIGH = "high"           # >90% confidence
    MEDIUM = "medium"       # 70-90% confidence
    LOW = "low"            # 50-70% confidence
    UNCERTAIN = "uncertain" # <50% confidence


class DataOriginType(Enum):
    """Types of data origins for source-based labeling."""
    NETWORK_SOURCE = "network_source"
    USER_GENERATED = "user_generated"
    SYSTEM_GENERATED = "system_generated"
    EXTERNAL_IMPORT = "external_import"
    CROSS_DOMAIN_TRANSFER = "cross_domain_transfer"


@dataclass
class LabelingRequest:
    """Request structure for automated data labeling."""
    request_id: str = field(default_factory=lambda: str(uuid4()))
    content: str = ""
    content_type: str = "text/plain"
    content_metadata: Dict[str, Any] = field(default_factory=dict)
    
    # Source information
    source_network: Optional[NetworkDomain] = None
    source_user_id: Optional[UUID] = None
    source_system: Optional[str] = None
    source_classification: Optional[ClassificationLevel] = None
    origin_type: DataOriginType = DataOriginType.SYSTEM_GENERATED
    
    # Context information
    workflow_context: Dict[str, Any] = field(default_factory=dict)
    surrounding_data: List[str] = field(default_factory=list)
    user_session_context: Dict[str, Any] = field(default_factory=dict)
    
    # Processing preferences
    strategy: LabelingStrategy = LabelingStrategy.HYBRID
    performance_mode: OptimizationLevel = OptimizationLevel.STANDARD
    require_manual_review: bool = False
    
    # Timestamps
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    priority: int = 5  # 1-10 scale


@dataclass
class LabelingResult:
    """Result structure for automated data labeling."""
    request_id: str
    
    # Classification results
    predicted_classification: ClassificationLevel
    confidence_level: LabelingConfidence
    confidence_score: float
    
    # Detailed analysis
    source_analysis: Dict[str, Any] = field(default_factory=dict)
    content_analysis: Dict[str, Any] = field(default_factory=dict)
    context_analysis: Dict[str, Any] = field(default_factory=dict)
    
    # Evidence and reasoning
    classification_evidence: List[ClassificationEvidence] = field(default_factory=list)
    reasoning: str = ""
    risk_factors: List[str] = field(default_factory=list)
    
    # Processing metadata
    processing_time_ms: float = 0.0
    strategies_used: List[LabelingStrategy] = field(default_factory=list)
    models_used: List[str] = field(default_factory=list)
    
    # Quality metrics
    consistency_score: float = 0.0
    accuracy_estimate: float = 0.0
    
    # Compliance information
    dod_compliance_level: str = ""
    network_compatibility: List[NetworkDomain] = field(default_factory=list)
    
    # Timestamps
    processed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: Optional[datetime] = None


@dataclass
class LabelingMetrics:
    """Metrics for automated labeling performance."""
    total_requests: int = 0
    successful_labels: int = 0
    failed_labels: int = 0
    average_processing_time_ms: float = 0.0
    confidence_distribution: Dict[LabelingConfidence, int] = field(default_factory=dict)
    strategy_usage: Dict[LabelingStrategy, int] = field(default_factory=dict)
    accuracy_by_classification: Dict[ClassificationLevel, float] = field(default_factory=dict)
    performance_sla_violations: int = 0
    
    def update_request(self, result: LabelingResult, success: bool = True):
        """Update metrics with a new labeling result."""
        self.total_requests += 1
        
        if success:
            self.successful_labels += 1
            
            # Update confidence distribution
            if result.confidence_level not in self.confidence_distribution:
                self.confidence_distribution[result.confidence_level] = 0
            self.confidence_distribution[result.confidence_level] += 1
            
            # Update strategy usage
            for strategy in result.strategies_used:
                if strategy not in self.strategy_usage:
                    self.strategy_usage[strategy] = 0
                self.strategy_usage[strategy] += 1
            
            # Update processing time
            total_time = self.average_processing_time_ms * (self.successful_labels - 1)
            self.average_processing_time_ms = (total_time + result.processing_time_ms) / self.successful_labels
            
            # Track SLA violations (>50ms)
            if result.processing_time_ms > 50.0:
                self.performance_sla_violations += 1
        else:
            self.failed_labels += 1


class AutomatedDataLabeler:
    """
    Core automated data labeling engine that orchestrates source-based,
    content-based, and context-aware labeling strategies.
    """
    
    def __init__(
        self,
        classification_engine: Optional[EnhancedClassificationEngine] = None,
        clearance_engine: Optional[ClearanceVerificationEngine] = None,
        audit_logger: Optional[ClassificationAuditLogger] = None,
        config: Optional[Dict[str, Any]] = None
    ):
        """Initialize the automated data labeler."""
        self.config = config or {}
        
        # Initialize engines
        self.classification_engine = classification_engine or EnhancedClassificationEngine()
        self.clearance_engine = clearance_engine or ClearanceVerificationEngine()
        self.audit_logger = audit_logger or ClassificationAuditLogger()
        
        # Initialize Bell-LaPadula security model
        self.security_model = BellLaPadulaSecurityModel()
        
        # Performance and caching
        self.metrics = LabelingMetrics()
        self._label_cache: Dict[str, LabelingResult] = {}
        self._cache_lock = Lock()
        self._max_cache_size = self.config.get('max_cache_size', 10000)
        self._cache_ttl_seconds = self.config.get('cache_ttl_seconds', 3600)
        
        # Processing pools
        self._thread_pool = ThreadPoolExecutor(
            max_workers=self.config.get('max_workers', 10),
            thread_name_prefix='labeler'
        )
        
        # Source analyzers (will be imported from separate modules)
        self._source_analyzers = {}
        self._content_analyzers = {}
        self._context_processors = {}
        
        # Configuration
        self._performance_target_ms = self.config.get('performance_target_ms', 50.0)
        self._default_confidence_threshold = self.config.get('confidence_threshold', 0.7)
        
        logger.info("AutomatedDataLabeler initialized with performance target: %.1fms", 
                   self._performance_target_ms)
    
    async def label_data(self, request: LabelingRequest) -> LabelingResult:
        """
        Main entry point for automated data labeling.
        
        Args:
            request: LabelingRequest containing data and context
            
        Returns:
            LabelingResult with classification and analysis
        """
        start_time = time.time()
        
        try:
            # Log request
            await self._log_labeling_request(request)
            
            # Check cache first
            cache_key = self._generate_cache_key(request)
            cached_result = self._get_cached_result(cache_key)
            if cached_result:
                logger.debug(f"Cache hit for request {request.request_id}")
                return cached_result
            
            # Execute labeling strategy
            result = await self._execute_labeling_strategy(request)
            
            # Update processing time
            processing_time_ms = (time.time() - start_time) * 1000
            result.processing_time_ms = processing_time_ms
            
            # Cache result
            self._cache_result(cache_key, result)
            
            # Update metrics
            self.metrics.update_request(result, success=True)
            
            # Log result
            await self._log_labeling_result(request, result)
            
            logger.debug(f"Labeled data for request {request.request_id} in {processing_time_ms:.2f}ms")
            return result
            
        except Exception as e:
            processing_time_ms = (time.time() - start_time) * 1000
            logger.error(f"Failed to label data for request {request.request_id}: {e}")
            
            # Create error result
            error_result = LabelingResult(
                request_id=request.request_id,
                predicted_classification=ClassificationLevel.UNCLASSIFIED,
                confidence_level=LabelingConfidence.UNCERTAIN,
                confidence_score=0.0,
                reasoning=f"Labeling failed: {str(e)}",
                processing_time_ms=processing_time_ms
            )
            
            # Update metrics
            self.metrics.update_request(error_result, success=False)
            
            # Log error
            await self._log_labeling_error(request, e)
            
            return error_result
    
    async def batch_label_data(self, requests: List[LabelingRequest]) -> List[LabelingResult]:
        """
        Process multiple labeling requests in parallel.
        
        Args:
            requests: List of LabelingRequest objects
            
        Returns:
            List of LabelingResult objects
        """
        logger.info(f"Processing batch of {len(requests)} labeling requests")
        
        # Process requests concurrently
        tasks = [self.label_data(request) for request in requests]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Convert exceptions to error results
        final_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                error_result = LabelingResult(
                    request_id=requests[i].request_id,
                    predicted_classification=ClassificationLevel.UNCLASSIFIED,
                    confidence_level=LabelingConfidence.UNCERTAIN,
                    confidence_score=0.0,
                    reasoning=f"Batch processing failed: {str(result)}"
                )
                final_results.append(error_result)
            else:
                final_results.append(result)
        
        return final_results
    
    async def _execute_labeling_strategy(self, request: LabelingRequest) -> LabelingResult:
        """Execute the appropriate labeling strategy based on request."""
        if request.strategy == LabelingStrategy.SOURCE_BASED:
            return await self._source_based_labeling(request)
        elif request.strategy == LabelingStrategy.CONTENT_BASED:
            return await self._content_based_labeling(request)
        elif request.strategy == LabelingStrategy.CONTEXT_AWARE:
            return await self._context_aware_labeling(request)
        elif request.strategy == LabelingStrategy.HYBRID:
            return await self._hybrid_labeling(request)
        elif request.strategy == LabelingStrategy.ML_ENHANCED:
            return await self._ml_enhanced_labeling(request)
        else:
            raise ValueError(f"Unknown labeling strategy: {request.strategy}")
    
    async def _source_based_labeling(self, request: LabelingRequest) -> LabelingResult:
        """Perform source-based labeling analysis."""
        result = LabelingResult(request_id=request.request_id)
        result.strategies_used.append(LabelingStrategy.SOURCE_BASED)
        
        # Analyze network source
        if request.source_network:
            network_classification = self._classify_by_network(request.source_network)
            result.source_analysis['network_classification'] = network_classification
            result.predicted_classification = max(
                result.predicted_classification, 
                network_classification,
                key=lambda x: x.value if hasattr(x, 'value') else 0
            )
        
        # Analyze user clearance
        if request.source_user_id:
            user_classification = await self._classify_by_user_clearance(request.source_user_id)
            result.source_analysis['user_classification'] = user_classification
            result.predicted_classification = max(
                result.predicted_classification,
                user_classification,
                key=lambda x: x.value if hasattr(x, 'value') else 0
            )
        
        # Analyze system source
        if request.source_system:
            system_classification = self._classify_by_system(request.source_system)
            result.source_analysis['system_classification'] = system_classification
            result.predicted_classification = max(
                result.predicted_classification,
                system_classification,
                key=lambda x: x.value if hasattr(x, 'value') else 0
            )
        
        # Set confidence based on available source information
        available_sources = sum([
            1 if request.source_network else 0,
            1 if request.source_user_id else 0,
            1 if request.source_system else 0
        ])
        
        if available_sources >= 2:
            result.confidence_level = LabelingConfidence.HIGH
            result.confidence_score = 0.85
        elif available_sources == 1:
            result.confidence_level = LabelingConfidence.MEDIUM
            result.confidence_score = 0.70
        else:
            result.confidence_level = LabelingConfidence.LOW
            result.confidence_score = 0.40
        
        result.reasoning = f"Source-based classification using {available_sources} source indicators"
        
        return result
    
    async def _content_based_labeling(self, request: LabelingRequest) -> LabelingResult:
        """Perform ML-powered content analysis for labeling."""
        result = LabelingResult(request_id=request.request_id)
        result.strategies_used.append(LabelingStrategy.CONTENT_BASED)
        
        # Use existing classification engine for content analysis
        classification_request = EnhancedClassificationRequest(
            request_id=request.request_id,
            content=request.content,
            content_type=request.content_type,
            user_id=request.source_user_id
        )
        
        classification_result = await self.classification_engine.classify_content(classification_request)
        
        # Extract results
        result.predicted_classification = classification_result.classification_level
        result.confidence_score = classification_result.confidence_score
        result.content_analysis = {
            'pii_detected': classification_result.pii_detected,
            'sensitive_patterns': classification_result.sensitive_patterns,
            'classification_markers': classification_result.classification_markers
        }
        
        # Map confidence score to confidence level
        if result.confidence_score >= 0.9:
            result.confidence_level = LabelingConfidence.HIGH
        elif result.confidence_score >= 0.7:
            result.confidence_level = LabelingConfidence.MEDIUM
        elif result.confidence_score >= 0.5:
            result.confidence_level = LabelingConfidence.LOW
        else:
            result.confidence_level = LabelingConfidence.UNCERTAIN
        
        result.reasoning = "Content-based classification using ML analysis"
        result.models_used.append("enhanced_classification_engine")
        
        return result
    
    async def _context_aware_labeling(self, request: LabelingRequest) -> LabelingResult:
        """Perform context-aware labeling considering surrounding data and workflow."""
        result = LabelingResult(request_id=request.request_id)
        result.strategies_used.append(LabelingStrategy.CONTEXT_AWARE)
        
        # Analyze workflow context
        workflow_classification = self._analyze_workflow_context(request.workflow_context)
        result.context_analysis['workflow_classification'] = workflow_classification
        
        # Analyze surrounding data
        surrounding_classification = await self._analyze_surrounding_data(request.surrounding_data)
        result.context_analysis['surrounding_classification'] = surrounding_classification
        
        # Analyze user session context
        session_classification = self._analyze_session_context(request.user_session_context)
        result.context_analysis['session_classification'] = session_classification
        
        # Determine final classification based on context
        context_classifications = [
            workflow_classification,
            surrounding_classification,
            session_classification
        ]
        
        # Use highest classification level (following Bell-LaPadula)
        result.predicted_classification = max(
            context_classifications,
            key=lambda x: x.value if hasattr(x, 'value') else 0
        )
        
        # Set confidence based on context consistency
        unique_classifications = set(context_classifications)
        if len(unique_classifications) == 1:
            result.confidence_level = LabelingConfidence.HIGH
            result.confidence_score = 0.90
        elif len(unique_classifications) == 2:
            result.confidence_level = LabelingConfidence.MEDIUM
            result.confidence_score = 0.75
        else:
            result.confidence_level = LabelingConfidence.LOW
            result.confidence_score = 0.60
        
        result.reasoning = "Context-aware classification based on workflow, surrounding data, and session analysis"
        
        return result
    
    async def _hybrid_labeling(self, request: LabelingRequest) -> LabelingResult:
        """Perform hybrid labeling combining multiple strategies."""
        # Execute all strategies in parallel
        source_task = self._source_based_labeling(request)
        content_task = self._content_based_labeling(request)
        context_task = self._context_aware_labeling(request)
        
        source_result, content_result, context_result = await asyncio.gather(
            source_task, content_task, context_task
        )
        
        # Combine results
        combined_result = LabelingResult(request_id=request.request_id)
        combined_result.strategies_used = [
            LabelingStrategy.SOURCE_BASED,
            LabelingStrategy.CONTENT_BASED,
            LabelingStrategy.CONTEXT_AWARE,
            LabelingStrategy.HYBRID
        ]
        
        # Merge analysis results
        combined_result.source_analysis = source_result.source_analysis
        combined_result.content_analysis = content_result.content_analysis
        combined_result.context_analysis = context_result.context_analysis
        
        # Determine final classification (highest level wins)
        classifications = [
            source_result.predicted_classification,
            content_result.predicted_classification,
            context_result.predicted_classification
        ]
        
        combined_result.predicted_classification = max(
            classifications,
            key=lambda x: x.value if hasattr(x, 'value') else 0
        )
        
        # Calculate weighted confidence
        confidences = [
            source_result.confidence_score,
            content_result.confidence_score,
            context_result.confidence_score
        ]
        
        # Weight content analysis higher for final confidence
        weights = [0.3, 0.5, 0.2]
        combined_result.confidence_score = sum(
            conf * weight for conf, weight in zip(confidences, weights)
        )
        
        # Set confidence level
        if combined_result.confidence_score >= 0.85:
            combined_result.confidence_level = LabelingConfidence.HIGH
        elif combined_result.confidence_score >= 0.65:
            combined_result.confidence_level = LabelingConfidence.MEDIUM
        elif combined_result.confidence_score >= 0.45:
            combined_result.confidence_level = LabelingConfidence.LOW
        else:
            combined_result.confidence_level = LabelingConfidence.UNCERTAIN
        
        combined_result.reasoning = "Hybrid classification combining source, content, and context analysis"
        combined_result.models_used = content_result.models_used
        
        return combined_result
    
    async def _ml_enhanced_labeling(self, request: LabelingRequest) -> LabelingResult:
        """Perform ML-enhanced labeling with advanced models."""
        # Start with hybrid approach
        base_result = await self._hybrid_labeling(request)
        
        # Enhance with additional ML models (placeholder for future implementation)
        base_result.strategies_used.append(LabelingStrategy.ML_ENHANCED)
        base_result.reasoning += " with ML enhancement"
        
        return base_result
    
    def _classify_by_network(self, network: NetworkDomain) -> ClassificationLevel:
        """Classify data based on network domain."""
        network_classifications = {
            NetworkDomain.NIPR: ClassificationLevel.UNCLASSIFIED,
            NetworkDomain.SIPR: ClassificationLevel.SECRET,
            NetworkDomain.JWICS: ClassificationLevel.TOP_SECRET
        }
        return network_classifications.get(network, ClassificationLevel.UNCLASSIFIED)
    
    async def _classify_by_user_clearance(self, user_id: UUID) -> ClassificationLevel:
        """Classify data based on user's clearance level."""
        try:
            # Use clearance verification engine
            verification_request = ClearanceVerificationRequest(
                user_id=user_id,
                requested_classification=ClassificationLevel.TOP_SECRET
            )
            
            verification_result = await self.clearance_engine.verify_clearance(verification_request)
            
            if verification_result.status == ClearanceStatus.VALID:
                return verification_result.verified_clearance.classification_level
            else:
                return ClassificationLevel.UNCLASSIFIED
                
        except Exception as e:
            logger.warning(f"Failed to verify user clearance for {user_id}: {e}")
            return ClassificationLevel.UNCLASSIFIED
    
    def _classify_by_system(self, system: str) -> ClassificationLevel:
        """Classify data based on source system."""
        # System classification mapping (configurable)
        system_classifications = self.config.get('system_classifications', {
            'sipr_system': ClassificationLevel.SECRET,
            'jwics_system': ClassificationLevel.TOP_SECRET,
            'nipr_system': ClassificationLevel.UNCLASSIFIED
        })
        
        return system_classifications.get(system.lower(), ClassificationLevel.UNCLASSIFIED)
    
    def _analyze_workflow_context(self, workflow_context: Dict[str, Any]) -> ClassificationLevel:
        """Analyze workflow context for classification hints."""
        # Look for workflow classification indicators
        workflow_type = workflow_context.get('workflow_type', '').lower()
        project_classification = workflow_context.get('project_classification')
        
        if project_classification:
            try:
                return ClassificationLevel(project_classification)
            except ValueError:
                pass
        
        # Default workflow classifications
        if 'secret' in workflow_type or 'classified' in workflow_type:
            return ClassificationLevel.SECRET
        elif 'sensitive' in workflow_type:
            return ClassificationLevel.CONFIDENTIAL
        else:
            return ClassificationLevel.UNCLASSIFIED
    
    async def _analyze_surrounding_data(self, surrounding_data: List[str]) -> ClassificationLevel:
        """Analyze surrounding data context for classification."""
        if not surrounding_data:
            return ClassificationLevel.UNCLASSIFIED
        
        # Classify each piece of surrounding data
        max_classification = ClassificationLevel.UNCLASSIFIED
        
        for data in surrounding_data[:5]:  # Limit analysis to first 5 items
            # Use content-based classification
            request = LabelingRequest(
                content=data,
                strategy=LabelingStrategy.CONTENT_BASED
            )
            result = await self._content_based_labeling(request)
            
            if result.predicted_classification.value > max_classification.value:
                max_classification = result.predicted_classification
        
        return max_classification
    
    def _analyze_session_context(self, session_context: Dict[str, Any]) -> ClassificationLevel:
        """Analyze user session context for classification."""
        session_classification = session_context.get('session_classification')
        if session_classification:
            try:
                return ClassificationLevel(session_classification)
            except ValueError:
                pass
        
        # Analyze session attributes
        network_domain = session_context.get('network_domain')
        if network_domain:
            return self._classify_by_network(NetworkDomain(network_domain))
        
        return ClassificationLevel.UNCLASSIFIED
    
    def _generate_cache_key(self, request: LabelingRequest) -> str:
        """Generate cache key for labeling request."""
        # Create hash of relevant request fields
        cache_data = {
            'content': request.content,
            'content_type': request.content_type,
            'source_network': request.source_network.value if request.source_network else None,
            'source_user_id': str(request.source_user_id) if request.source_user_id else None,
            'source_system': request.source_system,
            'strategy': request.strategy.value,
            'workflow_context': json.dumps(request.workflow_context, sort_keys=True),
            'surrounding_data': json.dumps(sorted(request.surrounding_data))
        }
        
        cache_string = json.dumps(cache_data, sort_keys=True)
        return hashlib.sha256(cache_string.encode()).hexdigest()
    
    def _get_cached_result(self, cache_key: str) -> Optional[LabelingResult]:
        """Get cached labeling result if available and valid."""
        with self._cache_lock:
            if cache_key in self._label_cache:
                result = self._label_cache[cache_key]
                
                # Check if result is still valid
                if result.expires_at and result.expires_at > datetime.now(timezone.utc):
                    return result
                else:
                    # Remove expired result
                    del self._label_cache[cache_key]
        
        return None
    
    def _cache_result(self, cache_key: str, result: LabelingResult):
        """Cache labeling result."""
        with self._cache_lock:
            # Set expiration time
            result.expires_at = datetime.now(timezone.utc) + timedelta(seconds=self._cache_ttl_seconds)
            
            # Add to cache
            self._label_cache[cache_key] = result
            
            # Maintain cache size limit
            if len(self._label_cache) > self._max_cache_size:
                # Remove oldest entries
                sorted_items = sorted(
                    self._label_cache.items(),
                    key=lambda x: x[1].processed_at
                )
                
                for key, _ in sorted_items[:len(self._label_cache) - self._max_cache_size]:
                    del self._label_cache[key]
    
    async def _log_labeling_request(self, request: LabelingRequest):
        """Log labeling request for audit purposes."""
        await self.audit_logger.log_classification_event({
            'event_type': 'automated_labeling_request',
            'request_id': request.request_id,
            'content_type': request.content_type,
            'source_network': request.source_network.value if request.source_network else None,
            'source_user_id': str(request.source_user_id) if request.source_user_id else None,
            'strategy': request.strategy.value,
            'timestamp': request.created_at.isoformat()
        })
    
    async def _log_labeling_result(self, request: LabelingRequest, result: LabelingResult):
        """Log labeling result for audit purposes."""
        await self.audit_logger.log_classification_event({
            'event_type': 'automated_labeling_result',
            'request_id': request.request_id,
            'predicted_classification': result.predicted_classification.value,
            'confidence_level': result.confidence_level.value,
            'confidence_score': result.confidence_score,
            'processing_time_ms': result.processing_time_ms,
            'strategies_used': [s.value for s in result.strategies_used],
            'timestamp': result.processed_at.isoformat()
        })
    
    async def _log_labeling_error(self, request: LabelingRequest, error: Exception):
        """Log labeling error for audit purposes."""
        await self.audit_logger.log_classification_event({
            'event_type': 'automated_labeling_error',
            'request_id': request.request_id,
            'error': str(error),
            'error_type': type(error).__name__,
            'timestamp': datetime.now(timezone.utc).isoformat()
        })
    
    def get_metrics(self) -> LabelingMetrics:
        """Get current labeling metrics."""
        return self.metrics
    
    def reset_metrics(self):
        """Reset labeling metrics."""
        self.metrics = LabelingMetrics()
    
    def clear_cache(self):
        """Clear the labeling cache."""
        with self._cache_lock:
            self._label_cache.clear()
        logger.info("Labeling cache cleared")
    
    async def shutdown(self):
        """Shutdown the automated data labeler."""
        logger.info("Shutting down AutomatedDataLabeler")
        
        # Shutdown thread pool
        self._thread_pool.shutdown(wait=True)
        
        # Clear cache
        self.clear_cache()
        
        logger.info("AutomatedDataLabeler shutdown complete")


# Example usage and testing
if __name__ == "__main__":
    import asyncio
    
    async def test_automated_labeler():
        """Test the automated data labeler."""
        labeler = AutomatedDataLabeler()
        
        # Test request
        request = LabelingRequest(
            content="This document contains sensitive operational data for Project ALPHA.",
            content_type="text/plain",
            source_network=NetworkDomain.SIPR,
            strategy=LabelingStrategy.HYBRID
        )
        
        # Process request
        result = await labeler.label_data(request)
        
        print(f"Classification: {result.predicted_classification}")
        print(f"Confidence: {result.confidence_level} ({result.confidence_score:.2f})")
        print(f"Processing time: {result.processing_time_ms:.2f}ms")
        print(f"Reasoning: {result.reasoning}")
        
        # Get metrics
        metrics = labeler.get_metrics()
        print(f"Total requests: {metrics.total_requests}")
        print(f"Success rate: {metrics.successful_labels / metrics.total_requests * 100:.1f}%")
        
        await labeler.shutdown()
    
    # Run test
    asyncio.run(test_automated_labeler())