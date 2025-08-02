"""
Context-Aware Processing for Automated Data Labeling
===================================================

This module provides advanced context-aware processing capabilities for automated
data labeling, analyzing surrounding data, user context, workflow patterns, and
environmental factors to enhance classification accuracy.

Key Features:
- Workflow context analysis with pattern recognition
- User session context tracking and correlation
- Surrounding data correlation and classification inheritance
- Temporal pattern analysis for context evolution
- Environmental context assessment (time, location, system state)
- Multi-modal context fusion for enhanced accuracy
- Real-time context streaming and updates
- Context-aware confidence scoring

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
import numpy as np
from collections import defaultdict, deque
import statistics

# Import existing infrastructure
from .models.bell_lapadula import BellLaPadulaSecurityModel, SecurityLabel, ClassificationLevel
from ..rbac.models.data_classification import NetworkDomain, DataSensitivity
from ..audits.audit_logger import AuditLogger

logger = logging.getLogger(__name__)


class ContextType(Enum):
    """Types of context for analysis."""
    WORKFLOW_CONTEXT = "workflow_context"
    USER_SESSION_CONTEXT = "user_session_context"
    SURROUNDING_DATA_CONTEXT = "surrounding_data_context"
    TEMPORAL_CONTEXT = "temporal_context"
    ENVIRONMENTAL_CONTEXT = "environmental_context"
    COLLABORATIVE_CONTEXT = "collaborative_context"


class ContextRelevance(Enum):
    """Relevance levels for context information."""
    CRITICAL = "critical"        # Directly impacts classification
    HIGH = "high"               # Strongly influences classification
    MEDIUM = "medium"           # Moderately influences classification
    LOW = "low"                 # Weak influence on classification
    IRRELEVANT = "irrelevant"   # No influence on classification


class WorkflowStage(Enum):
    """Stages in data processing workflows."""
    CREATION = "creation"
    REVIEW = "review"
    PROCESSING = "processing"
    ANALYSIS = "analysis"
    DISTRIBUTION = "distribution"
    ARCHIVAL = "archival"


@dataclass
class WorkflowContext:
    """Represents workflow context information."""
    workflow_id: str
    workflow_type: str
    current_stage: WorkflowStage
    
    # Workflow metadata
    project_name: Optional[str] = None
    project_classification: Optional[ClassificationLevel] = None
    workflow_purpose: Optional[str] = None
    
    # Processing history
    previous_stages: List[WorkflowStage] = field(default_factory=list)
    stage_timestamps: Dict[WorkflowStage, datetime] = field(default_factory=dict)
    
    # Participants
    workflow_participants: List[UUID] = field(default_factory=list)
    current_user: Optional[UUID] = None
    
    # Classification attributes
    data_handling_requirements: List[str] = field(default_factory=list)
    security_controls: List[str] = field(default_factory=list)
    
    # Quality attributes
    confidence_score: float = 0.0
    reliability: ContextRelevance = ContextRelevance.MEDIUM


@dataclass
class UserSessionContext:
    """Represents user session context information."""
    session_id: str
    user_id: UUID
    
    # Session attributes
    session_start: datetime
    last_activity: datetime
    session_duration_minutes: float = 0.0
    
    # User context
    user_clearance_level: Optional[ClassificationLevel] = None
    user_roles: List[str] = field(default_factory=list)
    user_organization: Optional[str] = None
    
    # Activity patterns
    recent_activities: List[Dict[str, Any]] = field(default_factory=list)
    document_access_history: List[str] = field(default_factory=list)
    classification_patterns: Dict[ClassificationLevel, int] = field(default_factory=dict)
    
    # Environment
    network_domain: Optional[NetworkDomain] = None
    access_location: Optional[str] = None
    device_type: Optional[str] = None
    
    # Risk factors
    anomalous_behavior: bool = False
    risk_score: float = 0.0
    risk_factors: List[str] = field(default_factory=list)
    
    # Quality attributes
    confidence_score: float = 0.0
    reliability: ContextRelevance = ContextRelevance.MEDIUM


@dataclass
class SurroundingDataContext:
    """Represents surrounding data context information."""
    primary_document_id: str
    
    # Related documents
    related_documents: List[str] = field(default_factory=list)
    document_similarities: Dict[str, float] = field(default_factory=dict)
    
    # Classification context
    surrounding_classifications: List[ClassificationLevel] = field(default_factory=list)
    classification_consistency: float = 0.0
    
    # Content relationships
    content_themes: List[str] = field(default_factory=list)
    shared_entities: List[str] = field(default_factory=list)
    semantic_similarity_scores: Dict[str, float] = field(default_factory=dict)
    
    # Temporal relationships
    creation_time_proximity: Dict[str, timedelta] = field(default_factory=dict)
    modification_correlations: List[Tuple[str, str, float]] = field(default_factory=list)
    
    # Source relationships
    common_sources: List[str] = field(default_factory=list)
    source_reliability_scores: Dict[str, float] = field(default_factory=dict)
    
    # Quality attributes
    confidence_score: float = 0.0
    reliability: ContextRelevance = ContextRelevance.MEDIUM


@dataclass
class TemporalContext:
    """Represents temporal context information."""
    reference_time: datetime
    
    # Time-based patterns
    time_of_day: str = ""
    day_of_week: str = ""
    business_hours: bool = True
    
    # Historical patterns
    historical_classifications: List[Tuple[datetime, ClassificationLevel]] = field(default_factory=list)
    classification_trends: Dict[str, float] = field(default_factory=dict)
    
    # Event correlation
    concurrent_events: List[Dict[str, Any]] = field(default_factory=list)
    related_incidents: List[str] = field(default_factory=list)
    
    # Seasonal patterns
    seasonal_factors: Dict[str, Any] = field(default_factory=dict)
    
    # Quality attributes
    confidence_score: float = 0.0
    reliability: ContextRelevance = ContextRelevance.MEDIUM


@dataclass
class EnvironmentalContext:
    """Represents environmental context information."""
    # System environment
    system_state: Dict[str, Any] = field(default_factory=dict)
    system_load: float = 0.0
    security_posture: str = "normal"
    
    # Network environment
    network_conditions: Dict[str, Any] = field(default_factory=dict)
    bandwidth_usage: float = 0.0
    network_security_level: str = "standard"
    
    # Operational environment
    operational_tempo: str = "normal"
    threat_level: str = "low"
    mission_critical_operations: bool = False
    
    # Geographic context
    geographic_location: Optional[str] = None
    time_zone: str = "UTC"
    
    # Quality attributes
    confidence_score: float = 0.0
    reliability: ContextRelevance = ContextRelevance.MEDIUM


@dataclass
class ContextProcessingResult:
    """Result of context-aware processing."""
    request_id: str
    
    # Context analyses
    workflow_context: Optional[WorkflowContext] = None
    session_context: Optional[UserSessionContext] = None
    surrounding_context: Optional[SurroundingDataContext] = None
    temporal_context: Optional[TemporalContext] = None
    environmental_context: Optional[EnvironmentalContext] = None
    
    # Processing results
    context_influenced_classification: ClassificationLevel = ClassificationLevel.UNCLASSIFIED
    context_confidence_score: float = 0.0
    context_reliability_score: float = 0.0
    
    # Context insights
    key_context_factors: List[str] = field(default_factory=list)
    context_anomalies: List[str] = field(default_factory=list)
    recommendation_rationale: str = ""
    
    # Quality metrics
    context_coverage: float = 0.0  # Percentage of available context used
    context_consistency: float = 0.0  # Consistency across context types
    processing_time_ms: float = 0.0
    
    # Risk assessment
    context_risk_factors: List[str] = field(default_factory=list)
    overall_risk_score: float = 0.0
    
    # Timestamps
    processed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class WorkflowAnalyzer:
    """Analyzes workflow context for classification insights."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize workflow analyzer."""
        self.config = config or {}
        
        # Load workflow patterns
        self._load_workflow_patterns()
        
        logger.info("WorkflowAnalyzer initialized")
    
    def _load_workflow_patterns(self):
        """Load known workflow patterns and their classification implications."""
        self.workflow_patterns = self.config.get('workflow_patterns', {
            'intelligence_analysis': {
                'default_classification': ClassificationLevel.SECRET,
                'security_controls': ['SC-7', 'SC-8', 'AC-3'],
                'typical_stages': ['creation', 'analysis', 'review', 'distribution']
            },
            'operational_planning': {
                'default_classification': ClassificationLevel.SECRET,
                'security_controls': ['SC-7', 'AC-2', 'AC-3'],
                'typical_stages': ['creation', 'processing', 'review', 'distribution']
            },
            'administrative': {
                'default_classification': ClassificationLevel.UNCLASSIFIED,
                'security_controls': ['AC-2'],
                'typical_stages': ['creation', 'review', 'archival']
            },
            'technical_documentation': {
                'default_classification': ClassificationLevel.CONFIDENTIAL,
                'security_controls': ['SC-7', 'SC-8'],
                'typical_stages': ['creation', 'processing', 'review', 'distribution']
            }
        })
    
    def analyze_workflow_context(
        self, 
        workflow_data: Dict[str, Any]
    ) -> WorkflowContext:
        """Analyze workflow context for classification insights."""
        context = WorkflowContext(
            workflow_id=workflow_data.get('workflow_id', str(uuid4())),
            workflow_type=workflow_data.get('workflow_type', 'unknown'),
            current_stage=WorkflowStage(workflow_data.get('current_stage', 'processing'))
        )
        
        # Extract workflow metadata
        context.project_name = workflow_data.get('project_name')
        context.workflow_purpose = workflow_data.get('purpose')
        
        # Determine project classification
        project_classification = workflow_data.get('project_classification')
        if project_classification:
            try:
                context.project_classification = ClassificationLevel(project_classification)
            except ValueError:
                logger.warning(f"Invalid project classification: {project_classification}")
        
        # Analyze workflow pattern
        if context.workflow_type in self.workflow_patterns:
            pattern = self.workflow_patterns[context.workflow_type]
            
            # Inherit default classification if not specified
            if not context.project_classification:
                context.project_classification = pattern['default_classification']
            
            # Set security controls
            context.security_controls = pattern.get('security_controls', [])
            
            # Set confidence based on pattern match
            context.confidence_score = 0.8
            context.reliability = ContextRelevance.HIGH
        else:
            # Unknown workflow type
            context.confidence_score = 0.3
            context.reliability = ContextRelevance.LOW
        
        # Analyze workflow history
        stage_history = workflow_data.get('stage_history', [])
        for stage_entry in stage_history:
            if isinstance(stage_entry, dict):
                stage = WorkflowStage(stage_entry.get('stage'))
                timestamp = datetime.fromisoformat(stage_entry.get('timestamp'))
                context.previous_stages.append(stage)
                context.stage_timestamps[stage] = timestamp
        
        # Extract participants
        context.workflow_participants = [
            UUID(uid) for uid in workflow_data.get('participants', [])
            if isinstance(uid, str)
        ]
        
        current_user = workflow_data.get('current_user')
        if current_user:
            context.current_user = UUID(current_user)
        
        # Extract data handling requirements
        context.data_handling_requirements = workflow_data.get('data_handling_requirements', [])
        
        return context


class SessionAnalyzer:
    """Analyzes user session context for classification insights."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize session analyzer."""
        self.config = config or {}
        
        # Session pattern thresholds
        self._anomaly_threshold = self.config.get('anomaly_threshold', 0.7)
        self._max_session_history = self.config.get('max_session_history', 100)
        
        logger.info("SessionAnalyzer initialized")
    
    def analyze_session_context(
        self, 
        session_data: Dict[str, Any]
    ) -> UserSessionContext:
        """Analyze user session context for classification insights."""
        context = UserSessionContext(
            session_id=session_data.get('session_id', str(uuid4())),
            user_id=UUID(session_data['user_id']),
            session_start=datetime.fromisoformat(session_data.get('session_start', datetime.now(timezone.utc).isoformat())),
            last_activity=datetime.fromisoformat(session_data.get('last_activity', datetime.now(timezone.utc).isoformat()))
        )
        
        # Calculate session duration
        context.session_duration_minutes = (
            context.last_activity - context.session_start
        ).total_seconds() / 60.0
        
        # Extract user attributes
        context.user_clearance_level = self._parse_clearance_level(
            session_data.get('user_clearance')
        )
        context.user_roles = session_data.get('user_roles', [])
        context.user_organization = session_data.get('user_organization')
        
        # Extract environment information
        network_domain = session_data.get('network_domain')
        if network_domain:
            try:
                context.network_domain = NetworkDomain(network_domain)
            except ValueError:
                logger.warning(f"Invalid network domain: {network_domain}")
        
        context.access_location = session_data.get('access_location')
        context.device_type = session_data.get('device_type')
        
        # Analyze recent activities
        activities = session_data.get('recent_activities', [])
        context.recent_activities = activities[-self._max_session_history:]
        
        # Extract document access history
        context.document_access_history = session_data.get('document_access_history', [])
        
        # Analyze classification patterns
        classification_history = session_data.get('classification_history', [])
        for classification_str in classification_history:
            try:
                classification = ClassificationLevel(classification_str)
                if classification not in context.classification_patterns:
                    context.classification_patterns[classification] = 0
                context.classification_patterns[classification] += 1
            except ValueError:
                continue
        
        # Assess risk factors
        context = self._assess_session_risks(context, session_data)
        
        # Set confidence and reliability
        context.confidence_score = self._calculate_session_confidence(context)
        context.reliability = self._determine_session_reliability(context)
        
        return context
    
    def _parse_clearance_level(self, clearance_str: Optional[str]) -> Optional[ClassificationLevel]:
        """Parse clearance level string."""
        if not clearance_str:
            return None
        
        try:
            return ClassificationLevel(clearance_str)
        except ValueError:
            logger.warning(f"Invalid clearance level: {clearance_str}")
            return None
    
    def _assess_session_risks(
        self, 
        context: UserSessionContext, 
        session_data: Dict[str, Any]
    ) -> UserSessionContext:
        """Assess risk factors in session context."""
        risk_score = 0.0
        risk_factors = []
        
        # Long session duration risk
        if context.session_duration_minutes > 480:  # 8 hours
            risk_score += 0.1
            risk_factors.append("Extended session duration")
        
        # Unusual access patterns
        unusual_patterns = session_data.get('unusual_patterns', [])
        if unusual_patterns:
            risk_score += 0.2 * len(unusual_patterns)
            risk_factors.extend(unusual_patterns)
        
        # Access outside normal hours
        if not self._is_business_hours(context.last_activity):
            risk_score += 0.1
            risk_factors.append("Access outside business hours")
        
        # Geographic anomalies
        if session_data.get('geographic_anomaly'):
            risk_score += 0.3
            risk_factors.append("Unusual geographic access")
        
        # Failed authentication attempts
        failed_attempts = session_data.get('failed_auth_attempts', 0)
        if failed_attempts > 3:
            risk_score += 0.2
            risk_factors.append(f"Multiple authentication failures ({failed_attempts})")
        
        context.risk_score = min(risk_score, 1.0)
        context.risk_factors = risk_factors
        context.anomalous_behavior = risk_score > self._anomaly_threshold
        
        return context
    
    def _is_business_hours(self, timestamp: datetime) -> bool:
        """Check if timestamp is within business hours."""
        # Assume business hours are 8 AM to 6 PM, Monday to Friday
        weekday = timestamp.weekday()  # 0 = Monday, 6 = Sunday
        hour = timestamp.hour
        
        return weekday < 5 and 8 <= hour <= 18
    
    def _calculate_session_confidence(self, context: UserSessionContext) -> float:
        """Calculate confidence score for session context."""
        confidence = 0.5  # Base confidence
        
        # Higher confidence for known users with clearance
        if context.user_clearance_level:
            confidence += 0.3
        
        # Higher confidence for longer, stable sessions
        if 30 <= context.session_duration_minutes <= 480:  # 30 minutes to 8 hours
            confidence += 0.2
        
        # Lower confidence for risky sessions
        confidence -= context.risk_score * 0.4
        
        # Higher confidence for consistent classification patterns
        if context.classification_patterns:
            pattern_consistency = max(context.classification_patterns.values()) / sum(context.classification_patterns.values())
            confidence += pattern_consistency * 0.2
        
        return max(0.0, min(1.0, confidence))
    
    def _determine_session_reliability(self, context: UserSessionContext) -> ContextRelevance:
        """Determine reliability of session context."""
        if context.confidence_score >= 0.8 and context.risk_score < 0.2:
            return ContextRelevance.HIGH
        elif context.confidence_score >= 0.6 and context.risk_score < 0.5:
            return ContextRelevance.MEDIUM
        elif context.confidence_score >= 0.4:
            return ContextRelevance.LOW
        else:
            return ContextRelevance.IRRELEVANT


class SurroundingDataAnalyzer:
    """Analyzes surrounding data context for classification insights."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize surrounding data analyzer."""
        self.config = config or {}
        
        # Analysis parameters
        self._similarity_threshold = self.config.get('similarity_threshold', 0.7)
        self._max_related_documents = self.config.get('max_related_documents', 20)
        
        logger.info("SurroundingDataAnalyzer initialized")
    
    async def analyze_surrounding_data(
        self, 
        primary_document_id: str,
        surrounding_data: List[Dict[str, Any]]
    ) -> SurroundingDataContext:
        """Analyze surrounding data context for classification insights."""
        context = SurroundingDataContext(primary_document_id=primary_document_id)
        
        if not surrounding_data:
            context.confidence_score = 0.0
            context.reliability = ContextRelevance.IRRELEVANT
            return context
        
        # Limit analysis to most relevant documents
        relevant_data = surrounding_data[:self._max_related_documents]
        
        # Extract document IDs and classifications
        for doc_data in relevant_data:
            doc_id = doc_data.get('document_id', str(uuid4()))
            context.related_documents.append(doc_id)
            
            # Extract classification if available
            classification_str = doc_data.get('classification')
            if classification_str:
                try:
                    classification = ClassificationLevel(classification_str)
                    context.surrounding_classifications.append(classification)
                except ValueError:
                    logger.warning(f"Invalid classification in surrounding data: {classification_str}")
            
            # Calculate similarity score
            similarity = doc_data.get('similarity_score', 0.0)
            context.document_similarities[doc_id] = similarity
            
            # Extract content themes
            themes = doc_data.get('content_themes', [])
            context.content_themes.extend(themes)
            
            # Extract shared entities
            entities = doc_data.get('shared_entities', [])
            context.shared_entities.extend(entities)
            
            # Extract semantic similarity
            semantic_similarity = doc_data.get('semantic_similarity', 0.0)
            context.semantic_similarity_scores[doc_id] = semantic_similarity
            
            # Extract temporal relationships
            creation_time_str = doc_data.get('creation_time')
            if creation_time_str:
                try:
                    creation_time = datetime.fromisoformat(creation_time_str)
                    reference_time = datetime.now(timezone.utc)  # Should be primary document time
                    proximity = abs((creation_time - reference_time).total_seconds())
                    context.creation_time_proximity[doc_id] = timedelta(seconds=proximity)
                except ValueError:
                    logger.warning(f"Invalid creation time: {creation_time_str}")
            
            # Extract source information
            source = doc_data.get('source')
            if source:
                context.common_sources.append(source)
                source_reliability = doc_data.get('source_reliability', 0.5)
                context.source_reliability_scores[source] = source_reliability
        
        # Calculate classification consistency
        if context.surrounding_classifications:
            classification_counts = {}
            for classification in context.surrounding_classifications:
                classification_counts[classification] = classification_counts.get(classification, 0) + 1
            
            most_common_count = max(classification_counts.values())
            context.classification_consistency = most_common_count / len(context.surrounding_classifications)
        
        # Deduplicate themes and entities
        context.content_themes = list(set(context.content_themes))
        context.shared_entities = list(set(context.shared_entities))
        
        # Calculate context quality
        context.confidence_score = self._calculate_surrounding_confidence(context)
        context.reliability = self._determine_surrounding_reliability(context)
        
        return context
    
    def _calculate_surrounding_confidence(self, context: SurroundingDataContext) -> float:
        """Calculate confidence score for surrounding data context."""
        confidence = 0.0
        
        # Base confidence from number of related documents
        document_factor = min(len(context.related_documents) / 10.0, 1.0)
        confidence += document_factor * 0.3
        
        # Confidence from classification consistency
        confidence += context.classification_consistency * 0.4
        
        # Confidence from similarity scores
        if context.document_similarities:
            avg_similarity = statistics.mean(context.document_similarities.values())
            confidence += avg_similarity * 0.3
        
        return min(1.0, confidence)
    
    def _determine_surrounding_reliability(self, context: SurroundingDataContext) -> ContextRelevance:
        """Determine reliability of surrounding data context."""
        if context.confidence_score >= 0.8 and context.classification_consistency >= 0.8:
            return ContextRelevance.HIGH
        elif context.confidence_score >= 0.6 and context.classification_consistency >= 0.6:
            return ContextRelevance.MEDIUM
        elif context.confidence_score >= 0.4:
            return ContextRelevance.LOW
        else:
            return ContextRelevance.IRRELEVANT


class ContextAwareProcessor:
    """
    Comprehensive context-aware processor that combines workflow, session,
    surrounding data, temporal, and environmental context for enhanced
    automated data labeling.
    """
    
    def __init__(
        self,
        audit_logger: Optional[AuditLogger] = None,
        config: Optional[Dict[str, Any]] = None
    ):
        """Initialize context-aware processor."""
        self.config = config or {}
        
        # Initialize component analyzers
        self.workflow_analyzer = WorkflowAnalyzer(config.get('workflow_config'))
        self.session_analyzer = SessionAnalyzer(config.get('session_config'))
        self.surrounding_analyzer = SurroundingDataAnalyzer(config.get('surrounding_config'))
        
        # Initialize audit logger
        self.audit_logger = audit_logger or AuditLogger()
        
        # Processing configuration
        self._context_weights = self.config.get('context_weights', {
            'workflow': 0.3,
            'session': 0.25,
            'surrounding': 0.25,
            'temporal': 0.1,
            'environmental': 0.1
        })
        
        logger.info("ContextAwareProcessor initialized")
    
    async def process_context(
        self,
        request_id: str,
        workflow_data: Optional[Dict[str, Any]] = None,
        session_data: Optional[Dict[str, Any]] = None,
        surrounding_data: Optional[List[Dict[str, Any]]] = None,
        temporal_data: Optional[Dict[str, Any]] = None,
        environmental_data: Optional[Dict[str, Any]] = None
    ) -> ContextProcessingResult:
        """
        Process comprehensive context information for automated labeling.
        
        Args:
            request_id: Unique identifier for the processing request
            workflow_data: Workflow context information
            session_data: User session context information
            surrounding_data: Surrounding data context information
            temporal_data: Temporal context information
            environmental_data: Environmental context information
            
        Returns:
            ContextProcessingResult with comprehensive context analysis
        """
        start_time = time.time()
        
        result = ContextProcessingResult(request_id=request_id)
        
        try:
            # Process different context types in parallel
            tasks = []
            
            if workflow_data:
                tasks.append(self._process_workflow_context(workflow_data))
            
            if session_data:
                tasks.append(self._process_session_context(session_data))
            
            if surrounding_data:
                tasks.append(self._process_surrounding_context(request_id, surrounding_data))
            
            if temporal_data:
                tasks.append(self._process_temporal_context(temporal_data))
            
            if environmental_data:
                tasks.append(self._process_environmental_context(environmental_data))
            
            # Execute all context analyses
            if tasks:
                context_results = await asyncio.gather(*tasks, return_exceptions=True)
                
                # Integrate results
                for i, context_result in enumerate(context_results):
                    if isinstance(context_result, Exception):
                        logger.error(f"Context analysis task {i} failed: {context_result}")
                    else:
                        self._integrate_context_result(result, context_result)
            
            # Determine context-influenced classification
            result = self._determine_context_classification(result)
            
            # Calculate quality metrics
            result.context_coverage = self._calculate_context_coverage(result)
            result.context_consistency = self._calculate_context_consistency(result)
            result.overall_risk_score = self._calculate_overall_risk(result)
            
            # Generate insights and recommendations
            result = self._generate_context_insights(result)
            
            # Calculate processing time
            result.processing_time_ms = (time.time() - start_time) * 1000
            
            # Log context processing
            await self._log_context_processing(result)
            
            logger.debug(f"Context processing complete for {request_id}: "
                        f"{result.context_influenced_classification} "
                        f"(confidence: {result.context_confidence_score:.2f}) "
                        f"in {result.processing_time_ms:.2f}ms")
            
        except Exception as e:
            logger.error(f"Context processing failed for {request_id}: {e}")
            result.context_influenced_classification = ClassificationLevel.UNCLASSIFIED
            result.context_confidence_score = 0.0
            result.recommendation_rationale = f"Context processing failed: {str(e)}"
            result.processing_time_ms = (time.time() - start_time) * 1000
        
        return result
    
    async def _process_workflow_context(self, workflow_data: Dict[str, Any]) -> WorkflowContext:
        """Process workflow context."""
        return self.workflow_analyzer.analyze_workflow_context(workflow_data)
    
    async def _process_session_context(self, session_data: Dict[str, Any]) -> UserSessionContext:
        """Process session context."""
        return self.session_analyzer.analyze_session_context(session_data)
    
    async def _process_surrounding_context(
        self, 
        request_id: str, 
        surrounding_data: List[Dict[str, Any]]
    ) -> SurroundingDataContext:
        """Process surrounding data context."""
        return await self.surrounding_analyzer.analyze_surrounding_data(request_id, surrounding_data)
    
    async def _process_temporal_context(self, temporal_data: Dict[str, Any]) -> TemporalContext:
        """Process temporal context."""
        context = TemporalContext(
            reference_time=datetime.fromisoformat(
                temporal_data.get('reference_time', datetime.now(timezone.utc).isoformat())
            )
        )
        
        # Extract time-based patterns
        context.time_of_day = temporal_data.get('time_of_day', '')
        context.day_of_week = temporal_data.get('day_of_week', '')
        context.business_hours = temporal_data.get('business_hours', True)
        
        # Extract historical patterns
        historical_data = temporal_data.get('historical_classifications', [])
        for hist_entry in historical_data:
            if isinstance(hist_entry, dict):
                timestamp = datetime.fromisoformat(hist_entry.get('timestamp'))
                classification = ClassificationLevel(hist_entry.get('classification'))
                context.historical_classifications.append((timestamp, classification))
        
        # Extract concurrent events
        context.concurrent_events = temporal_data.get('concurrent_events', [])
        context.related_incidents = temporal_data.get('related_incidents', [])
        
        # Set quality attributes
        context.confidence_score = 0.6  # Medium confidence for temporal context
        context.reliability = ContextRelevance.MEDIUM
        
        return context
    
    async def _process_environmental_context(self, environmental_data: Dict[str, Any]) -> EnvironmentalContext:
        """Process environmental context."""
        context = EnvironmentalContext()
        
        # Extract system environment
        context.system_state = environmental_data.get('system_state', {})
        context.system_load = environmental_data.get('system_load', 0.0)
        context.security_posture = environmental_data.get('security_posture', 'normal')
        
        # Extract network environment
        context.network_conditions = environmental_data.get('network_conditions', {})
        context.bandwidth_usage = environmental_data.get('bandwidth_usage', 0.0)
        context.network_security_level = environmental_data.get('network_security_level', 'standard')
        
        # Extract operational environment
        context.operational_tempo = environmental_data.get('operational_tempo', 'normal')
        context.threat_level = environmental_data.get('threat_level', 'low')
        context.mission_critical_operations = environmental_data.get('mission_critical_operations', False)
        
        # Extract geographic context
        context.geographic_location = environmental_data.get('geographic_location')
        context.time_zone = environmental_data.get('time_zone', 'UTC')
        
        # Set quality attributes
        context.confidence_score = 0.5  # Lower confidence for environmental context
        context.reliability = ContextRelevance.LOW
        
        return context
    
    def _integrate_context_result(self, result: ContextProcessingResult, context_result: Any):
        """Integrate individual context result into comprehensive result."""
        if isinstance(context_result, WorkflowContext):
            result.workflow_context = context_result
        elif isinstance(context_result, UserSessionContext):
            result.session_context = context_result
        elif isinstance(context_result, SurroundingDataContext):
            result.surrounding_context = context_result
        elif isinstance(context_result, TemporalContext):
            result.temporal_context = context_result
        elif isinstance(context_result, EnvironmentalContext):
            result.environmental_context = context_result
    
    def _determine_context_classification(self, result: ContextProcessingResult) -> ContextProcessingResult:
        """Determine context-influenced classification based on all context types."""
        classification_scores = defaultdict(float)
        confidence_contributions = []
        
        # Workflow context contribution
        if result.workflow_context and result.workflow_context.project_classification:
            classification = result.workflow_context.project_classification
            weight = self._context_weights.get('workflow', 0.3)
            reliability_factor = self._reliability_to_factor(result.workflow_context.reliability)
            
            classification_scores[classification] += weight * reliability_factor * result.workflow_context.confidence_score
            confidence_contributions.append(result.workflow_context.confidence_score * weight)
        
        # Session context contribution
        if result.session_context and result.session_context.user_clearance_level:
            classification = result.session_context.user_clearance_level
            weight = self._context_weights.get('session', 0.25)
            reliability_factor = self._reliability_to_factor(result.session_context.reliability)
            
            # Apply risk penalty
            risk_penalty = 1.0 - result.session_context.risk_score
            
            classification_scores[classification] += weight * reliability_factor * result.session_context.confidence_score * risk_penalty
            confidence_contributions.append(result.session_context.confidence_score * weight * risk_penalty)
        
        # Surrounding data context contribution
        if result.surrounding_context and result.surrounding_context.surrounding_classifications:
            # Use highest classification from surrounding data
            highest_classification = max(
                result.surrounding_context.surrounding_classifications,
                key=lambda x: x.value
            )
            
            weight = self._context_weights.get('surrounding', 0.25)
            reliability_factor = self._reliability_to_factor(result.surrounding_context.reliability)
            consistency_factor = result.surrounding_context.classification_consistency
            
            classification_scores[highest_classification] += weight * reliability_factor * result.surrounding_context.confidence_score * consistency_factor
            confidence_contributions.append(result.surrounding_context.confidence_score * weight * consistency_factor)
        
        # Determine final classification
        if classification_scores:
            result.context_influenced_classification = max(
                classification_scores.keys(),
                key=lambda x: classification_scores[x]
            )
        else:
            result.context_influenced_classification = ClassificationLevel.UNCLASSIFIED
        
        # Calculate combined confidence
        if confidence_contributions:
            result.context_confidence_score = sum(confidence_contributions) / len(confidence_contributions)
        else:
            result.context_confidence_score = 0.0
        
        # Calculate reliability score
        result.context_reliability_score = self._calculate_context_reliability(result)
        
        return result
    
    def _reliability_to_factor(self, reliability: ContextRelevance) -> float:
        """Convert reliability enum to numeric factor."""
        reliability_factors = {
            ContextRelevance.CRITICAL: 1.0,
            ContextRelevance.HIGH: 0.9,
            ContextRelevance.MEDIUM: 0.7,
            ContextRelevance.LOW: 0.5,
            ContextRelevance.IRRELEVANT: 0.1
        }
        return reliability_factors.get(reliability, 0.5)
    
    def _calculate_context_coverage(self, result: ContextProcessingResult) -> float:
        """Calculate percentage of available context that was processed."""
        available_contexts = 5  # workflow, session, surrounding, temporal, environmental
        processed_contexts = sum([
            1 if result.workflow_context else 0,
            1 if result.session_context else 0,
            1 if result.surrounding_context else 0,
            1 if result.temporal_context else 0,
            1 if result.environmental_context else 0
        ])
        
        return processed_contexts / available_contexts
    
    def _calculate_context_consistency(self, result: ContextProcessingResult) -> float:
        """Calculate consistency across different context types."""
        classifications = []
        
        if result.workflow_context and result.workflow_context.project_classification:
            classifications.append(result.workflow_context.project_classification)
        
        if result.session_context and result.session_context.user_clearance_level:
            classifications.append(result.session_context.user_clearance_level)
        
        if result.surrounding_context and result.surrounding_context.surrounding_classifications:
            # Use most common classification
            classification_counts = {}
            for classification in result.surrounding_context.surrounding_classifications:
                classification_counts[classification] = classification_counts.get(classification, 0) + 1
            
            most_common = max(classification_counts, key=classification_counts.get)
            classifications.append(most_common)
        
        if not classifications:
            return 0.0
        
        # Calculate consistency as ratio of most common classification
        classification_counts = {}
        for classification in classifications:
            classification_counts[classification] = classification_counts.get(classification, 0) + 1
        
        most_common_count = max(classification_counts.values())
        return most_common_count / len(classifications)
    
    def _calculate_context_reliability(self, result: ContextProcessingResult) -> float:
        """Calculate overall context reliability score."""
        reliability_scores = []
        
        if result.workflow_context:
            reliability_scores.append(self._reliability_to_factor(result.workflow_context.reliability))
        
        if result.session_context:
            reliability_scores.append(self._reliability_to_factor(result.session_context.reliability))
        
        if result.surrounding_context:
            reliability_scores.append(self._reliability_to_factor(result.surrounding_context.reliability))
        
        if result.temporal_context:
            reliability_scores.append(self._reliability_to_factor(result.temporal_context.reliability))
        
        if result.environmental_context:
            reliability_scores.append(self._reliability_to_factor(result.environmental_context.reliability))
        
        if reliability_scores:
            return sum(reliability_scores) / len(reliability_scores)
        else:
            return 0.0
    
    def _calculate_overall_risk(self, result: ContextProcessingResult) -> float:
        """Calculate overall risk score from all context sources."""
        risk_scores = []
        
        if result.session_context:
            risk_scores.append(result.session_context.risk_score)
        
        # Add other risk factors as needed
        # Environmental risks, temporal risks, etc.
        
        if risk_scores:
            return max(risk_scores)  # Use highest risk score
        else:
            return 0.0
    
    def _generate_context_insights(self, result: ContextProcessingResult) -> ContextProcessingResult:
        """Generate insights and recommendations based on context analysis."""
        key_factors = []
        anomalies = []
        rationale_parts = []
        
        # Workflow insights
        if result.workflow_context:
            if result.workflow_context.project_classification:
                key_factors.append(f"Workflow type: {result.workflow_context.workflow_type}")
                rationale_parts.append(f"Project classification: {result.workflow_context.project_classification.value}")
        
        # Session insights
        if result.session_context:
            if result.session_context.user_clearance_level:
                key_factors.append(f"User clearance: {result.session_context.user_clearance_level.value}")
            
            if result.session_context.anomalous_behavior:
                anomalies.append("Anomalous user behavior detected")
            
            if result.session_context.risk_score > 0.5:
                anomalies.extend(result.session_context.risk_factors)
        
        # Surrounding data insights
        if result.surrounding_context:
            if result.surrounding_context.classification_consistency > 0.8:
                key_factors.append(f"High classification consistency ({result.surrounding_context.classification_consistency:.2f})")
            elif result.surrounding_context.classification_consistency < 0.5:
                anomalies.append(f"Low classification consistency ({result.surrounding_context.classification_consistency:.2f})")
        
        # Environmental insights
        if result.environmental_context:
            if result.environmental_context.threat_level != 'low':
                key_factors.append(f"Elevated threat level: {result.environmental_context.threat_level}")
            
            if result.environmental_context.mission_critical_operations:
                key_factors.append("Mission critical operations active")
        
        result.key_context_factors = key_factors
        result.context_anomalies = anomalies
        
        # Build recommendation rationale
        if rationale_parts:
            result.recommendation_rationale = "Context-based recommendation: " + "; ".join(rationale_parts)
        else:
            result.recommendation_rationale = "Insufficient context for specific recommendations"
        
        return result
    
    async def _log_context_processing(self, result: ContextProcessingResult):
        """Log context processing for audit purposes."""
        await self.audit_logger.log_event({
            'event_type': 'context_processing_complete',
            'request_id': result.request_id,
            'context_influenced_classification': result.context_influenced_classification.value,
            'context_confidence_score': result.context_confidence_score,
            'context_reliability_score': result.context_reliability_score,
            'context_coverage': result.context_coverage,
            'context_consistency': result.context_consistency,
            'overall_risk_score': result.overall_risk_score,
            'processing_time_ms': result.processing_time_ms,
            'key_factors_count': len(result.key_context_factors),
            'anomalies_count': len(result.context_anomalies),
            'timestamp': result.processed_at.isoformat()
        })


# Example usage and testing
if __name__ == "__main__":
    import asyncio
    
    async def test_context_aware_processor():
        """Test the context-aware processor."""
        processor = ContextAwareProcessor()
        
        # Test data
        workflow_data = {
            'workflow_id': 'wf-001',
            'workflow_type': 'intelligence_analysis',
            'current_stage': 'analysis',
            'project_name': 'Project ALPHA',
            'project_classification': 'SECRET'
        }
        
        session_data = {
            'session_id': 'sess-001',
            'user_id': str(uuid4()),
            'user_clearance': 'SECRET',
            'network_domain': 'SIPR',
            'session_start': datetime.now(timezone.utc).isoformat(),
            'last_activity': datetime.now(timezone.utc).isoformat()
        }
        
        surrounding_data = [
            {
                'document_id': 'doc-001',
                'classification': 'SECRET',
                'similarity_score': 0.8,
                'semantic_similarity': 0.7
            },
            {
                'document_id': 'doc-002',
                'classification': 'CONFIDENTIAL',
                'similarity_score': 0.6,
                'semantic_similarity': 0.5
            }
        ]
        
        # Process context
        result = await processor.process_context(
            request_id='test-001',
            workflow_data=workflow_data,
            session_data=session_data,
            surrounding_data=surrounding_data
        )
        
        print(f"Context-influenced classification: {result.context_influenced_classification}")
        print(f"Context confidence: {result.context_confidence_score:.2f}")
        print(f"Context reliability: {result.context_reliability_score:.2f}")
        print(f"Context coverage: {result.context_coverage:.2f}")
        print(f"Context consistency: {result.context_consistency:.2f}")
        print(f"Overall risk score: {result.overall_risk_score:.2f}")
        print(f"Processing time: {result.processing_time_ms:.2f}ms")
        print(f"Key factors: {result.key_context_factors}")
        print(f"Anomalies: {result.context_anomalies}")
        print(f"Rationale: {result.recommendation_rationale}")
    
    # Run test
    asyncio.run(test_context_aware_processor())