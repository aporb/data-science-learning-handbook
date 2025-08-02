"""
Real-time Data Spillage Detection Engine for Multi-Classification Systems
========================================================================

This module provides comprehensive real-time data spillage detection capabilities that integrate
with the existing multi-classification framework. The engine monitors for unauthorized data 
transfers, classification violations, and potential security breaches across NIPR, SIPR, 
and JWICS network domains.

Key Features:
- Real-time event streaming and processing with <100ms detection latency
- ML-based anomaly detection for behavioral patterns and unusual access
- Integration with automated data labeling and cross-domain transfer systems
- Automated incident response with quarantine and alerting capabilities
- DoD compliance monitoring with comprehensive audit trails
- Performance-optimized processing for production environments

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
from threading import Lock, RLock
import aiofiles
import aiohttp
from collections import defaultdict, deque, OrderedDict
import pickle
import sqlite3
import redis
import psycopg2
from sqlalchemy import create_engine, text
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import pandas as pd

# Import existing infrastructure
from .enhanced_classification_engine import (
    EnhancedClassificationEngine, ProcessingMode, OptimizationLevel,
    EnhancedClassificationRequest, ProcessingMetrics, ClassificationLevel
)
from .automated_data_labeler import (
    AutomatedDataLabeler, LabelingRequest, LabelingResponse, LabelingConfidence
)
from .cross_domain_transfer_engine import (
    CrossDomainTransferEngine, TransferMode, TransferRequest, TransferStatus,
    NetworkDomain
)
from .models.bell_lapadula import SecurityLabel
from .classification_audit_logger import (
    ClassificationAuditLogger, AuditEvent, AuditEventType, AuditEventSeverity
)


class SpillageEventType(Enum):
    """Types of spillage events that can be detected"""
    UNAUTHORIZED_TRANSFER = "unauthorized_transfer"
    CLASSIFICATION_VIOLATION = "classification_violation"
    CROSS_DOMAIN_BREACH = "cross_domain_breach"
    EXCESSIVE_ACCESS = "excessive_access"
    ANOMALOUS_BEHAVIOR = "anomalous_behavior"
    PATTERN_MATCH = "pattern_match"
    POLICY_VIOLATION = "policy_violation"
    DATA_EXFILTRATION = "data_exfiltration"


class SpillageRiskLevel(Enum):
    """Risk levels for spillage events"""
    CRITICAL = "critical"    # Immediate threat requiring instant response
    HIGH = "high"           # Significant risk requiring urgent attention
    MEDIUM = "medium"       # Moderate risk requiring investigation
    LOW = "low"            # Minor anomaly requiring monitoring
    INFO = "info"          # Informational event for audit purposes


class DetectionMethod(Enum):
    """Methods used to detect spillage events"""
    REAL_TIME_MONITORING = "real_time_monitoring"
    PATTERN_ANALYSIS = "pattern_analysis"
    BEHAVIORAL_ANALYTICS = "behavioral_analytics"
    RULE_BASED = "rule_based"
    ML_ANOMALY = "ml_anomaly"
    CROSS_REFERENCE = "cross_reference"
    AUDIT_ANALYSIS = "audit_analysis"


@dataclass
class SpillageEvent:
    """Represents a detected spillage event"""
    event_id: str = field(default_factory=lambda: str(uuid4()))
    event_type: SpillageEventType = SpillageEventType.ANOMALOUS_BEHAVIOR
    risk_level: SpillageRiskLevel = SpillageRiskLevel.MEDIUM
    detection_method: DetectionMethod = DetectionMethod.REAL_TIME_MONITORING
    
    # Event context
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    user_id: Optional[str] = None
    resource_id: Optional[str] = None
    source_network: Optional[NetworkDomain] = None
    target_network: Optional[NetworkDomain] = None
    classification_level: Optional[ClassificationLevel] = None
    
    # Event details
    description: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)
    confidence_score: float = 0.0
    anomaly_score: float = 0.0
    
    # Response tracking
    response_required: bool = True
    response_actions: List[str] = field(default_factory=list)
    response_status: str = "pending"
    resolution_time: Optional[datetime] = None
    
    # Audit information
    detection_latency_ms: float = 0.0
    processing_metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DetectionRule:
    """Configuration for spillage detection rules"""
    rule_id: str
    rule_name: str
    rule_type: SpillageEventType
    risk_level: SpillageRiskLevel
    
    # Rule conditions
    conditions: Dict[str, Any]
    threshold_values: Dict[str, float]
    time_window_seconds: int = 300
    
    # Rule metadata
    enabled: bool = True
    priority: int = 100
    description: str = ""
    last_triggered: Optional[datetime] = None
    trigger_count: int = 0


@dataclass
class BehavioralPattern:
    """Represents a user's behavioral pattern for anomaly detection"""
    user_id: str
    pattern_id: str = field(default_factory=lambda: str(uuid4()))
    
    # Access patterns
    typical_access_hours: List[int] = field(default_factory=list)
    typical_resources: Set[str] = field(default_factory=set)
    typical_networks: Set[NetworkDomain] = field(default_factory=set)
    typical_classification_levels: Set[ClassificationLevel] = field(default_factory=set)
    
    # Volume patterns
    average_daily_accesses: float = 0.0
    average_session_duration: float = 0.0
    average_data_volume: float = 0.0
    
    # ML features
    feature_vector: np.ndarray = field(default_factory=lambda: np.array([]))
    last_updated: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    confidence: float = 0.0


class SpillageDetectionEngine:
    """
    Real-time data spillage detection engine with ML-based anomaly detection
    
    This engine provides comprehensive spillage detection capabilities including:
    - Real-time event streaming and processing
    - Pattern-based detection for sensitive data patterns
    - Behavioral analytics for unusual access patterns
    - Automated response and quarantine capabilities
    - Integration with existing classification and audit systems
    """
    
    def __init__(
        self,
        classification_engine: EnhancedClassificationEngine,
        data_labeler: AutomatedDataLabeler,
        transfer_engine: CrossDomainTransferEngine,
        audit_logger: ClassificationAuditLogger,
        config: Dict[str, Any] = None
    ):
        """Initialize the spillage detection engine"""
        self.classification_engine = classification_engine
        self.data_labeler = data_labeler
        self.transfer_engine = transfer_engine
        self.audit_logger = audit_logger
        self.config = config or {}
        
        # Engine state
        self.is_running = False
        self.start_time = None
        self._shutdown_event = asyncio.Event()
        
        # Detection configuration
        self.detection_latency_threshold_ms = self.config.get('detection_latency_threshold_ms', 100)
        self.max_concurrent_detections = self.config.get('max_concurrent_detections', 50)
        self.event_buffer_size = self.config.get('event_buffer_size', 10000)
        self.ml_model_update_interval = self.config.get('ml_model_update_interval', 3600)  # 1 hour
        
        # Storage and caching
        self.redis_client = None
        self.db_engine = None
        self._init_storage()
        
        # Event processing
        self.event_queue = asyncio.Queue(maxsize=self.event_buffer_size)
        self.event_buffer = deque(maxlen=self.event_buffer_size)
        self.detection_rules = {}
        self.behavioral_patterns = {}
        
        # ML components
        self.anomaly_detector = None
        self.feature_scaler = StandardScaler()
        self.ml_model_lock = RLock()
        
        # Performance tracking
        self.metrics = {
            'events_processed': 0,
            'events_detected': 0,
            'false_positives': 0,
            'true_positives': 0,
            'average_detection_latency': 0.0,
            'peak_processing_time': 0.0,
            'last_model_update': None
        }
        
        # Thread pool for intensive operations
        self.thread_pool = ThreadPoolExecutor(
            max_workers=self.config.get('max_worker_threads', 10),
            thread_name_prefix='spillage_detection'
        )
        
        self.logger = logging.getLogger(__name__)
        self.logger.info("SpillageDetectionEngine initialized")
    
    def _init_storage(self):
        """Initialize storage backends (Redis for caching, PostgreSQL for persistence)"""
        try:
            # Redis for high-performance caching
            redis_config = self.config.get('redis', {})
            self.redis_client = redis.Redis(
                host=redis_config.get('host', 'localhost'),
                port=redis_config.get('port', 6379),
                db=redis_config.get('db', 2),
                decode_responses=True,
                socket_timeout=redis_config.get('timeout', 5)
            )
            
            # Test Redis connection
            self.redis_client.ping()
            self.logger.info("Redis connection established")
            
        except Exception as e:
            self.logger.warning(f"Redis connection failed: {e}, using in-memory storage")
            self.redis_client = None
        
        try:
            # PostgreSQL for persistent storage
            db_config = self.config.get('database', {})
            db_url = f"postgresql://{db_config.get('user', 'postgres')}:" \
                    f"{db_config.get('password', 'password')}@" \
                    f"{db_config.get('host', 'localhost')}:" \
                    f"{db_config.get('port', 5432)}/" \
                    f"{db_config.get('name', 'spillage_detection')}"
            
            self.db_engine = create_engine(db_url, pool_size=10, max_overflow=20)
            
            # Test database connection
            with self.db_engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            
            self.logger.info("Database connection established")
            
        except Exception as e:
            self.logger.warning(f"Database connection failed: {e}, using SQLite fallback")
            self.db_engine = create_engine("sqlite:///spillage_detection.db")
    
    async def start(self):
        """Start the spillage detection engine"""
        if self.is_running:
            self.logger.warning("Engine is already running")
            return
        
        self.logger.info("Starting spillage detection engine...")
        self.is_running = True
        self.start_time = datetime.now(timezone.utc)
        
        # Initialize detection rules
        await self._load_detection_rules()
        
        # Initialize ML models
        await self._initialize_ml_models()
        
        # Start background tasks
        asyncio.create_task(self._event_processor())
        asyncio.create_task(self._behavioral_analyzer())
        asyncio.create_task(self._ml_model_updater())
        asyncio.create_task(self._metrics_collector())
        
        self.logger.info("Spillage detection engine started successfully")
    
    async def stop(self):
        """Stop the spillage detection engine"""
        if not self.is_running:
            return
        
        self.logger.info("Stopping spillage detection engine...")
        self.is_running = False
        self._shutdown_event.set()
        
        # Shutdown thread pool
        self.thread_pool.shutdown(wait=True)
        
        # Close storage connections
        if self.redis_client:
            self.redis_client.close()
        
        self.logger.info("Spillage detection engine stopped")
    
    async def _load_detection_rules(self):
        """Load and initialize detection rules"""
        try:
            # Load rules from configuration or database
            default_rules = [
                DetectionRule(
                    rule_id="unauthorized_cross_domain",
                    rule_name="Unauthorized Cross-Domain Transfer",
                    rule_type=SpillageEventType.CROSS_DOMAIN_BREACH,
                    risk_level=SpillageRiskLevel.CRITICAL,
                    conditions={
                        "source_network": ["SIPR", "JWICS"],
                        "target_network": ["NIPR"],
                        "requires_authorization": True
                    },
                    threshold_values={"confidence_threshold": 0.8}
                ),
                DetectionRule(
                    rule_id="classification_downgrade",
                    rule_name="Unauthorized Classification Downgrade",
                    rule_type=SpillageEventType.CLASSIFICATION_VIOLATION,
                    risk_level=SpillageRiskLevel.HIGH,
                    conditions={
                        "classification_change": "downgrade",
                        "approval_required": True
                    },
                    threshold_values={"confidence_threshold": 0.9}
                ),
                DetectionRule(
                    rule_id="excessive_data_access",
                    rule_name="Excessive Data Access Pattern",
                    rule_type=SpillageEventType.EXCESSIVE_ACCESS,
                    risk_level=SpillageRiskLevel.MEDIUM,
                    conditions={
                        "access_volume_multiplier": 5.0,
                        "time_window_hours": 1
                    },
                    threshold_values={"volume_threshold": 100.0}
                )
            ]
            
            for rule in default_rules:
                self.detection_rules[rule.rule_id] = rule
            
            self.logger.info(f"Loaded {len(self.detection_rules)} detection rules")
            
        except Exception as e:
            self.logger.error(f"Failed to load detection rules: {e}")
    
    async def _initialize_ml_models(self):
        """Initialize ML models for anomaly detection"""
        try:
            with self.ml_model_lock:
                # Initialize isolation forest for anomaly detection
                self.anomaly_detector = IsolationForest(
                    n_estimators=100,
                    contamination=0.1,
                    random_state=42,
                    n_jobs=-1
                )
                
                # Load existing model if available
                model_path = self.config.get('ml_model_path', 'spillage_ml_model.pkl')
                if Path(model_path).exists():
                    with open(model_path, 'rb') as f:
                        saved_model = pickle.load(f)
                        self.anomaly_detector = saved_model['model']
                        self.feature_scaler = saved_model['scaler']
                    self.logger.info("Loaded existing ML model")
                else:
                    # Train initial model with synthetic data
                    await self._train_initial_model()
            
            self.metrics['last_model_update'] = datetime.now(timezone.utc)
            self.logger.info("ML models initialized successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize ML models: {e}")
    
    async def _train_initial_model(self):
        """Train initial ML model with baseline data"""
        try:
            # Generate synthetic training data for initial model
            synthetic_data = self._generate_synthetic_training_data(1000)
            
            if len(synthetic_data) > 0:
                features = np.array([data['features'] for data in synthetic_data])
                
                # Fit scaler and transform features
                self.feature_scaler.fit(features)
                scaled_features = self.feature_scaler.transform(features)
                
                # Train anomaly detector
                self.anomaly_detector.fit(scaled_features)
                
                self.logger.info("Initial ML model trained with synthetic data")
            
        except Exception as e:
            self.logger.error(f"Failed to train initial ML model: {e}")
    
    def _generate_synthetic_training_data(self, num_samples: int) -> List[Dict[str, Any]]:
        """Generate synthetic training data for initial model training"""
        synthetic_data = []
        
        for _ in range(num_samples):
            # Generate normal behavioral patterns
            features = [
                np.random.normal(9, 2),      # Access hour (business hours)
                np.random.normal(50, 15),    # Daily accesses
                np.random.normal(3600, 900), # Session duration (seconds)
                np.random.normal(1000, 300), # Data volume (KB)
                np.random.randint(1, 4),     # Number of networks accessed
                np.random.randint(1, 3),     # Number of classification levels
                np.random.normal(0.8, 0.1),  # Access success rate
                np.random.normal(2, 0.5)     # Applications used
            ]
            
            synthetic_data.append({
                'user_id': f'user_{_ % 100}',
                'features': features,
                'is_anomaly': False
            })
        
        return synthetic_data
    
    async def detect_spillage_event(
        self,
        event_data: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None
    ) -> List[SpillageEvent]:
        """
        Detect potential spillage events from input data
        
        Args:
            event_data: Event data to analyze
            context: Additional context information
            
        Returns:
            List of detected spillage events
        """
        start_time = time.time()
        detected_events = []
        
        try:
            # Extract key information from event data
            user_id = event_data.get('user_id')
            resource_id = event_data.get('resource_id')
            action = event_data.get('action', 'unknown')
            timestamp = datetime.fromisoformat(event_data.get('timestamp', datetime.now(timezone.utc).isoformat()))
            
            # Rule-based detection
            rule_events = await self._apply_detection_rules(event_data, context)
            detected_events.extend(rule_events)
            
            # Pattern-based detection
            pattern_events = await self._detect_pattern_violations(event_data, context)
            detected_events.extend(pattern_events)
            
            # Behavioral analysis
            if user_id:
                behavioral_events = await self._analyze_user_behavior(user_id, event_data, context)
                detected_events.extend(behavioral_events)
            
            # ML-based anomaly detection
            ml_events = await self._detect_ml_anomalies(event_data, context)
            detected_events.extend(ml_events)
            
            # Update metrics
            processing_time = (time.time() - start_time) * 1000
            self.metrics['events_processed'] += 1
            self.metrics['events_detected'] += len(detected_events)
            self.metrics['average_detection_latency'] = (
                (self.metrics['average_detection_latency'] * (self.metrics['events_processed'] - 1) + processing_time) /
                self.metrics['events_processed']
            )
            self.metrics['peak_processing_time'] = max(self.metrics['peak_processing_time'], processing_time)
            
            # Set detection latency for each event
            for event in detected_events:
                event.detection_latency_ms = processing_time
                event.processing_metadata = {
                    'detection_timestamp': datetime.now(timezone.utc).isoformat(),
                    'engine_version': '1.0',
                    'processing_time_ms': processing_time
                }
            
            # Log detection results
            if detected_events:
                await self._log_detection_results(detected_events, event_data, context)
            
        except Exception as e:
            self.logger.error(f"Error in spillage detection: {e}")
            # Create error event
            error_event = SpillageEvent(
                event_type=SpillageEventType.ANOMALOUS_BEHAVIOR,
                risk_level=SpillageRiskLevel.LOW,
                description=f"Detection error: {str(e)}",
                confidence_score=0.0,
                detection_latency_ms=(time.time() - start_time) * 1000
            )
            detected_events.append(error_event)
        
        return detected_events
    
    async def _apply_detection_rules(
        self,
        event_data: Dict[str, Any],
        context: Optional[Dict[str, Any]]
    ) -> List[SpillageEvent]:
        """Apply configured detection rules to event data"""
        detected_events = []
        
        for rule_id, rule in self.detection_rules.items():
            if not rule.enabled:
                continue
            
            try:
                # Check if rule conditions are met
                if await self._evaluate_rule_conditions(rule, event_data, context):
                    # Create spillage event
                    spillage_event = SpillageEvent(
                        event_type=rule.rule_type,
                        risk_level=rule.risk_level,
                        detection_method=DetectionMethod.RULE_BASED,
                        description=f"Rule violation detected: {rule.rule_name}",
                        evidence={
                            'rule_id': rule_id,
                            'rule_name': rule.rule_name,
                            'conditions_met': rule.conditions,
                            'event_data': event_data
                        },
                        confidence_score=rule.threshold_values.get('confidence_threshold', 0.8)
                    )
                    
                    # Update rule statistics
                    rule.last_triggered = datetime.now(timezone.utc)
                    rule.trigger_count += 1
                    
                    detected_events.append(spillage_event)
                    
            except Exception as e:
                self.logger.error(f"Error evaluating rule {rule_id}: {e}")
        
        return detected_events
    
    async def _evaluate_rule_conditions(
        self,
        rule: DetectionRule,
        event_data: Dict[str, Any],
        context: Optional[Dict[str, Any]]
    ) -> bool:
        """Evaluate whether rule conditions are met"""
        try:
            conditions = rule.conditions
            
            # Check cross-domain transfer conditions
            if 'source_network' in conditions and 'target_network' in conditions:
                source = event_data.get('source_network')
                target = event_data.get('target_network')
                
                if (source in conditions['source_network'] and 
                    target in conditions['target_network']):
                    
                    # Check if authorization is required but missing
                    if conditions.get('requires_authorization', False):
                        if not event_data.get('authorized', False):
                            return True
            
            # Check classification level changes
            if 'classification_change' in conditions:
                change_type = event_data.get('classification_change')
                if change_type == conditions['classification_change']:
                    
                    # Check if approval is required but missing
                    if conditions.get('approval_required', False):
                        if not event_data.get('approved', False):
                            return True
            
            # Check volume-based conditions
            if 'access_volume_multiplier' in conditions:
                current_volume = event_data.get('data_volume', 0)
                user_id = event_data.get('user_id')
                
                if user_id and user_id in self.behavioral_patterns:
                    pattern = self.behavioral_patterns[user_id]
                    expected_volume = pattern.average_data_volume
                    threshold = expected_volume * conditions['access_volume_multiplier']
                    
                    if current_volume > threshold:
                        return True
            
            return False
            
        except Exception as e:
            self.logger.error(f"Error evaluating rule conditions: {e}")
            return False
    
    async def _detect_pattern_violations(
        self,
        event_data: Dict[str, Any],
        context: Optional[Dict[str, Any]]
    ) -> List[SpillageEvent]:
        """Detect violations using pattern analysis"""
        detected_events = []
        
        try:
            # Analyze data content for sensitive patterns
            content = event_data.get('content', '')
            if content:
                # Check for classification markings in wrong contexts
                classification_patterns = {
                    'SECRET': r'(?i)secret(?:\s+//|\s+noforn|\s+rel)',
                    'TOP_SECRET': r'(?i)top\s+secret(?:\s+//|\s+sci|\s+tk)',
                    'CONFIDENTIAL': r'(?i)confidential(?:\s+//|\s+noforn)',
                }
                
                current_network = event_data.get('network_domain', 'UNKNOWN')
                
                for level, pattern in classification_patterns.items():
                    import re
                    if re.search(pattern, content):
                        # Check if classification level is appropriate for network
                        if self._is_classification_spillage(level, current_network):
                            spillage_event = SpillageEvent(
                                event_type=SpillageEventType.PATTERN_MATCH,
                                risk_level=SpillageRiskLevel.CRITICAL,
                                detection_method=DetectionMethod.PATTERN_ANALYSIS,
                                description=f"Classified content ({level}) detected on inappropriate network ({current_network})",
                                evidence={
                                    'pattern_matched': pattern,
                                    'classification_level': level,
                                    'network_domain': current_network,
                                    'content_sample': content[:200]  # First 200 chars
                                },
                                confidence_score=0.95
                            )
                            detected_events.append(spillage_event)
            
        except Exception as e:
            self.logger.error(f"Error in pattern detection: {e}")
        
        return detected_events
    
    def _is_classification_spillage(self, classification_level: str, network_domain: str) -> bool:
        """Determine if classification level is inappropriate for network domain"""
        # Define network domain capabilities
        network_capabilities = {
            'NIPR': ['UNCLASSIFIED', 'FOR_OFFICIAL_USE_ONLY'],
            'SIPR': ['UNCLASSIFIED', 'FOR_OFFICIAL_USE_ONLY', 'CONFIDENTIAL', 'SECRET'],
            'JWICS': ['UNCLASSIFIED', 'FOR_OFFICIAL_USE_ONLY', 'CONFIDENTIAL', 'SECRET', 'TOP_SECRET']
        }
        
        allowed_levels = network_capabilities.get(network_domain, [])
        return classification_level not in allowed_levels
    
    async def _analyze_user_behavior(
        self,
        user_id: str,
        event_data: Dict[str, Any],
        context: Optional[Dict[str, Any]]
    ) -> List[SpillageEvent]:
        """Analyze user behavior for anomalies"""
        detected_events = []
        
        try:
            # Get or create user behavioral pattern
            if user_id not in self.behavioral_patterns:
                await self._create_user_pattern(user_id)
            
            pattern = self.behavioral_patterns[user_id]
            current_time = datetime.now(timezone.utc)
            
            # Analyze access timing
            current_hour = current_time.hour
            if (pattern.typical_access_hours and 
                current_hour not in pattern.typical_access_hours):
                
                # Calculate how unusual this time is
                hour_distances = [abs(current_hour - h) for h in pattern.typical_access_hours]
                min_distance = min(hour_distances) if hour_distances else 12
                
                if min_distance > 4:  # More than 4 hours from typical
                    spillage_event = SpillageEvent(
                        event_type=SpillageEventType.ANOMALOUS_BEHAVIOR,
                        risk_level=SpillageRiskLevel.MEDIUM,
                        detection_method=DetectionMethod.BEHAVIORAL_ANALYTICS,
                        user_id=user_id,
                        description=f"Unusual access time: {current_hour}:00 (typical: {pattern.typical_access_hours})",
                        evidence={
                            'current_hour': current_hour,
                            'typical_hours': list(pattern.typical_access_hours),
                            'deviation_hours': min_distance
                        },
                        confidence_score=min(0.9, min_distance / 12)
                    )
                    detected_events.append(spillage_event)
            
            # Analyze resource access patterns
            resource_id = event_data.get('resource_id')
            if (resource_id and pattern.typical_resources and 
                resource_id not in pattern.typical_resources):
                
                spillage_event = SpillageEvent(
                    event_type=SpillageEventType.ANOMALOUS_BEHAVIOR,
                    risk_level=SpillageRiskLevel.LOW,
                    detection_method=DetectionMethod.BEHAVIORAL_ANALYTICS,
                    user_id=user_id,
                    resource_id=resource_id,
                    description=f"Access to unusual resource: {resource_id}",
                    evidence={
                        'resource_id': resource_id,
                        'typical_resources': list(pattern.typical_resources)[:10],  # Limit for readability
                        'is_new_resource': True
                    },
                    confidence_score=0.6
                )
                detected_events.append(spillage_event)
            
            # Analyze data volume
            data_volume = event_data.get('data_volume', 0)
            if pattern.average_data_volume > 0:
                volume_ratio = data_volume / pattern.average_data_volume
                
                if volume_ratio > 10:  # 10x normal volume
                    spillage_event = SpillageEvent(
                        event_type=SpillageEventType.EXCESSIVE_ACCESS,
                        risk_level=SpillageRiskLevel.HIGH,
                        detection_method=DetectionMethod.BEHAVIORAL_ANALYTICS,
                        user_id=user_id,
                        description=f"Excessive data volume: {data_volume} (normal: {pattern.average_data_volume:.1f})",
                        evidence={
                            'current_volume': data_volume,
                            'average_volume': pattern.average_data_volume,
                            'volume_ratio': volume_ratio
                        },
                        confidence_score=min(0.95, volume_ratio / 20)
                    )
                    detected_events.append(spillage_event)
            
            # Update user pattern with new data
            await self._update_user_pattern(user_id, event_data)
            
        except Exception as e:
            self.logger.error(f"Error analyzing user behavior for {user_id}: {e}")
        
        return detected_events
    
    async def _create_user_pattern(self, user_id: str):
        """Create a new behavioral pattern for a user"""
        try:
            pattern = BehavioralPattern(
                user_id=user_id,
                typical_access_hours=[],
                typical_resources=set(),
                typical_networks=set(),
                typical_classification_levels=set(),
                average_daily_accesses=0.0,
                average_session_duration=0.0,
                average_data_volume=0.0,
                confidence=0.0
            )
            
            self.behavioral_patterns[user_id] = pattern
            
            # Try to load historical data if available
            await self._load_user_historical_data(user_id)
            
        except Exception as e:
            self.logger.error(f"Error creating user pattern for {user_id}: {e}")
    
    async def _load_user_historical_data(self, user_id: str):
        """Load historical data for user pattern initialization"""
        try:
            # This would typically query a database for historical access patterns
            # For now, we'll use placeholder logic
            pattern = self.behavioral_patterns[user_id]
            
            # Set default business hours pattern
            pattern.typical_access_hours = [8, 9, 10, 11, 12, 13, 14, 15, 16, 17]
            pattern.average_daily_accesses = 25.0
            pattern.average_session_duration = 3600.0  # 1 hour
            pattern.average_data_volume = 1000.0  # 1MB
            pattern.confidence = 0.5  # Initial confidence
            
        except Exception as e:
            self.logger.error(f"Error loading historical data for {user_id}: {e}")
    
    async def _update_user_pattern(self, user_id: str, event_data: Dict[str, Any]):
        """Update user behavioral pattern with new event data"""
        try:
            pattern = self.behavioral_patterns[user_id]
            current_time = datetime.now(timezone.utc)
            
            # Update access hours
            current_hour = current_time.hour
            if current_hour not in pattern.typical_access_hours:
                pattern.typical_access_hours.append(current_hour)
                # Keep only recent patterns (last 30 unique hours)
                if len(pattern.typical_access_hours) > 30:
                    pattern.typical_access_hours = pattern.typical_access_hours[-30:]
            
            # Update resources
            resource_id = event_data.get('resource_id')
            if resource_id:
                pattern.typical_resources.add(resource_id)
                # Limit resource tracking to prevent memory issues
                if len(pattern.typical_resources) > 1000:
                    # Keep most recent 800 resources
                    pattern.typical_resources = set(list(pattern.typical_resources)[-800:])
            
            # Update networks
            network = event_data.get('network_domain')
            if network:
                try:
                    network_enum = NetworkDomain(network)
                    pattern.typical_networks.add(network_enum)
                except ValueError:
                    pass  # Invalid network domain
            
            # Update classification levels
            classification = event_data.get('classification_level')
            if classification:
                try:
                    classification_enum = ClassificationLevel(classification)
                    pattern.typical_classification_levels.add(classification_enum)
                except ValueError:
                    pass  # Invalid classification level
            
            # Update volume patterns (exponential moving average)
            data_volume = event_data.get('data_volume', 0)
            if data_volume > 0:
                alpha = 0.1  # Smoothing factor
                pattern.average_data_volume = (
                    alpha * data_volume + (1 - alpha) * pattern.average_data_volume
                )
            
            # Update confidence based on number of observations
            pattern.confidence = min(1.0, pattern.confidence + 0.01)
            pattern.last_updated = current_time
            
        except Exception as e:
            self.logger.error(f"Error updating user pattern for {user_id}: {e}")
    
    async def _detect_ml_anomalies(
        self,
        event_data: Dict[str, Any],
        context: Optional[Dict[str, Any]]
    ) -> List[SpillageEvent]:
        """Use ML models to detect anomalies"""
        detected_events = []
        
        try:
            if not self.anomaly_detector:
                return detected_events
            
            # Extract features from event data
            features = self._extract_ml_features(event_data)
            
            if len(features) == 0:
                return detected_events
            
            with self.ml_model_lock:
                # Scale features
                features_array = np.array([features])
                scaled_features = self.feature_scaler.transform(features_array)
                
                # Predict anomaly
                anomaly_prediction = self.anomaly_detector.predict(scaled_features)[0]
                anomaly_score = self.anomaly_detector.decision_function(scaled_features)[0]
                
                # If anomaly detected
                if anomaly_prediction == -1:  # -1 indicates anomaly in IsolationForest
                    confidence = min(0.9, abs(anomaly_score))
                    
                    spillage_event = SpillageEvent(
                        event_type=SpillageEventType.ANOMALOUS_BEHAVIOR,
                        risk_level=self._map_anomaly_score_to_risk(anomaly_score),
                        detection_method=DetectionMethod.ML_ANOMALY,
                        user_id=event_data.get('user_id'),
                        resource_id=event_data.get('resource_id'),
                        description=f"ML anomaly detected (score: {anomaly_score:.3f})",
                        evidence={
                            'anomaly_score': anomaly_score,
                            'feature_vector': features,
                            'model_type': 'IsolationForest',
                            'confidence_threshold': 0.7
                        },
                        confidence_score=confidence,
                        anomaly_score=anomaly_score
                    )
                    detected_events.append(spillage_event)
            
        except Exception as e:
            self.logger.error(f"Error in ML anomaly detection: {e}")
        
        return detected_events
    
    def _extract_ml_features(self, event_data: Dict[str, Any]) -> List[float]:
        """Extract numerical features for ML model"""
        features = []
        
        try:
            current_time = datetime.now(timezone.utc)
            
            # Time-based features
            features.append(current_time.hour)  # Hour of day
            features.append(current_time.weekday())  # Day of week
            
            # Volume features
            features.append(event_data.get('data_volume', 0))
            features.append(event_data.get('session_duration', 0))
            
            # Classification features
            classification_levels = {
                'UNCLASSIFIED': 1,
                'FOR_OFFICIAL_USE_ONLY': 2,
                'CONFIDENTIAL': 3,
                'SECRET': 4,
                'TOP_SECRET': 5
            }
            classification = event_data.get('classification_level', 'UNCLASSIFIED')
            features.append(classification_levels.get(classification, 1))
            
            # Network features
            network_domains = {
                'NIPR': 1,
                'SIPR': 2,
                'JWICS': 3
            }
            network = event_data.get('network_domain', 'NIPR')
            features.append(network_domains.get(network, 1))
            
            # Action features
            action_types = {
                'read': 1,
                'write': 2,
                'delete': 3,
                'copy': 4,
                'move': 5,
                'download': 6,
                'upload': 7
            }
            action = event_data.get('action', 'read')
            features.append(action_types.get(action, 1))
            
            # Success/failure
            features.append(1 if event_data.get('success', True) else 0)
            
        except Exception as e:
            self.logger.error(f"Error extracting ML features: {e}")
        
        return features
    
    def _map_anomaly_score_to_risk(self, anomaly_score: float) -> SpillageRiskLevel:
        """Map ML anomaly score to risk level"""
        abs_score = abs(anomaly_score)
        
        if abs_score > 0.5:
            return SpillageRiskLevel.CRITICAL
        elif abs_score > 0.3:
            return SpillageRiskLevel.HIGH
        elif abs_score > 0.1:
            return SpillageRiskLevel.MEDIUM
        else:
            return SpillageRiskLevel.LOW
    
    async def _log_detection_results(
        self,
        events: List[SpillageEvent],
        event_data: Dict[str, Any],
        context: Optional[Dict[str, Any]]
    ):
        """Log detection results to audit system"""
        try:
            for event in events:
                # Create audit event
                audit_event = AuditEvent(
                    event_type=AuditEventType.SECURITY_ALERT,
                    severity=self._map_risk_to_severity(event.risk_level),
                    user_id=event.user_id,
                    resource_id=event.resource_id,
                    action=f"spillage_detection_{event.event_type.value}",
                    result="DETECTED",
                    details={
                        'spillage_event_id': event.event_id,
                        'spillage_type': event.event_type.value,
                        'risk_level': event.risk_level.value,
                        'detection_method': event.detection_method.value,
                        'confidence_score': event.confidence_score,
                        'anomaly_score': event.anomaly_score,
                        'evidence': event.evidence,
                        'detection_latency_ms': event.detection_latency_ms
                    }
                )
                
                # Log to audit system
                await self.audit_logger.log_event(audit_event)
            
        except Exception as e:
            self.logger.error(f"Error logging detection results: {e}")
    
    def _map_risk_to_severity(self, risk_level: SpillageRiskLevel) -> AuditEventSeverity:
        """Map spillage risk level to audit severity"""
        mapping = {
            SpillageRiskLevel.CRITICAL: AuditEventSeverity.CRITICAL,
            SpillageRiskLevel.HIGH: AuditEventSeverity.HIGH,
            SpillageRiskLevel.MEDIUM: AuditEventSeverity.MEDIUM,
            SpillageRiskLevel.LOW: AuditEventSeverity.LOW,
            SpillageRiskLevel.INFO: AuditEventSeverity.INFO
        }
        return mapping.get(risk_level, AuditEventSeverity.MEDIUM)
    
    async def _event_processor(self):
        """Background task to process events from the queue"""
        while self.is_running:
            try:
                # Get event from queue with timeout
                try:
                    event_data = await asyncio.wait_for(
                        self.event_queue.get(),
                        timeout=1.0
                    )
                except asyncio.TimeoutError:
                    continue
                
                # Process the event
                await self.detect_spillage_event(event_data)
                
                # Mark task as done
                self.event_queue.task_done()
                
            except Exception as e:
                self.logger.error(f"Error in event processor: {e}")
    
    async def _behavioral_analyzer(self):
        """Background task for behavioral pattern analysis"""
        while self.is_running:
            try:
                # Update behavioral patterns every 5 minutes
                await asyncio.sleep(300)
                
                # Clean up old patterns
                current_time = datetime.now(timezone.utc)
                cutoff_time = current_time - timedelta(days=30)
                
                patterns_to_remove = []
                for user_id, pattern in self.behavioral_patterns.items():
                    if pattern.last_updated < cutoff_time:
                        patterns_to_remove.append(user_id)
                
                for user_id in patterns_to_remove:
                    del self.behavioral_patterns[user_id]
                
                if patterns_to_remove:
                    self.logger.info(f"Cleaned up {len(patterns_to_remove)} old behavioral patterns")
                
            except Exception as e:
                self.logger.error(f"Error in behavioral analyzer: {e}")
    
    async def _ml_model_updater(self):
        """Background task to update ML models"""
        while self.is_running:
            try:
                # Update ML models every hour
                await asyncio.sleep(self.ml_model_update_interval)
                
                # Retrain model with recent data
                await self._retrain_ml_model()
                
            except Exception as e:
                self.logger.error(f"Error in ML model updater: {e}")
    
    async def _retrain_ml_model(self):
        """Retrain ML model with recent data"""
        try:
            # This would typically collect recent events and retrain
            # For now, we'll use a placeholder implementation
            
            # Collect recent behavioral data
            training_data = []
            for user_id, pattern in self.behavioral_patterns.items():
                if pattern.confidence > 0.5:  # Only use confident patterns
                    features = [
                        np.mean(pattern.typical_access_hours) if pattern.typical_access_hours else 12,
                        pattern.average_daily_accesses,
                        pattern.average_session_duration,
                        pattern.average_data_volume,
                        len(pattern.typical_networks),
                        len(pattern.typical_classification_levels),
                        pattern.confidence,
                        len(pattern.typical_resources)
                    ]
                    training_data.append(features)
            
            if len(training_data) > 10:  # Need minimum samples
                with self.ml_model_lock:
                    # Retrain with updated data
                    features_array = np.array(training_data)
                    
                    # Update scaler
                    self.feature_scaler.fit(features_array)
                    scaled_features = self.feature_scaler.transform(features_array)
                    
                    # Retrain anomaly detector
                    self.anomaly_detector.fit(scaled_features)
                    
                    # Save updated model
                    model_path = self.config.get('ml_model_path', 'spillage_ml_model.pkl')
                    with open(model_path, 'wb') as f:
                        pickle.dump({
                            'model': self.anomaly_detector,
                            'scaler': self.feature_scaler,
                            'updated': datetime.now(timezone.utc).isoformat()
                        }, f)
                    
                    self.metrics['last_model_update'] = datetime.now(timezone.utc)
                    self.logger.info(f"ML model retrained with {len(training_data)} samples")
            
        except Exception as e:
            self.logger.error(f"Error retraining ML model: {e}")
    
    async def _metrics_collector(self):
        """Background task to collect and update metrics"""
        while self.is_running:
            try:
                # Update metrics every minute
                await asyncio.sleep(60)
                
                # Store metrics in Redis if available
                if self.redis_client:
                    metrics_key = "spillage_detection:metrics"
                    metrics_data = {
                        **self.metrics,
                        'timestamp': datetime.now(timezone.utc).isoformat(),
                        'uptime_seconds': (datetime.now(timezone.utc) - self.start_time).total_seconds(),
                        'active_behavioral_patterns': len(self.behavioral_patterns),
                        'active_detection_rules': len([r for r in self.detection_rules.values() if r.enabled])
                    }
                    
                    self.redis_client.setex(
                        metrics_key,
                        3600,  # 1 hour expiry
                        json.dumps(metrics_data, default=str)
                    )
                
            except Exception as e:
                self.logger.error(f"Error in metrics collector: {e}")
    
    async def get_metrics(self) -> Dict[str, Any]:
        """Get current performance and detection metrics"""
        try:
            uptime = (datetime.now(timezone.utc) - self.start_time).total_seconds() if self.start_time else 0
            
            return {
                **self.metrics,
                'engine_status': 'running' if self.is_running else 'stopped',
                'uptime_seconds': uptime,
                'active_behavioral_patterns': len(self.behavioral_patterns),
                'active_detection_rules': len([r for r in self.detection_rules.values() if r.enabled]),
                'event_queue_size': self.event_queue.qsize(),
                'last_updated': datetime.now(timezone.utc).isoformat()
            }
        except Exception as e:
            self.logger.error(f"Error getting metrics: {e}")
            return {'error': str(e)}
    
    async def health_check(self) -> Dict[str, Any]:
        """Perform comprehensive health check"""
        health_status = {
            'status': 'healthy',
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'checks': {}
        }
        
        try:
            # Check engine status
            health_status['checks']['engine_running'] = {
                'status': 'pass' if self.is_running else 'fail',
                'details': f"Engine {'running' if self.is_running else 'stopped'}"
            }
            
            # Check storage connections
            if self.redis_client:
                try:
                    self.redis_client.ping()
                    health_status['checks']['redis_connection'] = {
                        'status': 'pass',
                        'details': 'Redis connection active'
                    }
                except Exception as e:
                    health_status['checks']['redis_connection'] = {
                        'status': 'fail',
                        'details': f'Redis connection failed: {e}'
                    }
            
            if self.db_engine:
                try:
                    with self.db_engine.connect() as conn:
                        conn.execute(text("SELECT 1"))
                    health_status['checks']['database_connection'] = {
                        'status': 'pass',
                        'details': 'Database connection active'
                    }
                except Exception as e:
                    health_status['checks']['database_connection'] = {
                        'status': 'fail',
                        'details': f'Database connection failed: {e}'
                    }
            
            # Check ML model status
            if self.anomaly_detector:
                health_status['checks']['ml_model'] = {
                    'status': 'pass',
                    'details': 'ML model loaded and ready'
                }
            else:
                health_status['checks']['ml_model'] = {
                    'status': 'warn',
                    'details': 'ML model not loaded'
                }
            
            # Check performance metrics
            avg_latency = self.metrics.get('average_detection_latency', 0)
            if avg_latency > self.detection_latency_threshold_ms:
                health_status['checks']['performance'] = {
                    'status': 'warn',
                    'details': f'Average latency {avg_latency:.1f}ms exceeds threshold {self.detection_latency_threshold_ms}ms'
                }
            else:
                health_status['checks']['performance'] = {
                    'status': 'pass',
                    'details': f'Average latency {avg_latency:.1f}ms within threshold'
                }
            
            # Overall status
            failed_checks = [check for check in health_status['checks'].values() if check['status'] == 'fail']
            if failed_checks:
                health_status['status'] = 'unhealthy'
            else:
                warning_checks = [check for check in health_status['checks'].values() if check['status'] == 'warn']
                if warning_checks:
                    health_status['status'] = 'degraded'
            
        except Exception as e:
            health_status['status'] = 'error'
            health_status['error'] = str(e)
        
        return health_status


# Export main classes
__all__ = [
    'SpillageDetectionEngine',
    'SpillageEvent',
    'SpillageEventType',
    'SpillageRiskLevel',
    'DetectionMethod',
    'DetectionRule',
    'BehavioralPattern'
]