"""
Classification-Aware Query Engine
=================================

Advanced query engine with comprehensive classification-aware result filtering,
aggregation controls, and Bell-LaPadula integration for multi-level security.

Classification: UNCLASSIFIED//FOR OFFICIAL USE ONLY
Created: 2025-07-17
Version: 1.0
"""

import logging
import hashlib
import json
from datetime import datetime, timedelta
from typing import List, Dict, Set, Optional, Any, Union, Tuple
from dataclasses import dataclass, field
from enum import Enum
import re
import asyncio
from abc import ABC, abstractmethod
import threading
from collections import defaultdict
import time

try:
    import pandas as pd
    import numpy as np
    PANDAS_AVAILABLE = True
except ImportError:
    PANDAS_AVAILABLE = False

try:
    import sqlalchemy
    from sqlalchemy import create_engine, text
    from sqlalchemy.pool import QueuePool
    SQLALCHEMY_AVAILABLE = True
except ImportError:
    SQLALCHEMY_AVAILABLE = False

from ..bell_lapadula import EnhancedBellLaPadulaEngine
from ...models.bell_lapadula import (
    SecurityLabel, ClassificationLevel, NetworkDomain, 
    AccessType, Subject, DataObject, AccessRequest, AccessDecision
)
from ..classification_engine import DataClassificationEngine, ClassificationResult

# Configure logging
logger = logging.getLogger(__name__)


class QueryType(Enum):
    """Types of queries supported by the engine."""
    SELECT = "SELECT"
    AGGREGATE = "AGGREGATE"
    ANALYTICAL = "ANALYTICAL"
    STREAMING = "STREAMING"
    BATCH = "BATCH"


class InferenceRisk(Enum):
    """Levels of inference attack risk."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class MaskingStrategy(Enum):
    """Strategies for masking sensitive data."""
    REDACT = "REDACT"
    HASH = "HASH"
    TOKENIZE = "TOKENIZE"
    BLUR = "BLUR"
    SUPPRESS = "SUPPRESS"


@dataclass
class QueryContext:
    """Context information for query execution."""
    query_id: str
    user_id: str
    session_id: str
    network_domain: NetworkDomain
    client_ip: str
    request_timestamp: datetime
    query_type: QueryType
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        """Initialize additional context fields."""
        if not self.query_id:
            self.query_id = self._generate_query_id()
    
    def _generate_query_id(self) -> str:
        """Generate unique query identifier."""
        timestamp = self.request_timestamp.isoformat()
        data = f"{self.user_id}:{self.session_id}:{timestamp}"
        return hashlib.sha256(data.encode()).hexdigest()[:12]


@dataclass
class QueryFilter:
    """Filter conditions for classification-aware queries."""
    max_classification: ClassificationLevel
    required_compartments: Set[str] = field(default_factory=set)
    excluded_compartments: Set[str] = field(default_factory=set)
    allowed_caveats: Set[str] = field(default_factory=set)
    network_restrictions: Set[NetworkDomain] = field(default_factory=set)
    temporal_restrictions: Optional[Dict[str, datetime]] = None
    
    def matches(self, data_classification: SecurityLabel) -> bool:
        """Check if data classification matches filter criteria."""
        # Check classification level
        if data_classification.classification > self.max_classification:
            return False
        
        # Check compartments
        if self.required_compartments and not self.required_compartments.issubset(data_classification.compartments):
            return False
        
        if self.excluded_compartments and self.excluded_compartments.intersection(data_classification.compartments):
            return False
        
        # Check caveats
        if self.allowed_caveats and not data_classification.caveats.issubset(self.allowed_caveats):
            return False
        
        return True


@dataclass
class AggregationControl:
    """Controls for aggregation operations to prevent inference attacks."""
    min_group_size: int = 5
    max_groups_per_query: int = 100
    suppression_threshold: float = 0.1
    noise_injection_enabled: bool = True
    differential_privacy_epsilon: float = 1.0
    k_anonymity_threshold: int = 3
    
    def validate_aggregation(self, group_sizes: List[int]) -> Tuple[bool, str]:
        """Validate aggregation parameters against controls."""
        if len(group_sizes) > self.max_groups_per_query:
            return False, f"Too many groups: {len(group_sizes)} > {self.max_groups_per_query}"
        
        small_groups = [size for size in group_sizes if size < self.min_group_size]
        if small_groups:
            return False, f"Groups too small: {small_groups}, minimum: {self.min_group_size}"
        
        return True, "Aggregation approved"


@dataclass
class QueryResult:
    """Result of a classification-aware query."""
    query_id: str
    data: Any
    classification: SecurityLabel
    masked_fields: List[str] = field(default_factory=list)
    suppressed_records: int = 0
    inference_risk: InferenceRisk = InferenceRisk.LOW
    audit_trail: List[Dict[str, Any]] = field(default_factory=list)
    execution_time: float = 0.0
    cache_hit: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary representation."""
        return {
            'query_id': self.query_id,
            'data': self.data,
            'classification': self.classification.to_dict(),
            'masked_fields': self.masked_fields,
            'suppressed_records': self.suppressed_records,
            'inference_risk': self.inference_risk.value,
            'execution_time': self.execution_time,
            'cache_hit': self.cache_hit,
            'metadata': self.metadata
        }


class QueryAuditLogger:
    """Comprehensive audit logging for all query operations."""
    
    def __init__(self, audit_db_url: Optional[str] = None):
        self.audit_db_url = audit_db_url
        self.audit_buffer = []
        self.buffer_lock = threading.Lock()
        self.max_buffer_size = 1000
        
        if SQLALCHEMY_AVAILABLE and audit_db_url:
            self.audit_engine = create_engine(audit_db_url, poolclass=QueuePool)
        else:
            self.audit_engine = None
    
    def log_query_start(self, context: QueryContext, query: str, filters: QueryFilter):
        """Log query execution start."""
        audit_entry = {
            'event_type': 'QUERY_START',
            'query_id': context.query_id,
            'user_id': context.user_id,
            'session_id': context.session_id,
            'network_domain': context.network_domain.value,
            'client_ip': context.client_ip,
            'timestamp': context.request_timestamp.isoformat(),
            'query_type': context.query_type.value,
            'query_hash': hashlib.sha256(query.encode()).hexdigest(),
            'max_classification': filters.max_classification.to_string(),
            'required_compartments': list(filters.required_compartments),
            'metadata': context.metadata
        }
        
        self._add_audit_entry(audit_entry)
    
    def log_query_result(self, context: QueryContext, result: QueryResult):
        """Log query execution result."""
        audit_entry = {
            'event_type': 'QUERY_RESULT',
            'query_id': context.query_id,
            'user_id': context.user_id,
            'timestamp': datetime.now().isoformat(),
            'execution_time': result.execution_time,
            'result_classification': result.classification.to_dict(),
            'masked_fields': result.masked_fields,
            'suppressed_records': result.suppressed_records,
            'inference_risk': result.inference_risk.value,
            'cache_hit': result.cache_hit,
            'records_returned': self._count_records(result.data)
        }
        
        self._add_audit_entry(audit_entry)
    
    def log_access_denial(self, context: QueryContext, reason: str, violated_rules: List[str]):
        """Log access denial."""
        audit_entry = {
            'event_type': 'ACCESS_DENIED',
            'query_id': context.query_id,
            'user_id': context.user_id,
            'timestamp': datetime.now().isoformat(),
            'denial_reason': reason,
            'violated_rules': violated_rules
        }
        
        self._add_audit_entry(audit_entry)
    
    def log_inference_detection(self, context: QueryContext, risk_level: InferenceRisk, 
                               details: Dict[str, Any]):
        """Log inference attack detection."""
        audit_entry = {
            'event_type': 'INFERENCE_DETECTION',
            'query_id': context.query_id,
            'user_id': context.user_id,
            'timestamp': datetime.now().isoformat(),
            'risk_level': risk_level.value,
            'detection_details': details
        }
        
        self._add_audit_entry(audit_entry)
    
    def _add_audit_entry(self, entry: Dict[str, Any]):
        """Add entry to audit buffer."""
        with self.buffer_lock:
            self.audit_buffer.append(entry)
            
            if len(self.audit_buffer) >= self.max_buffer_size:
                self._flush_buffer()
    
    def _flush_buffer(self):
        """Flush audit buffer to persistent storage."""
        if not self.audit_buffer:
            return
        
        if self.audit_engine:
            try:
                # Insert into database
                with self.audit_engine.connect() as conn:
                    for entry in self.audit_buffer:
                        conn.execute(
                            text("""
                            INSERT INTO query_audit_log 
                            (event_type, query_id, user_id, session_id, 
                             timestamp, details) 
                            VALUES 
                            (:event_type, :query_id, :user_id, :session_id, 
                             :timestamp, :details)
                            """),
                            {
                                'event_type': entry['event_type'],
                                'query_id': entry['query_id'],
                                'user_id': entry['user_id'],
                                'session_id': entry.get('session_id'),
                                'timestamp': entry['timestamp'],
                                'details': json.dumps(entry)
                            }
                        )
                    conn.commit()
                
                logger.info(f"Flushed {len(self.audit_buffer)} audit entries to database")
                
            except Exception as e:
                logger.error(f"Failed to flush audit buffer to database: {e}")
                # Fallback to file logging
                self._log_to_file()
        else:
            self._log_to_file()
        
        self.audit_buffer.clear()
    
    def _log_to_file(self):
        """Fallback logging to file."""
        try:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"query_audit_{timestamp}.log"
            
            with open(filename, 'a') as f:
                for entry in self.audit_buffer:
                    f.write(json.dumps(entry) + '\n')
            
            logger.info(f"Audit entries logged to {filename}")
            
        except Exception as e:
            logger.error(f"Failed to log audit entries to file: {e}")
    
    def _count_records(self, data: Any) -> int:
        """Count records in result data."""
        if PANDAS_AVAILABLE and isinstance(data, pd.DataFrame):
            return len(data)
        elif isinstance(data, list):
            return len(data)
        elif isinstance(data, dict):
            return 1
        else:
            return 0


class InferenceController:
    """Controller for detecting and preventing inference attacks."""
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.query_history = defaultdict(list)
        self.history_lock = threading.Lock()
        self.max_history_size = self.config.get('max_history_size', 1000)
        self.inference_window = self.config.get('inference_window_hours', 24)
        
    def assess_inference_risk(self, context: QueryContext, query: str, 
                            result: QueryResult) -> InferenceRisk:
        """Assess inference attack risk for a query."""
        risk_factors = []
        
        # Check query pattern similarity
        similar_queries = self._find_similar_queries(context.user_id, query)
        if len(similar_queries) >= 3:
            risk_factors.append(("similar_queries", len(similar_queries)))
        
        # Check result size patterns
        if result.suppressed_records > 0:
            suppression_ratio = result.suppressed_records / (result.suppressed_records + self._count_records(result.data))
            if suppression_ratio > 0.3:
                risk_factors.append(("high_suppression", suppression_ratio))
        
        # Check temporal patterns
        recent_queries = self._get_recent_queries(context.user_id, hours=1)
        if len(recent_queries) > 10:
            risk_factors.append(("high_frequency", len(recent_queries)))
        
        # Check classification level progression
        if self._detect_classification_escalation(context.user_id):
            risk_factors.append(("classification_escalation", True))
        
        # Calculate overall risk
        risk_score = len(risk_factors)
        
        if risk_score >= 3:
            return InferenceRisk.CRITICAL
        elif risk_score >= 2:
            return InferenceRisk.HIGH
        elif risk_score >= 1:
            return InferenceRisk.MEDIUM
        else:
            return InferenceRisk.LOW
    
    def _find_similar_queries(self, user_id: str, query: str) -> List[Dict[str, Any]]:
        """Find similar queries in user's history."""
        with self.history_lock:
            user_history = self.query_history.get(user_id, [])
            
            # Simple similarity check based on query structure
            query_words = set(query.lower().split())
            similar_queries = []
            
            for historical_query in user_history:
                hist_words = set(historical_query['query'].lower().split())
                similarity = len(query_words.intersection(hist_words)) / len(query_words.union(hist_words))
                
                if similarity > 0.7:  # 70% similarity threshold
                    similar_queries.append(historical_query)
            
            return similar_queries
    
    def _get_recent_queries(self, user_id: str, hours: int) -> List[Dict[str, Any]]:
        """Get recent queries for user."""
        cutoff_time = datetime.now() - timedelta(hours=hours)
        
        with self.history_lock:
            user_history = self.query_history.get(user_id, [])
            recent_queries = [
                q for q in user_history 
                if q['timestamp'] > cutoff_time
            ]
            
            return recent_queries
    
    def _detect_classification_escalation(self, user_id: str) -> bool:
        """Detect if user is progressively accessing higher classifications."""
        recent_queries = self._get_recent_queries(user_id, self.inference_window)
        
        if len(recent_queries) < 3:
            return False
        
        # Check if classification levels are increasing
        classifications = [q.get('max_classification', 0) for q in recent_queries]
        
        # Simple escalation detection
        for i in range(1, len(classifications)):
            if classifications[i] > classifications[i-1]:
                return True
        
        return False
    
    def record_query(self, context: QueryContext, query: str, filters: QueryFilter):
        """Record query in history for inference detection."""
        query_record = {
            'timestamp': context.request_timestamp,
            'query': query,
            'query_type': context.query_type.value,
            'max_classification': filters.max_classification.value,
            'network_domain': context.network_domain.value
        }
        
        with self.history_lock:
            user_history = self.query_history[context.user_id]
            user_history.append(query_record)
            
            # Maintain history size limit
            if len(user_history) > self.max_history_size:
                user_history.pop(0)


class ResultMasker:
    """Handles masking and redaction of sensitive data in query results."""
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.masking_patterns = self._load_masking_patterns()
    
    def _load_masking_patterns(self) -> Dict[str, Dict[str, Any]]:
        """Load patterns for identifying sensitive data."""
        return {
            'ssn': {
                'pattern': r'\b\d{3}-\d{2}-\d{4}\b',
                'strategy': MaskingStrategy.HASH,
                'classification': ClassificationLevel.CONFIDENTIAL
            },
            'credit_card': {
                'pattern': r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b',
                'strategy': MaskingStrategy.TOKENIZE,
                'classification': ClassificationLevel.CONFIDENTIAL
            },
            'email': {
                'pattern': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
                'strategy': MaskingStrategy.BLUR,
                'classification': ClassificationLevel.UNCLASSIFIED
            },
            'classified_keywords': {
                'pattern': r'\b(SECRET|CONFIDENTIAL|TOP SECRET|CLASSIFIED)\b',
                'strategy': MaskingStrategy.REDACT,
                'classification': ClassificationLevel.SECRET
            }
        }
    
    def mask_result(self, data: Any, user_clearance: SecurityLabel, 
                   data_classification: SecurityLabel) -> Tuple[Any, List[str]]:
        """
        Mask sensitive data in query results based on user clearance.
        
        Args:
            data: Query result data
            user_clearance: User's security clearance
            data_classification: Classification of the data
            
        Returns:
            Tuple of (masked_data, list_of_masked_fields)
        """
        masked_fields = []
        
        if not user_clearance.dominates(data_classification):
            # User doesn't have sufficient clearance - apply comprehensive masking
            if PANDAS_AVAILABLE and isinstance(data, pd.DataFrame):
                masked_data = self._mask_dataframe(data, user_clearance, True)
                masked_fields = list(data.columns)
            elif isinstance(data, list):
                masked_data = self._mask_list(data, user_clearance, True)
                masked_fields = ['all_fields']
            elif isinstance(data, dict):
                masked_data = self._mask_dict(data, user_clearance, True)
                masked_fields = list(data.keys())
            else:
                masked_data = "[REDACTED]"
                masked_fields = ['content']
        else:
            # User has sufficient clearance - apply selective masking
            if PANDAS_AVAILABLE and isinstance(data, pd.DataFrame):
                masked_data, masked_fields = self._mask_dataframe_selective(data, user_clearance)
            elif isinstance(data, list):
                masked_data, masked_fields = self._mask_list_selective(data, user_clearance)
            elif isinstance(data, dict):
                masked_data, masked_fields = self._mask_dict_selective(data, user_clearance)
            else:
                masked_data, masked_fields = self._mask_text_selective(str(data), user_clearance)
        
        return masked_data, masked_fields
    
    def _mask_dataframe(self, df: 'pd.DataFrame', user_clearance: SecurityLabel, 
                       comprehensive: bool = False) -> 'pd.DataFrame':
        """Mask DataFrame based on user clearance."""
        if comprehensive:
            # Return empty DataFrame with same structure
            return pd.DataFrame(columns=df.columns)
        
        # Selective masking would be implemented here
        return df
    
    def _mask_dataframe_selective(self, df: 'pd.DataFrame', 
                                 user_clearance: SecurityLabel) -> Tuple['pd.DataFrame', List[str]]:
        """Apply selective masking to DataFrame."""
        masked_df = df.copy()
        masked_fields = []
        
        for column in df.columns:
            if self._column_requires_masking(column, user_clearance):
                masked_df[column] = masked_df[column].apply(
                    lambda x: self._apply_masking_strategy(str(x), MaskingStrategy.REDACT)
                )
                masked_fields.append(column)
        
        return masked_df, masked_fields
    
    def _mask_list(self, data: List[Any], user_clearance: SecurityLabel, 
                  comprehensive: bool = False) -> List[Any]:
        """Mask list data."""
        if comprehensive:
            return []
        
        return [self._mask_item(item, user_clearance) for item in data]
    
    def _mask_list_selective(self, data: List[Any], 
                           user_clearance: SecurityLabel) -> Tuple[List[Any], List[str]]:
        """Apply selective masking to list."""
        masked_data = []
        masked_fields = []
        
        for i, item in enumerate(data):
            masked_item, item_masked_fields = self._mask_item_selective(item, user_clearance)
            masked_data.append(masked_item)
            if item_masked_fields:
                masked_fields.extend([f"item_{i}_{field}" for field in item_masked_fields])
        
        return masked_data, masked_fields
    
    def _mask_dict(self, data: Dict[str, Any], user_clearance: SecurityLabel, 
                  comprehensive: bool = False) -> Dict[str, Any]:
        """Mask dictionary data."""
        if comprehensive:
            return {}
        
        return {key: self._mask_item(value, user_clearance) for key, value in data.items()}
    
    def _mask_dict_selective(self, data: Dict[str, Any], 
                           user_clearance: SecurityLabel) -> Tuple[Dict[str, Any], List[str]]:
        """Apply selective masking to dictionary."""
        masked_data = {}
        masked_fields = []
        
        for key, value in data.items():
            if self._field_requires_masking(key, user_clearance):
                masked_data[key] = self._apply_masking_strategy(str(value), MaskingStrategy.REDACT)
                masked_fields.append(key)
            else:
                masked_item, item_masked_fields = self._mask_item_selective(value, user_clearance)
                masked_data[key] = masked_item
                if item_masked_fields:
                    masked_fields.extend([f"{key}.{field}" for field in item_masked_fields])
        
        return masked_data, masked_fields
    
    def _mask_text_selective(self, text: str, 
                           user_clearance: SecurityLabel) -> Tuple[str, List[str]]:
        """Apply selective masking to text."""
        masked_text = text
        masked_fields = []
        
        for pattern_name, pattern_config in self.masking_patterns.items():
            if user_clearance.classification < pattern_config['classification']:
                pattern = pattern_config['pattern']
                strategy = pattern_config['strategy']
                
                if re.search(pattern, masked_text):
                    masked_text = re.sub(pattern, 
                                       lambda m: self._apply_masking_strategy(m.group(), strategy), 
                                       masked_text)
                    masked_fields.append(pattern_name)
        
        return masked_text, masked_fields
    
    def _mask_item(self, item: Any, user_clearance: SecurityLabel) -> Any:
        """Mask individual item."""
        if isinstance(item, str):
            masked_item, _ = self._mask_text_selective(item, user_clearance)
            return masked_item
        elif isinstance(item, dict):
            return self._mask_dict(item, user_clearance)
        elif isinstance(item, list):
            return self._mask_list(item, user_clearance)
        else:
            return item
    
    def _mask_item_selective(self, item: Any, 
                           user_clearance: SecurityLabel) -> Tuple[Any, List[str]]:
        """Apply selective masking to item."""
        if isinstance(item, str):
            return self._mask_text_selective(item, user_clearance)
        elif isinstance(item, dict):
            return self._mask_dict_selective(item, user_clearance)
        elif isinstance(item, list):
            return self._mask_list_selective(item, user_clearance)
        else:
            return item, []
    
    def _column_requires_masking(self, column: str, user_clearance: SecurityLabel) -> bool:
        """Check if column requires masking based on user clearance."""
        # Simple heuristic - in practice, this would check column metadata
        sensitive_columns = ['ssn', 'social_security', 'credit_card', 'password', 'classified']
        return any(sensitive in column.lower() for sensitive in sensitive_columns)
    
    def _field_requires_masking(self, field: str, user_clearance: SecurityLabel) -> bool:
        """Check if field requires masking based on user clearance."""
        return self._column_requires_masking(field, user_clearance)
    
    def _apply_masking_strategy(self, value: str, strategy: MaskingStrategy) -> str:
        """Apply specific masking strategy to value."""
        if strategy == MaskingStrategy.REDACT:
            return "[REDACTED]"
        elif strategy == MaskingStrategy.HASH:
            return hashlib.sha256(value.encode()).hexdigest()[:8]
        elif strategy == MaskingStrategy.TOKENIZE:
            return f"TOKEN_{hashlib.md5(value.encode()).hexdigest()[:6]}"
        elif strategy == MaskingStrategy.BLUR:
            if len(value) <= 4:
                return "*" * len(value)
            else:
                return value[:2] + "*" * (len(value) - 4) + value[-2:]
        elif strategy == MaskingStrategy.SUPPRESS:
            return ""
        else:
            return value


class ClassificationAwareQueryEngine:
    """
    Main classification-aware query engine with comprehensive security controls.
    """
    
    def __init__(self, config: Dict[str, Any] = None):
        """
        Initialize the classification-aware query engine.
        
        Args:
            config: Configuration dictionary
        """
        self.config = config or {}
        
        # Initialize sub-components
        self.bell_lapadula_engine = EnhancedBellLaPadulaEngine()
        self.classification_engine = DataClassificationEngine()
        self.audit_logger = QueryAuditLogger(self.config.get('audit_db_url'))
        self.inference_controller = InferenceController(self.config.get('inference_config'))
        self.result_masker = ResultMasker(self.config.get('masking_config'))
        
        # Query cache for performance
        self.query_cache = {}
        self.cache_lock = threading.Lock()
        self.cache_ttl = self.config.get('cache_ttl_seconds', 300)  # 5 minutes
        
        # Aggregation controls
        self.aggregation_control = AggregationControl(
            **self.config.get('aggregation_config', {})
        )
        
        # Performance monitoring
        self.performance_metrics = defaultdict(list)
        self.metrics_lock = threading.Lock()
    
    def execute_query(self, query: str, context: QueryContext, 
                     user_clearance: SecurityLabel) -> QueryResult:
        """
        Execute a classification-aware query with comprehensive security controls.
        
        Args:
            query: SQL or query string
            context: Query execution context
            user_clearance: User's security clearance
            
        Returns:
            QueryResult with filtered and masked data
        """
        start_time = time.time()
        
        try:
            # Create query filter based on user clearance
            query_filter = self._create_query_filter(user_clearance, context)
            
            # Log query start
            self.audit_logger.log_query_start(context, query, query_filter)
            
            # Record query for inference detection
            self.inference_controller.record_query(context, query, query_filter)
            
            # Check cache first
            cache_key = self._generate_cache_key(query, context, user_clearance)
            cached_result = self._get_cached_result(cache_key)
            
            if cached_result:
                logger.info(f"Cache hit for query {context.query_id}")
                cached_result.cache_hit = True
                return cached_result
            
            # Execute query with classification filtering
            raw_result = self._execute_filtered_query(query, query_filter, context)
            
            # Classify result data
            result_classification = self._classify_result_data(raw_result, context)
            
            # Apply Bell-LaPadula access control
            access_decision = self._check_access_control(
                user_clearance, result_classification, context
            )
            
            if access_decision.decision != AccessDecision.PERMIT:
                self.audit_logger.log_access_denial(
                    context, access_decision.reason, access_decision.violated_rules
                )
                raise PermissionError(f"Access denied: {access_decision.reason}")
            
            # Apply result masking
            masked_data, masked_fields = self.result_masker.mask_result(
                raw_result, user_clearance, result_classification
            )
            
            # Check for inference attacks
            inference_risk = self.inference_controller.assess_inference_risk(
                context, query, 
                QueryResult(context.query_id, masked_data, result_classification)
            )
            
            if inference_risk == InferenceRisk.CRITICAL:
                self.audit_logger.log_inference_detection(
                    context, inference_risk, {'query': query}
                )
                raise SecurityError("Query blocked due to inference attack risk")
            
            # Create final result
            execution_time = time.time() - start_time
            result = QueryResult(
                query_id=context.query_id,
                data=masked_data,
                classification=result_classification,
                masked_fields=masked_fields,
                inference_risk=inference_risk,
                execution_time=execution_time,
                metadata={'query_type': context.query_type.value}
            )
            
            # Cache result
            self._cache_result(cache_key, result)
            
            # Log successful query
            self.audit_logger.log_query_result(context, result)
            
            # Record performance metrics
            self._record_performance_metrics(context, execution_time)
            
            return result
            
        except Exception as e:
            execution_time = time.time() - start_time
            logger.error(f"Query execution failed: {e}")
            
            # Log error
            self.audit_logger.log_access_denial(
                context, str(e), ['QUERY_EXECUTION_ERROR']
            )
            
            raise
    
    def _create_query_filter(self, user_clearance: SecurityLabel, 
                           context: QueryContext) -> QueryFilter:
        """Create query filter based on user clearance and context."""
        return QueryFilter(
            max_classification=user_clearance.classification,
            required_compartments=user_clearance.compartments.copy(),
            network_restrictions={context.network_domain}
        )
    
    def _execute_filtered_query(self, query: str, query_filter: QueryFilter, 
                              context: QueryContext) -> Any:
        """Execute query with classification-based filtering."""
        # This is a simplified implementation
        # In practice, this would integrate with actual database/data source
        
        # Parse query to understand intent
        query_type = self._parse_query_type(query)
        
        if query_type == QueryType.AGGREGATE:
            # Apply aggregation controls
            return self._execute_aggregate_query(query, query_filter, context)
        else:
            # Execute regular query
            return self._execute_regular_query(query, query_filter, context)
    
    def _execute_aggregate_query(self, query: str, query_filter: QueryFilter, 
                               context: QueryContext) -> Any:
        """Execute aggregate query with additional controls."""
        # Simulate aggregate query execution
        # In practice, this would interact with actual data sources
        
        # Example: Generate mock aggregated data
        if PANDAS_AVAILABLE:
            data = pd.DataFrame({
                'category': ['A', 'B', 'C', 'D', 'E'],
                'count': [15, 8, 23, 12, 45],
                'avg_value': [4.5, 3.2, 6.8, 2.1, 5.7]
            })
            
            # Apply aggregation controls
            group_sizes = data['count'].tolist()
            is_valid, reason = self.aggregation_control.validate_aggregation(group_sizes)
            
            if not is_valid:
                raise SecurityError(f"Aggregation control violation: {reason}")
            
            # Suppress small groups
            min_size = self.aggregation_control.min_group_size
            data = data[data['count'] >= min_size]
            
            return data
        else:
            return {'error': 'Pandas not available for aggregation'}
    
    def _execute_regular_query(self, query: str, query_filter: QueryFilter, 
                             context: QueryContext) -> Any:
        """Execute regular query with filtering."""
        # Simulate regular query execution
        # In practice, this would interact with actual data sources
        
        if PANDAS_AVAILABLE:
            # Example: Generate mock data
            data = pd.DataFrame({
                'id': range(1, 101),
                'name': [f'Record_{i}' for i in range(1, 101)],
                'classification': ['U'] * 50 + ['C'] * 30 + ['S'] * 20,
                'value': np.random.normal(100, 15, 100)
            })
            
            # Filter based on classification
            max_class_map = {'U': 0, 'C': 1, 'S': 2, 'TS': 3}
            user_max_level = query_filter.max_classification.value
            
            filtered_data = data[
                data['classification'].map(max_class_map) <= user_max_level
            ]
            
            return filtered_data
        else:
            return {'message': 'Query executed', 'records': 42}
    
    def _parse_query_type(self, query: str) -> QueryType:
        """Parse query to determine type."""
        query_lower = query.lower()
        
        if any(keyword in query_lower for keyword in ['count', 'sum', 'avg', 'group by']):
            return QueryType.AGGREGATE
        elif 'select' in query_lower:
            return QueryType.SELECT
        else:
            return QueryType.SELECT
    
    def _classify_result_data(self, data: Any, context: QueryContext) -> SecurityLabel:
        """Classify the result data to determine appropriate security label."""
        # This is a simplified implementation
        # In practice, this would analyze the actual data content
        
        if PANDAS_AVAILABLE and isinstance(data, pd.DataFrame):
            # Analyze DataFrame content
            max_classification = ClassificationLevel.UNCLASSIFIED
            compartments = set()
            
            # Check for classification indicators in data
            if 'classification' in data.columns:
                class_values = data['classification'].unique()
                class_map = {'U': 0, 'C': 1, 'S': 2, 'TS': 3}
                
                for class_val in class_values:
                    if class_val in class_map:
                        level = ClassificationLevel(class_map[class_val])
                        if level > max_classification:
                            max_classification = level
            
            # Check for sensitive data patterns
            for column in data.columns:
                if any(sensitive in column.lower() for sensitive in ['ssn', 'classified', 'secret']):
                    max_classification = max(max_classification, ClassificationLevel.CONFIDENTIAL)
                    compartments.add('PII')
            
            return SecurityLabel(max_classification, compartments)
        
        else:
            # For non-DataFrame data, use basic classification
            return SecurityLabel(ClassificationLevel.UNCLASSIFIED)
    
    def _check_access_control(self, user_clearance: SecurityLabel, 
                            data_classification: SecurityLabel, 
                            context: QueryContext) -> Any:
        """Check access control using Bell-LaPadula model."""
        # Create mock subject and object for access control check
        subject = Subject(
            id=context.user_id,
            name=f"User_{context.user_id}",
            clearance=user_clearance,
            network_access={context.network_domain}
        )
        
        data_object = DataObject(
            id=f"query_result_{context.query_id}",
            name="Query Result",
            classification=data_classification,
            data_type="query_result",
            owner=context.user_id
        )
        
        access_request = AccessRequest(
            subject=subject,
            object=data_object,
            access_type=AccessType.READ,
            context={'network': context.network_domain}
        )
        
        return self.bell_lapadula_engine.evaluate_access(access_request)
    
    def _generate_cache_key(self, query: str, context: QueryContext, 
                          user_clearance: SecurityLabel) -> str:
        """Generate cache key for query result."""
        cache_data = {
            'query_hash': hashlib.sha256(query.encode()).hexdigest(),
            'user_clearance': user_clearance.to_dict(),
            'network_domain': context.network_domain.value,
            'query_type': context.query_type.value
        }
        
        cache_string = json.dumps(cache_data, sort_keys=True)
        return hashlib.md5(cache_string.encode()).hexdigest()
    
    def _get_cached_result(self, cache_key: str) -> Optional[QueryResult]:
        """Get cached query result if available and valid."""
        with self.cache_lock:
            if cache_key in self.query_cache:
                cached_entry = self.query_cache[cache_key]
                
                # Check if cache entry is still valid
                if datetime.now() - cached_entry['timestamp'] < timedelta(seconds=self.cache_ttl):
                    return cached_entry['result']
                else:
                    # Remove expired entry
                    del self.query_cache[cache_key]
        
        return None
    
    def _cache_result(self, cache_key: str, result: QueryResult):
        """Cache query result."""
        with self.cache_lock:
            self.query_cache[cache_key] = {
                'result': result,
                'timestamp': datetime.now()
            }
            
            # Simple cache size management
            if len(self.query_cache) > 100:
                # Remove oldest entry
                oldest_key = min(self.query_cache.keys(), 
                               key=lambda k: self.query_cache[k]['timestamp'])
                del self.query_cache[oldest_key]
    
    def _record_performance_metrics(self, context: QueryContext, execution_time: float):
        """Record performance metrics."""
        with self.metrics_lock:
            metrics = self.performance_metrics[context.query_type.value]
            metrics.append({
                'execution_time': execution_time,
                'timestamp': datetime.now(),
                'user_id': context.user_id,
                'network_domain': context.network_domain.value
            })
            
            # Keep only recent metrics
            if len(metrics) > 1000:
                metrics.pop(0)
    
    def get_performance_metrics(self) -> Dict[str, Any]:
        """Get current performance metrics."""
        with self.metrics_lock:
            metrics_summary = {}
            
            for query_type, metrics in self.performance_metrics.items():
                if metrics:
                    execution_times = [m['execution_time'] for m in metrics]
                    metrics_summary[query_type] = {
                        'avg_execution_time': sum(execution_times) / len(execution_times),
                        'max_execution_time': max(execution_times),
                        'min_execution_time': min(execution_times),
                        'total_queries': len(execution_times)
                    }
            
            return metrics_summary
    
    def clear_cache(self):
        """Clear query result cache."""
        with self.cache_lock:
            self.query_cache.clear()
        
        logger.info("Query cache cleared")
    
    def shutdown(self):
        """Shutdown the query engine and flush any pending operations."""
        # Flush audit logs
        self.audit_logger._flush_buffer()
        
        # Clear caches
        self.clear_cache()
        
        logger.info("Query engine shutdown complete")


class SecurityError(Exception):
    """Exception for security-related errors."""
    pass


# Utility functions for external integration

def create_query_engine(config_path: Optional[str] = None) -> ClassificationAwareQueryEngine:
    """Create and configure a classification-aware query engine."""
    config = {}
    
    if config_path:
        with open(config_path, 'r') as f:
            config = json.load(f)
    
    return ClassificationAwareQueryEngine(config)


def execute_secure_query(query: str, user_id: str, user_clearance: SecurityLabel,
                        network_domain: NetworkDomain = NetworkDomain.NIPR) -> QueryResult:
    """Execute a secure query with default settings."""
    engine = create_query_engine()
    
    context = QueryContext(
        query_id="",
        user_id=user_id,
        session_id=f"session_{user_id}",
        network_domain=network_domain,
        client_ip="127.0.0.1",
        request_timestamp=datetime.now(),
        query_type=QueryType.SELECT
    )
    
    return engine.execute_query(query, context, user_clearance)


# Example usage
def example_usage():
    """Demonstrate classification-aware query engine usage."""
    # Create query engine
    engine = create_query_engine()
    
    # Create user clearance
    user_clearance = SecurityLabel(
        classification=ClassificationLevel.SECRET,
        compartments={'SI'},
        caveats=set()
    )
    
    # Create query context
    context = QueryContext(
        query_id="",
        user_id="analyst_001",
        session_id="session_123",
        network_domain=NetworkDomain.SIPR,
        client_ip="192.168.1.100",
        request_timestamp=datetime.now(),
        query_type=QueryType.SELECT
    )
    
    # Execute query
    try:
        result = engine.execute_query(
            "SELECT * FROM classified_data WHERE category = 'intelligence'",
            context,
            user_clearance
        )
        
        print(f"Query ID: {result.query_id}")
        print(f"Classification: {result.classification.classification.to_string()}")
        print(f"Masked fields: {result.masked_fields}")
        print(f"Inference risk: {result.inference_risk.value}")
        print(f"Execution time: {result.execution_time:.3f}s")
        
        if PANDAS_AVAILABLE and isinstance(result.data, pd.DataFrame):
            print(f"Records returned: {len(result.data)}")
            print(result.data.head())
        
    except Exception as e:
        print(f"Query failed: {e}")
    
    finally:
        engine.shutdown()


if __name__ == "__main__":
    example_usage()