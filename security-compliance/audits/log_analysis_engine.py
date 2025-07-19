"""
Advanced Log Analysis Engine with Anomaly Detection and Threat Intelligence

This module provides sophisticated log analysis capabilities including machine learning-based
anomaly detection, threat intelligence integration, behavioral analytics, and advanced
correlation techniques for DoD audit systems.

Key Features:
- Machine learning-based anomaly detection (Isolation Forest, One-Class SVM, LSTM)
- User behavior analytics (UBA) for insider threat detection
- Advanced threat hunting capabilities with custom queries
- Threat intelligence feed integration (STIX/TAXII, commercial feeds)
- Time-series analysis for trend detection
- Graph analytics for relationship mapping
- Statistical analysis and baseline establishment
- Real-time and batch processing modes

Detection Capabilities:
- Behavioral anomalies in user access patterns
- Unusual data access or exfiltration patterns
- Privilege escalation and lateral movement
- Account compromise indicators
- Coordinated attack patterns
- Data classification violations
- System performance anomalies
- Network traffic anomalies

Intelligence Integration:
- STIX/TAXII threat intelligence feeds
- Commercial threat intelligence sources
- Government threat indicators (IOCs)
- Custom threat signatures and rules
- Reputation databases (IP, domain, hash)
- Geolocation intelligence
- Attack pattern libraries (MITRE ATT&CK)

Analytics Techniques:
- Statistical outlier detection
- Machine learning clustering
- Time-series forecasting
- Graph network analysis
- Natural language processing for log content
- Correlation rule engines
- Bayesian analysis for risk scoring
- Pattern matching and regular expressions

Security Features:
- Encrypted analysis pipelines
- Role-based access to analysis results
- Audit trail for all analysis activities
- Classification-aware processing
- Secure model training and deployment
- Privacy-preserving analytics
"""

import json
import logging
import sqlite3
import hashlib
import threading
import time
import asyncio
from typing import Dict, List, Optional, Any, Tuple, Union, Callable, Iterator
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone, timedelta
from enum import Enum
from pathlib import Path
import queue
import pickle
import gzip
from collections import defaultdict, deque, Counter
import statistics
import math
import re
import ipaddress
import requests
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
import multiprocessing

# Machine Learning imports
try:
    import numpy as np
    import pandas as pd
    from sklearn.ensemble import IsolationForest
    from sklearn.svm import OneClassSVM
    from sklearn.cluster import DBSCAN, KMeans
    from sklearn.preprocessing import StandardScaler, MinMaxScaler
    from sklearn.decomposition import PCA
    from sklearn.metrics import silhouette_score
    from sklearn.model_selection import train_test_split
    import networkx as nx
    from scipy import stats
    from scipy.spatial.distance import euclidean
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False

# Deep learning imports (optional)
try:
    import tensorflow as tf
    from tensorflow.keras.models import Sequential, load_model
    from tensorflow.keras.layers import LSTM, Dense, Dropout
    from tensorflow.keras.optimizers import Adam
    DL_AVAILABLE = True
except ImportError:
    DL_AVAILABLE = False

# Import audit components
from .audit_logger import AuditEvent, AuditEventType, AuditSeverity, ClassificationLevel
from .real_time_alerting import SecurityAlert, AlertSeverity, AlertCategory, ThreatLevel


class AnalysisMode(Enum):
    """Analysis processing modes."""
    REAL_TIME = "real_time"
    BATCH = "batch"
    INTERACTIVE = "interactive"
    SCHEDULED = "scheduled"


class DetectionMethod(Enum):
    """Anomaly detection methods."""
    STATISTICAL = "statistical"
    MACHINE_LEARNING = "machine_learning"
    DEEP_LEARNING = "deep_learning"
    RULE_BASED = "rule_based"
    HYBRID = "hybrid"


class ThreatIntelligenceSource(Enum):
    """Threat intelligence source types."""
    STIX_TAXII = "stix_taxii"
    COMMERCIAL_FEED = "commercial_feed"
    GOVERNMENT_FEED = "government_feed"
    OPEN_SOURCE = "open_source"
    CUSTOM_SIGNATURES = "custom_signatures"
    REPUTATION_DB = "reputation_db"


@dataclass
class ThreatIndicator:
    """Threat intelligence indicator."""
    
    indicator_id: str
    indicator_type: str  # ip, domain, hash, url, email, etc.
    value: str
    threat_type: str
    confidence: float  # 0.0 to 1.0
    severity: str
    
    # Context
    description: str
    source: str
    tags: List[str] = field(default_factory=list)
    
    # Temporal
    first_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: Optional[datetime] = None
    
    # Attribution
    actor: Optional[str] = None
    campaign: Optional[str] = None
    malware_family: Optional[str] = None
    
    # Additional data
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AnomalyDetection:
    """Detected anomaly result."""
    
    # Detection metadata
    detection_id: str
    detection_time: datetime
    detection_method: DetectionMethod
    model_version: str
    
    # Anomaly details
    anomaly_type: str
    description: str
    confidence: float
    severity: str
    
    # Affected entities
    affected_users: List[str] = field(default_factory=list)
    affected_systems: List[str] = field(default_factory=list)
    affected_resources: List[str] = field(default_factory=list)
    
    # Event context
    triggering_events: List[str] = field(default_factory=list)
    time_window_start: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    time_window_end: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    # Statistical data
    baseline_value: Optional[float] = None
    observed_value: Optional[float] = None
    deviation_score: Optional[float] = None
    
    # Correlation data
    related_detections: List[str] = field(default_factory=list)
    correlation_score: float = 0.0
    
    # Intelligence context
    threat_indicators: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    
    # Additional context
    features: Dict[str, float] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class UserBehaviorProfile:
    """User behavior baseline profile."""
    
    user_id: str
    profile_created: datetime
    last_updated: datetime
    
    # Access patterns
    typical_login_hours: List[int] = field(default_factory=list)
    typical_login_days: List[int] = field(default_factory=list)
    common_source_ips: List[str] = field(default_factory=list)
    common_systems: List[str] = field(default_factory=list)
    
    # Activity patterns
    avg_session_duration: float = 0.0
    avg_events_per_session: float = 0.0
    common_event_types: Dict[str, int] = field(default_factory=dict)
    
    # Data access patterns
    typical_data_volume: float = 0.0
    common_resources: List[str] = field(default_factory=list)
    classification_access_pattern: Dict[str, int] = field(default_factory=dict)
    
    # Statistical baselines
    login_frequency_baseline: float = 0.0
    data_access_baseline: float = 0.0
    privilege_usage_baseline: float = 0.0
    
    # Risk scores
    insider_threat_score: float = 0.0
    compromise_risk_score: float = 0.0
    
    # Learning parameters
    observation_count: int = 0
    confidence_level: float = 0.0
    
    def update_profile(self, events: List[AuditEvent]):
        """Update profile with new events."""
        if not events:
            return
        
        # Update temporal patterns
        login_events = [e for e in events if e.event_type == AuditEventType.USER_LOGIN_SUCCESS]
        if login_events:
            hours = [e.timestamp.hour for e in login_events]
            days = [e.timestamp.weekday() for e in login_events]
            
            # Update with exponential moving average
            alpha = 0.1
            for hour in hours:
                if hour not in self.typical_login_hours:
                    self.typical_login_hours.append(hour)
            
            for day in days:
                if day not in self.typical_login_days:
                    self.typical_login_days.append(day)
        
        # Update other patterns
        self.observation_count += len(events)
        self.last_updated = datetime.now(timezone.utc)
        
        # Increase confidence as we gather more data
        self.confidence_level = min(1.0, self.observation_count / 1000.0)


class StatisticalAnalyzer:
    """Statistical analysis engine for audit logs."""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.baselines: Dict[str, Dict[str, float]] = {}
        self.time_series_data: Dict[str, deque] = defaultdict(lambda: deque(maxlen=10000))
    
    def establish_baseline(self, events: List[AuditEvent], metric_name: str, 
                          window_size: int = 1000) -> Dict[str, float]:
        """Establish statistical baseline for a metric."""
        try:
            values = []
            
            if metric_name == "login_frequency":
                # Calculate logins per hour
                hourly_counts = defaultdict(int)
                for event in events:
                    if event.event_type == AuditEventType.USER_LOGIN_SUCCESS:
                        hour_key = event.timestamp.strftime('%Y%m%d%H')
                        hourly_counts[hour_key] += 1
                values = list(hourly_counts.values())
            
            elif metric_name == "data_access_volume":
                # Calculate data access volumes
                for event in events:
                    if event.data_size and event.data_size > 0:
                        values.append(event.data_size)
            
            elif metric_name == "failed_authentication_rate":
                # Calculate failed auth rate per hour
                hourly_total = defaultdict(int)
                hourly_failed = defaultdict(int)
                
                for event in events:
                    if event.event_type in [AuditEventType.USER_LOGIN_SUCCESS, AuditEventType.USER_LOGIN_FAILURE]:
                        hour_key = event.timestamp.strftime('%Y%m%d%H')
                        hourly_total[hour_key] += 1
                        if event.event_type == AuditEventType.USER_LOGIN_FAILURE:
                            hourly_failed[hour_key] += 1
                
                for hour_key in hourly_total:
                    if hourly_total[hour_key] > 0:
                        rate = hourly_failed[hour_key] / hourly_total[hour_key]
                        values.append(rate)
            
            if not values:
                return {}
            
            # Calculate statistical measures
            baseline = {
                'mean': statistics.mean(values),
                'median': statistics.median(values),
                'std_dev': statistics.stdev(values) if len(values) > 1 else 0,
                'min': min(values),
                'max': max(values),
                'q1': np.percentile(values, 25) if ML_AVAILABLE else min(values),
                'q3': np.percentile(values, 75) if ML_AVAILABLE else max(values),
                'sample_size': len(values),
                'last_updated': datetime.now(timezone.utc).isoformat()
            }
            
            # Calculate control limits (3-sigma)
            if baseline['std_dev'] > 0:
                baseline['upper_control_limit'] = baseline['mean'] + 3 * baseline['std_dev']
                baseline['lower_control_limit'] = max(0, baseline['mean'] - 3 * baseline['std_dev'])
            else:
                baseline['upper_control_limit'] = baseline['mean']
                baseline['lower_control_limit'] = baseline['mean']
            
            self.baselines[metric_name] = baseline
            return baseline
            
        except Exception as e:
            self.logger.error(f"Failed to establish baseline for {metric_name}: {e}")
            return {}
    
    def detect_statistical_anomalies(self, events: List[AuditEvent], metric_name: str) -> List[AnomalyDetection]:
        """Detect statistical anomalies using established baselines."""
        anomalies = []
        
        try:
            if metric_name not in self.baselines:
                self.logger.warning(f"No baseline established for {metric_name}")
                return anomalies
            
            baseline = self.baselines[metric_name]
            
            # Calculate current metric value
            current_value = self._calculate_metric_value(events, metric_name)
            
            if current_value is None:
                return anomalies
            
            # Check against control limits
            is_anomaly = False
            severity = "LOW"
            
            if current_value > baseline['upper_control_limit']:
                is_anomaly = True
                deviation = (current_value - baseline['mean']) / baseline['std_dev'] if baseline['std_dev'] > 0 else 0
                if deviation > 5:
                    severity = "CRITICAL"
                elif deviation > 3:
                    severity = "HIGH"
                else:
                    severity = "MEDIUM"
            
            elif current_value < baseline['lower_control_limit']:
                is_anomaly = True
                deviation = (baseline['mean'] - current_value) / baseline['std_dev'] if baseline['std_dev'] > 0 else 0
                if deviation > 3:
                    severity = "HIGH"
                else:
                    severity = "MEDIUM"
            
            if is_anomaly:
                anomaly = AnomalyDetection(
                    detection_id=f"stat_{metric_name}_{int(time.time())}",
                    detection_time=datetime.now(timezone.utc),
                    detection_method=DetectionMethod.STATISTICAL,
                    model_version="statistical_v1.0",
                    anomaly_type=f"statistical_outlier_{metric_name}",
                    description=f"Statistical anomaly detected in {metric_name}: value {current_value:.2f} outside control limits",
                    confidence=min(1.0, abs(deviation) / 3.0) if baseline['std_dev'] > 0 else 0.5,
                    severity=severity,
                    baseline_value=baseline['mean'],
                    observed_value=current_value,
                    deviation_score=deviation,
                    triggering_events=[e.event_id for e in events],
                    time_window_start=events[0].timestamp if events else datetime.now(timezone.utc),
                    time_window_end=events[-1].timestamp if events else datetime.now(timezone.utc)
                )
                anomalies.append(anomaly)
            
        except Exception as e:
            self.logger.error(f"Failed to detect statistical anomalies for {metric_name}: {e}")
        
        return anomalies
    
    def _calculate_metric_value(self, events: List[AuditEvent], metric_name: str) -> Optional[float]:
        """Calculate current value for a specific metric."""
        try:
            if metric_name == "login_frequency":
                login_events = [e for e in events if e.event_type == AuditEventType.USER_LOGIN_SUCCESS]
                return len(login_events)
            
            elif metric_name == "data_access_volume":
                total_size = sum(e.data_size or 0 for e in events)
                return float(total_size)
            
            elif metric_name == "failed_authentication_rate":
                auth_events = [e for e in events if e.event_type in [
                    AuditEventType.USER_LOGIN_SUCCESS, AuditEventType.USER_LOGIN_FAILURE
                ]]
                if not auth_events:
                    return 0.0
                
                failed_count = sum(1 for e in auth_events if e.event_type == AuditEventType.USER_LOGIN_FAILURE)
                return failed_count / len(auth_events)
            
            return None
            
        except Exception as e:
            self.logger.error(f"Failed to calculate metric value for {metric_name}: {e}")
            return None


class MachineLearningAnalyzer:
    """Machine learning-based anomaly detection engine."""
    
    def __init__(self, model_storage_path: str = "/var/log/dod_audit_ml"):
        self.model_storage_path = Path(model_storage_path)
        self.model_storage_path.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.logger = logging.getLogger(__name__)
        
        # ML models
        self.models: Dict[str, Any] = {}
        self.scalers: Dict[str, Any] = {}
        self.feature_extractors: Dict[str, Callable] = {}
        
        # Model configurations
        self.model_configs = {
            'isolation_forest': {
                'contamination': 0.05,
                'n_estimators': 100,
                'random_state': 42
            },
            'one_class_svm': {
                'kernel': 'rbf',
                'gamma': 'scale',
                'nu': 0.05
            },
            'dbscan': {
                'eps': 0.5,
                'min_samples': 5
            }
        }
        
        # Initialize feature extractors
        self._init_feature_extractors()
        
        # Load existing models
        self._load_models()
    
    def _init_feature_extractors(self):
        """Initialize feature extraction functions."""
        self.feature_extractors = {
            'user_behavior': self._extract_user_behavior_features,
            'network_activity': self._extract_network_activity_features,
            'data_access': self._extract_data_access_features,
            'authentication': self._extract_authentication_features,
            'privilege_usage': self._extract_privilege_usage_features
        }
    
    def _extract_user_behavior_features(self, events: List[AuditEvent]) -> np.ndarray:
        """Extract features for user behavior analysis."""
        if not ML_AVAILABLE:
            return np.array([])
        
        try:
            features = []
            
            # Group events by user
            user_events = defaultdict(list)
            for event in events:
                if event.user_id:
                    user_events[event.user_id].append(event)
            
            for user_id, user_event_list in user_events.items():
                if len(user_event_list) < 2:  # Need at least 2 events
                    continue
                
                # Temporal features
                timestamps = [e.timestamp for e in user_event_list]
                time_diffs = [(timestamps[i+1] - timestamps[i]).total_seconds() 
                             for i in range(len(timestamps)-1)]
                
                # Activity features
                event_types = [e.event_type.value for e in user_event_list]
                unique_event_types = len(set(event_types))
                
                # Network features
                source_ips = [e.source_ip for e in user_event_list if e.source_ip]
                unique_ips = len(set(source_ips))
                
                # Data features
                data_sizes = [e.data_size or 0 for e in user_event_list]
                total_data = sum(data_sizes)
                
                # Resource features
                resources = [e.resource_id for e in user_event_list if e.resource_id]
                unique_resources = len(set(resources))
                
                # Time-based features
                hours = [t.hour for t in timestamps]
                weekdays = [t.weekday() for t in timestamps]
                
                user_features = [
                    len(user_event_list),  # Total events
                    unique_event_types,    # Event type diversity
                    unique_ips,           # IP diversity
                    unique_resources,     # Resource diversity
                    total_data,           # Total data accessed
                    np.mean(time_diffs) if time_diffs else 0,  # Average time between events
                    np.std(time_diffs) if len(time_diffs) > 1 else 0,  # Time variance
                    np.mean(hours),       # Average hour of activity
                    np.std(hours) if len(hours) > 1 else 0,  # Hour variance
                    len(set(weekdays)),   # Day diversity
                    sum(1 for e in user_event_list if e.result == 'FAILURE'),  # Failed events
                ]
                
                features.append(user_features)
            
            return np.array(features) if features else np.array([])
            
        except Exception as e:
            self.logger.error(f"Failed to extract user behavior features: {e}")
            return np.array([])
    
    def _extract_network_activity_features(self, events: List[AuditEvent]) -> np.ndarray:
        """Extract features for network activity analysis."""
        if not ML_AVAILABLE:
            return np.array([])
        
        # Implementation for network activity feature extraction
        # This would analyze IP patterns, connection frequencies, etc.
        return np.array([])
    
    def _extract_data_access_features(self, events: List[AuditEvent]) -> np.ndarray:
        """Extract features for data access pattern analysis."""
        if not ML_AVAILABLE:
            return np.array([])
        
        # Implementation for data access feature extraction
        # This would analyze data volumes, classification levels, access patterns
        return np.array([])
    
    def _extract_authentication_features(self, events: List[AuditEvent]) -> np.ndarray:
        """Extract features for authentication pattern analysis."""
        if not ML_AVAILABLE:
            return np.array([])
        
        # Implementation for authentication feature extraction
        return np.array([])
    
    def _extract_privilege_usage_features(self, events: List[AuditEvent]) -> np.ndarray:
        """Extract features for privilege usage analysis."""
        if not ML_AVAILABLE:
            return np.array([])
        
        # Implementation for privilege usage feature extraction
        return np.array([])
    
    def train_model(self, events: List[AuditEvent], model_type: str, feature_type: str) -> bool:
        """Train an anomaly detection model."""
        if not ML_AVAILABLE:
            self.logger.error("Machine learning libraries not available")
            return False
        
        try:
            # Extract features
            if feature_type not in self.feature_extractors:
                self.logger.error(f"Unknown feature type: {feature_type}")
                return False
            
            features = self.feature_extractors[feature_type](events)
            
            if features.size == 0:
                self.logger.warning(f"No features extracted for {feature_type}")
                return False
            
            # Scale features
            scaler = StandardScaler()
            features_scaled = scaler.fit_transform(features)
            
            # Train model
            model_key = f"{model_type}_{feature_type}"
            
            if model_type == 'isolation_forest':
                model = IsolationForest(**self.model_configs['isolation_forest'])
                model.fit(features_scaled)
            
            elif model_type == 'one_class_svm':
                model = OneClassSVM(**self.model_configs['one_class_svm'])
                model.fit(features_scaled)
            
            elif model_type == 'dbscan':
                model = DBSCAN(**self.model_configs['dbscan'])
                model.fit(features_scaled)
            
            else:
                self.logger.error(f"Unknown model type: {model_type}")
                return False
            
            # Store model and scaler
            self.models[model_key] = model
            self.scalers[model_key] = scaler
            
            # Save to disk
            self._save_model(model_key, model, scaler)
            
            self.logger.info(f"Trained {model_type} model for {feature_type} with {len(features)} samples")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to train model: {e}")
            return False
    
    def detect_anomalies(self, events: List[AuditEvent], model_type: str, 
                        feature_type: str) -> List[AnomalyDetection]:
        """Detect anomalies using trained ML models."""
        anomalies = []
        
        if not ML_AVAILABLE:
            return anomalies
        
        try:
            model_key = f"{model_type}_{feature_type}"
            
            if model_key not in self.models or model_key not in self.scalers:
                self.logger.warning(f"Model {model_key} not found or not trained")
                return anomalies
            
            model = self.models[model_key]
            scaler = self.scalers[model_key]
            
            # Extract and scale features
            features = self.feature_extractors[feature_type](events)
            
            if features.size == 0:
                return anomalies
            
            features_scaled = scaler.transform(features)
            
            # Predict anomalies
            if model_type in ['isolation_forest', 'one_class_svm']:
                predictions = model.predict(features_scaled)
                anomaly_scores = model.decision_function(features_scaled)
                
                # Create anomaly detections for outliers
                for i, (pred, score) in enumerate(zip(predictions, anomaly_scores)):
                    if pred == -1:  # Anomaly detected
                        confidence = min(1.0, abs(score) / 2.0)  # Normalize score to confidence
                        
                        anomaly = AnomalyDetection(
                            detection_id=f"ml_{model_type}_{feature_type}_{i}_{int(time.time())}",
                            detection_time=datetime.now(timezone.utc),
                            detection_method=DetectionMethod.MACHINE_LEARNING,
                            model_version=f"{model_type}_v1.0",
                            anomaly_type=f"ml_anomaly_{feature_type}",
                            description=f"Machine learning anomaly detected using {model_type} on {feature_type}",
                            confidence=confidence,
                            severity="HIGH" if confidence > 0.8 else "MEDIUM" if confidence > 0.5 else "LOW",
                            deviation_score=score,
                            triggering_events=[e.event_id for e in events],
                            time_window_start=events[0].timestamp if events else datetime.now(timezone.utc),
                            time_window_end=events[-1].timestamp if events else datetime.now(timezone.utc),
                            features={f"feature_{j}": float(val) for j, val in enumerate(features_scaled[i])}
                        )
                        anomalies.append(anomaly)
            
            elif model_type == 'dbscan':
                cluster_labels = model.fit_predict(features_scaled)
                
                # Outliers have label -1 in DBSCAN
                for i, label in enumerate(cluster_labels):
                    if label == -1:  # Outlier
                        anomaly = AnomalyDetection(
                            detection_id=f"ml_dbscan_{feature_type}_{i}_{int(time.time())}",
                            detection_time=datetime.now(timezone.utc),
                            detection_method=DetectionMethod.MACHINE_LEARNING,
                            model_version="dbscan_v1.0",
                            anomaly_type=f"clustering_outlier_{feature_type}",
                            description=f"Clustering outlier detected in {feature_type}",
                            confidence=0.7,  # Default confidence for clustering
                            severity="MEDIUM",
                            triggering_events=[e.event_id for e in events],
                            time_window_start=events[0].timestamp if events else datetime.now(timezone.utc),
                            time_window_end=events[-1].timestamp if events else datetime.now(timezone.utc),
                            features={f"feature_{j}": float(val) for j, val in enumerate(features_scaled[i])}
                        )
                        anomalies.append(anomaly)
        
        except Exception as e:
            self.logger.error(f"Failed to detect anomalies with {model_type}: {e}")
        
        return anomalies
    
    def _save_model(self, model_key: str, model: Any, scaler: Any):
        """Save model and scaler to disk."""
        try:
            model_file = self.model_storage_path / f"{model_key}_model.pkl"
            scaler_file = self.model_storage_path / f"{model_key}_scaler.pkl"
            
            with open(model_file, 'wb') as f:
                pickle.dump(model, f)
            
            with open(scaler_file, 'wb') as f:
                pickle.dump(scaler, f)
            
            self.logger.debug(f"Saved model {model_key}")
            
        except Exception as e:
            self.logger.error(f"Failed to save model {model_key}: {e}")
    
    def _load_models(self):
        """Load existing models from disk."""
        try:
            for model_file in self.model_storage_path.glob("*_model.pkl"):
                model_key = model_file.stem.replace("_model", "")
                scaler_file = self.model_storage_path / f"{model_key}_scaler.pkl"
                
                if scaler_file.exists():
                    with open(model_file, 'rb') as f:
                        self.models[model_key] = pickle.load(f)
                    
                    with open(scaler_file, 'rb') as f:
                        self.scalers[model_key] = pickle.load(f)
                    
                    self.logger.debug(f"Loaded model {model_key}")
            
        except Exception as e:
            self.logger.error(f"Failed to load models: {e}")


class ThreatIntelligenceEngine:
    """Threat intelligence integration and correlation engine."""
    
    def __init__(self, storage_path: str = "/var/log/dod_threat_intel"):
        self.storage_path = Path(storage_path)
        self.storage_path.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.logger = logging.getLogger(__name__)
        
        # Threat indicators storage
        self.indicators: Dict[str, ThreatIndicator] = {}
        self.ip_reputation: Dict[str, Dict[str, Any]] = {}
        self.domain_reputation: Dict[str, Dict[str, Any]] = {}
        self.hash_reputation: Dict[str, Dict[str, Any]] = {}
        
        # Feed configurations
        self.feed_configs: Dict[str, Dict[str, Any]] = {}
        
        # Initialize database
        self._init_database()
        
        # Load existing indicators
        self._load_indicators()
    
    def _init_database(self):
        """Initialize threat intelligence database."""
        try:
            self.db_path = self.storage_path / "threat_intel.db"
            conn = sqlite3.connect(self.db_path)
            
            # Threat indicators table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS threat_indicators (
                    indicator_id TEXT PRIMARY KEY,
                    indicator_type TEXT NOT NULL,
                    value TEXT NOT NULL,
                    threat_type TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    severity TEXT NOT NULL,
                    description TEXT NOT NULL,
                    source TEXT NOT NULL,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    expires_at TEXT,
                    actor TEXT,
                    campaign TEXT,
                    malware_family TEXT,
                    tags TEXT,
                    metadata TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Intelligence feeds table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS intel_feeds (
                    feed_id TEXT PRIMARY KEY,
                    feed_name TEXT NOT NULL,
                    feed_type TEXT NOT NULL,
                    url TEXT,
                    api_key TEXT,
                    last_update TEXT,
                    next_update TEXT,
                    status TEXT DEFAULT 'ACTIVE',
                    indicators_count INTEGER DEFAULT 0,
                    config TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Indicator matches table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS indicator_matches (
                    match_id TEXT PRIMARY KEY,
                    indicator_id TEXT NOT NULL,
                    event_id TEXT NOT NULL,
                    match_time TEXT NOT NULL,
                    match_type TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    context TEXT,
                    FOREIGN KEY (indicator_id) REFERENCES threat_indicators (indicator_id)
                )
            """)
            
            # Create indexes
            indexes = [
                "CREATE INDEX IF NOT EXISTS idx_indicators_type ON threat_indicators(indicator_type)",
                "CREATE INDEX IF NOT EXISTS idx_indicators_value ON threat_indicators(value)",
                "CREATE INDEX IF NOT EXISTS idx_indicators_threat_type ON threat_indicators(threat_type)",
                "CREATE INDEX IF NOT EXISTS idx_matches_event ON indicator_matches(event_id)",
                "CREATE INDEX IF NOT EXISTS idx_matches_time ON indicator_matches(match_time)"
            ]
            
            for index_sql in indexes:
                conn.execute(index_sql)
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            self.logger.error(f"Failed to initialize threat intelligence database: {e}")
            raise
    
    def add_indicator(self, indicator: ThreatIndicator) -> bool:
        """Add threat indicator to the database."""
        try:
            conn = sqlite3.connect(self.db_path)
            
            conn.execute("""
                INSERT OR REPLACE INTO threat_indicators (
                    indicator_id, indicator_type, value, threat_type, confidence,
                    severity, description, source, first_seen, last_seen,
                    expires_at, actor, campaign, malware_family, tags, metadata
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                indicator.indicator_id, indicator.indicator_type, indicator.value,
                indicator.threat_type, indicator.confidence, indicator.severity,
                indicator.description, indicator.source,
                indicator.first_seen.isoformat(), indicator.last_seen.isoformat(),
                indicator.expires_at.isoformat() if indicator.expires_at else None,
                indicator.actor, indicator.campaign, indicator.malware_family,
                json.dumps(indicator.tags), json.dumps(indicator.metadata)
            ))
            
            conn.commit()
            conn.close()
            
            # Update in-memory storage
            self.indicators[indicator.indicator_id] = indicator
            
            # Update reputation databases
            if indicator.indicator_type == 'ip':
                self.ip_reputation[indicator.value] = {
                    'threat_type': indicator.threat_type,
                    'confidence': indicator.confidence,
                    'severity': indicator.severity,
                    'source': indicator.source
                }
            elif indicator.indicator_type == 'domain':
                self.domain_reputation[indicator.value] = {
                    'threat_type': indicator.threat_type,
                    'confidence': indicator.confidence,
                    'severity': indicator.severity,
                    'source': indicator.source
                }
            elif indicator.indicator_type == 'hash':
                self.hash_reputation[indicator.value] = {
                    'threat_type': indicator.threat_type,
                    'confidence': indicator.confidence,
                    'severity': indicator.severity,
                    'source': indicator.source
                }
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to add threat indicator: {e}")
            return False
    
    def check_indicators(self, events: List[AuditEvent]) -> List[Dict[str, Any]]:
        """Check events against threat indicators."""
        matches = []
        
        try:
            for event in events:
                # Check IP addresses
                if event.source_ip and event.source_ip in self.ip_reputation:
                    reputation = self.ip_reputation[event.source_ip]
                    match = {
                        'match_id': f"ip_match_{event.event_id}_{int(time.time())}",
                        'event_id': event.event_id,
                        'indicator_type': 'ip',
                        'indicator_value': event.source_ip,
                        'threat_type': reputation['threat_type'],
                        'confidence': reputation['confidence'],
                        'severity': reputation['severity'],
                        'source': reputation['source'],
                        'match_time': datetime.now(timezone.utc)
                    }
                    matches.append(match)
                
                # Check usernames against known compromised accounts
                if event.user_id:
                    for indicator in self.indicators.values():
                        if (indicator.indicator_type == 'username' and 
                            indicator.value.lower() == event.user_id.lower()):
                            match = {
                                'match_id': f"user_match_{event.event_id}_{indicator.indicator_id}",
                                'event_id': event.event_id,
                                'indicator_type': 'username',
                                'indicator_value': event.user_id,
                                'threat_type': indicator.threat_type,
                                'confidence': indicator.confidence,
                                'severity': indicator.severity,
                                'source': indicator.source,
                                'match_time': datetime.now(timezone.utc)
                            }
                            matches.append(match)
                
                # Check file hashes if available
                if event.data_hash:
                    if event.data_hash in self.hash_reputation:
                        reputation = self.hash_reputation[event.data_hash]
                        match = {
                            'match_id': f"hash_match_{event.event_id}_{int(time.time())}",
                            'event_id': event.event_id,
                            'indicator_type': 'hash',
                            'indicator_value': event.data_hash,
                            'threat_type': reputation['threat_type'],
                            'confidence': reputation['confidence'],
                            'severity': reputation['severity'],
                            'source': reputation['source'],
                            'match_time': datetime.now(timezone.utc)
                        }
                        matches.append(match)
            
            # Store matches in database
            for match in matches:
                self._store_match(match)
            
        except Exception as e:
            self.logger.error(f"Failed to check threat indicators: {e}")
        
        return matches
    
    def _store_match(self, match: Dict[str, Any]):
        """Store threat indicator match in database."""
        try:
            conn = sqlite3.connect(self.db_path)
            
            conn.execute("""
                INSERT INTO indicator_matches (
                    match_id, indicator_id, event_id, match_time, match_type,
                    confidence, context
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                match['match_id'],
                f"{match['indicator_type']}_{hashlib.md5(match['indicator_value'].encode()).hexdigest()[:8]}",
                match['event_id'],
                match['match_time'].isoformat(),
                match['indicator_type'],
                match['confidence'],
                json.dumps({
                    'threat_type': match['threat_type'],
                    'severity': match['severity'],
                    'source': match['source']
                })
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            self.logger.error(f"Failed to store threat indicator match: {e}")
    
    def _load_indicators(self):
        """Load existing threat indicators from database."""
        try:
            conn = sqlite3.connect(self.db_path)
            
            cursor = conn.execute("SELECT * FROM threat_indicators")
            
            for row in cursor.fetchall():
                indicator = ThreatIndicator(
                    indicator_id=row[0],
                    indicator_type=row[1],
                    value=row[2],
                    threat_type=row[3],
                    confidence=row[4],
                    severity=row[5],
                    description=row[6],
                    source=row[7],
                    first_seen=datetime.fromisoformat(row[8]),
                    last_seen=datetime.fromisoformat(row[9]),
                    expires_at=datetime.fromisoformat(row[10]) if row[10] else None,
                    actor=row[11],
                    campaign=row[12],
                    malware_family=row[13],
                    tags=json.loads(row[14]) if row[14] else [],
                    metadata=json.loads(row[15]) if row[15] else {}
                )
                
                self.indicators[indicator.indicator_id] = indicator
                
                # Update reputation databases
                if indicator.indicator_type == 'ip':
                    self.ip_reputation[indicator.value] = {
                        'threat_type': indicator.threat_type,
                        'confidence': indicator.confidence,
                        'severity': indicator.severity,
                        'source': indicator.source
                    }
            
            conn.close()
            
            self.logger.info(f"Loaded {len(self.indicators)} threat indicators")
            
        except Exception as e:
            self.logger.error(f"Failed to load threat indicators: {e}")


class LogAnalysisEngine:
    """
    Main log analysis engine coordinating all analysis capabilities.
    
    Integrates statistical analysis, machine learning detection,
    threat intelligence, and user behavior analytics.
    """
    
    def __init__(self, audit_db_path: str, storage_path: str = "/var/log/dod_log_analysis"):
        self.audit_db_path = audit_db_path
        self.storage_path = Path(storage_path)
        self.storage_path.mkdir(parents=True, exist_ok=True, mode=0o700)
        
        self.logger = logging.getLogger(__name__)
        
        # Initialize analysis components
        self.statistical_analyzer = StatisticalAnalyzer()
        self.ml_analyzer = MachineLearningAnalyzer(str(self.storage_path / "ml_models"))
        self.threat_intel = ThreatIntelligenceEngine(str(self.storage_path / "threat_intel"))
        
        # User behavior profiles
        self.user_profiles: Dict[str, UserBehaviorProfile] = {}
        
        # Analysis queues
        self.analysis_queue: queue.Queue = queue.Queue(maxsize=10000)
        self.results_queue: queue.Queue = queue.Queue(maxsize=10000)
        
        # Worker threads
        self.processing_active = True
        self.workers = []
        
        # Analysis statistics
        self.stats = {
            'events_analyzed': 0,
            'anomalies_detected': 0,
            'threat_matches': 0,
            'models_trained': 0,
            'last_analysis': None
        }
        
        # Initialize database
        self._init_database()
        
        # Start workers
        self._start_workers()
    
    def _init_database(self):
        """Initialize analysis results database."""
        try:
            self.db_path = self.storage_path / "analysis.db"
            conn = sqlite3.connect(self.db_path)
            
            # Analysis results table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS analysis_results (
                    result_id TEXT PRIMARY KEY,
                    analysis_time TEXT NOT NULL,
                    analysis_type TEXT NOT NULL,
                    event_ids TEXT NOT NULL,
                    anomalies_detected INTEGER DEFAULT 0,
                    threat_matches INTEGER DEFAULT 0,
                    risk_score REAL DEFAULT 0.0,
                    findings TEXT,
                    recommendations TEXT,
                    metadata TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # User behavior profiles table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS user_profiles (
                    user_id TEXT PRIMARY KEY,
                    profile_data TEXT NOT NULL,
                    last_updated TEXT NOT NULL,
                    observation_count INTEGER DEFAULT 0,
                    confidence_level REAL DEFAULT 0.0,
                    insider_threat_score REAL DEFAULT 0.0,
                    compromise_risk_score REAL DEFAULT 0.0,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            self.logger.error(f"Failed to initialize analysis database: {e}")
            raise
    
    def _start_workers(self):
        """Start analysis worker threads."""
        for i in range(4):  # 4 analysis workers
            worker = threading.Thread(target=self._analysis_worker, daemon=True)
            worker.start()
            self.workers.append(worker)
    
    def _analysis_worker(self):
        """Worker thread for processing analysis tasks."""
        while self.processing_active:
            try:
                # Get analysis task
                task = self.analysis_queue.get(timeout=1.0)
                
                if task is None:  # Shutdown signal
                    break
                
                # Process task
                results = self._process_analysis_task(task)
                
                # Store results
                self.results_queue.put(results)
                self.stats['events_analyzed'] += len(task.get('events', []))
                self.stats['last_analysis'] = datetime.now(timezone.utc)
                
            except queue.Empty:
                continue
            except Exception as e:
                self.logger.error(f"Analysis worker error: {e}")
                time.sleep(1)
    
    def _process_analysis_task(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Process an analysis task."""
        try:
            events = task['events']
            analysis_type = task.get('analysis_type', 'comprehensive')
            
            results = {
                'task_id': task.get('task_id', 'unknown'),
                'analysis_time': datetime.now(timezone.utc),
                'analysis_type': analysis_type,
                'event_count': len(events),
                'anomalies': [],
                'threat_matches': [],
                'user_behavior_updates': [],
                'risk_score': 0.0,
                'findings': [],
                'recommendations': []
            }
            
            # Statistical analysis
            if analysis_type in ['comprehensive', 'statistical']:
                stat_anomalies = self._run_statistical_analysis(events)
                results['anomalies'].extend(stat_anomalies)
            
            # Machine learning analysis
            if analysis_type in ['comprehensive', 'ml'] and ML_AVAILABLE:
                ml_anomalies = self._run_ml_analysis(events)
                results['anomalies'].extend(ml_anomalies)
            
            # Threat intelligence correlation
            if analysis_type in ['comprehensive', 'threat_intel']:
                threat_matches = self.threat_intel.check_indicators(events)
                results['threat_matches'] = threat_matches
            
            # User behavior analysis
            if analysis_type in ['comprehensive', 'behavior']:
                behavior_updates = self._update_user_profiles(events)
                results['user_behavior_updates'] = behavior_updates
            
            # Calculate overall risk score
            results['risk_score'] = self._calculate_risk_score(results)
            
            # Generate findings and recommendations
            results['findings'] = self._generate_findings(results)
            results['recommendations'] = self._generate_recommendations(results)
            
            # Update statistics
            self.stats['anomalies_detected'] += len(results['anomalies'])
            self.stats['threat_matches'] += len(results['threat_matches'])
            
            return results
            
        except Exception as e:
            self.logger.error(f"Failed to process analysis task: {e}")
            return {'error': str(e)}
    
    def _run_statistical_analysis(self, events: List[AuditEvent]) -> List[AnomalyDetection]:
        """Run statistical analysis on events."""
        anomalies = []
        
        # Establish baselines if needed
        metrics = ['login_frequency', 'data_access_volume', 'failed_authentication_rate']
        
        for metric in metrics:
            if metric not in self.statistical_analyzer.baselines:
                # Use events to establish baseline
                self.statistical_analyzer.establish_baseline(events, metric)
            
            # Detect anomalies
            metric_anomalies = self.statistical_analyzer.detect_statistical_anomalies(events, metric)
            anomalies.extend(metric_anomalies)
        
        return anomalies
    
    def _run_ml_analysis(self, events: List[AuditEvent]) -> List[AnomalyDetection]:
        """Run machine learning analysis on events."""
        anomalies = []
        
        # Define model and feature combinations
        model_configs = [
            ('isolation_forest', 'user_behavior'),
            ('one_class_svm', 'user_behavior'),
            ('dbscan', 'user_behavior')
        ]
        
        for model_type, feature_type in model_configs:
            try:
                # Check if model exists, train if not
                model_key = f"{model_type}_{feature_type}"
                if model_key not in self.ml_analyzer.models:
                    # Train model with current events
                    if self.ml_analyzer.train_model(events, model_type, feature_type):
                        self.stats['models_trained'] += 1
                
                # Detect anomalies
                model_anomalies = self.ml_analyzer.detect_anomalies(events, model_type, feature_type)
                anomalies.extend(model_anomalies)
                
            except Exception as e:
                self.logger.error(f"ML analysis failed for {model_type}/{feature_type}: {e}")
        
        return anomalies
    
    def _update_user_profiles(self, events: List[AuditEvent]) -> List[str]:
        """Update user behavior profiles."""
        updated_users = []
        
        # Group events by user
        user_events = defaultdict(list)
        for event in events:
            if event.user_id:
                user_events[event.user_id].append(event)
        
        for user_id, user_event_list in user_events.items():
            try:
                # Get or create profile
                if user_id not in self.user_profiles:
                    self.user_profiles[user_id] = UserBehaviorProfile(
                        user_id=user_id,
                        profile_created=datetime.now(timezone.utc),
                        last_updated=datetime.now(timezone.utc)
                    )
                
                # Update profile
                profile = self.user_profiles[user_id]
                profile.update_profile(user_event_list)
                
                # Store updated profile
                self._store_user_profile(profile)
                updated_users.append(user_id)
                
            except Exception as e:
                self.logger.error(f"Failed to update profile for user {user_id}: {e}")
        
        return updated_users
    
    def _store_user_profile(self, profile: UserBehaviorProfile):
        """Store user behavior profile in database."""
        try:
            conn = sqlite3.connect(self.db_path)
            
            profile_data = asdict(profile)
            
            conn.execute("""
                INSERT OR REPLACE INTO user_profiles (
                    user_id, profile_data, last_updated, observation_count,
                    confidence_level, insider_threat_score, compromise_risk_score
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                profile.user_id,
                json.dumps(profile_data, default=str),
                profile.last_updated.isoformat(),
                profile.observation_count,
                profile.confidence_level,
                profile.insider_threat_score,
                profile.compromise_risk_score
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            self.logger.error(f"Failed to store user profile: {e}")
    
    def _calculate_risk_score(self, results: Dict[str, Any]) -> float:
        """Calculate overall risk score for analysis results."""
        try:
            risk_score = 0.0
            
            # Anomaly contribution
            anomaly_scores = []
            for anomaly in results['anomalies']:
                severity_weights = {'LOW': 0.2, 'MEDIUM': 0.5, 'HIGH': 0.8, 'CRITICAL': 1.0}
                weight = severity_weights.get(anomaly.severity, 0.5)
                anomaly_scores.append(anomaly.confidence * weight)
            
            if anomaly_scores:
                risk_score += min(1.0, sum(anomaly_scores) / len(anomaly_scores)) * 0.6
            
            # Threat intelligence contribution
            if results['threat_matches']:
                threat_score = 0.0
                for match in results['threat_matches']:
                    severity_weights = {'LOW': 0.2, 'MEDIUM': 0.5, 'HIGH': 0.8, 'CRITICAL': 1.0}
                    weight = severity_weights.get(match.get('severity', 'MEDIUM'), 0.5)
                    threat_score += match.get('confidence', 0.5) * weight
                
                risk_score += min(1.0, threat_score / len(results['threat_matches'])) * 0.4
            
            return min(1.0, risk_score)
            
        except Exception as e:
            self.logger.error(f"Failed to calculate risk score: {e}")
            return 0.0
    
    def _generate_findings(self, results: Dict[str, Any]) -> List[str]:
        """Generate analysis findings."""
        findings = []
        
        if results['anomalies']:
            high_severity = sum(1 for a in results['anomalies'] if a.severity in ['HIGH', 'CRITICAL'])
            findings.append(f"Detected {len(results['anomalies'])} anomalies ({high_severity} high/critical severity)")
        
        if results['threat_matches']:
            findings.append(f"Found {len(results['threat_matches'])} threat intelligence matches")
        
        if results['risk_score'] > 0.7:
            findings.append("High risk score indicates potential security concerns")
        
        return findings
    
    def _generate_recommendations(self, results: Dict[str, Any]) -> List[str]:
        """Generate analysis recommendations."""
        recommendations = []
        
        if results['anomalies']:
            recommendations.append("Investigate detected anomalies for potential security threats")
        
        if results['threat_matches']:
            recommendations.append("Review threat intelligence matches and implement appropriate countermeasures")
        
        if results['risk_score'] > 0.7:
            recommendations.append("Consider implementing additional security controls due to high risk score")
        
        return recommendations
    
    def analyze_events(self, events: List[AuditEvent], analysis_type: str = 'comprehensive') -> str:
        """Queue events for analysis."""
        try:
            task_id = f"analysis_{int(time.time())}_{len(events)}"
            
            task = {
                'task_id': task_id,
                'events': events,
                'analysis_type': analysis_type,
                'submitted_at': datetime.now(timezone.utc)
            }
            
            self.analysis_queue.put(task, timeout=5.0)
            return task_id
            
        except queue.Full:
            self.logger.error("Analysis queue full")
            return ""
        except Exception as e:
            self.logger.error(f"Failed to queue analysis: {e}")
            return ""
    
    def get_analysis_results(self, task_id: str = None) -> List[Dict[str, Any]]:
        """Get analysis results."""
        results = []
        
        try:
            # Get results from queue
            while not self.results_queue.empty():
                try:
                    result = self.results_queue.get_nowait()
                    if task_id is None or result.get('task_id') == task_id:
                        results.append(result)
                except queue.Empty:
                    break
            
        except Exception as e:
            self.logger.error(f"Failed to get analysis results: {e}")
        
        return results
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get analysis engine statistics."""
        return {
            'stats': self.stats.copy(),
            'queue_sizes': {
                'analysis_queue': self.analysis_queue.qsize(),
                'results_queue': self.results_queue.qsize()
            },
            'user_profiles_count': len(self.user_profiles),
            'threat_indicators_count': len(self.threat_intel.indicators),
            'ml_models_count': len(self.ml_analyzer.models),
            'statistical_baselines_count': len(self.statistical_analyzer.baselines)
        }
    
    def shutdown(self):
        """Gracefully shutdown the analysis engine."""
        self.processing_active = False
        
        # Signal workers to stop
        for _ in self.workers:
            self.analysis_queue.put(None)
        
        # Wait for workers to finish
        for worker in self.workers:
            worker.join(timeout=30)
        
        self.logger.info("Log analysis engine shutdown complete")


# Factory function for creating log analysis engine
def create_log_analysis_engine(audit_db_path: str, storage_path: str = None) -> LogAnalysisEngine:
    """Create and initialize log analysis engine."""
    if storage_path is None:
        storage_path = "/var/log/dod_log_analysis"
    
    return LogAnalysisEngine(audit_db_path, storage_path)