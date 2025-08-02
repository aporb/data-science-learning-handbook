"""
Advanced Performance Monitoring with Real-time Alerts

This module provides comprehensive performance monitoring for the DoD API Gateway
with advanced analytics, predictive capabilities, and real-time alerting.

Key Features:
- Real-time performance metrics collection and analysis
- Predictive performance degradation detection
- Advanced alerting with intelligent escalation
- Capacity planning and resource optimization
- Performance baseline establishment and drift detection
- Integration with monitoring and observability platforms
- DoD-compliant performance reporting

Performance Metrics:
- Response time percentiles (P50, P95, P99, P99.9)
- Throughput and request rate monitoring
- Error rate tracking and categorization
- Resource utilization (CPU, memory, network, disk)
- Database performance metrics
- Cache efficiency and hit ratios
- Circuit breaker and load balancer metrics

Security Standards:
- DoD performance monitoring requirements
- NIST 800-53 performance controls
- Real-time security performance correlation
- Performance audit trail maintenance
"""

import asyncio
import json
import logging
import time
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple, Union, Callable
from dataclasses import dataclass, asdict
from enum import Enum
from collections import defaultdict, deque
import statistics
import math

import asyncio
import aioredis
import numpy as np
import pandas as pd
from scipy import stats
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import psutil

# Import from existing modules
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from audits.audit_logger import AuditLogger
from monitoring.prometheus_integration import PrometheusMetrics
from monitoring.security_alerting import SecurityAlertManager


class PerformanceMetricType(Enum):
    """Types of performance metrics."""
    RESPONSE_TIME = "response_time"
    THROUGHPUT = "throughput"
    ERROR_RATE = "error_rate"
    CPU_UTILIZATION = "cpu_utilization"
    MEMORY_UTILIZATION = "memory_utilization"
    DISK_UTILIZATION = "disk_utilization"
    NETWORK_UTILIZATION = "network_utilization"
    DATABASE_LATENCY = "database_latency"
    CACHE_HIT_RATIO = "cache_hit_ratio"
    QUEUE_DEPTH = "queue_depth"
    CONNECTION_COUNT = "connection_count"
    CIRCUIT_BREAKER_STATE = "circuit_breaker_state"


class AlertSeverity(Enum):
    """Performance alert severity levels."""
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"
    EMERGENCY = "emergency"


class AlertCondition(Enum):
    """Alert condition types."""
    THRESHOLD_EXCEEDED = "threshold_exceeded"
    THRESHOLD_BELOW = "threshold_below"
    RATE_OF_CHANGE = "rate_of_change"
    ANOMALY_DETECTED = "anomaly_detected"
    PREDICTION_BREACH = "prediction_breach"
    BASELINE_DEVIATION = "baseline_deviation"


class PerformanceStatus(Enum):
    """Overall performance status."""
    OPTIMAL = "optimal"
    GOOD = "good"
    DEGRADED = "degraded"
    CRITICAL = "critical"
    FAILING = "failing"


@dataclass
class PerformanceMetric:
    """Performance metric data point."""
    metric_id: str
    metric_type: PerformanceMetricType
    value: float
    timestamp: datetime
    component: str
    tags: Dict[str, str] = None
    percentile: Optional[float] = None
    
    def __post_init__(self):
        if self.tags is None:
            self.tags = {}


@dataclass
class PerformanceThreshold:
    """Performance threshold configuration."""
    threshold_id: str
    metric_type: PerformanceMetricType
    component: str
    warning_threshold: float
    critical_threshold: float
    emergency_threshold: Optional[float]
    condition: AlertCondition
    evaluation_window: int  # seconds
    min_samples: int = 5
    enabled: bool = True


@dataclass
class PerformanceAlert:
    """Performance alert definition."""
    alert_id: str
    metric_type: PerformanceMetricType
    component: str
    severity: AlertSeverity
    condition: AlertCondition
    current_value: float
    threshold_value: float
    message: str
    triggered_at: datetime
    resolved_at: Optional[datetime] = None
    escalated: bool = False
    acknowledgements: List[str] = None
    
    def __post_init__(self):
        if self.acknowledgements is None:
            self.acknowledgements = []


@dataclass
class PerformanceBaseline:
    """Performance baseline for a metric."""
    baseline_id: str
    metric_type: PerformanceMetricType
    component: str
    baseline_value: float
    standard_deviation: float
    confidence_interval: Tuple[float, float]
    sample_count: int
    established_at: datetime
    valid_until: datetime


class PerformancePredictor:
    """Predicts performance issues using machine learning."""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.models = {}
        self.scalers = {}
        
    async def train_prediction_model(self, metric_type: PerformanceMetricType,
                                   historical_data: List[PerformanceMetric]) -> bool:
        """Train prediction model for a performance metric."""
        try:
            if len(historical_data) < 100:  # Need sufficient data
                return False
            
            # Prepare data
            df = pd.DataFrame([
                {
                    'timestamp': m.timestamp,
                    'value': m.value,
                    'hour': m.timestamp.hour,
                    'day_of_week': m.timestamp.weekday(),
                    'minute': m.timestamp.minute
                }
                for m in historical_data
            ])
            
            # Sort by timestamp
            df = df.sort_values('timestamp')
            
            # Create features
            df['value_lag1'] = df['value'].shift(1)
            df['value_lag2'] = df['value'].shift(2)
            df['value_lag3'] = df['value'].shift(3)
            df['rolling_mean_10'] = df['value'].rolling(window=10).mean()
            df['rolling_std_10'] = df['value'].rolling(window=10).std()
            
            # Remove rows with NaN values
            df = df.dropna()
            
            if len(df) < 50:
                return False
            
            # Prepare features and target
            feature_columns = ['hour', 'day_of_week', 'minute', 'value_lag1', 'value_lag2', 'value_lag3', 'rolling_mean_10', 'rolling_std_10']
            X = df[feature_columns].values
            y = df['value'].values
            
            # Scale features
            scaler = StandardScaler()
            X_scaled = scaler.fit_transform(X)
            
            # Train anomaly detection model
            isolation_forest = IsolationForest(contamination=0.1, random_state=42)
            isolation_forest.fit(X_scaled)
            
            # Store models
            self.models[metric_type] = isolation_forest
            self.scalers[metric_type] = scaler
            
            self.logger.info(f\"Prediction model trained for {metric_type.value}")
            return True
            
        except Exception as e:
            self.logger.error(f\"Failed to train prediction model for {metric_type.value}: {e}")
            return False
    
    async def predict_anomaly(self, metric_type: PerformanceMetricType,
                            current_metrics: List[PerformanceMetric]) -> Tuple[bool, float]:
        """Predict if current metrics indicate an anomaly."""
        try:
            if metric_type not in self.models or len(current_metrics) < 10:
                return False, 0.0
            
            # Prepare current data
            df = pd.DataFrame([
                {
                    'timestamp': m.timestamp,
                    'value': m.value,
                    'hour': m.timestamp.hour,
                    'day_of_week': m.timestamp.weekday(),
                    'minute': m.timestamp.minute
                }
                for m in current_metrics
            ])
            
            df = df.sort_values('timestamp')
            
            # Create features (using the same logic as training)
            df['value_lag1'] = df['value'].shift(1)
            df['value_lag2'] = df['value'].shift(2)
            df['value_lag3'] = df['value'].shift(3)
            df['rolling_mean_10'] = df['value'].rolling(window=10).mean()
            df['rolling_std_10'] = df['value'].rolling(window=10).std()
            
            # Get the last complete row
            last_row = df.dropna().iloc[-1:] if len(df.dropna()) > 0 else None
            if last_row is None:
                return False, 0.0
            
            feature_columns = ['hour', 'day_of_week', 'minute', 'value_lag1', 'value_lag2', 'value_lag3', 'rolling_mean_10', 'rolling_std_10']
            X = last_row[feature_columns].values
            
            # Scale features
            scaler = self.scalers[metric_type]
            X_scaled = scaler.transform(X)
            
            # Predict
            model = self.models[metric_type]
            prediction = model.predict(X_scaled)
            anomaly_score = model.decision_function(X_scaled)[0]
            
            is_anomaly = prediction[0] == -1
            confidence = abs(anomaly_score)
            
            return is_anomaly, confidence
            
        except Exception as e:
            self.logger.error(f\"Anomaly prediction failed for {metric_type.value}: {e}")
            return False, 0.0
    
    async def predict_future_values(self, metric_type: PerformanceMetricType,
                                  historical_data: List[PerformanceMetric],
                                  prediction_horizon: int = 300) -> List[Tuple[datetime, float]]:
        """Predict future metric values."""
        try:
            if len(historical_data) < 50:
                return []
            
            # Simple linear extrapolation for now
            # In production, would use more sophisticated time series models
            
            # Sort data by timestamp
            sorted_data = sorted(historical_data, key=lambda x: x.timestamp)
            
            # Get recent trend
            recent_data = sorted_data[-20:]  # Last 20 data points
            
            if len(recent_data) < 10:
                return []
            
            # Calculate trend
            timestamps = [(d.timestamp - recent_data[0].timestamp).total_seconds() for d in recent_data]
            values = [d.value for d in recent_data]
            
            # Linear regression
            slope, intercept, r_value, p_value, std_err = stats.linregress(timestamps, values)
            
            # Generate predictions
            predictions = []
            last_timestamp = sorted_data[-1].timestamp
            
            for i in range(1, prediction_horizon // 60 + 1):  # Predict every minute
                future_timestamp = last_timestamp + timedelta(minutes=i)
                future_seconds = (future_timestamp - recent_data[0].timestamp).total_seconds()
                predicted_value = slope * future_seconds + intercept
                
                predictions.append((future_timestamp, predicted_value))
            
            return predictions
            
        except Exception as e:
            self.logger.error(f\"Future value prediction failed for {metric_type.value}: {e}")
            return []


class PerformanceBaseliner:
    """Establishes and maintains performance baselines."""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.baselines: Dict[str, PerformanceBaseline] = {}
    
    async def establish_baseline(self, metric_type: PerformanceMetricType,
                               component: str,
                               historical_data: List[PerformanceMetric],
                               validity_days: int = 30) -> Optional[PerformanceBaseline]:
        """Establish performance baseline for a metric."""
        try:
            if len(historical_data) < 100:  # Need sufficient data
                return None
            
            # Filter data for the specific metric and component
            filtered_data = [
                m for m in historical_data
                if m.metric_type == metric_type and m.component == component
            ]
            
            if len(filtered_data) < 100:
                return None
            
            # Calculate baseline statistics
            values = [m.value for m in filtered_data]
            
            baseline_value = statistics.mean(values)
            standard_deviation = statistics.stdev(values)
            
            # Calculate confidence interval (95%)
            confidence_interval = (
                baseline_value - 1.96 * standard_deviation,
                baseline_value + 1.96 * standard_deviation
            )
            
            # Create baseline
            baseline_id = f\"{metric_type.value}_{component}_{int(time.time())}"
            baseline = PerformanceBaseline(
                baseline_id=baseline_id,
                metric_type=metric_type,
                component=component,
                baseline_value=baseline_value,
                standard_deviation=standard_deviation,
                confidence_interval=confidence_interval,
                sample_count=len(filtered_data),
                established_at=datetime.utcnow(),
                valid_until=datetime.utcnow() + timedelta(days=validity_days)
            )
            
            # Store baseline
            baseline_key = f\"{metric_type.value}_{component}"
            self.baselines[baseline_key] = baseline
            
            self.logger.info(f\"Baseline established for {metric_type.value} on {component}: {baseline_value:.2f} ± {standard_deviation:.2f}")
            
            return baseline
            
        except Exception as e:
            self.logger.error(f\"Failed to establish baseline for {metric_type.value} on {component}: {e}")
            return None
    
    async def check_baseline_deviation(self, metric: PerformanceMetric) -> Tuple[bool, float]:
        """Check if metric deviates significantly from baseline."""
        try:
            baseline_key = f\"{metric.metric_type.value}_{metric.component}"
            baseline = self.baselines.get(baseline_key)
            
            if not baseline or datetime.utcnow() > baseline.valid_until:
                return False, 0.0  # No valid baseline
            
            # Calculate deviation in standard deviations
            deviation = abs(metric.value - baseline.baseline_value) / baseline.standard_deviation
            
            # Consider significant if more than 2 standard deviations
            is_significant = deviation > 2.0
            
            return is_significant, deviation
            
        except Exception as e:
            self.logger.error(f\"Baseline deviation check failed: {e}")
            return False, 0.0
    
    def get_baseline(self, metric_type: PerformanceMetricType, component: str) -> Optional[PerformanceBaseline]:
        """Get current baseline for metric and component."""
        baseline_key = f\"{metric_type.value}_{component}"
        baseline = self.baselines.get(baseline_key)
        
        if baseline and datetime.utcnow() <= baseline.valid_until:
            return baseline
        return None


class AdvancedPerformanceMonitor:
    """
    Advanced Performance Monitoring System
    
    Provides comprehensive performance monitoring with predictive analytics,
    intelligent alerting, and automated baseline management.
    """
    
    def __init__(self, redis_url: str = "redis://localhost:6379"):
        """Initialize advanced performance monitor."""
        self.logger = logging.getLogger(__name__)
        self.redis_client = None
        self.redis_url = redis_url
        
        # Components
        self.predictor = PerformancePredictor()
        self.baseliner = PerformanceBaseliner()
        
        # Metrics storage
        self.metrics_buffer: deque = deque(maxlen=50000)
        self.alerts_buffer: deque = deque(maxlen=10000)
        
        # Thresholds
        self.thresholds: Dict[str, PerformanceThreshold] = {}
        self.active_alerts: Dict[str, PerformanceAlert] = {}
        
        # Integration components
        self.audit_logger = None
        self.prometheus_metrics = None
        self.alert_manager = None
        
        # Monitoring state
        self.monitoring_active = False
        self.last_prediction_update = None
        
    async def initialize(self) -> None:
        """Initialize performance monitor."""
        try:
            # Initialize Redis client
            self.redis_client = await aioredis.from_url(self.redis_url)
            await self.redis_client.ping()
            
            # Initialize integration components
            try:
                self.audit_logger = AuditLogger()
                await self.audit_logger.initialize()
            except Exception as e:
                self.logger.warning(f\"Audit logger initialization failed: {e}")
            
            try:
                self.prometheus_metrics = PrometheusMetrics()
            except Exception as e:
                self.logger.warning(f\"Prometheus metrics initialization failed: {e}")
            
            try:
                self.alert_manager = SecurityAlertManager()
                await self.alert_manager.initialize()
            except Exception as e:
                self.logger.warning(f\"Alert manager initialization failed: {e}")
            
            # Load existing thresholds and baselines
            await self._load_thresholds()
            await self._load_baselines()
            
            # Setup default thresholds if none exist
            if not self.thresholds:
                await self._setup_default_thresholds()
            
            # Start background monitoring tasks
            asyncio.create_task(self._monitoring_loop())
            asyncio.create_task(self._prediction_loop())
            asyncio.create_task(self._baseline_maintenance_loop())
            asyncio.create_task(self._alert_escalation_loop())
            
            self.monitoring_active = True
            self.logger.info("Advanced performance monitor initialized")
            
        except Exception as e:
            self.logger.error(f\"Failed to initialize performance monitor: {e}")
            raise
    
    async def _load_thresholds(self) -> None:
        """Load performance thresholds from storage."""
        try:
            thresholds_data = await self.redis_client.get("performance_thresholds")
            if thresholds_data:
                thresholds_dict = json.loads(thresholds_data)
                for threshold_id, threshold_data in thresholds_dict.items():
                    threshold = PerformanceThreshold(**threshold_data)
                    threshold.metric_type = PerformanceMetricType(threshold_data['metric_type'])
                    threshold.condition = AlertCondition(threshold_data['condition'])
                    self.thresholds[threshold_id] = threshold
                    
        except Exception as e:
            self.logger.error(f\"Failed to load thresholds: {e}")
    
    async def _load_baselines(self) -> None:
        """Load performance baselines from storage."""
        try:
            baselines_data = await self.redis_client.get("performance_baselines")
            if baselines_data:
                baselines_dict = json.loads(baselines_data)
                for baseline_key, baseline_data in baselines_dict.items():
                    baseline = PerformanceBaseline(**baseline_data)
                    baseline.metric_type = PerformanceMetricType(baseline_data['metric_type'])
                    baseline.established_at = datetime.fromisoformat(baseline_data['established_at'])
                    baseline.valid_until = datetime.fromisoformat(baseline_data['valid_until'])
                    self.baseliner.baselines[baseline_key] = baseline
                    
        except Exception as e:
            self.logger.error(f\"Failed to load baselines: {e}")
    
    async def _setup_default_thresholds(self) -> None:
        """Setup default performance thresholds."""
        default_thresholds = [
            PerformanceThreshold(
                threshold_id="response_time_api_gateway",
                metric_type=PerformanceMetricType.RESPONSE_TIME,
                component="api_gateway",
                warning_threshold=2.0,
                critical_threshold=5.0,
                emergency_threshold=10.0,
                condition=AlertCondition.THRESHOLD_EXCEEDED,
                evaluation_window=300
            ),
            PerformanceThreshold(
                threshold_id="cpu_utilization_api_gateway",
                metric_type=PerformanceMetricType.CPU_UTILIZATION,
                component="api_gateway",
                warning_threshold=70.0,
                critical_threshold=85.0,
                emergency_threshold=95.0,
                condition=AlertCondition.THRESHOLD_EXCEEDED,
                evaluation_window=300
            ),
            PerformanceThreshold(
                threshold_id="memory_utilization_api_gateway",
                metric_type=PerformanceMetricType.MEMORY_UTILIZATION,
                component="api_gateway",
                warning_threshold=75.0,
                critical_threshold=90.0,
                emergency_threshold=98.0,
                condition=AlertCondition.THRESHOLD_EXCEEDED,
                evaluation_window=300
            ),
            PerformanceThreshold(
                threshold_id="error_rate_api_gateway",
                metric_type=PerformanceMetricType.ERROR_RATE,
                component="api_gateway",
                warning_threshold=2.0,
                critical_threshold=5.0,
                emergency_threshold=10.0,
                condition=AlertCondition.THRESHOLD_EXCEEDED,
                evaluation_window=300
            ),
            PerformanceThreshold(
                threshold_id="throughput_api_gateway",
                metric_type=PerformanceMetricType.THROUGHPUT,
                component="api_gateway",
                warning_threshold=50.0,  # Below 50 requests/sec
                critical_threshold=20.0,
                emergency_threshold=10.0,
                condition=AlertCondition.THRESHOLD_BELOW,
                evaluation_window=300
            )
        ]
        
        for threshold in default_thresholds:
            await self.add_threshold(threshold)
    
    async def add_threshold(self, threshold: PerformanceThreshold) -> bool:
        """Add performance threshold."""
        try:
            self.thresholds[threshold.threshold_id] = threshold
            await self._save_thresholds()
            
            self.logger.info(f\"Performance threshold added: {threshold.threshold_id}")
            return True
            
        except Exception as e:
            self.logger.error(f\"Failed to add threshold: {e}")
            return False
    
    async def _save_thresholds(self) -> None:
        """Save thresholds to storage."""
        try:
            thresholds_dict = {}
            for threshold_id, threshold in self.thresholds.items():
                threshold_data = asdict(threshold)
                threshold_data['metric_type'] = threshold.metric_type.value
                threshold_data['condition'] = threshold.condition.value
                thresholds_dict[threshold_id] = threshold_data
            
            await self.redis_client.set("performance_thresholds", json.dumps(thresholds_dict))
            
        except Exception as e:
            self.logger.error(f\"Failed to save thresholds: {e}")
    
    async def record_metric(self, metric_type: PerformanceMetricType,
                          component: str, value: float,
                          tags: Optional[Dict[str, str]] = None,
                          percentile: Optional[float] = None) -> None:
        """Record a performance metric."""
        try:
            metric = PerformanceMetric(
                metric_id=str(uuid.uuid4()),
                metric_type=metric_type,
                value=value,
                timestamp=datetime.utcnow(),
                component=component,
                tags=tags or {},
                percentile=percentile
            )
            
            # Store metric
            self.metrics_buffer.append(metric)
            
            # Store in Redis for persistence
            metric_data = asdict(metric)
            metric_data['metric_type'] = metric.metric_type.value
            metric_data['timestamp'] = metric.timestamp.isoformat()
            
            await self.redis_client.lpush(
                f\"performance_metrics:{metric_type.value}:{component}",
                json.dumps(metric_data)
            )
            await self.redis_client.ltrim(
                f\"performance_metrics:{metric_type.value}:{component}",
                0, 10000
            )
            
            # Update Prometheus metrics if available
            if self.prometheus_metrics:
                await self._update_prometheus_metrics(metric)
            
            # Check thresholds
            await self._check_thresholds(metric)
            
            # Check baseline deviation
            await self._check_baseline_deviation(metric)
            
            self.logger.debug(f\"Recorded {metric_type.value} metric for {component}: {value}")
            
        except Exception as e:
            self.logger.error(f\"Failed to record metric: {e}")
    
    async def _update_prometheus_metrics(self, metric: PerformanceMetric) -> None:
        """Update Prometheus metrics."""
        try:
            # This would update Prometheus metrics based on the performance metric
            # Implementation depends on the specific Prometheus metrics structure
            pass
        except Exception as e:
            self.logger.error(f\"Failed to update Prometheus metrics: {e}")
    
    async def _check_thresholds(self, metric: PerformanceMetric) -> None:
        """Check metric against configured thresholds."""
        try:
            # Find applicable thresholds
            applicable_thresholds = [
                t for t in self.thresholds.values()
                if (t.metric_type == metric.metric_type and
                   t.component == metric.component and
                   t.enabled)
            ]
            
            for threshold in applicable_thresholds:
                # Get recent metrics for evaluation
                recent_metrics = [
                    m for m in self.metrics_buffer
                    if (m.metric_type == metric.metric_type and
                       m.component == metric.component and
                       (metric.timestamp - m.timestamp).total_seconds() <= threshold.evaluation_window)
                ]
                
                if len(recent_metrics) < threshold.min_samples:
                    continue
                
                # Evaluate threshold
                alert = await self._evaluate_threshold(threshold, recent_metrics, metric)
                if alert:
                    await self._trigger_alert(alert)
                    
        except Exception as e:
            self.logger.error(f\"Threshold check failed: {e}")
    
    async def _evaluate_threshold(self, threshold: PerformanceThreshold,
                                recent_metrics: List[PerformanceMetric],
                                current_metric: PerformanceMetric) -> Optional[PerformanceAlert]:
        """Evaluate threshold against recent metrics."""
        try:
            values = [m.value for m in recent_metrics]
            
            # Determine threshold value and severity
            if threshold.condition == AlertCondition.THRESHOLD_EXCEEDED:
                if threshold.emergency_threshold and current_metric.value >= threshold.emergency_threshold:
                    severity = AlertSeverity.EMERGENCY
                    threshold_value = threshold.emergency_threshold
                elif current_metric.value >= threshold.critical_threshold:
                    severity = AlertSeverity.CRITICAL
                    threshold_value = threshold.critical_threshold
                elif current_metric.value >= threshold.warning_threshold:
                    severity = AlertSeverity.WARNING
                    threshold_value = threshold.warning_threshold
                else:
                    return None
                    
            elif threshold.condition == AlertCondition.THRESHOLD_BELOW:
                if threshold.emergency_threshold and current_metric.value <= threshold.emergency_threshold:
                    severity = AlertSeverity.EMERGENCY
                    threshold_value = threshold.emergency_threshold
                elif current_metric.value <= threshold.critical_threshold:
                    severity = AlertSeverity.CRITICAL
                    threshold_value = threshold.critical_threshold
                elif current_metric.value <= threshold.warning_threshold:
                    severity = AlertSeverity.WARNING
                    threshold_value = threshold.warning_threshold
                else:
                    return None
                    
            elif threshold.condition == AlertCondition.RATE_OF_CHANGE:
                # Check rate of change
                if len(values) < 2:
                    return None
                
                rate_of_change = (values[-1] - values[0]) / len(values)
                if abs(rate_of_change) >= threshold.warning_threshold:
                    severity = AlertSeverity.WARNING if abs(rate_of_change) < threshold.critical_threshold else AlertSeverity.CRITICAL
                    threshold_value = threshold.warning_threshold
                else:
                    return None
            else:
                return None
            
            # Create alert
            alert_id = f\"{threshold.threshold_id}_{int(time.time())}"
            
            # Check if similar alert is already active
            existing_alert_key = f\"{threshold.metric_type.value}_{threshold.component}_{severity.value}"
            if existing_alert_key in self.active_alerts:
                return None  # Don't duplicate alerts
            
            alert = PerformanceAlert(
                alert_id=alert_id,
                metric_type=threshold.metric_type,
                component=threshold.component,
                severity=severity,
                condition=threshold.condition,
                current_value=current_metric.value,
                threshold_value=threshold_value,
                message=self._generate_alert_message(threshold, current_metric, severity),
                triggered_at=current_metric.timestamp
            )
            
            return alert
            
        except Exception as e:
            self.logger.error(f\"Threshold evaluation failed: {e}")
            return None
    
    def _generate_alert_message(self, threshold: PerformanceThreshold,
                              metric: PerformanceMetric,
                              severity: AlertSeverity) -> str:
        """Generate alert message."""
        condition_text = {
            AlertCondition.THRESHOLD_EXCEEDED: "exceeded",
            AlertCondition.THRESHOLD_BELOW: "fell below",
            AlertCondition.RATE_OF_CHANGE: "changed rapidly",
            AlertCondition.ANOMALY_DETECTED: "anomaly detected",
            AlertCondition.PREDICTION_BREACH: "predicted to breach",
            AlertCondition.BASELINE_DEVIATION: "deviated from baseline"
        }.get(threshold.condition, "violated")
        
        return (f\"{severity.value.upper()}: {threshold.metric_type.value} on {threshold.component} "
               f\"{condition_text} threshold. Current: {metric.value:.2f}, "
               f\"Threshold: {threshold.warning_threshold:.2f}")
    
    async def _trigger_alert(self, alert: PerformanceAlert) -> None:
        """Trigger performance alert."""
        try:
            # Store alert
            alert_key = f\"{alert.metric_type.value}_{alert.component}_{alert.severity.value}"
            self.active_alerts[alert_key] = alert
            self.alerts_buffer.append(alert)
            
            # Store in Redis
            alert_data = asdict(alert)
            alert_data['metric_type'] = alert.metric_type.value
            alert_data['severity'] = alert.severity.value
            alert_data['condition'] = alert.condition.value
            alert_data['triggered_at'] = alert.triggered_at.isoformat()
            
            await self.redis_client.lpush("performance_alerts", json.dumps(alert_data))
            await self.redis_client.ltrim("performance_alerts", 0, 10000)
            
            # Log to audit system
            if self.audit_logger:
                await self.audit_logger.log_event(
                    event_type="performance_alert",
                    severity=alert.severity.value,
                    details={
                        'alert_id': alert.alert_id,
                        'metric_type': alert.metric_type.value,
                        'component': alert.component,
                        'current_value': alert.current_value,
                        'threshold_value': alert.threshold_value,
                        'message': alert.message
                    }
                )
            
            # Send to alert manager
            if self.alert_manager:
                await self.alert_manager.send_alert({
                    'type': 'performance',
                    'severity': alert.severity.value,
                    'title': f\"Performance Alert: {alert.metric_type.value}",
                    'message': alert.message,
                    'component': alert.component,
                    'timestamp': alert.triggered_at.isoformat()
                })
            
            self.logger.warning(f\"Performance alert triggered: {alert.message}")
            
        except Exception as e:
            self.logger.error(f\"Failed to trigger alert: {e}")
    
    async def _check_baseline_deviation(self, metric: PerformanceMetric) -> None:
        """Check metric for baseline deviation."""
        try:
            is_significant, deviation = await self.baseliner.check_baseline_deviation(metric)
            
            if is_significant:
                alert = PerformanceAlert(
                    alert_id=str(uuid.uuid4()),
                    metric_type=metric.metric_type,
                    component=metric.component,
                    severity=AlertSeverity.WARNING if deviation < 3.0 else AlertSeverity.CRITICAL,
                    condition=AlertCondition.BASELINE_DEVIATION,
                    current_value=metric.value,
                    threshold_value=deviation,
                    message=f\"Baseline deviation detected: {metric.metric_type.value} on {metric.component} deviates {deviation:.1f} standard deviations from baseline\",
                    triggered_at=metric.timestamp
                )
                
                await self._trigger_alert(alert)
                
        except Exception as e:
            self.logger.error(f\"Baseline deviation check failed: {e}")
    
    async def _monitoring_loop(self) -> None:
        """Background monitoring loop."""
        while True:
            try:
                if self.monitoring_active:
                    await self._collect_system_metrics()
                
                await asyncio.sleep(30)  # Collect every 30 seconds
                
            except Exception as e:
                self.logger.error(f\"Monitoring loop error: {e}")
                await asyncio.sleep(30)
    
    async def _collect_system_metrics(self) -> None:
        """Collect system performance metrics."""
        try:
            # CPU utilization
            cpu_percent = psutil.cpu_percent(interval=1)
            await self.record_metric(PerformanceMetricType.CPU_UTILIZATION, "system", cpu_percent)
            
            # Memory utilization
            memory = psutil.virtual_memory()
            await self.record_metric(PerformanceMetricType.MEMORY_UTILIZATION, "system", memory.percent)
            
            # Disk utilization
            disk = psutil.disk_usage('/')
            disk_percent = (disk.used / disk.total) * 100
            await self.record_metric(PerformanceMetricType.DISK_UTILIZATION, "system", disk_percent)
            
            # Network utilization
            network = psutil.net_io_counters()
            network_mb_per_sec = (network.bytes_sent + network.bytes_recv) / (1024 * 1024)
            await self.record_metric(PerformanceMetricType.NETWORK_UTILIZATION, "system", network_mb_per_sec)
            
        except Exception as e:
            self.logger.error(f\"System metrics collection failed: {e}")
    
    async def _prediction_loop(self) -> None:
        """Background prediction loop."""
        while True:
            try:
                if self.monitoring_active:
                    await self._run_predictions()
                
                await asyncio.sleep(1800)  # Run every 30 minutes
                
            except Exception as e:
                self.logger.error(f\"Prediction loop error: {e}")
                await asyncio.sleep(1800)
    
    async def _run_predictions(self) -> None:
        """Run predictive analysis on performance metrics."""
        try:
            current_time = datetime.utcnow()
            
            # Group metrics by type and component
            metric_groups = defaultdict(list)
            
            # Get last 24 hours of metrics
            cutoff_time = current_time - timedelta(hours=24)
            recent_metrics = [
                m for m in self.metrics_buffer
                if m.timestamp >= cutoff_time
            ]
            
            for metric in recent_metrics:
                key = f\"{metric.metric_type.value}_{metric.component}"
                metric_groups[key].append(metric)
            
            # Run predictions for each group
            for group_key, metrics in metric_groups.items():
                if len(metrics) < 100:  # Need sufficient data
                    continue
                
                metric_type = metrics[0].metric_type
                component = metrics[0].component
                
                # Train/update prediction model
                await self.predictor.train_prediction_model(metric_type, metrics)
                
                # Check for anomalies
                is_anomaly, confidence = await self.predictor.predict_anomaly(metric_type, metrics[-20:])
                
                if is_anomaly and confidence > 0.7:
                    alert = PerformanceAlert(
                        alert_id=str(uuid.uuid4()),
                        metric_type=metric_type,
                        component=component,
                        severity=AlertSeverity.WARNING,
                        condition=AlertCondition.ANOMALY_DETECTED,
                        current_value=metrics[-1].value,
                        threshold_value=confidence,
                        message=f\"Anomaly detected in {metric_type.value} on {component} (confidence: {confidence:.2f})\",
                        triggered_at=current_time
                    )
                    
                    await self._trigger_alert(alert)
                
                # Check for future threshold breaches
                future_values = await self.predictor.predict_future_values(metric_type, metrics)
                await self._check_prediction_alerts(metric_type, component, future_values)
            
            self.last_prediction_update = current_time
            
        except Exception as e:
            self.logger.error(f\"Prediction analysis failed: {e}")
    
    async def _check_prediction_alerts(self, metric_type: PerformanceMetricType,
                                     component: str,
                                     future_values: List[Tuple[datetime, float]]) -> None:
        """Check predicted values against thresholds."""
        try:
            # Find applicable thresholds
            applicable_thresholds = [
                t for t in self.thresholds.values()
                if (t.metric_type == metric_type and
                   t.component == component and
                   t.enabled)
            ]
            
            for threshold in applicable_thresholds:
                for timestamp, predicted_value in future_values:
                    # Check if prediction will breach threshold
                    will_breach = False
                    severity = AlertSeverity.INFO
                    
                    if threshold.condition == AlertCondition.THRESHOLD_EXCEEDED:
                        if predicted_value >= threshold.critical_threshold:
                            will_breach = True
                            severity = AlertSeverity.CRITICAL
                        elif predicted_value >= threshold.warning_threshold:
                            will_breach = True
                            severity = AlertSeverity.WARNING
                    elif threshold.condition == AlertCondition.THRESHOLD_BELOW:
                        if predicted_value <= threshold.critical_threshold:
                            will_breach = True
                            severity = AlertSeverity.CRITICAL
                        elif predicted_value <= threshold.warning_threshold:
                            will_breach = True
                            severity = AlertSeverity.WARNING
                    
                    if will_breach:
                        # Check if prediction is within next 2 hours
                        time_to_breach = (timestamp - datetime.utcnow()).total_seconds()
                        if 0 < time_to_breach <= 7200:  # Within 2 hours
                            alert = PerformanceAlert(
                                alert_id=str(uuid.uuid4()),
                                metric_type=metric_type,
                                component=component,
                                severity=severity,
                                condition=AlertCondition.PREDICTION_BREACH,
                                current_value=predicted_value,
                                threshold_value=threshold.warning_threshold,
                                message=f\"Predicted threshold breach: {metric_type.value} on {component} predicted to reach {predicted_value:.2f} at {timestamp.strftime('%H:%M')}\",
                                triggered_at=datetime.utcnow()
                            )
                            
                            await self._trigger_alert(alert)
                        break  # Only alert for first breach
                        
        except Exception as e:
            self.logger.error(f\"Prediction alert check failed: {e}")
    
    async def _baseline_maintenance_loop(self) -> None:
        """Background baseline maintenance loop."""
        while True:
            try:
                if self.monitoring_active:
                    await self._maintain_baselines()
                
                await asyncio.sleep(86400)  # Run daily
                
            except Exception as e:
                self.logger.error(f\"Baseline maintenance loop error: {e}")
                await asyncio.sleep(86400)
    
    async def _maintain_baselines(self) -> None:
        """Maintain performance baselines."""
        try:
            current_time = datetime.utcnow()
            
            # Get metrics from last 7 days for baseline calculation
            cutoff_time = current_time - timedelta(days=7)
            baseline_metrics = [
                m for m in self.metrics_buffer
                if m.timestamp >= cutoff_time
            ]
            
            # Group by metric type and component
            metric_groups = defaultdict(list)
            for metric in baseline_metrics:
                key = f\"{metric.metric_type.value}_{metric.component}"
                metric_groups[key].append(metric)
            
            # Update baselines
            for group_key, metrics in metric_groups.items():
                if len(metrics) < 1000:  # Need sufficient data
                    continue
                
                metric_type = metrics[0].metric_type
                component = metrics[0].component
                
                # Check if current baseline is expired or doesn't exist
                current_baseline = self.baseliner.get_baseline(metric_type, component)
                if not current_baseline or current_time > current_baseline.valid_until:
                    new_baseline = await self.baseliner.establish_baseline(
                        metric_type, component, metrics
                    )
                    if new_baseline:
                        await self._save_baselines()
            
        except Exception as e:
            self.logger.error(f\"Baseline maintenance failed: {e}")
    
    async def _save_baselines(self) -> None:
        """Save baselines to storage."""
        try:
            baselines_dict = {}
            for baseline_key, baseline in self.baseliner.baselines.items():
                baseline_data = asdict(baseline)
                baseline_data['metric_type'] = baseline.metric_type.value
                baseline_data['established_at'] = baseline.established_at.isoformat()
                baseline_data['valid_until'] = baseline.valid_until.isoformat()
                baselines_dict[baseline_key] = baseline_data
            
            await self.redis_client.set("performance_baselines", json.dumps(baselines_dict))
            
        except Exception as e:
            self.logger.error(f\"Failed to save baselines: {e}")
    
    async def _alert_escalation_loop(self) -> None:
        """Background alert escalation loop."""
        while True:
            try:
                if self.monitoring_active:
                    await self._process_alert_escalation()
                
                await asyncio.sleep(600)  # Check every 10 minutes
                
            except Exception as e:
                self.logger.error(f\"Alert escalation loop error: {e}")
                await asyncio.sleep(600)
    
    async def _process_alert_escalation(self) -> None:
        """Process alert escalation logic."""
        try:
            current_time = datetime.utcnow()
            
            for alert_key, alert in list(self.active_alerts.items()):
                if alert.resolved_at:
                    continue
                
                # Check if alert should be escalated
                time_since_trigger = (current_time - alert.triggered_at).total_seconds()
                
                # Escalate after 30 minutes for critical alerts
                if (alert.severity == AlertSeverity.CRITICAL and
                   time_since_trigger > 1800 and
                   not alert.escalated):
                    
                    alert.escalated = True
                    
                    # Log escalation
                    if self.audit_logger:
                        await self.audit_logger.log_event(
                            event_type="alert_escalation",
                            severity="high",
                            details={
                                'alert_id': alert.alert_id,
                                'component': alert.component,
                                'time_since_trigger': time_since_trigger
                            }
                        )
                    
                    self.logger.warning(f\"Alert escalated: {alert.alert_id}")
                
                # Auto-resolve old warnings (after 2 hours)
                if (alert.severity == AlertSeverity.WARNING and
                   time_since_trigger > 7200):
                    
                    await self._resolve_alert(alert_key, "auto_resolved_timeout")
            
        except Exception as e:
            self.logger.error(f\"Alert escalation processing failed: {e}")
    
    async def resolve_alert(self, alert_id: str, resolution_reason: str = "manual") -> bool:
        """Manually resolve an alert."""
        try:
            # Find alert
            alert_key = None
            for key, alert in self.active_alerts.items():
                if alert.alert_id == alert_id:
                    alert_key = key
                    break
            
            if alert_key:
                return await self._resolve_alert(alert_key, resolution_reason)
            else:
                self.logger.warning(f\"Alert not found: {alert_id}")
                return False
                
        except Exception as e:
            self.logger.error(f\"Failed to resolve alert: {e}")
            return False
    
    async def _resolve_alert(self, alert_key: str, resolution_reason: str) -> bool:
        """Resolve an alert."""
        try:
            alert = self.active_alerts.get(alert_key)
            if not alert:
                return False
            
            alert.resolved_at = datetime.utcnow()
            
            # Log resolution
            if self.audit_logger:
                await self.audit_logger.log_event(
                    event_type="alert_resolved",
                    severity="info",
                    details={
                        'alert_id': alert.alert_id,
                        'resolution_reason': resolution_reason,
                        'duration_seconds': (alert.resolved_at - alert.triggered_at).total_seconds()
                    }
                )
            
            # Remove from active alerts
            del self.active_alerts[alert_key]
            
            self.logger.info(f\"Alert resolved: {alert.alert_id} - {resolution_reason}")
            return True
            
        except Exception as e:
            self.logger.error(f\"Failed to resolve alert {alert_key}: {e}")
            return False
    
    async def get_performance_status(self) -> Dict[str, Any]:
        """Get overall performance status."""
        try:
            current_time = datetime.utcnow()
            
            # Count active alerts by severity
            alert_counts = defaultdict(int)
            for alert in self.active_alerts.values():
                if not alert.resolved_at:
                    alert_counts[alert.severity.value] += 1
            
            # Determine overall status
            if alert_counts.get('emergency', 0) > 0:
                overall_status = PerformanceStatus.FAILING
            elif alert_counts.get('critical', 0) > 0:
                overall_status = PerformanceStatus.CRITICAL
            elif alert_counts.get('warning', 0) > 3:
                overall_status = PerformanceStatus.DEGRADED
            elif alert_counts.get('warning', 0) > 0:
                overall_status = PerformanceStatus.GOOD
            else:
                overall_status = PerformanceStatus.OPTIMAL
            
            # Get recent metrics summary
            recent_metrics = [
                m for m in self.metrics_buffer
                if (current_time - m.timestamp).total_seconds() < 3600  # Last hour
            ]
            
            metrics_summary = {}
            if recent_metrics:
                for metric_type in PerformanceMetricType:
                    type_metrics = [m for m in recent_metrics if m.metric_type == metric_type]
                    if type_metrics:
                        values = [m.value for m in type_metrics]
                        metrics_summary[metric_type.value] = {
                            'current': values[-1],
                            'average': statistics.mean(values),
                            'min': min(values),
                            'max': max(values),
                            'count': len(values)
                        }
            
            return {
                'timestamp': current_time.isoformat(),
                'overall_status': overall_status.value,
                'active_alerts': dict(alert_counts),
                'total_active_alerts': sum(alert_counts.values()),
                'metrics_summary': metrics_summary,
                'monitoring_active': self.monitoring_active,
                'last_prediction_update': self.last_prediction_update.isoformat() if self.last_prediction_update else None
            }
            
        except Exception as e:
            self.logger.error(f\"Failed to get performance status: {e}")
            return {'error': str(e)}
    
    async def get_performance_report(self, hours: int = 24) -> Dict[str, Any]:
        """Generate comprehensive performance report."""
        try:
            current_time = datetime.utcnow()
            start_time = current_time - timedelta(hours=hours)
            
            # Get metrics for time period
            period_metrics = [
                m for m in self.metrics_buffer
                if start_time <= m.timestamp <= current_time
            ]
            
            # Get alerts for time period
            period_alerts = [
                a for a in self.alerts_buffer
                if start_time <= a.triggered_at <= current_time
            ]
            
            # Generate summary statistics
            report = {
                'time_period': {
                    'start': start_time.isoformat(),
                    'end': current_time.isoformat(),
                    'duration_hours': hours
                },
                'metrics_summary': {},
                'alerts_summary': {
                    'total_alerts': len(period_alerts),
                    'by_severity': defaultdict(int),
                    'by_component': defaultdict(int),
                    'by_metric_type': defaultdict(int)
                },
                'baselines': {},
                'predictions': {}
            }
            
            # Summarize metrics by type
            for metric_type in PerformanceMetricType:
                type_metrics = [m for m in period_metrics if m.metric_type == metric_type]
                if type_metrics:
                    values = [m.value for m in type_metrics]
                    report['metrics_summary'][metric_type.value] = {
                        'count': len(values),
                        'average': statistics.mean(values),
                        'median': statistics.median(values),
                        'min': min(values),
                        'max': max(values),
                        'std_dev': statistics.stdev(values) if len(values) > 1 else 0,
                        'p95': np.percentile(values, 95),
                        'p99': np.percentile(values, 99)
                    }
            
            # Summarize alerts
            for alert in period_alerts:
                report['alerts_summary']['by_severity'][alert.severity.value] += 1
                report['alerts_summary']['by_component'][alert.component] += 1
                report['alerts_summary']['by_metric_type'][alert.metric_type.value] += 1
            
            # Include baseline information
            for baseline_key, baseline in self.baseliner.baselines.items():
                if baseline.valid_until > current_time:
                    report['baselines'][baseline_key] = {
                        'metric_type': baseline.metric_type.value,
                        'component': baseline.component,
                        'baseline_value': baseline.baseline_value,
                        'standard_deviation': baseline.standard_deviation,
                        'established_at': baseline.established_at.isoformat()
                    }
            
            return report
            
        except Exception as e:
            self.logger.error(f\"Performance report generation failed: {e}")
            return {'error': str(e)}
    
    async def close(self) -> None:
        """Clean up performance monitor resources."""
        self.monitoring_active = False
        
        if self.redis_client:
            await self.redis_client.close()
        
        self.logger.info("Advanced performance monitor closed")


if __name__ == "__main__":
    # Example usage
    async def main():
        monitor = AdvancedPerformanceMonitor()
        await monitor.initialize()
        
        # Simulate performance metrics
        for i in range(100):
            # Response time with some variation and occasional spikes
            response_time = 0.5 + (i % 10) * 0.1
            if i % 20 == 0:  # Occasional spike
                response_time += 2.0
            
            await monitor.record_metric(
                PerformanceMetricType.RESPONSE_TIME,
                "api_gateway",
                response_time
            )
            
            # CPU utilization
            cpu_usage = 50 + (i % 30) + (5 if i > 50 else 0)  # Gradual increase
            await monitor.record_metric(
                PerformanceMetricType.CPU_UTILIZATION,
                "api_gateway",
                cpu_usage
            )
            
            await asyncio.sleep(0.1)
        
        # Get performance status
        status = await monitor.get_performance_status()
        print(f"Performance Status: {json.dumps(status, indent=2)}")
        
        # Generate performance report
        report = await monitor.get_performance_report(1)  # Last 1 hour
        print(f"Performance Report: {json.dumps(report, indent=2)}")
        
        await monitor.close()
    
    asyncio.run(main())