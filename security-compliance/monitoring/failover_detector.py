#!/usr/bin/env python3
"""
CAC/PIV Card Health Monitoring and Failover Detection System

This module provides advanced health monitoring and failover detection capabilities
for CAC/PIV smart card infrastructure, enabling proactive detection of card failures,
reader malfunctions, and system degradation with automated failover mechanisms.

Key Features:
- Real-time card health monitoring with predictive failure detection
- Smart card reader health assessment and diagnostics
- Automated failover to backup authentication methods
- Performance degradation detection and alerting
- Certificate lifecycle monitoring and expiration warnings
- Communication error pattern analysis
- Predictive maintenance scheduling
- Integration with security monitoring system

Health Monitoring Capabilities:
- Card response time monitoring
- Certificate validity and chain verification
- PIN retry counter tracking
- Card memory integrity checks
- Reader communication quality assessment
- Temperature and voltage monitoring (where supported)
- Usage pattern analysis for wear prediction

Failover Mechanisms:
- Automatic fallback to backup authentication methods
- Load balancing across multiple card readers
- Graceful degradation of authentication requirements
- Emergency access protocols activation
- Backup certificate store utilization
- Alternative PKI path discovery

Author: Security Monitoring Team
Version: 1.0.0
"""

import os
import sys
import threading
import time
import logging
import queue
import json
import hashlib
import statistics
from typing import Dict, List, Optional, Set, Callable, Any, Union, Tuple, NamedTuple
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone, timedelta
from enum import Enum, IntEnum
from collections import defaultdict, deque
import weakref
from contextlib import contextmanager
import sqlite3
import psutil
import socket

# Import existing components
try:
    from .cac_piv_security_monitor import SecurityEvent, SecurityEventCategory, SecurityThreatLevel
    from ..auth.cac_piv.card_status_monitor import CardStatusMonitor, CardStatusEvent, CardEvent
    from ..auth.cac_piv.cac_piv_authenticator import CACPIVCard, CardStatus, CardType, CACPIVAuthenticator
    from ..auth.cac_piv.fallback_authenticator import FallbackAuthenticationManager
    from ..audits.audit_logger import AuditLogger, AuditEvent, AuditEventType
except ImportError:
    # Minimal implementations for standalone operation
    logger = logging.getLogger(__name__)


class HealthStatus(Enum):
    """Health status levels for monitored components."""
    HEALTHY = "healthy"
    WARNING = "warning"
    DEGRADED = "degraded"
    CRITICAL = "critical"
    FAILED = "failed"
    UNKNOWN = "unknown"


class FailoverTrigger(Enum):
    """Triggers that can initiate failover procedures."""
    CARD_FAILURE = "card_failure"
    READER_FAILURE = "reader_failure"
    CERTIFICATE_EXPIRED = "certificate_expired"
    CERTIFICATE_REVOKED = "certificate_revoked"
    COMMUNICATION_ERROR = "communication_error"
    PERFORMANCE_DEGRADATION = "performance_degradation"
    AUTHENTICATION_TIMEOUT = "authentication_timeout"
    PIN_LOCKED = "pin_locked"
    SECURITY_VIOLATION = "security_violation"
    SYSTEM_OVERLOAD = "system_overload"
    MANUAL_TRIGGER = "manual_trigger"


class FailoverStrategy(Enum):
    """Available failover strategies."""
    IMMEDIATE = "immediate"          # Switch immediately without delay
    GRACEFUL = "graceful"            # Allow current operations to complete
    CONDITIONAL = "conditional"      # Failover only if conditions are met
    LOAD_BALANCED = "load_balanced"  # Distribute load across available resources
    CASCADING = "cascading"          # Try alternatives in sequence
    MANUAL = "manual"                # Require manual intervention


@dataclass
class HealthMetric:
    """Individual health monitoring metric."""
    metric_name: str
    value: Union[int, float, str, bool]
    unit: str
    timestamp: datetime
    threshold_warning: Optional[float] = None
    threshold_critical: Optional[float] = None
    status: HealthStatus = HealthStatus.UNKNOWN
    trend: Optional[str] = None  # "improving", "stable", "degrading"
    
    def calculate_status(self) -> HealthStatus:
        """Calculate health status based on thresholds."""
        if not isinstance(self.value, (int, float)):
            return HealthStatus.UNKNOWN
        
        if self.threshold_critical and self.value >= self.threshold_critical:
            return HealthStatus.CRITICAL
        elif self.threshold_warning and self.value >= self.threshold_warning:
            return HealthStatus.WARNING
        else:
            return HealthStatus.HEALTHY


@dataclass
class ComponentHealth:
    """Health status for a monitored component."""
    component_id: str
    component_type: str
    overall_status: HealthStatus
    metrics: Dict[str, HealthMetric] = field(default_factory=dict)
    last_check: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    error_count: int = 0
    warning_count: int = 0
    uptime_seconds: float = 0.0
    availability_percentage: float = 100.0
    
    def update_overall_status(self):
        """Update overall status based on individual metrics."""
        if not self.metrics:
            self.overall_status = HealthStatus.UNKNOWN
            return
        
        statuses = [metric.status for metric in self.metrics.values()]
        
        if HealthStatus.FAILED in statuses:
            self.overall_status = HealthStatus.FAILED
        elif HealthStatus.CRITICAL in statuses:
            self.overall_status = HealthStatus.CRITICAL
        elif HealthStatus.DEGRADED in statuses:
            self.overall_status = HealthStatus.DEGRADED
        elif HealthStatus.WARNING in statuses:
            self.overall_status = HealthStatus.WARNING
        else:
            self.overall_status = HealthStatus.HEALTHY


@dataclass
class FailoverEvent:
    """Failover event information."""
    event_id: str
    timestamp: datetime
    trigger: FailoverTrigger
    source_component: str
    target_component: Optional[str]
    strategy: FailoverStrategy
    success: bool
    duration_seconds: float
    user_impact: str  # "none", "minimal", "moderate", "severe"
    error_message: Optional[str] = None
    recovery_actions: List[str] = field(default_factory=list)


class FailoverConfiguration:
    """Configuration for failover detection and response."""
    
    def __init__(self):
        # Health monitoring intervals
        self.health_check_interval = 30.0
        self.metric_collection_interval = 10.0
        self.trend_analysis_interval = 300.0
        
        # Failure detection thresholds
        self.card_response_timeout = 5.0
        self.reader_communication_timeout = 10.0
        self.authentication_timeout = 30.0
        self.max_consecutive_errors = 3
        self.error_rate_threshold = 0.1  # 10% error rate
        
        # Performance thresholds
        self.response_time_warning = 2.0
        self.response_time_critical = 5.0
        self.cpu_usage_warning = 80.0
        self.cpu_usage_critical = 95.0
        self.memory_usage_warning = 85.0
        self.memory_usage_critical = 95.0
        
        # Failover settings
        self.auto_failover_enabled = True
        self.failover_cooldown_seconds = 60.0
        self.max_failover_attempts = 3
        self.failback_delay_seconds = 300.0
        
        # Certificate monitoring
        self.certificate_expiry_warning_days = 30
        self.certificate_expiry_critical_days = 7
        self.crl_check_interval = 3600.0  # 1 hour
        
        # Load from environment
        self._load_from_environment()
    
    def _load_from_environment(self):
        """Load configuration from environment variables."""
        try:
            self.auto_failover_enabled = os.getenv('FAILOVER_AUTO_ENABLED', 'true').lower() == 'true'
            self.health_check_interval = float(os.getenv('FAILOVER_HEALTH_INTERVAL', '30.0'))
            self.max_consecutive_errors = int(os.getenv('FAILOVER_MAX_ERRORS', '3'))
        except Exception as e:
            logging.getLogger(__name__).warning(f"Failed to load failover config: {e}")


class FailoverDetector:
    """
    Advanced Health Monitoring and Failover Detection System
    
    Provides comprehensive monitoring of CAC/PIV infrastructure with:
    - Predictive failure detection
    - Automated failover mechanisms
    - Performance degradation monitoring
    - Certificate lifecycle management
    - Integration with security monitoring
    """
    
    def __init__(self,
                 config: Optional[FailoverConfiguration] = None,
                 authenticator: Optional[CACPIVAuthenticator] = None,
                 fallback_manager: Optional[FallbackAuthenticationManager] = None,
                 card_monitor: Optional[CardStatusMonitor] = None,
                 audit_logger: Optional[AuditLogger] = None):
        """
        Initialize failover detector.
        
        Args:
            config: Failover configuration
            authenticator: CAC/PIV authenticator instance
            fallback_manager: Fallback authentication manager
            card_monitor: Card status monitor
            audit_logger: Audit logging system
        """
        self.config = config or FailoverConfiguration()
        self.authenticator = authenticator
        self.fallback_manager = fallback_manager
        self.card_monitor = card_monitor
        self.audit_logger = audit_logger
        
        # Initialize database
        self._init_database()
        
        # Component health tracking
        self.component_health: Dict[str, ComponentHealth] = {}
        self.health_history: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        self.health_lock = threading.RLock()
        
        # Failover tracking
        self.failover_events: List[FailoverEvent] = []
        self.active_failovers: Dict[str, FailoverEvent] = {}
        self.failover_lock = threading.RLock()
        
        # Monitoring state
        self.is_running = False
        self._shutdown_event = threading.Event()
        self.monitoring_threads: List[threading.Thread] = []
        
        # Event queues
        self.health_event_queue = queue.Queue()
        self.failover_event_queue = queue.Queue()
        
        # Performance tracking
        self.performance_baselines: Dict[str, Dict] = {}
        self.anomaly_detectors: Dict[str, Any] = {}
        
        # Statistics
        self.stats = {
            'total_health_checks': 0,
            'total_failovers': 0,
            'successful_failovers': 0,
            'false_positives': 0,
            'mean_time_to_detect': 0.0,
            'mean_time_to_recover': 0.0
        }
        
        logger.info("Failover Detector initialized")
    
    def _init_database(self):
        """Initialize failover monitoring database."""
        try:
            self.db_path = "/tmp/failover_monitoring.db"
            conn = sqlite3.connect(self.db_path)
            
            # Component health table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS component_health (
                    component_id TEXT,
                    component_type TEXT,
                    timestamp TEXT,
                    overall_status TEXT,
                    metrics TEXT,
                    error_count INTEGER,
                    warning_count INTEGER,
                    availability_percentage REAL,
                    PRIMARY KEY (component_id, timestamp)
                )
            """)
            
            # Health metrics table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS health_metrics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    component_id TEXT NOT NULL,
                    metric_name TEXT NOT NULL,
                    value TEXT NOT NULL,
                    unit TEXT,
                    timestamp TEXT NOT NULL,
                    status TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Failover events table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS failover_events (
                    event_id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    trigger_type TEXT NOT NULL,
                    source_component TEXT NOT NULL,
                    target_component TEXT,
                    strategy TEXT NOT NULL,
                    success BOOLEAN NOT NULL,
                    duration_seconds REAL,
                    user_impact TEXT,
                    error_message TEXT,
                    recovery_actions TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Performance baselines table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS performance_baselines (
                    component_id TEXT,
                    metric_name TEXT,
                    baseline_value REAL,
                    deviation_threshold REAL,
                    last_updated TEXT,
                    PRIMARY KEY (component_id, metric_name)
                )
            """)
            
            # Create indexes
            indexes = [
                "CREATE INDEX IF NOT EXISTS idx_health_timestamp ON component_health(timestamp)",
                "CREATE INDEX IF NOT EXISTS idx_health_component ON component_health(component_id)",
                "CREATE INDEX IF NOT EXISTS idx_metrics_component ON health_metrics(component_id)",
                "CREATE INDEX IF NOT EXISTS idx_metrics_timestamp ON health_metrics(timestamp)",
                "CREATE INDEX IF NOT EXISTS idx_failover_timestamp ON failover_events(timestamp)"
            ]
            
            for index_sql in indexes:
                conn.execute(index_sql)
            
            conn.commit()
            conn.close()
            
            logger.info("Failover monitoring database initialized")
            
        except Exception as e:
            logger.error(f"Failed to initialize failover database: {e}")
            raise
    
    def start(self) -> bool:
        """Start health monitoring and failover detection."""
        if self.is_running:
            logger.warning("Failover detector already running")
            return False
        
        try:
            logger.info("Starting Failover Detector...")
            
            # Clear shutdown event
            self._shutdown_event.clear()
            
            # Initialize component monitoring
            self._initialize_component_monitoring()
            
            # Start monitoring threads
            self._start_monitoring_threads()
            
            # Register with card monitor if available
            if self.card_monitor:
                self._register_card_monitor_observer()
            
            self.is_running = True
            logger.info("Failover Detector started successfully")
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to start failover detector: {e}")
            return False
    
    def stop(self, timeout: float = 30.0) -> bool:
        """Stop health monitoring and failover detection."""
        if not self.is_running:
            return True
        
        try:
            logger.info("Stopping Failover Detector...")
            
            # Signal shutdown
            self._shutdown_event.set()
            self.is_running = False
            
            # Stop monitoring threads
            self._stop_monitoring_threads(timeout)
            
            # Save final statistics
            self._save_statistics()
            
            logger.info("Failover Detector stopped successfully")
            return True
            
        except Exception as e:
            logger.error(f"Error stopping failover detector: {e}")
            return False
    
    def _initialize_component_monitoring(self):
        """Initialize monitoring for all components."""
        try:
            # Monitor CAC/PIV authenticator
            if self.authenticator:
                self._register_component("cac_piv_authenticator", "authenticator")
            
            # Monitor fallback authentication manager
            if self.fallback_manager:
                self._register_component("fallback_auth_manager", "authenticator")
            
            # Monitor card readers (simulated)
            for reader_id in ["reader_1", "reader_2", "reader_3"]:
                self._register_component(reader_id, "card_reader")
            
            # Monitor system resources
            self._register_component("system_cpu", "system_resource")
            self._register_component("system_memory", "system_resource")
            self._register_component("system_disk", "system_resource")
            
            logger.info(f"Initialized monitoring for {len(self.component_health)} components")
            
        except Exception as e:
            logger.error(f"Failed to initialize component monitoring: {e}")
            raise
    
    def _register_component(self, component_id: str, component_type: str):
        """Register a component for health monitoring."""
        try:
            with self.health_lock:
                self.component_health[component_id] = ComponentHealth(
                    component_id=component_id,
                    component_type=component_type,
                    overall_status=HealthStatus.UNKNOWN
                )
            
            logger.debug(f"Registered component for monitoring: {component_id}")
            
        except Exception as e:
            logger.error(f"Failed to register component {component_id}: {e}")
    
    def _start_monitoring_threads(self):
        """Start background monitoring threads."""
        thread_configs = [
            ("HealthMonitor", self._health_monitoring_loop),
            ("FailoverProcessor", self._failover_processing_loop),
            ("TrendAnalyzer", self._trend_analysis_loop),
            ("CertificateMonitor", self._certificate_monitoring_loop),
            ("PerformanceAnalyzer", self._performance_analysis_loop)
        ]
        
        for name, target in thread_configs:
            thread = threading.Thread(
                target=target,
                name=f"FailoverDetector-{name}",
                daemon=True
            )
            thread.start()
            self.monitoring_threads.append(thread)
        
        logger.debug(f"Started {len(self.monitoring_threads)} monitoring threads")
    
    def _stop_monitoring_threads(self, timeout: float):
        """Stop monitoring threads."""
        for thread in self.monitoring_threads:
            if thread.is_alive():
                thread.join(timeout / len(self.monitoring_threads))
        
        self.monitoring_threads.clear()
        logger.debug("Monitoring threads stopped")
    
    def _health_monitoring_loop(self):
        """Main health monitoring loop."""
        logger.debug("Health monitoring loop started")
        
        while not self._shutdown_event.is_set():
            try:
                start_time = time.time()
                
                # Check health of all components
                self._check_all_component_health()
                
                # Process health events
                self._process_health_events()
                
                # Update statistics
                self.stats['total_health_checks'] += 1
                
                # Calculate sleep time to maintain interval
                elapsed = time.time() - start_time
                sleep_time = max(0, self.config.health_check_interval - elapsed)
                time.sleep(sleep_time)
                
            except Exception as e:
                logger.error(f"Error in health monitoring loop: {e}")
                time.sleep(self.config.health_check_interval)
        
        logger.debug("Health monitoring loop stopped")
    
    def _check_all_component_health(self):
        """Check health of all registered components."""
        try:
            with self.health_lock:
                components = list(self.component_health.items())
            
            for component_id, health in components:
                try:
                    self._check_component_health(component_id, health)
                except Exception as e:
                    logger.warning(f"Health check failed for {component_id}: {e}")
                    self._record_health_check_failure(component_id, str(e))
            
        except Exception as e:
            logger.error(f"Failed to check component health: {e}")
    
    def _check_component_health(self, component_id: str, health: ComponentHealth):
        """Check health of individual component."""
        try:
            now = datetime.now(timezone.utc)
            
            # Update basic component info
            health.last_check = now
            
            # Check component-specific metrics
            if health.component_type == "authenticator":
                self._check_authenticator_health(component_id, health)
            elif health.component_type == "card_reader":
                self._check_card_reader_health(component_id, health)
            elif health.component_type == "system_resource":
                self._check_system_resource_health(component_id, health)
            
            # Update overall status
            health.update_overall_status()
            
            # Store health data
            self._store_component_health(health)
            
            # Check for failover triggers
            self._check_failover_triggers(component_id, health)
            
        except Exception as e:
            logger.error(f"Failed to check health for {component_id}: {e}")
            raise
    
    def _check_authenticator_health(self, component_id: str, health: ComponentHealth):
        """Check health of authenticator component."""
        try:
            # Simulate authenticator health metrics
            # In production, these would be real measurements
            
            # Response time metric
            response_time = self._measure_authenticator_response_time(component_id)
            health.metrics["response_time"] = HealthMetric(
                metric_name="response_time",
                value=response_time,
                unit="seconds",
                timestamp=datetime.now(timezone.utc),
                threshold_warning=self.config.response_time_warning,
                threshold_critical=self.config.response_time_critical
            )
            health.metrics["response_time"].status = health.metrics["response_time"].calculate_status()
            
            # Success rate metric
            success_rate = self._calculate_authenticator_success_rate(component_id)
            health.metrics["success_rate"] = HealthMetric(
                metric_name="success_rate",
                value=success_rate,
                unit="percentage",
                timestamp=datetime.now(timezone.utc),
                threshold_warning=95.0,
                threshold_critical=90.0
            )
            
            # Calculate status for success rate (inverse logic - lower is worse)
            if success_rate < 90.0:
                health.metrics["success_rate"].status = HealthStatus.CRITICAL
            elif success_rate < 95.0:
                health.metrics["success_rate"].status = HealthStatus.WARNING
            else:
                health.metrics["success_rate"].status = HealthStatus.HEALTHY
            
            # Connection count metric
            active_connections = self._get_active_connection_count(component_id)
            health.metrics["active_connections"] = HealthMetric(
                metric_name="active_connections",
                value=active_connections,
                unit="count",
                timestamp=datetime.now(timezone.utc),
                threshold_warning=100,
                threshold_critical=150
            )
            health.metrics["active_connections"].status = health.metrics["active_connections"].calculate_status()
            
        except Exception as e:
            logger.error(f"Failed to check authenticator health for {component_id}: {e}")
            raise
    
    def _check_card_reader_health(self, component_id: str, health: ComponentHealth):
        """Check health of card reader component."""
        try:
            # Communication status
            comm_status = self._check_reader_communication(component_id)
            health.metrics["communication_status"] = HealthMetric(
                metric_name="communication_status",
                value=comm_status,
                unit="boolean",
                timestamp=datetime.now(timezone.utc)
            )
            health.metrics["communication_status"].status = (
                HealthStatus.HEALTHY if comm_status else HealthStatus.CRITICAL
            )
            
            # Read success rate
            read_success_rate = self._calculate_reader_success_rate(component_id)
            health.metrics["read_success_rate"] = HealthMetric(
                metric_name="read_success_rate",
                value=read_success_rate,
                unit="percentage",
                timestamp=datetime.now(timezone.utc),
                threshold_warning=95.0,
                threshold_critical=85.0
            )
            
            # Temperature monitoring (simulated)
            temperature = self._get_reader_temperature(component_id)
            health.metrics["temperature"] = HealthMetric(
                metric_name="temperature",
                value=temperature,
                unit="celsius",
                timestamp=datetime.now(timezone.utc),
                threshold_warning=60.0,
                threshold_critical=70.0
            )
            health.metrics["temperature"].status = health.metrics["temperature"].calculate_status()
            
        except Exception as e:
            logger.error(f"Failed to check card reader health for {component_id}: {e}")
            raise
    
    def _check_system_resource_health(self, component_id: str, health: ComponentHealth):
        """Check health of system resource component."""
        try:
            if component_id == "system_cpu":
                cpu_percent = psutil.cpu_percent(interval=1)
                health.metrics["usage_percentage"] = HealthMetric(
                    metric_name="usage_percentage",
                    value=cpu_percent,
                    unit="percentage",
                    timestamp=datetime.now(timezone.utc),
                    threshold_warning=self.config.cpu_usage_warning,
                    threshold_critical=self.config.cpu_usage_critical
                )
                health.metrics["usage_percentage"].status = health.metrics["usage_percentage"].calculate_status()
                
            elif component_id == "system_memory":
                memory = psutil.virtual_memory()
                health.metrics["usage_percentage"] = HealthMetric(
                    metric_name="usage_percentage",
                    value=memory.percent,
                    unit="percentage",
                    timestamp=datetime.now(timezone.utc),
                    threshold_warning=self.config.memory_usage_warning,
                    threshold_critical=self.config.memory_usage_critical
                )
                health.metrics["usage_percentage"].status = health.metrics["usage_percentage"].calculate_status()
                
            elif component_id == "system_disk":
                disk = psutil.disk_usage('/')
                disk_percent = (disk.used / disk.total) * 100
                health.metrics["usage_percentage"] = HealthMetric(
                    metric_name="usage_percentage",
                    value=disk_percent,
                    unit="percentage",
                    timestamp=datetime.now(timezone.utc),
                    threshold_warning=85.0,
                    threshold_critical=95.0
                )
                health.metrics["usage_percentage"].status = health.metrics["usage_percentage"].calculate_status()
            
        except Exception as e:
            logger.error(f"Failed to check system resource health for {component_id}: {e}")
            raise
    
    def _measure_authenticator_response_time(self, component_id: str) -> float:
        """Measure authenticator response time."""
        # Simulate measurement - in production this would be real
        import random
        base_time = 1.0
        variation = random.uniform(-0.5, 1.0)
        return max(0.1, base_time + variation)
    
    def _calculate_authenticator_success_rate(self, component_id: str) -> float:
        """Calculate authenticator success rate."""
        # Simulate calculation - in production this would be real metrics
        import random
        return random.uniform(92.0, 99.5)
    
    def _get_active_connection_count(self, component_id: str) -> int:
        """Get active connection count for authenticator."""
        # Simulate count - in production this would be real
        import random
        return random.randint(10, 80)
    
    def _check_reader_communication(self, component_id: str) -> bool:
        """Check card reader communication status."""
        # Simulate check - in production this would test actual communication
        import random
        return random.random() > 0.05  # 95% success rate
    
    def _calculate_reader_success_rate(self, component_id: str) -> float:
        """Calculate card reader success rate."""
        # Simulate calculation - in production this would be real metrics
        import random
        return random.uniform(88.0, 99.0)
    
    def _get_reader_temperature(self, component_id: str) -> float:
        """Get card reader temperature."""
        # Simulate temperature reading
        import random
        return random.uniform(35.0, 65.0)  # Normal operating temperature range
    
    def _store_component_health(self, health: ComponentHealth):
        """Store component health data in database."""
        try:
            conn = sqlite3.connect(self.db_path)
            
            # Store component health summary
            conn.execute("""
                INSERT INTO component_health (
                    component_id, component_type, timestamp, overall_status,
                    metrics, error_count, warning_count, availability_percentage
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                health.component_id,
                health.component_type,
                health.last_check.isoformat(),
                health.overall_status.value,
                json.dumps({k: asdict(v) for k, v in health.metrics.items()}),
                health.error_count,
                health.warning_count,
                health.availability_percentage
            ))
            
            # Store individual metrics
            for metric in health.metrics.values():
                conn.execute("""
                    INSERT INTO health_metrics (
                        component_id, metric_name, value, unit, timestamp, status
                    ) VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    health.component_id,
                    metric.metric_name,
                    str(metric.value),
                    metric.unit,
                    metric.timestamp.isoformat(),
                    metric.status.value
                ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"Failed to store component health: {e}")
    
    def _check_failover_triggers(self, component_id: str, health: ComponentHealth):
        """Check if component health indicates failover is needed."""
        try:
            # Check for critical health status
            if health.overall_status == HealthStatus.CRITICAL:
                self._trigger_failover(component_id, FailoverTrigger.CARD_FAILURE, health)
            
            # Check for degraded performance
            elif health.overall_status == HealthStatus.DEGRADED:
                self._trigger_failover(component_id, FailoverTrigger.PERFORMANCE_DEGRADATION, health)
            
            # Check specific metric thresholds
            for metric in health.metrics.values():
                if metric.status == HealthStatus.CRITICAL:
                    if metric.metric_name == "response_time":
                        self._trigger_failover(component_id, FailoverTrigger.AUTHENTICATION_TIMEOUT, health)
                    elif metric.metric_name == "communication_status" and not metric.value:
                        self._trigger_failover(component_id, FailoverTrigger.COMMUNICATION_ERROR, health)
            
        except Exception as e:
            logger.error(f"Failed to check failover triggers for {component_id}: {e}")
    
    def _trigger_failover(self, component_id: str, trigger: FailoverTrigger, health: ComponentHealth):
        """Trigger failover procedure for component."""
        if not self.config.auto_failover_enabled:
            logger.info(f"Auto-failover disabled, manual intervention required for {component_id}")
            return
        
        try:
            # Check cooldown period
            if self._is_in_failover_cooldown(component_id):
                logger.debug(f"Failover cooldown active for {component_id}, skipping")
                return
            
            # Create failover event
            event_id = f"failover_{component_id}_{int(time.time())}"
            failover_event = FailoverEvent(
                event_id=event_id,
                timestamp=datetime.now(timezone.utc),
                trigger=trigger,
                source_component=component_id,
                target_component=None,  # Will be determined by strategy
                strategy=FailoverStrategy.GRACEFUL,
                success=False,
                duration_seconds=0.0,
                user_impact="moderate"
            )
            
            # Queue failover event for processing
            self.failover_event_queue.put_nowait(failover_event)
            
            # Track active failover
            with self.failover_lock:
                self.active_failovers[component_id] = failover_event
            
            logger.warning(f"Failover triggered for {component_id}: {trigger.value}")
            
        except Exception as e:
            logger.error(f"Failed to trigger failover for {component_id}: {e}")
    
    def _is_in_failover_cooldown(self, component_id: str) -> bool:
        """Check if component is in failover cooldown period."""
        try:
            # Find most recent failover for this component
            recent_failovers = [
                event for event in self.failover_events
                if (event.source_component == component_id and
                    (datetime.now(timezone.utc) - event.timestamp).total_seconds() < 
                    self.config.failover_cooldown_seconds)
            ]
            
            return len(recent_failovers) > 0
            
        except Exception as e:
            logger.error(f"Failed to check failover cooldown for {component_id}: {e}")
            return False
    
    def _failover_processing_loop(self):
        """Process failover events."""
        logger.debug("Failover processing loop started")
        
        while not self._shutdown_event.is_set():
            try:
                # Get failover event from queue
                try:
                    event = self.failover_event_queue.get(timeout=1.0)
                    self._process_failover_event(event)
                    self.failover_event_queue.task_done()
                except queue.Empty:
                    continue
                
            except Exception as e:
                logger.error(f"Error in failover processing loop: {e}")
                time.sleep(1)
        
        logger.debug("Failover processing loop stopped")
    
    def _process_failover_event(self, event: FailoverEvent):
        """Process individual failover event."""
        try:
            start_time = time.time()
            
            logger.info(f"Processing failover event: {event.event_id}")
            
            # Determine target component for failover
            target_component = self._select_failover_target(event)
            event.target_component = target_component
            
            if not target_component:
                event.success = False
                event.error_message = "No suitable failover target available"
                logger.error(f"No failover target for {event.source_component}")
            else:
                # Execute failover based on strategy
                success = self._execute_failover(event)
                event.success = success
                
                if success:
                    logger.info(f"Failover successful: {event.source_component} -> {target_component}")
                else:
                    logger.error(f"Failover failed: {event.source_component} -> {target_component}")
            
            # Update event duration
            event.duration_seconds = time.time() - start_time
            
            # Store failover event
            self._store_failover_event(event)
            
            # Update statistics
            self.stats['total_failovers'] += 1
            if event.success:
                self.stats['successful_failovers'] += 1
            
            # Remove from active failovers
            with self.failover_lock:
                if event.source_component in self.active_failovers:
                    del self.active_failovers[event.source_component]
            
            # Add to failover history
            self.failover_events.append(event)
            if len(self.failover_events) > 1000:
                self.failover_events.pop(0)
            
            # Log to audit system
            if self.audit_logger:
                self._log_failover_to_audit(event)
            
        except Exception as e:
            logger.error(f"Failed to process failover event {event.event_id}: {e}")
            event.success = False
            event.error_message = str(e)
    
    def _select_failover_target(self, event: FailoverEvent) -> Optional[str]:
        """Select appropriate failover target for component."""
        try:
            source_component = event.source_component
            
            # Get component type
            with self.health_lock:
                if source_component not in self.component_health:
                    return None
                
                component_type = self.component_health[source_component].component_type
            
            # Find healthy components of same type
            healthy_components = []
            with self.health_lock:
                for comp_id, health in self.component_health.items():
                    if (comp_id != source_component and
                        health.component_type == component_type and
                        health.overall_status in [HealthStatus.HEALTHY, HealthStatus.WARNING]):
                        healthy_components.append(comp_id)
            
            if not healthy_components:
                # Look for fallback options
                if component_type == "authenticator" and self.fallback_manager:
                    return "fallback_authenticator"
                return None
            
            # Select best target based on health scores
            best_target = min(healthy_components, 
                            key=lambda x: self._calculate_component_health_score(x))
            
            return best_target
            
        except Exception as e:
            logger.error(f"Failed to select failover target: {e}")
            return None
    
    def _calculate_component_health_score(self, component_id: str) -> float:
        """Calculate health score for component selection."""
        try:
            with self.health_lock:
                if component_id not in self.component_health:
                    return 100.0  # Worst score
                
                health = self.component_health[component_id]
            
            # Calculate score based on various factors
            score = 0.0
            
            # Status score
            status_scores = {
                HealthStatus.HEALTHY: 0.0,
                HealthStatus.WARNING: 25.0,
                HealthStatus.DEGRADED: 50.0,
                HealthStatus.CRITICAL: 75.0,
                HealthStatus.FAILED: 100.0,
                HealthStatus.UNKNOWN: 90.0
            }
            score += status_scores.get(health.overall_status, 90.0)
            
            # Error count penalty
            score += min(25.0, health.error_count * 5.0)
            
            # Availability penalty
            score += (100.0 - health.availability_percentage) * 0.5
            
            return score
            
        except Exception as e:
            logger.error(f"Failed to calculate health score for {component_id}: {e}")
            return 100.0
    
    def _execute_failover(self, event: FailoverEvent) -> bool:
        """Execute failover based on strategy."""
        try:
            if event.strategy == FailoverStrategy.IMMEDIATE:
                return self._execute_immediate_failover(event)
            elif event.strategy == FailoverStrategy.GRACEFUL:
                return self._execute_graceful_failover(event)
            elif event.strategy == FailoverStrategy.LOAD_BALANCED:
                return self._execute_load_balanced_failover(event)
            else:
                logger.warning(f"Unsupported failover strategy: {event.strategy}")
                return False
                
        except Exception as e:
            logger.error(f"Failed to execute failover: {e}")
            event.error_message = str(e)
            return False
    
    def _execute_immediate_failover(self, event: FailoverEvent) -> bool:
        """Execute immediate failover."""
        try:
            # Immediate failover would:
            # 1. Disable source component
            # 2. Redirect all traffic to target immediately
            # 3. Update load balancer configuration
            
            logger.info(f"Executing immediate failover: {event.source_component} -> {event.target_component}")
            
            # Simulate failover actions
            time.sleep(0.1)  # Simulate brief switchover time
            
            event.user_impact = "minimal"
            return True
            
        except Exception as e:
            logger.error(f"Immediate failover failed: {e}")
            return False
    
    def _execute_graceful_failover(self, event: FailoverEvent) -> bool:
        """Execute graceful failover."""
        try:
            # Graceful failover would:
            # 1. Stop accepting new requests on source
            # 2. Allow existing operations to complete
            # 3. Switch to target when ready
            
            logger.info(f"Executing graceful failover: {event.source_component} -> {event.target_component}")
            
            # Simulate graceful transition
            time.sleep(2.0)  # Simulate time for operations to complete
            
            event.user_impact = "none"
            return True
            
        except Exception as e:
            logger.error(f"Graceful failover failed: {e}")
            return False
    
    def _execute_load_balanced_failover(self, event: FailoverEvent) -> bool:
        """Execute load-balanced failover."""
        try:
            # Load-balanced failover would:
            # 1. Redistribute load across healthy components
            # 2. Remove failed component from load balancer
            # 3. Monitor performance of remaining components
            
            logger.info(f"Executing load-balanced failover: redistributing load from {event.source_component}")
            
            # Simulate load redistribution
            time.sleep(1.0)
            
            event.user_impact = "minimal"
            return True
            
        except Exception as e:
            logger.error(f"Load-balanced failover failed: {e}")
            return False
    
    def _store_failover_event(self, event: FailoverEvent):
        """Store failover event in database."""
        try:
            conn = sqlite3.connect(self.db_path)
            
            conn.execute("""
                INSERT INTO failover_events (
                    event_id, timestamp, trigger_type, source_component, target_component,
                    strategy, success, duration_seconds, user_impact, error_message,
                    recovery_actions
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                event.event_id,
                event.timestamp.isoformat(),
                event.trigger.value,
                event.source_component,
                event.target_component,
                event.strategy.value,
                event.success,
                event.duration_seconds,
                event.user_impact,
                event.error_message,
                json.dumps(event.recovery_actions)
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"Failed to store failover event: {e}")
    
    def _trend_analysis_loop(self):
        """Analyze trends in health metrics."""
        logger.debug("Trend analysis loop started")
        
        while not self._shutdown_event.is_set():
            try:
                self._analyze_health_trends()
                time.sleep(self.config.trend_analysis_interval)
                
            except Exception as e:
                logger.error(f"Error in trend analysis loop: {e}")
                time.sleep(self.config.trend_analysis_interval)
        
        logger.debug("Trend analysis loop stopped")
    
    def _analyze_health_trends(self):
        """Analyze trends in component health."""
        try:
            # This would implement sophisticated trend analysis
            # For now, it's a placeholder
            logger.debug("Analyzing health trends...")
            
        except Exception as e:
            logger.error(f"Failed to analyze health trends: {e}")
    
    def _certificate_monitoring_loop(self):
        """Monitor certificate lifecycle and validity."""
        logger.debug("Certificate monitoring loop started")
        
        while not self._shutdown_event.is_set():
            try:
                self._check_certificate_status()
                time.sleep(self.config.crl_check_interval)
                
            except Exception as e:
                logger.error(f"Error in certificate monitoring loop: {e}")
                time.sleep(self.config.crl_check_interval)
        
        logger.debug("Certificate monitoring loop stopped")
    
    def _check_certificate_status(self):
        """Check certificate validity and expiration."""
        try:
            # This would implement certificate status checking
            # For now, it's a placeholder
            logger.debug("Checking certificate status...")
            
        except Exception as e:
            logger.error(f"Failed to check certificate status: {e}")
    
    def _performance_analysis_loop(self):
        """Analyze performance patterns and baselines."""
        logger.debug("Performance analysis loop started")
        
        while not self._shutdown_event.is_set():
            try:
                self._update_performance_baselines()
                time.sleep(300)  # Run every 5 minutes
                
            except Exception as e:
                logger.error(f"Error in performance analysis loop: {e}")
                time.sleep(300)
        
        logger.debug("Performance analysis loop stopped")
    
    def _update_performance_baselines(self):
        """Update performance baselines for anomaly detection."""
        try:
            # This would implement baseline calculation
            # For now, it's a placeholder
            logger.debug("Updating performance baselines...")
            
        except Exception as e:
            logger.error(f"Failed to update performance baselines: {e}")
    
    def _process_health_events(self):
        """Process health events from queue."""
        try:
            while not self.health_event_queue.empty():
                try:
                    event = self.health_event_queue.get_nowait()
                    # Process health event
                    self.health_event_queue.task_done()
                except queue.Empty:
                    break
                    
        except Exception as e:
            logger.error(f"Failed to process health events: {e}")
    
    def _record_health_check_failure(self, component_id: str, error_message: str):
        """Record health check failure."""
        try:
            with self.health_lock:
                if component_id in self.component_health:
                    self.component_health[component_id].error_count += 1
                    self.component_health[component_id].overall_status = HealthStatus.CRITICAL
            
            logger.warning(f"Health check failure for {component_id}: {error_message}")
            
        except Exception as e:
            logger.error(f"Failed to record health check failure: {e}")
    
    def _log_failover_to_audit(self, event: FailoverEvent):
        """Log failover event to audit system."""
        try:
            if self.audit_logger:
                audit_event = AuditEvent(
                    event_type=AuditEventType.SECURITY_MONITORING,
                    timestamp=event.timestamp,
                    severity=AuditSeverity.HIGH if not event.success else AuditSeverity.MEDIUM,
                    action=f"failover_{event.strategy.value}",
                    resource_type="infrastructure",
                    resource_id=event.source_component,
                    result="SUCCESS" if event.success else "FAILURE",
                    additional_data={
                        'failover_event_id': event.event_id,
                        'trigger': event.trigger.value,
                        'source_component': event.source_component,
                        'target_component': event.target_component,
                        'duration_seconds': event.duration_seconds,
                        'user_impact': event.user_impact
                    }
                )
                
                self.audit_logger.log_event(audit_event)
                
        except Exception as e:
            logger.error(f"Failed to log failover to audit: {e}")
    
    def _register_card_monitor_observer(self):
        """Register as observer with card monitor."""
        try:
            # This would register with the card monitor
            logger.info("Registered with card status monitor")
            
        except Exception as e:
            logger.error(f"Failed to register with card monitor: {e}")
    
    def _save_statistics(self):
        """Save final statistics."""
        try:
            logger.info(f"Failover Detector Statistics:")
            logger.info(f"  Total health checks: {self.stats['total_health_checks']}")
            logger.info(f"  Total failovers: {self.stats['total_failovers']}")
            logger.info(f"  Successful failovers: {self.stats['successful_failovers']}")
            logger.info(f"  Success rate: {self.stats['successful_failovers']/max(1, self.stats['total_failovers'])*100:.1f}%")
            
        except Exception as e:
            logger.error(f"Failed to save statistics: {e}")
    
    def get_component_health_status(self, component_id: Optional[str] = None) -> Dict[str, Any]:
        """Get health status for components."""
        try:
            with self.health_lock:
                if component_id:
                    if component_id in self.component_health:
                        health = self.component_health[component_id]
                        return {
                            'component_id': health.component_id,
                            'component_type': health.component_type,
                            'overall_status': health.overall_status.value,
                            'last_check': health.last_check.isoformat(),
                            'error_count': health.error_count,
                            'warning_count': health.warning_count,
                            'availability_percentage': health.availability_percentage,
                            'metrics': {k: asdict(v) for k, v in health.metrics.items()}
                        }
                    else:
                        return {'error': f'Component {component_id} not found'}
                else:
                    # Return all component health statuses
                    return {
                        comp_id: {
                            'component_type': health.component_type,
                            'overall_status': health.overall_status.value,
                            'last_check': health.last_check.isoformat(),
                            'error_count': health.error_count,
                            'availability_percentage': health.availability_percentage
                        }
                        for comp_id, health in self.component_health.items()
                    }
                    
        except Exception as e:
            logger.error(f"Failed to get component health status: {e}")
            return {'error': str(e)}
    
    def get_failover_history(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get recent failover events."""
        try:
            recent_events = sorted(self.failover_events, 
                                 key=lambda x: x.timestamp, reverse=True)[:limit]
            
            return [
                {
                    'event_id': event.event_id,
                    'timestamp': event.timestamp.isoformat(),
                    'trigger': event.trigger.value,
                    'source_component': event.source_component,
                    'target_component': event.target_component,
                    'strategy': event.strategy.value,
                    'success': event.success,
                    'duration_seconds': event.duration_seconds,
                    'user_impact': event.user_impact,
                    'error_message': event.error_message
                }
                for event in recent_events
            ]
            
        except Exception as e:
            logger.error(f"Failed to get failover history: {e}")
            return []
    
    def get_monitoring_statistics(self) -> Dict[str, Any]:
        """Get monitoring statistics."""
        try:
            return {
                'system_status': {
                    'is_running': self.is_running,
                    'monitored_components': len(self.component_health),
                    'active_failovers': len(self.active_failovers)
                },
                'statistics': self.stats.copy(),
                'health_summary': {
                    'healthy': len([h for h in self.component_health.values() 
                                  if h.overall_status == HealthStatus.HEALTHY]),
                    'warning': len([h for h in self.component_health.values() 
                                  if h.overall_status == HealthStatus.WARNING]),
                    'critical': len([h for h in self.component_health.values() 
                                   if h.overall_status == HealthStatus.CRITICAL]),
                    'failed': len([h for h in self.component_health.values() 
                                 if h.overall_status == HealthStatus.FAILED])
                },
                'recent_failovers': len([e for e in self.failover_events 
                                       if (datetime.now(timezone.utc) - e.timestamp).total_seconds() < 3600])
            }
            
        except Exception as e:
            logger.error(f"Failed to get monitoring statistics: {e}")
            return {'error': str(e)}