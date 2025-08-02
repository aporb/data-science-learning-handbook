#!/usr/bin/env python3
"""
Prometheus Integration for CAC/PIV Security Monitoring

This module provides comprehensive Prometheus metrics integration for the CAC/PIV
security monitoring system, enabling advanced monitoring, alerting, and visualization
capabilities through Prometheus and Grafana.

Key Features:
- Custom metrics collection for security events
- Performance monitoring with detailed metrics
- Integration with existing Prometheus infrastructure
- Grafana dashboard configuration
- Alert manager integration
- Health check endpoints
- Service discovery support
- Multi-dimensional metrics with labels

Metrics Categories:
- Authentication metrics (success/failure rates, response times)
- Card reader health metrics (status, errors, performance)
- Security event metrics (threat levels, event types, correlations)
- System performance metrics (CPU, memory, network)
- Failover metrics (triggers, success rates, recovery times)
- Alert metrics (generation rates, delivery success, escalations)

Prometheus Features:
- Counter metrics for cumulative values
- Gauge metrics for current values
- Histogram metrics for distributions
- Summary metrics for quantiles
- Custom labels for multi-dimensional analysis
- Health check endpoints
- Service discovery integration

Author: Monitoring Infrastructure Team
Version: 1.0.0
"""

import os
import sys
import threading
import time
import logging
import json
import socket
from typing import Dict, List, Optional, Set, Callable, Any, Union, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from enum import Enum
from collections import defaultdict, deque
import http.server
import socketserver
from urllib.parse import urlparse, parse_qs
import weakref

# Import monitoring components
try:
    from .cac_piv_security_monitor import SecurityEvent, SecurityEventCategory, SecurityThreatLevel
    from .failover_detector import FailoverEvent, HealthStatus, ComponentHealth
    from .security_alerting import Alert, AlertStatus, AlertSeverity
except ImportError:
    # Minimal implementations for standalone operation
    logger = logging.getLogger(__name__)

# Prometheus client library simulation (in production, use prometheus_client)
class MetricType(Enum):
    COUNTER = "counter"
    GAUGE = "gauge"
    HISTOGRAM = "histogram"
    SUMMARY = "summary"


@dataclass
class PrometheusMetric:
    """Prometheus metric definition."""
    name: str
    metric_type: MetricType
    description: str
    labels: List[str] = field(default_factory=list)
    value: Union[int, float] = 0.0
    samples: Dict[str, Union[int, float]] = field(default_factory=dict)
    buckets: List[float] = field(default_factory=list)  # For histograms
    quantiles: List[float] = field(default_factory=list)  # For summaries
    
    def format_prometheus(self) -> str:
        """Format metric in Prometheus exposition format."""
        lines = []
        
        # Help text
        lines.append(f"# HELP {self.name} {self.description}")
        lines.append(f"# TYPE {self.name} {self.metric_type.value}")
        
        if self.metric_type == MetricType.COUNTER or self.metric_type == MetricType.GAUGE:
            if self.samples:
                for label_combination, value in self.samples.items():
                    lines.append(f"{self.name}{{{label_combination}}} {value}")
            else:
                lines.append(f"{self.name} {self.value}")
        
        elif self.metric_type == MetricType.HISTOGRAM:
            # Histogram buckets and count/sum
            for label_combination, value in self.samples.items():
                if "_bucket" in label_combination:
                    lines.append(f"{self.name}_bucket{{{label_combination}}} {value}")
                elif "_count" in label_combination:
                    lines.append(f"{self.name}_count{{{label_combination}}} {value}")
                elif "_sum" in label_combination:
                    lines.append(f"{self.name}_sum{{{label_combination}}} {value}")
        
        elif self.metric_type == MetricType.SUMMARY:
            # Summary quantiles and count/sum
            for label_combination, value in self.samples.items():
                if "quantile" in label_combination:
                    lines.append(f"{self.name}{{{label_combination}}} {value}")
                elif "_count" in label_combination:
                    lines.append(f"{self.name}_count{{{label_combination}}} {value}")
                elif "_sum" in label_combination:
                    lines.append(f"{self.name}_sum{{{label_combination}}} {value}")
        
        return "\n".join(lines)


class PrometheusConfiguration:
    """Configuration for Prometheus integration."""
    
    def __init__(self):
        # Server configuration
        self.metrics_port = 8080
        self.metrics_path = "/metrics"
        self.health_path = "/health"
        self.metrics_bind_address = "0.0.0.0"
        
        # Metrics configuration
        self.collection_interval = 15.0  # Seconds
        self.metrics_retention_samples = 1000
        self.enable_histograms = True
        self.enable_summaries = True
        
        # Default histogram buckets
        self.default_buckets = [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]
        
        # Default summary quantiles
        self.default_quantiles = [0.5, 0.9, 0.95, 0.99]
        
        # Service discovery
        self.enable_service_discovery = True
        self.service_name = "cac-piv-security-monitor"
        self.service_tags = ["security", "monitoring", "cac-piv"]
        
        # Alert manager integration
        self.alertmanager_enabled = False
        self.alertmanager_webhook_url = ""
        
        # Security
        self.enable_basic_auth = False
        self.basic_auth_username = ""
        self.basic_auth_password = ""
        
        # Load from environment
        self._load_from_environment()
    
    def _load_from_environment(self):
        """Load configuration from environment variables."""
        try:
            self.metrics_port = int(os.getenv('PROMETHEUS_METRICS_PORT', '8080'))
            self.metrics_bind_address = os.getenv('PROMETHEUS_BIND_ADDRESS', '0.0.0.0')
            self.collection_interval = float(os.getenv('PROMETHEUS_COLLECTION_INTERVAL', '15.0'))
            self.service_name = os.getenv('PROMETHEUS_SERVICE_NAME', self.service_name)
            
            self.enable_service_discovery = os.getenv('PROMETHEUS_SERVICE_DISCOVERY', 'true').lower() == 'true'
            self.alertmanager_enabled = os.getenv('PROMETHEUS_ALERTMANAGER_ENABLED', 'false').lower() == 'true'
            self.alertmanager_webhook_url = os.getenv('PROMETHEUS_ALERTMANAGER_WEBHOOK', '')
            
        except Exception as e:
            logging.getLogger(__name__).warning(f"Failed to load Prometheus config: {e}")


class PrometheusMetricsServer:
    """HTTP server for Prometheus metrics exposition."""
    
    def __init__(self, metrics_registry: 'PrometheusMetricsRegistry', config: PrometheusConfiguration):
        self.metrics_registry = metrics_registry
        self.config = config
        self.httpd: Optional[socketserver.TCPServer] = None
        self.server_thread: Optional[threading.Thread] = None
        self.is_running = False
    
    def start(self) -> bool:
        """Start metrics HTTP server."""
        try:
            handler = self._create_request_handler()
            
            self.httpd = socketserver.TCPServer(
                (self.config.metrics_bind_address, self.config.metrics_port),
                handler
            )
            
            self.server_thread = threading.Thread(
                target=self.httpd.serve_forever,
                name="PrometheusMetricsServer",
                daemon=True
            )
            
            self.server_thread.start()
            self.is_running = True
            
            logger.info(f"Prometheus metrics server started on {self.config.metrics_bind_address}:{self.config.metrics_port}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to start Prometheus metrics server: {e}")
            return False
    
    def stop(self):
        """Stop metrics HTTP server."""
        try:
            if self.httpd:
                self.httpd.shutdown()
                self.httpd.server_close()
            
            if self.server_thread and self.server_thread.is_alive():
                self.server_thread.join(timeout=5.0)
            
            self.is_running = False
            logger.info("Prometheus metrics server stopped")
            
        except Exception as e:
            logger.error(f"Failed to stop Prometheus metrics server: {e}")
    
    def _create_request_handler(self):
        """Create HTTP request handler class."""
        metrics_registry = self.metrics_registry
        config = self.config
        
        class PrometheusHandler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                try:
                    if self.path == config.metrics_path:
                        self._handle_metrics()
                    elif self.path == config.health_path:
                        self._handle_health()
                    else:
                        self._handle_not_found()
                        
                except Exception as e:
                    logger.error(f"Error handling request: {e}")
                    self._handle_error()
            
            def _handle_metrics(self):
                """Handle metrics endpoint."""
                try:
                    # Check authentication if enabled
                    if config.enable_basic_auth:
                        if not self._check_auth():
                            self._send_auth_required()
                            return
                    
                    # Get metrics from registry
                    metrics_output = metrics_registry.get_prometheus_output()
                    
                    self.send_response(200)
                    self.send_header('Content-Type', 'text/plain; version=0.0.4; charset=utf-8')
                    self.send_header('Content-Length', str(len(metrics_output)))
                    self.end_headers()
                    self.wfile.write(metrics_output.encode('utf-8'))
                    
                except Exception as e:
                    logger.error(f"Error handling metrics request: {e}")
                    self._handle_error()
            
            def _handle_health(self):
                """Handle health check endpoint."""
                try:
                    health_status = metrics_registry.get_health_status()
                    
                    self.send_response(200 if health_status['healthy'] else 503)
                    self.send_header('Content-Type', 'application/json')
                    self.end_headers()
                    
                    response = json.dumps(health_status, indent=2)
                    self.wfile.write(response.encode('utf-8'))
                    
                except Exception as e:
                    logger.error(f"Error handling health request: {e}")
                    self._handle_error()
            
            def _handle_not_found(self):
                """Handle 404 not found."""
                self.send_response(404)
                self.send_header('Content-Type', 'text/plain')
                self.end_headers()
                self.wfile.write(b'Not Found')
            
            def _handle_error(self):
                """Handle internal server error."""
                self.send_response(500)
                self.send_header('Content-Type', 'text/plain')
                self.end_headers()
                self.wfile.write(b'Internal Server Error')
            
            def _check_auth(self):
                """Check basic authentication."""
                try:
                    auth_header = self.headers.get('Authorization')
                    if not auth_header or not auth_header.startswith('Basic '):
                        return False
                    
                    import base64
                    credentials = base64.b64decode(auth_header[6:]).decode('utf-8')
                    username, password = credentials.split(':', 1)
                    
                    return (username == config.basic_auth_username and 
                            password == config.basic_auth_password)
                    
                except Exception:
                    return False
            
            def _send_auth_required(self):
                """Send authentication required response."""
                self.send_response(401)
                self.send_header('WWW-Authenticate', 'Basic realm="Prometheus Metrics"')
                self.send_header('Content-Type', 'text/plain')
                self.end_headers()
                self.wfile.write(b'Authentication Required')
            
            def log_message(self, format, *args):
                """Override to reduce log noise."""
                pass
        
        return PrometheusHandler


class PrometheusMetricsRegistry:
    """Registry for Prometheus metrics."""
    
    def __init__(self, config: PrometheusConfiguration):
        self.config = config
        self.metrics: Dict[str, PrometheusMetric] = {}
        self.metrics_lock = threading.RLock()
        
        # Health tracking
        self.component_health: Dict[str, bool] = {}
        self.last_collection_time: Optional[datetime] = None
        
        # Initialize default metrics
        self._initialize_default_metrics()
    
    def _initialize_default_metrics(self):
        """Initialize default security monitoring metrics."""
        try:
            # Authentication metrics
            self.register_counter(
                "cac_piv_authentication_attempts_total",
                "Total number of authentication attempts",
                ["user_type", "result", "method"]
            )
            
            self.register_counter(
                "cac_piv_authentication_failures_total",
                "Total number of authentication failures",
                ["user_type", "reason", "source_ip"]
            )
            
            self.register_histogram(
                "cac_piv_authentication_duration_seconds",
                "Time spent on authentication attempts",
                ["method", "result"],
                buckets=self.config.default_buckets
            )
            
            # Card reader metrics
            self.register_gauge(
                "cac_piv_card_readers_total",
                "Total number of card readers",
                ["status"]
            )
            
            self.register_counter(
                "cac_piv_card_operations_total",
                "Total number of card operations",
                ["reader_id", "operation", "result"]
            )
            
            self.register_gauge(
                "cac_piv_card_reader_health",
                "Health status of card readers (1=healthy, 0=unhealthy)",
                ["reader_id", "manufacturer"]
            )
            
            # Security event metrics
            self.register_counter(
                "cac_piv_security_events_total",
                "Total number of security events",
                ["category", "threat_level", "source_component"]
            )
            
            self.register_gauge(
                "cac_piv_threat_score_current",
                "Current threat score for entities",
                ["entity_type", "entity_id"]
            )
            
            self.register_counter(
                "cac_piv_security_violations_total",
                "Total number of security violations",
                ["violation_type", "severity", "user_id"]
            )
            
            # Failover metrics
            self.register_counter(
                "cac_piv_failover_events_total",
                "Total number of failover events",
                ["trigger", "source_component", "target_component", "result"]
            )
            
            self.register_histogram(
                "cac_piv_failover_duration_seconds",
                "Time taken for failover operations",
                ["strategy", "result"],
                buckets=[0.1, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0, 60.0]
            )
            
            self.register_gauge(
                "cac_piv_component_availability",
                "Availability of system components (1=available, 0=unavailable)",
                ["component_id", "component_type"]
            )
            
            # Alert metrics
            self.register_counter(
                "cac_piv_alerts_generated_total",
                "Total number of alerts generated",
                ["rule_id", "severity", "channel"]
            )
            
            self.register_counter(
                "cac_piv_alert_deliveries_total",
                "Total number of alert delivery attempts",
                ["channel", "result", "contact_type"]
            )
            
            self.register_gauge(
                "cac_piv_active_alerts",
                "Number of currently active alerts",
                ["severity", "status"]
            )
            
            self.register_histogram(
                "cac_piv_alert_response_time_seconds",
                "Time from alert generation to acknowledgment",
                ["severity", "escalation_level"],
                buckets=[60, 300, 900, 1800, 3600, 7200, 14400]  # 1min to 4hr
            )
            
            # System performance metrics
            self.register_gauge(
                "cac_piv_system_cpu_usage_percent",
                "System CPU usage percentage",
                ["hostname"]
            )
            
            self.register_gauge(
                "cac_piv_system_memory_usage_percent",
                "System memory usage percentage",
                ["hostname"]
            )
            
            self.register_gauge(
                "cac_piv_system_disk_usage_percent",
                "System disk usage percentage",
                ["hostname", "mount_point"]
            )
            
            # Certificate metrics
            self.register_gauge(
                "cac_piv_certificates_expiring_soon",
                "Number of certificates expiring within threshold",
                ["days_until_expiry", "certificate_type"]
            )
            
            self.register_counter(
                "cac_piv_certificate_validation_total",
                "Total number of certificate validations",
                ["result", "issuer", "certificate_type"]
            )
            
            # Audit metrics
            self.register_counter(
                "cac_piv_audit_events_total",
                "Total number of audit events",
                ["event_type", "severity", "classification_level"]
            )
            
            self.register_gauge(
                "cac_piv_audit_queue_size",
                "Current size of audit event queue",
                ["queue_type"]
            )
            
            logger.info(f"Initialized {len(self.metrics)} default Prometheus metrics")
            
        except Exception as e:
            logger.error(f"Failed to initialize default metrics: {e}")
    
    def register_counter(self, name: str, description: str, labels: List[str] = None) -> PrometheusMetric:
        """Register a counter metric."""
        metric = PrometheusMetric(
            name=name,
            metric_type=MetricType.COUNTER,
            description=description,
            labels=labels or []
        )
        
        with self.metrics_lock:
            self.metrics[name] = metric
        
        return metric
    
    def register_gauge(self, name: str, description: str, labels: List[str] = None) -> PrometheusMetric:
        """Register a gauge metric."""
        metric = PrometheusMetric(
            name=name,
            metric_type=MetricType.GAUGE,
            description=description,
            labels=labels or []
        )
        
        with self.metrics_lock:
            self.metrics[name] = metric
        
        return metric
    
    def register_histogram(self, name: str, description: str, labels: List[str] = None, 
                          buckets: List[float] = None) -> PrometheusMetric:
        """Register a histogram metric."""
        metric = PrometheusMetric(
            name=name,
            metric_type=MetricType.HISTOGRAM,
            description=description,
            labels=labels or [],
            buckets=buckets or self.config.default_buckets
        )
        
        with self.metrics_lock:
            self.metrics[name] = metric
        
        return metric
    
    def register_summary(self, name: str, description: str, labels: List[str] = None,
                        quantiles: List[float] = None) -> PrometheusMetric:
        """Register a summary metric."""
        metric = PrometheusMetric(
            name=name,
            metric_type=MetricType.SUMMARY,
            description=description,
            labels=labels or [],
            quantiles=quantiles or self.config.default_quantiles
        )
        
        with self.metrics_lock:
            self.metrics[name] = metric
        
        return metric
    
    def increment_counter(self, name: str, value: float = 1.0, labels: Dict[str, str] = None):
        """Increment a counter metric."""
        try:
            with self.metrics_lock:
                if name not in self.metrics:
                    logger.warning(f"Counter metric {name} not found")
                    return
                
                metric = self.metrics[name]
                if metric.metric_type != MetricType.COUNTER:
                    logger.warning(f"Metric {name} is not a counter")
                    return
                
                if labels:
                    label_str = ",".join([f'{k}="{v}"' for k, v in labels.items()])
                    current_value = metric.samples.get(label_str, 0.0)
                    metric.samples[label_str] = current_value + value
                else:
                    metric.value += value
                    
        except Exception as e:
            logger.error(f"Failed to increment counter {name}: {e}")
    
    def set_gauge(self, name: str, value: float, labels: Dict[str, str] = None):
        """Set a gauge metric value."""
        try:
            with self.metrics_lock:
                if name not in self.metrics:
                    logger.warning(f"Gauge metric {name} not found")
                    return
                
                metric = self.metrics[name]
                if metric.metric_type != MetricType.GAUGE:
                    logger.warning(f"Metric {name} is not a gauge")
                    return
                
                if labels:
                    label_str = ",".join([f'{k}="{v}"' for k, v in labels.items()])
                    metric.samples[label_str] = value
                else:
                    metric.value = value
                    
        except Exception as e:
            logger.error(f"Failed to set gauge {name}: {e}")
    
    def observe_histogram(self, name: str, value: float, labels: Dict[str, str] = None):
        """Observe a value in a histogram metric."""
        try:
            with self.metrics_lock:
                if name not in self.metrics:
                    logger.warning(f"Histogram metric {name} not found")
                    return
                
                metric = self.metrics[name]
                if metric.metric_type != MetricType.HISTOGRAM:
                    logger.warning(f"Metric {name} is not a histogram")
                    return
                
                label_prefix = ""
                if labels:
                    label_prefix = ",".join([f'{k}="{v}"' for k, v in labels.items()]) + ","
                
                # Update bucket counts
                for bucket in metric.buckets:
                    bucket_key = f"{label_prefix}le=\"{bucket}\""
                    if value <= bucket:
                        current_count = metric.samples.get(f"{label_prefix}le=\"{bucket}\"", 0)
                        metric.samples[bucket_key] = current_count + 1
                
                # Update count and sum
                count_key = f"{label_prefix}_count"
                sum_key = f"{label_prefix}_sum"
                
                metric.samples[count_key] = metric.samples.get(count_key, 0) + 1
                metric.samples[sum_key] = metric.samples.get(sum_key, 0.0) + value
                
        except Exception as e:
            logger.error(f"Failed to observe histogram {name}: {e}")
    
    def observe_summary(self, name: str, value: float, labels: Dict[str, str] = None):
        """Observe a value in a summary metric."""
        try:
            with self.metrics_lock:
                if name not in self.metrics:
                    logger.warning(f"Summary metric {name} not found")
                    return
                
                metric = self.metrics[name]
                if metric.metric_type != MetricType.SUMMARY:
                    logger.warning(f"Metric {name} is not a summary")
                    return
                
                label_prefix = ""
                if labels:
                    label_prefix = ",".join([f'{k}="{v}"' for k, v in labels.items()]) + ","
                
                # Update count and sum
                count_key = f"{label_prefix}_count"
                sum_key = f"{label_prefix}_sum"
                
                metric.samples[count_key] = metric.samples.get(count_key, 0) + 1
                metric.samples[sum_key] = metric.samples.get(sum_key, 0.0) + value
                
                # TODO: Calculate quantiles (requires maintaining sample history)
                # For now, just approximate
                for quantile in metric.quantiles:
                    quantile_key = f"{label_prefix}quantile=\"{quantile}\""
                    metric.samples[quantile_key] = value  # Simplified
                
        except Exception as e:
            logger.error(f"Failed to observe summary {name}: {e}")
    
    def get_prometheus_output(self) -> str:
        """Get metrics in Prometheus exposition format."""
        try:
            output_lines = []
            
            with self.metrics_lock:
                for metric in self.metrics.values():
                    output_lines.append(metric.format_prometheus())
                    output_lines.append("")  # Empty line between metrics
            
            self.last_collection_time = datetime.now(timezone.utc)
            return "\n".join(output_lines)
            
        except Exception as e:
            logger.error(f"Failed to generate Prometheus output: {e}")
            return "# Error generating metrics\n"
    
    def get_health_status(self) -> Dict[str, Any]:
        """Get health status for health check endpoint."""
        try:
            now = datetime.now(timezone.utc)
            healthy = True
            
            # Check if metrics collection is recent
            if self.last_collection_time:
                time_since_collection = (now - self.last_collection_time).total_seconds()
                if time_since_collection > self.config.collection_interval * 3:
                    healthy = False
            
            # Check component health
            unhealthy_components = [
                comp for comp, status in self.component_health.items() if not status
            ]
            
            if unhealthy_components:
                healthy = False
            
            return {
                'healthy': healthy,
                'timestamp': now.isoformat(),
                'metrics_count': len(self.metrics),
                'last_collection': self.last_collection_time.isoformat() if self.last_collection_time else None,
                'unhealthy_components': unhealthy_components
            }
            
        except Exception as e:
            logger.error(f"Failed to get health status: {e}")
            return {
                'healthy': False,
                'error': str(e),
                'timestamp': datetime.now(timezone.utc).isoformat()
            }


class PrometheusIntegration:
    """
    Main Prometheus integration class for CAC/PIV security monitoring.
    
    Provides comprehensive metrics collection and exposition for:
    - Security events and threats
    - Authentication performance
    - Card reader health
    - System performance
    - Alert management
    - Failover operations
    """
    
    def __init__(self, config: Optional[PrometheusConfiguration] = None):
        """
        Initialize Prometheus integration.
        
        Args:
            config: Prometheus configuration
        """
        self.config = config or PrometheusConfiguration()
        self.metrics_registry = PrometheusMetricsRegistry(self.config)
        self.metrics_server = PrometheusMetricsServer(self.metrics_registry, self.config)
        
        # State management
        self.is_running = False
        self._shutdown_event = threading.Event()
        self.collection_thread: Optional[threading.Thread] = None
        
        # Data sources
        self.security_monitor = None
        self.failover_detector = None
        self.alerting_system = None
        
        # Metrics collection state
        self.collection_stats = {
            'collections_total': 0,
            'collection_errors': 0,
            'last_collection_duration': 0.0
        }
        
        logger.info("Prometheus integration initialized")
    
    def start(self) -> bool:
        """Start Prometheus integration."""
        if self.is_running:
            logger.warning("Prometheus integration already running")
            return False
        
        try:
            logger.info("Starting Prometheus integration...")
            
            # Start metrics server
            if not self.metrics_server.start():
                return False
            
            # Start metrics collection
            self._start_metrics_collection()
            
            # Register service discovery if enabled
            if self.config.enable_service_discovery:
                self._register_service_discovery()
            
            self.is_running = True
            logger.info(f"Prometheus integration started on port {self.config.metrics_port}")
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to start Prometheus integration: {e}")
            return False
    
    def stop(self, timeout: float = 30.0) -> bool:
        """Stop Prometheus integration."""
        if not self.is_running:
            return True
        
        try:
            logger.info("Stopping Prometheus integration...")
            
            # Signal shutdown
            self._shutdown_event.set()
            self.is_running = False
            
            # Stop metrics collection
            if self.collection_thread and self.collection_thread.is_alive():
                self.collection_thread.join(timeout=timeout)
            
            # Stop metrics server
            self.metrics_server.stop()
            
            # Unregister service discovery
            if self.config.enable_service_discovery:
                self._unregister_service_discovery()
            
            logger.info("Prometheus integration stopped successfully")
            return True
            
        except Exception as e:
            logger.error(f"Error stopping Prometheus integration: {e}")
            return False
    
    def register_security_monitor(self, security_monitor):
        """Register security monitor for metrics collection."""
        self.security_monitor = security_monitor
        logger.info("Security monitor registered with Prometheus integration")
    
    def register_failover_detector(self, failover_detector):
        """Register failover detector for metrics collection."""
        self.failover_detector = failover_detector
        logger.info("Failover detector registered with Prometheus integration")
    
    def register_alerting_system(self, alerting_system):
        """Register alerting system for metrics collection."""
        self.alerting_system = alerting_system
        logger.info("Alerting system registered with Prometheus integration")
    
    def record_authentication_attempt(self, user_type: str, method: str, result: str, 
                                    duration: float, source_ip: str = None):
        """Record authentication attempt metrics."""
        try:
            # Increment attempt counter
            self.metrics_registry.increment_counter(
                "cac_piv_authentication_attempts_total",
                labels={"user_type": user_type, "result": result, "method": method}
            )
            
            # Record duration
            self.metrics_registry.observe_histogram(
                "cac_piv_authentication_duration_seconds",
                duration,
                labels={"method": method, "result": result}
            )
            
            # Record failure if applicable
            if result == "failure":
                self.metrics_registry.increment_counter(
                    "cac_piv_authentication_failures_total",
                    labels={
                        "user_type": user_type,
                        "reason": "authentication_failed",
                        "source_ip": source_ip or "unknown"
                    }
                )
                
        except Exception as e:
            logger.error(f"Failed to record authentication metrics: {e}")
    
    def record_security_event(self, event: SecurityEvent):
        """Record security event metrics."""
        try:
            # Increment security events counter
            self.metrics_registry.increment_counter(
                "cac_piv_security_events_total",
                labels={
                    "category": event.category.value,
                    "threat_level": event.threat_level.name,
                    "source_component": event.source_component or "unknown"
                }
            )
            
            # Update threat score if available
            if event.user_id:
                risk_score = event.calculate_risk_score()
                self.metrics_registry.set_gauge(
                    "cac_piv_threat_score_current",
                    risk_score,
                    labels={"entity_type": "user", "entity_id": event.user_id}
                )
            
            # Record security violations
            if event.threat_level <= SecurityThreatLevel.HIGH:
                self.metrics_registry.increment_counter(
                    "cac_piv_security_violations_total",
                    labels={
                        "violation_type": event.category.value,
                        "severity": event.threat_level.name,
                        "user_id": event.user_id or "unknown"
                    }
                )
                
        except Exception as e:
            logger.error(f"Failed to record security event metrics: {e}")
    
    def record_failover_event(self, event: FailoverEvent):
        """Record failover event metrics."""
        try:
            # Increment failover events counter
            self.metrics_registry.increment_counter(
                "cac_piv_failover_events_total",
                labels={
                    "trigger": event.trigger.value,
                    "source_component": event.source_component,
                    "target_component": event.target_component or "none",
                    "result": "success" if event.success else "failure"
                }
            )
            
            # Record failover duration
            self.metrics_registry.observe_histogram(
                "cac_piv_failover_duration_seconds",
                event.duration_seconds,
                labels={
                    "strategy": event.strategy.value,
                    "result": "success" if event.success else "failure"
                }
            )
            
        except Exception as e:
            logger.error(f"Failed to record failover metrics: {e}")
    
    def record_alert_event(self, alert: Alert, event_type: str):
        """Record alert-related metrics."""
        try:
            if event_type == "generated":
                self.metrics_registry.increment_counter(
                    "cac_piv_alerts_generated_total",
                    labels={
                        "rule_id": alert.rule_id,
                        "severity": alert.severity.name,
                        "channel": "multiple"
                    }
                )
            
            elif event_type == "acknowledged":
                if alert.acknowledged_at and alert.created_at:
                    response_time = (alert.acknowledged_at - alert.created_at).total_seconds()
                    self.metrics_registry.observe_histogram(
                        "cac_piv_alert_response_time_seconds",
                        response_time,
                        labels={
                            "severity": alert.severity.name,
                            "escalation_level": str(alert.escalation_level)
                        }
                    )
                    
        except Exception as e:
            logger.error(f"Failed to record alert metrics: {e}")
    
    def update_component_health(self, component_id: str, component_type: str, health_status: HealthStatus):
        """Update component health metrics."""
        try:
            # Convert health status to availability metric
            availability = 1.0 if health_status == HealthStatus.HEALTHY else 0.0
            
            self.metrics_registry.set_gauge(
                "cac_piv_component_availability",
                availability,
                labels={"component_id": component_id, "component_type": component_type}
            )
            
            # Update registry health tracking
            self.metrics_registry.component_health[component_id] = (health_status == HealthStatus.HEALTHY)
            
        except Exception as e:
            logger.error(f"Failed to update component health metrics: {e}")
    
    def update_card_reader_metrics(self, reader_id: str, status: str, health_score: float, 
                                 manufacturer: str = "unknown"):
        """Update card reader metrics."""
        try:
            # Set reader health gauge
            health_value = 1.0 if status == "healthy" else 0.0
            self.metrics_registry.set_gauge(
                "cac_piv_card_reader_health",
                health_value,
                labels={"reader_id": reader_id, "manufacturer": manufacturer}
            )
            
        except Exception as e:
            logger.error(f"Failed to update card reader metrics: {e}")
    
    def update_system_metrics(self, hostname: str, cpu_percent: float, memory_percent: float, 
                            disk_usage: Dict[str, float]):
        """Update system performance metrics."""
        try:
            # CPU usage
            self.metrics_registry.set_gauge(
                "cac_piv_system_cpu_usage_percent",
                cpu_percent,
                labels={"hostname": hostname}
            )
            
            # Memory usage
            self.metrics_registry.set_gauge(
                "cac_piv_system_memory_usage_percent",
                memory_percent,
                labels={"hostname": hostname}
            )
            
            # Disk usage
            for mount_point, usage_percent in disk_usage.items():
                self.metrics_registry.set_gauge(
                    "cac_piv_system_disk_usage_percent",
                    usage_percent,
                    labels={"hostname": hostname, "mount_point": mount_point}
                )
                
        except Exception as e:
            logger.error(f"Failed to update system metrics: {e}")
    
    def _start_metrics_collection(self):
        """Start background metrics collection."""
        self._shutdown_event.clear()
        
        self.collection_thread = threading.Thread(
            target=self._metrics_collection_loop,
            name="PrometheusMetricsCollection",
            daemon=True
        )
        self.collection_thread.start()
        
        logger.debug("Metrics collection thread started")
    
    def _metrics_collection_loop(self):
        """Background metrics collection loop."""
        logger.debug("Metrics collection loop started")
        
        while not self._shutdown_event.is_set():
            try:
                start_time = time.time()
                
                # Collect metrics from registered sources
                self._collect_all_metrics()
                
                # Update collection stats
                collection_duration = time.time() - start_time
                self.collection_stats['collections_total'] += 1
                self.collection_stats['last_collection_duration'] = collection_duration
                
                # Sleep until next collection
                self._shutdown_event.wait(self.config.collection_interval)
                
            except Exception as e:
                logger.error(f"Error in metrics collection loop: {e}")
                self.collection_stats['collection_errors'] += 1
                self._shutdown_event.wait(self.config.collection_interval)
        
        logger.debug("Metrics collection loop stopped")
    
    def _collect_all_metrics(self):
        """Collect metrics from all registered sources."""
        try:
            # Collect from security monitor
            if self.security_monitor:
                self._collect_security_monitor_metrics()
            
            # Collect from failover detector
            if self.failover_detector:
                self._collect_failover_detector_metrics()
            
            # Collect from alerting system
            if self.alerting_system:
                self._collect_alerting_system_metrics()
            
            # Collect system metrics
            self._collect_system_metrics()
            
        except Exception as e:
            logger.error(f"Failed to collect metrics: {e}")
    
    def _collect_security_monitor_metrics(self):
        """Collect metrics from security monitor."""
        try:
            if hasattr(self.security_monitor, 'get_monitoring_status'):
                status = self.security_monitor.get_monitoring_status()
                
                # Update system health metrics
                if 'health' in status:
                    health_data = status['health']
                    if 'queue_sizes' in health_data:
                        for queue_name, size in health_data['queue_sizes'].items():
                            self.metrics_registry.set_gauge(
                                "cac_piv_audit_queue_size",
                                size,
                                labels={"queue_type": queue_name}
                            )
                
        except Exception as e:
            logger.error(f"Failed to collect security monitor metrics: {e}")
    
    def _collect_failover_detector_metrics(self):
        """Collect metrics from failover detector."""
        try:
            if hasattr(self.failover_detector, 'get_component_health_status'):
                health_status = self.failover_detector.get_component_health_status()
                
                # Update component health metrics
                for component_id, health_data in health_status.items():
                    if isinstance(health_data, dict):
                        component_type = health_data.get('component_type', 'unknown')
                        overall_status = health_data.get('overall_status', 'unknown')
                        
                        availability = 1.0 if overall_status == 'healthy' else 0.0
                        self.metrics_registry.set_gauge(
                            "cac_piv_component_availability",
                            availability,
                            labels={"component_id": component_id, "component_type": component_type}
                        )
                
        except Exception as e:
            logger.error(f"Failed to collect failover detector metrics: {e}")
    
    def _collect_alerting_system_metrics(self):
        """Collect metrics from alerting system."""
        try:
            if hasattr(self.alerting_system, 'get_alerting_statistics'):
                stats = self.alerting_system.get_alerting_statistics()
                
                # Update alert metrics
                if 'system_status' in stats:
                    system_status = stats['system_status']
                    
                    # Active alerts by severity
                    if hasattr(self.alerting_system, 'active_alerts'):
                        severity_counts = defaultdict(int)
                        status_counts = defaultdict(int)
                        
                        for alert in self.alerting_system.active_alerts.values():
                            severity_counts[alert.severity.name] += 1
                            status_counts[alert.status.value] += 1
                        
                        for severity, count in severity_counts.items():
                            self.metrics_registry.set_gauge(
                                "cac_piv_active_alerts",
                                count,
                                labels={"severity": severity, "status": "active"}
                            )
                
        except Exception as e:
            logger.error(f"Failed to collect alerting system metrics: {e}")
    
    def _collect_system_metrics(self):
        """Collect system performance metrics."""
        try:
            import psutil
            
            hostname = socket.gethostname()
            
            # CPU usage
            cpu_percent = psutil.cpu_percent(interval=1)
            self.metrics_registry.set_gauge(
                "cac_piv_system_cpu_usage_percent",
                cpu_percent,
                labels={"hostname": hostname}
            )
            
            # Memory usage
            memory = psutil.virtual_memory()
            self.metrics_registry.set_gauge(
                "cac_piv_system_memory_usage_percent",
                memory.percent,
                labels={"hostname": hostname}
            )
            
            # Disk usage
            disk = psutil.disk_usage('/')
            disk_percent = (disk.used / disk.total) * 100
            self.metrics_registry.set_gauge(
                "cac_piv_system_disk_usage_percent",
                disk_percent,
                labels={"hostname": hostname, "mount_point": "/"}
            )
            
        except Exception as e:
            logger.error(f"Failed to collect system metrics: {e}")
    
    def _register_service_discovery(self):
        """Register service with service discovery."""
        try:
            # This would implement service discovery registration
            # (e.g., Consul, etcd, Kubernetes service discovery)
            logger.info(f"Service discovery registration for {self.config.service_name}")
            
        except Exception as e:
            logger.error(f"Failed to register service discovery: {e}")
    
    def _unregister_service_discovery(self):
        """Unregister service from service discovery."""
        try:
            # This would implement service discovery deregistration
            logger.info(f"Service discovery deregistration for {self.config.service_name}")
            
        except Exception as e:
            logger.error(f"Failed to unregister service discovery: {e}")
    
    def get_metrics_url(self) -> str:
        """Get URL for metrics endpoint."""
        return f"http://{self.config.metrics_bind_address}:{self.config.metrics_port}{self.config.metrics_path}"
    
    def get_health_url(self) -> str:
        """Get URL for health check endpoint."""
        return f"http://{self.config.metrics_bind_address}:{self.config.metrics_port}{self.config.health_path}"
    
    def get_integration_status(self) -> Dict[str, Any]:
        """Get Prometheus integration status."""
        try:
            return {
                'is_running': self.is_running,
                'metrics_server_running': self.metrics_server.is_running,
                'metrics_count': len(self.metrics_registry.metrics),
                'collection_stats': self.collection_stats.copy(),
                'config': {
                    'metrics_port': self.config.metrics_port,
                    'collection_interval': self.config.collection_interval,
                    'service_discovery_enabled': self.config.enable_service_discovery
                },
                'endpoints': {
                    'metrics': self.get_metrics_url(),
                    'health': self.get_health_url()
                },
                'registered_sources': {
                    'security_monitor': self.security_monitor is not None,
                    'failover_detector': self.failover_detector is not None,
                    'alerting_system': self.alerting_system is not None
                }
            }
            
        except Exception as e:
            logger.error(f"Failed to get integration status: {e}")
            return {'error': str(e)}


# Global logger
logger = logging.getLogger(__name__)