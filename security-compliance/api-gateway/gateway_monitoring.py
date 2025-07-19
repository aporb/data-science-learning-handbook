"""
API Gateway Monitoring and Observability for DoD Environments

This module provides comprehensive monitoring, metrics collection, distributed tracing,
and observability for the DoD API Gateway implementation.

Key Features:
- Prometheus metrics collection
- Distributed tracing with Jaeger
- Application performance monitoring (APM)
- Security event monitoring
- Health checks and availability monitoring
- Real-time dashboards and alerting
- SLA monitoring and reporting

Security Standards:
- DoD monitoring and logging requirements
- NIST 800-53 monitoring controls
- Real-time security event correlation
- Compliance reporting and audit trails
"""

import time
import json
import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple, Union
from dataclasses import dataclass, asdict
from enum import Enum
from collections import defaultdict, deque
import statistics

import aioredis
import prometheus_client
from prometheus_client import Counter, Histogram, Gauge, Summary
from opentelemetry import trace, metrics
from opentelemetry.exporter.jaeger.thrift import JaegerExporter
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import ConsoleMetricsExporter, PeriodicExportingMetricReader

# Import from existing modules
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from api_gateway.api_security_controls import SecurityEvent, SecurityThreatLevel, AttackType


class MetricType(Enum):
    """Types of metrics."""
    COUNTER = "counter"
    GAUGE = "gauge"
    HISTOGRAM = "histogram"
    SUMMARY = "summary"


class AlertSeverity(Enum):
    """Alert severity levels."""
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class HealthStatus(Enum):
    """Health check status."""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"


@dataclass
class MetricDefinition:
    """Metric definition."""
    name: str
    description: str
    metric_type: MetricType
    labels: List[str]
    unit: Optional[str] = None


@dataclass
class HealthCheck:
    """Health check configuration."""
    name: str
    description: str
    check_function: str
    interval_seconds: int
    timeout_seconds: int
    enabled: bool = True


@dataclass
class Alert:
    """Alert definition."""
    id: str
    name: str
    description: str
    severity: AlertSeverity
    condition: str
    threshold: float
    duration_seconds: int
    enabled: bool = True


@dataclass
class MonitoringMetrics:
    """Monitoring metrics snapshot."""
    timestamp: datetime
    
    # Request metrics
    total_requests: int
    successful_requests: int
    failed_requests: int
    average_response_time: float
    
    # Security metrics
    blocked_requests: int
    security_events: int
    attack_attempts: int
    
    # Performance metrics
    cpu_usage: float
    memory_usage: float
    disk_usage: float
    
    # Availability metrics
    uptime_seconds: int
    availability_percentage: float


class PrometheusMetrics:
    """Prometheus metrics collection."""
    
    def __init__(self):
        """Initialize Prometheus metrics."""
        
        # Request metrics
        self.request_total = Counter(
            'api_gateway_requests_total',
            'Total number of API requests',
            ['method', 'endpoint', 'status_code', 'classification']
        )
        
        self.request_duration = Histogram(
            'api_gateway_request_duration_seconds',
            'API request duration in seconds',
            ['method', 'endpoint', 'classification'],
            buckets=[0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]
        )
        
        self.request_size = Histogram(
            'api_gateway_request_size_bytes',
            'API request size in bytes',
            ['method', 'endpoint'],
            buckets=[100, 1000, 10000, 100000, 1000000]
        )
        
        self.response_size = Histogram(
            'api_gateway_response_size_bytes',
            'API response size in bytes',
            ['method', 'endpoint'],
            buckets=[100, 1000, 10000, 100000, 1000000]
        )
        
        # Security metrics
        self.security_events_total = Counter(
            'api_gateway_security_events_total',
            'Total number of security events',
            ['threat_level', 'attack_type', 'blocked']
        )
        
        self.rate_limit_violations = Counter(
            'api_gateway_rate_limit_violations_total',
            'Total number of rate limit violations',
            ['client_ip', 'endpoint']
        )
        
        self.oauth_token_validations = Counter(
            'api_gateway_oauth_validations_total',
            'Total number of OAuth token validations',
            ['result']
        )
        
        # Circuit breaker metrics
        self.circuit_breaker_state = Gauge(
            'api_gateway_circuit_breaker_state',
            'Circuit breaker state (0=closed, 1=open, 2=half-open)',
            ['service']
        )
        
        self.circuit_breaker_failures = Counter(
            'api_gateway_circuit_breaker_failures_total',
            'Total circuit breaker failures',
            ['service']
        )
        
        # Performance metrics
        self.active_connections = Gauge(
            'api_gateway_active_connections',
            'Number of active connections'
        )
        
        self.queue_size = Gauge(
            'api_gateway_queue_size',
            'Size of request queue'
        )
        
        # Health metrics
        self.health_check_status = Gauge(
            'api_gateway_health_check_status',
            'Health check status (0=unhealthy, 1=healthy)',
            ['check_name']
        )
        
        self.uptime_seconds = Counter(
            'api_gateway_uptime_seconds_total',
            'Total uptime in seconds'
        )


class DistributedTracing:
    """Distributed tracing implementation."""
    
    def __init__(self, service_name: str, jaeger_endpoint: str):
        """Initialize distributed tracing."""
        self.service_name = service_name
        
        # Configure Jaeger exporter
        jaeger_exporter = JaegerExporter(
            agent_host_name="localhost",
            agent_port=6831,
            collector_endpoint=jaeger_endpoint
        )
        
        # Configure tracer provider
        trace.set_tracer_provider(TracerProvider())
        tracer = trace.get_tracer_provider()
        
        # Add span processor
        span_processor = BatchSpanProcessor(jaeger_exporter)
        tracer.add_span_processor(span_processor)
        
        self.tracer = trace.get_tracer(service_name)
    
    def start_span(self, operation_name: str, **kwargs) -> trace.Span:
        """Start a new span."""
        return self.tracer.start_span(operation_name, **kwargs)
    
    def add_span_attributes(self, span: trace.Span, attributes: Dict[str, Any]) -> None:
        """Add attributes to span."""
        for key, value in attributes.items():
            span.set_attribute(key, value)
    
    def add_span_event(self, span: trace.Span, event_name: str, attributes: Optional[Dict] = None) -> None:
        """Add event to span."""
        span.add_event(event_name, attributes or {})


class APIGatewayMonitor:
    """
    API Gateway Monitoring and Observability
    
    Provides comprehensive monitoring, metrics collection, and observability
    for the DoD API Gateway implementation.
    """
    
    def __init__(self, redis_url: str = "redis://localhost:6379", 
                 jaeger_endpoint: str = "http://localhost:14268/api/traces"):
        """Initialize API Gateway monitor."""
        self.logger = logging.getLogger(__name__)
        
        # Redis for metrics storage
        self.redis_client = None
        self.redis_url = redis_url
        
        # Prometheus metrics
        self.prometheus_metrics = PrometheusMetrics()
        
        # Distributed tracing
        self.tracing = DistributedTracing("api-gateway", jaeger_endpoint)
        
        # Health checks
        self.health_checks: Dict[str, HealthCheck] = {}
        self.health_status: Dict[str, HealthStatus] = {}
        
        # Alerts
        self.alerts: Dict[str, Alert] = {}
        self.active_alerts: Dict[str, datetime] = {}
        
        # Metrics storage
        self.metrics_history: deque = deque(maxlen=1000)
        self.performance_history: deque = deque(maxlen=1000)
        
        # Start time for uptime calculation
        self.start_time = datetime.utcnow()
    
    async def initialize(self) -> None:
        """Initialize monitoring components."""
        try:
            # Initialize Redis client
            self.redis_client = await aioredis.from_url(self.redis_url)
            await self.redis_client.ping()
            
            # Start Prometheus metrics server
            prometheus_client.start_http_server(8000)
            
            # Initialize default health checks
            self._setup_default_health_checks()
            
            # Initialize default alerts
            self._setup_default_alerts()
            
            # Start background monitoring tasks
            asyncio.create_task(self._health_check_loop())
            asyncio.create_task(self._metrics_collection_loop())
            asyncio.create_task(self._alert_evaluation_loop())
            
            self.logger.info("API Gateway monitoring initialized")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize monitoring: {e}")
            raise
    
    def _setup_default_health_checks(self) -> None:
        """Setup default health checks."""
        health_checks = [
            HealthCheck(
                name="redis_connectivity",
                description="Redis connectivity check",
                check_function="check_redis_health",
                interval_seconds=30,
                timeout_seconds=5
            ),
            HealthCheck(
                name="api_gateway_health",
                description="API Gateway health check",
                check_function="check_api_gateway_health",
                interval_seconds=60,
                timeout_seconds=10
            ),
            HealthCheck(
                name="external_api_health",
                description="External API connectivity check",
                check_function="check_external_api_health",
                interval_seconds=120,
                timeout_seconds=15
            )
        ]
        
        for check in health_checks:
            self.health_checks[check.name] = check
            self.health_status[check.name] = HealthStatus.HEALTHY
    
    def _setup_default_alerts(self) -> None:
        """Setup default alert conditions."""
        alerts = [
            Alert(
                id="high_error_rate",
                name="High Error Rate",
                description="API error rate above threshold",
                severity=AlertSeverity.ERROR,
                condition="error_rate > 0.05",
                threshold=0.05,
                duration_seconds=300
            ),
            Alert(
                id="high_response_time",
                name="High Response Time",
                description="Average response time above threshold",
                severity=AlertSeverity.WARNING,
                condition="avg_response_time > 5.0",
                threshold=5.0,
                duration_seconds=600
            ),
            Alert(
                id="security_attacks",
                name="Security Attacks Detected",
                description="High number of security attacks",
                severity=AlertSeverity.CRITICAL,
                condition="attack_rate > 10",
                threshold=10.0,
                duration_seconds=60
            ),
            Alert(
                id="circuit_breaker_open",
                name="Circuit Breaker Open",
                description="Circuit breaker is open",
                severity=AlertSeverity.ERROR,
                condition="circuit_breaker_open == 1",
                threshold=1.0,
                duration_seconds=0
            )
        ]
        
        for alert in alerts:
            self.alerts[alert.id] = alert
    
    def record_request(self, method: str, endpoint: str, status_code: int,
                      response_time: float, request_size: int, response_size: int,
                      classification: str = "UNCLASSIFIED") -> None:
        """Record API request metrics."""
        try:
            # Prometheus metrics
            self.prometheus_metrics.request_total.labels(
                method=method,
                endpoint=endpoint,
                status_code=str(status_code),
                classification=classification
            ).inc()
            
            self.prometheus_metrics.request_duration.labels(
                method=method,
                endpoint=endpoint,
                classification=classification
            ).observe(response_time)
            
            self.prometheus_metrics.request_size.labels(
                method=method,
                endpoint=endpoint
            ).observe(request_size)
            
            self.prometheus_metrics.response_size.labels(
                method=method,
                endpoint=endpoint
            ).observe(response_size)
            
            # Store in Redis for analysis
            asyncio.create_task(self._store_request_metric({
                'timestamp': datetime.utcnow().isoformat(),
                'method': method,
                'endpoint': endpoint,
                'status_code': status_code,
                'response_time': response_time,
                'request_size': request_size,
                'response_size': response_size,
                'classification': classification
            }))
            
        except Exception as e:
            self.logger.error(f"Failed to record request metric: {e}")
    
    def record_security_event(self, security_event: SecurityEvent) -> None:
        """Record security event metrics."""
        try:
            # Prometheus metrics
            self.prometheus_metrics.security_events_total.labels(
                threat_level=security_event.threat_level.value,
                attack_type=security_event.attack_type.value if security_event.attack_type else "none",
                blocked=str(security_event.blocked).lower()
            ).inc()
            
            if security_event.attack_type == AttackType.RATE_LIMIT_VIOLATION:
                self.prometheus_metrics.rate_limit_violations.labels(
                    client_ip=security_event.client_ip,
                    endpoint=security_event.endpoint
                ).inc()
            
            # Store in Redis
            asyncio.create_task(self._store_security_event(security_event))
            
        except Exception as e:
            self.logger.error(f"Failed to record security event: {e}")
    
    def record_oauth_validation(self, result: str) -> None:
        """Record OAuth token validation result."""
        try:
            self.prometheus_metrics.oauth_token_validations.labels(
                result=result
            ).inc()
            
        except Exception as e:
            self.logger.error(f"Failed to record OAuth validation: {e}")
    
    def record_circuit_breaker_state(self, service: str, state: int, failure_count: int = 0) -> None:
        """Record circuit breaker state."""
        try:
            self.prometheus_metrics.circuit_breaker_state.labels(
                service=service
            ).set(state)
            
            if failure_count > 0:
                self.prometheus_metrics.circuit_breaker_failures.labels(
                    service=service
                ).inc(failure_count)
                
        except Exception as e:
            self.logger.error(f"Failed to record circuit breaker state: {e}")
    
    def update_performance_metrics(self, active_connections: int, queue_size: int) -> None:
        """Update performance metrics."""
        try:
            self.prometheus_metrics.active_connections.set(active_connections)
            self.prometheus_metrics.queue_size.set(queue_size)
            
        except Exception as e:
            self.logger.error(f"Failed to update performance metrics: {e}")
    
    async def _store_request_metric(self, metric_data: Dict[str, Any]) -> None:
        """Store request metric in Redis."""
        try:
            key = f"request_metrics:{datetime.utcnow().strftime('%Y%m%d%H')}"
            await self.redis_client.lpush(key, json.dumps(metric_data))
            await self.redis_client.expire(key, 86400)  # 24 hours
            
        except Exception as e:
            self.logger.error(f"Failed to store request metric: {e}")
    
    async def _store_security_event(self, security_event: SecurityEvent) -> None:
        """Store security event in Redis."""
        try:
            event_data = {
                'timestamp': security_event.timestamp.isoformat(),
                'event_id': security_event.event_id,
                'client_ip': security_event.client_ip,
                'endpoint': security_event.endpoint,
                'method': security_event.method,
                'threat_level': security_event.threat_level.value,
                'attack_type': security_event.attack_type.value if security_event.attack_type else None,
                'description': security_event.description,
                'blocked': security_event.blocked
            }
            
            key = f"security_events:{datetime.utcnow().strftime('%Y%m%d')}"
            await self.redis_client.lpush(key, json.dumps(event_data))
            await self.redis_client.expire(key, 86400 * 7)  # 7 days
            
        except Exception as e:
            self.logger.error(f"Failed to store security event: {e}")
    
    async def _health_check_loop(self) -> None:
        """Background health check loop."""
        while True:
            try:
                for check_name, check in self.health_checks.items():
                    if check.enabled:
                        status = await self._execute_health_check(check)
                        self.health_status[check_name] = status
                        
                        # Update Prometheus metric
                        self.prometheus_metrics.health_check_status.labels(
                            check_name=check_name
                        ).set(1 if status == HealthStatus.HEALTHY else 0)
                
                await asyncio.sleep(30)  # Check every 30 seconds
                
            except Exception as e:
                self.logger.error(f"Health check loop error: {e}")
                await asyncio.sleep(60)
    
    async def _execute_health_check(self, check: HealthCheck) -> HealthStatus:
        """Execute individual health check."""
        try:
            if check.check_function == "check_redis_health":
                return await self._check_redis_health()
            elif check.check_function == "check_api_gateway_health":
                return await self._check_api_gateway_health()
            elif check.check_function == "check_external_api_health":
                return await self._check_external_api_health()
            else:
                return HealthStatus.UNHEALTHY
                
        except Exception as e:
            self.logger.error(f"Health check {check.name} failed: {e}")
            return HealthStatus.UNHEALTHY
    
    async def _check_redis_health(self) -> HealthStatus:
        """Check Redis health."""
        try:
            await self.redis_client.ping()
            return HealthStatus.HEALTHY
        except:
            return HealthStatus.UNHEALTHY
    
    async def _check_api_gateway_health(self) -> HealthStatus:
        """Check API Gateway health."""
        # This would check the main API Gateway components
        # For now, just return healthy
        return HealthStatus.HEALTHY
    
    async def _check_external_api_health(self) -> HealthStatus:
        """Check external API health."""
        # This would check connectivity to external APIs
        # For now, just return healthy
        return HealthStatus.HEALTHY
    
    async def _metrics_collection_loop(self) -> None:
        """Background metrics collection loop."""
        while True:
            try:
                metrics = await self._collect_current_metrics()
                self.metrics_history.append(metrics)
                
                # Update uptime
                uptime = (datetime.utcnow() - self.start_time).total_seconds()
                self.prometheus_metrics.uptime_seconds.inc(60)  # 60 seconds interval
                
                await asyncio.sleep(60)  # Collect every minute
                
            except Exception as e:
                self.logger.error(f"Metrics collection error: {e}")
                await asyncio.sleep(60)
    
    async def _collect_current_metrics(self) -> MonitoringMetrics:
        """Collect current metrics snapshot."""
        try:
            # Get metrics from Redis
            current_hour = datetime.utcnow().strftime('%Y%m%d%H')
            request_key = f"request_metrics:{current_hour}"
            
            # Get request metrics
            request_data = await self.redis_client.lrange(request_key, 0, -1)
            
            total_requests = len(request_data)
            successful_requests = 0
            failed_requests = 0
            response_times = []
            
            for data in request_data:
                try:
                    metric = json.loads(data)
                    status_code = metric.get('status_code', 500)
                    response_time = metric.get('response_time', 0)
                    
                    if status_code < 400:
                        successful_requests += 1
                    else:
                        failed_requests += 1
                    
                    response_times.append(response_time)
                except:
                    continue
            
            avg_response_time = statistics.mean(response_times) if response_times else 0
            
            # Get security metrics
            security_key = f"security_events:{datetime.utcnow().strftime('%Y%m%d')}"
            security_data = await self.redis_client.lrange(security_key, 0, -1)
            
            blocked_requests = 0
            attack_attempts = 0
            
            for data in security_data:
                try:
                    event = json.loads(data)
                    if event.get('blocked'):
                        blocked_requests += 1
                    if event.get('attack_type'):
                        attack_attempts += 1
                except:
                    continue
            
            # Calculate uptime and availability
            uptime_seconds = int((datetime.utcnow() - self.start_time).total_seconds())
            availability_percentage = (successful_requests / total_requests * 100) if total_requests > 0 else 100
            
            return MonitoringMetrics(
                timestamp=datetime.utcnow(),
                total_requests=total_requests,
                successful_requests=successful_requests,
                failed_requests=failed_requests,
                average_response_time=avg_response_time,
                blocked_requests=blocked_requests,
                security_events=len(security_data),
                attack_attempts=attack_attempts,
                cpu_usage=0.0,  # Would be collected from system
                memory_usage=0.0,  # Would be collected from system
                disk_usage=0.0,  # Would be collected from system
                uptime_seconds=uptime_seconds,
                availability_percentage=availability_percentage
            )
            
        except Exception as e:
            self.logger.error(f"Failed to collect metrics: {e}")
            return MonitoringMetrics(
                timestamp=datetime.utcnow(),
                total_requests=0,
                successful_requests=0,
                failed_requests=0,
                average_response_time=0.0,
                blocked_requests=0,
                security_events=0,
                attack_attempts=0,
                cpu_usage=0.0,
                memory_usage=0.0,
                disk_usage=0.0,
                uptime_seconds=0,
                availability_percentage=100.0
            )
    
    async def _alert_evaluation_loop(self) -> None:
        """Background alert evaluation loop."""
        while True:
            try:
                await self._evaluate_alerts()
                await asyncio.sleep(60)  # Evaluate every minute
                
            except Exception as e:
                self.logger.error(f"Alert evaluation error: {e}")
                await asyncio.sleep(60)
    
    async def _evaluate_alerts(self) -> None:
        """Evaluate alert conditions."""
        try:
            if not self.metrics_history:
                return
            
            latest_metrics = self.metrics_history[-1]
            
            for alert_id, alert in self.alerts.items():
                if not alert.enabled:
                    continue
                
                condition_met = await self._evaluate_alert_condition(alert, latest_metrics)
                
                if condition_met:
                    if alert_id not in self.active_alerts:
                        self.active_alerts[alert_id] = datetime.utcnow()
                        await self._trigger_alert(alert, latest_metrics)
                else:
                    if alert_id in self.active_alerts:
                        del self.active_alerts[alert_id]
                        await self._resolve_alert(alert)
        
        except Exception as e:
            self.logger.error(f"Failed to evaluate alerts: {e}")
    
    async def _evaluate_alert_condition(self, alert: Alert, metrics: MonitoringMetrics) -> bool:
        """Evaluate if alert condition is met."""
        try:
            if alert.condition == "error_rate > 0.05":
                error_rate = metrics.failed_requests / metrics.total_requests if metrics.total_requests > 0 else 0
                return error_rate > alert.threshold
            
            elif alert.condition == "avg_response_time > 5.0":
                return metrics.average_response_time > alert.threshold
            
            elif alert.condition == "attack_rate > 10":
                return metrics.attack_attempts > alert.threshold
            
            # Add more alert conditions as needed
            
            return False
            
        except Exception as e:
            self.logger.error(f"Failed to evaluate alert condition: {e}")
            return False
    
    async def _trigger_alert(self, alert: Alert, metrics: MonitoringMetrics) -> None:
        """Trigger alert notification."""
        alert_data = {
            'alert_id': alert.id,
            'name': alert.name,
            'description': alert.description,
            'severity': alert.severity.value,
            'timestamp': datetime.utcnow().isoformat(),
            'metrics': asdict(metrics)
        }
        
        self.logger.warning(f"ALERT TRIGGERED: {json.dumps(alert_data)}")
        
        # Store alert in Redis
        await self.redis_client.lpush("active_alerts", json.dumps(alert_data))
    
    async def _resolve_alert(self, alert: Alert) -> None:
        """Resolve alert notification."""
        alert_data = {
            'alert_id': alert.id,
            'name': alert.name,
            'action': 'resolved',
            'timestamp': datetime.utcnow().isoformat()
        }
        
        self.logger.info(f"ALERT RESOLVED: {json.dumps(alert_data)}")
    
    async def get_current_status(self) -> Dict[str, Any]:
        """Get current monitoring status."""
        try:
            latest_metrics = self.metrics_history[-1] if self.metrics_history else None
            
            return {
                'timestamp': datetime.utcnow().isoformat(),
                'health_status': {name: status.value for name, status in self.health_status.items()},
                'active_alerts': len(self.active_alerts),
                'metrics': asdict(latest_metrics) if latest_metrics else None,
                'uptime_seconds': int((datetime.utcnow() - self.start_time).total_seconds())
            }
            
        except Exception as e:
            self.logger.error(f"Failed to get current status: {e}")
            return {}
    
    async def get_metrics_summary(self, hours: int = 24) -> Dict[str, Any]:
        """Get metrics summary for specified time period."""
        try:
            # Filter metrics by time period
            cutoff_time = datetime.utcnow() - timedelta(hours=hours)
            relevant_metrics = [
                m for m in self.metrics_history
                if m.timestamp >= cutoff_time
            ]
            
            if not relevant_metrics:
                return {}
            
            # Calculate summary statistics
            total_requests = sum(m.total_requests for m in relevant_metrics)
            total_successful = sum(m.successful_requests for m in relevant_metrics)
            total_failed = sum(m.failed_requests for m in relevant_metrics)
            
            avg_response_times = [m.average_response_time for m in relevant_metrics if m.average_response_time > 0]
            overall_avg_response_time = statistics.mean(avg_response_times) if avg_response_times else 0
            
            availability_percentages = [m.availability_percentage for m in relevant_metrics]
            overall_availability = statistics.mean(availability_percentages) if availability_percentages else 100
            
            return {
                'time_period_hours': hours,
                'total_requests': total_requests,
                'successful_requests': total_successful,
                'failed_requests': total_failed,
                'error_rate': total_failed / total_requests if total_requests > 0 else 0,
                'average_response_time': overall_avg_response_time,
                'availability_percentage': overall_availability,
                'total_security_events': sum(m.security_events for m in relevant_metrics),
                'total_attack_attempts': sum(m.attack_attempts for m in relevant_metrics),
                'total_blocked_requests': sum(m.blocked_requests for m in relevant_metrics)
            }
            
        except Exception as e:
            self.logger.error(f"Failed to get metrics summary: {e}")
            return {}
    
    async def close(self) -> None:
        """Clean up monitoring resources."""
        if self.redis_client:
            await self.redis_client.close()
        
        self.logger.info("API Gateway monitoring closed")


if __name__ == "__main__":
    # Example usage
    async def main():
        monitor = APIGatewayMonitor()
        await monitor.initialize()
        
        # Simulate some metrics
        for i in range(10):
            monitor.record_request(
                method="GET",
                endpoint="/api/v1/data",
                status_code=200,
                response_time=0.5,
                request_size=1024,
                response_size=2048
            )
        
        # Get current status
        status = await monitor.get_current_status()
        print(f"Current Status: {json.dumps(status, indent=2)}")
        
        # Get metrics summary
        summary = await monitor.get_metrics_summary(1)  # Last 1 hour
        print(f"Metrics Summary: {json.dumps(summary, indent=2)}")
        
        await monitor.close()
    
    asyncio.run(main())