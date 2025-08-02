"""
DoD API Gateway Health Monitoring System

This module implements comprehensive health monitoring and dependency validation
for services registered with the DoD API Gateway, providing real-time health
status tracking, dependency chain monitoring, and automated failover support.

Key Features:
- Multi-dimensional health checks (HTTP, TCP, custom protocols)
- Dependency chain validation and cascade failure detection
- Automated failover and circuit breaker patterns
- Real-time health status tracking and alerting
- Performance metrics collection and trending
- SLA monitoring and compliance reporting
- Integration with service registry and load balancers

Security Standards:
- NIST 800-53 monitoring controls
- DoD 8500 series health monitoring requirements
- FIPS 140-2 secure communication for health checks
- STIGs compliance for monitoring infrastructure
"""

import asyncio
import aiohttp
import time
import json
import logging
import statistics
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple, Set, Callable
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict, deque
import socket
import ssl

# Import from existing modules
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from api_gateway.service_registry import (
    ServiceRegistry, ServiceStatus, ServiceRegistration, ServiceEndpoint
)
from api_gateway.dod_api_gateway import SecurityClassification, APIGatewayEnvironment
from audits.audit_logger import AuditLogger
from monitoring.security_alerting import SecurityAlertingSystem


class HealthCheckType(Enum):
    """Types of health checks."""
    HTTP = "http"
    HTTPS = "https"
    TCP = "tcp"
    UDP = "udp"
    GRPC = "grpc"
    CUSTOM = "custom"
    DEPENDENCY = "dependency"
    SYNTHETIC = "synthetic"


class HealthCheckResult(Enum):
    """Health check result status."""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    TIMEOUT = "timeout"
    ERROR = "error"
    UNKNOWN = "unknown"


class CircuitBreakerState(Enum):
    """Circuit breaker states."""
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class AlertSeverity(Enum):
    """Alert severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class HealthCheckConfig:
    """Health check configuration."""
    check_type: HealthCheckType
    endpoint: str
    interval_seconds: int = 30
    timeout_seconds: int = 10
    retries: int = 3
    retry_delay_seconds: int = 1
    expected_status_codes: List[int] = field(default_factory=lambda: [200, 201, 204])
    expected_response_pattern: Optional[str] = None
    custom_headers: Dict[str, str] = field(default_factory=dict)
    ssl_verify: bool = True
    follow_redirects: bool = False


@dataclass
class HealthMetrics:
    """Health check metrics."""
    check_count: int = 0
    success_count: int = 0
    failure_count: int = 0
    timeout_count: int = 0
    avg_response_time: float = 0.0
    min_response_time: float = float('inf')
    max_response_time: float = 0.0
    last_success: Optional[datetime] = None
    last_failure: Optional[datetime] = None
    uptime_percentage: float = 100.0
    response_times: deque = field(default_factory=lambda: deque(maxlen=100))


@dataclass
class HealthCheckData:
    """Individual health check result data."""
    timestamp: datetime
    check_type: HealthCheckType
    endpoint: str
    result: HealthCheckResult
    response_time: float
    status_code: Optional[int] = None
    response_body: Optional[str] = None
    error_message: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DependencyCheck:
    """Service dependency health check."""
    service_id: str
    dependency_service_id: str
    dependency_type: str
    required: bool = True
    timeout_seconds: int = 30
    health_endpoint: Optional[str] = None


@dataclass
class CircuitBreakerConfig:
    """Circuit breaker configuration."""
    failure_threshold: int = 5
    timeout_seconds: int = 60
    half_open_max_calls: int = 3
    monitoring_window_seconds: int = 300


@dataclass
class SLAConfig:
    """Service Level Agreement configuration."""
    uptime_percentage: float = 99.9
    response_time_percentile: int = 95
    max_response_time_ms: float = 1000.0
    error_rate_threshold: float = 1.0
    monitoring_window_hours: int = 24


class HealthMonitor:
    """
    DoD API Gateway Health Monitoring System
    
    Comprehensive health monitoring with dependency validation, circuit breakers,
    and automated failover support for DoD environments.
    """
    
    def __init__(self, service_registry: ServiceRegistry):
        """Initialize health monitor."""
        self.logger = logging.getLogger(__name__)
        
        # Core components
        self.service_registry = service_registry
        self.audit_logger = None
        self.alerting_system = None
        
        # Health check configurations
        self.health_configs: Dict[str, HealthCheckConfig] = {}
        self.dependency_checks: Dict[str, List[DependencyCheck]] = defaultdict(list)
        
        # Health monitoring state
        self.health_metrics: Dict[str, HealthMetrics] = defaultdict(HealthMetrics)
        self.health_history: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        self.current_health_status: Dict[str, HealthCheckResult] = {}
        
        # Circuit breakers
        self.circuit_breakers: Dict[str, Dict] = {}
        self.circuit_breaker_configs: Dict[str, CircuitBreakerConfig] = {}
        
        # SLA monitoring
        self.sla_configs: Dict[str, SLAConfig] = {}
        self.sla_violations: Dict[str, List[Dict]] = defaultdict(list)
        
        # Background tasks
        self._monitoring_tasks: Dict[str, asyncio.Task] = {}
        self._dependency_task = None
        self._metrics_task = None
        self._circuit_breaker_task = None
        
        # HTTP session for health checks
        self._session = None
        
        # Custom health check handlers
        self.custom_handlers: Dict[str, Callable] = {}
    
    async def initialize(self) -> None:
        """Initialize health monitoring system."""
        try:
            # Initialize audit logging
            self.audit_logger = AuditLogger()
            await self.audit_logger.initialize()
            
            # Initialize alerting system
            self.alerting_system = SecurityAlertingSystem()
            await self.alerting_system.initialize()
            
            # Create HTTP session for health checks
            timeout = aiohttp.ClientTimeout(total=30)
            connector = aiohttp.TCPConnector(
                limit=100,
                ssl=ssl.create_default_context(),
                enable_cleanup_closed=True
            )
            
            self._session = aiohttp.ClientSession(
                timeout=timeout,
                connector=connector,
                headers={'User-Agent': 'DoD-API-Gateway-HealthMonitor/1.0'}
            )
            
            # Start background monitoring tasks
            self._dependency_task = asyncio.create_task(self._monitor_dependencies())
            self._metrics_task = asyncio.create_task(self._calculate_metrics())
            self._circuit_breaker_task = asyncio.create_task(self._manage_circuit_breakers())
            
            self.logger.info("Health Monitor initialized successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize health monitor: {e}")
            raise
    
    async def register_health_check(self, service_id: str, config: HealthCheckConfig) -> None:
        """Register health check for a service."""
        try:
            self.health_configs[service_id] = config
            
            # Initialize metrics
            if service_id not in self.health_metrics:
                self.health_metrics[service_id] = HealthMetrics()
            
            # Initialize circuit breaker
            self.circuit_breakers[service_id] = {
                'state': CircuitBreakerState.CLOSED,
                'failure_count': 0,
                'last_failure_time': None,
                'half_open_attempts': 0
            }
            
            # Start monitoring task for this service
            if service_id not in self._monitoring_tasks:
                self._monitoring_tasks[service_id] = asyncio.create_task(
                    self._monitor_service_health(service_id)
                )
            
            # Log registration
            await self.audit_logger.log_event(
                event_type="health_check_registered",
                user_id="system",
                resource_id=service_id,
                details={
                    'check_type': config.check_type.value,
                    'endpoint': config.endpoint,
                    'interval_seconds': config.interval_seconds
                }
            )
            
            self.logger.info(f"Health check registered for service: {service_id}")
            
        except Exception as e:
            self.logger.error(f"Failed to register health check for {service_id}: {e}")
            raise
    
    async def register_dependency_check(self, service_id: str, dependency: DependencyCheck) -> None:
        """Register dependency check for a service."""
        try:
            self.dependency_checks[service_id].append(dependency)
            
            # Log dependency registration
            await self.audit_logger.log_event(
                event_type="dependency_check_registered",
                user_id="system",
                resource_id=service_id,
                details={
                    'dependency_service_id': dependency.dependency_service_id,
                    'dependency_type': dependency.dependency_type,
                    'required': dependency.required
                }
            )
            
            self.logger.info(f"Dependency check registered: {service_id} -> {dependency.dependency_service_id}")
            
        except Exception as e:
            self.logger.error(f"Failed to register dependency check: {e}")
            raise
    
    async def configure_circuit_breaker(self, service_id: str, config: CircuitBreakerConfig) -> None:
        """Configure circuit breaker for a service."""
        try:
            self.circuit_breaker_configs[service_id] = config
            
            # Initialize circuit breaker state if not exists
            if service_id not in self.circuit_breakers:
                self.circuit_breakers[service_id] = {
                    'state': CircuitBreakerState.CLOSED,
                    'failure_count': 0,
                    'last_failure_time': None,
                    'half_open_attempts': 0
                }
            
            self.logger.info(f"Circuit breaker configured for service: {service_id}")
            
        except Exception as e:
            self.logger.error(f"Failed to configure circuit breaker for {service_id}: {e}")
            raise
    
    async def configure_sla(self, service_id: str, config: SLAConfig) -> None:
        """Configure SLA monitoring for a service."""
        try:
            self.sla_configs[service_id] = config
            
            self.logger.info(f"SLA configuration set for service: {service_id}")
            
        except Exception as e:
            self.logger.error(f"Failed to configure SLA for {service_id}: {e}")
            raise
    
    async def perform_health_check(self, service_id: str) -> HealthCheckData:
        """Perform immediate health check for a service."""
        try:
            config = self.health_configs.get(service_id)
            if not config:
                raise ValueError(f"No health check configuration found for service: {service_id}")
            
            # Check circuit breaker state
            circuit_breaker = self.circuit_breakers.get(service_id, {})
            if circuit_breaker.get('state') == CircuitBreakerState.OPEN:
                return HealthCheckData(
                    timestamp=datetime.utcnow(),
                    check_type=config.check_type,
                    endpoint=config.endpoint,
                    result=HealthCheckResult.UNHEALTHY,
                    response_time=0.0,
                    error_message="Circuit breaker is open"
                )
            
            # Perform health check based on type
            if config.check_type in [HealthCheckType.HTTP, HealthCheckType.HTTPS]:
                return await self._perform_http_health_check(service_id, config)
            elif config.check_type == HealthCheckType.TCP:
                return await self._perform_tcp_health_check(service_id, config)
            elif config.check_type == HealthCheckType.GRPC:
                return await self._perform_grpc_health_check(service_id, config)
            elif config.check_type == HealthCheckType.CUSTOM:
                return await self._perform_custom_health_check(service_id, config)
            elif config.check_type == HealthCheckType.DEPENDENCY:
                return await self._perform_dependency_health_check(service_id, config)
            else:
                raise ValueError(f"Unsupported health check type: {config.check_type}")
            
        except Exception as e:
            self.logger.error(f"Health check failed for {service_id}: {e}")
            return HealthCheckData(
                timestamp=datetime.utcnow(),
                check_type=config.check_type if config else HealthCheckType.HTTP,
                endpoint=config.endpoint if config else "",
                result=HealthCheckResult.ERROR,
                response_time=0.0,
                error_message=str(e)
            )
    
    async def _perform_http_health_check(self, service_id: str, config: HealthCheckConfig) -> HealthCheckData:
        """Perform HTTP/HTTPS health check."""
        start_time = time.time()
        
        try:
            # Prepare request headers
            headers = config.custom_headers.copy()
            headers.setdefault('Accept', 'application/json')
            
            # Configure SSL verification
            ssl_context = None
            if config.check_type == HealthCheckType.HTTPS:
                ssl_context = ssl.create_default_context()
                if not config.ssl_verify:
                    ssl_context.check_hostname = False
                    ssl_context.verify_mode = ssl.CERT_NONE
            
            # Make HTTP request
            async with self._session.get(
                config.endpoint,
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=config.timeout_seconds),
                ssl=ssl_context,
                allow_redirects=config.follow_redirects
            ) as response:
                
                response_time = time.time() - start_time
                response_body = await response.text()
                
                # Check status code
                if response.status in config.expected_status_codes:
                    # Check response pattern if configured
                    if config.expected_response_pattern:
                        import re
                        if not re.search(config.expected_response_pattern, response_body):
                            return HealthCheckData(
                                timestamp=datetime.utcnow(),
                                check_type=config.check_type,
                                endpoint=config.endpoint,
                                result=HealthCheckResult.DEGRADED,
                                response_time=response_time,
                                status_code=response.status,
                                response_body=response_body[:500],  # Truncate for logging
                                error_message="Response pattern not matched"
                            )
                    
                    # Health check passed
                    return HealthCheckData(
                        timestamp=datetime.utcnow(),
                        check_type=config.check_type,
                        endpoint=config.endpoint,
                        result=HealthCheckResult.HEALTHY,
                        response_time=response_time,
                        status_code=response.status,
                        response_body=response_body[:500]  # Truncate for logging
                    )
                else:
                    # Unexpected status code
                    return HealthCheckData(
                        timestamp=datetime.utcnow(),
                        check_type=config.check_type,
                        endpoint=config.endpoint,
                        result=HealthCheckResult.UNHEALTHY,
                        response_time=response_time,
                        status_code=response.status,
                        response_body=response_body[:500],
                        error_message=f"Unexpected status code: {response.status}"
                    )
        
        except asyncio.TimeoutError:
            response_time = time.time() - start_time
            return HealthCheckData(
                timestamp=datetime.utcnow(),
                check_type=config.check_type,
                endpoint=config.endpoint,
                result=HealthCheckResult.TIMEOUT,
                response_time=response_time,
                error_message="Request timeout"
            )
        
        except Exception as e:
            response_time = time.time() - start_time
            return HealthCheckData(
                timestamp=datetime.utcnow(),
                check_type=config.check_type,
                endpoint=config.endpoint,
                result=HealthCheckResult.ERROR,
                response_time=response_time,
                error_message=str(e)
            )
    
    async def _perform_tcp_health_check(self, service_id: str, config: HealthCheckConfig) -> HealthCheckData:
        """Perform TCP health check."""
        start_time = time.time()
        
        try:
            # Parse endpoint to get host and port
            from urllib.parse import urlparse
            parsed = urlparse(f"tcp://{config.endpoint}")
            host = parsed.hostname
            port = parsed.port
            
            if not host or not port:
                raise ValueError("Invalid TCP endpoint format")
            
            # Attempt TCP connection
            future = asyncio.open_connection(host, port)
            reader, writer = await asyncio.wait_for(future, timeout=config.timeout_seconds)
            
            # Close connection immediately
            writer.close()
            await writer.wait_closed()
            
            response_time = time.time() - start_time
            
            return HealthCheckData(
                timestamp=datetime.utcnow(),
                check_type=config.check_type,
                endpoint=config.endpoint,
                result=HealthCheckResult.HEALTHY,
                response_time=response_time
            )
        
        except asyncio.TimeoutError:
            response_time = time.time() - start_time
            return HealthCheckData(
                timestamp=datetime.utcnow(),
                check_type=config.check_type,
                endpoint=config.endpoint,
                result=HealthCheckResult.TIMEOUT,
                response_time=response_time,
                error_message="TCP connection timeout"
            )
        
        except Exception as e:
            response_time = time.time() - start_time
            return HealthCheckData(
                timestamp=datetime.utcnow(),
                check_type=config.check_type,
                endpoint=config.endpoint,
                result=HealthCheckResult.ERROR,
                response_time=response_time,
                error_message=str(e)
            )
    
    async def _perform_grpc_health_check(self, service_id: str, config: HealthCheckConfig) -> HealthCheckData:
        """Perform gRPC health check."""
        # Placeholder for gRPC health check implementation
        # In production, use grpcio-health-checking
        return HealthCheckData(
            timestamp=datetime.utcnow(),
            check_type=config.check_type,
            endpoint=config.endpoint,
            result=HealthCheckResult.UNKNOWN,
            response_time=0.0,
            error_message="gRPC health check not implemented"
        )
    
    async def _perform_custom_health_check(self, service_id: str, config: HealthCheckConfig) -> HealthCheckData:
        """Perform custom health check using registered handler."""
        try:
            handler = self.custom_handlers.get(service_id)
            if not handler:
                raise ValueError(f"No custom handler registered for service: {service_id}")
            
            start_time = time.time()
            result = await handler(service_id, config)
            response_time = time.time() - start_time
            
            if isinstance(result, bool):
                # Convert boolean result to HealthCheckData
                return HealthCheckData(
                    timestamp=datetime.utcnow(),
                    check_type=config.check_type,
                    endpoint=config.endpoint,
                    result=HealthCheckResult.HEALTHY if result else HealthCheckResult.UNHEALTHY,
                    response_time=response_time
                )
            elif isinstance(result, HealthCheckData):
                return result
            else:
                raise ValueError("Custom handler must return bool or HealthCheckData")
        
        except Exception as e:
            return HealthCheckData(
                timestamp=datetime.utcnow(),
                check_type=config.check_type,
                endpoint=config.endpoint,
                result=HealthCheckResult.ERROR,
                response_time=0.0,
                error_message=str(e)
            )
    
    async def _perform_dependency_health_check(self, service_id: str, config: HealthCheckConfig) -> HealthCheckData:
        """Perform dependency chain health check."""
        try:
            dependencies = self.dependency_checks.get(service_id, [])
            if not dependencies:
                return HealthCheckData(
                    timestamp=datetime.utcnow(),
                    check_type=config.check_type,
                    endpoint=config.endpoint,
                    result=HealthCheckResult.HEALTHY,
                    response_time=0.0,
                    metadata={'dependencies_count': 0}
                )
            
            start_time = time.time()
            failed_dependencies = []
            degraded_dependencies = []
            
            for dependency in dependencies:
                # Check dependency health
                dep_status = self.current_health_status.get(dependency.dependency_service_id)
                
                if dependency.required:
                    if dep_status in [HealthCheckResult.UNHEALTHY, HealthCheckResult.ERROR, HealthCheckResult.TIMEOUT]:
                        failed_dependencies.append(dependency.dependency_service_id)
                    elif dep_status == HealthCheckResult.DEGRADED:
                        degraded_dependencies.append(dependency.dependency_service_id)
                
            response_time = time.time() - start_time
            
            # Determine overall health based on dependencies
            if failed_dependencies:
                result = HealthCheckResult.UNHEALTHY
                error_message = f"Required dependencies unhealthy: {', '.join(failed_dependencies)}"
            elif degraded_dependencies:
                result = HealthCheckResult.DEGRADED
                error_message = f"Required dependencies degraded: {', '.join(degraded_dependencies)}"
            else:
                result = HealthCheckResult.HEALTHY
                error_message = None
            
            return HealthCheckData(
                timestamp=datetime.utcnow(),
                check_type=config.check_type,
                endpoint=config.endpoint,
                result=result,
                response_time=response_time,
                error_message=error_message,
                metadata={
                    'dependencies_count': len(dependencies),
                    'failed_dependencies': failed_dependencies,
                    'degraded_dependencies': degraded_dependencies
                }
            )
        
        except Exception as e:
            return HealthCheckData(
                timestamp=datetime.utcnow(),
                check_type=config.check_type,
                endpoint=config.endpoint,
                result=HealthCheckResult.ERROR,
                response_time=0.0,
                error_message=str(e)
            )
    
    async def _monitor_service_health(self, service_id: str) -> None:
        """Background task to monitor service health."""
        config = self.health_configs.get(service_id)
        if not config:
            return
        
        while True:
            try:
                # Perform health check
                health_data = await self.perform_health_check(service_id)
                
                # Update metrics
                self._update_health_metrics(service_id, health_data)
                
                # Store health history
                self.health_history[service_id].append(health_data)
                
                # Update current status
                self.current_health_status[service_id] = health_data.result
                
                # Update service registry status
                service_status = self._convert_to_service_status(health_data.result)
                await self.service_registry.update_service_health(service_id, service_status)
                
                # Update circuit breaker
                self._update_circuit_breaker(service_id, health_data)
                
                # Check SLA compliance
                await self._check_sla_compliance(service_id, health_data)
                
                # Send alerts if needed
                await self._check_and_send_alerts(service_id, health_data)
                
                # Log health check
                await self._log_health_check(service_id, health_data)
                
                # Sleep until next check
                await asyncio.sleep(config.interval_seconds)
                
            except Exception as e:
                self.logger.error(f"Error in health monitoring for {service_id}: {e}")
                await asyncio.sleep(config.interval_seconds)
    
    def _update_health_metrics(self, service_id: str, health_data: HealthCheckData) -> None:
        """Update health metrics for a service."""
        metrics = self.health_metrics[service_id]
        
        metrics.check_count += 1
        metrics.response_times.append(health_data.response_time)
        
        if health_data.result == HealthCheckResult.HEALTHY:
            metrics.success_count += 1
            metrics.last_success = health_data.timestamp
        else:
            metrics.failure_count += 1
            metrics.last_failure = health_data.timestamp
            
            if health_data.result == HealthCheckResult.TIMEOUT:
                metrics.timeout_count += 1
        
        # Update response time statistics
        if health_data.response_time > 0:
            metrics.min_response_time = min(metrics.min_response_time, health_data.response_time)
            metrics.max_response_time = max(metrics.max_response_time, health_data.response_time)
            
            if metrics.response_times:
                metrics.avg_response_time = statistics.mean(metrics.response_times)
        
        # Calculate uptime percentage
        if metrics.check_count > 0:
            metrics.uptime_percentage = (metrics.success_count / metrics.check_count) * 100
    
    def _convert_to_service_status(self, health_result: HealthCheckResult) -> ServiceStatus:
        """Convert health check result to service status."""
        if health_result == HealthCheckResult.HEALTHY:
            return ServiceStatus.HEALTHY
        elif health_result == HealthCheckResult.DEGRADED:
            return ServiceStatus.DEGRADED
        elif health_result in [HealthCheckResult.UNHEALTHY, HealthCheckResult.ERROR, HealthCheckResult.TIMEOUT]:
            return ServiceStatus.UNHEALTHY
        else:
            return ServiceStatus.UNKNOWN
    
    def _update_circuit_breaker(self, service_id: str, health_data: HealthCheckData) -> None:
        """Update circuit breaker state based on health check result."""
        if service_id not in self.circuit_breakers:
            return
        
        circuit_breaker = self.circuit_breakers[service_id]
        config = self.circuit_breaker_configs.get(service_id)
        
        if not config:
            return
        
        current_time = datetime.utcnow()
        
        if health_data.result in [HealthCheckResult.HEALTHY]:
            # Reset failure count on success
            circuit_breaker['failure_count'] = 0
            
            # Handle half-open state
            if circuit_breaker['state'] == CircuitBreakerState.HALF_OPEN:
                circuit_breaker['half_open_attempts'] += 1
                if circuit_breaker['half_open_attempts'] >= config.half_open_max_calls:
                    circuit_breaker['state'] = CircuitBreakerState.CLOSED
                    circuit_breaker['half_open_attempts'] = 0
        
        else:
            # Increment failure count
            circuit_breaker['failure_count'] += 1
            circuit_breaker['last_failure_time'] = current_time
            
            # Check if threshold reached
            if (circuit_breaker['state'] == CircuitBreakerState.CLOSED and 
                circuit_breaker['failure_count'] >= config.failure_threshold):
                circuit_breaker['state'] = CircuitBreakerState.OPEN
                
                # Log circuit breaker opening
                self.logger.warning(f"Circuit breaker opened for service: {service_id}")
    
    async def _check_sla_compliance(self, service_id: str, health_data: HealthCheckData) -> None:
        """Check SLA compliance and record violations."""
        sla_config = self.sla_configs.get(service_id)
        if not sla_config:
            return
        
        metrics = self.health_metrics[service_id]
        violations = []
        
        # Check uptime SLA
        if metrics.uptime_percentage < sla_config.uptime_percentage:
            violations.append({
                'type': 'uptime',
                'expected': sla_config.uptime_percentage,
                'actual': metrics.uptime_percentage,
                'timestamp': health_data.timestamp
            })
        
        # Check response time SLA
        if (health_data.response_time * 1000 > sla_config.max_response_time_ms and
            health_data.result == HealthCheckResult.HEALTHY):
            violations.append({
                'type': 'response_time',
                'expected': sla_config.max_response_time_ms,
                'actual': health_data.response_time * 1000,
                'timestamp': health_data.timestamp
            })
        
        # Check error rate SLA
        if metrics.check_count > 0:
            error_rate = (metrics.failure_count / metrics.check_count) * 100
            if error_rate > sla_config.error_rate_threshold:
                violations.append({
                    'type': 'error_rate',
                    'expected': sla_config.error_rate_threshold,
                    'actual': error_rate,
                    'timestamp': health_data.timestamp
                })
        
        # Record violations
        if violations:
            self.sla_violations[service_id].extend(violations)
            
            # Send SLA violation alerts
            for violation in violations:
                await self.alerting_system.send_alert(
                    alert_type="sla_violation",
                    severity="high",
                    message=f"SLA violation for service {service_id}: {violation['type']}",
                    metadata={
                        'service_id': service_id,
                        'violation_type': violation['type'],
                        'expected': violation['expected'],
                        'actual': violation['actual']
                    }
                )
    
    async def _check_and_send_alerts(self, service_id: str, health_data: HealthCheckData) -> None:
        """Check if alerts should be sent based on health status."""
        try:
            # Determine alert severity
            severity = None
            if health_data.result == HealthCheckResult.UNHEALTHY:
                severity = AlertSeverity.HIGH
            elif health_data.result == HealthCheckResult.DEGRADED:
                severity = AlertSeverity.MEDIUM
            elif health_data.result in [HealthCheckResult.ERROR, HealthCheckResult.TIMEOUT]:
                severity = AlertSeverity.CRITICAL
            
            if severity:
                # Check if we should send alert (avoid spam)
                metrics = self.health_metrics[service_id]
                if (metrics.last_failure and 
                    (health_data.timestamp - metrics.last_failure).total_seconds() < 300):
                    # Don't send alert if last failure was within 5 minutes
                    return
                
                await self.alerting_system.send_alert(
                    alert_type="service_health_alert",
                    severity=severity.value,
                    message=f"Service {service_id} health check failed: {health_data.result.value}",
                    metadata={
                        'service_id': service_id,
                        'health_result': health_data.result.value,
                        'response_time': health_data.response_time,
                        'error_message': health_data.error_message,
                        'endpoint': health_data.endpoint
                    }
                )
        
        except Exception as e:
            self.logger.error(f"Failed to send health alert for {service_id}: {e}")
    
    async def _log_health_check(self, service_id: str, health_data: HealthCheckData) -> None:
        """Log health check result for audit purposes."""
        try:
            await self.audit_logger.log_event(
                event_type="health_check_performed",
                user_id="system",
                resource_id=service_id,
                details={
                    'check_type': health_data.check_type.value,
                    'endpoint': health_data.endpoint,
                    'result': health_data.result.value,
                    'response_time': health_data.response_time,
                    'status_code': health_data.status_code,
                    'error_message': health_data.error_message
                }
            )
        except Exception as e:
            self.logger.error(f"Failed to log health check for {service_id}: {e}")
    
    async def _monitor_dependencies(self) -> None:
        """Background task to monitor service dependencies."""
        while True:
            try:
                # Check for dependency health cascades
                for service_id, dependencies in self.dependency_checks.items():
                    if dependencies:
                        # Perform dependency checks
                        config = HealthCheckConfig(
                            check_type=HealthCheckType.DEPENDENCY,
                            endpoint="dependencies",
                            interval_seconds=60
                        )
                        
                        dep_health = await self._perform_dependency_health_check(service_id, config)
                        self.current_health_status[f"{service_id}_dependencies"] = dep_health.result
                
                await asyncio.sleep(60)  # Check dependencies every minute
                
            except Exception as e:
                self.logger.error(f"Error in dependency monitoring: {e}")
                await asyncio.sleep(60)
    
    async def _calculate_metrics(self) -> None:
        """Background task to calculate and update metrics."""
        while True:
            try:
                # Calculate aggregated metrics periodically
                # This could include trend analysis, capacity planning metrics, etc.
                await asyncio.sleep(300)  # Run every 5 minutes
                
            except Exception as e:
                self.logger.error(f"Error in metrics calculation: {e}")
                await asyncio.sleep(300)
    
    async def _manage_circuit_breakers(self) -> None:
        """Background task to manage circuit breaker states."""
        while True:
            try:
                current_time = datetime.utcnow()
                
                for service_id, circuit_breaker in self.circuit_breakers.items():
                    config = self.circuit_breaker_configs.get(service_id)
                    if not config:
                        continue
                    
                    # Handle circuit breaker state transitions
                    if circuit_breaker['state'] == CircuitBreakerState.OPEN:
                        if circuit_breaker['last_failure_time']:
                            time_since_failure = (current_time - circuit_breaker['last_failure_time']).total_seconds()
                            
                            if time_since_failure >= config.timeout_seconds:
                                # Transition to half-open
                                circuit_breaker['state'] = CircuitBreakerState.HALF_OPEN
                                circuit_breaker['half_open_attempts'] = 0
                                
                                self.logger.info(f"Circuit breaker transitioned to half-open for service: {service_id}")
                
                await asyncio.sleep(30)  # Check every 30 seconds
                
            except Exception as e:
                self.logger.error(f"Error in circuit breaker management: {e}")
                await asyncio.sleep(30)
    
    def register_custom_handler(self, service_id: str, handler: Callable) -> None:
        """Register custom health check handler for a service."""
        self.custom_handlers[service_id] = handler
        self.logger.info(f"Custom health check handler registered for service: {service_id}")
    
    async def get_health_status(self, service_id: str) -> Optional[HealthCheckResult]:
        """Get current health status for a service."""
        return self.current_health_status.get(service_id)
    
    async def get_health_metrics(self, service_id: str) -> Optional[HealthMetrics]:
        """Get health metrics for a service."""
        return self.health_metrics.get(service_id)
    
    async def get_health_history(self, service_id: str, limit: int = 100) -> List[HealthCheckData]:
        """Get health check history for a service."""
        history = self.health_history.get(service_id, deque())
        return list(history)[-limit:]
    
    async def get_circuit_breaker_status(self, service_id: str) -> Optional[Dict[str, Any]]:
        """Get circuit breaker status for a service."""
        return self.circuit_breakers.get(service_id)
    
    async def get_sla_violations(self, service_id: str) -> List[Dict[str, Any]]:
        """Get SLA violations for a service."""
        return self.sla_violations.get(service_id, [])
    
    async def get_overall_health_status(self) -> Dict[str, Any]:
        """Get overall health status across all services."""
        status_counts = defaultdict(int)
        total_services = len(self.current_health_status)
        
        for result in self.current_health_status.values():
            status_counts[result.value] += 1
        
        overall_health = "healthy"
        if status_counts.get("unhealthy", 0) > 0:
            overall_health = "unhealthy"
        elif status_counts.get("degraded", 0) > 0:
            overall_health = "degraded"
        
        return {
            'overall_status': overall_health,
            'total_services': total_services,
            'status_distribution': dict(status_counts),
            'healthy_percentage': (status_counts.get("healthy", 0) / total_services * 100) if total_services > 0 else 0
        }
    
    async def close(self) -> None:
        """Clean up resources."""
        try:
            # Cancel all monitoring tasks
            for task in self._monitoring_tasks.values():
                task.cancel()
            
            if self._dependency_task:
                self._dependency_task.cancel()
            if self._metrics_task:
                self._metrics_task.cancel()
            if self._circuit_breaker_task:
                self._circuit_breaker_task.cancel()
            
            # Close HTTP session
            if self._session:
                await self._session.close()
            
            # Close audit logger
            if self.audit_logger:
                await self.audit_logger.close()
            
            # Close alerting system
            if self.alerting_system:
                await self.alerting_system.close()
            
            self.logger.info("Health Monitor closed")
            
        except Exception as e:
            self.logger.error(f"Error closing health monitor: {e}")


# Configuration factories
def create_production_health_config() -> Dict[str, Any]:
    """Create production health monitoring configuration."""
    return {
        'default_check_interval': 30,
        'default_timeout': 10,
        'default_retries': 3,
        'circuit_breaker_enabled': True,
        'sla_monitoring_enabled': True,
        'dependency_monitoring_enabled': True,
        'alert_on_degraded': True,
        'alert_on_unhealthy': True,
        'metrics_retention_hours': 168  # 7 days
    }


if __name__ == "__main__":
    # Example usage
    async def main():
        from api_gateway.service_registry import ServiceRegistry
        
        # Initialize components
        registry = ServiceRegistry()
        await registry.initialize()
        
        monitor = HealthMonitor(registry)
        await monitor.initialize()
        
        # Example health check configuration
        health_config = HealthCheckConfig(
            check_type=HealthCheckType.HTTPS,
            endpoint="https://api.example.mil/health",
            interval_seconds=30,
            timeout_seconds=10,
            expected_status_codes=[200],
            expected_response_pattern="\"status\"\\s*:\\s*\"ok\""
        )
        
        # Register health check
        await monitor.register_health_check("test-service", health_config)
        
        # Configure circuit breaker
        circuit_config = CircuitBreakerConfig(
            failure_threshold=5,
            timeout_seconds=60,
            half_open_max_calls=3
        )
        await monitor.configure_circuit_breaker("test-service", circuit_config)
        
        # Configure SLA
        sla_config = SLAConfig(
            uptime_percentage=99.9,
            max_response_time_ms=1000.0,
            error_rate_threshold=1.0
        )
        await monitor.configure_sla("test-service", sla_config)
        
        # Let monitoring run for a bit
        await asyncio.sleep(10)
        
        # Get status
        status = await monitor.get_health_status("test-service")
        print(f"Health status: {status}")
        
        metrics = await monitor.get_health_metrics("test-service")
        print(f"Health metrics: {metrics}")
        
        overall = await monitor.get_overall_health_status()
        print(f"Overall health: {overall}")
        
        await monitor.close()
        await registry.close()
    
    asyncio.run(main())