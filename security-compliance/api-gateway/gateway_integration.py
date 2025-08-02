"""
DoD API Gateway Integration Layer

This module provides a comprehensive integration layer that combines the DoD API Gateway,
service registry, health monitoring, and discovery client components into a unified
system. It provides high-level APIs for service management and intelligent request
routing while maintaining security compliance and audit requirements.

Key Features:
- Unified API Gateway interface with integrated service discovery
- Automatic service registration and health monitoring
- Intelligent request routing with security classification awareness
- Circuit breaker patterns and failover support
- Comprehensive audit logging and compliance reporting
- Security controls integration and policy enforcement
- Performance monitoring and SLA management

Security Standards:
- NIST 800-53 integrated security controls
- DoD 8500 series comprehensive compliance
- FIPS 140-2 end-to-end encryption
- STIGs compliance for integrated systems
"""

import asyncio
import logging
import time
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple, Union, Callable
from dataclasses import dataclass, asdict
from enum import Enum

# Import existing components
from api_gateway.dod_api_gateway import (
    DoDAPIGateway, APIGatewayManager, DoDAGWConfig, APIRequest, APIResponse,
    SecurityClassification, APIGatewayEnvironment, APIEndpointType
)
from api_gateway.api_security_controls import (
    APISecurityController, SecurityPolicy, RateLimitConfig, SecurityEvent,
    AttackType, SecurityThreatLevel
)
from api_gateway.service_registry import (
    ServiceRegistry, ServiceRegistration, ServiceMetadata, ServiceEndpoint,
    ServiceDiscoveryQuery, ServiceStatus, ServiceType, LoadBalancingStrategy
)
from api_gateway.health_monitor import (
    HealthMonitor, HealthCheckConfig, HealthCheckType, HealthCheckResult,
    CircuitBreakerConfig, SLAConfig
)
from api_gateway.discovery_client import (
    DiscoveryClient, DiscoveryConfig, DiscoveryStrategy
)

# Import audit and monitoring
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from audits.audit_logger import AuditLogger
from monitoring.security_alerting import SecurityAlertingSystem


class IntegrationMode(Enum):
    """API Gateway integration modes."""
    STANDALONE = "standalone"
    FEDERATED = "federated"
    MESH = "mesh"
    HYBRID = "hybrid"


class RoutingStrategy(Enum):
    """Request routing strategies."""
    CLASSIFICATION_AWARE = "classification_aware"
    PERFORMANCE_OPTIMIZED = "performance_optimized"
    SECURITY_FIRST = "security_first"
    HYBRID_ROUTING = "hybrid_routing"


@dataclass
class IntegrationConfig:
    """Integration layer configuration."""
    mode: IntegrationMode = IntegrationMode.HYBRID
    routing_strategy: RoutingStrategy = RoutingStrategy.HYBRID_ROUTING
    enable_auto_registration: bool = True
    enable_health_monitoring: bool = True
    enable_security_controls: bool = True
    enable_load_balancing: bool = True
    enable_circuit_breakers: bool = True
    enable_sla_monitoring: bool = True
    auto_discovery_interval: int = 60
    health_check_interval: int = 30
    metrics_collection_interval: int = 300


@dataclass
class ServiceConfiguration:
    """Complete service configuration."""
    metadata: ServiceMetadata
    health_config: Optional[HealthCheckConfig] = None
    security_policy: Optional[SecurityPolicy] = None
    circuit_breaker_config: Optional[CircuitBreakerConfig] = None
    sla_config: Optional[SLAConfig] = None
    custom_routing_rules: Dict[str, Any] = None


@dataclass
class GatewayMetrics:
    """Comprehensive gateway metrics."""
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    avg_response_time: float = 0.0
    active_services: int = 0
    healthy_services: int = 0
    circuit_breakers_open: int = 0
    security_violations: int = 0
    cache_hit_ratio: float = 0.0
    uptime_percentage: float = 100.0


class IntegratedAPIGateway:
    """
    Integrated DoD API Gateway
    
    Provides a unified interface that combines all API Gateway components
    with intelligent service discovery, health monitoring, and security controls.
    """
    
    def __init__(self, gateway_config: DoDAGWConfig, 
                 integration_config: Optional[IntegrationConfig] = None):
        """Initialize integrated API gateway."""
        self.logger = logging.getLogger(__name__)
        
        # Configuration
        self.gateway_config = gateway_config
        self.integration_config = integration_config or IntegrationConfig()
        
        # Core components
        self.api_gateway = None
        self.security_controller = None
        self.service_registry = None
        self.health_monitor = None
        self.discovery_client = None
        
        # Audit and monitoring
        self.audit_logger = None
        self.alerting_system = None
        
        # Service management
        self.registered_services: Dict[str, ServiceConfiguration] = {}
        self.routing_rules: Dict[str, Callable] = {}
        
        # Metrics and monitoring
        self.metrics = GatewayMetrics()
        self.request_history: List[Dict[str, Any]] = []
        
        # Background tasks
        self._monitoring_tasks: List[asyncio.Task] = []
        
        # Integration state
        self._initialized = False
        self._startup_time = None
    
    async def initialize(self) -> None:
        """Initialize all gateway components."""
        try:
            self._startup_time = datetime.utcnow()
            
            self.logger.info("Initializing Integrated API Gateway...")
            
            # Initialize audit logging
            self.audit_logger = AuditLogger()
            await self.audit_logger.initialize()
            
            # Initialize alerting system
            self.alerting_system = SecurityAlertingSystem()
            await self.alerting_system.initialize()
            
            # Initialize service registry
            self.service_registry = ServiceRegistry()
            await self.service_registry.initialize()
            
            # Initialize health monitor
            if self.integration_config.enable_health_monitoring:
                self.health_monitor = HealthMonitor(self.service_registry)
                await self.health_monitor.initialize()
            
            # Initialize security controller
            if self.integration_config.enable_security_controls:
                self.security_controller = APISecurityController()
                await self.security_controller.initialize()
            
            # Initialize discovery client
            discovery_config = DiscoveryConfig(
                strategy=DiscoveryStrategy.HYBRID,
                enable_health_filtering=True,
                enable_load_balancing=self.integration_config.enable_load_balancing
            )
            self.discovery_client = DiscoveryClient(
                self.service_registry, 
                self.health_monitor, 
                discovery_config
            )
            await self.discovery_client.initialize()
            
            # Initialize API gateway
            self.api_gateway = DoDAPIGateway(self.gateway_config)
            await self.api_gateway.initialize()
            
            # Start background monitoring tasks
            await self._start_background_tasks()
            
            # Log initialization
            await self.audit_logger.log_event(
                event_type="gateway_initialized",
                user_id="system",
                resource_id="integrated_gateway",
                details={
                    'mode': self.integration_config.mode.value,
                    'routing_strategy': self.integration_config.routing_strategy.value,
                    'components_enabled': {
                        'health_monitoring': self.integration_config.enable_health_monitoring,
                        'security_controls': self.integration_config.enable_security_controls,
                        'load_balancing': self.integration_config.enable_load_balancing,
                        'circuit_breakers': self.integration_config.enable_circuit_breakers
                    }
                }
            )
            
            self._initialized = True
            self.logger.info("Integrated API Gateway initialized successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize Integrated API Gateway: {e}")
            raise
    
    async def register_service(self, service_config: ServiceConfiguration) -> str:
        """Register a service with full configuration."""
        try:
            # Validate service configuration
            self._validate_service_config(service_config)
            
            # Register with service registry
            registration_id = await self.service_registry.register_service(
                service_config.metadata,
                service_config.health_config.endpoint if service_config.health_config else None,
                service_config.health_config.interval_seconds if service_config.health_config else 30,
                300  # TTL
            )
            
            # Configure health monitoring
            if self.health_monitor and service_config.health_config:
                await self.health_monitor.register_health_check(
                    service_config.metadata.service_id,
                    service_config.health_config
                )
                
                # Configure circuit breaker
                if service_config.circuit_breaker_config:
                    await self.health_monitor.configure_circuit_breaker(
                        service_config.metadata.service_id,
                        service_config.circuit_breaker_config
                    )
                
                # Configure SLA monitoring
                if service_config.sla_config:
                    await self.health_monitor.configure_sla(
                        service_config.metadata.service_id,
                        service_config.sla_config
                    )
            
            # Configure security policy
            if self.security_controller and service_config.security_policy:
                endpoint_pattern = f"/api/{service_config.metadata.service_name}/.*"
                self.security_controller.add_security_policy(
                    endpoint_pattern,
                    service_config.security_policy
                )
            
            # Store service configuration
            self.registered_services[service_config.metadata.service_id] = service_config
            
            # Log service registration
            await self.audit_logger.log_event(
                event_type="service_registered",
                user_id=service_config.metadata.owner,
                resource_id=service_config.metadata.service_id,
                details={
                    'service_name': service_config.metadata.service_name,
                    'version': service_config.metadata.version,
                    'registration_id': registration_id,
                    'endpoints_count': len(service_config.metadata.endpoints),
                    'health_monitoring': service_config.health_config is not None,
                    'security_policy': service_config.security_policy is not None
                }
            )
            
            self.logger.info(f"Service registered successfully: {service_config.metadata.service_name}")
            return registration_id
            
        except Exception as e:
            self.logger.error(f"Service registration failed: {e}")
            raise
    
    async def make_intelligent_request(self, service_name: str, path: str = "/",
                                     method: str = "GET", data: Optional[Any] = None,
                                     headers: Optional[Dict[str, str]] = None,
                                     params: Optional[Dict[str, str]] = None,
                                     classification: Optional[SecurityClassification] = None,
                                     timeout: Optional[int] = None) -> Optional[APIResponse]:
        """
        Make intelligent request with automatic service discovery and routing.
        
        Args:
            service_name: Target service name
            path: Request path
            method: HTTP method
            data: Request data
            headers: Request headers
            params: Query parameters
            classification: Security classification
            timeout: Request timeout
            
        Returns:
            API response or None if request failed
        """
        start_time = time.time()
        correlation_id = headers.get('X-Correlation-ID') if headers else None
        
        try:
            # Prepare request headers
            if not headers:
                headers = {}
            
            if not correlation_id:
                import uuid
                correlation_id = str(uuid.uuid4())
                headers['X-Correlation-ID'] = correlation_id
            
            # Add gateway headers
            headers.update({
                'X-Gateway-Version': '1.0.0',
                'X-Request-Timestamp': datetime.utcnow().isoformat(),
                'X-Service-Name': service_name
            })
            
            # Validate request security if security controller available
            if self.security_controller:
                request_data = {
                    'client_ip': '127.0.0.1',  # Should be passed from actual client
                    'endpoint': f"/api/{service_name}{path}",
                    'method': method,
                    'headers': headers,
                    'body': data,
                    'params': params
                }
                
                is_valid, errors = await self.security_controller.validate_request(request_data)
                if not is_valid:
                    self.logger.warning(f"Request validation failed: {errors}")
                    self.metrics.security_violations += 1
                    return APIResponse(
                        status_code=403,
                        headers={},
                        data={'error': 'Request validation failed', 'details': errors},
                        response_time=time.time() - start_time,
                        correlation_id=correlation_id,
                        error="Security validation failed"
                    )
            
            # Use discovery client for intelligent routing
            if self.discovery_client:
                response = await self.discovery_client.make_request(
                    service_name=service_name,
                    path=path,
                    method=method,
                    data=data,
                    headers=headers,
                    params=params,
                    classification=classification,
                    timeout=timeout
                )
                
                if response:
                    # Update metrics
                    self.metrics.successful_requests += 1
                    self._update_response_time_metric(time.time() - start_time)
                    
                    # Log successful request
                    await self._log_successful_request(service_name, path, method, 
                                                     response.status_code, correlation_id)
                    
                    return response
            
            # Fallback to direct API gateway if discovery fails
            self.logger.warning(f"Discovery client unavailable, using direct gateway for {service_name}")
            
            # Try to find service endpoints manually
            endpoints = await self.service_registry.discover_services(
                ServiceDiscoveryQuery(service_name=service_name, classification=classification)
            )
            
            if not endpoints:
                self.logger.error(f"No endpoints found for service: {service_name}")
                self.metrics.failed_requests += 1
                return None
            
            # Use first healthy endpoint
            for registration in endpoints:
                if registration.status == ServiceStatus.HEALTHY:
                    endpoint = registration.metadata.endpoints[0]
                    full_url = f"{endpoint.protocol}://{endpoint.url}:{endpoint.port}{path}"
                    
                    # Create API request
                    api_request = APIRequest(
                        method=method,
                        endpoint=full_url,
                        headers=headers,
                        data=data,
                        params=params,
                        classification=classification or SecurityClassification.UNCLASSIFIED,
                        correlation_id=correlation_id
                    )
                    
                    # Make request through DoD API Gateway
                    response = await self.api_gateway.make_request(api_request)
                    
                    if response and response.status_code < 400:
                        self.metrics.successful_requests += 1
                        self._update_response_time_metric(response.response_time)
                        
                        await self._log_successful_request(service_name, path, method,
                                                         response.status_code, correlation_id)
                        return response
            
            # All endpoints failed
            self.metrics.failed_requests += 1
            await self._log_failed_request(service_name, path, method, correlation_id, "All endpoints failed")
            return None
            
        except Exception as e:
            self.logger.error(f"Intelligent request failed: {e}")
            self.metrics.failed_requests += 1
            
            await self._log_failed_request(service_name, path, method, correlation_id, str(e))
            
            return APIResponse(
                status_code=500,
                headers={},
                data={'error': 'Internal gateway error'},
                response_time=time.time() - start_time,
                correlation_id=correlation_id or '',
                error=str(e)
            )
    
    async def get_service_health(self, service_name: str) -> Optional[Dict[str, Any]]:
        """Get comprehensive service health information."""
        try:
            health_info = {}
            
            # Get basic service info from discovery client
            if self.discovery_client:
                service_info = await self.discovery_client.get_service_info(service_name)
                if service_info:
                    health_info.update(service_info)
            
            # Get detailed health metrics from health monitor
            if self.health_monitor:
                # Find service ID
                service_id = None
                for sid, config in self.registered_services.items():
                    if config.metadata.service_name == service_name:
                        service_id = sid
                        break
                
                if service_id:
                    health_status = await self.health_monitor.get_health_status(service_id)
                    health_metrics = await self.health_monitor.get_health_metrics(service_id)
                    circuit_breaker_status = await self.health_monitor.get_circuit_breaker_status(service_id)
                    sla_violations = await self.health_monitor.get_sla_violations(service_id)
                    
                    health_info.update({
                        'health_status': health_status.value if health_status else 'unknown',
                        'health_metrics': asdict(health_metrics) if health_metrics else None,
                        'circuit_breaker_status': circuit_breaker_status,
                        'sla_violations': sla_violations,
                        'health_history': await self.health_monitor.get_health_history(service_id, 10)
                    })
            
            return health_info if health_info else None
            
        except Exception as e:
            self.logger.error(f"Failed to get service health for {service_name}: {e}")
            return None
    
    async def get_gateway_metrics(self) -> GatewayMetrics:
        """Get comprehensive gateway metrics."""
        try:
            # Update basic metrics
            self.metrics.total_requests = self.metrics.successful_requests + self.metrics.failed_requests
            
            # Get service counts
            if self.service_registry:
                registry_metrics = await self.service_registry.get_registry_metrics()
                self.metrics.active_services = registry_metrics.get('total_services', 0)
                status_dist = registry_metrics.get('services_by_status', {})
                self.metrics.healthy_services = status_dist.get('healthy', 0)
            
            # Get circuit breaker status
            if self.health_monitor:
                overall_health = await self.health_monitor.get_overall_health_status()
                # Count would need to be implemented in health monitor
            
            # Get discovery metrics
            if self.discovery_client:
                discovery_metrics = await self.discovery_client.get_metrics()
                if discovery_metrics.total_discoveries > 0:
                    self.metrics.cache_hit_ratio = discovery_metrics.cache_hits / discovery_metrics.total_discoveries
            
            # Calculate uptime
            if self._startup_time:
                uptime = (datetime.utcnow() - self._startup_time).total_seconds()
                # Simple uptime calculation - could be more sophisticated
                self.metrics.uptime_percentage = min(100.0, (uptime / 86400) * 100)  # 24h reference
            
            return self.metrics
            
        except Exception as e:
            self.logger.error(f"Failed to get gateway metrics: {e}")
            return self.metrics
    
    async def get_system_status(self) -> Dict[str, Any]:
        """Get comprehensive system status."""
        try:
            status = {
                'timestamp': datetime.utcnow().isoformat(),
                'gateway_initialized': self._initialized,
                'uptime_seconds': (datetime.utcnow() - self._startup_time).total_seconds() if self._startup_time else 0,
                'components': {},
                'metrics': asdict(await self.get_gateway_metrics()),
                'alerts': []
            }
            
            # Component status
            status['components'] = {
                'api_gateway': self.api_gateway is not None,
                'service_registry': self.service_registry is not None,
                'health_monitor': self.health_monitor is not None,
                'discovery_client': self.discovery_client is not None,
                'security_controller': self.security_controller is not None,
                'audit_logger': self.audit_logger is not None,
                'alerting_system': self.alerting_system is not None
            }
            
            # Service status
            if self.health_monitor:
                overall_health = await self.health_monitor.get_overall_health_status()
                status['service_health'] = overall_health
            
            # Recent alerts (placeholder - would integrate with alerting system)
            status['recent_alerts'] = []
            
            return status
            
        except Exception as e:
            self.logger.error(f"Failed to get system status: {e}")
            return {'error': str(e), 'timestamp': datetime.utcnow().isoformat()}
    
    def _validate_service_config(self, config: ServiceConfiguration) -> None:
        """Validate service configuration."""
        if not config.metadata.service_id or not config.metadata.service_name:
            raise ValueError("Service ID and name are required")
        
        if not config.metadata.endpoints:
            raise ValueError("At least one endpoint is required")
        
        # Validate health check configuration
        if config.health_config:
            if not config.health_config.endpoint:
                raise ValueError("Health check endpoint is required")
        
        # Validate security policy
        if config.security_policy:
            if not config.security_policy.rate_limit_config:
                raise ValueError("Rate limit configuration is required in security policy")
    
    def _update_response_time_metric(self, response_time: float) -> None:
        """Update average response time metric."""
        total_requests = self.metrics.successful_requests + self.metrics.failed_requests
        if total_requests > 1:
            self.metrics.avg_response_time = (
                (self.metrics.avg_response_time * (total_requests - 1) + response_time) / total_requests
            )
        else:
            self.metrics.avg_response_time = response_time
    
    async def _log_successful_request(self, service_name: str, path: str, method: str,
                                    status_code: int, correlation_id: str) -> None:
        """Log successful request."""
        try:
            await self.audit_logger.log_event(
                event_type="gateway_request_success",
                user_id="gateway",
                resource_id=service_name,
                details={
                    'path': path,
                    'method': method,
                    'status_code': status_code,
                    'correlation_id': correlation_id
                }
            )
        except Exception as e:
            self.logger.error(f"Failed to log successful request: {e}")
    
    async def _log_failed_request(self, service_name: str, path: str, method: str,
                                correlation_id: str, error: str) -> None:
        """Log failed request."""
        try:
            await self.audit_logger.log_event(
                event_type="gateway_request_failure",
                user_id="gateway",
                resource_id=service_name,
                details={
                    'path': path,
                    'method': method,
                    'correlation_id': correlation_id,
                    'error': error
                }
            )
        except Exception as e:
            self.logger.error(f"Failed to log failed request: {e}")
    
    async def _start_background_tasks(self) -> None:
        """Start background monitoring tasks."""
        try:
            # Metrics collection task
            self._monitoring_tasks.append(
                asyncio.create_task(self._collect_metrics_periodically())
            )
            
            # System health monitoring task
            self._monitoring_tasks.append(
                asyncio.create_task(self._monitor_system_health())
            )
            
            self.logger.info("Background monitoring tasks started")
            
        except Exception as e:
            self.logger.error(f"Failed to start background tasks: {e}")
    
    async def _collect_metrics_periodically(self) -> None:
        """Background task to collect metrics."""
        while True:
            try:
                await asyncio.sleep(self.integration_config.metrics_collection_interval)
                
                # Collect and store metrics
                metrics = await self.get_gateway_metrics()
                
                # Log metrics
                await self.audit_logger.log_event(
                    event_type="metrics_collected",
                    user_id="system",
                    resource_id="gateway",
                    details=asdict(metrics)
                )
                
            except Exception as e:
                self.logger.error(f"Error in metrics collection task: {e}")
    
    async def _monitor_system_health(self) -> None:
        """Background task to monitor overall system health."""
        while True:
            try:
                await asyncio.sleep(60)  # Check every minute
                
                # Check component health
                components_healthy = all([
                    self.api_gateway is not None,
                    self.service_registry is not None,
                    self.discovery_client is not None
                ])
                
                if not components_healthy:
                    await self.alerting_system.send_alert(
                        alert_type="gateway_component_failure",
                        severity="critical",
                        message="One or more gateway components are not healthy",
                        metadata={'components_status': {
                            'api_gateway': self.api_gateway is not None,
                            'service_registry': self.service_registry is not None,
                            'health_monitor': self.health_monitor is not None,
                            'discovery_client': self.discovery_client is not None,
                            'security_controller': self.security_controller is not None
                        }}
                    )
                
            except Exception as e:
                self.logger.error(f"Error in system health monitoring: {e}")
    
    async def close(self) -> None:
        """Clean up all resources."""
        try:
            self.logger.info("Shutting down Integrated API Gateway...")
            
            # Cancel background tasks
            for task in self._monitoring_tasks:
                task.cancel()
            
            # Close components
            if self.discovery_client:
                await self.discovery_client.close()
            
            if self.health_monitor:
                await self.health_monitor.close()
            
            if self.security_controller:
                await self.security_controller.close()
            
            if self.service_registry:
                await self.service_registry.close()
            
            if self.api_gateway:
                await self.api_gateway.close()
            
            if self.audit_logger:
                await self.audit_logger.close()
            
            if self.alerting_system:
                await self.alerting_system.close()
            
            # Log shutdown
            self.logger.info("Integrated API Gateway shutdown complete")
            
        except Exception as e:
            self.logger.error(f"Error during gateway shutdown: {e}")


# Convenience functions for creating common configurations

def create_production_service_config(service_name: str, service_id: str, 
                                   endpoints: List[ServiceEndpoint],
                                   owner: str, contact_email: str) -> ServiceConfiguration:
    """Create production-ready service configuration."""
    
    # Service metadata
    metadata = ServiceMetadata(
        service_id=service_id,
        service_name=service_name,
        service_type=ServiceType.API,
        version="1.0.0",
        description=f"Production {service_name} service",
        endpoints=endpoints,
        security_classification=SecurityClassification.UNCLASSIFIED,
        environment=APIGatewayEnvironment.PRODUCTION,
        owner=owner,
        contact_email=contact_email
    )
    
    # Health check configuration
    health_config = HealthCheckConfig(
        check_type=HealthCheckType.HTTPS,
        endpoint=f"https://{endpoints[0].url}/health",
        interval_seconds=30,
        timeout_seconds=10,
        expected_status_codes=[200]
    )
    
    # Security policy
    security_policy = SecurityPolicy(
        name=f"{service_name}_production_policy",
        description=f"Production security policy for {service_name}",
        rate_limit_config=RateLimitConfig(
            algorithm="token_bucket",
            requests_per_window=1000,
            window_size_seconds=3600
        ),
        enable_oauth_validation=True,
        enable_input_validation=True,
        enable_attack_detection=True,
        max_request_size=1048576  # 1MB
    )
    
    # Circuit breaker configuration
    circuit_breaker_config = CircuitBreakerConfig(
        failure_threshold=5,
        timeout_seconds=60,
        half_open_max_calls=3
    )
    
    # SLA configuration
    sla_config = SLAConfig(
        uptime_percentage=99.9,
        response_time_percentile=95,
        max_response_time_ms=1000.0,
        error_rate_threshold=1.0
    )
    
    return ServiceConfiguration(
        metadata=metadata,
        health_config=health_config,
        security_policy=security_policy,
        circuit_breaker_config=circuit_breaker_config,
        sla_config=sla_config
    )


if __name__ == "__main__":
    # Example usage
    async def main():
        # Create gateway configuration
        from api_gateway.dod_api_gateway import create_development_config
        
        gateway_config = create_development_config()
        integration_config = IntegrationConfig(
            mode=IntegrationMode.HYBRID,
            enable_health_monitoring=True,
            enable_security_controls=True
        )
        
        # Initialize integrated gateway
        gateway = IntegratedAPIGateway(gateway_config, integration_config)
        await gateway.initialize()
        
        # Register a service
        service_endpoints = [
            ServiceEndpoint(
                url="api.example.mil",
                protocol="https",
                port=443
            )
        ]
        
        service_config = create_production_service_config(
            service_name="test-service",
            service_id="test-service-001",
            endpoints=service_endpoints,
            owner="test-team",
            contact_email="test@example.mil"
        )
        
        registration_id = await gateway.register_service(service_config)
        print(f"Service registered: {registration_id}")
        
        # Make intelligent request
        response = await gateway.make_intelligent_request(
            service_name="test-service",
            path="/api/v1/data",
            method="GET"
        )
        
        if response:
            print(f"Request successful: {response.status_code}")
        else:
            print("Request failed")
        
        # Get metrics
        metrics = await gateway.get_gateway_metrics()
        print(f"Gateway metrics: {asdict(metrics)}")
        
        # Get system status
        status = await gateway.get_system_status()
        print(f"System status: {json.dumps(status, indent=2)}")
        
        await gateway.close()
    
    asyncio.run(main())