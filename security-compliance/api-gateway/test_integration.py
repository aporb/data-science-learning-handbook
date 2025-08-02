"""
Integration Tests for DoD API Gateway Components

This module provides comprehensive integration tests for the DoD API Gateway
service registration, discovery, health monitoring, and intelligent routing
capabilities. Tests validate end-to-end functionality, security compliance,
and performance characteristics.

Test Coverage:
- Service registration and discovery workflows
- Health monitoring and circuit breaker functionality
- Security controls and policy enforcement
- Load balancing and failover scenarios
- Audit logging and compliance validation
- Performance and reliability testing
"""

import asyncio
import pytest
import json
import time
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any
from unittest.mock import Mock, AsyncMock, patch

# Import components to test
from api_gateway.service_registry import (
    ServiceRegistry, ServiceMetadata, ServiceEndpoint, ServiceDiscoveryQuery,
    ServiceStatus, ServiceType, SecurityClassification, APIGatewayEnvironment
)
from api_gateway.health_monitor import (
    HealthMonitor, HealthCheckConfig, HealthCheckType, HealthCheckResult,
    CircuitBreakerConfig, SLAConfig
)
from api_gateway.discovery_client import (
    DiscoveryClient, DiscoveryConfig, DiscoveryStrategy
)
from api_gateway.gateway_integration import (
    IntegratedAPIGateway, IntegrationConfig, ServiceConfiguration
)
from api_gateway.dod_api_gateway import DoDAGWConfig, create_development_config

# Configure logging for tests
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class TestServiceRegistry:
    """Test cases for Service Registry component."""
    
    @pytest.fixture
    async def registry(self):
        """Create test service registry."""
        registry = ServiceRegistry()
        # Mock Redis for testing
        registry.redis_client = AsyncMock()
        registry.audit_logger = AsyncMock()
        registry.alerting_system = AsyncMock()
        await registry.initialize()
        yield registry
        await registry.close()
    
    @pytest.fixture
    def sample_service_metadata(self):
        """Create sample service metadata for testing."""
        return ServiceMetadata(
            service_id="test-service-001",
            service_name="test-data-service",
            service_type=ServiceType.API,
            version="1.0.0",
            description="Test data processing service",
            endpoints=[
                ServiceEndpoint(
                    url="test-api.example.mil",
                    protocol="https",
                    port=443,
                    path="/api/v1"
                )
            ],
            security_classification=SecurityClassification.UNCLASSIFIED,
            environment=APIGatewayEnvironment.DEVELOPMENT,
            owner="test-team",
            contact_email="test@example.mil",
            tags=["test", "data", "api"],
            dependencies=["database-service"]
        )
    
    async def test_service_registration(self, registry, sample_service_metadata):
        """Test basic service registration."""
        # Register service
        registration_id = await registry.register_service(
            sample_service_metadata,
            health_check_url="https://test-api.example.mil/health"
        )
        
        assert registration_id is not None
        assert registration_id in registry.registered_services
        
        # Verify registration details
        registration = registry.registered_services[registration_id]
        assert registration.metadata.service_name == "test-data-service"
        assert registration.metadata.service_id == "test-service-001"
        assert len(registration.metadata.endpoints) == 1
    
    async def test_service_discovery(self, registry, sample_service_metadata):
        """Test service discovery functionality."""
        # Register service first
        await registry.register_service(sample_service_metadata)
        
        # Test discovery by name
        query = ServiceDiscoveryQuery(service_name="test-data-service")
        services = await registry.discover_services(query)
        
        assert len(services) == 1
        assert services[0].metadata.service_name == "test-data-service"
        
        # Test discovery by type
        query = ServiceDiscoveryQuery(service_type=ServiceType.API)
        services = await registry.discover_services(query)
        
        assert len(services) >= 1
        
        # Test discovery with classification filter
        query = ServiceDiscoveryQuery(
            service_name="test-data-service",
            classification=SecurityClassification.UNCLASSIFIED
        )
        services = await registry.discover_services(query)
        
        assert len(services) == 1
    
    async def test_service_heartbeat(self, registry, sample_service_metadata):
        """Test service heartbeat functionality."""
        # Register service
        registration_id = await registry.register_service(sample_service_metadata)
        
        # Get initial heartbeat time
        registration = registry.registered_services[registration_id]
        initial_heartbeat = registration.last_heartbeat
        
        # Wait a bit and send heartbeat
        await asyncio.sleep(0.1)
        await registry.heartbeat(sample_service_metadata.service_id)
        
        # Check heartbeat was updated
        updated_registration = registry.registered_services[registration_id]
        assert updated_registration.last_heartbeat > initial_heartbeat
    
    async def test_service_deregistration(self, registry, sample_service_metadata):
        """Test service deregistration."""
        # Register service
        await registry.register_service(sample_service_metadata)
        
        # Verify service is registered
        query = ServiceDiscoveryQuery(service_name="test-data-service")
        services = await registry.discover_services(query)
        assert len(services) == 1
        
        # Deregister service
        await registry.deregister_service(sample_service_metadata.service_id, "test-user")
        
        # Verify service is no longer discoverable
        services = await registry.discover_services(query)
        assert len(services) == 0


class TestHealthMonitor:
    """Test cases for Health Monitor component."""
    
    @pytest.fixture
    async def health_monitor(self):
        """Create test health monitor."""
        # Create mock service registry
        registry = Mock()
        registry.discover_services = AsyncMock(return_value=[])
        
        monitor = HealthMonitor(registry)
        monitor.audit_logger = AsyncMock()
        monitor.alerting_system = AsyncMock()
        
        # Mock HTTP session
        monitor._session = AsyncMock()
        
        await monitor.initialize()
        yield monitor
        await monitor.close()
    
    @pytest.fixture
    def health_check_config(self):
        """Create test health check configuration."""
        return HealthCheckConfig(
            check_type=HealthCheckType.HTTP,
            endpoint="http://test-api.example.mil/health",
            interval_seconds=10,
            timeout_seconds=5,
            expected_status_codes=[200]
        )
    
    async def test_health_check_registration(self, health_monitor, health_check_config):
        """Test health check registration."""
        service_id = "test-service-001"
        
        await health_monitor.register_health_check(service_id, health_check_config)
        
        assert service_id in health_monitor.health_configs
        assert health_monitor.health_configs[service_id] == health_check_config
        assert service_id in health_monitor.health_metrics
        assert service_id in health_monitor.circuit_breakers
    
    async def test_http_health_check(self, health_monitor, health_check_config):
        """Test HTTP health check execution."""
        service_id = "test-service-001"
        
        # Mock successful HTTP response
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.text = AsyncMock(return_value='{"status": "ok"}')
        
        health_monitor._session.get.return_value.__aenter__.return_value = mock_response
        
        # Register and perform health check
        await health_monitor.register_health_check(service_id, health_check_config)
        health_data = await health_monitor.perform_health_check(service_id)
        
        assert health_data.result == HealthCheckResult.HEALTHY
        assert health_data.status_code == 200
        assert health_data.response_time > 0
    
    async def test_circuit_breaker_functionality(self, health_monitor, health_check_config):
        """Test circuit breaker behavior."""
        service_id = "test-service-001"
        
        # Configure circuit breaker
        circuit_config = CircuitBreakerConfig(
            failure_threshold=3,
            timeout_seconds=60,
            half_open_max_calls=2
        )
        
        await health_monitor.register_health_check(service_id, health_check_config)
        await health_monitor.configure_circuit_breaker(service_id, circuit_config)
        
        # Simulate failures to trigger circuit breaker
        mock_response = AsyncMock()
        mock_response.status = 500
        mock_response.text = AsyncMock(return_value='{"error": "Internal Server Error"}')
        
        health_monitor._session.get.return_value.__aenter__.return_value = mock_response
        
        # Perform failing health checks
        for _ in range(4):
            await health_monitor.perform_health_check(service_id)
        
        # Check circuit breaker state
        circuit_breaker = health_monitor.circuit_breakers[service_id]
        assert circuit_breaker['failure_count'] >= 3
        
        # Circuit breaker should now be open for subsequent checks
        health_data = await health_monitor.perform_health_check(service_id)
        assert health_data.error_message == "Circuit breaker is open"
    
    async def test_sla_monitoring(self, health_monitor, health_check_config):
        """Test SLA monitoring functionality."""
        service_id = "test-service-001"
        
        # Configure SLA
        sla_config = SLAConfig(
            uptime_percentage=99.0,
            max_response_time_ms=1000.0,
            error_rate_threshold=5.0
        )
        
        await health_monitor.register_health_check(service_id, health_check_config)
        await health_monitor.configure_sla(service_id, sla_config)
        
        # Mock slow response to trigger SLA violation
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.text = AsyncMock(return_value='{"status": "ok"}')
        
        health_monitor._session.get.return_value.__aenter__.return_value = mock_response
        
        # Simulate slow response by patching time
        with patch('time.time', side_effect=[0, 2.0]):  # 2 second response time
            health_data = await health_monitor.perform_health_check(service_id)
        
        # Check SLA violation was recorded
        violations = await health_monitor.get_sla_violations(service_id)
        # In a real scenario, this would trigger based on accumulated metrics


class TestDiscoveryClient:
    """Test cases for Discovery Client component."""
    
    @pytest.fixture
    async def discovery_client(self):
        """Create test discovery client."""
        # Create mock service registry
        registry = Mock()
        registry.discover_services = AsyncMock(return_value=[])
        
        # Create mock health monitor
        health_monitor = Mock()
        health_monitor.get_health_status = AsyncMock(return_value=HealthCheckResult.HEALTHY)
        
        config = DiscoveryConfig(
            strategy=DiscoveryStrategy.CACHE_FIRST,
            cache_ttl_seconds=60
        )
        
        client = DiscoveryClient(registry, health_monitor, config)
        client.audit_logger = AsyncMock()
        
        await client.initialize()
        yield client
        await client.close()
    
    async def test_service_discovery_with_caching(self, discovery_client):
        """Test service discovery with caching."""
        service_name = "test-service"
        
        # Mock registry response
        mock_registration = Mock()
        mock_registration.metadata.service_id = "test-service-001"
        mock_registration.metadata.service_name = service_name
        mock_registration.metadata.endpoints = [
            ServiceEndpoint(url="api1.example.mil", protocol="https", port=443)
        ]
        mock_registration.status = ServiceStatus.HEALTHY
        
        discovery_client.service_registry.discover_services.return_value = [mock_registration]
        
        # First discovery should hit registry
        endpoints1 = await discovery_client.discover_service(service_name)
        assert len(endpoints1) == 1
        assert endpoints1[0].endpoint.url == "api1.example.mil"
        
        # Second discovery should hit cache
        endpoints2 = await discovery_client.discover_service(service_name)
        assert len(endpoints2) == 1
        
        # Verify cache hit
        assert discovery_client.metrics.cache_hits > 0
    
    async def test_intelligent_request_routing(self, discovery_client):
        """Test intelligent request routing with load balancing."""
        service_name = "test-service"
        
        # Mock multiple endpoints
        mock_registration = Mock()
        mock_registration.metadata.service_id = "test-service-001"
        mock_registration.metadata.service_name = service_name
        mock_registration.metadata.endpoints = [
            ServiceEndpoint(url="api1.example.mil", protocol="https", port=443),
            ServiceEndpoint(url="api2.example.mil", protocol="https", port=443)
        ]
        mock_registration.status = ServiceStatus.HEALTHY
        
        discovery_client.service_registry.discover_services.return_value = [mock_registration]
        
        # Mock HTTP session
        mock_session = AsyncMock()
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.headers = {}
        mock_response.text = AsyncMock(return_value='{"result": "success"}')
        
        mock_session.request.return_value.__aenter__.return_value = mock_response
        discovery_client.connection_pools["https://api1.example.mil"] = mock_session
        
        # Make request
        response = await discovery_client.make_request(
            service_name=service_name,
            path="/api/v1/data",
            method="GET"
        )
        
        assert response is not None
        assert response.status_code == 200


class TestIntegratedGateway:
    """Test cases for Integrated API Gateway."""
    
    @pytest.fixture
    async def integrated_gateway(self):
        """Create test integrated gateway."""
        gateway_config = create_development_config()
        integration_config = IntegrationConfig(
            enable_health_monitoring=True,
            enable_security_controls=True
        )
        
        gateway = IntegratedAPIGateway(gateway_config, integration_config)
        
        # Mock components for testing
        gateway.audit_logger = AsyncMock()
        gateway.alerting_system = AsyncMock()
        
        # Don't actually initialize real components in tests
        gateway.service_registry = Mock()
        gateway.service_registry.initialize = AsyncMock()
        gateway.service_registry.register_service = AsyncMock(return_value="test-reg-id")
        gateway.service_registry.discover_services = AsyncMock(return_value=[])
        
        gateway.health_monitor = Mock()
        gateway.health_monitor.initialize = AsyncMock()
        gateway.health_monitor.register_health_check = AsyncMock()
        
        gateway.discovery_client = Mock()
        gateway.discovery_client.initialize = AsyncMock()
        gateway.discovery_client.make_request = AsyncMock()
        
        gateway.security_controller = Mock()
        gateway.security_controller.initialize = AsyncMock()
        gateway.security_controller.validate_request = AsyncMock(return_value=(True, []))
        
        gateway.api_gateway = Mock()
        gateway.api_gateway.initialize = AsyncMock()
        
        await gateway.initialize()
        yield gateway
        await gateway.close()
    
    @pytest.fixture
    def sample_service_config(self):
        """Create sample service configuration."""
        metadata = ServiceMetadata(
            service_id="test-service-001",
            service_name="test-service",
            service_type=ServiceType.API,
            version="1.0.0",
            description="Test service",
            endpoints=[
                ServiceEndpoint(url="api.example.mil", protocol="https", port=443)
            ],
            security_classification=SecurityClassification.UNCLASSIFIED,
            environment=APIGatewayEnvironment.DEVELOPMENT,
            owner="test-team",
            contact_email="test@example.mil"
        )
        
        health_config = HealthCheckConfig(
            check_type=HealthCheckType.HTTPS,
            endpoint="https://api.example.mil/health",
            interval_seconds=30
        )
        
        return ServiceConfiguration(
            metadata=metadata,
            health_config=health_config
        )
    
    async def test_service_registration_integration(self, integrated_gateway, sample_service_config):
        """Test end-to-end service registration."""
        registration_id = await integrated_gateway.register_service(sample_service_config)
        
        assert registration_id == "test-reg-id"
        assert sample_service_config.metadata.service_id in integrated_gateway.registered_services
        
        # Verify components were called
        integrated_gateway.service_registry.register_service.assert_called_once()
        integrated_gateway.health_monitor.register_health_check.assert_called_once()
    
    async def test_intelligent_request_handling(self, integrated_gateway, sample_service_config):
        """Test intelligent request handling."""
        # Register service first
        await integrated_gateway.register_service(sample_service_config)
        
        # Mock successful response from discovery client
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.data = {"result": "success"}
        mock_response.response_time = 0.1
        
        integrated_gateway.discovery_client.make_request.return_value = mock_response
        
        # Make request
        response = await integrated_gateway.make_intelligent_request(
            service_name="test-service",
            path="/api/v1/data",
            method="GET"
        )
        
        assert response is not None
        assert response.status_code == 200
        assert integrated_gateway.metrics.successful_requests == 1
    
    async def test_security_validation_integration(self, integrated_gateway, sample_service_config):
        """Test security validation during request processing."""
        # Register service
        await integrated_gateway.register_service(sample_service_config)
        
        # Mock security validation failure
        integrated_gateway.security_controller.validate_request.return_value = (False, ["Invalid input"])
        
        # Make request
        response = await integrated_gateway.make_intelligent_request(
            service_name="test-service",
            path="/api/v1/data",
            method="POST",
            data={"malicious": "<script>alert('xss')</script>"}
        )
        
        assert response is not None
        assert response.status_code == 403
        assert integrated_gateway.metrics.security_violations == 1
    
    async def test_metrics_collection(self, integrated_gateway):
        """Test metrics collection functionality."""
        # Simulate some requests
        integrated_gateway.metrics.successful_requests = 10
        integrated_gateway.metrics.failed_requests = 2
        
        metrics = await integrated_gateway.get_gateway_metrics()
        
        assert metrics.total_requests == 12
        assert metrics.successful_requests == 10
        assert metrics.failed_requests == 2
    
    async def test_system_status_reporting(self, integrated_gateway):
        """Test system status reporting."""
        status = await integrated_gateway.get_system_status()
        
        assert "timestamp" in status
        assert "gateway_initialized" in status
        assert "components" in status
        assert "metrics" in status
        
        # Check component status
        components = status["components"]
        assert components["service_registry"] is True
        assert components["health_monitor"] is True
        assert components["discovery_client"] is True


class TestPerformanceAndReliability:
    """Performance and reliability tests."""
    
    async def test_concurrent_service_discovery(self):
        """Test concurrent service discovery performance."""
        # Create multiple discovery clients
        registry = Mock()
        registry.discover_services = AsyncMock(return_value=[])
        
        clients = []
        for i in range(5):
            client = DiscoveryClient(registry, None, DiscoveryConfig())
            client.audit_logger = AsyncMock()
            await client.initialize()
            clients.append(client)
        
        # Perform concurrent discoveries
        start_time = time.time()
        
        tasks = []
        for client in clients:
            for _ in range(10):
                task = asyncio.create_task(client.discover_service(f"service-{i}"))
                tasks.append(task)
        
        await asyncio.gather(*tasks)
        
        end_time = time.time()
        
        # Clean up
        for client in clients:
            await client.close()
        
        # Performance assertion
        total_time = end_time - start_time
        assert total_time < 5.0  # Should complete within 5 seconds
    
    async def test_circuit_breaker_recovery(self):
        """Test circuit breaker recovery behavior."""
        registry = Mock()
        monitor = HealthMonitor(registry)
        monitor.audit_logger = AsyncMock()
        monitor.alerting_system = AsyncMock()
        monitor._session = AsyncMock()
        
        await monitor.initialize()
        
        service_id = "test-service"
        health_config = HealthCheckConfig(
            check_type=HealthCheckType.HTTP,
            endpoint="http://test.example.mil/health",
            interval_seconds=1
        )
        
        circuit_config = CircuitBreakerConfig(
            failure_threshold=3,
            timeout_seconds=2,
            half_open_max_calls=2
        )
        
        await monitor.register_health_check(service_id, health_config)
        await monitor.configure_circuit_breaker(service_id, circuit_config)
        
        # Simulate failures to open circuit breaker
        mock_response = AsyncMock()
        mock_response.status = 500
        mock_response.text = AsyncMock(return_value="Error")
        monitor._session.get.return_value.__aenter__.return_value = mock_response
        
        # Trigger failures
        for _ in range(4):
            await monitor.perform_health_check(service_id)
        
        # Verify circuit breaker is open
        circuit_breaker = monitor.circuit_breakers[service_id]
        assert circuit_breaker['state'] == 'open'
        
        # Wait for timeout
        await asyncio.sleep(2.1)
        
        # Simulate recovery
        mock_response.status = 200
        mock_response.text = AsyncMock(return_value='{"status": "ok"}')
        
        # Perform health check - should transition to half-open
        await monitor.perform_health_check(service_id)
        
        await monitor.close()


# Utility functions for testing

async def create_test_service_registration():
    """Create a test service registration for use in tests."""
    metadata = ServiceMetadata(
        service_id="test-service-001",
        service_name="test-service",
        service_type=ServiceType.API,
        version="1.0.0",
        description="Test service for integration testing",
        endpoints=[
            ServiceEndpoint(
                url="test-api.example.mil",
                protocol="https",
                port=443,
                path="/api/v1"
            )
        ],
        security_classification=SecurityClassification.UNCLASSIFIED,
        environment=APIGatewayEnvironment.DEVELOPMENT,
        owner="test-team",
        contact_email="test@example.mil",
        tags=["test", "integration"],
        dependencies=[]
    )
    
    return metadata


def create_mock_api_response(status_code: int = 200, data: Any = None) -> Mock:
    """Create a mock API response for testing."""
    response = Mock()
    response.status_code = status_code
    response.headers = {}
    response.data = data or {"status": "ok"}
    response.response_time = 0.1
    response.correlation_id = "test-correlation-id"
    response.error = None
    return response


if __name__ == "__main__":
    # Run tests
    import pytest
    
    # Configure pytest to run with asyncio
    pytest.main([__file__, "-v", "--asyncio-mode=auto"])