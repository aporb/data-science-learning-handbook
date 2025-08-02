"""
Comprehensive Test Suite for DoD API Gateway Implementation

This test suite provides comprehensive testing for all API Gateway components
including security controls, monitoring, external API client, and service mesh
configuration.

Test Coverage:
- DoD API Gateway authentication and authorization
- Rate limiting and security controls
- External API client functionality
- Service mesh configuration
- Monitoring and observability
- Circuit breaker patterns
- Error handling and edge cases

Security Testing:
- OAuth 2.0 token validation
- Attack pattern detection
- Certificate-based authentication
- Input validation and sanitization
- Audit logging verification
"""

import asyncio
import json
import time
import uuid
import pytest
from datetime import datetime, timedelta
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from typing import Dict, List, Any
import ssl

import aiohttp
import aioredis
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

# Import modules to test
import sys
import os
sys.path.append(os.path.dirname(__file__))

# Additional test imports for comprehensive integration testing
import threading
import concurrent.futures
from contextlib import asynccontextmanager
from unittest.mock import call

from dod_api_gateway import (
    DoDAPIGateway, APIGatewayManager, DoDAGWConfig, APIRequest, APIResponse,
    APIGatewayEnvironment, SecurityClassification, APIEndpointType
)
from api_security_controls import (
    APISecurityController, SecurityPolicy, RateLimitConfig, SecurityEvent,
    RateLimitAlgorithm, SecurityThreatLevel, AttackType
)
from external_api_client import (
    ExternalAPIClient, ExternalAPIConfig, AuthenticationType,
    ExternalAPIEnvironment, RetryStrategy, CircuitBreaker
)
from service_mesh_config import (
    ServiceMeshManager, ServiceMeshConfig, ServiceConfig, TrafficManagementConfig,
    MeshEnvironment, SecurityMode
)
from gateway_monitoring import (
    APIGatewayMonitor, MonitoringMetrics, HealthStatus, AlertSeverity
)


class TestDoDAPIGateway:
    """Test cases for DoD API Gateway."""
    
    @pytest.fixture
    async def gateway_config(self):
        """Create test gateway configuration."""
        from auth.oauth_client import OAuthConfig, Platform
        
        oauth_config = OAuthConfig(
            platform=Platform.ADVANA,
            client_id="test-client-id",
            client_secret="test-client-secret",
            authorization_url="https://test-auth.mil/oauth/authorize",
            token_url="https://test-auth.mil/oauth/token",
            redirect_uri="https://localhost:8080/callback",
            scopes=["read", "write"]
        )
        
        return DoDAGWConfig(
            environment=APIGatewayEnvironment.DEVELOPMENT,
            gateway_url="https://test-gateway.mil",
            client_certificate_path="/tmp/test-client.crt",
            private_key_path="/tmp/test-client.key",
            ca_bundle_path="/tmp/test-ca.crt",
            oauth_config=oauth_config,
            service_name="test-service",
            service_version="1.0.0",
            security_classification=SecurityClassification.UNCLASSIFIED
        )
    
    @pytest.fixture
    async def mock_ssl_context(self):
        """Create mock SSL context."""
        context = Mock(spec=ssl.SSLContext)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.maximum_version = ssl.TLSVersion.TLSv1_3
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        return context
    
    @pytest.fixture
    async def api_gateway(self, gateway_config, mock_ssl_context):
        """Create API Gateway instance for testing."""
        with patch('dod_api_gateway.ssl.create_default_context', return_value=mock_ssl_context):
            gateway = DoDAPIGateway(gateway_config)
            gateway._ssl_context = mock_ssl_context
            yield gateway
    
    @pytest.mark.asyncio
    async def test_gateway_initialization(self, api_gateway, mock_ssl_context):
        """Test API Gateway initialization."""
        with patch('aiohttp.ClientSession') as mock_session:
            mock_session_instance = AsyncMock()
            mock_session.return_value = mock_session_instance
            
            # Mock OAuth client
            with patch('dod_api_gateway.OAuthClient') as mock_oauth:
                mock_oauth_instance = AsyncMock()
                mock_oauth.return_value = mock_oauth_instance
                mock_oauth_instance.get_client_credentials_token.return_value = {
                    'access_token': 'test-token'
                }
                
                # Mock health check
                mock_response = AsyncMock()
                mock_response.status = 200
                mock_session_instance.get.return_value.__aenter__.return_value = mock_response
                
                await api_gateway.initialize()
                
                assert api_gateway._session is not None
                assert api_gateway.oauth_client is not None
    
    @pytest.mark.asyncio
    async def test_make_request_success(self, api_gateway):
        """Test successful API request."""
        # Setup mock session
        mock_session = AsyncMock()
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.headers = {'Content-Type': 'application/json'}
        mock_response.json.return_value = {'result': 'success'}
        
        mock_session.request.return_value.__aenter__.return_value = mock_response
        api_gateway._session = mock_session
        
        # Create test request
        request = APIRequest(
            method='GET',
            endpoint='/api/v1/test',
            headers={'X-Test': 'value'},
            classification=SecurityClassification.UNCLASSIFIED
        )
        
        # Make request
        response = await api_gateway.make_request(request)
        
        assert response.status_code == 200
        assert response.data == {'result': 'success'}
        assert response.error is None
    
    @pytest.mark.asyncio
    async def test_make_request_with_encryption(self, api_gateway):
        """Test API request with encrypted data."""
        # Mock encryption manager
        mock_encryption = AsyncMock()
        mock_encryption.encrypt_data.return_value = b'encrypted_data'
        mock_encryption.decrypt_data.return_value = b'{"result": "decrypted"}'
        api_gateway.encryption_manager = mock_encryption
        
        # Setup mock session
        mock_session = AsyncMock()
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.headers = {'Content-Type': 'application/json', 'X-Encrypted': 'true'}
        mock_response.text.return_value = 'encrypted_response'
        
        mock_session.request.return_value.__aenter__.return_value = mock_response
        api_gateway._session = mock_session
        
        # Create test request with classified data
        request = APIRequest(
            method='POST',
            endpoint='/api/v1/classified',
            data={'sensitive': 'data'},
            classification=SecurityClassification.SECRET
        )
        
        response = await api_gateway.make_request(request)
        
        assert response.status_code == 200
        mock_encryption.encrypt_data.assert_called_once()
        mock_encryption.decrypt_data.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_rate_limiting(self, api_gateway):
        """Test rate limiting functionality."""
        api_gateway._rate_limit_tokens = 0
        api_gateway._rate_limit_reset = time.time() + 3600
        
        request = APIRequest(
            method='GET',
            endpoint='/api/v1/test',
            headers={}
        )
        
        response = await api_gateway.make_request(request)
        
        assert response.error is not None
        assert "Rate limit exceeded" in response.error
    
    @pytest.mark.asyncio
    async def test_security_validation(self, api_gateway):
        """Test security validation."""
        # Test classified data to public endpoint
        request = APIRequest(
            method='POST',
            endpoint='/api/v1/public',
            data={'data': 'classified'},
            endpoint_type=APIEndpointType.PUBLIC,
            classification=SecurityClassification.SECRET
        )
        
        response = await api_gateway.make_request(request)
        
        assert response.error is not None
        assert "classified data to public endpoint" in response.error.lower()


class TestAPISecurityControls:
    """Test cases for API Security Controls."""
    
    @pytest.fixture
    async def security_controller(self):
        """Create security controller for testing."""
        with patch('api_security_controls.aioredis.from_url') as mock_redis:
            mock_redis_instance = AsyncMock()
            mock_redis.return_value = mock_redis_instance
            
            controller = APISecurityController("redis://localhost:6379")
            controller.redis_client = mock_redis_instance
            
            yield controller
    
    @pytest.fixture
    def security_policy(self):
        """Create test security policy."""
        return SecurityPolicy(
            name="test_policy",
            description="Test security policy",
            rate_limit_config=RateLimitConfig(
                algorithm=RateLimitAlgorithm.TOKEN_BUCKET,
                requests_per_window=100,
                window_size_seconds=3600
            ),
            max_request_size=1048576
        )
    
    @pytest.mark.asyncio
    async def test_security_controller_initialization(self, security_controller):
        """Test security controller initialization."""
        await security_controller.initialize()
        
        assert security_controller.redis_client is not None
        assert len(security_controller.attack_patterns) > 0
    
    @pytest.mark.asyncio
    async def test_rate_limiting_token_bucket(self, security_controller):
        """Test token bucket rate limiting."""
        config = RateLimitConfig(
            algorithm=RateLimitAlgorithm.TOKEN_BUCKET,
            requests_per_window=5,
            window_size_seconds=60
        )
        
        # Mock Redis responses
        security_controller.redis_client.hgetall.return_value = {}
        security_controller.redis_client.hset = AsyncMock()
        security_controller.redis_client.expire = AsyncMock()
        
        # Test within rate limit
        for i in range(5):
            result = await security_controller._token_bucket_check("test_key", config)
            assert result is True
        
        # Test exceeding rate limit
        result = await security_controller._token_bucket_check("test_key", config)
        assert result is False
    
    @pytest.mark.asyncio
    async def test_attack_detection(self, security_controller):
        """Test attack pattern detection."""
        # Test SQL injection detection
        request_data = {
            'client_ip': '192.168.1.100',
            'endpoint': '/api/v1/users',
            'method': 'GET',
            'body': {'query': "'; DROP TABLE users; --"},
            'headers': {},
            'params': {}
        }
        
        result = await security_controller._detect_attacks(request_data)
        assert result is True
        
        # Test XSS detection
        request_data['body'] = {'comment': '<script>alert("XSS")</script>'}
        result = await security_controller._detect_attacks(request_data)
        assert result is True
        
        # Test clean request
        request_data['body'] = {'name': 'John Doe'}
        result = await security_controller._detect_attacks(request_data)
        assert result is False
    
    @pytest.mark.asyncio
    async def test_oauth_token_validation(self, security_controller):
        """Test OAuth token validation."""
        # Test invalid token format
        result = await security_controller._validate_oauth_token("invalid_token")
        assert result is False
        
        # Test missing Bearer prefix
        result = await security_controller._validate_oauth_token("Token xyz")
        assert result is False
        
        # Test valid format (mock JWT validation)
        with patch('jwt.decode') as mock_decode:
            mock_decode.return_value = {'exp': int(time.time()) + 3600}
            result = await security_controller._validate_oauth_token("Bearer valid_token")
            assert result is True
    
    @pytest.mark.asyncio
    async def test_request_validation(self, security_controller, security_policy):
        """Test comprehensive request validation."""
        security_controller.add_security_policy("/api/v1/.*", security_policy)
        
        # Test valid request
        request_data = {
            'client_ip': '192.168.1.100',
            'endpoint': '/api/v1/data',
            'method': 'GET',
            'headers': {
                'Authorization': 'Bearer valid_token',
                'Content-Type': 'application/json',
                'Content-Length': '100'
            },
            'body': {'name': 'test'}
        }
        
        # Mock rate limiting and OAuth validation
        with patch.object(security_controller, '_check_rate_limit', return_value=True), \
             patch.object(security_controller, '_validate_oauth_token', return_value=True):
            
            is_valid, errors = await security_controller.validate_request(request_data)
            assert is_valid is True
            assert len(errors) == 0
    
    @pytest.mark.asyncio
    async def test_security_metrics(self, security_controller):
        """Test security metrics collection."""
        # Add some security events
        for i in range(5):
            event = SecurityEvent(
                timestamp=datetime.utcnow(),
                event_id=str(uuid.uuid4()),
                client_ip=f"192.168.1.{i}",
                user_id=None,
                endpoint='/api/v1/test',
                method='GET',
                threat_level=SecurityThreatLevel.MEDIUM,
                attack_type=AttackType.RATE_LIMIT_VIOLATION,
                description="Rate limit exceeded",
                request_data=None,
                response_code=429,
                blocked=True
            )
            security_controller.security_events.append(event)
        
        metrics = await security_controller.get_security_metrics()
        
        assert metrics['events_last_hour'] == 5
        assert metrics['blocked_requests_last_hour'] == 5
        assert SecurityThreatLevel.MEDIUM.value in metrics['threat_levels']


class TestExternalAPIClient:
    """Test cases for External API Client."""
    
    @pytest.fixture
    def api_config(self):
        """Create test API configuration."""
        return ExternalAPIConfig(
            name="test-api",
            base_url="https://external-api.mil",
            environment=ExternalAPIEnvironment.DEVELOPMENT,
            authentication_type=AuthenticationType.API_KEY,
            api_key="test-api-key",
            timeout_seconds=30,
            max_retries=3,
            retry_strategy=RetryStrategy.EXPONENTIAL_BACKOFF
        )
    
    @pytest.fixture
    async def api_client(self, api_config):
        """Create API client for testing."""
        with patch('external_api_client.ssl.create_default_context'), \
             patch('external_api_client.certifi.where', return_value="/tmp/ca-bundle.crt"):
            
            client = ExternalAPIClient(api_config)
            yield client
    
    @pytest.mark.asyncio
    async def test_client_initialization(self, api_client):
        """Test external API client initialization."""
        with patch('aiohttp.ClientSession') as mock_session, \
             patch.object(api_client, '_test_connectivity', return_value=None):
            
            mock_session_instance = AsyncMock()
            mock_session.return_value = mock_session_instance
            
            await api_client.initialize()
            
            assert api_client._session is not None
            assert api_client._ssl_context is not None
    
    @pytest.mark.asyncio
    async def test_circuit_breaker(self, api_config):
        """Test circuit breaker functionality."""
        circuit_breaker = CircuitBreaker(api_config)
        
        # Test successful calls
        async def success_func():
            return "success"
        
        result = await circuit_breaker.call(success_func)
        assert result == "success"
        assert circuit_breaker.stats.failure_count == 0
        
        # Test failed calls
        async def failure_func():
            raise Exception("API error")
        
        # Fail enough times to open circuit breaker
        for i in range(api_config.failure_threshold):
            try:
                await circuit_breaker.call(failure_func)
            except:
                pass
        
        assert circuit_breaker.stats.state.value == "open"
        
        # Test that circuit breaker blocks requests
        with pytest.raises(Exception, match="Circuit breaker is OPEN"):
            await circuit_breaker.call(success_func)
    
    @pytest.mark.asyncio
    async def test_retry_mechanism(self, api_client):
        """Test retry mechanism with exponential backoff."""
        mock_session = AsyncMock()
        api_client._session = mock_session
        
        # Mock failing response then success
        call_count = 0
        
        async def mock_request(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            
            if call_count < 3:
                raise aiohttp.ClientError("Connection error")
            
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.headers = {'Content-Type': 'application/json'}
            mock_response.json.return_value = {'result': 'success'}
            mock_response.text.return_value = '{"result": "success"}'
            return mock_response
        
        mock_session.request.return_value.__aenter__ = mock_request
        
        from external_api_client import APIRequest
        request = APIRequest(
            method='GET',
            endpoint='/api/v1/test'
        )
        
        with patch('asyncio.sleep'):  # Speed up test
            response = await api_client._execute_request(request, "test-id", time.time())
        
        assert response.status_code == 200
        assert call_count == 3  # Failed twice, succeeded on third attempt
    
    @pytest.mark.asyncio
    async def test_hmac_signature(self, api_client):
        """Test HMAC signature generation."""
        api_client.config.authentication_type = AuthenticationType.HMAC_SIGNATURE
        api_client.config.api_secret = "test-secret"
        
        from external_api_client import APIRequest
        request = APIRequest(
            method='POST',
            endpoint='/api/v1/data',
            json_data={'key': 'value'}
        )
        
        headers = {'X-Timestamp': '2023-01-01T00:00:00'}
        signature = api_client._generate_hmac_signature(request, headers)
        
        assert signature is not None
        assert len(signature) == 64  # SHA256 hex digest length
    
    @pytest.mark.asyncio
    async def test_request_encryption(self, api_client):
        """Test request/response encryption."""
        # Mock encryption manager
        mock_encryption = AsyncMock()
        mock_encryption.encrypt_data.return_value = b'encrypted_data'
        mock_encryption.decrypt_data.return_value = b'{"result": "decrypted"}'
        api_client.encryption_manager = mock_encryption
        
        from external_api_client import APIRequest
        request = APIRequest(
            method='POST',
            endpoint='/api/v1/secure',
            json_data={'sensitive': 'data'},
            encrypt_payload=True
        )
        
        # Test data preparation with encryption
        prepared_data = await api_client._prepare_data(request)
        
        assert prepared_data == b'encrypted_data'
        mock_encryption.encrypt_data.assert_called_once()


class TestServiceMeshConfig:
    """Test cases for Service Mesh Configuration."""
    
    @pytest.fixture
    def mesh_config(self):
        """Create test mesh configuration."""
        return ServiceMeshConfig(
            namespace="test-namespace",
            environment=MeshEnvironment.DEVELOPMENT,
            cluster_name="test-cluster",
            mesh_id="test-mesh",
            network="test-network"
        )
    
    @pytest.fixture
    def service_config(self):
        """Create test service configuration."""
        return ServiceConfig(
            name="test-service",
            namespace="test-namespace",
            port=8080,
            version="v1"
        )
    
    @pytest.fixture
    async def mesh_manager(self, mesh_config):
        """Create mesh manager for testing."""
        with patch('service_mesh_config.config.load_kube_config'), \
             patch('service_mesh_config.client.ApiClient'), \
             patch('service_mesh_config.client.CustomObjectsApi'):
            
            manager = ServiceMeshManager(mesh_config)
            yield manager
    
    def test_istio_gateway_generation(self, mesh_manager):
        """Test Istio Gateway configuration generation."""
        gateway_config = mesh_manager.generate_istio_gateway(
            "test-gateway",
            ["test.example.mil"],
            443,
            "SIMPLE"
        )
        
        assert gateway_config['kind'] == 'Gateway'
        assert gateway_config['metadata']['name'] == 'test-gateway'
        assert gateway_config['spec']['servers'][0]['hosts'] == ['test.example.mil']
        assert gateway_config['spec']['servers'][0]['port']['number'] == 443
    
    def test_virtual_service_generation(self, mesh_manager):
        """Test VirtualService configuration generation."""
        vs_config = mesh_manager.generate_virtual_service(
            "test-service",
            "test-gateway",
            ["test.example.mil"],
            "test-service",
            8080
        )
        
        assert vs_config['kind'] == 'VirtualService'
        assert vs_config['metadata']['name'] == 'test-service-vs'
        assert vs_config['spec']['hosts'] == ['test.example.mil']
        assert vs_config['spec']['http'][0]['route'][0]['destination']['host'] == 'test-service'
    
    def test_destination_rule_generation(self, mesh_manager):
        """Test DestinationRule configuration generation."""
        traffic_config = TrafficManagementConfig(
            circuit_breaker_consecutive_errors=3,
            max_requests=50
        )
        
        dr_config = mesh_manager.generate_destination_rule(
            "test-service",
            "test-service",
            traffic_config
        )
        
        assert dr_config['kind'] == 'DestinationRule'
        assert dr_config['spec']['host'] == 'test-service'
        assert dr_config['spec']['trafficPolicy']['outlierDetection']['consecutiveErrors'] == 3
    
    def test_peer_authentication_generation(self, mesh_manager):
        """Test PeerAuthentication configuration generation."""
        peer_auth_config = mesh_manager.generate_peer_authentication(
            "test-service",
            SecurityMode.STRICT
        )
        
        assert peer_auth_config['kind'] == 'PeerAuthentication'
        assert peer_auth_config['spec']['mtls']['mode'] == 'STRICT'
        assert peer_auth_config['spec']['selector']['matchLabels']['app'] == 'test-service'
    
    def test_authorization_policy_generation(self, mesh_manager):
        """Test AuthorizationPolicy configuration generation."""
        auth_policy_config = mesh_manager.generate_authorization_policy(
            "test-service",
            ["api-gateway"],
            ["GET", "POST"]
        )
        
        assert auth_policy_config['kind'] == 'AuthorizationPolicy'
        assert len(auth_policy_config['spec']['rules']) == 2  # 1 source × 2 operations
    
    @pytest.mark.asyncio
    async def test_service_mesh_deployment(self, mesh_manager, service_config):
        """Test complete service mesh configuration deployment."""
        traffic_config = TrafficManagementConfig()
        
        with patch.object(mesh_manager, '_apply_k8s_resource', return_value=None) as mock_apply:
            result = await mesh_manager.deploy_service_mesh_config(service_config, traffic_config)
            
            assert result is True
            assert mock_apply.call_count >= 7  # Should apply multiple resources


class TestGatewayMonitoring:
    """Test cases for Gateway Monitoring."""
    
    @pytest.fixture
    async def monitor(self):
        """Create monitor for testing."""
        with patch('gateway_monitoring.aioredis.from_url') as mock_redis, \
             patch('prometheus_client.start_http_server'):
            
            mock_redis_instance = AsyncMock()
            mock_redis.return_value = mock_redis_instance
            
            monitor = APIGatewayMonitor("redis://localhost:6379")
            monitor.redis_client = mock_redis_instance
            
            yield monitor
    
    @pytest.mark.asyncio
    async def test_monitor_initialization(self, monitor):
        """Test monitor initialization."""
        with patch.object(monitor, '_setup_default_health_checks'), \
             patch.object(monitor, '_setup_default_alerts'):
            
            await monitor.initialize()
            
            assert monitor.redis_client is not None
            assert len(monitor.health_checks) > 0
            assert len(monitor.alerts) > 0
    
    def test_metrics_recording(self, monitor):
        """Test metrics recording."""
        # Test request recording
        monitor.record_request(
            method="GET",
            endpoint="/api/v1/test",
            status_code=200,
            response_time=0.5,
            request_size=1024,
            response_size=2048
        )
        
        # Verify Prometheus metrics were called
        assert monitor.prometheus_metrics.request_total._value._value > 0
    
    def test_security_event_recording(self, monitor):
        """Test security event recording."""
        security_event = SecurityEvent(
            timestamp=datetime.utcnow(),
            event_id=str(uuid.uuid4()),
            client_ip="192.168.1.100",
            user_id=None,
            endpoint="/api/v1/test",
            method="GET",
            threat_level=SecurityThreatLevel.HIGH,
            attack_type=AttackType.SQL_INJECTION,
            description="SQL injection attempt detected",
            request_data=None,
            response_code=403,
            blocked=True
        )
        
        monitor.record_security_event(security_event)
        
        # Verify security metrics were recorded
        assert monitor.prometheus_metrics.security_events_total._value._value > 0
    
    @pytest.mark.asyncio
    async def test_health_check_execution(self, monitor):
        """Test health check execution."""
        # Test Redis health check
        monitor.redis_client.ping = AsyncMock(return_value=True)
        
        result = await monitor._check_redis_health()
        assert result == HealthStatus.HEALTHY
        
        # Test Redis failure
        monitor.redis_client.ping = AsyncMock(side_effect=Exception("Connection failed"))
        
        result = await monitor._check_redis_health()
        assert result == HealthStatus.UNHEALTHY
    
    @pytest.mark.asyncio
    async def test_metrics_collection(self, monitor):
        """Test metrics collection."""
        # Mock Redis data
        mock_request_data = [
            json.dumps({
                'status_code': 200,
                'response_time': 0.5
            }),
            json.dumps({
                'status_code': 404,
                'response_time': 1.0
            })
        ]
        
        mock_security_data = [
            json.dumps({
                'blocked': True,
                'attack_type': 'sql_injection'
            })
        ]
        
        monitor.redis_client.lrange.side_effect = [mock_request_data, mock_security_data]
        
        metrics = await monitor._collect_current_metrics()
        
        assert metrics.total_requests == 2
        assert metrics.successful_requests == 1
        assert metrics.failed_requests == 1
        assert metrics.security_events == 1
        assert metrics.blocked_requests == 1
    
    @pytest.mark.asyncio
    async def test_alert_evaluation(self, monitor):
        """Test alert evaluation."""
        # Add test metrics
        test_metrics = MonitoringMetrics(
            timestamp=datetime.utcnow(),
            total_requests=100,
            successful_requests=90,
            failed_requests=10,
            average_response_time=6.0,  # Above threshold
            blocked_requests=5,
            security_events=2,
            attack_attempts=15,  # Above threshold
            cpu_usage=0.0,
            memory_usage=0.0,
            disk_usage=0.0,
            uptime_seconds=3600,
            availability_percentage=90.0
        )
        
        monitor.metrics_history.append(test_metrics)
        
        with patch.object(monitor, '_trigger_alert') as mock_trigger, \
             patch.object(monitor, '_resolve_alert') as mock_resolve:
            
            await monitor._evaluate_alerts()
            
            # Should trigger alerts for high response time and attacks
            assert mock_trigger.call_count >= 1


class TestIntegration:
    """Comprehensive integration tests for complete API Gateway system."""
    
    @pytest.fixture
    async def integrated_gateway(self):
        """Create fully integrated gateway system for testing."""
        # Setup integrated components
        from auth.oauth_client import OAuthConfig, Platform
        
        oauth_config = OAuthConfig(
            platform=Platform.ADVANA,
            client_id="integration-test-client",
            client_secret="integration-test-secret",
            authorization_url="https://test-auth.mil/oauth/authorize",
            token_url="https://test-auth.mil/oauth/token",
            redirect_uri="https://localhost:8080/callback",
            scopes=["read", "write", "admin"]
        )
        
        gateway_config = DoDAGWConfig(
            environment=APIGatewayEnvironment.DEVELOPMENT,
            gateway_url="https://integration-test-gateway.mil",
            client_certificate_path="/tmp/integration-test-client.crt",
            private_key_path="/tmp/integration-test-client.key",
            ca_bundle_path="/tmp/integration-test-ca.crt",
            oauth_config=oauth_config,
            service_name="integration-test-service",
            service_version="1.0.0",
            security_classification=SecurityClassification.UNCLASSIFIED
        )
        
        # Mock all external dependencies
        with patch('aiohttp.ClientSession') as mock_session, \
             patch('dod_api_gateway.ssl.create_default_context'), \
             patch('api_security_controls.aioredis.from_url') as mock_redis, \
             patch('gateway_monitoring.aioredis.from_url'):
            
            # Setup mock session
            mock_session_instance = AsyncMock()
            mock_session.return_value = mock_session_instance
            
            # Setup mock Redis
            mock_redis_instance = AsyncMock()
            mock_redis.return_value = mock_redis_instance
            
            # Create integrated system
            gateway = DoDAPIGateway(gateway_config)
            security_controller = APISecurityController("redis://localhost:6379")
            monitor = APIGatewayMonitor("redis://localhost:6379")
            
            # Initialize components
            gateway._session = mock_session_instance
            security_controller.redis_client = mock_redis_instance
            monitor.redis_client = mock_redis_instance
            
            yield {
                'gateway': gateway,
                'security': security_controller,
                'monitor': monitor,
                'mock_session': mock_session_instance,
                'mock_redis': mock_redis_instance
            }
    
    @pytest.mark.asyncio
    async def test_end_to_end_request_flow(self, integrated_gateway):
        """Test complete request flow through API Gateway."""
        gateway = integrated_gateway['gateway']
        security = integrated_gateway['security']
        monitor = integrated_gateway['monitor']
        mock_session = integrated_gateway['mock_session']
        
        # Setup successful response mock
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.headers = {'Content-Type': 'application/json'}
        mock_response.json.return_value = {'data': 'success', 'id': '12345'}
        mock_session.request.return_value.__aenter__.return_value = mock_response
        
        # Create test request
        request = APIRequest(
            method='GET',
            endpoint='/api/v1/users/12345',
            headers={
                'Authorization': 'Bearer valid_token',
                'X-Request-ID': 'test-request-123'
            },
            classification=SecurityClassification.UNCLASSIFIED
        )
        
        # Test complete flow
        start_time = time.time()
        
        # 1. Security validation
        request_data = {
            'client_ip': '192.168.1.100',
            'endpoint': request.endpoint,
            'method': request.method,
            'headers': request.headers,
            'body': None
        }
        
        with patch.object(security, '_check_rate_limit', return_value=True), \
             patch.object(security, '_validate_oauth_token', return_value=True), \
             patch.object(security, '_detect_attacks', return_value=False):
            
            is_valid, errors = await security.validate_request(request_data)
            assert is_valid is True
            assert len(errors) == 0
        
        # 2. Gateway request processing
        response = await gateway.make_request(request)
        
        # 3. Monitor metrics recording
        monitor.record_request(
            method=request.method,
            endpoint=request.endpoint,
            status_code=response.status_code,
            response_time=time.time() - start_time,
            request_size=1024,
            response_size=2048
        )
        
        # Verify end-to-end flow
        assert response.status_code == 200
        assert response.data['data'] == 'success'
        assert response.error is None
        
        # Verify security logging
        assert len(security.security_events) > 0
        
        # Verify monitoring metrics
        assert monitor.prometheus_metrics.request_total._value._value > 0
    
    @pytest.mark.asyncio
    async def test_security_incident_response(self, integrated_gateway):
        """Test complete security incident detection and response workflow."""
        gateway = integrated_gateway['gateway']
        security = integrated_gateway['security']
        monitor = integrated_gateway['monitor']
        
        # Create malicious request
        malicious_request = APIRequest(
            method='POST',
            endpoint='/api/v1/users',
            headers={
                'Authorization': 'Bearer invalid_token',
                'Content-Type': 'application/json'
            },
            data={'query': "'; DROP TABLE users; --"},  # SQL injection attempt
            classification=SecurityClassification.UNCLASSIFIED
        )
        
        request_data = {
            'client_ip': '192.168.1.100',
            'endpoint': malicious_request.endpoint,
            'method': malicious_request.method,
            'headers': malicious_request.headers,
            'body': malicious_request.data
        }
        
        # Test security incident detection
        with patch.object(security, '_check_rate_limit', return_value=True), \
             patch.object(security, '_validate_oauth_token', return_value=False):
            
            is_valid, errors = await security.validate_request(request_data)
            
            # Verify incident detection
            assert is_valid is False
            assert len(errors) > 0
            assert any('OAuth' in error for error in errors)
        
        # Verify security event logging
        security_events = [event for event in security.security_events if event.blocked]
        assert len(security_events) > 0
        
        # Verify high threat level events
        high_threat_events = [
            event for event in security_events 
            if event.threat_level in [SecurityThreatLevel.HIGH, SecurityThreatLevel.CRITICAL]
        ]
        assert len(high_threat_events) > 0
        
        # Test security metrics
        security_metrics = await security.get_security_metrics()
        assert security_metrics['blocked_requests_last_hour'] > 0
        
        # Record security event in monitor
        if security_events:
            monitor.record_security_event(security_events[0])
            assert monitor.prometheus_metrics.security_events_total._value._value > 0
    
    @pytest.mark.asyncio
    async def test_high_availability_scenarios(self, integrated_gateway):
        """Test high availability and failover scenarios."""
        gateway = integrated_gateway['gateway']
        mock_session = integrated_gateway['mock_session']
        
        # Test circuit breaker functionality
        from external_api_client import ExternalAPIConfig, ExternalAPIClient, AuthenticationType, ExternalAPIEnvironment, RetryStrategy
        
        api_config = ExternalAPIConfig(
            name="test-failover-api",
            base_url="https://failover-test.mil",
            environment=ExternalAPIEnvironment.DEVELOPMENT,
            authentication_type=AuthenticationType.API_KEY,
            api_key="test-key",
            timeout_seconds=5,
            max_retries=2,
            retry_strategy=RetryStrategy.EXPONENTIAL_BACKOFF,
            circuit_breaker_enabled=True,
            failure_threshold=3,
            recovery_timeout_seconds=30
        )
        
        with patch('external_api_client.ssl.create_default_context'), \
             patch('external_api_client.certifi.where', return_value="/tmp/ca-bundle.crt"):
            
            api_client = ExternalAPIClient(api_config)
            api_client._session = mock_session
            
            # Test failover scenario - simulate API failures
            mock_session.request.side_effect = Exception("Connection timeout")
            
            from external_api_client import APIRequest as ExtAPIRequest
            test_request = ExtAPIRequest(
                method='GET',
                endpoint='/api/v1/health'
            )
            
            # First few requests should fail and trigger circuit breaker
            for i in range(3):
                response = await api_client.make_request(test_request)
                assert response.error is not None
            
            # Circuit breaker should now be open
            circuit_status = api_client.get_circuit_breaker_status()
            assert circuit_status['failure_count'] >= 3
    
    @pytest.mark.asyncio
    async def test_classification_data_handling(self, integrated_gateway):
        """Test proper handling of classified data through the gateway."""
        gateway = integrated_gateway['gateway']
        security = integrated_gateway['security']
        mock_session = integrated_gateway['mock_session']
        
        # Test SECRET classification request
        classified_request = APIRequest(
            method='POST',
            endpoint='/api/v1/classified/data',
            headers={
                'Authorization': 'Bearer valid_secret_token',
                'Content-Type': 'application/json',
                'X-Classification': 'SECRET'
            },
            data={'sensitive_data': 'classified_information'},
            classification=SecurityClassification.SECRET,
            endpoint_type=APIEndpointType.CLASSIFIED
        )
        
        # Mock encryption for classified data
        mock_encryption = AsyncMock()
        mock_encryption.encrypt_data.return_value = b'encrypted_classified_data'
        mock_encryption.decrypt_data.return_value = b'{"result": "success", "classification": "SECRET"}'
        gateway.encryption_manager = mock_encryption
        
        # Setup classified response
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.headers = {
            'Content-Type': 'application/json',
            'X-Encrypted': 'true',
            'X-Classification': 'SECRET'
        }
        mock_response.text.return_value = 'encrypted_response_data'
        mock_session.request.return_value.__aenter__.return_value = mock_response
        
        # Execute classified request
        response = await gateway.make_request(classified_request)
        
        # Verify classified data handling
        assert response.status_code == 200
        assert mock_encryption.encrypt_data.called
        assert mock_encryption.decrypt_data.called
        
        # Verify security controls for classified data
        request_data = {
            'client_ip': '192.168.1.100',
            'endpoint': classified_request.endpoint,
            'method': classified_request.method,
            'headers': classified_request.headers,
            'body': classified_request.data,
            'classification': SecurityClassification.SECRET.value
        }
        
        # Should have stricter validation for classified endpoints
        high_security_policy = create_high_security_policy()
        security.add_security_policy(r"/api/v1/classified/.*", high_security_policy)
        
        with patch.object(security, '_check_rate_limit', return_value=True), \
             patch.object(security, '_validate_oauth_token', return_value=True), \
             patch.object(security, '_detect_attacks', return_value=False):
            
            is_valid, errors = await security.validate_request(request_data)
            assert is_valid is True
    
    @pytest.mark.asyncio
    async def test_service_mesh_integration(self):
        """Test service mesh configuration and deployment."""
        from service_mesh_config import ServiceMeshManager, ServiceMeshConfig, ServiceConfig, TrafficManagementConfig, MeshEnvironment, SecurityMode
        
        mesh_config = ServiceMeshConfig(
            namespace="api-gateway-test",
            environment=MeshEnvironment.DEVELOPMENT,
            cluster_name="test-cluster",
            mesh_id="test-mesh",
            network="test-network"
        )
        
        service_config = ServiceConfig(
            name="api-gateway",
            namespace="api-gateway-test",
            port=443,
            version="v1"
        )
        
        traffic_config = TrafficManagementConfig(
            circuit_breaker_consecutive_errors=5,
            max_requests=100,
            timeout_seconds=30
        )
        
        with patch('service_mesh_config.config.load_kube_config'), \
             patch('service_mesh_config.client.ApiClient'), \
             patch('service_mesh_config.client.CustomObjectsApi'):
            
            mesh_manager = ServiceMeshManager(mesh_config)
            
            # Test Istio configurations
            gateway_config = mesh_manager.generate_istio_gateway(
                "api-gateway",
                ["api.test.mil"],
                443,
                "SIMPLE"
            )
            
            assert gateway_config['kind'] == 'Gateway'
            assert gateway_config['spec']['servers'][0]['hosts'] == ['api.test.mil']
            
            # Test VirtualService configuration
            vs_config = mesh_manager.generate_virtual_service(
                "api-gateway",
                "api-gateway",
                ["api.test.mil"],
                "api-gateway",
                443
            )
            
            assert vs_config['kind'] == 'VirtualService'
            assert vs_config['spec']['hosts'] == ['api.test.mil']
            
            # Test mTLS configuration
            peer_auth = mesh_manager.generate_peer_authentication(
                "api-gateway",
                SecurityMode.STRICT
            )
            
            assert peer_auth['spec']['mtls']['mode'] == 'STRICT'
    
    @pytest.mark.asyncio
    async def test_external_api_integration(self):
        """Test external API client integration with gateway."""
        from external_api_client import ExternalAPIConfig, ExternalAPIClient, AuthenticationType, ExternalAPIEnvironment
        
        # Create external API configuration
        api_config = ExternalAPIConfig(
            name="external-dod-service",
            base_url="https://external.dod.mil",
            environment=ExternalAPIEnvironment.DEVELOPMENT,
            authentication_type=AuthenticationType.MUTUAL_TLS,
            client_cert_path="/tmp/external-client.crt",
            client_key_path="/tmp/external-client.key",
            ca_bundle_path="/tmp/external-ca.crt",
            timeout_seconds=30,
            max_retries=3
        )
        
        with patch('external_api_client.ssl.create_default_context'), \
             patch('external_api_client.certifi.where', return_value="/tmp/ca-bundle.crt"), \
             patch('aiohttp.ClientSession') as mock_session:
            
            mock_session_instance = AsyncMock()
            mock_session.return_value = mock_session_instance
            
            # Mock successful external API response
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.headers = {'Content-Type': 'application/json'}
            mock_response.text.return_value = '{"status": "success", "data": "external_data"}'
            mock_response.json.return_value = {'status': 'success', 'data': 'external_data'}
            mock_session_instance.request.return_value.__aenter__.return_value = mock_response
            
            # Test external API client
            api_client = ExternalAPIClient(api_config)
            api_client._session = mock_session_instance
            
            # Test GET request
            response = await api_client.get('/api/v1/external-data')
            
            assert response.status_code == 200
            assert response.json_data['status'] == 'success'
            assert response.error is None
            
            # Test circuit breaker status
            circuit_status = api_client.get_circuit_breaker_status()
            assert circuit_status['state'] == 'closed'
            assert circuit_status['failure_count'] == 0
    
    @pytest.mark.asyncio
    async def test_comprehensive_monitoring_integration(self, integrated_gateway):
        """Test comprehensive monitoring and alerting integration."""
        monitor = integrated_gateway['monitor']
        mock_redis = integrated_gateway['mock_redis']
        
        # Initialize monitoring
        await monitor.initialize()
        
        # Test metrics collection
        test_metrics = {
            'timestamp': datetime.utcnow().isoformat(),
            'method': 'GET',
            'endpoint': '/api/v1/test',
            'status_code': 200,
            'response_time': 0.5,
            'request_size': 1024,
            'response_size': 2048,
            'classification': 'UNCLASSIFIED'
        }
        
        # Mock Redis responses for metrics collection
        mock_redis.lrange.return_value = [json.dumps(test_metrics)]
        
        # Test health checks
        mock_redis.ping.return_value = True
        health_status = await monitor._check_redis_health()
        assert health_status == HealthStatus.HEALTHY
        
        # Test metrics collection
        current_metrics = await monitor._collect_current_metrics()
        assert current_metrics.total_requests == 1
        assert current_metrics.successful_requests == 1
        assert current_metrics.failed_requests == 0
        
        # Test security event recording
        from api_gateway.api_security_controls import SecurityEvent, SecurityThreatLevel, AttackType
        
        security_event = SecurityEvent(
            timestamp=datetime.utcnow(),
            event_id=str(uuid.uuid4()),
            client_ip="192.168.1.100",
            user_id=None,
            endpoint="/api/v1/test",
            method="GET",
            threat_level=SecurityThreatLevel.LOW,
            attack_type=None,
            description="Normal request processed",
            request_data=None,
            response_code=200,
            blocked=False
        )
        
        monitor.record_security_event(security_event)
        
        # Verify Prometheus metrics
        assert monitor.prometheus_metrics.security_events_total._value._value > 0


# Additional integration test utilities
class IntegrationTestUtils:
    """Utilities for integration testing."""
    
    @staticmethod
    def create_test_certificate():
        """Create test certificate for mTLS testing."""
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID
        
        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        
        # Create certificate
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "DC"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Washington"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "DoD Test"),
            x509.NameAttribute(NameOID.COMMON_NAME, "test.dod.mil"),
        ])
        
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=365)
        ).add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("test.dod.mil"),
                x509.DNSName("*.test.dod.mil"),
            ]),
            critical=False,
        ).sign(private_key, hashes.SHA256())
        
        return private_key, cert
    
    @staticmethod
    def setup_test_environment():
        """Setup test environment with necessary certificates and configurations."""
        import tempfile
        import os
        
        # Create temporary directory for test certificates
        test_dir = tempfile.mkdtemp(prefix='dod_api_gateway_test_')
        
        # Generate test certificates
        private_key, cert = IntegrationTestUtils.create_test_certificate()
        
        # Write certificate files
        cert_path = os.path.join(test_dir, 'test_cert.pem')
        key_path = os.path.join(test_dir, 'test_key.pem')
        ca_path = os.path.join(test_dir, 'test_ca.pem')
        
        with open(cert_path, 'wb') as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        
        with open(key_path, 'wb') as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        
        # Copy cert as CA for testing
        with open(ca_path, 'wb') as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        
        return {
            'test_dir': test_dir,
            'cert_path': cert_path,
            'key_path': key_path,
            'ca_path': ca_path
        }
    
    @staticmethod
    def cleanup_test_environment(test_env):
        """Clean up test environment."""
        import shutil
        shutil.rmtree(test_env['test_dir'], ignore_errors=True)


if __name__ == "__main__":
    # Run comprehensive integration tests
    pytest.main([
        __file__, 
        "-v", 
        "--tb=short",
        "-k", "test_",
        "--durations=10",
        "--cov=dod_api_gateway",
        "--cov=api_security_controls",
        "--cov=gateway_monitoring",
        "--cov=external_api_client",
        "--cov=service_mesh_config",
        "--cov-report=html",
        "--cov-report=term-missing"
    ])