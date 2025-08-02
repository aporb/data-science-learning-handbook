"""
DoD API Gateway Discovery Client

This module implements client-side service discovery mechanisms with intelligent
load balancing, caching, and failover capabilities for DoD API Gateway environments.
Provides high-level abstractions for service consumption with automatic endpoint
selection, health-aware routing, and security classification handling.

Key Features:
- Intelligent service discovery with caching and refresh strategies
- Multiple load balancing algorithms with health awareness
- Automatic failover and circuit breaker integration
- Security classification-aware service selection
- Connection pooling and request retry mechanisms
- Real-time service topology awareness
- Performance metrics collection and optimization

Security Standards:
- NIST 800-53 service discovery controls
- DoD 8500 series client security requirements
- FIPS 140-2 secure communication protocols
- STIGs compliance for client-side security
"""

import asyncio
import aiohttp
import time
import json
import logging
import random
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple, Callable, Union
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict, deque
import ipaddress

# Import from existing modules
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from api_gateway.service_registry import (
    ServiceRegistry, ServiceRegistration, ServiceEndpoint, ServiceDiscoveryQuery,
    LoadBalancingStrategy, SecurityClassification, APIGatewayEnvironment
)
from api_gateway.health_monitor import HealthMonitor, HealthCheckResult
from api_gateway.dod_api_gateway import DoDAPIGateway, APIRequest, APIResponse
from audits.audit_logger import AuditLogger


class DiscoveryStrategy(Enum):
    """Service discovery strategies."""
    CACHE_FIRST = "cache_first"
    REGISTRY_FIRST = "registry_first"
    HYBRID = "hybrid"
    REAL_TIME = "real_time"


class CachePolicy(Enum):
    """Service cache policies."""
    TTL_BASED = "ttl_based"
    HEALTH_BASED = "health_based"
    USAGE_BASED = "usage_based"
    ADAPTIVE = "adaptive"


class FailoverStrategy(Enum):
    """Failover strategies."""
    IMMEDIATE = "immediate"
    GRADUAL = "gradual"
    CIRCUIT_BREAKER = "circuit_breaker"
    MANUAL = "manual"


class ClientState(Enum):
    """Client connection states."""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    FAILED = "failed"
    RECONNECTING = "reconnecting"


@dataclass
class DiscoveryConfig:
    """Discovery client configuration."""
    strategy: DiscoveryStrategy = DiscoveryStrategy.HYBRID
    cache_policy: CachePolicy = CachePolicy.ADAPTIVE
    cache_ttl_seconds: int = 300
    refresh_interval_seconds: int = 60
    max_cached_services: int = 1000
    enable_health_filtering: bool = True
    enable_load_balancing: bool = True
    default_load_balancing: LoadBalancingStrategy = LoadBalancingStrategy.LEAST_RESPONSE_TIME
    connection_pool_size: int = 100
    request_timeout_seconds: int = 30
    max_retries: int = 3
    retry_backoff_factor: float = 2.0


@dataclass
class ServiceEndpointState:
    """Service endpoint state tracking."""
    endpoint: ServiceEndpoint
    service_id: str
    registration_id: str
    health_status: HealthCheckResult = HealthCheckResult.UNKNOWN
    response_times: deque = field(default_factory=lambda: deque(maxlen=100))
    success_count: int = 0
    failure_count: int = 0
    last_used: Optional[datetime] = None
    last_success: Optional[datetime] = None
    last_failure: Optional[datetime] = None
    connection_count: int = 0
    weight: float = 1.0


@dataclass
class CachedService:
    """Cached service information."""
    registration: ServiceRegistration
    endpoints: List[ServiceEndpointState]
    cache_time: datetime
    last_refresh: datetime
    access_count: int = 0
    last_access: Optional[datetime] = None
    ttl_seconds: int = 300


@dataclass
class DiscoveryMetrics:
    """Discovery client metrics."""
    total_discoveries: int = 0
    cache_hits: int = 0
    cache_misses: int = 0
    registry_queries: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    avg_discovery_time: float = 0.0
    avg_request_time: float = 0.0
    active_connections: int = 0
    failover_events: int = 0


class DiscoveryClient:
    """
    DoD API Gateway Discovery Client
    
    High-level client for service discovery, load balancing, and intelligent
    request routing with health awareness and failover capabilities.
    """
    
    def __init__(self, service_registry: ServiceRegistry, 
                 health_monitor: Optional[HealthMonitor] = None,
                 config: Optional[DiscoveryConfig] = None):
        """Initialize discovery client."""
        self.logger = logging.getLogger(__name__)
        
        # Core components
        self.service_registry = service_registry
        self.health_monitor = health_monitor
        self.config = config or DiscoveryConfig()
        
        # Service cache
        self.service_cache: Dict[str, CachedService] = {}
        self.cache_locks: Dict[str, asyncio.Lock] = defaultdict(asyncio.Lock)
        
        # Load balancing state
        self.load_balancer_state: Dict[str, Dict] = defaultdict(dict)
        self.endpoint_states: Dict[str, ServiceEndpointState] = {}
        
        # Connection management
        self.connection_pools: Dict[str, aiohttp.ClientSession] = {}
        self.active_connections: Dict[str, int] = defaultdict(int)
        
        # Metrics and monitoring
        self.metrics = DiscoveryMetrics()
        self.request_history: deque = deque(maxlen=10000)
        
        # Background tasks
        self._cache_refresh_task = None
        self._metrics_task = None
        self._cleanup_task = None
        
        # Audit logging
        self.audit_logger = None
        
        # Circuit breaker integration
        self.circuit_breakers: Dict[str, Dict] = {}
        
        # Custom service resolvers
        self.custom_resolvers: Dict[str, Callable] = {}
    
    async def initialize(self) -> None:
        """Initialize discovery client."""
        try:
            # Initialize audit logging
            self.audit_logger = AuditLogger()
            await self.audit_logger.initialize()
            
            # Initialize connection pools
            await self._initialize_connection_pools()
            
            # Start background tasks
            self._cache_refresh_task = asyncio.create_task(self._refresh_cache_periodically())
            self._metrics_task = asyncio.create_task(self._calculate_metrics_periodically())
            self._cleanup_task = asyncio.create_task(self._cleanup_expired_cache())
            
            self.logger.info("Discovery Client initialized successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize discovery client: {e}")
            raise
    
    async def discover_service(self, service_name: str, 
                             classification: Optional[SecurityClassification] = None,
                             environment: Optional[APIGatewayEnvironment] = None,
                             version: Optional[str] = None) -> List[ServiceEndpointState]:
        """
        Discover service endpoints with intelligent caching and load balancing.
        
        Args:
            service_name: Name of service to discover
            classification: Required security classification
            environment: Target environment
            version: Service version pattern
            
        Returns:
            List of available service endpoints ordered by load balancing strategy
        """
        start_time = time.time()
        self.metrics.total_discoveries += 1
        
        try:
            cache_key = self._generate_cache_key(service_name, classification, environment, version)
            
            # Check cache first if strategy allows
            if self.config.strategy in [DiscoveryStrategy.CACHE_FIRST, DiscoveryStrategy.HYBRID]:
                cached_endpoints = await self._get_cached_endpoints(cache_key)
                if cached_endpoints:
                    self.metrics.cache_hits += 1
                    discovery_time = time.time() - start_time
                    self.metrics.avg_discovery_time = self._update_average(
                        self.metrics.avg_discovery_time, discovery_time, self.metrics.total_discoveries
                    )
                    return cached_endpoints
            
            self.metrics.cache_misses += 1
            
            # Query service registry
            endpoints = await self._query_registry(service_name, classification, environment, version)
            
            # Cache the results
            if endpoints:
                await self._cache_endpoints(cache_key, endpoints, service_name)
            
            discovery_time = time.time() - start_time
            self.metrics.avg_discovery_time = self._update_average(
                self.metrics.avg_discovery_time, discovery_time, self.metrics.total_discoveries
            )
            
            # Log discovery
            await self._log_discovery(service_name, len(endpoints), discovery_time)
            
            return endpoints
            
        except Exception as e:
            self.logger.error(f"Service discovery failed for {service_name}: {e}")
            
            # Try to return cached endpoints as fallback
            try:
                cache_key = self._generate_cache_key(service_name, classification, environment, version)
                cached_endpoints = await self._get_cached_endpoints(cache_key, ignore_ttl=True)
                if cached_endpoints:
                    self.logger.warning(f"Using stale cache for {service_name} due to discovery error")
                    return cached_endpoints
            except:
                pass
            
            return []
    
    async def make_request(self, service_name: str, path: str = "/",
                          method: str = "GET", data: Optional[Any] = None,
                          headers: Optional[Dict[str, str]] = None,
                          params: Optional[Dict[str, str]] = None,
                          classification: Optional[SecurityClassification] = None,
                          timeout: Optional[int] = None,
                          retries: Optional[int] = None) -> Optional[APIResponse]:
        """
        Make request to a service with automatic endpoint selection and failover.
        
        Args:
            service_name: Target service name
            path: Request path
            method: HTTP method
            data: Request data
            headers: Request headers
            params: Query parameters
            classification: Security classification
            timeout: Request timeout
            retries: Number of retries
            
        Returns:
            API response or None if all endpoints failed
        """
        start_time = time.time()
        retries = retries or self.config.max_retries
        timeout = timeout or self.config.request_timeout_seconds
        headers = headers or {}
        
        try:
            # Discover service endpoints
            endpoints = await self.discover_service(service_name, classification)
            
            if not endpoints:
                self.logger.warning(f"No endpoints found for service: {service_name}")
                return None
            
            # Apply load balancing and health filtering
            ordered_endpoints = self._order_endpoints_for_request(endpoints)
            
            # Try endpoints in order with retries
            last_error = None
            
            for endpoint_state in ordered_endpoints:
                for attempt in range(retries + 1):
                    try:
                        # Check circuit breaker
                        if self._is_circuit_breaker_open(endpoint_state.service_id, endpoint_state.endpoint.url):
                            continue
                        
                        # Make the request
                        response = await self._make_endpoint_request(
                            endpoint_state, path, method, data, headers, params, timeout
                        )
                        
                        # Update endpoint state on success
                        await self._update_endpoint_success(endpoint_state, time.time() - start_time)
                        
                        # Update metrics
                        self.metrics.successful_requests += 1
                        request_time = time.time() - start_time
                        self.metrics.avg_request_time = self._update_average(
                            self.metrics.avg_request_time, request_time, 
                            self.metrics.successful_requests + self.metrics.failed_requests
                        )
                        
                        # Log successful request
                        await self._log_request_success(service_name, endpoint_state, request_time)
                        
                        return response
                        
                    except Exception as e:
                        last_error = e
                        
                        # Update endpoint state on failure
                        await self._update_endpoint_failure(endpoint_state, str(e))
                        
                        # Apply retry backoff
                        if attempt < retries:
                            backoff_time = self.config.retry_backoff_factor ** attempt
                            await asyncio.sleep(backoff_time)
                        
                        self.logger.warning(f"Request failed to {endpoint_state.endpoint.url}: {e}")
            
            # All endpoints failed
            self.metrics.failed_requests += 1
            
            # Log request failure
            await self._log_request_failure(service_name, last_error)
            
            return None
            
        except Exception as e:
            self.logger.error(f"Request to {service_name} failed: {e}")
            self.metrics.failed_requests += 1
            return None
    
    async def get_service_info(self, service_name: str) -> Optional[Dict[str, Any]]:
        """Get comprehensive service information including health and metrics."""
        try:
            endpoints = await self.discover_service(service_name)
            
            if not endpoints:
                return None
            
            # Collect service information
            service_info = {
                'service_name': service_name,
                'endpoints_count': len(endpoints),
                'healthy_endpoints': len([ep for ep in endpoints if ep.health_status == HealthCheckResult.HEALTHY]),
                'endpoints': [],
                'load_balancing_strategy': self.config.default_load_balancing.value,
                'cache_status': await self._get_cache_status(service_name)
            }
            
            # Add endpoint details
            for endpoint_state in endpoints:
                endpoint_info = {
                    'url': endpoint_state.endpoint.url,
                    'protocol': endpoint_state.endpoint.protocol,
                    'port': endpoint_state.endpoint.port,
                    'health_status': endpoint_state.health_status.value,
                    'response_time_avg': statistics.mean(endpoint_state.response_times) if endpoint_state.response_times else 0,
                    'success_count': endpoint_state.success_count,
                    'failure_count': endpoint_state.failure_count,
                    'last_used': endpoint_state.last_used.isoformat() if endpoint_state.last_used else None,
                    'connection_count': endpoint_state.connection_count,
                    'weight': endpoint_state.weight
                }
                service_info['endpoints'].append(endpoint_info)
            
            return service_info
            
        except Exception as e:
            self.logger.error(f"Failed to get service info for {service_name}: {e}")
            return None
    
    async def refresh_service_cache(self, service_name: Optional[str] = None) -> None:
        """Manually refresh service cache."""
        try:
            if service_name:
                # Refresh specific service
                cache_keys = [key for key in self.service_cache.keys() if service_name in key]
            else:
                # Refresh all services
                cache_keys = list(self.service_cache.keys())
            
            for cache_key in cache_keys:
                await self._refresh_cached_service(cache_key)
            
            self.logger.info(f"Refreshed cache for {len(cache_keys)} services")
            
        except Exception as e:
            self.logger.error(f"Failed to refresh service cache: {e}")
    
    async def invalidate_cache(self, service_name: Optional[str] = None) -> None:
        """Invalidate service cache."""
        try:
            if service_name:
                # Invalidate specific service
                cache_keys = [key for key in self.service_cache.keys() if service_name in key]
                for cache_key in cache_keys:
                    del self.service_cache[cache_key]
            else:
                # Invalidate all
                self.service_cache.clear()
            
            self.logger.info(f"Invalidated cache for service: {service_name or 'all services'}")
            
        except Exception as e:
            self.logger.error(f"Failed to invalidate cache: {e}")
    
    def register_custom_resolver(self, service_name: str, resolver: Callable) -> None:
        """Register custom service resolver."""
        self.custom_resolvers[service_name] = resolver
        self.logger.info(f"Custom resolver registered for service: {service_name}")
    
    async def get_metrics(self) -> DiscoveryMetrics:
        """Get discovery client metrics."""
        # Update active connections count
        self.metrics.active_connections = sum(self.active_connections.values())
        return self.metrics
    
    async def _get_cached_endpoints(self, cache_key: str, ignore_ttl: bool = False) -> Optional[List[ServiceEndpointState]]:
        """Get endpoints from cache."""
        try:
            async with self.cache_locks[cache_key]:
                cached_service = self.service_cache.get(cache_key)
                
                if not cached_service:
                    return None
                
                current_time = datetime.utcnow()
                
                # Check TTL unless ignored
                if not ignore_ttl:
                    if self.config.cache_policy == CachePolicy.TTL_BASED:
                        if (current_time - cached_service.cache_time).total_seconds() > cached_service.ttl_seconds:
                            return None
                    
                    elif self.config.cache_policy == CachePolicy.HEALTH_BASED:
                        # Check if any endpoint health has changed significantly
                        if self.health_monitor:
                            for endpoint_state in cached_service.endpoints:
                                current_health = await self.health_monitor.get_health_status(endpoint_state.service_id)
                                if current_health and current_health != endpoint_state.health_status:
                                    return None
                
                # Update access statistics
                cached_service.access_count += 1
                cached_service.last_access = current_time
                
                # Apply health filtering if enabled
                if self.config.enable_health_filtering:
                    healthy_endpoints = [
                        ep for ep in cached_service.endpoints 
                        if ep.health_status in [HealthCheckResult.HEALTHY, HealthCheckResult.DEGRADED]
                    ]
                    return healthy_endpoints if healthy_endpoints else cached_service.endpoints
                
                return cached_service.endpoints
                
        except Exception as e:
            self.logger.error(f"Error getting cached endpoints: {e}")
            return None
    
    async def _query_registry(self, service_name: str, 
                            classification: Optional[SecurityClassification],
                            environment: Optional[APIGatewayEnvironment],
                            version: Optional[str]) -> List[ServiceEndpointState]:
        """Query service registry for endpoints."""
        try:
            self.metrics.registry_queries += 1
            
            # Build discovery query
            query = ServiceDiscoveryQuery(
                service_name=service_name,
                classification=classification,
                environment=environment,
                version_pattern=version,
                exclude_unhealthy=self.config.enable_health_filtering
            )
            
            # Query registry
            registrations = await self.service_registry.discover_services(query)
            
            # Convert to endpoint states
            endpoint_states = []
            
            for registration in registrations:
                for endpoint in registration.metadata.endpoints:
                    # Create endpoint state
                    endpoint_state = ServiceEndpointState(
                        endpoint=endpoint,
                        service_id=registration.metadata.service_id,
                        registration_id=registration.registration_id,
                        health_status=registration.status.value if hasattr(registration.status, 'value') else HealthCheckResult.UNKNOWN
                    )
                    
                    # Get health status from health monitor if available
                    if self.health_monitor:
                        health_status = await self.health_monitor.get_health_status(registration.metadata.service_id)
                        if health_status:
                            endpoint_state.health_status = health_status
                    
                    # Generate endpoint key
                    endpoint_key = f"{registration.metadata.service_id}:{endpoint.url}"
                    
                    # Load existing state if available
                    if endpoint_key in self.endpoint_states:
                        existing_state = self.endpoint_states[endpoint_key]
                        endpoint_state.response_times = existing_state.response_times
                        endpoint_state.success_count = existing_state.success_count
                        endpoint_state.failure_count = existing_state.failure_count
                        endpoint_state.last_used = existing_state.last_used
                        endpoint_state.last_success = existing_state.last_success
                        endpoint_state.last_failure = existing_state.last_failure
                        endpoint_state.connection_count = existing_state.connection_count
                        endpoint_state.weight = existing_state.weight
                    
                    # Store endpoint state
                    self.endpoint_states[endpoint_key] = endpoint_state
                    endpoint_states.append(endpoint_state)
            
            return endpoint_states
            
        except Exception as e:
            self.logger.error(f"Registry query failed: {e}")
            return []
    
    async def _cache_endpoints(self, cache_key: str, endpoints: List[ServiceEndpointState], service_name: str) -> None:
        """Cache discovered endpoints."""
        try:
            async with self.cache_locks[cache_key]:
                # Create cached service entry
                cached_service = CachedService(
                    registration=None,  # We could store the first registration for metadata
                    endpoints=endpoints.copy(),
                    cache_time=datetime.utcnow(),
                    last_refresh=datetime.utcnow(),
                    ttl_seconds=self.config.cache_ttl_seconds
                )
                
                # Store in cache
                self.service_cache[cache_key] = cached_service
                
                # Implement cache size limit
                if len(self.service_cache) > self.config.max_cached_services:
                    await self._evict_cache_entries()
                
        except Exception as e:
            self.logger.error(f"Failed to cache endpoints: {e}")
    
    def _generate_cache_key(self, service_name: str, 
                          classification: Optional[SecurityClassification],
                          environment: Optional[APIGatewayEnvironment],
                          version: Optional[str]) -> str:
        """Generate cache key for service discovery parameters."""
        key_parts = [service_name]
        
        if classification:
            key_parts.append(classification.value)
        if environment:
            key_parts.append(environment.value)
        if version:
            key_parts.append(version)
        
        return ":".join(key_parts)
    
    def _order_endpoints_for_request(self, endpoints: List[ServiceEndpointState]) -> List[ServiceEndpointState]:
        """Order endpoints based on load balancing strategy."""
        if not endpoints:
            return []
        
        strategy = self.config.default_load_balancing
        
        if strategy == LoadBalancingStrategy.ROUND_ROBIN:
            # Simple round-robin (stateful implementation would be better)
            return endpoints
        
        elif strategy == LoadBalancingStrategy.LEAST_CONNECTIONS:
            # Sort by connection count
            return sorted(endpoints, key=lambda ep: ep.connection_count)
        
        elif strategy == LoadBalancingStrategy.LEAST_RESPONSE_TIME:
            # Sort by average response time
            def get_avg_response_time(ep):
                if ep.response_times:
                    return statistics.mean(ep.response_times)
                return float('inf')
            
            return sorted(endpoints, key=get_avg_response_time)
        
        elif strategy == LoadBalancingStrategy.WEIGHTED_ROUND_ROBIN:
            # Sort by weight (descending)
            return sorted(endpoints, key=lambda ep: ep.weight, reverse=True)
        
        elif strategy == LoadBalancingStrategy.RANDOM:
            shuffled = endpoints.copy()
            random.shuffle(shuffled)
            return shuffled
        
        elif strategy == LoadBalancingStrategy.IP_HASH:
            # Simple hash-based selection (would need client IP in real implementation)
            return sorted(endpoints, key=lambda ep: hash(ep.endpoint.url))
        
        else:
            return endpoints
    
    async def _make_endpoint_request(self, endpoint_state: ServiceEndpointState,
                                   path: str, method: str, data: Any,
                                   headers: Dict[str, str], params: Dict[str, str],
                                   timeout: int) -> APIResponse:
        """Make HTTP request to specific endpoint."""
        try:
            # Get connection pool for endpoint
            pool_key = f"{endpoint_state.endpoint.protocol}://{endpoint_state.endpoint.url}"
            session = self.connection_pools.get(pool_key)
            
            if not session:
                # Create new session for this endpoint
                session = await self._create_session_for_endpoint(endpoint_state.endpoint)
                self.connection_pools[pool_key] = session
            
            # Build full URL
            url = f"{endpoint_state.endpoint.protocol}://{endpoint_state.endpoint.url}:{endpoint_state.endpoint.port}{path}"
            
            # Track connection
            self.active_connections[pool_key] += 1
            endpoint_state.connection_count += 1
            endpoint_state.last_used = datetime.utcnow()
            
            try:
                # Make HTTP request
                async with session.request(
                    method=method,
                    url=url,
                    headers=headers,
                    params=params,
                    json=data if data and headers.get('Content-Type') == 'application/json' else None,
                    data=data if data and headers.get('Content-Type') != 'application/json' else None,
                    timeout=aiohttp.ClientTimeout(total=timeout)
                ) as response:
                    
                    # Read response data
                    response_data = await response.text()
                    
                    # Create API response
                    api_response = APIResponse(
                        status_code=response.status,
                        headers=dict(response.headers),
                        data=response_data,
                        response_time=0.0,  # Will be set by caller
                        correlation_id=headers.get('X-Correlation-ID', '')
                    )
                    
                    return api_response
                    
            finally:
                # Release connection
                self.active_connections[pool_key] -= 1
                endpoint_state.connection_count -= 1
                
        except Exception as e:
            self.logger.error(f"HTTP request failed to {endpoint_state.endpoint.url}: {e}")
            raise
    
    async def _create_session_for_endpoint(self, endpoint: ServiceEndpoint) -> aiohttp.ClientSession:
        """Create HTTP session for endpoint."""
        # Configure SSL context based on protocol
        ssl_context = None
        if endpoint.protocol == 'https':
            ssl_context = ssl.create_default_context()
        
        # Create connector with connection limits
        connector = aiohttp.TCPConnector(
            limit=self.config.connection_pool_size,
            limit_per_host=endpoint.max_connections,
            ttl_dns_cache=300,
            use_dns_cache=True,
            ssl=ssl_context
        )
        
        # Create session
        timeout = aiohttp.ClientTimeout(total=self.config.request_timeout_seconds)
        session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout
        )
        
        return session
    
    async def _update_endpoint_success(self, endpoint_state: ServiceEndpointState, response_time: float) -> None:
        """Update endpoint state after successful request."""
        try:
            endpoint_state.success_count += 1
            endpoint_state.last_success = datetime.utcnow()
            endpoint_state.response_times.append(response_time)
            
            # Improve weight on success
            endpoint_state.weight = min(endpoint_state.weight * 1.1, 2.0)
            
            # Reset circuit breaker on success
            circuit_breaker_key = f"{endpoint_state.service_id}:{endpoint_state.endpoint.url}"
            if circuit_breaker_key in self.circuit_breakers:
                self.circuit_breakers[circuit_breaker_key]['failure_count'] = 0
                
        except Exception as e:
            self.logger.error(f"Failed to update endpoint success state: {e}")
    
    async def _update_endpoint_failure(self, endpoint_state: ServiceEndpointState, error: str) -> None:
        """Update endpoint state after failed request."""
        try:
            endpoint_state.failure_count += 1
            endpoint_state.last_failure = datetime.utcnow()
            
            # Degrade weight on failure
            endpoint_state.weight = max(endpoint_state.weight * 0.9, 0.1)
            
            # Update circuit breaker
            circuit_breaker_key = f"{endpoint_state.service_id}:{endpoint_state.endpoint.url}"
            if circuit_breaker_key not in self.circuit_breakers:
                self.circuit_breakers[circuit_breaker_key] = {
                    'failure_count': 0,
                    'last_failure_time': None,
                    'state': 'closed'
                }
            
            circuit_breaker = self.circuit_breakers[circuit_breaker_key]
            circuit_breaker['failure_count'] += 1
            circuit_breaker['last_failure_time'] = datetime.utcnow()
            
            # Open circuit breaker if threshold reached
            if circuit_breaker['failure_count'] >= 5:  # Configurable threshold
                circuit_breaker['state'] = 'open'
                
        except Exception as e:
            self.logger.error(f"Failed to update endpoint failure state: {e}")
    
    def _is_circuit_breaker_open(self, service_id: str, endpoint_url: str) -> bool:
        """Check if circuit breaker is open for endpoint."""
        circuit_breaker_key = f"{service_id}:{endpoint_url}"
        circuit_breaker = self.circuit_breakers.get(circuit_breaker_key)
        
        if not circuit_breaker:
            return False
        
        if circuit_breaker['state'] == 'open':
            # Check if timeout has passed
            if circuit_breaker['last_failure_time']:
                time_since_failure = (datetime.utcnow() - circuit_breaker['last_failure_time']).total_seconds()
                if time_since_failure > 60:  # 60 second timeout
                    circuit_breaker['state'] = 'half-open'
                    return False
            return True
        
        return False
    
    async def _initialize_connection_pools(self) -> None:
        """Initialize HTTP connection pools."""
        # Connection pools will be created on-demand for each endpoint
        pass
    
    async def _refresh_cache_periodically(self) -> None:
        """Background task to refresh service cache."""
        while True:
            try:
                await asyncio.sleep(self.config.refresh_interval_seconds)
                
                # Refresh cached services based on policy
                current_time = datetime.utcnow()
                
                for cache_key, cached_service in list(self.service_cache.items()):
                    # Check if refresh is needed
                    time_since_refresh = (current_time - cached_service.last_refresh).total_seconds()
                    
                    if time_since_refresh > self.config.refresh_interval_seconds:
                        await self._refresh_cached_service(cache_key)
                
            except Exception as e:
                self.logger.error(f"Error in cache refresh task: {e}")
    
    async def _refresh_cached_service(self, cache_key: str) -> None:
        """Refresh a specific cached service."""
        try:
            async with self.cache_locks[cache_key]:
                cached_service = self.service_cache.get(cache_key)
                if not cached_service:
                    return
                
                # Parse cache key to extract discovery parameters
                parts = cache_key.split(':')
                service_name = parts[0]
                classification = SecurityClassification(parts[1]) if len(parts) > 1 else None
                environment = APIGatewayEnvironment(parts[2]) if len(parts) > 2 else None
                version = parts[3] if len(parts) > 3 else None
                
                # Query registry for fresh data
                fresh_endpoints = await self._query_registry(service_name, classification, environment, version)
                
                if fresh_endpoints:
                    cached_service.endpoints = fresh_endpoints
                    cached_service.last_refresh = datetime.utcnow()
                
        except Exception as e:
            self.logger.error(f"Failed to refresh cached service {cache_key}: {e}")
    
    async def _calculate_metrics_periodically(self) -> None:
        """Background task to calculate metrics."""
        while True:
            try:
                await asyncio.sleep(60)  # Calculate every minute
                
                # Calculate cache hit ratio
                total_requests = self.metrics.cache_hits + self.metrics.cache_misses
                if total_requests > 0:
                    cache_hit_ratio = self.metrics.cache_hits / total_requests
                    self.logger.debug(f"Cache hit ratio: {cache_hit_ratio:.2%}")
                
            except Exception as e:
                self.logger.error(f"Error in metrics calculation: {e}")
    
    async def _cleanup_expired_cache(self) -> None:
        """Background task to clean up expired cache entries."""
        while True:
            try:
                await asyncio.sleep(300)  # Clean up every 5 minutes
                
                current_time = datetime.utcnow()
                expired_keys = []
                
                for cache_key, cached_service in self.service_cache.items():
                    # Check if cache entry has expired
                    if self.config.cache_policy == CachePolicy.TTL_BASED:
                        if (current_time - cached_service.cache_time).total_seconds() > cached_service.ttl_seconds * 2:
                            expired_keys.append(cache_key)
                    
                    elif self.config.cache_policy == CachePolicy.USAGE_BASED:
                        # Remove entries that haven't been accessed recently
                        if cached_service.last_access:
                            if (current_time - cached_service.last_access).total_seconds() > 3600:  # 1 hour
                                expired_keys.append(cache_key)
                
                # Remove expired entries
                for key in expired_keys:
                    del self.service_cache[key]
                    if key in self.cache_locks:
                        del self.cache_locks[key]
                
                if expired_keys:
                    self.logger.info(f"Cleaned up {len(expired_keys)} expired cache entries")
                
            except Exception as e:
                self.logger.error(f"Error in cache cleanup: {e}")
    
    async def _evict_cache_entries(self) -> None:
        """Evict cache entries when cache is full."""
        try:
            # Implement LRU eviction
            if len(self.service_cache) <= self.config.max_cached_services:
                return
            
            # Sort by last access time
            sorted_entries = sorted(
                self.service_cache.items(),
                key=lambda x: x[1].last_access or datetime.min
            )
            
            # Remove oldest entries
            entries_to_remove = len(self.service_cache) - self.config.max_cached_services + 10
            
            for i in range(entries_to_remove):
                if i < len(sorted_entries):
                    cache_key = sorted_entries[i][0]
                    del self.service_cache[cache_key]
                    if cache_key in self.cache_locks:
                        del self.cache_locks[cache_key]
            
        except Exception as e:
            self.logger.error(f"Failed to evict cache entries: {e}")
    
    async def _get_cache_status(self, service_name: str) -> Dict[str, Any]:
        """Get cache status for a service."""
        try:
            matching_entries = {k: v for k, v in self.service_cache.items() if service_name in k}
            
            return {
                'cached_variants': len(matching_entries),
                'total_cache_size': len(self.service_cache),
                'cache_hit_ratio': self.metrics.cache_hits / (self.metrics.cache_hits + self.metrics.cache_misses) if (self.metrics.cache_hits + self.metrics.cache_misses) > 0 else 0
            }
            
        except Exception as e:
            self.logger.error(f"Failed to get cache status: {e}")
            return {}
    
    def _update_average(self, current_avg: float, new_value: float, count: int) -> float:
        """Update running average."""
        if count <= 1:
            return new_value
        return ((current_avg * (count - 1)) + new_value) / count
    
    async def _log_discovery(self, service_name: str, endpoints_count: int, discovery_time: float) -> None:
        """Log service discovery event."""
        try:
            await self.audit_logger.log_event(
                event_type="service_discovery",
                user_id="discovery_client",
                resource_id=service_name,
                details={
                    'endpoints_found': endpoints_count,
                    'discovery_time': discovery_time,
                    'cache_status': 'hit' if endpoints_count > 0 else 'miss'
                }
            )
        except Exception as e:
            self.logger.error(f"Failed to log discovery event: {e}")
    
    async def _log_request_success(self, service_name: str, endpoint_state: ServiceEndpointState, request_time: float) -> None:
        """Log successful request."""
        try:
            await self.audit_logger.log_event(
                event_type="service_request_success",
                user_id="discovery_client",
                resource_id=service_name,
                details={
                    'endpoint_url': endpoint_state.endpoint.url,
                    'response_time': request_time,
                    'service_id': endpoint_state.service_id
                }
            )
        except Exception as e:
            self.logger.error(f"Failed to log request success: {e}")
    
    async def _log_request_failure(self, service_name: str, error: Exception) -> None:
        """Log request failure."""
        try:
            await self.audit_logger.log_event(
                event_type="service_request_failure",
                user_id="discovery_client",
                resource_id=service_name,
                details={
                    'error': str(error),
                    'error_type': type(error).__name__
                }
            )
        except Exception as e:
            self.logger.error(f"Failed to log request failure: {e}")
    
    async def close(self) -> None:
        """Clean up resources."""
        try:
            # Cancel background tasks
            if self._cache_refresh_task:
                self._cache_refresh_task.cancel()
            if self._metrics_task:
                self._metrics_task.cancel()
            if self._cleanup_task:
                self._cleanup_task.cancel()
            
            # Close all connection pools
            for session in self.connection_pools.values():
                await session.close()
            
            # Close audit logger
            if self.audit_logger:
                await self.audit_logger.close()
            
            self.logger.info("Discovery Client closed")
            
        except Exception as e:
            self.logger.error(f"Error closing discovery client: {e}")


# Configuration factories
def create_production_discovery_config() -> DiscoveryConfig:
    """Create production discovery client configuration."""
    return DiscoveryConfig(
        strategy=DiscoveryStrategy.HYBRID,
        cache_policy=CachePolicy.ADAPTIVE,
        cache_ttl_seconds=300,
        refresh_interval_seconds=60,
        max_cached_services=1000,
        enable_health_filtering=True,
        enable_load_balancing=True,
        default_load_balancing=LoadBalancingStrategy.LEAST_RESPONSE_TIME,
        connection_pool_size=100,
        request_timeout_seconds=30,
        max_retries=3,
        retry_backoff_factor=2.0
    )


def create_development_discovery_config() -> DiscoveryConfig:
    """Create development discovery client configuration."""
    return DiscoveryConfig(
        strategy=DiscoveryStrategy.CACHE_FIRST,
        cache_policy=CachePolicy.TTL_BASED,
        cache_ttl_seconds=600,
        refresh_interval_seconds=120,
        max_cached_services=100,
        enable_health_filtering=False,
        enable_load_balancing=True,
        default_load_balancing=LoadBalancingStrategy.ROUND_ROBIN,
        connection_pool_size=50,
        request_timeout_seconds=60,
        max_retries=1,
        retry_backoff_factor=1.5
    )


if __name__ == "__main__":
    # Example usage
    import statistics
    import ssl
    
    async def main():
        # Initialize components
        from api_gateway.service_registry import ServiceRegistry
        from api_gateway.health_monitor import HealthMonitor
        
        registry = ServiceRegistry()
        await registry.initialize()
        
        health_monitor = HealthMonitor(registry)
        await health_monitor.initialize()
        
        # Create discovery client
        config = create_development_discovery_config()
        client = DiscoveryClient(registry, health_monitor, config)
        await client.initialize()
        
        # Example service discovery
        endpoints = await client.discover_service("data-processing-service")
        print(f"Found {len(endpoints)} endpoints")
        
        # Example request
        if endpoints:
            response = await client.make_request(
                service_name="data-processing-service",
                path="/api/v1/data",
                method="GET"
            )
            if response:
                print(f"Request successful: {response.status_code}")
            else:
                print("Request failed")
        
        # Get service info
        service_info = await client.get_service_info("data-processing-service")
        if service_info:
            print(f"Service info: {json.dumps(service_info, indent=2)}")
        
        # Get metrics
        metrics = await client.get_metrics()
        print(f"Discovery metrics: {metrics}")
        
        await client.close()
        await health_monitor.close()
        await registry.close()
    
    asyncio.run(main())