"""
DoD API Gateway Service Registry

This module implements a comprehensive service registration and discovery system
for DoD API Gateway environments with support for service metadata, versioning,
security classification handling, and health monitoring integration.

Key Features:
- Service registration with comprehensive metadata
- Dynamic service discovery with load balancing
- Security classification-aware routing
- Service versioning and lifecycle management
- Health status integration and failover support
- Audit logging and compliance tracking
- Real-time service topology monitoring

Security Standards:
- NIST 800-53 service registry controls
- DoD 8500 series compliance for service discovery
- FIPS 140-2 data encryption for service metadata
- STIGs compliance for service management
"""

import asyncio
import json
import time
import uuid
import logging
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple, Set, Union
from dataclasses import dataclass, asdict, field
from enum import Enum
from collections import defaultdict
import ipaddress

import aioredis
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Import from existing modules
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from api_gateway.dod_api_gateway import SecurityClassification, APIGatewayEnvironment
from audits.audit_logger import AuditLogger
from monitoring.security_alerting import SecurityAlertingSystem


class ServiceStatus(Enum):
    """Service status enumeration."""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    MAINTENANCE = "maintenance"
    UNKNOWN = "unknown"


class ServiceType(Enum):
    """Service type classification."""
    API = "api"
    MICROSERVICE = "microservice"
    DATABASE = "database"
    CACHE = "cache"
    QUEUE = "queue"
    STORAGE = "storage"
    COMPUTE = "compute"
    EXTERNAL = "external"


class LoadBalancingStrategy(Enum):
    """Load balancing strategies."""
    ROUND_ROBIN = "round_robin"
    LEAST_CONNECTIONS = "least_connections"
    WEIGHTED_ROUND_ROBIN = "weighted_round_robin"
    IP_HASH = "ip_hash"
    LEAST_RESPONSE_TIME = "least_response_time"
    RANDOM = "random"


class RegistrationPolicy(Enum):
    """Service registration policies."""
    OPEN = "open"
    APPROVAL_REQUIRED = "approval_required"
    WHITELIST_ONLY = "whitelist_only"
    CLASSIFIED_ONLY = "classified_only"


@dataclass
class ServiceEndpoint:
    """Service endpoint definition."""
    url: str
    protocol: str
    port: int
    path: str = "/"
    is_primary: bool = True
    weight: int = 100
    max_connections: int = 1000
    timeout_seconds: int = 30


@dataclass
class ServiceMetadata:
    """Extended service metadata."""
    service_id: str
    service_name: str
    service_type: ServiceType
    version: str
    description: str
    endpoints: List[ServiceEndpoint]
    security_classification: SecurityClassification
    environment: APIGatewayEnvironment
    owner: str
    contact_email: str
    documentation_url: Optional[str] = None
    api_spec_url: Optional[str] = None
    dependencies: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    capabilities: Dict[str, Any] = field(default_factory=dict)
    sla_requirements: Dict[str, Any] = field(default_factory=dict)
    compliance_info: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ServiceRegistration:
    """Complete service registration."""
    metadata: ServiceMetadata
    registration_time: datetime
    last_heartbeat: datetime
    status: ServiceStatus
    health_check_url: Optional[str] = None
    heartbeat_interval: int = 30
    ttl_seconds: int = 300
    registration_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    encrypted_config: Optional[str] = None


@dataclass
class ServiceDiscoveryQuery:
    """Service discovery query parameters."""
    service_name: Optional[str] = None
    service_type: Optional[ServiceType] = None
    version_pattern: Optional[str] = None
    classification: Optional[SecurityClassification] = None
    environment: Optional[APIGatewayEnvironment] = None
    tags: List[str] = field(default_factory=list)
    capabilities: Dict[str, Any] = field(default_factory=dict)
    exclude_unhealthy: bool = True
    max_results: int = 100


@dataclass
class LoadBalancerConfig:
    """Load balancer configuration."""
    strategy: LoadBalancingStrategy
    health_check_enabled: bool = True
    sticky_sessions: bool = False
    circuit_breaker_enabled: bool = True
    failover_enabled: bool = True
    retry_attempts: int = 3
    timeout_seconds: int = 30


class ServiceRegistry:
    """
    DoD API Gateway Service Registry
    
    Comprehensive service registration and discovery system with security
    classification handling, load balancing, and health monitoring integration.
    """
    
    def __init__(self, redis_url: str = "redis://localhost:6379", 
                 encryption_key: Optional[bytes] = None):
        """Initialize service registry."""
        self.logger = logging.getLogger(__name__)
        
        # Redis client for service data storage
        self.redis_client = None
        self.redis_url = redis_url
        
        # Encryption for sensitive service data
        if encryption_key:
            self.cipher_suite = Fernet(encryption_key)
        else:
            # Generate a key for this instance (in production, use external key management)
            key = Fernet.generate_key()
            self.cipher_suite = Fernet(key)
            self.logger.warning("Using generated encryption key - use external key management in production")
        
        # Service registry state
        self.registered_services: Dict[str, ServiceRegistration] = {}
        self.service_topology: Dict[str, Set[str]] = defaultdict(set)
        
        # Load balancing state
        self.load_balancer_configs: Dict[str, LoadBalancerConfig] = {}
        self.connection_counts: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
        self.response_times: Dict[str, Dict[str, List[float]]] = defaultdict(lambda: defaultdict(list))
        
        # Registration policies
        self.registration_policy = RegistrationPolicy.APPROVAL_REQUIRED
        self.whitelisted_services: Set[str] = set()
        self.pending_approvals: Dict[str, ServiceRegistration] = {}
        
        # Integration components
        self.audit_logger = None
        self.alerting_system = None
        
        # Background tasks
        self._cleanup_task = None
        self._health_check_task = None
        
    async def initialize(self) -> None:
        """Initialize service registry."""
        try:
            # Initialize Redis client
            self.redis_client = await aioredis.from_url(self.redis_url)
            
            # Test Redis connection
            await self.redis_client.ping()
            
            # Initialize audit logging
            self.audit_logger = AuditLogger()
            await self.audit_logger.initialize()
            
            # Initialize alerting system
            self.alerting_system = SecurityAlertingSystem()
            await self.alerting_system.initialize()
            
            # Load existing registrations from Redis
            await self._load_existing_registrations()
            
            # Start background tasks
            self._cleanup_task = asyncio.create_task(self._cleanup_expired_services())
            self._health_check_task = asyncio.create_task(self._periodic_health_checks())
            
            self.logger.info("Service Registry initialized successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize service registry: {e}")
            raise
    
    async def register_service(self, metadata: ServiceMetadata, 
                             health_check_url: Optional[str] = None,
                             heartbeat_interval: int = 30,
                             ttl_seconds: int = 300) -> str:
        """
        Register a service with the registry.
        
        Args:
            metadata: Complete service metadata
            health_check_url: URL for health checks
            heartbeat_interval: Heartbeat interval in seconds
            ttl_seconds: Time-to-live for registration
            
        Returns:
            Registration ID
        """
        try:
            # Validate metadata
            self._validate_service_metadata(metadata)
            
            # Check registration policy
            if not await self._check_registration_policy(metadata):
                raise ValueError(f"Service registration denied by policy: {self.registration_policy.value}")
            
            # Create service registration
            registration = ServiceRegistration(
                metadata=metadata,
                registration_time=datetime.utcnow(),
                last_heartbeat=datetime.utcnow(),
                status=ServiceStatus.UNKNOWN,
                health_check_url=health_check_url,
                heartbeat_interval=heartbeat_interval,
                ttl_seconds=ttl_seconds
            )
            
            # Encrypt sensitive configuration if needed
            if metadata.security_classification != SecurityClassification.UNCLASSIFIED:
                config_data = {
                    'endpoints': [asdict(ep) for ep in metadata.endpoints],
                    'capabilities': metadata.capabilities,
                    'compliance_info': metadata.compliance_info
                }
                registration.encrypted_config = self._encrypt_data(json.dumps(config_data))
            
            # Store registration
            if self.registration_policy == RegistrationPolicy.APPROVAL_REQUIRED:
                self.pending_approvals[registration.registration_id] = registration
                await self._notify_pending_approval(registration)
                
                # Log pending registration
                await self.audit_logger.log_event(
                    event_type="service_registration_pending",
                    user_id=metadata.owner,
                    resource_id=metadata.service_id,
                    details={
                        'service_name': metadata.service_name,
                        'version': metadata.version,
                        'classification': metadata.security_classification.value,
                        'registration_id': registration.registration_id
                    }
                )
                
                return registration.registration_id
            else:
                # Direct registration
                await self._store_registration(registration)
                return registration.registration_id
                
        except Exception as e:
            self.logger.error(f"Service registration failed: {e}")
            
            # Log registration failure
            if self.audit_logger:
                await self.audit_logger.log_event(
                    event_type="service_registration_failed",
                    user_id=metadata.owner if 'metadata' in locals() else "unknown",
                    resource_id=metadata.service_id if 'metadata' in locals() else "unknown",
                    details={'error': str(e)}
                )
            
            raise
    
    async def approve_registration(self, registration_id: str, approver_id: str) -> None:
        """Approve a pending service registration."""
        try:
            if registration_id not in self.pending_approvals:
                raise ValueError(f"No pending registration found: {registration_id}")
            
            registration = self.pending_approvals.pop(registration_id)
            await self._store_registration(registration)
            
            # Log approval
            await self.audit_logger.log_event(
                event_type="service_registration_approved",
                user_id=approver_id,
                resource_id=registration.metadata.service_id,
                details={
                    'service_name': registration.metadata.service_name,
                    'registration_id': registration_id,
                    'original_requester': registration.metadata.owner
                }
            )
            
            self.logger.info(f"Service registration approved: {registration_id}")
            
        except Exception as e:
            self.logger.error(f"Registration approval failed: {e}")
            raise
    
    async def deregister_service(self, service_id: str, user_id: str) -> None:
        """Deregister a service from the registry."""
        try:
            # Find registration
            registration = None
            for reg in self.registered_services.values():
                if reg.metadata.service_id == service_id:
                    registration = reg
                    break
            
            if not registration:
                raise ValueError(f"Service not found: {service_id}")
            
            # Remove from registry
            del self.registered_services[registration.registration_id]
            
            # Remove from Redis
            await self.redis_client.delete(f"service_reg:{registration.registration_id}")
            await self.redis_client.srem("active_services", registration.registration_id)
            
            # Update topology
            self._update_service_topology(registration.metadata, remove=True)
            
            # Log deregistration
            await self.audit_logger.log_event(
                event_type="service_deregistered",
                user_id=user_id,
                resource_id=service_id,
                details={
                    'service_name': registration.metadata.service_name,
                    'registration_id': registration.registration_id
                }
            )
            
            self.logger.info(f"Service deregistered: {service_id}")
            
        except Exception as e:
            self.logger.error(f"Service deregistration failed: {e}")
            raise
    
    async def discover_services(self, query: ServiceDiscoveryQuery) -> List[ServiceRegistration]:
        """
        Discover services based on query parameters.
        
        Args:
            query: Discovery query parameters
            
        Returns:
            List of matching service registrations
        """
        try:
            matching_services = []
            
            for registration in self.registered_services.values():
                if self._matches_query(registration, query):
                    # Decrypt configuration if needed for authorized access
                    if registration.encrypted_config:
                        decrypted_reg = await self._decrypt_registration_for_access(registration, query)
                        if decrypted_reg:
                            matching_services.append(decrypted_reg)
                    else:
                        matching_services.append(registration)
            
            # Apply result limits
            if len(matching_services) > query.max_results:
                matching_services = matching_services[:query.max_results]
            
            # Log discovery request
            await self.audit_logger.log_event(
                event_type="service_discovery",
                user_id="system",  # This should be passed in production
                resource_id="registry",
                details={
                    'query_service_name': query.service_name,
                    'query_type': query.service_type.value if query.service_type else None,
                    'results_count': len(matching_services)
                }
            )
            
            return matching_services
            
        except Exception as e:
            self.logger.error(f"Service discovery failed: {e}")
            raise
    
    async def get_service_endpoints(self, service_name: str, 
                                  load_balancer_config: Optional[LoadBalancerConfig] = None) -> List[ServiceEndpoint]:
        """
        Get load-balanced endpoints for a service.
        
        Args:
            service_name: Name of the service
            load_balancer_config: Load balancing configuration
            
        Returns:
            Ordered list of endpoints based on load balancing strategy
        """
        try:
            # Find healthy services
            query = ServiceDiscoveryQuery(
                service_name=service_name,
                exclude_unhealthy=True
            )
            
            services = await self.discover_services(query)
            
            if not services:
                raise ValueError(f"No healthy services found: {service_name}")
            
            # Get load balancer config
            if not load_balancer_config:
                load_balancer_config = self.load_balancer_configs.get(
                    service_name, 
                    LoadBalancerConfig(strategy=LoadBalancingStrategy.ROUND_ROBIN)
                )
            
            # Collect all endpoints
            all_endpoints = []
            for service in services:
                for endpoint in service.metadata.endpoints:
                    all_endpoints.append({
                        'endpoint': endpoint,
                        'service_id': service.metadata.service_id,
                        'registration_id': service.registration_id
                    })
            
            # Apply load balancing strategy
            ordered_endpoints = self._apply_load_balancing(all_endpoints, load_balancer_config)
            
            return [ep['endpoint'] for ep in ordered_endpoints]
            
        except Exception as e:
            self.logger.error(f"Failed to get service endpoints: {e}")
            raise
    
    async def update_service_health(self, service_id: str, status: ServiceStatus, 
                                  health_data: Optional[Dict[str, Any]] = None) -> None:
        """Update service health status."""
        try:
            # Find registration
            registration = None
            for reg in self.registered_services.values():
                if reg.metadata.service_id == service_id:
                    registration = reg
                    break
            
            if not registration:
                raise ValueError(f"Service not found: {service_id}")
            
            # Update status
            old_status = registration.status
            registration.status = status
            registration.last_heartbeat = datetime.utcnow()
            
            # Store updated registration
            await self._store_registration(registration)
            
            # Log status change
            if old_status != status:
                await self.audit_logger.log_event(
                    event_type="service_health_changed",
                    user_id="system",
                    resource_id=service_id,
                    details={
                        'service_name': registration.metadata.service_name,
                        'old_status': old_status.value,
                        'new_status': status.value,
                        'health_data': health_data
                    }
                )
                
                # Send alert for critical status changes
                if status in [ServiceStatus.UNHEALTHY, ServiceStatus.DEGRADED]:
                    await self.alerting_system.send_alert(
                        alert_type="service_health_degraded",
                        severity="high" if status == ServiceStatus.UNHEALTHY else "medium",
                        message=f"Service {registration.metadata.service_name} status changed to {status.value}",
                        metadata={
                            'service_id': service_id,
                            'service_name': registration.metadata.service_name,
                            'status': status.value,
                            'health_data': health_data
                        }
                    )
            
        except Exception as e:
            self.logger.error(f"Health update failed: {e}")
            raise
    
    async def heartbeat(self, service_id: str) -> None:
        """Update service heartbeat timestamp."""
        try:
            # Find registration
            registration = None
            for reg in self.registered_services.values():
                if reg.metadata.service_id == service_id:
                    registration = reg
                    break
            
            if not registration:
                raise ValueError(f"Service not found: {service_id}")
            
            # Update heartbeat
            registration.last_heartbeat = datetime.utcnow()
            
            # Store updated registration
            await self._store_registration(registration)
            
        except Exception as e:
            self.logger.error(f"Heartbeat update failed: {e}")
            raise
    
    async def get_service_topology(self) -> Dict[str, Any]:
        """Get service dependency topology."""
        try:
            topology = {
                'services': {},
                'dependencies': {},
                'clusters': {}
            }
            
            # Build service information
            for registration in self.registered_services.values():
                service_id = registration.metadata.service_id
                topology['services'][service_id] = {
                    'name': registration.metadata.service_name,
                    'type': registration.metadata.service_type.value,
                    'version': registration.metadata.version,
                    'status': registration.status.value,
                    'classification': registration.metadata.security_classification.value,
                    'endpoints_count': len(registration.metadata.endpoints),
                    'last_heartbeat': registration.last_heartbeat.isoformat()
                }
                
                # Add dependencies
                if registration.metadata.dependencies:
                    topology['dependencies'][service_id] = registration.metadata.dependencies
            
            # Group by environment and classification
            for registration in self.registered_services.values():
                env_key = f"{registration.metadata.environment.value}_{registration.metadata.security_classification.value}"
                if env_key not in topology['clusters']:
                    topology['clusters'][env_key] = []
                topology['clusters'][env_key].append(registration.metadata.service_id)
            
            return topology
            
        except Exception as e:
            self.logger.error(f"Failed to get service topology: {e}")
            raise
    
    async def get_registry_metrics(self) -> Dict[str, Any]:
        """Get service registry metrics and statistics."""
        try:
            current_time = datetime.utcnow()
            
            metrics = {
                'total_services': len(self.registered_services),
                'pending_approvals': len(self.pending_approvals),
                'services_by_status': {},
                'services_by_type': {},
                'services_by_classification': {},
                'services_by_environment': {},
                'average_response_times': {},
                'connection_counts': {},
                'unhealthy_services': [],
                'expired_services': []
            }
            
            # Aggregate metrics
            for registration in self.registered_services.values():
                # Status distribution
                status = registration.status.value
                metrics['services_by_status'][status] = metrics['services_by_status'].get(status, 0) + 1
                
                # Type distribution
                service_type = registration.metadata.service_type.value
                metrics['services_by_type'][service_type] = metrics['services_by_type'].get(service_type, 0) + 1
                
                # Classification distribution
                classification = registration.metadata.security_classification.value
                metrics['services_by_classification'][classification] = metrics['services_by_classification'].get(classification, 0) + 1
                
                # Environment distribution
                environment = registration.metadata.environment.value
                metrics['services_by_environment'][environment] = metrics['services_by_environment'].get(environment, 0) + 1
                
                # Check for unhealthy services
                if registration.status == ServiceStatus.UNHEALTHY:
                    metrics['unhealthy_services'].append({
                        'service_id': registration.metadata.service_id,
                        'service_name': registration.metadata.service_name,
                        'last_heartbeat': registration.last_heartbeat.isoformat()
                    })
                
                # Check for expired services
                if (current_time - registration.last_heartbeat).total_seconds() > registration.ttl_seconds:
                    metrics['expired_services'].append({
                        'service_id': registration.metadata.service_id,
                        'service_name': registration.metadata.service_name,
                        'last_heartbeat': registration.last_heartbeat.isoformat(),
                        'ttl_seconds': registration.ttl_seconds
                    })
            
            # Calculate average response times
            for service_name, endpoints in self.response_times.items():
                avg_times = {}
                for endpoint_url, times in endpoints.items():
                    if times:
                        avg_times[endpoint_url] = sum(times) / len(times)
                if avg_times:
                    metrics['average_response_times'][service_name] = avg_times
            
            # Copy connection counts
            metrics['connection_counts'] = dict(self.connection_counts)
            
            return metrics
            
        except Exception as e:
            self.logger.error(f"Failed to get registry metrics: {e}")
            return {}
    
    def _validate_service_metadata(self, metadata: ServiceMetadata) -> None:
        """Validate service metadata completeness and format."""
        if not metadata.service_id or not metadata.service_name:
            raise ValueError("Service ID and name are required")
        
        if not metadata.version:
            raise ValueError("Service version is required")
        
        if not metadata.endpoints:
            raise ValueError("At least one endpoint is required")
        
        if not metadata.owner or not metadata.contact_email:
            raise ValueError("Owner and contact email are required")
        
        # Validate endpoints
        for endpoint in metadata.endpoints:
            if not endpoint.url or not endpoint.protocol:
                raise ValueError("Endpoint URL and protocol are required")
            
            # Validate protocol
            if endpoint.protocol not in ['http', 'https', 'tcp', 'udp', 'grpc']:
                raise ValueError(f"Unsupported protocol: {endpoint.protocol}")
        
        # Validate security classification consistency
        if metadata.security_classification != SecurityClassification.UNCLASSIFIED:
            if metadata.environment == APIGatewayEnvironment.DEVELOPMENT:
                self.logger.warning("Classified service in development environment")
    
    async def _check_registration_policy(self, metadata: ServiceMetadata) -> bool:
        """Check if service registration is allowed by policy."""
        if self.registration_policy == RegistrationPolicy.OPEN:
            return True
        elif self.registration_policy == RegistrationPolicy.WHITELIST_ONLY:
            return metadata.service_name in self.whitelisted_services
        elif self.registration_policy == RegistrationPolicy.CLASSIFIED_ONLY:
            return metadata.security_classification != SecurityClassification.UNCLASSIFIED
        elif self.registration_policy == RegistrationPolicy.APPROVAL_REQUIRED:
            return True  # Allow registration but require approval
        
        return False
    
    async def _store_registration(self, registration: ServiceRegistration) -> None:
        """Store service registration in Redis and local cache."""
        try:
            # Store in local cache
            self.registered_services[registration.registration_id] = registration
            
            # Store in Redis
            registration_data = {
                'metadata': asdict(registration.metadata),
                'registration_time': registration.registration_time.isoformat(),
                'last_heartbeat': registration.last_heartbeat.isoformat(),
                'status': registration.status.value,
                'health_check_url': registration.health_check_url,
                'heartbeat_interval': registration.heartbeat_interval,
                'ttl_seconds': registration.ttl_seconds,
                'encrypted_config': registration.encrypted_config
            }
            
            await self.redis_client.hset(
                f"service_reg:{registration.registration_id}",
                mapping={k: json.dumps(v) for k, v in registration_data.items()}
            )
            
            # Add to active services set
            await self.redis_client.sadd("active_services", registration.registration_id)
            
            # Set TTL
            await self.redis_client.expire(
                f"service_reg:{registration.registration_id}",
                registration.ttl_seconds * 2  # Double TTL for safety
            )
            
            # Update service topology
            self._update_service_topology(registration.metadata)
            
            # Log successful registration
            await self.audit_logger.log_event(
                event_type="service_registered",
                user_id=registration.metadata.owner,
                resource_id=registration.metadata.service_id,
                details={
                    'service_name': registration.metadata.service_name,
                    'version': registration.metadata.version,
                    'registration_id': registration.registration_id,
                    'endpoints_count': len(registration.metadata.endpoints)
                }
            )
            
        except Exception as e:
            self.logger.error(f"Failed to store registration: {e}")
            raise
    
    async def _load_existing_registrations(self) -> None:
        """Load existing service registrations from Redis."""
        try:
            # Get all active service IDs
            active_services = await self.redis_client.smembers("active_services")
            
            for service_id in active_services:
                try:
                    # Load registration data
                    registration_data = await self.redis_client.hgetall(f"service_reg:{service_id}")
                    
                    if registration_data:
                        # Parse registration data
                        metadata_data = json.loads(registration_data['metadata'])
                        
                        # Reconstruct ServiceMetadata
                        endpoints = [ServiceEndpoint(**ep) for ep in metadata_data['endpoints']]
                        metadata_data['endpoints'] = endpoints
                        metadata_data['service_type'] = ServiceType(metadata_data['service_type'])
                        metadata_data['security_classification'] = SecurityClassification(metadata_data['security_classification'])
                        metadata_data['environment'] = APIGatewayEnvironment(metadata_data['environment'])
                        
                        metadata = ServiceMetadata(**metadata_data)
                        
                        # Reconstruct ServiceRegistration
                        registration = ServiceRegistration(
                            metadata=metadata,
                            registration_time=datetime.fromisoformat(json.loads(registration_data['registration_time'])),
                            last_heartbeat=datetime.fromisoformat(json.loads(registration_data['last_heartbeat'])),
                            status=ServiceStatus(json.loads(registration_data['status'])),
                            health_check_url=json.loads(registration_data.get('health_check_url', 'null')),
                            heartbeat_interval=json.loads(registration_data['heartbeat_interval']),
                            ttl_seconds=json.loads(registration_data['ttl_seconds']),
                            registration_id=service_id.decode(),
                            encrypted_config=json.loads(registration_data.get('encrypted_config', 'null'))
                        )
                        
                        # Add to local cache
                        self.registered_services[registration.registration_id] = registration
                        
                except Exception as e:
                    self.logger.error(f"Failed to load registration {service_id}: {e}")
                    # Remove invalid registration
                    await self.redis_client.srem("active_services", service_id)
                    await self.redis_client.delete(f"service_reg:{service_id}")
            
            self.logger.info(f"Loaded {len(self.registered_services)} existing service registrations")
            
        except Exception as e:
            self.logger.error(f"Failed to load existing registrations: {e}")
    
    def _update_service_topology(self, metadata: ServiceMetadata, remove: bool = False) -> None:
        """Update service dependency topology."""
        service_id = metadata.service_id
        
        if remove:
            # Remove from topology
            if service_id in self.service_topology:
                del self.service_topology[service_id]
            
            # Remove as dependency from other services
            for deps in self.service_topology.values():
                deps.discard(service_id)
        else:
            # Add dependencies
            self.service_topology[service_id] = set(metadata.dependencies)
    
    def _matches_query(self, registration: ServiceRegistration, query: ServiceDiscoveryQuery) -> bool:
        """Check if service registration matches discovery query."""
        metadata = registration.metadata
        
        # Service name match
        if query.service_name and metadata.service_name != query.service_name:
            return False
        
        # Service type match
        if query.service_type and metadata.service_type != query.service_type:
            return False
        
        # Version pattern match (simplified - could use regex)
        if query.version_pattern and query.version_pattern not in metadata.version:
            return False
        
        # Classification match
        if query.classification and metadata.security_classification != query.classification:
            return False
        
        # Environment match
        if query.environment and metadata.environment != query.environment:
            return False
        
        # Tags match (all query tags must be present)
        if query.tags and not all(tag in metadata.tags for tag in query.tags):
            return False
        
        # Capabilities match (all query capabilities must be present)
        if query.capabilities:
            for cap_name, cap_value in query.capabilities.items():
                if cap_name not in metadata.capabilities:
                    return False
                if metadata.capabilities[cap_name] != cap_value:
                    return False
        
        # Health status filter
        if query.exclude_unhealthy and registration.status in [ServiceStatus.UNHEALTHY, ServiceStatus.UNKNOWN]:
            return False
        
        return True
    
    async def _decrypt_registration_for_access(self, registration: ServiceRegistration, 
                                             query: ServiceDiscoveryQuery) -> Optional[ServiceRegistration]:
        """Decrypt registration data for authorized access."""
        try:
            # In production, implement proper authorization checks here
            # For now, return decrypted data for unclassified queries
            if query.classification == SecurityClassification.UNCLASSIFIED:
                return registration
            
            # Decrypt configuration
            if registration.encrypted_config:
                decrypted_config = self._decrypt_data(registration.encrypted_config)
                config_data = json.loads(decrypted_config)
                
                # Create a copy with decrypted data
                metadata_copy = registration.metadata
                # In a real implementation, you'd merge the decrypted config back
                
            return registration
            
        except Exception as e:
            self.logger.error(f"Failed to decrypt registration: {e}")
            return None
    
    def _encrypt_data(self, data: str) -> str:
        """Encrypt sensitive data."""
        return self.cipher_suite.encrypt(data.encode()).decode()
    
    def _decrypt_data(self, encrypted_data: str) -> str:
        """Decrypt sensitive data."""
        return self.cipher_suite.decrypt(encrypted_data.encode()).decode()
    
    def _apply_load_balancing(self, endpoints: List[Dict], config: LoadBalancerConfig) -> List[Dict]:
        """Apply load balancing strategy to endpoints."""
        if not endpoints:
            return []
        
        if config.strategy == LoadBalancingStrategy.ROUND_ROBIN:
            # Simple round-robin (in production, maintain state)
            return endpoints
        
        elif config.strategy == LoadBalancingStrategy.LEAST_CONNECTIONS:
            # Sort by connection count
            return sorted(endpoints, key=lambda ep: self.connection_counts.get(
                ep['service_id'], {}
            ).get(ep['endpoint'].url, 0))
        
        elif config.strategy == LoadBalancingStrategy.WEIGHTED_ROUND_ROBIN:
            # Sort by weight (descending)
            return sorted(endpoints, key=lambda ep: ep['endpoint'].weight, reverse=True)
        
        elif config.strategy == LoadBalancingStrategy.LEAST_RESPONSE_TIME:
            # Sort by average response time
            def get_avg_response_time(ep):
                times = self.response_times.get(ep['service_id'], {}).get(ep['endpoint'].url, [])
                return sum(times) / len(times) if times else float('inf')
            
            return sorted(endpoints, key=get_avg_response_time)
        
        elif config.strategy == LoadBalancingStrategy.RANDOM:
            import random
            random.shuffle(endpoints)
            return endpoints
        
        else:
            return endpoints
    
    async def _cleanup_expired_services(self) -> None:
        """Background task to clean up expired services."""
        while True:
            try:
                current_time = datetime.utcnow()
                expired_registrations = []
                
                for registration_id, registration in list(self.registered_services.items()):
                    time_since_heartbeat = (current_time - registration.last_heartbeat).total_seconds()
                    
                    if time_since_heartbeat > registration.ttl_seconds:
                        expired_registrations.append(registration)
                
                # Remove expired services
                for registration in expired_registrations:
                    self.logger.warning(f"Removing expired service: {registration.metadata.service_name}")
                    
                    # Remove from local cache
                    del self.registered_services[registration.registration_id]
                    
                    # Remove from Redis
                    await self.redis_client.delete(f"service_reg:{registration.registration_id}")
                    await self.redis_client.srem("active_services", registration.registration_id)
                    
                    # Update topology
                    self._update_service_topology(registration.metadata, remove=True)
                    
                    # Log expiration
                    await self.audit_logger.log_event(
                        event_type="service_expired",
                        user_id="system",
                        resource_id=registration.metadata.service_id,
                        details={
                            'service_name': registration.metadata.service_name,
                            'registration_id': registration.registration_id,
                            'ttl_seconds': registration.ttl_seconds,
                            'time_since_heartbeat': time_since_heartbeat
                        }
                    )
                
                # Sleep for cleanup interval
                await asyncio.sleep(60)  # Run every minute
                
            except Exception as e:
                self.logger.error(f"Cleanup task error: {e}")
                await asyncio.sleep(60)
    
    async def _periodic_health_checks(self) -> None:
        """Background task for periodic health checks."""
        while True:
            try:
                # Health check logic will be implemented in health_monitor.py
                # This is a placeholder for integration
                await asyncio.sleep(30)  # Run every 30 seconds
                
            except Exception as e:
                self.logger.error(f"Health check task error: {e}")
                await asyncio.sleep(30)
    
    async def _notify_pending_approval(self, registration: ServiceRegistration) -> None:
        """Notify administrators of pending service registration."""
        try:
            await self.alerting_system.send_alert(
                alert_type="service_registration_pending",
                severity="info",
                message=f"Service registration pending approval: {registration.metadata.service_name}",
                metadata={
                    'service_id': registration.metadata.service_id,
                    'service_name': registration.metadata.service_name,
                    'owner': registration.metadata.owner,
                    'registration_id': registration.registration_id,
                    'classification': registration.metadata.security_classification.value
                }
            )
        except Exception as e:
            self.logger.error(f"Failed to notify pending approval: {e}")
    
    async def close(self) -> None:
        """Clean up resources."""
        try:
            # Cancel background tasks
            if self._cleanup_task:
                self._cleanup_task.cancel()
            if self._health_check_task:
                self._health_check_task.cancel()
            
            # Close Redis connection
            if self.redis_client:
                await self.redis_client.close()
            
            # Close audit logger
            if self.audit_logger:
                await self.audit_logger.close()
            
            # Close alerting system
            if self.alerting_system:
                await self.alerting_system.close()
            
            self.logger.info("Service Registry closed")
            
        except Exception as e:
            self.logger.error(f"Error closing service registry: {e}")


# Configuration factories
def create_production_registry_config() -> Dict[str, Any]:
    """Create production service registry configuration."""
    return {
        'redis_url': 'redis://redis-cluster:6379',
        'registration_policy': RegistrationPolicy.APPROVAL_REQUIRED,
        'default_ttl_seconds': 300,
        'cleanup_interval_seconds': 60,
        'health_check_interval_seconds': 30,
        'encryption_enabled': True,
        'audit_logging_enabled': True,
        'alerting_enabled': True
    }


def create_development_registry_config() -> Dict[str, Any]:
    """Create development service registry configuration."""
    return {
        'redis_url': 'redis://localhost:6379',
        'registration_policy': RegistrationPolicy.OPEN,
        'default_ttl_seconds': 600,
        'cleanup_interval_seconds': 120,
        'health_check_interval_seconds': 60,
        'encryption_enabled': False,
        'audit_logging_enabled': True,
        'alerting_enabled': False
    }


if __name__ == "__main__":
    # Example usage
    async def main():
        registry = ServiceRegistry()
        await registry.initialize()
        
        # Example service registration
        metadata = ServiceMetadata(
            service_id="data-service-001",
            service_name="data-processing-service",
            service_type=ServiceType.API,
            version="1.0.0",
            description="Data processing microservice",
            endpoints=[
                ServiceEndpoint(
                    url="https://data-service.example.mil",
                    protocol="https",
                    port=443
                )
            ],
            security_classification=SecurityClassification.UNCLASSIFIED,
            environment=APIGatewayEnvironment.DEVELOPMENT,
            owner="data-team",
            contact_email="data-team@example.mil",
            tags=["data", "processing", "api"],
            dependencies=["database-service", "cache-service"]
        )
        
        # Register service
        registration_id = await registry.register_service(metadata)
        print(f"Service registered: {registration_id}")
        
        # Discover services
        query = ServiceDiscoveryQuery(service_name="data-processing-service")
        services = await registry.discover_services(query)
        print(f"Found {len(services)} services")
        
        # Get metrics
        metrics = await registry.get_registry_metrics()
        print(f"Registry metrics: {json.dumps(metrics, indent=2)}")
        
        await registry.close()
    
    asyncio.run(main())