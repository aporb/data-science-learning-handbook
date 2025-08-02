"""
Isolated Penetration Testing Environment
=======================================

Comprehensive isolated testing environment that leverages existing security
infrastructure while maintaining strict isolation for security testing activities.

Key Features:
- Docker-based isolated testing containers
- Network segmentation and security controls
- Resource allocation and monitoring
- Environment lifecycle management
- Multi-classification support for different security levels
- Integration with existing monitoring and audit systems

Classification: UNCLASSIFIED//FOR OFFICIAL USE ONLY
Version: 1.0 - Isolated Testing Environment
Author: Security Testing Team
Date: 2025-07-28
"""

import asyncio
import json
import logging
import time
import docker
import subprocess
import ipaddress
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Tuple, Set, Union
from uuid import UUID, uuid4
from dataclasses import dataclass, field, asdict
from enum import Enum
from collections import defaultdict
from pathlib import Path
import yaml

# Optional imports for production use
try:
    from ..monitoring.cac_piv_security_monitor import CACPIVSecurityMonitor
    from ..audits.audit_logger import AuditLogger
    from ..multi_classification.enhanced_classification_engine import EnhancedClassificationEngine
    MONITORING_AVAILABLE = True
except ImportError:
    MONITORING_AVAILABLE = False

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

logger = logging.getLogger(__name__)

class EnvironmentStatus(Enum):
    """Environment lifecycle states"""
    CREATING = "creating"
    RUNNING = "running"
    STOPPED = "stopped"
    DESTROYING = "destroying"
    ERROR = "error"
    ISOLATED = "isolated"

class SecurityLevel(Enum):
    """Security classification levels"""
    UNCLASSIFIED = "unclassified"
    CUI = "cui"
    CONFIDENTIAL = "confidential"
    SECRET = "secret"
    TOP_SECRET = "top_secret"

class NetworkIsolationType(Enum):
    """Network isolation types"""
    COMPLETE_ISOLATION = "complete_isolation"
    CONTROLLED_ACCESS = "controlled_access"
    MONITORED_ACCESS = "monitored_access"
    SIMULATION_ONLY = "simulation_only"

@dataclass
class ResourceLimits:
    """Resource allocation limits for testing environments"""
    cpu_cores: float = 2.0
    memory_gb: float = 4.0
    disk_gb: float = 20.0
    network_bandwidth_mbps: float = 100.0
    max_containers: int = 10
    max_duration_hours: int = 24

@dataclass
class NetworkConfiguration:
    """Network configuration for isolated environment"""
    network_name: str
    subnet: str
    gateway: str
    isolation_type: NetworkIsolationType
    allowed_outbound_hosts: List[str] = field(default_factory=list)
    allowed_inbound_ports: List[int] = field(default_factory=list)
    dns_servers: List[str] = field(default_factory=lambda: ["8.8.8.8", "8.8.4.4"])
    firewall_rules: List[Dict[str, Any]] = field(default_factory=list)

@dataclass
class TestingEnvironment:
    """Isolated testing environment configuration"""
    environment_id: str
    name: str
    security_level: SecurityLevel
    status: EnvironmentStatus
    created_at: datetime
    expires_at: datetime
    authorized_by: str
    description: str
    network_config: NetworkConfiguration
    resource_limits: ResourceLimits
    containers: List[str] = field(default_factory=list)
    volumes: List[str] = field(default_factory=list)
    networks: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

class IsolatedTestEnvironment:
    """
    Main class for managing isolated penetration testing environments.
    
    Provides comprehensive isolation, monitoring, and lifecycle management
    for security testing activities while integrating with existing
    security infrastructure.
    """
    
    def __init__(self, 
                 audit_logger: Optional[Any] = None,
                 monitoring_system: Optional[Any] = None,
                 classification_engine: Optional[Any] = None,
                 base_network_cidr: str = "172.30.0.0/16"):
        """
        Initialize isolated testing environment manager.
        
        Args:
            audit_logger: Audit logging system integration
            monitoring_system: Security monitoring system integration
            classification_engine: Multi-classification engine integration
            base_network_cidr: Base CIDR for isolated networks
        """
        self.audit_logger = audit_logger
        self.monitoring_system = monitoring_system
        self.classification_engine = classification_engine
        self.base_network_cidr = base_network_cidr
        
        # Initialize Docker client
        try:
            self.docker_client = docker.from_env()
        except Exception as e:
            logger.error(f"Failed to initialize Docker client: {e}")
            self.docker_client = None
        
        # Environment storage
        self.environments: Dict[str, TestingEnvironment] = {}
        self.network_allocations: Dict[str, str] = {}  # env_id -> subnet
        
        # Resource tracking
        self.resource_usage = {
            'total_cpu_cores': 0.0,
            'total_memory_gb': 0.0,
            'total_disk_gb': 0.0,
            'active_environments': 0
        }
        
        # Configuration
        self.config = {
            'max_environments': 50,
            'default_duration_hours': 8,
            'max_duration_hours': 72,
            'resource_monitoring_interval': 60,
            'cleanup_interval': 300,
            'network_cleanup_delay': 60
        }
        
        logger.info("Isolated Test Environment manager initialized")

    async def create_environment(self,
                                name: str,
                                security_level: SecurityLevel,
                                authorized_by: str,
                                description: str,
                                duration_hours: int = 8,
                                resource_limits: Optional[ResourceLimits] = None,
                                isolation_type: NetworkIsolationType = NetworkIsolationType.COMPLETE_ISOLATION,
                                environment_template: Optional[str] = None) -> str:
        """
        Create a new isolated testing environment.
        
        Args:
            name: Environment name
            security_level: Security classification level
            authorized_by: Authorization authority
            description: Environment description
            duration_hours: Environment lifetime in hours
            resource_limits: Resource allocation limits
            isolation_type: Network isolation type
            environment_template: Optional environment template
            
        Returns:
            Environment ID
        """
        try:
            # Generate environment ID
            environment_id = str(uuid4())
            
            # Validate duration
            if duration_hours > self.config['max_duration_hours']:
                raise ValueError(f"Duration exceeds maximum of {self.config['max_duration_hours']} hours")
            
            # Check resource availability
            if not await self._check_resource_availability(resource_limits or ResourceLimits()):
                raise ValueError("Insufficient resources available")
            
            # Allocate network subnet
            network_subnet = await self._allocate_network_subnet(environment_id)
            if not network_subnet:
                raise ValueError("Failed to allocate network subnet")
            
            # Create network configuration
            network_config = NetworkConfiguration(
                network_name=f"pentest-{environment_id[:8]}",
                subnet=network_subnet,
                gateway=str(ipaddress.IPv4Network(network_subnet).network_address + 1),
                isolation_type=isolation_type
            )
            
            # Set default resource limits
            if not resource_limits:
                resource_limits = ResourceLimits()
            
            # Create environment object
            environment = TestingEnvironment(
                environment_id=environment_id,
                name=name,
                security_level=security_level,
                status=EnvironmentStatus.CREATING,
                created_at=datetime.now(timezone.utc),
                expires_at=datetime.now(timezone.utc) + timedelta(hours=duration_hours),
                authorized_by=authorized_by,
                description=description,
                network_config=network_config,
                resource_limits=resource_limits
            )
            
            # Store environment
            self.environments[environment_id] = environment
            
            # Create Docker network
            await self._create_docker_network(environment)
            
            # Apply security classification
            if self.classification_engine:
                await self._apply_security_classification(environment)
            
            # Log environment creation
            await self._log_environment_event(
                environment_id,
                "environment_created",
                f"Isolated testing environment '{name}' created by {authorized_by}"
            )
            
            # Update environment status
            environment.status = EnvironmentStatus.RUNNING
            
            logger.info(f"Created isolated environment {environment_id} for {authorized_by}")
            
            return environment_id
            
        except Exception as e:
            logger.error(f"Failed to create environment: {e}")
            
            # Cleanup on failure
            if environment_id in self.environments:
                await self._cleanup_failed_environment(environment_id)
            
            raise

    async def deploy_container(self,
                             environment_id: str,
                             container_config: Dict[str, Any],
                             container_type: str = "testing") -> str:
        """
        Deploy a container in the isolated environment.
        
        Args:
            environment_id: Target environment ID
            container_config: Container configuration
            container_type: Type of container (testing, target, tool)
            
        Returns:
            Container ID
        """
        try:
            if environment_id not in self.environments:
                raise ValueError(f"Environment {environment_id} not found")
            
            environment = self.environments[environment_id]
            
            if environment.status != EnvironmentStatus.RUNNING:
                raise ValueError(f"Environment {environment_id} is not running")
            
            # Check resource limits
            if len(environment.containers) >= environment.resource_limits.max_containers:
                raise ValueError("Container limit reached for environment")
            
            # Configure container for isolation
            isolated_config = await self._prepare_container_config(
                environment, container_config, container_type
            )
            
            # Create container
            container = self.docker_client.containers.run(
                **isolated_config,
                detach=True,
                network=environment.network_config.network_name
            )
            
            # Add to environment
            environment.containers.append(container.id)
            
            # Apply resource limits
            await self._apply_container_limits(container, environment.resource_limits)
            
            # Log container deployment
            await self._log_environment_event(
                environment_id,
                "container_deployed",
                f"Container {container.id[:12]} deployed as {container_type}"
            )
            
            logger.info(f"Deployed container {container.id[:12]} in environment {environment_id}")
            
            return container.id
            
        except Exception as e:
            logger.error(f"Failed to deploy container: {e}")
            raise

    async def get_environment_status(self, environment_id: str) -> Dict[str, Any]:
        """
        Get comprehensive environment status.
        
        Args:
            environment_id: Environment ID
            
        Returns:
            Environment status information
        """
        try:
            if environment_id not in self.environments:
                raise ValueError(f"Environment {environment_id} not found")
            
            environment = self.environments[environment_id]
            
            # Get container statuses
            container_statuses = []
            for container_id in environment.containers:
                try:
                    container = self.docker_client.containers.get(container_id)
                    container_statuses.append({
                        'id': container_id[:12],
                        'status': container.status,
                        'created': container.attrs['Created'],
                        'image': container.image.tags[0] if container.image.tags else 'unknown'
                    })
                except Exception as e:
                    container_statuses.append({
                        'id': container_id[:12],
                        'status': 'error',
                        'error': str(e)
                    })
            
            # Get resource usage
            resource_usage = await self._get_environment_resource_usage(environment_id)
            
            # Get network status
            network_status = await self._get_network_status(environment)
            
            # Calculate time remaining
            time_remaining = environment.expires_at - datetime.now(timezone.utc)
            
            status = {
                'environment_id': environment_id,
                'name': environment.name,
                'status': environment.status.value,
                'security_level': environment.security_level.value,
                'created_at': environment.created_at.isoformat(),
                'expires_at': environment.expires_at.isoformat(),
                'time_remaining_minutes': max(0, time_remaining.total_seconds() / 60),
                'authorized_by': environment.authorized_by,
                'description': environment.description,
                'containers': container_statuses,
                'resource_usage': resource_usage,
                'network_status': network_status,
                'isolation_type': environment.network_config.isolation_type.value
            }
            
            return status
            
        except Exception as e:
            logger.error(f"Failed to get environment status: {e}")
            raise

    async def destroy_environment(self, environment_id: str, force: bool = False) -> bool:
        """
        Destroy an isolated testing environment.
        
        Args:
            environment_id: Environment ID to destroy
            force: Force destruction even if not expired
            
        Returns:
            True if successful
        """
        try:
            if environment_id not in self.environments:
                raise ValueError(f"Environment {environment_id} not found")
            
            environment = self.environments[environment_id]
            
            # Check if environment has expired or force is requested
            if not force and datetime.now(timezone.utc) < environment.expires_at:
                raise ValueError("Environment has not expired and force is not specified")
            
            environment.status = EnvironmentStatus.DESTROYING
            
            # Stop and remove containers
            for container_id in environment.containers:
                try:
                    container = self.docker_client.containers.get(container_id)
                    container.stop(timeout=30)
                    container.remove()
                    logger.info(f"Removed container {container_id[:12]}")
                except Exception as e:
                    logger.warning(f"Failed to remove container {container_id[:12]}: {e}")
            
            # Remove volumes
            for volume_name in environment.volumes:
                try:
                    volume = self.docker_client.volumes.get(volume_name)
                    volume.remove()
                    logger.info(f"Removed volume {volume_name}")
                except Exception as e:
                    logger.warning(f"Failed to remove volume {volume_name}: {e}")
            
            # Remove network after delay (allow cleanup)
            await asyncio.sleep(self.config['network_cleanup_delay'])
            await self._remove_docker_network(environment)
            
            # Deallocate network subnet
            if environment_id in self.network_allocations:
                del self.network_allocations[environment_id]
            
            # Update resource usage
            self._update_resource_usage(environment, remove=True)
            
            # Log environment destruction
            await self._log_environment_event(
                environment_id,
                "environment_destroyed",
                f"Environment '{environment.name}' destroyed"
            )
            
            # Remove from storage
            del self.environments[environment_id]
            
            logger.info(f"Destroyed environment {environment_id}")
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to destroy environment: {e}")
            return False

    async def list_environments(self, include_expired: bool = False) -> List[Dict[str, Any]]:
        """
        List all testing environments.
        
        Args:
            include_expired: Include expired environments
            
        Returns:
            List of environment summaries
        """
        try:
            current_time = datetime.now(timezone.utc)
            environments = []
            
            for env_id, environment in self.environments.items():
                # Skip expired environments if not requested
                if not include_expired and current_time >= environment.expires_at:
                    continue
                
                time_remaining = environment.expires_at - current_time
                
                env_summary = {
                    'environment_id': env_id,
                    'name': environment.name,
                    'status': environment.status.value,
                    'security_level': environment.security_level.value,
                    'created_at': environment.created_at.isoformat(),
                    'expires_at': environment.expires_at.isoformat(),
                    'time_remaining_minutes': max(0, time_remaining.total_seconds() / 60),
                    'authorized_by': environment.authorized_by,
                    'container_count': len(environment.containers),
                    'isolation_type': environment.network_config.isolation_type.value
                }
                
                environments.append(env_summary)
            
            return environments
            
        except Exception as e:
            logger.error(f"Failed to list environments: {e}")
            return []

    async def cleanup_expired_environments(self) -> int:
        """
        Cleanup expired environments.
        
        Returns:
            Number of environments cleaned up
        """
        try:
            current_time = datetime.now(timezone.utc)
            cleanup_count = 0
            
            expired_environments = [
                env_id for env_id, environment in self.environments.items()
                if current_time >= environment.expires_at
            ]
            
            for env_id in expired_environments:
                try:
                    await self.destroy_environment(env_id, force=True)
                    cleanup_count += 1
                except Exception as e:
                    logger.error(f"Failed to cleanup expired environment {env_id}: {e}")
            
            if cleanup_count > 0:
                logger.info(f"Cleaned up {cleanup_count} expired environments")
            
            return cleanup_count
            
        except Exception as e:
            logger.error(f"Failed to cleanup expired environments: {e}")
            return 0

    async def get_resource_usage(self) -> Dict[str, Any]:
        """
        Get overall resource usage statistics.
        
        Returns:
            Resource usage information
        """
        try:
            # Update current usage
            await self._update_resource_usage_stats()
            
            # Get system resource information
            system_resources = {}
            if PSUTIL_AVAILABLE:
                system_resources = {
                    'system_cpu_percent': psutil.cpu_percent(),
                    'system_memory_percent': psutil.virtual_memory().percent,
                    'system_disk_percent': psutil.disk_usage('/').percent,
                    'system_load_average': psutil.getloadavg() if hasattr(psutil, 'getloadavg') else None
                }
            
            usage_stats = {
                'environments': {
                    'total_environments': len(self.environments),
                    'active_environments': len([
                        e for e in self.environments.values() 
                        if e.status == EnvironmentStatus.RUNNING
                    ]),
                    'max_environments': self.config['max_environments']
                },
                'resources': {
                    'total_cpu_cores': self.resource_usage['total_cpu_cores'],
                    'total_memory_gb': self.resource_usage['total_memory_gb'],
                    'total_disk_gb': self.resource_usage['total_disk_gb'],
                    'total_containers': sum(len(e.containers) for e in self.environments.values())
                },
                'system': system_resources,
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
            
            return usage_stats
            
        except Exception as e:
            logger.error(f"Failed to get resource usage: {e}")
            return {}

    # Private methods

    async def _check_resource_availability(self, resource_limits: ResourceLimits) -> bool:
        """Check if requested resources are available"""
        try:
            current_usage = self.resource_usage
            
            # Check CPU cores
            if (current_usage['total_cpu_cores'] + resource_limits.cpu_cores) > 16:  # Limit
                return False
            
            # Check memory
            if (current_usage['total_memory_gb'] + resource_limits.memory_gb) > 64:  # Limit
                return False
            
            # Check disk
            if (current_usage['total_disk_gb'] + resource_limits.disk_gb) > 500:  # Limit
                return False
            
            # Check environment count
            if len(self.environments) >= self.config['max_environments']:
                return False
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to check resource availability: {e}")
            return False

    async def _allocate_network_subnet(self, environment_id: str) -> Optional[str]:
        """Allocate a network subnet for the environment"""
        try:
            base_network = ipaddress.IPv4Network(self.base_network_cidr)
            
            # Find available /24 subnet
            for i in range(1, 255):  # Skip .0 network
                subnet = f"{base_network.network_address}/{24}"
                subnet_network = ipaddress.IPv4Network(subnet)
                
                # Check if subnet is already allocated
                if subnet not in self.network_allocations.values():
                    self.network_allocations[environment_id] = subnet
                    return subnet
            
            logger.error("No available network subnets")
            return None
            
        except Exception as e:
            logger.error(f"Failed to allocate network subnet: {e}")
            return None

    async def _create_docker_network(self, environment: TestingEnvironment) -> None:
        """Create Docker network for environment"""
        try:
            network_config = {
                'name': environment.network_config.network_name,
                'driver': 'bridge',
                'ipam': docker.types.IPAMConfig(
                    pool_configs=[
                        docker.types.IPAMPool(
                            subnet=environment.network_config.subnet,
                            gateway=environment.network_config.gateway
                        )
                    ]
                ),
                'options': {
                    'com.docker.network.bridge.enable_icc': 'false',  # Disable inter-container communication by default
                    'com.docker.network.bridge.enable_ip_masquerade': 'false'  # Disable masquerading for isolation
                },
                'labels': {
                    'environment_id': environment.environment_id,
                    'security_level': environment.security_level.value,
                    'isolation_type': environment.network_config.isolation_type.value,
                    'created_by': 'isolated_test_environment'
                }
            }
            
            network = self.docker_client.networks.create(**network_config)
            environment.networks.append(network.id)
            
            logger.info(f"Created network {environment.network_config.network_name} for environment {environment.environment_id}")
            
        except Exception as e:
            logger.error(f"Failed to create Docker network: {e}")
            raise

    async def _remove_docker_network(self, environment: TestingEnvironment) -> None:
        """Remove Docker network for environment"""
        try:
            network = self.docker_client.networks.get(environment.network_config.network_name)
            network.remove()
            logger.info(f"Removed network {environment.network_config.network_name}")
            
        except Exception as e:
            logger.warning(f"Failed to remove network {environment.network_config.network_name}: {e}")

    async def _prepare_container_config(self, 
                                      environment: TestingEnvironment,
                                      container_config: Dict[str, Any],
                                      container_type: str) -> Dict[str, Any]:
        """Prepare container configuration for isolation"""
        try:
            # Base isolated configuration
            isolated_config = {
                'image': container_config.get('image', 'alpine:latest'),
                'name': f"{environment.network_config.network_name}-{container_type}-{len(environment.containers)}",
                'hostname': f"{container_type}-{len(environment.containers)}",
                'environment': container_config.get('environment', {}),
                'volumes': container_config.get('volumes', {}),
                'ports': {},  # No external ports by default for isolation
                'labels': {
                    'environment_id': environment.environment_id,
                    'container_type': container_type,
                    'security_level': environment.security_level.value,
                    'created_by': 'isolated_test_environment'
                },
                'security_opt': ['no-new-privileges:true'],  # Security hardening
                'cap_drop': ['ALL'],  # Drop all capabilities by default
                'read_only': container_config.get('read_only', False),
                'tmpfs': {'/tmp': 'rw,noexec,nosuid,size=100m'},  # Secure tmp
                'ulimits': [
                    docker.types.Ulimit(name='nofile', soft=1024, hard=2048),
                    docker.types.Ulimit(name='nproc', soft=512, hard=1024)
                ]
            }
            
            # Add specific capabilities if needed
            if container_config.get('capabilities'):
                isolated_config['cap_add'] = container_config['capabilities']
            
            # Add command if specified
            if container_config.get('command'):
                isolated_config['command'] = container_config['command']
            
            # Add working directory if specified
            if container_config.get('working_dir'):
                isolated_config['working_dir'] = container_config['working_dir']
            
            return isolated_config
            
        except Exception as e:
            logger.error(f"Failed to prepare container config: {e}")
            raise

    async def _apply_container_limits(self, container, resource_limits: ResourceLimits) -> None:
        """Apply resource limits to container"""
        try:
            # Update container with resource limits
            container.update(
                cpu_quota=int(resource_limits.cpu_cores * 100000),  # CPU quota in microseconds
                cpu_period=100000,  # 100ms period
                mem_limit=f"{resource_limits.memory_gb}g",
                memswap_limit=f"{resource_limits.memory_gb}g",  # Same as memory to disable swap
                pids_limit=1024,  # Limit number of processes
                shm_size="64m"  # Limit shared memory
            )
            
            logger.info(f"Applied resource limits to container {container.id[:12]}")
            
        except Exception as e:
            logger.warning(f"Failed to apply container limits: {e}")

    async def _apply_security_classification(self, environment: TestingEnvironment) -> None:
        """Apply security classification to environment"""
        try:
            if not self.classification_engine:
                return
            
            # Classification metadata
            classification_data = {
                'environment_id': environment.environment_id,
                'security_level': environment.security_level.value,
                'classification_markings': {
                    'banner': f"{environment.security_level.value.upper()}//FOR OFFICIAL USE ONLY",
                    'portion_markings': True,
                    'dissemination_controls': []
                },
                'access_controls': {
                    'authorized_personnel': [environment.authorized_by],
                    'clearance_required': environment.security_level.value,
                    'need_to_know': True
                }
            }
            
            # Apply classification through engine
            await self.classification_engine.apply_classification(
                resource_id=environment.environment_id,
                resource_type="testing_environment",
                classification_data=classification_data
            )
            
            logger.info(f"Applied {environment.security_level.value} classification to environment {environment.environment_id}")
            
        except Exception as e:
            logger.error(f"Failed to apply security classification: {e}")

    async def _log_environment_event(self, environment_id: str, event_type: str, message: str) -> None:
        """Log environment-related events"""
        try:
            if not self.audit_logger:
                return
            
            event_data = {
                'environment_id': environment_id,
                'event_type': event_type,
                'message': message,
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'component': 'isolated_test_environment'
            }
            
            await self.audit_logger.log_event(
                event_type="ENVIRONMENT_MANAGEMENT",
                severity="INFO",
                resource_type="testing_environment",
                resource_id=environment_id,
                action=event_type,
                additional_data=event_data
            )
            
        except Exception as e:
            logger.error(f"Failed to log environment event: {e}")

    async def _get_environment_resource_usage(self, environment_id: str) -> Dict[str, Any]:
        """Get resource usage for specific environment"""
        try:
            if environment_id not in self.environments:
                return {}
            
            environment = self.environments[environment_id]
            
            # Get container resource usage
            total_cpu_usage = 0.0
            total_memory_usage = 0.0
            container_stats = []
            
            for container_id in environment.containers:
                try:
                    container = self.docker_client.containers.get(container_id)
                    stats = container.stats(stream=False)
                    
                    # Calculate CPU usage percentage
                    cpu_usage = 0.0
                    if 'cpu_stats' in stats and 'precpu_stats' in stats:
                        cpu_stats = stats['cpu_stats']
                        precpu_stats = stats['precpu_stats']
                        
                        cpu_delta = cpu_stats['cpu_usage']['total_usage'] - precpu_stats['cpu_usage']['total_usage']
                        system_delta = cpu_stats['system_cpu_usage'] - precpu_stats['system_cpu_usage']
                        
                        if system_delta > 0:
                            cpu_usage = (cpu_delta / system_delta) * len(cpu_stats['cpu_usage']['percpu_usage']) * 100.0
                    
                    # Calculate memory usage
                    memory_usage = 0.0
                    if 'memory_stats' in stats:
                        memory_usage = stats['memory_stats'].get('usage', 0) / (1024 * 1024 * 1024)  # GB
                    
                    total_cpu_usage += cpu_usage
                    total_memory_usage += memory_usage
                    
                    container_stats.append({
                        'container_id': container_id[:12],
                        'cpu_usage_percent': cpu_usage,
                        'memory_usage_gb': memory_usage
                    })
                    
                except Exception as e:
                    logger.warning(f"Failed to get stats for container {container_id[:12]}: {e}")
            
            return {
                'total_cpu_usage_percent': total_cpu_usage,
                'total_memory_usage_gb': total_memory_usage,
                'container_count': len(environment.containers),
                'containers': container_stats,
                'resource_limits': {
                    'cpu_cores': environment.resource_limits.cpu_cores,
                    'memory_gb': environment.resource_limits.memory_gb,
                    'disk_gb': environment.resource_limits.disk_gb
                }
            }
            
        except Exception as e:
            logger.error(f"Failed to get environment resource usage: {e}")
            return {}

    async def _get_network_status(self, environment: TestingEnvironment) -> Dict[str, Any]:
        """Get network status for environment"""
        try:
            network = self.docker_client.networks.get(environment.network_config.network_name)
            
            # Get connected containers
            connected_containers = []
            for container_id, container_info in network.attrs.get('Containers', {}).items():
                connected_containers.append({
                    'container_id': container_id[:12],
                    'ip_address': container_info.get('IPv4Address', '').split('/')[0],
                    'mac_address': container_info.get('MacAddress', '')
                })
            
            return {
                'network_name': environment.network_config.network_name,
                'subnet': environment.network_config.subnet,
                'gateway': environment.network_config.gateway,
                'isolation_type': environment.network_config.isolation_type.value,
                'connected_containers': connected_containers,
                'network_id': network.id[:12]
            }
            
        except Exception as e:
            logger.error(f"Failed to get network status: {e}")
            return {}

    async def _update_resource_usage_stats(self) -> None:
        """Update overall resource usage statistics"""
        try:
            total_cpu = 0.0
            total_memory = 0.0
            total_disk = 0.0
            
            for environment in self.environments.values():
                if environment.status == EnvironmentStatus.RUNNING:
                    total_cpu += environment.resource_limits.cpu_cores
                    total_memory += environment.resource_limits.memory_gb
                    total_disk += environment.resource_limits.disk_gb
            
            self.resource_usage.update({
                'total_cpu_cores': total_cpu,
                'total_memory_gb': total_memory,
                'total_disk_gb': total_disk,
                'active_environments': len([
                    e for e in self.environments.values() 
                    if e.status == EnvironmentStatus.RUNNING
                ])
            })
            
        except Exception as e:
            logger.error(f"Failed to update resource usage stats: {e}")

    def _update_resource_usage(self, environment: TestingEnvironment, remove: bool = False) -> None:
        """Update resource usage tracking"""
        try:
            multiplier = -1 if remove else 1
            
            self.resource_usage['total_cpu_cores'] += environment.resource_limits.cpu_cores * multiplier
            self.resource_usage['total_memory_gb'] += environment.resource_limits.memory_gb * multiplier
            self.resource_usage['total_disk_gb'] += environment.resource_limits.disk_gb * multiplier
            
            if remove:
                self.resource_usage['active_environments'] = max(0, self.resource_usage['active_environments'] - 1)
            else:
                self.resource_usage['active_environments'] += 1
                
        except Exception as e:
            logger.warning(f"Failed to update resource usage: {e}")

    async def _cleanup_failed_environment(self, environment_id: str) -> None:
        """Cleanup environment that failed to create"""
        try:
            if environment_id in self.environments:
                environment = self.environments[environment_id]
                environment.status = EnvironmentStatus.ERROR
                
                # Try to remove any created resources
                await self.destroy_environment(environment_id, force=True)
                
        except Exception as e:
            logger.error(f"Failed to cleanup failed environment: {e}")


def create_isolated_test_environment(audit_logger=None, 
                                   monitoring_system=None, 
                                   classification_engine=None,
                                   base_network_cidr="172.30.0.0/16"):
    """
    Factory function to create an IsolatedTestEnvironment instance.
    
    Args:
        audit_logger: Audit logging system integration
        monitoring_system: Security monitoring system integration
        classification_engine: Multi-classification engine integration
        base_network_cidr: Base CIDR for isolated networks
        
    Returns:
        IsolatedTestEnvironment instance
    """
    return IsolatedTestEnvironment(
        audit_logger=audit_logger,
        monitoring_system=monitoring_system,
        classification_engine=classification_engine,
        base_network_cidr=base_network_cidr
    )


# Example usage
if __name__ == "__main__":
    async def example_usage():
        """Example usage of the isolated test environment"""
        
        # Create environment manager
        env_manager = create_isolated_test_environment()
        
        # Create an isolated environment
        env_id = await env_manager.create_environment(
            name="Penetration Test Environment",
            security_level=SecurityLevel.CUI,
            authorized_by="Security Team",
            description="Isolated environment for web application penetration testing",
            duration_hours=8,
            isolation_type=NetworkIsolationType.COMPLETE_ISOLATION
        )
        
        print(f"Created environment: {env_id}")
        
        # Deploy a Kali Linux container
        kali_config = {
            'image': 'kalilinux/kali-rolling:latest',
            'command': '/bin/bash',
            'environment': {
                'DISPLAY': ':1.0'
            },
            'capabilities': ['NET_ADMIN', 'SYS_ADMIN'],  # Required for some penetration testing tools
            'volumes': {
                '/tmp/.X11-unix': {'bind': '/tmp/.X11-unix', 'mode': 'rw'}
            }
        }
        
        container_id = await env_manager.deploy_container(
            env_id, kali_config, "penetration_testing"
        )
        
        print(f"Deployed Kali Linux container: {container_id[:12]}")
        
        # Get environment status
        status = await env_manager.get_environment_status(env_id)
        print(f"Environment status: {status}")
        
        # List all environments
        environments = await env_manager.list_environments()
        print(f"Active environments: {len(environments)}")
        
        # Get resource usage
        usage = await env_manager.get_resource_usage()
        print(f"Resource usage: {usage}")
    
    # Run example
    asyncio.run(example_usage())