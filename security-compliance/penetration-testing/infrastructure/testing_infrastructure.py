"""
Penetration Testing Infrastructure Setup
=======================================

Comprehensive testing infrastructure that integrates Kali Linux penetration
testing toolkit with custom security testing tools, target system simulation,
and network topology creation for isolated security testing.

Key Features:
- Kali Linux penetration testing toolkit integration
- Custom security testing tools deployment
- Target system simulation and deployment
- Network topology simulation
- Vulnerability scanning integration
- Tool orchestration and automation

Classification: UNCLASSIFIED//FOR OFFICIAL USE ONLY
Version: 1.0 - Testing Infrastructure
Author: Security Testing Team
Date: 2025-07-28
"""

import asyncio
import json
import logging
import time
import docker
import subprocess
import yaml
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Tuple, Set, Union
from uuid import UUID, uuid4
from dataclasses import dataclass, field, asdict
from enum import Enum
from collections import defaultdict
from pathlib import Path
import tempfile
import shutil

# Optional imports for production use
try:
    from ..environment.isolated_test_environment import IsolatedTestEnvironment, SecurityLevel
    from ..security_testing.penetration_testing_framework import PenetrationTestingFramework
    ENVIRONMENT_AVAILABLE = True
except ImportError:
    ENVIRONMENT_AVAILABLE = False

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False

logger = logging.getLogger(__name__)

class InfrastructureType(Enum):
    """Infrastructure deployment types"""
    KALI_LINUX = "kali_linux"
    TARGET_SIMULATION = "target_simulation"
    VULNERABILITY_SCANNER = "vulnerability_scanner"
    CUSTOM_TOOL = "custom_tool"
    NETWORK_SIMULATION = "network_simulation"

class TargetSystemType(Enum):
    """Target system types for testing"""
    WEB_APPLICATION = "web_application"
    DATABASE_SERVER = "database_server"
    WINDOWS_SERVER = "windows_server"
    LINUX_SERVER = "linux_server"
    NETWORK_DEVICE = "network_device"
    VULNERABLE_APP = "vulnerable_app"

class NetworkTopology(Enum):
    """Network topology types"""
    FLAT_NETWORK = "flat_network"
    SEGMENTED_NETWORK = "segmented_network"
    DMZ_NETWORK = "dmz_network"
    MULTI_TIER = "multi_tier"
    ISOLATED_VLANS = "isolated_vlans"

@dataclass
class KaliToolConfig:
    """Configuration for Kali Linux tools"""
    tool_name: str
    enabled: bool = True
    custom_config: Dict[str, Any] = field(default_factory=dict)
    resource_requirements: Dict[str, Any] = field(default_factory=dict)
    network_access_required: bool = False
    privilege_escalation_required: bool = False

@dataclass
class TargetSystemConfig:
    """Configuration for target systems"""
    system_id: str
    system_type: TargetSystemType
    name: str
    description: str
    image: str
    ports: List[int] = field(default_factory=list)
    environment_vars: Dict[str, str] = field(default_factory=dict)
    volumes: Dict[str, str] = field(default_factory=dict)
    vulnerabilities: List[str] = field(default_factory=list)
    services: List[str] = field(default_factory=list)
    custom_scripts: List[str] = field(default_factory=list)

@dataclass
class NetworkTopologyConfig:
    """Network topology configuration"""
    topology_id: str
    topology_type: NetworkTopology
    name: str
    description: str
    networks: Dict[str, str] = field(default_factory=dict)  # network_name -> subnet
    routing_rules: List[Dict[str, Any]] = field(default_factory=list)
    firewall_rules: List[Dict[str, Any]] = field(default_factory=list)
    network_services: List[str] = field(default_factory=list)

@dataclass
class InfrastructureDeployment:
    """Infrastructure deployment tracking"""
    deployment_id: str
    environment_id: str
    infrastructure_type: InfrastructureType
    name: str
    status: str
    deployed_at: datetime
    containers: List[str] = field(default_factory=list)
    volumes: List[str] = field(default_factory=list)
    networks: List[str] = field(default_factory=list)
    configuration: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)

class TestingInfrastructure:
    """
    Main class for managing penetration testing infrastructure setup.
    
    Provides comprehensive infrastructure deployment, tool configuration,
    and target system simulation for isolated security testing environments.
    """
    
    def __init__(self, 
                 environment_manager: Optional[Any] = None,
                 audit_logger: Optional[Any] = None,
                 monitoring_system: Optional[Any] = None):
        """
        Initialize testing infrastructure manager.
        
        Args:
            environment_manager: Isolated test environment manager
            audit_logger: Audit logging system integration
            monitoring_system: Security monitoring system integration
        """
        self.environment_manager = environment_manager
        self.audit_logger = audit_logger
        self.monitoring_system = monitoring_system
        
        # Initialize Docker client
        try:
            self.docker_client = docker.from_env()
        except Exception as e:
            logger.error(f"Failed to initialize Docker client: {e}")
            self.docker_client = None
        
        # Deployment tracking
        self.deployments: Dict[str, InfrastructureDeployment] = {}
        
        # Tool configurations
        self.kali_tools_config = self._get_default_kali_tools()
        self.target_systems_config = self._get_default_target_systems()
        self.network_topologies_config = self._get_default_network_topologies()
        
        # Configuration
        self.config = {
            'kali_image': 'kalilinux/kali-rolling:latest',
            'tool_update_on_deploy': True,
            'custom_tools_directory': '/opt/custom-tools',
            'shared_volume_size': '10G',
            'default_tool_timeout': 3600,
            'max_concurrent_scans': 5
        }
        
        logger.info("Testing Infrastructure manager initialized")

    async def deploy_kali_linux(self,
                               environment_id: str,
                               tools_config: Optional[List[KaliToolConfig]] = None,
                               custom_config: Optional[Dict[str, Any]] = None) -> str:
        """
        Deploy Kali Linux penetration testing environment.
        
        Args:
            environment_id: Target environment ID
            tools_config: Custom tools configuration
            custom_config: Additional configuration options
            
        Returns:
            Deployment ID
        """
        try:
            deployment_id = str(uuid4())
            
            # Prepare Kali Linux configuration
            kali_config = await self._prepare_kali_config(
                tools_config or self.kali_tools_config,
                custom_config or {}
            )
            
            # Deploy container
            container_id = await self.environment_manager.deploy_container(
                environment_id, kali_config, "kali_linux"
            )
            
            # Install and configure tools
            await self._configure_kali_tools(container_id, tools_config or self.kali_tools_config)
            
            # Create deployment record
            deployment = InfrastructureDeployment(
                deployment_id=deployment_id,
                environment_id=environment_id,
                infrastructure_type=InfrastructureType.KALI_LINUX,
                name="Kali Linux Penetration Testing",
                status="deployed",
                deployed_at=datetime.now(timezone.utc),
                containers=[container_id],
                configuration=kali_config
            )
            
            self.deployments[deployment_id] = deployment
            
            # Log deployment
            await self._log_infrastructure_event(
                deployment_id,
                "kali_deployed",
                f"Kali Linux penetration testing environment deployed"
            )
            
            logger.info(f"Deployed Kali Linux environment {deployment_id}")
            
            return deployment_id
            
        except Exception as e:
            logger.error(f"Failed to deploy Kali Linux: {e}")
            raise

    async def deploy_target_systems(self,
                                  environment_id: str,
                                  target_configs: List[TargetSystemConfig],
                                  network_topology: Optional[NetworkTopologyConfig] = None) -> str:
        """
        Deploy target systems for penetration testing.
        
        Args:
            environment_id: Target environment ID
            target_configs: Target system configurations
            network_topology: Network topology configuration
            
        Returns:
            Deployment ID
        """
        try:
            deployment_id = str(uuid4())
            deployed_containers = []
            
            # Deploy network topology if specified
            if network_topology:
                await self._deploy_network_topology(environment_id, network_topology)
            
            # Deploy each target system
            for target_config in target_configs:
                container_config = await self._prepare_target_config(target_config)
                
                container_id = await self.environment_manager.deploy_container(
                    environment_id, container_config, f"target_{target_config.system_type.value}"
                )
                
                deployed_containers.append(container_id)
                
                # Configure target system
                await self._configure_target_system(container_id, target_config)
                
                logger.info(f"Deployed target system {target_config.name} ({container_id[:12]})")
            
            # Create deployment record
            deployment = InfrastructureDeployment(
                deployment_id=deployment_id,
                environment_id=environment_id,
                infrastructure_type=InfrastructureType.TARGET_SIMULATION,
                name="Target Systems Simulation",
                status="deployed",
                deployed_at=datetime.now(timezone.utc),
                containers=deployed_containers,
                configuration={
                    'targets': [asdict(config) for config in target_configs],
                    'network_topology': asdict(network_topology) if network_topology else None
                }
            )
            
            self.deployments[deployment_id] = deployment
            
            # Log deployment
            await self._log_infrastructure_event(
                deployment_id,
                "targets_deployed",
                f"Target systems deployed: {len(target_configs)} systems"
            )
            
            logger.info(f"Deployed target systems {deployment_id}")
            
            return deployment_id
            
        except Exception as e:
            logger.error(f"Failed to deploy target systems: {e}")
            raise

    async def deploy_vulnerability_scanner(self,
                                         environment_id: str,
                                         scanner_type: str = "openvas",
                                         custom_config: Optional[Dict[str, Any]] = None) -> str:
        """
        Deploy vulnerability scanning infrastructure.
        
        Args:
            environment_id: Target environment ID
            scanner_type: Type of vulnerability scanner
            custom_config: Custom scanner configuration
            
        Returns:
            Deployment ID
        """
        try:
            deployment_id = str(uuid4())
            
            # Prepare scanner configuration
            scanner_config = await self._prepare_scanner_config(scanner_type, custom_config or {})
            
            # Deploy scanner container
            container_id = await self.environment_manager.deploy_container(
                environment_id, scanner_config, "vulnerability_scanner"
            )
            
            # Configure scanner
            await self._configure_vulnerability_scanner(container_id, scanner_type, custom_config or {})
            
            # Create deployment record
            deployment = InfrastructureDeployment(
                deployment_id=deployment_id,
                environment_id=environment_id,
                infrastructure_type=InfrastructureType.VULNERABILITY_SCANNER,
                name=f"{scanner_type.title()} Vulnerability Scanner",
                status="deployed",
                deployed_at=datetime.now(timezone.utc),
                containers=[container_id],
                configuration=scanner_config
            )
            
            self.deployments[deployment_id] = deployment
            
            # Log deployment
            await self._log_infrastructure_event(
                deployment_id,
                "scanner_deployed",
                f"{scanner_type} vulnerability scanner deployed"
            )
            
            logger.info(f"Deployed vulnerability scanner {deployment_id}")
            
            return deployment_id
            
        except Exception as e:
            logger.error(f"Failed to deploy vulnerability scanner: {e}")
            raise

    async def get_deployment_status(self, deployment_id: str) -> Dict[str, Any]:
        """
        Get deployment status and information.
        
        Args:
            deployment_id: Deployment ID
            
        Returns:
            Deployment status information
        """
        try:
            if deployment_id not in self.deployments:
                raise ValueError(f"Deployment {deployment_id} not found")
            
            deployment = self.deployments[deployment_id]
            
            # Get container statuses
            container_statuses = []
            for container_id in deployment.containers:
                try:
                    container = self.docker_client.containers.get(container_id)
                    container_statuses.append({
                        'container_id': container_id[:12],
                        'status': container.status,
                        'created': container.attrs['Created'],
                        'image': container.image.tags[0] if container.image.tags else 'unknown',
                        'ports': container.attrs.get('NetworkSettings', {}).get('Ports', {})
                    })
                except Exception as e:
                    container_statuses.append({
                        'container_id': container_id[:12],
                        'status': 'error',
                        'error': str(e)
                    })
            
            # Get tool status for Kali deployments
            tool_status = {}
            if deployment.infrastructure_type == InfrastructureType.KALI_LINUX:
                tool_status = await self._get_kali_tool_status(deployment.containers[0])
            
            status = {
                'deployment_id': deployment_id,
                'environment_id': deployment.environment_id,
                'infrastructure_type': deployment.infrastructure_type.value,
                'name': deployment.name,
                'status': deployment.status,
                'deployed_at': deployment.deployed_at.isoformat(),
                'containers': container_statuses,
                'tool_status': tool_status,
                'configuration': deployment.configuration
            }
            
            return status
            
        except Exception as e:
            logger.error(f"Failed to get deployment status: {e}")
            raise

    async def execute_tool(self,
                          deployment_id: str,
                          tool_name: str,
                          target: str,
                          arguments: Optional[List[str]] = None,
                          timeout: int = 3600) -> Dict[str, Any]:
        """
        Execute a penetration testing tool.
        
        Args:
            deployment_id: Deployment ID
            tool_name: Name of tool to execute
            target: Target for the tool
            arguments: Additional tool arguments
            timeout: Execution timeout in seconds
            
        Returns:
            Tool execution results
        """
        try:
            if deployment_id not in self.deployments:
                raise ValueError(f"Deployment {deployment_id} not found")
            
            deployment = self.deployments[deployment_id]
            
            if deployment.infrastructure_type != InfrastructureType.KALI_LINUX:
                raise ValueError("Tool execution only supported for Kali Linux deployments")
            
            container_id = deployment.containers[0]
            container = self.docker_client.containers.get(container_id)
            
            # Prepare command
            command = self._prepare_tool_command(tool_name, target, arguments or [])
            
            # Execute tool
            result = container.exec_run(
                command,
                stdout=True,
                stderr=True,
                user='root',
                workdir='/root'
            )
            
            # Parse results
            execution_result = {
                'tool_name': tool_name,
                'target': target,
                'command': ' '.join(command),
                'exit_code': result.exit_code,
                'stdout': result.output.decode('utf-8', errors='ignore'),
                'stderr': '',
                'executed_at': datetime.now(timezone.utc).isoformat(),
                'duration_seconds': 0  # Would need timing implementation
            }
            
            # Log tool execution
            await self._log_infrastructure_event(
                deployment_id,
                "tool_executed",
                f"Executed {tool_name} against {target}"
            )
            
            logger.info(f"Executed tool {tool_name} in deployment {deployment_id}")
            
            return execution_result
            
        except Exception as e:
            logger.error(f"Failed to execute tool: {e}")
            raise

    async def list_deployments(self, environment_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        List infrastructure deployments.
        
        Args:
            environment_id: Filter by environment ID
            
        Returns:
            List of deployment summaries
        """
        try:
            deployments = []
            
            for deployment_id, deployment in self.deployments.items():
                # Filter by environment if specified
                if environment_id and deployment.environment_id != environment_id:
                    continue
                
                deployment_summary = {
                    'deployment_id': deployment_id,
                    'environment_id': deployment.environment_id,
                    'infrastructure_type': deployment.infrastructure_type.value,
                    'name': deployment.name,
                    'status': deployment.status,
                    'deployed_at': deployment.deployed_at.isoformat(),
                    'container_count': len(deployment.containers)
                }
                
                deployments.append(deployment_summary)
            
            return deployments
            
        except Exception as e:
            logger.error(f"Failed to list deployments: {e}")
            return []

    # Private methods

    def _get_default_kali_tools(self) -> List[KaliToolConfig]:
        """Get default Kali Linux tools configuration"""
        return [
            KaliToolConfig(
                tool_name="nmap",
                enabled=True,
                custom_config={
                    'default_args': ['-sS', '-sV', '-O', '--script=default'],
                    'max_concurrent': 3
                },
                network_access_required=True
            ),
            KaliToolConfig(
                tool_name="nikto",
                enabled=True,
                custom_config={
                    'default_args': ['-h'],
                    'output_format': 'xml'
                },
                network_access_required=True
            ),
            KaliToolConfig(
                tool_name="sqlmap",
                enabled=True,
                custom_config={
                    'default_args': ['--batch', '--smart'],
                    'risk_level': 1,
                    'level': 1
                },
                network_access_required=True
            ),
            KaliToolConfig(
                tool_name="dirb",
                enabled=True,
                custom_config={
                    'wordlist': '/usr/share/dirb/wordlists/common.txt'
                },
                network_access_required=True
            ),
            KaliToolConfig(
                tool_name="hydra",
                enabled=True,
                custom_config={
                    'max_threads': 16,
                    'timeout': 30
                },
                network_access_required=True
            ),
            KaliToolConfig(
                tool_name="metasploit",
                enabled=True,
                custom_config={
                    'database': 'postgresql',
                    'auto_update': True
                },
                resource_requirements={
                    'memory': '2G',
                    'cpu': '1.0'
                },
                privilege_escalation_required=True
            )
        ]

    def _get_default_target_systems(self) -> List[TargetSystemConfig]:
        """Get default target system configurations"""
        return [
            TargetSystemConfig(
                system_id="dvwa",
                system_type=TargetSystemType.WEB_APPLICATION,
                name="Damn Vulnerable Web Application",
                description="Intentionally vulnerable web application for testing",
                image="vulnerables/web-dvwa:latest",
                ports=[80, 3306],
                environment_vars={
                    'MYSQL_ROOT_PASSWORD': 'p@ssw0rd',
                    'MYSQL_DATABASE': 'dvwa',
                    'MYSQL_USER': 'dvwa',
                    'MYSQL_PASSWORD': 'p@ssw0rd'
                },
                vulnerabilities=['sql_injection', 'xss', 'csrf', 'command_injection'],
                services=['apache', 'mysql']
            ),
            TargetSystemConfig(
                system_id="metasploitable",
                system_type=TargetSystemType.LINUX_SERVER,
                name="Metasploitable 2",
                description="Intentionally vulnerable Linux system",
                image="tleemcjr/metasploitable2:latest",
                ports=[21, 22, 23, 25, 53, 80, 111, 139, 445, 512, 513, 514, 1099, 1524, 2049, 2121, 3306, 3632, 5432, 5900, 6000, 6667, 6697, 8009, 8180],
                vulnerabilities=['weak_passwords', 'unpatched_services', 'misconfigurations'],
                services=['ftp', 'ssh', 'telnet', 'smtp', 'dns', 'http', 'samba', 'mysql', 'postgresql']
            ),
            TargetSystemConfig(
                system_id="webgoat",
                system_type=TargetSystemType.WEB_APPLICATION,
                name="WebGoat",
                description="OWASP WebGoat vulnerable web application",
                image="webgoat/goatandwolf:latest",
                ports=[8080, 9090],
                vulnerabilities=['injection', 'broken_auth', 'sensitive_data', 'xxe', 'broken_access_control'],
                services=['tomcat']
            )
        ]

    def _get_default_network_topologies(self) -> List[NetworkTopologyConfig]:
        """Get default network topology configurations"""
        return [
            NetworkTopologyConfig(
                topology_id="flat_network",
                topology_type=NetworkTopology.FLAT_NETWORK,
                name="Flat Network Topology",
                description="Single flat network for basic testing",
                networks={
                    'testing_network': '172.31.1.0/24'
                }
            ),
            NetworkTopologyConfig(
                topology_id="dmz_network",
                topology_type=NetworkTopology.DMZ_NETWORK,
                name="DMZ Network Topology",
                description="DMZ network with internal and external segments",
                networks={
                    'external': '172.31.1.0/24',
                    'dmz': '172.31.2.0/24',
                    'internal': '172.31.3.0/24'
                },
                firewall_rules=[
                    {'source': 'external', 'destination': 'dmz', 'ports': [80, 443], 'action': 'allow'},
                    {'source': 'dmz', 'destination': 'internal', 'ports': [3306, 5432], 'action': 'allow'},
                    {'source': 'external', 'destination': 'internal', 'action': 'deny'}
                ]
            )
        ]

    async def _prepare_kali_config(self, 
                                 tools_config: List[KaliToolConfig],
                                 custom_config: Dict[str, Any]) -> Dict[str, Any]:
        """Prepare Kali Linux container configuration"""
        try:
            # Base Kali configuration
            kali_config = {
                'image': self.config['kali_image'],
                'command': '/bin/bash',
                'environment': {
                    'DEBIAN_FRONTEND': 'noninteractive',
                    'DISPLAY': ':1.0'
                },
                'volumes': {
                    f"pentest-tools": {'bind': '/opt/tools', 'mode': 'rw'},
                    f"pentest-results": {'bind': '/root/results', 'mode': 'rw'}
                },
                'capabilities': ['NET_ADMIN', 'SYS_ADMIN'],  # Required for network tools
                'working_dir': '/root',
                'user': 'root'
            }
            
            # Add custom environment variables
            if 'environment' in custom_config:
                kali_config['environment'].update(custom_config['environment'])
            
            # Add custom volumes
            if 'volumes' in custom_config:
                kali_config['volumes'].update(custom_config['volumes'])
            
            return kali_config
            
        except Exception as e:
            logger.error(f"Failed to prepare Kali config: {e}")
            raise

    async def _configure_kali_tools(self, container_id: str, tools_config: List[KaliToolConfig]) -> None:
        """Configure Kali Linux tools in container"""
        try:
            container = self.docker_client.containers.get(container_id)
            
            # Update package lists
            if self.config['tool_update_on_deploy']:
                result = container.exec_run(['apt-get', 'update'], user='root')
                if result.exit_code != 0:
                    logger.warning("Failed to update package lists")
            
            # Install/configure each tool
            for tool_config in tools_config:
                if not tool_config.enabled:
                    continue
                
                try:
                    await self._configure_individual_tool(container, tool_config)
                except Exception as e:
                    logger.warning(f"Failed to configure tool {tool_config.tool_name}: {e}")
            
            # Create custom tool directories
            container.exec_run(['mkdir', '-p', self.config['custom_tools_directory']], user='root')
            container.exec_run(['mkdir', '-p', '/root/results'], user='root')
            container.exec_run(['mkdir', '-p', '/root/wordlists'], user='root')
            
            logger.info(f"Configured Kali tools in container {container_id[:12]}")
            
        except Exception as e:
            logger.error(f"Failed to configure Kali tools: {e}")
            raise

    async def _configure_individual_tool(self, container, tool_config: KaliToolConfig) -> None:
        """Configure individual Kali tool"""
        try:
            tool_name = tool_config.tool_name
            
            if tool_name == "metasploit":
                # Initialize Metasploit database
                container.exec_run(['msfdb', 'init'], user='root')
                
            elif tool_name == "sqlmap":
                # Create SQLMap configuration
                config_content = f"""
[Target]
risk = {tool_config.custom_config.get('risk_level', 1)}
level = {tool_config.custom_config.get('level', 1)}

[Request]
timeout = 30
retries = 3
"""
                # Write config file (would need proper implementation)
                
            elif tool_name == "hydra":
                # Configure Hydra
                max_threads = tool_config.custom_config.get('max_threads', 16)
                # Set system limits for hydra
                
            # Install tool if not present
            result = container.exec_run(['which', tool_name], user='root')
            if result.exit_code != 0:
                # Try to install the tool
                install_result = container.exec_run(['apt-get', 'install', '-y', tool_name], user='root')
                if install_result.exit_code != 0:
                    logger.warning(f"Failed to install {tool_name}")
            
        except Exception as e:
            logger.error(f"Failed to configure tool {tool_config.tool_name}: {e}")

    async def _prepare_target_config(self, target_config: TargetSystemConfig) -> Dict[str, Any]:
        """Prepare target system container configuration"""
        try:
            container_config = {
                'image': target_config.image,
                'name': f"target-{target_config.system_id}",
                'hostname': target_config.system_id,
                'environment': target_config.environment_vars,
                'volumes': target_config.volumes,
                'ports': {},  # Ports will be exposed internally only
                'labels': {
                    'target_system_id': target_config.system_id,
                    'target_type': target_config.system_type.value,
                    'vulnerabilities': ','.join(target_config.vulnerabilities)
                }
            }
            
            # Configure ports for internal exposure
            for port in target_config.ports:
                container_config['ports'][f"{port}/tcp"] = None
            
            return container_config
            
        except Exception as e:
            logger.error(f"Failed to prepare target config: {e}")
            raise

    async def _configure_target_system(self, container_id: str, target_config: TargetSystemConfig) -> None:
        """Configure target system after deployment"""
        try:
            container = self.docker_client.containers.get(container_id)
            
            # Run custom configuration scripts
            for script in target_config.custom_scripts:
                try:
                    result = container.exec_run(script, user='root')
                    if result.exit_code != 0:
                        logger.warning(f"Custom script failed for {target_config.system_id}: {script}")
                except Exception as e:
                    logger.warning(f"Failed to run custom script: {e}")
            
            # Configure services
            for service in target_config.services:
                try:
                    # Start service if not running
                    container.exec_run(['service', service, 'start'], user='root')
                except Exception as e:
                    logger.warning(f"Failed to start service {service}: {e}")
            
            logger.info(f"Configured target system {target_config.system_id}")
            
        except Exception as e:
            logger.error(f"Failed to configure target system: {e}")

    async def _deploy_network_topology(self, environment_id: str, topology_config: NetworkTopologyConfig) -> None:
        """Deploy network topology"""
        try:
            # Create additional networks for topology
            for network_name, subnet in topology_config.networks.items():
                if network_name != 'testing_network':  # Skip default network
                    try:
                        network = self.docker_client.networks.create(
                            name=f"{environment_id}-{network_name}",
                            driver='bridge',
                            ipam=docker.types.IPAMConfig(
                                pool_configs=[
                                    docker.types.IPAMPool(subnet=subnet)
                                ]
                            ),
                            labels={
                                'environment_id': environment_id,
                                'topology_id': topology_config.topology_id,
                                'network_role': network_name
                            }
                        )
                        logger.info(f"Created network {network_name} for topology {topology_config.topology_id}")
                    except Exception as e:
                        logger.warning(f"Failed to create network {network_name}: {e}")
            
            # Apply firewall rules (would need proper implementation with iptables or similar)
            for rule in topology_config.firewall_rules:
                logger.info(f"Would apply firewall rule: {rule}")
                
        except Exception as e:
            logger.error(f"Failed to deploy network topology: {e}")

    async def _prepare_scanner_config(self, scanner_type: str, custom_config: Dict[str, Any]) -> Dict[str, Any]:
        """Prepare vulnerability scanner configuration"""
        try:
            if scanner_type == "openvas":
                scanner_config = {
                    'image': 'mikesplain/openvas:latest',
                    'environment': {
                        'PUBLIC_HOSTNAME': 'localhost',
                        'HTTPS': 'true'
                    },
                    'ports': {'443/tcp': None, '9390/tcp': None},
                    'volumes': {
                        'openvas-data': {'bind': '/usr/local/var/lib/openvas', 'mode': 'rw'}
                    }
                }
            elif scanner_type == "nessus":
                scanner_config = {
                    'image': 'tenableofficial/nessus:latest',
                    'environment': {
                        'AUTO_UPDATE': 'all'
                    },
                    'ports': {'8834/tcp': None}
                }
            else:
                raise ValueError(f"Unsupported scanner type: {scanner_type}")
            
            # Apply custom configuration
            if custom_config:
                if 'environment' in custom_config:
                    scanner_config['environment'].update(custom_config['environment'])
                if 'volumes' in custom_config:
                    scanner_config['volumes'].update(custom_config['volumes'])
            
            return scanner_config
            
        except Exception as e:
            logger.error(f"Failed to prepare scanner config: {e}")
            raise

    async def _configure_vulnerability_scanner(self, container_id: str, scanner_type: str, custom_config: Dict[str, Any]) -> None:
        """Configure vulnerability scanner after deployment"""
        try:
            container = self.docker_client.containers.get(container_id)
            
            # Wait for scanner to be ready
            await asyncio.sleep(30)
            
            if scanner_type == "openvas":
                # Update NVT feeds
                result = container.exec_run(['greenbone-nvt-sync'], user='root')
                if result.exit_code == 0:
                    logger.info("Updated OpenVAS NVT feeds")
                
            elif scanner_type == "nessus":
                # Nessus configuration would be done through web interface
                logger.info("Nessus scanner deployed - configure through web interface")
            
            logger.info(f"Configured {scanner_type} scanner")
            
        except Exception as e:
            logger.error(f"Failed to configure scanner: {e}")

    async def _get_kali_tool_status(self, container_id: str) -> Dict[str, Any]:
        """Get status of Kali tools"""
        try:
            container = self.docker_client.containers.get(container_id)
            tool_status = {}
            
            for tool_config in self.kali_tools_config:
                tool_name = tool_config.tool_name
                
                # Check if tool is installed
                result = container.exec_run(['which', tool_name], user='root')
                
                tool_status[tool_name] = {
                    'installed': result.exit_code == 0,
                    'enabled': tool_config.enabled,
                    'path': result.output.decode('utf-8').strip() if result.exit_code == 0 else None
                }
                
                # Get version if installed
                if result.exit_code == 0:
                    try:
                        version_result = container.exec_run([tool_name, '--version'], user='root')
                        if version_result.exit_code == 0:
                            tool_status[tool_name]['version'] = version_result.output.decode('utf-8').strip()[:100]
                    except Exception:
                        pass
            
            return tool_status
            
        except Exception as e:
            logger.error(f"Failed to get tool status: {e}")
            return {}

    def _prepare_tool_command(self, tool_name: str, target: str, arguments: List[str]) -> List[str]:
        """Prepare command for tool execution"""
        try:
            base_commands = {
                'nmap': ['nmap'] + arguments + [target],
                'nikto': ['nikto'] + arguments + ['-h', target],
                'sqlmap': ['sqlmap'] + arguments + ['-u', target],
                'dirb': ['dirb', target] + arguments,
                'hydra': ['hydra'] + arguments + [target],
                'metasploit': ['msfconsole', '-q', '-x'] + arguments
            }
            
            if tool_name in base_commands:
                return base_commands[tool_name]
            else:
                # Generic command
                return [tool_name] + arguments + [target]
            
        except Exception as e:
            logger.error(f"Failed to prepare tool command: {e}")
            return [tool_name, target]

    async def _log_infrastructure_event(self, deployment_id: str, event_type: str, message: str) -> None:
        """Log infrastructure-related events"""
        try:
            if not self.audit_logger:
                return
            
            event_data = {
                'deployment_id': deployment_id,
                'event_type': event_type,
                'message': message,
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'component': 'testing_infrastructure'
            }
            
            await self.audit_logger.log_event(
                event_type="INFRASTRUCTURE_MANAGEMENT",
                severity="INFO",
                resource_type="testing_infrastructure",
                resource_id=deployment_id,
                action=event_type,
                additional_data=event_data
            )
            
        except Exception as e:
            logger.error(f"Failed to log infrastructure event: {e}")


def create_testing_infrastructure(environment_manager=None, 
                                audit_logger=None, 
                                monitoring_system=None):
    """
    Factory function to create a TestingInfrastructure instance.
    
    Args:
        environment_manager: Isolated test environment manager
        audit_logger: Audit logging system integration
        monitoring_system: Security monitoring system integration
        
    Returns:
        TestingInfrastructure instance
    """
    return TestingInfrastructure(
        environment_manager=environment_manager,
        audit_logger=audit_logger,
        monitoring_system=monitoring_system
    )


# Example usage
if __name__ == "__main__":
    async def example_usage():
        """Example usage of the testing infrastructure"""
        
        # Create infrastructure manager
        infra_manager = create_testing_infrastructure()
        
        # Deploy Kali Linux environment
        kali_deployment = await infra_manager.deploy_kali_linux(
            environment_id="test-env-001",
            tools_config=None,  # Use defaults
            custom_config={
                'environment': {
                    'CUSTOM_VAR': 'value'
                }
            }
        )
        
        print(f"Deployed Kali Linux: {kali_deployment}")
        
        # Deploy target systems
        target_configs = [
            TargetSystemConfig(
                system_id="dvwa-test",
                system_type=TargetSystemType.WEB_APPLICATION,
                name="DVWA Test Instance",
                description="Test instance of DVWA",
                image="vulnerables/web-dvwa:latest",
                ports=[80],
                vulnerabilities=['sql_injection', 'xss']
            )
        ]
        
        targets_deployment = await infra_manager.deploy_target_systems(
            environment_id="test-env-001",
            target_configs=target_configs
        )
        
        print(f"Deployed targets: {targets_deployment}")
        
        # Execute a tool
        tool_result = await infra_manager.execute_tool(
            deployment_id=kali_deployment,
            tool_name="nmap",
            target="dvwa-test",
            arguments=['-sS', '-sV']
        )
        
        print(f"Tool execution result: {tool_result}")
        
        # Get deployment status
        status = await infra_manager.get_deployment_status(kali_deployment)
        print(f"Deployment status: {status}")
    
    # Run example
    asyncio.run(example_usage())