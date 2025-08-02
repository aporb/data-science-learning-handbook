"""
Target System Simulation
========================

Main target system simulator for creating realistic penetration testing targets.
Provides vulnerable application deployment, network service configuration,
and multi-platform target environment support with classification awareness.

Key Features:
- Vulnerable application deployment and configuration
- Network service simulation with realistic vulnerabilities
- Authentication system simulation with various weaknesses
- Database and file system targets with controlled access
- Multi-platform target environment support (Linux, Windows, Web)
- Classification-aware target configuration
- Integration with monitoring and audit systems

Classification: UNCLASSIFIED//FOR OFFICIAL USE ONLY
Version: 1.0
Author: Security Compliance Team
Date: 2025-07-28
"""

import asyncio
import json
import logging
import uuid
import docker
import subprocess
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Tuple, Set, Union
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
import tempfile
import shutil
from jinja2 import Template

# Import existing infrastructure
from ...multi_classification.enhanced_classification_engine import ClassificationLevel
from ...audits.audit_logger import AuditLogger
from ...rbac.models.data_classification import NetworkDomain

logger = logging.getLogger(__name__)

class TargetType(Enum):
    """Types of target systems."""
    WEB_APPLICATION = "web_application"
    DATABASE_SERVER = "database_server"
    FILE_SERVER = "file_server"
    NETWORK_SERVICE = "network_service"
    AUTHENTICATION_SERVER = "authentication_server"
    API_SERVER = "api_server"
    CONTAINER_SERVICE = "container_service"
    CLOUD_SERVICE = "cloud_service"

class VulnerabilityLevel(Enum):
    """Vulnerability levels for targets."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class TargetStatus(Enum):
    """Status of target systems."""
    CREATING = "creating"
    RUNNING = "running"
    STOPPED = "stopped"
    ERROR = "error"
    DESTROYED = "destroyed"

@dataclass
class TargetConfiguration:
    """Configuration for a target system."""
    target_id: str
    name: str
    description: str
    target_type: TargetType
    vulnerability_level: VulnerabilityLevel
    classification_level: ClassificationLevel
    network_domain: NetworkDomain = NetworkDomain.NIPR
    platform: str = "linux"  # linux, windows, web
    services: List[str] = field(default_factory=list)
    ports: List[int] = field(default_factory=list)
    vulnerabilities: List[str] = field(default_factory=list)
    credentials: Dict[str, str] = field(default_factory=dict)
    file_shares: List[str] = field(default_factory=list)
    databases: List[str] = field(default_factory=list)
    docker_config: Optional[Dict[str, Any]] = None
    network_config: Dict[str, Any] = field(default_factory=dict)
    persistence: bool = False  # Whether target persists between tests
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class TargetInstance:
    """Running instance of a target system."""
    instance_id: str
    target_id: str
    status: TargetStatus
    ip_address: Optional[str] = None
    ports: List[int] = field(default_factory=list)
    docker_container_id: Optional[str] = None
    process_id: Optional[int] = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    destroyed_at: Optional[datetime] = None
    access_logs: List[Dict[str, Any]] = field(default_factory=list)
    resource_usage: Dict[str, Any] = field(default_factory=dict)

class TargetSystemSimulator:
    """
    Main target system simulator for creating realistic penetration testing targets.
    
    Provides comprehensive target system creation and management with
    classification awareness and integration with existing security infrastructure.
    """
    
    def __init__(self, 
                 audit_logger: Optional[AuditLogger] = None,
                 docker_client: Optional[docker.DockerClient] = None):
        """Initialize the target system simulator."""
        self.audit_logger = audit_logger
        
        # Initialize Docker client
        try:
            self.docker_client = docker_client or docker.from_env()
            self.docker_available = True
        except Exception as e:
            logger.warning(f"Docker not available: {str(e)}")
            self.docker_client = None
            self.docker_available = False
        
        # Target storage
        self.target_configs: Dict[str, TargetConfiguration] = {}
        self.target_instances: Dict[str, TargetInstance] = {}
        
        # Simulator statistics
        self.simulator_stats = {
            'targets_created': 0,
            'instances_deployed': 0,
            'total_uptime': 0,
            'vulnerability_distribution': {},
            'classification_distribution': {}
        }
        
        # Built-in target templates
        self.target_templates = {}
        asyncio.create_task(self._load_builtin_targets())
        
        logger.info("TargetSystemSimulator initialized")
    
    async def create_target(self, config: TargetConfiguration) -> str:
        """
        Create a new target system configuration.
        
        Args:
            config: Target configuration
            
        Returns:
            Target ID
        """
        try:
            target_id = config.target_id or str(uuid.uuid4())
            config.target_id = target_id
            
            # Validate configuration
            await self._validate_target_config(config)
            
            # Store target configuration
            self.target_configs[target_id] = config
            
            # Update statistics
            self.simulator_stats['targets_created'] += 1
            vuln_level = config.vulnerability_level.value
            self.simulator_stats['vulnerability_distribution'][vuln_level] = \
                self.simulator_stats['vulnerability_distribution'].get(vuln_level, 0) + 1
            
            class_level = config.classification_level.value
            self.simulator_stats['classification_distribution'][class_level] = \
                self.simulator_stats['classification_distribution'].get(class_level, 0) + 1
            
            # Audit target creation
            if self.audit_logger:
                await self.audit_logger.log_event(
                    event_type="target_created",
                    data={
                        'target_id': target_id,
                        'target_type': config.target_type.value,
                        'vulnerability_level': config.vulnerability_level.value,
                        'classification': config.classification_level.value
                    },
                    classification=config.classification_level
                )
            
            logger.info(f"Created target {target_id}: {config.name}")
            return target_id
            
        except Exception as e:
            error_msg = f"Failed to create target: {str(e)}"
            logger.error(error_msg)
            raise
    
    async def deploy_target(self, 
                          target_id: str,
                          deployment_params: Optional[Dict[str, Any]] = None) -> str:
        """
        Deploy a target system instance.
        
        Args:
            target_id: ID of target to deploy
            deployment_params: Optional deployment parameters
            
        Returns:
            Instance ID
        """
        try:
            if target_id not in self.target_configs:
                raise ValueError(f"Target {target_id} not found")
            
            config = self.target_configs[target_id]
            instance_id = str(uuid.uuid4())
            
            # Create instance
            instance = TargetInstance(
                instance_id=instance_id,
                target_id=target_id,
                status=TargetStatus.CREATING
            )
            
            self.target_instances[instance_id] = instance
            
            # Deploy based on configuration
            await self._deploy_target_instance(instance, config, deployment_params or {})
            
            # Update statistics
            self.simulator_stats['instances_deployed'] += 1
            
            # Audit deployment
            if self.audit_logger:
                await self.audit_logger.log_event(
                    event_type="target_deployed",
                    data={
                        'instance_id': instance_id,
                        'target_id': target_id,
                        'target_type': config.target_type.value
                    },
                    classification=config.classification_level
                )
            
            logger.info(f"Deployed target instance {instance_id}")
            return instance_id
            
        except Exception as e:
            error_msg = f"Failed to deploy target: {str(e)}"
            logger.error(error_msg)
            raise
    
    async def _deploy_target_instance(self, 
                                    instance: TargetInstance,
                                    config: TargetConfiguration,
                                    params: Dict[str, Any]) -> None:
        """Deploy a target instance based on configuration."""
        try:
            # Deployment handlers by target type
            handlers = {
                TargetType.WEB_APPLICATION: self._deploy_web_application,
                TargetType.DATABASE_SERVER: self._deploy_database_server,
                TargetType.FILE_SERVER: self._deploy_file_server,
                TargetType.NETWORK_SERVICE: self._deploy_network_service,
                TargetType.AUTHENTICATION_SERVER: self._deploy_auth_server,
                TargetType.API_SERVER: self._deploy_api_server,
                TargetType.CONTAINER_SERVICE: self._deploy_container_service,
                TargetType.CLOUD_SERVICE: self._deploy_cloud_service
            }
            
            handler = handlers.get(config.target_type)
            if not handler:
                raise ValueError(f"Unsupported target type: {config.target_type}")
            
            await handler(instance, config, params)
            
            instance.status = TargetStatus.RUNNING
            
        except Exception as e:
            instance.status = TargetStatus.ERROR
            logger.error(f"Failed to deploy instance: {str(e)}")
            raise
    
    async def _deploy_web_application(self, 
                                    instance: TargetInstance,
                                    config: TargetConfiguration,
                                    params: Dict[str, Any]) -> None:
        """Deploy a vulnerable web application."""
        if self.docker_available and config.docker_config:
            # Deploy using Docker
            container = await self._deploy_docker_container(instance, config)
            instance.docker_container_id = container.id
            instance.ip_address = self._get_container_ip(container)
            instance.ports = config.ports or [80, 443]
        else:
            # Deploy using local process (simplified)
            await self._deploy_local_web_app(instance, config)
    
    async def _deploy_database_server(self, 
                                    instance: TargetInstance,
                                    config: TargetConfiguration,
                                    params: Dict[str, Any]) -> None:
        """Deploy a vulnerable database server."""
        # Simulate database deployment
        instance.ip_address = "127.0.0.1"
        instance.ports = config.ports or [3306, 5432, 1433]  # MySQL, PostgreSQL, SQL Server
        
        # Create test databases
        for db_name in config.databases:
            await self._create_test_database(instance, config, db_name)
    
    async def _deploy_file_server(self, 
                                instance: TargetInstance,
                                config: TargetConfiguration,
                                params: Dict[str, Any]) -> None:
        """Deploy a vulnerable file server."""
        # Simulate file server deployment
        instance.ip_address = "127.0.0.1"
        instance.ports = config.ports or [21, 22, 445]  # FTP, SSH, SMB
        
        # Create file shares
        for share_name in config.file_shares:
            await self._create_file_share(instance, config, share_name)
    
    async def _deploy_network_service(self, 
                                    instance: TargetInstance,
                                    config: TargetConfiguration,
                                    params: Dict[str, Any]) -> None:
        """Deploy a vulnerable network service."""
        # Simulate network service deployment
        instance.ip_address = "127.0.0.1"
        instance.ports = config.ports or [80, 23, 25]  # HTTP, Telnet, SMTP
        
        # Start network services
        for service in config.services:
            await self._start_network_service(instance, config, service)
    
    async def _deploy_auth_server(self, 
                                instance: TargetInstance,
                                config: TargetConfiguration,
                                params: Dict[str, Any]) -> None:
        """Deploy a vulnerable authentication server."""
        # Simulate authentication server deployment
        instance.ip_address = "127.0.0.1"
        instance.ports = config.ports or [389, 636, 88]  # LDAP, LDAPS, Kerberos
        
        # Configure authentication mechanisms
        await self._configure_auth_mechanisms(instance, config)
    
    async def _deploy_api_server(self, 
                               instance: TargetInstance,
                               config: TargetConfiguration,
                               params: Dict[str, Any]) -> None:
        """Deploy a vulnerable API server."""
        if self.docker_available and config.docker_config:
            # Deploy API using Docker
            container = await self._deploy_docker_container(instance, config)
            instance.docker_container_id = container.id
            instance.ip_address = self._get_container_ip(container)
            instance.ports = config.ports or [8080, 8443]
        else:
            # Deploy using local process
            await self._deploy_local_api_server(instance, config)
    
    async def _deploy_container_service(self, 
                                      instance: TargetInstance,
                                      config: TargetConfiguration,
                                      params: Dict[str, Any]) -> None:
        """Deploy a vulnerable containerized service."""
        if not self.docker_available:
            raise RuntimeError("Docker is required for container service deployment")
        
        container = await self._deploy_docker_container(instance, config)
        instance.docker_container_id = container.id
        instance.ip_address = self._get_container_ip(container)
        instance.ports = config.ports or [8080]
    
    async def _deploy_cloud_service(self, 
                                  instance: TargetInstance,
                                  config: TargetConfiguration,
                                  params: Dict[str, Any]) -> None:
        """Deploy a cloud service simulation."""
        # Simulate cloud service deployment
        instance.ip_address = "cloud.example.com"
        instance.ports = config.ports or [443, 80]
        
        # Configure cloud-specific vulnerabilities
        await self._configure_cloud_vulnerabilities(instance, config)
    
    async def _deploy_docker_container(self, 
                                     instance: TargetInstance,
                                     config: TargetConfiguration) -> Any:
        """Deploy a Docker container for the target."""
        if not self.docker_available or not config.docker_config:
            raise RuntimeError("Docker deployment not available")
        
        docker_config = config.docker_config
        
        # Pull image if needed
        image_name = docker_config.get('image')
        if image_name:
            try:
                self.docker_client.images.pull(image_name)
            except Exception as e:
                logger.warning(f"Failed to pull image {image_name}: {str(e)}")
        
        # Create container
        container = self.docker_client.containers.run(
            image=image_name,
            detach=True,
            ports=docker_config.get('ports', {}),
            environment=docker_config.get('environment', {}),
            volumes=docker_config.get('volumes', {}),
            name=f"pentest_target_{instance.instance_id}",
            labels={
                'pentest.target_id': config.target_id,
                'pentest.instance_id': instance.instance_id,
                'pentest.classification': config.classification_level.value
            }
        )
        
        return container
    
    async def _deploy_local_web_app(self, 
                                  instance: TargetInstance,
                                  config: TargetConfiguration) -> None:
        """Deploy a local web application."""
        # Create temporary directory for web app
        temp_dir = tempfile.mkdtemp(prefix=f"pentest_webapp_{instance.instance_id}_")
        
        # Generate vulnerable web app
        await self._generate_vulnerable_webapp(temp_dir, config)
        
        # Start simple HTTP server (for demonstration)
        # In a real implementation, this would use a proper web server
        instance.ip_address = "127.0.0.1"
        instance.ports = [8000 + int(instance.instance_id[-4:], 16) % 1000]
        
        # Store deployment path for cleanup
        instance.metadata = {'deployment_path': temp_dir}
    
    async def _deploy_local_api_server(self, 
                                     instance: TargetInstance,
                                     config: TargetConfiguration) -> None:
        """Deploy a local API server."""
        # Similar to web app but for API
        temp_dir = tempfile.mkdtemp(prefix=f"pentest_api_{instance.instance_id}_")
        
        await self._generate_vulnerable_api(temp_dir, config)
        
        instance.ip_address = "127.0.0.1"
        instance.ports = [9000 + int(instance.instance_id[-4:], 16) % 1000]
        instance.metadata = {'deployment_path': temp_dir}
    
    async def _generate_vulnerable_webapp(self, 
                                        deployment_path: str,
                                        config: TargetConfiguration) -> None:
        """Generate a vulnerable web application."""
        # Create basic vulnerable web app structure
        webapp_template = """
<!DOCTYPE html>
<html>
<head>
    <title>{{ app_name }} - Test Application</title>
</head>
<body>
    <h1>{{ app_name }}</h1>
    <p>Classification: {{ classification }}</p>
    
    <!-- Vulnerable login form -->
    <form method="POST" action="/login">
        <input type="text" name="username" placeholder="Username">
        <input type="password" name="password" placeholder="Password">
        <input type="submit" value="Login">
    </form>
    
    <!-- XSS vulnerability -->
    <div id="message">{{ user_message | safe }}</div>
    
    {% for vulnerability in vulnerabilities %}
    <div class="vuln-{{ vulnerability }}">
        Vulnerability: {{ vulnerability }}
    </div>
    {% endfor %}
</body>
</html>
        """
        
        template = Template(webapp_template)
        html_content = template.render(
            app_name=config.name,
            classification=config.classification_level.value,
            user_message="Welcome to the test application",
            vulnerabilities=config.vulnerabilities
        )
        
        # Write HTML file
        html_path = Path(deployment_path) / "index.html"
        html_path.write_text(html_content)
        
        # Create additional vulnerable endpoints
        await self._create_vulnerable_endpoints(deployment_path, config)
    
    async def _generate_vulnerable_api(self, 
                                     deployment_path: str,
                                     config: TargetConfiguration) -> None:
        """Generate a vulnerable API."""
        # Create API specification and implementation
        api_spec = {
            "openapi": "3.0.0",
            "info": {
                "title": config.name,
                "version": "1.0.0",
                "description": f"Test API - {config.classification_level.value}"
            },
            "paths": {
                "/api/users": {
                    "get": {
                        "summary": "Get users",
                        "responses": {"200": {"description": "Success"}}
                    }
                },
                "/api/login": {
                    "post": {
                        "summary": "User login",
                        "responses": {"200": {"description": "Success"}}
                    }
                }
            }
        }
        
        # Write API spec
        spec_path = Path(deployment_path) / "api_spec.json"
        spec_path.write_text(json.dumps(api_spec, indent=2))
    
    async def _create_vulnerable_endpoints(self, 
                                         deployment_path: str,
                                         config: TargetConfiguration) -> None:
        """Create additional vulnerable endpoints."""
        # Create SQL injection endpoint
        if "sql_injection" in config.vulnerabilities:
            sql_endpoint = """
            // Vulnerable SQL endpoint
            app.get('/search', (req, res) => {
                const query = req.query.q;
                const sql = `SELECT * FROM users WHERE name LIKE '%${query}%'`;
                // This is vulnerable to SQL injection
                db.query(sql, (err, results) => {
                    res.json(results);
                });
            });
            """
            
            endpoint_path = Path(deployment_path) / "sql_endpoint.js"
            endpoint_path.write_text(sql_endpoint)
        
        # Create file upload endpoint
        if "file_upload" in config.vulnerabilities:
            upload_html = """
            <form method="POST" action="/upload" enctype="multipart/form-data">
                <input type="file" name="file">
                <input type="submit" value="Upload">
            </form>
            """
            
            upload_path = Path(deployment_path) / "upload.html"
            upload_path.write_text(upload_html)
    
    async def _create_test_database(self, 
                                  instance: TargetInstance,
                                  config: TargetConfiguration,
                                  db_name: str) -> None:
        """Create a test database with vulnerabilities."""
        # Simulate database creation
        db_info = {
            'name': db_name,
            'type': 'mysql',  # or postgresql, mssql
            'port': 3306,
            'credentials': config.credentials,
            'vulnerabilities': config.vulnerabilities
        }
        
        instance.metadata.setdefault('databases', []).append(db_info)
    
    async def _create_file_share(self, 
                               instance: TargetInstance,
                               config: TargetConfiguration,
                               share_name: str) -> None:
        """Create a file share with vulnerabilities."""
        # Simulate file share creation
        share_info = {
            'name': share_name,
            'path': f'/shares/{share_name}',
            'permissions': '777' if 'weak_permissions' in config.vulnerabilities else '755',
            'protocol': 'smb'
        }
        
        instance.metadata.setdefault('file_shares', []).append(share_info)
    
    async def _start_network_service(self, 
                                   instance: TargetInstance,
                                   config: TargetConfiguration,
                                   service: str) -> None:
        """Start a network service."""
        # Simulate service startup
        service_info = {
            'name': service,
            'port': {'ftp': 21, 'ssh': 22, 'telnet': 23, 'http': 80}.get(service, 8080),
            'status': 'running',
            'vulnerabilities': config.vulnerabilities
        }
        
        instance.metadata.setdefault('services', []).append(service_info)
    
    async def _configure_auth_mechanisms(self, 
                                       instance: TargetInstance,
                                       config: TargetConfiguration) -> None:
        """Configure authentication mechanisms."""
        auth_config = {
            'ldap_enabled': True,
            'weak_passwords': 'weak_passwords' in config.vulnerabilities,
            'default_credentials': 'default_credentials' in config.vulnerabilities,
            'password_policy': 'weak' if config.vulnerability_level == VulnerabilityLevel.HIGH else 'strong'
        }
        
        instance.metadata['authentication'] = auth_config
    
    async def _configure_cloud_vulnerabilities(self, 
                                             instance: TargetInstance,
                                             config: TargetConfiguration) -> None:
        """Configure cloud-specific vulnerabilities."""
        cloud_vulns = {
            'open_s3_buckets': 'cloud_storage' in config.vulnerabilities,
            'iam_misconfig': 'iam_issues' in config.vulnerabilities,
            'metadata_exposure': 'metadata_exposure' in config.vulnerabilities
        }
        
        instance.metadata['cloud_vulnerabilities'] = cloud_vulns
    
    def _get_container_ip(self, container) -> str:
        """Get IP address of Docker container."""
        try:
            container.reload()
            networks = container.attrs['NetworkSettings']['Networks']
            for network in networks.values():
                if network.get('IPAddress'):
                    return network['IPAddress']
        except Exception as e:
            logger.warning(f"Failed to get container IP: {str(e)}")
        
        return "127.0.0.1"
    
    async def _validate_target_config(self, config: TargetConfiguration) -> None:
        """Validate target configuration."""
        if not config.name:
            raise ValueError("Target name is required")
        
        if config.target_type == TargetType.CONTAINER_SERVICE and not self.docker_available:
            raise ValueError("Docker is required for container service targets")
        
        # Validate ports
        for port in config.ports:
            if not (1 <= port <= 65535):
                raise ValueError(f"Invalid port number: {port}")
    
    async def _load_builtin_targets(self) -> None:
        """Load built-in target templates."""
        builtin_targets = [
            await self._create_dvwa_target(),
            await self._create_vulnerable_db_target(),
            await self._create_vulnerable_api_target(),
            await self._create_vulnerable_ftp_target()
        ]
        
        for target in builtin_targets:
            self.target_templates[target.target_id] = target
        
        logger.info(f"Loaded {len(builtin_targets)} built-in target templates")
    
    async def _create_dvwa_target(self) -> TargetConfiguration:
        """Create DVWA (Damn Vulnerable Web Application) target."""
        return TargetConfiguration(
            target_id="builtin_dvwa",
            name="DVWA - Damn Vulnerable Web Application",
            description="Popular vulnerable web application for testing",
            target_type=TargetType.WEB_APPLICATION,
            vulnerability_level=VulnerabilityLevel.HIGH,
            classification_level=ClassificationLevel.UNCLASSIFIED,
            platform="linux",
            ports=[80, 443],
            services=["apache", "mysql"],
            vulnerabilities=[
                "sql_injection",
                "xss",
                "csrf",
                "file_inclusion",
                "command_injection",
                "weak_session_management"
            ],
            credentials={
                "admin": "password",
                "user": "password"
            },
            docker_config={
                "image": "vulnerables/web-dvwa",
                "ports": {"80/tcp": 80},
                "environment": {}
            }
        )
    
    async def _create_vulnerable_db_target(self) -> TargetConfiguration:
        """Create vulnerable database target."""
        return TargetConfiguration(
            target_id="builtin_vulnerable_db",
            name="Vulnerable Database Server",
            description="Database server with multiple vulnerabilities",
            target_type=TargetType.DATABASE_SERVER,
            vulnerability_level=VulnerabilityLevel.MEDIUM,
            classification_level=ClassificationLevel.UNCLASSIFIED,
            platform="linux",
            ports=[3306, 5432],
            services=["mysql", "postgresql"],
            vulnerabilities=[
                "default_credentials",
                "weak_passwords",
                "privilege_escalation",
                "unencrypted_connections"
            ],
            credentials={
                "root": "root",
                "admin": "admin",
                "user": "password123"
            },
            databases=["testdb", "userdb", "inventory"]
        )
    
    async def _create_vulnerable_api_target(self) -> TargetConfiguration:
        """Create vulnerable API target."""
        return TargetConfiguration(
            target_id="builtin_vulnerable_api",
            name="Vulnerable REST API",
            description="REST API with OWASP API Top 10 vulnerabilities",
            target_type=TargetType.API_SERVER,
            vulnerability_level=VulnerabilityLevel.HIGH,
            classification_level=ClassificationLevel.UNCLASSIFIED,
            platform="linux",
            ports=[8080, 8443],
            services=["api_service"],
            vulnerabilities=[
                "broken_authentication",
                "excessive_data_exposure",
                "lack_of_resources_rate_limiting",
                "broken_function_level_authorization",
                "mass_assignment",
                "security_misconfiguration"
            ],
            credentials={
                "api_user": "apikey123",
                "admin": "admin_token"
            }
        )
    
    async def _create_vulnerable_ftp_target(self) -> TargetConfiguration:
        """Create vulnerable FTP target."""
        return TargetConfiguration(
            target_id="builtin_vulnerable_ftp",
            name="Vulnerable FTP Server",
            description="FTP server with directory traversal and weak authentication",
            target_type=TargetType.FILE_SERVER,
            vulnerability_level=VulnerabilityLevel.MEDIUM,
            classification_level=ClassificationLevel.UNCLASSIFIED,
            platform="linux",
            ports=[21, 20],
            services=["ftp"],
            vulnerabilities=[
                "anonymous_access",
                "directory_traversal",
                "weak_permissions",
                "unencrypted_transmission"
            ],
            credentials={
                "ftp": "ftp",
                "anonymous": ""
            },
            file_shares=["public", "uploads", "temp"]
        )
    
    async def stop_target(self, instance_id: str) -> bool:
        """Stop a running target instance."""
        try:
            instance = self.target_instances.get(instance_id)
            if not instance:
                return False
            
            if instance.status != TargetStatus.RUNNING:
                return False
            
            # Stop based on deployment type
            if instance.docker_container_id and self.docker_available:
                container = self.docker_client.containers.get(instance.docker_container_id)
                container.stop()
                instance.status = TargetStatus.STOPPED
            elif instance.process_id:
                # Stop local process
                subprocess.run(['kill', str(instance.process_id)], check=False)
                instance.status = TargetStatus.STOPPED
            
            # Audit stop
            if self.audit_logger:
                await self.audit_logger.log_event(
                    event_type="target_stopped",
                    data={
                        'instance_id': instance_id,
                        'target_id': instance.target_id
                    },
                    classification=ClassificationLevel.UNCLASSIFIED
                )
            
            logger.info(f"Stopped target instance {instance_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to stop target instance: {str(e)}")
            return False
    
    async def destroy_target(self, instance_id: str) -> bool:
        """Destroy a target instance and clean up resources."""
        try:
            instance = self.target_instances.get(instance_id)
            if not instance:
                return False
            
            # Stop first if running
            if instance.status == TargetStatus.RUNNING:
                await self.stop_target(instance_id)
            
            # Cleanup resources
            if instance.docker_container_id and self.docker_available:
                try:
                    container = self.docker_client.containers.get(instance.docker_container_id)
                    container.remove(force=True)
                except Exception as e:
                    logger.warning(f"Failed to remove container: {str(e)}")
            
            # Cleanup local files
            deployment_path = instance.metadata.get('deployment_path')
            if deployment_path and Path(deployment_path).exists():
                shutil.rmtree(deployment_path, ignore_errors=True)
            
            instance.status = TargetStatus.DESTROYED
            instance.destroyed_at = datetime.now(timezone.utc)
            
            # Audit destruction
            if self.audit_logger:
                await self.audit_logger.log_event(
                    event_type="target_destroyed",
                    data={
                        'instance_id': instance_id,
                        'target_id': instance.target_id
                    },
                    classification=ClassificationLevel.UNCLASSIFIED
                )
            
            logger.info(f"Destroyed target instance {instance_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to destroy target instance: {str(e)}")
            return False
    
    def get_target_config(self, target_id: str) -> Optional[TargetConfiguration]:
        """Get target configuration by ID."""
        return self.target_configs.get(target_id)
    
    def get_target_instance(self, instance_id: str) -> Optional[TargetInstance]:
        """Get target instance by ID."""
        return self.target_instances.get(instance_id)
    
    def list_targets(self, 
                    target_type: Optional[TargetType] = None,
                    vulnerability_level: Optional[VulnerabilityLevel] = None) -> List[TargetConfiguration]:
        """List target configurations with optional filtering."""
        results = []
        
        for target in self.target_configs.values():
            if target_type and target.target_type != target_type:
                continue
            if vulnerability_level and target.vulnerability_level != vulnerability_level:
                continue
            results.append(target)
        
        return results
    
    def list_instances(self, 
                      target_id: Optional[str] = None,
                      status: Optional[TargetStatus] = None) -> List[TargetInstance]:
        """List target instances with optional filtering."""
        results = []
        
        for instance in self.target_instances.values():
            if target_id and instance.target_id != target_id:
                continue
            if status and instance.status != status:
                continue
            results.append(instance)
        
        return results
    
    def get_target_templates(self) -> Dict[str, TargetConfiguration]:
        """Get available target templates."""
        return self.target_templates.copy()
    
    async def create_from_template(self, 
                                 template_id: str,
                                 customizations: Optional[Dict[str, Any]] = None) -> str:
        """Create a target from a template with optional customizations."""
        template = self.target_templates.get(template_id)
        if not template:
            raise ValueError(f"Template {template_id} not found")
        
        # Clone template
        config_dict = asdict(template)
        config_dict['target_id'] = str(uuid.uuid4())
        
        # Apply customizations
        if customizations:
            config_dict.update(customizations)
        
        # Create target configuration
        config = TargetConfiguration(**config_dict)
        
        return await self.create_target(config)
    
    def get_simulator_statistics(self) -> Dict[str, Any]:
        """Get simulator usage statistics."""
        return self.simulator_stats.copy()
    
    async def health_check(self) -> Dict[str, Any]:
        """Perform health check on the simulator."""
        health_status = {
            'status': 'healthy',
            'docker_available': self.docker_available,
            'total_targets': len(self.target_configs),
            'running_instances': len([i for i in self.target_instances.values() 
                                    if i.status == TargetStatus.RUNNING]),
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
        
        # Check Docker connectivity
        if self.docker_available:
            try:
                self.docker_client.ping()
                health_status['docker_status'] = 'connected'
            except Exception:
                health_status['docker_status'] = 'disconnected'
                health_status['status'] = 'degraded'
        
        return health_status