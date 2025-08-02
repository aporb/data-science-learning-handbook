"""
Unified Access Control Configuration and Deployment Infrastructure

Comprehensive configuration management for the unified access control system with
enterprise-grade deployment, monitoring, and operational capabilities.

This module provides:
- UnifiedAccessConfig: Central configuration for all access control components
- PlatformConfig: Platform-specific configuration management
- Deployment and orchestration configuration
- Environment-specific settings and secrets management
- Performance tuning and operational parameters
- Health monitoring and alerting configuration

Classification: UNCLASSIFIED//FOR OFFICIAL USE ONLY
"""

import os
import json
import logging
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, field
from pathlib import Path
from datetime import timedelta

# Import database connection
from ...rbac.models.base import DatabaseConnection

logger = logging.getLogger(__name__)


@dataclass
class DatabaseConfig:
    """Database configuration settings."""
    host: str = "localhost"
    port: int = 5432
    database: str = "unified_access_control"
    username: str = "postgres"
    password: str = ""
    ssl_mode: str = "require"
    pool_size: int = 20
    max_overflow: int = 30
    pool_timeout: int = 30
    pool_recycle: int = 3600
    
    def to_connection_string(self) -> str:
        """Generate database connection string."""
        return (
            f"postgresql://{self.username}:{self.password}@"
            f"{self.host}:{self.port}/{self.database}"
            f"?sslmode={self.ssl_mode}"
        )


@dataclass
class CacheConfig:
    """Cache configuration settings."""
    redis_host: str = "localhost"
    redis_port: int = 6379
    redis_password: str = ""
    redis_db: int = 0
    ttl_seconds: int = 300
    max_size: int = 10000
    enable_compression: bool = True
    cluster_mode: bool = False
    cluster_nodes: List[str] = field(default_factory=list)


@dataclass
class VaultConfig:
    """HashiCorp Vault configuration."""
    url: str = "https://vault.example.com"
    token: str = ""
    mount_path: str = "kv"
    auth_method: str = "token"  # token, aws, kubernetes, etc.
    role: str = ""
    namespace: str = ""
    timeout: int = 30
    verify_ssl: bool = True
    ca_cert_path: str = ""


@dataclass
class OAuthPlatformConfig:
    """OAuth configuration for a specific platform."""
    client_id: str
    client_secret: str
    authorization_url: str
    token_url: str
    redirect_uri: str
    scopes: List[str] = field(default_factory=list)
    audience: Optional[str] = None
    issuer: Optional[str] = None
    jwks_uri: Optional[str] = None
    use_pkce: bool = True
    token_endpoint_auth_method: str = "client_secret_basic"


@dataclass
class PlatformConfig:
    """Configuration for a specific platform integration."""
    name: str
    enabled: bool = True
    adapter_class: str = ""
    base_url: str = ""
    api_version: str = "v1"
    timeout: int = 30
    max_retries: int = 3
    retry_delay: float = 1.0
    circuit_breaker_threshold: int = 5
    circuit_breaker_timeout: int = 300
    oauth: Optional[OAuthPlatformConfig] = None
    custom_settings: Dict[str, Any] = field(default_factory=dict)
    health_check_endpoint: Optional[str] = None
    metrics_endpoint: Optional[str] = None


@dataclass
class SecurityConfig:
    """Security configuration settings."""
    enable_cac_piv: bool = True
    require_cac_for_admin: bool = True
    enable_emergency_access: bool = True
    emergency_access_timeout_hours: int = 4
    session_timeout_hours: int = 8
    platform_session_timeout_hours: int = 2
    max_concurrent_sessions: int = 5
    enable_session_tracking: bool = True
    enable_geo_blocking: bool = False
    allowed_ip_ranges: List[str] = field(default_factory=list)
    blocked_ip_ranges: List[str] = field(default_factory=list)
    enable_rate_limiting: bool = True
    rate_limit_requests_per_minute: int = 100


@dataclass
class AuditConfig:
    """Audit logging configuration."""
    enabled: bool = True
    batch_size: int = 100
    batch_timeout: int = 10
    enable_compression: bool = True
    retention_days: int = 2555  # 7 years for DoD compliance
    enable_real_time_alerts: bool = True
    alert_severity_threshold: str = "medium"
    storage_backend: str = "database"  # database, s3, azure, etc.
    encryption_enabled: bool = True
    tamper_proof: bool = True
    compliance_standards: List[str] = field(default_factory=lambda: ["dod_8500", "nist_sp_800_53"])


@dataclass
class MonitoringConfig:
    """Monitoring and alerting configuration."""
    enable_metrics: bool = True
    metrics_port: int = 9090
    metrics_path: str = "/metrics"
    enable_health_checks: bool = True
    health_check_port: int = 8080
    health_check_path: str = "/health"
    prometheus_enabled: bool = True
    grafana_enabled: bool = True
    alert_manager_url: str = ""
    smtp_server: str = ""
    smtp_port: int = 587
    smtp_username: str = ""
    smtp_password: str = ""
    alert_recipients: List[str] = field(default_factory=list)


@dataclass
class PerformanceConfig:
    """Performance tuning configuration."""
    max_worker_threads: int = 10
    async_timeout: int = 30
    connection_pool_size: int = 20
    enable_async_processing: bool = True
    batch_processing_enabled: bool = True
    cache_optimization_enabled: bool = True
    performance_monitoring: bool = True
    slow_query_threshold_ms: int = 1000
    response_time_sla_ms: int = 50


@dataclass
class DeploymentConfig:
    """Deployment and orchestration configuration."""
    environment: str = "development"  # development, staging, production
    deployment_mode: str = "standalone"  # standalone, kubernetes, docker_swarm
    replica_count: int = 1
    auto_scaling_enabled: bool = False
    min_replicas: int = 1
    max_replicas: int = 10
    cpu_request: str = "100m"
    cpu_limit: str = "500m"
    memory_request: str = "256Mi"
    memory_limit: str = "512Mi"
    persistent_volume_size: str = "10Gi"
    config_map_name: str = "unified-access-config"
    secret_name: str = "unified-access-secrets"
    namespace: str = "default"


class UnifiedAccessConfig:
    """
    Central configuration for the unified access control system.
    
    Manages all configuration aspects including:
    - Database connections and pooling
    - Platform integrations and OAuth settings
    - Security policies and authentication methods
    - Performance tuning and optimization
    - Audit logging and compliance requirements
    - Monitoring and alerting
    - Deployment and operational parameters
    """
    
    def __init__(self, config_file: Optional[str] = None, environment: str = "development"):
        """
        Initialize unified access configuration.
        
        Args:
            config_file: Path to configuration file (JSON/YAML)
            environment: Deployment environment
        """
        self.environment = environment
        self.config_file = config_file
        
        # Initialize with defaults
        self.database = DatabaseConfig()
        self.cache = CacheConfig()
        self.vault = VaultConfig()
        self.security = SecurityConfig()
        self.audit = AuditConfig()
        self.monitoring = MonitoringConfig()
        self.performance = PerformanceConfig()
        self.deployment = DeploymentConfig(environment=environment)
        
        # Platform configurations
        self.platform_configs: Dict[str, PlatformConfig] = {}
        
        # Load configuration from file or environment
        if config_file:
            self._load_from_file(config_file)
        else:
            self._load_from_environment()
        
        # Validate configuration
        self._validate_configuration()
        
        # Create database connection
        self._database_connection = None
        
        logger.info(f"Unified Access Configuration initialized for environment: {environment}")
    
    def _load_from_file(self, config_file: str):
        """Load configuration from file."""
        try:
            config_path = Path(config_file)
            
            if not config_path.exists():
                logger.warning(f"Configuration file not found: {config_file}")
                return
            
            with open(config_path, 'r') as f:
                if config_path.suffix.lower() == '.json':
                    config_data = json.load(f)
                elif config_path.suffix.lower() in ['.yml', '.yaml']:
                    import yaml
                    config_data = yaml.safe_load(f)
                else:
                    logger.error(f"Unsupported configuration file format: {config_path.suffix}")
                    return
            
            self._apply_config_data(config_data)
            logger.info(f"Configuration loaded from file: {config_file}")
            
        except Exception as e:
            logger.error(f"Failed to load configuration from file {config_file}: {e}")
    
    def _load_from_environment(self):
        """Load configuration from environment variables."""
        try:
            # Database configuration
            if os.getenv('UAC_DB_HOST'):
                self.database.host = os.getenv('UAC_DB_HOST')
            if os.getenv('UAC_DB_PORT'):
                self.database.port = int(os.getenv('UAC_DB_PORT'))
            if os.getenv('UAC_DB_NAME'):
                self.database.database = os.getenv('UAC_DB_NAME')
            if os.getenv('UAC_DB_USER'):
                self.database.username = os.getenv('UAC_DB_USER')
            if os.getenv('UAC_DB_PASSWORD'):
                self.database.password = os.getenv('UAC_DB_PASSWORD')
            
            # Cache configuration
            if os.getenv('UAC_REDIS_HOST'):
                self.cache.redis_host = os.getenv('UAC_REDIS_HOST')
            if os.getenv('UAC_REDIS_PORT'):
                self.cache.redis_port = int(os.getenv('UAC_REDIS_PORT'))
            if os.getenv('UAC_REDIS_PASSWORD'):
                self.cache.redis_password = os.getenv('UAC_REDIS_PASSWORD')
            
            # Vault configuration
            if os.getenv('UAC_VAULT_URL'):
                self.vault.url = os.getenv('UAC_VAULT_URL')
            if os.getenv('UAC_VAULT_TOKEN'):
                self.vault.token = os.getenv('UAC_VAULT_TOKEN')
            
            # Security configuration
            if os.getenv('UAC_ENABLE_CAC_PIV'):
                self.security.enable_cac_piv = os.getenv('UAC_ENABLE_CAC_PIV').lower() == 'true'
            if os.getenv('UAC_ENABLE_EMERGENCY_ACCESS'):
                self.security.enable_emergency_access = os.getenv('UAC_ENABLE_EMERGENCY_ACCESS').lower() == 'true'
            
            # Performance configuration
            if os.getenv('UAC_MAX_WORKER_THREADS'):
                self.performance.max_worker_threads = int(os.getenv('UAC_MAX_WORKER_THREADS'))
            if os.getenv('UAC_RESPONSE_TIME_SLA_MS'):
                self.performance.response_time_sla_ms = int(os.getenv('UAC_RESPONSE_TIME_SLA_MS'))
            
            logger.info("Configuration loaded from environment variables")
            
        except Exception as e:
            logger.error(f"Failed to load configuration from environment: {e}")
    
    def _apply_config_data(self, config_data: Dict[str, Any]):
        """Apply configuration data from loaded file."""
        try:
            # Apply database config
            if 'database' in config_data:
                db_config = config_data['database']
                for key, value in db_config.items():
                    if hasattr(self.database, key):
                        setattr(self.database, key, value)
            
            # Apply cache config
            if 'cache' in config_data:
                cache_config = config_data['cache']
                for key, value in cache_config.items():
                    if hasattr(self.cache, key):
                        setattr(self.cache, key, value)
            
            # Apply vault config
            if 'vault' in config_data:
                vault_config = config_data['vault']
                for key, value in vault_config.items():
                    if hasattr(self.vault, key):
                        setattr(self.vault, key, value)
            
            # Apply security config
            if 'security' in config_data:
                security_config = config_data['security']
                for key, value in security_config.items():
                    if hasattr(self.security, key):
                        setattr(self.security, key, value)
            
            # Apply audit config
            if 'audit' in config_data:
                audit_config = config_data['audit']
                for key, value in audit_config.items():
                    if hasattr(self.audit, key):
                        setattr(self.audit, key, value)
            
            # Apply monitoring config
            if 'monitoring' in config_data:
                monitoring_config = config_data['monitoring']
                for key, value in monitoring_config.items():
                    if hasattr(self.monitoring, key):
                        setattr(self.monitoring, key, value)
            
            # Apply performance config
            if 'performance' in config_data:
                performance_config = config_data['performance']
                for key, value in performance_config.items():
                    if hasattr(self.performance, key):
                        setattr(self.performance, key, value)
            
            # Apply deployment config
            if 'deployment' in config_data:
                deployment_config = config_data['deployment']
                for key, value in deployment_config.items():
                    if hasattr(self.deployment, key):
                        setattr(self.deployment, key, value)
            
            # Apply platform configs
            if 'platforms' in config_data:
                platforms_config = config_data['platforms']
                for platform_name, platform_data in platforms_config.items():
                    oauth_config = None
                    if 'oauth' in platform_data:
                        oauth_data = platform_data['oauth']
                        oauth_config = OAuthPlatformConfig(**oauth_data)
                    
                    platform_config = PlatformConfig(
                        name=platform_name,
                        oauth=oauth_config,
                        **{k: v for k, v in platform_data.items() if k != 'oauth'}
                    )
                    
                    self.platform_configs[platform_name] = platform_config
            
        except Exception as e:
            logger.error(f"Failed to apply configuration data: {e}")
    
    def _validate_configuration(self):
        """Validate configuration settings."""
        errors = []
        
        # Validate database configuration
        if not self.database.host:
            errors.append("Database host is required")
        if not self.database.database:
            errors.append("Database name is required")
        if not self.database.username:
            errors.append("Database username is required")
        
        # Validate security configuration
        if self.security.session_timeout_hours <= 0:
            errors.append("Session timeout must be positive")
        if self.security.max_concurrent_sessions <= 0:
            errors.append("Max concurrent sessions must be positive")
        
        # Validate performance configuration
        if self.performance.max_worker_threads <= 0:
            errors.append("Max worker threads must be positive")
        if self.performance.response_time_sla_ms <= 0:
            errors.append("Response time SLA must be positive")
        
        # Validate audit configuration
        if self.audit.retention_days <= 0:
            errors.append("Audit retention days must be positive")
        if self.audit.batch_size <= 0:
            errors.append("Audit batch size must be positive")
        
        # Validate platform configurations
        for platform_name, platform_config in self.platform_configs.items():
            if not platform_config.name:
                errors.append(f"Platform {platform_name} name is required")
            if platform_config.oauth:
                oauth = platform_config.oauth
                if not oauth.client_id:
                    errors.append(f"Platform {platform_name} OAuth client_id is required")
                if not oauth.authorization_url:
                    errors.append(f"Platform {platform_name} OAuth authorization_url is required")
                if not oauth.token_url:
                    errors.append(f"Platform {platform_name} OAuth token_url is required")
        
        if errors:
            error_message = "Configuration validation failed:\n" + "\n".join(f"- {error}" for error in errors)
            logger.error(error_message)
            raise ValueError(error_message)
        
        logger.info("Configuration validation passed")
    
    @property
    def database_connection(self) -> DatabaseConnection:
        """Get database connection instance."""
        if not self._database_connection:
            self._database_connection = DatabaseConnection(
                connection_string=self.database.to_connection_string(),
                pool_size=self.database.pool_size,
                max_overflow=self.database.max_overflow,
                pool_timeout=self.database.pool_timeout,
                pool_recycle=self.database.pool_recycle
            )
        
        return self._database_connection
    
    # Convenience properties for commonly used settings
    
    @property
    def cache_ttl(self) -> int:
        """Get cache TTL in seconds."""
        return self.cache.ttl_seconds
    
    @property
    def cache_size(self) -> int:
        """Get cache max size."""
        return self.cache.max_size
    
    @property
    def enable_cac_piv(self) -> bool:
        """Check if CAC/PIV authentication is enabled."""
        return self.security.enable_cac_piv
    
    @property
    def enable_emergency_access(self) -> bool:
        """Check if emergency access is enabled."""
        return self.security.enable_emergency_access
    
    @property
    def session_timeout_hours(self) -> int:
        """Get session timeout in hours."""
        return self.security.session_timeout_hours
    
    @property
    def max_worker_threads(self) -> int:
        """Get max worker threads."""
        return self.performance.max_worker_threads
    
    @property
    def response_time_sla_ms(self) -> int:
        """Get response time SLA in milliseconds."""
        return self.performance.response_time_sla_ms
    
    @property
    def audit_batch_size(self) -> int:
        """Get audit batch size."""
        return self.audit.batch_size
    
    @property
    def audit_batch_timeout(self) -> int:
        """Get audit batch timeout in seconds."""
        return self.audit.batch_timeout
    
    @property
    def audit_enable_compression(self) -> bool:
        """Check if audit compression is enabled."""
        return self.audit.enable_compression
    
    @property
    def audit_retention_days(self) -> int:
        """Get audit retention period in days."""
        return self.audit.retention_days
    
    @property
    def audit_worker_threads(self) -> int:
        """Get audit worker threads."""
        return min(self.performance.max_worker_threads, 4)
    
    @property
    def session_sync_interval(self) -> int:
        """Get session sync interval in seconds."""
        return 60  # 1 minute default
    
    def get_platform_config(self, platform_name: str) -> Optional[PlatformConfig]:
        """Get configuration for a specific platform."""
        return self.platform_configs.get(platform_name)
    
    def add_platform_config(self, platform_config: PlatformConfig):
        """Add platform configuration."""
        self.platform_configs[platform_config.name] = platform_config
        logger.info(f"Added platform configuration: {platform_config.name}")
    
    def remove_platform_config(self, platform_name: str):
        """Remove platform configuration."""
        if platform_name in self.platform_configs:
            del self.platform_configs[platform_name]
            logger.info(f"Removed platform configuration: {platform_name}")
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary."""
        return {
            'environment': self.environment,
            'database': {
                'host': self.database.host,
                'port': self.database.port,
                'database': self.database.database,
                'username': self.database.username,
                # Don't include password in serialization
                'ssl_mode': self.database.ssl_mode,
                'pool_size': self.database.pool_size
            },
            'cache': {
                'redis_host': self.cache.redis_host,
                'redis_port': self.cache.redis_port,
                'redis_db': self.cache.redis_db,
                'ttl_seconds': self.cache.ttl_seconds,
                'max_size': self.cache.max_size
            },
            'security': {
                'enable_cac_piv': self.security.enable_cac_piv,
                'enable_emergency_access': self.security.enable_emergency_access,
                'session_timeout_hours': self.security.session_timeout_hours,
                'max_concurrent_sessions': self.security.max_concurrent_sessions
            },
            'audit': {
                'enabled': self.audit.enabled,
                'batch_size': self.audit.batch_size,
                'retention_days': self.audit.retention_days,
                'enable_compression': self.audit.enable_compression
            },
            'performance': {
                'max_worker_threads': self.performance.max_worker_threads,
                'response_time_sla_ms': self.performance.response_time_sla_ms,
                'connection_pool_size': self.performance.connection_pool_size
            },
            'platforms': {
                name: {
                    'name': config.name,
                    'enabled': config.enabled,
                    'base_url': config.base_url,
                    'timeout': config.timeout,
                    'max_retries': config.max_retries
                    # Don't include OAuth secrets in serialization
                } for name, config in self.platform_configs.items()
            }
        }
    
    def save_to_file(self, output_file: str):
        """Save configuration to file."""
        try:
            config_data = self.to_dict()
            
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(output_path, 'w') as f:
                if output_path.suffix.lower() == '.json':
                    json.dump(config_data, f, indent=2)
                elif output_path.suffix.lower() in ['.yml', '.yaml']:
                    import yaml
                    yaml.safe_dump(config_data, f, indent=2)
                else:
                    raise ValueError(f"Unsupported output format: {output_path.suffix}")
            
            logger.info(f"Configuration saved to file: {output_file}")
            
        except Exception as e:
            logger.error(f"Failed to save configuration to file {output_file}: {e}")
            raise
    
    def close(self):
        """Close configuration and cleanup resources."""
        if self._database_connection:
            self._database_connection.close()
            self._database_connection = None
        
        logger.info("Unified Access Configuration closed")