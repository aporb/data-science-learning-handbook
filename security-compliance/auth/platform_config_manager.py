#!/usr/bin/env python3
"""
Platform Configuration Manager for CAC/PIV Integration
Centralized configuration management for all platform adapters
"""

import os
import json
import yaml
import logging
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, asdict
from pathlib import Path
from cryptography.fernet import Fernet
import base64

from .platform_adapters import PlatformConfig, MiddlewareType

logger = logging.getLogger(__name__)

@dataclass
class GlobalCAMConfig:
    """Global CAC/PIV configuration"""
    middleware_preference: MiddlewareType = MiddlewareType.ACTIVCLIENT
    enable_pin_caching: bool = True
    session_timeout: int = 3600
    max_retry_attempts: int = 3
    audit_enabled: bool = True
    encryption_enabled: bool = True
    auto_discover_middleware: bool = True

@dataclass
class SecurityConfig:
    """Security configuration for CAC/PIV system"""
    require_certificate_validation: bool = True
    enable_revocation_checking: bool = True
    allowed_certificate_authorities: List[str] = None
    minimum_key_size: int = 2048
    allowed_signature_algorithms: List[str] = None
    session_encryption_key: Optional[str] = None
    
    def __post_init__(self):
        if self.allowed_certificate_authorities is None:
            self.allowed_certificate_authorities = [
                "DoD Root CA 2", "DoD Root CA 3", "DoD Root CA 4", "DoD Root CA 5"
            ]
        if self.allowed_signature_algorithms is None:
            self.allowed_signature_algorithms = ["SHA256withRSA", "SHA384withRSA", "SHA256withECDSA"]

class PlatformConfigManager:
    """
    Centralized configuration manager for all platform adapters
    Handles configuration loading, validation, and secure storage
    """
    
    def __init__(self, config_dir: str = None, encryption_key: str = None):
        """
        Initialize configuration manager
        
        Args:
            config_dir: Directory for configuration files
            encryption_key: Key for encrypting sensitive data
        """
        self.config_dir = Path(config_dir) if config_dir else Path.cwd() / "config"
        self.config_dir.mkdir(exist_ok=True)
        
        # Initialize encryption
        self.encryption_key = encryption_key or os.environ.get('CAC_CONFIG_ENCRYPTION_KEY')
        if self.encryption_key:
            try:
                self.cipher = Fernet(self.encryption_key.encode() if isinstance(self.encryption_key, str) else self.encryption_key)
            except Exception:
                # Generate new key if invalid
                self.encryption_key = Fernet.generate_key().decode()
                self.cipher = Fernet(self.encryption_key.encode())
                logger.warning("Generated new encryption key for configuration")
        else:
            self.encryption_key = Fernet.generate_key().decode()
            self.cipher = Fernet(self.encryption_key.encode())
        
        # Initialize configurations
        self.global_config = GlobalCAMConfig()
        self.security_config = SecurityConfig()
        self.platform_configs = {}
        self.environment_configs = {}
        
        # Load existing configurations
        self._load_configurations()
        
        logger.info(f"Configuration manager initialized with config dir: {self.config_dir}")
    
    def _load_configurations(self):
        """Load all configuration files"""
        try:
            # Load global configuration
            global_config_file = self.config_dir / "global_config.yaml"
            if global_config_file.exists():
                with open(global_config_file, 'r') as f:
                    global_data = yaml.safe_load(f)
                    self.global_config = GlobalCAMConfig(**global_data)
            
            # Load security configuration
            security_config_file = self.config_dir / "security_config.yaml"
            if security_config_file.exists():
                with open(security_config_file, 'r') as f:
                    security_data = yaml.safe_load(f)
                    self.security_config = SecurityConfig(**security_data)
            
            # Load platform configurations
            platform_config_dir = self.config_dir / "platforms"
            if platform_config_dir.exists():
                for config_file in platform_config_dir.glob("*.yaml"):
                    platform_name = config_file.stem
                    with open(config_file, 'r') as f:
                        platform_data = yaml.safe_load(f)
                        # Decrypt sensitive data
                        platform_data = self._decrypt_sensitive_data(platform_data)
                        self.platform_configs[platform_name] = PlatformConfig(**platform_data)
            
            # Load environment configurations
            env_config_dir = self.config_dir / "environments"
            if env_config_dir.exists():
                for config_file in env_config_dir.glob("*.yaml"):
                    env_name = config_file.stem
                    with open(config_file, 'r') as f:
                        env_data = yaml.safe_load(f)
                        self.environment_configs[env_name] = env_data
            
            logger.info("Configurations loaded successfully")
            
        except Exception as e:
            logger.error(f"Error loading configurations: {e}")
    
    def save_configurations(self):
        """Save all configurations to files"""
        try:
            # Save global configuration
            global_config_file = self.config_dir / "global_config.yaml"
            with open(global_config_file, 'w') as f:
                yaml.dump(asdict(self.global_config), f, default_flow_style=False)
            
            # Save security configuration
            security_config_file = self.config_dir / "security_config.yaml"
            with open(security_config_file, 'w') as f:
                yaml.dump(asdict(self.security_config), f, default_flow_style=False)
            
            # Save platform configurations
            platform_config_dir = self.config_dir / "platforms"
            platform_config_dir.mkdir(exist_ok=True)
            
            for platform_name, config in self.platform_configs.items():
                config_file = platform_config_dir / f"{platform_name}.yaml"
                config_data = asdict(config)
                # Encrypt sensitive data
                config_data = self._encrypt_sensitive_data(config_data)
                
                with open(config_file, 'w') as f:
                    yaml.dump(config_data, f, default_flow_style=False)
            
            # Save environment configurations
            env_config_dir = self.config_dir / "environments"
            env_config_dir.mkdir(exist_ok=True)
            
            for env_name, config in self.environment_configs.items():
                config_file = env_config_dir / f"{env_name}.yaml"
                with open(config_file, 'w') as f:
                    yaml.dump(config, f, default_flow_style=False)
            
            logger.info("Configurations saved successfully")
            
        except Exception as e:
            logger.error(f"Error saving configurations: {e}")
            raise
    
    def add_platform_config(self, platform_name: str, config: PlatformConfig):
        """
        Add or update platform configuration
        
        Args:
            platform_name: Name of the platform
            config: Platform configuration
        """
        self.platform_configs[platform_name] = config
        logger.info(f"Added/updated configuration for platform: {platform_name}")
    
    def get_platform_config(self, platform_name: str, environment: str = "production") -> Optional[PlatformConfig]:
        """
        Get platform configuration for specific environment
        
        Args:
            platform_name: Name of the platform
            environment: Environment name (dev, test, prod)
            
        Returns:
            Platform configuration or None if not found
        """
        base_config = self.platform_configs.get(platform_name)
        if not base_config:
            return None
        
        # Apply environment-specific overrides
        env_config = self.environment_configs.get(environment, {})
        platform_env_config = env_config.get(platform_name, {})
        
        if platform_env_config:
            # Create a copy and apply overrides
            config_dict = asdict(base_config)
            config_dict.update(platform_env_config)
            return PlatformConfig(**config_dict)
        
        return base_config
    
    def create_default_configs(self):
        """Create default configurations for all supported platforms"""
        
        # Advana configuration
        advana_config = PlatformConfig(
            platform_name="advana",
            base_url="https://advana.data.mil",
            api_version="v1",
            authentication_endpoint="/api/v1/auth/cac",
            token_endpoint="/api/v1/auth/token",
            user_info_endpoint="/api/v1/user/profile",
            timeout=30,
            max_retries=3,
            verify_ssl=True,
            additional_config={
                "tenant_id": "your-tenant-id",
                "environment": "prod",
                "classification_level": "UNCLASSIFIED"
            }
        )
        self.add_platform_config("advana", advana_config)
        
        # Qlik configuration
        qlik_config = PlatformConfig(
            platform_name="qlik",
            base_url="https://your-qlik-server.mil",
            api_version="v1",
            authentication_endpoint="/api/v1/auth/certificate",
            token_endpoint="/api/v1/auth/jwt",
            user_info_endpoint="/api/v1/users/me",
            timeout=30,
            max_retries=3,
            verify_ssl=True,
            additional_config={
                "qlik_domain": "qlik.local",
                "virtual_proxy": "",
                "app_access_point": "/hub",
                "certificate_header": "X-Qlik-User",
                "jwt_secret": "your-jwt-secret",
                "jwt_algorithm": "HS256"
            }
        )
        self.add_platform_config("qlik", qlik_config)
        
        # Databricks configuration
        databricks_config = PlatformConfig(
            platform_name="databricks",
            base_url="https://your-workspace.cloud.databricks.mil",
            api_version="2.0",
            authentication_endpoint="/api/2.0/preview/scim/v2/Users",
            token_endpoint="/api/2.0/token/create",
            user_info_endpoint="/api/2.0/preview/scim/v2/Me",
            timeout=30,
            max_retries=3,
            verify_ssl=True,
            additional_config={
                "workspace_id": "your-workspace-id",
                "workspace_url": "https://your-workspace.cloud.databricks.mil",
                "instance_pool_id": "your-instance-pool-id",
                "cluster_policy_id": "your-cluster-policy-id",
                "auth_method": "personal_access_token",
                "service_principal_id": "your-service-principal-id"
            }
        )
        self.add_platform_config("databricks", databricks_config)
        
        # Navy Jupiter configuration
        navy_jupiter_config = PlatformConfig(
            platform_name="navy_jupiter",
            base_url="https://navy-jupiter.navy.mil",
            api_version="v1",
            authentication_endpoint="/api/v1/auth/cac",
            token_endpoint="/api/v1/auth/token",
            user_info_endpoint="/api/v1/user/profile",
            timeout=30,
            max_retries=3,
            verify_ssl=True,
            additional_config={
                "navy_network": "NIPR",
                "classification_level": "UNCLASSIFIED",
                "command_code": "your-command-code",
                "facility_code": "your-facility-code",
                "enclave_id": "your-enclave-id",
                "require_dual_auth": False,
                "session_timeout": 3600,
                "max_concurrent_sessions": 1
            }
        )
        self.add_platform_config("navy_jupiter", navy_jupiter_config)
        
        # Create environment configurations
        self.environment_configs["development"] = {
            "advana": {
                "base_url": "https://advana-dev.data.mil",
                "verify_ssl": False
            },
            "qlik": {
                "base_url": "https://qlik-dev.local",
                "verify_ssl": False
            },
            "databricks": {
                "base_url": "https://workspace-dev.cloud.databricks.mil"
            },
            "navy_jupiter": {
                "base_url": "https://navy-jupiter-dev.navy.mil",
                "verify_ssl": False
            }
        }
        
        self.environment_configs["testing"] = {
            "advana": {
                "base_url": "https://advana-test.data.mil"
            },
            "qlik": {
                "base_url": "https://qlik-test.local"
            },
            "databricks": {
                "base_url": "https://workspace-test.cloud.databricks.mil"
            },
            "navy_jupiter": {
                "base_url": "https://navy-jupiter-test.navy.mil"
            }
        }
        
        logger.info("Default configurations created")
    
    def validate_configuration(self, platform_name: str, config: PlatformConfig) -> Dict[str, Any]:
        """
        Validate platform configuration
        
        Args:
            platform_name: Name of the platform
            config: Configuration to validate
            
        Returns:
            Validation result
        """
        validation_result = {
            "valid": True,
            "errors": [],
            "warnings": []
        }
        
        # Required fields validation
        required_fields = ["platform_name", "base_url", "api_version"]
        for field in required_fields:
            if not getattr(config, field):
                validation_result["errors"].append(f"Missing required field: {field}")
                validation_result["valid"] = False
        
        # URL validation
        if config.base_url and not config.base_url.startswith(('http://', 'https://')):
            validation_result["errors"].append("base_url must start with http:// or https://")
            validation_result["valid"] = False
        
        # SSL verification warning
        if not config.verify_ssl:
            validation_result["warnings"].append("SSL verification is disabled - not recommended for production")
        
        # Platform-specific validation
        if platform_name == "advana":
            self._validate_advana_config(config, validation_result)
        elif platform_name == "qlik":
            self._validate_qlik_config(config, validation_result)
        elif platform_name == "databricks":
            self._validate_databricks_config(config, validation_result)
        elif platform_name == "navy_jupiter":
            self._validate_navy_jupiter_config(config, validation_result)
        
        return validation_result
    
    def _validate_advana_config(self, config: PlatformConfig, validation_result: Dict[str, Any]):
        """Validate Advana-specific configuration"""
        additional_config = config.additional_config or {}
        
        if not additional_config.get("tenant_id"):
            validation_result["warnings"].append("Advana tenant_id not specified")
        
        classification = additional_config.get("classification_level", "UNCLASSIFIED")
        valid_classifications = ["UNCLASSIFIED", "CONFIDENTIAL", "SECRET", "TOP_SECRET"]
        if classification not in valid_classifications:
            validation_result["errors"].append(f"Invalid classification level: {classification}")
            validation_result["valid"] = False
    
    def _validate_qlik_config(self, config: PlatformConfig, validation_result: Dict[str, Any]):
        """Validate Qlik-specific configuration"""
        additional_config = config.additional_config or {}
        
        if not additional_config.get("qlik_domain"):
            validation_result["warnings"].append("Qlik domain not specified, using default")
        
        if additional_config.get("jwt_secret") and len(additional_config["jwt_secret"]) < 32:
            validation_result["warnings"].append("JWT secret should be at least 32 characters for security")
    
    def _validate_databricks_config(self, config: PlatformConfig, validation_result: Dict[str, Any]):
        """Validate Databricks-specific configuration"""
        additional_config = config.additional_config or {}
        
        if not additional_config.get("workspace_id"):
            validation_result["warnings"].append("Databricks workspace_id not specified")
        
        auth_method = additional_config.get("auth_method", "personal_access_token")
        valid_auth_methods = ["personal_access_token", "service_principal"]
        if auth_method not in valid_auth_methods:
            validation_result["errors"].append(f"Invalid auth_method: {auth_method}")
            validation_result["valid"] = False
    
    def _validate_navy_jupiter_config(self, config: PlatformConfig, validation_result: Dict[str, Any]):
        """Validate Navy Jupiter-specific configuration"""
        additional_config = config.additional_config or {}
        
        navy_network = additional_config.get("navy_network", "NIPR")
        valid_networks = ["NIPR", "SIPR"]
        if navy_network not in valid_networks:
            validation_result["errors"].append(f"Invalid navy_network: {navy_network}")
            validation_result["valid"] = False
        
        if not additional_config.get("command_code"):
            validation_result["warnings"].append("Navy command_code not specified")
    
    def _encrypt_sensitive_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Encrypt sensitive configuration data"""
        if not self.cipher:
            return data
        
        sensitive_fields = [
            "jwt_secret", "service_principal_id", "api_key", "secret_key",
            "password", "token", "private_key"
        ]
        
        encrypted_data = data.copy()
        
        def encrypt_recursive(obj):
            if isinstance(obj, dict):
                for key, value in obj.items():
                    if key.lower() in sensitive_fields and isinstance(value, str):
                        try:
                            encrypted_value = self.cipher.encrypt(value.encode()).decode()
                            obj[key] = f"encrypted:{encrypted_value}"
                        except Exception as e:
                            logger.warning(f"Failed to encrypt field {key}: {e}")
                    elif isinstance(value, (dict, list)):
                        encrypt_recursive(value)
            elif isinstance(obj, list):
                for item in obj:
                    if isinstance(item, (dict, list)):
                        encrypt_recursive(item)
        
        encrypt_recursive(encrypted_data)
        return encrypted_data
    
    def _decrypt_sensitive_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Decrypt sensitive configuration data"""
        if not self.cipher:
            return data
        
        decrypted_data = data.copy()
        
        def decrypt_recursive(obj):
            if isinstance(obj, dict):
                for key, value in obj.items():
                    if isinstance(value, str) and value.startswith("encrypted:"):
                        try:
                            encrypted_value = value[10:]  # Remove "encrypted:" prefix
                            decrypted_value = self.cipher.decrypt(encrypted_value.encode()).decode()
                            obj[key] = decrypted_value
                        except Exception as e:
                            logger.warning(f"Failed to decrypt field {key}: {e}")
                    elif isinstance(value, (dict, list)):
                        decrypt_recursive(value)
            elif isinstance(obj, list):
                for item in obj:
                    if isinstance(item, (dict, list)):
                        decrypt_recursive(item)
        
        decrypt_recursive(decrypted_data)
        return decrypted_data
    
    def export_configuration(self, output_file: str, include_sensitive: bool = False):
        """
        Export all configurations to a single file
        
        Args:
            output_file: Output file path
            include_sensitive: Whether to include sensitive data
        """
        export_data = {
            "global_config": asdict(self.global_config),
            "security_config": asdict(self.security_config),
            "platform_configs": {},
            "environment_configs": self.environment_configs,
            "metadata": {
                "exported_at": datetime.now(timezone.utc).isoformat(),
                "version": "1.0",
                "includes_sensitive": include_sensitive
            }
        }
        
        for platform_name, config in self.platform_configs.items():
            config_data = asdict(config)
            if not include_sensitive:
                config_data = self._encrypt_sensitive_data(config_data)
            export_data["platform_configs"][platform_name] = config_data
        
        with open(output_file, 'w') as f:
            yaml.dump(export_data, f, default_flow_style=False)
        
        logger.info(f"Configuration exported to: {output_file}")
    
    def import_configuration(self, input_file: str):
        """
        Import configurations from a file
        
        Args:
            input_file: Input file path
        """
        with open(input_file, 'r') as f:
            import_data = yaml.safe_load(f)
        
        # Import global config
        if "global_config" in import_data:
            self.global_config = GlobalCAMConfig(**import_data["global_config"])
        
        # Import security config
        if "security_config" in import_data:
            self.security_config = SecurityConfig(**import_data["security_config"])
        
        # Import platform configs
        if "platform_configs" in import_data:
            for platform_name, config_data in import_data["platform_configs"].items():
                # Decrypt sensitive data if needed
                if not import_data.get("metadata", {}).get("includes_sensitive", False):
                    config_data = self._decrypt_sensitive_data(config_data)
                self.platform_configs[platform_name] = PlatformConfig(**config_data)
        
        # Import environment configs
        if "environment_configs" in import_data:
            self.environment_configs = import_data["environment_configs"]
        
        logger.info(f"Configuration imported from: {input_file}")
    
    def get_encryption_key(self) -> str:
        """Get the encryption key for external use"""
        return self.encryption_key
    
    def list_platforms(self) -> List[str]:
        """Get list of configured platforms"""
        return list(self.platform_configs.keys())
    
    def list_environments(self) -> List[str]:
        """Get list of configured environments"""
        return list(self.environment_configs.keys())
    
    def get_config_summary(self) -> Dict[str, Any]:
        """Get summary of all configurations"""
        return {
            "global_config": {
                "middleware_preference": self.global_config.middleware_preference.value,
                "session_timeout": self.global_config.session_timeout,
                "audit_enabled": self.global_config.audit_enabled
            },
            "security_config": {
                "certificate_validation": self.security_config.require_certificate_validation,
                "revocation_checking": self.security_config.enable_revocation_checking,
                "min_key_size": self.security_config.minimum_key_size
            },
            "platforms": {
                name: {
                    "base_url": config.base_url,
                    "api_version": config.api_version,
                    "timeout": config.timeout
                }
                for name, config in self.platform_configs.items()
            },
            "environments": list(self.environment_configs.keys())
        }