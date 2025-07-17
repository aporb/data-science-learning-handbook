"""
OAuth 2.0 Configuration for DoD Platforms
Platform-specific configurations for Advana, Qlik, Databricks, and Navy Jupiter.
"""

import os
from typing import Dict, List, Optional
from dataclasses import dataclass, field
from enum import Enum

from .oauth_client import Platform, OAuthConfig


class Environment(Enum):
    """Deployment environments."""
    DEVELOPMENT = "dev"
    STAGING = "staging"
    PRODUCTION = "prod"
    NIPR = "nipr"
    SIPR = "sipr"
    JWICS = "jwics"


@dataclass
class PlatformEndpoints:
    """Platform-specific OAuth endpoints."""
    authorization_url: str
    token_url: str
    userinfo_url: str
    jwks_uri: str
    revoke_url: Optional[str] = None
    introspect_url: Optional[str] = None


class DoD_OAuth_Configurator:
    """
    DoD OAuth 2.0 configuration manager.
    
    Provides environment-specific configurations for all supported DoD platforms
    with proper security settings and compliance requirements.
    """
    
    # Base URLs for different environments and classifications
    BASE_URLS = {
        Environment.NIPR: {
            Platform.ADVANA: "https://advana.data.mil",
            Platform.QLIK: "https://qlik.advana.data.mil",
            Platform.DATABRICKS: "https://databricks.advana.data.mil",
            Platform.NAVY_JUPITER: "https://jupiter.navy.mil",
        },
        Environment.SIPR: {
            Platform.ADVANA: "https://advana.data.smil.mil",
            Platform.QLIK: "https://qlik.advana.data.smil.mil",
            Platform.DATABRICKS: "https://databricks.advana.data.smil.mil",
            Platform.NAVY_JUPITER: "https://jupiter.navy.smil.mil",
        },
        Environment.JWICS: {
            Platform.ADVANA: "https://advana.data.ic.gov",
            Platform.QLIK: "https://qlik.advana.data.ic.gov",
            Platform.DATABRICKS: "https://databricks.advana.data.ic.gov",
            Platform.NAVY_JUPITER: "https://jupiter.navy.ic.gov",
        },
        Environment.DEVELOPMENT: {
            Platform.ADVANA: "https://dev.advana.data.mil",
            Platform.QLIK: "https://dev.qlik.advana.data.mil",
            Platform.DATABRICKS: "https://dev.databricks.advana.data.mil",
            Platform.NAVY_JUPITER: "https://dev.jupiter.navy.mil",
        },
        Environment.STAGING: {
            Platform.ADVANA: "https://staging.advana.data.mil",
            Platform.QLIK: "https://staging.qlik.advana.data.mil",
            Platform.DATABRICKS: "https://staging.databricks.advana.data.mil",
            Platform.NAVY_JUPITER: "https://staging.jupiter.navy.mil",
        }
    }
    
    # Platform-specific OAuth endpoints
    PLATFORM_ENDPOINTS = {
        Platform.ADVANA: PlatformEndpoints(
            authorization_url="/oauth2/authorize",
            token_url="/oauth2/token",
            userinfo_url="/oauth2/userinfo",
            jwks_uri="/oauth2/jwks",
            revoke_url="/oauth2/revoke",
            introspect_url="/oauth2/introspect"
        ),
        Platform.QLIK: PlatformEndpoints(
            authorization_url="/oauth/authorize",
            token_url="/oauth/token",
            userinfo_url="/oauth/userinfo",
            jwks_uri="/oauth/jwks",
            revoke_url="/oauth/revoke"
        ),
        Platform.DATABRICKS: PlatformEndpoints(
            authorization_url="/oidc/v1/authorize",
            token_url="/oidc/v1/token",
            userinfo_url="/oidc/v1/userinfo",
            jwks_uri="/oidc/v1/jwks",
            revoke_url="/oidc/v1/revoke"
        ),
        Platform.NAVY_JUPITER: PlatformEndpoints(
            authorization_url="/auth/oauth2/authorize",
            token_url="/auth/oauth2/token",
            userinfo_url="/auth/oauth2/userinfo",
            jwks_uri="/auth/oauth2/jwks",
            revoke_url="/auth/oauth2/revoke"
        )
    }
    
    # Default scopes for each platform
    DEFAULT_SCOPES = {
        Platform.ADVANA: [
            "openid", "profile", "email",
            "advana:read", "advana:write",
            "data:read", "data:write",
            "analytics:read", "analytics:write"
        ],
        Platform.QLIK: [
            "openid", "profile", "email",
            "qlik:read", "qlik:write", "qlik:admin",
            "apps:read", "apps:write", "apps:create",
            "spaces:read", "spaces:write"
        ],
        Platform.DATABRICKS: [
            "openid", "profile", "email",
            "databricks:read", "databricks:write", "databricks:admin",
            "clusters:read", "clusters:write", "clusters:create",
            "jobs:read", "jobs:write", "jobs:run",
            "notebooks:read", "notebooks:write"
        ],
        Platform.NAVY_JUPITER: [
            "openid", "profile", "email",
            "jupiter:read", "jupiter:write", "jupiter:compute",
            "hpc:read", "hpc:write", "hpc:submit",
            "storage:read", "storage:write"
        ]
    }
    
    # Security requirements by classification level
    SECURITY_REQUIREMENTS = {
        Environment.NIPR: {
            "min_key_size": 2048,
            "allowed_algorithms": ["RS256", "RS384", "RS512"],
            "token_lifetime": 3600,  # 1 hour
            "refresh_lifetime": 86400,  # 24 hours
            "require_pkce": True,
            "require_state": True,
            "require_nonce": True,
        },
        Environment.SIPR: {
            "min_key_size": 3072,
            "allowed_algorithms": ["RS384", "RS512", "ES384", "ES512"],
            "token_lifetime": 1800,  # 30 minutes
            "refresh_lifetime": 43200,  # 12 hours
            "require_pkce": True,
            "require_state": True,
            "require_nonce": True,
        },
        Environment.JWICS: {
            "min_key_size": 4096,
            "allowed_algorithms": ["RS512", "ES512"],
            "token_lifetime": 900,  # 15 minutes
            "refresh_lifetime": 21600,  # 6 hours
            "require_pkce": True,
            "require_state": True,
            "require_nonce": True,
        }
    }
    
    def __init__(self, environment: Environment = Environment.NIPR):
        """
        Initialize OAuth configurator.
        
        Args:
            environment: Target environment/classification level
        """
        self.environment = environment
        self.security_requirements = self.SECURITY_REQUIREMENTS.get(
            environment, 
            self.SECURITY_REQUIREMENTS[Environment.NIPR]
        )
    
    def create_config(self, 
                     platform: Platform,
                     client_id: str,
                     client_secret: str,
                     redirect_uri: str,
                     scopes: Optional[List[str]] = None,
                     additional_params: Optional[Dict[str, str]] = None) -> OAuthConfig:
        """
        Create OAuth configuration for a platform.
        
        Args:
            platform: Target platform
            client_id: OAuth client ID
            client_secret: OAuth client secret
            redirect_uri: OAuth redirect URI
            scopes: Optional custom scopes (uses defaults if not provided)
            additional_params: Additional configuration parameters
            
        Returns:
            Configured OAuthConfig instance
            
        Raises:
            ValueError: If platform or environment not supported
        """
        if platform not in self.PLATFORM_ENDPOINTS:
            raise ValueError(f"Unsupported platform: {platform}")
        
        if self.environment not in self.BASE_URLS:
            raise ValueError(f"Unsupported environment: {self.environment}")
        
        # Get base URL and endpoints
        base_url = self.BASE_URLS[self.environment][platform]
        endpoints = self.PLATFORM_ENDPOINTS[platform]
        
        # Use default scopes if not provided
        if scopes is None:
            scopes = self.DEFAULT_SCOPES[platform].copy()
        
        # Build full URLs
        authorization_url = f"{base_url}{endpoints.authorization_url}"
        token_url = f"{base_url}{endpoints.token_url}"
        jwks_uri = f"{base_url}{endpoints.jwks_uri}"
        
        # Create configuration
        config = OAuthConfig(
            platform=platform,
            client_id=client_id,
            client_secret=client_secret,
            authorization_url=authorization_url,
            token_url=token_url,
            redirect_uri=redirect_uri,
            scopes=scopes,
            audience=base_url,
            issuer=base_url,
            jwks_uri=jwks_uri,
            use_pkce=self.security_requirements["require_pkce"],
            token_endpoint_auth_method="client_secret_basic"
        )
        
        return config
    
    def create_config_from_env(self, platform: Platform) -> OAuthConfig:
        """
        Create OAuth configuration from environment variables.
        
        Args:
            platform: Target platform
            
        Returns:
            Configured OAuthConfig instance
            
        Raises:
            ValueError: If required environment variables are missing
        """
        platform_name = platform.value.upper()
        
        # Required environment variables
        client_id = os.getenv(f"{platform_name}_CLIENT_ID")
        client_secret = os.getenv(f"{platform_name}_CLIENT_SECRET")
        redirect_uri = os.getenv(f"{platform_name}_REDIRECT_URI")
        
        if not all([client_id, client_secret, redirect_uri]):
            missing = []
            if not client_id:
                missing.append(f"{platform_name}_CLIENT_ID")
            if not client_secret:
                missing.append(f"{platform_name}_CLIENT_SECRET")
            if not redirect_uri:
                missing.append(f"{platform_name}_REDIRECT_URI")
            
            raise ValueError(f"Missing required environment variables: {missing}")
        
        # Optional environment variables
        scopes_env = os.getenv(f"{platform_name}_SCOPES")
        scopes = scopes_env.split(",") if scopes_env else None
        
        return self.create_config(
            platform=platform,
            client_id=client_id,
            client_secret=client_secret,
            redirect_uri=redirect_uri,
            scopes=scopes
        )
    
    def get_all_configs(self) -> Dict[Platform, OAuthConfig]:
        """
        Get OAuth configurations for all platforms from environment variables.
        
        Returns:
            Dictionary mapping platforms to their OAuth configurations
            
        Raises:
            ValueError: If any required environment variables are missing
        """
        configs = {}
        
        for platform in Platform:
            try:
                config = self.create_config_from_env(platform)
                configs[platform] = config
            except ValueError as e:
                # Log warning but continue with other platforms
                print(f"Warning: Could not create config for {platform.value}: {e}")
        
        return configs
    
    def validate_config(self, config: OAuthConfig) -> List[str]:
        """
        Validate OAuth configuration against security requirements.
        
        Args:
            config: OAuth configuration to validate
            
        Returns:
            List of validation errors (empty if valid)
        """
        errors = []
        
        # Validate URLs use HTTPS
        urls_to_check = [
            config.authorization_url,
            config.token_url,
            config.jwks_uri
        ]
        
        for url in urls_to_check:
            if url and not url.startswith("https://"):
                errors.append(f"URL must use HTTPS: {url}")
        
        # Validate PKCE requirement
        if self.security_requirements["require_pkce"] and not config.use_pkce:
            errors.append("PKCE is required for this environment")
        
        # Validate scopes
        required_scopes = ["openid", "profile"]
        missing_scopes = [scope for scope in required_scopes if scope not in config.scopes]
        if missing_scopes:
            errors.append(f"Missing required scopes: {missing_scopes}")
        
        # Validate redirect URI
        if not config.redirect_uri.startswith("https://"):
            errors.append("Redirect URI must use HTTPS")
        
        return errors
    
    @classmethod
    def get_supported_platforms(cls) -> List[Platform]:
        """Get list of supported platforms."""
        return list(Platform)
    
    @classmethod
    def get_supported_environments(cls) -> List[Environment]:
        """Get list of supported environments."""
        return list(Environment)
    
    @classmethod
    def get_platform_scopes(cls, platform: Platform) -> List[str]:
        """
        Get default scopes for a platform.
        
        Args:
            platform: Target platform
            
        Returns:
            List of default scopes
        """
        return cls.DEFAULT_SCOPES.get(platform, [])
    
    @classmethod
    def get_security_requirements(cls, environment: Environment) -> Dict[str, any]:
        """
        Get security requirements for an environment.
        
        Args:
            environment: Target environment
            
        Returns:
            Dictionary of security requirements
        """
        return cls.SECURITY_REQUIREMENTS.get(environment, {})


# Convenience functions for common configurations
def create_advana_config(client_id: str, client_secret: str, redirect_uri: str,
                        environment: Environment = Environment.NIPR) -> OAuthConfig:
    """Create Advana OAuth configuration."""
    configurator = DoD_OAuth_Configurator(environment)
    return configurator.create_config(Platform.ADVANA, client_id, client_secret, redirect_uri)


def create_qlik_config(client_id: str, client_secret: str, redirect_uri: str,
                      environment: Environment = Environment.NIPR) -> OAuthConfig:
    """Create Qlik OAuth configuration."""
    configurator = DoD_OAuth_Configurator(environment)
    return configurator.create_config(Platform.QLIK, client_id, client_secret, redirect_uri)


def create_databricks_config(client_id: str, client_secret: str, redirect_uri: str,
                           environment: Environment = Environment.NIPR) -> OAuthConfig:
    """Create Databricks OAuth configuration."""
    configurator = DoD_OAuth_Configurator(environment)
    return configurator.create_config(Platform.DATABRICKS, client_id, client_secret, redirect_uri)


def create_navy_jupiter_config(client_id: str, client_secret: str, redirect_uri: str,
                             environment: Environment = Environment.NIPR) -> OAuthConfig:
    """Create Navy Jupiter OAuth configuration."""
    configurator = DoD_OAuth_Configurator(environment)
    return configurator.create_config(Platform.NAVY_JUPITER, client_id, client_secret, redirect_uri)


def create_all_configs_from_env(environment: Environment = Environment.NIPR) -> Dict[Platform, OAuthConfig]:
    """Create all platform configurations from environment variables."""
    configurator = DoD_OAuth_Configurator(environment)
    return configurator.get_all_configs()
