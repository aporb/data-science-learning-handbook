"""
Databricks OAuth Vault Integration
Integrates enhanced Databricks OAuth implementation with existing Vault credential management
and comprehensive audit logging systems.
Adapted from proven Qlik OAuth patterns for maximum code reuse.
"""

import json
import logging
import hashlib
import base64
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta, timezone
from enum import Enum
import threading

# Import Vault components (assuming they exist in the codebase)
try:
    from ..credential_management.vault_manager import VaultManager, SecretType
    from ..credential_management.key_rotation import KeyRotationManager
except ImportError:
    # Fallback implementations for development
    class VaultManager:
        def store_secret(self, path: str, secret: Dict[str, Any], secret_type: str) -> bool:
            return True
        def retrieve_secret(self, path: str) -> Optional[Dict[str, Any]]:
            return None
        def delete_secret(self, path: str) -> bool:
            return True
    
    class KeyRotationManager:
        def schedule_rotation(self, key_id: str, rotation_interval: timedelta) -> bool:
            return True
    
    class SecretType:
        OAUTH_TOKEN = "oauth_token"
        CLIENT_CREDENTIALS = "client_credentials"
        CAC_BINDING = "cac_binding"
        SERVICE_PRINCIPAL = "service_principal"

# Import enhanced OAuth components
from .enhanced_databricks_oauth import EnhancedDatabricksOAuthClient, DatabricksOAuthSessionManager
from .enhanced_cac_oauth_binding import EnhancedCACOAuthBinder, CACTokenBinding
from .databricks_permission_mapper import AdvancedDatabricksPermissionMapper
from .databricks_oauth_error_handler import DatabricksOAuthErrorHandler

# Import base components
from .oauth_client import TokenResponse, Platform
from .cac_piv_integration import CACCredentials
from .security_managers import AuditLogger, AuditEvent, AuditEventType

logger = logging.getLogger(__name__)


class VaultSecretType(Enum):
    """Vault secret types for Databricks OAuth integration."""
    OAUTH_CLIENT_CREDENTIALS = "oauth_client_credentials"
    OAUTH_ACCESS_TOKEN = "oauth_access_token"
    OAUTH_REFRESH_TOKEN = "oauth_refresh_token"
    CAC_OAUTH_BINDING = "cac_oauth_binding"
    USER_SESSION_DATA = "user_session_data"
    SERVICE_PRINCIPAL_CREDENTIALS = "service_principal_credentials"
    DATABRICKS_API_KEY = "databricks_api_key"
    CLUSTER_CONFIGURATION = "cluster_configuration"
    WORKSPACE_CONFIGURATION = "workspace_configuration"
    ENCRYPTION_KEY = "encryption_key"
    MLFLOW_TRACKING_TOKEN = "mlflow_tracking_token"
    UNITY_CATALOG_TOKEN = "unity_catalog_token"


@dataclass
class VaultSecretMetadata:
    """Metadata for Vault secrets."""
    secret_id: str
    secret_type: VaultSecretType
    created_at: datetime
    expires_at: Optional[datetime]
    user_id: str
    platform: Platform
    classification_level: str
    workspace_id: Optional[str] = None
    cluster_id: Optional[str] = None
    service_principal_id: Optional[str] = None
    rotation_enabled: bool = False
    rotation_interval: Optional[timedelta] = None
    access_count: int = 0
    last_accessed: Optional[datetime] = None


class DatabricksOAuthVaultIntegration:
    """Integration layer between Databricks OAuth and Vault credential management."""
    
    def __init__(self, vault_manager: Optional[VaultManager] = None,
                 key_rotation_manager: Optional[KeyRotationManager] = None):
        """
        Initialize Vault integration.
        
        Args:
            vault_manager: Vault manager instance
            key_rotation_manager: Key rotation manager instance
        """
        self.vault_manager = vault_manager or VaultManager()
        self.key_rotation_manager = key_rotation_manager or KeyRotationManager()
        self.secret_metadata: Dict[str, VaultSecretMetadata] = {}
        self._lock = threading.RLock()
        
        # Vault path templates
        self.vault_paths = {
            VaultSecretType.OAUTH_CLIENT_CREDENTIALS: "oauth/client/{platform}/{workspace_id}/{client_id}",
            VaultSecretType.OAUTH_ACCESS_TOKEN: "oauth/tokens/{platform}/{workspace_id}/{user_id}/access",
            VaultSecretType.OAUTH_REFRESH_TOKEN: "oauth/tokens/{platform}/{workspace_id}/{user_id}/refresh",
            VaultSecretType.CAC_OAUTH_BINDING: "oauth/bindings/{platform}/{workspace_id}/{user_id}/{binding_id}",
            VaultSecretType.USER_SESSION_DATA: "oauth/sessions/{platform}/{workspace_id}/{user_id}/{session_id}",
            VaultSecretType.SERVICE_PRINCIPAL_CREDENTIALS: "databricks/service_principals/{workspace_id}/{sp_id}",
            VaultSecretType.DATABRICKS_API_KEY: "databricks/api_keys/{workspace_id}/{user_id}",
            VaultSecretType.CLUSTER_CONFIGURATION: "databricks/clusters/{workspace_id}/{cluster_id}",
            VaultSecretType.WORKSPACE_CONFIGURATION: "databricks/workspaces/{workspace_id}/config",
            VaultSecretType.ENCRYPTION_KEY: "encryption/databricks/{key_id}",
            VaultSecretType.MLFLOW_TRACKING_TOKEN: "databricks/mlflow/{workspace_id}/{user_id}",
            VaultSecretType.UNITY_CATALOG_TOKEN: "databricks/unity_catalog/{workspace_id}/{user_id}"
        }
        
        logger.info("Databricks OAuth Vault integration initialized")
    
    def store_oauth_client_credentials(self, platform: Platform, workspace_id: str, 
                                     client_id: str, client_secret: str, 
                                     metadata: Dict[str, Any]) -> bool:
        """
        Store OAuth client credentials in Vault.
        
        Args:
            platform: OAuth platform
            workspace_id: Databricks workspace ID
            client_id: OAuth client ID
            client_secret: OAuth client secret
            metadata: Additional metadata
            
        Returns:
            True if storage successful
        """
        with self._lock:
            try:
                vault_path = self.vault_paths[VaultSecretType.OAUTH_CLIENT_CREDENTIALS].format(
                    platform=platform.value,
                    workspace_id=workspace_id,
                    client_id=client_id
                )
                
                secret_data = {
                    "client_id": client_id,
                    "client_secret": client_secret,
                    "platform": platform.value,
                    "workspace_id": workspace_id,
                    "created_at": datetime.now(timezone.utc).isoformat(),
                    "metadata": metadata
                }
                
                # Store in Vault
                success = self.vault_manager.store_secret(
                    path=vault_path,
                    secret=secret_data,
                    secret_type=SecretType.CLIENT_CREDENTIALS
                )
                
                if success:
                    # Store metadata
                    secret_metadata = VaultSecretMetadata(
                        secret_id=vault_path,
                        secret_type=VaultSecretType.OAUTH_CLIENT_CREDENTIALS,
                        created_at=datetime.now(timezone.utc),
                        expires_at=None,  # Client credentials don't expire
                        user_id="system",
                        platform=platform,
                        classification_level=metadata.get("classification", "CONFIDENTIAL"),
                        workspace_id=workspace_id,
                        rotation_enabled=True,
                        rotation_interval=timedelta(days=90)
                    )
                    
                    self.secret_metadata[vault_path] = secret_metadata
                    
                    # Schedule key rotation
                    self.key_rotation_manager.schedule_rotation(
                        vault_path, secret_metadata.rotation_interval
                    )
                    
                    # Audit log
                    AuditLogger.instance().log_event(AuditEvent(
                        event_type=AuditEventType.CREDENTIAL_STORED,
                        timestamp=datetime.now(timezone.utc),
                        user_id="system",
                        success=True,
                        additional_data={
                            "credential_type": "oauth_client_credentials",
                            "platform": platform.value,
                            "workspace_id": workspace_id,
                            "client_id": client_id,
                            "vault_path": vault_path
                        }
                    ))
                    
                    logger.info(f"OAuth client credentials stored for {platform.value} workspace {workspace_id}")
                
                return success
                
            except Exception as e:
                logger.error(f"Failed to store OAuth client credentials: {e}")
                return False
    
    def retrieve_oauth_client_credentials(self, platform: Platform, workspace_id: str, 
                                        client_id: str) -> Optional[Dict[str, str]]:
        """
        Retrieve OAuth client credentials from Vault.
        
        Args:
            platform: OAuth platform
            workspace_id: Databricks workspace ID
            client_id: OAuth client ID
            
        Returns:
            Client credentials or None if not found
        """
        with self._lock:
            try:
                vault_path = self.vault_paths[VaultSecretType.OAUTH_CLIENT_CREDENTIALS].format(
                    platform=platform.value,
                    workspace_id=workspace_id,
                    client_id=client_id
                )
                
                secret_data = self.vault_manager.retrieve_secret(vault_path)
                if not secret_data:
                    return None
                
                # Update access metadata
                if vault_path in self.secret_metadata:
                    metadata = self.secret_metadata[vault_path]
                    metadata.access_count += 1
                    metadata.last_accessed = datetime.now(timezone.utc)
                
                # Audit log
                AuditLogger.instance().log_event(AuditEvent(
                    event_type=AuditEventType.CREDENTIAL_ACCESSED,
                    timestamp=datetime.now(timezone.utc),
                    user_id="system",
                    success=True,
                    additional_data={
                        "credential_type": "oauth_client_credentials",
                        "platform": platform.value,
                        "workspace_id": workspace_id,
                        "client_id": client_id,
                        "vault_path": vault_path
                    }
                ))
                
                return {
                    "client_id": secret_data.get("client_id"),
                    "client_secret": secret_data.get("client_secret")
                }
                
            except Exception as e:
                logger.error(f"Failed to retrieve OAuth client credentials: {e}")
                return None
    
    def store_oauth_tokens(self, platform: Platform, workspace_id: str, user_id: str,
                          access_token: TokenResponse, cac_credentials: Optional[CACCredentials] = None) -> bool:
        """
        Store OAuth tokens securely in Vault.
        
        Args:
            platform: OAuth platform
            workspace_id: Databricks workspace ID
            user_id: User identifier
            access_token: OAuth token response
            cac_credentials: Optional CAC credentials for enhanced metadata
            
        Returns:
            True if storage successful
        """
        with self._lock:
            try:
                # Store access token
                access_token_path = self.vault_paths[VaultSecretType.OAUTH_ACCESS_TOKEN].format(
                    platform=platform.value,
                    workspace_id=workspace_id,
                    user_id=user_id
                )
                
                access_token_data = {
                    "access_token": access_token.access_token,
                    "token_type": access_token.token_type,
                    "expires_in": access_token.expires_in,
                    "scope": access_token.scope,
                    "issued_at": access_token.issued_at.isoformat(),
                    "expires_at": access_token.expires_at.isoformat(),
                    "user_id": user_id,
                    "platform": platform.value,
                    "workspace_id": workspace_id
                }
                
                # Add CAC binding information
                if cac_credentials:
                    access_token_data["cac_bound"] = True
                    access_token_data["edipi"] = cac_credentials.edipi
                    access_token_data["clearance_level"] = cac_credentials.clearance_level
                    access_token_data["organization"] = cac_credentials.organization
                
                # Store access token
                access_success = self.vault_manager.store_secret(
                    path=access_token_path,
                    secret=access_token_data,
                    secret_type=SecretType.OAUTH_TOKEN
                )
                
                # Store refresh token if available
                refresh_success = True
                if access_token.refresh_token:
                    refresh_token_path = self.vault_paths[VaultSecretType.OAUTH_REFRESH_TOKEN].format(
                        platform=platform.value,
                        workspace_id=workspace_id,
                        user_id=user_id
                    )
                    
                    refresh_token_data = {
                        "refresh_token": access_token.refresh_token,
                        "user_id": user_id,
                        "platform": platform.value,
                        "workspace_id": workspace_id,
                        "issued_at": access_token.issued_at.isoformat(),
                        "linked_access_token": access_token_path
                    }
                    
                    refresh_success = self.vault_manager.store_secret(
                        path=refresh_token_path,
                        secret=refresh_token_data,
                        secret_type=SecretType.OAUTH_TOKEN
                    )
                
                if access_success and refresh_success:
                    # Store metadata
                    clearance_level = "UNCLASSIFIED"
                    if cac_credentials and cac_credentials.clearance_level:
                        clearance_level = cac_credentials.clearance_level
                    
                    access_metadata = VaultSecretMetadata(
                        secret_id=access_token_path,
                        secret_type=VaultSecretType.OAUTH_ACCESS_TOKEN,
                        created_at=datetime.now(timezone.utc),
                        expires_at=access_token.expires_at,
                        user_id=user_id,
                        platform=platform,
                        classification_level=clearance_level,
                        workspace_id=workspace_id
                    )
                    
                    self.secret_metadata[access_token_path] = access_metadata
                    
                    # Audit log
                    AuditLogger.instance().log_event(AuditEvent(
                        event_type=AuditEventType.TOKEN_STORED,
                        timestamp=datetime.now(timezone.utc),
                        user_id=user_id,
                        success=True,
                        additional_data={
                            "platform": platform.value,
                            "workspace_id": workspace_id,
                            "token_type": "oauth_access_token",
                            "expires_at": access_token.expires_at.isoformat(),
                            "cac_bound": cac_credentials is not None,
                            "vault_path": access_token_path
                        }
                    ))
                    
                    logger.info(f"OAuth tokens stored for user {user_id} in workspace {workspace_id}")
                
                return access_success and refresh_success
                
            except Exception as e:
                logger.error(f"Failed to store OAuth tokens: {e}")
                return False
    
    def retrieve_oauth_tokens(self, platform: Platform, workspace_id: str, user_id: str) -> Optional[TokenResponse]:
        """
        Retrieve OAuth tokens from Vault.
        
        Args:
            platform: OAuth platform
            workspace_id: Databricks workspace ID
            user_id: User identifier
            
        Returns:
            Token response or None if not found
        """
        with self._lock:
            try:
                access_token_path = self.vault_paths[VaultSecretType.OAUTH_ACCESS_TOKEN].format(
                    platform=platform.value,
                    workspace_id=workspace_id,
                    user_id=user_id
                )
                
                access_token_data = self.vault_manager.retrieve_secret(access_token_path)
                if not access_token_data:
                    return None
                
                # Retrieve refresh token
                refresh_token_path = self.vault_paths[VaultSecretType.OAUTH_REFRESH_TOKEN].format(
                    platform=platform.value,
                    workspace_id=workspace_id,
                    user_id=user_id
                )
                
                refresh_token_data = self.vault_manager.retrieve_secret(refresh_token_path)
                refresh_token = refresh_token_data.get("refresh_token") if refresh_token_data else None
                
                # Create token response
                token_response = TokenResponse(
                    access_token=access_token_data["access_token"],
                    token_type=access_token_data["token_type"],
                    expires_in=access_token_data["expires_in"],
                    refresh_token=refresh_token,
                    scope=access_token_data.get("scope"),
                    issued_at=datetime.fromisoformat(access_token_data["issued_at"])
                )
                
                # Update access metadata
                if access_token_path in self.secret_metadata:
                    metadata = self.secret_metadata[access_token_path]
                    metadata.access_count += 1
                    metadata.last_accessed = datetime.now(timezone.utc)
                
                # Audit log
                AuditLogger.instance().log_event(AuditEvent(
                    event_type=AuditEventType.TOKEN_ACCESSED,
                    timestamp=datetime.now(timezone.utc),
                    user_id=user_id,
                    success=True,
                    additional_data={
                        "platform": platform.value,
                        "workspace_id": workspace_id,
                        "token_type": "oauth_access_token",
                        "vault_path": access_token_path
                    }
                ))
                
                return token_response
                
            except Exception as e:
                logger.error(f"Failed to retrieve OAuth tokens: {e}")
                return None
    
    def store_service_principal(self, workspace_id: str, service_principal_id: str,
                              service_principal_data: Dict[str, Any], 
                              cac_credentials: CACCredentials) -> bool:
        """
        Store service principal information in Vault.
        
        Args:
            workspace_id: Databricks workspace ID
            service_principal_id: Service principal ID
            service_principal_data: Service principal configuration
            cac_credentials: CAC credentials for binding
            
        Returns:
            True if storage successful
        """
        with self._lock:
            try:
                vault_path = self.vault_paths[VaultSecretType.SERVICE_PRINCIPAL_CREDENTIALS].format(
                    workspace_id=workspace_id,
                    sp_id=service_principal_id
                )
                
                sp_vault_data = {
                    "service_principal_id": service_principal_id,
                    "workspace_id": workspace_id,
                    "display_name": service_principal_data.get("displayName"),
                    "external_id": service_principal_data.get("externalId"),
                    "active": service_principal_data.get("active", True),
                    "created_at": datetime.now(timezone.utc).isoformat(),
                    "bound_to_edipi": cac_credentials.edipi,
                    "clearance_level": cac_credentials.clearance_level,
                    "organization": cac_credentials.organization,
                    "entitlements": service_principal_data.get("entitlements", []),
                    "groups": service_principal_data.get("groups", [])
                }
                
                success = self.vault_manager.store_secret(
                    path=vault_path,
                    secret=sp_vault_data,
                    secret_type=SecretType.SERVICE_PRINCIPAL
                )
                
                if success:
                    # Store metadata
                    sp_metadata = VaultSecretMetadata(
                        secret_id=vault_path,
                        secret_type=VaultSecretType.SERVICE_PRINCIPAL_CREDENTIALS,
                        created_at=datetime.now(timezone.utc),
                        expires_at=None,  # Service principals don't expire by default
                        user_id=cac_credentials.edipi,
                        platform=Platform.DATABRICKS,
                        classification_level=cac_credentials.clearance_level,
                        workspace_id=workspace_id,
                        service_principal_id=service_principal_id
                    )
                    
                    self.secret_metadata[vault_path] = sp_metadata
                    
                    # Audit log
                    AuditLogger.instance().log_event(AuditEvent(
                        event_type=AuditEventType.SERVICE_PRINCIPAL_STORED,
                        timestamp=datetime.now(timezone.utc),
                        user_id=cac_credentials.edipi,
                        success=True,
                        additional_data={
                            "workspace_id": workspace_id,
                            "service_principal_id": service_principal_id,
                            "bound_to_edipi": cac_credentials.edipi,
                            "clearance_level": cac_credentials.clearance_level,
                            "vault_path": vault_path
                        }
                    ))
                    
                    logger.info(f"Service principal stored: {service_principal_id} for workspace {workspace_id}")
                
                return success
                
            except Exception as e:
                logger.error(f"Failed to store service principal: {e}")
                return False
    
    def store_cluster_configuration(self, workspace_id: str, cluster_id: str,
                                  cluster_config: Dict[str, Any], 
                                  user_id: str, classification_level: str) -> bool:
        """
        Store cluster configuration in Vault.
        
        Args:
            workspace_id: Databricks workspace ID
            cluster_id: Cluster ID
            cluster_config: Cluster configuration
            user_id: User who created the cluster
            classification_level: Classification level of cluster
            
        Returns:
            True if storage successful
        """
        with self._lock:
            try:
                vault_path = self.vault_paths[VaultSecretType.CLUSTER_CONFIGURATION].format(
                    workspace_id=workspace_id,
                    cluster_id=cluster_id
                )
                
                cluster_vault_data = {
                    "cluster_id": cluster_id,
                    "workspace_id": workspace_id,
                    "cluster_name": cluster_config.get("cluster_name"),
                    "spark_version": cluster_config.get("spark_version"),
                    "node_type_id": cluster_config.get("node_type_id"),
                    "num_workers": cluster_config.get("num_workers"),
                    "autotermination_minutes": cluster_config.get("autotermination_minutes"),
                    "policy_id": cluster_config.get("policy_id"),
                    "instance_pool_id": cluster_config.get("instance_pool_id"),
                    "classification_level": classification_level,
                    "created_by": user_id,
                    "created_at": datetime.now(timezone.utc).isoformat(),
                    "spark_conf": cluster_config.get("spark_conf", {}),
                    "spark_env_vars": cluster_config.get("spark_env_vars", {}),
                    "ssh_public_keys": cluster_config.get("ssh_public_keys", []),
                    "custom_tags": cluster_config.get("custom_tags", {})
                }
                
                success = self.vault_manager.store_secret(
                    path=vault_path,
                    secret=cluster_vault_data,
                    secret_type="cluster_configuration"
                )
                
                if success:
                    # Store metadata
                    cluster_metadata = VaultSecretMetadata(
                        secret_id=vault_path,
                        secret_type=VaultSecretType.CLUSTER_CONFIGURATION,
                        created_at=datetime.now(timezone.utc),
                        expires_at=None,  # Cluster configs don't expire
                        user_id=user_id,
                        platform=Platform.DATABRICKS,
                        classification_level=classification_level,
                        workspace_id=workspace_id,
                        cluster_id=cluster_id
                    )
                    
                    self.secret_metadata[vault_path] = cluster_metadata
                    
                    # Audit log
                    AuditLogger.instance().log_event(AuditEvent(
                        event_type=AuditEventType.CLUSTER_CONFIG_STORED,
                        timestamp=datetime.now(timezone.utc),
                        user_id=user_id,
                        success=True,
                        additional_data={
                            "workspace_id": workspace_id,
                            "cluster_id": cluster_id,
                            "classification_level": classification_level,
                            "vault_path": vault_path
                        }
                    ))
                    
                    logger.info(f"Cluster configuration stored: {cluster_id} for workspace {workspace_id}")
                
                return success
                
            except Exception as e:
                logger.error(f"Failed to store cluster configuration: {e}")
                return False
    
    def store_cac_oauth_binding(self, platform: Platform, workspace_id: str, user_id: str,
                              binding: CACTokenBinding) -> bool:
        """
        Store CAC-OAuth binding in Vault.
        
        Args:
            platform: OAuth platform
            workspace_id: Databricks workspace ID
            user_id: User identifier
            binding: CAC-OAuth binding
            
        Returns:
            True if storage successful
        """
        with self._lock:
            try:
                vault_path = self.vault_paths[VaultSecretType.CAC_OAUTH_BINDING].format(
                    platform=platform.value,
                    workspace_id=workspace_id,
                    user_id=user_id,
                    binding_id=binding.binding_id
                )
                
                binding_data = {
                    "binding_id": binding.binding_id,
                    "edipi": binding.edipi,
                    "workspace_id": workspace_id,
                    "certificate_fingerprint": binding.certificate_fingerprint,
                    "certificate_serial": binding.certificate_serial,
                    "oauth_token_hash": binding.oauth_token_hash,
                    "binding_timestamp": binding.binding_timestamp.isoformat(),
                    "expires_at": binding.expires_at.isoformat(),
                    "binding_strength": binding.binding_strength.value,
                    "clearance_level": binding.clearance_level,
                    "organization": binding.organization,
                    "validation_challenges": binding.validation_challenges,
                    "metadata": binding.metadata
                }
                
                success = self.vault_manager.store_secret(
                    path=vault_path,
                    secret=binding_data,
                    secret_type=SecretType.CAC_BINDING
                )
                
                if success:
                    # Store metadata
                    binding_metadata = VaultSecretMetadata(
                        secret_id=vault_path,
                        secret_type=VaultSecretType.CAC_OAUTH_BINDING,
                        created_at=datetime.now(timezone.utc),
                        expires_at=binding.expires_at,
                        user_id=user_id,
                        platform=platform,
                        classification_level=binding.clearance_level,
                        workspace_id=workspace_id
                    )
                    
                    self.secret_metadata[vault_path] = binding_metadata
                    
                    # Audit log
                    AuditLogger.instance().log_event(AuditEvent(
                        event_type=AuditEventType.BINDING_STORED,
                        timestamp=datetime.now(timezone.utc),
                        user_id=user_id,
                        success=True,
                        additional_data={
                            "platform": platform.value,
                            "workspace_id": workspace_id,
                            "binding_id": binding.binding_id,
                            "binding_strength": binding.binding_strength.value,
                            "clearance_level": binding.clearance_level,
                            "vault_path": vault_path
                        }
                    ))
                    
                    logger.info(f"CAC-OAuth binding stored: {binding.binding_id} for workspace {workspace_id}")
                
                return success
                
            except Exception as e:
                logger.error(f"Failed to store CAC-OAuth binding: {e}")
                return False
    
    def store_mlflow_tracking_token(self, workspace_id: str, user_id: str,
                                  tracking_token: str, experiment_id: Optional[str] = None) -> bool:
        """
        Store MLflow tracking token in Vault.
        
        Args:
            workspace_id: Databricks workspace ID
            user_id: User identifier
            tracking_token: MLflow tracking token
            experiment_id: Optional experiment ID
            
        Returns:
            True if storage successful
        """
        with self._lock:
            try:
                vault_path = self.vault_paths[VaultSecretType.MLFLOW_TRACKING_TOKEN].format(
                    workspace_id=workspace_id,
                    user_id=user_id
                )
                
                tracking_data = {
                    "tracking_token": tracking_token,
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                    "experiment_id": experiment_id,
                    "created_at": datetime.now(timezone.utc).isoformat(),
                    "expires_at": (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()  # 30-day expiry
                }
                
                success = self.vault_manager.store_secret(
                    path=vault_path,
                    secret=tracking_data,
                    secret_type="mlflow_token"
                )
                
                if success:
                    # Store metadata
                    tracking_metadata = VaultSecretMetadata(
                        secret_id=vault_path,
                        secret_type=VaultSecretType.MLFLOW_TRACKING_TOKEN,
                        created_at=datetime.now(timezone.utc),
                        expires_at=datetime.now(timezone.utc) + timedelta(days=30),
                        user_id=user_id,
                        platform=Platform.DATABRICKS,
                        classification_level="CONFIDENTIAL",  # Default for MLflow
                        workspace_id=workspace_id
                    )
                    
                    self.secret_metadata[vault_path] = tracking_metadata
                    
                    logger.info(f"MLflow tracking token stored for user {user_id} in workspace {workspace_id}")
                
                return success
                
            except Exception as e:
                logger.error(f"Failed to store MLflow tracking token: {e}")
                return False
    
    def cleanup_expired_secrets(self) -> int:
        """
        Clean up expired secrets from Vault.
        
        Returns:
            Number of secrets cleaned up
        """
        with self._lock:
            try:
                cleaned_count = 0
                current_time = datetime.now(timezone.utc)
                expired_paths = []
                
                # Find expired secrets
                for vault_path, metadata in self.secret_metadata.items():
                    if metadata.expires_at and current_time >= metadata.expires_at:
                        expired_paths.append(vault_path)
                
                # Delete expired secrets
                for vault_path in expired_paths:
                    try:
                        success = self.vault_manager.delete_secret(vault_path)
                        if success:
                            metadata = self.secret_metadata.pop(vault_path, None)
                            cleaned_count += 1
                            
                            # Audit log
                            AuditLogger.instance().log_event(AuditEvent(
                                event_type=AuditEventType.SECRET_EXPIRED,
                                timestamp=datetime.now(timezone.utc),
                                user_id=metadata.user_id if metadata else "system",
                                success=True,
                                additional_data={
                                    "vault_path": vault_path,
                                    "secret_type": metadata.secret_type.value if metadata else "unknown",
                                    "workspace_id": metadata.workspace_id if metadata else None,
                                    "expired_at": metadata.expires_at.isoformat() if metadata and metadata.expires_at else None
                                }
                            ))
                            
                    except Exception as delete_error:
                        logger.error(f"Failed to delete expired secret {vault_path}: {delete_error}")
                
                logger.info(f"Cleaned up {cleaned_count} expired secrets")
                return cleaned_count
                
            except Exception as e:
                logger.error(f"Failed to cleanup expired secrets: {e}")
                return 0
    
    def get_vault_usage_statistics(self) -> Dict[str, Any]:
        """
        Get Vault usage statistics for monitoring.
        
        Returns:
            Usage statistics dictionary
        """
        with self._lock:
            try:
                current_time = datetime.now(timezone.utc)
                
                # Count by secret type
                type_counts = {}
                for metadata in self.secret_metadata.values():
                    secret_type = metadata.secret_type.value
                    type_counts[secret_type] = type_counts.get(secret_type, 0) + 1
                
                # Count by workspace
                workspace_counts = {}
                for metadata in self.secret_metadata.values():
                    workspace = metadata.workspace_id or "unknown"
                    workspace_counts[workspace] = workspace_counts.get(workspace, 0) + 1
                
                # Count by classification
                classification_counts = {}
                for metadata in self.secret_metadata.values():
                    classification = metadata.classification_level
                    classification_counts[classification] = classification_counts.get(classification, 0) + 1
                
                # Count expiring soon (next 24 hours)
                expiring_soon = 0
                for metadata in self.secret_metadata.values():
                    if (metadata.expires_at and 
                        current_time <= metadata.expires_at <= current_time + timedelta(hours=24)):
                        expiring_soon += 1
                
                # Calculate total access count
                total_accesses = sum(metadata.access_count for metadata in self.secret_metadata.values())
                
                # Count service principals
                service_principal_count = sum(1 for metadata in self.secret_metadata.values() 
                                            if metadata.secret_type == VaultSecretType.SERVICE_PRINCIPAL_CREDENTIALS)
                
                # Count cluster configurations
                cluster_config_count = sum(1 for metadata in self.secret_metadata.values() 
                                         if metadata.secret_type == VaultSecretType.CLUSTER_CONFIGURATION)
                
                return {
                    "total_secrets": len(self.secret_metadata),
                    "secrets_by_type": type_counts,
                    "secrets_by_workspace": workspace_counts,
                    "secrets_by_classification": classification_counts,
                    "expiring_soon": expiring_soon,
                    "total_accesses": total_accesses,
                    "service_principal_count": service_principal_count,
                    "cluster_config_count": cluster_config_count,
                    "statistics_timestamp": current_time.isoformat()
                }
                
            except Exception as e:
                logger.error(f"Failed to get vault usage statistics: {e}")
                return {"error": str(e)}
    
    def rotate_workspace_credentials(self, workspace_id: str) -> Dict[str, Any]:
        """
        Rotate all credentials for a specific workspace.
        
        Args:
            workspace_id: Databricks workspace ID
            
        Returns:
            Rotation results
        """
        with self._lock:
            try:
                rotation_results = {
                    "workspace_id": workspace_id,
                    "rotated_secrets": [],
                    "failed_rotations": [],
                    "timestamp": datetime.now(timezone.utc).isoformat()
                }
                
                # Find all secrets for the workspace
                workspace_secrets = [
                    (path, metadata) for path, metadata in self.secret_metadata.items()
                    if metadata.workspace_id == workspace_id and metadata.rotation_enabled
                ]
                
                for vault_path, metadata in workspace_secrets:
                    try:
                        # Schedule rotation with key rotation manager
                        success = self.key_rotation_manager.schedule_rotation(
                            vault_path, metadata.rotation_interval or timedelta(days=30)
                        )
                        
                        if success:
                            rotation_results["rotated_secrets"].append({
                                "vault_path": vault_path,
                                "secret_type": metadata.secret_type.value,
                                "user_id": metadata.user_id
                            })
                        else:
                            rotation_results["failed_rotations"].append({
                                "vault_path": vault_path,
                                "error": "rotation_scheduling_failed"
                            })
                            
                    except Exception as rotation_error:
                        rotation_results["failed_rotations"].append({
                            "vault_path": vault_path,
                            "error": str(rotation_error)
                        })
                
                # Audit log
                AuditLogger.instance().log_event(AuditEvent(
                    event_type=AuditEventType.CREDENTIAL_ROTATION,
                    timestamp=datetime.now(timezone.utc),
                    user_id="system",
                    success=len(rotation_results["failed_rotations"]) == 0,
                    additional_data={
                        "workspace_id": workspace_id,
                        "rotated_count": len(rotation_results["rotated_secrets"]),
                        "failed_count": len(rotation_results["failed_rotations"])
                    }
                ))
                
                logger.info(f"Credential rotation completed for workspace {workspace_id}: "
                          f"{len(rotation_results['rotated_secrets'])} successful, "
                          f"{len(rotation_results['failed_rotations'])} failed")
                
                return rotation_results
                
            except Exception as e:
                logger.error(f"Failed to rotate workspace credentials: {e}")
                return {"error": str(e), "workspace_id": workspace_id}


class ComprehensiveDatabricksAuditLogger:
    """Enhanced audit logger for comprehensive Databricks OAuth operations."""
    
    def __init__(self):
        """Initialize comprehensive audit logger."""
        self.audit_logger = AuditLogger.instance()
        
    def log_oauth_flow_start(self, user_id: str, platform: Platform,
                           flow_type: str, workspace_id: str, 
                           additional_data: Dict[str, Any] = None):
        """Log start of OAuth flow."""
        self.audit_logger.log_event(AuditEvent(
            event_type=AuditEventType.OAUTH_FLOW_START,
            timestamp=datetime.now(timezone.utc),
            user_id=user_id,
            success=True,
            additional_data={
                "platform": platform.value,
                "workspace_id": workspace_id,
                "flow_type": flow_type,
                **(additional_data or {})
            }
        ))
    
    def log_oauth_flow_complete(self, user_id: str, platform: Platform,
                              flow_type: str, workspace_id: str, success: bool,
                              additional_data: Dict[str, Any] = None):
        """Log completion of OAuth flow."""
        self.audit_logger.log_event(AuditEvent(
            event_type=AuditEventType.OAUTH_FLOW_COMPLETE,
            timestamp=datetime.now(timezone.utc),
            user_id=user_id,
            success=success,
            additional_data={
                "platform": platform.value,
                "workspace_id": workspace_id,
                "flow_type": flow_type,
                **(additional_data or {})
            }
        ))
    
    def log_cluster_operation(self, user_id: str, workspace_id: str, cluster_id: str,
                            operation: str, success: bool,
                            additional_data: Dict[str, Any] = None):
        """Log cluster operations."""
        self.audit_logger.log_event(AuditEvent(
            event_type=AuditEventType.CLUSTER_OPERATION,
            timestamp=datetime.now(timezone.utc),
            user_id=user_id,
            success=success,
            additional_data={
                "workspace_id": workspace_id,
                "cluster_id": cluster_id,
                "operation": operation,
                **(additional_data or {})
            }
        ))
    
    def log_service_principal_operation(self, user_id: str, workspace_id: str,
                                      service_principal_id: str, operation: str,
                                      success: bool, additional_data: Dict[str, Any] = None):
        """Log service principal operations."""
        self.audit_logger.log_event(AuditEvent(
            event_type=AuditEventType.SERVICE_PRINCIPAL_OPERATION,
            timestamp=datetime.now(timezone.utc),
            user_id=user_id,
            success=success,
            additional_data={
                "workspace_id": workspace_id,
                "service_principal_id": service_principal_id,
                "operation": operation,
                **(additional_data or {})
            }
        ))
    
    def log_vault_operation(self, user_id: str, operation: str,
                          vault_path: str, workspace_id: str, success: bool,
                          additional_data: Dict[str, Any] = None):
        """Log Vault operations."""
        self.audit_logger.log_event(AuditEvent(
            event_type=AuditEventType.VAULT_OPERATION,
            timestamp=datetime.now(timezone.utc),
            user_id=user_id,
            success=success,
            additional_data={
                "operation": operation,
                "vault_path": vault_path,
                "workspace_id": workspace_id,
                **(additional_data or {})
            }
        ))
    
    def log_unity_catalog_access(self, user_id: str, workspace_id: str,
                                catalog_name: str, operation: str, success: bool,
                                additional_data: Dict[str, Any] = None):
        """Log Unity Catalog access operations."""
        self.audit_logger.log_event(AuditEvent(
            event_type=AuditEventType.UNITY_CATALOG_ACCESS,
            timestamp=datetime.now(timezone.utc),
            user_id=user_id,
            success=success,
            additional_data={
                "workspace_id": workspace_id,
                "catalog_name": catalog_name,
                "operation": operation,
                **(additional_data or {})
            }
        ))