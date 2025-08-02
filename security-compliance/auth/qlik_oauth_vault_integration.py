"""
Qlik OAuth Vault Integration
Integrates enhanced Qlik OAuth implementation with existing Vault credential management
and comprehensive audit logging systems.
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

# Import enhanced OAuth components
from .enhanced_qlik_oauth import EnhancedQlikOAuthClient, QlikOAuthSessionManager
from .enhanced_cac_oauth_binding import EnhancedCACOAuthBinder, CACTokenBinding
from .qlik_permission_mapper import AdvancedQlikPermissionMapper
from .qlik_oauth_error_handler import QlikOAuthErrorHandler

# Import base components
from .oauth_client import TokenResponse, Platform
from .cac_piv_integration import CACCredentials
from .security_managers import AuditLogger, AuditEvent, AuditEventType

logger = logging.getLogger(__name__)


class VaultSecretType(Enum):
    """Vault secret types for OAuth integration."""
    OAUTH_CLIENT_CREDENTIALS = "oauth_client_credentials"
    OAUTH_ACCESS_TOKEN = "oauth_access_token"
    OAUTH_REFRESH_TOKEN = "oauth_refresh_token"
    CAC_OAUTH_BINDING = "cac_oauth_binding"
    USER_SESSION_DATA = "user_session_data"
    QLIK_API_KEY = "qlik_api_key"
    ENCRYPTION_KEY = "encryption_key"


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
    rotation_enabled: bool = False
    rotation_interval: Optional[timedelta] = None
    access_count: int = 0
    last_accessed: Optional[datetime] = None


class QlikOAuthVaultIntegration:
    """Integration layer between Qlik OAuth and Vault credential management."""
    
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
            VaultSecretType.OAUTH_CLIENT_CREDENTIALS: "oauth/client/{platform}/{client_id}",
            VaultSecretType.OAUTH_ACCESS_TOKEN: "oauth/tokens/{platform}/{user_id}/access",
            VaultSecretType.OAUTH_REFRESH_TOKEN: "oauth/tokens/{platform}/{user_id}/refresh",
            VaultSecretType.CAC_OAUTH_BINDING: "oauth/bindings/{platform}/{user_id}/{binding_id}",
            VaultSecretType.USER_SESSION_DATA: "oauth/sessions/{platform}/{user_id}/{session_id}",
            VaultSecretType.QLIK_API_KEY: "qlik/api_keys/{user_id}",
            VaultSecretType.ENCRYPTION_KEY: "encryption/oauth/{key_id}"
        }
        
        logger.info("Qlik OAuth Vault integration initialized")
    
    def store_oauth_client_credentials(self, platform: Platform, client_id: str,
                                     client_secret: str, metadata: Dict[str, Any]) -> bool:
        """
        Store OAuth client credentials in Vault.
        
        Args:
            platform: OAuth platform
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
                    client_id=client_id
                )
                
                secret_data = {
                    "client_id": client_id,
                    "client_secret": client_secret,
                    "platform": platform.value,
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
                            "client_id": client_id,
                            "vault_path": vault_path
                        }
                    ))
                    
                    logger.info(f"OAuth client credentials stored for {platform.value}")
                
                return success
                
            except Exception as e:
                logger.error(f"Failed to store OAuth client credentials: {e}")
                return False
    
    def retrieve_oauth_client_credentials(self, platform: Platform, client_id: str) -> Optional[Dict[str, str]]:
        """
        Retrieve OAuth client credentials from Vault.
        
        Args:
            platform: OAuth platform
            client_id: OAuth client ID
            
        Returns:
            Client credentials or None if not found
        """
        with self._lock:
            try:
                vault_path = self.vault_paths[VaultSecretType.OAUTH_CLIENT_CREDENTIALS].format(
                    platform=platform.value,
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
    
    def store_oauth_tokens(self, platform: Platform, user_id: str,
                          access_token: TokenResponse, cac_credentials: Optional[CACCredentials] = None) -> bool:
        """
        Store OAuth tokens securely in Vault.
        
        Args:
            platform: OAuth platform
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
                    "platform": platform.value
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
                        user_id=user_id
                    )
                    
                    refresh_token_data = {
                        "refresh_token": access_token.refresh_token,
                        "user_id": user_id,
                        "platform": platform.value,
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
                        classification_level=clearance_level
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
                            "token_type": "oauth_access_token",
                            "expires_at": access_token.expires_at.isoformat(),
                            "cac_bound": cac_credentials is not None,
                            "vault_path": access_token_path
                        }
                    ))
                    
                    logger.info(f"OAuth tokens stored for user {user_id} on {platform.value}")
                
                return access_success and refresh_success
                
            except Exception as e:
                logger.error(f"Failed to store OAuth tokens: {e}")
                return False
    
    def retrieve_oauth_tokens(self, platform: Platform, user_id: str) -> Optional[TokenResponse]:
        """
        Retrieve OAuth tokens from Vault.
        
        Args:
            platform: OAuth platform
            user_id: User identifier
            
        Returns:
            Token response or None if not found
        """
        with self._lock:
            try:
                access_token_path = self.vault_paths[VaultSecretType.OAUTH_ACCESS_TOKEN].format(
                    platform=platform.value,
                    user_id=user_id
                )
                
                access_token_data = self.vault_manager.retrieve_secret(access_token_path)
                if not access_token_data:
                    return None
                
                # Retrieve refresh token
                refresh_token_path = self.vault_paths[VaultSecretType.OAUTH_REFRESH_TOKEN].format(
                    platform=platform.value,
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
                        "token_type": "oauth_access_token",
                        "vault_path": access_token_path
                    }
                ))
                
                return token_response
                
            except Exception as e:
                logger.error(f"Failed to retrieve OAuth tokens: {e}")
                return None
    
    def store_cac_oauth_binding(self, platform: Platform, user_id: str,
                              binding: CACTokenBinding) -> bool:
        """
        Store CAC-OAuth binding in Vault.
        
        Args:
            platform: OAuth platform
            user_id: User identifier
            binding: CAC-OAuth binding
            
        Returns:
            True if storage successful
        """
        with self._lock:
            try:
                vault_path = self.vault_paths[VaultSecretType.CAC_OAUTH_BINDING].format(
                    platform=platform.value,
                    user_id=user_id,
                    binding_id=binding.binding_id
                )
                
                binding_data = {
                    "binding_id": binding.binding_id,
                    "edipi": binding.edipi,
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
                        classification_level=binding.clearance_level
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
                            "binding_id": binding.binding_id,
                            "binding_strength": binding.binding_strength.value,
                            "clearance_level": binding.clearance_level,
                            "vault_path": vault_path
                        }
                    ))
                    
                    logger.info(f"CAC-OAuth binding stored: {binding.binding_id}")
                
                return success
                
            except Exception as e:
                logger.error(f"Failed to store CAC-OAuth binding: {e}")
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
                
                # Count by platform
                platform_counts = {}
                for metadata in self.secret_metadata.values():
                    platform = metadata.platform.value
                    platform_counts[platform] = platform_counts.get(platform, 0) + 1
                
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
                
                return {
                    "total_secrets": len(self.secret_metadata),
                    "secrets_by_type": type_counts,
                    "secrets_by_platform": platform_counts,
                    "secrets_by_classification": classification_counts,
                    "expiring_soon": expiring_soon,
                    "total_accesses": total_accesses,
                    "statistics_timestamp": current_time.isoformat()
                }
                
            except Exception as e:
                logger.error(f"Failed to get vault usage statistics: {e}")
                return {"error": str(e)}


class ComprehensiveAuditLogger:
    """Enhanced audit logger for comprehensive OAuth operations."""
    
    def __init__(self):
        """Initialize comprehensive audit logger."""
        self.audit_logger = AuditLogger.instance()
        
    def log_oauth_flow_start(self, user_id: str, platform: Platform,
                           flow_type: str, additional_data: Dict[str, Any] = None):
        """Log start of OAuth flow."""
        self.audit_logger.log_event(AuditEvent(
            event_type=AuditEventType.OAUTH_FLOW_START,
            timestamp=datetime.now(timezone.utc),
            user_id=user_id,
            success=True,
            additional_data={
                "platform": platform.value,
                "flow_type": flow_type,
                **(additional_data or {})
            }
        ))
    
    def log_oauth_flow_complete(self, user_id: str, platform: Platform,
                              flow_type: str, success: bool,
                              additional_data: Dict[str, Any] = None):
        """Log completion of OAuth flow."""
        self.audit_logger.log_event(AuditEvent(
            event_type=AuditEventType.OAUTH_FLOW_COMPLETE,
            timestamp=datetime.now(timezone.utc),
            user_id=user_id,
            success=success,
            additional_data={
                "platform": platform.value,
                "flow_type": flow_type,
                **(additional_data or {})
            }
        ))
    
    def log_cac_binding_operation(self, user_id: str, operation: str,
                                binding_id: str, success: bool,
                                additional_data: Dict[str, Any] = None):
        """Log CAC binding operations."""
        self.audit_logger.log_event(AuditEvent(
            event_type=AuditEventType.CAC_BINDING_OPERATION,
            timestamp=datetime.now(timezone.utc),
            user_id=user_id,
            success=success,
            additional_data={
                "operation": operation,
                "binding_id": binding_id,
                **(additional_data or {})
            }
        ))
    
    def log_permission_decision(self, user_id: str, resource_id: str,
                              permission: str, decision: bool,
                              additional_data: Dict[str, Any] = None):
        """Log permission access decisions."""
        self.audit_logger.log_event(AuditEvent(
            event_type=AuditEventType.PERMISSION_DECISION,
            timestamp=datetime.now(timezone.utc),
            user_id=user_id,
            success=decision,
            additional_data={
                "resource_id": resource_id,
                "permission": permission,
                "decision": "granted" if decision else "denied",
                **(additional_data or {})
            }
        ))
    
    def log_vault_operation(self, user_id: str, operation: str,
                          vault_path: str, success: bool,
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
                **(additional_data or {})
            }
        ))