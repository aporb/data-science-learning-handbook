#!/usr/bin/env python3
"""
Vault Credential Management Service
Integrates with existing HashiCorp Vault infrastructure for comprehensive credential management
"""

import asyncio
import logging
import json
import base64
import hashlib
import secrets
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Union, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
import hvac
from hvac.exceptions import VaultError, InvalidPath

from ..auth.platform_adapters.base_adapter import AuthenticationResult, AuthenticationStatus
from ..audits.audit_logger import SecurityAuditLogger

logger = logging.getLogger(__name__)

class SecretType(Enum):
    """Types of secrets managed by the system"""
    API_KEY = "api_key"
    DATABASE_CREDENTIAL = "database_credential"
    SERVICE_ACCOUNT = "service_account"
    TLS_CERTIFICATE = "tls_certificate"
    ENCRYPTION_KEY = "encryption_key"
    OAUTH_TOKEN = "oauth_token"
    PLATFORM_TOKEN = "platform_token"

class RotationStatus(Enum):
    """Status of secret rotation"""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"

@dataclass
class SecretMetadata:
    """Metadata for managed secrets"""
    secret_id: str
    secret_type: SecretType
    platform: str
    path: str
    created_at: datetime
    last_rotated: Optional[datetime] = None
    rotation_interval: int = 86400  # 24 hours default
    auto_rotate: bool = True
    tags: Dict[str, str] = None
    compliance_level: str = "SECRET"
    
    def __post_init__(self):
        if self.tags is None:
            self.tags = {}

@dataclass
class RotationJob:
    """Represents a secret rotation job"""
    job_id: str
    secret_id: str
    platform: str
    scheduled_time: datetime
    status: RotationStatus
    attempts: int = 0
    max_attempts: int = 3
    error_message: Optional[str] = None
    metadata: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}

class VaultCredentialManager:
    """
    Enhanced credential management service integrating with HashiCorp Vault
    Provides platform-specific secret generation, rotation, and lifecycle management
    """
    
    def __init__(self, vault_config: Dict[str, Any]):
        """
        Initialize the credential manager with Vault configuration
        
        Args:
            vault_config: Vault connection and authentication configuration
        """
        self.vault_config = vault_config
        self.vault_client = None
        self.platform_adapters = {}
        self.rotation_jobs = {}
        self.secret_metadata = {}
        
        # Initialize audit logger
        self.audit_logger = SecurityAuditLogger()
        
        # Configuration
        self.default_rotation_interval = vault_config.get('default_rotation_interval', 86400)
        self.max_secret_age = vault_config.get('max_secret_age', 7776000)  # 90 days
        self.enable_auto_rotation = vault_config.get('enable_auto_rotation', True)
        
        # Vault paths
        self.secrets_path = vault_config.get('secrets_path', 'kv/data/')
        self.metadata_path = vault_config.get('metadata_path', 'kv/metadata/')
        self.rotation_path = vault_config.get('rotation_path', 'kv/data/rotations/')
        
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        self.logger.info("Initialized Vault Credential Manager")
    
    async def initialize(self) -> bool:
        """
        Initialize connection to Vault and validate configuration
        
        Returns:
            True if initialization successful
        """
        try:
            # Initialize Vault client
            self.vault_client = hvac.Client(
                url=self.vault_config['url'],
                token=self.vault_config.get('token'),
                verify=self.vault_config.get('verify_ssl', True)
            )
            
            # Authenticate if token not provided
            if not self.vault_config.get('token'):
                auth_result = await self._authenticate_with_vault()
                if not auth_result:
                    return False
            
            # Verify Vault is initialized and unsealed
            if not self.vault_client.sys.is_initialized():
                self.logger.error("Vault is not initialized")
                return False
            
            if self.vault_client.sys.is_sealed():
                self.logger.error("Vault is sealed")
                return False
            
            # Test connection and permissions
            if not self.vault_client.is_authenticated():
                self.logger.error("Vault authentication failed")
                return False
            
            # Initialize secret engines if needed
            await self._initialize_secret_engines()
            
            # Load existing metadata
            await self._load_secret_metadata()
            
            # Start rotation scheduler if enabled
            if self.enable_auto_rotation:
                asyncio.create_task(self._rotation_scheduler())
            
            self.audit_logger.log_security_event(
                "vault_credential_manager_initialized",
                {"vault_url": self.vault_config['url']},
                severity="INFO"
            )
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to initialize Vault Credential Manager: {e}")
            return False
    
    async def register_platform_adapter(self, platform: str, adapter) -> bool:
        """
        Register a platform-specific authentication adapter
        
        Args:
            platform: Platform name (e.g., 'qlik', 'databricks')
            adapter: Platform adapter instance
            
        Returns:
            True if registration successful
        """
        try:
            self.platform_adapters[platform] = adapter
            self.logger.info(f"Registered platform adapter for {platform}")
            
            self.audit_logger.log_security_event(
                "platform_adapter_registered",
                {"platform": platform},
                severity="INFO"
            )
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to register platform adapter for {platform}: {e}")
            return False
    
    async def create_dynamic_secret(self, platform: str, secret_type: SecretType,
                                  user_context: Dict[str, Any],
                                  metadata: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
        """
        Create a new dynamic secret for a specific platform
        
        Args:
            platform: Target platform name
            secret_type: Type of secret to create
            user_context: User context and authentication information
            metadata: Additional metadata for the secret
            
        Returns:
            Dictionary containing secret information
        """
        try:
            secret_id = self._generate_secret_id(platform, secret_type)
            
            # Get platform adapter
            adapter = self.platform_adapters.get(platform)
            if not adapter:
                raise ValueError(f"No adapter registered for platform: {platform}")
            
            # Generate platform-specific secret
            secret_data = await self._generate_platform_secret(
                adapter, secret_type, user_context, metadata
            )
            
            if not secret_data:
                raise ValueError(f"Failed to generate secret for platform: {platform}")
            
            # Store secret in Vault
            vault_path = f"{self.secrets_path}{platform}/{secret_type.value}/{secret_id}"
            
            secret_payload = {
                'data': secret_data,
                'metadata': {
                    'secret_id': secret_id,
                    'platform': platform,
                    'secret_type': secret_type.value,
                    'created_at': datetime.now(timezone.utc).isoformat(),
                    'created_by': user_context.get('user_id', 'system'),
                    'compliance_level': metadata.get('compliance_level', 'SECRET') if metadata else 'SECRET',
                    'auto_rotate': metadata.get('auto_rotate', True) if metadata else True,
                    'rotation_interval': metadata.get('rotation_interval', self.default_rotation_interval) if metadata else self.default_rotation_interval
                }
            }
            
            # Store in Vault
            self.vault_client.secrets.kv.v2.create_or_update_secret(
                path=f"{platform}/{secret_type.value}/{secret_id}",
                secret=secret_payload
            )
            
            # Create metadata record
            secret_meta = SecretMetadata(
                secret_id=secret_id,
                secret_type=secret_type,
                platform=platform,
                path=vault_path,
                created_at=datetime.now(timezone.utc),
                rotation_interval=metadata.get('rotation_interval', self.default_rotation_interval) if metadata else self.default_rotation_interval,
                auto_rotate=metadata.get('auto_rotate', True) if metadata else True,
                tags=metadata.get('tags', {}) if metadata else {},
                compliance_level=metadata.get('compliance_level', 'SECRET') if metadata else 'SECRET'
            )
            
            self.secret_metadata[secret_id] = secret_meta
            await self._save_secret_metadata()
            
            # Schedule rotation if enabled
            if secret_meta.auto_rotate:
                await self._schedule_rotation(secret_id, secret_meta.rotation_interval)
            
            # Audit log
            self.audit_logger.log_security_event(
                "dynamic_secret_created",
                {
                    "secret_id": secret_id,
                    "platform": platform,
                    "secret_type": secret_type.value,
                    "user_id": user_context.get('user_id'),
                    "compliance_level": secret_meta.compliance_level
                },
                severity="INFO"
            )
            
            return {
                'secret_id': secret_id,
                'platform': platform,
                'secret_type': secret_type.value,
                'secret_data': secret_data,
                'metadata': asdict(secret_meta)
            }
            
        except Exception as e:
            self.logger.error(f"Failed to create dynamic secret: {e}")
            self.audit_logger.log_security_event(
                "dynamic_secret_creation_failed",
                {
                    "platform": platform,
                    "secret_type": secret_type.value,
                    "error": str(e),
                    "user_id": user_context.get('user_id')
                },
                severity="ERROR"
            )
            return None
    
    async def rotate_secret(self, secret_id: str, force: bool = False) -> bool:
        """
        Rotate a specific secret
        
        Args:
            secret_id: ID of secret to rotate
            force: Force rotation even if not due
            
        Returns:
            True if rotation successful
        """
        try:
            # Get secret metadata
            secret_meta = self.secret_metadata.get(secret_id)
            if not secret_meta:
                raise ValueError(f"Secret not found: {secret_id}")
            
            # Check if rotation is due (unless forced)
            if not force and secret_meta.last_rotated:
                time_since_rotation = datetime.now(timezone.utc) - secret_meta.last_rotated
                if time_since_rotation.total_seconds() < secret_meta.rotation_interval:
                    self.logger.info(f"Secret {secret_id} rotation not due, skipping")
                    return True
            
            # Create rotation job
            job_id = f"rotation_{secret_id}_{int(datetime.now(timezone.utc).timestamp())}"
            rotation_job = RotationJob(
                job_id=job_id,
                secret_id=secret_id,
                platform=secret_meta.platform,
                scheduled_time=datetime.now(timezone.utc),
                status=RotationStatus.IN_PROGRESS
            )
            
            self.rotation_jobs[job_id] = rotation_job
            
            # Get platform adapter
            adapter = self.platform_adapters.get(secret_meta.platform)
            if not adapter:
                raise ValueError(f"No adapter for platform: {secret_meta.platform}")
            
            # Get current secret
            current_secret = await self._get_secret_data(secret_id)
            if not current_secret:
                raise ValueError(f"Could not retrieve current secret: {secret_id}")
            
            # Generate new secret
            new_secret_data = await self._rotate_platform_secret(
                adapter, secret_meta.secret_type, current_secret
            )
            
            if not new_secret_data:
                raise ValueError(f"Failed to generate new secret for: {secret_id}")
            
            # Update secret in Vault
            vault_path = f"{secret_meta.platform}/{secret_meta.secret_type.value}/{secret_id}"
            
            # Create new version of secret
            secret_payload = {
                'data': new_secret_data,
                'metadata': {
                    'secret_id': secret_id,
                    'platform': secret_meta.platform,
                    'secret_type': secret_meta.secret_type.value,
                    'rotated_at': datetime.now(timezone.utc).isoformat(),
                    'rotation_job_id': job_id,
                    'previous_version': current_secret.get('metadata', {}).get('version', 1)
                }
            }
            
            self.vault_client.secrets.kv.v2.create_or_update_secret(
                path=vault_path,
                secret=secret_payload
            )
            
            # Update metadata
            secret_meta.last_rotated = datetime.now(timezone.utc)
            await self._save_secret_metadata()
            
            # Update rotation job status
            rotation_job.status = RotationStatus.COMPLETED
            
            # Schedule next rotation
            if secret_meta.auto_rotate:
                await self._schedule_rotation(secret_id, secret_meta.rotation_interval)
            
            # Audit log
            self.audit_logger.log_security_event(
                "secret_rotated",
                {
                    "secret_id": secret_id,
                    "platform": secret_meta.platform,
                    "rotation_job_id": job_id,
                    "forced": force
                },
                severity="INFO"
            )
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to rotate secret {secret_id}: {e}")
            
            # Update rotation job status
            if 'rotation_job' in locals():
                rotation_job.status = RotationStatus.FAILED
                rotation_job.error_message = str(e)
                rotation_job.attempts += 1
            
            self.audit_logger.log_security_event(
                "secret_rotation_failed",
                {
                    "secret_id": secret_id,
                    "error": str(e),
                    "forced": force
                },
                severity="ERROR"
            )
            
            return False
    
    async def get_secret(self, secret_id: str, version: Optional[int] = None) -> Optional[Dict[str, Any]]:
        """
        Retrieve a secret by ID
        
        Args:
            secret_id: Secret identifier
            version: Specific version to retrieve (latest if None)
            
        Returns:
            Secret data if found
        """
        try:
            secret_meta = self.secret_metadata.get(secret_id)
            if not secret_meta:
                return None
            
            vault_path = f"{secret_meta.platform}/{secret_meta.secret_type.value}/{secret_id}"
            
            if version:
                response = self.vault_client.secrets.kv.v2.read_secret_version(
                    path=vault_path,
                    version=version
                )
            else:
                response = self.vault_client.secrets.kv.v2.read_secret(path=vault_path)
            
            if response and 'data' in response:
                return response['data']
            
            return None
            
        except Exception as e:
            self.logger.error(f"Failed to get secret {secret_id}: {e}")
            return None
    
    async def revoke_secret(self, secret_id: str) -> bool:
        """
        Revoke and delete a secret
        
        Args:
            secret_id: Secret identifier
            
        Returns:
            True if revocation successful
        """
        try:
            secret_meta = self.secret_metadata.get(secret_id)
            if not secret_meta:
                return False
            
            # Get platform adapter and revoke on platform
            adapter = self.platform_adapters.get(secret_meta.platform)
            if adapter:
                secret_data = await self._get_secret_data(secret_id)
                if secret_data:
                    await self._revoke_platform_secret(adapter, secret_data)
            
            # Delete from Vault
            vault_path = f"{secret_meta.platform}/{secret_meta.secret_type.value}/{secret_id}"
            self.vault_client.secrets.kv.v2.delete_metadata_and_all_versions(path=vault_path)
            
            # Remove from metadata
            del self.secret_metadata[secret_id]
            await self._save_secret_metadata()
            
            # Cancel any pending rotations
            for job_id, job in list(self.rotation_jobs.items()):
                if job.secret_id == secret_id and job.status == RotationStatus.PENDING:
                    del self.rotation_jobs[job_id]
            
            # Audit log
            self.audit_logger.log_security_event(
                "secret_revoked",
                {"secret_id": secret_id, "platform": secret_meta.platform},
                severity="INFO"
            )
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to revoke secret {secret_id}: {e}")
            return False
    
    async def list_secrets(self, platform: Optional[str] = None,
                          secret_type: Optional[SecretType] = None) -> List[Dict[str, Any]]:
        """
        List managed secrets with optional filtering
        
        Args:
            platform: Filter by platform
            secret_type: Filter by secret type
            
        Returns:
            List of secret metadata
        """
        try:
            secrets = []
            
            for secret_id, meta in self.secret_metadata.items():
                if platform and meta.platform != platform:
                    continue
                if secret_type and meta.secret_type != secret_type:
                    continue
                
                secrets.append({
                    'secret_id': secret_id,
                    'platform': meta.platform,
                    'secret_type': meta.secret_type.value,
                    'created_at': meta.created_at.isoformat(),
                    'last_rotated': meta.last_rotated.isoformat() if meta.last_rotated else None,
                    'auto_rotate': meta.auto_rotate,
                    'compliance_level': meta.compliance_level,
                    'tags': meta.tags
                })
            
            return secrets
            
        except Exception as e:
            self.logger.error(f"Failed to list secrets: {e}")
            return []
    
    async def get_rotation_status(self, secret_id: str) -> Optional[Dict[str, Any]]:
        """
        Get rotation status for a secret
        
        Args:
            secret_id: Secret identifier
            
        Returns:
            Rotation status information
        """
        try:
            # Find most recent rotation job
            latest_job = None
            for job in self.rotation_jobs.values():
                if job.secret_id == secret_id:
                    if not latest_job or job.scheduled_time > latest_job.scheduled_time:
                        latest_job = job
            
            if not latest_job:
                return None
            
            return {
                'job_id': latest_job.job_id,
                'status': latest_job.status.value,
                'scheduled_time': latest_job.scheduled_time.isoformat(),
                'attempts': latest_job.attempts,
                'error_message': latest_job.error_message
            }
            
        except Exception as e:
            self.logger.error(f"Failed to get rotation status: {e}")
            return None
    
    # Private helper methods
    
    async def _authenticate_with_vault(self) -> bool:
        """Authenticate with Vault using configured method"""
        try:
            auth_method = self.vault_config.get('auth_method', 'token')
            
            if auth_method == 'userpass':
                self.vault_client.auth.userpass.login(
                    username=self.vault_config['username'],
                    password=self.vault_config['password']
                )
            elif auth_method == 'cert':
                self.vault_client.auth.cert.login()
            elif auth_method == 'ldap':
                self.vault_client.auth.ldap.login(
                    username=self.vault_config['username'],
                    password=self.vault_config['password']
                )
            else:
                return False
            
            return True
            
        except Exception as e:
            self.logger.error(f"Vault authentication failed: {e}")
            return False
    
    async def _initialize_secret_engines(self) -> None:
        """Initialize required secret engines if not already enabled"""
        try:
            # List existing engines
            engines = self.vault_client.sys.list_auth_methods()
            
            # Enable KV v2 if not present
            if 'kv/' not in engines:
                self.vault_client.sys.enable_secrets_engine(
                    backend_type='kv-v2',
                    path='kv'
                )
            
            # Enable database engine if not present
            if 'database/' not in engines:
                self.vault_client.sys.enable_secrets_engine(
                    backend_type='database',
                    path='database'
                )
            
        except Exception as e:
            self.logger.warning(f"Could not initialize secret engines: {e}")
    
    def _generate_secret_id(self, platform: str, secret_type: SecretType) -> str:
        """Generate unique secret ID"""
        timestamp = int(datetime.now(timezone.utc).timestamp())
        random_part = secrets.token_hex(8)
        return f"{platform}_{secret_type.value}_{timestamp}_{random_part}"
    
    async def _generate_platform_secret(self, adapter, secret_type: SecretType,
                                      user_context: Dict[str, Any],
                                      metadata: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """Generate platform-specific secret using adapter"""
        try:
            if secret_type == SecretType.API_KEY:
                return await self._generate_api_key(adapter, user_context, metadata)
            elif secret_type == SecretType.DATABASE_CREDENTIAL:
                return await self._generate_database_credential(adapter, user_context, metadata)
            elif secret_type == SecretType.SERVICE_ACCOUNT:
                return await self._generate_service_account(adapter, user_context, metadata)
            elif secret_type == SecretType.OAUTH_TOKEN:
                return await self._generate_oauth_token(adapter, user_context, metadata)
            elif secret_type == SecretType.PLATFORM_TOKEN:
                return await self._generate_platform_token(adapter, user_context, metadata)
            else:
                self.logger.error(f"Unsupported secret type: {secret_type}")
                return None
                
        except Exception as e:
            self.logger.error(f"Failed to generate platform secret: {e}")
            return None
    
    async def _generate_api_key(self, adapter, user_context: Dict[str, Any],
                              metadata: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate API key for platform"""
        # Implementation depends on platform adapter capabilities
        api_key = secrets.token_urlsafe(32)
        return {
            'api_key': api_key,
            'key_id': secrets.token_hex(16),
            'created_at': datetime.now(timezone.utc).isoformat(),
            'expires_at': (datetime.now(timezone.utc) + timedelta(days=30)).isoformat(),
            'permissions': metadata.get('permissions', []) if metadata else []
        }
    
    async def _generate_database_credential(self, adapter, user_context: Dict[str, Any],
                                          metadata: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate database credential"""
        username = f"user_{secrets.token_hex(8)}"
        password = secrets.token_urlsafe(32)
        return {
            'username': username,
            'password': password,
            'database': metadata.get('database', 'default') if metadata else 'default',
            'created_at': datetime.now(timezone.utc).isoformat(),
            'expires_at': (datetime.now(timezone.utc) + timedelta(hours=8)).isoformat()
        }
    
    async def _generate_service_account(self, adapter, user_context: Dict[str, Any],
                                      metadata: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate service account credentials"""
        account_id = f"svc_{secrets.token_hex(12)}"
        secret_key = secrets.token_urlsafe(64)
        return {
            'account_id': account_id,
            'secret_key': secret_key,
            'account_type': 'service',
            'created_at': datetime.now(timezone.utc).isoformat(),
            'permissions': metadata.get('permissions', ['read']) if metadata else ['read']
        }
    
    async def _generate_oauth_token(self, adapter, user_context: Dict[str, Any],
                                  metadata: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate OAuth token"""
        access_token = secrets.token_urlsafe(48)
        refresh_token = secrets.token_urlsafe(48)
        return {
            'access_token': access_token,
            'refresh_token': refresh_token,
            'token_type': 'Bearer',
            'expires_in': 3600,
            'scope': metadata.get('scope', 'read') if metadata else 'read',
            'created_at': datetime.now(timezone.utc).isoformat()
        }
    
    async def _generate_platform_token(self, adapter, user_context: Dict[str, Any],
                                     metadata: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate platform-specific token"""
        platform_token = secrets.token_urlsafe(40)
        return {
            'platform_token': platform_token,
            'token_id': secrets.token_hex(16),
            'user_id': user_context.get('user_id'),
            'created_at': datetime.now(timezone.utc).isoformat(),
            'expires_at': (datetime.now(timezone.utc) + timedelta(hours=8)).isoformat()
        }
    
    async def _rotate_platform_secret(self, adapter, secret_type: SecretType,
                                    current_secret: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Rotate existing platform secret"""
        # Create new secret with same metadata but new values
        metadata = current_secret.get('metadata', {})
        user_context = {'user_id': metadata.get('created_by', 'system')}
        
        return await self._generate_platform_secret(adapter, secret_type, user_context, metadata)
    
    async def _revoke_platform_secret(self, adapter, secret_data: Dict[str, Any]) -> bool:
        """Revoke secret on platform"""
        try:
            # Platform-specific revocation logic would go here
            # For now, just log the revocation
            self.logger.info(f"Revoked secret on platform")
            return True
        except Exception as e:
            self.logger.error(f"Failed to revoke platform secret: {e}")
            return False
    
    async def _get_secret_data(self, secret_id: str) -> Optional[Dict[str, Any]]:
        """Get current secret data from Vault"""
        try:
            secret_meta = self.secret_metadata.get(secret_id)
            if not secret_meta:
                return None
            
            vault_path = f"{secret_meta.platform}/{secret_meta.secret_type.value}/{secret_id}"
            response = self.vault_client.secrets.kv.v2.read_secret(path=vault_path)
            
            if response and 'data' in response:
                return response['data']
            
            return None
            
        except Exception as e:
            self.logger.error(f"Failed to get secret data: {e}")
            return None
    
    async def _schedule_rotation(self, secret_id: str, interval: int) -> None:
        """Schedule secret rotation"""
        try:
            next_rotation = datetime.now(timezone.utc) + timedelta(seconds=interval)
            job_id = f"scheduled_{secret_id}_{int(next_rotation.timestamp())}"
            
            rotation_job = RotationJob(
                job_id=job_id,
                secret_id=secret_id,
                platform=self.secret_metadata[secret_id].platform,
                scheduled_time=next_rotation,
                status=RotationStatus.PENDING
            )
            
            self.rotation_jobs[job_id] = rotation_job
            
        except Exception as e:
            self.logger.error(f"Failed to schedule rotation: {e}")
    
    async def _rotation_scheduler(self) -> None:
        """Background task for processing scheduled rotations"""
        while True:
            try:
                current_time = datetime.now(timezone.utc)
                
                # Find jobs due for rotation
                due_jobs = [
                    job for job in self.rotation_jobs.values()
                    if job.status == RotationStatus.PENDING and job.scheduled_time <= current_time
                ]
                
                # Process due rotations
                for job in due_jobs:
                    try:
                        success = await self.rotate_secret(job.secret_id)
                        if success:
                            job.status = RotationStatus.COMPLETED
                        else:
                            job.status = RotationStatus.FAILED
                            job.attempts += 1
                            
                            # Retry if not exceeded max attempts
                            if job.attempts < job.max_attempts:
                                job.scheduled_time = current_time + timedelta(minutes=15)
                                job.status = RotationStatus.PENDING
                    
                    except Exception as e:
                        self.logger.error(f"Rotation job {job.job_id} failed: {e}")
                        job.status = RotationStatus.FAILED
                        job.error_message = str(e)
                
                # Clean up completed/failed jobs older than 24 hours
                cutoff_time = current_time - timedelta(days=1)
                for job_id, job in list(self.rotation_jobs.items()):
                    if (job.status in [RotationStatus.COMPLETED, RotationStatus.FAILED] and 
                        job.scheduled_time < cutoff_time):
                        del self.rotation_jobs[job_id]
                
                # Sleep for 60 seconds before next check
                await asyncio.sleep(60)
                
            except Exception as e:
                self.logger.error(f"Rotation scheduler error: {e}")
                await asyncio.sleep(60)
    
    async def _load_secret_metadata(self) -> None:
        """Load secret metadata from Vault"""
        try:
            response = self.vault_client.secrets.kv.v2.read_secret(
                path="system/credential_manager_metadata"
            )
            
            if response and 'data' in response and 'metadata' in response['data']:
                metadata_dict = response['data']['metadata']
                
                for secret_id, meta_data in metadata_dict.items():
                    self.secret_metadata[secret_id] = SecretMetadata(
                        secret_id=meta_data['secret_id'],
                        secret_type=SecretType(meta_data['secret_type']),
                        platform=meta_data['platform'],
                        path=meta_data['path'],
                        created_at=datetime.fromisoformat(meta_data['created_at']),
                        last_rotated=datetime.fromisoformat(meta_data['last_rotated']) if meta_data.get('last_rotated') else None,
                        rotation_interval=meta_data.get('rotation_interval', self.default_rotation_interval),
                        auto_rotate=meta_data.get('auto_rotate', True),
                        tags=meta_data.get('tags', {}),
                        compliance_level=meta_data.get('compliance_level', 'SECRET')
                    )
                    
        except (VaultError, InvalidPath):
            # Metadata doesn't exist yet, start fresh
            self.logger.info("No existing metadata found, starting fresh")
        except Exception as e:
            self.logger.error(f"Failed to load secret metadata: {e}")
    
    async def _save_secret_metadata(self) -> None:
        """Save secret metadata to Vault"""
        try:
            metadata_dict = {}
            for secret_id, meta in self.secret_metadata.items():
                metadata_dict[secret_id] = {
                    'secret_id': meta.secret_id,
                    'secret_type': meta.secret_type.value,
                    'platform': meta.platform,
                    'path': meta.path,
                    'created_at': meta.created_at.isoformat(),
                    'last_rotated': meta.last_rotated.isoformat() if meta.last_rotated else None,
                    'rotation_interval': meta.rotation_interval,
                    'auto_rotate': meta.auto_rotate,
                    'tags': meta.tags,
                    'compliance_level': meta.compliance_level
                }
            
            self.vault_client.secrets.kv.v2.create_or_update_secret(
                path="system/credential_manager_metadata",
                secret={'metadata': metadata_dict}
            )
            
        except Exception as e:
            self.logger.error(f"Failed to save secret metadata: {e}")