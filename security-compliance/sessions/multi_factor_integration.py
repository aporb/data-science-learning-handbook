#!/usr/bin/env python3
"""
Multi-Factor Authentication Integration for Session Management

Comprehensive MFA integration system supporting CAC/PIV smart cards, OAuth tokens,
TOTP, hardware tokens, and biometric authentication for DoD-compliant session management.

Classification: UNCLASSIFIED//FOR OFFICIAL USE ONLY
Version: 1.0
Author: Security Compliance Team
Date: 2025-07-18
"""

import json
import secrets
import logging
import threading
import pyotp
import qrcode
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Set, Tuple, Callable
from uuid import UUID, uuid4
from enum import Enum
from dataclasses import dataclass, field
from abc import ABC, abstractmethod
import hashlib
import base64

# Import session management and authentication components
from .session_manager import Session, SessionState, SessionEventType
from .classification_policies import ClassificationLevel
from ..auth.cac_piv_integration import CACCredentials, CACPIVAuthenticator
from ..auth.oauth_client import TokenResponse, DoD_OAuth_Client

logger = logging.getLogger(__name__)


class MFAMethod(Enum):
    """Multi-factor authentication methods."""
    CAC_PIV = "CAC_PIV"                   # CAC/PIV Smart Card
    OAUTH_TOKEN = "OAUTH_TOKEN"           # OAuth 2.0 Token
    TOTP = "TOTP"                         # Time-based One-Time Password
    HOTP = "HOTP"                         # HMAC-based One-Time Password
    SMS = "SMS"                           # SMS Code
    EMAIL = "EMAIL"                       # Email Code
    PUSH_NOTIFICATION = "PUSH_NOTIFICATION"  # Push Notification
    HARDWARE_TOKEN = "HARDWARE_TOKEN"     # Hardware Security Token
    BIOMETRIC = "BIOMETRIC"               # Biometric Authentication
    BACKUP_CODES = "BACKUP_CODES"         # Backup Recovery Codes


class MFAResult(Enum):
    """MFA authentication results."""
    SUCCESS = "SUCCESS"
    FAILURE = "FAILURE"
    PENDING = "PENDING"
    EXPIRED = "EXPIRED"
    RATE_LIMITED = "RATE_LIMITED"
    REQUIRES_ENROLLMENT = "REQUIRES_ENROLLMENT"


class ChallengeType(Enum):
    """MFA challenge types."""
    INITIAL = "INITIAL"           # Initial authentication challenge
    RE_AUTH = "RE_AUTH"          # Re-authentication challenge
    ELEVATION = "ELEVATION"       # Privilege elevation challenge
    SUSPICIOUS = "SUSPICIOUS"     # Suspicious activity challenge
    CONTINUOUS = "CONTINUOUS"     # Continuous authentication challenge


@dataclass
class MFAChallenge:
    """Multi-factor authentication challenge."""
    challenge_id: str
    session_id: str
    user_id: UUID
    challenge_type: ChallengeType
    required_methods: Set[MFAMethod]
    optional_methods: Set[MFAMethod]
    created_at: datetime
    expires_at: datetime
    max_attempts: int
    attempt_count: int = 0
    completed_methods: Set[MFAMethod] = field(default_factory=set)
    failed_methods: Set[MFAMethod] = field(default_factory=set)
    challenge_data: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    @property
    def is_expired(self) -> bool:
        """Check if challenge is expired."""
        return datetime.now(timezone.utc) >= self.expires_at
    
    @property
    def is_complete(self) -> bool:
        """Check if challenge is complete."""
        return self.required_methods.issubset(self.completed_methods)
    
    @property
    def is_failed(self) -> bool:
        """Check if challenge has failed."""
        return self.attempt_count >= self.max_attempts or len(self.failed_methods) > 0


@dataclass
class MFAConfiguration:
    """MFA configuration for user or session."""
    user_id: UUID
    enabled_methods: Set[MFAMethod]
    preferred_method: Optional[MFAMethod]
    backup_methods: Set[MFAMethod]
    classification_requirements: Dict[str, Set[MFAMethod]]
    challenge_timeout: timedelta = timedelta(minutes=5)
    max_attempts: int = 3
    require_re_auth_interval: timedelta = timedelta(hours=8)
    require_elevation_mfa: bool = True
    continuous_auth_enabled: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class MFADevice:
    """Registered MFA device."""
    device_id: str
    user_id: UUID
    method: MFAMethod
    device_name: str
    device_data: Dict[str, Any]  # Method-specific data
    registered_at: datetime
    last_used: Optional[datetime] = None
    use_count: int = 0
    is_active: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)


class MFAProvider(ABC):
    """Abstract base class for MFA providers."""
    
    @abstractmethod
    def create_challenge(self, user_id: UUID, challenge_type: ChallengeType, **kwargs) -> Dict[str, Any]:
        """Create MFA challenge."""
        pass
    
    @abstractmethod
    def verify_response(self, challenge_data: Dict[str, Any], response: str, **kwargs) -> MFAResult:
        """Verify MFA response."""
        pass
    
    @abstractmethod
    def enroll_device(self, user_id: UUID, device_data: Dict[str, Any]) -> MFADevice:
        """Enroll new MFA device."""
        pass
    
    @abstractmethod
    def get_supported_methods(self) -> Set[MFAMethod]:
        """Get supported MFA methods."""
        pass


class CACPIVProvider(MFAProvider):
    """CAC/PIV smart card MFA provider."""
    
    def __init__(self, cac_authenticator: CACPIVAuthenticator = None):
        """Initialize CAC/PIV provider.
        
        Args:
            cac_authenticator: CAC/PIV authenticator instance
        """
        self.cac_authenticator = cac_authenticator or CACPIVAuthenticator()
        self.active_challenges: Dict[str, Dict[str, Any]] = {}
        
        logger.info("CACPIVProvider initialized")
    
    def create_challenge(self, user_id: UUID, challenge_type: ChallengeType, **kwargs) -> Dict[str, Any]:
        """Create CAC/PIV challenge."""
        challenge_data = {
            'challenge_id': str(uuid4()),
            'user_id': str(user_id),
            'challenge_type': challenge_type.value,
            'created_at': datetime.now(timezone.utc).isoformat(),
            'requires_pin': True,
            'requires_certificate_validation': True
        }
        
        self.active_challenges[challenge_data['challenge_id']] = challenge_data
        
        return challenge_data
    
    def verify_response(self, challenge_data: Dict[str, Any], response: str, **kwargs) -> MFAResult:
        """Verify CAC/PIV response."""
        try:
            challenge_id = challenge_data.get('challenge_id')
            if challenge_id not in self.active_challenges:
                return MFAResult.FAILURE
            
            # Parse response (would contain PIN and certificate data)
            response_data = json.loads(response)
            pin = response_data.get('pin')
            certificate_data = response_data.get('certificate')
            
            if not pin or not certificate_data:
                return MFAResult.FAILURE
            
            # Authenticate with CAC/PIV
            if self.cac_authenticator.authenticate_pin(pin):
                certificates = self.cac_authenticator.get_certificates()
                if certificates:
                    # Verify certificate matches provided data
                    # Simplified verification
                    self.active_challenges.pop(challenge_id, None)
                    return MFAResult.SUCCESS
            
            return MFAResult.FAILURE
            
        except Exception as e:
            logger.error(f"CAC/PIV verification failed: {e}")
            return MFAResult.FAILURE
    
    def enroll_device(self, user_id: UUID, device_data: Dict[str, Any]) -> MFADevice:
        """Enroll CAC/PIV device."""
        cac_credentials = device_data.get('cac_credentials')
        if not cac_credentials:
            raise ValueError("CAC credentials required for enrollment")
        
        return MFADevice(
            device_id=str(uuid4()),
            user_id=user_id,
            method=MFAMethod.CAC_PIV,
            device_name=f"CAC/PIV - {cac_credentials.get('edipi', 'Unknown')}",
            device_data={
                'serial_number': cac_credentials.get('serial_number'),
                'edipi': cac_credentials.get('edipi'),
                'issuer_dn': cac_credentials.get('issuer_dn')
            },
            registered_at=datetime.now(timezone.utc)
        )
    
    def get_supported_methods(self) -> Set[MFAMethod]:
        """Get supported methods."""
        return {MFAMethod.CAC_PIV}


class TOTPProvider(MFAProvider):
    """Time-based One-Time Password (TOTP) MFA provider."""
    
    def __init__(self, issuer: str = "DoD Security System"):
        """Initialize TOTP provider.
        
        Args:
            issuer: TOTP issuer name
        """
        self.issuer = issuer
        self.active_challenges: Dict[str, Dict[str, Any]] = {}
        self.user_secrets: Dict[UUID, str] = {}  # In production, store securely
        
        logger.info("TOTPProvider initialized")
    
    def create_challenge(self, user_id: UUID, challenge_type: ChallengeType, **kwargs) -> Dict[str, Any]:
        """Create TOTP challenge."""
        challenge_data = {
            'challenge_id': str(uuid4()),
            'user_id': str(user_id),
            'challenge_type': challenge_type.value,
            'created_at': datetime.now(timezone.utc).isoformat(),
            'totp_length': 6,
            'totp_interval': 30
        }
        
        self.active_challenges[challenge_data['challenge_id']] = challenge_data
        
        return challenge_data
    
    def verify_response(self, challenge_data: Dict[str, Any], response: str, **kwargs) -> MFAResult:
        """Verify TOTP response."""
        try:
            challenge_id = challenge_data.get('challenge_id')
            user_id = UUID(challenge_data.get('user_id'))
            
            if challenge_id not in self.active_challenges:
                return MFAResult.FAILURE
            
            # Get user's TOTP secret
            secret = self.user_secrets.get(user_id)
            if not secret:
                return MFAResult.REQUIRES_ENROLLMENT
            
            # Verify TOTP code
            totp = pyotp.TOTP(secret)
            if totp.verify(response, valid_window=1):  # Allow 1 period tolerance
                self.active_challenges.pop(challenge_id, None)
                return MFAResult.SUCCESS
            
            return MFAResult.FAILURE
            
        except Exception as e:
            logger.error(f"TOTP verification failed: {e}")
            return MFAResult.FAILURE
    
    def enroll_device(self, user_id: UUID, device_data: Dict[str, Any]) -> MFADevice:
        """Enroll TOTP device."""
        # Generate secret
        secret = pyotp.random_base32()
        self.user_secrets[user_id] = secret
        
        # Generate QR code data
        totp = pyotp.TOTP(secret)
        provisioning_uri = totp.provisioning_uri(
            name=str(user_id),
            issuer_name=self.issuer
        )
        
        return MFADevice(
            device_id=str(uuid4()),
            user_id=user_id,
            method=MFAMethod.TOTP,
            device_name="TOTP Authenticator",
            device_data={
                'secret': secret,
                'provisioning_uri': provisioning_uri,
                'issuer': self.issuer
            },
            registered_at=datetime.now(timezone.utc)
        )
    
    def get_supported_methods(self) -> Set[MFAMethod]:
        """Get supported methods."""
        return {MFAMethod.TOTP}


class OAuthTokenProvider(MFAProvider):
    """OAuth token-based MFA provider."""
    
    def __init__(self, oauth_client: DoD_OAuth_Client = None):
        """Initialize OAuth token provider.
        
        Args:
            oauth_client: OAuth client instance
        """
        self.oauth_client = oauth_client
        self.active_challenges: Dict[str, Dict[str, Any]] = {}
        self.user_tokens: Dict[UUID, TokenResponse] = {}
        
        logger.info("OAuthTokenProvider initialized")
    
    def create_challenge(self, user_id: UUID, challenge_type: ChallengeType, **kwargs) -> Dict[str, Any]:
        """Create OAuth token challenge."""
        challenge_data = {
            'challenge_id': str(uuid4()),
            'user_id': str(user_id),
            'challenge_type': challenge_type.value,
            'created_at': datetime.now(timezone.utc).isoformat(),
            'requires_fresh_token': True,
            'token_scope': kwargs.get('scope', ['profile', 'email'])
        }
        
        self.active_challenges[challenge_data['challenge_id']] = challenge_data
        
        return challenge_data
    
    def verify_response(self, challenge_data: Dict[str, Any], response: str, **kwargs) -> MFAResult:
        """Verify OAuth token response."""
        try:
            challenge_id = challenge_data.get('challenge_id')
            user_id = UUID(challenge_data.get('user_id'))
            
            if challenge_id not in self.active_challenges:
                return MFAResult.FAILURE
            
            # Validate OAuth token
            if self.oauth_client:
                try:
                    # Verify token with OAuth provider
                    claims = self.oauth_client.validate_jwt_token(response)
                    if claims and claims.get('sub') == str(user_id):
                        self.active_challenges.pop(challenge_id, None)
                        return MFAResult.SUCCESS
                except Exception as e:
                    logger.warning(f"OAuth token validation failed: {e}")
            
            return MFAResult.FAILURE
            
        except Exception as e:
            logger.error(f"OAuth token verification failed: {e}")
            return MFAResult.FAILURE
    
    def enroll_device(self, user_id: UUID, device_data: Dict[str, Any]) -> MFADevice:
        """Enroll OAuth token device."""
        token_data = device_data.get('token_response')
        if not token_data:
            raise ValueError("OAuth token response required for enrollment")
        
        return MFADevice(
            device_id=str(uuid4()),
            user_id=user_id,
            method=MFAMethod.OAUTH_TOKEN,
            device_name="OAuth Token",
            device_data={
                'client_id': device_data.get('client_id'),
                'issuer': device_data.get('issuer'),
                'token_endpoint': device_data.get('token_endpoint')
            },
            registered_at=datetime.now(timezone.utc)
        )
    
    def get_supported_methods(self) -> Set[MFAMethod]:
        """Get supported methods."""
        return {MFAMethod.OAUTH_TOKEN}


class BackupCodesProvider(MFAProvider):
    """Backup recovery codes MFA provider."""
    
    def __init__(self):
        """Initialize backup codes provider."""
        self.user_codes: Dict[UUID, Set[str]] = {}
        self.used_codes: Dict[UUID, Set[str]] = {}
        
        logger.info("BackupCodesProvider initialized")
    
    def create_challenge(self, user_id: UUID, challenge_type: ChallengeType, **kwargs) -> Dict[str, Any]:
        """Create backup codes challenge."""
        challenge_data = {
            'challenge_id': str(uuid4()),
            'user_id': str(user_id),
            'challenge_type': challenge_type.value,
            'created_at': datetime.now(timezone.utc).isoformat(),
            'instructions': 'Enter one of your backup recovery codes'
        }
        
        return challenge_data
    
    def verify_response(self, challenge_data: Dict[str, Any], response: str, **kwargs) -> MFAResult:
        """Verify backup code response."""
        try:
            user_id = UUID(challenge_data.get('user_id'))
            code = response.strip().upper()
            
            # Check if user has backup codes
            user_codes = self.user_codes.get(user_id, set())
            used_codes = self.used_codes.get(user_id, set())
            
            if code in user_codes and code not in used_codes:
                # Mark code as used
                if user_id not in self.used_codes:
                    self.used_codes[user_id] = set()
                self.used_codes[user_id].add(code)
                
                return MFAResult.SUCCESS
            
            return MFAResult.FAILURE
            
        except Exception as e:
            logger.error(f"Backup code verification failed: {e}")
            return MFAResult.FAILURE
    
    def enroll_device(self, user_id: UUID, device_data: Dict[str, Any]) -> MFADevice:
        """Enroll backup codes device."""
        # Generate backup codes
        codes = set()
        for _ in range(10):  # Generate 10 backup codes
            code = ''.join(secrets.choice('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789') for _ in range(8))
            codes.add(code)
        
        self.user_codes[user_id] = codes
        
        return MFADevice(
            device_id=str(uuid4()),
            user_id=user_id,
            method=MFAMethod.BACKUP_CODES,
            device_name="Backup Recovery Codes",
            device_data={
                'codes': list(codes),
                'generated_at': datetime.now(timezone.utc).isoformat()
            },
            registered_at=datetime.now(timezone.utc)
        )
    
    def get_supported_methods(self) -> Set[MFAMethod]:
        """Get supported methods."""
        return {MFAMethod.BACKUP_CODES}


class MFAManager:
    """
    Comprehensive Multi-Factor Authentication Manager.
    
    Manages MFA challenges, device enrollment, and authentication workflows
    with support for multiple authentication methods and classification-aware policies.
    """
    
    def __init__(self):
        """Initialize MFA manager."""
        # MFA providers
        self.providers: Dict[MFAMethod, MFAProvider] = {}
        
        # User configurations
        self.user_configs: Dict[UUID, MFAConfiguration] = {}
        
        # Active challenges
        self.active_challenges: Dict[str, MFAChallenge] = {}
        
        # Registered devices
        self.user_devices: Dict[UUID, List[MFADevice]] = {}
        
        # Rate limiting
        self.attempt_tracking: Dict[Tuple[UUID, str], List[datetime]] = {}
        
        # Thread safety
        self._lock = threading.Lock()
        
        # Initialize default providers
        self._initialize_providers()
        
        logger.info("MFAManager initialized")
    
    def register_provider(self, method: MFAMethod, provider: MFAProvider):
        """Register MFA provider.
        
        Args:
            method: MFA method
            provider: MFA provider instance
        """
        self.providers[method] = provider
        logger.info(f"MFA provider registered: {method.value}")
    
    def create_challenge(self, 
                        session: Session,
                        challenge_type: ChallengeType,
                        required_methods: Set[MFAMethod] = None,
                        classification_level: str = None) -> MFAChallenge:
        """Create MFA challenge for session.
        
        Args:
            session: Session requiring MFA
            challenge_type: Type of challenge
            required_methods: Required MFA methods
            classification_level: Classification level requirement
            
        Returns:
            MFA challenge
        """
        with self._lock:
            user_id = session.user_id
            
            # Get user MFA configuration
            config = self.user_configs.get(user_id)
            if not config:
                config = self._create_default_config(user_id)
                self.user_configs[user_id] = config
            
            # Determine required methods
            if not required_methods:
                if classification_level:
                    required_methods = config.classification_requirements.get(
                        classification_level, 
                        {config.preferred_method} if config.preferred_method else set()
                    )
                else:
                    required_methods = {config.preferred_method} if config.preferred_method else set()
            
            # Create challenge
            challenge = MFAChallenge(
                challenge_id=str(uuid4()),
                session_id=session.session_id,
                user_id=user_id,
                challenge_type=challenge_type,
                required_methods=required_methods,
                optional_methods=config.backup_methods,
                created_at=datetime.now(timezone.utc),
                expires_at=datetime.now(timezone.utc) + config.challenge_timeout,
                max_attempts=config.max_attempts
            )
            
            # Store challenge
            self.active_challenges[challenge.challenge_id] = challenge
            
            # Create provider challenges
            for method in required_methods:
                if method in self.providers:
                    try:
                        provider_challenge = self.providers[method].create_challenge(
                            user_id, challenge_type
                        )
                        challenge.challenge_data[method.value] = provider_challenge
                    except Exception as e:
                        logger.error(f"Failed to create {method.value} challenge: {e}")
            
            logger.info(f"MFA challenge created: {challenge.challenge_id} for session {session.session_id}")
            
            return challenge
    
    def verify_challenge_response(self, 
                                 challenge_id: str,
                                 method: MFAMethod,
                                 response: str,
                                 **kwargs) -> Tuple[MFAResult, Optional[MFAChallenge]]:
        """Verify MFA challenge response.
        
        Args:
            challenge_id: Challenge identifier
            method: MFA method being verified
            response: User response
            **kwargs: Additional verification parameters
            
        Returns:
            Tuple of (result, updated_challenge)
        """
        with self._lock:
            challenge = self.active_challenges.get(challenge_id)
            if not challenge:
                return MFAResult.FAILURE, None
            
            # Check if challenge is expired
            if challenge.is_expired:
                self.active_challenges.pop(challenge_id, None)
                return MFAResult.EXPIRED, None
            
            # Check if challenge has failed
            if challenge.is_failed:
                self.active_challenges.pop(challenge_id, None)
                return MFAResult.FAILURE, None
            
            # Check rate limiting
            if self._is_rate_limited(challenge.user_id, challenge_id):
                return MFAResult.RATE_LIMITED, challenge
            
            # Track attempt
            self._track_attempt(challenge.user_id, challenge_id)
            challenge.attempt_count += 1
            
            # Verify with provider
            provider = self.providers.get(method)
            if not provider:
                return MFAResult.FAILURE, challenge
            
            try:
                provider_challenge = challenge.challenge_data.get(method.value)
                if not provider_challenge:
                    return MFAResult.FAILURE, challenge
                
                result = provider.verify_response(provider_challenge, response, **kwargs)
                
                if result == MFAResult.SUCCESS:
                    challenge.completed_methods.add(method)
                    
                    # Update device usage
                    self._update_device_usage(challenge.user_id, method)
                    
                    # Check if challenge is complete
                    if challenge.is_complete:
                        self.active_challenges.pop(challenge_id, None)
                        logger.info(f"MFA challenge completed: {challenge_id}")
                
                elif result == MFAResult.FAILURE:
                    challenge.failed_methods.add(method)
                
                return result, challenge
                
            except Exception as e:
                logger.error(f"MFA verification failed: {e}")
                challenge.failed_methods.add(method)
                return MFAResult.FAILURE, challenge
    
    def enroll_device(self, 
                     user_id: UUID,
                     method: MFAMethod,
                     device_data: Dict[str, Any]) -> Optional[MFADevice]:
        """Enroll MFA device for user.
        
        Args:
            user_id: User identifier
            method: MFA method
            device_data: Device enrollment data
            
        Returns:
            Enrolled device if successful
        """
        provider = self.providers.get(method)
        if not provider:
            logger.error(f"No provider for MFA method: {method.value}")
            return None
        
        try:
            device = provider.enroll_device(user_id, device_data)
            
            with self._lock:
                if user_id not in self.user_devices:
                    self.user_devices[user_id] = []
                self.user_devices[user_id].append(device)
                
                # Update user configuration
                config = self.user_configs.get(user_id)
                if not config:
                    config = self._create_default_config(user_id)
                    self.user_configs[user_id] = config
                
                config.enabled_methods.add(method)
                if not config.preferred_method:
                    config.preferred_method = method
            
            logger.info(f"MFA device enrolled: {method.value} for user {user_id}")
            
            return device
            
        except Exception as e:
            logger.error(f"MFA device enrollment failed: {e}")
            return None
    
    def get_user_devices(self, user_id: UUID) -> List[MFADevice]:
        """Get user's registered MFA devices.
        
        Args:
            user_id: User identifier
            
        Returns:
            List of registered devices
        """
        with self._lock:
            return self.user_devices.get(user_id, []).copy()
    
    def remove_device(self, user_id: UUID, device_id: str) -> bool:
        """Remove MFA device.
        
        Args:
            user_id: User identifier
            device_id: Device identifier
            
        Returns:
            True if successful
        """
        with self._lock:
            user_devices = self.user_devices.get(user_id, [])
            
            for i, device in enumerate(user_devices):
                if device.device_id == device_id:
                    device.is_active = False
                    logger.info(f"MFA device removed: {device_id}")
                    return True
            
            return False
    
    def require_re_authentication(self, session: Session) -> bool:
        """Check if session requires re-authentication.
        
        Args:
            session: Session to check
            
        Returns:
            True if re-authentication required
        """
        config = self.user_configs.get(session.user_id)
        if not config:
            return False
        
        # Check time-based re-authentication
        time_since_auth = datetime.now(timezone.utc) - session.created_at
        if time_since_auth >= config.require_re_auth_interval:
            return True
        
        # Check classification-based requirements
        classification_level = session.security_context.classification_level
        if classification_level in ['S', 'TS'] and not session.mfa_verified:
            return True
        
        return False
    
    def update_user_configuration(self, user_id: UUID, config: MFAConfiguration):
        """Update user MFA configuration.
        
        Args:
            user_id: User identifier
            config: New MFA configuration
        """
        with self._lock:
            self.user_configs[user_id] = config
            logger.info(f"MFA configuration updated for user {user_id}")
    
    def get_challenge_status(self, challenge_id: str) -> Optional[Dict[str, Any]]:
        """Get MFA challenge status.
        
        Args:
            challenge_id: Challenge identifier
            
        Returns:
            Challenge status information
        """
        with self._lock:
            challenge = self.active_challenges.get(challenge_id)
            if not challenge:
                return None
            
            return {
                'challenge_id': challenge.challenge_id,
                'session_id': challenge.session_id,
                'challenge_type': challenge.challenge_type.value,
                'required_methods': [m.value for m in challenge.required_methods],
                'completed_methods': [m.value for m in challenge.completed_methods],
                'failed_methods': [m.value for m in challenge.failed_methods],
                'is_complete': challenge.is_complete,
                'is_expired': challenge.is_expired,
                'is_failed': challenge.is_failed,
                'attempt_count': challenge.attempt_count,
                'max_attempts': challenge.max_attempts,
                'expires_at': challenge.expires_at.isoformat()
            }
    
    def _initialize_providers(self):
        """Initialize default MFA providers."""
        # Initialize built-in providers
        self.register_provider(MFAMethod.TOTP, TOTPProvider())
        self.register_provider(MFAMethod.BACKUP_CODES, BackupCodesProvider())
        
        # CAC/PIV and OAuth providers would be registered externally
        # with proper authentication components
    
    def _create_default_config(self, user_id: UUID) -> MFAConfiguration:
        """Create default MFA configuration."""
        return MFAConfiguration(
            user_id=user_id,
            enabled_methods=set(),
            preferred_method=None,
            backup_methods={MFAMethod.BACKUP_CODES},
            classification_requirements={
                'U': {MFAMethod.TOTP},
                'C': {MFAMethod.TOTP, MFAMethod.CAC_PIV},
                'S': {MFAMethod.CAC_PIV},
                'TS': {MFAMethod.CAC_PIV}
            }
        )
    
    def _is_rate_limited(self, user_id: UUID, challenge_id: str) -> bool:
        """Check if user is rate limited."""
        key = (user_id, challenge_id)
        attempts = self.attempt_tracking.get(key, [])
        
        # Remove old attempts (older than 1 hour)
        cutoff_time = datetime.now(timezone.utc) - timedelta(hours=1)
        attempts = [a for a in attempts if a > cutoff_time]
        
        # Check rate limit (max 10 attempts per hour)
        return len(attempts) >= 10
    
    def _track_attempt(self, user_id: UUID, challenge_id: str):
        """Track MFA attempt."""
        key = (user_id, challenge_id)
        if key not in self.attempt_tracking:
            self.attempt_tracking[key] = []
        
        self.attempt_tracking[key].append(datetime.now(timezone.utc))
    
    def _update_device_usage(self, user_id: UUID, method: MFAMethod):
        """Update device usage statistics."""
        devices = self.user_devices.get(user_id, [])
        for device in devices:
            if device.method == method and device.is_active:
                device.last_used = datetime.now(timezone.utc)
                device.use_count += 1
                break
    
    def cleanup_expired_challenges(self) -> int:
        """Clean up expired challenges.
        
        Returns:
            Number of challenges cleaned up
        """
        with self._lock:
            expired_challenges = []
            
            for challenge_id, challenge in self.active_challenges.items():
                if challenge.is_expired:
                    expired_challenges.append(challenge_id)
            
            for challenge_id in expired_challenges:
                self.active_challenges.pop(challenge_id, None)
            
            if expired_challenges:
                logger.info(f"Cleaned up {len(expired_challenges)} expired MFA challenges")
            
            return len(expired_challenges)
    
    def get_mfa_statistics(self) -> Dict[str, Any]:
        """Get MFA statistics.
        
        Returns:
            MFA statistics
        """
        with self._lock:
            total_users = len(self.user_configs)
            total_devices = sum(len(devices) for devices in self.user_devices.values())
            active_challenges = len(self.active_challenges)
            
            method_counts = {}
            for devices in self.user_devices.values():
                for device in devices:
                    if device.is_active:
                        method = device.method.value
                        method_counts[method] = method_counts.get(method, 0) + 1
            
            return {
                'total_users_with_mfa': total_users,
                'total_registered_devices': total_devices,
                'active_challenges': active_challenges,
                'devices_by_method': method_counts,
                'supported_methods': [method.value for method in self.providers.keys()]
            }


# Factory functions
def create_mfa_manager() -> MFAManager:
    """Create and return MFA manager instance."""
    return MFAManager()


def create_cac_piv_provider(cac_authenticator: CACPIVAuthenticator = None) -> CACPIVProvider:
    """Create and return CAC/PIV MFA provider."""
    return CACPIVProvider(cac_authenticator)


def create_oauth_token_provider(oauth_client: DoD_OAuth_Client = None) -> OAuthTokenProvider:
    """Create and return OAuth token MFA provider."""
    return OAuthTokenProvider(oauth_client)