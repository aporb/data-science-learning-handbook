"""
OAuth-CAC Integration Bridge
Combines OAuth 2.0 authentication with CAC/PIV smart card authentication
for enhanced DoD platform security.
"""

import logging
import secrets
import threading
from typing import Dict, Optional, List, Any, Tuple
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from urllib.parse import urlencode, parse_qs, urlparse

# Import OAuth components
from .oauth_client import DoD_OAuth_Client, DoD_OAuth_Manager, Platform, TokenResponse, OAuthConfig
from .oauth_config import DoD_OAuth_Configurator, Environment

# Import CAC components
from .cac_piv_integration import CACAuthenticationManager, CACCredentials

# Import secure storage
from .secure_token_storage import TokenStorageManager

# Import audit logging
from .security_managers import AuditLogger, AuditEvent, AuditEventType

logger = logging.getLogger(__name__)


class AuthenticationMode(Enum):
    """Authentication modes for OAuth-CAC integration."""
    CAC_ONLY = "cac_only"
    OAUTH_ONLY = "oauth_only"
    CAC_THEN_OAUTH = "cac_then_oauth"
    OAUTH_WITH_CAC_BINDING = "oauth_with_cac_binding"
    DUAL_FACTOR = "dual_factor"


class AuthenticationResult(Enum):
    """Authentication result status."""
    SUCCESS = "success"
    CAC_REQUIRED = "cac_required"
    OAUTH_REQUIRED = "oauth_required"
    FAILED = "failed"
    EXPIRED = "expired"
    INSUFFICIENT_CLEARANCE = "insufficient_clearance"


@dataclass
class IntegratedCredentials:
    """Combined CAC and OAuth credentials."""
    cac_credentials: Optional[CACCredentials] = None
    oauth_token: Optional[TokenResponse] = None
    platform: Optional[Platform] = None
    user_id: str = ""
    session_id: str = ""
    authentication_mode: AuthenticationMode = AuthenticationMode.CAC_ONLY
    authenticated_at: datetime = None
    expires_at: datetime = None
    clearance_level: str = "UNCLASSIFIED"
    roles: List[str] = None
    metadata: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.authenticated_at is None:
            self.authenticated_at = datetime.now(timezone.utc)
        if self.expires_at is None:
            # Default 1 hour expiration
            self.expires_at = self.authenticated_at + timedelta(hours=1)
        if self.roles is None:
            self.roles = []
        if self.metadata is None:
            self.metadata = {}
    
    @property
    def is_expired(self) -> bool:
        """Check if credentials are expired."""
        return datetime.now(timezone.utc) >= self.expires_at
    
    @property
    def is_cac_authenticated(self) -> bool:
        """Check if CAC authentication is present."""
        return self.cac_credentials is not None
    
    @property
    def is_oauth_authenticated(self) -> bool:
        """Check if OAuth authentication is present."""
        return self.oauth_token is not None and not self.oauth_token.is_expired
    
    @property
    def effective_user_id(self) -> str:
        """Get effective user ID (prefer EDIPI from CAC)."""
        if self.cac_credentials and self.cac_credentials.edipi:
            return self.cac_credentials.edipi
        return self.user_id


class OAuthCACBridge:
    """
    OAuth-CAC Authentication Bridge.
    
    Provides integrated authentication combining:
    - CAC/PIV smart card authentication
    - OAuth 2.0 platform authentication
    - Secure token storage and management
    - Multi-factor authentication workflows
    """
    
    def __init__(self, 
                 environment: Environment = Environment.NIPR,
                 default_mode: AuthenticationMode = AuthenticationMode.CAC_THEN_OAUTH,
                 session_timeout: int = 3600,
                 enable_token_storage: bool = True):
        """
        Initialize OAuth-CAC bridge.
        
        Args:
            environment: DoD network environment
            default_mode: Default authentication mode
            session_timeout: Session timeout in seconds
            enable_token_storage: Enable secure token storage
        """
        self.environment = environment
        self.default_mode = default_mode
        self.session_timeout = session_timeout
        self.enable_token_storage = enable_token_storage
        
        # Initialize components
        self.oauth_configurator = DoD_OAuth_Configurator(environment)
        self.oauth_manager = DoD_OAuth_Manager()
        self.cac_auth_manager = CACAuthenticationManager()
        
        # Initialize token storage if enabled
        if self.enable_token_storage:
            self.token_storage = TokenStorageManager.instance()
        
        # Active sessions
        self._sessions: Dict[str, IntegratedCredentials] = {}
        self._lock = threading.RLock()
        
        # Platform configurations
        self._platform_configs: Dict[Platform, OAuthConfig] = {}
        
        logger.info(f"OAuth-CAC bridge initialized for {environment.value}")
    
    def configure_platform(self, platform: Platform, 
                          client_id: str, client_secret: str, 
                          redirect_uri: str,
                          scopes: Optional[List[str]] = None) -> bool:
        """
        Configure OAuth for a specific platform.
        
        Args:
            platform: Target platform
            client_id: OAuth client ID
            client_secret: OAuth client secret
            redirect_uri: OAuth redirect URI
            scopes: Optional custom scopes
            
        Returns:
            True if configuration successful
        """
        try:
            config = self.oauth_configurator.create_config(
                platform=platform,
                client_id=client_id,
                client_secret=client_secret,
                redirect_uri=redirect_uri,
                scopes=scopes
            )
            
            # Validate configuration
            validation_errors = self.oauth_configurator.validate_config(config)
            if validation_errors:
                logger.error(f"OAuth config validation failed: {validation_errors}")
                return False
            
            # Store configuration and create OAuth client
            self._platform_configs[platform] = config
            self.oauth_manager.add_platform(config)
            
            logger.info(f"Platform {platform.value} configured successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to configure platform {platform.value}: {e}")
            return False
    
    def authenticate_with_cac(self, pin: str, 
                             platform: Optional[Platform] = None,
                             required_clearance: str = "UNCLASSIFIED") -> Tuple[AuthenticationResult, Optional[IntegratedCredentials]]:
        """
        Authenticate user with CAC/PIV card.
        
        Args:
            pin: CAC PIN
            platform: Target platform (for role determination)
            required_clearance: Minimum required clearance level
            
        Returns:
            Tuple of (result, credentials)
        """
        with self._lock:
            try:
                # Perform CAC authentication
                cac_credentials = self.cac_auth_manager.authenticate_user(pin)
                if not cac_credentials:
                    return AuthenticationResult.FAILED, None
                
                # Check clearance level
                if not self._check_clearance_level(cac_credentials.clearance_level, required_clearance):
                    logger.warning(f"Insufficient clearance: {cac_credentials.clearance_level} < {required_clearance}")
                    return AuthenticationResult.INSUFFICIENT_CLEARANCE, None
                
                # Create integrated credentials
                session_id = self._generate_session_id()
                user_id = cac_credentials.edipi or "unknown"
                
                credentials = IntegratedCredentials(
                    cac_credentials=cac_credentials,
                    platform=platform,
                    user_id=user_id,
                    session_id=session_id,
                    authentication_mode=AuthenticationMode.CAC_ONLY,
                    clearance_level=cac_credentials.clearance_level or "UNCLASSIFIED",
                    roles=self._determine_cac_roles(cac_credentials, platform),
                    expires_at=datetime.now(timezone.utc) + timedelta(seconds=self.session_timeout)
                )
                
                # Store session
                self._sessions[session_id] = credentials
                
                # Log successful authentication
                AuditLogger.instance().log_event(AuditEvent(
                    event_type=AuditEventType.AUTHENTICATION_SUCCESS,
                    timestamp=datetime.now(timezone.utc),
                    user_id=user_id,
                    success=True,
                    additional_data={
                        "method": "CAC",
                        "clearance_level": cac_credentials.clearance_level,
                        "platform": platform.value if platform else None,
                        "session_id": session_id
                    }
                ))
                
                logger.info(f"CAC authentication successful for EDIPI: {user_id}")
                return AuthenticationResult.SUCCESS, credentials
                
            except Exception as e:
                logger.error(f"CAC authentication failed: {e}")
                AuditLogger.instance().log_event(AuditEvent(
                    event_type=AuditEventType.AUTHENTICATION_FAILURE,
                    timestamp=datetime.now(timezone.utc),
                    user_id="unknown",
                    success=False,
                    error_message=str(e),
                    additional_data={"method": "CAC"}
                ))
                return AuthenticationResult.FAILED, None
    
    def authenticate_with_oauth(self, platform: Platform, 
                               authorization_code: str,
                               state: str,
                               cac_credentials: Optional[CACCredentials] = None) -> Tuple[AuthenticationResult, Optional[IntegratedCredentials]]:
        """
        Authenticate user with OAuth 2.0.
        
        Args:
            platform: OAuth platform
            authorization_code: Authorization code from callback
            state: State parameter for CSRF protection
            cac_credentials: Optional CAC credentials for binding
            
        Returns:
            Tuple of (result, credentials)
        """
        with self._lock:
            try:
                # Get OAuth client for platform
                oauth_client = self.oauth_manager.get_client(platform)
                if not oauth_client:
                    logger.error(f"OAuth client not configured for platform: {platform.value}")
                    return AuthenticationResult.FAILED, None
                
                # Exchange authorization code for token
                token = oauth_client.exchange_code_for_token(authorization_code, state)
                if not token:
                    return AuthenticationResult.FAILED, None
                
                # Get user info from OAuth provider
                user_info = oauth_client.get_user_info(token.access_token)
                user_id = user_info.get("sub", user_info.get("id", "unknown"))
                
                # If CAC credentials provided, bind them
                if cac_credentials:
                    # Verify EDIPI matches if available in OAuth user info
                    oauth_edipi = user_info.get("edipi")
                    if oauth_edipi and oauth_edipi != cac_credentials.edipi:
                        logger.warning(f"EDIPI mismatch: CAC={cac_credentials.edipi}, OAuth={oauth_edipi}")
                        return AuthenticationResult.FAILED, None
                    user_id = cac_credentials.edipi or user_id
                
                # Create integrated credentials
                session_id = self._generate_session_id()
                auth_mode = (AuthenticationMode.OAUTH_WITH_CAC_BINDING if cac_credentials 
                           else AuthenticationMode.OAUTH_ONLY)
                
                credentials = IntegratedCredentials(
                    cac_credentials=cac_credentials,
                    oauth_token=token,
                    platform=platform,
                    user_id=user_id,
                    session_id=session_id,
                    authentication_mode=auth_mode,
                    clearance_level=cac_credentials.clearance_level if cac_credentials else "UNCLASSIFIED",
                    roles=self._determine_oauth_roles(user_info, platform, cac_credentials),
                    expires_at=min(
                        token.expires_at,
                        datetime.now(timezone.utc) + timedelta(seconds=self.session_timeout)
                    ),
                    metadata={"oauth_user_info": user_info}
                )
                
                # Store session
                self._sessions[session_id] = credentials
                
                # Store token securely if enabled
                if self.enable_token_storage:
                    try:
                        self.token_storage.store_token(
                            platform=platform,
                            user_id=user_id,
                            token=token,
                            metadata={
                                "cac_bound": cac_credentials is not None,
                                "session_id": session_id
                            }
                        )
                    except Exception as storage_error:
                        logger.warning(f"Token storage failed: {storage_error}")
                
                # Log successful authentication
                AuditLogger.instance().log_event(AuditEvent(
                    event_type=AuditEventType.AUTHENTICATION_SUCCESS,
                    timestamp=datetime.now(timezone.utc),
                    user_id=user_id,
                    success=True,
                    additional_data={
                        "method": "OAuth",
                        "platform": platform.value,
                        "cac_bound": cac_credentials is not None,
                        "session_id": session_id
                    }
                ))
                
                logger.info(f"OAuth authentication successful for user: {user_id}")
                return AuthenticationResult.SUCCESS, credentials
                
            except Exception as e:
                logger.error(f"OAuth authentication failed: {e}")
                AuditLogger.instance().log_event(AuditEvent(
                    event_type=AuditEventType.AUTHENTICATION_FAILURE,
                    timestamp=datetime.now(timezone.utc),
                    user_id="unknown",
                    success=False,
                    error_message=str(e),
                    additional_data={
                        "method": "OAuth",
                        "platform": platform.value if platform else None
                    }
                ))
                return AuthenticationResult.FAILED, None
    
    def authenticate_dual_factor(self, pin: str, platform: Platform,
                                authorization_code: str, state: str,
                                required_clearance: str = "UNCLASSIFIED") -> Tuple[AuthenticationResult, Optional[IntegratedCredentials]]:
        """
        Perform dual-factor authentication (CAC + OAuth).
        
        Args:
            pin: CAC PIN
            platform: OAuth platform
            authorization_code: OAuth authorization code
            state: OAuth state parameter
            required_clearance: Minimum required clearance
            
        Returns:
            Tuple of (result, credentials)
        """
        with self._lock:
            try:
                # First, authenticate with CAC
                cac_result, cac_session = self.authenticate_with_cac(
                    pin, platform, required_clearance
                )
                
                if cac_result != AuthenticationResult.SUCCESS:
                    return cac_result, None
                
                # Then, authenticate with OAuth using CAC credentials
                oauth_result, oauth_session = self.authenticate_with_oauth(
                    platform, authorization_code, state, cac_session.cac_credentials
                )
                
                if oauth_result != AuthenticationResult.SUCCESS:
                    # Clean up CAC session on OAuth failure
                    self.invalidate_session(cac_session.session_id)
                    return oauth_result, None
                
                # Update authentication mode for dual factor
                oauth_session.authentication_mode = AuthenticationMode.DUAL_FACTOR
                
                # Clean up the CAC-only session
                self.invalidate_session(cac_session.session_id)
                
                logger.info(f"Dual-factor authentication successful for EDIPI: {oauth_session.effective_user_id}")
                return AuthenticationResult.SUCCESS, oauth_session
                
            except Exception as e:
                logger.error(f"Dual-factor authentication failed: {e}")
                return AuthenticationResult.FAILED, None
    
    def get_oauth_authorization_url(self, platform: Platform, 
                                   cac_credentials: Optional[CACCredentials] = None,
                                   additional_params: Optional[Dict[str, str]] = None) -> Optional[Tuple[str, str]]:
        """
        Get OAuth authorization URL for platform.
        
        Args:
            platform: Target platform
            cac_credentials: Optional CAC credentials for enhanced params
            additional_params: Additional OAuth parameters
            
        Returns:
            Tuple of (authorization_url, state) or None if failed
        """
        try:
            oauth_client = self.oauth_manager.get_client(platform)
            if not oauth_client:
                logger.error(f"OAuth client not configured for platform: {platform.value}")
                return None
            
            # Add CAC-specific parameters if available
            params = additional_params or {}
            if cac_credentials:
                params.update({
                    "cac_bound": "true",
                    "edipi": cac_credentials.edipi or "",
                    "clearance": cac_credentials.clearance_level or "UNCLASSIFIED"
                })
            
            return oauth_client.get_authorization_url(additional_params=params)
            
        except Exception as e:
            logger.error(f"Failed to get authorization URL: {e}")
            return None
    
    def refresh_oauth_token(self, session_id: str) -> bool:
        """
        Refresh OAuth token for session.
        
        Args:
            session_id: Session identifier
            
        Returns:
            True if refresh successful
        """
        with self._lock:
            try:
                credentials = self._sessions.get(session_id)
                if not credentials or not credentials.oauth_token:
                    return False
                
                if not credentials.oauth_token.refresh_token:
                    logger.warning("No refresh token available")
                    return False
                
                # Get OAuth client
                oauth_client = self.oauth_manager.get_client(credentials.platform)
                if not oauth_client:
                    return False
                
                # Refresh token
                new_token = oauth_client.refresh_access_token(
                    credentials.oauth_token.refresh_token
                )
                
                # Update stored token
                credentials.oauth_token = new_token
                credentials.expires_at = min(
                    new_token.expires_at,
                    credentials.authenticated_at + timedelta(seconds=self.session_timeout)
                )
                
                # Update secure storage
                if self.enable_token_storage:
                    self.token_storage.store_token(
                        platform=credentials.platform,
                        user_id=credentials.effective_user_id,
                        token=new_token,
                        metadata={"session_id": session_id}
                    )
                
                logger.info(f"Token refreshed for session: {session_id}")
                return True
                
            except Exception as e:
                logger.error(f"Token refresh failed: {e}")
                return False
    
    def get_session(self, session_id: str) -> Optional[IntegratedCredentials]:
        """
        Get active session by ID.
        
        Args:
            session_id: Session identifier
            
        Returns:
            Session credentials or None if not found/expired
        """
        with self._lock:
            credentials = self._sessions.get(session_id)
            if not credentials:
                return None
            
            # Check if session is expired
            if credentials.is_expired:
                self.invalidate_session(session_id)
                return None
            
            # Check if OAuth token needs refresh
            if (credentials.oauth_token and 
                credentials.oauth_token.is_expired and 
                credentials.oauth_token.refresh_token):
                self.refresh_oauth_token(session_id)
            
            return credentials
    
    def invalidate_session(self, session_id: str) -> bool:
        """
        Invalidate and remove session.
        
        Args:
            session_id: Session identifier
            
        Returns:
            True if session was invalidated
        """
        with self._lock:
            try:
                credentials = self._sessions.pop(session_id, None)
                if not credentials:
                    return False
                
                # Revoke OAuth token if available
                if credentials.oauth_token and credentials.platform:
                    try:
                        oauth_client = self.oauth_manager.get_client(credentials.platform)
                        if oauth_client:
                            oauth_client.revoke_token(credentials.oauth_token.access_token)
                    except Exception as e:
                        logger.warning(f"Token revocation failed: {e}")
                
                # Remove from secure storage
                if self.enable_token_storage and credentials.platform:
                    try:
                        self.token_storage.remove_token(
                            credentials.platform, 
                            credentials.effective_user_id
                        )
                    except Exception as e:
                        logger.warning(f"Token storage removal failed: {e}")
                
                # Log session invalidation
                AuditLogger.instance().log_event(AuditEvent(
                    event_type=AuditEventType.SESSION_TERMINATION,
                    timestamp=datetime.now(timezone.utc),
                    user_id=credentials.effective_user_id,
                    success=True,
                    additional_data={"session_id": session_id}
                ))
                
                logger.info(f"Session invalidated: {session_id}")
                return True
                
            except Exception as e:
                logger.error(f"Session invalidation failed: {e}")
                return False
    
    def list_active_sessions(self, user_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        List active sessions.
        
        Args:
            user_id: Filter by user ID
            
        Returns:
            List of session metadata
        """
        with self._lock:
            sessions = []
            for session_id, credentials in self._sessions.items():
                if user_id and credentials.effective_user_id != user_id:
                    continue
                
                # Skip expired sessions
                if credentials.is_expired:
                    continue
                
                sessions.append({
                    "session_id": session_id,
                    "user_id": credentials.effective_user_id,
                    "platform": credentials.platform.value if credentials.platform else None,
                    "authentication_mode": credentials.authentication_mode.value,
                    "authenticated_at": credentials.authenticated_at.isoformat(),
                    "expires_at": credentials.expires_at.isoformat(),
                    "clearance_level": credentials.clearance_level,
                    "roles": credentials.roles,
                    "cac_authenticated": credentials.is_cac_authenticated,
                    "oauth_authenticated": credentials.is_oauth_authenticated
                })
            
            return sessions
    
    def cleanup_expired_sessions(self) -> int:
        """
        Clean up expired sessions.
        
        Returns:
            Number of sessions cleaned up
        """
        with self._lock:
            expired_sessions = []
            for session_id, credentials in self._sessions.items():
                if credentials.is_expired:
                    expired_sessions.append(session_id)
            
            for session_id in expired_sessions:
                self.invalidate_session(session_id)
            
            logger.info(f"Cleaned up {len(expired_sessions)} expired sessions")
            return len(expired_sessions)
    
    def _generate_session_id(self) -> str:
        """Generate cryptographically secure session ID."""
        return secrets.token_urlsafe(32)
    
    def _check_clearance_level(self, user_clearance: str, required_clearance: str) -> bool:
        """Check if user clearance meets requirement."""
        clearance_levels = {
            "UNCLASSIFIED": 0,
            "CONFIDENTIAL": 1,
            "SECRET": 2,
            "TOP_SECRET": 3
        }
        
        user_level = clearance_levels.get(user_clearance.upper(), 0)
        required_level = clearance_levels.get(required_clearance.upper(), 0)
        
        return user_level >= required_level
    
    def _determine_cac_roles(self, cac_credentials: CACCredentials, 
                           platform: Optional[Platform]) -> List[str]:
        """Determine user roles from CAC credentials."""
        roles = ["authenticated_user", "cac_user"]
        
        # Add clearance-based roles
        if cac_credentials.clearance_level:
            roles.append(f"clearance_{cac_credentials.clearance_level.lower()}")
        
        # Add organization-based roles
        if cac_credentials.organization:
            org_clean = cac_credentials.organization.replace(" ", "_").lower()
            roles.append(f"org_{org_clean}")
        
        # Add platform-specific roles
        if platform:
            roles.append(f"platform_{platform.value}")
        
        return roles
    
    def _determine_oauth_roles(self, user_info: Dict[str, Any], 
                             platform: Platform,
                             cac_credentials: Optional[CACCredentials]) -> List[str]:
        """Determine user roles from OAuth user info."""
        roles = ["authenticated_user", "oauth_user"]
        
        # Add platform-specific roles
        roles.append(f"platform_{platform.value}")
        
        # Add OAuth-specific roles from user info
        oauth_roles = user_info.get("roles", [])
        if isinstance(oauth_roles, list):
            roles.extend(oauth_roles)
        
        # Add CAC-derived roles if available
        if cac_credentials:
            roles.extend(self._determine_cac_roles(cac_credentials, platform))
        
        return list(set(roles))  # Remove duplicates


class IntegratedAuthenticationManager:
    """
    High-level integrated authentication manager.
    
    Provides simplified interface for OAuth-CAC authentication workflows.
    """
    
    def __init__(self, environment: Environment = Environment.NIPR):
        """Initialize integrated authentication manager."""
        self.bridge = OAuthCACBridge(environment=environment)
        self.environment = environment
    
    def configure_all_platforms_from_env(self) -> Dict[Platform, bool]:
        """Configure all platforms from environment variables."""
        configurator = DoD_OAuth_Configurator(self.environment)
        results = {}
        
        for platform in Platform:
            try:
                config = configurator.create_config_from_env(platform)
                success = self.bridge.configure_platform(
                    platform=platform,
                    client_id=config.client_id,
                    client_secret=config.client_secret,
                    redirect_uri=config.redirect_uri,
                    scopes=config.scopes
                )
                results[platform] = success
            except Exception as e:
                logger.warning(f"Failed to configure {platform.value}: {e}")
                results[platform] = False
        
        return results
    
    def start_cac_oauth_flow(self, pin: str, platform: Platform,
                           required_clearance: str = "UNCLASSIFIED") -> Tuple[AuthenticationResult, Optional[str], Optional[str]]:
        """
        Start CAC-then-OAuth authentication flow.
        
        Args:
            pin: CAC PIN
            platform: Target platform
            required_clearance: Minimum clearance required
            
        Returns:
            Tuple of (result, oauth_url, state)
        """
        # First authenticate with CAC
        result, credentials = self.bridge.authenticate_with_cac(
            pin, platform, required_clearance
        )
        
        if result != AuthenticationResult.SUCCESS:
            return result, None, None
        
        # Get OAuth authorization URL with CAC binding
        auth_url_result = self.bridge.get_oauth_authorization_url(
            platform, credentials.cac_credentials
        )
        
        if not auth_url_result:
            return AuthenticationResult.FAILED, None, None
        
        oauth_url, state = auth_url_result
        return AuthenticationResult.SUCCESS, oauth_url, state
    
    def complete_oauth_flow(self, platform: Platform, 
                          authorization_code: str, state: str,
                          session_id: Optional[str] = None) -> Tuple[AuthenticationResult, Optional[IntegratedCredentials]]:
        """
        Complete OAuth authentication flow.
        
        Args:
            platform: OAuth platform
            authorization_code: Authorization code from callback
            state: State parameter
            session_id: Optional existing CAC session ID
            
        Returns:
            Tuple of (result, credentials)
        """
        cac_credentials = None
        
        # If session ID provided, get CAC credentials
        if session_id:
            session = self.bridge.get_session(session_id)
            if session and session.cac_credentials:
                cac_credentials = session.cac_credentials
        
        return self.bridge.authenticate_with_oauth(
            platform, authorization_code, state, cac_credentials
        )
    
    def get_user_session(self, session_id: str) -> Optional[IntegratedCredentials]:
        """Get user session by ID."""
        return self.bridge.get_session(session_id)
    
    def logout_user(self, session_id: str) -> bool:
        """Logout user and invalidate session."""
        return self.bridge.invalidate_session(session_id)