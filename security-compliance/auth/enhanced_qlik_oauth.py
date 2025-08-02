"""
Enhanced Qlik OAuth 2.0 Integration
Completes the missing 15% for production-ready Qlik platform OAuth implementation.
"""

import json
import logging
import secrets
import time
from typing import Dict, List, Optional, Any, Tuple, Union
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from urllib.parse import urlencode, urlparse, parse_qs
import threading

import requests
import jwt
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa

# Import base OAuth components
from .oauth_client import DoD_OAuth_Client, TokenResponse, Platform, OAuthConfig
from .oauth_config import DoD_OAuth_Configurator, Environment

# Import CAC integration
from .cac_piv_integration import CACCredentials
from .oauth_cac_bridge import IntegratedCredentials

# Import platform adapter
from .platform_adapters.qlik_adapter import QlikAuthAdapter

# Import security components
from .security_managers import AuditLogger, AuditEvent, AuditEventType
from .secure_token_storage import TokenStorageManager

logger = logging.getLogger(__name__)


class QlikResourceType(Enum):
    """Qlik resource types for permission mapping."""
    APP = "app"
    SHEET = "sheet"
    STORY = "story"
    STREAM = "stream"
    SPACE = "space"
    DATA_CONNECTION = "dataconnection"
    EXTENSION = "extension"
    THEME = "theme"
    CUSTOM_PROPERTY = "customproperty"
    TAG = "tag"


class QlikPermissionLevel(Enum):
    """Qlik permission levels."""
    READ = "read"
    UPDATE = "update"
    CREATE = "create"
    DELETE = "delete"
    PUBLISH = "publish"
    ADMIN = "admin"
    OWNER = "owner"


@dataclass
class QlikScope:
    """Enhanced Qlik OAuth scope with resource mapping."""
    name: str
    description: str
    resource_types: List[QlikResourceType]
    permission_levels: List[QlikPermissionLevel]
    requires_clearance: Optional[str] = None
    requires_roles: List[str] = field(default_factory=list)
    
    @property
    def oauth_scope_name(self) -> str:
        """Get OAuth 2.0 scope name."""
        return f"qlik:{self.name}"


class QlikOAuth2Config:
    """Enhanced Qlik OAuth 2.0 configuration with platform-specific settings."""
    
    # Qlik-specific OAuth scopes with enhanced mapping
    QLIK_SCOPES = {
        "basic_read": QlikScope(
            name="basic_read",
            description="Basic read access to Qlik apps and content",
            resource_types=[QlikResourceType.APP, QlikResourceType.SHEET],
            permission_levels=[QlikPermissionLevel.READ],
            requires_clearance="UNCLASSIFIED"
        ),
        "app_create": QlikScope(
            name="app_create",
            description="Create and manage Qlik applications",
            resource_types=[QlikResourceType.APP],
            permission_levels=[QlikPermissionLevel.CREATE, QlikPermissionLevel.UPDATE, QlikPermissionLevel.DELETE],
            requires_clearance="CONFIDENTIAL",
            requires_roles=["qlik_developer"]
        ),
        "space_manage": QlikScope(
            name="space_manage",
            description="Manage Qlik Sense spaces",
            resource_types=[QlikResourceType.SPACE],
            permission_levels=[QlikPermissionLevel.CREATE, QlikPermissionLevel.UPDATE, QlikPermissionLevel.DELETE, QlikPermissionLevel.ADMIN],
            requires_clearance="SECRET",
            requires_roles=["qlik_admin", "space_manager"]
        ),
        "stream_publish": QlikScope(
            name="stream_publish",
            description="Publish content to Qlik streams",
            resource_types=[QlikResourceType.STREAM, QlikResourceType.APP],
            permission_levels=[QlikPermissionLevel.PUBLISH],
            requires_clearance="CONFIDENTIAL",
            requires_roles=["qlik_publisher"]
        ),
        "admin_full": QlikScope(
            name="admin_full",
            description="Full administrative access to Qlik platform",
            resource_types=list(QlikResourceType),
            permission_levels=list(QlikPermissionLevel),
            requires_clearance="TOP_SECRET",
            requires_roles=["qlik_admin", "platform_admin"]
        ),
        "data_connection": QlikScope(
            name="data_connection",
            description="Manage data connections",
            resource_types=[QlikResourceType.DATA_CONNECTION],
            permission_levels=[QlikPermissionLevel.CREATE, QlikPermissionLevel.UPDATE, QlikPermissionLevel.DELETE],
            requires_clearance="SECRET",
            requires_roles=["data_admin"]
        )
    }
    
    # Qlik platform-specific endpoints
    QLIK_ENDPOINTS = {
        "authorization": "/oauth/authorize",
        "token": "/oauth/token",
        "introspect": "/oauth/introspect",
        "userinfo": "/oauth/userinfo",
        "jwks": "/.well-known/jwks.json",
        "revoke": "/oauth/revoke",
        "device_auth": "/oauth/device/code",
        "apps": "/api/v1/apps",
        "spaces": "/api/v1/spaces",
        "users": "/api/v1/users",
        "permissions": "/api/v1/permissions",
        "audit": "/api/v1/audit"
    }
    
    @classmethod
    def get_scope_for_clearance(cls, clearance_level: str) -> List[str]:
        """Get available scopes for a clearance level."""
        clearance_hierarchy = {
            "UNCLASSIFIED": 0,
            "CONFIDENTIAL": 1,
            "SECRET": 2,
            "TOP_SECRET": 3
        }
        
        user_level = clearance_hierarchy.get(clearance_level.upper(), 0)
        available_scopes = []
        
        for scope_name, scope in cls.QLIK_SCOPES.items():
            if scope.requires_clearance:
                required_level = clearance_hierarchy.get(scope.requires_clearance.upper(), 0)
                if user_level >= required_level:
                    available_scopes.append(scope.oauth_scope_name)
            else:
                available_scopes.append(scope.oauth_scope_name)
        
        return available_scopes
    
    @classmethod
    def get_scope_for_roles(cls, user_roles: List[str]) -> List[str]:
        """Get available scopes for user roles."""
        available_scopes = []
        
        for scope_name, scope in cls.QLIK_SCOPES.items():
            if not scope.requires_roles or any(role in user_roles for role in scope.requires_roles):
                available_scopes.append(scope.oauth_scope_name)
        
        return available_scopes


class EnhancedQlikOAuthClient(DoD_OAuth_Client):
    """Enhanced Qlik OAuth 2.0 client with platform-specific features."""
    
    def __init__(self, config: OAuthConfig, qlik_adapter: Optional[QlikAuthAdapter] = None):
        """
        Initialize enhanced Qlik OAuth client.
        
        Args:
            config: OAuth configuration
            qlik_adapter: Optional Qlik platform adapter for CAC integration
        """
        super().__init__(config)
        self.qlik_adapter = qlik_adapter
        self.introspection_cache: Dict[str, Tuple[Dict, datetime]] = {}
        self.cache_duration = timedelta(minutes=5)
        self._lock = threading.RLock()
        
        # Qlik-specific configuration
        self.qlik_tenant_id = self._extract_tenant_id_from_url(config.authorization_url)
        self.api_base_url = self._build_api_base_url(config.authorization_url)
        
        logger.info(f"Enhanced Qlik OAuth client initialized for tenant: {self.qlik_tenant_id}")
    
    def _extract_tenant_id_from_url(self, url: str) -> Optional[str]:
        """Extract Qlik tenant ID from OAuth URL."""
        try:
            parsed = urlparse(url)
            # Qlik cloud URLs typically include tenant ID
            if "qlikcloud.com" in parsed.netloc:
                parts = parsed.netloc.split('.')
                if len(parts) > 1:
                    return parts[0]
            return None
        except Exception:
            return None
    
    def _build_api_base_url(self, oauth_url: str) -> str:
        """Build API base URL from OAuth URL."""
        parsed = urlparse(oauth_url)
        return f"{parsed.scheme}://{parsed.netloc}"
    
    def introspect_token(self, token: str, token_type_hint: str = "access_token") -> Optional[Dict[str, Any]]:
        """
        Introspect OAuth token with Qlik's introspection endpoint.
        
        Args:
            token: Token to introspect
            token_type_hint: Type hint for token
            
        Returns:
            Token introspection result or None if failed
        """
        with self._lock:
            # Check cache first
            cache_key = f"{token}:{token_type_hint}"
            if cache_key in self.introspection_cache:
                cached_result, cached_time = self.introspection_cache[cache_key]
                if datetime.now(timezone.utc) - cached_time < self.cache_duration:
                    return cached_result
            
            try:
                introspect_url = f"{self.api_base_url}{QlikOAuth2Config.QLIK_ENDPOINTS['introspect']}"
                
                data = {
                    'token': token,
                    'token_type_hint': token_type_hint
                }
                
                auth = (self.config.client_id, self.config.client_secret)
                
                response = self.session.post(
                    introspect_url,
                    data=data,
                    auth=auth,
                    timeout=30
                )
                
                if response.ok:
                    result = response.json()
                    # Cache successful introspection
                    self.introspection_cache[cache_key] = (result, datetime.now(timezone.utc))
                    
                    logger.debug(f"Token introspection successful: active={result.get('active', False)}")
                    return result
                else:
                    logger.warning(f"Token introspection failed: {response.status_code}")
                    return None
                    
            except Exception as e:
                logger.error(f"Token introspection error: {e}")
                return None
    
    def get_qlik_user_permissions(self, access_token: str, user_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Get user permissions from Qlik platform.
        
        Args:
            access_token: Valid access token
            user_id: Optional specific user ID
            
        Returns:
            List of user permissions
        """
        try:
            permissions_url = f"{self.api_base_url}{QlikOAuth2Config.QLIK_ENDPOINTS['permissions']}"
            
            headers = {
                'Authorization': f'Bearer {access_token}',
                'Accept': 'application/json'
            }
            
            params = {}
            if user_id:
                params['userId'] = user_id
            
            response = self.session.get(
                permissions_url,
                headers=headers,
                params=params,
                timeout=30
            )
            
            if response.ok:
                permissions_data = response.json()
                return permissions_data.get('data', [])
            else:
                logger.warning(f"Failed to get user permissions: {response.status_code}")
                return []
                
        except Exception as e:
            logger.error(f"Error getting user permissions: {e}")
            return []
    
    def validate_token_with_cac(self, access_token: str, cac_credentials: CACCredentials) -> bool:
        """
        Validate OAuth token against CAC credentials.
        
        Args:
            access_token: OAuth access token
            cac_credentials: CAC credentials for validation
            
        Returns:
            True if token is valid and bound to CAC
        """
        try:
            # Introspect token
            introspection = self.introspect_token(access_token)
            if not introspection or not introspection.get('active', False):
                return False
            
            # Check if token includes CAC binding claims
            cac_bound = introspection.get('cac_bound', False)
            if not cac_bound:
                logger.warning("Token is not CAC-bound")
                return False
            
            # Validate EDIPI matches
            token_edipi = introspection.get('edipi')
            if token_edipi and token_edipi != cac_credentials.edipi:
                logger.warning(f"EDIPI mismatch: token={token_edipi}, cac={cac_credentials.edipi}")
                return False
            
            # Validate clearance level
            token_clearance = introspection.get('clearance_level')
            if token_clearance and token_clearance != cac_credentials.clearance_level:
                logger.warning(f"Clearance mismatch: token={token_clearance}, cac={cac_credentials.clearance_level}")
                return False
            
            return True
            
        except Exception as e:
            logger.error(f"CAC token validation error: {e}")
            return False
    
    def get_qlik_apps_for_user(self, access_token: str, user_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Get Qlik apps accessible to user.
        
        Args:
            access_token: Valid access token
            user_id: Optional user ID
            
        Returns:
            List of accessible apps
        """
        try:
            apps_url = f"{self.api_base_url}{QlikOAuth2Config.QLIK_ENDPOINTS['apps']}"
            
            headers = {
                'Authorization': f'Bearer {access_token}',
                'Accept': 'application/json'
            }
            
            params = {}
            if user_id:
                params['ownerId'] = user_id
            
            response = self.session.get(
                apps_url,
                headers=headers,
                params=params,
                timeout=30
            )
            
            if response.ok:
                apps_data = response.json()
                return apps_data.get('data', [])
            else:
                logger.warning(f"Failed to get user apps: {response.status_code}")
                return []
                
        except Exception as e:
            logger.error(f"Error getting user apps: {e}")
            return []
    
    def create_qlik_session_with_oauth(self, access_token: str, app_id: Optional[str] = None) -> Optional[str]:
        """
        Create Qlik session URL using OAuth token.
        
        Args:
            access_token: Valid OAuth access token
            app_id: Optional specific app ID
            
        Returns:
            Qlik session URL or None if failed
        """
        try:
            # Get user info to build session context
            user_info = self.get_user_info(access_token)
            if not user_info:
                return None
            
            # Build Qlik session URL
            base_url = self.api_base_url
            
            if app_id:
                session_url = f"{base_url}/sense/app/{app_id}"
            else:
                session_url = f"{base_url}/hub"
            
            # Add OAuth token as query parameter
            session_url += f"?access_token={access_token}"
            
            return session_url
            
        except Exception as e:
            logger.error(f"Error creating Qlik session: {e}")
            return None
    
    def refresh_token_with_enhanced_validation(self, refresh_token: str, 
                                             cac_credentials: Optional[CACCredentials] = None) -> Optional[TokenResponse]:
        """
        Refresh OAuth token with enhanced validation.
        
        Args:
            refresh_token: Refresh token
            cac_credentials: Optional CAC credentials for validation
            
        Returns:
            New token response or None if failed
        """
        try:
            # Standard token refresh
            new_token = self.refresh_access_token(refresh_token)
            
            # If CAC credentials provided, validate binding
            if cac_credentials and new_token:
                if not self.validate_token_with_cac(new_token.access_token, cac_credentials):
                    logger.error("Refreshed token failed CAC validation")
                    return None
            
            return new_token
            
        except Exception as e:
            logger.error(f"Enhanced token refresh failed: {e}")
            return None


class QlikOAuthSessionManager:
    """Enhanced Qlik OAuth session manager with CAC integration."""
    
    def __init__(self, oauth_client: EnhancedQlikOAuthClient, 
                 token_storage: Optional[TokenStorageManager] = None):
        """
        Initialize Qlik OAuth session manager.
        
        Args:
            oauth_client: Enhanced Qlik OAuth client
            token_storage: Optional token storage manager
        """
        self.oauth_client = oauth_client
        self.token_storage = token_storage or TokenStorageManager.instance()
        self.active_sessions: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.RLock()
        
        logger.info("Qlik OAuth session manager initialized")
    
    def create_cac_bound_session(self, authorization_code: str, state: str,
                               cac_credentials: CACCredentials) -> Optional[Dict[str, Any]]:
        """
        Create OAuth session bound to CAC credentials.
        
        Args:
            authorization_code: OAuth authorization code
            state: OAuth state parameter
            cac_credentials: CAC credentials for binding
            
        Returns:
            Session information or None if failed
        """
        with self._lock:
            try:
                # Exchange code for token
                token = self.oauth_client.exchange_code_for_token(authorization_code, state)
                if not token:
                    return None
                
                # Validate token with CAC
                if not self.oauth_client.validate_token_with_cac(token.access_token, cac_credentials):
                    logger.error("Token validation with CAC failed")
                    return None
                
                # Create session
                session_id = secrets.token_urlsafe(32)
                session_data = {
                    "session_id": session_id,
                    "user_id": cac_credentials.edipi,
                    "oauth_token": token,
                    "cac_credentials": cac_credentials,
                    "created_at": datetime.now(timezone.utc),
                    "expires_at": token.expires_at,
                    "clearance_level": cac_credentials.clearance_level,
                    "last_activity": datetime.now(timezone.utc)
                }
                
                # Store session
                self.active_sessions[session_id] = session_data
                
                # Store token securely
                if self.token_storage:
                    self.token_storage.store_token(
                        platform=Platform.QLIK,
                        user_id=cac_credentials.edipi,
                        token=token,
                        metadata={
                            "cac_bound": True,
                            "session_id": session_id,
                            "clearance_level": cac_credentials.clearance_level
                        }
                    )
                
                # Log session creation
                AuditLogger.instance().log_event(AuditEvent(
                    event_type=AuditEventType.SESSION_CREATION,
                    timestamp=datetime.now(timezone.utc),
                    user_id=cac_credentials.edipi,
                    success=True,
                    additional_data={
                        "platform": "qlik",
                        "session_id": session_id,
                        "cac_bound": True,
                        "clearance_level": cac_credentials.clearance_level
                    }
                ))
                
                logger.info(f"CAC-bound OAuth session created: {session_id}")
                return session_data
                
            except Exception as e:
                logger.error(f"Failed to create CAC-bound session: {e}")
                return None
    
    def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """
        Get active session by ID.
        
        Args:
            session_id: Session identifier
            
        Returns:
            Session data or None if not found/expired
        """
        with self._lock:
            session = self.active_sessions.get(session_id)
            if not session:
                return None
            
            # Check if session is expired
            if datetime.now(timezone.utc) >= session["expires_at"]:
                self.invalidate_session(session_id)
                return None
            
            # Update last activity
            session["last_activity"] = datetime.now(timezone.utc)
            
            # Check if token needs refresh
            token = session.get("oauth_token")
            if token and token.is_expired and token.refresh_token:
                cac_credentials = session.get("cac_credentials")
                new_token = self.oauth_client.refresh_token_with_enhanced_validation(
                    token.refresh_token, cac_credentials
                )
                if new_token:
                    session["oauth_token"] = new_token
                    session["expires_at"] = new_token.expires_at
                else:
                    self.invalidate_session(session_id)
                    return None
            
            return session
    
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
                session = self.active_sessions.pop(session_id, None)
                if not session:
                    return False
                
                # Revoke OAuth token
                token = session.get("oauth_token")
                if token:
                    try:
                        self.oauth_client.revoke_token(token.access_token)
                    except Exception as e:
                        logger.warning(f"Token revocation failed: {e}")
                
                # Remove from token storage
                if self.token_storage:
                    try:
                        self.token_storage.remove_token(
                            Platform.QLIK, 
                            session["user_id"]
                        )
                    except Exception as e:
                        logger.warning(f"Token storage removal failed: {e}")
                
                # Log session termination
                AuditLogger.instance().log_event(AuditEvent(
                    event_type=AuditEventType.SESSION_TERMINATION,
                    timestamp=datetime.now(timezone.utc),
                    user_id=session["user_id"],
                    success=True,
                    additional_data={
                        "platform": "qlik",
                        "session_id": session_id
                    }
                ))
                
                logger.info(f"Session invalidated: {session_id}")
                return True
                
            except Exception as e:
                logger.error(f"Session invalidation failed: {e}")
                return False
    
    def cleanup_expired_sessions(self) -> int:
        """
        Clean up expired sessions.
        
        Returns:
            Number of sessions cleaned up
        """
        with self._lock:
            expired_sessions = []
            current_time = datetime.now(timezone.utc)
            
            for session_id, session in self.active_sessions.items():
                if current_time >= session["expires_at"]:
                    expired_sessions.append(session_id)
            
            for session_id in expired_sessions:
                self.invalidate_session(session_id)
            
            logger.info(f"Cleaned up {len(expired_sessions)} expired sessions")
            return len(expired_sessions)
    
    def get_user_sessions(self, user_id: str) -> List[Dict[str, Any]]:
        """
        Get all active sessions for a user.
        
        Args:
            user_id: User identifier
            
        Returns:
            List of active sessions
        """
        with self._lock:
            user_sessions = []
            for session_id, session in self.active_sessions.items():
                if session["user_id"] == user_id:
                    # Check if session is still valid
                    if datetime.now(timezone.utc) < session["expires_at"]:
                        user_sessions.append({
                            "session_id": session_id,
                            "created_at": session["created_at"].isoformat(),
                            "expires_at": session["expires_at"].isoformat(),
                            "last_activity": session["last_activity"].isoformat(),
                            "clearance_level": session.get("clearance_level", "UNCLASSIFIED"),
                            "cac_bound": session.get("cac_credentials") is not None
                        })
            
            return user_sessions