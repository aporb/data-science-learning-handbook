#!/usr/bin/env python3
"""
OAuth 2.0 RBAC Integration Bridge

This module provides the integration layer between OAuth 2.0 authentication
(for Qlik and Databricks platforms) and the RBAC system, implementing DoD-compliant
role mapping and session management.

Key Features:
- Multi-platform OAuth 2.0 support (Qlik, Databricks)
- Token validation and introspection
- Role mapping from OAuth scopes to RBAC roles
- Session management with token refresh
- Comprehensive audit logging
- DoD security compliance (STIG, NIST 800-53)
- CAC/PIV token binding support

Classification: UNCLASSIFIED//CUI
"""

import os
import json
import logging
import hashlib
import secrets
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Tuple, Set, Union
from uuid import UUID, uuid4
from dataclasses import dataclass, asdict
from enum import Enum
import threading
from pathlib import Path
import jwt
import requests
from urllib.parse import urljoin

# Import OAuth components
try:
    from ...auth.complete_qlik_oauth_integration import CompleteQlikOAuthIntegration, QlikSessionContext
    from ...auth.complete_databricks_oauth_integration import CompleteDatabricksOAuthIntegration, DatabricksSessionContext
    from ...auth.oauth_client import Platform, OAuthConfig, TokenResponse
    from ...auth.enhanced_cac_oauth_binding import EnhancedCACOAuthBinder, TokenBindingStrength
    from ...auth.security_managers import AuditLogger, AuditEvent, AuditEventType
except ImportError:
    # Fallback imports for development
    from security_compliance.auth.complete_qlik_oauth_integration import CompleteQlikOAuthIntegration, QlikSessionContext
    from security_compliance.auth.complete_databricks_oauth_integration import CompleteDatabricksOAuthIntegration, DatabricksSessionContext
    from security_compliance.auth.oauth_client import Platform, OAuthConfig, TokenResponse
    from security_compliance.auth.enhanced_cac_oauth_binding import EnhancedCACOAuthBinder, TokenBindingStrength
    from security_compliance.auth.security_managers import AuditLogger, AuditEvent, AuditEventType

# Import RBAC components
try:
    from ..models.user import User
    from ..models.role import Role
    from ..models.permission import Permission
    from ..models.authentication import AuthenticationStatus
    from ..models.audit import AuditLog, AuditSeverity
    from ..db_utils import DatabaseConnection
except ImportError:
    # Fallback imports for development
    from security_compliance.rbac.models.user import User
    from security_compliance.rbac.models.role import Role
    from security_compliance.rbac.models.permission import Permission
    from security_compliance.rbac.models.authentication import AuthenticationStatus
    from security_compliance.rbac.models.audit import AuditLog, AuditSeverity
    from security_compliance.rbac.db_utils import DatabaseConnection

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class OAuthValidationError(Exception):
    """OAuth validation error"""
    pass


class OAuthMappingError(Exception):
    """OAuth role mapping error"""
    pass


class SupportedPlatform(Enum):
    """Supported OAuth platforms"""
    QLIK = "qlik"
    DATABRICKS = "databricks"


class OAuthSessionStatus(Enum):
    """OAuth session status enumeration"""
    ACTIVE = "ACTIVE"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"
    TERMINATED = "TERMINATED"
    TOKEN_EXPIRED = "TOKEN_EXPIRED"
    REFRESH_REQUIRED = "REFRESH_REQUIRED"


@dataclass
class OAuthUserProfile:
    """OAuth user profile with RBAC mappings"""
    user_id: str
    platform: SupportedPlatform
    oauth_sub: str  # OAuth subject identifier
    email: Optional[str]
    name: Optional[str]
    organization: Optional[str]
    department: Optional[str]
    clearance_level: Optional[str]
    edipi: Optional[str]
    oauth_scopes: List[str]
    oauth_roles: List[str]
    rbac_roles: List[str]
    permissions: List[str]
    platform_permissions: List[str]
    workspace_access: Dict[str, Any]  # Platform-specific workspace access
    created_at: datetime
    last_authenticated: datetime
    cac_bound: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        result = asdict(self)
        result['platform'] = self.platform.value
        result['created_at'] = self.created_at.isoformat()
        result['last_authenticated'] = self.last_authenticated.isoformat()
        return result


@dataclass
class OAuthSession:
    """OAuth authentication session"""
    session_id: str
    platform: SupportedPlatform
    user_profile: OAuthUserProfile
    oauth_token: TokenResponse
    status: OAuthSessionStatus
    created_at: datetime
    expires_at: datetime
    last_activity: datetime
    last_token_refresh: Optional[datetime]
    token_expires_at: datetime
    refresh_token_expires_at: Optional[datetime]
    ip_address: Optional[str]
    user_agent: Optional[str]
    cac_binding: Optional[Dict[str, Any]]
    platform_session_data: Dict[str, Any]
    metadata: Dict[str, Any]


class PlatformTokenValidator:
    """
    Validates OAuth tokens for different platforms.
    """
    
    def __init__(self, platform_configs: Dict[SupportedPlatform, Dict[str, Any]]):
        """
        Initialize token validator.
        
        Args:
            platform_configs: Platform-specific configurations
        """
        self.platform_configs = platform_configs
        self.jwks_cache: Dict[str, Dict[str, Any]] = {}
        self.cache_lock = threading.RLock()
        
    def validate_token(self, platform: SupportedPlatform, token: str) -> Tuple[bool, Dict[str, Any], str]:
        """
        Validate OAuth token for platform.
        
        Args:
            platform: Platform type
            token: OAuth access token
            
        Returns:
            Tuple of (valid, claims, message)
        """
        try:
            config = self.platform_configs.get(platform)
            if not config:
                return False, {}, f"Platform {platform.value} not configured"
            
            # Decode JWT without verification first to get header info
            unverified_header = jwt.get_unverified_header(token)
            unverified_payload = jwt.decode(token, options={"verify_signature": False})
            
            # Get issuer from token
            issuer = unverified_payload.get('iss')
            if not issuer:
                return False, {}, "Token missing issuer claim"
            
            # Get JWKS for issuer
            jwks_uri = config.get('jwks_uri')
            if not jwks_uri:
                return False, {}, "JWKS URI not configured"
            
            public_key = self._get_public_key(jwks_uri, unverified_header.get('kid'))
            if not public_key:
                return False, {}, "Unable to retrieve public key"
            
            # Verify token
            claims = jwt.decode(
                token,
                public_key,
                algorithms=[unverified_header.get('alg', 'RS256')],
                audience=config.get('audience'),
                issuer=issuer
            )
            
            # Additional validations
            now = datetime.now(timezone.utc).timestamp()
            
            if claims.get('exp', 0) < now:
                return False, {}, "Token expired"
            
            if claims.get('nbf', 0) > now:
                return False, {}, "Token not yet valid"
            
            return True, claims, "Token valid"
            
        except jwt.ExpiredSignatureError:
            return False, {}, "Token expired"
        except jwt.InvalidTokenError as e:
            return False, {}, f"Invalid token: {e}"
        except Exception as e:
            logger.error(f"Token validation error: {e}")
            return False, {}, f"Validation error: {e}"
    
    def introspect_token(self, platform: SupportedPlatform, token: str) -> Tuple[bool, Dict[str, Any], str]:
        """
        Introspect OAuth token using platform's introspection endpoint.
        
        Args:
            platform: Platform type
            token: OAuth access token
            
        Returns:
            Tuple of (active, token_info, message)
        """
        try:
            config = self.platform_configs.get(platform)
            if not config:
                return False, {}, f"Platform {platform.value} not configured"
            
            introspect_url = config.get('introspect_url')
            if not introspect_url:
                return False, {}, "Introspection endpoint not configured"
            
            # Prepare introspection request
            data = {
                'token': token,
                'token_type_hint': 'access_token'
            }
            
            headers = {
                'Content-Type': 'application/x-www-form-urlencoded',
                'Accept': 'application/json'
            }
            
            # Add client authentication
            client_id = config.get('client_id')
            client_secret = config.get('client_secret')
            
            if client_id and client_secret:
                import base64
                credentials = base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()
                headers['Authorization'] = f"Basic {credentials}"
            
            # Make introspection request
            response = requests.post(
                introspect_url,
                data=data,
                headers=headers,
                timeout=10,
                verify=True
            )
            
            if response.status_code != 200:
                return False, {}, f"Introspection failed: {response.status_code}"
            
            token_info = response.json()
            active = token_info.get('active', False)
            
            if not active:
                return False, token_info, "Token not active"
            
            return True, token_info, "Token active"
            
        except Exception as e:
            logger.error(f"Token introspection error: {e}")
            return False, {}, f"Introspection error: {e}"
    
    def _get_public_key(self, jwks_uri: str, kid: str) -> Optional[str]:
        """Get public key from JWKS"""
        try:
            with self.cache_lock:
                # Check cache first
                if jwks_uri in self.jwks_cache:
                    jwks = self.jwks_cache[jwks_uri]
                    if datetime.now(timezone.utc) < jwks.get('expires_at', datetime.min.replace(tzinfo=timezone.utc)):
                        for key in jwks.get('keys', []):
                            if key.get('kid') == kid:
                                return key.get('public_key')
                
                # Fetch JWKS
                response = requests.get(jwks_uri, timeout=10, verify=True)
                if response.status_code != 200:
                    return None
                
                jwks_data = response.json()
                
                # Cache JWKS
                expires_at = datetime.now(timezone.utc) + timedelta(hours=1)
                cached_jwks = {
                    'keys': [],
                    'expires_at': expires_at
                }
                
                # Process keys
                from cryptography.hazmat.primitives import serialization
                from cryptography.hazmat.primitives.asymmetric import rsa
                
                for key_data in jwks_data.get('keys', []):
                    if key_data.get('kty') == 'RSA':
                        try:
                            # Convert JWK to PEM
                            import base64
                            n = base64.urlsafe_b64decode(key_data['n'] + '==')
                            e = base64.urlsafe_b64decode(key_data['e'] + '==')
                            
                            public_key = rsa.RSAPublicNumbers(
                                int.from_bytes(e, 'big'),
                                int.from_bytes(n, 'big')
                            ).public_key()
                            
                            pem = public_key.public_bytes(
                                encoding=serialization.Encoding.PEM,
                                format=serialization.PublicFormat.SubjectPublicKeyInfo
                            ).decode()
                            
                            cached_jwks['keys'].append({
                                'kid': key_data.get('kid'),
                                'public_key': pem
                            })
                            
                        except Exception as e:
                            logger.warning(f"Failed to process JWK key: {e}")
                            continue
                
                self.jwks_cache[jwks_uri] = cached_jwks
                
                # Find requested key
                for key in cached_jwks['keys']:
                    if key.get('kid') == kid:
                        return key.get('public_key')
                
                return None
                
        except Exception as e:
            logger.error(f"Failed to get public key: {e}")
            return None


class OAuthRoleMapper:
    """
    Maps OAuth scopes and roles to RBAC roles using platform configurations.
    """
    
    def __init__(self, platform_configs: Dict[SupportedPlatform, Dict[str, Any]]):
        """
        Initialize OAuth role mapper.
        
        Args:
            platform_configs: Platform-specific configurations
        """
        self.platform_configs = platform_configs
        self.audit_logger = AuditLogger()
    
    def map_oauth_to_rbac(self, platform: SupportedPlatform, oauth_claims: Dict[str, Any],
                         token_info: Dict[str, Any] = None) -> OAuthUserProfile:
        """
        Map OAuth claims to RBAC user profile.
        
        Args:
            platform: Platform type
            oauth_claims: OAuth token claims
            token_info: Additional token information from introspection
            
        Returns:
            OAuth user profile with RBAC mappings
        """
        try:
            config = self.platform_configs.get(platform)
            if not config:
                raise OAuthMappingError(f"Platform {platform.value} not configured")
            
            rbac_config = config.get('rbac_integration', {})
            attribute_mapping = rbac_config.get('attribute_mapping', {})
            
            # Extract user attributes
            user_id = str(uuid4())
            now = datetime.now(timezone.utc)
            
            profile = OAuthUserProfile(
                user_id=user_id,
                platform=platform,
                oauth_sub=oauth_claims.get(attribute_mapping.get('user_id', 'sub'), ''),
                email=oauth_claims.get(attribute_mapping.get('email', 'email')),
                name=oauth_claims.get(attribute_mapping.get('name', 'name')),
                organization=oauth_claims.get(attribute_mapping.get('organization', 'org')),
                department=oauth_claims.get(attribute_mapping.get('department', 'dept')),
                clearance_level=oauth_claims.get(attribute_mapping.get('clearance_level', 'clearance')),
                edipi=oauth_claims.get(attribute_mapping.get('edipi', 'edipi')),
                oauth_scopes=[],
                oauth_roles=[],
                rbac_roles=[],
                permissions=[],
                platform_permissions=[],
                workspace_access={},
                created_at=now,
                last_authenticated=now
            )
            
            # Extract OAuth scopes
            scopes = oauth_claims.get('scope', '')
            if isinstance(scopes, str):
                profile.oauth_scopes = scopes.split()
            elif isinstance(scopes, list):
                profile.oauth_scopes = scopes
            
            # Extract OAuth roles
            role_claim = rbac_config.get('role_claim', f'{platform.value}_roles')
            oauth_roles = oauth_claims.get(role_claim, [])
            if isinstance(oauth_roles, str):
                profile.oauth_roles = [oauth_roles]
            elif isinstance(oauth_roles, list):
                profile.oauth_roles = oauth_roles
            
            # Map scopes to RBAC roles
            self._map_scopes_to_roles(profile, config)
            
            # Map OAuth roles to RBAC roles
            self._map_oauth_roles_to_rbac(profile, config)
            
            # Get permissions for RBAC roles
            self._map_roles_to_permissions(profile, config)
            
            # Set platform-specific workspace access
            self._set_workspace_access(profile, oauth_claims, config)
            
            # Audit role mapping
            self._audit_role_mapping(profile, oauth_claims)
            
            return profile
            
        except Exception as e:
            logger.error(f"Failed to map OAuth to RBAC: {e}")
            raise OAuthMappingError(f"Role mapping failed: {e}")
    
    def _map_scopes_to_roles(self, profile: OAuthUserProfile, config: Dict[str, Any]) -> None:
        """Map OAuth scopes to RBAC roles"""
        scope_mappings = config.get('scopes', {}).get('rbac_mapping', {})
        
        for scope in profile.oauth_scopes:
            if scope in scope_mappings:
                rbac_roles = scope_mappings[scope]
                for role in rbac_roles:
                    if role not in profile.rbac_roles:
                        profile.rbac_roles.append(role)
    
    def _map_oauth_roles_to_rbac(self, profile: OAuthUserProfile, config: Dict[str, Any]) -> None:
        """Map OAuth roles to RBAC roles"""
        rbac_config = config.get('rbac_integration', {})
        role_hierarchy = rbac_config.get('role_hierarchy', {})
        
        for oauth_role in profile.oauth_roles:
            if oauth_role in role_hierarchy:
                role_config = role_hierarchy[oauth_role]
                rbac_roles = role_config.get('rbac_roles', [])
                
                for role in rbac_roles:
                    if role not in profile.rbac_roles:
                        profile.rbac_roles.append(role)
                
                # Handle role inheritance
                inherited_roles = role_config.get('inherits', [])
                for inherited_role in inherited_roles:
                    if inherited_role in role_hierarchy:
                        inherited_rbac_roles = role_hierarchy[inherited_role].get('rbac_roles', [])
                        for role in inherited_rbac_roles:
                            if role not in profile.rbac_roles:
                                profile.rbac_roles.append(role)
    
    def _map_roles_to_permissions(self, profile: OAuthUserProfile, config: Dict[str, Any]) -> None:
        """Map RBAC roles to permissions"""
        permission_mappings = config.get('permission_mapping', {}).get(f'{profile.platform.value}_permissions', {})
        
        for oauth_role in profile.oauth_roles:
            if oauth_role in permission_mappings:
                role_config = permission_mappings[oauth_role]
                rbac_permissions = role_config.get('rbac_permissions', [])
                
                for permission in rbac_permissions:
                    if permission not in profile.platform_permissions:
                        profile.platform_permissions.append(permission)
    
    def _set_workspace_access(self, profile: OAuthUserProfile, oauth_claims: Dict[str, Any], 
                            config: Dict[str, Any]) -> None:
        """Set platform-specific workspace access"""
        if profile.platform == SupportedPlatform.DATABRICKS:
            workspace_claim = config.get('rbac_integration', {}).get('workspace_claim', 'workspace_id')
            workspace_id = oauth_claims.get(workspace_claim)
            
            if workspace_id:
                profile.workspace_access = {
                    'workspace_id': workspace_id,
                    'workspace_url': config.get('workspace_url')
                }
        elif profile.platform == SupportedPlatform.QLIK:
            # Qlik-specific workspace/space access
            profile.workspace_access = {
                'tenant_id': oauth_claims.get('tenant_id'),
                'spaces': oauth_claims.get('spaces', [])
            }
    
    def _audit_role_mapping(self, profile: OAuthUserProfile, oauth_claims: Dict[str, Any]) -> None:
        """Audit OAuth role mapping"""
        audit_event = AuditEvent(
            event_type=AuditEventType.ROLE_ASSIGNMENT,
            user_id=profile.oauth_sub,
            details={
                'platform': profile.platform.value,
                'oauth_claims': oauth_claims,
                'oauth_scopes': profile.oauth_scopes,
                'oauth_roles': profile.oauth_roles,
                'rbac_roles': profile.rbac_roles,
                'platform_permissions': profile.platform_permissions,
                'workspace_access': profile.workspace_access
            },
            timestamp=datetime.now(timezone.utc),
            source='OAuthRoleMapper'
        )
        
        self.audit_logger.log_event(audit_event)


class OAuthSessionManager:
    """
    Manages OAuth authentication sessions with token refresh.
    """
    
    def __init__(self, session_timeout: int = 3600, max_concurrent_sessions: int = 5):
        """
        Initialize OAuth session manager.
        
        Args:
            session_timeout: Session timeout in seconds
            max_concurrent_sessions: Maximum concurrent sessions per user per platform
        """
        self.session_timeout = session_timeout
        self.max_concurrent_sessions = max_concurrent_sessions
        self.active_sessions: Dict[str, OAuthSession] = {}
        self.user_sessions: Dict[str, Dict[SupportedPlatform, Set[str]]] = {}  # user_id -> platform -> session_ids
        self.session_lock = threading.RLock()
        self.audit_logger = AuditLogger()
        
        # Start session cleanup and token refresh threads
        self._start_maintenance_threads()
    
    def create_session(self, user_profile: OAuthUserProfile, oauth_token: TokenResponse,
                      ip_address: str = None, user_agent: str = None,
                      cac_binding: Dict[str, Any] = None) -> OAuthSession:
        """
        Create new OAuth authentication session.
        
        Args:
            user_profile: User profile with RBAC roles
            oauth_token: OAuth token response
            ip_address: Client IP address
            user_agent: Client user agent
            cac_binding: CAC/PIV binding information
            
        Returns:
            OAuth session
        """
        with self.session_lock:
            try:
                # Check concurrent session limit
                user_id = user_profile.oauth_sub
                platform = user_profile.platform
                
                if user_id not in self.user_sessions:
                    self.user_sessions[user_id] = {}
                if platform not in self.user_sessions[user_id]:
                    self.user_sessions[user_id][platform] = set()
                
                existing_sessions = self.user_sessions[user_id][platform]
                
                if len(existing_sessions) >= self.max_concurrent_sessions:
                    # Terminate oldest session
                    oldest_session_id = min(existing_sessions, 
                                          key=lambda sid: self.active_sessions[sid].created_at)
                    self.terminate_session(oldest_session_id, "Concurrent session limit exceeded")
                
                # Calculate token expiration
                now = datetime.now(timezone.utc)
                token_expires_at = now + timedelta(seconds=oauth_token.expires_in or 3600)
                refresh_token_expires_at = None
                
                if oauth_token.refresh_token:
                    # Assume refresh token expires in 24 hours if not specified
                    refresh_token_expires_at = now + timedelta(days=1)
                
                # Create new session
                session_id = str(uuid4())
                expires_at = now + timedelta(seconds=self.session_timeout)
                
                session = OAuthSession(
                    session_id=session_id,
                    platform=platform,
                    user_profile=user_profile,
                    oauth_token=oauth_token,
                    status=OAuthSessionStatus.ACTIVE,
                    created_at=now,
                    expires_at=expires_at,
                    last_activity=now,
                    last_token_refresh=None,
                    token_expires_at=token_expires_at,
                    refresh_token_expires_at=refresh_token_expires_at,
                    ip_address=ip_address,
                    user_agent=user_agent,
                    cac_binding=cac_binding,
                    platform_session_data={},
                    metadata={}
                )
                
                # Store session
                self.active_sessions[session_id] = session
                self.user_sessions[user_id][platform].add(session_id)
                
                # Audit session creation
                self._audit_session_event(session, "SESSION_CREATED")
                
                logger.info(f"Created OAuth session {session_id} for user {user_profile.oauth_sub} on {platform.value}")
                return session
                
            except Exception as e:
                logger.error(f"Failed to create OAuth session: {e}")
                raise
    
    def validate_session(self, session_id: str, update_activity: bool = True) -> Optional[OAuthSession]:
        """
        Validate and retrieve session.
        
        Args:
            session_id: Session ID
            update_activity: Whether to update last activity time
            
        Returns:
            OAuth session if valid, None otherwise
        """
        with self.session_lock:
            session = self.active_sessions.get(session_id)
            
            if not session:
                return None
            
            now = datetime.now(timezone.utc)
            
            # Check session expiration
            if now > session.expires_at:
                self.terminate_session(session_id, "Session expired")
                return None
            
            # Check session status
            if session.status != OAuthSessionStatus.ACTIVE:
                return None
            
            # Check token expiration
            if now > session.token_expires_at:
                if session.oauth_token.refresh_token and session.refresh_token_expires_at and now < session.refresh_token_expires_at:
                    session.status = OAuthSessionStatus.REFRESH_REQUIRED
                else:
                    session.status = OAuthSessionStatus.TOKEN_EXPIRED
                    return None
            
            # Update activity
            if update_activity:
                session.last_activity = now
                # Extend session if needed
                new_expires_at = now + timedelta(seconds=self.session_timeout)
                if new_expires_at > session.expires_at:
                    session.expires_at = new_expires_at
            
            return session
    
    def refresh_token(self, session_id: str, new_token: TokenResponse) -> bool:
        """
        Refresh OAuth token for session.
        
        Args:
            session_id: Session ID
            new_token: New OAuth token response
            
        Returns:
            True if token was refreshed
        """
        with self.session_lock:
            session = self.active_sessions.get(session_id)
            
            if not session:
                return False
            
            # Update token
            session.oauth_token = new_token
            session.last_token_refresh = datetime.now(timezone.utc)
            session.token_expires_at = session.last_token_refresh + timedelta(seconds=new_token.expires_in or 3600)
            session.status = OAuthSessionStatus.ACTIVE
            
            # Audit token refresh
            self._audit_session_event(session, "TOKEN_REFRESHED")
            
            logger.info(f"Refreshed token for OAuth session {session_id}")
            return True
    
    def terminate_session(self, session_id: str, reason: str = "User logout") -> bool:
        """
        Terminate session.
        
        Args:
            session_id: Session ID
            reason: Termination reason
            
        Returns:
            True if session was terminated
        """
        with self.session_lock:
            session = self.active_sessions.get(session_id)
            
            if not session:
                return False
            
            # Update session status
            session.status = OAuthSessionStatus.TERMINATED
            
            # Remove from active sessions
            del self.active_sessions[session_id]
            
            # Remove from user sessions
            user_id = session.user_profile.oauth_sub
            platform = session.platform
            
            if user_id in self.user_sessions and platform in self.user_sessions[user_id]:
                self.user_sessions[user_id][platform].discard(session_id)
                if not self.user_sessions[user_id][platform]:
                    del self.user_sessions[user_id][platform]
                if not self.user_sessions[user_id]:
                    del self.user_sessions[user_id]
            
            # Audit session termination
            self._audit_session_event(session, "SESSION_TERMINATED", {"reason": reason})
            
            logger.info(f"Terminated OAuth session {session_id}: {reason}")
            return True
    
    def get_user_sessions(self, user_id: str, platform: SupportedPlatform = None) -> List[OAuthSession]:
        """Get all active sessions for user"""
        with self.session_lock:
            sessions = []
            user_session_data = self.user_sessions.get(user_id, {})
            
            if platform:
                session_ids = user_session_data.get(platform, set())
            else:
                session_ids = set()
                for platform_sessions in user_session_data.values():
                    session_ids.update(platform_sessions)
            
            for session_id in session_ids:
                if session_id in self.active_sessions:
                    sessions.append(self.active_sessions[session_id])
            
            return sessions
    
    def _start_maintenance_threads(self) -> None:
        """Start background threads for session maintenance"""
        def cleanup_expired_sessions():
            import time
            while True:
                try:
                    with self.session_lock:
                        now = datetime.now(timezone.utc)
                        expired_sessions = []
                        
                        for session_id, session in self.active_sessions.items():
                            if now > session.expires_at:
                                expired_sessions.append(session_id)
                            elif now > session.token_expires_at and session.status == OAuthSessionStatus.ACTIVE:
                                if not session.oauth_token.refresh_token or (
                                    session.refresh_token_expires_at and now > session.refresh_token_expires_at
                                ):
                                    expired_sessions.append(session_id)
                        
                        for session_id in expired_sessions:
                            self.terminate_session(session_id, "Session expired (cleanup)")
                    
                    time.sleep(60)  # Check every minute
                except Exception as e:
                    logger.error(f"Session cleanup error: {e}")
                    time.sleep(60)
        
        cleanup_thread = threading.Thread(target=cleanup_expired_sessions, daemon=True)
        cleanup_thread.start()
    
    def _audit_session_event(self, session: OAuthSession, event_type: str, details: Dict[str, Any] = None) -> None:
        """Audit session event"""
        audit_details = {
            'session_id': session.session_id,
            'platform': session.platform.value,
            'user_id': session.user_profile.oauth_sub,
            'ip_address': session.ip_address,
            'user_agent': session.user_agent,
            'cac_bound': bool(session.cac_binding)
        }
        
        if details:
            audit_details.update(details)
        
        audit_event = AuditEvent(
            event_type=AuditEventType.AUTHENTICATION,
            user_id=session.user_profile.oauth_sub,
            details=audit_details,
            timestamp=datetime.now(timezone.utc),
            source='OAuthSessionManager'
        )
        
        self.audit_logger.log_event(audit_event)


class OAuthRBACBridge:
    """
    Main bridge between OAuth 2.0 authentication and RBAC system.
    
    Provides complete integration including:
    - Multi-platform OAuth 2.0 support
    - Token validation and introspection
    - Role mapping to RBAC system
    - Session management with token refresh
    - CAC/PIV token binding
    - Comprehensive audit logging
    """
    
    def __init__(self, session_timeout: int = 3600, enable_cac_binding: bool = True):
        """
        Initialize OAuth RBAC bridge.
        
        Args:
            session_timeout: Session timeout in seconds
            enable_cac_binding: Enable CAC/PIV token binding
        """
        # Load platform configurations
        self.platform_configs = self._load_platform_configs()
        
        # Initialize components
        self.token_validator = PlatformTokenValidator(self.platform_configs)
        self.role_mapper = OAuthRoleMapper(self.platform_configs)
        self.session_manager = OAuthSessionManager(session_timeout)
        
        # Initialize platform integrations
        self.qlik_integration = CompleteQlikOAuthIntegration()
        self.databricks_integration = CompleteDatabricksOAuthIntegration()
        
        # Initialize CAC binding if enabled
        self.cac_binder = EnhancedCACOAuthBinder() if enable_cac_binding else None
        
        self.audit_logger = AuditLogger()
        
        logger.info("Initialized OAuth RBAC Bridge")
    
    def authenticate_user(self, platform: SupportedPlatform, access_token: str,
                         ip_address: str = None, user_agent: str = None,
                         cac_credentials: Any = None) -> Tuple[bool, Optional[OAuthSession], str]:
        """
        Authenticate user with OAuth token.
        
        Args:
            platform: Platform type
            access_token: OAuth access token
            ip_address: Client IP address
            user_agent: Client user agent
            cac_credentials: CAC credentials for binding
            
        Returns:
            Tuple of (success, session, message)
        """
        try:
            # Validate token
            valid, claims, message = self.token_validator.validate_token(platform, access_token)
            
            if not valid:
                self._audit_authentication_failure(platform, None, message, ip_address)
                return False, None, f"Token validation failed: {message}"
            
            # Introspect token for additional information
            active, token_info, _ = self.token_validator.introspect_token(platform, access_token)
            
            if not active:
                self._audit_authentication_failure(platform, claims.get('sub'), "Token not active", ip_address)
                return False, None, "Token not active"
            
            # Map OAuth claims to RBAC profile
            user_profile = self.role_mapper.map_oauth_to_rbac(platform, claims, token_info)
            
            # Create token response object
            oauth_token = TokenResponse(
                access_token=access_token,
                token_type="Bearer",
                expires_in=claims.get('exp', 0) - int(datetime.now(timezone.utc).timestamp()),
                refresh_token=None,  # Will be provided separately if available
                scope=" ".join(user_profile.oauth_scopes)
            )
            
            # Handle CAC binding if enabled and credentials provided
            cac_binding = None
            if self.cac_binder and cac_credentials:
                try:
                    binding_result = self.cac_binder.bind_cac_to_oauth_token(
                        cac_credentials, 
                        oauth_token,
                        binding_strength=TokenBindingStrength.STRONG
                    )
                    
                    if binding_result.success:
                        user_profile.cac_bound = True
                        cac_binding = {
                            'binding_id': binding_result.binding_id,
                            'binding_strength': binding_result.binding_strength.value,
                            'certificate_serial': cac_credentials.serial_number,
                            'bound_at': datetime.now(timezone.utc).isoformat()
                        }
                except Exception as e:
                    logger.warning(f"CAC binding failed: {e}")
            
            # Create session
            session = self.session_manager.create_session(
                user_profile=user_profile,
                oauth_token=oauth_token,
                ip_address=ip_address,
                user_agent=user_agent,
                cac_binding=cac_binding
            )
            
            # Create/update user in RBAC system
            self._create_or_update_rbac_user(user_profile)
            
            message = f"Authentication successful for {user_profile.oauth_sub} on {platform.value}"
            logger.info(message)
            
            return True, session, message
            
        except Exception as e:
            message = f"Authentication error: {e}"
            logger.error(message)
            self._audit_authentication_failure(platform, None, message, ip_address)
            return False, None, message
    
    def validate_session(self, session_id: str) -> Tuple[bool, Optional[OAuthSession], str]:
        """
        Validate existing session.
        
        Args:
            session_id: Session ID
            
        Returns:
            Tuple of (valid, session, message)
        """
        try:
            session = self.session_manager.validate_session(session_id)
            
            if session:
                if session.status == OAuthSessionStatus.REFRESH_REQUIRED:
                    return False, session, "Token refresh required"
                return True, session, "Session valid"
            else:
                return False, None, "Session invalid or expired"
                
        except Exception as e:
            message = f"Session validation error: {e}"
            logger.error(message)
            return False, None, message
    
    def refresh_session_token(self, session_id: str, refresh_token: str) -> Tuple[bool, Optional[OAuthSession], str]:
        """
        Refresh session token.
        
        Args:
            session_id: Session ID
            refresh_token: OAuth refresh token
            
        Returns:
            Tuple of (success, session, message)
        """
        try:
            session = self.session_manager.active_sessions.get(session_id)
            
            if not session:
                return False, None, "Session not found"
            
            # Use platform-specific integration to refresh token
            if session.platform == SupportedPlatform.QLIK:
                token_response = self.qlik_integration.refresh_token(refresh_token)
            elif session.platform == SupportedPlatform.DATABRICKS:
                token_response = self.databricks_integration.refresh_token(refresh_token)
            else:
                return False, None, f"Platform {session.platform.value} not supported"
            
            if not token_response:
                return False, None, "Token refresh failed"
            
            # Update session with new token
            success = self.session_manager.refresh_token(session_id, token_response)
            
            if success:
                updated_session = self.session_manager.active_sessions.get(session_id)
                return True, updated_session, "Token refreshed successfully"
            else:
                return False, None, "Failed to update session with new token"
                
        except Exception as e:
            message = f"Token refresh error: {e}"
            logger.error(message)
            return False, None, message
    
    def logout_user(self, session_id: str) -> Tuple[bool, str]:
        """
        Logout user and terminate session.
        
        Args:
            session_id: Session ID
            
        Returns:
            Tuple of (success, message)
        """
        try:
            success = self.session_manager.terminate_session(session_id, "User logout")
            
            if success:
                return True, "Logout successful"
            else:
                return False, "Session not found"
                
        except Exception as e:
            message = f"Logout error: {e}"
            logger.error(message)
            return False, message
    
    def get_user_permissions(self, session_id: str) -> Tuple[bool, List[str], str]:
        """
        Get user permissions from session.
        
        Args:
            session_id: Session ID
            
        Returns:
            Tuple of (success, permissions, message)
        """
        try:
            session = self.session_manager.validate_session(session_id)
            
            if not session:
                return False, [], "Session invalid"
            
            permissions = session.user_profile.platform_permissions
            return True, permissions, "Permissions retrieved"
            
        except Exception as e:
            message = f"Permission retrieval error: {e}"
            logger.error(message)
            return False, [], message
    
    def get_platform_access(self, session_id: str) -> Tuple[bool, Dict[str, Any], str]:
        """
        Get platform-specific access information.
        
        Args:
            session_id: Session ID
            
        Returns:
            Tuple of (success, access_info, message)
        """
        try:
            session = self.session_manager.validate_session(session_id)
            
            if not session:
                return False, {}, "Session invalid"
            
            access_info = {
                'platform': session.platform.value,
                'oauth_scopes': session.user_profile.oauth_scopes,
                'oauth_roles': session.user_profile.oauth_roles,
                'rbac_roles': session.user_profile.rbac_roles,
                'workspace_access': session.user_profile.workspace_access,
                'cac_bound': session.user_profile.cac_bound
            }
            
            return True, access_info, "Access information retrieved"
            
        except Exception as e:
            message = f"Access information retrieval error: {e}"
            logger.error(message)
            return False, {}, message
    
    def _load_platform_configs(self) -> Dict[SupportedPlatform, Dict[str, Any]]:
        """Load platform-specific configurations"""
        configs = {}
        
        try:
            # Get configuration directory
            current_dir = Path(__file__).parent.parent
            config_dir = current_dir / "config" / "oauth"
            
            # Load Qlik configuration
            qlik_config_path = config_dir / "qlik_oauth.json"
            if qlik_config_path.exists():
                with open(qlik_config_path, 'r') as f:
                    qlik_data = json.load(f)
                    configs[SupportedPlatform.QLIK] = qlik_data.get('oauth_config', {})
            
            # Load Databricks configuration
            databricks_config_path = config_dir / "databricks_oauth.json"
            if databricks_config_path.exists():
                with open(databricks_config_path, 'r') as f:
                    databricks_data = json.load(f)
                    configs[SupportedPlatform.DATABRICKS] = databricks_data.get('oauth_config', {})
            
        except Exception as e:
            logger.error(f"Failed to load platform configurations: {e}")
        
        return configs
    
    def _create_or_update_rbac_user(self, user_profile: OAuthUserProfile) -> None:
        """Create or update user in RBAC system"""
        try:
            # This would integrate with the RBAC database
            # Implementation depends on the specific RBAC database schema
            pass
        except Exception as e:
            logger.error(f"Failed to create/update RBAC user: {e}")
    
    def _audit_authentication_failure(self, platform: SupportedPlatform, user_id: str, 
                                    message: str, ip_address: str) -> None:
        """Audit authentication failure"""
        audit_event = AuditEvent(
            event_type=AuditEventType.AUTHENTICATION_FAILURE,
            user_id=user_id or "unknown",
            details={
                'platform': platform.value,
                'message': message,
                'ip_address': ip_address,
                'authentication_method': 'OAuth 2.0'
            },
            timestamp=datetime.now(timezone.utc),
            source='OAuthRBACBridge'
        )
        
        self.audit_logger.log_event(audit_event)


# Export main classes
__all__ = [
    'OAuthRBACBridge',
    'OAuthSessionManager',
    'OAuthRoleMapper',
    'PlatformTokenValidator',
    'OAuthUserProfile',
    'OAuthSession',
    'SupportedPlatform',
    'OAuthValidationError',
    'OAuthMappingError'
]