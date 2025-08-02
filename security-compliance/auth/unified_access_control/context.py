"""
Unified User Context and Platform Context Management

Single user profile merging CAC credentials, RBAC roles, OAuth scopes, and platform 
sessions with real-time synchronization and comprehensive attribute management.

This module provides:
- UnifiedUserContext: Comprehensive user profile across all authentication methods
- PlatformContext: Platform-specific user context and permissions
- Real-time context synchronization across platforms and sessions
- Multi-classification user attributes with Bell-LaPadula enforcement
- CAC/PIV credential binding and validation
- OAuth scope and permission mapping
- Session state tracking and platform correlation

Classification: UNCLASSIFIED//FOR OFFICIAL USE ONLY
"""

import json
import logging
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Set
from uuid import UUID
from dataclasses import dataclass, field, asdict
from enum import Enum

# Import existing RBAC infrastructure
from ...rbac.models.user import User, UserRole
from ...rbac.models.role import Role
from ...rbac.models.classification import SecurityClearance, ClassificationLevel

logger = logging.getLogger(__name__)


class ContextStatus(Enum):
    """User context status."""
    ACTIVE = "active"
    INACTIVE = "inactive"
    LOCKED = "locked"
    EXPIRED = "expired"
    SUSPENDED = "suspended"


class PlatformStatus(Enum):
    """Platform context status."""
    CONNECTED = "connected"
    DISCONNECTED = "disconnected"
    AUTHENTICATING = "authenticating"
    ERROR = "error"
    EXPIRED = "expired"


@dataclass
class CACCredentials:
    """CAC/PIV credential information."""
    cac_id: Optional[str] = None
    piv_id: Optional[str] = None
    dod_id: Optional[str] = None
    edipi: Optional[str] = None
    certificate_serial: Optional[str] = None
    certificate_subject: Optional[str] = None
    certificate_issuer: Optional[str] = None
    certificate_expiry: Optional[datetime] = None
    last_validated: Optional[datetime] = None
    validation_status: str = "unknown"
    
    def is_valid(self) -> bool:
        """Check if CAC credentials are valid."""
        if not self.certificate_expiry:
            return False
        
        now = datetime.now(timezone.utc)
        return (
            self.certificate_expiry > now and
            self.validation_status == "valid" and
            self.last_validated and
            (now - self.last_validated) < timedelta(hours=24)
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        result = asdict(self)
        if self.certificate_expiry:
            result['certificate_expiry'] = self.certificate_expiry.isoformat()
        if self.last_validated:
            result['last_validated'] = self.last_validated.isoformat()
        return result


@dataclass
class SecurityAttributes:
    """Security clearance and classification attributes."""
    clearance_level: Optional[str] = None
    clearance_verified: bool = False
    clearance_expiry: Optional[datetime] = None
    sci_compartments: List[str] = field(default_factory=list)
    caveat_codes: List[str] = field(default_factory=list)
    investigation_type: Optional[str] = None
    polygraph_current: bool = False
    polygraph_expiry: Optional[datetime] = None
    training_current: bool = False
    training_expiry: Optional[datetime] = None
    last_background_check: Optional[datetime] = None
    
    def can_access_classification(self, required_level: str) -> bool:
        """Check if user can access required classification level."""
        if not self.clearance_verified or not self.clearance_level:
            return False
        
        # Simple hierarchical check (would use proper classification engine in production)
        level_hierarchy = {
            'U': 0,           # Unclassified
            'CUI': 1,         # Controlled Unclassified Information
            'C': 2,           # Confidential
            'S': 3,           # Secret
            'TS': 4,          # Top Secret
            'TS_SCI': 5       # Top Secret/SCI
        }
        
        user_level = level_hierarchy.get(self.clearance_level, -1)
        required_level_num = level_hierarchy.get(required_level, 999)
        
        return user_level >= required_level_num
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        result = asdict(self)
        if self.clearance_expiry:
            result['clearance_expiry'] = self.clearance_expiry.isoformat()
        if self.polygraph_expiry:
            result['polygraph_expiry'] = self.polygraph_expiry.isoformat()
        if self.training_expiry:
            result['training_expiry'] = self.training_expiry.isoformat()
        if self.last_background_check:
            result['last_background_check'] = self.last_background_check.isoformat()
        return result


@dataclass
class PlatformContext:
    """Platform-specific user context and permissions."""
    platform: str
    status: PlatformStatus = PlatformStatus.DISCONNECTED
    user_info: Dict[str, Any] = field(default_factory=dict)
    permissions: List[str] = field(default_factory=list)
    oauth_scopes: List[str] = field(default_factory=list)
    available_scopes: List[str] = field(default_factory=list)
    access_token: Optional[str] = None
    refresh_token: Optional[str] = None
    token_expiry: Optional[datetime] = None
    session_id: Optional[str] = None
    last_accessed: Optional[datetime] = None
    last_updated: Optional[datetime] = None
    conditions: Dict[str, Any] = field(default_factory=dict)
    platform_roles: List[str] = field(default_factory=list)
    platform_groups: List[str] = field(default_factory=list)
    connection_metadata: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        if self.last_updated is None:
            self.last_updated = datetime.now(timezone.utc)
    
    def is_connected(self) -> bool:
        """Check if platform context is connected and valid."""
        return (
            self.status == PlatformStatus.CONNECTED and
            self.is_token_valid()
        )
    
    def is_token_valid(self) -> bool:
        """Check if OAuth token is valid."""
        if not self.access_token or not self.token_expiry:
            return False
        
        # Add 5-minute buffer for token expiry
        buffer = timedelta(minutes=5)
        return datetime.now(timezone.utc) < (self.token_expiry - buffer)
    
    def needs_refresh(self) -> bool:
        """Check if token needs refresh."""
        if not self.token_expiry:
            return False
        
        # Refresh if expiring within 15 minutes
        refresh_threshold = timedelta(minutes=15)
        return datetime.now(timezone.utc) >= (self.token_expiry - refresh_threshold)
    
    def update_token(self, access_token: str, expires_in: int, 
                    refresh_token: str = None) -> None:
        """Update OAuth token information."""
        self.access_token = access_token
        self.token_expiry = datetime.now(timezone.utc) + timedelta(seconds=expires_in)
        if refresh_token:
            self.refresh_token = refresh_token
        self.last_updated = datetime.now(timezone.utc)
        self.status = PlatformStatus.CONNECTED
    
    def update_last_accessed(self) -> None:
        """Update last accessed timestamp."""
        self.last_accessed = datetime.now(timezone.utc)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        result = asdict(self)
        result['status'] = self.status.value
        
        # Convert datetime fields
        if self.token_expiry:
            result['token_expiry'] = self.token_expiry.isoformat()
        if self.last_accessed:
            result['last_accessed'] = self.last_accessed.isoformat()
        if self.last_updated:
            result['last_updated'] = self.last_updated.isoformat()
        
        # Don't include sensitive tokens in serialization
        result.pop('access_token', None)
        result.pop('refresh_token', None)
        
        return result


@dataclass
class SessionInfo:
    """Session information across platforms."""
    session_id: str
    user_id: UUID
    created_at: datetime
    last_activity: datetime
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    platform_sessions: Dict[str, str] = field(default_factory=dict)  # platform -> platform_session_id
    active_platforms: Set[str] = field(default_factory=set)
    authentication_methods: List[str] = field(default_factory=list)
    session_attributes: Dict[str, Any] = field(default_factory=dict)
    expires_at: Optional[datetime] = None
    
    def is_active(self) -> bool:
        """Check if session is active."""
        now = datetime.now(timezone.utc)
        
        # Check expiry
        if self.expires_at and now > self.expires_at:
            return False
        
        # Check last activity (default 8 hour timeout)
        activity_timeout = timedelta(hours=8)
        if now - self.last_activity > activity_timeout:
            return False
        
        return True
    
    def update_activity(self) -> None:
        """Update last activity timestamp."""
        self.last_activity = datetime.now(timezone.utc)
    
    def add_platform_session(self, platform: str, platform_session_id: str) -> None:
        """Add platform session mapping."""
        self.platform_sessions[platform] = platform_session_id
        self.active_platforms.add(platform)
        self.update_activity()
    
    def remove_platform_session(self, platform: str) -> None:
        """Remove platform session mapping."""
        self.platform_sessions.pop(platform, None)
        self.active_platforms.discard(platform)
        self.update_activity()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        result = asdict(self)
        
        # Convert datetime fields
        result['created_at'] = self.created_at.isoformat()
        result['last_activity'] = self.last_activity.isoformat()
        if self.expires_at:
            result['expires_at'] = self.expires_at.isoformat()
        
        # Convert sets to lists for JSON serialization
        result['active_platforms'] = list(self.active_platforms)
        result['user_id'] = str(self.user_id)
        
        return result


class UnifiedUserContext:
    """
    Comprehensive unified user context across all authentication methods and platforms.
    
    Integrates:
    - Base RBAC user profile with roles and permissions
    - CAC/PIV credentials and certificate validation
    - Security clearance and classification attributes
    - Platform-specific contexts with OAuth tokens and permissions
    - Session information and cross-platform correlation
    - Real-time synchronization and cache invalidation
    """
    
    def __init__(self, user_id: UUID, username: str, email: str = None):
        """
        Initialize unified user context.
        
        Args:
            user_id: Unique user identifier
            username: Username
            email: User email address
        """
        # Core identity
        self.user_id = user_id
        self.username = username
        self.email = email
        
        # Status and metadata
        self.status = ContextStatus.ACTIVE
        self.created_at = datetime.now(timezone.utc)
        self.last_updated = datetime.now(timezone.utc)
        self.last_accessed = datetime.now(timezone.utc)
        
        # RBAC attributes
        self.roles: List[Role] = []
        self.effective_permissions: List[Dict[str, Any]] = []
        self.account_status = "active"
        
        # DoD identity attributes
        self.department: Optional[str] = None
        self.organization: Optional[str] = None
        self.rank: Optional[str] = None
        self.unit: Optional[str] = None
        self.command: Optional[str] = None
        
        # CAC/PIV credentials
        self.cac_credentials = CACCredentials()
        
        # Security attributes
        self.security_attributes = SecurityAttributes()
        
        # Platform contexts
        self.platform_contexts: Dict[str, PlatformContext] = {}
        
        # Session information
        self.session_info: Optional[SessionInfo] = None
        
        # Additional attributes
        self.additional_attributes: Dict[str, Any] = {}
        
        # Performance tracking
        self._cache_version = 1
        self._dirty_platforms: Set[str] = set()
    
    @classmethod
    def from_user(cls, user: User) -> 'UnifiedUserContext':
        """Create unified context from RBAC User object."""
        context = cls(
            user_id=user.id,
            username=user.username,
            email=user.email
        )
        
        # Copy RBAC attributes
        context.account_status = user.account_status
        context.department = user.department
        context.organization = user.organization
        
        # Copy DoD identity
        context.cac_credentials.dod_id = user.dod_id
        context.cac_credentials.cac_id = user.cac_id
        context.cac_credentials.piv_id = user.piv_id
        
        # Copy security clearance
        clearance = user.get_security_clearance()
        if clearance:
            context.security_attributes.clearance_level = clearance.clearance_level
            context.security_attributes.clearance_verified = user.is_clearance_verified()
            context.security_attributes.clearance_expiry = clearance.expires_at
            context.security_attributes.sci_compartments = clearance.compartments or []
            context.security_attributes.caveat_codes = clearance.caveat_codes or []
            context.security_attributes.investigation_type = clearance.investigation_type
        
        # Copy training information
        context.security_attributes.training_current = user.is_training_current()
        context.security_attributes.training_expiry = user.security_training_expires
        
        # Get user roles
        user_roles = user.get_roles(active_only=True)
        for user_role in user_roles:
            role = user_role.get_role()
            if role:
                context.roles.append(role)
        
        return context
    
    @property
    def user_id_str(self) -> str:
        """Get user ID as string."""
        return str(self.user_id)
    
    @property
    def dod_id(self) -> Optional[str]:
        """Get DoD ID."""
        return self.cac_credentials.dod_id
    
    @property
    def cac_id(self) -> Optional[str]:
        """Get CAC ID."""
        return self.cac_credentials.cac_id
    
    @property
    def piv_id(self) -> Optional[str]:
        """Get PIV ID."""
        return self.cac_credentials.piv_id
    
    @property
    def security_clearance(self) -> Optional[str]:
        """Get security clearance level."""
        return self.security_attributes.clearance_level
    
    @property
    def clearance_verified(self) -> bool:
        """Check if clearance is verified."""
        return self.security_attributes.clearance_verified
    
    @property
    def training_current(self) -> bool:
        """Check if training is current."""
        return self.security_attributes.training_current
    
    def is_active(self) -> bool:
        """Check if user context is active."""
        return (
            self.status == ContextStatus.ACTIVE and
            self.account_status == "active"
        )
    
    def can_access_classification(self, classification_level: str) -> bool:
        """Check if user can access required classification level."""
        return self.security_attributes.can_access_classification(classification_level)
    
    def can_emergency_access(self) -> bool:
        """Check if user is eligible for emergency access."""
        # Emergency access requires valid clearance and current training
        return (
            self.clearance_verified and
            self.training_current and
            any(role.role_name in ['EMERGENCY_RESPONDER', 'ADMIN', 'SYSTEM_ADMIN'] for role in self.roles)
        )
    
    def add_platform_context(self, platform: str, context: PlatformContext) -> None:
        """Add or update platform context."""
        self.platform_contexts[platform] = context
        self._dirty_platforms.add(platform)
        self.last_updated = datetime.now(timezone.utc)
        self._cache_version += 1
    
    def get_platform_context(self, platform: str) -> Optional[PlatformContext]:
        """Get platform context."""
        return self.platform_contexts.get(platform)
    
    def remove_platform_context(self, platform: str) -> None:
        """Remove platform context."""
        if platform in self.platform_contexts:
            del self.platform_contexts[platform]
            self._dirty_platforms.add(platform)
            self.last_updated = datetime.now(timezone.utc)
            self._cache_version += 1
    
    def get_connected_platforms(self) -> List[str]:
        """Get list of connected platforms."""
        return [
            platform for platform, context in self.platform_contexts.items()
            if context.is_connected()
        ]
    
    def get_expired_platforms(self) -> List[str]:
        """Get list of platforms with expired tokens."""
        return [
            platform for platform, context in self.platform_contexts.items()
            if not context.is_token_valid()
        ]
    
    def needs_token_refresh(self) -> List[str]:
        """Get list of platforms that need token refresh."""
        return [
            platform for platform, context in self.platform_contexts.items()
            if context.needs_refresh()
        ]
    
    def update_cac_credentials(self, **kwargs) -> None:
        """Update CAC/PIV credential information."""
        for key, value in kwargs.items():
            if hasattr(self.cac_credentials, key):
                setattr(self.cac_credentials, key, value)
        
        self.last_updated = datetime.now(timezone.utc)
        self._cache_version += 1
    
    def update_security_attributes(self, **kwargs) -> None:
        """Update security clearance and training attributes."""
        for key, value in kwargs.items():
            if hasattr(self.security_attributes, key):
                setattr(self.security_attributes, key, value)
        
        self.last_updated = datetime.now(timezone.utc)
        self._cache_version += 1
    
    def update_last_accessed(self) -> None:
        """Update last accessed timestamp."""
        self.last_accessed = datetime.now(timezone.utc)
        
        # Also update session if available
        if self.session_info:
            self.session_info.update_activity()
    
    def set_session_info(self, session_info: SessionInfo) -> None:
        """Set session information."""
        self.session_info = session_info
        self.last_updated = datetime.now(timezone.utc)
        self._cache_version += 1
    
    def add_role(self, role: Role) -> None:
        """Add role to user context."""
        if role not in self.roles:
            self.roles.append(role)
            self.last_updated = datetime.now(timezone.utc)
            self._cache_version += 1
    
    def remove_role(self, role: Role) -> None:
        """Remove role from user context."""
        if role in self.roles:
            self.roles.remove(role)
            self.last_updated = datetime.now(timezone.utc)
            self._cache_version += 1
    
    def get_all_permissions(self) -> Set[str]:
        """Get all permissions from all sources."""
        permissions = set()
        
        # Add RBAC permissions
        for perm in self.effective_permissions:
            permissions.add(f"{perm['resource_type']}.{perm['action']}")
        
        # Add platform permissions
        for platform_context in self.platform_contexts.values():
            permissions.update(platform_context.permissions)
        
        return permissions
    
    def get_all_oauth_scopes(self) -> Set[str]:
        """Get all OAuth scopes from all platforms."""
        scopes = set()
        
        for platform_context in self.platform_contexts.values():
            scopes.update(platform_context.oauth_scopes)
        
        return scopes
    
    def has_permission(self, resource_type: str, action: str, platform: str = None) -> bool:
        """Check if user has specific permission."""
        # Check RBAC permissions
        for perm in self.effective_permissions:
            if perm['resource_type'] == resource_type and perm['action'] == action:
                return True
        
        # Check platform permissions if specified
        if platform and platform in self.platform_contexts:
            platform_context = self.platform_contexts[platform]
            permission_string = f"{resource_type}.{action}"
            return permission_string in platform_context.permissions
        
        return False
    
    def has_oauth_scope(self, scope: str, platform: str = None) -> bool:
        """Check if user has specific OAuth scope."""
        if platform and platform in self.platform_contexts:
            platform_context = self.platform_contexts[platform]
            return scope in platform_context.oauth_scopes
        
        # Check all platforms
        for platform_context in self.platform_contexts.values():
            if scope in platform_context.oauth_scopes:
                return True
        
        return False
    
    def get_cache_version(self) -> int:
        """Get cache version for invalidation tracking."""
        return self._cache_version
    
    def get_dirty_platforms(self) -> Set[str]:
        """Get platforms that have been modified since last sync."""
        return self._dirty_platforms.copy()
    
    def mark_platforms_clean(self, platforms: Set[str] = None) -> None:
        """Mark platforms as clean (synchronized)."""
        if platforms is None:
            self._dirty_platforms.clear()
        else:
            self._dirty_platforms -= platforms
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            'user_id': str(self.user_id),
            'username': self.username,
            'email': self.email,
            'status': self.status.value,
            'created_at': self.created_at.isoformat(),
            'last_updated': self.last_updated.isoformat(),
            'last_accessed': self.last_accessed.isoformat(),
            'account_status': self.account_status,
            'department': self.department,
            'organization': self.organization,
            'rank': self.rank,
            'unit': self.unit,
            'command': self.command,
            'roles': [{'role_name': role.role_name, 'role_code': role.role_code} for role in self.roles],
            'effective_permissions': self.effective_permissions,
            'cac_credentials': self.cac_credentials.to_dict(),
            'security_attributes': self.security_attributes.to_dict(),
            'platform_contexts': {
                platform: context.to_dict() 
                for platform, context in self.platform_contexts.items()
            },
            'session_info': self.session_info.to_dict() if self.session_info else None,
            'connected_platforms': self.get_connected_platforms(),
            'expired_platforms': self.get_expired_platforms(),
            'all_permissions': list(self.get_all_permissions()),
            'all_oauth_scopes': list(self.get_all_oauth_scopes()),
            'cache_version': self._cache_version,
            'additional_attributes': self.additional_attributes
        }
    
    def __str__(self) -> str:
        """String representation."""
        return f"UnifiedUserContext(user_id={self.user_id}, username={self.username}, platforms={list(self.platform_contexts.keys())})"
    
    def __repr__(self) -> str:
        """Detailed representation."""
        return (
            f"UnifiedUserContext(user_id={self.user_id}, username={self.username}, "
            f"status={self.status.value}, roles={len(self.roles)}, "
            f"platforms={list(self.platform_contexts.keys())}, "
            f"clearance={self.security_clearance})"
        )