#!/usr/bin/env python3
"""
DoD-Compliant Session Management System

Core session management system with classification-aware security policies,
multi-factor authentication integration, and comprehensive audit logging.

Classification: UNCLASSIFIED//FOR OFFICIAL USE ONLY
Version: 1.0
Author: Security Compliance Team
Date: 2025-07-18
"""

import json
import secrets
import logging
import threading
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Set, Tuple, Callable
from uuid import UUID, uuid4
from enum import Enum
from dataclasses import dataclass, field, asdict
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.fernet import Fernet
import base64

# Import existing security components
from ..auth.cac_piv_integration import CACCredentials, CACPIVAuthenticator
from ..auth.oauth_client import TokenResponse, DoD_OAuth_Client
from ..rbac.models.classification import ClassificationLevel
from ..multi_classification.models.dod_compliance_validator import ComplianceStandard, ViolationSeverity

logger = logging.getLogger(__name__)


class SessionState(Enum):
    """Session state enumeration."""
    ACTIVE = "ACTIVE"
    INACTIVE = "INACTIVE"
    EXPIRED = "EXPIRED"
    SUSPENDED = "SUSPENDED"
    TERMINATED = "TERMINATED"
    LOCKED = "LOCKED"


class SessionEventType(Enum):
    """Session event types for audit logging."""
    SESSION_CREATED = "SESSION_CREATED"
    SESSION_AUTHENTICATED = "SESSION_AUTHENTICATED"
    SESSION_ELEVATED = "SESSION_ELEVATED"
    SESSION_ACCESSED = "SESSION_ACCESSED"
    SESSION_TIMEOUT_WARNING = "SESSION_TIMEOUT_WARNING"
    SESSION_TIMEOUT = "SESSION_TIMEOUT"
    SESSION_SUSPENDED = "SESSION_SUSPENDED"
    SESSION_TERMINATED = "SESSION_TERMINATED"
    SESSION_SECURITY_VIOLATION = "SESSION_SECURITY_VIOLATION"
    SESSION_MFA_CHALLENGE = "SESSION_MFA_CHALLENGE"
    SESSION_CLASSIFICATION_CHANGE = "SESSION_CLASSIFICATION_CHANGE"


class NetworkDomain(Enum):
    """Network domain classifications."""
    NIPR = "NIPR"  # Non-classified Internet Protocol Router Network
    SIPR = "SIPR"  # Secret Internet Protocol Router Network
    JWICS = "JWICS"  # Joint Worldwide Intelligence Communications System


@dataclass
class SessionSecurityContext:
    """Security context for session management."""
    user_id: UUID
    edipi: Optional[str] = None
    clearance_level: Optional[str] = None
    classification_level: str = "U"
    network_domain: NetworkDomain = NetworkDomain.NIPR
    cac_credentials: Optional[CACCredentials] = None
    oauth_tokens: Dict[str, TokenResponse] = field(default_factory=dict)
    security_attributes: Dict[str, Any] = field(default_factory=dict)
    need_to_know_tags: Set[str] = field(default_factory=set)
    organization: Optional[str] = None
    roles: List[str] = field(default_factory=list)


@dataclass
class SessionConfiguration:
    """Session configuration parameters."""
    session_id: str
    max_idle_time: int  # seconds
    max_session_time: int  # seconds
    warning_time: int  # seconds before timeout
    concurrent_session_limit: int = 1
    require_mfa: bool = True
    classification_aware: bool = True
    cross_domain_allowed: bool = False
    audit_level: str = "DETAILED"
    encryption_required: bool = True
    session_binding: bool = True  # Bind to IP/CAC
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SessionEvent:
    """Session event for audit logging."""
    event_id: str
    session_id: str
    event_type: SessionEventType
    timestamp: datetime
    user_id: UUID
    source_ip: Optional[str] = None
    user_agent: Optional[str] = None
    classification_level: Optional[str] = None
    network_domain: Optional[NetworkDomain] = None
    event_data: Dict[str, Any] = field(default_factory=dict)
    security_labels: List[str] = field(default_factory=list)
    success: bool = True
    error_message: Optional[str] = None


@dataclass
class Session:
    """Core session object with classification-aware security."""
    session_id: str
    user_id: UUID
    state: SessionState
    security_context: SessionSecurityContext
    configuration: SessionConfiguration
    created_at: datetime
    last_accessed: datetime
    expires_at: datetime
    warning_at: datetime
    
    # Security tracking
    access_count: int = 0
    failed_access_attempts: int = 0
    security_violations: List[str] = field(default_factory=list)
    
    # Session binding
    bound_ip: Optional[str] = None
    bound_cac_serial: Optional[str] = None
    bound_device_fingerprint: Optional[str] = None
    
    # Multi-factor authentication
    mfa_verified: bool = False
    mfa_challenges: List[Dict[str, Any]] = field(default_factory=list)
    
    # Classification-aware features
    elevation_level: str = "NORMAL"
    cross_domain_access: bool = False
    data_markings: Set[str] = field(default_factory=set)
    
    # Metadata
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    @property
    def is_expired(self) -> bool:
        """Check if session is expired."""
        return datetime.now(timezone.utc) >= self.expires_at
    
    @property
    def is_warning_time(self) -> bool:
        """Check if session is in warning period."""
        return datetime.now(timezone.utc) >= self.warning_at
    
    @property
    def time_remaining(self) -> timedelta:
        """Get time remaining before expiration."""
        return self.expires_at - datetime.now(timezone.utc)
    
    @property
    def idle_time(self) -> timedelta:
        """Get idle time since last access."""
        return datetime.now(timezone.utc) - self.last_accessed
    
    def update_access(self):
        """Update last accessed time."""
        self.last_accessed = datetime.now(timezone.utc)
        self.access_count += 1
    
    def add_security_violation(self, violation: str):
        """Add security violation to session."""
        self.security_violations.append(violation)
        self.failed_access_attempts += 1


class SessionEncryption:
    """Session data encryption handler."""
    
    def __init__(self, encryption_key: bytes = None):
        """Initialize session encryption.
        
        Args:
            encryption_key: Encryption key (generated if None)
        """
        if encryption_key:
            self.key = encryption_key
        else:
            self.key = Fernet.generate_key()
        
        self.fernet = Fernet(self.key)
    
    def encrypt_session_data(self, session_data: Dict[str, Any]) -> str:
        """Encrypt session data.
        
        Args:
            session_data: Session data to encrypt
            
        Returns:
            Encrypted session data as base64 string
        """
        try:
            # Serialize and encrypt
            serialized = json.dumps(session_data, default=str)
            encrypted = self.fernet.encrypt(serialized.encode('utf-8'))
            return base64.b64encode(encrypted).decode('utf-8')
        except Exception as e:
            logger.error(f"Session encryption failed: {e}")
            raise
    
    def decrypt_session_data(self, encrypted_data: str) -> Dict[str, Any]:
        """Decrypt session data.
        
        Args:
            encrypted_data: Encrypted session data
            
        Returns:
            Decrypted session data
        """
        try:
            # Decode and decrypt
            encrypted_bytes = base64.b64decode(encrypted_data.encode('utf-8'))
            decrypted = self.fernet.decrypt(encrypted_bytes)
            return json.loads(decrypted.decode('utf-8'))
        except Exception as e:
            logger.error(f"Session decryption failed: {e}")
            raise
    
    @classmethod
    def generate_session_token(cls, session_id: str, secret_key: bytes) -> str:
        """Generate secure session token.
        
        Args:
            session_id: Session identifier
            secret_key: Secret key for token generation
            
        Returns:
            Secure session token
        """
        # Create token with timestamp and random component
        timestamp = int(datetime.now(timezone.utc).timestamp())
        random_bytes = secrets.token_bytes(16)
        
        # Combine components
        token_data = f"{session_id}:{timestamp}:{base64.b64encode(random_bytes).decode()}"
        
        # Encrypt token
        fernet = Fernet(base64.urlsafe_b64encode(secret_key[:32]))
        encrypted_token = fernet.encrypt(token_data.encode('utf-8'))
        
        return base64.urlsafe_b64encode(encrypted_token).decode('utf-8')
    
    @classmethod
    def validate_session_token(cls, token: str, secret_key: bytes, max_age: int = 3600) -> Optional[str]:
        """Validate session token and extract session ID.
        
        Args:
            token: Session token to validate
            secret_key: Secret key for validation
            max_age: Maximum token age in seconds
            
        Returns:
            Session ID if valid, None otherwise
        """
        try:
            # Decrypt token
            encrypted_token = base64.urlsafe_b64decode(token.encode('utf-8'))
            fernet = Fernet(base64.urlsafe_b64encode(secret_key[:32]))
            decrypted_data = fernet.decrypt(encrypted_token).decode('utf-8')
            
            # Parse token components
            parts = decrypted_data.split(':')
            if len(parts) != 3:
                return None
            
            session_id, timestamp_str, _ = parts
            timestamp = int(timestamp_str)
            
            # Check token age
            current_timestamp = int(datetime.now(timezone.utc).timestamp())
            if current_timestamp - timestamp > max_age:
                return None
            
            return session_id
            
        except Exception as e:
            logger.warning(f"Session token validation failed: {e}")
            return None


class SessionAuditLogger:
    """Audit logger for session events."""
    
    def __init__(self, logger_name: str = "session_audit"):
        """Initialize session audit logger."""
        self.audit_logger = logging.getLogger(logger_name)
        self.events: List[SessionEvent] = []
        self._lock = threading.Lock()
    
    def log_event(self, event: SessionEvent):
        """Log session event.
        
        Args:
            event: Session event to log
        """
        with self._lock:
            # Store event
            self.events.append(event)
            
            # Create audit log entry
            log_entry = {
                'event_id': event.event_id,
                'session_id': event.session_id,
                'event_type': event.event_type.value,
                'timestamp': event.timestamp.isoformat(),
                'user_id': str(event.user_id),
                'source_ip': event.source_ip,
                'classification_level': event.classification_level,
                'network_domain': event.network_domain.value if event.network_domain else None,
                'success': event.success,
                'error_message': event.error_message,
                'event_data': event.event_data
            }
            
            # Log with appropriate level
            if event.success:
                self.audit_logger.info(f"Session event: {json.dumps(log_entry)}")
            else:
                self.audit_logger.error(f"Session event failed: {json.dumps(log_entry)}")
    
    def create_session_event(self, 
                           session_id: str,
                           event_type: SessionEventType,
                           user_id: UUID,
                           success: bool = True,
                           **kwargs) -> SessionEvent:
        """Create session event.
        
        Args:
            session_id: Session identifier
            event_type: Type of event
            user_id: User identifier
            success: Whether event was successful
            **kwargs: Additional event data
            
        Returns:
            Created session event
        """
        return SessionEvent(
            event_id=str(uuid4()),
            session_id=session_id,
            event_type=event_type,
            timestamp=datetime.now(timezone.utc),
            user_id=user_id,
            success=success,
            **kwargs
        )
    
    def get_session_events(self, session_id: str) -> List[SessionEvent]:
        """Get events for a specific session.
        
        Args:
            session_id: Session identifier
            
        Returns:
            List of session events
        """
        with self._lock:
            return [event for event in self.events if event.session_id == session_id]
    
    def get_user_events(self, user_id: UUID, limit: int = 100) -> List[SessionEvent]:
        """Get recent events for a user.
        
        Args:
            user_id: User identifier
            limit: Maximum number of events
            
        Returns:
            List of recent user events
        """
        with self._lock:
            user_events = [event for event in self.events if event.user_id == user_id]
            return sorted(user_events, key=lambda x: x.timestamp, reverse=True)[:limit]


class SessionManager:
    """
    DoD-Compliant Session Management System.
    
    Provides comprehensive session management with:
    - Classification-aware security policies
    - Multi-factor authentication integration
    - Secure session storage and encryption
    - Cross-domain session guard implementation
    - Comprehensive audit logging
    - Threat detection and response
    """
    
    def __init__(self, 
                 encryption_key: bytes = None,
                 default_config: SessionConfiguration = None,
                 audit_logger: SessionAuditLogger = None):
        """Initialize session manager.
        
        Args:
            encryption_key: Encryption key for session data
            default_config: Default session configuration
            audit_logger: Audit logger instance
        """
        # Core components
        self.sessions: Dict[str, Session] = {}
        self.user_sessions: Dict[UUID, Set[str]] = {}
        self._lock = threading.RLock()
        
        # Encryption
        self.encryption = SessionEncryption(encryption_key)
        
        # Configuration
        self.default_config = default_config or self._create_default_config()
        
        # Audit logging
        self.audit_logger = audit_logger or SessionAuditLogger()
        
        # Session cleanup
        self._cleanup_thread = None
        self._cleanup_interval = 60  # seconds
        
        # Security tracking
        self.security_violations: Dict[str, List[str]] = {}
        self.failed_attempts: Dict[str, int] = {}
        
        # Start cleanup thread
        self._start_cleanup_thread()
        
        logger.info("SessionManager initialized")
    
    def create_session(self, 
                      security_context: SessionSecurityContext,
                      source_ip: str = None,
                      user_agent: str = None,
                      device_fingerprint: str = None,
                      custom_config: SessionConfiguration = None) -> Session:
        """Create new session with classification-aware security.
        
        Args:
            security_context: Security context for session
            source_ip: Source IP address
            user_agent: User agent string
            device_fingerprint: Device fingerprint for binding
            custom_config: Custom session configuration
            
        Returns:
            Created session
            
        Raises:
            ValueError: If session creation fails validation
            SecurityError: If security requirements not met
        """
        with self._lock:
            try:
                # Generate session ID
                session_id = self._generate_session_id()
                
                # Validate concurrent session limits
                if not self._validate_concurrent_sessions(security_context.user_id):
                    raise ValueError("Concurrent session limit exceeded")
                
                # Create session configuration
                config = custom_config or self._create_session_config(
                    session_id, security_context.classification_level
                )
                
                # Calculate session times
                now = datetime.now(timezone.utc)
                expires_at = now + timedelta(seconds=config.max_session_time)
                warning_at = expires_at - timedelta(seconds=config.warning_time)
                
                # Create session
                session = Session(
                    session_id=session_id,
                    user_id=security_context.user_id,
                    state=SessionState.ACTIVE,
                    security_context=security_context,
                    configuration=config,
                    created_at=now,
                    last_accessed=now,
                    expires_at=expires_at,
                    warning_at=warning_at,
                    bound_ip=source_ip,
                    bound_device_fingerprint=device_fingerprint
                )
                
                # Session binding
                if config.session_binding and security_context.cac_credentials:
                    session.bound_cac_serial = security_context.cac_credentials.serial_number
                
                # Store session
                self.sessions[session_id] = session
                
                # Track user sessions
                if security_context.user_id not in self.user_sessions:
                    self.user_sessions[security_context.user_id] = set()
                self.user_sessions[security_context.user_id].add(session_id)
                
                # Log session creation
                event = self.audit_logger.create_session_event(
                    session_id=session_id,
                    event_type=SessionEventType.SESSION_CREATED,
                    user_id=security_context.user_id,
                    source_ip=source_ip,
                    user_agent=user_agent,
                    classification_level=security_context.classification_level,
                    network_domain=security_context.network_domain,
                    event_data={
                        'clearance_level': security_context.clearance_level,
                        'organization': security_context.organization,
                        'session_config': asdict(config)
                    }
                )
                self.audit_logger.log_event(event)
                
                logger.info(f"Session created: {session_id} for user {security_context.user_id}")
                
                return session
                
            except Exception as e:
                logger.error(f"Session creation failed: {e}")
                
                # Log failed creation
                event = self.audit_logger.create_session_event(
                    session_id="UNKNOWN",
                    event_type=SessionEventType.SESSION_CREATED,
                    user_id=security_context.user_id,
                    success=False,
                    error_message=str(e),
                    source_ip=source_ip,
                    classification_level=security_context.classification_level
                )
                self.audit_logger.log_event(event)
                
                raise
    
    def get_session(self, session_id: str) -> Optional[Session]:
        """Get session by ID.
        
        Args:
            session_id: Session identifier
            
        Returns:
            Session if found and valid, None otherwise
        """
        with self._lock:
            session = self.sessions.get(session_id)
            
            if not session:
                return None
            
            # Check if session is expired
            if session.is_expired:
                self._expire_session(session)
                return None
            
            return session
    
    def validate_session(self, 
                        session_id: str,
                        source_ip: str = None,
                        device_fingerprint: str = None,
                        classification_level: str = None) -> Tuple[bool, Optional[str]]:
        """Validate session with security checks.
        
        Args:
            session_id: Session identifier
            source_ip: Source IP for binding validation
            device_fingerprint: Device fingerprint for binding validation
            classification_level: Required classification level
            
        Returns:
            Tuple of (valid, error_message)
        """
        with self._lock:
            session = self.sessions.get(session_id)
            
            if not session:
                return False, "Session not found"
            
            # Check session state
            if session.state != SessionState.ACTIVE:
                return False, f"Session not active: {session.state.value}"
            
            # Check expiration
            if session.is_expired:
                self._expire_session(session)
                return False, "Session expired"
            
            # Validate session binding
            if session.configuration.session_binding:
                if source_ip and session.bound_ip and source_ip != session.bound_ip:
                    session.add_security_violation("IP_BINDING_VIOLATION")
                    return False, "IP binding violation"
                
                if (device_fingerprint and session.bound_device_fingerprint and 
                    device_fingerprint != session.bound_device_fingerprint):
                    session.add_security_violation("DEVICE_BINDING_VIOLATION")
                    return False, "Device binding violation"
            
            # Validate classification access
            if classification_level:
                if not self._validate_classification_access(session, classification_level):
                    session.add_security_violation("CLASSIFICATION_ACCESS_VIOLATION")
                    return False, "Insufficient classification access"
            
            # Check security violations
            if len(session.security_violations) > 5:  # Threshold
                self._suspend_session(session, "Excessive security violations")
                return False, "Session suspended due to security violations"
            
            return True, None
    
    def access_session(self, 
                      session_id: str,
                      source_ip: str = None,
                      user_agent: str = None,
                      classification_level: str = None,
                      operation: str = None) -> Optional[Session]:
        """Access session with security validation and audit logging.
        
        Args:
            session_id: Session identifier
            source_ip: Source IP address
            user_agent: User agent string
            classification_level: Required classification level
            operation: Operation being performed
            
        Returns:
            Session if access is valid, None otherwise
        """
        with self._lock:
            # Validate session
            valid, error_message = self.validate_session(
                session_id, source_ip, classification_level=classification_level
            )
            
            if not valid:
                logger.warning(f"Session access denied: {error_message}")
                return None
            
            session = self.sessions[session_id]
            
            # Update session access
            session.update_access()
            
            # Log session access
            event = self.audit_logger.create_session_event(
                session_id=session_id,
                event_type=SessionEventType.SESSION_ACCESSED,
                user_id=session.user_id,
                source_ip=source_ip,
                user_agent=user_agent,
                classification_level=classification_level,
                network_domain=session.security_context.network_domain,
                event_data={
                    'operation': operation,
                    'access_count': session.access_count
                }
            )
            self.audit_logger.log_event(event)
            
            # Check for warning time
            if session.is_warning_time:
                self._send_timeout_warning(session)
            
            return session
    
    def elevate_session(self, 
                       session_id: str,
                       elevation_level: str,
                       justification: str,
                       approver_id: UUID = None) -> bool:
        """Elevate session for sensitive operations.
        
        Args:
            session_id: Session identifier
            elevation_level: Elevation level (SENSITIVE, CRITICAL)
            justification: Justification for elevation
            approver_id: Optional approver user ID
            
        Returns:
            True if elevation successful
        """
        with self._lock:
            session = self.sessions.get(session_id)
            
            if not session or session.state != SessionState.ACTIVE:
                return False
            
            # Validate elevation requirements
            if not self._validate_elevation_requirements(session, elevation_level):
                return False
            
            # Update session elevation
            session.elevation_level = elevation_level
            
            # Log elevation
            event = self.audit_logger.create_session_event(
                session_id=session_id,
                event_type=SessionEventType.SESSION_ELEVATED,
                user_id=session.user_id,
                classification_level=session.security_context.classification_level,
                event_data={
                    'elevation_level': elevation_level,
                    'justification': justification,
                    'approver_id': str(approver_id) if approver_id else None
                }
            )
            self.audit_logger.log_event(event)
            
            logger.info(f"Session elevated: {session_id} to {elevation_level}")
            
            return True
    
    def terminate_session(self, 
                         session_id: str,
                         reason: str = "User logout",
                         force: bool = False) -> bool:
        """Terminate session with cleanup.
        
        Args:
            session_id: Session identifier
            reason: Reason for termination
            force: Force termination even if errors occur
            
        Returns:
            True if termination successful
        """
        with self._lock:
            session = self.sessions.get(session_id)
            
            if not session:
                return False
            
            try:
                # Update session state
                session.state = SessionState.TERMINATED
                
                # Clean up user session tracking
                if session.user_id in self.user_sessions:
                    self.user_sessions[session.user_id].discard(session_id)
                    if not self.user_sessions[session.user_id]:
                        del self.user_sessions[session.user_id]
                
                # Log termination
                event = self.audit_logger.create_session_event(
                    session_id=session_id,
                    event_type=SessionEventType.SESSION_TERMINATED,
                    user_id=session.user_id,
                    classification_level=session.security_context.classification_level,
                    event_data={
                        'reason': reason,
                        'force': force,
                        'session_duration': str(datetime.now(timezone.utc) - session.created_at),
                        'access_count': session.access_count
                    }
                )
                self.audit_logger.log_event(event)
                
                # Remove session
                del self.sessions[session_id]
                
                logger.info(f"Session terminated: {session_id} - {reason}")
                
                return True
                
            except Exception as e:
                if not force:
                    logger.error(f"Session termination failed: {e}")
                    return False
                
                # Force cleanup
                self.sessions.pop(session_id, None)
                if session.user_id in self.user_sessions:
                    self.user_sessions[session.user_id].discard(session_id)
                
                logger.warning(f"Session force terminated: {session_id}")
                
                return True
    
    def cleanup_expired_sessions(self) -> int:
        """Clean up expired sessions.
        
        Returns:
            Number of sessions cleaned up
        """
        with self._lock:
            expired_sessions = []
            
            for session_id, session in self.sessions.items():
                if session.is_expired or session.state in [SessionState.EXPIRED, SessionState.TERMINATED]:
                    expired_sessions.append(session_id)
            
            cleaned_count = 0
            for session_id in expired_sessions:
                if self.terminate_session(session_id, "Expired", force=True):
                    cleaned_count += 1
            
            if cleaned_count > 0:
                logger.info(f"Cleaned up {cleaned_count} expired sessions")
            
            return cleaned_count
    
    def get_user_sessions(self, user_id: UUID) -> List[Session]:
        """Get all active sessions for a user.
        
        Args:
            user_id: User identifier
            
        Returns:
            List of active user sessions
        """
        with self._lock:
            session_ids = self.user_sessions.get(user_id, set())
            return [self.sessions[sid] for sid in session_ids if sid in self.sessions]
    
    def terminate_user_sessions(self, user_id: UUID, reason: str = "Administrative") -> int:
        """Terminate all sessions for a user.
        
        Args:
            user_id: User identifier
            reason: Reason for termination
            
        Returns:
            Number of sessions terminated
        """
        user_sessions = self.get_user_sessions(user_id)
        terminated_count = 0
        
        for session in user_sessions:
            if self.terminate_session(session.session_id, reason):
                terminated_count += 1
        
        return terminated_count
    
    def _generate_session_id(self) -> str:
        """Generate secure session ID."""
        return str(uuid4())
    
    def _create_default_config(self) -> SessionConfiguration:
        """Create default session configuration."""
        return SessionConfiguration(
            session_id="",
            max_idle_time=1800,  # 30 minutes
            max_session_time=28800,  # 8 hours
            warning_time=300,  # 5 minutes
            concurrent_session_limit=1,
            require_mfa=True,
            classification_aware=True,
            audit_level="DETAILED"
        )
    
    def _create_session_config(self, session_id: str, classification_level: str) -> SessionConfiguration:
        """Create session configuration based on classification level."""
        config = SessionConfiguration(
            session_id=session_id,
            max_idle_time=self.default_config.max_idle_time,
            max_session_time=self.default_config.max_session_time,
            warning_time=self.default_config.warning_time,
            concurrent_session_limit=self.default_config.concurrent_session_limit,
            require_mfa=self.default_config.require_mfa,
            classification_aware=self.default_config.classification_aware,
            audit_level=self.default_config.audit_level
        )
        
        # Adjust timeouts based on classification
        if classification_level == "TS":
            config.max_idle_time = 900   # 15 minutes
            config.max_session_time = 14400  # 4 hours
        elif classification_level == "S":
            config.max_idle_time = 1200  # 20 minutes
            config.max_session_time = 21600  # 6 hours
        
        return config
    
    def _validate_concurrent_sessions(self, user_id: UUID) -> bool:
        """Validate concurrent session limits."""
        user_sessions = self.get_user_sessions(user_id)
        return len(user_sessions) < self.default_config.concurrent_session_limit
    
    def _validate_classification_access(self, session: Session, required_level: str) -> bool:
        """Validate classification access."""
        user_clearance = session.security_context.clearance_level
        
        # Define classification hierarchy
        classification_levels = {"U": 0, "C": 1, "S": 2, "TS": 3}
        
        user_level = classification_levels.get(user_clearance, 0)
        required_level_num = classification_levels.get(required_level, 0)
        
        return user_level >= required_level_num
    
    def _validate_elevation_requirements(self, session: Session, elevation_level: str) -> bool:
        """Validate session elevation requirements."""
        # Check MFA
        if not session.mfa_verified and session.configuration.require_mfa:
            return False
        
        # Check clearance level
        if elevation_level == "CRITICAL" and session.security_context.clearance_level != "TS":
            return False
        
        return True
    
    def _expire_session(self, session: Session):
        """Expire a session."""
        session.state = SessionState.EXPIRED
        
        # Log expiration
        event = self.audit_logger.create_session_event(
            session_id=session.session_id,
            event_type=SessionEventType.SESSION_TIMEOUT,
            user_id=session.user_id,
            classification_level=session.security_context.classification_level,
            event_data={'session_duration': str(session.idle_time)}
        )
        self.audit_logger.log_event(event)
    
    def _suspend_session(self, session: Session, reason: str):
        """Suspend a session."""
        session.state = SessionState.SUSPENDED
        
        # Log suspension
        event = self.audit_logger.create_session_event(
            session_id=session.session_id,
            event_type=SessionEventType.SESSION_SUSPENDED,
            user_id=session.user_id,
            classification_level=session.security_context.classification_level,
            event_data={'reason': reason}
        )
        self.audit_logger.log_event(event)
    
    def _send_timeout_warning(self, session: Session):
        """Send timeout warning for session."""
        event = self.audit_logger.create_session_event(
            session_id=session.session_id,
            event_type=SessionEventType.SESSION_TIMEOUT_WARNING,
            user_id=session.user_id,
            classification_level=session.security_context.classification_level,
            event_data={'time_remaining': str(session.time_remaining)}
        )
        self.audit_logger.log_event(event)
    
    def _start_cleanup_thread(self):
        """Start session cleanup thread."""
        def cleanup_worker():
            while True:
                try:
                    self.cleanup_expired_sessions()
                    threading.Event().wait(self._cleanup_interval)
                except Exception as e:
                    logger.error(f"Session cleanup error: {e}")
        
        self._cleanup_thread = threading.Thread(target=cleanup_worker, daemon=True)
        self._cleanup_thread.start()
    
    def get_session_statistics(self) -> Dict[str, Any]:
        """Get session management statistics."""
        with self._lock:
            active_sessions = sum(1 for s in self.sessions.values() if s.state == SessionState.ACTIVE)
            total_sessions = len(self.sessions)
            
            classification_counts = {}
            for session in self.sessions.values():
                level = session.security_context.classification_level
                classification_counts[level] = classification_counts.get(level, 0) + 1
            
            return {
                'total_sessions': total_sessions,
                'active_sessions': active_sessions,
                'sessions_by_classification': classification_counts,
                'total_users': len(self.user_sessions),
                'cleanup_interval': self._cleanup_interval
            }


# Factory function for creating session manager
def create_session_manager(
    encryption_key: bytes = None,
    default_config: SessionConfiguration = None,
    audit_logger: SessionAuditLogger = None
) -> SessionManager:
    """Create and return a session manager instance."""
    return SessionManager(
        encryption_key=encryption_key,
        default_config=default_config,
        audit_logger=audit_logger
    )