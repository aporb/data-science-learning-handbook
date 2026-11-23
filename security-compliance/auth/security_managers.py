#!/usr/bin/env python3
"""
Enhanced Security Management for CAC/PIV Integration
Implements secure PIN caching, session management, and audit logging
"""

import os
import json
import logging
import threading
import time
import hashlib
import secrets
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, asdict
from datetime import datetime, timezone, timedelta
from enum import Enum
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Configure logging
logger = logging.getLogger(__name__)

class AuditEventType(Enum):
    """Types of audit events"""
    AUTHENTICATION_ATTEMPT = "authentication_attempt"
    AUTHENTICATION_SUCCESS = "authentication_success"
    AUTHENTICATION_FAILURE = "authentication_failure"
    PIN_VERIFICATION = "pin_verification"
    PIN_CACHE_ACCESS = "pin_cache_access"
    SESSION_CREATED = "session_created"
    SESSION_EXPIRED = "session_expired"
    SESSION_TERMINATED = "session_terminated"
    CERTIFICATE_VALIDATION = "certificate_validation"
    REVOCATION_CHECK = "revocation_check"
    SIGNING_OPERATION = "signing_operation"
    MIDDLEWARE_DETECTION = "middleware_detection"
    SECURITY_VIOLATION = "security_violation"
    CONFIGURATION_CHANGE = "configuration_change"

@dataclass
class AuditEvent:
    """Audit event data structure"""
    event_type: AuditEventType
    timestamp: datetime
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    source_ip: Optional[str] = None
    user_agent: Optional[str] = None
    success: bool = True
    error_message: Optional[str] = None
    additional_data: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.additional_data is None:
            self.additional_data = {}

class SecurePINManager:
    """
    Secure PIN caching with encryption and timeout
    Implements DoD-compliant secure PIN management
    """
    
    def __init__(self, cache_timeout: int = 900, max_cache_entries: int = 10, 
                 enable_encryption: bool = True):
        """
        Initialize secure PIN manager
        
        Args:
            cache_timeout: PIN cache timeout in seconds (default 15 minutes)
            max_cache_entries: Maximum number of cached PINs
            enable_encryption: Whether to encrypt cached PINs
        """
        self.cache_timeout = cache_timeout
        self.max_cache_entries = max_cache_entries
        self.enable_encryption = enable_encryption
        self._pin_cache = {}
        self._cache_lock = threading.RLock()
        self._encryption_key = None
        self._salt = secrets.token_bytes(32)
        
        if enable_encryption:
            self._initialize_encryption()
        
        # Start cleanup thread
        self._cleanup_thread = threading.Thread(target=self._cleanup_expired_pins, daemon=True)
        self._cleanup_thread.start()
        
        logger.info(f"Secure PIN Manager initialized (timeout={cache_timeout}s, encrypted={enable_encryption})")
    
    def _initialize_encryption(self):
        """Initialize encryption for PIN storage"""
        try:
            # Derive encryption key from system entropy
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=self._salt,
                iterations=100000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(secrets.token_bytes(32)))
            self._encryption_key = Fernet(key)
            logger.debug("PIN encryption initialized")
        except Exception as e:
            logger.error(f"Failed to initialize PIN encryption: {e}")
            self.enable_encryption = False
    
    def cache_pin(self, card_identifier: str, pin: str, user_id: str = None) -> str:
        """
        Cache PIN securely with timeout
        
        Args:
            card_identifier: Unique identifier for the card/user
            pin: PIN to cache
            user_id: User identifier for audit trail
            
        Returns:
            Cache token for PIN retrieval
        """
        with self._cache_lock:
            try:
                # Generate unique cache token
                cache_token = secrets.token_urlsafe(32)
                
                # Encrypt PIN if encryption is enabled
                stored_pin = pin
                if self.enable_encryption and self._encryption_key:
                    stored_pin = self._encryption_key.encrypt(pin.encode()).decode()
                
                # Create cache entry
                cache_entry = {
                    'pin': stored_pin,
                    'encrypted': self.enable_encryption,
                    'created_at': time.time(),
                    'expires_at': time.time() + self.cache_timeout,
                    'card_identifier': card_identifier,
                    'access_count': 0,
                    'last_access': time.time()
                }
                
                # Check cache size limit
                if len(self._pin_cache) >= self.max_cache_entries:
                    self._evict_oldest_entry()

                self._pin_cache[cache_token] = cache_entry

                # Audit event
                AuditLogger.instance().log_event(AuditEvent(
                    event_type=AuditEventType.PIN_CACHE_ACCESS,
                    timestamp=datetime.now(timezone.utc),
                    user_id=user_id,
                    success=True,
                    additional_data={
                        'action': 'cache_pin',
                        'card_identifier': self._hash_identifier(card_identifier),
                        'cache_timeout': self.cache_timeout
                    }
                ))

                logger.debug(f"PIN cached for card {self._hash_identifier(card_identifier)}")
                return cache_token

            except Exception as e:
                logger.error(f"Failed to cache PIN: {e}")
                AuditLogger.instance().log_event(AuditEvent(
                    event_type=AuditEventType.SECURITY_VIOLATION,
                    timestamp=datetime.now(timezone.utc),
                    user_id=user_id,
                    success=False,
                    error_message=f"PIN caching failed: {str(e)}"
                ))
                raise

    def retrieve_pin(self, cache_token: str, user_id: str = None) -> Optional[str]:
        """
        Retrieve cached PIN using token

        Args:
            cache_token: Cache token returned by cache_pin
            user_id: User identifier for audit trail

        Returns:
            Decrypted PIN if valid and not expired, None otherwise
        """
        with self._cache_lock:
            try:
                cache_entry = self._pin_cache.get(cache_token)

                if not cache_entry:
                    logger.warning("Invalid PIN cache token")
                    AuditLogger.instance().log_event(AuditEvent(
                        event_type=AuditEventType.SECURITY_VIOLATION,
                        timestamp=datetime.now(timezone.utc),
                        user_id=user_id,
                        success=False,
                        error_message="Invalid PIN cache token"
                    ))
                    return None

                # Check expiration
                if time.time() > cache_entry['expires_at']:
                    logger.debug("PIN cache entry expired")
                    del self._pin_cache[cache_token]
                    AuditLogger.instance().log_event(AuditEvent(
                        event_type=AuditEventType.PIN_CACHE_ACCESS,
                        timestamp=datetime.now(timezone.utc),
                        user_id=user_id,
                        success=False,
                        error_message="PIN cache entry expired"
                    ))
                    return None

                # Update access statistics
                cache_entry['access_count'] += 1
                cache_entry['last_access'] = time.time()

                # Decrypt PIN if necessary
                pin = cache_entry['pin']
                if cache_entry['encrypted'] and self._encryption_key:
                    pin = self._encryption_key.decrypt(pin.encode()).decode()

                # Audit successful access
                AuditLogger.instance().log_event(AuditEvent(
                    event_type=AuditEventType.PIN_CACHE_ACCESS,
                    timestamp=datetime.now(timezone.utc),
                    user_id=user_id,
                    success=True,
                    additional_data={
                        'action': 'retrieve_pin',
                        'access_count': cache_entry['access_count']
                    }
                ))

                return pin

            except Exception as e:
                logger.error(f"Failed to retrieve PIN: {e}")
                AuditLogger.instance().log_event(AuditEvent(
                    event_type=AuditEventType.SECURITY_VIOLATION,
                    timestamp=datetime.now(timezone.utc),
                    user_id=user_id,
                    success=False,
                    error_message=f"PIN retrieval failed: {str(e)}"
                ))
                return None

    def invalidate_pin(self, cache_token: str, user_id: str = None):
        """Invalidate cached PIN"""
        with self._cache_lock:
            if cache_token in self._pin_cache:
                del self._pin_cache[cache_token]
                AuditLogger.instance().log_event(AuditEvent(
                    event_type=AuditEventType.PIN_CACHE_ACCESS,
                    timestamp=datetime.now(timezone.utc),
                    user_id=user_id,
                    success=True,
                    additional_data={'action': 'invalidate_pin'}
                ))
                logger.debug("PIN cache entry invalidated")

    def clear_all_pins(self, user_id: str = None):
        """Clear all cached PINs"""
        with self._cache_lock:
            count = len(self._pin_cache)
            self._pin_cache.clear()
            AuditLogger.instance().log_event(AuditEvent(
                event_type=AuditEventType.PIN_CACHE_ACCESS,
                timestamp=datetime.now(timezone.utc),
                user_id=user_id,
                success=True,
                additional_data={
                    'action': 'clear_all_pins',
                    'cleared_count': count
                }
            ))
            logger.info(f"Cleared {count} cached PINs")

    def _evict_oldest_entry(self):
        """Evict oldest cache entry when limit is reached"""
        if not self._pin_cache:
            return

        oldest_token = min(self._pin_cache.keys(),
                          key=lambda k: self._pin_cache[k]['created_at'])
        del self._pin_cache[oldest_token]
        logger.debug("Evicted oldest PIN cache entry")

    def _cleanup_expired_pins(self):
        """Background thread to cleanup expired PINs"""
        while True:
            try:
                time.sleep(60)  # Check every minute
                current_time = time.time()

                with self._cache_lock:
                    expired_tokens = [
                        token for token, entry in self._pin_cache.items()
                        if current_time > entry['expires_at']
                    ]

                    for token in expired_tokens:
                        del self._pin_cache[token]

                    if expired_tokens:
                        logger.debug(f"Cleaned up {len(expired_tokens)} expired PIN cache entries")

            except Exception as e:
                logger.error(f"Error in PIN cleanup thread: {e}")

    def _hash_identifier(self, identifier: str) -> str:
        """Hash identifier for privacy in logs"""
        return hashlib.sha256(identifier.encode()).hexdigest()[:16]

    def get_cache_stats(self) -> Dict[str, Any]:
        """Get PIN cache statistics"""
        with self._cache_lock:
            current_time = time.time()
            active_entries = sum(1 for entry in self._pin_cache.values()
                               if current_time <= entry['expires_at'])

            return {
                'total_entries': len(self._pin_cache),
                'active_entries': active_entries,
                'max_entries': self.max_cache_entries,
                'cache_timeout': self.cache_timeout,
                'encryption_enabled': self.enable_encryption
            }

class SessionManager:
    """
    Advanced session management with auto-logout and security monitoring
    """

    def __init__(self, default_timeout: int = 3600, max_sessions: int = 100):
        """
        Initialize session manager

        Args:
            default_timeout: Default session timeout in seconds
            max_sessions: Maximum concurrent sessions
        """
        self.default_timeout = default_timeout
        self.max_sessions = max_sessions
        self._sessions = {}
        self._session_lock = threading.RLock()

        # Start session cleanup thread
        self._cleanup_thread = threading.Thread(target=self._cleanup_expired_sessions, daemon=True)
        self._cleanup_thread.start()

        logger.info(f"Session Manager initialized (timeout={default_timeout}s, max_sessions={max_sessions})")

    def create_session(self, user_id: str, card_identifier: str,
                      timeout: Optional[int] = None,
                      metadata: Dict[str, Any] = None) -> str:
        """
        Create new authenticated session

        Args:
            user_id: User identifier
            card_identifier: Card/certificate identifier
            timeout: Custom session timeout
            metadata: Additional session metadata

        Returns:
            Session ID
        """
        with self._session_lock:
            # Check session limit
            if len(self._sessions) >= self.max_sessions:
                self._cleanup_expired_sessions()
                if len(self._sessions) >= self.max_sessions:
                    raise RuntimeError("Maximum number of sessions reached")

            session_id = secrets.token_urlsafe(32)
            session_timeout = timeout or self.default_timeout
            current_time = time.time()

            session_data = {
                'session_id': session_id,
                'user_id': user_id,
                'card_identifier': card_identifier,
                'created_at': current_time,
                'last_activity': current_time,
                'expires_at': current_time + session_timeout,
                'timeout': session_timeout,
                'is_active': True,
                'activity_count': 1,
                'metadata': metadata or {}
            }

            self._sessions[session_id] = session_data

            # Audit session creation
            AuditLogger.instance().log_event(AuditEvent(
                event_type=AuditEventType.SESSION_CREATED,
                timestamp=datetime.now(timezone.utc),
                user_id=user_id,
                session_id=session_id,
                success=True,
                additional_data={
                    'session_timeout': session_timeout,
                    'card_identifier': self._hash_identifier(card_identifier)
                }
            ))

            logger.info(f"Session created for user {user_id}: {session_id}")
            return session_id

    def validate_session(self, session_id: str) -> bool:
        """
        Validate session and update activity

        Args:
            session_id: Session ID to validate

        Returns:
            True if session is valid and active
        """
        with self._session_lock:
            session = self._sessions.get(session_id)

            if not session:
                return False

            current_time = time.time()

            # Check if session has expired
            if current_time > session['expires_at'] or not session['is_active']:
                self._terminate_session(session_id, reason="expired")
                return False

            # Update activity
            session['last_activity'] = current_time
            session['activity_count'] += 1

            return True

    def extend_session(self, session_id: str, additional_time: int = None) -> bool:
        """
        Extend session timeout

        Args:
            session_id: Session ID to extend
            additional_time: Additional time in seconds (default: original timeout)

        Returns:
            True if session was extended
        """
        with self._session_lock:
            session = self._sessions.get(session_id)

            if not session or not session['is_active']:
                return False

            extension = additional_time or session['timeout']
            session['expires_at'] = time.time() + extension

            AuditLogger.instance().log_event(AuditEvent(
                event_type=AuditEventType.SESSION_CREATED,  # Reusing for extension
                timestamp=datetime.now(timezone.utc),
                user_id=session['user_id'],
                session_id=session_id,
                success=True,
                additional_data={
                    'action': 'extend_session',
                    'extension_time': extension
                }
            ))

            logger.debug(f"Session {session_id} extended by {extension} seconds")
            return True

    def terminate_session(self, session_id: str, reason: str = "user_logout"):
        """
        Terminate session

        Args:
            session_id: Session ID to terminate
            reason: Reason for termination
        """
        self._terminate_session(session_id, reason)

    def _terminate_session(self, session_id: str, reason: str = "unknown"):
        """Internal session termination"""
        with self._session_lock:
            session = self._sessions.get(session_id)

            if session:
                session['is_active'] = False

                AuditLogger.instance().log_event(AuditEvent(
                    event_type=AuditEventType.SESSION_TERMINATED,
                    timestamp=datetime.now(timezone.utc),
                    user_id=session['user_id'],
                    session_id=session_id,
                    success=True,
                    additional_data={
                        'reason': reason,
                        'duration': time.time() - session['created_at'],
                        'activity_count': session['activity_count']
                    }
                ))

                # Remove from active sessions after audit
                del self._sessions[session_id]

                logger.info(f"Session terminated: {session_id} (reason: {reason})")

    def get_session_info(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Get session information"""
        with self._session_lock:
            session = self._sessions.get(session_id)
            if session:
                return session.copy()
            return None

    def get_user_sessions(self, user_id: str) -> List[str]:
        """Get all active sessions for user"""
        with self._session_lock:
            return [
                session_id for session_id, session in self._sessions.items()
                if session['user_id'] == user_id and session['is_active']
            ]

    def terminate_user_sessions(self, user_id: str, reason: str = "admin_action"):
        """Terminate all sessions for specific user"""
        user_sessions = self.get_user_sessions(user_id)
        for session_id in user_sessions:
            self._terminate_session(session_id, reason)

        logger.info(f"Terminated {len(user_sessions)} sessions for user {user_id}")

    def _cleanup_expired_sessions(self):
        """Cleanup expired sessions"""
        current_time = time.time()
        expired_sessions = []

        with self._session_lock:
            for session_id, session in list(self._sessions.items()):
                if current_time > session['expires_at']:
                    expired_sessions.append(session_id)

            for session_id in expired_sessions:
                self._terminate_session(session_id, "expired")

        if expired_sessions:
            logger.debug(f"Cleaned up {len(expired_sessions)} expired sessions")

    def _hash_identifier(self, identifier: str) -> str:
        """Hash identifier for privacy in logs"""
        return hashlib.sha256(identifier.encode()).hexdigest()[:16]

    def get_session_stats(self) -> Dict[str, Any]:
        """Get session statistics"""
        with self._session_lock:
            current_time = time.time()
            active_sessions = sum(1 for s in self._sessions.values()
                                if s['is_active'] and current_time <= s['expires_at'])

            return {
                'total_sessions': len(self._sessions),
                'active_sessions': active_sessions,
                'max_sessions': self.max_sessions,
                'default_timeout': self.default_timeout
            }

class AuditLogger:
    """
    Comprehensive audit logging for authentication events
    Implements DoD-compliant audit trail
    """

    _instance = None
    _lock = threading.Lock()

    def __new__(cls, *args, **kwargs):
        """Singleton pattern for audit logger"""
        if not cls._instance:
            with cls._lock:
                if not cls._instance:
                    cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self, log_file_path: str = None, max_log_size: int = 100_000_000,
                 backup_count: int = 10, enable_syslog: bool = False):
        """
        Initialize audit logger

        Args:
            log_file_path: Path to audit log file
            max_log_size: Maximum log file size in bytes
            backup_count: Number of backup log files to keep
            enable_syslog: Whether to also log to syslog
        """
        if hasattr(self, '_initialized'):
            return

        self.log_file_path = log_file_path or os.path.expanduser("~/.cac/audit.log")
        self.max_log_size = max_log_size
        self.backup_count = backup_count
        self.enable_syslog = enable_syslog

        # Create log directory
        os.makedirs(os.path.dirname(self.log_file_path), exist_ok=True)

        # Setup file handler with rotation
        from logging.handlers import RotatingFileHandler
        self.file_handler = RotatingFileHandler(
            self.log_file_path,
            maxBytes=max_log_size,
            backupCount=backup_count
        )

        # Setup formatter
        formatter = logging.Formatter(
            '%(asctime)s - AUDIT - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S UTC'
        )
        self.file_handler.setFormatter(formatter)

        # Setup audit logger
        self.audit_logger = logging.getLogger('cac_audit')
        self.audit_logger.setLevel(logging.INFO)
        self.audit_logger.addHandler(self.file_handler)

        # Setup syslog if enabled
        if enable_syslog:
            try:
                from logging.handlers import SysLogHandler
                syslog_handler = SysLogHandler(address='/dev/log')
                syslog_handler.setFormatter(formatter)
                self.audit_logger.addHandler(syslog_handler)
            except Exception as e:
                logger.warning(f"Failed to setup syslog: {e}")

        self._initialized = True
        logger.info(f"Audit Logger initialized: {self.log_file_path}")

    @classmethod
    def instance(cls):
        """Get singleton instance"""
        if not cls._instance:
            cls()
        return cls._instance

    def log_event(self, event: AuditEvent):
        """
        Log audit event

        Args:
            event: AuditEvent to log
        """
        try:
            # Convert event to JSON
            event_dict = {
                'event_type': event.event_type.value,
                'timestamp': event.timestamp.isoformat(),
                'user_id': event.user_id,
                'session_id': event.session_id,
                'source_ip': event.source_ip,
                'user_agent': event.user_agent,
                'success': event.success,
                'error_message': event.error_message,
                'additional_data': event.additional_data
            }

            # Remove None values
            event_dict = {k: v for k, v in event_dict.items() if v is not None}

            # Log as JSON
            log_message = json.dumps(event_dict, separators=(',', ':'))

            if event.success:
                self.audit_logger.info(log_message)
            else:
                self.audit_logger.warning(log_message)

        except Exception as e:
            logger.error(f"Failed to log audit event: {e}")

    def log_authentication_attempt(self, user_id: str, card_identifier: str,
                                 success: bool, error_message: str = None,
                                 session_id: str = None, source_ip: str = None):
        """Log authentication attempt"""
        event_type = AuditEventType.AUTHENTICATION_SUCCESS if success else AuditEventType.AUTHENTICATION_FAILURE

        self.log_event(AuditEvent(
            event_type=event_type,
            timestamp=datetime.now(timezone.utc),
            user_id=user_id,
            session_id=session_id,
            source_ip=source_ip,
            success=success,
            error_message=error_message,
            additional_data={
                'card_identifier': hashlib.sha256(card_identifier.encode()).hexdigest()[:16]
            }
        ))

    def log_certificate_validation(self, certificate_subject: str, issuer: str,
                                 validation_result: bool, details: Dict[str, Any] = None):
        """Log certificate validation"""
        self.log_event(AuditEvent(
            event_type=AuditEventType.CERTIFICATE_VALIDATION,
            timestamp=datetime.now(timezone.utc),
            success=validation_result,
            additional_data={
                'certificate_subject': certificate_subject,
                'issuer': issuer,
                'validation_details': details or {}
            }
        ))

    def log_signing_operation(self, user_id: str, data_hash: str,
                            success: bool, session_id: str = None):
        """Log digital signing operation"""
        self.log_event(AuditEvent(
            event_type=AuditEventType.SIGNING_OPERATION,
            timestamp=datetime.now(timezone.utc),
            user_id=user_id,
            session_id=session_id,
            success=success,
            additional_data={
                'data_hash': data_hash
            }
        ))

    def get_audit_stats(self) -> Dict[str, Any]:
        """Get audit logging statistics"""
        stats = {
            'log_file_path': self.log_file_path,
            'max_log_size': self.max_log_size,
            'backup_count': self.backup_count,
            'syslog_enabled': self.enable_syslog
        }

        # Get log file size
        try:
            if os.path.exists(self.log_file_path):
                stats['current_log_size'] = os.path.getsize(self.log_file_path)
            else:
                stats['current_log_size'] = 0
        except Exception:
            stats['current_log_size'] = 0

        return stats
