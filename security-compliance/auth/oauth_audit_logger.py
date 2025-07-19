"""
Enhanced OAuth Audit Logging System
Extends the existing audit logging with OAuth-specific events and compliance features.
"""

import json
import logging
import threading
import time
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, asdict
from datetime import datetime, timezone, timedelta
from enum import Enum
from pathlib import Path
import sqlite3
import hashlib
from urllib.parse import urlparse

# Import base audit components
from .security_managers import AuditLogger, AuditEvent, AuditEventType

# Import OAuth components for type hints
from .oauth_client import Platform, TokenResponse

logger = logging.getLogger(__name__)


class OAuthAuditEventType(Enum):
    """OAuth-specific audit event types."""
    # OAuth Flow Events
    OAUTH_AUTHORIZATION_REQUEST = "oauth_authorization_request"
    OAUTH_AUTHORIZATION_CALLBACK = "oauth_authorization_callback"
    OAUTH_TOKEN_EXCHANGE = "oauth_token_exchange"
    OAUTH_TOKEN_REFRESH = "oauth_token_refresh"
    OAUTH_TOKEN_REVOCATION = "oauth_token_revocation"
    OAUTH_CLIENT_CREDENTIALS = "oauth_client_credentials"
    
    # Token Management Events
    TOKEN_STORAGE = "token_storage"
    TOKEN_RETRIEVAL = "token_retrieval"
    TOKEN_DELETION = "token_deletion"
    TOKEN_CLEANUP = "token_cleanup"
    TOKEN_ENCRYPTION = "token_encryption"
    TOKEN_DECRYPTION = "token_decryption"
    
    # Security Events
    TOKEN_HIJACKING_ATTEMPT = "token_hijacking_attempt"
    SUSPICIOUS_TOKEN_USAGE = "suspicious_token_usage"
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
    INVALID_STATE_PARAMETER = "invalid_state_parameter"
    PKCE_VALIDATION_FAILURE = "pkce_validation_failure"
    
    # Integration Events
    CAC_OAUTH_BINDING = "cac_oauth_binding"
    DUAL_FACTOR_AUTHENTICATION = "dual_factor_authentication"
    SESSION_ELEVATION = "session_elevation"
    CLEARANCE_VALIDATION = "clearance_validation"
    
    # Platform Events
    PLATFORM_API_CALL = "platform_api_call"
    PLATFORM_ERROR = "platform_error"
    PLATFORM_RATE_LIMIT = "platform_rate_limit"
    
    # Compliance Events
    DATA_ACCESS_AUDIT = "data_access_audit"
    EXPORT_CONTROL_CHECK = "export_control_check"
    CLASSIFICATION_VIOLATION = "classification_violation"


@dataclass
class OAuthAuditEvent:
    """Enhanced OAuth audit event with additional context."""
    event_type: Union[AuditEventType, OAuthAuditEventType]
    timestamp: datetime
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    platform: Optional[str] = None
    client_id: Optional[str] = None
    scopes: Optional[List[str]] = None
    
    # Network context
    source_ip: Optional[str] = None
    user_agent: Optional[str] = None
    request_id: Optional[str] = None
    
    # OAuth-specific context
    authorization_code: Optional[str] = None  # Hashed for security
    state_parameter: Optional[str] = None     # Hashed for security
    token_id: Optional[str] = None
    token_type: Optional[str] = None
    grant_type: Optional[str] = None
    
    # CAC integration context
    edipi: Optional[str] = None
    clearance_level: Optional[str] = None
    cac_certificate_subject: Optional[str] = None
    
    # Security context
    threat_level: str = "LOW"  # LOW, MEDIUM, HIGH, CRITICAL
    
    # Result context
    success: bool = True
    error_code: Optional[str] = None
    error_message: Optional[str] = None
    
    # Additional data
    additional_data: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.additional_data is None:
            self.additional_data = {}
        
        # Hash sensitive parameters
        if self.authorization_code:
            self.authorization_code = self._hash_sensitive_data(self.authorization_code)
        if self.state_parameter:
            self.state_parameter = self._hash_sensitive_data(self.state_parameter)
    
    def _hash_sensitive_data(self, data: str) -> str:
        """Hash sensitive data for audit logging."""
        return hashlib.sha256(data.encode()).hexdigest()[:16]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for storage."""
        data = asdict(self)
        # Convert datetime to ISO format
        data['timestamp'] = self.timestamp.isoformat()
        # Convert enum to string
        if hasattr(self.event_type, 'value'):
            data['event_type'] = self.event_type.value
        return data
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'OAuthAuditEvent':
        """Create from dictionary."""
        # Convert ISO string to datetime
        data['timestamp'] = datetime.fromisoformat(data['timestamp'])
        # Convert string to enum
        event_type_str = data['event_type']
        try:
            data['event_type'] = OAuthAuditEventType(event_type_str)
        except ValueError:
            data['event_type'] = AuditEventType(event_type_str)
        return cls(**data)


class OAuthComplianceChecker:
    """
    OAuth compliance checker for DoD requirements.
    
    Validates OAuth operations against DoD security policies
    and generates compliance audit events.
    """
    
    # DoD-approved OAuth scopes by classification level
    APPROVED_SCOPES = {
        "UNCLASSIFIED": [
            "openid", "profile", "email",
            "read:basic", "write:basic",
            "admin:basic"
        ],
        "CONFIDENTIAL": [
            "openid", "profile", "email",
            "read:classified", "write:classified"
        ],
        "SECRET": [
            "openid", "profile", "email",
            "read:secret", "write:secret"
        ],
        "TOP_SECRET": [
            "openid", "profile", "email",
            "read:topsecret"
        ]
    }
    
    # Suspicious patterns
    SUSPICIOUS_PATTERNS = [
        r".*javascript:",  # XSS attempts
        r".*<script",      # Script injection
        r".*\.\./",        # Path traversal
        r".*eval\(",       # Code evaluation
        r".*system\(",     # System commands
    ]
    
    def __init__(self):
        self.blocked_ips = set()
        self.suspicious_users = set()
        self._lock = threading.Lock()
    
    def validate_scopes(self, requested_scopes: List[str], 
                       clearance_level: str) -> List[str]:
        """
        Validate requested scopes against clearance level.
        
        Args:
            requested_scopes: Requested OAuth scopes
            clearance_level: User's security clearance
            
        Returns:
            List of approved scopes
        """
        approved_scopes = self.APPROVED_SCOPES.get(clearance_level.upper(), [])
        validated_scopes = []
        
        for scope in requested_scopes:
            if scope in approved_scopes:
                validated_scopes.append(scope)
            else:
                logger.warning(f"Scope '{scope}' not approved for clearance level '{clearance_level}'")
        
        return validated_scopes
    
    def check_suspicious_activity(self, event: OAuthAuditEvent) -> str:
        """
        Check for suspicious OAuth activity.
        
        Args:
            event: OAuth audit event to check
            
        Returns:
            Threat level assessment
        """
        threat_level = "LOW"
        
        # Check for suspicious patterns in request data
        import re
        for pattern in self.SUSPICIOUS_PATTERNS:
            for field in [event.authorization_code, event.state_parameter]:
                if field and re.match(pattern, field, re.IGNORECASE):
                    threat_level = "HIGH"
                    break
        
        # Check for unusual token usage patterns
        if event.event_type == OAuthAuditEventType.TOKEN_RETRIEVAL:
            # Check access frequency
            if self._check_rapid_access(event.user_id, event.token_id):
                threat_level = max(threat_level, "MEDIUM")
        
        # Check for IP address changes
        if self._check_ip_change(event.user_id, event.source_ip):
            threat_level = max(threat_level, "MEDIUM")
        
        return threat_level
    
    def _check_rapid_access(self, user_id: str, token_id: str) -> bool:
        """Check for rapid token access patterns."""
        # Implementation would check recent access history
        # For now, return False as placeholder
        return False
    
    def _check_ip_change(self, user_id: str, source_ip: str) -> bool:
        """Check for suspicious IP address changes."""
        # Implementation would check IP history
        # For now, return False as placeholder
        return False


class EnhancedOAuthAuditLogger:
    """
    Enhanced OAuth audit logger with DoD compliance features.
    
    Extends the base audit logger with OAuth-specific logging,
    real-time threat detection, and compliance reporting.
    """
    
    _instance = None
    _lock = threading.Lock()
    
    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self):
        if not hasattr(self, '_initialized'):
            self.base_logger = AuditLogger.instance()
            self.compliance_checker = OAuthComplianceChecker()
            
            # OAuth-specific storage
            self.oauth_events: List[OAuthAuditEvent] = []
            self.events_lock = threading.RLock()
            
            # Real-time monitoring
            self.threat_handlers: List[Callable] = []
            self.compliance_handlers: List[Callable] = []
            
            # Database storage for OAuth events
            self._init_oauth_audit_db()
            
            self._initialized = True
            logger.info("Enhanced OAuth audit logger initialized")
    
    def _init_oauth_audit_db(self):
        """Initialize OAuth audit database."""
        try:
            # Create audit directory
            audit_dir = Path.home() / ".dod_oauth_audit"
            audit_dir.mkdir(exist_ok=True, mode=0o700)
            
            self.db_path = audit_dir / "oauth_audit.db"
            
            # Create database
            conn = sqlite3.connect(self.db_path)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS oauth_audit_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_type TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    user_id TEXT,
                    session_id TEXT,
                    platform TEXT,
                    client_id TEXT,
                    scopes TEXT,
                    source_ip TEXT,
                    user_agent TEXT,
                    request_id TEXT,
                    authorization_code_hash TEXT,
                    state_parameter_hash TEXT,
                    token_id TEXT,
                    token_type TEXT,
                    grant_type TEXT,
                    edipi TEXT,
                    clearance_level TEXT,
                    cac_certificate_subject TEXT,
                    threat_level TEXT DEFAULT 'LOW',
                    success BOOLEAN DEFAULT TRUE,
                    error_code TEXT,
                    error_message TEXT,
                    additional_data TEXT
                )
            """)
            
            # Create indexes
            conn.execute("CREATE INDEX IF NOT EXISTS idx_oauth_timestamp ON oauth_audit_events(timestamp)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_oauth_user_id ON oauth_audit_events(user_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_oauth_platform ON oauth_audit_events(platform)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_oauth_threat_level ON oauth_audit_events(threat_level)")
            
            conn.commit()
            conn.close()
            
            logger.info(f"OAuth audit database initialized: {self.db_path}")
            
        except Exception as e:
            logger.error(f"Failed to initialize OAuth audit database: {e}")
    
    @classmethod
    def instance(cls) -> 'EnhancedOAuthAuditLogger':
        """Get singleton instance."""
        return cls()
    
    def log_oauth_event(self, event: OAuthAuditEvent):
        """
        Log OAuth audit event with compliance checking.
        
        Args:
            event: OAuth audit event to log
        """
        with self.events_lock:
            try:
                # Perform compliance checking
                event.threat_level = self.compliance_checker.check_suspicious_activity(event)
                
                # Store in memory
                self.oauth_events.append(event)
                
                # Store in database
                self._store_oauth_event_db(event)
                
                # Also log to base audit logger
                base_event = AuditEvent(
                    event_type=AuditEventType.AUTHENTICATION_ATTEMPT if event.event_type in [
                        OAuthAuditEventType.OAUTH_AUTHORIZATION_REQUEST,
                        OAuthAuditEventType.OAUTH_TOKEN_EXCHANGE
                    ] else AuditEventType.SECURITY_VIOLATION,
                    timestamp=event.timestamp,
                    user_id=event.user_id,
                    session_id=event.session_id,
                    source_ip=event.source_ip,
                    user_agent=event.user_agent,
                    success=event.success,
                    error_message=event.error_message,
                    additional_data={
                        "oauth_event_type": event.event_type.value,
                        "platform": event.platform,
                        "threat_level": event.threat_level,
                        **event.additional_data
                    }
                )
                self.base_logger.log_event(base_event)
                
                # Trigger threat handlers if high threat level
                if event.threat_level in ["HIGH", "CRITICAL"]:
                    self._trigger_threat_handlers(event)
                
                logger.debug(f"OAuth audit event logged: {event.event_type.value}")
                
            except Exception as e:
                logger.error(f"Failed to log OAuth audit event: {e}")
    
    def _store_oauth_event_db(self, event: OAuthAuditEvent):
        """Store OAuth event in database."""
        try:
            conn = sqlite3.connect(self.db_path)
            
            # Convert scopes list to JSON string
            scopes_json = json.dumps(event.scopes) if event.scopes else None
            additional_data_json = json.dumps(event.additional_data) if event.additional_data else None
            
            conn.execute("""
                INSERT INTO oauth_audit_events (
                    event_type, timestamp, user_id, session_id, platform, client_id,
                    scopes, source_ip, user_agent, request_id, authorization_code_hash,
                    state_parameter_hash, token_id, token_type, grant_type, edipi,
                    clearance_level, cac_certificate_subject, threat_level, success,
                    error_code, error_message, additional_data
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                event.event_type.value,
                event.timestamp.isoformat(),
                event.user_id,
                event.session_id,
                event.platform,
                event.client_id,
                scopes_json,
                event.source_ip,
                event.user_agent,
                event.request_id,
                event.authorization_code,
                event.state_parameter,
                event.token_id,
                event.token_type,
                event.grant_type,
                event.edipi,
                event.clearance_level,
                event.cac_certificate_subject,
                event.threat_level,
                event.success,
                event.error_code,
                event.error_message,
                additional_data_json
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"Failed to store OAuth event in database: {e}")
    
    def log_oauth_authorization_request(self, user_id: str, platform: Platform,
                                      client_id: str, scopes: List[str],
                                      state: str, source_ip: str = None,
                                      **kwargs):
        """Log OAuth authorization request."""
        event = OAuthAuditEvent(
            event_type=OAuthAuditEventType.OAUTH_AUTHORIZATION_REQUEST,
            timestamp=datetime.now(timezone.utc),
            user_id=user_id,
            platform=platform.value,
            client_id=client_id,
            scopes=scopes,
            state_parameter=state,
            source_ip=source_ip,
            additional_data=kwargs
        )
        self.log_oauth_event(event)
    
    def log_token_exchange(self, user_id: str, platform: Platform,
                          authorization_code: str, success: bool,
                          token_id: str = None, error_message: str = None,
                          **kwargs):
        """Log OAuth token exchange."""
        event = OAuthAuditEvent(
            event_type=OAuthAuditEventType.OAUTH_TOKEN_EXCHANGE,
            timestamp=datetime.now(timezone.utc),
            user_id=user_id,
            platform=platform.value,
            authorization_code=authorization_code,
            token_id=token_id,
            success=success,
            error_message=error_message,
            additional_data=kwargs
        )
        self.log_oauth_event(event)
    
    def log_token_refresh(self, user_id: str, platform: Platform,
                         old_token_id: str, new_token_id: str = None,
                         success: bool = True, error_message: str = None,
                         **kwargs):
        """Log OAuth token refresh."""
        event = OAuthAuditEvent(
            event_type=OAuthAuditEventType.OAUTH_TOKEN_REFRESH,
            timestamp=datetime.now(timezone.utc),
            user_id=user_id,
            platform=platform.value,
            token_id=old_token_id,
            success=success,
            error_message=error_message,
            additional_data={
                "old_token_id": old_token_id,
                "new_token_id": new_token_id,
                **kwargs
            }
        )
        self.log_oauth_event(event)
    
    def log_cac_oauth_binding(self, user_id: str, edipi: str,
                            platform: Platform, clearance_level: str,
                            certificate_subject: str, success: bool,
                            **kwargs):
        """Log CAC-OAuth binding event."""
        event = OAuthAuditEvent(
            event_type=OAuthAuditEventType.CAC_OAUTH_BINDING,
            timestamp=datetime.now(timezone.utc),
            user_id=user_id,
            platform=platform.value,
            edipi=edipi,
            clearance_level=clearance_level,
            cac_certificate_subject=certificate_subject,
            success=success,
            additional_data=kwargs
        )
        self.log_oauth_event(event)
    
    def log_rate_limit_exceeded(self, user_id: str, platform: Platform,
                              limit_type: str, current_count: int,
                              limit_value: int, **kwargs):
        """Log rate limit exceeded event."""
        event = OAuthAuditEvent(
            event_type=OAuthAuditEventType.RATE_LIMIT_EXCEEDED,
            timestamp=datetime.now(timezone.utc),
            user_id=user_id,
            platform=platform.value,
            threat_level="MEDIUM",
            success=False,
            additional_data={
                "limit_type": limit_type,
                "current_count": current_count,
                "limit_value": limit_value,
                **kwargs
            }
        )
        self.log_oauth_event(event)
    
    def log_suspicious_activity(self, user_id: str, activity_type: str,
                              threat_level: str, description: str,
                              **kwargs):
        """Log suspicious OAuth activity."""
        event = OAuthAuditEvent(
            event_type=OAuthAuditEventType.SUSPICIOUS_TOKEN_USAGE,
            timestamp=datetime.now(timezone.utc),
            user_id=user_id,
            threat_level=threat_level,
            success=False,
            error_message=description,
            additional_data={
                "activity_type": activity_type,
                **kwargs
            }
        )
        self.log_oauth_event(event)
    
    def add_threat_handler(self, handler: Callable[[OAuthAuditEvent], None]):
        """Add handler for high-threat events."""
        self.threat_handlers.append(handler)
    
    def _trigger_threat_handlers(self, event: OAuthAuditEvent):
        """Trigger registered threat handlers."""
        for handler in self.threat_handlers:
            try:
                handler(event)
            except Exception as e:
                logger.error(f"Threat handler error: {e}")
    
    def generate_compliance_report(self, start_date: datetime, 
                                 end_date: datetime) -> Dict[str, Any]:
        """
        Generate OAuth compliance report.
        
        Args:
            start_date: Report start date
            end_date: Report end date
            
        Returns:
            Compliance report dictionary
        """
        try:
            conn = sqlite3.connect(self.db_path)
            
            # Total events
            cursor = conn.execute("""
                SELECT COUNT(*) FROM oauth_audit_events 
                WHERE timestamp BETWEEN ? AND ?
            """, (start_date.isoformat(), end_date.isoformat()))
            total_events = cursor.fetchone()[0]
            
            # Events by type
            cursor = conn.execute("""
                SELECT event_type, COUNT(*) FROM oauth_audit_events 
                WHERE timestamp BETWEEN ? AND ?
                GROUP BY event_type
            """, (start_date.isoformat(), end_date.isoformat()))
            events_by_type = dict(cursor.fetchall())
            
            # Threat level distribution
            cursor = conn.execute("""
                SELECT threat_level, COUNT(*) FROM oauth_audit_events 
                WHERE timestamp BETWEEN ? AND ?
                GROUP BY threat_level
            """, (start_date.isoformat(), end_date.isoformat()))
            threat_distribution = dict(cursor.fetchall())
            
            # Platform usage
            cursor = conn.execute("""
                SELECT platform, COUNT(*) FROM oauth_audit_events 
                WHERE timestamp BETWEEN ? AND ? AND platform IS NOT NULL
                GROUP BY platform
            """, (start_date.isoformat(), end_date.isoformat()))
            platform_usage = dict(cursor.fetchall())
            
            # Failed events
            cursor = conn.execute("""
                SELECT COUNT(*) FROM oauth_audit_events 
                WHERE timestamp BETWEEN ? AND ? AND success = FALSE
            """, (start_date.isoformat(), end_date.isoformat()))
            failed_events = cursor.fetchone()[0]
            
            conn.close()
            
            return {
                "report_period": {
                    "start_date": start_date.isoformat(),
                    "end_date": end_date.isoformat()
                },
                "summary": {
                    "total_events": total_events,
                    "failed_events": failed_events,
                    "success_rate": (total_events - failed_events) / max(1, total_events) * 100
                },
                "event_breakdown": events_by_type,
                "threat_analysis": threat_distribution,
                "platform_usage": platform_usage,
                "generated_at": datetime.now(timezone.utc).isoformat()
            }
            
        except Exception as e:
            logger.error(f"Failed to generate compliance report: {e}")
            return {"error": str(e)}
    
    def query_events(self, filters: Dict[str, Any], 
                    limit: int = 100) -> List[OAuthAuditEvent]:
        """
        Query OAuth audit events with filters.
        
        Args:
            filters: Query filters
            limit: Maximum number of results
            
        Returns:
            List of matching events
        """
        try:
            conn = sqlite3.connect(self.db_path)
            
            # Build query
            where_clauses = []
            params = []
            
            if 'user_id' in filters:
                where_clauses.append("user_id = ?")
                params.append(filters['user_id'])
            
            if 'platform' in filters:
                where_clauses.append("platform = ?")
                params.append(filters['platform'])
            
            if 'threat_level' in filters:
                where_clauses.append("threat_level = ?")
                params.append(filters['threat_level'])
            
            if 'start_date' in filters:
                where_clauses.append("timestamp >= ?")
                params.append(filters['start_date'].isoformat())
            
            if 'end_date' in filters:
                where_clauses.append("timestamp <= ?")
                params.append(filters['end_date'].isoformat())
            
            where_clause = " WHERE " + " AND ".join(where_clauses) if where_clauses else ""
            
            query = f"""
                SELECT * FROM oauth_audit_events
                {where_clause}
                ORDER BY timestamp DESC
                LIMIT ?
            """
            params.append(limit)
            
            cursor = conn.execute(query, params)
            rows = cursor.fetchall()
            
            # Convert to OAuthAuditEvent objects
            events = []
            columns = [desc[0] for desc in cursor.description]
            
            for row in rows:
                event_data = dict(zip(columns, row))
                
                # Convert back from storage format
                event_data['timestamp'] = datetime.fromisoformat(event_data['timestamp'])
                if event_data['scopes']:
                    event_data['scopes'] = json.loads(event_data['scopes'])
                if event_data['additional_data']:
                    event_data['additional_data'] = json.loads(event_data['additional_data'])
                
                # Convert to enum
                try:
                    event_data['event_type'] = OAuthAuditEventType(event_data['event_type'])
                except ValueError:
                    event_data['event_type'] = AuditEventType(event_data['event_type'])
                
                # Remove database-specific fields
                event_data.pop('id', None)
                
                events.append(OAuthAuditEvent(**event_data))
            
            conn.close()
            return events
            
        except Exception as e:
            logger.error(f"Failed to query OAuth events: {e}")
            return []


# Convenience functions for common OAuth audit operations
def log_oauth_success(user_id: str, platform: Platform, event_type: str, **kwargs):
    """Log successful OAuth operation."""
    logger = EnhancedOAuthAuditLogger.instance()
    event = OAuthAuditEvent(
        event_type=OAuthAuditEventType(event_type),
        timestamp=datetime.now(timezone.utc),
        user_id=user_id,
        platform=platform.value,
        success=True,
        additional_data=kwargs
    )
    logger.log_oauth_event(event)


def log_oauth_failure(user_id: str, platform: Platform, event_type: str, 
                     error_message: str, **kwargs):
    """Log failed OAuth operation."""
    logger = EnhancedOAuthAuditLogger.instance()
    event = OAuthAuditEvent(
        event_type=OAuthAuditEventType(event_type),
        timestamp=datetime.now(timezone.utc),
        user_id=user_id,
        platform=platform.value,
        success=False,
        error_message=error_message,
        additional_data=kwargs
    )
    logger.log_oauth_event(event)


def setup_default_threat_handlers():
    """Setup default threat handlers for high-risk events."""
    def default_threat_handler(event: OAuthAuditEvent):
        """Default handler for high-threat OAuth events."""
        if event.threat_level in ["HIGH", "CRITICAL"]:
            logger.warning(f"HIGH THREAT OAuth event detected: {event.event_type.value} "
                         f"for user {event.user_id} from IP {event.source_ip}")
            
            # Could integrate with SIEM systems, send alerts, etc.
    
    audit_logger = EnhancedOAuthAuditLogger.instance()
    audit_logger.add_threat_handler(default_threat_handler)