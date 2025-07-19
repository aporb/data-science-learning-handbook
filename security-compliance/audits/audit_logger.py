"""
DoD-Compliant Security Audit Logging System

This module provides a comprehensive audit logging framework that meets Department of Defense
(DoD) requirements for security event logging, tamper-proof storage, and compliance reporting.

Key Features:
- Centralized log aggregation with structured schemas
- Real-time log streaming and buffering
- Multi-source log collection (applications, systems, security devices)
- DoD 8500.01E and NIST SP 800-53 compliance
- Cryptographic signing and immutable storage
- SIEM integration (Splunk, ELK, Azure Sentinel)
- Real-time threat detection and alerting
- Long-term retention (7+ years) with compliance reporting

Security Features:
- Tamper-proof audit trails with cryptographic integrity
- Write-once, read-many (WORM) compliance
- Chain-of-custody tracking
- Encrypted log storage and transmission
- Role-based access controls for audit data
- Recursive auditing (audit of audit system itself)

Compliance Standards:
- DoD 8500.01E - Information Assurance Policy
- NIST SP 800-53 - Security and Privacy Controls
- FISMA - Federal Information Security Management Act
- CJCSI 6510.01F - Information Assurance and Support to Computer Network Defense
"""

import json
import logging
import threading
import time
import uuid
import hashlib
import hmac
from typing import Dict, List, Optional, Any, Union, Callable, Iterator
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone, timedelta
from enum import Enum, IntEnum
from pathlib import Path
import sqlite3
import queue
import asyncio
import aiofiles
from concurrent.futures import ThreadPoolExecutor
import gzip
import base64

# Import security components
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from encryption.encryption_manager import EncryptionManager, EncryptionMode
from encryption.key_manager import KeyManager
from rbac.models.audit import AuditLog


class AuditEventType(Enum):
    """DoD-compliant audit event types."""
    
    # Authentication Events
    USER_LOGIN_SUCCESS = "user_login_success"
    USER_LOGIN_FAILURE = "user_login_failure"
    USER_LOGOUT = "user_logout"
    SESSION_TIMEOUT = "session_timeout"
    PASSWORD_CHANGE = "password_change"
    ACCOUNT_LOCKOUT = "account_lockout"
    ACCOUNT_UNLOCK = "account_unlock"
    CAC_AUTHENTICATION = "cac_authentication"
    PIV_AUTHENTICATION = "piv_authentication"
    MULTI_FACTOR_AUTH = "multi_factor_auth"
    
    # Authorization Events
    ACCESS_GRANTED = "access_granted"
    ACCESS_DENIED = "access_denied"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    ROLE_ASSIGNMENT = "role_assignment"
    ROLE_REMOVAL = "role_removal"
    PERMISSION_GRANT = "permission_grant"
    PERMISSION_REVOKE = "permission_revoke"
    CLEARANCE_VERIFICATION = "clearance_verification"
    CLEARANCE_DENIED = "clearance_denied"
    
    # Data Access Events
    DATA_READ = "data_read"
    DATA_WRITE = "data_write"
    DATA_DELETE = "data_delete"
    DATA_EXPORT = "data_export"
    DATA_IMPORT = "data_import"
    FILE_ACCESS = "file_access"
    DATABASE_QUERY = "database_query"
    API_ACCESS = "api_access"
    
    # Classification Events
    CLASSIFICATION_CHANGE = "classification_change"
    CROSS_DOMAIN_TRANSFER = "cross_domain_transfer"
    DECLASSIFICATION = "declassification"
    CLASSIFICATION_VIOLATION = "classification_violation"
    SPILLAGE_INCIDENT = "spillage_incident"
    
    # Administrative Events
    USER_CREATE = "user_create"
    USER_MODIFY = "user_modify"
    USER_DELETE = "user_delete"
    SYSTEM_CONFIG_CHANGE = "system_config_change"
    POLICY_CHANGE = "policy_change"
    AUDIT_CONFIG_CHANGE = "audit_config_change"
    SYSTEM_MAINTENANCE = "system_maintenance"
    BACKUP_OPERATION = "backup_operation"
    
    # Security Events
    SECURITY_VIOLATION = "security_violation"
    INTRUSION_ATTEMPT = "intrusion_attempt"
    MALWARE_DETECTION = "malware_detection"
    VULNERABILITY_SCAN = "vulnerability_scan"
    SECURITY_ALERT = "security_alert"
    INCIDENT_RESPONSE = "incident_response"
    FORENSIC_ACTIVITY = "forensic_activity"
    
    # System Events
    SYSTEM_STARTUP = "system_startup"
    SYSTEM_SHUTDOWN = "system_shutdown"
    SERVICE_START = "service_start"
    SERVICE_STOP = "service_stop"
    SYSTEM_ERROR = "system_error"
    PERFORMANCE_ALERT = "performance_alert"
    RESOURCE_EXHAUSTION = "resource_exhaustion"
    
    # Audit System Events
    AUDIT_LOG_ACCESS = "audit_log_access"
    AUDIT_LOG_EXPORT = "audit_log_export"
    AUDIT_CONFIG_ACCESS = "audit_config_access"
    AUDIT_INTEGRITY_CHECK = "audit_integrity_check"
    AUDIT_FAILURE = "audit_failure"


class AuditSeverity(IntEnum):
    """Audit event severity levels (aligned with DoD standards)."""
    
    CRITICAL = 1    # System compromise, data breach, security failure
    HIGH = 2        # Security violations, failed access attempts
    MEDIUM = 3      # Administrative changes, configuration updates
    LOW = 4         # Normal operations, successful access
    INFO = 5        # Informational events, system status


class ClassificationLevel(Enum):
    """DoD classification levels."""
    
    UNCLASSIFIED = "U"
    CONTROLLED_UNCLASSIFIED = "CUI"
    CONFIDENTIAL = "C"
    SECRET = "S"
    TOP_SECRET = "TS"
    TOP_SECRET_SCI = "TS/SCI"


@dataclass
class AuditEvent:
    """
    Comprehensive audit event structure compliant with DoD requirements.
    
    Contains all required fields for security auditing including temporal,
    spatial, identity, and action contexts as specified in DoD 8500.01E.
    """
    
    # Core Event Information
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    event_type: AuditEventType = AuditEventType.SYSTEM_ERROR
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    severity: AuditSeverity = AuditSeverity.INFO
    
    # Identity Context (Who)
    user_id: Optional[str] = None
    username: Optional[str] = None
    edipi: Optional[str] = None  # Electronic Data Interchange Personal Identifier
    session_id: Optional[str] = None
    process_id: Optional[int] = None
    service_account: Optional[str] = None
    
    # Spatial Context (Where)
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    hostname: Optional[str] = None
    system_name: Optional[str] = None
    facility_code: Optional[str] = None
    geographic_location: Optional[str] = None
    
    # Action Context (What)
    action: Optional[str] = None
    resource_type: Optional[str] = None
    resource_id: Optional[str] = None
    resource_name: Optional[str] = None
    operation: Optional[str] = None
    result: str = "SUCCESS"  # SUCCESS, FAILURE, PARTIAL
    
    # Classification Context
    classification_level: ClassificationLevel = ClassificationLevel.UNCLASSIFIED
    security_markings: List[str] = field(default_factory=list)
    handling_caveats: List[str] = field(default_factory=list)
    
    # Security Context
    clearance_level: Optional[str] = None
    need_to_know: List[str] = field(default_factory=list)
    compartments: List[str] = field(default_factory=list)
    
    # Technical Context
    application: Optional[str] = None
    module: Optional[str] = None
    function: Optional[str] = None
    protocol: Optional[str] = None
    port: Optional[int] = None
    
    # Data Context
    data_size: Optional[int] = None
    data_hash: Optional[str] = None
    before_value: Optional[str] = None
    after_value: Optional[str] = None
    
    # Outcome Context
    error_code: Optional[str] = None
    error_message: Optional[str] = None
    warning_message: Optional[str] = None
    
    # Compliance Context
    policy_reference: Optional[str] = None
    regulation_reference: Optional[str] = None
    control_reference: Optional[str] = None
    
    # Additional Context
    additional_data: Dict[str, Any] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)
    correlation_id: Optional[str] = None
    parent_event_id: Optional[str] = None
    
    # Integrity Protection
    signature: Optional[str] = None
    hash_chain_previous: Optional[str] = None
    hash_chain_current: Optional[str] = None
    
    def __post_init__(self):
        """Post-initialization processing."""
        # Ensure timestamp is UTC
        if self.timestamp.tzinfo is None:
            self.timestamp = self.timestamp.replace(tzinfo=timezone.utc)
        
        # Auto-generate hash if data is present
        if self.before_value or self.after_value:
            data_content = f"{self.before_value}|{self.after_value}"
            self.data_hash = hashlib.sha256(data_content.encode()).hexdigest()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert audit event to dictionary for serialization."""
        data = asdict(self)
        
        # Convert datetime to ISO format
        data['timestamp'] = self.timestamp.isoformat()
        
        # Convert enums to values
        data['event_type'] = self.event_type.value
        data['severity'] = self.severity.value
        data['classification_level'] = self.classification_level.value
        
        return data
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'AuditEvent':
        """Create audit event from dictionary."""
        # Convert timestamp
        if isinstance(data.get('timestamp'), str):
            data['timestamp'] = datetime.fromisoformat(data['timestamp'])
        
        # Convert enums
        if isinstance(data.get('event_type'), str):
            data['event_type'] = AuditEventType(data['event_type'])
        
        if isinstance(data.get('severity'), (int, str)):
            data['severity'] = AuditSeverity(int(data['severity']))
        
        if isinstance(data.get('classification_level'), str):
            data['classification_level'] = ClassificationLevel(data['classification_level'])
        
        return cls(**data)
    
    def calculate_integrity_hash(self, previous_hash: str = "") -> str:
        """
        Calculate integrity hash for the event.
        
        Args:
            previous_hash: Hash of the previous event in the chain
            
        Returns:
            SHA-256 hash of the event content
        """
        # Create deterministic string representation
        content = (
            f"{self.event_id}|{self.event_type.value}|{self.timestamp.isoformat()}|"
            f"{self.user_id}|{self.action}|{self.resource_id}|{self.result}|"
            f"{self.classification_level.value}|{previous_hash}"
        )
        
        return hashlib.sha256(content.encode()).hexdigest()
    
    def sign_event(self, signing_key: bytes) -> str:
        """
        Create HMAC signature for the event.
        
        Args:
            signing_key: Key for HMAC signing
            
        Returns:
            Base64-encoded HMAC signature
        """
        content = self.calculate_integrity_hash()
        signature = hmac.new(signing_key, content.encode(), hashlib.sha256).digest()
        return base64.b64encode(signature).decode()
    
    def verify_signature(self, signing_key: bytes, signature: str) -> bool:
        """
        Verify HMAC signature of the event.
        
        Args:
            signing_key: Key for HMAC verification
            signature: Base64-encoded signature to verify
            
        Returns:
            True if signature is valid
        """
        try:
            expected_signature = self.sign_event(signing_key)
            return hmac.compare_digest(expected_signature, signature)
        except Exception:
            return False


@dataclass
class AuditConfiguration:
    """Configuration for audit logging system."""
    
    # Storage Configuration
    storage_path: str = "/var/log/dod_audit"
    max_file_size: int = 100 * 1024 * 1024  # 100MB
    max_files_count: int = 1000
    compression_enabled: bool = True
    encryption_enabled: bool = True
    
    # Retention Configuration
    retention_days: int = 2555  # 7 years
    archive_after_days: int = 365
    purge_after_days: int = 2920  # 8 years (1 year grace period)
    
    # Real-time Configuration
    buffer_size: int = 10000
    flush_interval_seconds: int = 60
    async_processing: bool = True
    batch_size: int = 1000
    
    # Integrity Configuration
    hash_chain_enabled: bool = True
    signature_enabled: bool = True
    integrity_check_interval: int = 3600  # 1 hour
    
    # SIEM Integration
    siem_enabled: bool = False
    siem_endpoint: Optional[str] = None
    siem_api_key: Optional[str] = None
    siem_format: str = "CEF"  # Common Event Format
    
    # Alert Configuration
    real_time_alerts: bool = True
    alert_severity_threshold: int = AuditSeverity.HIGH
    alert_endpoints: List[str] = field(default_factory=list)
    
    # Compliance Configuration
    nist_compliance: bool = True
    dod_compliance: bool = True
    fisma_compliance: bool = True
    
    # Performance Configuration
    max_memory_usage: int = 512 * 1024 * 1024  # 512MB
    worker_threads: int = 4
    queue_timeout: int = 30


class AuditLogger:
    """
    DoD-compliant centralized audit logging system.
    
    Provides comprehensive security event logging with:
    - Tamper-proof storage with cryptographic integrity
    - Real-time streaming and buffering
    - SIEM integration capabilities
    - DoD compliance reporting
    - Multi-source log aggregation
    - Chain-of-custody tracking
    """
    
    _instance = None
    _lock = threading.Lock()
    
    def __new__(cls, config: Optional[AuditConfiguration] = None):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self, config: Optional[AuditConfiguration] = None):
        if not hasattr(self, '_initialized'):
            self.config = config or AuditConfiguration()
            self.logger = logging.getLogger(__name__)
            
            # Initialize components
            self._init_storage()
            self._init_security()
            self._init_processing()
            self._init_monitoring()
            
            # Event buffers and queues
            self.event_queue: queue.Queue = queue.Queue(maxsize=self.config.buffer_size)
            self.failed_events: List[AuditEvent] = []
            
            # Threading and async
            self.executor = ThreadPoolExecutor(max_workers=self.config.worker_threads)
            self.processing_active = True
            self.processing_thread = threading.Thread(target=self._process_events, daemon=True)
            self.processing_thread.start()
            
            # Integrity tracking
            self.last_hash = ""
            self.event_counter = 0
            self.integrity_failures = 0
            
            # SIEM connectors
            self.siem_connectors: Dict[str, Any] = {}
            
            # Alert handlers
            self.alert_handlers: List[Callable] = []
            
            self._initialized = True
            self.logger.info("DoD Audit Logger initialized successfully")
            
            # Log initialization event
            self.log_system_event(
                AuditEventType.SYSTEM_STARTUP,
                "Audit logging system initialized",
                severity=AuditSeverity.INFO
            )
    
    def _init_storage(self):
        """Initialize storage components."""
        try:
            # Create storage directories
            self.storage_path = Path(self.config.storage_path)
            self.storage_path.mkdir(parents=True, exist_ok=True, mode=0o700)
            
            # Create subdirectories
            (self.storage_path / "active").mkdir(exist_ok=True, mode=0o700)
            (self.storage_path / "archive").mkdir(exist_ok=True, mode=0o700)
            (self.storage_path / "integrity").mkdir(exist_ok=True, mode=0o700)
            
            # Initialize database for indexing and search
            self.db_path = self.storage_path / "audit_index.db"
            self._init_database()
            
            self.logger.info(f"Storage initialized at {self.storage_path}")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize storage: {e}")
            raise RuntimeError(f"Storage initialization failed: {e}")
    
    def _init_database(self):
        """Initialize SQLite database for audit event indexing."""
        try:
            conn = sqlite3.connect(self.db_path)
            
            # Create audit events table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS audit_events (
                    event_id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    severity INTEGER NOT NULL,
                    user_id TEXT,
                    username TEXT,
                    edipi TEXT,
                    source_ip TEXT,
                    hostname TEXT,
                    action TEXT,
                    resource_type TEXT,
                    resource_id TEXT,
                    result TEXT,
                    classification_level TEXT,
                    application TEXT,
                    error_code TEXT,
                    correlation_id TEXT,
                    file_path TEXT,
                    file_offset INTEGER,
                    hash_chain_current TEXT,
                    signature TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Create indexes for common queries
            indexes = [
                "CREATE INDEX IF NOT EXISTS idx_timestamp ON audit_events(timestamp)",
                "CREATE INDEX IF NOT EXISTS idx_event_type ON audit_events(event_type)",
                "CREATE INDEX IF NOT EXISTS idx_user_id ON audit_events(user_id)",
                "CREATE INDEX IF NOT EXISTS idx_severity ON audit_events(severity)",
                "CREATE INDEX IF NOT EXISTS idx_source_ip ON audit_events(source_ip)",
                "CREATE INDEX IF NOT EXISTS idx_classification ON audit_events(classification_level)",
                "CREATE INDEX IF NOT EXISTS idx_correlation ON audit_events(correlation_id)",
                "CREATE INDEX IF NOT EXISTS idx_result ON audit_events(result)",
                "CREATE INDEX IF NOT EXISTS idx_compound_search ON audit_events(timestamp, event_type, severity)"
            ]
            
            for index_sql in indexes:
                conn.execute(index_sql)
            
            # Create integrity tracking table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS integrity_chains (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    previous_hash TEXT,
                    current_hash TEXT NOT NULL,
                    event_count INTEGER NOT NULL,
                    signature TEXT,
                    verified BOOLEAN DEFAULT FALSE
                )
            """)
            
            # Create retention tracking table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS retention_tracking (
                    file_path TEXT PRIMARY KEY,
                    creation_date TEXT NOT NULL,
                    archive_date TEXT,
                    purge_date TEXT,
                    event_count INTEGER DEFAULT 0,
                    file_size INTEGER DEFAULT 0,
                    status TEXT DEFAULT 'ACTIVE'
                )
            """)
            
            conn.commit()
            conn.close()
            
            self.logger.info("Audit database initialized successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize audit database: {e}")
            raise RuntimeError(f"Database initialization failed: {e}")
    
    def _init_security(self):
        """Initialize security components for encryption and signing."""
        try:
            # Initialize key manager and encryption
            if self.config.encryption_enabled:
                self.key_manager = KeyManager()
                self.encryption_manager = EncryptionManager(self.key_manager)
                
                # Generate audit system signing key
                try:
                    self.signing_key = self.key_manager.get_key("audit_signing_key")
                except:
                    self.key_manager.generate_key(
                        key_id="audit_signing_key",
                        purpose="Audit log signing and integrity verification"
                    )
                    self.signing_key = self.key_manager.get_key("audit_signing_key")
                
                self.logger.info("Security components initialized")
            else:
                self.signing_key = b"default_audit_key_insecure"
                self.logger.warning("Encryption disabled - using insecure configuration")
                
        except Exception as e:
            self.logger.error(f"Failed to initialize security components: {e}")
            raise RuntimeError(f"Security initialization failed: {e}")
    
    def _init_processing(self):
        """Initialize event processing components."""
        try:
            # Initialize current log file
            self.current_file_path = self._get_current_log_file()
            self.current_file_size = 0
            
            # Load last hash for integrity chain
            self._load_last_hash()
            
            self.logger.info("Event processing initialized")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize processing: {e}")
            raise RuntimeError(f"Processing initialization failed: {e}")
    
    def _init_monitoring(self):
        """Initialize monitoring and health check components."""
        try:
            # Performance metrics
            self.metrics = {
                'events_logged': 0,
                'events_failed': 0,
                'bytes_written': 0,
                'integrity_checks': 0,
                'last_flush': datetime.now(timezone.utc),
                'processing_time_total': 0.0,
                'processing_time_avg': 0.0
            }
            
            # Health status
            self.health_status = {
                'status': 'HEALTHY',
                'last_check': datetime.now(timezone.utc),
                'storage_available': True,
                'encryption_working': True,
                'queue_size': 0,
                'errors': []
            }
            
            self.logger.info("Monitoring initialized")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize monitoring: {e}")
            raise RuntimeError(f"Monitoring initialization failed: {e}")
    
    def log_event(self, event: AuditEvent) -> bool:
        """
        Log an audit event to the secure audit trail.
        
        Args:
            event: AuditEvent to be logged
            
        Returns:
            True if event was successfully queued for processing
        """
        try:
            # Validate event
            if not self._validate_event(event):
                self.logger.error(f"Invalid event rejected: {event.event_id}")
                return False
            
            # Add integrity protection
            if self.config.hash_chain_enabled:
                event.hash_chain_previous = self.last_hash
                event.hash_chain_current = event.calculate_integrity_hash(self.last_hash)
            
            # Add signature
            if self.config.signature_enabled and self.signing_key:
                event.signature = event.sign_event(self.signing_key)
            
            # Queue for processing
            try:
                self.event_queue.put(event, timeout=self.config.queue_timeout)
                return True
            except queue.Full:
                self.logger.error("Event queue full, event dropped")
                self.metrics['events_failed'] += 1
                return False
                
        except Exception as e:
            self.logger.error(f"Failed to log event: {e}")
            self.metrics['events_failed'] += 1
            return False
    
    def log_authentication_event(self,
                                event_type: AuditEventType,
                                user_id: str,
                                result: str = "SUCCESS",
                                source_ip: str = None,
                                **kwargs) -> bool:
        """Log authentication-related audit event."""
        severity = AuditSeverity.HIGH if result != "SUCCESS" else AuditSeverity.LOW
        
        event = AuditEvent(
            event_type=event_type,
            severity=severity,
            user_id=user_id,
            result=result,
            source_ip=source_ip,
            action="authenticate",
            **kwargs
        )
        
        return self.log_event(event)
    
    def log_access_event(self,
                        event_type: AuditEventType,
                        user_id: str,
                        resource_type: str,
                        resource_id: str,
                        action: str,
                        result: str = "SUCCESS",
                        **kwargs) -> bool:
        """Log resource access audit event."""
        severity = AuditSeverity.MEDIUM if result != "SUCCESS" else AuditSeverity.LOW
        
        event = AuditEvent(
            event_type=event_type,
            severity=severity,
            user_id=user_id,
            resource_type=resource_type,
            resource_id=resource_id,
            action=action,
            result=result,
            **kwargs
        )
        
        return self.log_event(event)
    
    def log_security_event(self,
                          event_type: AuditEventType,
                          description: str,
                          severity: AuditSeverity = AuditSeverity.HIGH,
                          **kwargs) -> bool:
        """Log security-related audit event."""
        event = AuditEvent(
            event_type=event_type,
            severity=severity,
            action=description,
            result="DETECTED",
            **kwargs
        )
        
        return self.log_event(event)
    
    def log_system_event(self,
                        event_type: AuditEventType,
                        description: str,
                        severity: AuditSeverity = AuditSeverity.INFO,
                        **kwargs) -> bool:
        """Log system-related audit event."""
        event = AuditEvent(
            event_type=event_type,
            severity=severity,
            action=description,
            system_name=kwargs.get('hostname', 'audit_system'),
            **kwargs
        )
        
        return self.log_event(event)
    
    def _validate_event(self, event: AuditEvent) -> bool:
        """Validate audit event before processing."""
        try:
            # Check required fields
            if not event.event_id or not event.timestamp:
                return False
            
            # Validate timestamp is recent (within 24 hours)
            time_diff = abs((datetime.now(timezone.utc) - event.timestamp).total_seconds())
            if time_diff > 86400:  # 24 hours
                self.logger.warning(f"Event timestamp outside acceptable range: {event.event_id}")
            
            # Validate classification level consistency
            if event.classification_level and event.clearance_level:
                # Add validation logic for clearance vs classification
                pass
            
            return True
            
        except Exception as e:
            self.logger.error(f"Event validation error: {e}")
            return False
    
    def _process_events(self):
        """Background thread for processing audit events."""
        batch = []
        last_flush = time.time()
        
        while self.processing_active:
            try:
                # Get event from queue with timeout
                try:
                    event = self.event_queue.get(timeout=1.0)
                    batch.append(event)
                except queue.Empty:
                    pass
                
                # Process batch if full or timeout reached
                current_time = time.time()
                should_flush = (
                    len(batch) >= self.config.batch_size or
                    (batch and current_time - last_flush >= self.config.flush_interval_seconds)
                )
                
                if should_flush:
                    self._process_batch(batch)
                    batch.clear()
                    last_flush = current_time
                
                # Update queue size metric
                self.health_status['queue_size'] = self.event_queue.qsize()
                
            except Exception as e:
                self.logger.error(f"Error in event processing thread: {e}")
                time.sleep(1)
        
        # Process any remaining events
        if batch:
            self._process_batch(batch)
    
    def _process_batch(self, events: List[AuditEvent]):
        """Process a batch of audit events."""
        if not events:
            return
        
        start_time = time.time()
        
        try:
            # Write events to file
            self._write_events_to_file(events)
            
            # Index events in database
            self._index_events(events)
            
            # Send to SIEM if configured
            if self.config.siem_enabled:
                self._send_to_siem(events)
            
            # Check for alerts
            self._check_alerts(events)
            
            # Update metrics
            self.metrics['events_logged'] += len(events)
            self.metrics['last_flush'] = datetime.now(timezone.utc)
            
            processing_time = time.time() - start_time
            self.metrics['processing_time_total'] += processing_time
            self.metrics['processing_time_avg'] = (
                self.metrics['processing_time_total'] / 
                max(1, self.metrics['events_logged'])
            )
            
            self.logger.debug(f"Processed batch of {len(events)} events in {processing_time:.3f}s")
            
        except Exception as e:
            self.logger.error(f"Failed to process event batch: {e}")
            self.failed_events.extend(events)
            self.metrics['events_failed'] += len(events)
    
    def _write_events_to_file(self, events: List[AuditEvent]):
        """Write events to secure log file."""
        try:
            # Check if new file is needed
            if self._should_rotate_file():
                self._rotate_log_file()
            
            # Prepare events for writing
            output_lines = []
            for event in events:
                # Update hash chain
                if self.config.hash_chain_enabled:
                    event.hash_chain_previous = self.last_hash
                    event.hash_chain_current = event.calculate_integrity_hash(self.last_hash)
                    self.last_hash = event.hash_chain_current
                
                # Convert to JSON
                event_json = json.dumps(event.to_dict(), separators=(',', ':'))
                output_lines.append(event_json)
            
            # Write to file
            output_data = '\n'.join(output_lines) + '\n'
            
            if self.config.encryption_enabled:
                # Encrypt the data
                encrypted_data = self.encryption_manager.encrypt_data(
                    data=output_data,
                    mode=EncryptionMode.DATA_AT_REST
                )
                
                # Write encrypted data with metadata
                with open(self.current_file_path, 'ab') as f:
                    encrypted_json = json.dumps(encrypted_data.to_dict())
                    f.write(encrypted_json.encode() + b'\n')
                    self.current_file_size += len(encrypted_json) + 1
            else:
                # Write plaintext (not recommended for production)
                with open(self.current_file_path, 'a', encoding='utf-8') as f:
                    f.write(output_data)
                    self.current_file_size += len(output_data.encode())
            
            self.metrics['bytes_written'] += len(output_data.encode())
            
        except Exception as e:
            self.logger.error(f"Failed to write events to file: {e}")
            raise
    
    def _index_events(self, events: List[AuditEvent]):
        """Index events in database for searching."""
        try:
            conn = sqlite3.connect(self.db_path)
            
            for event in events:
                conn.execute("""
                    INSERT INTO audit_events (
                        event_id, timestamp, event_type, severity, user_id, username,
                        edipi, source_ip, hostname, action, resource_type, resource_id,
                        result, classification_level, application, error_code,
                        correlation_id, file_path, file_offset, hash_chain_current,
                        signature
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    event.event_id,
                    event.timestamp.isoformat(),
                    event.event_type.value,
                    event.severity.value,
                    event.user_id,
                    event.username,
                    event.edipi,
                    event.source_ip,
                    event.hostname,
                    event.action,
                    event.resource_type,
                    event.resource_id,
                    event.result,
                    event.classification_level.value,
                    event.application,
                    event.error_code,
                    event.correlation_id,
                    str(self.current_file_path),
                    self.current_file_size,
                    event.hash_chain_current,
                    event.signature
                ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            self.logger.error(f"Failed to index events: {e}")
            raise
    
    def _send_to_siem(self, events: List[AuditEvent]):
        """Send events to configured SIEM systems."""
        # Implementation for SIEM integration will be in siem_integration.py
        pass
    
    def _check_alerts(self, events: List[AuditEvent]):
        """Check events for alert conditions."""
        for event in events:
            if event.severity <= self.config.alert_severity_threshold:
                self._trigger_alert(event)
    
    def _trigger_alert(self, event: AuditEvent):
        """Trigger alert for high-severity event."""
        for handler in self.alert_handlers:
            try:
                handler(event)
            except Exception as e:
                self.logger.error(f"Alert handler error: {e}")
    
    def _should_rotate_file(self) -> bool:
        """Check if log file should be rotated."""
        return (
            not self.current_file_path.exists() or
            self.current_file_size >= self.config.max_file_size
        )
    
    def _rotate_log_file(self):
        """Rotate to a new log file."""
        try:
            # Archive current file if it exists
            if self.current_file_path.exists():
                archive_path = self.storage_path / "archive" / self.current_file_path.name
                self.current_file_path.rename(archive_path)
                
                # Compress if enabled
                if self.config.compression_enabled:
                    self._compress_file(archive_path)
            
            # Create new file
            self.current_file_path = self._get_current_log_file()
            self.current_file_size = 0
            
            self.logger.info(f"Log file rotated to {self.current_file_path}")
            
        except Exception as e:
            self.logger.error(f"Failed to rotate log file: {e}")
            raise
    
    def _get_current_log_file(self) -> Path:
        """Get path for current log file."""
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        filename = f"audit_{timestamp}_{uuid.uuid4().hex[:8]}.log"
        return self.storage_path / "active" / filename
    
    def _load_last_hash(self):
        """Load the last integrity hash from database."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.execute("""
                SELECT current_hash FROM integrity_chains 
                ORDER BY timestamp DESC LIMIT 1
            """)
            result = cursor.fetchone()
            conn.close()
            
            if result:
                self.last_hash = result[0]
            else:
                self.last_hash = ""
                
        except Exception as e:
            self.logger.error(f"Failed to load last hash: {e}")
            self.last_hash = ""
    
    def _compress_file(self, file_path: Path):
        """Compress archived log file."""
        try:
            compressed_path = file_path.with_suffix(file_path.suffix + '.gz')
            
            with open(file_path, 'rb') as f_in:
                with gzip.open(compressed_path, 'wb') as f_out:
                    f_out.writelines(f_in)
            
            file_path.unlink()  # Remove original
            self.logger.debug(f"Compressed {file_path} to {compressed_path}")
            
        except Exception as e:
            self.logger.error(f"Failed to compress file {file_path}: {e}")
    
    def query_events(self,
                    start_time: Optional[datetime] = None,
                    end_time: Optional[datetime] = None,
                    event_types: Optional[List[AuditEventType]] = None,
                    user_id: Optional[str] = None,
                    severity: Optional[AuditSeverity] = None,
                    limit: int = 1000) -> List[Dict[str, Any]]:
        """
        Query audit events with filtering.
        
        Args:
            start_time: Start of time range
            end_time: End of time range
            event_types: List of event types to filter
            user_id: Specific user ID to filter
            severity: Minimum severity level
            limit: Maximum number of results
            
        Returns:
            List of matching audit events
        """
        try:
            conn = sqlite3.connect(self.db_path)
            
            # Build query
            where_clauses = []
            params = []
            
            if start_time:
                where_clauses.append("timestamp >= ?")
                params.append(start_time.isoformat())
            
            if end_time:
                where_clauses.append("timestamp <= ?")
                params.append(end_time.isoformat())
            
            if event_types:
                placeholders = ','.join('?' * len(event_types))
                where_clauses.append(f"event_type IN ({placeholders})")
                params.extend([et.value for et in event_types])
            
            if user_id:
                where_clauses.append("user_id = ?")
                params.append(user_id)
            
            if severity:
                where_clauses.append("severity <= ?")
                params.append(severity.value)
            
            where_clause = " WHERE " + " AND ".join(where_clauses) if where_clauses else ""
            
            query = f"""
                SELECT * FROM audit_events
                {where_clause}
                ORDER BY timestamp DESC
                LIMIT ?
            """
            params.append(limit)
            
            cursor = conn.execute(query, params)
            columns = [desc[0] for desc in cursor.description]
            results = []
            
            for row in cursor.fetchall():
                event_dict = dict(zip(columns, row))
                results.append(event_dict)
            
            conn.close()
            return results
            
        except Exception as e:
            self.logger.error(f"Failed to query events: {e}")
            return []
    
    def get_health_status(self) -> Dict[str, Any]:
        """Get current health status of audit logging system."""
        self.health_status.update({
            'last_check': datetime.now(timezone.utc),
            'queue_size': self.event_queue.qsize(),
            'storage_available': self.storage_path.exists(),
            'encryption_working': self.config.encryption_enabled and hasattr(self, 'encryption_manager'),
            'metrics': self.metrics.copy()
        })
        
        return self.health_status.copy()
    
    def add_alert_handler(self, handler: Callable[[AuditEvent], None]):
        """Add custom alert handler."""
        self.alert_handlers.append(handler)
    
    def shutdown(self):
        """Gracefully shutdown the audit logging system."""
        try:
            self.logger.info("Shutting down audit logging system")
            
            # Stop processing
            self.processing_active = False
            
            # Wait for processing thread to finish
            if self.processing_thread.is_alive():
                self.processing_thread.join(timeout=30)
            
            # Process any remaining events
            remaining_events = []
            try:
                while True:
                    event = self.event_queue.get_nowait()
                    remaining_events.append(event)
            except queue.Empty:
                pass
            
            if remaining_events:
                self._process_batch(remaining_events)
            
            # Shutdown executor
            self.executor.shutdown(wait=True)
            
            # Log shutdown event
            self.log_system_event(
                AuditEventType.SYSTEM_SHUTDOWN,
                "Audit logging system shutdown",
                severity=AuditSeverity.INFO
            )
            
            self.logger.info("Audit logging system shutdown complete")
            
        except Exception as e:
            self.logger.error(f"Error during shutdown: {e}")


# Singleton access function
def get_audit_logger(config: Optional[AuditConfiguration] = None) -> AuditLogger:
    """Get the singleton audit logger instance."""
    return AuditLogger(config)


# Convenience functions for common audit operations
def audit_authentication(user_id: str, result: str = "SUCCESS", **kwargs) -> bool:
    """Audit user authentication event."""
    logger = get_audit_logger()
    event_type = AuditEventType.USER_LOGIN_SUCCESS if result == "SUCCESS" else AuditEventType.USER_LOGIN_FAILURE
    return logger.log_authentication_event(event_type, user_id, result, **kwargs)


def audit_access(user_id: str, resource_type: str, resource_id: str, 
                action: str, result: str = "SUCCESS", **kwargs) -> bool:
    """Audit resource access event."""
    logger = get_audit_logger()
    event_type = AuditEventType.ACCESS_GRANTED if result == "SUCCESS" else AuditEventType.ACCESS_DENIED
    return logger.log_access_event(event_type, user_id, resource_type, resource_id, action, result, **kwargs)


def audit_security_violation(description: str, severity: AuditSeverity = AuditSeverity.HIGH, **kwargs) -> bool:
    """Audit security violation event."""
    logger = get_audit_logger()
    return logger.log_security_event(AuditEventType.SECURITY_VIOLATION, description, severity, **kwargs)