"""
Comprehensive Audit Integration System

Unified audit logging combining RBAC decisions with platform-specific access logs,
providing enterprise-grade compliance reporting and real-time security monitoring.

This module provides:
- AuditIntegrationManager: Central audit logging across all platforms and systems
- Unified audit event correlation and enrichment
- Real-time security event detection and alerting
- Compliance reporting for DoD and enterprise standards
- Tamper-proof audit storage with integrity verification
- Performance-optimized logging with batching and compression

Classification: UNCLASSIFIED//FOR OFFICIAL USE ONLY
"""

import asyncio
import json
import logging
import hashlib
import time
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Set
from uuid import UUID, uuid4
from dataclasses import dataclass, field, asdict
from enum import Enum
from concurrent.futures import ThreadPoolExecutor
import gzip
import base64

# Import existing audit infrastructure
from ...audits.audit_logger import AuditLogger
from ...audits.real_time_alerting import RealTimeAlerting
from ...audits.compliance_reporter import ComplianceReporter
from ...audits.tamper_proof_storage import TamperProofStorage

# Import unified components
from .context import UnifiedUserContext
from .config import UnifiedAccessConfig

logger = logging.getLogger(__name__)


class AuditEventType(Enum):
    """Audit event types."""
    ACCESS_GRANTED = "access_granted"
    ACCESS_DENIED = "access_denied"
    AUTHENTICATION_SUCCESS = "authentication_success"
    AUTHENTICATION_FAILURE = "authentication_failure"
    SESSION_CREATED = "session_created"
    SESSION_TERMINATED = "session_terminated"
    PLATFORM_ACCESS = "platform_access"
    OAUTH_TOKEN_ISSUED = "oauth_token_issued"
    OAUTH_TOKEN_REFRESHED = "oauth_token_refreshed"
    PERMISSION_CHANGED = "permission_changed"
    ROLE_ASSIGNED = "role_assigned"
    ROLE_REMOVED = "role_removed"
    EMERGENCY_ACCESS = "emergency_access"
    SECURITY_VIOLATION = "security_violation"
    SYSTEM_ERROR = "system_error"
    CONFIGURATION_CHANGE = "configuration_change"
    DATA_ACCESS = "data_access"
    ADMINISTRATIVE_ACTION = "administrative_action"


class AuditSeverity(Enum):
    """Audit event severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ComplianceStandard(Enum):
    """Compliance standards for audit reporting."""
    DOD_8500 = "dod_8500"
    NIST_SP_800_53 = "nist_sp_800_53"
    FISMA = "fisma"
    SOX = "sox"
    PCI_DSS = "pci_dss"
    HIPAA = "hipaa"


@dataclass
class AuditEvent:
    """Comprehensive audit event structure."""
    event_id: str = field(default_factory=lambda: str(uuid4()))
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    event_type: AuditEventType = AuditEventType.SYSTEM_ERROR
    severity: AuditSeverity = AuditSeverity.MEDIUM
    
    # Subject information
    user_id: Optional[UUID] = None
    username: Optional[str] = None
    session_id: Optional[str] = None
    
    # Object information
    resource_type: Optional[str] = None
    resource_id: Optional[str] = None
    platform: Optional[str] = None
    
    # Action information
    action: Optional[str] = None
    result: str = "unknown"
    reason: Optional[str] = None
    
    # Context information
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    classification_level: Optional[str] = None
    
    # Additional data
    additional_data: Dict[str, Any] = field(default_factory=dict)
    
    # Correlation
    correlation_id: Optional[str] = None
    parent_event_id: Optional[str] = None
    
    # Security
    integrity_hash: Optional[str] = None
    
    def __post_init__(self):
        """Generate integrity hash after initialization."""
        if not self.integrity_hash:
            self.integrity_hash = self._generate_integrity_hash()
    
    def _generate_integrity_hash(self) -> str:
        """Generate integrity hash for tamper detection."""
        # Create a deterministic representation
        hash_data = {
            'event_id': self.event_id,
            'timestamp': self.timestamp.isoformat(),
            'event_type': self.event_type.value,
            'user_id': str(self.user_id) if self.user_id else None,
            'resource_type': self.resource_type,
            'resource_id': self.resource_id,
            'action': self.action,
            'result': self.result,
            'ip_address': self.ip_address
        }
        
        # Sort keys for deterministic hash
        hash_string = json.dumps(hash_data, sort_keys=True)
        return hashlib.sha256(hash_string.encode()).hexdigest()
    
    def verify_integrity(self) -> bool:
        """Verify event integrity."""
        expected_hash = self._generate_integrity_hash()
        return self.integrity_hash == expected_hash
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        result = asdict(self)
        result['timestamp'] = self.timestamp.isoformat()
        result['event_type'] = self.event_type.value
        result['severity'] = self.severity.value
        if self.user_id:
            result['user_id'] = str(self.user_id)
        return result
    
    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict())
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'AuditEvent':
        """Create from dictionary."""
        # Convert timestamp
        if 'timestamp' in data and isinstance(data['timestamp'], str):
            data['timestamp'] = datetime.fromisoformat(data['timestamp'].replace('Z', '+00:00'))
        
        # Convert enums
        if 'event_type' in data and isinstance(data['event_type'], str):
            data['event_type'] = AuditEventType(data['event_type'])
        
        if 'severity' in data and isinstance(data['severity'], str):
            data['severity'] = AuditSeverity(data['severity'])
        
        # Convert user_id
        if 'user_id' in data and isinstance(data['user_id'], str):
            data['user_id'] = UUID(data['user_id'])
        
        return cls(**data)


@dataclass
class AuditBatch:
    """Batch of audit events for efficient processing."""
    batch_id: str = field(default_factory=lambda: str(uuid4()))
    events: List[AuditEvent] = field(default_factory=list)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    compressed: bool = False
    
    def add_event(self, event: AuditEvent):
        """Add event to batch."""
        self.events.append(event)
    
    def compress(self) -> bytes:
        """Compress batch for storage."""
        json_data = json.dumps([event.to_dict() for event in self.events])
        compressed_data = gzip.compress(json_data.encode())
        self.compressed = True
        return compressed_data
    
    @classmethod
    def decompress(cls, compressed_data: bytes) -> 'AuditBatch':
        """Decompress batch from storage."""
        json_data = gzip.decompress(compressed_data).decode()
        events_data = json.loads(json_data)
        
        batch = cls()
        batch.events = [AuditEvent.from_dict(event_data) for event_data in events_data]
        batch.compressed = True
        
        return batch


class SecurityEventDetector:
    """Real-time security event detection and correlation."""
    
    def __init__(self):
        """Initialize security event detector."""
        self.detection_rules: List[Dict[str, Any]] = []
        self.event_window = timedelta(minutes=5)
        self.event_buffer: List[AuditEvent] = []
        self.alert_thresholds = {
            'failed_logins': 5,
            'permission_escalations': 3,
            'unusual_access_patterns': 10,
            'emergency_access_usage': 1
        }
        
        self._load_detection_rules()
    
    def _load_detection_rules(self):
        """Load security detection rules."""
        self.detection_rules = [
            {
                'name': 'Brute Force Attack',
                'pattern': 'multiple_failed_logins',
                'threshold': 5,
                'window_minutes': 5,
                'severity': AuditSeverity.HIGH
            },
            {
                'name': 'Privilege Escalation',
                'pattern': 'permission_change_after_denial',
                'threshold': 1,
                'window_minutes': 1,
                'severity': AuditSeverity.CRITICAL
            },
            {
                'name': 'Unusual Access Pattern',
                'pattern': 'cross_platform_rapid_access',
                'threshold': 10,
                'window_minutes': 2,
                'severity': AuditSeverity.MEDIUM
            },
            {
                'name': 'Emergency Access Abuse',
                'pattern': 'repeated_emergency_access',
                'threshold': 2,
                'window_minutes': 60,
                'severity': AuditSeverity.HIGH
            }
        ]
    
    def analyze_event(self, event: AuditEvent) -> List[Dict[str, Any]]:
        """Analyze event for security violations."""
        alerts = []
        
        # Add to buffer
        self.event_buffer.append(event)
        
        # Clean old events from buffer
        cutoff_time = datetime.now(timezone.utc) - self.event_window
        self.event_buffer = [e for e in self.event_buffer if e.timestamp > cutoff_time]
        
        # Apply detection rules
        for rule in self.detection_rules:
            alert = self._apply_rule(rule, event)
            if alert:
                alerts.append(alert)
        
        return alerts
    
    def _apply_rule(self, rule: Dict[str, Any], event: AuditEvent) -> Optional[Dict[str, Any]]:
        """Apply detection rule to event."""
        pattern = rule['pattern']
        
        if pattern == 'multiple_failed_logins':
            return self._detect_brute_force(rule, event)
        elif pattern == 'permission_change_after_denial':
            return self._detect_privilege_escalation(rule, event)
        elif pattern == 'cross_platform_rapid_access':
            return self._detect_unusual_access(rule, event)
        elif pattern == 'repeated_emergency_access':
            return self._detect_emergency_abuse(rule, event)
        
        return None
    
    def _detect_brute_force(self, rule: Dict[str, Any], event: AuditEvent) -> Optional[Dict[str, Any]]:
        """Detect brute force attacks."""
        if event.event_type != AuditEventType.AUTHENTICATION_FAILURE:
            return None
        
        # Count failed logins for this user/IP
        failed_count = 0
        for buffered_event in self.event_buffer:
            if (buffered_event.event_type == AuditEventType.AUTHENTICATION_FAILURE and
                (buffered_event.user_id == event.user_id or 
                 buffered_event.ip_address == event.ip_address)):
                failed_count += 1
        
        if failed_count >= rule['threshold']:
            return {
                'rule_name': rule['name'],
                'severity': rule['severity'].value,
                'details': f"Detected {failed_count} failed login attempts",
                'user_id': str(event.user_id) if event.user_id else None,
                'ip_address': event.ip_address,
                'event_count': failed_count
            }
        
        return None
    
    def _detect_privilege_escalation(self, rule: Dict[str, Any], event: AuditEvent) -> Optional[Dict[str, Any]]:
        """Detect privilege escalation attempts."""
        if event.event_type != AuditEventType.PERMISSION_CHANGED:
            return None
        
        # Look for recent access denials followed by permission changes
        for buffered_event in self.event_buffer:
            if (buffered_event.event_type == AuditEventType.ACCESS_DENIED and
                buffered_event.user_id == event.user_id and
                buffered_event.resource_type == event.additional_data.get('resource_type')):
                
                return {
                    'rule_name': rule['name'],
                    'severity': rule['severity'].value,
                    'details': "Permission change detected after access denial",
                    'user_id': str(event.user_id) if event.user_id else None,
                    'resource_type': event.additional_data.get('resource_type'),
                    'time_diff_seconds': (event.timestamp - buffered_event.timestamp).total_seconds()
                }
        
        return None
    
    def _detect_unusual_access(self, rule: Dict[str, Any], event: AuditEvent) -> Optional[Dict[str, Any]]:
        """Detect unusual access patterns."""
        if event.event_type != AuditEventType.PLATFORM_ACCESS:
            return None
        
        # Count platform accesses for this user
        access_count = 0
        platforms = set()
        
        for buffered_event in self.event_buffer:
            if (buffered_event.event_type == AuditEventType.PLATFORM_ACCESS and
                buffered_event.user_id == event.user_id):
                access_count += 1
                if buffered_event.platform:
                    platforms.add(buffered_event.platform)
        
        if access_count >= rule['threshold'] and len(platforms) >= 3:
            return {
                'rule_name': rule['name'],
                'severity': rule['severity'].value,
                'details': f"Rapid access across {len(platforms)} platforms ({access_count} accesses)",
                'user_id': str(event.user_id) if event.user_id else None,
                'platforms': list(platforms),
                'access_count': access_count
            }
        
        return None
    
    def _detect_emergency_abuse(self, rule: Dict[str, Any], event: AuditEvent) -> Optional[Dict[str, Any]]:
        """Detect emergency access abuse."""
        if event.event_type != AuditEventType.EMERGENCY_ACCESS:
            return None
        
        # Count emergency access usage
        emergency_count = 0
        for buffered_event in self.event_buffer:
            if (buffered_event.event_type == AuditEventType.EMERGENCY_ACCESS and
                buffered_event.user_id == event.user_id):
                emergency_count += 1
        
        if emergency_count >= rule['threshold']:
            return {
                'rule_name': rule['name'],
                'severity': rule['severity'].value,
                'details': f"Repeated emergency access usage ({emergency_count} times)",
                'user_id': str(event.user_id) if event.user_id else None,
                'emergency_count': emergency_count
            }
        
        return None


class AuditIntegrationManager:
    """
    Comprehensive audit integration manager.
    
    Provides:
    - Unified audit logging across all platforms and authentication methods
    - Real-time security event detection and correlation
    - Compliance reporting for multiple standards (DoD, NIST, etc.)
    - Tamper-proof audit storage with integrity verification
    - Performance-optimized logging with batching and compression
    - Event enrichment with user context and platform information
    """
    
    def __init__(self, config: UnifiedAccessConfig):
        """Initialize audit integration manager."""
        self.config = config
        
        # Core audit components
        self.audit_logger = AuditLogger(config.database_connection)
        self.real_time_alerting = RealTimeAlerting()
        self.compliance_reporter = ComplianceReporter()
        self.tamper_proof_storage = TamperProofStorage()
        
        # Security event detection
        self.security_detector = SecurityEventDetector()
        
        # Configuration
        self.batch_size = config.audit_batch_size
        self.batch_timeout = config.audit_batch_timeout
        self.enable_compression = config.audit_enable_compression
        self.retention_days = config.audit_retention_days
        
        # Event processing
        self.event_queue: asyncio.Queue = asyncio.Queue(maxsize=10000)
        self.current_batch = AuditBatch()
        self.processing_enabled = True
        
        # Background tasks
        self._processing_task: Optional[asyncio.Task] = None
        self._batch_task: Optional[asyncio.Task] = None
        self._cleanup_task: Optional[asyncio.Task] = None
        self._shutdown_event = asyncio.Event()
        
        # Metrics
        self._events_processed = 0
        self._events_dropped = 0
        self._batches_stored = 0
        self._alerts_generated = 0
        
        # Thread pool for blocking operations
        self.executor = ThreadPoolExecutor(
            max_workers=config.audit_worker_threads,
            thread_name_prefix="AuditIntegration"
        )
        
        logger.info("Audit Integration Manager initialized")
    
    async def start(self):
        """Start audit processing tasks."""
        if self._processing_task:
            return
        
        # Start processing tasks
        self._processing_task = asyncio.create_task(self._process_events())
        self._batch_task = asyncio.create_task(self._batch_processor())
        self._cleanup_task = asyncio.create_task(self._cleanup_loop())
        
        logger.info("Audit Integration Manager started")
    
    async def stop(self):
        """Stop audit processing tasks."""
        # Stop processing
        self.processing_enabled = False
        self._shutdown_event.set()
        
        # Cancel tasks
        for task in [self._processing_task, self._batch_task, self._cleanup_task]:
            if task and not task.done():
                task.cancel()
        
        # Wait for tasks to complete
        tasks = [t for t in [self._processing_task, self._batch_task, self._cleanup_task] if t]
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process remaining events
        if self.current_batch.events:
            await self._store_batch(self.current_batch)
        
        logger.info("Audit Integration Manager stopped")
    
    async def log_unified_access_decision(self, request, response, user_context: Optional[UnifiedUserContext]):
        """Log unified access control decision."""
        try:
            # Determine event type and severity
            if response.decision.value == "PERMIT":
                event_type = AuditEventType.ACCESS_GRANTED
                severity = AuditSeverity.LOW
            elif response.decision.value == "EMERGENCY":
                event_type = AuditEventType.EMERGENCY_ACCESS
                severity = AuditSeverity.HIGH
            else:
                event_type = AuditEventType.ACCESS_DENIED
                severity = AuditSeverity.MEDIUM
            
            # Create audit event
            event = AuditEvent(
                event_type=event_type,
                severity=severity,
                user_id=request.user_id,
                username=user_context.username if user_context else None,
                session_id=request.session_id,
                resource_type=request.resource_type,
                resource_id=request.resource_id,
                platform=request.platform,
                action=request.action,
                result=response.decision.value,
                reason=response.reason,
                ip_address=request.ip_address,
                classification_level=request.classification_level,
                additional_data={
                    'oauth_scopes': request.oauth_scopes,
                    'emergency_access': request.emergency_access,
                    'platform_context': request.platform_context,
                    'response_time_ms': response.response_time_ms,
                    'cache_hit': response.cache_hit,
                    'effective_permissions': len(response.effective_permissions),
                    'platform_permissions': {k: len(v) for k, v in response.platform_permissions.items()},
                    'clearance_verified': response.clearance_verified,
                    'training_current': response.training_current,
                    'conditions_met': response.conditions_met
                }
            )
            
            # Add correlation if available
            if hasattr(request, 'correlation_id'):
                event.correlation_id = request.correlation_id
            
            await self.log_event(event)
            
        except Exception as e:
            logger.error(f"Failed to log unified access decision: {e}")
    
    async def log_authentication_event(self, user_id: UUID, method: str, success: bool,
                                     ip_address: str = None, user_agent: str = None,
                                     details: Dict[str, Any] = None):
        """Log authentication event."""
        try:
            event_type = AuditEventType.AUTHENTICATION_SUCCESS if success else AuditEventType.AUTHENTICATION_FAILURE
            severity = AuditSeverity.LOW if success else AuditSeverity.MEDIUM
            
            event = AuditEvent(
                event_type=event_type,
                severity=severity,
                user_id=user_id,
                action=method,
                result="SUCCESS" if success else "FAILURE",
                ip_address=ip_address,
                user_agent=user_agent,
                additional_data=details or {}
            )
            
            await self.log_event(event)
            
        except Exception as e:
            logger.error(f"Failed to log authentication event: {e}")
    
    async def log_platform_access(self, user_id: UUID, platform: str, resource_type: str,
                                action: str, success: bool, session_id: str = None,
                                details: Dict[str, Any] = None):
        """Log platform access event."""
        try:
            event = AuditEvent(
                event_type=AuditEventType.PLATFORM_ACCESS,
                severity=AuditSeverity.LOW,
                user_id=user_id,
                session_id=session_id,
                platform=platform,
                resource_type=resource_type,
                action=action,
                result="SUCCESS" if success else "FAILURE",
                additional_data=details or {}
            )
            
            await self.log_event(event)
            
        except Exception as e:
            logger.error(f"Failed to log platform access: {e}")
    
    async def log_session_event(self, event_type: AuditEventType, session_id: str,
                              user_id: UUID, details: Dict[str, Any] = None):
        """Log session-related event."""
        try:
            event = AuditEvent(
                event_type=event_type,
                severity=AuditSeverity.LOW,
                user_id=user_id,
                session_id=session_id,
                additional_data=details or {}
            )
            
            await self.log_event(event)
            
        except Exception as e:
            logger.error(f"Failed to log session event: {e}")
    
    async def log_security_violation(self, violation_type: str, user_id: UUID = None,
                                   ip_address: str = None, details: Dict[str, Any] = None):
        """Log security violation."""
        try:
            event = AuditEvent(
                event_type=AuditEventType.SECURITY_VIOLATION,
                severity=AuditSeverity.HIGH,
                user_id=user_id,
                ip_address=ip_address,
                reason=violation_type,
                additional_data=details or {}
            )
            
            await self.log_event(event)
            
        except Exception as e:
            logger.error(f"Failed to log security violation: {e}")
    
    async def log_event(self, event: AuditEvent):
        """Log audit event."""
        try:
            # Add to processing queue
            if self.event_queue.full():
                self._events_dropped += 1
                logger.warning("Audit event queue full, dropping event")
                return
            
            await self.event_queue.put(event)
            
        except Exception as e:
            logger.error(f"Failed to queue audit event: {e}")
            self._events_dropped += 1
    
    async def _process_events(self):
        """Process events from queue."""
        while self.processing_enabled or not self.event_queue.empty():
            try:
                # Get event with timeout
                try:
                    event = await asyncio.wait_for(self.event_queue.get(), timeout=1.0)
                except asyncio.TimeoutError:
                    continue
                
                # Security analysis
                alerts = self.security_detector.analyze_event(event)
                for alert in alerts:
                    await self._handle_security_alert(alert, event)
                    self._alerts_generated += 1
                
                # Add to current batch
                self.current_batch.add_event(event)
                self._events_processed += 1
                
                # Check if batch is ready
                if len(self.current_batch.events) >= self.batch_size:
                    await self._store_batch(self.current_batch)
                    self.current_batch = AuditBatch()
                
            except Exception as e:
                logger.error(f"Error processing audit event: {e}")
    
    async def _batch_processor(self):
        """Process batches on timeout."""
        while not self._shutdown_event.is_set():
            try:
                await asyncio.sleep(self.batch_timeout)
                
                if self.current_batch.events:
                    await self._store_batch(self.current_batch)
                    self.current_batch = AuditBatch()
                    
            except Exception as e:
                logger.error(f"Error in batch processor: {e}")
    
    async def _store_batch(self, batch: AuditBatch):
        """Store audit batch."""
        try:
            # Compress if enabled
            if self.enable_compression:
                batch_data = batch.compress()
            else:
                batch_data = json.dumps([event.to_dict() for event in batch.events]).encode()
            
            # Store in tamper-proof storage
            await asyncio.get_event_loop().run_in_executor(
                self.executor,
                self.tamper_proof_storage.store_batch,
                batch.batch_id,
                batch_data
            )
            
            self._batches_stored += 1
            
            logger.debug(f"Stored audit batch {batch.batch_id} with {len(batch.events)} events")
            
        except Exception as e:
            logger.error(f"Failed to store audit batch: {e}")
    
    async def _handle_security_alert(self, alert: Dict[str, Any], event: AuditEvent):
        """Handle security alert."""
        try:
            # Send real-time alert
            await self.real_time_alerting.send_alert(
                alert_type=alert['rule_name'],
                severity=alert['severity'],
                message=alert['details'],
                context={
                    'event_id': event.event_id,
                    'user_id': str(event.user_id) if event.user_id else None,
                    'timestamp': event.timestamp.isoformat(),
                    'additional_details': alert
                }
            )
            
            # Log security event
            security_event = AuditEvent(
                event_type=AuditEventType.SECURITY_VIOLATION,
                severity=AuditSeverity(alert['severity']),
                user_id=event.user_id,
                reason=alert['rule_name'],
                ip_address=event.ip_address,
                correlation_id=event.event_id,  # Correlate with triggering event
                additional_data=alert
            )
            
            await self.event_queue.put(security_event)
            
        except Exception as e:
            logger.error(f"Failed to handle security alert: {e}")
    
    async def _cleanup_loop(self):
        """Background cleanup of old audit data."""
        while not self._shutdown_event.is_set():
            try:
                # Clean up old audit data
                cutoff_date = datetime.now(timezone.utc) - timedelta(days=self.retention_days)
                
                await asyncio.get_event_loop().run_in_executor(
                    self.executor,
                    self.tamper_proof_storage.cleanup_old_data,
                    cutoff_date
                )
                
                # Sleep for 24 hours
                await asyncio.sleep(86400)
                
            except Exception as e:
                logger.error(f"Error in audit cleanup: {e}")
                await asyncio.sleep(3600)  # Retry in 1 hour
    
    async def generate_compliance_report(self, standard: ComplianceStandard,
                                       start_date: datetime, end_date: datetime) -> Dict[str, Any]:
        """Generate compliance report for specified standard and date range."""
        try:
            report = await asyncio.get_event_loop().run_in_executor(
                self.executor,
                self.compliance_reporter.generate_report,
                standard.value,
                start_date,
                end_date
            )
            
            return report
            
        except Exception as e:
            logger.error(f"Failed to generate compliance report: {e}")
            return {'error': str(e)}
    
    async def search_audit_events(self, filters: Dict[str, Any],
                                start_date: datetime = None,
                                end_date: datetime = None,
                                limit: int = 1000) -> List[Dict[str, Any]]:
        """Search audit events with filters."""
        try:
            events = await asyncio.get_event_loop().run_in_executor(
                self.executor,
                self.tamper_proof_storage.search_events,
                filters,
                start_date,
                end_date,
                limit
            )
            
            return events
            
        except Exception as e:
            logger.error(f"Failed to search audit events: {e}")
            return []
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get comprehensive audit metrics."""
        return {
            'audit_integration': {
                'events_processed': self._events_processed,
                'events_dropped': self._events_dropped,
                'batches_stored': self._batches_stored,
                'alerts_generated': self._alerts_generated,
                'queue_size': self.event_queue.qsize(),
                'current_batch_size': len(self.current_batch.events),
                'processing_enabled': self.processing_enabled,
                'compression_enabled': self.enable_compression,
                'retention_days': self.retention_days
            },
            'security_detector': {
                'detection_rules': len(self.security_detector.detection_rules),
                'event_buffer_size': len(self.security_detector.event_buffer),
                'alert_thresholds': self.security_detector.alert_thresholds
            }
        }
    
    async def health_check(self) -> Dict[str, Any]:
        """Perform health check on audit system."""
        try:
            tasks_running = all([
                self._processing_task and not self._processing_task.done(),
                self._batch_task and not self._batch_task.done(),
                self._cleanup_task and not self._cleanup_task.done()
            ])
            
            storage_health = await asyncio.get_event_loop().run_in_executor(
                self.executor,
                self.tamper_proof_storage.health_check
            )
            
            return {
                'status': 'healthy' if tasks_running and storage_health else 'degraded',
                'processing_enabled': self.processing_enabled,
                'tasks_running': tasks_running,
                'queue_size': self.event_queue.qsize(),
                'storage_health': storage_health,
                'events_processed': self._events_processed,
                'events_dropped': self._events_dropped
            }
            
        except Exception as e:
            return {
                'status': 'unhealthy',
                'error': str(e)
            }
    
    async def close(self):
        """Close audit integration manager."""
        await self.stop()
        
        # Shutdown thread pool
        self.executor.shutdown(wait=True)
        
        # Close storage
        if hasattr(self.tamper_proof_storage, 'close'):
            await self.tamper_proof_storage.close()
        
        logger.info("Audit Integration Manager closed")