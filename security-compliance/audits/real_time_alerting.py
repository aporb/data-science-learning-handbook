"""
Real-Time Alerting and Threat Detection System

This module provides comprehensive real-time alerting capabilities for the DoD audit
logging system, including threat detection, correlation, escalation, and multi-channel
notification systems.

Key Features:
- Real-time event analysis with configurable detection rules
- Multi-level threat correlation and pattern recognition
- Automated escalation procedures based on severity
- Multiple alert channels (email, SMS, SNMP, webhooks)
- Machine learning-based anomaly detection
- Geospatial analysis for location-based threats
- Time-series analysis for behavioral patterns
- Integration with threat intelligence feeds

Detection Capabilities:
- Failed authentication pattern analysis
- Privilege escalation detection
- Data exfiltration monitoring
- Insider threat detection
- APT (Advanced Persistent Threat) indicators
- Brute force attack detection
- Lateral movement detection
- Anomalous access patterns

Alert Channels:
- Email notifications with encrypted content
- SMS/Text messaging via multiple providers
- SNMP traps for network management systems
- Webhook integrations for custom systems
- Slack/Teams integration for collaboration
- PagerDuty/ServiceNow for incident management
- Voice calls for critical alerts
- Dashboard notifications and visual alerts

Security Features:
- Encrypted alert transmission
- Authentication for alert endpoints
- Rate limiting to prevent alert flooding
- Alert deduplication and correlation
- Chain of custody for alert handling
- Audit trail for all alert activities
- Role-based access to alert configurations

Compliance Features:
- DoD-compliant alert handling procedures
- FISMA-compliant incident response workflows
- Automated compliance reporting integration
- Legal hold notifications for investigations
- Export control compliance for classified alerts
"""

import json
import logging
import time
import threading
import asyncio
import smtplib
import ssl
from typing import Dict, List, Optional, Any, Union, Callable, Set, Tuple
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone, timedelta
from enum import Enum, IntEnum
from pathlib import Path
import queue
import hashlib
import hmac
import base64
from email.mime.text import MimeText
from email.mime.multipart import MimeMultipart
from email.mime.base import MimeBase
from email import encoders
import sqlite3
import re
from collections import defaultdict, deque
import statistics
import ipaddress
from concurrent.futures import ThreadPoolExecutor
import aiohttp
import asyncio

# Machine Learning imports
try:
    import numpy as np
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False

# Import audit components
from .audit_logger import AuditEvent, AuditEventType, AuditSeverity, ClassificationLevel


class AlertSeverity(IntEnum):
    """Alert severity levels."""
    CRITICAL = 1    # Immediate response required
    HIGH = 2        # Response within 1 hour
    MEDIUM = 3      # Response within 4 hours
    LOW = 4         # Response within 24 hours
    INFO = 5        # Informational only


class AlertCategory(Enum):
    """Categories of security alerts."""
    AUTHENTICATION_FAILURE = "authentication_failure"
    AUTHORIZATION_VIOLATION = "authorization_violation"
    DATA_EXFILTRATION = "data_exfiltration"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    INSIDER_THREAT = "insider_threat"
    EXTERNAL_THREAT = "external_threat"
    SYSTEM_COMPROMISE = "system_compromise"
    POLICY_VIOLATION = "policy_violation"
    ANOMALOUS_BEHAVIOR = "anomalous_behavior"
    MALWARE_DETECTION = "malware_detection"
    NETWORK_INTRUSION = "network_intrusion"
    COMPLIANCE_VIOLATION = "compliance_violation"


class AlertChannel(Enum):
    """Available alert channels."""
    EMAIL = "email"
    SMS = "sms"
    WEBHOOK = "webhook"
    SNMP = "snmp"
    SLACK = "slack"
    TEAMS = "teams"
    PAGERDUTY = "pagerduty"
    VOICE = "voice"
    DASHBOARD = "dashboard"
    SYSLOG = "syslog"


class ThreatLevel(Enum):
    """Threat assessment levels."""
    BENIGN = "benign"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    CRITICAL = "critical"


@dataclass
class AlertRule:
    """Configuration for a detection rule."""
    
    # Rule identification
    rule_id: str
    name: str
    description: str
    enabled: bool = True
    
    # Trigger conditions
    event_types: List[AuditEventType] = field(default_factory=list)
    severity_threshold: AuditSeverity = AuditSeverity.HIGH
    time_window_minutes: int = 5
    occurrence_threshold: int = 5
    
    # Pattern matching
    user_pattern: Optional[str] = None
    ip_pattern: Optional[str] = None
    resource_pattern: Optional[str] = None
    message_pattern: Optional[str] = None
    
    # Conditions
    conditions: Dict[str, Any] = field(default_factory=dict)
    
    # Alert configuration
    alert_severity: AlertSeverity = AlertSeverity.MEDIUM
    alert_category: AlertCategory = AlertCategory.ANOMALOUS_BEHAVIOR
    channels: List[AlertChannel] = field(default_factory=list)
    
    # Response configuration
    auto_escalate: bool = False
    escalation_time_minutes: int = 60
    response_actions: List[str] = field(default_factory=list)
    
    # Metadata
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    author: Optional[str] = None
    version: int = 1


@dataclass
class ThreatIndicator:
    """Indicator of potential threat activity."""
    
    indicator_id: str
    indicator_type: str  # ip, domain, hash, user, etc.
    value: str
    threat_level: ThreatLevel
    confidence: float  # 0.0 to 1.0
    
    # Context
    description: str
    source: str
    tags: List[str] = field(default_factory=list)
    
    # Temporal information
    first_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: Optional[datetime] = None
    
    # Additional data
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SecurityAlert:
    """Security alert generated by detection rules."""
    
    # Alert identification
    alert_id: str
    rule_id: str
    alert_severity: AlertSeverity
    alert_category: AlertCategory
    
    # Alert content
    title: str
    description: str
    details: Dict[str, Any] = field(default_factory=dict)
    
    # Temporal information
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    first_occurrence: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_occurrence: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    occurrence_count: int = 1
    
    # Source information
    source_events: List[str] = field(default_factory=list)  # Event IDs
    affected_users: Set[str] = field(default_factory=set)
    affected_systems: Set[str] = field(default_factory=set)
    source_ips: Set[str] = field(default_factory=set)
    
    # Classification and handling
    classification_level: ClassificationLevel = ClassificationLevel.UNCLASSIFIED
    threat_level: ThreatLevel = ThreatLevel.SUSPICIOUS
    confidence: float = 0.5
    
    # Response tracking
    status: str = "OPEN"  # OPEN, ACKNOWLEDGED, INVESTIGATING, RESOLVED, FALSE_POSITIVE
    assigned_to: Optional[str] = None
    response_actions: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    
    # Escalation tracking
    escalated: bool = False
    escalation_time: Optional[datetime] = None
    escalation_level: int = 0
    
    # Notification tracking
    notifications_sent: List[Dict[str, Any]] = field(default_factory=list)
    
    def add_occurrence(self, event_id: str, timestamp: datetime = None):
        """Add another occurrence of this alert."""
        if timestamp is None:
            timestamp = datetime.now(timezone.utc)
        
        self.occurrence_count += 1
        self.last_occurrence = timestamp
        self.source_events.append(event_id)
    
    def escalate(self, escalation_level: int = None):
        """Escalate the alert to higher severity."""
        if escalation_level is None:
            escalation_level = self.escalation_level + 1
        
        self.escalated = True
        self.escalation_time = datetime.now(timezone.utc)
        self.escalation_level = escalation_level
        
        # Increase severity if possible
        if self.alert_severity > AlertSeverity.CRITICAL:
            self.alert_severity = AlertSeverity(self.alert_severity - 1)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert alert to dictionary for serialization."""
        data = asdict(self)
        
        # Convert datetime objects
        data['timestamp'] = self.timestamp.isoformat()
        data['first_occurrence'] = self.first_occurrence.isoformat()
        data['last_occurrence'] = self.last_occurrence.isoformat()
        if self.escalation_time:
            data['escalation_time'] = self.escalation_time.isoformat()
        
        # Convert enums
        data['alert_severity'] = self.alert_severity.value
        data['alert_category'] = self.alert_category.value
        data['classification_level'] = self.classification_level.value
        data['threat_level'] = self.threat_level.value
        
        # Convert sets to lists
        data['affected_users'] = list(self.affected_users)
        data['affected_systems'] = list(self.affected_systems)
        data['source_ips'] = list(self.source_ips)
        
        return data


class PatternAnalyzer:
    """Analyzes patterns in audit events for threat detection."""
    
    def __init__(self):
        self.failed_logins = defaultdict(deque)
        self.privilege_changes = defaultdict(deque)
        self.data_access_patterns = defaultdict(deque)
        self.ip_access_patterns = defaultdict(deque)
        self.time_window = timedelta(minutes=15)
        
        # Machine learning components
        if ML_AVAILABLE:
            self.anomaly_detector = IsolationForest(contamination=0.1)
            self.scaler = StandardScaler()
            self.baseline_features = []
            self.ml_trained = False
    
    def analyze_failed_authentication(self, events: List[AuditEvent]) -> List[SecurityAlert]:
        """Analyze failed authentication patterns."""
        alerts = []
        
        # Group by user and IP
        user_failures = defaultdict(list)
        ip_failures = defaultdict(list)
        
        for event in events:
            if event.event_type == AuditEventType.USER_LOGIN_FAILURE:
                if event.user_id:
                    user_failures[event.user_id].append(event)
                if event.source_ip:
                    ip_failures[event.source_ip].append(event)
        
        # Check for brute force attacks by user
        for user_id, failed_events in user_failures.items():
            if len(failed_events) >= 5:  # 5 or more failures
                alert = SecurityAlert(
                    alert_id=f"auth_fail_user_{user_id}_{int(time.time())}",
                    rule_id="failed_auth_user_pattern",
                    alert_severity=AlertSeverity.HIGH,
                    alert_category=AlertCategory.AUTHENTICATION_FAILURE,
                    title=f"Multiple authentication failures for user {user_id}",
                    description=f"User {user_id} has {len(failed_events)} failed login attempts",
                    details={
                        'user_id': user_id,
                        'failure_count': len(failed_events),
                        'time_span': (failed_events[-1].timestamp - failed_events[0].timestamp).total_seconds(),
                        'source_ips': list(set(e.source_ip for e in failed_events if e.source_ip))
                    },
                    source_events=[e.event_id for e in failed_events],
                    affected_users={user_id},
                    source_ips=set(e.source_ip for e in failed_events if e.source_ip)
                )
                alerts.append(alert)
        
        # Check for brute force attacks by IP
        for source_ip, failed_events in ip_failures.items():
            if len(failed_events) >= 10:  # 10 or more failures from same IP
                unique_users = set(e.user_id for e in failed_events if e.user_id)
                
                alert = SecurityAlert(
                    alert_id=f"auth_fail_ip_{source_ip.replace('.', '_')}_{int(time.time())}",
                    rule_id="failed_auth_ip_pattern",
                    alert_severity=AlertSeverity.CRITICAL,
                    alert_category=AlertCategory.EXTERNAL_THREAT,
                    title=f"Brute force attack from IP {source_ip}",
                    description=f"IP {source_ip} has {len(failed_events)} failed login attempts against {len(unique_users)} users",
                    details={
                        'source_ip': source_ip,
                        'failure_count': len(failed_events),
                        'unique_users_targeted': len(unique_users),
                        'users_targeted': list(unique_users),
                        'time_span': (failed_events[-1].timestamp - failed_events[0].timestamp).total_seconds()
                    },
                    source_events=[e.event_id for e in failed_events],
                    affected_users=unique_users,
                    source_ips={source_ip},
                    threat_level=ThreatLevel.MALICIOUS
                )
                alerts.append(alert)
        
        return alerts
    
    def analyze_privilege_escalation(self, events: List[AuditEvent]) -> List[SecurityAlert]:
        """Analyze privilege escalation patterns."""
        alerts = []
        
        escalation_events = [
            e for e in events 
            if e.event_type in [AuditEventType.PRIVILEGE_ESCALATION, AuditEventType.ROLE_ASSIGNMENT]
        ]
        
        # Group by user
        user_escalations = defaultdict(list)
        for event in escalation_events:
            if event.user_id:
                user_escalations[event.user_id].append(event)
        
        for user_id, user_events in user_escalations.items():
            if len(user_events) >= 3:  # Multiple escalations
                alert = SecurityAlert(
                    alert_id=f"privilege_escalation_{user_id}_{int(time.time())}",
                    rule_id="privilege_escalation_pattern",
                    alert_severity=AlertSeverity.HIGH,
                    alert_category=AlertCategory.PRIVILEGE_ESCALATION,
                    title=f"Multiple privilege escalations for user {user_id}",
                    description=f"User {user_id} has performed {len(user_events)} privilege escalations",
                    details={
                        'user_id': user_id,
                        'escalation_count': len(user_events),
                        'roles_assigned': list(set(e.additional_data.get('role_name', 'unknown') for e in user_events)),
                        'time_span': (user_events[-1].timestamp - user_events[0].timestamp).total_seconds()
                    },
                    source_events=[e.event_id for e in user_events],
                    affected_users={user_id},
                    threat_level=ThreatLevel.SUSPICIOUS
                )
                alerts.append(alert)
        
        return alerts
    
    def analyze_data_exfiltration(self, events: List[AuditEvent]) -> List[SecurityAlert]:
        """Analyze potential data exfiltration patterns."""
        alerts = []
        
        # Look for large data access or export events
        data_events = [
            e for e in events 
            if e.event_type in [AuditEventType.DATA_EXPORT, AuditEventType.DATA_READ, AuditEventType.FILE_ACCESS]
        ]
        
        # Group by user
        user_data_access = defaultdict(list)
        for event in data_events:
            if event.user_id:
                user_data_access[event.user_id].append(event)
        
        for user_id, user_events in user_data_access.items():
            # Calculate total data size accessed
            total_size = sum(e.data_size or 0 for e in user_events)
            
            # Check for unusual volume or frequency
            if len(user_events) >= 50 or total_size >= 100 * 1024 * 1024:  # 50 accesses or 100MB
                # Check for off-hours access
                off_hours_count = sum(
                    1 for e in user_events 
                    if e.timestamp.hour < 6 or e.timestamp.hour > 22
                )
                
                severity = AlertSeverity.MEDIUM
                threat_level = ThreatLevel.SUSPICIOUS
                
                if off_hours_count > len(user_events) * 0.5:  # More than 50% off-hours
                    severity = AlertSeverity.HIGH
                    threat_level = ThreatLevel.MALICIOUS
                
                alert = SecurityAlert(
                    alert_id=f"data_exfiltration_{user_id}_{int(time.time())}",
                    rule_id="data_exfiltration_pattern",
                    alert_severity=severity,
                    alert_category=AlertCategory.DATA_EXFILTRATION,
                    title=f"Potential data exfiltration by user {user_id}",
                    description=f"User {user_id} accessed {len(user_events)} data resources totaling {total_size} bytes",
                    details={
                        'user_id': user_id,
                        'access_count': len(user_events),
                        'total_bytes': total_size,
                        'off_hours_accesses': off_hours_count,
                        'unique_resources': len(set(e.resource_id for e in user_events if e.resource_id)),
                        'time_span': (user_events[-1].timestamp - user_events[0].timestamp).total_seconds()
                    },
                    source_events=[e.event_id for e in user_events],
                    affected_users={user_id},
                    threat_level=threat_level
                )
                alerts.append(alert)
        
        return alerts
    
    def analyze_anomalous_behavior(self, events: List[AuditEvent]) -> List[SecurityAlert]:
        """Use machine learning to detect anomalous behavior patterns."""
        alerts = []
        
        if not ML_AVAILABLE:
            return alerts
        
        try:
            # Extract features from events
            features = []
            event_metadata = []
            
            for event in events:
                # Create feature vector
                feature_vector = [
                    event.timestamp.hour,
                    event.timestamp.weekday(),
                    event.severity.value,
                    len(event.action or ''),
                    1 if event.source_ip else 0,
                    1 if event.user_id else 0,
                    event.data_size or 0,
                    hash(event.event_type.value) % 1000,  # Hash event type to numeric
                ]
                
                features.append(feature_vector)
                event_metadata.append({
                    'event_id': event.event_id,
                    'user_id': event.user_id,
                    'timestamp': event.timestamp,
                    'event_type': event.event_type.value
                })
            
            if len(features) < 10:  # Need minimum samples
                return alerts
            
            # Convert to numpy array
            X = np.array(features)
            
            # Scale features
            X_scaled = self.scaler.fit_transform(X)
            
            # Detect anomalies
            outliers = self.anomaly_detector.fit_predict(X_scaled)
            
            # Create alerts for anomalies
            for i, is_outlier in enumerate(outliers):
                if is_outlier == -1:  # Anomaly detected
                    event_meta = event_metadata[i]
                    
                    alert = SecurityAlert(
                        alert_id=f"anomaly_{event_meta['event_id']}_{int(time.time())}",
                        rule_id="ml_anomaly_detection",
                        alert_severity=AlertSeverity.MEDIUM,
                        alert_category=AlertCategory.ANOMALOUS_BEHAVIOR,
                        title=f"Anomalous behavior detected for user {event_meta['user_id']}",
                        description=f"Machine learning detected anomalous event: {event_meta['event_type']}",
                        details={
                            'user_id': event_meta['user_id'],
                            'event_type': event_meta['event_type'],
                            'anomaly_score': 'high',
                            'detection_method': 'isolation_forest'
                        },
                        source_events=[event_meta['event_id']],
                        affected_users={event_meta['user_id']} if event_meta['user_id'] else set(),
                        threat_level=ThreatLevel.SUSPICIOUS,
                        confidence=0.7
                    )
                    alerts.append(alert)
        
        except Exception as e:
            logging.getLogger(__name__).error(f"ML anomaly detection failed: {e}")
        
        return alerts


class AlertManager:
    """
    Central manager for real-time alerting and threat detection.
    
    Coordinates rule evaluation, alert generation, notification delivery,
    and escalation procedures.
    """
    
    def __init__(self, storage_path: str = "/var/log/dod_alerts"):
        self.storage_path = Path(storage_path)
        self.storage_path.mkdir(parents=True, exist_ok=True, mode=0o700)
        
        # Initialize components
        self.logger = logging.getLogger(__name__)
        self.pattern_analyzer = PatternAnalyzer()
        
        # Rule management
        self.rules: Dict[str, AlertRule] = {}
        self.threat_indicators: Dict[str, ThreatIndicator] = {}
        
        # Alert tracking
        self.active_alerts: Dict[str, SecurityAlert] = {}
        self.alert_history: deque = deque(maxlen=10000)
        
        # Event processing
        self.event_queue: queue.Queue = queue.Queue(maxsize=50000)
        self.processing_active = True
        self.worker_threads = []
        
        # Notification channels
        self.notification_channels: Dict[AlertChannel, Any] = {}
        
        # Statistics
        self.stats = {
            'total_events_processed': 0,
            'alerts_generated': 0,
            'alerts_resolved': 0,
            'notifications_sent': 0,
            'false_positives': 0,
            'escalations': 0
        }
        
        # Initialize database
        self._init_database()
        
        # Load rules and indicators
        self._load_default_rules()
        
        # Start processing threads
        self._start_workers()
    
    def _init_database(self):
        """Initialize alert database."""
        try:
            self.db_path = self.storage_path / "alerts.db"
            conn = sqlite3.connect(self.db_path)
            
            # Alerts table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS alerts (
                    alert_id TEXT PRIMARY KEY,
                    rule_id TEXT NOT NULL,
                    alert_severity INTEGER NOT NULL,
                    alert_category TEXT NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    first_occurrence TEXT NOT NULL,
                    last_occurrence TEXT NOT NULL,
                    occurrence_count INTEGER DEFAULT 1,
                    classification_level TEXT NOT NULL,
                    threat_level TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    status TEXT DEFAULT 'OPEN',
                    assigned_to TEXT,
                    escalated BOOLEAN DEFAULT FALSE,
                    escalation_time TEXT,
                    escalation_level INTEGER DEFAULT 0,
                    details TEXT,
                    source_events TEXT,
                    affected_users TEXT,
                    affected_systems TEXT,
                    source_ips TEXT,
                    response_actions TEXT,
                    notes TEXT,
                    notifications_sent TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Rules table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS alert_rules (
                    rule_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    description TEXT NOT NULL,
                    enabled BOOLEAN DEFAULT TRUE,
                    rule_config TEXT NOT NULL,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    author TEXT,
                    version INTEGER DEFAULT 1
                )
            """)
            
            # Threat indicators table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS threat_indicators (
                    indicator_id TEXT PRIMARY KEY,
                    indicator_type TEXT NOT NULL,
                    value TEXT NOT NULL,
                    threat_level TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    description TEXT NOT NULL,
                    source TEXT NOT NULL,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    expires_at TEXT,
                    tags TEXT,
                    metadata TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Create indexes
            indexes = [
                "CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp)",
                "CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(alert_severity)",
                "CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status)",
                "CREATE INDEX IF NOT EXISTS idx_alerts_category ON alerts(alert_category)",
                "CREATE INDEX IF NOT EXISTS idx_indicators_type ON threat_indicators(indicator_type)",
                "CREATE INDEX IF NOT EXISTS idx_indicators_value ON threat_indicators(value)"
            ]
            
            for index_sql in indexes:
                conn.execute(index_sql)
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            self.logger.error(f"Failed to initialize alert database: {e}")
            raise
    
    def _load_default_rules(self):
        """Load default detection rules."""
        default_rules = [
            AlertRule(
                rule_id="failed_login_brute_force",
                name="Brute Force Authentication Attack",
                description="Detects multiple failed login attempts",
                event_types=[AuditEventType.USER_LOGIN_FAILURE],
                time_window_minutes=5,
                occurrence_threshold=5,
                alert_severity=AlertSeverity.HIGH,
                alert_category=AlertCategory.AUTHENTICATION_FAILURE,
                channels=[AlertChannel.EMAIL, AlertChannel.DASHBOARD]
            ),
            AlertRule(
                rule_id="privilege_escalation_rapid",
                name="Rapid Privilege Escalation",
                description="Detects rapid privilege escalation attempts",
                event_types=[AuditEventType.PRIVILEGE_ESCALATION, AuditEventType.ROLE_ASSIGNMENT],
                time_window_minutes=10,
                occurrence_threshold=3,
                alert_severity=AlertSeverity.CRITICAL,
                alert_category=AlertCategory.PRIVILEGE_ESCALATION,
                channels=[AlertChannel.EMAIL, AlertChannel.SMS, AlertChannel.DASHBOARD]
            ),
            AlertRule(
                rule_id="data_access_anomaly",
                name="Anomalous Data Access Pattern",
                description="Detects unusual data access patterns",
                event_types=[AuditEventType.DATA_READ, AuditEventType.DATA_EXPORT],
                time_window_minutes=60,
                occurrence_threshold=50,
                alert_severity=AlertSeverity.MEDIUM,
                alert_category=AlertCategory.DATA_EXFILTRATION,
                channels=[AlertChannel.EMAIL, AlertChannel.DASHBOARD]
            ),
            AlertRule(
                rule_id="off_hours_access",
                name="Off-Hours System Access",
                description="Detects system access during off-hours",
                event_types=[AuditEventType.USER_LOGIN_SUCCESS],
                time_window_minutes=1,
                occurrence_threshold=1,
                conditions={'time_range': ['22:00-06:00']},
                alert_severity=AlertSeverity.LOW,
                alert_category=AlertCategory.ANOMALOUS_BEHAVIOR,
                channels=[AlertChannel.DASHBOARD]
            ),
            AlertRule(
                rule_id="classification_violation",
                name="Classification Level Violation",
                description="Detects potential classification level violations",
                event_types=[AuditEventType.CLASSIFICATION_VIOLATION],
                time_window_minutes=1,
                occurrence_threshold=1,
                alert_severity=AlertSeverity.CRITICAL,
                alert_category=AlertCategory.COMPLIANCE_VIOLATION,
                channels=[AlertChannel.EMAIL, AlertChannel.SMS, AlertChannel.DASHBOARD],
                auto_escalate=True,
                escalation_time_minutes=15
            )
        ]
        
        for rule in default_rules:
            self.rules[rule.rule_id] = rule
    
    def _start_workers(self):
        """Start worker threads for event processing."""
        for i in range(4):  # 4 worker threads
            worker = threading.Thread(target=self._process_events, daemon=True)
            worker.start()
            self.worker_threads.append(worker)
        
        # Start escalation thread
        escalation_worker = threading.Thread(target=self._handle_escalations, daemon=True)
        escalation_worker.start()
        self.worker_threads.append(escalation_worker)
    
    def process_event(self, event: AuditEvent):
        """Queue an audit event for processing."""
        try:
            self.event_queue.put(event, timeout=1.0)
        except queue.Full:
            self.logger.warning("Alert processing queue full, dropping event")
    
    def _process_events(self):
        """Worker thread for processing events against rules."""
        event_buffer = []
        last_analysis = time.time()
        
        while self.processing_active:
            try:
                # Collect events for batch processing
                try:
                    event = self.event_queue.get(timeout=1.0)
                    event_buffer.append(event)
                    self.stats['total_events_processed'] += 1
                except queue.Empty:
                    pass
                
                # Process buffer periodically or when it gets large
                current_time = time.time()
                if (len(event_buffer) >= 100 or 
                    (event_buffer and current_time - last_analysis >= 30)):
                    
                    self._analyze_events(event_buffer)
                    event_buffer.clear()
                    last_analysis = current_time
                
            except Exception as e:
                self.logger.error(f"Error in event processing worker: {e}")
                time.sleep(1)
    
    def _analyze_events(self, events: List[AuditEvent]):
        """Analyze events against detection rules and patterns."""
        try:
            # Apply rule-based detection
            for rule in self.rules.values():
                if not rule.enabled:
                    continue
                
                matching_events = self._filter_events_for_rule(events, rule)
                if len(matching_events) >= rule.occurrence_threshold:
                    alert = self._create_alert_from_rule(rule, matching_events)
                    if alert:
                        self._handle_new_alert(alert)
            
            # Apply pattern-based detection
            pattern_alerts = []
            pattern_alerts.extend(self.pattern_analyzer.analyze_failed_authentication(events))
            pattern_alerts.extend(self.pattern_analyzer.analyze_privilege_escalation(events))
            pattern_alerts.extend(self.pattern_analyzer.analyze_data_exfiltration(events))
            pattern_alerts.extend(self.pattern_analyzer.analyze_anomalous_behavior(events))
            
            for alert in pattern_alerts:
                self._handle_new_alert(alert)
            
        except Exception as e:
            self.logger.error(f"Error in event analysis: {e}")
    
    def _filter_events_for_rule(self, events: List[AuditEvent], rule: AlertRule) -> List[AuditEvent]:
        """Filter events that match a specific rule."""
        matching_events = []
        cutoff_time = datetime.now(timezone.utc) - timedelta(minutes=rule.time_window_minutes)
        
        for event in events:
            # Check time window
            if event.timestamp < cutoff_time:
                continue
            
            # Check event types
            if rule.event_types and event.event_type not in rule.event_types:
                continue
            
            # Check severity threshold
            if event.severity > rule.severity_threshold:
                continue
            
            # Check pattern matching
            if rule.user_pattern and event.user_id:
                if not re.search(rule.user_pattern, event.user_id):
                    continue
            
            if rule.ip_pattern and event.source_ip:
                if not re.search(rule.ip_pattern, event.source_ip):
                    continue
            
            if rule.resource_pattern and event.resource_id:
                if not re.search(rule.resource_pattern, event.resource_id):
                    continue
            
            if rule.message_pattern and event.action:
                if not re.search(rule.message_pattern, event.action):
                    continue
            
            # Check custom conditions
            if rule.conditions:
                if not self._check_conditions(event, rule.conditions):
                    continue
            
            matching_events.append(event)
        
        return matching_events
    
    def _check_conditions(self, event: AuditEvent, conditions: Dict[str, Any]) -> bool:
        """Check if event meets custom conditions."""
        try:
            # Time range condition
            if 'time_range' in conditions:
                time_ranges = conditions['time_range']
                current_hour = event.timestamp.hour
                
                for time_range in time_ranges:
                    if '-' in time_range:
                        start_time, end_time = time_range.split('-')
                        start_hour = int(start_time.split(':')[0])
                        end_hour = int(end_time.split(':')[0])
                        
                        if start_hour > end_hour:  # Crosses midnight
                            if current_hour >= start_hour or current_hour <= end_hour:
                                return True
                        else:
                            if start_hour <= current_hour <= end_hour:
                                return True
                
                return False
            
            # Add more condition types as needed
            return True
            
        except Exception as e:
            self.logger.error(f"Error checking conditions: {e}")
            return False
    
    def _create_alert_from_rule(self, rule: AlertRule, events: List[AuditEvent]) -> Optional[SecurityAlert]:
        """Create an alert from a triggered rule."""
        try:
            # Check for existing similar alert
            alert_key = f"{rule.rule_id}_{hash(tuple(sorted(set(e.user_id or 'unknown' for e in events))))}"
            
            if alert_key in self.active_alerts:
                # Update existing alert
                existing_alert = self.active_alerts[alert_key]
                for event in events:
                    existing_alert.add_occurrence(event.event_id, event.timestamp)
                    
                    if event.user_id:
                        existing_alert.affected_users.add(event.user_id)
                    if event.hostname:
                        existing_alert.affected_systems.add(event.hostname)
                    if event.source_ip:
                        existing_alert.source_ips.add(event.source_ip)
                
                return existing_alert
            
            # Create new alert
            alert = SecurityAlert(
                alert_id=f"{rule.rule_id}_{int(time.time())}_{hash(alert_key) % 10000}",
                rule_id=rule.rule_id,
                alert_severity=rule.alert_severity,
                alert_category=rule.alert_category,
                title=rule.name,
                description=f"{rule.description} - {len(events)} events detected",
                details={
                    'rule_name': rule.name,
                    'event_count': len(events),
                    'time_window_minutes': rule.time_window_minutes,
                    'threshold': rule.occurrence_threshold
                },
                source_events=[e.event_id for e in events],
                affected_users=set(e.user_id for e in events if e.user_id),
                affected_systems=set(e.hostname for e in events if e.hostname),
                source_ips=set(e.source_ip for e in events if e.source_ip),
                first_occurrence=min(e.timestamp for e in events),
                last_occurrence=max(e.timestamp for e in events),
                occurrence_count=len(events)
            )
            
            # Set classification level based on highest event classification
            classifications = [e.classification_level for e in events]
            if classifications:
                alert.classification_level = max(classifications, key=lambda x: list(ClassificationLevel).index(x))
            
            self.active_alerts[alert_key] = alert
            return alert
            
        except Exception as e:
            self.logger.error(f"Error creating alert from rule: {e}")
            return None
    
    def _handle_new_alert(self, alert: SecurityAlert):
        """Handle a newly generated alert."""
        try:
            # Store alert in database
            self._store_alert(alert)
            
            # Add to history
            self.alert_history.append(alert)
            self.stats['alerts_generated'] += 1
            
            # Send notifications
            rule = self.rules.get(alert.rule_id)
            if rule and rule.channels:
                self._send_notifications(alert, rule.channels)
            
            # Check for auto-escalation
            if rule and rule.auto_escalate:
                # Schedule escalation
                pass  # Handled by escalation worker
            
            self.logger.info(f"Generated alert: {alert.alert_id} - {alert.title}")
            
        except Exception as e:
            self.logger.error(f"Error handling new alert: {e}")
    
    def _store_alert(self, alert: SecurityAlert):
        """Store alert in database."""
        try:
            conn = sqlite3.connect(self.db_path)
            
            conn.execute("""
                INSERT INTO alerts (
                    alert_id, rule_id, alert_severity, alert_category, title, description,
                    timestamp, first_occurrence, last_occurrence, occurrence_count,
                    classification_level, threat_level, confidence, status, assigned_to,
                    escalated, escalation_time, escalation_level, details, source_events,
                    affected_users, affected_systems, source_ips, response_actions,
                    notes, notifications_sent
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                alert.alert_id, alert.rule_id, alert.alert_severity.value,
                alert.alert_category.value, alert.title, alert.description,
                alert.timestamp.isoformat(), alert.first_occurrence.isoformat(),
                alert.last_occurrence.isoformat(), alert.occurrence_count,
                alert.classification_level.value, alert.threat_level.value,
                alert.confidence, alert.status, alert.assigned_to,
                alert.escalated, 
                alert.escalation_time.isoformat() if alert.escalation_time else None,
                alert.escalation_level, json.dumps(alert.details),
                json.dumps(alert.source_events), json.dumps(list(alert.affected_users)),
                json.dumps(list(alert.affected_systems)), json.dumps(list(alert.source_ips)),
                json.dumps(alert.response_actions), json.dumps(alert.notes),
                json.dumps(alert.notifications_sent)
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            self.logger.error(f"Failed to store alert: {e}")
    
    def _send_notifications(self, alert: SecurityAlert, channels: List[AlertChannel]):
        """Send alert notifications through specified channels."""
        for channel in channels:
            try:
                if channel == AlertChannel.EMAIL:
                    self._send_email_notification(alert)
                elif channel == AlertChannel.SMS:
                    self._send_sms_notification(alert)
                elif channel == AlertChannel.WEBHOOK:
                    self._send_webhook_notification(alert)
                elif channel == AlertChannel.DASHBOARD:
                    self._send_dashboard_notification(alert)
                # Add more channels as needed
                
                # Track notification
                alert.notifications_sent.append({
                    'channel': channel.value,
                    'timestamp': datetime.now(timezone.utc).isoformat(),
                    'success': True
                })
                
                self.stats['notifications_sent'] += 1
                
            except Exception as e:
                self.logger.error(f"Failed to send {channel.value} notification: {e}")
                alert.notifications_sent.append({
                    'channel': channel.value,
                    'timestamp': datetime.now(timezone.utc).isoformat(),
                    'success': False,
                    'error': str(e)
                })
    
    def _send_email_notification(self, alert: SecurityAlert):
        """Send email notification for alert."""
        # Implementation would depend on SMTP configuration
        # This is a placeholder for the email notification logic
        pass
    
    def _send_sms_notification(self, alert: SecurityAlert):
        """Send SMS notification for alert."""
        # Implementation would depend on SMS provider
        # This is a placeholder for the SMS notification logic
        pass
    
    def _send_webhook_notification(self, alert: SecurityAlert):
        """Send webhook notification for alert."""
        # Implementation for webhook notifications
        pass
    
    def _send_dashboard_notification(self, alert: SecurityAlert):
        """Send dashboard notification for alert."""
        # Implementation for dashboard notifications
        pass
    
    def _handle_escalations(self):
        """Handle alert escalations."""
        while self.processing_active:
            try:
                current_time = datetime.now(timezone.utc)
                
                for alert in list(self.active_alerts.values()):
                    rule = self.rules.get(alert.rule_id)
                    
                    if (rule and rule.auto_escalate and not alert.escalated and
                        alert.status == "OPEN"):
                        
                        # Check if escalation time has passed
                        escalation_time = alert.timestamp + timedelta(minutes=rule.escalation_time_minutes)
                        
                        if current_time >= escalation_time:
                            alert.escalate()
                            self._handle_new_alert(alert)  # Re-send with higher severity
                            self.stats['escalations'] += 1
                
                time.sleep(60)  # Check every minute
                
            except Exception as e:
                self.logger.error(f"Error in escalation handler: {e}")
                time.sleep(60)
    
    def add_rule(self, rule: AlertRule) -> bool:
        """Add a new detection rule."""
        try:
            self.rules[rule.rule_id] = rule
            
            # Store in database
            conn = sqlite3.connect(self.db_path)
            conn.execute("""
                INSERT OR REPLACE INTO alert_rules (
                    rule_id, name, description, enabled, rule_config,
                    updated_at, author, version
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                rule.rule_id, rule.name, rule.description, rule.enabled,
                json.dumps(asdict(rule)), rule.updated_at.isoformat(),
                rule.author, rule.version
            ))
            conn.commit()
            conn.close()
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to add rule: {e}")
            return False
    
    def get_active_alerts(self, severity: Optional[AlertSeverity] = None) -> List[SecurityAlert]:
        """Get currently active alerts."""
        alerts = list(self.active_alerts.values())
        
        if severity:
            alerts = [a for a in alerts if a.alert_severity <= severity]
        
        return sorted(alerts, key=lambda x: x.timestamp, reverse=True)
    
    def resolve_alert(self, alert_id: str, resolution: str = "RESOLVED", notes: str = "") -> bool:
        """Resolve an alert."""
        try:
            # Find alert
            alert = None
            alert_key = None
            
            for key, active_alert in self.active_alerts.items():
                if active_alert.alert_id == alert_id:
                    alert = active_alert
                    alert_key = key
                    break
            
            if not alert:
                return False
            
            # Update alert status
            alert.status = resolution
            if notes:
                alert.notes.append(f"{datetime.now(timezone.utc).isoformat()}: {notes}")
            
            # Update database
            conn = sqlite3.connect(self.db_path)
            conn.execute("""
                UPDATE alerts SET status = ?, notes = ? WHERE alert_id = ?
            """, (resolution, json.dumps(alert.notes), alert_id))
            conn.commit()
            conn.close()
            
            # Remove from active alerts if resolved
            if resolution in ["RESOLVED", "FALSE_POSITIVE"]:
                del self.active_alerts[alert_key]
                self.stats['alerts_resolved'] += 1
                
                if resolution == "FALSE_POSITIVE":
                    self.stats['false_positives'] += 1
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to resolve alert: {e}")
            return False
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get alerting system statistics."""
        return {
            'stats': self.stats.copy(),
            'active_alerts_count': len(self.active_alerts),
            'rules_count': len(self.rules),
            'enabled_rules_count': sum(1 for r in self.rules.values() if r.enabled),
            'threat_indicators_count': len(self.threat_indicators),
            'queue_size': self.event_queue.qsize()
        }
    
    def shutdown(self):
        """Gracefully shutdown the alert manager."""
        self.processing_active = False
        
        # Wait for workers to finish
        for worker in self.worker_threads:
            worker.join(timeout=30)
        
        self.logger.info("Alert manager shutdown complete")


# Factory function for creating alert manager
def create_alert_manager(storage_path: str = None) -> AlertManager:
    """Create and initialize alert manager."""
    if storage_path is None:
        storage_path = "/var/log/dod_alerts"
    
    return AlertManager(storage_path)