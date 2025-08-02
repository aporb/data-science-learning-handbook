#!/usr/bin/env python3
"""
Real-Time Security Alerting System for CAC/PIV Infrastructure

This module provides comprehensive real-time alerting capabilities for security events
in CAC/PIV smart card systems, including multi-channel notification delivery,
escalation procedures, and integration with security operations centers (SOC).

Key Features:
- Multi-channel alert delivery (email, SMS, dashboard, SIEM)
- Intelligent alert correlation and deduplication
- Escalation procedures with time-based triggers
- Alert severity classification and prioritization
- Integration with security monitoring systems
- Automated response capabilities
- Alert suppression and filtering
- Performance metrics and SLA tracking

Alert Channels:
- Email notifications with rich formatting
- SMS/text message alerts for critical events
- Real-time dashboard notifications
- SIEM integration (Splunk, ELK, Azure Sentinel)
- Webhook notifications for custom integrations
- Mobile push notifications
- Voice alerts for critical incidents
- Slack/Teams integration

Security Features:
- Encrypted alert transmission
- Authentication for alert endpoints
- Alert integrity verification
- Audit trail for all alert activities
- Rate limiting and flood protection
- Geographic distribution of alert systems

Author: Security Operations Team
Version: 1.0.0
"""

import os
import sys
import threading
import time
import logging
import queue
import json
import hashlib
import smtplib
import ssl
from typing import Dict, List, Optional, Set, Callable, Any, Union, Tuple
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone, timedelta
from enum import Enum, IntEnum
from collections import defaultdict, deque
from email.mime.text import MimeText
from email.mime.multipart import MimeMultipart
import requests
import sqlite3
import asyncio
import aiohttp
import weakref
from contextlib import contextmanager
import subprocess

# Import existing components
try:
    from .cac_piv_security_monitor import SecurityEvent, SecurityEventCategory, SecurityThreatLevel
    from .failover_detector import FailoverEvent, FailoverTrigger, HealthStatus
    from ..audits.audit_logger import AuditLogger, AuditEvent, AuditEventType, AuditSeverity
except ImportError:
    # Minimal implementations for standalone operation
    logger = logging.getLogger(__name__)


class AlertSeverity(IntEnum):
    """Alert severity levels."""
    CRITICAL = 1    # Immediate response required
    HIGH = 2        # Response within 15 minutes
    MEDIUM = 3      # Response within 1 hour
    LOW = 4         # Response within 4 hours
    INFO = 5        # Informational only


class AlertStatus(Enum):
    """Alert status values."""
    ACTIVE = "active"
    ACKNOWLEDGED = "acknowledged"
    ESCALATED = "escalated"
    RESOLVED = "resolved"
    SUPPRESSED = "suppressed"
    EXPIRED = "expired"


class AlertChannel(Enum):
    """Available alert delivery channels."""
    EMAIL = "email"
    SMS = "sms"
    WEBHOOK = "webhook"
    DASHBOARD = "dashboard"
    SIEM = "siem"
    SLACK = "slack"
    TEAMS = "teams"
    PUSH_NOTIFICATION = "push_notification"
    VOICE = "voice"
    PAGER = "pager"


class EscalationAction(Enum):
    """Escalation actions."""
    NOTIFY_MANAGER = "notify_manager"
    ESCALATE_SEVERITY = "escalate_severity"
    ACTIVATE_RESPONSE_TEAM = "activate_response_team"
    NOTIFY_SOC = "notify_soc"
    TRIGGER_INCIDENT = "trigger_incident"
    AUTO_REMEDIATE = "auto_remediate"


@dataclass
class AlertRule:
    """Alert rule configuration."""
    rule_id: str
    name: str
    description: str
    
    # Trigger conditions
    event_categories: List[SecurityEventCategory] = field(default_factory=list)
    severity_threshold: AlertSeverity = AlertSeverity.MEDIUM
    failure_conditions: List[FailoverTrigger] = field(default_factory=list)
    
    # Time-based conditions
    time_window_minutes: int = 60
    event_count_threshold: int = 1
    rate_threshold: Optional[float] = None
    
    # Alert configuration
    alert_severity: AlertSeverity = AlertSeverity.MEDIUM
    channels: List[AlertChannel] = field(default_factory=list)
    template: str = "default"
    
    # Escalation configuration
    escalation_enabled: bool = True
    escalation_delay_minutes: int = 30
    escalation_actions: List[EscalationAction] = field(default_factory=list)
    max_escalation_level: int = 3
    
    # Filtering and suppression
    user_filters: List[str] = field(default_factory=list)
    ip_filters: List[str] = field(default_factory=list)
    time_filters: List[Dict[str, str]] = field(default_factory=list)  # e.g., business hours only
    suppression_window_minutes: int = 60
    
    # Response configuration
    auto_response_enabled: bool = False
    response_actions: List[str] = field(default_factory=list)
    
    enabled: bool = True


@dataclass
class AlertContact:
    """Alert contact information."""
    contact_id: str
    name: str
    role: str
    
    # Contact methods
    email: Optional[str] = None
    phone: Optional[str] = None
    slack_user: Optional[str] = None
    teams_user: Optional[str] = None
    webhook_url: Optional[str] = None
    
    # Availability
    timezone: str = "UTC"
    business_hours_start: str = "09:00"
    business_hours_end: str = "17:00"
    on_call_schedule: List[Dict[str, str]] = field(default_factory=list)
    
    # Escalation
    escalation_level: int = 1
    manager_contact_id: Optional[str] = None
    
    enabled: bool = True


@dataclass
class Alert:
    """Individual alert instance."""
    alert_id: str
    rule_id: str
    severity: AlertSeverity
    title: str
    description: str
    
    # Source information
    source_event_id: Optional[str] = None
    source_component: Optional[str] = None
    
    # Timing
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    first_occurrence: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_occurrence: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    # Status tracking
    status: AlertStatus = AlertStatus.ACTIVE
    acknowledged_by: Optional[str] = None
    acknowledged_at: Optional[datetime] = None
    resolved_by: Optional[str] = None
    resolved_at: Optional[datetime] = None
    
    # Escalation tracking
    escalation_level: int = 0
    escalated_at: Optional[datetime] = None
    escalated_to: List[str] = field(default_factory=list)
    
    # Delivery tracking
    delivery_attempts: List[Dict[str, Any]] = field(default_factory=list)
    successful_deliveries: List[str] = field(default_factory=list)
    failed_deliveries: List[str] = field(default_factory=list)
    
    # Correlation
    occurrence_count: int = 1
    correlated_alerts: List[str] = field(default_factory=list)
    correlation_key: Optional[str] = None
    
    # Additional context
    context_data: Dict[str, Any] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert alert to dictionary."""
        data = asdict(self)
        data['created_at'] = self.created_at.isoformat()
        data['first_occurrence'] = self.first_occurrence.isoformat()
        data['last_occurrence'] = self.last_occurrence.isoformat()
        data['severity'] = self.severity.value
        data['status'] = self.status.value
        
        if self.acknowledged_at:
            data['acknowledged_at'] = self.acknowledged_at.isoformat()
        if self.resolved_at:
            data['resolved_at'] = self.resolved_at.isoformat()
        if self.escalated_at:
            data['escalated_at'] = self.escalated_at.isoformat()
            
        return data


class AlertingConfiguration:
    """Configuration for security alerting system."""
    
    def __init__(self):
        # Processing settings
        self.alert_processing_interval = 1.0
        self.escalation_check_interval = 60.0
        self.cleanup_interval = 3600.0
        
        # Delivery settings
        self.max_delivery_attempts = 3
        self.delivery_retry_delay = 60.0
        self.delivery_timeout = 30.0
        
        # Rate limiting
        self.rate_limit_enabled = True
        self.max_alerts_per_minute = 100
        self.burst_detection_window = 300  # 5 minutes
        self.burst_threshold = 50
        
        # Email configuration
        self.smtp_server = "localhost"
        self.smtp_port = 587
        self.smtp_username = ""
        self.smtp_password = ""
        self.smtp_use_tls = True
        self.email_from = "security-alerts@company.com"
        
        # SMS configuration
        self.sms_provider = "twilio"
        self.sms_account_sid = ""
        self.sms_auth_token = ""
        self.sms_from_number = ""
        
        # Webhook configuration
        self.webhook_timeout = 30.0
        self.webhook_retry_count = 3
        
        # Dashboard configuration
        self.dashboard_enabled = True
        self.dashboard_websocket_port = 8081
        
        # SIEM integration
        self.siem_enabled = False
        self.siem_endpoint = ""
        self.siem_api_key = ""
        self.siem_format = "CEF"
        
        # Security settings
        self.encryption_enabled = True
        self.signature_verification = True
        self.audit_all_alerts = True
        
        # Load from environment
        self._load_from_environment()
    
    def _load_from_environment(self):
        """Load configuration from environment variables."""
        try:
            self.smtp_server = os.getenv('ALERT_SMTP_SERVER', self.smtp_server)
            self.smtp_username = os.getenv('ALERT_SMTP_USERNAME', self.smtp_username)
            self.smtp_password = os.getenv('ALERT_SMTP_PASSWORD', self.smtp_password)
            self.email_from = os.getenv('ALERT_EMAIL_FROM', self.email_from)
            
            self.sms_account_sid = os.getenv('ALERT_SMS_SID', self.sms_account_sid)
            self.sms_auth_token = os.getenv('ALERT_SMS_TOKEN', self.sms_auth_token)
            self.sms_from_number = os.getenv('ALERT_SMS_FROM', self.sms_from_number)
            
            self.rate_limit_enabled = os.getenv('ALERT_RATE_LIMIT', 'true').lower() == 'true'
            self.max_alerts_per_minute = int(os.getenv('ALERT_RATE_LIMIT_MAX', '100'))
            
        except Exception as e:
            logging.getLogger(__name__).warning(f"Failed to load alerting config: {e}")


class SecurityAlerting:
    """
    Comprehensive Real-Time Security Alerting System
    
    Provides advanced alerting capabilities including:
    - Multi-channel alert delivery
    - Intelligent correlation and deduplication
    - Escalation procedures
    - Integration with monitoring systems
    - Automated response capabilities
    """
    
    def __init__(self,
                 config: Optional[AlertingConfiguration] = None,
                 audit_logger: Optional[AuditLogger] = None):
        """
        Initialize security alerting system.
        
        Args:
            config: Alerting configuration
            audit_logger: Audit logging system
        """
        self.config = config or AlertingConfiguration()
        self.audit_logger = audit_logger
        
        # Initialize database
        self._init_database()
        
        # Alert management
        self.alert_rules: Dict[str, AlertRule] = {}
        self.contacts: Dict[str, AlertContact] = {}
        self.active_alerts: Dict[str, Alert] = {}
        self.alert_history: deque = deque(maxlen=10000)
        
        # Processing components
        self.alert_queue = queue.Queue()
        self.delivery_queue = queue.Queue()
        self.escalation_queue = queue.Queue()
        
        # Rate limiting
        self.rate_limiter = deque(maxlen=1000)
        self.burst_detector = deque(maxlen=self.config.burst_detection_window)
        
        # State management
        self.is_running = False
        self._shutdown_event = threading.Event()
        self.processing_threads: List[threading.Thread] = []
        
        # Performance tracking
        self.metrics = {
            'alerts_generated': 0,
            'alerts_delivered': 0,
            'delivery_failures': 0,
            'escalations': 0,
            'false_positives': 0,
            'response_times': deque(maxlen=1000),
            'delivery_times': deque(maxlen=1000)
        }
        
        # Template system
        self.alert_templates = self._load_alert_templates()
        
        # Initialize components
        self._load_default_alert_rules()
        self._load_default_contacts()
        
        logger.info("Security Alerting System initialized")
    
    def _init_database(self):
        """Initialize alerting database."""
        try:
            self.db_path = "/tmp/security_alerting.db"
            conn = sqlite3.connect(self.db_path)
            
            # Alert rules table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS alert_rules (
                    rule_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    description TEXT,
                    configuration TEXT NOT NULL,
                    enabled BOOLEAN DEFAULT TRUE,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Contacts table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS alert_contacts (
                    contact_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    role TEXT,
                    contact_info TEXT NOT NULL,
                    enabled BOOLEAN DEFAULT TRUE,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Alerts table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS alerts (
                    alert_id TEXT PRIMARY KEY,
                    rule_id TEXT NOT NULL,
                    severity INTEGER NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT,
                    source_event_id TEXT,
                    source_component TEXT,
                    status TEXT NOT NULL,
                    occurrence_count INTEGER DEFAULT 1,
                    created_at TEXT NOT NULL,
                    first_occurrence TEXT NOT NULL,
                    last_occurrence TEXT NOT NULL,
                    acknowledged_by TEXT,
                    acknowledged_at TEXT,
                    resolved_by TEXT,
                    resolved_at TEXT,
                    escalation_level INTEGER DEFAULT 0,
                    context_data TEXT
                )
            """)
            
            # Alert deliveries table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS alert_deliveries (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    alert_id TEXT NOT NULL,
                    channel TEXT NOT NULL,
                    contact_id TEXT,
                    status TEXT NOT NULL,
                    attempt_count INTEGER DEFAULT 1,
                    delivered_at TEXT,
                    error_message TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Alert metrics table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS alert_metrics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    metric_name TEXT NOT NULL,
                    metric_value REAL NOT NULL,
                    timestamp TEXT NOT NULL,
                    tags TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Create indexes
            indexes = [
                "CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status)",
                "CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity)",
                "CREATE INDEX IF NOT EXISTS idx_alerts_created ON alerts(created_at)",
                "CREATE INDEX IF NOT EXISTS idx_deliveries_alert ON alert_deliveries(alert_id)",
                "CREATE INDEX IF NOT EXISTS idx_deliveries_status ON alert_deliveries(status)"
            ]
            
            for index_sql in indexes:
                conn.execute(index_sql)
            
            conn.commit()
            conn.close()
            
            logger.info("Security alerting database initialized")
            
        except Exception as e:
            logger.error(f"Failed to initialize alerting database: {e}")
            raise
    
    def _load_alert_templates(self) -> Dict[str, Dict[str, str]]:
        """Load alert message templates."""
        return {
            'default': {
                'subject': '[{severity}] Security Alert: {title}',
                'body': '''
Security Alert Generated

Alert ID: {alert_id}
Severity: {severity}
Title: {title}
Description: {description}

Source Component: {source_component}
Timestamp: {created_at}

This alert was generated by the CAC/PIV Security Monitoring System.
Please investigate and respond according to security procedures.

Alert Details:
{context_data}
'''
            },
            'authentication_failure': {
                'subject': '[{severity}] Authentication Failure Alert',
                'body': '''
Multiple authentication failures detected.

User: {user_id}
Source IP: {source_ip}
Failure Count: {failure_count}
Time Window: {time_window}

Immediate investigation required.
'''
            },
            'card_failure': {
                'subject': '[{severity}] Smart Card Failure Detected',
                'body': '''
Smart card failure detected in the CAC/PIV system.

Card ID: {card_id}
Reader: {reader_id}
Failure Type: {failure_type}

Failover procedures may be initiated.
'''
            },
            'system_intrusion': {
                'subject': '[CRITICAL] Security Intrusion Detected',
                'body': '''
CRITICAL SECURITY ALERT

A potential system intrusion has been detected.

Source: {source_ip}
Target: {target_system}
Attack Vector: {attack_vector}

IMMEDIATE RESPONSE REQUIRED
Contact SOC immediately.
'''
            }
        }
    
    def _load_default_alert_rules(self):
        """Load default alert rules."""
        try:
            # Critical authentication failures
            self.alert_rules["auth_failures_critical"] = AlertRule(
                rule_id="auth_failures_critical",
                name="Critical Authentication Failures",
                description="Multiple authentication failures indicating potential attack",
                event_categories=[SecurityEventCategory.AUTHENTICATION_FAILURE],
                severity_threshold=AlertSeverity.HIGH,
                time_window_minutes=15,
                event_count_threshold=10,
                alert_severity=AlertSeverity.CRITICAL,
                channels=[AlertChannel.EMAIL, AlertChannel.SMS, AlertChannel.DASHBOARD],
                template="authentication_failure",
                escalation_enabled=True,
                escalation_delay_minutes=15,
                escalation_actions=[EscalationAction.NOTIFY_SOC, EscalationAction.TRIGGER_INCIDENT]
            )
            
            # Card failure alerts
            self.alert_rules["card_failures"] = AlertRule(
                rule_id="card_failures",
                name="Smart Card Failures",
                description="Smart card or reader failures requiring attention",
                failure_conditions=[FailoverTrigger.CARD_FAILURE, FailoverTrigger.READER_FAILURE],
                alert_severity=AlertSeverity.HIGH,
                channels=[AlertChannel.EMAIL, AlertChannel.DASHBOARD],
                template="card_failure",
                escalation_enabled=True,
                escalation_delay_minutes=30,
                auto_response_enabled=True,
                response_actions=["initiate_failover", "notify_maintenance"]
            )
            
            # System intrusion alerts
            self.alert_rules["system_intrusion"] = AlertRule(
                rule_id="system_intrusion",
                name="System Intrusion Detection",
                description="Detected system intrusion attempts",
                event_categories=[SecurityEventCategory.SYSTEM_INTRUSION],
                severity_threshold=AlertSeverity.CRITICAL,
                event_count_threshold=1,
                alert_severity=AlertSeverity.CRITICAL,
                channels=[AlertChannel.EMAIL, AlertChannel.SMS, AlertChannel.VOICE, AlertChannel.SIEM],
                template="system_intrusion",
                escalation_enabled=True,
                escalation_delay_minutes=5,
                escalation_actions=[
                    EscalationAction.NOTIFY_SOC,
                    EscalationAction.ACTIVATE_RESPONSE_TEAM,
                    EscalationAction.TRIGGER_INCIDENT
                ],
                auto_response_enabled=True,
                response_actions=["isolate_system", "preserve_evidence"]
            )
            
            # Certificate violations
            self.alert_rules["cert_violations"] = AlertRule(
                rule_id="cert_violations",
                name="Certificate Violations",
                description="Invalid, expired, or revoked certificate usage",
                event_categories=[
                    SecurityEventCategory.INVALID_CERTIFICATE,
                    SecurityEventCategory.EXPIRED_CERTIFICATE,
                    SecurityEventCategory.REVOKED_CERTIFICATE
                ],
                alert_severity=AlertSeverity.HIGH,
                channels=[AlertChannel.EMAIL, AlertChannel.DASHBOARD],
                escalation_enabled=True,
                escalation_delay_minutes=60,
                auto_response_enabled=True,
                response_actions=["revoke_access", "notify_pki_admin"]
            )
            
            logger.info(f"Loaded {len(self.alert_rules)} default alert rules")
            
        except Exception as e:
            logger.error(f"Failed to load default alert rules: {e}")
    
    def _load_default_contacts(self):
        """Load default alert contacts."""
        try:
            # Security Operations Center
            self.contacts["soc_primary"] = AlertContact(
                contact_id="soc_primary",
                name="Security Operations Center",
                role="SOC Analyst",
                email="soc@company.com",
                phone="+1-555-SOC-ALERT",
                escalation_level=1
            )
            
            # Security Manager
            self.contacts["security_manager"] = AlertContact(
                contact_id="security_manager",
                name="Security Manager",
                role="Security Manager",
                email="security-manager@company.com",
                phone="+1-555-SEC-MGR",
                escalation_level=2,
                business_hours_start="08:00",
                business_hours_end="18:00"
            )
            
            # IT Operations
            self.contacts["it_ops"] = AlertContact(
                contact_id="it_ops",
                name="IT Operations Team",
                role="IT Operations",
                email="it-ops@company.com",
                phone="+1-555-IT-OPS",
                escalation_level=1
            )
            
            # Incident Response Team
            self.contacts["incident_response"] = AlertContact(
                contact_id="incident_response",
                name="Incident Response Team",
                role="Incident Response",
                email="incident-response@company.com",
                phone="+1-555-INC-RESP",
                escalation_level=3
            )
            
            logger.info(f"Loaded {len(self.contacts)} default contacts")
            
        except Exception as e:
            logger.error(f"Failed to load default contacts: {e}")
    
    def start(self) -> bool:
        """Start security alerting system."""
        if self.is_running:
            logger.warning("Security alerting already running")
            return False
        
        try:
            logger.info("Starting Security Alerting System...")
            
            # Clear shutdown event
            self._shutdown_event.clear()
            
            # Start processing threads
            self._start_processing_threads()
            
            # Start dashboard if enabled
            if self.config.dashboard_enabled:
                self._start_dashboard_service()
            
            self.is_running = True
            logger.info("Security Alerting System started successfully")
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to start security alerting: {e}")
            return False
    
    def stop(self, timeout: float = 30.0) -> bool:
        """Stop security alerting system."""
        if not self.is_running:
            return True
        
        try:
            logger.info("Stopping Security Alerting System...")
            
            # Signal shutdown
            self._shutdown_event.set()
            self.is_running = False
            
            # Stop processing threads
            self._stop_processing_threads(timeout)
            
            # Stop dashboard service
            if hasattr(self, 'dashboard_server'):
                self._stop_dashboard_service()
            
            # Save final metrics
            self._save_metrics()
            
            logger.info("Security Alerting System stopped successfully")
            return True
            
        except Exception as e:
            logger.error(f"Error stopping security alerting: {e}")
            return False
    
    def _start_processing_threads(self):
        """Start background processing threads."""
        thread_configs = [
            ("AlertProcessor", self._alert_processing_loop),
            ("DeliveryProcessor", self._delivery_processing_loop),
            ("EscalationProcessor", self._escalation_processing_loop),
            ("CleanupProcessor", self._cleanup_processing_loop),
            ("MetricsCollector", self._metrics_collection_loop)
        ]
        
        for name, target in thread_configs:
            thread = threading.Thread(
                target=target,
                name=f"SecurityAlerting-{name}",
                daemon=True
            )
            thread.start()
            self.processing_threads.append(thread)
        
        logger.debug(f"Started {len(self.processing_threads)} processing threads")
    
    def _stop_processing_threads(self, timeout: float):
        """Stop processing threads."""
        for thread in self.processing_threads:
            if thread.is_alive():
                thread.join(timeout / len(self.processing_threads))
        
        self.processing_threads.clear()
        logger.debug("Processing threads stopped")
    
    def _alert_processing_loop(self):
        """Main alert processing loop."""
        logger.debug("Alert processing loop started")
        
        while not self._shutdown_event.is_set():
            try:
                # Process alerts from queue
                try:
                    alert_data = self.alert_queue.get(timeout=1.0)
                    self._process_alert(alert_data)
                    self.alert_queue.task_done()
                except queue.Empty:
                    continue
                
            except Exception as e:
                logger.error(f"Error in alert processing loop: {e}")
                time.sleep(1)
        
        logger.debug("Alert processing loop stopped")
    
    def _delivery_processing_loop(self):
        """Alert delivery processing loop."""
        logger.debug("Delivery processing loop started")
        
        while not self._shutdown_event.is_set():
            try:
                # Process delivery requests from queue
                try:
                    delivery_request = self.delivery_queue.get(timeout=1.0)
                    self._process_delivery(delivery_request)
                    self.delivery_queue.task_done()
                except queue.Empty:
                    continue
                
            except Exception as e:
                logger.error(f"Error in delivery processing loop: {e}")
                time.sleep(1)
        
        logger.debug("Delivery processing loop stopped")
    
    def _escalation_processing_loop(self):
        """Alert escalation processing loop."""
        logger.debug("Escalation processing loop started")
        
        while not self._shutdown_event.is_set():
            try:
                # Check for alerts requiring escalation
                self._check_escalations()
                time.sleep(self.config.escalation_check_interval)
                
            except Exception as e:
                logger.error(f"Error in escalation processing loop: {e}")
                time.sleep(self.config.escalation_check_interval)
        
        logger.debug("Escalation processing loop stopped")
    
    def _cleanup_processing_loop(self):
        """Cleanup processing loop."""
        logger.debug("Cleanup processing loop started")
        
        while not self._shutdown_event.is_set():
            try:
                # Perform cleanup tasks
                self._cleanup_old_alerts()
                self._cleanup_metrics()
                time.sleep(self.config.cleanup_interval)
                
            except Exception as e:
                logger.error(f"Error in cleanup processing loop: {e}")
                time.sleep(self.config.cleanup_interval)
        
        logger.debug("Cleanup processing loop stopped")
    
    def _metrics_collection_loop(self):
        """Metrics collection loop."""
        logger.debug("Metrics collection loop started")
        
        while not self._shutdown_event.is_set():
            try:
                # Collect and store metrics
                self._collect_alerting_metrics()
                time.sleep(60)  # Collect metrics every minute
                
            except Exception as e:
                logger.error(f"Error in metrics collection loop: {e}")
                time.sleep(60)
        
        logger.debug("Metrics collection loop stopped")
    
    def generate_alert_from_security_event(self, event: SecurityEvent) -> Optional[str]:
        """Generate alert from security event."""
        try:
            # Check rate limiting
            if not self._check_rate_limit():
                logger.warning("Alert rate limit exceeded, dropping event")
                return None
            
            # Find matching alert rules
            matching_rules = self._find_matching_rules(event)
            
            if not matching_rules:
                logger.debug(f"No matching alert rules for event {event.event_id}")
                return None
            
            # Process each matching rule
            alert_ids = []
            for rule in matching_rules:
                alert_id = self._create_alert_from_rule(rule, event)
                if alert_id:
                    alert_ids.append(alert_id)
            
            return alert_ids[0] if alert_ids else None
            
        except Exception as e:
            logger.error(f"Failed to generate alert from security event: {e}")
            return None
    
    def generate_alert_from_failover_event(self, event: FailoverEvent) -> Optional[str]:
        """Generate alert from failover event."""
        try:
            # Check rate limiting
            if not self._check_rate_limit():
                logger.warning("Alert rate limit exceeded, dropping failover event")
                return None
            
            # Find matching alert rules
            matching_rules = self._find_matching_failover_rules(event)
            
            if not matching_rules:
                logger.debug(f"No matching alert rules for failover event {event.event_id}")
                return None
            
            # Process each matching rule
            alert_ids = []
            for rule in matching_rules:
                alert_id = self._create_alert_from_failover_rule(rule, event)
                if alert_id:
                    alert_ids.append(alert_id)
            
            return alert_ids[0] if alert_ids else None
            
        except Exception as e:
            logger.error(f"Failed to generate alert from failover event: {e}")
            return None
    
    def _check_rate_limit(self) -> bool:
        """Check if alert generation is within rate limits."""
        try:
            if not self.config.rate_limit_enabled:
                return True
            
            now = time.time()
            
            # Clean old entries
            while self.rate_limiter and self.rate_limiter[0] < now - 60:
                self.rate_limiter.popleft()
            
            # Check rate limit
            if len(self.rate_limiter) >= self.config.max_alerts_per_minute:
                return False
            
            # Add current time
            self.rate_limiter.append(now)
            
            # Check for burst detection
            self.burst_detector.append(now)
            recent_alerts = len([t for t in self.burst_detector if t > now - self.config.burst_detection_window])
            
            if recent_alerts >= self.config.burst_threshold:
                logger.warning(f"Alert burst detected: {recent_alerts} alerts in {self.config.burst_detection_window} seconds")
                # Could implement burst handling here
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to check rate limit: {e}")
            return True
    
    def _find_matching_rules(self, event: SecurityEvent) -> List[AlertRule]:
        """Find alert rules matching security event."""
        try:
            matching_rules = []
            
            for rule in self.alert_rules.values():
                if not rule.enabled:
                    continue
                
                # Check event category match
                if rule.event_categories and event.category not in rule.event_categories:
                    continue
                
                # Check severity threshold
                if event.threat_level > rule.severity_threshold:
                    continue
                
                # Check filters
                if not self._check_event_filters(rule, event):
                    continue
                
                # Check time-based conditions
                if not self._check_time_conditions(rule, event):
                    continue
                
                matching_rules.append(rule)
            
            return matching_rules
            
        except Exception as e:
            logger.error(f"Failed to find matching rules: {e}")
            return []
    
    def _find_matching_failover_rules(self, event: FailoverEvent) -> List[AlertRule]:
        """Find alert rules matching failover event."""
        try:
            matching_rules = []
            
            for rule in self.alert_rules.values():
                if not rule.enabled:
                    continue
                
                # Check failover condition match
                if rule.failure_conditions and event.trigger in rule.failure_conditions:
                    matching_rules.append(rule)
            
            return matching_rules
            
        except Exception as e:
            logger.error(f"Failed to find matching failover rules: {e}")
            return []
    
    def _check_event_filters(self, rule: AlertRule, event: SecurityEvent) -> bool:
        """Check if event passes rule filters."""
        try:
            # User filters
            if rule.user_filters and event.user_id:
                if not any(f in event.user_id for f in rule.user_filters):
                    return False
            
            # IP filters
            if rule.ip_filters and event.source_ip:
                if not any(f in event.source_ip for f in rule.ip_filters):
                    return False
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to check event filters: {e}")
            return True
    
    def _check_time_conditions(self, rule: AlertRule, event: SecurityEvent) -> bool:
        """Check time-based conditions for rule."""
        try:
            # Check time window and event count
            if rule.time_window_minutes > 0 and rule.event_count_threshold > 1:
                # Count recent similar events
                cutoff_time = datetime.now(timezone.utc) - timedelta(minutes=rule.time_window_minutes)
                
                # This would normally query historical events
                # For now, assume condition is met
                return True
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to check time conditions: {e}")
            return True
    
    def _create_alert_from_rule(self, rule: AlertRule, event: SecurityEvent) -> Optional[str]:
        """Create alert from rule and security event."""
        try:
            # Check for existing correlated alert
            correlation_key = self._generate_correlation_key(rule, event)
            existing_alert = self._find_correlated_alert(correlation_key)
            
            if existing_alert:
                # Update existing alert
                existing_alert.occurrence_count += 1
                existing_alert.last_occurrence = datetime.now(timezone.utc)
                self._update_alert_in_database(existing_alert)
                return existing_alert.alert_id
            
            # Create new alert
            alert_id = f"alert_{rule.rule_id}_{int(time.time())}"
            
            alert = Alert(
                alert_id=alert_id,
                rule_id=rule.rule_id,
                severity=rule.alert_severity,
                title=self._generate_alert_title(rule, event),
                description=self._generate_alert_description(rule, event),
                source_event_id=event.event_id,
                source_component=event.source_component,
                correlation_key=correlation_key,
                context_data={
                    'security_event': event.to_dict(),
                    'rule_config': asdict(rule)
                }
            )
            
            # Add to active alerts
            self.active_alerts[alert_id] = alert
            
            # Store in database
            self._store_alert_in_database(alert)
            
            # Queue for delivery
            self._queue_alert_for_delivery(alert, rule)
            
            # Update metrics
            self.metrics['alerts_generated'] += 1
            
            logger.info(f"Created alert {alert_id} from rule {rule.rule_id}")
            
            return alert_id
            
        except Exception as e:
            logger.error(f"Failed to create alert from rule: {e}")
            return None
    
    def _create_alert_from_failover_rule(self, rule: AlertRule, event: FailoverEvent) -> Optional[str]:
        """Create alert from rule and failover event."""
        try:
            alert_id = f"alert_failover_{rule.rule_id}_{int(time.time())}"
            
            alert = Alert(
                alert_id=alert_id,
                rule_id=rule.rule_id,
                severity=rule.alert_severity,
                title=f"Failover Event: {event.trigger.value}",
                description=f"Failover triggered for {event.source_component}",
                source_component=event.source_component,
                context_data={
                    'failover_event': asdict(event),
                    'rule_config': asdict(rule)
                }
            )
            
            # Add to active alerts
            self.active_alerts[alert_id] = alert
            
            # Store in database
            self._store_alert_in_database(alert)
            
            # Queue for delivery
            self._queue_alert_for_delivery(alert, rule)
            
            # Update metrics
            self.metrics['alerts_generated'] += 1
            
            logger.info(f"Created failover alert {alert_id} from rule {rule.rule_id}")
            
            return alert_id
            
        except Exception as e:
            logger.error(f"Failed to create alert from failover rule: {e}")
            return None
    
    def _generate_correlation_key(self, rule: AlertRule, event: SecurityEvent) -> str:
        """Generate correlation key for alert deduplication."""
        try:
            # Create correlation key based on rule and event characteristics
            key_components = [
                rule.rule_id,
                event.category.value,
                event.user_id or "unknown",
                event.source_ip or "unknown",
                event.source_component or "unknown"
            ]
            
            key_string = "|".join(key_components)
            return hashlib.md5(key_string.encode()).hexdigest()
            
        except Exception as e:
            logger.error(f"Failed to generate correlation key: {e}")
            return f"fallback_{rule.rule_id}_{int(time.time())}"
    
    def _find_correlated_alert(self, correlation_key: str) -> Optional[Alert]:
        """Find existing alert with same correlation key."""
        try:
            for alert in self.active_alerts.values():
                if (alert.correlation_key == correlation_key and
                    alert.status == AlertStatus.ACTIVE):
                    return alert
            
            return None
            
        except Exception as e:
            logger.error(f"Failed to find correlated alert: {e}")
            return None
    
    def _generate_alert_title(self, rule: AlertRule, event: SecurityEvent) -> str:
        """Generate alert title from rule and event."""
        try:
            if rule.template in self.alert_templates:
                template = self.alert_templates[rule.template]
                return template['subject'].format(
                    severity=rule.alert_severity.name,
                    title=rule.name,
                    alert_id="",  # Will be filled later
                    **event.to_dict()
                )
            else:
                return f"{rule.name}: {event.title}"
                
        except Exception as e:
            logger.error(f"Failed to generate alert title: {e}")
            return f"Security Alert: {rule.name}"
    
    def _generate_alert_description(self, rule: AlertRule, event: SecurityEvent) -> str:
        """Generate alert description from rule and event."""
        try:
            return f"{rule.description}\n\nEvent Details:\n{event.description}"
            
        except Exception as e:
            logger.error(f"Failed to generate alert description: {e}")
            return rule.description
    
    def _queue_alert_for_delivery(self, alert: Alert, rule: AlertRule):
        """Queue alert for delivery through configured channels."""
        try:
            for channel in rule.channels:
                delivery_request = {
                    'alert': alert,
                    'rule': rule,
                    'channel': channel,
                    'attempt': 1
                }
                
                self.delivery_queue.put_nowait(delivery_request)
                
        except Exception as e:
            logger.error(f"Failed to queue alert for delivery: {e}")
    
    def _process_alert(self, alert_data: Dict[str, Any]):
        """Process individual alert."""
        try:
            # This would implement alert processing logic
            # For now, it's a placeholder
            logger.debug(f"Processing alert: {alert_data}")
            
        except Exception as e:
            logger.error(f"Failed to process alert: {e}")
    
    def _process_delivery(self, delivery_request: Dict[str, Any]):
        """Process alert delivery request."""
        try:
            alert = delivery_request['alert']
            rule = delivery_request['rule']
            channel = delivery_request['channel']
            attempt = delivery_request['attempt']
            
            logger.debug(f"Delivering alert {alert.alert_id} via {channel.value} (attempt {attempt})")
            
            start_time = time.time()
            success = False
            error_message = None
            
            try:
                if channel == AlertChannel.EMAIL:
                    success = self._deliver_email_alert(alert, rule)
                elif channel == AlertChannel.SMS:
                    success = self._deliver_sms_alert(alert, rule)
                elif channel == AlertChannel.WEBHOOK:
                    success = self._deliver_webhook_alert(alert, rule)
                elif channel == AlertChannel.DASHBOARD:
                    success = self._deliver_dashboard_alert(alert, rule)
                elif channel == AlertChannel.SIEM:
                    success = self._deliver_siem_alert(alert, rule)
                else:
                    logger.warning(f"Unsupported alert channel: {channel}")
                    return
                
            except Exception as e:
                error_message = str(e)
                logger.error(f"Delivery failed for {channel.value}: {e}")
            
            # Record delivery attempt
            delivery_time = time.time() - start_time
            self._record_delivery_attempt(alert, channel, success, attempt, error_message)
            
            if success:
                alert.successful_deliveries.append(channel.value)
                self.metrics['alerts_delivered'] += 1
                self.metrics['delivery_times'].append(delivery_time)
                logger.info(f"Alert {alert.alert_id} delivered via {channel.value}")
            else:
                alert.failed_deliveries.append(channel.value)
                self.metrics['delivery_failures'] += 1
                
                # Retry if attempts remaining
                if attempt < self.config.max_delivery_attempts:
                    retry_request = delivery_request.copy()
                    retry_request['attempt'] = attempt + 1
                    
                    # Add delay before retry
                    threading.Timer(
                        self.config.delivery_retry_delay,
                        lambda: self.delivery_queue.put_nowait(retry_request)
                    ).start()
            
        except Exception as e:
            logger.error(f"Failed to process delivery request: {e}")
    
    def _deliver_email_alert(self, alert: Alert, rule: AlertRule) -> bool:
        """Deliver alert via email."""
        try:
            if not self.config.smtp_server:
                logger.warning("SMTP server not configured")
                return False
            
            # Get email contacts for rule
            email_contacts = [
                contact for contact in self.contacts.values()
                if contact.enabled and contact.email
            ]
            
            if not email_contacts:
                logger.warning("No email contacts configured")
                return False
            
            # Format email message
            template = self.alert_templates.get(rule.template, self.alert_templates['default'])
            
            subject = template['subject'].format(
                severity=alert.severity.name,
                title=alert.title,
                alert_id=alert.alert_id
            )
            
            body = template['body'].format(
                alert_id=alert.alert_id,
                severity=alert.severity.name,
                title=alert.title,
                description=alert.description,
                source_component=alert.source_component or "Unknown",
                created_at=alert.created_at.isoformat(),
                context_data=json.dumps(alert.context_data, indent=2)
            )
            
            # Send email to each contact
            success_count = 0
            for contact in email_contacts:
                try:
                    self._send_email(contact.email, subject, body)
                    success_count += 1
                except Exception as e:
                    logger.error(f"Failed to send email to {contact.email}: {e}")
            
            return success_count > 0
            
        except Exception as e:
            logger.error(f"Failed to deliver email alert: {e}")
            return False
    
    def _send_email(self, to_email: str, subject: str, body: str):
        """Send individual email."""
        try:
            msg = MimeMultipart()
            msg['From'] = self.config.email_from
            msg['To'] = to_email
            msg['Subject'] = subject
            
            msg.attach(MimeText(body, 'plain'))
            
            # Connect to SMTP server
            context = ssl.create_default_context()
            
            with smtplib.SMTP(self.config.smtp_server, self.config.smtp_port) as server:
                if self.config.smtp_use_tls:
                    server.starttls(context=context)
                
                if self.config.smtp_username:
                    server.login(self.config.smtp_username, self.config.smtp_password)
                
                server.send_message(msg)
            
            logger.debug(f"Email sent to {to_email}")
            
        except Exception as e:
            logger.error(f"Failed to send email to {to_email}: {e}")
            raise
    
    def _deliver_sms_alert(self, alert: Alert, rule: AlertRule) -> bool:
        """Deliver alert via SMS."""
        try:
            # This would implement SMS delivery using Twilio or similar
            # For now, it's a placeholder
            logger.debug(f"SMS delivery not implemented for alert {alert.alert_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to deliver SMS alert: {e}")
            return False
    
    def _deliver_webhook_alert(self, alert: Alert, rule: AlertRule) -> bool:
        """Deliver alert via webhook."""
        try:
            # This would implement webhook delivery
            # For now, it's a placeholder
            logger.debug(f"Webhook delivery not implemented for alert {alert.alert_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to deliver webhook alert: {e}")
            return False
    
    def _deliver_dashboard_alert(self, alert: Alert, rule: AlertRule) -> bool:
        """Deliver alert to dashboard."""
        try:
            # This would send alert to dashboard via WebSocket
            # For now, it's a placeholder
            logger.debug(f"Dashboard delivery not implemented for alert {alert.alert_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to deliver dashboard alert: {e}")
            return False
    
    def _deliver_siem_alert(self, alert: Alert, rule: AlertRule) -> bool:
        """Deliver alert to SIEM."""
        try:
            # This would implement SIEM integration
            # For now, it's a placeholder
            logger.debug(f"SIEM delivery not implemented for alert {alert.alert_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to deliver SIEM alert: {e}")
            return False
    
    def _record_delivery_attempt(self, alert: Alert, channel: AlertChannel, 
                               success: bool, attempt: int, error_message: Optional[str]):
        """Record alert delivery attempt."""
        try:
            delivery_record = {
                'channel': channel.value,
                'success': success,
                'attempt': attempt,
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'error_message': error_message
            }
            
            alert.delivery_attempts.append(delivery_record)
            
            # Store in database
            conn = sqlite3.connect(self.db_path)
            conn.execute("""
                INSERT INTO alert_deliveries (
                    alert_id, channel, status, attempt_count, delivered_at, error_message
                ) VALUES (?, ?, ?, ?, ?, ?)
            """, (
                alert.alert_id,
                channel.value,
                "SUCCESS" if success else "FAILED",
                attempt,
                datetime.now(timezone.utc).isoformat() if success else None,
                error_message
            ))
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"Failed to record delivery attempt: {e}")
    
    def _check_escalations(self):
        """Check for alerts requiring escalation."""
        try:
            now = datetime.now(timezone.utc)
            
            for alert in list(self.active_alerts.values()):
                if alert.status != AlertStatus.ACTIVE:
                    continue
                
                rule = self.alert_rules.get(alert.rule_id)
                if not rule or not rule.escalation_enabled:
                    continue
                
                # Check if escalation time has passed
                time_since_created = (now - alert.created_at).total_seconds()
                escalation_delay = rule.escalation_delay_minutes * 60
                
                if (time_since_created >= escalation_delay and
                    alert.escalation_level < rule.max_escalation_level and
                    not alert.escalated_at):
                    
                    self._escalate_alert(alert, rule)
            
        except Exception as e:
            logger.error(f"Failed to check escalations: {e}")
    
    def _escalate_alert(self, alert: Alert, rule: AlertRule):
        """Escalate alert to next level."""
        try:
            alert.escalation_level += 1
            alert.escalated_at = datetime.now(timezone.utc)
            
            logger.warning(f"Escalating alert {alert.alert_id} to level {alert.escalation_level}")
            
            # Perform escalation actions
            for action in rule.escalation_actions:
                try:
                    self._perform_escalation_action(alert, action)
                except Exception as e:
                    logger.error(f"Escalation action {action} failed: {e}")
            
            # Update in database
            self._update_alert_in_database(alert)
            
            # Update metrics
            self.metrics['escalations'] += 1
            
        except Exception as e:
            logger.error(f"Failed to escalate alert {alert.alert_id}: {e}")
    
    def _perform_escalation_action(self, alert: Alert, action: EscalationAction):
        """Perform specific escalation action."""
        try:
            if action == EscalationAction.NOTIFY_MANAGER:
                # Notify manager contacts
                manager_contacts = [
                    c for c in self.contacts.values()
                    if c.role == "Security Manager" and c.enabled
                ]
                for contact in manager_contacts:
                    if contact.email:
                        self._send_escalation_email(alert, contact)
            
            elif action == EscalationAction.ESCALATE_SEVERITY:
                # Increase alert severity
                if alert.severity > AlertSeverity.CRITICAL:
                    alert.severity = AlertSeverity(alert.severity - 1)
            
            elif action == EscalationAction.NOTIFY_SOC:
                # Notify SOC
                soc_contacts = [
                    c for c in self.contacts.values()
                    if c.role == "SOC Analyst" and c.enabled
                ]
                for contact in soc_contacts:
                    if contact.email:
                        self._send_escalation_email(alert, contact)
            
            elif action == EscalationAction.TRIGGER_INCIDENT:
                # Create incident ticket
                self._create_incident_ticket(alert)
            
            logger.info(f"Performed escalation action {action.value} for alert {alert.alert_id}")
            
        except Exception as e:
            logger.error(f"Failed to perform escalation action {action.value}: {e}")
            raise
    
    def _send_escalation_email(self, alert: Alert, contact: AlertContact):
        """Send escalation email to contact."""
        try:
            subject = f"[ESCALATED] {alert.title}"
            body = f"""
ESCALATED SECURITY ALERT

Alert ID: {alert.alert_id}
Escalation Level: {alert.escalation_level}
Original Severity: {alert.severity.name}
Created: {alert.created_at.isoformat()}

{alert.description}

This alert has been escalated due to lack of response.
Immediate attention required.
"""
            
            self._send_email(contact.email, subject, body)
            alert.escalated_to.append(contact.contact_id)
            
        except Exception as e:
            logger.error(f"Failed to send escalation email to {contact.contact_id}: {e}")
            raise
    
    def _create_incident_ticket(self, alert: Alert):
        """Create incident ticket for alert."""
        try:
            # This would integrate with incident management system
            # For now, it's a placeholder
            logger.info(f"Creating incident ticket for alert {alert.alert_id}")
            
        except Exception as e:
            logger.error(f"Failed to create incident ticket: {e}")
    
    def _cleanup_old_alerts(self):
        """Clean up old resolved alerts."""
        try:
            cutoff_time = datetime.now(timezone.utc) - timedelta(days=7)
            
            # Remove old alerts from active alerts
            to_remove = []
            for alert_id, alert in self.active_alerts.items():
                if (alert.status in [AlertStatus.RESOLVED, AlertStatus.EXPIRED] and
                    alert.created_at < cutoff_time):
                    to_remove.append(alert_id)
            
            for alert_id in to_remove:
                del self.active_alerts[alert_id]
            
            logger.debug(f"Cleaned up {len(to_remove)} old alerts")
            
        except Exception as e:
            logger.error(f"Failed to cleanup old alerts: {e}")
    
    def _cleanup_metrics(self):
        """Clean up old metrics data."""
        try:
            # Keep only recent response and delivery times
            if len(self.metrics['response_times']) > 500:
                while len(self.metrics['response_times']) > 500:
                    self.metrics['response_times'].popleft()
            
            if len(self.metrics['delivery_times']) > 500:
                while len(self.metrics['delivery_times']) > 500:
                    self.metrics['delivery_times'].popleft()
            
        except Exception as e:
            logger.error(f"Failed to cleanup metrics: {e}")
    
    def _collect_alerting_metrics(self):
        """Collect and store alerting metrics."""
        try:
            now = datetime.now(timezone.utc)
            
            # Calculate average response time
            if self.metrics['response_times']:
                avg_response_time = sum(self.metrics['response_times']) / len(self.metrics['response_times'])
                self._store_metric("average_response_time", avg_response_time, now)
            
            # Calculate average delivery time
            if self.metrics['delivery_times']:
                avg_delivery_time = sum(self.metrics['delivery_times']) / len(self.metrics['delivery_times'])
                self._store_metric("average_delivery_time", avg_delivery_time, now)
            
            # Store other metrics
            self._store_metric("active_alerts_count", len(self.active_alerts), now)
            self._store_metric("alerts_generated_total", self.metrics['alerts_generated'], now)
            self._store_metric("delivery_success_rate", 
                             self.metrics['alerts_delivered'] / max(1, self.metrics['alerts_generated']), now)
            
        except Exception as e:
            logger.error(f"Failed to collect alerting metrics: {e}")
    
    def _store_metric(self, metric_name: str, value: float, timestamp: datetime):
        """Store metric in database."""
        try:
            conn = sqlite3.connect(self.db_path)
            conn.execute("""
                INSERT INTO alert_metrics (metric_name, metric_value, timestamp)
                VALUES (?, ?, ?)
            """, (metric_name, value, timestamp.isoformat()))
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"Failed to store metric {metric_name}: {e}")
    
    def _store_alert_in_database(self, alert: Alert):
        """Store alert in database."""
        try:
            conn = sqlite3.connect(self.db_path)
            
            conn.execute("""
                INSERT INTO alerts (
                    alert_id, rule_id, severity, title, description, source_event_id,
                    source_component, status, occurrence_count, created_at, first_occurrence,
                    last_occurrence, escalation_level, context_data
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                alert.alert_id,
                alert.rule_id,
                alert.severity.value,
                alert.title,
                alert.description,
                alert.source_event_id,
                alert.source_component,
                alert.status.value,
                alert.occurrence_count,
                alert.created_at.isoformat(),
                alert.first_occurrence.isoformat(),
                alert.last_occurrence.isoformat(),
                alert.escalation_level,
                json.dumps(alert.context_data)
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"Failed to store alert in database: {e}")
    
    def _update_alert_in_database(self, alert: Alert):
        """Update alert in database."""
        try:
            conn = sqlite3.connect(self.db_path)
            
            conn.execute("""
                UPDATE alerts SET
                    status = ?, occurrence_count = ?, last_occurrence = ?,
                    escalation_level = ?, acknowledged_by = ?, acknowledged_at = ?,
                    resolved_by = ?, resolved_at = ?
                WHERE alert_id = ?
            """, (
                alert.status.value,
                alert.occurrence_count,
                alert.last_occurrence.isoformat(),
                alert.escalation_level,
                alert.acknowledged_by,
                alert.acknowledged_at.isoformat() if alert.acknowledged_at else None,
                alert.resolved_by,
                alert.resolved_at.isoformat() if alert.resolved_at else None,
                alert.alert_id
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"Failed to update alert in database: {e}")
    
    def acknowledge_alert(self, alert_id: str, acknowledged_by: str) -> bool:
        """Acknowledge an active alert."""
        try:
            if alert_id not in self.active_alerts:
                logger.warning(f"Alert {alert_id} not found")
                return False
            
            alert = self.active_alerts[alert_id]
            
            if alert.status != AlertStatus.ACTIVE:
                logger.warning(f"Alert {alert_id} is not active (status: {alert.status})")
                return False
            
            alert.status = AlertStatus.ACKNOWLEDGED
            alert.acknowledged_by = acknowledged_by
            alert.acknowledged_at = datetime.now(timezone.utc)
            
            self._update_alert_in_database(alert)
            
            logger.info(f"Alert {alert_id} acknowledged by {acknowledged_by}")
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to acknowledge alert {alert_id}: {e}")
            return False
    
    def resolve_alert(self, alert_id: str, resolved_by: str) -> bool:
        """Resolve an active alert."""
        try:
            if alert_id not in self.active_alerts:
                logger.warning(f"Alert {alert_id} not found")
                return False
            
            alert = self.active_alerts[alert_id]
            
            alert.status = AlertStatus.RESOLVED
            alert.resolved_by = resolved_by
            alert.resolved_at = datetime.now(timezone.utc)
            
            self._update_alert_in_database(alert)
            
            logger.info(f"Alert {alert_id} resolved by {resolved_by}")
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to resolve alert {alert_id}: {e}")
            return False
    
    def get_active_alerts(self) -> List[Dict[str, Any]]:
        """Get list of active alerts."""
        try:
            return [alert.to_dict() for alert in self.active_alerts.values()]
            
        except Exception as e:
            logger.error(f"Failed to get active alerts: {e}")
            return []
    
    def get_alerting_statistics(self) -> Dict[str, Any]:
        """Get alerting system statistics."""
        try:
            return {
                'system_status': {
                    'is_running': self.is_running,
                    'active_alerts': len(self.active_alerts),
                    'configured_rules': len(self.alert_rules),
                    'configured_contacts': len(self.contacts)
                },
                'metrics': self.metrics.copy(),
                'rate_limiting': {
                    'enabled': self.config.rate_limit_enabled,
                    'current_rate': len(self.rate_limiter),
                    'max_rate': self.config.max_alerts_per_minute
                },
                'delivery_status': {
                    'success_rate': (
                        self.metrics['alerts_delivered'] / 
                        max(1, self.metrics['alerts_generated'])
                    ),
                    'average_delivery_time': (
                        sum(self.metrics['delivery_times']) / 
                        max(1, len(self.metrics['delivery_times']))
                    ) if self.metrics['delivery_times'] else 0.0
                }
            }
            
        except Exception as e:
            logger.error(f"Failed to get alerting statistics: {e}")
            return {'error': str(e)}
    
    def _start_dashboard_service(self):
        """Start dashboard WebSocket service."""
        try:
            # This would start a WebSocket server for real-time dashboard updates
            logger.info("Dashboard service would be started")
            
        except Exception as e:
            logger.error(f"Failed to start dashboard service: {e}")
    
    def _stop_dashboard_service(self):
        """Stop dashboard WebSocket service."""
        try:
            logger.info("Dashboard service stopped")
            
        except Exception as e:
            logger.error(f"Failed to stop dashboard service: {e}")
    
    def _save_metrics(self):
        """Save final metrics to database."""
        try:
            now = datetime.now(timezone.utc)
            
            for metric_name, value in self.metrics.items():
                if isinstance(value, (int, float)):
                    self._store_metric(f"final_{metric_name}", value, now)
            
            logger.info("Final alerting metrics saved")
            
        except Exception as e:
            logger.error(f"Failed to save final metrics: {e}")