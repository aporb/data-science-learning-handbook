#!/usr/bin/env python3
"""
Certificate Expiration Monitor

This module provides comprehensive certificate expiration monitoring with
automated alerting, renewal tracking, and compliance reporting for DoD PKI
and CAC/PIV certificates.
"""

import os
import logging
import json
import sqlite3
import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Optional, Dict, List, Tuple, Set, Any, Callable
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone, timedelta
from enum import Enum
from pathlib import Path
import threading
import time
import schedule
from cryptography import x509
from cryptography.hazmat.primitives import serialization
import requests

logger = logging.getLogger(__name__)


class AlertSeverity(Enum):
    """Alert severity levels."""
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"
    EMERGENCY = "emergency"


class CertificateStatus(Enum):
    """Certificate status for monitoring."""
    VALID = "valid"
    EXPIRING_SOON = "expiring_soon"
    EXPIRED = "expired"
    REVOKED = "revoked"
    UNKNOWN = "unknown"


@dataclass
class ExpirationAlert:
    """Certificate expiration alert information."""
    certificate_id: str
    subject_dn: str
    issuer_dn: str
    serial_number: str
    expiration_date: datetime
    days_until_expiry: int
    severity: AlertSeverity
    status: CertificateStatus
    
    # Alert metadata
    alert_id: str = ""
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_sent: Optional[datetime] = None
    send_count: int = 0
    acknowledged: bool = False
    acknowledged_by: Optional[str] = None
    acknowledged_at: Optional[datetime] = None
    
    # Certificate details
    certificate_type: str = "unknown"
    key_usage: List[str] = field(default_factory=list)
    edipi: Optional[str] = None
    dod_id: Optional[str] = None
    
    # Alert configuration
    alert_thresholds: Dict[str, int] = field(default_factory=dict)
    notification_channels: List[str] = field(default_factory=list)
    
    # Additional context
    renewal_instructions: str = ""
    impact_assessment: str = ""
    related_systems: List[str] = field(default_factory=list)


@dataclass
class MonitoringConfiguration:
    """Configuration for certificate monitoring."""
    # Alert thresholds (days before expiration)
    critical_threshold: int = 7
    warning_threshold: int = 30
    info_threshold: int = 90
    
    # Monitoring intervals
    check_interval_hours: int = 24
    urgent_check_interval_hours: int = 6
    
    # Notification settings
    enable_email_alerts: bool = True
    enable_webhook_alerts: bool = False
    enable_syslog_alerts: bool = False
    
    # Email configuration
    smtp_server: str = ""
    smtp_port: int = 587
    smtp_username: str = ""
    smtp_password: str = ""
    smtp_use_tls: bool = True
    
    # Recipients
    default_recipients: List[str] = field(default_factory=list)
    critical_recipients: List[str] = field(default_factory=list)
    
    # Webhook settings
    webhook_urls: List[str] = field(default_factory=list)
    webhook_auth_headers: Dict[str, str] = field(default_factory=dict)
    
    # Filtering
    monitor_ca_certificates: bool = True
    monitor_end_entity_certificates: bool = True
    exclude_self_signed: bool = False
    
    # DoD-specific settings
    prioritize_dod_certificates: bool = True
    require_dod_renewal_process: bool = True


class ExpirationMonitor:
    """
    Comprehensive certificate expiration monitor.
    
    Provides automated monitoring, alerting, and reporting for certificate
    expiration with special handling for DoD PKI certificates.
    """
    
    def __init__(self, config: MonitoringConfiguration = None,
                 database_path: str = None):
        """
        Initialize expiration monitor.
        
        Args:
            config: Monitoring configuration
            database_path: Path to monitoring database
        """
        self.config = config or MonitoringConfiguration()
        self.database_path = database_path or self._get_default_database_path()
        
        # Initialize database
        self._initialize_database()
        
        # Monitoring state
        self.is_monitoring = False
        self._monitor_thread = None
        self._shutdown_event = threading.Event()
        
        # Alert tracking
        self._active_alerts = {}
        self._alert_lock = threading.Lock()
        
        # Notification handlers
        self._notification_handlers = {}
        self._setup_notification_handlers()
        
        # Statistics
        self._stats = {
            'total_certificates': 0,
            'monitored_certificates': 0,
            'active_alerts': 0,
            'alerts_sent': 0,
            'last_check': None
        }
        
        logger.info("Certificate expiration monitor initialized")
    
    def _get_default_database_path(self) -> str:
        """Get default database path."""
        data_dir = os.path.expanduser("~/.cac/monitoring")
        os.makedirs(data_dir, exist_ok=True)
        return os.path.join(data_dir, "expiration_monitor.db")
    
    def _initialize_database(self):
        """Initialize monitoring database."""
        with sqlite3.connect(self.database_path) as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS monitored_certificates (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    certificate_id TEXT UNIQUE NOT NULL,
                    subject_dn TEXT NOT NULL,
                    issuer_dn TEXT NOT NULL,
                    serial_number TEXT NOT NULL,
                    fingerprint_sha256 TEXT NOT NULL,
                    expiration_date TEXT NOT NULL,
                    certificate_type TEXT NOT NULL,
                    key_usage TEXT,
                    edipi TEXT,
                    dod_id TEXT,
                    file_path TEXT,
                    is_ca_certificate BOOLEAN DEFAULT 0,
                    is_monitored BOOLEAN DEFAULT 1,
                    added_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    last_checked TEXT,
                    status TEXT DEFAULT 'valid'
                )
            ''')
            
            conn.execute('''
                CREATE TABLE IF NOT EXISTS expiration_alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    alert_id TEXT UNIQUE NOT NULL,
                    certificate_id TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    status TEXT NOT NULL,
                    days_until_expiry INTEGER NOT NULL,
                    created_at TEXT NOT NULL,
                    last_sent TEXT,
                    send_count INTEGER DEFAULT 0,
                    acknowledged BOOLEAN DEFAULT 0,
                    acknowledged_by TEXT,
                    acknowledged_at TEXT,
                    renewal_instructions TEXT,
                    impact_assessment TEXT,
                    FOREIGN KEY (certificate_id) REFERENCES monitored_certificates (certificate_id)
                )
            ''')
            
            conn.execute('''
                CREATE TABLE IF NOT EXISTS monitoring_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    event_type TEXT NOT NULL,
                    certificate_id TEXT,
                    details TEXT,
                    severity TEXT DEFAULT 'info'
                )
            ''')
            
            # Create indexes
            conn.execute('CREATE INDEX IF NOT EXISTS idx_cert_expiration ON monitored_certificates(expiration_date)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_cert_status ON monitored_certificates(status)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_alert_severity ON expiration_alerts(severity)')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_alert_status ON expiration_alerts(status)')
            
            conn.commit()
        
        logger.debug("Monitoring database initialized")
    
    def add_certificate_for_monitoring(self, certificate: x509.Certificate,
                                     certificate_metadata: Dict[str, Any] = None,
                                     file_path: str = None) -> str:
        """
        Add certificate to monitoring system.
        
        Args:
            certificate: X.509 certificate to monitor
            certificate_metadata: Additional metadata about certificate
            file_path: Path to certificate file
            
        Returns:
            Certificate ID for tracking
        """
        try:
            # Generate certificate ID
            cert_der = certificate.public_bytes(serialization.Encoding.DER)
            certificate_id = f"cert_{hash(cert_der) & 0x7FFFFFFF:08x}"
            
            # Extract basic information
            subject_dn = certificate.subject.rfc4514_string()
            issuer_dn = certificate.issuer.rfc4514_string()
            serial_number = str(certificate.serial_number)
            fingerprint_sha256 = hashlib.sha256(cert_der).hexdigest()
            expiration_date = certificate.not_valid_after
            
            # Determine certificate type
            certificate_type = "end_entity"
            is_ca = False
            
            try:
                basic_constraints = certificate.extensions.get_extension_for_oid(
                    x509.oid.ExtensionOID.BASIC_CONSTRAINTS
                )
                if basic_constraints.value.ca:
                    certificate_type = "ca_certificate"
                    is_ca = True
            except x509.ExtensionNotFound:
                pass
            
            # Extract key usage
            key_usage = []
            try:
                key_usage_ext = certificate.extensions.get_extension_for_oid(
                    x509.oid.ExtensionOID.KEY_USAGE
                )
                ku = key_usage_ext.value
                if ku.digital_signature: key_usage.append("digital_signature")
                if ku.key_encipherment: key_usage.append("key_encipherment")
                if ku.key_cert_sign: key_usage.append("key_cert_sign")
            except x509.ExtensionNotFound:
                pass
            
            # Extract DoD identifiers if available
            edipi = None
            dod_id = None
            
            if certificate_metadata:
                edipi = certificate_metadata.get('edipi')
                dod_id = certificate_metadata.get('dod_id')
                certificate_type = certificate_metadata.get('certificate_type', certificate_type)
            
            # Store in database
            with sqlite3.connect(self.database_path) as conn:
                conn.execute('''
                    INSERT OR REPLACE INTO monitored_certificates (
                        certificate_id, subject_dn, issuer_dn, serial_number, fingerprint_sha256,
                        expiration_date, certificate_type, key_usage, edipi, dod_id, file_path,
                        is_ca_certificate, last_checked, status
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    certificate_id, subject_dn, issuer_dn, serial_number, fingerprint_sha256,
                    expiration_date.isoformat(), certificate_type, json.dumps(key_usage),
                    edipi, dod_id, file_path, is_ca, 
                    datetime.now(timezone.utc).isoformat(), "valid"
                ))
                conn.commit()
            
            # Log the addition
            self._log_event("certificate_added", certificate_id, 
                          f"Added certificate for monitoring: {subject_dn}")
            
            logger.info(f"Added certificate to monitoring: {subject_dn}")
            return certificate_id
            
        except Exception as e:
            logger.error(f"Failed to add certificate for monitoring: {e}")
            raise
    
    def start_monitoring(self):
        """Start background monitoring."""
        if self.is_monitoring:
            logger.warning("Monitoring is already running")
            return
        
        self.is_monitoring = True
        self._shutdown_event.clear()
        
        # Start monitoring thread
        self._monitor_thread = threading.Thread(target=self._monitoring_worker, daemon=True)
        self._monitor_thread.start()
        
        logger.info("Certificate expiration monitoring started")
    
    def stop_monitoring(self):
        """Stop background monitoring."""
        if not self.is_monitoring:
            return
        
        self.is_monitoring = False
        self._shutdown_event.set()
        
        if self._monitor_thread and self._monitor_thread.is_alive():
            self._monitor_thread.join(timeout=10)
        
        logger.info("Certificate expiration monitoring stopped")
    
    def _monitoring_worker(self):
        """Background monitoring worker."""
        while not self._shutdown_event.is_set():
            try:
                # Perform monitoring check
                self.check_expirations()
                
                # Determine next check interval
                has_critical_alerts = self._has_critical_alerts()
                interval_hours = (self.config.urgent_check_interval_hours if has_critical_alerts 
                                else self.config.check_interval_hours)
                
                # Wait for next check
                self._shutdown_event.wait(interval_hours * 3600)
                
            except Exception as e:
                logger.error(f"Error in monitoring worker: {e}")
                # Wait a bit before retrying
                self._shutdown_event.wait(300)  # 5 minutes
    
    def check_expirations(self) -> List[ExpirationAlert]:
        """
        Check for certificate expirations and generate alerts.
        
        Returns:
            List of generated alerts
        """
        alerts = []
        current_time = datetime.now(timezone.utc)
        
        try:
            with sqlite3.connect(self.database_path) as conn:
                conn.row_factory = sqlite3.Row
                
                # Get all monitored certificates
                cursor = conn.execute('''
                    SELECT * FROM monitored_certificates 
                    WHERE is_monitored = 1
                    ORDER BY expiration_date ASC
                ''')
                
                certificates = cursor.fetchall()
                self._stats['total_certificates'] = len(certificates)
                monitored_count = 0
                
                for cert_row in certificates:
                    try:
                        # Skip if not monitoring this type
                        if (cert_row['is_ca_certificate'] and not self.config.monitor_ca_certificates):
                            continue
                        if (not cert_row['is_ca_certificate'] and not self.config.monitor_end_entity_certificates):
                            continue
                        
                        monitored_count += 1
                        
                        # Calculate days until expiration
                        expiration_date = datetime.fromisoformat(cert_row['expiration_date'])
                        days_until_expiry = (expiration_date - current_time).days
                        
                        # Determine status and severity
                        status = self._determine_certificate_status(days_until_expiry)
                        severity = self._determine_alert_severity(days_until_expiry)
                        
                        # Update certificate status in database
                        conn.execute('''
                            UPDATE monitored_certificates 
                            SET status = ?, last_checked = ?
                            WHERE certificate_id = ?
                        ''', (status.value, current_time.isoformat(), cert_row['certificate_id']))
                        
                        # Generate alert if needed
                        if severity and self._should_generate_alert(cert_row, severity, days_until_expiry):
                            alert = self._create_expiration_alert(cert_row, severity, status, days_until_expiry)
                            alerts.append(alert)
                            
                            # Store alert in database
                            self._store_alert(alert)
                            
                            # Send notifications
                            self._send_alert_notifications(alert)
                        
                    except Exception as e:
                        logger.warning(f"Error checking certificate {cert_row['certificate_id']}: {e}")
                
                self._stats['monitored_certificates'] = monitored_count
                self._stats['last_check'] = current_time.isoformat()
                
                conn.commit()
            
            # Update active alerts count
            with self._alert_lock:
                self._stats['active_alerts'] = len([a for a in self._active_alerts.values() 
                                                   if not a.acknowledged])
            
            # Log monitoring completion
            self._log_event("monitoring_check", None, 
                          f"Checked {monitored_count} certificates, generated {len(alerts)} alerts")
            
            logger.info(f"Expiration check completed: {monitored_count} certificates, {len(alerts)} alerts")
            return alerts
            
        except Exception as e:
            logger.error(f"Error during expiration check: {e}")
            return []
    
    def _determine_certificate_status(self, days_until_expiry: int) -> CertificateStatus:
        """Determine certificate status based on expiration."""
        if days_until_expiry < 0:
            return CertificateStatus.EXPIRED
        elif days_until_expiry <= self.config.critical_threshold:
            return CertificateStatus.EXPIRING_SOON
        else:
            return CertificateStatus.VALID
    
    def _determine_alert_severity(self, days_until_expiry: int) -> Optional[AlertSeverity]:
        """Determine alert severity based on days until expiration."""
        if days_until_expiry < 0:
            return AlertSeverity.EMERGENCY
        elif days_until_expiry <= self.config.critical_threshold:
            return AlertSeverity.CRITICAL
        elif days_until_expiry <= self.config.warning_threshold:
            return AlertSeverity.WARNING
        elif days_until_expiry <= self.config.info_threshold:
            return AlertSeverity.INFO
        else:
            return None
    
    def _should_generate_alert(self, cert_row, severity: AlertSeverity, days_until_expiry: int) -> bool:
        """Determine if an alert should be generated."""
        certificate_id = cert_row['certificate_id']
        
        # Check if we already have an active alert for this certificate
        with self._alert_lock:
            if certificate_id in self._active_alerts:
                existing_alert = self._active_alerts[certificate_id]
                
                # Don't generate if already acknowledged
                if existing_alert.acknowledged:
                    return False
                
                # Check if severity has increased
                severity_order = [AlertSeverity.INFO, AlertSeverity.WARNING, 
                                AlertSeverity.CRITICAL, AlertSeverity.EMERGENCY]
                current_severity_level = severity_order.index(severity)
                existing_severity_level = severity_order.index(existing_alert.severity)
                
                # Only generate if severity increased or it's been a while since last alert
                if current_severity_level <= existing_severity_level:
                    last_sent = existing_alert.last_sent
                    if last_sent:
                        hours_since_last = (datetime.now(timezone.utc) - last_sent).total_seconds() / 3600
                        # Re-alert based on severity
                        if severity == AlertSeverity.CRITICAL and hours_since_last < 24:
                            return False
                        elif severity == AlertSeverity.WARNING and hours_since_last < 168:  # 1 week
                            return False
                        elif severity == AlertSeverity.INFO and hours_since_last < 720:  # 30 days
                            return False
        
        return True
    
    def _create_expiration_alert(self, cert_row, severity: AlertSeverity, 
                               status: CertificateStatus, days_until_expiry: int) -> ExpirationAlert:
        """Create expiration alert object."""
        import uuid
        
        alert_id = f"alert_{uuid.uuid4().hex[:8]}"
        
        # Extract key usage from JSON
        key_usage = []
        try:
            if cert_row['key_usage']:
                key_usage = json.loads(cert_row['key_usage'])
        except:
            pass
        
        # Determine renewal instructions based on certificate type
        renewal_instructions = self._get_renewal_instructions(cert_row, severity)
        impact_assessment = self._get_impact_assessment(cert_row, days_until_expiry)
        
        alert = ExpirationAlert(
            alert_id=alert_id,
            certificate_id=cert_row['certificate_id'],
            subject_dn=cert_row['subject_dn'],
            issuer_dn=cert_row['issuer_dn'],
            serial_number=cert_row['serial_number'],
            expiration_date=datetime.fromisoformat(cert_row['expiration_date']),
            days_until_expiry=days_until_expiry,
            severity=severity,
            status=status,
            certificate_type=cert_row['certificate_type'],
            key_usage=key_usage,
            edipi=cert_row['edipi'],
            dod_id=cert_row['dod_id'],
            renewal_instructions=renewal_instructions,
            impact_assessment=impact_assessment
        )
        
        # Store in active alerts
        with self._alert_lock:
            self._active_alerts[cert_row['certificate_id']] = alert
        
        return alert
    
    def _get_renewal_instructions(self, cert_row, severity: AlertSeverity) -> str:
        """Get certificate-specific renewal instructions."""
        cert_type = cert_row['certificate_type']
        subject_dn = cert_row['subject_dn']
        
        if "DoD" in subject_dn or cert_row['edipi']:
            # DoD certificate renewal
            if "Root CA" in subject_dn:
                return ("DoD Root CA renewal requires coordination with DoD PKI office. "
                       "Contact DoD PKI management for renewal procedures.")
            elif cert_type == "ca_certificate":
                return ("DoD Intermediate CA renewal requires submission to DoD PKI office. "
                       "Ensure all subordinate certificates are updated after renewal.")
            else:
                return ("CAC/PIV certificate renewal:\n"
                       "1. Visit your local RAPIDS ID Card Office\n"
                       "2. Bring two forms of ID and current CAC\n"
                       "3. Complete renewal application\n"
                       "4. Update certificates in all applications")
        else:
            # Commercial certificate renewal
            return ("Commercial certificate renewal:\n"
                   "1. Contact certificate authority or issuer\n"
                   "2. Generate new certificate signing request (CSR)\n"
                   "3. Submit renewal request with payment\n"
                   "4. Install new certificate before expiration")
    
    def _get_impact_assessment(self, cert_row, days_until_expiry: int) -> str:
        """Assess impact of certificate expiration."""
        cert_type = cert_row['certificate_type']
        key_usage = []
        
        try:
            if cert_row['key_usage']:
                key_usage = json.loads(cert_row['key_usage'])
        except:
            pass
        
        impact_parts = []
        
        if cert_type == "ca_certificate":
            impact_parts.append("CA certificate expiration will invalidate all subordinate certificates")
        
        if "digital_signature" in key_usage:
            impact_parts.append("Loss of digital signature capability")
        
        if "key_encipherment" in key_usage:
            impact_parts.append("Loss of encryption/decryption capability")
        
        if days_until_expiry < 0:
            impact_parts.append("Certificate has already expired - immediate action required")
        elif days_until_expiry <= 7:
            impact_parts.append("Critical: Certificate expires within one week")
        
        if cert_row['edipi']:
            impact_parts.append("DoD user authentication will be affected")
        
        return ". ".join(impact_parts) if impact_parts else "Standard certificate expiration impact"
    
    def _store_alert(self, alert: ExpirationAlert):
        """Store alert in database."""
        with sqlite3.connect(self.database_path) as conn:
            conn.execute('''
                INSERT OR REPLACE INTO expiration_alerts (
                    alert_id, certificate_id, severity, status, days_until_expiry,
                    created_at, renewal_instructions, impact_assessment
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                alert.alert_id, alert.certificate_id, alert.severity.value, alert.status.value,
                alert.days_until_expiry, alert.created_at.isoformat(),
                alert.renewal_instructions, alert.impact_assessment
            ))
            conn.commit()
    
    def _send_alert_notifications(self, alert: ExpirationAlert):
        """Send alert notifications via configured channels."""
        try:
            # Determine recipients based on severity
            recipients = self.config.default_recipients.copy()
            if alert.severity in [AlertSeverity.CRITICAL, AlertSeverity.EMERGENCY]:
                recipients.extend(self.config.critical_recipients)
            
            # Remove duplicates
            recipients = list(set(recipients))
            
            if not recipients:
                logger.warning(f"No recipients configured for alert {alert.alert_id}")
                return
            
            # Send email notifications
            if self.config.enable_email_alerts and recipients:
                self._send_email_alert(alert, recipients)
            
            # Send webhook notifications
            if self.config.enable_webhook_alerts and self.config.webhook_urls:
                self._send_webhook_alert(alert)
            
            # Update alert send tracking
            alert.last_sent = datetime.now(timezone.utc)
            alert.send_count += 1
            
            # Update database
            with sqlite3.connect(self.database_path) as conn:
                conn.execute('''
                    UPDATE expiration_alerts 
                    SET last_sent = ?, send_count = ?
                    WHERE alert_id = ?
                ''', (alert.last_sent.isoformat(), alert.send_count, alert.alert_id))
                conn.commit()
            
            self._stats['alerts_sent'] += 1
            
        except Exception as e:
            logger.error(f"Failed to send alert notifications: {e}")
    
    def _send_email_alert(self, alert: ExpirationAlert, recipients: List[str]):
        """Send email alert notification."""
        try:
            # Create message
            msg = MIMEMultipart('alternative')
            msg['Subject'] = f"[{alert.severity.value.upper()}] Certificate Expiration Alert"
            msg['From'] = self.config.smtp_username
            msg['To'] = ', '.join(recipients)
            
            # Create email content
            text_content = self._create_text_alert_content(alert)
            html_content = self._create_html_alert_content(alert)
            
            # Attach content
            msg.attach(MIMEText(text_content, 'plain'))
            msg.attach(MIMEText(html_content, 'html'))
            
            # Send email
            context = ssl.create_default_context()
            with smtplib.SMTP(self.config.smtp_server, self.config.smtp_port) as server:
                if self.config.smtp_use_tls:
                    server.starttls(context=context)
                server.login(self.config.smtp_username, self.config.smtp_password)
                server.send_message(msg)
            
            logger.info(f"Email alert sent for certificate {alert.certificate_id}")
            
        except Exception as e:
            logger.error(f"Failed to send email alert: {e}")
    
    def _create_text_alert_content(self, alert: ExpirationAlert) -> str:
        """Create plain text alert content."""
        content = f"""
Certificate Expiration Alert - {alert.severity.value.upper()}

Certificate Details:
- Subject: {alert.subject_dn}
- Serial Number: {alert.serial_number}
- Expiration Date: {alert.expiration_date.strftime('%Y-%m-%d %H:%M:%S UTC')}
- Days Until Expiry: {alert.days_until_expiry}
- Status: {alert.status.value}

Certificate Information:
- Type: {alert.certificate_type}
- Key Usage: {', '.join(alert.key_usage)}
"""
        
        if alert.edipi:
            content += f"- EDIPI: {alert.edipi}\n"
        
        if alert.dod_id:
            content += f"- DoD ID: {alert.dod_id}\n"
        
        content += f"""
Impact Assessment:
{alert.impact_assessment}

Renewal Instructions:
{alert.renewal_instructions}

Alert ID: {alert.alert_id}
Generated: {alert.created_at.strftime('%Y-%m-%d %H:%M:%S UTC')}
"""
        
        return content
    
    def _create_html_alert_content(self, alert: ExpirationAlert) -> str:
        """Create HTML alert content."""
        severity_colors = {
            AlertSeverity.INFO: "#3498db",
            AlertSeverity.WARNING: "#f39c12", 
            AlertSeverity.CRITICAL: "#e74c3c",
            AlertSeverity.EMERGENCY: "#8e44ad"
        }
        
        color = severity_colors.get(alert.severity, "#3498db")
        
        html_content = f"""
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .header {{ background-color: {color}; color: white; padding: 15px; border-radius: 5px; }}
                .content {{ margin: 20px 0; }}
                .section {{ margin: 15px 0; }}
                .field {{ margin: 5px 0; }}
                .label {{ font-weight: bold; }}
                .value {{ margin-left: 10px; }}
                .instructions {{ background-color: #f8f9fa; padding: 15px; border-radius: 5px; white-space: pre-line; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h2>Certificate Expiration Alert - {alert.severity.value.upper()}</h2>
            </div>
            
            <div class="content">
                <div class="section">
                    <h3>Certificate Details</h3>
                    <div class="field"><span class="label">Subject:</span><span class="value">{alert.subject_dn}</span></div>
                    <div class="field"><span class="label">Serial Number:</span><span class="value">{alert.serial_number}</span></div>
                    <div class="field"><span class="label">Expiration Date:</span><span class="value">{alert.expiration_date.strftime('%Y-%m-%d %H:%M:%S UTC')}</span></div>
                    <div class="field"><span class="label">Days Until Expiry:</span><span class="value">{alert.days_until_expiry}</span></div>
                    <div class="field"><span class="label">Status:</span><span class="value">{alert.status.value}</span></div>
                </div>
                
                <div class="section">
                    <h3>Certificate Information</h3>
                    <div class="field"><span class="label">Type:</span><span class="value">{alert.certificate_type}</span></div>
                    <div class="field"><span class="label">Key Usage:</span><span class="value">{', '.join(alert.key_usage)}</span></div>
        """
        
        if alert.edipi:
            html_content += f'<div class="field"><span class="label">EDIPI:</span><span class="value">{alert.edipi}</span></div>'
        
        if alert.dod_id:
            html_content += f'<div class="field"><span class="label">DoD ID:</span><span class="value">{alert.dod_id}</span></div>'
        
        html_content += f"""
                </div>
                
                <div class="section">
                    <h3>Impact Assessment</h3>
                    <div class="instructions">{alert.impact_assessment}</div>
                </div>
                
                <div class="section">
                    <h3>Renewal Instructions</h3>
                    <div class="instructions">{alert.renewal_instructions}</div>
                </div>
                
                <div class="section">
                    <small>
                        Alert ID: {alert.alert_id}<br>
                        Generated: {alert.created_at.strftime('%Y-%m-%d %H:%M:%S UTC')}
                    </small>
                </div>
            </div>
        </body>
        </html>
        """
        
        return html_content
    
    def _send_webhook_alert(self, alert: ExpirationAlert):
        """Send webhook alert notification."""
        for webhook_url in self.config.webhook_urls:
            try:
                payload = {
                    'alert_id': alert.alert_id,
                    'certificate_id': alert.certificate_id,
                    'severity': alert.severity.value,
                    'status': alert.status.value,
                    'subject_dn': alert.subject_dn,
                    'days_until_expiry': alert.days_until_expiry,
                    'expiration_date': alert.expiration_date.isoformat(),
                    'created_at': alert.created_at.isoformat(),
                    'impact_assessment': alert.impact_assessment,
                    'renewal_instructions': alert.renewal_instructions
                }
                
                headers = {'Content-Type': 'application/json'}
                headers.update(self.config.webhook_auth_headers)
                
                response = requests.post(
                    webhook_url,
                    json=payload,
                    headers=headers,
                    timeout=30
                )
                response.raise_for_status()
                
                logger.info(f"Webhook alert sent to {webhook_url}")
                
            except Exception as e:
                logger.error(f"Failed to send webhook alert to {webhook_url}: {e}")
    
    def _has_critical_alerts(self) -> bool:
        """Check if there are any critical alerts."""
        with self._alert_lock:
            return any(alert.severity in [AlertSeverity.CRITICAL, AlertSeverity.EMERGENCY] 
                      and not alert.acknowledged 
                      for alert in self._active_alerts.values())
    
    def get_active_alerts(self, severity: AlertSeverity = None) -> List[ExpirationAlert]:
        """Get list of active alerts."""
        with self._alert_lock:
            alerts = list(self._active_alerts.values())
            
            if severity:
                alerts = [alert for alert in alerts if alert.severity == severity]
            
            # Filter out acknowledged alerts
            alerts = [alert for alert in alerts if not alert.acknowledged]
            
            # Sort by severity and days until expiry
            severity_order = {
                AlertSeverity.EMERGENCY: 0,
                AlertSeverity.CRITICAL: 1,
                AlertSeverity.WARNING: 2,
                AlertSeverity.INFO: 3
            }
            
            alerts.sort(key=lambda a: (severity_order[a.severity], a.days_until_expiry))
            
            return alerts
    
    def acknowledge_alert(self, alert_id: str, acknowledged_by: str) -> bool:
        """Acknowledge an alert."""
        try:
            with self._alert_lock:
                # Find alert
                alert = None
                for cert_alert in self._active_alerts.values():
                    if cert_alert.alert_id == alert_id:
                        alert = cert_alert
                        break
                
                if not alert:
                    logger.warning(f"Alert {alert_id} not found")
                    return False
                
                # Mark as acknowledged
                alert.acknowledged = True
                alert.acknowledged_by = acknowledged_by
                alert.acknowledged_at = datetime.now(timezone.utc)
            
            # Update database
            with sqlite3.connect(self.database_path) as conn:
                conn.execute('''
                    UPDATE expiration_alerts 
                    SET acknowledged = 1, acknowledged_by = ?, acknowledged_at = ?
                    WHERE alert_id = ?
                ''', (acknowledged_by, alert.acknowledged_at.isoformat(), alert_id))
                conn.commit()
            
            logger.info(f"Alert {alert_id} acknowledged by {acknowledged_by}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to acknowledge alert {alert_id}: {e}")
            return False
    
    def get_monitoring_statistics(self) -> Dict[str, Any]:
        """Get monitoring statistics."""
        stats = dict(self._stats)
        
        # Add database statistics
        try:
            with sqlite3.connect(self.database_path) as conn:
                cursor = conn.execute('SELECT COUNT(*) FROM monitored_certificates')
                stats['total_in_database'] = cursor.fetchone()[0]
                
                cursor = conn.execute('SELECT COUNT(*) FROM expiration_alerts WHERE acknowledged = 0')
                stats['unacknowledged_alerts'] = cursor.fetchone()[0]
                
                cursor = conn.execute('''
                    SELECT severity, COUNT(*) FROM expiration_alerts 
                    WHERE acknowledged = 0 
                    GROUP BY severity
                ''')
                severity_counts = dict(cursor.fetchall())
                stats['alerts_by_severity'] = severity_counts
        except Exception as e:
            logger.warning(f"Error getting database statistics: {e}")
        
        stats['is_monitoring'] = self.is_monitoring
        stats['config'] = asdict(self.config)
        
        return stats
    
    def _log_event(self, event_type: str, certificate_id: str = None, 
                  details: str = "", severity: str = "info"):
        """Log monitoring event."""
        try:
            with sqlite3.connect(self.database_path) as conn:
                conn.execute('''
                    INSERT INTO monitoring_log (event_type, certificate_id, details, severity)
                    VALUES (?, ?, ?, ?)
                ''', (event_type, certificate_id, details, severity))
                conn.commit()
        except Exception as e:
            logger.warning(f"Failed to log event: {e}")
    
    def _setup_notification_handlers(self):
        """Setup notification handlers."""
        # Email handler is built-in
        # Additional handlers can be registered here
        pass
    
    def cleanup(self):
        """Cleanup resources."""
        self.stop_monitoring()
        logger.info("Expiration monitor cleanup completed")


# Example usage
def main():
    """Example usage of expiration monitor."""
    # Create configuration
    config = MonitoringConfiguration(
        critical_threshold=7,
        warning_threshold=30,
        enable_email_alerts=False,  # Disabled for example
        check_interval_hours=1  # Check every hour for demo
    )
    
    # Initialize monitor
    monitor = ExpirationMonitor(config)
    
    # Get statistics
    stats = monitor.get_monitoring_statistics()
    print(f"Monitoring statistics: {stats}")
    
    # Check for expirations
    alerts = monitor.check_expirations()
    print(f"Generated {len(alerts)} alerts")
    
    # Get active alerts
    active_alerts = monitor.get_active_alerts()
    print(f"Active alerts: {len(active_alerts)}")
    
    monitor.cleanup()


if __name__ == "__main__":
    import hashlib
    main()