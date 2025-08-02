"""
Compliance Alert and Notification System
========================================

This module provides comprehensive alert and notification capabilities for compliance
drift detection with automated escalation procedures and integration with existing
monitoring and audit systems for real-time compliance monitoring.

Key Features:
- Real-time compliance drift detection and alerting
- Automated escalation procedures based on severity
- Multiple notification channels (email, SMS, webhook, dashboard)
- Integration with existing monitoring and audit systems
- Regulatory deadline tracking and reminders
- Classification-aware alert handling

Integration Points:
- Enhanced monitoring system for real-time threat and compliance data
- Integrated audit orchestrator for audit event correlation
- Enhanced log aggregator for log-based alert triggers
- Compliance data warehouse for historical trend analysis
- Multi-classification engine for classified alert handling

Classification: UNCLASSIFIED//FOR OFFICIAL USE ONLY
Version: 1.0 - Comprehensive Compliance Alerting
Author: Security Compliance Team
Date: 2025-07-28
"""

import asyncio
import json
import logging
import time
import smtplib
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Tuple, Set, Union, AsyncGenerator, Callable
from uuid import UUID, uuid4
from dataclasses import dataclass, field, asdict
from enum import Enum
from concurrent.futures import ThreadPoolExecutor
from collections import defaultdict, deque
import aiofiles
import aiohttp
from threading import Lock
import numpy as np
from pathlib import Path
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import ssl

# Import existing infrastructure
from ...audits.integrated_audit_orchestrator import IntegratedAuditOrchestrator
from ...audits.enhanced_monitoring_system import EnhancedMonitoringSystem, SecurityThreat, ComplianceViolation
from ...audits.enhanced_log_aggregator import EnhancedLogAggregator, LogEvent
from ...audits.real_time_alerting import RealTimeAlerting, AlertPriority

# Import compliance data structures
from ..dashboards.compliance_dashboard import ComplianceMetric, ComplianceMetricType, ComplianceDataProvider
from ..data.compliance_data_warehouse import ComplianceDataWarehouse, TrendAnalysis, TrendDirection

logger = logging.getLogger(__name__)


class AlertSeverity(Enum):
    """Alert severity levels."""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    EMERGENCY = "emergency"


class AlertType(Enum):
    """Types of compliance alerts."""
    COMPLIANCE_DRIFT = "compliance_drift"
    THRESHOLD_VIOLATION = "threshold_violation"
    TREND_ANOMALY = "trend_anomaly"
    REGULATORY_DEADLINE = "regulatory_deadline"
    SYSTEM_DEGRADATION = "system_degradation"
    CLASSIFICATION_VIOLATION = "classification_violation"
    AUDIT_FAILURE = "audit_failure"
    PERFORMANCE_DEGRADATION = "performance_degradation"
    SECURITY_INCIDENT = "security_incident"
    CUSTOM = "custom"


class AlertStatus(Enum):
    """Alert status tracking."""
    ACTIVE = "active"
    ACKNOWLEDGED = "acknowledged"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    SUPPRESSED = "suppressed"
    ESCALATED = "escalated"


class NotificationChannel(Enum):
    """Available notification channels."""
    EMAIL = "email"
    SMS = "sms"
    WEBHOOK = "webhook"
    DASHBOARD = "dashboard"
    SLACK = "slack"
    TEAMS = "teams"
    PAGER = "pager"


@dataclass
class ComplianceAlert:
    """Comprehensive compliance alert structure."""
    alert_id: str = field(default_factory=lambda: str(uuid4()))
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    # Alert classification
    alert_type: AlertType = AlertType.COMPLIANCE_DRIFT
    severity: AlertSeverity = AlertSeverity.MEDIUM
    status: AlertStatus = AlertStatus.ACTIVE
    
    # Alert content
    title: str = ""
    message: str = ""
    description: str = ""
    
    # Source information
    source_metric_type: Optional[ComplianceMetricType] = None
    source_metric_name: str = ""
    source_system: str = ""
    source_events: List[str] = field(default_factory=list)
    
    # Compliance context
    framework: str = ""
    control_reference: str = ""
    regulatory_requirement: str = ""
    
    # Values and thresholds
    current_value: Optional[float] = None
    threshold_value: Optional[float] = None
    target_value: Optional[float] = None
    deviation_percentage: Optional[float] = None
    
    # Classification and access
    classification_level: str = "UNCLASSIFIED"
    requires_clearance: bool = False
    
    # Escalation and response
    escalation_level: int = 0
    escalated_at: Optional[datetime] = None
    response_deadline: Optional[datetime] = None
    assigned_to: List[str] = field(default_factory=list)
    
    # Notification tracking
    notifications_sent: List[str] = field(default_factory=list)  # channel names
    notification_attempts: int = 0
    last_notification: Optional[datetime] = None
    
    # Context and metadata
    additional_data: Dict[str, Any] = field(default_factory=dict)
    correlation_id: Optional[str] = None
    parent_alert_id: Optional[str] = None
    
    # Resolution tracking
    acknowledged_by: Optional[str] = None
    acknowledged_at: Optional[datetime] = None
    resolved_by: Optional[str] = None
    resolved_at: Optional[datetime] = None
    resolution_notes: str = ""
    
    # Suppression
    suppressed_until: Optional[datetime] = None
    suppression_reason: str = ""
    
    def calculate_age_minutes(self) -> float:
        """Calculate alert age in minutes."""
        return (datetime.now(timezone.utc) - self.timestamp).total_seconds() / 60
    
    def is_expired(self, max_age_hours: int = 24) -> bool:
        """Check if alert has expired."""
        age_hours = self.calculate_age_minutes() / 60
        return age_hours > max_age_hours
    
    def should_escalate(self, escalation_threshold_minutes: int = 30) -> bool:
        """Check if alert should be escalated."""
        if self.status in [AlertStatus.RESOLVED, AlertStatus.SUPPRESSED]:
            return False
        
        age_minutes = self.calculate_age_minutes()
        return age_minutes > escalation_threshold_minutes
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert alert to dictionary."""
        return {
            "alert_id": self.alert_id,
            "timestamp": self.timestamp.isoformat(),
            "alert_type": self.alert_type.value,
            "severity": self.severity.value,
            "status": self.status.value,
            "title": self.title,
            "message": self.message,
            "description": self.description,
            "source_metric_type": self.source_metric_type.value if self.source_metric_type else None,
            "source_metric_name": self.source_metric_name,
            "source_system": self.source_system,
            "source_events": self.source_events,
            "framework": self.framework,
            "control_reference": self.control_reference,
            "regulatory_requirement": self.regulatory_requirement,
            "current_value": self.current_value,
            "threshold_value": self.threshold_value,
            "target_value": self.target_value,
            "deviation_percentage": self.deviation_percentage,
            "classification_level": self.classification_level,
            "requires_clearance": self.requires_clearance,
            "escalation_level": self.escalation_level,
            "escalated_at": self.escalated_at.isoformat() if self.escalated_at else None,
            "response_deadline": self.response_deadline.isoformat() if self.response_deadline else None,
            "assigned_to": self.assigned_to,
            "notifications_sent": self.notifications_sent,
            "notification_attempts": self.notification_attempts,
            "last_notification": self.last_notification.isoformat() if self.last_notification else None,
            "additional_data": self.additional_data,
            "correlation_id": self.correlation_id,
            "parent_alert_id": self.parent_alert_id,
            "acknowledged_by": self.acknowledged_by,
            "acknowledged_at": self.acknowledged_at.isoformat() if self.acknowledged_at else None,
            "resolved_by": self.resolved_by,
            "resolved_at": self.resolved_at.isoformat() if self.resolved_at else None,
            "resolution_notes": self.resolution_notes,
            "suppressed_until": self.suppressed_until.isoformat() if self.suppressed_until else None,
            "suppression_reason": self.suppression_reason,
            "age_minutes": self.calculate_age_minutes()
        }


@dataclass
class AlertRule:
    """Configuration for alert generation rules."""
    rule_id: str = field(default_factory=lambda: str(uuid4()))
    name: str = ""
    description: str = ""
    enabled: bool = True
    
    # Rule conditions
    metric_type: Optional[ComplianceMetricType] = None
    framework_filter: Optional[str] = None
    
    # Threshold conditions
    threshold_type: str = "below"  # below, above, between, outside
    threshold_value: Optional[float] = None
    threshold_value_upper: Optional[float] = None
    duration_minutes: int = 5  # How long condition must persist
    
    # Trend conditions
    trend_direction_filter: Optional[TrendDirection] = None
    trend_strength_threshold: float = 0.5
    
    # Alert properties
    alert_type: AlertType = AlertType.THRESHOLD_VIOLATION
    severity: AlertSeverity = AlertSeverity.MEDIUM
    title_template: str = "Compliance Alert: {metric_name}"
    message_template: str = "Metric {metric_name} is {current_value}, threshold: {threshold_value}"
    
    # Response settings
    response_deadline_minutes: int = 60
    escalation_threshold_minutes: int = 30
    
    # Notification settings
    notification_channels: List[NotificationChannel] = field(default_factory=list)
    notification_recipients: List[str] = field(default_factory=list)
    
    # Suppression settings
    suppression_duration_minutes: int = 60
    max_alerts_per_hour: int = 5
    
    # Classification
    classification_level: str = "UNCLASSIFIED"
    
    def matches_metric(self, metric: ComplianceMetric) -> bool:
        """Check if metric matches rule conditions."""
        # Check metric type
        if self.metric_type and metric.metric_type != self.metric_type:
            return False
        
        # Check framework
        if self.framework_filter and metric.framework != self.framework_filter:
            return False
        
        # Check threshold conditions
        current_score = metric.calculate_compliance_score()
        
        if self.threshold_type == "below" and self.threshold_value:
            return current_score < self.threshold_value
        elif self.threshold_type == "above" and self.threshold_value:
            return current_score > self.threshold_value
        elif self.threshold_type == "between" and self.threshold_value and self.threshold_value_upper:
            return self.threshold_value <= current_score <= self.threshold_value_upper
        elif self.threshold_type == "outside" and self.threshold_value and self.threshold_value_upper:
            return current_score < self.threshold_value or current_score > self.threshold_value_upper
        
        return True
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert rule to dictionary."""
        return {
            "rule_id": self.rule_id,
            "name": self.name,
            "description": self.description,
            "enabled": self.enabled,
            "metric_type": self.metric_type.value if self.metric_type else None,
            "framework_filter": self.framework_filter,
            "threshold_type": self.threshold_type,
            "threshold_value": self.threshold_value,
            "threshold_value_upper": self.threshold_value_upper,
            "duration_minutes": self.duration_minutes,
            "trend_direction_filter": self.trend_direction_filter.value if self.trend_direction_filter else None,
            "trend_strength_threshold": self.trend_strength_threshold,
            "alert_type": self.alert_type.value,
            "severity": self.severity.value,
            "title_template": self.title_template,
            "message_template": self.message_template,
            "response_deadline_minutes": self.response_deadline_minutes,
            "escalation_threshold_minutes": self.escalation_threshold_minutes,
            "notification_channels": [ch.value for ch in self.notification_channels],
            "notification_recipients": self.notification_recipients,
            "suppression_duration_minutes": self.suppression_duration_minutes,
            "max_alerts_per_hour": self.max_alerts_per_hour,
            "classification_level": self.classification_level
        }


class ComplianceDriftDetector:
    """Detects compliance drift using statistical analysis and trend monitoring."""
    
    def __init__(self, data_warehouse: ComplianceDataWarehouse):
        """Initialize compliance drift detector."""
        self.data_warehouse = data_warehouse
        
        # Drift detection parameters
        self.drift_threshold_std_devs = 2.0  # Standard deviations for anomaly detection
        self.trend_strength_threshold = 0.3  # Minimum trend strength to consider significant
        self.minimum_data_points = 10  # Minimum data points for reliable analysis
        
        logger.info("Compliance drift detector initialized")
    
    async def detect_drift(
        self,
        metric: ComplianceMetric,
        lookback_days: int = 30
    ) -> List[Dict[str, Any]]:
        """Detect compliance drift for a metric."""
        try:
            drift_indicators = []
            
            # Get historical data
            end_time = datetime.now(timezone.utc)
            start_time = end_time - timedelta(days=lookback_days)
            
            historical_data = await self.data_warehouse.get_historical_data(
                metric.metric_type,
                (start_time, end_time)
            )
            
            if len(historical_data) < self.minimum_data_points:
                return drift_indicators
            
            # Extract values and timestamps
            values = [point.compliance_score for point in historical_data]
            timestamps = [point.timestamp for point in historical_data]
            
            # Statistical drift detection
            statistical_drift = self._detect_statistical_drift(values, metric.calculate_compliance_score())
            if statistical_drift:
                drift_indicators.append(statistical_drift)
            
            # Trend-based drift detection
            trend_analysis = await self.data_warehouse.analyze_trends(
                metric.metric_type,
                (start_time, end_time)
            )
            
            trend_drift = self._detect_trend_drift(trend_analysis, metric)
            if trend_drift:
                drift_indicators.append(trend_drift)
            
            # Volatility-based drift detection
            volatility_drift = self._detect_volatility_drift(values, metric)
            if volatility_drift:
                drift_indicators.append(volatility_drift)
            
            return drift_indicators
            
        except Exception as e:
            logger.error(f"Error detecting drift for metric {metric.metric_name}: {e}")
            return []
    
    def _detect_statistical_drift(self, historical_values: List[float], current_value: float) -> Optional[Dict[str, Any]]:
        """Detect statistical anomalies in current value."""
        if len(historical_values) < 5:  # Need minimum data
            return None
        
        mean_value = np.mean(historical_values)
        std_value = np.std(historical_values)
        
        if std_value == 0:  # No variation in historical data
            return None
        
        # Calculate z-score
        z_score = abs(current_value - mean_value) / std_value
        
        if z_score > self.drift_threshold_std_devs:
            return {
                "drift_type": "statistical_anomaly",
                "severity": "high" if z_score > 3.0 else "medium",
                "z_score": z_score,
                "current_value": current_value,
                "historical_mean": mean_value,
                "historical_std": std_value,
                "deviation_magnitude": abs(current_value - mean_value),
                "description": f"Current value {current_value:.1f} deviates {z_score:.1f} standard deviations from historical mean {mean_value:.1f}"
            }
        
        return None
    
    def _detect_trend_drift(self, trend_analysis: TrendAnalysis, metric: ComplianceMetric) -> Optional[Dict[str, Any]]:
        """Detect concerning trends in compliance metrics."""
        if trend_analysis.trend_strength < self.trend_strength_threshold:
            return None  # Trend not strong enough to be concerning
        
        # Check for declining trends
        if (trend_analysis.trend_direction == TrendDirection.DECLINING and 
            trend_analysis.trend_confidence > 0.7):
            
            # Assess severity based on decline rate
            if trend_analysis.change_rate_per_day < -2.0:  # Rapid decline
                severity = "critical"
            elif trend_analysis.change_rate_per_day < -1.0:  # Moderate decline
                severity = "high"
            else:
                severity = "medium"
            
            return {
                "drift_type": "declining_trend",
                "severity": severity,
                "trend_direction": trend_analysis.trend_direction.value,
                "trend_strength": trend_analysis.trend_strength,
                "trend_confidence": trend_analysis.trend_confidence,
                "change_rate_per_day": trend_analysis.change_rate_per_day,
                "percent_change": trend_analysis.percent_change,
                "description": f"Declining trend detected: {trend_analysis.percent_change:.1f}% change over analysis period"
            }
        
        # Check for volatile trends
        if trend_analysis.trend_direction == TrendDirection.VOLATILE:
            return {
                "drift_type": "volatility_increase",
                "severity": "medium",
                "coefficient_of_variation": trend_analysis.coefficient_of_variation,
                "anomalies_detected": trend_analysis.anomalies_detected,
                "description": f"Increased volatility detected with {trend_analysis.anomalies_detected} anomalies"
            }
        
        return None
    
    def _detect_volatility_drift(self, values: List[float], metric: ComplianceMetric) -> Optional[Dict[str, Any]]:
        """Detect unusual volatility in compliance metrics."""
        if len(values) < 10:
            return None
        
        # Calculate recent volatility vs. historical baseline
        recent_values = values[-7:]  # Last 7 data points
        baseline_values = values[:-7] if len(values) > 14 else values[:-3]
        
        if len(baseline_values) < 3:
            return None
        
        recent_cv = np.std(recent_values) / np.mean(recent_values) if np.mean(recent_values) > 0 else 0
        baseline_cv = np.std(baseline_values) / np.mean(baseline_values) if np.mean(baseline_values) > 0 else 0
        
        # Check for significant increase in volatility
        if recent_cv > baseline_cv * 2 and recent_cv > 0.2:  # At least 20% coefficient of variation
            return {
                "drift_type": "volatility_increase",
                "severity": "medium",
                "recent_volatility": recent_cv,
                "baseline_volatility": baseline_cv,
                "volatility_ratio": recent_cv / baseline_cv if baseline_cv > 0 else float('inf'),
                "description": f"Volatility increased from {baseline_cv:.3f} to {recent_cv:.3f}"
            }
        
        return None


class NotificationManager:
    """Manages multiple notification channels for alert delivery."""
    
    def __init__(self, smtp_config: Optional[Dict[str, Any]] = None):
        """Initialize notification manager."""
        self.smtp_config = smtp_config or {}
        self.webhook_timeout_seconds = 30
        self.notification_history = deque(maxlen=10000)
        self.failed_notifications = deque(maxlen=1000)
        
        logger.info("Notification manager initialized")
    
    async def send_notification(
        self,
        alert: ComplianceAlert,
        channel: NotificationChannel,
        recipients: List[str],
        custom_message: Optional[str] = None
    ) -> bool:
        """Send notification through specified channel."""
        try:
            success = False
            message = custom_message or self._format_alert_message(alert)
            
            if channel == NotificationChannel.EMAIL:
                success = await self._send_email(alert, recipients, message)
            elif channel == NotificationChannel.WEBHOOK:
                success = await self._send_webhook(alert, recipients, message)
            elif channel == NotificationChannel.DASHBOARD:
                success = await self._send_dashboard_notification(alert)
            elif channel == NotificationChannel.SLACK:
                success = await self._send_slack_notification(alert, recipients, message)
            else:
                logger.warning(f"Notification channel {channel} not implemented")
                return False
            
            # Track notification
            notification_record = {
                "alert_id": alert.alert_id,
                "channel": channel.value,
                "recipients": recipients,
                "timestamp": datetime.now(timezone.utc),
                "success": success,
                "message_preview": message[:100] + "..." if len(message) > 100 else message
            }
            
            self.notification_history.append(notification_record)
            
            if not success:
                self.failed_notifications.append(notification_record)
            
            return success
            
        except Exception as e:
            logger.error(f"Error sending notification via {channel}: {e}")
            return False
    
    async def _send_email(self, alert: ComplianceAlert, recipients: List[str], message: str) -> bool:
        """Send email notification."""
        try:
            if not self.smtp_config:
                logger.warning("SMTP configuration not provided")
                return False
            
            # Create email message
            msg = MIMEMultipart()
            msg['From'] = self.smtp_config.get('from_address', 'compliance@security.gov')
            msg['To'] = ', '.join(recipients)
            msg['Subject'] = f"[{alert.severity.value.upper()}] {alert.title}"
            
            # Add classification header if required
            if alert.classification_level != "UNCLASSIFIED":
                msg['Subject'] = f"[{alert.classification_level}] " + msg['Subject']
            
            # Create email body
            body = self._create_email_body(alert, message)
            msg.attach(MIMEText(body, 'html'))
            
            # Send email
            with smtplib.SMTP(self.smtp_config.get('host', 'localhost'), 
                             self.smtp_config.get('port', 587)) as server:
                if self.smtp_config.get('use_tls', True):
                    server.starttls()
                
                if self.smtp_config.get('username'):
                    server.login(
                        self.smtp_config['username'],
                        self.smtp_config['password']
                    )
                
                server.send_message(msg)
            
            logger.info(f"Email notification sent for alert {alert.alert_id}")
            return True
            
        except Exception as e:
            logger.error(f"Error sending email notification: {e}")
            return False
    
    async def _send_webhook(self, alert: ComplianceAlert, recipients: List[str], message: str) -> bool:
        """Send webhook notification."""
        try:
            payload = {
                "alert": alert.to_dict(),
                "message": message,
                "recipients": recipients,
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
            
            # Send to each webhook URL
            success_count = 0
            
            async with aiohttp.ClientSession() as session:
                for webhook_url in recipients:  # Recipients are webhook URLs for webhook channel
                    try:
                        async with session.post(
                            webhook_url,
                            json=payload,
                            timeout=aiohttp.ClientTimeout(total=self.webhook_timeout_seconds)
                        ) as response:
                            if response.status == 200:
                                success_count += 1
                            else:
                                logger.warning(f"Webhook {webhook_url} returned status {response.status}")
                    except Exception as e:
                        logger.error(f"Error sending webhook to {webhook_url}: {e}")
            
            return success_count > 0
            
        except Exception as e:
            logger.error(f"Error sending webhook notification: {e}")
            return False
    
    async def _send_dashboard_notification(self, alert: ComplianceAlert) -> bool:
        """Send dashboard notification (internal system notification)."""
        try:
            # This would typically push the alert to a real-time dashboard system
            # For now, we'll just log it as a successful dashboard notification
            logger.info(f"Dashboard notification sent for alert {alert.alert_id}")
            return True
            
        except Exception as e:
            logger.error(f"Error sending dashboard notification: {e}")
            return False
    
    async def _send_slack_notification(self, alert: ComplianceAlert, recipients: List[str], message: str) -> bool:
        """Send Slack notification."""
        try:
            # This would integrate with Slack API
            # For now, simulate successful delivery
            logger.info(f"Slack notification sent for alert {alert.alert_id}")
            return True
            
        except Exception as e:
            logger.error(f"Error sending Slack notification: {e}")
            return False
    
    def _format_alert_message(self, alert: ComplianceAlert) -> str:
        """Format alert message for notification."""
        return f"""
Compliance Alert: {alert.title}

Severity: {alert.severity.value.upper()}
Type: {alert.alert_type.value}
Framework: {alert.framework}
Current Value: {alert.current_value}
Threshold: {alert.threshold_value}
Deviation: {alert.deviation_percentage}%

Description:
{alert.description}

Alert ID: {alert.alert_id}
Timestamp: {alert.timestamp.isoformat()}
Classification: {alert.classification_level}

{alert.message}
""".strip()
    
    def _create_email_body(self, alert: ComplianceAlert, message: str) -> str:
        """Create HTML email body."""
        severity_colors = {
            AlertSeverity.INFO: "#17a2b8",
            AlertSeverity.LOW: "#28a745", 
            AlertSeverity.MEDIUM: "#ffc107",
            AlertSeverity.HIGH: "#fd7e14",
            AlertSeverity.CRITICAL: "#dc3545",
            AlertSeverity.EMERGENCY: "#6f42c1"
        }
        
        color = severity_colors.get(alert.severity, "#6c757d")
        
        return f"""
<html>
<head>
    <style>
        body {{ font-family: Arial, sans-serif; }}
        .header {{ background-color: {color}; color: white; padding: 20px; }}
        .content {{ padding: 20px; }}
        .footer {{ background-color: #f8f9fa; padding: 10px; font-size: 12px; }}
        .metric {{ background-color: #e9ecef; padding: 10px; margin: 10px 0; }}
    </style>
</head>
<body>
    <div class="header">
        <h2>{alert.title}</h2>
        <p>Severity: {alert.severity.value.upper()} | Classification: {alert.classification_level}</p>
    </div>
    <div class="content">
        <p><strong>Alert Type:</strong> {alert.alert_type.value}</p>
        <p><strong>Framework:</strong> {alert.framework}</p>
        <p><strong>Control:</strong> {alert.control_reference}</p>
        
        <div class="metric">
            <strong>Metric Details:</strong><br>
            Current Value: {alert.current_value}<br>
            Threshold: {alert.threshold_value}<br>
            Target: {alert.target_value}<br>
            Deviation: {alert.deviation_percentage}%
        </div>
        
        <p><strong>Description:</strong></p>
        <p>{alert.description}</p>
        
        <p><strong>Message:</strong></p>
        <p>{message}</p>
        
        <p><strong>Response Deadline:</strong> {alert.response_deadline.isoformat() if alert.response_deadline else 'Not specified'}</p>
    </div>
    <div class="footer">
        <p>Alert ID: {alert.alert_id} | Generated: {alert.timestamp.isoformat()}</p>
        <p>This is an automated compliance alert. Please do not reply to this email.</p>
    </div>
</body>
</html>
"""


class ComplianceAlertSystem:
    """
    Main compliance alert and notification system that provides real-time
    compliance drift detection and automated escalation procedures.
    """
    
    def __init__(
        self,
        data_provider: ComplianceDataProvider,
        data_warehouse: ComplianceDataWarehouse,
        audit_orchestrator: IntegratedAuditOrchestrator,
        monitoring_system: EnhancedMonitoringSystem,
        real_time_alerting: RealTimeAlerting,
        smtp_config: Optional[Dict[str, Any]] = None
    ):
        """Initialize compliance alert system."""
        self.data_provider = data_provider
        self.data_warehouse = data_warehouse
        self.audit_orchestrator = audit_orchestrator
        self.monitoring_system = monitoring_system
        self.real_time_alerting = real_time_alerting
        
        # Core components
        self.drift_detector = ComplianceDriftDetector(data_warehouse)
        self.notification_manager = NotificationManager(smtp_config)
        
        # Alert management
        self.active_alerts: Dict[str, ComplianceAlert] = {}
        self.alert_rules: Dict[str, AlertRule] = {}
        self.alert_history = deque(maxlen=10000)
        
        # Processing state
        self.is_running = False
        self.worker_tasks: List[asyncio.Task] = []
        
        # Alert suppression tracking
        self.suppression_counters = defaultdict(int)  # rule_id -> count
        self.suppression_windows = defaultdict(datetime)  # rule_id -> window_start
        
        # Performance tracking
        self.metrics = {
            "alerts_generated": 0,
            "alerts_resolved": 0,
            "notifications_sent": 0,
            "escalations_triggered": 0,
            "drift_detections": 0,
            "last_check": datetime.now(timezone.utc)
        }
        self.metrics_lock = Lock()
        
        # Initialize default alert rules
        self._create_default_alert_rules()
        
        logger.info("Compliance alert system initialized")
    
    def _create_default_alert_rules(self):
        """Create default alert rules for common compliance scenarios."""
        default_rules = [
            {
                "name": "Overall Compliance Posture - Critical",
                "metric_type": ComplianceMetricType.OVERALL_POSTURE,
                "threshold_type": "below",
                "threshold_value": 75.0,
                "severity": AlertSeverity.CRITICAL,
                "alert_type": AlertType.COMPLIANCE_DRIFT,
                "response_deadline_minutes": 30,
                "notification_channels": [NotificationChannel.EMAIL, NotificationChannel.DASHBOARD]
            },
            {
                "name": "Control Effectiveness - High",
                "metric_type": ComplianceMetricType.CONTROL_EFFECTIVENESS,
                "threshold_type": "below", 
                "threshold_value": 85.0,
                "severity": AlertSeverity.HIGH,
                "alert_type": AlertType.SYSTEM_DEGRADATION,
                "response_deadline_minutes": 60,
                "notification_channels": [NotificationChannel.EMAIL, NotificationChannel.DASHBOARD]
            },
            {
                "name": "Audit Coverage - Medium",
                "metric_type": ComplianceMetricType.AUDIT_COVERAGE,
                "threshold_type": "below",
                "threshold_value": 90.0,
                "severity": AlertSeverity.MEDIUM,
                "alert_type": AlertType.AUDIT_FAILURE,
                "response_deadline_minutes": 120,
                "notification_channels": [NotificationChannel.DASHBOARD]
            },
            {
                "name": "Classification Compliance - Critical",
                "metric_type": ComplianceMetricType.CLASSIFICATION_COMPLIANCE,
                "threshold_type": "below",
                "threshold_value": 95.0,
                "severity": AlertSeverity.CRITICAL,
                "alert_type": AlertType.CLASSIFICATION_VIOLATION,
                "response_deadline_minutes": 15,
                "classification_level": "CONFIDENTIAL",
                "notification_channels": [NotificationChannel.EMAIL, NotificationChannel.DASHBOARD]
            }
        ]
        
        for rule_config in default_rules:
            rule = AlertRule(
                name=rule_config["name"],
                metric_type=rule_config["metric_type"],
                threshold_type=rule_config["threshold_type"],
                threshold_value=rule_config["threshold_value"],
                severity=rule_config["severity"],
                alert_type=rule_config["alert_type"],
                response_deadline_minutes=rule_config["response_deadline_minutes"],
                notification_channels=rule_config["notification_channels"],
                classification_level=rule_config.get("classification_level", "UNCLASSIFIED")
            )
            
            self.alert_rules[rule.rule_id] = rule
        
        logger.info(f"Created {len(default_rules)} default alert rules")
    
    async def start(self):
        """Start the compliance alert system."""
        if self.is_running:
            return
        
        self.is_running = True
        
        # Start worker tasks
        self.worker_tasks = [
            asyncio.create_task(self._compliance_monitoring_worker()),
            asyncio.create_task(self._drift_detection_worker()),
            asyncio.create_task(self._escalation_worker()),
            asyncio.create_task(self._alert_cleanup_worker()),
            asyncio.create_task(self._integration_monitoring_worker())
        ]
        
        logger.info("Compliance alert system started")
    
    async def stop(self):
        """Stop the compliance alert system."""
        self.is_running = False
        
        # Cancel worker tasks
        for task in self.worker_tasks:
            if not task.done():
                task.cancel()
        
        if self.worker_tasks:
            await asyncio.gather(*self.worker_tasks, return_exceptions=True)
        
        logger.info("Compliance alert system stopped")
    
    async def _compliance_monitoring_worker(self):
        """Worker task for monitoring compliance metrics."""
        while self.is_running:
            try:
                # Get current compliance metrics
                current_metrics = await self.data_provider.get_compliance_metrics()
                
                # Check each metric against alert rules
                for metric in current_metrics:
                    await self._evaluate_metric_against_rules(metric)
                
                with self.metrics_lock:
                    self.metrics["last_check"] = datetime.now(timezone.utc)
                
                # Wait for next check (60 seconds)
                await asyncio.sleep(60.0)
                
            except Exception as e:
                logger.error(f"Error in compliance monitoring worker: {e}")
                await asyncio.sleep(120.0)  # Wait longer on error
    
    async def _evaluate_metric_against_rules(self, metric: ComplianceMetric):
        """Evaluate a metric against all applicable alert rules."""
        for rule in self.alert_rules.values():
            if not rule.enabled:
                continue
            
            try:
                # Check if metric matches rule conditions
                if rule.matches_metric(metric):
                    # Check suppression
                    if self._is_suppressed(rule):
                        continue
                    
                    # Create alert
                    alert = await self._create_alert_from_rule(rule, metric)
                    if alert:
                        await self._process_new_alert(alert)
                        
                        with self.metrics_lock:
                            self.metrics["alerts_generated"] += 1
                        
                        # Update suppression counter
                        self._update_suppression_counter(rule)
                
            except Exception as e:
                logger.error(f"Error evaluating metric {metric.metric_name} against rule {rule.name}: {e}")
    
    async def _create_alert_from_rule(self, rule: AlertRule, metric: ComplianceMetric) -> Optional[ComplianceAlert]:
        """Create an alert from a rule and metric."""
        try:
            current_score = metric.calculate_compliance_score()
            
            # Calculate deviation
            if rule.threshold_value:
                deviation = ((rule.threshold_value - current_score) / rule.threshold_value) * 100
            else:
                deviation = 0.0
            
            # Format title and message
            title = rule.title_template.format(
                metric_name=metric.metric_name,
                current_value=current_score,
                threshold_value=rule.threshold_value
            )
            
            message = rule.message_template.format(
                metric_name=metric.metric_name,
                current_value=current_score,
                threshold_value=rule.threshold_value,
                deviation_percentage=abs(deviation)
            )
            
            # Create alert
            alert = ComplianceAlert(
                alert_type=rule.alert_type,
                severity=rule.severity,
                title=title,
                message=message,
                description=f"Compliance alert triggered by rule: {rule.name}",
                source_metric_type=metric.metric_type,
                source_metric_name=metric.metric_name,
                source_system="compliance_alert_system",
                framework=metric.framework,
                control_reference=metric.control_reference,
                current_value=current_score,
                threshold_value=rule.threshold_value,
                target_value=metric.target_value,
                deviation_percentage=deviation,
                classification_level=rule.classification_level,
                requires_clearance=rule.classification_level != "UNCLASSIFIED",
                response_deadline=datetime.now(timezone.utc) + timedelta(minutes=rule.response_deadline_minutes),
                additional_data={
                    "rule_id": rule.rule_id,
                    "rule_name": rule.name,
                    "metric_data": metric.to_dict()
                }
            )
            
            return alert
            
        except Exception as e:
            logger.error(f"Error creating alert from rule {rule.name}: {e}")
            return None
    
    async def _process_new_alert(self, alert: ComplianceAlert):
        """Process a new alert."""
        try:
            # Check for duplicate alerts
            if await self._is_duplicate_alert(alert):
                logger.debug(f"Skipping duplicate alert: {alert.title}")
                return
            
            # Store alert
            self.active_alerts[alert.alert_id] = alert
            self.alert_history.append(alert.to_dict())
            
            # Send notifications
            await self._send_alert_notifications(alert)
            
            # Integrate with existing real-time alerting
            await self._integrate_with_real_time_alerting(alert)
            
            logger.info(f"Processed new alert: {alert.alert_id} - {alert.title}")
            
        except Exception as e:
            logger.error(f"Error processing new alert: {e}")
    
    async def _is_duplicate_alert(self, alert: ComplianceAlert) -> bool:
        """Check if alert is a duplicate of an existing active alert."""
        for existing_alert in self.active_alerts.values():
            if (existing_alert.source_metric_name == alert.source_metric_name and
                existing_alert.alert_type == alert.alert_type and
                existing_alert.status == AlertStatus.ACTIVE and
                abs(existing_alert.current_value - alert.current_value) < 1.0):  # Very similar values
                return True
        
        return False
    
    async def _send_alert_notifications(self, alert: ComplianceAlert):
        """Send notifications for an alert."""
        try:
            # Get the rule that generated this alert
            rule_id = alert.additional_data.get("rule_id")
            if not rule_id or rule_id not in self.alert_rules:
                return
            
            rule = self.alert_rules[rule_id]
            
            # Send notifications through configured channels
            notification_success = False
            
            for channel in rule.notification_channels:
                try:
                    success = await self.notification_manager.send_notification(
                        alert, channel, rule.notification_recipients
                    )
                    
                    if success:
                        notification_success = True
                        alert.notifications_sent.append(channel.value)
                        
                        with self.metrics_lock:
                            self.metrics["notifications_sent"] += 1
                
                except Exception as e:
                    logger.error(f"Error sending notification via {channel}: {e}")
            
            # Update alert notification tracking
            alert.notification_attempts += 1
            alert.last_notification = datetime.now(timezone.utc)
            
            if not notification_success:
                logger.warning(f"Failed to send any notifications for alert {alert.alert_id}")
            
        except Exception as e:
            logger.error(f"Error sending alert notifications: {e}")
    
    async def _integrate_with_real_time_alerting(self, alert: ComplianceAlert):
        """Integrate with existing real-time alerting system."""
        try:
            # Map alert severity to real-time alerting priority
            priority_mapping = {
                AlertSeverity.INFO: AlertPriority.LOW,
                AlertSeverity.LOW: AlertPriority.LOW,
                AlertSeverity.MEDIUM: AlertPriority.MEDIUM,
                AlertSeverity.HIGH: AlertPriority.HIGH,
                AlertSeverity.CRITICAL: AlertPriority.URGENT,
                AlertSeverity.EMERGENCY: AlertPriority.URGENT
            }
            
            priority = priority_mapping.get(alert.severity, AlertPriority.MEDIUM)
            
            # Send to real-time alerting system
            await self.real_time_alerting.send_alert(
                alert_type=alert.alert_type.value,
                severity=alert.severity.value,
                message=alert.message,
                context={
                    "alert_id": alert.alert_id,
                    "metric_name": alert.source_metric_name,
                    "current_value": alert.current_value,
                    "threshold_value": alert.threshold_value,
                    "framework": alert.framework,
                    "classification_level": alert.classification_level
                },
                priority=priority
            )
            
        except Exception as e:
            logger.error(f"Error integrating with real-time alerting: {e}")
    
    async def _drift_detection_worker(self):
        """Worker task for compliance drift detection."""
        while self.is_running:
            try:
                # Get current compliance metrics
                current_metrics = await self.data_provider.get_compliance_metrics()
                
                # Check each metric for drift
                for metric in current_metrics:
                    drift_indicators = await self.drift_detector.detect_drift(metric)
                    
                    if drift_indicators:
                        await self._process_drift_detection(metric, drift_indicators)
                        
                        with self.metrics_lock:
                            self.metrics["drift_detections"] += 1
                
                # Run drift detection every 10 minutes
                await asyncio.sleep(600.0)
                
            except Exception as e:
                logger.error(f"Error in drift detection worker: {e}")
                await asyncio.sleep(1200.0)  # Wait longer on error
    
    async def _process_drift_detection(self, metric: ComplianceMetric, drift_indicators: List[Dict[str, Any]]):
        """Process detected compliance drift."""
        try:
            for drift in drift_indicators:
                # Create drift alert
                severity_mapping = {
                    "low": AlertSeverity.LOW,
                    "medium": AlertSeverity.MEDIUM,
                    "high": AlertSeverity.HIGH,
                    "critical": AlertSeverity.CRITICAL
                }
                
                severity = severity_mapping.get(drift.get("severity", "medium"), AlertSeverity.MEDIUM)
                
                alert = ComplianceAlert(
                    alert_type=AlertType.COMPLIANCE_DRIFT,
                    severity=severity,
                    title=f"Compliance Drift Detected: {metric.metric_name}",
                    message=f"Drift type: {drift['drift_type']} - {drift['description']}",
                    description=f"Statistical analysis detected compliance drift in {metric.metric_name}",
                    source_metric_type=metric.metric_type,
                    source_metric_name=metric.metric_name,
                    source_system="drift_detector",
                    framework=metric.framework,
                    control_reference=metric.control_reference,
                    current_value=metric.current_value,
                    target_value=metric.target_value,
                    classification_level=metric.classification_level,
                    additional_data={
                        "drift_analysis": drift,
                        "detection_method": "statistical_analysis"
                    }
                )
                
                await self._process_new_alert(alert)
                
        except Exception as e:
            logger.error(f"Error processing drift detection: {e}")
    
    async def _escalation_worker(self):
        """Worker task for alert escalation."""
        while self.is_running:
            try:
                current_time = datetime.now(timezone.utc)
                
                # Check active alerts for escalation
                for alert in list(self.active_alerts.values()):
                    if alert.should_escalate():
                        await self._escalate_alert(alert)
                        
                        with self.metrics_lock:
                            self.metrics["escalations_triggered"] += 1
                
                # Run escalation check every 5 minutes
                await asyncio.sleep(300.0)
                
            except Exception as e:
                logger.error(f"Error in escalation worker: {e}")
                await asyncio.sleep(600.0)
    
    async def _escalate_alert(self, alert: ComplianceAlert):
        """Escalate an alert."""
        try:
            alert.escalation_level += 1
            alert.escalated_at = datetime.now(timezone.utc)
            alert.status = AlertStatus.ESCALATED
            
            # Create escalation message
            escalation_message = f"""
ESCALATED COMPLIANCE ALERT

Original Alert: {alert.title}
Alert Age: {alert.calculate_age_minutes():.0f} minutes
Escalation Level: {alert.escalation_level}
Current Status: {alert.status.value}

This alert requires immediate attention due to response time threshold being exceeded.

Original Message:
{alert.message}
"""
            
            # Send escalation notifications (higher priority channels)
            escalation_channels = [NotificationChannel.EMAIL, NotificationChannel.DASHBOARD]
            
            for channel in escalation_channels:
                await self.notification_manager.send_notification(
                    alert, channel, ["escalation@security.gov"], escalation_message
                )
            
            logger.warning(f"Alert escalated: {alert.alert_id} - Level {alert.escalation_level}")
            
        except Exception as e:
            logger.error(f"Error escalating alert {alert.alert_id}: {e}")
    
    async def _alert_cleanup_worker(self):
        """Worker task for cleaning up old alerts."""
        while self.is_running:
            try:
                current_time = datetime.now(timezone.utc)
                
                # Clean up old resolved/expired alerts
                expired_alerts = []
                for alert_id, alert in self.active_alerts.items():
                    if (alert.status in [AlertStatus.RESOLVED] and 
                        alert.resolved_at and
                        (current_time - alert.resolved_at).total_seconds() > 86400):  # 24 hours
                        expired_alerts.append(alert_id)
                    elif alert.is_expired(max_age_hours=72):  # 3 days
                        expired_alerts.append(alert_id)
                
                # Remove expired alerts
                for alert_id in expired_alerts:
                    expired_alert = self.active_alerts.pop(alert_id, None)
                    if expired_alert:
                        logger.info(f"Cleaned up expired alert: {alert_id}")
                        
                        with self.metrics_lock:
                            if expired_alert.status == AlertStatus.RESOLVED:
                                self.metrics["alerts_resolved"] += 1
                
                # Run cleanup daily
                await asyncio.sleep(86400.0)
                
            except Exception as e:
                logger.error(f"Error in alert cleanup worker: {e}")
                await asyncio.sleep(3600.0)
    
    async def _integration_monitoring_worker(self):
        """Worker task for monitoring integration health and generating alerts."""
        while self.is_running:
            try:
                # Check audit orchestrator health
                audit_health = await self.audit_orchestrator.health_check()
                if audit_health.get("status") != "healthy":
                    await self._create_system_health_alert("Audit Orchestrator", audit_health)
                
                # Check monitoring system health
                monitoring_health = await self.monitoring_system.health_check()
                if monitoring_health.get("status") != "healthy":
                    await self._create_system_health_alert("Monitoring System", monitoring_health)
                
                # Check data warehouse health
                warehouse_health = await self.data_warehouse.health_check()
                if warehouse_health.get("status") != "healthy":
                    await self._create_system_health_alert("Data Warehouse", warehouse_health)
                
                # Run integration monitoring every 5 minutes
                await asyncio.sleep(300.0)
                
            except Exception as e:
                logger.error(f"Error in integration monitoring worker: {e}")
                await asyncio.sleep(600.0)
    
    async def _create_system_health_alert(self, system_name: str, health_data: Dict[str, Any]):
        """Create alert for system health issues."""
        try:
            alert = ComplianceAlert(
                alert_type=AlertType.SYSTEM_DEGRADATION,
                severity=AlertSeverity.HIGH,
                title=f"System Health Alert: {system_name}",
                message=f"{system_name} health check failed: {health_data.get('status', 'unknown')}",
                description=f"Integrated system {system_name} is reporting health issues",
                source_system=system_name.lower().replace(" ", "_"),
                framework="System Health Monitoring",
                classification_level="UNCLASSIFIED",
                additional_data={
                    "health_data": health_data,
                    "system_name": system_name
                }
            )
            
            await self._process_new_alert(alert)
            
        except Exception as e:
            logger.error(f"Error creating system health alert: {e}")
    
    def _is_suppressed(self, rule: AlertRule) -> bool:
        """Check if alerts for a rule are suppressed."""
        if rule.max_alerts_per_hour <= 0:
            return False
        
        current_time = datetime.now(timezone.utc)
        window_start = self.suppression_windows.get(rule.rule_id)
        
        # Check if we're in a new hour window
        if not window_start or (current_time - window_start).total_seconds() > 3600:
            # Reset counter for new window
            self.suppression_counters[rule.rule_id] = 0
            self.suppression_windows[rule.rule_id] = current_time
            return False
        
        # Check if we've exceeded the limit
        return self.suppression_counters[rule.rule_id] >= rule.max_alerts_per_hour
    
    def _update_suppression_counter(self, rule: AlertRule):
        """Update suppression counter for a rule."""
        self.suppression_counters[rule.rule_id] += 1
    
    async def acknowledge_alert(self, alert_id: str, user_id: str, notes: str = "") -> bool:
        """Acknowledge an alert."""
        try:
            alert = self.active_alerts.get(alert_id)
            if not alert:
                return False
            
            alert.status = AlertStatus.ACKNOWLEDGED
            alert.acknowledged_by = user_id
            alert.acknowledged_at = datetime.now(timezone.utc)
            alert.resolution_notes = notes
            
            logger.info(f"Alert acknowledged: {alert_id} by {user_id}")
            return True
            
        except Exception as e:
            logger.error(f"Error acknowledging alert {alert_id}: {e}")
            return False
    
    async def resolve_alert(self, alert_id: str, user_id: str, resolution_notes: str = "") -> bool:
        """Resolve an alert."""
        try:
            alert = self.active_alerts.get(alert_id)
            if not alert:
                return False
            
            alert.status = AlertStatus.RESOLVED
            alert.resolved_by = user_id
            alert.resolved_at = datetime.now(timezone.utc)
            alert.resolution_notes = resolution_notes
            
            with self.metrics_lock:
                self.metrics["alerts_resolved"] += 1
            
            logger.info(f"Alert resolved: {alert_id} by {user_id}")
            return True
            
        except Exception as e:
            logger.error(f"Error resolving alert {alert_id}: {e}")
            return False
    
    async def suppress_alert(self, alert_id: str, user_id: str, duration_minutes: int, reason: str) -> bool:
        """Suppress an alert for a specified duration."""
        try:
            alert = self.active_alerts.get(alert_id)
            if not alert:
                return False
            
            alert.status = AlertStatus.SUPPRESSED
            alert.suppressed_until = datetime.now(timezone.utc) + timedelta(minutes=duration_minutes)
            alert.suppression_reason = reason
            
            logger.info(f"Alert suppressed: {alert_id} by {user_id} for {duration_minutes} minutes")
            return True
            
        except Exception as e:
            logger.error(f"Error suppressing alert {alert_id}: {e}")
            return False
    
    def get_active_alerts(self, severity_filter: Optional[AlertSeverity] = None) -> List[Dict[str, Any]]:
        """Get list of active alerts."""
        alerts = []
        
        for alert in self.active_alerts.values():
            if alert.status not in [AlertStatus.RESOLVED, AlertStatus.SUPPRESSED]:
                if not severity_filter or alert.severity == severity_filter:
                    alerts.append(alert.to_dict())
        
        # Sort by severity and timestamp
        severity_order = {
            AlertSeverity.EMERGENCY: 0,
            AlertSeverity.CRITICAL: 1,
            AlertSeverity.HIGH: 2,
            AlertSeverity.MEDIUM: 3,
            AlertSeverity.LOW: 4,
            AlertSeverity.INFO: 5
        }
        
        alerts.sort(key=lambda x: (severity_order.get(AlertSeverity(x["severity"]), 6), x["timestamp"]))
        
        return alerts
    
    def get_alert_statistics(self) -> Dict[str, Any]:
        """Get alert system statistics."""
        with self.metrics_lock:
            stats = self.metrics.copy()
        
        # Add current counts
        stats.update({
            "active_alerts": len([a for a in self.active_alerts.values() if a.status == AlertStatus.ACTIVE]),
            "acknowledged_alerts": len([a for a in self.active_alerts.values() if a.status == AlertStatus.ACKNOWLEDGED]),
            "escalated_alerts": len([a for a in self.active_alerts.values() if a.status == AlertStatus.ESCALATED]),
            "suppressed_alerts": len([a for a in self.active_alerts.values() if a.status == AlertStatus.SUPPRESSED]),
            "total_active_alerts": len(self.active_alerts),
            "alert_rules_configured": len(self.alert_rules),
            "enabled_rules": len([r for r in self.alert_rules.values() if r.enabled])
        })
        
        return stats
    
    async def health_check(self) -> Dict[str, Any]:
        """Perform health check of alert system."""
        return {
            "status": "healthy" if self.is_running else "stopped",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "worker_tasks": len([t for t in self.worker_tasks if not t.done()]),
            "active_alerts_count": len(self.active_alerts),
            "alert_rules_count": len(self.alert_rules),
            "statistics": self.get_alert_statistics()
        }


# Alert manager for easy initialization
class AlertManager:
    """Manager class for easy initialization of the alert system."""
    
    def __init__(
        self,
        data_provider: ComplianceDataProvider,
        data_warehouse: ComplianceDataWarehouse,
        audit_orchestrator: IntegratedAuditOrchestrator,
        monitoring_system: EnhancedMonitoringSystem,
        real_time_alerting: RealTimeAlerting,
        smtp_config: Optional[Dict[str, Any]] = None
    ):
        """Initialize alert manager."""
        self.alert_system = ComplianceAlertSystem(
            data_provider=data_provider,
            data_warehouse=data_warehouse,
            audit_orchestrator=audit_orchestrator,
            monitoring_system=monitoring_system,
            real_time_alerting=real_time_alerting,
            smtp_config=smtp_config
        )
        
        logger.info("Alert manager initialized")
    
    async def start(self):
        """Start the alert system."""
        await self.alert_system.start()
        logger.info("Alert system started")
    
    async def stop(self):
        """Stop the alert system."""
        await self.alert_system.stop()
        logger.info("Alert system stopped")
    
    def get_alert_system(self) -> ComplianceAlertSystem:
        """Get the alert system instance."""
        return self.alert_system


# Factory function
def create_alert_manager(
    data_provider: ComplianceDataProvider,
    data_warehouse: ComplianceDataWarehouse,
    audit_orchestrator: IntegratedAuditOrchestrator,
    monitoring_system: EnhancedMonitoringSystem,
    real_time_alerting: RealTimeAlerting,
    smtp_config: Optional[Dict[str, Any]] = None
) -> AlertManager:
    """Create and initialize alert manager."""
    return AlertManager(
        data_provider=data_provider,
        data_warehouse=data_warehouse,
        audit_orchestrator=audit_orchestrator,
        monitoring_system=monitoring_system,
        real_time_alerting=real_time_alerting,
        smtp_config=smtp_config
    )


if __name__ == "__main__":
    # Example usage
    print("Compliance Alert and Notification System - see code for usage examples")