"""
Compliance Alert and Notification System
=======================================

This module provides comprehensive alert and notification capabilities for
compliance drift detection and automated escalation procedures.

Module Components:
- compliance_alert_system.py: Main alert and notification system
- drift_detection_engine.py: Compliance drift detection
- escalation_manager.py: Automated escalation procedures
- notification_channels.py: Multiple notification channel support

Classification: UNCLASSIFIED//FOR OFFICIAL USE ONLY
"""

from .compliance_alert_system import ComplianceAlertSystem, AlertManager
from .drift_detection_engine import ComplianceDriftDetector
from .escalation_manager import EscalationManager
from .notification_channels import NotificationChannelManager

__all__ = [
    'ComplianceAlertSystem',
    'AlertManager',
    'ComplianceDriftDetector',
    'EscalationManager',
    'NotificationChannelManager'
]