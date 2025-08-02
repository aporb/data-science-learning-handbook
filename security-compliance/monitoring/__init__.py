"""
CAC/PIV Security Monitoring and Audit System

This package provides comprehensive security monitoring, threat detection, and compliance
capabilities for CAC/PIV smart card infrastructure in DoD environments.

Key Components:
- CACPIVSecurityMonitor: Real-time security event detection and analysis
- FailoverDetector: Health monitoring and failover capabilities
- SecurityAlerting: Multi-channel alerting and escalation
- PrometheusIntegration: Metrics collection and monitoring integration
- ComplianceReporting: Automated DoD compliance reporting

Author: Security Monitoring Team
Version: 1.0.0
"""

from .cac_piv_security_monitor import (
    CACPIVSecurityMonitor,
    SecurityEvent,
    SecurityEventCategory,
    SecurityThreatLevel,
    SecurityMonitoringConfig
)

from .failover_detector import (
    FailoverDetector,
    FailoverEvent,
    FailoverTrigger,
    HealthStatus,
    ComponentHealth,
    FailoverConfiguration
)

from .security_alerting import (
    SecurityAlerting,
    Alert,
    AlertRule,
    AlertContact,
    AlertSeverity,
    AlertStatus,
    AlertChannel,
    AlertingConfiguration
)

from .prometheus_integration import (
    PrometheusIntegration,
    PrometheusMetricsRegistry,
    PrometheusConfiguration,
    MetricType
)

from .compliance_reporting import (
    ComplianceReporting,
    ComplianceReport,
    ComplianceControl,
    ComplianceMetric,
    ComplianceFramework,
    ComplianceStatus,
    ReportType,
    ComplianceReportingConfiguration
)

__version__ = "1.0.0"
__author__ = "Security Monitoring Team"

# Package-level exports
__all__ = [
    # Main classes
    "CACPIVSecurityMonitor",
    "FailoverDetector", 
    "SecurityAlerting",
    "PrometheusIntegration",
    "ComplianceReporting",
    
    # Event and data classes
    "SecurityEvent",
    "FailoverEvent",
    "Alert",
    "ComplianceReport",
    "ComplianceControl",
    "ComplianceMetric",
    "AlertRule",
    "AlertContact",
    "ComponentHealth",
    
    # Enums
    "SecurityEventCategory",
    "SecurityThreatLevel", 
    "FailoverTrigger",
    "HealthStatus",
    "AlertSeverity",
    "AlertStatus",
    "AlertChannel",
    "ComplianceFramework",
    "ComplianceStatus",
    "ReportType",
    "MetricType",
    
    # Configuration classes
    "SecurityMonitoringConfig",
    "FailoverConfiguration",
    "AlertingConfiguration", 
    "PrometheusConfiguration",
    "ComplianceReportingConfiguration"
]