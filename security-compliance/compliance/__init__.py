"""
Comprehensive Compliance Reporting and Dashboard System
======================================================

This module provides comprehensive compliance reporting and dashboard capabilities
that integrate with existing monitoring and audit systems to deliver real-time
visibility into compliance posture and automate regulatory reporting.

Module Components:
- dashboards/: Real-time compliance dashboards and visualization
- reporting/: Automated reporting engine with government formats  
- data/: Compliance data warehouse and historical analysis
- alerts/: Alert and notification system for compliance drift
- integration_layer.py: Integration with existing systems

Key Features:
- Real-time compliance posture visualization
- Executive-level and technical dashboard views
- Automated government format reporting (FISMA, FedRAMP, DoD)
- Historical data warehousing and trend analysis
- Compliance drift detection and alerting
- Multi-classification level support
- Integration with existing audit and monitoring infrastructure

Classification: UNCLASSIFIED//FOR OFFICIAL USE ONLY
"""

from .dashboards import (
    ComplianceDashboard, 
    DashboardManager,
    ExecutiveDashboard,
    TechnicalDashboard,
    MultiClassificationDashboard
)

from .reporting import (
    AutomatedReportingEngine,
    ReportingManager,
    GovernmentReportGenerator,
    ReportScheduler,
    ReportTemplateManager
)

from .data import (
    ComplianceDataWarehouse,
    DataWarehouseManager,
    HistoricalDataAggregator,
    TrendAnalyzer,
    DataCorrelationEngine
)

from .alerts import (
    ComplianceAlertSystem,
    AlertManager,
    ComplianceDriftDetector,
    EscalationManager,
    NotificationChannelManager
)

from .integration_layer import (
    ComplianceIntegrationLayer,
    IntegrationManager
)

__all__ = [
    # Dashboards
    'ComplianceDashboard',
    'DashboardManager', 
    'ExecutiveDashboard',
    'TechnicalDashboard',
    'MultiClassificationDashboard',
    
    # Reporting
    'AutomatedReportingEngine',
    'ReportingManager',
    'GovernmentReportGenerator',
    'ReportScheduler',
    'ReportTemplateManager',
    
    # Data Warehouse
    'ComplianceDataWarehouse',
    'DataWarehouseManager',
    'HistoricalDataAggregator',
    'TrendAnalyzer',
    'DataCorrelationEngine',
    
    # Alerts
    'ComplianceAlertSystem',
    'AlertManager',
    'ComplianceDriftDetector',
    'EscalationManager',
    'NotificationChannelManager',
    
    # Integration
    'ComplianceIntegrationLayer',
    'IntegrationManager'
]