"""
Real-Time Compliance Dashboard Framework
=======================================

This module provides comprehensive real-time compliance dashboards that provide
visibility into compliance posture and automate regulatory reporting across all
security domains with integration to existing monitoring and audit systems.

Key Features:
- Real-time compliance posture visualization
- Executive-level compliance summaries with drill-down capabilities
- Technical compliance metrics and KPIs
- Multi-classification level reporting with proper access controls
- Integration with existing monitoring and audit infrastructure
- Automated alert generation for compliance drift detection

Integration Points:
- Enhanced monitoring system for real-time data
- Integrated audit orchestrator for comprehensive audit data
- Enhanced log aggregator for event correlation
- Multi-classification engine for classified data handling
- RBAC system for access-controlled dashboard viewing

Classification: UNCLASSIFIED//FOR OFFICIAL USE ONLY
Version: 1.0 - Comprehensive Compliance Visualization
Author: Security Compliance Team
Date: 2025-07-28
"""

import asyncio
import json
import logging
import time
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Tuple, Set, Union, AsyncGenerator
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

# Import existing audit infrastructure
from ...audits.integrated_audit_orchestrator import IntegratedAuditOrchestrator
from ...audits.enhanced_monitoring_system import EnhancedMonitoringSystem
from ...audits.enhanced_log_aggregator import EnhancedLogAggregator
from ...audits.audit_logger import AuditLogger, AuditEvent, AuditEventType, AuditSeverity

# Import RBAC for access control
from ...auth.rbac_system import RBACController

# Import multi-classification for data handling
from ...multi_classification.enhanced_classification_engine import EnhancedMultiClassificationEngine

logger = logging.getLogger(__name__)


class DashboardType(Enum):
    """Types of compliance dashboards."""
    EXECUTIVE = "executive"
    TECHNICAL = "technical" 
    OPERATIONAL = "operational"
    MULTI_CLASSIFICATION = "multi_classification"
    HISTORICAL = "historical"
    REAL_TIME = "real_time"


class ComplianceMetricType(Enum):
    """Types of compliance metrics."""
    OVERALL_POSTURE = "overall_posture"
    CONTROL_EFFECTIVENESS = "control_effectiveness"
    VULNERABILITY_MANAGEMENT = "vulnerability_management"
    INCIDENT_RESPONSE = "incident_response"
    ACCESS_CONTROL = "access_control"
    DATA_PROTECTION = "data_protection"
    CLASSIFICATION_COMPLIANCE = "classification_compliance"
    AUDIT_COVERAGE = "audit_coverage"
    REGULATORY_ADHERENCE = "regulatory_adherence"


class AlertLevel(Enum):
    """Alert levels for compliance issues."""
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"
    EMERGENCY = "emergency"


@dataclass
class ComplianceMetric:
    """Individual compliance metric."""
    metric_id: str = field(default_factory=lambda: str(uuid4()))
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    # Metric identification
    metric_type: ComplianceMetricType = ComplianceMetricType.OVERALL_POSTURE
    metric_name: str = ""
    description: str = ""
    
    # Metric values
    current_value: float = 0.0
    target_value: float = 100.0
    threshold_warning: float = 80.0
    threshold_critical: float = 60.0
    
    # Compliance framework context
    framework: str = ""  # e.g., "DoD 8500.01E", "NIST SP 800-53"
    control_reference: str = ""
    regulatory_requirement: str = ""
    
    # Classification and access
    classification_level: str = "UNCLASSIFIED"
    requires_clearance: bool = False
    
    # Trend and analysis
    trend_direction: str = "stable"  # improving, declining, stable
    variance_percentage: float = 0.0
    historical_average: float = 0.0
    
    # Context and metadata
    data_sources: List[str] = field(default_factory=list)
    calculation_method: str = ""
    last_calculation: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    # Alert information
    current_alert_level: AlertLevel = AlertLevel.INFO
    alert_message: str = ""
    
    def calculate_compliance_score(self) -> float:
        """Calculate normalized compliance score (0-100)."""
        if self.target_value == 0:
            return 0.0
            
        score = (self.current_value / self.target_value) * 100
        return min(100.0, max(0.0, score))
    
    def get_alert_level(self) -> AlertLevel:
        """Determine alert level based on current value."""
        score = self.calculate_compliance_score()
        
        if score < self.threshold_critical:
            return AlertLevel.CRITICAL
        elif score < self.threshold_warning:
            return AlertLevel.WARNING
        else:
            return AlertLevel.INFO
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert metric to dictionary for serialization."""
        return {
            "metric_id": self.metric_id,
            "timestamp": self.timestamp.isoformat(),
            "metric_type": self.metric_type.value,
            "metric_name": self.metric_name,
            "description": self.description,
            "current_value": self.current_value,
            "target_value": self.target_value,
            "compliance_score": self.calculate_compliance_score(),
            "threshold_warning": self.threshold_warning,
            "threshold_critical": self.threshold_critical,
            "framework": self.framework,
            "control_reference": self.control_reference,
            "classification_level": self.classification_level,
            "trend_direction": self.trend_direction,
            "variance_percentage": self.variance_percentage,
            "current_alert_level": self.get_alert_level().value,
            "alert_message": self.alert_message,
            "data_sources": self.data_sources,
            "last_calculation": self.last_calculation.isoformat()
        }


@dataclass 
class DashboardWidget:
    """Dashboard widget configuration."""
    widget_id: str = field(default_factory=lambda: str(uuid4()))
    widget_type: str = ""  # chart, table, metric, alert, trend
    title: str = ""
    description: str = ""
    
    # Data configuration
    data_source: str = ""
    refresh_interval_seconds: int = 30
    
    # Visualization configuration
    chart_type: str = "line"  # line, bar, pie, gauge, heatmap
    display_options: Dict[str, Any] = field(default_factory=dict)
    
    # Access control
    required_clearance: str = "UNCLASSIFIED"
    required_permissions: List[str] = field(default_factory=list)
    
    # Layout
    position: Dict[str, int] = field(default_factory=lambda: {"x": 0, "y": 0, "width": 4, "height": 3})
    
    # Interactivity
    drill_down_enabled: bool = True
    export_enabled: bool = True
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert widget to dictionary."""
        return asdict(self)


@dataclass
class DashboardConfiguration:
    """Complete dashboard configuration."""
    dashboard_id: str = field(default_factory=lambda: str(uuid4()))
    dashboard_type: DashboardType = DashboardType.EXECUTIVE
    name: str = ""
    description: str = ""
    
    # Widgets and layout
    widgets: List[DashboardWidget] = field(default_factory=list)
    layout_config: Dict[str, Any] = field(default_factory=dict)
    
    # Access control and security
    required_clearance: str = "UNCLASSIFIED"
    required_roles: List[str] = field(default_factory=list)
    classification_level: str = "UNCLASSIFIED"
    
    # Refresh and updates
    auto_refresh_enabled: bool = True
    refresh_interval_seconds: int = 30
    
    # Customization
    theme: str = "default"
    custom_css: str = ""
    
    # Metadata
    created_by: str = ""
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_modified: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert dashboard configuration to dictionary."""
        return {
            "dashboard_id": self.dashboard_id,
            "dashboard_type": self.dashboard_type.value,
            "name": self.name,
            "description": self.description,
            "widgets": [widget.to_dict() for widget in self.widgets],
            "layout_config": self.layout_config,
            "required_clearance": self.required_clearance,
            "required_roles": self.required_roles,
            "classification_level": self.classification_level,
            "auto_refresh_enabled": self.auto_refresh_enabled,
            "refresh_interval_seconds": self.refresh_interval_seconds,
            "theme": self.theme,
            "created_by": self.created_by,
            "created_at": self.created_at.isoformat(),
            "last_modified": self.last_modified.isoformat()
        }


class ComplianceDataProvider:
    """Provider for compliance data from various sources."""
    
    def __init__(
        self,
        audit_orchestrator: IntegratedAuditOrchestrator,
        monitoring_system: EnhancedMonitoringSystem,
        log_aggregator: EnhancedLogAggregator,
        classification_engine: Optional[EnhancedMultiClassificationEngine] = None
    ):
        """Initialize compliance data provider."""
        self.audit_orchestrator = audit_orchestrator
        self.monitoring_system = monitoring_system
        self.log_aggregator = log_aggregator
        self.classification_engine = classification_engine
        
        # Data cache for performance
        self.data_cache = {}
        self.cache_timestamps = {}
        self.cache_ttl_seconds = 30
        
        # Metric calculations
        self.metric_calculators = self._initialize_metric_calculators()
        
        logger.info("Compliance data provider initialized")
    
    def _initialize_metric_calculators(self) -> Dict[str, callable]:
        """Initialize metric calculation functions."""
        return {
            ComplianceMetricType.OVERALL_POSTURE: self._calculate_overall_posture,
            ComplianceMetricType.CONTROL_EFFECTIVENESS: self._calculate_control_effectiveness,
            ComplianceMetricType.VULNERABILITY_MANAGEMENT: self._calculate_vulnerability_management,
            ComplianceMetricType.INCIDENT_RESPONSE: self._calculate_incident_response,
            ComplianceMetricType.ACCESS_CONTROL: self._calculate_access_control,
            ComplianceMetricType.DATA_PROTECTION: self._calculate_data_protection,
            ComplianceMetricType.CLASSIFICATION_COMPLIANCE: self._calculate_classification_compliance,
            ComplianceMetricType.AUDIT_COVERAGE: self._calculate_audit_coverage,
            ComplianceMetricType.REGULATORY_ADHERENCE: self._calculate_regulatory_adherence
        }
    
    async def get_compliance_metrics(
        self, 
        metric_types: Optional[List[ComplianceMetricType]] = None,
        time_range: Optional[Tuple[datetime, datetime]] = None,
        classification_filter: Optional[str] = None
    ) -> List[ComplianceMetric]:
        """Get compliance metrics with optional filtering."""
        if metric_types is None:
            metric_types = list(ComplianceMetricType)
        
        metrics = []
        
        for metric_type in metric_types:
            try:
                calculator = self.metric_calculators.get(metric_type)
                if calculator:
                    metric = await calculator(time_range, classification_filter)
                    if metric:
                        metrics.append(metric)
            except Exception as e:
                logger.error(f"Error calculating metric {metric_type}: {e}")
        
        return metrics
    
    async def _calculate_overall_posture(
        self, 
        time_range: Optional[Tuple[datetime, datetime]] = None,
        classification_filter: Optional[str] = None
    ) -> ComplianceMetric:
        """Calculate overall compliance posture."""
        try:
            # Get comprehensive metrics from integrated systems
            audit_metrics = self.audit_orchestrator.get_comprehensive_metrics()
            monitoring_metrics = self.monitoring_system.get_performance_metrics()
            
            # Calculate overall score based on multiple factors
            audit_health = audit_metrics.get("integration_status", {}).get("overall_health", 0) * 100
            monitoring_health = self._extract_health_score(monitoring_metrics)
            
            # Average health scores
            overall_score = (audit_health + monitoring_health) / 2
            
            # Determine trend
            trend = self._calculate_trend(overall_score, "overall_posture")
            
            metric = ComplianceMetric(
                metric_type=ComplianceMetricType.OVERALL_POSTURE,
                metric_name="Overall Compliance Posture",
                description="Comprehensive compliance health across all security domains",
                current_value=overall_score,
                target_value=95.0,
                threshold_warning=85.0,
                threshold_critical=70.0,
                framework="DoD 8500.01E",
                trend_direction=trend,
                data_sources=["audit_orchestrator", "monitoring_system"],
                calculation_method="Weighted average of system health metrics"
            )
            
            metric.current_alert_level = metric.get_alert_level()
            if metric.current_alert_level != AlertLevel.INFO:
                metric.alert_message = f"Overall compliance posture at {overall_score:.1f}% - below target"
            
            return metric
            
        except Exception as e:
            logger.error(f"Error calculating overall posture: {e}")
            return None
    
    async def _calculate_control_effectiveness(
        self,
        time_range: Optional[Tuple[datetime, datetime]] = None,
        classification_filter: Optional[str] = None
    ) -> ComplianceMetric:
        """Calculate security control effectiveness."""
        try:
            # Get monitoring metrics for control effectiveness
            monitoring_metrics = self.monitoring_system.get_performance_metrics()
            
            # Calculate control effectiveness based on threat detection and response
            threat_metrics = monitoring_metrics.get("threat_detector", {})
            active_threats = threat_metrics.get("active_threats", 0)
            
            # Control effectiveness inversely related to unmitigated threats
            # Assume baseline of 100 total possible threats
            baseline_threats = 100
            effectiveness_score = max(0, (baseline_threats - active_threats) / baseline_threats * 100)
            
            metric = ComplianceMetric(
                metric_type=ComplianceMetricType.CONTROL_EFFECTIVENESS,
                metric_name="Security Control Effectiveness",
                description="Effectiveness of implemented security controls",
                current_value=effectiveness_score,
                target_value=98.0,
                threshold_warning=90.0,
                threshold_critical=80.0,
                framework="NIST SP 800-53",
                control_reference="SC-7",
                data_sources=["monitoring_system"],
                calculation_method="Threat mitigation rate calculation"
            )
            
            metric.current_alert_level = metric.get_alert_level()
            if active_threats > 5:
                metric.alert_message = f"{active_threats} active threats detected - control effectiveness may be compromised"
            
            return metric
            
        except Exception as e:
            logger.error(f"Error calculating control effectiveness: {e}")
            return None
    
    async def _calculate_vulnerability_management(
        self,
        time_range: Optional[Tuple[datetime, datetime]] = None,
        classification_filter: Optional[str] = None
    ) -> ComplianceMetric:
        """Calculate vulnerability management effectiveness."""
        try:
            # Get system health data
            audit_health = await self.audit_orchestrator.health_check()
            
            # Calculate vulnerability score based on system health
            component_health = audit_health.get("components", {})
            healthy_components = sum(1 for comp in component_health.values() 
                                   if comp.get("status") == "healthy")
            total_components = len(component_health)
            
            if total_components > 0:
                vulnerability_score = (healthy_components / total_components) * 100
            else:
                vulnerability_score = 100.0
            
            metric = ComplianceMetric(
                metric_type=ComplianceMetricType.VULNERABILITY_MANAGEMENT,
                metric_name="Vulnerability Management",
                description="System vulnerability management and remediation effectiveness",
                current_value=vulnerability_score,
                target_value=99.0,
                threshold_warning=95.0,
                threshold_critical=90.0,
                framework="DoD 8500.01E",
                control_reference="SI-2",
                data_sources=["audit_orchestrator"],
                calculation_method="Component health assessment"
            )
            
            metric.current_alert_level = metric.get_alert_level()
            unhealthy_count = total_components - healthy_components
            if unhealthy_count > 0:
                metric.alert_message = f"{unhealthy_count} unhealthy components detected"
            
            return metric
            
        except Exception as e:
            logger.error(f"Error calculating vulnerability management: {e}")
            return None
    
    async def _calculate_incident_response(
        self,
        time_range: Optional[Tuple[datetime, datetime]] = None,
        classification_filter: Optional[str] = None
    ) -> ComplianceMetric:
        """Calculate incident response capability."""
        try:
            # Get monitoring system metrics for incident response
            monitoring_metrics = self.monitoring_system.get_performance_metrics()
            
            # Calculate response time and effectiveness
            system_metrics = monitoring_metrics.get("monitoring_system", {})
            alerts_sent = system_metrics.get("alerts_sent", 0)
            threats_detected = system_metrics.get("threats_detected", 0)
            
            # Response effectiveness based on alert-to-threat ratio
            if threats_detected > 0:
                response_effectiveness = min(100, (alerts_sent / threats_detected) * 100)
            else:
                response_effectiveness = 100.0
            
            metric = ComplianceMetric(
                metric_type=ComplianceMetricType.INCIDENT_RESPONSE,
                metric_name="Incident Response Capability",
                description="Effectiveness of incident detection and response procedures",
                current_value=response_effectiveness,
                target_value=100.0,
                threshold_warning=95.0,
                threshold_critical=85.0,
                framework="NIST SP 800-53",
                control_reference="IR-1",
                data_sources=["monitoring_system"],
                calculation_method="Alert generation rate vs. threat detection"
            )
            
            metric.current_alert_level = metric.get_alert_level()
            if response_effectiveness < 95:
                metric.alert_message = "Incident response effectiveness below target - review alert procedures"
            
            return metric
            
        except Exception as e:
            logger.error(f"Error calculating incident response: {e}")
            return None
    
    async def _calculate_access_control(
        self,
        time_range: Optional[Tuple[datetime, datetime]] = None,
        classification_filter: Optional[str] = None
    ) -> ComplianceMetric:
        """Calculate access control effectiveness."""
        try:
            # Get audit orchestrator metrics for access control
            audit_metrics = self.audit_orchestrator.get_comprehensive_metrics()
            
            # Calculate access control score based on system integration health
            rbac_metrics = audit_metrics.get("component_metrics", {}).get("rbac_integration", {})
            integration_status = audit_metrics.get("integration_status", {})
            
            # Access control effectiveness based on RBAC system health
            rbac_health = 100.0  # Default if no specific metrics
            if "rbac_system" in integration_status.get("integrations", {}):
                rbac_status = integration_status["integrations"]["rbac_system"]
                rbac_health = 100.0 if rbac_status == "active" else 75.0
            
            metric = ComplianceMetric(
                metric_type=ComplianceMetricType.ACCESS_CONTROL,
                metric_name="Access Control Effectiveness",
                description="Role-based access control and authorization effectiveness",
                current_value=rbac_health,
                target_value=100.0,
                threshold_warning=95.0,
                threshold_critical=85.0,
                framework="DoD 8500.01E",
                control_reference="AC-2",
                data_sources=["audit_orchestrator", "rbac_system"],
                calculation_method="RBAC system integration health"
            )
            
            metric.current_alert_level = metric.get_alert_level()
            if rbac_health < 100:
                metric.alert_message = "RBAC system integration issues detected"
            
            return metric
            
        except Exception as e:
            logger.error(f"Error calculating access control: {e}")
            return None
    
    async def _calculate_data_protection(
        self,
        time_range: Optional[Tuple[datetime, datetime]] = None,
        classification_filter: Optional[str] = None
    ) -> ComplianceMetric:
        """Calculate data protection effectiveness."""
        try:
            # Get log aggregator metrics for data protection
            log_metrics = self.log_aggregator.get_performance_metrics()
            
            # Data protection score based on log processing health
            aggregator_metrics = log_metrics.get("log_aggregator", {})
            processing_errors = aggregator_metrics.get("processing_errors", 0)
            total_events = aggregator_metrics.get("total_events_processed", 1)
            
            # Data protection effectiveness inversely related to processing errors
            error_rate = (processing_errors / total_events) * 100 if total_events > 0 else 0
            protection_score = max(0, 100 - error_rate)
            
            metric = ComplianceMetric(
                metric_type=ComplianceMetricType.DATA_PROTECTION,
                metric_name="Data Protection Effectiveness",
                description="Data integrity and protection mechanism effectiveness",
                current_value=protection_score,
                target_value=99.9,
                threshold_warning=99.0,
                threshold_critical=95.0,
                framework="DoD 8500.01E",
                control_reference="SC-8",
                data_sources=["log_aggregator"],
                calculation_method="Inverse of data processing error rate"
            )
            
            metric.current_alert_level = metric.get_alert_level()
            if error_rate > 1.0:
                metric.alert_message = f"Data processing error rate at {error_rate:.2f}%"
            
            return metric
            
        except Exception as e:
            logger.error(f"Error calculating data protection: {e}")
            return None
    
    async def _calculate_classification_compliance(
        self,
        time_range: Optional[Tuple[datetime, datetime]] = None,
        classification_filter: Optional[str] = None
    ) -> ComplianceMetric:
        """Calculate classification handling compliance."""
        try:
            # Get classification-related metrics
            audit_metrics = self.audit_orchestrator.get_comprehensive_metrics()
            classification_metrics = audit_metrics.get("component_metrics", {}).get("classification", {})
            
            # Classification compliance based on system health
            integration_status = audit_metrics.get("integration_status", {})
            classification_health = 100.0  # Default
            
            if "classification_framework" in integration_status.get("integrations", {}):
                classification_status = integration_status["integrations"]["classification_framework"]
                classification_health = 100.0 if classification_status == "active" else 60.0
            
            metric = ComplianceMetric(
                metric_type=ComplianceMetricType.CLASSIFICATION_COMPLIANCE,
                metric_name="Classification Handling Compliance",
                description="Multi-level security classification handling compliance",
                current_value=classification_health,
                target_value=100.0,
                threshold_warning=95.0,
                threshold_critical=80.0,
                framework="DoD 8500.01E",
                control_reference="AC-4",
                classification_level="CONFIDENTIAL",
                requires_clearance=True,
                data_sources=["classification_engine", "audit_orchestrator"],
                calculation_method="Classification framework integration health"
            )
            
            metric.current_alert_level = metric.get_alert_level()
            if classification_health < 100:
                metric.alert_message = "Classification framework integration issues"
            
            return metric
            
        except Exception as e:
            logger.error(f"Error calculating classification compliance: {e}")
            return None
    
    async def _calculate_audit_coverage(
        self,
        time_range: Optional[Tuple[datetime, datetime]] = None,
        classification_filter: Optional[str] = None
    ) -> ComplianceMetric:
        """Calculate audit coverage effectiveness."""
        try:
            # Get audit system health and coverage metrics
            audit_health = await self.audit_orchestrator.health_check()
            audit_metrics = self.audit_orchestrator.get_comprehensive_metrics()
            
            # Calculate coverage based on active integrations
            integration_status = audit_metrics.get("integration_status", {})
            active_integrations = integration_status.get("active_integrations", 0)
            total_integrations = len(integration_status.get("integrations", {}))
            
            if total_integrations > 0:
                coverage_score = (active_integrations / total_integrations) * 100
            else:
                coverage_score = 0.0
            
            metric = ComplianceMetric(
                metric_type=ComplianceMetricType.AUDIT_COVERAGE,
                metric_name="Audit Coverage",
                description="Comprehensive audit trail coverage across all systems",
                current_value=coverage_score,
                target_value=100.0,
                threshold_warning=95.0,
                threshold_critical=85.0,
                framework="DoD 8500.01E",
                control_reference="AU-2",
                data_sources=["audit_orchestrator"],
                calculation_method="Active system integrations percentage"
            )
            
            metric.current_alert_level = metric.get_alert_level()
            failed_integrations = total_integrations - active_integrations
            if failed_integrations > 0:
                metric.alert_message = f"{failed_integrations} audit integrations inactive"
            
            return metric
            
        except Exception as e:
            logger.error(f"Error calculating audit coverage: {e}")
            return None
    
    async def _calculate_regulatory_adherence(
        self,
        time_range: Optional[Tuple[datetime, datetime]] = None,
        classification_filter: Optional[str] = None
    ) -> ComplianceMetric:
        """Calculate regulatory adherence score."""
        try:
            # Calculate overall regulatory adherence based on all other metrics
            all_metrics = await self.get_compliance_metrics([
                ComplianceMetricType.OVERALL_POSTURE,
                ComplianceMetricType.CONTROL_EFFECTIVENESS,
                ComplianceMetricType.AUDIT_COVERAGE,
                ComplianceMetricType.DATA_PROTECTION
            ])
            
            if all_metrics:
                # Average compliance scores for regulatory adherence
                scores = [metric.calculate_compliance_score() for metric in all_metrics]
                regulatory_score = sum(scores) / len(scores)
            else:
                regulatory_score = 85.0  # Default conservative score
            
            metric = ComplianceMetric(
                metric_type=ComplianceMetricType.REGULATORY_ADHERENCE,
                metric_name="Regulatory Adherence",
                description="Overall adherence to regulatory requirements",
                current_value=regulatory_score,
                target_value=98.0,
                threshold_warning=92.0,
                threshold_critical=85.0,
                framework="Multiple (DoD 8500.01E, NIST SP 800-53, FISMA)",
                regulatory_requirement="Federal compliance mandates",
                data_sources=["comprehensive_metrics"],
                calculation_method="Weighted average of all compliance metrics"
            )
            
            metric.current_alert_level = metric.get_alert_level()
            if regulatory_score < 95:
                metric.alert_message = f"Regulatory adherence at {regulatory_score:.1f}% - review compliance gaps"
            
            return metric
            
        except Exception as e:
            logger.error(f"Error calculating regulatory adherence: {e}")
            return None
    
    def _extract_health_score(self, metrics: Dict[str, Any]) -> float:
        """Extract health score from monitoring metrics."""
        try:
            system_metrics = metrics.get("monitoring_system", {})
            
            # Calculate health based on various factors
            events_per_second = system_metrics.get("events_per_second", 0)
            active_threats = system_metrics.get("active_threats", 0)
            buffer_size = system_metrics.get("buffer_size", 0)
            
            # Health score calculation (simplified)
            health_score = 100.0
            
            # Reduce score for high threat count
            if active_threats > 10:
                health_score -= min(20, active_threats)
                
            # Reduce score for buffer overload
            if buffer_size > 8000:  # Assuming max buffer size ~10000
                health_score -= 10
            
            return max(0, health_score)
            
        except Exception as e:
            logger.error(f"Error extracting health score: {e}")
            return 75.0  # Default moderate health
    
    def _calculate_trend(self, current_value: float, metric_name: str) -> str:
        """Calculate trend direction for metric."""
        try:
            # Get cached previous value
            cache_key = f"trend_{metric_name}"
            previous_value = self.data_cache.get(cache_key, current_value)
            
            # Update cache
            self.data_cache[cache_key] = current_value
            self.cache_timestamps[cache_key] = datetime.now(timezone.utc)
            
            # Determine trend
            if current_value > previous_value + 1.0:
                return "improving"
            elif current_value < previous_value - 1.0:
                return "declining"
            else:
                return "stable"
                
        except Exception as e:
            logger.error(f"Error calculating trend: {e}")
            return "stable"


class ComplianceDashboard:
    """
    Main compliance dashboard providing real-time visibility into compliance posture.
    
    This dashboard integrates with all existing security infrastructure to provide
    comprehensive compliance monitoring and reporting capabilities.
    """
    
    def __init__(
        self,
        dashboard_config: DashboardConfiguration,
        data_provider: ComplianceDataProvider,
        rbac_controller: Optional[RBACController] = None
    ):
        """Initialize compliance dashboard."""
        self.config = dashboard_config
        self.data_provider = data_provider
        self.rbac_controller = rbac_controller
        
        # Dashboard state
        self.is_active = False
        self.last_refresh = datetime.now(timezone.utc)
        self.refresh_tasks: List[asyncio.Task] = []
        
        # Data cache
        self.dashboard_data = {}
        self.data_lock = Lock()
        
        # User sessions
        self.active_sessions = {}
        
        logger.info(f"Compliance dashboard {self.config.name} initialized")
    
    async def start(self):
        """Start the dashboard with automatic refresh."""
        if self.is_active:
            return
        
        self.is_active = True
        
        # Start refresh tasks
        if self.config.auto_refresh_enabled:
            self.refresh_tasks = [
                asyncio.create_task(self._auto_refresh_loop()),
                asyncio.create_task(self._session_cleanup_loop())
            ]
        
        # Initial data load
        await self.refresh_data()
        
        logger.info(f"Dashboard {self.config.name} started")
    
    async def stop(self):
        """Stop the dashboard."""
        self.is_active = False
        
        # Cancel refresh tasks
        for task in self.refresh_tasks:
            if not task.done():
                task.cancel()
        
        if self.refresh_tasks:
            await asyncio.gather(*self.refresh_tasks, return_exceptions=True)
        
        logger.info(f"Dashboard {self.config.name} stopped")
    
    async def refresh_data(self, user_clearance: str = "UNCLASSIFIED"):
        """Refresh dashboard data based on user clearance."""
        try:
            start_time = time.time()
            
            # Get compliance metrics
            metrics = await self.data_provider.get_compliance_metrics(
                classification_filter=user_clearance
            )
            
            # Filter metrics based on clearance level
            filtered_metrics = self._filter_metrics_by_clearance(metrics, user_clearance)
            
            # Organize data by widget requirements
            dashboard_data = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "refresh_duration_ms": (time.time() - start_time) * 1000,
                "metrics": [metric.to_dict() for metric in filtered_metrics],
                "summary": self._generate_summary(filtered_metrics),
                "alerts": self._extract_alerts(filtered_metrics),
                "trends": self._generate_trends(filtered_metrics)
            }
            
            # Update cached data
            with self.data_lock:
                self.dashboard_data[user_clearance] = dashboard_data
                self.last_refresh = datetime.now(timezone.utc)
            
            logger.debug(f"Dashboard data refreshed for {user_clearance} clearance")
            
        except Exception as e:
            logger.error(f"Error refreshing dashboard data: {e}")
    
    def _filter_metrics_by_clearance(
        self, 
        metrics: List[ComplianceMetric], 
        user_clearance: str
    ) -> List[ComplianceMetric]:
        """Filter metrics based on user clearance level."""
        clearance_levels = {
            "UNCLASSIFIED": 0,
            "CONFIDENTIAL": 1,
            "SECRET": 2,
            "TOP_SECRET": 3
        }
        
        user_level = clearance_levels.get(user_clearance, 0)
        filtered_metrics = []
        
        for metric in metrics:
            metric_level = clearance_levels.get(metric.classification_level, 0)
            
            if metric_level <= user_level:
                # User can access this metric
                if metric.requires_clearance and user_level == 0:
                    # Skip metrics requiring clearance for unclassified users
                    continue
                filtered_metrics.append(metric)
        
        return filtered_metrics
    
    def _generate_summary(self, metrics: List[ComplianceMetric]) -> Dict[str, Any]:
        """Generate executive summary from metrics."""
        if not metrics:
            return {"overall_score": 0, "status": "No Data", "total_metrics": 0}
        
        # Calculate overall compliance score
        scores = [metric.calculate_compliance_score() for metric in metrics]
        overall_score = sum(scores) / len(scores)
        
        # Count alerts by level
        alert_counts = {level.value: 0 for level in AlertLevel}
        for metric in metrics:
            alert_level = metric.get_alert_level()
            alert_counts[alert_level.value] += 1
        
        # Determine overall status
        if overall_score >= 95:
            status = "Excellent"
        elif overall_score >= 85:
            status = "Good"
        elif overall_score >= 75:
            status = "Fair"
        else:
            status = "Needs Attention"
        
        return {
            "overall_score": round(overall_score, 1),
            "status": status,
            "total_metrics": len(metrics),
            "alert_counts": alert_counts,
            "metrics_by_framework": self._group_metrics_by_framework(metrics)
        }
    
    def _extract_alerts(self, metrics: List[ComplianceMetric]) -> List[Dict[str, Any]]:
        """Extract active alerts from metrics."""
        alerts = []
        
        for metric in metrics:
            alert_level = metric.get_alert_level()
            if alert_level in [AlertLevel.WARNING, AlertLevel.CRITICAL, AlertLevel.EMERGENCY]:
                alerts.append({
                    "metric_id": metric.metric_id,
                    "metric_name": metric.metric_name,
                    "alert_level": alert_level.value,
                    "message": metric.alert_message,
                    "current_value": metric.current_value,
                    "target_value": metric.target_value,
                    "framework": metric.framework,
                    "timestamp": metric.timestamp.isoformat()
                })
        
        # Sort by alert level priority
        priority_order = {"emergency": 0, "critical": 1, "warning": 2}
        alerts.sort(key=lambda x: priority_order.get(x["alert_level"], 3))
        
        return alerts
    
    def _generate_trends(self, metrics: List[ComplianceMetric]) -> Dict[str, Any]:
        """Generate trend analysis from metrics."""
        trends = {
            "improving": [],
            "declining": [], 
            "stable": []
        }
        
        for metric in metrics:
            trends[metric.trend_direction].append({
                "metric_name": metric.metric_name,
                "current_value": metric.current_value,
                "variance_percentage": metric.variance_percentage
            })
        
        return trends
    
    def _group_metrics_by_framework(self, metrics: List[ComplianceMetric]) -> Dict[str, Any]:
        """Group metrics by compliance framework."""
        frameworks = defaultdict(list)
        
        for metric in metrics:
            if metric.framework:
                frameworks[metric.framework].append({
                    "name": metric.metric_name,
                    "score": metric.calculate_compliance_score(),
                    "alert_level": metric.get_alert_level().value
                })
        
        # Calculate framework scores
        framework_scores = {}
        for framework, framework_metrics in frameworks.items():
            scores = [m["score"] for m in framework_metrics]
            framework_scores[framework] = {
                "average_score": sum(scores) / len(scores) if scores else 0,
                "metric_count": len(framework_metrics),
                "metrics": framework_metrics
            }
        
        return framework_scores
    
    async def get_dashboard_data(
        self, 
        user_id: str, 
        session_id: str,
        user_clearance: str = "UNCLASSIFIED"
    ) -> Dict[str, Any]:
        """Get dashboard data for specific user session."""
        try:
            # Validate access if RBAC controller available
            if self.rbac_controller:
                access_granted = await self._validate_dashboard_access(user_id, user_clearance)
                if not access_granted:
                    return {"error": "Access denied - insufficient permissions"}
            
            # Get cached data or refresh if needed
            with self.data_lock:
                cached_data = self.dashboard_data.get(user_clearance)
            
            if not cached_data or self._is_data_stale():
                await self.refresh_data(user_clearance)
                with self.data_lock:
                    cached_data = self.dashboard_data.get(user_clearance, {})
            
            # Track user session
            self.active_sessions[session_id] = {
                "user_id": user_id,
                "user_clearance": user_clearance,
                "last_access": datetime.now(timezone.utc)
            }
            
            # Add session context to response
            response_data = cached_data.copy()
            response_data["session_info"] = {
                "session_id": session_id,
                "user_clearance": user_clearance,
                "dashboard_type": self.config.dashboard_type.value,
                "last_refresh": self.last_refresh.isoformat()
            }
            
            return response_data
            
        except Exception as e:
            logger.error(f"Error getting dashboard data: {e}")
            return {"error": "Internal server error"}
    
    async def _validate_dashboard_access(self, user_id: str, user_clearance: str) -> bool:
        """Validate user access to dashboard."""
        try:
            # Check if user has required roles
            if self.config.required_roles:
                user_roles = await self.rbac_controller.get_user_roles(user_id)
                user_role_names = [role.name for role in user_roles]
                
                if not any(role in user_role_names for role in self.config.required_roles):
                    return False
            
            # Check clearance level
            clearance_levels = {
                "UNCLASSIFIED": 0,
                "CONFIDENTIAL": 1, 
                "SECRET": 2,
                "TOP_SECRET": 3
            }
            
            required_level = clearance_levels.get(self.config.required_clearance, 0)
            user_level = clearance_levels.get(user_clearance, 0)
            
            return user_level >= required_level
            
        except Exception as e:
            logger.error(f"Error validating dashboard access: {e}")
            return False
    
    def _is_data_stale(self) -> bool:
        """Check if cached data is stale."""
        if not self.last_refresh:
            return True
        
        staleness_threshold = timedelta(seconds=self.config.refresh_interval_seconds)
        return datetime.now(timezone.utc) - self.last_refresh > staleness_threshold
    
    async def _auto_refresh_loop(self):
        """Automatic data refresh loop."""
        while self.is_active:
            try:
                # Refresh data for all clearance levels that have active sessions
                clearance_levels = set()
                
                with self.data_lock:
                    for session_info in self.active_sessions.values():
                        clearance_levels.add(session_info["user_clearance"])
                
                # Refresh data for each active clearance level
                for clearance in clearance_levels:
                    await self.refresh_data(clearance)
                
                await asyncio.sleep(self.config.refresh_interval_seconds)
                
            except Exception as e:
                logger.error(f"Error in auto-refresh loop: {e}")
                await asyncio.sleep(60)  # Wait before retrying
    
    async def _session_cleanup_loop(self):
        """Clean up inactive user sessions."""
        while self.is_active:
            try:
                current_time = datetime.now(timezone.utc)
                session_timeout = timedelta(hours=1)  # 1 hour timeout
                
                # Remove inactive sessions
                inactive_sessions = []
                for session_id, session_info in self.active_sessions.items():
                    if current_time - session_info["last_access"] > session_timeout:
                        inactive_sessions.append(session_id)
                
                for session_id in inactive_sessions:
                    del self.active_sessions[session_id]
                
                await asyncio.sleep(300)  # Clean up every 5 minutes
                
            except Exception as e:
                logger.error(f"Error in session cleanup: {e}")
                await asyncio.sleep(600)
    
    def get_config(self) -> Dict[str, Any]:
        """Get dashboard configuration."""
        return self.config.to_dict()
    
    async def update_config(self, new_config: DashboardConfiguration):
        """Update dashboard configuration."""
        self.config = new_config
        
        # Restart if refresh interval changed
        if self.is_active:
            await self.stop()
            await self.start()
        
        logger.info(f"Dashboard {self.config.name} configuration updated")


class DashboardManager:
    """
    Manager for multiple compliance dashboards with integrated data sources.
    """
    
    def __init__(
        self,
        audit_orchestrator: IntegratedAuditOrchestrator,
        monitoring_system: EnhancedMonitoringSystem,
        log_aggregator: EnhancedLogAggregator,
        classification_engine: Optional[EnhancedMultiClassificationEngine] = None,
        rbac_controller: Optional[RBACController] = None
    ):
        """Initialize dashboard manager."""
        # Initialize data provider
        self.data_provider = ComplianceDataProvider(
            audit_orchestrator, monitoring_system, log_aggregator, classification_engine
        )
        
        self.rbac_controller = rbac_controller
        
        # Dashboard registry
        self.dashboards: Dict[str, ComplianceDashboard] = {}
        
        # Default dashboard configurations
        self.default_configs = self._create_default_dashboard_configs()
        
        logger.info("Dashboard manager initialized")
    
    def _create_default_dashboard_configs(self) -> Dict[str, DashboardConfiguration]:
        """Create default dashboard configurations."""
        configs = {}
        
        # Executive Dashboard
        executive_widgets = [
            DashboardWidget(
                widget_type="metric",
                title="Overall Compliance Posture",
                data_source="overall_posture",
                chart_type="gauge",
                position={"x": 0, "y": 0, "width": 6, "height": 4}
            ),
            DashboardWidget(
                widget_type="alert",
                title="Critical Alerts", 
                data_source="critical_alerts",
                chart_type="table",
                position={"x": 6, "y": 0, "width": 6, "height": 4}
            ),
            DashboardWidget(
                widget_type="chart",
                title="Compliance Trends",
                data_source="compliance_trends",
                chart_type="line",
                position={"x": 0, "y": 4, "width": 12, "height": 6}
            )
        ]
        
        configs["executive"] = DashboardConfiguration(
            dashboard_type=DashboardType.EXECUTIVE,
            name="Executive Compliance Dashboard",
            description="High-level compliance overview for executive leadership",
            widgets=executive_widgets,
            required_clearance="UNCLASSIFIED",
            refresh_interval_seconds=60
        )
        
        # Technical Dashboard
        technical_widgets = [
            DashboardWidget(
                widget_type="metric",
                title="Control Effectiveness",
                data_source="control_effectiveness", 
                chart_type="gauge",
                position={"x": 0, "y": 0, "width": 4, "height": 3}
            ),
            DashboardWidget(
                widget_type="metric",
                title="Vulnerability Management",
                data_source="vulnerability_management",
                chart_type="gauge",
                position={"x": 4, "y": 0, "width": 4, "height": 3}
            ),
            DashboardWidget(
                widget_type="metric",
                title="Incident Response",
                data_source="incident_response",
                chart_type="gauge", 
                position={"x": 8, "y": 0, "width": 4, "height": 3}
            ),
            DashboardWidget(
                widget_type="table",
                title="System Health",
                data_source="system_health",
                position={"x": 0, "y": 3, "width": 6, "height": 6}
            ),
            DashboardWidget(
                widget_type="chart",
                title="Performance Metrics",
                data_source="performance_metrics",
                chart_type="line",
                position={"x": 6, "y": 3, "width": 6, "height": 6}
            )
        ]
        
        configs["technical"] = DashboardConfiguration(
            dashboard_type=DashboardType.TECHNICAL,
            name="Technical Compliance Dashboard",
            description="Detailed technical compliance metrics and system health",
            widgets=technical_widgets,
            required_clearance="UNCLASSIFIED",
            required_roles=["security_analyst", "system_administrator"],
            refresh_interval_seconds=30
        )
        
        return configs
    
    async def create_dashboard(
        self, 
        dashboard_type: str,
        custom_config: Optional[DashboardConfiguration] = None
    ) -> str:
        """Create a new dashboard."""
        try:
            # Use custom config or default
            if custom_config:
                config = custom_config
            else:
                config = self.default_configs.get(dashboard_type)
                if not config:
                    raise ValueError(f"Unknown dashboard type: {dashboard_type}")
            
            # Create dashboard
            dashboard = ComplianceDashboard(
                dashboard_config=config,
                data_provider=self.data_provider,
                rbac_controller=self.rbac_controller
            )
            
            # Start dashboard
            await dashboard.start()
            
            # Register dashboard
            self.dashboards[config.dashboard_id] = dashboard
            
            logger.info(f"Created dashboard: {config.name} ({config.dashboard_id})")
            return config.dashboard_id
            
        except Exception as e:
            logger.error(f"Error creating dashboard: {e}")
            raise
    
    async def get_dashboard_data(
        self,
        dashboard_id: str,
        user_id: str,
        session_id: str,
        user_clearance: str = "UNCLASSIFIED"
    ) -> Dict[str, Any]:
        """Get data for specific dashboard."""
        dashboard = self.dashboards.get(dashboard_id)
        if not dashboard:
            return {"error": "Dashboard not found"}
        
        return await dashboard.get_dashboard_data(user_id, session_id, user_clearance)
    
    async def list_dashboards(self, user_clearance: str = "UNCLASSIFIED") -> List[Dict[str, Any]]:
        """List available dashboards for user."""
        dashboard_list = []
        
        for dashboard_id, dashboard in self.dashboards.items():
            config = dashboard.get_config()
            
            # Check if user can access this dashboard
            clearance_levels = {
                "UNCLASSIFIED": 0,
                "CONFIDENTIAL": 1,
                "SECRET": 2, 
                "TOP_SECRET": 3
            }
            
            required_level = clearance_levels.get(config["required_clearance"], 0)
            user_level = clearance_levels.get(user_clearance, 0)
            
            if user_level >= required_level:
                dashboard_list.append({
                    "dashboard_id": dashboard_id,
                    "name": config["name"],
                    "description": config["description"],
                    "dashboard_type": config["dashboard_type"],
                    "required_clearance": config["required_clearance"]
                })
        
        return dashboard_list
    
    async def start_all_dashboards(self):
        """Start all registered dashboards."""
        for dashboard in self.dashboards.values():
            if not dashboard.is_active:
                await dashboard.start()
        
        logger.info("All dashboards started")
    
    async def stop_all_dashboards(self):
        """Stop all registered dashboards."""
        for dashboard in self.dashboards.values():
            if dashboard.is_active:
                await dashboard.stop()
        
        logger.info("All dashboards stopped")
    
    async def health_check(self) -> Dict[str, Any]:
        """Check health of dashboard manager."""
        health_status = {
            "status": "healthy",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "total_dashboards": len(self.dashboards),
            "active_dashboards": sum(1 for d in self.dashboards.values() if d.is_active),
            "dashboards": {}
        }
        
        for dashboard_id, dashboard in self.dashboards.items():
            health_status["dashboards"][dashboard_id] = {
                "active": dashboard.is_active,
                "last_refresh": dashboard.last_refresh.isoformat() if dashboard.last_refresh else None,
                "active_sessions": len(dashboard.active_sessions)
            }
        
        return health_status


# Factory function for creating dashboard manager
def create_dashboard_manager(
    audit_orchestrator: IntegratedAuditOrchestrator,
    monitoring_system: EnhancedMonitoringSystem,
    log_aggregator: EnhancedLogAggregator,
    classification_engine: Optional[EnhancedMultiClassificationEngine] = None,
    rbac_controller: Optional[RBACController] = None
) -> DashboardManager:
    """Create and initialize dashboard manager."""
    return DashboardManager(
        audit_orchestrator=audit_orchestrator,
        monitoring_system=monitoring_system,
        log_aggregator=log_aggregator,
        classification_engine=classification_engine,
        rbac_controller=rbac_controller
    )


if __name__ == "__main__":
    # Example usage
    print("Real-Time Compliance Dashboard Framework - see code for usage examples")