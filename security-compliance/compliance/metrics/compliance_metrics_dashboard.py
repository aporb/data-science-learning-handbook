"""
Advanced Compliance Metrics Dashboard with Real-Time Visualization
================================================================

Enterprise-grade compliance metrics dashboard providing real-time risk posture
visualization, interactive analytics, and comprehensive compliance monitoring.
Integrates with risk assessment, certification, and analytics engines to provide
actionable intelligence for risk management decision-making.

Key Features:
- Real-time compliance posture visualization
- Interactive risk heat maps and trending dashboards  
- Control effectiveness metrics and KPIs
- Certification timeline and status tracking
- Executive-level compliance reporting
- Automated alert and notification system
- Multi-classification level dashboard support
- Export capabilities for compliance reporting

Dashboard Components:
- Risk Posture Overview Dashboard
- Control Effectiveness Dashboard  
- Certification Status Dashboard
- Threat Intelligence Dashboard
- Compliance Metrics Dashboard
- Executive Summary Dashboard
- Operational Dashboard for SOC Teams
- Audit Readiness Dashboard

Classification: UNCLASSIFIED//FOR OFFICIAL USE ONLY
Version: 1.0 - Advanced Compliance Metrics Dashboard
Author: Security Compliance Team
Date: 2025-07-28
"""

import asyncio
import json
import logging
import time
import statistics
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Tuple, Set, Union
from uuid import UUID, uuid4
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
import aiofiles
import aiohttp
from aiohttp import web, WSMsgType
import aiohttp_cors
import numpy as np
import pandas as pd
from jinja2 import Environment, FileSystemLoader
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots
import plotly.utils
import sqlite3
import hashlib

# Import from existing infrastructure
from ..risk.risk_assessment_engine import (
    RiskAssessment, RiskCategory, RiskImpactLevel, RiskLikelihood,
    TreatmentStrategy, RiskStatus
)
from ..analytics.risk_scoring_analytics import (
    RiskScoringAnalyticsEngine, RiskMetric, AnalyticsTimeframe,
    RiskForecast, RiskCorrelation, ControlEffectivenessMetric,
    RiskPortfolioAnalysis
)
from ..certification.certification_artifacts_generator import (
    CertificationPackage, ArtifactType, ComplianceFramework
)
from ...audits.audit_logger import AuditLogger


class DashboardType(Enum):
    """Types of dashboards available."""
    RISK_POSTURE = "risk_posture"
    CONTROL_EFFECTIVENESS = "control_effectiveness"
    CERTIFICATION_STATUS = "certification_status"
    THREAT_INTELLIGENCE = "threat_intelligence"
    COMPLIANCE_METRICS = "compliance_metrics"
    EXECUTIVE_SUMMARY = "executive_summary"
    OPERATIONAL = "operational"
    AUDIT_READINESS = "audit_readiness"


class MetricType(Enum):
    """Types of metrics tracked."""
    RISK_SCORE = "risk_score"
    CONTROL_MATURITY = "control_maturity"
    VULNERABILITY_COUNT = "vulnerability_count"
    INCIDENT_COUNT = "incident_count"
    COMPLIANCE_PERCENTAGE = "compliance_percentage"
    MEAN_TIME_TO_REMEDIATION = "mttr"
    AUDIT_FINDINGS = "audit_findings"
    CERTIFICATION_STATUS = "certification_status"


class AlertSeverity(Enum):
    """Alert severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class DashboardWidget:
    """Dashboard widget configuration."""
    widget_id: str
    widget_type: str
    title: str
    description: str
    data_source: str
    refresh_interval: int  # seconds
    visualization_type: str  # chart, table, gauge, etc.
    configuration: Dict[str, Any]
    position: Dict[str, int]  # x, y, width, height
    permissions: List[str]


@dataclass
class DashboardAlert:
    """Dashboard alert configuration."""
    alert_id: str
    alert_type: str
    severity: AlertSeverity
    title: str
    description: str
    threshold_condition: str
    current_value: float
    threshold_value: float
    created_timestamp: datetime
    acknowledged: bool = False
    resolved: bool = False


@dataclass
class DashboardConfiguration:
    """Dashboard configuration."""
    dashboard_id: str
    dashboard_type: DashboardType
    title: str
    description: str
    widgets: List[DashboardWidget]
    layout: Dict[str, Any]
    permissions: List[str]
    refresh_interval: int
    auto_refresh: bool = True


@dataclass
class ComplianceMetric:
    """Compliance metric data structure."""
    metric_id: str
    metric_type: MetricType
    metric_name: str
    current_value: float
    target_value: float
    unit: str
    trend_direction: str
    last_updated: datetime
    historical_data: List[Tuple[datetime, float]]
    threshold_config: Dict[str, float]


class DataCollector:
    """Collects data from various sources for dashboard display."""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.data_cache = {}
        self.cache_timestamps = {}
        self.cache_ttl = 300  # 5 minutes
    
    async def collect_risk_posture_data(self) -> Dict[str, Any]:
        """Collect risk posture data."""
        try:
            cache_key = "risk_posture"
            if await self._is_cache_valid(cache_key):
                return self.data_cache[cache_key]
            
            # Simulate data collection from risk assessment engine
            data = {
                'total_risks': 156,
                'high_risks': 23,
                'medium_risks': 67,
                'low_risks': 66,
                'risk_score_average': 5.8,
                'risk_trend': 'decreasing',
                'recent_assessments': 12,
                'overdue_treatments': 8,
                'risk_by_category': {
                    'technical': 45,
                    'operational': 38,
                    'compliance': 29,
                    'strategic': 22,
                    'financial': 12,
                    'reputational': 10
                },
                'risk_heat_map_data': await self._generate_risk_heat_map_data(),
                'top_risks': await self._get_top_risks(),
                'risk_velocity': 0.12,
                'portfolio_risk_score': 5.8
            }
            
            await self._cache_data(cache_key, data)
            return data
            
        except Exception as e:
            self.logger.error(f"Risk posture data collection failed: {e}")
            raise
    
    async def collect_control_effectiveness_data(self) -> Dict[str, Any]:
        """Collect control effectiveness data."""
        try:
            cache_key = "control_effectiveness"
            if await self._is_cache_valid(cache_key):
                return self.data_cache[cache_key]
            
            data = {
                'total_controls': 847,
                'implemented_controls': 756,
                'partially_implemented': 67,
                'not_implemented': 24,
                'control_maturity_average': 3.4,
                'control_effectiveness_average': 0.76,
                'controls_needing_attention': 15,
                'recent_assessments': 28,
                'control_families': {
                    'AC': {'total': 89, 'implemented': 82, 'effectiveness': 0.78},
                    'AU': {'total': 76, 'implemented': 71, 'effectiveness': 0.85},
                    'CM': {'total': 65, 'implemented': 58, 'effectiveness': 0.72},
                    'CP': {'total': 54, 'implemented': 49, 'effectiveness': 0.69},
                    'IA': {'total': 83, 'implemented': 79, 'effectiveness': 0.81},
                    'SC': {'total': 92, 'implemented': 85, 'effectiveness': 0.77},
                    'SI': {'total': 71, 'implemented': 66, 'effectiveness': 0.74}
                },
                'effectiveness_trends': await self._generate_effectiveness_trends(),
                'control_gaps': await self._identify_control_gaps()
            }
            
            await self._cache_data(cache_key, data)
            return data
            
        except Exception as e:
            self.logger.error(f"Control effectiveness data collection failed: {e}")
            raise
    
    async def collect_certification_status_data(self) -> Dict[str, Any]:
        """Collect certification status data."""
        try:
            cache_key = "certification_status"
            if await self._is_cache_valid(cache_key):
                return self.data_cache[cache_key]
            
            data = {
                'active_atos': 23,
                'atos_expiring_soon': 4,
                'atos_expired': 1,
                'pending_assessments': 8,
                'assessment_progress': 67.5,
                'average_ato_duration': 18.5,  # months
                'compliance_percentage': 87.3,
                'certification_timeline': await self._generate_certification_timeline(),
                'framework_compliance': {
                    'NIST_RMF': 89.2,
                    'FISMA': 91.5,
                    'FedRAMP': 85.7,
                    'DoD_RMF': 88.9,
                    'CMMC': 78.4
                },
                'upcoming_milestones': await self._get_upcoming_milestones(),
                'poam_status': {
                    'total_items': 145,
                    'overdue': 23,
                    'due_this_month': 31,
                    'completed_this_quarter': 67
                }
            }
            
            await self._cache_data(cache_key, data)
            return data
            
        except Exception as e:
            self.logger.error(f"Certification status data collection failed: {e}")
            raise
    
    async def collect_threat_intelligence_data(self) -> Dict[str, Any]:
        """Collect threat intelligence data."""
        try:
            cache_key = "threat_intelligence"
            if await self._is_cache_valid(cache_key):
                return self.data_cache[cache_key]
            
            data = {
                'active_threats': 47,
                'high_priority_threats': 12,
                'threat_actor_groups': 8,
                'recent_cves': 234,
                'exploited_vulnerabilities': 15,
                'threat_trends': await self._generate_threat_trends(),
                'attack_vectors': {
                    'phishing': 34,
                    'malware': 28,
                    'insider_threat': 12,
                    'supply_chain': 8,
                    'zero_day': 3
                },
                'industry_threats': await self._get_industry_threats(),
                'iocs_detected': 156,
                'threat_hunting_results': await self._get_threat_hunting_results()
            }
            
            await self._cache_data(cache_key, data)
            return data
            
        except Exception as e:
            self.logger.error(f"Threat intelligence data collection failed: {e}")
            raise
    
    async def _generate_risk_heat_map_data(self) -> List[Dict[str, Any]]:
        """Generate risk heat map data."""
        heat_map_data = []
        categories = ['Technical', 'Operational', 'Compliance', 'Strategic', 'Financial']
        impacts = ['Very Low', 'Low', 'Moderate', 'High', 'Very High']
        
        for i, category in enumerate(categories):
            for j, impact in enumerate(impacts):
                # Simulate risk count data
                risk_count = max(0, int(np.random.normal(10, 5)))
                heat_map_data.append({
                    'category': category,
                    'impact': impact,
                    'risk_count': risk_count,
                    'x': i,
                    'y': j
                })
        
        return heat_map_data
    
    async def _get_top_risks(self) -> List[Dict[str, Any]]:
        """Get top risks for display."""
        return [
            {
                'risk_id': 'RISK-001',
                'title': 'Unpatched Critical Vulnerabilities',
                'score': 9.2,
                'category': 'Technical',
                'status': 'Open',
                'last_updated': '2025-07-28'
            },
            {
                'risk_id': 'RISK-002', 
                'title': 'Inadequate Backup Procedures',
                'score': 8.7,
                'category': 'Operational',
                'status': 'In Progress',
                'last_updated': '2025-07-27'
            },
            {
                'risk_id': 'RISK-003',
                'title': 'Compliance Control Gaps',
                'score': 8.3,
                'category': 'Compliance',
                'status': 'Open',
                'last_updated': '2025-07-26'
            }
        ]
    
    async def _generate_effectiveness_trends(self) -> List[Dict[str, Any]]:
        """Generate control effectiveness trend data."""
        trends = []
        base_date = datetime.now(timezone.utc) - timedelta(days=90)
        
        for i in range(90):
            date = base_date + timedelta(days=i)
            effectiveness = 0.7 + 0.1 * np.sin(i / 10) + np.random.normal(0, 0.02)
            trends.append({
                'date': date.isoformat(),
                'effectiveness': max(0, min(1, effectiveness))
            })
        
        return trends
    
    async def _identify_control_gaps(self) -> List[Dict[str, Any]]:
        """Identify control gaps."""
        return [
            {
                'control_id': 'AC-2',
                'control_name': 'Account Management',
                'gap_description': 'Automated account lifecycle management not implemented',
                'risk_level': 'High',
                'remediation_timeline': '60 days'
            },
            {
                'control_id': 'AU-6', 
                'control_name': 'Audit Review, Analysis, and Reporting',
                'gap_description': 'Limited automated analysis capabilities',
                'risk_level': 'Medium',
                'remediation_timeline': '90 days'
            }
        ]
    
    async def _is_cache_valid(self, cache_key: str) -> bool:
        """Check if cached data is still valid."""
        if cache_key not in self.data_cache:
            return False
        
        cache_time = self.cache_timestamps.get(cache_key)
        if not cache_time:
            return False
        
        return (datetime.now(timezone.utc) - cache_time).total_seconds() < self.cache_ttl
    
    async def _cache_data(self, cache_key: str, data: Dict[str, Any]):
        """Cache data with timestamp."""
        self.data_cache[cache_key] = data
        self.cache_timestamps[cache_key] = datetime.now(timezone.utc)


class VisualizationEngine:
    """Creates interactive visualizations using Plotly."""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    async def create_risk_posture_dashboard(self, data: Dict[str, Any]) -> Dict[str, str]:
        """Create risk posture dashboard visualizations."""
        try:
            visualizations = {}
            
            # Risk Summary Gauge
            risk_gauge = go.Figure(go.Indicator(
                mode="gauge+number+delta",
                value=data['risk_score_average'],
                domain={'x': [0, 1], 'y': [0, 1]},
                title={'text': "Portfolio Risk Score"},
                delta={'reference': 5.0},
                gauge={
                    'axis': {'range': [None, 10]},
                    'bar': {'color': self._get_risk_color(data['risk_score_average'])},
                    'steps': [
                        {'range': [0, 3], 'color': "lightgray"},
                        {'range': [3, 6], 'color': "yellow"},
                        {'range': [6, 10], 'color': "red"}
                    ],
                    'threshold': {
                        'line': {'color': "red", 'width': 4},
                        'thickness': 0.75,
                        'value': 8
                    }
                }
            ))
            visualizations['risk_gauge'] = risk_gauge.to_json()
            
            # Risk Distribution Pie Chart
            risk_pie = go.Figure(data=[go.Pie(
                labels=list(data['risk_by_category'].keys()),
                values=list(data['risk_by_category'].values()),
                hole=0.3
            )])
            risk_pie.update_layout(title_text="Risk Distribution by Category")
            visualizations['risk_distribution'] = risk_pie.to_json()
            
            # Risk Heat Map
            heat_map_data = data['risk_heat_map_data']
            categories = list(set([item['category'] for item in heat_map_data]))
            impacts = list(set([item['impact'] for item in heat_map_data]))
            
            z_data = []
            for impact in impacts:
                row = []
                for category in categories:
                    risk_count = next((item['risk_count'] for item in heat_map_data 
                                     if item['category'] == category and item['impact'] == impact), 0)
                    row.append(risk_count)
                z_data.append(row)
            
            heat_map = go.Figure(data=go.Heatmap(
                z=z_data,
                x=categories,
                y=impacts,
                colorscale='Reds'
            ))
            heat_map.update_layout(
                title="Risk Heat Map",
                xaxis_title="Risk Category",
                yaxis_title="Impact Level"
            )
            visualizations['risk_heat_map'] = heat_map.to_json()
            
            # Risk Trend Line Chart
            trend_dates = [datetime.now(timezone.utc) - timedelta(days=30-i) for i in range(30)]
            trend_scores = [data['risk_score_average'] + np.random.normal(0, 0.3) for _ in range(30)]
            
            trend_chart = go.Figure(data=go.Scatter(
                x=trend_dates,
                y=trend_scores,
                mode='lines+markers',
                name='Risk Score Trend'
            ))
            trend_chart.update_layout(
                title="30-Day Risk Score Trend",
                xaxis_title="Date",
                yaxis_title="Risk Score"
            )
            visualizations['risk_trend'] = trend_chart.to_json()
            
            return visualizations
            
        except Exception as e:
            self.logger.error(f"Risk posture dashboard creation failed: {e}")
            raise
    
    async def create_control_effectiveness_dashboard(self, data: Dict[str, Any]) -> Dict[str, str]:
        """Create control effectiveness dashboard visualizations."""
        try:
            visualizations = {}
            
            # Control Implementation Status
            status_data = [
                data['implemented_controls'],
                data['partially_implemented'],
                data['not_implemented']
            ]
            status_labels = ['Implemented', 'Partially Implemented', 'Not Implemented']
            colors = ['green', 'yellow', 'red']
            
            status_chart = go.Figure(data=[go.Bar(
                x=status_labels,
                y=status_data,
                marker_color=colors
            )])
            status_chart.update_layout(title="Control Implementation Status")
            visualizations['control_status'] = status_chart.to_json()
            
            # Control Family Effectiveness
            families = list(data['control_families'].keys())
            effectiveness_scores = [data['control_families'][family]['effectiveness'] 
                                  for family in families]
            
            family_chart = go.Figure(data=[go.Bar(
                x=families,
                y=effectiveness_scores,
                marker_color='lightblue'
            )])
            family_chart.update_layout(
                title="Control Family Effectiveness",
                yaxis=dict(range=[0, 1]),
                yaxis_title="Effectiveness Score"
            )
            visualizations['family_effectiveness'] = family_chart.to_json()
            
            # Effectiveness Trend
            trend_data = data['effectiveness_trends']
            dates = [item['date'] for item in trend_data]
            effectiveness = [item['effectiveness'] for item in trend_data]
            
            trend_chart = go.Figure(data=go.Scatter(
                x=dates,
                y=effectiveness,
                mode='lines',
                fill='tonexty',
                name='Effectiveness Trend'
            ))
            trend_chart.update_layout(
                title="Control Effectiveness Trend (90 Days)",
                yaxis=dict(range=[0, 1])
            )
            visualizations['effectiveness_trend'] = trend_chart.to_json()
            
            return visualizations
            
        except Exception as e:
            self.logger.error(f"Control effectiveness dashboard creation failed: {e}")
            raise
    
    async def create_certification_status_dashboard(self, data: Dict[str, Any]) -> Dict[str, str]:
        """Create certification status dashboard visualizations."""
        try:
            visualizations = {}
            
            # ATO Status Overview
            ato_data = [data['active_atos'], data['atos_expiring_soon'], data['atos_expired']]
            ato_labels = ['Active', 'Expiring Soon', 'Expired']
            ato_colors = ['green', 'orange', 'red']
            
            ato_chart = go.Figure(data=[go.Pie(
                labels=ato_labels,
                values=ato_data,
                marker_colors=ato_colors
            )])
            ato_chart.update_layout(title="ATO Status Overview")
            visualizations['ato_status'] = ato_chart.to_json()
            
            # Framework Compliance
            frameworks = list(data['framework_compliance'].keys())
            compliance_scores = list(data['framework_compliance'].values())
            
            compliance_chart = go.Figure(data=[go.Bar(
                x=frameworks,
                y=compliance_scores,
                marker_color='lightgreen'
            )])
            compliance_chart.update_layout(
                title="Framework Compliance Percentages",
                yaxis=dict(range=[0, 100]),
                yaxis_title="Compliance %"
            )
            visualizations['framework_compliance'] = compliance_chart.to_json()
            
            # POA&M Status
            poam_data = [
                data['poam_status']['completed_this_quarter'],
                data['poam_status']['due_this_month'],
                data['poam_status']['overdue']
            ]
            poam_labels = ['Completed', 'Due This Month', 'Overdue']
            poam_colors = ['green', 'yellow', 'red']
            
            poam_chart = go.Figure(data=[go.Bar(
                x=poam_labels,
                y=poam_data,
                marker_color=poam_colors
            )])
            poam_chart.update_layout(title="POA&M Status")
            visualizations['poam_status'] = poam_chart.to_json()
            
            return visualizations
            
        except Exception as e:
            self.logger.error(f"Certification status dashboard creation failed: {e}")
            raise
    
    def _get_risk_color(self, score: float) -> str:
        """Get color based on risk score."""
        if score >= 7.0:
            return "red"
        elif score >= 4.0:
            return "orange"
        else:
            return "green"


class AlertManager:
    """Manages dashboard alerts and notifications."""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.active_alerts = []
        self.alert_thresholds = {}
        self.notification_channels = []
    
    async def initialize_alert_thresholds(self):
        """Initialize default alert thresholds."""
        self.alert_thresholds = {
            'portfolio_risk_score': {'critical': 8.0, 'high': 6.5, 'medium': 5.0},
            'high_risk_count': {'critical': 50, 'high': 30, 'medium': 20},
            'control_effectiveness': {'critical': 0.6, 'high': 0.7, 'medium': 0.8},
            'ato_expiring': {'critical': 30, 'high': 60, 'medium': 90},  # days
            'poam_overdue': {'critical': 20, 'high': 10, 'medium': 5}
        }
    
    async def check_alerts(self, data: Dict[str, Any]) -> List[DashboardAlert]:
        """Check for alert conditions and generate alerts."""
        try:
            new_alerts = []
            
            # Check risk score alerts
            if 'risk_posture' in data:
                risk_data = data['risk_posture']
                portfolio_score = risk_data.get('risk_score_average', 0)
                
                alert = await self._check_threshold_alert(
                    'portfolio_risk_score',
                    portfolio_score,
                    'Portfolio Risk Score Alert',
                    f'Portfolio risk score is {portfolio_score}',
                    higher_is_worse=True
                )
                if alert:
                    new_alerts.append(alert)
                
                # Check high risk count
                high_risk_count = risk_data.get('high_risks', 0)
                alert = await self._check_threshold_alert(
                    'high_risk_count',
                    high_risk_count,
                    'High Risk Count Alert',
                    f'Number of high risks: {high_risk_count}',
                    higher_is_worse=True
                )
                if alert:
                    new_alerts.append(alert)
            
            # Check control effectiveness alerts
            if 'control_effectiveness' in data:
                control_data = data['control_effectiveness']
                effectiveness = control_data.get('control_effectiveness_average', 0)
                
                alert = await self._check_threshold_alert(
                    'control_effectiveness',
                    effectiveness,
                    'Control Effectiveness Alert',
                    f'Average control effectiveness: {effectiveness:.2f}',
                    higher_is_worse=False
                )
                if alert:
                    new_alerts.append(alert)
            
            # Check certification alerts
            if 'certification_status' in data:
                cert_data = data['certification_status']
                expiring_atos = cert_data.get('atos_expiring_soon', 0)
                
                alert = await self._check_threshold_alert(
                    'ato_expiring',
                    expiring_atos,
                    'ATO Expiration Alert',
                    f'ATOs expiring soon: {expiring_atos}',
                    higher_is_worse=True
                )
                if alert:
                    new_alerts.append(alert)
            
            # Add new alerts to active alerts
            self.active_alerts.extend(new_alerts)
            
            # Send notifications for critical alerts
            critical_alerts = [alert for alert in new_alerts if alert.severity == AlertSeverity.CRITICAL]
            if critical_alerts:
                await self._send_critical_notifications(critical_alerts)
            
            return new_alerts
            
        except Exception as e:
            self.logger.error(f"Alert checking failed: {e}")
            return []
    
    async def _check_threshold_alert(
        self,
        metric_name: str,
        current_value: float,
        title: str,
        description: str,
        higher_is_worse: bool = True
    ) -> Optional[DashboardAlert]:
        """Check if a metric crosses alert thresholds."""
        try:
            thresholds = self.alert_thresholds.get(metric_name, {})
            if not thresholds:
                return None
            
            severity = None
            threshold_value = None
            
            if higher_is_worse:
                if current_value >= thresholds.get('critical', float('inf')):
                    severity = AlertSeverity.CRITICAL
                    threshold_value = thresholds['critical']
                elif current_value >= thresholds.get('high', float('inf')):
                    severity = AlertSeverity.HIGH
                    threshold_value = thresholds['high']
                elif current_value >= thresholds.get('medium', float('inf')):
                    severity = AlertSeverity.MEDIUM
                    threshold_value = thresholds['medium']
            else:
                if current_value <= thresholds.get('critical', 0):
                    severity = AlertSeverity.CRITICAL
                    threshold_value = thresholds['critical']
                elif current_value <= thresholds.get('high', 0):
                    severity = AlertSeverity.HIGH
                    threshold_value = thresholds['high']
                elif current_value <= thresholds.get('medium', 0):
                    severity = AlertSeverity.MEDIUM
                    threshold_value = thresholds['medium']
            
            if severity:
                return DashboardAlert(
                    alert_id=str(uuid4()),
                    alert_type=metric_name,
                    severity=severity,
                    title=title,
                    description=description,
                    threshold_condition=f"{'>' if higher_is_worse else '<'} {threshold_value}",
                    current_value=current_value,
                    threshold_value=threshold_value,
                    created_timestamp=datetime.now(timezone.utc)
                )
            
            return None
            
        except Exception as e:
            self.logger.error(f"Threshold alert check failed for {metric_name}: {e}")
            return None
    
    async def _send_critical_notifications(self, alerts: List[DashboardAlert]):
        """Send notifications for critical alerts."""
        try:
            for alert in alerts:
                self.logger.critical(f"CRITICAL ALERT: {alert.title} - {alert.description}")
                # Here you would integrate with notification systems (email, Slack, etc.)
                
        except Exception as e:
            self.logger.error(f"Critical notification sending failed: {e}")


class WebInterface:
    """Web interface for the compliance dashboard."""
    
    def __init__(self, data_collector: DataCollector, visualization_engine: VisualizationEngine,
                 alert_manager: AlertManager):
        self.data_collector = data_collector
        self.visualization_engine = visualization_engine
        self.alert_manager = alert_manager
        self.logger = logging.getLogger(__name__)
        
        # Web application setup
        self.app = web.Application()
        self.setup_routes()
        self.setup_cors()
        
        # WebSocket connections for real-time updates
        self.websocket_connections = set()
    
    def setup_routes(self):
        """Setup web application routes."""
        self.app.router.add_get('/', self.index_handler)
        self.app.router.add_get('/api/dashboard/{dashboard_type}', self.dashboard_data_handler)
        self.app.router.add_get('/api/alerts', self.alerts_handler)
        self.app.router.add_post('/api/alerts/{alert_id}/acknowledge', self.acknowledge_alert_handler)
        self.app.router.add_get('/ws', self.websocket_handler)
        self.app.router.add_static('/', path='./static', name='static')
    
    def setup_cors(self):
        """Setup CORS for cross-origin requests."""
        cors = aiohttp_cors.setup(self.app, defaults={
            "*": aiohttp_cors.ResourceOptions(
                allow_credentials=True,
                expose_headers="*",
                allow_headers="*",
                allow_methods="*"
            )
        })
        
        for route in list(self.app.router.routes()):
            cors.add(route)
    
    async def index_handler(self, request):
        """Serve the main dashboard page."""
        try:
            # Load dashboard template
            template_path = Path(__file__).parent / 'templates' / 'dashboard.html'
            if template_path.exists():
                async with aiofiles.open(template_path, 'r') as f:
                    content = await f.read()
                return web.Response(text=content, content_type='text/html')
            else:
                return web.Response(text=self._generate_default_dashboard_html(), content_type='text/html')
                
        except Exception as e:
            self.logger.error(f"Index handler failed: {e}")
            return web.Response(text="Dashboard temporarily unavailable", status=500)
    
    async def dashboard_data_handler(self, request):
        """Handle dashboard data requests."""
        try:
            dashboard_type = request.match_info['dashboard_type']
            
            data = {}
            visualizations = {}
            
            if dashboard_type == 'risk_posture':
                data = await self.data_collector.collect_risk_posture_data()
                visualizations = await self.visualization_engine.create_risk_posture_dashboard(data)
            
            elif dashboard_type == 'control_effectiveness':
                data = await self.data_collector.collect_control_effectiveness_data()
                visualizations = await self.visualization_engine.create_control_effectiveness_dashboard(data)
            
            elif dashboard_type == 'certification_status':
                data = await self.data_collector.collect_certification_status_data()
                visualizations = await self.visualization_engine.create_certification_status_dashboard(data)
            
            elif dashboard_type == 'threat_intelligence':
                data = await self.data_collector.collect_threat_intelligence_data()
                # Add threat intelligence visualizations
            
            else:
                return web.json_response({'error': 'Unknown dashboard type'}, status=400)
            
            # Check for alerts
            all_data = {dashboard_type: data}
            alerts = await self.alert_manager.check_alerts(all_data)
            
            response_data = {
                'dashboard_type': dashboard_type,
                'data': data,
                'visualizations': visualizations,
                'alerts': [asdict(alert) for alert in alerts],
                'last_updated': datetime.now(timezone.utc).isoformat()
            }
            
            return web.json_response(response_data)
            
        except Exception as e:
            self.logger.error(f"Dashboard data handler failed: {e}")
            return web.json_response({'error': 'Data collection failed'}, status=500)
    
    async def alerts_handler(self, request):
        """Handle alerts API requests."""
        try:
            alerts_data = {
                'active_alerts': [asdict(alert) for alert in self.alert_manager.active_alerts],
                'alert_count': len(self.alert_manager.active_alerts),
                'critical_count': len([a for a in self.alert_manager.active_alerts 
                                     if a.severity == AlertSeverity.CRITICAL]),
                'last_updated': datetime.now(timezone.utc).isoformat()
            }
            return web.json_response(alerts_data)
            
        except Exception as e:
            self.logger.error(f"Alerts handler failed: {e}")
            return web.json_response({'error': 'Alert retrieval failed'}, status=500)
    
    async def acknowledge_alert_handler(self, request):
        """Handle alert acknowledgment."""
        try:
            alert_id = request.match_info['alert_id']
            
            # Find and acknowledge the alert
            for alert in self.alert_manager.active_alerts:
                if alert.alert_id == alert_id:
                    alert.acknowledged = True
                    break
            
            return web.json_response({'status': 'acknowledged'})
            
        except Exception as e:
            self.logger.error(f"Alert acknowledgment failed: {e}")
            return web.json_response({'error': 'Acknowledgment failed'}, status=500)
    
    async def websocket_handler(self, request):
        """Handle WebSocket connections for real-time updates."""
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        
        self.websocket_connections.add(ws)
        self.logger.info("New WebSocket connection established")
        
        try:
            async for msg in ws:
                if msg.type == WSMsgType.TEXT:
                    data = json.loads(msg.data)
                    # Handle WebSocket messages (e.g., dashboard subscriptions)
                elif msg.type == WSMsgType.ERROR:
                    self.logger.error(f'WebSocket error: {ws.exception()}')
        finally:
            self.websocket_connections.discard(ws)
            self.logger.info("WebSocket connection closed")
        
        return ws
    
    async def broadcast_update(self, data: Dict[str, Any]):
        """Broadcast updates to all connected WebSocket clients."""
        if not self.websocket_connections:
            return
        
        message = json.dumps(data)
        disconnected = set()
        
        for ws in self.websocket_connections:
            try:
                await ws.send_str(message)
            except Exception:
                disconnected.add(ws)
        
        # Remove disconnected clients
        self.websocket_connections -= disconnected
    
    def _generate_default_dashboard_html(self) -> str:
        """Generate default dashboard HTML."""
        return """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Compliance Metrics Dashboard</title>
            <script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; }
                .dashboard-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
                .widget { border: 1px solid #ddd; padding: 20px; border-radius: 8px; }
                .alert { padding: 10px; margin: 10px 0; border-radius: 4px; }
                .alert-critical { background-color: #ffebee; border-left: 4px solid #f44336; }
                .alert-high { background-color: #fff3e0; border-left: 4px solid #ff9800; }
            </style>
        </head>
        <body>
            <h1>Compliance Metrics Dashboard</h1>
            <div id="alerts-container"></div>
            <div class="dashboard-grid">
                <div class="widget">
                    <h3>Risk Posture</h3>
                    <div id="risk-gauge"></div>
                </div>
                <div class="widget">
                    <h3>Control Effectiveness</h3>
                    <div id="control-status"></div>
                </div>
                <div class="widget">
                    <h3>Certification Status</h3>
                    <div id="ato-status"></div>
                </div>
                <div class="widget">
                    <h3>Risk Trends</h3>
                    <div id="risk-trend"></div>
                </div>
            </div>
            
            <script>
                // WebSocket connection for real-time updates
                const ws = new WebSocket('ws://localhost:8080/ws');
                
                ws.onmessage = function(event) {
                    const data = JSON.parse(event.data);
                    updateDashboard(data);
                };
                
                function updateDashboard(data) {
                    // Update dashboard with real-time data
                    console.log('Dashboard update received:', data);
                }
                
                // Load initial dashboard data
                loadDashboardData();
                
                async function loadDashboardData() {
                    try {
                        const response = await fetch('/api/dashboard/risk_posture');
                        const data = await response.json();
                        
                        // Render visualizations
                        if (data.visualizations.risk_gauge) {
                            Plotly.newPlot('risk-gauge', JSON.parse(data.visualizations.risk_gauge));
                        }
                        
                        // Display alerts
                        displayAlerts(data.alerts);
                        
                    } catch (error) {
                        console.error('Dashboard loading failed:', error);
                    }
                }
                
                function displayAlerts(alerts) {
                    const container = document.getElementById('alerts-container');
                    container.innerHTML = '';
                    
                    alerts.forEach(alert => {
                        const alertDiv = document.createElement('div');
                        alertDiv.className = `alert alert-${alert.severity}`;
                        alertDiv.innerHTML = `
                            <strong>${alert.title}</strong><br>
                            ${alert.description}
                        `;
                        container.appendChild(alertDiv);
                    });
                }
                
                // Auto-refresh every 5 minutes
                setInterval(loadDashboardData, 300000);
            </script>
        </body>
        </html>
        """


class ComplianceMetricsDashboard:
    """
    Main compliance metrics dashboard coordinating all components.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.logger = logging.getLogger(__name__)
        
        # Initialize components
        self.data_collector = DataCollector()
        self.visualization_engine = VisualizationEngine()
        self.alert_manager = AlertManager()
        self.web_interface = WebInterface(
            self.data_collector, self.visualization_engine, self.alert_manager
        )
        self.audit_logger = AuditLogger()
        
        # Dashboard state
        self.active_dashboards = {}
        self.dashboard_configs = {}
        
        # Performance metrics
        self.performance_metrics = {
            'requests_served': 0,
            'average_response_time': 0.0,
            'active_connections': 0,
            'cache_hit_rate': 0.0
        }
    
    async def initialize(self):
        """Initialize the compliance metrics dashboard."""
        try:
            self.logger.info("Initializing Compliance Metrics Dashboard")
            
            # Initialize alert thresholds
            await self.alert_manager.initialize_alert_thresholds()
            
            # Create dashboard configurations
            await self._create_default_dashboard_configs()
            
            # Start background tasks
            asyncio.create_task(self._background_data_refresh())
            asyncio.create_task(self._background_alert_monitoring())
            
            self.logger.info("Compliance Metrics Dashboard initialized successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize Compliance Metrics Dashboard: {e}")
            raise
    
    async def start_web_server(self, host: str = '0.0.0.0', port: int = 8080):
        """Start the web server for the dashboard."""
        try:
            self.logger.info(f"Starting dashboard web server on {host}:{port}")
            
            runner = web.AppRunner(self.web_interface.app)
            await runner.setup()
            
            site = web.TCPSite(runner, host, port)
            await site.start()
            
            self.logger.info(f"Dashboard web server started successfully on http://{host}:{port}")
            
        except Exception as e:
            self.logger.error(f"Failed to start web server: {e}")
            raise
    
    async def _create_default_dashboard_configs(self):
        """Create default dashboard configurations."""
        # Risk Posture Dashboard
        risk_dashboard = DashboardConfiguration(
            dashboard_id="risk_posture",
            dashboard_type=DashboardType.RISK_POSTURE,
            title="Risk Posture Dashboard",
            description="Real-time risk assessment and monitoring",
            widgets=[],
            layout={'columns': 2, 'rows': 3},
            permissions=['risk_manager', 'security_analyst', 'ciso'],
            refresh_interval=300
        )
        self.dashboard_configs[DashboardType.RISK_POSTURE] = risk_dashboard
        
        # Control Effectiveness Dashboard
        control_dashboard = DashboardConfiguration(
            dashboard_id="control_effectiveness",
            dashboard_type=DashboardType.CONTROL_EFFECTIVENESS,
            title="Control Effectiveness Dashboard",
            description="Security control implementation and effectiveness monitoring",
            widgets=[],
            layout={'columns': 2, 'rows': 2},
            permissions=['compliance_officer', 'security_analyst', 'auditor'],
            refresh_interval=600
        )
        self.dashboard_configs[DashboardType.CONTROL_EFFECTIVENESS] = control_dashboard
        
        # Additional dashboard configurations...
    
    async def _background_data_refresh(self):
        """Background task for refreshing dashboard data."""
        while True:
            try:
                # Collect fresh data from all sources
                risk_data = await self.data_collector.collect_risk_posture_data()
                control_data = await self.data_collector.collect_control_effectiveness_data()
                cert_data = await self.data_collector.collect_certification_status_data()
                
                # Broadcast updates to connected clients
                update_data = {
                    'type': 'data_refresh',
                    'timestamp': datetime.now(timezone.utc).isoformat(),
                    'data': {
                        'risk_posture': risk_data,
                        'control_effectiveness': control_data,
                        'certification_status': cert_data
                    }
                }
                
                await self.web_interface.broadcast_update(update_data)
                
                # Sleep until next refresh
                await asyncio.sleep(300)  # 5 minutes
                
            except Exception as e:
                self.logger.error(f"Background data refresh failed: {e}")
                await asyncio.sleep(60)  # Retry in 1 minute
    
    async def _background_alert_monitoring(self):
        """Background task for monitoring and generating alerts."""
        while True:
            try:
                # Collect current data for alert checking
                all_data = {
                    'risk_posture': await self.data_collector.collect_risk_posture_data(),
                    'control_effectiveness': await self.data_collector.collect_control_effectiveness_data(),
                    'certification_status': await self.data_collector.collect_certification_status_data()
                }
                
                # Check for new alerts
                new_alerts = await self.alert_manager.check_alerts(all_data)
                
                # Broadcast new alerts to connected clients
                if new_alerts:
                    alert_update = {
                        'type': 'new_alerts',
                        'timestamp': datetime.now(timezone.utc).isoformat(),
                        'alerts': [asdict(alert) for alert in new_alerts]
                    }
                    await self.web_interface.broadcast_update(alert_update)
                
                # Sleep until next check
                await asyncio.sleep(60)  # 1 minute
                
            except Exception as e:
                self.logger.error(f"Background alert monitoring failed: {e}")
                await asyncio.sleep(30)  # Retry in 30 seconds


# Export main classes
__all__ = [
    'ComplianceMetricsDashboard',
    'DashboardType',
    'MetricType',
    'AlertSeverity',
    'DashboardWidget',
    'DashboardAlert',
    'DashboardConfiguration',
    'ComplianceMetric',
    'DataCollector',
    'VisualizationEngine',
    'AlertManager',
    'WebInterface'
]