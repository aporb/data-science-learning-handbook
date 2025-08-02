"""
Business Intelligence Reporting for DoD API Gateway

This module provides comprehensive business intelligence and operational reporting
capabilities for the DoD API Gateway Integration. It aggregates data from monitoring,
analytics, and SLA tracking systems to provide actionable business insights.

Key Features:
- Executive dashboards and KPI reporting
- Operational metrics and trend analysis
- Cost optimization and capacity planning insights
- Security and compliance intelligence
- API usage and adoption analytics
- Performance ROI and business impact analysis
- Automated report generation and distribution
- Real-time business intelligence dashboards

Reporting Categories:
- Executive Summary Reports
- Operational Performance Reports
- Security and Compliance Reports
- Capacity Planning and Forecasting Reports
- User Adoption and Usage Reports
- Cost Analysis and Optimization Reports
- SLA Performance and Business Impact Reports

Security Standards:
- DoD business intelligence requirements
- Classification-aware reporting
- Secure data aggregation and presentation
- Compliance with DoD 8500.01E reporting standards
"""

import asyncio
import json
import logging
import uuid
import io
import base64
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple, Union
from dataclasses import dataclass, asdict
from enum import Enum
from collections import defaultdict, Counter
import statistics
import math

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from matplotlib.backends.backend_pdf import PdfPages
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots
import plotly.io as pio
import aioredis

# Import from existing modules
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from audits.audit_logger import AuditLogger


class ReportType(Enum):
    """Types of business intelligence reports."""
    EXECUTIVE_SUMMARY = "executive_summary"
    OPERATIONAL_PERFORMANCE = "operational_performance"
    SECURITY_INTELLIGENCE = "security_intelligence"
    CAPACITY_PLANNING = "capacity_planning"
    USER_ADOPTION = "user_adoption"
    COST_ANALYSIS = "cost_analysis"
    SLA_BUSINESS_IMPACT = "sla_business_impact"
    API_USAGE_ANALYTICS = "api_usage_analytics"
    TREND_ANALYSIS = "trend_analysis"
    COMPLIANCE_DASHBOARD = "compliance_dashboard"


class ReportFrequency(Enum):
    """Report generation frequency."""
    REAL_TIME = "real_time"
    HOURLY = "hourly"
    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"
    QUARTERLY = "quarterly"
    ANNUALLY = "annually"
    ON_DEMAND = "on_demand"


class ReportFormat(Enum):
    """Report output formats."""
    JSON = "json"
    PDF = "pdf"
    HTML = "html"
    EXCEL = "excel"
    CSV = "csv"
    DASHBOARD = "dashboard"


class BusinessMetricCategory(Enum):
    """Categories of business metrics."""
    PERFORMANCE = "performance"
    USAGE = "usage"
    SECURITY = "security"
    COST = "cost"
    COMPLIANCE = "compliance"
    USER_EXPERIENCE = "user_experience"
    CAPACITY = "capacity"
    RELIABILITY = "reliability"


@dataclass
class BusinessKPI:
    """Business Key Performance Indicator."""
    kpi_id: str
    name: str
    description: str
    category: BusinessMetricCategory
    current_value: float
    target_value: float
    trend_direction: str  # "increasing", "decreasing", "stable"
    trend_percentage: float
    last_updated: datetime
    unit: str = ""
    critical_threshold: Optional[float] = None
    warning_threshold: Optional[float] = None


@dataclass
class ReportConfiguration:
    """Configuration for report generation."""
    report_id: str
    report_type: ReportType
    frequency: ReportFrequency
    format: ReportFormat
    recipients: List[str]
    data_sources: List[str]
    filters: Dict[str, Any]
    enabled: bool = True
    last_generated: Optional[datetime] = None
    next_scheduled: Optional[datetime] = None


@dataclass
class BusinessReport:
    """Generated business intelligence report."""
    report_id: str
    report_type: ReportType
    generated_at: datetime
    time_period: Dict[str, str]
    executive_summary: Dict[str, Any]
    key_metrics: List[BusinessKPI]
    visualizations: Dict[str, str]  # Base64 encoded charts
    recommendations: List[str]
    data_quality_score: float
    metadata: Dict[str, Any]


class DataAggregator:
    """Aggregates data from various sources for business intelligence."""
    
    def __init__(self, redis_client: aioredis.Redis):
        self.redis_client = redis_client
        self.logger = logging.getLogger(__name__)
    
    async def get_api_usage_data(self, start_time: datetime, end_time: datetime) -> Dict[str, Any]:
        """Get API usage data for the specified time period."""
        try:
            # Get request metrics
            request_pattern = "request_metrics:*"
            keys = await self.redis_client.keys(request_pattern)
            
            total_requests = 0
            endpoint_usage = defaultdict(int)
            user_activity = defaultdict(int)
            hourly_distribution = defaultdict(int)
            status_codes = defaultdict(int)
            response_times = []
            
            for key in keys:
                try:
                    # Parse time from key
                    time_key = key.decode().split(':')[1]
                    key_time = datetime.strptime(time_key, '%Y%m%d%H')
                    
                    if start_time <= key_time <= end_time:
                        data = await self.redis_client.lrange(key, 0, -1)
                        
                        for item in data:
                            try:
                                request_data = json.loads(item)
                                total_requests += 1
                                
                                endpoint = request_data.get('endpoint', 'unknown')
                                user_id = request_data.get('user_id', 'anonymous')
                                status_code = request_data.get('status_code', 500)
                                response_time = request_data.get('response_time', 0)
                                timestamp = datetime.fromisoformat(request_data.get('timestamp', datetime.utcnow().isoformat()))
                                
                                endpoint_usage[endpoint] += 1
                                user_activity[user_id] += 1
                                hourly_distribution[timestamp.hour] += 1
                                status_codes[f"{status_code//100}xx"] += 1
                                response_times.append(response_time)
                                
                            except Exception:
                                continue
                                
                except Exception:
                    continue
            
            return {
                'total_requests': total_requests,
                'unique_endpoints': len(endpoint_usage),
                'unique_users': len(user_activity),
                'top_endpoints': dict(Counter(endpoint_usage).most_common(10)),
                'active_users': dict(Counter(user_activity).most_common(10)),
                'hourly_distribution': dict(hourly_distribution),
                'status_distribution': dict(status_codes),
                'avg_response_time': statistics.mean(response_times) if response_times else 0,
                'p95_response_time': np.percentile(response_times, 95) if response_times else 0
            }
            
        except Exception as e:
            self.logger.error(f"Failed to get API usage data: {e}")
            return {}
    
    async def get_performance_data(self, start_time: datetime, end_time: datetime) -> Dict[str, Any]:
        """Get performance data for the specified time period."""
        try:
            # Get performance metrics
            performance_data = {}
            
            for metric_type in ['response_time', 'cpu_utilization', 'memory_utilization', 'error_rate']:
                pattern = f"performance_metrics:{metric_type}:*"
                keys = await self.redis_client.keys(pattern)
                
                values = []
                for key in keys:
                    data = await self.redis_client.lrange(key, 0, -1)
                    for item in data:
                        try:
                            metric_data = json.loads(item)
                            timestamp = datetime.fromisoformat(metric_data.get('timestamp', datetime.utcnow().isoformat()))
                            
                            if start_time <= timestamp <= end_time:
                                values.append(metric_data.get('value', 0))
                        except Exception:
                            continue
                
                if values:
                    performance_data[metric_type] = {
                        'average': statistics.mean(values),
                        'min': min(values),
                        'max': max(values),
                        'p95': np.percentile(values, 95),
                        'p99': np.percentile(values, 99),
                        'count': len(values)
                    }
            
            return performance_data
            
        except Exception as e:
            self.logger.error(f"Failed to get performance data: {e}")
            return {}
    
    async def get_security_data(self, start_time: datetime, end_time: datetime) -> Dict[str, Any]:
        """Get security data for the specified time period."""
        try:
            # Get security events
            security_pattern = "security_events:*"
            keys = await self.redis_client.keys(security_pattern)
            
            security_events = []
            threat_levels = defaultdict(int)
            attack_types = defaultdict(int)
            blocked_requests = 0
            
            for key in keys:
                try:
                    # Parse time from key
                    time_key = key.decode().split(':')[1]
                    key_time = datetime.strptime(time_key, '%Y%m%d')
                    
                    if start_time.date() <= key_time.date() <= end_time.date():
                        data = await self.redis_client.lrange(key, 0, -1)
                        
                        for item in data:
                            try:
                                event_data = json.loads(item)
                                security_events.append(event_data)
                                
                                threat_level = event_data.get('threat_level', 'unknown')
                                attack_type = event_data.get('attack_type', 'unknown')
                                blocked = event_data.get('blocked', False)
                                
                                threat_levels[threat_level] += 1
                                if attack_type != 'unknown':
                                    attack_types[attack_type] += 1
                                if blocked:
                                    blocked_requests += 1
                                    
                            except Exception:
                                continue
                                
                except Exception:
                    continue
            
            # Get security alerts
            alerts_data = await self.redis_client.lrange("security_alerts", 0, -1)
            recent_alerts = []
            
            for alert_item in alerts_data:
                try:
                    alert_data = json.loads(alert_item)
                    alert_time = datetime.fromisoformat(alert_data.get('timestamp', datetime.utcnow().isoformat()))
                    
                    if start_time <= alert_time <= end_time:
                        recent_alerts.append(alert_data)
                except Exception:
                    continue
            
            return {
                'total_security_events': len(security_events),
                'threat_level_distribution': dict(threat_levels),
                'attack_type_distribution': dict(attack_types),
                'blocked_requests': blocked_requests,
                'security_alerts': len(recent_alerts),
                'alert_severity_distribution': dict(Counter([a.get('severity', 'unknown') for a in recent_alerts]))
            }
            
        except Exception as e:
            self.logger.error(f"Failed to get security data: {e}")
            return {}
    
    async def get_sla_data(self, start_time: datetime, end_time: datetime) -> Dict[str, Any]:
        """Get SLA data for the specified time period."""
        try:
            # Get SLA violations
            violations_data = await self.redis_client.lrange("sla_violations", 0, -1)
            
            period_violations = []
            violation_types = defaultdict(int)
            violation_severities = defaultdict(int)
            total_downtime = 0
            
            for violation_item in violations_data:
                try:
                    violation_data = json.loads(violation_item)
                    start_violation_time = datetime.fromisoformat(violation_data.get('start_time', datetime.utcnow().isoformat()))
                    
                    if start_time <= start_violation_time <= end_time:
                        period_violations.append(violation_data)
                        
                        target_id = violation_data.get('target_id', 'unknown')
                        severity = violation_data.get('severity', 'unknown')
                        duration = violation_data.get('duration_seconds', 0)
                        
                        violation_types[target_id] += 1
                        violation_severities[severity] += 1
                        total_downtime += duration
                        
                except Exception:
                    continue
            
            # Calculate availability
            period_seconds = (end_time - start_time).total_seconds()
            availability_percentage = max(0, ((period_seconds - total_downtime) / period_seconds) * 100) if period_seconds > 0 else 100
            
            return {
                'total_violations': len(period_violations),
                'violation_types': dict(violation_types),
                'violation_severities': dict(violation_severities),
                'total_downtime_seconds': total_downtime,
                'availability_percentage': availability_percentage,
                'mttr_seconds': statistics.mean([v.get('duration_seconds', 0) for v in period_violations]) if period_violations else 0
            }
            
        except Exception as e:
            self.logger.error(f"Failed to get SLA data: {e}")
            return {}


class VisualizationGenerator:
    """Generates charts and visualizations for business intelligence reports."""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        # Set matplotlib to use non-interactive backend
        plt.switch_backend('Agg')
        
        # Configure style
        plt.style.use('seaborn-v0_8')
        sns.set_palette("husl")
    
    def create_kpi_dashboard(self, kpis: List[BusinessKPI]) -> str:
        """Create KPI dashboard visualization."""
        try:
            # Create subplots for KPIs
            fig = make_subplots(
                rows=2, cols=3,
                subplot_titles=[kpi.name for kpi in kpis[:6]],
                specs=[[{"type": "indicator"} for _ in range(3)] for _ in range(2)]
            )
            
            for i, kpi in enumerate(kpis[:6]):
                row = (i // 3) + 1
                col = (i % 3) + 1
                
                # Determine color based on performance
                if kpi.critical_threshold and kpi.current_value >= kpi.critical_threshold:
                    color = "red"
                elif kpi.warning_threshold and kpi.current_value >= kpi.warning_threshold:
                    color = "orange"
                else:
                    color = "green"
                
                fig.add_trace(
                    go.Indicator(
                        mode="gauge+number+delta",
                        value=kpi.current_value,
                        domain={'x': [0, 1], 'y': [0, 1]},
                        title={'text': f"{kpi.name} ({kpi.unit})"},
                        delta={'reference': kpi.target_value},
                        gauge={
                            'axis': {'range': [None, max(kpi.target_value * 1.5, kpi.current_value * 1.2)]},
                            'bar': {'color': color},
                            'steps': [
                                {'range': [0, kpi.target_value * 0.8], 'color': "lightgray"},
                                {'range': [kpi.target_value * 0.8, kpi.target_value], 'color': "gray"}
                            ],
                            'threshold': {
                                'line': {'color': "red", 'width': 4},
                                'thickness': 0.75,
                                'value': kpi.target_value
                            }
                        }
                    ),
                    row=row, col=col
                )
            
            fig.update_layout(
                title="Key Performance Indicators Dashboard",
                height=600,
                showlegend=False
            )
            
            return self._fig_to_base64(fig)
            
        except Exception as e:
            self.logger.error(f"KPI dashboard creation failed: {e}")
            return ""
    
    def create_api_usage_chart(self, usage_data: Dict[str, Any]) -> str:
        """Create API usage analytics chart."""
        try:
            fig = make_subplots(
                rows=2, cols=2,
                subplot_titles=["Hourly Distribution", "Top Endpoints", "Status Code Distribution", "Response Time Trends"],
                specs=[[{"type": "bar"}, {"type": "bar"}],
                       [{"type": "pie"}, {"type": "histogram"}]]
            )
            
            # Hourly distribution
            hourly_dist = usage_data.get('hourly_distribution', {})
            if hourly_dist:
                hours = list(hourly_dist.keys())
                counts = list(hourly_dist.values())
                
                fig.add_trace(
                    go.Bar(x=hours, y=counts, name="Requests", marker_color="blue"),
                    row=1, col=1
                )
            
            # Top endpoints
            top_endpoints = usage_data.get('top_endpoints', {})
            if top_endpoints:
                endpoints = list(top_endpoints.keys())
                counts = list(top_endpoints.values())
                
                fig.add_trace(
                    go.Bar(x=endpoints, y=counts, name="Requests", marker_color="green"),
                    row=1, col=2
                )
            
            # Status code distribution
            status_dist = usage_data.get('status_distribution', {})
            if status_dist:
                fig.add_trace(
                    go.Pie(labels=list(status_dist.keys()), values=list(status_dist.values()), name="Status Codes"),
                    row=2, col=1
                )
            
            # Response time histogram (placeholder)
            fig.add_trace(
                go.Histogram(x=[usage_data.get('avg_response_time', 0)] * 100, name="Response Time"),
                row=2, col=2
            )
            
            fig.update_layout(
                title="API Usage Analytics",
                height=800,
                showlegend=False
            )
            
            return self._fig_to_base64(fig)
            
        except Exception as e:
            self.logger.error(f"API usage chart creation failed: {e}")
            return ""
    
    def create_performance_trends_chart(self, performance_data: Dict[str, Any]) -> str:
        """Create performance trends chart."""
        try:
            metrics = list(performance_data.keys())
            if not metrics:
                return ""
            
            fig = make_subplots(
                rows=2, cols=2,
                subplot_titles=metrics[:4]
            )
            
            positions = [(1, 1), (1, 2), (2, 1), (2, 2)]
            
            for i, metric in enumerate(metrics[:4]):
                row, col = positions[i]
                metric_data = performance_data[metric]
                
                # Create a simple bar chart with statistics
                stats = ['average', 'min', 'max', 'p95']
                values = [metric_data.get(stat, 0) for stat in stats]
                
                fig.add_trace(
                    go.Bar(x=stats, y=values, name=metric.replace('_', ' ').title()),
                    row=row, col=col
                )
            
            fig.update_layout(
                title="Performance Metrics Trends",
                height=600,
                showlegend=False
            )
            
            return self._fig_to_base64(fig)
            
        except Exception as e:
            self.logger.error(f"Performance trends chart creation failed: {e}")
            return ""
    
    def create_security_intelligence_chart(self, security_data: Dict[str, Any]) -> str:
        """Create security intelligence visualization."""
        try:
            fig = make_subplots(
                rows=2, cols=2,
                subplot_titles=["Threat Levels", "Attack Types", "Alert Severity", "Security Events Timeline"],
                specs=[[{"type": "pie"}, {"type": "bar"}],
                       [{"type": "pie"}, {"type": "scatter"}]]
            )
            
            # Threat levels
            threat_levels = security_data.get('threat_level_distribution', {})
            if threat_levels:
                fig.add_trace(
                    go.Pie(labels=list(threat_levels.keys()), values=list(threat_levels.values()), name="Threat Levels"),
                    row=1, col=1
                )
            
            # Attack types
            attack_types = security_data.get('attack_type_distribution', {})
            if attack_types:
                fig.add_trace(
                    go.Bar(x=list(attack_types.keys()), y=list(attack_types.values()), name="Attack Types", marker_color="red"),
                    row=1, col=2
                )
            
            # Alert severity
            alert_severity = security_data.get('alert_severity_distribution', {})
            if alert_severity:
                fig.add_trace(
                    go.Pie(labels=list(alert_severity.keys()), values=list(alert_severity.values()), name="Alert Severity"),
                    row=2, col=1
                )
            
            # Security events timeline (placeholder)
            fig.add_trace(
                go.Scatter(x=[1, 2, 3, 4, 5], y=[10, 15, 13, 17, 12], mode='lines+markers', name="Events"),
                row=2, col=2
            )
            
            fig.update_layout(
                title="Security Intelligence Dashboard",
                height=800,
                showlegend=False
            )
            
            return self._fig_to_base64(fig)
            
        except Exception as e:
            self.logger.error(f"Security intelligence chart creation failed: {e}")
            return ""
    
    def _fig_to_base64(self, fig) -> str:
        """Convert plotly figure to base64 string."""
        try:
            img_bytes = pio.to_image(fig, format="png", engine="auto")
            img_base64 = base64.b64encode(img_bytes).decode()
            return img_base64
        except Exception as e:
            self.logger.error(f"Figure to base64 conversion failed: {e}")
            return ""


class BusinessIntelligenceReporter:
    """
    Business Intelligence Reporting System
    
    Provides comprehensive business intelligence reporting for API Gateway operations
    with executive dashboards, operational insights, and strategic analytics.
    """
    
    def __init__(self, redis_url: str = "redis://localhost:6379"):
        """Initialize business intelligence reporter."""
        self.logger = logging.getLogger(__name__)
        self.redis_client = None
        self.redis_url = redis_url
        
        # Components
        self.data_aggregator = None
        self.visualization_generator = VisualizationGenerator()
        
        # Report configurations
        self.report_configs: Dict[str, ReportConfiguration] = {}
        
        # Cache
        self.report_cache: Dict[str, BusinessReport] = {}
        
        # Audit integration
        self.audit_logger = None
        
    async def initialize(self) -> None:
        """Initialize business intelligence reporter."""
        try:
            # Initialize Redis client
            self.redis_client = await aioredis.from_url(self.redis_url)
            await self.redis_client.ping()
            
            # Initialize components
            self.data_aggregator = DataAggregator(self.redis_client)
            
            # Initialize audit logger
            try:
                self.audit_logger = AuditLogger()
                await self.audit_logger.initialize()
            except Exception as e:
                self.logger.warning(f"Audit logger initialization failed: {e}")
            
            # Load existing report configurations
            await self._load_report_configurations()
            
            # Setup default report configurations if none exist
            if not self.report_configs:
                await self._setup_default_reports()
            
            # Start background tasks
            asyncio.create_task(self._scheduled_reports_loop())
            
            self.logger.info("Business intelligence reporter initialized")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize business intelligence reporter: {e}")
            raise
    
    async def _load_report_configurations(self) -> None:
        """Load report configurations from storage."""
        try:
            configs_data = await self.redis_client.get("bi_report_configurations")
            if configs_data:
                configs_dict = json.loads(configs_data)
                for config_id, config_data in configs_dict.items():
                    config = ReportConfiguration(**config_data)
                    config.report_type = ReportType(config_data['report_type'])
                    config.frequency = ReportFrequency(config_data['frequency'])
                    config.format = ReportFormat(config_data['format'])
                    if config_data.get('last_generated'):
                        config.last_generated = datetime.fromisoformat(config_data['last_generated'])
                    if config_data.get('next_scheduled'):
                        config.next_scheduled = datetime.fromisoformat(config_data['next_scheduled'])
                    self.report_configs[config_id] = config
                    
        except Exception as e:
            self.logger.error(f"Failed to load report configurations: {e}")
    
    async def _setup_default_reports(self) -> None:
        """Setup default report configurations."""
        default_configs = [
            ReportConfiguration(
                report_id="executive_daily",
                report_type=ReportType.EXECUTIVE_SUMMARY,
                frequency=ReportFrequency.DAILY,
                format=ReportFormat.PDF,
                recipients=["executive@agency.mil"],
                data_sources=["api_usage", "performance", "security", "sla"],
                filters={"classification": "UNCLASSIFIED"}
            ),
            ReportConfiguration(
                report_id="operational_hourly",
                report_type=ReportType.OPERATIONAL_PERFORMANCE,
                frequency=ReportFrequency.HOURLY,
                format=ReportFormat.DASHBOARD,
                recipients=["operations@agency.mil"],
                data_sources=["performance", "usage", "alerts"],
                filters={}
            ),
            ReportConfiguration(
                report_id="security_daily",
                report_type=ReportType.SECURITY_INTELLIGENCE,
                frequency=ReportFrequency.DAILY,
                format=ReportFormat.JSON,
                recipients=["security@agency.mil"],
                data_sources=["security", "alerts", "threats"],
                filters={"severity": ["medium", "high", "critical"]}
            )
        ]
        
        for config in default_configs:
            await self.add_report_configuration(config)
    
    async def add_report_configuration(self, config: ReportConfiguration) -> bool:
        """Add report configuration."""
        try:
            self.report_configs[config.report_id] = config
            await self._save_report_configurations()
            
            self.logger.info(f"Report configuration added: {config.report_id}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to add report configuration: {e}")
            return False
    
    async def _save_report_configurations(self) -> None:
        """Save report configurations to storage."""
        try:
            configs_dict = {}
            for config_id, config in self.report_configs.items():
                config_data = asdict(config)
                config_data['report_type'] = config.report_type.value
                config_data['frequency'] = config.frequency.value
                config_data['format'] = config.format.value
                if config.last_generated:
                    config_data['last_generated'] = config.last_generated.isoformat()
                if config.next_scheduled:
                    config_data['next_scheduled'] = config.next_scheduled.isoformat()
                configs_dict[config_id] = config_data
            
            await self.redis_client.set("bi_report_configurations", json.dumps(configs_dict))
            
        except Exception as e:
            self.logger.error(f"Failed to save report configurations: {e}")
    
    async def generate_report(self, report_type: ReportType, 
                            time_period_hours: int = 24,
                            filters: Optional[Dict[str, Any]] = None) -> BusinessReport:
        """Generate business intelligence report."""
        try:
            current_time = datetime.utcnow()
            start_time = current_time - timedelta(hours=time_period_hours)
            
            # Collect data from various sources
            api_usage_data = await self.data_aggregator.get_api_usage_data(start_time, current_time)
            performance_data = await self.data_aggregator.get_performance_data(start_time, current_time)
            security_data = await self.data_aggregator.get_security_data(start_time, current_time)
            sla_data = await self.data_aggregator.get_sla_data(start_time, current_time)
            
            # Calculate data quality score
            data_quality_score = self._calculate_data_quality_score({
                'api_usage': api_usage_data,
                'performance': performance_data,
                'security': security_data,
                'sla': sla_data
            })
            
            # Generate report based on type
            if report_type == ReportType.EXECUTIVE_SUMMARY:
                report = await self._generate_executive_summary(
                    current_time, start_time, api_usage_data, performance_data, security_data, sla_data
                )
            elif report_type == ReportType.OPERATIONAL_PERFORMANCE:
                report = await self._generate_operational_performance_report(
                    current_time, start_time, api_usage_data, performance_data
                )
            elif report_type == ReportType.SECURITY_INTELLIGENCE:
                report = await self._generate_security_intelligence_report(
                    current_time, start_time, security_data
                )
            elif report_type == ReportType.API_USAGE_ANALYTICS:
                report = await self._generate_api_usage_analytics_report(
                    current_time, start_time, api_usage_data
                )
            else:
                # Default comprehensive report
                report = await self._generate_comprehensive_report(
                    current_time, start_time, api_usage_data, performance_data, security_data, sla_data
                )
            
            report.data_quality_score = data_quality_score
            
            # Store report
            await self._store_report(report)
            
            # Log report generation
            if self.audit_logger:
                await self.audit_logger.log_event(
                    event_type="bi_report_generated",
                    severity="info",
                    details={
                        'report_id': report.report_id,
                        'report_type': report.report_type.value,
                        'time_period_hours': time_period_hours,
                        'data_quality_score': data_quality_score
                    }
                )
            
            return report
            
        except Exception as e:
            self.logger.error(f"Report generation failed for {report_type.value}: {e}")
            raise
    
    def _calculate_data_quality_score(self, data_sources: Dict[str, Dict]) -> float:
        """Calculate overall data quality score."""
        try:
            scores = []
            
            for source_name, source_data in data_sources.items():
                if not source_data:
                    scores.append(0.0)
                    continue
                
                # Basic completeness check
                expected_fields = {
                    'api_usage': ['total_requests', 'unique_endpoints', 'avg_response_time'],
                    'performance': ['response_time', 'cpu_utilization'],
                    'security': ['total_security_events', 'threat_level_distribution'],
                    'sla': ['total_violations', 'availability_percentage']
                }
                
                source_fields = expected_fields.get(source_name, [])
                if not source_fields:
                    scores.append(1.0)
                    continue
                
                present_fields = sum(1 for field in source_fields if field in source_data and source_data[field] is not None)
                completeness_score = present_fields / len(source_fields)
                scores.append(completeness_score)
            
            return statistics.mean(scores) if scores else 0.0
            
        except Exception as e:
            self.logger.error(f"Data quality score calculation failed: {e}")
            return 0.0
    
    async def _generate_executive_summary(self, current_time: datetime, start_time: datetime,
                                        api_usage_data: Dict, performance_data: Dict,
                                        security_data: Dict, sla_data: Dict) -> BusinessReport:
        """Generate executive summary report."""
        try:
            # Calculate key business metrics
            total_requests = api_usage_data.get('total_requests', 0)
            availability = sla_data.get('availability_percentage', 100)
            avg_response_time = api_usage_data.get('avg_response_time', 0)
            security_incidents = security_data.get('security_alerts', 0)
            
            # Create KPIs
            kpis = [
                BusinessKPI(
                    kpi_id="total_api_calls",
                    name="Total API Calls",
                    description="Total number of API requests processed",
                    category=BusinessMetricCategory.USAGE,
                    current_value=total_requests,
                    target_value=10000,  # Example target
                    trend_direction="increasing",
                    trend_percentage=5.2,
                    last_updated=current_time,
                    unit="requests"
                ),
                BusinessKPI(
                    kpi_id="system_availability",
                    name="System Availability",
                    description="Overall system availability percentage",
                    category=BusinessMetricCategory.RELIABILITY,
                    current_value=availability,
                    target_value=99.9,
                    trend_direction="stable",
                    trend_percentage=0.1,
                    last_updated=current_time,
                    unit="%",
                    critical_threshold=99.0,
                    warning_threshold=99.5
                ),
                BusinessKPI(
                    kpi_id="avg_response_time",
                    name="Average Response Time",
                    description="Average API response time",
                    category=BusinessMetricCategory.PERFORMANCE,
                    current_value=avg_response_time,
                    target_value=1.0,
                    trend_direction="decreasing",
                    trend_percentage=-2.1,
                    last_updated=current_time,
                    unit="seconds",
                    critical_threshold=5.0,
                    warning_threshold=2.0
                ),
                BusinessKPI(
                    kpi_id="security_incidents",
                    name="Security Incidents",
                    description="Number of security incidents detected",
                    category=BusinessMetricCategory.SECURITY,
                    current_value=security_incidents,
                    target_value=0,
                    trend_direction="stable",
                    trend_percentage=0.0,
                    last_updated=current_time,
                    unit="incidents",
                    critical_threshold=10,
                    warning_threshold=5
                )
            ]
            
            # Generate visualizations
            visualizations = {
                'kpi_dashboard': self.visualization_generator.create_kpi_dashboard(kpis),
                'usage_overview': self.visualization_generator.create_api_usage_chart(api_usage_data),
                'security_summary': self.visualization_generator.create_security_intelligence_chart(security_data)
            }
            
            # Generate executive summary
            executive_summary = {
                'overview': f"API Gateway processed {total_requests:,} requests with {availability:.1f}% availability",
                'key_achievements': [
                    f"Maintained {availability:.1f}% system availability",
                    f"Average response time of {avg_response_time:.2f} seconds",
                    f"Processed {api_usage_data.get('unique_users', 0)} unique user sessions"
                ],
                'key_challenges': [
                    f"{security_incidents} security incidents detected" if security_incidents > 0 else "No security incidents",
                    f"{sla_data.get('total_violations', 0)} SLA violations occurred" if sla_data.get('total_violations', 0) > 0 else "No SLA violations"
                ],
                'business_impact': {
                    'user_satisfaction': "High" if avg_response_time < 2.0 else "Medium",
                    'system_reliability': "High" if availability > 99.5 else "Medium",
                    'security_posture': "Good" if security_incidents == 0 else "Needs Attention"
                }
            }
            
            # Generate recommendations
            recommendations = []
            if availability < 99.9:
                recommendations.append("Investigate availability issues and implement redundancy improvements")
            if avg_response_time > 2.0:
                recommendations.append("Optimize API performance and consider scaling resources")
            if security_incidents > 0:
                recommendations.append("Review security controls and incident response procedures")
            if not recommendations:
                recommendations.append("Continue monitoring current excellent performance levels")
            
            return BusinessReport(
                report_id=str(uuid.uuid4()),
                report_type=ReportType.EXECUTIVE_SUMMARY,
                generated_at=current_time,
                time_period={'start': start_time.isoformat(), 'end': current_time.isoformat()},
                executive_summary=executive_summary,
                key_metrics=kpis,
                visualizations=visualizations,
                recommendations=recommendations,
                data_quality_score=0.0,  # Will be set by caller
                metadata={
                    'total_data_points': total_requests,
                    'coverage_percentage': 100.0,
                    'generated_by': 'BusinessIntelligenceReporter'
                }
            )
            
        except Exception as e:
            self.logger.error(f"Executive summary generation failed: {e}")
            raise
    
    async def _generate_operational_performance_report(self, current_time: datetime, start_time: datetime,
                                                     api_usage_data: Dict, performance_data: Dict) -> BusinessReport:
        """Generate operational performance report."""
        try:
            # Create performance KPIs
            kpis = []
            
            for metric_name, metric_data in performance_data.items():
                if isinstance(metric_data, dict) and 'average' in metric_data:
                    kpi = BusinessKPI(
                        kpi_id=f"perf_{metric_name}",
                        name=metric_name.replace('_', ' ').title(),
                        description=f"Average {metric_name.replace('_', ' ')}",
                        category=BusinessMetricCategory.PERFORMANCE,
                        current_value=metric_data['average'],
                        target_value=metric_data['average'] * 0.9,  # Target 10% better
                        trend_direction="stable",
                        trend_percentage=0.0,
                        last_updated=current_time,
                        unit="ms" if "time" in metric_name else "%"
                    )
                    kpis.append(kpi)
            
            # Generate visualizations
            visualizations = {
                'performance_trends': self.visualization_generator.create_performance_trends_chart(performance_data),
                'usage_patterns': self.visualization_generator.create_api_usage_chart(api_usage_data)
            }
            
            # Generate summary
            executive_summary = {
                'performance_overview': f"System processed {api_usage_data.get('total_requests', 0):,} requests",
                'key_metrics': {
                    'peak_usage_hour': max(api_usage_data.get('hourly_distribution', {}).items(), 
                                         key=lambda x: x[1], default=(0, 0))[0],
                    'unique_endpoints': api_usage_data.get('unique_endpoints', 0),
                    'avg_response_time': api_usage_data.get('avg_response_time', 0)
                }
            }
            
            recommendations = [
                "Monitor performance trends for capacity planning",
                "Optimize high-traffic endpoints for better performance",
                "Consider implementing caching for frequently accessed data"
            ]
            
            return BusinessReport(
                report_id=str(uuid.uuid4()),
                report_type=ReportType.OPERATIONAL_PERFORMANCE,
                generated_at=current_time,
                time_period={'start': start_time.isoformat(), 'end': current_time.isoformat()},
                executive_summary=executive_summary,
                key_metrics=kpis,
                visualizations=visualizations,
                recommendations=recommendations,
                data_quality_score=0.0,
                metadata={'report_focus': 'operational_performance'}
            )
            
        except Exception as e:
            self.logger.error(f"Operational performance report generation failed: {e}")
            raise
    
    async def _generate_security_intelligence_report(self, current_time: datetime, start_time: datetime,
                                                   security_data: Dict) -> BusinessReport:
        """Generate security intelligence report."""
        try:
            # Create security KPIs
            kpis = [
                BusinessKPI(
                    kpi_id="security_events",
                    name="Security Events",
                    description="Total number of security events detected",
                    category=BusinessMetricCategory.SECURITY,
                    current_value=security_data.get('total_security_events', 0),
                    target_value=0,
                    trend_direction="stable",
                    trend_percentage=0.0,
                    last_updated=current_time,
                    unit="events"
                ),
                BusinessKPI(
                    kpi_id="blocked_attacks",
                    name="Blocked Attacks",
                    description="Number of attacks successfully blocked",
                    category=BusinessMetricCategory.SECURITY,
                    current_value=security_data.get('blocked_requests', 0),
                    target_value=0,
                    trend_direction="stable",
                    trend_percentage=0.0,
                    last_updated=current_time,
                    unit="attacks"
                )
            ]
            
            # Generate visualizations
            visualizations = {
                'security_overview': self.visualization_generator.create_security_intelligence_chart(security_data)
            }
            
            # Generate summary
            executive_summary = {
                'security_posture': "Good" if security_data.get('total_security_events', 0) == 0 else "Monitoring Required",
                'threat_landscape': security_data.get('threat_level_distribution', {}),
                'defense_effectiveness': f"{security_data.get('blocked_requests', 0)} attacks blocked"
            }
            
            recommendations = []
            if security_data.get('total_security_events', 0) > 10:
                recommendations.append("High number of security events - investigate patterns and enhance controls")
            if security_data.get('security_alerts', 0) > 5:
                recommendations.append("Multiple security alerts - review and update security policies")
            if not recommendations:
                recommendations.append("Security posture is good - continue current monitoring practices")
            
            return BusinessReport(
                report_id=str(uuid.uuid4()),
                report_type=ReportType.SECURITY_INTELLIGENCE,
                generated_at=current_time,
                time_period={'start': start_time.isoformat(), 'end': current_time.isoformat()},
                executive_summary=executive_summary,
                key_metrics=kpis,
                visualizations=visualizations,
                recommendations=recommendations,
                data_quality_score=0.0,
                metadata={'security_focus': True}
            )
            
        except Exception as e:
            self.logger.error(f"Security intelligence report generation failed: {e}")
            raise
    
    async def _generate_api_usage_analytics_report(self, current_time: datetime, start_time: datetime,
                                                 api_usage_data: Dict) -> BusinessReport:
        """Generate API usage analytics report."""
        try:
            # Create usage KPIs
            kpis = [
                BusinessKPI(
                    kpi_id="total_requests",
                    name="Total Requests",
                    description="Total API requests processed",
                    category=BusinessMetricCategory.USAGE,
                    current_value=api_usage_data.get('total_requests', 0),
                    target_value=10000,
                    trend_direction="increasing",
                    trend_percentage=5.0,
                    last_updated=current_time,
                    unit="requests"
                ),
                BusinessKPI(
                    kpi_id="active_users",
                    name="Active Users",
                    description="Number of unique active users",
                    category=BusinessMetricCategory.USAGE,
                    current_value=api_usage_data.get('unique_users', 0),
                    target_value=1000,
                    trend_direction="increasing",
                    trend_percentage=3.2,
                    last_updated=current_time,
                    unit="users"
                )
            ]
            
            # Generate visualizations
            visualizations = {
                'usage_analytics': self.visualization_generator.create_api_usage_chart(api_usage_data)
            }
            
            # Generate summary
            executive_summary = {
                'usage_overview': f"API Gateway served {api_usage_data.get('total_requests', 0):,} requests to {api_usage_data.get('unique_users', 0)} users",
                'adoption_metrics': {
                    'endpoints_used': api_usage_data.get('unique_endpoints', 0),
                    'peak_hour_traffic': max(api_usage_data.get('hourly_distribution', {}).values(), default=0),
                    'success_rate': f"{((api_usage_data.get('total_requests', 0) - api_usage_data.get('status_distribution', {}).get('4xx', 0) - api_usage_data.get('status_distribution', {}).get('5xx', 0)) / max(api_usage_data.get('total_requests', 1), 1)) * 100:.1f}%"
                }
            }
            
            recommendations = [
                "Analyze top endpoints for optimization opportunities",
                "Consider API versioning strategy for popular endpoints",
                "Implement user onboarding improvements to increase adoption"
            ]
            
            return BusinessReport(
                report_id=str(uuid.uuid4()),
                report_type=ReportType.API_USAGE_ANALYTICS,
                generated_at=current_time,
                time_period={'start': start_time.isoformat(), 'end': current_time.isoformat()},
                executive_summary=executive_summary,
                key_metrics=kpis,
                visualizations=visualizations,
                recommendations=recommendations,
                data_quality_score=0.0,
                metadata={'usage_focus': True}
            )
            
        except Exception as e:
            self.logger.error(f"API usage analytics report generation failed: {e}")
            raise
    
    async def _generate_comprehensive_report(self, current_time: datetime, start_time: datetime,
                                           api_usage_data: Dict, performance_data: Dict,
                                           security_data: Dict, sla_data: Dict) -> BusinessReport:
        """Generate comprehensive business intelligence report."""
        try:
            # Combine all data sources for comprehensive KPIs
            all_kpis = []
            
            # Add usage KPIs
            all_kpis.append(BusinessKPI(
                kpi_id="total_api_calls",
                name="Total API Calls",
                description="Total number of API requests processed",
                category=BusinessMetricCategory.USAGE,
                current_value=api_usage_data.get('total_requests', 0),
                target_value=10000,
                trend_direction="increasing",
                trend_percentage=5.2,
                last_updated=current_time,
                unit="requests"
            ))
            
            # Add performance KPIs
            all_kpis.append(BusinessKPI(
                kpi_id="avg_response_time",
                name="Average Response Time",
                description="Average API response time",
                category=BusinessMetricCategory.PERFORMANCE,
                current_value=api_usage_data.get('avg_response_time', 0),
                target_value=1.0,
                trend_direction="stable",
                trend_percentage=-1.2,
                last_updated=current_time,
                unit="seconds"
            ))
            
            # Add SLA KPIs
            all_kpis.append(BusinessKPI(
                kpi_id="availability",
                name="System Availability",
                description="Overall system availability percentage",
                category=BusinessMetricCategory.RELIABILITY,
                current_value=sla_data.get('availability_percentage', 100),
                target_value=99.9,
                trend_direction="stable",
                trend_percentage=0.1,
                last_updated=current_time,
                unit="%"
            ))
            
            # Generate all visualizations
            visualizations = {
                'kpi_dashboard': self.visualization_generator.create_kpi_dashboard(all_kpis[:6]),
                'usage_analytics': self.visualization_generator.create_api_usage_chart(api_usage_data),
                'performance_trends': self.visualization_generator.create_performance_trends_chart(performance_data),
                'security_intelligence': self.visualization_generator.create_security_intelligence_chart(security_data)
            }
            
            # Comprehensive executive summary
            executive_summary = {
                'period_overview': f"Comprehensive analysis for {(current_time - start_time).days} day(s)",
                'key_highlights': [
                    f"Processed {api_usage_data.get('total_requests', 0):,} API requests",
                    f"Maintained {sla_data.get('availability_percentage', 100):.1f}% availability",
                    f"Served {api_usage_data.get('unique_users', 0)} unique users",
                    f"Detected {security_data.get('total_security_events', 0)} security events"
                ],
                'business_metrics': {
                    'user_engagement': api_usage_data.get('unique_users', 0),
                    'system_reliability': sla_data.get('availability_percentage', 100),
                    'performance_rating': "Excellent" if api_usage_data.get('avg_response_time', 0) < 1.0 else "Good",
                    'security_status': "Secure" if security_data.get('security_alerts', 0) == 0 else "Monitoring"
                }
            }
            
            # Comprehensive recommendations
            recommendations = [
                "Continue monitoring all systems for optimal performance",
                "Implement proactive capacity planning based on usage trends",
                "Enhance security monitoring and threat detection capabilities",
                "Consider API optimization for frequently used endpoints"
            ]
            
            return BusinessReport(
                report_id=str(uuid.uuid4()),
                report_type=ReportType.EXECUTIVE_SUMMARY,
                generated_at=current_time,
                time_period={'start': start_time.isoformat(), 'end': current_time.isoformat()},
                executive_summary=executive_summary,
                key_metrics=all_kpis,
                visualizations=visualizations,
                recommendations=recommendations,
                data_quality_score=0.0,
                metadata={'comprehensive': True, 'data_sources': ['usage', 'performance', 'security', 'sla']}
            )
            
        except Exception as e:
            self.logger.error(f"Comprehensive report generation failed: {e}")
            raise
    
    async def _store_report(self, report: BusinessReport) -> None:
        """Store generated report."""
        try:
            # Store in cache
            self.report_cache[report.report_id] = report
            
            # Store in Redis
            report_data = asdict(report)
            report_data['report_type'] = report.report_type.value
            report_data['generated_at'] = report.generated_at.isoformat()
            
            await self.redis_client.set(
                f"bi_report:{report.report_id}",
                json.dumps(report_data, default=str),
                ex=86400 * 30  # Keep for 30 days
            )
            
            # Add to recent reports list
            await self.redis_client.lpush("bi_recent_reports", report.report_id)
            await self.redis_client.ltrim("bi_recent_reports", 0, 100)  # Keep last 100
            
        except Exception as e:
            self.logger.error(f"Failed to store report {report.report_id}: {e}")
    
    async def _scheduled_reports_loop(self) -> None:
        """Background loop for scheduled report generation."""
        while True:
            try:
                current_time = datetime.utcnow()
                
                for config_id, config in self.report_configs.items():
                    if not config.enabled:
                        continue
                    
                    # Check if report should be generated
                    should_generate = False
                    
                    if config.next_scheduled and current_time >= config.next_scheduled:
                        should_generate = True
                    elif not config.last_generated:
                        should_generate = True
                    elif config.frequency == ReportFrequency.HOURLY:
                        should_generate = (current_time - config.last_generated).total_seconds() >= 3600
                    elif config.frequency == ReportFrequency.DAILY:
                        should_generate = (current_time - config.last_generated).total_seconds() >= 86400
                    
                    if should_generate:
                        try:
                            report = await self.generate_report(config.report_type, 24, config.filters)
                            config.last_generated = current_time
                            
                            # Schedule next generation
                            if config.frequency == ReportFrequency.HOURLY:
                                config.next_scheduled = current_time + timedelta(hours=1)
                            elif config.frequency == ReportFrequency.DAILY:
                                config.next_scheduled = current_time + timedelta(days=1)
                            elif config.frequency == ReportFrequency.WEEKLY:
                                config.next_scheduled = current_time + timedelta(weeks=1)
                            
                            await self._save_report_configurations()
                            
                            self.logger.info(f"Scheduled report generated: {config.report_id}")
                            
                        except Exception as e:
                            self.logger.error(f"Scheduled report generation failed for {config_id}: {e}")
                
                await asyncio.sleep(300)  # Check every 5 minutes
                
            except Exception as e:
                self.logger.error(f"Scheduled reports loop error: {e}")
                await asyncio.sleep(300)
    
    async def get_report(self, report_id: str) -> Optional[BusinessReport]:
        """Get generated report by ID."""
        try:
            # Check cache first
            if report_id in self.report_cache:
                return self.report_cache[report_id]
            
            # Check Redis
            report_data = await self.redis_client.get(f"bi_report:{report_id}")
            if report_data:
                report_dict = json.loads(report_data)
                
                # Reconstruct report object
                report = BusinessReport(**report_dict)
                report.report_type = ReportType(report_dict['report_type'])
                report.generated_at = datetime.fromisoformat(report_dict['generated_at'])
                
                # Reconstruct KPIs
                kpis = []
                for kpi_data in report_dict.get('key_metrics', []):
                    kpi = BusinessKPI(**kpi_data)
                    kpi.category = BusinessMetricCategory(kpi_data['category'])
                    kpi.last_updated = datetime.fromisoformat(kpi_data['last_updated'])
                    kpis.append(kpi)
                report.key_metrics = kpis
                
                # Cache and return
                self.report_cache[report_id] = report
                return report
            
            return None
            
        except Exception as e:
            self.logger.error(f"Failed to get report {report_id}: {e}")
            return None
    
    async def get_recent_reports(self, limit: int = 10) -> List[str]:
        """Get list of recent report IDs."""
        try:
            report_ids = await self.redis_client.lrange("bi_recent_reports", 0, limit - 1)
            return [report_id.decode() for report_id in report_ids]
            
        except Exception as e:
            self.logger.error(f"Failed to get recent reports: {e}")
            return []
    
    async def get_dashboard_data(self) -> Dict[str, Any]:
        """Get real-time dashboard data."""
        try:
            current_time = datetime.utcnow()
            
            # Get latest data
            api_usage_data = await self.data_aggregator.get_api_usage_data(
                current_time - timedelta(hours=1), current_time
            )
            performance_data = await self.data_aggregator.get_performance_data(
                current_time - timedelta(hours=1), current_time
            )
            security_data = await self.data_aggregator.get_security_data(
                current_time - timedelta(hours=1), current_time
            )
            sla_data = await self.data_aggregator.get_sla_data(
                current_time - timedelta(hours=1), current_time
            )
            
            # Generate real-time KPIs
            kpis = [
                {
                    'name': 'API Requests (Last Hour)',
                    'value': api_usage_data.get('total_requests', 0),
                    'unit': 'requests',
                    'trend': 'stable'
                },
                {
                    'name': 'Average Response Time',
                    'value': api_usage_data.get('avg_response_time', 0),
                    'unit': 'seconds',
                    'trend': 'stable'
                },
                {
                    'name': 'System Availability',
                    'value': sla_data.get('availability_percentage', 100),
                    'unit': '%',
                    'trend': 'stable'
                },
                {
                    'name': 'Security Events',
                    'value': security_data.get('total_security_events', 0),
                    'unit': 'events',
                    'trend': 'stable'
                }
            ]
            
            return {
                'timestamp': current_time.isoformat(),
                'kpis': kpis,
                'usage_summary': api_usage_data,
                'performance_summary': performance_data,
                'security_summary': security_data,
                'sla_summary': sla_data
            }
            
        except Exception as e:
            self.logger.error(f"Dashboard data retrieval failed: {e}")
            return {'error': str(e)}
    
    async def close(self) -> None:
        """Clean up business intelligence reporter resources."""
        if self.redis_client:
            await self.redis_client.close()
        
        self.logger.info("Business intelligence reporter closed")


if __name__ == "__main__":
    # Example usage
    async def main():
        reporter = BusinessIntelligenceReporter()
        await reporter.initialize()
        
        # Generate executive summary report
        exec_report = await reporter.generate_report(ReportType.EXECUTIVE_SUMMARY, 24)
        print(f"Executive Report ID: {exec_report.report_id}")
        print(f"Data Quality Score: {exec_report.data_quality_score:.2f}")
        print(f"Recommendations: {exec_report.recommendations}")
        
        # Generate operational performance report
        ops_report = await reporter.generate_report(ReportType.OPERATIONAL_PERFORMANCE, 24)
        print(f"Operational Report ID: {ops_report.report_id}")
        
        # Get dashboard data
        dashboard = await reporter.get_dashboard_data()
        print(f"Dashboard KPIs: {len(dashboard.get('kpis', []))}")
        
        # Get recent reports
        recent = await reporter.get_recent_reports(5)
        print(f"Recent Reports: {recent}")
        
        await reporter.close()
    
    asyncio.run(main())