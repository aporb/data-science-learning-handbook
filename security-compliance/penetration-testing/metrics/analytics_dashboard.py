"""
Penetration Testing Metrics and Analytics Dashboard
=================================================

Real-time penetration testing metrics visualization and analytics system that
provides comprehensive security posture trending, vulnerability tracking, and
integration with existing compliance dashboards.

Key Features:
- Real-time penetration testing metrics visualization
- Security posture trending and analysis
- Vulnerability discovery and remediation tracking
- Test coverage and effectiveness metrics
- Integration with existing compliance dashboards
- Advanced analytics and predictive insights
- Performance and efficiency tracking

Integration Points:
- Enhanced monitoring system for real-time data
- Compliance dashboard integration for unified view
- Risk assessment framework for risk trending
- Multi-classification engine for classified metrics
- Audit system for metrics audit trails

Classification: UNCLASSIFIED//FOR OFFICIAL USE ONLY
Version: 1.0 - Penetration Testing Analytics Dashboard
Author: Red Team Operations
Date: 2025-07-28
"""

import asyncio
import json
import logging
import time
import statistics
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
import pandas as pd
from pathlib import Path
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots
import plotly.offline as pyo
from flask import Flask, render_template, jsonify, request
import sqlite3
from contextlib import asynccontextmanager
import asyncpg

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class MetricType(Enum):
    """Types of penetration testing metrics."""
    VULNERABILITY_COUNT = "vulnerability_count"
    SEVERITY_DISTRIBUTION = "severity_distribution"
    REMEDIATION_RATE = "remediation_rate"
    TEST_COVERAGE = "test_coverage" 
    RISK_SCORE = "risk_score"
    TIME_TO_DISCOVERY = "time_to_discovery"
    FALSE_POSITIVE_RATE = "false_positive_rate"
    EXPLOITATION_SUCCESS = "exploitation_success"
    COMPLIANCE_SCORE = "compliance_score"

class DashboardWidget(Enum):
    """Dashboard widget types."""
    LINE_CHART = "line_chart"
    BAR_CHART = "bar_chart"
    PIE_CHART = "pie_chart"
    GAUGE = "gauge"
    METRIC_CARD = "metric_card"
    HEATMAP = "heatmap"
    TABLE = "table"
    TREND_LINE = "trend_line"

@dataclass
class MetricDataPoint:
    """Individual metric data point."""
    id: str = field(default_factory=lambda: str(uuid4()))
    metric_type: MetricType = MetricType.VULNERABILITY_COUNT
    value: float = 0.0
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    test_id: str = ""
    system_id: str = ""
    category: str = ""
    severity: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)

@dataclass
class DashboardConfiguration:
    """Dashboard configuration settings."""
    id: str = field(default_factory=lambda: str(uuid4()))
    name: str = ""
    description: str = ""
    widgets: List[Dict[str, Any]] = field(default_factory=list)
    refresh_interval: int = 30  # seconds
    time_range: str = "24h"
    filters: Dict[str, Any] = field(default_factory=dict)
    permissions: List[str] = field(default_factory=list)
    created_by: str = ""
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_updated: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

@dataclass
class SecurityTrend:
    """Security posture trend analysis."""
    metric_name: str = ""
    trend_direction: str = "stable"  # improving, degrading, stable
    change_percentage: float = 0.0
    time_period: str = "7d"
    significance: str = "low"  # low, medium, high
    description: str = ""
    recommendation: str = ""

@dataclass
class ComplianceMetrics:
    """Compliance-related metrics."""
    framework: str = ""  # NIST, DoD, FISMA, etc.
    total_controls: int = 0
    tested_controls: int = 0
    compliant_controls: int = 0
    non_compliant_controls: int = 0
    compliance_percentage: float = 0.0
    last_assessment: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    findings_by_control: Dict[str, int] = field(default_factory=dict)

class PentestAnalyticsDashboard:
    """
    Real-time penetration testing metrics and analytics dashboard.
    
    Provides comprehensive visualization and analysis of penetration testing
    metrics, security posture trends, and compliance status.
    """
    
    def __init__(self, db_path: str = None):
        """Initialize the analytics dashboard."""
        self.db_path = db_path or str(Path(__file__).parent / "pentest_metrics.db")
        self.metrics_cache = {}
        self.cache_lock = Lock()
        self.cache_expiry = 300  # 5 minutes
        
        # Flask app for web dashboard
        self.app = Flask(__name__, template_folder='../templates')
        self._setup_routes()
        
        # Initialize database
        asyncio.create_task(self._initialize_database())
        
        logger.info("Penetration Testing Analytics Dashboard initialized")
    
    async def _initialize_database(self):
        """Initialize the metrics database."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Create metrics table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS metrics (
                    id TEXT PRIMARY KEY,
                    metric_type TEXT NOT NULL,
                    value REAL NOT NULL,
                    timestamp DATETIME NOT NULL,
                    test_id TEXT,
                    system_id TEXT,
                    category TEXT,
                    severity TEXT,
                    metadata TEXT,
                    tags TEXT
                )
            """)
            
            # Create dashboard configurations table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS dashboard_configs (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    description TEXT,
                    widgets TEXT,
                    refresh_interval INTEGER,
                    time_range TEXT,
                    filters TEXT,
                    permissions TEXT,
                    created_by TEXT,
                    created_at DATETIME,
                    last_updated DATETIME
                )
            """)
            
            # Create trends table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS security_trends (
                    id TEXT PRIMARY KEY,
                    metric_name TEXT NOT NULL,
                    trend_direction TEXT,
                    change_percentage REAL,
                    time_period TEXT,
                    significance TEXT,
                    description TEXT,
                    recommendation TEXT,
                    created_at DATETIME
                )
            """)
            
            # Create compliance metrics table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS compliance_metrics (
                    id TEXT PRIMARY KEY,
                    framework TEXT NOT NULL,
                    total_controls INTEGER,
                    tested_controls INTEGER,
                    compliant_controls INTEGER,
                    non_compliant_controls INTEGER,
                    compliance_percentage REAL,
                    last_assessment DATETIME,
                    findings_by_control TEXT
                )
            """)
            
            # Create indexes for performance
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_metrics_timestamp ON metrics(timestamp)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_metrics_type ON metrics(metric_type)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_metrics_test_id ON metrics(test_id)")
            
            conn.commit()
            conn.close()
            
            logger.info("Metrics database initialized successfully")
            
        except Exception as e:
            logger.error(f"Error initializing database: {str(e)}")
            raise
    
    def _setup_routes(self):
        """Setup Flask routes for the web dashboard."""
        
        @self.app.route('/')
        def dashboard_home():
            """Main dashboard page."""
            return render_template('pentest_dashboard.html')
        
        @self.app.route('/api/metrics/<metric_type>')
        def get_metrics_api(metric_type):
            """API endpoint for metric data."""
            time_range = request.args.get('time_range', '24h')
            system_id = request.args.get('system_id')
            
            metrics = asyncio.run(self.get_metrics(
                metric_type=MetricType(metric_type),
                time_range=time_range,
                system_id=system_id
            ))
            
            return jsonify([asdict(metric) for metric in metrics])
        
        @self.app.route('/api/dashboard/<dashboard_id>')
        def get_dashboard_config(dashboard_id):
            """Get dashboard configuration."""
            config = asyncio.run(self.get_dashboard_configuration(dashboard_id))
            return jsonify(asdict(config) if config else {})
        
        @self.app.route('/api/trends')
        def get_trends_api():
            """Get security trends."""
            trends = asyncio.run(self.analyze_security_trends())
            return jsonify([asdict(trend) for trend in trends])
        
        @self.app.route('/api/compliance')
        def get_compliance_api():
            """Get compliance metrics."""
            framework = request.args.get('framework', 'NIST')
            compliance = asyncio.run(self.get_compliance_metrics(framework))
            return jsonify(asdict(compliance) if compliance else {})
    
    async def record_metric(self, metric: MetricDataPoint):
        """
        Record a new metric data point.
        
        Args:
            metric: The metric data point to record
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT INTO metrics (
                    id, metric_type, value, timestamp, test_id, system_id,
                    category, severity, metadata, tags
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                metric.id,
                metric.metric_type.value,
                metric.value,
                metric.timestamp.isoformat(),
                metric.test_id,
                metric.system_id,
                metric.category,
                metric.severity,
                json.dumps(metric.metadata),
                json.dumps(metric.tags)
            ))
            
            conn.commit()
            conn.close()
            
            # Clear cache for this metric type
            with self.cache_lock:
                cache_key = f"{metric.metric_type.value}_{metric.system_id}"
                if cache_key in self.metrics_cache:
                    del self.metrics_cache[cache_key]
            
            logger.debug(f"Recorded metric: {metric.metric_type.value} = {metric.value}")
            
        except Exception as e:
            logger.error(f"Error recording metric: {str(e)}")
            raise
    
    async def get_metrics(self, 
                         metric_type: MetricType,
                         time_range: str = "24h",
                         system_id: str = None,
                         limit: int = 1000) -> List[MetricDataPoint]:
        """
        Retrieve metrics from the database.
        
        Args:
            metric_type: Type of metric to retrieve
            time_range: Time range (e.g., "24h", "7d", "30d")
            system_id: Filter by system ID
            limit: Maximum number of records to return
            
        Returns:
            List of metric data points
        """
        try:
            # Check cache first
            cache_key = f"{metric_type.value}_{system_id}_{time_range}"
            with self.cache_lock:
                if cache_key in self.metrics_cache:
                    cached_data, cache_time = self.metrics_cache[cache_key]
                    if time.time() - cache_time < self.cache_expiry:
                        return cached_data
            
            # Parse time range
            time_delta = self._parse_time_range(time_range)
            since_time = datetime.now(timezone.utc) - time_delta
            
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            query = """
                SELECT id, metric_type, value, timestamp, test_id, system_id,
                       category, severity, metadata, tags
                FROM metrics
                WHERE metric_type = ? AND timestamp >= ?
            """
            params = [metric_type.value, since_time.isoformat()]
            
            if system_id:
                query += " AND system_id = ?"
                params.append(system_id)
            
            query += " ORDER BY timestamp DESC LIMIT ?"
            params.append(limit)
            
            cursor.execute(query, params)
            rows = cursor.fetchall()
            
            metrics = []
            for row in rows:
                metric = MetricDataPoint(
                    id=row[0],
                    metric_type=MetricType(row[1]),
                    value=row[2],
                    timestamp=datetime.fromisoformat(row[3]),
                    test_id=row[4] or "",
                    system_id=row[5] or "",
                    category=row[6] or "",
                    severity=row[7] or "",
                    metadata=json.loads(row[8]) if row[8] else {},
                    tags=json.loads(row[9]) if row[9] else []
                )
                metrics.append(metric)
            
            conn.close()
            
            # Cache the results
            with self.cache_lock:
                self.metrics_cache[cache_key] = (metrics, time.time())
            
            logger.debug(f"Retrieved {len(metrics)} metrics for {metric_type.value}")
            return metrics
            
        except Exception as e:
            logger.error(f"Error retrieving metrics: {str(e)}")
            raise
    
    def _parse_time_range(self, time_range: str) -> timedelta:
        """Parse time range string to timedelta."""
        if time_range.endswith('h'):
            hours = int(time_range[:-1])
            return timedelta(hours=hours)
        elif time_range.endswith('d'):
            days = int(time_range[:-1])
            return timedelta(days=days)
        elif time_range.endswith('w'):
            weeks = int(time_range[:-1])
            return timedelta(weeks=weeks)
        else:
            return timedelta(hours=24)  # Default to 24 hours
    
    async def create_dashboard_widget(self, 
                                    widget_type: DashboardWidget,
                                    metric_type: MetricType,
                                    title: str = "",
                                    config: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Create a dashboard widget configuration.
        
        Args:
            widget_type: Type of widget to create
            metric_type: Metric type to display
            title: Widget title
            config: Additional widget configuration
            
        Returns:
            Widget configuration dictionary
        """
        try:
            widget_config = {
                'id': str(uuid4()),
                'type': widget_type.value,
                'metric_type': metric_type.value,
                'title': title or f"{metric_type.value.replace('_', ' ').title()} Widget",
                'config': config or {},
                'created_at': datetime.now(timezone.utc).isoformat()
            }
            
            # Get sample data for the widget
            metrics = await self.get_metrics(metric_type, time_range="24h", limit=100)
            
            if widget_type == DashboardWidget.LINE_CHART:
                widget_config['data'] = self._create_line_chart_data(metrics)
            elif widget_type == DashboardWidget.BAR_CHART:
                widget_config['data'] = self._create_bar_chart_data(metrics)
            elif widget_type == DashboardWidget.PIE_CHART:
                widget_config['data'] = self._create_pie_chart_data(metrics)
            elif widget_type == DashboardWidget.GAUGE:
                widget_config['data'] = self._create_gauge_data(metrics)
            elif widget_type == DashboardWidget.METRIC_CARD:
                widget_config['data'] = self._create_metric_card_data(metrics)
            
            return widget_config
            
        except Exception as e:
            logger.error(f"Error creating dashboard widget: {str(e)}")
            raise
    
    def _create_line_chart_data(self, metrics: List[MetricDataPoint]) -> Dict[str, Any]:
        """Create line chart data from metrics."""
        if not metrics:
            return {'x': [], 'y': []}
        
        # Sort by timestamp
        sorted_metrics = sorted(metrics, key=lambda m: m.timestamp)
        
        return {
            'x': [m.timestamp.isoformat() for m in sorted_metrics],
            'y': [m.value for m in sorted_metrics],
            'type': 'scatter',
            'mode': 'lines+markers',
            'name': 'Metric Value'
        }
    
    def _create_bar_chart_data(self, metrics: List[MetricDataPoint]) -> Dict[str, Any]:
        """Create bar chart data from metrics."""
        if not metrics:
            return {'x': [], 'y': []}
        
        # Group by category or severity
        groups = defaultdict(list)
        for metric in metrics:
            key = metric.category or metric.severity or "Unknown"
            groups[key].append(metric.value)
        
        # Calculate averages
        categories = list(groups.keys())
        values = [statistics.mean(group_values) for group_values in groups.values()]
        
        return {
            'x': categories,
            'y': values,
            'type': 'bar',
            'name': 'Average Value'
        }
    
    def _create_pie_chart_data(self, metrics: List[MetricDataPoint]) -> Dict[str, Any]:
        """Create pie chart data from metrics."""
        if not metrics:
            return {'labels': [], 'values': []}
        
        # Count by severity
        severity_counts = defaultdict(int)
        for metric in metrics:
            severity = metric.severity or "Unknown"
            severity_counts[severity] += 1
        
        return {
            'labels': list(severity_counts.keys()),
            'values': list(severity_counts.values()),
            'type': 'pie'
        }
    
    def _create_gauge_data(self, metrics: List[MetricDataPoint]) -> Dict[str, Any]:
        """Create gauge data from metrics."""
        if not metrics:
            return {'value': 0, 'max': 100}
        
        # Use latest metric value
        latest_metric = max(metrics, key=lambda m: m.timestamp)
        
        return {
            'value': latest_metric.value,
            'max': 100,
            'type': 'indicator',
            'mode': 'gauge+number',
            'title': {'text': 'Current Value'}
        }
    
    def _create_metric_card_data(self, metrics: List[MetricDataPoint]) -> Dict[str, Any]:
        """Create metric card data from metrics."""
        if not metrics:
            return {'current': 0, 'change': 0, 'trend': 'stable'}
        
        # Calculate current value and trend
        sorted_metrics = sorted(metrics, key=lambda m: m.timestamp)
        current_value = sorted_metrics[-1].value if sorted_metrics else 0
        
        # Calculate trend (compare last 25% vs previous 25%)
        quarter_size = max(1, len(sorted_metrics) // 4)
        if len(sorted_metrics) >= quarter_size * 2:
            recent_avg = statistics.mean([m.value for m in sorted_metrics[-quarter_size:]])
            previous_avg = statistics.mean([m.value for m in sorted_metrics[-quarter_size*2:-quarter_size]])
            change_percent = ((recent_avg - previous_avg) / previous_avg) * 100 if previous_avg != 0 else 0
            
            if change_percent > 5:
                trend = 'up'
            elif change_percent < -5:
                trend = 'down'
            else:
                trend = 'stable'
        else:
            change_percent = 0
            trend = 'stable'
        
        return {
            'current': current_value,
            'change': change_percent,
            'trend': trend
        }
    
    async def analyze_security_trends(self, time_period: str = "7d") -> List[SecurityTrend]:
        """
        Analyze security trends across different metrics.
        
        Args:
            time_period: Time period for trend analysis
            
        Returns:
            List of security trend analyses
        """
        try:
            trends = []
            
            # Analyze trends for each metric type
            for metric_type in MetricType:
                metrics = await self.get_metrics(metric_type, time_range=time_period)
                
                if len(metrics) < 10:  # Need sufficient data for trend analysis
                    continue
                
                trend = await self._analyze_metric_trend(metrics, metric_type.value)
                if trend:
                    trends.append(trend)
            
            logger.info(f"Analyzed {len(trends)} security trends")
            return trends
            
        except Exception as e:
            logger.error(f"Error analyzing security trends: {str(e)}")
            raise
    
    async def _analyze_metric_trend(self, metrics: List[MetricDataPoint], metric_name: str) -> Optional[SecurityTrend]:
        """Analyze trend for a specific metric."""
        if len(metrics) < 10:
            return None
        
        # Sort by timestamp
        sorted_metrics = sorted(metrics, key=lambda m: m.timestamp)
        values = [m.value for m in sorted_metrics]
        
        # Calculate trend using linear regression
        x = list(range(len(values)))
        correlation = np.corrcoef(x, values)[0, 1] if len(values) > 1 else 0
        
        # Determine trend direction
        if correlation > 0.3:
            trend_direction = "improving" if "remediation" in metric_name.lower() else "degrading"
        elif correlation < -0.3:
            trend_direction = "degrading" if "remediation" in metric_name.lower() else "improving"
        else:
            trend_direction = "stable"
        
        # Calculate change percentage
        if len(values) >= 2:
            start_avg = statistics.mean(values[:len(values)//4])
            end_avg = statistics.mean(values[-len(values)//4:])
            change_percentage = ((end_avg - start_avg) / start_avg) * 100 if start_avg != 0 else 0
        else:
            change_percentage = 0
        
        # Determine significance
        if abs(change_percentage) > 20:
            significance = "high"
        elif abs(change_percentage) > 10:
            significance = "medium"
        else:
            significance = "low"
        
        # Generate description and recommendation
        description = f"{metric_name.replace('_', ' ').title()} has been {trend_direction} over the past period"
        
        recommendations = {
            "vulnerability_count": "Focus on remediation efforts to reduce vulnerability count",
            "remediation_rate": "Improve remediation processes and resource allocation",
            "test_coverage": "Expand testing scope to improve coverage",
            "risk_score": "Address high-risk vulnerabilities to reduce overall risk"
        }
        
        recommendation = recommendations.get(metric_name, "Monitor trend and take appropriate action")
        
        return SecurityTrend(
            metric_name=metric_name,
            trend_direction=trend_direction,
            change_percentage=change_percentage,
            significance=significance,
            description=description,
            recommendation=recommendation
        )
    
    async def get_compliance_metrics(self, framework: str = "NIST") -> Optional[ComplianceMetrics]:
        """
        Get compliance metrics for a specific framework.
        
        Args:
            framework: Compliance framework (NIST, DoD, FISMA, etc.)
            
        Returns:
            Compliance metrics or None if not found
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT framework, total_controls, tested_controls, compliant_controls,
                       non_compliant_controls, compliance_percentage, last_assessment,
                       findings_by_control
                FROM compliance_metrics
                WHERE framework = ?
                ORDER BY last_assessment DESC
                LIMIT 1
            """, (framework,))
            
            row = cursor.fetchone()
            conn.close()
            
            if not row:
                return None
            
            return ComplianceMetrics(
                framework=row[0],
                total_controls=row[1],
                tested_controls=row[2],
                compliant_controls=row[3],
                non_compliant_controls=row[4],
                compliance_percentage=row[5],
                last_assessment=datetime.fromisoformat(row[6]),
                findings_by_control=json.loads(row[7]) if row[7] else {}
            )
            
        except Exception as e:
            logger.error(f"Error retrieving compliance metrics: {str(e)}")
            raise
    
    async def update_compliance_metrics(self, compliance: ComplianceMetrics):
        """Update compliance metrics in the database."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT OR REPLACE INTO compliance_metrics (
                    id, framework, total_controls, tested_controls, compliant_controls,
                    non_compliant_controls, compliance_percentage, last_assessment,
                    findings_by_control
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                str(uuid4()),
                compliance.framework,
                compliance.total_controls,
                compliance.tested_controls,
                compliance.compliant_controls,
                compliance.non_compliant_controls,
                compliance.compliance_percentage,
                compliance.last_assessment.isoformat(),
                json.dumps(compliance.findings_by_control)
            ))
            
            conn.commit()
            conn.close()
            
            logger.info(f"Updated compliance metrics for {compliance.framework}")
            
        except Exception as e:
            logger.error(f"Error updating compliance metrics: {str(e)}")
            raise
    
    async def save_dashboard_configuration(self, config: DashboardConfiguration):
        """Save dashboard configuration to database."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT OR REPLACE INTO dashboard_configs (
                    id, name, description, widgets, refresh_interval, time_range,
                    filters, permissions, created_by, created_at, last_updated
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                config.id,
                config.name,
                config.description,
                json.dumps(config.widgets),
                config.refresh_interval,
                config.time_range,
                json.dumps(config.filters),
                json.dumps(config.permissions),
                config.created_by,
                config.created_at.isoformat(),
                config.last_updated.isoformat()
            ))
            
            conn.commit()
            conn.close()
            
            logger.info(f"Saved dashboard configuration: {config.name}")
            
        except Exception as e:
            logger.error(f"Error saving dashboard configuration: {str(e)}")
            raise
    
    async def get_dashboard_configuration(self, dashboard_id: str) -> Optional[DashboardConfiguration]:
        """Get dashboard configuration by ID."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT id, name, description, widgets, refresh_interval, time_range,
                       filters, permissions, created_by, created_at, last_updated
                FROM dashboard_configs
                WHERE id = ?
            """, (dashboard_id,))
            
            row = cursor.fetchone()
            conn.close()
            
            if not row:
                return None
            
            return DashboardConfiguration(
                id=row[0],
                name=row[1],
                description=row[2],
                widgets=json.loads(row[3]) if row[3] else [],
                refresh_interval=row[4],
                time_range=row[5],
                filters=json.loads(row[6]) if row[6] else {},
                permissions=json.loads(row[7]) if row[7] else [],
                created_by=row[8],
                created_at=datetime.fromisoformat(row[9]),
                last_updated=datetime.fromisoformat(row[10])
            )
            
        except Exception as e:
            logger.error(f"Error retrieving dashboard configuration: {str(e)}")
            raise
    
    def run_dashboard(self, host: str = "localhost", port: int = 5000, debug: bool = False):
        """
        Run the web dashboard server.
        
        Args:
            host: Host to bind to
            port: Port to bind to
            debug: Enable debug mode
        """
        logger.info(f"Starting penetration testing dashboard on {host}:{port}")
        self.app.run(host=host, port=port, debug=debug)

# Convenience functions
async def record_pentest_metric(metric_type: MetricType, 
                               value: float,
                               test_id: str = "",
                               system_id: str = "",
                               metadata: Dict[str, Any] = None):
    """Record a penetration testing metric."""
    dashboard = PentestAnalyticsDashboard()
    
    metric = MetricDataPoint(
        metric_type=metric_type,
        value=value,
        test_id=test_id,
        system_id=system_id,
        metadata=metadata or {}
    )
    
    await dashboard.record_metric(metric)

async def get_security_dashboard_data(time_range: str = "24h") -> Dict[str, Any]:
    """Get comprehensive dashboard data."""
    dashboard = PentestAnalyticsDashboard()
    
    # Get metrics for different types
    vulnerability_metrics = await dashboard.get_metrics(MetricType.VULNERABILITY_COUNT, time_range)
    severity_metrics = await dashboard.get_metrics(MetricType.SEVERITY_DISTRIBUTION, time_range)
    remediation_metrics = await dashboard.get_metrics(MetricType.REMEDIATION_RATE, time_range)
    
    # Get trends
    trends = await dashboard.analyze_security_trends()
    
    # Get compliance metrics
    nist_compliance = await dashboard.get_compliance_metrics("NIST")
    
    return {
        'vulnerability_count': [asdict(m) for m in vulnerability_metrics],
        'severity_distribution': [asdict(m) for m in severity_metrics],
        'remediation_rate': [asdict(m) for m in remediation_metrics],
        'trends': [asdict(t) for t in trends],
        'compliance': asdict(nist_compliance) if nist_compliance else None
    }

if __name__ == "__main__":
    # Example usage
    async def main():
        dashboard = PentestAnalyticsDashboard()
        
        # Record some sample metrics
        await dashboard.record_metric(MetricDataPoint(
            metric_type=MetricType.VULNERABILITY_COUNT,
            value=25,
            system_id="web-app-01",
            category="web_application"
        ))
        
        await dashboard.record_metric(MetricDataPoint(
            metric_type=MetricType.REMEDIATION_RATE,
            value=0.75,
            system_id="web-app-01"
        ))
        
        # Get metrics
        vuln_metrics = await dashboard.get_metrics(MetricType.VULNERABILITY_COUNT)
        print(f"Retrieved {len(vuln_metrics)} vulnerability metrics")
        
        # Analyze trends
        trends = await dashboard.analyze_security_trends()
        print(f"Analyzed {len(trends)} security trends")
        
        # Run dashboard (uncomment to start web server)
        # dashboard.run_dashboard(debug=True)
    
    asyncio.run(main())