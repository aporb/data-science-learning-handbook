"""
Comprehensive Testing and Validation Framework
=============================================

This module provides comprehensive testing and validation for the compliance
reporting and dashboard system, ensuring all components work correctly with
existing monitoring and audit infrastructure.

Key Features:
- Unit tests for all compliance components
- Integration tests with existing systems
- End-to-end workflow validation
- Performance and stress testing
- Security and access control validation
- Data accuracy and consistency checks

Test Coverage:
- Compliance dashboard functionality
- Automated reporting engine
- Data warehouse operations
- Alert and notification system
- Integration layer connectivity
- Classification handling
- RBAC integration

Classification: UNCLASSIFIED//FOR OFFICIAL USE ONLY
Version: 1.0 - Comprehensive System Testing
Author: Security Compliance Team
Date: 2025-07-28
"""

import asyncio
import json
import logging
import pytest
import unittest
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Tuple
from unittest.mock import Mock, MagicMock, AsyncMock, patch
import numpy as np
import tempfile
import shutil
from pathlib import Path

# Import components to test
from .dashboards.compliance_dashboard import (
    ComplianceDataProvider, ComplianceDashboard, DashboardManager,
    ComplianceMetric, ComplianceMetricType, DashboardConfiguration, DashboardType
)
from .reporting.automated_reporting_engine import (
    AutomatedReportingEngine, ReportingManager, ReportConfiguration,
    ReportType, ReportFormat, ReportFrequency
)
from .data.compliance_data_warehouse import (
    ComplianceDataWarehouse, DataWarehouseManager, HistoricalMetricPoint,
    TrendAnalysis, ForecastResult, DataAggregationLevel
)
from .alerts.compliance_alert_system import (
    ComplianceAlertSystem, AlertManager, ComplianceAlert, AlertRule,
    AlertSeverity, AlertType, AlertStatus, ComplianceDriftDetector
)
from .integration_layer import (
    ComplianceIntegrationLayer, IntegrationManager, SystemConnector,
    IntegrationConfiguration, IntegrationStatus
)

# Mock imports for existing infrastructure
from unittest.mock import MagicMock as MockAuditOrchestrator
from unittest.mock import MagicMock as MockMonitoringSystem
from unittest.mock import MagicMock as MockLogAggregator
from unittest.mock import MagicMock as MockRealTimeAlerting
from unittest.mock import MagicMock as MockRBACController

logger = logging.getLogger(__name__)


class TestComplianceDataProvider(unittest.TestCase):
    """Test cases for ComplianceDataProvider."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.mock_audit_orchestrator = MockAuditOrchestrator()
        self.mock_monitoring_system = MockMonitoringSystem()
        self.mock_log_aggregator = MockLogAggregator()
        
        self.data_provider = ComplianceDataProvider(
            self.mock_audit_orchestrator,
            self.mock_monitoring_system,
            self.mock_log_aggregator
        )
    
    @pytest.mark.asyncio
    async def test_get_compliance_metrics(self):
        """Test getting compliance metrics."""
        # Mock return values
        self.mock_audit_orchestrator.get_comprehensive_metrics.return_value = {
            "integration_status": {"overall_health": 0.95},
            "component_metrics": {"rbac_integration": {}}
        }
        
        self.mock_monitoring_system.get_performance_metrics.return_value = {
            "threat_detector": {"active_threats": 2},
            "monitoring_system": {"alerts_sent": 10, "threats_detected": 8}
        }
        
        # Test
        metrics = await self.data_provider.get_compliance_metrics()
        
        # Assertions
        self.assertIsInstance(metrics, list)
        self.assertGreater(len(metrics), 0)
        
        for metric in metrics:
            self.assertIsInstance(metric, ComplianceMetric)
            self.assertIsInstance(metric.metric_type, ComplianceMetricType)
            self.assertGreaterEqual(metric.current_value, 0)
    
    @pytest.mark.asyncio
    async def test_calculate_overall_posture(self):
        """Test overall compliance posture calculation."""
        # Mock return values
        self.mock_audit_orchestrator.get_comprehensive_metrics.return_value = {
            "integration_status": {"overall_health": 0.9}
        }
        
        self.mock_monitoring_system.get_performance_metrics.return_value = {
            "monitoring_system": {"events_per_second": 100, "active_threats": 1}
        }
        
        # Test
        metric = await self.data_provider._calculate_overall_posture()
        
        # Assertions
        self.assertIsInstance(metric, ComplianceMetric)
        self.assertEqual(metric.metric_type, ComplianceMetricType.OVERALL_POSTURE)
        self.assertGreaterEqual(metric.current_value, 0)
        self.assertLessEqual(metric.current_value, 100)
    
    def test_extract_health_score(self):
        """Test health score extraction from metrics."""
        # Test data
        metrics = {
            "monitoring_system": {
                "events_per_second": 50,
                "active_threats": 3,
                "buffer_size": 5000
            }
        }
        
        # Test
        health_score = self.data_provider._extract_health_score(metrics)
        
        # Assertions
        self.assertIsInstance(health_score, float)
        self.assertGreaterEqual(health_score, 0)
        self.assertLessEqual(health_score, 100)


class TestComplianceDashboard(unittest.TestCase):
    """Test cases for ComplianceDashboard."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.mock_data_provider = Mock()
        self.mock_rbac_controller = Mock()
        
        # Create dashboard configuration
        self.dashboard_config = DashboardConfiguration(
            dashboard_type=DashboardType.EXECUTIVE,
            name="Test Dashboard",
            description="Test dashboard for validation"
        )
        
        self.dashboard = ComplianceDashboard(
            self.dashboard_config,
            self.mock_data_provider,
            self.mock_rbac_controller
        )
    
    @pytest.mark.asyncio
    async def test_dashboard_start_stop(self):
        """Test dashboard start and stop functionality."""
        # Test start
        await self.dashboard.start()
        self.assertTrue(self.dashboard.is_active)
        
        # Test stop
        await self.dashboard.stop()
        self.assertFalse(self.dashboard.is_active)
    
    @pytest.mark.asyncio
    async def test_refresh_data(self):
        """Test dashboard data refresh."""
        # Mock compliance metrics
        mock_metrics = [
            ComplianceMetric(
                metric_type=ComplianceMetricType.OVERALL_POSTURE,
                metric_name="Test Metric",
                current_value=85.0,
                target_value=95.0
            )
        ]
        
        self.mock_data_provider.get_compliance_metrics.return_value = mock_metrics
        
        # Test
        await self.dashboard.refresh_data()
        
        # Assertions
        self.assertIsNotNone(self.dashboard.last_refresh)
        self.assertIn("UNCLASSIFIED", self.dashboard.dashboard_data)
    
    def test_filter_metrics_by_clearance(self):
        """Test metric filtering by clearance level."""
        # Test metrics with different classification levels
        metrics = [
            ComplianceMetric(
                metric_type=ComplianceMetricType.OVERALL_POSTURE,
                metric_name="Unclassified Metric",
                classification_level="UNCLASSIFIED"
            ),
            ComplianceMetric(
                metric_type=ComplianceMetricType.CLASSIFICATION_COMPLIANCE,
                metric_name="Confidential Metric",
                classification_level="CONFIDENTIAL",
                requires_clearance=True
            ),
            ComplianceMetric(
                metric_type=ComplianceMetricType.ACCESS_CONTROL,
                metric_name="Secret Metric",
                classification_level="SECRET",
                requires_clearance=True
            )
        ]
        
        # Test with UNCLASSIFIED clearance
        filtered = self.dashboard._filter_metrics_by_clearance(metrics, "UNCLASSIFIED")
        self.assertEqual(len(filtered), 1)
        self.assertEqual(filtered[0].classification_level, "UNCLASSIFIED")
        
        # Test with CONFIDENTIAL clearance
        filtered = self.dashboard._filter_metrics_by_clearance(metrics, "CONFIDENTIAL")
        self.assertEqual(len(filtered), 2)
        
        # Test with SECRET clearance
        filtered = self.dashboard._filter_metrics_by_clearance(metrics, "SECRET")
        self.assertEqual(len(filtered), 3)
    
    def test_generate_summary(self):
        """Test dashboard summary generation."""
        # Test metrics
        metrics = [
            ComplianceMetric(
                metric_type=ComplianceMetricType.OVERALL_POSTURE,
                metric_name="High Score Metric",
                current_value=95.0,
                target_value=100.0,
                framework="TestFramework1"
            ),
            ComplianceMetric(
                metric_type=ComplianceMetricType.CONTROL_EFFECTIVENESS,
                metric_name="Medium Score Metric",
                current_value=80.0,
                target_value=100.0,
                framework="TestFramework2"
            )
        ]
        
        # Test
        summary = self.dashboard._generate_summary(metrics)
        
        # Assertions
        self.assertIn("overall_score", summary)
        self.assertIn("total_metrics", summary)
        self.assertIn("status", summary)
        self.assertIn("alert_counts", summary)
        self.assertEqual(summary["total_metrics"], 2)
        self.assertGreater(summary["overall_score"], 0)


class TestAutomatedReportingEngine(unittest.TestCase):
    """Test cases for AutomatedReportingEngine."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        
        # Mock dependencies
        self.mock_data_provider = Mock()
        self.mock_audit_orchestrator = MockAuditOrchestrator()
        self.mock_monitoring_system = MockMonitoringSystem()
        
        self.reporting_engine = AutomatedReportingEngine(
            self.mock_data_provider,
            self.mock_audit_orchestrator,
            self.mock_monitoring_system
        )
    
    def tearDown(self):
        """Clean up test fixtures."""
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    @pytest.mark.asyncio
    async def test_create_report_config(self):
        """Test report configuration creation."""
        config = ReportConfiguration(
            name="Test Report",
            report_type=ReportType.EXECUTIVE_SUMMARY,
            frequency=ReportFrequency.DAILY,
            output_formats=[ReportFormat.PDF, ReportFormat.JSON],
            output_directory=self.temp_dir
        )
        
        # Test
        config_id = await self.reporting_engine.create_report_config(config)
        
        # Assertions
        self.assertIsInstance(config_id, str)
        self.assertIn(config_id, self.reporting_engine.report_configs)
        self.assertEqual(self.reporting_engine.report_configs[config_id].name, "Test Report")
    
    @pytest.mark.asyncio
    async def test_generate_report_on_demand(self):
        """Test on-demand report generation."""
        # Create report configuration
        config = ReportConfiguration(
            name="Test On-Demand Report",
            report_type=ReportType.EXECUTIVE_SUMMARY,
            output_formats=[ReportFormat.JSON],
            output_directory=self.temp_dir
        )
        
        config_id = await self.reporting_engine.create_report_config(config)
        
        # Mock compliance metrics
        mock_metrics = [
            ComplianceMetric(
                metric_type=ComplianceMetricType.OVERALL_POSTURE,
                metric_name="Test Metric",
                current_value=85.0
            )
        ]
        
        self.mock_data_provider.get_compliance_metrics.return_value = mock_metrics
        
        # Test
        generation_id = await self.reporting_engine.generate_report_on_demand(config_id)
        
        # Assertions
        self.assertIsInstance(generation_id, str)
        self.assertIn(generation_id, self.reporting_engine.generated_reports)
    
    def test_calculate_next_run(self):
        """Test next run time calculation."""
        current_time = datetime.now(timezone.utc)
        
        # Test daily frequency
        next_run = self.reporting_engine._calculate_next_run(ReportFrequency.DAILY)
        expected = current_time + timedelta(days=1)
        self.assertAlmostEqual(
            next_run.timestamp(), 
            expected.timestamp(), 
            delta=60  # 1 minute tolerance
        )
        
        # Test weekly frequency
        next_run = self.reporting_engine._calculate_next_run(ReportFrequency.WEEKLY)
        expected = current_time + timedelta(weeks=1)
        self.assertAlmostEqual(
            next_run.timestamp(),
            expected.timestamp(),
            delta=3600  # 1 hour tolerance
        )


class TestComplianceDataWarehouse(unittest.TestCase):
    """Test cases for ComplianceDataWarehouse."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.temp_db = tempfile.NamedTemporaryFile(suffix='.db', delete=False)
        self.temp_db.close()
        
        # Mock dependencies
        self.mock_data_provider = Mock()
        self.mock_audit_orchestrator = MockAuditOrchestrator()
        self.mock_monitoring_system = MockMonitoringSystem()
        
        self.data_warehouse = ComplianceDataWarehouse(
            self.mock_data_provider,
            self.mock_audit_orchestrator,
            self.mock_monitoring_system,
            self.temp_db.name
        )
    
    def tearDown(self):
        """Clean up test fixtures."""
        try:
            Path(self.temp_db.name).unlink()
        except:
            pass
    
    @pytest.mark.asyncio
    async def test_initialize_database(self):
        """Test database initialization."""
        await self.data_warehouse.initialize()
        
        # Check that database file exists
        self.assertTrue(Path(self.temp_db.name).exists())
    
    @pytest.mark.asyncio
    async def test_store_historical_metric(self):
        """Test storing historical metrics."""
        await self.data_warehouse.initialize()
        
        # Create test metric point
        metric_point = HistoricalMetricPoint(
            metric_type=ComplianceMetricType.OVERALL_POSTURE,
            metric_name="Test Metric",
            value=85.0,
            target_value=95.0,
            compliance_score=89.5
        )
        
        # Test storage  
        await self.data_warehouse.db_manager.store_historical_metric(metric_point)
        
        # Verify storage
        retrieved = await self.data_warehouse.db_manager.get_historical_metrics(
            metric_type=ComplianceMetricType.OVERALL_POSTURE,
            limit=1
        )
        
        self.assertEqual(len(retrieved), 1)
        self.assertEqual(retrieved[0].metric_name, "Test Metric")
        self.assertEqual(retrieved[0].value, 85.0)
    
    @pytest.mark.asyncio
    async def test_analyze_trends(self):
        """Test trend analysis functionality."""
        await self.data_warehouse.initialize()
        
        # Create test data with trend
        base_time = datetime.now(timezone.utc) - timedelta(days=10)
        
        for i in range(10):
            metric_point = HistoricalMetricPoint(
                timestamp=base_time + timedelta(days=i),
                metric_type=ComplianceMetricType.OVERALL_POSTURE,
                metric_name="Trending Metric",
                value=80.0 + i * 2,  # Increasing trend
                compliance_score=80.0 + i * 2
            )
            await self.data_warehouse.db_manager.store_historical_metric(metric_point)
        
        # Test trend analysis
        time_range = (base_time, datetime.now(timezone.utc))
        trend_analysis = await self.data_warehouse.analyze_trends(
            ComplianceMetricType.OVERALL_POSTURE,
            time_range
        )
        
        # Assertions
        self.assertIsInstance(trend_analysis, TrendAnalysis)
        self.assertEqual(trend_analysis.metric_type, ComplianceMetricType.OVERALL_POSTURE)
        self.assertGreater(trend_analysis.data_points_analyzed, 0)
    
    @pytest.mark.asyncio
    async def test_generate_forecast(self):
        """Test forecast generation functionality."""
        await self.data_warehouse.initialize()
        
        # Create historical data
        base_time = datetime.now(timezone.utc) - timedelta(days=20)
        
        for i in range(15):  # Need minimum data for forecasting
            metric_point = HistoricalMetricPoint(
                timestamp=base_time + timedelta(days=i),
                metric_type=ComplianceMetricType.CONTROL_EFFECTIVENESS,
                metric_name="Forecast Test Metric",
                value=85.0 + np.random.normal(0, 2),  # Add some noise
                compliance_score=85.0 + np.random.normal(0, 2)
            )
            await self.data_warehouse.db_manager.store_historical_metric(metric_point)
        
        # Test forecast generation
        historical_period = (base_time, base_time + timedelta(days=15))
        forecast_period = (base_time + timedelta(days=15), base_time + timedelta(days=25))
        
        forecast = await self.data_warehouse.generate_forecast(
            ComplianceMetricType.CONTROL_EFFECTIVENESS,
            historical_period,
            forecast_period
        )
        
        # Assertions
        self.assertIsInstance(forecast, ForecastResult)
        self.assertEqual(forecast.metric_type, ComplianceMetricType.CONTROL_EFFECTIVENESS)
        self.assertGreater(len(forecast.forecasted_values), 0)


class TestComplianceAlertSystem(unittest.TestCase):
    """Test cases for ComplianceAlertSystem."""
    
    def setUp(self):
        """Set up test fixtures."""
        # Mock dependencies
        self.mock_data_provider = Mock()
        self.mock_data_warehouse = Mock()
        self.mock_audit_orchestrator = MockAuditOrchestrator()
        self.mock_monitoring_system = MockMonitoringSystem()
        self.mock_real_time_alerting = MockRealTimeAlerting()
        
        # Mock async methods
        self.mock_real_time_alerting.send_alert = AsyncMock()
        
        self.alert_system = ComplianceAlertSystem(
            self.mock_data_provider,
            self.mock_data_warehouse,
            self.mock_audit_orchestrator,
            self.mock_monitoring_system,
            self.mock_real_time_alerting
        )
    
    @pytest.mark.asyncio
    async def test_alert_system_start_stop(self):
        """Test alert system start and stop functionality."""
        # Test start
        await self.alert_system.start()
        self.assertTrue(self.alert_system.is_running)
        
        # Test stop
        await self.alert_system.stop()
        self.assertFalse(self.alert_system.is_running)
    
    def test_create_default_alert_rules(self):
        """Test creation of default alert rules."""
        # Check that default rules were created
        self.assertGreater(len(self.alert_system.alert_rules), 0)
        
        # Check rule properties
        for rule in self.alert_system.alert_rules.values():
            self.assertIsInstance(rule, AlertRule)
            self.assertIsInstance(rule.alert_type, AlertType)
            self.assertIsInstance(rule.severity, AlertSeverity)
            self.assertTrue(rule.enabled)
            self.assertGreater(len(rule.name), 0)
    
    @pytest.mark.asyncio
    async def test_create_alert_from_rule(self):
        """Test alert creation from rule."""
        # Create test rule
        rule = AlertRule(
            name="Test Rule",
            metric_type=ComplianceMetricType.OVERALL_POSTURE,
            threshold_type="below",
            threshold_value=80.0,
            alert_type=AlertType.THRESHOLD_VIOLATION,
            severity=AlertSeverity.HIGH
        )
        
        # Create test metric that violates rule
        metric = ComplianceMetric(
            metric_type=ComplianceMetricType.OVERALL_POSTURE,
            metric_name="Test Metric",
            current_value=75.0,  # Below threshold
            target_value=95.0,
            framework="Test Framework"
        )
        
        # Test alert creation
        alert = await self.alert_system._create_alert_from_rule(rule, metric)
        
        # Assertions
        self.assertIsInstance(alert, ComplianceAlert)
        self.assertEqual(alert.alert_type, AlertType.THRESHOLD_VIOLATION)
        self.assertEqual(alert.severity, AlertSeverity.HIGH)
        self.assertEqual(alert.current_value, 75.0)
        self.assertEqual(alert.threshold_value, 80.0)
    
    @pytest.mark.asyncio
    async def test_acknowledge_alert(self):
        """Test alert acknowledgment."""
        # Create test alert
        alert = ComplianceAlert(
            title="Test Alert",
            message="Test alert message",
            severity=AlertSeverity.MEDIUM
        )
        
        # Add to active alerts
        self.alert_system.active_alerts[alert.alert_id] = alert
        
        # Test acknowledgment
        success = await self.alert_system.acknowledge_alert(
            alert.alert_id, 
            "test_user", 
            "Test acknowledgment"
        )
        
        # Assertions
        self.assertTrue(success)
        self.assertEqual(alert.status, AlertStatus.ACKNOWLEDGED)
        self.assertEqual(alert.acknowledged_by, "test_user")
        self.assertIsNotNone(alert.acknowledged_at)
    
    @pytest.mark.asyncio
    async def test_resolve_alert(self):
        """Test alert resolution."""
        # Create test alert
        alert = ComplianceAlert(
            title="Test Alert",
            message="Test alert message",
            severity=AlertSeverity.LOW
        )
        
        # Add to active alerts
        self.alert_system.active_alerts[alert.alert_id] = alert
        
        # Test resolution
        success = await self.alert_system.resolve_alert(
            alert.alert_id,
            "test_user",
            "Issue resolved"
        )
        
        # Assertions
        self.assertTrue(success)
        self.assertEqual(alert.status, AlertStatus.RESOLVED)
        self.assertEqual(alert.resolved_by, "test_user")
        self.assertEqual(alert.resolution_notes, "Issue resolved")
    
    def test_get_active_alerts(self):
        """Test retrieving active alerts."""
        # Create test alerts
        alert1 = ComplianceAlert(
            title="High Severity Alert",
            severity=AlertSeverity.HIGH,
            status=AlertStatus.ACTIVE
        )
        
        alert2 = ComplianceAlert(
            title="Low Severity Alert", 
            severity=AlertSeverity.LOW,
            status=AlertStatus.ACTIVE
        )
        
        alert3 = ComplianceAlert(
            title="Resolved Alert",
            severity=AlertSeverity.MEDIUM,
            status=AlertStatus.RESOLVED
        )
        
        # Add to active alerts
        self.alert_system.active_alerts[alert1.alert_id] = alert1
        self.alert_system.active_alerts[alert2.alert_id] = alert2
        self.alert_system.active_alerts[alert3.alert_id] = alert3
        
        # Test getting all active alerts
        active_alerts = self.alert_system.get_active_alerts()
        
        # Should return 2 active alerts (resolved one excluded)
        self.assertEqual(len(active_alerts), 2)
        
        # Test filtering by severity
        high_alerts = self.alert_system.get_active_alerts(AlertSeverity.HIGH)
        self.assertEqual(len(high_alerts), 1)
        self.assertEqual(high_alerts[0]["title"], "High Severity Alert")


class TestComplianceDriftDetector(unittest.TestCase):
    """Test cases for ComplianceDriftDetector."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.mock_data_warehouse = Mock()
        self.drift_detector = ComplianceDriftDetector(self.mock_data_warehouse)
    
    def test_detect_statistical_drift(self):
        """Test statistical drift detection."""
        # Test data - historical values with normal distribution
        historical_values = [85.0, 87.0, 84.0, 86.0, 85.5, 86.5, 84.5, 87.5]
        current_value = 95.0  # Significant deviation
        
        # Test drift detection
        drift = self.drift_detector._detect_statistical_drift(historical_values, current_value)
        
        # Assertions
        self.assertIsNotNone(drift)
        self.assertEqual(drift["drift_type"], "statistical_anomaly")
        self.assertGreater(drift["z_score"], 2.0)  # Should exceed threshold
        self.assertEqual(drift["current_value"], 95.0)
    
    def test_no_drift_detection(self):
        """Test when no drift should be detected."""
        # Test data - values within normal range
        historical_values = [85.0, 87.0, 84.0, 86.0, 85.5]
        current_value = 86.0  # Normal value
        
        # Test drift detection
        drift = self.drift_detector._detect_statistical_drift(historical_values, current_value)
        
        # Assertions
        self.assertIsNone(drift)  # No drift should be detected


class TestComplianceIntegrationLayer(unittest.TestCase):
    """Test cases for ComplianceIntegrationLayer."""
    
    def setUp(self):
        """Set up test fixtures."""
        # Mock infrastructure components
        self.mock_audit_orchestrator = MockAuditOrchestrator()
        self.mock_monitoring_system = MockMonitoringSystem()
        self.mock_log_aggregator = MockLogAggregator()
        self.mock_real_time_alerting = MockRealTimeAlerting()
        
        # Mock async methods
        self.mock_audit_orchestrator.health_check = AsyncMock(
            return_value={"status": "healthy"}
        )
        self.mock_monitoring_system.health_check = AsyncMock(
            return_value={"overall_healthy": True}
        )
        self.mock_log_aggregator.health_check = AsyncMock(
            return_value={"status": "healthy"}
        )
        
        self.integration_layer = ComplianceIntegrationLayer(
            self.mock_audit_orchestrator,
            self.mock_monitoring_system,
            self.mock_log_aggregator,
            self.mock_real_time_alerting
        )
    
    @pytest.mark.asyncio
    async def test_integration_layer_initialize(self):
        """Test integration layer initialization."""
        await self.integration_layer.initialize()
        
        # Check that components were initialized
        self.assertIsNotNone(self.integration_layer.data_provider)
        self.assertIsNotNone(self.integration_layer.dashboard_manager)
        self.assertIsNotNone(self.integration_layer.reporting_manager)
        self.assertIsNotNone(self.integration_layer.data_warehouse_manager)
        self.assertIsNotNone(self.integration_layer.alert_manager)
        
        # Check connectors
        self.assertIn("audit_orchestrator", self.integration_layer.connectors)
        self.assertIn("monitoring_system", self.integration_layer.connectors)
        self.assertIn("log_aggregator", self.integration_layer.connectors)
    
    @pytest.mark.asyncio
    async def test_integration_layer_start_stop(self):
        """Test integration layer start and stop."""
        await self.integration_layer.initialize()
        
        # Test start
        await self.integration_layer.start()
        self.assertTrue(self.integration_layer.is_running)
        
        # Test stop
        await self.integration_layer.stop()
        self.assertFalse(self.integration_layer.is_running)
    
    @pytest.mark.asyncio
    async def test_connector_health_check(self):
        """Test connector health checks."""
        await self.integration_layer.initialize()
        
        # Test health check for audit orchestrator connector
        connector = self.integration_layer.connectors["audit_orchestrator"]
        health = await connector.health_check()
        
        # Assertions
        self.assertIsInstance(health, dict)
        self.assertIn("integration_name", health)
        self.assertIn("status", health)
    
    def test_get_integration_status(self):
        """Test getting integration status."""
        status = self.integration_layer.get_integration_status()
        
        # Assertions
        self.assertIsInstance(status, dict)
        self.assertIn("overall_status", status)
        self.assertIn("integration_metrics", status)
        self.assertIn("connectors", status)
        self.assertIn("compliance_components", status)


class TestSystemConnector(unittest.TestCase):
    """Test cases for SystemConnector base class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.config = IntegrationConfiguration(
            name="Test Connector",
            description="Test connector for validation",
            sync_interval_seconds=60
        )
        
        self.connector = SystemConnector(self.config)
    
    @pytest.mark.asyncio
    async def test_connector_connect_disconnect(self):
        """Test connector connection and disconnection."""
        # Test connection
        connected = await self.connector.connect()
        self.assertTrue(connected)
        self.assertTrue(self.connector.connection_established)
        self.assertEqual(self.connector.status, IntegrationStatus.ACTIVE)
        
        # Test disconnection
        await self.connector.disconnect()
        self.assertFalse(self.connector.connection_established)
        self.assertEqual(self.connector.status, IntegrationStatus.INACTIVE)
    
    @pytest.mark.asyncio
    async def test_sync_data(self):
        """Test data synchronization."""
        # Connect first
        await self.connector.connect()
        
        # Test sync
        result = await self.connector.sync_data()
        
        # Assertions
        self.assertIsInstance(result, dict)
        self.assertIn("status", result)
        self.assertEqual(result["status"], "success")
    
    @pytest.mark.asyncio
    async def test_health_check(self):
        """Test health check functionality."""
        health = await self.connector.health_check()
        
        # Assertions
        self.assertIsInstance(health, dict)
        self.assertIn("integration_name", health)
        self.assertIn("status", health)
        self.assertEqual(health["integration_name"], "Test Connector")


# Integration test suite
class TestCompleteWorkflow(unittest.TestCase):
    """End-to-end integration tests for the complete compliance system."""
    
    def setUp(self):
        """Set up comprehensive test environment."""
        self.temp_dir = tempfile.mkdtemp()
        self.temp_db = tempfile.NamedTemporaryFile(suffix='.db', delete=False)
        self.temp_db.close()
        
        # Mock all infrastructure components
        self.mock_audit_orchestrator = MockAuditOrchestrator()
        self.mock_monitoring_system = MockMonitoringSystem()
        self.mock_log_aggregator = MockLogAggregator()
        self.mock_real_time_alerting = MockRealTimeAlerting()
        
        # Set up comprehensive mock return values
        self._setup_mock_responses()
    
    def tearDown(self):
        """Clean up test environment."""
        shutil.rmtree(self.temp_dir, ignore_errors=True)
        try:
            Path(self.temp_db.name).unlink()
        except:
            pass
    
    def _setup_mock_responses(self):
        """Set up comprehensive mock responses."""
        # Audit orchestrator mocks
        self.mock_audit_orchestrator.get_comprehensive_metrics.return_value = {
            "integration_status": {"overall_health": 0.92, "active_integrations": 5},
            "component_metrics": {
                "rbac_integration": {"status": "active"},
                "classification": {"status": "active"}
            }
        }
        
        self.mock_audit_orchestrator.get_integration_status.return_value = {
            "integrations": {"rbac_system": "active", "classification_framework": "active"}
        }
        
        self.mock_audit_orchestrator.health_check = AsyncMock(
            return_value={"status": "healthy", "components": {"storage": {"status": "healthy"}}}
        )
        
        # Monitoring system mocks
        self.mock_monitoring_system.get_performance_metrics.return_value = {
            "monitoring_system": {
                "events_per_second": 150,
                "active_threats": 2,
                "alerts_sent": 15,
                "threats_detected": 12
            },
            "threat_detector": {"active_threats": 2}
        }
        
        self.mock_monitoring_system.health_check = AsyncMock(
            return_value={"overall_healthy": True, "status": "healthy"}
        )
        
        # Log aggregator mocks
        self.mock_log_aggregator.get_performance_metrics.return_value = {
            "log_aggregator": {
                "total_events_processed": 50000,
                "processing_errors": 5,
                "events_per_second": 100
            }
        }
        
        self.mock_log_aggregator.health_check = AsyncMock(
            return_value={"status": "healthy"}
        )
        
        # Real-time alerting mocks
        self.mock_real_time_alerting.send_alert = AsyncMock(return_value=True)
    
    @pytest.mark.asyncio
    async def test_complete_system_integration(self):
        """Test complete system integration workflow."""
        # Initialize integration layer
        integration_layer = ComplianceIntegrationLayer(
            self.mock_audit_orchestrator,
            self.mock_monitoring_system,
            self.mock_log_aggregator,
            self.mock_real_time_alerting
        )
        
        # Initialize and start
        await integration_layer.initialize()
        await integration_layer.start()
        
        try:
            # Verify all components are initialized
            self.assertIsNotNone(integration_layer.data_provider)
            self.assertIsNotNone(integration_layer.dashboard_manager)
            self.assertIsNotNone(integration_layer.reporting_manager)
            self.assertIsNotNone(integration_layer.data_warehouse_manager)
            self.assertIsNotNone(integration_layer.alert_manager)
            
            # Test data provider functionality
            data_provider = integration_layer.data_provider
            metrics = await data_provider.get_compliance_metrics()
            
            self.assertIsInstance(metrics, list)
            self.assertGreater(len(metrics), 0)
            
            # Test dashboard functionality
            dashboard_manager = integration_layer.dashboard_manager
            
            # Create executive dashboard
            exec_dashboard_id = await dashboard_manager.create_dashboard("executive")
            self.assertIsInstance(exec_dashboard_id, str)
            
            # Get dashboard data
            dashboard_data = await dashboard_manager.get_dashboard_data(
                exec_dashboard_id, "test_user", "test_session", "UNCLASSIFIED"
            )
            
            self.assertIsInstance(dashboard_data, dict)
            self.assertIn("metrics", dashboard_data)
            
            # Test reporting functionality
            reporting_manager = integration_layer.reporting_manager
            reporting_engine = reporting_manager.get_reporting_engine()
            
            # Create report configuration
            report_config = ReportConfiguration(
                name="Integration Test Report",
                report_type=ReportType.EXECUTIVE_SUMMARY,
                output_formats=[ReportFormat.JSON],
                output_directory=self.temp_dir
            )
            
            config_id = await reporting_engine.create_report_config(report_config)
            self.assertIsInstance(config_id, str)
            
            # Generate report
            generation_id = await reporting_engine.generate_report_on_demand(config_id)
            self.assertIsInstance(generation_id, str)
            
            # Test alert functionality
            alert_manager = integration_layer.alert_manager
            alert_system = alert_manager.get_alert_system()
            
            # Check default alert rules
            rules = alert_system.alert_rules
            self.assertGreater(len(rules), 0)
            
            # Test health check
            health = await integration_layer.health_check()
            self.assertIsInstance(health, dict)
            self.assertIn("status", health)
            
            # Test integration status
            status = integration_layer.get_integration_status()
            self.assertIsInstance(status, dict)
            self.assertIn("overall_status", status)
            
        finally:
            # Clean up
            await integration_layer.stop()
    
    @pytest.mark.asyncio
    async def test_error_handling_and_resilience(self):
        """Test system error handling and resilience."""
        # Set up failing mocks
        self.mock_audit_orchestrator.health_check = AsyncMock(
            return_value={"status": "unhealthy"}
        )
        
        # Initialize integration layer
        integration_layer = ComplianceIntegrationLayer(
            self.mock_audit_orchestrator,
            self.mock_monitoring_system,
            self.mock_log_aggregator,
            self.mock_real_time_alerting
        )
        
        await integration_layer.initialize()
        await integration_layer.start()
        
        try:
            # System should still function despite unhealthy audit orchestrator
            data_provider = integration_layer.data_provider
            
            # This should not crash even with unhealthy dependency
            metrics = await data_provider.get_compliance_metrics()
            self.assertIsInstance(metrics, list)
            
            # Health check should report degraded status
            health = await integration_layer.health_check()
            self.assertIn(health["status"], ["degraded", "failed"])
            
        finally:
            await integration_layer.stop()


# Performance and stress tests
class TestPerformanceAndStress(unittest.TestCase):
    """Performance and stress tests for compliance system."""
    
    def setUp(self):
        """Set up performance test environment."""
        self.temp_db = tempfile.NamedTemporaryFile(suffix='.db', delete=False)
        self.temp_db.close()
        
        # Mock components
        self.mock_data_provider = Mock()
        self.mock_audit_orchestrator = MockAuditOrchestrator()
        self.mock_monitoring_system = MockMonitoringSystem()
        
        self.data_warehouse = ComplianceDataWarehouse(
            self.mock_data_provider,
            self.mock_audit_orchestrator,
            self.mock_monitoring_system,
            self.temp_db.name
        )
    
    def tearDown(self):
        """Clean up performance test environment."""
        try:
            Path(self.temp_db.name).unlink()
        except:
            pass
    
    @pytest.mark.asyncio
    async def test_high_volume_data_storage(self):
        """Test storing high volume of historical data."""
        await self.data_warehouse.initialize()
        
        # Generate large number of metric points
        metric_points = []
        base_time = datetime.now(timezone.utc) - timedelta(days=30)
        
        for i in range(1000):  # 1000 data points
            metric_point = HistoricalMetricPoint(
                timestamp=base_time + timedelta(minutes=i),
                metric_type=ComplianceMetricType.OVERALL_POSTURE,
                metric_name=f"Metric_{i % 10}",
                value=80.0 + np.random.normal(0, 5),
                compliance_score=80.0 + np.random.normal(0, 5)
            )
            metric_points.append(metric_point)
        
        # Measure storage performance
        start_time = time.time()
        await self.data_warehouse.db_manager.store_multiple_historical_metrics(metric_points)
        storage_time = time.time() - start_time
        
        # Assertions
        self.assertLess(storage_time, 10.0)  # Should complete within 10 seconds
        
        # Verify data was stored
        retrieved = await self.data_warehouse.db_manager.get_historical_metrics(
            metric_type=ComplianceMetricType.OVERALL_POSTURE,
            limit=1000
        )
        
        self.assertEqual(len(retrieved), 1000)
    
    @pytest.mark.asyncio
    async def test_concurrent_dashboard_access(self):
        """Test concurrent dashboard access."""
        # Mock data provider
        mock_metrics = [
            ComplianceMetric(
                metric_type=ComplianceMetricType.OVERALL_POSTURE,
                metric_name="Test Metric",
                current_value=85.0
            )
        ]
        
        self.mock_data_provider.get_compliance_metrics.return_value = mock_metrics
        
        # Create dashboard
        dashboard_config = DashboardConfiguration(
            name="Performance Test Dashboard",
            dashboard_type=DashboardType.EXECUTIVE  
        )
        
        dashboard = ComplianceDashboard(
            dashboard_config,
            self.mock_data_provider
        )
        
        await dashboard.start()
        
        try:
            # Simulate concurrent access
            tasks = []
            for i in range(50):  # 50 concurrent requests
                task = dashboard.get_dashboard_data(
                    f"user_{i}", f"session_{i}", "UNCLASSIFIED"
                )
                tasks.append(task)
            
            # Measure concurrent access performance
            start_time = time.time()
            results = await asyncio.gather(*tasks)
            access_time = time.time() - start_time
            
            # Assertions
            self.assertEqual(len(results), 50)
            self.assertLess(access_time, 5.0)  # Should complete within 5 seconds
            
            # All requests should be successful
            for result in results:
                self.assertIsInstance(result, dict)
                self.assertNotIn("error", result)
        
        finally:
            await dashboard.stop()


# Test runner and utilities
def run_all_tests():
    """Run all compliance system tests."""
    print("Running Comprehensive Compliance System Tests...")
    print("=" * 60)
    
    # Configure logging for tests
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Create test suite
    test_suite = unittest.TestSuite()
    
    # Add test cases
    test_classes = [
        TestComplianceDataProvider,
        TestComplianceDashboard,
        TestAutomatedReportingEngine,
        TestComplianceDataWarehouse,
        TestComplianceAlertSystem,
        TestComplianceDriftDetector,
        TestComplianceIntegrationLayer,
        TestSystemConnector,
        TestCompleteWorkflow,
        TestPerformanceAndStress
    ]
    
    for test_class in test_classes:
        tests = unittest.TestLoader().loadTestsFromTestCase(test_class)
        test_suite.addTests(tests)
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(test_suite)
    
    # Print summary
    print("\n" + "=" * 60)
    print("Test Summary:")
    print(f"Total Tests: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Skipped: {len(result.skipped) if hasattr(result, 'skipped') else 0}")
    
    if result.failures:
        print("\nFailures:")
        for test, traceback in result.failures:
            print(f"- {test}: {traceback}")
    
    if result.errors:
        print("\nErrors:")
        for test, traceback in result.errors:
            print(f"- {test}: {traceback}")
    
    # Return success status
    return len(result.failures) == 0 and len(result.errors) == 0


if __name__ == "__main__":
    success = run_all_tests()
    exit(0 if success else 1)