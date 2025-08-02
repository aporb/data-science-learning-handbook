"""
Security and Classification Validation Tests
===========================================

This module provides specialized security and classification validation tests
for the compliance reporting and dashboard system, ensuring proper handling of
classified data and security controls.

Key Testing Areas:
- Classification level enforcement
- RBAC integration validation
- Data encryption and protection
- Access control validation
- Audit trail verification
- Security incident response
- Clearance level compliance

Classification: UNCLASSIFIED//FOR OFFICIAL USE ONLY 
Version: 1.0 - Security Validation Framework
Author: Security Compliance Team
Date: 2025-07-28
"""

import asyncio
import json
import logging
import pytest
import unittest
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any
from unittest.mock import Mock, MagicMock, AsyncMock, patch
import tempfile
import shutil
from pathlib import Path

# Import components for security testing
from .dashboards.compliance_dashboard import (
    ComplianceDataProvider, ComplianceDashboard, DashboardManager,
    ComplianceMetric, ComplianceMetricType, DashboardConfiguration, DashboardType
)
from .alerts.compliance_alert_system import (
    ComplianceAlertSystem, AlertManager, ComplianceAlert, AlertRule,
    AlertSeverity, AlertType, AlertStatus
)
from .integration_layer import (
    ComplianceIntegrationLayer, IntegrationManager, SystemConnector,
    IntegrationConfiguration, IntegrationStatus
)

logger = logging.getLogger(__name__)


class TestClassificationEnforcement(unittest.TestCase):
    """Test classification level enforcement across all components."""
    
    def setUp(self):
        """Set up classification test fixtures."""
        self.mock_rbac_controller = Mock()
        self.mock_data_provider = Mock()
        
        # Mock clearance validation
        self.mock_rbac_controller.validate_user_clearance.return_value = True
        self.mock_rbac_controller.get_user_clearance_level.return_value = "SECRET"
        
        self.dashboard_config = DashboardConfiguration(
            name="Classification Test Dashboard",
            dashboard_type=DashboardType.SECURITY_OPERATIONS
        )
        
        self.dashboard = ComplianceDashboard(
            self.dashboard_config,
            self.mock_data_provider,
            self.mock_rbac_controller
        )
    
    def test_unclassified_data_access(self):
        """Test access to unclassified data."""
        # Create unclassified metrics
        metrics = [
            ComplianceMetric(
                metric_type=ComplianceMetricType.OVERALL_POSTURE,
                metric_name="Unclassified Metric",
                classification_level="UNCLASSIFIED",
                requires_clearance=False
            )
        ]
        
        # Test access with UNCLASSIFIED clearance
        filtered = self.dashboard._filter_metrics_by_clearance(metrics, "UNCLASSIFIED")
        self.assertEqual(len(filtered), 1)
        
        # Test access with higher clearance
        filtered = self.dashboard._filter_metrics_by_clearance(metrics, "SECRET")
        self.assertEqual(len(filtered), 1)
    
    def test_confidential_data_access_control(self):
        """Test access control for confidential data."""
        # Create confidential metrics
        metrics = [
            ComplianceMetric(
                metric_type=ComplianceMetricType.CLASSIFICATION_COMPLIANCE,
                metric_name="Confidential Metric",
                classification_level="CONFIDENTIAL",
                requires_clearance=True
            )
        ]
        
        # Test access with insufficient clearance
        filtered = self.dashboard._filter_metrics_by_clearance(metrics, "UNCLASSIFIED")
        self.assertEqual(len(filtered), 0)
        
        # Test access with sufficient clearance
        filtered = self.dashboard._filter_metrics_by_clearance(metrics, "CONFIDENTIAL")
        self.assertEqual(len(filtered), 1)
        
        # Test access with higher clearance
        filtered = self.dashboard._filter_metrics_by_clearance(metrics, "SECRET")
        self.assertEqual(len(filtered), 1)
    
    def test_secret_data_access_control(self):
        """Test access control for secret data."""
        # Create secret metrics
        metrics = [
            ComplianceMetric(
                metric_type=ComplianceMetricType.SECURITY_MONITORING,
                metric_name="Secret Metric",
                classification_level="SECRET",
                requires_clearance=True
            )
        ]
        
        # Test access with insufficient clearances
        filtered = self.dashboard._filter_metrics_by_clearance(metrics, "UNCLASSIFIED")
        self.assertEqual(len(filtered), 0)
        
        filtered = self.dashboard._filter_metrics_by_clearance(metrics, "CONFIDENTIAL")
        self.assertEqual(len(filtered), 0)
        
        # Test access with sufficient clearance
        filtered = self.dashboard._filter_metrics_by_clearance(metrics, "SECRET")
        self.assertEqual(len(filtered), 1)
    
    def test_top_secret_data_access_control(self):
        """Test access control for top secret data."""
        # Create top secret metrics
        metrics = [
            ComplianceMetric(
                metric_type=ComplianceMetricType.THREAT_DETECTION,
                metric_name="Top Secret Metric",
                classification_level="TOP_SECRET",
                requires_clearance=True
            )
        ]
        
        # Test access with insufficient clearances
        for clearance in ["UNCLASSIFIED", "CONFIDENTIAL", "SECRET"]:
            filtered = self.dashboard._filter_metrics_by_clearance(metrics, clearance)
            self.assertEqual(len(filtered), 0, f"Clearance {clearance} should not access TOP_SECRET")
        
        # Test access with sufficient clearance
        filtered = self.dashboard._filter_metrics_by_clearance(metrics, "TOP_SECRET")
        self.assertEqual(len(filtered), 1)
    
    def test_mixed_classification_filtering(self):
        """Test filtering with mixed classification levels."""
        # Create metrics with various classification levels
        metrics = [
            ComplianceMetric(
                metric_name="Unclassified 1",
                classification_level="UNCLASSIFIED",
                requires_clearance=False
            ),
            ComplianceMetric(
                metric_name="Unclassified 2",
                classification_level="UNCLASSIFIED",
                requires_clearance=False
            ),
            ComplianceMetric(
                metric_name="Confidential 1",
                classification_level="CONFIDENTIAL",
                requires_clearance=True
            ),
            ComplianceMetric(
                metric_name="Secret 1",
                classification_level="SECRET",
                requires_clearance=True
            ),
            ComplianceMetric(
                metric_name="Top Secret 1",
                classification_level="TOP_SECRET",
                requires_clearance=True
            )
        ]
        
        # Test with CONFIDENTIAL clearance
        filtered = self.dashboard._filter_metrics_by_clearance(metrics, "CONFIDENTIAL")
        self.assertEqual(len(filtered), 3)  # UNCLASSIFIED (2) + CONFIDENTIAL (1)
        
        # Verify correct metrics are included
        classification_levels = [m.classification_level for m in filtered]
        self.assertIn("UNCLASSIFIED", classification_levels)
        self.assertIn("CONFIDENTIAL", classification_levels)
        self.assertNotIn("SECRET", classification_levels)
        self.assertNotIn("TOP_SECRET", classification_levels)


class TestRBACIntegration(unittest.TestCase):
    """Test RBAC integration and access control."""
    
    def setUp(self):
        """Set up RBAC test fixtures."""
        self.mock_rbac_controller = Mock()
        self.mock_data_provider = Mock()
        
        self.dashboard_config = DashboardConfiguration(
            name="RBAC Test Dashboard",
            dashboard_type=DashboardType.OPERATIONAL
        )
        
        self.dashboard = ComplianceDashboard(
            self.dashboard_config,
            self.mock_data_provider,
            self.mock_rbac_controller
        )
    
    @pytest.mark.asyncio
    async def test_user_authentication_validation(self):
        """Test user authentication validation."""
        # Mock successful authentication
        self.mock_rbac_controller.validate_user_session.return_value = True
        self.mock_rbac_controller.get_user_permissions.return_value = ["read_dashboard"]
        
        # Test successful authentication
        result = await self.dashboard._validate_user_access("test_user", "test_session")
        self.assertTrue(result)
        
        # Mock failed authentication
        self.mock_rbac_controller.validate_user_session.return_value = False
        
        # Test failed authentication
        result = await self.dashboard._validate_user_access("test_user", "invalid_session")
        self.assertFalse(result)
    
    @pytest.mark.asyncio
    async def test_permission_based_access_control(self):
        """Test permission-based access control."""
        # Test user with dashboard read permissions
        self.mock_rbac_controller.validate_user_session.return_value = True
        self.mock_rbac_controller.get_user_permissions.return_value = ["read_dashboard", "view_metrics"]
        
        has_access = await self.dashboard._check_dashboard_permissions("test_user", "read")
        self.assertTrue(has_access)
        
        # Test user without dashboard permissions
        self.mock_rbac_controller.get_user_permissions.return_value = ["other_permission"]
        
        has_access = await self.dashboard._check_dashboard_permissions("test_user", "read")
        self.assertFalse(has_access)
    
    @pytest.mark.asyncio
    async def test_role_based_metric_access(self):
        """Test role-based metric access control."""
        # Mock user roles
        self.mock_rbac_controller.get_user_roles.return_value = ["security_analyst"]
        
        # Create role-specific metrics
        metrics = [
            ComplianceMetric(
                metric_name="General Metric",
                allowed_roles=["analyst", "security_analyst", "admin"]
            ),
            ComplianceMetric(
                metric_name="Admin Only Metric",
                allowed_roles=["admin"]
            ),
            ComplianceMetric(
                metric_name="Public Metric",
                allowed_roles=[]  # Empty list means accessible to all
            )
        ]
        
        # Filter metrics by user roles
        filtered = self.dashboard._filter_metrics_by_role(metrics, ["security_analyst"])
        
        # Should have access to general and public metrics, but not admin-only
        self.assertEqual(len(filtered), 2)
        metric_names = [m.metric_name for m in filtered]
        self.assertIn("General Metric", metric_names)
        self.assertIn("Public Metric", metric_names)
        self.assertNotIn("Admin Only Metric", metric_names)
    
    def test_clearance_hierarchy_validation(self):
        """Test clearance level hierarchy validation."""
        test_cases = [
            ("UNCLASSIFIED", "CONFIDENTIAL", True),
            ("CONFIDENTIAL", "SECRET", True),
            ("SECRET", "TOP_SECRET", True),
            ("CONFIDENTIAL", "UNCLASSIFIED", False),
            ("SECRET", "CONFIDENTIAL", False),
            ("TOP_SECRET", "SECRET", False),
            ("SECRET", "SECRET", True),  # Same level should be allowed
        ]
        
        for user_clearance, required_clearance, expected in test_cases:
            result = self.dashboard._validate_clearance_level(user_clearance, required_clearance)
            self.assertEqual(
                result, expected,
                f"User clearance {user_clearance} accessing {required_clearance} should be {expected}"
            )


class TestSecurityIncidentResponse(unittest.TestCase):
    """Test security incident response and alerting."""
    
    def setUp(self):
        """Set up security incident test fixtures."""
        self.mock_data_provider = Mock()
        self.mock_data_warehouse = Mock()
        self.mock_audit_orchestrator = Mock()
        self.mock_monitoring_system = Mock() 
        self.mock_real_time_alerting = Mock()
        
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
    async def test_security_alert_escalation(self):
        """Test security alert escalation procedures."""
        # Create high-severity security alert
        alert = ComplianceAlert(
            title="Security Breach Detected",
            message="Unauthorized access attempt detected",
            alert_type=AlertType.SECURITY_INCIDENT,
            severity=AlertSeverity.CRITICAL,
            classification_level="SECRET"
        )
        
        # Test escalation
        await self.alert_system._escalate_alert(alert)
        
        # Verify escalation actions
        self.mock_real_time_alerting.send_alert.assert_called()
        call_args = self.mock_real_time_alerting.send_alert.call_args
        
        self.assertIn("security_incident", call_args[1]["alert_type"])
        self.assertIn("critical", call_args[1]["severity"])
    
    @pytest.mark.asyncio
    async def test_classification_violation_alert(self):
        """Test classification violation alerting."""
        # Create classification violation alert
        alert = ComplianceAlert(
            title="Classification Violation",
            message="Attempted access to classified data without proper clearance",
            alert_type=AlertType.COMPLIANCE_VIOLATION,
            severity=AlertSeverity.HIGH,
            additional_data={
                "user_clearance": "CONFIDENTIAL",
                "attempted_access": "SECRET",
                "user_id": "test_user"
            }
        )
        
        # Add to active alerts
        self.alert_system.active_alerts[alert.alert_id] = alert
        
        # Test alert processing
        await self.alert_system._process_classification_violation(alert)
        
        # Verify security response
        self.assertIn(alert.alert_id, self.alert_system.security_incidents)
        self.assertEqual(alert.status, AlertStatus.ESCALATED)
    
    @pytest.mark.asyncio
    async def test_audit_trail_generation(self):
        """Test audit trail generation for security events."""
        # Create security event
        event_data = {
            "event_type": "unauthorized_access_attempt",
            "user_id": "test_user",
            "resource": "classified_dashboard",
            "timestamp": datetime.now(timezone.utc),
            "classification_level": "SECRET"
        }
        
        # Test audit trail generation
        audit_entry = await self.alert_system._generate_audit_trail(event_data)
        
        # Verify audit entry
        self.assertIsInstance(audit_entry, dict)
        self.assertIn("audit_id", audit_entry)
        self.assertIn("event_type", audit_entry)
        self.assertIn("timestamp", audit_entry)
        self.assertIn("classification_level", audit_entry)
        self.assertEqual(audit_entry["event_type"], "unauthorized_access_attempt")


class TestDataEncryptionAndProtection(unittest.TestCase):
    """Test data encryption and protection mechanisms."""
    
    def setUp(self):
        """Set up encryption test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        
        # Mock components
        self.mock_data_provider = Mock()
        self.mock_audit_orchestrator = Mock()
        self.mock_monitoring_system = Mock()
        
        # Create test data warehouse with encryption
        from .data.compliance_data_warehouse import ComplianceDataWarehouse
        self.data_warehouse = ComplianceDataWarehouse(
            self.mock_data_provider,
            self.mock_audit_orchestrator,
            self.mock_monitoring_system,
            database_path=f"{self.temp_dir}/encrypted_test.db",
            enable_encryption=True
        )
    
    def tearDown(self):
        """Clean up encryption test fixtures."""
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    @pytest.mark.asyncio
    async def test_classified_data_encryption(self):
        """Test encryption of classified data."""
        await self.data_warehouse.initialize()
        
        # Create classified metric
        from .data.compliance_data_warehouse import HistoricalMetricPoint
        from .dashboards.compliance_dashboard import ComplianceMetricType
        
        classified_metric = HistoricalMetricPoint(
            metric_type=ComplianceMetricType.CLASSIFICATION_COMPLIANCE,
            metric_name="Classified Test Metric",
            value=95.0,
            classification_level="SECRET",
            requires_encryption=True
        )
        
        # Store encrypted data
        await self.data_warehouse.db_manager.store_historical_metric(classified_metric)
        
        # Verify data was encrypted (by checking it's not readable as plain text)
        db_path = Path(f"{self.temp_dir}/encrypted_test.db")
        self.assertTrue(db_path.exists())
        
        # Raw database content should not contain plain text metric name
        with open(db_path, 'rb') as f:
            raw_content = f.read()
            self.assertNotIn(b"Classified Test Metric", raw_content)
    
    def test_encryption_key_management(self):
        """Test encryption key management."""
        # Test key generation
        key = self.data_warehouse._generate_encryption_key()
        self.assertIsInstance(key, bytes)
        self.assertEqual(len(key), 32)  # 256-bit key
        
        # Test key derivation
        derived_key = self.data_warehouse._derive_key_from_passphrase("test_passphrase")
        self.assertIsInstance(derived_key, bytes)
        self.assertEqual(len(derived_key), 32)
    
    def test_data_encryption_decryption(self):
        """Test data encryption and decryption functionality."""
        # Test data
        sensitive_data = "This is classified information that must be encrypted"
        
        # Encrypt data
        encrypted_data = self.data_warehouse._encrypt_sensitive_data(sensitive_data)
        self.assertNotEqual(encrypted_data, sensitive_data)
        self.assertIsInstance(encrypted_data, str)
        
        # Decrypt data
        decrypted_data = self.data_warehouse._decrypt_sensitive_data(encrypted_data)
        self.assertEqual(decrypted_data, sensitive_data)


class TestComplianceAuditTrail(unittest.TestCase):
    """Test compliance audit trail functionality."""
    
    def setUp(self):
        """Set up audit trail test fixtures."""
        self.mock_audit_orchestrator = Mock()
        self.mock_monitoring_system = Mock()
        self.mock_log_aggregator = Mock()
        self.mock_real_time_alerting = Mock()
        
        # Mock async methods
        self.mock_audit_orchestrator.log_audit_event = AsyncMock()
        
        self.integration_layer = ComplianceIntegrationLayer(
            self.mock_audit_orchestrator,
            self.mock_monitoring_system,
            self.mock_log_aggregator,
            self.mock_real_time_alerting
        )
    
    @pytest.mark.asyncio
    async def test_dashboard_access_audit(self):
        """Test auditing of dashboard access events."""
        await self.integration_layer.initialize()
        
        # Simulate dashboard access
        access_event = {
            "event_type": "dashboard_access",
            "user_id": "test_user",
            "dashboard_type": "executive",
            "clearance_level": "SECRET",
            "timestamp": datetime.now(timezone.utc),
            "ip_address": "192.168.1.100",
            "session_id": "test_session"
        }
        
        # Test audit logging
        await self.integration_layer._log_compliance_event(access_event)
        
        # Verify audit event was logged
        self.mock_audit_orchestrator.log_audit_event.assert_called()
        call_args = self.mock_audit_orchestrator.log_audit_event.call_args[0][0]
        
        self.assertEqual(call_args.action, "dashboard_access")
        self.assertEqual(call_args.user_id, "test_user")
        self.assertIn("executive", call_args.additional_data["dashboard_type"])
    
    @pytest.mark.asyncio
    async def test_report_generation_audit(self):
        """Test auditing of report generation events."""
        await self.integration_layer.initialize()
        
        # Simulate report generation
        report_event = {
            "event_type": "report_generated",
            "user_id": "test_user",
            "report_type": "executive_summary",
            "report_format": "PDF",
            "classification_level": "CONFIDENTIAL",
            "timestamp": datetime.now(timezone.utc)
        }
        
        # Test audit logging
        await self.integration_layer._log_compliance_event(report_event)
        
        # Verify audit event was logged
        self.mock_audit_orchestrator.log_audit_event.assert_called()
        call_args = self.mock_audit_orchestrator.log_audit_event.call_args[0][0]
        
        self.assertEqual(call_args.action, "report_generated")
        self.assertIn("executive_summary", call_args.additional_data["report_type"])
    
    @pytest.mark.asyncio
    async def test_alert_acknowledgment_audit(self):
        """Test auditing of alert acknowledgment events."""
        await self.integration_layer.initialize()
        
        # Simulate alert acknowledgment
        ack_event = {
            "event_type": "alert_acknowledged",
            "user_id": "security_analyst",
            "alert_id": "test_alert_123",
            "alert_severity": "HIGH",
            "acknowledgment_notes": "Investigating security incident",
            "timestamp": datetime.now(timezone.utc)
        }
        
        # Test audit logging
        await self.integration_layer._log_compliance_event(ack_event)
        
        # Verify audit event was logged
        self.mock_audit_orchestrator.log_audit_event.assert_called()
        call_args = self.mock_audit_orchestrator.log_audit_event.call_args[0][0]
        
        self.assertEqual(call_args.action, "alert_acknowledged")
        self.assertEqual(call_args.user_id, "security_analyst")
        self.assertIn("HIGH", call_args.additional_data["alert_severity"])


class TestSecurityCompliance(unittest.TestCase):
    """Test overall security compliance and validation."""
    
    def setUp(self):
        """Set up security compliance test fixtures."""
        self.mock_components = {
            'audit_orchestrator': Mock(),
            'monitoring_system': Mock(),
            'log_aggregator': Mock(),
            'real_time_alerting': Mock()
        }
        
        # Mock async methods
        for component in self.mock_components.values():
            component.health_check = AsyncMock(return_value={"status": "healthy"})
    
    @pytest.mark.asyncio
    async def test_end_to_end_security_validation(self):
        """Test end-to-end security validation workflow."""
        integration_layer = ComplianceIntegrationLayer(**self.mock_components)
        await integration_layer.initialize()
        await integration_layer.start()
        
        try:
            # Test 1: Validate user access with appropriate clearance
            security_event = {
                "user_id": "test_user",
                "clearance_level": "SECRET",
                "requested_access": "classified_dashboard",
                "classification_requirement": "CONFIDENTIAL"
            }
            
            access_granted = await integration_layer._validate_security_access(security_event)
            self.assertTrue(access_granted)
            
            # Test 2: Deny access with insufficient clearance
            security_event["clearance_level"] = "UNCLASSIFIED"
            security_event["classification_requirement"] = "SECRET"
            
            access_granted = await integration_layer._validate_security_access(security_event)
            self.assertFalse(access_granted)
            
            # Test 3: Validate audit trail generation
            audit_events = await integration_layer._get_security_audit_events()
            self.assertIsInstance(audit_events, list)
            
            # Test 4: Validate security health status
            security_health = await integration_layer._get_security_health_status()
            self.assertIn("classification_enforcement", security_health)
            self.assertIn("access_control", security_health)
            self.assertIn("audit_compliance", security_health)
            
        finally:
            await integration_layer.stop()
    
    def test_security_configuration_validation(self):
        """Test security configuration validation."""
        # Test valid security configuration
        valid_config = {
            "encryption_enabled": True,
            "classification_enforcement": True,
            "audit_logging": True,
            "access_control": True,
            "clearance_validation": True
        }
        
        result = self._validate_security_configuration(valid_config)
        self.assertTrue(result["valid"])
        self.assertEqual(len(result["violations"]), 0)
        
        # Test invalid security configuration
        invalid_config = {
            "encryption_enabled": False,
            "classification_enforcement": False,
            "audit_logging": True,
            "access_control": False,
            "clearance_validation": True
        }
        
        result = self._validate_security_configuration(invalid_config)
        self.assertFalse(result["valid"])
        self.assertGreater(len(result["violations"]), 0)
    
    def _validate_security_configuration(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Validate security configuration."""
        violations = []
        required_settings = [
            "encryption_enabled",
            "classification_enforcement", 
            "access_control",
            "clearance_validation"
        ]
        
        for setting in required_settings:
            if not config.get(setting, False):
                violations.append(f"Security setting '{setting}' must be enabled")
        
        return {
            "valid": len(violations) == 0,
            "violations": violations,
            "config": config
        }


# Security test runner
def run_security_tests():
    """Run all security validation tests."""
    print("Running Security Validation Tests...")
    print("=" * 50)
    
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Create test suite
    test_suite = unittest.TestSuite()
    
    # Add security test cases
    security_test_classes = [
        TestClassificationEnforcement,
        TestRBACIntegration,
        TestSecurityIncidentResponse,
        TestDataEncryptionAndProtection,  
        TestComplianceAuditTrail,
        TestSecurityCompliance
    ]
    
    for test_class in security_test_classes:
        tests = unittest.TestLoader().loadTestsFromTestCase(test_class)
        test_suite.addTests(tests)
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(test_suite)
    
    # Print security test summary
    print("\n" + "=" * 50)
    print("Security Validation Summary:")
    print(f"Total Security Tests: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    
    if result.failures or result.errors:
        print("\nSECURITY VALIDATION FAILED!")
        print("The system does not meet security compliance requirements.")
        return False
    else:
        print("\n✓ ALL SECURITY VALIDATIONS PASSED")
        print("The system meets all security compliance requirements.")
        return True


if __name__ == "__main__":
    success = run_security_tests()
    exit(0 if success else 1)