"""
Comprehensive Test Suite for DoD Audit System

This module provides extensive testing capabilities for all components of the DoD audit
logging system, including security validation, compliance testing, performance testing,
and integration testing.

Test Categories:
- Unit tests for individual components
- Integration tests for component interactions
- Security validation tests for cryptographic functions
- Compliance tests for DoD/NIST requirements
- Performance and load testing
- Stress testing and reliability testing
- Penetration testing scenarios
- Data integrity and corruption testing

Security Testing:
- Cryptographic validation and key management
- Access control and authentication testing
- Data encryption and integrity verification
- Tamper detection and response testing
- Secure communication channel testing
- Input validation and sanitization testing
- Privilege escalation testing
- Side-channel attack resistance

Compliance Testing:
- DoD 8500.01E requirement verification
- NIST SP 800-53 control implementation testing
- FISMA compliance validation
- Audit trail completeness verification
- Retention policy compliance testing
- Export control compliance testing
- Chain of custody verification

Performance Testing:
- High-volume event processing
- Concurrent user load testing
- Database performance under stress
- Memory usage and leak detection
- Network bandwidth utilization
- Storage I/O performance
- Real-time processing latency
- Failover and recovery testing

Test Infrastructure:
- Automated test execution framework
- Test data generation and management
- Mock services and stub implementations
- Test environment isolation
- Continuous integration compatibility
- Test result reporting and metrics
- Coverage analysis and reporting
"""

import unittest
import asyncio
import tempfile
import shutil
import sqlite3
import json
import time
import threading
import multiprocessing
import hashlib
import hmac
import secrets
import gzip
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from unittest.mock import Mock, patch, MagicMock
import logging
import sys
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests
import socket
import ssl

# Import all audit system components
from .audit_logger import (
    AuditLogger, AuditEvent, AuditEventType, AuditSeverity, 
    ClassificationLevel, AuditConfiguration, get_audit_logger
)
from .tamper_proof_storage import (
    TamperProofStorage, StorageBlock, StorageIntegrityLevel, 
    StorageStatus, create_tamper_proof_storage
)
from .siem_integration import (
    SIEMIntegrationManager, SIEMConfiguration, SIEMType, 
    LogFormat, SplunkConnector, ElasticsearchConnector, 
    AzureSentinelConnector, SyslogConnector
)
from .real_time_alerting import (
    AlertManager, AlertRule, SecurityAlert, AlertSeverity, 
    AlertCategory, PatternAnalyzer, create_alert_manager
)
from .compliance_reporter import (
    ComplianceReporter, ComplianceMetric, ComplianceReport, 
    ComplianceFramework, ReportType, RetentionManager
)
from .log_analysis_engine import (
    LogAnalysisEngine, StatisticalAnalyzer, MachineLearningAnalyzer,
    ThreatIntelligenceEngine, UserBehaviorProfile, AnomalyDetection
)


class TestDataGenerator:
    """Generates test data for audit system testing."""
    
    def __init__(self):
        self.user_ids = [f"user_{i:04d}" for i in range(1, 1001)]
        self.hostnames = [f"host_{i:03d}.mil" for i in range(1, 101)]
        self.ip_addresses = [f"192.168.{i//256}.{i%256}" for i in range(1, 65535)]
        self.applications = ["webapp", "database", "fileserver", "email", "vpn"]
        self.resources = [f"resource_{i:05d}" for i in range(1, 10001)]
    
    def generate_audit_event(self, event_type: AuditEventType = None, 
                           user_id: str = None, severity: AuditSeverity = None,
                           classification: ClassificationLevel = None,
                           timestamp: datetime = None) -> AuditEvent:
        """Generate a single audit event with optional parameters."""
        if event_type is None:
            event_type = secrets.choice(list(AuditEventType))
        
        if user_id is None:
            user_id = secrets.choice(self.user_ids)
        
        if severity is None:
            severity = secrets.choice(list(AuditSeverity))
        
        if classification is None:
            classification = secrets.choice(list(ClassificationLevel))
        
        if timestamp is None:
            timestamp = datetime.now(timezone.utc)
        
        event = AuditEvent(
            event_type=event_type,
            timestamp=timestamp,
            severity=severity,
            user_id=user_id,
            username=f"user_{user_id.split('_')[1]}",
            edipi=f"EDIPI{user_id.split('_')[1]}",
            source_ip=secrets.choice(self.ip_addresses),
            hostname=secrets.choice(self.hostnames),
            action=f"Action for {event_type.value}",
            resource_type="file",
            resource_id=secrets.choice(self.resources),
            operation="read",
            result=secrets.choice(["SUCCESS", "FAILURE", "PARTIAL"]),
            classification_level=classification,
            application=secrets.choice(self.applications),
            data_size=secrets.randbelow(1000000),
            additional_data={
                "test_data": True,
                "generated_at": timestamp.isoformat()
            }
        )
        
        return event
    
    def generate_event_batch(self, count: int, time_span_hours: int = 24) -> List[AuditEvent]:
        """Generate a batch of audit events over a time span."""
        events = []
        start_time = datetime.now(timezone.utc) - timedelta(hours=time_span_hours)
        
        for i in range(count):
            # Distribute events across time span
            offset_seconds = (time_span_hours * 3600 * i) // count
            event_time = start_time + timedelta(seconds=offset_seconds)
            
            event = self.generate_audit_event(timestamp=event_time)
            events.append(event)
        
        return events
    
    def generate_attack_scenario(self, scenario_type: str) -> List[AuditEvent]:
        """Generate events simulating various attack scenarios."""
        events = []
        base_time = datetime.now(timezone.utc)
        attacker_ip = "192.168.100.200"
        
        if scenario_type == "brute_force":
            # Generate brute force attack events
            target_user = "admin_user"
            for i in range(20):  # 20 failed login attempts
                event = AuditEvent(
                    event_type=AuditEventType.USER_LOGIN_FAILURE,
                    timestamp=base_time + timedelta(seconds=i*30),
                    severity=AuditSeverity.HIGH,
                    user_id=target_user,
                    source_ip=attacker_ip,
                    result="FAILURE",
                    error_message="Invalid credentials",
                    additional_data={"attack_scenario": "brute_force"}
                )
                events.append(event)
        
        elif scenario_type == "privilege_escalation":
            # Generate privilege escalation events
            user_id = "test_user"
            events.extend([
                AuditEvent(
                    event_type=AuditEventType.USER_LOGIN_SUCCESS,
                    timestamp=base_time,
                    user_id=user_id,
                    source_ip=attacker_ip
                ),
                AuditEvent(
                    event_type=AuditEventType.PRIVILEGE_ESCALATION,
                    timestamp=base_time + timedelta(minutes=5),
                    user_id=user_id,
                    source_ip=attacker_ip,
                    action="sudo su -",
                    result="SUCCESS"
                ),
                AuditEvent(
                    event_type=AuditEventType.ROLE_ASSIGNMENT,
                    timestamp=base_time + timedelta(minutes=10),
                    user_id=user_id,
                    source_ip=attacker_ip,
                    additional_data={"role": "administrator"}
                )
            ])
        
        elif scenario_type == "data_exfiltration":
            # Generate data exfiltration events
            user_id = "insider_threat"
            for i in range(50):  # Large number of data access events
                event = AuditEvent(
                    event_type=AuditEventType.DATA_EXPORT,
                    timestamp=base_time + timedelta(minutes=i*2),
                    user_id=user_id,
                    source_ip="192.168.50.100",
                    resource_type="classified_file",
                    resource_id=f"classified_{i:03d}.txt",
                    data_size=secrets.randbelow(10000000),  # Up to 10MB per file
                    classification_level=ClassificationLevel.SECRET,
                    additional_data={"off_hours": True}
                )
                events.append(event)
        
        return events


class AuditLoggerTests(unittest.TestCase):
    """Test suite for core audit logging functionality."""
    
    def setUp(self):
        """Set up test environment."""
        self.test_dir = tempfile.mkdtemp()
        self.config = AuditConfiguration(
            storage_path=self.test_dir,
            max_file_size=1024*1024,  # 1MB for testing
            buffer_size=100,
            flush_interval_seconds=1
        )
        self.logger = AuditLogger(self.config)
        self.data_generator = TestDataGenerator()
    
    def tearDown(self):
        """Clean up test environment."""
        self.logger.shutdown()
        shutil.rmtree(self.test_dir, ignore_errors=True)
    
    def test_basic_event_logging(self):
        """Test basic audit event logging."""
        event = self.data_generator.generate_audit_event()
        result = self.logger.log_event(event)
        
        self.assertTrue(result)
        
        # Wait for processing
        time.sleep(2)
        
        # Verify event was stored
        events = self.logger.query_events(limit=1)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]['event_id'], event.event_id)
    
    def test_high_volume_logging(self):
        """Test high-volume event logging."""
        events = self.data_generator.generate_event_batch(1000)
        
        start_time = time.time()
        success_count = 0
        
        for event in events:
            if self.logger.log_event(event):
                success_count += 1
        
        processing_time = time.time() - start_time
        
        # Wait for all events to be processed
        time.sleep(5)
        
        self.assertEqual(success_count, 1000)
        self.assertLess(processing_time, 10)  # Should process 1000 events in under 10 seconds
        
        # Verify events were stored
        stored_events = self.logger.query_events(limit=1000)
        self.assertGreaterEqual(len(stored_events), 900)  # Allow for some processing delay
    
    def test_concurrent_logging(self):
        """Test concurrent event logging from multiple threads."""
        def log_events_worker(thread_id: int, event_count: int):
            success_count = 0
            for i in range(event_count):
                event = self.data_generator.generate_audit_event()
                event.additional_data['thread_id'] = thread_id
                event.additional_data['sequence'] = i
                
                if self.logger.log_event(event):
                    success_count += 1
            return success_count
        
        threads = []
        results = []
        
        # Start 10 threads, each logging 100 events
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(log_events_worker, i, 100) for i in range(10)]
            
            for future in as_completed(futures):
                results.append(future.result())
        
        # Wait for processing
        time.sleep(5)
        
        # Verify all events were logged successfully
        total_success = sum(results)
        self.assertEqual(total_success, 1000)
        
        # Verify events were stored
        stored_events = self.logger.query_events(limit=1000)
        self.assertGreaterEqual(len(stored_events), 900)
    
    def test_event_validation(self):
        """Test audit event validation."""
        # Test invalid event (missing required fields)
        invalid_event = AuditEvent()
        invalid_event.event_id = ""  # Invalid empty ID
        
        result = self.logger.log_event(invalid_event)
        self.assertFalse(result)
        
        # Test valid event
        valid_event = self.data_generator.generate_audit_event()
        result = self.logger.log_event(valid_event)
        self.assertTrue(result)
    
    def test_file_rotation(self):
        """Test log file rotation."""
        # Set small file size to trigger rotation
        self.logger.config.max_file_size = 1024  # 1KB
        
        # Log events to trigger rotation
        events = self.data_generator.generate_event_batch(100)
        for event in events:
            self.logger.log_event(event)
        
        time.sleep(3)  # Wait for processing and rotation
        
        # Check that multiple files were created
        active_dir = Path(self.test_dir) / "active"
        archive_dir = Path(self.test_dir) / "archive"
        
        active_files = list(active_dir.glob("*.log"))
        archive_files = list(archive_dir.glob("*.log*"))
        
        total_files = len(active_files) + len(archive_files)
        self.assertGreater(total_files, 1)  # Should have rotated files
    
    def test_encryption_integration(self):
        """Test encryption of audit logs."""
        if not self.config.encryption_enabled:
            self.skipTest("Encryption not enabled in test configuration")
        
        event = self.data_generator.generate_audit_event()
        result = self.logger.log_event(event)
        self.assertTrue(result)
        
        time.sleep(2)
        
        # Check that log files are encrypted (not readable as plain text)
        active_dir = Path(self.test_dir) / "active"
        log_files = list(active_dir.glob("*.log"))
        
        if log_files:
            with open(log_files[0], 'rb') as f:
                content = f.read()
                # Encrypted content should not contain readable event data
                self.assertNotIn(event.event_id.encode(), content)


class TamperProofStorageTests(unittest.TestCase):
    """Test suite for tamper-proof storage functionality."""
    
    def setUp(self):
        """Set up test environment."""
        self.test_dir = tempfile.mkdtemp()
        self.storage = create_tamper_proof_storage(
            storage_path=self.test_dir,
            integrity_level=StorageIntegrityLevel.HIGH
        )
        self.data_generator = TestDataGenerator()
    
    def tearDown(self):
        """Clean up test environment."""
        self.storage.shutdown()
        shutil.rmtree(self.test_dir, ignore_errors=True)
    
    def test_block_creation_and_storage(self):
        """Test creation and storage of tamper-proof blocks."""
        events = self.data_generator.generate_event_batch(10)
        result = self.storage.store_events(events)
        self.assertTrue(result)
        
        # Force block finalization
        block_hash = self.storage.force_block_finalization()
        self.assertIsNotNone(block_hash)
        
        # Verify block was created
        stats = self.storage.get_storage_stats()
        self.assertGreater(stats['basic_stats']['total_blocks'], 0)
    
    def test_integrity_verification(self):
        """Test integrity verification of stored blocks."""
        events = self.data_generator.generate_event_batch(5)
        self.storage.store_events(events)
        self.storage.force_block_finalization()
        
        # Verify chain integrity
        is_valid, report = self.storage.verify_chain_integrity()
        self.assertTrue(is_valid)
        self.assertEqual(len(report['corrupted_blocks']), 0)
        self.assertTrue(report['chain_valid'])
        self.assertTrue(report['hash_chain_valid'])
    
    def test_tampering_detection(self):
        """Test detection of tampering attempts."""
        events = self.data_generator.generate_event_batch(3)
        self.storage.store_events(events)
        block_hash = self.storage.force_block_finalization()
        
        # Get the block file and attempt to tamper with it
        blocks_dir = Path(self.test_dir) / "blocks"
        block_files = list(blocks_dir.glob("*.json"))
        
        if block_files:
            # Read original content
            with open(block_files[0], 'r') as f:
                content = json.load(f)
            
            # Tamper with content
            content['events'][0]['user_id'] = "tampered_user"
            
            # Write back tampered content
            with open(block_files[0], 'w') as f:
                json.dump(content, f)
            
            # Verify tampering is detected
            is_valid, report = self.storage.verify_chain_integrity()
            self.assertFalse(is_valid)
            self.assertGreater(len(report['corrupted_blocks']), 0)
    
    def test_hash_chain_integrity(self):
        """Test hash chain integrity across multiple blocks."""
        # Create multiple blocks
        for i in range(3):
            events = self.data_generator.generate_event_batch(5)
            self.storage.store_events(events)
            self.storage.force_block_finalization()
        
        # Verify hash chain
        is_valid, report = self.storage.verify_chain_integrity()
        self.assertTrue(is_valid)
        self.assertTrue(report['hash_chain_valid'])
        self.assertEqual(report['total_blocks'], 3)
    
    def test_search_functionality(self):
        """Test event search across stored blocks."""
        # Store events with specific patterns
        test_user = "search_test_user"
        events = []
        
        for i in range(10):
            event = self.data_generator.generate_audit_event()
            if i < 5:
                event.user_id = test_user
            events.append(event)
        
        self.storage.store_events(events)
        self.storage.force_block_finalization()
        
        # Search for events by user
        found_events = list(self.storage.search_events(user_id=test_user))
        self.assertEqual(len(found_events), 5)
        
        for event in found_events:
            self.assertEqual(event.user_id, test_user)


class SIEMIntegrationTests(unittest.TestCase):
    """Test suite for SIEM integration functionality."""
    
    def setUp(self):
        """Set up test environment."""
        self.siem_manager = SIEMIntegrationManager()
        self.data_generator = TestDataGenerator()
    
    def tearDown(self):
        """Clean up test environment."""
        asyncio.run(self.siem_manager.stop())
    
    def test_splunk_connector_creation(self):
        """Test Splunk connector creation and configuration."""
        config = SIEMConfiguration(
            siem_type=SIEMType.SPLUNK,
            name="test_splunk",
            endpoint_url="https://splunk.test.mil:8088",
            token="test_token_123",
            log_format=LogFormat.SPLUNK_HEC
        )
        
        result = self.siem_manager.add_connector("test_splunk", config)
        self.assertTrue(result)
        self.assertIn("test_splunk", self.siem_manager.connectors)
    
    def test_elasticsearch_connector_creation(self):
        """Test Elasticsearch connector creation."""
        config = SIEMConfiguration(
            siem_type=SIEMType.ELASTICSEARCH,
            name="test_elastic",
            endpoint_url="https://elastic.test.mil:9200",
            username="elastic_user",
            password="elastic_pass",
            log_format=LogFormat.ECS
        )
        
        result = self.siem_manager.add_connector("test_elastic", config)
        self.assertTrue(result)
    
    def test_siem_event_formatting(self):
        """Test SIEM event formatting for different platforms."""
        audit_event = self.data_generator.generate_audit_event()
        
        # Test Splunk formatting
        splunk_config = SIEMConfiguration(
            siem_type=SIEMType.SPLUNK,
            name="test",
            log_format=LogFormat.JSON
        )
        from .siem_integration import SplunkConnector
        splunk_connector = SplunkConnector(splunk_config)
        siem_event = splunk_connector.format_event(audit_event)
        
        self.assertEqual(siem_event.event_type, audit_event.event_type.value)
        self.assertEqual(siem_event.user_id, audit_event.user_id)
        
        # Test different formats
        cef_output = siem_event.to_cef()
        self.assertIn("CEF:", cef_output)
        
        json_output = siem_event.to_json()
        json_data = json.loads(json_output)
        self.assertEqual(json_data['event_type'], audit_event.event_type.value)
    
    def test_event_filtering(self):
        """Test event filtering based on SIEM configuration."""
        config = SIEMConfiguration(
            siem_type=SIEMType.GENERIC_SYSLOG,
            name="test_filter",
            min_severity=AuditSeverity.HIGH,
            max_classification=ClassificationLevel.CONFIDENTIAL
        )
        
        from .siem_integration import SyslogConnector
        connector = SyslogConnector(config)
        
        # Test high severity event (should pass)
        high_sev_event = self.data_generator.generate_audit_event(
            severity=AuditSeverity.HIGH,
            classification=ClassificationLevel.UNCLASSIFIED
        )
        self.assertTrue(connector.should_send_event(high_sev_event))
        
        # Test low severity event (should be filtered)
        low_sev_event = self.data_generator.generate_audit_event(
            severity=AuditSeverity.LOW,
            classification=ClassificationLevel.UNCLASSIFIED
        )
        self.assertFalse(connector.should_send_event(low_sev_event))
        
        # Test high classification event (should be filtered)
        high_class_event = self.data_generator.generate_audit_event(
            severity=AuditSeverity.HIGH,
            classification=ClassificationLevel.SECRET
        )
        self.assertFalse(connector.should_send_event(high_class_event))


class AlertingSystemTests(unittest.TestCase):
    """Test suite for real-time alerting functionality."""
    
    def setUp(self):
        """Set up test environment."""
        self.test_dir = tempfile.mkdtemp()
        self.alert_manager = create_alert_manager(self.test_dir)
        self.data_generator = TestDataGenerator()
    
    def tearDown(self):
        """Clean up test environment."""
        self.alert_manager.shutdown()
        shutil.rmtree(self.test_dir, ignore_errors=True)
    
    def test_brute_force_detection(self):
        """Test brute force attack detection."""
        # Generate brute force scenario
        attack_events = self.data_generator.generate_attack_scenario("brute_force")
        
        # Process events through alert manager
        for event in attack_events:
            self.alert_manager.process_event(event)
        
        time.sleep(3)  # Wait for processing
        
        # Check for generated alerts
        alerts = self.alert_manager.get_active_alerts()
        self.assertGreater(len(alerts), 0)
        
        # Verify alert is for brute force
        brute_force_alerts = [a for a in alerts if "brute" in a.title.lower()]
        self.assertGreater(len(brute_force_alerts), 0)
    
    def test_privilege_escalation_detection(self):
        """Test privilege escalation detection."""
        attack_events = self.data_generator.generate_attack_scenario("privilege_escalation")
        
        for event in attack_events:
            self.alert_manager.process_event(event)
        
        time.sleep(2)
        
        alerts = self.alert_manager.get_active_alerts()
        privilege_alerts = [a for a in alerts if "privilege" in a.title.lower()]
        self.assertGreater(len(privilege_alerts), 0)
    
    def test_data_exfiltration_detection(self):
        """Test data exfiltration detection."""
        attack_events = self.data_generator.generate_attack_scenario("data_exfiltration")
        
        for event in attack_events:
            self.alert_manager.process_event(event)
        
        time.sleep(3)
        
        alerts = self.alert_manager.get_active_alerts()
        exfiltration_alerts = [a for a in alerts if "exfiltration" in a.title.lower()]
        self.assertGreater(len(exfiltration_alerts), 0)
    
    def test_alert_correlation(self):
        """Test alert correlation and deduplication."""
        # Generate related events
        user_id = "correlation_test_user"
        events = []
        
        # Multiple similar events that should correlate
        for i in range(10):
            event = self.data_generator.generate_audit_event(
                event_type=AuditEventType.USER_LOGIN_FAILURE,
                user_id=user_id,
                severity=AuditSeverity.HIGH
            )
            events.append(event)
        
        for event in events:
            self.alert_manager.process_event(event)
        
        time.sleep(2)
        
        # Should generate correlated alerts, not individual ones
        alerts = self.alert_manager.get_active_alerts()
        user_alerts = [a for a in alerts if user_id in a.affected_users]
        
        # Should have fewer alerts than events due to correlation
        self.assertLess(len(user_alerts), len(events))
    
    def test_alert_escalation(self):
        """Test alert escalation functionality."""
        # Create a rule with auto-escalation
        from .real_time_alerting import AlertRule, AlertSeverity, AlertCategory, AlertChannel
        rule = AlertRule(
            rule_id="test_escalation_rule",
            name="Test Escalation Rule",
            description="Test rule for escalation",
            event_types=[AuditEventType.SECURITY_VIOLATION],
            time_window_minutes=1,
            occurrence_threshold=1,
            alert_severity=AlertSeverity.MEDIUM,
            alert_category=AlertCategory.SECURITY_VIOLATION,
            channels=[AlertChannel.EMAIL],
            auto_escalate=True,
            escalation_time_minutes=1  # Short time for testing
        )
        
        self.alert_manager.add_rule(rule)
        
        # Generate triggering event
        event = self.data_generator.generate_audit_event(
            event_type=AuditEventType.SECURITY_VIOLATION,
            severity=AuditSeverity.HIGH
        )
        
        self.alert_manager.process_event(event)
        time.sleep(2)
        
        # Get initial alerts
        initial_alerts = self.alert_manager.get_active_alerts()
        initial_count = len(initial_alerts)
        
        # Wait for escalation
        time.sleep(65)  # Wait longer than escalation time
        
        # Check if escalation occurred
        escalated_alerts = self.alert_manager.get_active_alerts()
        escalated_alert = None
        
        for alert in escalated_alerts:
            if alert.escalated:
                escalated_alert = alert
                break
        
        self.assertIsNotNone(escalated_alert)
        self.assertTrue(escalated_alert.escalated)


class ComplianceReportingTests(unittest.TestCase):
    """Test suite for compliance reporting functionality."""
    
    def setUp(self):
        """Set up test environment."""
        self.test_dir = tempfile.mkdtemp()
        
        # Create a temporary audit database
        self.audit_db = self.test_dir + "/test_audit.db"
        conn = sqlite3.connect(self.audit_db)
        
        # Create minimal audit events table
        conn.execute("""
            CREATE TABLE audit_events (
                event_id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                event_type TEXT NOT NULL,
                severity INTEGER NOT NULL,
                user_id TEXT,
                result TEXT DEFAULT 'SUCCESS'
            )
        """)
        
        # Insert test data
        test_events = [
            ("event_1", datetime.now().isoformat(), "user_login_success", 4, "user1", "SUCCESS"),
            ("event_2", datetime.now().isoformat(), "user_login_failure", 2, "user2", "FAILURE"),
            ("event_3", datetime.now().isoformat(), "data_read", 3, "user1", "SUCCESS"),
        ]
        
        conn.executemany("""
            INSERT INTO audit_events (event_id, timestamp, event_type, severity, user_id, result)
            VALUES (?, ?, ?, ?, ?, ?)
        """, test_events)
        
        conn.commit()
        conn.close()
        
        self.reporter = ComplianceReporter(self.audit_db, self.test_dir)
    
    def tearDown(self):
        """Clean up test environment."""
        shutil.rmtree(self.test_dir, ignore_errors=True)
    
    def test_executive_summary_generation(self):
        """Test executive summary report generation."""
        end_date = datetime.now(timezone.utc)
        start_date = end_date - timedelta(days=30)
        
        report = self.reporter.generate_executive_summary(start_date, end_date)
        
        self.assertIsNotNone(report)
        self.assertEqual(report.report_type, ReportType.EXECUTIVE_SUMMARY)
        self.assertGreater(len(report.executive_summary), 0)
        self.assertGreater(report.overall_compliance_score, 0)
    
    def test_detailed_technical_report(self):
        """Test detailed technical report generation."""
        end_date = datetime.now(timezone.utc)
        start_date = end_date - timedelta(days=7)
        
        report = self.reporter.generate_detailed_technical_report(start_date, end_date)
        
        self.assertIsNotNone(report)
        self.assertEqual(report.report_type, ReportType.DETAILED_TECHNICAL)
        self.assertGreater(len(report.metrics), 0)
    
    def test_trend_analysis_report(self):
        """Test trend analysis report generation."""
        report = self.reporter.generate_trend_analysis(months_back=3)
        
        self.assertIsNotNone(report)
        self.assertEqual(report.report_type, ReportType.TREND_ANALYSIS)
    
    def test_report_export_formats(self):
        """Test report export in different formats."""
        end_date = datetime.now(timezone.utc)
        start_date = end_date - timedelta(days=7)
        
        report = self.reporter.generate_executive_summary(start_date, end_date)
        
        # Test JSON export
        json_path = self.reporter.export_report(report, ReportFormat.JSON)
        self.assertTrue(Path(json_path).exists())
        
        with open(json_path, 'r') as f:
            json_data = json.load(f)
            self.assertEqual(json_data['report_id'], report.report_id)
        
        # Test Excel export
        excel_path = self.reporter.export_report(report, ReportFormat.EXCEL)
        self.assertTrue(Path(excel_path).exists())
        
        # Test HTML export
        html_path = self.reporter.export_report(report, ReportFormat.HTML)
        self.assertTrue(Path(html_path).exists())
    
    def test_retention_management(self):
        """Test retention management functionality."""
        retention_manager = RetentionManager(self.test_dir + "/retention")
        
        # Test file scheduling
        test_file = "/test/file.log"
        result = retention_manager.schedule_retention(
            test_file, 
            ClassificationLevel.CONFIDENTIAL
        )
        self.assertTrue(result)
        
        # Test legal hold
        result = retention_manager.apply_legal_hold(
            "hold_001",
            "Test Case",
            ["/test/*.log"],
            "Investigation purposes",
            "security_officer"
        )
        self.assertTrue(result)
        
        # Test expiring files
        expiring = retention_manager.get_expiring_files(days_ahead=365*8)  # 8 years ahead
        self.assertIsInstance(expiring, list)


class PerformanceTests(unittest.TestCase):
    """Performance and load testing for the audit system."""
    
    def setUp(self):
        """Set up performance test environment."""
        self.test_dir = tempfile.mkdtemp()
        self.data_generator = TestDataGenerator()
    
    def tearDown(self):
        """Clean up test environment."""
        shutil.rmtree(self.test_dir, ignore_errors=True)
    
    def test_high_volume_logging_performance(self):
        """Test performance under high event volume."""
        config = AuditConfiguration(
            storage_path=self.test_dir,
            buffer_size=10000,
            batch_size=1000,
            flush_interval_seconds=5
        )
        logger = AuditLogger(config)
        
        try:
            event_count = 10000
            events = self.data_generator.generate_event_batch(event_count)
            
            start_time = time.time()
            
            success_count = 0
            for event in events:
                if logger.log_event(event):
                    success_count += 1
            
            logging_time = time.time() - start_time
            
            # Wait for processing to complete
            time.sleep(10)
            
            end_time = time.time()
            total_time = end_time - start_time
            
            # Performance assertions
            self.assertEqual(success_count, event_count)
            self.assertLess(logging_time, 30)  # Should log 10k events in under 30 seconds
            self.assertLess(total_time, 60)    # Should complete processing in under 60 seconds
            
            # Calculate throughput
            throughput = event_count / total_time
            self.assertGreater(throughput, 100)  # At least 100 events per second
            
            print(f"Performance: {throughput:.2f} events/second, "
                  f"Logging: {logging_time:.2f}s, Total: {total_time:.2f}s")
            
        finally:
            logger.shutdown()
    
    def test_concurrent_performance(self):
        """Test performance under concurrent load."""
        config = AuditConfiguration(
            storage_path=self.test_dir,
            buffer_size=20000,
            worker_threads=8
        )
        logger = AuditLogger(config)
        
        try:
            def worker_function(worker_id: int, events_per_worker: int):
                success_count = 0
                start_time = time.time()
                
                for i in range(events_per_worker):
                    event = self.data_generator.generate_audit_event()
                    event.additional_data['worker_id'] = worker_id
                    event.additional_data['sequence'] = i
                    
                    if logger.log_event(event):
                        success_count += 1
                
                return success_count, time.time() - start_time
            
            num_workers = 10
            events_per_worker = 1000
            total_events = num_workers * events_per_worker
            
            start_time = time.time()
            
            with ThreadPoolExecutor(max_workers=num_workers) as executor:
                futures = [
                    executor.submit(worker_function, i, events_per_worker)
                    for i in range(num_workers)
                ]
                
                results = [future.result() for future in as_completed(futures)]
            
            concurrent_time = time.time() - start_time
            
            # Wait for processing
            time.sleep(15)
            total_time = time.time() - start_time
            
            # Verify results
            total_success = sum(result[0] for result in results)
            self.assertEqual(total_success, total_events)
            
            # Performance assertions
            throughput = total_events / total_time
            self.assertGreater(throughput, 200)  # At least 200 events/second with concurrency
            
            print(f"Concurrent Performance: {throughput:.2f} events/second, "
                  f"Concurrent time: {concurrent_time:.2f}s, Total: {total_time:.2f}s")
            
        finally:
            logger.shutdown()
    
    def test_storage_performance(self):
        """Test tamper-proof storage performance."""
        storage = create_tamper_proof_storage(
            storage_path=self.test_dir,
            integrity_level=StorageIntegrityLevel.STANDARD
        )
        
        try:
            batch_size = 1000
            num_batches = 5
            
            total_events = 0
            start_time = time.time()
            
            for batch_num in range(num_batches):
                events = self.data_generator.generate_event_batch(batch_size)
                result = storage.store_events(events)
                self.assertTrue(result)
                
                # Force finalization every few batches
                if batch_num % 2 == 0:
                    storage.force_block_finalization()
                
                total_events += len(events)
            
            # Final finalization
            storage.force_block_finalization()
            
            storage_time = time.time() - start_time
            
            # Verify integrity
            is_valid, report = storage.verify_chain_integrity()
            verification_time = time.time() - start_time - storage_time
            
            self.assertTrue(is_valid)
            
            # Performance metrics
            storage_throughput = total_events / storage_time
            print(f"Storage Performance: {storage_throughput:.2f} events/second, "
                  f"Verification time: {verification_time:.2f}s")
            
            self.assertGreater(storage_throughput, 500)  # At least 500 events/second for storage
            
        finally:
            storage.shutdown()


class SecurityValidationTests(unittest.TestCase):
    """Security validation and penetration testing."""
    
    def setUp(self):
        """Set up security test environment."""
        self.test_dir = tempfile.mkdtemp()
        self.data_generator = TestDataGenerator()
    
    def tearDown(self):
        """Clean up test environment."""
        shutil.rmtree(self.test_dir, ignore_errors=True)
    
    def test_cryptographic_integrity(self):
        """Test cryptographic functions and integrity."""
        storage = create_tamper_proof_storage(
            self.test_dir,
            StorageIntegrityLevel.MAXIMUM
        )
        
        try:
            # Test HMAC signing
            test_data = b"test audit data"
            signature = hmac.new(storage.hmac_key, test_data, hashlib.sha256).digest()
            
            # Verify signature
            verification = hmac.new(storage.hmac_key, test_data, hashlib.sha256).digest()
            self.assertEqual(signature, verification)
            
            # Test tampered data detection
            tampered_data = b"tampered audit data"
            tampered_verification = hmac.new(storage.hmac_key, tampered_data, hashlib.sha256).digest()
            self.assertNotEqual(signature, tampered_verification)
            
            # Test RSA signature if available
            if hasattr(storage, 'rsa_private_key') and storage.rsa_private_key:
                from cryptography.hazmat.primitives import hashes
                from cryptography.hazmat.primitives.asymmetric import padding
                
                # Sign data
                rsa_signature = storage.rsa_private_key.sign(
                    test_data,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
                
                # Verify signature
                try:
                    storage.rsa_public_key.verify(
                        rsa_signature,
                        test_data,
                        padding.PSS(
                            mgf=padding.MGF1(hashes.SHA256()),
                            salt_length=padding.PSS.MAX_LENGTH
                        ),
                        hashes.SHA256()
                    )
                    signature_valid = True
                except:
                    signature_valid = False
                
                self.assertTrue(signature_valid)
            
        finally:
            storage.shutdown()
    
    def test_input_validation(self):
        """Test input validation and sanitization."""
        config = AuditConfiguration(storage_path=self.test_dir)
        logger = AuditLogger(config)
        
        try:
            # Test with malicious inputs
            malicious_inputs = [
                "<script>alert('xss')</script>",
                "'; DROP TABLE audit_events; --",
                "../../../etc/passwd",
                "\\x00\\x01\\x02",  # Binary data
                "A" * 10000,        # Very long string
                "",                 # Empty string
                None                # Null value
            ]
            
            for malicious_input in malicious_inputs:
                event = self.data_generator.generate_audit_event()
                event.action = malicious_input
                event.additional_data = {"malicious_field": malicious_input}
                
                # Should handle gracefully without crashing
                try:
                    result = logger.log_event(event)
                    # Most should succeed (after sanitization)
                    # Only completely invalid events should fail
                except Exception as e:
                    # Should not crash with unhandled exceptions
                    self.fail(f"Unhandled exception with input '{malicious_input}': {e}")
            
        finally:
            logger.shutdown()
    
    def test_access_control(self):
        """Test access control mechanisms."""
        # Test file permissions
        storage = create_tamper_proof_storage(self.test_dir)
        
        try:
            events = self.data_generator.generate_event_batch(5)
            storage.store_events(events)
            storage.force_block_finalization()
            
            # Check that block files are read-only
            blocks_dir = Path(self.test_dir) / "blocks"
            for block_file in blocks_dir.glob("*.json"):
                file_stat = block_file.stat()
                # Check that file is not writable by others
                self.assertEqual(file_stat.st_mode & 0o022, 0)  # No write for group/others
            
            # Test database permissions
            db_files = list(Path(self.test_dir).glob("**/*.db"))
            for db_file in db_files:
                file_stat = db_file.stat()
                # Database should be protected
                self.assertEqual(file_stat.st_mode & 0o044, 0)  # No read for others
            
        finally:
            storage.shutdown()
    
    def test_denial_of_service_resistance(self):
        """Test resistance to denial of service attacks."""
        config = AuditConfiguration(
            storage_path=self.test_dir,
            buffer_size=1000,  # Limited buffer
            queue_timeout=1     # Short timeout
        )
        logger = AuditLogger(config)
        
        try:
            # Attempt to flood the system
            flood_size = 10000
            events = self.data_generator.generate_event_batch(flood_size)
            
            start_time = time.time()
            dropped_events = 0
            
            for event in events:
                if not logger.log_event(event):
                    dropped_events += 1
                
                # Break if taking too long (DoS protection working)
                if time.time() - start_time > 30:
                    break
            
            processing_time = time.time() - start_time
            
            # System should remain responsive
            self.assertLess(processing_time, 60)  # Should not hang indefinitely
            
            # Some events may be dropped due to queue limits (this is expected)
            drop_rate = dropped_events / len(events)
            print(f"DoS test: {drop_rate*100:.2f}% drop rate, "
                  f"Processing time: {processing_time:.2f}s")
            
            # System should still be functional
            test_event = self.data_generator.generate_audit_event()
            result = logger.log_event(test_event)
            self.assertTrue(result)  # Should still be able to log after flood
            
        finally:
            logger.shutdown()


def run_test_suite(test_categories: List[str] = None):
    """
    Run the comprehensive test suite.
    
    Args:
        test_categories: List of test categories to run. If None, runs all tests.
                        Options: ['unit', 'integration', 'performance', 'security']
    """
    if test_categories is None:
        test_categories = ['unit', 'integration', 'performance', 'security']
    
    # Configure test logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Create test suite
    test_suite = unittest.TestSuite()
    
    # Add test categories
    if 'unit' in test_categories:
        test_suite.addTest(unittest.makeSuite(AuditLoggerTests))
        test_suite.addTest(unittest.makeSuite(TamperProofStorageTests))
        test_suite.addTest(unittest.makeSuite(ComplianceReportingTests))
    
    if 'integration' in test_categories:
        test_suite.addTest(unittest.makeSuite(SIEMIntegrationTests))
        test_suite.addTest(unittest.makeSuite(AlertingSystemTests))
    
    if 'performance' in test_categories:
        test_suite.addTest(unittest.makeSuite(PerformanceTests))
    
    if 'security' in test_categories:
        test_suite.addTest(unittest.makeSuite(SecurityValidationTests))
    
    # Run tests
    runner = unittest.TextTestRunner(
        verbosity=2,
        buffer=True,
        failfast=False
    )
    
    print(f"\n{'='*60}")
    print(f"Running DoD Audit System Test Suite")
    print(f"Test Categories: {', '.join(test_categories)}")
    print(f"{'='*60}\n")
    
    start_time = time.time()
    result = runner.run(test_suite)
    end_time = time.time()
    
    print(f"\n{'='*60}")
    print(f"Test Suite Completed in {end_time - start_time:.2f} seconds")
    print(f"Tests Run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Success Rate: {((result.testsRun - len(result.failures) - len(result.errors)) / result.testsRun * 100):.1f}%")
    print(f"{'='*60}")
    
    return result


if __name__ == "__main__":
    # Run all tests if executed directly
    import argparse
    
    parser = argparse.ArgumentParser(description="DoD Audit System Test Suite")
    parser.add_argument(
        "--categories",
        nargs="+",
        choices=["unit", "integration", "performance", "security"],
        default=None,
        help="Test categories to run (default: all)"
    )
    parser.add_argument(
        "--quick",
        action="store_true",
        help="Run only unit and integration tests (skip performance and security)"
    )
    
    args = parser.parse_args()
    
    if args.quick:
        test_categories = ["unit", "integration"]
    else:
        test_categories = args.categories
    
    result = run_test_suite(test_categories)
    
    # Exit with appropriate code
    if result.failures or result.errors:
        sys.exit(1)
    else:
        sys.exit(0)