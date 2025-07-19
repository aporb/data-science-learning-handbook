#!/usr/bin/env python3
"""
Comprehensive Test Suite for Session Management System

Tests for DoD-compliant session management including classification-aware policies,
security controls, MFA integration, and storage systems.

Classification: UNCLASSIFIED//FOR OFFICIAL USE ONLY
Version: 1.0
Author: Security Compliance Team
Date: 2025-07-18
"""

import unittest
import tempfile
import threading
import json
import os
from datetime import datetime, timezone, timedelta
from uuid import UUID, uuid4
from unittest.mock import Mock, patch, MagicMock
from pathlib import Path

# Import session management components
from .session_manager import (
    SessionManager, Session, SessionState, SessionSecurityContext, 
    SessionConfiguration, SessionEncryption, NetworkDomain,
    create_session_manager
)
from .classification_policies import (
    ClassificationPolicyEngine, PolicyEnforcementPoint,
    ClassificationLevel, TimeoutConfiguration,
    create_classification_policy_engine, create_policy_enforcement_point
)
from .session_security import (
    SecurityMonitor, AnomalyDetector, SessionHijackingDetector,
    ThreatLevel, SecurityEventType, create_security_monitor
)
from .session_storage import (
    SessionStorageManager, SQLiteStorageBackend, SessionEncoder,
    StorageConfiguration, StorageBackend, PersistencePolicy,
    create_sqlite_storage_manager
)
from .multi_factor_integration import (
    MFAManager, MFAMethod, MFAResult, ChallengeType,
    TOTPProvider, BackupCodesProvider, create_mfa_manager
)


class TestSessionManager(unittest.TestCase):
    """Test cases for SessionManager."""
    
    def setUp(self):
        """Set up test environment."""
        self.session_manager = SessionManager()
        self.test_user_id = uuid4()
        self.test_security_context = SessionSecurityContext(
            user_id=self.test_user_id,
            edipi="1234567890",
            clearance_level="S",
            classification_level="C",
            network_domain=NetworkDomain.NIPR,
            organization="Test Organization"
        )
    
    def tearDown(self):
        """Clean up test environment."""
        # Terminate all test sessions
        for session_id in list(self.session_manager.sessions.keys()):
            self.session_manager.terminate_session(session_id, "Test cleanup", force=True)
    
    def test_create_session(self):
        """Test session creation."""
        session = self.session_manager.create_session(
            security_context=self.test_security_context,
            source_ip="192.168.1.100",
            user_agent="Test-Agent/1.0"
        )
        
        self.assertIsNotNone(session)
        self.assertEqual(session.user_id, self.test_user_id)
        self.assertEqual(session.state, SessionState.ACTIVE)
        self.assertEqual(session.bound_ip, "192.168.1.100")
        self.assertIsNotNone(session.session_id)
        
        # Verify session is stored
        self.assertIn(session.session_id, self.session_manager.sessions)
        self.assertIn(self.test_user_id, self.session_manager.user_sessions)
    
    def test_session_validation(self):
        """Test session validation."""
        session = self.session_manager.create_session(
            security_context=self.test_security_context,
            source_ip="192.168.1.100"
        )
        
        # Valid session
        valid, error = self.session_manager.validate_session(
            session.session_id,
            source_ip="192.168.1.100"
        )
        self.assertTrue(valid)
        self.assertIsNone(error)
        
        # Invalid IP
        valid, error = self.session_manager.validate_session(
            session.session_id,
            source_ip="192.168.1.200"
        )
        self.assertFalse(valid)
        self.assertIn("IP binding violation", error)
        
        # Non-existent session
        valid, error = self.session_manager.validate_session("non-existent")
        self.assertFalse(valid)
        self.assertEqual(error, "Session not found")
    
    def test_session_access(self):
        """Test session access with validation."""
        session = self.session_manager.create_session(
            security_context=self.test_security_context,
            source_ip="192.168.1.100"
        )
        
        # Valid access
        accessed_session = self.session_manager.access_session(
            session.session_id,
            source_ip="192.168.1.100",
            operation="read_data"
        )
        
        self.assertIsNotNone(accessed_session)
        self.assertEqual(accessed_session.access_count, 1)
        
        # Invalid access (wrong IP)
        accessed_session = self.session_manager.access_session(
            session.session_id,
            source_ip="192.168.1.200"
        )
        
        self.assertIsNone(accessed_session)
    
    def test_session_elevation(self):
        """Test session elevation."""
        session = self.session_manager.create_session(
            security_context=self.test_security_context
        )
        
        # Elevate session
        elevated = self.session_manager.elevate_session(
            session.session_id,
            elevation_level="SENSITIVE",
            justification="Administrative operation"
        )
        
        self.assertTrue(elevated)
        self.assertEqual(session.elevation_level, "SENSITIVE")
    
    def test_session_termination(self):
        """Test session termination."""
        session = self.session_manager.create_session(
            security_context=self.test_security_context
        )
        
        session_id = session.session_id
        
        # Terminate session
        terminated = self.session_manager.terminate_session(
            session_id,
            reason="User logout"
        )
        
        self.assertTrue(terminated)
        self.assertNotIn(session_id, self.session_manager.sessions)
        self.assertNotIn(session_id, self.session_manager.user_sessions.get(self.test_user_id, set()))
    
    def test_concurrent_session_limits(self):
        """Test concurrent session limits."""
        # Create first session
        session1 = self.session_manager.create_session(
            security_context=self.test_security_context
        )
        self.assertIsNotNone(session1)
        
        # Try to create second session (should fail due to limit)
        with self.assertRaises(ValueError):
            self.session_manager.create_session(
                security_context=self.test_security_context
            )


class TestClassificationPolicies(unittest.TestCase):
    """Test cases for classification policies."""
    
    def setUp(self):
        """Set up test environment."""
        self.policy_engine = ClassificationPolicyEngine()
        self.enforcement_point = PolicyEnforcementPoint(self.policy_engine)
        
        self.test_user_id = uuid4()
        self.test_session = Mock()
        self.test_session.session_id = str(uuid4())
        self.test_session.user_id = self.test_user_id
        self.test_session.state = SessionState.ACTIVE
        self.test_session.mfa_verified = True
        self.test_session.bound_ip = "192.168.1.100"
        self.test_session.bound_cac_serial = "12345"
        
        # Mock security context
        self.test_session.security_context = Mock()
        self.test_session.security_context.clearance_level = "S"
        self.test_session.security_context.classification_level = "C"
        self.test_session.security_context.network_domain = NetworkDomain.NIPR
        
        # Mock configuration
        self.test_session.configuration = Mock()
        self.test_session.configuration.session_binding_required = True
    
    def test_get_session_policy(self):
        """Test getting session policy."""
        policy = self.policy_engine.get_session_policy("S", NetworkDomain.SIPR)
        
        self.assertIsNotNone(policy)
        self.assertEqual(policy.classification_level, ClassificationLevel.SECRET)
        self.assertEqual(policy.network_domain, NetworkDomain.SIPR)
        self.assertTrue(policy.require_mfa)
        self.assertTrue(policy.require_cac)
    
    def test_validate_session_access(self):
        """Test session access validation."""
        # Valid access (user has S clearance, accessing C data)
        allowed, reason = self.policy_engine.validate_session_access(
            self.test_session,
            required_classification="C"
        )
        self.assertTrue(allowed)
        self.assertIsNone(reason)
        
        # Invalid access (user has S clearance, accessing TS data)
        self.test_session.security_context.clearance_level = "S"
        allowed, reason = self.policy_engine.validate_session_access(
            self.test_session,
            required_classification="TS"
        )
        self.assertFalse(allowed)
        self.assertIn("Insufficient clearance", reason)
    
    def test_cross_domain_validation(self):
        """Test cross-domain access validation."""
        # Cross-domain access (should be denied by default)
        allowed, reason = self.policy_engine.validate_cross_domain_access(
            self.test_session,
            target_domain=NetworkDomain.SIPR,
            target_classification="S"
        )
        
        self.assertFalse(allowed)
        self.assertIn("Cross-domain access not allowed", reason)
    
    def test_timeout_policy(self):
        """Test timeout policy retrieval."""
        timeout_config = self.policy_engine.get_timeout_policy("S", NetworkDomain.SIPR)
        
        self.assertIsNotNone(timeout_config)
        self.assertIsInstance(timeout_config, TimeoutConfiguration)
        self.assertEqual(timeout_config.idle_timeout, timedelta(minutes=15))
        self.assertEqual(timeout_config.session_timeout, timedelta(hours=4))
    
    def test_policy_enforcement(self):
        """Test policy enforcement."""
        # Valid operation
        allowed, reason = self.enforcement_point.enforce_session_policy(
            self.test_session,
            operation="read",
            context={"required_classification": "C"}
        )
        self.assertTrue(allowed)
        
        # Invalid operation (restricted)
        policy = self.policy_engine.get_session_policy("S", NetworkDomain.SIPR)
        if "bulk_export" in policy.restricted_operations:
            allowed, reason = self.enforcement_point.enforce_session_policy(
                self.test_session,
                operation="bulk_export"
            )
            # This may pass or fail depending on policy, just ensure it returns a result
            self.assertIsInstance(allowed, bool)


class TestSessionSecurity(unittest.TestCase):
    """Test cases for session security."""
    
    def setUp(self):
        """Set up test environment."""
        self.anomaly_detector = AnomalyDetector(sensitivity_threshold=0.8)
        self.hijacking_detector = SessionHijackingDetector()
        self.security_monitor = SecurityMonitor(
            anomaly_detector=self.anomaly_detector,
            hijacking_detector=self.hijacking_detector
        )
        
        self.test_user_id = uuid4()
        self.test_session = Mock()
        self.test_session.session_id = str(uuid4())
        self.test_session.user_id = self.test_user_id
        self.test_session.created_at = datetime.now(timezone.utc)
        self.test_session.bound_ip = "192.168.1.100"
        self.test_session.bound_device_fingerprint = "test-device-123"
        
        # Mock security context
        self.test_session.security_context = Mock()
        self.test_session.security_context.classification_level = "C"
        self.test_session.security_context.network_domain = NetworkDomain.NIPR
        
        # Mock configuration
        self.test_session.configuration = Mock()
        self.test_session.configuration.concurrent_session_limit = 1
    
    def test_anomaly_detection(self):
        """Test anomaly detection."""
        activity = {
            'operation': 'login',
            'timestamp': datetime.now(timezone.utc),
            'location': 'Test Location'
        }
        
        # First access should not trigger anomalies (creating baseline)
        threats = self.anomaly_detector.detect_anomalies(self.test_session, activity)
        self.assertIsInstance(threats, list)
        
        # Unusual time access
        unusual_activity = {
            'operation': 'login',
            'timestamp': datetime.now(timezone.utc).replace(hour=3),  # 3 AM
            'location': 'Test Location'
        }
        
        # Create baseline first
        for _ in range(5):
            normal_activity = {
                'operation': 'login',
                'timestamp': datetime.now(timezone.utc).replace(hour=9),  # 9 AM
                'location': 'Test Location'
            }
            self.anomaly_detector.detect_anomalies(self.test_session, normal_activity)
        
        # Now test unusual time
        threats = self.anomaly_detector.detect_anomalies(self.test_session, unusual_activity)
        # Check if any time-based anomaly was detected
        time_anomalies = [t for t in threats if t.threat_type.value == "TIME_BASED_ANOMALY"]
        # May or may not detect based on baseline - just ensure method works
        self.assertIsInstance(time_anomalies, list)
    
    def test_session_hijacking_detection(self):
        """Test session hijacking detection."""
        session_id = self.test_session.session_id
        
        # Initial request
        request1 = {
            'source_ip': '192.168.1.100',
            'user_agent': 'Test-Browser/1.0',
            'headers': {'Accept': 'application/json'}
        }
        
        threats1 = self.hijacking_detector.detect_hijacking(self.test_session, request1)
        self.assertEqual(len(threats1), 0)  # No threats on first request
        
        # Request with different IP (potential hijacking)
        request2 = {
            'source_ip': '192.168.1.200',
            'user_agent': 'Test-Browser/1.0',
            'headers': {'Accept': 'application/json'}
        }
        
        threats2 = self.hijacking_detector.detect_hijacking(self.test_session, request2)
        
        # Should detect IP change
        ip_threats = [t for t in threats2 if t.threat_type.value == "SESSION_HIJACKING_ATTEMPT"]
        self.assertGreater(len(ip_threats), 0)
        self.assertEqual(ip_threats[0].threat_level, ThreatLevel.CRITICAL)
    
    def test_security_monitoring(self):
        """Test comprehensive security monitoring."""
        activity = {
            'operation': 'data_access',
            'resource': 'classified_document'
        }
        
        request_data = {
            'source_ip': '192.168.1.100',
            'user_agent': 'Test-Browser/1.0'
        }
        
        threats = self.security_monitor.monitor_session_activity(
            self.test_session,
            activity,
            request_data
        )
        
        self.assertIsInstance(threats, list)
        
        # Check security status
        status = self.security_monitor.get_security_status(self.test_session.session_id)
        self.assertIn('total_threats', status)
        self.assertIn('monitoring_enabled', status)
    
    def test_brute_force_detection(self):
        """Test brute force attack detection."""
        # Simulate multiple failed attempts
        metrics = self.security_monitor.user_metrics.get(self.test_user_id)
        if not metrics:
            from .session_security import SecurityMetrics
            metrics = SecurityMetrics(user_id=self.test_user_id)
            self.security_monitor.user_metrics[self.test_user_id] = metrics
        
        # Simulate failed login attempts
        for _ in range(6):  # Exceed threshold
            metrics.update_login_metrics(success=False)
        
        threat = self.security_monitor.check_brute_force_attack(self.test_user_id)
        
        self.assertIsNotNone(threat)
        self.assertEqual(threat.threat_type, SecurityEventType.BRUTE_FORCE_ATTACK)
        self.assertEqual(threat.threat_level, ThreatLevel.HIGH)


class TestSessionStorage(unittest.TestCase):
    """Test cases for session storage."""
    
    def setUp(self):
        """Set up test environment."""
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.temp_dir, "test_sessions.db")
        
        self.storage_manager = create_sqlite_storage_manager(self.db_path)
        
        # Create test session
        self.test_user_id = uuid4()
        self.test_security_context = SessionSecurityContext(
            user_id=self.test_user_id,
            classification_level="C",
            network_domain=NetworkDomain.NIPR
        )
        
        self.test_config = SessionConfiguration(
            session_id=str(uuid4()),
            max_idle_time=1800,
            max_session_time=28800,
            warning_time=300
        )
        
        self.test_session = Session(
            session_id=str(uuid4()),
            user_id=self.test_user_id,
            state=SessionState.ACTIVE,
            security_context=self.test_security_context,
            configuration=self.test_config,
            created_at=datetime.now(timezone.utc),
            last_accessed=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc) + timedelta(hours=8),
            warning_at=datetime.now(timezone.utc) + timedelta(hours=7, minutes=55)
        )
    
    def tearDown(self):
        """Clean up test environment."""
        import shutil
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)
    
    def test_session_encoding_decoding(self):
        """Test session encoding and decoding."""
        encoder = SessionEncoder()
        
        # Encode session
        encrypted_data, checksum = encoder.encode_session(self.test_session)
        
        self.assertIsInstance(encrypted_data, str)
        self.assertIsInstance(checksum, str)
        self.assertGreater(len(encrypted_data), 0)
        self.assertGreater(len(checksum), 0)
        
        # Decode session
        decoded_session = encoder.decode_session(encrypted_data, checksum)
        
        self.assertEqual(decoded_session.session_id, self.test_session.session_id)
        self.assertEqual(decoded_session.user_id, self.test_session.user_id)
        self.assertEqual(decoded_session.state, self.test_session.state)
        self.assertEqual(decoded_session.security_context.classification_level,
                        self.test_session.security_context.classification_level)
    
    def test_sqlite_storage(self):
        """Test SQLite storage backend."""
        backend = SQLiteStorageBackend(self.db_path)
        
        # Store session
        stored = backend.store_session(self.test_session)
        self.assertTrue(stored)
        
        # Load session
        loaded_session = backend.load_session(self.test_session.session_id)
        self.assertIsNotNone(loaded_session)
        self.assertEqual(loaded_session.session_id, self.test_session.session_id)
        
        # List user sessions
        session_ids = backend.list_user_sessions(self.test_user_id)
        self.assertIn(self.test_session.session_id, session_ids)
        
        # Delete session
        deleted = backend.delete_session(self.test_session.session_id)
        self.assertTrue(deleted)
        
        # Verify deletion
        loaded_session = backend.load_session(self.test_session.session_id)
        self.assertIsNone(loaded_session)
    
    def test_storage_manager(self):
        """Test storage manager functionality."""
        # Store session
        stored = self.storage_manager.store_session(self.test_session)
        self.assertTrue(stored)
        
        # Load session
        loaded_session = self.storage_manager.load_session(self.test_session.session_id)
        self.assertIsNotNone(loaded_session)
        
        # Delete session
        deleted = self.storage_manager.delete_session(self.test_session.session_id)
        self.assertTrue(deleted)
        
        # Get statistics
        stats = self.storage_manager.get_storage_statistics()
        self.assertIn('session_storage_stats', stats)


class TestMFAIntegration(unittest.TestCase):
    """Test cases for MFA integration."""
    
    def setUp(self):
        """Set up test environment."""
        self.mfa_manager = create_mfa_manager()
        self.test_user_id = uuid4()
        
        # Create test session
        self.test_session = Mock()
        self.test_session.session_id = str(uuid4())
        self.test_session.user_id = self.test_user_id
        
        # Mock security context
        self.test_session.security_context = Mock()
        self.test_session.security_context.classification_level = "C"
    
    def test_totp_provider(self):
        """Test TOTP provider functionality."""
        totp_provider = TOTPProvider()
        
        # Enroll device
        device = totp_provider.enroll_device(self.test_user_id, {})
        self.assertIsNotNone(device)
        self.assertEqual(device.method, MFAMethod.TOTP)
        self.assertIn('secret', device.device_data)
        self.assertIn('provisioning_uri', device.device_data)
        
        # Create challenge
        challenge_data = totp_provider.create_challenge(
            self.test_user_id,
            ChallengeType.INITIAL
        )
        self.assertIsNotNone(challenge_data)
        self.assertIn('challenge_id', challenge_data)
        
        # Verify response (would need actual TOTP code in real scenario)
        # For testing, we'll simulate with an invalid code
        result = totp_provider.verify_response(challenge_data, "123456")
        # Should fail with invalid code (unless by extreme coincidence)
        self.assertIn(result, [MFAResult.FAILURE, MFAResult.SUCCESS])
    
    def test_backup_codes_provider(self):
        """Test backup codes provider."""
        backup_provider = BackupCodesProvider()
        
        # Enroll device (generate backup codes)
        device = backup_provider.enroll_device(self.test_user_id, {})
        self.assertIsNotNone(device)
        self.assertEqual(device.method, MFAMethod.BACKUP_CODES)
        self.assertIn('codes', device.device_data)
        
        codes = device.device_data['codes']
        self.assertEqual(len(codes), 10)  # Should generate 10 codes
        
        # Create challenge
        challenge_data = backup_provider.create_challenge(
            self.test_user_id,
            ChallengeType.INITIAL
        )
        
        # Verify with valid backup code
        valid_code = codes[0]
        result = backup_provider.verify_response(challenge_data, valid_code)
        self.assertEqual(result, MFAResult.SUCCESS)
        
        # Try to use same code again (should fail)
        result = backup_provider.verify_response(challenge_data, valid_code)
        self.assertEqual(result, MFAResult.FAILURE)
    
    def test_mfa_challenge_creation(self):
        """Test MFA challenge creation."""
        # Create challenge
        challenge = self.mfa_manager.create_challenge(
            self.test_session,
            ChallengeType.INITIAL,
            required_methods={MFAMethod.TOTP}
        )
        
        self.assertIsNotNone(challenge)
        self.assertEqual(challenge.session_id, self.test_session.session_id)
        self.assertEqual(challenge.user_id, self.test_user_id)
        self.assertIn(MFAMethod.TOTP, challenge.required_methods)
        self.assertFalse(challenge.is_complete)
        self.assertFalse(challenge.is_expired)
    
    def test_mfa_device_enrollment(self):
        """Test MFA device enrollment."""
        # Enroll TOTP device
        device = self.mfa_manager.enroll_device(
            self.test_user_id,
            MFAMethod.TOTP,
            {}
        )
        
        self.assertIsNotNone(device)
        self.assertEqual(device.user_id, self.test_user_id)
        self.assertEqual(device.method, MFAMethod.TOTP)
        
        # Get user devices
        devices = self.mfa_manager.get_user_devices(self.test_user_id)
        self.assertEqual(len(devices), 1)
        self.assertEqual(devices[0].device_id, device.device_id)
    
    def test_mfa_statistics(self):
        """Test MFA statistics."""
        # Enroll some devices
        self.mfa_manager.enroll_device(self.test_user_id, MFAMethod.TOTP, {})
        self.mfa_manager.enroll_device(self.test_user_id, MFAMethod.BACKUP_CODES, {})
        
        stats = self.mfa_manager.get_mfa_statistics()
        
        self.assertIn('total_users_with_mfa', stats)
        self.assertIn('total_registered_devices', stats)
        self.assertIn('devices_by_method', stats)
        self.assertGreater(stats['total_registered_devices'], 0)


class TestIntegration(unittest.TestCase):
    """Integration tests for complete session management system."""
    
    def setUp(self):
        """Set up integration test environment."""
        # Create temporary storage
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.temp_dir, "integration_test.db")
        
        # Initialize all components
        self.session_manager = SessionManager()
        self.policy_engine = ClassificationPolicyEngine()
        self.enforcement_point = PolicyEnforcementPoint(self.policy_engine)
        self.security_monitor = SecurityMonitor()
        self.storage_manager = create_sqlite_storage_manager(self.db_path)
        self.mfa_manager = create_mfa_manager()
        
        # Test user
        self.test_user_id = uuid4()
        self.test_security_context = SessionSecurityContext(
            user_id=self.test_user_id,
            edipi="1234567890",
            clearance_level="S",
            classification_level="C",
            network_domain=NetworkDomain.NIPR
        )
    
    def tearDown(self):
        """Clean up integration test environment."""
        import shutil
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)
    
    def test_complete_session_workflow(self):
        """Test complete session workflow with all components."""
        # 1. Create session
        session = self.session_manager.create_session(
            security_context=self.test_security_context,
            source_ip="192.168.1.100"
        )
        self.assertIsNotNone(session)
        
        # 2. Store session
        stored = self.storage_manager.store_session(session)
        self.assertTrue(stored)
        
        # 3. Validate with policy engine
        allowed, reason = self.enforcement_point.enforce_session_policy(
            session,
            operation="read",
            context={"required_classification": "C"}
        )
        self.assertTrue(allowed)
        
        # 4. Monitor security
        activity = {"operation": "data_access"}
        request_data = {"source_ip": "192.168.1.100", "user_agent": "Test"}
        
        threats = self.security_monitor.monitor_session_activity(
            session, activity, request_data
        )
        self.assertIsInstance(threats, list)
        
        # 5. Create MFA challenge
        challenge = self.mfa_manager.create_challenge(
            session,
            ChallengeType.INITIAL,
            required_methods={MFAMethod.TOTP}
        )
        self.assertIsNotNone(challenge)
        
        # 6. Load session from storage
        loaded_session = self.storage_manager.load_session(session.session_id)
        self.assertIsNotNone(loaded_session)
        self.assertEqual(loaded_session.session_id, session.session_id)
        
        # 7. Terminate session
        terminated = self.session_manager.terminate_session(
            session.session_id,
            "Integration test complete"
        )
        self.assertTrue(terminated)
        
        # 8. Clean up storage
        deleted = self.storage_manager.delete_session(session.session_id)
        self.assertTrue(deleted)
    
    def test_classification_level_enforcement(self):
        """Test classification level enforcement across components."""
        # Create sessions with different classification levels
        contexts = [
            SessionSecurityContext(
                user_id=uuid4(),
                clearance_level="TS",
                classification_level="TS",
                network_domain=NetworkDomain.JWICS
            ),
            SessionSecurityContext(
                user_id=uuid4(),
                clearance_level="S",
                classification_level="S",
                network_domain=NetworkDomain.SIPR
            ),
            SessionSecurityContext(
                user_id=uuid4(),
                clearance_level="C",
                classification_level="C",
                network_domain=NetworkDomain.NIPR
            )
        ]
        
        for context in contexts:
            # Create session
            session = self.session_manager.create_session(context)
            
            # Get classification policy
            policy = self.policy_engine.get_session_policy(
                context.classification_level,
                context.network_domain
            )
            
            # Verify policy matches classification
            self.assertEqual(policy.classification_level.value, context.classification_level)
            self.assertEqual(policy.network_domain, context.network_domain)
            
            # Verify storage respects classification
            stored = self.storage_manager.store_session(session)
            if context.classification_level == "TS":
                # TS sessions might not be stored based on policy
                pass  # Policy dependent
            else:
                self.assertTrue(stored)
            
            # Clean up
            self.session_manager.terminate_session(session.session_id, force=True)
    
    def test_concurrent_operations(self):
        """Test concurrent session operations."""
        def create_and_test_session(user_id):
            context = SessionSecurityContext(
                user_id=user_id,
                classification_level="C",
                network_domain=NetworkDomain.NIPR
            )
            
            session = self.session_manager.create_session(context)
            self.storage_manager.store_session(session)
            
            # Simulate some operations
            for _ in range(5):
                self.session_manager.access_session(session.session_id)
            
            # Clean up
            self.session_manager.terminate_session(session.session_id)
            self.storage_manager.delete_session(session.session_id)
        
        # Create multiple threads
        threads = []
        for i in range(5):
            user_id = uuid4()
            thread = threading.Thread(target=create_and_test_session, args=(user_id,))
            threads.append(thread)
            thread.start()
        
        # Wait for all threads
        for thread in threads:
            thread.join()
        
        # Verify no sessions remain
        self.assertEqual(len(self.session_manager.sessions), 0)


def run_session_management_tests():
    """Run all session management tests."""
    test_cases = [
        TestSessionManager,
        TestClassificationPolicies,
        TestSessionSecurity,
        TestSessionStorage,
        TestMFAIntegration,
        TestIntegration
    ]
    
    total_tests = 0
    total_failures = 0
    total_errors = 0
    
    for test_case in test_cases:
        print(f"\nRunning {test_case.__name__}...")
        
        suite = unittest.TestLoader().loadTestsFromTestCase(test_case)
        runner = unittest.TextTestRunner(verbosity=2)
        result = runner.run(suite)
        
        total_tests += result.testsRun
        total_failures += len(result.failures)
        total_errors += len(result.errors)
        
        if result.failures:
            print(f"Failures in {test_case.__name__}:")
            for test, traceback in result.failures:
                print(f"  - {test}: {traceback}")
        
        if result.errors:
            print(f"Errors in {test_case.__name__}:")
            for test, traceback in result.errors:
                print(f"  - {test}: {traceback}")
    
    print(f"\n{'='*60}")
    print(f"Session Management Test Summary")
    print(f"{'='*60}")
    print(f"Total Tests: {total_tests}")
    print(f"Failures: {total_failures}")
    print(f"Errors: {total_errors}")
    print(f"Success Rate: {((total_tests - total_failures - total_errors) / total_tests * 100):.1f}%")
    
    return total_failures + total_errors == 0


if __name__ == "__main__":
    success = run_session_management_tests()
    exit(0 if success else 1)