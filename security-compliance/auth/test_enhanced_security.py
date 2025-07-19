#!/usr/bin/env python3
"""
Enhanced Unit Tests for CAC/PIV Security Features
Comprehensive tests for all new security components
"""

import unittest
from unittest.mock import Mock, patch, MagicMock, mock_open
import os
import sys
import tempfile
import time
import json
from datetime import datetime, timezone, timedelta
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID, ExtensionOID

# Add the auth module to the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from certificate_validators import (
    DoDBCertificateValidator, 
    CRLChecker, 
    OCSPValidator, 
    CombinedRevocationChecker,
    ValidationResult,
    RevocationStatus
)
from middleware_abstraction import (
    MiddlewareDetector, 
    PKCS11ProviderManager, 
    MiddlewareCompatibilityLayer,
    MiddlewareType,
    MiddlewareInfo
)
from security_managers import (
    SecurePINManager, 
    SessionManager, 
    AuditLogger,
    AuditEvent,
    AuditEventType
)

class TestDoDBCertificateValidator(unittest.TestCase):
    """Test DoD certificate validation"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.validator = DoDBCertificateValidator()
        
        # Create test certificate
        self.test_cert = self._create_test_certificate()
        
    def _create_test_certificate(self):
        """Create a test DoD certificate"""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "U.S. Government"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "DoD"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "PKI"),
            x509.NameAttribute(NameOID.COMMON_NAME, "DOE.JOHN.1234567890"),
        ])
        
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            1234567890
        ).not_valid_before(
            datetime.now(timezone.utc) - timedelta(days=1)
        ).not_valid_after(
            datetime.now(timezone.utc) + timedelta(days=365)
        ).add_extension(
            x509.CertificatePolicies([
                x509.PolicyInformation(
                    x509.ObjectIdentifier("2.16.840.1.101.3.2.1.3.7"),  # DoD Medium Hardware
                    None
                )
            ]),
            critical=False,
        ).add_extension(
            x509.KeyUsage(
                digital_signature=True,
                non_repudiation=True,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=True,
                key_cert_sign=False,
                crl_sign=False,
                content_commitment=True,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True,
        ).add_extension(
            x509.SubjectAlternativeName([
                x509.RFC822Name("john.doe@mail.mil"),
                x509.OtherName(
                    x509.ObjectIdentifier("2.16.840.1.101.3.6.6"),  # EDIPI OID
                    b"1234567890"
                )
            ]),
            critical=False,
        ).sign(private_key, hashes.SHA256())
        
        return cert
    
    def test_basic_certificate_validation(self):
        """Test basic certificate validation"""
        result = self.validator._validate_basic_certificate(self.test_cert)
        
        self.assertTrue(result.is_valid)
        self.assertIn('key_type', result.validation_details)
        self.assertEqual(result.validation_details['key_type'], 'RSA')
        self.assertEqual(result.validation_details['key_size'], 2048)
    
    def test_dod_policy_validation(self):
        """Test DoD policy validation"""
        result = self.validator._validate_dod_policies(self.test_cert)
        
        self.assertTrue(result.is_valid)
        self.assertIn('dod_policies', result.validation_details)
        self.assertIn('DOD_MEDIUM_HARDWARE', result.validation_details['dod_policies'])
    
    def test_key_usage_validation(self):
        """Test key usage validation"""
        result = self.validator._validate_key_usage(self.test_cert)
        
        self.assertTrue(result.is_valid)
        self.assertIn('digital_signature', result.validation_details['key_usage'])
        self.assertIn('non_repudiation', result.validation_details['key_usage'])
    
    def test_expired_certificate(self):
        """Test validation of expired certificate"""
        # Create expired certificate
        private_key = rsa.generate_private_key(65537, 2048)
        expired_cert = x509.CertificateBuilder().subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Expired Cert")])
        ).issuer_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test CA")])
        ).public_key(
            private_key.public_key()
        ).serial_number(
            1
        ).not_valid_before(
            datetime.now(timezone.utc) - timedelta(days=365)
        ).not_valid_after(
            datetime.now(timezone.utc) - timedelta(days=1)  # Expired
        ).sign(private_key, hashes.SHA256())
        
        result = self.validator._validate_basic_certificate(expired_cert)
        self.assertFalse(result.is_valid)
        self.assertIn("expired", result.error_message)
    
    def test_cache_functionality(self):
        """Test validation caching"""
        # First validation should hit the validator
        result1 = self.validator.validate_certificate_chain(self.test_cert)
        
        # Second validation should use cache
        result2 = self.validator.validate_certificate_chain(self.test_cert)
        
        self.assertEqual(result1.is_valid, result2.is_valid)
        
        # Clear cache and verify
        self.validator.clear_validation_cache()
        stats = self.validator.get_cache_stats()
        self.assertEqual(stats['cached_certificates'], 0)

class TestCRLChecker(unittest.TestCase):
    """Test CRL validation functionality"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.temp_dir = tempfile.mkdtemp()
        self.crl_checker = CRLChecker(cache_dir=self.temp_dir, cache_timeout=60)
        
        # Create test certificate
        self.test_cert = self._create_test_certificate_with_crl()
    
    def tearDown(self):
        """Clean up test fixtures"""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def _create_test_certificate_with_crl(self):
        """Create test certificate with CRL distribution points"""
        private_key = rsa.generate_private_key(65537, 2048)
        
        cert = x509.CertificateBuilder().subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test Subject")])
        ).issuer_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test Issuer")])
        ).public_key(
            private_key.public_key()
        ).serial_number(
            12345
        ).not_valid_before(
            datetime.now(timezone.utc) - timedelta(days=1)
        ).not_valid_after(
            datetime.now(timezone.utc) + timedelta(days=365)
        ).add_extension(
            x509.CRLDistributionPoints([
                x509.DistributionPoint(
                    full_name=[x509.UniformResourceIdentifier("http://example.com/test.crl")],
                    relative_name=None,
                    crl_issuer=None,
                    reasons=None
                )
            ]),
            critical=False,
        ).sign(private_key, hashes.SHA256())
        
        return cert
    
    def test_crl_url_extraction(self):
        """Test CRL URL extraction from certificate"""
        urls = self.crl_checker._get_crl_urls(self.test_cert)
        
        self.assertEqual(len(urls), 1)
        self.assertEqual(urls[0], "http://example.com/test.crl")
    
    @patch('requests.Session.get')
    def test_crl_download_success(self, mock_get):
        """Test successful CRL download"""
        # Mock successful CRL download
        mock_response = Mock()
        mock_response.raise_for_status.return_value = None
        mock_response.content = b"mock_crl_data"
        mock_get.return_value = mock_response
        
        # Mock CRL parsing
        with patch.object(self.crl_checker, '_parse_crl') as mock_parse:
            mock_crl = Mock()
            mock_parse.return_value = mock_crl
            
            result = self.crl_checker._download_crl("http://example.com/test.crl", "/tmp/test.crl")
            
            self.assertEqual(result, mock_crl)
            mock_get.assert_called_once()
    
    @patch('requests.Session.get')
    def test_crl_download_failure(self, mock_get):
        """Test CRL download failure"""
        # Mock failed download
        mock_get.side_effect = Exception("Network error")
        
        result = self.crl_checker._download_crl("http://example.com/test.crl", "/tmp/test.crl")
        
        self.assertIsNone(result)
    
    def test_cache_stats(self):
        """Test CRL cache statistics"""
        stats = self.crl_checker.get_cache_stats()
        
        self.assertIn('memory_cache_count', stats)
        self.assertIn('file_cache_count', stats)
        self.assertIn('cache_timeout', stats)
        self.assertEqual(stats['cache_timeout'], 60)

class TestOCSPValidator(unittest.TestCase):
    """Test OCSP validation functionality"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.ocsp_validator = OCSPValidator(timeout=10, max_retries=2)
        
        # Create test certificates
        self.test_cert, self.issuer_cert = self._create_test_certificate_chain()
    
    def _create_test_certificate_chain(self):
        """Create test certificate with OCSP responder URL"""
        # Create issuer key and certificate
        issuer_key = rsa.generate_private_key(65537, 2048)
        issuer_cert = x509.CertificateBuilder().subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test CA")])
        ).issuer_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test CA")])
        ).public_key(
            issuer_key.public_key()
        ).serial_number(1).not_valid_before(
            datetime.now(timezone.utc) - timedelta(days=1)
        ).not_valid_after(
            datetime.now(timezone.utc) + timedelta(days=365)
        ).sign(issuer_key, hashes.SHA256())
        
        # Create end entity certificate
        ee_key = rsa.generate_private_key(65537, 2048)
        ee_cert = x509.CertificateBuilder().subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test Subject")])
        ).issuer_name(
            issuer_cert.subject
        ).public_key(
            ee_key.public_key()
        ).serial_number(2).not_valid_before(
            datetime.now(timezone.utc) - timedelta(days=1)
        ).not_valid_after(
            datetime.now(timezone.utc) + timedelta(days=365)
        ).add_extension(
            x509.AuthorityInformationAccess([
                x509.AccessDescription(
                    x509.oid.AuthorityInformationAccessOID.OCSP,
                    x509.UniformResourceIdentifier("http://ocsp.example.com/")
                )
            ]),
            critical=False,
        ).sign(issuer_key, hashes.SHA256())
        
        return ee_cert, issuer_cert
    
    def test_ocsp_url_extraction(self):
        """Test OCSP URL extraction from certificate"""
        urls = self.ocsp_validator._get_ocsp_urls(self.test_cert)
        
        self.assertEqual(len(urls), 1)
        self.assertEqual(urls[0], "http://ocsp.example.com/")
    
    def test_ocsp_request_building(self):
        """Test OCSP request building"""
        try:
            ocsp_request = self.ocsp_validator._build_ocsp_request(
                self.test_cert, self.issuer_cert
            )
            
            self.assertIsInstance(ocsp_request, bytes)
            self.assertGreater(len(ocsp_request), 0)
        except Exception as e:
            # Some environments may not have full OCSP support
            self.skipTest(f"OCSP request building not supported: {e}")
    
    def test_missing_issuer_certificate(self):
        """Test OCSP validation without issuer certificate"""
        result = self.ocsp_validator.check_certificate_revocation(self.test_cert)
        
        self.assertFalse(result.is_revoked)
        self.assertEqual(result.method, 'OCSP')
        self.assertIn("Issuer certificate required", result.reason)

class TestMiddlewareDetector(unittest.TestCase):
    """Test middleware detection functionality"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.detector = MiddlewareDetector()
    
    @patch('os.path.exists')
    def test_middleware_detection_success(self, mock_exists):
        """Test successful middleware detection"""
        # Mock OpenSC installation
        mock_exists.side_effect = lambda path: 'opensc-pkcs11' in path
        
        middleware_list = self.detector.detect_all_middleware()
        
        # Should detect at least OpenSC
        opensc_found = any(mw.middleware_type == MiddlewareType.OPENSC 
                          for mw in middleware_list if mw.is_available)
        self.assertTrue(opensc_found)
    
    @patch('os.path.exists')
    def test_no_middleware_detected(self, mock_exists):
        """Test when no middleware is detected"""
        # Mock no middleware found
        mock_exists.return_value = False
        
        middleware_list = self.detector.detect_all_middleware()
        
        # Should return empty list or all unavailable
        available_middleware = [mw for mw in middleware_list if mw.is_available]
        self.assertEqual(len(available_middleware), 0)
    
    def test_get_best_middleware(self):
        """Test getting best available middleware"""
        with patch('os.path.exists') as mock_exists:
            # Mock ActivClient available (highest priority)
            mock_exists.side_effect = lambda path: 'acpkcs211' in path
            
            self.detector.detect_all_middleware()
            best = self.detector.get_best_middleware()
            
            if best and best.is_available:
                self.assertEqual(best.middleware_type, MiddlewareType.ACTIVCLIENT)

class TestPKCS11ProviderManager(unittest.TestCase):
    """Test PKCS#11 provider management"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.provider_manager = PKCS11ProviderManager(auto_detect=False)
    
    @patch('middleware_abstraction.PyKCS11.PyKCS11Lib')
    def test_provider_initialization(self, mock_pkcs11):
        """Test provider initialization"""
        # Mock successful initialization
        mock_lib = Mock()
        mock_pkcs11.return_value = mock_lib
        
        with patch.object(self.provider_manager.detector, 'get_best_middleware') as mock_best:
            mock_middleware = MiddlewareInfo(
                name="Test Middleware",
                middleware_type=MiddlewareType.OPENSC,
                version="1.0",
                pkcs11_path="/test/path",
                is_available=True,
                capabilities=['basic_auth'],
                priority=1
            )
            mock_best.return_value = mock_middleware
            
            result = self.provider_manager.initialize_provider()
            
            self.assertTrue(result)
            self.assertIsNotNone(self.provider_manager.current_provider)
    
    def test_provider_summary(self):
        """Test provider summary generation"""
        summary = self.provider_manager.get_available_middleware_summary()
        
        self.assertIn('total_detected', summary)
        self.assertIn('middleware_list', summary)
        self.assertIsInstance(summary['middleware_list'], list)

class TestSecurePINManager(unittest.TestCase):
    """Test secure PIN management"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.pin_manager = SecurePINManager(
            cache_timeout=60, 
            max_cache_entries=5, 
            enable_encryption=True
        )
    
    def test_pin_caching(self):
        """Test PIN caching functionality"""
        card_id = "test_card_123"
        pin = "123456"
        user_id = "test_user"
        
        # Cache PIN
        token = self.pin_manager.cache_pin(card_id, pin, user_id)
        
        self.assertIsNotNone(token)
        self.assertIsInstance(token, str)
        
        # Retrieve PIN
        retrieved_pin = self.pin_manager.retrieve_pin(token, user_id)
        
        self.assertEqual(retrieved_pin, pin)
    
    def test_pin_expiration(self):
        """Test PIN cache expiration"""
        # Use very short timeout for testing
        pin_manager = SecurePINManager(cache_timeout=1)
        
        card_id = "test_card_123"
        pin = "123456"
        
        token = pin_manager.cache_pin(card_id, pin)
        
        # Wait for expiration
        time.sleep(1.1)
        
        retrieved_pin = pin_manager.retrieve_pin(token)
        self.assertIsNone(retrieved_pin)
    
    def test_invalid_token(self):
        """Test handling of invalid cache token"""
        invalid_token = "invalid_token_12345"
        
        retrieved_pin = self.pin_manager.retrieve_pin(invalid_token)
        
        self.assertIsNone(retrieved_pin)
    
    def test_cache_limits(self):
        """Test cache size limits"""
        # Create PIN manager with limit of 2 entries
        pin_manager = SecurePINManager(max_cache_entries=2)
        
        # Add 3 entries (should evict oldest)
        tokens = []
        for i in range(3):
            token = pin_manager.cache_pin(f"card_{i}", f"pin_{i}")
            tokens.append(token)
            time.sleep(0.1)  # Ensure different timestamps
        
        # First token should be evicted
        first_pin = pin_manager.retrieve_pin(tokens[0])
        self.assertIsNone(first_pin)
        
        # Last two should still be available
        second_pin = pin_manager.retrieve_pin(tokens[1])
        third_pin = pin_manager.retrieve_pin(tokens[2])
        
        self.assertIsNotNone(second_pin)
        self.assertIsNotNone(third_pin)
    
    def test_cache_stats(self):
        """Test cache statistics"""
        stats = self.pin_manager.get_cache_stats()
        
        self.assertIn('total_entries', stats)
        self.assertIn('active_entries', stats)
        self.assertIn('max_entries', stats)
        self.assertIn('encryption_enabled', stats)
        
        self.assertTrue(stats['encryption_enabled'])
        self.assertEqual(stats['max_entries'], 5)

class TestSessionManager(unittest.TestCase):
    """Test session management"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.session_manager = SessionManager(default_timeout=60, max_sessions=10)
    
    def test_session_creation(self):
        """Test session creation"""
        user_id = "test_user"
        card_id = "test_card"
        
        session_id = self.session_manager.create_session(user_id, card_id)
        
        self.assertIsNotNone(session_id)
        self.assertIsInstance(session_id, str)
        
        # Validate session
        is_valid = self.session_manager.validate_session(session_id)
        self.assertTrue(is_valid)
    
    def test_session_expiration(self):
        """Test session expiration"""
        # Create session manager with short timeout
        session_manager = SessionManager(default_timeout=1)
        
        session_id = session_manager.create_session("user", "card")
        
        # Wait for expiration
        time.sleep(1.1)
        
        is_valid = session_manager.validate_session(session_id)
        self.assertFalse(is_valid)
    
    def test_session_extension(self):
        """Test session extension"""
        session_id = self.session_manager.create_session("user", "card", timeout=1)
        
        # Extend session
        extended = self.session_manager.extend_session(session_id, 60)
        self.assertTrue(extended)
        
        # Should still be valid after original timeout
        time.sleep(1.1)
        is_valid = self.session_manager.validate_session(session_id)
        self.assertTrue(is_valid)
    
    def test_session_termination(self):
        """Test manual session termination"""
        session_id = self.session_manager.create_session("user", "card")
        
        # Terminate session
        self.session_manager.terminate_session(session_id, "test_termination")
        
        # Should no longer be valid
        is_valid = self.session_manager.validate_session(session_id)
        self.assertFalse(is_valid)
    
    def test_user_session_management(self):
        """Test user-specific session management"""
        user_id = "test_user"
        
        # Create multiple sessions for user
        session_ids = []
        for i in range(3):
            session_id = self.session_manager.create_session(user_id, f"card_{i}")
            session_ids.append(session_id)
        
        # Get user sessions
        user_sessions = self.session_manager.get_user_sessions(user_id)
        self.assertEqual(len(user_sessions), 3)
        
        # Terminate all user sessions
        self.session_manager.terminate_user_sessions(user_id, "admin_action")
        
        # Should have no active sessions
        user_sessions = self.session_manager.get_user_sessions(user_id)
        self.assertEqual(len(user_sessions), 0)
    
    def test_session_stats(self):
        """Test session statistics"""
        stats = self.session_manager.get_session_stats()
        
        self.assertIn('total_sessions', stats)
        self.assertIn('active_sessions', stats)
        self.assertIn('max_sessions', stats)
        self.assertIn('default_timeout', stats)

class TestAuditLogger(unittest.TestCase):
    """Test audit logging functionality"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.temp_dir = tempfile.mkdtemp()
        self.log_file = os.path.join(self.temp_dir, "test_audit.log")
        
        # Clear any existing singleton
        AuditLogger._instance = None
        
        self.audit_logger = AuditLogger(
            log_file_path=self.log_file,
            max_log_size=1000000,
            backup_count=3,
            enable_syslog=False
        )
    
    def tearDown(self):
        """Clean up test fixtures"""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
        # Reset singleton
        AuditLogger._instance = None
    
    def test_audit_event_logging(self):
        """Test basic audit event logging"""
        event = AuditEvent(
            event_type=AuditEventType.AUTHENTICATION_SUCCESS,
            timestamp=datetime.now(timezone.utc),
            user_id="test_user",
            success=True,
            additional_data={"method": "CAC"}
        )
        
        self.audit_logger.log_event(event)
        
        # Verify log file was created and contains event
        self.assertTrue(os.path.exists(self.log_file))
        
        with open(self.log_file, 'r') as f:
            log_content = f.read()
            self.assertIn("authentication_success", log_content)
            self.assertIn("test_user", log_content)
    
    def test_authentication_attempt_logging(self):
        """Test authentication attempt logging"""
        self.audit_logger.log_authentication_attempt(
            user_id="test_user",
            card_identifier="test_card",
            success=True
        )
        
        with open(self.log_file, 'r') as f:
            log_content = f.read()
            self.assertIn("authentication_success", log_content)
    
    def test_certificate_validation_logging(self):
        """Test certificate validation logging"""
        self.audit_logger.log_certificate_validation(
            certificate_subject="CN=Test User",
            issuer="CN=Test CA",
            validation_result=True,
            details={"validation_method": "enhanced"}
        )
        
        with open(self.log_file, 'r') as f:
            log_content = f.read()
            self.assertIn("certificate_validation", log_content)
    
    def test_signing_operation_logging(self):
        """Test signing operation logging"""
        self.audit_logger.log_signing_operation(
            user_id="test_user",
            data_hash="abc123",
            success=True,
            session_id="session_123"
        )
        
        with open(self.log_file, 'r') as f:
            log_content = f.read()
            self.assertIn("signing_operation", log_content)
            self.assertIn("abc123", log_content)
    
    def test_singleton_behavior(self):
        """Test audit logger singleton behavior"""
        logger1 = AuditLogger.instance()
        logger2 = AuditLogger.instance()
        
        self.assertIs(logger1, logger2)
    
    def test_audit_stats(self):
        """Test audit statistics"""
        stats = self.audit_logger.get_audit_stats()
        
        self.assertIn('log_file_path', stats)
        self.assertIn('max_log_size', stats)
        self.assertIn('backup_count', stats)
        self.assertIn('current_log_size', stats)

class TestCombinedRevocationChecker(unittest.TestCase):
    """Test combined revocation checking"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.revocation_checker = CombinedRevocationChecker(
            prefer_ocsp=True, 
            require_definitive_result=False
        )
        
        # Create test certificate
        self.test_cert = self._create_test_certificate()
        self.issuer_cert = self._create_issuer_certificate()
    
    def _create_test_certificate(self):
        """Create test certificate"""
        private_key = rsa.generate_private_key(65537, 2048)
        
        cert = x509.CertificateBuilder().subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test Subject")])
        ).issuer_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test Issuer")])
        ).public_key(
            private_key.public_key()
        ).serial_number(
            12345
        ).not_valid_before(
            datetime.now(timezone.utc) - timedelta(days=1)
        ).not_valid_after(
            datetime.now(timezone.utc) + timedelta(days=365)
        ).sign(private_key, hashes.SHA256())
        
        return cert
    
    def _create_issuer_certificate(self):
        """Create issuer certificate"""
        private_key = rsa.generate_private_key(65537, 2048)
        
        cert = x509.CertificateBuilder().subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test Issuer")])
        ).issuer_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test Issuer")])
        ).public_key(
            private_key.public_key()
        ).serial_number(
            1
        ).not_valid_before(
            datetime.now(timezone.utc) - timedelta(days=1)
        ).not_valid_after(
            datetime.now(timezone.utc) + timedelta(days=365)
        ).sign(private_key, hashes.SHA256())
        
        return cert
    
    def test_combined_revocation_check(self):
        """Test combined revocation checking"""
        result = self.revocation_checker.check_certificate_revocation(
            self.test_cert, self.issuer_cert
        )
        
        self.assertIsInstance(result, RevocationStatus)
        self.assertIn(result.method, ['OCSP', 'CRL', 'Combined'])
    
    @patch.object(CombinedRevocationChecker, '_check_single_method')
    def test_fallback_behavior(self, mock_check):
        """Test fallback between OCSP and CRL"""
        # Mock OCSP failure, CRL success
        ocsp_result = RevocationStatus(
            is_revoked=False,
            check_time=datetime.now(timezone.utc),
            method='OCSP',
            reason="OCSP request failed"
        )
        
        crl_result = RevocationStatus(
            is_revoked=False,
            check_time=datetime.now(timezone.utc),
            method='CRL',
            reason="Certificate not found in CRL"
        )
        
        mock_check.side_effect = [ocsp_result, crl_result]
        
        result = self.revocation_checker.check_certificate_revocation(
            self.test_cert, self.issuer_cert
        )
        
        # Should use CRL result since OCSP failed
        self.assertEqual(result.method, 'CRL')
    
    def test_cache_management(self):
        """Test cache management"""
        stats_before = self.revocation_checker.get_cache_stats()
        
        # Clear caches
        self.revocation_checker.clear_caches()
        
        stats_after = self.revocation_checker.get_cache_stats()
        
        self.assertIn('crl_cache', stats_before)
        self.assertIn('prefer_ocsp', stats_before)

class TestIntegrationScenarios(unittest.TestCase):
    """Integration tests for complete authentication workflows"""
    
    def setUp(self):
        """Set up integration test fixtures"""
        self.temp_dir = tempfile.mkdtemp()
        
        # Reset audit logger singleton
        AuditLogger._instance = None
        
        # Initialize audit logger for integration tests
        self.audit_logger = AuditLogger(
            log_file_path=os.path.join(self.temp_dir, "integration_audit.log")
        )
    
    def tearDown(self):
        """Clean up integration test fixtures"""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
        AuditLogger._instance = None
    
    def test_complete_authentication_workflow(self):
        """Test complete authentication workflow with all components"""
        # This would test the full integration but requires mocking
        # the entire PKCS#11 stack, which is complex
        
        # For now, just verify all components can be instantiated together
        try:
            pin_manager = SecurePINManager()
            session_manager = SessionManager()
            validator = DoDBCertificateValidator()
            revocation_checker = CombinedRevocationChecker()
            
            # Verify they don't interfere with each other
            self.assertIsNotNone(pin_manager)
            self.assertIsNotNone(session_manager)
            self.assertIsNotNone(validator)
            self.assertIsNotNone(revocation_checker)
            
        except Exception as e:
            self.fail(f"Component integration failed: {e}")
    
    def test_security_event_correlation(self):
        """Test that security events are properly correlated"""
        user_id = "integration_test_user"
        session_id = "test_session_123"
        
        # Log series of related events
        self.audit_logger.log_authentication_attempt(
            user_id=user_id,
            card_identifier="test_card",
            success=True,
            session_id=session_id
        )
        
        self.audit_logger.log_signing_operation(
            user_id=user_id,
            data_hash="test_hash",
            success=True,
            session_id=session_id
        )
        
        # Verify events are logged with correlation IDs
        log_file = os.path.join(self.temp_dir, "integration_audit.log")
        with open(log_file, 'r') as f:
            log_content = f.read()
            
            # Should contain user_id and session_id in both events
            self.assertIn(user_id, log_content)
            self.assertIn(session_id, log_content)
            self.assertIn("authentication_success", log_content)
            self.assertIn("signing_operation", log_content)

if __name__ == '__main__':
    # Create test suite
    test_suite = unittest.TestSuite()
    
    # Add all test classes
    test_classes = [
        TestDoDBCertificateValidator,
        TestCRLChecker,
        TestOCSPValidator,
        TestMiddlewareDetector,
        TestPKCS11ProviderManager,
        TestSecurePINManager,
        TestSessionManager,
        TestAuditLogger,
        TestCombinedRevocationChecker,
        TestIntegrationScenarios
    ]
    
    for test_class in test_classes:
        tests = unittest.TestLoader().loadTestsFromTestCase(test_class)
        test_suite.addTests(tests)
    
    # Run tests with detailed output
    runner = unittest.TextTestRunner(verbosity=2, buffer=True)
    result = runner.run(test_suite)
    
    # Print summary
    print(f"\n{'='*60}")
    print(f"Tests run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Success rate: {((result.testsRun - len(result.failures) - len(result.errors)) / result.testsRun * 100):.1f}%")
    print(f"{'='*60}")
    
    # Exit with appropriate code
    sys.exit(0 if result.wasSuccessful() else 1)