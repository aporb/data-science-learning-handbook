#!/usr/bin/env python3
"""
Comprehensive Tests for Certificate Management Module

This module provides thorough testing of all certificate management components
including extraction, validation, trust store management, parsing, and monitoring.
"""

import os
import tempfile
import unittest
import logging
from datetime import datetime, timezone, timedelta
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID, ExtensionOID

# Import modules to test
from .certificate_extractor import CertificateExtractor, CertificateType, CertificateInfo
from .dod_pki_validator import DoDPKIValidator, ValidationLevel, ValidationContext
from .trust_store_manager import TrustStoreManager, TrustedCAInfo
from .certificate_parser import CertificateParser, CertificateCategory, AssuranceLevel
from .expiration_monitor import ExpirationMonitor, MonitoringConfiguration, AlertSeverity
from .certificate_manager import CertificateManager, CertificateManagementConfig

# Configure logging for tests
logging.basicConfig(level=logging.WARNING)
logger = logging.getLogger(__name__)


class TestCertificateUtils:
    """Utility class for creating test certificates."""
    
    @staticmethod
    def create_test_certificate(subject_name: str = "Test Certificate",
                              issuer_name: str = None,
                              is_ca: bool = False,
                              valid_days: int = 365,
                              key_size: int = 2048) -> x509.Certificate:
        """Create a test certificate for testing purposes."""
        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size
        )
        
        # Create subject and issuer names
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "VA"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Test City"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Organization"),
            x509.NameAttribute(NameOID.COMMON_NAME, subject_name)
        ])
        
        issuer = subject if issuer_name is None else x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "VA"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Test City"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Organization"),
            x509.NameAttribute(NameOID.COMMON_NAME, issuer_name)
        ])
        
        # Create certificate
        now = datetime.now(timezone.utc)
        cert_builder = x509.CertificateBuilder()
        cert_builder = cert_builder.subject_name(subject)
        cert_builder = cert_builder.issuer_name(issuer)
        cert_builder = cert_builder.public_key(private_key.public_key())
        cert_builder = cert_builder.serial_number(x509.random_serial_number())
        cert_builder = cert_builder.not_valid_before(now)
        cert_builder = cert_builder.not_valid_after(now + timedelta(days=valid_days))
        
        # Add basic constraints
        cert_builder = cert_builder.add_extension(
            x509.BasicConstraints(ca=is_ca, path_length=None),
            critical=True
        )
        
        # Add key usage
        if is_ca:
            cert_builder = cert_builder.add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_cert_sign=True,
                    crl_sign=True,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    content_commitment=False,
                    encipher_only=False,
                    decipher_only=False
                ),
                critical=True
            )
        else:
            cert_builder = cert_builder.add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=True,
                    key_cert_sign=False,
                    crl_sign=False,
                    data_encipherment=False,
                    key_agreement=False,
                    content_commitment=False,
                    encipher_only=False,
                    decipher_only=False
                ),
                critical=True
            )
        
        # Add subject key identifier
        cert_builder = cert_builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
            critical=False
        )
        
        # Sign certificate
        certificate = cert_builder.sign(private_key, hashes.SHA256())
        
        return certificate
    
    @staticmethod
    def create_dod_test_certificate(cert_type: str = "authentication") -> x509.Certificate:
        """Create DoD-style test certificate."""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        
        # DoD-style subject
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "U.S. Government"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "DoD"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "PKI"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "1234567890"),  # EDIPI
            x509.NameAttribute(NameOID.COMMON_NAME, "DOE.JOHN.TEST.1234567890")
        ])
        
        issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "U.S. Government"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "DoD"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "PKI"),
            x509.NameAttribute(NameOID.COMMON_NAME, "DoD Test CA")
        ])
        
        now = datetime.now(timezone.utc)
        cert_builder = x509.CertificateBuilder()
        cert_builder = cert_builder.subject_name(subject)
        cert_builder = cert_builder.issuer_name(issuer)
        cert_builder = cert_builder.public_key(private_key.public_key())
        cert_builder = cert_builder.serial_number(x509.random_serial_number())
        cert_builder = cert_builder.not_valid_before(now)
        cert_builder = cert_builder.not_valid_after(now + timedelta(days=365))
        
        # Add DoD certificate policy
        cert_builder = cert_builder.add_extension(
            x509.CertificatePolicies([
                x509.PolicyInformation(
                    policy_identifier=x509.ObjectIdentifier("2.16.840.1.101.3.2.1.3.7"),
                    policy_qualifiers=None
                )
            ]),
            critical=False
        )
        
        # Add basic constraints
        cert_builder = cert_builder.add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True
        )
        
        # Add key usage based on certificate type
        if cert_type == "authentication":
            cert_builder = cert_builder.add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=True,
                    key_cert_sign=False,
                    crl_sign=False,
                    data_encipherment=False,
                    key_agreement=False,
                    content_commitment=False,
                    encipher_only=False,
                    decipher_only=False
                ),
                critical=True
            )
            
            # Add extended key usage for client authentication
            cert_builder = cert_builder.add_extension(
                x509.ExtendedKeyUsage([
                    x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH
                ]),
                critical=True
            )
        
        # Add subject alternative name with EDIPI
        cert_builder = cert_builder.add_extension(
            x509.SubjectAlternativeName([
                x509.RFC822Name("john.doe@mail.mil"),
                x509.OtherName(
                    type_id=x509.ObjectIdentifier("2.16.840.1.101.3.6.9.1"),
                    value=b"1234567890"
                )
            ]),
            critical=False
        )
        
        # Add subject key identifier
        cert_builder = cert_builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
            critical=False
        )
        
        # Sign certificate
        certificate = cert_builder.sign(private_key, hashes.SHA256())
        
        return certificate


class TestCertificateExtractor(unittest.TestCase):
    """Test certificate extraction functionality."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
    
    def tearDown(self):
        """Clean up test fixtures."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    @patch('PyKCS11.PyKCS11Lib')
    def test_extractor_initialization(self, mock_pkcs11):
        """Test certificate extractor initialization."""
        mock_lib = Mock()
        mock_pkcs11.return_value = mock_lib
        
        extractor = CertificateExtractor(enable_enhanced_extraction=True)
        
        self.assertIsNotNone(extractor)
        self.assertTrue(extractor.enable_enhanced_extraction)
    
    def test_determine_certificate_type(self):
        """Test certificate type determination."""
        extractor = CertificateExtractor()
        
        # Test with DoD authentication certificate
        dod_cert = TestCertificateUtils.create_dod_test_certificate("authentication")
        cert_type = extractor._determine_certificate_type(dod_cert, "Authentication Certificate")
        
        self.assertEqual(cert_type, CertificateType.AUTHENTICATION)
    
    def test_enhanced_metadata_extraction(self):
        """Test enhanced metadata extraction."""
        extractor = CertificateExtractor(enable_enhanced_extraction=True)
        
        # Create test certificate with metadata
        cert = TestCertificateUtils.create_dod_test_certificate()
        
        # Create certificate info object
        from .certificate_extractor import CertificateSlotInfo
        slot_info = CertificateSlotInfo(
            slot_id=0,
            object_handle=1,
            label="Test Certificate",
            id=b"test",
            certificate_type=CertificateType.AUTHENTICATION
        )
        
        cert_info = CertificateInfo(
            certificate=cert,
            slot_info=slot_info,
            certificate_type=CertificateType.AUTHENTICATION,
            extraction_method=extractor.ExtractionMethod.PKCS11_ENHANCED,
            raw_der_data=cert.public_bytes(serialization.Encoding.DER),
            fingerprint_sha256="test_fingerprint",
            fingerprint_sha1="test_fingerprint_sha1"
        )
        
        # Extract enhanced metadata
        extractor._extract_enhanced_metadata(cert_info)
        
        # Verify metadata was extracted
        self.assertIsNotNone(cert_info.key_usage)
        self.assertIsNotNone(cert_info.certificate_policies)


class TestDoDPKIValidator(unittest.TestCase):
    """Test DoD PKI validation functionality."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.validator = DoDPKIValidator(trusted_ca_store_path=self.temp_dir)
    
    def tearDown(self):
        """Clean up test fixtures."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_validator_initialization(self):
        """Test validator initialization."""
        self.assertIsNotNone(self.validator)
        self.assertIsNotNone(self.validator.trusted_store)
    
    def test_basic_certificate_validation(self):
        """Test basic certificate validation."""
        # Create test certificate
        cert = TestCertificateUtils.create_test_certificate()
        
        # Create validation context
        context = ValidationContext(validation_level=ValidationLevel.BASIC)
        
        # Validate certificate
        result = self.validator.validate_certificate_chain(cert, context=context)
        
        self.assertIsNotNone(result)
        self.assertIsNotNone(result.certificate_subject)
    
    def test_dod_policy_validation(self):
        """Test DoD policy validation."""
        # Create DoD test certificate
        cert = TestCertificateUtils.create_dod_test_certificate()
        
        # Create validation context requiring DoD policies
        context = ValidationContext(
            validation_level=ValidationLevel.STRICT,
            require_dod_policies=True
        )
        
        # Validate certificate
        result = self.validator.validate_certificate_chain(cert, context=context)
        
        self.assertIsNotNone(result)
        # Should find DoD policies in the test certificate
        self.assertTrue(len(result.certificate_policies) > 0)
    
    def test_key_usage_validation(self):
        """Test key usage validation."""
        cert = TestCertificateUtils.create_test_certificate()
        context = ValidationContext()
        result = self.validator.validate_certificate_chain(cert, context=context)
        
        self.assertIsNotNone(result.key_usage_validation)


class TestTrustStoreManager(unittest.TestCase):
    """Test trust store management functionality."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.trust_manager = TrustStoreManager(
            trust_store_path=self.temp_dir,
            enable_auto_update=False
        )
    
    def tearDown(self):
        """Clean up test fixtures."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
        self.trust_manager.cleanup()
    
    def test_trust_manager_initialization(self):
        """Test trust manager initialization."""
        self.assertIsNotNone(self.trust_manager)
        self.assertEqual(self.trust_manager.trust_store_path, self.temp_dir)
    
    def test_add_certificate_to_trust_store(self):
        """Test adding certificate to trust store."""
        # Create test CA certificate
        ca_cert = TestCertificateUtils.create_test_certificate(
            subject_name="Test CA",
            is_ca=True
        )
        
        cert_data = ca_cert.public_bytes(serialization.Encoding.PEM)
        source_info = {'source_url': 'test://localhost'}
        
        # Add to trust store
        trust_info = self.trust_manager.add_certificate(cert_data, source_info)
        
        self.assertIsNotNone(trust_info)
        self.assertEqual(trust_info.ca_type, "ROOT")
        self.assertTrue(trust_info.is_valid)
    
    def test_get_trusted_certificates(self):
        """Test retrieving trusted certificates."""
        # Add a test certificate first
        ca_cert = TestCertificateUtils.create_test_certificate(is_ca=True)
        cert_data = ca_cert.public_bytes(serialization.Encoding.PEM)
        
        self.trust_manager.add_certificate(cert_data)
        
        # Get trusted certificates
        trusted_certs = self.trust_manager.get_trusted_certificates()
        
        self.assertGreaterEqual(len(trusted_certs), 1)
    
    def test_trust_store_statistics(self):
        """Test trust store statistics."""
        stats = self.trust_manager.get_trust_store_stats()
        
        self.assertIsNotNone(stats)
        self.assertIn('total_trusted', stats)


class TestCertificateParser(unittest.TestCase):
    """Test certificate parsing functionality."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.parser = CertificateParser(enable_enhanced_parsing=True)
    
    def test_parser_initialization(self):
        """Test parser initialization."""
        self.assertIsNotNone(self.parser)
        self.assertTrue(self.parser.enable_enhanced_parsing)
    
    def test_basic_certificate_parsing(self):
        """Test basic certificate parsing."""
        cert = TestCertificateUtils.create_test_certificate()
        metadata = self.parser.parse_certificate(cert)
        
        self.assertIsNotNone(metadata)
        self.assertIsNotNone(metadata.subject_dn)
        self.assertIsNotNone(metadata.issuer_dn)
        self.assertIsNotNone(metadata.key_info)
    
    def test_dod_certificate_parsing(self):
        """Test DoD certificate parsing."""
        cert = TestCertificateUtils.create_dod_test_certificate()
        metadata = self.parser.parse_certificate(cert)
        
        self.assertIsNotNone(metadata)
        self.assertEqual(metadata.category, CertificateCategory.DOD_END_ENTITY)
        self.assertIsNotNone(metadata.dod_identifiers.edipi)
    
    def test_key_information_extraction(self):
        """Test key information extraction."""
        cert = TestCertificateUtils.create_test_certificate(key_size=2048)
        key_info = self.parser._extract_key_information(cert)
        
        self.assertEqual(key_info.algorithm, "RSA")
        self.assertEqual(key_info.size_bits, 2048)
        self.assertFalse(key_info.is_weak)
    
    def test_certificate_categorization(self):
        """Test certificate categorization."""
        # Test CA certificate
        ca_cert = TestCertificateUtils.create_test_certificate(is_ca=True)
        ca_metadata = self.parser.parse_certificate(ca_cert)
        
        self.assertTrue(ca_metadata.is_ca_certificate)
        
        # Test end-entity certificate
        ee_cert = TestCertificateUtils.create_test_certificate(is_ca=False)
        ee_metadata = self.parser.parse_certificate(ee_cert)
        
        self.assertFalse(ee_metadata.is_ca_certificate)


class TestExpirationMonitor(unittest.TestCase):
    """Test certificate expiration monitoring."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        
        # Create monitoring configuration
        config = MonitoringConfiguration(
            critical_threshold=7,
            warning_threshold=30,
            enable_email_alerts=False,  # Disable for testing
            check_interval_hours=1
        )
        
        self.monitor = ExpirationMonitor(
            config=config,
            database_path=os.path.join(self.temp_dir, "test_monitor.db")
        )
    
    def tearDown(self):
        """Clean up test fixtures."""
        import shutil
        self.monitor.cleanup()
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_monitor_initialization(self):
        """Test monitor initialization."""
        self.assertIsNotNone(self.monitor)
        self.assertIsNotNone(self.monitor.config)
    
    def test_add_certificate_for_monitoring(self):
        """Test adding certificate for monitoring."""
        cert = TestCertificateUtils.create_test_certificate()
        
        cert_id = self.monitor.add_certificate_for_monitoring(cert)
        
        self.assertIsNotNone(cert_id)
        self.assertTrue(cert_id.startswith("cert_"))
    
    def test_expiration_checking(self):
        """Test expiration checking."""
        # Create certificate expiring soon
        expiring_cert = TestCertificateUtils.create_test_certificate(valid_days=5)
        self.monitor.add_certificate_for_monitoring(expiring_cert)
        
        # Check for expirations
        alerts = self.monitor.check_expirations()
        
        # Should generate an alert for the expiring certificate
        self.assertGreaterEqual(len(alerts), 1)
        
        # Check alert details
        alert = alerts[0]
        self.assertEqual(alert.severity, AlertSeverity.CRITICAL)
        self.assertLessEqual(alert.days_until_expiry, 7)
    
    def test_alert_severity_determination(self):
        """Test alert severity determination."""
        # Test different expiration scenarios
        self.assertEqual(
            self.monitor._determine_alert_severity(-1),
            AlertSeverity.EMERGENCY
        )
        
        self.assertEqual(
            self.monitor._determine_alert_severity(5),
            AlertSeverity.CRITICAL
        )
        
        self.assertEqual(
            self.monitor._determine_alert_severity(20),
            AlertSeverity.WARNING
        )
        
        self.assertIsNone(
            self.monitor._determine_alert_severity(100)
        )


class TestCertificateManager(unittest.TestCase):
    """Test unified certificate management."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        
        # Create management configuration
        config = CertificateManagementConfig(
            trust_store_path=self.temp_dir,
            enable_expiration_monitoring=False,  # Disable for testing
            enable_dod_compliance_checking=True
        )
        
        self.manager = CertificateManager(config)
    
    def tearDown(self):
        """Clean up test fixtures."""
        import shutil
        self.manager.cleanup()
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_manager_initialization(self):
        """Test manager initialization."""
        self.assertIsNotNone(self.manager)
        self.assertIsNotNone(self.manager.config)
        self.assertIsNotNone(self.manager.extractor)
        self.assertIsNotNone(self.manager.validator)
        self.assertIsNotNone(self.manager.parser)
        self.assertIsNotNone(self.manager.trust_manager)
    
    def test_load_certificate_file(self):
        """Test loading certificate from file."""
        # Create test certificate file
        cert = TestCertificateUtils.create_test_certificate()
        cert_path = os.path.join(self.temp_dir, "test_cert.pem")
        
        with open(cert_path, 'wb') as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        
        # Load certificate
        managed_cert = self.manager.load_certificate_file(cert_path, validate=True)
        
        self.assertIsNotNone(managed_cert)
        self.assertTrue(managed_cert.source.startswith("file:"))
        self.assertIsNotNone(managed_cert.metadata)
    
    def test_certificate_validation(self):
        """Test certificate validation through manager."""
        cert = TestCertificateUtils.create_test_certificate()
        
        result = self.manager.validate_certificate_chain(cert)
        
        self.assertIsNotNone(result)
        self.assertIsNotNone(result.certificate_subject)
    
    def test_managed_certificate_registry(self):
        """Test managed certificate registry."""
        # Load a test certificate
        cert = TestCertificateUtils.create_test_certificate()
        cert_path = os.path.join(self.temp_dir, "test_cert.pem")
        
        with open(cert_path, 'wb') as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        
        managed_cert = self.manager.load_certificate_file(cert_path)
        
        # Test registry operations
        all_certs = self.manager.get_all_managed_certificates()
        self.assertGreaterEqual(len(all_certs), 1)
        
        # Test getting specific certificate
        retrieved_cert = self.manager.get_managed_certificate(managed_cert.certificate_id)
        self.assertIsNotNone(retrieved_cert)
        self.assertEqual(retrieved_cert.certificate_id, managed_cert.certificate_id)
    
    def test_comprehensive_check(self):
        """Test comprehensive check functionality."""
        # Load a test certificate first
        cert = TestCertificateUtils.create_test_certificate()
        cert_path = os.path.join(self.temp_dir, "test_cert.pem")
        
        with open(cert_path, 'wb') as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        
        self.manager.load_certificate_file(cert_path)
        
        # Perform comprehensive check
        results = self.manager.perform_comprehensive_check()
        
        self.assertIsNotNone(results)
        self.assertIn('timestamp', results)
        self.assertIn('certificates_checked', results)
        self.assertIn('validation_results', results)
        self.assertIn('statistics', results)
    
    def test_management_statistics(self):
        """Test management statistics."""
        stats = self.manager.get_management_statistics()
        
        self.assertIsNotNone(stats)
        self.assertIn('total_certificates', stats)
        self.assertIn('valid_certificates', stats)


class TestIntegration(unittest.TestCase):
    """Integration tests for certificate management system."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
    
    def tearDown(self):
        """Clean up test fixtures."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_end_to_end_certificate_processing(self):
        """Test end-to-end certificate processing workflow."""
        # Create test certificates
        ca_cert = TestCertificateUtils.create_test_certificate(
            subject_name="Test Root CA",
            is_ca=True,
            valid_days=3650
        )
        
        end_cert = TestCertificateUtils.create_dod_test_certificate()
        
        # Initialize certificate manager
        config = CertificateManagementConfig(
            trust_store_path=self.temp_dir,
            enable_expiration_monitoring=False,
            enable_dod_compliance_checking=True
        )
        manager = CertificateManager(config)
        
        try:
            # 1. Add CA to trust store
            ca_cert_data = ca_cert.public_bytes(serialization.Encoding.PEM)
            trust_info = manager.add_certificate_to_trust_store(ca_cert_data)
            self.assertIsNotNone(trust_info)
            
            # 2. Load end-entity certificate
            cert_path = os.path.join(self.temp_dir, "end_cert.pem")
            with open(cert_path, 'wb') as f:
                f.write(end_cert.public_bytes(serialization.Encoding.PEM))
            
            managed_cert = manager.load_certificate_file(cert_path, validate=True)
            self.assertIsNotNone(managed_cert)
            
            # 3. Verify certificate was parsed correctly
            self.assertIsNotNone(managed_cert.metadata)
            self.assertEqual(managed_cert.metadata.category, CertificateCategory.DOD_END_ENTITY)
            
            # 4. Check validation results
            self.assertIsNotNone(managed_cert.validation_result)
            
            # 5. Verify statistics
            stats = manager.get_management_statistics()
            self.assertGreater(stats['total_certificates'], 0)
            
            # 6. Test comprehensive check
            check_results = manager.perform_comprehensive_check()
            self.assertIsNotNone(check_results)
            self.assertGreater(check_results['certificates_checked'], 0)
            
        finally:
            manager.cleanup()


def create_test_suite():
    """Create comprehensive test suite."""
    suite = unittest.TestSuite()
    
    # Add test classes
    test_classes = [
        TestCertificateExtractor,
        TestDoDPKIValidator,
        TestTrustStoreManager,
        TestCertificateParser,
        TestExpirationMonitor,
        TestCertificateManager,
        TestIntegration
    ]
    
    for test_class in test_classes:
        tests = unittest.TestLoader().loadTestsFromTestCase(test_class)
        suite.addTests(tests)
    
    return suite


def run_tests():
    """Run all certificate management tests."""
    # Configure test logging
    logging.basicConfig(
        level=logging.WARNING,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Create and run test suite
    suite = create_test_suite()
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Print summary
    print(f"\nTest Summary:")
    print(f"Tests run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    
    if result.failures:
        print("\nFailures:")
        for test, traceback in result.failures:
            print(f"  {test}: {traceback}")
    
    if result.errors:
        print("\nErrors:")
        for test, traceback in result.errors:
            print(f"  {test}: {traceback}")
    
    return result.wasSuccessful()


if __name__ == "__main__":
    success = run_tests()
    exit(0 if success else 1)