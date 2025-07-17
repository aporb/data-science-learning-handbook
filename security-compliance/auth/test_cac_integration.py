#!/usr/bin/env python3
"""
Test Suite for CAC/PIV Smart Card Integration
Comprehensive tests for DoD Common Access Card authentication
"""

import unittest
from unittest.mock import Mock, patch, MagicMock
import os
import sys
from datetime import datetime, timezone, timedelta
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID, ExtensionOID

# Add the auth module to the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from cac_piv_integration import (
    CACPIVAuthenticator, 
    CACAuthenticationManager, 
    CACCredentials
)
from cac_config import CACConfig, NetworkClassificationConfig

class TestCACCredentials(unittest.TestCase):
    """Test CACCredentials data class"""
    
    def setUp(self):
        """Set up test fixtures"""
        # Create a mock certificate
        self.mock_cert = Mock(spec=x509.Certificate)
        self.mock_cert.subject.rfc4514_string.return_value = "CN=DOE.JOHN.1234567890,OU=CONTRACTOR,O=U.S. Government,C=US"
        self.mock_cert.issuer.rfc4514_string.return_value = "CN=DOD ID CA-59,OU=PKI,OU=DoD,O=U.S. Government,C=US"
        self.mock_cert.serial_number = 1234567890
        
    def test_cac_credentials_creation(self):
        """Test CACCredentials object creation"""
        credentials = CACCredentials(
            certificate=self.mock_cert,
            subject_dn="CN=DOE.JOHN.1234567890",
            issuer_dn="CN=DOD ID CA-59",
            serial_number="1234567890",
            edipi="1234567890",
            email="john.doe@mail.mil",
            organization="U.S. Government",
            clearance_level="SECRET"
        )
        
        self.assertEqual(credentials.edipi, "1234567890")
        self.assertEqual(credentials.email, "john.doe@mail.mil")
        self.assertEqual(credentials.clearance_level, "SECRET")
        self.assertEqual(credentials.organization, "U.S. Government")

class TestCACPIVAuthenticator(unittest.TestCase):
    """Test CACPIVAuthenticator class"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.mock_pkcs11_lib_path = "/usr/lib/opensc-pkcs11.so"
        
    @patch('cac_piv_integration.PyKCS11.PyKCS11Lib')
    @patch('cac_piv_integration.os.path.exists')
    def test_pkcs11_library_detection(self, mock_exists, mock_pkcs11):
        """Test PKCS#11 library auto-detection"""
        # Mock library exists
        mock_exists.side_effect = lambda path: path == "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so"
        
        authenticator = CACPIVAuthenticator()
        
        self.assertEqual(authenticator.pkcs11_lib_path, "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so")
        mock_pkcs11.assert_called_once()
    
    @patch('cac_piv_integration.PyKCS11.PyKCS11Lib')
    @patch('cac_piv_integration.os.path.exists')
    def test_pkcs11_library_not_found(self, mock_exists, mock_pkcs11):
        """Test PKCS#11 library not found error"""
        # Mock no library exists
        mock_exists.return_value = False
        
        with self.assertRaises(FileNotFoundError):
            CACPIVAuthenticator()
    
    @patch('cac_piv_integration.PyKCS11.PyKCS11Lib')
    @patch('cac_piv_integration.os.path.exists')
    def test_get_available_slots(self, mock_exists, mock_pkcs11):
        """Test getting available smart card slots"""
        mock_exists.return_value = True
        mock_lib = Mock()
        mock_lib.getSlotList.return_value = [0, 1, 2]
        mock_pkcs11.return_value = mock_lib
        
        authenticator = CACPIVAuthenticator(self.mock_pkcs11_lib_path)
        slots = authenticator.get_available_slots()
        
        self.assertEqual(slots, [0, 1, 2])
        mock_lib.getSlotList.assert_called_with(tokenPresent=True)
    
    @patch('cac_piv_integration.PyKCS11.PyKCS11Lib')
    @patch('cac_piv_integration.os.path.exists')
    def test_open_session_success(self, mock_exists, mock_pkcs11):
        """Test successful session opening"""
        mock_exists.return_value = True
        mock_lib = Mock()
        mock_session = Mock()
        mock_lib.getSlotList.return_value = [0]
        mock_lib.openSession.return_value = mock_session
        mock_pkcs11.return_value = mock_lib
        
        authenticator = CACPIVAuthenticator(self.mock_pkcs11_lib_path)
        result = authenticator.open_session()
        
        self.assertTrue(result)
        self.assertEqual(authenticator.session, mock_session)
    
    @patch('cac_piv_integration.PyKCS11.PyKCS11Lib')
    @patch('cac_piv_integration.os.path.exists')
    def test_pin_authentication(self, mock_exists, mock_pkcs11):
        """Test PIN authentication"""
        mock_exists.return_value = True
        mock_lib = Mock()
        mock_session = Mock()
        mock_lib.openSession.return_value = mock_session
        mock_pkcs11.return_value = mock_lib
        
        authenticator = CACPIVAuthenticator(self.mock_pkcs11_lib_path)
        authenticator.session = mock_session
        
        result = authenticator.authenticate_pin("123456")
        
        self.assertTrue(result)
        mock_session.login.assert_called_with("123456")

class TestCertificateHandling(unittest.TestCase):
    """Test certificate handling and validation"""
    
    def setUp(self):
        """Set up test certificate"""
        # Create a test certificate
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "DC"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Washington"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "U.S. Government"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "DoD"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "PKI"),
            x509.NameAttribute(NameOID.COMMON_NAME, "DOE.JOHN.1234567890"),
        ])
        
        self.test_cert = x509.CertificateBuilder().subject_name(
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
            x509.SubjectAlternativeName([
                x509.RFC822Name("john.doe@mail.mil"),
                x509.OtherName(
                    x509.ObjectIdentifier("2.16.840.1.101.3.6.6"),
                    b"1234567890"
                )
            ]),
            critical=False,
        ).add_extension(
            x509.CertificatePolicies([
                x509.PolicyInformation(
                    x509.ObjectIdentifier("2.16.840.1.101.3.2.1.3.2"),
                    None
                )
            ]),
            critical=False,
        ).sign(private_key, hashes.SHA256())
    
    @patch('cac_piv_integration.PyKCS11.PyKCS11Lib')
    @patch('cac_piv_integration.os.path.exists')
    def test_extract_cac_credentials(self, mock_exists, mock_pkcs11):
        """Test extracting credentials from CAC certificate"""
        mock_exists.return_value = True
        mock_pkcs11.return_value = Mock()
        
        authenticator = CACPIVAuthenticator("/mock/path")
        credentials = authenticator.extract_cac_credentials(self.test_cert)
        
        self.assertIsInstance(credentials, CACCredentials)
        self.assertEqual(credentials.edipi, "1234567890")
        self.assertEqual(credentials.email, "john.doe@mail.mil")
        self.assertEqual(credentials.clearance_level, "SECRET")
        self.assertIn("U.S. Government", credentials.organization)
    
    @patch('cac_piv_integration.PyKCS11.PyKCS11Lib')
    @patch('cac_piv_integration.os.path.exists')
    def test_certificate_validation(self, mock_exists, mock_pkcs11):
        """Test certificate chain validation"""
        mock_exists.return_value = True
        mock_pkcs11.return_value = Mock()
        
        authenticator = CACPIVAuthenticator("/mock/path")
        
        # Test valid certificate (not expired, DoD issuer)
        result = authenticator.verify_certificate_chain(self.test_cert)
        self.assertTrue(result)
    
    @patch('cac_piv_integration.PyKCS11.PyKCS11Lib')
    @patch('cac_piv_integration.os.path.exists')
    def test_clearance_level_determination(self, mock_exists, mock_pkcs11):
        """Test clearance level determination from certificate"""
        mock_exists.return_value = True
        mock_pkcs11.return_value = Mock()
        
        authenticator = CACPIVAuthenticator("/mock/path")
        clearance = authenticator._determine_clearance_level(self.test_cert)
        
        self.assertEqual(clearance, "SECRET")

class TestCACAuthenticationManager(unittest.TestCase):
    """Test high-level authentication manager"""
    
    @patch('cac_piv_integration.CACPIVAuthenticator')
    def test_authentication_workflow(self, mock_authenticator_class):
        """Test complete authentication workflow"""
        # Mock authenticator instance
        mock_authenticator = Mock()
        mock_authenticator.open_session.return_value = True
        mock_authenticator.authenticate_pin.return_value = True
        mock_authenticator.get_certificates.return_value = [Mock()]
        mock_authenticator.verify_certificate_chain.return_value = True
        
        # Mock credentials
        mock_credentials = CACCredentials(
            certificate=Mock(),
            subject_dn="CN=DOE.JOHN.1234567890",
            issuer_dn="CN=DOD ID CA-59",
            serial_number="1234567890",
            edipi="1234567890",
            email="john.doe@mail.mil",
            organization="U.S. Government",
            clearance_level="SECRET"
        )
        mock_authenticator.extract_cac_credentials.return_value = mock_credentials
        mock_authenticator_class.return_value = mock_authenticator
        
        # Test authentication
        auth_manager = CACAuthenticationManager()
        result = auth_manager.authenticate_user("123456")
        
        self.assertIsNotNone(result)
        self.assertEqual(result.edipi, "1234567890")
        self.assertEqual(auth_manager.current_credentials, mock_credentials)
    
    def test_user_roles_determination(self):
        """Test user role determination from credentials"""
        credentials = CACCredentials(
            certificate=Mock(),
            subject_dn="CN=DOE.JOHN.1234567890",
            issuer_dn="CN=DOD ID CA-59,OU=PKI,OU=DoD,O=U.S. Government,C=US",
            serial_number="1234567890",
            edipi="1234567890",
            email="john.doe@mail.mil",
            organization="U.S. Government",
            clearance_level="SECRET"
        )
        
        auth_manager = CACAuthenticationManager()
        roles = auth_manager.get_user_roles(credentials)
        
        expected_roles = [
            "authenticated_user",
            "clearance_secret",
            "org_u.s._government",
            "dod_user"
        ]
        
        for role in expected_roles:
            self.assertIn(role, roles)

class TestConfiguration(unittest.TestCase):
    """Test configuration classes"""
    
    def test_cac_config_structure(self):
        """Test CACConfig data structure"""
        config = CACConfig()
        
        # Test required attributes exist
        self.assertIsInstance(config.PKCS11_PATHS, dict)
        self.assertIsInstance(config.DOD_CA_OIDS, dict)
        self.assertIsInstance(config.CLEARANCE_POLICY_OIDS, dict)
        self.assertIsInstance(config.SECURITY_SETTINGS, dict)
        
        # Test specific values
        self.assertIn('windows', config.PKCS11_PATHS)
        self.assertIn('linux', config.PKCS11_PATHS)
        self.assertIn('darwin', config.PKCS11_PATHS)
        
        self.assertIn('UNCLASSIFIED', config.CLEARANCE_POLICY_OIDS)
        self.assertIn('SECRET', config.CLEARANCE_POLICY_OIDS)
        self.assertIn('TOP_SECRET', config.CLEARANCE_POLICY_OIDS)
    
    def test_network_classification_config(self):
        """Test network classification configuration"""
        unclass_config = NetworkClassificationConfig.get_classification_config('UNCLASSIFIED')
        secret_config = NetworkClassificationConfig.get_classification_config('SECRET')
        
        self.assertEqual(unclass_config['banner_text'], 'UNCLASSIFIED')
        self.assertEqual(secret_config['banner_text'], 'SECRET')
        self.assertTrue(secret_config['encryption_required'])
        self.assertFalse(unclass_config['encryption_required'])

class TestSecurityFeatures(unittest.TestCase):
    """Test security-specific features"""
    
    @patch.dict(os.environ, {
        'CAC_DEBUG': 'true',
        'CAC_CARD_TIMEOUT': '45',
        'NETWORK_CLASSIFICATION': 'SECRET'
    })
    def test_environment_configuration(self):
        """Test environment-based configuration"""
        from cac_config import CACEnvironmentConfig
        
        config = CACEnvironmentConfig.get_config()
        
        self.assertTrue(config['enable_debug'])
        self.assertEqual(config['card_reader_timeout'], 45)
        self.assertEqual(config['network_classification'], 'SECRET')
    
    @patch('cac_piv_integration.PyKCS11.PyKCS11Lib')
    @patch('cac_piv_integration.os.path.exists')
    def test_session_cleanup(self, mock_exists, mock_pkcs11):
        """Test proper session cleanup"""
        mock_exists.return_value = True
        mock_session = Mock()
        mock_lib = Mock()
        mock_lib.openSession.return_value = mock_session
        mock_pkcs11.return_value = mock_lib
        
        authenticator = CACPIVAuthenticator("/mock/path")
        authenticator.session = mock_session
        
        authenticator.close_session()
        
        mock_session.logout.assert_called_once()
        mock_session.closeSession.assert_called_once()
        self.assertIsNone(authenticator.session)

class TestErrorHandling(unittest.TestCase):
    """Test error handling and edge cases"""
    
    @patch('cac_piv_integration.PyKCS11.PyKCS11Lib')
    @patch('cac_piv_integration.os.path.exists')
    def test_no_smart_card_present(self, mock_exists, mock_pkcs11):
        """Test handling when no smart card is present"""
        mock_exists.return_value = True
        mock_lib = Mock()
        mock_lib.getSlotList.return_value = []  # No slots with tokens
        mock_pkcs11.return_value = mock_lib
        
        authenticator = CACPIVAuthenticator("/mock/path")
        result = authenticator.open_session()
        
        self.assertFalse(result)
    
    @patch('cac_piv_integration.CACPIVAuthenticator')
    def test_authentication_failure(self, mock_authenticator_class):
        """Test authentication failure handling"""
        mock_authenticator = Mock()
        mock_authenticator.open_session.return_value = False
        mock_authenticator_class.return_value = mock_authenticator
        
        auth_manager = CACAuthenticationManager()
        result = auth_manager.authenticate_user("123456")
        
        self.assertIsNone(result)
    
    @patch('cac_piv_integration.CACPIVAuthenticator')
    def test_no_certificates_found(self, mock_authenticator_class):
        """Test handling when no certificates are found"""
        mock_authenticator = Mock()
        mock_authenticator.open_session.return_value = True
        mock_authenticator.authenticate_pin.return_value = True
        mock_authenticator.get_certificates.return_value = []  # No certificates
        mock_authenticator_class.return_value = mock_authenticator
        
        auth_manager = CACAuthenticationManager()
        result = auth_manager.authenticate_user("123456")
        
        self.assertIsNone(result)

if __name__ == '__main__':
    # Create test suite
    test_suite = unittest.TestSuite()
    
    # Add test cases
    test_classes = [
        TestCACCredentials,
        TestCACPIVAuthenticator,
        TestCertificateHandling,
        TestCACAuthenticationManager,
        TestConfiguration,
        TestSecurityFeatures,
        TestErrorHandling
    ]
    
    for test_class in test_classes:
        tests = unittest.TestLoader().loadTestsFromTestCase(test_class)
        test_suite.addTests(tests)
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(test_suite)
    
    # Exit with appropriate code
    sys.exit(0 if result.wasSuccessful() else 1)
