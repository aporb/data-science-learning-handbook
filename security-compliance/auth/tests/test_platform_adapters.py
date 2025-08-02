#!/usr/bin/env python3
"""
Platform Adapter Integration Tests
Tests for all platform-specific authentication adapters
"""

import unittest
import base64
import json
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime, timezone, timedelta
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from ..platform_adapters import (
    PlatformConfig, AuthenticationResult, AuthenticationStatus,
    AdvanaAuthAdapter, QlikAuthAdapter, DatabricksAuthAdapter, NavyJupiterAuthAdapter
)

class TestPlatformAdapters(unittest.TestCase):
    """Test suite for platform adapters"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.test_certificate, self.test_private_key = self._generate_test_certificate()
        self.test_challenge = b"test_challenge_data"
        self.test_signature = self._sign_data(self.test_challenge, self.test_private_key)
        
        # Common test configuration
        self.base_config = PlatformConfig(
            platform_name="test",
            base_url="https://test.example.com",
            api_version="v1",
            authentication_endpoint="/auth",
            token_endpoint="/token",
            user_info_endpoint="/user",
            timeout=30,
            verify_ssl=False  # For testing
        )
    
    def _generate_test_certificate(self):
        """Generate test certificate and private key"""
        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        
        # Create certificate
        subject = issuer = x509.Name([
            x509.NameAttribute(x509.oid.NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(x509.oid.NameOID.STATE_OR_PROVINCE_NAME, "Virginia"),
            x509.NameAttribute(x509.oid.NameOID.LOCALITY_NAME, "Arlington"),
            x509.NameAttribute(x509.oid.NameOID.ORGANIZATION_NAME, "U.S. Department of Defense"),
            x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "Test User"),
        ])
        
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.now(timezone.utc)
        ).not_valid_after(
            datetime.now(timezone.utc) + timedelta(days=365)
        ).add_extension(
            x509.SubjectAlternativeName([
                x509.RFC822Name("test.user@mil"),
                x509.OtherName(
                    type_id=x509.ObjectIdentifier("2.16.840.1.101.3.6.6"),
                    value=b"1234567890"  # Test EDIPI
                )
            ]),
            critical=False,
        ).sign(private_key, hashes.SHA256())
        
        return cert, private_key
    
    def _sign_data(self, data, private_key):
        """Sign data with private key"""
        from cryptography.hazmat.primitives.asymmetric import padding
        signature = private_key.sign(
            data,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return signature
    
    def test_advana_adapter_initialization(self):
        """Test Advana adapter initialization"""
        config = self.base_config
        config.platform_name = "advana"
        config.additional_config = {
            "tenant_id": "test-tenant",
            "environment": "test",
            "classification_level": "UNCLASSIFIED"
        }
        
        adapter = AdvanaAuthAdapter(config)
        
        self.assertEqual(adapter.config.platform_name, "advana")
        self.assertEqual(adapter.tenant_id, "test-tenant")
        self.assertEqual(adapter.environment, "test")
        self.assertEqual(adapter.classification_level, "UNCLASSIFIED")
    
    @patch('requests.Session.request')
    def test_advana_authentication_success(self, mock_request):
        """Test successful Advana authentication"""
        # Mock successful API response
        mock_response = Mock()
        mock_response.json.return_value = {
            "status": "success",
            "access_token": "test_token",
            "advana_token": "advana_token",
            "expires_in": 3600,
            "user_profile": {"id": "test_user"},
            "permissions": ["read", "write"]
        }
        mock_response.raise_for_status.return_value = None
        mock_request.return_value = mock_response
        
        # Setup adapter
        config = self.base_config
        config.platform_name = "advana"
        config.additional_config = {"tenant_id": "test-tenant"}
        adapter = AdvanaAuthAdapter(config)
        
        # Test authentication
        certificate_data = self.test_certificate.public_bytes(serialization.Encoding.DER)
        result = adapter.authenticate_with_cac(
            certificate_data=certificate_data,
            signature=self.test_signature,
            challenge=self.test_challenge
        )
        
        self.assertEqual(result.status, AuthenticationStatus.SUCCESS)
        self.assertEqual(result.session_token, "test_token")
        self.assertEqual(result.platform_token, "advana_token")
        self.assertIn("advana_user", result.roles)
    
    @patch('requests.Session.request')
    def test_advana_authentication_failure(self, mock_request):
        """Test failed Advana authentication"""
        # Mock failed API response
        mock_response = Mock()
        mock_response.json.return_value = {
            "status": "failed",
            "error": "Invalid certificate"
        }
        mock_response.raise_for_status.return_value = None
        mock_request.return_value = mock_response
        
        # Setup adapter
        config = self.base_config
        config.platform_name = "advana"
        adapter = AdvanaAuthAdapter(config)
        
        # Test authentication
        certificate_data = self.test_certificate.public_bytes(serialization.Encoding.DER)
        result = adapter.authenticate_with_cac(
            certificate_data=certificate_data,
            signature=self.test_signature,
            challenge=self.test_challenge
        )
        
        self.assertEqual(result.status, AuthenticationStatus.FAILED)
        self.assertEqual(result.error_message, "Invalid certificate")
    
    def test_qlik_adapter_initialization(self):
        """Test Qlik adapter initialization"""
        config = self.base_config
        config.platform_name = "qlik"
        config.additional_config = {
            "qlik_domain": "test.qlik.local",
            "virtual_proxy": "cac",
            "jwt_secret": "test_secret"
        }
        
        adapter = QlikAuthAdapter(config)
        
        self.assertEqual(adapter.config.platform_name, "qlik")
        self.assertEqual(adapter.qlik_domain, "test.qlik.local")
        self.assertEqual(adapter.virtual_proxy, "cac")
        self.assertEqual(adapter.jwt_secret, "test_secret")
    
    @patch('requests.Session.request')
    def test_qlik_authentication_with_jwt(self, mock_request):
        """Test Qlik authentication with JWT token creation"""
        # Mock successful API response
        mock_response = Mock()
        mock_response.json.return_value = {
            "success": True,
            "session_token": "qlik_session",
            "ticket": "QlikTicket123",
            "expires_in": 3600
        }
        mock_response.raise_for_status.return_value = None
        mock_request.return_value = mock_response
        
        # Setup adapter with JWT secret
        config = self.base_config
        config.platform_name = "qlik"
        config.additional_config = {
            "qlik_domain": "test.local",
            "jwt_secret": "test_secret_key_32_characters_long"
        }
        adapter = QlikAuthAdapter(config)
        
        # Test authentication
        certificate_data = self.test_certificate.public_bytes(serialization.Encoding.DER)
        result = adapter.authenticate_with_cac(
            certificate_data=certificate_data,
            signature=self.test_signature,
            challenge=self.test_challenge
        )
        
        self.assertEqual(result.status, AuthenticationStatus.SUCCESS)
        self.assertEqual(result.session_token, "qlik_session")
        self.assertEqual(result.platform_token, "QlikTicket123")
        self.assertIn("qlik_user", result.roles)
    
    def test_databricks_adapter_initialization(self):
        """Test Databricks adapter initialization"""
        config = self.base_config
        config.platform_name = "databricks"
        config.additional_config = {
            "workspace_id": "test-workspace",
            "workspace_url": "https://test.databricks.com",
            "auth_method": "personal_access_token"
        }
        
        adapter = DatabricksAuthAdapter(config)
        
        self.assertEqual(adapter.config.platform_name, "databricks")
        self.assertEqual(adapter.workspace_id, "test-workspace")
        self.assertEqual(adapter.auth_method, "personal_access_token")
    
    @patch('requests.Session.request')
    def test_databricks_user_creation(self, mock_request):
        """Test Databricks user creation process"""
        # Mock responses for user search and creation
        def mock_request_side_effect(*args, **kwargs):
            endpoint = kwargs.get('url', '').split('/')[-1]
            
            if 'scim/v2/Users' in kwargs['url'] and kwargs['method'] == 'GET':
                # User search - return empty
                mock_resp = Mock()
                mock_resp.json.return_value = {"Resources": []}
                mock_resp.raise_for_status.return_value = None
                return mock_resp
            elif 'scim/v2/Users' in kwargs['url'] and kwargs['method'] == 'POST':
                # User creation
                mock_resp = Mock()
                mock_resp.json.return_value = {
                    "id": "test_user_id",
                    "userName": "test.user@mil",
                    "active": True
                }
                mock_resp.raise_for_status.return_value = None
                return mock_resp
            elif 'token/create' in kwargs['url']:
                # Token creation
                mock_resp = Mock()
                mock_resp.json.return_value = {
                    "token_value": "databricks_token",
                    "token_info": {"token_id": "token_123"}
                }
                mock_resp.raise_for_status.return_value = None
                return mock_resp
            
            # Default response
            mock_resp = Mock()
            mock_resp.json.return_value = {}
            mock_resp.raise_for_status.return_value = None
            return mock_resp
        
        mock_request.side_effect = mock_request_side_effect
        
        # Setup adapter
        config = self.base_config
        config.platform_name = "databricks"
        config.additional_config = {"workspace_id": "test-workspace"}
        adapter = DatabricksAuthAdapter(config)
        
        # Test authentication
        certificate_data = self.test_certificate.public_bytes(serialization.Encoding.DER)
        result = adapter.authenticate_with_cac(
            certificate_data=certificate_data,
            signature=self.test_signature,
            challenge=self.test_challenge
        )
        
        self.assertEqual(result.status, AuthenticationStatus.SUCCESS)
        self.assertEqual(result.session_token, "databricks_token")
        self.assertIn("databricks_user", result.roles)
    
    def test_navy_jupiter_adapter_initialization(self):
        """Test Navy Jupiter adapter initialization"""
        config = self.base_config
        config.platform_name = "navy_jupiter"
        config.additional_config = {
            "navy_network": "NIPR",
            "classification_level": "UNCLASSIFIED",
            "command_code": "TEST_CMD",
            "require_dual_auth": False
        }
        
        adapter = NavyJupiterAuthAdapter(config)
        
        self.assertEqual(adapter.config.platform_name, "navy_jupiter")
        self.assertEqual(adapter.navy_network, "NIPR")
        self.assertEqual(adapter.classification_level, "UNCLASSIFIED")
        self.assertEqual(adapter.command_code, "TEST_CMD")
        self.assertFalse(adapter.require_dual_auth)
    
    @patch('requests.Session.request')
    def test_navy_jupiter_authentication_success(self, mock_request):
        """Test successful Navy Jupiter authentication"""
        # Mock successful API response
        mock_response = Mock()
        mock_response.json.return_value = {
            "status": "success",
            "access_token": "navy_token",
            "navy_session_token": "navy_session",
            "expires_in": 3600,
            "user_profile": {"id": "test_navy_user"},
            "permissions": ["navy:basic_access"],
            "session_id": "session_123",
            "security_context": {"classification": "UNCLASSIFIED"}
        }
        mock_response.raise_for_status.return_value = None
        mock_request.return_value = mock_response
        
        # Setup adapter
        config = self.base_config
        config.platform_name = "navy_jupiter"
        config.additional_config = {
            "navy_network": "NIPR",
            "classification_level": "UNCLASSIFIED"
        }
        adapter = NavyJupiterAuthAdapter(config)
        
        # Test authentication
        certificate_data = self.test_certificate.public_bytes(serialization.Encoding.DER)
        result = adapter.authenticate_with_cac(
            certificate_data=certificate_data,
            signature=self.test_signature,
            challenge=self.test_challenge
        )
        
        self.assertEqual(result.status, AuthenticationStatus.SUCCESS)
        self.assertEqual(result.session_token, "navy_token")
        self.assertEqual(result.platform_token, "navy_session")
        self.assertIn("navy_jupiter_user", result.roles)
        self.assertIn("navy:basic_access", result.permissions)
    
    def test_navy_jupiter_dual_auth_requirement(self):
        """Test Navy Jupiter dual authentication requirement"""
        config = self.base_config
        config.platform_name = "navy_jupiter"
        config.additional_config = {
            "navy_network": "SIPR",
            "classification_level": "SECRET",
            "require_dual_auth": True
        }
        adapter = NavyJupiterAuthAdapter(config)
        
        # Test authentication without secondary auth
        certificate_data = self.test_certificate.public_bytes(serialization.Encoding.DER)
        result = adapter.authenticate_with_cac(
            certificate_data=certificate_data,
            signature=self.test_signature,
            challenge=self.test_challenge
        )
        
        self.assertEqual(result.status, AuthenticationStatus.PENDING)
        self.assertIn("Secondary authentication required", result.error_message)
        self.assertTrue(result.metadata.get("requires_dual_auth"))
    
    def test_certificate_attribute_extraction(self):
        """Test certificate attribute extraction across adapters"""
        certificate_data = self.test_certificate.public_bytes(serialization.Encoding.DER)
        
        # Test Advana adapter
        advana_config = self.base_config
        advana_config.platform_name = "advana"
        advana_adapter = AdvanaAuthAdapter(advana_config)
        
        user_id = advana_adapter._extract_user_id_from_certificate(certificate_data)
        self.assertIsNotNone(user_id)
        
        # Test Navy Jupiter adapter
        navy_config = self.base_config
        navy_config.platform_name = "navy_jupiter"
        navy_adapter = NavyJupiterAuthAdapter(navy_config)
        
        navy_attrs = navy_adapter._extract_navy_certificate_attributes(certificate_data)
        self.assertIn("edipi", navy_attrs)
        self.assertIn("email", navy_attrs)
        self.assertIn("is_dod_cert", navy_attrs)
    
    def test_signature_verification(self):
        """Test digital signature verification"""
        certificate_data = self.test_certificate.public_bytes(serialization.Encoding.DER)
        
        # Test with correct signature
        adapter = AdvanaAuthAdapter(self.base_config)
        is_valid = adapter._verify_signature(certificate_data, self.test_signature, self.test_challenge)
        self.assertTrue(is_valid)
        
        # Test with incorrect signature
        wrong_signature = b"wrong_signature"
        is_valid = adapter._verify_signature(certificate_data, wrong_signature, self.test_challenge)
        self.assertFalse(is_valid)
    
    def test_platform_info_retrieval(self):
        """Test platform information retrieval"""
        adapters = [
            AdvanaAuthAdapter(self.base_config),
            QlikAuthAdapter(self.base_config),
            DatabricksAuthAdapter(self.base_config),
            NavyJupiterAuthAdapter(self.base_config)
        ]
        
        for adapter in adapters:
            platform_info = adapter.get_platform_info()
            
            self.assertIn("platform_name", platform_info)
            self.assertIn("supports_cac", platform_info)
            self.assertIn("supports_token_refresh", platform_info)
            self.assertTrue(platform_info["supports_cac"])
    
    @patch('requests.Session.request')
    def test_token_refresh_functionality(self, mock_request):
        """Test token refresh across adapters"""
        # Mock successful refresh response
        mock_response = Mock()
        mock_response.json.return_value = {
            "status": "success",
            "access_token": "new_token",
            "expires_in": 3600
        }
        mock_response.raise_for_status.return_value = None
        mock_request.return_value = mock_response
        
        adapter = AdvanaAuthAdapter(self.base_config)
        result = adapter.refresh_token("old_token")
        
        self.assertEqual(result.status, AuthenticationStatus.SUCCESS)
        self.assertEqual(result.session_token, "new_token")
    
    @patch('requests.Session.request')
    def test_session_validation(self, mock_request):
        """Test session validation across adapters"""
        # Mock successful validation response
        mock_response = Mock()
        mock_response.json.return_value = {"valid": True}
        mock_response.raise_for_status.return_value = None
        mock_request.return_value = mock_response
        
        adapter = AdvanaAuthAdapter(self.base_config)
        is_valid = adapter.validate_session("test_token")
        
        self.assertTrue(is_valid)

if __name__ == '__main__':
    unittest.main()