#!/usr/bin/env python3
"""
Integration Tests for CAC/PIV Authentication System
End-to-end testing across all components
"""

import unittest
import asyncio
import json
import base64
from unittest.mock import Mock, patch
from datetime import datetime, timezone
from fastapi.testclient import TestClient

from ..api.auth_api import create_auth_app, AuthAPIConfig
from ..platform_config_manager import PlatformConfigManager
from ..platform_adapters import PlatformConfig

class TestIntegration(unittest.TestCase):
    """Integration tests for the complete CAC/PIV system"""
    
    @classmethod
    def setUpClass(cls):
        """Set up test class"""
        # Create test API configuration
        cls.api_config = AuthAPIConfig()
        cls.api_config.debug = True
        cls.api_config.require_https = False
        cls.api_config.cors_origins = ["*"]
        
        # Create test app
        cls.app = create_auth_app(cls.api_config)
        cls.client = TestClient(cls.app)
        
        # Test data
        cls.test_certificate_b64 = base64.b64encode(b"test_certificate_data").decode()
        cls.test_signature_b64 = base64.b64encode(b"test_signature_data").decode()
        cls.test_challenge_b64 = base64.b64encode(b"test_challenge_data").decode()
    
    def test_health_endpoint(self):
        """Test API health endpoint"""
        response = self.client.get("/health")
        
        self.assertEqual(response.status_code, 200)
        data = response.json()
        
        self.assertEqual(data["status"], "healthy")
        self.assertIn("timestamp", data)
        self.assertIn("version", data)
        self.assertIn("services", data)
    
    def test_challenge_generation(self):
        """Test challenge generation endpoint"""
        request_data = {
            "platform": "advana",
            "client_info": {"ip": "192.168.1.1"}
        }
        
        response = self.client.post("/api/v1/auth/challenge", json=request_data)
        
        self.assertEqual(response.status_code, 200)
        data = response.json()
        
        self.assertIn("challenge", data)
        self.assertIn("expires_in", data)
        self.assertIn("challenge_id", data)
        self.assertEqual(data["expires_in"], 300)  # 5 minutes
    
    @patch('requests.Session.request')
    def test_full_authentication_flow_advana(self, mock_request):
        """Test complete authentication flow for Advana"""
        # Mock successful Advana response
        mock_response = Mock()
        mock_response.json.return_value = {
            "status": "success",
            "access_token": "advana_access_token",
            "advana_token": "advana_platform_token",
            "expires_in": 3600,
            "user_profile": {
                "id": "test_user",
                "name": "Test User",
                "email": "test.user@mil"
            },
            "permissions": ["advana:read", "advana:write"]
        }
        mock_response.raise_for_status.return_value = None
        mock_request.return_value = mock_response
        
        # Step 1: Generate challenge
        challenge_response = self.client.post("/api/v1/auth/challenge", json={
            "platform": "advana"
        })
        self.assertEqual(challenge_response.status_code, 200)
        challenge_data = challenge_response.json()
        
        # Step 2: Authenticate
        auth_request = {
            "certificate_data": self.test_certificate_b64,
            "signature": self.test_signature_b64,
            "challenge": challenge_data["challenge"],
            "platform": "advana",
            "environment": "testing",
            "additional_params": {
                "tenant_id": "test-tenant"
            }
        }
        
        auth_response = self.client.post("/api/v1/auth/authenticate", json=auth_request)
        
        self.assertEqual(auth_response.status_code, 200)
        auth_data = auth_response.json()
        
        self.assertEqual(auth_data["status"], "success")
        self.assertEqual(auth_data["session_token"], "advana_access_token")
        self.assertEqual(auth_data["platform_token"], "advana_platform_token")
        self.assertIn("advana_user", auth_data["roles"])
        
        # Step 3: Validate session
        validation_request = {
            "session_token": auth_data["session_token"],
            "platform": "advana",
            "environment": "testing"
        }
        
        # Mock validation response
        mock_response.json.return_value = {"valid": True}
        
        validation_response = self.client.post("/api/v1/auth/validate", json=validation_request)
        
        self.assertEqual(validation_response.status_code, 200)
        validation_data = validation_response.json()
        
        self.assertTrue(validation_data["valid"])
        
        # Step 4: Get user info
        user_info_request = {
            "session_token": auth_data["session_token"],
            "platform": "advana",
            "environment": "testing"
        }
        
        # Mock user info response
        mock_response.json.return_value = {
            "status": "success",
            "user_profile": {
                "id": "test_user",
                "name": "Test User",
                "email": "test.user@mil",
                "organization": "Test Org"
            }
        }
        
        user_info_response = self.client.post("/api/v1/user/info", json=user_info_request)
        
        self.assertEqual(user_info_response.status_code, 200)
        user_info_data = user_info_response.json()
        
        self.assertEqual(user_info_data["user_id"], "test_user")
        self.assertIn("name", user_info_data["user_info"])
        
        # Step 5: Logout
        logout_request = {
            "session_token": auth_data["session_token"],
            "platform": "advana",
            "environment": "testing"
        }
        
        # Mock logout response
        mock_response.json.return_value = {"status": "success"}
        
        logout_response = self.client.post("/api/v1/auth/logout", json=logout_request)
        
        self.assertEqual(logout_response.status_code, 200)
        logout_data = logout_response.json()
        
        self.assertTrue(logout_data["success"])
    
    @patch('requests.Session.request')
    def test_qlik_authentication_flow(self, mock_request):
        """Test Qlik-specific authentication flow"""
        # Mock Qlik response
        mock_response = Mock()
        mock_response.json.return_value = {
            "success": True,
            "session_token": "qlik_session_token",
            "ticket": "QlikTicket123456",
            "expires_in": 3600
        }
        mock_response.raise_for_status.return_value = None
        mock_request.return_value = mock_response
        
        # Authenticate with Qlik
        auth_request = {
            "certificate_data": self.test_certificate_b64,
            "signature": self.test_signature_b64,
            "challenge": self.test_challenge_b64,
            "platform": "qlik",
            "additional_params": {
                "virtual_proxy": "cac",
                "app_id": "test-app"
            }
        }
        
        response = self.client.post("/api/v1/auth/authenticate", json=auth_request)
        
        self.assertEqual(response.status_code, 200)
        data = response.json()
        
        self.assertEqual(data["status"], "success")
        self.assertEqual(data["session_token"], "qlik_session_token")
        self.assertEqual(data["platform_token"], "QlikTicket123456")
        self.assertIn("qlik_user", data["roles"])
    
    @patch('requests.Session.request')
    def test_databricks_authentication_flow(self, mock_request):
        """Test Databricks-specific authentication flow"""
        # Mock multiple Databricks API responses
        def mock_request_side_effect(*args, **kwargs):
            url = kwargs.get('url', '')
            method = kwargs.get('method', 'GET')
            
            mock_resp = Mock()
            mock_resp.raise_for_status.return_value = None
            
            if 'scim/v2/Users' in url and method == 'GET':
                # User search - return empty to trigger creation
                mock_resp.json.return_value = {"Resources": []}
            elif 'scim/v2/Users' in url and method == 'POST':
                # User creation
                mock_resp.json.return_value = {
                    "id": "databricks_user_id",
                    "userName": "test.user@mil",
                    "active": True,
                    "groups": [{"display": "users"}]
                }
            elif 'token/create' in url:
                # Token creation
                mock_resp.json.return_value = {
                    "token_value": "databricks_pat_token",
                    "token_info": {"token_id": "token_123"}
                }
            else:
                mock_resp.json.return_value = {}
            
            return mock_resp
        
        mock_request.side_effect = mock_request_side_effect
        
        # Authenticate with Databricks
        auth_request = {
            "certificate_data": self.test_certificate_b64,
            "signature": self.test_signature_b64,
            "challenge": self.test_challenge_b64,
            "platform": "databricks",
            "additional_params": {
                "workspace_id": "test-workspace",
                "cluster_config": {
                    "cluster_name": "test-cluster",
                    "num_workers": 1
                }
            }
        }
        
        response = self.client.post("/api/v1/auth/authenticate", json=auth_request)
        
        self.assertEqual(response.status_code, 200)
        data = response.json()
        
        self.assertEqual(data["status"], "success")
        self.assertEqual(data["session_token"], "databricks_pat_token")
        self.assertIn("databricks_user", data["roles"])
    
    @patch('requests.Session.request')
    def test_navy_jupiter_authentication_flow(self, mock_request):
        """Test Navy Jupiter-specific authentication flow"""
        # Mock Navy Jupiter response
        mock_response = Mock()
        mock_response.json.return_value = {
            "status": "success",
            "access_token": "navy_access_token",
            "navy_session_token": "navy_session_123",
            "expires_in": 3600,
            "user_profile": {
                "id": "navy_user",
                "edipi": "1234567890",
                "rank": "LT"
            },
            "permissions": [
                "navy:basic_access",
                "navy:network:nipr",
                "navy:classification:unclassified"
            ],
            "session_id": "session_456",
            "security_context": {
                "classification": "UNCLASSIFIED",
                "network": "NIPR"
            }
        }
        mock_response.raise_for_status.return_value = None
        mock_request.return_value = mock_response
        
        # Authenticate with Navy Jupiter
        auth_request = {
            "certificate_data": self.test_certificate_b64,
            "signature": self.test_signature_b64,
            "challenge": self.test_challenge_b64,
            "platform": "navy_jupiter",
            "additional_params": {
                "command_code": "TEST_CMD",
                "facility_code": "TEST_FAC",
                "client_ip": "192.168.1.100"
            }
        }
        
        response = self.client.post("/api/v1/auth/authenticate", json=auth_request)
        
        self.assertEqual(response.status_code, 200)
        data = response.json()
        
        self.assertEqual(data["status"], "success")
        self.assertEqual(data["session_token"], "navy_access_token")
        self.assertEqual(data["platform_token"], "navy_session_123")
        self.assertIn("navy_jupiter_user", data["roles"])
        self.assertIn("navy:basic_access", data["permissions"])
        self.assertIn("navy_network_nipr", data["roles"])
    
    def test_authentication_failure_scenarios(self):
        """Test various authentication failure scenarios"""
        # Test with invalid platform
        auth_request = {
            "certificate_data": self.test_certificate_b64,
            "signature": self.test_signature_b64,
            "challenge": self.test_challenge_b64,
            "platform": "invalid_platform"
        }
        
        response = self.client.post("/api/v1/auth/authenticate", json=auth_request)
        
        self.assertEqual(response.status_code, 422)  # Validation error
        
        # Test with missing certificate data
        auth_request = {
            "signature": self.test_signature_b64,
            "challenge": self.test_challenge_b64,
            "platform": "advana"
        }
        
        response = self.client.post("/api/v1/auth/authenticate", json=auth_request)
        
        self.assertEqual(response.status_code, 422)  # Validation error
        
        # Test with invalid base64 data
        auth_request = {
            "certificate_data": "invalid_base64",
            "signature": self.test_signature_b64,
            "challenge": self.test_challenge_b64,
            "platform": "advana"
        }
        
        response = self.client.post("/api/v1/auth/authenticate", json=auth_request)
        
        self.assertEqual(response.status_code, 422)  # Validation error
    
    @patch('requests.Session.request')
    def test_token_refresh_flow(self, mock_request):
        """Test token refresh functionality"""
        # Mock refresh response
        mock_response = Mock()
        mock_response.json.return_value = {
            "status": "success",
            "access_token": "new_access_token",
            "expires_in": 3600
        }
        mock_response.raise_for_status.return_value = None
        mock_request.return_value = mock_response
        
        refresh_request = {
            "session_token": "old_session_token",
            "platform": "advana"
        }
        
        response = self.client.post("/api/v1/auth/refresh", json=refresh_request)
        
        self.assertEqual(response.status_code, 200)
        data = response.json()
        
        self.assertEqual(data["status"], "success")
        self.assertEqual(data["session_token"], "new_access_token")
    
    def test_configuration_endpoint(self):
        """Test configuration information endpoint"""
        response = self.client.get("/api/v1/config")
        
        self.assertEqual(response.status_code, 200)
        data = response.json()
        
        self.assertIn("platforms", data)
        self.assertIn("global_config", data)
        self.assertIn("security_config", data)
        
        # Check platform information
        for platform in data["platforms"]:
            self.assertIn("platform", platform)
            self.assertIn("available", platform)
            self.assertIn("base_url", platform)
            self.assertIn("api_version", platform)
    
    def test_permissions_endpoint(self):
        """Test user permissions endpoint"""
        with patch('requests.Session.request') as mock_request:
            # Mock permissions response
            mock_response = Mock()
            mock_response.json.return_value = {
                "status": "success",
                "permissions": ["read", "write", "admin"]
            }
            mock_response.raise_for_status.return_value = None
            mock_request.return_value = mock_response
            
            permissions_request = {
                "session_token": "test_session_token",
                "platform": "advana",
                "user_id": "test_user"
            }
            
            response = self.client.post("/api/v1/user/permissions", json=permissions_request)
            
            self.assertEqual(response.status_code, 200)
            data = response.json()
            
            self.assertEqual(data["user_id"], "test_user")
            self.assertEqual(data["platform"], "advana")
            self.assertIn("read", data["permissions"])
            self.assertIn("write", data["permissions"])
            self.assertIn("admin", data["permissions"])
    
    def test_audit_logs_endpoint(self):
        """Test audit logs endpoint"""
        audit_request = {
            "start_date": "2024-01-01T00:00:00Z",
            "end_date": "2024-12-31T23:59:59Z",
            "event_type": "authentication",
            "page": 1,
            "page_size": 50
        }
        
        response = self.client.post("/api/v1/audit/logs", json=audit_request)
        
        self.assertEqual(response.status_code, 200)
        data = response.json()
        
        self.assertIn("entries", data)
        self.assertIn("total_count", data)
        self.assertIn("page", data)
        self.assertIn("page_size", data)
        self.assertEqual(data["page"], 1)
        self.assertEqual(data["page_size"], 50)
    
    def test_cors_headers(self):
        """Test CORS headers are properly set"""
        response = self.client.options("/api/v1/auth/challenge", headers={
            "Origin": "https://example.com",
            "Access-Control-Request-Method": "POST"
        })
        
        # CORS preflight should be handled
        self.assertIn(response.status_code, [200, 204])
    
    def test_security_headers(self):
        """Test security headers are present"""
        response = self.client.get("/health")
        
        headers = response.headers
        
        self.assertIn("X-Content-Type-Options", headers)
        self.assertIn("X-Frame-Options", headers)
        self.assertIn("X-XSS-Protection", headers)
        self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(headers["X-Frame-Options"], "DENY")
    
    def test_rate_limiting(self):
        """Test rate limiting functionality"""
        # Make multiple requests rapidly
        responses = []
        for i in range(10):
            response = self.client.get("/health")
            responses.append(response.status_code)
        
        # All requests should succeed for health endpoint (not rate limited)
        self.assertTrue(all(status == 200 for status in responses))
    
    def test_error_handling(self):
        """Test API error handling"""
        # Test 404 for non-existent endpoint
        response = self.client.get("/api/v1/nonexistent")
        self.assertEqual(response.status_code, 404)
        
        # Test validation error
        response = self.client.post("/api/v1/auth/authenticate", json={})
        self.assertEqual(response.status_code, 422)
        
        data = response.json()
        self.assertIn("detail", data)
    
    @patch('requests.Session.request')
    def test_multi_platform_session_management(self, mock_request):
        """Test managing sessions across multiple platforms"""
        # Mock responses for different platforms
        def mock_platform_response(*args, **kwargs):
            mock_resp = Mock()
            mock_resp.raise_for_status.return_value = None
            
            if "advana" in kwargs.get('url', ''):
                mock_resp.json.return_value = {
                    "status": "success",
                    "access_token": "advana_token",
                    "expires_in": 3600
                }
            elif "databricks" in kwargs.get('url', ''):
                mock_resp.json.return_value = {
                    "token_value": "databricks_token",
                    "token_info": {"token_id": "db_123"}
                }
            else:
                mock_resp.json.return_value = {"success": True, "session_token": "generic_token"}
            
            return mock_resp
        
        mock_request.side_effect = mock_platform_response
        
        # Authenticate with multiple platforms
        platforms = ["advana", "qlik"]
        tokens = {}
        
        for platform in platforms:
            auth_request = {
                "certificate_data": self.test_certificate_b64,
                "signature": self.test_signature_b64,
                "challenge": self.test_challenge_b64,
                "platform": platform
            }
            
            response = self.client.post("/api/v1/auth/authenticate", json=auth_request)
            
            if response.status_code == 200:
                data = response.json()
                if data["status"] == "success":
                    tokens[platform] = data["session_token"]
        
        # Verify we got tokens for platforms that succeeded
        self.assertGreater(len(tokens), 0)

if __name__ == '__main__':
    unittest.main()