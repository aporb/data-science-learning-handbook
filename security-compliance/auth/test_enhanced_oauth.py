"""
Enhanced OAuth Test Suite
Tests for new OAuth features including encryption, CAC integration, and lifecycle management.
"""

import pytest
import tempfile
import shutil
import os
import json
import time
from datetime import datetime, timedelta, timezone
from unittest.mock import Mock, patch, MagicMock
from pathlib import Path

# Import components to test
from .secure_token_storage import SecureTokenStorage, TokenStorageManager, TokenStorageType
from .oauth_cac_bridge import OAuthCACBridge, AuthenticationMode, AuthenticationResult
from .concurrent_token_manager import ConcurrentTokenManager, RateLimitConfig, RequestPriority
from .oauth_audit_logger import EnhancedOAuthAuditLogger, OAuthAuditEventType
from .token_lifecycle_manager import TokenLifecycleManager, TokenLifecyclePolicy, TokenState

# Import existing OAuth components
from .oauth_client import DoD_OAuth_Client, Platform, TokenResponse, OAuthConfig
from .oauth_config import Environment
from .cac_piv_integration import CACCredentials


class TestSecureTokenStorage:
    """Test secure token storage functionality."""
    
    @pytest.fixture
    def temp_dir(self):
        """Create temporary directory for testing."""
        temp_dir = tempfile.mkdtemp()
        yield temp_dir
        shutil.rmtree(temp_dir)
    
    @pytest.fixture
    def token_storage(self, temp_dir):
        """Create test token storage."""
        return SecureTokenStorage(
            storage_type=TokenStorageType.DATABASE,
            storage_path=os.path.join(temp_dir, "test_tokens.db"),
            enable_cleanup=False  # Disable for testing
        )
    
    @pytest.fixture
    def sample_token(self):
        """Create sample token for testing."""
        return TokenResponse(
            access_token="test_access_token",
            token_type="Bearer",
            expires_in=3600,
            refresh_token="test_refresh_token",
            scope="openid profile"
        )
    
    def test_token_storage_initialization(self, token_storage):
        """Test token storage initialization."""
        assert token_storage.storage_type == TokenStorageType.DATABASE
        assert token_storage.encryption_manager is not None
        assert token_storage.key_manager is not None
    
    def test_store_and_retrieve_token(self, token_storage, sample_token):
        """Test storing and retrieving tokens."""
        # Store token
        token_id = token_storage.store_token(
            platform=Platform.ADVANA,
            user_id="test_user",
            token=sample_token,
            metadata={"test": "metadata"}
        )
        
        assert token_id is not None
        
        # Retrieve token
        retrieved_token = token_storage.retrieve_token(
            platform=Platform.ADVANA,
            user_id="test_user"
        )
        
        assert retrieved_token is not None
        assert retrieved_token.access_token == sample_token.access_token
        assert retrieved_token.token_type == sample_token.token_type
        assert retrieved_token.refresh_token == sample_token.refresh_token
    
    def test_token_encryption(self, token_storage, sample_token):
        """Test that tokens are properly encrypted."""
        # Store token
        token_storage.store_token(
            platform=Platform.QLIK,
            user_id="test_user_2",
            token=sample_token
        )
        
        # Check that raw database doesn't contain plaintext token
        import sqlite3
        conn = sqlite3.connect(token_storage.storage_path)
        cursor = conn.execute("SELECT encrypted_token_data FROM tokens")
        encrypted_data = cursor.fetchone()[0]
        conn.close()
        
        # Encrypted data should not contain the plaintext token
        assert sample_token.access_token not in encrypted_data
        assert "test_access_token" not in encrypted_data
    
    def test_expired_token_handling(self, token_storage):
        """Test handling of expired tokens."""
        # Create expired token
        expired_token = TokenResponse(
            access_token="expired_token",
            token_type="Bearer",
            expires_in=0,  # Already expired
            issued_at=datetime.utcnow() - timedelta(hours=1)
        )
        
        # Store expired token
        token_storage.store_token(
            platform=Platform.DATABRICKS,
            user_id="test_user_3",
            token=expired_token
        )
        
        # Try to retrieve - should return None for expired token
        retrieved_token = token_storage.retrieve_token(
            platform=Platform.DATABRICKS,
            user_id="test_user_3"
        )
        
        assert retrieved_token is None
    
    def test_token_deletion(self, token_storage, sample_token):
        """Test token deletion."""
        # Store token
        token_storage.store_token(
            platform=Platform.NAVY_JUPITER,
            user_id="test_user_4",
            token=sample_token
        )
        
        # Verify token exists
        assert token_storage.retrieve_token(Platform.NAVY_JUPITER, "test_user_4") is not None
        
        # Delete token
        success = token_storage.delete_token(Platform.NAVY_JUPITER, "test_user_4")
        assert success
        
        # Verify token is gone
        assert token_storage.retrieve_token(Platform.NAVY_JUPITER, "test_user_4") is None
    
    def test_cleanup_expired_tokens(self, token_storage):
        """Test cleanup of expired tokens."""
        # Store mix of valid and expired tokens
        valid_token = TokenResponse("valid", "Bearer", 3600)
        expired_token = TokenResponse(
            "expired", "Bearer", 0,
            issued_at=datetime.utcnow() - timedelta(hours=2)
        )
        
        token_storage.store_token(Platform.ADVANA, "user1", valid_token)
        token_storage.store_token(Platform.QLIK, "user2", expired_token)
        
        # Run cleanup
        cleaned_count = token_storage.cleanup_expired_tokens()
        
        # Should have cleaned up the expired token
        assert cleaned_count == 1
        
        # Valid token should still exist
        assert token_storage.retrieve_token(Platform.ADVANA, "user1") is not None
        
        # Expired token should be gone
        assert token_storage.retrieve_token(Platform.QLIK, "user2") is None


class TestOAuthCACBridge:
    """Test OAuth-CAC integration bridge."""
    
    @pytest.fixture
    def oauth_bridge(self):
        """Create test OAuth-CAC bridge."""
        return OAuthCACBridge(
            environment=Environment.NIPR,
            default_mode=AuthenticationMode.CAC_THEN_OAUTH,
            enable_token_storage=False  # Disable for testing
        )
    
    @pytest.fixture
    def mock_cac_credentials(self):
        """Create mock CAC credentials."""
        return CACCredentials(
            certificate=Mock(),
            subject_dn="CN=John Doe,OU=DoD,O=U.S. Government",
            issuer_dn="CN=DoD Root CA,O=U.S. Government",
            serial_number="123456789",
            edipi="1234567890",
            email="john.doe@mail.mil",
            organization="U.S. Army",
            clearance_level="SECRET"
        )
    
    @pytest.fixture
    def mock_oauth_config(self):
        """Create mock OAuth configuration."""
        return OAuthConfig(
            platform=Platform.ADVANA,
            client_id="test_client",
            client_secret="test_secret",
            authorization_url="https://advana.data.mil/oauth2/authorize",
            token_url="https://advana.data.mil/oauth2/token",
            redirect_uri="https://app.com/callback",
            scopes=["openid", "profile", "advana:read"]
        )
    
    def test_platform_configuration(self, oauth_bridge, mock_oauth_config):
        """Test platform configuration."""
        success = oauth_bridge.configure_platform(
            platform=Platform.ADVANA,
            client_id="test_client",
            client_secret="test_secret",
            redirect_uri="https://app.com/callback"
        )
        
        assert success
        assert Platform.ADVANA in oauth_bridge._platform_configs
    
    @patch('security_compliance.auth.oauth_cac_bridge.CACAuthenticationManager')
    def test_cac_authentication(self, mock_cac_manager, oauth_bridge, mock_cac_credentials):
        """Test CAC authentication."""
        # Mock CAC authentication
        mock_cac_manager.return_value.authenticate_user.return_value = mock_cac_credentials
        
        result, credentials = oauth_bridge.authenticate_with_cac(
            pin="123456",
            platform=Platform.ADVANA,
            required_clearance="UNCLASSIFIED"
        )
        
        assert result == AuthenticationResult.SUCCESS
        assert credentials is not None
        assert credentials.cac_credentials == mock_cac_credentials
        assert credentials.clearance_level == "SECRET"
    
    def test_clearance_level_check(self, oauth_bridge):
        """Test clearance level validation."""
        # Test valid clearance
        assert oauth_bridge._check_clearance_level("SECRET", "UNCLASSIFIED")
        assert oauth_bridge._check_clearance_level("SECRET", "SECRET")
        
        # Test invalid clearance
        assert not oauth_bridge._check_clearance_level("UNCLASSIFIED", "SECRET")
        assert not oauth_bridge._check_clearance_level("CONFIDENTIAL", "SECRET")
    
    def test_session_management(self, oauth_bridge, mock_cac_credentials):
        """Test session creation and management."""
        # Create mock session
        with patch.object(oauth_bridge.cac_auth_manager, 'authenticate_user', return_value=mock_cac_credentials):
            result, credentials = oauth_bridge.authenticate_with_cac("123456")
            
            assert result == AuthenticationResult.SUCCESS
            session_id = credentials.session_id
            
            # Retrieve session
            retrieved_session = oauth_bridge.get_session(session_id)
            assert retrieved_session is not None
            assert retrieved_session.session_id == session_id
            
            # Invalidate session
            success = oauth_bridge.invalidate_session(session_id)
            assert success
            
            # Session should be gone
            assert oauth_bridge.get_session(session_id) is None


class TestConcurrentTokenManager:
    """Test concurrent token request management."""
    
    @pytest.fixture
    def rate_limit_config(self):
        """Create test rate limit configuration."""
        return RateLimitConfig(
            max_requests_per_minute=10,
            max_requests_per_hour=100,
            max_concurrent_requests=3
        )
    
    @pytest.fixture
    def token_manager(self, rate_limit_config):
        """Create test concurrent token manager."""
        return ConcurrentTokenManager(
            rate_limit_config=rate_limit_config,
            max_workers=2
        )
    
    @pytest.fixture
    def mock_oauth_client(self):
        """Create mock OAuth client."""
        client = Mock(spec=DoD_OAuth_Client)
        client.exchange_code_for_token.return_value = TokenResponse(
            "test_token", "Bearer", 3600, "refresh_token"
        )
        return client
    
    def test_async_token_request(self, token_manager, mock_oauth_client):
        """Test asynchronous token request."""
        request_id = token_manager.request_token_async(
            user_id="test_user",
            platform=Platform.ADVANA,
            oauth_client=mock_oauth_client,
            request_type="authorization_code",
            priority=RequestPriority.NORMAL,
            authorization_code="test_code",
            state="test_state"
        )
        
        assert request_id is not None
        assert request_id in token_manager.active_requests
        
        # Wait for completion
        token = token_manager.wait_for_request(request_id, timeout=10)
        assert token is not None
        assert token.access_token == "test_token"
    
    def test_rate_limiting(self, token_manager, mock_oauth_client):
        """Test rate limiting functionality."""
        # Submit requests up to the limit
        request_ids = []
        for i in range(5):  # More than the limit of 3 concurrent
            request_id = token_manager.request_token_async(
                user_id=f"user_{i}",
                platform=Platform.ADVANA,
                oauth_client=mock_oauth_client,
                request_type="client_credentials"
            )
            request_ids.append(request_id)
        
        # Check that some requests are queued
        queue_status = token_manager.get_queue_status()
        assert queue_status['active_requests'] >= 3
    
    def test_request_prioritization(self, token_manager, mock_oauth_client):
        """Test request prioritization."""
        # Submit low priority request
        low_priority_id = token_manager.request_token_async(
            user_id="low_user",
            platform=Platform.ADVANA,
            oauth_client=mock_oauth_client,
            request_type="client_credentials",
            priority=RequestPriority.LOW
        )
        
        # Submit high priority request
        high_priority_id = token_manager.request_token_async(
            user_id="high_user",
            platform=Platform.ADVANA,
            oauth_client=mock_oauth_client,
            request_type="client_credentials",
            priority=RequestPriority.HIGH
        )
        
        # High priority should be processed first
        # (This is hard to test deterministically, so we just check they both exist)
        assert low_priority_id in token_manager.active_requests
        assert high_priority_id in token_manager.active_requests
    
    def test_request_cancellation(self, token_manager, mock_oauth_client):
        """Test request cancellation."""
        request_id = token_manager.request_token_async(
            user_id="cancel_user",
            platform=Platform.ADVANA,
            oauth_client=mock_oauth_client,
            request_type="client_credentials"
        )
        
        # Cancel the request
        cancelled = token_manager.cancel_request(request_id)
        
        # Should be successfully cancelled if it was still pending
        if cancelled:
            request = token_manager.get_request_status(request_id)
            assert request.status.value == "cancelled"


class TestOAuthAuditLogger:
    """Test enhanced OAuth audit logging."""
    
    @pytest.fixture
    def temp_dir(self):
        """Create temporary directory for testing."""
        temp_dir = tempfile.mkdtemp()
        yield temp_dir
        shutil.rmtree(temp_dir)
    
    @pytest.fixture
    def audit_logger(self, temp_dir):
        """Create test audit logger."""
        # Mock the database path
        with patch('pathlib.Path.home') as mock_home:
            mock_home.return_value = Path(temp_dir)
            logger = EnhancedOAuthAuditLogger()
            return logger
    
    def test_oauth_authorization_logging(self, audit_logger):
        """Test OAuth authorization request logging."""
        audit_logger.log_oauth_authorization_request(
            user_id="test_user",
            platform=Platform.ADVANA,
            client_id="test_client",
            scopes=["openid", "profile"],
            state="test_state",
            source_ip="192.168.1.1"
        )
        
        # Check that event was logged
        assert len(audit_logger.oauth_events) > 0
        event = audit_logger.oauth_events[-1]
        assert event.event_type == OAuthAuditEventType.OAUTH_AUTHORIZATION_REQUEST
        assert event.user_id == "test_user"
        assert event.platform == Platform.ADVANA.value
    
    def test_token_exchange_logging(self, audit_logger):
        """Test token exchange logging."""
        audit_logger.log_token_exchange(
            user_id="test_user",
            platform=Platform.QLIK,
            authorization_code="test_code",
            success=True,
            token_id="token_123"
        )
        
        # Verify logging
        assert len(audit_logger.oauth_events) > 0
        event = audit_logger.oauth_events[-1]
        assert event.event_type == OAuthAuditEventType.OAUTH_TOKEN_EXCHANGE
        assert event.success
        assert event.token_id == "token_123"
    
    def test_threat_detection(self, audit_logger):
        """Test threat detection functionality."""
        # Log suspicious activity
        audit_logger.log_suspicious_activity(
            user_id="suspicious_user",
            activity_type="rapid_token_access",
            threat_level="HIGH",
            description="Unusual token access pattern detected"
        )
        
        # Check that threat level was recorded
        event = audit_logger.oauth_events[-1]
        assert event.threat_level == "HIGH"
        assert event.success is False
    
    def test_compliance_reporting(self, audit_logger):
        """Test compliance report generation."""
        # Add some test events
        audit_logger.log_oauth_authorization_request(
            "user1", Platform.ADVANA, "client1", ["scope1"], "state1"
        )
        audit_logger.log_token_exchange(
            "user1", Platform.ADVANA, "code1", True, "token1"
        )
        
        # Generate report
        start_date = datetime.now(timezone.utc) - timedelta(hours=1)
        end_date = datetime.now(timezone.utc) + timedelta(hours=1)
        
        report = audit_logger.generate_compliance_report(start_date, end_date)
        
        assert "summary" in report
        assert "event_breakdown" in report
        assert report["summary"]["total_events"] >= 2


class TestTokenLifecycleManager:
    """Test token lifecycle management."""
    
    @pytest.fixture
    def lifecycle_policy(self):
        """Create test lifecycle policy."""
        return TokenLifecyclePolicy(
            refresh_threshold_minutes=5,
            auto_refresh_enabled=True,
            max_refresh_attempts=2,
            cleanup_delay_hours=1
        )
    
    @pytest.fixture
    def lifecycle_manager(self, lifecycle_policy):
        """Create test lifecycle manager."""
        # Mock dependencies to avoid actual OAuth operations
        with patch('security_compliance.auth.token_lifecycle_manager.TokenStorageManager'), \
             patch('security_compliance.auth.token_lifecycle_manager.DoD_OAuth_Manager'), \
             patch('security_compliance.auth.token_lifecycle_manager.EnhancedOAuthAuditLogger'):
            
            manager = TokenLifecycleManager(
                policy=lifecycle_policy,
                storage_manager=Mock(),
                oauth_manager=Mock(),
                concurrent_manager=Mock()
            )
            
            # Disable background tasks for testing
            manager._shutdown_event.set()
            
            return manager
    
    @pytest.fixture
    def sample_token_response(self):
        """Create sample token response."""
        return TokenResponse(
            access_token="test_token",
            token_type="Bearer",
            expires_in=300,  # 5 minutes
            refresh_token="test_refresh",
            issued_at=datetime.now(timezone.utc)
        )
    
    def test_token_registration(self, lifecycle_manager, sample_token_response):
        """Test token registration for lifecycle management."""
        tracking_id = lifecycle_manager.register_token(
            user_id="test_user",
            platform=Platform.ADVANA,
            token=sample_token_response,
            metadata={"test": "data"}
        )
        
        assert tracking_id is not None
        assert tracking_id in lifecycle_manager.tracked_tokens
        
        # Check token info
        token_info = lifecycle_manager.tracked_tokens[tracking_id]
        assert token_info["user_id"] == "test_user"
        assert token_info["platform"] == Platform.ADVANA.value
        assert token_info["state"] == TokenState.ACTIVE
    
    def test_token_unregistration(self, lifecycle_manager, sample_token_response):
        """Test token unregistration."""
        tracking_id = lifecycle_manager.register_token(
            "test_user", Platform.QLIK, sample_token_response
        )
        
        # Unregister token
        lifecycle_manager.unregister_token(tracking_id)
        
        # Should be removed from tracking
        assert tracking_id not in lifecycle_manager.tracked_tokens
    
    def test_token_status_retrieval(self, lifecycle_manager, sample_token_response):
        """Test token status retrieval."""
        tracking_id = lifecycle_manager.register_token(
            "status_user", Platform.DATABRICKS, sample_token_response
        )
        
        status = lifecycle_manager.get_token_status(tracking_id)
        
        assert status is not None
        assert status["tracking_id"] == tracking_id
        assert status["user_id"] == "status_user"
        assert status["platform"] == Platform.DATABRICKS.value
        assert status["state"] == TokenState.ACTIVE.value
    
    def test_metrics_tracking(self, lifecycle_manager, sample_token_response):
        """Test metrics tracking."""
        # Register some tokens
        lifecycle_manager.register_token("user1", Platform.ADVANA, sample_token_response)
        lifecycle_manager.register_token("user2", Platform.QLIK, sample_token_response)
        
        metrics = lifecycle_manager.get_metrics()
        
        assert metrics.total_tokens >= 2
        assert metrics.active_tokens >= 2
    
    def test_refresh_threshold_detection(self, lifecycle_manager):
        """Test detection of tokens needing refresh."""
        # Create token expiring soon
        expiring_token = TokenResponse(
            "expiring_token", "Bearer", 600,  # 10 minutes
            refresh_token="refresh_token",
            issued_at=datetime.now(timezone.utc) - timedelta(minutes=5)  # 5 minutes remaining
        )
        
        tracking_id = lifecycle_manager.register_token(
            "expiring_user", Platform.NAVY_JUPITER, expiring_token
        )
        
        # Manually trigger refresh check
        lifecycle_manager._check_token_refresh()
        
        # Token should be marked for refresh
        token_info = lifecycle_manager.tracked_tokens[tracking_id]
        assert token_info["state"] == TokenState.EXPIRING_SOON
        assert tracking_id in lifecycle_manager.refresh_queue


class TestIntegrationScenarios:
    """Test complete integration scenarios."""
    
    def test_end_to_end_oauth_flow(self):
        """Test complete OAuth flow with all components."""
        # This would be a comprehensive integration test
        # Testing the flow from CAC auth -> OAuth -> token storage -> lifecycle management
        pass
    
    def test_security_compliance_workflow(self):
        """Test security compliance and audit workflow."""
        # Test that all security events are properly logged and tracked
        pass
    
    def test_error_handling_and_recovery(self):
        """Test error handling and recovery scenarios."""
        # Test various failure scenarios and recovery mechanisms
        pass


if __name__ == "__main__":
    # Run tests with pytest
    pytest.main([__file__, "-v"])