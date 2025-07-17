"""
Test suite for OAuth 2.0 client implementation.
Tests DoD-compliant OAuth flows for all supported platforms.
"""

import json
import pytest
import responses
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, MagicMock
from urllib.parse import parse_qs, urlparse

from .oauth_client import (
    DoD_OAuth_Client, DoD_OAuth_Manager, Platform, GrantType,
    OAuthConfig, TokenResponse, PKCEChallenge
)
from .oauth_config import DoD_OAuth_Configurator, Environment


class TestPKCEChallenge:
    """Test PKCE challenge generation."""
    
    def test_code_verifier_generation(self):
        """Test code verifier is properly generated."""
        challenge = PKCEChallenge()
        
        # Code verifier should be base64url encoded
        assert len(challenge.code_verifier) >= 43  # Minimum length
        assert len(challenge.code_verifier) <= 128  # Maximum length
        assert all(c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_' 
                  for c in challenge.code_verifier)
    
    def test_code_challenge_generation(self):
        """Test code challenge is properly generated from verifier."""
        challenge = PKCEChallenge()
        
        # Code challenge should be base64url encoded SHA256 hash
        assert len(challenge.code_challenge) == 43  # SHA256 base64url length
        assert all(c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_' 
                  for c in challenge.code_challenge)
    
    def test_challenge_uniqueness(self):
        """Test that each challenge is unique."""
        challenge1 = PKCEChallenge()
        challenge2 = PKCEChallenge()
        
        assert challenge1.code_verifier != challenge2.code_verifier
        assert challenge1.code_challenge != challenge2.code_challenge


class TestTokenResponse:
    """Test token response handling."""
    
    def test_token_response_creation(self):
        """Test token response creation with required fields."""
        token = TokenResponse(
            access_token="test_token",
            token_type="Bearer",
            expires_in=3600
        )
        
        assert token.access_token == "test_token"
        assert token.token_type == "Bearer"
        assert token.expires_in == 3600
        assert token.issued_at is not None
        assert isinstance(token.issued_at, datetime)
    
    def test_token_expiration_calculation(self):
        """Test token expiration time calculation."""
        issued_at = datetime.utcnow()
        token = TokenResponse(
            access_token="test_token",
            token_type="Bearer",
            expires_in=3600,
            issued_at=issued_at
        )
        
        expected_expiry = issued_at + timedelta(seconds=3600)
        assert token.expires_at == expected_expiry
    
    def test_token_expiration_check(self):
        """Test token expiration status check."""
        # Non-expired token
        token = TokenResponse(
            access_token="test_token",
            token_type="Bearer",
            expires_in=3600
        )
        assert not token.is_expired
        
        # Expired token
        past_time = datetime.utcnow() - timedelta(hours=2)
        expired_token = TokenResponse(
            access_token="test_token",
            token_type="Bearer",
            expires_in=3600,
            issued_at=past_time
        )
        assert expired_token.is_expired


class TestOAuthConfig:
    """Test OAuth configuration."""
    
    def test_oauth_config_creation(self):
        """Test OAuth configuration creation."""
        config = OAuthConfig(
            platform=Platform.ADVANA,
            client_id="test_client",
            client_secret="test_secret",
            authorization_url="https://example.com/auth",
            token_url="https://example.com/token",
            redirect_uri="https://app.com/callback",
            scopes=["read", "write"]
        )
        
        assert config.platform == Platform.ADVANA
        assert config.client_id == "test_client"
        assert config.use_pkce is True  # Default value


class TestDoD_OAuth_Client:
    """Test DoD OAuth 2.0 client implementation."""
    
    @pytest.fixture
    def oauth_config(self):
        """Create test OAuth configuration."""
        return OAuthConfig(
            platform=Platform.ADVANA,
            client_id="test_client_id",
            client_secret="test_client_secret",
            authorization_url="https://advana.data.mil/oauth2/authorize",
            token_url="https://advana.data.mil/oauth2/token",
            redirect_uri="https://app.example.com/callback",
            scopes=["openid", "profile", "advana:read"],
            audience="https://advana.data.mil",
            issuer="https://advana.data.mil",
            jwks_uri="https://advana.data.mil/oauth2/jwks"
        )
    
    @pytest.fixture
    def oauth_client(self, oauth_config):
        """Create test OAuth client."""
        return DoD_OAuth_Client(oauth_config)
    
    def test_client_initialization(self, oauth_client, oauth_config):
        """Test OAuth client initialization."""
        assert oauth_client.config == oauth_config
        assert oauth_client.session is not None
        assert oauth_client.platform_config is not None
        assert oauth_client._access_token is None
        assert oauth_client._pkce_challenge is None
    
    def test_authorization_url_generation(self, oauth_client):
        """Test authorization URL generation."""
        auth_url, state = oauth_client.get_authorization_url()
        
        # Parse URL components
        parsed = urlparse(auth_url)
        params = parse_qs(parsed.query)
        
        assert parsed.scheme == "https"
        assert parsed.netloc == "advana.data.mil"
        assert parsed.path == "/oauth2/authorize"
        
        # Check required parameters
        assert params["response_type"][0] == "code"
        assert params["client_id"][0] == "test_client_id"
        assert params["redirect_uri"][0] == "https://app.example.com/callback"
        assert "openid profile advana:read" in params["scope"][0]
        assert params["state"][0] == state
        
        # Check PKCE parameters
        assert "code_challenge" in params
        assert params["code_challenge_method"][0] == "S256"
        
        # Verify PKCE challenge was created
        assert oauth_client._pkce_challenge is not None
    
    def test_authorization_url_with_custom_state(self, oauth_client):
        """Test authorization URL generation with custom state."""
        custom_state = "custom_state_value"
        auth_url, state = oauth_client.get_authorization_url(state=custom_state)
        
        parsed = urlparse(auth_url)
        params = parse_qs(parsed.query)
        
        assert params["state"][0] == custom_state
        assert state == custom_state
    
    @responses.activate
    def test_authorization_code_exchange_success(self, oauth_client):
        """Test successful authorization code exchange."""
        # Setup mock response
        token_response = {
            "access_token": "test_access_token",
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": "test_refresh_token",
            "scope": "openid profile advana:read"
        }
        
        responses.add(
            responses.POST,
            "https://advana.data.mil/oauth2/token",
            json=token_response,
            status=200
        )
        
        # Generate authorization URL first to create PKCE challenge
        oauth_client.get_authorization_url()
        
        # Exchange code for token
        token = oauth_client.exchange_code_for_token("test_auth_code")
        
        assert token.access_token == "test_access_token"
        assert token.token_type == "Bearer"
        assert token.expires_in == 3600
        assert token.refresh_token == "test_refresh_token"
        assert oauth_client._pkce_challenge is None  # Should be cleared
    
    @responses.activate
    def test_authorization_code_exchange_failure(self, oauth_client):
        """Test failed authorization code exchange."""
        # Setup mock error response
        error_response = {
            "error": "invalid_grant",
            "error_description": "Authorization code is invalid"
        }
        
        responses.add(
            responses.POST,
            "https://advana.data.mil/oauth2/token",
            json=error_response,
            status=400
        )
        
        # Generate authorization URL first
        oauth_client.get_authorization_url()
        
        # Exchange should fail
        with pytest.raises(Exception) as exc_info:
            oauth_client.exchange_code_for_token("invalid_code")
        
        assert "invalid_grant" in str(exc_info.value)
    
    @responses.activate
    def test_client_credentials_flow(self, oauth_client):
        """Test client credentials grant flow."""
        token_response = {
            "access_token": "client_credentials_token",
            "token_type": "Bearer",
            "expires_in": 7200,
            "scope": "advana:read advana:write"
        }
        
        responses.add(
            responses.POST,
            "https://advana.data.mil/oauth2/token",
            json=token_response,
            status=200
        )
        
        token = oauth_client.get_client_credentials_token()
        
        assert token.access_token == "client_credentials_token"
        assert token.expires_in == 7200
        
        # Verify request was made correctly
        request = responses.calls[0].request
        assert "grant_type=client_credentials" in request.body
    
    @responses.activate
    def test_token_refresh(self, oauth_client):
        """Test token refresh flow."""
        refresh_response = {
            "access_token": "new_access_token",
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": "new_refresh_token"
        }
        
        responses.add(
            responses.POST,
            "https://advana.data.mil/oauth2/token",
            json=refresh_response,
            status=200
        )
        
        token = oauth_client.refresh_access_token("old_refresh_token")
        
        assert token.access_token == "new_access_token"
        assert token.refresh_token == "new_refresh_token"
        
        # Verify request
        request = responses.calls[0].request
        assert "grant_type=refresh_token" in request.body
        assert "refresh_token=old_refresh_token" in request.body
    
    def test_jwt_validation_without_signature(self, oauth_client):
        """Test JWT validation without signature verification."""
        # Create a simple JWT payload (not signed)
        import base64
        
        header = {"alg": "none", "typ": "JWT"}
        payload = {
            "sub": "user123",
            "edipi": "1234567890",
            "clearance": "SECRET",
            "org": "DoD",
            "exp": int((datetime.utcnow() + timedelta(hours=1)).timestamp())
        }
        
        # Create unsigned JWT
        header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
        payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
        jwt_token = f"{header_b64}.{payload_b64}."
        
        claims = oauth_client.validate_jwt_token(jwt_token, verify_signature=False)
        
        assert claims["sub"] == "user123"
        assert claims["edipi"] == "1234567890"
        assert claims["clearance"] == "SECRET"
    
    @responses.activate
    def test_get_user_info(self, oauth_client):
        """Test user info retrieval."""
        user_info = {
            "sub": "user123",
            "name": "John Doe",
            "email": "john.doe@example.mil",
            "edipi": "1234567890",
            "clearance": "SECRET"
        }
        
        responses.add(
            responses.GET,
            "https://advana.data.mil/oauth2/userinfo",
            json=user_info,
            status=200
        )
        
        result = oauth_client.get_user_info("test_access_token")
        
        assert result == user_info
        
        # Verify authorization header
        request = responses.calls[0].request
        assert request.headers["Authorization"] == "Bearer test_access_token"
    
    @responses.activate
    def test_token_revocation(self, oauth_client):
        """Test token revocation."""
        responses.add(
            responses.POST,
            "https://advana.data.mil/oauth2/revoke",
            status=200
        )
        
        result = oauth_client.revoke_token("test_token")
        
        assert result is True
        
        # Verify request
        request = responses.calls[0].request
        assert "token=test_token" in request.body
        assert "token_type_hint=access_token" in request.body
    
    def test_current_token_property(self, oauth_client):
        """Test current token property."""
        # No token initially
        assert oauth_client.current_token is None
        
        # Set valid token
        valid_token = TokenResponse(
            access_token="valid_token",
            token_type="Bearer",
            expires_in=3600
        )
        oauth_client._access_token = valid_token
        
        assert oauth_client.current_token == valid_token
        
        # Set expired token
        expired_token = TokenResponse(
            access_token="expired_token",
            token_type="Bearer",
            expires_in=3600,
            issued_at=datetime.utcnow() - timedelta(hours=2)
        )
        oauth_client._access_token = expired_token
        
        assert oauth_client.current_token is None


class TestDoD_OAuth_Manager:
    """Test OAuth manager for multiple platforms."""
    
    @pytest.fixture
    def oauth_manager(self):
        """Create test OAuth manager."""
        return DoD_OAuth_Manager()
    
    @pytest.fixture
    def sample_configs(self):
        """Create sample OAuth configurations."""
        return {
            Platform.ADVANA: OAuthConfig(
                platform=Platform.ADVANA,
                client_id="advana_client",
                client_secret="advana_secret",
                authorization_url="https://advana.data.mil/oauth2/authorize",
                token_url="https://advana.data.mil/oauth2/token",
                redirect_uri="https://app.com/callback",
                scopes=["openid", "profile"]
            ),
            Platform.QLIK: OAuthConfig(
                platform=Platform.QLIK,
                client_id="qlik_client",
                client_secret="qlik_secret",
                authorization_url="https://qlik.advana.data.mil/oauth/authorize",
                token_url="https://qlik.advana.data.mil/oauth/token",
                redirect_uri="https://app.com/callback",
                scopes=["openid", "profile"]
            )
        }
    
    def test_manager_initialization(self, oauth_manager):
        """Test OAuth manager initialization."""
        assert len(oauth_manager.clients) == 0
        assert len(oauth_manager.tokens) == 0
    
    def test_add_platform(self, oauth_manager, sample_configs):
        """Test adding platform to manager."""
        config = sample_configs[Platform.ADVANA]
        client = oauth_manager.add_platform(config)
        
        assert isinstance(client, DoD_OAuth_Client)
        assert oauth_manager.clients[Platform.ADVANA] == client
        assert client.config == config
    
    def test_get_client(self, oauth_manager, sample_configs):
        """Test getting client from manager."""
        # No client initially
        assert oauth_manager.get_client(Platform.ADVANA) is None
        
        # Add client and retrieve
        config = sample_configs[Platform.ADVANA]
        added_client = oauth_manager.add_platform(config)
        retrieved_client = oauth_manager.get_client(Platform.ADVANA)
        
        assert retrieved_client == added_client
    
    def test_token_storage_and_retrieval(self, oauth_manager):
        """Test token storage and retrieval."""
        token = TokenResponse(
            access_token="test_token",
            token_type="Bearer",
            expires_in=3600
        )
        
        # Store token
        oauth_manager.store_token(Platform.ADVANA, token)
        
        # Retrieve valid token
        retrieved_token = oauth_manager.get_valid_token(Platform.ADVANA)
        assert retrieved_token == token
        
        # Test with expired token
        expired_token = TokenResponse(
            access_token="expired_token",
            token_type="Bearer",
            expires_in=3600,
            issued_at=datetime.utcnow() - timedelta(hours=2)
        )
        oauth_manager.store_token(Platform.QLIK, expired_token)
        
        assert oauth_manager.get_valid_token(Platform.QLIK) is None
    
    def test_clear_tokens(self, oauth_manager):
        """Test clearing tokens."""
        # Store tokens for multiple platforms
        token1 = TokenResponse("token1", "Bearer", 3600)
        token2 = TokenResponse("token2", "Bearer", 3600)
        
        oauth_manager.store_token(Platform.ADVANA, token1)
        oauth_manager.store_token(Platform.QLIK, token2)
        
        # Clear specific platform
        oauth_manager.clear_tokens(Platform.ADVANA)
        assert Platform.ADVANA not in oauth_manager.tokens
        assert Platform.QLIK in oauth_manager.tokens
        
        # Clear all tokens
        oauth_manager.clear_tokens()
        assert len(oauth_manager.tokens) == 0


class TestDoD_OAuth_Configurator:
    """Test OAuth configurator."""
    
    def test_configurator_initialization(self):
        """Test configurator initialization."""
        configurator = DoD_OAuth_Configurator(Environment.NIPR)
        
        assert configurator.environment == Environment.NIPR
        assert configurator.security_requirements is not None
    
    def test_config_creation(self):
        """Test OAuth config creation."""
        configurator = DoD_OAuth_Configurator(Environment.NIPR)
        
        config = configurator.create_config(
            platform=Platform.ADVANA,
            client_id="test_client",
            client_secret="test_secret",
            redirect_uri="https://app.com/callback"
        )
        
        assert config.platform == Platform.ADVANA
        assert config.client_id == "test_client"
        assert config.authorization_url == "https://advana.data.mil/oauth2/authorize"
        assert config.use_pkce is True
    
    def test_config_validation(self):
        """Test OAuth config validation."""
        configurator = DoD_OAuth_Configurator(Environment.NIPR)
        
        # Valid config
        valid_config = OAuthConfig(
            platform=Platform.ADVANA,
            client_id="test_client",
            client_secret="test_secret",
            authorization_url="https://advana.data.mil/oauth2/authorize",
            token_url="https://advana.data.mil/oauth2/token",
            redirect_uri="https://app.com/callback",
            scopes=["openid", "profile", "advana:read"],
            jwks_uri="https://advana.data.mil/oauth2/jwks",
            use_pkce=True
        )
        
        errors = configurator.validate_config(valid_config)
        assert len(errors) == 0
        
        # Invalid config (HTTP URLs)
        invalid_config = OAuthConfig(
            platform=Platform.ADVANA,
            client_id="test_client",
            client_secret="test_secret",
            authorization_url="http://advana.data.mil/oauth2/authorize",  # HTTP
            token_url="http://advana.data.mil/oauth2/token",  # HTTP
            redirect_uri="http://app.com/callback",  # HTTP
            scopes=["advana:read"],  # Missing required scopes
            jwks_uri="http://advana.data.mil/oauth2/jwks",  # HTTP
            use_pkce=False  # PKCE required
        )
        
        errors = configurator.validate_config(invalid_config)
        assert len(errors) > 0
        assert any("HTTPS" in error for error in errors)
        assert any("PKCE" in error for error in errors)
        assert any("scopes" in error for error in errors)
    
    @patch.dict('os.environ', {
        'ADVANA_CLIENT_ID': 'env_client_id',
        'ADVANA_CLIENT_SECRET': 'env_client_secret',
        'ADVANA_REDIRECT_URI': 'https://app.com/callback',
        'ADVANA_SCOPES': 'openid,profile,advana:read'
    })
    def test_config_from_environment(self):
        """Test config creation from environment variables."""
        configurator = DoD_OAuth_Configurator(Environment.NIPR)
        
        config = configurator.create_config_from_env(Platform.ADVANA)
        
        assert config.client_id == "env_client_id"
        assert config.client_secret == "env_client_secret"
        assert config.redirect_uri == "https://app.com/callback"
        assert "openid" in config.scopes
        assert "profile" in config.scopes
        assert "advana:read" in config.scopes
    
    def test_environment_specific_security_requirements(self):
        """Test security requirements for different environments."""
        nipr_config = DoD_OAuth_Configurator(Environment.NIPR)
        sipr_config = DoD_OAuth_Configurator(Environment.SIPR)
        jwics_config = DoD_OAuth_Configurator(Environment.JWICS)
        
        # NIPR should have less strict requirements
        assert nipr_config.security_requirements["min_key_size"] == 2048
        assert nipr_config.security_requirements["token_lifetime"] == 3600
        
        # SIPR should have stricter requirements
        assert sipr_config.security_requirements["min_key_size"] == 3072
        assert sipr_config.security_requirements["token_lifetime"] == 1800
        
        # JWICS should have the strictest requirements
        assert jwics_config.security_requirements["min_key_size"] == 4096
        assert jwics_config.security_requirements["token_lifetime"] == 900


if __name__ == "__main__":
    pytest.main([__file__])
