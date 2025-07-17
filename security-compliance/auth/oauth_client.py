"""
OAuth 2.0 Client Implementation for DoD Platforms
Supports Advana, Qlik, Databricks, and Navy Jupiter platforms with DoD-compliant security configurations.
"""

import base64
import hashlib
import json
import secrets
import time
import urllib.parse
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from enum import Enum

import requests
import jwt
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption


class Platform(Enum):
    """Supported DoD platforms for OAuth 2.0 authentication."""
    ADVANA = "advana"
    QLIK = "qlik"
    DATABRICKS = "databricks"
    NAVY_JUPITER = "navy_jupiter"


class GrantType(Enum):
    """OAuth 2.0 grant types."""
    AUTHORIZATION_CODE = "authorization_code"
    CLIENT_CREDENTIALS = "client_credentials"
    REFRESH_TOKEN = "refresh_token"


@dataclass
class OAuthConfig:
    """OAuth 2.0 configuration for a platform."""
    platform: Platform
    client_id: str
    client_secret: str
    authorization_url: str
    token_url: str
    redirect_uri: str
    scopes: List[str]
    audience: Optional[str] = None
    issuer: Optional[str] = None
    jwks_uri: Optional[str] = None
    use_pkce: bool = True
    token_endpoint_auth_method: str = "client_secret_basic"


@dataclass
class TokenResponse:
    """OAuth 2.0 token response."""
    access_token: str
    token_type: str
    expires_in: int
    refresh_token: Optional[str] = None
    scope: Optional[str] = None
    id_token: Optional[str] = None
    issued_at: Optional[datetime] = None
    
    def __post_init__(self):
        if self.issued_at is None:
            self.issued_at = datetime.utcnow()
    
    @property
    def expires_at(self) -> datetime:
        """Calculate token expiration time."""
        return self.issued_at + timedelta(seconds=self.expires_in)
    
    @property
    def is_expired(self) -> bool:
        """Check if token is expired (with 5-minute buffer)."""
        buffer = timedelta(minutes=5)
        return datetime.utcnow() >= (self.expires_at - buffer)


class PKCEChallenge:
    """PKCE (Proof Key for Code Exchange) challenge generator."""
    
    def __init__(self):
        self.code_verifier = self._generate_code_verifier()
        self.code_challenge = self._generate_code_challenge()
    
    def _generate_code_verifier(self) -> str:
        """Generate a cryptographically random code verifier."""
        return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode('utf-8').rstrip('=')
    
    def _generate_code_challenge(self) -> str:
        """Generate code challenge from verifier using SHA256."""
        digest = hashlib.sha256(self.code_verifier.encode('utf-8')).digest()
        return base64.urlsafe_b64encode(digest).decode('utf-8').rstrip('=')


class DoD_OAuth_Client:
    """
    DoD-compliant OAuth 2.0 client implementation.
    
    Supports authorization code flow with PKCE, client credentials flow,
    and token refresh mechanisms for DoD platforms.
    """
    
    # DoD-specific platform configurations
    PLATFORM_CONFIGS = {
        Platform.ADVANA: {
            "default_scopes": ["read", "write", "admin"],
            "required_claims": ["edipi", "clearance", "org"],
            "token_lifetime": 3600,  # 1 hour
            "refresh_lifetime": 86400,  # 24 hours
        },
        Platform.QLIK: {
            "default_scopes": ["qlik:read", "qlik:write", "qlik:admin"],
            "required_claims": ["sub", "edipi", "groups"],
            "token_lifetime": 7200,  # 2 hours
            "refresh_lifetime": 604800,  # 7 days
        },
        Platform.DATABRICKS: {
            "default_scopes": ["databricks:read", "databricks:write", "databricks:admin"],
            "required_claims": ["sub", "edipi", "workspace"],
            "token_lifetime": 3600,  # 1 hour
            "refresh_lifetime": 86400,  # 24 hours
        },
        Platform.NAVY_JUPITER: {
            "default_scopes": ["jupiter:read", "jupiter:write", "jupiter:compute"],
            "required_claims": ["sub", "edipi", "clearance", "command"],
            "token_lifetime": 1800,  # 30 minutes
            "refresh_lifetime": 43200,  # 12 hours
        }
    }
    
    def __init__(self, config: OAuthConfig, session: Optional[requests.Session] = None):
        """
        Initialize OAuth 2.0 client.
        
        Args:
            config: OAuth configuration for the platform
            session: Optional requests session for connection pooling
        """
        self.config = config
        self.session = session or requests.Session()
        self.session.headers.update({
            'User-Agent': 'DoD-OAuth-Client/1.0',
            'Accept': 'application/json',
            'Content-Type': 'application/x-www-form-urlencoded'
        })
        
        # Platform-specific configuration
        self.platform_config = self.PLATFORM_CONFIGS.get(config.platform, {})
        
        # Current tokens
        self._access_token: Optional[TokenResponse] = None
        self._pkce_challenge: Optional[PKCEChallenge] = None
    
    def get_authorization_url(self, state: Optional[str] = None, 
                            additional_params: Optional[Dict[str, str]] = None) -> Tuple[str, str]:
        """
        Generate authorization URL for OAuth 2.0 authorization code flow.
        
        Args:
            state: Optional state parameter for CSRF protection
            additional_params: Additional query parameters
            
        Returns:
            Tuple of (authorization_url, state)
        """
        if state is None:
            state = secrets.token_urlsafe(32)
        
        # Generate PKCE challenge if enabled
        if self.config.use_pkce:
            self._pkce_challenge = PKCEChallenge()
        
        params = {
            'response_type': 'code',
            'client_id': self.config.client_id,
            'redirect_uri': self.config.redirect_uri,
            'scope': ' '.join(self.config.scopes),
            'state': state,
        }
        
        # Add PKCE parameters
        if self._pkce_challenge:
            params.update({
                'code_challenge': self._pkce_challenge.code_challenge,
                'code_challenge_method': 'S256'
            })
        
        # Add additional parameters
        if additional_params:
            params.update(additional_params)
        
        # Build authorization URL
        auth_url = f"{self.config.authorization_url}?{urllib.parse.urlencode(params)}"
        
        return auth_url, state
    
    def exchange_code_for_token(self, authorization_code: str, 
                              state: Optional[str] = None) -> TokenResponse:
        """
        Exchange authorization code for access token.
        
        Args:
            authorization_code: Authorization code from callback
            state: State parameter for validation
            
        Returns:
            TokenResponse containing access and refresh tokens
            
        Raises:
            ValueError: If PKCE challenge is missing or token exchange fails
            requests.RequestException: If HTTP request fails
        """
        if self.config.use_pkce and not self._pkce_challenge:
            raise ValueError("PKCE challenge not found. Call get_authorization_url first.")
        
        # Prepare token request
        data = {
            'grant_type': GrantType.AUTHORIZATION_CODE.value,
            'code': authorization_code,
            'redirect_uri': self.config.redirect_uri,
            'client_id': self.config.client_id,
        }
        
        # Add PKCE verifier
        if self._pkce_challenge:
            data['code_verifier'] = self._pkce_challenge.code_verifier
        
        # Add client authentication
        auth = None
        if self.config.token_endpoint_auth_method == "client_secret_basic":
            auth = (self.config.client_id, self.config.client_secret)
        elif self.config.token_endpoint_auth_method == "client_secret_post":
            data['client_secret'] = self.config.client_secret
        
        # Make token request
        response = self.session.post(
            self.config.token_url,
            data=data,
            auth=auth,
            timeout=30
        )
        
        if not response.ok:
            error_data = response.json() if response.headers.get('content-type', '').startswith('application/json') else {}
            raise requests.RequestException(
                f"Token exchange failed: {response.status_code} - "
                f"{error_data.get('error', 'Unknown error')}: "
                f"{error_data.get('error_description', response.text)}"
            )
        
        token_data = response.json()
        self._access_token = TokenResponse(**token_data)
        
        # Clear PKCE challenge after use
        self._pkce_challenge = None
        
        return self._access_token
    
    def get_client_credentials_token(self, scopes: Optional[List[str]] = None) -> TokenResponse:
        """
        Get access token using client credentials flow.
        
        Args:
            scopes: Optional list of scopes to request
            
        Returns:
            TokenResponse containing access token
            
        Raises:
            requests.RequestException: If HTTP request fails
        """
        scopes = scopes or self.config.scopes
        
        data = {
            'grant_type': GrantType.CLIENT_CREDENTIALS.value,
            'scope': ' '.join(scopes),
        }
        
        # Client authentication
        auth = (self.config.client_id, self.config.client_secret)
        
        response = self.session.post(
            self.config.token_url,
            data=data,
            auth=auth,
            timeout=30
        )
        
        if not response.ok:
            error_data = response.json() if response.headers.get('content-type', '').startswith('application/json') else {}
            raise requests.RequestException(
                f"Client credentials token request failed: {response.status_code} - "
                f"{error_data.get('error', 'Unknown error')}: "
                f"{error_data.get('error_description', response.text)}"
            )
        
        token_data = response.json()
        self._access_token = TokenResponse(**token_data)
        
        return self._access_token
    
    def refresh_access_token(self, refresh_token: str) -> TokenResponse:
        """
        Refresh access token using refresh token.
        
        Args:
            refresh_token: Refresh token from previous token response
            
        Returns:
            TokenResponse containing new access token
            
        Raises:
            requests.RequestException: If HTTP request fails
        """
        data = {
            'grant_type': GrantType.REFRESH_TOKEN.value,
            'refresh_token': refresh_token,
        }
        
        # Client authentication
        auth = (self.config.client_id, self.config.client_secret)
        
        response = self.session.post(
            self.config.token_url,
            data=data,
            auth=auth,
            timeout=30
        )
        
        if not response.ok:
            error_data = response.json() if response.headers.get('content-type', '').startswith('application/json') else {}
            raise requests.RequestException(
                f"Token refresh failed: {response.status_code} - "
                f"{error_data.get('error', 'Unknown error')}: "
                f"{error_data.get('error_description', response.text)}"
            )
        
        token_data = response.json()
        self._access_token = TokenResponse(**token_data)
        
        return self._access_token
    
    def validate_jwt_token(self, token: str, verify_signature: bool = True) -> Dict[str, Any]:
        """
        Validate and decode JWT token.
        
        Args:
            token: JWT token to validate
            verify_signature: Whether to verify token signature
            
        Returns:
            Decoded token claims
            
        Raises:
            jwt.InvalidTokenError: If token validation fails
        """
        if not verify_signature:
            return jwt.decode(token, options={"verify_signature": False})
        
        # Get JWKS for signature verification
        if not self.config.jwks_uri:
            raise ValueError("JWKS URI not configured for signature verification")
        
        jwks_response = self.session.get(self.config.jwks_uri, timeout=30)
        jwks_response.raise_for_status()
        jwks = jwks_response.json()
        
        # Decode and validate token
        claims = jwt.decode(
            token,
            jwks,
            algorithms=["RS256", "ES256"],
            audience=self.config.audience,
            issuer=self.config.issuer,
            options={
                "verify_signature": True,
                "verify_aud": bool(self.config.audience),
                "verify_iss": bool(self.config.issuer),
                "verify_exp": True,
                "verify_nbf": True,
                "verify_iat": True,
            }
        )
        
        # Validate DoD-specific claims
        required_claims = self.platform_config.get("required_claims", [])
        missing_claims = [claim for claim in required_claims if claim not in claims]
        if missing_claims:
            raise jwt.InvalidTokenError(f"Missing required claims: {missing_claims}")
        
        return claims
    
    def get_user_info(self, access_token: str) -> Dict[str, Any]:
        """
        Get user information using access token.
        
        Args:
            access_token: Valid access token
            
        Returns:
            User information dictionary
            
        Raises:
            requests.RequestException: If HTTP request fails
        """
        headers = {
            'Authorization': f'Bearer {access_token}',
            'Accept': 'application/json'
        }
        
        # Platform-specific userinfo endpoints
        userinfo_urls = {
            Platform.ADVANA: f"{self.config.authorization_url.replace('/authorize', '/userinfo')}",
            Platform.QLIK: f"{self.config.authorization_url.replace('/authorize', '/userinfo')}",
            Platform.DATABRICKS: f"{self.config.authorization_url.replace('/authorize', '/userinfo')}",
            Platform.NAVY_JUPITER: f"{self.config.authorization_url.replace('/authorize', '/userinfo')}",
        }
        
        userinfo_url = userinfo_urls.get(self.config.platform)
        if not userinfo_url:
            raise ValueError(f"Userinfo endpoint not configured for platform: {self.config.platform}")
        
        response = self.session.get(userinfo_url, headers=headers, timeout=30)
        response.raise_for_status()
        
        return response.json()
    
    def revoke_token(self, token: str, token_type_hint: str = "access_token") -> bool:
        """
        Revoke access or refresh token.
        
        Args:
            token: Token to revoke
            token_type_hint: Type of token (access_token or refresh_token)
            
        Returns:
            True if revocation successful
            
        Raises:
            requests.RequestException: If HTTP request fails
        """
        revoke_url = self.config.token_url.replace('/token', '/revoke')
        
        data = {
            'token': token,
            'token_type_hint': token_type_hint,
        }
        
        auth = (self.config.client_id, self.config.client_secret)
        
        response = self.session.post(
            revoke_url,
            data=data,
            auth=auth,
            timeout=30
        )
        
        # RFC 7009: successful revocation returns 200, invalid token returns 200
        return response.status_code == 200
    
    @property
    def current_token(self) -> Optional[TokenResponse]:
        """Get current access token if available and valid."""
        if self._access_token and not self._access_token.is_expired:
            return self._access_token
        return None
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - cleanup resources."""
        if self.session:
            self.session.close()


class DoD_OAuth_Manager:
    """
    Manager for multiple OAuth 2.0 clients across DoD platforms.
    
    Provides centralized token management, automatic refresh, and
    platform-specific client creation.
    """
    
    def __init__(self):
        """Initialize OAuth manager."""
        self.clients: Dict[Platform, DoD_OAuth_Client] = {}
        self.tokens: Dict[Platform, TokenResponse] = {}
    
    def add_platform(self, config: OAuthConfig) -> DoD_OAuth_Client:
        """
        Add OAuth client for a platform.
        
        Args:
            config: OAuth configuration for the platform
            
        Returns:
            Configured OAuth client
        """
        client = DoD_OAuth_Client(config)
        self.clients[config.platform] = client
        return client
    
    def get_client(self, platform: Platform) -> Optional[DoD_OAuth_Client]:
        """
        Get OAuth client for a platform.
        
        Args:
            platform: Platform to get client for
            
        Returns:
            OAuth client or None if not configured
        """
        return self.clients.get(platform)
    
    def get_valid_token(self, platform: Platform) -> Optional[TokenResponse]:
        """
        Get valid access token for a platform.
        
        Args:
            platform: Platform to get token for
            
        Returns:
            Valid token or None if not available
        """
        token = self.tokens.get(platform)
        if token and not token.is_expired:
            return token
        return None
    
    def refresh_token_if_needed(self, platform: Platform) -> Optional[TokenResponse]:
        """
        Refresh token if needed and available.
        
        Args:
            platform: Platform to refresh token for
            
        Returns:
            Refreshed token or None if refresh not possible
        """
        client = self.get_client(platform)
        token = self.tokens.get(platform)
        
        if not client or not token or not token.refresh_token:
            return None
        
        if token.is_expired:
            try:
                new_token = client.refresh_access_token(token.refresh_token)
                self.tokens[platform] = new_token
                return new_token
            except requests.RequestException:
                # Refresh failed, remove invalid token
                self.tokens.pop(platform, None)
                return None
        
        return token
    
    def store_token(self, platform: Platform, token: TokenResponse):
        """
        Store token for a platform.
        
        Args:
            platform: Platform to store token for
            token: Token to store
        """
        self.tokens[platform] = token
    
    def clear_tokens(self, platform: Optional[Platform] = None):
        """
        Clear stored tokens.
        
        Args:
            platform: Specific platform to clear, or None for all platforms
        """
        if platform:
            self.tokens.pop(platform, None)
        else:
            self.tokens.clear()
