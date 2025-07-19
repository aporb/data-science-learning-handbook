"""
DoD Enterprise API Gateway Integration

This module provides integration with DoD Enterprise API Gateway for authentication
federation, secure external communications, and compliance with DoD security standards.

Key Features:
- DoD API Gateway authentication federation
- TLS 1.3 enforcement for all external communications
- Certificate-based mutual authentication
- OAuth 2.0 integration with existing systems
- Rate limiting and security controls
- Comprehensive audit logging

Security Standards:
- NIST 800-53 controls implementation
- DoD 8500 series compliance
- FIPS 140-2 cryptographic standards
- STIGs compliance for API security
"""

import asyncio
import ssl
import time
import uuid
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple, Union
from dataclasses import dataclass, asdict
from enum import Enum
from urllib.parse import urljoin, urlparse
import hashlib
import hmac

import aiohttp
import jwt
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

# Import from existing modules
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from auth.oauth_client import OAuthClient, Platform, OAuthConfig
from encryption.encryption_manager import EncryptionManager
from auth.cac_piv_integration import CACPIVAuthenticator


class APIGatewayEnvironment(Enum):
    """DoD API Gateway environments."""
    DEVELOPMENT = "dev"
    TESTING = "test"
    STAGING = "staging"
    PRODUCTION = "prod"
    NIPRNET = "nipr"
    SIPRNET = "sipr"


class SecurityClassification(Enum):
    """Data security classifications."""
    UNCLASSIFIED = "U"
    CONFIDENTIAL = "C"
    SECRET = "S"
    TOP_SECRET = "TS"


class APIEndpointType(Enum):
    """API endpoint types for routing."""
    PUBLIC = "public"
    INTERNAL = "internal"
    CLASSIFIED = "classified"
    EXTERNAL = "external"


@dataclass
class DoDAGWConfig:
    """DoD API Gateway configuration."""
    environment: APIGatewayEnvironment
    gateway_url: str
    client_certificate_path: str
    private_key_path: str
    ca_bundle_path: str
    oauth_config: OAuthConfig
    service_name: str
    service_version: str
    security_classification: SecurityClassification
    api_key: Optional[str] = None
    timeout_seconds: int = 30
    max_retries: int = 3
    rate_limit_requests: int = 1000
    rate_limit_window: int = 3600  # 1 hour


@dataclass
class APIRequest:
    """Structured API request."""
    method: str
    endpoint: str
    headers: Dict[str, str]
    data: Optional[Union[Dict, str, bytes]] = None
    params: Optional[Dict[str, str]] = None
    endpoint_type: APIEndpointType = APIEndpointType.INTERNAL
    classification: SecurityClassification = SecurityClassification.UNCLASSIFIED
    correlation_id: Optional[str] = None


@dataclass
class APIResponse:
    """Structured API response."""
    status_code: int
    headers: Dict[str, str]
    data: Any
    response_time: float
    correlation_id: str
    error: Optional[str] = None


class DoDAPIGateway:
    """
    DoD Enterprise API Gateway Integration Client
    
    Provides secure integration with DoD API Gateway infrastructure including:
    - Certificate-based mutual authentication
    - OAuth 2.0 token federation
    - TLS 1.3 enforcement
    - Rate limiting and security controls
    - Comprehensive audit logging
    """
    
    def __init__(self, config: DoDAGWConfig):
        """Initialize DoD API Gateway client."""
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # Initialize components
        self.oauth_client = None
        self.encryption_manager = None
        self.cac_authenticator = None
        
        # Rate limiting
        self._rate_limit_tokens = config.rate_limit_requests
        self._rate_limit_reset = time.time() + config.rate_limit_window
        
        # Session management
        self._session = None
        self._ssl_context = None
        
        # Initialize SSL context
        self._setup_ssl_context()
        
        # Initialize OAuth if configured
        if config.oauth_config:
            self.oauth_client = OAuthClient(config.oauth_config)
    
    def _setup_ssl_context(self) -> None:
        """Configure SSL context for TLS 1.3 with client certificates."""
        try:
            # Create SSL context with TLS 1.3 minimum
            self._ssl_context = ssl.create_default_context()
            self._ssl_context.minimum_version = ssl.TLSVersion.TLSv1_3
            self._ssl_context.maximum_version = ssl.TLSVersion.TLSv1_3
            
            # Load client certificate and private key
            self._ssl_context.load_cert_chain(
                self.config.client_certificate_path,
                self.config.private_key_path
            )
            
            # Load CA bundle
            self._ssl_context.load_verify_locations(self.config.ca_bundle_path)
            
            # Strict certificate verification
            self._ssl_context.check_hostname = True
            self._ssl_context.verify_mode = ssl.CERT_REQUIRED
            
            # Security hardening
            self._ssl_context.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS')
            
            self.logger.info("SSL context configured with TLS 1.3 and client certificates")
            
        except Exception as e:
            self.logger.error(f"Failed to setup SSL context: {e}")
            raise
    
    async def initialize(self) -> None:
        """Initialize API Gateway client with authentication."""
        try:
            # Create HTTP session with SSL context
            connector = aiohttp.TCPConnector(
                ssl=self._ssl_context,
                limit=100,
                ttl_dns_cache=300,
                use_dns_cache=True
            )
            
            timeout = aiohttp.ClientTimeout(total=self.config.timeout_seconds)
            self._session = aiohttp.ClientSession(
                connector=connector,
                timeout=timeout,
                headers={
                    'User-Agent': f'{self.config.service_name}/{self.config.service_version}',
                    'X-Service-Name': self.config.service_name,
                    'X-Environment': self.config.environment.value
                }
            )
            
            # Initialize OAuth authentication
            if self.oauth_client:
                await self._authenticate_oauth()
            
            # Test gateway connectivity
            await self._test_connectivity()
            
            self.logger.info("DoD API Gateway client initialized successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize API Gateway client: {e}")
            raise
    
    async def _authenticate_oauth(self) -> None:
        """Authenticate with OAuth 2.0 provider."""
        try:
            # Get access token using client credentials flow
            token_response = await self.oauth_client.get_client_credentials_token()
            
            if not token_response or 'access_token' not in token_response:
                raise Exception("Failed to obtain OAuth access token")
            
            # Add OAuth token to session headers
            self._session.headers.update({
                'Authorization': f"Bearer {token_response['access_token']}"
            })
            
            self.logger.info("OAuth authentication successful")
            
        except Exception as e:
            self.logger.error(f"OAuth authentication failed: {e}")
            raise
    
    async def _test_connectivity(self) -> None:
        """Test connectivity to API Gateway."""
        try:
            health_url = urljoin(self.config.gateway_url, '/health')
            
            async with self._session.get(health_url) as response:
                if response.status == 200:
                    self.logger.info("API Gateway connectivity test successful")
                else:
                    raise Exception(f"Gateway health check failed: {response.status}")
                    
        except Exception as e:
            self.logger.error(f"Gateway connectivity test failed: {e}")
            raise
    
    async def make_request(self, request: APIRequest) -> APIResponse:
        """
        Make authenticated request through DoD API Gateway.
        
        Args:
            request: Structured API request
            
        Returns:
            APIResponse with results and metadata
        """
        start_time = time.time()
        correlation_id = request.correlation_id or str(uuid.uuid4())
        
        try:
            # Rate limiting check
            await self._check_rate_limit()
            
            # Prepare request
            url = urljoin(self.config.gateway_url, request.endpoint)
            headers = self._prepare_headers(request, correlation_id)
            
            # Security validation
            self._validate_request_security(request)
            
            # Log request
            self._log_request(request, correlation_id)
            
            # Make HTTP request
            async with self._session.request(
                method=request.method,
                url=url,
                headers=headers,
                params=request.params,
                data=await self._prepare_request_data(request),
                ssl=self._ssl_context
            ) as response:
                
                # Process response
                response_data = await self._process_response(response)
                response_time = time.time() - start_time
                
                api_response = APIResponse(
                    status_code=response.status,
                    headers=dict(response.headers),
                    data=response_data,
                    response_time=response_time,
                    correlation_id=correlation_id
                )
                
                # Log response
                self._log_response(api_response)
                
                return api_response
                
        except Exception as e:
            response_time = time.time() - start_time
            error_response = APIResponse(
                status_code=0,
                headers={},
                data=None,
                response_time=response_time,
                correlation_id=correlation_id,
                error=str(e)
            )
            
            self._log_error(request, error_response, e)
            return error_response
    
    def _prepare_headers(self, request: APIRequest, correlation_id: str) -> Dict[str, str]:
        """Prepare request headers with security and metadata."""
        headers = {
            'X-Correlation-ID': correlation_id,
            'X-Request-ID': str(uuid.uuid4()),
            'X-Timestamp': datetime.utcnow().isoformat(),
            'X-Service-Name': self.config.service_name,
            'X-Service-Version': self.config.service_version,
            'X-Environment': self.config.environment.value,
            'X-Classification': request.classification.value,
            'X-Endpoint-Type': request.endpoint_type.value,
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }
        
        # Add API key if configured
        if self.config.api_key:
            headers['X-API-Key'] = self.config.api_key
        
        # Merge with request headers
        headers.update(request.headers)
        
        return headers
    
    async def _prepare_request_data(self, request: APIRequest) -> Optional[bytes]:
        """Prepare and optionally encrypt request data."""
        if not request.data:
            return None
        
        # Convert to JSON if dict
        if isinstance(request.data, dict):
            data_str = json.dumps(request.data)
        elif isinstance(request.data, str):
            data_str = request.data
        else:
            return request.data  # Already bytes
        
        # Encrypt sensitive data if required
        if request.classification != SecurityClassification.UNCLASSIFIED:
            if self.encryption_manager:
                encrypted_data = await self.encryption_manager.encrypt_data(
                    data_str.encode('utf-8')
                )
                return encrypted_data
        
        return data_str.encode('utf-8')
    
    async def _process_response(self, response: aiohttp.ClientResponse) -> Any:
        """Process and optionally decrypt response data."""
        try:
            content_type = response.headers.get('Content-Type', '')
            
            if 'application/json' in content_type:
                data = await response.json()
            else:
                data = await response.text()
            
            # Decrypt if encrypted response
            if response.headers.get('X-Encrypted') == 'true':
                if self.encryption_manager and isinstance(data, bytes):
                    decrypted_data = await self.encryption_manager.decrypt_data(data)
                    return json.loads(decrypted_data.decode('utf-8'))
            
            return data
            
        except Exception as e:
            self.logger.error(f"Failed to process response: {e}")
            return await response.text()
    
    def _validate_request_security(self, request: APIRequest) -> None:
        """Validate request meets security requirements."""
        # Check classification handling
        if request.classification != SecurityClassification.UNCLASSIFIED:
            if request.endpoint_type == APIEndpointType.PUBLIC:
                raise ValueError("Cannot send classified data to public endpoint")
        
        # Validate endpoint type
        if request.endpoint_type == APIEndpointType.EXTERNAL:
            if self.config.environment in [APIGatewayEnvironment.SIPRNET]:
                raise ValueError("External endpoints not allowed on SIPRNET")
        
        # Additional security validations
        self._validate_headers_security(request.headers)
    
    def _validate_headers_security(self, headers: Dict[str, str]) -> None:
        """Validate headers for security compliance."""
        # Check for dangerous headers
        dangerous_headers = ['X-Forwarded-For', 'X-Real-IP', 'X-Original-IP']
        for header in dangerous_headers:
            if header in headers:
                self.logger.warning(f"Potentially dangerous header detected: {header}")
        
        # Validate authorization headers
        if 'Authorization' in headers:
            auth_value = headers['Authorization']
            if not (auth_value.startswith('Bearer ') or auth_value.startswith('Basic ')):
                raise ValueError("Invalid authorization header format")
    
    async def _check_rate_limit(self) -> None:
        """Check and enforce rate limiting."""
        current_time = time.time()
        
        # Reset window if expired
        if current_time >= self._rate_limit_reset:
            self._rate_limit_tokens = self.config.rate_limit_requests
            self._rate_limit_reset = current_time + self.config.rate_limit_window
        
        # Check if tokens available
        if self._rate_limit_tokens <= 0:
            wait_time = self._rate_limit_reset - current_time
            raise Exception(f"Rate limit exceeded. Wait {wait_time:.1f} seconds")
        
        # Consume token
        self._rate_limit_tokens -= 1
    
    def _log_request(self, request: APIRequest, correlation_id: str) -> None:
        """Log API request for audit purposes."""
        log_data = {
            'timestamp': datetime.utcnow().isoformat(),
            'correlation_id': correlation_id,
            'service': self.config.service_name,
            'environment': self.config.environment.value,
            'method': request.method,
            'endpoint': request.endpoint,
            'endpoint_type': request.endpoint_type.value,
            'classification': request.classification.value,
            'user_agent': f'{self.config.service_name}/{self.config.service_version}'
        }
        
        self.logger.info(f"API Request: {json.dumps(log_data)}")
    
    def _log_response(self, response: APIResponse) -> None:
        """Log API response for audit purposes."""
        log_data = {
            'timestamp': datetime.utcnow().isoformat(),
            'correlation_id': response.correlation_id,
            'status_code': response.status_code,
            'response_time': round(response.response_time, 3),
            'success': response.status_code < 400
        }
        
        self.logger.info(f"API Response: {json.dumps(log_data)}")
    
    def _log_error(self, request: APIRequest, response: APIResponse, error: Exception) -> None:
        """Log API error for audit and debugging."""
        log_data = {
            'timestamp': datetime.utcnow().isoformat(),
            'correlation_id': response.correlation_id,
            'service': self.config.service_name,
            'method': request.method,
            'endpoint': request.endpoint,
            'error': str(error),
            'error_type': type(error).__name__
        }
        
        self.logger.error(f"API Error: {json.dumps(log_data)}")
    
    async def close(self) -> None:
        """Clean up resources."""
        if self._session:
            await self._session.close()
        
        self.logger.info("DoD API Gateway client closed")


class APIGatewayManager:
    """
    High-level manager for DoD API Gateway operations.
    
    Provides simplified interface for common operations while maintaining
    full security compliance and audit requirements.
    """
    
    def __init__(self, config: DoDAGWConfig):
        """Initialize API Gateway manager."""
        self.gateway = DoDAPIGateway(config)
        self.logger = logging.getLogger(__name__)
    
    async def initialize(self) -> None:
        """Initialize the gateway manager."""
        await self.gateway.initialize()
    
    async def get_data(self, endpoint: str, params: Optional[Dict] = None,
                      classification: SecurityClassification = SecurityClassification.UNCLASSIFIED) -> APIResponse:
        """GET request through API Gateway."""
        request = APIRequest(
            method='GET',
            endpoint=endpoint,
            headers={},
            params=params,
            classification=classification
        )
        
        return await self.gateway.make_request(request)
    
    async def post_data(self, endpoint: str, data: Dict,
                       classification: SecurityClassification = SecurityClassification.UNCLASSIFIED) -> APIResponse:
        """POST request through API Gateway."""
        request = APIRequest(
            method='POST',
            endpoint=endpoint,
            headers={},
            data=data,
            classification=classification
        )
        
        return await self.gateway.make_request(request)
    
    async def put_data(self, endpoint: str, data: Dict,
                      classification: SecurityClassification = SecurityClassification.UNCLASSIFIED) -> APIResponse:
        """PUT request through API Gateway."""
        request = APIRequest(
            method='PUT',
            endpoint=endpoint,
            headers={},
            data=data,
            classification=classification
        )
        
        return await self.gateway.make_request(request)
    
    async def delete_data(self, endpoint: str,
                         classification: SecurityClassification = SecurityClassification.UNCLASSIFIED) -> APIResponse:
        """DELETE request through API Gateway."""
        request = APIRequest(
            method='DELETE',
            endpoint=endpoint,
            headers={},
            classification=classification
        )
        
        return await self.gateway.make_request(request)
    
    async def close(self) -> None:
        """Clean up resources."""
        await self.gateway.close()


# Example usage and configuration templates
def create_development_config() -> DoDAGWConfig:
    """Create development environment configuration."""
    oauth_config = OAuthConfig(
        platform=Platform.ADVANA,
        client_id="dev-client-id",
        client_secret="dev-client-secret",
        authorization_url="https://dev-auth.advana.mil/oauth/authorize",
        token_url="https://dev-auth.advana.mil/oauth/token",
        redirect_uri="https://localhost:8080/callback",
        scopes=["read", "write"]
    )
    
    return DoDAGWConfig(
        environment=APIGatewayEnvironment.DEVELOPMENT,
        gateway_url="https://dev-api-gateway.advana.mil",
        client_certificate_path="/path/to/client.crt",
        private_key_path="/path/to/client.key",
        ca_bundle_path="/path/to/ca-bundle.crt",
        oauth_config=oauth_config,
        service_name="data-science-platform",
        service_version="1.0.0",
        security_classification=SecurityClassification.UNCLASSIFIED
    )


if __name__ == "__main__":
    # Example usage
    async def main():
        config = create_development_config()
        manager = APIGatewayManager(config)
        
        try:
            await manager.initialize()
            
            # Example API calls
            response = await manager.get_data("/api/v1/data")
            print(f"GET Response: {response.status_code}")
            
            post_response = await manager.post_data(
                "/api/v1/data",
                {"key": "value"}
            )
            print(f"POST Response: {post_response.status_code}")
            
        finally:
            await manager.close()
    
    asyncio.run(main())