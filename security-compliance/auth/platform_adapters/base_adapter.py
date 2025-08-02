#!/usr/bin/env python3
"""
Base Platform Authentication Adapter
Defines common interface for platform-specific CAC/PIV integrations
"""

import logging
from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum

logger = logging.getLogger(__name__)

class AuthenticationStatus(Enum):
    """Authentication result status"""
    SUCCESS = "success"
    FAILED = "failed"
    PENDING = "pending"
    EXPIRED = "expired"
    LOCKED = "locked"
    INVALID_CERTIFICATE = "invalid_certificate"
    NETWORK_ERROR = "network_error"

@dataclass
class AuthenticationResult:
    """Result of authentication attempt"""
    status: AuthenticationStatus
    user_id: Optional[str] = None
    session_token: Optional[str] = None
    platform_token: Optional[str] = None
    roles: List[str] = None
    permissions: List[str] = None
    session_expires: Optional[datetime] = None
    error_message: Optional[str] = None
    metadata: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.roles is None:
            self.roles = []
        if self.permissions is None:
            self.permissions = []
        if self.metadata is None:
            self.metadata = {}

@dataclass
class PlatformConfig:
    """Platform-specific configuration"""
    platform_name: str
    base_url: str
    api_version: str
    authentication_endpoint: str
    token_endpoint: str
    user_info_endpoint: str
    timeout: int = 30
    max_retries: int = 3
    verify_ssl: bool = True
    custom_headers: Dict[str, str] = None
    additional_config: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.custom_headers is None:
            self.custom_headers = {}
        if self.additional_config is None:
            self.additional_config = {}

class BasePlatformAdapter(ABC):
    """
    Base class for platform-specific CAC/PIV authentication adapters
    """
    
    def __init__(self, config: PlatformConfig):
        """
        Initialize platform adapter
        
        Args:
            config: Platform-specific configuration
        """
        self.config = config
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        self._session = None
        self._last_authentication = None
        
        self.logger.info(f"Initialized {config.platform_name} adapter")
    
    @abstractmethod
    def authenticate_with_cac(self, certificate_data: bytes, 
                             signature: bytes, challenge: bytes,
                             additional_params: Dict[str, Any] = None) -> AuthenticationResult:
        """
        Authenticate user using CAC/PIV certificate
        
        Args:
            certificate_data: X.509 certificate in DER format
            signature: Digital signature of challenge
            challenge: Challenge data that was signed
            additional_params: Platform-specific parameters
            
        Returns:
            AuthenticationResult with platform-specific tokens
        """
        pass
    
    @abstractmethod
    def refresh_token(self, session_token: str) -> AuthenticationResult:
        """
        Refresh authentication token
        
        Args:
            session_token: Current session token
            
        Returns:
            AuthenticationResult with refreshed token
        """
        pass
    
    @abstractmethod
    def validate_session(self, session_token: str) -> bool:
        """
        Validate if session token is still valid
        
        Args:
            session_token: Session token to validate
            
        Returns:
            True if session is valid
        """
        pass
    
    @abstractmethod
    def logout(self, session_token: str) -> bool:
        """
        Logout and invalidate session
        
        Args:
            session_token: Session token to invalidate
            
        Returns:
            True if logout successful
        """
        pass
    
    @abstractmethod
    def get_user_info(self, session_token: str) -> Dict[str, Any]:
        """
        Get user information from platform
        
        Args:
            session_token: Valid session token
            
        Returns:
            Dictionary with user information
        """
        pass
    
    @abstractmethod
    def get_user_permissions(self, session_token: str, 
                           user_id: str = None) -> List[str]:
        """
        Get user permissions for the platform
        
        Args:
            session_token: Valid session token
            user_id: User identifier (optional)
            
        Returns:
            List of permission strings
        """
        pass
    
    def get_platform_info(self) -> Dict[str, Any]:
        """
        Get platform information and capabilities
        
        Returns:
            Dictionary with platform information
        """
        return {
            'platform_name': self.config.platform_name,
            'api_version': self.config.api_version,
            'base_url': self.config.base_url,
            'supports_cac': True,
            'supports_token_refresh': True,
            'supports_sso': self._supports_sso(),
            'max_session_duration': self._get_max_session_duration(),
            'required_certificate_fields': self._get_required_certificate_fields(),
            'supported_signature_algorithms': self._get_supported_signature_algorithms()
        }
    
    def _supports_sso(self) -> bool:
        """Check if platform supports SSO integration"""
        return False  # Override in subclasses
    
    def _get_max_session_duration(self) -> int:
        """Get maximum session duration in seconds"""
        return 3600  # Default 1 hour, override in subclasses
    
    def _get_required_certificate_fields(self) -> List[str]:
        """Get list of required certificate fields for this platform"""
        return ['subject', 'issuer', 'serial_number', 'edipi']
    
    def _get_supported_signature_algorithms(self) -> List[str]:
        """Get list of supported signature algorithms"""
        return ['SHA256withRSA', 'SHA1withRSA']
    
    def _extract_user_id_from_certificate(self, certificate_data: bytes) -> Optional[str]:
        """
        Extract user ID from certificate data
        
        Args:
            certificate_data: X.509 certificate in DER format
            
        Returns:
            User ID if found
        """
        try:
            from cryptography import x509
            
            cert = x509.load_der_x509_certificate(certificate_data)
            
            # Try to extract EDIPI from SAN
            try:
                san_ext = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                for name in san_ext.value:
                    if isinstance(name, x509.OtherName):
                        # EDIPI is typically in OtherName with specific OID
                        if name.type_id.dotted_string == "2.16.840.1.101.3.6.6":
                            return name.value.decode('utf-8') if isinstance(name.value, bytes) else str(name.value)
            except x509.ExtensionNotFound:
                pass
            
            # Fallback to CN from subject
            for attribute in cert.subject:
                if attribute.oid == x509.oid.NameOID.COMMON_NAME:
                    return attribute.value
                    
        except Exception as e:
            self.logger.error(f"Error extracting user ID from certificate: {e}")
        
        return None
    
    def _generate_challenge(self) -> bytes:
        """
        Generate authentication challenge
        
        Returns:
            Random challenge bytes
        """
        import secrets
        return secrets.token_bytes(32)
    
    def _verify_signature(self, certificate_data: bytes, signature: bytes, 
                         challenge: bytes) -> bool:
        """
        Verify digital signature against certificate
        
        Args:
            certificate_data: X.509 certificate in DER format
            signature: Digital signature to verify
            challenge: Original challenge data
            
        Returns:
            True if signature is valid
        """
        try:
            from cryptography import x509
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.asymmetric import padding
            
            # Load certificate
            cert = x509.load_der_x509_certificate(certificate_data)
            public_key = cert.public_key()
            
            # Verify signature
            public_key.verify(
                signature,
                challenge,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            
            return True
            
        except Exception as e:
            self.logger.error(f"Signature verification failed: {e}")
            return False
    
    def _make_api_request(self, method: str, endpoint: str, 
                         headers: Dict[str, str] = None,
                         data: Dict[str, Any] = None,
                         params: Dict[str, str] = None) -> Union[Dict[str, Any], None]:
        """
        Make API request to platform
        
        Args:
            method: HTTP method (GET, POST, etc.)
            endpoint: API endpoint path
            headers: Additional headers
            data: Request body data
            params: Query parameters
            
        Returns:
            Response data or None if failed
        """
        import requests
        from requests.adapters import HTTPAdapter
        from urllib3.util.retry import Retry
        
        # Prepare URL
        url = f"{self.config.base_url.rstrip('/')}/{endpoint.lstrip('/')}"
        
        # Prepare headers
        request_headers = self.config.custom_headers.copy()
        if headers:
            request_headers.update(headers)
        
        # Setup session with retries
        if not self._session:
            self._session = requests.Session()
            retry_strategy = Retry(
                total=self.config.max_retries,
                backoff_factor=1,
                status_forcelist=[429, 500, 502, 503, 504],
            )
            adapter = HTTPAdapter(max_retries=retry_strategy)
            self._session.mount("http://", adapter)
            self._session.mount("https://", adapter)
        
        try:
            response = self._session.request(
                method=method,
                url=url,
                headers=request_headers,
                json=data,
                params=params,
                timeout=self.config.timeout,
                verify=self.config.verify_ssl
            )
            
            response.raise_for_status()
            
            # Try to return JSON, fallback to text
            try:
                return response.json()
            except:
                return {'response': response.text, 'status_code': response.status_code}
                
        except requests.exceptions.RequestException as e:
            self.logger.error(f"API request failed: {e}")
            return None
    
    def __del__(self):
        """Cleanup session on destruction"""
        if hasattr(self, '_session') and self._session:
            self._session.close()