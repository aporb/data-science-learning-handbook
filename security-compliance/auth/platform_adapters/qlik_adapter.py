#!/usr/bin/env python3
"""
Qlik Platform Authentication Adapter
Implements CAC/PIV authentication for Qlik Sense Enterprise
"""

import json
import base64
import jwt
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any
from urllib.parse import urljoin

from .base_adapter import (
    BasePlatformAdapter, 
    AuthenticationResult, 
    AuthenticationStatus,
    PlatformConfig
)

class QlikAuthAdapter(BasePlatformAdapter):
    """
    Qlik Sense Enterprise CAC/PIV authentication adapter
    Implements Qlik-specific authentication protocols
    """
    
    def __init__(self, config: PlatformConfig):
        """
        Initialize Qlik authentication adapter
        
        Args:
            config: Qlik-specific configuration
        """
        # Set Qlik-specific defaults if not provided
        if not config.authentication_endpoint:
            config.authentication_endpoint = "/api/v1/auth/certificate"
        if not config.token_endpoint:
            config.token_endpoint = "/api/v1/auth/jwt"
        if not config.user_info_endpoint:
            config.user_info_endpoint = "/api/v1/users/me"
        
        super().__init__(config)
        
        # Qlik-specific configuration
        self.qlik_domain = config.additional_config.get('qlik_domain', 'qlik.local')
        self.virtual_proxy = config.additional_config.get('virtual_proxy', '')
        self.app_access_point = config.additional_config.get('app_access_point', '/hub')
        self.certificate_header = config.additional_config.get('certificate_header', 'X-Qlik-User')
        
        # Qlik JWT configuration
        self.jwt_secret = config.additional_config.get('jwt_secret')
        self.jwt_algorithm = config.additional_config.get('jwt_algorithm', 'HS256')
        
        self.logger.info(f"Initialized Qlik adapter for domain: {self.qlik_domain}")
    
    def authenticate_with_cac(self, certificate_data: bytes, 
                             signature: bytes, challenge: bytes,
                             additional_params: Dict[str, Any] = None) -> AuthenticationResult:
        """
        Authenticate with Qlik using CAC/PIV certificate
        
        Args:
            certificate_data: X.509 certificate in DER format
            signature: Digital signature of challenge
            challenge: Challenge data that was signed
            additional_params: Qlik-specific parameters
            
        Returns:
            AuthenticationResult with Qlik session information
        """
        try:
            # Verify signature first
            if not self._verify_signature(certificate_data, signature, challenge):
                return AuthenticationResult(
                    status=AuthenticationStatus.FAILED,
                    error_message="Digital signature verification failed"
                )
            
            # Extract user information from certificate
            user_id = self._extract_user_id_from_certificate(certificate_data)
            if not user_id:
                return AuthenticationResult(
                    status=AuthenticationStatus.FAILED,
                    error_message="Could not extract user ID from certificate"
                )
            
            # Parse certificate for Qlik user attributes
            user_attributes = self._extract_qlik_user_attributes(certificate_data)
            
            # Create Qlik JWT token
            jwt_payload = {
                'sub': user_id,
                'name': user_attributes.get('name', user_id),
                'email': user_attributes.get('email', ''),
                'groups': user_attributes.get('groups', []),
                'custom_attributes': user_attributes.get('custom_attributes', {}),
                'iat': datetime.now(timezone.utc),
                'exp': datetime.now(timezone.utc) + timedelta(hours=8),
                'iss': 'cac-auth-adapter',
                'aud': self.qlik_domain
            }
            
            # Generate JWT token if secret is available
            jwt_token = None
            if self.jwt_secret:
                jwt_token = jwt.encode(jwt_payload, self.jwt_secret, algorithm=self.jwt_algorithm)
            
            # Prepare authentication request for Qlik
            auth_data = {
                'certificate': base64.b64encode(certificate_data).decode('utf-8'),
                'signature': base64.b64encode(signature).decode('utf-8'),
                'challenge': base64.b64encode(challenge).decode('utf-8'),
                'user_id': user_id,
                'user_attributes': user_attributes,
                'virtual_proxy': self.virtual_proxy,
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
            
            # Add JWT token if available
            if jwt_token:
                auth_data['jwt_token'] = jwt_token
            
            # Custom headers for Qlik
            headers = {
                'Content-Type': 'application/json',
                'X-Qlik-API-Version': self.config.api_version,
                self.certificate_header: user_id
            }
            
            # Make authentication request
            response = self._make_api_request(
                method='POST',
                endpoint=self.config.authentication_endpoint,
                headers=headers,
                data=auth_data
            )
            
            if not response:
                # Fallback: create session ticket directly if API not available
                return self._create_qlik_session_ticket(user_id, user_attributes)
            
            # Parse Qlik response
            if response.get('success', False):
                session_expires = None
                if response.get('expires_in'):
                    session_expires = datetime.now(timezone.utc) + timedelta(seconds=response['expires_in'])
                
                return AuthenticationResult(
                    status=AuthenticationStatus.SUCCESS,
                    user_id=user_id,
                    session_token=response.get('session_token'),
                    platform_token=response.get('ticket'),
                    roles=self._extract_qlik_roles(user_attributes),
                    permissions=self._extract_qlik_permissions(response.get('permissions', [])),
                    session_expires=session_expires,
                    metadata={
                        'qlik_domain': self.qlik_domain,
                        'virtual_proxy': self.virtual_proxy,
                        'user_attributes': user_attributes,
                        'app_access_point': self.app_access_point,
                        'session_ticket': response.get('ticket')
                    }
                )
            else:
                return AuthenticationResult(
                    status=AuthenticationStatus.FAILED,
                    error_message=response.get('error', 'Authentication failed')
                )
                
        except Exception as e:
            self.logger.error(f"Qlik authentication error: {e}")
            return AuthenticationResult(
                status=AuthenticationStatus.FAILED,
                error_message=f"Authentication error: {str(e)}"
            )
    
    def _create_qlik_session_ticket(self, user_id: str, user_attributes: Dict[str, Any]) -> AuthenticationResult:
        """
        Create Qlik session ticket directly (fallback method)
        
        Args:
            user_id: User identifier
            user_attributes: User attributes from certificate
            
        Returns:
            AuthenticationResult with session ticket
        """
        try:
            # Generate session ticket using Qlik Engine API
            ticket_data = {
                'UserDirectory': user_attributes.get('domain', self.qlik_domain),
                'UserId': user_id,
                'Attributes': []
            }
            
            # Add user attributes
            for key, value in user_attributes.items():
                if key not in ['domain', 'user_id']:
                    ticket_data['Attributes'].append({
                        'Name': key,
                        'Value': str(value)
                    })
            
            # Make request to Qlik Proxy Service
            headers = {
                'Content-Type': 'application/json',
                'X-Qlik-User': f"{self.qlik_domain}\\{user_id}",
                'X-Qlik-Virtual-Proxy-Prefix': self.virtual_proxy
            }
            
            response = self._make_api_request(
                method='POST',
                endpoint='/qps/ticket',
                headers=headers,
                data=ticket_data
            )
            
            if response and response.get('Ticket'):
                return AuthenticationResult(
                    status=AuthenticationStatus.SUCCESS,
                    user_id=user_id,
                    platform_token=response['Ticket'],
                    roles=self._extract_qlik_roles(user_attributes),
                    session_expires=datetime.now(timezone.utc) + timedelta(hours=1),
                    metadata={
                        'qlik_domain': self.qlik_domain,
                        'virtual_proxy': self.virtual_proxy,
                        'user_attributes': user_attributes,
                        'session_ticket': response['Ticket']
                    }
                )
            else:
                return AuthenticationResult(
                    status=AuthenticationStatus.FAILED,
                    error_message="Failed to create Qlik session ticket"
                )
                
        except Exception as e:
            self.logger.error(f"Qlik session ticket creation error: {e}")
            return AuthenticationResult(
                status=AuthenticationStatus.FAILED,
                error_message=f"Session ticket creation error: {str(e)}"
            )
    
    def refresh_token(self, session_token: str) -> AuthenticationResult:
        """
        Refresh Qlik authentication token
        
        Args:
            session_token: Current session token
            
        Returns:
            AuthenticationResult with refreshed token
        """
        try:
            headers = {
                'Authorization': f'Bearer {session_token}',
                'X-Qlik-API-Version': self.config.api_version
            }
            
            response = self._make_api_request(
                method='POST',
                endpoint='/api/v1/auth/refresh',
                headers=headers
            )
            
            if response and response.get('success', False):
                session_expires = None
                if response.get('expires_in'):
                    session_expires = datetime.now(timezone.utc) + timedelta(seconds=response['expires_in'])
                
                return AuthenticationResult(
                    status=AuthenticationStatus.SUCCESS,
                    session_token=response.get('session_token'),
                    platform_token=response.get('ticket'),
                    session_expires=session_expires
                )
            else:
                return AuthenticationResult(
                    status=AuthenticationStatus.FAILED,
                    error_message=response.get('error', 'Token refresh failed') if response else 'Network error'
                )
                
        except Exception as e:
            self.logger.error(f"Qlik token refresh error: {e}")
            return AuthenticationResult(
                status=AuthenticationStatus.FAILED,
                error_message=f"Token refresh error: {str(e)}"
            )
    
    def validate_session(self, session_token: str) -> bool:
        """
        Validate Qlik session token
        
        Args:
            session_token: Session token to validate
            
        Returns:
            True if session is valid
        """
        try:
            headers = {
                'X-Qlik-Session': session_token,
                'X-Qlik-API-Version': self.config.api_version
            }
            
            response = self._make_api_request(
                method='GET',
                endpoint='/api/v1/auth/validate',
                headers=headers
            )
            
            return response and response.get('valid', False)
            
        except Exception as e:
            self.logger.error(f"Qlik session validation error: {e}")
            return False
    
    def logout(self, session_token: str) -> bool:
        """
        Logout from Qlik platform
        
        Args:
            session_token: Session token to invalidate
            
        Returns:
            True if logout successful
        """
        try:
            headers = {
                'X-Qlik-Session': session_token,
                'X-Qlik-API-Version': self.config.api_version
            }
            
            response = self._make_api_request(
                method='DELETE',
                endpoint='/api/v1/auth/session',
                headers=headers
            )
            
            return response and response.get('success', False)
            
        except Exception as e:
            self.logger.error(f"Qlik logout error: {e}")
            return False
    
    def get_user_info(self, session_token: str) -> Dict[str, Any]:
        """
        Get user information from Qlik
        
        Args:
            session_token: Valid session token
            
        Returns:
            Dictionary with user information
        """
        try:
            headers = {
                'X-Qlik-Session': session_token,
                'X-Qlik-API-Version': self.config.api_version
            }
            
            response = self._make_api_request(
                method='GET',
                endpoint=self.config.user_info_endpoint,
                headers=headers
            )
            
            if response:
                return response
            else:
                return {}
                
        except Exception as e:
            self.logger.error(f"Qlik user info error: {e}")
            return {}
    
    def get_user_permissions(self, session_token: str, 
                           user_id: str = None) -> List[str]:
        """
        Get user permissions from Qlik
        
        Args:
            session_token: Valid session token
            user_id: User identifier (optional)
            
        Returns:
            List of permission strings
        """
        try:
            headers = {
                'X-Qlik-Session': session_token,
                'X-Qlik-API-Version': self.config.api_version
            }
            
            params = {}
            if user_id:
                params['userId'] = user_id
            
            response = self._make_api_request(
                method='GET',
                endpoint='/api/v1/users/permissions',
                headers=headers,
                params=params
            )
            
            if response:
                return response.get('permissions', [])
            else:
                return []
                
        except Exception as e:
            self.logger.error(f"Qlik permissions error: {e}")
            return []
    
    def _extract_qlik_user_attributes(self, certificate_data: bytes) -> Dict[str, Any]:
        """
        Extract Qlik-specific user attributes from certificate
        
        Args:
            certificate_data: X.509 certificate in DER format
            
        Returns:
            Dictionary with user attributes
        """
        try:
            from cryptography import x509
            
            cert = x509.load_der_x509_certificate(certificate_data)
            attributes = {}
            
            # Extract common name
            for attr in cert.subject:
                if attr.oid == x509.oid.NameOID.COMMON_NAME:
                    attributes['name'] = attr.value
                elif attr.oid == x509.oid.NameOID.ORGANIZATION_NAME:
                    attributes['organization'] = attr.value
                elif attr.oid == x509.oid.NameOID.ORGANIZATIONAL_UNIT_NAME:
                    attributes['department'] = attr.value
                elif attr.oid == x509.oid.NameOID.COUNTRY_NAME:
                    attributes['country'] = attr.value
            
            # Extract email from SAN
            try:
                san_ext = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                for name in san_ext.value:
                    if isinstance(name, x509.RFC822Name):
                        attributes['email'] = name.value
                        break
            except x509.ExtensionNotFound:
                pass
            
            # Set default domain
            attributes['domain'] = self.qlik_domain
            
            # Extract groups from organization
            groups = ['qlik_users']
            if attributes.get('organization'):
                org_clean = attributes['organization'].replace(' ', '_').lower()
                groups.append(f"org_{org_clean}")
            
            if attributes.get('department'):
                dept_clean = attributes['department'].replace(' ', '_').lower()
                groups.append(f"dept_{dept_clean}")
            
            attributes['groups'] = groups
            
            return attributes
            
        except Exception as e:
            self.logger.error(f"Error extracting Qlik user attributes: {e}")
            return {'domain': self.qlik_domain, 'groups': ['qlik_users']}
    
    def _extract_qlik_roles(self, user_attributes: Dict[str, Any]) -> List[str]:
        """
        Extract Qlik-specific roles from user attributes
        
        Args:
            user_attributes: User attributes
            
        Returns:
            List of role strings
        """
        roles = ['qlik_user']
        
        # Add groups as roles
        if user_attributes.get('groups'):
            roles.extend(user_attributes['groups'])
        
        # Add organization-based roles
        if user_attributes.get('organization'):
            org_clean = user_attributes['organization'].replace(' ', '_').lower()
            roles.append(f"qlik_org_{org_clean}")
        
        return list(set(roles))
    
    def _extract_qlik_permissions(self, permissions_data: List) -> List[str]:
        """
        Extract Qlik-specific permissions
        
        Args:
            permissions_data: Permissions data from Qlik
            
        Returns:
            List of permission strings
        """
        permissions = ['qlik:read']
        
        # Add based on groups or roles
        for perm in permissions_data:
            if isinstance(perm, str):
                permissions.append(perm)
            elif isinstance(perm, dict):
                resource = perm.get('resource', '')
                action = perm.get('action', '')
                if resource and action:
                    permissions.append(f"qlik:{resource}:{action}")
        
        return permissions
    
    def _supports_sso(self) -> bool:
        """Check if Qlik supports SSO integration"""
        return True
    
    def _get_max_session_duration(self) -> int:
        """Get maximum session duration for Qlik (8 hours)"""
        return 28800
    
    def _get_required_certificate_fields(self) -> List[str]:
        """Get required certificate fields for Qlik"""
        return ['subject', 'issuer', 'serial_number']
    
    def get_qlik_apps(self, session_token: str) -> List[Dict[str, Any]]:
        """
        Get available Qlik apps for user
        
        Args:
            session_token: Valid session token
            
        Returns:
            List of available apps
        """
        try:
            headers = {
                'X-Qlik-Session': session_token,
                'X-Qlik-API-Version': self.config.api_version
            }
            
            response = self._make_api_request(
                method='GET',
                endpoint='/api/v1/apps',
                headers=headers
            )
            
            if response:
                return response.get('data', [])
            else:
                return []
                
        except Exception as e:
            self.logger.error(f"Qlik apps error: {e}")
            return []
    
    def create_qlik_session_url(self, session_token: str, app_id: str = None) -> str:
        """
        Create Qlik session URL with embedded authentication
        
        Args:
            session_token: Valid session token
            app_id: Specific app ID (optional)
            
        Returns:
            Qlik session URL
        """
        base_url = self.config.base_url.rstrip('/')
        
        if self.virtual_proxy:
            url_prefix = f"{base_url}/{self.virtual_proxy}"
        else:
            url_prefix = base_url
        
        if app_id:
            return f"{url_prefix}/sense/app/{app_id}?qlikTicket={session_token}"
        else:
            return f"{url_prefix}{self.app_access_point}?qlikTicket={session_token}"