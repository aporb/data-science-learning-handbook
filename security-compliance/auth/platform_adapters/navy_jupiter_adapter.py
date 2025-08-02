#!/usr/bin/env python3
"""
Navy Jupiter Platform Authentication Adapter
Implements CAC/PIV authentication for Navy Jupiter analytics platform
"""

import json
import base64
import hashlib
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any
from urllib.parse import urljoin

from .base_adapter import (
    BasePlatformAdapter, 
    AuthenticationResult, 
    AuthenticationStatus,
    PlatformConfig
)

class NavyJupiterAuthAdapter(BasePlatformAdapter):
    """
    Navy Jupiter platform CAC/PIV authentication adapter
    Implements Jupiter-specific authentication protocols and Navy security requirements
    """
    
    def __init__(self, config: PlatformConfig):
        """
        Initialize Navy Jupiter authentication adapter
        
        Args:
            config: Jupiter-specific configuration
        """
        # Set Jupiter-specific defaults if not provided
        if not config.authentication_endpoint:
            config.authentication_endpoint = "/api/v2/auth/cac"
        if not config.token_endpoint:
            config.token_endpoint = "/api/v2/auth/token"
        if not config.user_info_endpoint:
            config.user_info_endpoint = "/api/v2/user/profile"
        
        super().__init__(config)
        
        # Jupiter-specific configuration
        self.jupiter_environment = config.additional_config.get('environment', 'production')
        self.classification_marking = config.additional_config.get('classification_marking', 'FOUO')
        self.fleet_designation = config.additional_config.get('fleet_designation')
        self.ship_hull_number = config.additional_config.get('ship_hull_number')
        
        # Navy PKI configuration
        self.navy_ca_bundle = config.additional_config.get('navy_ca_bundle_path')
        self.require_nec_code = config.additional_config.get('require_nec_code', True)
        self.allowed_commands = config.additional_config.get('allowed_commands', [])
        
        # Analytics platform settings
        self.jupyter_hub_url = config.additional_config.get('jupyter_hub_url')
        self.analytics_workspace = config.additional_config.get('analytics_workspace', 'default')
        self.data_lake_access = config.additional_config.get('data_lake_access', False)
        
        # Security settings
        self.max_session_duration = config.additional_config.get('max_session_duration', 14400)  # 4 hours
        self.require_operational_security = config.additional_config.get('require_opsec', True)
        
        self.logger.info(f"Initialized Navy Jupiter adapter for environment: {self.jupiter_environment}")
    
    def authenticate_with_cac(self, certificate_data: bytes, 
                             signature: bytes, challenge: bytes,
                             additional_params: Dict[str, Any] = None) -> AuthenticationResult:
        """
        Authenticate with Navy Jupiter using CAC/PIV certificate
        
        Args:
            certificate_data: X.509 certificate in DER format
            signature: Digital signature of challenge
            challenge: Challenge data that was signed
            additional_params: Jupiter-specific parameters
            
        Returns:
            AuthenticationResult with Jupiter session information
        """
        try:
            # Verify signature first
            if not self._verify_signature(certificate_data, signature, challenge):
                return AuthenticationResult(
                    status=AuthenticationStatus.FAILED,
                    error_message="Digital signature verification failed"
                )
            
            # Validate certificate against Navy PKI requirements
            cert_validation = self._validate_navy_certificate(certificate_data)
            if not cert_validation['valid']:
                return AuthenticationResult(
                    status=AuthenticationStatus.INVALID_CERTIFICATE,
                    error_message=f"Certificate validation failed: {cert_validation['error']}"
                )
            
            # Extract user information from certificate
            user_id = self._extract_user_id_from_certificate(certificate_data)
            if not user_id:
                return AuthenticationResult(
                    status=AuthenticationStatus.FAILED,
                    error_message="Could not extract user ID from certificate"
                )
            
            # Extract Jupiter-specific user attributes
            user_attributes = self._extract_jupiter_user_attributes(certificate_data)
            
            # Check user authorization for Jupiter access
            auth_check = self._check_jupiter_authorization(user_id, user_attributes)
            if not auth_check['authorized']:
                return AuthenticationResult(
                    status=AuthenticationStatus.FAILED,
                    error_message=f"User not authorized for Jupiter: {auth_check['reason']}"
                )
            
            # Prepare authentication request for Jupiter
            auth_data = {
                'certificate': base64.b64encode(certificate_data).decode('utf-8'),
                'signature': base64.b64encode(signature).decode('utf-8'),
                'challenge': base64.b64encode(challenge).decode('utf-8'),
                'user_id': user_id,
                'edipi': user_attributes.get('edipi'),
                'nec_code': user_attributes.get('nec_code'),
                'command': user_attributes.get('command'),
                'classification_marking': self.classification_marking,
                'fleet_designation': self.fleet_designation,
                'ship_hull_number': self.ship_hull_number,
                'environment': self.jupiter_environment,
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'session_metadata': {
                    'operational_security': self.require_operational_security,
                    'max_session_duration': self.max_session_duration,
                    'analytics_workspace': self.analytics_workspace
                }
            }
            
            # Custom headers for Jupiter
            headers = {
                'Content-Type': 'application/json',
                'X-Jupiter-Environment': self.jupiter_environment,
                'X-Classification-Marking': self.classification_marking,
                'X-User-EDIPI': user_attributes.get('edipi', ''),
                'X-Navy-Command': user_attributes.get('command', ''),
                'X-CAC-Auth': 'true'
            }
            
            if self.fleet_designation:
                headers['X-Fleet-Designation'] = self.fleet_designation
            
            if self.ship_hull_number:
                headers['X-Ship-Hull-Number'] = self.ship_hull_number
            
            # Make authentication request
            response = self._make_api_request(
                method='POST',
                endpoint=self.config.authentication_endpoint,
                headers=headers,
                data=auth_data
            )
            
            if not response:
                return AuthenticationResult(
                    status=AuthenticationStatus.NETWORK_ERROR,
                    error_message="Failed to connect to Jupiter authentication service"
                )
            
            # Parse Jupiter response
            if response.get('success', False):
                session_expires = None
                if response.get('expires_in'):
                    session_expires = datetime.now(timezone.utc) + timedelta(seconds=response['expires_in'])
                elif response.get('expires_at'):
                    session_expires = datetime.fromisoformat(response['expires_at'])
                
                return AuthenticationResult(
                    status=AuthenticationStatus.SUCCESS,
                    user_id=user_id,
                    session_token=response.get('access_token'),
                    platform_token=response.get('jupiter_token'),
                    roles=self._extract_jupiter_roles(user_attributes, response.get('user_roles', [])),
                    permissions=self._extract_jupiter_permissions(response.get('permissions', [])),
                    session_expires=session_expires,
                    metadata={
                        'jupiter_environment': self.jupiter_environment,
                        'classification_marking': self.classification_marking,
                        'fleet_designation': self.fleet_designation,
                        'ship_hull_number': self.ship_hull_number,
                        'edipi': user_attributes.get('edipi'),
                        'nec_code': user_attributes.get('nec_code'),
                        'command': user_attributes.get('command'),
                        'user_attributes': user_attributes,
                        'jupyter_hub_access': response.get('jupyter_hub_access', False),
                        'data_lake_access': response.get('data_lake_access', False),
                        'analytics_workspace': self.analytics_workspace,
                        'session_id': response.get('session_id')
                    }
                )
            else:
                return AuthenticationResult(
                    status=AuthenticationStatus.FAILED,
                    error_message=response.get('error', 'Jupiter authentication failed')
                )
                
        except Exception as e:
            self.logger.error(f"Navy Jupiter authentication error: {e}")
            return AuthenticationResult(
                status=AuthenticationStatus.FAILED,
                error_message=f"Authentication error: {str(e)}"
            )
    
    def refresh_token(self, session_token: str) -> AuthenticationResult:
        """
        Refresh Jupiter authentication token
        
        Args:
            session_token: Current session token
            
        Returns:
            AuthenticationResult with refreshed token
        """
        try:
            headers = {
                'Authorization': f'Bearer {session_token}',
                'X-Jupiter-Environment': self.jupiter_environment,
                'Content-Type': 'application/json'
            }
            
            response = self._make_api_request(
                method='POST',
                endpoint='/api/v2/auth/refresh',
                headers=headers
            )
            
            if response and response.get('success', False):
                session_expires = None
                if response.get('expires_in'):
                    session_expires = datetime.now(timezone.utc) + timedelta(seconds=response['expires_in'])
                
                return AuthenticationResult(
                    status=AuthenticationStatus.SUCCESS,
                    session_token=response.get('access_token'),
                    platform_token=response.get('jupiter_token'),
                    session_expires=session_expires
                )
            else:
                return AuthenticationResult(
                    status=AuthenticationStatus.FAILED,
                    error_message=response.get('error', 'Token refresh failed') if response else 'Network error'
                )
                
        except Exception as e:
            self.logger.error(f"Jupiter token refresh error: {e}")
            return AuthenticationResult(
                status=AuthenticationStatus.FAILED,
                error_message=f"Token refresh error: {str(e)}"
            )
    
    def validate_session(self, session_token: str) -> bool:
        """
        Validate Jupiter session token
        
        Args:
            session_token: Session token to validate
            
        Returns:
            True if session is valid
        """
        try:
            headers = {
                'Authorization': f'Bearer {session_token}',
                'X-Jupiter-Environment': self.jupiter_environment
            }
            
            response = self._make_api_request(
                method='GET',
                endpoint='/api/v2/auth/validate',
                headers=headers
            )
            
            return response and response.get('valid', False)
            
        except Exception as e:
            self.logger.error(f"Jupiter session validation error: {e}")
            return False
    
    def logout(self, session_token: str) -> bool:
        """
        Logout from Jupiter platform
        
        Args:
            session_token: Session token to invalidate
            
        Returns:
            True if logout successful
        """
        try:
            headers = {
                'Authorization': f'Bearer {session_token}',
                'X-Jupiter-Environment': self.jupiter_environment
            }
            
            response = self._make_api_request(
                method='POST',
                endpoint='/api/v2/auth/logout',
                headers=headers
            )
            
            return response and response.get('success', False)
            
        except Exception as e:
            self.logger.error(f"Jupiter logout error: {e}")
            return False
    
    def get_user_info(self, session_token: str) -> Dict[str, Any]:
        """
        Get user information from Jupiter
        
        Args:
            session_token: Valid session token
            
        Returns:
            Dictionary with user information
        """
        try:
            headers = {
                'Authorization': f'Bearer {session_token}',
                'X-Jupiter-Environment': self.jupiter_environment
            }
            
            response = self._make_api_request(
                method='GET',
                endpoint=self.config.user_info_endpoint,
                headers=headers
            )
            
            return response if response else {}
                
        except Exception as e:
            self.logger.error(f"Jupiter user info error: {e}")
            return {}
    
    def get_user_permissions(self, session_token: str, 
                           user_id: str = None) -> List[str]:
        """
        Get user permissions from Jupiter
        
        Args:
            session_token: Valid session token
            user_id: User identifier (optional)
            
        Returns:
            List of permission strings
        """
        try:
            headers = {
                'Authorization': f'Bearer {session_token}',
                'X-Jupiter-Environment': self.jupiter_environment
            }
            
            params = {}
            if user_id:
                params['user_id'] = user_id
            
            response = self._make_api_request(
                method='GET',
                endpoint='/api/v2/user/permissions',
                headers=headers,
                params=params
            )
            
            if response:
                return response.get('permissions', [])
            else:
                return []
                
        except Exception as e:
            self.logger.error(f"Jupiter permissions error: {e}")
            return []
    
    def _validate_navy_certificate(self, certificate_data: bytes) -> Dict[str, Any]:
        """
        Validate certificate against Navy PKI requirements
        
        Args:
            certificate_data: X.509 certificate in DER format
            
        Returns:
            Dictionary with validation results
        """
        try:
            from cryptography import x509
            
            cert = x509.load_der_x509_certificate(certificate_data)
            validation_result = {'valid': True, 'error': None, 'warnings': []}
            
            # Check certificate validity period
            now = datetime.now(timezone.utc)
            if cert.not_valid_after < now:
                validation_result['valid'] = False
                validation_result['error'] = "Certificate has expired"
                return validation_result
            
            if cert.not_valid_before > now:
                validation_result['valid'] = False
                validation_result['error'] = "Certificate is not yet valid"
                return validation_result
            
            # Check issuer for Navy-specific CAs
            issuer_cn = None
            for attr in cert.issuer:
                if attr.oid == x509.oid.NameOID.COMMON_NAME:
                    issuer_cn = attr.value
                    break
            
            # Check if issuer is Navy-related
            if issuer_cn and not any(navy_term in issuer_cn.upper() for navy_term in ['NAVY', 'DOD', 'DISA']):
                validation_result['warnings'].append(f"Certificate issuer may not be Navy PKI: {issuer_cn}")
            
            # Check for EDIPI if required
            edipi = self._extract_edipi_from_certificate(certificate_data)
            if not edipi:
                validation_result['warnings'].append("EDIPI not found in certificate")
            
            # Check for NEC code if required
            if self.require_nec_code:
                nec_code = self._extract_nec_code_from_certificate(certificate_data)
                if not nec_code:
                    validation_result['warnings'].append("NEC code not found in certificate")
            
            return validation_result
            
        except Exception as e:
            return {'valid': False, 'error': f"Certificate validation error: {str(e)}"}
    
    def _extract_edipi_from_certificate(self, certificate_data: bytes) -> Optional[str]:
        """
        Extract EDIPI from certificate
        
        Args:
            certificate_data: X.509 certificate in DER format
            
        Returns:
            EDIPI if found
        """
        try:
            from cryptography import x509
            
            cert = x509.load_der_x509_certificate(certificate_data)
            
            # EDIPI in Subject Alternative Name
            try:
                san_ext = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                for name in san_ext.value:
                    if isinstance(name, x509.OtherName):
                        if name.type_id.dotted_string == "2.16.840.1.101.3.6.6":
                            return name.value.decode('utf-8') if isinstance(name.value, bytes) else str(name.value)
            except x509.ExtensionNotFound:
                pass
            
            # Fallback to serial number
            for attr in cert.subject:
                if attr.oid == x509.oid.NameOID.SERIAL_NUMBER:
                    serial = attr.value
                    if serial.isdigit() and len(serial) == 10:
                        return serial
            
            return None
            
        except Exception as e:
            self.logger.error(f"Error extracting EDIPI: {e}")
            return None
    
    def _extract_nec_code_from_certificate(self, certificate_data: bytes) -> Optional[str]:
        """
        Extract Navy Enlisted Classification (NEC) code from certificate
        
        Args:
            certificate_data: X.509 certificate in DER format
            
        Returns:
            NEC code if found
        """
        try:
            from cryptography import x509
            
            cert = x509.load_der_x509_certificate(certificate_data)
            
            # NEC might be in organizational unit
            for attr in cert.subject:
                if attr.oid == x509.oid.NameOID.ORGANIZATIONAL_UNIT_NAME:
                    ou_value = attr.value.upper()
                    # Look for NEC pattern (4-digit code)
                    import re
                    nec_match = re.search(r'NEC[:\s]*([0-9]{4})', ou_value)
                    if nec_match:
                        return nec_match.group(1)
            
            # Check in Subject Alternative Name extensions
            try:
                san_ext = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                for name in san_ext.value:
                    if isinstance(name, x509.OtherName):
                        # Custom Navy OID for NEC (example OID)
                        if name.type_id.dotted_string == "2.16.840.1.101.3.6.8":
                            return name.value.decode('utf-8') if isinstance(name.value, bytes) else str(name.value)
            except x509.ExtensionNotFound:
                pass
            
            return None
            
        except Exception as e:
            self.logger.error(f"Error extracting NEC code: {e}")
            return None
    
    def _check_jupiter_authorization(self, user_id: str, user_attributes: Dict[str, Any]) -> Dict[str, Any]:
        """
        Check if user is authorized for Jupiter access
        
        Args:
            user_id: User identifier
            user_attributes: User attributes from certificate
            
        Returns:
            Authorization check result
        """
        try:
            # Check EDIPI format
            edipi = user_attributes.get('edipi')
            if not edipi or not edipi.isdigit() or len(edipi) != 10:
                return {'authorized': False, 'reason': 'Invalid or missing EDIPI'}
            
            # Check Navy command authorization
            command = user_attributes.get('command', '').upper()
            if self.allowed_commands and command not in [cmd.upper() for cmd in self.allowed_commands]:
                return {'authorized': False, 'reason': f'Command not authorized for Jupiter: {command}'}
            
            # Check for Navy-specific organization
            organization = user_attributes.get('organization', '').upper()
            if not any(navy_term in organization for navy_term in ['NAVY', 'USN', 'NAVAL']):
                return {'authorized': False, 'reason': 'User not from Navy organization'}
            
            # Check NEC code if required
            if self.require_nec_code and not user_attributes.get('nec_code'):
                return {'authorized': False, 'reason': 'Missing required NEC code'}
            
            return {'authorized': True, 'reason': 'User authorized for Jupiter access'}
            
        except Exception as e:
            return {'authorized': False, 'reason': f'Authorization check failed: {str(e)}'}
    
    def _extract_jupiter_user_attributes(self, certificate_data: bytes) -> Dict[str, Any]:
        """
        Extract Jupiter-specific user attributes from certificate
        
        Args:
            certificate_data: X.509 certificate in DER format
            
        Returns:
            Dictionary with user attributes
        """
        try:
            from cryptography import x509
            
            cert = x509.load_der_x509_certificate(certificate_data)
            attributes = {}
            
            # Extract basic attributes
            for attr in cert.subject:
                if attr.oid == x509.oid.NameOID.COMMON_NAME:
                    attributes['name'] = attr.value
                elif attr.oid == x509.oid.NameOID.ORGANIZATION_NAME:
                    attributes['organization'] = attr.value
                elif attr.oid == x509.oid.NameOID.ORGANIZATIONAL_UNIT_NAME:
                    attributes['unit'] = attr.value
                    # Extract command from OU
                    if 'COMMAND' in attr.value.upper():
                        attributes['command'] = attr.value
                elif attr.oid == x509.oid.NameOID.COUNTRY_NAME:
                    attributes['country'] = attr.value
            
            # Extract EDIPI and NEC code
            attributes['edipi'] = self._extract_edipi_from_certificate(certificate_data)
            attributes['nec_code'] = self._extract_nec_code_from_certificate(certificate_data)
            
            # Extract email
            try:
                san_ext = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                for name in san_ext.value:
                    if isinstance(name, x509.RFC822Name):
                        attributes['email'] = name.value
                        break
            except x509.ExtensionNotFound:
                pass
            
            # Set Jupiter-specific attributes
            attributes['classification_marking'] = self.classification_marking
            attributes['jupiter_environment'] = self.jupiter_environment
            attributes['fleet_designation'] = self.fleet_designation
            attributes['ship_hull_number'] = self.ship_hull_number
            
            return attributes
            
        except Exception as e:
            self.logger.error(f"Error extracting Jupiter user attributes: {e}")
            return {
                'classification_marking': self.classification_marking,
                'jupiter_environment': self.jupiter_environment
            }
    
    def _extract_jupiter_roles(self, user_attributes: Dict[str, Any], 
                              platform_roles: List[str]) -> List[str]:
        """
        Extract Jupiter-specific roles from user attributes and platform response
        
        Args:
            user_attributes: User attributes
            platform_roles: Roles from platform response
            
        Returns:
            List of role strings
        """
        roles = ['jupiter_user']
        
        # Add command-based roles
        if user_attributes.get('command'):
            command_clean = user_attributes['command'].replace(' ', '_').lower()
            roles.append(f"jupiter_command_{command_clean}")
        
        # Add NEC-based roles
        if user_attributes.get('nec_code'):
            roles.append(f"jupiter_nec_{user_attributes['nec_code']}")
        
        # Add fleet-based roles
        if self.fleet_designation:
            roles.append(f"jupiter_fleet_{self.fleet_designation.lower()}")
        
        # Add ship-based roles
        if self.ship_hull_number:
            roles.append(f"jupiter_ship_{self.ship_hull_number.lower()}")
        
        # Add platform-specific roles
        roles.extend([f"jupiter_{role}" for role in platform_roles])
        
        return list(set(roles))
    
    def _extract_jupiter_permissions(self, permissions_data: List) -> List[str]:
        """
        Extract Jupiter-specific permissions
        
        Args:
            permissions_data: Permissions data from Jupiter
            
        Returns:
            List of permission strings
        """
        permissions = ['jupiter:access']
        
        # Add based on permissions data
        for perm in permissions_data:
            if isinstance(perm, str):
                permissions.append(f"jupiter:{perm}")
            elif isinstance(perm, dict):
                resource = perm.get('resource', '')
                action = perm.get('action', '')
                if resource and action:
                    permissions.append(f"jupiter:{resource}:{action}")
        
        return permissions
    
    def _supports_sso(self) -> bool:
        """Check if Jupiter supports SSO integration"""
        return True
    
    def _get_max_session_duration(self) -> int:
        """Get maximum session duration for Jupiter"""
        return self.max_session_duration
    
    def _get_required_certificate_fields(self) -> List[str]:
        """Get required certificate fields for Jupiter"""
        fields = ['subject', 'issuer', 'edipi']
        if self.require_nec_code:
            fields.append('nec_code')
        return fields
    
    def get_jupiter_notebooks(self, session_token: str) -> List[Dict[str, Any]]:
        """
        Get available Jupyter notebooks for user
        
        Args:
            session_token: Valid session token
            
        Returns:
            List of available notebooks
        """
        try:
            headers = {
                'Authorization': f'Bearer {session_token}',
                'X-Jupiter-Environment': self.jupiter_environment
            }
            
            response = self._make_api_request(
                method='GET',
                endpoint='/api/v2/notebooks',
                headers=headers
            )
            
            return response.get('notebooks', []) if response else []
                
        except Exception as e:
            self.logger.error(f"Jupiter notebooks error: {e}")
            return []
    
    def create_jupiter_notebook_session(self, session_token: str, 
                                       notebook_config: Dict[str, Any]) -> Optional[str]:
        """
        Create notebook session in Jupiter
        
        Args:
            session_token: Valid session token
            notebook_config: Notebook session configuration
            
        Returns:
            Notebook session ID if successful
        """
        try:
            headers = {
                'Authorization': f'Bearer {session_token}',
                'X-Jupiter-Environment': self.jupiter_environment,
                'Content-Type': 'application/json'
            }
            
            # Add default configuration
            default_config = {
                'notebook_name': f'CAC-Notebook-{datetime.now().strftime("%Y%m%d-%H%M%S")}',
                'kernel_type': 'python3',
                'classification_marking': self.classification_marking,
                'workspace': self.analytics_workspace,
                'auto_save': True,
                'max_idle_time': 1800  # 30 minutes
            }
            
            final_config = {**default_config, **notebook_config}
            
            # Add fleet/ship context if available
            if self.fleet_designation:
                final_config['fleet_context'] = self.fleet_designation
            if self.ship_hull_number:
                final_config['ship_context'] = self.ship_hull_number
            
            response = self._make_api_request(
                method='POST',
                endpoint='/api/v2/notebooks/sessions',
                headers=headers,
                data=final_config
            )
            
            return response.get('session_id') if response else None
                
        except Exception as e:
            self.logger.error(f"Jupiter notebook session creation error: {e}")
            return None
    
    def get_jupiter_data_lake_access(self, session_token: str) -> List[Dict[str, Any]]:
        """
        Get available data lake resources for user
        
        Args:
            session_token: Valid session token
            
        Returns:
            List of available data lake resources
        """
        try:
            headers = {
                'Authorization': f'Bearer {session_token}',
                'X-Jupiter-Environment': self.jupiter_environment,
                'X-Classification-Marking': self.classification_marking
            }
            
            response = self._make_api_request(
                method='GET',
                endpoint='/api/v2/data-lake/resources',
                headers=headers
            )
            
            return response.get('resources', []) if response else []
                
        except Exception as e:
            self.logger.error(f"Jupiter data lake access error: {e}")
            return []