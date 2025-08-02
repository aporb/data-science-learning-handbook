#!/usr/bin/env python3
"""
Advana Platform Authentication Adapter
Implements CAC/PIV authentication for DoD Advana platform
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

class AdvanaAuthAdapter(BasePlatformAdapter):
    """
    DoD Advana platform CAC/PIV authentication adapter
    Implements Advana-specific authentication protocols and DoD security requirements
    """
    
    def __init__(self, config: PlatformConfig):
        """
        Initialize Advana authentication adapter
        
        Args:
            config: Advana-specific configuration
        """
        # Set Advana-specific defaults if not provided
        if not config.authentication_endpoint:
            config.authentication_endpoint = "/api/v1/auth/pki"
        if not config.token_endpoint:
            config.token_endpoint = "/api/v1/auth/token"
        if not config.user_info_endpoint:
            config.user_info_endpoint = "/api/v1/user/profile"
        
        super().__init__(config)
        
        # Advana-specific configuration
        self.advana_environment = config.additional_config.get('environment', 'prod')
        self.classification_level = config.additional_config.get('classification_level', 'UNCLASSIFIED')
        self.tenant_id = config.additional_config.get('tenant_id')
        self.data_fabric_url = config.additional_config.get('data_fabric_url')
        
        # DoD PKI configuration
        self.dod_ca_bundle = config.additional_config.get('dod_ca_bundle_path')
        self.require_edipi = config.additional_config.get('require_edipi', True)
        self.allowed_issuers = config.additional_config.get('allowed_issuers', [])
        
        # Security settings
        self.max_session_duration = config.additional_config.get('max_session_duration', 28800)  # 8 hours
        self.require_smart_card_removal_detection = config.additional_config.get('require_smart_card_removal', True)
        
        self.logger.info(f"Initialized Advana adapter for environment: {self.advana_environment}")
    
    def authenticate_with_cac(self, certificate_data: bytes, 
                             signature: bytes, challenge: bytes,
                             additional_params: Dict[str, Any] = None) -> AuthenticationResult:
        """
        Authenticate with Advana using CAC/PIV certificate
        
        Args:
            certificate_data: X.509 certificate in DER format
            signature: Digital signature of challenge
            challenge: Challenge data that was signed
            additional_params: Advana-specific parameters
            
        Returns:
            AuthenticationResult with Advana session information
        """
        try:
            # Verify signature first
            if not self._verify_signature(certificate_data, signature, challenge):
                return AuthenticationResult(
                    status=AuthenticationStatus.FAILED,
                    error_message="Digital signature verification failed"
                )
            
            # Validate certificate against DoD PKI requirements
            cert_validation = self._validate_dod_certificate(certificate_data)
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
            
            # Extract Advana-specific user attributes
            user_attributes = self._extract_advana_user_attributes(certificate_data)
            
            # Check user authorization in Advana
            auth_check = self._check_advana_authorization(user_id, user_attributes)
            if not auth_check['authorized']:
                return AuthenticationResult(
                    status=AuthenticationStatus.FAILED,
                    error_message=f"User not authorized for Advana: {auth_check['reason']}"
                )
            
            # Prepare authentication request for Advana
            auth_data = {
                'certificate': base64.b64encode(certificate_data).decode('utf-8'),
                'signature': base64.b64encode(signature).decode('utf-8'),
                'challenge': base64.b64encode(challenge).decode('utf-8'),
                'user_id': user_id,
                'edipi': user_attributes.get('edipi'),
                'classification_level': self.classification_level,
                'tenant_id': self.tenant_id,
                'environment': self.advana_environment,
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'session_metadata': {
                    'smart_card_removal_detection': self.require_smart_card_removal_detection,
                    'max_session_duration': self.max_session_duration
                }
            }
            
            # Custom headers for Advana
            headers = {
                'Content-Type': 'application/json',
                'X-Advana-Environment': self.advana_environment,
                'X-Classification-Level': self.classification_level,
                'X-User-EDIPI': user_attributes.get('edipi', ''),
                'X-PKI-Auth': 'true'
            }
            
            if self.tenant_id:
                headers['X-Tenant-ID'] = self.tenant_id
            
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
                    error_message="Failed to connect to Advana authentication service"
                )
            
            # Parse Advana response
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
                    platform_token=response.get('advana_token'),
                    roles=self._extract_advana_roles(user_attributes, response.get('user_roles', [])),
                    permissions=self._extract_advana_permissions(response.get('permissions', [])),
                    session_expires=session_expires,
                    metadata={
                        'advana_environment': self.advana_environment,
                        'classification_level': self.classification_level,
                        'tenant_id': self.tenant_id,
                        'edipi': user_attributes.get('edipi'),
                        'user_attributes': user_attributes,
                        'data_fabric_access': response.get('data_fabric_access', False),
                        'security_clearance': user_attributes.get('security_clearance'),
                        'session_id': response.get('session_id')
                    }
                )
            else:
                return AuthenticationResult(
                    status=AuthenticationStatus.FAILED,
                    error_message=response.get('error', 'Advana authentication failed')
                )
                
        except Exception as e:
            self.logger.error(f"Advana authentication error: {e}")
            return AuthenticationResult(
                status=AuthenticationStatus.FAILED,
                error_message=f"Authentication error: {str(e)}"
            )
    
    def refresh_token(self, session_token: str) -> AuthenticationResult:
        """
        Refresh Advana authentication token
        
        Args:
            session_token: Current session token
            
        Returns:
            AuthenticationResult with refreshed token
        """
        try:
            headers = {
                'Authorization': f'Bearer {session_token}',
                'X-Advana-Environment': self.advana_environment,
                'Content-Type': 'application/json'
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
                    session_token=response.get('access_token'),
                    platform_token=response.get('advana_token'),
                    session_expires=session_expires
                )
            else:
                return AuthenticationResult(
                    status=AuthenticationStatus.FAILED,
                    error_message=response.get('error', 'Token refresh failed') if response else 'Network error'
                )
                
        except Exception as e:
            self.logger.error(f"Advana token refresh error: {e}")
            return AuthenticationResult(
                status=AuthenticationStatus.FAILED,
                error_message=f"Token refresh error: {str(e)}"
            )
    
    def validate_session(self, session_token: str) -> bool:
        """
        Validate Advana session token
        
        Args:
            session_token: Session token to validate
            
        Returns:
            True if session is valid
        """
        try:
            headers = {
                'Authorization': f'Bearer {session_token}',
                'X-Advana-Environment': self.advana_environment
            }
            
            response = self._make_api_request(
                method='GET',
                endpoint='/api/v1/auth/validate',
                headers=headers
            )
            
            return response and response.get('valid', False)
            
        except Exception as e:
            self.logger.error(f"Advana session validation error: {e}")
            return False
    
    def logout(self, session_token: str) -> bool:
        """
        Logout from Advana platform
        
        Args:
            session_token: Session token to invalidate
            
        Returns:
            True if logout successful
        """
        try:
            headers = {
                'Authorization': f'Bearer {session_token}',
                'X-Advana-Environment': self.advana_environment
            }
            
            response = self._make_api_request(
                method='POST',
                endpoint='/api/v1/auth/logout',
                headers=headers
            )
            
            return response and response.get('success', False)
            
        except Exception as e:
            self.logger.error(f"Advana logout error: {e}")
            return False
    
    def get_user_info(self, session_token: str) -> Dict[str, Any]:
        """
        Get user information from Advana
        
        Args:
            session_token: Valid session token
            
        Returns:
            Dictionary with user information
        """
        try:
            headers = {
                'Authorization': f'Bearer {session_token}',
                'X-Advana-Environment': self.advana_environment
            }
            
            response = self._make_api_request(
                method='GET',
                endpoint=self.config.user_info_endpoint,
                headers=headers
            )
            
            return response if response else {}
                
        except Exception as e:
            self.logger.error(f"Advana user info error: {e}")
            return {}
    
    def get_user_permissions(self, session_token: str, 
                           user_id: str = None) -> List[str]:
        """
        Get user permissions from Advana
        
        Args:
            session_token: Valid session token
            user_id: User identifier (optional)
            
        Returns:
            List of permission strings
        """
        try:
            headers = {
                'Authorization': f'Bearer {session_token}',
                'X-Advana-Environment': self.advana_environment
            }
            
            params = {}
            if user_id:
                params['user_id'] = user_id
            
            response = self._make_api_request(
                method='GET',
                endpoint='/api/v1/user/permissions',
                headers=headers,
                params=params
            )
            
            if response:
                return response.get('permissions', [])
            else:
                return []
                
        except Exception as e:
            self.logger.error(f"Advana permissions error: {e}")
            return []
    
    def _validate_dod_certificate(self, certificate_data: bytes) -> Dict[str, Any]:
        """
        Validate certificate against DoD PKI requirements
        
        Args:
            certificate_data: X.509 certificate in DER format
            
        Returns:
            Dictionary with validation results
        """
        try:
            from cryptography import x509
            from cryptography.x509.verification import PolicyBuilder, StoreBuilder
            
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
            
            # Check issuer against allowed issuers
            issuer_cn = None
            for attr in cert.issuer:
                if attr.oid == x509.oid.NameOID.COMMON_NAME:
                    issuer_cn = attr.value
                    break
            
            if self.allowed_issuers and issuer_cn not in self.allowed_issuers:
                validation_result['valid'] = False
                validation_result['error'] = f"Certificate issuer not allowed: {issuer_cn}"
                return validation_result
            
            # Check for EDIPI if required
            if self.require_edipi:
                edipi = self._extract_edipi_from_certificate(certificate_data)
                if not edipi:
                    validation_result['valid'] = False
                    validation_result['error'] = "EDIPI not found in certificate"
                    return validation_result
            
            # Check key usage extensions
            try:
                key_usage = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.KEY_USAGE).value
                if not key_usage.digital_signature:
                    validation_result['warnings'].append("Certificate does not have digital signature key usage")
            except x509.ExtensionNotFound:
                validation_result['warnings'].append("Certificate missing key usage extension")
            
            # Check for DoD-specific OIDs
            self._validate_dod_certificate_extensions(cert, validation_result)
            
            return validation_result
            
        except Exception as e:
            return {'valid': False, 'error': f"Certificate validation error: {str(e)}"}
    
    def _extract_edipi_from_certificate(self, certificate_data: bytes) -> Optional[str]:
        """
        Extract EDIPI (Electronic Data Interchange Personal Identifier) from certificate
        
        Args:
            certificate_data: X.509 certificate in DER format
            
        Returns:
            EDIPI if found
        """
        try:
            from cryptography import x509
            
            cert = x509.load_der_x509_certificate(certificate_data)
            
            # EDIPI is typically in Subject Alternative Name extension
            try:
                san_ext = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                for name in san_ext.value:
                    if isinstance(name, x509.OtherName):
                        # DoD EDIPI OID: 2.16.840.1.101.3.6.6
                        if name.type_id.dotted_string == "2.16.840.1.101.3.6.6":
                            return name.value.decode('utf-8') if isinstance(name.value, bytes) else str(name.value)
            except x509.ExtensionNotFound:
                pass
            
            # Fallback: check subject for EDIPI patterns
            for attr in cert.subject:
                if attr.oid == x509.oid.NameOID.SERIAL_NUMBER:
                    # EDIPI might be in serial number field
                    serial = attr.value
                    if serial.isdigit() and len(serial) == 10:
                        return serial
            
            return None
            
        except Exception as e:
            self.logger.error(f"Error extracting EDIPI: {e}")
            return None
    
    def _validate_dod_certificate_extensions(self, cert, validation_result: Dict[str, Any]) -> None:
        """
        Validate DoD-specific certificate extensions
        
        Args:
            cert: X.509 certificate object
            validation_result: Validation result dictionary to update
        """
        try:
            # Check for DoD PKI policy OIDs
            dod_policy_oids = [
                "2.16.840.1.101.3.2.1.3.1",  # DoD Basic
                "2.16.840.1.101.3.2.1.3.2",  # DoD Medium
                "2.16.840.1.101.3.2.1.3.3",  # DoD Medium-CBP
                "2.16.840.1.101.3.2.1.3.4",  # DoD Basic-Subscriber
            ]
            
            try:
                cert_policies = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.CERTIFICATE_POLICIES).value
                found_dod_policy = False
                
                for policy in cert_policies:
                    if policy.policy_identifier.dotted_string in dod_policy_oids:
                        found_dod_policy = True
                        break
                
                if not found_dod_policy:
                    validation_result['warnings'].append("No DoD policy OID found in certificate")
                    
            except x509.ExtensionNotFound:
                validation_result['warnings'].append("Certificate policies extension not found")
            
        except Exception as e:
            validation_result['warnings'].append(f"Error validating DoD extensions: {str(e)}")
    
    def _check_advana_authorization(self, user_id: str, user_attributes: Dict[str, Any]) -> Dict[str, Any]:
        """
        Check if user is authorized for Advana access
        
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
            
            # Check organization
            organization = user_attributes.get('organization', '').upper()
            if 'DOD' not in organization and 'US' not in organization:
                return {'authorized': False, 'reason': 'User not from authorized DoD organization'}
            
            # Check security clearance if required
            clearance = user_attributes.get('security_clearance')
            if self.classification_level == 'SECRET' and clearance not in ['SECRET', 'TOP SECRET']:
                return {'authorized': False, 'reason': 'Insufficient security clearance'}
            
            # Additional Advana-specific checks could go here
            # For now, assume authorized if basic checks pass
            return {'authorized': True, 'reason': 'User authorized for Advana access'}
            
        except Exception as e:
            return {'authorized': False, 'reason': f'Authorization check failed: {str(e)}'}
    
    def _extract_advana_user_attributes(self, certificate_data: bytes) -> Dict[str, Any]:
        """
        Extract Advana-specific user attributes from certificate
        
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
                elif attr.oid == x509.oid.NameOID.COUNTRY_NAME:
                    attributes['country'] = attr.value
            
            # Extract EDIPI
            attributes['edipi'] = self._extract_edipi_from_certificate(certificate_data)
            
            # Extract email from SAN
            try:
                san_ext = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                for name in san_ext.value:
                    if isinstance(name, x509.RFC822Name):
                        attributes['email'] = name.value
                        break
            except x509.ExtensionNotFound:
                pass
            
            # Determine security clearance level based on certificate type
            attributes['security_clearance'] = self._determine_security_clearance(cert)
            
            # Set Advana-specific attributes
            attributes['classification_level'] = self.classification_level
            attributes['advana_environment'] = self.advana_environment
            
            return attributes
            
        except Exception as e:
            self.logger.error(f"Error extracting Advana user attributes: {e}")
            return {
                'classification_level': self.classification_level,
                'advana_environment': self.advana_environment
            }
    
    def _determine_security_clearance(self, cert) -> str:
        """
        Determine security clearance level from certificate
        
        Args:
            cert: X.509 certificate object
            
        Returns:
            Security clearance level
        """
        try:
            # Check certificate policies for clearance indicators
            cert_policies = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.CERTIFICATE_POLICIES).value
            
            for policy in cert_policies:
                policy_oid = policy.policy_identifier.dotted_string
                
                # DoD policy OID mappings (simplified)
                if policy_oid == "2.16.840.1.101.3.2.1.3.3":  # DoD Medium-CBP
                    return "SECRET"
                elif policy_oid == "2.16.840.1.101.3.2.1.3.2":  # DoD Medium
                    return "SECRET"
                elif policy_oid == "2.16.840.1.101.3.2.1.3.1":  # DoD Basic
                    return "CONFIDENTIAL"
            
            return "UNCLASSIFIED"
            
        except x509.ExtensionNotFound:
            return "UNCLASSIFIED"
        except Exception:
            return "UNCLASSIFIED"
    
    def _extract_advana_roles(self, user_attributes: Dict[str, Any], 
                             platform_roles: List[str]) -> List[str]:
        """
        Extract Advana-specific roles from user attributes and platform response
        
        Args:
            user_attributes: User attributes
            platform_roles: Roles from platform response
            
        Returns:
            List of role strings
        """
        roles = ['advana_user']
        
        # Add clearance-based roles
        clearance = user_attributes.get('security_clearance', 'UNCLASSIFIED')
        roles.append(f"advana_clearance_{clearance.lower()}")
        
        # Add organization-based roles
        if user_attributes.get('organization'):
            org_clean = user_attributes['organization'].replace(' ', '_').lower()
            roles.append(f"advana_org_{org_clean}")
        
        # Add unit-based roles
        if user_attributes.get('unit'):
            unit_clean = user_attributes['unit'].replace(' ', '_').lower()
            roles.append(f"advana_unit_{unit_clean}")
        
        # Add platform-specific roles
        roles.extend([f"advana_{role}" for role in platform_roles])
        
        return list(set(roles))
    
    def _extract_advana_permissions(self, permissions_data: List) -> List[str]:
        """
        Extract Advana-specific permissions
        
        Args:
            permissions_data: Permissions data from Advana
            
        Returns:
            List of permission strings
        """
        permissions = ['advana:access']
        
        # Add based on permissions data
        for perm in permissions_data:
            if isinstance(perm, str):
                permissions.append(f"advana:{perm}")
            elif isinstance(perm, dict):
                resource = perm.get('resource', '')
                action = perm.get('action', '')
                if resource and action:
                    permissions.append(f"advana:{resource}:{action}")
        
        return permissions
    
    def _supports_sso(self) -> bool:
        """Check if Advana supports SSO integration"""
        return True
    
    def _get_max_session_duration(self) -> int:
        """Get maximum session duration for Advana"""
        return self.max_session_duration
    
    def _get_required_certificate_fields(self) -> List[str]:
        """Get required certificate fields for Advana"""
        fields = ['subject', 'issuer', 'serial_number']
        if self.require_edipi:
            fields.append('edipi')
        return fields
    
    def get_advana_data_fabric_access(self, session_token: str) -> List[Dict[str, Any]]:
        """
        Get available data fabric resources for user
        
        Args:
            session_token: Valid session token
            
        Returns:
            List of available data fabric resources
        """
        try:
            headers = {
                'Authorization': f'Bearer {session_token}',
                'X-Advana-Environment': self.advana_environment,
                'X-Classification-Level': self.classification_level
            }
            
            response = self._make_api_request(
                method='GET',
                endpoint='/api/v1/data-fabric/resources',
                headers=headers
            )
            
            return response.get('resources', []) if response else []
                
        except Exception as e:
            self.logger.error(f"Advana data fabric access error: {e}")
            return []
    
    def create_advana_analytics_session(self, session_token: str, 
                                      analytics_config: Dict[str, Any]) -> Optional[str]:
        """
        Create analytics session in Advana
        
        Args:
            session_token: Valid session token
            analytics_config: Analytics session configuration
            
        Returns:
            Analytics session ID if successful
        """
        try:
            headers = {
                'Authorization': f'Bearer {session_token}',
                'X-Advana-Environment': self.advana_environment,
                'Content-Type': 'application/json'
            }
            
            # Add default configuration if not specified
            default_config = {
                'session_name': f'CAC-Analytics-{datetime.now().strftime("%Y%m%d-%H%M%S")}',
                'classification_level': self.classification_level,
                'auto_cleanup': True,
                'max_duration': 14400  # 4 hours
            }
            
            final_config = {**default_config, **analytics_config}
            
            response = self._make_api_request(
                method='POST',
                endpoint='/api/v1/analytics/sessions',
                headers=headers,
                data=final_config
            )
            
            return response.get('session_id') if response else None
                
        except Exception as e:
            self.logger.error(f"Advana analytics session creation error: {e}")
            return None