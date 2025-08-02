#!/usr/bin/env python3
"""
Databricks Platform Authentication Adapter
Implements CAC/PIV authentication for Databricks platform
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

class DatabricksAuthAdapter(BasePlatformAdapter):
    """
    Databricks platform CAC/PIV authentication adapter
    Implements Databricks-specific authentication protocols
    """
    
    def __init__(self, config: PlatformConfig):
        """
        Initialize Databricks authentication adapter
        
        Args:
            config: Databricks-specific configuration
        """
        # Set Databricks-specific defaults if not provided
        if not config.authentication_endpoint:
            config.authentication_endpoint = "/api/2.0/preview/scim/v2/Users"
        if not config.token_endpoint:
            config.token_endpoint = "/api/2.0/token/create"
        if not config.user_info_endpoint:
            config.user_info_endpoint = "/api/2.0/preview/scim/v2/Me"
        
        super().__init__(config)
        
        # Databricks-specific configuration
        self.workspace_id = config.additional_config.get('workspace_id')
        self.workspace_url = config.additional_config.get('workspace_url')
        self.instance_pool_id = config.additional_config.get('instance_pool_id')
        self.cluster_policy_id = config.additional_config.get('cluster_policy_id')
        
        # Authentication method configuration
        self.auth_method = config.additional_config.get('auth_method', 'personal_access_token')
        self.service_principal_id = config.additional_config.get('service_principal_id')
        
        # OAuth 2.0 integration points
        self.oauth_enabled = config.additional_config.get('oauth_enabled', False)
        self.oauth_client_id = config.additional_config.get('oauth_client_id')
        self.oauth_scopes = config.additional_config.get('oauth_scopes', [])
        
        self.logger.info(f"Initialized Databricks adapter for workspace: {self.workspace_id} (OAuth: {self.oauth_enabled})")
    
    def authenticate_with_cac(self, certificate_data: bytes, 
                             signature: bytes, challenge: bytes,
                             additional_params: Dict[str, Any] = None) -> AuthenticationResult:
        """
        Authenticate with Databricks using CAC/PIV certificate
        
        Args:
            certificate_data: X.509 certificate in DER format
            signature: Digital signature of challenge
            challenge: Challenge data that was signed
            additional_params: Databricks-specific parameters
            
        Returns:
            AuthenticationResult with Databricks session information
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
            
            # Extract user attributes for Databricks
            user_attributes = self._extract_databricks_user_attributes(certificate_data)
            
            # Check if user exists in Databricks, create if not
            existing_user = self._get_or_create_databricks_user(user_id, user_attributes)
            if not existing_user:
                return AuthenticationResult(
                    status=AuthenticationStatus.FAILED,
                    error_message="Failed to create or retrieve Databricks user"
                )
            
            # Create personal access token for user
            token_result = self._create_personal_access_token(user_id, user_attributes)
            if not token_result:
                return AuthenticationResult(
                    status=AuthenticationStatus.FAILED,
                    error_message="Failed to create Databricks access token"
                )
            
            # Extract roles and permissions
            roles = self._extract_databricks_roles(user_attributes, existing_user)
            permissions = self._extract_databricks_permissions(existing_user)
            
            return AuthenticationResult(
                status=AuthenticationStatus.SUCCESS,
                user_id=user_id,
                session_token=token_result['access_token'],
                platform_token=token_result['token_id'],
                roles=roles,
                permissions=permissions,
                session_expires=token_result.get('expires_at'),
                metadata={
                    'workspace_id': self.workspace_id,
                    'workspace_url': self.workspace_url,
                    'user_attributes': user_attributes,
                    'databricks_user_id': existing_user.get('id'),
                    'token_info': token_result,
                    'instance_pool_id': self.instance_pool_id,
                    'cluster_policy_id': self.cluster_policy_id
                }
            )
                
        except Exception as e:
            self.logger.error(f"Databricks authentication error: {e}")
            return AuthenticationResult(
                status=AuthenticationStatus.FAILED,
                error_message=f"Authentication error: {str(e)}"
            )
    
    def refresh_token(self, session_token: str) -> AuthenticationResult:
        """
        Refresh Databricks authentication token
        
        Args:
            session_token: Current session token (personal access token)
            
        Returns:
            AuthenticationResult with refreshed token
        """
        try:
            # For Databricks, we typically create a new token rather than refresh
            # Check if current token is still valid first
            if self.validate_session(session_token):
                # Token is still valid, extend expiration if possible
                headers = {
                    'Authorization': f'Bearer {session_token}',
                    'Content-Type': 'application/json'
                }
                
                # Get token info
                response = self._make_api_request(
                    method='GET',
                    endpoint='/api/2.0/token/list',
                    headers=headers
                )
                
                if response and 'token_infos' in response:
                    # Find current token and try to extend it
                    current_token_info = None
                    for token_info in response['token_infos']:
                        # Match by token prefix or creation time
                        if token_info.get('comment', '').startswith('CAC-Auth'):
                            current_token_info = token_info
                            break
                    
                    if current_token_info:
                        # Create new token to replace the old one
                        new_token_result = self._create_personal_access_token(
                            self._last_authentication.user_id if self._last_authentication else None,
                            self._last_authentication.metadata.get('user_attributes', {}) if self._last_authentication else {}
                        )
                        
                        if new_token_result:
                            # Revoke old token
                            self._revoke_token(current_token_info['token_id'], session_token)
                            
                            return AuthenticationResult(
                                status=AuthenticationStatus.SUCCESS,
                                session_token=new_token_result['access_token'],
                                platform_token=new_token_result['token_id'],
                                session_expires=new_token_result.get('expires_at')
                            )
            
            return AuthenticationResult(
                status=AuthenticationStatus.FAILED,
                error_message="Token refresh failed - token may be invalid or expired"
            )
                
        except Exception as e:
            self.logger.error(f"Databricks token refresh error: {e}")
            return AuthenticationResult(
                status=AuthenticationStatus.FAILED,
                error_message=f"Token refresh error: {str(e)}"
            )
    
    def validate_session(self, session_token: str) -> bool:
        """
        Validate Databricks session token
        
        Args:
            session_token: Session token to validate
            
        Returns:
            True if session is valid
        """
        try:
            headers = {
                'Authorization': f'Bearer {session_token}',
                'Content-Type': 'application/json'
            }
            
            # Try to access user info to validate token
            response = self._make_api_request(
                method='GET',
                endpoint=self.config.user_info_endpoint,
                headers=headers
            )
            
            return response is not None and 'id' in response
            
        except Exception as e:
            self.logger.error(f"Databricks session validation error: {e}")
            return False
    
    def logout(self, session_token: str) -> bool:
        """
        Logout from Databricks platform (revoke token)
        
        Args:
            session_token: Session token to invalidate
            
        Returns:
            True if logout successful
        """
        try:
            # Find and revoke the token
            headers = {
                'Authorization': f'Bearer {session_token}',
                'Content-Type': 'application/json'
            }
            
            # Get token list to find token ID
            response = self._make_api_request(
                method='GET',
                endpoint='/api/2.0/token/list',
                headers=headers
            )
            
            if response and 'token_infos' in response:
                # Find CAC-related token
                for token_info in response['token_infos']:
                    if token_info.get('comment', '').startswith('CAC-Auth'):
                        return self._revoke_token(token_info['token_id'], session_token)
            
            return False
            
        except Exception as e:
            self.logger.error(f"Databricks logout error: {e}")
            return False
    
    def get_user_info(self, session_token: str) -> Dict[str, Any]:
        """
        Get user information from Databricks
        
        Args:
            session_token: Valid session token
            
        Returns:
            Dictionary with user information
        """
        try:
            headers = {
                'Authorization': f'Bearer {session_token}',
                'Content-Type': 'application/json'
            }
            
            response = self._make_api_request(
                method='GET',
                endpoint=self.config.user_info_endpoint,
                headers=headers
            )
            
            return response if response else {}
                
        except Exception as e:
            self.logger.error(f"Databricks user info error: {e}")
            return {}
    
    def get_user_permissions(self, session_token: str, 
                           user_id: str = None) -> List[str]:
        """
        Get user permissions from Databricks
        
        Args:
            session_token: Valid session token
            user_id: User identifier (optional)
            
        Returns:
            List of permission strings
        """
        try:
            headers = {
                'Authorization': f'Bearer {session_token}',
                'Content-Type': 'application/json'
            }
            
            permissions = ['databricks:workspace:access']
            
            # Get user groups
            if user_id:
                user_response = self._make_api_request(
                    method='GET',
                    endpoint=f'/api/2.0/preview/scim/v2/Users/{user_id}',
                    headers=headers
                )
                
                if user_response and 'groups' in user_response:
                    for group in user_response['groups']:
                        group_name = group.get('display', '').lower()
                        permissions.append(f'databricks:group:{group_name}')
            
            # Check cluster access
            clusters_response = self._make_api_request(
                method='GET',
                endpoint='/api/2.0/clusters/list',
                headers=headers
            )
            
            if clusters_response and 'clusters' in clusters_response:
                permissions.append('databricks:clusters:list')
                if clusters_response['clusters']:
                    permissions.append('databricks:clusters:access')
            
            # Check notebook access
            workspace_response = self._make_api_request(
                method='GET',
                endpoint='/api/2.0/workspace/list',
                headers=headers,
                params={'path': '/'}
            )
            
            if workspace_response:
                permissions.append('databricks:workspace:list')
            
            return permissions
                
        except Exception as e:
            self.logger.error(f"Databricks permissions error: {e}")
            return ['databricks:workspace:access']
    
    def _extract_databricks_user_attributes(self, certificate_data: bytes) -> Dict[str, Any]:
        """
        Extract Databricks-specific user attributes from certificate
        
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
                    attributes['displayName'] = attr.value
                    attributes['name'] = {'familyName': attr.value.split()[-1] if ' ' in attr.value else attr.value,
                                         'givenName': attr.value.split()[0] if ' ' in attr.value else ''}
                elif attr.oid == x509.oid.NameOID.ORGANIZATION_NAME:
                    attributes['organization'] = attr.value
                elif attr.oid == x509.oid.NameOID.ORGANIZATIONAL_UNIT_NAME:
                    attributes['department'] = attr.value
            
            # Extract email from SAN
            try:
                san_ext = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                for name in san_ext.value:
                    if isinstance(name, x509.RFC822Name):
                        attributes['emails'] = [{'value': name.value, 'primary': True}]
                        attributes['userName'] = name.value
                        break
            except x509.ExtensionNotFound:
                pass
            
            # Set defaults if not found
            if 'userName' not in attributes:
                user_id = self._extract_user_id_from_certificate(certificate_data)
                attributes['userName'] = user_id or 'unknown@mil'
            
            # Add Databricks-specific attributes
            attributes['active'] = True
            attributes['schemas'] = ['urn:ietf:params:scim:schemas:core:2.0:User']
            
            return attributes
            
        except Exception as e:
            self.logger.error(f"Error extracting Databricks user attributes: {e}")
            return {'userName': 'unknown@mil', 'active': True, 'schemas': ['urn:ietf:params:scim:schemas:core:2.0:User']}
    
    def _get_or_create_databricks_user(self, user_id: str, user_attributes: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Get existing Databricks user or create new one
        
        Args:
            user_id: User identifier
            user_attributes: User attributes
            
        Returns:
            User object from Databricks
        """
        try:
            # Use service account token for user management
            headers = {
                'Content-Type': 'application/json'
            }
            
            # Add service principal authentication if configured
            if self.service_principal_id:
                headers['Authorization'] = f'Bearer {self.service_principal_id}'
            
            # Try to find existing user
            search_response = self._make_api_request(
                method='GET',
                endpoint='/api/2.0/preview/scim/v2/Users',
                headers=headers,
                params={'filter': f'userName eq "{user_attributes["userName"]}"'}
            )
            
            if search_response and search_response.get('Resources'):
                # User exists, return it
                return search_response['Resources'][0]
            
            # User doesn't exist, create new one
            create_response = self._make_api_request(
                method='POST',
                endpoint='/api/2.0/preview/scim/v2/Users',
                headers=headers,
                data=user_attributes
            )
            
            return create_response
            
        except Exception as e:
            self.logger.error(f"Error getting/creating Databricks user: {e}")
            return None
    
    def _create_personal_access_token(self, user_id: str, user_attributes: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Create personal access token for user
        
        Args:
            user_id: User identifier
            user_attributes: User attributes
            
        Returns:
            Token information
        """
        try:
            # Use service account for token creation
            headers = {
                'Content-Type': 'application/json'
            }
            
            if self.service_principal_id:
                headers['Authorization'] = f'Bearer {self.service_principal_id}'
            
            # Create token with 8-hour expiration
            token_data = {
                'comment': f'CAC-Auth token for {user_id}',
                'lifetime_seconds': 28800  # 8 hours
            }
            
            response = self._make_api_request(
                method='POST',
                endpoint='/api/2.0/token/create',
                headers=headers,
                data=token_data
            )
            
            if response and 'token_value' in response:
                return {
                    'access_token': response['token_value'],
                    'token_id': response.get('token_info', {}).get('token_id'),
                    'expires_at': datetime.now(timezone.utc) + timedelta(seconds=28800),
                    'comment': token_data['comment']
                }
            
            return None
            
        except Exception as e:
            self.logger.error(f"Error creating Databricks token: {e}")
            return None
    
    def _revoke_token(self, token_id: str, session_token: str) -> bool:
        """
        Revoke a specific token
        
        Args:
            token_id: Token ID to revoke
            session_token: Current session token for authorization
            
        Returns:
            True if revocation successful
        """
        try:
            headers = {
                'Authorization': f'Bearer {session_token}',
                'Content-Type': 'application/json'
            }
            
            response = self._make_api_request(
                method='POST',
                endpoint='/api/2.0/token/delete',
                headers=headers,
                data={'token_id': token_id}
            )
            
            return response is not None
            
        except Exception as e:
            self.logger.error(f"Error revoking Databricks token: {e}")
            return False
    
    def _extract_databricks_roles(self, user_attributes: Dict[str, Any], 
                                 databricks_user: Dict[str, Any]) -> List[str]:
        """
        Extract Databricks-specific roles
        
        Args:
            user_attributes: User attributes from certificate
            databricks_user: User object from Databricks
            
        Returns:
            List of role strings
        """
        roles = ['databricks_user']
        
        # Add organization-based roles
        if user_attributes.get('organization'):
            org_clean = user_attributes['organization'].replace(' ', '_').lower()
            roles.append(f"databricks_org_{org_clean}")
        
        # Add group-based roles
        if databricks_user.get('groups'):
            for group in databricks_user['groups']:
                group_name = group.get('display', '').replace(' ', '_').lower()
                roles.append(f"databricks_group_{group_name}")
        
        return roles
    
    def _extract_databricks_permissions(self, databricks_user: Dict[str, Any]) -> List[str]:
        """
        Extract Databricks-specific permissions
        
        Args:
            databricks_user: User object from Databricks
            
        Returns:
            List of permission strings
        """
        permissions = ['databricks:workspace:access', 'databricks:user:authenticated']
        
        # Add admin permissions if user is admin
        if databricks_user.get('roles') and 'admin' in [r.get('value', '') for r in databricks_user['roles']]:
            permissions.extend(['databricks:admin:access', 'databricks:clusters:create', 'databricks:workspace:admin'])
        
        return permissions
    
    def _supports_sso(self) -> bool:
        """Check if Databricks supports SSO integration"""
        return True
    
    def _get_max_session_duration(self) -> int:
        """Get maximum session duration for Databricks (8 hours)"""
        return 28800
    
    def _get_required_certificate_fields(self) -> List[str]:
        """Get required certificate fields for Databricks"""
        return ['subject', 'issuer', 'email']
    
    def get_databricks_clusters(self, session_token: str) -> List[Dict[str, Any]]:
        """
        Get available Databricks clusters
        
        Args:
            session_token: Valid session token
            
        Returns:
            List of available clusters
        """
        try:
            headers = {
                'Authorization': f'Bearer {session_token}',
                'Content-Type': 'application/json'
            }
            
            response = self._make_api_request(
                method='GET',
                endpoint='/api/2.0/clusters/list',
                headers=headers
            )
            
            return response.get('clusters', []) if response else []
                
        except Exception as e:
            self.logger.error(f"Databricks clusters error: {e}")
            return []
    
    def create_databricks_cluster(self, session_token: str, 
                                 cluster_config: Dict[str, Any]) -> Optional[str]:
        """
        Create a new Databricks cluster
        
        Args:
            session_token: Valid session token
            cluster_config: Cluster configuration
            
        Returns:
            Cluster ID if successful
        """
        try:
            headers = {
                'Authorization': f'Bearer {session_token}',
                'Content-Type': 'application/json'
            }
            
            # Add default configuration if not specified
            default_config = {
                'cluster_name': f'CAC-User-Cluster-{datetime.now().strftime("%Y%m%d-%H%M%S")}',
                'spark_version': '11.3.x-scala2.12',
                'node_type_id': 'i3.xlarge',
                'num_workers': 1,
                'autotermination_minutes': 60
            }
            
            # Merge with provided config
            final_config = {**default_config, **cluster_config}
            
            # Use instance pool if configured
            if self.instance_pool_id:
                final_config['instance_pool_id'] = self.instance_pool_id
                final_config.pop('node_type_id', None)
            
            # Use cluster policy if configured
            if self.cluster_policy_id:
                final_config['policy_id'] = self.cluster_policy_id
            
            response = self._make_api_request(
                method='POST',
                endpoint='/api/2.0/clusters/create',
                headers=headers,
                data=final_config
            )
            
            return response.get('cluster_id') if response else None
                
        except Exception as e:
            self.logger.error(f"Databricks cluster creation error: {e}")
            return None
    
    def authenticate_with_oauth(self, oauth_token: str, 
                              oauth_metadata: Dict[str, Any] = None) -> AuthenticationResult:
        """
        Authenticate with Databricks using OAuth 2.0 token
        
        Args:
            oauth_token: OAuth 2.0 access token
            oauth_metadata: Optional OAuth metadata
            
        Returns:
            AuthenticationResult with OAuth session information
        """
        try:
            if not self.oauth_enabled:
                return AuthenticationResult(
                    status=AuthenticationStatus.FAILED,
                    error_message="OAuth authentication not enabled for this workspace"
                )
            
            # Validate token with Databricks
            headers = {
                'Authorization': f'Bearer {oauth_token}',
                'Content-Type': 'application/json'
            }
            
            # Get user info using OAuth token
            response = self._make_api_request(
                method='GET',
                endpoint=self.config.user_info_endpoint,
                headers=headers
            )
            
            if not response:
                return AuthenticationResult(
                    status=AuthenticationStatus.FAILED,
                    error_message="Failed to validate OAuth token with Databricks"
                )
            
            user_id = response.get('id') or response.get('userName')
            if not user_id:
                return AuthenticationResult(
                    status=AuthenticationStatus.FAILED,
                    error_message="Could not extract user ID from OAuth response"
                )
            
            # Extract user roles and permissions from OAuth metadata and Databricks response
            roles = self._extract_oauth_roles(oauth_metadata, response)
            permissions = self._extract_oauth_permissions(response)
            
            # Get workspace permissions
            workspace_permissions = self._get_oauth_workspace_permissions(oauth_token, user_id)
            
            return AuthenticationResult(
                status=AuthenticationStatus.SUCCESS,
                user_id=user_id,
                session_token=oauth_token,
                platform_token=oauth_token,
                roles=roles,
                permissions=permissions,
                session_expires=oauth_metadata.get('expires_at') if oauth_metadata else None,
                metadata={
                    'workspace_id': self.workspace_id,
                    'workspace_url': self.workspace_url,
                    'oauth_scopes': oauth_metadata.get('scopes', []) if oauth_metadata else [],
                    'databricks_user_info': response,
                    'workspace_permissions': workspace_permissions,
                    'authentication_method': 'oauth2'
                }
            )
                
        except Exception as e:
            self.logger.error(f"Databricks OAuth authentication error: {e}")
            return AuthenticationResult(
                status=AuthenticationStatus.FAILED,
                error_message=f"OAuth authentication error: {str(e)}"
            )
    
    def validate_oauth_session(self, oauth_token: str) -> bool:
        """
        Validate OAuth session token
        
        Args:
            oauth_token: OAuth access token to validate
            
        Returns:
            True if session is valid
        """
        try:
            if not self.oauth_enabled:
                return False
            
            headers = {
                'Authorization': f'Bearer {oauth_token}',
                'Content-Type': 'application/json'
            }
            
            # Try to access user info to validate token
            response = self._make_api_request(
                method='GET',
                endpoint=self.config.user_info_endpoint,
                headers=headers
            )
            
            return response is not None and ('id' in response or 'userName' in response)
            
        except Exception as e:
            self.logger.error(f"OAuth session validation error: {e}")
            return False
    
    def _extract_oauth_roles(self, oauth_metadata: Dict[str, Any], 
                           databricks_response: Dict[str, Any]) -> List[str]:
        """Extract roles from OAuth metadata and Databricks response."""
        roles = ['databricks_oauth_user']
        
        # Add roles from OAuth scopes
        if oauth_metadata and 'scopes' in oauth_metadata:
            for scope in oauth_metadata['scopes']:
                if 'admin' in scope:
                    roles.append('databricks_admin')
                elif 'cluster' in scope:
                    roles.append('cluster_user')
                elif 'job' in scope:
                    roles.append('job_user')
                elif 'mlflow' in scope:
                    roles.append('mlflow_user')
        
        # Add roles from Databricks groups
        if 'groups' in databricks_response:
            for group in databricks_response['groups']:
                group_name = group.get('display', '').replace(' ', '_').lower()
                if group_name:
                    roles.append(f'databricks_group_{group_name}')
        
        # Add roles from entitlements
        if 'entitlements' in databricks_response:
            for entitlement in databricks_response['entitlements']:
                entitlement_value = entitlement.get('value', '').replace('-', '_').lower()
                if entitlement_value:
                    roles.append(f'databricks_{entitlement_value}')
        
        return roles
    
    def _extract_oauth_permissions(self, databricks_response: Dict[str, Any]) -> List[str]:
        """Extract permissions from Databricks response."""
        permissions = ['databricks:oauth:authenticated']
        
        # Add workspace access permission
        permissions.append('databricks:workspace:access')
        
        # Add permissions based on entitlements
        if 'entitlements' in databricks_response:
            for entitlement in databricks_response['entitlements']:
                entitlement_value = entitlement.get('value', '')
                if entitlement_value:
                    permissions.append(f'databricks:{entitlement_value}')
        
        # Add permissions based on groups
        if 'groups' in databricks_response:
            for group in databricks_response['groups']:
                group_name = group.get('display', '').lower()
                if 'admin' in group_name:
                    permissions.extend([
                        'databricks:admin:access',
                        'databricks:clusters:create',
                        'databricks:workspace:admin'
                    ])
                elif 'user' in group_name:
                    permissions.extend([
                        'databricks:clusters:list',
                        'databricks:workspace:list'
                    ])
        
        return permissions
    
    def _get_oauth_workspace_permissions(self, oauth_token: str, user_id: str) -> List[str]:
        """Get workspace-specific permissions for OAuth user."""
        try:
            headers = {
                'Authorization': f'Bearer {oauth_token}',
                'Content-Type': 'application/json'
            }
            
            workspace_permissions = []
            
            # Check cluster permissions
            clusters_response = self._make_api_request(
                method='GET',
                endpoint='/api/2.0/clusters/list',
                headers=headers
            )
            
            if clusters_response and 'clusters' in clusters_response:
                workspace_permissions.append('databricks:clusters:list')
                if clusters_response['clusters']:
                    workspace_permissions.append('databricks:clusters:access')
            
            # Check workspace list permissions
            workspace_response = self._make_api_request(
                method='GET',
                endpoint='/api/2.0/workspace/list',
                headers=headers,
                params={'path': '/'}
            )
            
            if workspace_response:
                workspace_permissions.append('databricks:workspace:list')
            
            # Check job permissions
            jobs_response = self._make_api_request(
                method='GET',
                endpoint='/api/2.1/jobs/list',
                headers=headers
            )
            
            if jobs_response and 'jobs' in jobs_response:
                workspace_permissions.append('databricks:jobs:list')
                if jobs_response['jobs']:
                    workspace_permissions.append('databricks:jobs:access')
            
            return workspace_permissions
            
        except Exception as e:
            self.logger.error(f"Error getting OAuth workspace permissions: {e}")
            return ['databricks:workspace:basic_access']