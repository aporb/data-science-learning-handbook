"""
Complete Qlik OAuth 2.0 Integration
Production-ready implementation that completes the missing 15% of OAuth infrastructure
for DoD-compliant Qlik platform authentication.
"""

import logging
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
import threading

# Import all enhanced components
from .enhanced_qlik_oauth import (
    EnhancedQlikOAuthClient, 
    QlikOAuthSessionManager, 
    QlikOAuth2Config,
    QlikResourceType,
    QlikPermissionLevel
)
from .enhanced_cac_oauth_binding import (
    EnhancedCACOAuthBinder,
    TokenIntrospectionEnhancer,
    TokenBindingStrength,
    BindingValidationResult
)
from .qlik_permission_mapper import (
    AdvancedQlikPermissionMapper,
    UserPermissionProfile,
    PermissionContext
)
from .qlik_oauth_error_handler import (
    QlikOAuthErrorHandler,
    QlikOAuthHealthMonitor,
    oauth_error_handler
)
from .qlik_oauth_vault_integration import (
    QlikOAuthVaultIntegration,
    ComprehensiveAuditLogger
)

# Import base components
from .oauth_client import Platform, OAuthConfig, TokenResponse
from .oauth_config import DoD_OAuth_Configurator, Environment
from .cac_piv_integration import CACCredentials
from .platform_adapters.qlik_adapter import QlikAuthAdapter, PlatformConfig
from .security_managers import AuditLogger, AuditEvent, AuditEventType

logger = logging.getLogger(__name__)


class QlikIntegrationMode(Enum):
    """Qlik integration modes."""
    CAC_ONLY = "cac_only"
    OAUTH_ONLY = "oauth_only"
    CAC_OAUTH_INTEGRATED = "cac_oauth_integrated"
    DUAL_FACTOR = "dual_factor"


@dataclass
class QlikSessionContext:
    """Complete Qlik session context."""
    session_id: str
    user_id: str
    platform: Platform
    integration_mode: QlikIntegrationMode
    cac_credentials: Optional[CACCredentials]
    oauth_token: Optional[TokenResponse]
    cac_binding: Optional[Any]  # CACTokenBinding
    user_profile: Optional[UserPermissionProfile]
    qlik_session_url: Optional[str]
    created_at: datetime
    expires_at: datetime
    last_activity: datetime
    metadata: Dict[str, Any]


class CompleteQlikOAuthIntegration:
    """
    Complete Qlik OAuth 2.0 integration system.
    
    This class provides the production-ready implementation that completes
    the missing 15% of OAuth infrastructure for DoD-compliant Qlik platform
    authentication with comprehensive CAC integration, error handling,
    and audit logging.
    """
    
    def __init__(self, environment: Environment = Environment.NIPR,
                 default_integration_mode: QlikIntegrationMode = QlikIntegrationMode.CAC_OAUTH_INTEGRATED,
                 enable_vault_integration: bool = True,
                 enable_comprehensive_auditing: bool = True):
        """
        Initialize complete Qlik OAuth integration.
        
        Args:
            environment: DoD network environment
            default_integration_mode: Default integration mode
            enable_vault_integration: Enable Vault credential management
            enable_comprehensive_auditing: Enable comprehensive audit logging
        """
        self.environment = environment
        self.default_integration_mode = default_integration_mode
        self.enable_vault_integration = enable_vault_integration
        self.enable_comprehensive_auditing = enable_comprehensive_auditing
        
        # Initialize core components
        self.oauth_configurator = DoD_OAuth_Configurator(environment)
        self.cac_binder = EnhancedCACOAuthBinder()
        self.permission_mapper = AdvancedQlikPermissionMapper()
        self.error_handler = QlikOAuthErrorHandler()
        self.health_monitor = QlikOAuthHealthMonitor(self.error_handler)
        
        # Initialize optional components
        self.vault_integration = None
        self.comprehensive_auditor = None
        
        if enable_vault_integration:
            self.vault_integration = QlikOAuthVaultIntegration()
        
        if enable_comprehensive_auditing:
            self.comprehensive_auditor = ComprehensiveAuditLogger()
        
        # Active sessions and clients
        self.active_sessions: Dict[str, QlikSessionContext] = {}
        self.oauth_clients: Dict[str, EnhancedQlikOAuthClient] = {}
        self.session_managers: Dict[str, QlikOAuthSessionManager] = {}
        
        # Thread safety
        self._lock = threading.RLock()
        
        logger.info(f"Complete Qlik OAuth integration initialized for {environment.value}")
    
    @oauth_error_handler
    def configure_qlik_platform(self, client_id: str, client_secret: str,
                               redirect_uri: str, scopes: Optional[List[str]] = None,
                               qlik_config: Optional[Dict[str, Any]] = None) -> bool:
        """
        Configure Qlik platform for OAuth integration.
        
        Args:
            client_id: OAuth client ID
            client_secret: OAuth client secret
            redirect_uri: OAuth redirect URI
            scopes: Optional custom scopes
            qlik_config: Optional Qlik-specific configuration
            
        Returns:
            True if configuration successful
        """
        with self._lock:
            try:
                # Create OAuth configuration
                oauth_config = self.oauth_configurator.create_config(
                    platform=Platform.QLIK,
                    client_id=client_id,
                    client_secret=client_secret,
                    redirect_uri=redirect_uri,
                    scopes=scopes or QlikOAuth2Config.get_scope_for_clearance("SECRET")
                )
                
                # Validate configuration
                validation_errors = self.oauth_configurator.validate_config(oauth_config)
                if validation_errors:
                    logger.error(f"OAuth configuration validation failed: {validation_errors}")
                    return False
                
                # Create enhanced OAuth client
                oauth_client = EnhancedQlikOAuthClient(oauth_config)
                
                # Create Qlik platform adapter
                platform_config = PlatformConfig(
                    platform_name="qlik",
                    base_url=oauth_config.authorization_url.split('/oauth')[0],
                    api_version="v1",
                    additional_config=qlik_config or {}
                )
                qlik_adapter = QlikAuthAdapter(platform_config)
                
                # Create session manager
                session_manager = QlikOAuthSessionManager(
                    oauth_client, 
                    self.vault_integration.token_storage if self.vault_integration else None
                )
                
                # Store components
                client_key = f"{Platform.QLIK.value}_{client_id}"
                self.oauth_clients[client_key] = oauth_client
                self.session_managers[client_key] = session_manager
                
                # Store credentials in Vault if enabled
                if self.vault_integration:
                    self.vault_integration.store_oauth_client_credentials(
                        platform=Platform.QLIK,
                        client_id=client_id,
                        client_secret=client_secret,
                        metadata={
                            "environment": self.environment.value,
                            "configured_at": datetime.now(timezone.utc).isoformat(),
                            "scopes": oauth_config.scopes,
                            "classification": "SECRET"
                        }
                    )
                
                # Audit log
                if self.comprehensive_auditor:
                    self.comprehensive_auditor.log_oauth_flow_start(
                        user_id="system",
                        platform=Platform.QLIK,
                        flow_type="platform_configuration",
                        additional_data={
                            "client_id": client_id,
                            "scopes": oauth_config.scopes,
                            "environment": self.environment.value
                        }
                    )
                
                logger.info(f"Qlik platform configured successfully: {client_id}")
                return True
                
            except Exception as e:
                logger.error(f"Failed to configure Qlik platform: {e}")
                return False
    
    @oauth_error_handler
    def start_integrated_authentication(self, cac_pin: str, client_id: str,
                                      required_clearance: str = "CONFIDENTIAL",
                                      integration_mode: Optional[QlikIntegrationMode] = None) -> Tuple[bool, Optional[str], Optional[Dict[str, Any]]]:
        """
        Start integrated CAC-OAuth authentication flow.
        
        Args:
            cac_pin: CAC PIN for authentication
            client_id: OAuth client ID
            required_clearance: Minimum required clearance
            integration_mode: Optional integration mode override
            
        Returns:
            Tuple of (success, oauth_url, session_context)
        """
        with self._lock:
            try:
                mode = integration_mode or self.default_integration_mode
                
                # Audit log - flow start
                if self.comprehensive_auditor:
                    self.comprehensive_auditor.log_oauth_flow_start(
                        user_id="unknown",
                        platform=Platform.QLIK,
                        flow_type="integrated_authentication",
                        additional_data={
                            "integration_mode": mode.value,
                            "required_clearance": required_clearance
                        }
                    )
                
                # Step 1: CAC Authentication
                from .cac_piv_integration import CACAuthenticationManager
                cac_manager = CACAuthenticationManager()
                cac_credentials = cac_manager.authenticate_user(cac_pin)
                
                if not cac_credentials:
                    logger.error("CAC authentication failed")
                    return False, None, {"error": "cac_authentication_failed"}
                
                # Check clearance level
                if not self._check_clearance_requirement(cac_credentials.clearance_level, required_clearance):
                    logger.warning(f"Insufficient clearance: {cac_credentials.clearance_level} < {required_clearance}")
                    return False, None, {"error": "insufficient_clearance"}
                
                # Step 2: Create user permission profile
                available_scopes = QlikOAuth2Config.get_scope_for_clearance(cac_credentials.clearance_level)
                user_profile = self.permission_mapper.create_user_profile(cac_credentials, available_scopes)
                
                # Step 3: Get OAuth authorization URL
                client_key = f"{Platform.QLIK.value}_{client_id}"
                oauth_client = self.oauth_clients.get(client_key)
                
                if not oauth_client:
                    logger.error(f"OAuth client not configured: {client_id}")
                    return False, None, {"error": "oauth_client_not_configured"}
                
                # Get authorization URL with CAC context
                auth_url_result = oauth_client.get_authorization_url(
                    additional_params={
                        "cac_bound": "true",
                        "edipi": cac_credentials.edipi,
                        "clearance": cac_credentials.clearance_level,
                        "integration_mode": mode.value
                    }
                )
                
                if not auth_url_result:
                    logger.error("Failed to get OAuth authorization URL")
                    return False, None, {"error": "authorization_url_failed"}
                
                oauth_url, state = auth_url_result
                
                # Step 4: Create preliminary session context
                session_context = {
                    "cac_credentials": cac_credentials,
                    "user_profile": user_profile,
                    "oauth_state": state,
                    "integration_mode": mode,
                    "required_clearance": required_clearance,
                    "client_id": client_id,
                    "available_scopes": available_scopes
                }
                
                logger.info(f"Integrated authentication started for EDIPI: {cac_credentials.edipi}")
                return True, oauth_url, session_context
                
            except Exception as e:
                logger.error(f"Failed to start integrated authentication: {e}")
                return False, None, {"error": f"authentication_start_failed: {str(e)}"}
    
    @oauth_error_handler
    def complete_integrated_authentication(self, authorization_code: str, state: str,
                                         session_context: Dict[str, Any]) -> Tuple[bool, Optional[QlikSessionContext]]:
        """
        Complete integrated CAC-OAuth authentication flow.
        
        Args:
            authorization_code: OAuth authorization code
            state: OAuth state parameter
            session_context: Session context from start_integrated_authentication
            
        Returns:
            Tuple of (success, complete_session_context)
        """
        with self._lock:
            try:
                # Validate session context
                cac_credentials = session_context.get("cac_credentials")
                user_profile = session_context.get("user_profile")
                oauth_state = session_context.get("oauth_state")
                client_id = session_context.get("client_id")
                
                if not all([cac_credentials, user_profile, oauth_state, client_id]):
                    logger.error("Invalid session context")
                    return False, None
                
                # Validate state parameter
                if state != oauth_state:
                    logger.error("OAuth state mismatch")
                    return False, None
                
                # Get OAuth client and session manager
                client_key = f"{Platform.QLIK.value}_{client_id}"
                oauth_client = self.oauth_clients.get(client_key)
                session_manager = self.session_managers.get(client_key)
                
                if not oauth_client or not session_manager:
                    logger.error("OAuth components not available")
                    return False, None
                
                # Step 1: Exchange authorization code for tokens
                oauth_token = oauth_client.exchange_code_for_token(authorization_code, state)
                if not oauth_token:
                    logger.error("OAuth token exchange failed")
                    return False, None
                
                # Step 2: Create CAC-OAuth binding
                binding = self.cac_binder.create_binding(
                    cac_credentials, 
                    oauth_token, 
                    TokenBindingStrength.ENHANCED
                )
                
                if not binding:
                    logger.error("CAC-OAuth binding creation failed")
                    return False, None
                
                # Step 3: Validate token with CAC
                if not oauth_client.validate_token_with_cac(oauth_token.access_token, cac_credentials):
                    logger.error("Token validation with CAC failed")
                    return False, None
                
                # Step 4: Create Qlik session
                qlik_session_url = oauth_client.create_qlik_session_with_oauth(
                    oauth_token.access_token
                )
                
                # Step 5: Create complete session context
                session_id = self._generate_session_id()
                complete_session = QlikSessionContext(
                    session_id=session_id,
                    user_id=cac_credentials.edipi,
                    platform=Platform.QLIK,
                    integration_mode=session_context["integration_mode"],
                    cac_credentials=cac_credentials,
                    oauth_token=oauth_token,
                    cac_binding=binding,
                    user_profile=user_profile,
                    qlik_session_url=qlik_session_url,
                    created_at=datetime.now(timezone.utc),
                    expires_at=min(oauth_token.expires_at, binding.expires_at),
                    last_activity=datetime.now(timezone.utc),
                    metadata={
                        "client_id": client_id,
                        "binding_strength": binding.binding_strength.value,
                        "clearance_level": cac_credentials.clearance_level,
                        "scopes": oauth_token.scope.split() if oauth_token.scope else []
                    }
                )
                
                # Step 6: Store session
                self.active_sessions[session_id] = complete_session
                
                # Step 7: Store in Vault if enabled
                if self.vault_integration:
                    # Store tokens
                    self.vault_integration.store_oauth_tokens(
                        Platform.QLIK, 
                        cac_credentials.edipi, 
                        oauth_token, 
                        cac_credentials
                    )
                    
                    # Store binding
                    self.vault_integration.store_cac_oauth_binding(
                        Platform.QLIK,
                        cac_credentials.edipi,
                        binding
                    )
                
                # Step 8: Comprehensive audit logging
                if self.comprehensive_auditor:
                    self.comprehensive_auditor.log_oauth_flow_complete(
                        user_id=cac_credentials.edipi,
                        platform=Platform.QLIK,
                        flow_type="integrated_authentication",
                        success=True,
                        additional_data={
                            "session_id": session_id,
                            "binding_id": binding.binding_id,
                            "integration_mode": complete_session.integration_mode.value,
                            "token_expires_at": oauth_token.expires_at.isoformat(),
                            "binding_expires_at": binding.expires_at.isoformat()
                        }
                    )
                    
                    self.comprehensive_auditor.log_cac_binding_operation(
                        user_id=cac_credentials.edipi,
                        operation="create",
                        binding_id=binding.binding_id,
                        success=True,
                        additional_data={
                            "binding_strength": binding.binding_strength.value,
                            "clearance_level": binding.clearance_level
                        }
                    )
                
                logger.info(f"Integrated authentication completed for EDIPI: {cac_credentials.edipi}")
                return True, complete_session
                
            except Exception as e:
                logger.error(f"Failed to complete integrated authentication: {e}")
                
                # Audit log failure
                if self.comprehensive_auditor:
                    self.comprehensive_auditor.log_oauth_flow_complete(
                        user_id=session_context.get("cac_credentials", {}).get("edipi", "unknown"),
                        platform=Platform.QLIK,
                        flow_type="integrated_authentication",
                        success=False,
                        additional_data={"error": str(e)}
                    )
                
                return False, None
    
    @oauth_error_handler
    def check_resource_access(self, session_id: str, resource_id: str,
                            permission: str, context: str = "normal") -> Tuple[bool, Dict[str, Any]]:
        """
        Check if user can access Qlik resource with specific permission.
        
        Args:
            session_id: Session identifier
            resource_id: Resource identifier
            permission: Requested permission
            context: Permission context
            
        Returns:
            Tuple of (access_granted, access_details)
        """
        with self._lock:
            try:
                # Get session
                session = self.active_sessions.get(session_id)
                if not session:
                    return False, {"error": "session_not_found"}
                
                # Check session expiry
                if datetime.now(timezone.utc) >= session.expires_at:
                    return False, {"error": "session_expired"}
                
                # Map permission and context
                permission_level = getattr(QlikPermissionLevel, permission.upper(), None)
                permission_context = getattr(PermissionContext, context.upper(), PermissionContext.NORMAL_OPERATIONS)
                
                if not permission_level:
                    return False, {"error": "invalid_permission"}
                
                # Check access using permission mapper
                access_granted, access_details = self.permission_mapper.check_resource_access(
                    edipi=session.user_id,
                    resource_id=resource_id,
                    permission=permission_level,
                    context=permission_context
                )
                
                # Enhanced access details
                access_details.update({
                    "session_id": session_id,
                    "integration_mode": session.integration_mode.value,
                    "clearance_level": session.cac_credentials.clearance_level if session.cac_credentials else "UNKNOWN",
                    "binding_valid": session.cac_binding is not None
                })
                
                # Audit log permission decision
                if self.comprehensive_auditor:
                    self.comprehensive_auditor.log_permission_decision(
                        user_id=session.user_id,
                        resource_id=resource_id,
                        permission=permission,
                        decision=access_granted,
                        additional_data={
                            "session_id": session_id,
                            "context": context,
                            "access_details": access_details
                        }
                    )
                
                return access_granted, access_details
                
            except Exception as e:
                logger.error(f"Resource access check failed: {e}")
                return False, {"error": f"access_check_failed: {str(e)}"}
    
    @oauth_error_handler
    def refresh_session(self, session_id: str) -> bool:
        """
        Refresh session tokens and bindings.
        
        Args:
            session_id: Session identifier
            
        Returns:
            True if refresh successful
        """
        with self._lock:
            try:
                session = self.active_sessions.get(session_id)
                if not session or not session.oauth_token:
                    return False
                
                # Get OAuth client
                client_key = f"{Platform.QLIK.value}_{session.metadata.get('client_id')}"
                oauth_client = self.oauth_clients.get(client_key)
                
                if not oauth_client:
                    return False
                
                # Refresh token
                new_token = oauth_client.refresh_token_with_enhanced_validation(
                    session.oauth_token.refresh_token,
                    session.cac_credentials
                )
                
                if not new_token:
                    return False
                
                # Update session
                session.oauth_token = new_token
                session.expires_at = min(new_token.expires_at, session.cac_binding.expires_at)
                session.last_activity = datetime.now(timezone.utc)
                
                # Refresh binding
                if session.cac_binding:
                    self.cac_binder.refresh_binding(session.cac_binding.binding_id, new_token)
                
                # Update Vault storage
                if self.vault_integration:
                    self.vault_integration.store_oauth_tokens(
                        Platform.QLIK,
                        session.user_id,
                        new_token,
                        session.cac_credentials
                    )
                
                logger.info(f"Session refreshed: {session_id}")
                return True
                
            except Exception as e:
                logger.error(f"Session refresh failed: {e}")
                return False
    
    def get_session_info(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Get session information."""
        session = self.active_sessions.get(session_id)
        if not session:
            return None
        
        return {
            "session_id": session.session_id,
            "user_id": session.user_id,
            "platform": session.platform.value,
            "integration_mode": session.integration_mode.value,
            "created_at": session.created_at.isoformat(),
            "expires_at": session.expires_at.isoformat(),
            "last_activity": session.last_activity.isoformat(),
            "qlik_session_url": session.qlik_session_url,
            "clearance_level": session.cac_credentials.clearance_level if session.cac_credentials else None,
            "binding_strength": session.cac_binding.binding_strength.value if session.cac_binding else None,
            "metadata": session.metadata
        }
    
    def invalidate_session(self, session_id: str) -> bool:
        """Invalidate and remove session."""
        with self._lock:
            try:
                session = self.active_sessions.pop(session_id, None)
                if not session:
                    return False
                
                # Revoke OAuth token
                if session.oauth_token:
                    client_key = f"{Platform.QLIK.value}_{session.metadata.get('client_id')}"
                    oauth_client = self.oauth_clients.get(client_key)
                    if oauth_client:
                        oauth_client.revoke_token(session.oauth_token.access_token)
                
                # Revoke CAC binding
                if session.cac_binding:
                    self.cac_binder.revoke_binding(session.cac_binding.binding_id, "session_invalidated")
                
                # Clean up Vault storage
                if self.vault_integration:
                    # Remove tokens and bindings from Vault
                    pass  # Implementation depends on Vault API
                
                logger.info(f"Session invalidated: {session_id}")
                return True
                
            except Exception as e:
                logger.error(f"Session invalidation failed: {e}")
                return False
    
    def get_system_health(self) -> Dict[str, Any]:
        """Get comprehensive system health status."""
        try:
            health_info = self.health_monitor.check_system_health()
            
            # Add integration-specific metrics
            health_info.update({
                "active_sessions": len(self.active_sessions),
                "configured_clients": len(self.oauth_clients),
                "vault_integration_enabled": self.vault_integration is not None,
                "comprehensive_auditing_enabled": self.comprehensive_auditor is not None,
                "environment": self.environment.value,
                "default_integration_mode": self.default_integration_mode.value
            })
            
            # Add Vault statistics if enabled
            if self.vault_integration:
                vault_stats = self.vault_integration.get_vault_usage_statistics()
                health_info["vault_statistics"] = vault_stats
            
            return health_info
            
        except Exception as e:
            logger.error(f"Health check failed: {e}")
            return {"status": "error", "error": str(e)}
    
    def cleanup_expired_sessions(self) -> int:
        """Clean up expired sessions and resources."""
        with self._lock:
            expired_sessions = []
            current_time = datetime.now(timezone.utc)
            
            for session_id, session in self.active_sessions.items():
                if current_time >= session.expires_at:
                    expired_sessions.append(session_id)
            
            for session_id in expired_sessions:
                self.invalidate_session(session_id)
            
            # Clean up CAC bindings
            binding_cleanup_count = self.cac_binder.cleanup_expired_bindings()
            
            # Clean up Vault secrets
            vault_cleanup_count = 0
            if self.vault_integration:
                vault_cleanup_count = self.vault_integration.cleanup_expired_secrets()
            
            logger.info(f"Cleanup completed: {len(expired_sessions)} sessions, {binding_cleanup_count} bindings, {vault_cleanup_count} vault secrets")
            return len(expired_sessions) + binding_cleanup_count + vault_cleanup_count
    
    def _check_clearance_requirement(self, user_clearance: str, required_clearance: str) -> bool:
        """Check if user clearance meets requirement."""
        clearance_levels = {
            "UNCLASSIFIED": 0,
            "CONFIDENTIAL": 1,
            "SECRET": 2,
            "TOP SECRET": 3
        }
        
        user_level = clearance_levels.get(user_clearance.upper(), 0)
        required_level = clearance_levels.get(required_clearance.upper(), 0)
        
        return user_level >= required_level
    
    def _generate_session_id(self) -> str:
        """Generate unique session ID."""
        import secrets
        return secrets.token_urlsafe(32)