"""
RBAC Authentication Integration Layer

This module provides integration bridges between authentication systems
and the RBAC (Role-Based Access Control) system for DoD environments.

The integration layer supports:
- CAC/PIV certificate-based authentication with RBAC role mapping
- OAuth 2.0 authentication for Qlik and Databricks platforms with RBAC integration
- Session management and token validation
- Comprehensive audit logging and error handling
- DoD security compliance standards

Main Components:
- CACRBACBridge: Integrates CAC/PIV authentication with RBAC
- OAuthRBACBridge: Integrates OAuth 2.0 clients with RBAC
- SessionManager: Manages authentication sessions across platforms
- AuditLogger: Provides comprehensive audit logging for authentication events

Usage:
    from security_compliance.rbac.integrations import (
        CACRBACBridge, 
        OAuthRBACBridge
    )
    
    # Initialize CAC integration
    cac_bridge = CACRBACBridge()
    
    # Initialize OAuth integration
    oauth_bridge = OAuthRBACBridge()
"""

from .cac_rbac_bridge import (
    CACRBACBridge,
    CACSessionManager,
    CACRoleMapper,
    CACValidationError,
    CACMappingError
)

from .oauth_rbac_bridge import (
    OAuthRBACBridge,
    OAuthSessionManager,
    OAuthRoleMapper,
    PlatformTokenValidator,
    OAuthValidationError,
    OAuthMappingError,
    SupportedPlatform
)

__all__ = [
    # CAC Integration
    'CACRBACBridge',
    'CACSessionManager', 
    'CACRoleMapper',
    'CACValidationError',
    'CACMappingError',
    
    # OAuth Integration
    'OAuthRBACBridge',
    'OAuthSessionManager',
    'OAuthRoleMapper', 
    'PlatformTokenValidator',
    'OAuthValidationError',
    'OAuthMappingError',
    'SupportedPlatform'
]

__version__ = '2.0.0'
__author__ = 'DoD RBAC Integration Team'
__classification__ = 'UNCLASSIFIED//CUI'