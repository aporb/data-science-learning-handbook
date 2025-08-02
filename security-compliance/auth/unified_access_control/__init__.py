"""
Unified Access Control System for DoD Multi-Platform Integration

Provides enterprise-grade unified access control across CAC/PIV authentication,
RBAC permissions, OAuth platform integrations, and comprehensive audit logging.

This module integrates:
- Existing RBAC infrastructure with PermissionResolver and ABAC policy engine
- OAuth 2.0 platform integrations (Qlik, Databricks, Advana, Navy Jupiter)
- CAC/PIV authentication and certificate management
- Cross-platform session management and synchronization
- Unified audit logging and compliance reporting
- Vault-based secure credential management

Architecture:
- UnifiedAccessController: Central access control interface
- CrossPlatformPermissionResolver: Advanced permission resolution engine
- UnifiedUserContext: Multi-platform user profile and context management
- PlatformSessionManager: Cross-platform session synchronization
- AuditIntegrationManager: Comprehensive audit logging across all platforms

Classification: UNCLASSIFIED//FOR OFFICIAL USE ONLY
Version: 1.0
Author: Security Compliance Team
Date: 2025-07-27
"""

from .controller import UnifiedAccessController
from .resolver import CrossPlatformPermissionResolver
from .context import UnifiedUserContext, PlatformContext
from .sessions import PlatformSessionManager, SessionSyncManager
from .audit import AuditIntegrationManager
from .adapters import EnhancedPlatformAdapter, PlatformAdapterRegistry
from .config import UnifiedAccessConfig, PlatformConfig

__all__ = [
    'UnifiedAccessController',
    'CrossPlatformPermissionResolver', 
    'UnifiedUserContext',
    'PlatformContext',
    'PlatformSessionManager',
    'SessionSyncManager',
    'AuditIntegrationManager',
    'EnhancedPlatformAdapter',
    'PlatformAdapterRegistry',
    'UnifiedAccessConfig',
    'PlatformConfig'
]

__version__ = '1.0.0'