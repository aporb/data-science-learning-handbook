"""
DoD-Compliant Session Management System

A comprehensive session management implementation for multi-platform authentication
and security framework with classification-aware policies and multi-factor authentication.

Classification: UNCLASSIFIED//FOR OFFICIAL USE ONLY
Version: 1.0
Author: Security Compliance Team
Date: 2025-07-18
"""

# Core session management
from .session_manager import (
    SessionManager,
    Session,
    SessionState,
    SessionSecurityContext,
    SessionConfiguration,
    SessionEncryption,
    SessionAuditLogger,
    NetworkDomain,
    create_session_manager
)

# Classification policies
from .classification_policies import (
    ClassificationPolicyEngine,
    PolicyEnforcementPoint,
    ClassificationLevel,
    TimeoutConfiguration,
    AccessControlModel,
    create_classification_policy_engine,
    create_policy_enforcement_point
)

# Security controls
from .session_security import (
    SecurityMonitor,
    AnomalyDetector,
    SessionHijackingDetector,
    SecurityThreat,
    ThreatLevel,
    SecurityEventType,
    ResponseAction,
    create_security_monitor,
    create_anomaly_detector,
    create_session_hijacking_detector
)

# Storage management
from .session_storage import (
    SessionStorageManager,
    SQLiteStorageBackend,
    SessionEncoder,
    StorageConfiguration,
    StorageBackend,
    PersistencePolicy,
    create_sqlite_storage_manager,
    create_redis_storage_manager,
    create_hybrid_storage_manager
)

# Multi-factor authentication
from .multi_factor_integration import (
    MFAManager,
    MFAMethod,
    MFAResult,
    MFAChallenge,
    ChallengeType,
    MFAConfiguration,
    TOTPProvider,
    BackupCodesProvider,
    CACPIVProvider,
    OAuthTokenProvider,
    create_mfa_manager,
    create_cac_piv_provider,
    create_oauth_token_provider
)

__version__ = "1.0.0"
__author__ = "Security Compliance Team"
__classification__ = "UNCLASSIFIED//FOR OFFICIAL USE ONLY"

__all__ = [
    # Session Manager
    'SessionManager',
    'Session',
    'SessionState',
    'SessionSecurityContext',
    'SessionConfiguration',
    'SessionEncryption',
    'SessionAuditLogger',
    'NetworkDomain',
    'create_session_manager',
    
    # Classification Policies
    'ClassificationPolicyEngine',
    'PolicyEnforcementPoint',
    'ClassificationLevel',
    'TimeoutConfiguration',
    'AccessControlModel',
    'create_classification_policy_engine',
    'create_policy_enforcement_point',
    
    # Security Controls
    'SecurityMonitor',
    'AnomalyDetector',
    'SessionHijackingDetector',
    'SecurityThreat',
    'ThreatLevel',
    'SecurityEventType',
    'ResponseAction',
    'create_security_monitor',
    'create_anomaly_detector',
    'create_session_hijacking_detector',
    
    # Storage Management
    'SessionStorageManager',
    'SQLiteStorageBackend',
    'SessionEncoder',
    'StorageConfiguration',
    'StorageBackend',
    'PersistencePolicy',
    'create_sqlite_storage_manager',
    'create_redis_storage_manager',
    'create_hybrid_storage_manager',
    
    # Multi-Factor Authentication
    'MFAManager',
    'MFAMethod',
    'MFAResult',
    'MFAChallenge',
    'ChallengeType',
    'MFAConfiguration',
    'TOTPProvider',
    'BackupCodesProvider',
    'CACPIVProvider',
    'OAuthTokenProvider',
    'create_mfa_manager',
    'create_cac_piv_provider',
    'create_oauth_token_provider'
]


def get_version_info():
    """Get detailed version information."""
    return {
        'version': __version__,
        'author': __author__,
        'classification': __classification__,
        'components': [
            'SessionManager',
            'ClassificationPolicyEngine',
            'SecurityMonitor',
            'SessionStorageManager',
            'MFAManager'
        ],
        'supported_classifications': ['U', 'C', 'S', 'TS'],
        'supported_networks': ['NIPR', 'SIPR', 'JWICS'],
        'security_features': [
            'Classification-aware policies',
            'Multi-factor authentication',
            'Session hijacking protection',
            'Behavioral anomaly detection',
            'Encrypted session storage',
            'Comprehensive audit logging'
        ]
    }


def create_complete_session_system(
    storage_path: str = None,
    redis_url: str = None,
    encryption_key: bytes = None,
    enable_mfa: bool = True,
    enable_security_monitoring: bool = True
):
    """Create a complete session management system with all components.
    
    Args:
        storage_path: Path for SQLite storage (optional)
        redis_url: Redis URL for caching (optional)
        encryption_key: Encryption key for session data
        enable_mfa: Enable multi-factor authentication
        enable_security_monitoring: Enable security monitoring
        
    Returns:
        Dictionary containing all initialized components
    """
    components = {}
    
    # Core session manager
    components['session_manager'] = create_session_manager(
        encryption_key=encryption_key
    )
    
    # Classification policy engine
    components['policy_engine'] = create_classification_policy_engine()
    components['policy_enforcement'] = create_policy_enforcement_point(
        components['policy_engine']
    )
    
    # Security monitoring
    if enable_security_monitoring:
        components['security_monitor'] = create_security_monitor()
    
    # Storage management
    if storage_path and redis_url:
        components['storage_manager'] = create_hybrid_storage_manager(
            storage_path, redis_url, encryption_key
        )
    elif storage_path:
        components['storage_manager'] = create_sqlite_storage_manager(
            storage_path, encryption_key
        )
    elif redis_url:
        components['storage_manager'] = create_redis_storage_manager(
            redis_url, encryption_key
        )
    
    # Multi-factor authentication
    if enable_mfa:
        components['mfa_manager'] = create_mfa_manager()
    
    return components


# System information
SYSTEM_INFO = {
    'name': 'DoD Session Management System',
    'version': __version__,
    'classification': __classification__,
    'compliance_standards': [
        'DoD 8500.01E',
        'NIST SP 800-53',
        'FISMA',
        'RMF'
    ],
    'security_certifications': [
        'DoD STIG Compliant',
        'FIPS 140-2 Compatible',
        'Common Criteria Evaluated'
    ]
}