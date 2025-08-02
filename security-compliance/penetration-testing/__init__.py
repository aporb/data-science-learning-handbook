"""
Isolated Penetration Testing Environment
========================================

Comprehensive penetration testing platform for DoD and federal environments
providing isolated, monitored, and controlled security testing capabilities.

Key Components:
- Isolated Test Environment: Docker-based isolated testing containers
- Testing Infrastructure: Kali Linux and custom security tools deployment
- Security Isolation Framework: Network isolation and monitoring
- Environment Orchestration: Automated provisioning and management
- Integrated Platform: Unified API and existing infrastructure integration

Classification: UNCLASSIFIED//FOR OFFICIAL USE ONLY
Version: 1.0
Date: 2025-07-28
"""

__version__ = "1.0.0"
__author__ = "Security Testing Team"
__classification__ = "UNCLASSIFIED//FOR OFFICIAL USE ONLY"
__date__ = "2025-07-28"

# Import main platform components
try:
    from .integrated_pentest_platform import (
        IntegratedPentestPlatform,
        create_integrated_pentest_platform,
        PlatformConfiguration,
        TestingMode,
        SecurityLevel
    )
    PLATFORM_AVAILABLE = True
except ImportError:
    PLATFORM_AVAILABLE = False

# Import individual components
try:
    from .environment.isolated_test_environment import (
        IsolatedTestEnvironment,
        create_isolated_test_environment
    )
    ENVIRONMENT_AVAILABLE = True
except ImportError:
    ENVIRONMENT_AVAILABLE = False

try:
    from .infrastructure.testing_infrastructure import (
        TestingInfrastructure, 
        create_testing_infrastructure
    )
    INFRASTRUCTURE_AVAILABLE = True
except ImportError:
    INFRASTRUCTURE_AVAILABLE = False

try:
    from .isolation.security_isolation_framework import (
        SecurityIsolationFramework,
        create_security_isolation_framework
    )
    ISOLATION_AVAILABLE = True
except ImportError:
    ISOLATION_AVAILABLE = False

try:
    from .orchestration.environment_orchestrator import (
        EnvironmentOrchestrator,
        create_environment_orchestrator
    )
    ORCHESTRATION_AVAILABLE = True
except ImportError:
    ORCHESTRATION_AVAILABLE = False

# Convenience functions
def get_platform_info():
    """Get platform information and component availability"""
    return {
        "version": __version__,
        "classification": __classification__,
        "components_available": {
            "integrated_platform": PLATFORM_AVAILABLE,
            "environment_manager": ENVIRONMENT_AVAILABLE,
            "infrastructure_manager": INFRASTRUCTURE_AVAILABLE,
            "isolation_framework": ISOLATION_AVAILABLE,
            "orchestration": ORCHESTRATION_AVAILABLE
        }
    }

def create_default_platform():
    """Create platform with default configuration"""
    if not PLATFORM_AVAILABLE:
        raise ImportError("Integrated platform not available")
    
    return create_integrated_pentest_platform()

# Export main classes and functions
__all__ = [
    # Platform
    "IntegratedPentestPlatform",
    "create_integrated_pentest_platform",
    "PlatformConfiguration", 
    "TestingMode",
    "SecurityLevel",
    
    # Individual components
    "IsolatedTestEnvironment",
    "create_isolated_test_environment",
    "TestingInfrastructure",
    "create_testing_infrastructure", 
    "SecurityIsolationFramework",
    "create_security_isolation_framework",
    "EnvironmentOrchestrator",
    "create_environment_orchestrator",
    
    # Utility functions
    "get_platform_info",
    "create_default_platform",
    
    # Availability flags
    "PLATFORM_AVAILABLE",
    "ENVIRONMENT_AVAILABLE", 
    "INFRASTRUCTURE_AVAILABLE",
    "ISOLATION_AVAILABLE",
    "ORCHESTRATION_AVAILABLE"
]