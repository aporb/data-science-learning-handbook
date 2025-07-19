"""
Bell-LaPadula Security Model Engine Package

This package implements the Bell-LaPadula mandatory access control model
with comprehensive integration to existing ABAC/RBAC systems.

Classification: UNCLASSIFIED//FOR OFFICIAL USE ONLY
Created: 2025-07-17
Version: 1.0
"""

from .enhanced_engine import EnhancedBellLaPadulaEngine
from .compartment_manager import CompartmentManager
from .information_flow_controller import InformationFlowController
from .security_level_validator import SecurityLevelValidator
from .abac_integration import ABACBellLaPadulaIntegration
from .audit_logger import BellLaPadulaAuditLogger
from .discretionary_access_controller import DiscretionaryAccessController

__all__ = [
    'EnhancedBellLaPadulaEngine',
    'CompartmentManager',
    'InformationFlowController',
    'SecurityLevelValidator',
    'ABACBellLaPadulaIntegration',
    'BellLaPadulaAuditLogger',
    'DiscretionaryAccessController'
]

__version__ = '1.0.0'