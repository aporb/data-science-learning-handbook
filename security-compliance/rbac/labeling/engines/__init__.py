"""
Data Labeling System Engines Package

This package contains the core engines for the data labeling system including
validation, access control, and label management engines.

Classification: UNCLASSIFIED//FOR OFFICIAL USE ONLY
Version: 1.0
Author: Security Compliance Team
Date: 2025-07-17
"""

from .validation_engine import (
    ValidationEngine,
    BatchValidationEngine,
    ValidationJobManager,
    ValidationScheduler
)

from .mac_enforcement_engine import (
    MACEnforcementEngine,
    BellLaPadulaEngine,
    AccessControlDecisionEngine,
    PolicyEvaluationEngine
)

from .label_management_engine import (
    LabelManagementEngine,
    LabelClassificationEngine,
    LabelLifecycleManager,
    CrossDomainTransferEngine
)

from .audit_engine import (
    AuditEngine,
    ComplianceTrackingEngine,
    ReportingEngine,
    MetricsCollectionEngine
)

__all__ = [
    # Validation engines
    'ValidationEngine',
    'BatchValidationEngine',
    'ValidationJobManager',
    'ValidationScheduler',
    
    # MAC enforcement engines
    'MACEnforcementEngine',
    'BellLaPadulaEngine',
    'AccessControlDecisionEngine',
    'PolicyEvaluationEngine',
    
    # Label management engines
    'LabelManagementEngine',
    'LabelClassificationEngine',
    'LabelLifecycleManager',
    'CrossDomainTransferEngine',
    
    # Audit engines
    'AuditEngine',
    'ComplianceTrackingEngine',
    'ReportingEngine',
    'MetricsCollectionEngine'
]

# Package version
__version__ = '1.0.0'

# Package metadata
__author__ = 'Security Compliance Team'
__email__ = 'security@company.mil'
__description__ = 'Data Labeling System Engines'
__classification__ = 'UNCLASSIFIED//FOR OFFICIAL USE ONLY'