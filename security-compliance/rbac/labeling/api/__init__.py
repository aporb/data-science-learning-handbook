"""
Data Labeling System API Package

This package contains the RESTful API endpoints for the data labeling system
with mandatory access control enforcement.

Classification: UNCLASSIFIED//FOR OFFICIAL USE ONLY
Version: 1.0
Author: Security Compliance Team
Date: 2025-07-17
"""

from .label_management_api import (
    app,
    api,
    LabelResource,
    LabelListResource,
    LabelValidationResource,
    LabelComplianceResource,
    LabelInheritanceResource,
    LabelAccessResource,
    LabelStatisticsResource
)

__all__ = [
    'app',
    'api',
    'LabelResource',
    'LabelListResource',
    'LabelValidationResource',
    'LabelComplianceResource',
    'LabelInheritanceResource',
    'LabelAccessResource',
    'LabelStatisticsResource'
]

# Package version
__version__ = '1.0.0'

# Package metadata
__author__ = 'Security Compliance Team'
__email__ = 'security@company.mil'
__description__ = 'Data Labeling System API'
__classification__ = 'UNCLASSIFIED//FOR OFFICIAL USE ONLY'