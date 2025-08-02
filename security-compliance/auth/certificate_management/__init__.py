#!/usr/bin/env python3
"""
Certificate Management Module for CAC/PIV Smart Cards

This module provides comprehensive certificate management functionality including:
- Certificate extraction from CAC/PIV cards
- DoD PKI certificate chain validation
- Certificate Revocation List (CRL) checking
- Certificate parsing and metadata extraction
- Trust store management for DoD root CAs
- Certificate expiration monitoring
"""

from .certificate_extractor import CertificateExtractor, CertificateInfo
from .dod_pki_validator import DoDPKIValidator, ValidationContext, ValidationLevel
from .trust_store_manager import TrustStoreManager, TrustedCAInfo
from .certificate_parser import CertificateParser, CertificateMetadata
from .expiration_monitor import ExpirationMonitor, ExpirationAlert
from .certificate_manager import CertificateManager

__all__ = [
    'CertificateExtractor',
    'CertificateInfo', 
    'DoDPKIValidator',
    'ValidationContext',
    'ValidationLevel',
    'TrustStoreManager',
    'TrustedCAInfo',
    'CertificateParser',
    'CertificateMetadata',
    'ExpirationMonitor',
    'ExpirationAlert',
    'CertificateManager'
]

__version__ = "1.0.0"
__author__ = "Data Science Learning Handbook Security Team"