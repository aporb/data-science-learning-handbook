#!/usr/bin/env python3
"""
DoD PKI Certificate Chain Validation Module

This module provides comprehensive DoD PKI-compliant certificate chain validation
with support for multiple validation levels, policy enforcement, and detailed
compliance reporting.
"""

import os
import logging
import hashlib
import time
from typing import Optional, Dict, List, Tuple, Union, Any, Set
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from enum import Enum
from pathlib import Path
import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding, dsa
from cryptography.x509.verification import PolicyBuilder, StoreBuilder
from cryptography.x509.oid import ExtensionOID, SignatureAlgorithmOID, NameOID
import concurrent.futures
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


class ValidationLevel(Enum):
    """Certificate validation strictness levels."""
    BASIC = "basic"                 # Basic certificate validity and signature
    STANDARD = "standard"           # Standard DoD PKI validation
    STRICT = "strict"              # Strict DoD compliance validation
    MAXIMUM = "maximum"            # Maximum security validation


class PolicyEnforcement(Enum):
    """Certificate policy enforcement modes."""
    PERMISSIVE = "permissive"      # Allow non-DoD certificates with warnings
    STANDARD = "standard"          # Require DoD policies but allow exceptions
    STRICT = "strict"              # Enforce strict DoD policy compliance


class ValidationStatus(Enum):
    """Certificate validation status."""
    VALID = "valid"
    INVALID = "invalid"
    WARNING = "warning"
    UNKNOWN = "unknown"


@dataclass
class ValidationIssue:
    """Individual validation issue or warning."""
    level: str  # ERROR, WARNING, INFO
    category: str  # EXPIRY, POLICY, CHAIN, REVOCATION, etc.
    code: str
    message: str
    details: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class ValidationContext:
    """Context for certificate validation."""
    validation_level: ValidationLevel = ValidationLevel.STANDARD
    policy_enforcement: PolicyEnforcement = PolicyEnforcement.STANDARD
    check_revocation: bool = True
    check_ocsp: bool = True
    check_crl: bool = True
    require_dod_policies: bool = True
    allow_self_signed_roots: bool = False
    max_chain_length: int = 10
    clock_skew_tolerance: timedelta = timedelta(minutes=5)
    trusted_ca_store_path: Optional[str] = None
    validation_time: Optional[datetime] = None  # Use current time if None
    
    # DoD-specific validation options
    require_hardware_protection: bool = True
    minimum_key_size_rsa: int = 2048
    minimum_key_size_ecc: int = 256
    allowed_signature_algorithms: Set[str] = field(default_factory=lambda: {
        'sha256WithRSAEncryption',
        'sha384WithRSAEncryption', 
        'sha512WithRSAEncryption',
        'ecdsa-with-SHA256',
        'ecdsa-with-SHA384',
        'ecdsa-with-SHA512'
    })
    
    # Custom validation hooks
    custom_validators: List[callable] = field(default_factory=list)


@dataclass
class ChainValidationResult:
    """Result of certificate chain validation."""
    status: ValidationStatus
    certificate_subject: str
    issuer_subject: str
    chain_length: int
    validation_time: datetime
    issues: List[ValidationIssue] = field(default_factory=list)
    warnings: List[ValidationIssue] = field(default_factory=list)
    validated_chain: List[str] = field(default_factory=list)  # Subject DNs
    trust_anchor: Optional[str] = None
    
    # DoD-specific validation results
    dod_compliance_level: Optional[str] = None
    certificate_policies: List[str] = field(default_factory=list)
    assurance_level: Optional[str] = None
    key_usage_validation: Dict[str, bool] = field(default_factory=dict)
    
    # Performance metrics
    validation_duration_ms: float = 0.0
    revocation_check_duration_ms: float = 0.0
    
    @property
    def is_valid(self) -> bool:
        """Check if validation passed without errors."""
        return self.status == ValidationStatus.VALID
    
    @property
    def has_warnings(self) -> bool:
        """Check if validation has warnings."""
        return len(self.warnings) > 0
    
    @property
    def error_count(self) -> int:
        """Get count of validation errors."""
        return len([issue for issue in self.issues if issue.level == "ERROR"])
    
    @property
    def warning_count(self) -> int:
        """Get count of validation warnings."""
        return len(self.warnings) + len([issue for issue in self.issues if issue.level == "WARNING"])


class DoDPKIValidator:
    """
    DoD PKI-compliant certificate chain validator.
    
    Implements comprehensive certificate validation according to DoD PKI standards
    with support for multiple validation levels and detailed compliance reporting.
    """
    
    # DoD Root CA certificates and their identifiers
    DOD_ROOT_CA_SUBJECTS = [
        "CN=DoD Root CA 2, OU=PKI, OU=DoD, O=U.S. Government, C=US",
        "CN=DoD Root CA 3, OU=PKI, OU=DoD, O=U.S. Government, C=US",
        "CN=DoD Root CA 4, OU=PKI, OU=DoD, O=U.S. Government, C=US",
        "CN=DoD Root CA 5, OU=PKI, OU=DoD, O=U.S. Government, C=US",
        "CN=DoD Root CA 6, OU=PKI, OU=DoD, O=U.S. Government, C=US"
    ]
    
    # DoD Certificate Policy OIDs and their assurance levels
    DOD_CERTIFICATE_POLICIES = {
        # Medium Hardware Token policies
        '2.16.840.1.101.3.2.1.3.7': {
            'name': 'DoD Medium Hardware',
            'assurance_level': 'MEDIUM',
            'hardware_required': True,
            'description': 'DoD PKI Medium Hardware Certificate Policy'
        },
        '2.16.840.1.101.3.2.1.3.13': {
            'name': 'DoD Medium Hardware PIV-Auth',
            'assurance_level': 'MEDIUM',
            'hardware_required': True,
            'description': 'DoD PKI Medium Hardware PIV Authentication Certificate Policy'
        },
        '2.16.840.1.101.3.2.1.3.15': {
            'name': 'DoD Medium CBP',
            'assurance_level': 'MEDIUM', 
            'hardware_required': True,
            'description': 'DoD PKI Medium CBP Certificate Policy'
        },
        '2.16.840.1.101.3.2.1.3.16': {
            'name': 'DoD High Hardware',
            'assurance_level': 'HIGH',
            'hardware_required': True,
            'description': 'DoD PKI High Hardware Certificate Policy'
        },
        # Medium Software policies
        '2.16.840.1.101.3.2.1.3.6': {
            'name': 'DoD Medium Software',
            'assurance_level': 'MEDIUM',
            'hardware_required': False,
            'description': 'DoD PKI Medium Software Certificate Policy'
        },
        # Basic policies
        '2.16.840.1.101.3.2.1.3.1': {
            'name': 'DoD Basic',
            'assurance_level': 'BASIC',
            'hardware_required': False,
            'description': 'DoD PKI Basic Certificate Policy'
        }
    }
    
    # Required key usage for different certificate types
    REQUIRED_KEY_USAGE_PATTERNS = {
        'authentication': {
            'required': ['digital_signature'],
            'optional': ['key_agreement', 'key_encipherment']
        },
        'signing': {
            'required': ['digital_signature'],
            'optional': ['non_repudiation']
        },
        'encryption': {
            'required': ['key_encipherment'],
            'optional': ['data_encipherment', 'key_agreement']
        }
    }
    
    def __init__(self, trusted_ca_store_path: str = None, 
                 enable_ocsp: bool = True, enable_crl: bool = True):
        """
        Initialize DoD PKI validator.
        
        Args:
            trusted_ca_store_path: Path to trusted CA certificates
            enable_ocsp: Enable OCSP validation
            enable_crl: Enable CRL validation
        """
        self.trusted_ca_store_path = trusted_ca_store_path or self._get_default_ca_store_path()
        self.enable_ocsp = enable_ocsp
        self.enable_crl = enable_crl
        
        # Build trusted CA store
        self.trusted_store = self._build_trusted_ca_store()
        
        # Validation cache
        self._validation_cache = {}
        self._cache_timeout = 300  # 5 minutes
        
        # Performance tracking
        self._validation_stats = {
            'total_validations': 0,
            'successful_validations': 0,
            'cache_hits': 0,
            'average_duration_ms': 0.0
        }
        
        logger.info("DoD PKI validator initialized")
    
    def _get_default_ca_store_path(self) -> str:
        """Get default path for trusted CA store."""
        default_paths = [
            "/etc/ssl/certs/dod",
            "/usr/local/share/ca-certificates/dod",
            os.path.expanduser("~/.cac/ca-certificates"),
            "./ca-certificates/dod"
        ]
        
        for path in default_paths:
            if os.path.exists(path):
                return path
        
        # Create default directory
        default_path = os.path.expanduser("~/.cac/ca-certificates")
        os.makedirs(default_path, exist_ok=True)
        logger.warning(f"No DoD CA store found. Created: {default_path}")
        return default_path
    
    def _build_trusted_ca_store(self) -> x509.verification.Store:
        """Build trusted CA certificate store."""
        builder = StoreBuilder()
        ca_count = 0
        
        if os.path.exists(self.trusted_ca_store_path):
            for filename in os.listdir(self.trusted_ca_store_path):
                if filename.endswith(('.pem', '.crt', '.cer', '.der')):
                    cert_path = os.path.join(self.trusted_ca_store_path, filename)
                    try:
                        with open(cert_path, 'rb') as f:
                            cert_data = f.read()
                        
                        # Try PEM format first, then DER
                        try:
                            cert = x509.load_pem_x509_certificate(cert_data)
                        except ValueError:
                            cert = x509.load_der_x509_certificate(cert_data)
                        
                        builder = builder.add_certs([cert])
                        ca_count += 1
                        logger.debug(f"Loaded CA certificate: {cert.subject.rfc4514_string()}")
                        
                    except Exception as e:
                        logger.warning(f"Failed to load CA certificate {filename}: {e}")
        
        logger.info(f"Built trusted CA store with {ca_count} certificates")
        return builder.build()
    
    def validate_certificate_chain(self, certificate: x509.Certificate,
                                 intermediate_certs: List[x509.Certificate] = None,
                                 context: ValidationContext = None) -> ChainValidationResult:
        """
        Validate complete certificate chain with DoD PKI compliance.
        
        Args:
            certificate: End-entity certificate to validate
            intermediate_certs: List of intermediate CA certificates  
            context: Validation context with options
            
        Returns:
            ChainValidationResult with detailed validation information
        """
        start_time = time.time()
        
        if context is None:
            context = ValidationContext()
        
        # Check cache first
        cert_hash = self._get_certificate_hash(certificate)
        cache_key = f"{cert_hash}_{hash(str(context))}"
        
        if cache_key in self._validation_cache:
            cached_result, cache_time = self._validation_cache[cache_key]
            if time.time() - cache_time < self._cache_timeout:
                self._validation_stats['cache_hits'] += 1
                logger.debug("Using cached validation result")
                return cached_result
        
        # Initialize result
        result = ChainValidationResult(
            status=ValidationStatus.INVALID,
            certificate_subject=certificate.subject.rfc4514_string(),
            issuer_subject=certificate.issuer.rfc4514_string(),
            chain_length=1,
            validation_time=context.validation_time or datetime.now(timezone.utc)
        )
        
        try:
            # Update stats
            self._validation_stats['total_validations'] += 1
            
            # Step 1: Basic certificate validation
            self._validate_basic_certificate(certificate, context, result)
            
            # Step 2: DoD-specific policy validation
            if not self._has_fatal_errors(result):
                self._validate_dod_policies(certificate, context, result)
            
            # Step 3: Certificate chain path validation
            if not self._has_fatal_errors(result):
                self._validate_certificate_path(certificate, intermediate_certs, context, result)
            
            # Step 4: Key usage and constraints validation
            if not self._has_fatal_errors(result):
                self._validate_key_usage_and_constraints(certificate, context, result)
            
            # Step 5: Extensions validation
            if not self._has_fatal_errors(result):
                self._validate_required_extensions(certificate, context, result)
            
            # Step 6: Custom validators
            if not self._has_fatal_errors(result) and context.custom_validators:
                self._run_custom_validators(certificate, context, result)
            
            # Step 7: Revocation checking (if enabled and no fatal errors)
            if (not self._has_fatal_errors(result) and 
                context.check_revocation and 
                (context.check_crl or context.check_ocsp)):
                revocation_start = time.time()
                self._check_revocation_status(certificate, intermediate_certs, context, result)
                result.revocation_check_duration_ms = (time.time() - revocation_start) * 1000
            
            # Determine final status
            if not self._has_fatal_errors(result):
                result.status = ValidationStatus.VALID
                self._validation_stats['successful_validations'] += 1
                logger.info(f"Certificate validation successful: {result.certificate_subject}")
            else:
                result.status = ValidationStatus.INVALID
                logger.warning(f"Certificate validation failed: {result.certificate_subject}")
            
        except Exception as e:
            error_issue = ValidationIssue(
                level="ERROR",
                category="SYSTEM",
                code="VALIDATION_EXCEPTION",
                message=f"Validation error: {str(e)}",
                details={'exception_type': type(e).__name__}
            )
            result.issues.append(error_issue)
            result.status = ValidationStatus.INVALID
            logger.error(f"Certificate validation exception: {e}")
        
        # Calculate performance metrics
        validation_duration = (time.time() - start_time) * 1000
        result.validation_duration_ms = validation_duration
        
        # Update average duration
        total_validations = self._validation_stats['total_validations']
        current_avg = self._validation_stats['average_duration_ms']
        self._validation_stats['average_duration_ms'] = (
            (current_avg * (total_validations - 1) + validation_duration) / total_validations
        )
        
        # Cache result
        self._validation_cache[cache_key] = (result, time.time())
        
        return result
    
    def _validate_basic_certificate(self, certificate: x509.Certificate,
                                   context: ValidationContext,
                                   result: ChainValidationResult):
        """Validate basic certificate properties."""
        validation_time = context.validation_time or datetime.now(timezone.utc)
        
        # Check validity period
        not_before = certificate.not_valid_before
        not_after = certificate.not_valid_after
        
        # Apply clock skew tolerance
        effective_not_before = not_before - context.clock_skew_tolerance
        effective_not_after = not_after + context.clock_skew_tolerance
        
        if validation_time < effective_not_before:
            result.issues.append(ValidationIssue(
                level="ERROR",
                category="VALIDITY",
                code="NOT_YET_VALID",
                message=f"Certificate is not yet valid (valid from {not_before})",
                details={
                    'not_before': not_before.isoformat(),
                    'validation_time': validation_time.isoformat(),
                    'clock_skew_applied': context.clock_skew_tolerance.total_seconds()
                }
            ))
        
        if validation_time > effective_not_after:
            result.issues.append(ValidationIssue(
                level="ERROR",
                category="VALIDITY", 
                code="EXPIRED",
                message=f"Certificate has expired (expired {not_after})",
                details={
                    'not_after': not_after.isoformat(),
                    'validation_time': validation_time.isoformat(),
                    'clock_skew_applied': context.clock_skew_tolerance.total_seconds()
                }
            ))
        
        # Check for expiration warnings (30 days)
        expiry_warning_threshold = validation_time + timedelta(days=30)
        if not_after < expiry_warning_threshold:
            days_until_expiry = (not_after - validation_time).days
            result.warnings.append(ValidationIssue(
                level="WARNING",
                category="VALIDITY",
                code="EXPIRING_SOON",
                message=f"Certificate expires in {days_until_expiry} days",
                details={
                    'days_until_expiry': days_until_expiry,
                    'expiry_date': not_after.isoformat()
                }
            ))
        
        # Validate signature algorithm
        sig_algo_oid = certificate.signature_algorithm_oid.dotted_string
        sig_algo_name = certificate.signature_algorithm_oid._name
        
        if context.validation_level in [ValidationLevel.STRICT, ValidationLevel.MAXIMUM]:
            if sig_algo_name not in context.allowed_signature_algorithms:
                result.issues.append(ValidationIssue(
                    level="ERROR",
                    category="ALGORITHM",
                    code="WEAK_SIGNATURE_ALGORITHM",
                    message=f"Signature algorithm not allowed: {sig_algo_name}",
                    details={
                        'algorithm': sig_algo_name,
                        'oid': sig_algo_oid,
                        'allowed_algorithms': list(context.allowed_signature_algorithms)
                    }
                ))
        
        # Validate public key
        public_key = certificate.public_key()
        
        if isinstance(public_key, rsa.RSAPublicKey):
            key_size = public_key.key_size
            if key_size < context.minimum_key_size_rsa:
                result.issues.append(ValidationIssue(
                    level="ERROR",
                    category="KEY",
                    code="WEAK_RSA_KEY",
                    message=f"RSA key size too small: {key_size} bits (minimum: {context.minimum_key_size_rsa})",
                    details={
                        'key_size': key_size,
                        'minimum_required': context.minimum_key_size_rsa,
                        'key_type': 'RSA'
                    }
                ))
                
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            key_size = public_key.curve.key_size
            if key_size < context.minimum_key_size_ecc:
                result.issues.append(ValidationIssue(
                    level="ERROR",
                    category="KEY",
                    code="WEAK_ECC_KEY",
                    message=f"ECC key size too small: {key_size} bits (minimum: {context.minimum_key_size_ecc})",
                    details={
                        'key_size': key_size,
                        'minimum_required': context.minimum_key_size_ecc,
                        'key_type': 'ECC',
                        'curve_name': public_key.curve.name
                    }
                ))
                
        elif isinstance(public_key, dsa.DSAPublicKey):
            # DSA is generally not recommended for new certificates
            if context.validation_level in [ValidationLevel.STRICT, ValidationLevel.MAXIMUM]:
                result.warnings.append(ValidationIssue(
                    level="WARNING",
                    category="KEY",
                    code="DSA_KEY_DEPRECATED",
                    message="DSA keys are deprecated and not recommended",
                    details={'key_type': 'DSA'}
                ))
        else:
            result.warnings.append(ValidationIssue(
                level="WARNING",
                category="KEY",
                code="UNKNOWN_KEY_TYPE",
                message=f"Unknown or unsupported key type: {type(public_key).__name__}",
                details={'key_type': type(public_key).__name__}
            ))
    
    def _validate_dod_policies(self, certificate: x509.Certificate,
                             context: ValidationContext,
                             result: ChainValidationResult):
        """Validate DoD-specific certificate policies."""
        try:
            policies_ext = certificate.extensions.get_extension_for_oid(
                ExtensionOID.CERTIFICATE_POLICIES
            )
            
            policy_oids = []
            dod_policies_found = []
            
            for policy in policies_ext.value:
                policy_oid = policy.policy_identifier.dotted_string
                policy_oids.append(policy_oid)
                
                # Check if it's a DoD policy
                if policy_oid in self.DOD_CERTIFICATE_POLICIES:
                    dod_policy_info = self.DOD_CERTIFICATE_POLICIES[policy_oid]
                    dod_policies_found.append(dod_policy_info)
                    
                    # Set assurance level from highest DoD policy found
                    if not result.assurance_level or dod_policy_info['assurance_level'] == 'HIGH':
                        result.assurance_level = dod_policy_info['assurance_level']
            
            result.certificate_policies = policy_oids
            
            # Check DoD policy requirements
            if context.require_dod_policies:
                if not dod_policies_found:
                    if context.policy_enforcement == PolicyEnforcement.STRICT:
                        result.issues.append(ValidationIssue(
                            level="ERROR",
                            category="POLICY",
                            code="NO_DOD_POLICIES",
                            message="No DoD certificate policies found",
                            details={'found_policies': policy_oids}
                        ))
                    else:
                        result.warnings.append(ValidationIssue(
                            level="WARNING",
                            category="POLICY",
                            code="NO_DOD_POLICIES",
                            message="No DoD certificate policies found",
                            details={'found_policies': policy_oids}
                        ))
                else:
                    # Check hardware protection requirement
                    if context.require_hardware_protection:
                        hardware_protected = any(
                            policy['hardware_required'] for policy in dod_policies_found
                        )
                        if not hardware_protected:
                            if context.policy_enforcement == PolicyEnforcement.STRICT:
                                result.issues.append(ValidationIssue(
                                    level="ERROR",
                                    category="POLICY",
                                    code="NO_HARDWARE_PROTECTION",
                                    message="Certificate not issued with hardware protection",
                                    details={
                                        'dod_policies': [p['name'] for p in dod_policies_found],
                                        'hardware_requirement': True
                                    }
                                ))
                            else:
                                result.warnings.append(ValidationIssue(
                                    level="WARNING", 
                                    category="POLICY",
                                    code="NO_HARDWARE_PROTECTION",
                                    message="Certificate not issued with hardware protection",
                                    details={
                                        'dod_policies': [p['name'] for p in dod_policies_found],
                                        'hardware_requirement': True
                                    }
                                ))
            
            # Check issuer for DoD PKI
            issuer_dn = certificate.issuer.rfc4514_string()
            is_dod_issuer = any("DoD" in root_ca for root_ca in self.DOD_ROOT_CA_SUBJECTS
                               if self._issuer_matches_root(issuer_dn, root_ca))
            
            if context.require_dod_policies and not is_dod_issuer:
                result.warnings.append(ValidationIssue(
                    level="WARNING",
                    category="POLICY",
                    code="NON_DOD_ISSUER",
                    message="Certificate not issued by recognized DoD CA",
                    details={'issuer': issuer_dn}
                ))
            
            # Set DoD compliance level
            if dod_policies_found:
                if any(p['assurance_level'] == 'HIGH' for p in dod_policies_found):
                    result.dod_compliance_level = "HIGH"
                elif any(p['assurance_level'] == 'MEDIUM' for p in dod_policies_found):
                    result.dod_compliance_level = "MEDIUM"
                else:
                    result.dod_compliance_level = "BASIC"
            
        except x509.ExtensionNotFound:
            if context.require_dod_policies:
                if context.policy_enforcement == PolicyEnforcement.STRICT:
                    result.issues.append(ValidationIssue(
                        level="ERROR",
                        category="POLICY",
                        code="NO_CERTIFICATE_POLICIES",
                        message="Certificate policies extension not found",
                        details={'extension_required': True}
                    ))
                else:
                    result.warnings.append(ValidationIssue(
                        level="WARNING",
                        category="POLICY", 
                        code="NO_CERTIFICATE_POLICIES",
                        message="Certificate policies extension not found",
                        details={'extension_required': True}
                    ))
    
    def _validate_certificate_path(self, certificate: x509.Certificate,
                                 intermediate_certs: List[x509.Certificate],
                                 context: ValidationContext,
                                 result: ChainValidationResult):
        """Validate certificate path to trusted root."""
        try:
            # Build verification chain
            builder = PolicyBuilder().store(self.trusted_store)
            
            if intermediate_certs:
                builder = builder.add_certs(intermediate_certs)
                result.chain_length = len(intermediate_certs) + 1
            
            # Check maximum chain length
            if result.chain_length > context.max_chain_length:
                result.issues.append(ValidationIssue(
                    level="ERROR",
                    category="CHAIN",
                    code="CHAIN_TOO_LONG",
                    message=f"Certificate chain too long: {result.chain_length} (max: {context.max_chain_length})",
                    details={
                        'chain_length': result.chain_length,
                        'max_allowed': context.max_chain_length
                    }
                ))
                return
            
            # Set validation time if specified
            if context.validation_time:
                builder = builder.verification_time(context.validation_time)
            
            # Build the verifier
            verifier = builder.build()
            
            # Perform path validation
            try:
                chain = verifier.verify(certificate, intermediate_certs or [])
                
                # Extract subject DNs from validated chain
                validated_subjects = []
                for cert in chain:
                    validated_subjects.append(cert.subject.rfc4514_string())
                
                result.validated_chain = validated_subjects
                result.chain_length = len(chain)
                
                # Identify trust anchor (root CA)
                if chain:
                    root_cert = chain[-1]
                    result.trust_anchor = root_cert.subject.rfc4514_string()
                    
                    # Check if it's a recognized DoD root
                    if not any(self._issuer_matches_root(result.trust_anchor, root_ca) 
                             for root_ca in self.DOD_ROOT_CA_SUBJECTS):
                        if context.require_dod_policies:
                            result.warnings.append(ValidationIssue(
                                level="WARNING",
                                category="CHAIN",
                                code="NON_DOD_ROOT",
                                message="Certificate not rooted in DoD PKI",
                                details={'trust_anchor': result.trust_anchor}
                            ))
                
                logger.debug(f"Path validation successful, chain length: {result.chain_length}")
                
            except Exception as path_error:
                # Analyze path validation error
                error_msg = str(path_error).lower()
                
                if "unable to get local issuer certificate" in error_msg:
                    result.issues.append(ValidationIssue(
                        level="ERROR",
                        category="CHAIN",
                        code="MISSING_ISSUER",
                        message="Unable to find issuer certificate in trusted store",
                        details={'error': str(path_error)}
                    ))
                elif "certificate has expired" in error_msg:
                    result.issues.append(ValidationIssue(
                        level="ERROR",
                        category="CHAIN",
                        code="EXPIRED_IN_CHAIN",
                        message="Certificate in chain has expired",
                        details={'error': str(path_error)}
                    ))
                elif "certificate is not yet valid" in error_msg:
                    result.issues.append(ValidationIssue(
                        level="ERROR",
                        category="CHAIN",
                        code="NOT_YET_VALID_IN_CHAIN",
                        message="Certificate in chain is not yet valid",
                        details={'error': str(path_error)}
                    ))
                elif "unable to verify the first certificate" in error_msg:
                    result.issues.append(ValidationIssue(
                        level="ERROR",
                        category="CHAIN",
                        code="VERIFICATION_FAILED",
                        message="Unable to verify certificate against trusted roots",
                        details={'error': str(path_error)}
                    ))
                else:
                    result.issues.append(ValidationIssue(
                        level="ERROR",
                        category="CHAIN",
                        code="PATH_VALIDATION_FAILED",
                        message=f"Path validation failed: {str(path_error)}",
                        details={'error': str(path_error)}
                    ))
                
        except Exception as e:
            result.issues.append(ValidationIssue(
                level="ERROR",
                category="CHAIN",
                code="PATH_VALIDATION_ERROR",
                message=f"Path validation error: {str(e)}",
                details={'error': str(e)}
            ))
    
    def _validate_key_usage_and_constraints(self, certificate: x509.Certificate,
                                          context: ValidationContext,
                                          result: ChainValidationResult):
        """Validate key usage and basic constraints."""
        key_usage_validation = {}
        
        # Check key usage extension
        try:
            key_usage_ext = certificate.extensions.get_extension_for_oid(
                ExtensionOID.KEY_USAGE
            )
            key_usage = key_usage_ext.value
            
            usage_flags = []
            if key_usage.digital_signature:
                usage_flags.append('digital_signature')
            if key_usage.non_repudiation:
                usage_flags.append('non_repudiation')
            if key_usage.key_encipherment:
                usage_flags.append('key_encipherment')
            if key_usage.data_encipherment:
                usage_flags.append('data_encipherment')
            if key_usage.key_agreement:
                usage_flags.append('key_agreement')
            if key_usage.key_cert_sign:
                usage_flags.append('key_cert_sign')
            if key_usage.crl_sign:
                usage_flags.append('crl_sign')
            
            key_usage_validation['key_usage'] = usage_flags
            
            # For end-entity certificates, check that key_cert_sign is not set
            if key_usage.key_cert_sign:
                try:
                    basic_constraints_ext = certificate.extensions.get_extension_for_oid(
                        ExtensionOID.BASIC_CONSTRAINTS
                    )
                    if not basic_constraints_ext.value.ca:
                        result.issues.append(ValidationIssue(
                            level="ERROR",
                            category="KEY_USAGE",
                            code="INVALID_KEY_CERT_SIGN",
                            message="key_cert_sign set for non-CA certificate",
                            details={'key_usage': usage_flags}
                        ))
                except x509.ExtensionNotFound:
                    result.issues.append(ValidationIssue(
                        level="ERROR",
                        category="KEY_USAGE",
                        code="INVALID_KEY_CERT_SIGN_NO_BC",
                        message="key_cert_sign set without basic constraints",
                        details={'key_usage': usage_flags}
                    ))
            
        except x509.ExtensionNotFound:
            if context.validation_level in [ValidationLevel.STRICT, ValidationLevel.MAXIMUM]:
                result.issues.append(ValidationIssue(
                    level="ERROR",
                    category="KEY_USAGE",
                    code="MISSING_KEY_USAGE",
                    message="Key usage extension not found",
                    details={'extension_required': True}
                ))
            else:
                result.warnings.append(ValidationIssue(
                    level="WARNING",
                    category="KEY_USAGE",
                    code="MISSING_KEY_USAGE",
                    message="Key usage extension not found",
                    details={'extension_required': False}
                ))
        
        # Check extended key usage
        try:
            ext_key_usage_ext = certificate.extensions.get_extension_for_oid(
                ExtensionOID.EXTENDED_KEY_USAGE
            )
            
            ext_usage_oids = [usage.dotted_string for usage in ext_key_usage_ext.value]
            key_usage_validation['extended_key_usage'] = ext_usage_oids
            
            # Check for client authentication usage (required for CAC authentication)
            client_auth_oid = x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH.dotted_string
            if client_auth_oid not in ext_usage_oids:
                result.warnings.append(ValidationIssue(
                    level="WARNING",
                    category="KEY_USAGE",
                    code="NO_CLIENT_AUTH",
                    message="Client authentication usage not found",
                    details={'extended_key_usage': ext_usage_oids}
                ))
            
        except x509.ExtensionNotFound:
            if context.validation_level == ValidationLevel.MAXIMUM:
                result.warnings.append(ValidationIssue(
                    level="WARNING",
                    category="KEY_USAGE",
                    code="MISSING_EXTENDED_KEY_USAGE",
                    message="Extended key usage extension not found",
                    details={'extension_required': False}
                ))
        
        # Check basic constraints for CA certificates
        try:
            basic_constraints_ext = certificate.extensions.get_extension_for_oid(
                ExtensionOID.BASIC_CONSTRAINTS
            )
            basic_constraints = basic_constraints_ext.value
            
            key_usage_validation['is_ca'] = basic_constraints.ca
            key_usage_validation['path_length'] = basic_constraints.path_length
            
            # If it's a CA, ensure key_cert_sign is present
            if basic_constraints.ca:
                try:
                    key_usage_ext = certificate.extensions.get_extension_for_oid(
                        ExtensionOID.KEY_USAGE
                    )
                    if not key_usage_ext.value.key_cert_sign:
                        result.issues.append(ValidationIssue(
                            level="ERROR",
                            category="KEY_USAGE",
                            code="CA_MISSING_KEY_CERT_SIGN",
                            message="CA certificate missing key_cert_sign usage",
                            details={'is_ca': True}
                        ))
                except x509.ExtensionNotFound:
                    result.issues.append(ValidationIssue(
                        level="ERROR",
                        category="KEY_USAGE",
                        code="CA_MISSING_KEY_USAGE",
                        message="CA certificate missing key usage extension",
                        details={'is_ca': True}
                    ))
            
        except x509.ExtensionNotFound:
            # Basic constraints missing - assume it's an end-entity certificate
            key_usage_validation['is_ca'] = False
        
        result.key_usage_validation = key_usage_validation
    
    def _validate_required_extensions(self, certificate: x509.Certificate,
                                    context: ValidationContext,
                                    result: ChainValidationResult):
        """Validate required certificate extensions."""
        required_extensions = {
            'subject_key_identifier': ExtensionOID.SUBJECT_KEY_IDENTIFIER,
            'authority_key_identifier': ExtensionOID.AUTHORITY_KEY_IDENTIFIER,
        }
        
        if context.validation_level in [ValidationLevel.STRICT, ValidationLevel.MAXIMUM]:
            required_extensions.update({
                'subject_alternative_name': ExtensionOID.SUBJECT_ALTERNATIVE_NAME,
                'crl_distribution_points': ExtensionOID.CRL_DISTRIBUTION_POINTS,
                'authority_information_access': ExtensionOID.AUTHORITY_INFORMATION_ACCESS
            })
        
        for ext_name, ext_oid in required_extensions.items():
            try:
                certificate.extensions.get_extension_for_oid(ext_oid)
            except x509.ExtensionNotFound:
                if context.validation_level == ValidationLevel.MAXIMUM:
                    result.issues.append(ValidationIssue(
                        level="ERROR",
                        category="EXTENSIONS",
                        code=f"MISSING_{ext_name.upper()}",
                        message=f"{ext_name.replace('_', ' ').title()} extension not found",
                        details={'extension_oid': ext_oid.dotted_string}
                    ))
                else:
                    result.warnings.append(ValidationIssue(
                        level="WARNING",
                        category="EXTENSIONS",
                        code=f"MISSING_{ext_name.upper()}",
                        message=f"{ext_name.replace('_', ' ').title()} extension not found",
                        details={'extension_oid': ext_oid.dotted_string}
                    ))
    
    def _run_custom_validators(self, certificate: x509.Certificate,
                             context: ValidationContext,
                             result: ChainValidationResult):
        """Run custom validation functions."""
        for validator_func in context.custom_validators:
            try:
                validator_func(certificate, context, result)
            except Exception as e:
                result.warnings.append(ValidationIssue(
                    level="WARNING",
                    category="CUSTOM",
                    code="CUSTOM_VALIDATOR_ERROR",
                    message=f"Custom validator error: {str(e)}",
                    details={'validator': validator_func.__name__}
                ))
    
    def _check_revocation_status(self, certificate: x509.Certificate,
                               intermediate_certs: List[x509.Certificate],
                               context: ValidationContext,
                               result: ChainValidationResult):
        """Check certificate revocation status via CRL and/or OCSP."""
        # This would integrate with the existing CRL and OCSP checking modules
        # For now, we'll add a placeholder that indicates revocation checking was attempted
        result.warnings.append(ValidationIssue(
            level="INFO",
            category="REVOCATION",
            code="REVOCATION_CHECK_SKIPPED",
            message="Revocation checking not yet implemented in this validator",
            details={
                'crl_enabled': context.check_crl,
                'ocsp_enabled': context.check_ocsp
            }
        ))
    
    def _has_fatal_errors(self, result: ChainValidationResult) -> bool:
        """Check if validation result has fatal errors."""
        return any(issue.level == "ERROR" for issue in result.issues)
    
    def _issuer_matches_root(self, issuer_dn: str, root_ca_dn: str) -> bool:
        """Check if issuer DN matches or is subordinate to root CA DN."""
        # This could be enhanced with more sophisticated DN matching
        return root_ca_dn in issuer_dn or issuer_dn == root_ca_dn
    
    def _get_certificate_hash(self, certificate: x509.Certificate) -> str:
        """Generate hash for certificate caching."""
        cert_der = certificate.public_bytes(serialization.Encoding.DER)
        return hashlib.sha256(cert_der).hexdigest()
    
    def clear_validation_cache(self):
        """Clear the validation cache."""
        self._validation_cache.clear()
        logger.info("Validation cache cleared")
    
    def get_validation_stats(self) -> Dict[str, Any]:
        """Get validation statistics."""
        return dict(self._validation_stats)
    
    def get_supported_policies(self) -> Dict[str, Dict[str, Any]]:
        """Get information about supported DoD certificate policies."""
        return dict(self.DOD_CERTIFICATE_POLICIES)


# Example usage
def main():
    """Example usage of DoD PKI validator."""
    # This would typically be used with actual certificate data
    validator = DoDPKIValidator()
    
    # Example validation context
    context = ValidationContext(
        validation_level=ValidationLevel.STRICT,
        policy_enforcement=PolicyEnforcement.STANDARD,
        require_dod_policies=True,
        require_hardware_protection=True
    )
    
    print("DoD PKI Validator initialized")
    print(f"Supported policies: {len(validator.get_supported_policies())}")
    print(f"Validation stats: {validator.get_validation_stats()}")


if __name__ == "__main__":
    main()