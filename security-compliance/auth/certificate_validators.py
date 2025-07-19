#!/usr/bin/env python3
"""
Enhanced Certificate Validation Module for CAC/PIV Integration
Implements DoD-compliant certificate chain validation, CRL checking, and OCSP validation
"""

import os
import logging
import hashlib
import time
from typing import Optional, Dict, List, Tuple, Union
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from urllib.parse import urlparse
import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.x509.verification import PolicyBuilder, StoreBuilder
from cryptography.x509.oid import ExtensionOID, SignatureAlgorithmOID
import concurrent.futures
from cryptography.x509 import ocsp

# Configure logging
logger = logging.getLogger(__name__)

@dataclass
class ValidationResult:
    """Result of certificate validation"""
    is_valid: bool
    error_message: Optional[str] = None
    warning_messages: List[str] = None
    validation_details: Dict = None
    
    def __post_init__(self):
        if self.warning_messages is None:
            self.warning_messages = []
        if self.validation_details is None:
            self.validation_details = {}

@dataclass
class RevocationStatus:
    """Certificate revocation status"""
    is_revoked: bool
    check_time: datetime
    method: str  # 'CRL' or 'OCSP'
    reason: Optional[str] = None
    revocation_time: Optional[datetime] = None
    next_update: Optional[datetime] = None

class DoDBCertificateValidator:
    """
    Enhanced DoD-compliant certificate validator
    Implements comprehensive certificate chain validation against DoD PKI hierarchy
    """
    
    # DoD Root CA certificates (these would typically be loaded from files)
    DOD_ROOT_CA_SUBJECTS = [
        "CN=DoD Root CA 2, OU=PKI, OU=DoD, O=U.S. Government, C=US",
        "CN=DoD Root CA 3, OU=PKI, OU=DoD, O=U.S. Government, C=US", 
        "CN=DoD Root CA 4, OU=PKI, OU=DoD, O=U.S. Government, C=US",
        "CN=DoD Root CA 5, OU=PKI, OU=DoD, O=U.S. Government, C=US",
        "CN=DoD Root CA 6, OU=PKI, OU=DoD, O=U.S. Government, C=US"
    ]
    
    # DoD Certificate Policy OIDs
    DOD_POLICY_OIDS = {
        'DOD_MEDIUM_HARDWARE': '2.16.840.1.101.3.2.1.3.7',
        'DOD_MEDIUM_HARDWARE_PIV_AUTH': '2.16.840.1.101.3.2.1.3.13',
        'DOD_MEDIUM_CBP': '2.16.840.1.101.3.2.1.3.15',
        'DOD_HIGH_HARDWARE': '2.16.840.1.101.3.2.1.3.16',
        'DOD_MEDIUM_SOFTWARE': '2.16.840.1.101.3.2.1.3.6',
        'DOD_BASIC': '2.16.840.1.101.3.2.1.3.1'
    }
    
    # Required key usage for CAC certificates
    REQUIRED_KEY_USAGE = {
        'authentication': ['digital_signature', 'key_agreement'],
        'signing': ['digital_signature', 'non_repudiation'],
        'encryption': ['key_encipherment', 'data_encipherment']
    }
    
    def __init__(self, dod_ca_cert_path: str = None, enable_ocsp: bool = True, enable_crl: bool = True):
        """
        Initialize DoD certificate validator
        
        Args:
            dod_ca_cert_path: Path to DoD CA certificates directory
            enable_ocsp: Enable OCSP validation
            enable_crl: Enable CRL validation
        """
        self.dod_ca_cert_path = dod_ca_cert_path or self._get_default_ca_path()
        self.enable_ocsp = enable_ocsp
        self.enable_crl = enable_crl
        self.trusted_ca_store = self._build_trusted_ca_store()
        self._validation_cache = {}
        self._cache_timeout = 300  # 5 minutes
        
        logger.info(f"DoD Certificate Validator initialized with CA path: {self.dod_ca_cert_path}")
    
    def _get_default_ca_path(self) -> str:
        """Get default DoD CA certificate path"""
        default_paths = [
            "/etc/ssl/certs/dod",
            "/usr/local/share/ca-certificates/dod",
            os.path.expanduser("~/.cac/ca-certificates"),
            "./ca-certificates"
        ]
        
        for path in default_paths:
            if os.path.exists(path):
                return path
        
        # Create default directory if none exists
        default_path = os.path.expanduser("~/.cac/ca-certificates")
        os.makedirs(default_path, exist_ok=True)
        logger.warning(f"No DoD CA certificates found. Created directory: {default_path}")
        return default_path
    
    def _build_trusted_ca_store(self) -> x509.verification.Store:
        """Build trusted CA certificate store"""
        builder = StoreBuilder()
        
        # Load DoD CA certificates from directory
        if os.path.exists(self.dod_ca_cert_path):
            for filename in os.listdir(self.dod_ca_cert_path):
                if filename.endswith(('.pem', '.crt', '.cer')):
                    cert_path = os.path.join(self.dod_ca_cert_path, filename)
                    try:
                        with open(cert_path, 'rb') as f:
                            cert_data = f.read()
                            
                        # Try PEM format first, then DER
                        try:
                            cert = x509.load_pem_x509_certificate(cert_data)
                        except ValueError:
                            cert = x509.load_der_x509_certificate(cert_data)
                        
                        builder = builder.add_certs([cert])
                        logger.debug(f"Loaded CA certificate: {cert.subject}")
                        
                    except Exception as e:
                        logger.warning(f"Failed to load CA certificate {filename}: {e}")
        
        return builder.build()
    
    def validate_certificate_chain(self, certificate: x509.Certificate, 
                                 intermediate_certs: List[x509.Certificate] = None) -> ValidationResult:
        """
        Validate complete certificate chain against DoD PKI
        
        Args:
            certificate: End-entity certificate to validate
            intermediate_certs: List of intermediate CA certificates
            
        Returns:
            ValidationResult with validation outcome
        """
        # Check cache first
        cert_hash = self._get_certificate_hash(certificate)
        if cert_hash in self._validation_cache:
            cached_result, cache_time = self._validation_cache[cert_hash]
            if time.time() - cache_time < self._cache_timeout:
                logger.debug("Using cached validation result")
                return cached_result
        
        result = ValidationResult(is_valid=False)
        
        try:
            # Step 1: Basic certificate validation
            basic_validation = self._validate_basic_certificate(certificate)
            if not basic_validation.is_valid:
                result.error_message = f"Basic validation failed: {basic_validation.error_message}"
                return result
            
            result.warning_messages.extend(basic_validation.warning_messages)
            
            # Step 2: DoD-specific policy validation
            policy_validation = self._validate_dod_policies(certificate)
            if not policy_validation.is_valid:
                result.error_message = f"DoD policy validation failed: {policy_validation.error_message}"
                return result
            
            result.warning_messages.extend(policy_validation.warning_messages)
            
            # Step 3: Certificate path validation
            path_validation = self._validate_certificate_path(certificate, intermediate_certs)
            if not path_validation.is_valid:
                result.error_message = f"Path validation failed: {path_validation.error_message}"
                return result
            
            result.warning_messages.extend(path_validation.warning_messages)
            
            # Step 4: Key usage validation
            key_usage_validation = self._validate_key_usage(certificate)
            if not key_usage_validation.is_valid:
                result.error_message = f"Key usage validation failed: {key_usage_validation.error_message}"
                return result
            
            result.warning_messages.extend(key_usage_validation.warning_messages)
            
            # Step 5: Extensions validation
            extensions_validation = self._validate_required_extensions(certificate)
            if not extensions_validation.is_valid:
                result.warning_messages.append(f"Extensions validation warning: {extensions_validation.error_message}")
            
            # Combine validation details
            result.validation_details = {
                'basic_validation': basic_validation.validation_details,
                'policy_validation': policy_validation.validation_details,
                'path_validation': path_validation.validation_details,
                'key_usage_validation': key_usage_validation.validation_details,
                'extensions_validation': extensions_validation.validation_details
            }
            
            result.is_valid = True
            logger.info(f"Certificate validation successful for: {certificate.subject}")
            
        except Exception as e:
            result.error_message = f"Validation error: {str(e)}"
            logger.error(f"Certificate validation failed: {e}")
        
        # Cache the result
        self._validation_cache[cert_hash] = (result, time.time())
        
        return result
    
    def _validate_basic_certificate(self, certificate: x509.Certificate) -> ValidationResult:
        """Validate basic certificate properties"""
        result = ValidationResult(is_valid=False)
        details = {}
        
        try:
            current_time = datetime.now(timezone.utc)
            
            # Check validity period
            if certificate.not_valid_before > current_time:
                result.error_message = "Certificate is not yet valid"
                return result
            
            if certificate.not_valid_after < current_time:
                result.error_message = "Certificate has expired"
                return result
            
            # Check if expiring soon (30 days)
            expiry_warning_threshold = current_time + timedelta(days=30)
            if certificate.not_valid_after < expiry_warning_threshold:
                days_until_expiry = (certificate.not_valid_after - current_time).days
                result.warning_messages.append(f"Certificate expires in {days_until_expiry} days")
            
            # Validate signature algorithm
            sig_algo = certificate.signature_algorithm_oid
            if sig_algo not in [SignatureAlgorithmOID.RSA_WITH_SHA256, 
                              SignatureAlgorithmOID.RSA_WITH_SHA384,
                              SignatureAlgorithmOID.ECDSA_WITH_SHA256,
                              SignatureAlgorithmOID.ECDSA_WITH_SHA384]:
                result.warning_messages.append(f"Non-standard signature algorithm: {sig_algo}")
            
            # Validate public key
            public_key = certificate.public_key()
            if isinstance(public_key, rsa.RSAPublicKey):
                key_size = public_key.key_size
                if key_size < 2048:
                    result.error_message = f"RSA key size too small: {key_size} bits"
                    return result
                details['key_type'] = 'RSA'
                details['key_size'] = key_size
            elif isinstance(public_key, ec.EllipticCurvePublicKey):
                curve_name = public_key.curve.name
                details['key_type'] = 'ECC'
                details['curve'] = curve_name
            else:
                result.warning_messages.append(f"Unsupported key type: {type(public_key)}")
            
            details['serial_number'] = str(certificate.serial_number)
            details['issuer'] = certificate.issuer.rfc4514_string()
            details['subject'] = certificate.subject.rfc4514_string()
            details['not_before'] = certificate.not_valid_before.isoformat()
            details['not_after'] = certificate.not_valid_after.isoformat()
            
            result.validation_details = details
            result.is_valid = True
            
        except Exception as e:
            result.error_message = f"Basic validation error: {str(e)}"
        
        return result
    
    def _validate_dod_policies(self, certificate: x509.Certificate) -> ValidationResult:
        """Validate DoD-specific certificate policies"""
        result = ValidationResult(is_valid=False)
        details = {}
        
        try:
            # Check for certificate policies extension
            try:
                policies_ext = certificate.extensions.get_extension_for_oid(ExtensionOID.CERTIFICATE_POLICIES)
                policy_oids = []
                
                for policy in policies_ext.value:
                    policy_oid = policy.policy_identifier.dotted_string
                    policy_oids.append(policy_oid)
                
                details['certificate_policies'] = policy_oids
                
                # Check for DoD policies
                dod_policies_found = []
                for oid in policy_oids:
                    for policy_name, policy_oid in self.DOD_POLICY_OIDS.items():
                        if oid.startswith(policy_oid):
                            dod_policies_found.append(policy_name)
                
                if not dod_policies_found:
                    result.error_message = "No DoD certificate policies found"
                    return result
                
                details['dod_policies'] = dod_policies_found
                logger.debug(f"Found DoD policies: {dod_policies_found}")
                
            except x509.ExtensionNotFound:
                result.error_message = "Certificate policies extension not found"
                return result
            
            # Validate issuer is DoD CA
            issuer_dn = certificate.issuer.rfc4514_string()
            is_dod_issuer = any("DoD" in issuer_dn for root_ca in self.DOD_ROOT_CA_SUBJECTS 
                              if "DoD" in root_ca)
            
            if not is_dod_issuer and "DoD" not in issuer_dn:
                result.warning_messages.append("Certificate not issued by recognized DoD CA")
            
            details['is_dod_issuer'] = is_dod_issuer
            
            result.validation_details = details
            result.is_valid = True
            
        except Exception as e:
            result.error_message = f"DoD policy validation error: {str(e)}"
        
        return result
    
    def _validate_certificate_path(self, certificate: x509.Certificate,
                                 intermediate_certs: List[x509.Certificate] = None) -> ValidationResult:
        """Validate certificate path to trusted root"""
        result = ValidationResult(is_valid=False)
        details = {}
        
        try:
            # Build verification chain
            builder = PolicyBuilder().store(self.trusted_ca_store)
            
            if intermediate_certs:
                builder = builder.add_certs(intermediate_certs)
            
            # Build the verifier
            verifier = builder.build()
            
            # Perform path validation
            try:
                # Note: This is a simplified validation - in practice, you'd want more sophisticated path building
                chain = verifier.verify(certificate, intermediate_certs or [])
                details['chain_length'] = len(chain)
                details['validated_chain'] = [cert.subject.rfc4514_string() for cert in chain]
                result.is_valid = True
                
            except Exception as path_error:
                # Try to provide more specific error information
                if "unable to get local issuer certificate" in str(path_error):
                    result.error_message = "Unable to find issuer certificate in trusted store"
                elif "certificate has expired" in str(path_error):
                    result.error_message = "Certificate in chain has expired"
                elif "certificate is not yet valid" in str(path_error):
                    result.error_message = "Certificate in chain is not yet valid"
                else:
                    result.error_message = f"Path validation failed: {str(path_error)}"
                
                logger.debug(f"Path validation failed: {path_error}")
                return result
            
            result.validation_details = details
            
        except Exception as e:
            result.error_message = f"Path validation error: {str(e)}"
        
        return result
    
    def _validate_key_usage(self, certificate: x509.Certificate) -> ValidationResult:
        """Validate key usage extensions"""
        result = ValidationResult(is_valid=False)
        details = {}
        
        try:
            # Check key usage extension
            try:
                key_usage_ext = certificate.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE)
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
                
                details['key_usage'] = usage_flags
                
                # For CAC certificates, we expect digital signature at minimum
                if not key_usage.digital_signature:
                    result.warning_messages.append("Digital signature usage not enabled")
                
            except x509.ExtensionNotFound:
                result.warning_messages.append("Key usage extension not found")
                details['key_usage'] = []
            
            # Check extended key usage
            try:
                ext_key_usage_ext = certificate.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE)
                ext_key_usage = ext_key_usage_ext.value
                
                ext_usage_oids = [usage.dotted_string for usage in ext_key_usage]
                details['extended_key_usage'] = ext_usage_oids
                
                # Check for client authentication usage
                client_auth_oid = "1.3.6.1.5.5.7.3.2"
                if client_auth_oid not in ext_usage_oids:
                    result.warning_messages.append("Client authentication usage not found")
                
            except x509.ExtensionNotFound:
                result.warning_messages.append("Extended key usage extension not found")
                details['extended_key_usage'] = []
            
            result.validation_details = details
            result.is_valid = True
            
        except Exception as e:
            result.error_message = f"Key usage validation error: {str(e)}"
        
        return result
    
    def _validate_required_extensions(self, certificate: x509.Certificate) -> ValidationResult:
        """Validate required certificate extensions"""
        result = ValidationResult(is_valid=False)
        details = {}
        warnings = []
        
        try:
            extensions_found = []
            
            # Check for Subject Alternative Name (required for CAC)
            try:
                san_ext = certificate.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                extensions_found.append('subject_alternative_name')
                
                san_values = []
                for name in san_ext.value:
                    if isinstance(name, x509.RFC822Name):
                        san_values.append(f"email:{name.value}")
                    elif isinstance(name, x509.OtherName):
                        san_values.append(f"othername:{name.type_id.dotted_string}")
                    elif isinstance(name, x509.DirectoryName):
                        san_values.append(f"dirname:{name.value.rfc4514_string()}")
                
                details['subject_alternative_name'] = san_values
                
            except x509.ExtensionNotFound:
                warnings.append("Subject Alternative Name extension not found")
            
            # Check for Authority Key Identifier
            try:
                aki_ext = certificate.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_KEY_IDENTIFIER)
                extensions_found.append('authority_key_identifier')
                details['authority_key_identifier'] = aki_ext.value.key_identifier.hex() if aki_ext.value.key_identifier else None
            except x509.ExtensionNotFound:
                warnings.append("Authority Key Identifier extension not found")
            
            # Check for Subject Key Identifier
            try:
                ski_ext = certificate.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_KEY_IDENTIFIER)
                extensions_found.append('subject_key_identifier')
                details['subject_key_identifier'] = ski_ext.value.digest.hex()
            except x509.ExtensionNotFound:
                warnings.append("Subject Key Identifier extension not found")
            
            # Check for CRL Distribution Points
            try:
                crl_ext = certificate.extensions.get_extension_for_oid(ExtensionOID.CRL_DISTRIBUTION_POINTS)
                extensions_found.append('crl_distribution_points')
                
                crl_urls = []
                for dist_point in crl_ext.value:
                    if dist_point.full_name:
                        for name in dist_point.full_name:
                            if isinstance(name, x509.UniformResourceIdentifier):
                                crl_urls.append(name.value)
                
                details['crl_distribution_points'] = crl_urls
                
            except x509.ExtensionNotFound:
                warnings.append("CRL Distribution Points extension not found")
            
            # Check for Authority Information Access (for OCSP)
            try:
                aia_ext = certificate.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
                extensions_found.append('authority_information_access')
                
                ocsp_urls = []
                ca_issuer_urls = []
                
                for access_desc in aia_ext.value:
                    if access_desc.access_method == x509.oid.AuthorityInformationAccessOID.OCSP:
                        if isinstance(access_desc.access_location, x509.UniformResourceIdentifier):
                            ocsp_urls.append(access_desc.access_location.value)
                    elif access_desc.access_method == x509.oid.AuthorityInformationAccessOID.CA_ISSUERS:
                        if isinstance(access_desc.access_location, x509.UniformResourceIdentifier):
                            ca_issuer_urls.append(access_desc.access_location.value)
                
                details['ocsp_urls'] = ocsp_urls
                details['ca_issuer_urls'] = ca_issuer_urls
                
            except x509.ExtensionNotFound:
                warnings.append("Authority Information Access extension not found")
            
            details['extensions_found'] = extensions_found
            result.validation_details = details
            result.warning_messages = warnings
            result.is_valid = True
            
        except Exception as e:
            result.error_message = f"Extensions validation error: {str(e)}"
        
        return result
    
    def _get_certificate_hash(self, certificate: x509.Certificate) -> str:
        """Generate hash for certificate caching"""
        cert_der = certificate.public_bytes(serialization.Encoding.DER)
        return hashlib.sha256(cert_der).hexdigest()
    
    def clear_validation_cache(self):
        """Clear the validation cache"""
        self._validation_cache.clear()
        logger.info("Validation cache cleared")
    
    def get_cache_stats(self) -> Dict:
        """Get cache statistics"""
        return {
            'cached_certificates': len(self._validation_cache),
            'cache_timeout': self._cache_timeout
        }


class CRLChecker:
    """
    Certificate Revocation List (CRL) validation
    Implements downloading, parsing, and checking of CRL for certificate revocation status
    """
    
    def __init__(self, cache_dir: str = None, cache_timeout: int = 3600):
        """
        Initialize CRL checker
        
        Args:
            cache_dir: Directory to cache downloaded CRLs
            cache_timeout: CRL cache timeout in seconds (default 1 hour)
        """
        self.cache_dir = cache_dir or os.path.expanduser("~/.cac/crl_cache")
        self.cache_timeout = cache_timeout
        self._crl_cache = {}
        self._session = requests.Session()
        self._session.headers.update({
            'User-Agent': 'DoD-CAC-CRL-Checker/1.0',
            'Accept': 'application/pkix-crl, application/x-pkcs7-crl'
        })
        
        # Create cache directory
        os.makedirs(self.cache_dir, exist_ok=True)
        logger.info(f"CRL Checker initialized with cache dir: {self.cache_dir}")
    
    def check_certificate_revocation(self, certificate: x509.Certificate) -> RevocationStatus:
        """
        Check if certificate is revoked using CRL
        
        Args:
            certificate: Certificate to check
            
        Returns:
            RevocationStatus with revocation information
        """
        try:
            # Get CRL distribution points from certificate
            crl_urls = self._get_crl_urls(certificate)
            
            if not crl_urls:
                logger.warning("No CRL distribution points found in certificate")
                return RevocationStatus(
                    is_revoked=False,
                    check_time=datetime.now(timezone.utc),
                    method='CRL',
                    reason="No CRL distribution points available"
                )
            
            # Check each CRL URL until we find the certificate or exhaust all
            for crl_url in crl_urls:
                try:
                    revocation_status = self._check_against_crl(certificate, crl_url)
                    if revocation_status.is_revoked or revocation_status.reason != "Certificate not found in CRL":
                        return revocation_status
                except Exception as e:
                    logger.warning(f"Failed to check CRL at {crl_url}: {e}")
                    continue
            
            # If we get here, certificate was not found in any CRL
            return RevocationStatus(
                is_revoked=False,
                check_time=datetime.now(timezone.utc),
                method='CRL',
                reason="Certificate not found in any available CRL"
            )
            
        except Exception as e:
            logger.error(f"CRL revocation check failed: {e}")
            return RevocationStatus(
                is_revoked=False,
                check_time=datetime.now(timezone.utc),
                method='CRL',
                reason=f"CRL check error: {str(e)}"
            )
    
    def _get_crl_urls(self, certificate: x509.Certificate) -> List[str]:
        """Extract CRL URLs from certificate"""
        crl_urls = []
        
        try:
            crl_ext = certificate.extensions.get_extension_for_oid(ExtensionOID.CRL_DISTRIBUTION_POINTS)
            
            for dist_point in crl_ext.value:
                if dist_point.full_name:
                    for name in dist_point.full_name:
                        if isinstance(name, x509.UniformResourceIdentifier):
                            url = name.value
                            if url.startswith(('http://', 'https://')):
                                crl_urls.append(url)
                            
        except x509.ExtensionNotFound:
            logger.debug("No CRL distribution points extension found")
        
        return crl_urls
    
    def _check_against_crl(self, certificate: x509.Certificate, crl_url: str) -> RevocationStatus:
        """Check certificate against specific CRL"""
        # Get or download CRL
        crl = self._get_crl(crl_url)
        
        if not crl:
            return RevocationStatus(
                is_revoked=False,
                check_time=datetime.now(timezone.utc),
                method='CRL',
                reason="Failed to retrieve CRL"
            )
        
        # Check if certificate is in revoked list
        cert_serial = certificate.serial_number
        check_time = datetime.now(timezone.utc)
        
        try:
            for revoked_cert in crl:
                if revoked_cert.serial_number == cert_serial:
                    # Certificate is revoked
                    revocation_time = revoked_cert.revocation_date
                    reason = "Unknown"
                    
                    # Try to get revocation reason
                    if revoked_cert.extensions:
                        try:
                            reason_ext = revoked_cert.extensions.get_extension_for_oid(
                                ExtensionOID.CRL_REASON
                            )
                            reason = reason_ext.value.reason.name
                        except x509.ExtensionNotFound:
                            pass
                    
                    return RevocationStatus(
                        is_revoked=True,
                        check_time=check_time,
                        method='CRL',
                        reason=reason,
                        revocation_time=revocation_time,
                        next_update=getattr(crl, 'next_update', None)
                    )
            
            # Certificate not found in revoked list
            return RevocationStatus(
                is_revoked=False,
                check_time=check_time,
                method='CRL',
                reason="Certificate not found in CRL",
                next_update=getattr(crl, 'next_update', None)
            )
            
        except Exception as e:
            logger.error(f"Error checking CRL: {e}")
            return RevocationStatus(
                is_revoked=False,
                check_time=check_time,
                method='CRL',
                reason=f"CRL parsing error: {str(e)}"
            )
    
    def _get_crl(self, crl_url: str) -> Optional[x509.CertificateRevocationList]:
        """Download and parse CRL with caching"""
        # Check memory cache first
        if crl_url in self._crl_cache:
            crl_data, cache_time = self._crl_cache[crl_url]
            if time.time() - cache_time < self.cache_timeout:
                logger.debug(f"Using cached CRL for {crl_url}")
                return crl_data
        
        # Check file cache
        cache_filename = self._get_cache_filename(crl_url)
        cache_filepath = os.path.join(self.cache_dir, cache_filename)
        
        if os.path.exists(cache_filepath):
            file_age = time.time() - os.path.getmtime(cache_filepath)
            if file_age < self.cache_timeout:
                try:
                    with open(cache_filepath, 'rb') as f:
                        crl_data = f.read()
                    
                    crl = self._parse_crl(crl_data)
                    if crl:
                        self._crl_cache[crl_url] = (crl, time.time())
                        logger.debug(f"Loaded CRL from file cache: {cache_filepath}")
                        return crl
                        
                except Exception as e:
                    logger.warning(f"Failed to load cached CRL: {e}")
        
        # Download new CRL
        return self._download_crl(crl_url, cache_filepath)
    
    def _download_crl(self, crl_url: str, cache_filepath: str) -> Optional[x509.CertificateRevocationList]:
        """Download CRL from URL"""
        try:
            logger.info(f"Downloading CRL from: {crl_url}")
            
            response = self._session.get(crl_url, timeout=30)
            response.raise_for_status()
            
            crl_data = response.content
            crl = self._parse_crl(crl_data)
            
            if crl:
                # Cache to file
                try:
                    with open(cache_filepath, 'wb') as f:
                        f.write(crl_data)
                    logger.debug(f"Cached CRL to: {cache_filepath}")
                except Exception as e:
                    logger.warning(f"Failed to cache CRL: {e}")
                
                # Cache to memory
                self._crl_cache[crl_url] = (crl, time.time())
                
                return crl
            
        except requests.RequestException as e:
            logger.error(f"Failed to download CRL from {crl_url}: {e}")
        except Exception as e:
            logger.error(f"Unexpected error downloading CRL: {e}")
        
        return None
    
    def _parse_crl(self, crl_data: bytes) -> Optional[x509.CertificateRevocationList]:
        """Parse CRL data"""
        try:
            # Try DER format first
            try:
                return x509.load_der_x509_crl(crl_data)
            except ValueError:
                # Try PEM format
                return x509.load_pem_x509_crl(crl_data)
                
        except Exception as e:
            logger.error(f"Failed to parse CRL: {e}")
            return None
    
    def _get_cache_filename(self, crl_url: str) -> str:
        """Generate cache filename for CRL URL"""
        url_hash = hashlib.sha256(crl_url.encode()).hexdigest()[:16]
        return f"crl_{url_hash}.der"
    
    def clear_cache(self):
        """Clear CRL cache"""
        self._crl_cache.clear()
        
        # Clear file cache
        try:
            for filename in os.listdir(self.cache_dir):
                if filename.startswith('crl_') and filename.endswith('.der'):
                    os.remove(os.path.join(self.cache_dir, filename))
            logger.info("CRL cache cleared")
        except Exception as e:
            logger.warning(f"Failed to clear file cache: {e}")
    
    def get_cache_stats(self) -> Dict:
        """Get CRL cache statistics"""
        file_cache_count = 0
        try:
            file_cache_count = len([f for f in os.listdir(self.cache_dir) 
                                  if f.startswith('crl_') and f.endswith('.der')])
        except Exception:
            pass
        
        return {
            'memory_cache_count': len(self._crl_cache),
            'file_cache_count': file_cache_count,
            'cache_timeout': self.cache_timeout,
            'cache_directory': self.cache_dir
        }


class OCSPValidator:
    """
    Online Certificate Status Protocol (OCSP) validator
    Implements real-time certificate revocation checking via OCSP
    """
    
    def __init__(self, timeout: int = 30, max_retries: int = 3):
        """
        Initialize OCSP validator
        
        Args:
            timeout: Network timeout for OCSP requests
            max_retries: Maximum retry attempts for failed requests
        """
        self.timeout = timeout
        self.max_retries = max_retries
        self._session = requests.Session()
        self._session.headers.update({
            'User-Agent': 'DoD-CAC-OCSP-Validator/1.0',
            'Content-Type': 'application/ocsp-request',
            'Accept': 'application/ocsp-response'
        })
        
        logger.info("OCSP Validator initialized")
    
    def check_certificate_revocation(self, certificate: x509.Certificate, 
                                   issuer_certificate: x509.Certificate = None) -> RevocationStatus:
        """
        Check certificate revocation status via OCSP
        
        Args:
            certificate: Certificate to check
            issuer_certificate: Issuer certificate (required for OCSP)
            
        Returns:
            RevocationStatus with OCSP response information
        """
        if not issuer_certificate:
            return RevocationStatus(
                is_revoked=False,
                check_time=datetime.now(timezone.utc),
                method='OCSP',
                reason="Issuer certificate required for OCSP validation"
            )
        
        try:
            # Get OCSP URLs from certificate
            ocsp_urls = self._get_ocsp_urls(certificate)
            
            if not ocsp_urls:
                return RevocationStatus(
                    is_revoked=False,
                    check_time=datetime.now(timezone.utc),
                    method='OCSP',
                    reason="No OCSP responder URLs found in certificate"
                )
            
            # Try each OCSP URL
            for ocsp_url in ocsp_urls:
                try:
                    revocation_status = self._check_ocsp_responder(
                        certificate, issuer_certificate, ocsp_url
                    )
                    
                    # If we got a definitive answer, return it
                    if revocation_status.reason != "OCSP request failed":
                        return revocation_status
                        
                except Exception as e:
                    logger.warning(f"OCSP check failed for {ocsp_url}: {e}")
                    continue
            
            # All OCSP responders failed
            return RevocationStatus(
                is_revoked=False,
                check_time=datetime.now(timezone.utc),
                method='OCSP',
                reason="All OCSP responders failed"
            )
            
        except Exception as e:
            logger.error(f"OCSP validation error: {e}")
            return RevocationStatus(
                is_revoked=False,
                check_time=datetime.now(timezone.utc),
                method='OCSP',
                reason=f"OCSP validation error: {str(e)}"
            )
    
    def _get_ocsp_urls(self, certificate: x509.Certificate) -> List[str]:
        """Extract OCSP URLs from certificate Authority Information Access extension"""
        ocsp_urls = []
        
        try:
            aia_ext = certificate.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
            
            for access_desc in aia_ext.value:
                if access_desc.access_method == x509.oid.AuthorityInformationAccessOID.OCSP:
                    if isinstance(access_desc.access_location, x509.UniformResourceIdentifier):
                        url = access_desc.access_location.value
                        if url.startswith(('http://', 'https://')):
                            ocsp_urls.append(url)
                            
        except x509.ExtensionNotFound:
            logger.debug("No Authority Information Access extension found")
        
        return ocsp_urls
    
    def _check_ocsp_responder(self, certificate: x509.Certificate, 
                             issuer_certificate: x509.Certificate, 
                             ocsp_url: str) -> RevocationStatus:
        """Check certificate status with specific OCSP responder"""
        try:
            # Build OCSP request
            ocsp_request = self._build_ocsp_request(certificate, issuer_certificate)
            
            # Send OCSP request
            ocsp_response_data = self._send_ocsp_request(ocsp_url, ocsp_request)
            
            if not ocsp_response_data:
                return RevocationStatus(
                    is_revoked=False,
                    check_time=datetime.now(timezone.utc),
                    method='OCSP',
                    reason="OCSP request failed"
                )
            
            # Parse OCSP response
            return self._parse_ocsp_response(ocsp_response_data)
            
        except Exception as e:
            logger.error(f"OCSP responder check failed: {e}")
            return RevocationStatus(
                is_revoked=False,
                check_time=datetime.now(timezone.utc),
                method='OCSP',
                reason=f"OCSP responder error: {str(e)}"
            )
    
    def _build_ocsp_request(self, certificate: x509.Certificate, 
                           issuer_certificate: x509.Certificate) -> bytes:
        """Build OCSP request for certificate"""
        try:
            # Create OCSP request
            builder = ocsp.OCSPRequestBuilder()
            builder = builder.add_certificate(certificate, issuer_certificate, hashes.SHA1())
            
            ocsp_request = builder.build()
            return ocsp_request.public_bytes(serialization.Encoding.DER)
            
        except Exception as e:
            logger.error(f"Failed to build OCSP request: {e}")
            raise
    
    def _send_ocsp_request(self, ocsp_url: str, ocsp_request: bytes) -> Optional[bytes]:
        """Send OCSP request to responder"""
        for attempt in range(self.max_retries):
            try:
                logger.debug(f"Sending OCSP request to {ocsp_url} (attempt {attempt + 1})")
                
                response = self._session.post(
                    ocsp_url, 
                    data=ocsp_request,
                    timeout=self.timeout
                )
                response.raise_for_status()
                
                if response.headers.get('Content-Type') == 'application/ocsp-response':
                    return response.content
                else:
                    logger.warning(f"Unexpected content type: {response.headers.get('Content-Type')}")
                    return None
                    
            except requests.RequestException as e:
                logger.warning(f"OCSP request attempt {attempt + 1} failed: {e}")
                if attempt == self.max_retries - 1:
                    raise
                time.sleep(1)  # Brief delay before retry
        
        return None
    
    def _parse_ocsp_response(self, ocsp_response_data: bytes) -> RevocationStatus:
        """Parse OCSP response"""
        try:
            ocsp_response = ocsp.load_der_ocsp_response(ocsp_response_data)
            
            check_time = datetime.now(timezone.utc)
            
            # Check response status
            if ocsp_response.response_status != ocsp.OCSPResponseStatus.SUCCESSFUL:
                return RevocationStatus(
                    is_revoked=False,
                    check_time=check_time,
                    method='OCSP',
                    reason=f"OCSP response status: {ocsp_response.response_status.name}"
                )
            
            # Get certificate status
            certificate_status = ocsp_response.certificate_status
            
            if isinstance(certificate_status, ocsp.OCSPCertStatus):
                # Certificate is good (not revoked)
                return RevocationStatus(
                    is_revoked=False,
                    check_time=check_time,
                    method='OCSP',
                    reason="Certificate status: GOOD",
                    next_update=ocsp_response.next_update
                )
            
            elif isinstance(certificate_status, ocsp.OCSPRevokedCertStatus):
                # Certificate is revoked
                revocation_time = certificate_status.revocation_time
                revocation_reason = "Unknown"
                
                if certificate_status.revocation_reason:
                    revocation_reason = certificate_status.revocation_reason.name
                
                return RevocationStatus(
                    is_revoked=True,
                    check_time=check_time,
                    method='OCSP',
                    reason=revocation_reason,
                    revocation_time=revocation_time,
                    next_update=ocsp_response.next_update
                )
            
            elif isinstance(certificate_status, ocsp.OCSPUnknownCertStatus):
                # Certificate status unknown
                return RevocationStatus(
                    is_revoked=False,
                    check_time=check_time,
                    method='OCSP',
                    reason="Certificate status: UNKNOWN",
                    next_update=ocsp_response.next_update
                )
            
            else:
                return RevocationStatus(
                    is_revoked=False,
                    check_time=check_time,
                    method='OCSP',
                    reason=f"Unexpected certificate status type: {type(certificate_status)}"
                )
                
        except Exception as e:
            logger.error(f"Failed to parse OCSP response: {e}")
            return RevocationStatus(
                is_revoked=False,
                check_time=datetime.now(timezone.utc),
                method='OCSP',
                reason=f"OCSP response parsing error: {str(e)}"
            )


class CombinedRevocationChecker:
    """
    Combined certificate revocation checker using both CRL and OCSP
    Implements fallback strategy: OCSP first, then CRL if OCSP fails
    """
    
    def __init__(self, prefer_ocsp: bool = True, require_definitive_result: bool = False):
        """
        Initialize combined revocation checker
        
        Args:
            prefer_ocsp: Whether to prefer OCSP over CRL (default True)
            require_definitive_result: Whether to require definitive revocation status
        """
        self.prefer_ocsp = prefer_ocsp
        self.require_definitive_result = require_definitive_result
        self.ocsp_validator = OCSPValidator()
        self.crl_checker = CRLChecker()
        
        logger.info(f"Combined revocation checker initialized (prefer_ocsp={prefer_ocsp})")
    
    def check_certificate_revocation(self, certificate: x509.Certificate, 
                                   issuer_certificate: x509.Certificate = None) -> RevocationStatus:
        """
        Check certificate revocation using both OCSP and CRL with fallback
        
        Args:
            certificate: Certificate to check
            issuer_certificate: Issuer certificate (for OCSP)
            
        Returns:
            RevocationStatus with best available revocation information
        """
        primary_method = 'OCSP' if self.prefer_ocsp else 'CRL'
        fallback_method = 'CRL' if self.prefer_ocsp else 'OCSP'
        
        logger.debug(f"Checking revocation: primary={primary_method}, fallback={fallback_method}")
        
        # Try primary method first
        primary_result = self._check_single_method(
            certificate, issuer_certificate, primary_method
        )
        
        # If primary method gave definitive result (revoked or good status), use it
        if self._is_definitive_result(primary_result):
            logger.debug(f"Got definitive result from {primary_method}")
            return primary_result
        
        # Try fallback method
        fallback_result = self._check_single_method(
            certificate, issuer_certificate, fallback_method
        )
        
        # If fallback method gave definitive result, use it
        if self._is_definitive_result(fallback_result):
            logger.debug(f"Got definitive result from {fallback_method}")
            return fallback_result
        
        # Neither method gave definitive result
        if self.require_definitive_result:
            return RevocationStatus(
                is_revoked=False,
                check_time=datetime.now(timezone.utc),
                method='Combined',
                reason="No definitive revocation status available from any method"
            )
        
        # Return the better of the two results (prefer the one with fewer errors)
        if self._is_better_result(primary_result, fallback_result):
            return primary_result
        else:
            return fallback_result
    
    def _check_single_method(self, certificate: x509.Certificate, 
                           issuer_certificate: x509.Certificate, 
                           method: str) -> RevocationStatus:
        """Check revocation using single method"""
        try:
            if method == 'OCSP':
                return self.ocsp_validator.check_certificate_revocation(
                    certificate, issuer_certificate
                )
            elif method == 'CRL':
                return self.crl_checker.check_certificate_revocation(certificate)
            else:
                raise ValueError(f"Unknown method: {method}")
                
        except Exception as e:
            logger.error(f"Revocation check failed for method {method}: {e}")
            return RevocationStatus(
                is_revoked=False,
                check_time=datetime.now(timezone.utc),
                method=method,
                reason=f"Method {method} failed: {str(e)}"
            )
    
    def _is_definitive_result(self, result: RevocationStatus) -> bool:
        """Check if revocation result is definitive"""
        # Certificate is definitely revoked
        if result.is_revoked:
            return True
        
        # Certificate status was successfully checked and is good
        good_status_indicators = [
            "Certificate status: GOOD",
            "Certificate not found in CRL"
        ]
        
        return any(indicator in result.reason for indicator in good_status_indicators)
    
    def _is_better_result(self, result1: RevocationStatus, result2: RevocationStatus) -> bool:
        """Compare two results and return True if result1 is better"""
        # Revoked status is always definitive
        if result1.is_revoked and not result2.is_revoked:
            return True
        if result2.is_revoked and not result1.is_revoked:
            return False
        
        # Neither is revoked, prefer the one with better reason
        error_indicators = ["failed", "error", "timeout", "unavailable"]
        
        result1_has_error = any(indicator in result1.reason.lower() for indicator in error_indicators)
        result2_has_error = any(indicator in result2.reason.lower() for indicator in error_indicators)
        
        if not result1_has_error and result2_has_error:
            return True
        if result1_has_error and not result2_has_error:
            return False
        
        # Both similar quality, prefer by method preference
        if self.prefer_ocsp:
            return result1.method == 'OCSP'
        else:
            return result1.method == 'CRL'
    
    def clear_caches(self):
        """Clear all revocation caches"""
        self.crl_checker.clear_cache()
        logger.info("All revocation caches cleared")
    
    def get_cache_stats(self) -> Dict:
        """Get cache statistics from all checkers"""
        return {
            'crl_cache': self.crl_checker.get_cache_stats(),
            'prefer_ocsp': self.prefer_ocsp,
            'require_definitive_result': self.require_definitive_result
        }