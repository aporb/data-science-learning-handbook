#!/usr/bin/env python3
"""
Trust Store Manager for DoD PKI Root Certificates

This module provides comprehensive trust store management for DoD PKI root and
intermediate CA certificates with automatic updates, validation, and secure storage.
"""

import os
import logging
import hashlib
import json
import shutil
import tempfile
from typing import Optional, Dict, List, Tuple, Set, Any
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone, timedelta
from pathlib import Path
from urllib.parse import urlparse
import requests
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.x509.oid import ExtensionOID, NameOID
import threading
import time
import zipfile
import sqlite3

logger = logging.getLogger(__name__)


@dataclass
class TrustedCAInfo:
    """Information about a trusted CA certificate."""
    subject_dn: str
    issuer_dn: str
    serial_number: str
    fingerprint_sha256: str
    fingerprint_sha1: str
    not_before: datetime
    not_after: datetime
    key_algorithm: str
    key_size: int
    signature_algorithm: str
    
    # DoD-specific information
    ca_type: str  # ROOT, INTERMEDIATE, CROSS_SIGNED
    dod_ca_level: str  # ROOT_CA_2, ROOT_CA_3, etc.
    distribution_point: Optional[str] = None
    crl_urls: List[str] = field(default_factory=list)
    ocsp_urls: List[str] = field(default_factory=list)
    
    # File information
    file_path: str = ""
    file_format: str = ""  # PEM, DER
    last_updated: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    source_url: Optional[str] = None
    
    # Validation status
    is_valid: bool = True
    is_trusted: bool = True
    validation_errors: List[str] = field(default_factory=list)
    last_validated: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class TrustStoreManager:
    """
    Comprehensive trust store manager for DoD PKI certificates.
    
    Provides automated downloading, validation, and management of DoD root and
    intermediate CA certificates with secure storage and update mechanisms.
    """
    
    # DoD PKI certificate distribution points
    DOD_PKI_DISTRIBUTION_POINTS = {
        'primary': 'http://crl.disa.mil/crl/',
        'backup': 'https://crl.gds.disa.mil/',
        'cyber_exchange': 'https://cyber.mil/pki-pke/'
    }
    
    # Known DoD Root CA certificates with expected properties
    DOD_ROOT_CAS = {
        'DoD Root CA 2': {
            'expected_subject': 'CN=DoD Root CA 2, OU=PKI, OU=DoD, O=U.S. Government, C=US',
            'key_size_min': 2048,
            'valid_from': '2000-12-05',
            'valid_until': '2029-12-30'
        },
        'DoD Root CA 3': {
            'expected_subject': 'CN=DoD Root CA 3, OU=PKI, OU=DoD, O=U.S. Government, C=US',
            'key_size_min': 2048,
            'valid_from': '2010-01-01',
            'valid_until': '2029-12-30'
        },
        'DoD Root CA 4': {
            'expected_subject': 'CN=DoD Root CA 4, OU=PKI, OU=DoD, O=U.S. Government, C=US',
            'key_size_min': 2048,
            'valid_from': '2012-01-01',
            'valid_until': '2029-12-30'
        },
        'DoD Root CA 5': {
            'expected_subject': 'CN=DoD Root CA 5, OU=PKI, OU=DoD, O=U.S. Government, C=US',
            'key_size_min': 2048,
            'valid_from': '2015-01-01',
            'valid_until': '2029-12-30'
        },
        'DoD Root CA 6': {
            'expected_subject': 'CN=DoD Root CA 6, OU=PKI, OU=DoD, O=U.S. Government, C=US',
            'key_size_min': 2048,
            'valid_from': '2019-01-01',
            'valid_until': '2029-12-30'
        }
    }
    
    # Standard DoD intermediate CA patterns
    DOD_INTERMEDIATE_PATTERNS = [
        'DoD EMAIL CA-*',
        'DoD ID CA-*',
        'DoD ID SW CA-*',
        'DoD SW CA-*',
        'US DoD CCEB Interoperability Root CA*'
    ]
    
    def __init__(self, trust_store_path: str = None, 
                 enable_auto_update: bool = True,
                 update_interval_hours: int = 24):
        """
        Initialize trust store manager.
        
        Args:
            trust_store_path: Path to trust store directory
            enable_auto_update: Enable automatic certificate updates
            update_interval_hours: Update check interval in hours
        """
        self.trust_store_path = trust_store_path or self._get_default_trust_store_path()
        self.enable_auto_update = enable_auto_update
        self.update_interval_hours = update_interval_hours
        
        # Create trust store directory structure
        self._initialize_trust_store()
        
        # Database for tracking certificates
        self.db_path = os.path.join(self.trust_store_path, 'trust_store.db')
        self._initialize_database()
        
        # Loaded certificates cache
        self._loaded_certificates = {}
        self._cache_lock = threading.Lock()
        
        # Update tracking
        self._last_update_check = None
        self._update_thread = None
        self._shutdown_event = threading.Event()
        
        # Session for HTTP requests
        self._session = requests.Session()
        self._session.headers.update({
            'User-Agent': 'DoD-PKI-TrustStore-Manager/1.0'
        })
        
        logger.info(f"Trust store manager initialized: {self.trust_store_path}")
        
        # Start auto-update thread if enabled
        if enable_auto_update:
            self._start_auto_update_thread()
    
    def _get_default_trust_store_path(self) -> str:
        """Get default path for trust store."""
        default_paths = [
            os.path.expanduser("~/.cac/trust-store"),
            "/etc/ssl/certs/dod-pki",
            "/usr/local/share/ca-certificates/dod-pki",
            "./trust-store"
        ]
        
        # Use first existing path or create the first one
        for path in default_paths:
            if os.path.exists(path):
                return path
        
        # Create default path
        default_path = default_paths[0]
        os.makedirs(default_path, exist_ok=True)
        return default_path
    
    def _initialize_trust_store(self):
        """Initialize trust store directory structure."""
        directories = [
            'root-cas',
            'intermediate-cas', 
            'cross-signed',
            'backup',
            'quarantine'
        ]
        
        for directory in directories:
            dir_path = os.path.join(self.trust_store_path, directory)
            os.makedirs(dir_path, exist_ok=True)
        
        logger.debug("Trust store directory structure initialized")
    
    def _initialize_database(self):
        """Initialize SQLite database for certificate tracking."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS trusted_cas (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    subject_dn TEXT UNIQUE NOT NULL,
                    issuer_dn TEXT NOT NULL,
                    serial_number TEXT NOT NULL,
                    fingerprint_sha256 TEXT UNIQUE NOT NULL,
                    fingerprint_sha1 TEXT NOT NULL,
                    not_before TEXT NOT NULL,
                    not_after TEXT NOT NULL,
                    key_algorithm TEXT NOT NULL,
                    key_size INTEGER NOT NULL,
                    signature_algorithm TEXT NOT NULL,
                    ca_type TEXT NOT NULL,
                    dod_ca_level TEXT,
                    distribution_point TEXT,
                    crl_urls TEXT,
                    ocsp_urls TEXT,
                    file_path TEXT NOT NULL,
                    file_format TEXT NOT NULL,
                    last_updated TEXT NOT NULL,
                    source_url TEXT,
                    is_valid BOOLEAN NOT NULL DEFAULT 1,
                    is_trusted BOOLEAN NOT NULL DEFAULT 1,
                    validation_errors TEXT,
                    last_validated TEXT NOT NULL,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            conn.execute('''
                CREATE INDEX IF NOT EXISTS idx_subject_dn ON trusted_cas(subject_dn)
            ''')
            
            conn.execute('''
                CREATE INDEX IF NOT EXISTS idx_fingerprint_sha256 ON trusted_cas(fingerprint_sha256)
            ''')
            
            conn.execute('''
                CREATE INDEX IF NOT EXISTS idx_ca_type ON trusted_cas(ca_type)
            ''')
            
            conn.commit()
        
        logger.debug("Trust store database initialized")
    
    def add_certificate(self, certificate_data: bytes, 
                       source_info: Dict[str, Any] = None) -> TrustedCAInfo:
        """
        Add certificate to trust store with validation.
        
        Args:
            certificate_data: Certificate data (PEM or DER)
            source_info: Information about certificate source
            
        Returns:
            TrustedCAInfo object for added certificate
        """
        try:
            # Parse certificate
            try:
                certificate = x509.load_pem_x509_certificate(certificate_data)
                file_format = "PEM"
            except ValueError:
                certificate = x509.load_der_x509_certificate(certificate_data)
                file_format = "DER"
            
            # Extract certificate information
            ca_info = self._extract_certificate_info(certificate, file_format)
            
            # Add source information if provided
            if source_info:
                ca_info.source_url = source_info.get('source_url')
                ca_info.distribution_point = source_info.get('distribution_point')
            
            # Validate certificate
            self._validate_certificate(certificate, ca_info)
            
            # Determine appropriate storage location
            storage_path = self._get_storage_path(ca_info)
            
            # Generate filename
            filename = self._generate_certificate_filename(ca_info)
            full_path = os.path.join(storage_path, filename)
            
            # Write certificate to file
            with open(full_path, 'wb') as f:
                f.write(certificate_data)
            
            ca_info.file_path = full_path
            
            # Store in database
            self._store_certificate_info(ca_info)
            
            # Update cache
            with self._cache_lock:
                self._loaded_certificates[ca_info.fingerprint_sha256] = ca_info
            
            logger.info(f"Added certificate to trust store: {ca_info.subject_dn}")
            return ca_info
            
        except Exception as e:
            logger.error(f"Failed to add certificate to trust store: {e}")
            raise
    
    def _extract_certificate_info(self, certificate: x509.Certificate, 
                                 file_format: str) -> TrustedCAInfo:
        """Extract information from certificate."""
        # Basic certificate information
        subject_dn = certificate.subject.rfc4514_string()
        issuer_dn = certificate.issuer.rfc4514_string()
        serial_number = str(certificate.serial_number)
        
        # Calculate fingerprints
        cert_der = certificate.public_bytes(serialization.Encoding.DER)
        fingerprint_sha256 = hashlib.sha256(cert_der).hexdigest()
        fingerprint_sha1 = hashlib.sha1(cert_der).hexdigest()
        
        # Extract key information
        public_key = certificate.public_key()
        key_algorithm = type(public_key).__name__.replace('PublicKey', '')
        key_size = getattr(public_key, 'key_size', 0)
        
        # Signature algorithm
        signature_algorithm = certificate.signature_algorithm_oid.dotted_string
        
        # Determine CA type and DoD level
        ca_type, dod_ca_level = self._determine_ca_type(certificate)
        
        # Extract CRL and OCSP URLs
        crl_urls = self._extract_crl_urls(certificate)
        ocsp_urls = self._extract_ocsp_urls(certificate)
        
        return TrustedCAInfo(
            subject_dn=subject_dn,
            issuer_dn=issuer_dn,
            serial_number=serial_number,
            fingerprint_sha256=fingerprint_sha256,
            fingerprint_sha1=fingerprint_sha1,
            not_before=certificate.not_valid_before,
            not_after=certificate.not_valid_after,
            key_algorithm=key_algorithm,
            key_size=key_size,
            signature_algorithm=signature_algorithm,
            ca_type=ca_type,
            dod_ca_level=dod_ca_level,
            crl_urls=crl_urls,
            ocsp_urls=ocsp_urls,
            file_format=file_format
        )
    
    def _determine_ca_type(self, certificate: x509.Certificate) -> Tuple[str, str]:
        """Determine CA type and DoD level from certificate."""
        subject_dn = certificate.subject.rfc4514_string()
        issuer_dn = certificate.issuer.rfc4514_string()
        
        # Check if it's a DoD Root CA
        for root_name, root_info in self.DOD_ROOT_CAS.items():
            if root_info['expected_subject'] in subject_dn:
                return "ROOT", root_name.replace(" ", "_").upper()
        
        # Check if it's self-signed (likely root)
        if subject_dn == issuer_dn:
            return "ROOT", "UNKNOWN_ROOT"
        
        # Check for DoD intermediate patterns
        subject_cn = self._get_cn_from_dn(subject_dn)
        for pattern in self.DOD_INTERMEDIATE_PATTERNS:
            if self._matches_pattern(subject_cn, pattern):
                return "INTERMEDIATE", "DOD_INTERMEDIATE"
        
        # Check if issued by DoD root
        for root_name, root_info in self.DOD_ROOT_CAS.items():
            if root_info['expected_subject'] in issuer_dn:
                return "INTERMEDIATE", "DOD_INTERMEDIATE"
        
        # Check for cross-signed certificates
        if "Cross" in subject_dn or "Bridge" in subject_dn:
            return "CROSS_SIGNED", "CROSS_SIGNED"
        
        return "INTERMEDIATE", "UNKNOWN"
    
    def _get_cn_from_dn(self, dn: str) -> str:
        """Extract CN from distinguished name."""
        try:
            # Parse DN and extract CN
            dn_components = [comp.strip() for comp in dn.split(',')]
            for component in dn_components:
                if component.startswith('CN='):
                    return component[3:]  # Remove 'CN=' prefix
        except Exception:
            pass
        return ""
    
    def _matches_pattern(self, text: str, pattern: str) -> bool:
        """Check if text matches pattern with wildcards."""
        import fnmatch
        return fnmatch.fnmatch(text, pattern)
    
    def _extract_crl_urls(self, certificate: x509.Certificate) -> List[str]:
        """Extract CRL URLs from certificate."""
        crl_urls = []
        try:
            crl_ext = certificate.extensions.get_extension_for_oid(
                ExtensionOID.CRL_DISTRIBUTION_POINTS
            )
            
            for dist_point in crl_ext.value:
                if dist_point.full_name:
                    for name in dist_point.full_name:
                        if isinstance(name, x509.UniformResourceIdentifier):
                            crl_urls.append(name.value)
        except x509.ExtensionNotFound:
            pass
        
        return crl_urls
    
    def _extract_ocsp_urls(self, certificate: x509.Certificate) -> List[str]:
        """Extract OCSP URLs from certificate."""
        ocsp_urls = []
        try:
            aia_ext = certificate.extensions.get_extension_for_oid(
                ExtensionOID.AUTHORITY_INFORMATION_ACCESS
            )
            
            for access_desc in aia_ext.value:
                if access_desc.access_method == x509.oid.AuthorityInformationAccessOID.OCSP:
                    if isinstance(access_desc.access_location, x509.UniformResourceIdentifier):
                        ocsp_urls.append(access_desc.access_location.value)
        except x509.ExtensionNotFound:
            pass
        
        return ocsp_urls
    
    def _validate_certificate(self, certificate: x509.Certificate, ca_info: TrustedCAInfo):
        """Validate certificate for trust store inclusion."""
        validation_errors = []
        
        # Check if certificate is currently valid
        current_time = datetime.now(timezone.utc)
        if certificate.not_valid_before > current_time:
            validation_errors.append("Certificate is not yet valid")
        
        if certificate.not_valid_after < current_time:
            validation_errors.append("Certificate has expired")
        
        # Check key size requirements
        if ca_info.key_algorithm == "RSA" and ca_info.key_size < 2048:
            validation_errors.append(f"RSA key size too small: {ca_info.key_size}")
        elif ca_info.key_algorithm == "EllipticCurve" and ca_info.key_size < 256:
            validation_errors.append(f"EC key size too small: {ca_info.key_size}")
        
        # Check if it's a CA certificate
        try:
            basic_constraints_ext = certificate.extensions.get_extension_for_oid(
                ExtensionOID.BASIC_CONSTRAINTS
            )
            if not basic_constraints_ext.value.ca:
                validation_errors.append("Certificate is not a CA certificate")
        except x509.ExtensionNotFound:
            validation_errors.append("Basic constraints extension missing")
        
        # Check key usage for CA
        try:
            key_usage_ext = certificate.extensions.get_extension_for_oid(
                ExtensionOID.KEY_USAGE
            )
            if not key_usage_ext.value.key_cert_sign:
                validation_errors.append("Certificate signing capability missing")
        except x509.ExtensionNotFound:
            validation_errors.append("Key usage extension missing")
        
        # Check for DoD-specific validation if it's a DoD certificate
        if "DoD" in ca_info.subject_dn or "U.S. Government" in ca_info.subject_dn:
            self._validate_dod_certificate(certificate, ca_info, validation_errors)
        
        ca_info.validation_errors = validation_errors
        ca_info.is_valid = len(validation_errors) == 0
        
        if validation_errors:
            logger.warning(f"Certificate validation issues: {ca_info.subject_dn} - {validation_errors}")
    
    def _validate_dod_certificate(self, certificate: x509.Certificate, 
                                ca_info: TrustedCAInfo, validation_errors: List[str]):
        """Perform DoD-specific certificate validation."""
        # Check against known DoD Root CA information
        if ca_info.ca_type == "ROOT":
            for root_name, root_info in self.DOD_ROOT_CAS.items():
                if root_info['expected_subject'] in ca_info.subject_dn:
                    # Validate key size
                    if ca_info.key_size < root_info['key_size_min']:
                        validation_errors.append(
                            f"Key size below minimum for {root_name}: {ca_info.key_size}"
                        )
                    break
        
        # Check signature algorithm (should be SHA-256 or higher)
        weak_algorithms = ['sha1WithRSAEncryption', 'md5WithRSAEncryption']
        if any(weak_algo in ca_info.signature_algorithm.lower() for weak_algo in weak_algorithms):
            validation_errors.append(f"Weak signature algorithm: {ca_info.signature_algorithm}")
    
    def _get_storage_path(self, ca_info: TrustedCAInfo) -> str:
        """Get appropriate storage path for certificate type."""
        if ca_info.ca_type == "ROOT":
            return os.path.join(self.trust_store_path, 'root-cas')
        elif ca_info.ca_type == "INTERMEDIATE":
            return os.path.join(self.trust_store_path, 'intermediate-cas')
        elif ca_info.ca_type == "CROSS_SIGNED":
            return os.path.join(self.trust_store_path, 'cross-signed')
        else:
            return os.path.join(self.trust_store_path, 'intermediate-cas')
    
    def _generate_certificate_filename(self, ca_info: TrustedCAInfo) -> str:
        """Generate filename for certificate."""
        # Clean subject CN for filename
        subject_cn = self._get_cn_from_dn(ca_info.subject_dn)
        clean_cn = ''.join(c for c in subject_cn if c.isalnum() or c in '._- ')
        clean_cn = clean_cn.replace(' ', '_')
        
        # Add fingerprint suffix for uniqueness
        fingerprint_suffix = ca_info.fingerprint_sha256[:8]
        
        # Determine extension
        ext = '.pem' if ca_info.file_format == 'PEM' else '.der'
        
        return f"{clean_cn}_{fingerprint_suffix}{ext}"
    
    def _store_certificate_info(self, ca_info: TrustedCAInfo):
        """Store certificate information in database."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                INSERT OR REPLACE INTO trusted_cas (
                    subject_dn, issuer_dn, serial_number, fingerprint_sha256, fingerprint_sha1,
                    not_before, not_after, key_algorithm, key_size, signature_algorithm,
                    ca_type, dod_ca_level, distribution_point, crl_urls, ocsp_urls,
                    file_path, file_format, last_updated, source_url,
                    is_valid, is_trusted, validation_errors, last_validated, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                ca_info.subject_dn, ca_info.issuer_dn, ca_info.serial_number,
                ca_info.fingerprint_sha256, ca_info.fingerprint_sha1,
                ca_info.not_before.isoformat(), ca_info.not_after.isoformat(),
                ca_info.key_algorithm, ca_info.key_size, ca_info.signature_algorithm,
                ca_info.ca_type, ca_info.dod_ca_level, ca_info.distribution_point,
                json.dumps(ca_info.crl_urls), json.dumps(ca_info.ocsp_urls),
                ca_info.file_path, ca_info.file_format, ca_info.last_updated.isoformat(),
                ca_info.source_url, ca_info.is_valid, ca_info.is_trusted,
                json.dumps(ca_info.validation_errors), ca_info.last_validated.isoformat(),
                datetime.now(timezone.utc).isoformat()
            ))
            conn.commit()
    
    def get_trusted_certificates(self, ca_type: str = None, 
                               include_invalid: bool = False) -> List[TrustedCAInfo]:
        """
        Get list of trusted certificates from store.
        
        Args:
            ca_type: Filter by CA type (ROOT, INTERMEDIATE, CROSS_SIGNED)
            include_invalid: Include certificates that failed validation
            
        Returns:
            List of TrustedCAInfo objects
        """
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            
            query = "SELECT * FROM trusted_cas WHERE is_trusted = 1"
            params = []
            
            if not include_invalid:
                query += " AND is_valid = 1"
            
            if ca_type:
                query += " AND ca_type = ?"
                params.append(ca_type)
            
            query += " ORDER BY ca_type, subject_dn"
            
            cursor = conn.execute(query, params)
            rows = cursor.fetchall()
            
            certificates = []
            for row in rows:
                ca_info = self._row_to_ca_info(row)
                certificates.append(ca_info)
            
            return certificates
    
    def _row_to_ca_info(self, row) -> TrustedCAInfo:
        """Convert database row to TrustedCAInfo object."""
        return TrustedCAInfo(
            subject_dn=row['subject_dn'],
            issuer_dn=row['issuer_dn'],
            serial_number=row['serial_number'],
            fingerprint_sha256=row['fingerprint_sha256'],
            fingerprint_sha1=row['fingerprint_sha1'],
            not_before=datetime.fromisoformat(row['not_before']),
            not_after=datetime.fromisoformat(row['not_after']),
            key_algorithm=row['key_algorithm'],
            key_size=row['key_size'],
            signature_algorithm=row['signature_algorithm'],
            ca_type=row['ca_type'],
            dod_ca_level=row['dod_ca_level'],
            distribution_point=row['distribution_point'],
            crl_urls=json.loads(row['crl_urls'] or '[]'),
            ocsp_urls=json.loads(row['ocsp_urls'] or '[]'),
            file_path=row['file_path'],
            file_format=row['file_format'],
            last_updated=datetime.fromisoformat(row['last_updated']),
            source_url=row['source_url'],
            is_valid=bool(row['is_valid']),
            is_trusted=bool(row['is_trusted']),
            validation_errors=json.loads(row['validation_errors'] or '[]'),
            last_validated=datetime.fromisoformat(row['last_validated'])
        )
    
    def load_certificate_files(self, directory_path: str) -> int:
        """
        Load certificate files from directory into trust store.
        
        Args:
            directory_path: Path to directory containing certificate files
            
        Returns:
            Number of certificates loaded
        """
        loaded_count = 0
        
        if not os.path.exists(directory_path):
            logger.error(f"Directory not found: {directory_path}")
            return 0
        
        for filename in os.listdir(directory_path):
            if filename.endswith(('.pem', '.crt', '.cer', '.der')):
                file_path = os.path.join(directory_path, filename)
                try:
                    with open(file_path, 'rb') as f:
                        cert_data = f.read()
                    
                    source_info = {
                        'source_url': f"file://{file_path}",
                        'distribution_point': 'local_file'
                    }
                    
                    self.add_certificate(cert_data, source_info)
                    loaded_count += 1
                    logger.debug(f"Loaded certificate from {filename}")
                    
                except Exception as e:
                    logger.warning(f"Failed to load certificate from {filename}: {e}")
        
        logger.info(f"Loaded {loaded_count} certificates from {directory_path}")
        return loaded_count
    
    def update_from_dod_pki(self) -> Dict[str, int]:
        """
        Update trust store with latest DoD PKI certificates.
        
        Returns:
            Dictionary with update statistics
        """
        stats = {
            'downloaded': 0,
            'updated': 0,
            'errors': 0,
            'skipped': 0
        }
        
        logger.info("Starting DoD PKI trust store update")
        
        # Try each distribution point
        for point_name, base_url in self.DOD_PKI_DISTRIBUTION_POINTS.items():
            try:
                logger.info(f"Checking distribution point: {point_name}")
                point_stats = self._update_from_distribution_point(base_url)
                
                for key in stats:
                    stats[key] += point_stats.get(key, 0)
                    
                # If we got certificates from this point, we can stop
                if point_stats.get('downloaded', 0) > 0:
                    break
                    
            except Exception as e:
                logger.warning(f"Failed to update from {point_name}: {e}")
                stats['errors'] += 1
        
        # Update last check time
        self._last_update_check = datetime.now(timezone.utc)
        
        logger.info(f"DoD PKI update completed: {stats}")
        return stats
    
    def _update_from_distribution_point(self, base_url: str) -> Dict[str, int]:
        """Update from specific distribution point."""
        stats = {'downloaded': 0, 'updated': 0, 'errors': 0, 'skipped': 0}
        
        # This is a simplified implementation
        # In practice, you would need to know the specific URLs for DoD certificates
        # or implement a discovery mechanism
        
        known_cert_urls = [
            f"{base_url}/dodrootca2.crt",
            f"{base_url}/dodrootca3.crt", 
            f"{base_url}/dodrootca4.crt",
            f"{base_url}/dodrootca5.crt",
            f"{base_url}/dodrootca6.crt"
        ]
        
        for cert_url in known_cert_urls:
            try:
                response = self._session.get(cert_url, timeout=30)
                response.raise_for_status()
                
                source_info = {
                    'source_url': cert_url,
                    'distribution_point': base_url
                }
                
                # Check if we already have this certificate
                cert_data = response.content
                cert_hash = hashlib.sha256(cert_data).hexdigest()
                
                if self._certificate_exists(cert_hash):
                    stats['skipped'] += 1
                    continue
                
                self.add_certificate(cert_data, source_info)
                stats['downloaded'] += 1
                stats['updated'] += 1
                
                logger.debug(f"Downloaded certificate from {cert_url}")
                
            except requests.RequestException as e:
                logger.warning(f"Failed to download from {cert_url}: {e}")
                stats['errors'] += 1
            except Exception as e:
                logger.error(f"Error processing certificate from {cert_url}: {e}")
                stats['errors'] += 1
        
        return stats
    
    def _certificate_exists(self, fingerprint_sha256: str) -> bool:
        """Check if certificate already exists in trust store."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                "SELECT COUNT(*) FROM trusted_cas WHERE fingerprint_sha256 = ?",
                (fingerprint_sha256,)
            )
            count = cursor.fetchone()[0]
            return count > 0
    
    def _start_auto_update_thread(self):
        """Start background thread for automatic updates."""
        def update_worker():
            while not self._shutdown_event.is_set():
                try:
                    # Check if update is needed
                    if (self._last_update_check is None or 
                        datetime.now(timezone.utc) - self._last_update_check > 
                        timedelta(hours=self.update_interval_hours)):
                        
                        logger.info("Starting scheduled trust store update")
                        self.update_from_dod_pki()
                    
                    # Wait for next check (check every hour, but only update based on interval)
                    self._shutdown_event.wait(3600)  # 1 hour
                    
                except Exception as e:
                    logger.error(f"Error in auto-update thread: {e}")
                    self._shutdown_event.wait(3600)
        
        self._update_thread = threading.Thread(target=update_worker, daemon=True)
        self._update_thread.start()
        logger.info("Auto-update thread started")
    
    def export_to_bundle(self, output_path: str, ca_type: str = None, 
                        format: str = 'PEM') -> int:
        """
        Export certificates to bundle file.
        
        Args:
            output_path: Output file path
            ca_type: Filter by CA type
            format: Output format (PEM or DER)
            
        Returns:
            Number of certificates exported
        """
        certificates = self.get_trusted_certificates(ca_type, include_invalid=False)
        
        if format.upper() == 'PEM':
            with open(output_path, 'w') as f:
                for ca_info in certificates:
                    # Load certificate file
                    with open(ca_info.file_path, 'rb') as cert_file:
                        cert_data = cert_file.read()
                    
                    # Convert to PEM if necessary
                    if ca_info.file_format == 'DER':
                        cert = x509.load_der_x509_certificate(cert_data)
                        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
                        f.write(cert_pem.decode('utf-8'))
                    else:
                        f.write(cert_data.decode('utf-8'))
                    f.write('\n')
        else:
            # For DER format, create a ZIP file with individual certificates
            with zipfile.ZipFile(output_path, 'w') as zf:
                for ca_info in certificates:
                    cert_filename = os.path.basename(ca_info.file_path)
                    zf.write(ca_info.file_path, cert_filename)
        
        logger.info(f"Exported {len(certificates)} certificates to {output_path}")
        return len(certificates)
    
    def get_trust_store_stats(self) -> Dict[str, Any]:
        """Get trust store statistics."""
        with sqlite3.connect(self.db_path) as conn:
            stats = {}
            
            # Count by type
            cursor = conn.execute(
                "SELECT ca_type, COUNT(*) FROM trusted_cas WHERE is_trusted = 1 GROUP BY ca_type"
            )
            type_counts = dict(cursor.fetchall())
            stats['certificates_by_type'] = type_counts
            
            # Total counts
            cursor = conn.execute("SELECT COUNT(*) FROM trusted_cas WHERE is_trusted = 1")
            stats['total_trusted'] = cursor.fetchone()[0]
            
            cursor = conn.execute("SELECT COUNT(*) FROM trusted_cas WHERE is_valid = 0")
            stats['invalid_certificates'] = cursor.fetchone()[0]
            
            # Expiration information
            current_time = datetime.now(timezone.utc)
            thirty_days = current_time + timedelta(days=30)
            
            cursor = conn.execute(
                "SELECT COUNT(*) FROM trusted_cas WHERE is_trusted = 1 AND not_after < ?",
                (thirty_days.isoformat(),)
            )
            stats['expiring_soon'] = cursor.fetchone()[0]
            
            cursor = conn.execute(
                "SELECT COUNT(*) FROM trusted_cas WHERE is_trusted = 1 AND not_after < ?",
                (current_time.isoformat(),)
            )
            stats['expired'] = cursor.fetchone()[0]
            
            # Last update
            stats['last_update_check'] = self._last_update_check.isoformat() if self._last_update_check else None
            stats['auto_update_enabled'] = self.enable_auto_update
            stats['update_interval_hours'] = self.update_interval_hours
            
            return stats
    
    def cleanup(self):
        """Cleanup resources and stop background threads."""
        if self._update_thread and self._update_thread.is_alive():
            self._shutdown_event.set()
            self._update_thread.join(timeout=5)
        
        if hasattr(self, '_session'):
            self._session.close()
        
        logger.info("Trust store manager cleanup completed")
    
    def __del__(self):
        """Cleanup when object is destroyed."""
        self.cleanup()


# Example usage
def main():
    """Example usage of trust store manager."""
    manager = TrustStoreManager(enable_auto_update=False)
    
    # Get statistics
    stats = manager.get_trust_store_stats()
    print(f"Trust store statistics: {stats}")
    
    # Load certificates from directory if available
    ca_dir = "/etc/ssl/certs"
    if os.path.exists(ca_dir):
        loaded = manager.load_certificate_files(ca_dir)
        print(f"Loaded {loaded} certificates from {ca_dir}")
    
    # Get trusted certificates
    trusted_certs = manager.get_trusted_certificates(ca_type="ROOT")
    print(f"Found {len(trusted_certs)} trusted root certificates")
    
    for cert in trusted_certs[:3]:  # Show first 3
        print(f"  - {cert.subject_dn}")
        print(f"    Valid until: {cert.not_after}")
        print(f"    Key: {cert.key_algorithm} {cert.key_size} bits")
    
    manager.cleanup()


if __name__ == "__main__":
    main()