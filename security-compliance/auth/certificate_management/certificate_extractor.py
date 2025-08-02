#!/usr/bin/env python3
"""
Enhanced Certificate Extraction Module for CAC/PIV Smart Cards

This module provides comprehensive certificate extraction capabilities from CAC/PIV
smart cards using PKCS#11 interface with enhanced metadata extraction and DoD-specific
certificate handling.
"""

import os
import logging
import hashlib
from typing import Optional, Dict, List, Tuple, Union, Any
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
import PyKCS11
from PyKCS11 import PyKCS11Error
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.x509.oid import ExtensionOID, NameOID
import threading
import time

logger = logging.getLogger(__name__)


class CertificateType(Enum):
    """Types of certificates found on CAC/PIV cards."""
    AUTHENTICATION = "authentication"
    SIGNING = "signing"
    ENCRYPTION = "encryption"
    PIV_AUTH = "piv_auth"
    CARD_AUTH = "card_auth"
    CONTENT_SIGNING = "content_signing"
    UNKNOWN = "unknown"


class ExtractionMethod(Enum):
    """Methods for certificate extraction."""
    PKCS11_STANDARD = "pkcs11_standard"
    PKCS11_ENHANCED = "pkcs11_enhanced"
    PIV_APPLET = "piv_applet"
    CAC_APPLET = "cac_applet"


@dataclass
class CertificateSlotInfo:
    """Information about certificate slot on smart card."""
    slot_id: int
    object_handle: int
    label: str
    id: bytes
    certificate_type: CertificateType
    key_usage: List[str] = field(default_factory=list)
    subject_dn: str = ""
    issuer_dn: str = ""
    serial_number: str = ""
    fingerprint: str = ""


@dataclass
class CertificateInfo:
    """Comprehensive certificate information with CAC/PIV specific metadata."""
    certificate: x509.Certificate
    slot_info: CertificateSlotInfo
    certificate_type: CertificateType
    extraction_method: ExtractionMethod
    raw_der_data: bytes
    fingerprint_sha256: str
    fingerprint_sha1: str
    
    # DoD-specific fields
    edipi: Optional[str] = None
    dod_id: Optional[str] = None
    agency_code: Optional[str] = None
    piv_guid: Optional[str] = None
    fasc_n: Optional[str] = None
    
    # Certificate metadata
    subject_dn: str = ""
    issuer_dn: str = ""
    serial_number: str = ""
    not_before: Optional[datetime] = None
    not_after: Optional[datetime] = None
    
    # Key information
    public_key_algorithm: str = ""
    public_key_size: int = 0
    signature_algorithm: str = ""
    
    # Extensions and policies
    key_usage: List[str] = field(default_factory=list)
    extended_key_usage: List[str] = field(default_factory=list)
    certificate_policies: List[str] = field(default_factory=list)
    subject_alternative_names: List[str] = field(default_factory=list)
    
    # CRL and OCSP information
    crl_distribution_points: List[str] = field(default_factory=list)
    ocsp_responders: List[str] = field(default_factory=list)
    
    # Validation metadata
    is_self_signed: bool = False
    is_ca_certificate: bool = False
    path_length_constraint: Optional[int] = None
    
    # Extraction metadata
    extraction_time: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    extraction_errors: List[str] = field(default_factory=list)
    extraction_warnings: List[str] = field(default_factory=list)


class CertificateExtractor:
    """
    Enhanced certificate extractor for CAC/PIV smart cards.
    
    Provides comprehensive certificate extraction with DoD-specific metadata
    parsing and enhanced error handling.
    """
    
    # DoD certificate object identifiers and labels
    DOD_CERT_LABELS = {
        "id_authentication": [
            "Certificate for PIV Authentication",
            "PIV AUTH",
            "Authentication Certificate",
            "Email Certificate",
            "ID Certificate"
        ],
        "signing": [
            "Certificate for Digital Signature",
            "Digital Signature Certificate", 
            "Signature Certificate",
            "Content Signing Certificate"
        ],
        "encryption": [
            "Certificate for Key Management",
            "Key Management Certificate",
            "Encryption Certificate"
        ],
        "card_auth": [
            "Certificate for Card Authentication",
            "Card Authentication Certificate",
            "CARD AUTH"
        ]
    }
    
    # DoD-specific OIDs
    DOD_OIDS = {
        'piv_auth_cert': '2.16.840.1.101.3.7.2.1.1',
        'card_auth_cert': '2.16.840.1.101.3.7.2.5.0',
        'digital_sig_cert': '2.16.840.1.101.3.7.2.1.2',
        'key_mgmt_cert': '2.16.840.1.101.3.7.2.1.3',
        'fasc_n': '2.16.840.1.101.3.6.6',
        'edipi': '2.16.840.1.101.3.6.9.1',
        'dod_pki_med_hw': '2.16.840.1.101.3.2.1.3.7',
        'dod_pki_med_hw_piv_auth': '2.16.840.1.101.3.2.1.3.13'
    }
    
    def __init__(self, pkcs11_library_path: str = None, enable_enhanced_extraction: bool = True):
        """
        Initialize certificate extractor.
        
        Args:
            pkcs11_library_path: Path to PKCS#11 library
            enable_enhanced_extraction: Enable enhanced metadata extraction
        """
        self.pkcs11_library_path = pkcs11_library_path
        self.enable_enhanced_extraction = enable_enhanced_extraction
        self.pkcs11 = None
        self.session = None
        self._extraction_cache = {}
        self._cache_lock = threading.Lock()
        
        # Initialize PKCS#11
        self._initialize_pkcs11()
        
        logger.info("Certificate extractor initialized")
    
    def _initialize_pkcs11(self):
        """Initialize PKCS#11 library."""
        try:
            if not self.pkcs11_library_path:
                self.pkcs11_library_path = self._detect_pkcs11_library()
            
            self.pkcs11 = PyKCS11.PyKCS11Lib()
            self.pkcs11.load(self.pkcs11_library_path)
            logger.info(f"PKCS#11 library loaded: {self.pkcs11_library_path}")
            
        except Exception as e:
            logger.error(f"Failed to initialize PKCS#11: {e}")
            raise
    
    def _detect_pkcs11_library(self) -> str:
        """Auto-detect PKCS#11 library."""
        common_paths = [
            # Windows
            "C:\\Windows\\System32\\opensc-pkcs11.dll",
            "C:\\Program Files\\OpenSC Project\\OpenSC\\pkcs11\\opensc-pkcs11.dll",
            "C:\\Program Files (x86)\\ActivIdentity\\ActivClient\\acpkcs211.dll",
            # Linux
            "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so",
            "/usr/lib/opensc-pkcs11.so",
            "/usr/local/lib/opensc-pkcs11.so",
            "/usr/lib/pkcs11/opensc-pkcs11.so",
            # macOS
            "/usr/local/lib/opensc-pkcs11.so",
            "/opt/homebrew/lib/opensc-pkcs11.so",
            "/Library/OpenSC/lib/opensc-pkcs11.so"
        ]
        
        for path in common_paths:
            if os.path.exists(path):
                logger.info(f"Auto-detected PKCS#11 library: {path}")
                return path
        
        raise FileNotFoundError(
            "PKCS#11 library not found. Please install OpenSC, ActivClient, "
            "or specify the library path manually."
        )
    
    def get_available_slots(self) -> List[Dict[str, Any]]:
        """
        Get list of available smart card slots with detailed information.
        
        Returns:
            List of slot information dictionaries
        """
        slots_info = []
        
        try:
            # Get slots with tokens present
            slots = self.pkcs11.getSlotList(tokenPresent=True)
            
            for slot_id in slots:
                try:
                    slot_info = self.pkcs11.getSlotInfo(slot_id)
                    token_info = self.pkcs11.getTokenInfo(slot_id)
                    
                    slots_info.append({
                        'slot_id': slot_id,
                        'slot_description': slot_info.slotDescription.strip(),
                        'token_label': token_info.label.strip(),
                        'token_serial': token_info.serialNumber.strip(),
                        'token_model': token_info.model.strip(),
                        'token_manufacturer': token_info.manufacturerID.strip(),
                        'token_flags': token_info.flags,
                        'has_token': True
                    })
                    
                except PyKCS11Error as e:
                    logger.warning(f"Error getting info for slot {slot_id}: {e}")
                    
        except PyKCS11Error as e:
            logger.error(f"Error listing slots: {e}")
        
        logger.info(f"Found {len(slots_info)} slots with tokens")
        return slots_info
    
    def open_session(self, slot_id: int = None) -> bool:
        """
        Open session with smart card.
        
        Args:
            slot_id: Specific slot ID (auto-detect if None)
            
        Returns:
            True if session opened successfully
        """
        try:
            if slot_id is None:
                available_slots = self.get_available_slots()
                if not available_slots:
                    logger.error("No smart cards detected")
                    return False
                slot_id = available_slots[0]['slot_id']
            
            self.session = self.pkcs11.openSession(slot_id)
            logger.info(f"Session opened with slot {slot_id}")
            return True
            
        except PyKCS11Error as e:
            logger.error(f"Failed to open session: {e}")
            return False
    
    def extract_all_certificates(self, slot_id: int = None, 
                               include_metadata: bool = True) -> List[CertificateInfo]:
        """
        Extract all certificates from smart card with comprehensive metadata.
        
        Args:
            slot_id: Specific slot ID (auto-detect if None)
            include_metadata: Whether to extract detailed metadata
            
        Returns:
            List of CertificateInfo objects
        """
        certificates = []
        
        # Open session if not already open
        if not self.session:
            if not self.open_session(slot_id):
                return certificates
        
        try:
            # Find all certificate objects
            cert_objects = self.session.findObjects([
                (PyKCS11.CKA_CLASS, PyKCS11.CKO_CERTIFICATE)
            ])
            
            logger.info(f"Found {len(cert_objects)} certificate objects")
            
            for cert_obj in cert_objects:
                try:
                    cert_info = self._extract_certificate_from_object(
                        cert_obj, include_metadata
                    )
                    if cert_info:
                        certificates.append(cert_info)
                        
                except Exception as e:
                    logger.warning(f"Failed to extract certificate from object {cert_obj}: {e}")
                    
        except PyKCS11Error as e:
            logger.error(f"Error finding certificate objects: {e}")
        
        # Sort certificates by type priority
        certificates.sort(key=lambda x: self._get_cert_type_priority(x.certificate_type))
        
        logger.info(f"Successfully extracted {len(certificates)} certificates")
        return certificates
    
    def _extract_certificate_from_object(self, cert_obj: int, 
                                       include_metadata: bool = True) -> Optional[CertificateInfo]:
        """Extract certificate information from PKCS#11 object."""
        try:
            # Get certificate attributes
            attributes = self.session.getAttributeValue(cert_obj, [
                PyKCS11.CKA_VALUE,
                PyKCS11.CKA_LABEL,
                PyKCS11.CKA_ID,
                PyKCS11.CKA_SUBJECT,
                PyKCS11.CKA_ISSUER
            ])
            
            cert_der = bytes(attributes[0])
            label = attributes[1] if attributes[1] else ""
            cert_id = bytes(attributes[2]) if attributes[2] else b""
            
            # Parse certificate
            certificate = x509.load_der_x509_certificate(cert_der)
            
            # Determine certificate type
            cert_type = self._determine_certificate_type(certificate, label)
            
            # Create slot information
            slot_info = CertificateSlotInfo(
                slot_id=self.session.getSessionInfo().slotID,
                object_handle=cert_obj,
                label=label,
                id=cert_id,
                certificate_type=cert_type,
                subject_dn=certificate.subject.rfc4514_string(),
                issuer_dn=certificate.issuer.rfc4514_string(),
                serial_number=str(certificate.serial_number),
                fingerprint=hashlib.sha256(cert_der).hexdigest()
            )
            
            # Create certificate info
            cert_info = CertificateInfo(
                certificate=certificate,
                slot_info=slot_info,
                certificate_type=cert_type,
                extraction_method=ExtractionMethod.PKCS11_ENHANCED,
                raw_der_data=cert_der,
                fingerprint_sha256=hashlib.sha256(cert_der).hexdigest(),
                fingerprint_sha1=hashlib.sha1(cert_der).hexdigest(),
                subject_dn=certificate.subject.rfc4514_string(),
                issuer_dn=certificate.issuer.rfc4514_string(),
                serial_number=str(certificate.serial_number),
                not_before=certificate.not_valid_before,
                not_after=certificate.not_valid_after
            )
            
            # Extract enhanced metadata if requested
            if include_metadata:
                self._extract_enhanced_metadata(cert_info)
            
            return cert_info
            
        except Exception as e:
            logger.error(f"Failed to extract certificate from object {cert_obj}: {e}")
            return None
    
    def _determine_certificate_type(self, certificate: x509.Certificate, 
                                  label: str) -> CertificateType:
        """Determine certificate type based on various indicators."""
        
        # Check label first
        label_lower = label.lower()
        for cert_type, labels in self.DOD_CERT_LABELS.items():
            if any(l.lower() in label_lower for l in labels):
                if cert_type == "id_authentication":
                    return CertificateType.AUTHENTICATION
                elif cert_type == "signing":
                    return CertificateType.SIGNING
                elif cert_type == "encryption":
                    return CertificateType.ENCRYPTION
                elif cert_type == "card_auth":
                    return CertificateType.CARD_AUTH
        
        # Check certificate policies
        try:
            policies_ext = certificate.extensions.get_extension_for_oid(
                ExtensionOID.CERTIFICATE_POLICIES
            )
            
            for policy in policies_ext.value:
                policy_oid = policy.policy_identifier.dotted_string
                
                if policy_oid == self.DOD_OIDS['piv_auth_cert']:
                    return CertificateType.PIV_AUTH
                elif policy_oid == self.DOD_OIDS['card_auth_cert']:
                    return CertificateType.CARD_AUTH
                elif policy_oid == self.DOD_OIDS['digital_sig_cert']:
                    return CertificateType.SIGNING
                elif policy_oid == self.DOD_OIDS['key_mgmt_cert']:
                    return CertificateType.ENCRYPTION
                    
        except x509.ExtensionNotFound:
            pass
        
        # Check key usage
        try:
            key_usage_ext = certificate.extensions.get_extension_for_oid(
                ExtensionOID.KEY_USAGE
            )
            key_usage = key_usage_ext.value
            
            if key_usage.digital_signature and not key_usage.key_encipherment:
                return CertificateType.SIGNING
            elif key_usage.key_encipherment or key_usage.data_encipherment:
                return CertificateType.ENCRYPTION
            elif key_usage.digital_signature:
                return CertificateType.AUTHENTICATION
                
        except x509.ExtensionNotFound:
            pass
        
        # Check extended key usage
        try:
            ext_key_usage_ext = certificate.extensions.get_extension_for_oid(
                ExtensionOID.EXTENDED_KEY_USAGE
            )
            
            client_auth_oid = x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH
            if client_auth_oid in ext_key_usage_ext.value:
                return CertificateType.AUTHENTICATION
                
        except x509.ExtensionNotFound:
            pass
        
        return CertificateType.UNKNOWN
    
    def _extract_enhanced_metadata(self, cert_info: CertificateInfo):
        """Extract enhanced DoD-specific metadata from certificate."""
        certificate = cert_info.certificate
        
        try:
            # Extract key usage
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
                
                cert_info.key_usage = usage_flags
                cert_info.slot_info.key_usage = usage_flags
                
            except x509.ExtensionNotFound:
                pass
            
            # Extract extended key usage
            try:
                ext_key_usage_ext = certificate.extensions.get_extension_for_oid(
                    ExtensionOID.EXTENDED_KEY_USAGE
                )
                cert_info.extended_key_usage = [
                    usage.dotted_string for usage in ext_key_usage_ext.value
                ]
            except x509.ExtensionNotFound:
                pass
            
            # Extract certificate policies
            try:
                policies_ext = certificate.extensions.get_extension_for_oid(
                    ExtensionOID.CERTIFICATE_POLICIES
                )
                cert_info.certificate_policies = [
                    policy.policy_identifier.dotted_string 
                    for policy in policies_ext.value
                ]
            except x509.ExtensionNotFound:
                pass
            
            # Extract Subject Alternative Name and DoD-specific identifiers
            try:
                san_ext = certificate.extensions.get_extension_for_oid(
                    ExtensionOID.SUBJECT_ALTERNATIVE_NAME
                )
                
                san_list = []
                for name in san_ext.value:
                    if isinstance(name, x509.RFC822Name):
                        san_list.append(f"email:{name.value}")
                    elif isinstance(name, x509.OtherName):
                        oid = name.type_id.dotted_string
                        san_list.append(f"othername:{oid}")
                        
                        # Extract DoD-specific identifiers
                        if oid == self.DOD_OIDS.get('edipi'):
                            try:
                                cert_info.edipi = name.value.decode('utf-8')
                            except:
                                pass
                        elif oid == self.DOD_OIDS.get('fasc_n'):
                            try:
                                cert_info.fasc_n = name.value.hex()
                            except:
                                pass
                    elif isinstance(name, x509.DirectoryName):
                        san_list.append(f"dirname:{name.value.rfc4514_string()}")
                    elif isinstance(name, x509.UniformResourceIdentifier):
                        san_list.append(f"uri:{name.value}")
                
                cert_info.subject_alternative_names = san_list
                
            except x509.ExtensionNotFound:
                pass
            
            # Extract CRL distribution points
            try:
                crl_ext = certificate.extensions.get_extension_for_oid(
                    ExtensionOID.CRL_DISTRIBUTION_POINTS
                )
                
                crl_urls = []
                for dist_point in crl_ext.value:
                    if dist_point.full_name:
                        for name in dist_point.full_name:
                            if isinstance(name, x509.UniformResourceIdentifier):
                                crl_urls.append(name.value)
                
                cert_info.crl_distribution_points = crl_urls
                
            except x509.ExtensionNotFound:
                pass
            
            # Extract OCSP responders
            try:
                aia_ext = certificate.extensions.get_extension_for_oid(
                    ExtensionOID.AUTHORITY_INFORMATION_ACCESS
                )
                
                ocsp_urls = []
                for access_desc in aia_ext.value:
                    if access_desc.access_method == x509.oid.AuthorityInformationAccessOID.OCSP:
                        if isinstance(access_desc.access_location, x509.UniformResourceIdentifier):
                            ocsp_urls.append(access_desc.access_location.value)
                
                cert_info.ocsp_responders = ocsp_urls
                
            except x509.ExtensionNotFound:
                pass
            
            # Extract public key information
            public_key = certificate.public_key()
            
            if hasattr(public_key, 'key_size'):
                cert_info.public_key_size = public_key.key_size
            
            if hasattr(public_key, 'algorithm'):
                cert_info.public_key_algorithm = public_key.algorithm.name
            else:
                cert_info.public_key_algorithm = type(public_key).__name__
            
            # Extract signature algorithm
            cert_info.signature_algorithm = certificate.signature_algorithm_oid.dotted_string
            
            # Check if it's a CA certificate
            try:
                basic_constraints_ext = certificate.extensions.get_extension_for_oid(
                    ExtensionOID.BASIC_CONSTRAINTS
                )
                cert_info.is_ca_certificate = basic_constraints_ext.value.ca
                cert_info.path_length_constraint = basic_constraints_ext.value.path_length
            except x509.ExtensionNotFound:
                cert_info.is_ca_certificate = False
            
            # Check if self-signed
            cert_info.is_self_signed = certificate.issuer == certificate.subject
            
            # Extract additional DoD identifiers from subject DN
            self._extract_dod_identifiers_from_dn(cert_info)
            
        except Exception as e:
            error_msg = f"Error extracting enhanced metadata: {e}"
            cert_info.extraction_errors.append(error_msg)
            logger.warning(error_msg)
    
    def _extract_dod_identifiers_from_dn(self, cert_info: CertificateInfo):
        """Extract DoD-specific identifiers from subject DN."""
        try:
            subject = cert_info.certificate.subject
            
            # Look for agency codes, DOD ID, etc. in subject attributes
            for attribute in subject:
                if attribute.oid == NameOID.ORGANIZATIONAL_UNIT_NAME:
                    value = attribute.value.upper()
                    
                    # Check for DOD ID patterns
                    if value.startswith('DOD.'):
                        cert_info.dod_id = value
                    elif value.startswith('USA.'):
                        cert_info.agency_code = value
                    elif len(value) == 10 and value.isdigit():
                        # Likely EDIPI in OU field
                        if not cert_info.edipi:
                            cert_info.edipi = value
                            
        except Exception as e:
            warning_msg = f"Error extracting DoD identifiers from DN: {e}"
            cert_info.extraction_warnings.append(warning_msg)
            logger.debug(warning_msg)
    
    def _get_cert_type_priority(self, cert_type: CertificateType) -> int:
        """Get priority for certificate type sorting."""
        priority_map = {
            CertificateType.AUTHENTICATION: 1,
            CertificateType.PIV_AUTH: 2,
            CertificateType.SIGNING: 3,
            CertificateType.CONTENT_SIGNING: 4,
            CertificateType.ENCRYPTION: 5,
            CertificateType.CARD_AUTH: 6,
            CertificateType.UNKNOWN: 99
        }
        return priority_map.get(cert_type, 99)
    
    def extract_certificate_by_type(self, cert_type: CertificateType, 
                                   slot_id: int = None) -> Optional[CertificateInfo]:
        """
        Extract specific certificate type from smart card.
        
        Args:
            cert_type: Type of certificate to extract
            slot_id: Specific slot ID (auto-detect if None)
            
        Returns:
            CertificateInfo object or None if not found
        """
        certificates = self.extract_all_certificates(slot_id, include_metadata=True)
        
        for cert_info in certificates:
            if cert_info.certificate_type == cert_type:
                return cert_info
        
        logger.warning(f"Certificate of type {cert_type} not found")
        return None
    
    def get_certificate_summary(self, cert_info: CertificateInfo) -> Dict[str, Any]:
        """
        Get summary information about a certificate.
        
        Args:
            cert_info: Certificate information object
            
        Returns:
            Dictionary with certificate summary
        """
        return {
            'type': cert_info.certificate_type.value,
            'subject': cert_info.subject_dn,
            'issuer': cert_info.issuer_dn,
            'serial_number': cert_info.serial_number,
            'fingerprint_sha256': cert_info.fingerprint_sha256[:16] + "...",
            'valid_from': cert_info.not_before.isoformat() if cert_info.not_before else None,
            'valid_until': cert_info.not_after.isoformat() if cert_info.not_after else None,
            'edipi': cert_info.edipi,
            'key_size': cert_info.public_key_size,
            'key_algorithm': cert_info.public_key_algorithm,
            'key_usage': cert_info.key_usage,
            'is_ca': cert_info.is_ca_certificate,
            'extraction_method': cert_info.extraction_method.value,
            'slot_label': cert_info.slot_info.label
        }
    
    def close_session(self):
        """Close PKCS#11 session and cleanup."""
        if self.session:
            try:
                self.session.closeSession()
                logger.info("Session closed successfully")
            except PyKCS11Error as e:
                logger.warning(f"Error closing session: {e}")
            finally:
                self.session = None
    
    def __del__(self):
        """Cleanup when object is destroyed."""
        self.close_session()


# Example usage and testing functions
def main():
    """Example usage of certificate extractor."""
    try:
        # Initialize extractor
        extractor = CertificateExtractor(enable_enhanced_extraction=True)
        
        # Get available slots
        slots = extractor.get_available_slots()
        print(f"Available slots: {len(slots)}")
        for slot in slots:
            print(f"  Slot {slot['slot_id']}: {slot['token_label']}")
        
        if not slots:
            print("No smart cards detected")
            return
        
        # Extract all certificates
        certificates = extractor.extract_all_certificates(include_metadata=True)
        print(f"\nExtracted {len(certificates)} certificates:")
        
        for i, cert_info in enumerate(certificates, 1):
            summary = extractor.get_certificate_summary(cert_info)
            print(f"\nCertificate {i}:")
            print(f"  Type: {summary['type']}")
            print(f"  Subject: {summary['subject']}")
            print(f"  EDIPI: {summary['edipi']}")
            print(f"  Valid until: {summary['valid_until']}")
            print(f"  Key: {summary['key_algorithm']} {summary['key_size']} bits")
            
        # Clean up
        extractor.close_session()
        
    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    main()