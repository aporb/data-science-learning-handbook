#!/usr/bin/env python3
"""
Advanced Certificate Parser and Metadata Extractor

This module provides comprehensive parsing and metadata extraction capabilities
for X.509 certificates with special focus on DoD PKI and CAC/PIV certificates.
"""

import os
import logging
import re
import hashlib
from typing import Optional, Dict, List, Tuple, Union, Any, Set
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa, ed25519, ed448
from cryptography.x509.oid import ExtensionOID, NameOID, SignatureAlgorithmOID
import ipaddress
import base64

logger = logging.getLogger(__name__)


class CertificateCategory(Enum):
    """Certificate categories based on usage and policies."""
    DOD_ROOT_CA = "dod_root_ca"
    DOD_INTERMEDIATE_CA = "dod_intermediate_ca"
    DOD_END_ENTITY = "dod_end_entity"
    PIV_AUTHENTICATION = "piv_authentication"
    PIV_CARD_AUTH = "piv_card_auth"
    PIV_SIGNING = "piv_signing"
    PIV_ENCRYPTION = "piv_encryption"
    CAC_AUTHENTICATION = "cac_authentication"
    CAC_EMAIL = "cac_email"
    FEDERAL_BRIDGE = "federal_bridge"
    COMMERCIAL_CA = "commercial_ca"
    SELF_SIGNED = "self_signed"
    UNKNOWN = "unknown"


class AssuranceLevel(Enum):
    """Certificate assurance levels."""
    NONE = "none"
    BASIC = "basic"
    MEDIUM_HARDWARE = "medium_hardware"
    MEDIUM_SOFTWARE = "medium_software"
    HIGH = "high"
    UNKNOWN = "unknown"


@dataclass
class KeyInformation:
    """Detailed public key information."""
    algorithm: str
    size_bits: int
    curve_name: Optional[str] = None
    public_key_info: Dict[str, Any] = field(default_factory=dict)
    
    # Key strength assessment
    strength_bits: int = 0
    is_weak: bool = False
    weakness_reasons: List[str] = field(default_factory=list)


@dataclass
class ExtensionInfo:
    """Information about a certificate extension."""
    oid: str
    name: str
    critical: bool
    value_summary: str
    parsed_value: Any = None
    raw_value: bytes = b""


@dataclass
class SubjectAlternativeName:
    """Parsed Subject Alternative Name entry."""
    type: str  # email, dns, uri, ip, othername, dirname
    value: str
    raw_value: Any = None


@dataclass
class PolicyInformation:
    """Certificate policy information."""
    oid: str
    policy_name: str
    policy_type: str  # DOD, COMMERCIAL, UNKNOWN
    assurance_level: AssuranceLevel = AssuranceLevel.UNKNOWN
    hardware_required: bool = False
    qualifiers: List[str] = field(default_factory=list)


@dataclass
class DoDIdentifiers:
    """DoD-specific identifiers extracted from certificates."""
    edipi: Optional[str] = None
    dod_id: Optional[str] = None
    agency_code: Optional[str] = None
    piv_guid: Optional[str] = None
    fasc_n: Optional[str] = None
    uuid: Optional[str] = None
    card_id: Optional[str] = None
    org_affiliation: Optional[str] = None


@dataclass
class CertificateMetadata:
    """Comprehensive certificate metadata."""
    # Basic certificate information
    version: int
    serial_number: str
    subject_dn: str
    issuer_dn: str
    not_before: datetime
    not_after: datetime
    signature_algorithm: str
    
    # Key information
    key_info: KeyInformation
    
    # Certificate categorization
    category: CertificateCategory
    assurance_level: AssuranceLevel
    is_ca_certificate: bool = False
    is_self_signed: bool = False
    
    # Subject and issuer details
    subject_components: Dict[str, List[str]] = field(default_factory=dict)
    issuer_components: Dict[str, List[str]] = field(default_factory=dict)
    
    # Extensions
    extensions: List[ExtensionInfo] = field(default_factory=list)
    subject_alternative_names: List[SubjectAlternativeName] = field(default_factory=list)
    
    # Policy information
    certificate_policies: List[PolicyInformation] = field(default_factory=list)
    
    # Key usage information
    key_usage: List[str] = field(default_factory=list)
    extended_key_usage: List[str] = field(default_factory=list)
    
    # DoD-specific information
    dod_identifiers: DoDIdentifiers = field(default_factory=DoDIdentifiers)
    
    # CRL and OCSP information
    crl_distribution_points: List[str] = field(default_factory=list)
    ocsp_responders: List[str] = field(default_factory=list)
    ca_issuers: List[str] = field(default_factory=list)
    
    # Security assessment
    security_warnings: List[str] = field(default_factory=list)
    compliance_notes: List[str] = field(default_factory=list)
    
    # Fingerprints and identifiers
    fingerprint_sha1: str = ""
    fingerprint_sha256: str = ""
    fingerprint_md5: str = ""
    subject_key_identifier: Optional[str] = None
    authority_key_identifier: Optional[str] = None
    
    # Additional metadata
    parsing_errors: List[str] = field(default_factory=list)
    parsing_warnings: List[str] = field(default_factory=list)
    parsed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class CertificateParser:
    """
    Advanced certificate parser with DoD PKI expertise.
    
    Provides comprehensive parsing and metadata extraction from X.509 certificates
    with special handling for DoD PKI, CAC, and PIV certificates.
    """
    
    # DoD Certificate Policy OIDs and their metadata
    DOD_CERTIFICATE_POLICIES = {
        '2.16.840.1.101.3.2.1.3.1': {
            'name': 'DoD Basic',
            'type': 'DOD',
            'assurance_level': AssuranceLevel.BASIC,
            'hardware_required': False
        },
        '2.16.840.1.101.3.2.1.3.6': {
            'name': 'DoD Medium Software',
            'type': 'DOD',
            'assurance_level': AssuranceLevel.MEDIUM_SOFTWARE,
            'hardware_required': False
        },
        '2.16.840.1.101.3.2.1.3.7': {
            'name': 'DoD Medium Hardware',
            'type': 'DOD',
            'assurance_level': AssuranceLevel.MEDIUM_HARDWARE,
            'hardware_required': True
        },
        '2.16.840.1.101.3.2.1.3.13': {
            'name': 'DoD Medium Hardware PIV-Auth',
            'type': 'DOD',
            'assurance_level': AssuranceLevel.MEDIUM_HARDWARE,
            'hardware_required': True
        },
        '2.16.840.1.101.3.2.1.3.15': {
            'name': 'DoD Medium CBP',
            'type': 'DOD',
            'assurance_level': AssuranceLevel.MEDIUM_HARDWARE,
            'hardware_required': True
        },
        '2.16.840.1.101.3.2.1.3.16': {
            'name': 'DoD High Hardware',
            'type': 'DOD',
            'assurance_level': AssuranceLevel.HIGH,
            'hardware_required': True
        }
    }
    
    # PIV and CAC specific OIDs
    PIV_CAC_OIDS = {
        '2.16.840.1.101.3.6.6': 'FASC-N',
        '2.16.840.1.101.3.6.9.1': 'EDIPI',
        '2.16.840.1.101.3.6.9.2': 'PIV_GUID',
        '2.16.840.1.101.3.7.2.1.1': 'PIV_AUTH_CERT',
        '2.16.840.1.101.3.7.2.5.0': 'CARD_AUTH_CERT',
        '2.16.840.1.101.3.7.2.1.2': 'DIGITAL_SIG_CERT',
        '2.16.840.1.101.3.7.2.1.3': 'KEY_MGMT_CERT'
    }
    
    # Common DoD organizational patterns
    DOD_ORG_PATTERNS = {
        r'\.MIL$': 'Military',
        r'\.ARMY\.MIL$': 'US Army',
        r'\.NAVY\.MIL$': 'US Navy',
        r'\.AF\.MIL$': 'US Air Force',
        r'\.MARINES\.MIL$': 'US Marine Corps',
        r'\.USCG\.MIL$': 'US Coast Guard',
        r'\.OSD\.MIL$': 'Office of the Secretary of Defense',
        r'\.DISA\.MIL$': 'Defense Information Systems Agency'
    }
    
    def __init__(self, enable_enhanced_parsing: bool = True):
        """
        Initialize certificate parser.
        
        Args:
            enable_enhanced_parsing: Enable detailed DoD-specific parsing
        """
        self.enable_enhanced_parsing = enable_enhanced_parsing
        
        # OID to name mappings for extensions
        self.extension_names = {
            ExtensionOID.SUBJECT_KEY_IDENTIFIER: "Subject Key Identifier",
            ExtensionOID.KEY_USAGE: "Key Usage",
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME: "Subject Alternative Name",
            ExtensionOID.ISSUER_ALTERNATIVE_NAME: "Issuer Alternative Name",
            ExtensionOID.BASIC_CONSTRAINTS: "Basic Constraints",
            ExtensionOID.CRL_DISTRIBUTION_POINTS: "CRL Distribution Points",
            ExtensionOID.CERTIFICATE_POLICIES: "Certificate Policies",
            ExtensionOID.AUTHORITY_KEY_IDENTIFIER: "Authority Key Identifier",
            ExtensionOID.EXTENDED_KEY_USAGE: "Extended Key Usage",
            ExtensionOID.AUTHORITY_INFORMATION_ACCESS: "Authority Information Access",
            ExtensionOID.POLICY_CONSTRAINTS: "Policy Constraints",
            ExtensionOID.NAME_CONSTRAINTS: "Name Constraints",
            ExtensionOID.POLICY_MAPPINGS: "Policy Mappings",
            ExtensionOID.INHIBIT_ANY_POLICY: "Inhibit Any Policy"
        }
        
        logger.debug("Certificate parser initialized")
    
    def parse_certificate(self, certificate: x509.Certificate) -> CertificateMetadata:
        """
        Parse certificate and extract comprehensive metadata.
        
        Args:
            certificate: X.509 certificate to parse
            
        Returns:
            CertificateMetadata with extracted information
        """
        try:
            # Initialize metadata
            metadata = CertificateMetadata(
                version=certificate.version.value,
                serial_number=str(certificate.serial_number),
                subject_dn=certificate.subject.rfc4514_string(),
                issuer_dn=certificate.issuer.rfc4514_string(),
                not_before=certificate.not_valid_before,
                not_after=certificate.not_valid_after,
                signature_algorithm=certificate.signature_algorithm_oid._name or 
                                  certificate.signature_algorithm_oid.dotted_string,
                key_info=self._extract_key_information(certificate),
                category=CertificateCategory.UNKNOWN,
                assurance_level=AssuranceLevel.UNKNOWN
            )
            
            # Calculate fingerprints
            cert_der = certificate.public_bytes(serialization.Encoding.DER)
            metadata.fingerprint_sha1 = hashlib.sha1(cert_der).hexdigest()
            metadata.fingerprint_sha256 = hashlib.sha256(cert_der).hexdigest()
            metadata.fingerprint_md5 = hashlib.md5(cert_der).hexdigest()
            
            # Parse subject and issuer components
            metadata.subject_components = self._parse_distinguished_name(certificate.subject)
            metadata.issuer_components = self._parse_distinguished_name(certificate.issuer)
            
            # Check if self-signed
            metadata.is_self_signed = certificate.subject == certificate.issuer
            
            # Parse extensions
            self._parse_extensions(certificate, metadata)
            
            # Determine certificate category and assurance level
            self._categorize_certificate(certificate, metadata)
            
            # Extract DoD-specific identifiers if enabled
            if self.enable_enhanced_parsing:
                self._extract_dod_identifiers(certificate, metadata)
                self._perform_security_assessment(certificate, metadata)
                self._add_compliance_notes(certificate, metadata)
            
            logger.debug(f"Successfully parsed certificate: {metadata.subject_dn}")
            return metadata
            
        except Exception as e:
            # Create minimal metadata with error information
            error_metadata = CertificateMetadata(
                version=0,
                serial_number="unknown",
                subject_dn="parsing_failed",
                issuer_dn="parsing_failed",
                not_before=datetime.min.replace(tzinfo=timezone.utc),
                not_after=datetime.min.replace(tzinfo=timezone.utc),
                signature_algorithm="unknown",
                key_info=KeyInformation(algorithm="unknown", size_bits=0),
                category=CertificateCategory.UNKNOWN,
                assurance_level=AssuranceLevel.UNKNOWN
            )
            error_metadata.parsing_errors.append(f"Certificate parsing failed: {str(e)}")
            logger.error(f"Certificate parsing failed: {e}")
            return error_metadata
    
    def _extract_key_information(self, certificate: x509.Certificate) -> KeyInformation:
        """Extract detailed public key information."""
        try:
            public_key = certificate.public_key()
            
            if isinstance(public_key, rsa.RSAPublicKey):
                key_info = KeyInformation(
                    algorithm="RSA",
                    size_bits=public_key.key_size,
                    public_key_info={
                        'modulus_length': public_key.key_size,
                        'public_exponent': public_key.public_numbers().e
                    }
                )
                # RSA strength is approximately equal to key size
                key_info.strength_bits = public_key.key_size
                
                # Check for weak keys
                if public_key.key_size < 2048:
                    key_info.is_weak = True
                    key_info.weakness_reasons.append(f"RSA key size {public_key.key_size} < 2048 bits")
                
            elif isinstance(public_key, ec.EllipticCurvePublicKey):
                curve_name = public_key.curve.name
                key_info = KeyInformation(
                    algorithm="ECC",
                    size_bits=public_key.curve.key_size,
                    curve_name=curve_name,
                    public_key_info={
                        'curve_name': curve_name,
                        'curve_size': public_key.curve.key_size
                    }
                )
                
                # ECC strength mapping (approximate)
                strength_mapping = {
                    256: 128,  # P-256
                    384: 192,  # P-384
                    521: 256   # P-521
                }
                key_info.strength_bits = strength_mapping.get(public_key.curve.key_size, 
                                                            public_key.curve.key_size // 2)
                
                # Check for weak curves
                if public_key.curve.key_size < 256:
                    key_info.is_weak = True
                    key_info.weakness_reasons.append(f"ECC curve size {public_key.curve.key_size} < 256 bits")
                
            elif isinstance(public_key, dsa.DSAPublicKey):
                key_info = KeyInformation(
                    algorithm="DSA",
                    size_bits=public_key.key_size,
                    public_key_info={
                        'key_size': public_key.key_size
                    }
                )
                key_info.strength_bits = public_key.key_size
                
                # DSA is generally considered legacy
                key_info.is_weak = True
                key_info.weakness_reasons.append("DSA is deprecated and not recommended for new applications")
                
            elif isinstance(public_key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
                algorithm = "Ed25519" if isinstance(public_key, ed25519.Ed25519PublicKey) else "Ed448"
                key_size = 255 if algorithm == "Ed25519" else 448
                key_info = KeyInformation(
                    algorithm=algorithm,
                    size_bits=key_size,
                    public_key_info={
                        'algorithm': algorithm
                    }
                )
                key_info.strength_bits = 128 if algorithm == "Ed25519" else 224
                
            else:
                # Unknown key type
                key_info = KeyInformation(
                    algorithm=type(public_key).__name__,
                    size_bits=0,
                    public_key_info={
                        'type': type(public_key).__name__
                    }
                )
                key_info.is_weak = True
                key_info.weakness_reasons.append(f"Unknown or unsupported key type: {type(public_key).__name__}")
            
            return key_info
            
        except Exception as e:
            logger.warning(f"Error extracting key information: {e}")
            return KeyInformation(
                algorithm="unknown",
                size_bits=0,
                is_weak=True,
                weakness_reasons=[f"Key extraction failed: {str(e)}"]
            )
    
    def _parse_distinguished_name(self, dn: x509.Name) -> Dict[str, List[str]]:
        """Parse distinguished name into components."""
        components = {}
        
        for attribute in dn:
            oid_name = attribute.oid._name or attribute.oid.dotted_string
            value = attribute.value
            
            if oid_name not in components:
                components[oid_name] = []
            components[oid_name].append(value)
        
        return components
    
    def _parse_extensions(self, certificate: x509.Certificate, metadata: CertificateMetadata):
        """Parse certificate extensions."""
        for extension in certificate.extensions:
            try:
                oid = extension.oid.dotted_string
                name = self.extension_names.get(extension.oid, f"Unknown ({oid})")
                critical = extension.critical
                
                # Get summary of extension value
                value_summary = self._get_extension_summary(extension)
                
                ext_info = ExtensionInfo(
                    oid=oid,
                    name=name,
                    critical=critical,
                    value_summary=value_summary,
                    parsed_value=extension.value,
                    raw_value=extension.value.public_bytes() if hasattr(extension.value, 'public_bytes') else b""
                )
                
                metadata.extensions.append(ext_info)
                
                # Handle specific extensions
                self._handle_specific_extension(extension, metadata)
                
            except Exception as e:
                metadata.parsing_warnings.append(f"Error parsing extension {extension.oid}: {e}")
    
    def _get_extension_summary(self, extension) -> str:
        """Get human-readable summary of extension value."""
        try:
            if extension.oid == ExtensionOID.KEY_USAGE:
                usages = []
                ku = extension.value
                if ku.digital_signature: usages.append("Digital Signature")
                if ku.non_repudiation: usages.append("Non-Repudiation")
                if ku.key_encipherment: usages.append("Key Encipherment")
                if ku.data_encipherment: usages.append("Data Encipherment")
                if ku.key_agreement: usages.append("Key Agreement")
                if ku.key_cert_sign: usages.append("Certificate Sign")
                if ku.crl_sign: usages.append("CRL Sign")
                return ", ".join(usages)
                
            elif extension.oid == ExtensionOID.EXTENDED_KEY_USAGE:
                return f"{len(extension.value)} purposes"
                
            elif extension.oid == ExtensionOID.BASIC_CONSTRAINTS:
                bc = extension.value
                if bc.ca:
                    path_len = f", pathlen={bc.path_length}" if bc.path_length is not None else ""
                    return f"CA:TRUE{path_len}"
                else:
                    return "CA:FALSE"
                    
            elif extension.oid == ExtensionOID.SUBJECT_ALTERNATIVE_NAME:
                return f"{len(extension.value)} names"
                
            elif extension.oid == ExtensionOID.CERTIFICATE_POLICIES:
                return f"{len(extension.value)} policies"
                
            elif extension.oid == ExtensionOID.CRL_DISTRIBUTION_POINTS:
                return f"{len(extension.value)} distribution points"
                
            elif extension.oid == ExtensionOID.AUTHORITY_INFORMATION_ACCESS:
                return f"{len(extension.value)} access methods"
                
            else:
                return f"Extension value ({type(extension.value).__name__})"
                
        except Exception:
            return "Parse error"
    
    def _handle_specific_extension(self, extension, metadata: CertificateMetadata):
        """Handle parsing of specific extension types."""
        try:
            if extension.oid == ExtensionOID.KEY_USAGE:
                ku = extension.value
                if ku.digital_signature: metadata.key_usage.append("digital_signature")
                if ku.non_repudiation: metadata.key_usage.append("non_repudiation")
                if ku.key_encipherment: metadata.key_usage.append("key_encipherment")
                if ku.data_encipherment: metadata.key_usage.append("data_encipherment")
                if ku.key_agreement: metadata.key_usage.append("key_agreement")
                if ku.key_cert_sign: 
                    metadata.key_usage.append("key_cert_sign")
                    metadata.is_ca_certificate = True
                if ku.crl_sign: metadata.key_usage.append("crl_sign")
                
            elif extension.oid == ExtensionOID.EXTENDED_KEY_USAGE:
                for usage in extension.value:
                    metadata.extended_key_usage.append(usage.dotted_string)
                    
            elif extension.oid == ExtensionOID.BASIC_CONSTRAINTS:
                metadata.is_ca_certificate = extension.value.ca
                
            elif extension.oid == ExtensionOID.SUBJECT_ALTERNATIVE_NAME:
                for name in extension.value:
                    san = self._parse_san_entry(name)
                    if san:
                        metadata.subject_alternative_names.append(san)
                        
            elif extension.oid == ExtensionOID.CERTIFICATE_POLICIES:
                for policy in extension.value:
                    policy_info = self._parse_certificate_policy(policy)
                    metadata.certificate_policies.append(policy_info)
                    
            elif extension.oid == ExtensionOID.CRL_DISTRIBUTION_POINTS:
                for dist_point in extension.value:
                    if dist_point.full_name:
                        for name in dist_point.full_name:
                            if isinstance(name, x509.UniformResourceIdentifier):
                                metadata.crl_distribution_points.append(name.value)
                                
            elif extension.oid == ExtensionOID.AUTHORITY_INFORMATION_ACCESS:
                for access_desc in extension.value:
                    if isinstance(access_desc.access_location, x509.UniformResourceIdentifier):
                        url = access_desc.access_location.value
                        if access_desc.access_method == x509.oid.AuthorityInformationAccessOID.OCSP:
                            metadata.ocsp_responders.append(url)
                        elif access_desc.access_method == x509.oid.AuthorityInformationAccessOID.CA_ISSUERS:
                            metadata.ca_issuers.append(url)
                            
            elif extension.oid == ExtensionOID.SUBJECT_KEY_IDENTIFIER:
                metadata.subject_key_identifier = extension.value.digest.hex()
                
            elif extension.oid == ExtensionOID.AUTHORITY_KEY_IDENTIFIER:
                if extension.value.key_identifier:
                    metadata.authority_key_identifier = extension.value.key_identifier.hex()
                    
        except Exception as e:
            metadata.parsing_warnings.append(f"Error handling extension {extension.oid}: {e}")
    
    def _parse_san_entry(self, name) -> Optional[SubjectAlternativeName]:
        """Parse Subject Alternative Name entry."""
        try:
            if isinstance(name, x509.RFC822Name):
                return SubjectAlternativeName(
                    type="email",
                    value=name.value,
                    raw_value=name
                )
            elif isinstance(name, x509.DNSName):
                return SubjectAlternativeName(
                    type="dns",
                    value=name.value,
                    raw_value=name
                )
            elif isinstance(name, x509.UniformResourceIdentifier):
                return SubjectAlternativeName(
                    type="uri",
                    value=name.value,
                    raw_value=name
                )
            elif isinstance(name, x509.IPAddress):
                return SubjectAlternativeName(
                    type="ip",
                    value=str(name.value),
                    raw_value=name
                )
            elif isinstance(name, x509.DirectoryName):
                return SubjectAlternativeName(
                    type="dirname",
                    value=name.value.rfc4514_string(),
                    raw_value=name
                )
            elif isinstance(name, x509.OtherName):
                # Handle DoD-specific OtherName types
                oid = name.type_id.dotted_string
                value_str = f"OtherName({oid})"
                
                # Try to extract meaningful value for known OIDs
                if oid in self.PIV_CAC_OIDS:
                    try:
                        if isinstance(name.value, bytes):
                            value_str = name.value.hex()
                        else:
                            value_str = str(name.value)
                    except:
                        pass
                
                return SubjectAlternativeName(
                    type="othername",
                    value=value_str,
                    raw_value=name
                )
            else:
                return SubjectAlternativeName(
                    type="unknown",
                    value=str(name),
                    raw_value=name
                )
        except Exception as e:
            logger.debug(f"Error parsing SAN entry: {e}")
            return None
    
    def _parse_certificate_policy(self, policy) -> PolicyInformation:
        """Parse certificate policy information."""
        oid = policy.policy_identifier.dotted_string
        
        # Check if it's a known DoD policy
        if oid in self.DOD_CERTIFICATE_POLICIES:
            dod_policy = self.DOD_CERTIFICATE_POLICIES[oid]
            return PolicyInformation(
                oid=oid,
                policy_name=dod_policy['name'],
                policy_type=dod_policy['type'],
                assurance_level=dod_policy['assurance_level'],
                hardware_required=dod_policy['hardware_required']
            )
        else:
            # Unknown policy
            return PolicyInformation(
                oid=oid,
                policy_name=f"Unknown Policy ({oid})",
                policy_type="UNKNOWN"
            )
    
    def _categorize_certificate(self, certificate: x509.Certificate, metadata: CertificateMetadata):
        """Determine certificate category and assurance level."""
        subject_dn = metadata.subject_dn
        issuer_dn = metadata.issuer_dn
        
        # Check for DoD Root CAs
        if metadata.is_self_signed and "DoD Root CA" in subject_dn:
            metadata.category = CertificateCategory.DOD_ROOT_CA
            metadata.assurance_level = AssuranceLevel.HIGH
            return
        
        # Check for DoD Intermediate CAs
        if metadata.is_ca_certificate and ("DoD" in subject_dn or "DoD" in issuer_dn):
            metadata.category = CertificateCategory.DOD_INTERMEDIATE_CA
            metadata.assurance_level = AssuranceLevel.MEDIUM_HARDWARE
            return
        
        # Check certificate policies for PIV/CAC classification
        for policy_info in metadata.certificate_policies:
            if policy_info.policy_type == "DOD":
                metadata.assurance_level = policy_info.assurance_level
                
                # Determine category based on key usage and policies
                if "client_auth" in metadata.extended_key_usage:
                    if policy_info.oid == "2.16.840.1.101.3.2.1.3.13":
                        metadata.category = CertificateCategory.PIV_AUTHENTICATION
                    else:
                        metadata.category = CertificateCategory.CAC_AUTHENTICATION
                elif "digital_signature" in metadata.key_usage and "non_repudiation" in metadata.key_usage:
                    metadata.category = CertificateCategory.PIV_SIGNING
                elif "key_encipherment" in metadata.key_usage or "data_encipherment" in metadata.key_usage:
                    metadata.category = CertificateCategory.PIV_ENCRYPTION
                else:
                    metadata.category = CertificateCategory.DOD_END_ENTITY
                return
        
        # Check for Federal Bridge or Cross-signed certificates
        if "Bridge" in subject_dn or "Cross" in subject_dn:
            metadata.category = CertificateCategory.FEDERAL_BRIDGE
            return
        
        # Check for commercial CAs
        if metadata.is_ca_certificate and not metadata.is_self_signed:
            metadata.category = CertificateCategory.COMMERCIAL_CA
            return
        
        # Check for self-signed certificates
        if metadata.is_self_signed:
            metadata.category = CertificateCategory.SELF_SIGNED
            return
        
        # Default to unknown
        metadata.category = CertificateCategory.UNKNOWN
    
    def _extract_dod_identifiers(self, certificate: x509.Certificate, metadata: CertificateMetadata):
        """Extract DoD-specific identifiers from certificate."""
        dod_ids = DoDIdentifiers()
        
        # Extract from Subject Alternative Name
        for san in metadata.subject_alternative_names:
            if san.type == "othername" and isinstance(san.raw_value, x509.OtherName):
                oid = san.raw_value.type_id.dotted_string
                
                try:
                    if oid == "2.16.840.1.101.3.6.9.1":  # EDIPI
                        if isinstance(san.raw_value.value, bytes):
                            dod_ids.edipi = san.raw_value.value.decode('utf-8', errors='ignore')
                        else:
                            dod_ids.edipi = str(san.raw_value.value)
                    elif oid == "2.16.840.1.101.3.6.6":  # FASC-N
                        if isinstance(san.raw_value.value, bytes):
                            dod_ids.fasc_n = san.raw_value.value.hex()
                    elif oid == "2.16.840.1.101.3.6.9.2":  # PIV GUID
                        if isinstance(san.raw_value.value, bytes):
                            dod_ids.piv_guid = san.raw_value.value.hex()
                except Exception as e:
                    metadata.parsing_warnings.append(f"Error extracting DoD identifier from OID {oid}: {e}")
        
        # Extract from subject DN components
        subject_components = metadata.subject_components
        
        # Look for organizational unit patterns
        if "organizationalUnitName" in subject_components:
            for ou in subject_components["organizationalUnitName"]:
                # Check for DOD ID patterns
                if ou.startswith("DOD."):
                    dod_ids.dod_id = ou
                elif ou.startswith("USA."):
                    dod_ids.agency_code = ou
                elif len(ou) == 10 and ou.isdigit():
                    # Likely EDIPI in OU field
                    if not dod_ids.edipi:
                        dod_ids.edipi = ou
        
        # Extract organizational affiliation
        if "organizationName" in subject_components:
            org = subject_components["organizationName"][0]
            if "U.S. Government" in org:
                dod_ids.org_affiliation = "US_GOVERNMENT"
        
        # Look for email domain patterns to determine org affiliation
        for san in metadata.subject_alternative_names:
            if san.type == "email":
                email = san.value.lower()
                for pattern, org_name in self.DOD_ORG_PATTERNS.items():
                    if re.search(pattern, email):
                        dod_ids.org_affiliation = org_name
                        break
        
        metadata.dod_identifiers = dod_ids
    
    def _perform_security_assessment(self, certificate: x509.Certificate, metadata: CertificateMetadata):
        """Perform security assessment and identify potential issues."""
        current_time = datetime.now(timezone.utc)
        
        # Check for expiration warnings
        days_until_expiry = (metadata.not_after - current_time).days
        if days_until_expiry < 30:
            metadata.security_warnings.append(f"Certificate expires in {days_until_expiry} days")
        
        # Check for weak keys
        if metadata.key_info.is_weak:
            for reason in metadata.key_info.weakness_reasons:
                metadata.security_warnings.append(f"Weak key: {reason}")
        
        # Check for weak signature algorithms
        weak_sig_algorithms = ["sha1", "md5", "md2"]
        sig_algo = metadata.signature_algorithm.lower()
        if any(weak_algo in sig_algo for weak_algo in weak_sig_algorithms):
            metadata.security_warnings.append(f"Weak signature algorithm: {metadata.signature_algorithm}")
        
        # Check for missing critical extensions
        critical_extensions = [ext for ext in metadata.extensions if ext.critical]
        if metadata.is_ca_certificate and not any(ext.name == "Basic Constraints" for ext in critical_extensions):
            metadata.security_warnings.append("CA certificate missing critical Basic Constraints extension")
        
        # Check for self-signed end-entity certificates
        if metadata.is_self_signed and not metadata.is_ca_certificate:
            metadata.security_warnings.append("Self-signed end-entity certificate")
    
    def _add_compliance_notes(self, certificate: x509.Certificate, metadata: CertificateMetadata):
        """Add compliance-related notes."""
        # FIPS 140-2 compliance notes
        if metadata.key_info.algorithm == "RSA" and metadata.key_info.size_bits >= 2048:
            metadata.compliance_notes.append("RSA key size meets FIPS 140-2 requirements")
        elif metadata.key_info.algorithm == "ECC" and metadata.key_info.size_bits >= 256:
            metadata.compliance_notes.append("ECC key size meets FIPS 140-2 requirements")
        
        # DoD PKI compliance
        if metadata.category in [CertificateCategory.DOD_ROOT_CA, CertificateCategory.DOD_INTERMEDIATE_CA,
                               CertificateCategory.PIV_AUTHENTICATION, CertificateCategory.CAC_AUTHENTICATION]:
            metadata.compliance_notes.append("Certificate appears to be DoD PKI compliant")
        
        # PIV compliance notes
        if metadata.category.value.startswith("piv_"):
            if metadata.assurance_level == AssuranceLevel.MEDIUM_HARDWARE:
                metadata.compliance_notes.append("PIV certificate with medium hardware assurance")
            if any(oid.startswith("2.16.840.1.101.3.7.2") for oid in [p.oid for p in metadata.certificate_policies]):
                metadata.compliance_notes.append("Contains PIV certificate policies")
    
    def get_certificate_summary(self, metadata: CertificateMetadata) -> Dict[str, Any]:
        """
        Get concise summary of certificate metadata.
        
        Args:
            metadata: Certificate metadata
            
        Returns:
            Dictionary with summary information
        """
        return {
            'subject': metadata.subject_dn,
            'issuer': metadata.issuer_dn,
            'serial_number': metadata.serial_number,
            'category': metadata.category.value,
            'assurance_level': metadata.assurance_level.value,
            'is_ca': metadata.is_ca_certificate,
            'is_self_signed': metadata.is_self_signed,
            'key_algorithm': metadata.key_info.algorithm,
            'key_size': metadata.key_info.size_bits,
            'signature_algorithm': metadata.signature_algorithm,
            'valid_from': metadata.not_before.isoformat(),
            'valid_until': metadata.not_after.isoformat(),
            'fingerprint_sha256': metadata.fingerprint_sha256[:16] + "...",
            'edipi': metadata.dod_identifiers.edipi,
            'has_security_warnings': len(metadata.security_warnings) > 0,
            'warning_count': len(metadata.security_warnings),
            'parsing_errors': len(metadata.parsing_errors) > 0
        }


# Example usage and utility functions
def main():
    """Example usage of certificate parser."""
    parser = CertificateParser(enable_enhanced_parsing=True)
    
    # This would typically be used with actual certificate data
    print("Certificate Parser initialized")
    print(f"Known DoD policies: {len(parser.DOD_CERTIFICATE_POLICIES)}")
    print(f"PIV/CAC OIDs: {len(parser.PIV_CAC_OIDS)}")


if __name__ == "__main__":
    main()