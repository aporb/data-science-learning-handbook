#!/usr/bin/env python3
"""
Unified Certificate Manager

This module provides a unified interface for comprehensive certificate management
including extraction, validation, trust store management, parsing, and monitoring.
"""

import os
import logging
import threading
from typing import Optional, Dict, List, Tuple, Union, Any
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from cryptography import x509

# Import our certificate management modules
from .certificate_extractor import CertificateExtractor, CertificateInfo, CertificateType
from .dod_pki_validator import DoDPKIValidator, ValidationContext, ValidationLevel, ChainValidationResult
from .trust_store_manager import TrustStoreManager, TrustedCAInfo
from .certificate_parser import CertificateParser, CertificateMetadata, CertificateCategory
from .expiration_monitor import ExpirationMonitor, MonitoringConfiguration, ExpirationAlert

logger = logging.getLogger(__name__)


@dataclass
class CertificateManagementConfig:
    """Configuration for certificate management system."""
    # Directories
    trust_store_path: Optional[str] = None
    certificate_cache_path: Optional[str] = None
    
    # PKCS#11 configuration
    pkcs11_library_path: Optional[str] = None
    enable_pkcs11_auto_detect: bool = True
    
    # Validation configuration
    validation_level: ValidationLevel = ValidationLevel.STANDARD
    enable_revocation_checking: bool = True
    enable_ocsp: bool = True
    enable_crl: bool = True
    
    # Trust store configuration
    enable_auto_update: bool = True
    update_interval_hours: int = 24
    
    # Monitoring configuration
    enable_expiration_monitoring: bool = True
    monitoring_config: Optional[MonitoringConfiguration] = None
    
    # Enhanced features
    enable_enhanced_parsing: bool = True
    enable_dod_compliance_checking: bool = True
    enable_smart_card_monitoring: bool = True


@dataclass
class ManagedCertificate:
    """Unified certificate information from all management components."""
    # Basic certificate information
    certificate: x509.Certificate
    certificate_id: str
    
    # Extracted information (from certificate_extractor)
    extraction_info: Optional[CertificateInfo] = None
    
    # Validation results (from dod_pki_validator)
    validation_result: Optional[ChainValidationResult] = None
    
    # Parsed metadata (from certificate_parser)
    metadata: Optional[CertificateMetadata] = None
    
    # Trust store information (if it's a CA)
    trust_info: Optional[TrustedCAInfo] = None
    
    # Monitoring information
    is_monitored: bool = False
    active_alerts: List[ExpirationAlert] = field(default_factory=list)
    
    # Management metadata
    source: str = "unknown"  # smart_card, file, trust_store, etc.
    added_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_validated: Optional[datetime] = None
    last_checked: Optional[datetime] = None
    
    # Computed properties
    @property
    def is_valid(self) -> bool:
        """Check if certificate is valid based on all available information."""
        if self.validation_result:
            return self.validation_result.is_valid
        return True  # Default to true if no validation performed
    
    @property
    def has_warnings(self) -> bool:
        """Check if certificate has any warnings."""
        warnings_count = 0
        if self.validation_result:
            warnings_count += self.validation_result.warning_count
        if self.metadata:
            warnings_count += len(self.metadata.security_warnings)
        return warnings_count > 0
    
    @property
    def is_dod_certificate(self) -> bool:
        """Check if this is a DoD certificate."""
        if self.metadata and self.metadata.category:
            return self.metadata.category.value.startswith('dod_')
        return False
    
    @property
    def days_until_expiry(self) -> int:
        """Get days until certificate expiry."""
        expiry_date = self.certificate.not_valid_after
        return (expiry_date - datetime.now(timezone.utc)).days


class CertificateManager:
    """
    Unified certificate management system.
    
    Provides a comprehensive interface for certificate extraction, validation,
    trust management, parsing, and monitoring with special focus on DoD PKI
    and CAC/PIV certificates.
    """
    
    def __init__(self, config: CertificateManagementConfig = None):
        """
        Initialize certificate manager.
        
        Args:
            config: Configuration for certificate management
        """
        self.config = config or CertificateManagementConfig()
        
        # Initialize components
        self._initialize_components()
        
        # Managed certificates registry
        self._managed_certificates = {}
        self._registry_lock = threading.Lock()
        
        # Statistics tracking
        self._stats = {
            'total_certificates': 0,
            'valid_certificates': 0,
            'dod_certificates': 0,
            'monitored_certificates': 0,
            'smart_card_certificates': 0,
            'trust_store_certificates': 0,
            'active_alerts': 0
        }
        
        logger.info("Certificate manager initialized")
    
    def _initialize_components(self):
        """Initialize certificate management components."""
        try:
            # Initialize certificate extractor
            self.extractor = CertificateExtractor(
                pkcs11_library_path=self.config.pkcs11_library_path,
                enable_enhanced_extraction=self.config.enable_enhanced_parsing
            )
            
            # Initialize DoD PKI validator
            validation_context = ValidationContext(
                validation_level=self.config.validation_level,
                check_revocation=self.config.enable_revocation_checking,
                check_ocsp=self.config.enable_ocsp,
                check_crl=self.config.enable_crl
            )
            self.validator = DoDPKIValidator(
                trusted_ca_store_path=self.config.trust_store_path,
                enable_ocsp=self.config.enable_ocsp,
                enable_crl=self.config.enable_crl
            )
            self.validation_context = validation_context
            
            # Initialize certificate parser
            self.parser = CertificateParser(
                enable_enhanced_parsing=self.config.enable_enhanced_parsing
            )
            
            # Initialize trust store manager
            self.trust_manager = TrustStoreManager(
                trust_store_path=self.config.trust_store_path,
                enable_auto_update=self.config.enable_auto_update,
                update_interval_hours=self.config.update_interval_hours
            )
            
            # Initialize expiration monitor if enabled
            self.expiration_monitor = None
            if self.config.enable_expiration_monitoring:
                monitoring_config = self.config.monitoring_config or MonitoringConfiguration()
                self.expiration_monitor = ExpirationMonitor(monitoring_config)
                self.expiration_monitor.start_monitoring()
            
            logger.debug("All certificate management components initialized")
            
        except Exception as e:
            logger.error(f"Failed to initialize certificate management components: {e}")
            raise
    
    def extract_smart_card_certificates(self, slot_id: int = None, 
                                      validate: bool = True,
                                      monitor: bool = None) -> List[ManagedCertificate]:
        """
        Extract certificates from smart card and add to management system.
        
        Args:
            slot_id: Specific smart card slot (auto-detect if None)
            validate: Whether to validate certificates
            monitor: Whether to monitor for expiration (uses config default if None)
            
        Returns:
            List of managed certificate objects
        """
        managed_certs = []
        
        try:
            # Extract certificates from smart card
            cert_infos = self.extractor.extract_all_certificates(slot_id, include_metadata=True)
            
            for cert_info in cert_infos:
                try:
                    managed_cert = self._create_managed_certificate(
                        cert_info.certificate, 
                        source="smart_card",
                        extraction_info=cert_info
                    )
                    
                    # Validate certificate if requested
                    if validate:
                        self._validate_certificate(managed_cert)
                    
                    # Add to monitoring if enabled
                    monitor_cert = monitor if monitor is not None else self.config.enable_expiration_monitoring
                    if monitor_cert and self.expiration_monitor:
                        self._add_to_monitoring(managed_cert)
                    
                    managed_certs.append(managed_cert)
                    
                    logger.info(f"Extracted and managed certificate: {cert_info.subject_dn}")
                    
                except Exception as e:
                    logger.warning(f"Failed to manage extracted certificate: {e}")
            
            # Update statistics
            self._update_statistics()
            
            logger.info(f"Successfully extracted {len(managed_certs)} certificates from smart card")
            return managed_certs
            
        except Exception as e:
            logger.error(f"Failed to extract smart card certificates: {e}")
            return []
    
    def load_certificate_file(self, file_path: str, 
                            validate: bool = True,
                            monitor: bool = None) -> Optional[ManagedCertificate]:
        """
        Load certificate from file and add to management system.
        
        Args:
            file_path: Path to certificate file
            validate: Whether to validate certificate
            monitor: Whether to monitor for expiration
            
        Returns:
            Managed certificate object or None if failed
        """
        try:
            # Read certificate file
            with open(file_path, 'rb') as f:
                cert_data = f.read()
            
            # Parse certificate
            try:
                certificate = x509.load_pem_x509_certificate(cert_data)
            except ValueError:
                certificate = x509.load_der_x509_certificate(cert_data)
            
            # Create managed certificate
            managed_cert = self._create_managed_certificate(
                certificate,
                source=f"file:{file_path}"
            )
            
            # Validate certificate if requested
            if validate:
                self._validate_certificate(managed_cert)
            
            # Add to monitoring if enabled
            monitor_cert = monitor if monitor is not None else self.config.enable_expiration_monitoring
            if monitor_cert and self.expiration_monitor:
                cert_metadata = {}
                if managed_cert.metadata:
                    cert_metadata = {
                        'edipi': managed_cert.metadata.dod_identifiers.edipi,
                        'dod_id': managed_cert.metadata.dod_identifiers.dod_id,
                        'certificate_type': managed_cert.metadata.category.value
                    }
                
                self.expiration_monitor.add_certificate_for_monitoring(
                    certificate, cert_metadata, file_path
                )
                managed_cert.is_monitored = True
            
            # Update statistics
            self._update_statistics()
            
            logger.info(f"Successfully loaded certificate from {file_path}")
            return managed_cert
            
        except Exception as e:
            logger.error(f"Failed to load certificate from {file_path}: {e}")
            return None
    
    def add_certificate_to_trust_store(self, certificate_data: bytes,
                                     source_info: Dict[str, Any] = None) -> Optional[TrustedCAInfo]:
        """
        Add certificate to trust store.
        
        Args:
            certificate_data: Certificate data (PEM or DER)
            source_info: Information about certificate source
            
        Returns:
            TrustedCAInfo object or None if failed
        """
        try:
            trust_info = self.trust_manager.add_certificate(certificate_data, source_info)
            
            # Also create a managed certificate for the trust store certificate
            try:
                certificate = x509.load_pem_x509_certificate(certificate_data)
            except ValueError:
                certificate = x509.load_der_x509_certificate(certificate_data)
            
            managed_cert = self._create_managed_certificate(
                certificate,
                source="trust_store",
                trust_info=trust_info
            )
            
            # Validate the trust store certificate
            self._validate_certificate(managed_cert)
            
            # Update statistics
            self._update_statistics()
            
            logger.info(f"Added certificate to trust store: {trust_info.subject_dn}")
            return trust_info
            
        except Exception as e:
            logger.error(f"Failed to add certificate to trust store: {e}")
            return None
    
    def validate_certificate_chain(self, certificate: x509.Certificate,
                                 intermediate_certs: List[x509.Certificate] = None) -> ChainValidationResult:
        """
        Validate certificate chain using DoD PKI validator.
        
        Args:
            certificate: Certificate to validate
            intermediate_certs: Intermediate certificates
            
        Returns:
            Validation result
        """
        try:
            result = self.validator.validate_certificate_chain(
                certificate, intermediate_certs, self.validation_context
            )
            
            # Update managed certificate if it exists
            cert_id = self._get_certificate_id(certificate)
            with self._registry_lock:
                if cert_id in self._managed_certificates:
                    managed_cert = self._managed_certificates[cert_id]
                    managed_cert.validation_result = result
                    managed_cert.last_validated = datetime.now(timezone.utc)
            
            return result
            
        except Exception as e:
            logger.error(f"Certificate validation failed: {e}")
            # Return a failed validation result
            return ChainValidationResult(
                status="INVALID",
                certificate_subject=certificate.subject.rfc4514_string(),
                issuer_subject=certificate.issuer.rfc4514_string(),
                chain_length=1,
                validation_time=datetime.now(timezone.utc)
            )
    
    def get_managed_certificate(self, certificate_id: str) -> Optional[ManagedCertificate]:
        """
        Get managed certificate by ID.
        
        Args:
            certificate_id: Certificate identifier
            
        Returns:
            Managed certificate or None if not found
        """
        with self._registry_lock:
            return self._managed_certificates.get(certificate_id)
    
    def get_all_managed_certificates(self, 
                                   category: CertificateCategory = None,
                                   source: str = None,
                                   valid_only: bool = False) -> List[ManagedCertificate]:
        """
        Get all managed certificates with optional filtering.
        
        Args:
            category: Filter by certificate category
            source: Filter by source
            valid_only: Only return valid certificates
            
        Returns:
            List of managed certificates
        """
        with self._registry_lock:
            certificates = list(self._managed_certificates.values())
        
        # Apply filters
        if category:
            certificates = [cert for cert in certificates 
                          if cert.metadata and cert.metadata.category == category]
        
        if source:
            certificates = [cert for cert in certificates if cert.source.startswith(source)]
        
        if valid_only:
            certificates = [cert for cert in certificates if cert.is_valid]
        
        # Sort by most recently added
        certificates.sort(key=lambda x: x.added_at, reverse=True)
        
        return certificates
    
    def get_dod_certificates(self) -> List[ManagedCertificate]:
        """Get all DoD certificates."""
        return [cert for cert in self.get_all_managed_certificates() 
                if cert.is_dod_certificate]
    
    def get_expiring_certificates(self, days_threshold: int = 30) -> List[ManagedCertificate]:
        """
        Get certificates expiring within threshold.
        
        Args:
            days_threshold: Days until expiration threshold
            
        Returns:
            List of expiring certificates
        """
        expiring_certs = []
        
        for cert in self.get_all_managed_certificates():
            if cert.days_until_expiry <= days_threshold:
                expiring_certs.append(cert)
        
        # Sort by days until expiry (most urgent first)
        expiring_certs.sort(key=lambda x: x.days_until_expiry)
        
        return expiring_certs
    
    def get_active_alerts(self) -> List[ExpirationAlert]:
        """Get all active expiration alerts."""
        if self.expiration_monitor:
            return self.expiration_monitor.get_active_alerts()
        return []
    
    def update_trust_store(self) -> Dict[str, int]:
        """Update trust store with latest DoD PKI certificates."""
        try:
            stats = self.trust_manager.update_from_dod_pki()
            
            # Update our statistics
            self._update_statistics()
            
            logger.info(f"Trust store update completed: {stats}")
            return stats
            
        except Exception as e:
            logger.error(f"Trust store update failed: {e}")
            return {'errors': 1}
    
    def perform_comprehensive_check(self) -> Dict[str, Any]:
        """
        Perform comprehensive check of all managed certificates.
        
        Returns:
            Dictionary with check results and statistics
        """
        results = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'certificates_checked': 0,
            'validation_results': {},
            'expiration_alerts': [],
            'trust_store_status': {},
            'statistics': {}
        }
        
        try:
            # Check all managed certificates
            certificates = self.get_all_managed_certificates()
            results['certificates_checked'] = len(certificates)
            
            for managed_cert in certificates:
                cert_id = managed_cert.certificate_id
                
                # Re-validate certificate
                validation_result = self.validate_certificate_chain(managed_cert.certificate)
                results['validation_results'][cert_id] = {
                    'is_valid': validation_result.is_valid,
                    'status': validation_result.status.value if hasattr(validation_result.status, 'value') else str(validation_result.status),
                    'error_count': validation_result.error_count,
                    'warning_count': validation_result.warning_count
                }
                
                # Update last checked time
                managed_cert.last_checked = datetime.now(timezone.utc)
            
            # Check expiration alerts
            if self.expiration_monitor:
                alerts = self.expiration_monitor.check_expirations()
                results['expiration_alerts'] = [
                    {
                        'alert_id': alert.alert_id,
                        'certificate_id': alert.certificate_id,
                        'severity': alert.severity.value,
                        'days_until_expiry': alert.days_until_expiry,
                        'subject_dn': alert.subject_dn
                    }
                    for alert in alerts
                ]
            
            # Check trust store status
            trust_stats = self.trust_manager.get_trust_store_stats()
            results['trust_store_status'] = trust_stats
            
            # Update and include statistics
            self._update_statistics()
            results['statistics'] = dict(self._stats)
            
            logger.info(f"Comprehensive check completed: {results['certificates_checked']} certificates")
            return results
            
        except Exception as e:
            logger.error(f"Comprehensive check failed: {e}")
            results['error'] = str(e)
            return results
    
    def _create_managed_certificate(self, certificate: x509.Certificate,
                                  source: str,
                                  extraction_info: CertificateInfo = None,
                                  trust_info: TrustedCAInfo = None) -> ManagedCertificate:
        """Create managed certificate object."""
        # Generate certificate ID
        cert_id = self._get_certificate_id(certificate)
        
        # Parse certificate metadata
        metadata = self.parser.parse_certificate(certificate)
        
        # Create managed certificate
        managed_cert = ManagedCertificate(
            certificate=certificate,
            certificate_id=cert_id,
            extraction_info=extraction_info,
            metadata=metadata,
            trust_info=trust_info,
            source=source
        )
        
        # Add to registry
        with self._registry_lock:
            self._managed_certificates[cert_id] = managed_cert
        
        return managed_cert
    
    def _validate_certificate(self, managed_cert: ManagedCertificate):
        """Validate a managed certificate."""
        try:
            validation_result = self.validator.validate_certificate_chain(
                managed_cert.certificate, None, self.validation_context
            )
            managed_cert.validation_result = validation_result
            managed_cert.last_validated = datetime.now(timezone.utc)
            
        except Exception as e:
            logger.warning(f"Certificate validation failed for {managed_cert.certificate_id}: {e}")
    
    def _add_to_monitoring(self, managed_cert: ManagedCertificate):
        """Add certificate to expiration monitoring."""
        try:
            if not self.expiration_monitor:
                return
            
            # Prepare metadata for monitoring
            cert_metadata = {}
            if managed_cert.metadata:
                cert_metadata = {
                    'edipi': managed_cert.metadata.dod_identifiers.edipi,
                    'dod_id': managed_cert.metadata.dod_identifiers.dod_id,
                    'certificate_type': managed_cert.metadata.category.value
                }
            
            self.expiration_monitor.add_certificate_for_monitoring(
                managed_cert.certificate, cert_metadata
            )
            managed_cert.is_monitored = True
            
        except Exception as e:
            logger.warning(f"Failed to add certificate to monitoring: {e}")
    
    def _get_certificate_id(self, certificate: x509.Certificate) -> str:
        """Generate unique certificate ID."""
        from cryptography.hazmat.primitives import serialization
        import hashlib
        
        cert_der = certificate.public_bytes(serialization.Encoding.DER)
        return f"cert_{hashlib.sha256(cert_der).hexdigest()[:16]}"
    
    def _update_statistics(self):
        """Update management statistics."""
        with self._registry_lock:
            certificates = list(self._managed_certificates.values())
        
        self._stats['total_certificates'] = len(certificates)
        self._stats['valid_certificates'] = len([c for c in certificates if c.is_valid])
        self._stats['dod_certificates'] = len([c for c in certificates if c.is_dod_certificate])
        self._stats['monitored_certificates'] = len([c for c in certificates if c.is_monitored])
        self._stats['smart_card_certificates'] = len([c for c in certificates if c.source == "smart_card"])
        self._stats['trust_store_certificates'] = len([c for c in certificates if c.source == "trust_store"])
        
        if self.expiration_monitor:
            active_alerts = self.expiration_monitor.get_active_alerts()
            self._stats['active_alerts'] = len(active_alerts)
    
    def get_management_statistics(self) -> Dict[str, Any]:
        """Get comprehensive management statistics."""
        self._update_statistics()
        
        stats = dict(self._stats)
        
        # Add component statistics
        if hasattr(self.validator, 'get_validation_stats'):
            stats['validation_stats'] = self.validator.get_validation_stats()
        
        if hasattr(self.trust_manager, 'get_trust_store_stats'):
            stats['trust_store_stats'] = self.trust_manager.get_trust_store_stats()
        
        if self.expiration_monitor:
            stats['monitoring_stats'] = self.expiration_monitor.get_monitoring_statistics()
        
        return stats
    
    def export_certificates(self, output_path: str, 
                          format: str = 'PEM',
                          category: CertificateCategory = None) -> int:
        """
        Export managed certificates to file.
        
        Args:
            output_path: Output file path
            format: Export format (PEM or DER)
            category: Filter by certificate category
            
        Returns:
            Number of certificates exported
        """
        try:
            certificates = self.get_all_managed_certificates(category=category, valid_only=True)
            
            if format.upper() == 'PEM':
                with open(output_path, 'w') as f:
                    for managed_cert in certificates:
                        cert_pem = managed_cert.certificate.public_bytes(
                            serialization.Encoding.PEM
                        )
                        f.write(cert_pem.decode('utf-8'))
                        f.write('\n')
            else:
                # For DER format, create individual files
                output_dir = Path(output_path).parent
                output_dir.mkdir(parents=True, exist_ok=True)
                
                for i, managed_cert in enumerate(certificates):
                    cert_der = managed_cert.certificate.public_bytes(
                        serialization.Encoding.DER
                    )
                    cert_filename = f"certificate_{i:03d}.der"
                    cert_path = output_dir / cert_filename
                    
                    with open(cert_path, 'wb') as f:
                        f.write(cert_der)
            
            logger.info(f"Exported {len(certificates)} certificates to {output_path}")
            return len(certificates)
            
        except Exception as e:
            logger.error(f"Failed to export certificates: {e}")
            return 0
    
    def cleanup(self):
        """Cleanup resources and stop background processes."""
        try:
            if self.expiration_monitor:
                self.expiration_monitor.cleanup()
            
            if hasattr(self.trust_manager, 'cleanup'):
                self.trust_manager.cleanup()
            
            if hasattr(self.extractor, 'close_session'):
                self.extractor.close_session()
            
            logger.info("Certificate manager cleanup completed")
            
        except Exception as e:
            logger.warning(f"Error during cleanup: {e}")
    
    def __del__(self):
        """Cleanup when object is destroyed."""
        self.cleanup()


# Example usage and utility functions
def main():
    """Example usage of certificate manager."""
    # Create configuration
    config = CertificateManagementConfig(
        validation_level=ValidationLevel.STANDARD,
        enable_expiration_monitoring=True,
        enable_dod_compliance_checking=True
    )
    
    # Initialize certificate manager
    manager = CertificateManager(config)
    
    # Get statistics
    stats = manager.get_management_statistics()
    print(f"Certificate management statistics: {stats}")
    
    # Try to extract smart card certificates
    try:
        smart_card_certs = manager.extract_smart_card_certificates(validate=True)
        print(f"Extracted {len(smart_card_certs)} certificates from smart card")
        
        for cert in smart_card_certs:
            print(f"  - {cert.metadata.subject_dn if cert.metadata else 'Unknown subject'}")
            print(f"    Category: {cert.metadata.category.value if cert.metadata else 'Unknown'}")
            print(f"    Valid: {cert.is_valid}")
            print(f"    Days until expiry: {cert.days_until_expiry}")
    
    except Exception as e:
        print(f"Smart card extraction failed: {e}")
    
    # Check for expiring certificates
    expiring_certs = manager.get_expiring_certificates(days_threshold=90)
    print(f"Found {len(expiring_certs)} certificates expiring within 90 days")
    
    # Perform comprehensive check
    check_results = manager.perform_comprehensive_check()
    print(f"Comprehensive check results: {check_results['statistics']}")
    
    # Cleanup
    manager.cleanup()


if __name__ == "__main__":
    from cryptography.hazmat.primitives import serialization
    main()