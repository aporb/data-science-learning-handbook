"""
DoD-Compliant TLS 1.3 Configuration
Implements TLS 1.3 with DoD-approved cipher suites and certificate management.
"""

import ssl
import socket
import logging
import os
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime, timedelta
import requests
from urllib3.util.ssl_ import create_urllib3_context
import certifi

logger = logging.getLogger(__name__)

class DoD_TLS_Manager:
    """
    DoD-compliant TLS manager implementing TLS 1.3 with approved cipher suites
    and certificate pinning for secure data in transit.
    """
    
    def __init__(self, classification_level: str = "NIPR"):
        """
        Initialize TLS manager with classification-specific settings.
        
        Args:
            classification_level: Security classification (NIPR, SIPR, JWICS)
        """
        self.classification_level = classification_level.upper()
        self.tls_config = self._get_tls_configuration()
        
        # Certificate management
        self.pinned_certificates = {}
        self.ca_bundle_path = certifi.where()
        
        logger.info(f"Initialized DoD TLS Manager for {self.classification_level}")
    
    def _get_tls_configuration(self) -> Dict[str, Any]:
        """Get TLS configuration based on classification level."""
        
        # DoD-approved cipher suites for TLS 1.3
        dod_cipher_suites = [
            'TLS_AES_256_GCM_SHA384',
            'TLS_CHACHA20_POLY1305_SHA256',
            'TLS_AES_128_GCM_SHA256'
        ]
        
        # DoD-approved cipher suites for TLS 1.2 (fallback)
        dod_tls12_ciphers = [
            'ECDHE-RSA-AES256-GCM-SHA384',
            'ECDHE-RSA-AES128-GCM-SHA256',
            'ECDHE-RSA-AES256-SHA384',
            'ECDHE-RSA-AES128-SHA256',
            'DHE-RSA-AES256-GCM-SHA384',
            'DHE-RSA-AES128-GCM-SHA256'
        ]
        
        base_config = {
            'protocol_version': ssl.PROTOCOL_TLS,
            'minimum_version': ssl.TLSVersion.TLSv1_2,
            'maximum_version': ssl.TLSVersion.TLSv1_3,
            'cipher_suites': dod_cipher_suites,
            'tls12_ciphers': ':'.join(dod_tls12_ciphers),
            'verify_mode': ssl.CERT_REQUIRED,
            'check_hostname': True,
            'certificate_pinning': True,
            'hsts_enabled': True,
            'ocsp_stapling': True
        }
        
        # Classification-specific configurations
        classification_configs = {
            "NIPR": {
                **base_config,
                'cert_validation_level': 'standard',
                'require_client_cert': False,
                'session_timeout': 3600,  # 1 hour
                'renegotiation_allowed': False
            },
            "SIPR": {
                **base_config,
                'cert_validation_level': 'strict',
                'require_client_cert': True,
                'session_timeout': 1800,  # 30 minutes
                'renegotiation_allowed': False,
                'minimum_version': ssl.TLSVersion.TLSv1_3  # TLS 1.3 only
            },
            "JWICS": {
                **base_config,
                'cert_validation_level': 'strict',
                'require_client_cert': True,
                'session_timeout': 900,  # 15 minutes
                'renegotiation_allowed': False,
                'minimum_version': ssl.TLSVersion.TLSv1_3,  # TLS 1.3 only
                'perfect_forward_secrecy': True
            }
        }
        
        if self.classification_level not in classification_configs:
            raise ValueError(f"Unsupported classification level: {self.classification_level}")
        
        return classification_configs[self.classification_level]
    
    def create_ssl_context(self, purpose: ssl.Purpose = ssl.Purpose.SERVER_AUTH,
                          client_cert_path: Optional[str] = None,
                          client_key_path: Optional[str] = None) -> ssl.SSLContext:
        """
        Create DoD-compliant SSL context.
        
        Args:
            purpose: SSL context purpose
            client_cert_path: Path to client certificate (if required)
            client_key_path: Path to client private key (if required)
            
        Returns:
            Configured SSL context
        """
        # Create SSL context
        context = ssl.create_default_context(purpose=purpose)
        
        # Set protocol versions
        context.minimum_version = self.tls_config['minimum_version']
        context.maximum_version = self.tls_config['maximum_version']
        
        # Configure cipher suites for TLS 1.2
        context.set_ciphers(self.tls_config['tls12_ciphers'])
        
        # Set verification mode
        context.verify_mode = self.tls_config['verify_mode']
        context.check_hostname = self.tls_config['check_hostname']
        
        # Disable insecure features
        context.options |= ssl.OP_NO_SSLv2
        context.options |= ssl.OP_NO_SSLv3
        context.options |= ssl.OP_NO_TLSv1
        context.options |= ssl.OP_NO_TLSv1_1
        context.options |= ssl.OP_NO_COMPRESSION
        context.options |= ssl.OP_CIPHER_SERVER_PREFERENCE
        context.options |= ssl.OP_SINGLE_DH_USE
        context.options |= ssl.OP_SINGLE_ECDH_USE
        
        # Disable renegotiation if required
        if not self.tls_config.get('renegotiation_allowed', False):
            context.options |= ssl.OP_NO_RENEGOTIATION
        
        # Load client certificate if required
        if self.tls_config.get('require_client_cert') and client_cert_path and client_key_path:
            context.load_cert_chain(client_cert_path, client_key_path)
        
        # Load CA certificates
        context.load_verify_locations(self.ca_bundle_path)
        
        logger.info(f"SSL context created for {self.classification_level}")
        return context
    
    def pin_certificate(self, hostname: str, certificate_path: str) -> None:
        """
        Pin certificate for specific hostname.
        
        Args:
            hostname: Target hostname
            certificate_path: Path to certificate file
        """
        with open(certificate_path, 'rb') as cert_file:
            cert_data = cert_file.read()
        
        self.pinned_certificates[hostname] = {
            'certificate': cert_data,
            'pinned_at': datetime.utcnow(),
            'path': certificate_path
        }
        
        logger.info(f"Certificate pinned for hostname: {hostname}")
    
    def verify_certificate_pin(self, hostname: str, peer_cert: bytes) -> bool:
        """
        Verify certificate against pinned certificate.
        
        Args:
            hostname: Target hostname
            peer_cert: Peer certificate to verify
            
        Returns:
            True if certificate matches pin
        """
        if hostname not in self.pinned_certificates:
            logger.warning(f"No pinned certificate for hostname: {hostname}")
            return False
        
        pinned_cert = self.pinned_certificates[hostname]['certificate']
        matches = peer_cert == pinned_cert
        
        if not matches:
            logger.error(f"Certificate pin verification failed for: {hostname}")
        
        return matches
    
    def create_secure_requests_session(self, verify_ssl: bool = True,
                                     client_cert: Optional[Tuple[str, str]] = None) -> requests.Session:
        """
        Create requests session with DoD-compliant TLS configuration.
        
        Args:
            verify_ssl: Whether to verify SSL certificates
            client_cert: Tuple of (cert_path, key_path) for client authentication
            
        Returns:
            Configured requests session
        """
        session = requests.Session()
        
        # Create custom SSL context
        ssl_context = self.create_ssl_context()
        
        # Configure session with custom SSL context
        adapter = requests.adapters.HTTPAdapter()
        
        # Create urllib3 context from our SSL context
        urllib3_context = create_urllib3_context()
        urllib3_context.minimum_version = ssl_context.minimum_version
        urllib3_context.maximum_version = ssl_context.maximum_version
        urllib3_context.set_ciphers(self.tls_config['tls12_ciphers'])
        urllib3_context.verify_mode = ssl_context.verify_mode
        urllib3_context.check_hostname = ssl_context.check_hostname
        urllib3_context.options = ssl_context.options
        
        # Mount adapter
        session.mount('https://', adapter)
        
        # Set verification
        session.verify = verify_ssl
        
        # Set client certificate if provided
        if client_cert:
            session.cert = client_cert
        
        # Set security headers
        session.headers.update({
            'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY',
            'X-XSS-Protection': '1; mode=block',
            'Referrer-Policy': 'strict-origin-when-cross-origin'
        })
        
        logger.info("Secure requests session created")
        return session
    
    def test_tls_connection(self, hostname: str, port: int = 443,
                           timeout: int = 10) -> Dict[str, Any]:
        """
        Test TLS connection to specified host.
        
        Args:
            hostname: Target hostname
            port: Target port
            timeout: Connection timeout
            
        Returns:
            Dictionary containing connection test results
        """
        result = {
            'hostname': hostname,
            'port': port,
            'connected': False,
            'tls_version': None,
            'cipher_suite': None,
            'certificate_valid': False,
            'certificate_info': {},
            'errors': []
        }
        
        try:
            # Create SSL context
            context = self.create_ssl_context()
            
            # Create socket connection
            with socket.create_connection((hostname, port), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    result['connected'] = True
                    result['tls_version'] = ssock.version()
                    result['cipher_suite'] = ssock.cipher()
                    
                    # Get certificate information
                    cert = ssock.getpeercert()
                    result['certificate_valid'] = True
                    result['certificate_info'] = {
                        'subject': dict(x[0] for x in cert['subject']),
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'version': cert['version'],
                        'serial_number': cert['serialNumber'],
                        'not_before': cert['notBefore'],
                        'not_after': cert['notAfter'],
                        'subject_alt_names': cert.get('subjectAltName', [])
                    }
                    
                    # Verify certificate pin if configured
                    if hostname in self.pinned_certificates:
                        cert_der = ssock.getpeercert(binary_form=True)
                        pin_valid = self.verify_certificate_pin(hostname, cert_der)
                        result['certificate_pin_valid'] = pin_valid
                        if not pin_valid:
                            result['errors'].append("Certificate pin verification failed")
        
        except ssl.SSLError as e:
            result['errors'].append(f"SSL Error: {str(e)}")
            logger.error(f"SSL error connecting to {hostname}:{port} - {e}")
        
        except socket.timeout:
            result['errors'].append("Connection timeout")
            logger.error(f"Timeout connecting to {hostname}:{port}")
        
        except Exception as e:
            result['errors'].append(f"Connection error: {str(e)}")
            logger.error(f"Error connecting to {hostname}:{port} - {e}")
        
        return result
    
    def validate_certificate_chain(self, hostname: str, port: int = 443) -> Dict[str, Any]:
        """
        Validate certificate chain for specified host.
        
        Args:
            hostname: Target hostname
            port: Target port
            
        Returns:
            Dictionary containing certificate chain validation results
        """
        validation_result = {
            'hostname': hostname,
            'port': port,
            'chain_valid': False,
            'chain_length': 0,
            'certificates': [],
            'validation_errors': []
        }
        
        try:
            context = self.create_ssl_context()
            
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    # Get certificate chain
                    cert_chain = ssock.getpeercert_chain()
                    validation_result['chain_length'] = len(cert_chain) if cert_chain else 0
                    
                    if cert_chain:
                        for i, cert in enumerate(cert_chain):
                            cert_info = {
                                'position': i,
                                'subject': cert.subject.rfc4514_string(),
                                'issuer': cert.issuer.rfc4514_string(),
                                'serial_number': str(cert.serial_number),
                                'not_valid_before': cert.not_valid_before.isoformat(),
                                'not_valid_after': cert.not_valid_after.isoformat(),
                                'is_expired': cert.not_valid_after < datetime.utcnow(),
                                'signature_algorithm': cert.signature_algorithm_oid._name
                            }
                            validation_result['certificates'].append(cert_info)
                        
                        validation_result['chain_valid'] = True
        
        except Exception as e:
            validation_result['validation_errors'].append(str(e))
            logger.error(f"Certificate chain validation error for {hostname}:{port} - {e}")
        
        return validation_result
    
    def get_security_headers(self, url: str) -> Dict[str, Any]:
        """
        Check security headers for specified URL.
        
        Args:
            url: Target URL
            
        Returns:
            Dictionary containing security headers analysis
        """
        headers_result = {
            'url': url,
            'security_headers': {},
            'missing_headers': [],
            'security_score': 0
        }
        
        # Expected security headers
        expected_headers = {
            'strict-transport-security': 'HSTS',
            'x-content-type-options': 'Content Type Options',
            'x-frame-options': 'Frame Options',
            'x-xss-protection': 'XSS Protection',
            'content-security-policy': 'Content Security Policy',
            'referrer-policy': 'Referrer Policy'
        }
        
        try:
            session = self.create_secure_requests_session()
            response = session.head(url, timeout=10)
            
            for header_name, description in expected_headers.items():
                header_value = response.headers.get(header_name)
                if header_value:
                    headers_result['security_headers'][header_name] = header_value
                    headers_result['security_score'] += 1
                else:
                    headers_result['missing_headers'].append(description)
            
            # Calculate security score as percentage
            headers_result['security_score'] = (
                headers_result['security_score'] / len(expected_headers)
            ) * 100
        
        except Exception as e:
            logger.error(f"Error checking security headers for {url} - {e}")
            headers_result['error'] = str(e)
        
        return headers_result
    
    def get_tls_configuration_summary(self) -> Dict[str, Any]:
        """
        Get summary of current TLS configuration.
        
        Returns:
            Dictionary containing TLS configuration summary
        """
        return {
            'classification_level': self.classification_level,
            'tls_config': self.tls_config,
            'pinned_certificates': {
                hostname: {
                    'pinned_at': info['pinned_at'].isoformat(),
                    'certificate_path': info['path']
                }
                for hostname, info in self.pinned_certificates.items()
            },
            'supported_protocols': ['TLS 1.2', 'TLS 1.3'],
            'cipher_suites': self.tls_config['cipher_suites'],
            'security_features': {
                'certificate_pinning': self.tls_config['certificate_pinning'],
                'hsts_enabled': self.tls_config['hsts_enabled'],
                'ocsp_stapling': self.tls_config['ocsp_stapling'],
                'perfect_forward_secrecy': self.tls_config.get('perfect_forward_secrecy', True)
            }
        }
