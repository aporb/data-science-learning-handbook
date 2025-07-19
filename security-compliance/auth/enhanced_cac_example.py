#!/usr/bin/env python3
"""
Enhanced CAC/PIV Integration Example
Demonstrates the use of all new security features
"""

import logging
import os
import sys
from datetime import datetime, timezone

# Import enhanced CAC components
from cac_piv_integration import CACPIVAuthenticator, CACAuthenticationManager
from certificate_validators import DoDBCertificateValidator, CombinedRevocationChecker
from middleware_abstraction import MiddlewareDetector, PKCS11ProviderManager
from security_managers import SecurePINManager, SessionManager, AuditLogger, AuditEventType

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class EnhancedCACDemo:
    """
    Demonstration of enhanced CAC/PIV security features
    """
    
    def __init__(self):
        """Initialize enhanced CAC demo"""
        print("🔐 Enhanced CAC/PIV Security Demo")
        print("=" * 50)
        
        # Initialize audit logging
        self.audit_logger = AuditLogger(
            log_file_path="./cac_demo_audit.log",
            enable_syslog=False
        )
        
        print("✓ Audit logging initialized")
    
    def demonstrate_middleware_detection(self):
        """Demonstrate middleware detection capabilities"""
        print("\n🔍 Middleware Detection Demo")
        print("-" * 30)
        
        try:
            # Initialize middleware detector
            detector = MiddlewareDetector()
            
            # Detect all available middleware
            middleware_list = detector.detect_all_middleware()
            
            print(f"Found {len(middleware_list)} middleware solutions:")
            
            for middleware in middleware_list:
                status = "✓ Available" if middleware.is_available else "✗ Not Available"
                print(f"  - {middleware.name} ({middleware.middleware_type.value})")
                print(f"    Status: {status}")
                print(f"    Path: {middleware.pkcs11_path}")
                print(f"    Priority: {middleware.priority}")
                print(f"    Capabilities: {', '.join(middleware.capabilities)}")
                if middleware.version:
                    print(f"    Version: {middleware.version}")
                print()
            
            # Get best middleware
            best = detector.get_best_middleware()
            if best:
                print(f"🏆 Best available middleware: {best.name}")
            else:
                print("⚠️  No middleware available")
                
        except Exception as e:
            print(f"❌ Middleware detection failed: {e}")
    
    def demonstrate_provider_management(self):
        """Demonstrate PKCS#11 provider management"""
        print("\n⚙️  PKCS#11 Provider Management Demo")
        print("-" * 40)
        
        try:
            # Initialize provider manager
            provider_manager = PKCS11ProviderManager(auto_detect=True)
            
            # Get summary of available middleware
            summary = provider_manager.get_available_middleware_summary()
            
            print("Provider Summary:")
            print(f"  Total detected: {summary['total_detected']}")
            
            if summary['best_available']:
                best = summary['best_available']
                print(f"  Best available: {best['name']} ({best['type']})")
                print(f"  Path: {best['path']}")
            
            # Attempt to initialize with fallback
            print("\nAttempting provider initialization with fallback...")
            if provider_manager.initialize_with_fallback():
                print("✓ Provider initialized successfully")
                
                # Get current provider info
                current_info = provider_manager.get_current_provider_info()
                if current_info:
                    print(f"  Active provider: {current_info.name}")
                    print(f"  Capabilities: {', '.join(current_info.capabilities)}")
            else:
                print("❌ Failed to initialize any provider")
                
        except Exception as e:
            print(f"❌ Provider management failed: {e}")
    
    def demonstrate_certificate_validation(self):
        """Demonstrate enhanced certificate validation"""
        print("\n📜 Enhanced Certificate Validation Demo")
        print("-" * 42)
        
        try:
            # Initialize enhanced validator
            validator = DoDBCertificateValidator()
            
            print("DoD Certificate Validator initialized with:")
            print(f"  - CA certificate path: {validator.dod_ca_cert_path}")
            print(f"  - OCSP validation: {validator.enable_ocsp}")
            print(f"  - CRL validation: {validator.enable_crl}")
            
            # Show supported DoD policies
            print("\nSupported DoD Certificate Policies:")
            for policy_name, oid in validator.DOD_POLICY_OIDS.items():
                print(f"  - {policy_name}: {oid}")
            
            # Get cache stats
            stats = validator.get_cache_stats()
            print(f"\nValidation cache: {stats['cached_certificates']} entries")
            
        except Exception as e:
            print(f"❌ Certificate validation demo failed: {e}")
    
    def demonstrate_revocation_checking(self):
        """Demonstrate certificate revocation checking"""
        print("\n🔍 Certificate Revocation Checking Demo")
        print("-" * 42)
        
        try:
            # Initialize combined revocation checker
            revocation_checker = CombinedRevocationChecker(
                prefer_ocsp=True,
                require_definitive_result=False
            )
            
            print("Combined revocation checker initialized:")
            print(f"  - Prefers OCSP: {revocation_checker.prefer_ocsp}")
            print(f"  - Requires definitive result: {revocation_checker.require_definitive_result}")
            
            # Show cache stats
            cache_stats = revocation_checker.get_cache_stats()
            print(f"\nRevocation cache stats:")
            print(f"  - CRL cache: {cache_stats['crl_cache']}")
            
        except Exception as e:
            print(f"❌ Revocation checking demo failed: {e}")
    
    def demonstrate_security_managers(self):
        """Demonstrate security management features"""
        print("\n🛡️  Security Management Demo")
        print("-" * 30)
        
        try:
            # PIN Manager Demo
            print("PIN Manager:")
            pin_manager = SecurePINManager(
                cache_timeout=300,  # 5 minutes
                max_cache_entries=10,
                enable_encryption=True
            )
            
            pin_stats = pin_manager.get_cache_stats()
            print(f"  - Max entries: {pin_stats['max_entries']}")
            print(f"  - Cache timeout: {pin_stats['cache_timeout']}s")
            print(f"  - Encryption: {pin_stats['encryption_enabled']}")
            print(f"  - Current entries: {pin_stats['total_entries']}")
            
            # Session Manager Demo
            print("\nSession Manager:")
            session_manager = SessionManager(
                default_timeout=3600,  # 1 hour
                max_sessions=100
            )
            
            session_stats = session_manager.get_session_stats()
            print(f"  - Default timeout: {session_stats['default_timeout']}s")
            print(f"  - Max sessions: {session_stats['max_sessions']}")
            print(f"  - Active sessions: {session_stats['active_sessions']}")
            
            # Audit Logger Demo
            print("\nAudit Logger:")
            audit_stats = self.audit_logger.get_audit_stats()
            print(f"  - Log file: {audit_stats['log_file_path']}")
            print(f"  - Max size: {audit_stats['max_log_size']} bytes")
            print(f"  - Backup count: {audit_stats['backup_count']}")
            print(f"  - Current size: {audit_stats['current_log_size']} bytes")
            
        except Exception as e:
            print(f"❌ Security managers demo failed: {e}")
    
    def demonstrate_enhanced_authentication(self):
        """Demonstrate enhanced authentication workflow"""
        print("\n🔐 Enhanced Authentication Workflow Demo")
        print("-" * 45)
        
        try:
            print("Enhanced authentication features:")
            print("  ✓ Middleware auto-detection and fallback")
            print("  ✓ DoD-compliant certificate validation")
            print("  ✓ Certificate revocation checking (CRL/OCSP)")
            print("  ✓ Secure PIN caching with encryption")
            print("  ✓ Session management with auto-logout")
            print("  ✓ Comprehensive audit logging")
            print("  ✓ Middleware compatibility layer")
            print("  ✓ Security policy enforcement")
            
            print("\nTo use enhanced authentication:")
            print("  1. Initialize CACPIVAuthenticator with enhanced features enabled")
            print("  2. Authentication automatically uses best available middleware")
            print("  3. Certificates are validated against DoD PKI hierarchy")
            print("  4. Revocation status is checked via OCSP/CRL")
            print("  5. All events are logged for audit compliance")
            print("  6. Sessions are managed with automatic timeout")
            
            # Show example code
            print("\nExample usage:")
            print("""
    # Initialize with enhanced features
    authenticator = CACPIVAuthenticator(
        enable_pin_caching=True,
        enable_enhanced_validation=True,
        session_timeout=3600
    )
    
    # Authenticate user
    if authenticator.open_session():
        if authenticator.authenticate_pin(pin, user_id="john.doe"):
            certificates = authenticator.get_certificates()
            if certificates:
                # Enhanced validation with revocation checking
                validation_result = authenticator.verify_certificate_chain(
                    certificates[0], 
                    enable_revocation_check=True
                )
                
                if validation_result.is_valid:
                    credentials = authenticator.extract_cac_credentials(certificates[0])
                    print(f"Authentication successful: {credentials.edipi}")
                else:
                    print(f"Validation failed: {validation_result.error_message}")
            """)
            
        except Exception as e:
            print(f"❌ Enhanced authentication demo failed: {e}")
    
    def demonstrate_audit_features(self):
        """Demonstrate audit logging features"""
        print("\n📊 Audit Logging Demo")
        print("-" * 22)
        
        try:
            from security_managers import AuditEvent
            
            # Log sample authentication event
            auth_event = AuditEvent(
                event_type=AuditEventType.AUTHENTICATION_SUCCESS,
                timestamp=datetime.now(timezone.utc),
                user_id="demo_user",
                session_id="demo_session_123",
                source_ip="192.168.1.100",
                success=True,
                additional_data={
                    "method": "CAC_PIN",
                    "middleware": "OpenSC",
                    "certificate_subject": "CN=DEMO.USER.1234567890"
                }
            )
            
            self.audit_logger.log_event(auth_event)
            print("✓ Authentication event logged")
            
            # Log certificate validation event
            self.audit_logger.log_certificate_validation(
                certificate_subject="CN=DEMO.USER.1234567890",
                issuer="CN=DOD ID CA-59",
                validation_result=True,
                details={
                    "validation_method": "enhanced_dod_validation",
                    "revocation_checked": True,
                    "revocation_method": "OCSP"
                }
            )
            print("✓ Certificate validation event logged")
            
            # Log signing operation
            self.audit_logger.log_signing_operation(
                user_id="demo_user",
                data_hash="sha256:abc123def456",
                success=True,
                session_id="demo_session_123"
            )
            print("✓ Signing operation event logged")
            
            print(f"\nAudit events written to: {self.audit_logger.log_file_path}")
            print("All events include timestamps, user correlation, and detailed context")
            
        except Exception as e:
            print(f"❌ Audit logging demo failed: {e}")
    
    def demonstrate_configuration_options(self):
        """Demonstrate configuration options"""
        print("\n⚙️  Configuration Options Demo")
        print("-" * 32)
        
        print("Enhanced CAC integration supports extensive configuration:")
        
        print("\n📁 Directory Structure:")
        print("  ~/.cac/")
        print("  ├── ca-certificates/     # DoD CA certificates")
        print("  ├── crl_cache/          # CRL cache directory")
        print("  ├── audit.log          # Audit log file")
        print("  └── config.json        # Configuration file")
        
        print("\n🔧 Environment Variables:")
        print("  CAC_PKCS11_LIB_PATH    # Custom PKCS#11 library path")
        print("  CAC_DEBUG              # Enable debug logging")
        print("  CAC_CARD_TIMEOUT       # Card detection timeout")
        print("  CAC_PIN_CACHE          # Enable PIN caching")
        print("  CAC_AUDIT_LOG_PATH     # Custom audit log path")
        print("  CAC_CERT_STORE_PATH    # DoD certificate store path")
        print("  CAC_OCSP_VALIDATION    # Enable OCSP validation")
        print("  CAC_CRL_CHECK          # Enable CRL checking")
        print("  NETWORK_CLASSIFICATION # Network classification level")
        
        print("\n🛡️  Security Settings:")
        print("  - PIN caching with encryption and timeout")
        print("  - Session management with auto-logout")
        print("  - Certificate validation caching")
        print("  - Audit logging with rotation")
        print("  - Network classification support")
        print("  - Middleware compatibility layer")
        
        print("\n📋 DoD Compliance Features:")
        print("  - DoD PKI certificate validation")
        print("  - Certificate policy enforcement")
        print("  - Revocation checking (CRL/OCSP)")
        print("  - Comprehensive audit trail")
        print("  - Classification level handling")
        print("  - Security violation detection")
    
    def run_demo(self):
        """Run the complete demonstration"""
        try:
            self.demonstrate_middleware_detection()
            self.demonstrate_provider_management()
            self.demonstrate_certificate_validation()
            self.demonstrate_revocation_checking()
            self.demonstrate_security_managers()
            self.demonstrate_enhanced_authentication()
            self.demonstrate_audit_features()
            self.demonstrate_configuration_options()
            
            print("\n" + "=" * 50)
            print("🎉 Enhanced CAC/PIV Security Demo Complete!")
            print("=" * 50)
            
            print("\nKey Security Enhancements:")
            print("✓ Enhanced DoD certificate validation")
            print("✓ Certificate revocation checking")
            print("✓ Middleware abstraction and fallback")
            print("✓ Secure PIN caching")
            print("✓ Session management")
            print("✓ Comprehensive audit logging")
            print("✓ DoD compliance features")
            
            print(f"\nAudit log available at: {self.audit_logger.log_file_path}")
            
        except Exception as e:
            logger.error(f"Demo failed: {e}")
            print(f"\n❌ Demo failed: {e}")

def main():
    """Main function"""
    print("Starting Enhanced CAC/PIV Security Demonstration...")
    
    try:
        demo = EnhancedCACDemo()
        demo.run_demo()
        
    except KeyboardInterrupt:
        print("\n\n⏹️  Demo interrupted by user")
    except Exception as e:
        print(f"\n❌ Fatal error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()