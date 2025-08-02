"""
Enhanced CAC-OAuth Token Binding
Provides stronger binding between CAC certificates and OAuth tokens with advanced introspection.
"""

import hashlib
import hmac
import json
import logging
import secrets
import time
from typing import Dict, List, Optional, Any, Tuple, Union
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
import threading
from urllib.parse import urlencode

import jwt
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding

# Import base components
from .oauth_client import TokenResponse, Platform
from .cac_piv_integration import CACCredentials
from .enhanced_qlik_oauth import EnhancedQlikOAuthClient
from .security_managers import AuditLogger, AuditEvent, AuditEventType

logger = logging.getLogger(__name__)


class TokenBindingStrength(Enum):
    """Token binding strength levels."""
    BASIC = "basic"  # Simple EDIPI matching
    ENHANCED = "enhanced"  # Certificate fingerprint + claims
    CRYPTOGRAPHIC = "cryptographic"  # Cryptographic proof of possession
    MULTI_FACTOR = "multi_factor"  # Multiple validation layers


class BindingValidationResult(Enum):
    """Token binding validation results."""
    VALID = "valid"
    INVALID_CERTIFICATE = "invalid_certificate"
    INVALID_SIGNATURE = "invalid_signature"
    EXPIRED_BINDING = "expired_binding"
    INSUFFICIENT_CLEARANCE = "insufficient_clearance"
    EDIPI_MISMATCH = "edipi_mismatch"
    BINDING_NOT_FOUND = "binding_not_found"


@dataclass
class CACTokenBinding:
    """Enhanced CAC-OAuth token binding record."""
    binding_id: str
    edipi: str
    certificate_fingerprint: str
    certificate_serial: str
    oauth_token_hash: str
    binding_timestamp: datetime
    expires_at: datetime
    binding_strength: TokenBindingStrength
    clearance_level: str
    organization: str
    validation_challenges: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def is_expired(self) -> bool:
        """Check if binding is expired."""
        return datetime.now(timezone.utc) >= self.expires_at
    
    def is_valid_for_token(self, token_hash: str) -> bool:
        """Check if binding is valid for a specific token."""
        return not self.is_expired() and self.oauth_token_hash == token_hash


class EnhancedCACOAuthBinder:
    """Enhanced CAC-OAuth token binding with cryptographic validation."""
    
    def __init__(self, binding_duration: timedelta = timedelta(hours=8),
                 default_strength: TokenBindingStrength = TokenBindingStrength.ENHANCED):
        """
        Initialize enhanced CAC-OAuth binder.
        
        Args:
            binding_duration: Duration for token bindings
            default_strength: Default binding strength
        """
        self.binding_duration = binding_duration
        self.default_strength = default_strength
        self.active_bindings: Dict[str, CACTokenBinding] = {}
        self.challenge_store: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.RLock()
        
        # Binding validation settings
        self.validation_settings = {
            TokenBindingStrength.BASIC: {
                "require_edipi_match": True,
                "require_certificate_validation": False,
                "require_signature_proof": False,
                "challenge_count": 0
            },
            TokenBindingStrength.ENHANCED: {
                "require_edipi_match": True,
                "require_certificate_validation": True,
                "require_signature_proof": False,
                "challenge_count": 1
            },
            TokenBindingStrength.CRYPTOGRAPHIC: {
                "require_edipi_match": True,
                "require_certificate_validation": True,
                "require_signature_proof": True,
                "challenge_count": 2
            },
            TokenBindingStrength.MULTI_FACTOR: {
                "require_edipi_match": True,
                "require_certificate_validation": True,
                "require_signature_proof": True,
                "challenge_count": 3
            }
        }
        
        logger.info(f"Enhanced CAC-OAuth binder initialized with {default_strength.value} strength")
    
    def create_binding(self, cac_credentials: CACCredentials, 
                      oauth_token: TokenResponse,
                      binding_strength: Optional[TokenBindingStrength] = None) -> Optional[CACTokenBinding]:
        """
        Create enhanced binding between CAC credentials and OAuth token.
        
        Args:
            cac_credentials: CAC credentials
            oauth_token: OAuth token
            binding_strength: Optional binding strength override
            
        Returns:
            Created binding or None if failed
        """
        with self._lock:
            try:
                strength = binding_strength or self.default_strength
                
                # Generate binding ID
                binding_id = self._generate_binding_id(cac_credentials, oauth_token)
                
                # Extract certificate information
                cert_fingerprint = self._calculate_certificate_fingerprint(cac_credentials.certificate_data)
                cert_serial = self._extract_certificate_serial(cac_credentials.certificate_data)
                
                # Hash OAuth token for privacy
                token_hash = self._hash_token(oauth_token.access_token)
                
                # Create binding
                binding = CACTokenBinding(
                    binding_id=binding_id,
                    edipi=cac_credentials.edipi,
                    certificate_fingerprint=cert_fingerprint,
                    certificate_serial=cert_serial,
                    oauth_token_hash=token_hash,
                    binding_timestamp=datetime.now(timezone.utc),
                    expires_at=min(
                        oauth_token.expires_at,
                        datetime.now(timezone.utc) + self.binding_duration
                    ),
                    binding_strength=strength,
                    clearance_level=cac_credentials.clearance_level or "UNCLASSIFIED",
                    organization=cac_credentials.organization or "Unknown",
                    metadata={
                        "token_type": oauth_token.token_type,
                        "token_scope": oauth_token.scope,
                        "created_via": "enhanced_binding"
                    }
                )
                
                # Generate validation challenges based on strength
                if strength in [TokenBindingStrength.ENHANCED, TokenBindingStrength.CRYPTOGRAPHIC, TokenBindingStrength.MULTI_FACTOR]:
                    binding.validation_challenges = self._generate_validation_challenges(
                        cac_credentials, strength
                    )
                
                # Store binding
                self.active_bindings[binding_id] = binding
                
                # Log binding creation
                AuditLogger.instance().log_event(AuditEvent(
                    event_type=AuditEventType.TOKEN_BINDING_CREATED,
                    timestamp=datetime.now(timezone.utc),
                    user_id=cac_credentials.edipi,
                    success=True,
                    additional_data={
                        "binding_id": binding_id,
                        "binding_strength": strength.value,
                        "clearance_level": cac_credentials.clearance_level,
                        "expires_at": binding.expires_at.isoformat()
                    }
                ))
                
                logger.info(f"CAC-OAuth binding created: {binding_id} (strength: {strength.value})")
                return binding
                
            except Exception as e:
                logger.error(f"Failed to create CAC-OAuth binding: {e}")
                return None
    
    def validate_binding(self, oauth_token: str, cac_credentials: CACCredentials,
                        binding_id: Optional[str] = None) -> Tuple[BindingValidationResult, Optional[CACTokenBinding]]:
        """
        Validate CAC-OAuth token binding with enhanced checks.
        
        Args:
            oauth_token: OAuth access token
            cac_credentials: CAC credentials
            binding_id: Optional specific binding ID to validate
            
        Returns:
            Tuple of (validation_result, binding)
        """
        with self._lock:
            try:
                # Find binding
                token_hash = self._hash_token(oauth_token)
                binding = None
                
                if binding_id:
                    binding = self.active_bindings.get(binding_id)
                else:
                    # Search for binding by EDIPI and token hash
                    for b in self.active_bindings.values():
                        if b.edipi == cac_credentials.edipi and b.oauth_token_hash == token_hash:
                            binding = b
                            break
                
                if not binding:
                    return BindingValidationResult.BINDING_NOT_FOUND, None
                
                # Check if binding is expired
                if binding.is_expired():
                    self._remove_binding(binding.binding_id)
                    return BindingValidationResult.EXPIRED_BINDING, None
                
                # Validate EDIPI match
                if binding.edipi != cac_credentials.edipi:
                    return BindingValidationResult.EDIPI_MISMATCH, None
                
                # Validate certificate fingerprint
                current_fingerprint = self._calculate_certificate_fingerprint(cac_credentials.certificate_data)
                if binding.certificate_fingerprint != current_fingerprint:
                    return BindingValidationResult.INVALID_CERTIFICATE, None
                
                # Validate token hash
                if not binding.is_valid_for_token(token_hash):
                    return BindingValidationResult.INVALID_SIGNATURE, None
                
                # Perform strength-specific validations
                validation_result = self._perform_strength_validation(binding, cac_credentials, oauth_token)
                if validation_result != BindingValidationResult.VALID:
                    return validation_result, binding
                
                # Log successful validation
                AuditLogger.instance().log_event(AuditEvent(
                    event_type=AuditEventType.TOKEN_BINDING_VALIDATED,
                    timestamp=datetime.now(timezone.utc),
                    user_id=cac_credentials.edipi,
                    success=True,
                    additional_data={
                        "binding_id": binding.binding_id,
                        "binding_strength": binding.binding_strength.value,
                        "validation_method": "enhanced"
                    }
                ))
                
                return BindingValidationResult.VALID, binding
                
            except Exception as e:
                logger.error(f"Binding validation error: {e}")
                return BindingValidationResult.INVALID_SIGNATURE, None
    
    def refresh_binding(self, binding_id: str, new_oauth_token: TokenResponse) -> bool:
        """
        Refresh binding with new OAuth token.
        
        Args:
            binding_id: Binding identifier
            new_oauth_token: New OAuth token
            
        Returns:
            True if refresh successful
        """
        with self._lock:
            try:
                binding = self.active_bindings.get(binding_id)
                if not binding:
                    return False
                
                # Update token hash and expiration
                binding.oauth_token_hash = self._hash_token(new_oauth_token.access_token)
                binding.expires_at = min(
                    new_oauth_token.expires_at,
                    binding.binding_timestamp + self.binding_duration
                )
                binding.metadata.update({
                    "refreshed_at": datetime.now(timezone.utc).isoformat(),
                    "token_type": new_oauth_token.token_type,
                    "token_scope": new_oauth_token.scope
                })
                
                logger.info(f"Binding refreshed: {binding_id}")
                return True
                
            except Exception as e:
                logger.error(f"Binding refresh failed: {e}")
                return False
    
    def revoke_binding(self, binding_id: str, reason: str = "user_requested") -> bool:
        """
        Revoke CAC-OAuth binding.
        
        Args:
            binding_id: Binding identifier
            reason: Revocation reason
            
        Returns:
            True if revocation successful
        """
        with self._lock:
            try:
                binding = self.active_bindings.pop(binding_id, None)
                if not binding:
                    return False
                
                # Log binding revocation
                AuditLogger.instance().log_event(AuditEvent(
                    event_type=AuditEventType.TOKEN_BINDING_REVOKED,
                    timestamp=datetime.now(timezone.utc),
                    user_id=binding.edipi,
                    success=True,
                    additional_data={
                        "binding_id": binding_id,
                        "reason": reason,
                        "binding_strength": binding.binding_strength.value
                    }
                ))
                
                logger.info(f"Binding revoked: {binding_id} (reason: {reason})")
                return True
                
            except Exception as e:
                logger.error(f"Binding revocation failed: {e}")
                return False
    
    def get_user_bindings(self, edipi: str) -> List[Dict[str, Any]]:
        """
        Get all active bindings for a user.
        
        Args:
            edipi: User EDIPI
            
        Returns:
            List of binding metadata
        """
        with self._lock:
            user_bindings = []
            current_time = datetime.now(timezone.utc)
            
            for binding in self.active_bindings.values():
                if binding.edipi == edipi and not binding.is_expired():
                    user_bindings.append({
                        "binding_id": binding.binding_id,
                        "created_at": binding.binding_timestamp.isoformat(),
                        "expires_at": binding.expires_at.isoformat(),
                        "binding_strength": binding.binding_strength.value,
                        "clearance_level": binding.clearance_level,
                        "organization": binding.organization,
                        "certificate_serial": binding.certificate_serial
                    })
            
            return user_bindings
    
    def cleanup_expired_bindings(self) -> int:
        """
        Clean up expired bindings.
        
        Returns:
            Number of bindings cleaned up
        """
        with self._lock:
            expired_bindings = []
            current_time = datetime.now(timezone.utc)
            
            for binding_id, binding in self.active_bindings.items():
                if binding.is_expired():
                    expired_bindings.append(binding_id)
            
            for binding_id in expired_bindings:
                self._remove_binding(binding_id)
            
            logger.info(f"Cleaned up {len(expired_bindings)} expired bindings")
            return len(expired_bindings)
    
    def _generate_binding_id(self, cac_credentials: CACCredentials, oauth_token: TokenResponse) -> str:
        """Generate unique binding ID."""
        data = f"{cac_credentials.edipi}:{oauth_token.access_token[:16]}:{int(time.time())}"
        return hashlib.sha256(data.encode()).hexdigest()[:32]
    
    def _calculate_certificate_fingerprint(self, cert_data: bytes) -> str:
        """Calculate certificate fingerprint."""
        return hashlib.sha256(cert_data).hexdigest()
    
    def _extract_certificate_serial(self, cert_data: bytes) -> str:
        """Extract certificate serial number."""
        try:
            cert = x509.load_der_x509_certificate(cert_data)
            return str(cert.serial_number)
        except Exception:
            return "unknown"
    
    def _hash_token(self, token: str) -> str:
        """Hash OAuth token for privacy."""
        return hashlib.sha256(token.encode()).hexdigest()
    
    def _generate_validation_challenges(self, cac_credentials: CACCredentials,
                                      strength: TokenBindingStrength) -> List[str]:
        """Generate validation challenges based on binding strength."""
        challenges = []
        challenge_count = self.validation_settings[strength]["challenge_count"]
        
        for i in range(challenge_count):
            challenge = secrets.token_urlsafe(32)
            challenges.append(challenge)
            
            # Store challenge for later validation
            self.challenge_store[challenge] = {
                "edipi": cac_credentials.edipi,
                "created_at": datetime.now(timezone.utc),
                "expires_at": datetime.now(timezone.utc) + timedelta(minutes=5),
                "strength": strength
            }
        
        return challenges
    
    def _perform_strength_validation(self, binding: CACTokenBinding,
                                   cac_credentials: CACCredentials,
                                   oauth_token: str) -> BindingValidationResult:
        """Perform validation based on binding strength."""
        try:
            settings = self.validation_settings[binding.binding_strength]
            
            # Basic validations already performed
            
            # Enhanced validation - certificate validation
            if settings["require_certificate_validation"]:
                if not self._validate_certificate_chain(cac_credentials.certificate_data):
                    return BindingValidationResult.INVALID_CERTIFICATE
            
            # Cryptographic validation - signature proof
            if settings["require_signature_proof"]:
                if not self._validate_signature_proof(binding, cac_credentials):
                    return BindingValidationResult.INVALID_SIGNATURE
            
            # Multi-factor validation - additional challenges
            if binding.binding_strength == TokenBindingStrength.MULTI_FACTOR:
                if not self._validate_multi_factor_challenges(binding, cac_credentials):
                    return BindingValidationResult.INVALID_SIGNATURE
            
            return BindingValidationResult.VALID
            
        except Exception as e:
            logger.error(f"Strength validation error: {e}")
            return BindingValidationResult.INVALID_SIGNATURE
    
    def _validate_certificate_chain(self, cert_data: bytes) -> bool:
        """Validate certificate chain (placeholder for full implementation)."""
        try:
            cert = x509.load_der_x509_certificate(cert_data)
            # In production, this would validate against DoD CA roots
            # For now, just check if certificate is parseable and not expired
            current_time = datetime.now(timezone.utc)
            return cert.not_valid_after_utc > current_time
        except Exception:
            return False
    
    def _validate_signature_proof(self, binding: CACTokenBinding,
                                cac_credentials: CACCredentials) -> bool:
        """Validate cryptographic signature proof (placeholder)."""
        try:
            # In production, this would require a signature challenge
            # For now, validate that certificate can be used for signing
            cert = x509.load_der_x509_certificate(cac_credentials.certificate_data)
            
            # Check key usage for digital signature
            try:
                key_usage = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.KEY_USAGE)
                return key_usage.value.digital_signature
            except x509.ExtensionNotFound:
                return True  # Assume valid if extension not present
                
        except Exception:
            return False
    
    def _validate_multi_factor_challenges(self, binding: CACTokenBinding,
                                        cac_credentials: CACCredentials) -> bool:
        """Validate multi-factor challenges (placeholder)."""
        # In production, this would validate response to cryptographic challenges
        # For now, check that challenges were generated
        return len(binding.validation_challenges) >= 3
    
    def _remove_binding(self, binding_id: str) -> None:
        """Remove binding and clean up associated data."""
        binding = self.active_bindings.pop(binding_id, None)
        if binding:
            # Clean up associated challenges
            for challenge in binding.validation_challenges:
                self.challenge_store.pop(challenge, None)


class TokenIntrospectionEnhancer:
    """Enhanced token introspection with CAC binding information."""
    
    def __init__(self, oauth_client: EnhancedQlikOAuthClient,
                 cac_binder: EnhancedCACOAuthBinder):
        """
        Initialize token introspection enhancer.
        
        Args:
            oauth_client: Enhanced Qlik OAuth client
            cac_binder: CAC-OAuth binder
        """
        self.oauth_client = oauth_client
        self.cac_binder = cac_binder
        
        logger.info("Token introspection enhancer initialized")
    
    def enhanced_introspect(self, access_token: str,
                          cac_credentials: Optional[CACCredentials] = None) -> Dict[str, Any]:
        """
        Perform enhanced token introspection with CAC binding information.
        
        Args:
            access_token: OAuth access token
            cac_credentials: Optional CAC credentials for binding validation
            
        Returns:
            Enhanced introspection result
        """
        try:
            # Standard OAuth introspection
            introspection = self.oauth_client.introspect_token(access_token)
            if not introspection:
                return {"active": False, "error": "introspection_failed"}
            
            # Enhance with CAC binding information
            enhanced_result = introspection.copy()
            enhanced_result["cac_binding"] = {}
            
            if cac_credentials:
                # Validate CAC binding
                validation_result, binding = self.cac_binder.validate_binding(
                    access_token, cac_credentials
                )
                
                enhanced_result["cac_binding"] = {
                    "validation_result": validation_result.value,
                    "binding_found": binding is not None
                }
                
                if binding:
                    enhanced_result["cac_binding"].update({
                        "binding_id": binding.binding_id,
                        "binding_strength": binding.binding_strength.value,
                        "edipi": binding.edipi,
                        "clearance_level": binding.clearance_level,
                        "organization": binding.organization,
                        "expires_at": binding.expires_at.isoformat()
                    })
                    
                    # Add binding-specific claims
                    enhanced_result.update({
                        "cac_bound": True,
                        "edipi": binding.edipi,
                        "clearance_level": binding.clearance_level,
                        "binding_strength": binding.binding_strength.value
                    })
            
            return enhanced_result
            
        except Exception as e:
            logger.error(f"Enhanced introspection error: {e}")
            return {"active": False, "error": f"introspection_error: {str(e)}"}
    
    def validate_token_with_binding(self, access_token: str,
                                  cac_credentials: CACCredentials) -> Tuple[bool, Dict[str, Any]]:
        """
        Validate token with comprehensive CAC binding checks.
        
        Args:
            access_token: OAuth access token
            cac_credentials: CAC credentials
            
        Returns:
            Tuple of (is_valid, validation_details)
        """
        try:
            # Enhanced introspection
            introspection = self.enhanced_introspect(access_token, cac_credentials)
            
            validation_details = {
                "token_active": introspection.get("active", False),
                "cac_binding_valid": False,
                "validation_timestamp": datetime.now(timezone.utc).isoformat()
            }
            
            if not introspection.get("active", False):
                validation_details["error"] = "token_inactive"
                return False, validation_details
            
            # Check CAC binding
            cac_binding = introspection.get("cac_binding", {})
            if cac_binding.get("validation_result") == "valid":
                validation_details["cac_binding_valid"] = True
                validation_details.update(cac_binding)
                return True, validation_details
            else:
                validation_details["error"] = f"cac_binding_invalid: {cac_binding.get('validation_result', 'unknown')}"
                return False, validation_details
            
        except Exception as e:
            logger.error(f"Token validation error: {e}")
            return False, {"error": f"validation_error: {str(e)}"}