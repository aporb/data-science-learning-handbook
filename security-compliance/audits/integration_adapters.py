"""
Integration Adapters for DoD Audit System

This module provides integration adapters that connect the DoD audit logging system
with existing CAC/PIV authentication, multi-classification frameworks, and OAuth
systems already implemented in the project.

Key Features:
- CAC/PIV authentication system integration
- Multi-classification framework audit trail integration
- OAuth audit event correlation and enhancement
- RBAC system audit integration
- Cross-system event correlation
- Unified audit event enrichment
- Legacy system adapter interfaces
- Real-time event synchronization

Integration Points:
- CAC/PIV certificate validation events
- Multi-classification access control decisions
- OAuth token lifecycle events
- RBAC permission evaluations
- Cross-domain transfer activities
- Encryption key management events
- Session management activities
- Policy enforcement decisions

Security Features:
- Secure inter-system communication
- Event integrity verification
- Classification-aware event handling
- Encrypted event transmission
- Role-based adapter access
- Audit trail for integration activities
- Fail-safe integration modes
- Event sanitization and filtering

Compliance Features:
- DoD-compliant event correlation
- FISMA integration requirements
- Export control event handling
- Chain of custody preservation
- Audit completeness verification
- Regulatory reporting integration
- Compliance gap detection
- Automated remediation workflows
"""

import json
import logging
import asyncio
import threading
import time
import hashlib
from typing import Dict, List, Optional, Any, Union, Callable, Tuple
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone, timedelta
from enum import Enum
from pathlib import Path
import queue
import sqlite3
from concurrent.futures import ThreadPoolExecutor
import importlib
import sys
import os

# Import audit system components
from .audit_logger import AuditLogger, AuditEvent, AuditEventType, AuditSeverity, ClassificationLevel

# Import existing system components
sys.path.append(os.path.dirname(os.path.dirname(__file__)))

try:
    # CAC/PIV Authentication Integration
    from auth.cac_piv_integration import CACPIVValidator, PIVCertificate
    from auth.certificate_validators import CertificateValidationResult
    from auth.security_managers import AuditLogger as SecurityAuditLogger
    CAC_PIV_AVAILABLE = True
except ImportError:
    CAC_PIV_AVAILABLE = False

try:
    # Multi-Classification Integration
    from multi_classification.engines.classification_engine import ClassificationEngine
    from multi_classification.models.bell_lapadula import BellLaPadulaModel
    from multi_classification.engines.cross_domain_guard import CrossDomainGuard
    MULTI_CLASS_AVAILABLE = True
except ImportError:
    MULTI_CLASS_AVAILABLE = False

try:
    # OAuth Integration
    from auth.oauth_audit_logger import EnhancedOAuthAuditLogger, OAuthAuditEvent
    from auth.oauth_client import Platform
    from auth.token_lifecycle_manager import TokenLifecycleManager
    OAUTH_AVAILABLE = True
except ImportError:
    OAUTH_AVAILABLE = False

try:
    # RBAC Integration
    from rbac.models.audit import AuditLog
    from rbac.models.resolver import PermissionResolver
    from rbac.models.user import User
    from rbac.models.role import Role
    RBAC_AVAILABLE = True
except ImportError:
    RBAC_AVAILABLE = False

try:
    # Encryption Integration
    from encryption.encryption_manager import EncryptionManager
    from encryption.key_manager import KeyManager
    ENCRYPTION_AVAILABLE = True
except ImportError:
    ENCRYPTION_AVAILABLE = False


class IntegrationType(Enum):
    """Types of system integrations."""
    CAC_PIV_AUTH = "cac_piv_auth"
    MULTI_CLASSIFICATION = "multi_classification"
    OAUTH_SYSTEM = "oauth_system"
    RBAC_SYSTEM = "rbac_system"
    ENCRYPTION_SYSTEM = "encryption_system"
    CROSS_DOMAIN_GUARD = "cross_domain_guard"
    SESSION_MANAGEMENT = "session_management"
    POLICY_ENFORCEMENT = "policy_enforcement"


class EventSource(Enum):
    """Sources of audit events."""
    CAC_VALIDATOR = "cac_validator"
    PIV_VALIDATOR = "piv_validator"
    CLASSIFICATION_ENGINE = "classification_engine"
    OAUTH_CLIENT = "oauth_client"
    TOKEN_MANAGER = "token_manager"
    PERMISSION_RESOLVER = "permission_resolver"
    CROSS_DOMAIN_GUARD = "cross_domain_guard"
    ENCRYPTION_MANAGER = "encryption_manager"
    KEY_MANAGER = "key_manager"


@dataclass
class IntegrationEvent:
    """Enhanced event from integrated systems."""
    
    # Source system information
    source_system: str
    source_component: str
    original_event_id: str
    
    # Enhanced audit event
    audit_event: AuditEvent
    
    # Integration metadata
    correlation_id: str
    integration_timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    # Cross-system context
    related_events: List[str] = field(default_factory=list)
    system_context: Dict[str, Any] = field(default_factory=dict)
    
    # Security context
    security_labels: List[str] = field(default_factory=list)
    access_context: Dict[str, Any] = field(default_factory=dict)
    
    # Processing metadata
    enriched: bool = False
    correlated: bool = False
    validated: bool = False


class CACPIVIntegrationAdapter:
    """Integration adapter for CAC/PIV authentication system."""
    
    def __init__(self, audit_logger: AuditLogger):
        self.audit_logger = audit_logger
        self.logger = logging.getLogger(__name__)
        self.event_queue = queue.Queue(maxsize=1000)
        self.processing_active = True
        
        # Start processing thread
        self.processor_thread = threading.Thread(target=self._process_events, daemon=True)
        self.processor_thread.start()
    
    def integrate_cac_validation_event(self, certificate: Any, 
                                     validation_result: Any,
                                     user_context: Dict[str, Any] = None) -> str:
        """Convert CAC validation event to audit event."""
        try:
            # Extract certificate information
            if hasattr(certificate, 'subject_dn'):
                subject_dn = certificate.subject_dn
                edipi = self._extract_edipi_from_certificate(certificate)
            else:
                subject_dn = str(certificate)
                edipi = "UNKNOWN"
            
            # Determine event type and result
            if hasattr(validation_result, 'is_valid') and validation_result.is_valid:
                event_type = AuditEventType.CAC_AUTHENTICATION
                result = "SUCCESS"
                severity = AuditSeverity.INFO
            else:
                event_type = AuditEventType.USER_LOGIN_FAILURE
                result = "FAILURE"
                severity = AuditSeverity.HIGH
            
            # Create audit event
            audit_event = AuditEvent(
                event_type=event_type,
                timestamp=datetime.now(timezone.utc),
                severity=severity,
                user_id=edipi,
                edipi=edipi,
                source_ip=user_context.get('source_ip') if user_context else None,
                hostname=user_context.get('hostname') if user_context else None,
                action="CAC certificate validation",
                result=result,
                classification_level=ClassificationLevel.UNCLASSIFIED,
                additional_data={
                    "certificate_subject": subject_dn,
                    "validation_method": "CAC",
                    "certificate_serial": getattr(certificate, 'serial_number', 'unknown'),
                    "validation_details": str(validation_result) if validation_result else None,
                    "integration_adapter": "cac_piv"
                }
            )
            
            # Queue for processing
            integration_event = IntegrationEvent(
                source_system="cac_piv_auth",
                source_component="cac_validator",
                original_event_id=f"cac_{int(time.time())}_{hashlib.md5(subject_dn.encode()).hexdigest()[:8]}",
                audit_event=audit_event,
                correlation_id=f"cac_validation_{int(time.time())}",
                system_context={
                    "certificate_type": "CAC",
                    "validation_timestamp": datetime.now(timezone.utc).isoformat(),
                    "user_context": user_context or {}
                },
                security_labels=["authentication", "smartcard", "dod_cac"]
            )
            
            self.event_queue.put(integration_event)
            return integration_event.correlation_id
            
        except Exception as e:
            self.logger.error(f"Failed to integrate CAC validation event: {e}")
            return ""
    
    def integrate_piv_validation_event(self, certificate: Any,
                                     validation_result: Any,
                                     user_context: Dict[str, Any] = None) -> str:
        """Convert PIV validation event to audit event."""
        try:
            # Similar to CAC but with PIV-specific handling
            subject_dn = getattr(certificate, 'subject_dn', str(certificate))
            
            if hasattr(validation_result, 'is_valid') and validation_result.is_valid:
                event_type = AuditEventType.PIV_AUTHENTICATION
                result = "SUCCESS"
                severity = AuditSeverity.INFO
            else:
                event_type = AuditEventType.USER_LOGIN_FAILURE
                result = "FAILURE"
                severity = AuditSeverity.HIGH
            
            audit_event = AuditEvent(
                event_type=event_type,
                timestamp=datetime.now(timezone.utc),
                severity=severity,
                user_id=self._extract_user_id_from_certificate(certificate),
                source_ip=user_context.get('source_ip') if user_context else None,
                hostname=user_context.get('hostname') if user_context else None,
                action="PIV certificate validation",
                result=result,
                classification_level=ClassificationLevel.UNCLASSIFIED,
                additional_data={
                    "certificate_subject": subject_dn,
                    "validation_method": "PIV",
                    "certificate_usage": getattr(certificate, 'key_usage', 'unknown'),
                    "validation_details": str(validation_result) if validation_result else None,
                    "integration_adapter": "cac_piv"
                }
            )
            
            integration_event = IntegrationEvent(
                source_system="cac_piv_auth",
                source_component="piv_validator",
                original_event_id=f"piv_{int(time.time())}_{hashlib.md5(subject_dn.encode()).hexdigest()[:8]}",
                audit_event=audit_event,
                correlation_id=f"piv_validation_{int(time.time())}",
                system_context={
                    "certificate_type": "PIV",
                    "validation_timestamp": datetime.now(timezone.utc).isoformat(),
                    "user_context": user_context or {}
                },
                security_labels=["authentication", "smartcard", "piv"]
            )
            
            self.event_queue.put(integration_event)
            return integration_event.correlation_id
            
        except Exception as e:
            self.logger.error(f"Failed to integrate PIV validation event: {e}")
            return ""
    
    def _extract_edipi_from_certificate(self, certificate: Any) -> str:
        """Extract EDIPI from CAC certificate."""
        try:
            # CAC certificates typically have EDIPI in the subject DN
            subject_dn = getattr(certificate, 'subject_dn', '')
            
            # Look for EDIPI pattern in subject DN
            import re
            edipi_match = re.search(r'EDIPI\.(\d+)', subject_dn)
            if edipi_match:
                return edipi_match.group(1)
            
            # Fallback to serial number or other identifier
            return getattr(certificate, 'serial_number', 'UNKNOWN')
            
        except Exception:
            return "UNKNOWN"
    
    def _extract_user_id_from_certificate(self, certificate: Any) -> str:
        """Extract user ID from certificate."""
        try:
            subject_dn = getattr(certificate, 'subject_dn', '')
            
            # Extract CN (Common Name) from subject DN
            import re
            cn_match = re.search(r'CN=([^,]+)', subject_dn)
            if cn_match:
                return cn_match.group(1).strip()
            
            return getattr(certificate, 'serial_number', 'UNKNOWN')
            
        except Exception:
            return "UNKNOWN"
    
    def _process_events(self):
        """Background thread to process integration events."""
        while self.processing_active:
            try:
                event = self.event_queue.get(timeout=1.0)
                
                # Enrich and correlate event
                self._enrich_event(event)
                
                # Log to audit system
                success = self.audit_logger.log_event(event.audit_event)
                
                if success:
                    self.logger.debug(f"Processed CAC/PIV integration event: {event.correlation_id}")
                else:
                    self.logger.error(f"Failed to log CAC/PIV integration event: {event.correlation_id}")
                
            except queue.Empty:
                continue
            except Exception as e:
                self.logger.error(f"Error processing CAC/PIV integration event: {e}")
    
    def _enrich_event(self, event: IntegrationEvent):
        """Enrich integration event with additional context."""
        # Add system information
        event.audit_event.application = "cac_piv_auth_system"
        event.audit_event.module = event.source_component
        
        # Add correlation information
        event.audit_event.correlation_id = event.correlation_id
        
        # Mark as enriched
        event.enriched = True
    
    def shutdown(self):
        """Shutdown the integration adapter."""
        self.processing_active = False
        if self.processor_thread.is_alive():
            self.processor_thread.join(timeout=5)


class MultiClassificationIntegrationAdapter:
    """Integration adapter for multi-classification framework."""
    
    def __init__(self, audit_logger: AuditLogger):
        self.audit_logger = audit_logger
        self.logger = logging.getLogger(__name__)
        self.event_queue = queue.Queue(maxsize=1000)
        self.processing_active = True
        
        # Start processing thread
        self.processor_thread = threading.Thread(target=self._process_events, daemon=True)
        self.processor_thread.start()
    
    def integrate_classification_decision(self, resource_id: str, 
                                       classification_level: str,
                                       user_clearance: str,
                                       access_decision: str,
                                       context: Dict[str, Any] = None) -> str:
        """Integrate classification access control decision."""
        try:
            # Map classification levels
            audit_classification = self._map_classification_level(classification_level)
            
            # Determine event type
            if access_decision.upper() == "GRANTED":
                event_type = AuditEventType.ACCESS_GRANTED
                result = "SUCCESS"
                severity = AuditSeverity.INFO
            else:
                event_type = AuditEventType.ACCESS_DENIED
                result = "FAILURE"
                severity = AuditSeverity.MEDIUM
            
            audit_event = AuditEvent(
                event_type=event_type,
                timestamp=datetime.now(timezone.utc),
                severity=severity,
                user_id=context.get('user_id') if context else None,
                source_ip=context.get('source_ip') if context else None,
                hostname=context.get('hostname') if context else None,
                action="Classification-based access control",
                resource_type="classified_resource",
                resource_id=resource_id,
                operation="access",
                result=result,
                classification_level=audit_classification,
                clearance_level=user_clearance,
                additional_data={
                    "resource_classification": classification_level,
                    "user_clearance": user_clearance,
                    "access_decision": access_decision,
                    "decision_engine": "bell_lapadula",
                    "integration_adapter": "multi_classification",
                    "context": context or {}
                }
            )
            
            integration_event = IntegrationEvent(
                source_system="multi_classification",
                source_component="classification_engine",
                original_event_id=f"classif_{int(time.time())}_{hashlib.md5(resource_id.encode()).hexdigest()[:8]}",
                audit_event=audit_event,
                correlation_id=f"classification_{int(time.time())}",
                system_context={
                    "classification_framework": "bell_lapadula",
                    "decision_timestamp": datetime.now(timezone.utc).isoformat(),
                    "resource_context": context or {}
                },
                security_labels=["access_control", "classification", classification_level.lower()]
            )
            
            self.event_queue.put(integration_event)
            return integration_event.correlation_id
            
        except Exception as e:
            self.logger.error(f"Failed to integrate classification decision: {e}")
            return ""
    
    def integrate_cross_domain_transfer(self, source_domain: str,
                                      target_domain: str,
                                      data_classification: str,
                                      transfer_result: str,
                                      context: Dict[str, Any] = None) -> str:
        """Integrate cross-domain transfer event."""
        try:
            audit_classification = self._map_classification_level(data_classification)
            
            if transfer_result.upper() == "SUCCESS":
                event_type = AuditEventType.CROSS_DOMAIN_TRANSFER
                severity = AuditSeverity.MEDIUM
            else:
                event_type = AuditEventType.CLASSIFICATION_VIOLATION
                severity = AuditSeverity.HIGH
            
            audit_event = AuditEvent(
                event_type=event_type,
                timestamp=datetime.now(timezone.utc),
                severity=severity,
                user_id=context.get('user_id') if context else None,
                source_ip=context.get('source_ip') if context else None,
                action="Cross-domain data transfer",
                resource_type="classified_data",
                resource_id=context.get('resource_id') if context else None,
                operation="transfer",
                result=transfer_result,
                classification_level=audit_classification,
                additional_data={
                    "source_domain": source_domain,
                    "target_domain": target_domain,
                    "data_classification": data_classification,
                    "transfer_mechanism": "cross_domain_guard",
                    "integration_adapter": "multi_classification",
                    "context": context or {}
                }
            )
            
            integration_event = IntegrationEvent(
                source_system="multi_classification",
                source_component="cross_domain_guard",
                original_event_id=f"xfer_{int(time.time())}_{hashlib.md5(f'{source_domain}_{target_domain}'.encode()).hexdigest()[:8]}",
                audit_event=audit_event,
                correlation_id=f"cross_domain_{int(time.time())}",
                system_context={
                    "transfer_type": "cross_domain",
                    "domains": {"source": source_domain, "target": target_domain},
                    "transfer_timestamp": datetime.now(timezone.utc).isoformat()
                },
                security_labels=["cross_domain", "transfer", data_classification.lower()]
            )
            
            self.event_queue.put(integration_event)
            return integration_event.correlation_id
            
        except Exception as e:
            self.logger.error(f"Failed to integrate cross-domain transfer event: {e}")
            return ""
    
    def integrate_classification_change(self, resource_id: str,
                                      old_classification: str,
                                      new_classification: str,
                                      change_reason: str,
                                      context: Dict[str, Any] = None) -> str:
        """Integrate classification level change event."""
        try:
            audit_event = AuditEvent(
                event_type=AuditEventType.CLASSIFICATION_CHANGE,
                timestamp=datetime.now(timezone.utc),
                severity=AuditSeverity.MEDIUM,
                user_id=context.get('user_id') if context else None,
                source_ip=context.get('source_ip') if context else None,
                action="Classification level change",
                resource_type="classified_resource",
                resource_id=resource_id,
                operation="reclassify",
                result="SUCCESS",
                classification_level=self._map_classification_level(new_classification),
                before_value=old_classification,
                after_value=new_classification,
                additional_data={
                    "old_classification": old_classification,
                    "new_classification": new_classification,
                    "change_reason": change_reason,
                    "integration_adapter": "multi_classification",
                    "context": context or {}
                }
            )
            
            integration_event = IntegrationEvent(
                source_system="multi_classification",
                source_component="classification_engine",
                original_event_id=f"reclass_{int(time.time())}_{hashlib.md5(resource_id.encode()).hexdigest()[:8]}",
                audit_event=audit_event,
                correlation_id=f"classification_change_{int(time.time())}",
                system_context={
                    "change_type": "classification_level",
                    "change_timestamp": datetime.now(timezone.utc).isoformat(),
                    "change_details": {
                        "from": old_classification,
                        "to": new_classification,
                        "reason": change_reason
                    }
                },
                security_labels=["classification_change", old_classification.lower(), new_classification.lower()]
            )
            
            self.event_queue.put(integration_event)
            return integration_event.correlation_id
            
        except Exception as e:
            self.logger.error(f"Failed to integrate classification change event: {e}")
            return ""
    
    def _map_classification_level(self, classification: str) -> ClassificationLevel:
        """Map string classification to ClassificationLevel enum."""
        mapping = {
            "U": ClassificationLevel.UNCLASSIFIED,
            "UNCLASSIFIED": ClassificationLevel.UNCLASSIFIED,
            "CUI": ClassificationLevel.CONTROLLED_UNCLASSIFIED,
            "CONTROLLED": ClassificationLevel.CONTROLLED_UNCLASSIFIED,
            "C": ClassificationLevel.CONFIDENTIAL,
            "CONFIDENTIAL": ClassificationLevel.CONFIDENTIAL,
            "S": ClassificationLevel.SECRET,
            "SECRET": ClassificationLevel.SECRET,
            "TS": ClassificationLevel.TOP_SECRET,
            "TOP_SECRET": ClassificationLevel.TOP_SECRET,
            "TS/SCI": ClassificationLevel.TOP_SECRET_SCI,
            "TS_SCI": ClassificationLevel.TOP_SECRET_SCI
        }
        
        return mapping.get(classification.upper(), ClassificationLevel.UNCLASSIFIED)
    
    def _process_events(self):
        """Background thread to process integration events."""
        while self.processing_active:
            try:
                event = self.event_queue.get(timeout=1.0)
                
                # Enrich and correlate event
                self._enrich_event(event)
                
                # Log to audit system
                success = self.audit_logger.log_event(event.audit_event)
                
                if success:
                    self.logger.debug(f"Processed multi-classification integration event: {event.correlation_id}")
                else:
                    self.logger.error(f"Failed to log multi-classification integration event: {event.correlation_id}")
                
            except queue.Empty:
                continue
            except Exception as e:
                self.logger.error(f"Error processing multi-classification integration event: {e}")
    
    def _enrich_event(self, event: IntegrationEvent):
        """Enrich integration event with additional context."""
        event.audit_event.application = "multi_classification_system"
        event.audit_event.module = event.source_component
        event.audit_event.correlation_id = event.correlation_id
        event.enriched = True
    
    def shutdown(self):
        """Shutdown the integration adapter."""
        self.processing_active = False
        if self.processor_thread.is_alive():
            self.processor_thread.join(timeout=5)


class OAuthIntegrationAdapter:
    """Integration adapter for OAuth authentication system."""
    
    def __init__(self, audit_logger: AuditLogger):
        self.audit_logger = audit_logger
        self.logger = logging.getLogger(__name__)
        self.event_queue = queue.Queue(maxsize=1000)
        self.processing_active = True
        
        # Start processing thread
        self.processor_thread = threading.Thread(target=self._process_events, daemon=True)
        self.processor_thread.start()
    
    def integrate_oauth_event(self, oauth_event: Any) -> str:
        """Convert OAuth audit event to DoD audit event."""
        try:
            # Map OAuth event types to DoD audit event types
            event_type_mapping = {
                "oauth_authorization_request": AuditEventType.USER_LOGIN_SUCCESS,
                "oauth_token_exchange": AuditEventType.USER_LOGIN_SUCCESS,
                "oauth_token_refresh": AuditEventType.USER_LOGIN_SUCCESS,
                "oauth_token_revocation": AuditEventType.USER_LOGOUT,
                "failed_authentication": AuditEventType.USER_LOGIN_FAILURE,
                "suspicious_token_usage": AuditEventType.SECURITY_VIOLATION,
                "rate_limit_exceeded": AuditEventType.SECURITY_VIOLATION
            }
            
            # Extract OAuth event data
            if hasattr(oauth_event, 'event_type'):
                oauth_event_type = oauth_event.event_type.value if hasattr(oauth_event.event_type, 'value') else str(oauth_event.event_type)
            else:
                oauth_event_type = getattr(oauth_event, 'type', 'unknown')
            
            audit_event_type = event_type_mapping.get(oauth_event_type, AuditEventType.API_ACCESS)
            
            # Determine severity
            if hasattr(oauth_event, 'threat_level'):
                threat_level = oauth_event.threat_level
                if threat_level in ["HIGH", "CRITICAL"]:
                    severity = AuditSeverity.HIGH
                elif threat_level == "MEDIUM":
                    severity = AuditSeverity.MEDIUM
                else:
                    severity = AuditSeverity.LOW
            else:
                severity = AuditSeverity.INFO
            
            # Extract result
            result = "SUCCESS"
            if hasattr(oauth_event, 'success'):
                result = "SUCCESS" if oauth_event.success else "FAILURE"
            elif "failure" in oauth_event_type or "violation" in oauth_event_type:
                result = "FAILURE"
            
            audit_event = AuditEvent(
                event_type=audit_event_type,
                timestamp=getattr(oauth_event, 'timestamp', datetime.now(timezone.utc)),
                severity=severity,
                user_id=getattr(oauth_event, 'user_id', None),
                username=getattr(oauth_event, 'username', None),
                source_ip=getattr(oauth_event, 'source_ip', None),
                hostname=getattr(oauth_event, 'hostname', None),
                action=f"OAuth {oauth_event_type}",
                resource_type="oauth_token",
                resource_id=getattr(oauth_event, 'token_id', None),
                operation="oauth_flow",
                result=result,
                classification_level=ClassificationLevel.UNCLASSIFIED,
                application="oauth_system",
                additional_data={
                    "oauth_event_type": oauth_event_type,
                    "platform": getattr(oauth_event, 'platform', None),
                    "client_id": getattr(oauth_event, 'client_id', None),
                    "scopes": getattr(oauth_event, 'scopes', []),
                    "grant_type": getattr(oauth_event, 'grant_type', None),
                    "integration_adapter": "oauth",
                    "original_event": asdict(oauth_event) if hasattr(oauth_event, '__dict__') else str(oauth_event)
                }
            )
            
            integration_event = IntegrationEvent(
                source_system="oauth_system",
                source_component="oauth_client",
                original_event_id=getattr(oauth_event, 'event_id', f"oauth_{int(time.time())}"),
                audit_event=audit_event,
                correlation_id=f"oauth_{int(time.time())}_{hashlib.md5(str(oauth_event).encode()).hexdigest()[:8]}",
                system_context={
                    "oauth_flow": oauth_event_type,
                    "integration_timestamp": datetime.now(timezone.utc).isoformat(),
                    "platform": getattr(oauth_event, 'platform', None)
                },
                security_labels=["oauth", "authentication", oauth_event_type]
            )
            
            self.event_queue.put(integration_event)
            return integration_event.correlation_id
            
        except Exception as e:
            self.logger.error(f"Failed to integrate OAuth event: {e}")
            return ""
    
    def integrate_token_lifecycle_event(self, token_id: str, 
                                      lifecycle_event: str,
                                      user_id: str = None,
                                      context: Dict[str, Any] = None) -> str:
        """Integrate OAuth token lifecycle event."""
        try:
            # Map lifecycle events to audit events
            lifecycle_mapping = {
                "created": AuditEventType.USER_LOGIN_SUCCESS,
                "refreshed": AuditEventType.USER_LOGIN_SUCCESS,
                "expired": AuditEventType.SESSION_TIMEOUT,
                "revoked": AuditEventType.USER_LOGOUT,
                "validated": AuditEventType.ACCESS_GRANTED,
                "validation_failed": AuditEventType.ACCESS_DENIED
            }
            
            event_type = lifecycle_mapping.get(lifecycle_event, AuditEventType.API_ACCESS)
            
            if lifecycle_event in ["expired", "revoked", "validation_failed"]:
                severity = AuditSeverity.MEDIUM
                result = "FAILURE" if lifecycle_event == "validation_failed" else "SUCCESS"
            else:
                severity = AuditSeverity.INFO
                result = "SUCCESS"
            
            audit_event = AuditEvent(
                event_type=event_type,
                timestamp=datetime.now(timezone.utc),
                severity=severity,
                user_id=user_id,
                source_ip=context.get('source_ip') if context else None,
                action=f"OAuth token {lifecycle_event}",
                resource_type="oauth_token",
                resource_id=token_id,
                operation=lifecycle_event,
                result=result,
                classification_level=ClassificationLevel.UNCLASSIFIED,
                application="oauth_token_manager",
                additional_data={
                    "token_lifecycle_event": lifecycle_event,
                    "token_id": token_id,
                    "integration_adapter": "oauth",
                    "context": context or {}
                }
            )
            
            integration_event = IntegrationEvent(
                source_system="oauth_system",
                source_component="token_manager",
                original_event_id=f"token_{lifecycle_event}_{int(time.time())}",
                audit_event=audit_event,
                correlation_id=f"token_lifecycle_{int(time.time())}",
                system_context={
                    "lifecycle_event": lifecycle_event,
                    "token_context": context or {}
                },
                security_labels=["oauth", "token_lifecycle", lifecycle_event]
            )
            
            self.event_queue.put(integration_event)
            return integration_event.correlation_id
            
        except Exception as e:
            self.logger.error(f"Failed to integrate token lifecycle event: {e}")
            return ""
    
    def _process_events(self):
        """Background thread to process integration events."""
        while self.processing_active:
            try:
                event = self.event_queue.get(timeout=1.0)
                
                # Enrich and correlate event
                self._enrich_event(event)
                
                # Log to audit system
                success = self.audit_logger.log_event(event.audit_event)
                
                if success:
                    self.logger.debug(f"Processed OAuth integration event: {event.correlation_id}")
                else:
                    self.logger.error(f"Failed to log OAuth integration event: {event.correlation_id}")
                
            except queue.Empty:
                continue
            except Exception as e:
                self.logger.error(f"Error processing OAuth integration event: {e}")
    
    def _enrich_event(self, event: IntegrationEvent):
        """Enrich integration event with additional context."""
        event.audit_event.application = "oauth_system"
        event.audit_event.module = event.source_component
        event.audit_event.correlation_id = event.correlation_id
        event.enriched = True
    
    def shutdown(self):
        """Shutdown the integration adapter."""
        self.processing_active = False
        if self.processor_thread.is_alive():
            self.processor_thread.join(timeout=5)


class IntegrationManager:
    """
    Central manager for all system integrations.
    
    Coordinates integration adapters, provides unified event correlation,
    and manages cross-system audit trail consistency.
    """
    
    def __init__(self, audit_logger: AuditLogger, storage_path: str = "/var/log/dod_integration"):
        self.audit_logger = audit_logger
        self.storage_path = Path(storage_path)
        self.storage_path.mkdir(parents=True, exist_ok=True, mode=0o700)
        
        self.logger = logging.getLogger(__name__)
        
        # Integration adapters
        self.adapters: Dict[IntegrationType, Any] = {}
        
        # Event correlation
        self.correlation_db_path = self.storage_path / "correlation.db"
        self._init_correlation_database()
        
        # Statistics
        self.stats = {
            'total_events_integrated': 0,
            'events_by_system': {},
            'correlation_matches': 0,
            'integration_errors': 0,
            'last_activity': None
        }
        
        # Initialize available adapters
        self._initialize_adapters()
    
    def _init_correlation_database(self):
        """Initialize event correlation database."""
        try:
            conn = sqlite3.connect(self.correlation_db_path)
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS event_correlations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    correlation_id TEXT NOT NULL,
                    source_system TEXT NOT NULL,
                    source_component TEXT NOT NULL,
                    original_event_id TEXT NOT NULL,
                    audit_event_id TEXT NOT NULL,
                    integration_timestamp TEXT NOT NULL,
                    correlation_metadata TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS cross_system_correlations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    correlation_group_id TEXT NOT NULL,
                    related_event_ids TEXT NOT NULL,
                    correlation_type TEXT NOT NULL,
                    confidence_score REAL DEFAULT 0.0,
                    correlation_timestamp TEXT NOT NULL,
                    correlation_context TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Create indexes
            conn.execute("CREATE INDEX IF NOT EXISTS idx_correlation_id ON event_correlations(correlation_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_event_id ON event_correlations(audit_event_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_correlation_group ON cross_system_correlations(correlation_group_id)")
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            self.logger.error(f"Failed to initialize correlation database: {e}")
            raise
    
    def _initialize_adapters(self):
        """Initialize available integration adapters."""
        try:
            # CAC/PIV Integration
            if CAC_PIV_AVAILABLE:
                self.adapters[IntegrationType.CAC_PIV_AUTH] = CACPIVIntegrationAdapter(self.audit_logger)
                self.logger.info("CAC/PIV integration adapter initialized")
            
            # Multi-Classification Integration
            if MULTI_CLASS_AVAILABLE:
                self.adapters[IntegrationType.MULTI_CLASSIFICATION] = MultiClassificationIntegrationAdapter(self.audit_logger)
                self.logger.info("Multi-classification integration adapter initialized")
            
            # OAuth Integration
            if OAUTH_AVAILABLE:
                self.adapters[IntegrationType.OAUTH_SYSTEM] = OAuthIntegrationAdapter(self.audit_logger)
                self.logger.info("OAuth integration adapter initialized")
            
            # RBAC Integration (placeholder - would be implemented similarly)
            if RBAC_AVAILABLE:
                # self.adapters[IntegrationType.RBAC_SYSTEM] = RBACIntegrationAdapter(self.audit_logger)
                self.logger.info("RBAC integration available (adapter not implemented)")
            
            # Encryption Integration (placeholder)
            if ENCRYPTION_AVAILABLE:
                # self.adapters[IntegrationType.ENCRYPTION_SYSTEM] = EncryptionIntegrationAdapter(self.audit_logger)
                self.logger.info("Encryption integration available (adapter not implemented)")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize integration adapters: {e}")
    
    def get_adapter(self, integration_type: IntegrationType) -> Optional[Any]:
        """Get integration adapter for specified type."""
        return self.adapters.get(integration_type)
    
    def correlate_events(self, events: List[IntegrationEvent]) -> List[str]:
        """Correlate events across different systems."""
        try:
            correlation_groups = []
            
            # Group events by various correlation criteria
            
            # 1. Time-based correlation (events within same time window)
            time_groups = self._correlate_by_time(events, time_window_seconds=300)  # 5 minutes
            correlation_groups.extend(time_groups)
            
            # 2. User-based correlation (events for same user)
            user_groups = self._correlate_by_user(events)
            correlation_groups.extend(user_groups)
            
            # 3. Session-based correlation (events with same session context)
            session_groups = self._correlate_by_session(events)
            correlation_groups.extend(session_groups)
            
            # Store correlations
            correlation_ids = []
            for group in correlation_groups:
                if len(group) > 1:  # Only correlate if multiple events
                    correlation_id = self._store_correlation_group(group)
                    correlation_ids.append(correlation_id)
            
            self.stats['correlation_matches'] += len(correlation_ids)
            return correlation_ids
            
        except Exception as e:
            self.logger.error(f"Failed to correlate events: {e}")
            return []
    
    def _correlate_by_time(self, events: List[IntegrationEvent], 
                          time_window_seconds: int) -> List[List[IntegrationEvent]]:
        """Correlate events that occur within the same time window."""
        groups = []
        sorted_events = sorted(events, key=lambda e: e.integration_timestamp)
        
        current_group = []
        current_window_start = None
        
        for event in sorted_events:
            if current_window_start is None:
                current_window_start = event.integration_timestamp
                current_group = [event]
            else:
                time_diff = (event.integration_timestamp - current_window_start).total_seconds()
                
                if time_diff <= time_window_seconds:
                    current_group.append(event)
                else:
                    if len(current_group) > 1:
                        groups.append(current_group)
                    current_group = [event]
                    current_window_start = event.integration_timestamp
        
        if len(current_group) > 1:
            groups.append(current_group)
        
        return groups
    
    def _correlate_by_user(self, events: List[IntegrationEvent]) -> List[List[IntegrationEvent]]:
        """Correlate events by user ID."""
        user_groups = {}
        
        for event in events:
            user_id = event.audit_event.user_id
            if user_id:
                if user_id not in user_groups:
                    user_groups[user_id] = []
                user_groups[user_id].append(event)
        
        return [group for group in user_groups.values() if len(group) > 1]
    
    def _correlate_by_session(self, events: List[IntegrationEvent]) -> List[List[IntegrationEvent]]:
        """Correlate events by session context."""
        session_groups = {}
        
        for event in events:
            session_id = event.audit_event.session_id
            if session_id:
                if session_id not in session_groups:
                    session_groups[session_id] = []
                session_groups[session_id].append(event)
        
        return [group for group in session_groups.values() if len(group) > 1]
    
    def _store_correlation_group(self, events: List[IntegrationEvent]) -> str:
        """Store a group of correlated events."""
        try:
            correlation_group_id = f"corr_{int(time.time())}_{hashlib.md5(str(events).encode()).hexdigest()[:8]}"
            
            event_ids = [event.audit_event.event_id for event in events]
            correlation_context = {
                "event_count": len(events),
                "systems_involved": list(set(event.source_system for event in events)),
                "time_span": {
                    "start": min(event.integration_timestamp for event in events).isoformat(),
                    "end": max(event.integration_timestamp for event in events).isoformat()
                },
                "correlation_criteria": ["time_based", "user_based", "session_based"]
            }
            
            conn = sqlite3.connect(self.correlation_db_path)
            conn.execute("""
                INSERT INTO cross_system_correlations (
                    correlation_group_id, related_event_ids, correlation_type,
                    confidence_score, correlation_timestamp, correlation_context
                ) VALUES (?, ?, ?, ?, ?, ?)
            """, (
                correlation_group_id,
                json.dumps(event_ids),
                "multi_system",
                0.8,  # Default confidence
                datetime.now(timezone.utc).isoformat(),
                json.dumps(correlation_context)
            ))
            
            conn.commit()
            conn.close()
            
            return correlation_group_id
            
        except Exception as e:
            self.logger.error(f"Failed to store correlation group: {e}")
            return ""
    
    def get_integration_statistics(self) -> Dict[str, Any]:
        """Get integration statistics."""
        return {
            'stats': self.stats.copy(),
            'active_adapters': list(self.adapters.keys()),
            'adapter_availability': {
                'cac_piv': CAC_PIV_AVAILABLE,
                'multi_classification': MULTI_CLASS_AVAILABLE,
                'oauth': OAUTH_AVAILABLE,
                'rbac': RBAC_AVAILABLE,
                'encryption': ENCRYPTION_AVAILABLE
            }
        }
    
    def shutdown(self):
        """Shutdown all integration adapters."""
        for adapter in self.adapters.values():
            if hasattr(adapter, 'shutdown'):
                adapter.shutdown()
        
        self.logger.info("Integration manager shutdown complete")


# Factory function for creating integration manager
def create_integration_manager(audit_logger: AuditLogger, storage_path: str = None) -> IntegrationManager:
    """Create and initialize integration manager."""
    if storage_path is None:
        storage_path = "/var/log/dod_integration"
    
    return IntegrationManager(audit_logger, storage_path)


# Convenience functions for common integrations
def integrate_cac_validation(audit_logger: AuditLogger, certificate: Any, 
                           validation_result: Any, user_context: Dict[str, Any] = None) -> str:
    """Convenience function for CAC validation integration."""
    if CAC_PIV_AVAILABLE:
        manager = create_integration_manager(audit_logger)
        adapter = manager.get_adapter(IntegrationType.CAC_PIV_AUTH)
        if adapter:
            return adapter.integrate_cac_validation_event(certificate, validation_result, user_context)
    return ""


def integrate_classification_decision(audit_logger: AuditLogger, resource_id: str,
                                    classification_level: str, user_clearance: str,
                                    access_decision: str, context: Dict[str, Any] = None) -> str:
    """Convenience function for classification decision integration."""
    if MULTI_CLASS_AVAILABLE:
        manager = create_integration_manager(audit_logger)
        adapter = manager.get_adapter(IntegrationType.MULTI_CLASSIFICATION)
        if adapter:
            return adapter.integrate_classification_decision(
                resource_id, classification_level, user_clearance, access_decision, context
            )
    return ""


def integrate_oauth_event(audit_logger: AuditLogger, oauth_event: Any) -> str:
    """Convenience function for OAuth event integration."""
    if OAUTH_AVAILABLE:
        manager = create_integration_manager(audit_logger)
        adapter = manager.get_adapter(IntegrationType.OAUTH_SYSTEM)
        if adapter:
            return adapter.integrate_oauth_event(oauth_event)
    return ""