"""
Classification-Aware Audit Logging System
=========================================

This module provides comprehensive audit logging specifically designed for
multi-classification data handling with deep integration into the existing
audit infrastructure.

Key Features:
- Classification-specific audit events and logging
- Cross-domain data movement tracking and compliance
- Real-time classification decision auditing
- DoD 8500.01E and NIST SP 800-53 compliance reporting
- Tamper-proof audit trails with cryptographic integrity
- Performance-optimized logging with intelligent batching
- Integration with existing audit infrastructure
- Emergency access and override tracking
- Data spillage detection and alerting

Classification: UNCLASSIFIED//FOR OFFICIAL USE ONLY
Version: 3.0 - Enhanced Classification Auditing
Author: Security Compliance Team
Date: 2025-07-27
"""

import asyncio
import json
import logging
import hashlib
import time
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Tuple, Set, Union
from uuid import UUID, uuid4
from dataclasses import dataclass, field, asdict
from enum import Enum
from concurrent.futures import ThreadPoolExecutor
import gzip
import base64
from collections import defaultdict, deque

# Import existing audit infrastructure
from ..audits.audit_logger import AuditLogger
from ..audits.real_time_alerting import RealTimeAlerting
from ..audits.compliance_reporter import ComplianceReporter
from ..audits.tamper_proof_storage import TamperProofStorage

# Import unified audit system
from ..auth.unified_access_control.audit import (
    AuditIntegrationManager,
    AuditEvent,
    AuditEventType,
    AuditSeverity,
    ComplianceStandard
)

# Import classification components
from .enhanced_classification_engine import (
    EnhancedClassificationRequest,
    EnhancedClassificationResponse
)
from .clearance_verification_engine import (
    ClearanceVerificationRequest,
    ClearanceVerificationResult
)
from .integration_layer import (
    ClassificationAwareAccessRequest,
    ClassificationAwareAccessResponse
)

# Import data models
from ..rbac.models.classification import ClassificationLevel, SecurityClearance

logger = logging.getLogger(__name__)


class ClassificationAuditEventType(Enum):
    """Classification-specific audit event types."""
    CONTENT_CLASSIFICATION = "content_classification"
    CLASSIFICATION_OVERRIDE = "classification_override"
    CLEARANCE_VERIFICATION = "clearance_verification"
    CROSS_DOMAIN_ACCESS = "cross_domain_access"
    DATA_SPILLAGE_DETECTED = "data_spillage_detected"
    CLASSIFICATION_DOWNGRADE = "classification_downgrade"
    CLASSIFICATION_UPGRADE = "classification_upgrade"
    EMERGENCY_CLASSIFICATION_ACCESS = "emergency_classification_access"
    SANITIZATION_APPLIED = "sanitization_applied"
    PII_DETECTION = "pii_detection"
    COMPARTMENT_ACCESS = "compartment_access"
    CAVEAT_VALIDATION = "caveat_validation"
    CROSS_DOMAIN_TRANSFER = "cross_domain_transfer"
    CLASSIFICATION_ACCURACY_CHECK = "classification_accuracy_check"
    MANUAL_CLASSIFICATION_REVIEW = "manual_classification_review"


@dataclass
class ClassificationAuditEvent(AuditEvent):
    """Enhanced audit event for classification-specific logging."""
    
    # Classification-specific fields
    classification_level: Optional[str] = None
    original_classification: Optional[str] = None
    final_classification: Optional[str] = None
    confidence_score: Optional[float] = None
    
    # Content analysis
    content_hash: Optional[str] = None
    content_type: Optional[str] = None
    content_size_bytes: Optional[int] = None
    
    # Clearance information
    user_clearance_level: Optional[str] = None
    required_clearance: Optional[str] = None
    compartments_accessed: List[str] = field(default_factory=list)
    caveats_applied: List[str] = field(default_factory=list)
    
    # Cross-domain information
    source_domain: Optional[str] = None
    target_domain: Optional[str] = None
    domain_compatibility: Optional[bool] = None
    
    # Processing metrics
    classification_time_ms: Optional[float] = None
    verification_time_ms: Optional[float] = None
    total_processing_time_ms: Optional[float] = None
    
    # PII and sensitive data
    pii_types_detected: List[str] = field(default_factory=list)
    sensitive_markers: List[str] = field(default_factory=list)
    
    # Override and emergency access
    override_reason: Optional[str] = None
    override_authority: Optional[str] = None
    emergency_justification: Optional[str] = None
    
    # Compliance and risk
    compliance_standards_checked: List[str] = field(default_factory=list)
    risk_level: Optional[str] = None
    warnings_generated: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary with classification-specific fields."""
        base_dict = super().to_dict()
        
        # Add classification-specific fields
        classification_fields = {
            'classification_level': self.classification_level,
            'original_classification': self.original_classification,
            'final_classification': self.final_classification,
            'confidence_score': self.confidence_score,
            'content_hash': self.content_hash,
            'content_type': self.content_type,
            'content_size_bytes': self.content_size_bytes,
            'user_clearance_level': self.user_clearance_level,
            'required_clearance': self.required_clearance,
            'compartments_accessed': self.compartments_accessed,
            'caveats_applied': self.caveats_applied,
            'source_domain': self.source_domain,
            'target_domain': self.target_domain,
            'domain_compatibility': self.domain_compatibility,
            'classification_time_ms': self.classification_time_ms,
            'verification_time_ms': self.verification_time_ms,
            'total_processing_time_ms': self.total_processing_time_ms,
            'pii_types_detected': self.pii_types_detected,
            'sensitive_markers': self.sensitive_markers,
            'override_reason': self.override_reason,
            'override_authority': self.override_authority,
            'emergency_justification': self.emergency_justification,
            'compliance_standards_checked': self.compliance_standards_checked,
            'risk_level': self.risk_level,
            'warnings_generated': self.warnings_generated
        }
        
        base_dict.update(classification_fields)
        return base_dict


@dataclass
class ClassificationAuditMetrics:
    """Metrics for classification audit logging."""
    total_classification_events: int = 0
    total_clearance_verifications: int = 0
    total_cross_domain_accesses: int = 0
    total_data_spillage_detections: int = 0
    total_emergency_accesses: int = 0
    
    # Classification accuracy metrics
    high_confidence_classifications: int = 0
    low_confidence_classifications: int = 0
    manual_review_required: int = 0
    
    # Performance metrics
    average_classification_time_ms: float = 0.0
    average_verification_time_ms: float = 0.0
    
    # Security metrics
    clearance_violations: int = 0
    domain_violations: int = 0
    pii_exposures: int = 0
    
    # Compliance metrics
    dod_compliance_checks: int = 0
    nist_compliance_checks: int = 0
    fisma_compliance_checks: int = 0


class ClassificationSpillageDetector:
    """Real-time data spillage detection for classified information."""
    
    def __init__(self):
        """Initialize spillage detector."""
        self.spillage_patterns = self._load_spillage_patterns()
        self.recent_events = deque(maxlen=1000)
        self.spillage_count = 0
        
    def _load_spillage_patterns(self) -> List[Dict[str, Any]]:
        """Load data spillage detection patterns."""
        return [
            {
                "name": "Cross-Domain Classification Mismatch",
                "pattern": "classification_mismatch",
                "severity": "high",
                "description": "Content classified higher than target domain allows"
            },
            {
                "name": "Unclassified System Secret Access",
                "pattern": "unclassified_secret_access",
                "severity": "critical",
                "description": "Secret or higher classified content on unclassified system"
            },
            {
                "name": "Insufficient Clearance Access",
                "pattern": "insufficient_clearance",
                "severity": "high",
                "description": "User accessing content above their clearance level"
            },
            {
                "name": "Compartment Violation",
                "pattern": "compartment_violation",
                "severity": "high",
                "description": "User accessing compartmented information without proper access"
            },
            {
                "name": "PII in Classified System",
                "pattern": "pii_classified_system",
                "severity": "medium",
                "description": "Personally identifiable information in inappropriate classification level"
            },
            {
                "name": "Classification Downgrade Without Authority",
                "pattern": "unauthorized_downgrade",
                "severity": "critical",
                "description": "Content classification reduced without proper authority"
            }
        ]
    
    def detect_spillage(
        self,
        event: ClassificationAuditEvent,
        context: Dict[str, Any] = None
    ) -> List[Dict[str, Any]]:
        """Detect potential data spillage events."""
        spillage_alerts = []
        
        # Add event to recent history
        self.recent_events.append(event)
        
        # Apply spillage detection patterns
        for pattern in self.spillage_patterns:
            alert = self._apply_spillage_pattern(pattern, event, context)
            if alert:
                spillage_alerts.append(alert)
                self.spillage_count += 1
        
        return spillage_alerts
    
    def _apply_spillage_pattern(
        self,
        pattern: Dict[str, Any],
        event: ClassificationAuditEvent,
        context: Dict[str, Any] = None
    ) -> Optional[Dict[str, Any]]:
        """Apply specific spillage detection pattern."""
        pattern_name = pattern["pattern"]
        
        if pattern_name == "classification_mismatch":
            return self._detect_classification_mismatch(pattern, event, context)
        elif pattern_name == "unclassified_secret_access":
            return self._detect_unclassified_secret_access(pattern, event, context)
        elif pattern_name == "insufficient_clearance":
            return self._detect_insufficient_clearance(pattern, event, context)
        elif pattern_name == "compartment_violation":
            return self._detect_compartment_violation(pattern, event, context)
        elif pattern_name == "pii_classified_system":
            return self._detect_pii_classified_system(pattern, event, context)
        elif pattern_name == "unauthorized_downgrade":
            return self._detect_unauthorized_downgrade(pattern, event, context)
        
        return None
    
    def _detect_classification_mismatch(
        self,
        pattern: Dict[str, Any],
        event: ClassificationAuditEvent,
        context: Dict[str, Any] = None
    ) -> Optional[Dict[str, Any]]:
        """Detect classification level mismatches."""
        if not (event.classification_level and event.target_domain):
            return None
        
        # Define domain classification limits
        domain_limits = {
            "NIPR": ["UNCLASSIFIED", "CUI"],
            "SIPR": ["UNCLASSIFIED", "CUI", "CONFIDENTIAL", "SECRET"],
            "JWICS": ["UNCLASSIFIED", "CUI", "CONFIDENTIAL", "SECRET", "TOP_SECRET", "TS_SCI"]
        }
        
        allowed_levels = domain_limits.get(event.target_domain, [])
        
        if event.classification_level not in allowed_levels:
            return {
                "pattern_name": pattern["name"],
                "severity": pattern["severity"],
                "description": pattern["description"],
                "details": {
                    "classification_level": event.classification_level,
                    "target_domain": event.target_domain,
                    "allowed_levels": allowed_levels
                },
                "event_id": event.event_id,
                "timestamp": event.timestamp.isoformat()
            }
        
        return None
    
    def _detect_unclassified_secret_access(
        self,
        pattern: Dict[str, Any],
        event: ClassificationAuditEvent,
        context: Dict[str, Any] = None
    ) -> Optional[Dict[str, Any]]:
        """Detect secret information on unclassified systems."""
        if (event.classification_level in ["SECRET", "TOP_SECRET", "TS_SCI"] and
            event.target_domain == "NIPR"):
            
            return {
                "pattern_name": pattern["name"],
                "severity": pattern["severity"],
                "description": pattern["description"],
                "details": {
                    "classification_level": event.classification_level,
                    "target_domain": event.target_domain,
                    "violation_type": "classified_on_unclassified"
                },
                "event_id": event.event_id,
                "timestamp": event.timestamp.isoformat()
            }
        
        return None
    
    def _detect_insufficient_clearance(
        self,
        pattern: Dict[str, Any],
        event: ClassificationAuditEvent,
        context: Dict[str, Any] = None
    ) -> Optional[Dict[str, Any]]:
        """Detect access attempts with insufficient clearance."""
        if not (event.user_clearance_level and event.required_clearance):
            return None
        
        # Define clearance hierarchy
        clearance_levels = {
            "UNCLASSIFIED": 0,
            "CONFIDENTIAL": 1,
            "SECRET": 2,
            "TOP_SECRET": 3,
            "TS_SCI": 4
        }
        
        user_level = clearance_levels.get(event.user_clearance_level, -1)
        required_level = clearance_levels.get(event.required_clearance, 5)
        
        if user_level < required_level:
            return {
                "pattern_name": pattern["name"],
                "severity": pattern["severity"],
                "description": pattern["description"],
                "details": {
                    "user_clearance": event.user_clearance_level,
                    "required_clearance": event.required_clearance,
                    "clearance_gap": required_level - user_level
                },
                "event_id": event.event_id,
                "timestamp": event.timestamp.isoformat()
            }
        
        return None
    
    def _detect_compartment_violation(
        self,
        pattern: Dict[str, Any],
        event: ClassificationAuditEvent,
        context: Dict[str, Any] = None
    ) -> Optional[Dict[str, Any]]:
        """Detect compartment access violations."""
        if event.compartments_accessed and context:
            user_compartments = context.get("user_compartments", [])
            
            # Check if user has access to all required compartments
            missing_compartments = [
                comp for comp in event.compartments_accessed
                if comp not in user_compartments
            ]
            
            if missing_compartments:
                return {
                    "pattern_name": pattern["name"],
                    "severity": pattern["severity"],
                    "description": pattern["description"],
                    "details": {
                        "missing_compartments": missing_compartments,
                        "user_compartments": user_compartments,
                        "required_compartments": event.compartments_accessed
                    },
                    "event_id": event.event_id,
                    "timestamp": event.timestamp.isoformat()
                }
        
        return None
    
    def _detect_pii_classified_system(
        self,
        pattern: Dict[str, Any],
        event: ClassificationAuditEvent,
        context: Dict[str, Any] = None
    ) -> Optional[Dict[str, Any]]:
        """Detect PII in inappropriate classification levels."""
        if event.pii_types_detected and event.classification_level:
            # PII should generally not be in highly classified systems
            # unless specifically authorized
            if (event.classification_level in ["SECRET", "TOP_SECRET"] and
                event.pii_types_detected):
                
                return {
                    "pattern_name": pattern["name"],
                    "severity": pattern["severity"],
                    "description": pattern["description"],
                    "details": {
                        "pii_types": event.pii_types_detected,
                        "classification_level": event.classification_level,
                        "concern": "PII in high classification system"
                    },
                    "event_id": event.event_id,
                    "timestamp": event.timestamp.isoformat()
                }
        
        return None
    
    def _detect_unauthorized_downgrade(
        self,
        pattern: Dict[str, Any],
        event: ClassificationAuditEvent,
        context: Dict[str, Any] = None
    ) -> Optional[Dict[str, Any]]:
        """Detect unauthorized classification downgrades."""
        if (event.original_classification and 
            event.final_classification and
            not event.override_authority):
            
            # Define classification hierarchy
            classification_levels = {
                "UNCLASSIFIED": 0,
                "CONFIDENTIAL": 1,
                "SECRET": 2,
                "TOP_SECRET": 3,
                "TS_SCI": 4
            }
            
            original_level = classification_levels.get(event.original_classification, 0)
            final_level = classification_levels.get(event.final_classification, 0)
            
            # Check for downgrade without authority
            if final_level < original_level:
                return {
                    "pattern_name": pattern["name"],
                    "severity": pattern["severity"],
                    "description": pattern["description"],
                    "details": {
                        "original_classification": event.original_classification,
                        "final_classification": event.final_classification,
                        "downgrade_levels": original_level - final_level,
                        "authority_provided": bool(event.override_authority)
                    },
                    "event_id": event.event_id,
                    "timestamp": event.timestamp.isoformat()
                }
        
        return None


class ClassificationAuditLogger:
    """
    Enhanced audit logger specifically designed for multi-classification systems.
    
    This integrates with the existing audit infrastructure while providing
    specialized logging for classification-specific events.
    """
    
    def __init__(
        self,
        base_audit_manager: AuditIntegrationManager,
        enable_spillage_detection: bool = True,
        enable_real_time_alerts: bool = True
    ):
        """Initialize classification audit logger."""
        self.base_audit_manager = base_audit_manager
        self.enable_spillage_detection = enable_spillage_detection
        self.enable_real_time_alerts = enable_real_time_alerts
        
        # Spillage detection
        self.spillage_detector = ClassificationSpillageDetector() if enable_spillage_detection else None
        
        # Metrics tracking
        self.metrics = ClassificationAuditMetrics()
        self._metrics_lock = asyncio.Lock()
        
        # Event queue for classification-specific events
        self.classification_event_queue: asyncio.Queue = asyncio.Queue(maxsize=5000)
        self._processing_task: Optional[asyncio.Task] = None
        self._shutdown_event = asyncio.Event()
        
        logger.info("Classification Audit Logger initialized")
    
    async def start(self):
        """Start classification audit processing."""
        if self._processing_task:
            return
        
        self._processing_task = asyncio.create_task(self._process_classification_events())
        logger.info("Classification audit processing started")
    
    async def stop(self):
        """Stop classification audit processing."""
        self._shutdown_event.set()
        
        if self._processing_task:
            await self._processing_task
            self._processing_task = None
        
        logger.info("Classification audit processing stopped")
    
    async def log_content_classification(
        self,
        request: EnhancedClassificationRequest,
        response: EnhancedClassificationResponse,
        user_context: Optional[Dict[str, Any]] = None
    ):
        """Log content classification event."""
        try:
            # Create classification audit event
            event = ClassificationAuditEvent(
                event_type=AuditEventType.DATA_ACCESS,  # Map to base type
                severity=self._determine_severity(response),
                user_id=request.user_id,
                session_id=request.session_id,
                resource_type="classified_content",
                action="classify",
                result="SUCCESS" if response.classification_result else "FAILURE",
                
                # Classification-specific fields
                classification_level=response.classification_result.classification_level.name,
                confidence_score=response.confidence_score,
                content_hash=response.classification_result.content_hash,
                content_type=request.content_type,
                content_size_bytes=len(request.content),
                classification_time_ms=response.processing_time_ms,
                pii_types_detected=[result.pii_type for result in response.pii_results],
                warnings_generated=response.recommendations,
                compliance_standards_checked=["DOD_8500", "NIST_SP_800_53"]
            )
            
            # Add user clearance information if available
            if user_context and "clearance" in user_context:
                event.user_clearance_level = user_context["clearance"].get("level")
            
            await self._queue_classification_event(event, user_context)
            
            # Update metrics
            async with self._metrics_lock:
                self.metrics.total_classification_events += 1
                if response.confidence_score >= 0.85:
                    self.metrics.high_confidence_classifications += 1
                else:
                    self.metrics.low_confidence_classifications += 1
                
                # Update timing metrics
                if self.metrics.average_classification_time_ms == 0:
                    self.metrics.average_classification_time_ms = response.processing_time_ms
                else:
                    self.metrics.average_classification_time_ms = (
                        (self.metrics.average_classification_time_ms + response.processing_time_ms) / 2
                    )
            
        except Exception as e:
            logger.error(f"Failed to log content classification: {e}")
    
    async def log_clearance_verification(
        self,
        request: ClearanceVerificationRequest,
        result: ClearanceVerificationResult,
        user_context: Optional[Dict[str, Any]] = None
    ):
        """Log clearance verification event."""
        try:
            # Create clearance verification audit event
            event = ClassificationAuditEvent(
                event_type=AuditEventType.AUTHENTICATION_SUCCESS if result.clearance_status.name == "VALID" else AuditEventType.AUTHENTICATION_FAILURE,
                severity=AuditSeverity.HIGH if result.clearance_status.name != "VALID" else AuditSeverity.LOW,
                user_id=request.user_id,
                session_id=request.session_id,
                resource_type=request.resource_type,
                action="clearance_verification",
                result=result.access_decision.value,
                
                # Clearance-specific fields
                user_clearance_level=result.verified_clearance.level if result.verified_clearance else None,
                required_clearance=request.requested_classification.name,
                compartments_accessed=request.requested_compartments,
                caveats_applied=request.requested_caveats,
                verification_time_ms=result.verification_time_ms,
                confidence_score=result.confidence_score,
                warnings_generated=result.clearance_warnings + result.expiration_alerts,
                compliance_standards_checked=["DOD_8500", "NIST_SP_800_53", "FISMA"]
            )
            
            # Add certificate information if available
            if result.certificate_details:
                event.additional_data["certificate_verification"] = result.certificate_details
            
            await self._queue_classification_event(event, user_context)
            
            # Update metrics
            async with self._metrics_lock:
                self.metrics.total_clearance_verifications += 1
                if result.access_decision.value == "DENY":
                    self.metrics.clearance_violations += 1
                
                # Update timing metrics
                if self.metrics.average_verification_time_ms == 0:
                    self.metrics.average_verification_time_ms = result.verification_time_ms
                else:
                    self.metrics.average_verification_time_ms = (
                        (self.metrics.average_verification_time_ms + result.verification_time_ms) / 2
                    )
            
        except Exception as e:
            logger.error(f"Failed to log clearance verification: {e}")
    
    async def log_classification_aware_access(
        self,
        request: ClassificationAwareAccessRequest,
        response: ClassificationAwareAccessResponse,
        user_context: Optional[Dict[str, Any]] = None
    ):
        """Log classification-aware access event."""
        try:
            # Create comprehensive access event
            event = ClassificationAuditEvent(
                event_type=AuditEventType.ACCESS_GRANTED if response.decision.value == "PERMIT" else AuditEventType.ACCESS_DENIED,
                severity=self._determine_access_severity(response),
                user_id=request.user_id,
                session_id=request.session_id,
                resource_type=request.resource_type,
                resource_id=request.resource_id,
                platform=request.platform,
                action=request.action,
                result=response.decision.value,
                reason=response.reason,
                
                # Classification context
                classification_level=request.expected_classification.name if request.expected_classification else None,
                source_domain=request.network_domain,
                total_processing_time_ms=response.total_processing_time_ms,
                warnings_generated=response.security_warnings,
                compliance_standards_checked=["DOD_8500", "NIST_SP_800_53", "FISMA"]
            )
            
            # Add classification response details
            if response.classification_response:
                event.classification_level = response.classification_response.classification_result.classification_level.name
                event.confidence_score = response.classification_response.confidence_score
                event.classification_time_ms = response.classification_time_ms
                event.pii_types_detected = [result.pii_type for result in response.classification_response.pii_results]
            
            # Add clearance verification details
            if response.clearance_verification:
                event.user_clearance_level = response.clearance_verification.verified_clearance.level if response.clearance_verification.verified_clearance else None
                event.verification_time_ms = response.clearance_verification_time_ms
                event.compartments_accessed = response.clearance_verification.approved_compartments
                event.caveats_applied = response.clearance_verification.approved_caveats
            
            await self._queue_classification_event(event, user_context)
            
            # Update metrics
            async with self._metrics_lock:
                if request.network_domain and response.cross_domain_compatibility:
                    self.metrics.total_cross_domain_accesses += 1
                    
                    # Check for domain violations
                    if not response.cross_domain_compatibility.get(request.network_domain, True):
                        self.metrics.domain_violations += 1
                
                # Check for PII exposures
                if (response.classification_response and
                    response.classification_response.pii_results):
                    self.metrics.pii_exposures += 1
            
        except Exception as e:
            logger.error(f"Failed to log classification-aware access: {e}")
    
    async def log_emergency_classification_access(
        self,
        user_id: UUID,
        resource_type: str,
        action: str,
        classification_level: str,
        justification: str,
        authority: Optional[str] = None,
        session_id: Optional[str] = None
    ):
        """Log emergency classification access."""
        try:
            event = ClassificationAuditEvent(
                event_type=AuditEventType.EMERGENCY_ACCESS,
                severity=AuditSeverity.HIGH,
                user_id=user_id,
                session_id=session_id,
                resource_type=resource_type,
                action=action,
                result="EMERGENCY_GRANTED",
                
                # Emergency access fields
                classification_level=classification_level,
                emergency_justification=justification,
                override_authority=authority,
                compliance_standards_checked=["DOD_8500", "NIST_SP_800_53"],
                warnings_generated=["Emergency classification access granted"]
            )
            
            await self._queue_classification_event(event)
            
            # Update metrics
            async with self._metrics_lock:
                self.metrics.total_emergency_accesses += 1
            
        except Exception as e:
            logger.error(f"Failed to log emergency classification access: {e}")
    
    async def _queue_classification_event(
        self,
        event: ClassificationAuditEvent,
        context: Optional[Dict[str, Any]] = None
    ):
        """Queue classification event for processing."""
        try:
            # Perform spillage detection if enabled
            if self.spillage_detector:
                spillage_alerts = self.spillage_detector.detect_spillage(event, context)
                for alert in spillage_alerts:
                    await self._handle_spillage_alert(alert, event)
            
            # Queue event for processing
            if not self.classification_event_queue.full():
                await self.classification_event_queue.put((event, context))
            else:
                logger.warning("Classification event queue full, dropping event")
        
        except Exception as e:
            logger.error(f"Failed to queue classification event: {e}")
    
    async def _process_classification_events(self):
        """Process queued classification events."""
        while not self._shutdown_event.is_set():
            try:
                # Get event with timeout
                try:
                    event_data = await asyncio.wait_for(
                        self.classification_event_queue.get(),
                        timeout=1.0
                    )
                    event, context = event_data
                except asyncio.TimeoutError:
                    continue
                
                # Forward to base audit manager
                await self.base_audit_manager.log_event(event)
                
            except Exception as e:
                logger.error(f"Error processing classification event: {e}")
    
    async def _handle_spillage_alert(
        self,
        alert: Dict[str, Any],
        triggering_event: ClassificationAuditEvent
    ):
        """Handle data spillage alert."""
        try:
            # Create spillage detection event
            spillage_event = ClassificationAuditEvent(
                event_type=AuditEventType.SECURITY_VIOLATION,
                severity=AuditSeverity.CRITICAL if alert["severity"] == "critical" else AuditSeverity.HIGH,
                user_id=triggering_event.user_id,
                session_id=triggering_event.session_id,
                resource_type="data_spillage",
                action="spillage_detection",
                result="SPILLAGE_DETECTED",
                reason=alert["description"],
                
                # Spillage-specific information
                classification_level=triggering_event.classification_level,
                additional_data={
                    "spillage_pattern": alert["pattern_name"],
                    "spillage_details": alert["details"],
                    "triggering_event_id": triggering_event.event_id
                }
            )
            
            # Queue spillage event
            await self.classification_event_queue.put((spillage_event, None))
            
            # Send real-time alert if enabled
            if self.enable_real_time_alerts:
                await self._send_real_time_spillage_alert(alert, triggering_event)
            
            # Update metrics
            async with self._metrics_lock:
                self.metrics.total_data_spillage_detections += 1
            
        except Exception as e:
            logger.error(f"Failed to handle spillage alert: {e}")
    
    async def _send_real_time_spillage_alert(
        self,
        alert: Dict[str, Any],
        triggering_event: ClassificationAuditEvent
    ):
        """Send real-time spillage alert."""
        try:
            alert_message = {
                "alert_type": "DATA_SPILLAGE_DETECTED",
                "severity": alert["severity"].upper(),
                "pattern": alert["pattern_name"],
                "description": alert["description"],
                "user_id": str(triggering_event.user_id) if triggering_event.user_id else None,
                "timestamp": triggering_event.timestamp.isoformat(),
                "event_id": triggering_event.event_id,
                "details": alert["details"]
            }
            
            # Use base audit manager's real-time alerting
            await self.base_audit_manager.real_time_alerting.send_alert(
                alert_type="data_spillage",
                severity=alert["severity"],
                message=alert["description"],
                context=alert_message
            )
            
        except Exception as e:
            logger.error(f"Failed to send real-time spillage alert: {e}")
    
    def _determine_severity(self, response: EnhancedClassificationResponse) -> AuditSeverity:
        """Determine audit severity based on classification response."""
        if response.classification_result.classification_level >= ClassificationLevel.SECRET:
            return AuditSeverity.HIGH
        elif response.classification_result.classification_level >= ClassificationLevel.CONFIDENTIAL:
            return AuditSeverity.MEDIUM
        else:
            return AuditSeverity.LOW
    
    def _determine_access_severity(self, response: ClassificationAwareAccessResponse) -> AuditSeverity:
        """Determine audit severity based on access response."""
        if response.decision.value == "DENY":
            return AuditSeverity.HIGH
        elif response.security_warnings or response.sanitization_requirements:
            return AuditSeverity.MEDIUM
        else:
            return AuditSeverity.LOW
    
    async def generate_classification_compliance_report(
        self,
        standard: ComplianceStandard,
        start_date: datetime,
        end_date: datetime
    ) -> Dict[str, Any]:
        """Generate classification-specific compliance report."""
        try:
            # Get base compliance report
            base_report = await self.base_audit_manager.generate_compliance_report(
                standard, start_date, end_date
            )
            
            # Add classification-specific metrics
            async with self._metrics_lock:
                classification_metrics = asdict(self.metrics)
            
            # Enhanced compliance report
            enhanced_report = {
                "base_compliance": base_report,
                "classification_metrics": classification_metrics,
                "spillage_detection": {
                    "total_spillage_detections": self.metrics.total_data_spillage_detections,
                    "spillage_rate": self.metrics.total_data_spillage_detections / max(1, self.metrics.total_classification_events),
                    "detector_status": "enabled" if self.spillage_detector else "disabled"
                },
                "clearance_compliance": {
                    "total_verifications": self.metrics.total_clearance_verifications,
                    "violation_rate": self.metrics.clearance_violations / max(1, self.metrics.total_clearance_verifications),
                    "average_verification_time": self.metrics.average_verification_time_ms
                },
                "cross_domain_compliance": {
                    "total_accesses": self.metrics.total_cross_domain_accesses,
                    "violation_rate": self.metrics.domain_violations / max(1, self.metrics.total_cross_domain_accesses),
                    "pii_exposures": self.metrics.pii_exposures
                },
                "report_metadata": {
                    "standard": standard.value,
                    "start_date": start_date.isoformat(),
                    "end_date": end_date.isoformat(),
                    "generated_at": datetime.now(timezone.utc).isoformat()
                }
            }
            
            return enhanced_report
            
        except Exception as e:
            logger.error(f"Failed to generate classification compliance report: {e}")
            return {"error": str(e)}
    
    def get_classification_metrics(self) -> Dict[str, Any]:
        """Get classification audit metrics."""
        return {
            "classification_audit": asdict(self.metrics),
            "spillage_detection": {
                "enabled": self.spillage_detector is not None,
                "patterns_loaded": len(self.spillage_detector.spillage_patterns) if self.spillage_detector else 0,
                "recent_events": len(self.spillage_detector.recent_events) if self.spillage_detector else 0
            },
            "queue_status": {
                "queue_size": self.classification_event_queue.qsize(),
                "max_queue_size": self.classification_event_queue.maxsize,
                "processing_active": self._processing_task is not None and not self._processing_task.done()
            }
        }
    
    async def health_check(self) -> Dict[str, Any]:
        """Perform health check on classification audit system."""
        health_status = {
            "status": "healthy",
            "components": {},
            "metrics": {}
        }
        
        try:
            # Check base audit manager
            base_health = await self.base_audit_manager.health_check()
            health_status["components"]["base_audit_manager"] = base_health["status"]
            
            # Check spillage detector
            health_status["components"]["spillage_detector"] = "enabled" if self.spillage_detector else "disabled"
            
            # Check processing task
            processing_healthy = (self._processing_task is not None and 
                                not self._processing_task.done())
            health_status["components"]["event_processing"] = "healthy" if processing_healthy else "stopped"
            
            # Check queue health
            queue_usage = self.classification_event_queue.qsize() / self.classification_event_queue.maxsize
            health_status["components"]["event_queue"] = "healthy" if queue_usage < 0.8 else "high_usage"
            
            # Add metrics
            health_status["metrics"] = self.get_classification_metrics()
            
            # Overall status
            if not processing_healthy or base_health["status"] != "healthy":
                health_status["status"] = "degraded"
            
        except Exception as e:
            health_status["status"] = "unhealthy"
            health_status["error"] = str(e)
        
        return health_status


if __name__ == "__main__":
    # Example usage
    print("Classification-Aware Audit Logging System - see code for usage examples")