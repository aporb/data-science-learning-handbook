"""
Multi-Classification Framework Integration Layer
==============================================

This module provides the comprehensive integration layer that unifies the enhanced 
multi-classification framework with automated data labeling, existing unified access 
control, RBAC, and OAuth systems.

Key Integration Features:
- Seamless integration with UnifiedAccessController
- Automated data labeling integration with real-time classification
- Classification-aware permission resolution
- Real-time classification during access control decisions
- Cross-platform classification consistency
- Performance-optimized classification workflows with automated labeling
- Comprehensive audit integration for classified data access
- Support for emergency access with classification overrides
- Source-based, content-based, and context-aware labeling integration

Classification: UNCLASSIFIED//FOR OFFICIAL USE ONLY
Version: 4.0 - Enhanced with Automated Labeling
Author: Security Compliance Team
Date: 2025-07-29
"""

import asyncio
import json
import logging
import time
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any, Tuple, Set, Union
from uuid import UUID, uuid4
from dataclasses import dataclass, field, asdict
from enum import Enum
from concurrent.futures import ThreadPoolExecutor

# Import enhanced classification components
from .enhanced_classification_engine import (
    EnhancedMultiClassificationEngine,
    EnhancedClassificationRequest,
    EnhancedClassificationResponse,
    ProcessingMode,
    OptimizationLevel
)
from .clearance_verification_engine import (
    EnhancedClearanceVerificationEngine,
    ClearanceVerificationRequest,
    ClearanceVerificationResult,
    AccessDecision as ClearanceAccessDecision,
    ClearanceStatus
)

# Import automated labeling components
from .labeling_integration_layer import (
    LabelingIntegrationLayer,
    IntegrationRequest,
    IntegrationResult,
    IntegrationMode,
    ProcessingPriority
)
from .automated_data_labeler import (
    AutomatedDataLabeler,
    LabelingRequest,
    LabelingResult,
    LabelingStrategy,
    DataOriginType
)
from .performance_optimizer import (
    PerformanceOptimizer,
    OptimizationConfig
)

# Import existing infrastructure
from ..auth.unified_access_control.controller import (
    UnifiedAccessController,
    UnifiedAccessRequest,
    UnifiedAccessResponse,
    AccessDecision
)
from ..auth.unified_access_control.context import UnifiedUserContext, PlatformContext
from ..auth.unified_access_control.resolver import CrossPlatformPermissionResolver
from ..rbac.models.classification import ClassificationLevel, SecurityClearance
from ..rbac.rbac_engine import RBACEngine
from ..rbac.abac.attribute_manager import AttributeManager
from ..rbac.abac.policy_engine import PolicyEngine
from ..audits.audit_logger import AuditLogger

logger = logging.getLogger(__name__)


class ClassificationIntegrationMode(Enum):
    """Classification integration modes."""
    REAL_TIME = "real_time"
    CACHED = "cached"
    BACKGROUND = "background"
    MANUAL = "manual"


@dataclass
class ClassificationAwareAccessRequest:
    """Enhanced access request with classification awareness."""
    # Base access request fields
    user_id: UUID
    resource_type: str
    action: str
    resource_id: Optional[str] = None
    platform: Optional[str] = None
    session_id: Optional[str] = None
    
    # Classification-specific fields
    resource_content: Optional[str] = None
    expected_classification: Optional[ClassificationLevel] = None
    require_classification_verification: bool = True
    classification_integration_mode: ClassificationIntegrationMode = ClassificationIntegrationMode.REAL_TIME
    
    # Enhanced context
    user_clearance: Optional[SecurityClearance] = None
    client_certificate: Optional[str] = None
    network_domain: Optional[str] = None
    
    # Performance options
    max_classification_time_ms: float = 100.0
    enable_classification_caching: bool = True
    
    # Request metadata
    request_id: str = field(default_factory=lambda: str(uuid4()))
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class ClassificationAwareAccessResponse:
    """Enhanced access response with classification details."""
    # Base access response
    request_id: str
    decision: AccessDecision
    reason: str
    effective_permissions: List[str] = field(default_factory=list)
    
    # Classification results
    classification_response: Optional[EnhancedClassificationResponse] = None
    clearance_verification: Optional[ClearanceVerificationResult] = None
    
    # Cross-domain analysis
    cross_domain_compatibility: Dict[str, bool] = field(default_factory=dict)
    sanitization_requirements: List[str] = field(default_factory=list)
    
    # Enhanced security
    security_warnings: List[str] = field(default_factory=list)
    compliance_notes: List[str] = field(default_factory=list)
    
    # Performance metrics
    total_processing_time_ms: float = 0.0
    classification_time_ms: float = 0.0
    clearance_verification_time_ms: float = 0.0
    
    # Audit information
    audit_event_ids: List[str] = field(default_factory=list)
    
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class ClassificationAwarePermissionResolver:
    """Enhanced permission resolver with classification awareness."""
    
    def __init__(
        self,
        base_resolver: CrossPlatformPermissionResolver,
        classification_engine: EnhancedMultiClassificationEngine,
        clearance_engine: EnhancedClearanceVerificationEngine
    ):
        """Initialize classification-aware permission resolver."""
        self.base_resolver = base_resolver
        self.classification_engine = classification_engine
        self.clearance_engine = clearance_engine
        
        # Performance tracking
        self.resolution_count = 0
        self.classification_count = 0
        self.clearance_verification_count = 0
        
        logger.info("Classification-Aware Permission Resolver initialized")
    
    async def resolve_permissions(
        self,
        request: ClassificationAwareAccessRequest,
        user_context: UnifiedUserContext
    ) -> ClassificationAwareAccessResponse:
        """
        Resolve permissions with classification awareness.
        
        This integrates classification analysis with existing permission resolution.
        """
        start_time = time.time()
        self.resolution_count += 1
        
        # Initialize response
        response = ClassificationAwareAccessResponse(
            request_id=request.request_id,
            decision=AccessDecision.DENY,
            reason="Processing"
        )
        
        try:
            # Step 1: Perform resource classification if needed
            if request.resource_content and request.require_classification_verification:
                classification_response = await self._classify_resource(request, user_context)
                response.classification_response = classification_response
                response.classification_time_ms = classification_response.processing_time_ms
                
                # Update expected classification if not provided
                if not request.expected_classification:
                    request.expected_classification = classification_response.classification_result.classification_level
            
            # Step 2: Verify user clearance for the classification level
            if request.expected_classification:
                clearance_result = await self._verify_user_clearance(request, user_context)
                response.clearance_verification = clearance_result
                response.clearance_verification_time_ms = clearance_result.verification_time_ms
                
                # Check if clearance verification failed
                if clearance_result.access_decision == ClearanceAccessDecision.DENY:
                    response.decision = AccessDecision.DENY
                    response.reason = f"Insufficient clearance: {clearance_result.clearance_warnings}"
                    response.total_processing_time_ms = (time.time() - start_time) * 1000
                    return response
            
            # Step 3: Call base permission resolver with enhanced context
            enhanced_request = await self._create_enhanced_unified_request(request, response)
            base_response = await self.base_resolver.resolve_permissions(
                enhanced_request, user_context
            )
            
            # Step 4: Apply classification-aware permission filtering
            filtered_permissions = await self._filter_permissions_by_classification(
                base_response.effective_permissions,
                request,
                response
            )
            
            # Step 5: Perform cross-domain compatibility analysis
            cross_domain_analysis = await self._analyze_cross_domain_compatibility(
                request, response
            )
            response.cross_domain_compatibility = cross_domain_analysis["compatibility"]
            response.sanitization_requirements = cross_domain_analysis["sanitization_requirements"]
            
            # Step 6: Generate security warnings and compliance notes
            response.security_warnings = await self._generate_security_warnings(request, response)
            response.compliance_notes = await self._generate_compliance_notes(request, response)
            
            # Step 7: Make final access decision
            final_decision = await self._make_final_access_decision(
                base_response, response, filtered_permissions
            )
            
            response.decision = final_decision["decision"]
            response.reason = final_decision["reason"]
            response.effective_permissions = filtered_permissions
            
        except Exception as e:
            logger.error(f"Classification-aware permission resolution failed: {e}")
            response.decision = AccessDecision.DENY
            response.reason = f"Permission resolution error: {str(e)}"
        
        # Update total processing time
        response.total_processing_time_ms = (time.time() - start_time) * 1000
        
        return response
    
    async def _classify_resource(
        self,
        request: ClassificationAwareAccessRequest,
        user_context: UnifiedUserContext
    ) -> EnhancedClassificationResponse:
        """Classify resource content."""
        self.classification_count += 1
        
        # Create classification request
        classification_request = EnhancedClassificationRequest(
            content=request.resource_content,
            user_id=request.user_id,
            session_id=request.session_id,
            source_platform=request.platform,
            processing_mode=ProcessingMode.REAL_TIME if request.classification_integration_mode == ClassificationIntegrationMode.REAL_TIME else ProcessingMode.BATCH,
            optimization_level=OptimizationLevel.HIGH_PERFORMANCE,
            user_clearance=request.user_clearance,
            max_processing_time_ms=request.max_classification_time_ms,
            enable_audit_logging=True
        )
        
        # Perform classification
        return await self.classification_engine.classify_content(classification_request)
    
    async def _verify_user_clearance(
        self,
        request: ClassificationAwareAccessRequest,
        user_context: UnifiedUserContext
    ) -> ClearanceVerificationResult:
        """Verify user clearance for the requested classification level."""
        self.clearance_verification_count += 1
        
        # Create clearance verification request
        clearance_request = ClearanceVerificationRequest(
            user_id=request.user_id,
            session_id=request.session_id,
            requested_classification=request.expected_classification,
            client_certificate=request.client_certificate,
            resource_type=request.resource_type,
            resource_id=request.resource_id,
            action=request.action,
            platform=request.platform,
            network_domain=request.network_domain,
            max_verification_time_ms=50.0,  # Fast verification for real-time use
            enable_caching=request.enable_classification_caching
        )
        
        # Perform clearance verification
        return await self.clearance_engine.verify_clearance(clearance_request)
    
    async def _create_enhanced_unified_request(
        self,
        request: ClassificationAwareAccessRequest,
        response: ClassificationAwareAccessResponse
    ) -> UnifiedAccessRequest:
        """Create enhanced unified access request with classification context."""
        # Create base unified request
        unified_request = UnifiedAccessRequest(
            user_id=request.user_id,
            resource_type=request.resource_type,
            action=request.action,
            resource_id=request.resource_id,
            platform=request.platform,
            session_id=request.session_id
        )
        
        # Add classification context
        if request.expected_classification:
            unified_request.classification_level = request.expected_classification.name
        
        # Add clearance verification results
        if response.clearance_verification:
            unified_request.additional_attributes = {
                "clearance_status": response.clearance_verification.clearance_status.value,
                "clearance_level": response.clearance_verification.verified_clearance.level if response.clearance_verification.verified_clearance else None,
                "clearance_confidence": response.clearance_verification.confidence_score
            }
        
        # Add classification results
        if response.classification_response:
            unified_request.additional_attributes = unified_request.additional_attributes or {}
            unified_request.additional_attributes.update({
                "content_classification": response.classification_response.classification_result.classification_level.name,
                "classification_confidence": response.classification_response.confidence_score,
                "pii_detected": len(response.classification_response.pii_results) > 0
            })
        
        return unified_request
    
    async def _filter_permissions_by_classification(
        self,
        base_permissions: List[str],
        request: ClassificationAwareAccessRequest,
        response: ClassificationAwareAccessResponse
    ) -> List[str]:
        """Filter permissions based on classification requirements."""
        filtered_permissions = base_permissions.copy()
        
        # Apply Bell-LaPadula filtering
        if (response.clearance_verification and 
            response.clearance_verification.access_decision == ClearanceAccessDecision.DENY):
            # Remove all permissions if clearance verification failed
            filtered_permissions = []
        
        # Apply classification-based permission filtering
        if response.classification_response:
            classification_level = response.classification_response.classification_result.classification_level
            
            # Remove high-privilege permissions for highly classified content
            if classification_level >= ClassificationLevel.SECRET:
                high_privilege_actions = ["delete", "admin", "configure", "export"]
                filtered_permissions = [
                    perm for perm in filtered_permissions 
                    if not any(action in perm.lower() for action in high_privilege_actions)
                ]
            
            # Add classification-specific permissions
            if classification_level <= ClassificationLevel.CONFIDENTIAL:
                filtered_permissions.append("unclassified_access")
            
            if (response.clearance_verification and 
                response.clearance_verification.verified_clearance and
                ClassificationLevel.from_string(response.clearance_verification.verified_clearance.level) >= classification_level):
                filtered_permissions.append("classified_access")
        
        return list(set(filtered_permissions))  # Remove duplicates
    
    async def _analyze_cross_domain_compatibility(
        self,
        request: ClassificationAwareAccessRequest,
        response: ClassificationAwareAccessResponse
    ) -> Dict[str, Any]:
        """Analyze cross-domain compatibility and requirements."""
        analysis = {
            "compatibility": {},
            "sanitization_requirements": []
        }
        
        if not response.classification_response:
            return analysis
        
        classification_level = response.classification_response.classification_result.classification_level
        
        # Network domain compatibility
        analysis["compatibility"] = {
            "NIPR": classification_level <= ClassificationLevel.CONFIDENTIAL,
            "SIPR": classification_level <= ClassificationLevel.SECRET,
            "JWICS": True  # JWICS can handle all levels
        }
        
        # Sanitization requirements
        if classification_level >= ClassificationLevel.SECRET:
            analysis["sanitization_requirements"].extend([
                "Remove classification markings",
                "Sanitize sensitive metadata",
                "Apply redaction policies"
            ])
        
        if response.classification_response.pii_results:
            analysis["sanitization_requirements"].extend([
                "Remove or mask PII data",
                "Apply data anonymization"
            ])
        
        return analysis
    
    async def _generate_security_warnings(
        self,
        request: ClassificationAwareAccessRequest,
        response: ClassificationAwareAccessResponse
    ) -> List[str]:
        """Generate security warnings based on analysis results."""
        warnings = []
        
        # Classification warnings
        if response.classification_response:
            if response.classification_response.confidence_score < 0.85:
                warnings.append(f"Low classification confidence ({response.classification_response.confidence_score:.2f})")
            
            if response.classification_response.pii_results:
                pii_types = [result.pii_type for result in response.classification_response.pii_results]
                warnings.append(f"PII detected: {', '.join(pii_types)}")
        
        # Clearance warnings
        if response.clearance_verification:
            warnings.extend(response.clearance_verification.clearance_warnings)
            warnings.extend(response.clearance_verification.expiration_alerts)
        
        # Cross-domain warnings
        current_domain = request.network_domain
        if current_domain and current_domain in response.cross_domain_compatibility:
            if not response.cross_domain_compatibility[current_domain]:
                warnings.append(f"Content classification incompatible with {current_domain} domain")
        
        return warnings
    
    async def _generate_compliance_notes(
        self,
        request: ClassificationAwareAccessRequest,
        response: ClassificationAwareAccessResponse
    ) -> List[str]:
        """Generate compliance notes for audit purposes."""
        notes = []
        
        # Classification compliance
        if response.classification_response:
            classification_level = response.classification_response.classification_result.classification_level
            
            if classification_level >= ClassificationLevel.SECRET:
                notes.append("DoD 8500.01E mandatory access controls applied")
                notes.append("NIST SP 800-53 security controls enforced")
            
            if response.classification_response.pii_results:
                notes.append("Privacy Act of 1974 protections applied")
        
        # Clearance compliance
        if response.clearance_verification:
            if response.clearance_verification.verified_clearance:
                notes.append(f"Security clearance verified: {response.clearance_verification.verified_clearance.level}")
            
            if response.clearance_verification.certificate_details:
                notes.append("PKI certificate validation performed")
        
        return notes
    
    async def _make_final_access_decision(
        self,
        base_response: UnifiedAccessResponse,
        classification_response: ClassificationAwareAccessResponse,
        filtered_permissions: List[str]
    ) -> Dict[str, Any]:
        """Make final access decision based on all factors."""
        # Start with base decision
        decision = base_response.decision
        reason = base_response.reason
        
        # Apply classification-based restrictions
        if classification_response.clearance_verification:
            clearance_decision = classification_response.clearance_verification.access_decision
            
            if clearance_decision == ClearanceAccessDecision.DENY:
                decision = AccessDecision.DENY
                reason = "Insufficient security clearance"
            elif clearance_decision == ClearanceAccessDecision.CONDITIONAL:
                if decision == AccessDecision.PERMIT:
                    decision = AccessDecision.CONDITIONAL
                    reason = "Access granted with clearance conditions"
        
        # Check for security warnings that should deny access
        critical_warnings = [w for w in classification_response.security_warnings if "CRITICAL" in w.upper()]
        if critical_warnings:
            decision = AccessDecision.DENY
            reason = f"Critical security warnings: {'; '.join(critical_warnings)}"
        
        # Ensure permissions are available
        if decision == AccessDecision.PERMIT and not filtered_permissions:
            decision = AccessDecision.DENY
            reason = "No permissions available after classification filtering"
        
        return {
            "decision": decision,
            "reason": reason
        }
    
    def get_performance_metrics(self) -> Dict[str, Any]:
        """Get performance metrics for the resolver."""
        return {
            "classification_aware_resolver": {
                "total_resolutions": self.resolution_count,
                "classifications_performed": self.classification_count,
                "clearance_verifications": self.clearance_verification_count,
                "classification_rate": self.classification_count / max(1, self.resolution_count),
                "clearance_verification_rate": self.clearance_verification_count / max(1, self.resolution_count)
            }
        }


class ClassificationIntegratedAccessController(UnifiedAccessController):
    """
    Enhanced Unified Access Controller with integrated multi-classification support.
    
    This extends the existing UnifiedAccessController with seamless classification
    capabilities while maintaining backward compatibility.
    """
    
    def __init__(
        self,
        config,
        classification_engine: Optional[EnhancedMultiClassificationEngine] = None,
        clearance_engine: Optional[EnhancedClearanceVerificationEngine] = None,
        enable_classification_integration: bool = True,
        enable_automated_labeling: bool = True,
        labeling_integration_config: Optional[Dict[str, Any]] = None
    ):
        """Initialize classification-integrated access controller with automated labeling."""
        # Initialize base controller
        super().__init__(config)
        
        # Classification components
        self.classification_engine = classification_engine
        self.clearance_engine = clearance_engine
        self.enable_classification_integration = enable_classification_integration
        self.enable_automated_labeling = enable_automated_labeling
        
        # Initialize automated labeling components
        if enable_automated_labeling:
            try:
                self.labeling_integration_layer = LabelingIntegrationLayer(
                    enhanced_classification_engine=classification_engine,
                    clearance_verification_engine=clearance_engine,
                    config=labeling_integration_config
                )
                
                # Initialize performance optimizer for automated labeling
                optimizer_config = OptimizationConfig(
                    target_latency_ms=config.get('automated_labeling_target_ms', 25.0),
                    cache_enabled=config.get('enable_labeling_cache', True),
                    adaptive_optimization=config.get('adaptive_labeling_optimization', True)
                )
                self.performance_optimizer = PerformanceOptimizer(optimizer_config)
                
                logger.info("Automated labeling integration enabled")
            except Exception as e:
                logger.error(f"Failed to initialize automated labeling: {e}")
                self.labeling_integration_layer = None
                self.performance_optimizer = None
                self.enable_automated_labeling = False
        else:
            self.labeling_integration_layer = None
            self.performance_optimizer = None
        
        # Replace permission resolver with classification-aware version
        if (enable_classification_integration and 
            classification_engine and 
            clearance_engine):
            
            self.classification_aware_resolver = ClassificationAwarePermissionResolver(
                base_resolver=self.cross_platform_resolver,
                classification_engine=classification_engine,
                clearance_engine=clearance_engine
            )
        else:
            self.classification_aware_resolver = None
        
        logger.info("Classification-Integrated Access Controller with Automated Labeling initialized")
    
    async def check_classification_aware_access(
        self,
        request: ClassificationAwareAccessRequest
    ) -> ClassificationAwareAccessResponse:
        """
        Check access with classification awareness.
        
        This is the main entry point for classification-aware access control.
        """
        start_time = time.time()
        
        try:
            # Get user context
            user_context = await self.context_manager.get_user_context(
                request.user_id,
                request.session_id
            )
            
            if not user_context:
                return ClassificationAwareAccessResponse(
                    request_id=request.request_id,
                    decision=AccessDecision.DENY,
                    reason="User context not available",
                    total_processing_time_ms=(time.time() - start_time) * 1000
                )
            
            # Use classification-aware resolver if available
            if self.classification_aware_resolver:
                response = await self.classification_aware_resolver.resolve_permissions(
                    request, user_context
                )
            else:
                # Fallback to base functionality
                unified_request = UnifiedAccessRequest(
                    user_id=request.user_id,
                    resource_type=request.resource_type,
                    action=request.action,
                    resource_id=request.resource_id,
                    platform=request.platform,
                    session_id=request.session_id
                )
                
                base_response = await self.check_access(unified_request)
                
                response = ClassificationAwareAccessResponse(
                    request_id=request.request_id,
                    decision=base_response.decision,
                    reason=base_response.reason,
                    effective_permissions=base_response.effective_permissions,
                    total_processing_time_ms=(time.time() - start_time) * 1000
                )
            
            # Audit logging
            await self._log_classification_aware_access(request, response)
            
            return response
            
        except Exception as e:
            logger.error(f"Classification-aware access check failed: {e}")
            
            return ClassificationAwareAccessResponse(
                request_id=request.request_id,
                decision=AccessDecision.DENY,
                reason=f"Access control error: {str(e)}",
                total_processing_time_ms=(time.time() - start_time) * 1000
            )
    
    async def _log_classification_aware_access(
        self,
        request: ClassificationAwareAccessRequest,
        response: ClassificationAwareAccessResponse
    ):
        """Log classification-aware access for audit purposes."""
        try:
            audit_data = {
                "event_type": "classification_aware_access",
                "request_id": request.request_id,
                "user_id": str(request.user_id),
                "session_id": request.session_id,
                "resource_type": request.resource_type,
                "action": request.action,
                "platform": request.platform,
                "decision": response.decision.value,
                "reason": response.reason,
                "total_processing_time_ms": response.total_processing_time_ms,
                "classification_performed": response.classification_response is not None,
                "clearance_verified": response.clearance_verification is not None,
                "security_warnings_count": len(response.security_warnings),
                "compliance_notes_count": len(response.compliance_notes)
            }
            
            # Add classification details if available
            if response.classification_response:
                audit_data.update({
                    "content_classification": response.classification_response.classification_result.classification_level.name,
                    "classification_confidence": response.classification_response.confidence_score,
                    "classification_time_ms": response.classification_time_ms,
                    "pii_detected": len(response.classification_response.pii_results) > 0
                })
            
            # Add clearance details if available
            if response.clearance_verification:
                audit_data.update({
                    "clearance_status": response.clearance_verification.clearance_status.value,
                    "clearance_decision": response.clearance_verification.access_decision.value,
                    "clearance_verification_time_ms": response.clearance_verification_time_ms,
                    "clearance_confidence": response.clearance_verification.confidence_score
                })
            
            await self.audit_manager.log_unified_access_decision(
                request, response, None, additional_data=audit_data
            )
            
        except Exception as e:
            logger.error(f"Failed to log classification-aware access: {e}")
    
    async def check_access_with_automated_labeling(
        self,
        request: ClassificationAwareAccessRequest,
        enable_source_analysis: bool = True,
        enable_content_analysis: bool = True,
        enable_context_analysis: bool = True
    ) -> ClassificationAwareAccessResponse:
        """
        Check access with comprehensive automated labeling integration.
        
        This method combines automated data labeling with classification-aware
        access control for enhanced accuracy and performance.
        """
        if not self.enable_automated_labeling or not self.labeling_integration_layer:
            # Fall back to standard classification-aware access
            return await self.check_classification_aware_access(request)
        
        start_time = time.time()
        
        try:
            # Create integration request for automated labeling
            labeling_request = IntegrationRequest(
                content=request.resource_content or "",
                content_type="text/plain",
                source_user_id=request.user_id,
                source_network=self._map_network_domain(request.network_domain),
                integration_mode=IntegrationMode.HYBRID,
                processing_priority=self._map_processing_priority(request.max_classification_time_ms),
                labeling_strategy=LabelingStrategy.HYBRID,
                
                # Add context information
                workflow_data=self._extract_workflow_context(request),
                session_data=self._extract_session_context(request),
                
                # Performance requirements
                minimum_confidence=0.7,
                use_existing_engines=True,
                enable_cross_validation=True
            )
            
            # Process with automated labeling integration
            if self.performance_optimizer:
                labeling_result, perf_metrics = self.performance_optimizer.optimize_request_processing(
                    request.request_id,
                    self.labeling_integration_layer.process_integrated_labeling,
                    labeling_request
                )
            else:
                labeling_result = await self.labeling_integration_layer.process_integrated_labeling(labeling_request)
                perf_metrics = {'processing_time_ms': 0.0}
            
            # Create enhanced classification response
            enhanced_response = self._create_enhanced_response_from_labeling(
                request, labeling_result, perf_metrics
            )
            
            # Perform standard access control with enhanced classification
            access_response = await self._perform_access_control_with_classification(
                request, enhanced_response
            )
            
            # Add automated labeling metadata
            access_response.automated_labeling_used = True
            access_response.automated_labeling_confidence = labeling_result.confidence_score
            access_response.engines_used = labeling_result.engines_used
            access_response.cross_validation_passed = labeling_result.cross_validation_passed
            
            processing_time_ms = (time.time() - start_time) * 1000
            access_response.total_processing_time_ms = processing_time_ms
            
            # Log enhanced access decision
            await self._log_automated_labeling_access(request, access_response, labeling_result)
            
            return access_response
            
        except Exception as e:
            logger.error(f"Automated labeling access check failed: {e}")
            # Fall back to standard classification-aware access
            return await self.check_classification_aware_access(request)
    
    def _map_network_domain(self, network_domain: Optional[str]) -> Optional[Any]:
        """Map network domain string to NetworkDomain enum."""
        if not network_domain:
            return None
        
        try:
            from ..rbac.models.data_classification import NetworkDomain
            return NetworkDomain(network_domain.upper())
        except (ValueError, AttributeError):
            return None
    
    def _map_processing_priority(self, max_time_ms: float) -> ProcessingPriority:
        """Map maximum processing time to processing priority."""
        if max_time_ms <= 10.0:
            return ProcessingPriority.CRITICAL
        elif max_time_ms <= 25.0:
            return ProcessingPriority.HIGH
        elif max_time_ms <= 50.0:
            return ProcessingPriority.NORMAL
        elif max_time_ms <= 100.0:
            return ProcessingPriority.LOW
        else:
            return ProcessingPriority.BATCH
    
    def _extract_workflow_context(self, request: ClassificationAwareAccessRequest) -> Dict[str, Any]:
        """Extract workflow context from access request."""
        return {
            'resource_type': request.resource_type,
            'action': request.action,
            'platform': request.platform,
            'session_id': request.session_id,
            'expected_classification': request.expected_classification.value if request.expected_classification else None
        }
    
    def _extract_session_context(self, request: ClassificationAwareAccessRequest) -> Dict[str, Any]:
        """Extract session context from access request."""
        return {
            'user_id': str(request.user_id),
            'session_id': request.session_id,
            'network_domain': request.network_domain,
            'user_clearance': request.user_clearance.level if request.user_clearance else None,
            'session_start': request.timestamp.isoformat(),
            'last_activity': request.timestamp.isoformat()
        }
    
    def _create_enhanced_response_from_labeling(
        self, 
        request: ClassificationAwareAccessRequest,
        labeling_result: IntegrationResult,
        perf_metrics: Dict[str, float]
    ) -> Any:
        """Create enhanced classification response from automated labeling result."""
        # This would create a mock enhanced classification response
        # In production, this would properly map the labeling result
        mock_response = type('MockClassificationResponse', (), {})()
        mock_response.classification_level = labeling_result.final_classification
        mock_response.confidence_score = labeling_result.confidence_score
        mock_response.processing_time_ms = perf_metrics.get('processing_time_ms', 0.0)
        mock_response.reasoning = labeling_result.reasoning
        mock_response.engines_used = labeling_result.engines_used
        
        return mock_response
    
    async def _perform_access_control_with_classification(
        self,
        request: ClassificationAwareAccessRequest,
        classification_response: Any
    ) -> ClassificationAwareAccessResponse:
        """Perform access control using automated labeling classification."""
        # Create updated request with automated labeling classification
        updated_request = ClassificationAwareAccessRequest(
            user_id=request.user_id,
            resource_type=request.resource_type,
            action=request.action,
            resource_id=request.resource_id,
            platform=request.platform,
            session_id=request.session_id,
            resource_content=request.resource_content,
            expected_classification=classification_response.classification_level,
            require_classification_verification=False,  # Already classified
            user_clearance=request.user_clearance,
            client_certificate=request.client_certificate,
            network_domain=request.network_domain,
            request_id=request.request_id,
            timestamp=request.timestamp
        )
        
        # Use standard classification-aware access control
        return await self.check_classification_aware_access(updated_request)
    
    async def _log_automated_labeling_access(
        self,
        request: ClassificationAwareAccessRequest,
        response: ClassificationAwareAccessResponse,
        labeling_result: IntegrationResult
    ):
        """Log access decision with automated labeling details."""
        try:
            audit_data = {
                "automated_labeling_used": True,
                "automated_labeling_confidence": labeling_result.confidence_score,
                "automated_labeling_engines": labeling_result.engines_used,
                "cross_validation_passed": labeling_result.cross_validation_passed,
                "result_consistency": labeling_result.result_consistency,
                "automated_labeling_time_ms": labeling_result.total_processing_time_ms,
                "integration_warnings": len(labeling_result.integration_warnings),
                "fallback_used": labeling_result.fallback_used
            }
            
            # Add component-specific metrics
            if labeling_result.source_analysis_result:
                audit_data["source_analysis_confidence"] = labeling_result.source_analysis_result.confidence_score
                audit_data["sources_analyzed"] = labeling_result.source_analysis_result.sources_analyzed
            
            if labeling_result.content_analysis_result:
                audit_data["content_patterns_detected"] = labeling_result.content_analysis_result.total_patterns
                audit_data["content_analysis_confidence"] = labeling_result.content_analysis_result.confidence_score
            
            if labeling_result.context_processing_result:
                audit_data["context_coverage"] = labeling_result.context_processing_result.context_coverage
                audit_data["context_consistency"] = labeling_result.context_processing_result.context_consistency
            
            await self.audit_manager.log_unified_access_decision(
                request, response, None, additional_data=audit_data
            )
            
        except Exception as e:
            logger.error(f"Failed to log automated labeling access: {e}")
    
    def get_automated_labeling_metrics(self) -> Dict[str, Any]:
        """Get metrics for automated labeling integration."""
        metrics = {}
        
        if self.labeling_integration_layer:
            integration_metrics = self.labeling_integration_layer.get_metrics()
            metrics.update({
                "labeling_total_requests": integration_metrics.total_requests,
                "labeling_success_rate": integration_metrics.successful_integrations / max(1, integration_metrics.total_requests),
                "labeling_average_time_ms": integration_metrics.average_processing_time_ms,
                "labeling_sla_violations": integration_metrics.sla_violations,
                "cross_validation_success_rate": integration_metrics.cross_validation_success_rate
            })
        
        if self.performance_optimizer:
            optimizer_metrics = self.performance_optimizer.get_performance_metrics()
            metrics.update({
                "optimizer_cache_hit_rate": optimizer_metrics.cache_hit_rate,
                "optimizer_sla_compliance": optimizer_metrics.sla_compliance_rate,
                "optimizer_resource_efficiency": optimizer_metrics.resource_efficiency
            })
        
        return metrics
    
    def get_enhanced_performance_metrics(self) -> Dict[str, Any]:
        """Get enhanced performance metrics including classification and automated labeling components."""
        base_metrics = self.get_performance_metrics()
        
        if self.classification_aware_resolver:
            classification_metrics = self.classification_aware_resolver.get_performance_metrics()
            base_metrics.update(classification_metrics)
        
        if self.classification_engine:
            classification_engine_metrics = self.classification_engine.get_performance_metrics()
            base_metrics.update(classification_engine_metrics)
        
        if self.clearance_engine:
            clearance_engine_metrics = self.clearance_engine.get_performance_metrics()
            base_metrics.update(clearance_engine_metrics)
        
        # Add automated labeling metrics
        if self.enable_automated_labeling:
            automated_labeling_metrics = self.get_automated_labeling_metrics()
            base_metrics.update(automated_labeling_metrics)
        
        return base_metrics
    
    async def enhanced_health_check(self) -> Dict[str, Any]:
        """Perform enhanced health check including classification components."""
        health_status = await self.health_check()
        
        # Add classification component health
        if self.classification_engine:
            classification_health = await self.classification_engine.health_check()
            health_status["classification_engine"] = classification_health
        
        if self.clearance_engine:
            clearance_health = await self.clearance_engine.health_check()
            health_status["clearance_engine"] = clearance_health
        
        return health_status


# Convenience functions for integration

async def create_classification_integrated_controller(
    config,
    rbac_engine: RBACEngine,
    attribute_manager: AttributeManager,
    policy_engine: PolicyEngine,
    audit_logger: AuditLogger
) -> ClassificationIntegratedAccessController:
    """Create a fully integrated classification-aware access controller."""
    
    # Create classification engine
    classification_engine = EnhancedMultiClassificationEngine(
        unified_access_controller=None,  # Will be set after controller creation
        audit_logger=audit_logger,
        enable_performance_optimization=True,
        enable_streaming=True
    )
    
    # Create clearance verification engine
    clearance_engine = EnhancedClearanceVerificationEngine(
        rbac_engine=rbac_engine,
        attribute_manager=attribute_manager,
        policy_engine=policy_engine,
        unified_access_controller=None,  # Will be set after controller creation
        audit_logger=audit_logger,
        enable_pki_verification=True
    )
    
    # Create integrated controller
    controller = ClassificationIntegratedAccessController(
        config=config,
        classification_engine=classification_engine,
        clearance_engine=clearance_engine,
        enable_classification_integration=True
    )
    
    # Set circular references
    classification_engine.unified_access_controller = controller
    clearance_engine.unified_access_controller = controller
    
    # Start engines
    await classification_engine.start()
    
    return controller


if __name__ == "__main__":
    # Example usage
    print("Multi-Classification Framework Integration Layer - see code for usage examples")