"""
Mandatory Access Control (MAC) Enforcement Engine

Implements mandatory access control with Bell-LaPadula security model enforcement,
policy evaluation, and access control decision making for the data labeling system.

Classification: UNCLASSIFIED//FOR OFFICIAL USE ONLY
Version: 1.0
Author: Security Compliance Team
Date: 2025-07-17
"""

import logging
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Tuple, Set, Union
from uuid import UUID, uuid4
from enum import Enum
from dataclasses import dataclass, field
from abc import ABC, abstractmethod
from functools import lru_cache
import json

# Import models
from ..models.label_models import (
    DataLabel, ClassificationLevel, NetworkDomain, AccessDecision,
    UserClearanceExtension, LabelAccessPolicy, LabelAuditLog,
    AuditEventType, ValidationStatus
)

# Import existing ABAC system
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent.parent / 'models'))
from abac import ABACContext, PolicyEngine, PolicyDecision, check_permission

logger = logging.getLogger(__name__)


class AccessControlContext(Enum):
    """Context for access control decisions."""
    NORMAL = "NORMAL"
    EMERGENCY = "EMERGENCY"
    MAINTENANCE = "MAINTENANCE"
    AUDIT = "AUDIT"
    SYSTEM = "SYSTEM"


class SecurityViolationType(Enum):
    """Types of security violations."""
    BELL_LAPADULA_READ_UP = "BELL_LAPADULA_READ_UP"
    BELL_LAPADULA_WRITE_DOWN = "BELL_LAPADULA_WRITE_DOWN"
    COMPARTMENT_VIOLATION = "COMPARTMENT_VIOLATION"
    CAVEAT_VIOLATION = "CAVEAT_VIOLATION"
    NETWORK_DOMAIN_VIOLATION = "NETWORK_DOMAIN_VIOLATION"
    TEMPORAL_VIOLATION = "TEMPORAL_VIOLATION"
    POLICY_VIOLATION = "POLICY_VIOLATION"
    INVALID_CLEARANCE = "INVALID_CLEARANCE"


@dataclass
class AccessRequest:
    """Represents an access request to labeled data."""
    request_id: str
    user_id: UUID
    label_id: UUID
    action: str  # read, write, delete, export, etc.
    context: AccessControlContext = AccessControlContext.NORMAL
    justification: Optional[str] = None
    emergency_override: bool = False
    request_timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    session_id: Optional[UUID] = None
    source_ip: Optional[str] = None
    user_agent: Optional[str] = None
    additional_attributes: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for logging."""
        return {
            'request_id': self.request_id,
            'user_id': str(self.user_id),
            'label_id': str(self.label_id),
            'action': self.action,
            'context': self.context.value,
            'justification': self.justification,
            'emergency_override': self.emergency_override,
            'request_timestamp': self.request_timestamp.isoformat(),
            'session_id': str(self.session_id) if self.session_id else None,
            'source_ip': self.source_ip,
            'user_agent': self.user_agent,
            'additional_attributes': self.additional_attributes
        }


@dataclass
class AccessDecisionResult:
    """Result of access control decision."""
    decision: AccessDecision
    request: AccessRequest
    reasons: List[str] = field(default_factory=list)
    violations: List[SecurityViolationType] = field(default_factory=list)
    policy_decisions: List[Dict[str, Any]] = field(default_factory=list)
    confidence_score: float = 1.0
    decision_timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    evaluation_time_ms: Optional[int] = None
    requires_audit: bool = True
    additional_actions: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for logging."""
        return {
            'decision': self.decision.value,
            'request': self.request.to_dict(),
            'reasons': self.reasons,
            'violations': [v.value for v in self.violations],
            'policy_decisions': self.policy_decisions,
            'confidence_score': self.confidence_score,
            'decision_timestamp': self.decision_timestamp.isoformat(),
            'evaluation_time_ms': self.evaluation_time_ms,
            'requires_audit': self.requires_audit,
            'additional_actions': self.additional_actions,
            'metadata': self.metadata
        }


class BellLaPadulaEngine:
    """Implements Bell-LaPadula security model enforcement."""
    
    def __init__(self):
        self.strict_mode = True  # Enforce strict Bell-LaPadula
        self.allow_write_equal = True  # Allow write at same level
        self.compartment_enforcement = True  # Enforce compartment restrictions
    
    def validate_read_access(self, user_clearance: ClassificationLevel, 
                           data_classification: ClassificationLevel,
                           user_compartments: List[UUID] = None,
                           data_compartments: List[UUID] = None) -> Tuple[bool, List[str]]:
        """
        Validate read access using Bell-LaPadula "no read up" rule.
        
        Args:
            user_clearance: User's clearance level
            data_classification: Data classification level
            user_compartments: User's authorized compartments
            data_compartments: Data's required compartments
            
        Returns:
            Tuple of (allowed, reasons)
        """
        reasons = []
        
        # Basic Bell-LaPadula: no read up
        if user_clearance < data_classification:
            reasons.append(f"User clearance {user_clearance.value} insufficient for data classification {data_classification.value}")
            return False, reasons
        
        # Compartment check
        if self.compartment_enforcement and data_compartments:
            user_compartments = user_compartments or []
            missing_compartments = set(data_compartments) - set(user_compartments)
            
            if missing_compartments:
                reasons.append(f"User missing required compartments: {missing_compartments}")
                return False, reasons
        
        reasons.append("Read access granted per Bell-LaPadula model")
        return True, reasons
    
    def validate_write_access(self, user_clearance: ClassificationLevel,
                            data_classification: ClassificationLevel,
                            user_compartments: List[UUID] = None,
                            data_compartments: List[UUID] = None) -> Tuple[bool, List[str]]:
        """
        Validate write access using Bell-LaPadula "no write down" rule.
        
        Args:
            user_clearance: User's clearance level
            data_classification: Data classification level
            user_compartments: User's authorized compartments
            data_compartments: Data's required compartments
            
        Returns:
            Tuple of (allowed, reasons)
        """
        reasons = []
        
        # Basic Bell-LaPadula: no write down
        if self.strict_mode:
            if user_clearance != data_classification:
                reasons.append(f"Strict mode: User clearance {user_clearance.value} must equal data classification {data_classification.value}")
                return False, reasons
        else:
            # Allow write at same level or higher
            if user_clearance < data_classification:
                reasons.append(f"User clearance {user_clearance.value} insufficient for writing to {data_classification.value}")
                return False, reasons
        
        # Compartment check
        if self.compartment_enforcement and data_compartments:
            user_compartments = user_compartments or []
            missing_compartments = set(data_compartments) - set(user_compartments)
            
            if missing_compartments:
                reasons.append(f"User missing required compartments for write: {missing_compartments}")
                return False, reasons
        
        reasons.append("Write access granted per Bell-LaPadula model")
        return True, reasons
    
    def validate_access(self, action: str, user_clearance: ClassificationLevel,
                       data_classification: ClassificationLevel,
                       user_compartments: List[UUID] = None,
                       data_compartments: List[UUID] = None) -> Tuple[bool, List[str], List[SecurityViolationType]]:
        """
        Validate access based on action type.
        
        Args:
            action: Action being performed
            user_clearance: User's clearance level
            data_classification: Data classification level
            user_compartments: User's authorized compartments
            data_compartments: Data's required compartments
            
        Returns:
            Tuple of (allowed, reasons, violations)
        """
        violations = []
        
        # Determine if this is a read or write operation
        read_actions = ['read', 'view', 'download', 'export', 'search', 'query']
        write_actions = ['write', 'update', 'modify', 'delete', 'create', 'upload']
        
        if action.lower() in read_actions:
            allowed, reasons = self.validate_read_access(
                user_clearance, data_classification, user_compartments, data_compartments
            )
            if not allowed:
                violations.append(SecurityViolationType.BELL_LAPADULA_READ_UP)
        
        elif action.lower() in write_actions:
            allowed, reasons = self.validate_write_access(
                user_clearance, data_classification, user_compartments, data_compartments
            )
            if not allowed:
                violations.append(SecurityViolationType.BELL_LAPADULA_WRITE_DOWN)
        
        else:
            # Unknown action - default to read rules
            allowed, reasons = self.validate_read_access(
                user_clearance, data_classification, user_compartments, data_compartments
            )
            if not allowed:
                violations.append(SecurityViolationType.BELL_LAPADULA_READ_UP)
        
        return allowed, reasons, violations


class PolicyEvaluationEngine:
    """Evaluates label access policies."""
    
    def __init__(self, db_connection=None):
        self.db_connection = db_connection
        self.policy_cache = {}
        self.cache_ttl = timedelta(minutes=5)
        self.last_cache_update = None
    
    def evaluate_policies(self, access_request: AccessRequest, 
                         label: DataLabel, 
                         user_clearance: UserClearanceExtension) -> Tuple[AccessDecision, List[Dict[str, Any]]]:
        """
        Evaluate all applicable policies for access request.
        
        Args:
            access_request: Access request details
            label: Data label being accessed
            user_clearance: User's clearance information
            
        Returns:
            Tuple of (decision, policy_decisions)
        """
        # Get applicable policies
        applicable_policies = self._get_applicable_policies(label)
        
        policy_decisions = []
        overall_decision = AccessDecision.PERMIT
        
        for policy in applicable_policies:
            decision = self._evaluate_single_policy(policy, access_request, label, user_clearance)
            policy_decisions.append(decision)
            
            # DENY takes precedence (fail-secure)
            if decision['decision'] == AccessDecision.DENY:
                overall_decision = AccessDecision.DENY
        
        return overall_decision, policy_decisions
    
    def _get_applicable_policies(self, label: DataLabel) -> List[LabelAccessPolicy]:
        """Get policies applicable to the label."""
        # Check cache first
        if self._is_cache_valid():
            cache_key = f"{label.classification_level}_{label.network_domain}"
            if cache_key in self.policy_cache:
                return self.policy_cache[cache_key]
        
        # Get from database
        all_policies = LabelAccessPolicy.find_all({'is_active': True}, self.db_connection)
        applicable_policies = []
        
        for policy in all_policies:
            if policy.applies_to_label(label):
                applicable_policies.append(policy)
        
        # Sort by priority (higher priority first)
        applicable_policies.sort(key=lambda p: p.policy_priority, reverse=True)
        
        # Cache result
        cache_key = f"{label.classification_level}_{label.network_domain}"
        self.policy_cache[cache_key] = applicable_policies
        self.last_cache_update = datetime.now(timezone.utc)
        
        return applicable_policies
    
    def _evaluate_single_policy(self, policy: LabelAccessPolicy, 
                               access_request: AccessRequest,
                               label: DataLabel, 
                               user_clearance: UserClearanceExtension) -> Dict[str, Any]:
        """Evaluate a single policy."""
        decision_result = {
            'policy_id': str(policy.policy_id),
            'policy_name': policy.policy_name,
            'decision': AccessDecision.INDETERMINATE,
            'reasons': [],
            'evaluation_time': datetime.now(timezone.utc).isoformat()
        }
        
        try:
            # Evaluate policy
            decision = policy.evaluate_access(label, user_clearance)
            decision_result['decision'] = decision
            
            if decision == AccessDecision.PERMIT:
                decision_result['reasons'].append(f"Policy {policy.policy_name} permits access")
            elif decision == AccessDecision.DENY:
                decision_result['reasons'].append(f"Policy {policy.policy_name} denies access")
            else:
                decision_result['reasons'].append(f"Policy {policy.policy_name} is indeterminate")
        
        except Exception as e:
            logger.error(f"Error evaluating policy {policy.policy_id}: {e}")
            decision_result['decision'] = AccessDecision.DENY
            decision_result['reasons'].append(f"Policy evaluation error: {str(e)}")
        
        return decision_result
    
    def _is_cache_valid(self) -> bool:
        """Check if policy cache is still valid."""
        if not self.last_cache_update:
            return False
        
        return datetime.now(timezone.utc) - self.last_cache_update < self.cache_ttl
    
    def invalidate_cache(self):
        """Invalidate policy cache."""
        self.policy_cache.clear()
        self.last_cache_update = None


class AccessControlDecisionEngine:
    """Makes final access control decisions."""
    
    def __init__(self, db_connection=None):
        self.db_connection = db_connection
        self.bell_lapadula_engine = BellLaPadulaEngine()
        self.policy_engine = PolicyEvaluationEngine(db_connection)
        self.abac_engine = PolicyEngine(db_connection)
        
        # Decision weights
        self.bell_lapadula_weight = 0.6
        self.policy_weight = 0.3
        self.abac_weight = 0.1
    
    def make_decision(self, access_request: AccessRequest) -> AccessDecisionResult:
        """
        Make comprehensive access control decision.
        
        Args:
            access_request: Access request to evaluate
            
        Returns:
            AccessDecisionResult: Decision with rationale
        """
        start_time = datetime.now(timezone.utc)
        
        # Initialize result
        result = AccessDecisionResult(
            decision=AccessDecision.DENY,  # Fail-secure default
            request=access_request
        )
        
        try:
            # Get label and user clearance
            label = DataLabel.find_by_id(access_request.label_id, self.db_connection)
            if not label:
                result.reasons.append(f"Label {access_request.label_id} not found")
                result.violations.append(SecurityViolationType.POLICY_VIOLATION)
                return result
            
            user_clearance = UserClearanceExtension.find_all({
                'user_id': access_request.user_id,
                'is_active': True
            }, self.db_connection)
            
            if not user_clearance:
                result.reasons.append(f"User {access_request.user_id} has no active clearance")
                result.violations.append(SecurityViolationType.INVALID_CLEARANCE)
                return result
            
            clearance = user_clearance[0]
            
            # Check if user clearance is expired
            if clearance.valid_until and datetime.now(timezone.utc) > clearance.valid_until:
                result.reasons.append("User clearance has expired")
                result.violations.append(SecurityViolationType.INVALID_CLEARANCE)
                return result
            
            # Check if label is active and validated
            if not label.is_active:
                result.reasons.append("Label is not active")
                result.violations.append(SecurityViolationType.POLICY_VIOLATION)
                return result
            
            if label.validation_status == ValidationStatus.REJECTED.value:
                result.reasons.append("Label has been rejected")
                result.violations.append(SecurityViolationType.POLICY_VIOLATION)
                return result
            
            # 1. Bell-LaPadula evaluation
            bell_lapadula_allowed, bell_lapadula_reasons, bell_lapadula_violations = self._evaluate_bell_lapadula(
                access_request, label, clearance
            )
            
            result.reasons.extend(bell_lapadula_reasons)
            result.violations.extend(bell_lapadula_violations)
            
            # 2. Policy evaluation
            policy_decision, policy_decisions = self.policy_engine.evaluate_policies(
                access_request, label, clearance
            )
            
            result.policy_decisions = policy_decisions
            
            # 3. ABAC evaluation (if available)
            abac_decision = self._evaluate_abac(access_request, label, clearance)
            
            # 4. Network domain validation
            network_allowed, network_reasons, network_violations = self._evaluate_network_domain(
                access_request, label, clearance
            )
            
            result.reasons.extend(network_reasons)
            result.violations.extend(network_violations)
            
            # 5. Temporal validation
            temporal_allowed, temporal_reasons, temporal_violations = self._evaluate_temporal_constraints(
                access_request, label, clearance
            )
            
            result.reasons.extend(temporal_reasons)
            result.violations.extend(temporal_violations)
            
            # 6. Emergency override check
            emergency_allowed = self._check_emergency_override(access_request, clearance)
            
            # Make final decision
            if emergency_allowed:
                result.decision = AccessDecision.PERMIT
                result.reasons.append("Emergency override granted")
                result.additional_actions.append("EMERGENCY_AUDIT_REQUIRED")
            else:
                # All checks must pass
                all_checks_passed = (
                    bell_lapadula_allowed and
                    policy_decision != AccessDecision.DENY and
                    abac_decision != AccessDecision.DENY and
                    network_allowed and
                    temporal_allowed
                )
                
                if all_checks_passed:
                    result.decision = AccessDecision.PERMIT
                    result.reasons.append("All access control checks passed")
                else:
                    result.decision = AccessDecision.DENY
                    result.reasons.append("One or more access control checks failed")
            
            # Calculate confidence score
            result.confidence_score = self._calculate_confidence_score(
                bell_lapadula_allowed, policy_decision, abac_decision,
                network_allowed, temporal_allowed
            )
            
        except Exception as e:
            logger.error(f"Error in access control decision: {e}")
            result.decision = AccessDecision.DENY
            result.reasons.append(f"Access control error: {str(e)}")
            result.violations.append(SecurityViolationType.POLICY_VIOLATION)
        
        # Calculate evaluation time
        end_time = datetime.now(timezone.utc)
        result.evaluation_time_ms = int((end_time - start_time).total_seconds() * 1000)
        
        return result
    
    def _evaluate_bell_lapadula(self, access_request: AccessRequest, 
                               label: DataLabel, 
                               clearance: UserClearanceExtension) -> Tuple[bool, List[str], List[SecurityViolationType]]:
        """Evaluate Bell-LaPadula security model."""
        user_clearance_level = clearance.get_clearance_level_enum()
        data_classification = label.get_classification_level_enum()
        
        return self.bell_lapadula_engine.validate_access(
            access_request.action,
            user_clearance_level,
            data_classification,
            clearance.authorized_compartments,
            label.compartments
        )
    
    def _evaluate_abac(self, access_request: AccessRequest, 
                      label: DataLabel, 
                      clearance: UserClearanceExtension) -> AccessDecision:
        """Evaluate using ABAC system."""
        try:
            # Convert to ABAC context
            is_authorized = check_permission(
                user_id=access_request.user_id,
                resource_type=label.data_object_type,
                action_type=access_request.action,
                resource_id=label.data_object_id,
                db_connection=self.db_connection
            )
            
            return AccessDecision.PERMIT if is_authorized else AccessDecision.DENY
        
        except Exception as e:
            logger.error(f"ABAC evaluation error: {e}")
            return AccessDecision.INDETERMINATE
    
    def _evaluate_network_domain(self, access_request: AccessRequest, 
                                label: DataLabel, 
                                clearance: UserClearanceExtension) -> Tuple[bool, List[str], List[SecurityViolationType]]:
        """Evaluate network domain restrictions."""
        reasons = []
        violations = []
        
        domain_enum = label.get_network_domain_enum()
        
        # Check if user has access to network domain
        if not clearance.can_access_network_domain(domain_enum):
            reasons.append(f"User does not have access to network domain {domain_enum.value}")
            violations.append(SecurityViolationType.NETWORK_DOMAIN_VIOLATION)
            return False, reasons, violations
        
        reasons.append(f"Network domain {domain_enum.value} access granted")
        return True, reasons, violations
    
    def _evaluate_temporal_constraints(self, access_request: AccessRequest, 
                                     label: DataLabel, 
                                     clearance: UserClearanceExtension) -> Tuple[bool, List[str], List[SecurityViolationType]]:
        """Evaluate temporal constraints."""
        reasons = []
        violations = []
        
        # Check if data is declassified
        if label.declassification_date and datetime.now(timezone.utc) > label.declassification_date:
            reasons.append("Data has been declassified")
            return True, reasons, violations
        
        # Check business hours (if required)
        current_time = datetime.now(timezone.utc)
        if access_request.context == AccessControlContext.NORMAL:
            # Check if this is during business hours (simplified check)
            if current_time.weekday() >= 5:  # Weekend
                reasons.append("Access during business hours only")
                violations.append(SecurityViolationType.TEMPORAL_VIOLATION)
                return False, reasons, violations
        
        reasons.append("Temporal constraints satisfied")
        return True, reasons, violations
    
    def _check_emergency_override(self, access_request: AccessRequest, 
                                 clearance: UserClearanceExtension) -> bool:
        """Check if emergency override is applicable."""
        if not access_request.emergency_override:
            return False
        
        # Check if user has emergency override authority
        if clearance.clearance_level in ['TOP_SECRET', 'TOP_SECRET_SCI']:
            return True
        
        # Check if this is an emergency context
        if access_request.context == AccessControlContext.EMERGENCY:
            return True
        
        return False
    
    def _calculate_confidence_score(self, bell_lapadula_allowed: bool, 
                                   policy_decision: AccessDecision, 
                                   abac_decision: AccessDecision,
                                   network_allowed: bool, 
                                   temporal_allowed: bool) -> float:
        """Calculate confidence score for decision."""
        score = 0.0
        
        if bell_lapadula_allowed:
            score += self.bell_lapadula_weight
        
        if policy_decision == AccessDecision.PERMIT:
            score += self.policy_weight
        
        if abac_decision == AccessDecision.PERMIT:
            score += self.abac_weight
        
        if network_allowed:
            score += 0.05
        
        if temporal_allowed:
            score += 0.05
        
        return min(1.0, score)


class MACEnforcementEngine:
    """Main engine for mandatory access control enforcement."""
    
    def __init__(self, db_connection=None):
        self.db_connection = db_connection
        self.decision_engine = AccessControlDecisionEngine(db_connection)
        self.audit_all_decisions = True
        self.deny_unknown_actions = True
        self.emergency_bypass_enabled = True
        
        # Performance metrics
        self.decision_count = 0
        self.permit_count = 0
        self.deny_count = 0
        self.average_decision_time = 0.0
    
    def enforce_access(self, user_id: UUID, label_id: UUID, action: str,
                      context: AccessControlContext = AccessControlContext.NORMAL,
                      justification: str = None,
                      emergency_override: bool = False,
                      session_id: UUID = None,
                      source_ip: str = None,
                      user_agent: str = None) -> AccessDecisionResult:
        """
        Enforce access control for labeled data.
        
        Args:
            user_id: User requesting access
            label_id: Label being accessed
            action: Action being performed
            context: Access control context
            justification: Justification for access
            emergency_override: Emergency override flag
            session_id: Session identifier
            source_ip: Source IP address
            user_agent: User agent string
            
        Returns:
            AccessDecisionResult: Decision with rationale
        """
        # Create access request
        access_request = AccessRequest(
            request_id=str(uuid4()),
            user_id=user_id,
            label_id=label_id,
            action=action,
            context=context,
            justification=justification,
            emergency_override=emergency_override,
            session_id=session_id,
            source_ip=source_ip,
            user_agent=user_agent
        )
        
        # Make decision
        decision_result = self.decision_engine.make_decision(access_request)
        
        # Update metrics
        self._update_metrics(decision_result)
        
        # Audit decision
        if self.audit_all_decisions or decision_result.requires_audit:
            self._audit_decision(decision_result)
        
        return decision_result
    
    def batch_enforce_access(self, access_requests: List[Dict[str, Any]]) -> List[AccessDecisionResult]:
        """Enforce access control for multiple requests."""
        results = []
        
        for request_data in access_requests:
            try:
                result = self.enforce_access(**request_data)
                results.append(result)
            except Exception as e:
                logger.error(f"Error in batch access enforcement: {e}")
                # Create error result
                error_result = AccessDecisionResult(
                    decision=AccessDecision.DENY,
                    request=AccessRequest(
                        request_id=str(uuid4()),
                        user_id=request_data.get('user_id'),
                        label_id=request_data.get('label_id'),
                        action=request_data.get('action', 'unknown')
                    ),
                    reasons=[f"Batch enforcement error: {str(e)}"],
                    metadata={'error': str(e)}
                )
                results.append(error_result)
        
        return results
    
    def check_label_access(self, user_id: UUID, label: DataLabel, 
                          action: str = 'read') -> Tuple[bool, str]:
        """
        Simple check for label access.
        
        Args:
            user_id: User ID
            label: Data label
            action: Action to check
            
        Returns:
            Tuple of (allowed, reason)
        """
        decision_result = self.enforce_access(user_id, label.label_id, action)
        
        return (
            decision_result.decision == AccessDecision.PERMIT,
            '; '.join(decision_result.reasons)
        )
    
    def get_accessible_labels(self, user_id: UUID, 
                             action: str = 'read',
                             max_labels: int = 1000) -> List[DataLabel]:
        """
        Get all labels accessible to user.
        
        Args:
            user_id: User ID
            action: Action to check
            max_labels: Maximum number of labels to check
            
        Returns:
            List of accessible labels
        """
        accessible_labels = []
        
        # Get all active labels
        all_labels = DataLabel.find_all({'is_active': True}, self.db_connection)
        
        # Limit to max_labels for performance
        labels_to_check = all_labels[:max_labels]
        
        for label in labels_to_check:
            allowed, _ = self.check_label_access(user_id, label, action)
            if allowed:
                accessible_labels.append(label)
        
        return accessible_labels
    
    def _update_metrics(self, decision_result: AccessDecisionResult):
        """Update performance metrics."""
        self.decision_count += 1
        
        if decision_result.decision == AccessDecision.PERMIT:
            self.permit_count += 1
        elif decision_result.decision == AccessDecision.DENY:
            self.deny_count += 1
        
        # Update average decision time
        if decision_result.evaluation_time_ms:
            self.average_decision_time = (
                (self.average_decision_time * (self.decision_count - 1) + decision_result.evaluation_time_ms) 
                / self.decision_count
            )
    
    def _audit_decision(self, decision_result: AccessDecisionResult):
        """Audit access control decision."""
        try:
            event_type = AuditEventType.ACCESS_GRANTED if decision_result.decision == AccessDecision.PERMIT else AuditEventType.ACCESS_DENIED
            
            description = f"Access {decision_result.decision.value.lower()}: {decision_result.request.action} on {decision_result.request.label_id}"
            
            LabelAuditLog.log_event(
                event_type=event_type,
                event_description=description,
                user_id=decision_result.request.user_id,
                label_id=decision_result.request.label_id,
                event_outcome=decision_result.decision,
                state_after=decision_result.to_dict(),
                audit_metadata={
                    'request_id': decision_result.request.request_id,
                    'action': decision_result.request.action,
                    'context': decision_result.request.context.value,
                    'evaluation_time_ms': decision_result.evaluation_time_ms,
                    'confidence_score': decision_result.confidence_score,
                    'violations': [v.value for v in decision_result.violations]
                },
                db_connection=self.db_connection
            )
        
        except Exception as e:
            logger.error(f"Failed to audit access decision: {e}")
    
    def get_enforcement_statistics(self) -> Dict[str, Any]:
        """Get enforcement statistics."""
        return {
            'total_decisions': self.decision_count,
            'permit_decisions': self.permit_count,
            'deny_decisions': self.deny_count,
            'permit_rate': self.permit_count / self.decision_count if self.decision_count > 0 else 0,
            'deny_rate': self.deny_count / self.decision_count if self.decision_count > 0 else 0,
            'average_decision_time_ms': self.average_decision_time,
            'configuration': {
                'audit_all_decisions': self.audit_all_decisions,
                'deny_unknown_actions': self.deny_unknown_actions,
                'emergency_bypass_enabled': self.emergency_bypass_enabled
            }
        }
    
    def reset_statistics(self):
        """Reset enforcement statistics."""
        self.decision_count = 0
        self.permit_count = 0
        self.deny_count = 0
        self.average_decision_time = 0.0
    
    def validate_security_configuration(self) -> List[str]:
        """Validate security configuration."""
        issues = []
        
        if not self.audit_all_decisions:
            issues.append("Audit all decisions is disabled - potential compliance issue")
        
        if not self.deny_unknown_actions:
            issues.append("Unknown actions are not denied - potential security risk")
        
        if self.emergency_bypass_enabled:
            issues.append("Emergency bypass is enabled - ensure proper controls")
        
        return issues