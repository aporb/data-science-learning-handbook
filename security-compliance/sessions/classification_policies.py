#!/usr/bin/env python3
"""
Classification-Aware Session Policies

Implements DoD-compliant classification-specific session policies including
timeout policies, security controls, and cross-domain access management.

Classification: UNCLASSIFIED//FOR OFFICIAL USE ONLY
Version: 1.0
Author: Security Compliance Team
Date: 2025-07-18
"""

import json
import logging
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Set, Tuple
from uuid import UUID
from enum import Enum
from dataclasses import dataclass, field
from abc import ABC, abstractmethod

# Import session management components
from .session_manager import (
    SessionConfiguration, SessionSecurityContext, Session, 
    SessionState, NetworkDomain, SessionEventType
)

logger = logging.getLogger(__name__)


class ClassificationLevel(Enum):
    """DoD classification levels."""
    UNCLASSIFIED = "U"
    CONFIDENTIAL = "C"
    SECRET = "S"
    TOP_SECRET = "TS"
    
    @property
    def numeric_level(self) -> int:
        """Get numeric representation for comparison."""
        levels = {"U": 0, "C": 1, "S": 2, "TS": 3}
        return levels[self.value]
    
    def __lt__(self, other):
        return self.numeric_level < other.numeric_level
    
    def __le__(self, other):
        return self.numeric_level <= other.numeric_level
    
    def __gt__(self, other):
        return self.numeric_level > other.numeric_level
    
    def __ge__(self, other):
        return self.numeric_level >= other.numeric_level


class AccessControlModel(Enum):
    """Access control models for sessions."""
    DISCRETIONARY = "DAC"  # Discretionary Access Control
    MANDATORY = "MAC"      # Mandatory Access Control
    ROLE_BASED = "RBAC"    # Role-Based Access Control
    ATTRIBUTE_BASED = "ABAC"  # Attribute-Based Access Control


@dataclass
class ClassificationPolicy:
    """Classification-specific session policy."""
    classification_level: ClassificationLevel
    network_domain: NetworkDomain
    max_session_duration: timedelta
    max_idle_time: timedelta
    warning_time: timedelta
    concurrent_session_limit: int
    require_mfa: bool
    require_cac: bool
    require_continuous_auth: bool
    allowed_operations: Set[str]
    restricted_operations: Set[str]
    access_control_model: AccessControlModel
    audit_level: str
    encryption_required: bool
    session_binding_required: bool
    cross_domain_allowed: bool
    auto_lock_idle: bool
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class NetworkPolicy:
    """Network domain-specific policies."""
    domain: NetworkDomain
    allowed_classification_levels: Set[ClassificationLevel]
    encryption_requirements: Dict[str, str]
    access_restrictions: Dict[str, Any]
    bandwidth_limits: Dict[str, int]
    connection_timeouts: Dict[str, int]
    monitoring_level: str
    cross_domain_rules: Dict[str, Any]
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class TimeoutConfiguration:
    """Timeout configuration for different scenarios."""
    idle_timeout: timedelta
    session_timeout: timedelta
    warning_period: timedelta
    grace_period: timedelta
    escalation_timeout: timedelta
    inactivity_detection_interval: timedelta
    auto_extension_enabled: bool = False
    max_extensions: int = 0
    extension_duration: timedelta = timedelta(minutes=15)


@dataclass
class SecurityControl:
    """Security control definition."""
    control_id: str
    control_name: str
    control_type: str
    classification_levels: Set[ClassificationLevel]
    network_domains: Set[NetworkDomain]
    enforcement_level: str  # MANDATORY, RECOMMENDED, OPTIONAL
    validation_rules: List[str]
    violation_actions: List[str]
    metadata: Dict[str, Any] = field(default_factory=dict)


class PolicyEngine(ABC):
    """Abstract base class for policy engines."""
    
    @abstractmethod
    def evaluate_policy(self, session: Session, operation: str, context: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        """Evaluate policy for session operation."""
        pass
    
    @abstractmethod
    def get_applicable_policies(self, session: Session) -> List[Any]:
        """Get applicable policies for session."""
        pass


class ClassificationPolicyEngine(PolicyEngine):
    """
    Classification-aware policy engine for session management.
    
    Implements DoD-compliant classification policies including:
    - Bell-LaPadula security model enforcement
    - Classification-specific timeout policies
    - Cross-domain access controls
    - Need-to-know validation
    - Security control enforcement
    """
    
    def __init__(self):
        """Initialize classification policy engine."""
        self.classification_policies = self._initialize_classification_policies()
        self.network_policies = self._initialize_network_policies()
        self.security_controls = self._initialize_security_controls()
        self.timeout_configurations = self._initialize_timeout_configurations()
        
        logger.info("ClassificationPolicyEngine initialized")
    
    def get_session_policy(self, 
                          classification_level: str,
                          network_domain: NetworkDomain) -> ClassificationPolicy:
        """Get session policy for classification level and network domain.
        
        Args:
            classification_level: Classification level
            network_domain: Network domain
            
        Returns:
            Applicable classification policy
        """
        try:
            level = ClassificationLevel(classification_level)
            policy_key = (level, network_domain)
            
            if policy_key in self.classification_policies:
                return self.classification_policies[policy_key]
            
            # Fall back to default policy for classification level
            for (policy_level, policy_domain), policy in self.classification_policies.items():
                if policy_level == level:
                    return policy
            
            # Ultimate fallback to unclassified policy
            return self.classification_policies[(ClassificationLevel.UNCLASSIFIED, NetworkDomain.NIPR)]
            
        except ValueError:
            # Invalid classification level, use unclassified
            return self.classification_policies[(ClassificationLevel.UNCLASSIFIED, NetworkDomain.NIPR)]
    
    def validate_session_access(self, 
                               session: Session,
                               required_classification: str,
                               operation: str = None) -> Tuple[bool, Optional[str]]:
        """Validate session access for classification level.
        
        Args:
            session: Session to validate
            required_classification: Required classification level
            operation: Optional operation being performed
            
        Returns:
            Tuple of (allowed, reason if denied)
        """
        try:
            required_level = ClassificationLevel(required_classification)
            user_clearance = ClassificationLevel(session.security_context.clearance_level or "U")
            session_level = ClassificationLevel(session.security_context.classification_level)
            
            # Bell-LaPadula: No read up (user clearance must be >= required level)
            if user_clearance < required_level:
                return False, f"Insufficient clearance: {user_clearance.value} < {required_level.value}"
            
            # Session classification level must match or exceed required level
            if session_level < required_level:
                return False, f"Session classification insufficient: {session_level.value} < {required_level.value}"
            
            # Check network domain compatibility
            network_policy = self.network_policies.get(session.security_context.network_domain)
            if network_policy and required_level not in network_policy.allowed_classification_levels:
                return False, f"Classification {required_level.value} not allowed on {session.security_context.network_domain.value}"
            
            # Check operation restrictions
            if operation:
                policy = self.get_session_policy(session.security_context.classification_level, 
                                               session.security_context.network_domain)
                if operation in policy.restricted_operations:
                    return False, f"Operation {operation} restricted for {required_level.value}"
                
                if policy.allowed_operations and operation not in policy.allowed_operations:
                    return False, f"Operation {operation} not allowed for {required_level.value}"
            
            return True, None
            
        except ValueError as e:
            return False, f"Invalid classification level: {e}"
    
    def validate_cross_domain_access(self, 
                                   session: Session,
                                   target_domain: NetworkDomain,
                                   target_classification: str) -> Tuple[bool, Optional[str]]:
        """Validate cross-domain access request.
        
        Args:
            session: Source session
            target_domain: Target network domain
            target_classification: Target classification level
            
        Returns:
            Tuple of (allowed, reason if denied)
        """
        source_domain = session.security_context.network_domain
        source_classification = session.security_context.classification_level
        
        # Check if cross-domain access is allowed
        source_policy = self.get_session_policy(source_classification, source_domain)
        if not source_policy.cross_domain_allowed:
            return False, "Cross-domain access not allowed by policy"
        
        # Check domain compatibility
        if not self._validate_domain_compatibility(source_domain, target_domain):
            return False, f"Domain {source_domain.value} to {target_domain.value} not allowed"
        
        # Check classification compatibility
        if not self._validate_classification_compatibility(source_classification, target_classification):
            return False, f"Classification {source_classification} to {target_classification} not allowed"
        
        # Check security controls
        for control in self.security_controls:
            if (source_domain in control.network_domains and 
                target_domain in control.network_domains and
                control.enforcement_level == "MANDATORY"):
                # Evaluate control
                if not self._evaluate_security_control(session, control, {"target_domain": target_domain}):
                    return False, f"Security control {control.control_id} failed"
        
        return True, None
    
    def get_timeout_policy(self, 
                          classification_level: str,
                          network_domain: NetworkDomain,
                          user_activity_level: str = "NORMAL") -> TimeoutConfiguration:
        """Get timeout policy for classification and activity level.
        
        Args:
            classification_level: Classification level
            network_domain: Network domain
            user_activity_level: User activity level (LOW, NORMAL, HIGH)
            
        Returns:
            Timeout configuration
        """
        try:
            level = ClassificationLevel(classification_level)
            config_key = (level, network_domain, user_activity_level)
            
            if config_key in self.timeout_configurations:
                return self.timeout_configurations[config_key]
            
            # Fall back to normal activity level
            fallback_key = (level, network_domain, "NORMAL")
            if fallback_key in self.timeout_configurations:
                return self.timeout_configurations[fallback_key]
            
            # Create default configuration
            return self._create_default_timeout_config(level, network_domain)
            
        except ValueError:
            # Invalid classification, use unclassified defaults
            return self._create_default_timeout_config(ClassificationLevel.UNCLASSIFIED, network_domain)
    
    def evaluate_policy(self, 
                       session: Session,
                       operation: str,
                       context: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        """Evaluate policy for session operation.
        
        Args:
            session: Session to evaluate
            operation: Operation being performed
            context: Additional context for evaluation
            
        Returns:
            Tuple of (allowed, reason if denied)
        """
        # Get applicable policy
        policy = self.get_session_policy(
            session.security_context.classification_level,
            session.security_context.network_domain
        )
        
        # Check operation permissions
        if operation in policy.restricted_operations:
            return False, f"Operation {operation} is restricted"
        
        if policy.allowed_operations and operation not in policy.allowed_operations:
            return False, f"Operation {operation} not in allowed operations"
        
        # Check classification requirements
        required_classification = context.get('required_classification')
        if required_classification:
            allowed, reason = self.validate_session_access(session, required_classification, operation)
            if not allowed:
                return False, reason
        
        # Check MFA requirements
        if policy.require_mfa and not session.mfa_verified:
            return False, "Multi-factor authentication required"
        
        # Check continuous authentication
        if policy.require_continuous_auth:
            last_auth_time = context.get('last_auth_time')
            if not last_auth_time or (datetime.now(timezone.utc) - last_auth_time) > timedelta(minutes=15):
                return False, "Continuous authentication required"
        
        # Check session binding
        if policy.session_binding_required:
            if not session.bound_ip or not session.bound_cac_serial:
                return False, "Session binding required but not established"
        
        return True, None
    
    def get_applicable_policies(self, session: Session) -> List[ClassificationPolicy]:
        """Get applicable policies for session.
        
        Args:
            session: Session to get policies for
            
        Returns:
            List of applicable policies
        """
        applicable_policies = []
        
        # Primary policy for session's classification and domain
        primary_policy = self.get_session_policy(
            session.security_context.classification_level,
            session.security_context.network_domain
        )
        applicable_policies.append(primary_policy)
        
        # Additional policies based on session attributes
        for (level, domain), policy in self.classification_policies.items():
            if (level.value == session.security_context.classification_level and
                domain != session.security_context.network_domain):
                # Policies for same classification on different domains
                applicable_policies.append(policy)
        
        return applicable_policies
    
    def _initialize_classification_policies(self) -> Dict[Tuple[ClassificationLevel, NetworkDomain], ClassificationPolicy]:
        """Initialize classification-specific policies."""
        policies = {}
        
        # UNCLASSIFIED policies
        policies[(ClassificationLevel.UNCLASSIFIED, NetworkDomain.NIPR)] = ClassificationPolicy(
            classification_level=ClassificationLevel.UNCLASSIFIED,
            network_domain=NetworkDomain.NIPR,
            max_session_duration=timedelta(hours=8),
            max_idle_time=timedelta(minutes=30),
            warning_time=timedelta(minutes=5),
            concurrent_session_limit=3,
            require_mfa=False,
            require_cac=False,
            require_continuous_auth=False,
            allowed_operations={"read", "write", "execute", "admin"},
            restricted_operations=set(),
            access_control_model=AccessControlModel.ROLE_BASED,
            audit_level="BASIC",
            encryption_required=True,
            session_binding_required=False,
            cross_domain_allowed=False,
            auto_lock_idle=False
        )
        
        # CONFIDENTIAL policies
        policies[(ClassificationLevel.CONFIDENTIAL, NetworkDomain.NIPR)] = ClassificationPolicy(
            classification_level=ClassificationLevel.CONFIDENTIAL,
            network_domain=NetworkDomain.NIPR,
            max_session_duration=timedelta(hours=6),
            max_idle_time=timedelta(minutes=20),
            warning_time=timedelta(minutes=5),
            concurrent_session_limit=2,
            require_mfa=True,
            require_cac=True,
            require_continuous_auth=False,
            allowed_operations={"read", "write", "admin"},
            restricted_operations={"bulk_export", "external_share"},
            access_control_model=AccessControlModel.MANDATORY,
            audit_level="DETAILED",
            encryption_required=True,
            session_binding_required=True,
            cross_domain_allowed=False,
            auto_lock_idle=True
        )
        
        # SECRET policies
        policies[(ClassificationLevel.SECRET, NetworkDomain.SIPR)] = ClassificationPolicy(
            classification_level=ClassificationLevel.SECRET,
            network_domain=NetworkDomain.SIPR,
            max_session_duration=timedelta(hours=4),
            max_idle_time=timedelta(minutes=15),
            warning_time=timedelta(minutes=3),
            concurrent_session_limit=1,
            require_mfa=True,
            require_cac=True,
            require_continuous_auth=True,
            allowed_operations={"read", "write"},
            restricted_operations={"bulk_export", "external_share", "print"},
            access_control_model=AccessControlModel.MANDATORY,
            audit_level="COMPREHENSIVE",
            encryption_required=True,
            session_binding_required=True,
            cross_domain_allowed=False,
            auto_lock_idle=True
        )
        
        # TOP SECRET policies
        policies[(ClassificationLevel.TOP_SECRET, NetworkDomain.JWICS)] = ClassificationPolicy(
            classification_level=ClassificationLevel.TOP_SECRET,
            network_domain=NetworkDomain.JWICS,
            max_session_duration=timedelta(hours=2),
            max_idle_time=timedelta(minutes=10),
            warning_time=timedelta(minutes=2),
            concurrent_session_limit=1,
            require_mfa=True,
            require_cac=True,
            require_continuous_auth=True,
            allowed_operations={"read"},
            restricted_operations={"write", "bulk_export", "external_share", "print", "copy"},
            access_control_model=AccessControlModel.MANDATORY,
            audit_level="COMPREHENSIVE",
            encryption_required=True,
            session_binding_required=True,
            cross_domain_allowed=False,
            auto_lock_idle=True
        )
        
        return policies
    
    def _initialize_network_policies(self) -> Dict[NetworkDomain, NetworkPolicy]:
        """Initialize network domain policies."""
        policies = {}
        
        policies[NetworkDomain.NIPR] = NetworkPolicy(
            domain=NetworkDomain.NIPR,
            allowed_classification_levels={ClassificationLevel.UNCLASSIFIED, ClassificationLevel.CONFIDENTIAL},
            encryption_requirements={
                "data_in_transit": "TLS_1.3",
                "data_at_rest": "AES_256"
            },
            access_restrictions={
                "external_access": False,
                "contractor_access": True,
                "foreign_national_access": False
            },
            bandwidth_limits={
                "per_session": 100_000_000,  # 100 Mbps
                "per_user": 1_000_000_000   # 1 Gbps
            },
            connection_timeouts={
                "tcp_timeout": 300,
                "http_timeout": 60
            },
            monitoring_level="STANDARD",
            cross_domain_rules={
                "to_sipr": False,
                "to_jwics": False
            }
        )
        
        policies[NetworkDomain.SIPR] = NetworkPolicy(
            domain=NetworkDomain.SIPR,
            allowed_classification_levels={ClassificationLevel.SECRET, ClassificationLevel.CONFIDENTIAL},
            encryption_requirements={
                "data_in_transit": "NSA_SUITE_B",
                "data_at_rest": "AES_256_GCM"
            },
            access_restrictions={
                "external_access": False,
                "contractor_access": False,
                "foreign_national_access": False
            },
            bandwidth_limits={
                "per_session": 50_000_000,   # 50 Mbps
                "per_user": 500_000_000     # 500 Mbps
            },
            connection_timeouts={
                "tcp_timeout": 180,
                "http_timeout": 30
            },
            monitoring_level="ENHANCED",
            cross_domain_rules={
                "to_nipr": False,
                "to_jwics": False
            }
        )
        
        policies[NetworkDomain.JWICS] = NetworkPolicy(
            domain=NetworkDomain.JWICS,
            allowed_classification_levels={ClassificationLevel.TOP_SECRET, ClassificationLevel.SECRET},
            encryption_requirements={
                "data_in_transit": "NSA_SUITE_B_TOP_SECRET",
                "data_at_rest": "NSA_APPROVED_CRYPTOGRAPHY"
            },
            access_restrictions={
                "external_access": False,
                "contractor_access": False,
                "foreign_national_access": False
            },
            bandwidth_limits={
                "per_session": 25_000_000,   # 25 Mbps
                "per_user": 250_000_000     # 250 Mbps
            },
            connection_timeouts={
                "tcp_timeout": 120,
                "http_timeout": 20
            },
            monitoring_level="MAXIMUM",
            cross_domain_rules={
                "to_nipr": False,
                "to_sipr": False
            }
        )
        
        return policies
    
    def _initialize_security_controls(self) -> List[SecurityControl]:
        """Initialize security controls."""
        return [
            SecurityControl(
                control_id="AC-2",
                control_name="Account Management",
                control_type="ACCESS_CONTROL",
                classification_levels={ClassificationLevel.CONFIDENTIAL, ClassificationLevel.SECRET, ClassificationLevel.TOP_SECRET},
                network_domains={NetworkDomain.NIPR, NetworkDomain.SIPR, NetworkDomain.JWICS},
                enforcement_level="MANDATORY",
                validation_rules=["active_clearance", "valid_cac", "current_background_investigation"],
                violation_actions=["suspend_session", "audit_log", "notify_security"]
            ),
            SecurityControl(
                control_id="IA-2",
                control_name="Identification and Authentication",
                control_type="AUTHENTICATION",
                classification_levels={ClassificationLevel.SECRET, ClassificationLevel.TOP_SECRET},
                network_domains={NetworkDomain.SIPR, NetworkDomain.JWICS},
                enforcement_level="MANDATORY",
                validation_rules=["mfa_verified", "cac_present", "continuous_auth"],
                violation_actions=["terminate_session", "security_alert"]
            ),
            SecurityControl(
                control_id="SC-8",
                control_name="Transmission Confidentiality",
                control_type="SYSTEM_COMMUNICATIONS",
                classification_levels={ClassificationLevel.CONFIDENTIAL, ClassificationLevel.SECRET, ClassificationLevel.TOP_SECRET},
                network_domains={NetworkDomain.NIPR, NetworkDomain.SIPR, NetworkDomain.JWICS},
                enforcement_level="MANDATORY",
                validation_rules=["encryption_enabled", "approved_algorithms"],
                violation_actions=["block_transmission", "audit_log"]
            )
        ]
    
    def _initialize_timeout_configurations(self) -> Dict[Tuple[ClassificationLevel, NetworkDomain, str], TimeoutConfiguration]:
        """Initialize timeout configurations."""
        configs = {}
        
        # UNCLASSIFIED configurations
        configs[(ClassificationLevel.UNCLASSIFIED, NetworkDomain.NIPR, "NORMAL")] = TimeoutConfiguration(
            idle_timeout=timedelta(minutes=30),
            session_timeout=timedelta(hours=8),
            warning_period=timedelta(minutes=5),
            grace_period=timedelta(minutes=2),
            escalation_timeout=timedelta(hours=4),
            inactivity_detection_interval=timedelta(minutes=1),
            auto_extension_enabled=True,
            max_extensions=2,
            extension_duration=timedelta(minutes=30)
        )
        
        # SECRET configurations
        configs[(ClassificationLevel.SECRET, NetworkDomain.SIPR, "NORMAL")] = TimeoutConfiguration(
            idle_timeout=timedelta(minutes=15),
            session_timeout=timedelta(hours=4),
            warning_period=timedelta(minutes=3),
            grace_period=timedelta(minutes=1),
            escalation_timeout=timedelta(hours=2),
            inactivity_detection_interval=timedelta(seconds=30),
            auto_extension_enabled=False,
            max_extensions=0
        )
        
        # TOP SECRET configurations
        configs[(ClassificationLevel.TOP_SECRET, NetworkDomain.JWICS, "NORMAL")] = TimeoutConfiguration(
            idle_timeout=timedelta(minutes=10),
            session_timeout=timedelta(hours=2),
            warning_period=timedelta(minutes=2),
            grace_period=timedelta(seconds=30),
            escalation_timeout=timedelta(hours=1),
            inactivity_detection_interval=timedelta(seconds=15),
            auto_extension_enabled=False,
            max_extensions=0
        )
        
        return configs
    
    def _validate_domain_compatibility(self, source_domain: NetworkDomain, target_domain: NetworkDomain) -> bool:
        """Validate domain compatibility for cross-domain access."""
        # Generally, cross-domain access is not allowed in DoD
        return False
    
    def _validate_classification_compatibility(self, source_classification: str, target_classification: str) -> bool:
        """Validate classification compatibility."""
        try:
            source_level = ClassificationLevel(source_classification)
            target_level = ClassificationLevel(target_classification)
            
            # Bell-LaPadula: No write down (can only write to same or higher classification)
            return source_level <= target_level
            
        except ValueError:
            return False
    
    def _evaluate_security_control(self, session: Session, control: SecurityControl, context: Dict[str, Any]) -> bool:
        """Evaluate security control for session."""
        for rule in control.validation_rules:
            if not self._validate_security_rule(session, rule, context):
                return False
        return True
    
    def _validate_security_rule(self, session: Session, rule: str, context: Dict[str, Any]) -> bool:
        """Validate individual security rule."""
        if rule == "active_clearance":
            return session.security_context.clearance_level is not None
        elif rule == "valid_cac":
            return session.security_context.cac_credentials is not None
        elif rule == "mfa_verified":
            return session.mfa_verified
        elif rule == "cac_present":
            return session.bound_cac_serial is not None
        elif rule == "continuous_auth":
            # Check if continuous authentication is current
            return True  # Simplified for example
        elif rule == "encryption_enabled":
            return session.configuration.encryption_required
        elif rule == "approved_algorithms":
            return True  # Would check actual encryption algorithms
        else:
            logger.warning(f"Unknown security rule: {rule}")
            return False
    
    def _create_default_timeout_config(self, level: ClassificationLevel, domain: NetworkDomain) -> TimeoutConfiguration:
        """Create default timeout configuration."""
        if level == ClassificationLevel.TOP_SECRET:
            return TimeoutConfiguration(
                idle_timeout=timedelta(minutes=10),
                session_timeout=timedelta(hours=2),
                warning_period=timedelta(minutes=2),
                grace_period=timedelta(seconds=30),
                escalation_timeout=timedelta(hours=1),
                inactivity_detection_interval=timedelta(seconds=15)
            )
        elif level == ClassificationLevel.SECRET:
            return TimeoutConfiguration(
                idle_timeout=timedelta(minutes=15),
                session_timeout=timedelta(hours=4),
                warning_period=timedelta(minutes=3),
                grace_period=timedelta(minutes=1),
                escalation_timeout=timedelta(hours=2),
                inactivity_detection_interval=timedelta(seconds=30)
            )
        else:
            return TimeoutConfiguration(
                idle_timeout=timedelta(minutes=30),
                session_timeout=timedelta(hours=8),
                warning_period=timedelta(minutes=5),
                grace_period=timedelta(minutes=2),
                escalation_timeout=timedelta(hours=4),
                inactivity_detection_interval=timedelta(minutes=1)
            )
    
    def get_policy_statistics(self) -> Dict[str, Any]:
        """Get policy engine statistics."""
        return {
            'total_classification_policies': len(self.classification_policies),
            'total_network_policies': len(self.network_policies),
            'total_security_controls': len(self.security_controls),
            'total_timeout_configurations': len(self.timeout_configurations),
            'supported_classification_levels': [level.value for level in ClassificationLevel],
            'supported_network_domains': [domain.value for domain in NetworkDomain]
        }


class PolicyEnforcementPoint:
    """Policy Enforcement Point for session management."""
    
    def __init__(self, policy_engine: ClassificationPolicyEngine):
        """Initialize policy enforcement point.
        
        Args:
            policy_engine: Classification policy engine
        """
        self.policy_engine = policy_engine
        self.enforcement_cache = {}
        self._cache_timeout = timedelta(minutes=5)
        
        logger.info("PolicyEnforcementPoint initialized")
    
    def enforce_session_policy(self, session: Session, operation: str, context: Dict[str, Any] = None) -> Tuple[bool, Optional[str]]:
        """Enforce session policy for operation.
        
        Args:
            session: Session to enforce policy on
            operation: Operation being performed
            context: Additional context
            
        Returns:
            Tuple of (allowed, reason if denied)
        """
        context = context or {}
        
        # Check cache
        cache_key = (session.session_id, operation, hash(frozenset(context.items())))
        if cache_key in self.enforcement_cache:
            cached_result, cached_time = self.enforcement_cache[cache_key]
            if datetime.now(timezone.utc) - cached_time < self._cache_timeout:
                return cached_result
        
        # Evaluate policy
        result = self.policy_engine.evaluate_policy(session, operation, context)
        
        # Cache result
        self.enforcement_cache[cache_key] = (result, datetime.now(timezone.utc))
        
        return result
    
    def enforce_classification_access(self, session: Session, required_classification: str) -> Tuple[bool, Optional[str]]:
        """Enforce classification access policy.
        
        Args:
            session: Session to validate
            required_classification: Required classification level
            
        Returns:
            Tuple of (allowed, reason if denied)
        """
        return self.policy_engine.validate_session_access(session, required_classification)
    
    def enforce_cross_domain_policy(self, session: Session, target_domain: NetworkDomain, target_classification: str) -> Tuple[bool, Optional[str]]:
        """Enforce cross-domain access policy.
        
        Args:
            session: Source session
            target_domain: Target network domain
            target_classification: Target classification level
            
        Returns:
            Tuple of (allowed, reason if denied)
        """
        return self.policy_engine.validate_cross_domain_access(session, target_domain, target_classification)
    
    def clear_enforcement_cache(self):
        """Clear enforcement cache."""
        self.enforcement_cache.clear()


# Factory functions
def create_classification_policy_engine() -> ClassificationPolicyEngine:
    """Create and return a classification policy engine."""
    return ClassificationPolicyEngine()


def create_policy_enforcement_point(policy_engine: ClassificationPolicyEngine = None) -> PolicyEnforcementPoint:
    """Create and return a policy enforcement point."""
    if not policy_engine:
        policy_engine = create_classification_policy_engine()
    return PolicyEnforcementPoint(policy_engine)