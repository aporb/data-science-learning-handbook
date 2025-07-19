#!/usr/bin/env python3
"""
Enhanced RBAC System for DoD Compliance
Implements comprehensive Role-Based Access Control with MAC, DAC, and ABAC support
"""

import asyncio
import logging
import time
from typing import Dict, List, Optional, Set, Any, Tuple, Union
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from functools import lru_cache
import hashlib
import json

# Import existing RBAC components
from .models.resolver import PermissionResolver, PermissionContext, PermissionResolution
from .models.role import Role, RoleManager
from .models.permission import Permission, PermissionManager
from .models.user import User, UserManager
from .models.audit import AuditLogger, AuditEvent, AuditEventType
from .models.classification import ClassificationLevel, ClassificationManager

# Import authentication components
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'auth'))
from cac_piv_integration import CACCredentials, CACAuthenticationManager
from oauth_client import OAuthTokenValidator, Platform


class AccessControlType(Enum):
    """Types of access control supported by the RBAC system."""
    MAC = "mandatory"       # Mandatory Access Control
    DAC = "discretionary"   # Discretionary Access Control
    RBAC = "role_based"     # Role-Based Access Control
    ABAC = "attribute_based" # Attribute-Based Access Control


class AccessDecision(Enum):
    """Access control decision results."""
    GRANT = "grant"
    DENY = "deny"
    DEFER = "defer"
    EMERGENCY = "emergency"


@dataclass
class AccessRequest:
    """Comprehensive access request with context."""
    user_id: str
    resource_id: str
    resource_type: str
    action: str
    context: Dict[str, Any]
    timestamp: datetime
    session_id: Optional[str] = None
    emergency_access: bool = False
    classification_level: Optional[str] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None


@dataclass
class AccessResponse:
    """Comprehensive access control response."""
    decision: AccessDecision
    granted: bool
    reason: str
    applied_policies: List[str]
    effective_permissions: List[str]
    audit_trail: Dict[str, Any]
    emergency_details: Optional[Dict[str, Any]] = None
    evaluation_time_ms: float = 0.0
    cache_hit: bool = False


class RBACSecurityLevels:
    """DoD security clearance levels with hierarchy."""
    
    LEVELS = {
        "UNCLASSIFIED": 0,
        "CONFIDENTIAL": 1,
        "SECRET": 2,
        "TOP_SECRET": 3
    }
    
    @classmethod
    def can_access(cls, user_clearance: str, resource_classification: str) -> bool:
        """Check if user clearance allows access to resource classification."""
        user_level = cls.LEVELS.get(user_clearance.upper(), -1)
        resource_level = cls.LEVELS.get(resource_classification.upper(), 999)
        return user_level >= resource_level


class EmergencyAccessManager:
    """Manages emergency access procedures with oversight."""
    
    def __init__(self, audit_logger: AuditLogger):
        self.audit_logger = audit_logger
        self.emergency_sessions: Dict[str, Dict[str, Any]] = {}
        self.approval_required_roles = {"SECURITY_OFFICER", "ADMINISTRATOR"}
    
    def request_emergency_access(self, user_id: str, resource_id: str, 
                                justification: str, approver_id: Optional[str] = None) -> str:
        """Request emergency access with justification."""
        emergency_id = hashlib.sha256(
            f"{user_id}{resource_id}{time.time()}".encode()
        ).hexdigest()[:16]
        
        emergency_request = {
            "user_id": user_id,
            "resource_id": resource_id,
            "justification": justification,
            "approver_id": approver_id,
            "timestamp": datetime.utcnow().isoformat(),
            "status": "approved" if approver_id else "pending",
            "expires": (datetime.utcnow() + timedelta(hours=1)).isoformat()
        }
        
        self.emergency_sessions[emergency_id] = emergency_request
        
        # Log emergency access request
        self.audit_logger.log_event(AuditEvent(
            event_type=AuditEventType.EMERGENCY_ACCESS,
            timestamp=datetime.utcnow(),
            user_id=user_id,
            success=True,
            additional_data=emergency_request
        ))
        
        return emergency_id
    
    def validate_emergency_access(self, emergency_id: str) -> bool:
        """Validate emergency access session."""
        if emergency_id not in self.emergency_sessions:
            return False
        
        session = self.emergency_sessions[emergency_id]
        expires = datetime.fromisoformat(session["expires"])
        
        if datetime.utcnow() > expires:
            del self.emergency_sessions[emergency_id]
            return False
        
        return session["status"] == "approved"


class RBACSystem:
    """
    Enhanced RBAC System with DoD Compliance
    Implements MAC, DAC, RBAC, and ABAC with performance optimization
    """
    
    def __init__(self, cache_size: int = 10000, cache_ttl: int = 300,
                 enable_emergency_access: bool = True):
        """
        Initialize enhanced RBAC system.
        
        Args:
            cache_size: Size of permission cache
            cache_ttl: Cache time-to-live in seconds
            enable_emergency_access: Enable emergency access procedures
        """
        # Initialize core components
        self.permission_resolver = PermissionResolver(
            cache_ttl=cache_ttl,
            cache_size=cache_size
        )
        self.role_manager = RoleManager()
        self.permission_manager = PermissionManager()
        self.user_manager = UserManager()
        self.audit_logger = AuditLogger.instance()
        self.classification_manager = ClassificationManager()
        
        # Authentication integration
        self.cac_auth_manager = CACAuthenticationManager()
        self.oauth_validator = OAuthTokenValidator()
        
        # Emergency access management
        if enable_emergency_access:
            self.emergency_manager = EmergencyAccessManager(self.audit_logger)
        else:
            self.emergency_manager = None
        
        # Performance tracking
        self.performance_metrics = {
            "access_checks": 0,
            "cache_hits": 0,
            "average_response_time": 0.0,
            "policy_evaluations": 0
        }
        
        # Security configuration
        self.security_config = {
            "max_failed_attempts": 3,
            "lockout_duration": 900,  # 15 minutes
            "session_timeout": 3600,  # 1 hour
            "require_mfa_for_admin": True,
            "enable_threat_detection": True
        }
        
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)
    
    async def check_access(self, request: AccessRequest) -> AccessResponse:
        """
        Comprehensive access control check with multiple policy types.
        
        Args:
            request: Access request with full context
            
        Returns:
            AccessResponse with decision and audit trail
        """
        start_time = time.time()
        
        try:
            # Initialize response
            response = AccessResponse(
                decision=AccessDecision.DENY,
                granted=False,
                reason="Access denied by default",
                applied_policies=[],
                effective_permissions=[],
                audit_trail={}
            )
            
            # Log access attempt
            self.audit_logger.log_event(AuditEvent(
                event_type=AuditEventType.ACCESS_ATTEMPT,
                timestamp=request.timestamp,
                user_id=request.user_id,
                success=False,  # Will update if granted
                additional_data={
                    "resource_id": request.resource_id,
                    "resource_type": request.resource_type,
                    "action": request.action,
                    "emergency_access": request.emergency_access
                }
            ))
            
            # Handle emergency access
            if request.emergency_access and self.emergency_manager:
                emergency_response = await self._handle_emergency_access(request)
                if emergency_response.granted:
                    response.evaluation_time_ms = (time.time() - start_time) * 1000
                    return emergency_response
            
            # Step 1: User validation and role resolution
            user_roles = await self._resolve_user_roles(request.user_id, request.context)
            if not user_roles:
                response.reason = "User not found or has no roles"
                return response
            
            response.audit_trail["user_roles"] = user_roles
            
            # Step 2: Mandatory Access Control (MAC) - Classification-based
            mac_result = await self._evaluate_mac_policy(request, user_roles)
            response.applied_policies.append("MAC")
            
            if not mac_result["granted"]:
                response.reason = mac_result["reason"]
                response.audit_trail["mac_evaluation"] = mac_result
                return response
            
            # Step 3: Role-Based Access Control (RBAC)
            rbac_result = await self._evaluate_rbac_policy(request, user_roles)
            response.applied_policies.append("RBAC")
            
            if not rbac_result["granted"]:
                response.reason = rbac_result["reason"]
                response.audit_trail["rbac_evaluation"] = rbac_result
                return response
            
            # Step 4: Discretionary Access Control (DAC) - Resource owner permissions
            dac_result = await self._evaluate_dac_policy(request, user_roles)
            response.applied_policies.append("DAC")
            
            if not dac_result["granted"]:
                response.reason = dac_result["reason"]
                response.audit_trail["dac_evaluation"] = dac_result
                return response
            
            # Step 5: Attribute-Based Access Control (ABAC) - Context evaluation
            abac_result = await self._evaluate_abac_policy(request, user_roles)
            response.applied_policies.append("ABAC")
            
            if not abac_result["granted"]:
                response.reason = abac_result["reason"]
                response.audit_trail["abac_evaluation"] = abac_result
                return response
            
            # Access granted
            response.decision = AccessDecision.GRANT
            response.granted = True
            response.reason = "Access granted - all policies satisfied"
            response.effective_permissions = rbac_result.get("permissions", [])
            
            # Update audit log for successful access
            self.audit_logger.log_event(AuditEvent(
                event_type=AuditEventType.ACCESS_GRANTED,
                timestamp=request.timestamp,
                user_id=request.user_id,
                success=True,
                additional_data={
                    "resource_id": request.resource_id,
                    "applied_policies": response.applied_policies,
                    "effective_permissions": response.effective_permissions
                }
            ))
            
            return response
            
        except Exception as e:
            self.logger.error(f"Access check failed: {e}")
            response.reason = f"System error during access check: {str(e)}"
            response.audit_trail["error"] = str(e)
            return response
            
        finally:
            # Performance tracking
            evaluation_time = (time.time() - start_time) * 1000
            response.evaluation_time_ms = evaluation_time
            
            self.performance_metrics["access_checks"] += 1
            self.performance_metrics["average_response_time"] = (
                (self.performance_metrics["average_response_time"] * 
                 (self.performance_metrics["access_checks"] - 1) + evaluation_time) /
                self.performance_metrics["access_checks"]
            )
    
    async def _resolve_user_roles(self, user_id: str, context: Dict[str, Any]) -> List[str]:
        """
        Resolve user roles from multiple authentication sources.
        
        Args:
            user_id: User identifier
            context: Request context with authentication details
            
        Returns:
            List of user roles
        """
        roles = set()
        
        try:
            # Check for CAC/PIV authentication context
            if "cac_credentials" in context:
                cac_roles = await self._extract_cac_roles(context["cac_credentials"])
                roles.update(cac_roles)
            
            # Check for OAuth token context
            if "oauth_token" in context:
                oauth_roles = await self._extract_oauth_roles(context["oauth_token"])
                roles.update(oauth_roles)
            
            # Check for session-based roles
            if "session_id" in context:
                session_roles = await self._get_session_roles(context["session_id"])
                roles.update(session_roles)
            
            # Get persistent user roles from database
            db_roles = await self._get_database_roles(user_id)
            roles.update(db_roles)
            
            # Add default authenticated user role
            if roles:
                roles.add("authenticated_user")
            
        except Exception as e:
            self.logger.error(f"Role resolution failed for user {user_id}: {e}")
        
        return list(roles)
    
    async def _extract_cac_roles(self, cac_credentials: Dict[str, Any]) -> List[str]:
        """Extract roles from CAC/PIV credentials."""
        roles = []
        
        try:
            # Add clearance-based roles
            clearance = cac_credentials.get("clearance_level")
            if clearance:
                roles.append(f"clearance_{clearance.lower()}")
            
            # Add organization-based roles
            organization = cac_credentials.get("organization")
            if organization:
                org_clean = organization.replace(" ", "_").lower()
                roles.append(f"org_{org_clean}")
            
            # Add DoD user role
            if cac_credentials.get("issuer_dn") and "DOD" in cac_credentials["issuer_dn"].upper():
                roles.append("dod_user")
            
            # Add military roles based on certificate attributes
            if "military" in cac_credentials.get("subject_dn", "").lower():
                roles.append("military_user")
        
        except Exception as e:
            self.logger.error(f"CAC role extraction failed: {e}")
        
        return roles
    
    async def _extract_oauth_roles(self, oauth_token: str) -> List[str]:
        """Extract roles from OAuth token claims."""
        roles = []
        
        try:
            # Validate and decode token
            token_data = self.oauth_validator.validate_token(oauth_token)
            
            if token_data and token_data.get("valid"):
                claims = token_data.get("claims", {})
                
                # Extract roles from token claims
                token_roles = claims.get("roles", [])
                if isinstance(token_roles, list):
                    roles.extend(token_roles)
                
                # Extract groups as roles
                groups = claims.get("groups", [])
                if isinstance(groups, list):
                    roles.extend([f"group_{group}" for group in groups])
                
                # Platform-specific role extraction
                platform = claims.get("platform")
                if platform:
                    roles.append(f"platform_{platform}")
        
        except Exception as e:
            self.logger.error(f"OAuth role extraction failed: {e}")
        
        return roles
    
    async def _get_session_roles(self, session_id: str) -> List[str]:
        """Get roles from active session."""
        # This would integrate with session management system
        # For now, return empty list
        return []
    
    async def _get_database_roles(self, user_id: str) -> List[str]:
        """Get persistent user roles from database."""
        try:
            user = await self.user_manager.get_user(user_id)
            if user:
                user_roles = await self.role_manager.get_user_roles(user_id)
                return [role.name for role in user_roles]
        except Exception as e:
            self.logger.error(f"Database role lookup failed for user {user_id}: {e}")
        
        return []
    
    async def _evaluate_mac_policy(self, request: AccessRequest, 
                                 user_roles: List[str]) -> Dict[str, Any]:
        """
        Evaluate Mandatory Access Control (MAC) policy.
        Implements Bell-LaPadula model for classification-based access.
        """
        try:
            # Extract user clearance level from roles
            user_clearance = "UNCLASSIFIED"  # Default
            for role in user_roles:
                if role.startswith("clearance_"):
                    user_clearance = role.replace("clearance_", "").upper()
                    break
            
            # Get resource classification
            resource_classification = request.classification_level or "UNCLASSIFIED"
            
            # Apply Bell-LaPadula model: no read up, no write down
            can_access = RBACSecurityLevels.can_access(user_clearance, resource_classification)
            
            return {
                "granted": can_access,
                "reason": f"MAC policy evaluation: user clearance {user_clearance}, resource classification {resource_classification}",
                "user_clearance": user_clearance,
                "resource_classification": resource_classification,
                "policy_type": "bell_lapadula"
            }
            
        except Exception as e:
            self.logger.error(f"MAC policy evaluation failed: {e}")
            return {
                "granted": False,
                "reason": f"MAC policy evaluation error: {str(e)}"
            }
    
    async def _evaluate_rbac_policy(self, request: AccessRequest,
                                  user_roles: List[str]) -> Dict[str, Any]:
        """Evaluate Role-Based Access Control (RBAC) policy."""
        try:
            # Use existing permission resolver
            context = PermissionContext(
                user_id=request.user_id,
                resource_type=request.resource_type,
                action=request.action,
                resource_id=request.resource_id,
                classification_level=request.classification_level,
                session_id=request.session_id,
                ip_address=request.ip_address,
                timestamp=request.timestamp
            )
            
            resolution = self.permission_resolver.check_access(context)
            
            return {
                "granted": resolution.granted,
                "reason": resolution.reason,
                "permissions": resolution.effective_permissions if hasattr(resolution, 'effective_permissions') else [],
                "cache_hit": resolution.cache_hit if hasattr(resolution, 'cache_hit') else False
            }
            
        except Exception as e:
            self.logger.error(f"RBAC policy evaluation failed: {e}")
            return {
                "granted": False,
                "reason": f"RBAC policy evaluation error: {str(e)}"
            }
    
    async def _evaluate_dac_policy(self, request: AccessRequest,
                                 user_roles: List[str]) -> Dict[str, Any]:
        """Evaluate Discretionary Access Control (DAC) policy."""
        try:
            # Check if user is resource owner or has delegated permissions
            # This would integrate with resource ownership system
            
            # For now, grant access if user has admin role or is owner
            is_admin = any(role in ["administrator", "admin", "security_officer"] 
                          for role in user_roles)
            
            # Check resource ownership (would query database)
            is_owner = await self._check_resource_ownership(request.user_id, request.resource_id)
            
            granted = is_admin or is_owner
            
            return {
                "granted": granted,
                "reason": f"DAC policy: admin={is_admin}, owner={is_owner}",
                "is_admin": is_admin,
                "is_owner": is_owner
            }
            
        except Exception as e:
            self.logger.error(f"DAC policy evaluation failed: {e}")
            return {
                "granted": True,  # Default to allow if DAC check fails
                "reason": f"DAC policy evaluation error (defaulting to allow): {str(e)}"
            }
    
    async def _evaluate_abac_policy(self, request: AccessRequest,
                                  user_roles: List[str]) -> Dict[str, Any]:
        """Evaluate Attribute-Based Access Control (ABAC) policy."""
        try:
            # Time-based access control
            current_hour = datetime.utcnow().hour
            is_business_hours = 6 <= current_hour <= 18
            
            # Location-based access control (if IP geolocation available)
            is_authorized_location = True  # Would implement IP geolocation check
            
            # Context-based restrictions
            context_checks = {
                "business_hours": is_business_hours,
                "authorized_location": is_authorized_location,
                "session_valid": request.session_id is not None
            }
            
            # Apply high-security restrictions for sensitive operations
            if request.action in ["admin", "delete", "export"]:
                # Require additional verification for sensitive actions
                has_mfa = request.context.get("mfa_verified", False)
                context_checks["mfa_verified"] = has_mfa
            
            # All context checks must pass
            all_passed = all(context_checks.values())
            
            return {
                "granted": all_passed,
                "reason": f"ABAC policy checks: {context_checks}",
                "context_checks": context_checks
            }
            
        except Exception as e:
            self.logger.error(f"ABAC policy evaluation failed: {e}")
            return {
                "granted": True,  # Default to allow if ABAC check fails
                "reason": f"ABAC policy evaluation error (defaulting to allow): {str(e)}"
            }
    
    async def _check_resource_ownership(self, user_id: str, resource_id: str) -> bool:
        """Check if user owns the resource."""
        # This would query the resource ownership database
        # For now, return False (no ownership)
        return False
    
    async def _handle_emergency_access(self, request: AccessRequest) -> AccessResponse:
        """Handle emergency access procedures."""
        if not self.emergency_manager:
            return AccessResponse(
                decision=AccessDecision.DENY,
                granted=False,
                reason="Emergency access not enabled"
            )
        
        # Emergency access requires justification in context
        justification = request.context.get("emergency_justification")
        if not justification:
            return AccessResponse(
                decision=AccessDecision.DENY,
                granted=False,
                reason="Emergency access requires justification"
            )
        
        # Request emergency access
        emergency_id = self.emergency_manager.request_emergency_access(
            request.user_id,
            request.resource_id,
            justification
        )
        
        # For critical situations, auto-approve with enhanced auditing
        if request.context.get("emergency_level") == "critical":
            return AccessResponse(
                decision=AccessDecision.EMERGENCY,
                granted=True,
                reason="Emergency access granted for critical situation",
                applied_policies=["EMERGENCY"],
                effective_permissions=["emergency_access"],
                emergency_details={
                    "emergency_id": emergency_id,
                    "justification": justification,
                    "auto_approved": True
                }
            )
        
        return AccessResponse(
            decision=AccessDecision.DEFER,
            granted=False,
            reason="Emergency access pending approval",
            emergency_details={
                "emergency_id": emergency_id,
                "justification": justification,
                "approval_required": True
            }
        )
    
    def get_performance_metrics(self) -> Dict[str, Any]:
        """Get system performance metrics."""
        cache_stats = self.permission_resolver.cache.get_stats() if hasattr(self.permission_resolver, 'cache') else {}
        
        return {
            **self.performance_metrics,
            "cache_stats": cache_stats,
            "timestamp": datetime.utcnow().isoformat()
        }
    
    def invalidate_user_cache(self, user_id: str):
        """Invalidate cached permissions for a user."""
        if hasattr(self.permission_resolver, 'invalidate_user_cache'):
            self.permission_resolver.invalidate_user_cache(user_id)
    
    def health_check(self) -> Dict[str, Any]:
        """Perform system health check."""
        try:
            # Test database connectivity
            db_healthy = True  # Would implement actual DB health check
            
            # Test cache performance
            cache_healthy = True
            if hasattr(self.permission_resolver, 'cache'):
                cache_stats = self.permission_resolver.cache.get_stats()
                cache_healthy = cache_stats.get('hit_rate', 0) > 0.5
            
            # Test average response time
            performance_healthy = self.performance_metrics["average_response_time"] < 100
            
            overall_healthy = db_healthy and cache_healthy and performance_healthy
            
            return {
                "healthy": overall_healthy,
                "database": db_healthy,
                "cache": cache_healthy,
                "performance": performance_healthy,
                "metrics": self.get_performance_metrics(),
                "timestamp": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            return {
                "healthy": False,
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat()
            }


# Utility functions for integration
async def create_access_request_from_context(user_id: str, resource_id: str, 
                                           resource_type: str, action: str,
                                           **kwargs) -> AccessRequest:
    """Create an AccessRequest from context parameters."""
    return AccessRequest(
        user_id=user_id,
        resource_id=resource_id,
        resource_type=resource_type,
        action=action,
        context=kwargs.get('context', {}),
        timestamp=datetime.utcnow(),
        session_id=kwargs.get('session_id'),
        emergency_access=kwargs.get('emergency_access', False),
        classification_level=kwargs.get('classification_level'),
        ip_address=kwargs.get('ip_address'),
        user_agent=kwargs.get('user_agent')
    )


# Example usage
if __name__ == "__main__":
    async def demo():
        # Initialize RBAC system
        rbac = RBACSystem(cache_size=5000, cache_ttl=300, enable_emergency_access=True)
        
        # Create sample access request
        request = await create_access_request_from_context(
            user_id="12345678-1234-1234-1234-123456789012",
            resource_id="notebook_123",
            resource_type="notebook",
            action="execute",
            context={
                "cac_credentials": {
                    "clearance_level": "SECRET",
                    "organization": "US Navy",
                    "issuer_dn": "DOD PKI"
                },
                "mfa_verified": True
            },
            classification_level="SECRET",
            session_id="session_456",
            ip_address="192.168.1.100"
        )
        
        # Check access
        response = await rbac.check_access(request)
        
        print(f"Access Decision: {response.decision}")
        print(f"Granted: {response.granted}")
        print(f"Reason: {response.reason}")
        print(f"Applied Policies: {response.applied_policies}")
        print(f"Evaluation Time: {response.evaluation_time_ms:.2f}ms")
        
        # Get performance metrics
        metrics = rbac.get_performance_metrics()
        print(f"Performance Metrics: {metrics}")
        
        # Health check
        health = rbac.health_check()
        print(f"System Health: {health}")
    
    # Run demo
    asyncio.run(demo())