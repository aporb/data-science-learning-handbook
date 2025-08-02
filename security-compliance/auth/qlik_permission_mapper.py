"""
Advanced Permission Mapping for Qlik Resources
Maps OAuth scopes to specific Qlik resources and permissions with dynamic clearance-based updates.
"""

import json
import logging
import re
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
import threading

# Import Qlik components
from .enhanced_qlik_oauth import QlikResourceType, QlikPermissionLevel, QlikScope
from .cac_piv_integration import CACCredentials
from .security_managers import AuditLogger, AuditEvent, AuditEventType

logger = logging.getLogger(__name__)


class ResourceAccessLevel(Enum):
    """Resource access levels based on classification."""
    UNCLASSIFIED = "unclassified"
    CONFIDENTIAL = "confidential"
    SECRET = "secret"
    TOP_SECRET = "top_secret"


class PermissionContext(Enum):
    """Permission context for different operational scenarios."""
    NORMAL_OPERATIONS = "normal"
    EMERGENCY_ACCESS = "emergency"
    AUDIT_REVIEW = "audit"
    ADMINISTRATIVE = "administrative"
    DEVELOPMENT = "development"


@dataclass
class QlikResourcePermission:
    """Detailed Qlik resource permission mapping."""
    resource_id: str
    resource_type: QlikResourceType
    resource_name: str
    required_clearance: ResourceAccessLevel
    allowed_permissions: Set[QlikPermissionLevel]
    context_restrictions: Dict[PermissionContext, Set[QlikPermissionLevel]]
    owner_edipi: Optional[str] = None
    classification_tags: List[str] = field(default_factory=list)
    data_sources: List[str] = field(default_factory=list)
    access_conditions: Dict[str, Any] = field(default_factory=dict)
    
    def can_access(self, user_clearance: ResourceAccessLevel,
                  permission_level: QlikPermissionLevel,
                  context: PermissionContext = PermissionContext.NORMAL_OPERATIONS) -> bool:
        """Check if user can access resource with specific permission."""
        # Check clearance level
        clearance_levels = {
            ResourceAccessLevel.UNCLASSIFIED: 0,
            ResourceAccessLevel.CONFIDENTIAL: 1,
            ResourceAccessLevel.SECRET: 2,
            ResourceAccessLevel.TOP_SECRET: 3
        }
        
        if clearance_levels.get(user_clearance, 0) < clearance_levels.get(self.required_clearance, 0):
            return False
        
        # Check permission level for context
        context_permissions = self.context_restrictions.get(context, self.allowed_permissions)
        return permission_level in context_permissions


@dataclass
class UserPermissionProfile:
    """User permission profile with dynamic capabilities."""
    edipi: str
    clearance_level: ResourceAccessLevel
    roles: Set[str]
    groups: Set[str]
    organization: str
    active_permissions: Dict[str, Set[QlikPermissionLevel]]
    permission_grants: Dict[str, datetime]
    permission_revocations: Dict[str, datetime]
    emergency_access_history: List[Dict[str, Any]] = field(default_factory=list)
    last_updated: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    def has_role(self, role: str) -> bool:
        """Check if user has specific role."""
        return role in self.roles
    
    def has_group(self, group: str) -> bool:
        """Check if user has specific group membership."""
        return group in self.groups
    
    def can_access_resource(self, resource: QlikResourcePermission,
                          permission: QlikPermissionLevel,
                          context: PermissionContext = PermissionContext.NORMAL_OPERATIONS) -> bool:
        """Check if user can access resource with permission."""
        return resource.can_access(self.clearance_level, permission, context)


class AdvancedQlikPermissionMapper:
    """Advanced permission mapper for Qlik resources with dynamic updates."""
    
    def __init__(self):
        """Initialize advanced permission mapper."""
        self.resource_registry: Dict[str, QlikResourcePermission] = {}
        self.user_profiles: Dict[str, UserPermissionProfile] = {}
        self.permission_templates: Dict[str, Dict[str, Any]] = {}
        self.classification_rules: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.RLock()
        
        # Initialize default permission templates
        self._initialize_default_templates()
        self._initialize_classification_rules()
        
        logger.info("Advanced Qlik permission mapper initialized")
    
    def _initialize_default_templates(self):
        """Initialize default permission templates."""
        self.permission_templates = {
            "standard_user": {
                "description": "Standard user permissions",
                "default_permissions": [QlikPermissionLevel.READ],
                "resource_restrictions": {
                    QlikResourceType.APP: [QlikPermissionLevel.READ],
                    QlikResourceType.SHEET: [QlikPermissionLevel.READ],
                    QlikResourceType.STORY: [QlikPermissionLevel.READ]
                },
                "clearance_requirements": {
                    QlikResourceType.APP: ResourceAccessLevel.UNCLASSIFIED,
                    QlikResourceType.SHEET: ResourceAccessLevel.UNCLASSIFIED,
                    QlikResourceType.STORY: ResourceAccessLevel.UNCLASSIFIED
                }
            },
            "analyst": {
                "description": "Analyst permissions",
                "default_permissions": [QlikPermissionLevel.READ, QlikPermissionLevel.UPDATE],
                "resource_restrictions": {
                    QlikResourceType.APP: [QlikPermissionLevel.READ, QlikPermissionLevel.UPDATE],
                    QlikResourceType.SHEET: [QlikPermissionLevel.READ, QlikPermissionLevel.UPDATE, QlikPermissionLevel.CREATE],
                    QlikResourceType.STORY: [QlikPermissionLevel.READ, QlikPermissionLevel.UPDATE, QlikPermissionLevel.CREATE]
                },
                "clearance_requirements": {
                    QlikResourceType.APP: ResourceAccessLevel.CONFIDENTIAL,
                    QlikResourceType.SHEET: ResourceAccessLevel.CONFIDENTIAL,
                    QlikResourceType.STORY: ResourceAccessLevel.CONFIDENTIAL
                }
            },
            "developer": {
                "description": "Developer permissions",
                "default_permissions": [QlikPermissionLevel.READ, QlikPermissionLevel.UPDATE, QlikPermissionLevel.CREATE],
                "resource_restrictions": {
                    QlikResourceType.APP: [QlikPermissionLevel.READ, QlikPermissionLevel.UPDATE, QlikPermissionLevel.CREATE, QlikPermissionLevel.DELETE],
                    QlikResourceType.DATA_CONNECTION: [QlikPermissionLevel.READ, QlikPermissionLevel.CREATE, QlikPermissionLevel.UPDATE],
                    QlikResourceType.EXTENSION: [QlikPermissionLevel.READ, QlikPermissionLevel.CREATE, QlikPermissionLevel.UPDATE]
                },
                "clearance_requirements": {
                    QlikResourceType.APP: ResourceAccessLevel.SECRET,
                    QlikResourceType.DATA_CONNECTION: ResourceAccessLevel.SECRET,
                    QlikResourceType.EXTENSION: ResourceAccessLevel.CONFIDENTIAL
                }
            },
            "admin": {
                "description": "Administrative permissions",
                "default_permissions": list(QlikPermissionLevel),
                "resource_restrictions": {
                    resource_type: list(QlikPermissionLevel) for resource_type in QlikResourceType
                },
                "clearance_requirements": {
                    resource_type: ResourceAccessLevel.TOP_SECRET for resource_type in QlikResourceType
                }
            }
        }
    
    def _initialize_classification_rules(self):
        """Initialize classification rules for automatic permission mapping."""
        self.classification_rules = {
            "data_classification": {
                "unclassified": {
                    "keywords": ["public", "unclassified", "open"],
                    "access_level": ResourceAccessLevel.UNCLASSIFIED,
                    "default_permissions": [QlikPermissionLevel.READ]
                },
                "confidential": {
                    "keywords": ["confidential", "internal", "restricted"],
                    "access_level": ResourceAccessLevel.CONFIDENTIAL,
                    "default_permissions": [QlikPermissionLevel.READ]
                },
                "secret": {
                    "keywords": ["secret", "classified", "sensitive"],
                    "access_level": ResourceAccessLevel.SECRET,
                    "default_permissions": [QlikPermissionLevel.READ]
                },
                "top_secret": {
                    "keywords": ["top secret", "ts", "compartmented"],
                    "access_level": ResourceAccessLevel.TOP_SECRET,
                    "default_permissions": [QlikPermissionLevel.READ]
                }
            },
            "organization_mapping": {
                "navy": {
                    "domains": ["navy.mil", "spawar.navy.mil"],
                    "default_roles": ["navy_user", "naval_intelligence"],
                    "clearance_boost": False
                },
                "army": {
                    "domains": ["army.mil", "usarc.army.mil"],
                    "default_roles": ["army_user", "army_intelligence"],
                    "clearance_boost": False
                },
                "air_force": {
                    "domains": ["af.mil", "us.af.mil"],
                    "default_roles": ["af_user", "af_intelligence"],
                    "clearance_boost": False
                },
                "dod_contractor": {
                    "domains": ["contractor.dod.mil"],
                    "default_roles": ["contractor_user"],
                    "clearance_boost": False
                }
            }
        }
    
    def register_resource(self, resource_id: str, resource_type: QlikResourceType,
                         resource_name: str, metadata: Dict[str, Any]) -> QlikResourcePermission:
        """
        Register Qlik resource with automatic permission mapping.
        
        Args:
            resource_id: Unique resource identifier
            resource_type: Type of Qlik resource
            resource_name: Human-readable resource name
            metadata: Resource metadata for classification
            
        Returns:
            Created resource permission object
        """
        with self._lock:
            try:
                # Determine classification level from metadata
                classification = self._classify_resource(resource_name, metadata)
                
                # Create resource permission
                resource_permission = QlikResourcePermission(
                    resource_id=resource_id,
                    resource_type=resource_type,
                    resource_name=resource_name,
                    required_clearance=classification["access_level"],
                    allowed_permissions=set(classification["default_permissions"]),
                    context_restrictions=self._build_context_restrictions(resource_type, classification),
                    owner_edipi=metadata.get("owner_edipi"),
                    classification_tags=metadata.get("classification_tags", []),
                    data_sources=metadata.get("data_sources", []),
                    access_conditions=metadata.get("access_conditions", {})
                )
                
                # Store resource
                self.resource_registry[resource_id] = resource_permission
                
                # Log resource registration
                AuditLogger.instance().log_event(AuditEvent(
                    event_type=AuditEventType.RESOURCE_REGISTERED,
                    timestamp=datetime.now(timezone.utc),
                    user_id="system",
                    success=True,
                    additional_data={
                        "resource_id": resource_id,
                        "resource_type": resource_type.value,
                        "resource_name": resource_name,
                        "classification": classification["access_level"].value,
                        "permissions": [p.value for p in resource_permission.allowed_permissions]
                    }
                ))
                
                logger.info(f"Resource registered: {resource_id} ({resource_type.value}) - {classification['access_level'].value}")
                return resource_permission
                
            except Exception as e:
                logger.error(f"Resource registration failed: {e}")
                raise
    
    def create_user_profile(self, cac_credentials: CACCredentials,
                          oauth_scopes: List[str]) -> UserPermissionProfile:
        """
        Create user permission profile from CAC credentials and OAuth scopes.
        
        Args:
            cac_credentials: CAC credentials
            oauth_scopes: OAuth scopes granted to user
            
        Returns:
            User permission profile
        """
        with self._lock:
            try:
                # Map clearance level
                clearance_mapping = {
                    "UNCLASSIFIED": ResourceAccessLevel.UNCLASSIFIED,
                    "CONFIDENTIAL": ResourceAccessLevel.CONFIDENTIAL,
                    "SECRET": ResourceAccessLevel.SECRET,
                    "TOP SECRET": ResourceAccessLevel.TOP_SECRET
                }
                
                clearance_level = clearance_mapping.get(
                    cac_credentials.clearance_level.upper() if cac_credentials.clearance_level else "UNCLASSIFIED",
                    ResourceAccessLevel.UNCLASSIFIED
                )
                
                # Determine roles from organization and scopes
                roles = self._determine_user_roles(cac_credentials, oauth_scopes)
                groups = self._determine_user_groups(cac_credentials)
                
                # Build active permissions from scopes
                active_permissions = self._map_scopes_to_permissions(oauth_scopes, clearance_level, roles)
                
                # Create profile
                profile = UserPermissionProfile(
                    edipi=cac_credentials.edipi,
                    clearance_level=clearance_level,
                    roles=roles,
                    groups=groups,
                    organization=cac_credentials.organization or "Unknown",
                    active_permissions=active_permissions,
                    permission_grants={scope: datetime.now(timezone.utc) for scope in oauth_scopes},
                    permission_revocations={}
                )
                
                # Store profile
                self.user_profiles[cac_credentials.edipi] = profile
                
                logger.info(f"User profile created: {cac_credentials.edipi} ({clearance_level.value})")
                return profile
                
            except Exception as e:
                logger.error(f"User profile creation failed: {e}")
                raise
    
    def check_resource_access(self, edipi: str, resource_id: str,
                            permission: QlikPermissionLevel,
                            context: PermissionContext = PermissionContext.NORMAL_OPERATIONS) -> Tuple[bool, Dict[str, Any]]:
        """
        Check if user can access resource with specific permission.
        
        Args:
            edipi: User EDIPI
            resource_id: Resource identifier
            permission: Requested permission level
            context: Permission context
            
        Returns:
            Tuple of (access_granted, access_details)
        """
        with self._lock:
            try:
                # Get user profile
                user_profile = self.user_profiles.get(edipi)
                if not user_profile:
                    return False, {"error": "user_profile_not_found"}
                
                # Get resource
                resource = self.resource_registry.get(resource_id)
                if not resource:
                    return False, {"error": "resource_not_found"}
                
                # Check basic access
                can_access = user_profile.can_access_resource(resource, permission, context)
                
                # Build access details
                access_details = {
                    "user_clearance": user_profile.clearance_level.value,
                    "required_clearance": resource.required_clearance.value,
                    "requested_permission": permission.value,
                    "context": context.value,
                    "resource_type": resource.resource_type.value,
                    "access_granted": can_access,
                    "check_timestamp": datetime.now(timezone.utc).isoformat()
                }
                
                # Add additional checks
                if can_access:
                    # Check for time-based restrictions
                    if resource.access_conditions.get("time_restricted"):
                        time_access = self._check_time_restrictions(resource.access_conditions, context)
                        can_access = can_access and time_access
                        access_details["time_restricted"] = not time_access
                    
                    # Check for owner-only restrictions
                    if resource.access_conditions.get("owner_only") and resource.owner_edipi != edipi:
                        can_access = False
                        access_details["owner_only_restriction"] = True
                
                access_details["access_granted"] = can_access
                
                # Log access check
                AuditLogger.instance().log_event(AuditEvent(
                    event_type=AuditEventType.PERMISSION_CHECK,
                    timestamp=datetime.now(timezone.utc),
                    user_id=edipi,
                    success=can_access,
                    additional_data={
                        "resource_id": resource_id,
                        "permission": permission.value,
                        "context": context.value,
                        "access_granted": can_access
                    }
                ))
                
                return can_access, access_details
                
            except Exception as e:
                logger.error(f"Resource access check failed: {e}")
                return False, {"error": f"check_failed: {str(e)}"}
    
    def update_user_clearance(self, edipi: str, new_clearance: str,
                            update_reason: str = "clearance_update") -> bool:
        """
        Update user clearance level and recompute permissions.
        
        Args:
            edipi: User EDIPI
            new_clearance: New clearance level
            update_reason: Reason for update
            
        Returns:
            True if update successful
        """
        with self._lock:
            try:
                user_profile = self.user_profiles.get(edipi)
                if not user_profile:
                    return False
                
                # Map new clearance
                clearance_mapping = {
                    "UNCLASSIFIED": ResourceAccessLevel.UNCLASSIFIED,
                    "CONFIDENTIAL": ResourceAccessLevel.CONFIDENTIAL,
                    "SECRET": ResourceAccessLevel.SECRET,
                    "TOP SECRET": ResourceAccessLevel.TOP_SECRET
                }
                
                new_clearance_level = clearance_mapping.get(new_clearance.upper())
                if not new_clearance_level:
                    return False
                
                old_clearance = user_profile.clearance_level
                user_profile.clearance_level = new_clearance_level
                user_profile.last_updated = datetime.now(timezone.utc)
                
                # Log clearance update
                AuditLogger.instance().log_event(AuditEvent(
                    event_type=AuditEventType.CLEARANCE_UPDATE,
                    timestamp=datetime.now(timezone.utc),
                    user_id=edipi,
                    success=True,
                    additional_data={
                        "old_clearance": old_clearance.value,
                        "new_clearance": new_clearance_level.value,
                        "reason": update_reason
                    }
                ))
                
                logger.info(f"Clearance updated for {edipi}: {old_clearance.value} -> {new_clearance_level.value}")
                return True
                
            except Exception as e:
                logger.error(f"Clearance update failed: {e}")
                return False
    
    def get_user_accessible_resources(self, edipi: str,
                                    resource_type: Optional[QlikResourceType] = None,
                                    permission: QlikPermissionLevel = QlikPermissionLevel.READ) -> List[Dict[str, Any]]:
        """
        Get list of resources accessible to user.
        
        Args:
            edipi: User EDIPI
            resource_type: Optional filter by resource type
            permission: Required permission level
            
        Returns:
            List of accessible resources
        """
        with self._lock:
            try:
                user_profile = self.user_profiles.get(edipi)
                if not user_profile:
                    return []
                
                accessible_resources = []
                
                for resource_id, resource in self.resource_registry.items():
                    # Filter by resource type if specified
                    if resource_type and resource.resource_type != resource_type:
                        continue
                    
                    # Check access
                    can_access, _ = self.check_resource_access(edipi, resource_id, permission)
                    
                    if can_access:
                        accessible_resources.append({
                            "resource_id": resource_id,
                            "resource_name": resource.resource_name,
                            "resource_type": resource.resource_type.value,
                            "required_clearance": resource.required_clearance.value,
                            "allowed_permissions": [p.value for p in resource.allowed_permissions],
                            "classification_tags": resource.classification_tags,
                            "owner_edipi": resource.owner_edipi
                        })
                
                return accessible_resources
                
            except Exception as e:
                logger.error(f"Failed to get accessible resources: {e}")
                return []
    
    def _classify_resource(self, resource_name: str, metadata: Dict[str, Any]) -> Dict[str, Any]:
        """Classify resource based on name and metadata."""
        # Default classification
        classification = {
            "access_level": ResourceAccessLevel.UNCLASSIFIED,
            "default_permissions": [QlikPermissionLevel.READ]
        }
        
        # Check classification keywords
        resource_text = f"{resource_name} {' '.join(metadata.get('description', []))}"
        resource_text_lower = resource_text.lower()
        
        for level_name, level_config in self.classification_rules["data_classification"].items():
            for keyword in level_config["keywords"]:
                if keyword in resource_text_lower:
                    classification["access_level"] = level_config["access_level"]
                    classification["default_permissions"] = level_config["default_permissions"]
                    break
        
        # Override with explicit classification
        if "classification" in metadata:
            level_mapping = {
                "unclassified": ResourceAccessLevel.UNCLASSIFIED,
                "confidential": ResourceAccessLevel.CONFIDENTIAL,
                "secret": ResourceAccessLevel.SECRET,
                "top_secret": ResourceAccessLevel.TOP_SECRET
            }
            explicit_level = level_mapping.get(metadata["classification"].lower())
            if explicit_level:
                classification["access_level"] = explicit_level
        
        return classification
    
    def _build_context_restrictions(self, resource_type: QlikResourceType,
                                  classification: Dict[str, Any]) -> Dict[PermissionContext, Set[QlikPermissionLevel]]:
        """Build context-specific permission restrictions."""
        restrictions = {}
        base_permissions = set(classification["default_permissions"])
        
        # Normal operations - base permissions
        restrictions[PermissionContext.NORMAL_OPERATIONS] = base_permissions.copy()
        
        # Emergency access - elevated permissions for critical situations
        emergency_permissions = base_permissions.copy()
        if resource_type in [QlikResourceType.APP, QlikResourceType.DATA_CONNECTION]:
            emergency_permissions.add(QlikPermissionLevel.UPDATE)
        restrictions[PermissionContext.EMERGENCY_ACCESS] = emergency_permissions
        
        # Audit review - read-only access
        restrictions[PermissionContext.AUDIT_REVIEW] = {QlikPermissionLevel.READ}
        
        # Administrative - full permissions for admins
        if classification["access_level"] in [ResourceAccessLevel.UNCLASSIFIED, ResourceAccessLevel.CONFIDENTIAL]:
            restrictions[PermissionContext.ADMINISTRATIVE] = set(QlikPermissionLevel)
        else:
            restrictions[PermissionContext.ADMINISTRATIVE] = base_permissions.copy()
        
        # Development - elevated permissions for development resources
        dev_permissions = base_permissions.copy()
        if resource_type in [QlikResourceType.APP, QlikResourceType.EXTENSION]:
            dev_permissions.update([QlikPermissionLevel.CREATE, QlikPermissionLevel.UPDATE, QlikPermissionLevel.DELETE])
        restrictions[PermissionContext.DEVELOPMENT] = dev_permissions
        
        return restrictions
    
    def _determine_user_roles(self, cac_credentials: CACCredentials, oauth_scopes: List[str]) -> Set[str]:
        """Determine user roles from CAC credentials and OAuth scopes."""
        roles = set()
        
        # Add base user role
        roles.add("qlik_user")
        
        # Add organization-based roles
        if cac_credentials.organization:
            org_lower = cac_credentials.organization.lower()
            for org_name, org_config in self.classification_rules["organization_mapping"].items():
                if any(domain in org_lower for domain in org_config.get("domains", [])):
                    roles.update(org_config["default_roles"])
        
        # Add scope-based roles
        for scope in oauth_scopes:
            if "admin" in scope:
                roles.add("qlik_admin")
            elif "create" in scope or "write" in scope:
                roles.add("qlik_developer")
            elif "publish" in scope:
                roles.add("qlik_publisher")
        
        return roles
    
    def _determine_user_groups(self, cac_credentials: CACCredentials) -> Set[str]:
        """Determine user groups from CAC credentials."""
        groups = set()
        
        # Add clearance-based groups
        if cac_credentials.clearance_level:
            groups.add(f"clearance_{cac_credentials.clearance_level.lower()}")
        
        # Add organization group
        if cac_credentials.organization:
            org_clean = cac_credentials.organization.replace(" ", "_").lower()
            groups.add(f"org_{org_clean}")
        
        return groups
    
    def _map_scopes_to_permissions(self, oauth_scopes: List[str],
                                  clearance_level: ResourceAccessLevel,
                                  roles: Set[str]) -> Dict[str, Set[QlikPermissionLevel]]:
        """Map OAuth scopes to Qlik permissions."""
        permissions = {}
        
        for scope in oauth_scopes:
            if scope.startswith("qlik:"):
                scope_name = scope[5:]  # Remove "qlik:" prefix
                
                # Map scope to permissions based on name
                if "read" in scope_name:
                    permissions[scope] = {QlikPermissionLevel.READ}
                elif "write" in scope_name or "update" in scope_name:
                    permissions[scope] = {QlikPermissionLevel.READ, QlikPermissionLevel.UPDATE}
                elif "create" in scope_name:
                    permissions[scope] = {QlikPermissionLevel.READ, QlikPermissionLevel.UPDATE, QlikPermissionLevel.CREATE}
                elif "admin" in scope_name:
                    permissions[scope] = set(QlikPermissionLevel)
                elif "publish" in scope_name:
                    permissions[scope] = {QlikPermissionLevel.READ, QlikPermissionLevel.PUBLISH}
                else:
                    permissions[scope] = {QlikPermissionLevel.READ}
        
        return permissions
    
    def _check_time_restrictions(self, access_conditions: Dict[str, Any],
                               context: PermissionContext) -> bool:
        """Check time-based access restrictions."""
        # In production, this would check business hours, maintenance windows, etc.
        # For now, always allow access
        return True