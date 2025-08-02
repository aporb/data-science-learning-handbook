"""
Advanced Permission Mapping for Databricks Resources
Maps OAuth scopes to specific Databricks resources and permissions with dynamic clearance-based updates.
Adapted from proven Qlik OAuth patterns for maximum code reuse.
"""

import json
import logging
import re
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
import threading

# Import Databricks components
from .enhanced_databricks_oauth import DatabricksResourceType, DatabricksPermissionLevel, DatabricksScope
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
    PRODUCTION = "production"
    RESEARCH = "research"


@dataclass
class DatabricksResourcePermission:
    """Detailed Databricks resource permission mapping."""
    resource_id: str
    resource_type: DatabricksResourceType
    resource_name: str
    required_clearance: ResourceAccessLevel
    allowed_permissions: Set[DatabricksPermissionLevel]
    context_restrictions: Dict[PermissionContext, Set[DatabricksPermissionLevel]]
    owner_edipi: Optional[str] = None
    classification_tags: List[str] = field(default_factory=list)
    data_sources: List[str] = field(default_factory=list)
    workspace_id: Optional[str] = None
    cluster_policy_id: Optional[str] = None
    access_conditions: Dict[str, Any] = field(default_factory=dict)
    
    def can_access(self, user_clearance: ResourceAccessLevel,
                  permission_level: DatabricksPermissionLevel,
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
    active_permissions: Dict[str, Set[DatabricksPermissionLevel]]
    permission_grants: Dict[str, datetime]
    permission_revocations: Dict[str, datetime]
    workspace_permissions: Dict[str, Set[str]] = field(default_factory=dict)
    cluster_policies: List[str] = field(default_factory=list)
    emergency_access_history: List[Dict[str, Any]] = field(default_factory=list)
    last_updated: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    def has_role(self, role: str) -> bool:
        """Check if user has specific role."""
        return role in self.roles
    
    def has_group(self, group: str) -> bool:
        """Check if user has specific group membership."""
        return group in self.groups
    
    def can_access_resource(self, resource: DatabricksResourcePermission,
                          permission: DatabricksPermissionLevel,
                          context: PermissionContext = PermissionContext.NORMAL_OPERATIONS) -> bool:
        """Check if user can access resource with permission."""
        return resource.can_access(self.clearance_level, permission, context)
    
    def has_workspace_permission(self, workspace_id: str, permission: str) -> bool:
        """Check if user has specific workspace permission."""
        workspace_perms = self.workspace_permissions.get(workspace_id, set())
        return permission in workspace_perms


class AdvancedDatabricksPermissionMapper:
    """Advanced permission mapper for Databricks resources with dynamic updates."""
    
    def __init__(self):
        """Initialize advanced permission mapper."""
        self.resource_registry: Dict[str, DatabricksResourcePermission] = {}
        self.user_profiles: Dict[str, UserPermissionProfile] = {}
        self.permission_templates: Dict[str, Dict[str, Any]] = {}
        self.classification_rules: Dict[str, Dict[str, Any]] = {}
        self.workspace_policies: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.RLock()
        
        # Initialize default permission templates
        self._initialize_default_templates()
        self._initialize_classification_rules()
        self._initialize_workspace_policies()
        
        logger.info("Advanced Databricks permission mapper initialized")
    
    def _initialize_default_templates(self):
        """Initialize default permission templates."""
        self.permission_templates = {
            "standard_user": {
                "description": "Standard Databricks user permissions",
                "default_permissions": [DatabricksPermissionLevel.READ, DatabricksPermissionLevel.CAN_USE],
                "resource_restrictions": {
                    DatabricksResourceType.WORKSPACE: [DatabricksPermissionLevel.READ],
                    DatabricksResourceType.NOTEBOOK: [DatabricksPermissionLevel.READ, DatabricksPermissionLevel.WRITE],
                    DatabricksResourceType.CLUSTER: [DatabricksPermissionLevel.CAN_ATTACH_TO]
                },
                "clearance_requirements": {
                    DatabricksResourceType.WORKSPACE: ResourceAccessLevel.UNCLASSIFIED,
                    DatabricksResourceType.NOTEBOOK: ResourceAccessLevel.UNCLASSIFIED,
                    DatabricksResourceType.CLUSTER: ResourceAccessLevel.CONFIDENTIAL
                }
            },
            "data_analyst": {
                "description": "Data analyst permissions",
                "default_permissions": [DatabricksPermissionLevel.READ, DatabricksPermissionLevel.WRITE, DatabricksPermissionLevel.EXECUTE],
                "resource_restrictions": {
                    DatabricksResourceType.NOTEBOOK: [DatabricksPermissionLevel.READ, DatabricksPermissionLevel.WRITE, DatabricksPermissionLevel.EXECUTE],
                    DatabricksResourceType.SQL_WAREHOUSE: [DatabricksPermissionLevel.CAN_USE, DatabricksPermissionLevel.CAN_MANAGE],
                    DatabricksResourceType.DELTA_TABLE: [DatabricksPermissionLevel.READ, DatabricksPermissionLevel.WRITE],
                    DatabricksResourceType.CLUSTER: [DatabricksPermissionLevel.CAN_ATTACH_TO, DatabricksPermissionLevel.CAN_RESTART]
                },
                "clearance_requirements": {
                    DatabricksResourceType.NOTEBOOK: ResourceAccessLevel.CONFIDENTIAL,
                    DatabricksResourceType.SQL_WAREHOUSE: ResourceAccessLevel.CONFIDENTIAL,
                    DatabricksResourceType.DELTA_TABLE: ResourceAccessLevel.CONFIDENTIAL,
                    DatabricksResourceType.CLUSTER: ResourceAccessLevel.CONFIDENTIAL
                }
            },
            "data_scientist": {
                "description": "Data scientist permissions",
                "default_permissions": [DatabricksPermissionLevel.READ, DatabricksPermissionLevel.WRITE, DatabricksPermissionLevel.EXECUTE, DatabricksPermissionLevel.MANAGE],
                "resource_restrictions": {
                    DatabricksResourceType.NOTEBOOK: [DatabricksPermissionLevel.READ, DatabricksPermissionLevel.WRITE, DatabricksPermissionLevel.EXECUTE],
                    DatabricksResourceType.MLflow_EXPERIMENT: [DatabricksPermissionLevel.READ, DatabricksPermissionLevel.WRITE, DatabricksPermissionLevel.MANAGE],
                    DatabricksResourceType.MLflow_MODEL: [DatabricksPermissionLevel.READ, DatabricksPermissionLevel.WRITE, DatabricksPermissionLevel.MANAGE],
                    DatabricksResourceType.CLUSTER: [DatabricksPermissionLevel.CAN_ATTACH_TO, DatabricksPermissionLevel.CAN_RESTART, DatabricksPermissionLevel.CAN_MANAGE],
                    DatabricksResourceType.JOB: [DatabricksPermissionLevel.READ, DatabricksPermissionLevel.WRITE, DatabricksPermissionLevel.EXECUTE]
                },
                "clearance_requirements": {
                    DatabricksResourceType.NOTEBOOK: ResourceAccessLevel.SECRET,
                    DatabricksResourceType.MLflow_EXPERIMENT: ResourceAccessLevel.SECRET,
                    DatabricksResourceType.MLflow_MODEL: ResourceAccessLevel.SECRET,
                    DatabricksResourceType.CLUSTER: ResourceAccessLevel.SECRET,
                    DatabricksResourceType.JOB: ResourceAccessLevel.SECRET
                }
            },
            "data_engineer": {
                "description": "Data engineer permissions",
                "default_permissions": [DatabricksPermissionLevel.READ, DatabricksPermissionLevel.WRITE, DatabricksPermissionLevel.EXECUTE, DatabricksPermissionLevel.MANAGE],
                "resource_restrictions": {
                    DatabricksResourceType.NOTEBOOK: [DatabricksPermissionLevel.READ, DatabricksPermissionLevel.WRITE, DatabricksPermissionLevel.EXECUTE],
                    DatabricksResourceType.JOB: [DatabricksPermissionLevel.READ, DatabricksPermissionLevel.WRITE, DatabricksPermissionLevel.EXECUTE, DatabricksPermissionLevel.MANAGE],
                    DatabricksResourceType.CLUSTER: [DatabricksPermissionLevel.CAN_ATTACH_TO, DatabricksPermissionLevel.CAN_RESTART, DatabricksPermissionLevel.CAN_MANAGE],
                    DatabricksResourceType.PIPELINE: [DatabricksPermissionLevel.READ, DatabricksPermissionLevel.WRITE, DatabricksPermissionLevel.MANAGE],
                    DatabricksResourceType.DELTA_TABLE: [DatabricksPermissionLevel.READ, DatabricksPermissionLevel.WRITE, DatabricksPermissionLevel.MANAGE],
                    DatabricksResourceType.REPO: [DatabricksPermissionLevel.READ, DatabricksPermissionLevel.WRITE]
                },
                "clearance_requirements": {
                    DatabricksResourceType.NOTEBOOK: ResourceAccessLevel.SECRET,
                    DatabricksResourceType.JOB: ResourceAccessLevel.SECRET,
                    DatabricksResourceType.CLUSTER: ResourceAccessLevel.SECRET,
                    DatabricksResourceType.PIPELINE: ResourceAccessLevel.SECRET,
                    DatabricksResourceType.DELTA_TABLE: ResourceAccessLevel.SECRET,
                    DatabricksResourceType.REPO: ResourceAccessLevel.CONFIDENTIAL
                }
            },
            "workspace_admin": {
                "description": "Workspace administrative permissions",
                "default_permissions": list(DatabricksPermissionLevel),
                "resource_restrictions": {
                    resource_type: list(DatabricksPermissionLevel) for resource_type in DatabricksResourceType
                },
                "clearance_requirements": {
                    DatabricksResourceType.SECRET_SCOPE: ResourceAccessLevel.TOP_SECRET,
                    DatabricksResourceType.UNITY_CATALOG: ResourceAccessLevel.TOP_SECRET,
                    DatabricksResourceType.METASTORE: ResourceAccessLevel.TOP_SECRET
                }
            },
            "security_admin": {
                "description": "Security and compliance admin permissions",
                "default_permissions": [DatabricksPermissionLevel.READ, DatabricksPermissionLevel.ADMIN],
                "resource_restrictions": {
                    DatabricksResourceType.SECRET_SCOPE: [DatabricksPermissionLevel.READ, DatabricksPermissionLevel.WRITE, DatabricksPermissionLevel.MANAGE, DatabricksPermissionLevel.ADMIN],
                    DatabricksResourceType.UNITY_CATALOG: [DatabricksPermissionLevel.READ, DatabricksPermissionLevel.MANAGE, DatabricksPermissionLevel.ADMIN],
                    DatabricksResourceType.CLUSTER_POLICY: [DatabricksPermissionLevel.READ, DatabricksPermissionLevel.WRITE, DatabricksPermissionLevel.MANAGE],
                    DatabricksResourceType.WORKSPACE: [DatabricksPermissionLevel.READ, DatabricksPermissionLevel.ADMIN]
                },
                "clearance_requirements": {
                    resource_type: ResourceAccessLevel.TOP_SECRET for resource_type in DatabricksResourceType
                }
            }
        }
    
    def _initialize_classification_rules(self):
        """Initialize classification rules for automatic permission mapping."""
        self.classification_rules = {
            "data_classification": {
                "unclassified": {
                    "keywords": ["public", "unclassified", "open", "demo"],
                    "access_level": ResourceAccessLevel.UNCLASSIFIED,
                    "default_permissions": [DatabricksPermissionLevel.READ, DatabricksPermissionLevel.CAN_USE]
                },
                "confidential": {
                    "keywords": ["confidential", "internal", "restricted", "fouo"],
                    "access_level": ResourceAccessLevel.CONFIDENTIAL,
                    "default_permissions": [DatabricksPermissionLevel.READ]
                },
                "secret": {
                    "keywords": ["secret", "classified", "sensitive", "controlled"],
                    "access_level": ResourceAccessLevel.SECRET,
                    "default_permissions": [DatabricksPermissionLevel.READ]
                },
                "top_secret": {
                    "keywords": ["top secret", "ts", "compartmented", "sci"],
                    "access_level": ResourceAccessLevel.TOP_SECRET,
                    "default_permissions": [DatabricksPermissionLevel.READ]
                }
            },
            "organization_mapping": {
                "navy": {
                    "domains": ["navy.mil", "spawar.navy.mil", "navair.navy.mil"],
                    "default_roles": ["navy_user", "naval_intelligence", "navy_analyst"],
                    "default_workspaces": ["navy-analytics", "naval-ops"],
                    "clearance_boost": False
                },
                "army": {
                    "domains": ["army.mil", "usarc.army.mil", "tradoc.army.mil"],
                    "default_roles": ["army_user", "army_intelligence", "army_analyst"],
                    "default_workspaces": ["army-analytics", "army-ops"],
                    "clearance_boost": False
                },
                "air_force": {
                    "domains": ["af.mil", "us.af.mil", "afit.edu"],
                    "default_roles": ["af_user", "af_intelligence", "af_analyst"],
                    "default_workspaces": ["af-analytics", "af-ops"],
                    "clearance_boost": False
                },
                "dod_contractor": {
                    "domains": ["contractor.dod.mil", "dcma.mil"],
                    "default_roles": ["contractor_user", "contractor_analyst"],
                    "default_workspaces": ["contractor-sandbox"],
                    "clearance_boost": False
                },
                "intel_community": {
                    "domains": ["ic.gov", "nsa.gov", "cia.gov"],
                    "default_roles": ["intel_analyst", "intel_user", "ic_user"],
                    "default_workspaces": ["intel-analytics", "ic-ops"],
                    "clearance_boost": True
                }
            },
            "resource_patterns": {
                "ml_experiments": {
                    "patterns": ["ml-", "mlflow", "experiment", "model-"],
                    "resource_type": DatabricksResourceType.MLflow_EXPERIMENT,
                    "default_clearance": ResourceAccessLevel.SECRET,
                    "required_roles": ["data_scientist", "ml_engineer"]
                },
                "production_jobs": {
                    "patterns": ["prod-", "production", "deploy", "live-"],
                    "resource_type": DatabricksResourceType.JOB,
                    "default_clearance": ResourceAccessLevel.SECRET,
                    "required_roles": ["data_engineer", "ops_engineer"]
                },
                "dev_notebooks": {
                    "patterns": ["dev-", "test-", "sandbox", "experimental"],
                    "resource_type": DatabricksResourceType.NOTEBOOK,
                    "default_clearance": ResourceAccessLevel.CONFIDENTIAL,
                    "required_roles": ["developer", "analyst"]
                }
            }
        }
    
    def _initialize_workspace_policies(self):
        """Initialize workspace-specific policies."""
        self.workspace_policies = {
            "default": {
                "max_cluster_size": 10,
                "auto_termination_minutes": 60,
                "allowed_instance_types": ["i3.xlarge", "r5.xlarge", "m5.xlarge"],
                "require_approval_for_large_clusters": True,
                "enable_audit_logging": True
            },
            "high_security": {
                "max_cluster_size": 5,
                "auto_termination_minutes": 30,
                "allowed_instance_types": ["i3.large", "r5.large"],
                "require_approval_for_large_clusters": True,
                "enable_audit_logging": True,
                "require_cac_binding": True,
                "disable_external_data_sources": True
            },
            "research": {
                "max_cluster_size": 20,
                "auto_termination_minutes": 120,
                "allowed_instance_types": ["i3.xlarge", "r5.xlarge", "m5.xlarge", "c5.2xlarge"],
                "require_approval_for_large_clusters": False,
                "enable_audit_logging": True,
                "allow_external_libraries": True
            }
        }
    
    def register_resource(self, resource_id: str, resource_type: DatabricksResourceType,
                         resource_name: str, metadata: Dict[str, Any]) -> DatabricksResourcePermission:
        """
        Register Databricks resource with automatic permission mapping.
        
        Args:
            resource_id: Unique resource identifier
            resource_type: Type of Databricks resource
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
                resource_permission = DatabricksResourcePermission(
                    resource_id=resource_id,
                    resource_type=resource_type,
                    resource_name=resource_name,
                    required_clearance=classification["access_level"],
                    allowed_permissions=set(classification["default_permissions"]),
                    context_restrictions=self._build_context_restrictions(resource_type, classification),
                    owner_edipi=metadata.get("owner_edipi"),
                    classification_tags=metadata.get("classification_tags", []),
                    data_sources=metadata.get("data_sources", []),
                    workspace_id=metadata.get("workspace_id"),
                    cluster_policy_id=metadata.get("cluster_policy_id"),
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
                        "permissions": [p.value for p in resource_permission.allowed_permissions],
                        "workspace_id": metadata.get("workspace_id")
                    }
                ))
                
                logger.info(f"Resource registered: {resource_id} ({resource_type.value}) - {classification['access_level'].value}")
                return resource_permission
                
            except Exception as e:
                logger.error(f"Resource registration failed: {e}")
                raise
    
    def create_user_profile(self, cac_credentials: CACCredentials,
                          oauth_scopes: List[str], workspace_id: str) -> UserPermissionProfile:
        """
        Create user permission profile from CAC credentials and OAuth scopes.
        
        Args:
            cac_credentials: CAC credentials
            oauth_scopes: OAuth scopes granted to user
            workspace_id: Databricks workspace ID
            
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
                
                # Determine workspace permissions
                workspace_permissions = self._determine_workspace_permissions(
                    cac_credentials, roles, workspace_id
                )
                
                # Get applicable cluster policies
                cluster_policies = self._get_applicable_cluster_policies(clearance_level, roles)
                
                # Create profile
                profile = UserPermissionProfile(
                    edipi=cac_credentials.edipi,
                    clearance_level=clearance_level,
                    roles=roles,
                    groups=groups,
                    organization=cac_credentials.organization or "Unknown",
                    active_permissions=active_permissions,
                    permission_grants={scope: datetime.now(timezone.utc) for scope in oauth_scopes},
                    permission_revocations={},
                    workspace_permissions={workspace_id: workspace_permissions},
                    cluster_policies=cluster_policies
                )
                
                # Store profile
                self.user_profiles[cac_credentials.edipi] = profile
                
                logger.info(f"User profile created: {cac_credentials.edipi} ({clearance_level.value}) for workspace {workspace_id}")
                return profile
                
            except Exception as e:
                logger.error(f"User profile creation failed: {e}")
                raise
    
    def check_resource_access(self, edipi: str, resource_id: str,
                            permission: DatabricksPermissionLevel,
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
                    "workspace_id": resource.workspace_id,
                    "access_granted": can_access,
                    "check_timestamp": datetime.now(timezone.utc).isoformat()
                }
                
                # Add additional checks
                if can_access:
                    # Check workspace permissions
                    if resource.workspace_id:
                        workspace_perms = user_profile.workspace_permissions.get(resource.workspace_id, set())
                        workspace_access = self._check_workspace_permissions(
                            resource.resource_type, permission, workspace_perms
                        )
                        can_access = can_access and workspace_access
                        access_details["workspace_permission_check"] = workspace_access
                    
                    # Check cluster policy restrictions
                    if resource.resource_type == DatabricksResourceType.CLUSTER and resource.cluster_policy_id:
                        policy_access = resource.cluster_policy_id in user_profile.cluster_policies
                        can_access = can_access and policy_access
                        access_details["cluster_policy_check"] = policy_access
                    
                    # Check time-based restrictions
                    if resource.access_conditions.get("time_restricted"):
                        time_access = self._check_time_restrictions(resource.access_conditions, context)
                        can_access = can_access and time_access
                        access_details["time_restricted"] = not time_access
                    
                    # Check owner-only restrictions
                    if resource.access_conditions.get("owner_only") and resource.owner_edipi != edipi:
                        can_access = False
                        access_details["owner_only_restriction"] = True
                    
                    # Check production environment restrictions
                    if (context == PermissionContext.PRODUCTION and 
                        not user_profile.has_role("production_user")):
                        can_access = False
                        access_details["production_restriction"] = True
                
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
                        "workspace_id": resource.workspace_id,
                        "access_granted": can_access
                    }
                ))
                
                return can_access, access_details
                
            except Exception as e:
                logger.error(f"Resource access check failed: {e}")
                return False, {"error": f"check_failed: {str(e)}"}
    
    def get_user_accessible_resources(self, edipi: str,
                                    resource_type: Optional[DatabricksResourceType] = None,
                                    workspace_id: Optional[str] = None,
                                    permission: DatabricksPermissionLevel = DatabricksPermissionLevel.READ) -> List[Dict[str, Any]]:
        """
        Get list of resources accessible to user.
        
        Args:
            edipi: User EDIPI
            resource_type: Optional filter by resource type
            workspace_id: Optional filter by workspace
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
                    
                    # Filter by workspace if specified
                    if workspace_id and resource.workspace_id != workspace_id:
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
                            "owner_edipi": resource.owner_edipi,
                            "workspace_id": resource.workspace_id,
                            "cluster_policy_id": resource.cluster_policy_id
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
            "default_permissions": [DatabricksPermissionLevel.READ, DatabricksPermissionLevel.CAN_USE]
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
        
        # Check resource patterns
        for pattern_name, pattern_config in self.classification_rules["resource_patterns"].items():
            for pattern in pattern_config["patterns"]:
                if pattern in resource_text_lower:
                    classification["access_level"] = pattern_config["default_clearance"]
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
    
    def _build_context_restrictions(self, resource_type: DatabricksResourceType,
                                  classification: Dict[str, Any]) -> Dict[PermissionContext, Set[DatabricksPermissionLevel]]:
        """Build context-specific permission restrictions."""
        restrictions = {}
        base_permissions = set(classification["default_permissions"])
        
        # Normal operations - base permissions
        restrictions[PermissionContext.NORMAL_OPERATIONS] = base_permissions.copy()
        
        # Emergency access - elevated permissions for critical situations
        emergency_permissions = base_permissions.copy()
        if resource_type in [DatabricksResourceType.CLUSTER, DatabricksResourceType.JOB]:
            emergency_permissions.update([DatabricksPermissionLevel.CAN_RESTART, DatabricksPermissionLevel.CAN_MANAGE])
        restrictions[PermissionContext.EMERGENCY_ACCESS] = emergency_permissions
        
        # Audit review - read-only access
        restrictions[PermissionContext.AUDIT_REVIEW] = {DatabricksPermissionLevel.READ}
        
        # Administrative - full permissions for admins
        if classification["access_level"] in [ResourceAccessLevel.UNCLASSIFIED, ResourceAccessLevel.CONFIDENTIAL]:
            restrictions[PermissionContext.ADMINISTRATIVE] = set(DatabricksPermissionLevel)
        else:
            restrictions[PermissionContext.ADMINISTRATIVE] = base_permissions.copy()
        
        # Development - elevated permissions for development resources
        dev_permissions = base_permissions.copy()
        if resource_type in [DatabricksResourceType.NOTEBOOK, DatabricksResourceType.REPO]:
            dev_permissions.update([DatabricksPermissionLevel.WRITE, DatabricksPermissionLevel.EXECUTE])
        restrictions[PermissionContext.DEVELOPMENT] = dev_permissions
        
        # Production - restricted permissions
        prod_permissions = {DatabricksPermissionLevel.READ}
        if resource_type == DatabricksResourceType.JOB:
            prod_permissions.add(DatabricksPermissionLevel.EXECUTE)
        restrictions[PermissionContext.PRODUCTION] = prod_permissions
        
        # Research - expanded permissions for research context
        research_permissions = base_permissions.copy()
        if resource_type in [DatabricksResourceType.MLflow_EXPERIMENT, DatabricksResourceType.NOTEBOOK]:
            research_permissions.update([DatabricksPermissionLevel.WRITE, DatabricksPermissionLevel.EXECUTE, DatabricksPermissionLevel.MANAGE])
        restrictions[PermissionContext.RESEARCH] = research_permissions
        
        return restrictions
    
    def _determine_user_roles(self, cac_credentials: CACCredentials, oauth_scopes: List[str]) -> Set[str]:
        """Determine user roles from CAC credentials and OAuth scopes."""
        roles = set()
        
        # Add base user role
        roles.add("databricks_user")
        
        # Add organization-based roles
        if cac_credentials.organization:
            org_lower = cac_credentials.organization.lower()
            for org_name, org_config in self.classification_rules["organization_mapping"].items():
                if any(domain in org_lower for domain in org_config.get("domains", [])):
                    roles.update(org_config["default_roles"])
        
        # Add scope-based roles
        for scope in oauth_scopes:
            if "admin" in scope:
                roles.add("databricks_admin")
            elif "mlflow" in scope or "ml_" in scope:
                roles.add("data_scientist")
            elif "job" in scope or "pipeline" in scope:
                roles.add("data_engineer")
            elif "sql" in scope or "warehouse" in scope:
                roles.add("data_analyst")
            elif "unity_catalog" in scope:
                roles.add("data_admin")
            elif "secret" in scope:
                roles.add("security_admin")
        
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
                                  roles: Set[str]) -> Dict[str, Set[DatabricksPermissionLevel]]:
        """Map OAuth scopes to Databricks permissions."""
        permissions = {}
        
        for scope in oauth_scopes:
            if scope.startswith("databricks:"):
                scope_name = scope[11:]  # Remove "databricks:" prefix
                
                # Map scope to permissions based on name
                if "read" in scope_name or "workspace_read" in scope_name:
                    permissions[scope] = {DatabricksPermissionLevel.READ}
                elif "write" in scope_name or "execute" in scope_name:
                    permissions[scope] = {DatabricksPermissionLevel.READ, DatabricksPermissionLevel.WRITE, DatabricksPermissionLevel.EXECUTE}
                elif "cluster_access" in scope_name:
                    permissions[scope] = {DatabricksPermissionLevel.CAN_USE, DatabricksPermissionLevel.CAN_ATTACH_TO, DatabricksPermissionLevel.CAN_RESTART}
                elif "job_execute" in scope_name:
                    permissions[scope] = {DatabricksPermissionLevel.READ, DatabricksPermissionLevel.EXECUTE}
                elif "mlflow_access" in scope_name:
                    permissions[scope] = {DatabricksPermissionLevel.READ, DatabricksPermissionLevel.WRITE, DatabricksPermissionLevel.MANAGE}
                elif "admin" in scope_name:
                    permissions[scope] = set(DatabricksPermissionLevel)
                elif "manage" in scope_name:
                    permissions[scope] = {DatabricksPermissionLevel.READ, DatabricksPermissionLevel.WRITE, DatabricksPermissionLevel.MANAGE}
                else:
                    permissions[scope] = {DatabricksPermissionLevel.READ}
        
        return permissions
    
    def _determine_workspace_permissions(self, cac_credentials: CACCredentials,
                                       roles: Set[str], workspace_id: str) -> Set[str]:
        """Determine workspace-specific permissions."""
        workspace_permissions = set()
        
        # Base workspace access
        workspace_permissions.add("workspace_access")
        
        # Role-based permissions
        if "databricks_admin" in roles:
            workspace_permissions.update([
                "workspace_admin", "cluster_create", "job_create", 
                "secret_manage", "user_manage"
            ])
        elif "data_engineer" in roles:
            workspace_permissions.update([
                "cluster_create", "job_create", "pipeline_create"
            ])
        elif "data_scientist" in roles:
            workspace_permissions.update([
                "notebook_create", "experiment_create", "model_create"
            ])
        elif "data_analyst" in roles:
            workspace_permissions.update([
                "sql_access", "dashboard_create"
            ])
        
        # Clearance-based permissions
        if cac_credentials.clearance_level in ["SECRET", "TOP SECRET"]:
            workspace_permissions.add("classified_data_access")
        
        return workspace_permissions
    
    def _get_applicable_cluster_policies(self, clearance_level: ResourceAccessLevel,
                                       roles: Set[str]) -> List[str]:
        """Get applicable cluster policies for user."""
        policies = []
        
        # Base policy based on clearance
        if clearance_level == ResourceAccessLevel.TOP_SECRET:
            policies.append("high_security_policy")
        elif clearance_level == ResourceAccessLevel.SECRET:
            policies.append("secure_policy")
        else:
            policies.append("standard_policy")
        
        # Role-based policies
        if "data_scientist" in roles:
            policies.append("ml_optimized_policy")
        elif "data_engineer" in roles:
            policies.append("etl_optimized_policy")
        
        return policies
    
    def _check_workspace_permissions(self, resource_type: DatabricksResourceType,
                                   permission: DatabricksPermissionLevel,
                                   workspace_perms: Set[str]) -> bool:
        """Check workspace-specific permission requirements."""
        required_workspace_perms = {
            DatabricksResourceType.CLUSTER: ["cluster_create"],
            DatabricksResourceType.JOB: ["job_create"],
            DatabricksResourceType.SECRET_SCOPE: ["secret_manage"],
            DatabricksResourceType.MLflow_EXPERIMENT: ["experiment_create"],
            DatabricksResourceType.PIPELINE: ["pipeline_create"]
        }
        
        if resource_type in required_workspace_perms:
            required_perms = required_workspace_perms[resource_type]
            if permission in [DatabricksPermissionLevel.WRITE, DatabricksPermissionLevel.MANAGE]:
                return any(perm in workspace_perms for perm in required_perms)
        
        return True  # Default allow for read operations
    
    def _check_time_restrictions(self, access_conditions: Dict[str, Any],
                               context: PermissionContext) -> bool:
        """Check time-based access restrictions."""
        # In production, this would check business hours, maintenance windows, etc.
        # For now, always allow access except during emergency context
        if context == PermissionContext.EMERGENCY_ACCESS:
            return True
        
        # Check if resource has specific time restrictions
        time_restrictions = access_conditions.get("time_restrictions", {})
        if not time_restrictions:
            return True
        
        current_hour = datetime.now().hour
        allowed_hours = time_restrictions.get("allowed_hours", list(range(24)))
        
        return current_hour in allowed_hours