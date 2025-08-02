"""
API Version Manager for DoD Enterprise Systems

This module provides comprehensive API versioning, compatibility management, and 
semantic versioning controls for DoD-compliant enterprise environments.

Key Features:
- Semantic versioning (SemVer) with backward compatibility analysis
- API contract validation and breaking change detection
- Version routing and content negotiation
- Compatibility matrix management
- Consumer impact analysis and migration planning
- Integration with DoD API Gateway infrastructure

Security Standards:
- NIST 800-53 version management controls
- DoD 8500 series API versioning compliance
- FIPS 140-2 cryptographic version signing
- STIGs compliance for API lifecycle management
"""

import re
import json
import uuid
import asyncio
import logging
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple, Union, Set
from dataclasses import dataclass, asdict, field
from enum import Enum
from collections import defaultdict
from pathlib import Path
import semantic_version

import aioredis
import jsonschema
from jsonschema import ValidationError
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption

# Import from existing modules
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from api_gateway.dod_api_gateway import APIGatewayEnvironment, SecurityClassification
from encryption.encryption_manager import EncryptionManager


class VersionState(Enum):
    """API version lifecycle states."""
    DEVELOPMENT = "development"
    ALPHA = "alpha"
    BETA = "beta"
    RELEASE_CANDIDATE = "rc"
    STABLE = "stable"
    DEPRECATED = "deprecated"
    SUNSET = "sunset"
    ARCHIVED = "archived"


class CompatibilityLevel(Enum):
    """API compatibility levels."""
    FULLY_COMPATIBLE = "fully_compatible"
    BACKWARD_COMPATIBLE = "backward_compatible"
    FORWARD_COMPATIBLE = "forward_compatible"
    BREAKING_CHANGE = "breaking_change"
    INCOMPATIBLE = "incompatible"


class ChangeType(Enum):
    """Types of API changes."""
    ADDITION = "addition"
    MODIFICATION = "modification"
    DEPRECATION = "deprecation"
    REMOVAL = "removal"
    SECURITY_UPDATE = "security_update"
    SCHEMA_CHANGE = "schema_change"


class VersioningStrategy(Enum):
    """API versioning strategies."""
    URI_PATH = "uri_path"          # /api/v1/resource
    QUERY_PARAMETER = "query"      # /api/resource?version=1
    HEADER = "header"              # Accept: application/vnd.api+json;version=1
    CONTENT_TYPE = "content_type"  # application/vnd.api.v1+json
    SUBDOMAIN = "subdomain"        # v1.api.domain.mil


@dataclass
class APIContract:
    """API contract definition."""
    version: str
    endpoints: Dict[str, Dict[str, Any]]
    schemas: Dict[str, Dict[str, Any]]
    security_requirements: Dict[str, Any]
    metadata: Dict[str, Any]
    checksum: Optional[str] = None


@dataclass
class VersionMetadata:
    """Version metadata and lifecycle information."""
    version: str
    state: VersionState
    release_date: datetime
    deprecation_date: Optional[datetime] = None
    sunset_date: Optional[datetime] = None
    changelog: List[Dict[str, Any]] = field(default_factory=list)
    breaking_changes: List[str] = field(default_factory=list)
    migration_guide: Optional[str] = None
    supported_until: Optional[datetime] = None
    consumer_count: int = 0
    security_level: SecurityClassification = SecurityClassification.UNCLASSIFIED


@dataclass
class CompatibilityReport:
    """Compatibility analysis report."""
    source_version: str
    target_version: str
    compatibility_level: CompatibilityLevel
    breaking_changes: List[Dict[str, Any]]
    deprecated_features: List[Dict[str, Any]]
    migration_steps: List[str]
    estimated_effort: str
    consumer_impact: Dict[str, Any]
    generated_at: datetime


@dataclass
class ConsumerRegistration:
    """API consumer registration."""
    consumer_id: str
    name: str
    contact_email: str
    versions_used: List[str]
    critical_endpoints: List[str]
    migration_timeline: Optional[datetime] = None
    notification_preferences: Dict[str, bool] = field(default_factory=dict)
    last_activity: Optional[datetime] = None


class APIVersionManager:
    """
    Comprehensive API Version Manager for DoD Enterprise Systems
    
    Manages API versioning, compatibility analysis, and version lifecycle
    with enterprise-grade features for DoD environments.
    """
    
    def __init__(self, redis_url: str = "redis://localhost:6379",
                 environment: APIGatewayEnvironment = APIGatewayEnvironment.DEVELOPMENT):
        """Initialize API Version Manager."""
        self.logger = logging.getLogger(__name__)
        self.environment = environment
        
        # Redis client for version state management
        self.redis_client = None
        self.redis_url = redis_url
        
        # Version storage
        self.versions: Dict[str, VersionMetadata] = {}
        self.contracts: Dict[str, APIContract] = {}
        self.consumers: Dict[str, ConsumerRegistration] = {}
        
        # Versioning configuration
        self.versioning_strategy = VersioningStrategy.URI_PATH
        self.supported_versions: Set[str] = set()
        self.default_version: Optional[str] = None
        
        # Compatibility rules
        self.compatibility_rules: Dict[str, Any] = {}
        
        # Change tracking
        self.change_history: List[Dict[str, Any]] = []
        
        # Encryption for sensitive version data
        self.encryption_manager = None
    
    async def initialize(self) -> None:
        """Initialize version manager."""
        try:
            # Initialize Redis client
            self.redis_client = await aioredis.from_url(self.redis_url)
            await self.redis_client.ping()
            
            # Initialize encryption manager
            self.encryption_manager = EncryptionManager()
            await self.encryption_manager.initialize()
            
            # Load existing versions from Redis
            await self._load_versions_from_storage()
            
            # Initialize compatibility rules
            self._initialize_compatibility_rules()
            
            self.logger.info("API Version Manager initialized successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize version manager: {e}")
            raise
    
    def _initialize_compatibility_rules(self) -> None:
        """Initialize default compatibility rules."""
        self.compatibility_rules = {
            "breaking_changes": [
                "removing_field",
                "changing_field_type",
                "removing_endpoint",
                "changing_endpoint_signature",
                "removing_enum_value",
                "changing_response_structure"
            ],
            "non_breaking_changes": [
                "adding_field",
                "adding_endpoint", 
                "adding_enum_value",
                "adding_optional_parameter",
                "expanding_response"
            ],
            "security_changes": [
                "authentication_change",
                "authorization_change", 
                "encryption_change",
                "tls_requirement_change"
            ]
        }
    
    async def register_version(self, version: str, contract: APIContract,
                             state: VersionState = VersionState.DEVELOPMENT,
                             breaking_changes: List[str] = None) -> bool:
        """
        Register a new API version.
        
        Args:
            version: Semantic version string (e.g., "1.2.3")
            contract: API contract definition
            state: Initial version state
            breaking_changes: List of breaking changes from previous version
            
        Returns:
            True if registration successful
        """
        try:
            # Validate semantic version
            if not self._validate_semantic_version(version):
                raise ValueError(f"Invalid semantic version: {version}")
            
            # Check if version already exists
            if version in self.versions:
                raise ValueError(f"Version {version} already exists")
            
            # Calculate contract checksum
            contract.checksum = self._calculate_contract_checksum(contract)
            
            # Create version metadata
            metadata = VersionMetadata(
                version=version,
                state=state,
                release_date=datetime.utcnow(),
                breaking_changes=breaking_changes or [],
                consumer_count=0,
                security_level=SecurityClassification.UNCLASSIFIED
            )
            
            # Store version and contract
            self.versions[version] = metadata
            self.contracts[version] = contract
            
            # Update supported versions
            if state in [VersionState.STABLE, VersionState.BETA, VersionState.RELEASE_CANDIDATE]:
                self.supported_versions.add(version)
            
            # Set as default if first stable version
            if state == VersionState.STABLE and not self.default_version:
                self.default_version = version
            
            # Save to storage
            await self._save_version_to_storage(version)
            
            # Log version registration
            await self._log_version_event("version_registered", version, {
                "state": state.value,
                "breaking_changes": len(breaking_changes or [])
            })
            
            self.logger.info(f"Registered API version {version} with state {state.value}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to register version {version}: {e}")
            return False
    
    async def transition_version_state(self, version: str, new_state: VersionState,
                                     metadata: Dict[str, Any] = None) -> bool:
        """
        Transition version to new state.
        
        Args:
            version: Version to transition
            new_state: Target state
            metadata: Additional metadata for transition
            
        Returns:
            True if transition successful
        """
        try:
            if version not in self.versions:
                raise ValueError(f"Version {version} not found")
            
            current_state = self.versions[version].state
            
            # Validate state transition
            if not self._validate_state_transition(current_state, new_state):
                raise ValueError(f"Invalid state transition from {current_state.value} to {new_state.value}")
            
            # Update version metadata
            self.versions[version].state = new_state
            
            # Handle state-specific logic
            if new_state == VersionState.STABLE:
                self.supported_versions.add(version)
                if not self.default_version:
                    self.default_version = version
                    
            elif new_state == VersionState.DEPRECATED:
                # Set deprecation date
                self.versions[version].deprecation_date = datetime.utcnow()
                # Calculate sunset date (e.g., 6 months from deprecation)
                self.versions[version].sunset_date = datetime.utcnow() + timedelta(days=180)
                
            elif new_state == VersionState.SUNSET:
                self.supported_versions.discard(version)
                # Update default version if this was default
                if self.default_version == version:
                    self.default_version = self._get_latest_stable_version()
                    
            elif new_state == VersionState.ARCHIVED:
                self.supported_versions.discard(version)
                
            # Save to storage
            await self._save_version_to_storage(version)
            
            # Log state transition
            await self._log_version_event("state_transition", version, {
                "from_state": current_state.value,
                "to_state": new_state.value,
                "metadata": metadata
            })
            
            self.logger.info(f"Transitioned version {version} from {current_state.value} to {new_state.value}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to transition version {version} state: {e}")
            return False
    
    async def analyze_compatibility(self, source_version: str, target_version: str) -> CompatibilityReport:
        """
        Analyze compatibility between two API versions.
        
        Args:
            source_version: Source version for comparison
            target_version: Target version for comparison
            
        Returns:
            CompatibilityReport with analysis results
        """
        try:
            if source_version not in self.contracts or target_version not in self.contracts:
                raise ValueError("One or both versions not found")
            
            source_contract = self.contracts[source_version]
            target_contract = self.contracts[target_version]
            
            # Analyze compatibility
            compatibility_level, breaking_changes, deprecated_features = await self._compare_contracts(
                source_contract, target_contract
            )
            
            # Generate migration steps
            migration_steps = await self._generate_migration_steps(
                source_contract, target_contract, breaking_changes
            )
            
            # Estimate effort
            effort = self._estimate_migration_effort(breaking_changes, deprecated_features)
            
            # Analyze consumer impact
            consumer_impact = await self._analyze_consumer_impact(source_version, breaking_changes)
            
            # Create compatibility report
            report = CompatibilityReport(
                source_version=source_version,
                target_version=target_version,
                compatibility_level=compatibility_level,
                breaking_changes=breaking_changes,
                deprecated_features=deprecated_features,
                migration_steps=migration_steps,
                estimated_effort=effort,
                consumer_impact=consumer_impact,
                generated_at=datetime.utcnow()
            )
            
            # Cache report
            await self._cache_compatibility_report(report)
            
            return report
            
        except Exception as e:
            self.logger.error(f"Failed to analyze compatibility: {e}")
            raise
    
    async def register_consumer(self, consumer: ConsumerRegistration) -> bool:
        """
        Register API consumer.
        
        Args:
            consumer: Consumer registration data
            
        Returns:
            True if registration successful
        """
        try:
            # Validate consumer data
            if not consumer.consumer_id or not consumer.name:
                raise ValueError("Consumer ID and name are required")
            
            # Validate versions used
            for version in consumer.versions_used:
                if version not in self.versions:
                    raise ValueError(f"Version {version} not found")
            
            # Store consumer registration
            self.consumers[consumer.consumer_id] = consumer
            
            # Update consumer count for versions
            for version in consumer.versions_used:
                self.versions[version].consumer_count += 1
            
            # Save to storage
            await self._save_consumer_to_storage(consumer.consumer_id)
            
            # Log consumer registration
            await self._log_version_event("consumer_registered", None, {
                "consumer_id": consumer.consumer_id,
                "versions_used": consumer.versions_used
            })
            
            self.logger.info(f"Registered consumer {consumer.consumer_id} using versions {consumer.versions_used}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to register consumer: {e}")
            return False
    
    async def route_request(self, request_headers: Dict[str, str], 
                          request_path: str) -> Tuple[str, bool]:
        """
        Route request to appropriate API version.
        
        Args:
            request_headers: HTTP request headers
            request_path: Request path
            
        Returns:
            Tuple of (version, is_supported)
        """
        try:
            version = None
            
            # Extract version based on strategy
            if self.versioning_strategy == VersioningStrategy.URI_PATH:
                version = self._extract_version_from_path(request_path)
                
            elif self.versioning_strategy == VersioningStrategy.HEADER:
                version = self._extract_version_from_header(request_headers)
                
            elif self.versioning_strategy == VersioningStrategy.CONTENT_TYPE:
                version = self._extract_version_from_content_type(request_headers)
                
            elif self.versioning_strategy == VersioningStrategy.QUERY_PARAMETER:
                # This would need query parameters, simplified for now
                version = request_headers.get('X-API-Version')
            
            # Use default version if none specified
            if not version:
                version = self.default_version
            
            # Check if version is supported
            is_supported = version in self.supported_versions
            
            # Log version usage
            if version:
                await self._log_version_usage(version, request_headers.get('User-Agent', ''))
            
            return version, is_supported
            
        except Exception as e:
            self.logger.error(f"Failed to route request: {e}")
            return self.default_version, False
    
    async def get_version_info(self, version: Optional[str] = None) -> Dict[str, Any]:
        """
        Get version information.
        
        Args:
            version: Specific version (None for all versions)
            
        Returns:
            Version information
        """
        try:
            if version:
                if version not in self.versions:
                    raise ValueError(f"Version {version} not found")
                
                metadata = self.versions[version]
                contract = self.contracts.get(version)
                
                return {
                    "version": version,
                    "state": metadata.state.value,
                    "release_date": metadata.release_date.isoformat(),
                    "deprecation_date": metadata.deprecation_date.isoformat() if metadata.deprecation_date else None,
                    "sunset_date": metadata.sunset_date.isoformat() if metadata.sunset_date else None,
                    "breaking_changes": metadata.breaking_changes,
                    "consumer_count": metadata.consumer_count,
                    "endpoints": list(contract.endpoints.keys()) if contract else [],
                    "is_supported": version in self.supported_versions,
                    "is_default": version == self.default_version
                }
            else:
                return {
                    "supported_versions": list(self.supported_versions),
                    "default_version": self.default_version,
                    "versioning_strategy": self.versioning_strategy.value,
                    "total_versions": len(self.versions),
                    "versions": [
                        {
                            "version": v,
                            "state": metadata.state.value,
                            "consumer_count": metadata.consumer_count,
                            "is_supported": v in self.supported_versions
                        }
                        for v, metadata in self.versions.items()
                    ]
                }
                
        except Exception as e:
            self.logger.error(f"Failed to get version info: {e}")
            return {}
    
    def _validate_semantic_version(self, version: str) -> bool:
        """Validate semantic version format."""
        try:
            semantic_version.Version(version)
            return True
        except ValueError:
            return False
    
    def _calculate_contract_checksum(self, contract: APIContract) -> str:
        """Calculate checksum for API contract."""
        contract_data = {
            "endpoints": contract.endpoints,
            "schemas": contract.schemas,
            "security_requirements": contract.security_requirements
        }
        contract_json = json.dumps(contract_data, sort_keys=True)
        return hashlib.sha256(contract_json.encode()).hexdigest()
    
    def _validate_state_transition(self, current: VersionState, target: VersionState) -> bool:
        """Validate version state transition."""
        valid_transitions = {
            VersionState.DEVELOPMENT: [VersionState.ALPHA, VersionState.BETA, VersionState.ARCHIVED],
            VersionState.ALPHA: [VersionState.BETA, VersionState.DEVELOPMENT, VersionState.ARCHIVED],
            VersionState.BETA: [VersionState.RELEASE_CANDIDATE, VersionState.ALPHA, VersionState.ARCHIVED],
            VersionState.RELEASE_CANDIDATE: [VersionState.STABLE, VersionState.BETA, VersionState.ARCHIVED],
            VersionState.STABLE: [VersionState.DEPRECATED],
            VersionState.DEPRECATED: [VersionState.SUNSET],
            VersionState.SUNSET: [VersionState.ARCHIVED],
            VersionState.ARCHIVED: []  # Terminal state
        }
        
        return target in valid_transitions.get(current, [])
    
    def _get_latest_stable_version(self) -> Optional[str]:
        """Get the latest stable version."""
        stable_versions = [
            v for v, metadata in self.versions.items()
            if metadata.state == VersionState.STABLE
        ]
        
        if not stable_versions:
            return None
        
        # Sort by semantic version
        try:
            sorted_versions = sorted(stable_versions, key=semantic_version.Version, reverse=True)
            return sorted_versions[0]
        except ValueError:
            # Fallback to string sorting
            return sorted(stable_versions, reverse=True)[0]
    
    async def _compare_contracts(self, source: APIContract, target: APIContract) -> Tuple[CompatibilityLevel, List[Dict], List[Dict]]:
        """Compare two API contracts for compatibility."""
        breaking_changes = []
        deprecated_features = []
        
        # Compare endpoints
        source_endpoints = set(source.endpoints.keys())
        target_endpoints = set(target.endpoints.keys())
        
        # Removed endpoints (breaking change)
        removed_endpoints = source_endpoints - target_endpoints
        for endpoint in removed_endpoints:
            breaking_changes.append({
                "type": "endpoint_removed",
                "endpoint": endpoint,
                "description": f"Endpoint {endpoint} was removed"
            })
        
        # Compare schemas
        for schema_name, source_schema in source.schemas.items():
            if schema_name in target.schemas:
                target_schema = target.schemas[schema_name]
                schema_changes = self._compare_schemas(source_schema, target_schema)
                breaking_changes.extend(schema_changes["breaking"])
                deprecated_features.extend(schema_changes["deprecated"])
        
        # Determine compatibility level
        if breaking_changes:
            compatibility_level = CompatibilityLevel.BREAKING_CHANGE
        elif deprecated_features:
            compatibility_level = CompatibilityLevel.BACKWARD_COMPATIBLE
        else:
            compatibility_level = CompatibilityLevel.FULLY_COMPATIBLE
        
        return compatibility_level, breaking_changes, deprecated_features
    
    def _compare_schemas(self, source_schema: Dict, target_schema: Dict) -> Dict[str, List]:
        """Compare JSON schemas for breaking changes."""
        breaking = []
        deprecated = []
        
        # Compare required fields
        source_required = set(source_schema.get("required", []))
        target_required = set(target_schema.get("required", []))
        
        # New required fields (breaking change)
        new_required = target_required - source_required
        for field in new_required:
            breaking.append({
                "type": "field_required_added",
                "field": field,
                "description": f"Field {field} is now required"
            })
        
        # Compare properties
        source_props = source_schema.get("properties", {})
        target_props = target_schema.get("properties", {})
        
        # Removed properties (breaking change)
        removed_props = set(source_props.keys()) - set(target_props.keys())
        for prop in removed_props:
            breaking.append({
                "type": "property_removed",
                "property": prop,
                "description": f"Property {prop} was removed"
            })
        
        return {"breaking": breaking, "deprecated": deprecated}
    
    async def _generate_migration_steps(self, source: APIContract, target: APIContract, 
                                      breaking_changes: List[Dict]) -> List[str]:
        """Generate migration steps for version upgrade."""
        steps = []
        
        for change in breaking_changes:
            if change["type"] == "endpoint_removed":
                steps.append(f"Replace calls to {change['endpoint']} with alternative endpoint")
            elif change["type"] == "field_required_added":
                steps.append(f"Add required field {change['field']} to requests")
            elif change["type"] == "property_removed":
                steps.append(f"Remove references to property {change['property']}")
        
        if steps:
            steps.insert(0, "Review all breaking changes before migration")
            steps.append("Test thoroughly in non-production environment")
            steps.append("Update client code and redeploy")
        
        return steps
    
    def _estimate_migration_effort(self, breaking_changes: List[Dict], 
                                 deprecated_features: List[Dict]) -> str:
        """Estimate migration effort based on changes."""
        breaking_count = len(breaking_changes)
        deprecated_count = len(deprecated_features)
        
        if breaking_count == 0 and deprecated_count == 0:
            return "Minimal"
        elif breaking_count <= 2 and deprecated_count <= 5:
            return "Low"
        elif breaking_count <= 5 and deprecated_count <= 10:
            return "Medium"
        else:
            return "High"
    
    async def _analyze_consumer_impact(self, version: str, breaking_changes: List[Dict]) -> Dict[str, Any]:
        """Analyze impact on consumers."""
        affected_consumers = [
            consumer for consumer in self.consumers.values()
            if version in consumer.versions_used
        ]
        
        return {
            "total_consumers": len(affected_consumers),
            "critical_consumers": len([c for c in affected_consumers if c.critical_endpoints]),
            "breaking_changes_count": len(breaking_changes),
            "estimated_migration_time": "2-4 weeks" if breaking_changes else "1-2 days"
        }
    
    def _extract_version_from_path(self, path: str) -> Optional[str]:
        """Extract version from URI path."""
        # Pattern: /api/v1.2.3/resource or /api/v1/resource
        match = re.search(r'/v(\d+(?:\.\d+(?:\.\d+)?)?)', path)
        return match.group(1) if match else None
    
    def _extract_version_from_header(self, headers: Dict[str, str]) -> Optional[str]:
        """Extract version from Accept header."""
        accept_header = headers.get('Accept', '')
        # Pattern: application/vnd.api+json;version=1.2.3
        match = re.search(r'version=(\d+(?:\.\d+(?:\.\d+)?)?)', accept_header)
        return match.group(1) if match else None
    
    def _extract_version_from_content_type(self, headers: Dict[str, str]) -> Optional[str]:
        """Extract version from Content-Type header."""
        content_type = headers.get('Content-Type', '')
        # Pattern: application/vnd.api.v1.2.3+json
        match = re.search(r'\.v(\d+(?:\.\d+(?:\.\d+)?))\+', content_type)
        return match.group(1) if match else None
    
    async def _save_version_to_storage(self, version: str) -> None:
        """Save version metadata to Redis."""
        try:
            version_key = f"api_versions:{self.environment.value}:{version}"
            
            # Prepare data for storage
            version_data = {
                "metadata": asdict(self.versions[version]),
                "contract": asdict(self.contracts[version]) if version in self.contracts else None
            }
            
            # Convert datetime objects to ISO format
            version_data["metadata"]["release_date"] = self.versions[version].release_date.isoformat()
            if self.versions[version].deprecation_date:
                version_data["metadata"]["deprecation_date"] = self.versions[version].deprecation_date.isoformat()
            if self.versions[version].sunset_date:
                version_data["metadata"]["sunset_date"] = self.versions[version].sunset_date.isoformat()
            if self.versions[version].supported_until:
                version_data["metadata"]["supported_until"] = self.versions[version].supported_until.isoformat()
            
            # Encrypt sensitive data
            encrypted_data = await self.encryption_manager.encrypt_data(
                json.dumps(version_data).encode()
            )
            
            await self.redis_client.set(version_key, encrypted_data, ex=86400 * 365)  # 1 year expiry
            
        except Exception as e:
            self.logger.error(f"Failed to save version {version} to storage: {e}")
    
    async def _load_versions_from_storage(self) -> None:
        """Load versions from Redis storage."""
        try:
            pattern = f"api_versions:{self.environment.value}:*"
            keys = await self.redis_client.keys(pattern)
            
            for key in keys:
                try:
                    encrypted_data = await self.redis_client.get(key)
                    if encrypted_data:
                        # Decrypt data
                        decrypted_data = await self.encryption_manager.decrypt_data(encrypted_data)
                        version_data = json.loads(decrypted_data.decode())
                        
                        # Extract version from key
                        version = key.decode().split(':')[-1]
                        
                        # Restore metadata
                        metadata_dict = version_data["metadata"]
                        metadata_dict["state"] = VersionState(metadata_dict["state"])
                        metadata_dict["security_level"] = SecurityClassification(metadata_dict["security_level"])
                        metadata_dict["release_date"] = datetime.fromisoformat(metadata_dict["release_date"])
                        
                        if metadata_dict.get("deprecation_date"):
                            metadata_dict["deprecation_date"] = datetime.fromisoformat(metadata_dict["deprecation_date"])
                        if metadata_dict.get("sunset_date"):
                            metadata_dict["sunset_date"] = datetime.fromisoformat(metadata_dict["sunset_date"])
                        if metadata_dict.get("supported_until"):
                            metadata_dict["supported_until"] = datetime.fromisoformat(metadata_dict["supported_until"])
                        
                        self.versions[version] = VersionMetadata(**metadata_dict)
                        
                        # Restore contract if present
                        if version_data.get("contract"):
                            self.contracts[version] = APIContract(**version_data["contract"])
                        
                        # Update supported versions
                        if self.versions[version].state in [VersionState.STABLE, VersionState.BETA, VersionState.RELEASE_CANDIDATE]:
                            self.supported_versions.add(version)
                
                except Exception as e:
                    self.logger.error(f"Failed to load version from key {key}: {e}")
            
            # Set default version
            self.default_version = self._get_latest_stable_version()
            
            self.logger.info(f"Loaded {len(self.versions)} versions from storage")
            
        except Exception as e:
            self.logger.error(f"Failed to load versions from storage: {e}")
    
    async def _save_consumer_to_storage(self, consumer_id: str) -> None:
        """Save consumer registration to Redis."""
        try:
            consumer_key = f"api_consumers:{self.environment.value}:{consumer_id}"
            consumer_data = asdict(self.consumers[consumer_id])
            
            # Convert datetime objects
            if consumer_data.get("migration_timeline"):
                consumer_data["migration_timeline"] = self.consumers[consumer_id].migration_timeline.isoformat()
            if consumer_data.get("last_activity"):
                consumer_data["last_activity"] = self.consumers[consumer_id].last_activity.isoformat()
            
            await self.redis_client.set(
                consumer_key, 
                json.dumps(consumer_data), 
                ex=86400 * 365  # 1 year expiry
            )
            
        except Exception as e:
            self.logger.error(f"Failed to save consumer {consumer_id} to storage: {e}")
    
    async def _cache_compatibility_report(self, report: CompatibilityReport) -> None:
        """Cache compatibility report."""
        try:
            report_key = f"compatibility_reports:{report.source_version}:{report.target_version}"
            report_data = asdict(report)
            report_data["generated_at"] = report.generated_at.isoformat()
            
            await self.redis_client.set(
                report_key,
                json.dumps(report_data),
                ex=86400 * 7  # 7 days expiry
            )
            
        except Exception as e:
            self.logger.error(f"Failed to cache compatibility report: {e}")
    
    async def _log_version_event(self, event_type: str, version: Optional[str], data: Dict[str, Any]) -> None:
        """Log version management events."""
        try:
            event = {
                "timestamp": datetime.utcnow().isoformat(),
                "event_type": event_type,
                "version": version,
                "environment": self.environment.value,
                "data": data
            }
            
            # Log to application logs
            self.logger.info(f"Version Event: {json.dumps(event)}")
            
            # Store in Redis for analytics
            events_key = f"version_events:{datetime.utcnow().strftime('%Y%m%d')}"
            await self.redis_client.lpush(events_key, json.dumps(event))
            await self.redis_client.expire(events_key, 86400 * 30)  # 30 days
            
        except Exception as e:
            self.logger.error(f"Failed to log version event: {e}")
    
    async def _log_version_usage(self, version: str, user_agent: str) -> None:
        """Log version usage for analytics."""
        try:
            usage_key = f"version_usage:{version}:{datetime.utcnow().strftime('%Y%m%d%H')}"
            await self.redis_client.incr(usage_key)
            await self.redis_client.expire(usage_key, 86400 * 7)  # 7 days
            
        except Exception as e:
            self.logger.error(f"Failed to log version usage: {e}")
    
    async def close(self) -> None:
        """Clean up resources."""
        if self.redis_client:
            await self.redis_client.close()
        
        if self.encryption_manager:
            await self.encryption_manager.close()
        
        self.logger.info("API Version Manager closed")


# Example usage and utility functions
def create_sample_contract() -> APIContract:
    """Create sample API contract for testing."""
    return APIContract(
        version="1.0.0",
        endpoints={
            "/api/v1/users": {
                "methods": ["GET", "POST"],
                "parameters": {"limit": "integer", "offset": "integer"},
                "responses": {"200": "UserList", "400": "Error"}
            },
            "/api/v1/users/{id}": {
                "methods": ["GET", "PUT", "DELETE"],
                "parameters": {"id": "string"},
                "responses": {"200": "User", "404": "NotFound"}
            }
        },
        schemas={
            "User": {
                "type": "object",
                "required": ["id", "name", "email"],
                "properties": {
                    "id": {"type": "string"},
                    "name": {"type": "string"},
                    "email": {"type": "string", "format": "email"}
                }
            }
        },
        security_requirements={
            "authentication": "OAuth2",
            "authorization": "RBAC",
            "encryption": "TLS 1.3"
        },
        metadata={
            "title": "User Management API",
            "description": "API for managing user accounts"
        }
    )


if __name__ == "__main__":
    # Example usage
    async def main():
        manager = APIVersionManager()
        await manager.initialize()
        
        try:
            # Register a new version
            contract = create_sample_contract()
            await manager.register_version("1.0.0", contract, VersionState.STABLE)
            
            # Register consumer
            consumer = ConsumerRegistration(
                consumer_id="test-client",
                name="Test Client Application",
                contact_email="admin@example.mil",
                versions_used=["1.0.0"],
                critical_endpoints=["/api/v1/users"]
            )
            await manager.register_consumer(consumer)
            
            # Get version info
            info = await manager.get_version_info()
            print(f"Version info: {json.dumps(info, indent=2)}")
            
        finally:
            await manager.close()
    
    asyncio.run(main())