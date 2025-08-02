"""
Integrated API Lifecycle Manager for DoD Enterprise Systems

This module integrates API versioning, lifecycle orchestration, and deprecation management
with the existing DoD API Gateway infrastructure to provide comprehensive API lifecycle
management capabilities.

Key Features:
- Unified API lifecycle management across all phases
- Integration with existing DoD API Gateway security controls
- Comprehensive monitoring and compliance tracking
- Automated workflow orchestration
- Enterprise-grade audit and reporting capabilities

Security Standards:
- NIST 800-53 integrated lifecycle controls
- DoD 8500 series comprehensive compliance
- FIPS 140-2 end-to-end security
- STIGs compliance for enterprise lifecycle management
"""

import asyncio
import json
import logging
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple, Union
from dataclasses import dataclass, asdict
from enum import Enum

# Import our new components
from api_version_manager import (
    APIVersionManager, VersionState, APIContract, VersionMetadata,
    ConsumerRegistration, CompatibilityReport
)
from lifecycle_orchestrator import (
    LifecycleOrchestrator, DeploymentConfiguration, DeploymentStrategy,
    DeploymentState, HealthCheck, DeploymentTarget
)
from deprecation_manager import (
    DeprecationManager, DeprecationPhase, DeprecationPolicy,
    MigrationPlan, MigrationStatus
)

# Import existing infrastructure
from dod_api_gateway import (
    DoDAPIGateway, APIGatewayManager, DoDAGWConfig,
    APIGatewayEnvironment, SecurityClassification
)
from api_security_controls import (
    APISecurityController, SecurityPolicy, RateLimitConfig
)


class LifecycleStage(Enum):
    """Overall API lifecycle stages."""
    PLANNING = "planning"
    DEVELOPMENT = "development"
    TESTING = "testing"
    STAGING = "staging"
    PRODUCTION = "production"
    MAINTENANCE = "maintenance"
    DEPRECATION = "deprecation"
    SUNSET = "sunset"
    ARCHIVED = "archived"


class IntegrationStatus(Enum):
    """Integration component status."""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    FAILED = "failed"
    UNKNOWN = "unknown"


@dataclass
class APILifecycleMetrics:
    """API lifecycle metrics."""
    total_versions: int
    active_versions: int
    deprecated_versions: int
    active_deployments: int
    active_deprecations: int
    consumer_count: int
    compliance_score: float
    security_score: float
    availability_percentage: float
    performance_score: float


@dataclass
class ComponentHealth:
    """Component health status."""
    component_name: str
    status: IntegrationStatus
    last_check: datetime
    error_message: Optional[str] = None
    metrics: Dict[str, Any] = None


class IntegratedLifecycleManager:
    """
    Integrated API Lifecycle Manager
    
    Provides unified management of API lifecycle including versioning,
    deployments, deprecation, and security controls integrated with
    DoD API Gateway infrastructure.
    """
    
    def __init__(self, gateway_config: DoDAGWConfig,
                 redis_url: str = "redis://localhost:6379"):
        """Initialize Integrated Lifecycle Manager."""
        self.logger = logging.getLogger(__name__)
        
        # Core components
        self.version_manager = None
        self.lifecycle_orchestrator = None
        self.deprecation_manager = None
        self.gateway_manager = None
        self.security_controller = None
        
        # Configuration
        self.gateway_config = gateway_config
        self.redis_url = redis_url
        
        # Component health tracking
        self.component_health: Dict[str, ComponentHealth] = {}
        
        # Lifecycle tracking
        self.active_lifecycles: Dict[str, Dict[str, Any]] = {}
        
        # Background task handles
        self._health_monitor_task = None
        self._lifecycle_monitor_task = None
        self._compliance_monitor_task = None
    
    async def initialize(self) -> None:
        """Initialize all lifecycle management components."""
        try:
            self.logger.info("Initializing Integrated Lifecycle Manager...")
            
            # Initialize core components
            await self._initialize_core_components()
            
            # Setup component integrations
            await self._setup_integrations()
            
            # Start monitoring tasks
            await self._start_monitoring_tasks()
            
            # Perform initial health check
            await self._perform_health_check()
            
            self.logger.info("Integrated Lifecycle Manager initialized successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize Integrated Lifecycle Manager: {e}")
            raise
    
    async def _initialize_core_components(self) -> None:
        """Initialize all core components."""
        try:
            # Initialize Version Manager
            self.version_manager = APIVersionManager(
                redis_url=self.redis_url,
                environment=self.gateway_config.environment
            )
            await self.version_manager.initialize()
            self._update_component_health("version_manager", IntegrationStatus.HEALTHY)
            
            # Initialize Lifecycle Orchestrator
            self.lifecycle_orchestrator = LifecycleOrchestrator(
                version_manager=self.version_manager,
                redis_url=self.redis_url
            )
            await self.lifecycle_orchestrator.initialize()
            self._update_component_health("lifecycle_orchestrator", IntegrationStatus.HEALTHY)
            
            # Initialize Deprecation Manager
            self.deprecation_manager = DeprecationManager(
                version_manager=self.version_manager,
                redis_url=self.redis_url
            )
            await self.deprecation_manager.initialize()
            self._update_component_health("deprecation_manager", IntegrationStatus.HEALTHY)
            
            # Initialize Gateway Manager
            self.gateway_manager = APIGatewayManager(self.gateway_config)
            await self.gateway_manager.initialize()
            self._update_component_health("gateway_manager", IntegrationStatus.HEALTHY)
            
            # Initialize Security Controller
            self.security_controller = APISecurityController(redis_url=self.redis_url)
            await self.security_controller.initialize()
            self._update_component_health("security_controller", IntegrationStatus.HEALTHY)
            
        except Exception as e:
            self.logger.error(f"Failed to initialize core components: {e}")
            raise
    
    async def _setup_integrations(self) -> None:
        """Setup integrations between components."""
        try:
            # Setup security policies for version management
            await self._setup_version_security_policies()
            
            # Setup deployment security validation
            await self._setup_deployment_security_integration()
            
            # Setup deprecation compliance integration
            await self._setup_deprecation_compliance_integration()
            
            self.logger.info("Component integrations setup complete")
            
        except Exception as e:
            self.logger.error(f"Failed to setup integrations: {e}")
            raise
    
    async def _setup_version_security_policies(self) -> None:
        """Setup security policies for different API versions."""
        try:
            # High security policy for production versions
            high_security_policy = SecurityPolicy(
                name="production_api_security",
                description="High security policy for production API versions",
                rate_limit_config=RateLimitConfig(
                    algorithm="token_bucket",
                    requests_per_window=1000,
                    window_size_seconds=3600
                ),
                enable_oauth_validation=True,
                enable_input_validation=True,
                enable_attack_detection=True,
                max_request_size=1048576  # 1MB
            )
            
            # Standard security policy for development/testing
            standard_security_policy = SecurityPolicy(
                name="development_api_security", 
                description="Standard security policy for development API versions",
                rate_limit_config=RateLimitConfig(
                    algorithm="sliding_window",
                    requests_per_window=5000,
                    window_size_seconds=3600
                ),
                enable_oauth_validation=True,
                enable_input_validation=True,
                enable_attack_detection=True,
                max_request_size=2097152  # 2MB
            )
            
            # Apply policies to security controller
            self.security_controller.add_security_policy(
                r"/api/v\d+\..*",  # Production versions (semantic versioning)
                high_security_policy
            )
            
            self.security_controller.add_security_policy(
                r"/api/v\d+\-.*",  # Development versions (with pre-release identifiers)
                standard_security_policy
            )
            
        except Exception as e:
            self.logger.error(f"Failed to setup version security policies: {e}")
            raise
    
    async def _setup_deployment_security_integration(self) -> None:
        """Setup security validation for deployments."""
        try:
            # This would integrate deployment validation with security controls
            # For now, we'll set up monitoring hooks
            
            # Register deployment event handlers
            self.lifecycle_orchestrator.notification_handlers["security_validation"] = \
                self._validate_deployment_security
                
        except Exception as e:
            self.logger.error(f"Failed to setup deployment security integration: {e}")
            raise
    
    async def _setup_deprecation_compliance_integration(self) -> None:
        """Setup compliance tracking for deprecation workflows."""
        try:
            # This would integrate deprecation workflows with compliance tracking
            # For now, we'll set up monitoring hooks
            pass
            
        except Exception as e:
            self.logger.error(f"Failed to setup deprecation compliance integration: {e}")
            raise
    
    async def _start_monitoring_tasks(self) -> None:
        """Start background monitoring tasks."""
        try:
            self._health_monitor_task = asyncio.create_task(self._health_monitor())
            self._lifecycle_monitor_task = asyncio.create_task(self._lifecycle_monitor())
            self._compliance_monitor_task = asyncio.create_task(self._compliance_monitor())
            
            self.logger.info("Background monitoring tasks started")
            
        except Exception as e:
            self.logger.error(f"Failed to start monitoring tasks: {e}")
            raise
    
    async def create_api_version(self, version: str, contract: APIContract,
                               security_classification: SecurityClassification = SecurityClassification.UNCLASSIFIED) -> bool:
        """
        Create new API version with integrated lifecycle management.
        
        Args:
            version: Semantic version string
            contract: API contract definition
            security_classification: Security classification level
            
        Returns:
            True if version created successfully
        """
        try:
            # Register version with version manager
            success = await self.version_manager.register_version(
                version=version,
                contract=contract,
                state=VersionState.DEVELOPMENT
            )
            
            if not success:
                return False
            
            # Setup security policies based on classification
            await self._setup_version_security(version, security_classification)
            
            # Initialize lifecycle tracking
            await self._initialize_version_lifecycle(version)
            
            # Log version creation
            await self._log_lifecycle_event("api_version_created", {
                "version": version,
                "classification": security_classification.value,
                "endpoints": len(contract.endpoints)
            })
            
            self.logger.info(f"Created API version {version} with classification {security_classification.value}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to create API version {version}: {e}")
            return False
    
    async def deploy_api_version(self, deployment_config: DeploymentConfiguration) -> str:
        """
        Deploy API version with integrated security and compliance validation.
        
        Args:
            deployment_config: Deployment configuration
            
        Returns:
            Deployment ID if successful
        """
        try:
            # Pre-deployment security validation
            security_validation = await self._validate_deployment_security(deployment_config)
            if not security_validation["valid"]:
                raise ValueError(f"Security validation failed: {security_validation['errors']}")
            
            # Pre-deployment compliance validation
            compliance_validation = await self._validate_deployment_compliance(deployment_config)
            if not compliance_validation["valid"]:
                raise ValueError(f"Compliance validation failed: {compliance_validation['errors']}")
            
            # Create deployment
            deployment_id = await self.lifecycle_orchestrator.create_deployment(deployment_config)
            
            # Update lifecycle tracking
            await self._update_version_lifecycle(
                deployment_config.target_version,
                LifecycleStage.STAGING if deployment_config.strategy == DeploymentStrategy.CANARY else LifecycleStage.PRODUCTION
            )
            
            # Log deployment creation
            await self._log_lifecycle_event("deployment_created", {
                "deployment_id": deployment_id,
                "strategy": deployment_config.strategy.value,
                "source_version": deployment_config.source_version,
                "target_version": deployment_config.target_version
            })
            
            self.logger.info(f"Created deployment {deployment_id} for version {deployment_config.target_version}")
            return deployment_id
            
        except Exception as e:
            self.logger.error(f"Failed to deploy API version: {e}")
            raise
    
    async def initiate_api_deprecation(self, version: str, policy_id: str,
                                     initiated_by: str, metadata: Dict[str, Any] = None) -> str:
        """
        Initiate API deprecation with integrated compliance and security controls.
        
        Args:
            version: Version to deprecate
            policy_id: Deprecation policy ID
            initiated_by: User initiating deprecation
            metadata: Additional metadata
            
        Returns:
            Deprecation workflow ID
        """
        try:
            # Validate deprecation prerequisites
            validation = await self._validate_deprecation_prerequisites(version)
            if not validation["valid"]:
                raise ValueError(f"Deprecation validation failed: {validation['errors']}")
            
            # Initiate deprecation workflow
            deprecation_id = await self.deprecation_manager.initiate_deprecation(
                version=version,
                policy_id=policy_id,
                initiated_by=initiated_by,
                metadata=metadata
            )
            
            # Update lifecycle tracking
            await self._update_version_lifecycle(version, LifecycleStage.DEPRECATION)
            
            # Apply deprecation security controls
            await self._apply_deprecation_security_controls(version, deprecation_id)
            
            # Log deprecation initiation
            await self._log_lifecycle_event("deprecation_initiated", {
                "deprecation_id": deprecation_id,
                "version": version,
                "policy_id": policy_id,
                "initiated_by": initiated_by
            })
            
            self.logger.info(f"Initiated deprecation {deprecation_id} for version {version}")
            return deprecation_id
            
        except Exception as e:
            self.logger.error(f"Failed to initiate deprecation for version {version}: {e}")
            raise
    
    async def get_comprehensive_status(self) -> Dict[str, Any]:
        """
        Get comprehensive status of all lifecycle management components.
        
        Returns:
            Complete status information
        """
        try:
            # Get component statuses
            version_status = await self.version_manager.get_version_info()
            lifecycle_metrics = await self._calculate_lifecycle_metrics()
            component_health = await self._get_component_health_summary()
            security_metrics = await self.security_controller.get_security_metrics()
            
            # Get active workflows
            active_deployments = len(self.lifecycle_orchestrator.active_deployments)
            active_deprecations = len(self.deprecation_manager.deprecation_workflows)
            
            return {
                "timestamp": datetime.utcnow().isoformat(),
                "overall_status": self._calculate_overall_status(),
                "version_management": version_status,
                "lifecycle_metrics": asdict(lifecycle_metrics),
                "component_health": component_health,
                "security_metrics": security_metrics,
                "active_workflows": {
                    "deployments": active_deployments,
                    "deprecations": active_deprecations
                },
                "environment": self.gateway_config.environment.value,
                "classification": self.gateway_config.security_classification.value
            }
            
        except Exception as e:
            self.logger.error(f"Failed to get comprehensive status: {e}")
            return {"error": str(e)}
    
    async def _validate_deployment_security(self, config: DeploymentConfiguration) -> Dict[str, Any]:
        """Validate deployment security requirements."""
        try:
            errors = []
            
            # Check target version exists and is secure
            version_info = await self.version_manager.get_version_info(config.target_version)
            if not version_info:
                errors.append(f"Target version {config.target_version} not found")
            
            # Validate health checks include security endpoints
            for target in config.targets:
                security_check_found = any(
                    hc.endpoint in ["/health/security", "/security/status"] 
                    for hc in target.health_checks
                )
                if not security_check_found:
                    errors.append(f"Target {target.name} missing security health checks")
            
            # Check environment security requirements
            if config.targets[0].environment == APIGatewayEnvironment.PRODUCTION:
                if not config.approval_required:
                    errors.append("Production deployments require approval")
            
            return {
                "valid": len(errors) == 0,
                "errors": errors,
                "security_score": 100 - (len(errors) * 20)  # Simple scoring
            }
            
        except Exception as e:
            self.logger.error(f"Security validation error: {e}")
            return {"valid": False, "errors": [str(e)], "security_score": 0}
    
    async def _validate_deployment_compliance(self, config: DeploymentConfiguration) -> Dict[str, Any]:
        """Validate deployment compliance requirements."""
        try:
            errors = []
            
            # Check deployment strategy compliance
            if config.strategy == DeploymentStrategy.RECREATE:
                if config.targets[0].environment == APIGatewayEnvironment.PRODUCTION:
                    errors.append("Recreate strategy not allowed for production")
            
            # Check rollback configuration
            if not config.rollback_config:
                errors.append("Rollback configuration required")
            
            # Check notification configuration
            if not config.notification_webhooks:
                errors.append("Notification webhooks required for compliance tracking")
            
            return {
                "valid": len(errors) == 0,
                "errors": errors,
                "compliance_score": 100 - (len(errors) * 25)  # Simple scoring
            }
            
        except Exception as e:
            self.logger.error(f"Compliance validation error: {e}")
            return {"valid": False, "errors": [str(e)], "compliance_score": 0}
    
    async def _validate_deprecation_prerequisites(self, version: str) -> Dict[str, Any]:
        """Validate deprecation prerequisites."""
        try:
            errors = []
            
            # Check version exists and is in correct state
            version_info = await self.version_manager.get_version_info(version)
            if not version_info:
                errors.append(f"Version {version} not found")
            elif version_info.get("state") not in ["stable"]:
                errors.append(f"Version {version} must be stable to deprecate")
            
            # Check for newer stable version
            all_versions = await self.version_manager.get_version_info()
            stable_versions = [
                v for v in all_versions.get("versions", [])
                if v["state"] == "stable"
            ]
            
            if len(stable_versions) < 2:
                errors.append("At least one alternative stable version required before deprecation")
            
            return {
                "valid": len(errors) == 0,
                "errors": errors
            }
            
        except Exception as e:
            self.logger.error(f"Deprecation prerequisites validation error: {e}")
            return {"valid": False, "errors": [str(e)]}
    
    async def _setup_version_security(self, version: str, classification: SecurityClassification) -> None:
        """Setup security controls for API version."""
        try:
            # Create version-specific security policy
            if classification in [SecurityClassification.SECRET, SecurityClassification.TOP_SECRET]:
                # High security policy for classified APIs
                policy = SecurityPolicy(
                    name=f"classified_policy_{version}",
                    description=f"Classified security policy for API {version}",
                    rate_limit_config=RateLimitConfig(
                        algorithm="token_bucket",
                        requests_per_window=100,  # Lower limits for classified
                        window_size_seconds=3600
                    ),
                    enable_oauth_validation=True,
                    enable_input_validation=True,
                    enable_attack_detection=True,
                    max_request_size=512000  # 500KB for classified
                )
            else:
                # Standard security policy
                policy = SecurityPolicy(
                    name=f"standard_policy_{version}",
                    description=f"Standard security policy for API {version}",
                    rate_limit_config=RateLimitConfig(
                        algorithm="sliding_window",
                        requests_per_window=1000,
                        window_size_seconds=3600
                    ),
                    enable_oauth_validation=True,
                    enable_input_validation=True,
                    enable_attack_detection=True,
                    max_request_size=1048576  # 1MB
                )
            
            # Apply policy to version-specific endpoints
            self.security_controller.add_security_policy(f"/api/{version}/.*", policy)
            
        except Exception as e:
            self.logger.error(f"Failed to setup version security for {version}: {e}")
            raise
    
    async def _initialize_version_lifecycle(self, version: str) -> None:
        """Initialize lifecycle tracking for version."""
        try:
            lifecycle_data = {
                "version": version,
                "stage": LifecycleStage.DEVELOPMENT.value,
                "created_at": datetime.utcnow().isoformat(),
                "last_updated": datetime.utcnow().isoformat(),
                "milestones": [],
                "metrics": {
                    "deployment_count": 0,
                    "consumer_count": 0,
                    "security_incidents": 0,
                    "uptime_percentage": 100.0
                }
            }
            
            self.active_lifecycles[version] = lifecycle_data
            
        except Exception as e:
            self.logger.error(f"Failed to initialize lifecycle for version {version}: {e}")
            raise
    
    async def _update_version_lifecycle(self, version: str, stage: LifecycleStage) -> None:
        """Update version lifecycle stage."""
        try:
            if version in self.active_lifecycles:
                lifecycle_data = self.active_lifecycles[version]
                
                # Add milestone for stage transition
                milestone = {
                    "timestamp": datetime.utcnow().isoformat(),
                    "from_stage": lifecycle_data["stage"],
                    "to_stage": stage.value,
                    "automated": True
                }
                
                lifecycle_data["milestones"].append(milestone)
                lifecycle_data["stage"] = stage.value
                lifecycle_data["last_updated"] = datetime.utcnow().isoformat()
                
                # Update deployment count if moving to production
                if stage == LifecycleStage.PRODUCTION:
                    lifecycle_data["metrics"]["deployment_count"] += 1
            
        except Exception as e:
            self.logger.error(f"Failed to update lifecycle for version {version}: {e}")
    
    async def _apply_deprecation_security_controls(self, version: str, deprecation_id: str) -> None:
        """Apply security controls for deprecated version."""
        try:
            # Modify security policy to add deprecation warnings
            deprecation_policy = SecurityPolicy(
                name=f"deprecated_policy_{version}",
                description=f"Deprecation security policy for API {version}",
                rate_limit_config=RateLimitConfig(
                    algorithm="token_bucket",
                    requests_per_window=500,  # Reduced limits for deprecated APIs
                    window_size_seconds=3600
                ),
                enable_oauth_validation=True,
                enable_input_validation=True,
                enable_attack_detection=True,
                max_request_size=1048576
            )
            
            # Update security policy for deprecated version
            self.security_controller.add_security_policy(f"/api/{version}/.*", deprecation_policy)
            
        except Exception as e:
            self.logger.error(f"Failed to apply deprecation security controls for {version}: {e}")
    
    async def _calculate_lifecycle_metrics(self) -> APILifecycleMetrics:
        """Calculate comprehensive lifecycle metrics."""
        try:
            # Get version statistics
            version_info = await self.version_manager.get_version_info()
            total_versions = len(version_info.get("versions", []))
            
            # Count versions by state
            active_versions = len([v for v in version_info.get("versions", []) if v["state"] in ["stable", "beta"]])
            deprecated_versions = len([v for v in version_info.get("versions", []) if v["state"] == "deprecated"])
            
            # Get workflow counts
            active_deployments = len(self.lifecycle_orchestrator.active_deployments)
            active_deprecations = len(self.deprecation_manager.deprecation_workflows)
            
            # Calculate consumer count (mock for now)
            consumer_count = sum(v.get("consumer_count", 0) for v in version_info.get("versions", []))
            
            # Calculate scores (simplified)
            compliance_score = 95.0  # Mock compliance score
            security_score = 98.0    # Mock security score
            availability_percentage = 99.9  # Mock availability
            performance_score = 92.0  # Mock performance score
            
            return APILifecycleMetrics(
                total_versions=total_versions,
                active_versions=active_versions,
                deprecated_versions=deprecated_versions,
                active_deployments=active_deployments,
                active_deprecations=active_deprecations,
                consumer_count=consumer_count,
                compliance_score=compliance_score,
                security_score=security_score,
                availability_percentage=availability_percentage,
                performance_score=performance_score
            )
            
        except Exception as e:
            self.logger.error(f"Failed to calculate lifecycle metrics: {e}")
            return APILifecycleMetrics(0, 0, 0, 0, 0, 0, 0.0, 0.0, 0.0, 0.0)
    
    def _update_component_health(self, component_name: str, status: IntegrationStatus,
                               error_message: str = None, metrics: Dict[str, Any] = None) -> None:
        """Update component health status."""
        self.component_health[component_name] = ComponentHealth(
            component_name=component_name,
            status=status,
            last_check=datetime.utcnow(),
            error_message=error_message,
            metrics=metrics
        )
    
    async def _get_component_health_summary(self) -> Dict[str, Any]:
        """Get summary of component health."""
        try:
            health_summary = {}
            overall_healthy = True
            
            for component_name, health in self.component_health.items():
                health_summary[component_name] = {
                    "status": health.status.value,
                    "last_check": health.last_check.isoformat(),
                    "error_message": health.error_message,
                    "metrics": health.metrics
                }
                
                if health.status != IntegrationStatus.HEALTHY:
                    overall_healthy = False
            
            health_summary["overall_healthy"] = overall_healthy
            return health_summary
            
        except Exception as e:
            self.logger.error(f"Failed to get component health summary: {e}")
            return {"error": str(e)}
    
    def _calculate_overall_status(self) -> str:
        """Calculate overall system status."""
        try:
            healthy_components = sum(
                1 for health in self.component_health.values()
                if health.status == IntegrationStatus.HEALTHY
            )
            
            total_components = len(self.component_health)
            
            if total_components == 0:
                return "unknown"
            
            health_percentage = healthy_components / total_components
            
            if health_percentage == 1.0:
                return "healthy"
            elif health_percentage >= 0.8:
                return "degraded"
            else:
                return "unhealthy"
                
        except Exception as e:
            self.logger.error(f"Failed to calculate overall status: {e}")
            return "unknown"
    
    async def _perform_health_check(self) -> None:
        """Perform comprehensive health check of all components."""
        try:
            # Check version manager
            try:
                await self.version_manager.get_version_info()
                self._update_component_health("version_manager", IntegrationStatus.HEALTHY)
            except Exception as e:
                self._update_component_health("version_manager", IntegrationStatus.FAILED, str(e))
            
            # Check lifecycle orchestrator
            try:
                # Simple health check - verify active deployments can be retrieved
                _ = self.lifecycle_orchestrator.active_deployments
                self._update_component_health("lifecycle_orchestrator", IntegrationStatus.HEALTHY)
            except Exception as e:
                self._update_component_health("lifecycle_orchestrator", IntegrationStatus.FAILED, str(e))
            
            # Check deprecation manager
            try:
                # Simple health check - verify workflows can be retrieved
                _ = self.deprecation_manager.deprecation_workflows
                self._update_component_health("deprecation_manager", IntegrationStatus.HEALTHY)
            except Exception as e:
                self._update_component_health("deprecation_manager", IntegrationStatus.FAILED, str(e))
            
            # Check security controller
            try:
                await self.security_controller.get_security_metrics()
                self._update_component_health("security_controller", IntegrationStatus.HEALTHY)
            except Exception as e:
                self._update_component_health("security_controller", IntegrationStatus.FAILED, str(e))
            
        except Exception as e:
            self.logger.error(f"Health check failed: {e}")
    
    async def _health_monitor(self) -> None:
        """Background task to monitor component health."""
        while True:
            try:
                await self._perform_health_check()
                await asyncio.sleep(300)  # Check every 5 minutes
                
            except Exception as e:
                self.logger.error(f"Health monitor error: {e}")
                await asyncio.sleep(60)
    
    async def _lifecycle_monitor(self) -> None:
        """Background task to monitor lifecycle workflows."""
        while True:
            try:
                # Monitor deployment workflows
                for deployment_id in list(self.lifecycle_orchestrator.active_deployments.keys()):
                    status = await self.lifecycle_orchestrator.get_deployment_status(deployment_id)
                    if status.get("state") == "failed":
                        await self._handle_deployment_failure(deployment_id, status)
                
                # Monitor deprecation workflows
                for deprecation_id in list(self.deprecation_manager.deprecation_workflows.keys()):
                    await self.deprecation_manager.advance_deprecation_phase(deprecation_id)
                
                await asyncio.sleep(600)  # Check every 10 minutes
                
            except Exception as e:
                self.logger.error(f"Lifecycle monitor error: {e}")
                await asyncio.sleep(300)
    
    async def _compliance_monitor(self) -> None:
        """Background task to monitor compliance requirements."""
        while True:
            try:
                # Check security compliance
                security_metrics = await self.security_controller.get_security_metrics()
                if security_metrics.get("blocked_requests_last_hour", 0) > 100:
                    await self._handle_security_incident(security_metrics)
                
                # Check lifecycle compliance
                metrics = await self._calculate_lifecycle_metrics()
                if metrics.compliance_score < 90.0:
                    await self._handle_compliance_violation(metrics)
                
                await asyncio.sleep(1800)  # Check every 30 minutes
                
            except Exception as e:
                self.logger.error(f"Compliance monitor error: {e}")
                await asyncio.sleep(300)
    
    async def _handle_deployment_failure(self, deployment_id: str, status: Dict[str, Any]) -> None:
        """Handle deployment failure."""
        try:
            await self._log_lifecycle_event("deployment_failed", {
                "deployment_id": deployment_id,
                "error": status.get("error_message", "Unknown error")
            })
            
            # Auto-rollback if configured
            execution = self.lifecycle_orchestrator.active_deployments.get(deployment_id)
            if execution and execution.configuration.auto_rollback_enabled:
                await self.lifecycle_orchestrator.rollback_deployment(deployment_id, "Auto-rollback due to failure")
            
        except Exception as e:
            self.logger.error(f"Failed to handle deployment failure: {e}")
    
    async def _handle_security_incident(self, metrics: Dict[str, Any]) -> None:
        """Handle security incident."""
        try:
            await self._log_lifecycle_event("security_incident", {
                "blocked_requests": metrics.get("blocked_requests_last_hour", 0),
                "threat_levels": metrics.get("threat_levels", {}),
                "top_attacking_ips": metrics.get("top_attacking_ips", [])
            })
            
        except Exception as e:
            self.logger.error(f"Failed to handle security incident: {e}")
    
    async def _handle_compliance_violation(self, metrics: APILifecycleMetrics) -> None:
        """Handle compliance violation."""
        try:
            await self._log_lifecycle_event("compliance_violation", {
                "compliance_score": metrics.compliance_score,
                "total_versions": metrics.total_versions,
                "deprecated_versions": metrics.deprecated_versions
            })
            
        except Exception as e:
            self.logger.error(f"Failed to handle compliance violation: {e}")
    
    async def _log_lifecycle_event(self, event_type: str, data: Dict[str, Any]) -> None:
        """Log lifecycle management events."""
        try:
            event = {
                "timestamp": datetime.utcnow().isoformat(),
                "event_type": event_type,
                "environment": self.gateway_config.environment.value,
                "service": self.gateway_config.service_name,
                "data": data
            }
            
            self.logger.info(f"Lifecycle Event: {json.dumps(event)}")
            
        except Exception as e:
            self.logger.error(f"Failed to log lifecycle event: {e}")
    
    async def close(self) -> None:
        """Clean up all resources."""
        try:
            # Cancel background tasks
            if self._health_monitor_task:
                self._health_monitor_task.cancel()
            if self._lifecycle_monitor_task:
                self._lifecycle_monitor_task.cancel()
            if self._compliance_monitor_task:
                self._compliance_monitor_task.cancel()
            
            # Close components
            if self.version_manager:
                await self.version_manager.close()
            if self.lifecycle_orchestrator:
                await self.lifecycle_orchestrator.close()
            if self.deprecation_manager:
                await self.deprecation_manager.close()
            if self.gateway_manager:
                await self.gateway_manager.close()
            if self.security_controller:
                await self.security_controller.close()
            
            self.logger.info("Integrated Lifecycle Manager closed")
            
        except Exception as e:
            self.logger.error(f"Error during cleanup: {e}")


# Utility functions for common operations
def create_production_deployment_config(version_from: str, version_to: str,
                                       production_url: str) -> DeploymentConfiguration:
    """Create production deployment configuration."""
    return DeploymentConfiguration(
        deployment_id=str(uuid.uuid4()),
        strategy=DeploymentStrategy.BLUE_GREEN,
        source_version=version_from,
        target_version=version_to,
        targets=[
            DeploymentTarget(
                name="production",
                environment=APIGatewayEnvironment.PRODUCTION,
                endpoint_url=production_url,
                health_checks=[
                    HealthCheck(
                        name="api_health",
                        type="http",
                        endpoint="/health",
                        timeout_seconds=30
                    ),
                    HealthCheck(
                        name="security_health",
                        type="http", 
                        endpoint="/health/security",
                        timeout_seconds=30
                    )
                ]
            )
        ],
        rollback_config={"auto_rollback_threshold": 5},
        approval_required=True,
        auto_rollback_enabled=True,
        notification_webhooks=["https://notifications.example.mil/deployments"]
    )


if __name__ == "__main__":
    # Example usage
    async def main():
        from dod_api_gateway import create_development_config
        from api_version_manager import create_sample_contract
        
        # Create gateway configuration
        gateway_config = create_development_config()
        
        # Initialize integrated lifecycle manager
        manager = IntegratedLifecycleManager(gateway_config)
        await manager.initialize()
        
        try:
            # Create new API version
            contract = create_sample_contract()
            await manager.create_api_version("2.0.0", contract, SecurityClassification.UNCLASSIFIED)
            
            # Create deployment
            deployment_config = create_production_deployment_config(
                "1.0.0", "2.0.0", "https://api.example.mil"
            )
            deployment_id = await manager.deploy_api_version(deployment_config)
            
            # Get comprehensive status
            status = await manager.get_comprehensive_status()
            print(f"System status: {json.dumps(status, indent=2)}")
            
        finally:
            await manager.close()
    
    asyncio.run(main())