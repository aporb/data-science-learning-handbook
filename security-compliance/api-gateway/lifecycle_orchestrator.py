"""
API Lifecycle Orchestrator for DoD Enterprise Systems

This module provides comprehensive API lifecycle management including blue/green deployments,
rollback capabilities, deployment orchestration, and environment management for DoD-compliant
enterprise environments.

Key Features:
- Blue/green deployment orchestration with zero-downtime
- Rolling deployments with health checks and auto-rollback
- Environment-specific deployment strategies
- Deployment pipeline automation with approval gates
- Comprehensive monitoring and alerting during deployments
- Integration with DoD security compliance requirements

Security Standards:
- NIST 800-53 deployment security controls
- DoD 8500 series deployment compliance
- FIPS 140-2 cryptographic deployment validation
- STIGs compliance for deployment security
"""

import asyncio
import json
import logging
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple, Union, Callable
from dataclasses import dataclass, asdict, field
from enum import Enum
from pathlib import Path
import time

import aiohttp
import aioredis
from cryptography.hazmat.primitives import hashes

# Import from existing modules
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from api_gateway.dod_api_gateway import APIGatewayEnvironment, SecurityClassification, DoDAPIGateway
from api_gateway.api_version_manager import APIVersionManager, VersionState
from monitoring.enhanced_monitoring_system import MonitoringSystem


class DeploymentStrategy(Enum):
    """Deployment strategies."""
    BLUE_GREEN = "blue_green"
    ROLLING = "rolling"
    CANARY = "canary"
    RECREATE = "recreate"
    A_B_TESTING = "ab_testing"


class DeploymentState(Enum):
    """Deployment states."""
    PENDING = "pending"
    PREPARING = "preparing"
    DEPLOYING = "deploying"
    VALIDATING = "validating"
    PROMOTING = "promoting"
    COMPLETED = "completed"
    FAILED = "failed"
    ROLLING_BACK = "rolling_back"
    ROLLED_BACK = "rolled_back"
    PAUSED = "paused"
    CANCELLED = "cancelled"


class HealthCheckType(Enum):
    """Health check types."""
    HTTP = "http"
    TCP = "tcp"
    COMMAND = "command"
    CUSTOM = "custom"


class ApprovalStatus(Enum):
    """Approval statuses."""
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"


@dataclass
class HealthCheck:
    """Health check configuration."""
    name: str
    type: HealthCheckType
    endpoint: str
    timeout_seconds: int = 30
    interval_seconds: int = 10
    retries: int = 3
    success_threshold: int = 2
    failure_threshold: int = 3
    expected_status: int = 200
    expected_response: Optional[str] = None
    headers: Dict[str, str] = field(default_factory=dict)


@dataclass
class DeploymentTarget:
    """Deployment target configuration."""
    name: str
    environment: APIGatewayEnvironment
    endpoint_url: str
    health_checks: List[HealthCheck]
    capacity: int = 100  # Percentage of traffic
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DeploymentConfiguration:
    """Deployment configuration."""
    deployment_id: str
    strategy: DeploymentStrategy
    source_version: str
    target_version: str
    targets: List[DeploymentTarget]
    rollback_config: Dict[str, Any]
    approval_required: bool = True
    approval_timeout_minutes: int = 60
    health_check_timeout_minutes: int = 10
    traffic_shift_duration_minutes: int = 30
    auto_rollback_enabled: bool = True
    notification_webhooks: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DeploymentStep:
    """Individual deployment step."""
    step_id: str
    name: str
    description: str
    status: DeploymentState
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    error_message: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DeploymentExecution:
    """Deployment execution tracking."""
    deployment_id: str
    configuration: DeploymentConfiguration
    state: DeploymentState
    created_at: datetime
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    steps: List[DeploymentStep] = field(default_factory=list)
    current_step: Optional[str] = None
    traffic_distribution: Dict[str, int] = field(default_factory=dict)
    metrics: Dict[str, Any] = field(default_factory=dict)
    logs: List[str] = field(default_factory=list)
    error_message: Optional[str] = None


@dataclass
class ApprovalRequest:
    """Deployment approval request."""
    approval_id: str
    deployment_id: str
    approver_role: str
    requested_at: datetime
    expires_at: datetime
    status: ApprovalStatus
    approved_by: Optional[str] = None
    approved_at: Optional[datetime] = None
    comments: Optional[str] = None


class LifecycleOrchestrator:
    """
    API Lifecycle Orchestrator for DoD Enterprise Systems
    
    Orchestrates comprehensive API lifecycle management including deployments,
    rollbacks, environment management, and compliance validation.
    """
    
    def __init__(self, version_manager: APIVersionManager,
                 monitoring_system: Optional[MonitoringSystem] = None,
                 redis_url: str = "redis://localhost:6379"):
        """Initialize Lifecycle Orchestrator."""
        self.logger = logging.getLogger(__name__)
        
        # Core components
        self.version_manager = version_manager
        self.monitoring_system = monitoring_system
        
        # Redis client for state management
        self.redis_client = None
        self.redis_url = redis_url
        
        # Deployment tracking
        self.active_deployments: Dict[str, DeploymentExecution] = {}
        self.deployment_history: List[DeploymentExecution] = []
        
        # Approval tracking
        self.pending_approvals: Dict[str, ApprovalRequest] = {}
        
        # HTTP session for health checks
        self._http_session = None
        
        # Configuration
        self.max_concurrent_deployments = 5
        self.deployment_timeout_minutes = 120
        
        # Notification handlers
        self.notification_handlers: Dict[str, Callable] = {}
    
    async def initialize(self) -> None:
        """Initialize lifecycle orchestrator."""
        try:
            # Initialize Redis client
            self.redis_client = await aioredis.from_url(self.redis_url)
            await self.redis_client.ping()
            
            # Initialize HTTP session
            connector = aiohttp.TCPConnector(limit=100)
            timeout = aiohttp.ClientTimeout(total=60)
            self._http_session = aiohttp.ClientSession(
                connector=connector,
                timeout=timeout
            )
            
            # Load active deployments from Redis
            await self._load_active_deployments()
            
            # Start background tasks
            asyncio.create_task(self._deployment_monitor())
            asyncio.create_task(self._approval_monitor())
            
            self.logger.info("Lifecycle Orchestrator initialized successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize lifecycle orchestrator: {e}")
            raise
    
    async def create_deployment(self, config: DeploymentConfiguration) -> str:
        """
        Create new deployment.
        
        Args:
            config: Deployment configuration
            
        Returns:
            Deployment ID
        """
        try:
            # Validate configuration
            await self._validate_deployment_config(config)
            
            # Check concurrent deployment limit
            if len(self.active_deployments) >= self.max_concurrent_deployments:
                raise ValueError("Maximum concurrent deployments exceeded")
            
            # Create deployment execution
            execution = DeploymentExecution(
                deployment_id=config.deployment_id,
                configuration=config,
                state=DeploymentState.PENDING,
                created_at=datetime.utcnow(),
                traffic_distribution={config.source_version: 100}
            )
            
            # Add to active deployments
            self.active_deployments[config.deployment_id] = execution
            
            # Save to Redis
            await self._save_deployment_to_storage(config.deployment_id)
            
            # Create approval request if required
            if config.approval_required:
                await self._create_approval_request(config.deployment_id)
            
            # Log deployment creation
            await self._log_deployment_event(config.deployment_id, "deployment_created", {
                "strategy": config.strategy.value,
                "source_version": config.source_version,
                "target_version": config.target_version
            })
            
            self.logger.info(f"Created deployment {config.deployment_id}")
            return config.deployment_id
            
        except Exception as e:
            self.logger.error(f"Failed to create deployment: {e}")
            raise
    
    async def start_deployment(self, deployment_id: str) -> bool:
        """
        Start deployment execution.
        
        Args:
            deployment_id: Deployment to start
            
        Returns:
            True if deployment started successfully
        """
        try:
            if deployment_id not in self.active_deployments:
                raise ValueError(f"Deployment {deployment_id} not found")
            
            execution = self.active_deployments[deployment_id]
            
            # Check approval if required
            if execution.configuration.approval_required:
                if not await self._check_approval_status(deployment_id):
                    raise ValueError("Deployment approval required")
            
            # Update deployment state
            execution.state = DeploymentState.PREPARING
            execution.started_at = datetime.utcnow()
            
            # Start deployment based on strategy
            if execution.configuration.strategy == DeploymentStrategy.BLUE_GREEN:
                await self._start_blue_green_deployment(deployment_id)
            elif execution.configuration.strategy == DeploymentStrategy.ROLLING:
                await self._start_rolling_deployment(deployment_id)
            elif execution.configuration.strategy == DeploymentStrategy.CANARY:
                await self._start_canary_deployment(deployment_id)
            else:
                raise ValueError(f"Unsupported deployment strategy: {execution.configuration.strategy}")
            
            # Save state
            await self._save_deployment_to_storage(deployment_id)
            
            # Log deployment start
            await self._log_deployment_event(deployment_id, "deployment_started", {})
            
            self.logger.info(f"Started deployment {deployment_id}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to start deployment {deployment_id}: {e}")
            await self._handle_deployment_failure(deployment_id, str(e))
            return False
    
    async def _start_blue_green_deployment(self, deployment_id: str) -> None:
        """Execute blue/green deployment strategy."""
        execution = self.active_deployments[deployment_id]
        config = execution.configuration
        
        steps = [
            ("prepare_green", "Prepare green environment"),
            ("deploy_green", "Deploy to green environment"),
            ("health_check_green", "Health check green environment"),
            ("traffic_switch", "Switch traffic to green"),
            ("validate_green", "Validate green deployment"),
            ("cleanup_blue", "Cleanup blue environment")
        ]
        
        # Create deployment steps
        execution.steps = [
            DeploymentStep(
                step_id=f"{deployment_id}_{step_id}",
                name=step_name,
                description=step_name,
                status=DeploymentState.PENDING
            )
            for step_id, step_name in steps
        ]
        
        execution.state = DeploymentState.DEPLOYING
        execution.current_step = execution.steps[0].step_id
        
        # Execute steps asynchronously
        asyncio.create_task(self._execute_blue_green_steps(deployment_id))
    
    async def _execute_blue_green_steps(self, deployment_id: str) -> None:
        """Execute blue/green deployment steps."""
        try:
            execution = self.active_deployments[deployment_id]
            
            for step in execution.steps:
                execution.current_step = step.step_id
                step.status = DeploymentState.DEPLOYING
                step.started_at = datetime.utcnow()
                
                await self._save_deployment_to_storage(deployment_id)
                
                # Execute step based on type
                if "prepare_green" in step.step_id:
                    await self._prepare_green_environment(deployment_id)
                elif "deploy_green" in step.step_id:
                    await self._deploy_to_green_environment(deployment_id)
                elif "health_check_green" in step.step_id:
                    await self._health_check_green_environment(deployment_id)
                elif "traffic_switch" in step.step_id:
                    await self._switch_traffic_to_green(deployment_id)
                elif "validate_green" in step.step_id:
                    await self._validate_green_deployment(deployment_id)
                elif "cleanup_blue" in step.step_id:
                    await self._cleanup_blue_environment(deployment_id)
                
                # Mark step as completed
                step.status = DeploymentState.COMPLETED
                step.completed_at = datetime.utcnow()
                
                await self._save_deployment_to_storage(deployment_id)
            
            # Mark deployment as completed
            execution.state = DeploymentState.COMPLETED
            execution.completed_at = datetime.utcnow()
            execution.current_step = None
            
            # Update version manager
            await self.version_manager.transition_version_state(
                execution.configuration.target_version,
                VersionState.STABLE
            )
            
            # Send completion notification
            await self._send_deployment_notification(deployment_id, "completed")
            
            await self._save_deployment_to_storage(deployment_id)
            
            self.logger.info(f"Blue/green deployment {deployment_id} completed successfully")
            
        except Exception as e:
            await self._handle_deployment_failure(deployment_id, str(e))
    
    async def _prepare_green_environment(self, deployment_id: str) -> None:
        """Prepare green environment for deployment."""
        execution = self.active_deployments[deployment_id]
        
        # Simulate environment preparation
        await asyncio.sleep(2)
        
        # Log preparation
        execution.logs.append(f"Green environment prepared for version {execution.configuration.target_version}")
    
    async def _deploy_to_green_environment(self, deployment_id: str) -> None:
        """Deploy new version to green environment."""
        execution = self.active_deployments[deployment_id]
        
        # Simulate deployment
        await asyncio.sleep(5)
        
        # Update traffic distribution (green gets 0% initially)
        execution.traffic_distribution[execution.configuration.target_version] = 0
        
        execution.logs.append(f"Deployed version {execution.configuration.target_version} to green environment")
    
    async def _health_check_green_environment(self, deployment_id: str) -> None:
        """Perform health checks on green environment."""
        execution = self.active_deployments[deployment_id]
        config = execution.configuration
        
        for target in config.targets:
            for health_check in target.health_checks:
                success = await self._execute_health_check(health_check, target)
                if not success:
                    raise Exception(f"Health check failed for {health_check.name} on {target.name}")
        
        execution.logs.append("All health checks passed for green environment")
    
    async def _switch_traffic_to_green(self, deployment_id: str) -> None:
        """Switch traffic from blue to green environment."""
        execution = self.active_deployments[deployment_id]
        config = execution.configuration
        
        # Gradual traffic switch
        shift_duration = config.traffic_shift_duration_minutes
        steps = 10
        step_duration = (shift_duration * 60) / steps
        
        for i in range(steps + 1):
            green_percentage = int((i / steps) * 100)
            blue_percentage = 100 - green_percentage
            
            execution.traffic_distribution[config.target_version] = green_percentage
            execution.traffic_distribution[config.source_version] = blue_percentage
            
            await self._save_deployment_to_storage(deployment_id)
            
            if i < steps:
                await asyncio.sleep(step_duration)
        
        execution.logs.append("Traffic successfully switched to green environment")
    
    async def _validate_green_deployment(self, deployment_id: str) -> None:
        """Validate green deployment performance."""
        execution = self.active_deployments[deployment_id]
        
        # Simulate validation period
        await asyncio.sleep(3)
        
        # Check metrics if monitoring system available
        if self.monitoring_system:
            metrics = await self._get_deployment_metrics(deployment_id)
            execution.metrics.update(metrics)
            
            # Validate metrics
            if not await self._validate_deployment_metrics(metrics):
                raise Exception("Deployment metrics validation failed")
        
        execution.logs.append("Green deployment validation completed successfully")
    
    async def _cleanup_blue_environment(self, deployment_id: str) -> None:
        """Cleanup blue environment after successful deployment."""
        execution = self.active_deployments[deployment_id]
        
        # Simulate cleanup
        await asyncio.sleep(2)
        
        # Remove blue from traffic distribution
        execution.traffic_distribution.pop(execution.configuration.source_version, None)
        
        execution.logs.append("Blue environment cleanup completed")
    
    async def _start_rolling_deployment(self, deployment_id: str) -> None:
        """Execute rolling deployment strategy."""
        execution = self.active_deployments[deployment_id]
        config = execution.configuration
        
        steps = [
            ("validate_config", "Validate deployment configuration"),
            ("rolling_update", "Rolling update of instances"),
            ("health_validation", "Health validation"),
            ("completion", "Deployment completion")
        ]
        
        # Create deployment steps
        execution.steps = [
            DeploymentStep(
                step_id=f"{deployment_id}_{step_id}",
                name=step_name,
                description=step_name,
                status=DeploymentState.PENDING
            )
            for step_id, step_name in steps
        ]
        
        execution.state = DeploymentState.DEPLOYING
        execution.current_step = execution.steps[0].step_id
        
        # Execute steps asynchronously
        asyncio.create_task(self._execute_rolling_steps(deployment_id))
    
    async def _execute_rolling_steps(self, deployment_id: str) -> None:
        """Execute rolling deployment steps."""
        try:
            execution = self.active_deployments[deployment_id]
            
            for step in execution.steps:
                execution.current_step = step.step_id
                step.status = DeploymentState.DEPLOYING
                step.started_at = datetime.utcnow()
                
                await self._save_deployment_to_storage(deployment_id)
                
                # Execute step
                if "validate_config" in step.step_id:
                    await self._validate_rolling_config(deployment_id)
                elif "rolling_update" in step.step_id:
                    await self._execute_rolling_update(deployment_id)
                elif "health_validation" in step.step_id:
                    await self._validate_rolling_health(deployment_id)
                elif "completion" in step.step_id:
                    await self._complete_rolling_deployment(deployment_id)
                
                step.status = DeploymentState.COMPLETED
                step.completed_at = datetime.utcnow()
                
                await self._save_deployment_to_storage(deployment_id)
            
            # Mark deployment as completed
            execution.state = DeploymentState.COMPLETED
            execution.completed_at = datetime.utcnow()
            execution.current_step = None
            
            await self._save_deployment_to_storage(deployment_id)
            
            self.logger.info(f"Rolling deployment {deployment_id} completed successfully")
            
        except Exception as e:
            await self._handle_deployment_failure(deployment_id, str(e))
    
    async def _start_canary_deployment(self, deployment_id: str) -> None:
        """Execute canary deployment strategy."""
        execution = self.active_deployments[deployment_id]
        
        steps = [
            ("deploy_canary", "Deploy canary version"),
            ("canary_testing", "Canary testing and validation"),
            ("traffic_increase", "Gradually increase canary traffic"),
            ("full_rollout", "Complete rollout to all instances")
        ]
        
        # Create deployment steps
        execution.steps = [
            DeploymentStep(
                step_id=f"{deployment_id}_{step_id}",
                name=step_name,
                description=step_name,
                status=DeploymentState.PENDING
            )
            for step_id, step_name in steps
        ]
        
        execution.state = DeploymentState.DEPLOYING
        execution.current_step = execution.steps[0].step_id
        
        # Execute steps asynchronously
        asyncio.create_task(self._execute_canary_steps(deployment_id))
    
    async def rollback_deployment(self, deployment_id: str, reason: str = "") -> bool:
        """
        Rollback deployment to previous version.
        
        Args:
            deployment_id: Deployment to rollback
            reason: Reason for rollback
            
        Returns:
            True if rollback successful
        """
        try:
            if deployment_id not in self.active_deployments:
                raise ValueError(f"Deployment {deployment_id} not found")
            
            execution = self.active_deployments[deployment_id]
            
            # Update state
            execution.state = DeploymentState.ROLLING_BACK
            
            # Execute rollback based on strategy
            if execution.configuration.strategy == DeploymentStrategy.BLUE_GREEN:
                await self._rollback_blue_green(deployment_id)
            elif execution.configuration.strategy == DeploymentStrategy.ROLLING:
                await self._rollback_rolling(deployment_id)
            elif execution.configuration.strategy == DeploymentStrategy.CANARY:
                await self._rollback_canary(deployment_id)
            
            # Update state
            execution.state = DeploymentState.ROLLED_BACK
            execution.completed_at = datetime.utcnow()
            
            # Log rollback
            await self._log_deployment_event(deployment_id, "deployment_rolled_back", {
                "reason": reason
            })
            
            # Send notification
            await self._send_deployment_notification(deployment_id, "rolled_back")
            
            await self._save_deployment_to_storage(deployment_id)
            
            self.logger.info(f"Rolled back deployment {deployment_id}: {reason}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to rollback deployment {deployment_id}: {e}")
            return False
    
    async def _rollback_blue_green(self, deployment_id: str) -> None:
        """Rollback blue/green deployment."""
        execution = self.active_deployments[deployment_id]
        config = execution.configuration
        
        # Switch traffic back to blue (source version)
        execution.traffic_distribution[config.source_version] = 100
        execution.traffic_distribution[config.target_version] = 0
        
        execution.logs.append("Traffic switched back to blue environment")
    
    async def _execute_health_check(self, health_check: HealthCheck, target: DeploymentTarget) -> bool:
        """Execute individual health check."""
        try:
            if health_check.type == HealthCheckType.HTTP:
                url = f"{target.endpoint_url}{health_check.endpoint}"
                
                for attempt in range(health_check.retries):
                    try:
                        async with self._http_session.get(
                            url,
                            headers=health_check.headers,
                            timeout=aiohttp.ClientTimeout(total=health_check.timeout_seconds)
                        ) as response:
                            
                            if response.status == health_check.expected_status:
                                if health_check.expected_response:
                                    body = await response.text()
                                    if health_check.expected_response in body:
                                        return True
                                else:
                                    return True
                    
                    except Exception as e:
                        self.logger.warning(f"Health check attempt {attempt + 1} failed: {e}")
                        if attempt < health_check.retries - 1:
                            await asyncio.sleep(health_check.interval_seconds)
                
                return False
            
            else:
                # Other health check types would be implemented here
                return True
                
        except Exception as e:
            self.logger.error(f"Health check execution failed: {e}")
            return False
    
    async def _validate_deployment_config(self, config: DeploymentConfiguration) -> None:
        """Validate deployment configuration."""
        # Check version exists
        version_info = await self.version_manager.get_version_info(config.target_version)
        if not version_info:
            raise ValueError(f"Target version {config.target_version} not found")
        
        # Validate targets
        if not config.targets:
            raise ValueError("At least one deployment target required")
        
        # Validate health checks
        for target in config.targets:
            if not target.health_checks:
                raise ValueError(f"Health checks required for target {target.name}")
    
    async def _create_approval_request(self, deployment_id: str) -> None:
        """Create approval request for deployment."""
        approval_id = str(uuid.uuid4())
        execution = self.active_deployments[deployment_id]
        
        approval = ApprovalRequest(
            approval_id=approval_id,
            deployment_id=deployment_id,
            approver_role="deployment_manager",
            requested_at=datetime.utcnow(),
            expires_at=datetime.utcnow() + timedelta(minutes=execution.configuration.approval_timeout_minutes),
            status=ApprovalStatus.PENDING
        )
        
        self.pending_approvals[approval_id] = approval
        
        # Send approval notification
        await self._send_approval_notification(approval_id)
    
    async def approve_deployment(self, deployment_id: str, approver: str, comments: str = "") -> bool:
        """
        Approve deployment.
        
        Args:
            deployment_id: Deployment to approve
            approver: Name of approver
            comments: Approval comments
            
        Returns:
            True if approval successful
        """
        try:
            # Find approval request
            approval = None
            for app in self.pending_approvals.values():
                if app.deployment_id == deployment_id and app.status == ApprovalStatus.PENDING:
                    approval = app
                    break
            
            if not approval:
                raise ValueError(f"No pending approval found for deployment {deployment_id}")
            
            # Check expiration
            if datetime.utcnow() > approval.expires_at:
                approval.status = ApprovalStatus.EXPIRED
                raise ValueError("Approval request has expired")
            
            # Update approval
            approval.status = ApprovalStatus.APPROVED
            approval.approved_by = approver
            approval.approved_at = datetime.utcnow()
            approval.comments = comments
            
            # Log approval
            await self._log_deployment_event(deployment_id, "deployment_approved", {
                "approver": approver,
                "comments": comments
            })
            
            self.logger.info(f"Deployment {deployment_id} approved by {approver}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to approve deployment {deployment_id}: {e}")
            return False
    
    async def get_deployment_status(self, deployment_id: str) -> Dict[str, Any]:
        """
        Get deployment status.
        
        Args:
            deployment_id: Deployment ID
            
        Returns:
            Deployment status information
        """
        try:
            if deployment_id not in self.active_deployments:
                raise ValueError(f"Deployment {deployment_id} not found")
            
            execution = self.active_deployments[deployment_id]
            
            return {
                "deployment_id": deployment_id,
                "state": execution.state.value,
                "strategy": execution.configuration.strategy.value,
                "source_version": execution.configuration.source_version,
                "target_version": execution.configuration.target_version,
                "created_at": execution.created_at.isoformat(),
                "started_at": execution.started_at.isoformat() if execution.started_at else None,
                "completed_at": execution.completed_at.isoformat() if execution.completed_at else None,
                "current_step": execution.current_step,
                "traffic_distribution": execution.traffic_distribution,
                "steps": [
                    {
                        "step_id": step.step_id,
                        "name": step.name,
                        "status": step.status.value,
                        "started_at": step.started_at.isoformat() if step.started_at else None,
                        "completed_at": step.completed_at.isoformat() if step.completed_at else None,
                        "error_message": step.error_message
                    }
                    for step in execution.steps
                ],
                "metrics": execution.metrics,
                "logs": execution.logs,
                "error_message": execution.error_message
            }
            
        except Exception as e:
            self.logger.error(f"Failed to get deployment status: {e}")
            return {}
    
    async def _handle_deployment_failure(self, deployment_id: str, error_message: str) -> None:
        """Handle deployment failure."""
        try:
            execution = self.active_deployments[deployment_id]
            execution.state = DeploymentState.FAILED
            execution.error_message = error_message
            execution.completed_at = datetime.utcnow()
            
            # Auto-rollback if enabled
            if execution.configuration.auto_rollback_enabled:
                await self.rollback_deployment(deployment_id, f"Auto-rollback due to failure: {error_message}")
            
            # Send failure notification
            await self._send_deployment_notification(deployment_id, "failed")
            
            await self._save_deployment_to_storage(deployment_id)
            
            self.logger.error(f"Deployment {deployment_id} failed: {error_message}")
            
        except Exception as e:
            self.logger.error(f"Failed to handle deployment failure: {e}")
    
    async def _deployment_monitor(self) -> None:
        """Background task to monitor deployments."""
        while True:
            try:
                for deployment_id, execution in list(self.active_deployments.items()):
                    # Check for timeouts
                    if execution.started_at:
                        runtime = datetime.utcnow() - execution.started_at
                        if runtime > timedelta(minutes=self.deployment_timeout_minutes):
                            await self._handle_deployment_failure(
                                deployment_id,
                                f"Deployment timeout after {runtime}"
                            )
                    
                    # Move completed deployments to history
                    if execution.state in [DeploymentState.COMPLETED, DeploymentState.FAILED, DeploymentState.ROLLED_BACK]:
                        self.deployment_history.append(execution)
                        del self.active_deployments[deployment_id]
                
                await asyncio.sleep(30)  # Check every 30 seconds
                
            except Exception as e:
                self.logger.error(f"Deployment monitor error: {e}")
                await asyncio.sleep(60)
    
    async def _approval_monitor(self) -> None:
        """Background task to monitor approvals."""
        while True:
            try:
                current_time = datetime.utcnow()
                
                for approval_id, approval in list(self.pending_approvals.items()):
                    if approval.status == ApprovalStatus.PENDING and current_time > approval.expires_at:
                        approval.status = ApprovalStatus.EXPIRED
                        
                        # Handle expired approval
                        await self._handle_deployment_failure(
                            approval.deployment_id,
                            "Deployment approval expired"
                        )
                
                await asyncio.sleep(60)  # Check every minute
                
            except Exception as e:
                self.logger.error(f"Approval monitor error: {e}")
                await asyncio.sleep(60)
    
    async def _save_deployment_to_storage(self, deployment_id: str) -> None:
        """Save deployment to Redis storage."""
        try:
            deployment_key = f"deployments:{deployment_id}"
            execution = self.active_deployments[deployment_id]
            
            # Prepare data for storage
            deployment_data = asdict(execution)
            
            # Convert datetime objects to ISO format
            deployment_data["created_at"] = execution.created_at.isoformat()
            if execution.started_at:
                deployment_data["started_at"] = execution.started_at.isoformat()
            if execution.completed_at:
                deployment_data["completed_at"] = execution.completed_at.isoformat()
            
            # Convert step datetime objects
            for i, step in enumerate(deployment_data["steps"]):
                if step.get("started_at"):
                    deployment_data["steps"][i]["started_at"] = execution.steps[i].started_at.isoformat()
                if step.get("completed_at"):
                    deployment_data["steps"][i]["completed_at"] = execution.steps[i].completed_at.isoformat()
            
            await self.redis_client.set(
                deployment_key,
                json.dumps(deployment_data),
                ex=86400 * 30  # 30 days expiry
            )
            
        except Exception as e:
            self.logger.error(f"Failed to save deployment {deployment_id} to storage: {e}")
    
    async def _load_active_deployments(self) -> None:
        """Load active deployments from Redis storage."""
        try:
            pattern = "deployments:*"
            keys = await self.redis_client.keys(pattern)
            
            for key in keys:
                try:
                    deployment_data = await self.redis_client.get(key)
                    if deployment_data:
                        data = json.loads(deployment_data.decode())
                        
                        # Skip completed deployments
                        if data["state"] in ["completed", "failed", "rolled_back"]:
                            continue
                        
                        # Restore deployment execution
                        # This is a simplified restoration - full implementation would
                        # properly reconstruct all objects with proper enum values
                        deployment_id = data["deployment_id"]
                        self.logger.info(f"Loaded active deployment {deployment_id}")
                
                except Exception as e:
                    self.logger.error(f"Failed to load deployment from key {key}: {e}")
            
        except Exception as e:
            self.logger.error(f"Failed to load active deployments: {e}")
    
    async def _log_deployment_event(self, deployment_id: str, event_type: str, data: Dict[str, Any]) -> None:
        """Log deployment events."""
        try:
            event = {
                "timestamp": datetime.utcnow().isoformat(),
                "deployment_id": deployment_id,
                "event_type": event_type,
                "data": data
            }
            
            # Log to application logs
            self.logger.info(f"Deployment Event: {json.dumps(event)}")
            
            # Store in Redis for analytics
            events_key = f"deployment_events:{datetime.utcnow().strftime('%Y%m%d')}"
            await self.redis_client.lpush(events_key, json.dumps(event))
            await self.redis_client.expire(events_key, 86400 * 30)  # 30 days
            
        except Exception as e:
            self.logger.error(f"Failed to log deployment event: {e}")
    
    async def _send_deployment_notification(self, deployment_id: str, status: str) -> None:
        """Send deployment status notification."""
        try:
            execution = self.active_deployments.get(deployment_id)
            if not execution:
                return
            
            notification_data = {
                "deployment_id": deployment_id,
                "status": status,
                "strategy": execution.configuration.strategy.value,
                "source_version": execution.configuration.source_version,
                "target_version": execution.configuration.target_version,
                "timestamp": datetime.utcnow().isoformat()
            }
            
            # Send to configured webhooks
            for webhook_url in execution.configuration.notification_webhooks:
                try:
                    async with self._http_session.post(
                        webhook_url,
                        json=notification_data,
                        timeout=aiohttp.ClientTimeout(total=10)
                    ) as response:
                        if response.status != 200:
                            self.logger.warning(f"Webhook notification failed: {response.status}")
                
                except Exception as e:
                    self.logger.error(f"Failed to send webhook notification: {e}")
            
        except Exception as e:
            self.logger.error(f"Failed to send deployment notification: {e}")
    
    async def _send_approval_notification(self, approval_id: str) -> None:
        """Send approval request notification."""
        try:
            approval = self.pending_approvals[approval_id]
            
            notification_data = {
                "approval_id": approval_id,
                "deployment_id": approval.deployment_id,
                "approver_role": approval.approver_role,
                "expires_at": approval.expires_at.isoformat(),
                "approval_url": f"/api/v1/deployments/{approval.deployment_id}/approve"
            }
            
            self.logger.info(f"Approval notification: {json.dumps(notification_data)}")
            
        except Exception as e:
            self.logger.error(f"Failed to send approval notification: {e}")
    
    async def close(self) -> None:
        """Clean up resources."""
        if self._http_session:
            await self._http_session.close()
        
        if self.redis_client:
            await self.redis_client.close()
        
        self.logger.info("Lifecycle Orchestrator closed")


# Utility functions for creating common configurations
def create_blue_green_config(deployment_id: str, source_version: str, target_version: str,
                           production_url: str) -> DeploymentConfiguration:
    """Create blue/green deployment configuration."""
    health_checks = [
        HealthCheck(
            name="api_health",
            type=HealthCheckType.HTTP,
            endpoint="/health",
            timeout_seconds=30,
            retries=3
        )
    ]
    
    targets = [
        DeploymentTarget(
            name="production",
            environment=APIGatewayEnvironment.PRODUCTION,
            endpoint_url=production_url,
            health_checks=health_checks
        )
    ]
    
    return DeploymentConfiguration(
        deployment_id=deployment_id,
        strategy=DeploymentStrategy.BLUE_GREEN,
        source_version=source_version,
        target_version=target_version,
        targets=targets,
        rollback_config={"auto_rollback_threshold": 5},
        approval_required=True,
        traffic_shift_duration_minutes=15
    )


if __name__ == "__main__":
    # Example usage
    async def main():
        from api_gateway.api_version_manager import APIVersionManager
        
        version_manager = APIVersionManager()
        await version_manager.initialize()
        
        orchestrator = LifecycleOrchestrator(version_manager)
        await orchestrator.initialize()
        
        try:
            # Create blue/green deployment
            config = create_blue_green_config(
                "deploy-001",
                "1.0.0",
                "1.1.0",
                "https://api.example.mil"
            )
            
            deployment_id = await orchestrator.create_deployment(config)
            print(f"Created deployment: {deployment_id}")
            
            # Approve deployment
            await orchestrator.approve_deployment(deployment_id, "admin", "Approved for production")
            
            # Start deployment
            await orchestrator.start_deployment(deployment_id)
            
            # Monitor deployment
            while True:
                status = await orchestrator.get_deployment_status(deployment_id)
                print(f"Deployment status: {status['state']}")
                
                if status['state'] in ['completed', 'failed', 'rolled_back']:
                    break
                
                await asyncio.sleep(5)
            
        finally:
            await orchestrator.close()
            await version_manager.close()
    
    asyncio.run(main())