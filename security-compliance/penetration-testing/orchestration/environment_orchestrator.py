"""
Environment Orchestration System
================================

Comprehensive orchestration system for automated provisioning, management,
and lifecycle control of isolated penetration testing environments with
integration to existing security infrastructure.

Key Features:
- Automated environment provisioning
- Test scenario deployment
- Resource cleanup and sanitization
- Environment state management
- Integration with existing monitoring systems
- Workflow automation and scheduling

Classification: UNCLASSIFIED//FOR OFFICIAL USE ONLY
Version: 1.0 - Environment Orchestration
Author: Security Testing Team
Date: 2025-07-28
"""

import asyncio
import json
import logging
import time
import yaml
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Tuple, Set, Union, Callable
from uuid import UUID, uuid4
from dataclasses import dataclass, field, asdict
from enum import Enum
from collections import defaultdict, deque
from pathlib import Path
import tempfile
import shutil

# Optional imports for production use
try:
    from ..environment.isolated_test_environment import (
        IsolatedTestEnvironment, SecurityLevel, NetworkIsolationType, ResourceLimits
    )
    from ..infrastructure.testing_infrastructure import (
        TestingInfrastructure, InfrastructureType, TargetSystemConfig, KaliToolConfig
    )
    from ..isolation.security_isolation_framework import (
        SecurityIsolationFramework, IsolationLevel, ResourceLimit
    )
    COMPONENTS_AVAILABLE = True
except ImportError:
    COMPONENTS_AVAILABLE = False

try:
    import schedule
    SCHEDULER_AVAILABLE = True
except ImportError:
    SCHEDULER_AVAILABLE = False

logger = logging.getLogger(__name__)

class OrchestrationStatus(Enum):
    """Orchestration workflow status"""
    PENDING = "pending"
    PROVISIONING = "provisioning"
    CONFIGURING = "configuring"
    RUNNING = "running"
    TESTING = "testing"
    CLEANUP = "cleanup"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

class TestScenarioType(Enum):
    """Test scenario types"""
    WEB_APPLICATION_PENTEST = "web_application_pentest"
    NETWORK_PENTEST = "network_pentest"
    INFRASTRUCTURE_ASSESSMENT = "infrastructure_assessment"
    RED_TEAM_EXERCISE = "red_team_exercise"
    COMPLIANCE_VALIDATION = "compliance_validation"
    CUSTOM_SCENARIO = "custom_scenario"

class WorkflowTrigger(Enum):
    """Workflow trigger types"""
    MANUAL = "manual"
    SCHEDULED = "scheduled"
    EVENT_DRIVEN = "event_driven"
    API_REQUEST = "api_request"

@dataclass
class TestScenario:
    """Test scenario definition"""
    scenario_id: str
    name: str
    description: str
    scenario_type: TestScenarioType
    security_level: SecurityLevel
    duration_hours: int
    resource_requirements: ResourceLimits
    isolation_level: IsolationLevel
    kali_tools: List[str] = field(default_factory=list)
    target_systems: List[Dict[str, Any]] = field(default_factory=list)
    network_topology: Optional[Dict[str, Any]] = None
    custom_scripts: List[str] = field(default_factory=list)
    success_criteria: List[str] = field(default_factory=list)
    cleanup_scripts: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class OrchestrationWorkflow:
    """Orchestration workflow definition"""
    workflow_id: str
    name: str
    description: str
    scenario: TestScenario
    status: OrchestrationStatus
    created_at: datetime
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    created_by: str = ""
    authorized_by: str = ""
    trigger: WorkflowTrigger = WorkflowTrigger.MANUAL
    environment_id: Optional[str] = None
    infrastructure_deployments: List[str] = field(default_factory=list)
    test_results: Dict[str, Any] = field(default_factory=dict)
    logs: List[str] = field(default_factory=list)
    metrics: Dict[str, Any] = field(default_factory=dict)

@dataclass
class WorkflowStep:
    """Individual workflow step"""
    step_id: str
    name: str
    description: str
    action: str
    parameters: Dict[str, Any]
    depends_on: List[str] = field(default_factory=list)
    timeout_minutes: int = 60
    retry_count: int = 3
    continue_on_failure: bool = False
    status: str = "pending"
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None

class EnvironmentOrchestrator:
    """
    Main class for orchestrating penetration testing environments.
    
    Provides comprehensive workflow management, automated provisioning,
    and integration with existing security infrastructure for complete
    penetration testing lifecycle management.
    """
    
    def __init__(self,
                 environment_manager: Optional[Any] = None,
                 infrastructure_manager: Optional[Any] = None,
                 isolation_framework: Optional[Any] = None,
                 audit_logger: Optional[Any] = None,
                 monitoring_system: Optional[Any] = None):
        """
        Initialize environment orchestrator.
        
        Args:
            environment_manager: Isolated test environment manager
            infrastructure_manager: Testing infrastructure manager
            isolation_framework: Security isolation framework
            audit_logger: Audit logging system integration
            monitoring_system: Security monitoring system integration
        """
        self.environment_manager = environment_manager
        self.infrastructure_manager = infrastructure_manager
        self.isolation_framework = isolation_framework
        self.audit_logger = audit_logger
        self.monitoring_system = monitoring_system
        
        # Workflow tracking
        self.workflows: Dict[str, OrchestrationWorkflow] = {}
        self.active_workflows: Set[str] = set()
        self.workflow_steps: Dict[str, List[WorkflowStep]] = {}
        
        # Scenario library
        self.test_scenarios: Dict[str, TestScenario] = {}
        self._initialize_default_scenarios()
        
        # Workflow templates
        self.workflow_templates: Dict[str, List[WorkflowStep]] = {}
        self._initialize_workflow_templates()
        
        # Configuration
        self.config = {
            'max_concurrent_workflows': 10,
            'default_timeout_minutes': 480,  # 8 hours
            'cleanup_retention_days': 30,
            'auto_cleanup_enabled': True,
            'workflow_monitoring_interval': 30,
            'metrics_collection_enabled': True,
            'notification_enabled': True
        }
        
        # Metrics and monitoring
        self.workflow_metrics = {
            'total_workflows': 0,
            'successful_workflows': 0,
            'failed_workflows': 0,
            'average_duration_minutes': 0.0,
            'resource_utilization': {},
            'popular_scenarios': defaultdict(int)
        }
        
        # Start background tasks
        self._monitoring_task = None
        self._start_monitoring()
        
        logger.info("Environment Orchestrator initialized")

    async def create_workflow(self,
                            scenario_id: str,
                            workflow_name: str,
                            created_by: str,
                            authorized_by: str,
                            custom_parameters: Optional[Dict[str, Any]] = None,
                            trigger: WorkflowTrigger = WorkflowTrigger.MANUAL) -> str:
        """
        Create a new orchestration workflow.
        
        Args:
            scenario_id: Test scenario ID
            workflow_name: Workflow name
            created_by: Workflow creator
            authorized_by: Authorization authority
            custom_parameters: Custom workflow parameters
            trigger: Workflow trigger type
            
        Returns:
            Workflow ID
        """
        try:
            if scenario_id not in self.test_scenarios:
                raise ValueError(f"Test scenario {scenario_id} not found")
            
            scenario = self.test_scenarios[scenario_id]
            workflow_id = str(uuid4())
            
            # Apply custom parameters
            if custom_parameters:
                # Merge custom parameters with scenario
                scenario = self._merge_scenario_parameters(scenario, custom_parameters)
            
            # Create workflow
            workflow = OrchestrationWorkflow(
                workflow_id=workflow_id,
                name=workflow_name,
                description=f"Orchestrated workflow for {scenario.name}",
                scenario=scenario,
                status=OrchestrationStatus.PENDING,
                created_at=datetime.now(timezone.utc),
                created_by=created_by,
                authorized_by=authorized_by,
                trigger=trigger
            )
            
            # Create workflow steps
            workflow_steps = await self._create_workflow_steps(scenario)
            self.workflow_steps[workflow_id] = workflow_steps
            
            # Store workflow
            self.workflows[workflow_id] = workflow
            
            # Update metrics
            self.workflow_metrics['total_workflows'] += 1
            self.workflow_metrics['popular_scenarios'][scenario_id] += 1
            
            # Log workflow creation
            await self._log_orchestration_event(
                workflow_id,
                "workflow_created",
                f"Workflow '{workflow_name}' created for scenario '{scenario.name}'"
            )
            
            logger.info(f"Created workflow {workflow_id} for scenario {scenario_id}")
            
            return workflow_id
            
        except Exception as e:
            logger.error(f"Failed to create workflow: {e}")
            raise

    async def start_workflow(self, workflow_id: str) -> bool:
        """
        Start orchestration workflow execution.
        
        Args:
            workflow_id: Workflow ID to start
            
        Returns:
            True if workflow started successfully
        """
        try:
            if workflow_id not in self.workflows:
                raise ValueError(f"Workflow {workflow_id} not found")
            
            workflow = self.workflows[workflow_id]
            
            if workflow.status != OrchestrationStatus.PENDING:
                raise ValueError(f"Workflow {workflow_id} is not in pending state")
            
            # Check concurrent workflow limit
            if len(self.active_workflows) >= self.config['max_concurrent_workflows']:
                raise ValueError("Maximum concurrent workflows limit reached")
            
            # Update workflow status
            workflow.status = OrchestrationStatus.PROVISIONING
            workflow.started_at = datetime.now(timezone.utc)
            self.active_workflows.add(workflow_id)
            
            # Log workflow start
            await self._log_orchestration_event(
                workflow_id,
                "workflow_started",
                f"Workflow execution started"
            )
            
            # Start workflow execution in background
            asyncio.create_task(self._execute_workflow(workflow_id))
            
            logger.info(f"Started workflow {workflow_id}")
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to start workflow {workflow_id}: {e}")
            return False

    async def cancel_workflow(self, workflow_id: str) -> bool:
        """
        Cancel running workflow.
        
        Args:
            workflow_id: Workflow ID to cancel
            
        Returns:
            True if workflow was cancelled
        """
        try:
            if workflow_id not in self.workflows:
                raise ValueError(f"Workflow {workflow_id} not found")
            
            workflow = self.workflows[workflow_id]
            
            if workflow.status not in [OrchestrationStatus.PROVISIONING, 
                                     OrchestrationStatus.CONFIGURING,
                                     OrchestrationStatus.RUNNING,
                                     OrchestrationStatus.TESTING]:
                raise ValueError(f"Workflow {workflow_id} cannot be cancelled")
            
            # Update status
            workflow.status = OrchestrationStatus.CANCELLED
            workflow.completed_at = datetime.now(timezone.utc)
            
            # Remove from active workflows
            self.active_workflows.discard(workflow_id)
            
            # Cleanup resources
            await self._cleanup_workflow_resources(workflow_id)
            
            # Log cancellation
            await self._log_orchestration_event(
                workflow_id,
                "workflow_cancelled",
                "Workflow execution cancelled"
            )
            
            logger.info(f"Cancelled workflow {workflow_id}")
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to cancel workflow {workflow_id}: {e}")
            return False

    async def get_workflow_status(self, workflow_id: str) -> Dict[str, Any]:
        """
        Get detailed workflow status.
        
        Args:
            workflow_id: Workflow ID
            
        Returns:
            Workflow status information
        """
        try:
            if workflow_id not in self.workflows:
                raise ValueError(f"Workflow {workflow_id} not found")
            
            workflow = self.workflows[workflow_id]
            workflow_steps = self.workflow_steps.get(workflow_id, [])
            
            # Calculate duration
            duration_minutes = 0.0
            if workflow.started_at:
                end_time = workflow.completed_at or datetime.now(timezone.utc)
                duration_minutes = (end_time - workflow.started_at).total_seconds() / 60
            
            # Count step statuses
            step_statuses = defaultdict(int)
            for step in workflow_steps:
                step_statuses[step.status] += 1
            
            # Get environment status if available
            environment_status = {}
            if workflow.environment_id and self.environment_manager:
                try:
                    environment_status = await self.environment_manager.get_environment_status(
                        workflow.environment_id
                    )
                except Exception as e:
                    logger.warning(f"Failed to get environment status: {e}")
            
            status_data = {
                'workflow_id': workflow_id,
                'name': workflow.name,
                'status': workflow.status.value,
                'scenario': {
                    'scenario_id': workflow.scenario.scenario_id,
                    'name': workflow.scenario.name,
                    'type': workflow.scenario.scenario_type.value,
                    'security_level': workflow.scenario.security_level.value
                },
                'created_at': workflow.created_at.isoformat(),
                'started_at': workflow.started_at.isoformat() if workflow.started_at else None,
                'completed_at': workflow.completed_at.isoformat() if workflow.completed_at else None,
                'duration_minutes': duration_minutes,
                'created_by': workflow.created_by,
                'authorized_by': workflow.authorized_by,
                'trigger': workflow.trigger.value,
                'environment_id': workflow.environment_id,
                'infrastructure_deployments': workflow.infrastructure_deployments,
                'step_summary': dict(step_statuses),
                'total_steps': len(workflow_steps),
                'test_results': workflow.test_results,
                'environment_status': environment_status,
                'metrics': workflow.metrics
            }
            
            return status_data
            
        except Exception as e:
            logger.error(f"Failed to get workflow status: {e}")
            return {'error': str(e)}

    async def list_workflows(self, 
                           status: Optional[OrchestrationStatus] = None,
                           hours: int = 24) -> List[Dict[str, Any]]:
        """
        List workflows with optional filtering.
        
        Args:
            status: Filter by workflow status
            hours: Time window in hours
            
        Returns:
            List of workflow summaries
        """
        try:
            cutoff_time = datetime.now(timezone.utc) - timedelta(hours=hours)
            workflows = []
            
            for workflow_id, workflow in self.workflows.items():
                # Apply filters
                if status and workflow.status != status:
                    continue
                
                if workflow.created_at < cutoff_time:
                    continue
                
                # Calculate duration
                duration_minutes = 0.0
                if workflow.started_at:
                    end_time = workflow.completed_at or datetime.now(timezone.utc)
                    duration_minutes = (end_time - workflow.started_at).total_seconds() / 60
                
                workflow_summary = {
                    'workflow_id': workflow_id,
                    'name': workflow.name,
                    'status': workflow.status.value,
                    'scenario_name': workflow.scenario.name,
                    'scenario_type': workflow.scenario.scenario_type.value,
                    'created_at': workflow.created_at.isoformat(),
                    'started_at': workflow.started_at.isoformat() if workflow.started_at else None,
                    'duration_minutes': duration_minutes,
                    'created_by': workflow.created_by,
                    'authorized_by': workflow.authorized_by
                }
                
                workflows.append(workflow_summary)
            
            # Sort by creation time (newest first)
            workflows.sort(key=lambda x: x['created_at'], reverse=True)
            
            return workflows
            
        except Exception as e:
            logger.error(f"Failed to list workflows: {e}")
            return []

    async def get_scenario_library(self) -> List[Dict[str, Any]]:
        """
        Get available test scenarios.
        
        Returns:
            List of available test scenarios
        """
        try:
            scenarios = []
            
            for scenario_id, scenario in self.test_scenarios.items():
                scenario_data = {
                    'scenario_id': scenario_id,
                    'name': scenario.name,
                    'description': scenario.description,
                    'type': scenario.scenario_type.value,
                    'security_level': scenario.security_level.value,
                    'duration_hours': scenario.duration_hours,
                    'isolation_level': scenario.isolation_level.value,
                    'target_count': len(scenario.target_systems),
                    'tool_count': len(scenario.kali_tools),
                    'usage_count': self.workflow_metrics['popular_scenarios'][scenario_id]
                }
                
                scenarios.append(scenario_data)
            
            # Sort by usage count (most popular first)
            scenarios.sort(key=lambda x: x['usage_count'], reverse=True)
            
            return scenarios
            
        except Exception as e:
            logger.error(f"Failed to get scenario library: {e}")
            return []

    async def create_custom_scenario(self,
                                   scenario_data: Dict[str, Any],
                                   created_by: str) -> str:
        """
        Create a custom test scenario.
        
        Args:
            scenario_data: Scenario configuration data
            created_by: Scenario creator
            
        Returns:
            Scenario ID
        """
        try:
            scenario_id = str(uuid4())
            
            # Validate scenario data
            required_fields = ['name', 'description', 'scenario_type', 'security_level', 'duration_hours']
            for field in required_fields:
                if field not in scenario_data:
                    raise ValueError(f"Required field '{field}' missing from scenario data")
            
            # Create scenario
            scenario = TestScenario(
                scenario_id=scenario_id,
                name=scenario_data['name'],
                description=scenario_data['description'],
                scenario_type=TestScenarioType(scenario_data['scenario_type']),
                security_level=SecurityLevel(scenario_data['security_level']),
                duration_hours=scenario_data['duration_hours'],
                resource_requirements=ResourceLimits(**scenario_data.get('resource_requirements', {})),
                isolation_level=IsolationLevel(scenario_data.get('isolation_level', 'controlled_access')),
                kali_tools=scenario_data.get('kali_tools', []),
                target_systems=scenario_data.get('target_systems', []),
                network_topology=scenario_data.get('network_topology'),
                custom_scripts=scenario_data.get('custom_scripts', []),
                success_criteria=scenario_data.get('success_criteria', []),
                cleanup_scripts=scenario_data.get('cleanup_scripts', []),
                metadata={'created_by': created_by, 'created_at': datetime.now(timezone.utc).isoformat()}
            )
            
            # Store scenario
            self.test_scenarios[scenario_id] = scenario
            
            # Log scenario creation
            await self._log_orchestration_event(
                scenario_id,
                "scenario_created",
                f"Custom scenario '{scenario.name}' created by {created_by}"
            )
            
            logger.info(f"Created custom scenario {scenario_id}: {scenario.name}")
            
            return scenario_id
            
        except Exception as e:
            logger.error(f"Failed to create custom scenario: {e}")
            raise

    async def get_orchestration_metrics(self) -> Dict[str, Any]:
        """
        Get orchestration system metrics.
        
        Returns:
            System metrics and statistics
        """
        try:
            # Calculate average duration
            completed_workflows = [
                w for w in self.workflows.values() 
                if w.status == OrchestrationStatus.COMPLETED and w.started_at and w.completed_at
            ]
            
            if completed_workflows:
                total_duration = sum(
                    (w.completed_at - w.started_at).total_seconds() / 60 
                    for w in completed_workflows
                )
                self.workflow_metrics['average_duration_minutes'] = total_duration / len(completed_workflows)
            
            # Get current resource utilization
            resource_utilization = {}
            if self.environment_manager:
                try:
                    usage_stats = await self.environment_manager.get_resource_usage()
                    resource_utilization = usage_stats.get('resources', {})
                except Exception as e:
                    logger.warning(f"Failed to get resource utilization: {e}")
            
            metrics = {
                'workflows': {
                    'total': self.workflow_metrics['total_workflows'],
                    'successful': self.workflow_metrics['successful_workflows'],
                    'failed': self.workflow_metrics['failed_workflows'],
                    'active': len(self.active_workflows),
                    'success_rate': (
                        self.workflow_metrics['successful_workflows'] / 
                        max(1, self.workflow_metrics['total_workflows'])
                    ) * 100
                },
                'performance': {
                    'average_duration_minutes': self.workflow_metrics['average_duration_minutes'],
                    'max_concurrent_workflows': self.config['max_concurrent_workflows'],
                    'current_utilization': len(self.active_workflows) / self.config['max_concurrent_workflows'] * 100
                },
                'scenarios': {
                    'total_scenarios': len(self.test_scenarios),
                    'popular_scenarios': dict(list(self.workflow_metrics['popular_scenarios'].most_common(5)))
                },
                'resources': resource_utilization,
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
            
            return metrics
            
        except Exception as e:
            logger.error(f"Failed to get orchestration metrics: {e}")
            return {}

    # Private methods

    def _initialize_default_scenarios(self) -> None:
        """Initialize default test scenarios"""
        try:
            default_scenarios = [
                TestScenario(
                    scenario_id="web_app_basic",
                    name="Basic Web Application Penetration Test",
                    description="Basic penetration test for web applications including OWASP Top 10 testing",
                    scenario_type=TestScenarioType.WEB_APPLICATION_PENTEST,
                    security_level=SecurityLevel.CUI,
                    duration_hours=4,
                    resource_requirements=ResourceLimits(cpu_cores=2.0, memory_gb=4.0, disk_gb=20.0),
                    isolation_level=IsolationLevel.CONTROLLED_ACCESS,
                    kali_tools=['nmap', 'nikto', 'sqlmap', 'dirb', 'burpsuite'],
                    target_systems=[
                        {
                            'system_id': 'dvwa',
                            'system_type': 'web_application',
                            'image': 'vulnerables/web-dvwa:latest',
                            'ports': [80, 3306]
                        }
                    ],
                    success_criteria=[
                        'Complete OWASP Top 10 assessment',
                        'Identify at least 3 vulnerabilities',
                        'Generate comprehensive report'
                    ]
                ),
                TestScenario(
                    scenario_id="network_infra_assess",
                    name="Network Infrastructure Assessment",
                    description="Comprehensive network infrastructure security assessment",
                    scenario_type=TestScenarioType.INFRASTRUCTURE_ASSESSMENT,
                    security_level=SecurityLevel.CUI,
                    duration_hours=8,
                    resource_requirements=ResourceLimits(cpu_cores=4.0, memory_gb=8.0, disk_gb=40.0),
                    isolation_level=IsolationLevel.MONITORED_ACCESS,
                    kali_tools=['nmap', 'masscan', 'metasploit', 'hydra', 'enum4linux'],
                    target_systems=[
                        {
                            'system_id': 'metasploitable',
                            'system_type': 'linux_server',
                            'image': 'tleemcjr/metasploitable2:latest',
                            'ports': [21, 22, 23, 25, 53, 80, 139, 445, 3306]
                        }
                    ],
                    success_criteria=[
                        'Complete network discovery',
                        'Service enumeration',
                        'Vulnerability assessment',
                        'Exploitation attempts'
                    ]
                ),
                TestScenario(
                    scenario_id="red_team_basic",
                    name="Basic Red Team Exercise",
                    description="Basic red team exercise with multiple attack vectors",
                    scenario_type=TestScenarioType.RED_TEAM_EXERCISE,
                    security_level=SecurityLevel.CONFIDENTIAL,
                    duration_hours=12,
                    resource_requirements=ResourceLimits(cpu_cores=6.0, memory_gb=12.0, disk_gb=60.0),
                    isolation_level=IsolationLevel.COMPLETE_ISOLATION,
                    kali_tools=['nmap', 'metasploit', 'cobalt-strike', 'empire', 'bloodhound'],
                    target_systems=[
                        {
                            'system_id': 'domain_controller',
                            'system_type': 'windows_server',
                            'image': 'custom/windows-server-2019:latest',
                            'ports': [53, 88, 135, 139, 389, 445, 3389]
                        },
                        {
                            'system_id': 'web_server',
                            'system_type': 'web_application',
                            'image': 'vulnerables/web-dvwa:latest',
                            'ports': [80, 443]
                        }
                    ],
                    success_criteria=[
                        'Initial compromise',
                        'Privilege escalation',
                        'Lateral movement',
                        'Domain admin access',
                        'Data exfiltration simulation'
                    ]
                )
            ]
            
            for scenario in default_scenarios:
                self.test_scenarios[scenario.scenario_id] = scenario
                
            logger.info(f"Initialized {len(default_scenarios)} default scenarios")
            
        except Exception as e:
            logger.error(f"Failed to initialize default scenarios: {e}")

    def _initialize_workflow_templates(self) -> None:
        """Initialize workflow step templates"""
        try:
            # Web Application Penetration Test Template
            web_app_template = [
                WorkflowStep(
                    step_id="create_environment",
                    name="Create Isolated Environment",
                    description="Create isolated testing environment",
                    action="create_environment",
                    parameters={},
                    timeout_minutes=15
                ),
                WorkflowStep(
                    step_id="enable_isolation",
                    name="Enable Security Isolation",
                    description="Enable security isolation framework",
                    action="enable_isolation",
                    parameters={},
                    depends_on=["create_environment"],
                    timeout_minutes=10
                ),
                WorkflowStep(
                    step_id="deploy_kali",
                    name="Deploy Kali Linux",
                    description="Deploy Kali Linux penetration testing environment",
                    action="deploy_kali",
                    parameters={},
                    depends_on=["enable_isolation"],
                    timeout_minutes=30
                ),
                WorkflowStep(
                    step_id="deploy_targets",
                    name="Deploy Target Systems",
                    description="Deploy target systems for testing",
                    action="deploy_targets",
                    parameters={},
                    depends_on=["deploy_kali"],
                    timeout_minutes=20
                ),
                WorkflowStep(
                    step_id="run_reconnaissance",
                    name="Run Reconnaissance",
                    description="Perform reconnaissance and discovery",
                    action="run_tools",
                    parameters={"tools": ["nmap", "dirb"]},
                    depends_on=["deploy_targets"],
                    timeout_minutes=60
                ),
                WorkflowStep(
                    step_id="run_vulnerability_scan",
                    name="Run Vulnerability Scanning",
                    description="Perform vulnerability scanning",
                    action="run_tools",
                    parameters={"tools": ["nikto", "sqlmap"]},
                    depends_on=["run_reconnaissance"],
                    timeout_minutes=120
                ),
                WorkflowStep(
                    step_id="generate_report",
                    name="Generate Report",
                    description="Generate comprehensive test report",
                    action="generate_report",
                    parameters={},
                    depends_on=["run_vulnerability_scan"],
                    timeout_minutes=30
                ),
                WorkflowStep(
                    step_id="cleanup",
                    name="Cleanup Resources",
                    description="Clean up all testing resources",
                    action="cleanup",
                    parameters={},
                    depends_on=["generate_report"],
                    timeout_minutes=15,
                    continue_on_failure=True
                )
            ]
            
            self.workflow_templates["web_application_pentest"] = web_app_template
            
            # Network Infrastructure Assessment Template
            network_template = [
                WorkflowStep(
                    step_id="create_environment",
                    name="Create Isolated Environment",
                    description="Create isolated testing environment",
                    action="create_environment",
                    parameters={},
                    timeout_minutes=15
                ),
                WorkflowStep(
                    step_id="enable_isolation",
                    name="Enable Security Isolation",
                    description="Enable security isolation framework",
                    action="enable_isolation",
                    parameters={},
                    depends_on=["create_environment"],
                    timeout_minutes=10
                ),
                WorkflowStep(
                    step_id="deploy_kali",
                    name="Deploy Kali Linux",
                    description="Deploy Kali Linux penetration testing environment",
                    action="deploy_kali",
                    parameters={},
                    depends_on=["enable_isolation"],
                    timeout_minutes=30
                ),
                WorkflowStep(
                    step_id="deploy_targets",
                    name="Deploy Target Systems",
                    description="Deploy target network infrastructure",
                    action="deploy_targets",
                    parameters={},
                    depends_on=["deploy_kali"],
                    timeout_minutes=30
                ),
                WorkflowStep(
                    step_id="network_discovery",
                    name="Network Discovery",
                    description="Perform network discovery and mapping",
                    action="run_tools",
                    parameters={"tools": ["nmap", "masscan"]},
                    depends_on=["deploy_targets"],
                    timeout_minutes=90
                ),
                WorkflowStep(
                    step_id="service_enumeration",
                    name="Service Enumeration",
                    description="Enumerate discovered services",
                    action="run_tools",
                    parameters={"tools": ["enum4linux", "smbclient"]},
                    depends_on=["network_discovery"],
                    timeout_minutes=120
                ),
                WorkflowStep(
                    step_id="vulnerability_assessment",
                    name="Vulnerability Assessment",
                    description="Assess vulnerabilities in discovered services",
                    action="run_tools",
                    parameters={"tools": ["metasploit", "hydra"]},
                    depends_on=["service_enumeration"],
                    timeout_minutes=180
                ),
                WorkflowStep(
                    step_id="generate_report",
                    name="Generate Report",
                    description="Generate comprehensive assessment report",
                    action="generate_report",
                    parameters={},
                    depends_on=["vulnerability_assessment"],
                    timeout_minutes=45
                ),
                WorkflowStep(
                    step_id="cleanup",
                    name="Cleanup Resources",
                    description="Clean up all testing resources",
                    action="cleanup",
                    parameters={},
                    depends_on=["generate_report"],
                    timeout_minutes=20,
                    continue_on_failure=True
                )
            ]
            
            self.workflow_templates["infrastructure_assessment"] = network_template
            
            logger.info(f"Initialized {len(self.workflow_templates)} workflow templates")
            
        except Exception as e:
            logger.error(f"Failed to initialize workflow templates: {e}")

    def _merge_scenario_parameters(self, scenario: TestScenario, custom_parameters: Dict[str, Any]) -> TestScenario:
        """Merge custom parameters with scenario"""
        try:
            # Create a copy of the scenario
            merged_scenario = TestScenario(**asdict(scenario))
            
            # Apply custom parameters
            for key, value in custom_parameters.items():
                if hasattr(merged_scenario, key):
                    setattr(merged_scenario, key, value)
            
            return merged_scenario
            
        except Exception as e:
            logger.error(f"Failed to merge scenario parameters: {e}")
            return scenario

    async def _create_workflow_steps(self, scenario: TestScenario) -> List[WorkflowStep]:
        """Create workflow steps based on scenario"""
        try:
            # Map scenario types to templates
            template_mapping = {
                TestScenarioType.WEB_APPLICATION_PENTEST: "web_application_pentest",
                TestScenarioType.INFRASTRUCTURE_ASSESSMENT: "infrastructure_assessment",
                TestScenarioType.NETWORK_PENTEST: "infrastructure_assessment",
                TestScenarioType.RED_TEAM_EXERCISE: "infrastructure_assessment",  # Use same template for now
                TestScenarioType.COMPLIANCE_VALIDATION: "web_application_pentest",  # Use same template for now
                TestScenarioType.CUSTOM_SCENARIO: "web_application_pentest"  # Default template
            }
            
            template_name = template_mapping.get(
                scenario.scenario_type, 
                "web_application_pentest"
            )
            
            if template_name not in self.workflow_templates:
                raise ValueError(f"Workflow template {template_name} not found")
            
            # Get template steps
            template_steps = self.workflow_templates[template_name]
            
            # Create workflow-specific steps
            workflow_steps = []
            for template_step in template_steps:
                step = WorkflowStep(
                    step_id=template_step.step_id,
                    name=template_step.name,
                    description=template_step.description,
                    action=template_step.action,
                    parameters=template_step.parameters.copy(),
                    depends_on=template_step.depends_on.copy(),
                    timeout_minutes=template_step.timeout_minutes,
                    retry_count=template_step.retry_count,
                    continue_on_failure=template_step.continue_on_failure
                )
                
                # Customize step parameters based on scenario
                if step.action == "deploy_kali":
                    step.parameters["tools"] = scenario.kali_tools
                elif step.action == "deploy_targets":
                    step.parameters["target_systems"] = scenario.target_systems
                elif step.action == "run_tools" and "tools" in step.parameters:
                    # Filter tools based on scenario requirements
                    available_tools = set(scenario.kali_tools)
                    step.parameters["tools"] = [
                        tool for tool in step.parameters["tools"] 
                        if tool in available_tools
                    ]
                
                workflow_steps.append(step)
            
            return workflow_steps
            
        except Exception as e:
            logger.error(f"Failed to create workflow steps: {e}")
            return []

    async def _execute_workflow(self, workflow_id: str) -> None:
        """Execute workflow steps"""
        try:
            workflow = self.workflows[workflow_id]
            workflow_steps = self.workflow_steps[workflow_id]
            
            # Create dependency graph
            step_graph = self._build_step_dependency_graph(workflow_steps)
            
            # Execute steps
            completed_steps = set()
            failed_steps = set()
            
            while len(completed_steps) < len(workflow_steps):
                # Find ready steps (dependencies satisfied)
                ready_steps = []
                for step in workflow_steps:
                    if (step.step_id not in completed_steps and 
                        step.step_id not in failed_steps and
                        step.status == "pending" and
                        all(dep in completed_steps for dep in step.depends_on)):
                        ready_steps.append(step)
                
                if not ready_steps:
                    # Check if we're stuck due to failures
                    if failed_steps:
                        workflow.status = OrchestrationStatus.FAILED
                        break
                    else:
                        # No ready steps but no failures - should not happen
                        logger.error(f"Workflow {workflow_id} has no ready steps")
                        workflow.status = OrchestrationStatus.FAILED
                        break
                
                # Execute ready steps (could be parallel, but sequential for now)
                for step in ready_steps:
                    try:
                        success = await self._execute_workflow_step(workflow_id, step)
                        if success:
                            completed_steps.add(step.step_id)
                        else:
                            failed_steps.add(step.step_id)
                            if not step.continue_on_failure:
                                workflow.status = OrchestrationStatus.FAILED
                                break
                    except Exception as e:
                        logger.error(f"Failed to execute step {step.step_id}: {e}")
                        failed_steps.add(step.step_id)
                        if not step.continue_on_failure:
                            workflow.status = OrchestrationStatus.FAILED
                            break
                
                if workflow.status == OrchestrationStatus.FAILED:
                    break
            
            # Update final workflow status
            if workflow.status != OrchestrationStatus.FAILED:
                if len(completed_steps) == len(workflow_steps):
                    workflow.status = OrchestrationStatus.COMPLETED
                    self.workflow_metrics['successful_workflows'] += 1
                else:
                    workflow.status = OrchestrationStatus.FAILED
                    self.workflow_metrics['failed_workflows'] += 1
            else:
                self.workflow_metrics['failed_workflows'] += 1
            
            workflow.completed_at = datetime.now(timezone.utc)
            self.active_workflows.discard(workflow_id)
            
            # Log workflow completion
            await self._log_orchestration_event(
                workflow_id,
                "workflow_completed",
                f"Workflow completed with status: {workflow.status.value}"
            )
            
            logger.info(f"Workflow {workflow_id} completed with status: {workflow.status.value}")
            
        except Exception as e:
            logger.error(f"Failed to execute workflow {workflow_id}: {e}")
            
            # Update workflow status on error
            workflow = self.workflows[workflow_id]
            workflow.status = OrchestrationStatus.FAILED
            workflow.completed_at = datetime.now(timezone.utc)
            self.active_workflows.discard(workflow_id)
            self.workflow_metrics['failed_workflows'] += 1

    def _build_step_dependency_graph(self, workflow_steps: List[WorkflowStep]) -> Dict[str, List[str]]:
        """Build step dependency graph"""
        try:
            graph = {}
            for step in workflow_steps:
                graph[step.step_id] = step.depends_on
            return graph
        except Exception as e:
            logger.error(f"Failed to build dependency graph: {e}")
            return {}

    async def _execute_workflow_step(self, workflow_id: str, step: WorkflowStep) -> bool:
        """Execute individual workflow step"""
        try:
            workflow = self.workflows[workflow_id]
            
            step.status = "running"
            step.started_at = datetime.now(timezone.utc)
            
            # Log step start
            await self._log_orchestration_event(
                workflow_id,
                "step_started",
                f"Step '{step.name}' started"
            )
            
            # Execute step based on action
            success = False
            result = {}
            
            if step.action == "create_environment":
                success, result = await self._execute_create_environment(workflow, step)
            elif step.action == "enable_isolation":
                success, result = await self._execute_enable_isolation(workflow, step)
            elif step.action == "deploy_kali":
                success, result = await self._execute_deploy_kali(workflow, step)
            elif step.action == "deploy_targets":
                success, result = await self._execute_deploy_targets(workflow, step)
            elif step.action == "run_tools":
                success, result = await self._execute_run_tools(workflow, step)
            elif step.action == "generate_report":
                success, result = await self._execute_generate_report(workflow, step)
            elif step.action == "cleanup":
                success, result = await self._execute_cleanup(workflow, step)
            else:
                logger.warning(f"Unknown step action: {step.action}")
                success = False
                result = {"error": f"Unknown action: {step.action}"}
            
            # Update step status
            step.status = "completed" if success else "failed"
            step.completed_at = datetime.now(timezone.utc)
            step.result = result
            
            if not success:
                step.error = result.get("error", "Step execution failed")
            
            # Log step completion
            await self._log_orchestration_event(
                workflow_id,
                "step_completed" if success else "step_failed",
                f"Step '{step.name}' {step.status}"
            )
            
            return success
            
        except Exception as e:
            logger.error(f"Failed to execute workflow step {step.step_id}: {e}")
            
            step.status = "failed"
            step.completed_at = datetime.now(timezone.utc)
            step.error = str(e)
            
            return False

    async def _execute_create_environment(self, workflow: OrchestrationWorkflow, step: WorkflowStep) -> Tuple[bool, Dict[str, Any]]:
        """Execute create environment step"""
        try:
            if not self.environment_manager:
                return False, {"error": "Environment manager not available"}
            
            scenario = workflow.scenario
            
            environment_id = await self.environment_manager.create_environment(
                name=f"Pentest-{workflow.name}",
                security_level=scenario.security_level,
                authorized_by=workflow.authorized_by,
                description=f"Environment for workflow {workflow.workflow_id}",
                duration_hours=scenario.duration_hours,
                resource_limits=scenario.resource_requirements,
                isolation_type=NetworkIsolationType.COMPLETE_ISOLATION
            )
            
            workflow.environment_id = environment_id
            workflow.status = OrchestrationStatus.CONFIGURING
            
            return True, {"environment_id": environment_id}
            
        except Exception as e:
            logger.error(f"Failed to create environment: {e}")
            return False, {"error": str(e)}

    async def _execute_enable_isolation(self, workflow: OrchestrationWorkflow, step: WorkflowStep) -> Tuple[bool, Dict[str, Any]]:
        """Execute enable isolation step"""
        try:
            if not self.isolation_framework or not workflow.environment_id:
                return False, {"error": "Isolation framework not available or no environment ID"}
            
            scenario = workflow.scenario
            
            success = await self.isolation_framework.enable_isolation(
                environment_id=workflow.environment_id,
                isolation_level=scenario.isolation_level,
                resource_limits=ResourceLimit(
                    cpu_percent=80.0,
                    memory_percent=80.0,
                    network_io_mbps=scenario.resource_requirements.network_bandwidth_mbps
                )
            )
            
            return success, {"isolation_enabled": success}
            
        except Exception as e:
            logger.error(f"Failed to enable isolation: {e}")
            return False, {"error": str(e)}

    async def _execute_deploy_kali(self, workflow: OrchestrationWorkflow, step: WorkflowStep) -> Tuple[bool, Dict[str, Any]]:
        """Execute deploy Kali step"""
        try:
            if not self.infrastructure_manager or not workflow.environment_id:
                return False, {"error": "Infrastructure manager not available or no environment ID"}
            
            tools_config = step.parameters.get("tools", [])
            
            deployment_id = await self.infrastructure_manager.deploy_kali_linux(
                environment_id=workflow.environment_id,
                tools_config=None,  # Use defaults for now
                custom_config={"environment": {"PENTEST_WORKFLOW": workflow.workflow_id}}
            )
            
            workflow.infrastructure_deployments.append(deployment_id)
            
            return True, {"deployment_id": deployment_id}
            
        except Exception as e:
            logger.error(f"Failed to deploy Kali: {e}")
            return False, {"error": str(e)}

    async def _execute_deploy_targets(self, workflow: OrchestrationWorkflow, step: WorkflowStep) -> Tuple[bool, Dict[str, Any]]:
        """Execute deploy targets step"""
        try:
            if not self.infrastructure_manager or not workflow.environment_id:
                return False, {"error": "Infrastructure manager not available or no environment ID"}
            
            target_systems = step.parameters.get("target_systems", [])
            
            # Convert target system definitions to TargetSystemConfig objects
            target_configs = []
            for target_data in target_systems:
                # This would need proper implementation based on target_data structure
                pass
            
            if target_configs:
                deployment_id = await self.infrastructure_manager.deploy_target_systems(
                    environment_id=workflow.environment_id,
                    target_configs=target_configs
                )
                
                workflow.infrastructure_deployments.append(deployment_id)
                
                return True, {"deployment_id": deployment_id}
            
            return True, {"message": "No target systems to deploy"}
            
        except Exception as e:
            logger.error(f"Failed to deploy targets: {e}")
            return False, {"error": str(e)}

    async def _execute_run_tools(self, workflow: OrchestrationWorkflow, step: WorkflowStep) -> Tuple[bool, Dict[str, Any]]:
        """Execute run tools step"""
        try:
            if not self.infrastructure_manager:
                return False, {"error": "Infrastructure manager not available"}
            
            tools = step.parameters.get("tools", [])
            results = {}
            
            # Find Kali deployment
            kali_deployment = None
            for deployment_id in workflow.infrastructure_deployments:
                deployment_status = await self.infrastructure_manager.get_deployment_status(deployment_id)
                if deployment_status.get("infrastructure_type") == "kali_linux":
                    kali_deployment = deployment_id
                    break
            
            if not kali_deployment:
                return False, {"error": "No Kali deployment found"}
            
            # Execute tools
            for tool in tools:
                try:
                    tool_result = await self.infrastructure_manager.execute_tool(
                        deployment_id=kali_deployment,
                        tool_name=tool,
                        target="target-dvwa",  # This should be dynamic
                        timeout=step.timeout_minutes * 60
                    )
                    results[tool] = tool_result
                except Exception as e:
                    logger.warning(f"Tool {tool} execution failed: {e}")
                    results[tool] = {"error": str(e)}
            
            workflow.test_results.update(results)
            workflow.status = OrchestrationStatus.TESTING
            
            return True, {"tool_results": results}
            
        except Exception as e:
            logger.error(f"Failed to run tools: {e}")
            return False, {"error": str(e)}

    async def _execute_generate_report(self, workflow: OrchestrationWorkflow, step: WorkflowStep) -> Tuple[bool, Dict[str, Any]]:
        """Execute generate report step"""
        try:
            # Generate report based on test results
            report_data = {
                "workflow_id": workflow.workflow_id,
                "scenario": workflow.scenario.name,
                "test_results": workflow.test_results,
                "environment_id": workflow.environment_id,
                "generated_at": datetime.now(timezone.utc).isoformat()
            }
            
            # Store report (in real implementation, would generate proper report)
            workflow.test_results["final_report"] = report_data
            
            return True, {"report_generated": True}
            
        except Exception as e:
            logger.error(f"Failed to generate report: {e}")
            return False, {"error": str(e)}

    async def _execute_cleanup(self, workflow: OrchestrationWorkflow, step: WorkflowStep) -> Tuple[bool, Dict[str, Any]]:
        """Execute cleanup step"""
        try:
            cleanup_results = {}
            
            # Cleanup environment
            if workflow.environment_id and self.environment_manager:
                try:
                    success = await self.environment_manager.destroy_environment(
                        workflow.environment_id, force=True
                    )
                    cleanup_results["environment_cleanup"] = success
                except Exception as e:
                    logger.warning(f"Environment cleanup failed: {e}")
                    cleanup_results["environment_cleanup"] = False
            
            # Disable isolation
            if workflow.environment_id and self.isolation_framework:
                try:
                    success = await self.isolation_framework.disable_isolation(
                        workflow.environment_id
                    )
                    cleanup_results["isolation_cleanup"] = success
                except Exception as e:
                    logger.warning(f"Isolation cleanup failed: {e}")
                    cleanup_results["isolation_cleanup"] = False
            
            workflow.status = OrchestrationStatus.CLEANUP
            
            return True, {"cleanup_results": cleanup_results}
            
        except Exception as e:
            logger.error(f"Failed to cleanup: {e}")
            return False, {"error": str(e)}

    async def _cleanup_workflow_resources(self, workflow_id: str) -> None:
        """Cleanup workflow resources"""
        try:
            workflow = self.workflows[workflow_id]
            
            # Force cleanup of environment
            if workflow.environment_id and self.environment_manager:
                await self.environment_manager.destroy_environment(
                    workflow.environment_id, force=True
                )
            
            # Disable isolation
            if workflow.environment_id and self.isolation_framework:
                await self.isolation_framework.disable_isolation(
                    workflow.environment_id
                )
            
            logger.info(f"Cleaned up resources for workflow {workflow_id}")
            
        except Exception as e:
            logger.error(f"Failed to cleanup workflow resources: {e}")

    def _start_monitoring(self) -> None:
        """Start background monitoring"""
        try:
            async def monitoring_loop():
                while True:
                    try:
                        await self._monitor_workflows()
                        await asyncio.sleep(self.config['workflow_monitoring_interval'])
                    except Exception as e:
                        logger.error(f"Error in workflow monitoring: {e}")
                        await asyncio.sleep(self.config['workflow_monitoring_interval'])
            
            self._monitoring_task = asyncio.create_task(monitoring_loop())
            
        except Exception as e:
            logger.error(f"Failed to start monitoring: {e}")

    async def _monitor_workflows(self) -> None:
        """Monitor active workflows"""
        try:
            current_time = datetime.now(timezone.utc)
            
            for workflow_id in list(self.active_workflows):
                workflow = self.workflows[workflow_id]
                
                # Check for timeout
                if workflow.started_at:
                    duration = (current_time - workflow.started_at).total_seconds() / 60
                    if duration > self.config['default_timeout_minutes']:
                        logger.warning(f"Workflow {workflow_id} timed out")
                        await self.cancel_workflow(workflow_id)
                        continue
                
                # Update workflow metrics
                if workflow.environment_id and self.environment_manager:
                    try:
                        env_status = await self.environment_manager.get_environment_status(
                            workflow.environment_id
                        )
                        workflow.metrics = env_status.get('resource_usage', {})
                    except Exception as e:
                        logger.warning(f"Failed to get environment metrics: {e}")
                        
        except Exception as e:
            logger.error(f"Failed to monitor workflows: {e}")

    async def _log_orchestration_event(self, workflow_id: str, event_type: str, message: str) -> None:
        """Log orchestration events"""
        try:
            if not self.audit_logger:
                return
            
            event_data = {
                'workflow_id': workflow_id,
                'event_type': event_type,
                'message': message,
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'component': 'environment_orchestrator'
            }
            
            await self.audit_logger.log_event(
                event_type="ORCHESTRATION_EVENT",
                severity="INFO",
                resource_type="orchestration_workflow",
                resource_id=workflow_id,
                action=event_type,
                additional_data=event_data
            )
            
        except Exception as e:
            logger.error(f"Failed to log orchestration event: {e}")


def create_environment_orchestrator(environment_manager=None,
                                  infrastructure_manager=None,
                                  isolation_framework=None,
                                  audit_logger=None,
                                  monitoring_system=None):
    """
    Factory function to create an EnvironmentOrchestrator instance.
    
    Args:
        environment_manager: Isolated test environment manager
        infrastructure_manager: Testing infrastructure manager
        isolation_framework: Security isolation framework
        audit_logger: Audit logging system integration
        monitoring_system: Security monitoring system integration
        
    Returns:
        EnvironmentOrchestrator instance
    """
    return EnvironmentOrchestrator(
        environment_manager=environment_manager,
        infrastructure_manager=infrastructure_manager,
        isolation_framework=isolation_framework,
        audit_logger=audit_logger,
        monitoring_system=monitoring_system
    )


# Example usage
if __name__ == "__main__":
    async def example_usage():
        """Example usage of the environment orchestrator"""
        
        # Create orchestrator
        orchestrator = create_environment_orchestrator()
        
        # Create a workflow
        workflow_id = await orchestrator.create_workflow(
            scenario_id="web_app_basic",
            workflow_name="Basic Web App Test",
            created_by="security_team",
            authorized_by="ciso@company.com"
        )
        
        print(f"Created workflow: {workflow_id}")
        
        # Start workflow
        started = await orchestrator.start_workflow(workflow_id)
        print(f"Workflow started: {started}")
        
        # Monitor workflow progress
        for i in range(10):
            await asyncio.sleep(30)  # Wait 30 seconds
            status = await orchestrator.get_workflow_status(workflow_id)
            print(f"Workflow status: {status['status']}")
            
            if status['status'] in ['completed', 'failed', 'cancelled']:
                break
        
        # Get final metrics
        metrics = await orchestrator.get_orchestration_metrics()
        print(f"Orchestration metrics: {metrics}")
    
    # Run example
    asyncio.run(example_usage())