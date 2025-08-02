"""
Security Scenario Framework
===========================

Main framework for creating, managing, and executing security testing scenarios.
Provides pre-defined attack scenarios and supports custom scenario creation
with classification-aware execution and compliance monitoring.

Key Features:
- Pre-defined attack scenario library (OWASP Top 10, MITRE ATT&CK)
- Custom scenario creation and configuration
- Multi-stage attack simulation support
- Classification-aware scenario generation
- Integration with compliance testing requirements
- Real-time scenario monitoring and reporting

Classification: UNCLASSIFIED//FOR OFFICIAL USE ONLY
Version: 1.0
Author: Security Compliance Team
Date: 2025-07-28
"""

import asyncio
import json
import logging
import uuid
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Tuple, Set, Union, AsyncGenerator
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
import yaml

# Import existing infrastructure
from ...multi_classification.enhanced_classification_engine import (
    ClassificationLevel,
    SecurityLabel
)
from ...audits.audit_logger import AuditLogger
from ...audits.enhanced_monitoring_system import EnhancedMonitoringSystem
from ...rbac.models.data_classification import NetworkDomain

logger = logging.getLogger(__name__)

class ScenarioType(Enum):
    """Types of security scenarios."""
    WEB_APPLICATION = "web_application"
    NETWORK_PENETRATION = "network_penetration"
    SOCIAL_ENGINEERING = "social_engineering"
    PHYSICAL_SECURITY = "physical_security"
    WIRELESS_SECURITY = "wireless_security"
    CLOUD_SECURITY = "cloud_security"
    API_SECURITY = "api_security"
    DATABASE_SECURITY = "database_security"
    MOBILE_SECURITY = "mobile_security"
    IOT_SECURITY = "iot_security"

class ScenarioComplexity(Enum):
    """Complexity levels for scenarios."""
    BASIC = "basic"
    INTERMEDIATE = "intermediate"
    ADVANCED = "advanced"
    EXPERT = "expert"

class ScenarioStatus(Enum):
    """Execution status of scenarios."""
    CREATED = "created"
    CONFIGURED = "configured"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

@dataclass
class ScenarioStep:
    """Individual step in a security scenario."""
    step_id: str
    name: str
    description: str
    step_type: str  # command, validation, wait, etc.
    parameters: Dict[str, Any] = field(default_factory=dict)
    expected_outcome: Optional[str] = None
    timeout_seconds: int = 300
    required_tools: List[str] = field(default_factory=list)
    classification_level: ClassificationLevel = ClassificationLevel.UNCLASSIFIED
    depends_on: List[str] = field(default_factory=list)

@dataclass
class ScenarioConfiguration:
    """Configuration for a security scenario."""
    scenario_id: str
    name: str
    description: str
    scenario_type: ScenarioType
    complexity: ScenarioComplexity
    classification_level: ClassificationLevel
    network_domain: NetworkDomain = NetworkDomain.NIPR
    target_systems: List[str] = field(default_factory=list)
    required_tools: List[str] = field(default_factory=list)
    estimated_duration: int = 3600  # seconds
    prerequisites: List[str] = field(default_factory=list)
    learning_objectives: List[str] = field(default_factory=list)
    compliance_frameworks: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    steps: List[ScenarioStep] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class ScenarioExecution:
    """Execution context and results for a scenario."""
    execution_id: str
    scenario_id: str
    status: ScenarioStatus
    started_at: datetime
    completed_at: Optional[datetime] = None
    current_step: int = 0
    total_steps: int = 0
    step_results: List[Dict[str, Any]] = field(default_factory=list)
    execution_logs: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    metrics: Dict[str, Any] = field(default_factory=dict)
    artifacts: List[str] = field(default_factory=list)

class SecurityScenarioFramework:
    """
    Main security scenario framework for managing penetration testing scenarios.
    
    Provides comprehensive scenario management with classification awareness,
    compliance monitoring, and integration with existing security infrastructure.
    """
    
    def __init__(self,
                 audit_logger: Optional[AuditLogger] = None,
                 monitoring_system: Optional[EnhancedMonitoringSystem] = None):
        """Initialize the security scenario framework."""
        self.audit_logger = audit_logger
        self.monitoring_system = monitoring_system
        
        # Scenario storage
        self.scenarios: Dict[str, ScenarioConfiguration] = {}
        self.executions: Dict[str, ScenarioExecution] = {}
        
        # Framework state
        self.framework_stats = {
            'scenarios_created': 0,
            'scenarios_executed': 0,
            'total_execution_time': 0,
            'success_rate': 0.0,
            'classification_distribution': {}
        }
        
        # Load built-in scenarios
        asyncio.create_task(self._load_builtin_scenarios())
        
        logger.info("SecurityScenarioFramework initialized")
    
    async def create_scenario(self, 
                            config: ScenarioConfiguration) -> str:
        """
        Create a new security scenario.
        
        Args:
            config: Scenario configuration
            
        Returns:
            Scenario ID
        """
        try:
            scenario_id = config.scenario_id or str(uuid.uuid4())
            config.scenario_id = scenario_id
            
            # Validate configuration
            await self._validate_scenario_config(config)
            
            # Store scenario
            self.scenarios[scenario_id] = config
            
            # Update statistics
            self.framework_stats['scenarios_created'] += 1
            class_level = config.classification_level.value
            self.framework_stats['classification_distribution'][class_level] = \
                self.framework_stats['classification_distribution'].get(class_level, 0) + 1
            
            # Audit scenario creation
            if self.audit_logger:
                await self.audit_logger.log_event(
                    event_type="scenario_created",
                    data={
                        'scenario_id': scenario_id,
                        'scenario_type': config.scenario_type.value,
                        'complexity': config.complexity.value,
                        'classification': config.classification_level.value
                    },
                    classification=config.classification_level
                )
            
            logger.info(f"Created scenario {scenario_id}: {config.name}")
            return scenario_id
            
        except Exception as e:
            error_msg = f"Failed to create scenario: {str(e)}"
            logger.error(error_msg)
            raise
    
    async def execute_scenario(self, 
                             scenario_id: str,
                             execution_params: Optional[Dict[str, Any]] = None) -> str:
        """
        Execute a security scenario.
        
        Args:
            scenario_id: ID of scenario to execute
            execution_params: Optional execution parameters
            
        Returns:
            Execution ID
        """
        try:
            if scenario_id not in self.scenarios:
                raise ValueError(f"Scenario {scenario_id} not found")
            
            scenario = self.scenarios[scenario_id]
            execution_id = str(uuid.uuid4())
            
            # Create execution context
            execution = ScenarioExecution(
                execution_id=execution_id,
                scenario_id=scenario_id,
                status=ScenarioStatus.RUNNING,
                started_at=datetime.now(timezone.utc),
                total_steps=len(scenario.steps)
            )
            
            self.executions[execution_id] = execution
            
            # Start monitoring if available
            if self.monitoring_system:
                await self.monitoring_system.start_scenario_monitoring(execution_id)
            
            # Audit execution start
            if self.audit_logger:
                await self.audit_logger.log_event(
                    event_type="scenario_execution_started",
                    data={
                        'execution_id': execution_id,
                        'scenario_id': scenario_id,
                        'scenario_name': scenario.name
                    },
                    classification=scenario.classification_level
                )
            
            # Execute scenario steps
            await self._execute_scenario_steps(execution, scenario, execution_params or {})
            
            logger.info(f"Started execution {execution_id} for scenario {scenario_id}")
            return execution_id
            
        except Exception as e:
            error_msg = f"Failed to execute scenario: {str(e)}"
            logger.error(error_msg)
            raise
    
    async def _execute_scenario_steps(self, 
                                    execution: ScenarioExecution,
                                    scenario: ScenarioConfiguration,
                                    params: Dict[str, Any]) -> None:
        """Execute all steps in a scenario."""
        try:
            for i, step in enumerate(scenario.steps):
                execution.current_step = i + 1
                
                # Check dependencies
                if not await self._check_step_dependencies(step, execution):
                    error_msg = f"Step {step.step_id} dependencies not met"
                    execution.errors.append(error_msg)
                    execution.status = ScenarioStatus.FAILED
                    return
                
                # Execute step
                step_result = await self._execute_step(step, execution, params)
                execution.step_results.append(step_result)
                
                # Check if step failed
                if not step_result.get('success', False):
                    error_msg = f"Step {step.step_id} failed: {step_result.get('error', 'Unknown error')}"
                    execution.errors.append(error_msg)
                    execution.status = ScenarioStatus.FAILED
                    return
                
                # Log progress
                execution.execution_logs.append(
                    f"Step {i+1}/{len(scenario.steps)} completed: {step.name}"
                )
            
            # Mark execution as completed
            execution.status = ScenarioStatus.COMPLETED
            execution.completed_at = datetime.now(timezone.utc)
            
            # Update statistics
            self.framework_stats['scenarios_executed'] += 1
            execution_time = (execution.completed_at - execution.started_at).total_seconds()
            self.framework_stats['total_execution_time'] += execution_time
            
            # Calculate success rate
            completed_executions = sum(1 for e in self.executions.values() 
                                     if e.status == ScenarioStatus.COMPLETED)
            total_executions = sum(1 for e in self.executions.values() 
                                 if e.status in [ScenarioStatus.COMPLETED, ScenarioStatus.FAILED])
            
            if total_executions > 0:
                self.framework_stats['success_rate'] = completed_executions / total_executions
            
            # Audit completion
            if self.audit_logger:
                await self.audit_logger.log_event(
                    event_type="scenario_execution_completed",
                    data={
                        'execution_id': execution.execution_id,
                        'scenario_id': execution.scenario_id,
                        'duration_seconds': execution_time,
                        'steps_completed': len(execution.step_results),
                        'success': True
                    },
                    classification=scenario.classification_level
                )
            
        except Exception as e:
            execution.status = ScenarioStatus.FAILED
            execution.completed_at = datetime.now(timezone.utc)
            execution.errors.append(str(e))
            
            logger.error(f"Scenario execution failed: {str(e)}")
    
    async def _execute_step(self, 
                          step: ScenarioStep,
                          execution: ScenarioExecution,
                          params: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a single scenario step."""
        start_time = datetime.now(timezone.utc)
        
        try:
            # Step type handlers
            handlers = {
                'command': self._execute_command_step,
                'validation': self._execute_validation_step,
                'wait': self._execute_wait_step,
                'data_generation': self._execute_data_generation_step,
                'network_scan': self._execute_network_scan_step,
                'vulnerability_scan': self._execute_vulnerability_scan_step,
                'exploit': self._execute_exploit_step,
                'report': self._execute_report_step
            }
            
            handler = handlers.get(step.step_type, self._execute_generic_step)
            result = await handler(step, execution, params)
            
            end_time = datetime.now(timezone.utc)
            duration = (end_time - start_time).total_seconds()
            
            return {
                'step_id': step.step_id,
                'step_name': step.name,
                'success': True,
                'duration_seconds': duration,
                'result': result,
                'timestamp': start_time.isoformat()
            }
            
        except Exception as e:
            end_time = datetime.now(timezone.utc)
            duration = (end_time - start_time).total_seconds()
            
            return {
                'step_id': step.step_id,
                'step_name': step.name,
                'success': False,
                'duration_seconds': duration,
                'error': str(e),
                'timestamp': start_time.isoformat()
            }
    
    async def _execute_command_step(self, 
                                  step: ScenarioStep,
                                  execution: ScenarioExecution,
                                  params: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a command step."""
        command = step.parameters.get('command')
        if not command:
            raise ValueError("Command step requires 'command' parameter")
        
        # Simulate command execution for safety
        # In a real implementation, this would execute actual commands
        # with proper sandboxing and security controls
        
        await asyncio.sleep(1)  # Simulate execution time
        
        return {
            'command': command,
            'stdout': f"Simulated output for: {command}",
            'stderr': "",
            'exit_code': 0,
            'execution_time': 1.0
        }
    
    async def _execute_validation_step(self, 
                                     step: ScenarioStep,
                                     execution: ScenarioExecution,
                                     params: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a validation step."""
        validation_type = step.parameters.get('validation_type')
        expected_value = step.parameters.get('expected_value')
        
        # Simulate validation
        await asyncio.sleep(0.5)
        
        return {
            'validation_type': validation_type,
            'expected_value': expected_value,
            'actual_value': expected_value,  # Simulate success
            'passed': True
        }
    
    async def _execute_wait_step(self, 
                               step: ScenarioStep,
                               execution: ScenarioExecution,
                               params: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a wait step."""
        wait_time = step.parameters.get('wait_seconds', 5)
        
        await asyncio.sleep(wait_time)
        
        return {
            'wait_seconds': wait_time,
            'completed': True
        }
    
    async def _execute_data_generation_step(self, 
                                          step: ScenarioStep,
                                          execution: ScenarioExecution,
                                          params: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a data generation step."""
        data_type = step.parameters.get('data_type', 'users')
        volume = step.parameters.get('volume', 100)
        
        # This would integrate with the TestDataGenerator
        return {
            'data_type': data_type,
            'volume': volume,
            'generated_data_id': str(uuid.uuid4()),
            'status': 'completed'
        }
    
    async def _execute_network_scan_step(self, 
                                       step: ScenarioStep,
                                       execution: ScenarioExecution,
                                       params: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a network scan step."""
        target = step.parameters.get('target')
        scan_type = step.parameters.get('scan_type', 'basic')
        
        # Simulate network scan
        await asyncio.sleep(2)
        
        return {
            'target': target,
            'scan_type': scan_type,
            'open_ports': [22, 80, 443],
            'services': ['ssh', 'http', 'https'],
            'vulnerabilities_found': 2
        }
    
    async def _execute_vulnerability_scan_step(self, 
                                             step: ScenarioStep,
                                             execution: ScenarioExecution,
                                             params: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a vulnerability scan step."""
        target = step.parameters.get('target')
        scan_profile = step.parameters.get('scan_profile', 'standard')
        
        # Simulate vulnerability scan
        await asyncio.sleep(3)
        
        return {
            'target': target,
            'scan_profile': scan_profile,
            'vulnerabilities': [
                {'cve': 'CVE-2023-1234', 'severity': 'high'},
                {'cve': 'CVE-2023-5678', 'severity': 'medium'}
            ],
            'total_vulnerabilities': 2
        }
    
    async def _execute_exploit_step(self, 
                                  step: ScenarioStep,
                                  execution: ScenarioExecution,
                                  params: Dict[str, Any]) -> Dict[str, Any]:
        """Execute an exploit step."""
        exploit_name = step.parameters.get('exploit_name')
        target = step.parameters.get('target')
        
        # Simulate exploit execution (safely)
        await asyncio.sleep(1.5)
        
        return {
            'exploit_name': exploit_name,
            'target': target,
            'success': True,
            'access_gained': 'user',
            'evidence_collected': ['screenshot', 'command_output']
        }
    
    async def _execute_report_step(self, 
                                 step: ScenarioStep,
                                 execution: ScenarioExecution,
                                 params: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a report generation step."""
        report_type = step.parameters.get('report_type', 'summary')
        
        return {
            'report_type': report_type,
            'report_id': str(uuid.uuid4()),
            'generated_at': datetime.now(timezone.utc).isoformat(),
            'status': 'completed'
        }
    
    async def _execute_generic_step(self, 
                                  step: ScenarioStep,
                                  execution: ScenarioExecution,
                                  params: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a generic step."""
        await asyncio.sleep(0.5)
        
        return {
            'step_type': step.step_type,
            'parameters': step.parameters,
            'status': 'completed'
        }
    
    async def _check_step_dependencies(self, 
                                     step: ScenarioStep,
                                     execution: ScenarioExecution) -> bool:
        """Check if step dependencies are met."""
        if not step.depends_on:
            return True
        
        # Check if all dependent steps have completed successfully
        completed_steps = {
            result['step_id']: result.get('success', False)
            for result in execution.step_results
        }
        
        for dep_step_id in step.depends_on:
            if dep_step_id not in completed_steps or not completed_steps[dep_step_id]:
                return False
        
        return True
    
    async def _validate_scenario_config(self, config: ScenarioConfiguration) -> None:
        """Validate scenario configuration."""
        if not config.name:
            raise ValueError("Scenario name is required")
        
        if not config.steps:
            raise ValueError("Scenario must have at least one step")
        
        # Validate steps
        step_ids = set()
        for step in config.steps:
            if step.step_id in step_ids:
                raise ValueError(f"Duplicate step ID: {step.step_id}")
            step_ids.add(step.step_id)
            
            # Validate dependencies
            for dep_id in step.depends_on:
                if dep_id not in step_ids:
                    # Check if dependency comes later (not allowed)
                    future_ids = {s.step_id for s in config.steps[config.steps.index(step):]}
                    if dep_id in future_ids:
                        raise ValueError(f"Step {step.step_id} cannot depend on future step {dep_id}")
    
    async def _load_builtin_scenarios(self) -> None:
        """Load built-in scenario templates."""
        builtin_scenarios = [
            await self._create_web_app_scenario(),
            await self._create_network_penetration_scenario(),
            await self._create_social_engineering_scenario(),
            await self._create_api_security_scenario()
        ]
        
        for scenario in builtin_scenarios:
            await self.create_scenario(scenario)
        
        logger.info(f"Loaded {len(builtin_scenarios)} built-in scenarios")
    
    async def _create_web_app_scenario(self) -> ScenarioConfiguration:
        """Create a web application penetration testing scenario."""
        return ScenarioConfiguration(
            scenario_id="builtin_web_app_pentest",
            name="Web Application Penetration Test",
            description="Comprehensive web application security assessment",
            scenario_type=ScenarioType.WEB_APPLICATION,
            complexity=ScenarioComplexity.INTERMEDIATE,
            classification_level=ClassificationLevel.UNCLASSIFIED,
            target_systems=["web_app_target"],
            required_tools=["burp_suite", "nmap", "sqlmap"],
            estimated_duration=7200,  # 2 hours
            learning_objectives=[
                "Identify common web vulnerabilities",
                "Perform SQL injection testing",
                "Test for XSS vulnerabilities",
                "Assess authentication mechanisms"
            ],
            compliance_frameworks=["OWASP", "NIST"],
            tags=["web", "owasp_top_10", "beginner_friendly"],
            steps=[
                ScenarioStep(
                    step_id="recon",
                    name="Reconnaissance",
                    description="Gather information about the target application",
                    step_type="network_scan",
                    parameters={
                        'target': 'web_app_target',
                        'scan_type': 'service_discovery'
                    }
                ),
                ScenarioStep(
                    step_id="vuln_scan",
                    name="Vulnerability Scanning",
                    description="Scan for common web vulnerabilities",
                    step_type="vulnerability_scan",
                    parameters={
                        'target': 'web_app_target',
                        'scan_profile': 'web_application'
                    },
                    depends_on=["recon"]
                ),
                ScenarioStep(
                    step_id="sql_injection",
                    name="SQL Injection Testing",
                    description="Test for SQL injection vulnerabilities",
                    step_type="exploit",
                    parameters={
                        'exploit_name': 'sql_injection',
                        'target': 'web_app_target',
                        'payload_type': 'union_based'
                    },
                    depends_on=["vuln_scan"]
                ),
                ScenarioStep(
                    step_id="report_generation",
                    name="Generate Report",
                    description="Generate comprehensive penetration test report",
                    step_type="report",
                    parameters={
                        'report_type': 'penetration_test',
                        'include_remediation': True
                    },
                    depends_on=["sql_injection"]
                )
            ]
        )
    
    async def _create_network_penetration_scenario(self) -> ScenarioConfiguration:
        """Create a network penetration testing scenario."""
        return ScenarioConfiguration(
            scenario_id="builtin_network_pentest",
            name="Network Infrastructure Penetration Test",
            description="Network-focused penetration testing scenario",
            scenario_type=ScenarioType.NETWORK_PENETRATION,
            complexity=ScenarioComplexity.ADVANCED,
            classification_level=ClassificationLevel.UNCLASSIFIED,
            target_systems=["network_infrastructure"],
            required_tools=["nmap", "metasploit", "wireshark"],
            estimated_duration=10800,  # 3 hours
            learning_objectives=[
                "Network discovery and enumeration",
                "Service exploitation",
                "Post-exploitation techniques",
                "Network pivoting"
            ],
            compliance_frameworks=["PTES", "NIST"],
            tags=["network", "infrastructure", "advanced"],
            steps=[
                ScenarioStep(
                    step_id="network_discovery",
                    name="Network Discovery",
                    description="Discover live hosts and services",
                    step_type="network_scan",
                    parameters={
                        'target': '192.168.1.0/24',
                        'scan_type': 'host_discovery'
                    }
                ),
                ScenarioStep(
                    step_id="service_enumeration",
                    name="Service Enumeration",
                    description="Enumerate running services",
                    step_type="network_scan",
                    parameters={
                        'target': 'discovered_hosts',
                        'scan_type': 'service_enumeration'
                    },
                    depends_on=["network_discovery"]
                ),
                ScenarioStep(
                    step_id="exploit_services",
                    name="Service Exploitation",
                    description="Attempt to exploit discovered services",
                    step_type="exploit",
                    parameters={
                        'exploit_name': 'service_exploit',
                        'target': 'vulnerable_services'
                    },
                    depends_on=["service_enumeration"]
                )
            ]
        )
    
    async def _create_social_engineering_scenario(self) -> ScenarioConfiguration:
        """Create a social engineering scenario."""
        return ScenarioConfiguration(
            scenario_id="builtin_social_engineering",
            name="Social Engineering Assessment",
            description="Social engineering and phishing simulation",
            scenario_type=ScenarioType.SOCIAL_ENGINEERING,
            complexity=ScenarioComplexity.BASIC,
            classification_level=ClassificationLevel.UNCLASSIFIED,
            target_systems=["email_system", "phone_system"],
            required_tools=["gophish", "social_engineer_toolkit"],
            estimated_duration=5400,  # 1.5 hours
            learning_objectives=[
                "Craft convincing phishing emails",
                "Understand social engineering tactics",
                "Measure security awareness",
                "Provide security training recommendations"
            ],
            compliance_frameworks=["NIST"],
            tags=["social_engineering", "phishing", "awareness"],
            steps=[
                ScenarioStep(
                    step_id="target_research",
                    name="Target Research",
                    description="Research target organization and personnel",
                    step_type="data_generation",
                    parameters={
                        'data_type': 'users',
                        'volume': 50,
                        'include_social_media': True
                    }
                ),
                ScenarioStep(
                    step_id="phishing_campaign",
                    name="Phishing Campaign",
                    description="Execute phishing email campaign",
                    step_type="command",
                    parameters={
                        'command': 'gophish_campaign --template corporate --targets user_list.csv'
                    },
                    depends_on=["target_research"]
                ),
                ScenarioStep(
                    step_id="analyze_results",
                    name="Analyze Results",
                    description="Analyze campaign effectiveness",
                    step_type="validation",
                    parameters={
                        'validation_type': 'campaign_metrics',
                        'expected_value': 'click_rate_calculated'
                    },
                    depends_on=["phishing_campaign"]
                )
            ]
        )
    
    async def _create_api_security_scenario(self) -> ScenarioConfiguration:
        """Create an API security testing scenario."""
        return ScenarioConfiguration(
            scenario_id="builtin_api_security",
            name="API Security Assessment",
            description="Comprehensive API security testing",
            scenario_type=ScenarioType.API_SECURITY,
            complexity=ScenarioComplexity.INTERMEDIATE,
            classification_level=ClassificationLevel.UNCLASSIFIED,
            target_systems=["api_endpoints"],
            required_tools=["burp_suite", "postman", "owasp_zap"],
            estimated_duration=6300,  # 1.75 hours
            learning_objectives=[
                "API endpoint discovery",
                "Authentication testing",
                "Authorization bypass",
                "Input validation testing"
            ],
            compliance_frameworks=["OWASP API Security"],
            tags=["api", "rest", "security"],
            steps=[
                ScenarioStep(
                    step_id="api_discovery",
                    name="API Discovery",
                    description="Discover API endpoints and documentation",
                    step_type="network_scan",
                    parameters={
                        'target': 'api_server',
                        'scan_type': 'api_discovery'
                    }
                ),
                ScenarioStep(
                    step_id="auth_testing",
                    name="Authentication Testing",
                    description="Test API authentication mechanisms",
                    step_type="exploit",
                    parameters={
                        'exploit_name': 'auth_bypass',
                        'target': 'api_endpoints'
                    },
                    depends_on=["api_discovery"]
                ),
                ScenarioStep(
                    step_id="input_validation",
                    name="Input Validation Testing",
                    description="Test API input validation",
                    step_type="exploit",
                    parameters={
                        'exploit_name': 'input_validation',
                        'target': 'api_endpoints',
                        'payload_types': ['injection', 'overflow', 'malformed']
                    },
                    depends_on=["auth_testing"]
                )
            ]
        )
    
    def get_scenario(self, scenario_id: str) -> Optional[ScenarioConfiguration]:
        """Get scenario configuration by ID."""
        return self.scenarios.get(scenario_id)
    
    def list_scenarios(self, 
                      scenario_type: Optional[ScenarioType] = None,
                      complexity: Optional[ScenarioComplexity] = None,
                      classification: Optional[ClassificationLevel] = None) -> List[ScenarioConfiguration]:
        """List scenarios with optional filtering."""
        results = []
        
        for scenario in self.scenarios.values():
            if scenario_type and scenario.scenario_type != scenario_type:
                continue
            if complexity and scenario.complexity != complexity:
                continue
            if classification and scenario.classification_level != classification:
                continue
            results.append(scenario)
        
        return results
    
    def get_execution(self, execution_id: str) -> Optional[ScenarioExecution]:
        """Get scenario execution by ID."""
        return self.executions.get(execution_id)
    
    def list_executions(self, 
                       scenario_id: Optional[str] = None,
                       status: Optional[ScenarioStatus] = None) -> List[ScenarioExecution]:
        """List scenario executions with optional filtering."""
        results = []
        
        for execution in self.executions.values():
            if scenario_id and execution.scenario_id != scenario_id:
                continue
            if status and execution.status != status:
                continue
            results.append(execution)
        
        return results
    
    async def cancel_execution(self, execution_id: str) -> bool:
        """Cancel a running scenario execution."""
        execution = self.executions.get(execution_id)
        if not execution:
            return False
        
        if execution.status == ScenarioStatus.RUNNING:
            execution.status = ScenarioStatus.CANCELLED
            execution.completed_at = datetime.now(timezone.utc)
            
            # Audit cancellation
            if self.audit_logger:
                await self.audit_logger.log_event(
                    event_type="scenario_execution_cancelled",
                    data={
                        'execution_id': execution_id,
                        'scenario_id': execution.scenario_id
                    },
                    classification=ClassificationLevel.UNCLASSIFIED
                )
            
            logger.info(f"Cancelled execution {execution_id}")
            return True
        
        return False
    
    def get_framework_statistics(self) -> Dict[str, Any]:
        """Get framework usage statistics."""
        return self.framework_stats.copy()
    
    async def export_scenario(self, 
                            scenario_id: str, 
                            format: str = 'yaml') -> Optional[str]:
        """Export scenario configuration."""
        scenario = self.scenarios.get(scenario_id)
        if not scenario:
            return None
        
        scenario_dict = asdict(scenario)
        
        if format.lower() == 'yaml':
            return yaml.dump(scenario_dict, default_flow_style=False)
        elif format.lower() == 'json':
            return json.dumps(scenario_dict, indent=2, default=str)
        
        return None
    
    async def import_scenario(self, 
                            scenario_data: str, 
                            format: str = 'yaml') -> str:
        """Import scenario configuration."""
        try:
            if format.lower() == 'yaml':
                data = yaml.safe_load(scenario_data)
            elif format.lower() == 'json':
                data = json.loads(scenario_data)
            else:
                raise ValueError(f"Unsupported format: {format}")
            
            # Convert to scenario configuration
            scenario = ScenarioConfiguration(**data)
            
            return await self.create_scenario(scenario)
            
        except Exception as e:
            logger.error(f"Failed to import scenario: {str(e)}")
            raise