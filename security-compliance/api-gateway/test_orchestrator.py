"""
Test Orchestrator for DoD API Gateway Integration Testing

This module provides automated test execution orchestration, scheduling, and comprehensive
reporting for all types of tests in the DoD API Gateway integration suite including
unit tests, integration tests, performance tests, and security validation.

Key Features:
- Automated test suite execution and orchestration
- Parallel test execution with dependency management
- Comprehensive test reporting and analytics
- CI/CD pipeline integration
- Test result aggregation and trend analysis
- Automated failure analysis and remediation suggestions
- Performance baseline comparison and regression detection

Test Types Supported:
- Unit and Integration Tests
- Performance and Load Testing
- Security Validation and Penetration Testing
- Compliance Verification Testing
- End-to-end System Testing
"""

import asyncio
import concurrent.futures
import json
import logging
import os
import time
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple, Callable, Union
from dataclasses import dataclass, asdict
from enum import Enum
import subprocess
import threading
from pathlib import Path
import shutil
import tempfile

import pytest
import yaml
from jinja2 import Template

# Import test modules
import sys
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from api_gateway.test_api_gateway import TestDoDAPIGateway, TestAPISecurityControls, TestExternalAPIClient, TestServiceMeshConfig, TestGatewayMonitoring, TestIntegration
from api_gateway.performance_benchmark import PerformanceBenchmark, LoadTestConfig, PerformanceRequirement
from api_gateway.security_validation_suite import SecurityValidationSuite, SecurityTestCategory, ComplianceStandard
from api_gateway.dod_api_gateway import DoDAGWConfig, APIGatewayEnvironment, SecurityClassification


class TestType(Enum):
    """Types of tests that can be orchestrated."""
    UNIT = "unit"
    INTEGRATION = "integration"
    PERFORMANCE = "performance"
    SECURITY = "security"
    COMPLIANCE = "compliance"
    END_TO_END = "end_to_end"
    SMOKE = "smoke"
    REGRESSION = "regression"


class TestPriority(Enum):
    """Test execution priority levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class TestStatus(Enum):
    """Test execution status."""
    PENDING = "pending"
    RUNNING = "running"
    PASSED = "passed"
    FAILED = "failed"
    SKIPPED = "skipped"
    ERROR = "error"
    TIMEOUT = "timeout"


class ExecutionMode(Enum):
    """Test execution modes."""
    SEQUENTIAL = "sequential"
    PARALLEL = "parallel"
    HYBRID = "hybrid"


@dataclass
class TestConfiguration:
    """Configuration for individual test execution."""
    test_id: str
    name: str
    description: str
    test_type: TestType
    priority: TestPriority
    test_class: str
    test_method: Optional[str] = None
    dependencies: List[str] = None
    timeout_seconds: int = 3600
    retry_count: int = 0
    parallel_safe: bool = True
    environment_requirements: Dict[str, Any] = None
    configuration_overrides: Dict[str, Any] = None


@dataclass
class TestExecution:
    """Test execution tracking."""
    test_id: str
    status: TestStatus
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    duration_seconds: float = 0.0
    result_data: Optional[Dict[str, Any]] = None
    error_message: Optional[str] = None
    retry_count: int = 0
    worker_id: Optional[str] = None


@dataclass
class TestSuiteConfiguration:
    """Configuration for test suite execution."""
    suite_name: str
    description: str
    execution_mode: ExecutionMode
    max_parallel_workers: int = 4
    timeout_seconds: int = 7200  # 2 hours
    failure_threshold: float = 0.1  # 10% failure threshold
    environments: List[str] = None
    include_test_types: List[TestType] = None
    exclude_test_types: List[TestType] = None
    performance_baseline: Optional[str] = None
    generate_reports: bool = True


@dataclass
class TestResult:
    """Comprehensive test result."""
    execution_id: str
    suite_name: str
    timestamp: datetime
    total_tests: int
    passed_tests: int
    failed_tests: int
    skipped_tests: int
    error_tests: int
    execution_time_seconds: float
    success_rate: float
    test_executions: List[TestExecution]
    performance_metrics: Optional[Dict[str, Any]] = None
    security_metrics: Optional[Dict[str, Any]] = None
    compliance_metrics: Optional[Dict[str, Any]] = None
    environment_info: Dict[str, Any] = None


@dataclass
class TestReport:
    """Comprehensive test report."""
    report_id: str
    generated_at: datetime
    suite_results: List[TestResult]
    summary_statistics: Dict[str, Any]
    trend_analysis: Dict[str, Any]
    failure_analysis: Dict[str, Any]
    recommendations: List[str]
    artifacts: List[str]


class TestOrchestrator:
    """
    Comprehensive Test Orchestrator for DoD API Gateway
    
    Manages execution of all test types with proper orchestration, dependency
    management, parallel execution, and comprehensive reporting.
    """
    
    def __init__(self, gateway_config: DoDAGWConfig, 
                 redis_url: str = "redis://localhost:6379",
                 work_dir: str = None):
        """Initialize test orchestrator."""
        self.logger = logging.getLogger(__name__)
        self.gateway_config = gateway_config
        self.redis_url = redis_url
        self.work_dir = work_dir or tempfile.mkdtemp(prefix='api_gateway_tests_')
        
        # Test components
        self.performance_benchmark = None
        self.security_suite = None
        
        # Test configurations
        self.test_configurations: Dict[str, TestConfiguration] = {}
        self.suite_configurations: Dict[str, TestSuiteConfiguration] = {}
        
        # Execution tracking
        self.active_executions: Dict[str, TestExecution] = {}
        self.execution_results: List[TestResult] = []
        self.execution_history: List[TestResult] = []
        
        # Worker management
        self.worker_pool = None
        self.max_workers = 4
        
        # Initialize test configurations
        self._initialize_test_configurations()
        self._initialize_suite_configurations()
    
    async def initialize(self) -> None:
        """Initialize test orchestrator components."""
        try:
            # Initialize test components
            self.performance_benchmark = PerformanceBenchmark(self.gateway_config, self.redis_url)
            await self.performance_benchmark.initialize()
            
            self.security_suite = SecurityValidationSuite(self.gateway_config, self.redis_url)
            await self.security_suite.initialize()
            
            # Create work directories
            os.makedirs(os.path.join(self.work_dir, 'reports'), exist_ok=True)
            os.makedirs(os.path.join(self.work_dir, 'artifacts'), exist_ok=True)
            os.makedirs(os.path.join(self.work_dir, 'logs'), exist_ok=True)
            
            # Initialize worker pool
            self.worker_pool = concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers)
            
            # Load execution history
            await self._load_execution_history()
            
            self.logger.info("Test orchestrator initialized")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize test orchestrator: {e}")
            raise
    
    def _initialize_test_configurations(self) -> None:
        """Initialize comprehensive test configurations."""
        
        # Unit Tests
        unit_tests = [
            TestConfiguration(
                test_id="UNIT-001",
                name="DoD API Gateway Unit Tests",
                description="Core API Gateway functionality tests",
                test_type=TestType.UNIT,
                priority=TestPriority.CRITICAL,
                test_class="TestDoDAPIGateway",
                timeout_seconds=300,
                parallel_safe=True
            ),
            TestConfiguration(
                test_id="UNIT-002",
                name="Security Controls Unit Tests",
                description="API security controls functionality tests",
                test_type=TestType.UNIT,
                priority=TestPriority.CRITICAL,
                test_class="TestAPISecurityControls",
                timeout_seconds=300,
                parallel_safe=True
            ),
            TestConfiguration(
                test_id="UNIT-003",
                name="External API Client Unit Tests",
                description="External API client functionality tests",
                test_type=TestType.UNIT,
                priority=TestPriority.HIGH,
                test_class="TestExternalAPIClient",
                timeout_seconds=300,
                parallel_safe=True
            ),
            TestConfiguration(
                test_id="UNIT-004",
                name="Service Mesh Config Unit Tests",
                description="Service mesh configuration tests",
                test_type=TestType.UNIT,
                priority=TestPriority.MEDIUM,
                test_class="TestServiceMeshConfig",
                timeout_seconds=300,
                parallel_safe=True
            ),
            TestConfiguration(
                test_id="UNIT-005",
                name="Gateway Monitoring Unit Tests",
                description="Gateway monitoring functionality tests",
                test_type=TestType.UNIT,
                priority=TestPriority.HIGH,
                test_class="TestGatewayMonitoring",
                timeout_seconds=300,
                parallel_safe=True
            )
        ]

        # Integration Tests
        integration_tests = [
            TestConfiguration(
                test_id="INTEGRATION-001",
                name="End-to-End Request Flow",
                description="Complete request flow through API Gateway",
                test_type=TestType.INTEGRATION,
                priority=TestPriority.CRITICAL,
                test_class="TestIntegration",
                test_method="test_end_to_end_request_flow",
                dependencies=["UNIT-001", "UNIT-002"],
                timeout_seconds=600,
                parallel_safe=False
            ),
            TestConfiguration(
                test_id="INTEGRATION-002",
                name="Security Incident Response",
                description="Security incident detection and response workflow",
                test_type=TestType.INTEGRATION,
                priority=TestPriority.CRITICAL,
                test_class="TestIntegration",
                test_method="test_security_incident_response",
                dependencies=["UNIT-002"],
                timeout_seconds=600,
                parallel_safe=False
            ),
            TestConfiguration(
                test_id="INTEGRATION-003",
                name="High Availability Scenarios",
                description="High availability and failover scenarios",
                test_type=TestType.INTEGRATION,
                priority=TestPriority.HIGH,
                test_class="TestIntegration",
                test_method="test_high_availability_scenarios",
                dependencies=["UNIT-003"],
                timeout_seconds=900,
                parallel_safe=False
            ),
            TestConfiguration(
                test_id="INTEGRATION-004",
                name="Classification Data Handling",
                description="Proper handling of classified data",
                test_type=TestType.INTEGRATION,
                priority=TestPriority.CRITICAL,
                test_class="TestIntegration",
                test_method="test_classification_data_handling",
                dependencies=["UNIT-001", "UNIT-002"],
                timeout_seconds=600,
                parallel_safe=False
            )
        ]

        # Performance Tests
        performance_tests = [
            TestConfiguration(
                test_id="PERF-001",
                name="Standard Load Test",
                description="Standard load test with gradual ramp-up",
                test_type=TestType.PERFORMANCE,
                priority=TestPriority.HIGH,
                test_class="PerformanceBenchmark",
                test_method="run_load_test",
                dependencies=["INTEGRATION-001"],
                timeout_seconds=1800,
                parallel_safe=False,
                configuration_overrides={"test_config": "standard_load_test"}
            ),
            TestConfiguration(
                test_id="PERF-002",
                name="Stress Test",
                description="Stress test to find system breaking point",
                test_type=TestType.PERFORMANCE,
                priority=TestPriority.MEDIUM,
                test_class="PerformanceBenchmark",
                test_method="run_load_test",
                dependencies=["PERF-001"],
                timeout_seconds=2400,
                parallel_safe=False,
                configuration_overrides={"test_config": "stress_test"}
            ),
            TestConfiguration(
                test_id="PERF-003",
                name="Spike Test",
                description="Spike test with sudden load increase",
                test_type=TestType.PERFORMANCE,
                priority=TestPriority.MEDIUM,
                test_class="PerformanceBenchmark",
                test_method="run_load_test",
                dependencies=["INTEGRATION-001"],
                timeout_seconds=900,
                parallel_safe=False,
                configuration_overrides={"test_config": "spike_test"}
            )
        ]

        # Security Tests
        security_tests = [
            TestConfiguration(
                test_id="SEC-001",
                name="Authentication Security Tests",
                description="Authentication mechanism security validation",
                test_type=TestType.SECURITY,
                priority=TestPriority.CRITICAL,
                test_class="SecurityValidationSuite",
                test_method="run_security_test_suite",
                dependencies=["UNIT-002"],
                timeout_seconds=1200,
                parallel_safe=True,
                configuration_overrides={"categories": ["AUTHENTICATION"]}
            ),
            TestConfiguration(
                test_id="SEC-002",
                name="Input Validation Security Tests",
                description="Input validation and injection attack protection",
                test_type=TestType.SECURITY,
                priority=TestPriority.CRITICAL,
                test_class="SecurityValidationSuite",
                test_method="run_security_test_suite",
                dependencies=["UNIT-002"],
                timeout_seconds=1200,
                parallel_safe=True,
                configuration_overrides={"categories": ["INPUT_VALIDATION"]}
            ),
            TestConfiguration(
                test_id="SEC-003",
                name="Cryptography Security Tests",
                description="Cryptographic implementation validation",
                test_type=TestType.SECURITY,
                priority=TestPriority.HIGH,
                test_class="SecurityValidationSuite",
                test_method="run_security_test_suite",
                dependencies=["UNIT-001"],
                timeout_seconds=900,
                parallel_safe=True,
                configuration_overrides={"categories": ["CRYPTOGRAPHY"]}
            ),
            TestConfiguration(
                test_id="SEC-004",
                name="Penetration Tests",
                description="Automated penetration testing",
                test_type=TestType.SECURITY,
                priority=TestPriority.HIGH,
                test_class="SecurityValidationSuite",
                test_method="run_penetration_tests",
                dependencies=["SEC-001", "SEC-002"],
                timeout_seconds=1800,
                parallel_safe=False
            )
        ]

        # Compliance Tests
        compliance_tests = [
            TestConfiguration(
                test_id="COMP-001",
                name="DoD 8500 Series Compliance",
                description="DoD 8500 series compliance validation",
                test_type=TestType.COMPLIANCE,
                priority=TestPriority.CRITICAL,
                test_class="SecurityValidationSuite",
                test_method="run_security_test_suite",
                dependencies=["SEC-001", "SEC-002", "SEC-003"],
                timeout_seconds=1800,
                parallel_safe=True,
                configuration_overrides={"compliance_standard": "DOD_8500_SERIES"}
            ),
            TestConfiguration(
                test_id="COMP-002",
                name="NIST 800-53 Compliance",
                description="NIST 800-53 security controls compliance",
                test_type=TestType.COMPLIANCE,
                priority=TestPriority.CRITICAL,
                test_class="SecurityValidationSuite",
                test_method="run_security_test_suite",
                dependencies=["SEC-001", "SEC-002", "SEC-003"],
                timeout_seconds=1800,
                parallel_safe=True,
                configuration_overrides={"compliance_standard": "NIST_800_53"}
            ),
            TestConfiguration(
                test_id="COMP-003",
                name="STIG Compliance",
                description="Security Technical Implementation Guide compliance",
                test_type=TestType.COMPLIANCE,
                priority=TestPriority.HIGH,
                test_class="SecurityValidationSuite",
                test_method="run_security_test_suite",
                dependencies=["SEC-003"],
                timeout_seconds=1200,
                parallel_safe=True,
                configuration_overrides={"compliance_standard": "STIG"}
            )
        ]

        # Add all tests to configurations
        all_tests = unit_tests + integration_tests + performance_tests + security_tests + compliance_tests
        for test_config in all_tests:
            self.test_configurations[test_config.test_id] = test_config

    def _initialize_suite_configurations(self) -> None:
        """Initialize test suite configurations."""

        # Smoke Test Suite - Quick validation
        self.suite_configurations["smoke"] = TestSuiteConfiguration(
            suite_name="Smoke Test Suite",
            description="Quick smoke tests for basic functionality validation",
            execution_mode=ExecutionMode.PARALLEL,
            max_parallel_workers=4,
            timeout_seconds=1800,
            include_test_types=[TestType.UNIT],
            generate_reports=True
        )

        # Full Regression Suite - Comprehensive testing
        self.suite_configurations["regression"] = TestSuiteConfiguration(
            suite_name="Full Regression Test Suite",
            description="Comprehensive regression testing suite",
            execution_mode=ExecutionMode.HYBRID,
            max_parallel_workers=4,
            timeout_seconds=14400,  # 4 hours
            failure_threshold=0.05,  # 5% failure threshold
            generate_reports=True
        )

        # Security Validation Suite
        self.suite_configurations["security"] = TestSuiteConfiguration(
            suite_name="Security Validation Suite",
            description="Comprehensive security testing and validation",
            execution_mode=ExecutionMode.PARALLEL,
            max_parallel_workers=3,
            timeout_seconds=7200,
            include_test_types=[TestType.SECURITY, TestType.COMPLIANCE],
            generate_reports=True
        )

        # Performance Testing Suite
        self.suite_configurations["performance"] = TestSuiteConfiguration(
            suite_name="Performance Testing Suite",
            description="Performance and load testing validation",
            execution_mode=ExecutionMode.SEQUENTIAL,
            max_parallel_workers=1,
            timeout_seconds=10800,  # 3 hours
            include_test_types=[TestType.PERFORMANCE],
            generate_reports=True
        )

        # CI/CD Pipeline Suite - Fast feedback
        self.suite_configurations["ci_cd"] = TestSuiteConfiguration(
            suite_name="CI/CD Pipeline Suite",
            description="Fast feedback tests for CI/CD pipeline",
            execution_mode=ExecutionMode.PARALLEL,
            max_parallel_workers=6,
            timeout_seconds=3600,
            failure_threshold=0.02,  # 2% failure threshold
            include_test_types=[TestType.UNIT, TestType.INTEGRATION],
            exclude_test_types=[TestType.PERFORMANCE],
            generate_reports=True
        )

    async def execute_test_suite(self, suite_name: str,
                               environment_overrides: Optional[Dict[str, Any]] = None) -> TestResult:
        """Execute a configured test suite."""
        if suite_name not in self.suite_configurations:
            raise ValueError(f"Unknown test suite: {suite_name}")

        suite_config = self.suite_configurations[suite_name]
        execution_id = str(uuid.uuid4())
        start_time = datetime.utcnow()

        self.logger.info(f"Starting test suite execution: {suite_name} (ID: {execution_id})")

        try:
            # Filter tests based on suite configuration
            tests_to_execute = self._filter_tests_for_suite(suite_config)

            # Apply environment overrides
            if environment_overrides:
                for test_id in tests_to_execute:
                    if self.test_configurations[test_id].environment_requirements is None:
                        self.test_configurations[test_id].environment_requirements = {}
                    self.test_configurations[test_id].environment_requirements.update(environment_overrides)

            # Execute tests based on execution mode
            if suite_config.execution_mode == ExecutionMode.SEQUENTIAL:
                test_executions = await self._execute_tests_sequential(tests_to_execute, suite_config)
            elif suite_config.execution_mode == ExecutionMode.PARALLEL:
                test_executions = await self._execute_tests_parallel(tests_to_execute, suite_config)
            else:  # HYBRID
                test_executions = await self._execute_tests_hybrid(tests_to_execute, suite_config)

            # Calculate results
            end_time = datetime.utcnow()
            execution_time = (end_time - start_time).total_seconds()

            total_tests = len(test_executions)
            passed_tests = len([e for e in test_executions if e.status == TestStatus.PASSED])
            failed_tests = len([e for e in test_executions if e.status == TestStatus.FAILED])
            skipped_tests = len([e for e in test_executions if e.status == TestStatus.SKIPPED])
            error_tests = len([e for e in test_executions if e.status == TestStatus.ERROR])

            success_rate = (passed_tests / total_tests * 100) if total_tests > 0 else 0

            # Collect performance and security metrics
            performance_metrics = await self._collect_performance_metrics(test_executions)
            security_metrics = await self._collect_security_metrics(test_executions)
            compliance_metrics = await self._collect_compliance_metrics(test_executions)

            # Create test result
            result = TestResult(
                execution_id=execution_id,
                suite_name=suite_name,
                timestamp=start_time,
                total_tests=total_tests,
                passed_tests=passed_tests,
                failed_tests=failed_tests,
                skipped_tests=skipped_tests,
                error_tests=error_tests,
                execution_time_seconds=execution_time,
                success_rate=success_rate,
                test_executions=test_executions,
                performance_metrics=performance_metrics,
                security_metrics=security_metrics,
                compliance_metrics=compliance_metrics,
                environment_info=self._collect_environment_info()
            )

            self.execution_results.append(result)
            await self._save_execution_result(result)

            # Generate reports if configured
            if suite_config.generate_reports:
                await self._generate_test_reports(result)

            self.logger.info(f"Test suite completed: {suite_name} - {passed_tests}/{total_tests} passed ({success_rate:.1f}%)")

            return result

        except Exception as e:
            self.logger.error(f"Test suite execution failed: {e}")
            raise

    def _filter_tests_for_suite(self, suite_config: TestSuiteConfiguration) -> List[str]:
        """Filter tests based on suite configuration."""
        filtered_tests = []

        for test_id, test_config in self.test_configurations.items():
            # Include/exclude by test type
            if suite_config.include_test_types and test_config.test_type not in suite_config.include_test_types:
                continue

            if suite_config.exclude_test_types and test_config.test_type in suite_config.exclude_test_types:
                continue

            filtered_tests.append(test_id)

        return filtered_tests

    async def _execute_tests_sequential(self, test_ids: List[str],
                                       suite_config: TestSuiteConfiguration) -> List[TestExecution]:
        """Execute tests sequentially with dependency resolution."""
        executions = []
        completed_tests = set()

        # Sort tests by dependencies
        sorted_tests = self._sort_tests_by_dependencies(test_ids)

        for test_id in sorted_tests:
            # Check if dependencies are satisfied
            test_config = self.test_configurations[test_id]
            if test_config.dependencies:
                missing_deps = set(test_config.dependencies) - completed_tests
                if missing_deps:
                    self.logger.warning(f"Skipping test {test_id} due to missing dependencies: {missing_deps}")
                    execution = TestExecution(
                        test_id=test_id,
                        status=TestStatus.SKIPPED,
                        error_message=f"Missing dependencies: {missing_deps}"
                    )
                    executions.append(execution)
                    continue

            # Execute test
            execution = await self._execute_single_test(test_id)
            executions.append(execution)

            if execution.status == TestStatus.PASSED:
                completed_tests.add(test_id)

            # Check failure threshold
            failed_count = len([e for e in executions if e.status in [TestStatus.FAILED, TestStatus.ERROR]])
            if failed_count / len(executions) > suite_config.failure_threshold:
                self.logger.warning(f"Failure threshold exceeded ({suite_config.failure_threshold * 100}%), stopping execution")
                # Mark remaining tests as skipped
                remaining_tests = sorted_tests[sorted_tests.index(test_id) + 1:]
                for remaining_test in remaining_tests:
                    execution = TestExecution(
                        test_id=remaining_test,
                        status=TestStatus.SKIPPED,
                        error_message="Skipped due to failure threshold exceeded"
                    )
                    executions.append(execution)
                break

        return executions

    async def _execute_tests_parallel(self, test_ids: List[str],
                                     suite_config: TestSuiteConfiguration) -> List[TestExecution]:
        """Execute tests in parallel with dependency management."""
        executions = []
        completed_tests = set()
        pending_tests = set(test_ids)
        running_tasks = {}

        while pending_tests or running_tasks:
            # Start new tests that have satisfied dependencies
            ready_tests = []
            for test_id in list(pending_tests):
                test_config = self.test_configurations[test_id]
                if not test_config.dependencies or set(test_config.dependencies).issubset(completed_tests):
                    if test_config.parallel_safe and len(running_tasks) < suite_config.max_parallel_workers:
                        ready_tests.append(test_id)

            # Start ready tests
            for test_id in ready_tests:
                if len(running_tasks) >= suite_config.max_parallel_workers:
                    break

                task = asyncio.create_task(self._execute_single_test(test_id))
                running_tasks[test_id] = task
                pending_tests.remove(test_id)

            # Wait for any test to complete
            if running_tasks:
                done, _ = await asyncio.wait(running_tasks.values(), return_when=asyncio.FIRST_COMPLETED)

                for task in done:
                    # Find which test completed
                    completed_test_id = None
                    for test_id, test_task in running_tasks.items():
                        if test_task == task:
                            completed_test_id = test_id
                            break

                    if completed_test_id:
                        execution = await task
                        executions.append(execution)

                        if execution.status == TestStatus.PASSED:
                            completed_tests.add(completed_test_id)

                        del running_tasks[completed_test_id]

                        # Check failure threshold
                        failed_count = len([e for e in executions if e.status in [TestStatus.FAILED, TestStatus.ERROR]])
                        if failed_count / len(executions) > suite_config.failure_threshold:
                            self.logger.warning(f"Failure threshold exceeded, cancelling remaining tests")
                            # Cancel running tasks
                            for remaining_task in running_tasks.values():
                                remaining_task.cancel()
                            # Mark pending tests as skipped
                            for pending_test in pending_tests:
                                execution = TestExecution(
                                    test_id=pending_test,
                                    status=TestStatus.SKIPPED,
                                    error_message="Skipped due to failure threshold exceeded"
                                )
                                executions.append(execution)
                            return executions

            # Small delay to prevent busy waiting
            await asyncio.sleep(0.1)

        return executions

    async def _execute_tests_hybrid(self, test_ids: List[str],
                                   suite_config: TestSuiteConfiguration) -> List[TestExecution]:
        """Execute tests using hybrid approach (parallel where safe, sequential where needed)."""
        # Separate parallel-safe and sequential-only tests
        parallel_tests = [tid for tid in test_ids if self.test_configurations[tid].parallel_safe]
        sequential_tests = [tid for tid in test_ids if not self.test_configurations[tid].parallel_safe]

        executions = []

        # Execute parallel-safe tests first
        if parallel_tests:
            parallel_executions = await self._execute_tests_parallel(parallel_tests, suite_config)
            executions.extend(parallel_executions)

        # Execute sequential tests
        if sequential_tests:
            sequential_executions = await self._execute_tests_sequential(sequential_tests, suite_config)
            executions.extend(sequential_executions)

        return executions

    async def _execute_single_test(self, test_id: str) -> TestExecution:
        """Execute a single test with proper error handling and timeouts."""
        test_config = self.test_configurations[test_id]
        execution = TestExecution(
            test_id=test_id,
            status=TestStatus.RUNNING,
            start_time=datetime.utcnow(),
            worker_id=threading.current_thread().name
        )

        self.active_executions[test_id] = execution

        try:
            self.logger.info(f"Starting test: {test_id} - {test_config.name}")

            # Execute test based on type and configuration
            result_data = None

            if test_config.test_class == "TestDoDAPIGateway":
                result_data = await self._execute_pytest_test(test_config)
            elif test_config.test_class == "PerformanceBenchmark":
                result_data = await self._execute_performance_test(test_config)
            elif test_config.test_class == "SecurityValidationSuite":
                result_data = await self._execute_security_test(test_config)
            else:
                result_data = await self._execute_pytest_test(test_config)

            # Determine test status from result
            if result_data and result_data.get('success', False):
                execution.status = TestStatus.PASSED
            else:
                execution.status = TestStatus.FAILED
                execution.error_message = result_data.get('error', 'Test failed') if result_data else 'No result data'

            execution.result_data = result_data

        except asyncio.TimeoutError:
            execution.status = TestStatus.TIMEOUT
            execution.error_message = f"Test timed out after {test_config.timeout_seconds} seconds"

        except Exception as e:
            execution.status = TestStatus.ERROR
            execution.error_message = str(e)
            self.logger.error(f"Test {test_id} failed with error: {e}")

        finally:
            execution.end_time = datetime.utcnow()
            if execution.start_time:
                execution.duration_seconds = (execution.end_time - execution.start_time).total_seconds()

            if test_id in self.active_executions:
                del self.active_executions[test_id]

            self.logger.info(f"Test completed: {test_id} - {execution.status.value.upper()} ({execution.duration_seconds:.2f}s)")

        return execution

    async def _execute_pytest_test(self, test_config: TestConfiguration) -> Dict[str, Any]:
        """Execute pytest-based test."""
        try:
            # Construct pytest command
            test_file = "test_api_gateway.py"
            test_path = os.path.join(os.path.dirname(__file__), test_file)

            if test_config.test_method:
                test_target = f"{test_path}::{test_config.test_class}::{test_config.test_method}"
            else:
                test_target = f"{test_path}::{test_config.test_class}"

            # Run pytest with timeout
            cmd = ["python", "-m", "pytest", test_target, "-v", "--tb=short"]

            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=os.path.dirname(__file__)
            )

            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=test_config.timeout_seconds
                )

                success = process.returncode == 0

                return {
                    'success': success,
                    'returncode': process.returncode,
                    'stdout': stdout.decode() if stdout else '',
                    'stderr': stderr.decode() if stderr else '',
                    'error': stderr.decode() if stderr and not success else None
                }

            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
                raise asyncio.TimeoutError()

        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }

    async def _execute_performance_test(self, test_config: TestConfiguration) -> Dict[str, Any]:
        """Execute performance test."""
        try:
            # Get test configuration
            config_name = test_config.configuration_overrides.get('test_config', 'standard_load_test')

            # Import and create test config
            from api_gateway.performance_benchmark import (
                create_standard_load_test, create_stress_test, create_spike_test
            )

            config_map = {
                'standard_load_test': create_standard_load_test,
                'stress_test': create_stress_test,
                'spike_test': create_spike_test
            }

            if config_name not in config_map:
                raise ValueError(f"Unknown performance test config: {config_name}")

            load_config = config_map[config_name]()

            # Execute performance test
            result = await self.performance_benchmark.run_load_test(load_config)

            return {
                'success': result.requirements_met,
                'performance_result': asdict(result),
                'error': None if result.requirements_met else f"Performance requirements not met: {result.failed_requirements}"
            }

        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }

    async def _execute_security_test(self, test_config: TestConfiguration) -> Dict[str, Any]:
        """Execute security test."""
        try:
            # Get test configuration
            categories = test_config.configuration_overrides.get('categories')
            compliance_standard = test_config.configuration_overrides.get('compliance_standard')

            if test_config.test_method == 'run_security_test_suite':
                # Convert category strings to enums if provided
                test_categories = None
                if categories:
                    from api_gateway.security_validation_suite import SecurityTestCategory
                    test_categories = [SecurityTestCategory(cat) for cat in categories]

                result = await self.security_suite.run_security_test_suite(test_categories)

                return {
                    'success': result.get('critical_failures', 0) == 0,
                    'security_result': result,
                    'error': None if result.get('critical_failures', 0) == 0 else f"Critical security failures found: {result.get('critical_failures', 0)}"
                }

            elif test_config.test_method == 'run_penetration_tests':
                results = await self.security_suite.run_penetration_tests()

                # Check if any critical vulnerabilities were found
                critical_vulns = [r for r in results if r.vulnerability_found and r.risk_level.value in ['critical', 'high']]

                return {
                    'success': len(critical_vulns) == 0,
                    'penetration_results': [asdict(r) for r in results],
                    'error': None if len(critical_vulns) == 0 else f"Critical vulnerabilities found: {len(critical_vulns)}"
                }

            else:
                raise ValueError(f"Unknown security test method: {test_config.test_method}")

        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }

    def _sort_tests_by_dependencies(self, test_ids: List[str]) -> List[str]:
        """Sort tests by dependencies using topological sort."""
        # Simple topological sort implementation
        sorted_tests = []
        remaining_tests = set(test_ids)

        while remaining_tests:
            # Find tests with no unresolved dependencies
            ready_tests = []
            for test_id in remaining_tests:
                test_config = self.test_configurations[test_id]
                if not test_config.dependencies or all(dep in sorted_tests for dep in test_config.dependencies):
                    ready_tests.append(test_id)

            if not ready_tests:
                # Circular dependency or missing dependency, add remaining tests anyway
                ready_tests = list(remaining_tests)

            # Add ready tests to sorted list
            for test_id in ready_tests:
                sorted_tests.append(test_id)
                remaining_tests.remove(test_id)

        return sorted_tests

    async def _collect_performance_metrics(self, executions: List[TestExecution]) -> Optional[Dict[str, Any]]:
        """Collect performance metrics from test executions."""
        performance_executions = [
            e for e in executions
            if self.test_configurations[e.test_id].test_type == TestType.PERFORMANCE and
            e.result_data and 'performance_result' in e.result_data
        ]

        if not performance_executions:
            return None

        # Aggregate performance metrics
        total_requests = sum(
            e.result_data['performance_result']['total_requests']
            for e in performance_executions
        )

        avg_response_time = sum(
            e.result_data['performance_result']['avg_response_time']
            for e in performance_executions
        ) / len(performance_executions)

        avg_throughput = sum(
            e.result_data['performance_result']['requests_per_second']
            for e in performance_executions
        ) / len(performance_executions)

        return {
            'total_requests': total_requests,
            'average_response_time': avg_response_time,
            'average_throughput': avg_throughput,
            'performance_tests_count': len(performance_executions)
        }

    async def _collect_security_metrics(self, executions: List[TestExecution]) -> Optional[Dict[str, Any]]:
        """Collect security metrics from test executions."""
        security_executions = [
            e for e in executions
            if self.test_configurations[e.test_id].test_type == TestType.SECURITY and
            e.result_data
        ]

        if not security_executions:
            return None

        # Aggregate security metrics
        total_security_tests = sum(
            e.result_data.get('security_result', {}).get('total_tests', 0)
            for e in security_executions
            if 'security_result' in e.result_data
        )

        total_passed_tests = sum(
            e.result_data.get('security_result', {}).get('passed_tests', 0)
            for e in security_executions
            if 'security_result' in e.result_data
        )

        critical_failures = sum(
            e.result_data.get('security_result', {}).get('critical_failures', 0)
            for e in security_executions
            if 'security_result' in e.result_data
        )

        return {
            'total_security_tests': total_security_tests,
            'passed_security_tests': total_passed_tests,
            'critical_security_failures': critical_failures,
            'security_test_suites': len(security_executions)
        }

    async def _collect_compliance_metrics(self, executions: List[TestExecution]) -> Optional[Dict[str, Any]]:
        """Collect compliance metrics from test executions."""
        compliance_executions = [
            e for e in executions
            if self.test_configurations[e.test_id].test_type == TestType.COMPLIANCE and
            e.result_data
        ]

        if not compliance_executions:
            return None

        # Aggregate compliance metrics
        compliance_scores = []
        for execution in compliance_executions:
            if 'security_result' in execution.result_data:
                compliance_summary = execution.result_data['security_result'].get('compliance_summary', {})
                for standard, score in compliance_summary.items():
                    compliance_scores.append({'standard': standard, 'score': score})

        return {
            'compliance_tests_count': len(compliance_executions),
            'compliance_scores': compliance_scores
        }

    def _collect_environment_info(self) -> Dict[str, Any]:
        """Collect environment information."""
        import platform
        import psutil

        return {
            'platform': platform.platform(),
            'python_version': platform.python_version(),
            'cpu_count': psutil.cpu_count(),
            'memory_total_gb': psutil.virtual_memory().total / (1024**3),
            'timestamp': datetime.utcnow().isoformat(),
            'gateway_config': {
                'environment': self.gateway_config.environment.value,
                'service_name': self.gateway_config.service_name,
                'classification': self.gateway_config.security_classification.value
            }
        }

    async def _save_execution_result(self, result: TestResult) -> None:
        """Save test execution result to persistent storage."""
        try:
            result_file = os.path.join(self.work_dir, 'results', f'test_result_{result.execution_id}.json')
            os.makedirs(os.path.dirname(result_file), exist_ok=True)

            with open(result_file, 'w') as f:
                json.dump(asdict(result), f, indent=2, default=str)

            # Also save to history
            history_file = os.path.join(self.work_dir, 'execution_history.json')
            if os.path.exists(history_file):
                with open(history_file, 'r') as f:
                    history = json.load(f)
            else:
                history = []

            history.append(asdict(result))

            with open(history_file, 'w') as f:
                json.dump(history, f, indent=2, default=str)

        except Exception as e:
            self.logger.error(f"Failed to save execution result: {e}")

    async def _load_execution_history(self) -> None:
        """Load execution history from persistent storage."""
        try:
            history_file = os.path.join(self.work_dir, 'execution_history.json')
            if os.path.exists(history_file):
                with open(history_file, 'r') as f:
                    history_data = json.load(f)

                for result_data in history_data:
                    # Convert back to TestResult object
                    result = TestResult(**result_data)
                    self.execution_history.append(result)

                self.logger.info(f"Loaded {len(self.execution_history)} historical test results")

        except Exception as e:
            self.logger.error(f"Failed to load execution history: {e}")

    async def _generate_test_reports(self, result: TestResult) -> None:
        """Generate comprehensive test reports."""
        try:
            # Generate HTML report
            await self._generate_html_report(result)

            # Generate JSON report
            await self._generate_json_report(result)

            # Generate trend analysis if we have history
            if len(self.execution_history) > 1:
                await self._generate_trend_report()

        except Exception as e:
            self.logger.error(f"Failed to generate test reports: {e}")

    async def _generate_html_report(self, result: TestResult) -> None:
        """Generate HTML test report."""
        html_template = """
<!DOCTYPE html>
<html>
<head>
    <title>API Gateway Test Report - {{ result.suite_name }}</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background-color: #f0f0f0; padding: 20px; border-radius: 5px; }
        .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0; }
        .metric { background-color: #e9f5ff; padding: 15px; border-radius: 5px; text-align: center; }
        .passed { background-color: #d4edda; }
        .failed { background-color: #f8d7da; }
        .test-details { margin: 20px 0; }
        .test-item { border: 1px solid #ddd; margin: 10px 0; padding: 15px; border-radius: 5px; }
        .status-passed { color: #28a745; font-weight: bold; }
        .status-failed { color: #dc3545; font-weight: bold; }
        .status-error { color: #ffc107; font-weight: bold; }
    </style>
</head>
<body>
    <div class="header">
        <h1>API Gateway Test Report</h1>
        <h2>{{ result.suite_name }}</h2>
        <p>Execution ID: {{ result.execution_id }}</p>
        <p>Generated: {{ result.timestamp.strftime('%Y-%m-%d %H:%M:%S') }} UTC</p>
    </div>

    <div class="summary">
        <div class="metric{% if result.passed_tests == result.total_tests %} passed{% endif %}">
            <h3>Total Tests</h3>
            <p>{{ result.total_tests }}</p>
        </div>
        <div class="metric passed">
            <h3>Passed</h3>
            <p>{{ result.passed_tests }}</p>
        </div>
        <div class="metric{% if result.failed_tests > 0 %} failed{% endif %}">
            <h3>Failed</h3>
            <p>{{ result.failed_tests }}</p>
        </div>
        <div class="metric">
            <h3>Success Rate</h3>
            <p>{{ "%.1f" | format(result.success_rate) }}%</p>
        </div>
        <div class="metric">
            <h3>Execution Time</h3>
            <p>{{ "%.1f" | format(result.execution_time_seconds) }}s</p>
        </div>
    </div>

    {% if result.performance_metrics %}
    <div class="performance-metrics">
        <h3>Performance Metrics</h3>
        <div class="summary">
            <div class="metric">
                <h4>Total Requests</h4>
                <p>{{ result.performance_metrics.total_requests }}</p>
            </div>
            <div class="metric">
                <h4>Avg Response Time</h4>
                <p>{{ "%.3f" | format(result.performance_metrics.average_response_time) }}s</p>
            </div>
            <div class="metric">
                <h4>Avg Throughput</h4>
                <p>{{ "%.1f" | format(result.performance_metrics.average_throughput) }} RPS</p>
            </div>
        </div>
    </div>
    {% endif %}

    <div class="test-details">
        <h3>Test Details</h3>
        {% for execution in result.test_executions %}
        <div class="test-item">
            <h4>{{ execution.test_id }}</h4>
            <p>Status: <span class="status-{{ execution.status.value }}">{{ execution.status.value.upper() }}</span></p>
            <p>Duration: {{ "%.2f" | format(execution.duration_seconds) }}s</p>
            {% if execution.error_message %}
            <p>Error: {{ execution.error_message }}</p>
            {% endif %}
        </div>
        {% endfor %}
    </div>
</body>
</html>
        """

        template = Template(html_template)
        html_content = template.render(result=result)

        report_file = os.path.join(self.work_dir, 'reports', f'test_report_{result.execution_id}.html')
        os.makedirs(os.path.dirname(report_file), exist_ok=True)

        with open(report_file, 'w') as f:
            f.write(html_content)

        self.logger.info(f"HTML report generated: {report_file}")

    async def _generate_json_report(self, result: TestResult) -> None:
        """Generate JSON test report."""
        report_file = os.path.join(self.work_dir, 'reports', f'test_report_{result.execution_id}.json')
        os.makedirs(os.path.dirname(report_file), exist_ok=True)

        with open(report_file, 'w') as f:
            json.dump(asdict(result), f, indent=2, default=str)

        self.logger.info(f"JSON report generated: {report_file}")

    async def _generate_trend_report(self) -> None:
        """Generate trend analysis report."""
        try:
            # Analyze trends over time
            all_results = self.execution_history + self.execution_results

            # Group by suite name
            suite_trends = {}
            for result in all_results:
                if result.suite_name not in suite_trends:
                    suite_trends[result.suite_name] = []
                suite_trends[result.suite_name].append(result)

            # Generate trend data
            trend_data = {}
            for suite_name, results in suite_trends.items():
                # Sort by timestamp
                results.sort(key=lambda x: x.timestamp)

                trend_data[suite_name] = {
                    'success_rates': [r.success_rate for r in results],
                    'execution_times': [r.execution_time_seconds for r in results],
                    'timestamps': [r.timestamp.isoformat() for r in results],
                    'total_tests': [r.total_tests for r in results]
                }

            # Save trend report
            trend_file = os.path.join(self.work_dir, 'reports', 'trend_analysis.json')
            with open(trend_file, 'w') as f:
                json.dump(trend_data, f, indent=2, default=str)

            self.logger.info(f"Trend analysis report generated: {trend_file}")

        except Exception as e:
            self.logger.error(f"Failed to generate trend report: {e}")

    def get_test_status(self, test_id: str) -> Optional[TestExecution]:
        """Get current status of a specific test."""
        return self.active_executions.get(test_id)

    def list_available_suites(self) -> List[str]:
        """List all available test suites."""
        return list(self.suite_configurations.keys())

    def get_suite_configuration(self, suite_name: str) -> Optional[TestSuiteConfiguration]:
        """Get configuration for a specific test suite."""
        return self.suite_configurations.get(suite_name)

    def get_execution_history(self, suite_name: Optional[str] = None) -> List[TestResult]:
        """Get execution history, optionally filtered by suite name."""
        if suite_name:
            return [r for r in self.execution_history if r.suite_name == suite_name]
        return self.execution_history

    async def cleanup(self) -> None:
        """Clean up orchestrator resources."""
        # Cancel any running tests
        for execution in self.active_executions.values():
            # Mark as cancelled (would need proper task cancellation in real implementation)
            execution.status = TestStatus.ERROR
            execution.error_message = "Test cancelled during cleanup"

        # Close worker pool
        if self.worker_pool:
            self.worker_pool.shutdown(wait=True)

        # Close test components
        if self.performance_benchmark:
            await self.performance_benchmark.close()
        if self.security_suite:
            await self.security_suite.close()

        self.logger.info("Test orchestrator cleanup completed")


if __name__ == "__main__":
    # Example usage
    async def main():
        from auth.oauth_client import OAuthConfig, Platform

        # Create gateway configuration
        oauth_config = OAuthConfig(
            platform=Platform.ADVANA,
            client_id="orchestrator-test-client",
            client_secret="orchestrator-test-secret",
            authorization_url="https://test-auth.mil/oauth/authorize",
            token_url="https://test-auth.mil/oauth/token",
            redirect_uri="https://localhost:8080/callback",
            scopes=["read", "write", "admin"]
        )

        gateway_config = DoDAGWConfig(
            environment=APIGatewayEnvironment.DEVELOPMENT,
            gateway_url="https://orchestrator-test-gateway.mil",
            client_certificate_path="/tmp/orchestrator-test-client.crt",
            private_key_path="/tmp/orchestrator-test-client.key",
            ca_bundle_path="/tmp/orchestrator-test-ca.crt",
            oauth_config=oauth_config,
            service_name="orchestrator-test-service",
            service_version="1.0.0",
            security_classification=SecurityClassification.UNCLASSIFIED
        )

        # Initialize test orchestrator
        orchestrator = TestOrchestrator(gateway_config)
        await orchestrator.initialize()

        try:
            # List available test suites
            print("Available test suites:")
            for suite in orchestrator.list_available_suites():
                print(f"- {suite}")

            # Run smoke test suite
            print("\
Running smoke test suite...")
            smoke_result = await orchestrator.execute_test_suite("smoke")
            print(f"Smoke tests: {smoke_result.passed_tests}/{smoke_result.total_tests} passed ({smoke_result.success_rate:.1f}%)")

            # Run security test suite
            print("\
Running security test suite...")
            security_result = await orchestrator.execute_test_suite("security")
            print(f"Security tests: {security_result.passed_tests}/{security_result.total_tests} passed ({security_result.success_rate:.1f}%)")

            # Show execution history
            history = orchestrator.get_execution_history()
            print(f"\
Total test executions in history: {len(history)}")

        finally:
            await orchestrator.cleanup()

    asyncio.run(main())
