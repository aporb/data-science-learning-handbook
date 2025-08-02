"""
Penetration Testing Framework Integration Example
===============================================

Comprehensive example demonstrating the integration of all penetration testing
framework components with existing security infrastructure.

This example shows how to:
1. Generate classification-aware test data
2. Create and execute security scenarios
3. Deploy target systems for testing
4. Manage data lifecycle with secure cleanup
5. Monitor and audit all activities

Classification: UNCLASSIFIED//FOR OFFICIAL USE ONLY
Version: 1.0
Author: Security Compliance Team
Date: 2025-07-28
"""

import asyncio
import logging
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any

# Import framework components
from .data.test_data_generator import (
    TestDataGenerator, TestDataConfiguration, TestDataType
)
from .scenarios.scenario_framework import (
    SecurityScenarioFramework, ScenarioConfiguration, ScenarioType,
    ScenarioComplexity, ScenarioStep
)
from .targets.target_simulator import (
    TargetSystemSimulator, TargetConfiguration, TargetType,
    VulnerabilityLevel
)
from .management.data_manager import (
    PenetrationTestDataManager, SanitizationMethod
)

# Import existing security infrastructure
from ..multi_classification.enhanced_classification_engine import (
    EnhancedClassificationEngine, ClassificationLevel
)
from ..audits.audit_logger import AuditLogger
from ..audits.enhanced_monitoring_system import EnhancedMonitoringSystem
from ..rbac.models.data_classification import NetworkDomain

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class PenetrationTestingOrchestrator:
    """
    Main orchestrator for penetration testing framework integration.
    
    Coordinates all framework components and integrates with existing
    security infrastructure for comprehensive testing capabilities.
    """
    
    def __init__(self):
        """Initialize the penetration testing orchestrator."""
        # Initialize existing infrastructure components
        self.classification_engine = EnhancedClassificationEngine()
        self.audit_logger = AuditLogger()
        self.monitoring_system = EnhancedMonitoringSystem()
        
        # Initialize framework components
        self.data_generator = TestDataGenerator(
            classification_engine=self.classification_engine,
            audit_logger=self.audit_logger
        )
        
        self.scenario_framework = SecurityScenarioFramework(
            audit_logger=self.audit_logger,
            monitoring_system=self.monitoring_system
        )
        
        self.target_simulator = TargetSystemSimulator(
            audit_logger=self.audit_logger
        )
        
        self.data_manager = PenetrationTestDataManager(
            audit_logger=self.audit_logger
        )
        
        logger.info("PenetrationTestingOrchestrator initialized")
    
    async def run_comprehensive_test(self, 
                                   test_name: str,
                                   classification_level: ClassificationLevel = ClassificationLevel.UNCLASSIFIED,
                                   scenario_type: ScenarioType = ScenarioType.WEB_APPLICATION) -> Dict[str, Any]:
        """
        Run a comprehensive penetration test integrating all components.
        
        Args:
            test_name: Name of the test
            classification_level: Classification level for test data
            scenario_type: Type of security scenario to run
            
        Returns:
            Test results summary
        """
        test_start_time = datetime.now(timezone.utc)
        test_results = {
            'test_name': test_name,
            'start_time': test_start_time.isoformat(),
            'classification_level': classification_level.value,
            'scenario_type': scenario_type.value,
            'components_used': [],
            'data_generated': [],
            'targets_deployed': [],
            'scenarios_executed': [],
            'cleanup_completed': False,
            'status': 'running'
        }
        
        try:
            logger.info(f"Starting comprehensive penetration test: {test_name}")
            
            # Step 1: Generate test data
            logger.info("Step 1: Generating test data...")
            test_data_ids = await self._generate_test_data(classification_level)
            test_results['data_generated'] = test_data_ids
            test_results['components_used'].append('TestDataGenerator')
            
            # Step 2: Deploy target systems
            logger.info("Step 2: Deploying target systems...")
            target_instance_ids = await self._deploy_targets(classification_level, scenario_type)
            test_results['targets_deployed'] = target_instance_ids
            test_results['components_used'].append('TargetSystemSimulator')
            
            # Step 3: Execute security scenarios
            logger.info("Step 3: Executing security scenarios...")
            scenario_execution_ids = await self._execute_scenarios(
                scenario_type, target_instance_ids, test_data_ids
            )
            test_results['scenarios_executed'] = scenario_execution_ids
            test_results['components_used'].append('SecurityScenarioFramework')
            
            # Step 4: Collect and analyze results
            logger.info("Step 4: Collecting results...")
            await self._collect_results(scenario_execution_ids, test_results)
            
            # Step 5: Cleanup
            logger.info("Step 5: Performing cleanup...")
            await self._cleanup_test_resources(
                test_data_ids, target_instance_ids, classification_level
            )
            test_results['cleanup_completed'] = True
            test_results['components_used'].append('PenetrationTestDataManager')
            
            test_results['status'] = 'completed'
            test_results['end_time'] = datetime.now(timezone.utc).isoformat()
            
            logger.info(f"Comprehensive penetration test completed: {test_name}")
            return test_results
            
        except Exception as e:
            test_results['status'] = 'failed'
            test_results['error'] = str(e)
            test_results['end_time'] = datetime.now(timezone.utc).isoformat()
            
            logger.error(f"Comprehensive penetration test failed: {str(e)}")
            
            # Attempt cleanup on failure
            try:
                await self._emergency_cleanup(test_results)
            except Exception as cleanup_error:
                logger.error(f"Emergency cleanup failed: {str(cleanup_error)}")
            
            return test_results
    
    async def _generate_test_data(self, 
                                classification_level: ClassificationLevel) -> List[str]:
        """Generate test data for the penetration test."""
        data_ids = []
        
        # Generate different types of test data
        data_types = [
            TestDataType.USERS,
            TestDataType.CREDENTIALS,
            TestDataType.DOCUMENTS,
            TestDataType.DATABASE_RECORDS,
            TestDataType.NETWORK_TRAFFIC
        ]
        
        for data_type in data_types:
            config = TestDataConfiguration(
                data_type=data_type,
                classification_level=classification_level,
                volume=50 if data_type != TestDataType.NETWORK_TRAFFIC else 200,
                complexity="medium",
                include_vulnerabilities=True,
                realistic_patterns=True,
                audit_enabled=True
            )
            
            generated_data = await self.data_generator.generate_test_data(config)
            
            # Register with data manager
            record_id = await self.data_manager.register_data(
                generated_data=generated_data,
                file_paths=[f"/tmp/test_data_{generated_data.data_id}.json"],
                database_tables=[f"test_{data_type.value}"]
            )
            
            data_ids.append(generated_data.data_id)
            logger.info(f"Generated {data_type.value} test data: {generated_data.data_id}")
        
        return data_ids
    
    async def _deploy_targets(self, 
                            classification_level: ClassificationLevel,
                            scenario_type: ScenarioType) -> List[str]:
        """Deploy target systems for testing."""
        instance_ids = []
        
        # Determine targets based on scenario type
        if scenario_type == ScenarioType.WEB_APPLICATION:
            # Deploy web application targets
            web_target_id = await self.target_simulator.create_from_template(
                template_id="builtin_dvwa",
                customizations={
                    'classification_level': classification_level,
                    'vulnerability_level': VulnerabilityLevel.HIGH
                }
            )
            
            web_instance_id = await self.target_simulator.deploy_target(web_target_id)
            instance_ids.append(web_instance_id)
            
        elif scenario_type == ScenarioType.NETWORK_PENETRATION:
            # Deploy network targets
            db_target_id = await self.target_simulator.create_from_template(
                template_id="builtin_vulnerable_db"
            )
            
            ftp_target_id = await self.target_simulator.create_from_template(
                template_id="builtin_vulnerable_ftp"
            )
            
            db_instance_id = await self.target_simulator.deploy_target(db_target_id)
            ftp_instance_id = await self.target_simulator.deploy_target(ftp_target_id)
            
            instance_ids.extend([db_instance_id, ftp_instance_id])
        
        elif scenario_type == ScenarioType.API_SECURITY:
            # Deploy API targets
            api_target_id = await self.target_simulator.create_from_template(
                template_id="builtin_vulnerable_api"
            )
            
            api_instance_id = await self.target_simulator.deploy_target(api_target_id)
            instance_ids.append(api_instance_id)
        
        logger.info(f"Deployed {len(instance_ids)} target instances")
        return instance_ids
    
    async def _execute_scenarios(self, 
                               scenario_type: ScenarioType,
                               target_instance_ids: List[str],
                               test_data_ids: List[str]) -> List[str]:
        """Execute security testing scenarios."""
        execution_ids = []
        
        # Get appropriate scenarios for the type
        scenarios = self.scenario_framework.list_scenarios(scenario_type=scenario_type)
        
        for scenario in scenarios[:2]:  # Limit to 2 scenarios for example
            # Customize scenario with our test data and targets
            execution_params = {
                'target_instances': target_instance_ids,
                'test_data_ids': test_data_ids,
                'classification_level': scenario.classification_level.value
            }
            
            execution_id = await self.scenario_framework.execute_scenario(
                scenario_id=scenario.scenario_id,
                execution_params=execution_params
            )
            
            execution_ids.append(execution_id)
            logger.info(f"Started scenario execution: {execution_id}")
        
        # Wait for scenarios to complete
        for execution_id in execution_ids:
            await self._wait_for_scenario_completion(execution_id)
        
        return execution_ids
    
    async def _wait_for_scenario_completion(self, execution_id: str) -> None:
        """Wait for a scenario execution to complete."""
        max_wait_time = 1800  # 30 minutes
        check_interval = 10   # 10 seconds
        elapsed_time = 0
        
        while elapsed_time < max_wait_time:
            execution = self.scenario_framework.get_execution(execution_id)
            if not execution:
                break
            
            if execution.status.value in ['completed', 'failed', 'cancelled']:
                logger.info(f"Scenario {execution_id} completed with status: {execution.status.value}")
                break
            
            await asyncio.sleep(check_interval)
            elapsed_time += check_interval
        
        if elapsed_time >= max_wait_time:
            logger.warning(f"Scenario {execution_id} timed out, cancelling...")
            await self.scenario_framework.cancel_execution(execution_id)
    
    async def _collect_results(self, 
                             scenario_execution_ids: List[str],
                             test_results: Dict[str, Any]) -> None:
        """Collect and summarize test results."""
        scenario_results = []
        
        for execution_id in scenario_execution_ids:
            execution = self.scenario_framework.get_execution(execution_id)
            if execution:
                result_summary = {
                    'execution_id': execution_id,
                    'scenario_id': execution.scenario_id,
                    'status': execution.status.value,
                    'steps_completed': len(execution.step_results),
                    'total_steps': execution.total_steps,
                    'success_rate': len([r for r in execution.step_results if r.get('success', False)]) / max(len(execution.step_results), 1),
                    'duration_seconds': (execution.completed_at - execution.started_at).total_seconds() if execution.completed_at else None,
                    'errors': execution.errors
                }
                scenario_results.append(result_summary)
        
        test_results['scenario_results'] = scenario_results
        
        # Calculate overall metrics
        total_scenarios = len(scenario_results)
        successful_scenarios = len([r for r in scenario_results if r['status'] == 'completed'])
        
        test_results['overall_metrics'] = {
            'total_scenarios': total_scenarios,
            'successful_scenarios': successful_scenarios,
            'success_rate': successful_scenarios / max(total_scenarios, 1),
            'total_vulnerabilities_found': sum(len(r['errors']) for r in scenario_results),
            'average_scenario_duration': sum(r['duration_seconds'] or 0 for r in scenario_results) / max(total_scenarios, 1)
        }
    
    async def _cleanup_test_resources(self, 
                                    test_data_ids: List[str],
                                    target_instance_ids: List[str],
                                    classification_level: ClassificationLevel) -> None:
        """Clean up test resources securely."""
        
        # Stop and destroy target instances
        for instance_id in target_instance_ids:
            await self.target_simulator.stop_target(instance_id)
            await self.target_simulator.destroy_target(instance_id)
        
        # Schedule test data for sanitization
        data_records = self.data_manager.list_data_records(
            classification=classification_level,
            status=None  # All statuses
        )
        
        record_ids = [record.record_id for record in data_records 
                     if record.data_id in test_data_ids]
        
        if record_ids:
            sanitization_job_id = await self.data_manager.schedule_sanitization(
                record_ids=record_ids,
                method=SanitizationMethod.DOD_5220_22M
            )
            
            logger.info(f"Scheduled sanitization job {sanitization_job_id} for {len(record_ids)} data records")
        
        logger.info("Test resource cleanup completed")
    
    async def _emergency_cleanup(self, test_results: Dict[str, Any]) -> None:
        """Perform emergency cleanup on test failure."""
        logger.info("Performing emergency cleanup...")
        
        # Clean up any deployed targets
        for instance_id in test_results.get('targets_deployed', []):
            try:
                await self.target_simulator.destroy_target(instance_id)
            except Exception as e:
                logger.error(f"Failed to cleanup target {instance_id}: {str(e)}")
        
        # Force cleanup of any generated data
        try:
            await self.data_manager.cleanup_all_data(force=True)
        except Exception as e:
            logger.error(f"Failed to cleanup test data: {str(e)}")
        
        logger.info("Emergency cleanup completed")
    
    async def generate_compliance_report(self, 
                                       test_results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate a compliance report for the penetration test."""
        report = {
            'report_id': f"pentest_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            'generated_at': datetime.now(timezone.utc).isoformat(),
            'test_summary': test_results,
            'compliance_status': {
                'data_handling': 'compliant',
                'classification_handling': 'compliant',
                'audit_logging': 'compliant',
                'secure_cleanup': 'compliant' if test_results.get('cleanup_completed') else 'non_compliant'
            },
            'security_controls': {
                'classification_engine_used': 'EnhancedClassificationEngine' in test_results.get('components_used', []),
                'audit_logging_enabled': 'AuditLogger' in test_results.get('components_used', []),
                'monitoring_active': 'EnhancedMonitoringSystem' in test_results.get('components_used', []),
                'data_sanitization_scheduled': 'PenetrationTestDataManager' in test_results.get('components_used', [])
            },
            'recommendations': []
        }
        
        # Add recommendations based on results
        if test_results.get('status') == 'failed':
            report['recommendations'].append("Review test failure causes and improve error handling")
        
        if not test_results.get('cleanup_completed'):
            report['recommendations'].append("Ensure all test data is properly sanitized")
            report['compliance_status']['overall'] = 'non_compliant'
        else:
            report['compliance_status']['overall'] = 'compliant'
        
        # Export audit logs for the test period
        start_time = datetime.fromisoformat(test_results['start_time'])
        end_time = datetime.fromisoformat(test_results.get('end_time', datetime.now(timezone.utc).isoformat()))
        
        audit_log = await self.data_manager.export_audit_log(
            start_date=start_time,
            end_date=end_time,
            format='json'
        )
        
        report['audit_trail'] = audit_log
        
        return report

async def main():
    """Main function demonstrating the penetration testing framework."""
    
    # Initialize the orchestrator
    orchestrator = PenetrationTestingOrchestrator()
    
    # Run a comprehensive web application penetration test
    web_test_results = await orchestrator.run_comprehensive_test(
        test_name="Web Application Security Assessment",
        classification_level=ClassificationLevel.UNCLASSIFIED,
        scenario_type=ScenarioType.WEB_APPLICATION
    )
    
    print("Web Application Test Results:")
    print(f"Status: {web_test_results['status']}")
    print(f"Components Used: {web_test_results['components_used']}")
    print(f"Data Generated: {len(web_test_results['data_generated'])} datasets")
    print(f"Targets Deployed: {len(web_test_results['targets_deployed'])} instances")
    print(f"Scenarios Executed: {len(web_test_results['scenarios_executed'])} scenarios")
    print(f"Cleanup Complete: {web_test_results['cleanup_completed']}")
    
    if 'overall_metrics' in web_test_results:
        metrics = web_test_results['overall_metrics']
        print(f"Success Rate: {metrics['success_rate']:.2%}")
        print(f"Vulnerabilities Found: {metrics['total_vulnerabilities_found']}")
    
    # Generate compliance report
    compliance_report = await orchestrator.generate_compliance_report(web_test_results)
    print(f"\\nCompliance Status: {compliance_report['compliance_status']['overall']}")
    
    # Run a network penetration test
    network_test_results = await orchestrator.run_comprehensive_test(
        test_name="Network Infrastructure Assessment", 
        classification_level=ClassificationLevel.UNCLASSIFIED,
        scenario_type=ScenarioType.NETWORK_PENETRATION
    )
    
    print(f"\\nNetwork Test Status: {network_test_results['status']}")
    
    # Demonstrate individual component usage
    print("\\n=== Individual Component Demonstrations ===")
    
    # Test data generation
    print("\\n1. Test Data Generation:")
    test_config = TestDataConfiguration(
        data_type=TestDataType.USERS,
        classification_level=ClassificationLevel.CONFIDENTIAL,
        volume=25,
        include_vulnerabilities=True
    )
    
    generated_data = await orchestrator.data_generator.generate_test_data(test_config)
    print(f"Generated {len(generated_data.content['users'])} classified user records")
    
    # Target deployment
    print("\\n2. Target System Deployment:")
    api_target_id = await orchestrator.target_simulator.create_from_template("builtin_vulnerable_api")
    api_instance_id = await orchestrator.target_simulator.deploy_target(api_target_id)
    print(f"Deployed API target instance: {api_instance_id}")
    
    # Scenario execution
    print("\\n3. Security Scenario Execution:")
    api_scenarios = orchestrator.scenario_framework.list_scenarios(
        scenario_type=ScenarioType.API_SECURITY
    )
    if api_scenarios:
        execution_id = await orchestrator.scenario_framework.execute_scenario(
            api_scenarios[0].scenario_id
        )
        print(f"Started API security scenario: {execution_id}")
    
    # Data management
    print("\\n4. Data Management:")
    record_id = await orchestrator.data_manager.register_data(generated_data)
    data_record = await orchestrator.data_manager.access_data(record_id)
    if data_record:
        print(f"Registered and accessed data record: {record_id}")
        print(f"Access count: {data_record.access_count}")
    
    # Schedule cleanup
    sanitization_job_id = await orchestrator.data_manager.schedule_sanitization(
        record_ids=[record_id],
        method=SanitizationMethod.SECURE_DELETE
    )
    print(f"Scheduled sanitization job: {sanitization_job_id}")
    
    # Framework statistics
    print("\\n=== Framework Statistics ===")
    print(f"Data Generator Stats: {orchestrator.data_generator.get_statistics()}")
    print(f"Scenario Framework Stats: {orchestrator.scenario_framework.get_framework_statistics()}")
    print(f"Target Simulator Stats: {orchestrator.target_simulator.get_simulator_statistics()}")
    print(f"Data Manager Stats: {orchestrator.data_manager.get_manager_statistics()}")
    
    print("\\n=== Integration Example Complete ===")

if __name__ == "__main__":
    asyncio.run(main())