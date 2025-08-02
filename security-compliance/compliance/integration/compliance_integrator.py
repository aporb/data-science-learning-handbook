#!/usr/bin/env python3
"""
Compliance Integrator
=====================

Central integration orchestrator for compliance documentation generation system.
Coordinates data collection from audit, security testing, and monitoring systems
and manages the document generation workflow.

Key Features:
- Orchestrates integration with existing infrastructure
- Manages data collection workflows
- Provides unified API for compliance document generation
- Handles multi-system data correlation and normalization
- Supports real-time and batch processing modes
- Implements caching and performance optimization

Classification: UNCLASSIFIED//FOR OFFICIAL USE ONLY
Version: 1.0
Author: Security Compliance Team
Date: 2025-07-28
"""

import asyncio
import json
import logging
from pathlib import Path
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Tuple, Union
from dataclasses import dataclass, asdict
import concurrent.futures
from contextlib import asynccontextmanager

# Import existing infrastructure components
import sys
sys.path.append(str(Path(__file__).parent.parent.parent))

# Import generators
from ..generators.document_generator import DocumentGenerator, GenerationContext, GenerationResult
from ..generators.ssp_generator import SSPGenerator
from ..generators.sar_generator import SARGenerator

# Import template system
from ..templates.compliance_template_engine import TemplateType, ClassificationLevel

# Import integration modules
from .audit_integration import AuditIntegration
from .security_testing_integration import SecurityTestingIntegration  
from .monitoring_integration import MonitoringIntegration
from .data_collector import DataCollector

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@dataclass
class IntegrationConfig:
    """Configuration for compliance integration"""
    audit_config: Dict[str, Any]
    testing_config: Dict[str, Any]
    monitoring_config: Dict[str, Any]
    templates_path: Path
    output_path: Path
    cache_enabled: bool = True
    cache_ttl_hours: int = 24
    max_concurrent_jobs: int = 4
    data_retention_days: int = 90
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        result = asdict(self)
        result['templates_path'] = str(self.templates_path)
        result['output_path'] = str(self.output_path)
        return result


@dataclass
class ComplianceJob:
    """Compliance document generation job"""
    job_id: str
    system_name: str
    system_id: str
    template_types: List[TemplateType]
    classification: ClassificationLevel
    organization: str
    output_format: str
    priority: str = "normal"
    created_date: datetime = None
    scheduled_date: Optional[datetime] = None
    status: str = "pending"  # pending, running, completed, failed
    progress: float = 0.0
    results: List[GenerationResult] = None
    errors: List[str] = None
    
    def __post_init__(self):
        if self.created_date is None:
            self.created_date = datetime.now(timezone.utc)
        if self.results is None:
            self.results = []
        if self.errors is None:
            self.errors = []


class ComplianceIntegrator:
    """
    Central Compliance Integration Orchestrator
    
    Coordinates compliance document generation across multiple systems
    and provides unified interface for automated compliance workflows.
    """
    
    def __init__(self, config: IntegrationConfig):
        """
        Initialize Compliance Integrator
        
        Args:
            config: Integration configuration
        """
        self.config = config
        
        # Initialize paths
        self.templates_path = config.templates_path
        self.output_path = config.output_path
        self.cache_path = self.output_path / "cache"
        
        # Ensure directories exist
        self.templates_path.mkdir(parents=True, exist_ok=True)
        self.output_path.mkdir(parents=True, exist_ok=True)
        self.cache_path.mkdir(parents=True, exist_ok=True)
        
        # Initialize integrations
        self.audit_integration = AuditIntegration(config.audit_config)
        self.testing_integration = SecurityTestingIntegration(config.testing_config)
        self.monitoring_integration = MonitoringIntegration(config.monitoring_config)
        
        # Initialize data collector
        self.data_collector = DataCollector(
            audit_integration=self.audit_integration,
            testing_integration=self.testing_integration,
            monitoring_integration=self.monitoring_integration,
            cache_path=self.cache_path if config.cache_enabled else None,
            cache_ttl_hours=config.cache_ttl_hours
        )
        
        # Initialize document generators
        self.generators = {
            TemplateType.SSP: SSPGenerator(
                templates_path=self.templates_path,
                output_path=self.output_path / "ssp",
                config=config.to_dict()
            ),
            TemplateType.SAR: SARGenerator(
                templates_path=self.templates_path,
                output_path=self.output_path / "sar",
                config=config.to_dict()
            )
            # Additional generators would be added here
        }
        
        # Job management
        self.active_jobs = {}
        self.job_history = []
        
        # Performance metrics
        self.metrics = {
            'total_documents_generated': 0,
            'total_jobs_completed': 0,
            'total_jobs_failed': 0,
            'average_generation_time': 0.0,
            'cache_hit_rate': 0.0
        }
        
        logger.info("Compliance Integrator initialized")
        logger.info(f"Available generators: {list(self.generators.keys())}")
        logger.info(f"Cache enabled: {config.cache_enabled}")
    
    async def health_check(self) -> Dict[str, Any]:
        """
        Perform health check on all integrated systems
        
        Returns:
            Health status of all systems
        """
        health_status = {
            'overall_status': 'healthy',
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'systems': {}
        }
        
        # Check audit system
        try:
            audit_health = await self.audit_integration.health_check()
            health_status['systems']['audit'] = audit_health
        except Exception as e:
            health_status['systems']['audit'] = {
                'status': 'unhealthy',
                'error': str(e)
            }
            health_status['overall_status'] = 'degraded'
        
        # Check security testing system
        try:
            testing_health = await self.testing_integration.health_check()
            health_status['systems']['security_testing'] = testing_health
        except Exception as e:
            health_status['systems']['security_testing'] = {
                'status': 'unhealthy',
                'error': str(e)
            }
            health_status['overall_status'] = 'degraded'
        
        # Check monitoring system
        try:
            monitoring_health = await self.monitoring_integration.health_check()
            health_status['systems']['monitoring'] = monitoring_health
        except Exception as e:
            health_status['systems']['monitoring'] = {
                'status': 'unhealthy',
                'error': str(e)
            }
            health_status['overall_status'] = 'degraded'
        
        # Check templates and output paths
        health_status['systems']['file_system'] = {
            'status': 'healthy' if self.templates_path.exists() and self.output_path.exists() else 'unhealthy',
            'templates_path_exists': self.templates_path.exists(),
            'output_path_exists': self.output_path.exists(),
            'cache_path_exists': self.cache_path.exists()
        }
        
        if not health_status['systems']['file_system']['status'] == 'healthy':
            health_status['overall_status'] = 'unhealthy'
        
        return health_status
    
    def create_job(self,
                   system_name: str,
                   system_id: str,
                   template_types: List[TemplateType],
                   classification: ClassificationLevel,
                   organization: str,
                   output_format: str = "html",
                   priority: str = "normal",
                   scheduled_date: Optional[datetime] = None) -> str:
        """
        Create a compliance document generation job
        
        Args:
            system_name: Name of the system
            system_id: System identifier
            template_types: List of template types to generate
            classification: Security classification
            organization: Organization name
            output_format: Output format (html, pdf, docx)
            priority: Job priority (low, normal, high, urgent)
            scheduled_date: Optional scheduled execution date
            
        Returns:
            Job ID
        """
        job_id = f"COMP-{datetime.now().strftime('%Y%m%d-%H%M%S')}-{len(self.active_jobs)}"
        
        job = ComplianceJob(
            job_id=job_id,
            system_name=system_name,
            system_id=system_id,
            template_types=template_types,
            classification=classification,
            organization=organization,
            output_format=output_format,
            priority=priority,
            scheduled_date=scheduled_date
        )
        
        self.active_jobs[job_id] = job
        
        logger.info(f"Created compliance job {job_id} for {system_name}")
        logger.info(f"Templates: {[t.value for t in template_types]}, Priority: {priority}")
        
        return job_id
    
    async def execute_job(self, job_id: str) -> ComplianceJob:
        """
        Execute a compliance document generation job
        
        Args:
            job_id: Job identifier
            
        Returns:
            Updated job with results
        """
        if job_id not in self.active_jobs:
            raise ValueError(f"Job {job_id} not found")
        
        job = self.active_jobs[job_id]
        job.status = "running"
        job.progress = 0.0
        
        logger.info(f"Starting execution of job {job_id}")
        
        try:
            # Generate documents for each template type
            total_templates = len(job.template_types)
            
            for i, template_type in enumerate(job.template_types):
                logger.info(f"Generating {template_type.value} document ({i+1}/{total_templates})")
                
                # Create generation context
                context = GenerationContext(
                    system_name=job.system_name,
                    system_id=job.system_id,
                    classification=job.classification,
                    organization=job.organization,
                    template_type=template_type,
                    output_format=job.output_format,
                    include_evidence=True,
                    include_metrics=True
                )
                
                # Get appropriate generator
                generator = self.generators.get(template_type)
                if not generator:
                    error_msg = f"No generator available for template type: {template_type.value}"
                    job.errors.append(error_msg)
                    logger.error(error_msg)
                    continue
                
                # Generate document
                try:
                    result = await generator.generate(context)
                    job.results.append(result)
                    
                    if result.success:
                        logger.info(f"Successfully generated {template_type.value} document")
                        self.metrics['total_documents_generated'] += 1
                    else:
                        job.errors.extend(result.errors)
                        logger.error(f"Failed to generate {template_type.value} document: {result.errors}")
                
                except Exception as e:
                    error_msg = f"Exception generating {template_type.value}: {str(e)}"
                    job.errors.append(error_msg)
                    logger.error(error_msg)
                
                # Update progress
                job.progress = (i + 1) / total_templates
            
            # Determine final status
            successful_results = [r for r in job.results if r.success]
            if len(successful_results) == total_templates:
                job.status = "completed"
                self.metrics['total_jobs_completed'] += 1
            elif len(successful_results) > 0:
                job.status = "completed_with_errors"
                self.metrics['total_jobs_completed'] += 1
            else:
                job.status = "failed"
                self.metrics['total_jobs_failed'] += 1
            
            job.progress = 1.0
            
            # Update metrics
            if job.results:
                avg_time = sum(r.generation_time for r in job.results) / len(job.results)
                current_avg = self.metrics['average_generation_time']
                total_docs = self.metrics['total_documents_generated']
                self.metrics['average_generation_time'] = ((current_avg * (total_docs - len(job.results))) + 
                                                          (avg_time * len(job.results))) / total_docs
            
            logger.info(f"Job {job_id} completed with status: {job.status}")
            
        except Exception as e:
            job.status = "failed"
            job.errors.append(f"Job execution failed: {str(e)}")
            self.metrics['total_jobs_failed'] += 1
            logger.error(f"Job {job_id} failed: {str(e)}")
        
        # Move to history
        self.job_history.append(job)
        if job_id in self.active_jobs:
            del self.active_jobs[job_id]
        
        return job
    
    async def execute_job_batch(self, job_ids: List[str]) -> List[ComplianceJob]:
        """
        Execute multiple compliance jobs in parallel
        
        Args:
            job_ids: List of job identifiers
            
        Returns:
            List of updated jobs with results
        """
        logger.info(f"Starting batch execution of {len(job_ids)} jobs")
        
        # Execute jobs with concurrency limit
        semaphore = asyncio.Semaphore(self.config.max_concurrent_jobs)
        
        async def execute_with_semaphore(job_id: str):
            async with semaphore:
                return await self.execute_job(job_id)
        
        # Execute all jobs
        results = await asyncio.gather(
            *[execute_with_semaphore(job_id) for job_id in job_ids],
            return_exceptions=True
        )
        
        # Process results
        completed_jobs = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                job_id = job_ids[i]
                if job_id in self.active_jobs:
                    job = self.active_jobs[job_id]
                    job.status = "failed"
                    job.errors.append(f"Batch execution error: {str(result)}")
                    completed_jobs.append(job)
                    del self.active_jobs[job_id]
                logger.error(f"Batch execution error for job {job_id}: {result}")
            else:
                completed_jobs.append(result)
        
        logger.info(f"Batch execution completed: {len(completed_jobs)} jobs processed")
        
        return completed_jobs
    
    def get_job_status(self, job_id: str) -> Optional[Dict[str, Any]]:
        """
        Get status of a compliance job
        
        Args:
            job_id: Job identifier
            
        Returns:
            Job status information or None if not found
        """
        # Check active jobs
        if job_id in self.active_jobs:
            job = self.active_jobs[job_id]
            return {
                'job_id': job.job_id,
                'status': job.status,
                'progress': job.progress,
                'created_date': job.created_date.isoformat(),
                'system_name': job.system_name,
                'template_types': [t.value for t in job.template_types],
                'results_count': len(job.results),
                'errors_count': len(job.errors)
            }
        
        # Check job history
        for job in self.job_history:
            if job.job_id == job_id:
                return {
                    'job_id': job.job_id,
                    'status': job.status,
                    'progress': job.progress,
                    'created_date': job.created_date.isoformat(),
                    'system_name': job.system_name,
                    'template_types': [t.value for t in job.template_types],
                    'results_count': len(job.results),
                    'errors_count': len(job.errors),
                    'successful_documents': len([r for r in job.results if r.success])
                }
        
        return None
    
    def list_jobs(self, 
                  status_filter: Optional[str] = None,
                  limit: int = 50) -> List[Dict[str, Any]]:
        """
        List compliance jobs
        
        Args:
            status_filter: Filter by job status
            limit: Maximum number of jobs to return
            
        Returns:
            List of job information
        """
        all_jobs = list(self.active_jobs.values()) + self.job_history
        
        # Apply status filter
        if status_filter:
            all_jobs = [job for job in all_jobs if job.status == status_filter]
        
        # Sort by creation date (newest first)
        all_jobs.sort(key=lambda x: x.created_date, reverse=True)
        
        # Apply limit
        limited_jobs = all_jobs[:limit]
        
        # Convert to summary format
        job_summaries = []
        for job in limited_jobs:
            job_summaries.append({
                'job_id': job.job_id,
                'system_name': job.system_name,
                'status': job.status,
                'progress': job.progress,
                'created_date': job.created_date.isoformat(),
                'template_types': [t.value for t in job.template_types],
                'priority': job.priority,
                'results_count': len(job.results),
                'errors_count': len(job.errors)
            })
        
        return job_summaries
    
    def get_metrics(self) -> Dict[str, Any]:
        """
        Get integration performance metrics
        
        Returns:
            Performance metrics
        """
        # Update cache hit rate from data collector
        cache_stats = self.data_collector.get_cache_stats()
        if cache_stats['total_requests'] > 0:
            self.metrics['cache_hit_rate'] = cache_stats['cache_hits'] / cache_stats['total_requests']
        
        return {
            **self.metrics,
            'active_jobs_count': len(self.active_jobs),
            'job_history_count': len(self.job_history),
            'available_generators': list(self.generators.keys()),
            'cache_stats': cache_stats,
            'uptime_hours': (datetime.now(timezone.utc) - datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)).total_seconds() / 3600
        }
    
    async def generate_system_documentation(self,
                                          system_name: str,
                                          system_id: str,
                                          classification: ClassificationLevel,
                                          organization: str,
                                          template_types: Optional[List[TemplateType]] = None,
                                          output_format: str = "html") -> List[GenerationResult]:
        """
        Generate complete compliance documentation for a system
        
        Args:
            system_name: Name of the system
            system_id: System identifier
            classification: Security classification
            organization: Organization name
            template_types: Template types to generate (defaults to SSP and SAR)
            output_format: Output format
            
        Returns:
            List of generation results
        """
        if template_types is None:
            template_types = [TemplateType.SSP, TemplateType.SAR]
        
        logger.info(f"Generating complete documentation for {system_name}")
        
        # Create and execute job
        job_id = self.create_job(
            system_name=system_name,
            system_id=system_id,
            template_types=template_types,
            classification=classification,
            organization=organization,
            output_format=output_format,
            priority="high"
        )
        
        # Execute job
        completed_job = await self.execute_job(job_id)
        
        return completed_job.results
    
    async def cleanup_old_jobs(self, retention_days: int = None) -> int:
        """
        Clean up old job history records
        
        Args:
            retention_days: Number of days to retain (uses config default if not specified)
            
        Returns:
            Number of jobs cleaned up
        """
        if retention_days is None:
            retention_days = self.config.data_retention_days
        
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=retention_days)
        
        initial_count = len(self.job_history)
        self.job_history = [job for job in self.job_history if job.created_date > cutoff_date]
        cleaned_count = initial_count - len(self.job_history)
        
        if cleaned_count > 0:
            logger.info(f"Cleaned up {cleaned_count} old job records")
        
        return cleaned_count
    
    async def shutdown(self):
        """Gracefully shutdown the integrator"""
        logger.info("Shutting down Compliance Integrator")
        
        # Cancel any running jobs
        for job in self.active_jobs.values():
            if job.status == "running":
                job.status = "cancelled"
                job.errors.append("Job cancelled due to shutdown")
        
        # Cleanup resources
        await self.data_collector.cleanup()
        
        logger.info("Compliance Integrator shutdown complete")


if __name__ == "__main__":
    # Example usage
    import tempfile
    
    async def main():
        with tempfile.TemporaryDirectory() as temp_dir:
            config = IntegrationConfig(
                audit_config={},
                testing_config={},
                monitoring_config={},
                templates_path=Path(temp_dir) / "templates",
                output_path=Path(temp_dir) / "output",
                cache_enabled=True,
                max_concurrent_jobs=2
            )
            
            integrator = ComplianceIntegrator(config)
            
            # Health check
            health = await integrator.health_check()
            print(f"System Health: {health['overall_status']}")
            
            # Generate documentation
            results = await integrator.generate_system_documentation(
                system_name="Test System",
                system_id="TEST-001",
                classification=ClassificationLevel.UNCLASSIFIED,
                organization="Test Organization",
                template_types=[TemplateType.SSP, TemplateType.SAR]
            )
            
            print(f"Generated {len(results)} documents")
            for result in results:
                print(f"  - {result.document_path}: {'Success' if result.success else 'Failed'}")
            
            # Get metrics
            metrics = integrator.get_metrics()
            print(f"Metrics: {metrics}")
            
            await integrator.shutdown()
    
    asyncio.run(main())