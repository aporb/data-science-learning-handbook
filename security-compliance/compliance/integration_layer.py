"""
Compliance Integration Layer
===========================

This module provides comprehensive integration capabilities that connect the compliance
reporting and dashboard system with existing monitoring and audit infrastructure to
ensure seamless data flow and unified compliance oversight.

Key Features:
- Integration with existing monitoring and audit systems
- Real-time data synchronization and correlation
- Unified compliance data aggregation
- Cross-system event correlation and analysis
- Performance monitoring and health checks
- Automated failover and redundancy

Integration Points:
- Enhanced monitoring system for real-time metrics
- Integrated audit orchestrator for audit data
- Enhanced log aggregator for event correlation
- Multi-classification engine for classified data
- RBAC system for access control
- Real-time alerting for immediate notifications

Classification: UNCLASSIFIED//FOR OFFICIAL USE ONLY
Version: 1.0 - Comprehensive System Integration
Author: Security Compliance Team
Date: 2025-07-28
"""

import asyncio
import json
import logging
import time
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Tuple, Set, Union, AsyncGenerator, Callable
from uuid import UUID, uuid4
from dataclasses import dataclass, field, asdict
from enum import Enum
from concurrent.futures import ThreadPoolExecutor
from collections import defaultdict, deque
import aiofiles
import aiohttp
from threading import Lock
import numpy as np
from pathlib import Path

# Import existing infrastructure
from ..audits.integrated_audit_orchestrator import IntegratedAuditOrchestrator
from ..audits.enhanced_monitoring_system import EnhancedMonitoringSystem
from ..audits.enhanced_log_aggregator import EnhancedLogAggregator
from ..audits.real_time_alerting import RealTimeAlerting
from ..auth.rbac_system import RBACController
from ..multi_classification.enhanced_classification_engine import EnhancedMultiClassificationEngine

# Import compliance components
from .dashboards.compliance_dashboard import ComplianceDataProvider, DashboardManager
from .reporting.automated_reporting_engine import ReportingManager
from .data.compliance_data_warehouse import DataWarehouseManager
from .alerts.compliance_alert_system import AlertManager

logger = logging.getLogger(__name__)


class IntegrationStatus(Enum):
    """Status of system integrations."""
    ACTIVE = "active"
    INACTIVE = "inactive"
    DEGRADED = "degraded"
    FAILED = "failed"
    INITIALIZING = "initializing"
    UNKNOWN = "unknown"


class DataSyncMode(Enum):
    """Data synchronization modes."""
    REAL_TIME = "real_time"
    BATCH = "batch"
    STREAMING = "streaming"
    HYBRID = "hybrid"


@dataclass
class IntegrationMetrics:
    """Metrics for system integration health."""
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    # Integration status
    total_integrations: int = 0
    active_integrations: int = 0
    failed_integrations: int = 0
    degraded_integrations: int = 0
    
    # Data flow metrics
    total_data_points_processed: int = 0
    data_processing_rate: float = 0.0
    average_processing_latency_ms: float = 0.0
    
    # Error metrics
    integration_errors: int = 0
    data_sync_failures: int = 0
    connection_timeouts: int = 0
    
    # Performance metrics
    memory_usage_mb: float = 0.0
    cpu_utilization: float = 0.0
    network_utilization: float = 0.0
    
    # Health scores
    overall_health_score: float = 1.0
    data_quality_score: float = 1.0
    integration_reliability_score: float = 1.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)


@dataclass
class IntegrationConfiguration:
    """Configuration for system integration."""
    integration_id: str = field(default_factory=lambda: str(uuid4()))
    name: str = ""
    description: str = ""
    enabled: bool = True
    
    # Connection settings
    connection_type: str = "direct"  # direct, api, webhook, queue
    endpoint_url: Optional[str] = None
    connection_timeout_seconds: int = 30
    retry_attempts: int = 3
    
    # Data synchronization
    sync_mode: DataSyncMode = DataSyncMode.REAL_TIME
    sync_interval_seconds: int = 60
    batch_size: int = 1000
    
    # Authentication
    authentication_type: str = "none"  # none, api_key, oauth, certificate
    credentials_config: Dict[str, Any] = field(default_factory=dict)
    
    # Data filtering and mapping
    data_filters: List[str] = field(default_factory=list)
    field_mappings: Dict[str, str] = field(default_factory=dict)
    
    # Quality and validation
    enable_data_validation: bool = True
    quality_threshold: float = 0.95
    
    # Error handling
    error_handling_mode: str = "retry"  # retry, skip, fail
    max_error_rate: float = 0.05  # 5%
    
    # Classification and security
    classification_level: str = "UNCLASSIFIED"
    requires_encryption: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self, dict_factory=lambda x: {k: v.value if isinstance(v, Enum) else v for k, v in x})


class SystemConnector:
    """Base connector for integrating with external systems."""
    
    def __init__(self, config: IntegrationConfiguration):
        """Initialize system connector."""
        self.config = config
        self.status = IntegrationStatus.INITIALIZING
        self.last_sync_time = None
        self.error_count = 0
        self.total_processed = 0
        
        # Connection state
        self.connection_established = False
        self.last_health_check = None
        
        # Performance tracking
        self.processing_times = deque(maxlen=100)
        self.error_history = deque(maxlen=100)
        
        logger.info(f"System connector initialized for {config.name}")
    
    async def connect(self) -> bool:
        """Establish connection to the system."""
        try:
            self.status = IntegrationStatus.INITIALIZING
            
            # Perform connection logic (to be implemented by subclasses)
            connection_successful = await self._establish_connection()
            
            if connection_successful:
                self.connection_established = True
                self.status = IntegrationStatus.ACTIVE
                logger.info(f"Successfully connected to {self.config.name}")
                return True
            else:
                self.status = IntegrationStatus.FAILED
                logger.error(f"Failed to connect to {self.config.name}")
                return False
                
        except Exception as e:
            self.status = IntegrationStatus.FAILED
            logger.error(f"Error connecting to {self.config.name}: {e}")
            return False
    
    async def disconnect(self):
        """Disconnect from the system."""
        try:
            await self._close_connection()
            self.connection_established = False
            self.status = IntegrationStatus.INACTIVE
            logger.info(f"Disconnected from {self.config.name}")
        except Exception as e:
            logger.error(f"Error disconnecting from {self.config.name}: {e}")
    
    async def sync_data(self) -> Dict[str, Any]:
        """Synchronize data from the system."""
        try:
            if not self.connection_established:
                raise ConnectionError("Connection not established")
            
            start_time = time.time()
            
            # Fetch data (to be implemented by subclasses)
            data = await self._fetch_data()
            
            # Validate and process data
            processed_data = await self._process_data(data)
            
            # Update metrics
            processing_time = (time.time() - start_time) * 1000
            self.processing_times.append(processing_time)
            self.total_processed += len(processed_data) if isinstance(processed_data, list) else 1
            self.last_sync_time = datetime.now(timezone.utc)
            
            return {
                "status": "success",
                "data": processed_data,
                "processing_time_ms": processing_time,
                "records_processed": len(processed_data) if isinstance(processed_data, list) else 1
            }
            
        except Exception as e:
            self.error_count += 1
            self.error_history.append({
                "timestamp": datetime.now(timezone.utc),
                "error": str(e)
            })
            
            # Update status based on error rate
            if self.error_count > 10:  # After 10 errors
                error_rate = len(self.error_history) / max(1, self.total_processed)
                if error_rate > self.config.max_error_rate:
                    self.status = IntegrationStatus.DEGRADED
            
            logger.error(f"Error syncing data from {self.config.name}: {e}")
            return {
                "status": "error",
                "error": str(e),
                "error_count": self.error_count
            }
    
    async def health_check(self) -> Dict[str, Any]:
        """Perform health check of the connection."""
        try:
            health_status = await self._check_system_health()
            self.last_health_check = datetime.now(timezone.utc)
            
            # Update status based on health check
            if health_status.get("healthy", False):
                if self.status == IntegrationStatus.DEGRADED:
                    self.status = IntegrationStatus.ACTIVE
            else:
                self.status = IntegrationStatus.DEGRADED
            
            return {
                "integration_name": self.config.name,
                "status": self.status.value,
                "connection_established": self.connection_established,
                "last_sync": self.last_sync_time.isoformat() if self.last_sync_time else None,
                "error_count": self.error_count,
                "total_processed": self.total_processed,
                "avg_processing_time_ms": np.mean(self.processing_times) if self.processing_times else 0,
                "system_health": health_status
            }
            
        except Exception as e:
            logger.error(f"Error during health check for {self.config.name}: {e}")
            return {
                "integration_name": self.config.name,
                "status": "failed",
                "error": str(e)
            }
    
    # Abstract methods to be implemented by subclasses
    async def _establish_connection(self) -> bool:
        """Establish connection to the specific system."""
        return True  # Default implementation
    
    async def _close_connection(self):
        """Close connection to the specific system."""
        pass  # Default implementation
    
    async def _fetch_data(self) -> Any:
        """Fetch data from the specific system."""
        return []  # Default implementation
    
    async def _process_data(self, raw_data: Any) -> Any:
        """Process and validate fetched data."""
        return raw_data  # Default implementation
    
    async def _check_system_health(self) -> Dict[str, Any]:
        """Check health of the specific system."""
        return {"healthy": True}  # Default implementation


class AuditOrchestratorConnector(SystemConnector):
    """Connector for integrated audit orchestrator."""
    
    def __init__(self, config: IntegrationConfiguration, audit_orchestrator: IntegratedAuditOrchestrator):
        """Initialize audit orchestrator connector."""
        super().__init__(config)
        self.audit_orchestrator = audit_orchestrator
    
    async def _establish_connection(self) -> bool:
        """Establish connection to audit orchestrator."""
        try:
            # Check if audit orchestrator is available and healthy
            health = await self.audit_orchestrator.health_check()
            return health.get("status") == "healthy"
        except Exception as e:
            logger.error(f"Error connecting to audit orchestrator: {e}")
            return False
    
    async def _fetch_data(self) -> Dict[str, Any]:
        """Fetch data from audit orchestrator."""
        try:
            # Get comprehensive metrics
            metrics = self.audit_orchestrator.get_comprehensive_metrics()
            
            # Get integration status
            integration_status = self.audit_orchestrator.get_integration_status()
            
            return {
                "metrics": metrics,
                "integration_status": integration_status,
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error fetching audit orchestrator data: {e}")
            raise
    
    async def _check_system_health(self) -> Dict[str, Any]:
        """Check audit orchestrator health."""
        try:
            return await self.audit_orchestrator.health_check()
        except Exception as e:
            return {"healthy": False, "error": str(e)}


class MonitoringSystemConnector(SystemConnector):
    """Connector for enhanced monitoring system."""
    
    def __init__(self, config: IntegrationConfiguration, monitoring_system: EnhancedMonitoringSystem):
        """Initialize monitoring system connector."""
        super().__init__(config)
        self.monitoring_system = monitoring_system
    
    async def _establish_connection(self) -> bool:
        """Establish connection to monitoring system."""
        try:
            health = await self.monitoring_system.health_check()
            return health.get("overall_healthy", False)
        except Exception as e:
            logger.error(f"Error connecting to monitoring system: {e}")
            return False
    
    async def _fetch_data(self) -> Dict[str, Any]:
        """Fetch data from monitoring system."""
        try:
            # Get performance metrics
            performance_metrics = self.monitoring_system.get_performance_metrics()
            
            return {
                "performance_metrics": performance_metrics,
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error fetching monitoring system data: {e}")
            raise
    
    async def _check_system_health(self) -> Dict[str, Any]:
        """Check monitoring system health."""
        try:
            return await self.monitoring_system.health_check()
        except Exception as e:
            return {"healthy": False, "error": str(e)}


class LogAggregatorConnector(SystemConnector):
    """Connector for enhanced log aggregator."""
    
    def __init__(self, config: IntegrationConfiguration, log_aggregator: EnhancedLogAggregator):
        """Initialize log aggregator connector."""
        super().__init__(config)
        self.log_aggregator = log_aggregator
    
    async def _establish_connection(self) -> bool:
        """Establish connection to log aggregator."""
        try:
            health = await self.log_aggregator.health_check()
            return health.get("status") == "healthy"
        except Exception as e:
            logger.error(f"Error connecting to log aggregator: {e}")
            return False
    
    async def _fetch_data(self) -> Dict[str, Any]:
        """Fetch data from log aggregator."""
        try:
            # Get performance metrics
            performance_metrics = self.log_aggregator.get_performance_metrics()
            
            return {
                "performance_metrics": performance_metrics,
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error fetching log aggregator data: {e}")
            raise
    
    async def _check_system_health(self) -> Dict[str, Any]:
        """Check log aggregator health."""
        try:
            return await self.log_aggregator.health_check()
        except Exception as e:
            return {"healthy": False, "error": str(e)}


class ComplianceIntegrationLayer:
    """
    Main integration layer that coordinates data flow between compliance
    systems and existing monitoring and audit infrastructure.
    """
    
    def __init__(
        self,
        audit_orchestrator: IntegratedAuditOrchestrator,
        monitoring_system: EnhancedMonitoringSystem,
        log_aggregator: EnhancedLogAggregator,
        real_time_alerting: RealTimeAlerting,
        rbac_controller: Optional[RBACController] = None,
        classification_engine: Optional[EnhancedMultiClassificationEngine] = None
    ):
        """Initialize compliance integration layer."""
        # Core infrastructure components
        self.audit_orchestrator = audit_orchestrator
        self.monitoring_system = monitoring_system
        self.log_aggregator = log_aggregator
        self.real_time_alerting = real_time_alerting
        self.rbac_controller = rbac_controller
        self.classification_engine = classification_engine
        
        # Integration components
        self.data_provider = None
        self.dashboard_manager = None
        self.reporting_manager = None
        self.data_warehouse_manager = None
        self.alert_manager = None
        
        # Connectors
        self.connectors: Dict[str, SystemConnector] = {}
        
        # Integration state
        self.is_running = False
        self.integration_tasks: List[asyncio.Task] = []
        
        # Metrics and monitoring
        self.metrics = IntegrationMetrics()
        self.metrics_lock = Lock()
        
        # Data correlation
        self.correlation_engine = DataCorrelationEngine()
        
        logger.info("Compliance integration layer initialized")
    
    async def initialize(self):
        """Initialize the integration layer and all components."""
        try:
            # Initialize data provider
            self.data_provider = ComplianceDataProvider(
                self.audit_orchestrator,
                self.monitoring_system,
                self.log_aggregator,
                self.classification_engine
            )
            
            # Initialize dashboard manager
            self.dashboard_manager = DashboardManager(
                self.audit_orchestrator,
                self.monitoring_system,
                self.log_aggregator,
                self.classification_engine,
                self.rbac_controller
            )
            
            # Initialize reporting manager
            self.reporting_manager = ReportingManager(
                self.audit_orchestrator,
                self.monitoring_system,
                self.log_aggregator,
                self.classification_engine,
                self.rbac_controller
            )
            
            # Initialize data warehouse manager
            self.data_warehouse_manager = DataWarehouseManager(
                self.data_provider,
                self.audit_orchestrator,
                self.monitoring_system
            )
            
            # Initialize alert manager
            self.alert_manager = AlertManager(
                self.data_provider,
                self.data_warehouse_manager.get_data_warehouse(),
                self.audit_orchestrator,
                self.monitoring_system,
                self.real_time_alerting
            )
            
            # Initialize system connectors
            await self._initialize_connectors()
            
            logger.info("Compliance integration layer initialized successfully")
            
        except Exception as e:
            logger.error(f"Error initializing integration layer: {e}")
            raise
    
    async def _initialize_connectors(self):
        """Initialize system connectors."""
        try:
            # Audit orchestrator connector
            audit_config = IntegrationConfiguration(
                name="Audit Orchestrator",
                description="Integration with integrated audit orchestrator",
                sync_mode=DataSyncMode.REAL_TIME,
                sync_interval_seconds=30
            )
            
            self.connectors["audit_orchestrator"] = AuditOrchestratorConnector(
                audit_config, self.audit_orchestrator
            )
            
            # Monitoring system connector
            monitoring_config = IntegrationConfiguration(
                name="Monitoring System",
                description="Integration with enhanced monitoring system",
                sync_mode=DataSyncMode.REAL_TIME,
                sync_interval_seconds=60
            )
            
            self.connectors["monitoring_system"] = MonitoringSystemConnector(
                monitoring_config, self.monitoring_system
            )
            
            # Log aggregator connector
            log_config = IntegrationConfiguration(
                name="Log Aggregator", 
                description="Integration with enhanced log aggregator",
                sync_mode=DataSyncMode.STREAMING,
                sync_interval_seconds=30
            )
            
            self.connectors["log_aggregator"] = LogAggregatorConnector(
                log_config, self.log_aggregator
            )
            
            # Connect all connectors
            for name, connector in self.connectors.items():
                connected = await connector.connect()
                if connected:
                    logger.info(f"Successfully connected to {name}")
                else:
                    logger.warning(f"Failed to connect to {name}")
            
        except Exception as e:
            logger.error(f"Error initializing connectors: {e}")
            raise
    
    async def start(self):
        """Start the integration layer."""
        if self.is_running:
            return
        
        self.is_running = True
        
        # Start all compliance components
        await self._start_compliance_components()
        
        # Start integration tasks
        self.integration_tasks = [
            asyncio.create_task(self._data_synchronization_worker()),
            asyncio.create_task(self._health_monitoring_worker()),
            asyncio.create_task(self._metrics_collection_worker()),
            asyncio.create_task(self._correlation_worker()),
            asyncio.create_task(self._failover_monitoring_worker())
        ]
        
        logger.info("Compliance integration layer started")
    
    async def stop(self):
        """Stop the integration layer."""
        self.is_running = False
        
        # Cancel integration tasks
        for task in self.integration_tasks:
            if not task.done():
                task.cancel()
        
        if self.integration_tasks:
            await asyncio.gather(*self.integration_tasks, return_exceptions=True)
        
        # Stop compliance components
        await self._stop_compliance_components()
        
        # Disconnect connectors
        for connector in self.connectors.values():
            await connector.disconnect()
        
        logger.info("Compliance integration layer stopped")
    
    async def _start_compliance_components(self):
        """Start all compliance system components."""
        try:
            # Start dashboard manager
            if self.dashboard_manager:
                await self.dashboard_manager.start_all_dashboards()
            
            # Start reporting manager
            if self.reporting_manager:
                await self.reporting_manager.start()
            
            # Start data warehouse manager
            if self.data_warehouse_manager:
                await self.data_warehouse_manager.start()
            
            # Start alert manager
            if self.alert_manager:
                await self.alert_manager.start()
            
            logger.info("All compliance components started")
            
        except Exception as e:
            logger.error(f"Error starting compliance components: {e}")
            raise
    
    async def _stop_compliance_components(self):
        """Stop all compliance system components."""
        try:
            # Stop alert manager
            if self.alert_manager:
                await self.alert_manager.stop()
            
            # Stop data warehouse manager
            if self.data_warehouse_manager:
                await self.data_warehouse_manager.stop()
            
            # Stop reporting manager
            if self.reporting_manager:
                await self.reporting_manager.stop()
            
            # Stop dashboard manager
            if self.dashboard_manager:
                await self.dashboard_manager.stop_all_dashboards()
            
            logger.info("All compliance components stopped")
            
        except Exception as e:
            logger.error(f"Error stopping compliance components: {e}")
    
    async def _data_synchronization_worker(self):
        """Worker task for data synchronization across systems."""
        while self.is_running:
            try:
                # Synchronize data from all connectors
                sync_results = {}
                
                for name, connector in self.connectors.items():
                    if connector.status == IntegrationStatus.ACTIVE:
                        result = await connector.sync_data()
                        sync_results[name] = result
                        
                        # Update metrics
                        with self.metrics_lock:
                            if result["status"] == "success":
                                self.metrics.total_data_points_processed += result.get("records_processed", 0)
                            else:
                                self.metrics.data_sync_failures += 1
                
                # Process correlated data
                await self._process_synchronized_data(sync_results)
                
                # Wait for next synchronization cycle
                await asyncio.sleep(30.0)
                
            except Exception as e:
                logger.error(f"Error in data synchronization worker: {e}")
                await asyncio.sleep(60.0)
    
    async def _process_synchronized_data(self, sync_results: Dict[str, Dict[str, Any]]):
        """Process synchronized data from multiple sources."""
        try:
            # Correlate data from different sources
            correlated_data = await self.correlation_engine.correlate_data(sync_results)
            
            # Update compliance components with correlated data
            if correlated_data:
                # Update data provider cache
                if self.data_provider:
                    await self._update_data_provider_cache(correlated_data)
                
                # Trigger dashboard updates
                if self.dashboard_manager:
                    await self._trigger_dashboard_updates(correlated_data)
            
        except Exception as e:
            logger.error(f"Error processing synchronized data: {e}")
    
    async def _update_data_provider_cache(self, correlated_data: Dict[str, Any]):
        """Update data provider cache with correlated data."""
        try:
            # This would typically update cached compliance metrics
            # with the latest correlated data from all systems
            pass
        except Exception as e:
            logger.error(f"Error updating data provider cache: {e}")
    
    async def _trigger_dashboard_updates(self, correlated_data: Dict[str, Any]):
        """Trigger dashboard updates with new data."""
        try:
            # This would typically trigger real-time dashboard updates
            # with the latest correlated compliance data
            pass
        except Exception as e:
            logger.error(f"Error triggering dashboard updates: {e}")
    
    async def _health_monitoring_worker(self):
        """Worker task for monitoring integration health."""
        while self.is_running:
            try:
                # Check health of all connectors
                health_results = {}
                
                for name, connector in self.connectors.items():
                    health = await connector.health_check()
                    health_results[name] = health
                
                # Update integration metrics
                with self.metrics_lock:
                    self.metrics.total_integrations = len(self.connectors)
                    self.metrics.active_integrations = sum(
                        1 for result in health_results.values()
                        if result.get("status") == "active"
                    )
                    self.metrics.failed_integrations = sum(
                        1 for result in health_results.values()
                        if result.get("status") == "failed"
                    )
                    self.metrics.degraded_integrations = sum(
                        1 for result in health_results.values()
                        if result.get("status") == "degraded"
                    )
                
                # Calculate overall health score
                await self._calculate_health_score(health_results)
                
                # Run health monitoring every 2 minutes
                await asyncio.sleep(120.0)
                
            except Exception as e:
                logger.error(f"Error in health monitoring worker: {e}")
                await asyncio.sleep(300.0)
    
    async def _calculate_health_score(self, health_results: Dict[str, Dict[str, Any]]):
        """Calculate overall integration health score."""
        try:
            if not health_results:
                health_score = 0.0
            else:
                # Calculate weighted health score
                active_weight = 1.0
                degraded_weight = 0.5
                failed_weight = 0.0
                
                total_weight = 0.0
                weighted_sum = 0.0
                
                for result in health_results.values():
                    status = result.get("status", "unknown")
                    if status == "active":
                        weighted_sum += active_weight
                    elif status == "degraded":
                        weighted_sum += degraded_weight
                    elif status == "failed":
                        weighted_sum += failed_weight
                    
                    total_weight += 1.0
                
                health_score = weighted_sum / total_weight if total_weight > 0 else 0.0
            
            with self.metrics_lock:
                self.metrics.overall_health_score = health_score
            
        except Exception as e:
            logger.error(f"Error calculating health score: {e}")
    
    async def _metrics_collection_worker(self):
        """Worker task for collecting integration metrics."""
        while self.is_running:
            try:
                # Collect performance metrics
                with self.metrics_lock:
                    self.metrics.timestamp = datetime.now(timezone.utc)
                    
                    # Calculate processing rate
                    if hasattr(self, '_last_processed_count'):
                        time_diff = (self.metrics.timestamp - self._last_metrics_time).total_seconds()
                        count_diff = self.metrics.total_data_points_processed - self._last_processed_count
                        self.metrics.data_processing_rate = count_diff / time_diff if time_diff > 0 else 0.0
                    
                    self._last_processed_count = self.metrics.total_data_points_processed
                    self._last_metrics_time = self.metrics.timestamp
                    
                    # Calculate average latency from all connectors
                    latencies = []
                    for connector in self.connectors.values():
                        if connector.processing_times:
                            latencies.extend(connector.processing_times)
                    
                    self.metrics.average_processing_latency_ms = np.mean(latencies) if latencies else 0.0
                
                # Run metrics collection every minute
                await asyncio.sleep(60.0)
                
            except Exception as e:
                logger.error(f"Error in metrics collection worker: {e}")
                await asyncio.sleep(120.0)
    
    async def _correlation_worker(self):
        """Worker task for cross-system data correlation."""
        while self.is_running:
            try:
                # Perform advanced data correlation analysis
                await self.correlation_engine.perform_correlation_analysis()
                
                # Run correlation analysis every 5 minutes
                await asyncio.sleep(300.0)
                
            except Exception as e:
                logger.error(f"Error in correlation worker: {e}")
                await asyncio.sleep(600.0)
    
    async def _failover_monitoring_worker(self):
        """Worker task for monitoring failover scenarios."""
        while self.is_running:
            try:
                # Check for failed integrations and attempt recovery
                for name, connector in self.connectors.items():
                    if connector.status == IntegrationStatus.FAILED:
                        logger.warning(f"Attempting to recover failed integration: {name}")
                        
                        # Attempt reconnection
                        reconnected = await connector.connect()
                        if reconnected:
                            logger.info(f"Successfully recovered integration: {name}")
                        else:
                            logger.error(f"Failed to recover integration: {name}")
                
                # Run failover monitoring every 5 minutes
                await asyncio.sleep(300.0)
                
            except Exception as e:
                logger.error(f"Error in failover monitoring worker: {e}")
                await asyncio.sleep(600.0)
    
    def get_integration_status(self) -> Dict[str, Any]:
        """Get current integration status."""
        connector_status = {}
        
        for name, connector in self.connectors.items():
            connector_status[name] = {
                "status": connector.status.value,
                "connection_established": connector.connection_established,
                "last_sync": connector.last_sync_time.isoformat() if connector.last_sync_time else None,
                "error_count": connector.error_count,
                "total_processed": connector.total_processed
            }
        
        with self.metrics_lock:
            metrics_dict = self.metrics.to_dict()
        
        return {
            "overall_status": "healthy" if self.is_running else "stopped",
            "integration_metrics": metrics_dict,
            "connectors": connector_status,
            "compliance_components": {
                "dashboard_manager": "active" if self.dashboard_manager else "not_initialized",
                "reporting_manager": "active" if self.reporting_manager else "not_initialized",
                "data_warehouse_manager": "active" if self.data_warehouse_manager else "not_initialized",
                "alert_manager": "active" if self.alert_manager else "not_initialized"
            }
        }
    
    async def health_check(self) -> Dict[str, Any]:
        """Perform comprehensive health check."""
        health_status = {
            "status": "healthy" if self.is_running else "stopped",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "integration_layer": {
                "running": self.is_running,
                "tasks_active": len([t for t in self.integration_tasks if not t.done()]),
                "total_tasks": len(self.integration_tasks)
            },
            "connectors": {},
            "compliance_components": {}
        }
        
        # Check connector health
        for name, connector in self.connectors.items():
            health_status["connectors"][name] = await connector.health_check()
        
        # Check compliance component health
        try:
            if self.dashboard_manager:
                health_status["compliance_components"]["dashboard_manager"] = await self.dashboard_manager.health_check()
            
            if self.reporting_manager:
                health_status["compliance_components"]["reporting_manager"] = await self.reporting_manager.get_reporting_engine().health_check()
            
            if self.data_warehouse_manager:
                health_status["compliance_components"]["data_warehouse_manager"] = await self.data_warehouse_manager.get_data_warehouse().health_check()
            
            if self.alert_manager:
                health_status["compliance_components"]["alert_manager"] = await self.alert_manager.get_alert_system().health_check()
        
        except Exception as e:
            health_status["compliance_components"]["error"] = str(e)
        
        # Overall health assessment
        component_health = []
        for connector_health in health_status["connectors"].values():
            component_health.append(connector_health.get("status") == "active")
        
        for component_health_data in health_status["compliance_components"].values():
            if isinstance(component_health_data, dict):
                component_health.append(component_health_data.get("status") == "healthy")
        
        if component_health and not all(component_health):
            health_status["status"] = "degraded"
        elif not component_health:
            health_status["status"] = "failed"
        
        return health_status


class DataCorrelationEngine:
    """Engine for correlating data across multiple systems."""
    
    def __init__(self):
        """Initialize data correlation engine."""
        self.correlation_rules = []
        self.correlation_cache = {}
        
        logger.info("Data correlation engine initialized")
    
    async def correlate_data(self, sync_results: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
        """Correlate data from multiple synchronized sources."""
        try:
            correlated_data = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "sources": list(sync_results.keys()),
                "correlations": {},
                "summary": {}
            }
            
            # Simple correlation logic - can be enhanced with ML models
            for source, data in sync_results.items():
                if data.get("status") == "success":
                    correlated_data["correlations"][source] = data.get("data", {})
            
            # Generate summary
            correlated_data["summary"] = {
                "successful_sources": len([d for d in sync_results.values() if d.get("status") == "success"]),
                "failed_sources": len([d for d in sync_results.values() if d.get("status") == "error"]),
                "total_sources": len(sync_results)
            }
            
            return correlated_data
            
        except Exception as e:
            logger.error(f"Error correlating data: {e}")
            return {}
    
    async def perform_correlation_analysis(self):
        """Perform advanced correlation analysis."""
        try:
            # This would perform more sophisticated correlation analysis
            # using machine learning models, statistical analysis, etc.
            pass
        except Exception as e:
            logger.error(f"Error performing correlation analysis: {e}")


class IntegrationManager:
    """Manager class for easy initialization of the integration layer."""
    
    def __init__(
        self,
        audit_orchestrator: IntegratedAuditOrchestrator,
        monitoring_system: EnhancedMonitoringSystem,
        log_aggregator: EnhancedLogAggregator,
        real_time_alerting: RealTimeAlerting,
        rbac_controller: Optional[RBACController] = None,
        classification_engine: Optional[EnhancedMultiClassificationEngine] = None
    ):
        """Initialize integration manager."""
        self.integration_layer = ComplianceIntegrationLayer(
            audit_orchestrator=audit_orchestrator,
            monitoring_system=monitoring_system,
            log_aggregator=log_aggregator,
            real_time_alerting=real_time_alerting,
            rbac_controller=rbac_controller,
            classification_engine=classification_engine
        )
        
        logger.info("Integration manager initialized")
    
    async def start(self):
        """Start the integration system."""
        await self.integration_layer.initialize()
        await self.integration_layer.start()
        logger.info("Integration system started")
    
    async def stop(self):
        """Stop the integration system."""
        await self.integration_layer.stop()
        logger.info("Integration system stopped")
    
    def get_integration_layer(self) -> ComplianceIntegrationLayer:
        """Get the integration layer instance."""
        return self.integration_layer


# Factory function
def create_integration_manager(
    audit_orchestrator: IntegratedAuditOrchestrator,
    monitoring_system: EnhancedMonitoringSystem,
    log_aggregator: EnhancedLogAggregator,
    real_time_alerting: RealTimeAlerting,
    rbac_controller: Optional[RBACController] = None,
    classification_engine: Optional[EnhancedMultiClassificationEngine] = None
) -> IntegrationManager:
    """Create and initialize integration manager."""
    return IntegrationManager(
        audit_orchestrator=audit_orchestrator,
        monitoring_system=monitoring_system,
        log_aggregator=log_aggregator,
        real_time_alerting=real_time_alerting,
        rbac_controller=rbac_controller,
        classification_engine=classification_engine
    )


if __name__ == "__main__":
    # Example usage
    print("Compliance Integration Layer - see code for usage examples")