#!/usr/bin/env python3
"""
RBAC System Manager - Main System Orchestrator

This module provides the main orchestration layer for the DoD-compliant RBAC system,
integrating all components including database, authentication bridges, models, and providing
a unified API for system-wide operations.

Key Features:
- Unified system initialization and lifecycle management
- Component integration and dependency management
- Health monitoring and system diagnostics
- Performance optimization and caching
- Comprehensive error handling and recovery
- DoD compliance validation and reporting
- Emergency access coordination
- Multi-environment configuration management

Classification: UNCLASSIFIED//CUI
Author: Security Compliance Team
Date: 2025-07-29
"""

import asyncio
import logging
import threading
import time
import yaml
from contextlib import asynccontextmanager
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any, Set, Tuple, Union
from dataclasses import dataclass, asdict
from enum import Enum
from uuid import uuid4
import json
import hashlib

# Core system imports
from .rbac_system import RBACSystem, AccessRequest, AccessResponse, AccessDecision
from .init_database import DatabaseInitializer
from .db_utils import DatabaseConnection, ConnectionPoolManager
from .models.base import DatabaseConfiguration

# Model imports
from .models.user import User, UserManager
from .models.role import Role, RoleManager
from .models.permission import Permission, PermissionManager
from .models.audit import AuditLogger, AuditEvent, AuditEventType
from .models.resolver import PermissionResolver
from .models.classification import ClassificationLevel, ClassificationManager

# Integration bridges
from .integrations.cac_rbac_bridge import CACRBACBridge
from .integrations.oauth_rbac_bridge import OAuthRBACBridge

# System validation
from .system_validation import SystemValidator


class SystemStatus(Enum):
    """System status enumeration"""
    INITIALIZING = "initializing"
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    CRITICAL = "critical"
    MAINTENANCE = "maintenance"
    SHUTDOWN = "shutdown"


class ComponentStatus(Enum):
    """Component status enumeration"""
    ACTIVE = "active"
    INACTIVE = "inactive"
    ERROR = "error"
    MAINTENANCE = "maintenance"


@dataclass
class SystemMetrics:
    """System performance and health metrics"""
    timestamp: datetime
    status: SystemStatus
    uptime_seconds: float
    total_requests: int
    successful_requests: int
    failed_requests: int
    average_response_time_ms: float
    cache_hit_rate: float
    database_connections: int
    active_sessions: int
    memory_usage_mb: float
    cpu_usage_percent: float
    component_statuses: Dict[str, ComponentStatus]
    last_error: Optional[str] = None


@dataclass
class ComponentHealth:
    """Individual component health status"""
    name: str
    status: ComponentStatus
    last_check: datetime
    response_time_ms: Optional[float]
    error_count: int
    error_message: Optional[str]
    dependencies: List[str]
    metrics: Dict[str, Any]


class RBACSystemManager:
    """
    Main RBAC System Manager
    
    Orchestrates all RBAC components and provides unified system management,
    monitoring, and control interfaces for DoD-compliant operations.
    """
    
    def __init__(self, config_path: Optional[str] = None, environment: str = 'production'):
        """
        Initialize the RBAC System Manager.
        
        Args:
            config_path: Path to system configuration file
            environment: Target environment (development, staging, production, nipr, sipr, jwics)
        """
        self.environment = environment
        self.start_time = datetime.now(timezone.utc)
        self.config_path = config_path
        
        # System state
        self._status = SystemStatus.INITIALIZING
        self._shutdown_event = threading.Event()
        self._maintenance_mode = False
        
        # Component references
        self._components: Dict[str, Any] = {}
        self._component_health: Dict[str, ComponentHealth] = {}
        
        # Configuration
        self._system_config = self._load_system_config()
        self._db_config = DatabaseConfiguration(config_path)
        
        # Metrics and monitoring
        self._metrics = SystemMetrics(
            timestamp=datetime.now(timezone.utc),
            status=SystemStatus.INITIALIZING,
            uptime_seconds=0.0,
            total_requests=0,
            successful_requests=0,
            failed_requests=0,
            average_response_time_ms=0.0,
            cache_hit_rate=0.0,
            database_connections=0,
            active_sessions=0,
            memory_usage_mb=0.0,
            cpu_usage_percent=0.0,
            component_statuses={}
        )
        
        # Performance tracking
        self._performance_lock = threading.RLock()
        self._request_times: List[float] = []
        
        # Configure logging
        self._setup_logging()
        self.logger = logging.getLogger(__name__)
        
        self.logger.info(f"RBAC System Manager initialized for environment: {environment}")
    
    def _load_system_config(self) -> Dict[str, Any]:
        """Load system configuration."""
        config_file = self.config_path or Path(__file__).parent / 'config' / 'system_config.yaml'
        
        try:
            if Path(config_file).exists():
                with open(config_file, 'r') as f:
                    config = yaml.safe_load(f)
            else:
                # Default configuration
                config = {
                    'system': {
                        'name': 'DoD RBAC System',
                        'version': '1.0.0',
                        'enable_caching': True,
                        'cache_ttl': 300,
                        'max_concurrent_requests': 1000,
                        'health_check_interval': 30,
                        'metrics_retention_days': 90
                    },
                    'components': {
                        'rbac_core': {'enabled': True, 'priority': 1},
                        'database': {'enabled': True, 'priority': 1},
                        'cac_bridge': {'enabled': True, 'priority': 2},
                        'oauth_bridge': {'enabled': True, 'priority': 2},
                        'audit_logger': {'enabled': True, 'priority': 1},
                        'validator': {'enabled': True, 'priority': 3}
                    },
                    'security': {
                        'emergency_access_enabled': True,
                        'session_timeout_minutes': 60,
                        'max_failed_attempts': 3,
                        'lockout_duration_minutes': 15,
                        'require_mfa_for_admin': True,
                        'audit_all_access': True
                    },
                    'performance': {
                        'enable_performance_monitoring': True,
                        'slow_request_threshold_ms': 1000,
                        'cache_size': 10000,
                        'connection_pool_size': 20
                    }
                }
            
            return config
        except Exception as e:
            self.logger.error(f"Failed to load system configuration: {e}")
            raise
    
    def _setup_logging(self):
        """Setup comprehensive logging configuration."""
        log_config = self._system_config.get('logging', {})
        
        # Configure root logger
        log_level = getattr(logging, log_config.get('level', 'INFO').upper())
        
        logging.basicConfig(
            level=log_level,
            format='%(asctime)s - %(name)s - %(levelname)s - [%(funcName)s:%(lineno)d] - %(message)s',
            handlers=[
                logging.StreamHandler(),
                logging.FileHandler(
                    log_config.get('file', f'/var/log/rbac/system_manager_{self.environment}.log'),
                    mode='a'
                )
            ]
        )
        
        # Configure audit logger
        audit_logger = logging.getLogger('rbac.audit')
        audit_handler = logging.FileHandler(
            log_config.get('audit_file', f'/var/log/rbac/audit_{self.environment}.log'),
            mode='a'
        )
        audit_handler.setFormatter(
            logging.Formatter('%(asctime)s - AUDIT - %(message)s')
        )
        audit_logger.addHandler(audit_handler)
        audit_logger.setLevel(logging.INFO)
    
    async def initialize_system(self, force_reinit: bool = False) -> bool:
        """
        Initialize the complete RBAC system.
        
        Args:
            force_reinit: Force re-initialization of all components
            
        Returns:
            bool: True if initialization successful
        """
        self.logger.info("Starting RBAC system initialization")
        
        try:
            self._status = SystemStatus.INITIALIZING
            
            # Step 1: Initialize database
            if not await self._initialize_database(force_reinit):
                self.logger.error("Database initialization failed")
                return False
            
            # Step 2: Initialize core RBAC system
            if not await self._initialize_rbac_core():
                self.logger.error("RBAC core initialization failed")
                return False
            
            # Step 3: Initialize authentication bridges
            if not await self._initialize_auth_bridges():
                self.logger.error("Authentication bridge initialization failed")
                return False
            
            # Step 4: Initialize system validator
            if not await self._initialize_validator():
                self.logger.error("System validator initialization failed")
                return False
            
            # Step 5: Start background services
            if not await self._start_background_services():
                self.logger.error("Background services startup failed")
                return False
            
            # Step 6: Validate complete system
            validation_result = await self._validate_system()
            if not validation_result:
                self.logger.error("System validation failed")
                return False
            
            # System initialized successfully
            self._status = SystemStatus.HEALTHY
            self.logger.info("RBAC system initialization completed successfully")
            
            # Log initialization event
            await self._log_system_event("SYSTEM_INITIALIZED", {
                "environment": self.environment,
                "initialization_time": datetime.now(timezone.utc).isoformat(),
                "components": list(self._components.keys())
            })
            
            return True
            
        except Exception as e:
            self.logger.error(f"System initialization failed: {e}")
            self._status = SystemStatus.CRITICAL
            return False
    
    async def _initialize_database(self, force_reinit: bool = False) -> bool:
        """Initialize database components."""
        self.logger.info("Initializing database components")
        
        try:
            # Initialize database initializer
            db_initializer = DatabaseInitializer(
                config_path=self.config_path,
                environment=self.environment
            )
            
            # Run database initialization
            init_success = db_initializer.initialize_database(
                force=force_reinit,
                validate_only=False
            )
            
            if not init_success:
                return False
            
            # Initialize connection pool manager
            pool_manager = ConnectionPoolManager(self._db_config)
            
            # Store components
            self._components['database_initializer'] = db_initializer
            self._components['connection_pool'] = pool_manager
            
            # Update component health
            self._component_health['database'] = ComponentHealth(
                name='database',
                status=ComponentStatus.ACTIVE,
                last_check=datetime.now(timezone.utc),
                response_time_ms=None,
                error_count=0,
                error_message=None,
                dependencies=[],
                metrics={"connections": pool_manager.get_pool_status() if hasattr(pool_manager, 'get_pool_status') else {}}
            )
            
            self.logger.info("Database components initialized successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Database initialization failed: {e}")
            self._component_health['database'] = ComponentHealth(
                name='database',
                status=ComponentStatus.ERROR,
                last_check=datetime.now(timezone.utc),
                response_time_ms=None,
                error_count=1,
                error_message=str(e),
                dependencies=[],
                metrics={}
            )
            return False
    
    async def _initialize_rbac_core(self) -> bool:
        """Initialize core RBAC system."""
        self.logger.info("Initializing RBAC core system")
        
        try:
            # Initialize RBAC system with configuration
            performance_config = self._system_config.get('performance', {})
            security_config = self._system_config.get('security', {})
            
            rbac_system = RBACSystem(
                cache_size=performance_config.get('cache_size', 10000),
                cache_ttl=self._system_config.get('system', {}).get('cache_ttl', 300),
                enable_emergency_access=security_config.get('emergency_access_enabled', True)
            )
            
            # Initialize component managers
            user_manager = UserManager()
            role_manager = RoleManager()
            permission_manager = PermissionManager()
            audit_logger = AuditLogger.instance()
            classification_manager = ClassificationManager()
            
            # Store components
            self._components['rbac_core'] = rbac_system
            self._components['user_manager'] = user_manager
            self._components['role_manager'] = role_manager
            self._components['permission_manager'] = permission_manager
            self._components['audit_logger'] = audit_logger
            self._components['classification_manager'] = classification_manager
            
            # Update component health
            self._component_health['rbac_core'] = ComponentHealth(
                name='rbac_core',
                status=ComponentStatus.ACTIVE,
                last_check=datetime.now(timezone.utc),
                response_time_ms=None,
                error_count=0,
                error_message=None,
                dependencies=['database'],
                metrics={}
            )
            
            self.logger.info("RBAC core system initialized successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"RBAC core initialization failed: {e}")
            self._component_health['rbac_core'] = ComponentHealth(
                name='rbac_core',
                status=ComponentStatus.ERROR,
                last_check=datetime.now(timezone.utc),
                response_time_ms=None,
                error_count=1,
                error_message=str(e),
                dependencies=['database'],
                metrics={}
            )
            return False
    
    async def _initialize_auth_bridges(self) -> bool:
        """Initialize authentication bridges."""
        self.logger.info("Initializing authentication bridges")
        
        try:
            components_config = self._system_config.get('components', {})
            
            # Initialize CAC/PIV bridge if enabled
            if components_config.get('cac_bridge', {}).get('enabled', True):
                cac_bridge = CACRBACBridge(
                    config_path=self.config_path,
                    environment=self.environment
                )
                self._components['cac_bridge'] = cac_bridge
                
                self._component_health['cac_bridge'] = ComponentHealth(
                    name='cac_bridge',
                    status=ComponentStatus.ACTIVE,
                    last_check=datetime.now(timezone.utc),
                    response_time_ms=None,
                    error_count=0,
                    error_message=None,
                    dependencies=['rbac_core', 'database'],
                    metrics={}
                )
            
            # Initialize OAuth bridge if enabled
            if components_config.get('oauth_bridge', {}).get('enabled', True):
                oauth_bridge = OAuthRBACBridge(
                    config_path=self.config_path,
                    environment=self.environment
                )
                self._components['oauth_bridge'] = oauth_bridge
                
                self._component_health['oauth_bridge'] = ComponentHealth(
                    name='oauth_bridge',
                    status=ComponentStatus.ACTIVE,
                    last_check=datetime.now(timezone.utc),
                    response_time_ms=None,
                    error_count=0,
                    error_message=None,
                    dependencies=['rbac_core', 'database'],
                    metrics={}
                )
            
            self.logger.info("Authentication bridges initialized successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Authentication bridge initialization failed: {e}")
            return False
    
    async def _initialize_validator(self) -> bool:
        """Initialize system validator."""
        self.logger.info("Initializing system validator")
        
        try:
            validator = SystemValidator(
                config_path=self.config_path,
                environment=self.environment
            )
            
            self._components['validator'] = validator
            
            self._component_health['validator'] = ComponentHealth(
                name='validator',
                status=ComponentStatus.ACTIVE,
                last_check=datetime.now(timezone.utc),
                response_time_ms=None,
                error_count=0,
                error_message=None,
                dependencies=['rbac_core', 'database'],
                metrics={}
            )
            
            self.logger.info("System validator initialized successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"System validator initialization failed: {e}")
            self._component_health['validator'] = ComponentHealth(
                name='validator',
                status=ComponentStatus.ERROR,
                last_check=datetime.now(timezone.utc),
                response_time_ms=None,
                error_count=1,
                error_message=str(e),
                dependencies=['rbac_core', 'database'],
                metrics={}
            )
            return False
    
    async def _start_background_services(self) -> bool:
        """Start background monitoring and maintenance services."""
        self.logger.info("Starting background services")
        
        try:
            # Start health monitoring
            asyncio.create_task(self._health_monitor_loop())
            
            # Start metrics collection
            asyncio.create_task(self._metrics_collection_loop())
            
            # Start maintenance tasks
            asyncio.create_task(self._maintenance_loop())
            
            self.logger.info("Background services started successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Background services startup failed: {e}")
            return False
    
    async def _validate_system(self) -> bool:
        """Validate complete system."""
        self.logger.info("Validating complete system")
        
        try:
            validator = self._components.get('validator')
            if not validator:
                self.logger.error("System validator not available")
                return False
            
            # Run comprehensive validation
            validation_result = await validator.validate_complete_system()
            
            if validation_result.get('overall_health', False):
                self.logger.info("System validation passed")
                return True
            else:
                self.logger.error(f"System validation failed: {validation_result}")
                return False
                
        except Exception as e:
            self.logger.error(f"System validation error: {e}")
            return False
    
    async def check_access(self, user_id: str, resource_id: str, resource_type: str, 
                          action: str, **kwargs) -> AccessResponse:
        """
        Unified access control check through the system manager.
        
        Args:
            user_id: User identifier
            resource_id: Resource identifier
            resource_type: Type of resource
            action: Action being performed
            **kwargs: Additional context parameters
            
        Returns:
            AccessResponse with decision and audit trail
        """
        start_time = time.time()
        
        try:
            # Update request metrics
            with self._performance_lock:
                self._metrics.total_requests += 1
            
            # Get RBAC core system
            rbac_core = self._components.get('rbac_core')
            if not rbac_core:
                raise Exception("RBAC core system not available")
            
            # Create access request
            request = AccessRequest(
                user_id=user_id,
                resource_id=resource_id,
                resource_type=resource_type,
                action=action,
                context=kwargs.get('context', {}),
                timestamp=datetime.now(timezone.utc),
                session_id=kwargs.get('session_id'),
                emergency_access=kwargs.get('emergency_access', False),
                classification_level=kwargs.get('classification_level'),
                ip_address=kwargs.get('ip_address'),
                user_agent=kwargs.get('user_agent')
            )
            
            # Perform access check
            response = await rbac_core.check_access(request)
            
            # Update metrics
            elapsed_time_ms = (time.time() - start_time) * 1000
            
            with self._performance_lock:
                if response.granted:
                    self._metrics.successful_requests += 1
                else:
                    self._metrics.failed_requests += 1
                
                self._request_times.append(elapsed_time_ms)
                
                # Keep only recent request times for average calculation
                if len(self._request_times) > 1000:
                    self._request_times = self._request_times[-1000:]
                
                # Update average response time
                if self._request_times:
                    self._metrics.average_response_time_ms = sum(self._request_times) / len(self._request_times)
            
            return response
            
        except Exception as e:
            # Update error metrics
            with self._performance_lock:
                self._metrics.failed_requests += 1
            
            self.logger.error(f"Access check failed: {e}")
            
            return AccessResponse(
                decision=AccessDecision.DENY,
                granted=False,
                reason=f"System error: {str(e)}",
                applied_policies=[],
                effective_permissions=[],
                audit_trail={"error": str(e)},
                evaluation_time_ms=(time.time() - start_time) * 1000
            )
    
    async def get_system_status(self) -> Dict[str, Any]:
        """Get comprehensive system status."""
        # Update metrics
        current_time = datetime.now(timezone.utc)
        uptime = (current_time - self.start_time).total_seconds()
        
        self._metrics.timestamp = current_time
        self._metrics.status = self._status
        self._metrics.uptime_seconds = uptime
        self._metrics.component_statuses = {
            name: health.status.value for name, health in self._component_health.items()
        }
        
        # Collect component-specific metrics
        component_metrics = {}
        for name, component in self._components.items():
            if hasattr(component, 'get_performance_metrics'):
                component_metrics[name] = component.get_performance_metrics()
            elif hasattr(component, 'health_check'):
                try:
                    health_result = component.health_check()
                    component_metrics[name] = health_result
                except Exception as e:
                    component_metrics[name] = {"error": str(e)}
        
        return {
            "system": asdict(self._metrics),
            "components": {
                name: asdict(health) for name, health in self._component_health.items()
            },
            "component_metrics": component_metrics,
            "environment": self.environment,
            "configuration": {
                "cache_enabled": self._system_config.get('system', {}).get('enable_caching', True),
                "emergency_access": self._system_config.get('security', {}).get('emergency_access_enabled', True),
                "audit_enabled": self._system_config.get('security', {}).get('audit_all_access', True)
            }
        }
    
    async def get_health_check(self) -> Dict[str, Any]:
        """Perform comprehensive health check."""
        health_results = {}
        overall_healthy = True
        
        # Check each component
        for name, component in self._components.items():
            try:
                if hasattr(component, 'health_check'):
                    start_time = time.time()
                    health_result = component.health_check()
                    response_time = (time.time() - start_time) * 1000
                    
                    is_healthy = health_result.get('healthy', False)
                    if not is_healthy:
                        overall_healthy = False
                    
                    health_results[name] = {
                        "healthy": is_healthy,
                        "response_time_ms": response_time,
                        "details": health_result
                    }
                    
                    # Update component health
                    if name in self._component_health:
                        self._component_health[name].last_check = datetime.now(timezone.utc)
                        self._component_health[name].response_time_ms = response_time
                        self._component_health[name].status = ComponentStatus.ACTIVE if is_healthy else ComponentStatus.ERROR
                        if not is_healthy:
                            self._component_health[name].error_count += 1
                            self._component_health[name].error_message = health_result.get('error')
                else:
                    health_results[name] = {
                        "healthy": True,
                        "response_time_ms": 0,
                        "details": {"status": "no health check available"}
                    }
            except Exception as e:
                overall_healthy = False
                health_results[name] = {
                    "healthy": False,
                    "response_time_ms": 0,
                    "details": {"error": str(e)}
                }
                
                # Update component health
                if name in self._component_health:
                    self._component_health[name].status = ComponentStatus.ERROR
                    self._component_health[name].error_count += 1
                    self._component_health[name].error_message = str(e)
        
        # Update system status based on health check
        if overall_healthy:
            if self._status == SystemStatus.DEGRADED:
                self._status = SystemStatus.HEALTHY
        else:
            if self._status == SystemStatus.HEALTHY:
                self._status = SystemStatus.DEGRADED
        
        return {
            "overall_healthy": overall_healthy,
            "system_status": self._status.value,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "components": health_results,
            "uptime_seconds": (datetime.now(timezone.utc) - self.start_time).total_seconds()
        }
    
    async def shutdown_system(self, graceful: bool = True, timeout: int = 30) -> bool:
        """
        Shutdown the RBAC system.
        
        Args:
            graceful: Perform graceful shutdown
            timeout: Timeout for graceful shutdown in seconds
            
        Returns:
            bool: True if shutdown successful
        """
        self.logger.info(f"Initiating system shutdown (graceful={graceful})")
        
        try:
            self._status = SystemStatus.SHUTDOWN
            
            if graceful:
                # Signal shutdown to background services
                self._shutdown_event.set()
                
                # Wait for active requests to complete
                shutdown_start = time.time()
                while time.time() - shutdown_start < timeout:
                    # Check if there are active requests
                    # This would be implemented based on request tracking
                    await asyncio.sleep(0.1)
                    break  # For now, just break immediately
            
            # Shutdown components in reverse dependency order
            shutdown_order = ['validator', 'oauth_bridge', 'cac_bridge', 'rbac_core', 'database']
            
            for component_name in shutdown_order:
                component = self._components.get(component_name)
                if component and hasattr(component, 'shutdown'):
                    try:
                        await component.shutdown()
                        self.logger.info(f"Component {component_name} shut down successfully")
                    except Exception as e:
                        self.logger.error(f"Error shutting down component {component_name}: {e}")
            
            # Log shutdown event
            await self._log_system_event("SYSTEM_SHUTDOWN", {
                "graceful": graceful,
                "shutdown_time": datetime.now(timezone.utc).isoformat()
            })
            
            self.logger.info("System shutdown completed")
            return True
            
        except Exception as e:
            self.logger.error(f"System shutdown failed: {e}")
            return False
    
    async def _health_monitor_loop(self):
        """Background health monitoring loop."""
        health_check_interval = self._system_config.get('system', {}).get('health_check_interval', 30)
        
        while not self._shutdown_event.is_set():
            try:
                await self.get_health_check()
                await asyncio.sleep(health_check_interval)
            except Exception as e:
                self.logger.error(f"Health monitor error: {e}")
                await asyncio.sleep(5)  # Short sleep on error
    
    async def _metrics_collection_loop(self):
        """Background metrics collection loop."""
        while not self._shutdown_event.is_set():
            try:
                # Collect system metrics
                current_status = await self.get_system_status()
                
                # Store metrics for reporting (could be sent to monitoring system)
                self.logger.debug(f"System metrics collected: {current_status['system']['timestamp']}")
                
                await asyncio.sleep(60)  # Collect metrics every minute
            except Exception as e:
                self.logger.error(f"Metrics collection error: {e}")
                await asyncio.sleep(10)
    
    async def _maintenance_loop(self):
        """Background maintenance tasks loop."""
        while not self._shutdown_event.is_set():
            try:
                # Perform maintenance tasks
                await self._perform_maintenance_tasks()
                
                # Run maintenance every hour
                await asyncio.sleep(3600)
            except Exception as e:
                self.logger.error(f"Maintenance loop error: {e}")
                await asyncio.sleep(300)  # 5 minutes on error
    
    async def _perform_maintenance_tasks(self):
        """Perform routine maintenance tasks."""
        try:
            # Cache cleanup
            rbac_core = self._components.get('rbac_core')
            if rbac_core and hasattr(rbac_core, 'permission_resolver'):
                # This would implement cache cleanup
                pass
            
            # Audit log rotation
            audit_logger = self._components.get('audit_logger')
            if audit_logger and hasattr(audit_logger, 'rotate_logs'):
                await audit_logger.rotate_logs()
            
            # Database maintenance
            db_connection = self._components.get('connection_pool')
            if db_connection and hasattr(db_connection, 'cleanup_connections'):
                await db_connection.cleanup_connections()
            
            self.logger.debug("Maintenance tasks completed")
            
        except Exception as e:
            self.logger.error(f"Maintenance task error: {e}")
    
    async def _log_system_event(self, event_type: str, event_data: Dict[str, Any]):
        """Log system-level events."""
        try:
            audit_logger = self._components.get('audit_logger')
            if audit_logger:
                await audit_logger.log_event(AuditEvent(
                    event_type=AuditEventType.SYSTEM_EVENT,
                    timestamp=datetime.now(timezone.utc),
                    user_id="system",
                    success=True,
                    additional_data={
                        "system_event_type": event_type,
                        **event_data
                    }
                ))
        except Exception as e:
            self.logger.error(f"Failed to log system event: {e}")
    
    @asynccontextmanager
    async def system_context(self):
        """Context manager for system lifecycle."""
        try:
            # Initialize system
            init_success = await self.initialize_system()
            if not init_success:
                raise Exception("System initialization failed")
            
            yield self
            
        finally:
            # Shutdown system
            await self.shutdown_system()


# Utility functions
async def create_system_manager(config_path: Optional[str] = None, 
                              environment: str = 'production') -> RBACSystemManager:
    """Create and initialize RBAC system manager."""
    manager = RBACSystemManager(config_path=config_path, environment=environment)
    
    init_success = await manager.initialize_system()
    if not init_success:
        raise Exception("Failed to initialize RBAC system manager")
    
    return manager


# Example usage
if __name__ == "__main__":
    async def demo():
        """Demonstrate system manager usage."""
        # Create system manager
        async with RBACSystemManager(environment='development').system_context() as manager:
            
            # Perform access check
            response = await manager.check_access(
                user_id="test_user",
                resource_id="test_resource",
                resource_type="notebook",
                action="execute",
                context={"test": True},
                classification_level="UNCLASSIFIED"
            )
            
            print(f"Access Decision: {response.decision}")
            print(f"Granted: {response.granted}")
            print(f"Reason: {response.reason}")
            
            # Get system status
            status = await manager.get_system_status()
            print(f"System Status: {status['system']['status']}")
            print(f"Total Requests: {status['system']['total_requests']}")
            
            # Perform health check
            health = await manager.get_health_check()
            print(f"System Health: {health['overall_healthy']}")
            print(f"Component Count: {len(health['components'])}")
    
    # Run demo
    asyncio.run(demo())