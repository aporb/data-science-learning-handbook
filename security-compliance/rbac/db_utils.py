"""
Database Utilities for DoD-Compliant RBAC System

Production-ready utilities for database connection management, health monitoring,
migration management, and maintenance operations.

Classification: UNCLASSIFIED//FOR OFFICIAL USE ONLY
Author: Security Compliance Team
Date: 2025-07-29
"""

import logging
import time
import threading
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Callable
from pathlib import Path
import psycopg2
from psycopg2.extras import RealDictCursor
import redis
import yaml
from contextlib import contextmanager
from dataclasses import dataclass
from enum import Enum

from models.base import DatabaseConfiguration, DatabaseConnection, ConnectionPoolManager

logger = logging.getLogger(__name__)


class HealthStatus(Enum):
    """Health check status enumeration."""
    HEALTHY = "healthy"
    DEGRADED = "degraded" 
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


@dataclass
class HealthCheckResult:
    """Health check result data structure."""
    status: HealthStatus
    component: str
    timestamp: datetime
    response_time_ms: float
    details: Dict[str, Any]
    error_message: Optional[str] = None


@dataclass
class MigrationInfo:
    """Migration information data structure."""
    filename: str
    version: str
    description: str
    executed_at: Optional[datetime]
    checksum: str
    execution_time_ms: Optional[float] = None


class DatabaseHealthMonitor:
    """
    Comprehensive database health monitoring system.
    
    Provides real-time health checks, performance monitoring, and alerting
    for all database components in the RBAC system.
    """
    
    def __init__(self, config: DatabaseConfiguration = None):
        """Initialize health monitor."""
        self.config = config or DatabaseConfiguration()
        self.pool_manager = ConnectionPoolManager(self.config)
        self._monitoring_active = False
        self._monitor_thread = None
        self._health_history: List[HealthCheckResult] = []
        self._max_history_size = 1000
        
        # Health check thresholds
        self.thresholds = {
            'response_time_warning_ms': 1000,
            'response_time_critical_ms': 5000,
            'connection_pool_warning_pct': 80,
            'connection_pool_critical_pct': 95
        }
        
        logger.info("Database health monitor initialized")
    
    def start_monitoring(self, interval_seconds: int = 60):
        """Start continuous health monitoring."""
        if self._monitoring_active:
            logger.warning("Health monitoring already active")
            return
        
        self._monitoring_active = True
        self._monitor_thread = threading.Thread(
            target=self._monitor_loop,
            args=(interval_seconds,),
            daemon=True
        )
        self._monitor_thread.start()
        
        logger.info(f"Started health monitoring with {interval_seconds}s interval")
    
    def stop_monitoring(self):
        """Stop continuous health monitoring."""
        self._monitoring_active = False
        if self._monitor_thread:
            self._monitor_thread.join(timeout=10)
        
        logger.info("Stopped health monitoring")
    
    def _monitor_loop(self, interval_seconds: int):
        """Main monitoring loop."""
        while self._monitoring_active:
            try:
                results = self.check_all_components()
                self._process_health_results(results)
                time.sleep(interval_seconds)
            except Exception as e:
                logger.error(f"Health monitoring loop error: {e}")
                time.sleep(interval_seconds)
    
    def check_all_components(self) -> List[HealthCheckResult]:
        """Perform health checks on all database components."""
        results = []
        
        # Check primary database
        results.append(self._check_database_health('primary'))
        
        # Check replica database if configured
        try:
            results.append(self._check_database_health('replica'))
        except Exception:
            pass  # Replica may not be configured
        
        # Check audit database if configured
        try:
            results.append(self._check_database_health('audit'))
        except Exception:
            pass  # Audit database may not be configured
        
        # Check Redis cache
        results.append(self._check_redis_health())
        
        # Check connection pool status
        results.append(self._check_connection_pools())
        
        return results
    
    def _check_database_health(self, db_type: str) -> HealthCheckResult:
        """Check health of a specific database."""
        start_time = time.time()
        
        try:
            db_conn = DatabaseConnection(self.config, db_type)
            
            with db_conn.get_connection() as conn:
                with conn.cursor() as cursor:
                    # Basic connectivity test
                    cursor.execute("SELECT 1 as health_check")
                    result = cursor.fetchone()
                    
                    # Check database size and activity
                    cursor.execute("""
                        SELECT 
                            pg_database_size(current_database()) as db_size_bytes,
                            (SELECT count(*) FROM pg_stat_activity WHERE state = 'active') as active_connections,
                            (SELECT count(*) FROM pg_stat_activity) as total_connections
                    """)
                    db_stats = cursor.fetchone()
                    
                    response_time_ms = (time.time() - start_time) * 1000
                    
                    # Determine status based on response time
                    if response_time_ms > self.thresholds['response_time_critical_ms']:
                        status = HealthStatus.UNHEALTHY
                    elif response_time_ms > self.thresholds['response_time_warning_ms']:
                        status = HealthStatus.DEGRADED
                    else:
                        status = HealthStatus.HEALTHY
                    
                    return HealthCheckResult(
                        status=status,
                        component=f"database_{db_type}",
                        timestamp=datetime.now(timezone.utc),
                        response_time_ms=response_time_ms,
                        details={
                            'database_size_bytes': db_stats['db_size_bytes'],
                            'active_connections': db_stats['active_connections'],
                            'total_connections': db_stats['total_connections'],
                            'database_type': db_type
                        }
                    )
        
        except Exception as e:
            return HealthCheckResult(
                status=HealthStatus.UNHEALTHY,
                component=f"database_{db_type}",
                timestamp=datetime.now(timezone.utc),
                response_time_ms=(time.time() - start_time) * 1000,
                details={'database_type': db_type},
                error_message=str(e)
            )
    
    def _check_redis_health(self) -> HealthCheckResult:
        """Check Redis cache health."""
        start_time = time.time()
        
        try:
            redis_client = self.pool_manager.get_redis_client()
            
            if not redis_client:
                return HealthCheckResult(
                    status=HealthStatus.UNKNOWN,
                    component="redis_cache",
                    timestamp=datetime.now(timezone.utc),
                    response_time_ms=0,
                    details={'configured': False}
                )
            
            # Test basic connectivity
            redis_client.ping()
            
            # Get Redis info
            info = redis_client.info()
            
            response_time_ms = (time.time() - start_time) * 1000
            
            # Check memory usage
            used_memory = info.get('used_memory', 0)
            max_memory = info.get('maxmemory', 0)
            
            status = HealthStatus.HEALTHY
            if max_memory > 0:
                memory_usage_pct = (used_memory / max_memory) * 100
                if memory_usage_pct > 90:
                    status = HealthStatus.DEGRADED
                elif memory_usage_pct > 95:
                    status = HealthStatus.UNHEALTHY
            
            return HealthCheckResult(
                status=status,
                component="redis_cache",
                timestamp=datetime.now(timezone.utc),
                response_time_ms=response_time_ms,
                details={
                    'used_memory_bytes': used_memory,
                    'max_memory_bytes': max_memory,
                    'connected_clients': info.get('connected_clients', 0),
                    'redis_version': info.get('redis_version', 'unknown')
                }
            )
        
        except Exception as e:
            return HealthCheckResult(
                status=HealthStatus.UNHEALTHY,
                component="redis_cache",
                timestamp=datetime.now(timezone.utc),
                response_time_ms=(time.time() - start_time) * 1000,
                details={},
                error_message=str(e)
            )
    
    def _check_connection_pools(self) -> HealthCheckResult:
        """Check connection pool health."""
        try:
            pool_status = self.pool_manager.get_pool_status()
            
            overall_status = HealthStatus.HEALTHY
            details = {}
            
            for pool_name, status in pool_status.items():
                details[pool_name] = status
                if not status.get('available', False):
                    overall_status = HealthStatus.UNHEALTHY
            
            return HealthCheckResult(
                status=overall_status,
                component="connection_pools",
                timestamp=datetime.now(timezone.utc),
                response_time_ms=0,
                details=details
            )
        
        except Exception as e:
            return HealthCheckResult(
                status=HealthStatus.UNHEALTHY,
                component="connection_pools",
                timestamp=datetime.now(timezone.utc),
                response_time_ms=0,
                details={},
                error_message=str(e)
            )
    
    def _process_health_results(self, results: List[HealthCheckResult]):
        """Process health check results and trigger alerts if needed."""
        # Store results in history
        self._health_history.extend(results)
        
        # Maintain history size limit
        if len(self._health_history) > self._max_history_size:
            self._health_history = self._health_history[-self._max_history_size:]
        
        # Check for alert conditions
        for result in results:
            if result.status in [HealthStatus.DEGRADED, HealthStatus.UNHEALTHY]:
                self._trigger_alert(result)
    
    def _trigger_alert(self, result: HealthCheckResult):
        """Trigger alert for unhealthy components."""
        alert_message = f"RBAC Health Alert: {result.component} is {result.status.value}"
        if result.error_message:
            alert_message += f" - {result.error_message}"
        
        logger.warning(alert_message)
        
        # Here you would integrate with your alerting system
        # e.g., send to Splunk, PagerDuty, email, etc.
    
    def get_health_summary(self) -> Dict[str, Any]:
        """Get current health summary."""
        recent_results = [
            r for r in self._health_history 
            if r.timestamp > datetime.now(timezone.utc) - timedelta(minutes=5)
        ]
        
        if not recent_results:
            return {'status': 'unknown', 'components': {}}
        
        component_status = {}
        overall_status = HealthStatus.HEALTHY
        
        for result in recent_results:
            component_status[result.component] = {
                'status': result.status.value,
                'last_check': result.timestamp.isoformat(),
                'response_time_ms': result.response_time_ms,
                'details': result.details
            }
            
            if result.status == HealthStatus.UNHEALTHY:
                overall_status = HealthStatus.UNHEALTHY
            elif result.status == HealthStatus.DEGRADED and overall_status == HealthStatus.HEALTHY:
                overall_status = HealthStatus.DEGRADED
        
        return {
            'status': overall_status.value,
            'last_updated': datetime.now(timezone.utc).isoformat(),
            'components': component_status
        }


class MigrationManager:
    """
    Database migration management system.
    
    Handles schema versioning, migration tracking, rollback capabilities,
    and safe deployment of database changes.
    """
    
    def __init__(self, config: DatabaseConfiguration = None):
        """Initialize migration manager."""
        self.config = config or DatabaseConfiguration()
        self.db_conn = DatabaseConnection(self.config, 'primary')
        self._ensure_migration_table()
        
        logger.info("Migration manager initialized")
    
    def _ensure_migration_table(self):
        """Ensure the migration tracking table exists."""
        with self.db_conn.get_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS rbac.schema_migrations (
                        id SERIAL PRIMARY KEY,
                        filename VARCHAR(255) UNIQUE NOT NULL,
                        version VARCHAR(50) NOT NULL,
                        description TEXT,
                        checksum VARCHAR(64) NOT NULL,
                        executed_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                        execution_time_ms INTEGER,
                        rollback_sql TEXT,
                        created_by VARCHAR(100) DEFAULT CURRENT_USER,
                        CONSTRAINT unique_version UNIQUE(version)
                    )
                """)
                
                # Create index for performance
                cursor.execute("""
                    CREATE INDEX IF NOT EXISTS idx_schema_migrations_version 
                    ON rbac.schema_migrations(version)
                """)
                
                conn.commit()
    
    def get_migration_status(self) -> List[MigrationInfo]:
        """Get status of all migrations."""
        with self.db_conn.get_cursor() as cursor:
            cursor.execute("""
                SELECT filename, version, description, executed_at, 
                       checksum, execution_time_ms
                FROM rbac.schema_migrations
                ORDER BY executed_at
            """)
            
            results = cursor.fetchall()
            
            return [
                MigrationInfo(
                    filename=row['filename'],
                    version=row['version'],
                    description=row['description'],
                    executed_at=row['executed_at'],
                    checksum=row['checksum'],
                    execution_time_ms=row['execution_time_ms']
                )
                for row in results
            ]
    
    def apply_migration(self, migration_file: Path, rollback_sql: str = None) -> bool:
        """Apply a single migration file."""
        try:
            # Read migration file
            with open(migration_file, 'r') as f:
                sql_content = f.read()
            
            # Calculate checksum
            import hashlib
            checksum = hashlib.sha256(sql_content.encode()).hexdigest()
            
            # Check if migration already applied
            with self.db_conn.get_cursor() as cursor:
                cursor.execute(
                    "SELECT checksum FROM rbac.schema_migrations WHERE filename = %s",
                    (migration_file.name,)
                )
                
                existing = cursor.fetchone()
                if existing:
                    if existing['checksum'] == checksum:
                        logger.info(f"Migration {migration_file.name} already applied")
                        return True
                    else:
                        logger.error(f"Migration {migration_file.name} checksum mismatch")
                        return False
            
            # Apply migration
            start_time = time.time()
            
            with self.db_conn.get_connection() as conn:
                with conn.cursor() as cursor:
                    # Execute migration SQL
                    cursor.execute(sql_content)
                    
                    execution_time_ms = int((time.time() - start_time) * 1000)
                    
                    # Record migration
                    cursor.execute("""
                        INSERT INTO rbac.schema_migrations 
                        (filename, version, description, checksum, execution_time_ms, rollback_sql)
                        VALUES (%s, %s, %s, %s, %s, %s)
                    """, (
                        migration_file.name,
                        self._extract_version(migration_file.name),
                        f"Migration from {migration_file.name}",
                        checksum,
                        execution_time_ms,
                        rollback_sql
                    ))
                    
                    conn.commit()
            
            logger.info(f"Successfully applied migration: {migration_file.name}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to apply migration {migration_file.name}: {e}")
            return False
    
    def _extract_version(self, filename: str) -> str:
        """Extract version from migration filename."""
        # Extract version from filename like "01_core_schema.sql"
        parts = filename.split('_')
        if parts:
            return parts[0]
        return "unknown"
    
    def rollback_migration(self, version: str) -> bool:
        """Rollback a specific migration."""
        try:
            with self.db_conn.get_cursor() as cursor:
                cursor.execute("""
                    SELECT rollback_sql FROM rbac.schema_migrations 
                    WHERE version = %s
                """, (version,))
                
                result = cursor.fetchone()
                if not result or not result['rollback_sql']:
                    logger.error(f"No rollback SQL found for version {version}")
                    return False
                
                # Execute rollback
                rollback_sql = result['rollback_sql']
                cursor.execute(rollback_sql)
                
                # Remove migration record
                cursor.execute(
                    "DELETE FROM rbac.schema_migrations WHERE version = %s",
                    (version,)
                )
            
            logger.info(f"Successfully rolled back migration version: {version}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to rollback migration {version}: {e}")
            return False


class DatabaseMaintenanceManager:
    """
    Database maintenance and optimization utilities.
    
    Provides automated maintenance tasks, performance optimization,
    and routine database housekeeping operations.
    """
    
    def __init__(self, config: DatabaseConfiguration = None):
        """Initialize maintenance manager."""
        self.config = config or DatabaseConfiguration()
        self.db_conn = DatabaseConnection(self.config, 'primary')
        
        logger.info("Database maintenance manager initialized")
    
    def analyze_table_statistics(self) -> Dict[str, Any]:
        """Analyze table statistics and performance metrics."""
        with self.db_conn.get_cursor() as cursor:
            cursor.execute("""
                SELECT 
                    schemaname,
                    tablename,
                    n_tup_ins as inserts,
                    n_tup_upd as updates,
                    n_tup_del as deletes,
                    n_live_tup as live_tuples,
                    n_dead_tup as dead_tuples,
                    last_vacuum,
                    last_autovacuum,
                    last_analyze,
                    last_autoanalyze
                FROM pg_stat_user_tables 
                WHERE schemaname = 'rbac'
                ORDER BY n_live_tup DESC
            """)
            
            tables = cursor.fetchall()
            
            # Get table sizes
            cursor.execute("""
                SELECT 
                    schemaname,
                    tablename,
                    pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) as size,
                    pg_total_relation_size(schemaname||'.'||tablename) as size_bytes
                FROM pg_tables 
                WHERE schemaname = 'rbac'
                ORDER BY pg_total_relation_size(schemaname||'.'||tablename) DESC
            """)
            
            sizes = cursor.fetchall()
            
            # Combine statistics
            table_stats = {}
            for table in tables:
                table_name = table['tablename']
                table_stats[table_name] = dict(table)
                
                # Add size information
                for size_info in sizes:
                    if size_info['tablename'] == table_name:
                        table_stats[table_name].update({
                            'size': size_info['size'],
                            'size_bytes': size_info['size_bytes']
                        })
                        break
            
            return table_stats
    
    def vacuum_analyze_tables(self, tables: List[str] = None) -> Dict[str, bool]:
        """Perform VACUUM ANALYZE on specified tables or all RBAC tables."""
        if tables is None:
            # Get all RBAC tables
            with self.db_conn.get_cursor() as cursor:
                cursor.execute("""
                    SELECT tablename FROM pg_tables 
                    WHERE schemaname = 'rbac'
                """)
                tables = [row['tablename'] for row in cursor.fetchall()]
        
        results = {}
        
        for table in tables:
            try:
                with self.db_conn.get_connection() as conn:
                    conn.autocommit = True  # Required for VACUUM
                    with conn.cursor() as cursor:
                        cursor.execute(f"VACUUM ANALYZE rbac.{table}")
                        results[table] = True
                        logger.info(f"Successfully vacuumed and analyzed table: {table}")
            
            except Exception as e:
                results[table] = False
                logger.error(f"Failed to vacuum table {table}: {e}")
        
        return results
    
    def reindex_tables(self, tables: List[str] = None) -> Dict[str, bool]:
        """Reindex specified tables or all RBAC tables."""
        if tables is None:
            # Get all RBAC tables
            with self.db_conn.get_cursor() as cursor:
                cursor.execute("""
                    SELECT tablename FROM pg_tables 
                    WHERE schemaname = 'rbac'
                """)
                tables = [row['tablename'] for row in cursor.fetchall()]
        
        results = {}
        
        for table in tables:
            try:
                with self.db_conn.get_connection() as conn:
                    with conn.cursor() as cursor:
                        cursor.execute(f"REINDEX TABLE rbac.{table}")
                        results[table] = True
                        logger.info(f"Successfully reindexed table: {table}")
                
            except Exception as e:
                results[table] = False
                logger.error(f"Failed to reindex table {table}: {e}")
        
        return results
    
    def cleanup_old_audit_logs(self, retention_days: int = None) -> Dict[str, int]:
        """Clean up old audit logs based on retention policy."""
        if retention_days is None:
            # Get retention policy from configuration
            security_config = self.config.get_security_config()
            audit_config = security_config.get('audit', {})
            retention_days = audit_config.get('retention_days', 2555)  # ~7 years default
        
        cleanup_results = {}
        
        # Define tables and their retention periods
        audit_tables = {
            'auth_events': retention_days,
            'authz_events': retention_days,
            'data_access_events': retention_days * 2,  # Keep data access logs longer
            'config_changes': retention_days * 2,  # Keep config changes longer
            'user_sessions': 90  # Keep session data for 90 days only
        }
        
        with self.db_conn.get_connection() as conn:
            with conn.cursor() as cursor:
                for table, retention in audit_tables.items():
                    try:
                        # Use appropriate timestamp column for each table
                        timestamp_column = self._get_timestamp_column(table)
                        
                        cursor.execute(f"""
                            DELETE FROM rbac.{table} 
                            WHERE {timestamp_column} < NOW() - INTERVAL '%s days'
                        """, (retention,))
                        
                        deleted_count = cursor.rowcount
                        cleanup_results[table] = deleted_count
                        
                        logger.info(f"Cleaned up {deleted_count} old records from {table}")
                    
                    except Exception as e:
                        cleanup_results[table] = -1
                        logger.error(f"Failed to cleanup table {table}: {e}")
                
                conn.commit()
        
        return cleanup_results
    
    def _get_timestamp_column(self, table: str) -> str:
        """Get the appropriate timestamp column for each audit table."""
        timestamp_columns = {
            'auth_events': 'event_timestamp',
            'authz_events': 'event_timestamp',
            'data_access_events': 'event_timestamp',
            'config_changes': 'change_timestamp',
            'user_sessions': 'created_at'
        }
        return timestamp_columns.get(table, 'created_at')
    
    def get_database_performance_metrics(self) -> Dict[str, Any]:
        """Get comprehensive database performance metrics."""
        metrics = {}
        
        with self.db_conn.get_cursor() as cursor:
            # Connection statistics
            cursor.execute("""
                SELECT 
                    count(*) as total_connections,
                    count(*) FILTER (WHERE state = 'active') as active_connections,
                    count(*) FILTER (WHERE state = 'idle') as idle_connections
                FROM pg_stat_activity
            """)
            
            conn_stats = cursor.fetchone()
            metrics['connections'] = dict(conn_stats)
            
            # Database size
            cursor.execute("""
                SELECT 
                    pg_size_pretty(pg_database_size(current_database())) as database_size,
                    pg_database_size(current_database()) as database_size_bytes
            """)
            
            size_stats = cursor.fetchone()
            metrics['database_size'] = dict(size_stats)
            
            # Top queries by execution time
            cursor.execute("""
                SELECT 
                    query,
                    calls,
                    total_time,
                    mean_time,
                    stddev_time,
                    rows
                FROM pg_stat_statements 
                WHERE query LIKE '%rbac%'
                ORDER BY total_time DESC 
                LIMIT 10
            """)
            
            try:
                slow_queries = cursor.fetchall()
                metrics['slow_queries'] = [dict(q) for q in slow_queries]
            except psycopg2.Error:
                # pg_stat_statements extension might not be enabled
                metrics['slow_queries'] = []
            
            # Index usage statistics
            cursor.execute("""
                SELECT 
                    schemaname,
                    tablename,
                    indexname,
                    idx_scan,
                    idx_tup_read,
                    idx_tup_fetch
                FROM pg_stat_user_indexes 
                WHERE schemaname = 'rbac'
                ORDER BY idx_scan DESC
                LIMIT 20
            """)
            
            index_stats = cursor.fetchall()
            metrics['index_usage'] = [dict(idx) for idx in index_stats]
        
        return metrics


@contextmanager
def database_transaction(db_conn: DatabaseConnection, isolation_level: str = None):
    """
    Context manager for database transactions with proper error handling.
    
    Args:
        db_conn: Database connection to use
        isolation_level: Transaction isolation level
    """
    with db_conn.get_connection() as conn:
        if isolation_level:
            conn.set_isolation_level(isolation_level)
        
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise


def create_database_backup(config: DatabaseConfiguration, 
                         backup_path: Path,
                         compression: bool = True) -> bool:
    """
    Create a database backup using pg_dump.
    
    Args:
        config: Database configuration
        backup_path: Path where backup will be saved
        compression: Whether to compress the backup
        
    Returns:
        bool: True if backup successful
    """
    try:
        import subprocess
        
        primary_config = config.get_database_config('primary')
        
        # Build pg_dump command
        cmd = [
            'pg_dump',
            '-h', primary_config.get('host', 'localhost'),
            '-p', str(primary_config.get('port', 5432)),
            '-U', primary_config.get('username', 'rbac_user'),
            '-d', primary_config.get('database', 'rbac_system'),
            '--verbose',
            '--schema=rbac'
        ]
        
        if compression:
            cmd.extend(['-Fc', '-f', str(backup_path)])
        else:
            cmd.extend(['-f', str(backup_path)])
        
        # Set password via environment
        env = os.environ.copy()
        env['PGPASSWORD'] = primary_config.get('password', '')
        
        # Execute backup
        result = subprocess.run(
            cmd,
            env=env,
            capture_output=True,
            text=True,
            timeout=3600  # 1 hour timeout
        )
        
        if result.returncode == 0:
            logger.info(f"Database backup created successfully: {backup_path}")
            return True
        else:
            logger.error(f"Database backup failed: {result.stderr}")
            return False
    
    except Exception as e:
        logger.error(f"Database backup error: {e}")
        return False


# Utility functions for common database operations
def get_user_permissions(user_id: str, db_conn: DatabaseConnection = None) -> List[Dict[str, Any]]:
    """Get all effective permissions for a user."""
    if not db_conn:
        db_conn = DatabaseConnection()
    
    with db_conn.get_cursor() as cursor:
        cursor.execute("""
            SELECT DISTINCT 
                p.permission_name,
                p.permission_code,
                p.resource_type,
                p.action,
                p.scope,
                p.classification_required,
                r.role_name,
                ur.expires_at as role_expires_at,
                rp.expires_at as permission_expires_at
            FROM rbac.users u
            JOIN rbac.user_roles ur ON u.user_id = ur.user_id
            JOIN rbac.roles r ON ur.role_id = r.role_id
            JOIN rbac.role_permissions rp ON r.role_id = rp.role_id
            JOIN rbac.permissions p ON rp.permission_id = p.permission_id
            WHERE u.user_id = %s
            AND ur.is_active = true
            AND rp.is_active = true
            AND p.is_active = true
            AND (ur.valid_until IS NULL OR ur.valid_until > NOW())
            AND (rp.valid_until IS NULL OR rp.valid_until > NOW())
            ORDER BY p.permission_name
        """, (user_id,))
        
        return [dict(row) for row in cursor.fetchall()]


def audit_user_activity(user_id: str, 
                       start_date: datetime = None,
                       end_date: datetime = None,
                       db_conn: DatabaseConnection = None) -> Dict[str, List[Dict[str, Any]]]:
    """Get comprehensive audit trail for a user."""
    if not db_conn:
        db_conn = DatabaseConnection()
    
    if not start_date:
        start_date = datetime.now(timezone.utc) - timedelta(days=30)
    
    if not end_date:
        end_date = datetime.now(timezone.utc)
    
    audit_data = {}
    
    with db_conn.get_cursor() as cursor:
        # Authentication events
        cursor.execute("""
            SELECT event_type, event_result, event_timestamp, client_ip_address, 
                   failure_reason, additional_data
            FROM rbac.auth_events
            WHERE user_id = %s
            AND event_timestamp BETWEEN %s AND %s
            ORDER BY event_timestamp DESC
        """, (user_id, start_date, end_date))
        
        audit_data['authentication'] = [dict(row) for row in cursor.fetchall()]
        
        # Authorization events
        cursor.execute("""
            SELECT event_type, decision, event_timestamp, resource_type, 
                   resource_identifier, requested_action, decision_reason
            FROM rbac.authz_events
            WHERE user_id = %s
            AND event_timestamp BETWEEN %s AND %s
            ORDER BY event_timestamp DESC
        """, (user_id, start_date, end_date))
        
        audit_data['authorization'] = [dict(row) for row in cursor.fetchall()]
        
        # Data access events
        cursor.execute("""
            SELECT event_type, data_classification, database_name, table_name,
                   records_affected, operation_result, event_timestamp
            FROM rbac.data_access_events
            WHERE user_id = %s
            AND event_timestamp BETWEEN %s AND %s
            ORDER BY event_timestamp DESC
        """, (user_id, start_date, end_date))
        
        audit_data['data_access'] = [dict(row) for row in cursor.fetchall()]
    
    return audit_data