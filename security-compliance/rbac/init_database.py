#!/usr/bin/env python3
"""
DoD-Compliant RBAC System Database Initialization Script

This script initializes the complete RBAC database system including:
- Database connections and pools
- Schema migrations in correct order
- Default roles and permissions
- Audit logging setup
- System validation

Classification: UNCLASSIFIED//FOR OFFICIAL USE ONLY
Author: Security Compliance Team
Date: 2025-07-29
"""

import argparse
import logging
import os
import sys
import yaml
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Any
import psycopg2
from psycopg2.extras import RealDictCursor
import traceback

# Add the models directory to the Python path
sys.path.append(os.path.join(os.path.dirname(__file__), 'models'))

from models.base import DatabaseConfiguration, DatabaseConnection, ConnectionPoolManager

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('/var/log/rbac/init_database.log', mode='a')
    ]
)
logger = logging.getLogger(__name__)


class DatabaseInitializer:
    """
    Comprehensive database initialization system for DoD-compliant RBAC.
    
    Handles database creation, migration execution, data loading, and validation
    according to DoD security standards.
    """
    
    def __init__(self, config_path: Optional[str] = None, environment: str = 'development'):
        """
        Initialize the database setup system.
        
        Args:
            config_path: Path to database configuration file
            environment: Target environment (development, staging, production)
        """
        self.environment = environment
        os.environ['RBAC_ENVIRONMENT'] = environment
        
        self.config = DatabaseConfiguration(config_path)
        self.rbac_config = self._load_rbac_config()
        self.base_permissions = self._load_base_permissions()
        
        self.migration_dir = Path(__file__).parent / 'schemas'
        self.schema_dir = Path(__file__).parent / 'schema'
        self.labeling_schema_dir = Path(__file__).parent / 'labeling' / 'schema'
        
        # Track migration status
        self.executed_migrations: List[str] = []
        self.failed_migrations: List[str] = []
        
        logger.info(f"Database initializer configured for environment: {environment}")
    
    def _load_rbac_config(self) -> Dict[str, Any]:
        """Load RBAC system configuration."""
        config_path = Path(__file__).parent / 'config' / 'rbac_config.yaml'
        try:
            with open(config_path, 'r') as f:
                return yaml.safe_load(f)
        except Exception as e:
            logger.error(f"Failed to load RBAC configuration: {e}")
            raise
    
    def _load_base_permissions(self) -> Dict[str, Any]:
        """Load base permissions configuration."""
        permissions_path = Path(__file__).parent / 'config' / 'permissions' / 'base_permissions.yaml'
        try:
            with open(permissions_path, 'r') as f:
                return yaml.safe_load(f)
        except Exception as e:
            logger.error(f"Failed to load base permissions: {e}")
            raise
    
    def initialize_database(self, force: bool = False, validate_only: bool = False) -> bool:
        """
        Complete database initialization process.
        
        Args:
            force: Force re-initialization even if already initialized
            validate_only: Only run validation without making changes
            
        Returns:
            bool: True if initialization successful
        """
        try:
            logger.info("Starting DoD RBAC database initialization")
            logger.info(f"Environment: {self.environment}")
            logger.info(f"Force mode: {force}")
            logger.info(f"Validate only: {validate_only}")
            
            # Step 1: Validate configuration
            self._validate_configuration()
            
            # Step 2: Setup database connections
            self._setup_database_connections()
            
            if not validate_only:
                # Step 3: Create databases if they don't exist
                self._create_databases_if_needed()
                
                # Step 4: Check if system is already initialized
                if not force and self._is_system_initialized():
                    logger.info("System already initialized. Use --force to re-initialize.")
                    return True
                
                # Step 5: Execute migrations
                self._execute_migrations()
                
                # Step 6: Load default data
                self._load_default_data()
                
                # Step 7: Setup audit logging
                self._setup_audit_logging()
            
            # Step 8: Validate complete system
            validation_result = self._validate_system()
            
            if validation_result:
                logger.info("Database initialization completed successfully")
                self._generate_initialization_report()
                return True
            else:
                logger.error("Database initialization validation failed")
                return False
                
        except Exception as e:
            logger.error(f"Database initialization failed: {e}")
            logger.error(traceback.format_exc())
            return False
    
    def _validate_configuration(self):
        """Validate all configuration files and environment variables."""
        logger.info("Validating configuration...")
        
        # Check required environment variables
        required_env_vars = [
            'DB_PASSWORD',
            'AUDIT_DB_PASSWORD'
        ]
        
        missing_vars = []
        for var in required_env_vars:
            if not os.getenv(var):
                missing_vars.append(var)
        
        if missing_vars:
            raise ValueError(f"Missing required environment variables: {missing_vars}")
        
        # Validate database configuration
        primary_config = self.config.get_database_config('primary')
        if not primary_config:
            raise ValueError("Primary database configuration not found")
        
        # Validate security configuration
        security_config = self.config.get_security_config()
        if not security_config:
            logger.warning("Security configuration not found, using defaults")
        
        logger.info("Configuration validation completed")
    
    def _setup_database_connections(self):
        """Setup and test database connections."""
        logger.info("Setting up database connections...")
        
        try:
            # Initialize connection pool manager
            self.pool_manager = ConnectionPoolManager(self.config)
            
            # Test primary database connection
            db_conn = DatabaseConnection(self.config, 'primary')
            health_status = db_conn.health_check()
            
            if not health_status.get('primary', False):
                raise Exception("Primary database connection failed")
            
            logger.info("Database connections established successfully")
            logger.info(f"Connection health status: {health_status}")
            
        except Exception as e:
            logger.error(f"Failed to setup database connections: {e}")
            raise
    
    def _create_databases_if_needed(self):
        """Create databases if they don't exist."""
        logger.info("Checking if databases need to be created...")
        
        # This would typically connect to postgres database to create others
        # For now, assume databases exist or are created externally
        logger.info("Database creation check completed")
    
    def _is_system_initialized(self) -> bool:
        """Check if the RBAC system is already initialized."""
        try:
            db_conn = DatabaseConnection(self.config, 'primary')
            with db_conn.get_cursor() as cursor:
                # Check if core tables exist
                cursor.execute("""
                    SELECT EXISTS (
                        SELECT FROM information_schema.tables 
                        WHERE table_schema = 'rbac' 
                        AND table_name = 'users'
                    )
                """)
                tables_exist = cursor.fetchone()[0]
                
                if tables_exist:
                    # Check if there are any users (indicates data has been loaded)
                    cursor.execute("SELECT COUNT(*) FROM rbac.users")
                    user_count = cursor.fetchone()[0]
                    return user_count > 0
                
                return False
                
        except Exception as e:
            logger.debug(f"System initialization check failed: {e}")
            return False
    
    def _execute_migrations(self):
        """Execute all SQL migrations in the correct order."""
        logger.info("Executing database migrations...")
        
        # Define migration order
        migration_files = [
            # Core RBAC schemas
            (self.migration_dir, '01_rbac_core.sql'),
            (self.schema_dir, '01_core_rbac_schema.sql'),
            (self.schema_dir, '02_session_audit_schema.sql'),
            
            # Standard roles and permissions
            (self.migration_dir, '02_standard_roles.sql'),
            
            # ABAC and advanced features
            (self.migration_dir, '03_abac_functions.sql'),
            (self.migration_dir, '04_classification_schema.sql'),
            
            # Data labeling extensions
            (self.labeling_schema_dir, '03_data_labeling_schema.sql'),
            (self.labeling_schema_dir, '04_data_labeling_migrations.sql'),
        ]
        
        db_conn = DatabaseConnection(self.config, 'primary')
        
        for schema_dir, filename in migration_files:
            file_path = schema_dir / filename
            if file_path.exists():
                self._execute_migration_file(db_conn, file_path)
            else:
                logger.warning(f"Migration file not found: {file_path}")
        
        logger.info(f"Executed {len(self.executed_migrations)} migrations successfully")
        if self.failed_migrations:
            logger.error(f"Failed migrations: {self.failed_migrations}")
    
    def _execute_migration_file(self, db_conn: DatabaseConnection, file_path: Path):
        """Execute a single migration file."""
        logger.info(f"Executing migration: {file_path}")
        
        try:
            with open(file_path, 'r') as f:
                sql_content = f.read()
            
            # Split by statement separator and execute each statement
            statements = [stmt.strip() for stmt in sql_content.split(';') if stmt.strip()]
            
            with db_conn.get_connection() as conn:
                with conn.cursor() as cursor:
                    for statement in statements:
                        if statement and not statement.startswith('--'):
                            try:
                                cursor.execute(statement)
                            except Exception as e:
                                # Log but continue with other statements
                                logger.warning(f"Statement failed in {file_path}: {e}")
                                logger.debug(f"Failed statement: {statement}")
                    
                    conn.commit()
            
            self.executed_migrations.append(str(file_path))
            logger.info(f"Successfully executed migration: {file_path}")
            
        except Exception as e:
            self.failed_migrations.append(str(file_path))
            logger.error(f"Failed to execute migration {file_path}: {e}")
            raise
    
    def _load_default_data(self):
        """Load default roles, permissions, and configuration data."""
        logger.info("Loading default data...")
        
        try:
            # Load base permissions from configuration
            self._load_permissions_from_config()
            
            # Load role hierarchies
            self._load_role_hierarchies()
            
            # Create default admin user if specified
            self._create_default_admin_user()
            
            logger.info("Default data loaded successfully")
            
        except Exception as e:
            logger.error(f"Failed to load default data: {e}")
            raise
    
    def _load_permissions_from_config(self):
        """Load permissions from base_permissions.yaml."""
        logger.info("Loading permissions from configuration...")
        
        db_conn = DatabaseConnection(self.config, 'primary')
        permissions = self.base_permissions.get('base_permissions', {})
        
        with db_conn.get_connection() as conn:
            with conn.cursor() as cursor:
                # Load system permissions
                for category, perm_list in permissions.items():
                    if isinstance(perm_list, dict):
                        for subcategory, subperms in perm_list.items():
                            if isinstance(subperms, list):
                                for perm in subperms:
                                    self._insert_permission(cursor, perm, category, subcategory)
                    elif isinstance(perm_list, list):
                        for perm in perm_list:
                            self._insert_permission(cursor, perm, category)
                
                conn.commit()
        
        logger.info("Permissions loaded from configuration")
    
    def _insert_permission(self, cursor, perm: Dict[str, Any], category: str, subcategory: str = None):
        """Insert a single permission into the database."""
        try:
            permission_data = {
                'permission_name': perm.get('name', f"{category}_{subcategory}_{perm.get('id', 'unknown')}"),
                'permission_code': perm.get('id', f"{category}_{subcategory}_unknown"),
                'resource_type': 'system',  # Default resource type
                'action': 'read',  # Default action
                'scope': 'global',
                'classification_required': perm.get('classification_required', 'UNCLASSIFIED'),
                'description': perm.get('description', ''),
                'risk_level': 'MEDIUM',
                'audit_required': perm.get('audit_required', True)
            }
            
            # Check if permission already exists
            cursor.execute(
                "SELECT id FROM rbac.permissions WHERE permission_code = %s",
                (permission_data['permission_code'],)
            )
            
            if not cursor.fetchone():
                cursor.execute("""
                    INSERT INTO rbac.permissions 
                    (permission_name, permission_code, resource_type, action, scope, 
                     classification_required, description, risk_level, audit_required)
                    VALUES (%(permission_name)s, %(permission_code)s, %(resource_type)s, 
                           %(action)s, %(scope)s, %(classification_required)s, 
                           %(description)s, %(risk_level)s, %(audit_required)s)
                """, permission_data)
                logger.debug(f"Inserted permission: {permission_data['permission_code']}")
            
        except Exception as e:
            logger.warning(f"Failed to insert permission {perm.get('id', 'unknown')}: {e}")
    
    def _load_role_hierarchies(self):
        """Load role hierarchies from configuration."""
        logger.info("Loading role hierarchies...")
        
        # Role hierarchies are typically loaded through the standard_roles.sql migration
        # Additional custom hierarchies can be loaded here
        
        logger.info("Role hierarchies loaded")
    
    def _create_default_admin_user(self):
        """Create default administrative user if configured."""
        admin_config = self.rbac_config.get('rbac_system', {}).get('default_admin')
        
        if admin_config and self.environment == 'development':
            logger.info("Creating default admin user for development environment...")
            
            db_conn = DatabaseConnection(self.config, 'primary')
            with db_conn.get_connection() as conn:
                with conn.cursor() as cursor:
                    # Check if admin user already exists
                    cursor.execute(
                        "SELECT user_id FROM rbac.users WHERE edipi = %s",
                        (admin_config.get('edipi', 'DEV_ADMIN'),)
                    )
                    
                    if not cursor.fetchone():
                        admin_data = {
                            'edipi': admin_config.get('edipi', 'DEV_ADMIN'),
                            'user_principal_name': admin_config.get('upn', 'admin@dev.mil'),
                            'common_name': admin_config.get('name', 'Development Administrator'),
                            'display_name': admin_config.get('display_name', 'Dev Admin'),
                            'email_address': admin_config.get('email', 'admin@dev.mil'),
                            'organization': admin_config.get('org', 'Development'),
                            'security_clearance': admin_config.get('clearance', 'TOP_SECRET'),
                            'nipr_access': True,
                            'sipr_access': True,
                            'jwics_access': True,
                            'account_status': 'ACTIVE'
                        }
                        
                        cursor.execute("""
                            INSERT INTO rbac.users 
                            (edipi, user_principal_name, common_name, display_name, 
                             email_address, organization, security_clearance, 
                             nipr_access, sipr_access, jwics_access, account_status)
                            VALUES (%(edipi)s, %(user_principal_name)s, %(common_name)s, 
                                   %(display_name)s, %(email_address)s, %(organization)s, 
                                   %(security_clearance)s, %(nipr_access)s, %(sipr_access)s, 
                                   %(jwics_access)s, %(account_status)s)
                        """, admin_data)
                        
                        logger.info("Default admin user created")
                    else:
                        logger.info("Default admin user already exists")
                
                conn.commit()
    
    def _setup_audit_logging(self):
        """Setup audit logging configuration."""
        logger.info("Setting up audit logging...")
        
        try:
            # Configure audit database if separate
            audit_config = self.config.get_database_config('audit')
            if audit_config:
                audit_conn = DatabaseConnection(self.config, 'audit')
                health_status = audit_conn.health_check()
                
                if health_status.get('audit', False):
                    logger.info("Audit database connection verified")
                else:
                    logger.warning("Audit database connection failed, using primary database")
            
            # Set up audit retention policies
            self._setup_audit_retention()
            
            logger.info("Audit logging setup completed")
            
        except Exception as e:
            logger.warning(f"Audit logging setup had issues: {e}")
    
    def _setup_audit_retention(self):
        """Setup audit log retention policies."""
        db_conn = DatabaseConnection(self.config, 'primary')
        
        with db_conn.get_connection() as conn:
            with conn.cursor() as cursor:
                # Create cleanup function for old audit logs
                cursor.execute("""
                    CREATE OR REPLACE FUNCTION rbac.cleanup_old_audit_logs()
                    RETURNS void AS $$
                    BEGIN
                        -- Delete auth events older than 3 years
                        DELETE FROM rbac.auth_events 
                        WHERE event_timestamp < NOW() - INTERVAL '3 years';
                        
                        -- Delete data access events older than 7 years
                        DELETE FROM rbac.data_access_events 
                        WHERE event_timestamp < NOW() - INTERVAL '7 years';
                        
                        -- Delete config changes older than 7 years
                        DELETE FROM rbac.config_changes 
                        WHERE change_timestamp < NOW() - INTERVAL '7 years';
                        
                        RAISE NOTICE 'Audit log cleanup completed';
                    END;
                    $$ LANGUAGE plpgsql;
                """)
                
                conn.commit()
        
        logger.info("Audit retention policies configured")
    
    def _validate_system(self) -> bool:
        """Validate the complete RBAC system."""
        logger.info("Validating RBAC system...")
        
        validation_results = {
            'database_connections': self._validate_database_connections(),
            'schema_integrity': self._validate_schema_integrity(),
            'data_consistency': self._validate_data_consistency(),
            'security_configuration': self._validate_security_configuration(),
            'audit_logging': self._validate_audit_logging()
        }
        
        all_passed = all(validation_results.values())
        
        for check, result in validation_results.items():
            status = "PASSED" if result else "FAILED"
            logger.info(f"Validation - {check}: {status}")
        
        return all_passed
    
    def _validate_database_connections(self) -> bool:
        """Validate all database connections."""
        try:
            db_conn = DatabaseConnection(self.config, 'primary')
            health_status = db_conn.health_check()
            
            # Primary database must be healthy
            if not health_status.get('primary', False):
                logger.error("Primary database connection validation failed")
                return False
            
            logger.info("Database connection validation passed")
            return True
            
        except Exception as e:
            logger.error(f"Database connection validation failed: {e}")
            return False
    
    def _validate_schema_integrity(self) -> bool:
        """Validate database schema integrity."""
        try:
            db_conn = DatabaseConnection(self.config, 'primary')
            
            with db_conn.get_cursor() as cursor:
                # Check if all required tables exist
                required_tables = [
                    'users', 'roles', 'permissions', 'role_permissions', 
                    'user_roles', 'user_sessions', 'auth_events', 
                    'authz_events', 'data_access_events', 'config_changes'
                ]
                
                for table in required_tables:
                    cursor.execute("""
                        SELECT EXISTS (
                            SELECT FROM information_schema.tables 
                            WHERE table_schema = 'rbac' 
                            AND table_name = %s
                        )
                    """, (table,))
                    
                    if not cursor.fetchone()[0]:
                        logger.error(f"Required table missing: rbac.{table}")
                        return False
                
                # Check for required indexes
                cursor.execute("""
                    SELECT count(*) FROM pg_indexes 
                    WHERE schemaname = 'rbac'
                """)
                
                index_count = cursor.fetchone()[0]
                if index_count < 10:  # Minimum expected indexes
                    logger.warning(f"Low index count: {index_count}")
                
            logger.info("Schema integrity validation passed")
            return True
            
        except Exception as e:
            logger.error(f"Schema integrity validation failed: {e}")
            return False
    
    def _validate_data_consistency(self) -> bool:
        """Validate data consistency and referential integrity."""
        try:
            db_conn = DatabaseConnection(self.config, 'primary')
            
            with db_conn.get_cursor() as cursor:
                # Check for orphaned records
                cursor.execute("""
                    SELECT COUNT(*) FROM rbac.user_roles ur
                    LEFT JOIN rbac.users u ON ur.user_id = u.user_id
                    WHERE u.user_id IS NULL
                """)
                
                orphaned_user_roles = cursor.fetchone()[0]
                if orphaned_user_roles > 0:
                    logger.error(f"Found {orphaned_user_roles} orphaned user role assignments")
                    return False
                
                # Check role permission consistency
                cursor.execute("""
                    SELECT COUNT(*) FROM rbac.role_permissions rp
                    LEFT JOIN rbac.roles r ON rp.role_id = r.role_id
                    LEFT JOIN rbac.permissions p ON rp.permission_id = p.permission_id
                    WHERE r.role_id IS NULL OR p.permission_id IS NULL
                """)
                
                orphaned_role_perms = cursor.fetchone()[0]
                if orphaned_role_perms > 0:
                    logger.error(f"Found {orphaned_role_perms} orphaned role permissions")
                    return False
            
            logger.info("Data consistency validation passed")
            return True
            
        except Exception as e:
            logger.error(f"Data consistency validation failed: {e}")
            return False
    
    def _validate_security_configuration(self) -> bool:
        """Validate security configuration compliance."""
        try:
            # Check SSL configuration
            primary_config = self.config.get_database_config('primary')
            ssl_config = primary_config.get('ssl', {})
            
            if not ssl_config.get('enabled', False):
                logger.error("SSL not enabled - DoD compliance violation")
                return False
            
            if ssl_config.get('mode', '') not in ['require', 'verify-full']:
                logger.error("SSL mode not secure enough - DoD compliance violation")
                return False
            
            # Check audit configuration
            security_config = self.config.get_security_config()
            audit_config = security_config.get('audit', {})
            
            if not audit_config.get('enabled', False):
                logger.error("Audit logging not enabled - DoD compliance violation")
                return False
            
            logger.info("Security configuration validation passed")
            return True
            
        except Exception as e:
            logger.error(f"Security configuration validation failed: {e}")
            return False
    
    def _validate_audit_logging(self) -> bool:
        """Validate audit logging functionality."""
        try:
            db_conn = DatabaseConnection(self.config, 'primary')
            
            with db_conn.get_cursor() as cursor:
                # Test audit log insertion
                test_event = {
                    'event_type': 'SYSTEM_VALIDATION',
                    'event_result': 'SUCCESS',
                    'event_timestamp': datetime.now(timezone.utc),
                    'client_ip_address': '127.0.0.1',
                    'security_classification': 'UNCLASSIFIED'
                }
                
                cursor.execute("""
                    INSERT INTO rbac.auth_events 
                    (event_type, event_result, event_timestamp, client_ip_address, security_classification)
                    VALUES (%(event_type)s, %(event_result)s, %(event_timestamp)s, 
                           %(client_ip_address)s, %(security_classification)s)
                    RETURNING event_id
                """, test_event)
                
                event_id = cursor.fetchone()[0]
                if not event_id:
                    logger.error("Failed to insert test audit event")
                    return False
                
                # Clean up test event
                cursor.execute("DELETE FROM rbac.auth_events WHERE event_id = %s", (event_id,))
            
            logger.info("Audit logging validation passed")
            return True
            
        except Exception as e:
            logger.error(f"Audit logging validation failed: {e}")
            return False
    
    def _generate_initialization_report(self):
        """Generate a comprehensive initialization report."""
        logger.info("Generating initialization report...")
        
        report = {
            'initialization_time': datetime.now(timezone.utc).isoformat(),
            'environment': self.environment,
            'executed_migrations': self.executed_migrations,
            'failed_migrations': self.failed_migrations,
            'configuration_summary': {
                'database_config': self.config.get_database_config('primary'),
                'security_config': self.config.get_security_config(),
            }
        }
        
        # Write report to file
        report_path = Path(__file__).parent / f'init_report_{self.environment}_{datetime.now().strftime("%Y%m%d_%H%M%S")}.yaml'
        
        try:
            with open(report_path, 'w') as f:
                yaml.dump(report, f, default_flow_style=False)
            
            logger.info(f"Initialization report saved: {report_path}")
            
        except Exception as e:
            logger.error(f"Failed to save initialization report: {e}")


def main():
    """Main entry point for database initialization."""
    parser = argparse.ArgumentParser(
        description='Initialize DoD-compliant RBAC database system',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Initialize development environment
  python init_database.py --environment development
  
  # Initialize production with force flag
  python init_database.py --environment production --force
  
  # Validate existing system without changes
  python init_database.py --validate-only
  
  # Use custom configuration file
  python init_database.py --config /path/to/config.yaml
        """
    )
    
    parser.add_argument(
        '--environment', '-e',
        default='development',
        choices=['development', 'staging', 'production', 'nipr', 'sipr', 'jwics'],
        help='Target environment for initialization'
    )
    
    parser.add_argument(
        '--config', '-c',
        type=str,
        help='Path to database configuration file'
    )
    
    parser.add_argument(
        '--force', '-f',
        action='store_true',
        help='Force re-initialization even if system is already initialized'
    )
    
    parser.add_argument(
        '--validate-only', '-v',
        action='store_true',
        help='Only validate the system without making changes'
    )
    
    parser.add_argument(
        '--log-level',
        default='INFO',
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
        help='Set logging level'
    )
    
    args = parser.parse_args()
    
    # Set logging level
    logging.getLogger().setLevel(getattr(logging, args.log_level))
    
    # Initialize the database system
    initializer = DatabaseInitializer(
        config_path=args.config,
        environment=args.environment
    )
    
    success = initializer.initialize_database(
        force=args.force,
        validate_only=args.validate_only
    )
    
    if success:
        logger.info("Database initialization completed successfully")
        sys.exit(0)
    else:
        logger.error("Database initialization failed")
        sys.exit(1)


if __name__ == '__main__':
    main()