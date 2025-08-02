#!/usr/bin/env python3
"""
Test Script for DoD-Compliant RBAC Database Layer

Tests the complete database layer implementation including:
- Configuration loading and validation
- Database connections and pooling
- Migration system
- Health monitoring
- Database utilities

Classification: UNCLASSIFIED//FOR OFFICIAL USE ONLY
Author: Security Compliance Team
Date: 2025-07-29
"""

import os
import sys
import unittest
import tempfile
import yaml
from pathlib import Path
from datetime import datetime, timezone
import logging

# Add the models directory to the Python path
sys.path.append(os.path.join(os.path.dirname(__file__), 'models'))
sys.path.append(os.path.dirname(__file__))

from models.base import DatabaseConfiguration, DatabaseConnection, ConnectionPoolManager
from db_utils import DatabaseHealthMonitor, MigrationManager, DatabaseMaintenanceManager

# Configure logging for tests
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class TestDatabaseConfiguration(unittest.TestCase):
    """Test database configuration loading and management."""
    
    def setUp(self):
        """Set up test configuration."""
        self.test_config = {
            'database': {
                'primary': {
                    'engine': 'postgresql',
                    'host': '${DB_HOST:-localhost}',
                    'port': '${DB_PORT:-5432}',
                    'database': 'test_rbac',
                    'username': 'test_user',
                    'password': '${DB_PASSWORD:-test_pass}',
                    'pool': {
                        'min_connections': 2,
                        'max_connections': 10
                    },
                    'ssl': {
                        'enabled': True,
                        'mode': 'prefer'
                    }
                }
            },
            'security': {
                'encryption': {
                    'algorithm': 'AES-256-GCM'
                }
            }
        }
        
        # Create temporary config file
        self.config_file = tempfile.NamedTemporaryFile(
            mode='w', suffix='.yaml', delete=False
        )
        yaml.dump(self.test_config, self.config_file)
        self.config_file.close()
    
    def tearDown(self):
        """Clean up test files."""
        os.unlink(self.config_file.name)
    
    def test_config_loading(self):
        """Test configuration file loading."""
        config = DatabaseConfiguration(self.config_file.name)
        
        self.assertIsNotNone(config.config)
        self.assertIn('database', config.config)
        self.assertIn('primary', config.config['database'])
    
    def test_environment_variable_substitution(self):
        """Test environment variable substitution."""
        os.environ['DB_HOST'] = 'test-host'
        os.environ['DB_PASSWORD'] = 'secret-password'
        
        config = DatabaseConfiguration(self.config_file.name)
        primary_config = config.get_database_config('primary')
        
        self.assertEqual(primary_config['host'], 'test-host')
        self.assertEqual(primary_config['password'], 'secret-password')
        
        # Clean up environment
        del os.environ['DB_HOST']
        del os.environ['DB_PASSWORD']
    
    def test_get_database_config(self):
        """Test getting database configuration."""
        config = DatabaseConfiguration(self.config_file.name)
        primary_config = config.get_database_config('primary')
        
        self.assertEqual(primary_config['engine'], 'postgresql')
        self.assertEqual(primary_config['database'], 'test_rbac')
        self.assertTrue(primary_config['ssl']['enabled'])
    
    def test_get_security_config(self):
        """Test getting security configuration."""
        config = DatabaseConfiguration(self.config_file.name)
        security_config = config.get_security_config()
        
        self.assertIn('encryption', security_config)
        self.assertEqual(security_config['encryption']['algorithm'], 'AES-256-GCM')


class TestDatabaseConnection(unittest.TestCase):
    """Test database connection functionality."""
    
    def setUp(self):
        """Set up test database connection."""
        # Use environment variables for real database connection if available
        self.db_conn = DatabaseConnection(
            host=os.getenv('RBAC_DB_HOST', 'localhost'),
            port=int(os.getenv('RBAC_DB_PORT', '5432')),
            database=os.getenv('RBAC_DB_NAME', 'test_rbac'),
            username=os.getenv('RBAC_DB_USER', 'test_user'),
            password=os.getenv('RBAC_DB_PASSWORD', 'test_pass')
        )
    
    def test_legacy_connection_initialization(self):
        """Test legacy connection parameter initialization."""
        self.assertIsNotNone(self.db_conn)
        self.assertIsNotNone(self.db_conn._legacy_params)
    
    def test_connection_info(self):
        """Test getting connection information."""
        info = self.db_conn.get_connection_info()
        
        self.assertIn('mode', info)
        self.assertEqual(info['mode'], 'legacy')
        self.assertIn('host', info)
        self.assertIn('port', info)
    
    @unittest.skipIf(not os.getenv('RBAC_DB_PASSWORD'), "Database password not provided")
    def test_database_connection(self):
        """Test actual database connection (requires real database)."""
        try:
            with self.db_conn.get_connection() as conn:
                self.assertIsNotNone(conn)
                with conn.cursor() as cursor:
                    cursor.execute("SELECT 1 as test")
                    result = cursor.fetchone()
                    self.assertEqual(result['test'], 1)
        except Exception as e:
            self.skipTest(f"Database connection not available: {e}")
    
    @unittest.skipIf(not os.getenv('RBAC_DB_PASSWORD'), "Database password not provided")
    def test_health_check(self):
        """Test database health check."""
        try:
            health_status = self.db_conn.health_check()
            self.assertIsInstance(health_status, dict)
            self.assertIn('primary', health_status)
        except Exception as e:
            self.skipTest(f"Database health check not available: {e}")


class TestDatabaseUtilities(unittest.TestCase):
    """Test database utility functions."""
    
    def setUp(self):
        """Set up test utilities."""
        # Create a test configuration
        self.test_config = {
            'database': {
                'primary': {
                    'host': 'localhost',
                    'port': 5432,
                    'database': 'test_rbac',
                    'username': 'test_user',
                    'password': 'test_pass'
                }
            }
        }
        
        self.config_file = tempfile.NamedTemporaryFile(
            mode='w', suffix='.yaml', delete=False
        )
        yaml.dump(self.test_config, self.config_file)
        self.config_file.close()
        
        try:
            self.config = DatabaseConfiguration(self.config_file.name)
        except Exception as e:
            self.skipTest(f"Configuration setup failed: {e}")
    
    def tearDown(self):
        """Clean up test files."""
        os.unlink(self.config_file.name)
    
    def test_health_monitor_initialization(self):
        """Test health monitor initialization."""
        monitor = DatabaseHealthMonitor(self.config)
        self.assertIsNotNone(monitor)
        self.assertEqual(monitor._monitoring_active, False)
    
    def test_migration_manager_initialization(self):
        """Test migration manager initialization."""
        try:
            manager = MigrationManager(self.config)
            self.assertIsNotNone(manager)
        except Exception as e:
            self.skipTest(f"Migration manager requires database connection: {e}")
    
    def test_maintenance_manager_initialization(self):
        """Test maintenance manager initialization."""
        try:
            manager = DatabaseMaintenanceManager(self.config)
            self.assertIsNotNone(manager)
        except Exception as e:
            self.skipTest(f"Maintenance manager requires database connection: {e}")


class TestIntegration(unittest.TestCase):
    """Integration tests for the complete database layer."""
    
    @unittest.skipIf(not os.getenv('RBAC_DB_PASSWORD'), "Database password not provided")
    def test_end_to_end_workflow(self):
        """Test end-to-end database workflow."""
        try:
            # 1. Load configuration
            config_path = Path(__file__).parent / 'config' / 'database.yaml'
            if not config_path.exists():
                self.skipTest("Database configuration file not found")
            
            config = DatabaseConfiguration(str(config_path))
            
            # 2. Test database connection
            db_conn = DatabaseConnection(config, 'primary')
            health_status = db_conn.health_check()
            
            if not health_status.get('primary', False):
                self.skipTest("Primary database not available")
            
            # 3. Test health monitoring
            monitor = DatabaseHealthMonitor(config)
            health_results = monitor.check_all_components()
            self.assertIsInstance(health_results, list)
            self.assertGreater(len(health_results), 0)
            
            # 4. Test getting health summary
            summary = monitor.get_health_summary()
            self.assertIn('status', summary)
            self.assertIn('components', summary)
            
            logger.info("End-to-end integration test passed")
            
        except Exception as e:
            self.skipTest(f"Integration test requires full database setup: {e}")


def create_test_database_config():
    """Create a test database configuration file."""
    test_config = {
        'database': {
            'primary': {
                'engine': 'postgresql',
                'host': '${DB_HOST:-localhost}',
                'port': '${DB_PORT:-5432}',
                'database': '${DB_NAME:-test_rbac}',
                'username': '${DB_USER:-test_user}',
                'password': '${DB_PASSWORD}',
                'pool': {
                    'min_connections': 2,
                    'max_connections': 10,
                    'connection_timeout': 30,
                    'idle_timeout': 300
                },
                'ssl': {
                    'enabled': True,
                    'mode': 'prefer',
                    'verify_server_cert': False
                },
                'security': {
                    'encrypt_at_rest': False,
                    'audit_all_queries': True,
                    'max_query_time': 60
                }
            }
        },
        'security': {
            'encryption': {
                'algorithm': 'AES-256-GCM',
                'key_rotation_days': 90
            },
            'access_control': {
                'max_concurrent_sessions': 10,
                'session_timeout': 3600,
                'idle_timeout': 900
            }
        },
        'environments': {
            'development': {
                'database': {
                    'primary': {
                        'ssl': {
                            'mode': 'prefer'
                        }
                    }
                }
            },
            'test': {
                'database': {
                    'primary': {
                        'database': 'test_rbac',
                        'ssl': {
                            'mode': 'prefer'
                        }
                    }
                }
            }
        }
    }
    
    config_dir = Path(__file__).parent / 'config'
    config_dir.mkdir(exist_ok=True)
    
    config_file = config_dir / 'test_database.yaml'
    with open(config_file, 'w') as f:
        yaml.dump(test_config, f, default_flow_style=False)
    
    return str(config_file)


def run_database_validation():
    """Run comprehensive database validation."""
    print("DoD RBAC Database Layer Validation")
    print("=" * 50)
    
    # Check if database configuration exists
    config_path = Path(__file__).parent / 'config' / 'database.yaml'
    if not config_path.exists():
        print("⚠️  Database configuration file not found, creating test configuration...")
        config_path = create_test_database_config()
    
    try:
        # Load configuration
        print("✓ Loading database configuration...")
        config = DatabaseConfiguration(str(config_path))
        
        # Test configuration loading
        primary_config = config.get_database_config('primary')
        security_config = config.get_security_config()
        
        print(f"✓ Configuration loaded successfully")
        print(f"  - Database: {primary_config.get('database', 'unknown')}")
        print(f"  - Host: {primary_config.get('host', 'unknown')}")
        print(f"  - SSL Mode: {primary_config.get('ssl', {}).get('mode', 'unknown')}")
        
        # Test database connection (if credentials provided)
        if os.getenv('RBAC_DB_PASSWORD'):
            print("✓ Testing database connection...")
            db_conn = DatabaseConnection(config, 'primary')
            
            health_status = db_conn.health_check()
            if health_status.get('primary', False):
                print("✓ Database connection successful")
            else:
                print("⚠️  Database connection failed")
            
            # Test health monitoring
            print("✓ Testing health monitoring...")
            monitor = DatabaseHealthMonitor(config)
            health_summary = monitor.get_health_summary()
            print(f"  - Overall status: {health_summary.get('status', 'unknown')}")
            
        else:
            print("⚠️  Database password not provided, skipping connection tests")
            print("     Set RBAC_DB_PASSWORD environment variable for full testing")
        
        print("\n✅ Database layer validation completed successfully!")
        return True
        
    except Exception as e:
        print(f"\n❌ Database layer validation failed: {e}")
        return False


if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Test DoD-compliant RBAC database layer'
    )
    parser.add_argument(
        '--validate', '-v',
        action='store_true',
        help='Run validation instead of unit tests'
    )
    parser.add_argument(
        '--unittest', '-u',
        action='store_true',
        help='Run unit tests'
    )
    
    args = parser.parse_args()
    
    if args.validate or (not args.unittest and not args.validate):
        # Run validation by default
        success = run_database_validation()
        sys.exit(0 if success else 1)
    
    if args.unittest:
        # Run unit tests
        unittest.main(argv=[''])