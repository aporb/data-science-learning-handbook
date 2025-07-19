#!/usr/bin/env python3
"""
Unit Tests for Permission Resolver

Comprehensive test suite for the PermissionResolver class including:
- Permission resolution functionality
- Access control checks
- Performance optimization
- Security features
- Error handling

Classification: UNCLASSIFIED//FOR OFFICIAL USE ONLY
"""

import unittest
import os
import sys
from datetime import datetime, timezone, timedelta
from uuid import uuid4
from unittest.mock import Mock, patch, MagicMock

# Add the parent directory to the path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models import (
    DatabaseConnection, User, Role, Permission, UserRole, RolePermission,
    PermissionResolver, PermissionContext, PermissionResolution, PermissionCache,
    SecurityClearance, AuditLog
)


class TestPermissionCache(unittest.TestCase):
    """Test cases for PermissionCache class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.cache = PermissionCache(ttl_seconds=5, max_size=3)
    
    def test_cache_put_and_get(self):
        """Test basic cache put and get operations."""
        resolution = PermissionResolution(granted=True, reason="Test")
        
        self.cache.put("test_key", resolution)
        cached_result = self.cache.get("test_key")
        
        self.assertIsNotNone(cached_result)
        self.assertEqual(cached_result.granted, True)
        self.assertEqual(cached_result.reason, "Test")
    
    def test_cache_ttl_expiration(self):
        """Test that cache entries expire after TTL."""
        resolution = PermissionResolution(granted=True, reason="Test")
        
        self.cache.put("test_key", resolution)
        
        # Should be available immediately
        self.assertIsNotNone(self.cache.get("test_key"))
        
        # Mock time advancement beyond TTL
        import time
        with patch('time.time', return_value=time.time() + 10):
            with patch('models.resolver.datetime') as mock_datetime:
                mock_datetime.now.return_value = datetime.now(timezone.utc) + timedelta(seconds=10)
                result = self.cache.get("test_key")
                self.assertIsNone(result)
    
    def test_cache_size_limit(self):
        """Test that cache respects size limits and evicts LRU entries."""
        # Fill cache to capacity
        for i in range(3):
            resolution = PermissionResolution(granted=True, reason=f"Test {i}")
            self.cache.put(f"key_{i}", resolution)
        
        # All entries should be present
        for i in range(3):
            self.assertIsNotNone(self.cache.get(f"key_{i}"))
        
        # Add one more entry (should evict LRU)
        resolution = PermissionResolution(granted=True, reason="Test 3")
        self.cache.put("key_3", resolution)
        
        # First entry should be evicted
        self.assertIsNone(self.cache.get("key_0"))
        self.assertIsNotNone(self.cache.get("key_3"))
    
    def test_cache_invalidation(self):
        """Test cache invalidation functionality."""
        user_id = uuid4()
        resolution = PermissionResolution(granted=True, reason="Test")
        
        # Put entry with user ID in key
        self.cache.put(f"user_{user_id}_test", resolution)
        self.assertIsNotNone(self.cache.get(f"user_{user_id}_test"))
        
        # Invalidate user cache
        self.cache.invalidate_user(user_id)
        self.assertIsNone(self.cache.get(f"user_{user_id}_test"))
    
    def test_cache_stats(self):
        """Test cache statistics."""
        stats = self.cache.get_stats()
        
        self.assertIn('size', stats)
        self.assertIn('max_size', stats)
        self.assertIn('ttl_seconds', stats)
        self.assertIn('utilization', stats)
        
        self.assertEqual(stats['max_size'], 3)
        self.assertEqual(stats['ttl_seconds'], 5)


class TestPermissionContext(unittest.TestCase):
    """Test cases for PermissionContext class."""
    
    def test_context_creation(self):
        """Test permission context creation."""
        user_id = uuid4()
        context = PermissionContext(
            user_id=user_id,
            resource_type="notebook",
            action="read",
            resource_id="test_resource",
            classification_level="CUI",
            ip_address="192.168.1.100",
            session_id="test_session",
            emergency_access=False,
            additional_attributes={"department": "IT"}
        )
        
        self.assertEqual(context.user_id, user_id)
        self.assertEqual(context.resource_type, "notebook")
        self.assertEqual(context.action, "read")
        self.assertEqual(context.classification_level, "CUI")
        self.assertFalse(context.emergency_access)
        self.assertEqual(context.additional_attributes["department"], "IT")
    
    def test_context_to_dict(self):
        """Test context serialization to dictionary."""
        user_id = uuid4()
        context = PermissionContext(
            user_id=user_id,
            resource_type="notebook",
            action="read"
        )
        
        context_dict = context.to_dict()
        
        self.assertIn('user_id', context_dict)
        self.assertIn('resource_type', context_dict)
        self.assertIn('action', context_dict)
        self.assertIn('timestamp', context_dict)
        self.assertEqual(context_dict['user_id'], str(user_id))
    
    def test_cache_key_generation(self):
        """Test cache key generation for contexts."""
        user_id = uuid4()
        
        context1 = PermissionContext(
            user_id=user_id,
            resource_type="notebook",
            action="read"
        )
        
        context2 = PermissionContext(
            user_id=user_id,
            resource_type="notebook",
            action="read"
        )
        
        # Same contexts should generate same cache key
        self.assertEqual(context1.get_cache_key(), context2.get_cache_key())
        
        context3 = PermissionContext(
            user_id=user_id,
            resource_type="notebook",
            action="write"  # Different action
        )
        
        # Different contexts should generate different cache keys
        self.assertNotEqual(context1.get_cache_key(), context3.get_cache_key())


class TestPermissionResolution(unittest.TestCase):
    """Test cases for PermissionResolution class."""
    
    def test_resolution_creation(self):
        """Test permission resolution creation."""
        permissions = [
            {"permission_name": "Test Permission", "resource_type": "notebook"}
        ]
        
        resolution = PermissionResolution(
            granted=True,
            reason="Access granted - all requirements met",
            effective_permissions=permissions,
            clearance_verified=True,
            training_current=True,
            emergency_override=False,
            conditions_met=True,
            audit_required=True
        )
        
        self.assertTrue(resolution.granted)
        self.assertEqual(len(resolution.effective_permissions), 1)
        self.assertTrue(resolution.clearance_verified)
        self.assertTrue(resolution.training_current)
        self.assertFalse(resolution.emergency_override)
        self.assertTrue(resolution.conditions_met)
        self.assertTrue(resolution.audit_required)
    
    def test_resolution_to_dict(self):
        """Test resolution serialization to dictionary."""
        resolution = PermissionResolution(
            granted=False,
            reason="Access denied - insufficient clearance"
        )
        
        resolution_dict = resolution.to_dict()
        
        self.assertIn('granted', resolution_dict)
        self.assertIn('reason', resolution_dict)
        self.assertIn('resolution_time', resolution_dict)
        self.assertFalse(resolution_dict['granted'])


class TestPermissionResolver(unittest.TestCase):
    """Test cases for PermissionResolver class."""
    
    def setUp(self):
        """Set up test fixtures."""
        # Mock database connection
        self.mock_db = Mock(spec=DatabaseConnection)
        self.mock_cursor = Mock()
        self.mock_db.get_cursor.return_value.__enter__.return_value = self.mock_cursor
        self.mock_db.get_cursor.return_value.__exit__.return_value = None
        
        # Create resolver with mock database
        self.resolver = PermissionResolver(
            db_connection=self.mock_db,
            cache_ttl=300,
            cache_size=1000,
            enable_emergency_access=True
        )
        
        # Test data
        self.user_id = uuid4()
        self.role_id = uuid4()
        self.permission_id = uuid4()
    
    def test_resolver_initialization(self):
        """Test resolver initialization."""
        resolver = PermissionResolver(
            db_connection=self.mock_db,
            cache_ttl=600,
            cache_size=2000
        )
        
        self.assertIsNotNone(resolver.cache)
        self.assertEqual(resolver.cache.ttl_seconds, 600)
        self.assertEqual(resolver.cache.max_size, 2000)
        self.assertTrue(resolver.enable_emergency_access)
    
    @patch('models.resolver.User')
    def test_resolve_user_permissions_user_not_found(self, mock_user_class):
        """Test permission resolution when user is not found."""
        mock_user_class.find_by_id.return_value = None
        
        permissions = self.resolver.resolve_user_permissions(self.user_id)
        
        self.assertEqual(permissions, [])
        mock_user_class.find_by_id.assert_called_once_with(self.user_id, self.mock_db)
    
    @patch('models.resolver.User')
    def test_resolve_user_permissions_inactive_user(self, mock_user_class):
        """Test permission resolution for inactive user."""
        mock_user = Mock()
        mock_user.is_active.return_value = False
        mock_user_class.find_by_id.return_value = mock_user
        
        permissions = self.resolver.resolve_user_permissions(self.user_id)
        
        self.assertEqual(permissions, [])
    
    @patch('models.resolver.User')
    def test_resolve_user_permissions_success(self, mock_user_class):
        """Test successful permission resolution."""
        # Mock user
        mock_user = Mock()
        mock_user.is_active.return_value = True
        mock_user_class.find_by_id.return_value = mock_user
        
        # Mock database results
        mock_permission_data = {
            'permission_id': self.permission_id,
            'permission_name': 'Test Permission',
            'permission_code': 'test.permission',
            'resource_type': 'notebook',
            'action': 'read',
            'scope': 'global',
            'classification_required': 'CUI',
            'risk_level': 'LOW',
            'audit_required': True,
            'role_id': self.role_id,
            'role_name': 'Test Role',
            'role_code': 'TEST_ROLE',
            'inheritance_level': 0,
            'conditions': {},
            'permission_expires_at': None,
            'granted_by': self.user_id,
            'granted_at': datetime.now(timezone.utc)
        }
        
        self.mock_cursor.fetchall.return_value = [mock_permission_data]
        
        permissions = self.resolver.resolve_user_permissions(self.user_id)
        
        self.assertEqual(len(permissions), 1)
        perm = permissions[0]
        self.assertEqual(perm['permission_name'], 'Test Permission')
        self.assertEqual(perm['resource_type'], 'notebook')
        self.assertEqual(perm['action'], 'read')
        self.assertFalse(perm['is_inherited'])
        self.assertFalse(perm['is_expired'])
        self.assertEqual(perm['full_permission_code'], 'notebook.read')
    
    @patch('models.resolver.User')
    @patch('models.resolver.Permission')
    @patch('models.resolver.AuditLog')
    def test_check_access_user_not_found(self, mock_audit_class, mock_permission_class, mock_user_class):
        """Test access check when user is not found."""
        mock_user_class.find_by_id.return_value = None
        
        context = PermissionContext(
            user_id=self.user_id,
            resource_type="notebook",
            action="read"
        )
        
        resolution = self.resolver.check_access(context)
        
        self.assertFalse(resolution.granted)
        self.assertEqual(resolution.reason, "User not found")
        self.assertTrue(resolution.audit_required)
    
    @patch('models.resolver.User')
    @patch('models.resolver.Permission')
    @patch('models.resolver.AuditLog')
    def test_check_access_inactive_user(self, mock_audit_class, mock_permission_class, mock_user_class):
        """Test access check for inactive user."""
        mock_user = Mock()
        mock_user.is_active.return_value = False
        mock_user_class.find_by_id.return_value = mock_user
        
        context = PermissionContext(
            user_id=self.user_id,
            resource_type="notebook",
            action="read"
        )
        
        resolution = self.resolver.check_access(context)
        
        self.assertFalse(resolution.granted)
        self.assertEqual(resolution.reason, "User account is not active")
    
    @patch('models.resolver.User')
    @patch('models.resolver.Permission')
    @patch('models.resolver.AuditLog')
    def test_check_access_no_permission_defined(self, mock_audit_class, mock_permission_class, mock_user_class):
        """Test access check when no permission is defined for the action."""
        # Mock active user
        mock_user = Mock()
        mock_user.is_active.return_value = True
        mock_user.is_clearance_verified.return_value = True
        mock_user.is_training_current.return_value = True
        mock_user_class.find_by_id.return_value = mock_user
        
        # No permission found for the action
        mock_permission_class.get_by_resource_action.return_value = None
        
        # Mock empty permissions
        self.resolver.resolve_user_permissions = Mock(return_value=[])
        
        context = PermissionContext(
            user_id=self.user_id,
            resource_type="notebook",
            action="unknown_action"
        )
        
        resolution = self.resolver.check_access(context)
        
        self.assertFalse(resolution.granted)
        self.assertIn("No permission defined", resolution.reason)
    
    @patch('models.resolver.User')
    @patch('models.resolver.Permission')
    @patch('models.resolver.AuditLog')
    def test_check_access_success(self, mock_audit_class, mock_permission_class, mock_user_class):
        """Test successful access check."""
        # Mock active user with proper clearance and training
        mock_user = Mock()
        mock_user.is_active.return_value = True
        mock_user.is_clearance_verified.return_value = True
        mock_user.is_training_current.return_value = True
        mock_user.can_access_classification.return_value = True
        mock_user_class.find_by_id.return_value = mock_user
        
        # Mock permission
        mock_permission = Mock()
        mock_permission.classification_required = 'CUI'
        mock_permission.is_high_risk.return_value = False
        mock_permission.audit_required = True
        mock_permission_class.get_by_resource_action.return_value = mock_permission
        
        # Mock user permissions
        mock_permissions = [{
            'resource_type': 'notebook',
            'action': 'read',
            'is_expired': False,
            'conditions': {}
        }]
        self.resolver.resolve_user_permissions = Mock(return_value=mock_permissions)
        
        context = PermissionContext(
            user_id=self.user_id,
            resource_type="notebook",
            action="read",
            classification_level="CUI"
        )
        
        resolution = self.resolver.check_access(context)
        
        self.assertTrue(resolution.granted)
        self.assertEqual(resolution.reason, "Access granted - all requirements met")
        self.assertTrue(resolution.clearance_verified)
        self.assertTrue(resolution.training_current)
        self.assertTrue(resolution.conditions_met)
    
    @patch('models.resolver.User')
    @patch('models.resolver.Permission')
    @patch('models.resolver.AuditLog')
    def test_check_access_emergency_override(self, mock_audit_class, mock_permission_class, mock_user_class):
        """Test emergency access override functionality."""
        # Mock user with expired training
        mock_user = Mock()
        mock_user.is_active.return_value = True
        mock_user.is_clearance_verified.return_value = True
        mock_user.is_training_current.return_value = False  # Expired training
        mock_user.can_access_classification.return_value = True
        mock_user_class.find_by_id.return_value = mock_user
        
        # Mock high-risk permission
        mock_permission = Mock()
        mock_permission.classification_required = 'CUI'
        mock_permission.is_high_risk.return_value = True
        mock_permission.audit_required = True
        mock_permission_class.get_by_resource_action.return_value = mock_permission
        
        # Mock user permissions
        mock_permissions = [{
            'resource_type': 'notebook',
            'action': 'execute',
            'is_expired': False,
            'conditions': {}
        }]
        self.resolver.resolve_user_permissions = Mock(return_value=mock_permissions)
        
        # Test emergency access
        context = PermissionContext(
            user_id=self.user_id,
            resource_type="notebook",
            action="execute",
            emergency_access=True
        )
        
        resolution = self.resolver.check_access(context)
        
        self.assertTrue(resolution.granted)
        self.assertTrue(resolution.emergency_override)
        self.assertIn("Emergency access granted", resolution.reason)
    
    def test_cache_integration(self):
        """Test cache integration in access checks."""
        context = PermissionContext(
            user_id=self.user_id,
            resource_type="notebook",
            action="read"
        )
        
        # Mock a cached result
        cached_resolution = PermissionResolution(
            granted=True,
            reason="Cached result",
            audit_required=False
        )
        
        cache_key = context.get_cache_key()
        self.resolver.cache.put(cache_key, cached_resolution)
        
        # Check access should return cached result
        resolution = self.resolver.check_access(context)
        
        self.assertTrue(resolution.granted)
        self.assertEqual(resolution.reason, "Cached result")
    
    def test_performance_metrics(self):
        """Test performance metrics tracking."""
        initial_metrics = self.resolver.get_performance_metrics()
        
        self.assertIn('total_resolutions', initial_metrics)
        self.assertIn('cache_hits', initial_metrics)
        self.assertIn('cache_misses', initial_metrics)
        self.assertIn('cache_hit_rate', initial_metrics)
        
        # Initial state should have zero values
        self.assertEqual(initial_metrics['total_resolutions'], 0)
        self.assertEqual(initial_metrics['cache_hits'], 0)
        self.assertEqual(initial_metrics['cache_misses'], 0)
    
    def test_bulk_check_access(self):
        """Test bulk access check functionality."""
        contexts = []
        for i in range(5):
            context = PermissionContext(
                user_id=self.user_id,
                resource_type="notebook",
                action="read",
                resource_id=f"resource_{i}"
            )
            contexts.append(context)
        
        # Mock the individual check_access method
        self.resolver.check_access = Mock(return_value=PermissionResolution(
            granted=True,
            reason="Bulk test"
        ))
        
        resolutions = self.resolver.bulk_check_access(contexts)
        
        self.assertEqual(len(resolutions), 5)
        self.assertEqual(self.resolver.check_access.call_count, 5)
    
    def test_conflict_resolution(self):
        """Test permission conflict resolution."""
        # Create conflicting permissions
        conflicting_permissions = [
            {
                'permission_id': uuid4(),
                'resource_type': 'notebook',
                'action': 'read',
                'is_inherited': True,
                'risk_level': 'LOW',
                'conditions': {},
                'granted_at': datetime.now(timezone.utc) - timedelta(days=1)
            },
            {
                'permission_id': uuid4(),
                'resource_type': 'notebook',
                'action': 'read',
                'is_inherited': False,  # Direct assignment
                'risk_level': 'MEDIUM',
                'conditions': {'time_restrictions': {}},
                'granted_at': datetime.now(timezone.utc)
            }
        ]
        
        resolved = self.resolver.resolve_conflicts(conflicting_permissions)
        
        # Should prefer direct assignment over inherited
        self.assertEqual(len(resolved), 1)
        self.assertFalse(resolved[0]['is_inherited'])
        self.assertEqual(resolved[0]['risk_level'], 'MEDIUM')
    
    @patch('models.resolver.User')
    def test_get_user_access_summary(self, mock_user_class):
        """Test user access summary generation."""
        # Mock user
        mock_user = Mock()
        mock_user.id = self.user_id
        mock_user.username = 'test.user'
        mock_user.account_status = 'ACTIVE'
        mock_user.is_clearance_verified.return_value = True
        mock_user.is_training_current.return_value = True
        mock_user.get_roles.return_value = []
        mock_user.get_security_clearance.return_value = Mock(clearance_level='S')
        mock_user_class.find_by_id.return_value = mock_user
        
        # Mock permissions
        mock_permissions = [
            {
                'resource_type': 'notebook',
                'action': 'read',
                'is_inherited': False,
                'is_expired': False,
                'risk_level': 'LOW'
            },
            {
                'resource_type': 'dataset',
                'action': 'write',
                'is_inherited': True,
                'is_expired': False,
                'risk_level': 'HIGH'
            }
        ]
        self.resolver.resolve_user_permissions = Mock(return_value=mock_permissions)
        
        summary = self.resolver.get_user_access_summary(self.user_id)
        
        self.assertIn('user_info', summary)
        self.assertIn('permission_summary', summary)
        self.assertIn('permissions_by_resource', summary)
        self.assertIn('roles', summary)
        self.assertIn('security_clearance', summary)
        
        self.assertEqual(summary['user_info']['username'], 'test.user')
        self.assertEqual(summary['permission_summary']['total_permissions'], 2)
        self.assertEqual(summary['permission_summary']['direct_permissions'], 1)
        self.assertEqual(summary['permission_summary']['inherited_permissions'], 1)
        self.assertEqual(summary['permission_summary']['high_risk_permissions'], 1)


class TestABACEvaluation(unittest.TestCase):
    """Test cases for ABAC condition evaluation."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.mock_db = Mock(spec=DatabaseConnection)
        self.resolver = PermissionResolver(db_connection=self.mock_db)
    
    def test_evaluate_time_conditions_allowed_hours(self):
        """Test time-based ABAC condition evaluation."""
        # Test allowed hours (8 AM to 6 PM)
        time_restrictions = {
            'allowed_hours': {'start': 8, 'end': 18}
        }
        
        # Mock current time to 2 PM (14:00)
        with patch('models.resolver.datetime') as mock_datetime:
            mock_now = Mock()
            mock_now.hour = 14
            mock_datetime.now.return_value = mock_now
            
            result = self.resolver._evaluate_time_conditions(time_restrictions)
            self.assertTrue(result[0])
            self.assertEqual(result[1], "Time conditions satisfied")
        
        # Mock current time to 10 PM (22:00) - outside allowed hours
        with patch('models.resolver.datetime') as mock_datetime:
            mock_now = Mock()
            mock_now.hour = 22
            mock_datetime.now.return_value = mock_now
            
            result = self.resolver._evaluate_time_conditions(time_restrictions)
            self.assertFalse(result[0])
            self.assertIn("Access only allowed between", result[1])
    
    def test_evaluate_location_conditions(self):
        """Test location-based ABAC condition evaluation."""
        location_restrictions = {
            'allowed_networks': ['192.168.1.0/24', '10.0.0.0/8']
        }
        
        # Test allowed IP
        result = self.resolver._evaluate_location_conditions(location_restrictions, '192.168.1.100')
        self.assertTrue(result[0])
        
        # Test disallowed IP
        result = self.resolver._evaluate_location_conditions(location_restrictions, '203.0.113.1')
        self.assertFalse(result[0])
        self.assertIn("not in allowed networks", result[1])
    
    def test_evaluate_attribute_conditions(self):
        """Test attribute-based ABAC condition evaluation."""
        required_attributes = {
            'department': 'IT',
            'clearance_level': ['S', 'TS']
        }
        
        # Test matching attributes
        user_attributes = {
            'department': 'IT',
            'clearance_level': 'S'
        }
        
        result = self.resolver._evaluate_attribute_conditions(required_attributes, user_attributes)
        self.assertTrue(result[0])
        
        # Test missing attribute
        user_attributes = {
            'department': 'HR'  # Missing clearance_level
        }
        
        result = self.resolver._evaluate_attribute_conditions(required_attributes, user_attributes)
        self.assertFalse(result[0])
        self.assertIn("Required attribute", result[1])


if __name__ == '__main__':
    # Run the tests
    unittest.main(verbosity=2)