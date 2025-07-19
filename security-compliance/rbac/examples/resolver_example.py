#!/usr/bin/env python3
"""
Permission Resolver Example and Test Script

Demonstrates comprehensive usage of the PermissionResolver system including:
- Basic permission resolution
- Advanced access control checks
- Performance optimization features
- Emergency access scenarios
- Bulk operations

Classification: UNCLASSIFIED//FOR OFFICIAL USE ONLY
"""

import os
import sys
import json
from datetime import datetime, timezone, timedelta
from uuid import uuid4, UUID
from typing import Dict, List, Any

# Add the parent directory to the path so we can import our models
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models import (
    DatabaseConnection, User, Role, Permission, UserRole, RolePermission,
    PermissionResolver, PermissionContext, PermissionResolution,
    SecurityClearance, AuditLog
)


def setup_test_data(db: DatabaseConnection) -> Dict[str, Any]:
    """
    Set up test data for the resolver demonstration.
    
    Returns:
        Dictionary containing test entities (users, roles, permissions)
    """
    print("Setting up test data...")
    
    # Create test security clearance
    clearance = SecurityClearance(
        clearance_level='S',
        clearance_name='Secret Clearance',
        investigation_type='SSBI',
        active=True,
        db_connection=db
    )
    clearance.save()
    
    # Create test users
    admin_user = User(
        username='admin.user',
        email='admin@example.mil',
        dod_id='1234567890',
        security_clearance_id=clearance.id,
        clearance_verified_at=datetime.now(timezone.utc),
        last_security_training=datetime.now(timezone.utc),
        security_training_expires=datetime.now(timezone.utc) + timedelta(days=365),
        account_status='ACTIVE',
        db_connection=db
    )
    admin_user.save()
    
    analyst_user = User(
        username='data.analyst',
        email='analyst@example.mil',
        dod_id='1234567891',
        security_clearance_id=clearance.id,
        clearance_verified_at=datetime.now(timezone.utc),
        last_security_training=datetime.now(timezone.utc),
        security_training_expires=datetime.now(timezone.utc) + timedelta(days=365),
        account_status='ACTIVE',
        db_connection=db
    )
    analyst_user.save()
    
    viewer_user = User(
        username='readonly.viewer',
        email='viewer@example.mil',
        dod_id='1234567892',
        security_clearance_id=clearance.id,
        clearance_verified_at=datetime.now(timezone.utc),
        last_security_training=datetime.now(timezone.utc) - timedelta(days=400),  # Expired training
        security_training_expires=datetime.now(timezone.utc) - timedelta(days=35),
        account_status='ACTIVE',
        db_connection=db
    )
    viewer_user.save()
    
    # Create test roles
    admin_role = Role(
        role_name='System Administrator',
        role_code='SYS_ADMIN',
        role_type='functional',
        description='Full system administration access',
        min_clearance_level='S',
        active=True,
        db_connection=db
    )
    admin_role.save()
    
    analyst_role = Role(
        role_name='Data Analyst',
        role_code='DATA_ANALYST',
        role_type='functional',
        description='Data analysis and modeling access',
        min_clearance_level='C',
        parent_role_id=None,  # Could inherit from a base role
        active=True,
        db_connection=db
    )
    analyst_role.save()
    
    viewer_role = Role(
        role_name='Read Only Viewer',
        role_code='VIEWER',
        role_type='functional',
        description='Read-only access to approved resources',
        min_clearance_level='CUI',
        active=True,
        db_connection=db
    )
    viewer_role.save()
    
    # Create test permissions
    permissions = [
        {
            'name': 'Read Notebooks',
            'code': 'notebook.read',
            'resource_type': 'notebook',
            'action': 'read',
            'classification_required': 'CUI',
            'risk_level': 'LOW'
        },
        {
            'name': 'Write Notebooks',
            'code': 'notebook.write',
            'resource_type': 'notebook',
            'action': 'write',
            'classification_required': 'C',
            'risk_level': 'MEDIUM'
        },
        {
            'name': 'Execute Notebooks',
            'code': 'notebook.execute',
            'resource_type': 'notebook',
            'action': 'execute',
            'classification_required': 'C',
            'risk_level': 'HIGH'
        },
        {
            'name': 'Admin System Config',
            'code': 'system_config.admin',
            'resource_type': 'system_config',
            'action': 'admin',
            'classification_required': 'S',
            'risk_level': 'CRITICAL'
        },
        {
            'name': 'Read Datasets',
            'code': 'dataset.read',
            'resource_type': 'dataset',
            'action': 'read',
            'classification_required': 'CUI',
            'risk_level': 'LOW'
        }
    ]
    
    perm_objects = []
    for perm_data in permissions:
        perm = Permission(
            permission_name=perm_data['name'],
            permission_code=perm_data['code'],
            resource_type=perm_data['resource_type'],
            action=perm_data['action'],
            classification_required=perm_data['classification_required'],
            risk_level=perm_data['risk_level'],
            audit_required=True,
            active=True,
            db_connection=db
        )
        perm.save()
        perm_objects.append(perm)
    
    # Assign permissions to roles
    # Admin gets all permissions
    for perm in perm_objects:
        role_perm = RolePermission(
            role_id=admin_role.id,
            permission_id=perm.id,
            granted_by=admin_user.id,
            granted_at=datetime.now(timezone.utc),
            active=True,
            db_connection=db
        )
        role_perm.save()
    
    # Analyst gets notebook and dataset permissions
    for perm in perm_objects:
        if perm.resource_type in ['notebook', 'dataset']:
            # Add time-based conditions for high-risk permissions
            conditions = {}
            if perm.risk_level == 'HIGH':
                conditions = {
                    'time_restrictions': {
                        'allowed_hours': {'start': 8, 'end': 18}  # 8 AM to 6 PM
                    }
                }
            
            role_perm = RolePermission(
                role_id=analyst_role.id,
                permission_id=perm.id,
                granted_by=admin_user.id,
                granted_at=datetime.now(timezone.utc),
                conditions=conditions,
                active=True,
                db_connection=db
            )
            role_perm.save()
    
    # Viewer gets only read permissions
    for perm in perm_objects:
        if perm.action == 'read':
            role_perm = RolePermission(
                role_id=viewer_role.id,
                permission_id=perm.id,
                granted_by=admin_user.id,
                granted_at=datetime.now(timezone.utc),
                active=True,
                db_connection=db
            )
            role_perm.save()
    
    # Assign roles to users
    # Admin user gets admin role
    admin_user_role = UserRole(
        user_id=admin_user.id,
        role_id=admin_role.id,
        assigned_by=admin_user.id,
        assigned_at=datetime.now(timezone.utc),
        approval_status='APPROVED',
        active=True,
        db_connection=db
    )
    admin_user_role.save()
    
    # Analyst user gets analyst role
    analyst_user_role = UserRole(
        user_id=analyst_user.id,
        role_id=analyst_role.id,
        assigned_by=admin_user.id,
        assigned_at=datetime.now(timezone.utc),
        approval_status='APPROVED',
        active=True,
        db_connection=db
    )
    analyst_user_role.save()
    
    # Viewer user gets viewer role
    viewer_user_role = UserRole(
        user_id=viewer_user.id,
        role_id=viewer_role.id,
        assigned_by=admin_user.id,
        assigned_at=datetime.now(timezone.utc),
        approval_status='APPROVED',
        active=True,
        db_connection=db
    )
    viewer_user_role.save()
    
    print("Test data setup complete!")
    
    return {
        'users': {
            'admin': admin_user,
            'analyst': analyst_user,
            'viewer': viewer_user
        },
        'roles': {
            'admin': admin_role,
            'analyst': analyst_role,
            'viewer': viewer_role
        },
        'permissions': {perm.permission_code: perm for perm in perm_objects},
        'clearance': clearance
    }


def demonstrate_basic_resolution(resolver: PermissionResolver, test_data: Dict[str, Any]):
    """Demonstrate basic permission resolution functionality."""
    print("\n" + "="*50)
    print("BASIC PERMISSION RESOLUTION DEMONSTRATION")
    print("="*50)
    
    # Get all permissions for admin user
    admin_user = test_data['users']['admin']
    print(f"\n1. Resolving permissions for admin user: {admin_user.username}")
    
    admin_permissions = resolver.resolve_user_permissions(admin_user.id)
    print(f"   Total permissions: {len(admin_permissions)}")
    
    for perm in admin_permissions[:3]:  # Show first 3
        print(f"   - {perm['permission_name']} ({perm['full_permission_code']}) "
              f"[Risk: {perm['risk_level']}, Inherited: {perm['is_inherited']}]")
    
    # Get permissions for analyst user
    analyst_user = test_data['users']['analyst']
    print(f"\n2. Resolving permissions for analyst user: {analyst_user.username}")
    
    analyst_permissions = resolver.resolve_user_permissions(analyst_user.id)
    print(f"   Total permissions: {len(analyst_permissions)}")
    
    for perm in analyst_permissions:
        conditions_str = f" [Conditions: {len(perm.get('conditions', {}))}]" if perm.get('conditions') else ""
        print(f"   - {perm['permission_name']} ({perm['full_permission_code']}){conditions_str}")
    
    # Get permissions for viewer user (with expired training)
    viewer_user = test_data['users']['viewer']
    print(f"\n3. Resolving permissions for viewer user: {viewer_user.username} (expired training)")
    
    viewer_permissions = resolver.resolve_user_permissions(viewer_user.id)
    print(f"   Total permissions: {len(viewer_permissions)}")
    
    for perm in viewer_permissions:
        print(f"   - {perm['permission_name']} ({perm['full_permission_code']})")


def demonstrate_access_control(resolver: PermissionResolver, test_data: Dict[str, Any]):
    """Demonstrate comprehensive access control checks."""
    print("\n" + "="*50)
    print("ACCESS CONTROL CHECK DEMONSTRATION")
    print("="*50)
    
    admin_user = test_data['users']['admin']
    analyst_user = test_data['users']['analyst']
    viewer_user = test_data['users']['viewer']
    
    # Test scenarios
    test_scenarios = [
        {
            'description': 'Admin accessing high-risk system config',
            'user': admin_user,
            'resource_type': 'system_config',
            'action': 'admin',
            'classification_level': 'S',
            'expected': True
        },
        {
            'description': 'Analyst executing notebook during business hours',
            'user': analyst_user,
            'resource_type': 'notebook',
            'action': 'execute',
            'classification_level': 'C',
            'expected': True,
            'additional_attrs': {'current_hour': 14}  # 2 PM
        },
        {
            'description': 'Analyst executing notebook after hours',
            'user': analyst_user,
            'resource_type': 'notebook',
            'action': 'execute',
            'classification_level': 'C',
            'expected': False,
            'additional_attrs': {'current_hour': 22}  # 10 PM
        },
        {
            'description': 'Viewer with expired training accessing high-risk operation',
            'user': viewer_user,
            'resource_type': 'notebook',
            'action': 'execute',
            'classification_level': 'C',
            'expected': False
        },
        {
            'description': 'Viewer with expired training - emergency access',
            'user': viewer_user,
            'resource_type': 'notebook',
            'action': 'read',
            'classification_level': 'CUI',
            'emergency_access': True,
            'expected': True
        },
        {
            'description': 'User without permission accessing resource',
            'user': viewer_user,
            'resource_type': 'system_config',
            'action': 'admin',
            'classification_level': 'S',
            'expected': False
        }
    ]
    
    for i, scenario in enumerate(test_scenarios, 1):
        print(f"\n{i}. Testing: {scenario['description']}")
        
        context = PermissionContext(
            user_id=scenario['user'].id,
            resource_type=scenario['resource_type'],
            action=scenario['action'],
            resource_id=f"test_resource_{i}",
            classification_level=scenario.get('classification_level'),
            ip_address='192.168.1.100',
            session_id=f"session_{i}",
            emergency_access=scenario.get('emergency_access', False),
            additional_attributes=scenario.get('additional_attrs', {})
        )
        
        resolution = resolver.check_access(context)
        
        status = "✓ GRANTED" if resolution.granted else "✗ DENIED"
        expected_status = "✓" if scenario['expected'] else "✗"
        match = "✓" if resolution.granted == scenario['expected'] else "✗ MISMATCH"
        
        print(f"   Result: {status} [Expected: {expected_status}] {match}")
        print(f"   Reason: {resolution.reason}")
        
        if resolution.emergency_override:
            print(f"   ⚠️  Emergency Override Applied")
        
        if not resolution.clearance_verified:
            print(f"   ⚠️  Clearance Not Verified")
        
        if not resolution.training_current:
            print(f"   ⚠️  Training Not Current")


def demonstrate_performance_features(resolver: PermissionResolver, test_data: Dict[str, Any]):
    """Demonstrate performance optimization features."""
    print("\n" + "="*50)
    print("PERFORMANCE OPTIMIZATION DEMONSTRATION")
    print("="*50)
    
    admin_user = test_data['users']['admin']
    analyst_user = test_data['users']['analyst']
    
    # Test caching
    print("\n1. Testing Permission Caching")
    
    # First access (cache miss)
    context1 = PermissionContext(
        user_id=admin_user.id,
        resource_type='notebook',
        action='read',
        classification_level='CUI',
        ip_address='192.168.1.100'
    )
    
    print("   First access (cache miss):")
    start_time = time.time()
    resolution1 = resolver.check_access(context1)
    duration1 = time.time() - start_time
    print(f"   - Duration: {duration1:.4f}s")
    print(f"   - Result: {'GRANTED' if resolution1.granted else 'DENIED'}")
    
    # Second access (cache hit)
    print("   Second access (cache hit):")
    start_time = time.time()
    resolution2 = resolver.check_access(context1)
    duration2 = time.time() - start_time
    print(f"   - Duration: {duration2:.4f}s")
    print(f"   - Result: {'GRANTED' if resolution2.granted else 'DENIED'}")
    print(f"   - Speed improvement: {duration1/duration2:.1f}x faster")
    
    # Test bulk operations
    print("\n2. Testing Bulk Access Checks")
    
    # Create multiple contexts
    bulk_contexts = []
    for i in range(10):
        for user in [admin_user, analyst_user]:
            context = PermissionContext(
                user_id=user.id,
                resource_type='dataset' if i % 2 == 0 else 'notebook',
                action='read' if i % 3 == 0 else 'write',
                resource_id=f"resource_{i}",
                classification_level='CUI',
                ip_address='192.168.1.100'
            )
            bulk_contexts.append(context)
    
    print(f"   Processing {len(bulk_contexts)} access checks...")
    start_time = time.time()
    bulk_results = resolver.bulk_check_access(bulk_contexts)
    duration = time.time() - start_time
    
    granted_count = sum(1 for result in bulk_results if result.granted)
    denied_count = len(bulk_results) - granted_count
    
    print(f"   - Duration: {duration:.4f}s")
    print(f"   - Average per check: {duration/len(bulk_contexts):.4f}s")
    print(f"   - Results: {granted_count} granted, {denied_count} denied")
    
    # Show performance metrics
    print("\n3. Performance Metrics")
    metrics = resolver.get_performance_metrics()
    print(f"   - Total resolutions: {metrics['total_resolutions']}")
    print(f"   - Cache hit rate: {metrics['cache_hit_rate']:.2%}")
    print(f"   - Cache utilization: {metrics['cache_stats']['utilization']:.2%}")


def demonstrate_user_access_summary(resolver: PermissionResolver, test_data: Dict[str, Any]):
    """Demonstrate user access summary functionality."""
    print("\n" + "="*50)
    print("USER ACCESS SUMMARY DEMONSTRATION")
    print("="*50)
    
    for user_type, user in test_data['users'].items():
        print(f"\n{user_type.upper()} USER SUMMARY ({user.username}):")
        
        summary = resolver.get_user_access_summary(user.id)
        
        print(f"   Account Status: {summary['user_info']['account_status']}")
        print(f"   Clearance Verified: {summary['user_info']['clearance_verified']}")
        print(f"   Training Current: {summary['user_info']['training_current']}")
        
        perm_summary = summary['permission_summary']
        print(f"   Total Permissions: {perm_summary['total_permissions']}")
        print(f"   Direct Permissions: {perm_summary['direct_permissions']}")
        print(f"   Inherited Permissions: {perm_summary['inherited_permissions']}")
        print(f"   High-Risk Permissions: {perm_summary['high_risk_permissions']}")
        
        print("   Permissions by Resource Type:")
        for resource_type, count in summary['permissions_by_resource'].items():
            print(f"     - {resource_type}: {count}")
        
        print("   Assigned Roles:")
        for role in summary['roles']:
            status = "Active" if role['active'] else "Inactive"
            print(f"     - {role['role_name']} ({role['role_code']}) - {status}")


def demonstrate_audit_trail(resolver: PermissionResolver, test_data: Dict[str, Any]):
    """Demonstrate audit trail functionality."""
    print("\n" + "="*50)
    print("AUDIT TRAIL DEMONSTRATION")
    print("="*50)
    
    # Get recent audit logs
    recent_logs = AuditLog.find_all(
        limit=10,
        db_connection=resolver.db
    )
    
    print(f"\nRecent Audit Events ({len(recent_logs)} shown):")
    
    for log in recent_logs:
        timestamp = log.created_at.strftime('%Y-%m-%d %H:%M:%S') if log.created_at else 'Unknown'
        user_info = f"User {log.user_id}" if log.user_id else "System"
        
        print(f"   [{timestamp}] {log.event_type}")
        print(f"     User: {user_info}")
        print(f"     Result: {log.result}")
        print(f"     Resource: {log.resource_type or 'N/A'}")
        
        if log.reason:
            print(f"     Reason: {log.reason}")
        
        print()


def main():
    """Main demonstration function."""
    print("Permission Resolver Comprehensive Demonstration")
    print("=" * 60)
    
    # Initialize database connection
    try:
        db = DatabaseConnection()
        print("Database connection established successfully!")
    except Exception as e:
        print(f"Failed to connect to database: {e}")
        print("Please ensure your database is running and environment variables are set.")
        return
    
    # Set up test data
    try:
        test_data = setup_test_data(db)
    except Exception as e:
        print(f"Failed to set up test data: {e}")
        return
    
    # Initialize resolver
    resolver = PermissionResolver(
        db_connection=db,
        cache_ttl=300,  # 5 minutes
        cache_size=1000,
        enable_emergency_access=True
    )
    
    try:
        # Run demonstrations
        demonstrate_basic_resolution(resolver, test_data)
        demonstrate_access_control(resolver, test_data)
        demonstrate_performance_features(resolver, test_data)
        demonstrate_user_access_summary(resolver, test_data)
        demonstrate_audit_trail(resolver, test_data)
        
        print("\n" + "="*60)
        print("DEMONSTRATION COMPLETE")
        print("="*60)
        print("\nKey Features Demonstrated:")
        print("✓ Role-based permission inheritance")
        print("✓ Temporal permission validation")
        print("✓ Classification level enforcement")
        print("✓ Context-aware permission evaluation (ABAC)")
        print("✓ Performance caching and optimization")
        print("✓ Emergency access handling")
        print("✓ Comprehensive audit trail")
        print("✓ Bulk operations support")
        print("✓ Conflict resolution")
        print("✓ Security features and training requirements")
        
        # Show final performance metrics
        print(f"\nFinal Performance Metrics:")
        final_metrics = resolver.get_performance_metrics()
        print(f"Total Access Checks: {final_metrics['total_resolutions']}")
        print(f"Cache Hit Rate: {final_metrics['cache_hit_rate']:.2%}")
        print(f"Cache Efficiency: {final_metrics['cache_stats']['utilization']:.2%}")
        
    except Exception as e:
        print(f"Error during demonstration: {e}")
        import traceback
        traceback.print_exc()


if __name__ == '__main__':
    import time
    main()