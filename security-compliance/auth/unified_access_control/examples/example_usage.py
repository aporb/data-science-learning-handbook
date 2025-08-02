"""
Unified Access Control System - Example Usage

Demonstrates how to use the unified access control system for enterprise-grade
access control across CAC/PIV authentication, RBAC permissions, OAuth platform
integrations, and comprehensive audit logging.

This example shows:
- System initialization and configuration
- User authentication and context building
- Cross-platform access control decisions
- Session management and synchronization
- Audit logging and compliance reporting
- Performance monitoring and health checks

Classification: UNCLASSIFIED//FOR OFFICIAL USE ONLY
"""

import asyncio
import logging
from datetime import datetime, timezone
from uuid import UUID, uuid4

# Import unified access control components
from ..controller import UnifiedAccessController, UnifiedAccessRequest, AccessDecision
from ..context import UnifiedUserContext, PlatformContext, PlatformStatus
from ..config import UnifiedAccessConfig, PlatformConfig, OAuthPlatformConfig
from ..adapters import PlatformAdapterRegistry

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


async def example_system_initialization():
    """Example: Initialize the unified access control system."""
    logger.info("=== System Initialization Example ===")
    
    # 1. Create configuration
    config = UnifiedAccessConfig(environment="development")
    
    # 2. Configure platforms
    qlik_oauth = OAuthPlatformConfig(
        client_id="qlik-client-id",
        client_secret="qlik-client-secret", 
        authorization_url="https://qlik.example.com/oauth/authorize",
        token_url="https://qlik.example.com/oauth/token",
        redirect_uri="https://app.example.com/callback",
        scopes=["qlik:read", "qlik:write"]
    )
    
    databricks_oauth = OAuthPlatformConfig(
        client_id="databricks-client-id",
        client_secret="databricks-client-secret",
        authorization_url="https://databricks.example.com/oauth/authorize", 
        token_url="https://databricks.example.com/oauth/token",
        redirect_uri="https://app.example.com/callback",
        scopes=["databricks:read", "databricks:write"]
    )
    
    qlik_platform = PlatformConfig(
        name="qlik",
        enabled=True,
        base_url="https://qlik.example.com",
        oauth=qlik_oauth
    )
    
    databricks_platform = PlatformConfig(
        name="databricks",
        enabled=True,
        base_url="https://databricks.example.com",
        oauth=databricks_oauth
    )
    
    config.add_platform_config(qlik_platform)
    config.add_platform_config(databricks_platform)
    
    # 3. Initialize unified access controller
    controller = UnifiedAccessController(config)
    
    # 4. Start the system
    await controller.session_manager.start()
    await controller.audit_manager.start()
    
    logger.info("Unified access control system initialized successfully")
    return controller, config


async def example_user_authentication_and_context():
    """Example: User authentication and unified context building."""
    logger.info("=== User Authentication and Context Example ===")
    
    controller, config = await example_system_initialization()
    
    try:
        # 1. Simulate user authentication (CAC/PIV)
        user_id = UUID("12345678-1234-5678-9012-123456789012")
        ip_address = "192.168.1.100"
        user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        
        # 2. Create unified session
        session_id = await controller.session_manager.create_unified_session(
            user_id=user_id,
            ip_address=ip_address,
            user_agent=user_agent,
            authentication_methods=["CAC", "PIV"]
        )
        
        logger.info(f"Created unified session: {session_id}")
        
        # 3. Add platform sessions (simulate OAuth flows)
        await controller.session_manager.add_platform_session(
            unified_session_id=session_id,
            platform="qlik",
            platform_session_id="qlik-session-123",
            oauth_token="qlik-access-token-xyz",
            oauth_expires_at=datetime.now(timezone.utc).replace(hour=23, minute=59),
            platform_attributes={
                "workspace": "analytics",
                "tenant": "organization-alpha"
            }
        )
        
        await controller.session_manager.add_platform_session(
            unified_session_id=session_id,
            platform="databricks",
            platform_session_id="databricks-session-456",
            oauth_token="databricks-access-token-abc",
            oauth_expires_at=datetime.now(timezone.utc).replace(hour=23, minute=59),
            platform_attributes={
                "workspace_id": "12345",
                "cluster_id": "cluster-67890"
            }
        )
        
        logger.info("Added platform sessions for Qlik and Databricks")
        
        # 4. Get session information
        session_info = await controller.session_manager.get_session_info(session_id)
        logger.info(f"Session active platforms: {session_info['active_platforms']}")
        
        return controller, session_id, user_id
        
    except Exception as e:
        logger.error(f"Authentication example failed: {e}")
        await controller.shutdown()
        raise


async def example_access_control_decisions():
    """Example: Cross-platform access control decisions."""
    logger.info("=== Access Control Decisions Example ===")
    
    controller, session_id, user_id = await example_user_authentication_and_context()
    
    try:
        # Test Case 1: Direct RBAC access
        logger.info("--- Test Case 1: Direct RBAC Access ---")
        
        rbac_request = UnifiedAccessRequest(
            user_id=user_id,
            resource_type="dashboard",
            action="read",
            session_id=session_id,
            ip_address="192.168.1.100"
        )
        
        rbac_response = await controller.check_access(rbac_request)
        logger.info(f"RBAC Decision: {rbac_response.decision.value} - {rbac_response.reason}")
        logger.info(f"Response time: {rbac_response.response_time_ms:.2f}ms")
        
        # Test Case 2: Platform OAuth access
        logger.info("--- Test Case 2: Platform OAuth Access ---")
        
        oauth_request = UnifiedAccessRequest(
            user_id=user_id,
            resource_type="dataset",
            action="write",
            platform="qlik",
            oauth_scopes=["qlik:read", "qlik:write"],
            session_id=session_id,
            ip_address="192.168.1.100"
        )
        
        oauth_response = await controller.check_access(oauth_request)
        logger.info(f"OAuth Decision: {oauth_response.decision.value} - {oauth_response.reason}")
        logger.info(f"OAuth scopes granted: {oauth_response.oauth_scopes_granted}")
        logger.info(f"Response time: {oauth_response.response_time_ms:.2f}ms")
        
        # Test Case 3: Cross-platform access
        logger.info("--- Test Case 3: Cross-Platform Access ---")
        
        cross_platform_request = UnifiedAccessRequest(
            user_id=user_id,
            resource_type="notebook",
            action="execute",
            platform="databricks",
            classification_level="C",  # Confidential
            session_id=session_id,
            ip_address="192.168.1.100"
        )
        
        cross_platform_response = await controller.check_access(cross_platform_request)
        logger.info(f"Cross-platform Decision: {cross_platform_response.decision.value} - {cross_platform_response.reason}")
        logger.info(f"Classification verified: {cross_platform_response.clearance_verified}")
        logger.info(f"Response time: {cross_platform_response.response_time_ms:.2f}ms")
        
        # Test Case 4: Emergency access
        logger.info("--- Test Case 4: Emergency Access ---")
        
        emergency_request = UnifiedAccessRequest(
            user_id=user_id,
            resource_type="system",
            action="admin",
            emergency_access=True,
            session_id=session_id,
            ip_address="192.168.1.100",
            additional_attributes={
                "emergency_reason": "Critical system maintenance required"
            }
        )
        
        emergency_response = await controller.check_access(emergency_request)
        logger.info(f"Emergency Decision: {emergency_response.decision.value} - {emergency_response.reason}")
        logger.info(f"Emergency override: {emergency_response.emergency_override}")
        logger.info(f"Response time: {emergency_response.response_time_ms:.2f}ms")
        
        return controller, session_id, user_id
        
    except Exception as e:
        logger.error(f"Access control example failed: {e}")
        await controller.shutdown()
        raise


async def example_session_management():
    """Example: Session management and synchronization."""
    logger.info("=== Session Management Example ===")
    
    controller, session_id, user_id = await example_access_control_decisions()
    
    try:
        # 1. Update session activity
        await controller.session_manager.update_session_access(
            unified_session_id=session_id,
            platform="qlik", 
            resource_type="dashboard",
            action="view"
        )
        
        logger.info("Updated session activity for Qlik platform")
        
        # 2. Get user sessions
        user_sessions = await controller.session_manager.get_user_sessions(user_id)
        logger.info(f"User has {len(user_sessions)} active sessions")
        
        # 3. Session metrics
        session_metrics = controller.session_manager.get_metrics()
        logger.info(f"Session manager metrics: {session_metrics['session_manager']}")
        
        # 4. Remove platform session
        await controller.session_manager.remove_platform_session(
            unified_session_id=session_id,
            platform="databricks"
        )
        
        logger.info("Removed Databricks platform session")
        
        # 5. Get updated session info
        updated_session_info = await controller.session_manager.get_session_info(session_id)
        logger.info(f"Updated active platforms: {updated_session_info['active_platforms']}")
        
        return controller, session_id, user_id
        
    except Exception as e:
        logger.error(f"Session management example failed: {e}")
        await controller.shutdown()
        raise


async def example_audit_and_compliance():
    """Example: Audit logging and compliance reporting."""
    logger.info("=== Audit and Compliance Example ===")
    
    controller, session_id, user_id = await example_session_management()
    
    try:
        # 1. Generate some audit events
        await controller.audit_manager.log_authentication_event(
            user_id=user_id,
            method="CAC",
            success=True,
            ip_address="192.168.1.100",
            details={"certificate_serial": "123ABC456DEF"}
        )
        
        await controller.audit_manager.log_platform_access(
            user_id=user_id,
            platform="qlik",
            resource_type="dashboard",
            action="view",
            success=True,
            session_id=session_id
        )
        
        await controller.audit_manager.log_security_violation(
            violation_type="Unusual Access Pattern",
            user_id=user_id,
            ip_address="192.168.1.100",
            details={"pattern": "rapid_cross_platform_access", "count": 15}
        )
        
        logger.info("Generated sample audit events")
        
        # 2. Get audit metrics
        audit_metrics = controller.audit_manager.get_metrics()
        logger.info(f"Audit metrics: {audit_metrics['audit_integration']}")
        
        # 3. Search audit events (simulated)
        try:
            search_filters = {"user_id": str(user_id), "event_type": "platform_access"}
            start_date = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0)
            end_date = datetime.now(timezone.utc)
            
            audit_events = await controller.audit_manager.search_audit_events(
                filters=search_filters,
                start_date=start_date, 
                end_date=end_date,
                limit=100
            )
            
            logger.info(f"Found {len(audit_events)} audit events for user")
            
        except Exception as e:
            logger.warning(f"Audit search failed (expected in demo): {e}")
        
        # 4. Generate compliance report (simulated)
        try:
            from ..audit import ComplianceStandard
            
            compliance_report = await controller.audit_manager.generate_compliance_report(
                standard=ComplianceStandard.DOD_8500,
                start_date=datetime.now(timezone.utc).replace(day=1),
                end_date=datetime.now(timezone.utc)
            )
            
            logger.info(f"Generated compliance report: {compliance_report.get('summary', 'Report generated')}")
            
        except Exception as e:
            logger.warning(f"Compliance report failed (expected in demo): {e}")
        
        return controller, session_id, user_id
        
    except Exception as e:
        logger.error(f"Audit example failed: {e}")
        await controller.shutdown()
        raise


async def example_performance_monitoring():
    """Example: Performance monitoring and health checks."""
    logger.info("=== Performance Monitoring Example ===")
    
    controller, session_id, user_id = await example_audit_and_compliance()
    
    try:
        # 1. Get comprehensive performance metrics
        performance_metrics = controller.get_performance_metrics()
        
        logger.info("=== Performance Metrics ===")
        logger.info(f"Unified Access: {performance_metrics['unified_access']}")
        logger.info(f"RBAC Resolver: {performance_metrics['rbac_resolver']}")
        
        # 2. Perform health check
        health_status = await controller.health_check()
        
        logger.info("=== Health Check ===")
        logger.info(f"Overall Status: {health_status['status']}")
        logger.info(f"Failed Components: {health_status.get('failed_components', 'None')}")
        
        # 3. Check individual component health
        session_health = await controller.session_manager.health_check()
        audit_health = await controller.audit_manager.health_check()
        
        logger.info(f"Session Manager Health: {session_health['status']}")
        logger.info(f"Audit Manager Health: {audit_health['status']}")
        
        # 4. Test cache performance
        logger.info("=== Cache Performance Test ===")
        
        # Make multiple identical requests to test caching
        cache_test_request = UnifiedAccessRequest(
            user_id=user_id,
            resource_type="report",
            action="read",
            session_id=session_id,
            ip_address="192.168.1.100"
        )
        
        # First request (cache miss)
        start_time = asyncio.get_event_loop().time()
        response1 = await controller.check_access(cache_test_request)
        first_time = (asyncio.get_event_loop().time() - start_time) * 1000
        
        # Second request (cache hit)
        start_time = asyncio.get_event_loop().time()
        response2 = await controller.check_access(cache_test_request)
        second_time = (asyncio.get_event_loop().time() - start_time) * 1000
        
        logger.info(f"First request (cache miss): {first_time:.2f}ms")
        logger.info(f"Second request (cache hit): {second_time:.2f}ms")
        logger.info(f"Cache hit improvement: {((first_time - second_time) / first_time * 100):.1f}%")
        
        return controller, session_id, user_id
        
    except Exception as e:
        logger.error(f"Performance monitoring example failed: {e}")
        await controller.shutdown()
        raise


async def example_system_shutdown():
    """Example: Graceful system shutdown."""
    logger.info("=== System Shutdown Example ===")
    
    controller, session_id, user_id = await example_performance_monitoring()
    
    try:
        # 1. Terminate user session
        await controller.session_manager.terminate_session(
            unified_session_id=session_id,
            reason="user_logout"
        )
        
        logger.info("Terminated user session")
        
        # 2. Get final metrics
        final_metrics = controller.get_performance_metrics()
        logger.info(f"Final session count: {final_metrics['unified_access']['total_requests']}")
        
        # 3. Graceful shutdown
        await controller.shutdown()
        
        logger.info("Unified access control system shutdown complete")
        
    except Exception as e:
        logger.error(f"Shutdown example failed: {e}")
        raise


async def main():
    """Run all examples."""
    logger.info("Starting Unified Access Control System Examples")
    
    try:
        await example_system_shutdown()
        logger.info("All examples completed successfully!")
        
    except Exception as e:
        logger.error(f"Examples failed: {e}")
        raise


if __name__ == "__main__":
    # Run the examples
    asyncio.run(main())