"""
Example Implementation - Complete Qlik OAuth 2.0 Integration
Demonstrates how to use the production-ready Qlik OAuth implementation
with CAC integration, Vault storage, and comprehensive audit logging.
"""

import asyncio
import logging
from typing import Dict, Any, Optional
from datetime import datetime, timezone

# Import the complete integration
from .complete_qlik_oauth_integration import (
    CompleteQlikOAuthIntegration,
    QlikIntegrationMode,
    QlikSessionContext
)
from .oauth_config import Environment
from .enhanced_qlik_oauth import QlikResourceType, QlikPermissionLevel

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class QlikOAuthIntegrationExample:
    """Example implementation showing complete Qlik OAuth integration usage."""
    
    def __init__(self):
        """Initialize the example integration."""
        # Initialize complete integration with production settings
        self.qlik_integration = CompleteQlikOAuthIntegration(
            environment=Environment.NIPR,  # Use appropriate environment
            default_integration_mode=QlikIntegrationMode.CAC_OAUTH_INTEGRATED,
            enable_vault_integration=True,
            enable_comprehensive_auditing=True
        )
        
        # Example configuration (in production, these would come from secure sources)
        self.example_config = {
            "client_id": "qlik-dod-analytics-platform",
            "client_secret": "secure-client-secret-from-vault",
            "redirect_uri": "https://analytics.dod.mil/oauth/callback",
            "qlik_base_url": "https://qlik.advana.data.mil",
            "scopes": [
                "qlik:basic_read",
                "qlik:app_create", 
                "qlik:space_manage",
                "qlik:data_connection"
            ]
        }
    
    async def setup_qlik_platform(self) -> bool:
        """
        Set up Qlik platform configuration.
        
        Returns:
            True if setup successful
        """
        try:
            logger.info("Setting up Qlik platform configuration...")
            
            # Configure Qlik platform
            success = self.qlik_integration.configure_qlik_platform(
                client_id=self.example_config["client_id"],
                client_secret=self.example_config["client_secret"],
                redirect_uri=self.example_config["redirect_uri"],
                scopes=self.example_config["scopes"],
                qlik_config={
                    "qlik_domain": "qlik.advana.data.mil",
                    "virtual_proxy": "",
                    "app_access_point": "/hub",
                    "certificate_header": "X-Qlik-User"
                }
            )
            
            if success:
                logger.info("Qlik platform configured successfully")
                return True
            else:
                logger.error("Failed to configure Qlik platform")
                return False
                
        except Exception as e:
            logger.error(f"Setup failed: {e}")
            return False
    
    async def demonstrate_integrated_authentication(self, cac_pin: str) -> Optional[QlikSessionContext]:
        """
        Demonstrate complete integrated CAC-OAuth authentication flow.
        
        Args:
            cac_pin: CAC PIN for authentication
            
        Returns:
            Complete session context if successful
        """
        try:
            logger.info("Starting integrated CAC-OAuth authentication...")
            
            # Step 1: Start integrated authentication
            success, oauth_url, session_context = self.qlik_integration.start_integrated_authentication(
                cac_pin=cac_pin,
                client_id=self.example_config["client_id"],
                required_clearance="SECRET",
                integration_mode=QlikIntegrationMode.CAC_OAUTH_INTEGRATED
            )
            
            if not success:
                logger.error(f"Failed to start authentication: {session_context}")
                return None
            
            logger.info(f"Authentication started successfully")
            logger.info(f"OAuth URL: {oauth_url}")
            logger.info(f"User EDIPI: {session_context['cac_credentials'].edipi}")
            logger.info(f"Clearance Level: {session_context['cac_credentials'].clearance_level}")
            
            # In a real implementation, the user would be redirected to oauth_url
            # and the authorization code would be received via the callback
            # For this example, we'll simulate the OAuth callback
            
            # Step 2: Simulate OAuth callback (in production, this comes from the redirect)
            authorization_code = "simulated_auth_code_12345"
            state = session_context["oauth_state"]
            
            # Step 3: Complete authentication
            success, complete_session = self.qlik_integration.complete_integrated_authentication(
                authorization_code=authorization_code,
                state=state,
                session_context=session_context
            )
            
            if not success:
                logger.error("Failed to complete authentication")
                return None
            
            logger.info("Integrated authentication completed successfully!")
            logger.info(f"Session ID: {complete_session.session_id}")
            logger.info(f"Qlik Session URL: {complete_session.qlik_session_url}")
            logger.info(f"Session expires at: {complete_session.expires_at}")
            logger.info(f"Binding ID: {complete_session.cac_binding.binding_id}")
            logger.info(f"Binding Strength: {complete_session.cac_binding.binding_strength.value}")
            
            return complete_session
            
        except Exception as e:
            logger.error(f"Authentication failed: {e}")
            return None
    
    async def demonstrate_resource_access_control(self, session_context: QlikSessionContext):
        """
        Demonstrate resource access control with permission checking.
        
        Args:
            session_context: Active session context
        """
        try:
            logger.info("Demonstrating resource access control...")
            
            # Example resources to test
            test_resources = [
                {
                    "resource_id": "app_001_financial_analytics",
                    "resource_type": QlikResourceType.APP,
                    "permission": "READ",
                    "context": "normal"
                },
                {
                    "resource_id": "app_002_classified_intel",
                    "resource_type": QlikResourceType.APP,
                    "permission": "UPDATE",
                    "context": "normal"
                },
                {
                    "resource_id": "space_001_executive_dashboards",
                    "resource_type": QlikResourceType.SPACE,
                    "permission": "ADMIN",
                    "context": "administrative"
                },
                {
                    "resource_id": "connection_001_classified_db",
                    "resource_type": QlikResourceType.DATA_CONNECTION,
                    "permission": "CREATE",
                    "context": "development"
                }
            ]
            
            # First, register example resources
            for resource in test_resources:
                self.qlik_integration.permission_mapper.register_resource(
                    resource_id=resource["resource_id"],
                    resource_type=resource["resource_type"],
                    resource_name=resource["resource_id"].replace("_", " ").title(),
                    metadata={
                        "classification": session_context.cac_credentials.clearance_level,
                        "owner_edipi": session_context.user_id,
                        "created_at": datetime.now(timezone.utc).isoformat()
                    }
                )
            
            logger.info(f"Registered {len(test_resources)} test resources")
            
            # Test access for each resource
            for resource in test_resources:
                access_granted, access_details = self.qlik_integration.check_resource_access(
                    session_id=session_context.session_id,
                    resource_id=resource["resource_id"],
                    permission=resource["permission"],
                    context=resource["context"]
                )
                
                logger.info(f"Resource: {resource['resource_id']}")
                logger.info(f"  Permission: {resource['permission']}")
                logger.info(f"  Context: {resource['context']}")
                logger.info(f"  Access Granted: {access_granted}")
                logger.info(f"  Details: {access_details}")
                logger.info("")
            
            # Get list of accessible resources
            accessible_resources = self.qlik_integration.permission_mapper.get_user_accessible_resources(
                edipi=session_context.user_id,
                permission=QlikPermissionLevel.READ
            )
            
            logger.info(f"User has READ access to {len(accessible_resources)} resources:")
            for resource in accessible_resources:
                logger.info(f"  - {resource['resource_name']} ({resource['resource_type']})")
            
        except Exception as e:
            logger.error(f"Resource access demonstration failed: {e}")
    
    async def demonstrate_session_management(self, session_context: QlikSessionContext):
        """
        Demonstrate session management capabilities.
        
        Args:
            session_context: Active session context
        """
        try:
            logger.info("Demonstrating session management...")
            
            # Get session info
            session_info = self.qlik_integration.get_session_info(session_context.session_id)
            logger.info(f"Session Info: {session_info}")
            
            # Refresh session
            refresh_success = self.qlik_integration.refresh_session(session_context.session_id)
            logger.info(f"Session refresh successful: {refresh_success}")
            
            # Get updated session info
            updated_session_info = self.qlik_integration.get_session_info(session_context.session_id)
            logger.info(f"Updated Session Info: {updated_session_info}")
            
            # Simulate some activity
            logger.info("Simulating user activity...")
            
            # Check multiple resources to generate audit trails
            for i in range(5):
                resource_id = f"test_resource_{i:03d}"
                access_granted, _ = self.qlik_integration.check_resource_access(
                    session_id=session_context.session_id,
                    resource_id=resource_id,
                    permission="READ",
                    context="normal"
                )
                logger.info(f"Access check {i+1}: {resource_id} - {access_granted}")
            
        except Exception as e:
            logger.error(f"Session management demonstration failed: {e}")
    
    async def demonstrate_system_monitoring(self):
        """Demonstrate system health monitoring and statistics."""
        try:
            logger.info("Demonstrating system monitoring...")
            
            # Get system health
            health_status = self.qlik_integration.get_system_health()
            logger.info("System Health Status:")
            logger.info(f"  Overall Status: {health_status.get('status')}")
            logger.info(f"  Active Sessions: {health_status.get('active_sessions')}")
            logger.info(f"  Configured Clients: {health_status.get('configured_clients')}")
            logger.info(f"  Vault Integration: {health_status.get('vault_integration_enabled')}")
            logger.info(f"  Comprehensive Auditing: {health_status.get('comprehensive_auditing_enabled')}")
            
            # Error statistics
            error_stats = health_status.get('error_statistics', {})
            logger.info(f"  Total Errors (24h): {error_stats.get('total_errors', 0)}")
            logger.info(f"  Recovery Success Rate: {error_stats.get('recovery_success_rate', 0):.2%}")
            
            # Vault statistics
            vault_stats = health_status.get('vault_statistics', {})
            if vault_stats:
                logger.info(f"  Vault Total Secrets: {vault_stats.get('total_secrets', 0)}")
                logger.info(f"  Vault Secrets Expiring Soon: {vault_stats.get('expiring_soon', 0)}")
            
            # Cleanup expired resources
            cleanup_count = self.qlik_integration.cleanup_expired_sessions()
            logger.info(f"Cleaned up {cleanup_count} expired resources")
            
        except Exception as e:
            logger.error(f"System monitoring demonstration failed: {e}")
    
    async def run_complete_demonstration(self, cac_pin: str):
        """
        Run complete demonstration of all features.
        
        Args:
            cac_pin: CAC PIN for authentication
        """
        try:
            logger.info("=" * 60)
            logger.info("COMPLETE QLIK OAUTH INTEGRATION DEMONSTRATION")
            logger.info("=" * 60)
            
            # Step 1: Setup
            logger.info("\n1. Setting up Qlik platform...")
            setup_success = await self.setup_qlik_platform()
            if not setup_success:
                logger.error("Setup failed, aborting demonstration")
                return
            
            # Step 2: Authentication
            logger.info("\n2. Performing integrated authentication...")
            session_context = await self.demonstrate_integrated_authentication(cac_pin)
            if not session_context:
                logger.error("Authentication failed, aborting demonstration")
                return
            
            # Step 3: Resource Access Control
            logger.info("\n3. Testing resource access control...")
            await self.demonstrate_resource_access_control(session_context)
            
            # Step 4: Session Management
            logger.info("\n4. Demonstrating session management...")
            await self.demonstrate_session_management(session_context)
            
            # Step 5: System Monitoring
            logger.info("\n5. Checking system health and monitoring...")
            await self.demonstrate_system_monitoring()
            
            # Step 6: Cleanup
            logger.info("\n6. Cleaning up session...")
            cleanup_success = self.qlik_integration.invalidate_session(session_context.session_id)
            logger.info(f"Session cleanup successful: {cleanup_success}")
            
            logger.info("\n" + "=" * 60)
            logger.info("DEMONSTRATION COMPLETED SUCCESSFULLY!")
            logger.info("=" * 60)
            
        except Exception as e:
            logger.error(f"Demonstration failed: {e}")


async def main():
    """Main example function."""
    # Create example instance
    example = QlikOAuthIntegrationExample()
    
    # NOTE: In production, CAC PIN would come from secure user input
    # This is just for demonstration purposes
    simulated_cac_pin = "123456"  # Replace with actual CAC PIN in real usage
    
    # Run complete demonstration
    await example.run_complete_demonstration(simulated_cac_pin)


if __name__ == "__main__":
    # Run the example
    asyncio.run(main())