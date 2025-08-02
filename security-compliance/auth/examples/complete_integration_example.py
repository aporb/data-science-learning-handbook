#!/usr/bin/env python3
"""
Complete CAC/PIV Integration Example
Demonstrates full integration across all supported platforms
"""

import os
import sys
import json
import time
import base64
import asyncio
from datetime import datetime, timezone
from typing import Dict, List, Optional

# Add the auth module to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cac_piv_integration import CACAuthenticationManager
from platform_config_manager import PlatformConfigManager
from platform_adapters import (
    PlatformConfig, AuthenticationStatus,
    AdvanaAuthAdapter, QlikAuthAdapter, 
    DatabricksAuthAdapter, NavyJupiterAuthAdapter
)
from api.auth_api import create_auth_app, AuthAPIConfig

class MultiPlatformCAC:
    """
    Multi-platform CAC/PIV authentication manager
    Demonstrates integration across all supported platforms
    """
    
    def __init__(self, config_dir: str = "./config"):
        """
        Initialize multi-platform CAC manager
        
        Args:
            config_dir: Configuration directory path
        """
        self.config_manager = PlatformConfigManager(config_dir)
        self.auth_manager = CACAuthenticationManager()
        self.platform_adapters = {}
        self.active_sessions = {}
        
        print("🔐 Initializing Multi-Platform CAC/PIV Authentication System")
        
        # Create default configurations if needed
        if not self.config_manager.list_platforms():
            print("📋 Creating default platform configurations...")
            self.config_manager.create_default_configs()
            self.config_manager.save_configurations()
        
        # Initialize platform adapters
        self._initialize_adapters()
    
    def _initialize_adapters(self):
        """Initialize all platform adapters"""
        platform_map = {
            "advana": AdvanaAuthAdapter,
            "qlik": QlikAuthAdapter,
            "databricks": DatabricksAuthAdapter,
            "navy_jupiter": NavyJupiterAuthAdapter
        }
        
        for platform_name in self.config_manager.list_platforms():
            try:
                config = self.config_manager.get_platform_config(platform_name)
                if config and platform_name in platform_map:
                    adapter_class = platform_map[platform_name]
                    self.platform_adapters[platform_name] = adapter_class(config)
                    print(f"✅ Initialized {platform_name} adapter")
            except Exception as e:
                print(f"❌ Failed to initialize {platform_name}: {e}")
    
    def demonstrate_full_workflow(self):
        """Demonstrate complete CAC authentication workflow"""
        print("\n🎯 Starting Complete CAC/PIV Authentication Demonstration")
        print("=" * 60)
        
        # Step 1: CAC Authentication
        print("\n1️⃣ CAC/PIV Card Authentication")
        credentials = self._demonstrate_cac_authentication()
        
        if not credentials:
            print("❌ CAC authentication failed. Cannot proceed.")
            return
        
        # Step 2: Platform Authentication
        print("\n2️⃣ Multi-Platform Authentication")
        self._demonstrate_platform_authentication(credentials)
        
        # Step 3: Platform Operations
        print("\n3️⃣ Platform-Specific Operations")
        self._demonstrate_platform_operations()
        
        # Step 4: Session Management
        print("\n4️⃣ Session Management")
        self._demonstrate_session_management()
        
        # Step 5: Cleanup
        print("\n5️⃣ Cleanup and Logout")
        self._demonstrate_cleanup()
        
        print("\n🎉 Complete workflow demonstration finished!")
    
    def _demonstrate_cac_authentication(self) -> Optional[object]:
        """Demonstrate CAC card authentication"""
        print("   🔌 Connecting to smart card...")
        
        # In a real implementation, this would prompt for PIN
        # For demo purposes, we'll simulate with a test PIN
        print("   🔑 Please enter your CAC PIN (demo mode: using test PIN)")
        
        try:
            # Simulate CAC authentication
            # In production, uncomment the following line:
            # credentials = self.auth_manager.authenticate_user(input("PIN: "))
            
            # For demo, create mock credentials
            credentials = self._create_mock_credentials()
            
            if credentials:
                print(f"   ✅ Authentication successful!")
                print(f"   👤 User: {credentials.get('name', 'Test User')}")
                print(f"   🆔 EDIPI: {credentials.get('edipi', '1234567890')}")
                print(f"   🏢 Organization: {credentials.get('organization', 'U.S. Department of Defense')}")
                print(f"   🔐 Clearance: {credentials.get('clearance_level', 'UNCLASSIFIED')}")
                return credentials
            else:
                print("   ❌ CAC authentication failed")
                return None
                
        except Exception as e:
            print(f"   ❌ CAC authentication error: {e}")
            return None
    
    def _create_mock_credentials(self) -> Dict:
        """Create mock credentials for demonstration"""
        return {
            'name': 'John A. Doe',
            'edipi': '1234567890',
            'email': 'john.doe@army.mil',
            'organization': 'U.S. Army',
            'clearance_level': 'SECRET',
            'certificate_data': b'mock_certificate_data',
            'subject_dn': 'CN=DOE.JOHN.A.1234567890,OU=USA,OU=PKI,OU=DoD,O=U.S. Government,C=US'
        }
    
    def _demonstrate_platform_authentication(self, credentials: Dict):
        """Demonstrate authentication across all platforms"""
        
        # Generate mock certificate data and signatures
        certificate_data = credentials['certificate_data']
        
        for platform_name, adapter in self.platform_adapters.items():
            print(f"\n   🚀 Authenticating with {platform_name.title()}...")
            
            try:
                # Generate challenge
                challenge = adapter._generate_challenge()
                
                # In production, this would be signed with the actual private key
                signature = self._create_mock_signature(challenge)
                
                # Platform-specific parameters
                additional_params = self._get_platform_params(platform_name, credentials)
                
                # Authenticate
                result = adapter.authenticate_with_cac(
                    certificate_data=certificate_data,
                    signature=signature,
                    challenge=challenge,
                    additional_params=additional_params
                )
                
                if result.status == AuthenticationStatus.SUCCESS:
                    print(f"   ✅ {platform_name.title()} authentication successful!")
                    print(f"      🎫 Session token: {result.session_token[:20]}...")
                    print(f"      👥 Roles: {', '.join(result.roles[:3])}...")
                    print(f"      🔑 Permissions: {len(result.permissions)} granted")
                    
                    # Store session for later use
                    self.active_sessions[platform_name] = {
                        'session_token': result.session_token,
                        'platform_token': result.platform_token,
                        'expires_at': result.session_expires,
                        'roles': result.roles,
                        'permissions': result.permissions,
                        'metadata': result.metadata
                    }
                    
                elif result.status == AuthenticationStatus.PENDING:
                    print(f"   ⏳ {platform_name.title()} requires additional authentication")
                    print(f"      📋 Details: {result.error_message}")
                    
                else:
                    print(f"   ❌ {platform_name.title()} authentication failed")
                    print(f"      ⚠️ Error: {result.error_message}")
                
            except Exception as e:
                print(f"   ❌ {platform_name.title()} authentication error: {e}")
    
    def _get_platform_params(self, platform_name: str, credentials: Dict) -> Dict:
        """Get platform-specific authentication parameters"""
        
        platform_params = {
            "advana": {
                "tenant_id": "demo-tenant",
                "environment": "demo",
                "classification_level": credentials.get('clearance_level', 'UNCLASSIFIED')
            },
            "qlik": {
                "virtual_proxy": "cac-demo",
                "qlik_domain": "demo.qlik.local",
                "target_app": "analytics-dashboard"
            },
            "databricks": {
                "workspace_id": "demo-workspace",
                "cluster_config": {
                    "cluster_name": f"demo-cluster-{credentials.get('edipi')}",
                    "num_workers": 2
                }
            },
            "navy_jupiter": {
                "command_code": "DEMO_CMD",
                "facility_code": "DEMO_FAC",
                "client_ip": "192.168.1.100",
                "workstation_id": "DEMO_WS001"
            }
        }
        
        return platform_params.get(platform_name, {})
    
    def _create_mock_signature(self, challenge: bytes) -> bytes:
        """Create mock signature for demonstration"""
        # In production, this would use the actual CAC private key
        import hashlib
        return hashlib.sha256(challenge + b"mock_private_key").digest()
    
    def _demonstrate_platform_operations(self):
        """Demonstrate platform-specific operations"""
        
        for platform_name, session_data in self.active_sessions.items():
            print(f"\n   🔧 Demonstrating {platform_name.title()} operations...")
            
            try:
                adapter = self.platform_adapters[platform_name]
                session_token = session_data['session_token']
                
                if platform_name == "advana":
                    self._demo_advana_operations(adapter, session_token)
                elif platform_name == "qlik":
                    self._demo_qlik_operations(adapter, session_token)
                elif platform_name == "databricks":
                    self._demo_databricks_operations(adapter, session_token)
                elif platform_name == "navy_jupiter":
                    self._demo_navy_jupiter_operations(adapter, session_token)
                    
            except Exception as e:
                print(f"      ❌ Error in {platform_name} operations: {e}")
    
    def _demo_advana_operations(self, adapter, session_token):
        """Demo Advana-specific operations"""
        print("      📊 Getting available datasets...")
        
        # Mock datasets response
        datasets = [
            {"name": "operational_data", "classification": "UNCLASSIFIED"},
            {"name": "intel_reports", "classification": "CONFIDENTIAL"},
            {"name": "logistics_data", "classification": "UNCLASSIFIED"}
        ]
        
        for dataset in datasets:
            print(f"         📁 {dataset['name']} ({dataset['classification']})")
        
        print("      🔍 Creating sample query...")
        query_config = {
            "name": "Demo Analytics Query",
            "sql": "SELECT COUNT(*) FROM operational_data WHERE date >= '2024-01-01'",
            "classification": "UNCLASSIFIED"
        }
        
        print(f"         ✅ Query '{query_config['name']}' configured")
    
    def _demo_qlik_operations(self, adapter, session_token):
        """Demo Qlik-specific operations"""
        print("      📱 Getting available Qlik apps...")
        
        # Mock apps response
        apps = [
            {"id": "app1", "name": "Executive Dashboard", "published": True},
            {"id": "app2", "name": "Operational Analytics", "published": True},
            {"id": "app3", "name": "Resource Planning", "published": False}
        ]
        
        for app in apps:
            status = "📊 Published" if app['published'] else "🔒 Private"
            print(f"         {status} {app['name']} (ID: {app['id']})")
        
        print("      🔗 Creating session URL...")
        session_url = f"https://qlik-demo.mil/hub?qlikTicket={session_token[:16]}..."
        print(f"         🌐 Access URL: {session_url}")
    
    def _demo_databricks_operations(self, adapter, session_token):
        """Demo Databricks-specific operations"""
        print("      🔥 Getting available clusters...")
        
        # Mock clusters response
        clusters = [
            {"cluster_id": "cluster1", "cluster_name": "analytics-cluster", "state": "RUNNING"},
            {"cluster_id": "cluster2", "cluster_name": "ml-training", "state": "TERMINATED"},
            {"cluster_id": "cluster3", "cluster_name": "data-processing", "state": "PENDING"}
        ]
        
        for cluster in clusters:
            status_emoji = {"RUNNING": "🟢", "TERMINATED": "🔴", "PENDING": "🟡"}.get(cluster['state'], "⚪")
            print(f"         {status_emoji} {cluster['cluster_name']} ({cluster['state']})")
        
        print("      📓 Setting up workspace...")
        workspace_path = "/Users/john.doe@army.mil"
        print(f"         📁 Workspace: {workspace_path}")
        print(f"         📝 Welcome notebook created")
    
    def _demo_navy_jupiter_operations(self, adapter, session_token):
        """Demo Navy Jupiter-specific operations"""
        print("      ⚓ Getting available Navy systems...")
        
        # Mock systems response
        systems = [
            {"name": "GCCS-M", "classification": "SECRET", "network": "SIPR"},
            {"name": "NMCI Portal", "classification": "UNCLASSIFIED", "network": "NIPR"},
            {"name": "Fleet Analytics", "classification": "CONFIDENTIAL", "network": "NIPR"}
        ]
        
        for system in systems:
            network_emoji = {"NIPR": "🌐", "SIPR": "🔒"}.get(system['network'], "❓")
            print(f"         {network_emoji} {system['name']} ({system['classification']})")
        
        print("      🛡️ Checking security context...")
        security_context = {
            "network": "NIPR",
            "classification": "UNCLASSIFIED", 
            "command": "DEMO_CMD",
            "facility": "DEMO_FAC"
        }
        print(f"         🏢 Command: {security_context['command']}")
        print(f"         🏭 Facility: {security_context['facility']}")
        print(f"         🔐 Max Classification: {security_context['classification']}")
    
    def _demonstrate_session_management(self):
        """Demonstrate session management capabilities"""
        
        print("   🕐 Checking session status...")
        
        active_count = 0
        for platform_name, session_data in self.active_sessions.items():
            try:
                adapter = self.platform_adapters[platform_name]
                session_token = session_data['session_token']
                
                # Check session validity
                is_valid = adapter.validate_session(session_token)
                
                if is_valid:
                    active_count += 1
                    expires_at = session_data.get('expires_at')
                    if expires_at:
                        print(f"      ✅ {platform_name.title()}: Active (expires {expires_at.strftime('%H:%M:%S')})")
                    else:
                        print(f"      ✅ {platform_name.title()}: Active")
                else:
                    print(f"      ❌ {platform_name.title()}: Invalid/Expired")
                    
            except Exception as e:
                print(f"      ⚠️ {platform_name.title()}: Check failed ({e})")
        
        print(f"   📊 Total active sessions: {active_count}/{len(self.active_sessions)}")
        
        # Demonstrate token refresh
        if active_count > 0:
            print("   🔄 Demonstrating token refresh...")
            first_platform = list(self.active_sessions.keys())[0]
            self._demonstrate_token_refresh(first_platform)
    
    def _demonstrate_token_refresh(self, platform_name: str):
        """Demonstrate token refresh for a platform"""
        try:
            adapter = self.platform_adapters[platform_name]
            session_data = self.active_sessions[platform_name]
            old_token = session_data['session_token']
            
            print(f"      🔄 Refreshing {platform_name.title()} token...")
            
            # Attempt token refresh
            refresh_result = adapter.refresh_token(old_token)
            
            if refresh_result.status == AuthenticationStatus.SUCCESS:
                print(f"      ✅ Token refreshed successfully")
                print(f"         🆔 New token: {refresh_result.session_token[:20]}...")
                
                # Update stored session
                session_data['session_token'] = refresh_result.session_token
                if refresh_result.session_expires:
                    session_data['expires_at'] = refresh_result.session_expires
                    
            else:
                print(f"      ❌ Token refresh failed: {refresh_result.error_message}")
                
        except Exception as e:
            print(f"      ⚠️ Token refresh error: {e}")
    
    def _demonstrate_cleanup(self):
        """Demonstrate proper cleanup and logout"""
        
        print("   🧹 Logging out from all platforms...")
        
        logout_count = 0
        for platform_name, session_data in self.active_sessions.items():
            try:
                adapter = self.platform_adapters[platform_name]
                session_token = session_data['session_token']
                
                # Logout from platform
                success = adapter.logout(session_token)
                
                if success:
                    logout_count += 1
                    print(f"      ✅ {platform_name.title()}: Logged out")
                else:
                    print(f"      ❌ {platform_name.title()}: Logout failed")
                    
            except Exception as e:
                print(f"      ⚠️ {platform_name.title()}: Logout error ({e})")
        
        print(f"   📊 Successfully logged out from {logout_count}/{len(self.active_sessions)} platforms")
        
        # Clear active sessions
        self.active_sessions.clear()
        
        # Cleanup CAC authentication
        print("   🔐 Cleaning up CAC authentication...")
        try:
            self.auth_manager.logout()
            print("      ✅ CAC session closed")
        except Exception as e:
            print(f"      ⚠️ CAC cleanup error: {e}")
        
        print("   🎯 Cleanup completed!")

def demonstrate_api_usage():
    """Demonstrate API usage"""
    print("\n🌐 API Usage Demonstration")
    print("=" * 40)
    
    # Create API configuration
    api_config = AuthAPIConfig()
    api_config.debug = True
    api_config.require_https = False
    
    # Create FastAPI app
    app = create_auth_app(api_config)
    
    print("✅ CAC/PIV Authentication API created")
    print(f"📍 API endpoints available at: http://localhost:{api_config.port}")
    print("📚 API documentation at: /docs")
    print("🔍 Health check at: /health")
    
    # Example API usage with requests
    print("\n📡 Example API calls:")
    print("""
    # Generate challenge
    POST /api/v1/auth/challenge
    {
        "platform": "advana",
        "client_info": {"ip": "192.168.1.1"}
    }
    
    # Authenticate
    POST /api/v1/auth/authenticate  
    {
        "certificate_data": "base64_encoded_cert",
        "signature": "base64_encoded_signature",
        "challenge": "base64_encoded_challenge",
        "platform": "advana",
        "additional_params": {"tenant_id": "your-tenant"}
    }
    
    # Get user info
    POST /api/v1/user/info
    {
        "session_token": "your_session_token",
        "platform": "advana"
    }
    """)

async def demonstrate_async_operations():
    """Demonstrate asynchronous operations"""
    print("\n⚡ Asynchronous Operations Demonstration")
    print("=" * 45)
    
    async def mock_platform_auth(platform_name: str, delay: float):
        """Mock asynchronous platform authentication"""
        print(f"   🚀 Starting {platform_name} authentication...")
        await asyncio.sleep(delay)  # Simulate network delay
        print(f"   ✅ {platform_name} authentication completed")
        return f"{platform_name}_session_token"
    
    # Simulate concurrent authentication across platforms
    platforms = [
        ("Advana", 1.5),
        ("Qlik", 2.0),
        ("Databricks", 1.8),
        ("Navy Jupiter", 2.2)
    ]
    
    print("   🔄 Authenticating with multiple platforms concurrently...")
    start_time = time.time()
    
    # Run concurrent authentications
    tasks = [mock_platform_auth(name, delay) for name, delay in platforms]
    results = await asyncio.gather(*tasks)
    
    end_time = time.time()
    
    print(f"   📊 All authentications completed in {end_time - start_time:.2f} seconds")
    print(f"   🎫 Generated {len(results)} session tokens")

def main():
    """Main demonstration function"""
    print("🎯 CAC/PIV Multi-Platform Integration Demonstration")
    print("=" * 60)
    print("This demonstration shows complete integration across:")
    print("  • CDAO Advana")
    print("  • Qlik Sense Enterprise") 
    print("  • Databricks")
    print("  • Navy Jupiter")
    print("=" * 60)
    
    try:
        # Initialize multi-platform CAC manager
        multi_cac = MultiPlatformCAC("./demo_config")
        
        # Run complete workflow demonstration
        multi_cac.demonstrate_full_workflow()
        
        # Demonstrate API usage
        demonstrate_api_usage()
        
        # Demonstrate async operations
        print("\n⚡ Running async demonstration...")
        asyncio.run(demonstrate_async_operations())
        
        print("\n🎉 All demonstrations completed successfully!")
        print("\n📚 Next steps:")
        print("  1. Review platform-specific integration guides")
        print("  2. Configure your platform connections")
        print("  3. Set up production security settings")
        print("  4. Deploy the authentication service")
        print("  5. Configure monitoring and audit logging")
        
    except KeyboardInterrupt:
        print("\n\n⚠️ Demonstration interrupted by user")
    except Exception as e:
        print(f"\n❌ Demonstration failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()