#!/usr/bin/env python3
"""
Platform-Specific CAC/PIV Integration Examples
Individual examples for each supported platform
"""

import os
import sys
import json
import base64
from datetime import datetime, timezone

# Add the auth module to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from platform_adapters import *
from cac_piv_integration import CACAuthenticationManager

class AdvanaExample:
    """Complete Advana integration example"""
    
    def __init__(self):
        self.setup_advana_config()
    
    def setup_advana_config(self):
        """Set up Advana configuration"""
        print("🚀 Setting up Advana CAC/PIV Integration")
        
        self.config = PlatformConfig(
            platform_name="advana",
            base_url="https://advana.data.mil",
            api_version="v1",
            authentication_endpoint="/api/v1/auth/cac",
            token_endpoint="/api/v1/auth/token",
            user_info_endpoint="/api/v1/user/profile",
            timeout=30,
            max_retries=3,
            verify_ssl=True,
            additional_config={
                "tenant_id": os.getenv("ADVANA_TENANT_ID", "demo-tenant"),
                "environment": os.getenv("ADVANA_ENV", "prod"),
                "classification_level": "UNCLASSIFIED"
            }
        )
        
        self.adapter = AdvanaAuthAdapter(self.config)
        print("✅ Advana adapter initialized")
    
    def authenticate_user(self, pin: str = None):
        """Authenticate user with Advana"""
        print("\n📋 Starting Advana Authentication Process")
        
        # Initialize CAC authentication
        auth_manager = CACAuthenticationManager()
        
        # Authenticate with CAC card
        if pin:
            credentials = auth_manager.authenticate_user(pin)
        else:
            print("🔑 Please insert CAC card and enter PIN")
            credentials = auth_manager.authenticate_user(input("PIN: "))
        
        if not credentials:
            print("❌ CAC authentication failed")
            return None
        
        print(f"✅ CAC authentication successful for {credentials.edipi}")
        
        # Extract certificate data
        certificate_data = credentials.certificate.public_bytes(serialization.Encoding.DER)
        
        # Generate challenge and sign it
        challenge = self.adapter._generate_challenge()
        signature = auth_manager.authenticator.sign_data(challenge)
        
        # Authenticate with Advana
        result = self.adapter.authenticate_with_cac(
            certificate_data=certificate_data,
            signature=signature,
            challenge=challenge,
            additional_params={
                "tenant_id": self.config.additional_config["tenant_id"],
                "user_preferences": {
                    "theme": "dark",
                    "timezone": "America/New_York"
                }
            }
        )
        
        if result.status == AuthenticationStatus.SUCCESS:
            print("🎉 Advana authentication successful!")
            print(f"   📧 User: {result.user_id}")
            print(f"   🎫 Session Token: {result.session_token[:20]}...")
            print(f"   🏷️ Roles: {', '.join(result.roles)}")
            print(f"   ⏰ Expires: {result.session_expires}")
            
            self.session_token = result.session_token
            return result
        else:
            print(f"❌ Advana authentication failed: {result.error_message}")
            return None
    
    def demonstrate_data_access(self):
        """Demonstrate Advana data access"""
        if not hasattr(self, 'session_token'):
            print("❌ No active session. Please authenticate first.")
            return
        
        print("\n📊 Demonstrating Advana Data Access")
        
        # Get available datasets
        print("   🔍 Fetching available datasets...")
        datasets = self.adapter.get_advana_datasets(
            session_token=self.session_token,
            classification_level="UNCLASSIFIED"
        )
        
        if datasets:
            print(f"   📁 Found {len(datasets)} datasets:")
            for dataset in datasets[:5]:  # Show first 5
                print(f"      • {dataset.get('name', 'Unknown')} ({dataset.get('size', 'Unknown size')})")
        else:
            print("   📁 No datasets available or access denied")
        
        # Create a sample query
        print("   📝 Creating sample analytics query...")
        query_config = {
            "name": "CAC User Analytics Query",
            "description": "Sample query for CAC authenticated user",
            "sql": """
                SELECT 
                    category,
                    COUNT(*) as record_count,
                    AVG(value) as avg_value
                FROM public_datasets.sample_data 
                WHERE date_created >= '2024-01-01'
                GROUP BY category
                ORDER BY record_count DESC
                LIMIT 10
            """,
            "classification": "UNCLASSIFIED",
            "output_format": "csv",
            "schedule": "daily"
        }
        
        query_id = self.adapter.create_advana_query(
            session_token=self.session_token,
            query_config=query_config
        )
        
        if query_id:
            print(f"   ✅ Query created with ID: {query_id}")
            print(f"   🔗 Query URL: {self.config.base_url}/queries/{query_id}")
        else:
            print("   ❌ Failed to create query")
    
    def demonstrate_collaboration(self):
        """Demonstrate Advana collaboration features"""
        if not hasattr(self, 'session_token'):
            print("❌ No active session. Please authenticate first.")
            return
        
        print("\n🤝 Demonstrating Advana Collaboration")
        
        # Get user profile
        user_info = self.adapter.get_user_info(self.session_token)
        if user_info:
            print(f"   👤 User Profile: {user_info.get('name', 'Unknown')}")
            print(f"   🏢 Organization: {user_info.get('organization', 'Unknown')}")
            print(f"   🔐 Clearance: {user_info.get('clearance_level', 'Unknown')}")
        
        # Example: Share analysis with team
        sharing_config = {
            "resource_type": "query",
            "resource_id": "sample_query_123",
            "shared_with": [
                {"type": "user", "email": "colleague@army.mil"},
                {"type": "group", "name": "analytics_team"},
                {"type": "organization", "name": "U.S. Army"}
            ],
            "permissions": ["read", "execute"],
            "expiration_date": (datetime.now() + timedelta(days=30)).isoformat(),
            "message": "Sharing analytics query for team collaboration"
        }
        
        print("   📤 Sharing analysis with team members...")
        print(f"      👥 Shared with: {len(sharing_config['shared_with'])} recipients")
        print(f"      🔑 Permissions: {', '.join(sharing_config['permissions'])}")
        print(f"      ⏰ Expires: {sharing_config['expiration_date']}")

class QlikExample:
    """Complete Qlik Sense integration example"""
    
    def __init__(self):
        self.setup_qlik_config()
    
    def setup_qlik_config(self):
        """Set up Qlik configuration"""
        print("🎯 Setting up Qlik Sense CAC/PIV Integration")
        
        self.config = PlatformConfig(
            platform_name="qlik",
            base_url="https://qlik-server.mil",
            api_version="v1",
            authentication_endpoint="/api/v1/auth/certificate",
            token_endpoint="/api/v1/auth/jwt",
            user_info_endpoint="/api/v1/users/me",
            timeout=30,
            verify_ssl=True,
            additional_config={
                "qlik_domain": "qlik.mil",
                "virtual_proxy": "cac",
                "app_access_point": "/hub",
                "certificate_header": "X-Qlik-User",
                "jwt_secret": os.getenv("QLIK_JWT_SECRET", "demo-secret-key"),
                "jwt_algorithm": "HS256"
            }
        )
        
        self.adapter = QlikAuthAdapter(self.config)
        print("✅ Qlik adapter initialized")
    
    def authenticate_and_create_session(self):
        """Authenticate and create Qlik session"""
        print("\n🔐 Starting Qlik Authentication Process")
        
        # Mock certificate data for demo
        mock_cert_data = self._create_mock_certificate()
        challenge = b"qlik_challenge_data"
        signature = b"mock_signature"
        
        result = self.adapter.authenticate_with_cac(
            certificate_data=mock_cert_data,
            signature=signature,
            challenge=challenge,
            additional_params={
                "virtual_proxy": "cac",
                "target_app": "executive-dashboard"
            }
        )
        
        if result.status == AuthenticationStatus.SUCCESS:
            print("🎉 Qlik authentication successful!")
            print(f"   🎫 Session Token: {result.session_token[:20]}...")
            print(f"   🎟️ Qlik Ticket: {result.platform_token[:20]}...")
            
            self.session_token = result.session_token
            self.qlik_ticket = result.platform_token
            
            # Create session URL
            session_url = self.adapter.create_qlik_session_url(
                session_token=result.platform_token,
                app_id="executive-dashboard"
            )
            
            print(f"   🔗 Access URL: {session_url}")
            return result
        else:
            print(f"❌ Qlik authentication failed: {result.error_message}")
            return None
    
    def demonstrate_app_access(self):
        """Demonstrate Qlik app access"""
        if not hasattr(self, 'session_token'):
            print("❌ No active session. Please authenticate first.")
            return
        
        print("\n📱 Demonstrating Qlik App Access")
        
        # Get available apps
        apps = self.adapter.get_qlik_apps(self.session_token)
        
        if apps:
            print(f"   📊 Available Apps ({len(apps)}):")
            for app in apps:
                status = "🟢 Published" if app.get('published') else "🟡 Personal"
                print(f"      {status} {app.get('name', 'Unknown')} (ID: {app.get('id', 'Unknown')})")
                
                # Show app details
                if app.get('description'):
                    print(f"         📝 {app['description']}")
                if app.get('last_reload_time'):
                    print(f"         🕐 Last updated: {app['last_reload_time']}")
        else:
            print("   📊 No apps available")
        
        # Demonstrate app selection and URL generation
        if apps:
            selected_app = apps[0]
            app_url = self.adapter.create_qlik_session_url(
                session_token=self.qlik_ticket,
                app_id=selected_app.get('id')
            )
            
            print(f"\n   🎯 Selected App: {selected_app.get('name')}")
            print(f"   🔗 Direct Access URL: {app_url}")
    
    def demonstrate_custom_visualization(self):
        """Demonstrate custom Qlik visualization setup"""
        print("\n📈 Setting up Custom Qlik Visualizations")
        
        # Example: Create custom mashup configuration
        mashup_config = {
            "app_id": "executive-dashboard",
            "objects": [
                {
                    "id": "kpi-overview",
                    "type": "kpi",
                    "title": "Mission Readiness KPIs",
                    "measures": ["ReadinessScore", "EquipmentStatus", "PersonnelCount"],
                    "dimensions": ["Unit", "Location"]
                },
                {
                    "id": "trend-chart",
                    "type": "line-chart", 
                    "title": "Operational Trends",
                    "measures": ["OperationalEfficiency"],
                    "dimensions": ["Date"]
                },
                {
                    "id": "geographic-view",
                    "type": "map",
                    "title": "Global Operations Map",
                    "layers": ["Bases", "Missions", "Assets"]
                }
            ],
            "security": {
                "data_reduction": True,
                "section_access": "UNIT_BASED",
                "classification_filtering": "AUTO"
            }
        }
        
        print("   🎨 Custom Mashup Configuration:")
        for obj in mashup_config["objects"]:
            print(f"      📊 {obj['title']} ({obj['type']})")
        
        print(f"   🔒 Security: {mashup_config['security']['section_access']}")
        print(f"   🏷️ Classification Filtering: {mashup_config['security']['classification_filtering']}")
    
    def _create_mock_certificate(self):
        """Create mock certificate data for demo"""
        return b"mock_qlik_certificate_data"

class DatabricksExample:
    """Complete Databricks integration example"""
    
    def __init__(self):
        self.setup_databricks_config()
    
    def setup_databricks_config(self):
        """Set up Databricks configuration"""
        print("⚡ Setting up Databricks CAC/PIV Integration")
        
        self.config = PlatformConfig(
            platform_name="databricks",
            base_url="https://demo-workspace.cloud.databricks.com",
            api_version="2.0",
            authentication_endpoint="/api/2.0/preview/scim/v2/Users",
            token_endpoint="/api/2.0/token/create",
            user_info_endpoint="/api/2.0/preview/scim/v2/Me",
            timeout=30,
            verify_ssl=True,
            additional_config={
                "workspace_id": "demo-workspace-123",
                "workspace_url": "https://demo-workspace.cloud.databricks.com",
                "instance_pool_id": "demo-pool-456",
                "cluster_policy_id": "demo-policy-789",
                "auth_method": "personal_access_token",
                "service_principal_id": os.getenv("DATABRICKS_SERVICE_PRINCIPAL_ID")
            }
        )
        
        self.adapter = DatabricksAuthAdapter(self.config)
        print("✅ Databricks adapter initialized")
    
    def authenticate_and_setup_user(self):
        """Authenticate and set up Databricks user"""
        print("\n🚀 Starting Databricks User Setup")
        
        # Mock authentication for demo
        mock_cert_data = b"mock_databricks_certificate"
        challenge = b"databricks_challenge"
        signature = b"mock_signature"
        
        result = self.adapter.authenticate_with_cac(
            certificate_data=mock_cert_data,
            signature=signature,
            challenge=challenge,
            additional_params={
                "workspace_id": self.config.additional_config["workspace_id"],
                "user_groups": ["data-scientists", "army-users"],
                "workspace_preferences": {
                    "default_catalog": "army_data",
                    "default_schema": "analytics"
                }
            }
        )
        
        if result.status == AuthenticationStatus.SUCCESS:
            print("🎉 Databricks authentication successful!")
            print(f"   👤 User ID: {result.user_id}")
            print(f"   🔑 Personal Access Token: {result.session_token[:20]}...")
            print(f"   👥 Groups: {', '.join(result.roles)}")
            
            self.access_token = result.session_token
            self.user_id = result.user_id
            return result
        else:
            print(f"❌ Databricks authentication failed: {result.error_message}")
            return None
    
    def demonstrate_cluster_management(self):
        """Demonstrate Databricks cluster management"""
        if not hasattr(self, 'access_token'):
            print("❌ No access token. Please authenticate first.")
            return
        
        print("\n🔥 Demonstrating Databricks Cluster Management")
        
        # Get existing clusters
        clusters = self.adapter.get_databricks_clusters(self.access_token)
        
        if clusters:
            print(f"   📋 Existing Clusters ({len(clusters)}):")
            for cluster in clusters:
                state_emoji = {
                    "RUNNING": "🟢",
                    "TERMINATED": "🔴", 
                    "PENDING": "🟡",
                    "TERMINATING": "🟠"
                }.get(cluster.get('state', 'UNKNOWN'), "⚪")
                
                print(f"      {state_emoji} {cluster.get('cluster_name', 'Unknown')} ({cluster.get('state', 'Unknown')})")
                if cluster.get('spark_version'):
                    print(f"         ⚡ Spark: {cluster['spark_version']}")
                if cluster.get('num_workers'):
                    print(f"         👥 Workers: {cluster['num_workers']}")
        
        # Create a new secure cluster
        print("\n   🔧 Creating new secure cluster...")
        cluster_config = {
            "cluster_name": f"CAC-Analytics-{datetime.now().strftime('%Y%m%d%H%M')}",
            "spark_version": "13.3.x-scala2.12",
            "node_type_id": "i3.xlarge",
            "num_workers": 2,
            "autotermination_minutes": 60,
            "enable_elastic_disk": True,
            "enable_local_disk_encryption": True,
            "spark_conf": {
                "spark.databricks.cluster.profile": "serverless",
                "spark.databricks.acl.dfAclsEnabled": "true",
                "spark.sql.adaptive.enabled": "true",
                "spark.sql.adaptive.coalescePartitions.enabled": "true"
            },
            "custom_tags": {
                "Environment": "Production",
                "Classification": "UNCLASSIFIED",
                "Owner": "cac-user",
                "Department": "Analytics",
                "AutoTerminate": "true"
            }
        }
        
        cluster_id = self.adapter.create_databricks_cluster(
            session_token=self.access_token,
            cluster_config=cluster_config
        )
        
        if cluster_id:
            print(f"   ✅ Cluster created: {cluster_id}")
            print(f"   🏷️ Name: {cluster_config['cluster_name']}")
            print(f"   ⚡ Spark Version: {cluster_config['spark_version']}")
            print(f"   👥 Workers: {cluster_config['num_workers']}")
            print(f"   ⏰ Auto-terminate: {cluster_config['autotermination_minutes']} minutes")
        else:
            print("   ❌ Failed to create cluster")
    
    def demonstrate_notebook_setup(self):
        """Demonstrate notebook workspace setup"""
        print("\n📓 Setting up Databricks Workspace")
        
        # Create workspace structure
        workspace_structure = {
            "base_path": f"/Users/{self.user_id}",
            "folders": [
                "01-Data-Exploration",
                "02-Feature-Engineering", 
                "03-Model-Training",
                "04-Model-Deployment",
                "99-Utilities"
            ],
            "sample_notebooks": [
                {
                    "path": "01-Data-Exploration/Welcome.py",
                    "content": self._create_welcome_notebook_content()
                },
                {
                    "path": "99-Utilities/CAC-User-Setup.py",
                    "content": self._create_setup_notebook_content()
                }
            ]
        }
        
        print(f"   📁 Base Path: {workspace_structure['base_path']}")
        print("   📂 Folder Structure:")
        for folder in workspace_structure["folders"]:
            print(f"      📁 {folder}")
        
        print("   📝 Sample Notebooks:")
        for notebook in workspace_structure["sample_notebooks"]:
            print(f"      📄 {notebook['path']}")
        
        print("\n   🔗 Workspace URL:")
        workspace_url = f"{self.config.base_url}/#workspace{workspace_structure['base_path']}"
        print(f"      {workspace_url}")
    
    def demonstrate_mlflow_integration(self):
        """Demonstrate MLflow integration"""
        print("\n🧪 Setting up MLflow Integration")
        
        mlflow_config = {
            "experiment_name": f"/Users/{self.user_id}/CAC-ML-Experiments",
            "tracking_uri": f"{self.config.base_url}",
            "artifact_location": f"dbfs:/Users/{self.user_id}/mlflow-artifacts",
            "tags": {
                "user_type": "cac_authenticated",
                "classification": "UNCLASSIFIED",
                "department": "analytics",
                "created_by": "cac_auth_system"
            }
        }
        
        print(f"   📊 Experiment: {mlflow_config['experiment_name']}")
        print(f"   📍 Tracking URI: {mlflow_config['tracking_uri']}")
        print(f"   📦 Artifacts: {mlflow_config['artifact_location']}")
        
        # Example MLflow tracking code
        sample_code = '''
        import mlflow
        import mlflow.sklearn
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.datasets import make_classification
        from sklearn.model_selection import train_test_split
        from sklearn.metrics import accuracy_score
        
        # Set up MLflow
        mlflow.set_tracking_uri("databricks")
        mlflow.set_experiment("/Users/{user}/CAC-ML-Experiments")
        
        # Start MLflow run
        with mlflow.start_run():
            # Create sample data
            X, y = make_classification(n_samples=1000, n_features=10, random_state=42)
            X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2)
            
            # Train model
            rf = RandomForestClassifier(n_estimators=100, random_state=42)
            rf.fit(X_train, y_train)
            
            # Make predictions and calculate accuracy
            predictions = rf.predict(X_test)
            accuracy = accuracy_score(y_test, predictions)
            
            # Log parameters and metrics
            mlflow.log_param("n_estimators", 100)
            mlflow.log_param("model_type", "RandomForest")
            mlflow.log_metric("accuracy", accuracy)
            
            # Log model
            mlflow.sklearn.log_model(rf, "model")
            
            print(f"Model accuracy: {accuracy:.4f}")
        '''.format(user=self.user_id)
        
        print("\n   📄 Sample MLflow Code:")
        print("      📝 Random Forest Classification Example")
        print("      📊 Automatic parameter and metric logging")
        print("      💾 Model artifact storage")
    
    def _create_welcome_notebook_content(self):
        """Create welcome notebook content"""
        return '''
# Welcome to Databricks - CAC Authenticated User

## Getting Started

Welcome! You've successfully authenticated using your CAC/PIV card. This notebook provides an overview of your Databricks environment.

### Your Environment Details
- **Authentication Method**: CAC/PIV Smart Card
- **User Type**: DoD Authenticated User
- **Security Classification**: UNCLASSIFIED
- **Workspace**: Secure Analytics Environment

### Available Resources
1. **Compute Clusters**: Secure, auto-terminating clusters
2. **Data Storage**: DBFS and Unity Catalog
3. **MLflow**: Experiment tracking and model management
4. **Libraries**: Pre-installed ML and analytics packages

### Security Reminders
- All activities are logged for audit purposes
- Data must be properly classified
- Follow DoD security guidelines
- Report any security incidents immediately

### Next Steps
1. Explore the sample notebooks in your workspace
2. Connect to approved data sources
3. Start building your analytics projects
4. Use MLflow for experiment tracking

For support, contact your system administrator.
        '''
    
    def _create_setup_notebook_content(self):
        """Create setup utility notebook content"""
        return '''
# CAC User Environment Setup

## Automated Environment Configuration

This notebook helps set up your Databricks environment for CAC-authenticated users.

### Environment Checks
```python
# Check Spark configuration
print("Spark Version:", spark.version)
print("Scala Version:", spark.conf.get("spark.sql.catalogImplementation"))

# Check available databases
databases = spark.sql("SHOW DATABASES").collect()
print("Available Databases:")
for db in databases:
    print(f"  - {db.databaseName}")

# Check user permissions
try:
    current_user = spark.sql("SELECT current_user()").collect()[0][0]
    print(f"Current User: {current_user}")
except:
    print("Unable to determine current user")
```

### Security Configuration
```python
# Verify security settings
security_settings = {
    "ACLs Enabled": spark.conf.get("spark.databricks.acl.dfAclsEnabled", "false"),
    "Passthrough Disabled": spark.conf.get("spark.databricks.passthrough.enabled", "true") == "false",
    "Cluster Profile": spark.conf.get("spark.databricks.cluster.profile", "standard")
}

print("Security Configuration:")
for setting, value in security_settings.items():
    status = "✅" if value in ["true", "serverless"] else "❌"
    print(f"  {status} {setting}: {value}")
```

### Initialization Complete
Your CAC-authenticated environment is ready for use!
        '''

class NavyJupiterExample:
    """Complete Navy Jupiter integration example"""
    
    def __init__(self):
        self.setup_navy_jupiter_config()
    
    def setup_navy_jupiter_config(self):
        """Set up Navy Jupiter configuration"""
        print("⚓ Setting up Navy Jupiter CAC/PIV Integration")
        
        self.config = PlatformConfig(
            platform_name="navy_jupiter",
            base_url="https://navy-jupiter.navy.mil",
            api_version="v1",
            authentication_endpoint="/api/v1/auth/cac",
            token_endpoint="/api/v1/auth/token",
            user_info_endpoint="/api/v1/user/profile",
            timeout=30,
            verify_ssl=True,
            additional_config={
                "navy_network": os.getenv("NAVY_NETWORK", "NIPR"),
                "classification_level": os.getenv("CLASSIFICATION", "UNCLASSIFIED"),
                "command_code": os.getenv("COMMAND_CODE", "NAVWAR"),
                "facility_code": os.getenv("FACILITY_CODE", "SD001"),
                "enclave_id": "SPAWAR-SD",
                "require_dual_auth": False,
                "session_timeout": 3600,
                "max_concurrent_sessions": 1
            }
        )
        
        self.adapter = NavyJupiterAuthAdapter(self.config)
        print("✅ Navy Jupiter adapter initialized")
    
    def authenticate_navy_user(self):
        """Authenticate Navy user with enhanced validation"""
        print("\n🛡️ Starting Navy Jupiter Authentication")
        
        # Mock Navy certificate data
        navy_cert_data = self._create_navy_mock_certificate()
        challenge = b"navy_jupiter_challenge"
        signature = b"navy_signature"
        
        # Additional Navy-specific parameters
        additional_params = {
            "command_code": self.config.additional_config["command_code"],
            "facility_code": self.config.additional_config["facility_code"],
            "client_ip": "192.168.1.100",
            "workstation_id": "NAVWS001",
            "user_agent": "Navy-Workstation/1.0",
            "security_context": {
                "network": self.config.additional_config["navy_network"],
                "classification": self.config.additional_config["classification_level"],
                "time_zone": "America/New_York"
            }
        }
        
        result = self.adapter.authenticate_with_cac(
            certificate_data=navy_cert_data,
            signature=signature,
            challenge=challenge,
            additional_params=additional_params
        )
        
        if result.status == AuthenticationStatus.SUCCESS:
            print("🎉 Navy Jupiter authentication successful!")
            print(f"   ⚓ Navy Network: {self.config.additional_config['navy_network']}")
            print(f"   🏢 Command: {self.config.additional_config['command_code']}")
            print(f"   🏭 Facility: {self.config.additional_config['facility_code']}")
            print(f"   🔐 Classification: {self.config.additional_config['classification_level']}")
            print(f"   🎫 Session Token: {result.session_token[:20]}...")
            
            self.session_token = result.session_token
            self.security_context = result.metadata.get('security_context', {})
            return result
        else:
            print(f"❌ Navy Jupiter authentication failed: {result.error_message}")
            return None
    
    def demonstrate_navy_systems_access(self):
        """Demonstrate access to Navy systems"""
        if not hasattr(self, 'session_token'):
            print("❌ No active session. Please authenticate first.")
            return
        
        print("\n🌊 Demonstrating Navy Systems Access")
        
        # Get available Navy systems
        systems = self.adapter.get_navy_systems(self.session_token)
        
        if systems:
            print(f"   🖥️ Available Systems ({len(systems)}):")
            for system in systems:
                classification = system.get('classification', 'UNKNOWN')
                network = system.get('network', 'UNKNOWN')
                
                class_emoji = {
                    "UNCLASSIFIED": "🟢",
                    "CONFIDENTIAL": "🟡", 
                    "SECRET": "🔴"
                }.get(classification, "⚪")
                
                net_emoji = {
                    "NIPR": "🌐",
                    "SIPR": "🔒"
                }.get(network, "❓")
                
                print(f"      {class_emoji}{net_emoji} {system.get('name', 'Unknown')}")
                print(f"         📊 {classification} on {network}")
                if system.get('description'):
                    print(f"         📝 {system['description']}")
        else:
            print("   🖥️ No systems available")
        
        # Demonstrate system-specific access
        print("\n   🔧 System-Specific Access Examples:")
        
        # GCCS-M Access
        if self.config.additional_config["classification_level"] in ["SECRET", "TOP_SECRET"]:
            print("      🎯 GCCS-M (Global Command & Control System - Maritime)")
            print("         ✅ Access authorized - SECRET clearance detected")
            print("         🌊 Maritime operations dashboard available")
            print("         📊 Real-time fleet tracking enabled")
        
        # NMCI Portal Access
        print("      🌐 NMCI Portal (Navy Marine Corps Intranet)")
        print("         ✅ Access authorized - Standard Navy services")
        print("         📧 Email and collaboration tools")
        print("         📋 Administrative systems")
        
        # Custom Navy Analytics
        print("      📊 Navy Analytics Platform")
        print("         ✅ Access authorized - Data analytics tools")
        print("         📈 Operational metrics dashboard")
        print("         🔍 Intelligence analysis tools")
    
    def demonstrate_security_monitoring(self):
        """Demonstrate Navy security monitoring"""
        print("\n🛡️ Navy Security Monitoring")
        
        # Get current security context
        security_ctx = self.adapter.get_security_context(self.session_token)
        
        if security_ctx:
            print("   🔍 Current Security Context:")
            print(f"      🌐 Network: {security_ctx.get('network', 'Unknown')}")
            print(f"      🔐 Classification: {security_ctx.get('classification', 'Unknown')}")
            print(f"      🏢 Command: {security_ctx.get('command', 'Unknown')}")
            print(f"      📍 Location: {security_ctx.get('facility', 'Unknown')}")
            print(f"      ⏰ Session Start: {security_ctx.get('session_start', 'Unknown')}")
        
        # Security monitoring features
        monitoring_features = [
            "🔐 Continuous certificate validation",
            "📊 Real-time activity monitoring", 
            "🚨 Anomaly detection and alerting",
            "📝 Comprehensive audit logging",
            "🔒 Data loss prevention (DLP)",
            "🛡️ Insider threat detection",
            "⏰ Session timeout enforcement",
            "📍 Geographic location tracking"
        ]
        
        print("\n   🛡️ Active Security Features:")
        for feature in monitoring_features:
            print(f"      {feature}")
    
    def demonstrate_classification_handling(self):
        """Demonstrate data classification handling"""
        print("\n🏷️ Data Classification Management")
        
        # Classification levels and handling
        classification_matrix = {
            "UNCLASSIFIED": {
                "marking": "UNCLASSIFIED",
                "handling": "Standard handling procedures",
                "storage": "Approved Navy systems",
                "transmission": "NIPR networks authorized",
                "access": "General Navy personnel"
            },
            "CONFIDENTIAL": {
                "marking": "CONFIDENTIAL//NOFORN",
                "handling": "Controlled access required",
                "storage": "Encrypted storage mandatory",
                "transmission": "Secure channels only",
                "access": "Cleared personnel with need-to-know"
            },
            "SECRET": {
                "marking": "SECRET//NOFORN",
                "handling": "Special handling required",
                "storage": "Classified storage systems",
                "transmission": "SIPR networks only",
                "access": "SECRET clearance with need-to-know"
            }
        }
        
        current_level = self.config.additional_config["classification_level"]
        
        print(f"   🔐 Current Classification Level: {current_level}")
        
        if current_level in classification_matrix:
            rules = classification_matrix[current_level]
            print("   📋 Classification Rules:")
            print(f"      🏷️ Marking: {rules['marking']}")
            print(f"      🤲 Handling: {rules['handling']}")
            print(f"      💾 Storage: {rules['storage']}")
            print(f"      📡 Transmission: {rules['transmission']}")
            print(f"      👥 Access: {rules['access']}")
        
        # Data handling examples
        print("\n   📊 Data Handling Examples:")
        examples = [
            "📧 Email Classification: Auto-tagging based on content",
            "📄 Document Marking: Automatic watermarking and headers", 
            "🔒 Database Access: Row-level classification filtering",
            "📤 Data Export: Classification-aware export controls",
            "🗂️ File Storage: Encrypted storage with access controls"
        ]
        
        for example in examples:
            print(f"      {example}")
    
    def _create_navy_mock_certificate(self):
        """Create mock Navy certificate for demo"""
        return b"mock_navy_certificate_data_with_navy_attributes"

def main():
    """Run all platform examples"""
    print("🎯 CAC/PIV Platform Integration Examples")
    print("=" * 50)
    
    examples = [
        ("Advana", AdvanaExample),
        ("Qlik Sense", QlikExample),
        ("Databricks", DatabricksExample),
        ("Navy Jupiter", NavyJupiterExample)
    ]
    
    for platform_name, example_class in examples:
        print(f"\n{'='*20} {platform_name} Example {'='*20}")
        
        try:
            example = example_class()
            
            # Run platform-specific demonstrations
            if hasattr(example, 'authenticate_user'):
                example.authenticate_user()
            elif hasattr(example, 'authenticate_and_create_session'):
                example.authenticate_and_create_session()
            elif hasattr(example, 'authenticate_and_setup_user'):
                example.authenticate_and_setup_user()
            elif hasattr(example, 'authenticate_navy_user'):
                example.authenticate_navy_user()
            
            # Run additional demonstrations
            for method_name in dir(example):
                if method_name.startswith('demonstrate_'):
                    method = getattr(example, method_name)
                    method()
            
            print(f"✅ {platform_name} example completed successfully")
            
        except Exception as e:
            print(f"❌ {platform_name} example failed: {e}")
    
    print(f"\n{'='*20} Examples Complete {'='*20}")
    print("🎉 All platform examples have been demonstrated!")
    print("\n📚 Next Steps:")
    print("  1. Review the integration guides for each platform")
    print("  2. Configure your production environments")
    print("  3. Set up monitoring and audit logging")
    print("  4. Train users on the authentication process")
    print("  5. Implement security best practices")

if __name__ == "__main__":
    main()