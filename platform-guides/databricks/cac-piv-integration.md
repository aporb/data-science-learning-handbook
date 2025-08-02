# Databricks CAC/PIV Integration Guide

## Overview

This guide provides comprehensive instructions for integrating CAC/PIV authentication with Databricks platform. The integration enables secure, certificate-based authentication for DoD users accessing Databricks analytics and machine learning capabilities.

## Prerequisites

### System Requirements
- Databricks workspace (AWS, Azure, or GCP)
- Admin access to Databricks workspace
- Valid DoD PKI certificates
- SCIM API access for user management

### Databricks Configuration Requirements
- Enterprise or Premium tier (for SCIM and advanced security)
- Unity Catalog enabled (recommended)
- Network connectivity to DoD networks
- Service principal for administrative operations

## Architecture Overview

```
[CAC Card] -> [CAC Auth Service] -> [SCIM API] -> [Databricks User] -> [Personal Access Token] -> [Databricks Services]
                                      |                                |
                                  [User Creation]              [Cluster Access]
                                      |                                |
                                  [Group Assignment]           [Notebook Access]
```

## Quick Start

### 1. Basic Configuration

```python
from security_compliance.auth.platform_adapters import PlatformConfig
from security_compliance.auth.platform_adapters import DatabricksAuthAdapter

# Configure Databricks connection
config = PlatformConfig(
    platform_name="databricks",
    base_url="https://your-workspace.cloud.databricks.com",
    api_version="2.0",
    authentication_endpoint="/api/2.0/preview/scim/v2/Users",
    token_endpoint="/api/2.0/token/create",
    user_info_endpoint="/api/2.0/preview/scim/v2/Me",
    timeout=30,
    max_retries=3,
    verify_ssl=True,
    additional_config={
        "workspace_id": "your-workspace-id",
        "workspace_url": "https://your-workspace.cloud.databricks.com",
        "instance_pool_id": "your-instance-pool-id",
        "cluster_policy_id": "your-cluster-policy-id", 
        "auth_method": "personal_access_token",
        "service_principal_id": "your-service-principal-id"
    }
)

# Initialize adapter
adapter = DatabricksAuthAdapter(config)
```

### 2. Authentication Flow

```python
from security_compliance.auth.cac_piv_integration import CACAuthenticationManager
from cryptography.hazmat.primitives import serialization

# Initialize authentication manager
auth_manager = CACAuthenticationManager()

# Authenticate user with CAC
credentials = auth_manager.authenticate_user("user_pin")

if credentials:
    # Get certificate data for Databricks
    certificate_data = credentials.certificate.public_bytes(serialization.Encoding.DER)
    
    # Generate challenge and signature
    challenge = adapter._generate_challenge()
    signature = auth_manager.authenticator.sign_data(challenge)
    
    # Authenticate with Databricks
    result = adapter.authenticate_with_cac(
        certificate_data=certificate_data,
        signature=signature,
        challenge=challenge,
        additional_params={
            "workspace_id": "your-workspace-id",
            "preferred_cluster_config": {
                "cluster_name": f"CAC-User-{credentials.edipi}",
                "spark_version": "13.3.x-scala2.12",
                "node_type_id": "i3.xlarge",
                "num_workers": 2
            }
        }
    )
    
    if result.status == AuthenticationStatus.SUCCESS:
        print(f"Databricks authentication successful!")
        print(f"Personal Access Token: {result.session_token}")
        print(f"User ID: {result.user_id}")
        
        # Get available clusters
        clusters = adapter.get_databricks_clusters(result.session_token)
        for cluster in clusters:
            print(f"Cluster: {cluster['cluster_name']} - {cluster['state']}")
        
        # Create new cluster if needed
        cluster_config = {
            "cluster_name": f"Analytics-{credentials.edipi}",
            "spark_version": "13.3.x-scala2.12",
            "node_type_id": "i3.xlarge",
            "num_workers": 1,
            "autotermination_minutes": 60
        }
        
        cluster_id = adapter.create_databricks_cluster(
            session_token=result.session_token,
            cluster_config=cluster_config
        )
        
        if cluster_id:
            print(f"Created cluster: {cluster_id}")
```

## Databricks-Specific Features

### User and Group Management

```python
def setup_databricks_user(adapter, session_token, user_attributes):
    """Set up user in Databricks with appropriate groups"""
    
    # User creation is handled automatically by the adapter
    # Get user info to verify creation
    user_info = adapter.get_user_info(session_token)
    
    if user_info:
        user_id = user_info.get('id')
        
        # Assign to groups based on organization
        organization = user_attributes.get('organization', '').lower()
        groups_to_assign = ['data-users']  # Default group
        
        if 'army' in organization:
            groups_to_assign.append('army-analysts')
        elif 'navy' in organization:
            groups_to_assign.append('navy-analysts')
        elif 'air force' in organization:
            groups_to_assign.append('af-analysts')
        
        # Add groups (this would require additional SCIM API calls)
        for group_name in groups_to_assign:
            assign_user_to_group(adapter, session_token, user_id, group_name)
        
        return user_id
    
    return None

def assign_user_to_group(adapter, session_token, user_id, group_name):
    """Assign user to Databricks group"""
    import requests
    
    headers = {
        'Authorization': f'Bearer {session_token}',
        'Content-Type': 'application/json'
    }
    
    # First, find or create the group
    group_response = requests.get(
        f"{adapter.config.base_url}/api/2.0/preview/scim/v2/Groups",
        headers=headers,
        params={'filter': f'displayName eq "{group_name}"'}
    )
    
    if group_response.status_code == 200:
        groups = group_response.json().get('Resources', [])
        if groups:
            group_id = groups[0]['id']
        else:
            # Create group if it doesn't exist
            group_data = {
                'displayName': group_name,
                'schemas': ['urn:ietf:params:scim:schemas:core:2.0:Group']
            }
            
            create_response = requests.post(
                f"{adapter.config.base_url}/api/2.0/preview/scim/v2/Groups",
                headers=headers,
                json=group_data
            )
            
            if create_response.status_code == 201:
                group_id = create_response.json()['id']
            else:
                print(f"Failed to create group {group_name}")
                return
        
        # Add user to group
        group_update_data = {
            'schemas': ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
            'Operations': [{
                'op': 'add',
                'path': 'members',
                'value': [{'value': user_id}]
            }]
        }
        
        update_response = requests.patch(
            f"{adapter.config.base_url}/api/2.0/preview/scim/v2/Groups/{group_id}",
            headers=headers,
            json=group_update_data
        )
        
        if update_response.status_code == 200:
            print(f"User {user_id} added to group {group_name}")
        else:
            print(f"Failed to add user to group: {update_response.text}")
```

### Cluster Management

```python
def create_secure_cluster(adapter, session_token, user_attrs, classification_level="UNCLASSIFIED"):
    """Create a security-compliant cluster"""
    
    cluster_config = {
        "cluster_name": f"Secure-{user_attrs.get('edipi', 'unknown')}-{classification_level}",
        "spark_version": "13.3.x-scala2.12",
        "node_type_id": "i3.xlarge",
        "driver_node_type_id": "i3.xlarge",
        "num_workers": 2,
        "autotermination_minutes": 120,  # 2 hours
        "enable_elastic_disk": True,
        "enable_local_disk_encryption": True,
        "spark_conf": {
            "spark.databricks.cluster.profile": "serverless",
            "spark.databricks.acl.dfAclsEnabled": "true",
            "spark.databricks.repl.allowedLanguages": "python,sql,scala,r",
            "spark.databricks.passthrough.enabled": "false"  # Disable for security
        },
        "custom_tags": {
            "Environment": "Production",
            "Classification": classification_level,
            "Owner": user_attrs.get('email', 'unknown'),
            "Organization": user_attrs.get('organization', 'DoD'),
            "CreatedBy": "CAC-Auth-Service"
        },
        "init_scripts": [
            {
                "dbfs": {
                    "destination": "dbfs:/databricks/init-scripts/security-init.sh"
                }
            }
        ]
    }
    
    # Add instance pool if configured
    if adapter.instance_pool_id:
        cluster_config["instance_pool_id"] = adapter.instance_pool_id
        cluster_config.pop("node_type_id", None)
        cluster_config.pop("driver_node_type_id", None)
    
    # Add cluster policy if configured
    if adapter.cluster_policy_id:
        cluster_config["policy_id"] = adapter.cluster_policy_id
    
    return adapter.create_databricks_cluster(session_token, cluster_config)

def setup_security_init_script():
    """Create initialization script for cluster security"""
    security_script = """#!/bin/bash
# Security initialization script for DoD compliance

# Set up audit logging
mkdir -p /databricks/driver/logs/audit
chmod 755 /databricks/driver/logs/audit

# Configure network security
iptables -A OUTPUT -p tcp --dport 443 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 80 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 22 -j DROP

# Set up file permissions
umask 027

# Install security monitoring
apt-get update
apt-get install -y aide tripwire

echo "Security initialization completed"
"""
    
    # Upload script to DBFS
    # This would require additional implementation
    return security_script
```

### Workspace and Notebook Management

```python
def create_user_workspace(adapter, session_token, user_attrs):
    """Create dedicated workspace for user"""
    import requests
    
    headers = {
        'Authorization': f'Bearer {session_token}',
        'Content-Type': 'application/json'
    }
    
    # Create user directory
    user_dir = f"/Users/{user_attrs.get('email', 'unknown')}"
    
    workspace_data = {
        "path": user_dir,
        "object_type": "DIRECTORY"
    }
    
    response = requests.post(
        f"{adapter.config.base_url}/api/2.0/workspace/mkdirs",
        headers=headers,
        json=workspace_data
    )
    
    if response.status_code == 200:
        print(f"Created workspace directory: {user_dir}")
        
        # Create welcome notebook
        create_welcome_notebook(adapter, session_token, user_dir, user_attrs)
        
        return user_dir
    else:
        print(f"Failed to create workspace: {response.text}")
        return None

def create_welcome_notebook(adapter, session_token, user_dir, user_attrs):
    """Create a welcome notebook for new users"""
    import base64
    
    notebook_content = f"""# Welcome to Databricks

## User Information
- **Name**: {user_attrs.get('name', 'Unknown')}
- **Email**: {user_attrs.get('email', 'Unknown')}
- **Organization**: {user_attrs.get('organization', 'DoD')}
- **EDIPI**: {user_attrs.get('edipi', 'Unknown')}

## Getting Started

This notebook provides a starting point for your data analytics work on Databricks.

### Available Resources
- Spark clusters for distributed computing
- MLflow for machine learning lifecycle management
- Delta Lake for reliable data storage
- Unity Catalog for data governance

### Security Reminders
- All work must comply with DoD security policies
- Data classification must be properly maintained
- Access controls are automatically enforced
- All activities are logged for audit purposes

### Sample Code

```python
# Display Spark configuration
spark.conf.getAll()

# Check available databases
spark.sql("SHOW DATABASES").show()

# Example data analysis
import pyspark.sql.functions as F
from pyspark.sql.types import *

# Create sample DataFrame
data = [("John", "Doe", 25), ("Jane", "Smith", 30)]
schema = StructType([
    StructField("first_name", StringType(), True),
    StructField("last_name", StringType(), True),
    StructField("age", IntegerType(), True)
])

df = spark.createDataFrame(data, schema)
df.show()
```

### Support
For technical support, contact your system administrator or refer to the platform documentation.
"""

    # Encode notebook content
    encoded_content = base64.b64encode(notebook_content.encode()).decode()
    
    notebook_data = {
        "path": f"{user_dir}/Welcome",
        "content": encoded_content,
        "language": "PYTHON",
        "format": "SOURCE",
        "overwrite": True
    }
    
    headers = {
        'Authorization': f'Bearer {session_token}',
        'Content-Type': 'application/json'
    }
    
    response = requests.post(
        f"{adapter.config.base_url}/api/2.0/workspace/import",
        headers=headers,
        json=notebook_data
    )
    
    if response.status_code == 200:
        print("Welcome notebook created successfully")
    else:
        print(f"Failed to create welcome notebook: {response.text}")
```

## Advanced Configuration

### Unity Catalog Integration

```python
def setup_unity_catalog_access(adapter, session_token, user_attrs):
    """Configure Unity Catalog access for user"""
    
    # This requires additional Unity Catalog API calls
    catalog_name = user_attrs.get('organization', 'default').lower().replace(' ', '_')
    
    # Grant access to appropriate catalogs/schemas
    permissions = [
        {
            "principal": user_attrs.get('email'),
            "privilege": "USE_CATALOG"
        },
        {
            "principal": user_attrs.get('email'), 
            "privilege": "USE_SCHEMA"
        }
    ]
    
    # Apply permissions (requires Unity Catalog API)
    for permission in permissions:
        grant_catalog_permission(adapter, session_token, catalog_name, permission)

def grant_catalog_permission(adapter, session_token, catalog_name, permission):
    """Grant Unity Catalog permission"""
    import requests
    
    headers = {
        'Authorization': f'Bearer {session_token}',
        'Content-Type': 'application/json'
    }
    
    grant_data = {
        "principal": permission["principal"],
        "privilege": permission["privilege"]
    }
    
    response = requests.post(
        f"{adapter.config.base_url}/api/2.1/unity-catalog/grants/{catalog_name}",
        headers=headers,
        json=grant_data
    )
    
    if response.status_code == 200:
        print(f"Granted {permission['privilege']} to {permission['principal']}")
    else:
        print(f"Failed to grant permission: {response.text}")
```

### MLflow Integration

```python
def setup_mlflow_tracking(adapter, session_token, user_attrs):
    """Set up MLflow tracking for user"""
    
    # Create MLflow experiment for user
    experiment_name = f"/Users/{user_attrs.get('email')}/CAC-Experiments"
    
    headers = {
        'Authorization': f'Bearer {session_token}',
        'Content-Type': 'application/json'
    }
    
    experiment_data = {
        "name": experiment_name,
        "tags": [
            {"key": "owner", "value": user_attrs.get('email', 'unknown')},
            {"key": "organization", "value": user_attrs.get('organization', 'DoD')},
            {"key": "classification", "value": "UNCLASSIFIED"},
            {"key": "created_by", "value": "cac-auth-service"}
        ]
    }
    
    response = requests.post(
        f"{adapter.config.base_url}/api/2.0/mlflow/experiments/create",
        headers=headers,
        json=experiment_data
    )
    
    if response.status_code == 200:
        experiment_id = response.json().get('experiment_id')
        print(f"Created MLflow experiment: {experiment_id}")
        return experiment_id
    else:
        print(f"Failed to create MLflow experiment: {response.text}")
        return None
```

## Security and Compliance

### Data Classification Handling

```python
def setup_data_classification_controls(adapter, session_token, classification_level):
    """Set up data classification controls"""
    
    classification_configs = {
        "UNCLASSIFIED": {
            "allowed_external_connections": True,
            "data_export_allowed": True,
            "cluster_isolation": False
        },
        "CONFIDENTIAL": {
            "allowed_external_connections": False,
            "data_export_allowed": False,
            "cluster_isolation": True
        },
        "SECRET": {
            "allowed_external_connections": False,
            "data_export_allowed": False,
            "cluster_isolation": True,
            "additional_monitoring": True
        }
    }
    
    config = classification_configs.get(classification_level, classification_configs["UNCLASSIFIED"])
    
    # Apply configuration through cluster policies and workspace settings
    return config

def create_classification_policy(classification_level):
    """Create cluster policy for data classification"""
    
    base_policy = {
        "cluster_type": {"type": "allowlist", "values": ["all-purpose"]},
        "runtime_engine": {"type": "allowlist", "values": ["PHOTON", "STANDARD"]},
        "autotermination_minutes": {"type": "fixed", "value": 120},
        "enable_elastic_disk": {"type": "fixed", "value": True},
        "enable_local_disk_encryption": {"type": "fixed", "value": True}
    }
    
    if classification_level in ["CONFIDENTIAL", "SECRET"]:
        base_policy.update({
            "spark_conf.spark.databricks.passthrough.enabled": {"type": "fixed", "value": "false"},
            "spark_conf.spark.databricks.cluster.profile": {"type": "fixed", "value": "serverless"},
            "spark_conf.spark.databricks.acl.dfAclsEnabled": {"type": "fixed", "value": "true"}
        })
    
    if classification_level == "SECRET":
        base_policy.update({
            "spark_conf.spark.databricks.security.credentials.enabled": {"type": "fixed", "value": "false"},
            "custom_tags.Classification": {"type": "fixed", "value": "SECRET"},
            "custom_tags.MonitoringLevel": {"type": "fixed", "value": "HIGH"}
        })
    
    return base_policy
```

### Audit and Monitoring

```python
def setup_audit_logging(adapter, session_token, user_attrs):
    """Set up comprehensive audit logging"""
    
    audit_config = {
        "user_id": user_attrs.get('edipi'),
        "email": user_attrs.get('email'),
        "organization": user_attrs.get('organization'),
        "access_time": datetime.now(timezone.utc).isoformat(),
        "workspace_url": adapter.config.base_url,
        "session_token_created": True
    }
    
    # Log to external audit system
    log_audit_event("databricks_access", audit_config)
    
    # Set up workspace-level audit log delivery
    setup_audit_log_delivery(adapter, session_token)

def log_audit_event(event_type, event_data):
    """Log audit event to external system"""
    import requests
    
    audit_payload = {
        "event_type": event_type,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "data": event_data
    }
    
    # Send to audit logging service
    try:
        response = requests.post(
            "https://audit-service.mil/api/v1/events",
            json=audit_payload,
            timeout=10
        )
        if response.status_code == 200:
            print("Audit event logged successfully")
        else:
            print(f"Failed to log audit event: {response.status_code}")
    except Exception as e:
        print(f"Audit logging error: {e}")

def setup_audit_log_delivery(adapter, session_token):
    """Configure Databricks audit log delivery"""
    
    headers = {
        'Authorization': f'Bearer {session_token}',
        'Content-Type': 'application/json'
    }
    
    # Configure log delivery to external system
    log_delivery_config = {
        "config_name": "dod-audit-logs",
        "output_format": "JSON",
        "delivery_path_prefix": "s3://dod-audit-bucket/databricks-logs/",
        "delivery_start_time": datetime.now(timezone.utc).isoformat(),
        "workspaces_ids": [adapter.workspace_id]
    }
    
    # This would use the Databricks audit log delivery API
    # Implementation depends on specific Databricks workspace configuration
```

## Testing and Validation

### Integration Tests

```python
import unittest
from unittest.mock import Mock, patch

class TestDatabricksCACIntegration(unittest.TestCase):
    
    def setUp(self):
        self.config = PlatformConfig(
            platform_name="databricks",
            base_url="https://test.cloud.databricks.com",
            verify_ssl=False
        )
        self.adapter = DatabricksAuthAdapter(self.config)
    
    @patch('requests.Session.request')
    def test_user_creation_flow(self, mock_request):
        """Test complete user creation and setup flow"""
        
        # Mock SCIM responses
        def mock_response_side_effect(*args, **kwargs):
            url = kwargs.get('url', '')
            method = kwargs.get('method', 'GET')
            
            mock_resp = Mock()
            mock_resp.raise_for_status.return_value = None
            
            if 'scim/v2/Users' in url and method == 'GET':
                mock_resp.json.return_value = {"Resources": []}
            elif 'scim/v2/Users' in url and method == 'POST':
                mock_resp.json.return_value = {
                    "id": "test_user_id",
                    "userName": "test@mil",
                    "active": True
                }
            elif 'token/create' in url:
                mock_resp.json.return_value = {
                    "token_value": "test_token",
                    "token_info": {"token_id": "token_123"}
                }
            else:
                mock_resp.json.return_value = {}
            
            return mock_resp
        
        mock_request.side_effect = mock_response_side_effect
        
        # Test authentication flow
        certificate_data = b"test_certificate"
        signature = b"test_signature"
        challenge = b"test_challenge"
        
        result = self.adapter.authenticate_with_cac(
            certificate_data=certificate_data,
            signature=signature,
            challenge=challenge
        )
        
        self.assertEqual(result.status, AuthenticationStatus.SUCCESS)
        self.assertIsNotNone(result.session_token)
    
    def test_cluster_configuration(self):
        """Test cluster configuration for different classification levels"""
        
        test_cases = [
            ("UNCLASSIFIED", False),
            ("CONFIDENTIAL", True),
            ("SECRET", True)
        ]
        
        for classification, should_isolate in test_cases:
            config = create_classification_policy(classification)
            
            if should_isolate:
                self.assertEqual(
                    config["spark_conf.spark.databricks.passthrough.enabled"]["value"],
                    "false"
                )
```

## Best Practices

1. **Security**
   - Use service principals for administrative operations
   - Implement proper RBAC with Unity Catalog
   - Enable audit logging for all activities
   - Regular access reviews and cleanup

2. **Resource Management**
   - Use cluster policies to control costs
   - Implement autotermination for all clusters
   - Monitor resource usage and quotas
   - Use instance pools for efficiency

3. **Data Governance**
   - Implement data classification tagging
   - Use Unity Catalog for data lineage
   - Regular data access audits
   - Proper data lifecycle management

4. **User Experience**
   - Provide welcome notebooks and documentation
   - Set up appropriate workspace organization
   - Configure MLflow for experiment tracking
   - Regular training and support

## Troubleshooting

### Common Issues

1. **SCIM API Access**
   ```
   Error: 403 Forbidden when creating users
   Solution: Verify service principal has admin privileges
   ```

2. **Token Creation Failures**
   ```
   Error: Unable to create personal access token
   Solution: Check workspace settings and user permissions
   ```

3. **Cluster Creation Issues**
   ```
   Error: Cluster policy violations
   Solution: Review cluster policy and adjust configuration
   ```

4. **Unity Catalog Access**
   ```
   Error: Permission denied accessing catalog
   Solution: Verify Unity Catalog permissions and grants
   ```

## Support and Resources

- Databricks documentation and API reference
- Unity Catalog governance guides
- SCIM API documentation
- DoD security compliance requirements
- Platform-specific support channels