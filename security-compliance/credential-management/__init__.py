#!/usr/bin/env python3
"""
Vault Credential Management System
Complete integration of HashiCorp Vault with platform-specific authentication,
automated rotation, monitoring, disaster recovery, and compliance reporting.
"""

import asyncio
import logging
from typing import Dict, Any, Optional

from .vault_credential_manager import VaultCredentialManager
from .platform_secret_manager import PlatformSecretManager
from .vault_metrics_exporter import VaultMetricsExporter
from .vault_disaster_recovery import VaultDisasterRecoveryManager
from .compliance_reporter import VaultComplianceReporter

logger = logging.getLogger(__name__)

class IntegratedCredentialManagementSystem:
    """
    Integrated credential management system combining all components
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the integrated system
        
        Args:
            config: System configuration
        """
        self.config = config
        
        # Initialize components
        self.vault_manager = VaultCredentialManager(config.get('vault', {}))
        self.platform_manager = PlatformSecretManager(
            config.get('vault', {}),
            config.get('platforms', {})
        )
        self.metrics_exporter = VaultMetricsExporter(
            config.get('vault', {}),
            config.get('metrics', {})
        )
        self.dr_manager = VaultDisasterRecoveryManager(
            config.get('vault', {}),
            config.get('disaster_recovery', {})
        )
        self.compliance_reporter = VaultComplianceReporter(
            config.get('compliance', {})
        )
        
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        self.logger.info("Initialized Integrated Credential Management System")
    
    async def initialize(self) -> bool:
        """
        Initialize all system components
        
        Returns:
            True if initialization successful
        """
        try:
            self.logger.info("Initializing Credential Management System...")
            
            # Initialize Vault credential manager
            if not await self.vault_manager.initialize():
                raise Exception("Failed to initialize Vault credential manager")
            
            # Initialize platform secret manager
            if not await self.platform_manager.initialize():
                raise Exception("Failed to initialize platform secret manager")
            
            # Initialize metrics exporter
            if not await self.metrics_exporter.initialize(
                self.vault_manager, self.platform_manager
            ):
                raise Exception("Failed to initialize metrics exporter")
            
            # Initialize disaster recovery manager
            if not await self.dr_manager.initialize():
                raise Exception("Failed to initialize disaster recovery manager")
            
            # Initialize compliance reporter
            if not await self.compliance_reporter.initialize(
                self.vault_manager, self.platform_manager, self.dr_manager
            ):
                raise Exception("Failed to initialize compliance reporter")
            
            self.logger.info("Credential Management System initialized successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to initialize system: {e}")
            return False
    
    async def create_platform_credential(self, platform: str, credential_type: str,
                                       user_context: Dict[str, Any],
                                       metadata: Optional[Dict[str, Any]] = None) -> Optional[str]:
        """
        Create a new platform credential
        
        Args:
            platform: Target platform
            credential_type: Type of credential
            user_context: User context
            metadata: Additional metadata
            
        Returns:
            Credential ID if successful
        """
        try:
            result = await self.platform_manager.create_platform_credential(
                platform, credential_type, user_context, metadata
            )
            
            if result:
                # Record metrics
                self.metrics_exporter.record_platform_auth_request(
                    platform, "success", 0.5
                )
                
                return result['credential_id']
            
            return None
            
        except Exception as e:
            self.logger.error(f"Failed to create platform credential: {e}")
            self.metrics_exporter.record_platform_auth_request(
                platform, "failed", 0.5
            )
            return None
    
    async def rotate_credential(self, credential_id: str, 
                              zero_downtime: bool = True) -> bool:
        """
        Rotate a credential with optional zero-downtime
        
        Args:
            credential_id: Credential to rotate
            zero_downtime: Use zero-downtime rotation
            
        Returns:
            True if successful
        """
        try:
            import time
            start_time = time.time()
            
            success = await self.platform_manager.rotate_platform_credential(
                credential_id, zero_downtime
            )
            
            duration = time.time() - start_time
            
            # Record metrics
            credential = self.platform_manager.active_credentials.get(credential_id)
            platform = credential.platform if credential else "unknown"
            rotation_type = "zero_downtime" if zero_downtime else "standard"
            
            self.metrics_exporter.record_credential_rotation(
                platform, rotation_type, 
                "success" if success else "failed", 
                duration
            )
            
            if zero_downtime and success:
                self.metrics_exporter.record_zero_downtime_rotation(
                    platform, "success", 
                    self.platform_manager.rotation_overlap_duration
                )
            
            return success
            
        except Exception as e:
            self.logger.error(f"Failed to rotate credential: {e}")
            return False
    
    async def create_backup(self, backup_type: str = "snapshot") -> Optional[str]:
        """
        Create a Vault backup
        
        Args:
            backup_type: Type of backup to create
            
        Returns:
            Backup ID if successful
        """
        try:
            return await self.dr_manager.create_backup(backup_type)
            
        except Exception as e:
            self.logger.error(f"Failed to create backup: {e}")
            return None
    
    async def generate_compliance_report(self, standards: Optional[list] = None) -> Optional[str]:
        """
        Generate compliance report
        
        Args:
            standards: Compliance standards to assess
            
        Returns:
            Report ID if successful
        """
        try:
            return await self.compliance_reporter.generate_compliance_report(
                standards=standards
            )
            
        except Exception as e:
            self.logger.error(f"Failed to generate compliance report: {e}")
            return None
    
    async def get_system_status(self) -> Dict[str, Any]:
        """
        Get overall system status
        
        Returns:
            System status information
        """
        try:
            status = {
                'vault_manager': {
                    'active_secrets': len(self.vault_manager.secret_metadata),
                    'rotation_jobs': len(self.vault_manager.rotation_jobs)
                },
                'platform_manager': {
                    'active_credentials': len(self.platform_manager.active_credentials),
                    'registered_platforms': len(self.platform_manager.adapters)
                },
                'disaster_recovery': {
                    'recent_backups': len(await self.dr_manager.list_backups(limit=5)),
                    'recovery_plans': len(self.dr_manager.recovery_plans)
                },
                'compliance': await self.compliance_reporter.get_compliance_dashboard_data()
            }
            
            return status
            
        except Exception as e:
            self.logger.error(f"Failed to get system status: {e}")
            return {}

# Example configuration
EXAMPLE_CONFIG = {
    'vault': {
        'url': 'https://vault:8200',
        'token': None,  # Will be loaded from environment or token file
        'verify_ssl': True,
        'auth_method': 'cert',
        'default_rotation_interval': 86400,
        'max_secret_age': 7776000,
        'enable_auto_rotation': True,
        'secrets_path': 'kv/data/',
        'metadata_path': 'kv/metadata/',
        'rotation_path': 'kv/data/rotations/'
    },
    'platforms': {
        'qlik': {
            'base_url': 'https://qlik.example.com',
            'api_version': 'v1',
            'timeout': 30,
            'verify_ssl': True,
            'additional_config': {
                'qlik_domain': 'qlik.local',
                'virtual_proxy': '',
                'app_access_point': '/hub',
                'jwt_secret': None  # Load from secure storage
            }
        },
        'databricks': {
            'base_url': 'https://databricks.example.com',
            'api_version': '2.0',
            'timeout': 30,
            'verify_ssl': True,
            'additional_config': {
                'workspace_id': 'workspace-123',
                'workspace_url': 'https://databricks.example.com',
                'service_principal_id': None  # Load from secure storage
            }
        },
        'advana': {
            'base_url': 'https://advana.example.mil',
            'api_version': 'v1',
            'timeout': 30,
            'verify_ssl': True,
            'additional_config': {
                'environment': 'prod',
                'classification_level': 'SECRET',
                'tenant_id': 'dod-tenant-123',
                'dod_ca_bundle_path': '/certs/dod-ca-bundle.pem',
                'require_edipi': True,
                'allowed_issuers': ['DoD CA-53', 'DoD CA-59']
            }
        },
        'navy_jupiter': {
            'base_url': 'https://jupiter.example.navy.mil',
            'api_version': 'v2',
            'timeout': 30,
            'verify_ssl': True,
            'additional_config': {
                'environment': 'production',
                'classification_marking': 'FOUO',
                'fleet_designation': 'PACFLT',
                'navy_ca_bundle_path': '/certs/navy-ca-bundle.pem',
                'require_nec_code': True,
                'jupyter_hub_url': 'https://jupyter.jupiter.example.navy.mil'
            }
        }
    },
    'metrics': {
        'collection_interval': 30,
        'export_port': 8080,
        'enable_detailed_metrics': True,
        'enable_security_metrics': True
    },
    'disaster_recovery': {
        'backup_retention_days': 90,
        'backup_schedule': '0 2 * * *',  # Daily at 2 AM
        'enable_scheduled_backups': True,
        'enable_cleanup': True,
        'backup_dir': '/vault/backups',
        'temp_dir': '/vault/temp',
        'max_rto_minutes': 60,
        'max_rpo_minutes': 15,
        'storage': {
            's3_primary': {
                'type': 's3',
                'bucket': 'vault-backups-primary',
                'region': 'us-gov-west-1',
                'access_key_id': None,  # Load from environment
                'secret_access_key': None  # Load from environment
            },
            'azure_secondary': {
                'type': 'azure',
                'account_name': 'vaultbackups',
                'container': 'backups',
                'account_key': None  # Load from environment
            }
        },
        'encryption': {
            'key': None,  # Load from secure storage
            'key_id': 'vault-backup-key'
        }
    },
    'compliance': {
        'report_output_dir': '/reports',
        'report_formats': ['json', 'html', 'csv'],
        'report_schedule': 'monthly',
        'enabled_standards': ['nist_800_53', 'disa_stig', 'fisma'],
        'assessment_scope': 'full',
        'evidence_collection': True,
        'enable_scheduled_reports': True
    }
}

# Export main classes
__all__ = [
    'IntegratedCredentialManagementSystem',
    'VaultCredentialManager',
    'PlatformSecretManager',
    'VaultMetricsExporter',
    'VaultDisasterRecoveryManager',
    'VaultComplianceReporter',
    'EXAMPLE_CONFIG'
]