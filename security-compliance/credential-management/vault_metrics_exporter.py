#!/usr/bin/env python3
"""
Vault Metrics Exporter
Exports HashiCorp Vault and credential management metrics to Prometheus
"""

import asyncio
import logging
import time
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any
from prometheus_client import CollectorRegistry, Gauge, Counter, Histogram, Info, start_http_server
import hvac
from hvac.exceptions import VaultError

from .vault_credential_manager import VaultCredentialManager
from .platform_secret_manager import PlatformSecretManager
from ..audits.audit_logger import SecurityAuditLogger

logger = logging.getLogger(__name__)

class VaultMetricsExporter:
    """
    Prometheus metrics exporter for HashiCorp Vault and credential management
    Integrates with existing Prometheus monitoring infrastructure
    """
    
    def __init__(self, vault_config: Dict[str, Any], metrics_config: Dict[str, Any]):
        """
        Initialize the Vault metrics exporter
        
        Args:
            vault_config: Vault connection configuration
            metrics_config: Metrics collection and export configuration
        """
        self.vault_config = vault_config
        self.metrics_config = metrics_config
        self.vault_client = None
        self.credential_manager = None
        self.platform_secret_manager = None
        
        # Prometheus registry
        self.registry = CollectorRegistry()
        
        # Initialize metrics
        self._init_vault_metrics()
        self._init_credential_metrics()
        self._init_security_metrics()
        
        # Configuration
        self.collection_interval = metrics_config.get('collection_interval', 30)
        self.export_port = metrics_config.get('export_port', 8080)
        self.enable_detailed_metrics = metrics_config.get('enable_detailed_metrics', True)
        self.enable_security_metrics = metrics_config.get('enable_security_metrics', True)
        
        # Initialize audit logger
        self.audit_logger = SecurityAuditLogger()
        
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        self.logger.info("Initialized Vault Metrics Exporter")
    
    def _init_vault_metrics(self) -> None:
        """Initialize Vault-specific metrics"""
        # Vault status metrics
        self.vault_status = Gauge(
            'vault_status',
            'Vault cluster status (1=healthy, 0=unhealthy)',
            registry=self.registry
        )
        
        self.vault_sealed = Gauge(
            'vault_sealed',
            'Vault seal status (1=sealed, 0=unsealed)',
            registry=self.registry
        )
        
        self.vault_initialized = Gauge(
            'vault_initialized',
            'Vault initialization status (1=initialized, 0=not initialized)',
            registry=self.registry
        )
        
        self.vault_standby = Gauge(
            'vault_standby',
            'Vault standby status (1=standby, 0=active)',
            registry=self.registry
        )
        
        # Vault performance metrics
        self.vault_request_duration = Histogram(
            'vault_request_duration_seconds',
            'Duration of Vault API requests',
            ['method', 'endpoint', 'status'],
            registry=self.registry
        )
        
        self.vault_secrets_count = Gauge(
            'vault_secrets_count',
            'Total number of secrets in Vault',
            ['secret_engine', 'path'],
            registry=self.registry
        )
        
        self.vault_leases_count = Gauge(
            'vault_leases_count',
            'Total number of active leases',
            registry=self.registry
        )
        
        self.vault_token_count = Gauge(
            'vault_token_count',
            'Total number of active tokens',
            registry=self.registry
        )
        
        # Vault auth metrics
        self.vault_auth_requests = Counter(
            'vault_auth_requests_total',
            'Total number of authentication requests',
            ['auth_method', 'status'],
            registry=self.registry
        )
        
        self.vault_auth_failures = Counter(
            'vault_auth_failures_total',
            'Total number of authentication failures',
            ['auth_method', 'reason'],
            registry=self.registry
        )
        
        # Vault audit metrics
        self.vault_audit_log_errors = Counter(
            'vault_audit_log_errors_total',
            'Total number of audit log errors',
            registry=self.registry
        )
        
        # Vault info metric
        self.vault_info = Info(
            'vault_info',
            'Vault version and build information',
            registry=self.registry
        )
    
    def _init_credential_metrics(self) -> None:
        """Initialize credential management metrics"""
        # Credential lifecycle metrics
        self.credentials_total = Gauge(
            'vault_credentials_total',
            'Total number of managed credentials',
            ['platform', 'credential_type', 'status'],
            registry=self.registry
        )
        
        self.credential_rotations_total = Counter(
            'vault_credential_rotations_total',
            'Total number of credential rotations',
            ['platform', 'rotation_type', 'status'],
            registry=self.registry
        )
        
        self.credential_rotation_duration = Histogram(
            'vault_credential_rotation_duration_seconds',
            'Duration of credential rotations',
            ['platform', 'rotation_type'],
            registry=self.registry
        )
        
        self.credential_age_seconds = Gauge(
            'vault_credential_age_seconds',
            'Age of credentials in seconds',
            ['credential_id', 'platform'],
            registry=self.registry
        )
        
        self.credential_expiry_seconds = Gauge(
            'vault_credential_expiry_seconds',
            'Time until credential expiry in seconds',
            ['credential_id', 'platform'],
            registry=self.registry
        )
        
        # Platform-specific metrics
        self.platform_connectivity = Gauge(
            'vault_platform_connectivity',
            'Platform connectivity status (1=connected, 0=disconnected)',
            ['platform'],
            registry=self.registry
        )
        
        self.platform_auth_requests = Counter(
            'vault_platform_auth_requests_total',
            'Total platform authentication requests',
            ['platform', 'status'],
            registry=self.registry
        )
        
        self.platform_auth_duration = Histogram(
            'vault_platform_auth_duration_seconds',
            'Duration of platform authentication requests',
            ['platform'],
            registry=self.registry
        )
        
        # Zero-downtime rotation metrics
        self.zero_downtime_rotations = Counter(
            'vault_zero_downtime_rotations_total',
            'Total zero-downtime rotations',
            ['platform', 'status'],
            registry=self.registry
        )
        
        self.rotation_overlap_duration = Histogram(
            'vault_rotation_overlap_duration_seconds',
            'Duration of credential overlap during zero-downtime rotation',
            ['platform'],
            registry=self.registry
        )
    
    def _init_security_metrics(self) -> None:
        """Initialize security and compliance metrics"""
        # Security events
        self.security_events_total = Counter(
            'vault_security_events_total',
            'Total number of security events',
            ['event_type', 'severity'],
            registry=self.registry
        )
        
        self.failed_access_attempts = Counter(
            'vault_failed_access_attempts_total',
            'Total number of failed access attempts',
            ['path', 'reason'],
            registry=self.registry
        )
        
        self.privilege_escalation_attempts = Counter(
            'vault_privilege_escalation_attempts_total',
            'Total number of privilege escalation attempts',
            ['user', 'path'],
            registry=self.registry
        )
        
        # Compliance metrics
        self.compliance_violations = Counter(
            'vault_compliance_violations_total',
            'Total number of compliance violations',
            ['violation_type', 'standard'],
            registry=self.registry
        )
        
        self.certificate_validations = Counter(
            'vault_certificate_validations_total',
            'Total number of certificate validations',
            ['validation_type', 'status'],
            registry=self.registry
        )
        
        self.dod_pki_validations = Counter(
            'vault_dod_pki_validations_total',
            'Total number of DoD PKI validations',
            ['certificate_type', 'status'],
            registry=self.registry
        )
        
        # Audit metrics
        self.audit_events_total = Counter(
            'vault_audit_events_total',
            'Total number of audit events',
            ['event_type', 'user_type'],
            registry=self.registry
        )
        
        self.audit_log_size_bytes = Gauge(
            'vault_audit_log_size_bytes',
            'Size of audit log files in bytes',
            ['log_type'],
            registry=self.registry
        )
    
    async def initialize(self, credential_manager: VaultCredentialManager,
                        platform_secret_manager: PlatformSecretManager) -> bool:
        """
        Initialize the metrics exporter
        
        Args:
            credential_manager: Vault credential manager instance
            platform_secret_manager: Platform secret manager instance
            
        Returns:
            True if initialization successful
        """
        try:
            # Store manager references
            self.credential_manager = credential_manager
            self.platform_secret_manager = platform_secret_manager
            
            # Initialize Vault client
            self.vault_client = hvac.Client(
                url=self.vault_config['url'],
                token=self.vault_config.get('token'),
                verify=self.vault_config.get('verify_ssl', True)
            )
            
            # Verify Vault connection
            if not self.vault_client.is_authenticated():
                self.logger.error("Failed to authenticate with Vault for metrics collection")
                return False
            
            # Set initial Vault info
            await self._update_vault_info()
            
            # Start metrics collection
            asyncio.create_task(self._metrics_collection_loop())
            
            # Start HTTP server for Prometheus scraping
            start_http_server(self.export_port, registry=self.registry)
            
            self.audit_logger.log_security_event(
                "vault_metrics_exporter_initialized",
                {"export_port": self.export_port, "collection_interval": self.collection_interval},
                severity="INFO"
            )
            
            self.logger.info(f"Vault metrics exporter started on port {self.export_port}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to initialize Vault metrics exporter: {e}")
            return False
    
    async def _metrics_collection_loop(self) -> None:
        """Main metrics collection loop"""
        while True:
            try:
                start_time = time.time()
                
                # Collect Vault metrics
                await self._collect_vault_metrics()
                
                # Collect credential metrics
                await self._collect_credential_metrics()
                
                # Collect security metrics
                if self.enable_security_metrics:
                    await self._collect_security_metrics()
                
                collection_time = time.time() - start_time
                self.logger.debug(f"Metrics collection completed in {collection_time:.2f} seconds")
                
                # Sleep until next collection
                await asyncio.sleep(self.collection_interval)
                
            except Exception as e:
                self.logger.error(f"Metrics collection error: {e}")
                await asyncio.sleep(self.collection_interval)
    
    async def _collect_vault_metrics(self) -> None:
        """Collect Vault-specific metrics"""
        try:
            # Vault status
            health = self.vault_client.sys.read_health_status(standby_ok=True)
            
            self.vault_status.set(1 if health.get('initialized', False) and not health.get('sealed', True) else 0)
            self.vault_sealed.set(1 if health.get('sealed', True) else 0)
            self.vault_initialized.set(1 if health.get('initialized', False) else 0)
            self.vault_standby.set(1 if health.get('standby', False) else 0)
            
            # Collect leases count
            if not health.get('sealed', True):
                try:
                    leases = self.vault_client.sys.list_leases()
                    if leases and 'data' in leases:
                        lease_count = len(leases['data'].get('keys', []))
                        self.vault_leases_count.set(lease_count)
                except Exception as e:
                    self.logger.debug(f"Could not collect lease metrics: {e}")
                
                # Collect secrets count by engine
                try:
                    mounts = self.vault_client.sys.list_mounted_secrets_engines()
                    for path, mount_info in mounts['data'].items():
                        if mount_info['type'] == 'kv':
                            try:
                                secrets = self.vault_client.secrets.kv.v2.list_secrets(path=path.rstrip('/'))
                                if secrets and 'data' in secrets:
                                    secret_count = len(secrets['data'].get('keys', []))
                                    self.vault_secrets_count.labels(
                                        secret_engine=mount_info['type'],
                                        path=path
                                    ).set(secret_count)
                            except Exception:
                                pass  # Path might be empty
                except Exception as e:
                    self.logger.debug(f"Could not collect secrets metrics: {e}")
                
                # Collect auth metrics
                try:
                    auth_methods = self.vault_client.sys.list_auth_methods()
                    for method_path, method_info in auth_methods['data'].items():
                        method_type = method_info['type']
                        # This would require access to audit logs to get request counts
                        # For now, we'll track this in the authentication methods
                        pass
                except Exception as e:
                    self.logger.debug(f"Could not collect auth metrics: {e}")
            
        except Exception as e:
            self.logger.error(f"Failed to collect Vault metrics: {e}")
            self.vault_status.set(0)
    
    async def _collect_credential_metrics(self) -> None:
        """Collect credential management metrics"""
        try:
            if not self.platform_secret_manager:
                return
            
            # Get all platform credentials
            all_credentials = await self.platform_secret_manager.list_platform_credentials()
            
            # Count credentials by platform and type
            credential_counts = {}
            now = datetime.now(timezone.utc)
            
            for cred in all_credentials:
                platform = cred['platform']
                cred_type = cred['credential_type']
                
                # Determine status
                status = 'active'
                if cred.get('expires_at'):
                    expires_at = datetime.fromisoformat(cred['expires_at'])
                    if expires_at <= now:
                        status = 'expired'
                    elif expires_at <= now + timedelta(hours=1):
                        status = 'expires_soon'
                
                key = (platform, cred_type, status)
                credential_counts[key] = credential_counts.get(key, 0) + 1
                
                # Set age and expiry metrics
                created_at = datetime.fromisoformat(cred['created_at'])
                age_seconds = (now - created_at).total_seconds()
                self.credential_age_seconds.labels(
                    credential_id=cred['credential_id'],
                    platform=platform
                ).set(age_seconds)
                
                if cred.get('expires_at'):
                    expires_at = datetime.fromisoformat(cred['expires_at'])
                    expiry_seconds = (expires_at - now).total_seconds()
                    self.credential_expiry_seconds.labels(
                        credential_id=cred['credential_id'],
                        platform=platform
                    ).set(max(0, expiry_seconds))
            
            # Update credential count metrics
            for (platform, cred_type, status), count in credential_counts.items():
                self.credentials_total.labels(
                    platform=platform,
                    credential_type=cred_type,
                    status=status
                ).set(count)
            
            # Check platform connectivity
            platforms = set(cred['platform'] for cred in all_credentials)
            for platform in platforms:
                if hasattr(self.platform_secret_manager, 'adapters') and platform in self.platform_secret_manager.adapters:
                    try:
                        # Simple connectivity check
                        adapter = self.platform_secret_manager.adapters[platform]
                        platform_info = adapter.get_platform_info()
                        self.platform_connectivity.labels(platform=platform).set(1)
                    except Exception:
                        self.platform_connectivity.labels(platform=platform).set(0)
            
        except Exception as e:
            self.logger.error(f"Failed to collect credential metrics: {e}")
    
    async def _collect_security_metrics(self) -> None:
        """Collect security and compliance metrics"""
        try:
            # This would typically read from audit logs
            # For now, we'll collect basic security status
            
            # Check audit log status
            try:
                audit_backends = self.vault_client.sys.list_enabled_audit_devices()
                if audit_backends and 'data' in audit_backends:
                    for backend_path, backend_info in audit_backends['data'].items():
                        if backend_info['type'] == 'file':
                            # Could check file size here if accessible
                            pass
            except Exception as e:
                self.logger.debug(f"Could not collect audit metrics: {e}")
            
        except Exception as e:
            self.logger.error(f"Failed to collect security metrics: {e}")
    
    async def _update_vault_info(self) -> None:
        """Update Vault version and build information"""
        try:
            # Get Vault version info
            health = self.vault_client.sys.read_health_status()
            version = health.get('version', 'unknown')
            cluster_name = health.get('cluster_name', 'unknown')
            cluster_id = health.get('cluster_id', 'unknown')
            
            self.vault_info.info({
                'version': version,
                'cluster_name': cluster_name,
                'cluster_id': cluster_id,
                'build_date': health.get('build_date', 'unknown')
            })
            
        except Exception as e:
            self.logger.error(f"Failed to update Vault info: {e}")
    
    def record_auth_request(self, auth_method: str, status: str) -> None:
        """Record authentication request metric"""
        self.vault_auth_requests.labels(auth_method=auth_method, status=status).inc()
    
    def record_auth_failure(self, auth_method: str, reason: str) -> None:
        """Record authentication failure metric"""
        self.vault_auth_failures.labels(auth_method=auth_method, reason=reason).inc()
    
    def record_credential_rotation(self, platform: str, rotation_type: str, 
                                 status: str, duration: float) -> None:
        """Record credential rotation metrics"""
        self.credential_rotations_total.labels(
            platform=platform,
            rotation_type=rotation_type,
            status=status
        ).inc()
        
        self.credential_rotation_duration.labels(
            platform=platform,
            rotation_type=rotation_type
        ).observe(duration)
    
    def record_platform_auth_request(self, platform: str, status: str, duration: float) -> None:
        """Record platform authentication request metrics"""
        self.platform_auth_requests.labels(platform=platform, status=status).inc()
        self.platform_auth_duration.labels(platform=platform).observe(duration)
    
    def record_zero_downtime_rotation(self, platform: str, status: str, overlap_duration: float) -> None:
        """Record zero-downtime rotation metrics"""
        self.zero_downtime_rotations.labels(platform=platform, status=status).inc()
        self.rotation_overlap_duration.labels(platform=platform).observe(overlap_duration)
    
    def record_security_event(self, event_type: str, severity: str) -> None:
        """Record security event metric"""
        self.security_events_total.labels(event_type=event_type, severity=severity).inc()
    
    def record_compliance_violation(self, violation_type: str, standard: str) -> None:
        """Record compliance violation metric"""
        self.compliance_violations.labels(violation_type=violation_type, standard=standard).inc()
    
    def record_certificate_validation(self, validation_type: str, status: str) -> None:
        """Record certificate validation metric"""
        self.certificate_validations.labels(validation_type=validation_type, status=status).inc()
    
    def record_dod_pki_validation(self, certificate_type: str, status: str) -> None:
        """Record DoD PKI validation metric"""
        self.dod_pki_validations.labels(certificate_type=certificate_type, status=status).inc()
    
    def record_audit_event(self, event_type: str, user_type: str) -> None:
        """Record audit event metric"""
        self.audit_events_total.labels(event_type=event_type, user_type=user_type).inc()