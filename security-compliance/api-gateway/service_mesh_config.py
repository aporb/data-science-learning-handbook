"""
Service Mesh Configuration for DoD Environments

This module provides service mesh implementation using Istio for microservices
communication within DoD environments. Includes traffic management, security
policies, and observability configurations.

Key Features:
- Istio service mesh configuration
- mTLS enforcement between services
- Traffic routing and load balancing
- Circuit breaker patterns
- Distributed tracing integration
- Security policies and network segmentation

Security Standards:
- Zero-trust networking model
- Service-to-service authentication
- Traffic encryption in transit
- Network policy enforcement
- Audit logging for all communications
"""

import yaml
import json
import logging
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, asdict
from enum import Enum
from pathlib import Path
import os

from kubernetes import client, config
from kubernetes.client.rest import ApiException


class MeshEnvironment(Enum):
    """Service mesh deployment environments."""
    DEVELOPMENT = "development"
    TESTING = "testing"
    STAGING = "staging"
    PRODUCTION = "production"
    NIPRNET = "niprnet"
    SIPRNET = "siprnet"


class TrafficPolicy(Enum):
    """Traffic management policies."""
    ROUND_ROBIN = "ROUND_ROBIN"
    LEAST_CONN = "LEAST_CONN"
    RANDOM = "RANDOM"
    PASSTHROUGH = "PASSTHROUGH"


class SecurityMode(Enum):
    """Istio security modes."""
    STRICT = "STRICT"
    PERMISSIVE = "PERMISSIVE"
    DISABLE = "DISABLE"


class CircuitBreakerState(Enum):
    """Circuit breaker states."""
    CLOSED = "CLOSED"
    OPEN = "OPEN"
    HALF_OPEN = "HALF_OPEN"


@dataclass
class ServiceMeshConfig:
    """Service mesh configuration settings."""
    namespace: str
    environment: MeshEnvironment
    cluster_name: str
    mesh_id: str
    network: str
    enable_mtls: bool = True
    enable_tracing: bool = True
    enable_metrics: bool = True
    enable_access_logs: bool = True
    trust_domain: str = "cluster.local"
    ca_cert_path: Optional[str] = None
    root_cert_path: Optional[str] = None


@dataclass
class ServiceConfig:
    """Individual service configuration."""
    name: str
    namespace: str
    port: int
    protocol: str = "HTTP"
    version: str = "v1"
    replicas: int = 1
    cpu_limit: str = "500m"
    memory_limit: str = "512Mi"
    security_classification: str = "UNCLASSIFIED"
    labels: Optional[Dict[str, str]] = None


@dataclass
class TrafficManagementConfig:
    """Traffic management configuration."""
    timeout: str = "30s"
    retries: int = 3
    retry_timeout: str = "5s"
    circuit_breaker_consecutive_errors: int = 5
    circuit_breaker_interval: str = "30s"
    circuit_breaker_base_ejection_time: str = "30s"
    max_request_per_connection: int = 10
    max_requests: int = 100
    max_pending_requests: int = 50


class ServiceMeshManager:
    """
    Service Mesh Manager for DoD Environments
    
    Manages Istio service mesh configuration, security policies,
    and traffic management for DoD-compliant microservices.
    """
    
    def __init__(self, config: ServiceMeshConfig):
        """Initialize service mesh manager."""
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # Kubernetes client
        self.k8s_client = None
        self.custom_client = None
        
        # Initialize Kubernetes clients
        self._initialize_k8s_clients()
    
    def _initialize_k8s_clients(self) -> None:
        """Initialize Kubernetes API clients."""
        try:
            # Load Kubernetes configuration
            if os.path.exists(os.path.expanduser("~/.kube/config")):
                config.load_kube_config()
            else:
                config.load_incluster_config()
            
            # Initialize clients
            self.k8s_client = client.ApiClient()
            self.custom_client = client.CustomObjectsApi()
            
            self.logger.info("Kubernetes clients initialized successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize Kubernetes clients: {e}")
            raise
    
    def generate_istio_gateway(self, gateway_name: str, hosts: List[str], 
                              port: int = 443, tls_mode: str = "SIMPLE") -> Dict[str, Any]:
        """Generate Istio Gateway configuration."""
        gateway_config = {
            "apiVersion": "networking.istio.io/v1beta1",
            "kind": "Gateway",
            "metadata": {
                "name": gateway_name,
                "namespace": self.config.namespace,
                "labels": {
                    "app": gateway_name,
                    "environment": self.config.environment.value,
                    "classification": "UNCLASSIFIED",
                    "managed-by": "dod-api-gateway"
                }
            },
            "spec": {
                "selector": {
                    "istio": "ingressgateway"
                },
                "servers": [
                    {
                        "port": {
                            "number": port,
                            "name": "https",
                            "protocol": "HTTPS"
                        },
                        "tls": {
                            "mode": tls_mode,
                            "credentialName": f"{gateway_name}-tls"
                        },
                        "hosts": hosts
                    }
                ]
            }
        }
        
        return gateway_config
    
    def generate_virtual_service(self, service_name: str, gateway_name: str,
                               hosts: List[str], destination_host: str,
                               destination_port: int) -> Dict[str, Any]:
        """Generate Istio VirtualService configuration."""
        virtual_service_config = {
            "apiVersion": "networking.istio.io/v1beta1",
            "kind": "VirtualService",
            "metadata": {
                "name": f"{service_name}-vs",
                "namespace": self.config.namespace,
                "labels": {
                    "app": service_name,
                    "environment": self.config.environment.value,
                    "classification": "UNCLASSIFIED"
                }
            },
            "spec": {
                "hosts": hosts,
                "gateways": [f"{self.config.namespace}/{gateway_name}"],
                "http": [
                    {
                        "match": [
                            {
                                "uri": {
                                    "prefix": f"/{service_name}"
                                }
                            }
                        ],
                        "route": [
                            {
                                "destination": {
                                    "host": destination_host,
                                    "port": {
                                        "number": destination_port
                                    }
                                }
                            }
                        ],
                        "timeout": "30s",
                        "retries": {
                            "attempts": 3,
                            "perTryTimeout": "10s"
                        }
                    }
                ]
            }
        }
        
        return virtual_service_config
    
    def generate_destination_rule(self, service_name: str, host: str,
                                traffic_config: TrafficManagementConfig) -> Dict[str, Any]:
        """Generate Istio DestinationRule with traffic policies."""
        destination_rule_config = {
            "apiVersion": "networking.istio.io/v1beta1",
            "kind": "DestinationRule",
            "metadata": {
                "name": f"{service_name}-dr",
                "namespace": self.config.namespace,
                "labels": {
                    "app": service_name,
                    "environment": self.config.environment.value
                }
            },
            "spec": {
                "host": host,
                "trafficPolicy": {
                    "loadBalancer": {
                        "simple": TrafficPolicy.ROUND_ROBIN.value
                    },
                    "connectionPool": {
                        "tcp": {
                            "maxConnections": traffic_config.max_requests
                        },
                        "http": {
                            "http1MaxPendingRequests": traffic_config.max_pending_requests,
                            "maxRequestsPerConnection": traffic_config.max_request_per_connection
                        }
                    },
                    "outlierDetection": {
                        "consecutiveErrors": traffic_config.circuit_breaker_consecutive_errors,
                        "interval": traffic_config.circuit_breaker_interval,
                        "baseEjectionTime": traffic_config.circuit_breaker_base_ejection_time,
                        "maxEjectionPercent": 50
                    }
                },
                "portLevelSettings": [
                    {
                        "port": {
                            "number": 80
                        },
                        "connectionPool": {
                            "tcp": {
                                "maxConnections": traffic_config.max_requests
                            }
                        }
                    }
                ]
            }
        }
        
        return destination_rule_config
    
    def generate_peer_authentication(self, service_name: str, 
                                   security_mode: SecurityMode = SecurityMode.STRICT) -> Dict[str, Any]:
        """Generate PeerAuthentication for mTLS enforcement."""
        peer_auth_config = {
            "apiVersion": "security.istio.io/v1beta1",
            "kind": "PeerAuthentication",
            "metadata": {
                "name": f"{service_name}-peer-auth",
                "namespace": self.config.namespace,
                "labels": {
                    "app": service_name,
                    "environment": self.config.environment.value
                }
            },
            "spec": {
                "selector": {
                    "matchLabels": {
                        "app": service_name
                    }
                },
                "mtls": {
                    "mode": security_mode.value
                }
            }
        }
        
        return peer_auth_config
    
    def generate_authorization_policy(self, service_name: str, 
                                    allowed_sources: List[str],
                                    allowed_operations: List[str]) -> Dict[str, Any]:
        """Generate AuthorizationPolicy for service access control."""
        auth_policy_config = {
            "apiVersion": "security.istio.io/v1beta1",
            "kind": "AuthorizationPolicy",
            "metadata": {
                "name": f"{service_name}-auth-policy",
                "namespace": self.config.namespace,
                "labels": {
                    "app": service_name,
                    "environment": self.config.environment.value
                }
            },
            "spec": {
                "selector": {
                    "matchLabels": {
                        "app": service_name
                    }
                },
                "rules": []
            }
        }
        
        # Add rules for allowed sources
        for source in allowed_sources:
            for operation in allowed_operations:
                rule = {
                    "from": [
                        {
                            "source": {
                                "principals": [f"cluster.local/ns/{self.config.namespace}/sa/{source}"]
                            }
                        }
                    ],
                    "to": [
                        {
                            "operation": {
                                "methods": [operation]
                            }
                        }
                    ]
                }
                auth_policy_config["spec"]["rules"].append(rule)
        
        return auth_policy_config
    
    def generate_service_monitor(self, service_name: str, port: int) -> Dict[str, Any]:
        """Generate ServiceMonitor for Prometheus metrics collection."""
        service_monitor_config = {
            "apiVersion": "monitoring.coreos.com/v1",
            "kind": "ServiceMonitor",
            "metadata": {
                "name": f"{service_name}-monitor",
                "namespace": self.config.namespace,
                "labels": {
                    "app": service_name,
                    "environment": self.config.environment.value
                }
            },
            "spec": {
                "selector": {
                    "matchLabels": {
                        "app": service_name
                    }
                },
                "endpoints": [
                    {
                        "port": "metrics",
                        "interval": "30s",
                        "path": "/metrics"
                    }
                ]
            }
        }
        
        return service_monitor_config
    
    def generate_network_policy(self, service_name: str, 
                              allowed_ingress: List[str],
                              allowed_egress: List[str]) -> Dict[str, Any]:
        """Generate Kubernetes NetworkPolicy for network segmentation."""
        network_policy_config = {
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": {
                "name": f"{service_name}-netpol",
                "namespace": self.config.namespace,
                "labels": {
                    "app": service_name,
                    "environment": self.config.environment.value
                }
            },
            "spec": {
                "podSelector": {
                    "matchLabels": {
                        "app": service_name
                    }
                },
                "policyTypes": ["Ingress", "Egress"],
                "ingress": [],
                "egress": []
            }
        }
        
        # Add ingress rules
        for source in allowed_ingress:
            ingress_rule = {
                "from": [
                    {
                        "podSelector": {
                            "matchLabels": {
                                "app": source
                            }
                        }
                    }
                ]
            }
            network_policy_config["spec"]["ingress"].append(ingress_rule)
        
        # Add egress rules
        for destination in allowed_egress:
            egress_rule = {
                "to": [
                    {
                        "podSelector": {
                            "matchLabels": {
                                "app": destination
                            }
                        }
                    }
                ]
            }
            network_policy_config["spec"]["egress"].append(egress_rule)
        
        return network_policy_config
    
    def generate_telemetry_config(self, service_name: str) -> Dict[str, Any]:
        """Generate Telemetry configuration for observability."""
        telemetry_config = {
            "apiVersion": "telemetry.istio.io/v1alpha1",
            "kind": "Telemetry",
            "metadata": {
                "name": f"{service_name}-telemetry",
                "namespace": self.config.namespace,
                "labels": {
                    "app": service_name,
                    "environment": self.config.environment.value
                }
            },
            "spec": {
                "selector": {
                    "matchLabels": {
                        "app": service_name
                    }
                },
                "metrics": [
                    {
                        "providers": [
                            {
                                "name": "prometheus"
                            }
                        ],
                        "overrides": [
                            {
                                "match": {
                                    "metric": "ALL_METRICS"
                                },
                                "tagOverrides": {
                                    "service_name": {
                                        "value": service_name
                                    },
                                    "environment": {
                                        "value": self.config.environment.value
                                    }
                                }
                            }
                        ]
                    }
                ],
                "tracing": [
                    {
                        "providers": [
                            {
                                "name": "jaeger"
                            }
                        ]
                    }
                ],
                "accessLogging": [
                    {
                        "providers": [
                            {
                                "name": "otel"
                            }
                        ]
                    }
                ]
            }
        }
        
        return telemetry_config
    
    async def deploy_service_mesh_config(self, service_config: ServiceConfig,
                                       traffic_config: TrafficManagementConfig) -> bool:
        """Deploy complete service mesh configuration for a service."""
        try:
            service_name = service_config.name
            
            # Generate all configurations
            configs = {
                "gateway": self.generate_istio_gateway(
                    f"{service_name}-gateway",
                    [f"{service_name}.{self.config.environment.value}.mil"]
                ),
                "virtual_service": self.generate_virtual_service(
                    service_name,
                    f"{service_name}-gateway",
                    [f"{service_name}.{self.config.environment.value}.mil"],
                    service_name,
                    service_config.port
                ),
                "destination_rule": self.generate_destination_rule(
                    service_name,
                    service_name,
                    traffic_config
                ),
                "peer_authentication": self.generate_peer_authentication(
                    service_name,
                    SecurityMode.STRICT
                ),
                "authorization_policy": self.generate_authorization_policy(
                    service_name,
                    ["api-gateway", "ingress-gateway"],
                    ["GET", "POST", "PUT", "DELETE"]
                ),
                "network_policy": self.generate_network_policy(
                    service_name,
                    ["api-gateway"],
                    ["database", "external-api"]
                ),
                "telemetry": self.generate_telemetry_config(service_name)
            }
            
            # Apply configurations
            for config_name, config_data in configs.items():
                await self._apply_k8s_resource(config_data)
                self.logger.info(f"Applied {config_name} for service {service_name}")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to deploy service mesh config for {service_config.name}: {e}")
            return False
    
    async def _apply_k8s_resource(self, resource_config: Dict[str, Any]) -> None:
        """Apply Kubernetes resource configuration."""
        try:
            api_version = resource_config["apiVersion"]
            kind = resource_config["kind"]
            
            if "istio.io" in api_version or "security.istio.io" in api_version:
                # Apply Istio resources
                group, version = api_version.split("/")
                await self._apply_custom_resource(group, version, kind, resource_config)
            elif api_version == "networking.k8s.io/v1":
                # Apply Kubernetes networking resources
                await self._apply_networking_resource(kind, resource_config)
            elif "monitoring.coreos.com" in api_version:
                # Apply monitoring resources
                group, version = api_version.split("/")
                await self._apply_custom_resource(group, version, kind, resource_config)
            
        except Exception as e:
            self.logger.error(f"Failed to apply resource {resource_config['metadata']['name']}: {e}")
            raise
    
    async def _apply_custom_resource(self, group: str, version: str, kind: str,
                                   resource_config: Dict[str, Any]) -> None:
        """Apply custom Kubernetes resource."""
        try:
            # Determine plural name
            plural = f"{kind.lower()}s"
            if kind.endswith('y'):
                plural = f"{kind[:-1].lower()}ies"
            
            # Apply resource
            response = self.custom_client.create_namespaced_custom_object(
                group=group,
                version=version,
                namespace=self.config.namespace,
                plural=plural,
                body=resource_config
            )
            
            self.logger.info(f"Applied {kind} resource: {resource_config['metadata']['name']}")
            
        except ApiException as e:
            if e.status == 409:  # Already exists
                # Update existing resource
                response = self.custom_client.patch_namespaced_custom_object(
                    group=group,
                    version=version,
                    namespace=self.config.namespace,
                    plural=plural,
                    name=resource_config['metadata']['name'],
                    body=resource_config
                )
                self.logger.info(f"Updated {kind} resource: {resource_config['metadata']['name']}")
            else:
                raise
    
    async def _apply_networking_resource(self, kind: str, resource_config: Dict[str, Any]) -> None:
        """Apply Kubernetes networking resource."""
        try:
            networking_v1 = client.NetworkingV1Api()
            
            if kind == "NetworkPolicy":
                try:
                    response = networking_v1.create_namespaced_network_policy(
                        namespace=self.config.namespace,
                        body=resource_config
                    )
                except ApiException as e:
                    if e.status == 409:  # Already exists
                        response = networking_v1.patch_namespaced_network_policy(
                            name=resource_config['metadata']['name'],
                            namespace=self.config.namespace,
                            body=resource_config
                        )
                    else:
                        raise
            
            self.logger.info(f"Applied {kind} resource: {resource_config['metadata']['name']}")
            
        except Exception as e:
            self.logger.error(f"Failed to apply {kind} resource: {e}")
            raise
    
    def export_mesh_configs(self, output_dir: str) -> None:
        """Export all mesh configurations to YAML files."""
        try:
            output_path = Path(output_dir)
            output_path.mkdir(parents=True, exist_ok=True)
            
            # Create sample configurations
            sample_service = ServiceConfig(
                name="sample-service",
                namespace=self.config.namespace,
                port=8080
            )
            
            sample_traffic = TrafficManagementConfig()
            
            configs = {
                "gateway.yaml": self.generate_istio_gateway(
                    "sample-gateway",
                    ["sample.example.mil"]
                ),
                "virtual-service.yaml": self.generate_virtual_service(
                    "sample-service",
                    "sample-gateway",
                    ["sample.example.mil"],
                    "sample-service",
                    8080
                ),
                "destination-rule.yaml": self.generate_destination_rule(
                    "sample-service",
                    "sample-service",
                    sample_traffic
                ),
                "peer-authentication.yaml": self.generate_peer_authentication(
                    "sample-service"
                ),
                "authorization-policy.yaml": self.generate_authorization_policy(
                    "sample-service",
                    ["api-gateway"],
                    ["GET", "POST"]
                ),
                "network-policy.yaml": self.generate_network_policy(
                    "sample-service",
                    ["api-gateway"],
                    ["database"]
                ),
                "telemetry.yaml": self.generate_telemetry_config("sample-service")
            }
            
            # Write configurations to files
            for filename, config in configs.items():
                file_path = output_path / filename
                with open(file_path, 'w') as f:
                    yaml.dump(config, f, default_flow_style=False, sort_keys=False)
                
                self.logger.info(f"Exported configuration: {file_path}")
            
        except Exception as e:
            self.logger.error(f"Failed to export mesh configurations: {e}")
            raise


# Example usage
def create_dod_mesh_config() -> ServiceMeshConfig:
    """Create DoD service mesh configuration."""
    return ServiceMeshConfig(
        namespace="dod-services",
        environment=MeshEnvironment.PRODUCTION,
        cluster_name="dod-cluster-01",
        mesh_id="dod-mesh",
        network="dod-network",
        enable_mtls=True,
        enable_tracing=True,
        enable_metrics=True,
        enable_access_logs=True,
        trust_domain="dod.mil"
    )


if __name__ == "__main__":
    # Example usage
    import asyncio
    
    async def main():
        config = create_dod_mesh_config()
        manager = ServiceMeshManager(config)
        
        # Export sample configurations
        manager.export_mesh_configs("./mesh-configs")
        
        print("Service mesh configurations generated successfully")
    
    asyncio.run(main())