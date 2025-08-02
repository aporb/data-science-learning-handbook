"""
Network Bridge Controllers for Cross-Domain Solutions

This module provides specialized network bridge controllers for different domain pairs,
implementing Bell-LaPadula mandatory access control enforcement and real-time monitoring.
"""

import logging
import asyncio
import ssl
import socket
import struct
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, List, Optional, Any, Tuple, Set
from dataclasses import dataclass, field
import uuid
import json
import hashlib
import hmac
from concurrent.futures import ThreadPoolExecutor
import threading
import queue
import time

# Import existing security components
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from models.classification_models import ClassificationLevel, DataItem
from cross_domain_guard.engines.cross_domain_guard import NetworkDomain, TransferRequest, TransferStatus
from models.bell_lapadula import BellLaPadulaPolicy, AccessControlDecision


class BridgeStatus(Enum):
    """Bridge status enumeration"""
    INITIALIZING = "initializing"
    ACTIVE = "active"
    MONITORING = "monitoring"
    DEGRADED = "degraded"
    FAILED = "failed"
    MAINTENANCE = "maintenance"


class ConnectionSecurity(Enum):
    """Connection security level"""
    STANDARD = "standard"
    ENHANCED = "enhanced"
    MAXIMUM = "maximum"
    QUANTUM_SAFE = "quantum_safe"


@dataclass
class BridgeMetrics:
    """Bridge performance and security metrics"""
    connection_count: int = 0
    active_transfers: int = 0
    bytes_transferred: int = 0
    packets_sent: int = 0
    packets_received: int = 0
    errors_detected: int = 0
    security_violations: int = 0
    average_latency_ms: float = 0.0
    throughput_mbps: float = 0.0
    last_activity: Optional[datetime] = None
    uptime_seconds: int = 0


@dataclass
class SecurityEvent:
    """Security event record"""
    id: str
    timestamp: datetime
    event_type: str
    severity: str
    description: str
    source_domain: NetworkDomain
    target_domain: NetworkDomain
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ConnectionProfile:
    """Connection security profile"""
    connection_id: str
    source_domain: NetworkDomain
    target_domain: NetworkDomain
    security_level: ConnectionSecurity
    classification_level: ClassificationLevel
    established_at: datetime
    last_activity: datetime
    bytes_transferred: int = 0
    packets_count: int = 0
    security_checks_passed: int = 0
    security_violations: int = 0
    is_active: bool = True


class BellLaPadulaEnforcer:
    """Enforces Bell-LaPadula mandatory access control for cross-domain transfers"""
    
    def __init__(self):
        self.policy = BellLaPadulaPolicy()
        self.access_matrix = self._initialize_access_matrix()
        self.security_labels = self._initialize_security_labels()
        
    def _initialize_access_matrix(self) -> Dict[Tuple[NetworkDomain, NetworkDomain], Dict[str, bool]]:
        """Initialize Bell-LaPadula access control matrix"""
        return {
            # NIPR -> SIPR (Read up allowed, Write up allowed)
            (NetworkDomain.NIPR, NetworkDomain.SIPR): {
                "read_up": True,
                "write_up": True,
                "read_down": False,
                "write_down": False,
                "classification_check": True,
                "compartment_check": True
            },
            # SIPR -> JWICS (Read up allowed, Write up allowed)
            (NetworkDomain.SIPR, NetworkDomain.JWICS): {
                "read_up": True,
                "write_up": True,
                "read_down": False,
                "write_down": False,
                "classification_check": True,
                "compartment_check": True
            },
            # SIPR -> NIPR (Read down forbidden, Write down requires declassification)
            (NetworkDomain.SIPR, NetworkDomain.NIPR): {
                "read_up": False,
                "write_up": False,
                "read_down": False,
                "write_down": False,  # Only with declassification authority
                "classification_check": True,
                "compartment_check": True,
                "declassification_required": True
            },
            # JWICS -> SIPR (Read down forbidden, Write down requires declassification)
            (NetworkDomain.JWICS, NetworkDomain.SIPR): {
                "read_up": False,
                "write_up": False,
                "read_down": False,
                "write_down": False,  # Only with declassification authority
                "classification_check": True,
                "compartment_check": True,
                "declassification_required": True
            }
        }
    
    def _initialize_security_labels(self) -> Dict[NetworkDomain, Dict[str, Any]]:
        """Initialize security labels for each domain"""
        return {
            NetworkDomain.NIPR: {
                "classification": ClassificationLevel.UNCLASSIFIED,
                "compartments": [],
                "handling_caveats": ["FOUO"],
                "releasability": ["US"]
            },
            NetworkDomain.SIPR: {
                "classification": ClassificationLevel.SECRET,
                "compartments": ["SI", "TK", "G", "HCS"],
                "handling_caveats": ["NOFORN", "REL TO USA"],
                "releasability": ["US", "FVEY"]
            },
            NetworkDomain.JWICS: {
                "classification": ClassificationLevel.TOP_SECRET,
                "compartments": ["SI", "TK", "G", "HCS", "COMINT", "TALENT KEYHOLE"],
                "handling_caveats": ["NOFORN", "REL TO USA", "ORCON"],
                "releasability": ["US"]
            }
        }
    
    def evaluate_transfer_access(self, request: TransferRequest) -> AccessControlDecision:
        """Evaluate transfer request against Bell-LaPadula policy"""
        
        domain_pair = (request.source_domain, request.target_domain)
        access_rules = self.access_matrix.get(domain_pair)
        
        if not access_rules:
            return AccessControlDecision(
                allowed=False,
                reason="No access rules defined for domain pair",
                violations=["UNDEFINED_DOMAIN_PAIR"]
            )
        
        violations = []
        
        # Check classification levels
        source_classification = self.security_labels[request.source_domain]["classification"]
        target_classification = self.security_labels[request.target_domain]["classification"]
        
        for data_item in request.data_items:
            item_classification = data_item.classification
            
            # Bell-LaPadula "no read up" property
            if item_classification.value > source_classification.value:
                violations.append(f"READ_UP_VIOLATION: Item {data_item.id} classification exceeds source domain")
            
            # Bell-LaPadula "no write down" property
            if item_classification.value > target_classification.value:
                if not access_rules.get("declassification_required", False):
                    violations.append(f"WRITE_DOWN_VIOLATION: Item {data_item.id} classification exceeds target domain")
                elif not self._check_declassification_authority(request):
                    violations.append(f"DECLASSIFICATION_AUTHORITY_REQUIRED: Item {data_item.id}")
        
        # Check compartment access
        if access_rules.get("compartment_check", False):
            compartment_violations = self._check_compartment_access(request, access_rules)
            violations.extend(compartment_violations)
        
        # Check handling caveats
        caveat_violations = self._check_handling_caveats(request, access_rules)
        violations.extend(caveat_violations)
        
        return AccessControlDecision(
            allowed=len(violations) == 0,
            reason="Bell-LaPadula policy evaluation completed",
            violations=violations,
            metadata={
                "source_classification": source_classification.value,
                "target_classification": target_classification.value,
                "domain_pair": domain_pair
            }
        )
    
    def _check_declassification_authority(self, request: TransferRequest) -> bool:
        """Check if requester has declassification authority"""
        # This would check against actual declassification authority database
        return request.metadata.get("declassification_authority", False)
    
    def _check_compartment_access(self, request: TransferRequest, access_rules: Dict[str, Any]) -> List[str]:
        """Check compartment access requirements"""
        violations = []
        
        source_compartments = set(self.security_labels[request.source_domain]["compartments"])
        target_compartments = set(self.security_labels[request.target_domain]["compartments"])
        
        for data_item in request.data_items:
            item_compartments = set(data_item.metadata.get("compartments", []))
            
            # Check if user has access to all required compartments
            user_compartments = set(request.metadata.get("user_compartments", []))
            
            if not item_compartments.issubset(user_compartments):
                missing_compartments = item_compartments - user_compartments
                violations.append(f"COMPARTMENT_ACCESS_VIOLATION: Item {data_item.id} requires {missing_compartments}")
            
            # Check if target domain supports required compartments
            if not item_compartments.issubset(target_compartments):
                unsupported_compartments = item_compartments - target_compartments
                violations.append(f"COMPARTMENT_SUPPORT_VIOLATION: Target domain does not support {unsupported_compartments}")
        
        return violations
    
    def _check_handling_caveats(self, request: TransferRequest, access_rules: Dict[str, Any]) -> List[str]:
        """Check handling caveat requirements"""
        violations = []
        
        source_caveats = set(self.security_labels[request.source_domain]["handling_caveats"])
        target_caveats = set(self.security_labels[request.target_domain]["handling_caveats"])
        
        for data_item in request.data_items:
            item_caveats = set(data_item.metadata.get("handling_caveats", []))
            
            # Check NOFORN restrictions
            if "NOFORN" in item_caveats:
                user_nationality = request.metadata.get("user_nationality", "US")
                if user_nationality != "US":
                    violations.append(f"NOFORN_VIOLATION: Item {data_item.id} restricted to US persons only")
            
            # Check releasability
            item_releasability = set(data_item.metadata.get("releasability", ["US"]))
            target_releasability = set(self.security_labels[request.target_domain]["releasability"])
            
            if not item_releasability.intersection(target_releasability):
                violations.append(f"RELEASABILITY_VIOLATION: Item {data_item.id} not releasable to target domain")
        
        return violations


class RealTimeMonitor:
    """Real-time monitoring and alerting for bridge operations"""
    
    def __init__(self, bridge_id: str):
        self.bridge_id = bridge_id
        self.metrics = BridgeMetrics()
        self.security_events = []
        self.alert_thresholds = self._initialize_alert_thresholds()
        self.monitoring_active = False
        self.alert_callbacks = []
        
    def _initialize_alert_thresholds(self) -> Dict[str, Any]:
        """Initialize monitoring alert thresholds"""
        return {
            "max_connection_count": 100,
            "max_error_rate_percent": 5.0,
            "max_latency_ms": 1000,
            "min_throughput_mbps": 1.0,
            "max_security_violations_per_hour": 10,
            "connection_timeout_seconds": 300
        }
    
    def start_monitoring(self):
        """Start real-time monitoring"""
        self.monitoring_active = True
        
        # Start monitoring thread
        monitoring_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
        monitoring_thread.start()
        
        logging.info(f"Real-time monitoring started for bridge {self.bridge_id}")
    
    def stop_monitoring(self):
        """Stop real-time monitoring"""
        self.monitoring_active = False
        logging.info(f"Real-time monitoring stopped for bridge {self.bridge_id}")
    
    def _monitoring_loop(self):
        """Main monitoring loop"""
        while self.monitoring_active:
            try:
                # Update metrics
                self._update_metrics()
                
                # Check thresholds
                self._check_alert_thresholds()
                
                # Clean old events
                self._clean_old_events()
                
                time.sleep(1)  # Monitor every second
                
            except Exception as e:
                logging.error(f"Monitoring error: {e}")
                time.sleep(5)  # Wait before retrying
    
    def _update_metrics(self):
        """Update bridge metrics"""
        current_time = datetime.now()
        
        # Update uptime
        if hasattr(self, 'start_time'):
            self.metrics.uptime_seconds = int((current_time - self.start_time).total_seconds())
        else:
            self.start_time = current_time
        
        # Calculate error rate
        if self.metrics.packets_sent > 0:
            error_rate = (self.metrics.errors_detected / self.metrics.packets_sent) * 100
        else:
            error_rate = 0.0
        
        # Update last activity
        self.metrics.last_activity = current_time
        
        # Store error rate for threshold checking
        self.current_error_rate = error_rate
    
    def _check_alert_thresholds(self):
        """Check metrics against alert thresholds"""
        
        # Check connection count
        if self.metrics.connection_count > self.alert_thresholds["max_connection_count"]:
            self._trigger_alert("HIGH_CONNECTION_COUNT", 
                              f"Connection count ({self.metrics.connection_count}) exceeds threshold")
        
        # Check error rate
        if hasattr(self, 'current_error_rate') and \
           self.current_error_rate > self.alert_thresholds["max_error_rate_percent"]:
            self._trigger_alert("HIGH_ERROR_RATE", 
                              f"Error rate ({self.current_error_rate:.1f}%) exceeds threshold")
        
        # Check latency
        if self.metrics.average_latency_ms > self.alert_thresholds["max_latency_ms"]:
            self._trigger_alert("HIGH_LATENCY", 
                              f"Average latency ({self.metrics.average_latency_ms:.1f}ms) exceeds threshold")
        
        # Check throughput
        if self.metrics.throughput_mbps < self.alert_thresholds["min_throughput_mbps"]:
            self._trigger_alert("LOW_THROUGHPUT", 
                              f"Throughput ({self.metrics.throughput_mbps:.1f}Mbps) below threshold")
        
        # Check security violations
        recent_violations = self._count_recent_security_violations()
        if recent_violations > self.alert_thresholds["max_security_violations_per_hour"]:
            self._trigger_alert("HIGH_SECURITY_VIOLATIONS", 
                              f"Security violations ({recent_violations}) exceed hourly threshold")
    
    def _count_recent_security_violations(self) -> int:
        """Count security violations in the last hour"""
        one_hour_ago = datetime.now() - timedelta(hours=1)
        return len([
            event for event in self.security_events
            if event.timestamp > one_hour_ago and event.event_type == "SECURITY_VIOLATION"
        ])
    
    def _clean_old_events(self):
        """Remove events older than 24 hours"""
        cutoff_time = datetime.now() - timedelta(hours=24)
        self.security_events = [
            event for event in self.security_events
            if event.timestamp > cutoff_time
        ]
    
    def _trigger_alert(self, alert_type: str, message: str):
        """Trigger security alert"""
        alert_event = SecurityEvent(
            id=str(uuid.uuid4()),
            timestamp=datetime.now(),
            event_type=alert_type,
            severity="HIGH" if "SECURITY" in alert_type else "MEDIUM",
            description=message,
            source_domain=NetworkDomain.NIPR,  # Default, would be set by caller
            target_domain=NetworkDomain.SIPR   # Default, would be set by caller
        )
        
        self.security_events.append(alert_event)
        
        # Notify alert callbacks
        for callback in self.alert_callbacks:
            try:
                callback(alert_event)
            except Exception as e:
                logging.error(f"Alert callback error: {e}")
        
        logging.warning(f"Bridge {self.bridge_id} alert: {alert_type} - {message}")
    
    def register_alert_callback(self, callback):
        """Register callback for security alerts"""
        self.alert_callbacks.append(callback)
    
    def record_security_event(self, event_type: str, description: str, 
                            source_domain: NetworkDomain, target_domain: NetworkDomain,
                            severity: str = "MEDIUM", metadata: Dict[str, Any] = None):
        """Record security event"""
        event = SecurityEvent(
            id=str(uuid.uuid4()),
            timestamp=datetime.now(),
            event_type=event_type,
            severity=severity,
            description=description,
            source_domain=source_domain,
            target_domain=target_domain,
            metadata=metadata or {}
        )
        
        self.security_events.append(event)
        self.metrics.security_violations += 1
        
        logging.info(f"Security event recorded: {event_type} - {description}")


class NetworkBridgeController:
    """Base network bridge controller for cross-domain connections"""
    
    def __init__(self, source_domain: NetworkDomain, target_domain: NetworkDomain, bridge_id: str):
        self.source_domain = source_domain
        self.target_domain = target_domain
        self.bridge_id = bridge_id
        self.status = BridgeStatus.INITIALIZING
        
        # Security components
        self.bell_lapadula_enforcer = BellLaPadulaEnforcer()
        self.monitor = RealTimeMonitor(bridge_id)
        
        # Connection management
        self.active_connections = {}
        self.connection_profiles = {}
        self.security_events = []
        
        # Performance tracking
        self.performance_stats = {}
        self.error_recovery_queue = queue.Queue()
        
        # Initialize bridge
        self._initialize_bridge()
    
    def _initialize_bridge(self):
        """Initialize bridge components"""
        try:
            # Start monitoring
            self.monitor.start_monitoring()
            self.monitor.register_alert_callback(self._handle_security_alert)
            
            # Set up error recovery
            self._start_error_recovery_handler()
            
            self.status = BridgeStatus.ACTIVE
            logging.info(f"Bridge {self.bridge_id} initialized successfully")
            
        except Exception as e:
            self.status = BridgeStatus.FAILED
            logging.error(f"Bridge {self.bridge_id} initialization failed: {e}")
            raise
    
    def _start_error_recovery_handler(self):
        """Start error recovery handler thread"""
        recovery_thread = threading.Thread(target=self._error_recovery_loop, daemon=True)
        recovery_thread.start()
    
    def _error_recovery_loop(self):
        """Error recovery loop"""
        while True:
            try:
                # Get error from queue (blocking)
                error_info = self.error_recovery_queue.get(timeout=60)
                
                # Attempt recovery
                self._attempt_error_recovery(error_info)
                
            except queue.Empty:
                continue
            except Exception as e:
                logging.error(f"Error recovery failed: {e}")
    
    def _attempt_error_recovery(self, error_info: Dict[str, Any]):
        """Attempt to recover from error"""
        error_type = error_info.get("type")
        connection_id = error_info.get("connection_id")
        
        if error_type == "CONNECTION_TIMEOUT":
            self._recover_connection_timeout(connection_id)
        elif error_type == "SECURITY_VIOLATION":
            self._recover_security_violation(connection_id, error_info)
        elif error_type == "NETWORK_ERROR":
            self._recover_network_error(connection_id, error_info)
        
        logging.info(f"Attempted recovery for error: {error_type}")
    
    def _recover_connection_timeout(self, connection_id: str):
        """Recover from connection timeout"""
        if connection_id in self.active_connections:
            # Close timed out connection
            self.close_connection(connection_id)
            
            # Record event
            self.monitor.record_security_event(
                "CONNECTION_TIMEOUT_RECOVERY",
                f"Connection {connection_id} closed due to timeout",
                self.source_domain,
                self.target_domain
            )
    
    def _recover_security_violation(self, connection_id: str, error_info: Dict[str, Any]):
        """Recover from security violation"""
        violation_type = error_info.get("violation_type")
        
        # Immediate connection termination for security violations
        if connection_id in self.active_connections:
            self.close_connection(connection_id)
        
        # Record security event
        self.monitor.record_security_event(
            "SECURITY_VIOLATION_RECOVERY",
            f"Connection {connection_id} terminated due to {violation_type}",
            self.source_domain,
            self.target_domain,
            severity="HIGH",
            metadata=error_info
        )
    
    def _recover_network_error(self, connection_id: str, error_info: Dict[str, Any]):
        """Recover from network error"""
        # Attempt connection reset
        if connection_id in self.active_connections:
            try:
                connection_profile = self.connection_profiles.get(connection_id)
                if connection_profile:
                    # Re-establish connection with same security parameters
                    new_connection_id = self.establish_secure_connection(
                        connection_profile.security_level,
                        connection_profile.classification_level
                    )
                    
                    # Update connection mapping
                    if new_connection_id:
                        logging.info(f"Connection {connection_id} recovered as {new_connection_id}")
                    
            except Exception as e:
                logging.error(f"Connection recovery failed: {e}")
    
    def _handle_security_alert(self, alert_event: SecurityEvent):
        """Handle security alert from monitor"""
        
        # Log alert
        logging.warning(f"Security alert: {alert_event.event_type} - {alert_event.description}")
        
        # Take action based on alert type
        if alert_event.event_type == "HIGH_SECURITY_VIOLATIONS":
            # Temporarily restrict new connections
            self.status = BridgeStatus.MONITORING
        elif alert_event.event_type == "HIGH_ERROR_RATE":
            # Switch to degraded mode
            self.status = BridgeStatus.DEGRADED
        
        # Record in security events
        self.security_events.append(alert_event)
    
    def establish_secure_connection(self, security_level: ConnectionSecurity, 
                                  classification_level: ClassificationLevel) -> Optional[str]:
        """Establish secure connection with specified security parameters"""
        
        if self.status not in [BridgeStatus.ACTIVE, BridgeStatus.MONITORING]:
            logging.warning(f"Bridge {self.bridge_id} not available for new connections")
            return None
        
        try:
            connection_id = str(uuid.uuid4())
            
            # Create connection profile
            profile = ConnectionProfile(
                connection_id=connection_id,
                source_domain=self.source_domain,
                target_domain=self.target_domain,
                security_level=security_level,
                classification_level=classification_level,
                established_at=datetime.now(),
                last_activity=datetime.now()
            )
            
            # Store connection info
            self.active_connections[connection_id] = {
                "profile": profile,
                "socket": None,  # Would be actual socket in real implementation
                "ssl_context": self._create_ssl_context(security_level),
                "encryption_key": self._generate_encryption_key(security_level)
            }
            
            self.connection_profiles[connection_id] = profile
            
            # Update metrics
            self.monitor.metrics.connection_count += 1
            
            # Record security event
            self.monitor.record_security_event(
                "CONNECTION_ESTABLISHED",
                f"Secure connection established with {security_level.value} security",
                self.source_domain,
                self.target_domain,
                metadata={
                    "connection_id": connection_id,
                    "security_level": security_level.value,
                    "classification_level": classification_level.value
                }
            )
            
            logging.info(f"Secure connection {connection_id} established")
            return connection_id
            
        except Exception as e:
            logging.error(f"Failed to establish secure connection: {e}")
            return None
    
    def _create_ssl_context(self, security_level: ConnectionSecurity) -> ssl.SSLContext:
        """Create SSL context based on security level"""
        
        if security_level == ConnectionSecurity.MAXIMUM:
            # Use highest security settings
            context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            context.minimum_version = ssl.TLSVersion.TLSv1_3
            context.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS')
        elif security_level == ConnectionSecurity.ENHANCED:
            context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
        else:
            context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        
        return context
    
    def _generate_encryption_key(self, security_level: ConnectionSecurity) -> bytes:
        """Generate encryption key based on security level"""
        
        if security_level == ConnectionSecurity.QUANTUM_SAFE:
            # Use quantum-safe key generation
            return os.urandom(64)  # 512-bit key
        elif security_level == ConnectionSecurity.MAXIMUM:
            return os.urandom(32)  # 256-bit key
        else:
            return os.urandom(32)  # 256-bit key
    
    def validate_transfer_request(self, request: TransferRequest) -> AccessControlDecision:
        """Validate transfer request against Bell-LaPadula policy"""
        return self.bell_lapadula_enforcer.evaluate_transfer_access(request)
    
    async def transfer_data(self, connection_id: str, data: bytes, 
                          request: TransferRequest) -> bool:
        """Transfer data through secure bridge"""
        
        # Validate connection
        if connection_id not in self.active_connections:
            logging.error(f"Invalid connection ID: {connection_id}")
            return False
        
        connection_info = self.active_connections[connection_id]
        profile = connection_info["profile"]
        
        try:
            # Validate Bell-LaPadula access control
            access_decision = self.validate_transfer_request(request)
            if not access_decision.allowed:
                self.monitor.record_security_event(
                    "ACCESS_CONTROL_VIOLATION",
                    f"Transfer blocked: {', '.join(access_decision.violations)}",
                    self.source_domain,
                    self.target_domain,
                    severity="HIGH",
                    metadata={"connection_id": connection_id, "violations": access_decision.violations}
                )
                return False
            
            # Encrypt data
            encrypted_data = self._encrypt_transfer_data(data, connection_info)
            
            # Transfer data (simulated)
            await asyncio.sleep(0.001 * len(encrypted_data) / 1024)  # Simulate transfer time
            
            # Update metrics
            profile.bytes_transferred += len(data)
            profile.packets_count += 1
            profile.last_activity = datetime.now()
            profile.security_checks_passed += 1
            
            self.monitor.metrics.bytes_transferred += len(data)
            self.monitor.metrics.packets_sent += 1
            
            # Record successful transfer
            self.monitor.record_security_event(
                "DATA_TRANSFER_SUCCESS",
                f"Data transfer completed successfully",
                self.source_domain,
                self.target_domain,
                severity="LOW",
                metadata={
                    "connection_id": connection_id,
                    "bytes_transferred": len(data),
                    "encrypted_size": len(encrypted_data)
                }
            )
            
            return True
            
        except Exception as e:
            # Record transfer error
            self.monitor.metrics.errors_detected += 1
            profile.security_violations += 1
            
            self.monitor.record_security_event(
                "DATA_TRANSFER_ERROR",
                f"Data transfer failed: {str(e)}",
                self.source_domain,
                self.target_domain,
                severity="HIGH",
                metadata={"connection_id": connection_id, "error": str(e)}
            )
            
            # Add to error recovery queue
            self.error_recovery_queue.put({
                "type": "NETWORK_ERROR",
                "connection_id": connection_id,
                "error": str(e),
                "timestamp": datetime.now()
            })
            
            return False
    
    def _encrypt_transfer_data(self, data: bytes, connection_info: Dict[str, Any]) -> bytes:
        """Encrypt data for transfer"""
        encryption_key = connection_info["encryption_key"]
        
        # Simple encryption (in practice, use proper encryption)
        cipher = Fernet(Fernet.generate_key())  # This is just for demonstration
        return cipher.encrypt(data)
    
    def close_connection(self, connection_id: str):
        """Close secure connection"""
        if connection_id in self.active_connections:
            profile = self.connection_profiles.get(connection_id)
            
            # Mark as inactive
            if profile:
                profile.is_active = False
            
            # Remove from active connections
            del self.active_connections[connection_id]
            
            # Update metrics
            self.monitor.metrics.connection_count -= 1
            
            # Record event
            self.monitor.record_security_event(
                "CONNECTION_CLOSED",
                f"Connection closed",
                self.source_domain,
                self.target_domain,
                metadata={"connection_id": connection_id}
            )
            
            logging.info(f"Connection {connection_id} closed")
    
    def get_bridge_status(self) -> Dict[str, Any]:
        """Get bridge status and metrics"""
        return {
            "bridge_id": self.bridge_id,
            "status": self.status.value,
            "source_domain": self.source_domain.value,
            "target_domain": self.target_domain.value,
            "active_connections": len(self.active_connections),
            "metrics": {
                "connection_count": self.monitor.metrics.connection_count,
                "active_transfers": self.monitor.metrics.active_transfers,
                "bytes_transferred": self.monitor.metrics.bytes_transferred,
                "errors_detected": self.monitor.metrics.errors_detected,
                "security_violations": self.monitor.metrics.security_violations,
                "uptime_seconds": self.monitor.metrics.uptime_seconds
            },
            "recent_security_events": len([
                event for event in self.security_events
                if event.timestamp > datetime.now() - timedelta(hours=1)
            ])
        }


class NIPRSIPRBridgeController(NetworkBridgeController):
    """Specialized bridge controller for NIPR ↔ SIPR transfers"""
    
    def __init__(self):
        super().__init__(NetworkDomain.NIPR, NetworkDomain.SIPR, "NIPR-SIPR-BRIDGE")
        self.specialized_rules = self._initialize_nipr_sipr_rules()
    
    def _initialize_nipr_sipr_rules(self) -> Dict[str, Any]:
        """Initialize NIPR-SIPR specific rules"""
        return {
            "max_file_size_mb": 100,
            "allowed_file_types": [".txt", ".pdf", ".docx", ".xlsx", ".pptx"],
            "content_scanning": True,
            "malware_detection": True,
            "data_loss_prevention": True,
            "classification_validation": True
        }


class SIPRJWICSBridgeController(NetworkBridgeController):
    """Specialized bridge controller for SIPR ↔ JWICS transfers"""
    
    def __init__(self):
        super().__init__(NetworkDomain.SIPR, NetworkDomain.JWICS, "SIPR-JWICS-BRIDGE")
        self.specialized_rules = self._initialize_sipr_jwics_rules()
    
    def _initialize_sipr_jwics_rules(self) -> Dict[str, Any]:
        """Initialize SIPR-JWICS specific rules"""
        return {
            "max_file_size_mb": 50,
            "intelligence_validation": True,
            "compartment_checking": True,
            "source_validation": True,
            "enhanced_encryption": True,
            "audit_logging": True
        }


class BridgeControllerManager:
    """Manager for all network bridge controllers"""
    
    def __init__(self):
        self.bridges = {}
        self.initialize_bridges()
    
    def initialize_bridges(self):
        """Initialize all bridge controllers"""
        try:
            # NIPR-SIPR bridge
            self.bridges["nipr_sipr"] = NIPRSIPRBridgeController()
            
            # SIPR-JWICS bridge
            self.bridges["sipr_jwics"] = SIPRJWICSBridgeController()
            
            logging.info("All bridge controllers initialized successfully")
            
        except Exception as e:
            logging.error(f"Failed to initialize bridge controllers: {e}")
            raise
    
    def get_bridge(self, source_domain: NetworkDomain, target_domain: NetworkDomain) -> Optional[NetworkBridgeController]:
        """Get appropriate bridge for domain pair"""
        
        if source_domain == NetworkDomain.NIPR and target_domain == NetworkDomain.SIPR:
            return self.bridges.get("nipr_sipr")
        elif source_domain == NetworkDomain.SIPR and target_domain == NetworkDomain.JWICS:
            return self.bridges.get("sipr_jwics")
        elif source_domain == NetworkDomain.SIPR and target_domain == NetworkDomain.NIPR:
            return self.bridges.get("nipr_sipr")  # Same bridge, reverse direction
        elif source_domain == NetworkDomain.JWICS and target_domain == NetworkDomain.SIPR:
            return self.bridges.get("sipr_jwics")  # Same bridge, reverse direction
        
        return None
    
    def get_system_status(self) -> Dict[str, Any]:
        """Get overall system status"""
        total_connections = sum(len(bridge.active_connections) for bridge in self.bridges.values())
        total_transfers = sum(bridge.monitor.metrics.bytes_transferred for bridge in self.bridges.values())
        total_violations = sum(bridge.monitor.metrics.security_violations for bridge in self.bridges.values())
        
        bridge_statuses = {
            bridge_id: bridge.get_bridge_status()
            for bridge_id, bridge in self.bridges.items()
        }
        
        return {
            "total_bridges": len(self.bridges),
            "total_connections": total_connections,
            "total_transfers_bytes": total_transfers,
            "total_security_violations": total_violations,
            "bridge_statuses": bridge_statuses
        }