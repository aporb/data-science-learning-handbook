#!/usr/bin/env python3
"""
Session Security Controls and Threat Detection

Comprehensive security controls and threat detection system for session management
including anomaly detection, session hijacking protection, and security monitoring.

Classification: UNCLASSIFIED//FOR OFFICIAL USE ONLY
Version: 1.0
Author: Security Compliance Team
Date: 2025-07-18
"""

import json
import logging
import threading
import statistics
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Set, Tuple, Callable
from uuid import UUID, uuid4
from enum import Enum
from dataclasses import dataclass, field
from collections import defaultdict, deque
import hashlib
import ipaddress

# Import session management components
from .session_manager import Session, SessionState, SessionEventType, SessionEvent, NetworkDomain
from .classification_policies import ClassificationLevel

logger = logging.getLogger(__name__)


class ThreatLevel(Enum):
    """Threat severity levels."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class SecurityEventType(Enum):
    """Security event types."""
    ANOMALOUS_BEHAVIOR = "ANOMALOUS_BEHAVIOR"
    SESSION_HIJACKING_ATTEMPT = "SESSION_HIJACKING_ATTEMPT"
    CONCURRENT_SESSION_VIOLATION = "CONCURRENT_SESSION_VIOLATION"
    GEOGRAPHIC_ANOMALY = "GEOGRAPHIC_ANOMALY"
    TIME_BASED_ANOMALY = "TIME_BASED_ANOMALY"
    FAILED_AUTHENTICATION = "FAILED_AUTHENTICATION"
    PRIVILEGE_ESCALATION_ATTEMPT = "PRIVILEGE_ESCALATION_ATTEMPT"
    CLASSIFICATION_VIOLATION = "CLASSIFICATION_VIOLATION"
    NETWORK_ANOMALY = "NETWORK_ANOMALY"
    DEVICE_ANOMALY = "DEVICE_ANOMALY"
    SUSPICIOUS_ACTIVITY = "SUSPICIOUS_ACTIVITY"
    BRUTE_FORCE_ATTACK = "BRUTE_FORCE_ATTACK"
    SESSION_FIXATION_ATTEMPT = "SESSION_FIXATION_ATTEMPT"


class ResponseAction(Enum):
    """Security response actions."""
    LOG_ONLY = "LOG_ONLY"
    WARN_USER = "WARN_USER"
    CHALLENGE_MFA = "CHALLENGE_MFA"
    SUSPEND_SESSION = "SUSPEND_SESSION"
    TERMINATE_SESSION = "TERMINATE_SESSION"
    LOCK_ACCOUNT = "LOCK_ACCOUNT"
    NOTIFY_SECURITY = "NOTIFY_SECURITY"
    ESCALATE_INCIDENT = "ESCALATE_INCIDENT"


@dataclass
class SecurityThreat:
    """Security threat detection result."""
    threat_id: str
    threat_type: SecurityEventType
    threat_level: ThreatLevel
    session_id: str
    user_id: UUID
    detected_at: datetime
    description: str
    indicators: Dict[str, Any]
    confidence_score: float  # 0.0 to 1.0
    recommended_actions: List[ResponseAction]
    affected_resources: List[str] = field(default_factory=list)
    source_ip: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SecurityMetrics:
    """Security metrics for monitoring."""
    user_id: UUID
    session_count: int = 0
    failed_login_attempts: int = 0
    successful_logins: int = 0
    last_login_time: Optional[datetime] = None
    last_login_ip: Optional[str] = None
    unusual_activity_count: int = 0
    geographic_locations: Set[str] = field(default_factory=set)
    device_fingerprints: Set[str] = field(default_factory=set)
    access_patterns: Dict[str, int] = field(default_factory=dict)
    classification_access_history: List[str] = field(default_factory=list)
    network_domains_used: Set[NetworkDomain] = field(default_factory=set)
    
    def update_login_metrics(self, success: bool, ip_address: str = None):
        """Update login metrics."""
        if success:
            self.successful_logins += 1
            self.last_login_time = datetime.now(timezone.utc)
            if ip_address:
                self.last_login_ip = ip_address
        else:
            self.failed_login_attempts += 1


@dataclass
class BehaviorBaseline:
    """User behavior baseline for anomaly detection."""
    user_id: UUID
    typical_login_times: List[int]  # Hours of day
    typical_session_duration: timedelta
    typical_activity_level: float
    typical_geographic_locations: Set[str]
    typical_devices: Set[str]
    typical_network_domains: Set[NetworkDomain]
    typical_classification_levels: Set[str]
    login_frequency: Dict[str, int]  # Day of week -> count
    access_patterns: Dict[str, float]  # Operation -> frequency
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_updated: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class AnomalyDetector:
    """Behavioral anomaly detection for sessions."""
    
    def __init__(self, sensitivity_threshold: float = 0.7):
        """Initialize anomaly detector.
        
        Args:
            sensitivity_threshold: Threshold for anomaly detection (0.0-1.0)
        """
        self.sensitivity_threshold = sensitivity_threshold
        self.user_baselines: Dict[UUID, BehaviorBaseline] = {}
        self.recent_activities: Dict[UUID, deque] = defaultdict(lambda: deque(maxlen=1000))
        self._lock = threading.Lock()
        
        logger.info(f"AnomalyDetector initialized with sensitivity {sensitivity_threshold}")
    
    def detect_anomalies(self, session: Session, activity: Dict[str, Any]) -> List[SecurityThreat]:
        """Detect anomalies in session activity.
        
        Args:
            session: Session to analyze
            activity: Current activity data
            
        Returns:
            List of detected security threats
        """
        threats = []
        user_id = session.user_id
        
        with self._lock:
            # Get or create user baseline
            baseline = self.user_baselines.get(user_id)
            if not baseline:
                baseline = self._create_initial_baseline(user_id, session)
                self.user_baselines[user_id] = baseline
            
            # Store activity
            self.recent_activities[user_id].append({
                'timestamp': datetime.now(timezone.utc),
                'session_id': session.session_id,
                'activity': activity,
                'session_info': {
                    'classification_level': session.security_context.classification_level,
                    'network_domain': session.security_context.network_domain.value,
                    'source_ip': session.bound_ip
                }
            })
            
            # Detect various anomaly types
            threats.extend(self._detect_temporal_anomalies(session, baseline, activity))
            threats.extend(self._detect_geographic_anomalies(session, baseline, activity))
            threats.extend(self._detect_device_anomalies(session, baseline, activity))
            threats.extend(self._detect_behavior_anomalies(session, baseline, activity))
            threats.extend(self._detect_classification_anomalies(session, baseline, activity))
            
            # Update baseline if no threats detected
            if not threats:
                self._update_baseline(baseline, session, activity)
        
        return threats
    
    def _detect_temporal_anomalies(self, session: Session, baseline: BehaviorBaseline, activity: Dict[str, Any]) -> List[SecurityThreat]:
        """Detect temporal anomalies."""
        threats = []
        current_time = datetime.now(timezone.utc)
        current_hour = current_time.hour
        current_weekday = current_time.strftime('%A')
        
        # Check unusual login time
        if baseline.typical_login_times:
            hour_frequencies = {hour: baseline.typical_login_times.count(hour) for hour in set(baseline.typical_login_times)}
            if hour_frequencies.get(current_hour, 0) == 0:
                threats.append(SecurityThreat(
                    threat_id=str(uuid4()),
                    threat_type=SecurityEventType.TIME_BASED_ANOMALY,
                    threat_level=ThreatLevel.MEDIUM,
                    session_id=session.session_id,
                    user_id=session.user_id,
                    detected_at=current_time,
                    description=f"Unusual login time: {current_hour}:00 (typical hours: {sorted(set(baseline.typical_login_times))})",
                    indicators={'unusual_hour': current_hour, 'typical_hours': baseline.typical_login_times},
                    confidence_score=0.8,
                    recommended_actions=[ResponseAction.CHALLENGE_MFA, ResponseAction.LOG_ONLY],
                    source_ip=session.bound_ip
                ))
        
        # Check session duration anomaly
        session_duration = current_time - session.created_at
        if baseline.typical_session_duration and session_duration > baseline.typical_session_duration * 2:
            threats.append(SecurityThreat(
                threat_id=str(uuid4()),
                threat_type=SecurityEventType.TIME_BASED_ANOMALY,
                threat_level=ThreatLevel.LOW,
                session_id=session.session_id,
                user_id=session.user_id,
                detected_at=current_time,
                description=f"Unusually long session duration: {session_duration}",
                indicators={'current_duration': str(session_duration), 'typical_duration': str(baseline.typical_session_duration)},
                confidence_score=0.6,
                recommended_actions=[ResponseAction.WARN_USER, ResponseAction.LOG_ONLY],
                source_ip=session.bound_ip
            ))
        
        return threats
    
    def _detect_geographic_anomalies(self, session: Session, baseline: BehaviorBaseline, activity: Dict[str, Any]) -> List[SecurityThreat]:
        """Detect geographic anomalies."""
        threats = []
        
        if not session.bound_ip:
            return threats
        
        try:
            # Simplified geolocation detection (would use actual GeoIP service)
            current_location = self._get_location_from_ip(session.bound_ip)
            
            if current_location and baseline.typical_geographic_locations:
                if current_location not in baseline.typical_geographic_locations:
                    # Check if it's a significant distance (simplified)
                    if not self._is_nearby_location(current_location, baseline.typical_geographic_locations):
                        threats.append(SecurityThreat(
                            threat_id=str(uuid4()),
                            threat_type=SecurityEventType.GEOGRAPHIC_ANOMALY,
                            threat_level=ThreatLevel.HIGH,
                            session_id=session.session_id,
                            user_id=session.user_id,
                            detected_at=datetime.now(timezone.utc),
                            description=f"Login from unusual location: {current_location}",
                            indicators={
                                'current_location': current_location,
                                'typical_locations': list(baseline.typical_geographic_locations)
                            },
                            confidence_score=0.9,
                            recommended_actions=[ResponseAction.CHALLENGE_MFA, ResponseAction.NOTIFY_SECURITY],
                            source_ip=session.bound_ip
                        ))
        
        except Exception as e:
            logger.warning(f"Geographic anomaly detection failed: {e}")
        
        return threats
    
    def _detect_device_anomalies(self, session: Session, baseline: BehaviorBaseline, activity: Dict[str, Any]) -> List[SecurityThreat]:
        """Detect device anomalies."""
        threats = []
        
        device_fingerprint = session.bound_device_fingerprint
        if device_fingerprint and baseline.typical_devices:
            if device_fingerprint not in baseline.typical_devices:
                threats.append(SecurityThreat(
                    threat_id=str(uuid4()),
                    threat_type=SecurityEventType.DEVICE_ANOMALY,
                    threat_level=ThreatLevel.MEDIUM,
                    session_id=session.session_id,
                    user_id=session.user_id,
                    detected_at=datetime.now(timezone.utc),
                    description="Login from unrecognized device",
                    indicators={
                        'device_fingerprint': device_fingerprint,
                        'known_devices': len(baseline.typical_devices)
                    },
                    confidence_score=0.7,
                    recommended_actions=[ResponseAction.CHALLENGE_MFA, ResponseAction.LOG_ONLY],
                    source_ip=session.bound_ip
                ))
        
        return threats
    
    def _detect_behavior_anomalies(self, session: Session, baseline: BehaviorBaseline, activity: Dict[str, Any]) -> List[SecurityThreat]:
        """Detect behavioral anomalies."""
        threats = []
        
        # Analyze activity patterns
        operation = activity.get('operation')
        if operation and baseline.access_patterns:
            typical_frequency = baseline.access_patterns.get(operation, 0)
            recent_frequency = self._get_recent_operation_frequency(session.user_id, operation)
            
            if typical_frequency > 0 and recent_frequency > typical_frequency * 3:
                threats.append(SecurityThreat(
                    threat_id=str(uuid4()),
                    threat_type=SecurityEventType.SUSPICIOUS_ACTIVITY,
                    threat_level=ThreatLevel.MEDIUM,
                    session_id=session.session_id,
                    user_id=session.user_id,
                    detected_at=datetime.now(timezone.utc),
                    description=f"Unusual frequency of {operation} operations",
                    indicators={
                        'operation': operation,
                        'recent_frequency': recent_frequency,
                        'typical_frequency': typical_frequency
                    },
                    confidence_score=0.6,
                    recommended_actions=[ResponseAction.LOG_ONLY, ResponseAction.WARN_USER],
                    source_ip=session.bound_ip
                ))
        
        return threats
    
    def _detect_classification_anomalies(self, session: Session, baseline: BehaviorBaseline, activity: Dict[str, Any]) -> List[SecurityThreat]:
        """Detect classification-related anomalies."""
        threats = []
        
        current_classification = session.security_context.classification_level
        if baseline.typical_classification_levels:
            if current_classification not in baseline.typical_classification_levels:
                # Check if it's a significant elevation
                current_level = ClassificationLevel(current_classification)
                typical_max = max([ClassificationLevel(level) for level in baseline.typical_classification_levels])
                
                if current_level > typical_max:
                    threats.append(SecurityThreat(
                        threat_id=str(uuid4()),
                        threat_type=SecurityEventType.CLASSIFICATION_VIOLATION,
                        threat_level=ThreatLevel.HIGH,
                        session_id=session.session_id,
                        user_id=session.user_id,
                        detected_at=datetime.now(timezone.utc),
                        description=f"Access to higher classification than typical: {current_classification}",
                        indicators={
                            'current_classification': current_classification,
                            'typical_classifications': list(baseline.typical_classification_levels)
                        },
                        confidence_score=0.8,
                        recommended_actions=[ResponseAction.CHALLENGE_MFA, ResponseAction.NOTIFY_SECURITY],
                        source_ip=session.bound_ip
                    ))
        
        return threats
    
    def _create_initial_baseline(self, user_id: UUID, session: Session) -> BehaviorBaseline:
        """Create initial behavior baseline."""
        return BehaviorBaseline(
            user_id=user_id,
            typical_login_times=[datetime.now(timezone.utc).hour],
            typical_session_duration=timedelta(hours=4),
            typical_activity_level=1.0,
            typical_geographic_locations=set(),
            typical_devices=set(),
            typical_network_domains={session.security_context.network_domain},
            typical_classification_levels={session.security_context.classification_level},
            login_frequency={},
            access_patterns={}
        )
    
    def _update_baseline(self, baseline: BehaviorBaseline, session: Session, activity: Dict[str, Any]):
        """Update user behavior baseline."""
        current_time = datetime.now(timezone.utc)
        
        # Update login times
        baseline.typical_login_times.append(current_time.hour)
        if len(baseline.typical_login_times) > 100:  # Keep recent history
            baseline.typical_login_times = baseline.typical_login_times[-100:]
        
        # Update geographic locations
        if session.bound_ip:
            location = self._get_location_from_ip(session.bound_ip)
            if location:
                baseline.typical_geographic_locations.add(location)
        
        # Update devices
        if session.bound_device_fingerprint:
            baseline.typical_devices.add(session.bound_device_fingerprint)
        
        # Update network domains
        baseline.typical_network_domains.add(session.security_context.network_domain)
        
        # Update classification levels
        baseline.typical_classification_levels.add(session.security_context.classification_level)
        
        # Update access patterns
        operation = activity.get('operation')
        if operation:
            baseline.access_patterns[operation] = baseline.access_patterns.get(operation, 0) + 1
        
        baseline.last_updated = current_time
    
    def _get_location_from_ip(self, ip_address: str) -> Optional[str]:
        """Get location from IP address (simplified implementation)."""
        try:
            # This would integrate with actual GeoIP service
            ip = ipaddress.ip_address(ip_address)
            if ip.is_private:
                return "Internal Network"
            else:
                # Simplified: return country code or region
                return "External Location"
        except ValueError:
            return None
    
    def _is_nearby_location(self, current_location: str, typical_locations: Set[str]) -> bool:
        """Check if current location is near typical locations."""
        # Simplified implementation
        return current_location in typical_locations
    
    def _get_recent_operation_frequency(self, user_id: UUID, operation: str) -> int:
        """Get frequency of operation in recent activities."""
        recent_activities = self.recent_activities.get(user_id, deque())
        cutoff_time = datetime.now(timezone.utc) - timedelta(hours=1)
        
        count = 0
        for activity_record in recent_activities:
            if activity_record['timestamp'] > cutoff_time:
                if activity_record.get('activity', {}).get('operation') == operation:
                    count += 1
        
        return count


class SessionHijackingDetector:
    """Session hijacking detection system."""
    
    def __init__(self):
        """Initialize session hijacking detector."""
        self.session_fingerprints: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.Lock()
        
        logger.info("SessionHijackingDetector initialized")
    
    def detect_hijacking(self, session: Session, request_data: Dict[str, Any]) -> List[SecurityThreat]:
        """Detect session hijacking attempts.
        
        Args:
            session: Session to analyze
            request_data: Current request data
            
        Returns:
            List of detected hijacking threats
        """
        threats = []
        
        with self._lock:
            session_id = session.session_id
            current_fingerprint = self._generate_request_fingerprint(request_data)
            
            if session_id in self.session_fingerprints:
                stored_fingerprint = self.session_fingerprints[session_id]
                
                # Check IP address consistency
                if self._detect_ip_change(stored_fingerprint, current_fingerprint):
                    threats.append(SecurityThreat(
                        threat_id=str(uuid4()),
                        threat_type=SecurityEventType.SESSION_HIJACKING_ATTEMPT,
                        threat_level=ThreatLevel.CRITICAL,
                        session_id=session_id,
                        user_id=session.user_id,
                        detected_at=datetime.now(timezone.utc),
                        description="Session IP address changed",
                        indicators={
                            'original_ip': stored_fingerprint.get('ip_address'),
                            'current_ip': current_fingerprint.get('ip_address')
                        },
                        confidence_score=0.9,
                        recommended_actions=[ResponseAction.TERMINATE_SESSION, ResponseAction.NOTIFY_SECURITY],
                        source_ip=current_fingerprint.get('ip_address')
                    ))
                
                # Check user agent consistency
                if self._detect_user_agent_change(stored_fingerprint, current_fingerprint):
                    threats.append(SecurityThreat(
                        threat_id=str(uuid4()),
                        threat_type=SecurityEventType.SESSION_HIJACKING_ATTEMPT,
                        threat_level=ThreatLevel.HIGH,
                        session_id=session_id,
                        user_id=session.user_id,
                        detected_at=datetime.now(timezone.utc),
                        description="Session user agent changed",
                        indicators={
                            'original_user_agent': stored_fingerprint.get('user_agent'),
                            'current_user_agent': current_fingerprint.get('user_agent')
                        },
                        confidence_score=0.7,
                        recommended_actions=[ResponseAction.CHALLENGE_MFA, ResponseAction.LOG_ONLY],
                        source_ip=current_fingerprint.get('ip_address')
                    ))
                
                # Check session token integrity
                if self._detect_token_anomaly(stored_fingerprint, current_fingerprint):
                    threats.append(SecurityThreat(
                        threat_id=str(uuid4()),
                        threat_type=SecurityEventType.SESSION_FIXATION_ATTEMPT,
                        threat_level=ThreatLevel.HIGH,
                        session_id=session_id,
                        user_id=session.user_id,
                        detected_at=datetime.now(timezone.utc),
                        description="Session token anomaly detected",
                        indicators={'token_anomaly': True},
                        confidence_score=0.8,
                        recommended_actions=[ResponseAction.TERMINATE_SESSION, ResponseAction.NOTIFY_SECURITY],
                        source_ip=current_fingerprint.get('ip_address')
                    ))
            
            # Update fingerprint
            self.session_fingerprints[session_id] = current_fingerprint
        
        return threats
    
    def _generate_request_fingerprint(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate fingerprint for request."""
        return {
            'ip_address': request_data.get('source_ip'),
            'user_agent': request_data.get('user_agent'),
            'accept_language': request_data.get('accept_language'),
            'accept_encoding': request_data.get('accept_encoding'),
            'timestamp': datetime.now(timezone.utc),
            'request_headers_hash': self._hash_headers(request_data.get('headers', {}))
        }
    
    def _detect_ip_change(self, stored: Dict[str, Any], current: Dict[str, Any]) -> bool:
        """Detect IP address change."""
        stored_ip = stored.get('ip_address')
        current_ip = current.get('ip_address')
        
        if not stored_ip or not current_ip:
            return False
        
        return stored_ip != current_ip
    
    def _detect_user_agent_change(self, stored: Dict[str, Any], current: Dict[str, Any]) -> bool:
        """Detect user agent change."""
        stored_ua = stored.get('user_agent')
        current_ua = current.get('user_agent')
        
        if not stored_ua or not current_ua:
            return False
        
        return stored_ua != current_ua
    
    def _detect_token_anomaly(self, stored: Dict[str, Any], current: Dict[str, Any]) -> bool:
        """Detect session token anomaly."""
        # Check for rapid token changes or suspicious patterns
        time_diff = current['timestamp'] - stored['timestamp']
        return time_diff < timedelta(seconds=1)  # Too rapid
    
    def _hash_headers(self, headers: Dict[str, str]) -> str:
        """Generate hash of request headers."""
        # Sort headers for consistent hashing
        header_string = ''.join(f"{k}:{v}" for k, v in sorted(headers.items()))
        return hashlib.sha256(header_string.encode()).hexdigest()
    
    def cleanup_session(self, session_id: str):
        """Clean up session fingerprint data."""
        with self._lock:
            self.session_fingerprints.pop(session_id, None)


class SecurityMonitor:
    """Comprehensive security monitoring system."""
    
    def __init__(self, 
                 anomaly_detector: AnomalyDetector = None,
                 hijacking_detector: SessionHijackingDetector = None):
        """Initialize security monitor.
        
        Args:
            anomaly_detector: Anomaly detection system
            hijacking_detector: Session hijacking detector
        """
        self.anomaly_detector = anomaly_detector or AnomalyDetector()
        self.hijacking_detector = hijacking_detector or SessionHijackingDetector()
        
        # Security metrics
        self.user_metrics: Dict[UUID, SecurityMetrics] = {}
        self.threat_history: List[SecurityThreat] = []
        self.active_threats: Dict[str, SecurityThreat] = {}
        
        # Monitoring configuration
        self.monitoring_enabled = True
        self.threat_response_enabled = True
        
        # Rate limiting
        self.rate_limits: Dict[str, Dict[str, Any]] = {}
        
        self._lock = threading.Lock()
        
        logger.info("SecurityMonitor initialized")
    
    def monitor_session_activity(self, 
                                session: Session,
                                activity: Dict[str, Any],
                                request_data: Dict[str, Any] = None) -> List[SecurityThreat]:
        """Monitor session activity for security threats.
        
        Args:
            session: Session to monitor
            activity: Activity data
            request_data: Request data for hijacking detection
            
        Returns:
            List of detected security threats
        """
        if not self.monitoring_enabled:
            return []
        
        threats = []
        
        try:
            # Update user metrics
            self._update_user_metrics(session, activity)
            
            # Detect anomalies
            anomaly_threats = self.anomaly_detector.detect_anomalies(session, activity)
            threats.extend(anomaly_threats)
            
            # Detect session hijacking
            if request_data:
                hijacking_threats = self.hijacking_detector.detect_hijacking(session, request_data)
                threats.extend(hijacking_threats)
            
            # Check rate limits
            rate_limit_threats = self._check_rate_limits(session, activity)
            threats.extend(rate_limit_threats)
            
            # Check concurrent sessions
            concurrent_threats = self._check_concurrent_sessions(session)
            threats.extend(concurrent_threats)
            
            # Store threats
            with self._lock:
                for threat in threats:
                    self.threat_history.append(threat)
                    self.active_threats[threat.threat_id] = threat
            
            # Respond to threats
            if self.threat_response_enabled:
                self._respond_to_threats(session, threats)
            
        except Exception as e:
            logger.error(f"Security monitoring failed: {e}")
        
        return threats
    
    def check_brute_force_attack(self, user_id: UUID, source_ip: str = None) -> Optional[SecurityThreat]:
        """Check for brute force attack patterns.
        
        Args:
            user_id: User identifier
            source_ip: Source IP address
            
        Returns:
            Security threat if brute force detected
        """
        with self._lock:
            metrics = self.user_metrics.get(user_id)
            if not metrics:
                return None
            
            # Check failed login attempts
            if metrics.failed_login_attempts >= 5:  # Threshold
                return SecurityThreat(
                    threat_id=str(uuid4()),
                    threat_type=SecurityEventType.BRUTE_FORCE_ATTACK,
                    threat_level=ThreatLevel.HIGH,
                    session_id="N/A",
                    user_id=user_id,
                    detected_at=datetime.now(timezone.utc),
                    description=f"Brute force attack detected: {metrics.failed_login_attempts} failed attempts",
                    indicators={'failed_attempts': metrics.failed_login_attempts},
                    confidence_score=0.9,
                    recommended_actions=[ResponseAction.LOCK_ACCOUNT, ResponseAction.NOTIFY_SECURITY],
                    source_ip=source_ip
                )
        
        return None
    
    def get_security_status(self, session_id: str) -> Dict[str, Any]:
        """Get security status for session.
        
        Args:
            session_id: Session identifier
            
        Returns:
            Security status information
        """
        with self._lock:
            session_threats = [t for t in self.threat_history if t.session_id == session_id]
            active_session_threats = [t for t in self.active_threats.values() if t.session_id == session_id]
            
            return {
                'total_threats': len(session_threats),
                'active_threats': len(active_session_threats),
                'threat_levels': {
                    level.value: len([t for t in session_threats if t.threat_level == level])
                    for level in ThreatLevel
                },
                'latest_threats': sorted(session_threats, key=lambda x: x.detected_at, reverse=True)[:5],
                'monitoring_enabled': self.monitoring_enabled
            }
    
    def _update_user_metrics(self, session: Session, activity: Dict[str, Any]):
        """Update user security metrics."""
        with self._lock:
            user_id = session.user_id
            if user_id not in self.user_metrics:
                self.user_metrics[user_id] = SecurityMetrics(user_id=user_id)
            
            metrics = self.user_metrics[user_id]
            metrics.session_count += 1
            
            # Update geographic locations
            if session.bound_ip:
                location = self.anomaly_detector._get_location_from_ip(session.bound_ip)
                if location:
                    metrics.geographic_locations.add(location)
            
            # Update device fingerprints
            if session.bound_device_fingerprint:
                metrics.device_fingerprints.add(session.bound_device_fingerprint)
            
            # Update access patterns
            operation = activity.get('operation')
            if operation:
                metrics.access_patterns[operation] = metrics.access_patterns.get(operation, 0) + 1
            
            # Update classification access history
            classification = session.security_context.classification_level
            metrics.classification_access_history.append(classification)
            if len(metrics.classification_access_history) > 100:
                metrics.classification_access_history = metrics.classification_access_history[-100:]
            
            # Update network domains
            metrics.network_domains_used.add(session.security_context.network_domain)
    
    def _check_rate_limits(self, session: Session, activity: Dict[str, Any]) -> List[SecurityThreat]:
        """Check for rate limit violations."""
        threats = []
        user_id = str(session.user_id)
        
        # Rate limit configuration
        rate_limit_configs = {
            'login_attempts': {'limit': 10, 'window': 300},  # 10 per 5 minutes
            'api_calls': {'limit': 1000, 'window': 3600},   # 1000 per hour
            'classification_access': {'limit': 50, 'window': 3600}  # 50 per hour
        }
        
        for limit_type, config in rate_limit_configs.items():
            if self._is_rate_limit_exceeded(user_id, limit_type, config):
                threats.append(SecurityThreat(
                    threat_id=str(uuid4()),
                    threat_type=SecurityEventType.SUSPICIOUS_ACTIVITY,
                    threat_level=ThreatLevel.MEDIUM,
                    session_id=session.session_id,
                    user_id=session.user_id,
                    detected_at=datetime.now(timezone.utc),
                    description=f"Rate limit exceeded for {limit_type}",
                    indicators={'limit_type': limit_type, 'config': config},
                    confidence_score=0.8,
                    recommended_actions=[ResponseAction.WARN_USER, ResponseAction.LOG_ONLY],
                    source_ip=session.bound_ip
                ))
        
        return threats
    
    def _check_concurrent_sessions(self, session: Session) -> List[SecurityThreat]:
        """Check for concurrent session violations."""
        threats = []
        
        # This would integrate with session manager to check concurrent sessions
        # For now, simplified implementation
        max_concurrent = session.configuration.concurrent_session_limit
        
        # Would check actual concurrent session count here
        # current_sessions = session_manager.get_user_sessions(session.user_id)
        # if len(current_sessions) > max_concurrent:
        #     threats.append(...)
        
        return threats
    
    def _is_rate_limit_exceeded(self, user_id: str, limit_type: str, config: Dict[str, Any]) -> bool:
        """Check if rate limit is exceeded."""
        # Simplified rate limiting implementation
        current_time = datetime.now(timezone.utc)
        window_start = current_time - timedelta(seconds=config['window'])
        
        # In production, would use Redis or similar for rate limiting
        # For now, simplified check
        return False
    
    def _respond_to_threats(self, session: Session, threats: List[SecurityThreat]):
        """Respond to detected security threats."""
        for threat in threats:
            for action in threat.recommended_actions:
                try:
                    self._execute_response_action(session, threat, action)
                except Exception as e:
                    logger.error(f"Response action {action} failed: {e}")
    
    def _execute_response_action(self, session: Session, threat: SecurityThreat, action: ResponseAction):
        """Execute security response action."""
        logger.info(f"Executing response action {action.value} for threat {threat.threat_id}")
        
        if action == ResponseAction.LOG_ONLY:
            logger.warning(f"Security threat detected: {threat.description}")
        
        elif action == ResponseAction.WARN_USER:
            # Would send warning to user
            logger.info(f"Warning user {session.user_id} about threat {threat.threat_type.value}")
        
        elif action == ResponseAction.CHALLENGE_MFA:
            # Would trigger MFA challenge
            logger.info(f"MFA challenge triggered for session {session.session_id}")
        
        elif action == ResponseAction.SUSPEND_SESSION:
            # Would suspend session
            logger.info(f"Suspending session {session.session_id}")
        
        elif action == ResponseAction.TERMINATE_SESSION:
            # Would terminate session
            logger.info(f"Terminating session {session.session_id}")
        
        elif action == ResponseAction.NOTIFY_SECURITY:
            # Would notify security team
            logger.warning(f"Security notification sent for threat {threat.threat_id}")
        
        elif action == ResponseAction.ESCALATE_INCIDENT:
            # Would escalate to incident response
            logger.critical(f"Incident escalated for threat {threat.threat_id}")
    
    def get_monitoring_statistics(self) -> Dict[str, Any]:
        """Get security monitoring statistics."""
        with self._lock:
            total_threats = len(self.threat_history)
            active_threats = len(self.active_threats)
            
            threat_type_counts = {}
            for threat in self.threat_history:
                threat_type = threat.threat_type.value
                threat_type_counts[threat_type] = threat_type_counts.get(threat_type, 0) + 1
            
            threat_level_counts = {}
            for threat in self.threat_history:
                threat_level = threat.threat_level.value
                threat_level_counts[threat_level] = threat_level_counts.get(threat_level, 0) + 1
            
            return {
                'total_threats_detected': total_threats,
                'active_threats': active_threats,
                'threats_by_type': threat_type_counts,
                'threats_by_level': threat_level_counts,
                'total_users_monitored': len(self.user_metrics),
                'monitoring_enabled': self.monitoring_enabled,
                'threat_response_enabled': self.threat_response_enabled
            }


# Factory functions
def create_anomaly_detector(sensitivity_threshold: float = 0.7) -> AnomalyDetector:
    """Create and return an anomaly detector."""
    return AnomalyDetector(sensitivity_threshold)


def create_session_hijacking_detector() -> SessionHijackingDetector:
    """Create and return a session hijacking detector."""
    return SessionHijackingDetector()


def create_security_monitor(
    anomaly_detector: AnomalyDetector = None,
    hijacking_detector: SessionHijackingDetector = None
) -> SecurityMonitor:
    """Create and return a security monitor."""
    return SecurityMonitor(anomaly_detector, hijacking_detector)