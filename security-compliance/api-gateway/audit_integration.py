"""
API Gateway Audit Integration

This module provides seamless integration between the API Gateway monitoring, analytics,
and SLA tracking systems with the existing DoD audit infrastructure. It ensures all
API operations are properly audited according to DoD requirements.

Key Features:
- Automated audit event generation for API operations
- Real-time security event correlation and analysis
- Compliance mapping for API-specific events
- Integration with existing audit logging infrastructure
- API-specific compliance reporting
- Threat detection for API security events
- Audit trail completeness verification

Security Standards:
- DoD 8500.01E audit requirements for API systems
- NIST 800-53 audit controls implementation
- API security event classification and handling
- Chain of custody for API audit data
"""

import asyncio
import json
import logging
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple, Union
from dataclasses import dataclass, asdict
from enum import Enum
from collections import defaultdict, deque

import aioredis

# Import from existing audit modules
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from audits.audit_logger import AuditLogger, AuditEvent, AuditEventType, AuditSeverity, ClassificationLevel
from audits.compliance_reporter import ComplianceReporter, ComplianceFramework, ReportType
from audits.real_time_alerting import SecurityAlert, AlertSeverity, AlertCategory
from api_gateway.api_security_controls import SecurityEvent, SecurityThreatLevel, AttackType


class APIAuditEventType(Enum):
    """API-specific audit event types."""
    # API Gateway Events
    API_GATEWAY_STARTUP = "api_gateway_startup"
    API_GATEWAY_SHUTDOWN = "api_gateway_shutdown"
    API_GATEWAY_CONFIG_CHANGE = "api_gateway_config_change"
    
    # API Request Events
    API_REQUEST_RECEIVED = "api_request_received"
    API_REQUEST_PROCESSED = "api_request_processed"
    API_REQUEST_BLOCKED = "api_request_blocked"
    API_REQUEST_RATE_LIMITED = "api_request_rate_limited"
    
    # Authentication Events
    API_OAUTH_TOKEN_VALIDATED = "api_oauth_token_validated"
    API_OAUTH_TOKEN_REJECTED = "api_oauth_token_rejected"
    API_CAC_AUTH_SUCCESS = "api_cac_auth_success"
    API_CAC_AUTH_FAILURE = "api_cac_auth_failure"
    
    # Authorization Events
    API_ACCESS_GRANTED = "api_access_granted"
    API_ACCESS_DENIED = "api_access_denied"
    API_INSUFFICIENT_CLEARANCE = "api_insufficient_clearance"
    
    # Data Events
    API_CLASSIFIED_DATA_ACCESS = "api_classified_data_access"
    API_DATA_EXPORT = "api_data_export"
    API_CROSS_DOMAIN_REQUEST = "api_cross_domain_request"
    
    # Security Events
    API_SECURITY_THREAT_DETECTED = "api_security_threat_detected"
    API_ATTACK_BLOCKED = "api_attack_blocked"
    API_SUSPICIOUS_ACTIVITY = "api_suspicious_activity"
    
    # Performance Events
    API_SLA_VIOLATION = "api_sla_violation"
    API_PERFORMANCE_DEGRADATION = "api_performance_degradation"
    API_CAPACITY_THRESHOLD = "api_capacity_threshold"
    
    # Analytics Events
    API_ANOMALY_DETECTED = "api_anomaly_detected"
    API_PATTERN_ANALYSIS = "api_pattern_analysis"
    API_PREDICTION_ALERT = "api_prediction_alert"


class APIComplianceMapping:
    """Maps API events to compliance requirements."""
    
    def __init__(self):
        self.compliance_mappings = {
            # DoD 8500.01E mappings
            ComplianceFramework.DOD_8500_01E: {
                APIAuditEventType.API_OAUTH_TOKEN_VALIDATED: ["IA-2", "IA-8"],
                APIAuditEventType.API_ACCESS_DENIED: ["AC-3", "AC-6"],
                APIAuditEventType.API_CLASSIFIED_DATA_ACCESS: ["AC-4", "SC-11"],
                APIAuditEventType.API_SECURITY_THREAT_DETECTED: ["SI-4", "IR-4"],
                APIAuditEventType.API_SLA_VIOLATION: ["CP-2", "SC-5"],
                APIAuditEventType.API_ANOMALY_DETECTED: ["SI-4", "AU-6"]
            },
            
            # NIST SP 800-53 mappings
            ComplianceFramework.NIST_SP_800_53: {
                APIAuditEventType.API_REQUEST_RECEIVED: ["AU-2", "AU-3"],
                APIAuditEventType.API_ACCESS_GRANTED: ["AC-6", "AU-2"],
                APIAuditEventType.API_ACCESS_DENIED: ["AC-3", "AU-2"],
                APIAuditEventType.API_ATTACK_BLOCKED: ["SI-4", "IR-4"],
                APIAuditEventType.API_DATA_EXPORT: ["AC-4", "AU-2"],
                APIAuditEventType.API_PERFORMANCE_DEGRADATION: ["CP-2", "SC-5"]
            }
        }
    
    def get_compliance_controls(self, event_type: APIAuditEventType, 
                              framework: ComplianceFramework) -> List[str]:
        """Get compliance controls for an API audit event."""
        return self.compliance_mappings.get(framework, {}).get(event_type, [])


@dataclass
class APIAuditContext:
    """Context information for API audit events."""
    request_id: str
    endpoint: str
    method: str
    user_id: Optional[str]
    client_ip: str
    user_agent: Optional[str]
    classification_level: ClassificationLevel
    response_status: Optional[int] = None
    response_time: Optional[float] = None
    data_size: Optional[int] = None
    session_id: Optional[str] = None
    authentication_method: Optional[str] = None
    clearance_level: Optional[str] = None


class APIAuditEventGenerator:
    """Generates audit events for API operations."""
    
    def __init__(self, audit_logger: AuditLogger):
        self.audit_logger = audit_logger
        self.compliance_mapper = APIComplianceMapping()
        self.logger = logging.getLogger(__name__)
    
    async def audit_api_request(self, context: APIAuditContext, 
                              event_type: APIAuditEventType,
                              additional_data: Optional[Dict[str, Any]] = None) -> str:
        """Generate audit event for API request."""
        try:
            # Determine severity based on event type and context
            severity = self._determine_severity(event_type, context)
            
            # Create audit event
            audit_data = {
                'api_context': asdict(context),
                'event_type': event_type.value,
                'compliance_controls': self._get_applicable_controls(event_type),
                'additional_data': additional_data or {}
            }
            
            # Map to standard audit event type
            standard_event_type = self._map_to_standard_event_type(event_type)
            
            event_id = await self.audit_logger.log_event(
                event_type=standard_event_type,
                severity=severity,
                details=audit_data,
                classification=context.classification_level,
                user_id=context.user_id,
                source_ip=context.client_ip,
                session_id=context.session_id
            )
            
            return event_id
            
        except Exception as e:
            self.logger.error(f"API audit event generation failed: {e}")
            raise
    
    def _determine_severity(self, event_type: APIAuditEventType, 
                          context: APIAuditContext) -> AuditSeverity:
        """Determine audit severity for API event."""
        # High severity events
        if event_type in [
            APIAuditEventType.API_SECURITY_THREAT_DETECTED,
            APIAuditEventType.API_ATTACK_BLOCKED,
            APIAuditEventType.API_CLASSIFIED_DATA_ACCESS,
            APIAuditEventType.API_SLA_VIOLATION
        ]:
            return AuditSeverity.HIGH
        
        # Medium severity events
        elif event_type in [
            APIAuditEventType.API_ACCESS_DENIED,
            APIAuditEventType.API_OAUTH_TOKEN_REJECTED,
            APIAuditEventType.API_INSUFFICIENT_CLEARANCE,
            APIAuditEventType.API_ANOMALY_DETECTED
        ]:
            return AuditSeverity.MEDIUM
        
        # Check response status for severity escalation
        if context.response_status and context.response_status >= 500:
            return AuditSeverity.MEDIUM
        elif context.response_status and context.response_status >= 400:
            return AuditSeverity.LOW
        
        # Default to informational
        return AuditSeverity.INFO
    
    def _map_to_standard_event_type(self, api_event_type: APIAuditEventType) -> AuditEventType:
        """Map API event type to standard audit event type."""
        mapping = {
            APIAuditEventType.API_OAUTH_TOKEN_VALIDATED: AuditEventType.USER_LOGIN_SUCCESS,
            APIAuditEventType.API_OAUTH_TOKEN_REJECTED: AuditEventType.USER_LOGIN_FAILURE,
            APIAuditEventType.API_CAC_AUTH_SUCCESS: AuditEventType.CAC_AUTHENTICATION,
            APIAuditEventType.API_CAC_AUTH_FAILURE: AuditEventType.USER_LOGIN_FAILURE,
            APIAuditEventType.API_ACCESS_GRANTED: AuditEventType.ACCESS_GRANTED,
            APIAuditEventType.API_ACCESS_DENIED: AuditEventType.ACCESS_DENIED,
            APIAuditEventType.API_CLASSIFIED_DATA_ACCESS: AuditEventType.DATA_READ,
            APIAuditEventType.API_DATA_EXPORT: AuditEventType.DATA_EXPORT,
            APIAuditEventType.API_SECURITY_THREAT_DETECTED: AuditEventType.SECURITY_INCIDENT,
            APIAuditEventType.API_ATTACK_BLOCKED: AuditEventType.INTRUSION_ATTEMPT,
            APIAuditEventType.API_SLA_VIOLATION: AuditEventType.SYSTEM_ERROR,
            APIAuditEventType.API_PERFORMANCE_DEGRADATION: AuditEventType.SYSTEM_ERROR
        }
        
        return mapping.get(api_event_type, AuditEventType.SYSTEM_EVENT)
    
    def _get_applicable_controls(self, event_type: APIAuditEventType) -> Dict[str, List[str]]:
        """Get applicable compliance controls for event type."""
        controls = {}
        
        for framework in [ComplianceFramework.DOD_8500_01E, ComplianceFramework.NIST_SP_800_53]:
            framework_controls = self.compliance_mapper.get_compliance_controls(event_type, framework)
            if framework_controls:
                controls[framework.value] = framework_controls
        
        return controls


class APISecurityCorrelator:
    """Correlates API security events for threat analysis."""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.security_events = deque(maxlen=10000)
        self.correlation_rules = self._load_correlation_rules()
    
    def _load_correlation_rules(self) -> Dict[str, Any]:
        """Load security event correlation rules."""
        return {
            'brute_force_detection': {
                'events': [APIAuditEventType.API_OAUTH_TOKEN_REJECTED, APIAuditEventType.API_ACCESS_DENIED],
                'threshold': 10,
                'time_window': 300,  # 5 minutes
                'severity': AlertSeverity.HIGH
            },
            'data_exfiltration_pattern': {
                'events': [APIAuditEventType.API_DATA_EXPORT, APIAuditEventType.API_CLASSIFIED_DATA_ACCESS],
                'threshold': 5,
                'time_window': 600,  # 10 minutes
                'severity': AlertSeverity.CRITICAL
            },
            'api_enumeration': {
                'events': [APIAuditEventType.API_ACCESS_DENIED],
                'threshold': 20,
                'time_window': 180,  # 3 minutes
                'severity': AlertSeverity.MEDIUM
            },
            'privilege_escalation': {
                'events': [APIAuditEventType.API_INSUFFICIENT_CLEARANCE],
                'threshold': 3,
                'time_window': 300,
                'severity': AlertSeverity.HIGH
            }
        }
    
    async def process_security_event(self, event_type: APIAuditEventType, 
                                   context: APIAuditContext) -> List[SecurityAlert]:
        """Process and correlate security events."""
        alerts = []
        
        try:
            # Store the event
            security_event = {
                'timestamp': datetime.utcnow(),
                'event_type': event_type,
                'context': context,
                'event_id': str(uuid.uuid4())
            }
            self.security_events.append(security_event)
            
            # Check correlation rules
            for rule_name, rule in self.correlation_rules.items():
                if event_type in rule['events']:
                    alert = await self._check_correlation_rule(rule_name, rule, context)
                    if alert:
                        alerts.append(alert)
            
        except Exception as e:
            self.logger.error(f"Security event correlation failed: {e}")
        
        return alerts
    
    async def _check_correlation_rule(self, rule_name: str, rule: Dict[str, Any], 
                                    context: APIAuditContext) -> Optional[SecurityAlert]:
        """Check if correlation rule is triggered."""
        try:
            current_time = datetime.utcnow()
            time_window = timedelta(seconds=rule['time_window'])\n            window_start = current_time - time_window
            \n            # Count relevant events in time window
            relevant_events = [
                event for event in self.security_events
                if (event['timestamp'] >= window_start and 
                   event['event_type'] in rule['events'] and
                   event['context'].client_ip == context.client_ip)
            ]
            \n            if len(relevant_events) >= rule['threshold']:
                # Generate security alert
                alert = SecurityAlert(
                    alert_id=str(uuid.uuid4()),
                    severity=rule['severity'],
                    category=AlertCategory.SECURITY_INCIDENT,
                    title=f\"{rule_name.replace('_', ' ').title()} Detected\",
                    description=f\"Detected {len(relevant_events)} {rule_name} events from {context.client_ip}\",
                    source_ip=context.client_ip,
                    affected_systems=[\"API Gateway\"],
                    indicators=[{
                        'type': 'ip_address',
                        'value': context.client_ip,
                        'confidence': 0.8
                    }],
                    recommended_actions=[
                        f\"Block IP address {context.client_ip}\",
                        \"Investigate user activity patterns\",
                        \"Review authentication logs\",
                        \"Consider implementing additional security controls\"
                    ],
                    compliance_impact=[
                        \"DoD 8500.01E - SI-4 (Information System Monitoring)\",
                        \"NIST 800-53 - IR-4 (Incident Handling)\"
                    ]
                )
                \n                return alert
            \n        except Exception as e:
            self.logger.error(f\"Correlation rule check failed for {rule_name}: {e}\")
        \n        return None


class APIAuditIntegration:
    """
    Main integration class for API Gateway audit functionality.
    
    Provides comprehensive audit integration between API Gateway operations
    and the DoD audit infrastructure.
    """
    
    def __init__(self, redis_url: str = "redis://localhost:6379"):
        """Initialize API audit integration."""
        self.logger = logging.getLogger(__name__)
        self.redis_client = None
        self.redis_url = redis_url
        
        # Audit components
        self.audit_logger = None
        self.compliance_reporter = None
        self.event_generator = None
        self.security_correlator = APISecurityCorrelator()
        
        # Metrics tracking
        self.audit_metrics = defaultdict(int)
        self.compliance_metrics = defaultdict(lambda: defaultdict(int))
        
    async def initialize(self) -> None:
        """Initialize audit integration."""
        try:
            # Initialize Redis client
            self.redis_client = await aioredis.from_url(self.redis_url)
            await self.redis_client.ping()
            
            # Initialize audit components
            self.audit_logger = AuditLogger()
            await self.audit_logger.initialize()
            
            self.compliance_reporter = ComplianceReporter()
            
            # Initialize event generator
            self.event_generator = APIAuditEventGenerator(self.audit_logger)
            
            # Start background tasks
            asyncio.create_task(self._metrics_collection_loop())
            asyncio.create_task(self._compliance_monitoring_loop())
            
            self.logger.info("API audit integration initialized")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize API audit integration: {e}")
            raise
    
    async def audit_api_request(self, method: str, endpoint: str, status_code: int,
                              response_time: float, user_id: str = None,
                              client_ip: str = "unknown", user_agent: str = None,
                              classification: ClassificationLevel = ClassificationLevel.UNCLASSIFIED,
                              additional_context: Dict[str, Any] = None) -> str:
        """Audit an API request with full context."""
        try:
            # Create audit context
            context = APIAuditContext(
                request_id=str(uuid.uuid4()),
                endpoint=endpoint,
                method=method,
                user_id=user_id,
                client_ip=client_ip,
                user_agent=user_agent,
                classification_level=classification,
                response_status=status_code,
                response_time=response_time
            )
            
            # Determine event type based on request characteristics
            event_type = self._determine_api_event_type(method, endpoint, status_code, additional_context)
            
            # Generate audit event
            event_id = await self.event_generator.audit_api_request(
                context, event_type, additional_context
            )
            
            # Update metrics
            self.audit_metrics['total_api_requests'] += 1
            self.audit_metrics[f'status_{status_code//100}xx'] += 1
            
            # Check for security correlations
            if self._is_security_relevant(event_type, status_code):
                alerts = await self.security_correlator.process_security_event(event_type, context)
                
                # Process any generated alerts
                for alert in alerts:
                    await self._handle_security_alert(alert)
            
            return event_id
            
        except Exception as e:
            self.logger.error(f"API request audit failed: {e}")
            raise
    
    def _determine_api_event_type(self, method: str, endpoint: str, status_code: int,
                                 additional_context: Dict[str, Any] = None) -> APIAuditEventType:
        """Determine appropriate audit event type for API request."""
        # Check for authentication events
        if '/oauth/' in endpoint or '/auth/' in endpoint:
            if status_code == 200:
                return APIAuditEventType.API_OAUTH_TOKEN_VALIDATED
            else:
                return APIAuditEventType.API_OAUTH_TOKEN_REJECTED
        
        # Check for access control events
        if status_code == 403:
            return APIAuditEventType.API_ACCESS_DENIED
        elif status_code == 401:
            return APIAuditEventType.API_OAUTH_TOKEN_REJECTED
        
        # Check for data access events
        if additional_context and additional_context.get('classified_data'):
            return APIAuditEventType.API_CLASSIFIED_DATA_ACCESS
        
        # Check for export events
        if method == 'GET' and '/export' in endpoint:
            return APIAuditEventType.API_DATA_EXPORT
        
        # Check for security events
        if additional_context and additional_context.get('security_threat'):
            return APIAuditEventType.API_SECURITY_THREAT_DETECTED
        
        # Default to standard request
        if status_code < 400:
            return APIAuditEventType.API_ACCESS_GRANTED
        else:
            return APIAuditEventType.API_REQUEST_BLOCKED
    
    def _is_security_relevant(self, event_type: APIAuditEventType, status_code: int) -> bool:
        """Check if event is security-relevant for correlation."""
        security_events = [
            APIAuditEventType.API_OAUTH_TOKEN_REJECTED,
            APIAuditEventType.API_ACCESS_DENIED,
            APIAuditEventType.API_SECURITY_THREAT_DETECTED,
            APIAuditEventType.API_ATTACK_BLOCKED,
            APIAuditEventType.API_INSUFFICIENT_CLEARANCE
        ]
        
        return event_type in security_events or status_code >= 400
    
    async def _handle_security_alert(self, alert: SecurityAlert) -> None:
        """Handle security alert generated from correlation."""
        try:
            # Log the alert as an audit event
            await self.audit_logger.log_event(
                event_type=AuditEventType.SECURITY_INCIDENT,
                severity=AuditSeverity.HIGH,
                details={
                    'alert_id': alert.alert_id,
                    'title': alert.title,
                    'description': alert.description,
                    'indicators': alert.indicators,
                    'recommended_actions': alert.recommended_actions
                },
                source_ip=alert.source_ip
            )
            
            # Store alert for monitoring systems
            alert_data = asdict(alert)
            await self.redis_client.lpush("security_alerts", json.dumps(alert_data, default=str))
            await self.redis_client.ltrim("security_alerts", 0, 1000)  # Keep recent 1000
            
            self.logger.warning(f"Security alert generated: {alert.title}")
            
        except Exception as e:
            self.logger.error(f"Security alert handling failed: {e}")
    
    async def audit_sla_violation(self, target_name: str, measured_value: float,
                                target_value: float, severity: str) -> str:
        """Audit SLA violation event."""
        try:
            context = APIAuditContext(
                request_id=str(uuid.uuid4()),
                endpoint="/sla/monitoring",
                method="MONITOR",
                user_id="system",
                client_ip="127.0.0.1",
                classification_level=ClassificationLevel.UNCLASSIFIED
            )
            
            additional_data = {
                'sla_target': target_name,
                'measured_value': measured_value,
                'target_value': target_value,
                'violation_severity': severity
            }
            
            event_id = await self.event_generator.audit_api_request(
                context, APIAuditEventType.API_SLA_VIOLATION, additional_data
            )
            
            self.audit_metrics['sla_violations'] += 1
            
            return event_id
            
        except Exception as e:
            self.logger.error(f"SLA violation audit failed: {e}")
            raise
    
    async def audit_analytics_event(self, event_type: str, analysis_results: Dict[str, Any]) -> str:
        """Audit analytics and monitoring events."""
        try:
            context = APIAuditContext(
                request_id=str(uuid.uuid4()),
                endpoint="/analytics/processing",
                method="ANALYZE",
                user_id="system",
                client_ip="127.0.0.1",
                classification_level=ClassificationLevel.UNCLASSIFIED
            )
            
            additional_data = {
                'analytics_type': event_type,
                'results': analysis_results
            }
            
            # Determine API audit event type
            if 'anomaly' in event_type.lower():
                api_event_type = APIAuditEventType.API_ANOMALY_DETECTED
            elif 'pattern' in event_type.lower():
                api_event_type = APIAuditEventType.API_PATTERN_ANALYSIS
            else:
                api_event_type = APIAuditEventType.API_REQUEST_PROCESSED
            
            event_id = await self.event_generator.audit_api_request(
                context, api_event_type, additional_data
            )
            
            self.audit_metrics['analytics_events'] += 1
            
            return event_id
            
        except Exception as e:
            self.logger.error(f"Analytics event audit failed: {e}")
            raise
    
    async def _metrics_collection_loop(self) -> None:
        """Background loop for collecting audit metrics."""
        while True:
            try:
                # Store current metrics
                metrics_data = {
                    'timestamp': datetime.utcnow().isoformat(),
                    'audit_metrics': dict(self.audit_metrics),
                    'compliance_metrics': {
                        framework: dict(metrics) 
                        for framework, metrics in self.compliance_metrics.items()
                    }
                }
                
                await self.redis_client.set(
                    "api_audit_metrics",
                    json.dumps(metrics_data),
                    ex=3600  # Expire after 1 hour
                )
                
                await asyncio.sleep(300)  # Update every 5 minutes
                
            except Exception as e:
                self.logger.error(f"Metrics collection error: {e}")
                await asyncio.sleep(300)
    
    async def _compliance_monitoring_loop(self) -> None:
        """Background loop for compliance monitoring."""
        while True:
            try:
                # Check compliance status
                await self._check_compliance_status()
                
                await asyncio.sleep(3600)  # Check every hour
                
            except Exception as e:
                self.logger.error(f"Compliance monitoring error: {e}")
                await asyncio.sleep(3600)
    
    async def _check_compliance_status(self) -> None:
        """Check overall compliance status."""
        try:
            # Get audit event counts by type
            for framework in [ComplianceFramework.DOD_8500_01E, ComplianceFramework.NIST_SP_800_53]:
                # This is a simplified compliance check
                # In a real implementation, this would check specific compliance requirements
                
                total_events = sum(self.audit_metrics.values())
                security_events = (
                    self.audit_metrics.get('security_incidents', 0) +
                    self.audit_metrics.get('sla_violations', 0)
                )
                
                compliance_score = max(0, 100 - (security_events / max(total_events, 1)) * 100)
                
                self.compliance_metrics[framework.value]['compliance_score'] = compliance_score
                self.compliance_metrics[framework.value]['total_events'] = total_events
                self.compliance_metrics[framework.value]['security_events'] = security_events
            
        except Exception as e:
            self.logger.error(f"Compliance status check failed: {e}")
    
    async def generate_api_compliance_report(self, framework: ComplianceFramework,
                                           start_time: datetime,
                                           end_time: datetime) -> Dict[str, Any]:
        """Generate API-specific compliance report."""
        try:
            # This would integrate with the existing compliance reporter
            # to generate API-specific compliance reports
            
            report_data = {
                'framework': framework.value,
                'period': {
                    'start': start_time.isoformat(),
                    'end': end_time.isoformat()
                },
                'api_metrics': dict(self.audit_metrics),
                'compliance_score': self.compliance_metrics[framework.value].get('compliance_score', 0),
                'recommendations': await self._generate_compliance_recommendations(framework)
            }
            
            return report_data
            
        except Exception as e:
            self.logger.error(f"API compliance report generation failed: {e}")
            return {'error': str(e)}
    
    async def _generate_compliance_recommendations(self, framework: ComplianceFramework) -> List[str]:
        """Generate compliance recommendations."""
        recommendations = []
        
        try:
            metrics = self.compliance_metrics[framework.value]
            
            if metrics.get('security_events', 0) > 10:
                recommendations.append(
                    "High number of security events detected. Review API security controls."
                )
            
            if metrics.get('compliance_score', 100) < 90:
                recommendations.append(
                    "Compliance score below 90%. Investigate audit findings and implement corrective actions."
                )
            
            if self.audit_metrics.get('sla_violations', 0) > 5:
                recommendations.append(
                    "Multiple SLA violations detected. Review system performance and capacity."
                )
            
            if not recommendations:
                recommendations.append("API audit compliance is within acceptable parameters.")
            
        except Exception as e:
            self.logger.error(f"Compliance recommendations generation failed: {e}")
        
        return recommendations
    
    async def get_audit_metrics(self) -> Dict[str, Any]:
        """Get current audit metrics."""
        try:
            return {
                'timestamp': datetime.utcnow().isoformat(),
                'audit_metrics': dict(self.audit_metrics),
                'compliance_metrics': {
                    framework: dict(metrics)
                    for framework, metrics in self.compliance_metrics.items()
                },
                'security_alerts_count': await self.redis_client.llen("security_alerts")
            }
            
        except Exception as e:
            self.logger.error(f"Failed to get audit metrics: {e}")
            return {'error': str(e)}
    
    async def close(self) -> None:
        """Clean up audit integration resources."""
        if self.redis_client:
            await self.redis_client.close()
        
        self.logger.info("API audit integration closed")


if __name__ == "__main__":
    # Example usage
    async def main():
        integration = APIAuditIntegration()
        await integration.initialize()
        
        # Simulate API request auditing
        for i in range(20):
            status_code = 200 if i % 8 != 0 else (403 if i % 4 == 0 else 500)
            
            event_id = await integration.audit_api_request(
                method="GET",
                endpoint=f"/api/v1/data/{i % 5}",
                status_code=status_code,
                response_time=0.5 + (i % 3) * 0.1,
                user_id=f"user_{i % 10}",
                client_ip=f"192.168.1.{i % 254 + 1}",
                classification=ClassificationLevel.UNCLASSIFIED
            )
            
            print(f"Generated audit event: {event_id}")
        
        # Simulate SLA violation
        await integration.audit_sla_violation(
            target_name="API Availability",
            measured_value=98.5,
            target_value=99.9,
            severity="high"
        )
        
        # Get audit metrics
        metrics = await integration.get_audit_metrics()
        print(f"Audit Metrics: {json.dumps(metrics, indent=2)}")
        
        # Generate compliance report
        report = await integration.generate_api_compliance_report(
            ComplianceFramework.DOD_8500_01E,
            datetime.utcnow() - timedelta(hours=1),
            datetime.utcnow()
        )
        print(f"Compliance Report: {json.dumps(report, indent=2)}")
        
        await integration.close()
    
    asyncio.run(main())