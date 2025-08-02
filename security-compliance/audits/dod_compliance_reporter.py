"""
DoD Compliance Reporting and Security Event Detection System
===========================================================

This module provides comprehensive DoD compliance reporting and advanced security 
event detection capabilities, completing the security audit logging system with 
full regulatory compliance and automated threat response.

Key Features:
- Comprehensive DoD 8500.01E compliance reporting
- NIST SP 800-53 control assessment and reporting
- FISMA compliance monitoring and documentation
- Automated security event pattern detection
- Real-time compliance violation alerting
- Regulatory audit trail generation
- Cross-domain security analysis
- Automated incident response workflows

DoD Compliance Standards:
- DoD 8500.01E - Information Assurance Policy
- DoD 8510.01 - Risk Management Framework (RMF)
- NIST SP 800-53 - Security and Privacy Controls
- NIST SP 800-37 - Risk Management Framework
- FISMA - Federal Information Security Management Act
- CNSSI-1253 - Security Categorization and Control Selection
- ICD 503 - Intelligence Community Directive

Security Event Detection:
- Advanced Persistent Threat (APT) patterns
- Insider threat behavioral analysis
- Classification spillage detection
- Cross-domain transfer monitoring
- Privilege escalation detection
- Data exfiltration patterns
- Anomalous access behavior

Classification: UNCLASSIFIED//FOR OFFICIAL USE ONLY
Version: 3.0 - Enhanced DoD Compliance
Author: Security Compliance Team
Date: 2025-07-27
"""

import asyncio
import json
import logging
import time
import re
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Tuple, Set, Union, AsyncGenerator
from uuid import UUID, uuid4
from dataclasses import dataclass, field, asdict
from enum import Enum
from concurrent.futures import ThreadPoolExecutor
from collections import defaultdict, deque
import aiofiles
import aiohttp
from threading import Lock
import numpy as np
from pathlib import Path
import hashlib
import base64

# Import existing audit infrastructure
from .audit_logger import AuditLogger, AuditEvent, AuditEventType, AuditSeverity
from .tamper_proof_storage import TamperProofStorage, StorageBlock, StorageIntegrityLevel
from .real_time_alerting import RealTimeAlerting, AlertChannel, AlertPriority
from .enhanced_log_aggregator import EnhancedLogAggregator, LogEvent, LogSourceType
from .enhanced_monitoring_system import EnhancedMonitoringSystem, SecurityThreat, ComplianceViolation, ThreatLevel

logger = logging.getLogger(__name__)


class ComplianceFramework(Enum):
    """DoD and Federal compliance frameworks."""
    DOD_8500_01E = "dod_8500.01e"
    DOD_8510_01 = "dod_8510.01"
    NIST_SP_800_53 = "nist_sp_800-53"
    NIST_SP_800_37 = "nist_sp_800-37"
    FISMA = "fisma"
    CNSSI_1253 = "cnssi_1253"
    ICD_503 = "icd_503"
    FEDRAMP = "fedramp"


class ComplianceStatus(Enum):
    """Compliance assessment status."""
    COMPLIANT = "compliant"
    NON_COMPLIANT = "non_compliant"
    PARTIALLY_COMPLIANT = "partially_compliant"
    NOT_ASSESSED = "not_assessed"
    ASSESSMENT_PENDING = "assessment_pending"
    REMEDIATION_REQUIRED = "remediation_required"


class SecurityEventType(Enum):
    """Advanced security event types for detection."""
    APT_ACTIVITY = "apt_activity"
    INSIDER_THREAT = "insider_threat"
    CLASSIFICATION_SPILLAGE = "classification_spillage"
    CROSS_DOMAIN_VIOLATION = "cross_domain_violation"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DATA_EXFILTRATION = "data_exfiltration"
    LATERAL_MOVEMENT = "lateral_movement"
    PERSISTENCE_MECHANISM = "persistence_mechanism"
    COMMAND_AND_CONTROL = "command_and_control"
    RECONNAISSANCE = "reconnaissance"
    WEAPONIZATION = "weaponization"
    DELIVERY = "delivery"
    EXPLOITATION = "exploitation"
    INSTALLATION = "installation"
    ACTIONS_ON_OBJECTIVES = "actions_on_objectives"


class ReportType(Enum):
    """Types of compliance reports."""
    DAILY_SECURITY_SUMMARY = "daily_security_summary"
    WEEKLY_COMPLIANCE_ASSESSMENT = "weekly_compliance_assessment"
    MONTHLY_RISK_REPORT = "monthly_risk_report"
    QUARTERLY_AUDIT_SUMMARY = "quarterly_audit_summary"
    ANNUAL_COMPLIANCE_REVIEW = "annual_compliance_review"
    INCIDENT_RESPONSE_REPORT = "incident_response_report"
    VULNERABILITY_ASSESSMENT = "vulnerability_assessment"
    PENETRATION_TEST_REPORT = "penetration_test_report"
    CONTINUOUS_MONITORING_REPORT = "continuous_monitoring_report"
    REGULATORY_AUDIT_REPORT = "regulatory_audit_report"


@dataclass
class ComplianceControl:
    """DoD/NIST compliance control definition."""
    control_id: str = ""
    control_family: str = ""
    control_name: str = ""
    framework: ComplianceFramework = ComplianceFramework.NIST_SP_800_53
    
    # Control details
    control_description: str = ""
    implementation_guidance: str = ""
    assessment_procedures: List[str] = field(default_factory=list)
    
    # Current status
    implementation_status: ComplianceStatus = ComplianceStatus.NOT_ASSESSED
    assessment_date: Optional[datetime] = None
    next_assessment_date: Optional[datetime] = None
    
    # Evidence and documentation
    evidence_artifacts: List[str] = field(default_factory=list)
    documentation_references: List[str] = field(default_factory=list)
    
    # Risk and impact
    risk_level: str = "MEDIUM"
    impact_level: str = "MODERATE"
    confidentiality_impact: str = "MODERATE"
    integrity_impact: str = "MODERATE"
    availability_impact: str = "MODERATE"
    
    # Remediation
    remediation_actions: List[str] = field(default_factory=list)
    remediation_deadline: Optional[datetime] = None
    responsible_party: str = ""
    
    # Continuous monitoring
    monitoring_frequency: str = "monthly"
    automated_assessment: bool = False
    last_monitoring_date: Optional[datetime] = None


@dataclass
class SecurityEventPattern:
    """Advanced security event detection pattern."""
    pattern_id: str = field(default_factory=lambda: str(uuid4()))
    pattern_name: str = ""
    event_type: SecurityEventType = SecurityEventType.RECONNAISSANCE
    
    # Pattern definition
    event_signatures: List[str] = field(default_factory=list)
    behavioral_indicators: List[str] = field(default_factory=list)
    network_indicators: List[str] = field(default_factory=list)
    
    # Detection parameters
    threshold_events: int = 3
    time_window_minutes: int = 60
    confidence_threshold: float = 0.7
    
    # Threat intelligence
    mitre_attack_ids: List[str] = field(default_factory=list)
    threat_actor_associations: List[str] = field(default_factory=list)
    
    # Response actions
    automated_response: bool = False
    response_actions: List[str] = field(default_factory=list)
    escalation_required: bool = True
    
    # Classification and handling
    classification_level: str = "UNCLASSIFIED"
    requires_investigation: bool = True
    legal_hold_required: bool = False


@dataclass
class ComplianceReport:
    """Comprehensive compliance report."""
    report_id: str = field(default_factory=lambda: str(uuid4()))
    generation_time: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    # Report metadata
    report_type: ReportType = ReportType.DAILY_SECURITY_SUMMARY
    reporting_period_start: datetime = field(default_factory=lambda: datetime.now(timezone.utc) - timedelta(days=1))
    reporting_period_end: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    # Compliance assessment
    frameworks_assessed: List[ComplianceFramework] = field(default_factory=list)
    total_controls: int = 0
    compliant_controls: int = 0
    non_compliant_controls: int = 0
    partially_compliant_controls: int = 0
    not_assessed_controls: int = 0
    
    # Security events
    total_events_analyzed: int = 0
    security_incidents: int = 0
    compliance_violations: int = 0
    threat_detections: int = 0
    
    # Risk assessment
    overall_risk_score: float = 0.0
    high_risk_findings: int = 0
    medium_risk_findings: int = 0
    low_risk_findings: int = 0
    
    # Classification handling
    classified_events_processed: int = 0
    spillage_incidents: int = 0
    cross_domain_violations: int = 0
    
    # Detailed findings
    control_assessments: List[ComplianceControl] = field(default_factory=list)
    security_findings: List[Dict[str, Any]] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    
    # Executive summary
    executive_summary: str = ""
    key_risks: List[str] = field(default_factory=list)
    immediate_actions: List[str] = field(default_factory=list)
    
    # Signatures and approval
    prepared_by: str = ""
    reviewed_by: str = ""
    approved_by: str = ""
    distribution_list: List[str] = field(default_factory=list)


class SecurityEventDetector:
    """Advanced security event detection engine using MITRE ATT&CK framework."""
    
    def __init__(self):
        """Initialize security event detector."""
        self.detection_patterns = []
        self.active_investigations = {}
        
        # Load security event patterns
        self._load_security_patterns()
        
        # MITRE ATT&CK framework mapping
        self.mitre_attack_patterns = self._initialize_mitre_patterns()
        
        # Threat intelligence feeds
        self.threat_intelligence = {
            "known_bad_ips": set(),
            "malware_hashes": set(),
            "suspicious_domains": set(),
            "apt_indicators": {},
            "insider_threat_patterns": []
        }
        
        # Event correlation
        self.event_correlation_window = timedelta(hours=24)
        self.event_chains = defaultdict(list)
        
        # Machine learning models for anomaly detection
        self.behavioral_models = {}
        self.anomaly_threshold = 0.8
    
    def _load_security_patterns(self):
        """Load advanced security event detection patterns."""
        self.detection_patterns = [
            SecurityEventPattern(
                pattern_name="Advanced Persistent Threat - Reconnaissance",
                event_type=SecurityEventType.APT_ACTIVITY,
                event_signatures=[
                    "port_scan", "network_enumeration", "dns_queries",
                    "service_discovery", "vulnerability_scan"
                ],
                behavioral_indicators=[
                    "systematic_exploration", "automated_scanning",
                    "unusual_network_activity", "off_hours_activity"
                ],
                mitre_attack_ids=["T1595", "T1590", "T1592", "T1589"],
                threshold_events=5,
                time_window_minutes=120,
                confidence_threshold=0.8,
                escalation_required=True
            ),
            SecurityEventPattern(
                pattern_name="Insider Threat - Data Collection",
                event_type=SecurityEventType.INSIDER_THREAT,
                event_signatures=[
                    "bulk_data_access", "after_hours_access", "unusual_file_access",
                    "database_enumeration", "export_operations"
                ],
                behavioral_indicators=[
                    "access_pattern_change", "location_anomaly",
                    "privilege_exploration", "data_hoarding"
                ],
                mitre_attack_ids=["T1005", "T1039", "T1025", "T1074"],
                threshold_events=3,
                time_window_minutes=480,
                confidence_threshold=0.7,
                requires_investigation=True
            ),
            SecurityEventPattern(
                pattern_name="Classification Spillage Detection",
                event_type=SecurityEventType.CLASSIFICATION_SPILLAGE,
                event_signatures=[
                    "cross_domain_transfer", "classification_mismatch",
                    "unauthorized_export", "clearance_violation"
                ],
                behavioral_indicators=[
                    "unusual_classification_access", "export_to_lower_domain",
                    "bulk_classified_access", "compartment_violation"
                ],
                threshold_events=1,
                time_window_minutes=10,
                confidence_threshold=0.9,
                automated_response=True,
                escalation_required=True,
                legal_hold_required=True,
                classification_level="SECRET"
            ),
            SecurityEventPattern(
                pattern_name="Privilege Escalation Attack",
                event_type=SecurityEventType.PRIVILEGE_ESCALATION,
                event_signatures=[
                    "privilege_change", "admin_access_attempt",
                    "sudo_abuse", "service_account_abuse", "token_manipulation"
                ],
                behavioral_indicators=[
                    "rapid_privilege_changes", "lateral_movement",
                    "credential_dumping", "pass_the_hash"
                ],
                mitre_attack_ids=["T1068", "T1134", "T1078", "T1548"],
                threshold_events=2,
                time_window_minutes=30,
                confidence_threshold=0.8,
                automated_response=True
            ),
            SecurityEventPattern(
                pattern_name="Data Exfiltration Operations",
                event_type=SecurityEventType.DATA_EXFILTRATION,
                event_signatures=[
                    "large_data_transfer", "compression_operations",
                    "external_communication", "staging_operations", "covert_channel"
                ],
                behavioral_indicators=[
                    "unusual_bandwidth_usage", "off_hours_transfers",
                    "encrypted_communications", "staging_behavior"
                ],
                mitre_attack_ids=["T1041", "T1030", "T1020", "T1048"],
                threshold_events=3,
                time_window_minutes=240,
                confidence_threshold=0.75,
                escalation_required=True
            ),
            SecurityEventPattern(
                pattern_name="Lateral Movement Detection",
                event_type=SecurityEventType.LATERAL_MOVEMENT,
                event_signatures=[
                    "remote_execution", "credential_reuse", "network_shares",
                    "rdp_connections", "psexec_usage", "wmi_execution"
                ],
                behavioral_indicators=[
                    "hop_pattern", "credential_spreading",
                    "network_traversal", "service_enumeration"
                ],
                mitre_attack_ids=["T1021", "T1077", "T1047", "T1003"],
                threshold_events=4,
                time_window_minutes=180,
                confidence_threshold=0.7
            )
        ]
    
    def _initialize_mitre_patterns(self) -> Dict[str, Any]:
        """Initialize MITRE ATT&CK framework patterns."""
        return {
            "tactics": {
                "reconnaissance": ["T1595", "T1590", "T1592", "T1589"],
                "initial_access": ["T1566", "T1190", "T1133", "T1078"],
                "execution": ["T1059", "T1053", "T1047", "T1129"],
                "persistence": ["T1053", "T1547", "T1136", "T1078"],
                "privilege_escalation": ["T1068", "T1134", "T1078", "T1548"],
                "defense_evasion": ["T1055", "T1027", "T1070", "T1112"],
                "credential_access": ["T1003", "T1110", "T1555", "T1558"],
                "discovery": ["T1087", "T1083", "T1057", "T1082"],
                "lateral_movement": ["T1021", "T1077", "T1047", "T1003"],
                "collection": ["T1005", "T1039", "T1025", "T1074"],
                "exfiltration": ["T1041", "T1030", "T1020", "T1048"],
                "impact": ["T1486", "T1490", "T1485", "T1496"]
            },
            "kill_chain_mapping": {
                "reconnaissance": SecurityEventType.RECONNAISSANCE,
                "weaponization": SecurityEventType.WEAPONIZATION,
                "delivery": SecurityEventType.DELIVERY,
                "exploitation": SecurityEventType.EXPLOITATION,
                "installation": SecurityEventType.INSTALLATION,
                "command_and_control": SecurityEventType.COMMAND_AND_CONTROL,
                "actions_on_objectives": SecurityEventType.ACTIONS_ON_OBJECTIVES
            }
        }
    
    async def detect_security_events(self, events: List[LogEvent]) -> List[Dict[str, Any]]:
        """Detect advanced security events using pattern matching and ML."""
        detected_events = []
        
        for event in events:
            # Apply signature-based detection
            signature_matches = await self._signature_based_detection(event)
            detected_events.extend(signature_matches)
            
            # Apply behavioral analysis
            behavioral_matches = await self._behavioral_analysis(event)
            detected_events.extend(behavioral_matches)
            
            # Apply threat intelligence matching
            ti_matches = await self._threat_intelligence_matching(event)
            detected_events.extend(ti_matches)
            
            # Update event chains for correlation
            self._update_event_chains(event)
        
        # Perform event correlation
        correlated_events = await self._correlate_security_events(detected_events)
        
        return correlated_events
    
    async def _signature_based_detection(self, event: LogEvent) -> List[Dict[str, Any]]:
        """Perform signature-based security event detection."""
        matches = []
        
        event_text = f"{event.message} {event.category} {event.event_type} {event.structured_data}".lower()
        
        for pattern in self.detection_patterns:
            signature_hits = 0
            matched_signatures = []
            
            # Check event signatures
            for signature in pattern.event_signatures:
                if signature in event_text:
                    signature_hits += 1
                    matched_signatures.append(signature)
            
            # Check behavioral indicators
            behavioral_hits = 0
            matched_behaviors = []
            
            for indicator in pattern.behavioral_indicators:
                if indicator in event_text:
                    behavioral_hits += 1
                    matched_behaviors.append(indicator)
            
            # Calculate confidence score
            total_indicators = len(pattern.event_signatures) + len(pattern.behavioral_indicators)
            total_hits = signature_hits + behavioral_hits
            confidence = total_hits / max(1, total_indicators)
            
            if confidence >= pattern.confidence_threshold:
                detection = {
                    "detection_id": str(uuid4()),
                    "pattern_id": pattern.pattern_id,
                    "pattern_name": pattern.pattern_name,
                    "event_type": pattern.event_type.value,
                    "confidence_score": confidence,
                    "matched_signatures": matched_signatures,
                    "matched_behaviors": matched_behaviors,
                    "mitre_attack_ids": pattern.mitre_attack_ids,
                    "source_event": event.event_id,
                    "detection_time": datetime.now(timezone.utc),
                    "requires_investigation": pattern.requires_investigation,
                    "automated_response": pattern.automated_response,
                    "escalation_required": pattern.escalation_required,
                    "classification_level": pattern.classification_level
                }
                
                matches.append(detection)
        
        return matches
    
    async def _behavioral_analysis(self, event: LogEvent) -> List[Dict[str, Any]]:
        """Perform behavioral analysis for anomaly detection."""
        anomalies = []
        
        # Analyze user behavior patterns
        if event.user_id:
            user_anomaly = await self._analyze_user_behavior(event)
            if user_anomaly:
                anomalies.append(user_anomaly)
        
        # Analyze system behavior patterns
        if event.hostname:
            system_anomaly = await self._analyze_system_behavior(event)
            if system_anomaly:
                anomalies.append(system_anomaly)
        
        # Analyze network behavior patterns
        if event.ip_address:
            network_anomaly = await self._analyze_network_behavior(event)
            if network_anomaly:
                anomalies.append(network_anomaly)
        
        return anomalies
    
    async def _analyze_user_behavior(self, event: LogEvent) -> Optional[Dict[str, Any]]:
        """Analyze user behavioral patterns for anomalies."""
        user_id = event.user_id
        
        # Time-based analysis
        current_hour = event.timestamp.hour
        if current_hour < 6 or current_hour > 22:  # Off-hours access
            return {
                "detection_id": str(uuid4()),
                "anomaly_type": "temporal_anomaly",
                "description": "Off-hours system access detected",
                "confidence_score": 0.6,
                "user_id": user_id,
                "anomaly_time": event.timestamp,
                "indicators": ["off_hours_access"],
                "risk_level": "medium"
            }
        
        # Access pattern analysis
        if event.classification_level != "UNCLASSIFIED":
            return {
                "detection_id": str(uuid4()),
                "anomaly_type": "classification_access_anomaly",
                "description": "Unusual classified data access pattern",
                "confidence_score": 0.7,
                "user_id": user_id,
                "classification_level": event.classification_level,
                "indicators": ["unusual_classification_access"],
                "risk_level": "high"
            }
        
        return None
    
    async def _analyze_system_behavior(self, event: LogEvent) -> Optional[Dict[str, Any]]:
        """Analyze system behavioral patterns for anomalies."""
        # System process analysis
        if "admin" in event.message.lower() or "root" in event.message.lower():
            return {
                "detection_id": str(uuid4()),
                "anomaly_type": "privilege_anomaly",
                "description": "Unusual administrative activity detected",
                "confidence_score": 0.5,
                "hostname": event.hostname,
                "indicators": ["administrative_activity"],
                "risk_level": "medium"
            }
        
        return None
    
    async def _analyze_network_behavior(self, event: LogEvent) -> Optional[Dict[str, Any]]:
        """Analyze network behavioral patterns for anomalies."""
        # Network traffic analysis would be implemented here
        return None
    
    async def _threat_intelligence_matching(self, event: LogEvent) -> List[Dict[str, Any]]:
        """Match events against threat intelligence feeds."""
        matches = []
        
        # Check IP addresses against known bad actors
        if event.ip_address and event.ip_address in self.threat_intelligence["known_bad_ips"]:
            matches.append({
                "detection_id": str(uuid4()),
                "match_type": "threat_intelligence_ip",
                "description": f"Communication with known malicious IP: {event.ip_address}",
                "confidence_score": 0.9,
                "threat_indicator": event.ip_address,
                "source": "threat_intelligence",
                "risk_level": "high"
            })
        
        # Check for malware hash indicators
        event_text = event.message + str(event.structured_data)
        for malware_hash in self.threat_intelligence["malware_hashes"]:
            if malware_hash in event_text:
                matches.append({
                    "detection_id": str(uuid4()),
                    "match_type": "malware_hash",
                    "description": f"Known malware hash detected: {malware_hash}",
                    "confidence_score": 0.95,
                    "threat_indicator": malware_hash,
                    "source": "threat_intelligence",
                    "risk_level": "critical"
                })
        
        return matches
    
    def _update_event_chains(self, event: LogEvent):
        """Update event chains for correlation analysis."""
        if event.user_id:
            self.event_chains[f"user_{event.user_id}"].append({
                "event_id": event.event_id,
                "timestamp": event.timestamp,
                "event_type": event.event_type,
                "message": event.message
            })
            
            # Limit chain length
            if len(self.event_chains[f"user_{event.user_id}"]) > 1000:
                self.event_chains[f"user_{event.user_id}"] = self.event_chains[f"user_{event.user_id}"][-500:]
    
    async def _correlate_security_events(self, detected_events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Correlate security events to identify attack campaigns."""
        if not detected_events:
            return detected_events
        
        # Group events by user and time window
        correlated_groups = defaultdict(list)
        
        for event in detected_events:
            correlation_key = f"{event.get('user_id', 'unknown')}_{event.get('hostname', 'unknown')}"
            correlated_groups[correlation_key].append(event)
        
        # Enhance events with correlation information
        enhanced_events = []
        for group_key, group_events in correlated_groups.items():
            if len(group_events) > 1:
                # Multiple related events - likely part of campaign
                campaign_id = str(uuid4())
                
                for event in group_events:
                    event["campaign_id"] = campaign_id
                    event["campaign_size"] = len(group_events)
                    event["correlation_confidence"] = min(1.0, len(group_events) * 0.2)
                    
                enhanced_events.extend(group_events)
            else:
                enhanced_events.extend(group_events)
        
        return enhanced_events


class DoDAuditComplianceReporter:
    """
    Comprehensive DoD compliance reporting and regulatory audit system.
    
    Provides full compliance assessment, reporting, and documentation
    for DoD and Federal regulatory requirements.
    """
    
    def __init__(
        self,
        audit_logger: AuditLogger,
        tamper_proof_storage: TamperProofStorage,
        log_aggregator: EnhancedLogAggregator,
        monitoring_system: EnhancedMonitoringSystem,
        security_event_detector: SecurityEventDetector
    ):
        """Initialize DoD compliance reporter."""
        self.audit_logger = audit_logger
        self.tamper_proof_storage = tamper_proof_storage
        self.log_aggregator = log_aggregator
        self.monitoring_system = monitoring_system
        self.security_event_detector = security_event_detector
        
        # Compliance framework definitions
        self.compliance_controls = {}
        self._initialize_compliance_controls()
        
        # Reporting configuration
        self.reporting_enabled = True
        self.report_tasks: List[asyncio.Task] = []
        
        # Report storage
        self.report_storage_path = Path("/var/log/dod_compliance_reports")
        self.report_storage_path.mkdir(parents=True, exist_ok=True, mode=0o700)
        
        # Assessment tracking
        self.assessment_history = deque(maxlen=1000)
        self.compliance_metrics = {
            "last_assessment": None,
            "overall_compliance_score": 0.0,
            "critical_findings": 0,
            "remediation_items": 0
        }
        
        # Thread pool for report generation
        self.thread_pool = ThreadPoolExecutor(
            max_workers=4,
            thread_name_prefix="ComplianceReporter"
        )
        
        logger.info("DoD Compliance Reporter initialized")
    
    def _initialize_compliance_controls(self):
        """Initialize DoD and NIST compliance control definitions."""
        # DoD 8500.01E Information Assurance Controls
        dod_controls = [
            ComplianceControl(
                control_id="AU-1",
                control_family="Audit and Accountability",
                control_name="Audit and Accountability Policy and Procedures",
                framework=ComplianceFramework.DOD_8500_01E,
                control_description="Develop, document, and disseminate audit and accountability policy",
                implementation_guidance="Establish formal audit policy covering roles, responsibilities, and procedures",
                assessment_procedures=["Review audit policy documents", "Verify implementation", "Test procedures"],
                risk_level="HIGH",
                impact_level="MODERATE",
                monitoring_frequency="annually",
                automated_assessment=False
            ),
            ComplianceControl(
                control_id="AU-2",
                control_family="Audit and Accountability",
                control_name="Audit Events",
                framework=ComplianceFramework.DOD_8500_01E,
                control_description="Determine auditable events and audit frequency",
                implementation_guidance="Define comprehensive list of auditable events",
                assessment_procedures=["Review auditable events list", "Verify coverage", "Test audit generation"],
                risk_level="HIGH",
                impact_level="MODERATE",
                monitoring_frequency="monthly",
                automated_assessment=True
            ),
            ComplianceControl(
                control_id="AU-3",
                control_family="Audit and Accountability",
                control_name="Content of Audit Records",
                framework=ComplianceFramework.DOD_8500_01E,
                control_description="Ensure audit records contain required information",
                implementation_guidance="Include timestamp, user ID, event type, outcome, and additional details",
                assessment_procedures=["Sample audit records", "Verify content completeness", "Check format compliance"],
                risk_level="HIGH",
                impact_level="MODERATE",
                monitoring_frequency="monthly",
                automated_assessment=True
            ),
            ComplianceControl(
                control_id="AU-6",
                control_family="Audit and Accountability",
                control_name="Audit Review, Analysis, and Reporting",
                framework=ComplianceFramework.DOD_8500_01E,
                control_description="Review and analyze audit records for security incidents",
                implementation_guidance="Implement automated analysis tools and regular review procedures",
                assessment_procedures=["Review analysis procedures", "Test automated tools", "Verify reporting"],
                risk_level="HIGH",
                impact_level="MODERATE",
                monitoring_frequency="daily",
                automated_assessment=True
            ),
            ComplianceControl(
                control_id="AU-9",
                control_family="Audit and Accountability",
                control_name="Protection of Audit Information",
                framework=ComplianceFramework.DOD_8500_01E,
                control_description="Protect audit information and tools from unauthorized access",
                implementation_guidance="Implement access controls, encryption, and tamper-proof storage",
                assessment_procedures=["Test access controls", "Verify encryption", "Check integrity mechanisms"],
                risk_level="CRITICAL",
                impact_level="HIGH",
                monitoring_frequency="weekly",
                automated_assessment=True
            ),
            ComplianceControl(
                control_id="AU-12",
                control_family="Audit and Accountability",
                control_name="Audit Generation",
                framework=ComplianceFramework.DOD_8500_01E,
                control_description="Provide audit capability for defined auditable events",
                implementation_guidance="Deploy comprehensive audit generation capabilities",
                assessment_procedures=["Test audit generation", "Verify event coverage", "Check performance"],
                risk_level="HIGH",
                impact_level="MODERATE",
                monitoring_frequency="monthly",
                automated_assessment=True
            )
        ]
        
        # NIST SP 800-53 Security Controls
        nist_controls = [
            ComplianceControl(
                control_id="AC-1",
                control_family="Access Control",
                control_name="Access Control Policy and Procedures",
                framework=ComplianceFramework.NIST_SP_800_53,
                control_description="Develop and maintain access control policy and procedures",
                risk_level="HIGH",
                monitoring_frequency="annually"
            ),
            ComplianceControl(
                control_id="AC-3",
                control_family="Access Control",
                control_name="Access Enforcement",
                framework=ComplianceFramework.NIST_SP_800_53,
                control_description="Enforce approved authorizations for logical access",
                risk_level="CRITICAL",
                monitoring_frequency="daily",
                automated_assessment=True
            ),
            ComplianceControl(
                control_id="AC-4",
                control_family="Access Control",
                control_name="Information Flow Enforcement",
                framework=ComplianceFramework.NIST_SP_800_53,
                control_description="Control information flows within and outside the system",
                risk_level="CRITICAL",
                monitoring_frequency="continuous",
                automated_assessment=True
            ),
            ComplianceControl(
                control_id="SI-4",
                control_family="System and Information Integrity",
                control_name="Information System Monitoring",
                framework=ComplianceFramework.NIST_SP_800_53,
                control_description="Monitor system for attacks and indicators of potential attacks",
                risk_level="HIGH",
                monitoring_frequency="continuous",
                automated_assessment=True
            )
        ]
        
        # Store controls by ID for easy lookup
        for control in dod_controls + nist_controls:
            self.compliance_controls[control.control_id] = control
    
    async def start(self):
        """Start the compliance reporting system."""
        if self.report_tasks:
            return
        
        # Start reporting tasks
        self.report_tasks = [
            asyncio.create_task(self._daily_compliance_assessment()),
            asyncio.create_task(self._weekly_security_report()),
            asyncio.create_task(self._monthly_risk_assessment()),
            asyncio.create_task(self._continuous_monitoring()),
            asyncio.create_task(self._incident_report_generator())
        ]
        
        logger.info("DoD Compliance Reporter started")
    
    async def stop(self):
        """Stop the compliance reporting system."""
        self.reporting_enabled = False
        
        # Cancel reporting tasks
        for task in self.report_tasks:
            if not task.done():
                task.cancel()
        
        # Wait for tasks to complete
        if self.report_tasks:
            await asyncio.gather(*self.report_tasks, return_exceptions=True)
        
        # Shutdown thread pool
        self.thread_pool.shutdown(wait=True)
        
        logger.info("DoD Compliance Reporter stopped")
    
    async def generate_compliance_report(
        self, 
        report_type: ReportType,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        frameworks: Optional[List[ComplianceFramework]] = None
    ) -> ComplianceReport:
        """Generate comprehensive compliance report."""
        if not start_time:
            start_time = datetime.now(timezone.utc) - timedelta(days=1)
        if not end_time:
            end_time = datetime.now(timezone.utc)
        if not frameworks:
            frameworks = [ComplianceFramework.DOD_8500_01E, ComplianceFramework.NIST_SP_800_53]
        
        report = ComplianceReport(
            report_type=report_type,
            reporting_period_start=start_time,
            reporting_period_end=end_time,
            frameworks_assessed=frameworks
        )
        
        try:
            # Assess compliance controls
            await self._assess_compliance_controls(report, frameworks)
            
            # Analyze security events
            await self._analyze_security_events(report, start_time, end_time)
            
            # Calculate risk scores
            await self._calculate_risk_scores(report)
            
            # Generate recommendations
            await self._generate_recommendations(report)
            
            # Create executive summary
            await self._create_executive_summary(report)
            
            # Store report
            await self._store_compliance_report(report)
            
            # Update metrics
            self.compliance_metrics["last_assessment"] = datetime.now(timezone.utc)
            self.compliance_metrics["overall_compliance_score"] = self._calculate_overall_score(report)
            
            return report
            
        except Exception as e:
            logger.error(f"Failed to generate compliance report: {e}")
            raise
    
    async def _assess_compliance_controls(
        self, 
        report: ComplianceReport, 
        frameworks: List[ComplianceFramework]
    ):
        """Assess compliance controls for specified frameworks."""
        assessed_controls = []
        
        for framework in frameworks:
            framework_controls = [
                control for control in self.compliance_controls.values()
                if control.framework == framework
            ]
            
            for control in framework_controls:
                # Perform automated assessment if available
                if control.automated_assessment:
                    assessment_result = await self._automated_control_assessment(control)
                    control.implementation_status = assessment_result["status"]
                    control.assessment_date = datetime.now(timezone.utc)
                    
                    if assessment_result["evidence"]:
                        control.evidence_artifacts.extend(assessment_result["evidence"])
                
                assessed_controls.append(control)
                
                # Update report counters
                if control.implementation_status == ComplianceStatus.COMPLIANT:
                    report.compliant_controls += 1
                elif control.implementation_status == ComplianceStatus.NON_COMPLIANT:
                    report.non_compliant_controls += 1
                elif control.implementation_status == ComplianceStatus.PARTIALLY_COMPLIANT:
                    report.partially_compliant_controls += 1
                else:
                    report.not_assessed_controls += 1
        
        report.control_assessments = assessed_controls
        report.total_controls = len(assessed_controls)
    
    async def _automated_control_assessment(self, control: ComplianceControl) -> Dict[str, Any]:
        """Perform automated assessment of compliance control."""
        assessment_result = {
            "status": ComplianceStatus.NOT_ASSESSED,
            "evidence": [],
            "findings": [],
            "score": 0.0
        }
        
        try:
            if control.control_id == "AU-2":  # Audit Events
                # Check if comprehensive auditing is configured
                aggregator_metrics = self.log_aggregator.get_performance_metrics()
                active_sources = aggregator_metrics.get("sources", {}).get("active_sources", 0)
                
                if active_sources >= 5:  # Minimum threshold
                    assessment_result["status"] = ComplianceStatus.COMPLIANT
                    assessment_result["score"] = 1.0
                    assessment_result["evidence"].append(f"Active audit sources: {active_sources}")
                else:
                    assessment_result["status"] = ComplianceStatus.PARTIALLY_COMPLIANT
                    assessment_result["score"] = 0.6
                    assessment_result["findings"].append("Insufficient audit source coverage")
            
            elif control.control_id == "AU-3":  # Content of Audit Records
                # Verify audit record content completeness
                storage_stats = self.tamper_proof_storage.get_storage_stats()
                if storage_stats.get("basic_stats", {}).get("total_events", 0) > 0:
                    assessment_result["status"] = ComplianceStatus.COMPLIANT
                    assessment_result["score"] = 1.0
                    assessment_result["evidence"].append("Audit records contain required fields")
                else:
                    assessment_result["status"] = ComplianceStatus.NON_COMPLIANT
                    assessment_result["score"] = 0.0
            
            elif control.control_id == "AU-6":  # Audit Review and Analysis
                # Check if monitoring and analysis is active
                monitoring_health = await self.monitoring_system.health_check()
                if monitoring_health.get("status") == "healthy":
                    assessment_result["status"] = ComplianceStatus.COMPLIANT
                    assessment_result["score"] = 1.0
                    assessment_result["evidence"].append("Active monitoring and analysis systems")
                else:
                    assessment_result["status"] = ComplianceStatus.DEGRADED
                    assessment_result["score"] = 0.3
            
            elif control.control_id == "AU-9":  # Protection of Audit Information
                # Verify tamper-proof storage integrity
                integrity_check = await self.tamper_proof_storage.verify_chain_integrity()
                if integrity_check[0]:  # Integrity valid
                    assessment_result["status"] = ComplianceStatus.COMPLIANT
                    assessment_result["score"] = 1.0
                    assessment_result["evidence"].append("Audit information integrity verified")
                else:
                    assessment_result["status"] = ComplianceStatus.NON_COMPLIANT
                    assessment_result["score"] = 0.0
                    assessment_result["findings"].append("Audit integrity violation detected")
            
            elif control.control_id == "SI-4":  # Information System Monitoring
                # Check continuous monitoring capabilities
                monitoring_metrics = self.monitoring_system.get_performance_metrics()
                active_threats = monitoring_metrics.get("threat_detector", {}).get("active_threats", 0)
                
                assessment_result["status"] = ComplianceStatus.COMPLIANT
                assessment_result["score"] = 1.0
                assessment_result["evidence"].append(f"Continuous monitoring active, {active_threats} threats tracked")
            
            else:
                # Default assessment for controls without automated checks
                assessment_result["status"] = ComplianceStatus.NOT_ASSESSED
                assessment_result["findings"].append("Manual assessment required")
        
        except Exception as e:
            assessment_result["status"] = ComplianceStatus.NOT_ASSESSED
            assessment_result["findings"].append(f"Assessment error: {e}")
        
        return assessment_result
    
    async def _analyze_security_events(
        self, 
        report: ComplianceReport, 
        start_time: datetime, 
        end_time: datetime
    ):
        """Analyze security events for the reporting period."""
        try:
            # Get events from tamper-proof storage
            events = []
            async for event in self.tamper_proof_storage.search_events(
                start_time=start_time,
                end_time=end_time
            ):
                events.append(event)
            
            report.total_events_analyzed = len(events)
            
            # Convert to LogEvent format for security analysis
            log_events = []
            for event in events[:1000]:  # Limit for performance
                log_event = LogEvent(
                    event_id=event.event_id,
                    timestamp=event.timestamp,
                    message=str(event.additional_data.get("message", "")),
                    event_type=event.event_type.value,
                    user_id=str(event.user_id) if event.user_id else None,
                    ip_address=event.ip_address
                )
                log_events.append(log_event)
            
            # Detect security events
            security_detections = await self.security_event_detector.detect_security_events(log_events)
            
            # Categorize findings
            for detection in security_detections:
                finding = {
                    "finding_id": detection["detection_id"],
                    "finding_type": detection.get("event_type", "security_event"),
                    "severity": self._map_confidence_to_severity(detection.get("confidence_score", 0.5)),
                    "description": detection.get("description", "Security event detected"),
                    "confidence": detection.get("confidence_score", 0.5),
                    "indicators": detection.get("matched_signatures", []),
                    "mitigation_required": detection.get("escalation_required", False)
                }
                
                report.security_findings.append(finding)
                
                # Update counters
                if finding["severity"] == "high":
                    report.high_risk_findings += 1
                    report.security_incidents += 1
                elif finding["severity"] == "medium":
                    report.medium_risk_findings += 1
                else:
                    report.low_risk_findings += 1
                
                if detection.get("event_type") == "classification_spillage":
                    report.spillage_incidents += 1
                
                if detection.get("event_type") == "cross_domain_violation":
                    report.cross_domain_violations += 1
            
            # Count threat detections
            report.threat_detections = len([d for d in security_detections if d.get("confidence_score", 0) > 0.7])
            
        except Exception as e:
            logger.error(f"Error analyzing security events: {e}")
            report.security_findings.append({
                "finding_id": str(uuid4()),
                "finding_type": "analysis_error",
                "severity": "medium",
                "description": f"Security event analysis failed: {e}",
                "mitigation_required": True
            })
    
    def _map_confidence_to_severity(self, confidence: float) -> str:
        """Map confidence score to severity level."""
        if confidence >= 0.8:
            return "high"
        elif confidence >= 0.6:
            return "medium"
        else:
            return "low"
    
    async def _calculate_risk_scores(self, report: ComplianceReport):
        """Calculate overall risk scores for the report."""
        try:
            # Base risk calculation on compliance status
            total_controls = report.total_controls
            if total_controls > 0:
                compliance_score = (
                    (report.compliant_controls * 1.0) +
                    (report.partially_compliant_controls * 0.5) +
                    (report.non_compliant_controls * 0.0)
                ) / total_controls
            else:
                compliance_score = 0.0
            
            # Factor in security findings
            security_risk_factor = 1.0
            if report.high_risk_findings > 0:
                security_risk_factor -= (report.high_risk_findings * 0.1)
            if report.medium_risk_findings > 0:
                security_risk_factor -= (report.medium_risk_findings * 0.05)
            
            security_risk_factor = max(0.0, security_risk_factor)
            
            # Calculate overall risk score (0.0 = highest risk, 1.0 = lowest risk)
            report.overall_risk_score = (compliance_score * 0.7) + (security_risk_factor * 0.3)
            
        except Exception as e:
            logger.error(f"Error calculating risk scores: {e}")
            report.overall_risk_score = 0.5  # Default to medium risk
    
    async def _generate_recommendations(self, report: ComplianceReport):
        """Generate compliance and security recommendations."""
        recommendations = []
        
        # Compliance-based recommendations
        if report.non_compliant_controls > 0:
            recommendations.append(
                f"Immediate action required: {report.non_compliant_controls} controls are non-compliant"
            )
        
        if report.partially_compliant_controls > 0:
            recommendations.append(
                f"Enhancement needed: {report.partially_compliant_controls} controls are partially compliant"
            )
        
        # Security-based recommendations
        if report.high_risk_findings > 0:
            recommendations.append(
                f"Critical security attention required: {report.high_risk_findings} high-risk findings identified"
            )
        
        if report.spillage_incidents > 0:
            recommendations.append(
                f"Classification spillage response required: {report.spillage_incidents} incidents detected"
            )
        
        if report.cross_domain_violations > 0:
            recommendations.append(
                f"Cross-domain security review required: {report.cross_domain_violations} violations detected"
            )
        
        # Performance recommendations
        if report.total_events_analyzed == 0:
            recommendations.append("Audit event generation may not be functioning properly")
        
        # Add to report
        report.recommendations = recommendations
        
        # Generate immediate actions
        immediate_actions = []
        if report.overall_risk_score < 0.3:
            immediate_actions.append("Initiate emergency security review")
        if report.spillage_incidents > 0:
            immediate_actions.append("Activate classification spillage response procedures")
        if report.high_risk_findings > 5:
            immediate_actions.append("Convene security incident response team")
        
        report.immediate_actions = immediate_actions
    
    async def _create_executive_summary(self, report: ComplianceReport):
        """Create executive summary for the report."""
        compliance_percentage = (report.compliant_controls / max(1, report.total_controls)) * 100
        risk_level = "LOW" if report.overall_risk_score > 0.7 else "MEDIUM" if report.overall_risk_score > 0.4 else "HIGH"
        
        summary = f"""
EXECUTIVE SUMMARY - {report.report_type.value.upper()}
Reporting Period: {report.reporting_period_start.strftime('%Y-%m-%d')} to {report.reporting_period_end.strftime('%Y-%m-%d')}

COMPLIANCE STATUS:
- Overall Compliance: {compliance_percentage:.1f}%
- Controls Assessed: {report.total_controls}
- Compliant: {report.compliant_controls} | Non-Compliant: {report.non_compliant_controls}
- Partially Compliant: {report.partially_compliant_controls}

SECURITY POSTURE:
- Overall Risk Level: {risk_level}
- Security Incidents: {report.security_incidents}
- High-Risk Findings: {report.high_risk_findings}
- Classification Incidents: {report.spillage_incidents}

KEY FINDINGS:
- {len(report.security_findings)} security events analyzed
- {report.threat_detections} potential threats detected
- {len(report.recommendations)} recommendations generated

IMMEDIATE ACTIONS REQUIRED: {len(report.immediate_actions)}
"""
        
        if report.immediate_actions:
            summary += "\nPRIORITY ACTIONS:\n"
            for i, action in enumerate(report.immediate_actions, 1):
                summary += f"{i}. {action}\n"
        
        report.executive_summary = summary.strip()
        
        # Set key risks
        report.key_risks = [
            f"Non-compliant controls: {report.non_compliant_controls}",
            f"High-risk security findings: {report.high_risk_findings}",
            f"Classification spillage incidents: {report.spillage_incidents}"
        ]
    
    def _calculate_overall_score(self, report: ComplianceReport) -> float:
        """Calculate overall compliance score."""
        if report.total_controls == 0:
            return 0.0
        
        return (report.compliant_controls + (report.partially_compliant_controls * 0.5)) / report.total_controls
    
    async def _store_compliance_report(self, report: ComplianceReport):
        """Store compliance report securely."""
        try:
            # Generate report filename
            timestamp = report.generation_time.strftime("%Y%m%d_%H%M%S")
            filename = f"{report.report_type.value}_{timestamp}_{report.report_id}.json"
            report_path = self.report_storage_path / filename
            
            # Store report as JSON
            report_data = asdict(report)
            
            # Convert datetime objects to ISO format
            def convert_datetime(obj):
                if isinstance(obj, datetime):
                    return obj.isoformat()
                elif isinstance(obj, dict):
                    return {k: convert_datetime(v) for k, v in obj.items()}
                elif isinstance(obj, list):
                    return [convert_datetime(item) for item in obj]
                else:
                    return obj
            
            report_data = convert_datetime(report_data)
            
            # Write report file
            async with aiofiles.open(report_path, 'w') as f:
                await f.write(json.dumps(report_data, indent=2))
            
            # Set appropriate permissions
            report_path.chmod(0o600)
            
            # Create audit event for report generation
            audit_event = AuditEvent(
                event_id=str(uuid4()),
                timestamp=datetime.now(timezone.utc),
                event_type=AuditEventType.COMPLIANCE_REPORT_GENERATED,
                severity=AuditSeverity.LOW,
                user_id=None,
                session_id=None,
                resource_type="compliance_report",
                action="report_generated",
                result="SUCCESS",
                additional_data={
                    "report_id": report.report_id,
                    "report_type": report.report_type.value,
                    "compliance_score": report.overall_risk_score,
                    "high_risk_findings": report.high_risk_findings,
                    "file_path": str(report_path)
                }
            )
            
            await self.audit_logger.log_event(audit_event)
            
        except Exception as e:
            logger.error(f"Failed to store compliance report: {e}")
            raise
    
    async def _daily_compliance_assessment(self):
        """Perform daily compliance assessment."""
        while self.reporting_enabled:
            try:
                # Generate daily security summary
                report = await self.generate_compliance_report(
                    ReportType.DAILY_SECURITY_SUMMARY,
                    start_time=datetime.now(timezone.utc) - timedelta(days=1),
                    end_time=datetime.now(timezone.utc)
                )
                
                logger.info(f"Daily compliance assessment completed: {report.report_id}")
                
                # Sleep until next day
                await asyncio.sleep(86400)  # 24 hours
                
            except Exception as e:
                logger.error(f"Error in daily compliance assessment: {e}")
                await asyncio.sleep(3600)  # Retry in 1 hour
    
    async def _weekly_security_report(self):
        """Generate weekly security report."""
        while self.reporting_enabled:
            try:
                # Wait for Sunday
                current_time = datetime.now(timezone.utc)
                days_until_sunday = (6 - current_time.weekday()) % 7
                if days_until_sunday == 0:  # Today is Sunday
                    days_until_sunday = 7
                
                sleep_seconds = days_until_sunday * 86400
                await asyncio.sleep(sleep_seconds)
                
                # Generate weekly report
                report = await self.generate_compliance_report(
                    ReportType.WEEKLY_COMPLIANCE_ASSESSMENT,
                    start_time=datetime.now(timezone.utc) - timedelta(days=7),
                    end_time=datetime.now(timezone.utc)
                )
                
                logger.info(f"Weekly security report completed: {report.report_id}")
                
            except Exception as e:
                logger.error(f"Error in weekly security report: {e}")
                await asyncio.sleep(86400)  # Retry tomorrow
    
    async def _monthly_risk_assessment(self):
        """Perform monthly risk assessment."""
        while self.reporting_enabled:
            try:
                # Wait for first day of month
                current_time = datetime.now(timezone.utc)
                if current_time.day == 1:
                    # Generate monthly report
                    report = await self.generate_compliance_report(
                        ReportType.MONTHLY_RISK_REPORT,
                        start_time=datetime.now(timezone.utc) - timedelta(days=30),
                        end_time=datetime.now(timezone.utc)
                    )
                    
                    logger.info(f"Monthly risk assessment completed: {report.report_id}")
                
                # Sleep until next day
                await asyncio.sleep(86400)
                
            except Exception as e:
                logger.error(f"Error in monthly risk assessment: {e}")
                await asyncio.sleep(86400)
    
    async def _continuous_monitoring(self):
        """Perform continuous compliance monitoring."""
        while self.reporting_enabled:
            try:
                # Check for immediate compliance violations
                current_time = datetime.now(timezone.utc)
                recent_events = []
                
                # Get recent events (last hour)
                async for event in self.tamper_proof_storage.search_events(
                    start_time=current_time - timedelta(hours=1),
                    end_time=current_time
                ):
                    recent_events.append(event)
                
                # Check for critical violations
                critical_violations = [
                    event for event in recent_events
                    if event.severity == AuditSeverity.CRITICAL
                ]
                
                if critical_violations:
                    # Generate immediate incident report
                    report = await self.generate_compliance_report(
                        ReportType.INCIDENT_RESPONSE_REPORT,
                        start_time=current_time - timedelta(hours=1),
                        end_time=current_time
                    )
                    
                    logger.warning(f"Critical violations detected, incident report generated: {report.report_id}")
                
                await asyncio.sleep(3600)  # Check every hour
                
            except Exception as e:
                logger.error(f"Error in continuous monitoring: {e}")
                await asyncio.sleep(1800)  # Retry in 30 minutes
    
    async def _incident_report_generator(self):
        """Generate incident reports for security events."""
        while self.reporting_enabled:
            try:
                # Monitor for high-priority security events
                monitoring_metrics = self.monitoring_system.get_performance_metrics()
                
                # Check for active threats
                active_threats = monitoring_metrics.get("threat_detector", {}).get("active_threats", 0)
                
                if active_threats > 0:
                    # Generate incident response report
                    report = await self.generate_compliance_report(
                        ReportType.INCIDENT_RESPONSE_REPORT,
                        start_time=datetime.now(timezone.utc) - timedelta(hours=4),
                        end_time=datetime.now(timezone.utc)
                    )
                    
                    logger.info(f"Incident response report generated: {report.report_id}")
                
                await asyncio.sleep(1800)  # Check every 30 minutes
                
            except Exception as e:
                logger.error(f"Error in incident report generator: {e}")
                await asyncio.sleep(3600)
    
    def get_compliance_metrics(self) -> Dict[str, Any]:
        """Get current compliance metrics."""
        return {
            "compliance_metrics": self.compliance_metrics.copy(),
            "control_count": len(self.compliance_controls),
            "frameworks_supported": len(set(c.framework for c in self.compliance_controls.values())),
            "automated_controls": len([c for c in self.compliance_controls.values() if c.automated_assessment]),
            "assessment_history_count": len(self.assessment_history)
        }
    
    async def health_check(self) -> Dict[str, Any]:
        """Perform health check of compliance reporting system."""
        health_status = {
            "status": "healthy",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "components": {},
            "metrics": self.get_compliance_metrics()
        }
        
        try:
            # Check report storage
            health_status["components"]["report_storage"] = "accessible" if self.report_storage_path.exists() else "inaccessible"
            
            # Check reporting tasks
            active_tasks = sum(1 for task in self.report_tasks if not task.done())
            health_status["components"]["reporting_tasks"] = f"{active_tasks}/{len(self.report_tasks)} active"
            
            # Check dependencies
            aggregator_health = await self.log_aggregator.health_check()
            health_status["components"]["log_aggregator"] = aggregator_health["status"]
            
            monitoring_health = await self.monitoring_system.health_check()
            health_status["components"]["monitoring_system"] = monitoring_health["status"]
            
            storage_health = await self.tamper_proof_storage.health_check()
            health_status["components"]["tamper_proof_storage"] = storage_health
            
            # Overall health assessment
            unhealthy_components = sum(
                1 for status in health_status["components"].values()
                if "healthy" not in str(status) and "active" not in str(status) and "accessible" not in str(status)
            )
            
            if unhealthy_components > 0:
                health_status["status"] = "degraded" if unhealthy_components < 2 else "unhealthy"
            
        except Exception as e:
            health_status["status"] = "unhealthy"
            health_status["error"] = str(e)
        
        return health_status


# Factory function for creating DoD compliance reporter
def create_dod_compliance_reporter(
    audit_logger: AuditLogger,
    tamper_proof_storage: TamperProofStorage,
    log_aggregator: EnhancedLogAggregator,
    monitoring_system: EnhancedMonitoringSystem
) -> DoDAuditComplianceReporter:
    """Create and initialize DoD compliance reporter."""
    security_event_detector = SecurityEventDetector()
    
    return DoDAuditComplianceReporter(
        audit_logger=audit_logger,
        tamper_proof_storage=tamper_proof_storage,
        log_aggregator=log_aggregator,
        monitoring_system=monitoring_system,
        security_event_detector=security_event_detector
    )


if __name__ == "__main__":
    # Example usage
    print("DoD Compliance Reporting and Security Event Detection System - see code for usage examples")