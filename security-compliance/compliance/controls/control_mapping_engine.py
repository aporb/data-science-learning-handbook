#!/usr/bin/env python3
"""
Security Control Mapping Engine

This module provides comprehensive mapping of security controls from various frameworks
(NIST 800-53, DoD STIGs, DoD 8500 series) to their implementations within the system.
It serves as the foundation for the security control implementation documentation framework.

Key Features:
- NIST 800-53 control mapping with implementation tracking
- STIG compliance control documentation and verification
- DoD 8500 series control tracking and assessment
- Automated control status monitoring and reporting
- Integration with existing security infrastructure

Classification: UNCLASSIFIED//FOR OFFICIAL USE ONLY
"""

import asyncio
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum
import uuid
from pathlib import Path

# Type definitions for better code clarity
ControlID = str
ImplementationID = str
EvidenceID = str

class ControlFramework(Enum):
    """Supported security control frameworks"""
    NIST_800_53 = "NIST_SP_800_53"
    DOD_8500 = "DOD_8500_SERIES" 
    STIG = "DISA_STIG"
    FISMA = "FISMA"
    FEDRAMP = "FEDRAMP"
    NIST_CSF = "NIST_CYBERSECURITY_FRAMEWORK"

class ImplementationStatus(Enum):
    """Control implementation status levels"""
    NOT_IMPLEMENTED = "not_implemented"
    PARTIALLY_IMPLEMENTED = "partially_implemented"
    IMPLEMENTED = "implemented"
    INHERITED = "inherited"
    NOT_APPLICABLE = "not_applicable"
    PLANNED = "planned"

class ControlFamily(Enum):
    """NIST 800-53 control families"""
    AC = "Access Control"
    AT = "Awareness and Training"
    AU = "Audit and Accountability"
    CA = "Assessment, Authorization, and Monitoring"
    CM = "Configuration Management"
    CP = "Contingency Planning"
    IA = "Identification and Authentication"
    IR = "Incident Response"
    MA = "Maintenance"
    MP = "Media Protection"
    PE = "Physical and Environmental Protection"
    PL = "Planning"
    PM = "Program Management"
    PS = "Personnel Security"
    PT = "PII Processing and Transparency"
    RA = "Risk Assessment"
    SA = "System and Services Acquisition"
    SC = "System and Communications Protection"
    SI = "System and Information Integrity"
    SR = "Supply Chain Risk Management"

@dataclass
class SecurityControl:
    """Represents a security control from any framework"""
    control_id: str
    framework: ControlFramework
    title: str
    description: str
    control_family: Optional[str] = None
    control_enhancements: List[str] = field(default_factory=list)
    priority: str = "P3"  # P0=Critical, P1=High, P2=Medium, P3=Low
    baseline: List[str] = field(default_factory=list)  # LOW, MODERATE, HIGH
    related_controls: List[str] = field(default_factory=list)
    references: Dict[str, str] = field(default_factory=dict)
    created_date: datetime = field(default_factory=datetime.now)
    updated_date: datetime = field(default_factory=datetime.now)

@dataclass
class ControlImplementation:
    """Represents how a control is implemented in the system"""
    implementation_id: str
    control_id: str
    implementation_type: str  # "technical", "operational", "management"
    implementation_description: str
    responsible_entity: str
    implementation_guidance: str
    system_component: str  # Which system component implements this
    configuration_settings: Dict[str, Any] = field(default_factory=dict)
    implementation_status: ImplementationStatus = ImplementationStatus.NOT_IMPLEMENTED
    evidence_sources: List[str] = field(default_factory=list)
    test_procedures: List[str] = field(default_factory=list)
    compensating_controls: List[str] = field(default_factory=list)
    residual_risk: str = "LOW"  # LOW, MODERATE, HIGH
    created_date: datetime = field(default_factory=datetime.now)
    updated_date: datetime = field(default_factory=datetime.now)

@dataclass
class ControlMapping:
    """Maps controls between different frameworks"""
    mapping_id: str
    primary_control: SecurityControl
    mapped_controls: List[SecurityControl] = field(default_factory=list)
    mapping_type: str = "equivalent"  # equivalent, related, derived
    mapping_rationale: str = ""
    confidence_level: float = 1.0  # 0.0 to 1.0
    created_date: datetime = field(default_factory=datetime.now)

@dataclass
class ControlAssessment:
    """Assessment results for a control implementation"""
    assessment_id: str
    control_id: str
    implementation_id: str
    assessment_date: datetime
    assessor: str
    assessment_method: str  # "automated", "manual", "hybrid"
    test_results: Dict[str, Any] = field(default_factory=dict)
    findings: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    effectiveness_score: float = 0.0  # 0.0 to 1.0
    compliance_status: str = "non_compliant"  # compliant, non_compliant, partially_compliant
    next_assessment_date: Optional[datetime] = None

class SecurityControlMappingEngine:
    """
    Core engine for managing security control mappings and implementations.
    
    This engine provides comprehensive capabilities for:
    - Loading and managing security controls from multiple frameworks
    - Mapping controls between frameworks
    - Tracking control implementations
    - Monitoring implementation status
    - Generating compliance reports
    """
    
    def __init__(self, 
                 data_directory: str = "./compliance_data",
                 audit_logger: Optional[Any] = None,
                 monitoring_system: Optional[Any] = None):
        """
        Initialize the Security Control Mapping Engine
        
        Args:
            data_directory: Directory for storing control data
            audit_logger: Audit logging system for compliance tracking
            monitoring_system: Monitoring system for real-time status updates
        """
        self.data_directory = Path(data_directory)
        self.audit_logger = audit_logger
        self.monitoring_system = monitoring_system
        
        # Core data structures
        self.controls: Dict[str, SecurityControl] = {}
        self.implementations: Dict[str, ControlImplementation] = {}
        self.mappings: Dict[str, ControlMapping] = {}
        self.assessments: Dict[str, List[ControlAssessment]] = {}
        
        # Performance tracking
        self.metrics = {
            "controls_loaded": 0,
            "implementations_tracked": 0,
            "assessments_completed": 0,
            "compliance_rate": 0.0,
            "last_update": datetime.now()
        }
        
        # Configuration
        self.config = {
            "auto_update_interval": 3600,  # 1 hour
            "assessment_retention_days": 365,
            "enable_real_time_monitoring": True,
            "require_evidence_validation": True
        }
        
        self.logger = logging.getLogger(__name__)
        self._initialize_directories()
    
    def _initialize_directories(self):
        """Initialize required directories"""
        directories = [
            self.data_directory,
            self.data_directory / "controls",
            self.data_directory / "implementations", 
            self.data_directory / "mappings",
            self.data_directory / "assessments",
            self.data_directory / "templates"
        ]
        
        for directory in directories:
            directory.mkdir(parents=True, exist_ok=True)
    
    async def initialize(self) -> bool:
        """
        Initialize the mapping engine with default control frameworks
        
        Returns:
            bool: True if initialization successful
        """
        try:
            # Load default NIST 800-53 controls
            await self._load_nist_800_53_controls()
            
            # Load DoD 8500 series controls
            await self._load_dod_8500_controls()
            
            # Load common STIG controls
            await self._load_stig_controls()
            
            # Create default control mappings
            await self._create_default_mappings()
            
            # Initialize monitoring if available
            if self.monitoring_system:
                await self._initialize_monitoring()
            
            self.logger.info("Security Control Mapping Engine initialized successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to initialize mapping engine: {e}")
            return False
    
    async def _load_nist_800_53_controls(self):
        """Load NIST 800-53 controls"""
        # Sample of critical NIST 800-53 controls - in production, load from authoritative source
        nist_controls = [
            {
                "control_id": "AC-3",
                "title": "Access Enforcement",
                "description": "Enforce approved authorizations for logical access to information and system resources.",
                "control_family": "Access Control",
                "priority": "P1",
                "baseline": ["LOW", "MODERATE", "HIGH"],
                "related_controls": ["AC-2", "AC-4", "AC-6", "AU-9", "SC-3"]
            },
            {
                "control_id": "AC-4",
                "title": "Information Flow Enforcement", 
                "description": "Control information flows within the system and between interconnected systems.",
                "control_family": "Access Control",
                "priority": "P1",
                "baseline": ["MODERATE", "HIGH"],
                "related_controls": ["AC-3", "SC-7", "SC-31"]
            },
            {
                "control_id": "AU-2",
                "title": "Event Logging",
                "description": "Identify the types of events that the system is capable of logging.",
                "control_family": "Audit and Accountability",
                "priority": "P1", 
                "baseline": ["LOW", "MODERATE", "HIGH"],
                "related_controls": ["AU-3", "AU-12", "SI-4"]
            },
            {
                "control_id": "AU-3",
                "title": "Content of Audit Records",
                "description": "Ensure audit records contain information to establish WWWWWH.",
                "control_family": "Audit and Accountability", 
                "priority": "P1",
                "baseline": ["LOW", "MODERATE", "HIGH"],
                "related_controls": ["AU-2", "AU-8", "AU-12", "SI-11"]
            },
            {
                "control_id": "IA-2",
                "title": "Identification and Authentication (Organizational Users)",
                "description": "Uniquely identify and authenticate organizational users.",
                "control_family": "Identification and Authentication",
                "priority": "P1",
                "baseline": ["LOW", "MODERATE", "HIGH"],
                "related_controls": ["AC-14", "IA-4", "IA-5", "IA-8"]
            },
            {
                "control_id": "SC-7",
                "title": "Boundary Protection", 
                "description": "Monitor and control communications at the external boundary of the system.",
                "control_family": "System and Communications Protection",
                "priority": "P1",
                "baseline": ["LOW", "MODERATE", "HIGH"],
                "related_controls": ["AC-4", "CA-3", "CM-7", "SC-5"]
            },
            {
                "control_id": "SI-4",
                "title": "System Monitoring",
                "description": "Monitor the system to detect attacks and indicators of potential attacks.",
                "control_family": "System and Information Integrity",
                "priority": "P1", 
                "baseline": ["LOW", "MODERATE", "HIGH"],
                "related_controls": ["AU-6", "IR-4", "RA-5", "SC-7"]
            }
        ]
        
        for control_data in nist_controls:
            control = SecurityControl(
                control_id=control_data["control_id"],
                framework=ControlFramework.NIST_800_53,
                title=control_data["title"],
                description=control_data["description"],
                control_family=control_data.get("control_family"),
                priority=control_data.get("priority", "P3"),
                baseline=control_data.get("baseline", []),
                related_controls=control_data.get("related_controls", [])
            )
            
            self.controls[control.control_id] = control
            self.metrics["controls_loaded"] += 1
    
    async def _load_dod_8500_controls(self):
        """Load DoD 8500 series controls"""
        # Sample DoD 8500 series controls
        dod_controls = [
            {
                "control_id": "DCID-6/3-OPSEC-1",
                "title": "Operations Security",
                "description": "Implement operations security measures to protect critical information.",
                "priority": "P0",
                "baseline": ["HIGH"]
            },
            {
                "control_id": "DCID-6/3-COMSEC-1", 
                "title": "Communications Security",
                "description": "Implement communications security measures for classified networks.",
                "priority": "P0",
                "baseline": ["HIGH"]
            },
            {
                "control_id": "DCID-6/3-PHYSEC-1",
                "title": "Physical Security",
                "description": "Implement physical security controls for secure facilities.",
                "priority": "P1",
                "baseline": ["MODERATE", "HIGH"]
            }
        ]
        
        for control_data in dod_controls:
            control = SecurityControl(
                control_id=control_data["control_id"],
                framework=ControlFramework.DOD_8500,
                title=control_data["title"],
                description=control_data["description"],
                priority=control_data.get("priority", "P3"),
                baseline=control_data.get("baseline", [])
            )
            
            self.controls[control.control_id] = control
            self.metrics["controls_loaded"] += 1
    
    async def _load_stig_controls(self):
        """Load STIG controls"""
        # Sample STIG controls
        stig_controls = [
            {
                "control_id": "STIG-OS-000001",
                "title": "Operating System Authentication",
                "description": "The operating system must authenticate users before allowing access.",
                "priority": "P0",
                "baseline": ["LOW", "MODERATE", "HIGH"]
            },
            {
                "control_id": "STIG-OS-000002",
                "title": "Account Lockout", 
                "description": "The operating system must lock user accounts after failed login attempts.",
                "priority": "P1",
                "baseline": ["LOW", "MODERATE", "HIGH"]
            },
            {
                "control_id": "STIG-NET-000001",
                "title": "Network Encryption",
                "description": "Network communications must be encrypted in transit.",
                "priority": "P0", 
                "baseline": ["MODERATE", "HIGH"]
            }
        ]
        
        for control_data in stig_controls:
            control = SecurityControl(
                control_id=control_data["control_id"],
                framework=ControlFramework.STIG,
                title=control_data["title"],
                description=control_data["description"],
                priority=control_data.get("priority", "P3"),
                baseline=control_data.get("baseline", [])
            )
            
            self.controls[control.control_id] = control
            self.metrics["controls_loaded"] += 1
    
    async def _create_default_mappings(self):
        """Create default mappings between control frameworks"""
        # Create mappings between NIST 800-53 and related controls
        mappings = [
            {
                "primary": "AC-3",
                "mapped": ["STIG-OS-000001", "DCID-6/3-OPSEC-1"],
                "type": "related",
                "rationale": "All controls address access enforcement and authentication"
            },
            {
                "primary": "AU-2", 
                "mapped": ["SI-4"],
                "type": "related",
                "rationale": "Both controls address system monitoring and logging"
            },
            {
                "primary": "SC-7",
                "mapped": ["STIG-NET-000001", "DCID-6/3-COMSEC-1"],
                "type": "equivalent",
                "rationale": "All controls address boundary protection and communications security"
            }
        ]
        
        for mapping_data in mappings:
            primary_control = self.controls.get(mapping_data["primary"])
            if not primary_control:
                continue
                
            mapped_controls = []
            for mapped_id in mapping_data["mapped"]:
                mapped_control = self.controls.get(mapped_id)
                if mapped_control:
                    mapped_controls.append(mapped_control)
            
            if mapped_controls:
                mapping = ControlMapping(
                    mapping_id=str(uuid.uuid4()),
                    primary_control=primary_control,
                    mapped_controls=mapped_controls,
                    mapping_type=mapping_data["type"],
                    mapping_rationale=mapping_data["rationale"],
                    confidence_level=0.9
                )
                
                self.mappings[mapping.mapping_id] = mapping
    
    async def _initialize_monitoring(self):
        """Initialize real-time monitoring integration"""
        if self.monitoring_system and hasattr(self.monitoring_system, 'register_metric'):
            # Register key metrics for monitoring
            metrics_to_register = [
                "security_controls_total",
                "control_implementations_active", 
                "compliance_rate_percentage",
                "failed_assessments_total",
                "control_assessment_duration_seconds"
            ]
            
            for metric in metrics_to_register:
                await self.monitoring_system.register_metric(f"security_controls.{metric}")
    
    async def register_control_implementation(self, 
                                            control_id: str,
                                            implementation_data: Dict[str, Any]) -> str:
        """
        Register a new control implementation
        
        Args:
            control_id: ID of the control being implemented
            implementation_data: Implementation details
            
        Returns:
            str: Implementation ID
        """
        try:
            # Validate control exists
            if control_id not in self.controls:
                raise ValueError(f"Control {control_id} not found")
            
            # Create implementation record
            implementation_id = str(uuid.uuid4())
            implementation = ControlImplementation(
                implementation_id=implementation_id,
                control_id=control_id,
                implementation_type=implementation_data.get("type", "technical"),
                implementation_description=implementation_data.get("description", ""),
                responsible_entity=implementation_data.get("responsible_entity", ""),
                implementation_guidance=implementation_data.get("guidance", ""),
                system_component=implementation_data.get("component", ""),
                configuration_settings=implementation_data.get("configuration", {}),
                implementation_status=ImplementationStatus(
                    implementation_data.get("status", "not_implemented")
                ),
                evidence_sources=implementation_data.get("evidence_sources", []),
                test_procedures=implementation_data.get("test_procedures", []),
                compensating_controls=implementation_data.get("compensating_controls", []),
                residual_risk=implementation_data.get("residual_risk", "LOW")
            )
            
            self.implementations[implementation_id] = implementation
            self.metrics["implementations_tracked"] += 1
            
            # Log the registration
            if self.audit_logger:
                await self.audit_logger.log_event({
                    "event_type": "control_implementation_registered",
                    "control_id": control_id,
                    "implementation_id": implementation_id,
                    "responsible_entity": implementation.responsible_entity,
                    "timestamp": datetime.now().isoformat()
                })
            
            # Update monitoring metrics
            if self.monitoring_system:
                await self.monitoring_system.update_metric(
                    "security_controls.control_implementations_active",
                    len(self.implementations)
                )
            
            self.logger.info(f"Registered implementation {implementation_id} for control {control_id}")
            return implementation_id
            
        except Exception as e:
            self.logger.error(f"Failed to register control implementation: {e}")
            raise
    
    async def get_control_status(self, control_id: str) -> Dict[str, Any]:
        """
        Get comprehensive status for a security control
        
        Args:
            control_id: Control identifier
            
        Returns:
            Dict containing control status information
        """
        try:
            control = self.controls.get(control_id)
            if not control:
                raise ValueError(f"Control {control_id} not found")
            
            # Get all implementations for this control
            implementations = [
                impl for impl in self.implementations.values()
                if impl.control_id == control_id
            ]
            
            # Get recent assessments
            recent_assessments = []
            for assessment_list in self.assessments.values():
                for assessment in assessment_list:
                    if assessment.control_id == control_id:
                        # Only include assessments from last 90 days
                        if (datetime.now() - assessment.assessment_date).days <= 90:
                            recent_assessments.append(assessment)
            
            # Calculate overall status
            overall_status = self._calculate_overall_control_status(
                implementations, recent_assessments
            )
            
            # Get mapped controls
            mapped_controls = []
            for mapping in self.mappings.values():
                if mapping.primary_control.control_id == control_id:
                    mapped_controls.extend([
                        {"control_id": mc.control_id, "framework": mc.framework.value}
                        for mc in mapping.mapped_controls
                    ])
            
            status = {
                "control_id": control_id,
                "framework": control.framework.value,
                "title": control.title,
                "description": control.description,
                "control_family": control.control_family,
                "priority": control.priority,
                "baseline": control.baseline,
                "overall_status": overall_status,
                "implementations": [
                    {
                        "implementation_id": impl.implementation_id,
                        "type": impl.implementation_type,
                        "status": impl.implementation_status.value,
                        "responsible_entity": impl.responsible_entity,
                        "system_component": impl.system_component,
                        "residual_risk": impl.residual_risk,
                        "last_updated": impl.updated_date.isoformat()
                    }
                    for impl in implementations
                ],
                "recent_assessments": [
                    {
                        "assessment_id": assess.assessment_id,
                        "assessment_date": assess.assessment_date.isoformat(),
                        "assessor": assess.assessor,
                        "compliance_status": assess.compliance_status,
                        "effectiveness_score": assess.effectiveness_score,
                        "findings_count": len(assess.findings),
                        "recommendations_count": len(assess.recommendations)
                    }
                    for assess in recent_assessments
                ],
                "mapped_controls": mapped_controls,
                "related_controls": control.related_controls,
                "last_updated": control.updated_date.isoformat()
            }
            
            return status
            
        except Exception as e:
            self.logger.error(f"Failed to get control status for {control_id}: {e}")
            raise
    
    def _calculate_overall_control_status(self, 
                                        implementations: List[ControlImplementation],
                                        assessments: List[ControlAssessment]) -> Dict[str, Any]:
        """Calculate overall status for a control based on implementations and assessments"""
        if not implementations:
            return {
                "status": "not_implemented",
                "compliance_rate": 0.0,
                "effectiveness_score": 0.0,
                "risk_level": "HIGH"
            }
        
        # Calculate implementation status distribution
        status_counts = {}
        for impl in implementations:
            status = impl.implementation_status.value
            status_counts[status] = status_counts.get(status, 0) + 1
        
        # Calculate compliance rate from recent assessments
        if assessments:
            compliant_assessments = [
                a for a in assessments 
                if a.compliance_status in ["compliant", "partially_compliant"]
            ]
            compliance_rate = len(compliant_assessments) / len(assessments)
            
            # Calculate average effectiveness score
            effectiveness_scores = [a.effectiveness_score for a in assessments if a.effectiveness_score > 0]
            avg_effectiveness = sum(effectiveness_scores) / len(effectiveness_scores) if effectiveness_scores else 0.0
        else:
            compliance_rate = 0.0
            avg_effectiveness = 0.0
        
        # Determine overall status
        if status_counts.get("implemented", 0) == len(implementations):
            overall_status = "fully_implemented"
        elif status_counts.get("implemented", 0) > 0:
            overall_status = "partially_implemented"
        else:
            overall_status = "not_implemented"
        
        # Determine risk level
        if compliance_rate >= 0.9 and avg_effectiveness >= 0.8:
            risk_level = "LOW"
        elif compliance_rate >= 0.7 and avg_effectiveness >= 0.6:
            risk_level = "MODERATE"
        else:
            risk_level = "HIGH"
        
        return {
            "status": overall_status,
            "compliance_rate": compliance_rate,
            "effectiveness_score": avg_effectiveness,
            "risk_level": risk_level,
            "implementation_distribution": status_counts
        }
    
    async def get_compliance_dashboard(self) -> Dict[str, Any]:
        """
        Generate a comprehensive compliance dashboard
        
        Returns:
            Dict containing dashboard data
        """
        try:
            # Calculate overall metrics
            total_controls = len(self.controls)
            total_implementations = len(self.implementations)
            
            # Control status distribution
            control_statuses = {}
            implementation_statuses = {}
            framework_distribution = {}
            
            for control in self.controls.values():
                framework = control.framework.value
                framework_distribution[framework] = framework_distribution.get(framework, 0) + 1
            
            for impl in self.implementations.values():
                status = impl.implementation_status.value
                implementation_statuses[status] = implementation_statuses.get(status, 0) + 1
            
            # Calculate compliance rates by framework
            framework_compliance = {}
            for framework in ControlFramework:
                framework_controls = [c for c in self.controls.values() if c.framework == framework]
                if framework_controls:
                    # Get implementations for these controls
                    framework_impls = [
                        impl for impl in self.implementations.values()
                        if impl.control_id in [c.control_id for c in framework_controls]
                    ]
                    
                    implemented_count = len([
                        impl for impl in framework_impls
                        if impl.implementation_status == ImplementationStatus.IMPLEMENTED
                    ])
                    
                    compliance_rate = implemented_count / len(framework_controls) if framework_controls else 0.0
                    framework_compliance[framework.value] = {
                        "total_controls": len(framework_controls),
                        "implemented_controls": implemented_count,
                        "compliance_rate": compliance_rate
                    }
            
            # Recent assessment summary
            recent_assessments = []
            cutoff_date = datetime.now() - timedelta(days=30)
            
            for assessment_list in self.assessments.values():
                for assessment in assessment_list:
                    if assessment.assessment_date >= cutoff_date:
                        recent_assessments.append(assessment)
            
            # Calculate trends
            monthly_assessments = len(recent_assessments)
            avg_effectiveness = (
                sum(a.effectiveness_score for a in recent_assessments) / len(recent_assessments)
                if recent_assessments else 0.0
            )
            
            # Priority control status
            priority_controls = {}
            for priority in ["P0", "P1", "P2", "P3"]:
                priority_control_list = [c for c in self.controls.values() if c.priority == priority]
                priority_impls = [
                    impl for impl in self.implementations.values()
                    if any(c.control_id == impl.control_id for c in priority_control_list)
                ]
                
                implemented = len([
                    impl for impl in priority_impls
                    if impl.implementation_status == ImplementationStatus.IMPLEMENTED
                ])
                
                priority_controls[priority] = {
                    "total": len(priority_control_list),
                    "implemented": implemented,
                    "rate": implemented / len(priority_control_list) if priority_control_list else 0.0
                }
            
            dashboard = {
                "summary": {
                    "total_controls": total_controls,
                    "total_implementations": total_implementations,
                    "overall_compliance_rate": self.metrics.get("compliance_rate", 0.0),
                    "last_updated": self.metrics.get("last_update", datetime.now()).isoformat()
                },
                "framework_distribution": framework_distribution,
                "implementation_status_distribution": implementation_statuses,
                "framework_compliance": framework_compliance,
                "priority_control_status": priority_controls,
                "recent_assessment_summary": {
                    "assessments_last_30_days": monthly_assessments,
                    "average_effectiveness_score": avg_effectiveness,
                    "compliance_trend": "stable"  # TODO: Calculate actual trend
                },
                "risk_summary": {
                    "high_risk_controls": len([
                        impl for impl in self.implementations.values()
                        if impl.residual_risk == "HIGH"
                    ]),
                    "medium_risk_controls": len([
                        impl for impl in self.implementations.values()
                        if impl.residual_risk == "MODERATE"
                    ]),
                    "low_risk_controls": len([
                        impl for impl in self.implementations.values()
                        if impl.residual_risk == "LOW"
                    ])
                }
            }
            
            return dashboard
            
        except Exception as e:
            self.logger.error(f"Failed to generate compliance dashboard: {e}")
            raise
    
    async def export_control_mappings(self, output_format: str = "json") -> str:
        """
        Export control mappings in specified format
        
        Args:
            output_format: Export format (json, csv, xlsx)
            
        Returns:
            str: Path to exported file
        """
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = self.data_directory / f"control_mappings_{timestamp}.{output_format}"
            
            if output_format == "json":
                export_data = {
                    "metadata": {
                        "export_date": datetime.now().isoformat(),
                        "total_controls": len(self.controls),
                        "total_implementations": len(self.implementations),
                        "total_mappings": len(self.mappings)
                    },
                    "controls": {
                        control_id: {
                            "control_id": control.control_id,
                            "framework": control.framework.value,
                            "title": control.title,
                            "description": control.description,
                            "control_family": control.control_family,
                            "priority": control.priority,
                            "baseline": control.baseline,
                            "related_controls": control.related_controls
                        }
                        for control_id, control in self.controls.items()
                    },
                    "implementations": {
                        impl_id: {
                            "implementation_id": impl.implementation_id,
                            "control_id": impl.control_id,
                            "type": impl.implementation_type,
                            "description": impl.implementation_description,
                            "responsible_entity": impl.responsible_entity,
                            "status": impl.implementation_status.value,
                            "system_component": impl.system_component,
                            "residual_risk": impl.residual_risk
                        }
                        for impl_id, impl in self.implementations.items()
                    },
                    "mappings": {
                        mapping_id: {
                            "mapping_id": mapping.mapping_id,
                            "primary_control": mapping.primary_control.control_id,
                            "mapped_controls": [mc.control_id for mc in mapping.mapped_controls],
                            "mapping_type": mapping.mapping_type,
                            "rationale": mapping.mapping_rationale,
                            "confidence_level": mapping.confidence_level
                        }
                        for mapping_id, mapping in self.mappings.items()
                    }
                }
                
                with open(output_file, 'w') as f:
                    json.dump(export_data, f, indent=2, default=str)
            
            self.logger.info(f"Exported control mappings to {output_file}")
            return str(output_file)
            
        except Exception as e:
            self.logger.error(f"Failed to export control mappings: {e}")
            raise
    
    async def health_check(self) -> Dict[str, Any]:
        """
        Perform comprehensive health check of the mapping engine
        
        Returns:
            Dict containing health status information
        """
        try:
            status = {
                "status": "healthy",
                "timestamp": datetime.now().isoformat(),
                "metrics": self.metrics.copy(),
                "data_integrity": {
                    "controls_loaded": len(self.controls),
                    "implementations_registered": len(self.implementations),
                    "mappings_created": len(self.mappings),
                    "assessments_tracked": sum(len(a) for a in self.assessments.values())
                },
                "system_health": {
                    "data_directory_exists": self.data_directory.exists(),
                    "data_directory_writable": os.access(self.data_directory, os.W_OK),
                    "audit_logger_available": self.audit_logger is not None,
                    "monitoring_system_available": self.monitoring_system is not None
                }
            }
            
            # Check for any critical issues
            critical_issues = []
            
            if not self.data_directory.exists():
                critical_issues.append("Data directory does not exist")
            
            if len(self.controls) == 0:
                critical_issues.append("No security controls loaded")
            
            if critical_issues:
                status["status"] = "unhealthy"
                status["critical_issues"] = critical_issues
            
            return status
            
        except Exception as e:
            return {
                "status": "error",
                "timestamp": datetime.now().isoformat(),
                "error": str(e)
            }

async def create_control_mapping_engine(data_directory: str = "./compliance_data",
                                      audit_logger: Optional[Any] = None,
                                      monitoring_system: Optional[Any] = None) -> SecurityControlMappingEngine:
    """
    Factory function to create and initialize a SecurityControlMappingEngine
    
    Args:
        data_directory: Directory for storing compliance data
        audit_logger: Audit logging system instance
        monitoring_system: Monitoring system instance
        
    Returns:
        Initialized SecurityControlMappingEngine
    """
    engine = SecurityControlMappingEngine(
        data_directory=data_directory,
        audit_logger=audit_logger,
        monitoring_system=monitoring_system
    )
    
    await engine.initialize()
    return engine

# Example usage and testing
if __name__ == "__main__":
    import os
    
    async def demo_control_mapping_engine():
        """Demonstrate the Security Control Mapping Engine"""
        print("Security Control Mapping Engine Demo")
        print("=" * 50)
        
        # Create engine
        engine = await create_control_mapping_engine()
        
        # Show initial status
        health = await engine.health_check()
        print(f"Engine Status: {health['status']}")
        print(f"Controls Loaded: {health['data_integrity']['controls_loaded']}")
        
        # Register a sample implementation
        implementation_data = {
            "type": "technical",
            "description": "CAC/PIV authentication implemented via PKCS#11 integration",
            "responsible_entity": "Security Team",
            "guidance": "Refer to CAC/PIV Integration Documentation",
            "component": "authentication_service",
            "status": "implemented",
            "evidence_sources": [
                "cac_piv_integration.py",
                "certificate_validators.py",
                "security_managers.py"
            ],
            "test_procedures": [
                "test_cac_integration.py",
                "test_enhanced_security.py"
            ],
            "residual_risk": "LOW"
        }
        
        impl_id = await engine.register_control_implementation("IA-2", implementation_data)
        print(f"Registered implementation: {impl_id}")
        
        # Get control status
        status = await engine.get_control_status("IA-2")
        print(f"Control IA-2 Status: {status['overall_status']['status']}")
        
        # Generate compliance dashboard
        dashboard = await engine.get_compliance_dashboard()
        print(f"Overall Compliance Rate: {dashboard['summary']['overall_compliance_rate']:.2%}")
        
        # Export mappings
        export_file = await engine.export_control_mappings()
        print(f"Exported mappings to: {export_file}")
        
        print("\nDemo completed successfully!")
    
    # Run the demo
    asyncio.run(demo_control_mapping_engine())