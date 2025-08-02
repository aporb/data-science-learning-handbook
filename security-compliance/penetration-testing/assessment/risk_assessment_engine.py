"""
Risk Assessment Engine
======================

Advanced vulnerability risk assessment engine that integrates multiple scoring
methodologies and organizational context to provide comprehensive risk analysis
and intelligent vulnerability prioritization.

Features:
- Multi-framework risk assessment (CVSS, EPSS, SSVC)
- Asset criticality and business impact analysis
- Classification-aware risk weighting
- Threat intelligence correlation
- Exploit availability assessment
- Environmental and temporal scoring
- Automated risk scoring and ranking
- Risk trend analysis and reporting
"""

import asyncio
import json
import logging
import sqlite3
import statistics
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Tuple, NamedTuple
from dataclasses import dataclass, field
from pathlib import Path
from enum import Enum
from uuid import uuid4
import math

# Import existing infrastructure
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '../../multi-classification'))
sys.path.append(os.path.join(os.path.dirname(__file__), '../../auth/security_testing_framework'))

logger = logging.getLogger(__name__)

class RiskLevel(Enum):
    """Risk levels for vulnerability assessment"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"

class PrioritizationMethod(Enum):
    """Available prioritization methods"""
    CVSS_ONLY = "cvss_only"
    CVSS_EPSS = "cvss_epss"
    CVSS_EPSS_SSVC = "cvss_epss_ssvc"
    ORGANIZATIONAL_CONTEXT = "organizational_context"
    THREAT_INTELLIGENCE = "threat_intelligence"
    COMPREHENSIVE = "comprehensive"

@dataclass
class AssetContext:
    """Asset context information for risk assessment"""
    asset_id: str
    asset_name: str
    asset_type: str
    criticality: str  # critical, high, medium, low
    classification: str  # NIPR, SIPR, JWICS
    business_value: float  # 0.0 - 1.0
    exposure_level: str  # public, internal, restricted
    network_zone: str
    owner: str
    compliance_requirements: List[str] = field(default_factory=list)
    data_sensitivity: str = "medium"
    availability_requirement: str = "medium"
    integrity_requirement: str = "medium"
    confidentiality_requirement: str = "medium"

@dataclass
class ThreatContext:
    """Threat intelligence context for risk assessment"""
    exploit_available: bool = False
    exploit_maturity: str = "unknown"  # functional, poc, unproven, high
    active_campaigns: List[str] = field(default_factory=list)
    threat_actors: List[str] = field(default_factory=list)
    attack_vectors: List[str] = field(default_factory=list)
    exploitation_likelihood: float = 0.0  # 0.0 - 1.0
    weaponization_status: str = "unknown"
    detection_difficulty: str = "medium"

@dataclass
class RiskScoreComponents:
    """Individual components of risk score calculation"""
    cvss_base_score: float = 0.0
    cvss_temporal_score: float = 0.0
    cvss_environmental_score: float = 0.0
    epss_score: float = 0.0
    ssvc_decision: str = "defer"
    asset_criticality_multiplier: float = 1.0
    classification_multiplier: float = 1.0
    threat_intelligence_multiplier: float = 1.0
    business_impact_score: float = 0.0
    exploitability_score: float = 0.0
    exposure_score: float = 0.0

@dataclass
class VulnerabilityRiskAssessment:
    """Complete vulnerability risk assessment"""
    vulnerability_id: str
    assessment_id: str
    assessment_timestamp: datetime
    risk_level: RiskLevel
    overall_risk_score: float
    priority_rank: int
    score_components: RiskScoreComponents
    asset_context: Optional[AssetContext]
    threat_context: Optional[ThreatContext]
    remediation_urgency: str
    business_justification: str
    risk_acceptance_threshold: float
    confidence_level: float
    assessment_method: PrioritizationMethod
    metadata: Dict[str, Any] = field(default_factory=dict)

class RiskAssessmentEngine:
    """
    Advanced vulnerability risk assessment engine
    
    Integrates multiple scoring methodologies and organizational context
    to provide comprehensive vulnerability risk analysis and prioritization.
    """
    
    def __init__(self, db_path: str = "risk_assessment.db"):
        self.db_path = Path(db_path)
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        
        # Initialize database
        self._initialize_database()
        
        # Initialize scoring components
        self.cvss_calculator = None  # Will be imported/initialized
        self.epss_integration = None
        self.ssvc_framework = None
        self.asset_analyzer = None
        self.classification_weighting = None
        self.threat_correlator = None
        
        # Risk assessment configuration
        self.config = {
            'default_method': PrioritizationMethod.COMPREHENSIVE,
            'risk_thresholds': {
                'critical': 9.0,
                'high': 7.0,
                'medium': 4.0,
                'low': 0.1
            },
            'scoring_weights': {
                'cvss_base': 0.4,
                'cvss_temporal': 0.1,
                'cvss_environmental': 0.2,
                'epss': 0.15,
                'threat_intelligence': 0.1,
                'asset_criticality': 0.05
            },
            'classification_multipliers': {
                'JWICS': 1.5,
                'SIPR': 1.3,
                'NIPR': 1.0
            },
            'asset_criticality_multipliers': {
                'critical': 1.4,
                'high': 1.2,
                'medium': 1.0,
                'low': 0.8
            }
        }
        
        # Assessment cache
        self.assessment_cache = {}
        self.cache_ttl = 3600  # 1 hour
    
    def _initialize_database(self):
        """Initialize risk assessment database"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS risk_assessments (
                    assessment_id TEXT PRIMARY KEY,
                    vulnerability_id TEXT NOT NULL,
                    assessment_timestamp TEXT NOT NULL,
                    risk_level TEXT NOT NULL,
                    overall_risk_score REAL NOT NULL,
                    priority_rank INTEGER,
                    score_components TEXT,  -- JSON
                    asset_context TEXT,     -- JSON
                    threat_context TEXT,    -- JSON
                    remediation_urgency TEXT,
                    business_justification TEXT,
                    risk_acceptance_threshold REAL,
                    confidence_level REAL,
                    assessment_method TEXT,
                    metadata TEXT,          -- JSON
                    created_at TEXT,
                    updated_at TEXT
                )
            """)
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS asset_contexts (
                    asset_id TEXT PRIMARY KEY,
                    asset_name TEXT NOT NULL,
                    asset_type TEXT,
                    criticality TEXT,
                    classification TEXT,
                    business_value REAL,
                    exposure_level TEXT,
                    network_zone TEXT,
                    owner TEXT,
                    compliance_requirements TEXT,  -- JSON
                    data_sensitivity TEXT,
                    availability_requirement TEXT,
                    integrity_requirement TEXT,
                    confidentiality_requirement TEXT,
                    created_at TEXT,
                    updated_at TEXT
                )
            """)
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS risk_trends (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    vulnerability_id TEXT NOT NULL,
                    assessment_date TEXT NOT NULL,
                    risk_score REAL NOT NULL,
                    risk_level TEXT NOT NULL,
                    factors_changed TEXT,  -- JSON
                    created_at TEXT
                )
            """)
            
            # Create indexes
            conn.execute("CREATE INDEX IF NOT EXISTS idx_risk_vuln_id ON risk_assessments(vulnerability_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_risk_level ON risk_assessments(risk_level)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_risk_score ON risk_assessments(overall_risk_score)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_asset_criticality ON asset_contexts(criticality)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_asset_classification ON asset_contexts(classification)")
    
    async def assess_vulnerability_risk(self,
                                      vulnerability: Dict[str, Any],
                                      asset_context: Optional[AssetContext] = None,
                                      threat_context: Optional[ThreatContext] = None,
                                      method: Optional[PrioritizationMethod] = None) -> VulnerabilityRiskAssessment:
        """
        Perform comprehensive risk assessment for a vulnerability
        """
        
        vulnerability_id = vulnerability.get('id', str(uuid4()))
        assessment_id = str(uuid4())
        assessment_method = method or self.config['default_method']
        
        try:
            self.logger.info(f"Assessing risk for vulnerability {vulnerability_id} using {assessment_method.value}")
            
            # Extract basic vulnerability information
            cvss_score = vulnerability.get('cvss_score', 0.0)
            severity = vulnerability.get('severity', 'medium')
            cve_id = vulnerability.get('cve_id')
            
            # Initialize score components
            score_components = RiskScoreComponents()
            
            # Calculate CVSS scores
            score_components.cvss_base_score = cvss_score
            if self.cvss_calculator:
                cvss_details = await self._calculate_cvss_scores(vulnerability, asset_context)
                score_components.cvss_temporal_score = cvss_details.get('temporal', cvss_score)
                score_components.cvss_environmental_score = cvss_details.get('environmental', cvss_score)
            
            # Calculate EPSS score if available
            if assessment_method in [PrioritizationMethod.CVSS_EPSS, PrioritizationMethod.CVSS_EPSS_SSVC, PrioritizationMethod.COMPREHENSIVE]:
                if self.epss_integration and cve_id:
                    score_components.epss_score = await self._get_epss_score(cve_id)
            
            # Get SSVC decision if available
            if assessment_method in [PrioritizationMethod.CVSS_EPSS_SSVC, PrioritizationMethod.COMPREHENSIVE]:
                if self.ssvc_framework:
                    score_components.ssvc_decision = await self._get_ssvc_decision(vulnerability, asset_context)
            
            # Calculate asset criticality multiplier
            if asset_context:
                score_components.asset_criticality_multiplier = self._calculate_asset_criticality_multiplier(asset_context)
                score_components.classification_multiplier = self._calculate_classification_multiplier(asset_context)
                score_components.business_impact_score = self._calculate_business_impact_score(asset_context)
                score_components.exposure_score = self._calculate_exposure_score(asset_context)
            
            # Calculate threat intelligence multiplier
            if threat_context:
                score_components.threat_intelligence_multiplier = self._calculate_threat_multiplier(threat_context)
                score_components.exploitability_score = self._calculate_exploitability_score(threat_context)
            
            # Calculate overall risk score
            overall_risk_score = await self._calculate_overall_risk_score(score_components, assessment_method)
            
            # Determine risk level
            risk_level = self._determine_risk_level(overall_risk_score)
            
            # Calculate confidence level
            confidence_level = self._calculate_confidence_level(vulnerability, asset_context, threat_context)
            
            # Generate business justification
            business_justification = self._generate_business_justification(
                vulnerability, asset_context, threat_context, overall_risk_score
            )
            
            # Determine remediation urgency
            remediation_urgency = self._determine_remediation_urgency(risk_level, score_components)
            
            # Create risk assessment
            assessment = VulnerabilityRiskAssessment(
                vulnerability_id=vulnerability_id,
                assessment_id=assessment_id,
                assessment_timestamp=datetime.now(timezone.utc),
                risk_level=risk_level,
                overall_risk_score=overall_risk_score,
                priority_rank=0,  # Will be calculated during batch prioritization
                score_components=score_components,
                asset_context=asset_context,
                threat_context=threat_context,
                remediation_urgency=remediation_urgency,
                business_justification=business_justification,
                risk_acceptance_threshold=self.config['risk_thresholds'][risk_level.value],
                confidence_level=confidence_level,
                assessment_method=assessment_method,
                metadata={
                    'vulnerability_data': vulnerability,
                    'assessment_version': '1.0',
                    'scoring_weights': self.config['scoring_weights']
                }
            )
            
            # Save assessment
            await self._save_risk_assessment(assessment)
            
            # Update risk trends
            await self._update_risk_trends(vulnerability_id, assessment)
            
            self.logger.info(f"Completed risk assessment for {vulnerability_id}: "
                           f"{risk_level.value} ({overall_risk_score:.2f})")
            
            return assessment
            
        except Exception as e:
            self.logger.error(f"Failed to assess risk for vulnerability {vulnerability_id}: {e}")
            raise
    
    async def _calculate_cvss_scores(self, vulnerability: Dict[str, Any], asset_context: Optional[AssetContext]) -> Dict[str, float]:
        """Calculate CVSS temporal and environmental scores"""
        
        # Placeholder implementation - would integrate with CVSS calculator
        base_score = vulnerability.get('cvss_score', 0.0)
        
        # Temporal factors
        exploit_code_maturity = 0.97  # Functional exploit code
        remediation_level = 0.95  # Official fix available
        report_confidence = 0.96  # Confirmed
        
        temporal_score = base_score * exploit_code_maturity * remediation_level * report_confidence
        
        # Environmental factors
        confidentiality_req = 1.0
        integrity_req = 1.0
        availability_req = 1.0
        
        if asset_context:
            # Map requirements to CVSS environmental values
            req_mapping = {'low': 0.5, 'medium': 1.0, 'high': 1.5}
            confidentiality_req = req_mapping.get(asset_context.confidentiality_requirement, 1.0)
            integrity_req = req_mapping.get(asset_context.integrity_requirement, 1.0)
            availability_req = req_mapping.get(asset_context.availability_requirement, 1.0)
        
        environmental_score = temporal_score * max(confidentiality_req, integrity_req, availability_req)
        
        return {
            'temporal': min(10.0, temporal_score),
            'environmental': min(10.0, environmental_score)
        }
    
    async def _get_epss_score(self, cve_id: str) -> float:
        """Get EPSS score for CVE"""
        # Placeholder implementation - would integrate with EPSS API
        # EPSS scores range from 0-1, representing probability of exploitation
        return 0.5  # Default medium probability
    
    async def _get_ssvc_decision(self, vulnerability: Dict[str, Any], asset_context: Optional[AssetContext]) -> str:
        """Get SSVC decision for vulnerability"""
        # Placeholder implementation - would integrate with SSVC framework
        # SSVC decisions: defer, scheduled, out-of-cycle, immediate
        
        cvss_score = vulnerability.get('cvss_score', 0.0)
        
        if cvss_score >= 9.0:
            return "immediate"
        elif cvss_score >= 7.0:
            return "out-of-cycle"
        elif cvss_score >= 4.0:
            return "scheduled"
        else:
            return "defer"
    
    def _calculate_asset_criticality_multiplier(self, asset_context: AssetContext) -> float:
        """Calculate asset criticality multiplier"""
        base_multiplier = self.config['asset_criticality_multipliers'].get(asset_context.criticality, 1.0)
        
        # Adjust based on business value
        business_value_adjustment = 0.5 + (asset_context.business_value * 0.5)
        
        return base_multiplier * business_value_adjustment
    
    def _calculate_classification_multiplier(self, asset_context: AssetContext) -> float:
        """Calculate classification level multiplier"""
        return self.config['classification_multipliers'].get(asset_context.classification, 1.0)
    
    def _calculate_business_impact_score(self, asset_context: AssetContext) -> float:
        """Calculate business impact score"""
        
        # Base impact from asset criticality
        criticality_impact = {
            'critical': 10.0,
            'high': 7.5,
            'medium': 5.0,
            'low': 2.5
        }.get(asset_context.criticality, 5.0)
        
        # Adjust for business value
        business_adjustment = asset_context.business_value * 2.0
        
        # Adjust for compliance requirements
        compliance_adjustment = len(asset_context.compliance_requirements) * 0.5
        
        total_impact = criticality_impact + business_adjustment + compliance_adjustment
        return min(10.0, total_impact)
    
    def _calculate_exposure_score(self, asset_context: AssetContext) -> float:
        """Calculate asset exposure score"""
        
        exposure_scores = {
            'public': 10.0,
            'internal': 5.0,
            'restricted': 2.0
        }
        
        return exposure_scores.get(asset_context.exposure_level, 5.0)
    
    def _calculate_threat_multiplier(self, threat_context: ThreatContext) -> float:
        """Calculate threat intelligence multiplier"""
        
        multiplier = 1.0
        
        # Increase for available exploits
        if threat_context.exploit_available:
            exploit_multipliers = {
                'high': 1.5,
                'functional': 1.4,
                'poc': 1.2,
                'unproven': 1.1
            }
            multiplier *= exploit_multipliers.get(threat_context.exploit_maturity, 1.2)
        
        # Increase for active campaigns
        if threat_context.active_campaigns:
            multiplier *= 1.3
        
        # Increase for known threat actors
        if threat_context.threat_actors:
            multiplier *= 1.2
        
        # Adjust for exploitation likelihood
        multiplier *= (1.0 + threat_context.exploitation_likelihood * 0.5)
        
        return min(2.0, multiplier)  # Cap at 2x multiplier
    
    def _calculate_exploitability_score(self, threat_context: ThreatContext) -> float:
        """Calculate exploitability score"""
        
        score = 0.0
        
        # Base score from exploit availability
        if threat_context.exploit_available:
            exploit_scores = {
                'high': 9.0,
                'functional': 8.0,
                'poc': 6.0,
                'unproven': 4.0
            }
            score = exploit_scores.get(threat_context.exploit_maturity, 5.0)
        
        # Adjust for exploitation likelihood
        score *= (0.5 + threat_context.exploitation_likelihood * 0.5)
        
        # Adjust for weaponization status
        if threat_context.weaponization_status == 'weaponized':
            score *= 1.3
        
        return min(10.0, score)
    
    async def _calculate_overall_risk_score(self, 
                                          components: RiskScoreComponents, 
                                          method: PrioritizationMethod) -> float:
        """Calculate overall risk score using specified method"""
        
        if method == PrioritizationMethod.CVSS_ONLY:
            return components.cvss_base_score
        
        elif method == PrioritizationMethod.CVSS_EPSS:
            # Weighted combination of CVSS and EPSS
            cvss_norm = components.cvss_base_score / 10.0
            epss_norm = components.epss_score
            
            combined_score = (cvss_norm * 0.7 + epss_norm * 0.3) * 10.0
            return combined_score
        
        elif method == PrioritizationMethod.COMPREHENSIVE:
            # Full comprehensive scoring
            weights = self.config['scoring_weights']
            
            # Normalize scores to 0-1 range
            cvss_base_norm = components.cvss_base_score / 10.0
            cvss_temporal_norm = components.cvss_temporal_score / 10.0
            cvss_env_norm = components.cvss_environmental_score / 10.0
            epss_norm = components.epss_score
            business_impact_norm = components.business_impact_score / 10.0
            exploitability_norm = components.exploitability_score / 10.0
            
            # Calculate weighted score
            weighted_score = (
                cvss_base_norm * weights['cvss_base'] +
                cvss_temporal_norm * weights['cvss_temporal'] +
                cvss_env_norm * weights['cvss_environmental'] +
                epss_norm * weights['epss'] +
                business_impact_norm * 0.1 +
                exploitability_norm * 0.1
            )
            
            # Apply multipliers
            final_score = weighted_score * 10.0
            final_score *= components.asset_criticality_multiplier
            final_score *= components.classification_multiplier
            final_score *= components.threat_intelligence_multiplier
            
            return min(10.0, final_score)
        
        else:
            # Default to CVSS base score
            return components.cvss_base_score
    
    def _determine_risk_level(self, risk_score: float) -> RiskLevel:
        """Determine risk level from risk score"""
        
        thresholds = self.config['risk_thresholds']
        
        if risk_score >= thresholds['critical']:
            return RiskLevel.CRITICAL
        elif risk_score >= thresholds['high']:
            return RiskLevel.HIGH
        elif risk_score >= thresholds['medium']:
            return RiskLevel.MEDIUM
        elif risk_score >= thresholds['low']:
            return RiskLevel.LOW
        else:
            return RiskLevel.INFORMATIONAL
    
    def _calculate_confidence_level(self, 
                                  vulnerability: Dict[str, Any], 
                                  asset_context: Optional[AssetContext], 
                                  threat_context: Optional[ThreatContext]) -> float:
        """Calculate confidence level for risk assessment"""
        
        confidence = 0.5  # Base confidence
        
        # Increase confidence if CVE is available
        if vulnerability.get('cve_id'):
            confidence += 0.2
        
        # Increase confidence if CVSS score is available
        if vulnerability.get('cvss_score', 0.0) > 0:
            confidence += 0.15
        
        # Increase confidence if asset context is available
        if asset_context:
            confidence += 0.1
        
        # Increase confidence if threat intelligence is available
        if threat_context and threat_context.exploit_available:
            confidence += 0.15
        
        return min(1.0, confidence)
    
    def _generate_business_justification(self, 
                                       vulnerability: Dict[str, Any],
                                       asset_context: Optional[AssetContext],
                                       threat_context: Optional[ThreatContext],
                                       risk_score: float) -> str:
        """Generate business justification for risk assessment"""
        
        justification_parts = []
        
        # Risk level justification
        risk_level = self._determine_risk_level(risk_score)
        justification_parts.append(f"Risk level: {risk_level.value.title()} (Score: {risk_score:.2f})")
        
        # CVSS justification
        cvss_score = vulnerability.get('cvss_score', 0.0)
        if cvss_score > 0:
            justification_parts.append(f"CVSS Base Score: {cvss_score}/10.0")
        
        # Asset context justification
        if asset_context:
            justification_parts.append(f"Asset Criticality: {asset_context.criticality.title()}")
            justification_parts.append(f"Classification: {asset_context.classification}")
            
            if asset_context.compliance_requirements:
                req_str = ", ".join(asset_context.compliance_requirements)
                justification_parts.append(f"Compliance Requirements: {req_str}")
        
        # Threat context justification
        if threat_context:
            if threat_context.exploit_available:
                justification_parts.append(f"Exploit Available: {threat_context.exploit_maturity}")
            
            if threat_context.active_campaigns:
                justification_parts.append("Active exploitation campaigns detected")
            
            if threat_context.threat_actors:
                justification_parts.append("Known threat actor involvement")
        
        return "; ".join(justification_parts)
    
    def _determine_remediation_urgency(self, risk_level: RiskLevel, components: RiskScoreComponents) -> str:
        """Determine remediation urgency"""
        
        if risk_level == RiskLevel.CRITICAL:
            if components.exploitability_score >= 8.0:
                return "immediate"
            else:
                return "urgent"
        elif risk_level == RiskLevel.HIGH:
            if components.threat_intelligence_multiplier > 1.3:
                return "urgent"
            else:
                return "high"
        elif risk_level == RiskLevel.MEDIUM:
            return "medium"
        elif risk_level == RiskLevel.LOW:
            return "low"
        else:
            return "informational"
    
    async def _save_risk_assessment(self, assessment: VulnerabilityRiskAssessment):
        """Save risk assessment to database"""
        
        with sqlite3.connect(self.db_path) as conn:
            now = datetime.now(timezone.utc).isoformat()
            
            conn.execute("""
                INSERT OR REPLACE INTO risk_assessments (
                    assessment_id, vulnerability_id, assessment_timestamp, risk_level,
                    overall_risk_score, priority_rank, score_components, asset_context,
                    threat_context, remediation_urgency, business_justification,
                    risk_acceptance_threshold, confidence_level, assessment_method,
                    metadata, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                assessment.assessment_id,
                assessment.vulnerability_id,
                assessment.assessment_timestamp.isoformat(),
                assessment.risk_level.value,
                assessment.overall_risk_score,
                assessment.priority_rank,
                json.dumps(assessment.score_components.__dict__),
                json.dumps(assessment.asset_context.__dict__) if assessment.asset_context else None,
                json.dumps(assessment.threat_context.__dict__) if assessment.threat_context else None,
                assessment.remediation_urgency,
                assessment.business_justification,
                assessment.risk_acceptance_threshold,
                assessment.confidence_level,
                assessment.assessment_method.value,
                json.dumps(assessment.metadata),
                now,
                now
            ))
    
    async def _update_risk_trends(self, vulnerability_id: str, assessment: VulnerabilityRiskAssessment):
        """Update risk trends for vulnerability"""
        
        with sqlite3.connect(self.db_path) as conn:
            now = datetime.now(timezone.utc).isoformat()
            
            conn.execute("""
                INSERT INTO risk_trends (
                    vulnerability_id, assessment_date, risk_score, risk_level,
                    factors_changed, created_at
                ) VALUES (?, ?, ?, ?, ?, ?)
            """, (
                vulnerability_id,
                assessment.assessment_timestamp.isoformat(),
                assessment.overall_risk_score,
                assessment.risk_level.value,
                json.dumps({"method": assessment.assessment_method.value}),
                now
            ))
    
    async def prioritize_vulnerabilities(self, 
                                       vulnerability_ids: List[str],
                                       method: Optional[PrioritizationMethod] = None) -> List[VulnerabilityRiskAssessment]:
        """Prioritize a list of vulnerabilities"""
        
        assessments = []
        
        # Get assessments for vulnerabilities
        with sqlite3.connect(self.db_path) as conn:
            placeholders = ','.join('?' * len(vulnerability_ids))
            cursor = conn.execute(f"""
                SELECT * FROM risk_assessments 
                WHERE vulnerability_id IN ({placeholders})
                ORDER BY overall_risk_score DESC, assessment_timestamp DESC
            """, vulnerability_ids)
            
            for idx, row in enumerate(cursor.fetchall()):
                assessment = self._row_to_assessment(row)
                assessment.priority_rank = idx + 1
                assessments.append(assessment)
        
        # Update priority ranks in database
        for assessment in assessments:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    UPDATE risk_assessments 
                    SET priority_rank = ?, updated_at = ?
                    WHERE assessment_id = ?
                """, (
                    assessment.priority_rank,
                    datetime.now(timezone.utc).isoformat(),
                    assessment.assessment_id
                ))
        
        return assessments
    
    def _row_to_assessment(self, row: tuple) -> VulnerabilityRiskAssessment:
        """Convert database row to VulnerabilityRiskAssessment"""
        
        # Parse score components
        score_components_data = json.loads(row[6]) if row[6] else {}
        score_components = RiskScoreComponents(**score_components_data)
        
        # Parse asset context
        asset_context = None
        if row[7]:
            asset_data = json.loads(row[7])
            asset_context = AssetContext(**asset_data)
        
        # Parse threat context
        threat_context = None
        if row[8]:
            threat_data = json.loads(row[8])
            threat_context = ThreatContext(**threat_data)
        
        return VulnerabilityRiskAssessment(
            assessment_id=row[0],
            vulnerability_id=row[1],
            assessment_timestamp=datetime.fromisoformat(row[2]),
            risk_level=RiskLevel(row[3]),
            overall_risk_score=row[4],
            priority_rank=row[5] or 0,
            score_components=score_components,
            asset_context=asset_context,
            threat_context=threat_context,
            remediation_urgency=row[9],
            business_justification=row[10],
            risk_acceptance_threshold=row[11],
            confidence_level=row[12],
            assessment_method=PrioritizationMethod(row[13]),
            metadata=json.loads(row[14]) if row[14] else {}
        )
    
    async def get_risk_dashboard_data(self, days: int = 30) -> Dict[str, Any]:
        """Get risk dashboard data"""
        
        since_date = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        
        with sqlite3.connect(self.db_path) as conn:
            # Risk level distribution
            cursor = conn.execute("""
                SELECT risk_level, COUNT(*) as count
                FROM risk_assessments
                WHERE assessment_timestamp > ?
                GROUP BY risk_level
            """, (since_date,))
            risk_distribution = dict(cursor.fetchall())
            
            # Average risk scores by asset criticality
            cursor = conn.execute("""
                SELECT 
                    JSON_EXTRACT(asset_context, '$.criticality') as criticality,
                    AVG(overall_risk_score) as avg_score,
                    COUNT(*) as count
                FROM risk_assessments
                WHERE assessment_timestamp > ? AND asset_context IS NOT NULL
                GROUP BY JSON_EXTRACT(asset_context, '$.criticality')
            """, (since_date,))
            criticality_scores = {}
            for row in cursor.fetchall():
                if row[0]:
                    criticality_scores[row[0]] = {
                        'average_score': round(row[1], 2),
                        'vulnerability_count': row[2]
                    }
            
            # Risk trends
            cursor = conn.execute("""
                SELECT 
                    DATE(assessment_date) as date,
                    AVG(risk_score) as avg_score,
                    COUNT(*) as count
                FROM risk_trends
                WHERE assessment_date > ?
                GROUP BY DATE(assessment_date)
                ORDER BY date
            """, (since_date,))
            risk_trends = [
                {
                    'date': row[0],
                    'average_score': round(row[1], 2),
                    'assessment_count': row[2]
                }
                for row in cursor.fetchall()
            ]
            
            # Top vulnerabilities
            cursor = conn.execute("""
                SELECT vulnerability_id, overall_risk_score, risk_level, remediation_urgency
                FROM risk_assessments
                WHERE assessment_timestamp > ?
                ORDER BY overall_risk_score DESC
                LIMIT 10
            """, (since_date,))
            top_vulnerabilities = [
                {
                    'vulnerability_id': row[0],
                    'risk_score': row[1],
                    'risk_level': row[2],
                    'urgency': row[3]
                }
                for row in cursor.fetchall()
            ]
            
            return {
                'period_days': days,
                'risk_level_distribution': risk_distribution,
                'risk_by_asset_criticality': criticality_scores,
                'risk_trends': risk_trends,
                'top_vulnerabilities': top_vulnerabilities,
                'total_assessments': sum(risk_distribution.values())
            }