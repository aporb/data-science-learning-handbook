"""
Risk Assessment and Prioritization Module
=========================================

Advanced risk assessment and prioritization engine that combines multiple
vulnerability scoring methodologies with organizational context to provide
intelligent vulnerability prioritization.

Components:
- RiskAssessmentEngine: Main risk assessment orchestration
- CVSSCalculator: CVSS 3.1 scoring and analysis
- EPSSIntegration: Exploit Prediction Scoring System
- SSVCFramework: Stakeholder-Specific Vulnerability Categorization
- AssetCriticalityAnalyzer: Asset importance and business impact assessment
- ClassificationRiskWeighting: DoD classification level risk adjustments
- ThreatIntelligenceCorrelator: Threat intelligence integration
- PrioritizationFramework: Multi-criteria decision framework
"""

from .risk_assessment_engine import RiskAssessmentEngine
from .cvss_calculator import CVSSCalculator
from .epss_integration import EPSSIntegration
from .ssvc_framework import SSVCFramework
from .asset_criticality_analyzer import AssetCriticalityAnalyzer
from .classification_risk_weighting import ClassificationRiskWeighting
from .threat_intelligence_correlator import ThreatIntelligenceCorrelator
from .prioritization_framework import PrioritizationFramework

__all__ = [
    'RiskAssessmentEngine',
    'CVSSCalculator',
    'EPSSIntegration',
    'SSVCFramework',
    'AssetCriticalityAnalyzer',
    'ClassificationRiskWeighting',
    'ThreatIntelligenceCorrelator',
    'PrioritizationFramework'
]