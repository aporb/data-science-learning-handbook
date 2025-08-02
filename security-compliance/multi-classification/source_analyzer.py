"""
Source-Based Data Analysis for Automated Labeling
================================================

This module provides comprehensive source-based analysis capabilities for automated
data labeling, including network domain analysis, user clearance verification,
system classification mapping, and data origin tracking.

Key Features:
- Network domain classification (NIPR, SIPR, JWICS)
- User clearance level verification and mapping
- System-based classification inheritance
- Data lineage and provenance tracking
- Cross-domain transfer analysis
- Source reliability scoring
- Real-time source validation
- Compliance with DoD security policies

Classification: UNCLASSIFIED//FOR OFFICIAL USE ONLY
Version: 1.0 - Initial Implementation
Author: Security Compliance Team
Date: 2025-07-29
"""

import asyncio
import json
import logging
import time
import re
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Tuple, Set, Union
from uuid import UUID, uuid4
from dataclasses import dataclass, field, asdict
from enum import Enum
from ipaddress import IPv4Address, IPv6Address, AddressValueError
import hashlib

# Import existing infrastructure
from .models.bell_lapadula import BellLaPadulaSecurityModel, SecurityLabel, ClassificationLevel
from ..rbac.models.classification import SecurityClearance
from ..rbac.models.data_classification import NetworkDomain, DataSensitivity
from ..rbac.models.user import User
from ..rbac.rbac_engine import RBACEngine
from ..audits.audit_logger import AuditLogger

logger = logging.getLogger(__name__)


class SourceReliability(Enum):
    """Source reliability levels."""
    VERIFIED = "verified"           # Cryptographically verified
    AUTHENTICATED = "authenticated" # Properly authenticated
    TRUSTED = "trusted"            # From trusted system
    UNVERIFIED = "unverified"      # Unknown or unverified
    SUSPICIOUS = "suspicious"       # Potentially compromised


class DataLineageType(Enum):
    """Types of data lineage tracking."""
    DIRECT_INPUT = "direct_input"
    DERIVED_DATA = "derived_data"
    AGGREGATED_DATA = "aggregated_data"
    TRANSFORMED_DATA = "transformed_data"
    CROSS_DOMAIN_TRANSFER = "cross_domain_transfer"


class NetworkSecurityZone(Enum):
    """Network security zones for classification."""
    DMZ = "dmz"
    INTERNAL = "internal"
    RESTRICTED = "restricted"
    CLASSIFIED = "classified"
    TOP_SECRET = "top_secret"


@dataclass
class NetworkAnalysisResult:
    """Result of network-based source analysis."""
    source_ip: Optional[str] = None
    network_domain: Optional[NetworkDomain] = None
    security_zone: Optional[NetworkSecurityZone] = None
    classification_level: ClassificationLevel = ClassificationLevel.UNCLASSIFIED
    
    # Network metadata
    subnet: Optional[str] = None
    gateway: Optional[str] = None
    vlan_id: Optional[int] = None
    
    # Security attributes
    is_encrypted: bool = False
    protocol_security: str = ""
    network_isolation: bool = False
    
    # Validation
    is_valid_source: bool = True
    validation_errors: List[str] = field(default_factory=list)
    reliability: SourceReliability = SourceReliability.UNVERIFIED
    
    # Timestamps
    analyzed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class UserClearanceAnalysis:
    """Result of user clearance analysis."""
    user_id: UUID
    current_clearance: Optional[SecurityClearance] = None
    effective_classification: ClassificationLevel = ClassificationLevel.UNCLASSIFIED
    
    # Clearance details
    clearance_level: Optional[str] = None
    compartments: List[str] = field(default_factory=list)
    special_access_programs: List[str] = field(default_factory=list)
    
    # Verification status
    is_active: bool = False
    is_valid: bool = False
    expiration_date: Optional[datetime] = None
    last_investigation: Optional[datetime] = None
    
    # Access limitations
    network_restrictions: List[NetworkDomain] = field(default_factory=list)
    time_restrictions: Dict[str, Any] = field(default_factory=dict)
    location_restrictions: List[str] = field(default_factory=list)
    
    # Risk factors
    risk_score: float = 0.0
    risk_factors: List[str] = field(default_factory=list)
    
    # Metadata
    reliability: SourceReliability = SourceReliability.UNVERIFIED
    analyzed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class SystemClassificationAnalysis:
    """Result of system-based classification analysis."""
    system_id: str
    system_name: Optional[str] = None
    system_type: Optional[str] = None
    
    # Classification attributes
    system_classification: ClassificationLevel = ClassificationLevel.UNCLASSIFIED
    accreditation_level: Optional[str] = None
    security_controls: List[str] = field(default_factory=list)
    
    # System metadata
    owner_organization: Optional[str] = None
    custodian: Optional[str] = None
    deployment_environment: Optional[str] = None
    
    # Compliance status
    is_accredited: bool = False
    compliance_frameworks: List[str] = field(default_factory=list)
    last_assessment: Optional[datetime] = None
    
    # Network information
    network_domains: List[NetworkDomain] = field(default_factory=list)
    network_segments: List[str] = field(default_factory=list)
    
    # Reliability
    reliability: SourceReliability = SourceReliability.UNVERIFIED
    analyzed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class DataLineageAnalysis:
    """Result of data lineage analysis."""
    source_data_id: Optional[str] = None
    lineage_type: DataLineageType = DataLineageType.DIRECT_INPUT
    
    # Source chain
    parent_sources: List[str] = field(default_factory=list)
    transformation_history: List[Dict[str, Any]] = field(default_factory=list)
    
    # Classification inheritance
    inherited_classification: ClassificationLevel = ClassificationLevel.UNCLASSIFIED
    classification_rationale: str = ""
    
    # Cross-domain information
    domain_transfers: List[Dict[str, Any]] = field(default_factory=list)
    sanitization_applied: bool = False
    
    # Metadata
    creation_timestamp: Optional[datetime] = None
    last_modified: Optional[datetime] = None
    analyzed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class ComprehensiveSourceAnalysis:
    """Comprehensive source analysis result."""
    request_id: str
    
    # Component analyses
    network_analysis: Optional[NetworkAnalysisResult] = None
    user_analysis: Optional[UserClearanceAnalysis] = None
    system_analysis: Optional[SystemClassificationAnalysis] = None
    lineage_analysis: Optional[DataLineageAnalysis] = None
    
    # Overall assessment
    final_classification: ClassificationLevel = ClassificationLevel.UNCLASSIFIED
    confidence_score: float = 0.0
    reliability_score: float = 0.0
    
    # Risk assessment
    risk_factors: List[str] = field(default_factory=list)
    security_concerns: List[str] = field(default_factory=list)
    
    # Compliance
    dod_compliance: bool = True
    network_compliance: Dict[NetworkDomain, bool] = field(default_factory=dict)
    
    # Processing metadata
    processing_time_ms: float = 0.0
    sources_analyzed: int = 0
    errors_encountered: List[str] = field(default_factory=list)
    
    # Timestamps
    analyzed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class NetworkDomainMapper:
    """Maps network addresses and domains to classification levels."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize network domain mapper."""
        self.config = config or {}
        
        # Load network classification mappings
        self._load_network_mappings()
        
        # Initialize IP range analyzers
        self._ip_classifiers = {}
        
        logger.info("NetworkDomainMapper initialized")
    
    def _load_network_mappings(self):
        """Load network classification mappings from configuration."""
        # Default network mappings (can be overridden by config)
        self.network_mappings = self.config.get('network_mappings', {
            # NIPR (Non-classified Internet Protocol Router Network)
            'nipr': {
                'domains': ['.mil', '.gov'],
                'ip_ranges': ['198.18.0.0/15', '10.0.0.0/8'],
                'classification': ClassificationLevel.UNCLASSIFIED,
                'security_zone': NetworkSecurityZone.INTERNAL
            },
            
            # SIPR (Secret Internet Protocol Router Network)
            'sipr': {
                'domains': ['.smil.mil', '.sipr.mil'],
                'ip_ranges': ['192.168.0.0/16', '172.16.0.0/12'],
                'classification': ClassificationLevel.SECRET,
                'security_zone': NetworkSecurityZone.CLASSIFIED
            },
            
            # JWICS (Joint Worldwide Intelligence Communications System)
            'jwics': {
                'domains': ['.ic.gov', '.jwics.mil'],
                'ip_ranges': ['10.32.0.0/12'],
                'classification': ClassificationLevel.TOP_SECRET,
                'security_zone': NetworkSecurityZone.TOP_SECRET
            }
        })
        
        # System classification mappings
        self.system_mappings = self.config.get('system_mappings', {
            'sipr_portal': ClassificationLevel.SECRET,
            'jwics_portal': ClassificationLevel.TOP_SECRET,
            'unclass_portal': ClassificationLevel.UNCLASSIFIED,
            'disa_system': ClassificationLevel.CONFIDENTIAL
        })
    
    def analyze_network_source(
        self, 
        source_ip: Optional[str] = None,
        source_domain: Optional[str] = None,
        source_hostname: Optional[str] = None
    ) -> NetworkAnalysisResult:
        """Analyze network source for classification."""
        result = NetworkAnalysisResult(source_ip=source_ip)
        
        try:
            # Analyze IP address if provided
            if source_ip:
                result = self._analyze_ip_address(source_ip, result)
            
            # Analyze domain if provided
            if source_domain:
                result = self._analyze_domain(source_domain, result)
            
            # Analyze hostname if provided
            if source_hostname:
                result = self._analyze_hostname(source_hostname, result)
            
            # Validate results
            result = self._validate_network_analysis(result)
            
            logger.debug(f"Network analysis complete: {result.classification_level}")
            
        except Exception as e:
            logger.error(f"Network source analysis failed: {e}")
            result.is_valid_source = False
            result.validation_errors.append(str(e))
            result.reliability = SourceReliability.SUSPICIOUS
        
        return result
    
    def _analyze_ip_address(self, ip_address: str, result: NetworkAnalysisResult) -> NetworkAnalysisResult:
        """Analyze IP address for classification."""
        try:
            # Parse IP address
            ip = IPv4Address(ip_address) if '.' in ip_address else IPv6Address(ip_address)
            
            # Check against known IP ranges
            for network_name, network_config in self.network_mappings.items():
                for ip_range in network_config.get('ip_ranges', []):
                    # Simple string-based matching (in production, use proper IP network checking)
                    if self._ip_in_range(str(ip), ip_range):
                        result.classification_level = network_config['classification']
                        result.security_zone = network_config['security_zone']
                        result.network_domain = self._map_network_domain(network_name)
                        result.reliability = SourceReliability.VERIFIED
                        break
            
            # Determine subnet information
            result.subnet = self._determine_subnet(str(ip))
            
        except AddressValueError as e:
            result.validation_errors.append(f"Invalid IP address: {e}")
            result.is_valid_source = False
        
        return result
    
    def _analyze_domain(self, domain: str, result: NetworkAnalysisResult) -> NetworkAnalysisResult:
        """Analyze domain name for classification."""
        domain = domain.lower()
        
        # Check against known domain patterns
        for network_name, network_config in self.network_mappings.items():
            for domain_pattern in network_config.get('domains', []):
                if domain.endswith(domain_pattern):
                    result.classification_level = max(
                        result.classification_level,
                        network_config['classification'],
                        key=lambda x: x.value
                    )
                    result.security_zone = network_config['security_zone']
                    result.network_domain = self._map_network_domain(network_name)
                    result.reliability = SourceReliability.AUTHENTICATED
                    break
        
        # Check for suspicious domains
        if self._is_suspicious_domain(domain):
            result.reliability = SourceReliability.SUSPICIOUS
            result.validation_errors.append(f"Suspicious domain: {domain}")
        
        return result
    
    def _analyze_hostname(self, hostname: str, result: NetworkAnalysisResult) -> NetworkAnalysisResult:
        """Analyze hostname for classification hints."""
        hostname = hostname.lower()
        
        # Look for classification indicators in hostname
        classification_indicators = {
            'secret': ClassificationLevel.SECRET,
            'confidential': ClassificationLevel.CONFIDENTIAL,
            'classified': ClassificationLevel.CONFIDENTIAL,
            'sipr': ClassificationLevel.SECRET,
            'jwics': ClassificationLevel.TOP_SECRET,
            'ts': ClassificationLevel.TOP_SECRET
        }
        
        for indicator, classification in classification_indicators.items():
            if indicator in hostname:
                result.classification_level = max(
                    result.classification_level,
                    classification,
                    key=lambda x: x.value
                )
        
        return result
    
    def _ip_in_range(self, ip: str, ip_range: str) -> bool:
        """Check if IP is in range (simplified implementation)."""
        # In production, use ipaddress.ip_network for proper checking
        return ip.startswith(ip_range.split('/')[0].rsplit('.', 1)[0])
    
    def _determine_subnet(self, ip: str) -> str:
        """Determine subnet for IP address."""
        # Simplified subnet determination
        parts = ip.split('.')
        if len(parts) >= 3:
            return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
        return ip
    
    def _map_network_domain(self, network_name: str) -> NetworkDomain:
        """Map network name to NetworkDomain enum."""
        mapping = {
            'nipr': NetworkDomain.NIPR,
            'sipr': NetworkDomain.SIPR,
            'jwics': NetworkDomain.JWICS
        }
        return mapping.get(network_name, NetworkDomain.NIPR)
    
    def _is_suspicious_domain(self, domain: str) -> bool:
        """Check if domain appears suspicious."""
        suspicious_patterns = [
            r'\d+\.\d+\.\d+\.\d+',  # IP addresses as domains
            r'[a-z0-9]{20,}',       # Very long random strings
            r'.*\.tk$|.*\.ml$',     # Free domains
        ]
        
        return any(re.match(pattern, domain) for pattern in suspicious_patterns)
    
    def _validate_network_analysis(self, result: NetworkAnalysisResult) -> NetworkAnalysisResult:
        """Validate network analysis results."""
        # Check for consistency
        if result.network_domain and result.classification_level:
            expected_classification = self._classify_by_network(result.network_domain)
            if result.classification_level.value < expected_classification.value:
                result.validation_errors.append(
                    f"Classification level {result.classification_level} is lower than expected for {result.network_domain}"
                )
        
        # Set reliability based on validation
        if not result.validation_errors and result.classification_level != ClassificationLevel.UNCLASSIFIED:
            result.reliability = SourceReliability.VERIFIED
        elif result.validation_errors:
            result.reliability = SourceReliability.SUSPICIOUS
        
        return result
    
    def _classify_by_network(self, network: NetworkDomain) -> ClassificationLevel:
        """Get expected classification for network domain."""
        network_classifications = {
            NetworkDomain.NIPR: ClassificationLevel.UNCLASSIFIED,
            NetworkDomain.SIPR: ClassificationLevel.SECRET,
            NetworkDomain.JWICS: ClassificationLevel.TOP_SECRET
        }
        return network_classifications.get(network, ClassificationLevel.UNCLASSIFIED)


class UserClearanceAnalyzer:
    """Analyzes user clearance information for source-based labeling."""
    
    def __init__(
        self,
        rbac_engine: Optional[RBACEngine] = None,
        config: Optional[Dict[str, Any]] = None
    ):
        """Initialize user clearance analyzer."""
        self.rbac_engine = rbac_engine or RBACEngine()
        self.config = config or {}
        
        # Cache for user clearance information
        self._clearance_cache: Dict[UUID, UserClearanceAnalysis] = {}
        self._cache_ttl = self.config.get('cache_ttl_seconds', 300)  # 5 minutes
        
        logger.info("UserClearanceAnalyzer initialized")
    
    async def analyze_user_clearance(self, user_id: UUID) -> UserClearanceAnalysis:
        """Analyze user clearance for classification purposes."""
        # Check cache first
        cached_analysis = self._get_cached_analysis(user_id)
        if cached_analysis:
            logger.debug(f"Using cached clearance analysis for user {user_id}")
            return cached_analysis
        
        analysis = UserClearanceAnalysis(user_id=user_id)
        
        try:
            # Get user information from RBAC engine
            user = await self._get_user_info(user_id)
            if not user:
                analysis.reliability = SourceReliability.UNVERIFIED
                analysis.risk_factors.append("User not found in system")
                return analysis
            
            # Analyze current clearance
            analysis = await self._analyze_current_clearance(user, analysis)
            
            # Check clearance validity and status
            analysis = await self._validate_clearance_status(user, analysis)
            
            # Assess risk factors
            analysis = self._assess_clearance_risks(analysis)
            
            # Cache the analysis
            self._cache_analysis(user_id, analysis)
            
            logger.debug(f"User clearance analysis complete for {user_id}: {analysis.effective_classification}")
            
        except Exception as e:
            logger.error(f"User clearance analysis failed for {user_id}: {e}")
            analysis.reliability = SourceReliability.SUSPICIOUS
            analysis.risk_factors.append(f"Analysis error: {str(e)}")
        
        return analysis
    
    async def _get_user_info(self, user_id: UUID) -> Optional[User]:
        """Get user information from RBAC system."""
        try:
            return await self.rbac_engine.get_user(user_id)
        except Exception as e:
            logger.warning(f"Failed to get user info for {user_id}: {e}")
            return None
    
    async def _analyze_current_clearance(
        self, 
        user: User, 
        analysis: UserClearanceAnalysis
    ) -> UserClearanceAnalysis:
        """Analyze user's current security clearance."""
        if hasattr(user, 'security_clearance') and user.security_clearance:
            clearance = user.security_clearance
            analysis.current_clearance = clearance
            analysis.effective_classification = clearance.classification_level
            analysis.clearance_level = clearance.level
            
            # Extract compartments and special access programs
            if hasattr(clearance, 'compartments'):
                analysis.compartments = list(clearance.compartments)
            
            if hasattr(clearance, 'special_access_programs'):
                analysis.special_access_programs = list(clearance.special_access_programs)
            
            # Check validity
            analysis.is_active = getattr(clearance, 'is_active', False)
            analysis.is_valid = getattr(clearance, 'is_valid', False)
            analysis.expiration_date = getattr(clearance, 'expiration_date', None)
            analysis.last_investigation = getattr(clearance, 'last_investigation', None)
            
            # Set reliability based on clearance status
            if analysis.is_active and analysis.is_valid:
                analysis.reliability = SourceReliability.VERIFIED
            elif analysis.is_valid:
                analysis.reliability = SourceReliability.AUTHENTICATED
            else:
                analysis.reliability = SourceReliability.UNVERIFIED
        
        return analysis
    
    async def _validate_clearance_status(
        self, 
        user: User, 
        analysis: UserClearanceAnalysis
    ) -> UserClearanceAnalysis:
        """Validate clearance status and restrictions."""
        if analysis.current_clearance:
            # Check expiration
            if analysis.expiration_date:
                if analysis.expiration_date < datetime.now(timezone.utc):
                    analysis.is_valid = False
                    analysis.risk_factors.append("Clearance expired")
                elif analysis.expiration_date < datetime.now(timezone.utc) + timedelta(days=30):
                    analysis.risk_factors.append("Clearance expires within 30 days")
            
            # Check investigation currency
            if analysis.last_investigation:
                investigation_age = datetime.now(timezone.utc) - analysis.last_investigation
                if investigation_age > timedelta(days=1825):  # 5 years
                    analysis.risk_factors.append("Investigation over 5 years old")
            
            # Check for restrictions
            if hasattr(user, 'access_restrictions'):
                restrictions = user.access_restrictions
                analysis.network_restrictions = getattr(restrictions, 'network_restrictions', [])
                analysis.time_restrictions = getattr(restrictions, 'time_restrictions', {})
                analysis.location_restrictions = getattr(restrictions, 'location_restrictions', [])
        
        return analysis
    
    def _assess_clearance_risks(self, analysis: UserClearanceAnalysis) -> UserClearanceAnalysis:
        """Assess risk factors for clearance reliability."""
        risk_score = 0.0
        
        # Base risk assessment
        if not analysis.is_valid:
            risk_score += 0.5
        if not analysis.is_active:
            risk_score += 0.3
        
        # Time-based risks
        if analysis.expiration_date:
            days_to_expiry = (analysis.expiration_date - datetime.now(timezone.utc)).days
            if days_to_expiry < 0:
                risk_score += 0.6  # Expired
            elif days_to_expiry < 30:
                risk_score += 0.2  # Expiring soon
        
        # Investigation currency
        if analysis.last_investigation:
            investigation_age_days = (datetime.now(timezone.utc) - analysis.last_investigation).days
            if investigation_age_days > 1825:  # > 5 years
                risk_score += 0.3
            elif investigation_age_days > 1460:  # > 4 years
                risk_score += 0.1
        
        # Restrictions penalty
        if analysis.network_restrictions:
            risk_score += 0.1
        if analysis.time_restrictions:
            risk_score += 0.1
        if analysis.location_restrictions:
            risk_score += 0.1
        
        analysis.risk_score = min(risk_score, 1.0)
        
        # Update reliability based on risk score
        if analysis.risk_score > 0.7:
            analysis.reliability = SourceReliability.SUSPICIOUS
        elif analysis.risk_score > 0.4:
            analysis.reliability = SourceReliability.UNVERIFIED
        elif analysis.reliability == SourceReliability.UNVERIFIED and analysis.risk_score < 0.2:
            analysis.reliability = SourceReliability.TRUSTED
        
        return analysis
    
    def _get_cached_analysis(self, user_id: UUID) -> Optional[UserClearanceAnalysis]:
        """Get cached clearance analysis if valid."""
        if user_id in self._clearance_cache:
            analysis = self._clearance_cache[user_id]
            age = datetime.now(timezone.utc) - analysis.analyzed_at
            if age.total_seconds() < self._cache_ttl:
                return analysis
            else:
                del self._clearance_cache[user_id]
        return None
    
    def _cache_analysis(self, user_id: UUID, analysis: UserClearanceAnalysis):
        """Cache clearance analysis."""
        self._clearance_cache[user_id] = analysis


class SystemClassificationAnalyzer:
    """Analyzes system-based classification information."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize system classification analyzer."""
        self.config = config or {}
        
        # Load system classification mappings
        self._load_system_mappings()
        
        logger.info("SystemClassificationAnalyzer initialized")
    
    def _load_system_mappings(self):
        """Load system classification mappings."""
        self.system_mappings = self.config.get('system_mappings', {
            # Default system classifications
            'sipr_portal': {
                'classification': ClassificationLevel.SECRET,
                'accreditation': 'ATO',
                'networks': [NetworkDomain.SIPR],
                'controls': ['SC-7', 'SC-8', 'IA-2']
            },
            'jwics_portal': {
                'classification': ClassificationLevel.TOP_SECRET,
                'accreditation': 'ATO',
                'networks': [NetworkDomain.JWICS],
                'controls': ['SC-7', 'SC-8', 'IA-2', 'IA-3']
            },
            'unclass_portal': {
                'classification': ClassificationLevel.UNCLASSIFIED,
                'accreditation': 'ATO',
                'networks': [NetworkDomain.NIPR],
                'controls': ['SC-7', 'AC-2']
            }
        })
    
    def analyze_system_classification(self, system_id: str) -> SystemClassificationAnalysis:
        """Analyze system for classification information."""
        analysis = SystemClassificationAnalysis(system_id=system_id)
        
        try:
            # Look up system in mappings
            system_config = self._get_system_config(system_id)
            if system_config:
                analysis = self._populate_from_config(analysis, system_config)
                analysis.reliability = SourceReliability.VERIFIED
            else:
                # Try to infer from system ID
                analysis = self._infer_from_system_id(analysis, system_id)
                analysis.reliability = SourceReliability.UNVERIFIED
            
            # Validate system analysis
            analysis = self._validate_system_analysis(analysis)
            
            logger.debug(f"System analysis complete for {system_id}: {analysis.system_classification}")
            
        except Exception as e:
            logger.error(f"System analysis failed for {system_id}: {e}")
            analysis.reliability = SourceReliability.SUSPICIOUS
        
        return analysis
    
    def _get_system_config(self, system_id: str) -> Optional[Dict[str, Any]]:
        """Get system configuration from mappings."""
        # Try exact match first
        if system_id in self.system_mappings:
            return self.system_mappings[system_id]
        
        # Try partial matches
        system_id_lower = system_id.lower()
        for mapped_id, config in self.system_mappings.items():
            if mapped_id.lower() in system_id_lower or system_id_lower in mapped_id.lower():
                return config
        
        return None
    
    def _populate_from_config(
        self, 
        analysis: SystemClassificationAnalysis, 
        config: Dict[str, Any]
    ) -> SystemClassificationAnalysis:
        """Populate analysis from system configuration."""
        analysis.system_classification = config.get('classification', ClassificationLevel.UNCLASSIFIED)
        analysis.accreditation_level = config.get('accreditation', '')
        analysis.security_controls = config.get('controls', [])
        analysis.network_domains = config.get('networks', [])
        analysis.is_accredited = config.get('accreditation') == 'ATO'
        analysis.compliance_frameworks = config.get('frameworks', ['NIST', 'DISA STIG'])
        
        return analysis
    
    def _infer_from_system_id(
        self, 
        analysis: SystemClassificationAnalysis, 
        system_id: str
    ) -> SystemClassificationAnalysis:
        """Infer classification from system ID patterns."""
        system_id_lower = system_id.lower()
        
        # Look for classification indicators
        if any(indicator in system_id_lower for indicator in ['sipr', 'secret']):
            analysis.system_classification = ClassificationLevel.SECRET
            analysis.network_domains = [NetworkDomain.SIPR]
        elif any(indicator in system_id_lower for indicator in ['jwics', 'ts', 'topsecret']):
            analysis.system_classification = ClassificationLevel.TOP_SECRET
            analysis.network_domains = [NetworkDomain.JWICS]
        elif any(indicator in system_id_lower for indicator in ['confidential', 'conf']):
            analysis.system_classification = ClassificationLevel.CONFIDENTIAL
        elif any(indicator in system_id_lower for indicator in ['unclass', 'nipr']):
            analysis.system_classification = ClassificationLevel.UNCLASSIFIED
            analysis.network_domains = [NetworkDomain.NIPR]
        
        return analysis
    
    def _validate_system_analysis(
        self, 
        analysis: SystemClassificationAnalysis
    ) -> SystemClassificationAnalysis:
        """Validate system analysis results."""
        # Check for consistency between classification and networks
        if analysis.network_domains and analysis.system_classification:
            for network in analysis.network_domains:
                expected_classification = self._get_network_classification(network)
                if analysis.system_classification.value < expected_classification.value:
                    # System classification should not be lower than network requirement
                    analysis.system_classification = expected_classification
        
        return analysis
    
    def _get_network_classification(self, network: NetworkDomain) -> ClassificationLevel:
        """Get minimum classification level for network."""
        network_classifications = {
            NetworkDomain.NIPR: ClassificationLevel.UNCLASSIFIED,
            NetworkDomain.SIPR: ClassificationLevel.SECRET,
            NetworkDomain.JWICS: ClassificationLevel.TOP_SECRET
        }
        return network_classifications.get(network, ClassificationLevel.UNCLASSIFIED)


class SourceAnalyzer:
    """
    Comprehensive source analyzer that combines network, user, and system analysis
    for automated data labeling.
    """
    
    def __init__(
        self,
        rbac_engine: Optional[RBACEngine] = None,
        audit_logger: Optional[AuditLogger] = None,
        config: Optional[Dict[str, Any]] = None
    ):
        """Initialize comprehensive source analyzer."""
        self.config = config or {}
        
        # Initialize component analyzers
        self.network_analyzer = NetworkDomainMapper(config.get('network_config'))
        self.user_analyzer = UserClearanceAnalyzer(rbac_engine, config.get('user_config'))
        self.system_analyzer = SystemClassificationAnalyzer(config.get('system_config'))
        
        # Initialize audit logger
        self.audit_logger = audit_logger or AuditLogger()
        
        # Initialize Bell-LaPadula security model
        self.security_model = BellLaPadulaSecurityModel()
        
        logger.info("SourceAnalyzer initialized")
    
    async def analyze_comprehensive_source(
        self,
        request_id: str,
        source_ip: Optional[str] = None,
        source_domain: Optional[str] = None,
        source_hostname: Optional[str] = None,
        user_id: Optional[UUID] = None,
        system_id: Optional[str] = None,
        data_lineage: Optional[Dict[str, Any]] = None
    ) -> ComprehensiveSourceAnalysis:
        """Perform comprehensive source analysis."""
        start_time = time.time()
        
        analysis = ComprehensiveSourceAnalysis(request_id=request_id)
        
        try:
            # Perform parallel analysis of different source components
            tasks = []
            
            # Network analysis
            if source_ip or source_domain or source_hostname:
                tasks.append(self._analyze_network_source(source_ip, source_domain, source_hostname))
            
            # User analysis
            if user_id:
                tasks.append(self._analyze_user_source(user_id))
            
            # System analysis
            if system_id:
                tasks.append(self._analyze_system_source(system_id))
            
            # Data lineage analysis
            if data_lineage:
                tasks.append(self._analyze_data_lineage(data_lineage))
            
            # Execute all analyses
            if tasks:
                results = await asyncio.gather(*tasks, return_exceptions=True)
                
                # Process results
                for i, result in enumerate(results):
                    if isinstance(result, Exception):
                        analysis.errors_encountered.append(str(result))
                        logger.error(f"Source analysis task {i} failed: {result}")
                    else:
                        self._integrate_analysis_result(analysis, result)
            
            # Determine final classification
            analysis.final_classification = self._determine_final_classification(analysis)
            
            # Calculate confidence and reliability scores  
            analysis.confidence_score = self._calculate_confidence_score(analysis)
            analysis.reliability_score = self._calculate_reliability_score(analysis)
            
            # Assess compliance
            analysis = self._assess_compliance(analysis)
            
            # Calculate processing time
            analysis.processing_time_ms = (time.time() - start_time) * 1000
            analysis.sources_analyzed = len([a for a in [
                analysis.network_analysis,
                analysis.user_analysis, 
                analysis.system_analysis,
                analysis.lineage_analysis
            ] if a is not None])
            
            # Log analysis
            await self._log_source_analysis(analysis)
            
            logger.debug(f"Comprehensive source analysis complete for {request_id}: {analysis.final_classification}")
            
        except Exception as e:
            logger.error(f"Comprehensive source analysis failed for {request_id}: {e}")
            analysis.errors_encountered.append(str(e))
            analysis.final_classification = ClassificationLevel.UNCLASSIFIED
            analysis.processing_time_ms = (time.time() - start_time) * 1000
        
        return analysis
    
    async def _analyze_network_source(
        self, 
        source_ip: Optional[str], 
        source_domain: Optional[str], 
        source_hostname: Optional[str]
    ) -> NetworkAnalysisResult:
        """Analyze network source."""
        return self.network_analyzer.analyze_network_source(source_ip, source_domain, source_hostname)
    
    async def _analyze_user_source(self, user_id: UUID) -> UserClearanceAnalysis:
        """Analyze user source."""
        return await self.user_analyzer.analyze_user_clearance(user_id)
    
    async def _analyze_system_source(self, system_id: str) -> SystemClassificationAnalysis:
        """Analyze system source."""
        return self.system_analyzer.analyze_system_classification(system_id)
    
    async def _analyze_data_lineage(self, lineage_data: Dict[str, Any]) -> DataLineageAnalysis:
        """Analyze data lineage."""
        analysis = DataLineageAnalysis()
        
        # Extract lineage information
        analysis.source_data_id = lineage_data.get('source_id')
        analysis.parent_sources = lineage_data.get('parent_sources', [])
        analysis.transformation_history = lineage_data.get('transformations', [])
        
        # Determine lineage type
        if lineage_data.get('is_derived'):
            analysis.lineage_type = DataLineageType.DERIVED_DATA
        elif lineage_data.get('is_aggregated'):
            analysis.lineage_type = DataLineageType.AGGREGATED_DATA
        elif lineage_data.get('is_transformed'):
            analysis.lineage_type = DataLineageType.TRANSFORMED_DATA
        elif lineage_data.get('cross_domain_transfer'):
            analysis.lineage_type = DataLineageType.CROSS_DOMAIN_TRANSFER
        
        # Inherit classification from sources
        source_classifications = lineage_data.get('source_classifications', [])
        if source_classifications:
            # Use highest classification (Bell-LaPadula principle)
            analysis.inherited_classification = max(
                [ClassificationLevel(c) for c in source_classifications],
                key=lambda x: x.value
            )
        
        return analysis
    
    def _integrate_analysis_result(
        self, 
        comprehensive_analysis: ComprehensiveSourceAnalysis, 
        component_result: Any
    ):
        """Integrate component analysis result into comprehensive analysis."""
        if isinstance(component_result, NetworkAnalysisResult):
            comprehensive_analysis.network_analysis = component_result
        elif isinstance(component_result, UserClearanceAnalysis):
            comprehensive_analysis.user_analysis = component_result
        elif isinstance(component_result, SystemClassificationAnalysis):
            comprehensive_analysis.system_analysis = component_result
        elif isinstance(component_result, DataLineageAnalysis):
            comprehensive_analysis.lineage_analysis = component_result
    
    def _determine_final_classification(
        self, 
        analysis: ComprehensiveSourceAnalysis
    ) -> ClassificationLevel:
        """Determine final classification based on all sources."""
        classifications = []
        
        # Collect classifications from all sources
        if analysis.network_analysis:
            classifications.append(analysis.network_analysis.classification_level)
        
        if analysis.user_analysis:
            classifications.append(analysis.user_analysis.effective_classification)
        
        if analysis.system_analysis:
            classifications.append(analysis.system_analysis.system_classification)
        
        if analysis.lineage_analysis:
            classifications.append(analysis.lineage_analysis.inherited_classification)
        
        # Apply Bell-LaPadula principle - use highest classification
        if classifications:
            return max(classifications, key=lambda x: x.value)
        else:
            return ClassificationLevel.UNCLASSIFIED
    
    def _calculate_confidence_score(self, analysis: ComprehensiveSourceAnalysis) -> float:
        """Calculate confidence score based on source reliability."""
        scores = []
        weights = []
        
        # Network analysis confidence
        if analysis.network_analysis:
            reliability_score = self._reliability_to_score(analysis.network_analysis.reliability)
            scores.append(reliability_score)
            weights.append(0.3)
        
        # User analysis confidence
        if analysis.user_analysis:
            reliability_score = self._reliability_to_score(analysis.user_analysis.reliability)
            # Factor in risk score
            adjusted_score = reliability_score * (1.0 - analysis.user_analysis.risk_score)
            scores.append(adjusted_score)
            weights.append(0.4)
        
        # System analysis confidence
        if analysis.system_analysis:
            reliability_score = self._reliability_to_score(analysis.system_analysis.reliability)
            scores.append(reliability_score)
            weights.append(0.3)
        
        # Calculate weighted average
        if scores:
            total_weight = sum(weights)
            weighted_sum = sum(score * weight for score, weight in zip(scores, weights))
            return weighted_sum / total_weight
        else:
            return 0.0
    
    def _calculate_reliability_score(self, analysis: ComprehensiveSourceAnalysis) -> float:
        """Calculate overall reliability score."""
        reliabilities = []
        
        if analysis.network_analysis:
            reliabilities.append(analysis.network_analysis.reliability)
        
        if analysis.user_analysis:
            reliabilities.append(analysis.user_analysis.reliability)
        
        if analysis.system_analysis:
            reliabilities.append(analysis.system_analysis.reliability)
        
        if not reliabilities:
            return 0.0
        
        # Calculate average reliability score
        reliability_scores = [self._reliability_to_score(r) for r in reliabilities]
        return sum(reliability_scores) / len(reliability_scores)
    
    def _reliability_to_score(self, reliability: SourceReliability) -> float:
        """Convert reliability enum to numeric score."""
        reliability_scores = {
            SourceReliability.VERIFIED: 1.0,
            SourceReliability.AUTHENTICATED: 0.8,
            SourceReliability.TRUSTED: 0.7,
            SourceReliability.UNVERIFIED: 0.4,
            SourceReliability.SUSPICIOUS: 0.1
        }
        return reliability_scores.get(reliability, 0.0)
    
    def _assess_compliance(self, analysis: ComprehensiveSourceAnalysis) -> ComprehensiveSourceAnalysis:
        """Assess DoD and network compliance."""
        # Check DoD compliance
        analysis.dod_compliance = True
        
        # Check for compliance issues
        if analysis.user_analysis and analysis.user_analysis.risk_score > 0.5:
            analysis.dod_compliance = False
            analysis.security_concerns.append("High user risk score")
        
        if analysis.network_analysis and not analysis.network_analysis.is_valid_source:
            analysis.dod_compliance = False
            analysis.security_concerns.append("Invalid network source")
        
        # Assess network compliance
        for network in NetworkDomain:
            is_compliant = True
            
            # Check if sources are compatible with network
            if analysis.network_analysis and analysis.network_analysis.network_domain:
                if analysis.network_analysis.network_domain != network:
                    network_class = self._get_network_classification(network)
                    source_class = analysis.network_analysis.classification_level
                    if source_class.value > network_class.value:
                        is_compliant = False
            
            analysis.network_compliance[network] = is_compliant
        
        return analysis
    
    def _get_network_classification(self, network: NetworkDomain) -> ClassificationLevel:
        """Get classification level for network domain."""
        network_classifications = {
            NetworkDomain.NIPR: ClassificationLevel.UNCLASSIFIED,
            NetworkDomain.SIPR: ClassificationLevel.SECRET,
            NetworkDomain.JWICS: ClassificationLevel.TOP_SECRET
        }
        return network_classifications.get(network, ClassificationLevel.UNCLASSIFIED)
    
    async def _log_source_analysis(self, analysis: ComprehensiveSourceAnalysis):
        """Log source analysis for audit purposes."""
        await self.audit_logger.log_event({
            'event_type': 'source_analysis_complete',
            'request_id': analysis.request_id,
            'final_classification': analysis.final_classification.value,
            'confidence_score': analysis.confidence_score,
            'reliability_score': analysis.reliability_score,
            'sources_analyzed': analysis.sources_analyzed,
            'processing_time_ms': analysis.processing_time_ms,
            'dod_compliance': analysis.dod_compliance,
            'errors': len(analysis.errors_encountered),
            'timestamp': analysis.analyzed_at.isoformat()
        })


# Example usage and testing
if __name__ == "__main__":
    import asyncio
    
    async def test_source_analyzer():
        """Test the source analyzer."""
        analyzer = SourceAnalyzer()
        
        # Test comprehensive analysis
        analysis = await analyzer.analyze_comprehensive_source(
            request_id="test-001",
            source_ip="192.168.1.100",
            source_domain="sipr.mil",
            user_id=uuid4(),
            system_id="sipr_portal"
        )
        
        print(f"Final Classification: {analysis.final_classification}")
        print(f"Confidence Score: {analysis.confidence_score:.2f}")
        print(f"Reliability Score: {analysis.reliability_score:.2f}")
        print(f"DoD Compliance: {analysis.dod_compliance}")
        print(f"Processing Time: {analysis.processing_time_ms:.2f}ms")
        print(f"Sources Analyzed: {analysis.sources_analyzed}")
    
    # Run test
    asyncio.run(test_source_analyzer())