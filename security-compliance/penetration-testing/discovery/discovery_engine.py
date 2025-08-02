"""
Vulnerability Discovery Engine
==============================

Advanced vulnerability discovery orchestration engine that integrates with existing
vulnerability assessment frameworks and provides unified vulnerability discovery,
processing, and enrichment capabilities.

This engine coordinates multiple discovery sources and enriches findings with
contextual information for enhanced risk assessment and prioritization.
"""

import asyncio
import json
import logging
import sqlite3
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from pathlib import Path
from uuid import uuid4
from enum import Enum

# Import existing vulnerability assessment capabilities
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '../../auth/security_testing_framework'))
sys.path.append(os.path.join(os.path.dirname(__file__), '../../security-testing'))

try:
    from vulnerability_assessor import VulnerabilityAssessor, Vulnerability, Asset, SeverityLevel, VulnerabilityStatus
except ImportError:
    # Fallback if direct import fails
    logging.warning("Could not import VulnerabilityAssessor - using mock implementation")
    
    class SeverityLevel(Enum):
        CRITICAL = "critical"
        HIGH = "high"
        MEDIUM = "medium"
        LOW = "low"
        INFO = "info"
    
    class VulnerabilityStatus(Enum):
        NEW = "new"
        CONFIRMED = "confirmed"
        IN_PROGRESS = "in_progress"
        REMEDIATED = "remediated"
        ACCEPTED_RISK = "accepted_risk"
        FALSE_POSITIVE = "false_positive"

logger = logging.getLogger(__name__)

class DiscoverySource(Enum):
    """Types of vulnerability discovery sources"""
    VULNERABILITY_SCANNER = "vulnerability_scanner"
    PENETRATION_TEST = "penetration_test"
    THREAT_INTELLIGENCE = "threat_intelligence"
    CODE_ANALYSIS = "code_analysis"
    CONFIGURATION_AUDIT = "configuration_audit"
    MANUAL_ASSESSMENT = "manual_assessment"
    COMPLIANCE_SCAN = "compliance_scan"
    THREAT_FEED = "threat_feed"

@dataclass
class DiscoveryConfig:
    """Configuration for vulnerability discovery engine"""
    enable_real_time_feeds: bool = True
    enable_threat_intelligence: bool = True
    enable_custom_rules: bool = True
    classification_aware: bool = True
    auto_enrichment: bool = True
    correlation_threshold: float = 0.8
    deduplication_enabled: bool = True
    max_concurrent_scans: int = 10
    feed_refresh_interval: int = 3600  # seconds
    database_path: str = "vulnerability_discovery.db"

@dataclass
class DiscoveryResult:
    """Result from vulnerability discovery process"""
    id: str
    source: DiscoverySource
    timestamp: datetime
    vulnerabilities_found: int
    new_vulnerabilities: int
    updated_vulnerabilities: int
    false_positives: int
    processing_time: float
    source_metadata: Dict[str, Any]
    errors: List[str] = field(default_factory=list)

@dataclass
class EnrichedVulnerability:
    """Enhanced vulnerability with discovery context"""
    base_vulnerability: Dict[str, Any]  # Base vulnerability from assessor
    discovery_source: DiscoverySource
    discovery_timestamp: datetime
    confidence_score: float
    threat_intelligence: Dict[str, Any] = field(default_factory=dict)
    exploit_information: Dict[str, Any] = field(default_factory=dict)
    business_context: Dict[str, Any] = field(default_factory=dict)
    correlation_ids: List[str] = field(default_factory=list)
    enrichment_metadata: Dict[str, Any] = field(default_factory=dict)

class VulnerabilityDiscoveryEngine:
    """
    Advanced vulnerability discovery orchestration engine
    
    Coordinates multiple vulnerability discovery sources, processes findings,
    and enriches them with contextual information for enhanced risk assessment.
    """
    
    def __init__(self, config: Optional[DiscoveryConfig] = None):
        self.config = config or DiscoveryConfig()
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        
        # Initialize database
        self.db_path = Path(self.config.database_path)
        self._initialize_database()
        
        # Initialize vulnerability assessor from existing framework
        try:
            self.vulnerability_assessor = VulnerabilityAssessor(
                db_path=str(self.db_path.parent / "vulnerability_assessment.db")
            )
        except Exception as e:
            self.logger.warning(f"Could not initialize VulnerabilityAssessor: {e}")
            self.vulnerability_assessor = None
        
        # Discovery source processors
        self.source_processors = {}
        self.active_scans = set()
        self.discovery_history = []
        
        # Threading and async
        self.semaphore = asyncio.Semaphore(self.config.max_concurrent_scans)
        
    def _initialize_database(self):
        """Initialize discovery tracking database"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS discovery_sessions (
                    id TEXT PRIMARY KEY,
                    source TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    completed_at TEXT,
                    status TEXT NOT NULL,
                    vulnerabilities_found INTEGER DEFAULT 0,
                    new_vulnerabilities INTEGER DEFAULT 0,
                    updated_vulnerabilities INTEGER DEFAULT 0,
                    false_positives INTEGER DEFAULT 0,
                    processing_time REAL,
                    source_metadata TEXT,
                    errors TEXT,
                    created_at TEXT NOT NULL
                )
            """)
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS enriched_vulnerabilities (
                    id TEXT PRIMARY KEY,
                    base_vulnerability_id TEXT NOT NULL,
                    discovery_source TEXT NOT NULL,
                    discovery_timestamp TEXT NOT NULL,
                    confidence_score REAL NOT NULL,
                    threat_intelligence TEXT,
                    exploit_information TEXT,
                    business_context TEXT,
                    correlation_ids TEXT,
                    enrichment_metadata TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
            """)
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS vulnerability_correlations (
                    id TEXT PRIMARY KEY,
                    primary_vuln_id TEXT NOT NULL,
                    correlated_vuln_id TEXT NOT NULL,
                    correlation_score REAL NOT NULL,
                    correlation_type TEXT NOT NULL,
                    correlation_metadata TEXT,
                    created_at TEXT NOT NULL
                )
            """)
            
            # Create indexes
            conn.execute("CREATE INDEX IF NOT EXISTS idx_discovery_source ON discovery_sessions(source)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_discovery_status ON discovery_sessions(status)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_enriched_source ON enriched_vulnerabilities(discovery_source)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_correlations_primary ON vulnerability_correlations(primary_vuln_id)")
    
    async def register_discovery_source(self, source: DiscoverySource, processor_class):
        """Register a discovery source processor"""
        try:
            processor = processor_class(self.config)
            self.source_processors[source] = processor
            self.logger.info(f"Registered discovery source: {source.value}")
        except Exception as e:
            self.logger.error(f"Failed to register discovery source {source.value}: {e}")
            raise
    
    async def start_discovery_session(self, 
                                    source: DiscoverySource, 
                                    targets: List[str],
                                    scan_config: Optional[Dict[str, Any]] = None) -> str:
        """Start a new vulnerability discovery session"""
        
        session_id = str(uuid4())
        start_time = datetime.now(timezone.utc)
        
        # Record session start
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT INTO discovery_sessions 
                (id, source, started_at, status, source_metadata, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                session_id,
                source.value,
                start_time.isoformat(),
                "running",
                json.dumps({"targets": targets, "config": scan_config or {}}),
                start_time.isoformat()
            ))
        
        self.active_scans.add(session_id)
        
        # Start discovery process
        asyncio.create_task(self._execute_discovery_session(
            session_id, source, targets, scan_config
        ))
        
        self.logger.info(f"Started discovery session {session_id} for source {source.value}")
        return session_id
    
    async def _execute_discovery_session(self,
                                       session_id: str,
                                       source: DiscoverySource,
                                       targets: List[str],
                                       scan_config: Optional[Dict[str, Any]]):
        """Execute a vulnerability discovery session"""
        
        async with self.semaphore:
            start_time = datetime.now(timezone.utc)
            errors = []
            vulnerabilities_found = 0
            new_vulnerabilities = 0
            updated_vulnerabilities = 0
            false_positives = 0
            
            try:
                # Get processor for this source
                if source not in self.source_processors:
                    raise ValueError(f"No processor registered for source: {source.value}")
                
                processor = self.source_processors[source]
                
                # Execute discovery
                findings = await processor.discover_vulnerabilities(targets, scan_config)
                
                # Process and enrich findings
                for finding in findings:
                    try:
                        enriched_vuln = await self._process_and_enrich_finding(
                            finding, source, session_id
                        )
                        
                        if enriched_vuln:
                            vulnerabilities_found += 1
                            
                            # Check if this is a new vulnerability
                            if await self._is_new_vulnerability(enriched_vuln):
                                new_vulnerabilities += 1
                            else:
                                updated_vulnerabilities += 1
                        
                    except Exception as e:
                        errors.append(f"Failed to process finding: {e}")
                        self.logger.error(f"Failed to process finding in session {session_id}: {e}")
                
            except Exception as e:
                errors.append(f"Discovery session failed: {e}")
                self.logger.error(f"Discovery session {session_id} failed: {e}")
            
            finally:
                # Update session completion
                end_time = datetime.now(timezone.utc)
                processing_time = (end_time - start_time).total_seconds()
                
                with sqlite3.connect(self.db_path) as conn:
                    conn.execute("""
                        UPDATE discovery_sessions 
                        SET completed_at = ?, status = ?, vulnerabilities_found = ?,
                            new_vulnerabilities = ?, updated_vulnerabilities = ?,
                            false_positives = ?, processing_time = ?, errors = ?
                        WHERE id = ?
                    """, (
                        end_time.isoformat(),
                        "completed" if not errors else "failed",
                        vulnerabilities_found,
                        new_vulnerabilities,
                        updated_vulnerabilities,
                        false_positives,
                        processing_time,
                        json.dumps(errors) if errors else None,
                        session_id
                    ))
                
                self.active_scans.discard(session_id)
                
                # Create discovery result
                result = DiscoveryResult(
                    id=session_id,
                    source=source,
                    timestamp=end_time,
                    vulnerabilities_found=vulnerabilities_found,
                    new_vulnerabilities=new_vulnerabilities,
                    updated_vulnerabilities=updated_vulnerabilities,
                    false_positives=false_positives,
                    processing_time=processing_time,
                    source_metadata={"targets": targets, "config": scan_config or {}},
                    errors=errors
                )
                
                self.discovery_history.append(result)
                
                self.logger.info(f"Completed discovery session {session_id}: "
                               f"{vulnerabilities_found} vulnerabilities found "
                               f"({new_vulnerabilities} new, {updated_vulnerabilities} updated)")
    
    async def _process_and_enrich_finding(self,
                                        finding: Dict[str, Any],
                                        source: DiscoverySource,
                                        session_id: str) -> Optional[EnrichedVulnerability]:
        """Process and enrich a vulnerability finding"""
        
        try:
            # Convert finding to standardized vulnerability format using existing assessor
            if self.vulnerability_assessor:
                # Create asset info if available
                asset_info = None
                if 'asset' in finding:
                    asset_data = finding['asset']
                    # Create Asset object (simplified - would need full implementation)
                    # This would typically extract asset information from the finding
                
                # Use existing vulnerability assessor to process the finding
                base_vulnerability = self.vulnerability_assessor.assess_vulnerability(finding, asset_info)
                base_vuln_dict = {
                    'id': base_vulnerability.id,
                    'cve_id': base_vulnerability.cve_id,
                    'title': base_vulnerability.title,
                    'description': base_vulnerability.description,
                    'severity': base_vulnerability.severity.value,
                    'cvss_score': base_vulnerability.cvss_score,
                    'affected_assets': base_vulnerability.affected_assets,
                    'remediation_priority': base_vulnerability.remediation_priority
                }
            else:
                # Fallback processing if assessor not available
                base_vuln_dict = {
                    'id': finding.get('id', str(uuid4())),
                    'title': finding.get('title', 'Unknown Vulnerability'),
                    'description': finding.get('description', ''),
                    'severity': finding.get('severity', 'medium'),
                    'cvss_score': finding.get('cvss_score', 0.0)
                }
            
            # Create enriched vulnerability
            enriched_vuln = EnrichedVulnerability(
                base_vulnerability=base_vuln_dict,
                discovery_source=source,
                discovery_timestamp=datetime.now(timezone.utc),
                confidence_score=self._calculate_confidence_score(finding, source)
            )
            
            # Apply enrichment if enabled
            if self.config.auto_enrichment:
                await self._enrich_vulnerability(enriched_vuln, finding)
            
            # Apply correlation if enabled
            if self.config.deduplication_enabled:
                await self._correlate_vulnerability(enriched_vuln)
            
            # Save enriched vulnerability
            await self._save_enriched_vulnerability(enriched_vuln)
            
            return enriched_vuln
            
        except Exception as e:
            self.logger.error(f"Failed to process finding: {e}")
            return None
    
    async def _enrich_vulnerability(self, vuln: EnrichedVulnerability, finding: Dict[str, Any]):
        """Enrich vulnerability with additional context"""
        
        # Threat intelligence enrichment
        if self.config.enable_threat_intelligence:
            vuln.threat_intelligence = await self._get_threat_intelligence(vuln)
        
        # Exploit information enrichment
        vuln.exploit_information = await self._get_exploit_information(vuln)
        
        # Business context enrichment
        if self.config.classification_aware:
            vuln.business_context = await self._get_business_context(vuln, finding)
        
        # Set enrichment metadata
        vuln.enrichment_metadata = {
            'enriched_at': datetime.now(timezone.utc).isoformat(),
            'enrichment_sources': ['threat_intelligence', 'exploit_db', 'business_context'],
            'enrichment_version': '1.0'
        }
    
    async def _get_threat_intelligence(self, vuln: EnrichedVulnerability) -> Dict[str, Any]:
        """Get threat intelligence for vulnerability"""
        # Placeholder implementation - would integrate with threat intel feeds
        return {
            'threats_detected': False,
            'exploitation_likelihood': 'unknown',
            'threat_actors': [],
            'campaigns': []
        }
    
    async def _get_exploit_information(self, vuln: EnrichedVulnerability) -> Dict[str, Any]:
        """Get exploit information for vulnerability"""
        # Placeholder implementation - would integrate with exploit databases
        return {
            'public_exploits': False,
            'exploit_complexity': 'unknown',
            'exploit_maturity': 'unknown',
            'weaponized': False
        }
    
    async def _get_business_context(self, vuln: EnrichedVulnerability, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Get business context for vulnerability"""
        # Placeholder implementation - would integrate with asset management and classification systems
        return {
            'asset_criticality': finding.get('asset', {}).get('criticality', 'unknown'),
            'classification_level': finding.get('asset', {}).get('classification', 'NIPR'),
            'business_impact': 'unknown',
            'compliance_impact': []
        }
    
    def _calculate_confidence_score(self, finding: Dict[str, Any], source: DiscoverySource) -> float:
        """Calculate confidence score for vulnerability finding"""
        
        base_confidence = {
            DiscoverySource.VULNERABILITY_SCANNER: 0.8,
            DiscoverySource.PENETRATION_TEST: 0.9,
            DiscoverySource.THREAT_INTELLIGENCE: 0.7,
            DiscoverySource.CODE_ANALYSIS: 0.85,
            DiscoverySource.CONFIGURATION_AUDIT: 0.9,
            DiscoverySource.MANUAL_ASSESSMENT: 0.95,
            DiscoverySource.COMPLIANCE_SCAN: 0.8,
            DiscoverySource.THREAT_FEED: 0.6
        }.get(source, 0.5)
        
        # Adjust based on finding characteristics
        adjustments = 0.0
        
        # Higher confidence for CVE-based findings
        if finding.get('cve_id'):
            adjustments += 0.1
        
        # Higher confidence for confirmed findings
        if finding.get('confirmed', False):
            adjustments += 0.15
        
        # Lower confidence for automated findings without validation
        if finding.get('automated', True) and not finding.get('validated', False):
            adjustments -= 0.1
        
        return max(0.0, min(1.0, base_confidence + adjustments))
    
    async def _correlate_vulnerability(self, vuln: EnrichedVulnerability):
        """Correlate vulnerability with existing vulnerabilities"""
        
        # Placeholder implementation - would implement sophisticated correlation logic
        # This would check for similar vulnerabilities, related CVEs, etc.
        correlations = []
        
        # Save correlations if found
        if correlations:
            with sqlite3.connect(self.db_path) as conn:
                for corr_id, score, corr_type in correlations:
                    conn.execute("""
                        INSERT INTO vulnerability_correlations
                        (id, primary_vuln_id, correlated_vuln_id, correlation_score, 
                         correlation_type, created_at)
                        VALUES (?, ?, ?, ?, ?, ?)
                    """, (
                        str(uuid4()),
                        vuln.base_vulnerability['id'],
                        corr_id,
                        score,
                        corr_type,
                        datetime.now(timezone.utc).isoformat()
                    ))
            
            vuln.correlation_ids = [corr_id for corr_id, _, _ in correlations]
    
    async def _is_new_vulnerability(self, vuln: EnrichedVulnerability) -> bool:
        """Check if this is a new vulnerability"""
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("""
                SELECT COUNT(*) FROM enriched_vulnerabilities 
                WHERE base_vulnerability_id = ?
            """, (vuln.base_vulnerability['id'],))
            
            count = cursor.fetchone()[0]
            return count == 0
    
    async def _save_enriched_vulnerability(self, vuln: EnrichedVulnerability):
        """Save enriched vulnerability to database"""
        
        with sqlite3.connect(self.db_path) as conn:
            now = datetime.now(timezone.utc).isoformat()
            
            conn.execute("""
                INSERT OR REPLACE INTO enriched_vulnerabilities (
                    id, base_vulnerability_id, discovery_source, discovery_timestamp,
                    confidence_score, threat_intelligence, exploit_information,
                    business_context, correlation_ids, enrichment_metadata,
                    created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                str(uuid4()),
                vuln.base_vulnerability['id'],
                vuln.discovery_source.value,
                vuln.discovery_timestamp.isoformat(),
                vuln.confidence_score,
                json.dumps(vuln.threat_intelligence),
                json.dumps(vuln.exploit_information),
                json.dumps(vuln.business_context),
                json.dumps(vuln.correlation_ids),
                json.dumps(vuln.enrichment_metadata),
                now,
                now
            ))
    
    async def get_discovery_status(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Get status of a discovery session"""
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("""
                SELECT * FROM discovery_sessions WHERE id = ?
            """, (session_id,))
            
            row = cursor.fetchone()
            if row:
                return {
                    'id': row[0],
                    'source': row[1],
                    'started_at': row[2],
                    'completed_at': row[3],
                    'status': row[4],
                    'vulnerabilities_found': row[5],
                    'new_vulnerabilities': row[6],
                    'updated_vulnerabilities': row[7],
                    'false_positives': row[8],
                    'processing_time': row[9],
                    'errors': json.loads(row[11]) if row[11] else []
                }
        
        return None
    
    async def get_active_scans(self) -> List[str]:
        """Get list of active scan session IDs"""
        return list(self.active_scans)
    
    async def cancel_discovery_session(self, session_id: str) -> bool:
        """Cancel an active discovery session"""
        
        if session_id in self.active_scans:
            # Mark as cancelled in database
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    UPDATE discovery_sessions 
                    SET status = 'cancelled', completed_at = ?
                    WHERE id = ? AND status = 'running'
                """, (datetime.now(timezone.utc).isoformat(), session_id))
            
            self.active_scans.discard(session_id)
            return True
        
        return False
    
    async def get_discovery_metrics(self, days: int = 30) -> Dict[str, Any]:
        """Get discovery metrics for the specified time period"""
        
        since_date = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        
        with sqlite3.connect(self.db_path) as conn:
            # Get session statistics
            cursor = conn.execute("""
                SELECT source, COUNT(*) as sessions, 
                       SUM(vulnerabilities_found) as total_vulns,
                       SUM(new_vulnerabilities) as new_vulns,
                       AVG(processing_time) as avg_time
                FROM discovery_sessions 
                WHERE created_at > ?
                GROUP BY source
            """, (since_date,))
            
            source_stats = {}
            for row in cursor.fetchall():
                source_stats[row[0]] = {
                    'sessions': row[1],
                    'total_vulnerabilities': row[2] or 0,
                    'new_vulnerabilities': row[3] or 0,
                    'average_processing_time': row[4] or 0
                }
            
            # Get overall statistics
            cursor = conn.execute("""
                SELECT COUNT(*) as total_sessions,
                       SUM(vulnerabilities_found) as total_vulns,
                       SUM(new_vulnerabilities) as new_vulns,
                       AVG(processing_time) as avg_time
                FROM discovery_sessions 
                WHERE created_at > ?
            """, (since_date,))
            
            overall_row = cursor.fetchone()
            overall_stats = {
                'total_sessions': overall_row[0] or 0,
                'total_vulnerabilities': overall_row[1] or 0,
                'new_vulnerabilities': overall_row[2] or 0,
                'average_processing_time': overall_row[3] or 0
            }
            
            return {
                'period_days': days,
                'overall_statistics': overall_stats,
                'source_statistics': source_stats,
                'active_scans': len(self.active_scans)
            }
    
    async def shutdown(self):
        """Shutdown the discovery engine gracefully"""
        
        self.logger.info("Shutting down discovery engine...")
        
        # Cancel all active scans
        active_scan_ids = list(self.active_scans)
        for session_id in active_scan_ids:
            await self.cancel_discovery_session(session_id)
        
        # Wait for any remaining operations
        await asyncio.sleep(1)
        
        self.logger.info("Discovery engine shutdown complete")