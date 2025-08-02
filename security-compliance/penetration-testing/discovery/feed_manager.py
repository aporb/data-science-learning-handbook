"""
Vulnerability Feed Manager
==========================

Manages real-time vulnerability intelligence feeds from multiple sources including
NIST NVD, vendor advisories, threat intelligence feeds, and security research.

Supported Feed Sources:
- NIST National Vulnerability Database (NVD)
- CISA Known Exploited Vulnerabilities (KEV)
- Vendor security advisories (Microsoft, Red Hat, etc.)
- Threat intelligence feeds
- Security research publications
- Zero-day vulnerability reports

Features:
- Real-time feed processing and ingestion
- Vulnerability correlation and enrichment
- Automated threat assessment
- Custom feed source integration
- Historical vulnerability trend analysis
"""

import asyncio
import aiohttp
import json
import logging
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, AsyncGenerator, Set
from dataclasses import dataclass, field
from enum import Enum
import xml.etree.ElementTree as ET
import sqlite3
from pathlib import Path
import hashlib
import re

logger = logging.getLogger(__name__)

class FeedType(Enum):
    """Types of vulnerability feeds"""
    NIST_NVD = "nist_nvd"
    CISA_KEV = "cisa_kev"
    VENDOR_ADVISORY = "vendor_advisory"
    THREAT_INTELLIGENCE = "threat_intelligence"
    EXPLOIT_DB = "exploit_db"
    SECURITY_RESEARCH = "security_research"
    CUSTOM = "custom"

class VulnerabilityStatus(Enum):
    """Status of vulnerabilities in feeds"""
    NEW = "new"
    UPDATED = "updated"
    ACTIVE = "active"
    PATCHED = "patched"
    EXPLOITED = "exploited"
    DEPRECATED = "deprecated"

@dataclass
class FeedSource:
    """Configuration for a vulnerability feed source"""
    name: str
    feed_type: FeedType
    url: str
    update_interval: int  # seconds
    api_key: Optional[str] = None
    headers: Dict[str, str] = field(default_factory=dict)
    params: Dict[str, str] = field(default_factory=dict)
    enabled: bool = True
    parser_config: Dict[str, Any] = field(default_factory=dict)
    rate_limit: int = 60  # requests per minute
    timeout: int = 300
    verify_ssl: bool = True

@dataclass
class FeedVulnerability:
    """Vulnerability information from feed sources"""
    feed_id: str
    source_name: str
    feed_type: FeedType
    cve_id: str
    title: str
    description: str
    severity: str
    cvss_score: float
    cvss_vector: Optional[str]
    published_date: datetime
    modified_date: datetime
    affected_products: List[str]
    references: List[str]
    exploit_available: bool
    exploitation_likelihood: str
    threat_actors: List[str] = field(default_factory=list)
    attack_patterns: List[str] = field(default_factory=list)
    mitigation_strategies: List[str] = field(default_factory=list)
    status: VulnerabilityStatus = VulnerabilityStatus.ACTIVE
    raw_data: Dict[str, Any] = field(default_factory=dict)

class VulnerabilityFeedManager:
    """
    Manages vulnerability intelligence feeds from multiple sources
    """
    
    def __init__(self, db_path: str = "vulnerability_feeds.db"):
        self.db_path = Path(db_path)
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        
        # Initialize database
        self._initialize_database()
        
        # Feed sources and processors
        self.feed_sources: Dict[str, FeedSource] = {}
        self.feed_processors = {
            FeedType.NIST_NVD: self._process_nist_nvd_feed,
            FeedType.CISA_KEV: self._process_cisa_kev_feed,
            FeedType.VENDOR_ADVISORY: self._process_vendor_advisory_feed,
            FeedType.THREAT_INTELLIGENCE: self._process_threat_intel_feed,
            FeedType.EXPLOIT_DB: self._process_exploit_db_feed,
        }
        
        # Rate limiting and session management
        self.session = None
        self.rate_limiters = {}
        self.last_updates = {}
        
        # Background task management
        self.running = False
        self.update_tasks = {}
    
    def _initialize_database(self):
        """Initialize vulnerability feeds database"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS feed_vulnerabilities (
                    feed_id TEXT PRIMARY KEY,
                    source_name TEXT NOT NULL,
                    feed_type TEXT NOT NULL,
                    cve_id TEXT NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT,
                    severity TEXT,
                    cvss_score REAL,
                    cvss_vector TEXT,
                    published_date TEXT,
                    modified_date TEXT,
                    affected_products TEXT,  -- JSON array
                    references TEXT,  -- JSON array
                    exploit_available BOOLEAN,
                    exploitation_likelihood TEXT,
                    threat_actors TEXT,  -- JSON array
                    attack_patterns TEXT,  -- JSON array
                    mitigation_strategies TEXT,  -- JSON array
                    status TEXT,
                    raw_data TEXT,  -- JSON object
                    created_at TEXT,
                    updated_at TEXT
                )
            """)
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS feed_updates (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    source_name TEXT NOT NULL,
                    feed_type TEXT NOT NULL,
                    update_timestamp TEXT NOT NULL,
                    vulnerabilities_processed INTEGER,
                    new_vulnerabilities INTEGER,
                    updated_vulnerabilities INTEGER,
                    errors TEXT,  -- JSON array
                    processing_time REAL,
                    status TEXT
                )
            """)
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS feed_sources (
                    name TEXT PRIMARY KEY,
                    feed_type TEXT NOT NULL,
                    url TEXT NOT NULL,
                    update_interval INTEGER,
                    enabled BOOLEAN,
                    last_update TEXT,
                    config TEXT,  -- JSON object
                    created_at TEXT,
                    updated_at TEXT
                )
            """)
            
            # Create indexes
            conn.execute("CREATE INDEX IF NOT EXISTS idx_feed_cve ON feed_vulnerabilities(cve_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_feed_severity ON feed_vulnerabilities(severity)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_feed_published ON feed_vulnerabilities(published_date)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_feed_source ON feed_vulnerabilities(source_name)")
    
    async def start(self):
        """Start the vulnerability feed manager"""
        if self.running:
            return
        
        self.running = True
        
        # Initialize HTTP session
        connector = aiohttp.TCPConnector(limit=100, limit_per_host=30)
        timeout = aiohttp.ClientTimeout(total=300)
        self.session = aiohttp.ClientSession(connector=connector, timeout=timeout)
        
        # Load feed sources from database
        await self._load_feed_sources()
        
        # Start background update tasks
        for source_name, source in self.feed_sources.items():
            if source.enabled:
                self.update_tasks[source_name] = asyncio.create_task(
                    self._feed_update_loop(source)
                )
        
        self.logger.info(f"Started vulnerability feed manager with {len(self.feed_sources)} sources")
    
    async def stop(self):
        """Stop the vulnerability feed manager"""
        if not self.running:
            return
        
        self.running = False
        
        # Cancel update tasks
        for task in self.update_tasks.values():
            task.cancel()
        
        # Wait for tasks to complete
        if self.update_tasks:
            await asyncio.gather(*self.update_tasks.values(), return_exceptions=True)
        
        # Close HTTP session
        if self.session:
            await self.session.close()
        
        self.logger.info("Stopped vulnerability feed manager")
    
    def register_feed_source(self, source: FeedSource):
        """Register a new vulnerability feed source"""
        self.feed_sources[source.name] = source
        
        # Save to database
        with sqlite3.connect(self.db_path) as conn:
            now = datetime.now(timezone.utc).isoformat()
            conn.execute("""
                INSERT OR REPLACE INTO feed_sources 
                (name, feed_type, url, update_interval, enabled, config, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                source.name,
                source.feed_type.value,
                source.url,
                source.update_interval,
                source.enabled,
                json.dumps({
                    'headers': source.headers,
                    'params': source.params,
                    'parser_config': source.parser_config,
                    'rate_limit': source.rate_limit,
                    'timeout': source.timeout,
                    'verify_ssl': source.verify_ssl
                }),
                now,
                now
            ))
        
        # Start update task if running and enabled
        if self.running and source.enabled:
            self.update_tasks[source.name] = asyncio.create_task(
                self._feed_update_loop(source)
            )
        
        self.logger.info(f"Registered feed source: {source.name} ({source.feed_type.value})")
    
    async def _load_feed_sources(self):
        """Load feed sources from database"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("SELECT * FROM feed_sources")
            
            for row in cursor.fetchall():
                name, feed_type, url, update_interval, enabled, last_update, config_json, _, _ = row
                
                config = json.loads(config_json) if config_json else {}
                
                source = FeedSource(
                    name=name,
                    feed_type=FeedType(feed_type),
                    url=url,
                    update_interval=update_interval,
                    enabled=bool(enabled),
                    headers=config.get('headers', {}),
                    params=config.get('params', {}),
                    parser_config=config.get('parser_config', {}),
                    rate_limit=config.get('rate_limit', 60),
                    timeout=config.get('timeout', 300),
                    verify_ssl=config.get('verify_ssl', True)
                )
                
                self.feed_sources[name] = source
                if last_update:
                    self.last_updates[name] = datetime.fromisoformat(last_update)
    
    async def _feed_update_loop(self, source: FeedSource):
        """Background loop for updating a feed source"""
        while self.running:
            try:
                await self._update_feed_source(source)
                await asyncio.sleep(source.update_interval)
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Error in feed update loop for {source.name}: {e}")
                await asyncio.sleep(min(source.update_interval, 300))  # Wait at least 5 minutes on error
    
    async def _update_feed_source(self, source: FeedSource):
        """Update vulnerabilities from a feed source"""
        start_time = datetime.now(timezone.utc)
        errors = []
        vulnerabilities_processed = 0
        new_vulnerabilities = 0
        updated_vulnerabilities = 0
        
        try:
            self.logger.info(f"Updating feed source: {source.name}")
            
            # Check if we have a processor for this feed type
            if source.feed_type not in self.feed_processors:
                raise ValueError(f"No processor available for feed type: {source.feed_type.value}")
            
            processor = self.feed_processors[source.feed_type]
            
            # Process the feed
            async for vulnerability in processor(source):
                try:
                    # Check if vulnerability already exists
                    is_new = await self._save_feed_vulnerability(vulnerability)
                    
                    vulnerabilities_processed += 1
                    if is_new:
                        new_vulnerabilities += 1
                    else:
                        updated_vulnerabilities += 1
                        
                except Exception as e:
                    errors.append(f"Failed to save vulnerability {vulnerability.cve_id}: {e}")
            
            # Update last update timestamp
            self.last_updates[source.name] = start_time
            
            # Record update statistics
            processing_time = (datetime.now(timezone.utc) - start_time).total_seconds()
            
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    INSERT INTO feed_updates 
                    (source_name, feed_type, update_timestamp, vulnerabilities_processed,
                     new_vulnerabilities, updated_vulnerabilities, errors, processing_time, status)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    source.name,
                    source.feed_type.value,
                    start_time.isoformat(),
                    vulnerabilities_processed,
                    new_vulnerabilities,
                    updated_vulnerabilities,
                    json.dumps(errors) if errors else None,
                    processing_time,
                    "completed" if not errors else "completed_with_errors"
                ))
                
                # Update feed source last update
                conn.execute("""
                    UPDATE feed_sources SET last_update = ?, updated_at = ?
                    WHERE name = ?
                """, (start_time.isoformat(), start_time.isoformat(), source.name))
            
            self.logger.info(f"Completed feed update for {source.name}: "
                           f"{vulnerabilities_processed} processed "
                           f"({new_vulnerabilities} new, {updated_vulnerabilities} updated)")
            
        except Exception as e:
            errors.append(f"Feed update failed: {e}")
            self.logger.error(f"Failed to update feed source {source.name}: {e}")
            
            # Record failed update
            processing_time = (datetime.now(timezone.utc) - start_time).total_seconds()
            
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    INSERT INTO feed_updates 
                    (source_name, feed_type, update_timestamp, vulnerabilities_processed,
                     new_vulnerabilities, updated_vulnerabilities, errors, processing_time, status)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    source.name,
                    source.feed_type.value,
                    start_time.isoformat(),
                    vulnerabilities_processed,
                    new_vulnerabilities,
                    updated_vulnerabilities,
                    json.dumps(errors),
                    processing_time,
                    "failed"
                ))
    
    async def _process_nist_nvd_feed(self, source: FeedSource) -> AsyncGenerator[FeedVulnerability, None]:
        """Process NIST NVD vulnerability feed"""
        
        # NIST NVD API endpoint
        base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        
        # Get last update time to fetch only new/modified vulnerabilities
        last_update = self.last_updates.get(source.name)
        params = source.params.copy()
        
        if last_update:
            params['lastModStartDate'] = last_update.isoformat()
        
        try:
            async with self.session.get(base_url, params=params, headers=source.headers) as response:
                response.raise_for_status()
                data = await response.json()
                
                vulnerabilities = data.get('vulnerabilities', [])
                
                for vuln_data in vulnerabilities:
                    cve_data = vuln_data.get('cve', {})
                    cve_id = cve_data.get('id', '')
                    
                    if not cve_id:
                        continue
                    
                    # Extract basic information
                    descriptions = cve_data.get('descriptions', [])
                    description = ""
                    for desc in descriptions:
                        if desc.get('lang') == 'en':
                            description = desc.get('value', '')
                            break
                    
                    # Extract CVSS information
                    cvss_score = 0.0
                    cvss_vector = None
                    severity = "unknown"
                    
                    metrics = cve_data.get('metrics', {})
                    if 'cvssMetricV31' in metrics:
                        cvss_data = metrics['cvssMetricV31'][0]['cvssData']
                        cvss_score = cvss_data.get('baseScore', 0.0)
                        cvss_vector = cvss_data.get('vectorString')
                        severity = cvss_data.get('baseSeverity', 'unknown').lower()
                    elif 'cvssMetricV30' in metrics:
                        cvss_data = metrics['cvssMetricV30'][0]['cvssData']
                        cvss_score = cvss_data.get('baseScore', 0.0)
                        cvss_vector = cvss_data.get('vectorString')
                        severity = cvss_data.get('baseSeverity', 'unknown').lower()
                    
                    # Extract dates
                    published_date = datetime.fromisoformat(cve_data.get('published', '').replace('Z', '+00:00'))
                    modified_date = datetime.fromisoformat(cve_data.get('lastModified', '').replace('Z', '+00:00'))
                    
                    # Extract references
                    references = []
                    ref_data = cve_data.get('references', [])
                    for ref in ref_data:
                        references.append(ref.get('url', ''))
                    
                    # Extract affected products
                    affected_products = []
                    configurations = cve_data.get('configurations', [])
                    for config in configurations:
                        nodes = config.get('nodes', [])
                        for node in nodes:
                            cpe_matches = node.get('cpeMatch', [])
                            for cpe_match in cpe_matches:
                                if cpe_match.get('vulnerable', False):
                                    cpe_name = cpe_match.get('criteria', '')
                                    if cpe_name:
                                        affected_products.append(cpe_name)
                    
                    # Generate feed ID
                    feed_id = f"nvd_{cve_id}"
                    
                    vulnerability = FeedVulnerability(
                        feed_id=feed_id,
                        source_name=source.name,
                        feed_type=source.feed_type,
                        cve_id=cve_id,
                        title=f"NIST NVD: {cve_id}",
                        description=description,
                        severity=severity,
                        cvss_score=cvss_score,
                        cvss_vector=cvss_vector,
                        published_date=published_date,
                        modified_date=modified_date,
                        affected_products=affected_products,
                        references=references,
                        exploit_available=False,  # Would need additional analysis
                        exploitation_likelihood="unknown",
                        raw_data=cve_data
                    )
                    
                    yield vulnerability
                    
        except Exception as e:
            self.logger.error(f"Error processing NIST NVD feed: {e}")
            raise
    
    async def _process_cisa_kev_feed(self, source: FeedSource) -> AsyncGenerator[FeedVulnerability, None]:
        """Process CISA Known Exploited Vulnerabilities feed"""
        
        try:
            async with self.session.get(source.url, headers=source.headers) as response:
                response.raise_for_status()
                data = await response.json()
                
                vulnerabilities = data.get('vulnerabilities', [])
                
                for vuln_data in vulnerabilities:
                    cve_id = vuln_data.get('cveID', '')
                    
                    if not cve_id:
                        continue
                    
                    # Parse dates
                    date_added = datetime.fromisoformat(vuln_data.get('dateAdded', ''))
                    due_date = datetime.fromisoformat(vuln_data.get('dueDate', ''))
                    
                    feed_id = f"cisa_kev_{cve_id}"
                    
                    vulnerability = FeedVulnerability(
                        feed_id=feed_id,
                        source_name=source.name,
                        feed_type=source.feed_type,
                        cve_id=cve_id,
                        title=f"CISA KEV: {vuln_data.get('vulnerabilityName', cve_id)}",
                        description=vuln_data.get('shortDescription', ''),
                        severity="high",  # KEV vulnerabilities are considered high risk
                        cvss_score=8.0,  # Default high score for exploited vulnerabilities
                        cvss_vector=None,
                        published_date=date_added,
                        modified_date=date_added,
                        affected_products=[vuln_data.get('product', '')],
                        references=[],
                        exploit_available=True,  # KEV means actively exploited
                        exploitation_likelihood="high",
                        mitigation_strategies=[vuln_data.get('requiredAction', '')],
                        status=VulnerabilityStatus.EXPLOITED,
                        raw_data=vuln_data
                    )
                    
                    yield vulnerability
                    
        except Exception as e:
            self.logger.error(f"Error processing CISA KEV feed: {e}")
            raise
    
    async def _process_vendor_advisory_feed(self, source: FeedSource) -> AsyncGenerator[FeedVulnerability, None]:
        """Process vendor security advisory feeds"""
        # This would be implemented based on specific vendor feed formats
        # Placeholder implementation
        if False:  # Placeholder condition
            yield FeedVulnerability(
                feed_id="", source_name="", feed_type=FeedType.VENDOR_ADVISORY,
                cve_id="", title="", description="", severity="", cvss_score=0.0,
                cvss_vector=None, published_date=datetime.now(timezone.utc),
                modified_date=datetime.now(timezone.utc), affected_products=[],
                references=[], exploit_available=False, exploitation_likelihood=""
            )
    
    async def _process_threat_intel_feed(self, source: FeedSource) -> AsyncGenerator[FeedVulnerability, None]:
        """Process threat intelligence feeds"""
        # This would be implemented based on threat intel feed formats
        # Placeholder implementation
        if False:  # Placeholder condition
            yield FeedVulnerability(
                feed_id="", source_name="", feed_type=FeedType.THREAT_INTELLIGENCE,
                cve_id="", title="", description="", severity="", cvss_score=0.0,
                cvss_vector=None, published_date=datetime.now(timezone.utc),
                modified_date=datetime.now(timezone.utc), affected_products=[],
                references=[], exploit_available=False, exploitation_likelihood=""
            )
    
    async def _process_exploit_db_feed(self, source: FeedSource) -> AsyncGenerator[FeedVulnerability, None]:
        """Process Exploit Database feeds"""
        # This would be implemented to process exploit database information
        # Placeholder implementation
        if False:  # Placeholder condition
            yield FeedVulnerability(
                feed_id="", source_name="", feed_type=FeedType.EXPLOIT_DB,
                cve_id="", title="", description="", severity="", cvss_score=0.0,
                cvss_vector=None, published_date=datetime.now(timezone.utc),
                modified_date=datetime.now(timezone.utc), affected_products=[],
                references=[], exploit_available=False, exploitation_likelihood=""
            )
    
    async def _save_feed_vulnerability(self, vulnerability: FeedVulnerability) -> bool:
        """Save vulnerability from feed to database"""
        
        with sqlite3.connect(self.db_path) as conn:
            # Check if vulnerability already exists
            cursor = conn.execute(
                "SELECT feed_id FROM feed_vulnerabilities WHERE feed_id = ?",
                (vulnerability.feed_id,)
            )
            existing = cursor.fetchone()
            is_new = existing is None
            
            now = datetime.now(timezone.utc).isoformat()
            
            conn.execute("""
                INSERT OR REPLACE INTO feed_vulnerabilities (
                    feed_id, source_name, feed_type, cve_id, title, description,
                    severity, cvss_score, cvss_vector, published_date, modified_date,
                    affected_products, references, exploit_available, exploitation_likelihood,
                    threat_actors, attack_patterns, mitigation_strategies, status,
                    raw_data, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                vulnerability.feed_id,
                vulnerability.source_name,
                vulnerability.feed_type.value,
                vulnerability.cve_id,
                vulnerability.title,
                vulnerability.description,
                vulnerability.severity,
                vulnerability.cvss_score,
                vulnerability.cvss_vector,
                vulnerability.published_date.isoformat(),
                vulnerability.modified_date.isoformat(),
                json.dumps(vulnerability.affected_products),
                json.dumps(vulnerability.references),
                vulnerability.exploit_available,
                vulnerability.exploitation_likelihood,
                json.dumps(vulnerability.threat_actors),
                json.dumps(vulnerability.attack_patterns),
                json.dumps(vulnerability.mitigation_strategies),
                vulnerability.status.value,
                json.dumps(vulnerability.raw_data),
                now if is_new else existing,
                now
            ))
        
        return is_new
    
    async def get_recent_vulnerabilities(self, 
                                       hours: int = 24, 
                                       severity_filter: Optional[List[str]] = None) -> List[FeedVulnerability]:
        """Get recent vulnerabilities from feeds"""
        
        since_date = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
        
        with sqlite3.connect(self.db_path) as conn:
            query = """
                SELECT * FROM feed_vulnerabilities 
                WHERE published_date > ? OR modified_date > ?
            """
            params = [since_date, since_date]
            
            if severity_filter:
                placeholders = ','.join('?' * len(severity_filter))
                query += f" AND severity IN ({placeholders})"
                params.extend(severity_filter)
            
            query += " ORDER BY published_date DESC"
            
            cursor = conn.execute(query, params)
            vulnerabilities = []
            
            for row in cursor.fetchall():
                vuln = self._row_to_feed_vulnerability(row)
                vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    async def get_exploited_vulnerabilities(self) -> List[FeedVulnerability]:
        """Get vulnerabilities that are known to be exploited"""
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("""
                SELECT * FROM feed_vulnerabilities 
                WHERE exploit_available = 1 OR status = 'exploited'
                ORDER BY published_date DESC
            """)
            
            vulnerabilities = []
            for row in cursor.fetchall():
                vuln = self._row_to_feed_vulnerability(row)
                vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    async def get_vulnerabilities_by_cve(self, cve_ids: List[str]) -> List[FeedVulnerability]:
        """Get vulnerabilities by CVE IDs"""
        
        if not cve_ids:
            return []
        
        with sqlite3.connect(self.db_path) as conn:
            placeholders = ','.join('?' * len(cve_ids))
            cursor = conn.execute(f"""
                SELECT * FROM feed_vulnerabilities 
                WHERE cve_id IN ({placeholders})
                ORDER BY published_date DESC
            """, cve_ids)
            
            vulnerabilities = []
            for row in cursor.fetchall():
                vuln = self._row_to_feed_vulnerability(row)
                vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _row_to_feed_vulnerability(self, row: tuple) -> FeedVulnerability:
        """Convert database row to FeedVulnerability object"""
        
        return FeedVulnerability(
            feed_id=row[0],
            source_name=row[1],
            feed_type=FeedType(row[2]),
            cve_id=row[3],
            title=row[4],
            description=row[5] or "",
            severity=row[6] or "unknown",
            cvss_score=row[7] or 0.0,
            cvss_vector=row[8],
            published_date=datetime.fromisoformat(row[9]),
            modified_date=datetime.fromisoformat(row[10]),
            affected_products=json.loads(row[11]) if row[11] else [],
            references=json.loads(row[12]) if row[12] else [],
            exploit_available=bool(row[13]),
            exploitation_likelihood=row[14] or "unknown",
            threat_actors=json.loads(row[15]) if row[15] else [],
            attack_patterns=json.loads(row[16]) if row[16] else [],
            mitigation_strategies=json.loads(row[17]) if row[17] else [],
            status=VulnerabilityStatus(row[18]) if row[18] else VulnerabilityStatus.ACTIVE,
            raw_data=json.loads(row[19]) if row[19] else {}
        )
    
    async def get_feed_statistics(self) -> Dict[str, Any]:
        """Get vulnerability feed statistics"""
        
        with sqlite3.connect(self.db_path) as conn:
            # Get total vulnerabilities by source
            cursor = conn.execute("""
                SELECT source_name, COUNT(*) as count
                FROM feed_vulnerabilities
                GROUP BY source_name
            """)
            source_counts = dict(cursor.fetchall())
            
            # Get vulnerabilities by severity
            cursor = conn.execute("""
                SELECT severity, COUNT(*) as count
                FROM feed_vulnerabilities
                GROUP BY severity
            """)
            severity_counts = dict(cursor.fetchall())
            
            # Get recent update statistics
            cursor = conn.execute("""
                SELECT source_name, MAX(update_timestamp) as last_update,
                       SUM(new_vulnerabilities) as total_new,
                       SUM(updated_vulnerabilities) as total_updated
                FROM feed_updates
                WHERE update_timestamp > datetime('now', '-7 days')
                GROUP BY source_name
            """)
            update_stats = {}
            for row in cursor.fetchall():
                update_stats[row[0]] = {
                    'last_update': row[1],
                    'new_vulnerabilities_7d': row[2] or 0,
                    'updated_vulnerabilities_7d': row[3] or 0
                }
            
            # Get exploit statistics
            cursor = conn.execute("""
                SELECT COUNT(*) as exploited_count
                FROM feed_vulnerabilities
                WHERE exploit_available = 1 OR status = 'exploited'
            """)
            exploited_count = cursor.fetchone()[0]
            
            return {
                'total_vulnerabilities': sum(source_counts.values()),
                'vulnerabilities_by_source': source_counts,
                'vulnerabilities_by_severity': severity_counts,
                'exploited_vulnerabilities': exploited_count,
                'active_sources': len(self.feed_sources),
                'enabled_sources': len([s for s in self.feed_sources.values() if s.enabled]),
                'source_update_statistics': update_stats
            }
    
    async def discover_vulnerabilities(self, 
                                     targets: List[str], 
                                     scan_config: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """
        Discovery interface for integration with vulnerability discovery engine
        Returns vulnerabilities from feeds that match specified criteria
        """
        
        findings = []
        
        try:
            # Get criteria from scan config
            severity_filter = None
            hours_back = 24
            include_exploited_only = False
            
            if scan_config:
                severity_filter = scan_config.get('severity_filter')
                hours_back = scan_config.get('hours_back', 24)
                include_exploited_only = scan_config.get('include_exploited_only', False)
            
            # Get vulnerabilities based on criteria
            if include_exploited_only:
                vulnerabilities = await self.get_exploited_vulnerabilities()
            else:
                vulnerabilities = await self.get_recent_vulnerabilities(
                    hours=hours_back, 
                    severity_filter=severity_filter
                )
            
            # Convert to standardized format
            for vuln in vulnerabilities:
                finding = {
                    'id': vuln.feed_id,
                    'title': vuln.title,
                    'description': vuln.description,
                    'severity': vuln.severity,
                    'cvss_score': vuln.cvss_score,
                    'cve_id': vuln.cve_id,
                    'scanner': 'vulnerability_feed',
                    'published_date': vuln.published_date.isoformat(),
                    'modified_date': vuln.modified_date.isoformat(),
                    'affected_products': vuln.affected_products,
                    'references': vuln.references,
                    'exploit_available': vuln.exploit_available,
                    'exploitation_likelihood': vuln.exploitation_likelihood,
                    'threat_actors': vuln.threat_actors,
                    'attack_patterns': vuln.attack_patterns,
                    'mitigation_strategies': vuln.mitigation_strategies,
                    'asset': {
                        'products': vuln.affected_products
                    },
                    'metadata': {
                        'feed_source': vuln.source_name,
                        'feed_type': vuln.feed_type.value,
                        'vulnerability_status': vuln.status.value,
                        'raw_data': vuln.raw_data
                    }
                }
                findings.append(finding)
            
            self.logger.info(f"Retrieved {len(findings)} vulnerabilities from feeds")
            
        except Exception as e:
            self.logger.error(f"Error retrieving vulnerabilities from feeds: {e}")
            raise
        
        return findings