"""
Penetration Testing Evidence Collection and Management
====================================================

Automated evidence collection and management system for penetration testing
that provides secure evidence storage, chain of custody maintenance, and
correlation with findings for compliance-ready documentation.

Key Features:
- Automated screenshot and proof-of-concept capture
- Network traffic and log evidence collection
- Chain of custody maintenance
- Evidence correlation with findings
- Secure evidence storage and retrieval
- Automated evidence validation and integrity checking
- Digital forensics support and timeline analysis

Integration Points:
- Tamper-proof storage for evidence integrity
- Enhanced audit system for chain of custody
- Multi-classification engine for evidence classification
- Compliance documentation for evidence correlation
- Risk assessment framework for evidence prioritization

Classification: UNCLASSIFIED//FOR OFFICIAL USE ONLY
Version: 1.0 - Penetration Testing Evidence Management
Author: Red Team Operations
Date: 2025-07-28
"""

import asyncio
import json
import logging
import time
import os
import shutil
import hashlib
import base64
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
import sqlite3
from PIL import Image, ImageDraw, ImageFont
import io
import subprocess
import mimetypes
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class EvidenceType(Enum):
    """Types of penetration testing evidence."""
    SCREENSHOT = "screenshot"
    NETWORK_CAPTURE = "network_capture"
    LOG_FILE = "log_file"
    COMMAND_OUTPUT = "command_output"
    PROOF_OF_CONCEPT = "proof_of_concept"
    EXPLOIT_CODE = "exploit_code"
    CONFIGURATION_FILE = "configuration_file"
    VULNERABILITY_SCAN = "vulnerability_scan"
    TRAFFIC_ANALYSIS = "traffic_analysis"
    FORENSIC_IMAGE = "forensic_image"

class EvidenceClassification(Enum):
    """Evidence classification levels."""
    UNCLASSIFIED = "UNCLASSIFIED"
    CUI = "CONTROLLED UNCLASSIFIED INFORMATION"
    CONFIDENTIAL = "CONFIDENTIAL"
    SECRET = "SECRET"
    TOP_SECRET = "TOP SECRET"

class EvidenceStatus(Enum):
    """Evidence processing status."""
    COLLECTED = "collected"
    VALIDATED = "validated"
    PROCESSED = "processed"
    ARCHIVED = "archived"
    DELETED = "deleted"

@dataclass
class ChainOfCustody:
    """Chain of custody record for evidence."""
    id: str = field(default_factory=lambda: str(uuid4()))
    evidence_id: str = ""
    action: str = ""  # collected, accessed, modified, transferred, etc.
    performed_by: str = ""
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    location: str = ""
    purpose: str = ""
    digital_signature: str = ""
    witness: str = ""
    notes: str = ""

@dataclass
class EvidenceItem:
    """Individual piece of evidence."""
    id: str = field(default_factory=lambda: str(uuid4()))
    type: EvidenceType = EvidenceType.SCREENSHOT
    classification: EvidenceClassification = EvidenceClassification.UNCLASSIFIED
    title: str = ""
    description: str = ""
    file_path: str = ""
    file_size: int = 0
    file_hash: str = ""
    mime_type: str = ""
    collected_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    collected_by: str = ""
    test_id: str = ""
    finding_id: str = ""
    system_id: str = ""
    network_location: str = ""
    status: EvidenceStatus = EvidenceStatus.COLLECTED
    metadata: Dict[str, Any] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)
    chain_of_custody: List[ChainOfCustody] = field(default_factory=list)
    retention_date: datetime = field(default_factory=lambda: datetime.now(timezone.utc) + timedelta(days=2555))  # 7 years
    is_encrypted: bool = False
    encryption_key_id: str = ""
    
    def add_custody_record(self, action: str, performed_by: str, purpose: str = "", notes: str = ""):
        """Add a chain of custody record."""
        custody_record = ChainOfCustody(
            evidence_id=self.id,
            action=action,
            performed_by=performed_by,
            purpose=purpose,
            notes=notes
        )
        self.chain_of_custody.append(custody_record)

@dataclass
class EvidenceCollection:
    """Collection of related evidence items."""
    id: str = field(default_factory=lambda: str(uuid4()))
    name: str = ""
    description: str = ""
    test_id: str = ""
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    created_by: str = ""
    evidence_items: List[EvidenceItem] = field(default_factory=list)
    total_size: int = 0
    total_items: int = 0
    classification: EvidenceClassification = EvidenceClassification.UNCLASSIFIED
    
    def add_evidence(self, evidence: EvidenceItem):
        """Add evidence item to collection."""
        self.evidence_items.append(evidence)
        self.total_items = len(self.evidence_items)
        self.total_size += evidence.file_size
        
        # Update collection classification to highest level
        if evidence.classification.value > self.classification.value:
            self.classification = evidence.classification

class EvidenceCollector:
    """
    Automated evidence collection and management system.
    
    This system provides comprehensive evidence collection, secure storage,
    chain of custody maintenance, and correlation with penetration testing
    findings for compliance-ready documentation.
    """
    
    def __init__(self, storage_path: str = None, encryption_key: str = None):
        """Initialize the evidence collector."""
        self.storage_path = Path(storage_path) if storage_path else Path(__file__).parent / "evidence_storage"
        self.storage_path.mkdir(exist_ok=True)
        
        # Create subdirectories
        self.screenshots_dir = self.storage_path / "screenshots"
        self.network_captures_dir = self.storage_path / "network_captures"
        self.logs_dir = self.storage_path / "logs"
        self.poc_dir = self.storage_path / "proof_of_concept"
        self.temp_dir = self.storage_path / "temp"
        
        for directory in [self.screenshots_dir, self.network_captures_dir, 
                         self.logs_dir, self.poc_dir, self.temp_dir]:
            directory.mkdir(exist_ok=True)
        
        # Database for evidence metadata
        self.db_path = self.storage_path / "evidence.db"
        
        # Encryption setup
        self.encryption_key = encryption_key.encode() if encryption_key else os.urandom(32)
        
        # Initialize database
        asyncio.create_task(self._initialize_database())
        
        logger.info("Evidence Collector initialized")
    
    async def _initialize_database(self):
        """Initialize the evidence database."""
        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()
            
            # Create evidence items table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS evidence_items (
                    id TEXT PRIMARY KEY,
                    type TEXT NOT NULL,
                    classification TEXT NOT NULL,
                    title TEXT,
                    description TEXT,
                    file_path TEXT,
                    file_size INTEGER,
                    file_hash TEXT,
                    mime_type TEXT,
                    collected_at DATETIME,
                    collected_by TEXT,
                    test_id TEXT,
                    finding_id TEXT,
                    system_id TEXT,
                    network_location TEXT,
                    status TEXT,
                    metadata TEXT,
                    tags TEXT,
                    retention_date DATETIME,
                    is_encrypted BOOLEAN,
                    encryption_key_id TEXT
                )
            """)
            
            # Create chain of custody table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS chain_of_custody (
                    id TEXT PRIMARY KEY,
                    evidence_id TEXT NOT NULL,
                    action TEXT NOT NULL,
                    performed_by TEXT NOT NULL,
                    timestamp DATETIME NOT NULL,
                    location TEXT,
                    purpose TEXT,
                    digital_signature TEXT,
                    witness TEXT,
                    notes TEXT,
                    FOREIGN KEY (evidence_id) REFERENCES evidence_items (id)
                )
            """)
            
            # Create evidence collections table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS evidence_collections (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    description TEXT,
                    test_id TEXT,
                    created_at DATETIME,
                    created_by TEXT,
                    total_size INTEGER,
                    total_items INTEGER,
                    classification TEXT
                )
            """)
            
            # Create collection items mapping table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS collection_items (
                    collection_id TEXT NOT NULL,
                    evidence_id TEXT NOT NULL,
                    PRIMARY KEY (collection_id, evidence_id),
                    FOREIGN KEY (collection_id) REFERENCES evidence_collections (id),
                    FOREIGN KEY (evidence_id) REFERENCES evidence_items (id)
                )
            """)
            
            # Create indexes
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_evidence_test_id ON evidence_items(test_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_evidence_finding_id ON evidence_items(finding_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_evidence_collected_at ON evidence_items(collected_at)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_custody_evidence_id ON chain_of_custody(evidence_id)")
            
            conn.commit()
            conn.close()
            
            logger.info("Evidence database initialized successfully")
            
        except Exception as e:
            logger.error(f"Error initializing evidence database: {str(e)}")
            raise
    
    async def capture_screenshot(self, 
                                title: str = "",
                                description: str = "",
                                test_id: str = "",
                                finding_id: str = "",
                                collected_by: str = "",
                                display: int = 0) -> EvidenceItem:
        """
        Capture a screenshot as evidence.
        
        Args:
            title: Screenshot title
            description: Screenshot description
            test_id: Associated test ID
            finding_id: Associated finding ID
            collected_by: Person collecting the evidence
            display: Display number (for multi-monitor systems)
            
        Returns:
            Evidence item for the screenshot
        """
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"screenshot_{timestamp}_{uuid4().hex[:8]}.png"
            file_path = self.screenshots_dir / filename
            
            # Capture screenshot using system tools
            if os.name == 'nt':  # Windows
                import pyautogui
                screenshot = pyautogui.screenshot()
                screenshot.save(str(file_path))
            else:  # Unix-like systems
                # Use scrot or ImageMagick import command
                result = subprocess.run(['scrot', str(file_path)], 
                                      capture_output=True, text=True)
                if result.returncode != 0:
                    # Fallback to ImageMagick
                    result = subprocess.run(['import', '-window', 'root', str(file_path)], 
                                          capture_output=True, text=True)
                    if result.returncode != 0:
                        raise Exception("Unable to capture screenshot")
            
            # Calculate file hash
            file_hash = await self._calculate_file_hash(file_path)
            file_size = file_path.stat().st_size
            
            # Create evidence item
            evidence = EvidenceItem(
                type=EvidenceType.SCREENSHOT,
                title=title or f"Screenshot {timestamp}",
                description=description,
                file_path=str(file_path),
                file_size=file_size,
                file_hash=file_hash,
                mime_type="image/png",
                collected_by=collected_by,
                test_id=test_id,
                finding_id=finding_id,
                metadata={
                    'display': display,
                    'capture_method': 'automated',
                    'screen_resolution': self._get_screen_resolution()
                }
            )
            
            # Add initial chain of custody record
            evidence.add_custody_record("collected", collected_by, "Screenshot captured during penetration testing")
            
            # Store in database
            await self._store_evidence_item(evidence)
            
            logger.info(f"Screenshot captured: {filename}")
            return evidence
            
        except Exception as e:
            logger.error(f"Error capturing screenshot: {str(e)}")
            raise
    
    def _get_screen_resolution(self) -> str:
        """Get screen resolution information."""
        try:
            if os.name == 'nt':  # Windows
                import tkinter as tk
                root = tk.Tk()
                width = root.winfo_screenwidth()
                height = root.winfo_screenheight()
                root.destroy()
                return f"{width}x{height}"
            else:  # Unix-like systems
                result = subprocess.run(['xrandr'], capture_output=True, text=True)
                if result.returncode == 0:
                    lines = result.stdout.split('\n')
                    for line in lines:
                        if '*' in line:  # Current resolution
                            parts = line.split()
                            for part in parts:
                                if 'x' in part and part.replace('x', '').replace('.', '').isdigit():
                                    return part.split()[0]
            return "unknown"
        except:
            return "unknown"
    
    async def collect_network_capture(self,
                                    interface: str = "any",
                                    duration: int = 60,
                                    filter_expression: str = "",
                                    title: str = "",
                                    description: str = "",
                                    test_id: str = "",
                                    finding_id: str = "",
                                    collected_by: str = "") -> EvidenceItem:
        """
        Collect network traffic capture as evidence.
        
        Args:
            interface: Network interface to capture from
            duration: Capture duration in seconds
            filter_expression: tcpdump/Wireshark filter expression
            title: Capture title
            description: Capture description
            test_id: Associated test ID
            finding_id: Associated finding ID
            collected_by: Person collecting the evidence
            
        Returns:
            Evidence item for the network capture
        """
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"network_capture_{timestamp}_{uuid4().hex[:8]}.pcap"
            file_path = self.network_captures_dir / filename
            
            # Build tcpdump command
            cmd = ['tcpdump', '-i', interface, '-w', str(file_path)]
            
            if filter_expression:
                cmd.extend(['-f', filter_expression])
            
            # Start capture process
            logger.info(f"Starting network capture on {interface} for {duration} seconds")
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            # Wait for specified duration
            await asyncio.sleep(duration)
            
            # Stop capture
            process.terminate()
            process.wait()
            
            if not file_path.exists() or file_path.stat().st_size == 0:
                raise Exception("Network capture failed or produced empty file")
            
            # Calculate file hash
            file_hash = await self._calculate_file_hash(file_path)
            file_size = file_path.stat().st_size
            
            # Create evidence item
            evidence = EvidenceItem(
                type=EvidenceType.NETWORK_CAPTURE,
                title=title or f"Network Capture {timestamp}",
                description=description,
                file_path=str(file_path),
                file_size=file_size,
                file_hash=file_hash,
                mime_type="application/vnd.tcpdump.pcap",
                collected_by=collected_by,
                test_id=test_id,
                finding_id=finding_id,
                metadata={
                    'interface': interface,
                    'duration': duration,
                    'filter': filter_expression,
                    'capture_method': 'tcpdump'
                }
            )
            
            # Add chain of custody record
            evidence.add_custody_record("collected", collected_by, f"Network traffic captured on {interface}")
            
            # Store in database
            await self._store_evidence_item(evidence)
            
            logger.info(f"Network capture completed: {filename} ({file_size} bytes)")
            return evidence
            
        except Exception as e:
            logger.error(f"Error collecting network capture: {str(e)}")
            raise
    
    async def collect_command_output(self,
                                   command: str,
                                   title: str = "",
                                   description: str = "",
                                   test_id: str = "",
                                   finding_id: str = "",
                                   collected_by: str = "",
                                   working_dir: str = None) -> EvidenceItem:
        """
        Collect command output as evidence.
        
        Args:
            command: Command to execute
            title: Output title
            description: Output description
            test_id: Associated test ID
            finding_id: Associated finding ID
            collected_by: Person collecting the evidence
            working_dir: Working directory for command execution
            
        Returns:
            Evidence item for the command output
        """
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"command_output_{timestamp}_{uuid4().hex[:8]}.txt"
            file_path = self.logs_dir / filename
            
            # Execute command
            logger.info(f"Executing command: {command}")
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                cwd=working_dir,
                timeout=300  # 5 minute timeout
            )
            
            # Create output content
            output_content = f"Command: {command}\n"
            output_content += f"Working Directory: {working_dir or os.getcwd()}\n"
            output_content += f"Executed At: {datetime.now().isoformat()}\n"
            output_content += f"Return Code: {result.returncode}\n"
            output_content += "-" * 50 + "\n"
            output_content += "STDOUT:\n"
            output_content += result.stdout
            output_content += "\n" + "-" * 50 + "\n"
            output_content += "STDERR:\n"
            output_content += result.stderr
            
            # Write to file
            async with aiofiles.open(file_path, 'w', encoding='utf-8') as f:
                await f.write(output_content)
            
            # Calculate file hash
            file_hash = await self._calculate_file_hash(file_path)
            file_size = file_path.stat().st_size
            
            # Create evidence item
            evidence = EvidenceItem(
                type=EvidenceType.COMMAND_OUTPUT,
                title=title or f"Command Output: {command[:50]}...",
                description=description,
                file_path=str(file_path),
                file_size=file_size,
                file_hash=file_hash,
                mime_type="text/plain",
                collected_by=collected_by,
                test_id=test_id,
                finding_id=finding_id,
                metadata={
                    'command': command,
                    'return_code': result.returncode,
                    'working_directory': working_dir or os.getcwd(),
                    'execution_time': datetime.now().isoformat()
                }
            )
            
            # Add chain of custody record
            evidence.add_custody_record("collected", collected_by, f"Command output collected: {command}")
            
            # Store in database
            await self._store_evidence_item(evidence)
            
            logger.info(f"Command output collected: {filename}")
            return evidence
            
        except Exception as e:
            logger.error(f"Error collecting command output: {str(e)}")
            raise
    
    async def collect_log_file(self,
                             log_file_path: str,
                             title: str = "",
                             description: str = "",
                             test_id: str = "",
                             finding_id: str = "",
                             collected_by: str = "",
                             lines_before: int = 0,
                             lines_after: int = 0) -> EvidenceItem:
        """
        Collect log file as evidence.
        
        Args:
            log_file_path: Path to the log file
            title: Log file title
            description: Log file description
            test_id: Associated test ID
            finding_id: Associated finding ID
            collected_by: Person collecting the evidence
            lines_before: Lines to include before relevant content
            lines_after: Lines to include after relevant content
            
        Returns:
            Evidence item for the log file
        """
        try:
            source_path = Path(log_file_path)
            if not source_path.exists():
                raise FileNotFoundError(f"Log file not found: {log_file_path}")
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"log_{source_path.stem}_{timestamp}_{uuid4().hex[:8]}.log"
            file_path = self.logs_dir / filename
            
            # Copy log file to evidence storage
            shutil.copy2(source_path, file_path)
            
            # Calculate file hash
            file_hash = await self._calculate_file_hash(file_path)
            file_size = file_path.stat().st_size
            
            # Detect MIME type
            mime_type, _ = mimetypes.guess_type(str(file_path))
            mime_type = mime_type or "text/plain"
            
            # Create evidence item
            evidence = EvidenceItem(
                type=EvidenceType.LOG_FILE,
                title=title or f"Log File: {source_path.name}",
                description=description,
                file_path=str(file_path),
                file_size=file_size,
                file_hash=file_hash,
                mime_type=mime_type,
                collected_by=collected_by,
                test_id=test_id,
                finding_id=finding_id,
                metadata={
                    'original_path': str(source_path),
                    'original_size': source_path.stat().st_size,
                    'lines_before': lines_before,
                    'lines_after': lines_after,
                    'file_modified_time': datetime.fromtimestamp(source_path.stat().st_mtime).isoformat()
                }
            )
            
            # Add chain of custody record
            evidence.add_custody_record("collected", collected_by, f"Log file collected from {source_path}")
            
            # Store in database
            await self._store_evidence_item(evidence)
            
            logger.info(f"Log file collected: {filename}")
            return evidence
            
        except Exception as e:
            logger.error(f"Error collecting log file: {str(e)}")
            raise
    
    async def store_proof_of_concept(self,
                                   content: str,
                                   file_type: str = "txt",
                                   title: str = "",
                                   description: str = "",
                                   test_id: str = "",
                                   finding_id: str = "",
                                   collected_by: str = "") -> EvidenceItem:
        """
        Store proof-of-concept code or documentation as evidence.
        
        Args:
            content: PoC content
            file_type: File extension (txt, py, sh, etc.)
            title: PoC title
            description: PoC description
            test_id: Associated test ID
            finding_id: Associated finding ID
            collected_by: Person collecting the evidence
            
        Returns:
            Evidence item for the proof-of-concept
        """
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"poc_{timestamp}_{uuid4().hex[:8]}.{file_type}"
            file_path = self.poc_dir / filename
            
            # Write content to file
            async with aiofiles.open(file_path, 'w', encoding='utf-8') as f:
                await f.write(content)
            
            # Calculate file hash
            file_hash = await self._calculate_file_hash(file_path)
            file_size = file_path.stat().st_size
            
            # Detect MIME type
            mime_type, _ = mimetypes.guess_type(str(file_path))
            mime_type = mime_type or "text/plain"
            
            # Create evidence item
            evidence = EvidenceItem(
                type=EvidenceType.PROOF_OF_CONCEPT,
                title=title or f"Proof of Concept {timestamp}",
                description=description,
                file_path=str(file_path),
                file_size=file_size,
                file_hash=file_hash,
                mime_type=mime_type,
                collected_by=collected_by,
                test_id=test_id,
                finding_id=finding_id,
                metadata={
                    'file_type': file_type,
                    'content_length': len(content),
                    'created_at': datetime.now().isoformat()
                }
            )
            
            # Add chain of custody record
            evidence.add_custody_record("created", collected_by, "Proof-of-concept code/documentation created")
            
            # Store in database
            await self._store_evidence_item(evidence)
            
            logger.info(f"Proof-of-concept stored: {filename}")
            return evidence
            
        except Exception as e:
            logger.error(f"Error storing proof-of-concept: {str(e)}")
            raise
    
    async def _calculate_file_hash(self, file_path: Path) -> str:
        """Calculate SHA-256 hash of a file."""
        hash_sha256 = hashlib.sha256()
        async with aiofiles.open(file_path, 'rb') as f:
            async for chunk in self._read_file_chunks(f):
                hash_sha256.update(chunk)
        return hash_sha256.hexdigest()
    
    async def _read_file_chunks(self, file_handle, chunk_size: int = 8192):
        """Read file in chunks for memory efficiency."""
        while True:
            chunk = await file_handle.read(chunk_size)
            if not chunk:
                break
            yield chunk
    
    async def _store_evidence_item(self, evidence: EvidenceItem):
        """Store evidence item in database."""
        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()
            
            # Insert evidence item
            cursor.execute("""
                INSERT INTO evidence_items (
                    id, type, classification, title, description, file_path,
                    file_size, file_hash, mime_type, collected_at, collected_by,
                    test_id, finding_id, system_id, network_location, status,
                    metadata, tags, retention_date, is_encrypted, encryption_key_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                evidence.id,
                evidence.type.value,
                evidence.classification.value,
                evidence.title,
                evidence.description,
                evidence.file_path,
                evidence.file_size,
                evidence.file_hash,
                evidence.mime_type,
                evidence.collected_at.isoformat(),
                evidence.collected_by,
                evidence.test_id,
                evidence.finding_id,
                evidence.system_id,
                evidence.network_location,
                evidence.status.value,
                json.dumps(evidence.metadata),
                json.dumps(evidence.tags),
                evidence.retention_date.isoformat(),
                evidence.is_encrypted,
                evidence.encryption_key_id
            ))
            
            # Insert chain of custody records
            for custody_record in evidence.chain_of_custody:
                cursor.execute("""
                    INSERT INTO chain_of_custody (
                        id, evidence_id, action, performed_by, timestamp,
                        location, purpose, digital_signature, witness, notes
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    custody_record.id,
                    custody_record.evidence_id,
                    custody_record.action,
                    custody_record.performed_by,
                    custody_record.timestamp.isoformat(),
                    custody_record.location,
                    custody_record.purpose,
                    custody_record.digital_signature,
                    custody_record.witness,
                    custody_record.notes
                ))
            
            conn.commit()
            conn.close()
            
            logger.debug(f"Evidence item stored in database: {evidence.id}")
            
        except Exception as e:
            logger.error(f"Error storing evidence item: {str(e)}")
            raise
    
    async def get_evidence_by_test(self, test_id: str) -> List[EvidenceItem]:
        """Get all evidence for a specific test."""
        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT id, type, classification, title, description, file_path,
                       file_size, file_hash, mime_type, collected_at, collected_by,
                       test_id, finding_id, system_id, network_location, status,
                       metadata, tags, retention_date, is_encrypted, encryption_key_id
                FROM evidence_items
                WHERE test_id = ?
                ORDER BY collected_at DESC
            """, (test_id,))
            
            rows = cursor.fetchall()
            evidence_items = []
            
            for row in rows:
                # Get chain of custody records
                cursor.execute("""
                    SELECT id, evidence_id, action, performed_by, timestamp,
                           location, purpose, digital_signature, witness, notes
                    FROM chain_of_custody
                    WHERE evidence_id = ?
                    ORDER BY timestamp ASC
                """, (row[0],))
                
                custody_rows = cursor.fetchall()
                chain_of_custody = []
                
                for custody_row in custody_rows:
                    custody = ChainOfCustody(
                        id=custody_row[0],
                        evidence_id=custody_row[1],
                        action=custody_row[2],
                        performed_by=custody_row[3],
                        timestamp=datetime.fromisoformat(custody_row[4]),
                        location=custody_row[5] or "",
                        purpose=custody_row[6] or "",
                        digital_signature=custody_row[7] or "",
                        witness=custody_row[8] or "",
                        notes=custody_row[9] or ""
                    )
                    chain_of_custody.append(custody)
                
                evidence = EvidenceItem(
                    id=row[0],
                    type=EvidenceType(row[1]),
                    classification=EvidenceClassification(row[2]),
                    title=row[3],
                    description=row[4],
                    file_path=row[5],
                    file_size=row[6],
                    file_hash=row[7],
                    mime_type=row[8],
                    collected_at=datetime.fromisoformat(row[9]),
                    collected_by=row[10],
                    test_id=row[11],
                    finding_id=row[12],
                    system_id=row[13] or "",
                    network_location=row[14] or "",
                    status=EvidenceStatus(row[15]),
                    metadata=json.loads(row[16]) if row[16] else {},
                    tags=json.loads(row[17]) if row[17] else [],
                    retention_date=datetime.fromisoformat(row[18]),
                    is_encrypted=bool(row[19]),
                    encryption_key_id=row[20] or "",
                    chain_of_custody=chain_of_custody
                )
                evidence_items.append(evidence)
            
            conn.close()
            logger.info(f"Retrieved {len(evidence_items)} evidence items for test {test_id}")
            return evidence_items
            
        except Exception as e:
            logger.error(f"Error retrieving evidence by test: {str(e)}")
            raise
    
    async def create_evidence_collection(self, 
                                       name: str,
                                       description: str = "",
                                       test_id: str = "",
                                       created_by: str = "") -> EvidenceCollection:
        """Create a new evidence collection."""
        try:
            collection = EvidenceCollection(
                name=name,
                description=description,
                test_id=test_id,
                created_by=created_by
            )
            
            # Store in database
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT INTO evidence_collections (
                    id, name, description, test_id, created_at, created_by,
                    total_size, total_items, classification
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                collection.id,
                collection.name,
                collection.description,
                collection.test_id,
                collection.created_at.isoformat(),
                collection.created_by,
                collection.total_size,
                collection.total_items,
                collection.classification.value
            ))
            
            conn.commit()
            conn.close()
            
            logger.info(f"Evidence collection created: {collection.name}")
            return collection
            
        except Exception as e:
            logger.error(f"Error creating evidence collection: {str(e)}")
            raise
    
    async def generate_chain_of_custody_report(self, evidence_id: str) -> str:
        """Generate a chain of custody report for an evidence item."""
        try:
            conn = sqlite3.connect(str(self.db_path))
            cursor = conn.cursor()
            
            # Get evidence item
            cursor.execute("""
                SELECT id, type, title, file_path, file_hash, collected_at, collected_by
                FROM evidence_items
                WHERE id = ?
            """, (evidence_id,))
            
            evidence_row = cursor.fetchone()
            if not evidence_row:
                raise ValueError(f"Evidence item not found: {evidence_id}")
            
            # Get chain of custody records
            cursor.execute("""
                SELECT action, performed_by, timestamp, purpose, notes
                FROM chain_of_custody
                WHERE evidence_id = ?
                ORDER BY timestamp ASC
            """, (evidence_id,))
            
            custody_rows = cursor.fetchall()
            conn.close()
            
            # Generate report
            report = f"CHAIN OF CUSTODY REPORT\n"
            report += f"=" * 50 + "\n\n"
            report += f"Evidence ID: {evidence_row[0]}\n"
            report += f"Evidence Type: {evidence_row[1]}\n"
            report += f"Title: {evidence_row[2]}\n"
            report += f"File Path: {evidence_row[3]}\n"
            report += f"File Hash: {evidence_row[4]}\n"
            report += f"Collected At: {evidence_row[5]}\n"
            report += f"Collected By: {evidence_row[6]}\n\n"
            
            report += f"CUSTODY RECORDS:\n"
            report += f"-" * 30 + "\n"
            
            for custody_row in custody_rows:
                report += f"Action: {custody_row[0]}\n"
                report += f"Performed By: {custody_row[1]}\n"
                report += f"Timestamp: {custody_row[2]}\n"
                report += f"Purpose: {custody_row[3]}\n"
                report += f"Notes: {custody_row[4]}\n"
                report += f"-" * 30 + "\n"
            
            # Save report to file
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            report_filename = f"chain_of_custody_{evidence_id}_{timestamp}.txt"
            report_path = self.storage_path / report_filename
            
            async with aiofiles.open(report_path, 'w', encoding='utf-8') as f:
                await f.write(report)
            
            logger.info(f"Chain of custody report generated: {report_filename}")
            return str(report_path)
            
        except Exception as e:
            logger.error(f"Error generating chain of custody report: {str(e)}")
            raise

# Convenience functions
async def collect_pentest_evidence(evidence_type: str,
                                 test_id: str,
                                 collected_by: str,
                                 **kwargs) -> EvidenceItem:
    """Collect penetration testing evidence based on type."""
    collector = EvidenceCollector()
    
    if evidence_type == "screenshot":
        return await collector.capture_screenshot(
            test_id=test_id,
            collected_by=collected_by,
            **kwargs
        )
    elif evidence_type == "network_capture":
        return await collector.collect_network_capture(
            test_id=test_id,
            collected_by=collected_by,
            **kwargs
        )
    elif evidence_type == "command_output":
        return await collector.collect_command_output(
            test_id=test_id,
            collected_by=collected_by,
            **kwargs
        )
    elif evidence_type == "log_file":
        return await collector.collect_log_file(
            test_id=test_id,
            collected_by=collected_by,
            **kwargs
        )
    elif evidence_type == "proof_of_concept":
        return await collector.store_proof_of_concept(
            test_id=test_id,
            collected_by=collected_by,
            **kwargs
        )
    else:
        raise ValueError(f"Unsupported evidence type: {evidence_type}")

if __name__ == "__main__":
    # Example usage
    async def main():
        collector = EvidenceCollector()
        
        # Capture screenshot
        screenshot = await collector.capture_screenshot(
            title="Login Page Vulnerability",
            description="Screenshot showing SQL injection in login form",
            test_id="TEST001",
            finding_id="FINDING001",
            collected_by="security_analyst"
        )
        
        print(f"Screenshot captured: {screenshot.title}")
        
        # Store proof-of-concept
        poc_content = """
# SQL Injection Proof of Concept
# Target: Login form at /login.php
# Payload: admin' OR '1'='1' --

import requests

url = "http://target.com/login.php"
data = {
    "username": "admin' OR '1'='1' --",
    "password": "anything"
}

response = requests.post(url, data=data)
print(response.text)
"""
        
        poc = await collector.store_proof_of_concept(
            content=poc_content,
            file_type="py",
            title="SQL Injection PoC",
            description="Proof-of-concept code for SQL injection vulnerability",
            test_id="TEST001",
            finding_id="FINDING001",
            collected_by="security_analyst"
        )
        
        print(f"PoC stored: {poc.title}")
        
        # Get all evidence for test
        evidence_list = await collector.get_evidence_by_test("TEST001")
        print(f"Total evidence items for TEST001: {len(evidence_list)}")
        
        # Generate chain of custody report
        if evidence_list:
            custody_report = await collector.generate_chain_of_custody_report(evidence_list[0].id)
            print(f"Chain of custody report: {custody_report}")
    
    asyncio.run(main())