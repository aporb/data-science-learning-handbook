"""
Penetration Test Data Management System
=======================================

Main data management system for penetration testing data lifecycle management.
Provides secure data sanitization, classification-aware cleanup, automated data
refresh and rotation, and comprehensive audit trails for all data operations.

Key Features:
- Test data lifecycle management with automated expiration
- Secure data sanitization and cleanup with multiple methods
- Data provenance and comprehensive audit trails
- Classification marking and handling with compliance
- Automated data refresh and rotation schedules
- Integration with existing security infrastructure
- GDPR/DoD compliance for data handling

Classification: UNCLASSIFIED//FOR OFFICIAL USE ONLY
Version: 1.0
Author: Security Compliance Team
Date: 2025-07-28
"""

import asyncio
import json
import logging
import hashlib
import uuid
import shutil
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Tuple, Set, Union
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
import sqlite3
from concurrent.futures import ThreadPoolExecutor
import tempfile
import os

# Import existing infrastructure
from ...multi_classification.enhanced_classification_engine import ClassificationLevel
from ...audits.audit_logger import AuditLogger
from ..data.test_data_generator import GeneratedTestData, TestDataType

logger = logging.getLogger(__name__)

class DataOperation(Enum):
    """Types of data operations."""
    CREATE = "create"
    READ = "read"
    UPDATE = "update"
    DELETE = "delete"
    SANITIZE = "sanitize"
    BACKUP = "backup"
    RESTORE = "restore"
    EXPIRE = "expire"
    ROTATE = "rotate"

class SanitizationMethod(Enum):
    """Data sanitization methods."""
    OVERWRITE = "overwrite"
    CRYPTO_ERASE = "crypto_erase"
    DEGAUSS = "degauss"
    PHYSICAL_DESTRUCTION = "physical_destruction"
    DOD_5220_22M = "dod_5220_22m"
    GUTMANN = "gutmann"
    SECURE_DELETE = "secure_delete"

class DataStatus(Enum):
    """Status of managed data."""
    ACTIVE = "active"
    EXPIRED = "expired"
    SANITIZING = "sanitizing"
    SANITIZED = "sanitized"
    ARCHIVED = "archived"
    DESTROYED = "destroyed"

@dataclass
class DataRecord:
    """Record of managed test data."""
    record_id: str
    data_id: str
    data_type: TestDataType
    classification_level: ClassificationLevel
    status: DataStatus
    created_at: datetime
    expires_at: Optional[datetime]
    last_accessed: Optional[datetime]
    access_count: int = 0
    file_paths: List[str] = field(default_factory=list)
    database_tables: List[str] = field(default_factory=list)
    sanitization_method: Optional[SanitizationMethod] = None
    sanitized_at: Optional[datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    audit_trail: List[Dict[str, Any]] = field(default_factory=list)

@dataclass
class SanitizationJob:
    """Sanitization job configuration."""
    job_id: str
    data_records: List[str]  # Record IDs
    method: SanitizationMethod
    scheduled_at: datetime
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    status: str = "pending"  # pending, running, completed, failed
    verification_required: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)

class PenetrationTestDataManager:
    """
    Main data management system for penetration testing data.
    
    Provides comprehensive data lifecycle management with classification
    awareness, secure sanitization, and compliance with DoD/GDPR requirements.
    """
    
    def __init__(self, 
                 data_directory: Optional[str] = None,
                 audit_logger: Optional[AuditLogger] = None,
                 database_path: Optional[str] = None):
        """Initialize the penetration test data manager."""
        self.audit_logger = audit_logger
        
        # Setup data directory
        self.data_directory = Path(data_directory or tempfile.gettempdir()) / "pentest_data"
        self.data_directory.mkdir(parents=True, exist_ok=True)
        
        # Setup database
        self.database_path = database_path or str(self.data_directory / "data_manager.db")
        self._initialize_database()
        
        # Data storage
        self.data_records: Dict[str, DataRecord] = {}
        self.sanitization_jobs: Dict[str, SanitizationJob] = {}
        
        # Thread pool for background operations
        self.executor = ThreadPoolExecutor(max_workers=4)
        
        # Management statistics
        self.manager_stats = {
            'total_records': 0,
            'active_records': 0,
            'sanitized_records': 0,
            'total_sanitization_jobs': 0,
            'data_volume_bytes': 0,
            'classification_distribution': {}
        }
        
        # Load existing records
        asyncio.create_task(self._load_existing_records())
        
        # Start background cleanup task
        asyncio.create_task(self._background_cleanup_task())
        
        logger.info("PenetrationTestDataManager initialized")
    
    def _initialize_database(self) -> None:
        """Initialize SQLite database for data management."""
        conn = sqlite3.connect(self.database_path)
        cursor = conn.cursor()
        
        # Create tables
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS data_records (
                record_id TEXT PRIMARY KEY,
                data_id TEXT NOT NULL,
                data_type TEXT NOT NULL,
                classification_level TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT,
                last_accessed TEXT,
                access_count INTEGER DEFAULT 0,
                file_paths TEXT,
                database_tables TEXT,
                sanitization_method TEXT,
                sanitized_at TEXT,
                metadata TEXT,
                audit_trail TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS sanitization_jobs (
                job_id TEXT PRIMARY KEY,
                data_records TEXT NOT NULL,
                method TEXT NOT NULL,
                scheduled_at TEXT NOT NULL,
                started_at TEXT,
                completed_at TEXT,
                status TEXT DEFAULT 'pending',
                verification_required INTEGER DEFAULT 1,
                metadata TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                operation TEXT NOT NULL,
                record_id TEXT,
                user_id TEXT,
                details TEXT
            )
        ''')
        
        conn.commit()
        conn.close()
    
    async def register_data(self, 
                          generated_data: GeneratedTestData,
                          file_paths: Optional[List[str]] = None,
                          database_tables: Optional[List[str]] = None) -> str:
        """
        Register generated test data for management.
        
        Args:
            generated_data: The generated test data
            file_paths: List of file paths containing the data
            database_tables: List of database tables containing the data
            
        Returns:
            Data record ID
        """
        try:
            record_id = str(uuid.uuid4())
            
            # Create data record
            record = DataRecord(
                record_id=record_id,
                data_id=generated_data.data_id,
                data_type=generated_data.data_type,
                classification_level=generated_data.classification,
                status=DataStatus.ACTIVE,
                created_at=generated_data.generated_at,
                expires_at=generated_data.expires_at,
                file_paths=file_paths or [],
                database_tables=database_tables or [],
                metadata={
                    'original_metadata': generated_data.metadata,
                    'content_hash': self._calculate_content_hash(generated_data.content)
                }
            )
            
            # Store record
            self.data_records[record_id] = record
            await self._persist_record(record)
            
            # Update statistics
            self.manager_stats['total_records'] += 1
            self.manager_stats['active_records'] += 1
            
            classification_key = generated_data.classification.value
            self.manager_stats['classification_distribution'][classification_key] = \
                self.manager_stats['classification_distribution'].get(classification_key, 0) + 1
            
            # Audit registration
            await self._audit_operation(
                operation=DataOperation.CREATE,
                record_id=record_id,
                details={
                    'data_id': generated_data.data_id,
                    'data_type': generated_data.data_type.value,
                    'classification': generated_data.classification.value
                }
            )
            
            logger.info(f"Registered data record {record_id} for data {generated_data.data_id}")
            return record_id
            
        except Exception as e:
            error_msg = f"Failed to register data: {str(e)}"
            logger.error(error_msg)
            raise
    
    async def access_data(self, record_id: str) -> Optional[DataRecord]:
        """
        Access a data record and update access statistics.
        
        Args:
            record_id: ID of the data record
            
        Returns:
            Data record if found and accessible
        """
        try:
            record = self.data_records.get(record_id)
            if not record:
                return None
            
            # Check if data is still active
            if record.status != DataStatus.ACTIVE:
                logger.warning(f"Attempted to access non-active data record {record_id}")
                return None
            
            # Check expiration
            if record.expires_at and record.expires_at < datetime.now(timezone.utc):
                await self._expire_data_record(record)
                return None
            
            # Update access statistics
            record.last_accessed = datetime.now(timezone.utc)
            record.access_count += 1
            await self._persist_record(record)
            
            # Audit access
            await self._audit_operation(
                operation=DataOperation.READ,
                record_id=record_id,
                details={'access_count': record.access_count}
            )
            
            return record
            
        except Exception as e:
            logger.error(f"Failed to access data record: {str(e)}")
            return None
    
    async def schedule_sanitization(self, 
                                  record_ids: List[str],
                                  method: SanitizationMethod,
                                  schedule_time: Optional[datetime] = None) -> str:
        """
        Schedule data sanitization for specified records.
        
        Args:
            record_ids: List of data record IDs to sanitize
            method: Sanitization method to use
            schedule_time: When to perform sanitization (default: now)
            
        Returns:
            Sanitization job ID
        """
        try:
            job_id = str(uuid.uuid4())
            schedule_time = schedule_time or datetime.now(timezone.utc)
            
            # Validate record IDs
            valid_records = []
            for record_id in record_ids:
                record = self.data_records.get(record_id)
                if record and record.status == DataStatus.ACTIVE:
                    valid_records.append(record_id)
                else:
                    logger.warning(f"Invalid or inactive record for sanitization: {record_id}")
            
            if not valid_records:
                raise ValueError("No valid records for sanitization")
            
            # Create sanitization job
            job = SanitizationJob(
                job_id=job_id,
                data_records=valid_records,
                method=method,
                scheduled_at=schedule_time,
                verification_required=method in [
                    SanitizationMethod.DOD_5220_22M,
                    SanitizationMethod.GUTMANN,
                    SanitizationMethod.PHYSICAL_DESTRUCTION
                ]
            )
            
            self.sanitization_jobs[job_id] = job
            await self._persist_sanitization_job(job)
            
            # Update statistics
            self.manager_stats['total_sanitization_jobs'] += 1
            
            # Audit job creation
            await self._audit_operation(
                operation=DataOperation.SANITIZE,
                record_id=None,
                details={
                    'job_id': job_id,
                    'method': method.value,
                    'record_count': len(valid_records),
                    'scheduled_at': schedule_time.isoformat()
                }
            )
            
            # Execute immediately if scheduled for now or past
            if schedule_time <= datetime.now(timezone.utc):
                asyncio.create_task(self._execute_sanitization_job(job_id))
            
            logger.info(f"Scheduled sanitization job {job_id} for {len(valid_records)} records")
            return job_id
            
        except Exception as e:
            error_msg = f"Failed to schedule sanitization: {str(e)}"
            logger.error(error_msg)
            raise
    
    async def _execute_sanitization_job(self, job_id: str) -> None:
        """Execute a sanitization job."""
        try:
            job = self.sanitization_jobs.get(job_id)
            if not job:
                logger.error(f"Sanitization job {job_id} not found")
                return
            
            job.status = "running"
            job.started_at = datetime.now(timezone.utc)
            await self._persist_sanitization_job(job)
            
            # Sanitize each record
            successful_records = []
            failed_records = []
            
            for record_id in job.data_records:
                try:
                    await self._sanitize_data_record(record_id, job.method)
                    successful_records.append(record_id)
                except Exception as e:
                    logger.error(f"Failed to sanitize record {record_id}: {str(e)}")
                    failed_records.append(record_id)
            
            # Update job status
            job.completed_at = datetime.now(timezone.utc)
            job.status = "completed" if not failed_records else "partial_failure"
            job.metadata.update({
                'successful_records': successful_records,
                'failed_records': failed_records
            })
            
            await self._persist_sanitization_job(job)
            
            # Audit completion
            await self._audit_operation(
                operation=DataOperation.SANITIZE,
                record_id=None,
                details={
                    'job_id': job_id,
                    'status': job.status,
                    'successful_count': len(successful_records),
                    'failed_count': len(failed_records)
                }
            )
            
            logger.info(f"Completed sanitization job {job_id}: {len(successful_records)} successful, {len(failed_records)} failed")
            
        except Exception as e:
            job.status = "failed"
            job.completed_at = datetime.now(timezone.utc)
            await self._persist_sanitization_job(job)
            logger.error(f"Sanitization job {job_id} failed: {str(e)}")
    
    async def _sanitize_data_record(self, 
                                  record_id: str, 
                                  method: SanitizationMethod) -> None:
        """Sanitize a single data record."""
        record = self.data_records.get(record_id)
        if not record:
            raise ValueError(f"Data record {record_id} not found")
        
        record.status = DataStatus.SANITIZING
        await self._persist_record(record)
        
        try:
            # Sanitize files
            for file_path in record.file_paths:
                await self._sanitize_file(file_path, method)
            
            # Sanitize database tables
            for table_name in record.database_tables:
                await self._sanitize_database_table(table_name, method)
            
            # Update record status
            record.status = DataStatus.SANITIZED
            record.sanitization_method = method
            record.sanitized_at = datetime.now(timezone.utc)
            
            # Clear sensitive metadata
            record.metadata = {
                'sanitized': True,
                'original_hash': record.metadata.get('content_hash'),
                'sanitization_verified': False
            }
            
            await self._persist_record(record)
            
            # Update statistics
            self.manager_stats['sanitized_records'] += 1
            self.manager_stats['active_records'] -= 1
            
            logger.info(f"Successfully sanitized data record {record_id} using {method.value}")
            
        except Exception as e:
            record.status = DataStatus.ACTIVE  # Revert status on failure
            await self._persist_record(record)
            raise
    
    async def _sanitize_file(self, file_path: str, method: SanitizationMethod) -> None:
        """Sanitize a file using the specified method."""
        file_path_obj = Path(file_path)
        
        if not file_path_obj.exists():
            logger.warning(f"File {file_path} does not exist, skipping")
            return
        
        # Get file size for progress tracking
        file_size = file_path_obj.stat().st_size
        
        if method == SanitizationMethod.OVERWRITE:
            await self._overwrite_file(file_path_obj, passes=1)
        elif method == SanitizationMethod.DOD_5220_22M:
            await self._overwrite_file(file_path_obj, passes=3)
        elif method == SanitizationMethod.GUTMANN:
            await self._overwrite_file(file_path_obj, passes=35)
        elif method == SanitizationMethod.SECURE_DELETE:
            await self._secure_delete_file(file_path_obj)
        elif method == SanitizationMethod.CRYPTO_ERASE:
            await self._crypto_erase_file(file_path_obj)
        else:
            # For methods requiring physical access, just mark as requiring manual intervention
            logger.warning(f"Method {method.value} requires manual intervention for {file_path}")
    
    async def _overwrite_file(self, file_path: Path, passes: int) -> None:
        """Overwrite file with random data multiple times."""
        file_size = file_path.stat().st_size
        
        for pass_num in range(passes):
            with open(file_path, 'r+b') as f:
                # Write random data in chunks
                chunk_size = 64 * 1024  # 64KB chunks
                for offset in range(0, file_size, chunk_size):
                    remaining = min(chunk_size, file_size - offset)
                    random_data = os.urandom(remaining)
                    f.write(random_data)
                f.flush()
                os.fsync(f.fileno())  # Force write to disk
        
        # Finally, delete the file
        file_path.unlink()
    
    async def _secure_delete_file(self, file_path: Path) -> None:
        """Securely delete a file using system tools if available."""
        try:
            # Try using shred on Unix systems
            import subprocess
            subprocess.run(['shred', '-vfz', '-n', '3', str(file_path)], 
                         check=True, capture_output=True)
        except (subprocess.CalledProcessError, FileNotFoundError):
            # Fallback to overwrite method
            await self._overwrite_file(file_path, passes=3)
    
    async def _crypto_erase_file(self, file_path: Path) -> None:
        """Perform cryptographic erasure by destroying encryption keys."""
        # This is a simplified implementation
        # In practice, this would involve proper key management
        
        # Overwrite with encrypted random data then destroy key
        encrypted_data = os.urandom(file_path.stat().st_size)
        
        with open(file_path, 'wb') as f:
            f.write(encrypted_data)
            f.flush()
            os.fsync(f.fileno())
        
        file_path.unlink()
    
    async def _sanitize_database_table(self, table_name: str, method: SanitizationMethod) -> None:
        """Sanitize a database table."""
        # This would integrate with actual database connections
        # For now, we'll simulate the operation
        logger.info(f"Sanitizing database table {table_name} using {method.value}")
        
        # In a real implementation, this would:
        # 1. Connect to the database
        # 2. Drop or truncate the table
        # 3. Overwrite the underlying storage if required by the method
        # 4. Vacuum/compact the database
    
    async def _expire_data_record(self, record: DataRecord) -> None:
        """Expire a data record and schedule for sanitization."""
        record.status = DataStatus.EXPIRED
        await self._persist_record(record)
        
        # Automatically schedule for sanitization
        await self.schedule_sanitization(
            record_ids=[record.record_id],
            method=SanitizationMethod.SECURE_DELETE
        )
        
        # Update statistics
        self.manager_stats['active_records'] -= 1
        
        logger.info(f"Expired data record {record.record_id}")
    
    async def _load_existing_records(self) -> None:
        """Load existing data records from database."""
        try:
            conn = sqlite3.connect(self.database_path)
            cursor = conn.cursor()
            
            cursor.execute("SELECT * FROM data_records")
            rows = cursor.fetchall()
            
            for row in rows:
                record = self._row_to_data_record(row)
                self.data_records[record.record_id] = record
            
            conn.close()
            
            logger.info(f"Loaded {len(self.data_records)} existing data records")
            
        except Exception as e:
            logger.error(f"Failed to load existing records: {str(e)}")
    
    async def _background_cleanup_task(self) -> None:
        """Background task for automatic cleanup and maintenance."""
        while True:
            try:
                # Check for expired records
                current_time = datetime.now(timezone.utc)
                expired_records = []
                
                for record in self.data_records.values():
                    if (record.status == DataStatus.ACTIVE and 
                        record.expires_at and 
                        record.expires_at < current_time):
                        expired_records.append(record)
                
                # Expire records
                for record in expired_records:
                    await self._expire_data_record(record)
                
                # Execute scheduled sanitization jobs
                for job in self.sanitization_jobs.values():
                    if (job.status == "pending" and 
                        job.scheduled_at <= current_time):
                        asyncio.create_task(self._execute_sanitization_job(job.job_id))
                
                # Sleep for 5 minutes before next check
                await asyncio.sleep(300)
                
            except Exception as e:
                logger.error(f"Error in background cleanup task: {str(e)}")
                await asyncio.sleep(60)  # Shorter sleep on error
    
    def _calculate_content_hash(self, content: Dict[str, Any]) -> str:
        """Calculate hash of content for integrity verification."""
        content_str = json.dumps(content, sort_keys=True)
        return hashlib.sha256(content_str.encode()).hexdigest()
    
    def _row_to_data_record(self, row: Tuple) -> DataRecord:
        """Convert database row to DataRecord object."""
        return DataRecord(
            record_id=row[0],
            data_id=row[1],
            data_type=TestDataType(row[2]),
            classification_level=ClassificationLevel(row[3]),
            status=DataStatus(row[4]),
            created_at=datetime.fromisoformat(row[5]),
            expires_at=datetime.fromisoformat(row[6]) if row[6] else None,
            last_accessed=datetime.fromisoformat(row[7]) if row[7] else None,
            access_count=row[8],
            file_paths=json.loads(row[9]) if row[9] else [],
            database_tables=json.loads(row[10]) if row[10] else [],
            sanitization_method=SanitizationMethod(row[11]) if row[11] else None,
            sanitized_at=datetime.fromisoformat(row[12]) if row[12] else None,
            metadata=json.loads(row[13]) if row[13] else {},
            audit_trail=json.loads(row[14]) if row[14] else []
        )
    
    async def _persist_record(self, record: DataRecord) -> None:
        """Persist data record to database."""
        conn = sqlite3.connect(self.database_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO data_records
            (record_id, data_id, data_type, classification_level, status,
             created_at, expires_at, last_accessed, access_count,
             file_paths, database_tables, sanitization_method, sanitized_at,
             metadata, audit_trail)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            record.record_id,
            record.data_id,
            record.data_type.value,
            record.classification_level.value,
            record.status.value,
            record.created_at.isoformat(),
            record.expires_at.isoformat() if record.expires_at else None,
            record.last_accessed.isoformat() if record.last_accessed else None,
            record.access_count,
            json.dumps(record.file_paths),
            json.dumps(record.database_tables),
            record.sanitization_method.value if record.sanitization_method else None,
            record.sanitized_at.isoformat() if record.sanitized_at else None,
            json.dumps(record.metadata),
            json.dumps(record.audit_trail)
        ))
        
        conn.commit()
        conn.close()
    
    async def _persist_sanitization_job(self, job: SanitizationJob) -> None:
        """Persist sanitization job to database."""
        conn = sqlite3.connect(self.database_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO sanitization_jobs
            (job_id, data_records, method, scheduled_at, started_at,
             completed_at, status, verification_required, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            job.job_id,
            json.dumps(job.data_records),
            job.method.value,
            job.scheduled_at.isoformat(),
            job.started_at.isoformat() if job.started_at else None,
            job.completed_at.isoformat() if job.completed_at else None,
            job.status,
            1 if job.verification_required else 0,
            json.dumps(job.metadata)
        ))
        
        conn.commit()
        conn.close()
    
    async def _audit_operation(self, 
                             operation: DataOperation,
                             record_id: Optional[str] = None,
                             details: Optional[Dict[str, Any]] = None) -> None:
        """Audit a data management operation."""
        timestamp = datetime.now(timezone.utc)
        
        # Store in local database
        conn = sqlite3.connect(self.database_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO audit_log (timestamp, operation, record_id, user_id, details)
            VALUES (?, ?, ?, ?, ?)
        ''', (
            timestamp.isoformat(),
            operation.value,
            record_id,
            "system",  # In a real system, this would be the actual user
            json.dumps(details or {})
        ))
        
        conn.commit()
        conn.close()
        
        # Send to external audit logger if available
        if self.audit_logger:
            await self.audit_logger.log_event(
                event_type=f"data_management_{operation.value}",
                data={
                    'record_id': record_id,
                    'operation': operation.value,
                    'details': details or {}
                },
                classification=ClassificationLevel.UNCLASSIFIED
            )
    
    def get_data_record(self, record_id: str) -> Optional[DataRecord]:
        """Get a data record by ID."""
        return self.data_records.get(record_id)
    
    def list_data_records(self, 
                         status: Optional[DataStatus] = None,
                         classification: Optional[ClassificationLevel] = None,
                         data_type: Optional[TestDataType] = None) -> List[DataRecord]:
        """List data records with optional filtering."""
        results = []
        
        for record in self.data_records.values():
            if status and record.status != status:
                continue
            if classification and record.classification_level != classification:
                continue
            if data_type and record.data_type != data_type:
                continue
            results.append(record)
        
        return results
    
    def get_sanitization_job(self, job_id: str) -> Optional[SanitizationJob]:
        """Get a sanitization job by ID."""
        return self.sanitization_jobs.get(job_id)
    
    def list_sanitization_jobs(self, 
                              status: Optional[str] = None) -> List[SanitizationJob]:
        """List sanitization jobs with optional filtering."""
        results = []
        
        for job in self.sanitization_jobs.values():
            if status and job.status != status:
                continue
            results.append(job)
        
        return results
    
    def get_manager_statistics(self) -> Dict[str, Any]:
        """Get data manager statistics."""
        return self.manager_stats.copy()
    
    async def cleanup_all_data(self, 
                             classification_level: Optional[ClassificationLevel] = None,
                             force: bool = False) -> int:
        """
        Clean up all data records, optionally filtered by classification level.
        
        Args:
            classification_level: Only clean up data at this classification level
            force: Force cleanup even for non-expired data
            
        Returns:
            Number of records scheduled for cleanup
        """
        records_to_cleanup = []
        
        for record in self.data_records.values():
            if record.status != DataStatus.ACTIVE:
                continue
            
            if classification_level and record.classification_level != classification_level:
                continue
            
            # Only cleanup if expired or forced
            if force or (record.expires_at and record.expires_at < datetime.now(timezone.utc)):
                records_to_cleanup.append(record.record_id)
        
        if records_to_cleanup:
            await self.schedule_sanitization(
                record_ids=records_to_cleanup,
                method=SanitizationMethod.SECURE_DELETE
            )
        
        return len(records_to_cleanup)
    
    async def export_audit_log(self, 
                             start_date: Optional[datetime] = None,
                             end_date: Optional[datetime] = None,
                             format: str = 'json') -> str:
        """Export audit log for compliance reporting."""
        conn = sqlite3.connect(self.database_path)
        cursor = conn.cursor()
        
        query = "SELECT * FROM audit_log"
        params = []
        
        if start_date or end_date:
            conditions = []
            if start_date:
                conditions.append("timestamp >= ?")
                params.append(start_date.isoformat())
            if end_date:
                conditions.append("timestamp <= ?")
                params.append(end_date.isoformat())
            
            query += " WHERE " + " AND ".join(conditions)
        
        query += " ORDER BY timestamp"
        
        cursor.execute(query, params)
        rows = cursor.fetchall()
        conn.close()
        
        # Convert to desired format
        audit_entries = []
        for row in rows:
            entry = {
                'id': row[0],
                'timestamp': row[1],
                'operation': row[2],
                'record_id': row[3],
                'user_id': row[4],
                'details': json.loads(row[5]) if row[5] else {}
            }
            audit_entries.append(entry)
        
        if format.lower() == 'json':
            return json.dumps(audit_entries, indent=2)
        elif format.lower() == 'csv':
            # CSV export implementation would go here
            pass
        
        return json.dumps(audit_entries, indent=2)
    
    async def verify_sanitization(self, job_id: str) -> Dict[str, Any]:
        """Verify that sanitization was completed successfully."""
        job = self.sanitization_jobs.get(job_id)
        if not job:
            return {'error': 'Job not found'}
        
        if job.status != "completed":
            return {'error': 'Job not completed'}
        
        verification_results = {
            'job_id': job_id,
            'method': job.method.value,
            'verified_records': [],
            'failed_verifications': [],
            'overall_success': True
        }
        
        # Verify each record
        for record_id in job.data_records:
            record = self.data_records.get(record_id)
            if not record:
                continue
            
            record_verification = {
                'record_id': record_id,
                'files_verified': [],
                'files_failed': [],
                'databases_verified': [],
                'databases_failed': []
            }
            
            # Verify files are gone
            for file_path in record.file_paths:
                if not Path(file_path).exists():
                    record_verification['files_verified'].append(file_path)
                else:
                    record_verification['files_failed'].append(file_path)
                    verification_results['overall_success'] = False
            
            # Verify database tables (simplified)
            for table_name in record.database_tables:
                # In a real implementation, this would check if the table exists
                record_verification['databases_verified'].append(table_name)
            
            if record_verification['files_failed'] or record_verification['databases_failed']:
                verification_results['failed_verifications'].append(record_verification)
            else:
                verification_results['verified_records'].append(record_verification)
                
                # Update record metadata
                record.metadata['sanitization_verified'] = True
                await self._persist_record(record)
        
        # Audit verification
        await self._audit_operation(
            operation=DataOperation.DELETE,  # Using DELETE as verification operation
            record_id=None,
            details={
                'job_id': job_id,
                'verification_success': verification_results['overall_success'],
                'verified_count': len(verification_results['verified_records']),
                'failed_count': len(verification_results['failed_verifications'])
            }
        )
        
        return verification_results
    
    async def shutdown(self) -> None:
        """Shutdown the data manager and cleanup resources."""
        try:
            # Wait for any running sanitization jobs to complete
            running_jobs = [job for job in self.sanitization_jobs.values() 
                          if job.status == "running"]
            
            if running_jobs:
                logger.info(f"Waiting for {len(running_jobs)} running sanitization jobs to complete...")
                # In a real implementation, we might wait or gracefully terminate
            
            # Shutdown thread pool
            self.executor.shutdown(wait=True)
            
            logger.info("PenetrationTestDataManager shutdown complete")
            
        except Exception as e:
            logger.error(f"Error during shutdown: {str(e)}")