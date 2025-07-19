#!/usr/bin/env python3
"""
Secure Session Storage and Persistence

Implements secure, encrypted storage for session data with classification-aware
persistence policies and cross-platform synchronization capabilities.

Classification: UNCLASSIFIED//FOR OFFICIAL USE ONLY
Version: 1.0
Author: Security Compliance Team
Date: 2025-07-18
"""

import json
import sqlite3
import redis
import threading
import logging
import base64
import hashlib
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Set, Tuple, Union
from uuid import UUID, uuid4
from enum import Enum
from dataclasses import dataclass, field, asdict
from pathlib import Path
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import pickle

# Import session management components
from .session_manager import Session, SessionState, SessionConfiguration, SessionSecurityContext, NetworkDomain
from .classification_policies import ClassificationLevel

logger = logging.getLogger(__name__)


class StorageBackend(Enum):
    """Storage backend types."""
    MEMORY = "MEMORY"
    SQLITE = "SQLITE"
    REDIS = "REDIS"
    POSTGRESQL = "POSTGRESQL"
    ENCRYPTED_FILE = "ENCRYPTED_FILE"


class PersistencePolicy(Enum):
    """Session persistence policies."""
    NEVER = "NEVER"                    # Never persist sessions
    TEMPORARY = "TEMPORARY"            # Persist only during application lifetime
    PERSISTENT = "PERSISTENT"          # Persist across restarts
    CROSS_PLATFORM = "CROSS_PLATFORM"  # Synchronize across platforms


@dataclass
class StorageConfiguration:
    """Storage configuration parameters."""
    backend: StorageBackend
    connection_string: str
    encryption_enabled: bool = True
    compression_enabled: bool = True
    persistence_policy: PersistencePolicy = PersistencePolicy.PERSISTENT
    classification_aware: bool = True
    sync_enabled: bool = False
    backup_enabled: bool = True
    retention_days: int = 30
    max_storage_size: int = 1_000_000_000  # 1GB
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class StorageRecord:
    """Storage record for session data."""
    record_id: str
    session_id: str
    user_id: str
    classification_level: str
    network_domain: str
    encrypted_data: str
    checksum: str
    created_at: datetime
    updated_at: datetime
    expires_at: Optional[datetime] = None
    access_count: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)


class SessionEncoder:
    """Session data encoder with encryption and compression."""
    
    def __init__(self, encryption_key: bytes = None):
        """Initialize session encoder.
        
        Args:
            encryption_key: Encryption key for session data
        """
        if encryption_key:
            self.encryption_key = encryption_key
        else:
            self.encryption_key = Fernet.generate_key()
        
        self.fernet = Fernet(self.encryption_key)
        
    def encode_session(self, session: Session, compression: bool = True) -> Tuple[str, str]:
        """Encode session data with encryption and compression.
        
        Args:
            session: Session to encode
            compression: Whether to compress data
            
        Returns:
            Tuple of (encrypted_data, checksum)
        """
        try:
            # Convert session to dictionary, handling non-serializable objects
            session_dict = self._session_to_dict(session)
            
            # Serialize to JSON
            json_data = json.dumps(session_dict, default=str)
            data_bytes = json_data.encode('utf-8')
            
            # Compress if enabled
            if compression:
                import zlib
                data_bytes = zlib.compress(data_bytes)
            
            # Encrypt
            encrypted_data = self.fernet.encrypt(data_bytes)
            encoded_data = base64.b64encode(encrypted_data).decode('utf-8')
            
            # Generate checksum
            checksum = hashlib.sha256(data_bytes).hexdigest()
            
            return encoded_data, checksum
            
        except Exception as e:
            logger.error(f"Session encoding failed: {e}")
            raise
    
    def decode_session(self, encrypted_data: str, checksum: str, compression: bool = True) -> Session:
        """Decode session data from encrypted storage.
        
        Args:
            encrypted_data: Encrypted session data
            checksum: Data checksum for integrity verification
            compression: Whether data is compressed
            
        Returns:
            Decoded session object
        """
        try:
            # Decode and decrypt
            encrypted_bytes = base64.b64decode(encrypted_data.encode('utf-8'))
            decrypted_data = self.fernet.decrypt(encrypted_bytes)
            
            # Decompress if enabled
            if compression:
                import zlib
                decrypted_data = zlib.decompress(decrypted_data)
            
            # Verify checksum
            actual_checksum = hashlib.sha256(decrypted_data).hexdigest()
            if actual_checksum != checksum:
                raise ValueError("Session data integrity check failed")
            
            # Deserialize
            json_data = decrypted_data.decode('utf-8')
            session_dict = json.loads(json_data)
            
            # Convert back to session object
            session = self._dict_to_session(session_dict)
            
            return session
            
        except Exception as e:
            logger.error(f"Session decoding failed: {e}")
            raise
    
    def _session_to_dict(self, session: Session) -> Dict[str, Any]:
        """Convert session to dictionary."""
        # Convert session to dict, handling special types
        session_dict = asdict(session)
        
        # Handle datetime objects
        for key, value in session_dict.items():
            if isinstance(value, datetime):
                session_dict[key] = value.isoformat()
            elif isinstance(value, UUID):
                session_dict[key] = str(value)
            elif isinstance(value, Enum):
                session_dict[key] = value.value
        
        # Handle nested objects
        if 'security_context' in session_dict:
            ctx = session_dict['security_context']
            if 'user_id' in ctx and isinstance(ctx['user_id'], UUID):
                ctx['user_id'] = str(ctx['user_id'])
            if 'network_domain' in ctx and hasattr(ctx['network_domain'], 'value'):
                ctx['network_domain'] = ctx['network_domain'].value
        
        return session_dict
    
    def _dict_to_session(self, session_dict: Dict[str, Any]) -> Session:
        """Convert dictionary to session object."""
        # Handle datetime conversions
        datetime_fields = ['created_at', 'last_accessed', 'expires_at', 'warning_at']
        for field in datetime_fields:
            if field in session_dict and isinstance(session_dict[field], str):
                session_dict[field] = datetime.fromisoformat(session_dict[field])
        
        # Handle UUID conversion
        if 'user_id' in session_dict and isinstance(session_dict['user_id'], str):
            session_dict['user_id'] = UUID(session_dict['user_id'])
        
        # Handle enum conversions
        if 'state' in session_dict and isinstance(session_dict['state'], str):
            session_dict['state'] = SessionState(session_dict['state'])
        
        # Handle security context
        if 'security_context' in session_dict:
            ctx = session_dict['security_context']
            if 'user_id' in ctx and isinstance(ctx['user_id'], str):
                ctx['user_id'] = UUID(ctx['user_id'])
            if 'network_domain' in ctx and isinstance(ctx['network_domain'], str):
                ctx['network_domain'] = NetworkDomain(ctx['network_domain'])
            
            # Convert to SessionSecurityContext object
            session_dict['security_context'] = SessionSecurityContext(**ctx)
        
        # Handle configuration
        if 'configuration' in session_dict:
            config = session_dict['configuration']
            session_dict['configuration'] = SessionConfiguration(**config)
        
        return Session(**session_dict)


class SQLiteStorageBackend:
    """SQLite-based session storage backend."""
    
    def __init__(self, db_path: str, encryption_key: bytes = None):
        """Initialize SQLite storage backend.
        
        Args:
            db_path: Path to SQLite database file
            encryption_key: Encryption key for session data
        """
        self.db_path = Path(db_path)
        self.encoder = SessionEncoder(encryption_key)
        self._connection_pool = {}
        self._lock = threading.Lock()
        
        # Create database and tables
        self._initialize_database()
        
        logger.info(f"SQLiteStorageBackend initialized: {db_path}")
    
    def _initialize_database(self):
        """Initialize database schema."""
        with self._get_connection() as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS sessions (
                    record_id TEXT PRIMARY KEY,
                    session_id TEXT UNIQUE NOT NULL,
                    user_id TEXT NOT NULL,
                    classification_level TEXT NOT NULL,
                    network_domain TEXT NOT NULL,
                    encrypted_data TEXT NOT NULL,
                    checksum TEXT NOT NULL,
                    created_at TIMESTAMP NOT NULL,
                    updated_at TIMESTAMP NOT NULL,
                    expires_at TIMESTAMP,
                    access_count INTEGER DEFAULT 0,
                    metadata TEXT
                )
            ''')
            
            conn.execute('''
                CREATE INDEX IF NOT EXISTS idx_sessions_session_id ON sessions(session_id)
            ''')
            
            conn.execute('''
                CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id)
            ''')
            
            conn.execute('''
                CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at)
            ''')
            
            conn.commit()
    
    def _get_connection(self) -> sqlite3.Connection:
        """Get database connection."""
        thread_id = threading.get_ident()
        
        with self._lock:
            if thread_id not in self._connection_pool:
                conn = sqlite3.connect(
                    str(self.db_path),
                    detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES
                )
                conn.row_factory = sqlite3.Row
                self._connection_pool[thread_id] = conn
            
            return self._connection_pool[thread_id]
    
    def store_session(self, session: Session) -> bool:
        """Store session in database.
        
        Args:
            session: Session to store
            
        Returns:
            True if successful
        """
        try:
            # Encode session
            encrypted_data, checksum = self.encoder.encode_session(session)
            
            # Create storage record
            record = StorageRecord(
                record_id=str(uuid4()),
                session_id=session.session_id,
                user_id=str(session.user_id),
                classification_level=session.security_context.classification_level,
                network_domain=session.security_context.network_domain.value,
                encrypted_data=encrypted_data,
                checksum=checksum,
                created_at=datetime.now(timezone.utc),
                updated_at=datetime.now(timezone.utc),
                expires_at=session.expires_at
            )
            
            # Store in database
            with self._get_connection() as conn:
                conn.execute('''
                    INSERT OR REPLACE INTO sessions (
                        record_id, session_id, user_id, classification_level,
                        network_domain, encrypted_data, checksum, created_at,
                        updated_at, expires_at, access_count, metadata
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    record.record_id, record.session_id, record.user_id,
                    record.classification_level, record.network_domain,
                    record.encrypted_data, record.checksum, record.created_at,
                    record.updated_at, record.expires_at, record.access_count,
                    json.dumps(record.metadata)
                ))
                conn.commit()
            
            logger.debug(f"Session stored: {session.session_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to store session {session.session_id}: {e}")
            return False
    
    def load_session(self, session_id: str) -> Optional[Session]:
        """Load session from database.
        
        Args:
            session_id: Session identifier
            
        Returns:
            Session if found, None otherwise
        """
        try:
            with self._get_connection() as conn:
                cursor = conn.execute('''
                    SELECT * FROM sessions WHERE session_id = ?
                ''', (session_id,))
                
                row = cursor.fetchone()
                if not row:
                    return None
                
                # Update access count
                conn.execute('''
                    UPDATE sessions SET access_count = access_count + 1
                    WHERE session_id = ?
                ''', (session_id,))
                conn.commit()
                
                # Decode session
                session = self.encoder.decode_session(
                    row['encrypted_data'],
                    row['checksum']
                )
                
                logger.debug(f"Session loaded: {session_id}")
                return session
            
        except Exception as e:
            logger.error(f"Failed to load session {session_id}: {e}")
            return None
    
    def delete_session(self, session_id: str) -> bool:
        """Delete session from database.
        
        Args:
            session_id: Session identifier
            
        Returns:
            True if successful
        """
        try:
            with self._get_connection() as conn:
                cursor = conn.execute('''
                    DELETE FROM sessions WHERE session_id = ?
                ''', (session_id,))
                conn.commit()
                
                deleted = cursor.rowcount > 0
                if deleted:
                    logger.debug(f"Session deleted: {session_id}")
                
                return deleted
            
        except Exception as e:
            logger.error(f"Failed to delete session {session_id}: {e}")
            return False
    
    def list_user_sessions(self, user_id: UUID) -> List[str]:
        """List session IDs for a user.
        
        Args:
            user_id: User identifier
            
        Returns:
            List of session IDs
        """
        try:
            with self._get_connection() as conn:
                cursor = conn.execute('''
                    SELECT session_id FROM sessions WHERE user_id = ?
                    AND (expires_at IS NULL OR expires_at > ?)
                ''', (str(user_id), datetime.now(timezone.utc)))
                
                return [row['session_id'] for row in cursor.fetchall()]
            
        except Exception as e:
            logger.error(f"Failed to list sessions for user {user_id}: {e}")
            return []
    
    def cleanup_expired_sessions(self) -> int:
        """Clean up expired sessions.
        
        Returns:
            Number of sessions cleaned up
        """
        try:
            with self._get_connection() as conn:
                cursor = conn.execute('''
                    DELETE FROM sessions WHERE expires_at < ?
                ''', (datetime.now(timezone.utc),))
                conn.commit()
                
                cleaned_count = cursor.rowcount
                if cleaned_count > 0:
                    logger.info(f"Cleaned up {cleaned_count} expired sessions")
                
                return cleaned_count
            
        except Exception as e:
            logger.error(f"Failed to cleanup expired sessions: {e}")
            return 0
    
    def get_storage_statistics(self) -> Dict[str, Any]:
        """Get storage statistics.
        
        Returns:
            Storage statistics
        """
        try:
            with self._get_connection() as conn:
                # Total sessions
                cursor = conn.execute('SELECT COUNT(*) as count FROM sessions')
                total_sessions = cursor.fetchone()['count']
                
                # Active sessions
                cursor = conn.execute('''
                    SELECT COUNT(*) as count FROM sessions 
                    WHERE expires_at IS NULL OR expires_at > ?
                ''', (datetime.now(timezone.utc),))
                active_sessions = cursor.fetchone()['count']
                
                # Sessions by classification
                cursor = conn.execute('''
                    SELECT classification_level, COUNT(*) as count 
                    FROM sessions GROUP BY classification_level
                ''')
                by_classification = {row['classification_level']: row['count'] for row in cursor.fetchall()}
                
                # Database size
                db_size = self.db_path.stat().st_size if self.db_path.exists() else 0
                
                return {
                    'total_sessions': total_sessions,
                    'active_sessions': active_sessions,
                    'sessions_by_classification': by_classification,
                    'database_size_bytes': db_size,
                    'storage_backend': 'SQLite'
                }
            
        except Exception as e:
            logger.error(f"Failed to get storage statistics: {e}")
            return {}


class RedisStorageBackend:
    """Redis-based session storage backend."""
    
    def __init__(self, redis_url: str, encryption_key: bytes = None):
        """Initialize Redis storage backend.
        
        Args:
            redis_url: Redis connection URL
            encryption_key: Encryption key for session data
        """
        self.redis_client = redis.from_url(redis_url)
        self.encoder = SessionEncoder(encryption_key)
        self.key_prefix = "session:"
        
        # Test connection
        try:
            self.redis_client.ping()
            logger.info(f"RedisStorageBackend initialized: {redis_url}")
        except Exception as e:
            logger.error(f"Redis connection failed: {e}")
            raise
    
    def store_session(self, session: Session) -> bool:
        """Store session in Redis.
        
        Args:
            session: Session to store
            
        Returns:
            True if successful
        """
        try:
            # Encode session
            encrypted_data, checksum = self.encoder.encode_session(session)
            
            # Create storage record
            record_data = {
                'session_id': session.session_id,
                'user_id': str(session.user_id),
                'classification_level': session.security_context.classification_level,
                'network_domain': session.security_context.network_domain.value,
                'encrypted_data': encrypted_data,
                'checksum': checksum,
                'created_at': session.created_at.isoformat(),
                'updated_at': datetime.now(timezone.utc).isoformat(),
                'expires_at': session.expires_at.isoformat() if session.expires_at else None
            }
            
            # Store in Redis
            key = f"{self.key_prefix}{session.session_id}"
            self.redis_client.hset(key, mapping=record_data)
            
            # Set expiration
            if session.expires_at:
                self.redis_client.expireat(key, session.expires_at)
            
            # Add to user session set
            user_key = f"user_sessions:{session.user_id}"
            self.redis_client.sadd(user_key, session.session_id)
            
            logger.debug(f"Session stored in Redis: {session.session_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to store session {session.session_id} in Redis: {e}")
            return False
    
    def load_session(self, session_id: str) -> Optional[Session]:
        """Load session from Redis.
        
        Args:
            session_id: Session identifier
            
        Returns:
            Session if found, None otherwise
        """
        try:
            key = f"{self.key_prefix}{session_id}"
            record_data = self.redis_client.hgetall(key)
            
            if not record_data:
                return None
            
            # Increment access count
            self.redis_client.hincrby(key, 'access_count', 1)
            
            # Decode session
            encrypted_data = record_data[b'encrypted_data'].decode()
            checksum = record_data[b'checksum'].decode()
            
            session = self.encoder.decode_session(encrypted_data, checksum)
            
            logger.debug(f"Session loaded from Redis: {session_id}")
            return session
            
        except Exception as e:
            logger.error(f"Failed to load session {session_id} from Redis: {e}")
            return None
    
    def delete_session(self, session_id: str) -> bool:
        """Delete session from Redis.
        
        Args:
            session_id: Session identifier
            
        Returns:
            True if successful
        """
        try:
            key = f"{self.key_prefix}{session_id}"
            
            # Get user ID before deletion
            user_id = self.redis_client.hget(key, 'user_id')
            
            # Delete session
            deleted = self.redis_client.delete(key) > 0
            
            # Remove from user session set
            if user_id and deleted:
                user_key = f"user_sessions:{user_id.decode()}"
                self.redis_client.srem(user_key, session_id)
            
            if deleted:
                logger.debug(f"Session deleted from Redis: {session_id}")
            
            return deleted
            
        except Exception as e:
            logger.error(f"Failed to delete session {session_id} from Redis: {e}")
            return False
    
    def list_user_sessions(self, user_id: UUID) -> List[str]:
        """List session IDs for a user.
        
        Args:
            user_id: User identifier
            
        Returns:
            List of session IDs
        """
        try:
            user_key = f"user_sessions:{user_id}"
            session_ids = self.redis_client.smembers(user_key)
            return [sid.decode() for sid in session_ids]
            
        except Exception as e:
            logger.error(f"Failed to list sessions for user {user_id} from Redis: {e}")
            return []
    
    def cleanup_expired_sessions(self) -> int:
        """Clean up expired sessions from Redis.
        
        Returns:
            Number of sessions cleaned up (Redis handles expiration automatically)
        """
        # Redis handles expiration automatically, but we can clean user session sets
        try:
            cleaned_count = 0
            
            # Get all user session sets
            user_keys = self.redis_client.keys("user_sessions:*")
            
            for user_key in user_keys:
                session_ids = self.redis_client.smembers(user_key)
                
                for session_id in session_ids:
                    session_key = f"{self.key_prefix}{session_id.decode()}"
                    if not self.redis_client.exists(session_key):
                        # Session expired, remove from user set
                        self.redis_client.srem(user_key, session_id)
                        cleaned_count += 1
            
            if cleaned_count > 0:
                logger.info(f"Cleaned up {cleaned_count} expired session references from Redis")
            
            return cleaned_count
            
        except Exception as e:
            logger.error(f"Failed to cleanup expired sessions from Redis: {e}")
            return 0


class SessionStorageManager:
    """
    Comprehensive session storage manager with multiple backend support,
    classification-aware policies, and cross-platform synchronization.
    """
    
    def __init__(self, 
                 primary_config: StorageConfiguration,
                 backup_config: StorageConfiguration = None,
                 sync_config: StorageConfiguration = None):
        """Initialize session storage manager.
        
        Args:
            primary_config: Primary storage configuration
            backup_config: Optional backup storage configuration
            sync_config: Optional sync storage configuration
        """
        self.primary_config = primary_config
        self.backup_config = backup_config
        self.sync_config = sync_config
        
        # Initialize storage backends
        self.primary_backend = self._create_backend(primary_config)
        self.backup_backend = self._create_backend(backup_config) if backup_config else None
        self.sync_backend = self._create_backend(sync_config) if sync_config else None
        
        # Classification policies
        self.classification_policies = self._initialize_classification_policies()
        
        # Statistics
        self.storage_stats = {
            'sessions_stored': 0,
            'sessions_loaded': 0,
            'sessions_deleted': 0,
            'storage_errors': 0
        }
        
        self._lock = threading.Lock()
        
        logger.info("SessionStorageManager initialized")
    
    def store_session(self, session: Session) -> bool:
        """Store session with classification-aware policies.
        
        Args:
            session: Session to store
            
        Returns:
            True if successful
        """
        try:
            # Check persistence policy
            classification_level = session.security_context.classification_level
            policy = self.classification_policies.get(classification_level, PersistencePolicy.TEMPORARY)
            
            if policy == PersistencePolicy.NEVER:
                logger.debug(f"Session {session.session_id} not stored due to policy")
                return True
            
            # Store in primary backend
            success = self.primary_backend.store_session(session)
            
            if success:
                with self._lock:
                    self.storage_stats['sessions_stored'] += 1
                
                # Store in backup backend if configured and policy allows
                if (self.backup_backend and 
                    policy in [PersistencePolicy.PERSISTENT, PersistencePolicy.CROSS_PLATFORM]):
                    try:
                        self.backup_backend.store_session(session)
                    except Exception as e:
                        logger.warning(f"Backup storage failed: {e}")
                
                # Store in sync backend if configured
                if (self.sync_backend and 
                    policy == PersistencePolicy.CROSS_PLATFORM and
                    self.primary_config.sync_enabled):
                    try:
                        self.sync_backend.store_session(session)
                    except Exception as e:
                        logger.warning(f"Sync storage failed: {e}")
                
                logger.debug(f"Session stored: {session.session_id}")
                
            else:
                with self._lock:
                    self.storage_stats['storage_errors'] += 1
            
            return success
            
        except Exception as e:
            logger.error(f"Failed to store session {session.session_id}: {e}")
            with self._lock:
                self.storage_stats['storage_errors'] += 1
            return False
    
    def load_session(self, session_id: str) -> Optional[Session]:
        """Load session from storage.
        
        Args:
            session_id: Session identifier
            
        Returns:
            Session if found, None otherwise
        """
        try:
            # Try primary backend first
            session = self.primary_backend.load_session(session_id)
            
            if session:
                with self._lock:
                    self.storage_stats['sessions_loaded'] += 1
                logger.debug(f"Session loaded from primary: {session_id}")
                return session
            
            # Try backup backend
            if self.backup_backend:
                session = self.backup_backend.load_session(session_id)
                if session:
                    with self._lock:
                        self.storage_stats['sessions_loaded'] += 1
                    logger.debug(f"Session loaded from backup: {session_id}")
                    
                    # Restore to primary backend
                    try:
                        self.primary_backend.store_session(session)
                    except Exception as e:
                        logger.warning(f"Failed to restore session to primary: {e}")
                    
                    return session
            
            # Try sync backend
            if self.sync_backend:
                session = self.sync_backend.load_session(session_id)
                if session:
                    with self._lock:
                        self.storage_stats['sessions_loaded'] += 1
                    logger.debug(f"Session loaded from sync: {session_id}")
                    
                    # Restore to primary backend
                    try:
                        self.primary_backend.store_session(session)
                    except Exception as e:
                        logger.warning(f"Failed to restore session to primary: {e}")
                    
                    return session
            
            return None
            
        except Exception as e:
            logger.error(f"Failed to load session {session_id}: {e}")
            with self._lock:
                self.storage_stats['storage_errors'] += 1
            return None
    
    def delete_session(self, session_id: str) -> bool:
        """Delete session from all storage backends.
        
        Args:
            session_id: Session identifier
            
        Returns:
            True if successful in at least one backend
        """
        success = False
        
        try:
            # Delete from primary backend
            if self.primary_backend.delete_session(session_id):
                success = True
                with self._lock:
                    self.storage_stats['sessions_deleted'] += 1
            
            # Delete from backup backend
            if self.backup_backend:
                try:
                    self.backup_backend.delete_session(session_id)
                except Exception as e:
                    logger.warning(f"Backup deletion failed: {e}")
            
            # Delete from sync backend
            if self.sync_backend:
                try:
                    self.sync_backend.delete_session(session_id)
                except Exception as e:
                    logger.warning(f"Sync deletion failed: {e}")
            
            if success:
                logger.debug(f"Session deleted: {session_id}")
            
            return success
            
        except Exception as e:
            logger.error(f"Failed to delete session {session_id}: {e}")
            with self._lock:
                self.storage_stats['storage_errors'] += 1
            return False
    
    def list_user_sessions(self, user_id: UUID) -> List[str]:
        """List session IDs for a user.
        
        Args:
            user_id: User identifier
            
        Returns:
            List of session IDs
        """
        try:
            # Get sessions from primary backend
            session_ids = set(self.primary_backend.list_user_sessions(user_id))
            
            # Merge with backup backend
            if self.backup_backend:
                try:
                    backup_sessions = self.backup_backend.list_user_sessions(user_id)
                    session_ids.update(backup_sessions)
                except Exception as e:
                    logger.warning(f"Failed to list backup sessions: {e}")
            
            # Merge with sync backend
            if self.sync_backend:
                try:
                    sync_sessions = self.sync_backend.list_user_sessions(user_id)
                    session_ids.update(sync_sessions)
                except Exception as e:
                    logger.warning(f"Failed to list sync sessions: {e}")
            
            return list(session_ids)
            
        except Exception as e:
            logger.error(f"Failed to list sessions for user {user_id}: {e}")
            return []
    
    def cleanup_expired_sessions(self) -> int:
        """Clean up expired sessions from all backends.
        
        Returns:
            Total number of sessions cleaned up
        """
        total_cleaned = 0
        
        try:
            # Cleanup primary backend
            cleaned = self.primary_backend.cleanup_expired_sessions()
            total_cleaned += cleaned
            
            # Cleanup backup backend
            if self.backup_backend:
                try:
                    cleaned = self.backup_backend.cleanup_expired_sessions()
                    total_cleaned += cleaned
                except Exception as e:
                    logger.warning(f"Backup cleanup failed: {e}")
            
            # Cleanup sync backend
            if self.sync_backend:
                try:
                    cleaned = self.sync_backend.cleanup_expired_sessions()
                    total_cleaned += cleaned
                except Exception as e:
                    logger.warning(f"Sync cleanup failed: {e}")
            
            if total_cleaned > 0:
                logger.info(f"Total sessions cleaned up: {total_cleaned}")
            
            return total_cleaned
            
        except Exception as e:
            logger.error(f"Session cleanup failed: {e}")
            return 0
    
    def synchronize_sessions(self, user_id: UUID = None) -> bool:
        """Synchronize sessions across backends.
        
        Args:
            user_id: Optional user ID to sync specific user sessions
            
        Returns:
            True if successful
        """
        if not self.sync_backend or not self.primary_config.sync_enabled:
            return False
        
        try:
            # Implementation would synchronize sessions between backends
            # This is a simplified version
            logger.info(f"Synchronizing sessions for user: {user_id or 'all'}")
            return True
            
        except Exception as e:
            logger.error(f"Session synchronization failed: {e}")
            return False
    
    def _create_backend(self, config: StorageConfiguration):
        """Create storage backend based on configuration."""
        if config.backend == StorageBackend.SQLITE:
            return SQLiteStorageBackend(config.connection_string)
        elif config.backend == StorageBackend.REDIS:
            return RedisStorageBackend(config.connection_string)
        else:
            raise ValueError(f"Unsupported storage backend: {config.backend}")
    
    def _initialize_classification_policies(self) -> Dict[str, PersistencePolicy]:
        """Initialize classification-specific persistence policies."""
        return {
            'U': PersistencePolicy.PERSISTENT,
            'C': PersistencePolicy.PERSISTENT,
            'S': PersistencePolicy.TEMPORARY,
            'TS': PersistencePolicy.NEVER
        }
    
    def get_storage_statistics(self) -> Dict[str, Any]:
        """Get comprehensive storage statistics.
        
        Returns:
            Storage statistics
        """
        with self._lock:
            stats = {
                'session_storage_stats': self.storage_stats.copy(),
                'primary_backend_stats': {},
                'backup_backend_stats': {},
                'sync_backend_stats': {}
            }
        
        # Get backend-specific statistics
        try:
            if hasattr(self.primary_backend, 'get_storage_statistics'):
                stats['primary_backend_stats'] = self.primary_backend.get_storage_statistics()
        except Exception as e:
            logger.warning(f"Failed to get primary backend stats: {e}")
        
        try:
            if self.backup_backend and hasattr(self.backup_backend, 'get_storage_statistics'):
                stats['backup_backend_stats'] = self.backup_backend.get_storage_statistics()
        except Exception as e:
            logger.warning(f"Failed to get backup backend stats: {e}")
        
        try:
            if self.sync_backend and hasattr(self.sync_backend, 'get_storage_statistics'):
                stats['sync_backend_stats'] = self.sync_backend.get_storage_statistics()
        except Exception as e:
            logger.warning(f"Failed to get sync backend stats: {e}")
        
        return stats


# Factory functions
def create_sqlite_storage_manager(db_path: str, encryption_key: bytes = None) -> SessionStorageManager:
    """Create SQLite-based session storage manager."""
    config = StorageConfiguration(
        backend=StorageBackend.SQLITE,
        connection_string=db_path,
        encryption_enabled=True,
        persistence_policy=PersistencePolicy.PERSISTENT
    )
    return SessionStorageManager(config)


def create_redis_storage_manager(redis_url: str, encryption_key: bytes = None) -> SessionStorageManager:
    """Create Redis-based session storage manager."""
    config = StorageConfiguration(
        backend=StorageBackend.REDIS,
        connection_string=redis_url,
        encryption_enabled=True,
        persistence_policy=PersistencePolicy.PERSISTENT
    )
    return SessionStorageManager(config)


def create_hybrid_storage_manager(
    sqlite_path: str,
    redis_url: str,
    encryption_key: bytes = None
) -> SessionStorageManager:
    """Create hybrid storage manager with SQLite primary and Redis backup."""
    primary_config = StorageConfiguration(
        backend=StorageBackend.SQLITE,
        connection_string=sqlite_path,
        encryption_enabled=True,
        persistence_policy=PersistencePolicy.PERSISTENT
    )
    
    backup_config = StorageConfiguration(
        backend=StorageBackend.REDIS,
        connection_string=redis_url,
        encryption_enabled=True,
        persistence_policy=PersistencePolicy.TEMPORARY
    )
    
    return SessionStorageManager(primary_config, backup_config)