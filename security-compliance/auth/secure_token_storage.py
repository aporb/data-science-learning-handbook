"""
Secure Token Storage for OAuth 2.0 Tokens
Implements AES-256 encrypted storage with DoD-compliant security features.
"""

import os
import json
import logging
import secrets
import threading
from typing import Dict, Optional, List, Any, Union
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
import sqlite3
import hashlib
import base64

# Import encryption framework
from ..encryption.encryption_manager import EncryptionManager, EncryptionAlgorithm, EncryptionMode
from ..encryption.key_manager import KeyManager, KeyType

# Import OAuth components
from .oauth_client import TokenResponse, Platform

# Import audit logging
from .security_managers import AuditLogger, AuditEvent, AuditEventType

logger = logging.getLogger(__name__)


class TokenStorageType(Enum):
    """Token storage backend types."""
    FILE_SYSTEM = "filesystem"
    DATABASE = "database"
    MEMORY = "memory"


class TokenStorageError(Exception):
    """Token storage specific errors."""
    pass


@dataclass
class StoredToken:
    """Encrypted token storage record."""
    token_id: str
    platform: str
    user_id: str
    encrypted_token_data: str
    metadata: Dict[str, Any]
    created_at: datetime
    expires_at: datetime
    last_accessed: Optional[datetime] = None
    access_count: int = 0
    encryption_key_id: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for storage."""
        data = asdict(self)
        # Convert datetime objects to ISO strings
        data['created_at'] = self.created_at.isoformat()
        data['expires_at'] = self.expires_at.isoformat()
        if self.last_accessed:
            data['last_accessed'] = self.last_accessed.isoformat()
        return data
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'StoredToken':
        """Create from dictionary."""
        # Convert ISO strings to datetime objects
        data['created_at'] = datetime.fromisoformat(data['created_at'])
        data['expires_at'] = datetime.fromisoformat(data['expires_at'])
        if data.get('last_accessed'):
            data['last_accessed'] = datetime.fromisoformat(data['last_accessed'])
        return cls(**data)


class SecureTokenStorage:
    """
    Secure token storage with AES-256 encryption.
    
    Features:
    - AES-256-GCM authenticated encryption
    - Key rotation support
    - Automatic token expiration and cleanup
    - Access audit logging
    - Platform-specific storage isolation
    - Thread-safe operations
    """
    
    def __init__(self, 
                 storage_type: TokenStorageType = TokenStorageType.DATABASE,
                 storage_path: Optional[str] = None,
                 encryption_key_id: Optional[str] = None,
                 enable_cleanup: bool = True,
                 cleanup_interval: int = 3600):
        """
        Initialize secure token storage.
        
        Args:
            storage_type: Backend storage type
            storage_path: Path for file/database storage
            encryption_key_id: Specific encryption key ID to use
            enable_cleanup: Enable automatic token cleanup
            cleanup_interval: Cleanup interval in seconds
        """
        self.storage_type = storage_type
        self.storage_path = storage_path or self._get_default_storage_path()
        self.enable_cleanup = enable_cleanup
        self.cleanup_interval = cleanup_interval
        
        # Initialize encryption
        self.key_manager = KeyManager()
        self.encryption_manager = EncryptionManager(key_manager=self.key_manager)
        
        # Use provided key or create new one for token encryption
        if encryption_key_id:
            self.encryption_key_id = encryption_key_id
        else:
            self.encryption_key_id = self._ensure_token_encryption_key()
        
        # Thread safety
        self._lock = threading.RLock()
        self._cleanup_thread = None
        
        # Initialize storage backend
        self._initialize_storage()
        
        # Start cleanup thread if enabled
        if self.enable_cleanup:
            self._start_cleanup_thread()
    
    def _get_default_storage_path(self) -> str:
        """Get default storage path based on storage type."""
        home_dir = Path.home()
        app_dir = home_dir / ".dod_oauth_tokens"
        app_dir.mkdir(exist_ok=True, mode=0o700)  # Secure permissions
        
        if self.storage_type == TokenStorageType.DATABASE:
            return str(app_dir / "tokens.db")
        elif self.storage_type == TokenStorageType.FILE_SYSTEM:
            return str(app_dir / "tokens")
        else:
            return str(app_dir)
    
    def _ensure_token_encryption_key(self) -> str:
        """Ensure token encryption key exists or create new one."""
        try:
            # Try to get existing token encryption key
            key_id = "oauth_token_encryption_key"
            if self.key_manager.key_exists(key_id):
                return key_id
            
            # Create new key for token encryption
            self.key_manager.create_key(
                key_id=key_id,
                key_type=KeyType.SYMMETRIC,
                algorithm="AES-256",
                usage=["encrypt", "decrypt"],
                metadata={
                    "purpose": "oauth_token_encryption",
                    "created_at": datetime.now(timezone.utc).isoformat()
                }
            )
            
            logger.info(f"Created new token encryption key: {key_id}")
            return key_id
            
        except Exception as e:
            logger.error(f"Failed to ensure token encryption key: {e}")
            raise TokenStorageError(f"Key management error: {e}")
    
    def _initialize_storage(self):
        """Initialize the storage backend."""
        if self.storage_type == TokenStorageType.DATABASE:
            self._initialize_database()
        elif self.storage_type == TokenStorageType.FILE_SYSTEM:
            self._initialize_filesystem()
        elif self.storage_type == TokenStorageType.MEMORY:
            self._tokens = {}
    
    def _initialize_database(self):
        """Initialize SQLite database for token storage."""
        try:
            # Ensure directory exists
            Path(self.storage_path).parent.mkdir(exist_ok=True, mode=0o700)
            
            # Create database with secure permissions
            conn = sqlite3.connect(self.storage_path)
            
            # Set secure database settings
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=FULL")
            conn.execute("PRAGMA temp_store=MEMORY")
            conn.execute("PRAGMA secure_delete=ON")
            
            # Create tokens table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS tokens (
                    token_id TEXT PRIMARY KEY,
                    platform TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    encrypted_token_data TEXT NOT NULL,
                    metadata TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    last_accessed TEXT,
                    access_count INTEGER DEFAULT 0,
                    encryption_key_id TEXT NOT NULL,
                    UNIQUE(platform, user_id)
                )
            """)
            
            # Create indexes for efficient queries
            conn.execute("CREATE INDEX IF NOT EXISTS idx_tokens_platform_user ON tokens(platform, user_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_tokens_expires_at ON tokens(expires_at)")
            
            conn.commit()
            conn.close()
            
            # Set secure file permissions
            os.chmod(self.storage_path, 0o600)
            
            logger.info(f"Database storage initialized: {self.storage_path}")
            
        except Exception as e:
            logger.error(f"Failed to initialize database storage: {e}")
            raise TokenStorageError(f"Database initialization error: {e}")
    
    def _initialize_filesystem(self):
        """Initialize filesystem storage."""
        try:
            storage_dir = Path(self.storage_path)
            storage_dir.mkdir(exist_ok=True, mode=0o700)
            logger.info(f"Filesystem storage initialized: {self.storage_path}")
        except Exception as e:
            logger.error(f"Failed to initialize filesystem storage: {e}")
            raise TokenStorageError(f"Filesystem initialization error: {e}")
    
    def store_token(self, 
                   platform: Platform, 
                   user_id: str, 
                   token: TokenResponse,
                   metadata: Optional[Dict[str, Any]] = None) -> str:
        """
        Store encrypted token securely.
        
        Args:
            platform: OAuth platform
            user_id: User identifier
            token: Token response to store
            metadata: Additional metadata
            
        Returns:
            Token ID for retrieval
            
        Raises:
            TokenStorageError: If storage operation fails
        """
        with self._lock:
            try:
                # Generate unique token ID
                token_id = self._generate_token_id(platform, user_id)
                
                # Prepare token data for encryption
                token_data = {
                    "access_token": token.access_token,
                    "token_type": token.token_type,
                    "expires_in": token.expires_in,
                    "refresh_token": token.refresh_token,
                    "scope": token.scope,
                    "id_token": token.id_token,
                    "issued_at": token.issued_at.isoformat() if token.issued_at else None
                }
                
                # Encrypt token data
                encrypted_data = self._encrypt_token_data(token_data)
                
                # Create storage record
                stored_token = StoredToken(
                    token_id=token_id,
                    platform=platform.value,
                    user_id=user_id,
                    encrypted_token_data=encrypted_data,
                    metadata=metadata or {},
                    created_at=datetime.now(timezone.utc),
                    expires_at=token.expires_at,
                    encryption_key_id=self.encryption_key_id
                )
                
                # Store in backend
                self._store_token_record(stored_token)
                
                # Log token storage
                AuditLogger.instance().log_event(AuditEvent(
                    event_type=AuditEventType.TOKEN_STORAGE,
                    timestamp=datetime.now(timezone.utc),
                    user_id=user_id,
                    success=True,
                    additional_data={
                        "platform": platform.value,
                        "token_id": token_id,
                        "expires_at": token.expires_at.isoformat()
                    }
                ))
                
                logger.info(f"Token stored successfully: {token_id}")
                return token_id
                
            except Exception as e:
                logger.error(f"Failed to store token: {e}")
                AuditLogger.instance().log_event(AuditEvent(
                    event_type=AuditEventType.TOKEN_STORAGE,
                    timestamp=datetime.now(timezone.utc),
                    user_id=user_id,
                    success=False,
                    error_message=str(e),
                    additional_data={"platform": platform.value}
                ))
                raise TokenStorageError(f"Token storage failed: {e}")
    
    def retrieve_token(self, 
                      platform: Platform, 
                      user_id: str) -> Optional[TokenResponse]:
        """
        Retrieve and decrypt stored token.
        
        Args:
            platform: OAuth platform
            user_id: User identifier
            
        Returns:
            Decrypted token response or None if not found
            
        Raises:
            TokenStorageError: If retrieval operation fails
        """
        with self._lock:
            try:
                # Generate token ID for lookup
                token_id = self._generate_token_id(platform, user_id)
                
                # Retrieve from backend
                stored_token = self._retrieve_token_record(token_id)
                if not stored_token:
                    return None
                
                # Check if token is expired
                if stored_token.expires_at <= datetime.now(timezone.utc):
                    logger.info(f"Token expired, removing: {token_id}")
                    self.delete_token(platform, user_id)
                    return None
                
                # Decrypt token data
                token_data = self._decrypt_token_data(
                    stored_token.encrypted_token_data,
                    stored_token.encryption_key_id
                )
                
                # Update access tracking
                self._update_access_tracking(token_id)
                
                # Create TokenResponse object
                token = TokenResponse(
                    access_token=token_data["access_token"],
                    token_type=token_data["token_type"],
                    expires_in=token_data["expires_in"],
                    refresh_token=token_data.get("refresh_token"),
                    scope=token_data.get("scope"),
                    id_token=token_data.get("id_token"),
                    issued_at=datetime.fromisoformat(token_data["issued_at"]) if token_data.get("issued_at") else None
                )
                
                # Log token retrieval
                AuditLogger.instance().log_event(AuditEvent(
                    event_type=AuditEventType.TOKEN_RETRIEVAL,
                    timestamp=datetime.now(timezone.utc),
                    user_id=user_id,
                    success=True,
                    additional_data={
                        "platform": platform.value,
                        "token_id": token_id
                    }
                ))
                
                logger.debug(f"Token retrieved successfully: {token_id}")
                return token
                
            except Exception as e:
                logger.error(f"Failed to retrieve token: {e}")
                AuditLogger.instance().log_event(AuditEvent(
                    event_type=AuditEventType.TOKEN_RETRIEVAL,
                    timestamp=datetime.now(timezone.utc),
                    user_id=user_id,
                    success=False,
                    error_message=str(e),
                    additional_data={"platform": platform.value}
                ))
                raise TokenStorageError(f"Token retrieval failed: {e}")
    
    def delete_token(self, platform: Platform, user_id: str) -> bool:
        """
        Delete stored token.
        
        Args:
            platform: OAuth platform
            user_id: User identifier
            
        Returns:
            True if token was deleted, False if not found
        """
        with self._lock:
            try:
                token_id = self._generate_token_id(platform, user_id)
                
                if self._delete_token_record(token_id):
                    # Log token deletion
                    AuditLogger.instance().log_event(AuditEvent(
                        event_type=AuditEventType.TOKEN_DELETION,
                        timestamp=datetime.now(timezone.utc),
                        user_id=user_id,
                        success=True,
                        additional_data={
                            "platform": platform.value,
                            "token_id": token_id
                        }
                    ))
                    logger.info(f"Token deleted: {token_id}")
                    return True
                
                return False
                
            except Exception as e:
                logger.error(f"Failed to delete token: {e}")
                raise TokenStorageError(f"Token deletion failed: {e}")
    
    def cleanup_expired_tokens(self) -> int:
        """
        Remove all expired tokens.
        
        Returns:
            Number of tokens cleaned up
        """
        with self._lock:
            try:
                count = self._cleanup_expired_tokens()
                
                if count > 0:
                    AuditLogger.instance().log_event(AuditEvent(
                        event_type=AuditEventType.TOKEN_CLEANUP,
                        timestamp=datetime.now(timezone.utc),
                        user_id="system",
                        success=True,
                        additional_data={"tokens_cleaned": count}
                    ))
                    logger.info(f"Cleaned up {count} expired tokens")
                
                return count
                
            except Exception as e:
                logger.error(f"Token cleanup failed: {e}")
                return 0
    
    def list_tokens(self, platform: Optional[Platform] = None, 
                   user_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        List stored tokens (metadata only, no sensitive data).
        
        Args:
            platform: Filter by platform
            user_id: Filter by user ID
            
        Returns:
            List of token metadata
        """
        with self._lock:
            try:
                return self._list_token_records(platform, user_id)
            except Exception as e:
                logger.error(f"Failed to list tokens: {e}")
                raise TokenStorageError(f"Token listing failed: {e}")
    
    def _generate_token_id(self, platform: Platform, user_id: str) -> str:
        """Generate deterministic token ID."""
        data = f"{platform.value}:{user_id}".encode('utf-8')
        return hashlib.sha256(data).hexdigest()[:32]
    
    def _encrypt_token_data(self, token_data: Dict[str, Any]) -> str:
        """Encrypt token data using AES-256-GCM."""
        try:
            # Serialize token data
            plaintext = json.dumps(token_data).encode('utf-8')
            
            # Encrypt using encryption manager
            encrypted_data = self.encryption_manager.encrypt_data(
                data=plaintext,
                key_id=self.encryption_key_id,
                algorithm=EncryptionAlgorithm.AES_256_GCM,
                mode=EncryptionMode.DATA_AT_REST
            )
            
            # Return base64 encoded for storage
            return base64.b64encode(encrypted_data).decode('utf-8')
            
        except Exception as e:
            logger.error(f"Token encryption failed: {e}")
            raise TokenStorageError(f"Encryption error: {e}")
    
    def _decrypt_token_data(self, encrypted_data: str, key_id: str) -> Dict[str, Any]:
        """Decrypt token data."""
        try:
            # Decode from base64
            encrypted_bytes = base64.b64decode(encrypted_data.encode('utf-8'))
            
            # Decrypt using encryption manager
            decrypted_data = self.encryption_manager.decrypt_data(
                encrypted_data=encrypted_bytes,
                key_id=key_id
            )
            
            # Deserialize token data
            return json.loads(decrypted_data.decode('utf-8'))
            
        except Exception as e:
            logger.error(f"Token decryption failed: {e}")
            raise TokenStorageError(f"Decryption error: {e}")
    
    def _store_token_record(self, stored_token: StoredToken):
        """Store token record in backend."""
        if self.storage_type == TokenStorageType.DATABASE:
            self._store_token_database(stored_token)
        elif self.storage_type == TokenStorageType.FILE_SYSTEM:
            self._store_token_filesystem(stored_token)
        elif self.storage_type == TokenStorageType.MEMORY:
            self._tokens[stored_token.token_id] = stored_token
    
    def _retrieve_token_record(self, token_id: str) -> Optional[StoredToken]:
        """Retrieve token record from backend."""
        if self.storage_type == TokenStorageType.DATABASE:
            return self._retrieve_token_database(token_id)
        elif self.storage_type == TokenStorageType.FILE_SYSTEM:
            return self._retrieve_token_filesystem(token_id)
        elif self.storage_type == TokenStorageType.MEMORY:
            return self._tokens.get(token_id)
        return None
    
    def _delete_token_record(self, token_id: str) -> bool:
        """Delete token record from backend."""
        if self.storage_type == TokenStorageType.DATABASE:
            return self._delete_token_database(token_id)
        elif self.storage_type == TokenStorageType.FILE_SYSTEM:
            return self._delete_token_filesystem(token_id)
        elif self.storage_type == TokenStorageType.MEMORY:
            return self._tokens.pop(token_id, None) is not None
        return False
    
    def _store_token_database(self, stored_token: StoredToken):
        """Store token in SQLite database."""
        conn = sqlite3.connect(self.storage_path)
        try:
            # Use REPLACE to handle updates
            conn.execute("""
                REPLACE INTO tokens 
                (token_id, platform, user_id, encrypted_token_data, metadata, 
                 created_at, expires_at, last_accessed, access_count, encryption_key_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                stored_token.token_id,
                stored_token.platform,
                stored_token.user_id,
                stored_token.encrypted_token_data,
                json.dumps(stored_token.metadata),
                stored_token.created_at.isoformat(),
                stored_token.expires_at.isoformat(),
                stored_token.last_accessed.isoformat() if stored_token.last_accessed else None,
                stored_token.access_count,
                stored_token.encryption_key_id
            ))
            conn.commit()
        finally:
            conn.close()
    
    def _retrieve_token_database(self, token_id: str) -> Optional[StoredToken]:
        """Retrieve token from SQLite database."""
        conn = sqlite3.connect(self.storage_path)
        try:
            cursor = conn.execute("""
                SELECT token_id, platform, user_id, encrypted_token_data, metadata,
                       created_at, expires_at, last_accessed, access_count, encryption_key_id
                FROM tokens WHERE token_id = ?
            """, (token_id,))
            
            row = cursor.fetchone()
            if not row:
                return None
            
            return StoredToken(
                token_id=row[0],
                platform=row[1],
                user_id=row[2],
                encrypted_token_data=row[3],
                metadata=json.loads(row[4]),
                created_at=datetime.fromisoformat(row[5]),
                expires_at=datetime.fromisoformat(row[6]),
                last_accessed=datetime.fromisoformat(row[7]) if row[7] else None,
                access_count=row[8],
                encryption_key_id=row[9]
            )
        finally:
            conn.close()
    
    def _delete_token_database(self, token_id: str) -> bool:
        """Delete token from SQLite database."""
        conn = sqlite3.connect(self.storage_path)
        try:
            cursor = conn.execute("DELETE FROM tokens WHERE token_id = ?", (token_id,))
            conn.commit()
            return cursor.rowcount > 0
        finally:
            conn.close()
    
    def _store_token_filesystem(self, stored_token: StoredToken):
        """Store token in filesystem."""
        token_file = Path(self.storage_path) / f"{stored_token.token_id}.json"
        with open(token_file, 'w') as f:
            json.dump(stored_token.to_dict(), f)
        os.chmod(token_file, 0o600)  # Secure permissions
    
    def _retrieve_token_filesystem(self, token_id: str) -> Optional[StoredToken]:
        """Retrieve token from filesystem."""
        token_file = Path(self.storage_path) / f"{token_id}.json"
        if not token_file.exists():
            return None
        
        with open(token_file, 'r') as f:
            data = json.load(f)
        
        return StoredToken.from_dict(data)
    
    def _delete_token_filesystem(self, token_id: str) -> bool:
        """Delete token from filesystem."""
        token_file = Path(self.storage_path) / f"{token_id}.json"
        if token_file.exists():
            token_file.unlink()
            return True
        return False
    
    def _update_access_tracking(self, token_id: str):
        """Update token access tracking."""
        if self.storage_type == TokenStorageType.DATABASE:
            conn = sqlite3.connect(self.storage_path)
            try:
                conn.execute("""
                    UPDATE tokens 
                    SET last_accessed = ?, access_count = access_count + 1
                    WHERE token_id = ?
                """, (datetime.now(timezone.utc).isoformat(), token_id))
                conn.commit()
            finally:
                conn.close()
        elif self.storage_type == TokenStorageType.MEMORY:
            if token_id in self._tokens:
                self._tokens[token_id].last_accessed = datetime.now(timezone.utc)
                self._tokens[token_id].access_count += 1
    
    def _cleanup_expired_tokens(self) -> int:
        """Remove expired tokens from storage."""
        current_time = datetime.now(timezone.utc)
        
        if self.storage_type == TokenStorageType.DATABASE:
            conn = sqlite3.connect(self.storage_path)
            try:
                cursor = conn.execute(
                    "DELETE FROM tokens WHERE expires_at <= ?",
                    (current_time.isoformat(),)
                )
                conn.commit()
                return cursor.rowcount
            finally:
                conn.close()
        
        elif self.storage_type == TokenStorageType.FILE_SYSTEM:
            count = 0
            for token_file in Path(self.storage_path).glob("*.json"):
                try:
                    with open(token_file, 'r') as f:
                        data = json.load(f)
                    
                    expires_at = datetime.fromisoformat(data['expires_at'])
                    if expires_at <= current_time:
                        token_file.unlink()
                        count += 1
                except Exception as e:
                    logger.warning(f"Error processing token file {token_file}: {e}")
            return count
        
        elif self.storage_type == TokenStorageType.MEMORY:
            expired_tokens = [
                token_id for token_id, token in self._tokens.items()
                if token.expires_at <= current_time
            ]
            for token_id in expired_tokens:
                del self._tokens[token_id]
            return len(expired_tokens)
        
        return 0
    
    def _list_token_records(self, platform: Optional[Platform] = None, 
                          user_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """List token records metadata."""
        records = []
        
        if self.storage_type == TokenStorageType.DATABASE:
            conn = sqlite3.connect(self.storage_path)
            try:
                query = """
                    SELECT platform, user_id, created_at, expires_at, 
                           last_accessed, access_count
                    FROM tokens
                """
                params = []
                
                conditions = []
                if platform:
                    conditions.append("platform = ?")
                    params.append(platform.value)
                if user_id:
                    conditions.append("user_id = ?")
                    params.append(user_id)
                
                if conditions:
                    query += " WHERE " + " AND ".join(conditions)
                
                cursor = conn.execute(query, params)
                for row in cursor.fetchall():
                    records.append({
                        "platform": row[0],
                        "user_id": row[1],
                        "created_at": row[2],
                        "expires_at": row[3],
                        "last_accessed": row[4],
                        "access_count": row[5]
                    })
            finally:
                conn.close()
        
        elif self.storage_type == TokenStorageType.MEMORY:
            for token in self._tokens.values():
                if platform and token.platform != platform.value:
                    continue
                if user_id and token.user_id != user_id:
                    continue
                
                records.append({
                    "platform": token.platform,
                    "user_id": token.user_id,
                    "created_at": token.created_at.isoformat(),
                    "expires_at": token.expires_at.isoformat(),
                    "last_accessed": token.last_accessed.isoformat() if token.last_accessed else None,
                    "access_count": token.access_count
                })
        
        return records
    
    def _start_cleanup_thread(self):
        """Start automatic token cleanup thread."""
        def cleanup_worker():
            import time
            while self.enable_cleanup:
                try:
                    self.cleanup_expired_tokens()
                except Exception as e:
                    logger.error(f"Cleanup thread error: {e}")
                time.sleep(self.cleanup_interval)
        
        self._cleanup_thread = threading.Thread(target=cleanup_worker, daemon=True)
        self._cleanup_thread.start()
        logger.info("Token cleanup thread started")
    
    def close(self):
        """Close storage and cleanup resources."""
        self.enable_cleanup = False
        if self._cleanup_thread:
            self._cleanup_thread.join(timeout=5)
        logger.info("Secure token storage closed")
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()


class TokenStorageManager:
    """
    High-level token storage manager.
    
    Provides simplified interface for token storage operations
    with automatic platform configuration.
    """
    
    _instance = None
    _lock = threading.Lock()
    
    def __new__(cls):
        """Singleton pattern implementation."""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self):
        if not hasattr(self, '_initialized'):
            self.storage = SecureTokenStorage()
            self._initialized = True
    
    @classmethod
    def instance(cls) -> 'TokenStorageManager':
        """Get singleton instance."""
        return cls()
    
    def store_token(self, platform: Platform, user_id: str, 
                   token: TokenResponse, metadata: Optional[Dict[str, Any]] = None) -> str:
        """Store token with automatic encryption."""
        return self.storage.store_token(platform, user_id, token, metadata)
    
    def get_token(self, platform: Platform, user_id: str) -> Optional[TokenResponse]:
        """Retrieve decrypted token."""
        return self.storage.retrieve_token(platform, user_id)
    
    def remove_token(self, platform: Platform, user_id: str) -> bool:
        """Remove stored token."""
        return self.storage.delete_token(platform, user_id)
    
    def cleanup_expired(self) -> int:
        """Clean up expired tokens."""
        return self.storage.cleanup_expired_tokens()
    
    def get_user_tokens(self, user_id: str) -> List[Dict[str, Any]]:
        """Get all tokens for a user (metadata only)."""
        return self.storage.list_tokens(user_id=user_id)
    
    def get_platform_tokens(self, platform: Platform) -> List[Dict[str, Any]]:
        """Get all tokens for a platform (metadata only)."""
        return self.storage.list_tokens(platform=platform)