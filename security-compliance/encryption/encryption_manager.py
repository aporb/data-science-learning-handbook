"""
Encryption Manager for Data at Rest and In Transit

This module provides a comprehensive encryption framework supporting:
- AES-256-GCM authenticated encryption for data at rest
- Envelope encryption for large data sets
- Field-level encryption for database records
- File-level encryption with secure metadata
- Stream encryption for large files
- Key versioning and migration support

Security Features:
- Authenticated encryption to prevent tampering
- Secure initialization vector (IV) generation
- Constant-time operations where possible
- Memory protection for sensitive data
- Comprehensive error handling without information leakage
"""

import os
import secrets
import hashlib
import json
import logging
from typing import Dict, Optional, Tuple, Union, List, Any, BinaryIO
from dataclasses import dataclass, asdict
from datetime import datetime
from enum import Enum
import base64
import struct

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag

from .key_manager import KeyManager, KeyType, KeyManagerError, SecureBytes


class EncryptionAlgorithm(Enum):
    """Supported encryption algorithms."""
    AES_256_GCM = "aes-256-gcm"
    AES_256_CBC = "aes-256-cbc"
    CHACHA20_POLY1305 = "chacha20-poly1305"


class EncryptionMode(Enum):
    """Encryption operation modes."""
    DATA_AT_REST = "at_rest"
    DATA_IN_TRANSIT = "in_transit"
    FIELD_LEVEL = "field_level"
    FILE_LEVEL = "file_level"


@dataclass
class EncryptionMetadata:
    """Metadata for encrypted data."""
    algorithm: str
    key_id: str
    key_version: int = 1
    iv: Optional[str] = None
    tag: Optional[str] = None
    timestamp: str = ""
    mode: str = EncryptionMode.DATA_AT_REST.value
    data_size: int = 0
    checksum: Optional[str] = None
    
    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.utcnow().isoformat()


@dataclass
class EncryptedData:
    """Container for encrypted data and its metadata."""
    data: bytes
    metadata: EncryptionMetadata
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            'data': base64.b64encode(self.data).decode('utf-8'),
            'metadata': asdict(self.metadata)
        }
    
    @classmethod
    def from_dict(cls, data_dict: Dict[str, Any]) -> 'EncryptedData':
        """Create from dictionary."""
        return cls(
            data=base64.b64decode(data_dict['data']),
            metadata=EncryptionMetadata(**data_dict['metadata'])
        )


class EncryptionError(Exception):
    """Base exception for encryption operations."""
    pass


class DecryptionError(EncryptionError):
    """Raised when decryption fails."""
    pass


class InvalidDataError(EncryptionError):
    """Raised when input data is invalid."""
    pass


class EncryptionManager:
    """
    Comprehensive encryption manager for data at rest and in transit.
    
    Features:
    - Multiple encryption algorithms (AES-256-GCM, ChaCha20-Poly1305)
    - Envelope encryption for large datasets
    - Field-level encryption for databases
    - File-level encryption with streaming support
    - Automatic key rotation and migration
    - Authenticated encryption with tamper detection
    - Secure random IV generation
    - Comprehensive audit logging
    """
    
    def __init__(self, 
                 key_manager: KeyManager,
                 default_algorithm: EncryptionAlgorithm = EncryptionAlgorithm.AES_256_GCM):
        """
        Initialize the Encryption Manager.
        
        Args:
            key_manager: Key management system instance
            default_algorithm: Default encryption algorithm to use
        """
        self.key_manager = key_manager
        self.default_algorithm = default_algorithm
        self.logger = logging.getLogger(__name__)
        
        # Algorithm configurations
        self._algorithm_configs = {
            EncryptionAlgorithm.AES_256_GCM: {
                'key_size': 32,  # 256 bits
                'iv_size': 12,   # 96 bits for GCM
                'tag_size': 16   # 128 bits
            },
            EncryptionAlgorithm.AES_256_CBC: {
                'key_size': 32,  # 256 bits
                'iv_size': 16,   # 128 bits
                'tag_size': 0    # No authentication tag
            },
            EncryptionAlgorithm.CHACHA20_POLY1305: {
                'key_size': 32,  # 256 bits
                'iv_size': 12,   # 96 bits
                'tag_size': 16   # 128 bits
            }
        }
        
        # Chunk size for streaming operations (1MB)
        self.chunk_size = 1024 * 1024
    
    def encrypt_data(self,
                     data: Union[str, bytes],
                     key_id: Optional[str] = None,
                     algorithm: Optional[EncryptionAlgorithm] = None,
                     mode: EncryptionMode = EncryptionMode.DATA_AT_REST,
                     additional_data: Optional[bytes] = None) -> EncryptedData:
        """
        Encrypt data using specified algorithm and key.
        
        Args:
            data: Data to encrypt (string or bytes)
            key_id: Key identifier (generated if None)
            algorithm: Encryption algorithm to use
            mode: Encryption mode context
            additional_data: Additional authenticated data (AAD) for AEAD
            
        Returns:
            EncryptedData object containing encrypted data and metadata
            
        Raises:
            EncryptionError: If encryption fails
        """
        try:
            # Input validation and conversion
            if isinstance(data, str):
                data_bytes = data.encode('utf-8')
            elif isinstance(data, bytes):
                data_bytes = data
            else:
                raise InvalidDataError("Data must be string or bytes")
            
            if len(data_bytes) == 0:
                raise InvalidDataError("Cannot encrypt empty data")
            
            # Use default algorithm if not specified
            algorithm = algorithm or self.default_algorithm
            config = self._algorithm_configs[algorithm]
            
            # Generate or retrieve key
            if key_id is None:
                key_id = f"dek_{secrets.token_hex(8)}"
                self.key_manager.generate_key(
                    key_id=key_id,
                    key_type=KeyType.DATA_ENCRYPTION_KEY,
                    key_length=config['key_size'],
                    purpose=f"Data encryption - {mode.value}"
                )
            
            encryption_key = self.key_manager.get_key(key_id)
            
            # Generate secure random IV
            iv = secrets.token_bytes(config['iv_size'])
            
            # Perform encryption based on algorithm
            if algorithm == EncryptionAlgorithm.AES_256_GCM:
                encrypted_data, tag = self._encrypt_aes_gcm(
                    data_bytes, encryption_key, iv, additional_data
                )
            elif algorithm == EncryptionAlgorithm.AES_256_CBC:
                encrypted_data = self._encrypt_aes_cbc(data_bytes, encryption_key, iv)
                tag = None
            elif algorithm == EncryptionAlgorithm.CHACHA20_POLY1305:
                encrypted_data, tag = self._encrypt_chacha20_poly1305(
                    data_bytes, encryption_key, iv, additional_data
                )
            else:
                raise EncryptionError(f"Unsupported algorithm: {algorithm}")
            
            # Calculate checksum for integrity verification
            checksum = hashlib.sha256(data_bytes).hexdigest()
            
            # Create metadata
            key_metadata = self.key_manager.get_key_metadata(key_id)
            metadata = EncryptionMetadata(
                algorithm=algorithm.value,
                key_id=key_id,
                key_version=key_metadata.version,
                iv=base64.b64encode(iv).decode('utf-8'),
                tag=base64.b64encode(tag).decode('utf-8') if tag else None,
                mode=mode.value,
                data_size=len(data_bytes),
                checksum=checksum
            )
            
            self.logger.info(f"Encrypted data using {algorithm.value} with key {key_id}")
            
            return EncryptedData(data=encrypted_data, metadata=metadata)
            
        except Exception as e:
            self.logger.error(f"Encryption failed: {e}")
            raise EncryptionError(f"Encryption failed: {e}")
    
    def decrypt_data(self,
                     encrypted_data: Union[EncryptedData, Dict[str, Any]],
                     additional_data: Optional[bytes] = None,
                     verify_checksum: bool = True) -> bytes:
        """
        Decrypt encrypted data.
        
        Args:
            encrypted_data: EncryptedData object or dictionary
            additional_data: Additional authenticated data (AAD) for AEAD
            verify_checksum: Whether to verify data integrity checksum
            
        Returns:
            Decrypted data as bytes
            
        Raises:
            DecryptionError: If decryption fails
        """
        try:
            # Handle different input formats
            if isinstance(encrypted_data, dict):
                encrypted_data = EncryptedData.from_dict(encrypted_data)
            elif not isinstance(encrypted_data, EncryptedData):
                raise InvalidDataError("Invalid encrypted data format")
            
            metadata = encrypted_data.metadata
            
            # Retrieve encryption key
            try:
                encryption_key = self.key_manager.get_key(metadata.key_id)
            except Exception as e:
                raise DecryptionError(f"Failed to retrieve decryption key: {e}")
            
            # Parse metadata
            algorithm = EncryptionAlgorithm(metadata.algorithm)
            iv = base64.b64decode(metadata.iv)
            tag = base64.b64decode(metadata.tag) if metadata.tag else None
            
            # Perform decryption based on algorithm
            if algorithm == EncryptionAlgorithm.AES_256_GCM:
                if not tag:
                    raise DecryptionError("Authentication tag missing for GCM mode")
                decrypted_data = self._decrypt_aes_gcm(
                    encrypted_data.data, encryption_key, iv, tag, additional_data
                )
            elif algorithm == EncryptionAlgorithm.AES_256_CBC:
                decrypted_data = self._decrypt_aes_cbc(
                    encrypted_data.data, encryption_key, iv
                )
            elif algorithm == EncryptionAlgorithm.CHACHA20_POLY1305:
                if not tag:
                    raise DecryptionError("Authentication tag missing for ChaCha20-Poly1305")
                decrypted_data = self._decrypt_chacha20_poly1305(
                    encrypted_data.data, encryption_key, iv, tag, additional_data
                )
            else:
                raise DecryptionError(f"Unsupported algorithm: {algorithm}")
            
            # Verify checksum if requested
            if verify_checksum and metadata.checksum:
                calculated_checksum = hashlib.sha256(decrypted_data).hexdigest()
                if calculated_checksum != metadata.checksum:
                    raise DecryptionError("Data integrity check failed")
            
            self.logger.info(f"Decrypted data using {algorithm.value} with key {metadata.key_id}")
            
            return decrypted_data
            
        except Exception as e:
            if isinstance(e, DecryptionError):
                raise
            self.logger.error(f"Decryption failed: {e}")
            raise DecryptionError(f"Decryption failed: {e}")
    
    def encrypt_field(self,
                      field_value: Any,
                      field_name: str,
                      table_name: str = "",
                      key_id: Optional[str] = None) -> Dict[str, str]:
        """
        Encrypt a database field value.
        
        Args:
            field_value: Value to encrypt
            field_name: Name of the database field
            table_name: Name of the database table
            key_id: Key identifier for encryption
            
        Returns:
            Dictionary with encrypted value and metadata
        """
        # Convert field value to string for encryption
        if field_value is None:
            return {"encrypted_value": None, "metadata": None}
        
        field_str = json.dumps(field_value) if not isinstance(field_value, str) else field_value
        
        # Use field-specific key if not provided
        if key_id is None:
            key_id = f"field_{table_name}_{field_name}".replace(" ", "_").lower()
            
            # Generate key if it doesn't exist
            try:
                self.key_manager.get_key(key_id)
            except:
                self.key_manager.generate_key(
                    key_id=key_id,
                    key_type=KeyType.DATA_ENCRYPTION_KEY,
                    purpose=f"Field encryption: {table_name}.{field_name}"
                )
        
        # Encrypt the field value
        encrypted_data = self.encrypt_data(
            data=field_str,
            key_id=key_id,
            mode=EncryptionMode.FIELD_LEVEL
        )
        
        return {
            "encrypted_value": base64.b64encode(encrypted_data.data).decode('utf-8'),
            "metadata": json.dumps(asdict(encrypted_data.metadata))
        }
    
    def decrypt_field(self, encrypted_field: Dict[str, str]) -> Any:
        """
        Decrypt a database field value.
        
        Args:
            encrypted_field: Dictionary with encrypted value and metadata
            
        Returns:
            Decrypted field value
        """
        if encrypted_field["encrypted_value"] is None:
            return None
        
        # Reconstruct encrypted data object
        encrypted_data = EncryptedData(
            data=base64.b64decode(encrypted_field["encrypted_value"]),
            metadata=EncryptionMetadata(**json.loads(encrypted_field["metadata"]))
        )
        
        # Decrypt the field value
        decrypted_bytes = self.decrypt_data(encrypted_data)
        decrypted_str = decrypted_bytes.decode('utf-8')
        
        # Try to parse as JSON, fallback to string
        try:
            return json.loads(decrypted_str)
        except json.JSONDecodeError:
            return decrypted_str
    
    def encrypt_file(self,
                     input_path: str,
                     output_path: Optional[str] = None,
                     key_id: Optional[str] = None,
                     remove_original: bool = False) -> str:
        """
        Encrypt a file using streaming encryption.
        
        Args:
            input_path: Path to input file
            output_path: Path to output encrypted file
            key_id: Key identifier for encryption
            remove_original: Whether to securely delete original file
            
        Returns:
            Path to encrypted file
        """
        if not os.path.exists(input_path):
            raise EncryptionError(f"Input file not found: {input_path}")
        
        if output_path is None:
            output_path = input_path + ".encrypted"
        
        # Generate key if not provided
        if key_id is None:
            key_id = f"file_{secrets.token_hex(8)}"
            self.key_manager.generate_key(
                key_id=key_id,
                key_type=KeyType.DATA_ENCRYPTION_KEY,
                purpose=f"File encryption: {os.path.basename(input_path)}"
            )
        
        encryption_key = self.key_manager.get_key(key_id)
        
        # Generate IV for file encryption
        iv = secrets.token_bytes(12)  # AES-GCM IV
        
        try:
            with open(input_path, 'rb') as infile, open(output_path, 'wb') as outfile:
                # Write file header with metadata
                file_size = os.path.getsize(input_path)
                metadata = EncryptionMetadata(
                    algorithm=self.default_algorithm.value,
                    key_id=key_id,
                    iv=base64.b64encode(iv).decode('utf-8'),
                    mode=EncryptionMode.FILE_LEVEL.value,
                    data_size=file_size
                )
                
                # Write metadata header
                metadata_json = json.dumps(asdict(metadata)).encode('utf-8')
                header_size = len(metadata_json)
                outfile.write(struct.pack('<I', header_size))  # 4 bytes for header size
                outfile.write(metadata_json)
                
                # Initialize cipher for streaming
                cipher = Cipher(
                    algorithms.AES(encryption_key),
                    modes.GCM(iv),
                    backend=default_backend()
                )
                encryptor = cipher.encryptor()
                
                # Encrypt file in chunks
                total_encrypted = 0
                while True:
                    chunk = infile.read(self.chunk_size)
                    if not chunk:
                        break
                    
                    encrypted_chunk = encryptor.update(chunk)
                    outfile.write(encrypted_chunk)
                    total_encrypted += len(chunk)
                
                # Finalize encryption and get authentication tag
                encryptor.finalize()
                tag = encryptor.tag
                outfile.write(tag)  # Write authentication tag at end
            
            # Update metadata with tag
            with open(output_path, 'rb+') as f:
                f.seek(4)  # Skip header size
                metadata_dict = json.loads(f.read(header_size))
                metadata_dict['tag'] = base64.b64encode(tag).decode('utf-8')
                
                # Rewrite metadata
                f.seek(4)
                updated_metadata = json.dumps(metadata_dict).encode('utf-8')
                if len(updated_metadata) <= header_size:
                    f.write(updated_metadata.ljust(header_size, b' '))
            
            # Securely delete original file if requested
            if remove_original:
                self._secure_delete_file(input_path)
            
            self.logger.info(f"Encrypted file {input_path} to {output_path}")
            return output_path
            
        except Exception as e:
            # Clean up partial output file
            if os.path.exists(output_path):
                os.remove(output_path)
            raise EncryptionError(f"File encryption failed: {e}")
    
    def decrypt_file(self,
                     input_path: str,
                     output_path: Optional[str] = None,
                     remove_encrypted: bool = False) -> str:
        """
        Decrypt an encrypted file.
        
        Args:
            input_path: Path to encrypted file
            output_path: Path to output decrypted file
            remove_encrypted: Whether to delete encrypted file after decryption
            
        Returns:
            Path to decrypted file
        """
        if not os.path.exists(input_path):
            raise DecryptionError(f"Encrypted file not found: {input_path}")
        
        try:
            with open(input_path, 'rb') as infile:
                # Read metadata header
                header_size = struct.unpack('<I', infile.read(4))[0]
                metadata_json = infile.read(header_size).rstrip(b' ')
                metadata_dict = json.loads(metadata_json)
                metadata = EncryptionMetadata(**metadata_dict)
                
                # Get decryption key
                encryption_key = self.key_manager.get_key(metadata.key_id)
                iv = base64.b64decode(metadata.iv)
                
                # Determine output path
                if output_path is None:
                    if input_path.endswith('.encrypted'):
                        output_path = input_path[:-10]  # Remove .encrypted extension
                    else:
                        output_path = input_path + ".decrypted"
                
                # Read encrypted data and authentication tag
                file_data = infile.read()
                encrypted_data = file_data[:-16]  # All except last 16 bytes (tag)
                tag = file_data[-16:]  # Last 16 bytes
                
                # Initialize cipher for decryption
                cipher = Cipher(
                    algorithms.AES(encryption_key),
                    modes.GCM(iv, tag),
                    backend=default_backend()
                )
                decryptor = cipher.decryptor()
                
                # Decrypt and write to output file
                with open(output_path, 'wb') as outfile:
                    # Decrypt in chunks if data is large
                    if len(encrypted_data) > self.chunk_size:
                        for i in range(0, len(encrypted_data), self.chunk_size):
                            chunk = encrypted_data[i:i + self.chunk_size]
                            decrypted_chunk = decryptor.update(chunk)
                            outfile.write(decrypted_chunk)
                    else:
                        decrypted_data = decryptor.update(encrypted_data)
                        outfile.write(decrypted_data)
                    
                    decryptor.finalize()  # Verify authentication tag
            
            # Remove encrypted file if requested
            if remove_encrypted:
                os.remove(input_path)
            
            self.logger.info(f"Decrypted file {input_path} to {output_path}")
            return output_path
            
        except Exception as e:
            raise DecryptionError(f"File decryption failed: {e}")
    
    def envelope_encrypt(self,
                         data: bytes,
                         master_key_id: str,
                         data_key_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Perform envelope encryption for large datasets.
        
        Args:
            data: Data to encrypt
            master_key_id: Master key identifier
            data_key_id: Data encryption key identifier
            
        Returns:
            Dictionary with encrypted data and encrypted data key
        """
        # Generate data encryption key if not provided
        if data_key_id is None:
            data_key_id = f"envelope_dek_{secrets.token_hex(8)}"
            self.key_manager.generate_key(
                key_id=data_key_id,
                key_type=KeyType.DATA_ENCRYPTION_KEY,
                purpose="Envelope encryption data key"
            )
        
        # Encrypt data with data key
        encrypted_data = self.encrypt_data(
            data=data,
            key_id=data_key_id,
            mode=EncryptionMode.DATA_AT_REST
        )
        
        # Encrypt data key with master key
        data_key = self.key_manager.get_key(data_key_id)
        encrypted_data_key = self.encrypt_data(
            data=data_key,
            key_id=master_key_id,
            mode=EncryptionMode.DATA_AT_REST
        )
        
        return {
            "encrypted_data": encrypted_data.to_dict(),
            "encrypted_data_key": encrypted_data_key.to_dict(),
            "master_key_id": master_key_id,
            "data_key_id": data_key_id
        }
    
    def envelope_decrypt(self, envelope_data: Dict[str, Any]) -> bytes:
        """
        Decrypt envelope-encrypted data.
        
        Args:
            envelope_data: Envelope encryption structure
            
        Returns:
            Decrypted data
        """
        # Decrypt data key using master key
        encrypted_data_key = EncryptedData.from_dict(envelope_data["encrypted_data_key"])
        data_key = self.decrypt_data(encrypted_data_key)
        
        # Temporarily store data key for decryption
        temp_key_id = f"temp_{secrets.token_hex(8)}"
        self.key_manager._key_cache[temp_key_id] = SecureBytes(data_key)
        
        try:
            # Decrypt data using data key
            encrypted_data = EncryptedData.from_dict(envelope_data["encrypted_data"])
            # Update metadata to use temporary key
            encrypted_data.metadata.key_id = temp_key_id
            
            decrypted_data = self.decrypt_data(encrypted_data)
            return decrypted_data
            
        finally:
            # Clean up temporary key
            if temp_key_id in self.key_manager._key_cache:
                del self.key_manager._key_cache[temp_key_id]
    
    def _encrypt_aes_gcm(self,
                         data: bytes,
                         key: bytes,
                         iv: bytes,
                         additional_data: Optional[bytes] = None) -> Tuple[bytes, bytes]:
        """Encrypt data using AES-256-GCM."""
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        
        if additional_data:
            encryptor.authenticate_additional_data(additional_data)
        
        ciphertext = encryptor.update(data) + encryptor.finalize()
        return ciphertext, encryptor.tag
    
    def _decrypt_aes_gcm(self,
                         ciphertext: bytes,
                         key: bytes,
                         iv: bytes,
                         tag: bytes,
                         additional_data: Optional[bytes] = None) -> bytes:
        """Decrypt data using AES-256-GCM."""
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(iv, tag),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        
        if additional_data:
            decryptor.authenticate_additional_data(additional_data)
        
        try:
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            return plaintext
        except InvalidTag:
            raise DecryptionError("Authentication tag verification failed")
    
    def _encrypt_aes_cbc(self, data: bytes, key: bytes, iv: bytes) -> bytes:
        """Encrypt data using AES-256-CBC with PKCS7 padding."""
        # Add PKCS7 padding
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(data) + padder.finalize()
        
        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        return encryptor.update(padded_data) + encryptor.finalize()
    
    def _decrypt_aes_cbc(self, ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
        """Decrypt data using AES-256-CBC with PKCS7 padding."""
        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Remove PKCS7 padding
        unpadder = padding.PKCS7(128).unpadder()
        return unpadder.update(padded_data) + unpadder.finalize()
    
    def _encrypt_chacha20_poly1305(self,
                                   data: bytes,
                                   key: bytes,
                                   nonce: bytes,
                                   additional_data: Optional[bytes] = None) -> Tuple[bytes, bytes]:
        """Encrypt data using ChaCha20-Poly1305."""
        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
        
        aesgcm = ChaCha20Poly1305(key)
        ciphertext = aesgcm.encrypt(nonce, data, additional_data)
        
        # ChaCha20Poly1305 returns ciphertext + tag
        return ciphertext[:-16], ciphertext[-16:]
    
    def _decrypt_chacha20_poly1305(self,
                                   ciphertext: bytes,
                                   key: bytes,
                                   nonce: bytes,
                                   tag: bytes,
                                   additional_data: Optional[bytes] = None) -> bytes:
        """Decrypt data using ChaCha20-Poly1305."""
        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
        
        aesgcm = ChaCha20Poly1305(key)
        combined_data = ciphertext + tag
        return aesgcm.decrypt(nonce, combined_data, additional_data)
    
    def _secure_delete_file(self, file_path: str):
        """Securely delete a file by overwriting with random data."""
        if not os.path.exists(file_path):
            return
        
        file_size = os.path.getsize(file_path)
        
        # Overwrite with random data multiple times
        with open(file_path, 'rb+') as f:
            for _ in range(3):  # DoD 5220.22-M standard
                f.seek(0)
                f.write(secrets.token_bytes(file_size))
                f.flush()
                os.fsync(f.fileno())
        
        os.remove(file_path)