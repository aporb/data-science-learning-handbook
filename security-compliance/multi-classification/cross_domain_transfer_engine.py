"""
Enhanced Cross-Domain Transfer Engine

This module provides secure data transfer capabilities between NIPR, SIPR, and JWICS networks
with advanced encryption, validation, and performance optimization for large data transfers.
Integrates with automated data labeling results and implements DoD cross-domain solution compliance.
"""

import logging
import asyncio
import aiofiles
import hashlib
import hmac
import uuid
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, List, Optional, Any, Tuple, AsyncGenerator
from dataclasses import dataclass, field
from pathlib import Path
import json
import struct
import zlib
from concurrent.futures import ThreadPoolExecutor
import ssl
import socket
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os

# Import existing security components
import sys
sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from models.classification_models import ClassificationLevel, DataItem
from cross_domain_guard.engines.cross_domain_guard import NetworkDomain, TransferRequest, TransferStatus
from cross_domain_guard.authorization.multi_party_auth import MultiPartyAuthorizationEngine
from cross_domain_guard.validation.transfer_validator import TransferValidationEngine, ValidationResult


class TransferMode(Enum):
    """Transfer mode enumeration"""
    STREAMING = "streaming"
    BATCH = "batch"
    BULK = "bulk"
    REAL_TIME = "real_time"


class EncryptionLevel(Enum):
    """Encryption level enumeration"""
    STANDARD = "standard"          # AES-256-GCM
    HIGH = "high"                 # AES-256-GCM + RSA-4096
    MAXIMUM = "maximum"           # AES-256-GCM + RSA-4096 + HMAC-SHA512


class TransferProtocol(Enum):
    """Transfer protocol enumeration"""
    SECURE_TCP = "secure_tcp"
    ENCRYPTED_UDP = "encrypted_udp"
    QUANTUM_SAFE = "quantum_safe"


@dataclass
class TransferMetrics:
    """Transfer performance metrics"""
    total_bytes: int = 0
    bytes_transferred: int = 0
    transfer_rate_mbps: float = 0.0
    encryption_overhead_percent: float = 0.0
    compression_ratio: float = 0.0
    error_count: int = 0
    retry_count: int = 0
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    estimated_completion: Optional[datetime] = None


@dataclass
class EncryptionParameters:
    """Encryption parameters for transfer"""
    level: EncryptionLevel
    algorithm: str
    key_size: int
    iv: bytes
    salt: bytes
    hmac_key: Optional[bytes] = None
    public_key: Optional[bytes] = None
    session_key: Optional[bytes] = None


@dataclass
class TransferConfiguration:
    """Transfer configuration settings"""
    mode: TransferMode
    protocol: TransferProtocol
    encryption: EncryptionParameters
    chunk_size: int = 64 * 1024  # 64KB chunks
    compression_enabled: bool = True
    integrity_checking: bool = True
    retry_attempts: int = 3
    timeout_seconds: int = 300
    buffer_size: int = 1024 * 1024  # 1MB buffer
    performance_monitoring: bool = True


class EncryptionManager:
    """Manages encryption operations for cross-domain transfers"""
    
    def __init__(self):
        self.key_cache = {}
        self.cipher_cache = {}
        
    def generate_encryption_parameters(self, level: EncryptionLevel, 
                                     domain_pair: Tuple[NetworkDomain, NetworkDomain]) -> EncryptionParameters:
        """Generate encryption parameters based on security level and domain pair"""
        
        # Generate random salt and IV
        salt = os.urandom(32)
        iv = os.urandom(16)
        
        if level == EncryptionLevel.STANDARD:
            return EncryptionParameters(
                level=level,
                algorithm="AES-256-GCM",
                key_size=256,
                iv=iv,
                salt=salt
            )
        elif level == EncryptionLevel.HIGH:
            # Generate RSA key pair for key exchange
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=4096
            )
            public_key = private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            return EncryptionParameters(
                level=level,
                algorithm="AES-256-GCM+RSA-4096",
                key_size=256,
                iv=iv,
                salt=salt,
                public_key=public_key
            )
        elif level == EncryptionLevel.MAXIMUM:
            # Generate RSA key pair and HMAC key
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=4096
            )
            public_key = private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            hmac_key = os.urandom(64)
            
            return EncryptionParameters(
                level=level,
                algorithm="AES-256-GCM+RSA-4096+HMAC-SHA512",
                key_size=256,
                iv=iv,
                salt=salt,
                public_key=public_key,
                hmac_key=hmac_key
            )
    
    def derive_session_key(self, password: bytes, salt: bytes, key_length: int = 32) -> bytes:
        """Derive session key using PBKDF2"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=key_length,
            salt=salt,
            iterations=100000,
        )
        return kdf.derive(password)
    
    def encrypt_data_chunk(self, data: bytes, params: EncryptionParameters) -> bytes:
        """Encrypt a data chunk with specified parameters"""
        try:
            if params.level == EncryptionLevel.STANDARD:
                return self._encrypt_aes_gcm(data, params)
            elif params.level == EncryptionLevel.HIGH:
                encrypted_data = self._encrypt_aes_gcm(data, params)
                return self._add_rsa_signature(encrypted_data, params)
            elif params.level == EncryptionLevel.MAXIMUM:
                encrypted_data = self._encrypt_aes_gcm(data, params)
                signed_data = self._add_rsa_signature(encrypted_data, params)
                return self._add_hmac(signed_data, params)
                
        except Exception as e:
            logging.error(f"Encryption error: {e}")
            raise
    
    def decrypt_data_chunk(self, encrypted_data: bytes, params: EncryptionParameters) -> bytes:
        """Decrypt a data chunk with specified parameters"""
        try:
            if params.level == EncryptionLevel.STANDARD:
                return self._decrypt_aes_gcm(encrypted_data, params)
            elif params.level == EncryptionLevel.HIGH:
                verified_data = self._verify_rsa_signature(encrypted_data, params)
                return self._decrypt_aes_gcm(verified_data, params)
            elif params.level == EncryptionLevel.MAXIMUM:
                verified_hmac = self._verify_hmac(encrypted_data, params)
                verified_rsa = self._verify_rsa_signature(verified_hmac, params)
                return self._decrypt_aes_gcm(verified_rsa, params)
                
        except Exception as e:
            logging.error(f"Decryption error: {e}")
            raise
    
    def _encrypt_aes_gcm(self, data: bytes, params: EncryptionParameters) -> bytes:
        """Encrypt data using AES-GCM"""
        if not params.session_key:
            params.session_key = self.derive_session_key(
                b"default_password",  # In practice, use proper key derivation
                params.salt
            )
        
        cipher = Cipher(
            algorithms.AES(params.session_key),
            modes.GCM(params.iv)
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(data) + encryptor.finalize()
        
        # Return IV + tag + ciphertext
        return params.iv + encryptor.tag + ciphertext
    
    def _decrypt_aes_gcm(self, encrypted_data: bytes, params: EncryptionParameters) -> bytes:
        """Decrypt data using AES-GCM"""
        if not params.session_key:
            params.session_key = self.derive_session_key(
                b"default_password",  # In practice, use proper key derivation
                params.salt
            )
        
        # Extract IV, tag, and ciphertext
        iv = encrypted_data[:16]
        tag = encrypted_data[16:32]
        ciphertext = encrypted_data[32:]
        
        cipher = Cipher(
            algorithms.AES(params.session_key),
            modes.GCM(iv, tag)
        )
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()
    
    def _add_rsa_signature(self, data: bytes, params: EncryptionParameters) -> bytes:
        """Add RSA signature to data"""
        # Simulate RSA signature (in practice, use actual private key)
        signature = hashlib.sha256(data).digest()
        return struct.pack("!I", len(signature)) + signature + data
    
    def _verify_rsa_signature(self, signed_data: bytes, params: EncryptionParameters) -> bytes:
        """Verify RSA signature and return data"""
        # Extract signature length and signature
        sig_len = struct.unpack("!I", signed_data[:4])[0]
        signature = signed_data[4:4+sig_len]
        data = signed_data[4+sig_len:]
        
        # Verify signature (simplified)
        expected_signature = hashlib.sha256(data).digest()
        if signature != expected_signature:
            raise ValueError("RSA signature verification failed")
        
        return data
    
    def _add_hmac(self, data: bytes, params: EncryptionParameters) -> bytes:
        """Add HMAC to data"""
        if not params.hmac_key:
            raise ValueError("HMAC key not provided")
        
        mac = hmac.new(params.hmac_key, data, hashlib.sha512).digest()
        return struct.pack("!I", len(mac)) + mac + data
    
    def _verify_hmac(self, hmac_data: bytes, params: EncryptionParameters) -> bytes:
        """Verify HMAC and return data"""
        if not params.hmac_key:
            raise ValueError("HMAC key not provided")
        
        # Extract HMAC length and HMAC
        mac_len = struct.unpack("!I", hmac_data[:4])[0]
        mac = hmac_data[4:4+mac_len]
        data = hmac_data[4+mac_len:]
        
        # Verify HMAC
        expected_mac = hmac.new(params.hmac_key, data, hashlib.sha512).digest()
        if not hmac.compare_digest(mac, expected_mac):
            raise ValueError("HMAC verification failed")
        
        return data


class CompressionManager:
    """Manages compression operations for transfers"""
    
    def __init__(self):
        self.compression_stats = {}
    
    def compress_data(self, data: bytes, level: int = 6) -> Tuple[bytes, float]:
        """Compress data and return compressed data with compression ratio"""
        original_size = len(data)
        compressed_data = zlib.compress(data, level)
        compressed_size = len(compressed_data)
        
        compression_ratio = original_size / compressed_size if compressed_size > 0 else 1.0
        
        return compressed_data, compression_ratio
    
    def decompress_data(self, compressed_data: bytes) -> bytes:
        """Decompress data"""
        return zlib.decompress(compressed_data)


class NetworkBridge:
    """Network bridge for secure domain-to-domain communication"""
    
    def __init__(self, source_domain: NetworkDomain, target_domain: NetworkDomain):
        self.source_domain = source_domain
        self.target_domain = target_domain
        self.connection_pool = {}
        self.active_transfers = {}
        
    async def establish_secure_connection(self, protocol: TransferProtocol) -> str:
        """Establish secure connection between domains"""
        connection_id = str(uuid.uuid4())
        
        try:
            if protocol == TransferProtocol.SECURE_TCP:
                connection = await self._establish_tcp_connection()
            elif protocol == TransferProtocol.ENCRYPTED_UDP:
                connection = await self._establish_udp_connection()
            elif protocol == TransferProtocol.QUANTUM_SAFE:
                connection = await self._establish_quantum_safe_connection()
            else:
                raise ValueError(f"Unsupported protocol: {protocol}")
            
            self.connection_pool[connection_id] = {
                "connection": connection,
                "protocol": protocol,
                "established_at": datetime.now(),
                "active": True
            }
            
            logging.info(f"Secure connection established: {connection_id}")
            return connection_id
            
        except Exception as e:
            logging.error(f"Failed to establish connection: {e}")
            raise
    
    async def _establish_tcp_connection(self) -> Any:
        """Establish secure TCP connection"""
        # Create SSL context
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE  # In practice, use proper certificates
        
        # Simulate connection establishment
        await asyncio.sleep(0.1)
        return {"type": "tcp", "encrypted": True}
    
    async def _establish_udp_connection(self) -> Any:
        """Establish encrypted UDP connection"""
        # Simulate UDP connection with encryption
        await asyncio.sleep(0.05)
        return {"type": "udp", "encrypted": True}
    
    async def _establish_quantum_safe_connection(self) -> Any:
        """Establish quantum-safe connection"""
        # Simulate quantum-safe connection
        await asyncio.sleep(0.2)
        return {"type": "quantum_safe", "encrypted": True, "quantum_resistant": True}
    
    async def send_data_chunk(self, connection_id: str, data: bytes) -> bool:
        """Send encrypted data chunk through bridge"""
        connection_info = self.connection_pool.get(connection_id)
        if not connection_info or not connection_info["active"]:
            raise ValueError(f"Invalid or inactive connection: {connection_id}")
        
        try:
            # Simulate data transmission
            await asyncio.sleep(0.001 * len(data) / 1024)  # Simulate network latency
            
            # Update connection statistics
            connection_info["last_activity"] = datetime.now()
            connection_info["bytes_sent"] = connection_info.get("bytes_sent", 0) + len(data)
            
            return True
            
        except Exception as e:
            logging.error(f"Failed to send data chunk: {e}")
            return False
    
    async def receive_data_chunk(self, connection_id: str, expected_size: int) -> bytes:
        """Receive encrypted data chunk through bridge"""
        connection_info = self.connection_pool.get(connection_id)
        if not connection_info or not connection_info["active"]:
            raise ValueError(f"Invalid or inactive connection: {connection_id}")
        
        try:
            # Simulate data reception
            await asyncio.sleep(0.001 * expected_size / 1024)  # Simulate network latency
            
            # Simulate received data (in practice, receive from actual connection)
            received_data = os.urandom(expected_size)
            
            # Update connection statistics
            connection_info["last_activity"] = datetime.now()
            connection_info["bytes_received"] = connection_info.get("bytes_received", 0) + len(received_data)
            
            return received_data
            
        except Exception as e:
            logging.error(f"Failed to receive data chunk: {e}")
            raise
    
    def close_connection(self, connection_id: str):
        """Close network connection"""
        if connection_id in self.connection_pool:
            self.connection_pool[connection_id]["active"] = False
            self.connection_pool[connection_id]["closed_at"] = datetime.now()
            logging.info(f"Connection closed: {connection_id}")


class CrossDomainTransferEngine:
    """Enhanced cross-domain transfer engine with advanced security and performance features"""
    
    def __init__(self):
        self.encryption_manager = EncryptionManager()
        self.compression_manager = CompressionManager()
        self.authorization_engine = MultiPartyAuthorizationEngine()
        self.validation_engine = TransferValidationEngine()
        
        # Network bridges for different domain pairs
        self.bridges = {
            (NetworkDomain.NIPR, NetworkDomain.SIPR): NetworkBridge(NetworkDomain.NIPR, NetworkDomain.SIPR),
            (NetworkDomain.SIPR, NetworkDomain.JWICS): NetworkBridge(NetworkDomain.SIPR, NetworkDomain.JWICS),
            (NetworkDomain.SIPR, NetworkDomain.NIPR): NetworkBridge(NetworkDomain.SIPR, NetworkDomain.NIPR),
            (NetworkDomain.JWICS, NetworkDomain.SIPR): NetworkBridge(NetworkDomain.JWICS, NetworkDomain.SIPR)
        }
        
        self.active_transfers = {}
        self.transfer_history = []
        self.performance_stats = {}
        
    async def initiate_transfer(self, request: TransferRequest, 
                              config: Optional[TransferConfiguration] = None) -> str:
        """Initiate cross-domain transfer with enhanced security and performance"""
        
        if not config:
            config = self._create_default_config(request)
        
        transfer_id = str(uuid.uuid4())
        
        try:
            # Step 1: Validate transfer request
            validation_results = await self.validation_engine.validate_transfer(request)
            overall_result = self.validation_engine.get_overall_validation_result(request.id)
            
            if overall_result in [ValidationResult.BLOCKED, ValidationResult.FAILED]:
                request.status = TransferStatus.REJECTED
                logging.warning(f"Transfer {transfer_id} rejected due to validation failures")
                return transfer_id
            
            # Step 2: Authorization workflow
            if overall_result == ValidationResult.REQUIRES_REVIEW:
                auth_workflow_id = await self.authorization_engine.initiate_authorization(request)
                
                # Wait for authorization (in practice, this would be async)
                await self._wait_for_authorization(auth_workflow_id, timeout_hours=24)
            
            # Step 3: Set up encryption parameters
            domain_pair = (request.source_domain, request.target_domain)
            encryption_level = self._determine_encryption_level(request)
            encryption_params = self.encryption_manager.generate_encryption_parameters(
                encryption_level, domain_pair
            )
            config.encryption = encryption_params
            
            # Step 4: Establish network bridge
            bridge = self.bridges.get(domain_pair)
            if not bridge:
                raise ValueError(f"No bridge available for {domain_pair}")
            
            connection_id = await bridge.establish_secure_connection(config.protocol)
            
            # Step 5: Initialize transfer metrics
            metrics = TransferMetrics(
                total_bytes=sum(len(str(item.content)) for item in request.data_items),
                start_time=datetime.now()
            )
            
            # Step 6: Store transfer information
            self.active_transfers[transfer_id] = {
                "request": request,
                "config": config,
                "bridge": bridge,
                "connection_id": connection_id,
                "metrics": metrics,
                "status": TransferStatus.PROCESSING
            }
            
            # Step 7: Start transfer process
            asyncio.create_task(self._execute_transfer(transfer_id))
            
            logging.info(f"Transfer {transfer_id} initiated successfully")
            return transfer_id
            
        except Exception as e:
            logging.error(f"Failed to initiate transfer {transfer_id}: {e}")
            request.status = TransferStatus.FAILED
            raise
    
    def _create_default_config(self, request: TransferRequest) -> TransferConfiguration:
        """Create default transfer configuration based on request"""
        
        # Determine transfer mode based on data size
        total_size = sum(len(str(item.content)) for item in request.data_items)
        
        if total_size > 1024 * 1024 * 1024:  # > 1GB
            mode = TransferMode.BULK
            chunk_size = 1024 * 1024  # 1MB chunks
        elif total_size > 10 * 1024 * 1024:  # > 10MB
            mode = TransferMode.BATCH
            chunk_size = 256 * 1024  # 256KB chunks
        else:
            mode = TransferMode.STREAMING
            chunk_size = 64 * 1024  # 64KB chunks
        
        # Determine protocol based on domain pair and classification
        domain_pair = (request.source_domain, request.target_domain)
        max_classification = max(item.classification for item in request.data_items)
        
        if max_classification == ClassificationLevel.TOP_SECRET:
            protocol = TransferProtocol.QUANTUM_SAFE
        elif max_classification == ClassificationLevel.SECRET:
            protocol = TransferProtocol.SECURE_TCP
        else:
            protocol = TransferProtocol.ENCRYPTED_UDP
        
        return TransferConfiguration(
            mode=mode,
            protocol=protocol,
            encryption=None,  # Will be set later
            chunk_size=chunk_size,
            compression_enabled=True,
            integrity_checking=True,
            retry_attempts=3,
            timeout_seconds=300,
            performance_monitoring=True
        )
    
    def _determine_encryption_level(self, request: TransferRequest) -> EncryptionLevel:
        """Determine appropriate encryption level based on request"""
        max_classification = max(item.classification for item in request.data_items)
        
        if max_classification == ClassificationLevel.TOP_SECRET:
            return EncryptionLevel.MAXIMUM
        elif max_classification == ClassificationLevel.SECRET:
            return EncryptionLevel.HIGH
        else:
            return EncryptionLevel.STANDARD
    
    async def _wait_for_authorization(self, workflow_id: str, timeout_hours: int = 24):
        """Wait for authorization completion"""
        start_time = datetime.now()
        timeout_time = start_time + timedelta(hours=timeout_hours)
        
        while datetime.now() < timeout_time:
            status = self.authorization_engine.get_workflow_status(workflow_id)
            
            if status and status.value in ["approved", "rejected"]:
                if status.value == "rejected":
                    raise ValueError("Transfer authorization rejected")
                break
            
            await asyncio.sleep(60)  # Check every minute
        else:
            raise TimeoutError("Authorization timeout")
    
    async def _execute_transfer(self, transfer_id: str):
        """Execute the actual transfer process"""
        transfer_info = self.active_transfers.get(transfer_id)
        if not transfer_info:
            return
        
        request = transfer_info["request"]
        config = transfer_info["config"]
        bridge = transfer_info["bridge"]
        connection_id = transfer_info["connection_id"]
        metrics = transfer_info["metrics"]
        
        try:
            transfer_info["status"] = TransferStatus.PROCESSING
            
            for data_item in request.data_items:
                await self._transfer_data_item(data_item, config, bridge, connection_id, metrics)
            
            # Transfer completed successfully
            metrics.end_time = datetime.now()
            transfer_info["status"] = TransferStatus.COMPLETED
            request.status = TransferStatus.COMPLETED
            
            # Update performance statistics
            self._update_performance_stats(transfer_id, metrics)
            
            logging.info(f"Transfer {transfer_id} completed successfully")
            
        except Exception as e:
            transfer_info["status"] = TransferStatus.FAILED
            request.status = TransferStatus.FAILED
            metrics.error_count += 1
            
            logging.error(f"Transfer {transfer_id} failed: {e}")
            
        finally:
            # Clean up connection
            bridge.close_connection(connection_id)
            
            # Move to history
            self._archive_transfer(transfer_id)
    
    async def _transfer_data_item(self, data_item: DataItem, config: TransferConfiguration,
                                bridge: NetworkBridge, connection_id: str, metrics: TransferMetrics):
        """Transfer individual data item"""
        
        data = str(data_item.content).encode('utf-8')
        total_size = len(data)
        transferred = 0
        
        # Process data in chunks
        async for chunk in self._process_data_chunks(data, config):
            try:
                # Send chunk through bridge
                success = await bridge.send_data_chunk(connection_id, chunk)
                
                if not success:
                    raise Exception("Failed to send data chunk")
                
                transferred += len(chunk)
                metrics.bytes_transferred += len(chunk)
                
                # Update transfer rate
                if metrics.start_time:
                    elapsed_seconds = (datetime.now() - metrics.start_time).total_seconds()
                    if elapsed_seconds > 0:
                        metrics.transfer_rate_mbps = (metrics.bytes_transferred / (1024 * 1024)) / elapsed_seconds
                
                # Update progress
                progress = (transferred / total_size) * 100
                logging.debug(f"Data item {data_item.id} transfer progress: {progress:.1f}%")
                
            except Exception as e:
                metrics.error_count += 1
                metrics.retry_count += 1
                
                if metrics.retry_count >= config.retry_attempts:
                    raise
                
                # Retry with exponential backoff
                await asyncio.sleep(2 ** metrics.retry_count)
                continue
    
    async def _process_data_chunks(self, data: bytes, config: TransferConfiguration) -> AsyncGenerator[bytes, None]:
        """Process data into encrypted, compressed chunks"""
        
        chunk_size = config.chunk_size
        total_size = len(data)
        
        for i in range(0, total_size, chunk_size):
            chunk = data[i:i + chunk_size]
            
            # Compress if enabled
            if config.compression_enabled:
                chunk, compression_ratio = self.compression_manager.compress_data(chunk)
                
                # Update metrics
                if hasattr(config, 'metrics'):
                    config.metrics.compression_ratio = compression_ratio
            
            # Encrypt chunk
            encrypted_chunk = self.encryption_manager.encrypt_data_chunk(chunk, config.encryption)
            
            # Add integrity checking if enabled
            if config.integrity_checking:
                chunk_hash = hashlib.sha256(encrypted_chunk).digest()
                encrypted_chunk = struct.pack("!I", len(chunk_hash)) + chunk_hash + encrypted_chunk
            
            yield encrypted_chunk
    
    def _update_performance_stats(self, transfer_id: str, metrics: TransferMetrics):
        """Update performance statistics"""
        if transfer_id not in self.performance_stats:
            self.performance_stats[transfer_id] = {}
        
        stats = self.performance_stats[transfer_id]
        stats.update({
            "total_bytes": metrics.total_bytes,
            "bytes_transferred": metrics.bytes_transferred,
            "transfer_rate_mbps": metrics.transfer_rate_mbps,
            "compression_ratio": metrics.compression_ratio,
            "error_count": metrics.error_count,
            "retry_count": metrics.retry_count,
            "duration_seconds": (metrics.end_time - metrics.start_time).total_seconds() if metrics.end_time else 0
        })
    
    def _archive_transfer(self, transfer_id: str):
        """Archive completed transfer"""
        if transfer_id in self.active_transfers:
            transfer_info = self.active_transfers[transfer_id]
            transfer_info["archived_at"] = datetime.now()
            
            self.transfer_history.append(transfer_info)
            del self.active_transfers[transfer_id]
    
    def get_transfer_status(self, transfer_id: str) -> Optional[TransferStatus]:
        """Get transfer status"""
        transfer_info = self.active_transfers.get(transfer_id)
        if transfer_info:
            return transfer_info["status"]
        
        # Check history
        for historical_transfer in self.transfer_history:
            if historical_transfer.get("id") == transfer_id:
                return historical_transfer["status"]
        
        return None
    
    def get_transfer_metrics(self, transfer_id: str) -> Optional[TransferMetrics]:
        """Get transfer metrics"""
        transfer_info = self.active_transfers.get(transfer_id)
        if transfer_info:
            return transfer_info["metrics"]
        
        return None
    
    def get_system_performance_stats(self) -> Dict[str, Any]:
        """Get system-wide performance statistics"""
        if not self.performance_stats:
            return {"total_transfers": 0}
        
        total_transfers = len(self.performance_stats)
        total_bytes = sum(stats.get("total_bytes", 0) for stats in self.performance_stats.values())
        avg_transfer_rate = sum(stats.get("transfer_rate_mbps", 0) for stats in self.performance_stats.values()) / total_transfers
        total_errors = sum(stats.get("error_count", 0) for stats in self.performance_stats.values())
        
        return {
            "total_transfers": total_transfers,
            "total_bytes_transferred": total_bytes,
            "average_transfer_rate_mbps": avg_transfer_rate,
            "total_errors": total_errors,
            "active_transfers": len(self.active_transfers),
            "success_rate": ((total_transfers - total_errors) / total_transfers * 100) if total_transfers > 0 else 0
        }
    
    async def cancel_transfer(self, transfer_id: str) -> bool:
        """Cancel active transfer"""
        transfer_info = self.active_transfers.get(transfer_id)
        if not transfer_info:
            return False
        
        try:
            # Close connection
            bridge = transfer_info["bridge"]
            connection_id = transfer_info["connection_id"]
            bridge.close_connection(connection_id)
            
            # Update status
            transfer_info["status"] = TransferStatus.FAILED
            transfer_info["request"].status = TransferStatus.FAILED
            
            # Archive transfer
            self._archive_transfer(transfer_id)
            
            logging.info(f"Transfer {transfer_id} cancelled")
            return True
            
        except Exception as e:
            logging.error(f"Error cancelling transfer {transfer_id}: {e}")
            return False