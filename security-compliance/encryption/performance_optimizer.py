"""
Encryption Performance Optimization Module

This module provides performance optimization features for encryption operations
including hardware acceleration, caching, batching, and monitoring.

Features:
- Hardware acceleration detection and utilization
- Intelligent caching strategies
- Batch processing optimization
- Performance monitoring and profiling
- Adaptive algorithm selection
- Memory usage optimization
- Parallel processing capabilities
"""

import os
import time
import threading
import multiprocessing
from typing import Dict, List, Optional, Tuple, Any, Union
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
import statistics
import hashlib
import pickle
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
import logging

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag
import psutil


class AccelerationType(Enum):
    """Hardware acceleration types."""
    CPU_AES_NI = "cpu_aes_ni"
    GPU_CUDA = "gpu_cuda"
    GPU_OPENCL = "gpu_opencl"
    HARDWARE_HSM = "hardware_hsm"
    INTEL_QAT = "intel_qat"
    ARM_CRYPTO = "arm_crypto"


class CacheStrategy(Enum):
    """Caching strategies for encryption operations."""
    LRU = "lru"
    LFU = "lfu"
    TTL = "ttl"
    ADAPTIVE = "adaptive"
    DISABLED = "disabled"


@dataclass
class PerformanceMetrics:
    """Performance metrics for encryption operations."""
    operation_type: str
    algorithm: str
    data_size: int
    execution_time: float
    throughput_mbps: float
    cpu_usage: float
    memory_usage: int
    cache_hit_rate: float = 0.0
    acceleration_used: Optional[AccelerationType] = None
    timestamp: datetime = field(default_factory=datetime.utcnow)


@dataclass
class OptimizationConfig:
    """Configuration for performance optimization."""
    enable_hardware_acceleration: bool = True
    enable_caching: bool = True
    cache_strategy: CacheStrategy = CacheStrategy.ADAPTIVE
    cache_size_mb: int = 100
    cache_ttl_seconds: int = 3600
    enable_parallel_processing: bool = True
    max_workers: int = 0  # 0 = auto-detect
    batch_size: int = 1024  # bytes
    enable_profiling: bool = True
    profiling_sample_rate: float = 0.1
    memory_limit_mb: int = 500
    adaptive_algorithm_selection: bool = True
    prefer_throughput_over_latency: bool = False


@dataclass
class CacheEntry:
    """Cache entry for encrypted data."""
    key_hash: str
    data_hash: str
    encrypted_data: bytes
    metadata: Dict[str, Any]
    created_at: datetime
    last_accessed: datetime
    access_count: int = 0
    
    def update_access(self):
        """Update access information."""
        self.last_accessed = datetime.utcnow()
        self.access_count += 1


class PerformanceOptimizer:
    """
    Encryption performance optimization system.
    
    Provides comprehensive performance optimization including:
    - Hardware acceleration utilization
    - Intelligent caching with multiple strategies
    - Batch processing and parallel execution
    - Real-time performance monitoring
    - Adaptive algorithm selection
    - Memory usage optimization
    """
    
    def __init__(self, config: Optional[OptimizationConfig] = None):
        """
        Initialize Performance Optimizer.
        
        Args:
            config: Optimization configuration
        """
        self.config = config or OptimizationConfig()
        self.logger = logging.getLogger(__name__)
        
        # Thread safety
        self._lock = threading.RLock()
        
        # Performance metrics storage
        self._metrics_history: List[PerformanceMetrics] = []
        self._current_metrics: Dict[str, PerformanceMetrics] = {}
        
        # Cache management
        self._cache: Dict[str, CacheEntry] = {}
        self._cache_stats = {
            "hits": 0,
            "misses": 0,
            "evictions": 0,
            "size_bytes": 0
        }
        
        # Hardware acceleration detection
        self._available_accelerations: List[AccelerationType] = []
        self._active_acceleration: Optional[AccelerationType] = None
        
        # Worker pools
        self._thread_pool: Optional[ThreadPoolExecutor] = None
        self._process_pool: Optional[ProcessPoolExecutor] = None
        
        # Algorithm performance profiles
        self._algorithm_profiles: Dict[str, Dict[str, float]] = {}
        
        # Initialize optimization features
        self._initialize_optimizer()
        
        self.logger.info("Encryption Performance Optimizer initialized")
    
    def _initialize_optimizer(self):
        """Initialize optimization features."""
        try:
            # Detect hardware acceleration
            self._detect_hardware_acceleration()
            
            # Initialize worker pools
            self._initialize_worker_pools()
            
            # Load algorithm profiles
            self._initialize_algorithm_profiles()
            
            self.logger.info(f"Available accelerations: {[acc.value for acc in self._available_accelerations]}")
            
        except Exception as e:
            self.logger.error(f"Optimizer initialization failed: {e}")
    
    def optimize_encrypt(self, 
                        data: bytes, 
                        algorithm: str, 
                        key: bytes,
                        iv: Optional[bytes] = None,
                        additional_data: Optional[bytes] = None) -> Tuple[bytes, Dict[str, Any]]:
        """
        Perform optimized encryption with caching and acceleration.
        
        Args:
            data: Data to encrypt
            algorithm: Encryption algorithm
            key: Encryption key
            iv: Initialization vector
            additional_data: Additional authenticated data
            
        Returns:
            Tuple of (encrypted_data, metadata)
        """
        start_time = time.time()
        
        try:
            # Check cache first
            if self.config.enable_caching:
                cache_result = self._check_cache(data, algorithm, key, iv)
                if cache_result:
                    self._update_cache_stats("hit")
                    metadata = {
                        "cache_hit": True,
                        "execution_time": time.time() - start_time,
                        "algorithm": algorithm
                    }
                    return cache_result, metadata
                else:
                    self._update_cache_stats("miss")
            
            # Select optimal algorithm variant if adaptive selection enabled
            if self.config.adaptive_algorithm_selection:
                algorithm = self._select_optimal_algorithm(algorithm, len(data))
            
            # Perform encryption with hardware acceleration if available
            if self._active_acceleration and len(data) >= self.config.batch_size:
                encrypted_data = self._encrypt_with_acceleration(
                    data, algorithm, key, iv, additional_data
                )
            else:
                encrypted_data = self._encrypt_standard(
                    data, algorithm, key, iv, additional_data
                )
            
            # Cache result if enabled
            if self.config.enable_caching:
                self._cache_result(data, algorithm, key, iv, encrypted_data)
            
            # Record metrics
            execution_time = time.time() - start_time
            metrics = self._calculate_metrics(
                "encrypt", algorithm, len(data), execution_time
            )
            self._record_metrics(metrics)
            
            metadata = {
                "cache_hit": False,
                "execution_time": execution_time,
                "algorithm": algorithm,
                "acceleration_used": self._active_acceleration.value if self._active_acceleration else None,
                "throughput_mbps": metrics.throughput_mbps
            }
            
            return encrypted_data, metadata
            
        except Exception as e:
            self.logger.error(f"Optimized encryption failed: {e}")
            raise
    
    def optimize_decrypt(self,
                        encrypted_data: bytes,
                        algorithm: str,
                        key: bytes,
                        iv: Optional[bytes] = None,
                        tag: Optional[bytes] = None,
                        additional_data: Optional[bytes] = None) -> Tuple[bytes, Dict[str, Any]]:
        """
        Perform optimized decryption with caching and acceleration.
        
        Args:
            encrypted_data: Data to decrypt
            algorithm: Encryption algorithm
            key: Decryption key
            iv: Initialization vector
            tag: Authentication tag (for AEAD)
            additional_data: Additional authenticated data
            
        Returns:
            Tuple of (decrypted_data, metadata)
        """
        start_time = time.time()
        
        try:
            # Perform decryption with hardware acceleration if available
            if self._active_acceleration and len(encrypted_data) >= self.config.batch_size:
                decrypted_data = self._decrypt_with_acceleration(
                    encrypted_data, algorithm, key, iv, tag, additional_data
                )
            else:
                decrypted_data = self._decrypt_standard(
                    encrypted_data, algorithm, key, iv, tag, additional_data
                )
            
            # Record metrics
            execution_time = time.time() - start_time
            metrics = self._calculate_metrics(
                "decrypt", algorithm, len(encrypted_data), execution_time
            )
            self._record_metrics(metrics)
            
            metadata = {
                "execution_time": execution_time,
                "algorithm": algorithm,
                "acceleration_used": self._active_acceleration.value if self._active_acceleration else None,
                "throughput_mbps": metrics.throughput_mbps
            }
            
            return decrypted_data, metadata
            
        except Exception as e:
            self.logger.error(f"Optimized decryption failed: {e}")
            raise
    
    def batch_encrypt(self, 
                     data_list: List[bytes],
                     algorithm: str,
                     key: bytes) -> List[Tuple[bytes, Dict[str, Any]]]:
        """
        Perform batch encryption with parallel processing.
        
        Args:
            data_list: List of data to encrypt
            algorithm: Encryption algorithm
            key: Encryption key
            
        Returns:
            List of (encrypted_data, metadata) tuples
        """
        if not self.config.enable_parallel_processing or len(data_list) < 2:
            # Sequential processing
            return [self.optimize_encrypt(data, algorithm, key) for data in data_list]
        
        # Parallel processing
        with self._thread_pool as executor:
            futures = [
                executor.submit(self.optimize_encrypt, data, algorithm, key)
                for data in data_list
            ]
            
            results = []
            for future in futures:
                results.append(future.result())
            
            return results
    
    def get_performance_report(self) -> Dict[str, Any]:
        """
        Generate comprehensive performance report.
        
        Returns:
            Performance report dictionary
        """
        with self._lock:
            if not self._metrics_history:
                return {"status": "No performance data available"}
            
            # Calculate statistics
            encrypt_metrics = [m for m in self._metrics_history if m.operation_type == "encrypt"]
            decrypt_metrics = [m for m in self._metrics_history if m.operation_type == "decrypt"]
            
            report = {
                "summary": {
                    "total_operations": len(self._metrics_history),
                    "encrypt_operations": len(encrypt_metrics),
                    "decrypt_operations": len(decrypt_metrics),
                    "measurement_period": {
                        "start": min(m.timestamp for m in self._metrics_history).isoformat(),
                        "end": max(m.timestamp for m in self._metrics_history).isoformat()
                    }
                },
                "performance": {
                    "avg_encrypt_throughput_mbps": statistics.mean([m.throughput_mbps for m in encrypt_metrics]) if encrypt_metrics else 0,
                    "avg_decrypt_throughput_mbps": statistics.mean([m.throughput_mbps for m in decrypt_metrics]) if decrypt_metrics else 0,
                    "avg_encryption_time": statistics.mean([m.execution_time for m in encrypt_metrics]) if encrypt_metrics else 0,
                    "avg_decryption_time": statistics.mean([m.execution_time for m in decrypt_metrics]) if decrypt_metrics else 0,
                    "max_throughput_mbps": max(m.throughput_mbps for m in self._metrics_history),
                    "min_throughput_mbps": min(m.throughput_mbps for m in self._metrics_history)
                },
                "cache": {
                    "enabled": self.config.enable_caching,
                    "strategy": self.config.cache_strategy.value,
                    "hit_rate": self._calculate_cache_hit_rate(),
                    "size_mb": self._cache_stats["size_bytes"] / (1024 * 1024),
                    "entries": len(self._cache),
                    "statistics": self._cache_stats.copy()
                },
                "hardware": {
                    "available_accelerations": [acc.value for acc in self._available_accelerations],
                    "active_acceleration": self._active_acceleration.value if self._active_acceleration else None,
                    "cpu_count": multiprocessing.cpu_count(),
                    "memory_total_gb": psutil.virtual_memory().total / (1024**3)
                },
                "algorithms": self._generate_algorithm_performance_report()
            }
            
            return report
    
    def clear_cache(self):
        """Clear encryption cache."""
        with self._lock:
            self._cache.clear()
            self._cache_stats = {
                "hits": 0,
                "misses": 0,
                "evictions": 0,
                "size_bytes": 0
            }
            self.logger.info("Cache cleared")
    
    def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        return {
            "hit_rate": self._calculate_cache_hit_rate(),
            "size_mb": self._cache_stats["size_bytes"] / (1024 * 1024),
            "entries": len(self._cache),
            "statistics": self._cache_stats.copy()
        }
    
    def _detect_hardware_acceleration(self):
        """Detect available hardware acceleration."""
        try:
            # Check for AES-NI support
            if self._check_aes_ni_support():
                self._available_accelerations.append(AccelerationType.CPU_AES_NI)
                if not self._active_acceleration:
                    self._active_acceleration = AccelerationType.CPU_AES_NI
            
            # Check for GPU acceleration (simplified detection)
            if self._check_gpu_support():
                self._available_accelerations.append(AccelerationType.GPU_CUDA)
            
            # Check for ARM crypto extensions
            if self._check_arm_crypto_support():
                self._available_accelerations.append(AccelerationType.ARM_CRYPTO)
            
        except Exception as e:
            self.logger.warning(f"Hardware acceleration detection failed: {e}")
    
    def _check_aes_ni_support(self) -> bool:
        """Check if CPU supports AES-NI instructions."""
        try:
            # On Linux, check /proc/cpuinfo
            if os.path.exists("/proc/cpuinfo"):
                with open("/proc/cpuinfo", "r") as f:
                    cpuinfo = f.read()
                    return "aes" in cpuinfo
            
            # Simplified detection - assume modern CPUs have AES-NI
            return True
            
        except Exception:
            return False
    
    def _check_gpu_support(self) -> bool:
        """Check for GPU acceleration support."""
        try:
            # Simplified check - in production, use proper GPU detection
            import subprocess
            result = subprocess.run(["nvidia-smi"], capture_output=True, text=True)
            return result.returncode == 0
        except Exception:
            return False
    
    def _check_arm_crypto_support(self) -> bool:
        """Check for ARM crypto extensions."""
        try:
            # Check if running on ARM architecture
            import platform
            return platform.machine().startswith("arm") or platform.machine().startswith("aarch")
        except Exception:
            return False
    
    def _initialize_worker_pools(self):
        """Initialize thread and process pools."""
        if self.config.enable_parallel_processing:
            max_workers = self.config.max_workers or min(32, (os.cpu_count() or 1) + 4)
            self._thread_pool = ThreadPoolExecutor(max_workers=max_workers)
            self._process_pool = ProcessPoolExecutor(max_workers=max_workers // 2)
    
    def _initialize_algorithm_profiles(self):
        """Initialize algorithm performance profiles."""
        # Default performance profiles (throughput in MB/s)
        self._algorithm_profiles = {
            "aes-256-gcm": {"cpu": 200, "aes_ni": 800, "gpu": 1500},
            "aes-256-cbc": {"cpu": 150, "aes_ni": 600, "gpu": 1200},
            "chacha20-poly1305": {"cpu": 300, "aes_ni": 300, "gpu": 800}
        }
    
    def _check_cache(self, 
                    data: bytes, 
                    algorithm: str, 
                    key: bytes, 
                    iv: Optional[bytes]) -> Optional[bytes]:
        """Check if encryption result is cached."""
        cache_key = self._generate_cache_key(data, algorithm, key, iv)
        
        with self._lock:
            if cache_key in self._cache:
                entry = self._cache[cache_key]
                
                # Check TTL if using TTL strategy
                if self.config.cache_strategy == CacheStrategy.TTL:
                    if datetime.utcnow() - entry.created_at > timedelta(seconds=self.config.cache_ttl_seconds):
                        del self._cache[cache_key]
                        return None
                
                entry.update_access()
                return entry.encrypted_data
        
        return None
    
    def _cache_result(self, 
                     data: bytes, 
                     algorithm: str, 
                     key: bytes, 
                     iv: Optional[bytes], 
                     encrypted_data: bytes):
        """Cache encryption result."""
        if not self.config.enable_caching:
            return
        
        cache_key = self._generate_cache_key(data, algorithm, key, iv)
        data_hash = hashlib.sha256(data).hexdigest()
        
        entry = CacheEntry(
            key_hash=cache_key,
            data_hash=data_hash,
            encrypted_data=encrypted_data,
            metadata={"algorithm": algorithm},
            created_at=datetime.utcnow(),
            last_accessed=datetime.utcnow()
        )
        
        with self._lock:
            # Check cache size limits
            entry_size = len(encrypted_data) + len(data)
            if self._cache_stats["size_bytes"] + entry_size > self.config.cache_size_mb * 1024 * 1024:
                self._evict_cache_entries()
            
            self._cache[cache_key] = entry
            self._cache_stats["size_bytes"] += entry_size
    
    def _generate_cache_key(self, 
                           data: bytes, 
                           algorithm: str, 
                           key: bytes, 
                           iv: Optional[bytes]) -> str:
        """Generate cache key for encryption parameters."""
        key_material = data + algorithm.encode() + key
        if iv:
            key_material += iv
        return hashlib.sha256(key_material).hexdigest()
    
    def _evict_cache_entries(self):
        """Evict cache entries based on strategy."""
        if not self._cache:
            return
        
        entries_to_remove = max(1, len(self._cache) // 4)  # Remove 25% of entries
        
        if self.config.cache_strategy == CacheStrategy.LRU:
            # Remove least recently used
            sorted_entries = sorted(
                self._cache.items(),
                key=lambda x: x[1].last_accessed
            )
        elif self.config.cache_strategy == CacheStrategy.LFU:
            # Remove least frequently used
            sorted_entries = sorted(
                self._cache.items(),
                key=lambda x: x[1].access_count
            )
        else:
            # Remove oldest entries
            sorted_entries = sorted(
                self._cache.items(),
                key=lambda x: x[1].created_at
            )
        
        for i in range(entries_to_remove):
            if i < len(sorted_entries):
                key, entry = sorted_entries[i]
                del self._cache[key]
                self._cache_stats["size_bytes"] -= len(entry.encrypted_data)
                self._cache_stats["evictions"] += 1
    
    def _encrypt_with_acceleration(self, 
                                  data: bytes, 
                                  algorithm: str, 
                                  key: bytes,
                                  iv: Optional[bytes],
                                  additional_data: Optional[bytes]) -> bytes:
        """Encrypt using hardware acceleration."""
        # This is a simplified implementation
        # In production, use specific acceleration libraries
        return self._encrypt_standard(data, algorithm, key, iv, additional_data)
    
    def _encrypt_standard(self, 
                         data: bytes, 
                         algorithm: str, 
                         key: bytes,
                         iv: Optional[bytes],
                         additional_data: Optional[bytes]) -> bytes:
        """Standard encryption without acceleration."""
        if algorithm.lower() == "aes-256-gcm":
            if not iv:
                iv = os.urandom(12)
            
            cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            
            if additional_data:
                encryptor.authenticate_additional_data(additional_data)
            
            ciphertext = encryptor.update(data) + encryptor.finalize()
            return iv + encryptor.tag + ciphertext
        
        raise ValueError(f"Unsupported algorithm: {algorithm}")
    
    def _decrypt_with_acceleration(self, 
                                  encrypted_data: bytes, 
                                  algorithm: str, 
                                  key: bytes,
                                  iv: Optional[bytes],
                                  tag: Optional[bytes],
                                  additional_data: Optional[bytes]) -> bytes:
        """Decrypt using hardware acceleration."""
        return self._decrypt_standard(encrypted_data, algorithm, key, iv, tag, additional_data)
    
    def _decrypt_standard(self, 
                         encrypted_data: bytes, 
                         algorithm: str, 
                         key: bytes,
                         iv: Optional[bytes],
                         tag: Optional[bytes],
                         additional_data: Optional[bytes]) -> bytes:
        """Standard decryption without acceleration."""
        if algorithm.lower() == "aes-256-gcm":
            if not iv or not tag:
                # Extract IV and tag from encrypted data
                iv = encrypted_data[:12]
                tag = encrypted_data[12:28]
                ciphertext = encrypted_data[28:]
            else:
                ciphertext = encrypted_data
            
            cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
            decryptor = cipher.decryptor()
            
            if additional_data:
                decryptor.authenticate_additional_data(additional_data)
            
            return decryptor.update(ciphertext) + decryptor.finalize()
        
        raise ValueError(f"Unsupported algorithm: {algorithm}")
    
    def _select_optimal_algorithm(self, algorithm: str, data_size: int) -> str:
        """Select optimal algorithm variant based on performance profiles."""
        # Simplified algorithm selection
        if data_size < 1024:  # Small data
            return algorithm
        elif data_size > 1024 * 1024:  # Large data
            if self._active_acceleration == AccelerationType.CPU_AES_NI:
                return "aes-256-gcm"  # AES-NI optimized
            else:
                return "chacha20-poly1305"  # Better software performance
        
        return algorithm
    
    def _calculate_metrics(self, 
                          operation_type: str, 
                          algorithm: str, 
                          data_size: int, 
                          execution_time: float) -> PerformanceMetrics:
        """Calculate performance metrics."""
        throughput_mbps = (data_size / (1024 * 1024)) / execution_time if execution_time > 0 else 0
        
        return PerformanceMetrics(
            operation_type=operation_type,
            algorithm=algorithm,
            data_size=data_size,
            execution_time=execution_time,
            throughput_mbps=throughput_mbps,
            cpu_usage=psutil.cpu_percent(),
            memory_usage=psutil.virtual_memory().used,
            cache_hit_rate=self._calculate_cache_hit_rate(),
            acceleration_used=self._active_acceleration
        )
    
    def _record_metrics(self, metrics: PerformanceMetrics):
        """Record performance metrics."""
        with self._lock:
            self._metrics_history.append(metrics)
            
            # Keep only recent metrics to prevent memory growth
            max_history = 1000
            if len(self._metrics_history) > max_history:
                self._metrics_history = self._metrics_history[-max_history:]
    
    def _update_cache_stats(self, result: str):
        """Update cache statistics."""
        with self._lock:
            if result == "hit":
                self._cache_stats["hits"] += 1
            elif result == "miss":
                self._cache_stats["misses"] += 1
    
    def _calculate_cache_hit_rate(self) -> float:
        """Calculate cache hit rate."""
        total_requests = self._cache_stats["hits"] + self._cache_stats["misses"]
        if total_requests == 0:
            return 0.0
        return self._cache_stats["hits"] / total_requests
    
    def _generate_algorithm_performance_report(self) -> Dict[str, Any]:
        """Generate algorithm-specific performance report."""
        algorithm_stats = {}
        
        for metrics in self._metrics_history:
            alg = metrics.algorithm
            if alg not in algorithm_stats:
                algorithm_stats[alg] = {
                    "operations": 0,
                    "total_time": 0,
                    "total_data": 0,
                    "throughputs": []
                }
            
            stats = algorithm_stats[alg]
            stats["operations"] += 1
            stats["total_time"] += metrics.execution_time
            stats["total_data"] += metrics.data_size
            stats["throughputs"].append(metrics.throughput_mbps)
        
        # Calculate averages
        for alg, stats in algorithm_stats.items():
            stats["avg_time"] = stats["total_time"] / stats["operations"]
            stats["avg_throughput"] = statistics.mean(stats["throughputs"])
            stats["max_throughput"] = max(stats["throughputs"])
            stats["min_throughput"] = min(stats["throughputs"])
            del stats["throughputs"]  # Remove raw data
        
        return algorithm_stats
    
    def __del__(self):
        """Cleanup resources."""
        if self._thread_pool:
            self._thread_pool.shutdown(wait=False)
        if self._process_pool:
            self._process_pool.shutdown(wait=False)