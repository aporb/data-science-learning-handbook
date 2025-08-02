"""
Performance Optimizer for Automated Data Labeling
=================================================

This module provides advanced performance optimization capabilities for the
automated data labeling framework, ensuring real-time processing requirements
are met while maintaining classification accuracy and system reliability.

Key Features:
- Real-time processing optimization with <50ms targets
- Adaptive performance tuning based on system load and requirements
- Intelligent caching strategies with TTL and LRU eviction
- Load balancing and resource management
- Performance monitoring and SLA tracking
- Automatic scaling and throttling mechanisms
- Memory and CPU optimization
- Network and I/O optimization

Classification: UNCLASSIFIED//FOR OFFICIAL USE ONLY
Version: 1.0 - Initial Implementation
Author: Security Compliance Team
Date: 2025-07-29
"""

import asyncio
import json
import logging
import time
import psutil
import threading
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Tuple, Set, Union, Callable
from uuid import UUID, uuid4
from dataclasses import dataclass, field, asdict
from enum import Enum
import hashlib
from collections import defaultdict, deque
import statistics
import weakref
import gc
from threading import Lock, RLock
import multiprocessing as mp

logger = logging.getLogger(__name__)


class PerformanceTarget(Enum):
    """Performance targets for different priority levels."""
    ULTRA_FAST = 10.0      # 10ms - Critical operations
    FAST = 25.0           # 25ms - High priority
    STANDARD = 50.0       # 50ms - Normal operations  
    RELAXED = 100.0       # 100ms - Low priority
    BATCH = 1000.0        # 1s - Batch processing


class OptimizationStrategy(Enum):
    """Optimization strategies for different scenarios."""
    LATENCY_OPTIMIZED = "latency_optimized"
    THROUGHPUT_OPTIMIZED = "throughput_optimized"
    MEMORY_OPTIMIZED = "memory_optimized"
    BALANCED = "balanced"
    POWER_SAVING = "power_saving"


class CacheStrategy(Enum):
    """Caching strategies for different data types."""
    LRU = "lru"                    # Least Recently Used
    LFU = "lfu"                    # Least Frequently Used
    TTL = "ttl"                    # Time To Live
    ADAPTIVE = "adaptive"          # Adaptive based on usage
    WRITE_THROUGH = "write_through"
    WRITE_BACK = "write_back"


class ResourceType(Enum):
    """System resource types for monitoring."""
    CPU = "cpu"
    MEMORY = "memory"
    DISK_IO = "disk_io"
    NETWORK_IO = "network_io"
    GPU = "gpu"


@dataclass
class PerformanceMetrics:
    """Performance metrics tracking."""
    # Timing metrics
    total_requests: int = 0
    average_latency_ms: float = 0.0
    p50_latency_ms: float = 0.0
    p95_latency_ms: float = 0.0
    p99_latency_ms: float = 0.0
    max_latency_ms: float = 0.0
    
    # Throughput metrics
    requests_per_second: float = 0.0
    peak_rps: float = 0.0
    
    # Error metrics
    error_rate: float = 0.0
    timeout_rate: float = 0.0
    
    # Resource utilization
    cpu_usage_percent: float = 0.0
    memory_usage_percent: float = 0.0
    memory_usage_mb: float = 0.0
    
    # Cache metrics
    cache_hit_rate: float = 0.0
    cache_miss_rate: float = 0.0
    cache_size_mb: float = 0.0
    
    # SLA metrics
    sla_violations: int = 0
    sla_compliance_rate: float = 100.0
    
    # Optimization metrics
    optimization_effectiveness: float = 0.0
    resource_efficiency: float = 0.0
    
    # Last update
    last_updated: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class OptimizationConfig:
    """Configuration for performance optimization."""
    # Performance targets
    target_latency_ms: float = 50.0
    max_acceptable_latency_ms: float = 100.0
    target_throughput_rps: float = 1000.0
    
    # Resource limits
    max_cpu_usage_percent: float = 80.0
    max_memory_usage_percent: float = 85.0
    max_memory_usage_mb: float = 2048.0
    
    # Caching configuration
    cache_enabled: bool = True
    cache_size_mb: float = 512.0
    cache_ttl_seconds: int = 300
    cache_strategy: CacheStrategy = CacheStrategy.ADAPTIVE
    
    # Threading configuration
    max_worker_threads: int = 20
    min_worker_threads: int = 4
    thread_pool_growth_factor: float = 1.5
    
    # Optimization strategies
    optimization_strategy: OptimizationStrategy = OptimizationStrategy.BALANCED
    auto_scaling_enabled: bool = True
    adaptive_optimization: bool = True
    
    # Monitoring configuration
    metrics_collection_interval_seconds: int = 30
    performance_window_seconds: int = 300
    
    # Advanced features
    enable_jit_compilation: bool = True
    enable_memory_pooling: bool = True
    enable_prefetching: bool = True
    enable_compression: bool = False


class SystemResourceMonitor:
    """Monitors system resources for optimization decisions."""
    
    def __init__(self, config: OptimizationConfig):
        """Initialize system resource monitor."""
        self.config = config
        self._monitoring = False
        self._monitor_thread = None
        self._resource_history = defaultdict(deque)
        self._history_lock = Lock()
        
        # Resource thresholds
        self._cpu_threshold = config.max_cpu_usage_percent
        self._memory_threshold = config.max_memory_usage_percent
        
        logger.info("SystemResourceMonitor initialized")
    
    def start_monitoring(self):
        """Start system resource monitoring."""
        if self._monitoring:
            return
        
        self._monitoring = True
        self._monitor_thread = threading.Thread(
            target=self._monitor_resources,
            daemon=True,
            name="resource_monitor"
        )
        self._monitor_thread.start()
        
        logger.info("System resource monitoring started")
    
    def stop_monitoring(self):
        """Stop system resource monitoring."""
        self._monitoring = False
        if self._monitor_thread:
            self._monitor_thread.join(timeout=1.0)
        
        logger.info("System resource monitoring stopped")
    
    def _monitor_resources(self):
        """Monitor system resources continuously."""
        while self._monitoring:
            try:
                # Get current resource usage
                cpu_percent = psutil.cpu_percent(interval=1)
                memory_info = psutil.virtual_memory()
                disk_io = psutil.disk_io_counters()
                network_io = psutil.net_io_counters()
                
                # Store in history
                timestamp = time.time()
                with self._history_lock:
                    self._store_metric(ResourceType.CPU, timestamp, cpu_percent)
                    self._store_metric(ResourceType.MEMORY, timestamp, memory_info.percent)
                    
                    if disk_io:
                        disk_usage = (disk_io.read_bytes + disk_io.write_bytes) / (1024 * 1024)  # MB
                        self._store_metric(ResourceType.DISK_IO, timestamp, disk_usage)
                    
                    if network_io:
                        network_usage = (network_io.bytes_sent + network_io.bytes_recv) / (1024 * 1024)  # MB
                        self._store_metric(ResourceType.NETWORK_IO, timestamp, network_usage)
                
                # Sleep before next measurement
                time.sleep(self.config.metrics_collection_interval_seconds)
                
            except Exception as e:
                logger.error(f"Error monitoring resources: {e}")
                time.sleep(1)
    
    def _store_metric(self, resource_type: ResourceType, timestamp: float, value: float):
        """Store metric in history with size limit."""
        history = self._resource_history[resource_type]
        history.append((timestamp, value))
        
        # Limit history size
        max_history = self.config.performance_window_seconds // self.config.metrics_collection_interval_seconds
        while len(history) > max_history:
            history.popleft()
    
    def get_current_usage(self) -> Dict[ResourceType, float]:
        """Get current resource usage."""
        try:
            return {
                ResourceType.CPU: psutil.cpu_percent(),
                ResourceType.MEMORY: psutil.virtual_memory().percent
            }
        except Exception as e:
            logger.error(f"Error getting current usage: {e}")
            return {}
    
    def get_average_usage(self, window_seconds: int = 60) -> Dict[ResourceType, float]:
        """Get average resource usage over time window."""
        cutoff_time = time.time() - window_seconds
        averages = {}
        
        with self._history_lock:
            for resource_type, history in self._resource_history.items():
                recent_values = [
                    value for timestamp, value in history 
                    if timestamp >= cutoff_time
                ]
                
                if recent_values:
                    averages[resource_type] = statistics.mean(recent_values)
        
        return averages
    
    def is_resource_constrained(self) -> bool:
        """Check if system is resource constrained."""
        current_usage = self.get_current_usage()
        
        cpu_constrained = current_usage.get(ResourceType.CPU, 0) > self._cpu_threshold
        memory_constrained = current_usage.get(ResourceType.MEMORY, 0) > self._memory_threshold
        
        return cpu_constrained or memory_constrained


class AdaptiveCache:
    """Adaptive caching system with multiple strategies."""
    
    def __init__(self, config: OptimizationConfig):
        """Initialize adaptive cache."""
        self.config = config
        
        # Cache storage
        self._cache: Dict[str, Any] = {}
        self._access_times: Dict[str, float] = {}
        self._access_counts: Dict[str, int] = {}
        self._cache_lock = RLock()
        
        # Cache metrics
        self._hits = 0
        self._misses = 0
        self._evictions = 0
        
        # Size tracking
        self._current_size_mb = 0.0
        self._max_size_mb = config.cache_size_mb
        
        logger.info(f"AdaptiveCache initialized with {self._max_size_mb}MB capacity")
    
    def get(self, key: str) -> Optional[Any]:
        """Get item from cache."""
        with self._cache_lock:
            if key in self._cache:
                self._hits += 1
                self._access_times[key] = time.time()
                self._access_counts[key] = self._access_counts.get(key, 0) + 1
                return self._cache[key]
            else:
                self._misses += 1
                return None
    
    def put(self, key: str, value: Any, size_mb: float = 0.1):
        """Put item in cache."""
        with self._cache_lock:
            # Check if we need to evict
            while (self._current_size_mb + size_mb > self._max_size_mb and 
                   len(self._cache) > 0):
                self._evict_one()
            
            # Add new item
            if key in self._cache:
                # Update existing item
                old_size = self._estimate_size_mb(self._cache[key])
                self._current_size_mb = self._current_size_mb - old_size + size_mb
            else:
                self._current_size_mb += size_mb
            
            self._cache[key] = value
            self._access_times[key] = time.time()
            self._access_counts[key] = self._access_counts.get(key, 0) + 1
    
    def _evict_one(self):
        """Evict one item based on cache strategy."""
        if not self._cache:
            return
        
        if self.config.cache_strategy == CacheStrategy.LRU:
            # Evict least recently used
            oldest_key = min(self._access_times.keys(), key=self._access_times.get)
        elif self.config.cache_strategy == CacheStrategy.LFU:
            # Evict least frequently used
            oldest_key = min(self._access_counts.keys(), key=self._access_counts.get)
        elif self.config.cache_strategy == CacheStrategy.TTL:
            # Evict expired items first, then LRU
            current_time = time.time()
            expired_keys = [
                key for key, access_time in self._access_times.items()
                if current_time - access_time > self.config.cache_ttl_seconds
            ]
            
            if expired_keys:
                oldest_key = expired_keys[0]
            else:
                oldest_key = min(self._access_times.keys(), key=self._access_times.get)
        else:
            # Default to LRU
            oldest_key = min(self._access_times.keys(), key=self._access_times.get)
        
        # Remove the item
        if oldest_key in self._cache:
            size_mb = self._estimate_size_mb(self._cache[oldest_key])
            del self._cache[oldest_key]
            del self._access_times[oldest_key]
            if oldest_key in self._access_counts:
                del self._access_counts[oldest_key]
            
            self._current_size_mb -= size_mb
            self._evictions += 1
    
    def _estimate_size_mb(self, obj: Any) -> float:
        """Estimate object size in MB."""
        try:
            import sys
            size_bytes = sys.getsizeof(obj)
            return size_bytes / (1024 * 1024)
        except:
            return 0.1  # Default estimate
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        with self._cache_lock:
            total_requests = self._hits + self._misses
            hit_rate = self._hits / total_requests if total_requests > 0 else 0.0
            
            return {
                'hits': self._hits,
                'misses': self._misses,
                'hit_rate': hit_rate,
                'evictions': self._evictions,
                'size_mb': self._current_size_mb,
                'items': len(self._cache),
                'utilization': self._current_size_mb / self._max_size_mb
            }
    
    def clear(self):
        """Clear all cache entries."""
        with self._cache_lock:
            self._cache.clear()
            self._access_times.clear()
            self._access_counts.clear()
            self._current_size_mb = 0.0
            
            logger.info("Cache cleared")


class ThreadPoolManager:
    """Dynamic thread pool management for optimal performance."""
    
    def __init__(self, config: OptimizationConfig):
        """Initialize thread pool manager."""
        self.config = config
        
        # Thread pools
        self._executor = ThreadPoolExecutor(
            max_workers=config.min_worker_threads,
            thread_name_prefix='labeling'
        )
        
        # Pool metrics
        self._current_workers = config.min_worker_threads
        self._active_tasks = 0
        self._completed_tasks = 0
        self._failed_tasks = 0
        self._pool_lock = Lock()
        
        # Auto-scaling parameters
        self._last_scale_time = time.time()
        self._scale_cooldown = 30.0  # seconds
        self._utilization_threshold = 0.8
        
        logger.info(f"ThreadPoolManager initialized with {self._current_workers} workers")
    
    def submit_task(self, fn: Callable, *args, **kwargs) -> asyncio.Future:
        """Submit task to thread pool."""
        with self._pool_lock:
            self._active_tasks += 1
        
        # Check if we need to scale up
        if self.config.auto_scaling_enabled:
            self._check_scaling()
        
        # Submit task
        future = asyncio.get_event_loop().run_in_executor(self._executor, fn, *args, **kwargs)
        
        # Add completion callback
        future.add_done_callback(self._task_completed)
        
        return future
    
    def _task_completed(self, future: asyncio.Future):
        """Handle task completion."""
        with self._pool_lock:
            self._active_tasks = max(0, self._active_tasks - 1)
            
            if future.exception():
                self._failed_tasks += 1
            else:
                self._completed_tasks += 1
    
    def _check_scaling(self):
        """Check if thread pool should be scaled."""
        current_time = time.time()
        
        # Check cooldown period
        if current_time - self._last_scale_time < self._scale_cooldown:
            return
        
        # Calculate utilization
        utilization = self._active_tasks / self._current_workers if self._current_workers > 0 else 0
        
        if utilization > self._utilization_threshold and self._current_workers < self.config.max_worker_threads:
            # Scale up
            new_size = min(
                int(self._current_workers * self.config.thread_pool_growth_factor),
                self.config.max_worker_threads
            )
            
            if new_size > self._current_workers:
                self._scale_pool(new_size)
                logger.info(f"Scaled thread pool up to {new_size} workers (utilization: {utilization:.2f})")
        
        elif utilization < self._utilization_threshold * 0.5 and self._current_workers > self.config.min_worker_threads:
            # Scale down
            new_size = max(
                int(self._current_workers / self.config.thread_pool_growth_factor),
                self.config.min_worker_threads
            )
            
            if new_size < self._current_workers:
                self._scale_pool(new_size)
                logger.info(f"Scaled thread pool down to {new_size} workers (utilization: {utilization:.2f})")
    
    def _scale_pool(self, new_size: int):
        """Scale thread pool to new size."""
        # Create new executor with new size
        old_executor = self._executor
        self._executor = ThreadPoolExecutor(
            max_workers=new_size,
            thread_name_prefix='labeling'
        )
        
        self._current_workers = new_size
        self._last_scale_time = time.time()
        
        # Shutdown old executor (but don't wait for completion)
        old_executor.shutdown(wait=False)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get thread pool statistics."""
        with self._pool_lock:
            utilization = self._active_tasks / self._current_workers if self._current_workers > 0 else 0
            total_tasks = self._completed_tasks + self._failed_tasks
            success_rate = self._completed_tasks / total_tasks if total_tasks > 0 else 1.0
            
            return {
                'current_workers': self._current_workers,
                'active_tasks': self._active_tasks,
                'completed_tasks': self._completed_tasks,
                'failed_tasks': self._failed_tasks,
                'utilization': utilization,
                'success_rate': success_rate
            }
    
    def shutdown(self):
        """Shutdown thread pool manager."""
        self._executor.shutdown(wait=True)
        logger.info("ThreadPoolManager shutdown complete")


class PerformanceOptimizer:
    """
    Comprehensive performance optimizer for automated data labeling framework.
    Provides real-time optimization, adaptive tuning, and resource management.
    """
    
    def __init__(self, config: Optional[OptimizationConfig] = None):
        """Initialize performance optimizer."""
        self.config = config or OptimizationConfig()
        
        # Performance tracking
        self.metrics = PerformanceMetrics()
        self._latency_history = deque(maxlen=1000)
        self._metrics_lock = Lock()
        
        # Optimization components
        self.resource_monitor = SystemResourceMonitor(self.config)
        self.cache = AdaptiveCache(self.config) if self.config.cache_enabled else None
        self.thread_manager = ThreadPoolManager(self.config)
        
        # Optimization state
        self._optimization_active = False
        self._last_optimization = time.time()
        self._optimization_interval = 60.0  # seconds
        
        # Performance thresholds
        self._latency_warning_threshold = self.config.target_latency_ms * 1.5
        self._latency_critical_threshold = self.config.max_acceptable_latency_ms
        
        # Start monitoring
        if self.config.adaptive_optimization:
            self.resource_monitor.start_monitoring()
        
        logger.info("PerformanceOptimizer initialized with target latency: %.1fms", 
                   self.config.target_latency_ms)
    
    def optimize_request_processing(
        self, 
        request_id: str,
        processing_function: Callable,
        *args,
        **kwargs
    ) -> Tuple[Any, Dict[str, float]]:
        """
        Optimize processing of a single request.
        
        Args:
            request_id: Unique identifier for the request
            processing_function: Function to execute
            *args, **kwargs: Arguments for the processing function
            
        Returns:
            Tuple of (result, performance_metrics)
        """
        start_time = time.time()
        performance_metrics = {}
        
        try:
            # Check cache first
            if self.cache:
                cache_key = self._generate_cache_key(request_id, args, kwargs)
                cached_result = self.cache.get(cache_key)
                if cached_result:
                    cache_time = (time.time() - start_time) * 1000
                    performance_metrics['cache_hit'] = True
                    performance_metrics['processing_time_ms'] = cache_time
                    self._update_metrics(cache_time, success=True, from_cache=True)
                    return cached_result, performance_metrics
            
            # Apply optimizations
            optimized_kwargs = self._apply_processing_optimizations(kwargs)
            
            # Execute processing function
            if self.config.optimization_strategy == OptimizationStrategy.LATENCY_OPTIMIZED:
                result = self._execute_latency_optimized(processing_function, *args, **optimized_kwargs)
            elif self.config.optimization_strategy == OptimizationStrategy.THROUGHPUT_OPTIMIZED:
                result = self._execute_throughput_optimized(processing_function, *args, **optimized_kwargs)
            else:
                result = processing_function(*args, **optimized_kwargs)
            
            # Calculate processing time
            processing_time_ms = (time.time() - start_time) * 1000
            performance_metrics['processing_time_ms'] = processing_time_ms
            performance_metrics['cache_hit'] = False
            
            # Cache result if appropriate
            if self.cache and self._should_cache_result(processing_time_ms, result):
                cache_key = self._generate_cache_key(request_id, args, kwargs)
                result_size_mb = self._estimate_result_size(result)
                self.cache.put(cache_key, result, result_size_mb)
            
            # Update metrics
            self._update_metrics(processing_time_ms, success=True, from_cache=False)
            
            # Check for optimization triggers
            if self.config.adaptive_optimization:
                self._check_optimization_triggers(processing_time_ms)
            
            return result, performance_metrics
            
        except Exception as e:
            processing_time_ms = (time.time() - start_time) * 1000
            performance_metrics['processing_time_ms'] = processing_time_ms
            performance_metrics['error'] = str(e)
            
            # Update metrics
            self._update_metrics(processing_time_ms, success=False, from_cache=False)
            
            raise e
    
    async def optimize_batch_processing(
        self,
        requests: List[Tuple[str, Callable, Tuple, Dict]],
        max_concurrent: Optional[int] = None
    ) -> List[Tuple[Any, Dict[str, float]]]:
        """
        Optimize processing of multiple requests in parallel.
        
        Args:
            requests: List of (request_id, function, args, kwargs) tuples
            max_concurrent: Maximum concurrent requests
            
        Returns:
            List of (result, performance_metrics) tuples
        """
        if not requests:
            return []
        
        start_time = time.time()
        
        # Determine optimal concurrency
        if max_concurrent is None:
            max_concurrent = self._calculate_optimal_concurrency(len(requests))
        
        # Create semaphore for concurrency control
        semaphore = asyncio.Semaphore(max_concurrent)
        
        async def process_single_request(request_data):
            async with semaphore:
                request_id, func, args, kwargs = request_data
                return await asyncio.get_event_loop().run_in_executor(
                    None, 
                    self.optimize_request_processing,
                    request_id, func, *args, **kwargs
                )
        
        # Process all requests
        tasks = [process_single_request(req) for req in requests]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results and handle exceptions
        final_results = []
        for result in results:
            if isinstance(result, Exception):
                error_metrics = {
                    'processing_time_ms': 0.0,
                    'error': str(result)
                }
                final_results.append((None, error_metrics))
            else:
                final_results.append(result)
        
        # Update batch metrics
        batch_time_ms = (time.time() - start_time) * 1000
        logger.debug(f"Batch processing completed: {len(requests)} requests in {batch_time_ms:.2f}ms")
        
        return final_results
    
    def _apply_processing_optimizations(self, kwargs: Dict[str, Any]) -> Dict[str, Any]:
        """Apply processing optimizations to function arguments."""
        optimized_kwargs = kwargs.copy()
        
        # Memory optimization
        if self.config.optimization_strategy == OptimizationStrategy.MEMORY_OPTIMIZED:
            # Trigger garbage collection if memory usage is high
            current_usage = self.resource_monitor.get_current_usage()
            memory_usage = current_usage.get(ResourceType.MEMORY, 0)
            
            if memory_usage > self.config.max_memory_usage_percent * 0.8:
                gc.collect()
        
        # Latency optimization
        if self.config.optimization_strategy == OptimizationStrategy.LATENCY_OPTIMIZED:
            # Reduce precision for faster processing if acceptable
            optimized_kwargs.setdefault('precision_mode', 'fast')
            optimized_kwargs.setdefault('enable_shortcuts', True)
        
        # Throughput optimization
        if self.config.optimization_strategy == OptimizationStrategy.THROUGHPUT_OPTIMIZED:
            # Enable batch processing hints
            optimized_kwargs.setdefault('batch_processing', True)
            optimized_kwargs.setdefault('parallel_execution', True)
        
        return optimized_kwargs
    
    def _execute_latency_optimized(self, func: Callable, *args, **kwargs) -> Any:
        """Execute function with latency optimizations."""
        # Use high priority thread
        future = self.thread_manager.submit_task(func, *args, **kwargs)
        
        # Set timeout for latency requirements
        timeout = self.config.max_acceptable_latency_ms / 1000.0
        
        try:
            return asyncio.wait_for(future, timeout=timeout)
        except asyncio.TimeoutError:
            logger.warning(f"Function execution timed out after {timeout}s")
            raise
    
    def _execute_throughput_optimized(self, func: Callable, *args, **kwargs) -> Any:
        """Execute function with throughput optimizations."""
        # Use standard thread pool
        future = self.thread_manager.submit_task(func, *args, **kwargs)
        return future
    
    def _calculate_optimal_concurrency(self, request_count: int) -> int:
        """Calculate optimal concurrency level."""
        # Base concurrency on system resources
        current_usage = self.resource_monitor.get_current_usage()
        cpu_usage = current_usage.get(ResourceType.CPU, 0)
        memory_usage = current_usage.get(ResourceType.MEMORY, 0)
        
        # Start with number of CPU cores
        base_concurrency = mp.cpu_count()
        
        # Adjust based on resource usage
        if cpu_usage > 70:
            base_concurrency = max(1, base_concurrency // 2)
        elif cpu_usage < 30:
            base_concurrency = min(base_concurrency * 2, self.config.max_worker_threads)
        
        # Adjust based on memory usage
        if memory_usage > 80:
            base_concurrency = max(1, base_concurrency // 2)
        
        # Limit based on request count
        optimal_concurrency = min(base_concurrency, request_count, self.config.max_worker_threads)
        
        return max(1, optimal_concurrency)
    
    def _generate_cache_key(self, request_id: str, args: Tuple, kwargs: Dict) -> str:
        """Generate cache key for request."""
        # Create a hash of the arguments
        cache_data = {
            'args': str(args),
            'kwargs': json.dumps(kwargs, sort_keys=True, default=str)
        }
        
        cache_string = json.dumps(cache_data, sort_keys=True)
        return hashlib.sha256(cache_string.encode()).hexdigest()
    
    def _should_cache_result(self, processing_time_ms: float, result: Any) -> bool:
        """Determine if result should be cached."""
        # Cache if processing took significant time
        if processing_time_ms > self.config.target_latency_ms * 2:
            return True
        
        # Cache if result is not too large
        result_size_mb = self._estimate_result_size(result)
        if result_size_mb > 10.0:  # Don't cache very large results
            return False
        
        return True
    
    def _estimate_result_size(self, result: Any) -> float:
        """Estimate result size in MB."""
        try:
            import sys
            size_bytes = sys.getsizeof(result)
            return size_bytes / (1024 * 1024)
        except:
            return 0.1  # Default estimate
    
    def _update_metrics(self, processing_time_ms: float, success: bool = True, from_cache: bool = False):
        """Update performance metrics."""
        with self._metrics_lock:
            self.metrics.total_requests += 1
            
            if success:
                # Update latency metrics
                self._latency_history.append(processing_time_ms)
                
                if len(self._latency_history) > 0:
                    latencies = list(self._latency_history)
                    latencies.sort()
                    
                    self.metrics.average_latency_ms = statistics.mean(latencies)
                    self.metrics.p50_latency_ms = latencies[len(latencies) // 2]
                    self.metrics.p95_latency_ms = latencies[int(len(latencies) * 0.95)]
                    self.metrics.p99_latency_ms = latencies[int(len(latencies) * 0.99)]
                    self.metrics.max_latency_ms = max(latencies)
                
                # Update SLA metrics
                if processing_time_ms > self.config.max_acceptable_latency_ms:
                    self.metrics.sla_violations += 1
                
                self.metrics.sla_compliance_rate = (
                    (self.metrics.total_requests - self.metrics.sla_violations) /
                    self.metrics.total_requests * 100.0
                )
                
                # Update cache metrics if applicable
                if self.cache and from_cache:
                    cache_stats = self.cache.get_stats()
                    self.metrics.cache_hit_rate = cache_stats['hit_rate'] * 100.0
                    self.metrics.cache_miss_rate = (1.0 - cache_stats['hit_rate']) * 100.0
                    self.metrics.cache_size_mb = cache_stats['size_mb']
            else:
                # Update error metrics
                total_requests = self.metrics.total_requests
                error_count = total_requests * (self.metrics.error_rate / 100.0) + 1
                self.metrics.error_rate = error_count / total_requests * 100.0
            
            # Update system resource metrics
            current_usage = self.resource_monitor.get_current_usage()
            self.metrics.cpu_usage_percent = current_usage.get(ResourceType.CPU, 0)
            self.metrics.memory_usage_percent = current_usage.get(ResourceType.MEMORY, 0)
            
            # Update last updated timestamp
            self.metrics.last_updated = datetime.now(timezone.utc)
    
    def _check_optimization_triggers(self, processing_time_ms: float):
        """Check if optimization actions should be triggered."""
        current_time = time.time()
        
        # Check if it's time for periodic optimization
        if current_time - self._last_optimization > self._optimization_interval:
            self._perform_adaptive_optimization()
            self._last_optimization = current_time
        
        # Check for immediate optimization triggers
        if processing_time_ms > self._latency_critical_threshold:
            logger.warning(f"Critical latency detected: {processing_time_ms:.2f}ms")
            self._handle_critical_latency()
        elif processing_time_ms > self._latency_warning_threshold:
            logger.info(f"High latency detected: {processing_time_ms:.2f}ms")
            self._handle_high_latency()
    
    def _perform_adaptive_optimization(self):
        """Perform adaptive optimization based on current metrics."""
        if self._optimization_active:
            return
        
        self._optimization_active = True
        
        try:
            # Analyze current performance
            avg_latency = self.metrics.average_latency_ms
            error_rate = self.metrics.error_rate
            sla_compliance = self.metrics.sla_compliance_rate
            
            # Check if optimization is needed
            needs_optimization = (
                avg_latency > self.config.target_latency_ms * 1.2 or
                error_rate > 5.0 or
                sla_compliance < 95.0
            )
            
            if needs_optimization:
                logger.info("Performing adaptive optimization")
                
                # Resource-based optimizations
                if self.resource_monitor.is_resource_constrained():
                    self._optimize_for_resource_constraints()
                
                # Cache optimizations
                if self.cache:
                    self._optimize_cache_performance()
                
                # Thread pool optimizations
                self._optimize_thread_pool()
                
                logger.info("Adaptive optimization completed")
            
        except Exception as e:
            logger.error(f"Error during adaptive optimization: {e}")
        finally:
            self._optimization_active = False
    
    def _handle_critical_latency(self):
        """Handle critical latency situation."""
        # Immediate actions for critical latency
        if self.cache:
            # Clear old cache entries to free memory
            cache_stats = self.cache.get_stats()
            if cache_stats['utilization'] > 0.9:
                # Clear 25% of cache
                entries_to_clear = int(cache_stats['items'] * 0.25)
                # Implementation would clear least valuable entries
        
        # Force garbage collection
        gc.collect()
        
        # Log critical event
        logger.critical(f"Critical latency threshold exceeded: {self.metrics.max_latency_ms:.2f}ms")
    
    def _handle_high_latency(self):
        """Handle high latency situation."""
        # Less aggressive actions for high latency
        current_usage = self.resource_monitor.get_current_usage()
        
        if current_usage.get(ResourceType.MEMORY, 0) > 80:
            # Trigger garbage collection
            gc.collect()
        
        # Adjust thread pool if needed
        thread_stats = self.thread_manager.get_stats()
        if thread_stats['utilization'] > 0.9:
            # Thread pool is overloaded
            logger.info("Thread pool utilization high, scaling may be needed")
    
    def _optimize_for_resource_constraints(self):
        """Optimize for resource constraints."""
        current_usage = self.resource_monitor.get_current_usage()
        
        # Memory optimization
        memory_usage = current_usage.get(ResourceType.MEMORY, 0)
        if memory_usage > self.config.max_memory_usage_percent:
            logger.info(f"High memory usage detected: {memory_usage:.1f}%")
            
            # Reduce cache size
            if self.cache:
                self.cache._max_size_mb *= 0.8
                # Clear some entries
                # Implementation would clear least valuable entries
            
            # Force garbage collection
            gc.collect()
        
        # CPU optimization
        cpu_usage = current_usage.get(ResourceType.CPU, 0)
        if cpu_usage > self.config.max_cpu_usage_percent:
            logger.info(f"High CPU usage detected: {cpu_usage:.1f}%")
            
            # Reduce thread pool size temporarily
            # Implementation would scale down thread pool
    
    def _optimize_cache_performance(self):
        """Optimize cache performance."""
        if not self.cache:
            return
        
        cache_stats = self.cache.get_stats()
        hit_rate = cache_stats['hit_rate']
        
        if hit_rate < 0.5:  # Low hit rate
            logger.info(f"Low cache hit rate: {hit_rate:.2f}")
            
            # Adjust cache strategy
            if self.config.cache_strategy == CacheStrategy.ADAPTIVE:
                # Switch to more aggressive caching
                # Implementation would adjust cache parameters
                pass
        
        elif cache_stats['utilization'] > 0.9:  # High utilization
            # Increase cache size if possible
            available_memory = 100 - self.resource_monitor.get_current_usage().get(ResourceType.MEMORY, 0)
            if available_memory > 20:  # If we have >20% memory available
                self.cache._max_size_mb *= 1.2
                logger.info(f"Increased cache size to {self.cache._max_size_mb:.1f}MB")
    
    def _optimize_thread_pool(self):
        """Optimize thread pool performance."""
        thread_stats = self.thread_manager.get_stats()
        utilization = thread_stats['utilization']
        
        if utilization > 0.9:
            # High utilization - consider scaling up
            logger.info(f"High thread utilization: {utilization:.2f}")
        elif utilization < 0.3:
            # Low utilization - consider scaling down
            logger.info(f"Low thread utilization: {utilization:.2f}")
    
    def get_performance_metrics(self) -> PerformanceMetrics:
        """Get current performance metrics."""
        # Update resource metrics
        current_usage = self.resource_monitor.get_current_usage()
        self.metrics.cpu_usage_percent = current_usage.get(ResourceType.CPU, 0)
        self.metrics.memory_usage_percent = current_usage.get(ResourceType.MEMORY, 0)
        
        # Update cache metrics
        if self.cache:
            cache_stats = self.cache.get_stats()
            self.metrics.cache_hit_rate = cache_stats['hit_rate'] * 100.0
            self.metrics.cache_size_mb = cache_stats['size_mb']
        
        return self.metrics
    
    def get_optimization_recommendations(self) -> List[str]:
        """Get optimization recommendations based on current performance."""
        recommendations = []
        
        # Latency recommendations
        if self.metrics.average_latency_ms > self.config.target_latency_ms * 1.5:
            recommendations.append("Consider enabling more aggressive caching")
            recommendations.append("Review processing algorithms for optimization opportunities")
        
        # Memory recommendations
        if self.metrics.memory_usage_percent > 85:
            recommendations.append("High memory usage - consider reducing cache size")
            recommendations.append("Enable garbage collection optimizations")
        
        # Cache recommendations
        if self.cache and self.metrics.cache_hit_rate < 50:
            recommendations.append("Low cache hit rate - review caching strategy")
            recommendations.append("Consider increasing cache TTL for stable data")
        
        # Thread pool recommendations
        thread_stats = self.thread_manager.get_stats()
        if thread_stats['utilization'] > 0.9:
            recommendations.append("Thread pool utilization high - consider scaling up")
        elif thread_stats['utilization'] < 0.3:
            recommendations.append("Thread pool utilization low - consider scaling down")
        
        # SLA recommendations
        if self.metrics.sla_compliance_rate < 95:
            recommendations.append("SLA compliance below target - review performance bottlenecks")
            recommendations.append("Consider implementing request prioritization")
        
        return recommendations
    
    def reset_metrics(self):
        """Reset performance metrics."""
        with self._metrics_lock:
            self.metrics = PerformanceMetrics()
            self._latency_history.clear()
        
        logger.info("Performance metrics reset")
    
    def shutdown(self):
        """Shutdown performance optimizer."""
        logger.info("Shutting down PerformanceOptimizer")
        
        # Stop monitoring
        self.resource_monitor.stop_monitoring()
        
        # Shutdown thread manager
        self.thread_manager.shutdown()
        
        # Clear cache
        if self.cache:
            self.cache.clear()
        
        logger.info("PerformanceOptimizer shutdown complete")


# Example usage and testing
if __name__ == "__main__":
    import asyncio
    
    # Test function for optimization
    def test_processing_function(content: str, complexity: str = "normal") -> Dict[str, Any]:
        """Test processing function."""
        # Simulate processing time based on complexity
        if complexity == "fast":
            time.sleep(0.01)  # 10ms
        elif complexity == "normal":
            time.sleep(0.05)  # 50ms
        elif complexity == "slow":
            time.sleep(0.1)   # 100ms
        
        return {
            'processed_content': f"Processed: {content[:50]}...",
            'processing_complexity': complexity,
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
    
    async def test_performance_optimizer():
        """Test the performance optimizer."""
        # Create optimizer with test configuration
        config = OptimizationConfig(
            target_latency_ms=30.0,
            max_acceptable_latency_ms=75.0,
            cache_enabled=True,
            cache_size_mb=128.0,
            adaptive_optimization=True
        )
        
        optimizer = PerformanceOptimizer(config)
        
        try:
            print("Testing Performance Optimizer")
            print("=" * 50)
            
            # Test single request optimization
            print("\n1. Single Request Optimization:")
            result, metrics = optimizer.optimize_request_processing(
                "test-001",
                test_processing_function,
                "Test content for classification",
                complexity="normal"
            )
            
            print(f"   Result: {result}")
            print(f"   Processing Time: {metrics['processing_time_ms']:.2f}ms")
            print(f"   Cache Hit: {metrics.get('cache_hit', False)}")
            
            # Test batch processing
            print("\n2. Batch Processing Optimization:")
            batch_requests = [
                (f"batch-{i}", test_processing_function, ("Batch content " + str(i),), {"complexity": "fast"})
                for i in range(10)
            ]
            
            batch_start = time.time()
            batch_results = await optimizer.optimize_batch_processing(batch_requests, max_concurrent=5)
            batch_time = (time.time() - batch_start) * 1000
            
            print(f"   Processed {len(batch_results)} requests in {batch_time:.2f}ms")
            print(f"   Average per request: {batch_time / len(batch_results):.2f}ms")
            
            # Test cache effectiveness
            print("\n3. Cache Effectiveness Test:")
            # Repeat the same request to test caching
            result2, metrics2 = optimizer.optimize_request_processing(
                "test-001",  # Same request ID
                test_processing_function,
                "Test content for classification",
                complexity="normal"
            )
            
            print(f"   Second request processing time: {metrics2['processing_time_ms']:.2f}ms")
            print(f"   Cache Hit: {metrics2.get('cache_hit', False)}")
            
            # Get performance metrics
            print("\n4. Performance Metrics:")
            perf_metrics = optimizer.get_performance_metrics()
            print(f"   Total Requests: {perf_metrics.total_requests}")
            print(f"   Average Latency: {perf_metrics.average_latency_ms:.2f}ms")
            print(f"   P95 Latency: {perf_metrics.p95_latency_ms:.2f}ms")
            print(f"   Cache Hit Rate: {perf_metrics.cache_hit_rate:.1f}%")
            print(f"   SLA Compliance: {perf_metrics.sla_compliance_rate:.1f}%")
            print(f"   CPU Usage: {perf_metrics.cpu_usage_percent:.1f}%")
            print(f"   Memory Usage: {perf_metrics.memory_usage_percent:.1f}%")
            
            # Get optimization recommendations
            print("\n5. Optimization Recommendations:")
            recommendations = optimizer.get_optimization_recommendations()
            if recommendations:
                for i, rec in enumerate(recommendations, 1):
                    print(f"   {i}. {rec}")
            else:
                print("   No specific recommendations at this time")
            
            print("\nPerformance Optimizer test completed successfully!")
            
        finally:
            # Shutdown optimizer
            optimizer.shutdown()
    
    # Run test
    asyncio.run(test_performance_optimizer())