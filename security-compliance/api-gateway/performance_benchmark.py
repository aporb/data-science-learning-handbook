"""
Performance Benchmarking and Load Testing for DoD API Gateway

This module provides comprehensive performance testing, load testing, and benchmarking
capabilities for the DoD API Gateway implementation to ensure it meets performance
requirements under various load conditions.

Key Features:
- Load testing with configurable user patterns
- Performance benchmarking across different scenarios
- Stress testing to identify breaking points
- Latency and throughput analysis
- Resource utilization monitoring
- Performance regression testing
- DoD-specific performance compliance validation

Performance Standards:
- Response time targets: < 2s for standard requests, < 5s for complex requests
- Throughput targets: > 1000 RPS for standard load, > 10000 RPS peak
- Availability targets: 99.9% uptime during normal operations
- Error rate targets: < 0.1% under normal load, < 1% under peak load
"""

import asyncio
import time
import statistics
import json
import uuid
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple, Callable
from dataclasses import dataclass, asdict
from enum import Enum
from concurrent.futures import ThreadPoolExecutor
import threading
import psutil
import gc

import aiohttp
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

# Import from existing modules
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from api_gateway.dod_api_gateway import DoDAPIGateway, DoDAGWConfig, APIRequest, SecurityClassification
from api_gateway.api_security_controls import APISecurityController, SecurityPolicy, create_standard_security_policy
from api_gateway.gateway_monitoring import APIGatewayMonitor
from api_gateway.external_api_client import ExternalAPIClient, ExternalAPIConfig


class LoadTestPattern(Enum):
    """Load test patterns."""
    CONSTANT = "constant"
    RAMP_UP = "ramp_up"
    SPIKE = "spike"
    STRESS = "stress"
    VOLUME = "volume"
    SOAK = "soak"


class PerformanceMetric(Enum):
    """Performance metrics to track."""
    RESPONSE_TIME = "response_time"
    THROUGHPUT = "throughput"
    ERROR_RATE = "error_rate"
    CPU_USAGE = "cpu_usage"
    MEMORY_USAGE = "memory_usage"
    CONCURRENT_USERS = "concurrent_users"
    QUEUE_DEPTH = "queue_depth"


@dataclass
class LoadTestConfig:
    """Configuration for load testing."""
    name: str
    description: str
    pattern: LoadTestPattern
    duration_seconds: int
    initial_users: int
    max_users: int
    ramp_up_duration: int = 60
    ramp_down_duration: int = 60
    target_rps: Optional[int] = None
    endpoints: List[str] = None
    request_weights: Dict[str, float] = None
    think_time_seconds: float = 1.0
    data_variation: bool = True


@dataclass
class PerformanceRequirement:
    """Performance requirement specification."""
    metric: PerformanceMetric
    threshold: float
    percentile: Optional[int] = None
    condition: str = "less_than"  # less_than, greater_than, equals
    classification: SecurityClassification = SecurityClassification.UNCLASSIFIED


@dataclass
class BenchmarkResult:
    """Performance benchmark result."""
    timestamp: datetime
    test_name: str
    duration_seconds: float
    total_requests: int
    successful_requests: int
    failed_requests: int
    requests_per_second: float
    
    # Response time metrics
    avg_response_time: float
    min_response_time: float
    max_response_time: float
    p50_response_time: float
    p90_response_time: float
    p95_response_time: float
    p99_response_time: float
    
    # Error metrics
    error_rate: float
    timeout_count: int
    connection_errors: int
    
    # Resource metrics
    peak_cpu_usage: float
    peak_memory_usage: float
    peak_concurrent_users: int
    
    # Security metrics
    security_events: int
    blocked_requests: int
    
    # Compliance status
    requirements_met: bool
    failed_requirements: List[str]


@dataclass
class LoadTestUser:
    """Simulated user for load testing."""
    user_id: str
    session: aiohttp.ClientSession
    request_count: int = 0
    error_count: int = 0
    total_response_time: float = 0.0
    last_request_time: Optional[datetime] = None


class PerformanceBenchmark:
    """
    Performance Benchmarking and Load Testing Framework
    
    Provides comprehensive performance testing capabilities for the DoD API Gateway
    including load testing, stress testing, and performance regression testing.
    """
    
    def __init__(self, gateway_config: DoDAGWConfig, 
                 redis_url: str = "redis://localhost:6379"):
        """Initialize performance benchmark framework."""
        self.logger = logging.getLogger(__name__)
        self.gateway_config = gateway_config
        self.redis_url = redis_url
        
        # Test components
        self.gateway = None
        self.security_controller = None
        self.monitor = None
        
        # Test state
        self.active_users: Dict[str, LoadTestUser] = {}
        self.test_results: List[BenchmarkResult] = []
        self.performance_requirements: List[PerformanceRequirement] = []
        
        # Metrics collection
        self.response_times: List[float] = []
        self.error_log: List[Dict[str, Any]] = []
        self.resource_metrics: List[Dict[str, Any]] = []
        
        # Test control
        self._stop_event = threading.Event()
        self._test_running = False
        
        # Resource monitoring
        self.resource_monitor_interval = 1.0  # seconds
    
    async def initialize(self) -> None:
        """Initialize benchmark framework components."""
        try:
            # Initialize gateway components
            self.gateway = DoDAPIGateway(self.gateway_config)
            await self.gateway.initialize()
            
            self.security_controller = APISecurityController(self.redis_url)
            await self.security_controller.initialize()
            
            self.monitor = APIGatewayMonitor(self.redis_url)
            await self.monitor.initialize()
            
            # Setup default performance requirements
            self._setup_default_requirements()
            
            self.logger.info("Performance benchmark framework initialized")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize benchmark framework: {e}")
            raise
    
    def _setup_default_requirements(self) -> None:
        """Setup default performance requirements."""
        default_requirements = [
            PerformanceRequirement(
                metric=PerformanceMetric.RESPONSE_TIME,
                threshold=2.0,
                percentile=95,
                condition="less_than"
            ),
            PerformanceRequirement(
                metric=PerformanceMetric.THROUGHPUT,
                threshold=1000.0,
                condition="greater_than"
            ),
            PerformanceRequirement(
                metric=PerformanceMetric.ERROR_RATE,
                threshold=0.1,
                condition="less_than"
            ),
            PerformanceRequirement(
                metric=PerformanceMetric.CPU_USAGE,
                threshold=80.0,
                condition="less_than"
            ),
            PerformanceRequirement(
                metric=PerformanceMetric.MEMORY_USAGE,
                threshold=85.0,
                condition="less_than"
            )
        ]
        
        self.performance_requirements.extend(default_requirements)
    
    def add_performance_requirement(self, requirement: PerformanceRequirement) -> None:
        """Add custom performance requirement."""
        self.performance_requirements.append(requirement)
        self.logger.info(f"Added performance requirement: {requirement.metric.value}")
    
    async def run_load_test(self, config: LoadTestConfig) -> BenchmarkResult:
        """Run comprehensive load test with specified configuration."""
        self.logger.info(f"Starting load test: {config.name}")
        start_time = datetime.utcnow()
        
        try:
            # Reset test state
            self._reset_test_state()
            
            # Start resource monitoring
            monitor_task = asyncio.create_task(self._monitor_resources())
            
            # Execute load test based on pattern
            if config.pattern == LoadTestPattern.CONSTANT:
                await self._run_constant_load_test(config)
            elif config.pattern == LoadTestPattern.RAMP_UP:
                await self._run_ramp_up_test(config)
            elif config.pattern == LoadTestPattern.SPIKE:
                await self._run_spike_test(config)
            elif config.pattern == LoadTestPattern.STRESS:
                await self._run_stress_test(config)
            elif config.pattern == LoadTestPattern.VOLUME:
                await self._run_volume_test(config)
            elif config.pattern == LoadTestPattern.SOAK:
                await self._run_soak_test(config)
            
            # Stop monitoring
            self._stop_event.set()
            await monitor_task
            
            # Generate benchmark result
            end_time = datetime.utcnow()
            duration = (end_time - start_time).total_seconds()
            
            result = await self._generate_benchmark_result(config.name, duration)
            self.test_results.append(result)
            
            self.logger.info(f"Load test completed: {config.name}")
            return result
            
        except Exception as e:
            self.logger.error(f"Load test failed: {e}")
            raise
        finally:
            self._stop_event.set()
            await self._cleanup_test_users()
    
    async def _run_constant_load_test(self, config: LoadTestConfig) -> None:
        """Run constant load test."""
        # Create initial users
        await self._create_users(config.initial_users, config)
        
        # Run test for specified duration
        start_time = time.time()
        while time.time() - start_time < config.duration_seconds and not self._stop_event.is_set():
            # Execute requests from all users
            tasks = []
            for user in self.active_users.values():
                task = asyncio.create_task(self._execute_user_request(user, config))
                tasks.append(task)
            
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
            
            # Think time between requests
            await asyncio.sleep(config.think_time_seconds)
    
    async def _run_ramp_up_test(self, config: LoadTestConfig) -> None:
        """Run ramp-up load test."""
        # Calculate user increment rate
        user_increment = (config.max_users - config.initial_users) / config.ramp_up_duration
        
        # Create initial users
        await self._create_users(config.initial_users, config)
        
        start_time = time.time()
        next_user_time = start_time + (1.0 / user_increment) if user_increment > 0 else float('inf')
        
        while time.time() - start_time < config.duration_seconds and not self._stop_event.is_set():
            current_time = time.time()
            
            # Add users during ramp-up period
            if (current_time < start_time + config.ramp_up_duration and 
                current_time >= next_user_time and 
                len(self.active_users) < config.max_users):
                
                await self._create_users(1, config)
                next_user_time = current_time + (1.0 / user_increment) if user_increment > 0 else float('inf')
            
            # Execute requests
            tasks = []
            for user in self.active_users.values():
                task = asyncio.create_task(self._execute_user_request(user, config))
                tasks.append(task)
            
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
            
            await asyncio.sleep(config.think_time_seconds)
    
    async def _run_spike_test(self, config: LoadTestConfig) -> None:
        """Run spike load test."""
        # Start with initial users
        await self._create_users(config.initial_users, config)
        
        # Run initial load
        initial_duration = config.duration_seconds * 0.3
        await self._run_load_for_duration(initial_duration, config)
        
        # Spike to max users
        spike_users = config.max_users - len(self.active_users)
        await self._create_users(spike_users, config)
        
        # Run spike load
        spike_duration = config.duration_seconds * 0.4
        await self._run_load_for_duration(spike_duration, config)
        
        # Return to initial load
        users_to_remove = spike_users
        await self._remove_users(users_to_remove)
        
        # Run final load
        final_duration = config.duration_seconds * 0.3
        await self._run_load_for_duration(final_duration, config)
    
    async def _run_stress_test(self, config: LoadTestConfig) -> None:
        """Run stress test to find breaking point."""
        current_users = config.initial_users
        await self._create_users(current_users, config)
        
        stress_increment = max(1, config.max_users // 10)  # 10% increments
        
        while current_users <= config.max_users and not self._stop_event.is_set():
            # Run load for measurement period
            measurement_duration = 60  # 1 minute measurement
            await self._run_load_for_duration(measurement_duration, config)
            
            # Check if system is stressed (high error rate or response time)
            recent_errors = len([e for e in self.error_log if 
                               datetime.fromisoformat(e['timestamp']) > 
                               datetime.utcnow() - timedelta(minutes=1)])
            recent_requests = len([rt for rt in self.response_times[-100:] if rt > 0])
            
            error_rate = recent_errors / recent_requests if recent_requests > 0 else 0
            avg_response_time = statistics.mean(self.response_times[-100:]) if self.response_times else 0
            
            if error_rate > 0.05 or avg_response_time > 10.0:  # 5% error rate or 10s response time
                self.logger.warning(f"System stress detected at {current_users} users")
                break
            
            # Add more users
            await self._create_users(stress_increment, config)
            current_users += stress_increment
    
    async def _run_volume_test(self, config: LoadTestConfig) -> None:
        """Run volume test with large amounts of data."""
        # Create users for volume testing
        await self._create_users(config.max_users, config)
        
        # Generate large data payloads
        large_payload = {"data": "x" * 10000}  # 10KB payload
        
        # Modify config for volume testing
        volume_config = config
        volume_config.think_time_seconds = 0.1  # Faster requests for volume
        
        await self._run_load_for_duration(config.duration_seconds, volume_config, large_payload)
    
    async def _run_soak_test(self, config: LoadTestConfig) -> None:
        """Run soak test for extended duration."""
        await self._create_users(config.initial_users, config)
        
        # Run for extended duration (usually hours)
        soak_duration = config.duration_seconds  # Should be set to hours for real soak test
        
        # Monitor for memory leaks and performance degradation
        start_time = time.time()
        check_interval = 300  # Check every 5 minutes
        last_check = start_time
        
        while time.time() - start_time < soak_duration and not self._stop_event.is_set():
            await self._run_load_for_duration(min(check_interval, soak_duration - (time.time() - start_time)), config)
            
            # Check for performance degradation
            if time.time() - last_check >= check_interval:
                await self._check_performance_degradation()
                last_check = time.time()
                
                # Force garbage collection to check for memory leaks
                gc.collect()
    
    async def _run_load_for_duration(self, duration: float, config: LoadTestConfig, 
                                   payload: Optional[Dict] = None) -> None:
        """Run load for specified duration."""
        start_time = time.time()
        
        while time.time() - start_time < duration and not self._stop_event.is_set():
            tasks = []
            for user in self.active_users.values():
                task = asyncio.create_task(self._execute_user_request(user, config, payload))
                tasks.append(task)
            
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
            
            await asyncio.sleep(config.think_time_seconds)
    
    async def _create_users(self, count: int, config: LoadTestConfig) -> None:
        """Create simulated users for load testing."""
        for i in range(count):
            user_id = f"user_{len(self.active_users) + 1}_{uuid.uuid4().hex[:8]}"
            
            # Create HTTP session for user
            connector = aiohttp.TCPConnector(limit=10)
            timeout = aiohttp.ClientTimeout(total=30)
            session = aiohttp.ClientSession(connector=connector, timeout=timeout)
            
            user = LoadTestUser(
                user_id=user_id,
                session=session
            )
            
            self.active_users[user_id] = user
        
        self.logger.info(f"Created {count} users, total active: {len(self.active_users)}")
    
    async def _remove_users(self, count: int) -> None:
        """Remove specified number of users."""
        users_to_remove = list(self.active_users.keys())[:count]
        
        for user_id in users_to_remove:
            user = self.active_users.pop(user_id)
            await user.session.close()
        
        self.logger.info(f"Removed {count} users, total active: {len(self.active_users)}")
    
    async def _execute_user_request(self, user: LoadTestUser, config: LoadTestConfig,
                                  payload: Optional[Dict] = None) -> None:
        """Execute request for a simulated user."""
        try:
            # Select endpoint
            endpoint = self._select_endpoint(config)
            
            # Create request
            request_data = payload or self._generate_request_data(endpoint)
            
            request = APIRequest(
                method='POST' if request_data else 'GET',
                endpoint=endpoint,
                data=request_data,
                headers={
                    'Authorization': 'Bearer test_token',
                    'User-Agent': f'LoadTest-{user.user_id}',
                    'X-Load-Test': 'true'
                }
            )
            
            # Execute request
            start_time = time.time()
            response = await self.gateway.make_request(request)
            response_time = time.time() - start_time
            
            # Record metrics
            self.response_times.append(response_time)
            user.request_count += 1
            user.total_response_time += response_time
            user.last_request_time = datetime.utcnow()
            
            # Record errors
            if response.error or response.status_code >= 400:
                user.error_count += 1
                self.error_log.append({
                    'timestamp': datetime.utcnow().isoformat(),
                    'user_id': user.user_id,
                    'endpoint': endpoint,
                    'status_code': response.status_code,
                    'error': response.error
                })
            
            # Record in monitor
            self.monitor.record_request(
                method=request.method,
                endpoint=endpoint,
                status_code=response.status_code,
                response_time=response_time,
                request_size=len(json.dumps(request_data).encode()) if request_data else 0,
                response_size=len(str(response.data).encode()) if response.data else 0
            )
            
        except Exception as e:
            user.error_count += 1
            self.error_log.append({
                'timestamp': datetime.utcnow().isoformat(),
                'user_id': user.user_id,
                'endpoint': endpoint if 'endpoint' in locals() else 'unknown',
                'error': str(e)
            })
    
    def _select_endpoint(self, config: LoadTestConfig) -> str:
        """Select endpoint based on configuration weights."""
        if config.endpoints:
            if config.request_weights:
                # Weighted selection
                import random
                return random.choices(
                    config.endpoints,
                    weights=[config.request_weights.get(ep, 1.0) for ep in config.endpoints]
                )[0]
            else:
                # Random selection
                import random
                return random.choice(config.endpoints)
        else:
            # Default test endpoints
            return "/api/v1/test"
    
    def _generate_request_data(self, endpoint: str) -> Optional[Dict]:
        """Generate request data based on endpoint."""
        if 'user' in endpoint.lower():
            return {
                'name': f'Test User {uuid.uuid4().hex[:8]}',
                'email': f'test.{uuid.uuid4().hex[:8]}@test.mil',
                'classification': 'UNCLASSIFIED'
            }
        elif 'data' in endpoint.lower():
            return {
                'query': 'SELECT * FROM test_table',
                'parameters': {'limit': 100},
                'classification': 'UNCLASSIFIED'
            }
        else:
            return None
    
    async def _monitor_resources(self) -> None:
        """Monitor system resources during load test."""
        while not self._stop_event.is_set():
            try:
                # Collect system metrics
                cpu_percent = psutil.cpu_percent(interval=1)
                memory = psutil.virtual_memory()
                disk = psutil.disk_usage('/')
                
                # Collect application metrics
                active_users = len(self.active_users)
                
                metrics = {
                    'timestamp': datetime.utcnow().isoformat(),
                    'cpu_percent': cpu_percent,
                    'memory_percent': memory.percent,
                    'memory_used_gb': memory.used / (1024**3),
                    'disk_percent': disk.percent,
                    'active_users': active_users,
                    'total_requests': sum(user.request_count for user in self.active_users.values()),
                    'total_errors': sum(user.error_count for user in self.active_users.values())
                }
                
                self.resource_metrics.append(metrics)
                
                await asyncio.sleep(self.resource_monitor_interval)
                
            except Exception as e:
                self.logger.error(f"Resource monitoring error: {e}")
                break
    
    async def _check_performance_degradation(self) -> None:
        """Check for performance degradation during soak test."""
        if len(self.response_times) < 100:
            return
        
        # Compare recent performance to initial performance
        initial_times = self.response_times[:100]
        recent_times = self.response_times[-100:]
        
        initial_avg = statistics.mean(initial_times)
        recent_avg = statistics.mean(recent_times)
        
        degradation_percent = ((recent_avg - initial_avg) / initial_avg) * 100
        
        if degradation_percent > 20:  # 20% degradation threshold
            self.logger.warning(f"Performance degradation detected: {degradation_percent:.2f}%")
        
        # Check memory usage trend
        if len(self.resource_metrics) >= 10:
            recent_memory = [m['memory_percent'] for m in self.resource_metrics[-10:]]
            if max(recent_memory) - min(recent_memory) > 10:  # 10% memory increase
                self.logger.warning("Memory usage increase detected - possible memory leak")
    
    async def _generate_benchmark_result(self, test_name: str, duration: float) -> BenchmarkResult:
        """Generate comprehensive benchmark result."""
        total_requests = sum(user.request_count for user in self.active_users.values())
        total_errors = sum(user.error_count for user in self.active_users.values())
        successful_requests = total_requests - total_errors
        
        # Calculate response time percentiles
        if self.response_times:
            response_times_array = np.array(self.response_times)
            percentiles = np.percentile(response_times_array, [50, 90, 95, 99])
        else:
            percentiles = [0, 0, 0, 0]
        
        # Calculate resource peaks
        peak_cpu = max([m['cpu_percent'] for m in self.resource_metrics]) if self.resource_metrics else 0
        peak_memory = max([m['memory_percent'] for m in self.resource_metrics]) if self.resource_metrics else 0
        peak_users = max([m['active_users'] for m in self.resource_metrics]) if self.resource_metrics else 0
        
        # Check requirements compliance
        requirements_met, failed_requirements = await self._check_requirements_compliance(
            total_requests, successful_requests, total_errors, duration, peak_cpu, peak_memory
        )
        
        result = BenchmarkResult(
            timestamp=datetime.utcnow(),
            test_name=test_name,
            duration_seconds=duration,
            total_requests=total_requests,
            successful_requests=successful_requests,
            failed_requests=total_errors,
            requests_per_second=total_requests / duration if duration > 0 else 0,
            
            # Response time metrics
            avg_response_time=statistics.mean(self.response_times) if self.response_times else 0,
            min_response_time=min(self.response_times) if self.response_times else 0,
            max_response_time=max(self.response_times) if self.response_times else 0,
            p50_response_time=percentiles[0],
            p90_response_time=percentiles[1],
            p95_response_time=percentiles[2],
            p99_response_time=percentiles[3],
            
            # Error metrics
            error_rate=(total_errors / total_requests * 100) if total_requests > 0 else 0,
            timeout_count=len([e for e in self.error_log if 'timeout' in e.get('error', '').lower()]),
            connection_errors=len([e for e in self.error_log if 'connection' in e.get('error', '').lower()]),
            
            # Resource metrics
            peak_cpu_usage=peak_cpu,
            peak_memory_usage=peak_memory,
            peak_concurrent_users=peak_users,
            
            # Security metrics (would be collected from security controller)
            security_events=0,  # TODO: Integrate with security controller
            blocked_requests=0,  # TODO: Integrate with security controller
            
            # Compliance
            requirements_met=requirements_met,
            failed_requirements=failed_requirements
        )
        
        return result
    
    async def _check_requirements_compliance(self, total_requests: int, successful_requests: int,
                                           total_errors: int, duration: float, peak_cpu: float,
                                           peak_memory: float) -> Tuple[bool, List[str]]:
        """Check if performance requirements are met."""
        failed_requirements = []
        
        for requirement in self.performance_requirements:
            metric_value = None
            
            if requirement.metric == PerformanceMetric.RESPONSE_TIME:
                if self.response_times and requirement.percentile:
                    metric_value = np.percentile(self.response_times, requirement.percentile)
                else:
                    metric_value = statistics.mean(self.response_times) if self.response_times else 0
                    
            elif requirement.metric == PerformanceMetric.THROUGHPUT:
                metric_value = total_requests / duration if duration > 0 else 0
                
            elif requirement.metric == PerformanceMetric.ERROR_RATE:
                metric_value = (total_errors / total_requests * 100) if total_requests > 0 else 0
                
            elif requirement.metric == PerformanceMetric.CPU_USAGE:
                metric_value = peak_cpu
                
            elif requirement.metric == PerformanceMetric.MEMORY_USAGE:
                metric_value = peak_memory
            
            # Check requirement
            if metric_value is not None:
                requirement_met = self._evaluate_requirement(metric_value, requirement)
                if not requirement_met:
                    failed_requirements.append(
                        f"{requirement.metric.value}: {metric_value:.2f} {requirement.condition} {requirement.threshold}"
                    )
        
        return len(failed_requirements) == 0, failed_requirements
    
    def _evaluate_requirement(self, value: float, requirement: PerformanceRequirement) -> bool:
        """Evaluate if a performance requirement is met."""
        if requirement.condition == "less_than":
            return value < requirement.threshold
        elif requirement.condition == "greater_than":
            return value > requirement.threshold
        elif requirement.condition == "equals":
            return abs(value - requirement.threshold) < 0.01  # Small tolerance for floats
        else:
            return False
    
    def _reset_test_state(self) -> None:
        """Reset test state for new test run."""
        self.response_times.clear()
        self.error_log.clear()
        self.resource_metrics.clear()
        self._stop_event.clear()
        self._test_running = False
    
    async def _cleanup_test_users(self) -> None:
        """Clean up all test users."""
        for user in self.active_users.values():
            try:
                await user.session.close()
            except:
                pass
        
        self.active_users.clear()
    
    def generate_performance_report(self, output_path: str = None) -> Dict[str, Any]:
        """Generate comprehensive performance report."""
        if not self.test_results:
            return {"error": "No test results available"}
        
        # Aggregate results
        total_tests = len(self.test_results)
        total_requests = sum(r.total_requests for r in self.test_results)
        total_duration = sum(r.duration_seconds for r in self.test_results)
        
        avg_response_time = statistics.mean([r.avg_response_time for r in self.test_results])
        avg_throughput = statistics.mean([r.requests_per_second for r in self.test_results])
        avg_error_rate = statistics.mean([r.error_rate for r in self.test_results])
        
        # Compliance summary
        passed_tests = len([r for r in self.test_results if r.requirements_met])
        compliance_rate = (passed_tests / total_tests * 100) if total_tests > 0 else 0
        
        report = {
            'summary': {
                'total_tests': total_tests,
                'total_requests': total_requests,
                'total_duration_hours': total_duration / 3600,
                'average_response_time': avg_response_time,
                'average_throughput': avg_throughput,
                'average_error_rate': avg_error_rate,
                'compliance_rate': compliance_rate
            },
            'test_results': [asdict(result) for result in self.test_results],
            'performance_trends': self._analyze_performance_trends(),
            'recommendations': self._generate_recommendations()
        }
        
        # Save report if path provided
        if output_path:
            with open(output_path, 'w') as f:
                json.dump(report, f, indent=2, default=str)
            
            # Generate visualizations
            self._generate_performance_charts(output_path.replace('.json', ''))
        
        return report
    
    def _analyze_performance_trends(self) -> Dict[str, Any]:
        """Analyze performance trends across test results."""
        if len(self.test_results) < 2:
            return {"message": "Insufficient data for trend analysis"}
        
        # Sort results by timestamp
        sorted_results = sorted(self.test_results, key=lambda x: x.timestamp)
        
        # Calculate trends
        response_times = [r.avg_response_time for r in sorted_results]
        throughputs = [r.requests_per_second for r in sorted_results]
        error_rates = [r.error_rate for r in sorted_results]
        
        trends = {
            'response_time_trend': self._calculate_trend(response_times),
            'throughput_trend': self._calculate_trend(throughputs),
            'error_rate_trend': self._calculate_trend(error_rates),
            'stability_score': self._calculate_stability_score(sorted_results)
        }
        
        return trends
    
    def _calculate_trend(self, values: List[float]) -> str:
        """Calculate trend direction for a metric."""
        if len(values) < 2:
            return "insufficient_data"
        
        # Simple linear trend calculation
        x = list(range(len(values)))
        correlation = np.corrcoef(x, values)[0, 1]
        
        if correlation > 0.1:
            return "increasing"
        elif correlation < -0.1:
            return "decreasing"
        else:
            return "stable"
    
    def _calculate_stability_score(self, results: List[BenchmarkResult]) -> float:
        """Calculate stability score based on variance in performance metrics."""
        if len(results) < 2:
            return 1.0
        
        # Calculate coefficient of variation for key metrics
        response_times = [r.avg_response_time for r in results]
        throughputs = [r.requests_per_second for r in results]
        error_rates = [r.error_rate for r in results]
        
        def cv(values):
            mean_val = statistics.mean(values)
            std_val = statistics.stdev(values) if len(values) > 1 else 0
            return std_val / mean_val if mean_val > 0 else 0
        
        # Lower coefficient of variation = higher stability
        response_cv = cv(response_times)
        throughput_cv = cv(throughputs)
        error_cv = cv(error_rates)
        
        # Combine metrics (lower is better, so invert)
        stability = 1.0 - min(1.0, (response_cv + throughput_cv + error_cv) / 3)
        
        return max(0.0, stability)
    
    def _generate_recommendations(self) -> List[str]:
        """Generate performance improvement recommendations."""
        recommendations = []
        
        if not self.test_results:
            return ["No test results available for recommendations"]
        
        latest_result = self.test_results[-1]
        
        # Response time recommendations
        if latest_result.p95_response_time > 5.0:
            recommendations.append("Consider optimizing response times - P95 exceeds 5 seconds")
        
        # Throughput recommendations
        if latest_result.requests_per_second < 1000:
            recommendations.append("Consider scaling infrastructure - throughput below 1000 RPS")
        
        # Error rate recommendations
        if latest_result.error_rate > 1.0:
            recommendations.append("Investigate error causes - error rate exceeds 1%")
        
        # Resource recommendations
        if latest_result.peak_cpu_usage > 80:
            recommendations.append("Consider CPU scaling - peak usage exceeds 80%")
        
        if latest_result.peak_memory_usage > 85:
            recommendations.append("Consider memory optimization - peak usage exceeds 85%")
        
        # Stability recommendations
        if len(self.test_results) > 1:
            trends = self._analyze_performance_trends()
            if trends.get('stability_score', 1.0) < 0.8:
                recommendations.append("Performance shows instability - investigate variability causes")
        
        return recommendations if recommendations else ["Performance appears to be within acceptable ranges"]
    
    def _generate_performance_charts(self, base_path: str) -> None:
        """Generate performance visualization charts."""
        try:
            # Set up the plotting style
            plt.style.use('seaborn-v0_8')
            
            if not self.test_results:
                return
            
            # Response time distribution
            plt.figure(figsize=(12, 8))
            if self.response_times:
                plt.hist(self.response_times, bins=50, alpha=0.7, edgecolor='black')
                plt.xlabel('Response Time (seconds)')
                plt.ylabel('Frequency')
                plt.title('Response Time Distribution')
                plt.axvline(np.percentile(self.response_times, 95), color='red', linestyle='--', label='P95')
                plt.legend()
                plt.savefig(f'{base_path}_response_time_distribution.png', dpi=300, bbox_inches='tight')
                plt.close()
            
            # Performance trends over time
            if len(self.test_results) > 1:
                fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(15, 10))
                
                timestamps = [r.timestamp for r in self.test_results]
                
                # Response time trend
                response_times = [r.avg_response_time for r in self.test_results]
                ax1.plot(timestamps, response_times, marker='o')
                ax1.set_title('Average Response Time Trend')
                ax1.set_ylabel('Response Time (s)')
                ax1.tick_params(axis='x', rotation=45)
                
                # Throughput trend
                throughputs = [r.requests_per_second for r in self.test_results]
                ax2.plot(timestamps, throughputs, marker='o', color='green')
                ax2.set_title('Throughput Trend')
                ax2.set_ylabel('Requests/Second')
                ax2.tick_params(axis='x', rotation=45)
                
                # Error rate trend
                error_rates = [r.error_rate for r in self.test_results]
                ax3.plot(timestamps, error_rates, marker='o', color='red')
                ax3.set_title('Error Rate Trend')
                ax3.set_ylabel('Error Rate (%)')
                ax3.tick_params(axis='x', rotation=45)
                
                # Resource usage
                cpu_usage = [r.peak_cpu_usage for r in self.test_results]
                memory_usage = [r.peak_memory_usage for r in self.test_results]
                ax4.plot(timestamps, cpu_usage, marker='o', label='CPU %')
                ax4.plot(timestamps, memory_usage, marker='s', label='Memory %')
                ax4.set_title('Resource Usage Trend')
                ax4.set_ylabel('Usage (%)')
                ax4.legend()
                ax4.tick_params(axis='x', rotation=45)
                
                plt.tight_layout()
                plt.savefig(f'{base_path}_performance_trends.png', dpi=300, bbox_inches='tight')
                plt.close()
            
            self.logger.info(f"Performance charts generated: {base_path}")
            
        except Exception as e:
            self.logger.error(f"Failed to generate performance charts: {e}")
    
    async def close(self) -> None:
        """Clean up benchmark framework resources."""
        self._stop_event.set()
        await self._cleanup_test_users()
        
        if self.gateway:
            await self.gateway.close()
        if self.security_controller:
            await self.security_controller.close()
        if self.monitor:
            await self.monitor.close()
        
        self.logger.info("Performance benchmark framework closed")


# Predefined test configurations
def create_standard_load_test() -> LoadTestConfig:
    """Create standard load test configuration."""
    return LoadTestConfig(
        name="standard_load_test",
        description="Standard load test with gradual ramp-up",
        pattern=LoadTestPattern.RAMP_UP,
        duration_seconds=600,  # 10 minutes
        initial_users=10,
        max_users=100,
        ramp_up_duration=120,  # 2 minutes
        endpoints=["/api/v1/users", "/api/v1/data", "/api/v1/health"],
        request_weights={"/api/v1/users": 0.4, "/api/v1/data": 0.5, "/api/v1/health": 0.1},
        think_time_seconds=1.0
    )


def create_stress_test() -> LoadTestConfig:
    """Create stress test configuration."""
    return LoadTestConfig(
        name="stress_test",
        description="Stress test to find system breaking point",
        pattern=LoadTestPattern.STRESS,
        duration_seconds=1800,  # 30 minutes
        initial_users=50,
        max_users=1000,
        endpoints=["/api/v1/users", "/api/v1/data"],
        think_time_seconds=0.5
    )


def create_spike_test() -> LoadTestConfig:
    """Create spike test configuration."""
    return LoadTestConfig(
        name="spike_test",
        description="Spike test with sudden load increase",
        pattern=LoadTestPattern.SPIKE,
        duration_seconds=300,  # 5 minutes
        initial_users=20,
        max_users=200,
        endpoints=["/api/v1/users", "/api/v1/data"],
        think_time_seconds=0.8
    )


def create_soak_test() -> LoadTestConfig:
    """Create soak test configuration."""
    return LoadTestConfig(
        name="soak_test",
        description="Extended soak test for stability validation",
        pattern=LoadTestPattern.SOAK,
        duration_seconds=7200,  # 2 hours
        initial_users=50,
        max_users=50,
        endpoints=["/api/v1/users", "/api/v1/data", "/api/v1/health"],
        think_time_seconds=2.0
    )


if __name__ == "__main__":
    # Example usage
    import asyncio
    
    async def main():
        # Create gateway configuration
        from auth.oauth_client import OAuthConfig, Platform
        
        oauth_config = OAuthConfig(
            platform=Platform.ADVANA,
            client_id="perf-test-client",
            client_secret="perf-test-secret",
            authorization_url="https://test-auth.mil/oauth/authorize",
            token_url="https://test-auth.mil/oauth/token",
            redirect_uri="https://localhost:8080/callback",
            scopes=["read", "write"]
        )
        
        gateway_config = DoDAGWConfig(
            environment=APIGatewayEnvironment.DEVELOPMENT,
            gateway_url="https://perf-test-gateway.mil",
            client_certificate_path="/tmp/perf-test-client.crt",
            private_key_path="/tmp/perf-test-client.key",
            ca_bundle_path="/tmp/perf-test-ca.crt",
            oauth_config=oauth_config,
            service_name="performance-test-service",
            service_version="1.0.0",
            security_classification=SecurityClassification.UNCLASSIFIED
        )
        
        # Initialize benchmark framework
        benchmark = PerformanceBenchmark(gateway_config)
        await benchmark.initialize()
        
        try:
            # Run different types of tests
            print("Running standard load test...")
            load_result = await benchmark.run_load_test(create_standard_load_test())
            print(f"Load test completed: {load_result.requests_per_second:.2f} RPS")
            
            print("Running spike test...")
            spike_result = await benchmark.run_load_test(create_spike_test())
            print(f"Spike test completed: {spike_result.p95_response_time:.2f}s P95")
            
            # Generate performance report
            report = benchmark.generate_performance_report("performance_report.json")
            print(f"Performance report generated with {len(report['test_results'])} test results")
            
            # Print recommendations
            print("\nRecommendations:")
            for rec in report['recommendations']:
                print(f"- {rec}")
            
        finally:
            await benchmark.close()
    
    asyncio.run(main())