"""
Concurrent Token Request Manager with Rate Limiting
Handles concurrent OAuth token requests with DoD-compliant rate limiting and throttling.
"""

import asyncio
import threading
import time
import logging
from typing import Dict, Optional, List, Any, Callable, Awaitable, Union
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from collections import defaultdict, deque
import json
from concurrent.futures import ThreadPoolExecutor, Future
import weakref

# Import OAuth components
from .oauth_client import DoD_OAuth_Client, Platform, TokenResponse, OAuthConfig
from .secure_token_storage import TokenStorageManager

# Import audit logging
from .security_managers import AuditLogger, AuditEvent, AuditEventType

logger = logging.getLogger(__name__)


class RateLimitStrategy(Enum):
    """Rate limiting strategies."""
    TOKEN_BUCKET = "token_bucket"
    SLIDING_WINDOW = "sliding_window"
    FIXED_WINDOW = "fixed_window"
    ADAPTIVE = "adaptive"


class RequestPriority(Enum):
    """Request priority levels."""
    CRITICAL = 0
    HIGH = 1
    NORMAL = 2
    LOW = 3


class RequestStatus(Enum):
    """Token request status."""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    RATE_LIMITED = "rate_limited"
    CANCELLED = "cancelled"


@dataclass
class RateLimitConfig:
    """Rate limiting configuration."""
    max_requests_per_minute: int = 60
    max_requests_per_hour: int = 1000
    max_concurrent_requests: int = 10
    burst_allowance: int = 20
    strategy: RateLimitStrategy = RateLimitStrategy.TOKEN_BUCKET
    
    # Platform-specific limits
    platform_limits: Dict[str, Dict[str, int]] = field(default_factory=dict)
    
    # User-specific limits
    user_limits: Dict[str, Dict[str, int]] = field(default_factory=dict)
    
    # Adaptive rate limiting parameters
    adaptive_threshold: float = 0.8  # 80% of limit triggers adaptation
    adaptive_backoff_factor: float = 1.5
    adaptive_recovery_time: int = 300  # 5 minutes


@dataclass
class TokenRequest:
    """Token request record."""
    request_id: str
    user_id: str
    platform: Platform
    request_type: str  # 'authorization_code', 'refresh', 'client_credentials'
    priority: RequestPriority
    created_at: datetime
    callback: Optional[Callable] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    # Request parameters
    authorization_code: Optional[str] = None
    refresh_token: Optional[str] = None
    state: Optional[str] = None
    
    # Status tracking
    status: RequestStatus = RequestStatus.PENDING
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    result: Optional[TokenResponse] = None
    error: Optional[str] = None
    retry_count: int = 0
    max_retries: int = 3


class TokenBucket:
    """Token bucket rate limiter implementation."""
    
    def __init__(self, capacity: int, refill_rate: float):
        """
        Initialize token bucket.
        
        Args:
            capacity: Maximum bucket capacity
            refill_rate: Tokens per second refill rate
        """
        self.capacity = capacity
        self.refill_rate = refill_rate
        self.tokens = capacity
        self.last_refill = time.time()
        self._lock = threading.Lock()
    
    def consume(self, tokens: int = 1) -> bool:
        """
        Attempt to consume tokens from bucket.
        
        Args:
            tokens: Number of tokens to consume
            
        Returns:
            True if tokens were consumed, False if insufficient tokens
        """
        with self._lock:
            self._refill()
            
            if self.tokens >= tokens:
                self.tokens -= tokens
                return True
            return False
    
    def _refill(self):
        """Refill bucket based on elapsed time."""
        now = time.time()
        elapsed = now - self.last_refill
        self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_rate)
        self.last_refill = now
    
    def available_tokens(self) -> int:
        """Get number of available tokens."""
        with self._lock:
            self._refill()
            return int(self.tokens)


class SlidingWindowLimiter:
    """Sliding window rate limiter implementation."""
    
    def __init__(self, window_size: int, max_requests: int):
        """
        Initialize sliding window limiter.
        
        Args:
            window_size: Window size in seconds
            max_requests: Maximum requests in window
        """
        self.window_size = window_size
        self.max_requests = max_requests
        self.requests = deque()
        self._lock = threading.Lock()
    
    def allow_request(self) -> bool:
        """
        Check if request is allowed.
        
        Returns:
            True if request is allowed
        """
        with self._lock:
            now = time.time()
            
            # Remove expired requests
            while self.requests and self.requests[0] <= now - self.window_size:
                self.requests.popleft()
            
            # Check if under limit
            if len(self.requests) < self.max_requests:
                self.requests.append(now)
                return True
            
            return False
    
    def get_current_count(self) -> int:
        """Get current request count in window."""
        with self._lock:
            now = time.time()
            
            # Remove expired requests
            while self.requests and self.requests[0] <= now - self.window_size:
                self.requests.popleft()
            
            return len(self.requests)


class AdaptiveRateLimiter:
    """Adaptive rate limiter that adjusts based on system load."""
    
    def __init__(self, base_config: RateLimitConfig):
        """Initialize adaptive rate limiter."""
        self.base_config = base_config
        self.current_limits = {
            'requests_per_minute': base_config.max_requests_per_minute,
            'requests_per_hour': base_config.max_requests_per_hour,
            'concurrent_requests': base_config.max_concurrent_requests
        }
        
        self.bucket = TokenBucket(
            capacity=self.current_limits['requests_per_minute'],
            refill_rate=self.current_limits['requests_per_minute'] / 60.0
        )
        
        self.sliding_window = SlidingWindowLimiter(
            window_size=3600,  # 1 hour
            max_requests=self.current_limits['requests_per_hour']
        )
        
        # Adaptation tracking
        self.error_rate = 0.0
        self.recent_errors = deque(maxlen=100)
        self.last_adaptation = time.time()
        self._lock = threading.Lock()
    
    def allow_request(self) -> bool:
        """Check if request is allowed with adaptive limits."""
        with self._lock:
            self._adapt_limits()
            
            # Check both bucket and sliding window
            return (self.bucket.consume() and 
                   self.sliding_window.allow_request())
    
    def record_error(self):
        """Record an error for adaptive rate limiting."""
        with self._lock:
            self.recent_errors.append(time.time())
            self._update_error_rate()
    
    def record_success(self):
        """Record a success for adaptive rate limiting."""
        with self._lock:
            self._update_error_rate()
    
    def _update_error_rate(self):
        """Update current error rate."""
        now = time.time()
        # Remove errors older than 5 minutes
        while self.recent_errors and self.recent_errors[0] < now - 300:
            self.recent_errors.popleft()
        
        total_requests = max(1, self.sliding_window.get_current_count())
        error_count = len(self.recent_errors)
        self.error_rate = error_count / total_requests
    
    def _adapt_limits(self):
        """Adapt rate limits based on current conditions."""
        now = time.time()
        
        # Only adapt every 60 seconds
        if now - self.last_adaptation < 60:
            return
        
        self.last_adaptation = now
        
        # If error rate is high, reduce limits
        if self.error_rate > 0.1:  # 10% error rate
            factor = self.base_config.adaptive_backoff_factor
            self.current_limits['requests_per_minute'] = max(
                10,  # Minimum limit
                int(self.current_limits['requests_per_minute'] / factor)
            )
            self.current_limits['concurrent_requests'] = max(
                2,  # Minimum concurrent
                int(self.current_limits['concurrent_requests'] / factor)
            )
            
            logger.warning(f"Adapted rate limits down due to high error rate: {self.error_rate:.2%}")
        
        # If error rate is low, gradually increase limits
        elif self.error_rate < 0.02 and now - self.last_adaptation > 300:  # 2% error rate, 5 min recovery
            recovery_factor = 1.1  # Gradual recovery
            self.current_limits['requests_per_minute'] = min(
                self.base_config.max_requests_per_minute,
                int(self.current_limits['requests_per_minute'] * recovery_factor)
            )
            self.current_limits['concurrent_requests'] = min(
                self.base_config.max_concurrent_requests,
                int(self.current_limits['concurrent_requests'] * recovery_factor)
            )


class ConcurrentTokenManager:
    """
    Concurrent token request manager with rate limiting.
    
    Features:
    - Concurrent token request handling
    - Multiple rate limiting strategies
    - Request prioritization
    - Automatic retry with exponential backoff
    - Platform-specific rate limits
    - Request queuing and throttling
    """
    
    def __init__(self, 
                 rate_limit_config: Optional[RateLimitConfig] = None,
                 max_workers: int = 10):
        """
        Initialize concurrent token manager.
        
        Args:
            rate_limit_config: Rate limiting configuration
            max_workers: Maximum worker threads
        """
        self.config = rate_limit_config or RateLimitConfig()
        self.max_workers = max_workers
        
        # Thread pool for concurrent execution
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        
        # Rate limiters
        self._init_rate_limiters()
        
        # Request tracking
        self.active_requests: Dict[str, TokenRequest] = {}
        self.request_queue: Dict[RequestPriority, deque] = {
            priority: deque() for priority in RequestPriority
        }
        
        # Concurrent request tracking
        self.concurrent_requests = 0
        self.platform_requests: Dict[Platform, int] = defaultdict(int)
        self.user_requests: Dict[str, int] = defaultdict(int)
        
        # Token storage integration
        self.token_storage = TokenStorageManager.instance()
        
        # Threading primitives
        self._lock = threading.RLock()
        self._queue_condition = threading.Condition(self._lock)
        
        # Statistics
        self.stats = {
            'total_requests': 0,
            'successful_requests': 0,
            'failed_requests': 0,
            'rate_limited_requests': 0,
            'retried_requests': 0
        }
        
        # Start queue processor
        self._start_queue_processor()
        
        logger.info("Concurrent token manager initialized")
    
    def _init_rate_limiters(self):
        """Initialize rate limiters based on configuration."""
        if self.config.strategy == RateLimitStrategy.ADAPTIVE:
            self.rate_limiter = AdaptiveRateLimiter(self.config)
        else:
            # Use token bucket as default
            self.rate_limiter = TokenBucket(
                capacity=self.config.burst_allowance,
                refill_rate=self.config.max_requests_per_minute / 60.0
            )
        
        # Platform-specific limiters
        self.platform_limiters: Dict[Platform, TokenBucket] = {}
        for platform in Platform:
            limits = self.config.platform_limits.get(platform.value, {})
            max_rpm = limits.get('max_requests_per_minute', self.config.max_requests_per_minute)
            
            self.platform_limiters[platform] = TokenBucket(
                capacity=max_rpm,
                refill_rate=max_rpm / 60.0
            )
    
    def request_token_async(self, 
                          user_id: str,
                          platform: Platform,
                          oauth_client: DoD_OAuth_Client,
                          request_type: str,
                          priority: RequestPriority = RequestPriority.NORMAL,
                          callback: Optional[Callable] = None,
                          **kwargs) -> str:
        """
        Submit asynchronous token request.
        
        Args:
            user_id: User identifier
            platform: OAuth platform
            oauth_client: OAuth client instance
            request_type: Type of request ('authorization_code', 'refresh', 'client_credentials')
            priority: Request priority
            callback: Optional callback function
            **kwargs: Additional request parameters
            
        Returns:
            Request ID for tracking
        """
        with self._lock:
            # Generate unique request ID
            request_id = self._generate_request_id(user_id, platform, request_type)
            
            # Create request record
            request = TokenRequest(
                request_id=request_id,
                user_id=user_id,
                platform=platform,
                request_type=request_type,
                priority=priority,
                created_at=datetime.now(timezone.utc),
                callback=callback,
                metadata={'oauth_client': oauth_client, **kwargs}
            )
            
            # Add request-specific parameters
            if request_type == 'authorization_code':
                request.authorization_code = kwargs.get('authorization_code')
                request.state = kwargs.get('state')
            elif request_type == 'refresh':
                request.refresh_token = kwargs.get('refresh_token')
            
            # Add to queue
            self.request_queue[priority].append(request)
            self.active_requests[request_id] = request
            
            # Notify queue processor
            self._queue_condition.notify()
            
            # Update statistics
            self.stats['total_requests'] += 1
            
            logger.debug(f"Token request queued: {request_id}")
            return request_id
    
    def get_request_status(self, request_id: str) -> Optional[TokenRequest]:
        """Get status of token request."""
        with self._lock:
            return self.active_requests.get(request_id)
    
    def cancel_request(self, request_id: str) -> bool:
        """
        Cancel pending token request.
        
        Args:
            request_id: Request identifier
            
        Returns:
            True if request was cancelled
        """
        with self._lock:
            request = self.active_requests.get(request_id)
            if not request:
                return False
            
            if request.status == RequestStatus.PENDING:
                request.status = RequestStatus.CANCELLED
                self._remove_from_queue(request)
                
                logger.info(f"Request cancelled: {request_id}")
                return True
            
            return False
    
    def wait_for_request(self, request_id: str, timeout: Optional[float] = None) -> Optional[TokenResponse]:
        """
        Wait for token request to complete.
        
        Args:
            request_id: Request identifier
            timeout: Optional timeout in seconds
            
        Returns:
            Token response or None if failed/timeout
        """
        start_time = time.time()
        
        while True:
            with self._lock:
                request = self.active_requests.get(request_id)
                if not request:
                    return None
                
                if request.status == RequestStatus.COMPLETED:
                    return request.result
                elif request.status in [RequestStatus.FAILED, RequestStatus.CANCELLED]:
                    return None
            
            # Check timeout
            if timeout and (time.time() - start_time) > timeout:
                return None
            
            time.sleep(0.1)  # Short sleep to avoid busy waiting
    
    def get_queue_status(self) -> Dict[str, Any]:
        """Get current queue status and statistics."""
        with self._lock:
            queue_sizes = {
                priority.name: len(queue) 
                for priority, queue in self.request_queue.items()
            }
            
            return {
                'queue_sizes': queue_sizes,
                'active_requests': len(self.active_requests),
                'concurrent_requests': self.concurrent_requests,
                'platform_requests': dict(self.platform_requests),
                'statistics': self.stats.copy(),
                'rate_limiter_status': self._get_rate_limiter_status()
            }
    
    def _generate_request_id(self, user_id: str, platform: Platform, request_type: str) -> str:
        """Generate unique request ID."""
        import uuid
        timestamp = int(time.time() * 1000)
        unique_id = str(uuid.uuid4())[:8]
        return f"{platform.value}_{user_id}_{request_type}_{timestamp}_{unique_id}"
    
    def _start_queue_processor(self):
        """Start background queue processor."""
        def process_queue():
            while True:
                try:
                    self._process_next_request()
                except Exception as e:
                    logger.error(f"Queue processor error: {e}")
                    time.sleep(1)  # Brief pause on error
        
        processor_thread = threading.Thread(target=process_queue, daemon=True)
        processor_thread.start()
        logger.info("Queue processor started")
    
    def _process_next_request(self):
        """Process next request from queue."""
        with self._queue_condition:
            # Wait for requests
            while not any(self.request_queue.values()):
                self._queue_condition.wait()
            
            # Find next request by priority
            request = None
            for priority in RequestPriority:
                if self.request_queue[priority]:
                    request = self.request_queue[priority].popleft()
                    break
            
            if not request:
                return
            
            # Check rate limits
            if not self._check_rate_limits(request):
                request.status = RequestStatus.RATE_LIMITED
                # Re-queue with delay
                self._requeue_request(request, delay=60)  # 1 minute delay
                self.stats['rate_limited_requests'] += 1
                return
            
            # Check concurrent request limits
            if not self._check_concurrent_limits(request):
                # Re-queue at front for immediate retry
                self.request_queue[request.priority].appendleft(request)
                self._queue_condition.wait(timeout=1)  # Wait briefly
                return
            
            # Submit request for execution
            request.status = RequestStatus.IN_PROGRESS
            request.started_at = datetime.now(timezone.utc)
            
            # Update concurrent counters
            self.concurrent_requests += 1
            self.platform_requests[request.platform] += 1
            self.user_requests[request.user_id] += 1
            
            # Submit to thread pool
            future = self.executor.submit(self._execute_token_request, request)
            
            # Add completion callback
            future.add_done_callback(lambda f: self._handle_request_completion(request, f))
    
    def _check_rate_limits(self, request: TokenRequest) -> bool:
        """Check if request passes rate limiting."""
        # Global rate limit
        if hasattr(self.rate_limiter, 'allow_request'):
            if not self.rate_limiter.allow_request():
                return False
        elif hasattr(self.rate_limiter, 'consume'):
            if not self.rate_limiter.consume():
                return False
        
        # Platform-specific rate limit
        platform_limiter = self.platform_limiters.get(request.platform)
        if platform_limiter and not platform_limiter.consume():
            return False
        
        return True
    
    def _check_concurrent_limits(self, request: TokenRequest) -> bool:
        """Check if request passes concurrent limits."""
        # Global concurrent limit
        if self.concurrent_requests >= self.config.max_concurrent_requests:
            return False
        
        # Platform-specific concurrent limit
        platform_limits = self.config.platform_limits.get(request.platform.value, {})
        max_platform_concurrent = platform_limits.get('max_concurrent', float('inf'))
        if self.platform_requests[request.platform] >= max_platform_concurrent:
            return False
        
        # User-specific concurrent limit
        user_limits = self.config.user_limits.get(request.user_id, {})
        max_user_concurrent = user_limits.get('max_concurrent', float('inf'))
        if self.user_requests[request.user_id] >= max_user_concurrent:
            return False
        
        return True
    
    def _execute_token_request(self, request: TokenRequest) -> TokenResponse:
        """Execute token request."""
        try:
            oauth_client = request.metadata['oauth_client']
            
            # Execute appropriate OAuth flow
            if request.request_type == 'authorization_code':
                token = oauth_client.exchange_code_for_token(
                    request.authorization_code, 
                    request.state
                )
            elif request.request_type == 'refresh':
                token = oauth_client.refresh_access_token(request.refresh_token)
            elif request.request_type == 'client_credentials':
                scopes = request.metadata.get('scopes')
                token = oauth_client.get_client_credentials_token(scopes)
            else:
                raise ValueError(f"Unknown request type: {request.request_type}")
            
            # Store token securely
            if token:
                self.token_storage.store_token(
                    platform=request.platform,
                    user_id=request.user_id,
                    token=token,
                    metadata={
                        'request_id': request.request_id,
                        'request_type': request.request_type
                    }
                )
            
            # Log successful request
            AuditLogger.instance().log_event(AuditEvent(
                event_type=AuditEventType.TOKEN_REQUEST,
                timestamp=datetime.now(timezone.utc),
                user_id=request.user_id,
                success=True,
                additional_data={
                    'platform': request.platform.value,
                    'request_type': request.request_type,
                    'request_id': request.request_id
                }
            ))
            
            return token
            
        except Exception as e:
            logger.error(f"Token request failed: {e}")
            
            # Record error for adaptive rate limiting
            if hasattr(self.rate_limiter, 'record_error'):
                self.rate_limiter.record_error()
            
            # Log failed request
            AuditLogger.instance().log_event(AuditEvent(
                event_type=AuditEventType.TOKEN_REQUEST,
                timestamp=datetime.now(timezone.utc),
                user_id=request.user_id,
                success=False,
                error_message=str(e),
                additional_data={
                    'platform': request.platform.value,
                    'request_type': request.request_type,
                    'request_id': request.request_id
                }
            ))
            
            raise
    
    def _handle_request_completion(self, request: TokenRequest, future: Future):
        """Handle request completion."""
        with self._lock:
            try:
                # Get result
                token = future.result()
                request.result = token
                request.status = RequestStatus.COMPLETED
                self.stats['successful_requests'] += 1
                
                # Record success for adaptive rate limiting
                if hasattr(self.rate_limiter, 'record_success'):
                    self.rate_limiter.record_success()
                
                logger.debug(f"Request completed successfully: {request.request_id}")
                
            except Exception as e:
                request.error = str(e)
                request.status = RequestStatus.FAILED
                self.stats['failed_requests'] += 1
                
                # Retry logic
                if request.retry_count < request.max_retries:
                    request.retry_count += 1
                    request.status = RequestStatus.PENDING
                    
                    # Exponential backoff
                    delay = min(300, 2 ** request.retry_count)  # Max 5 minutes
                    self._requeue_request(request, delay=delay)
                    self.stats['retried_requests'] += 1
                    
                    logger.info(f"Retrying request {request.request_id} (attempt {request.retry_count})")
                else:
                    logger.error(f"Request failed after {request.max_retries} retries: {request.request_id}")
            
            finally:
                # Update completion time
                request.completed_at = datetime.now(timezone.utc)
                
                # Update concurrent counters
                self.concurrent_requests -= 1
                self.platform_requests[request.platform] -= 1
                self.user_requests[request.user_id] -= 1
                
                # Call callback if provided
                if request.callback:
                    try:
                        request.callback(request)
                    except Exception as callback_error:
                        logger.error(f"Callback error: {callback_error}")
                
                # Notify queue processor
                self._queue_condition.notify()
    
    def _requeue_request(self, request: TokenRequest, delay: int = 0):
        """Re-queue request with optional delay."""
        def delayed_requeue():
            if delay > 0:
                time.sleep(delay)
            
            with self._lock:
                if request.status != RequestStatus.CANCELLED:
                    self.request_queue[request.priority].appendleft(request)
                    self._queue_condition.notify()
        
        if delay > 0:
            # Use thread pool for delayed re-queuing
            self.executor.submit(delayed_requeue)
        else:
            delayed_requeue()
    
    def _remove_from_queue(self, request: TokenRequest):
        """Remove request from queue."""
        for queue in self.request_queue.values():
            try:
                queue.remove(request)
                break
            except ValueError:
                continue
    
    def _get_rate_limiter_status(self) -> Dict[str, Any]:
        """Get rate limiter status information."""
        status = {}
        
        if hasattr(self.rate_limiter, 'available_tokens'):
            status['available_tokens'] = self.rate_limiter.available_tokens()
        
        if hasattr(self.rate_limiter, 'get_current_count'):
            status['current_requests'] = self.rate_limiter.get_current_count()
        
        if hasattr(self.rate_limiter, 'current_limits'):
            status['current_limits'] = self.rate_limiter.current_limits.copy()
        
        if hasattr(self.rate_limiter, 'error_rate'):
            status['error_rate'] = self.rate_limiter.error_rate
        
        return status
    
    def shutdown(self):
        """Shutdown token manager and cleanup resources."""
        logger.info("Shutting down concurrent token manager")
        
        # Cancel all pending requests
        with self._lock:
            for request in list(self.active_requests.values()):
                if request.status == RequestStatus.PENDING:
                    request.status = RequestStatus.CANCELLED
        
        # Shutdown thread pool
        self.executor.shutdown(wait=True)
        logger.info("Concurrent token manager shutdown complete")


# Convenience functions for common usage patterns
def create_concurrent_manager(environment: str = "NIPR") -> ConcurrentTokenManager:
    """Create concurrent token manager with environment-specific defaults."""
    # Define environment-specific rate limits
    env_configs = {
        "NIPR": RateLimitConfig(
            max_requests_per_minute=60,
            max_requests_per_hour=1000,
            max_concurrent_requests=10
        ),
        "SIPR": RateLimitConfig(
            max_requests_per_minute=30,
            max_requests_per_hour=500,
            max_concurrent_requests=5
        ),
        "JWICS": RateLimitConfig(
            max_requests_per_minute=15,
            max_requests_per_hour=200,
            max_concurrent_requests=3
        )
    }
    
    config = env_configs.get(environment, env_configs["NIPR"])
    return ConcurrentTokenManager(rate_limit_config=config)


# Global instance for singleton pattern
_global_manager: Optional[ConcurrentTokenManager] = None
_manager_lock = threading.Lock()


def get_global_manager() -> ConcurrentTokenManager:
    """Get global concurrent token manager instance."""
    global _global_manager
    
    if _global_manager is None:
        with _manager_lock:
            if _global_manager is None:
                _global_manager = create_concurrent_manager()
    
    return _global_manager