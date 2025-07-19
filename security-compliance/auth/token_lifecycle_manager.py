"""
Automated Token Lifecycle Management
Manages the complete lifecycle of OAuth tokens with secure cleanup and automated refresh.
"""

import asyncio
import threading
import time
import logging
import schedule
from typing import Dict, List, Optional, Set, Any, Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path

# Import OAuth components
from .oauth_client import DoD_OAuth_Client, DoD_OAuth_Manager, Platform, TokenResponse
from .secure_token_storage import TokenStorageManager, SecureTokenStorage
from .oauth_cac_bridge import OAuthCACBridge, IntegratedCredentials
from .concurrent_token_manager import ConcurrentTokenManager
from .oauth_audit_logger import EnhancedOAuthAuditLogger, OAuthAuditEventType

logger = logging.getLogger(__name__)


class TokenState(Enum):
    """Token lifecycle states."""
    ACTIVE = "active"
    EXPIRING_SOON = "expiring_soon"
    EXPIRED = "expired"
    REFRESH_PENDING = "refresh_pending"
    REFRESH_FAILED = "refresh_failed"
    REVOKED = "revoked"
    CLEANUP_PENDING = "cleanup_pending"


class LifecycleAction(Enum):
    """Token lifecycle actions."""
    REFRESH = "refresh"
    REVOKE = "revoke"
    CLEANUP = "cleanup"
    ARCHIVE = "archive"
    NOTIFY = "notify"


@dataclass
class TokenLifecyclePolicy:
    """Token lifecycle management policy."""
    # Refresh settings
    refresh_threshold_minutes: int = 15  # Refresh when token expires in 15 minutes
    auto_refresh_enabled: bool = True
    max_refresh_attempts: int = 3
    refresh_retry_delay: int = 60  # seconds
    
    # Cleanup settings
    cleanup_delay_hours: int = 24  # Keep expired tokens for 24 hours
    cleanup_batch_size: int = 100
    archive_before_cleanup: bool = True
    
    # Notification settings
    notify_before_expiry: bool = True
    notification_threshold_minutes: int = 30
    
    # Security settings
    revoke_on_suspicious_activity: bool = True
    max_concurrent_tokens_per_user: int = 5
    max_token_age_days: int = 30
    
    # Platform-specific policies
    platform_policies: Dict[str, Dict[str, Any]] = field(default_factory=dict)


@dataclass
class TokenMetrics:
    """Token lifecycle metrics."""
    total_tokens: int = 0
    active_tokens: int = 0
    expiring_tokens: int = 0
    expired_tokens: int = 0
    refreshed_tokens: int = 0
    failed_refreshes: int = 0
    revoked_tokens: int = 0
    cleaned_tokens: int = 0
    
    # Time-based metrics
    average_token_lifetime: float = 0.0
    refresh_success_rate: float = 0.0
    cleanup_efficiency: float = 0.0


class TokenLifecycleManager:
    """
    Automated token lifecycle manager.
    
    Manages the complete lifecycle of OAuth tokens including:
    - Automatic token refresh before expiration
    - Cleanup of expired tokens
    - Revocation of compromised tokens
    - Archival for compliance
    - Metrics and reporting
    """
    
    def __init__(self, 
                 policy: Optional[TokenLifecyclePolicy] = None,
                 storage_manager: Optional[TokenStorageManager] = None,
                 oauth_manager: Optional[DoD_OAuth_Manager] = None,
                 concurrent_manager: Optional[ConcurrentTokenManager] = None):
        """
        Initialize token lifecycle manager.
        
        Args:
            policy: Lifecycle management policy
            storage_manager: Token storage manager
            oauth_manager: OAuth client manager
            concurrent_manager: Concurrent token request manager
        """
        self.policy = policy or TokenLifecyclePolicy()
        self.storage_manager = storage_manager or TokenStorageManager.instance()
        self.oauth_manager = oauth_manager or DoD_OAuth_Manager()
        self.concurrent_manager = concurrent_manager
        
        # Audit logging
        self.audit_logger = EnhancedOAuthAuditLogger.instance()
        
        # Token tracking
        self.tracked_tokens: Dict[str, Dict[str, Any]] = {}
        self.refresh_queue: Set[str] = set()
        self.cleanup_queue: Set[str] = set()
        
        # Threading
        self._lock = threading.RLock()
        self._shutdown_event = threading.Event()
        self._executor = ThreadPoolExecutor(max_workers=5, thread_name_prefix="token-lifecycle")
        
        # Metrics
        self.metrics = TokenMetrics()
        
        # Lifecycle handlers
        self.lifecycle_handlers: Dict[LifecycleAction, List[Callable]] = {
            action: [] for action in LifecycleAction
        }
        
        # Initialize scheduler
        self._init_scheduler()
        
        # Start background tasks
        self._start_background_tasks()
        
        logger.info("Token lifecycle manager initialized")
    
    def _init_scheduler(self):
        """Initialize background task scheduler."""
        # Schedule token refresh checks every minute
        schedule.every(1).minutes.do(self._check_token_refresh)
        
        # Schedule cleanup every hour
        schedule.every().hour.do(self._cleanup_expired_tokens)
        
        # Schedule metrics update every 5 minutes
        schedule.every(5).minutes.do(self._update_metrics)
        
        # Schedule daily maintenance
        schedule.every().day.at("02:00").do(self._daily_maintenance)
    
    def _start_background_tasks(self):
        """Start background processing tasks."""
        # Scheduler thread
        def run_scheduler():
            while not self._shutdown_event.is_set():
                schedule.run_pending()
                time.sleep(30)  # Check every 30 seconds
        
        scheduler_thread = threading.Thread(target=run_scheduler, daemon=True)
        scheduler_thread.start()
        
        # Refresh processor thread
        def process_refresh_queue():
            while not self._shutdown_event.is_set():
                self._process_refresh_queue()
                time.sleep(60)  # Process every minute
        
        refresh_thread = threading.Thread(target=process_refresh_queue, daemon=True)
        refresh_thread.start()
        
        logger.info("Background tasks started")
    
    def register_token(self, user_id: str, platform: Platform, 
                      token: TokenResponse, metadata: Optional[Dict[str, Any]] = None):
        """
        Register token for lifecycle management.
        
        Args:
            user_id: User identifier
            platform: OAuth platform
            token: Token response
            metadata: Additional metadata
        """
        with self._lock:
            try:
                # Generate tracking ID
                tracking_id = f"{platform.value}_{user_id}_{int(time.time())}"
                
                # Store token
                token_id = self.storage_manager.store_token(
                    platform=platform,
                    user_id=user_id,
                    token=token,
                    metadata=metadata or {}
                )
                
                # Register for tracking
                self.tracked_tokens[tracking_id] = {
                    "token_id": token_id,
                    "user_id": user_id,
                    "platform": platform.value,
                    "created_at": datetime.now(timezone.utc),
                    "expires_at": token.expires_at,
                    "refresh_token": token.refresh_token,
                    "state": TokenState.ACTIVE,
                    "refresh_attempts": 0,
                    "last_refresh": None,
                    "metadata": metadata or {}
                }
                
                # Update metrics
                self.metrics.total_tokens += 1
                self.metrics.active_tokens += 1
                
                logger.debug(f"Token registered for lifecycle management: {tracking_id}")
                return tracking_id
                
            except Exception as e:
                logger.error(f"Failed to register token: {e}")
                return None
    
    def unregister_token(self, tracking_id: str):
        """
        Unregister token from lifecycle management.
        
        Args:
            tracking_id: Token tracking identifier
        """
        with self._lock:
            token_info = self.tracked_tokens.pop(tracking_id, None)
            if token_info:
                # Update metrics
                if token_info["state"] == TokenState.ACTIVE:
                    self.metrics.active_tokens -= 1
                
                logger.debug(f"Token unregistered: {tracking_id}")
    
    def _check_token_refresh(self):
        """Check tokens that need refresh."""
        with self._lock:
            current_time = datetime.now(timezone.utc)
            threshold = timedelta(minutes=self.policy.refresh_threshold_minutes)
            
            for tracking_id, token_info in self.tracked_tokens.items():
                if (token_info["state"] == TokenState.ACTIVE and
                    token_info["expires_at"] - current_time <= threshold and
                    token_info["refresh_token"] and
                    self.policy.auto_refresh_enabled):
                    
                    # Mark for refresh
                    token_info["state"] = TokenState.EXPIRING_SOON
                    self.refresh_queue.add(tracking_id)
                    
                    logger.debug(f"Token marked for refresh: {tracking_id}")
    
    def _process_refresh_queue(self):
        """Process tokens in refresh queue."""
        if not self.refresh_queue:
            return
        
        with self._lock:
            # Process a batch of refresh requests
            batch = list(self.refresh_queue)[:10]  # Process 10 at a time
            
            for tracking_id in batch:
                if tracking_id in self.tracked_tokens:
                    self._refresh_token_async(tracking_id)
                
                self.refresh_queue.discard(tracking_id)
    
    def _refresh_token_async(self, tracking_id: str):
        """Refresh token asynchronously."""
        def refresh_worker():
            try:
                self._refresh_token(tracking_id)
            except Exception as e:
                logger.error(f"Async token refresh failed: {e}")
        
        self._executor.submit(refresh_worker)
    
    def _refresh_token(self, tracking_id: str) -> bool:
        """
        Refresh a specific token.
        
        Args:
            tracking_id: Token tracking identifier
            
        Returns:
            True if refresh successful
        """
        with self._lock:
            token_info = self.tracked_tokens.get(tracking_id)
            if not token_info:
                return False
            
            try:
                token_info["state"] = TokenState.REFRESH_PENDING
                token_info["refresh_attempts"] += 1
                
                platform = Platform(token_info["platform"])
                user_id = token_info["user_id"]
                refresh_token = token_info["refresh_token"]
                
                # Get OAuth client
                oauth_client = self.oauth_manager.get_client(platform)
                if not oauth_client:
                    raise Exception(f"OAuth client not available for platform: {platform.value}")
                
                # Perform refresh
                if self.concurrent_manager:
                    # Use concurrent manager for refresh
                    request_id = self.concurrent_manager.request_token_async(
                        user_id=user_id,
                        platform=platform,
                        oauth_client=oauth_client,
                        request_type="refresh",
                        refresh_token=refresh_token
                    )
                    
                    # Wait for completion (with timeout)
                    new_token = self.concurrent_manager.wait_for_request(request_id, timeout=30)
                else:
                    # Direct refresh
                    new_token = oauth_client.refresh_access_token(refresh_token)
                
                if new_token:
                    # Update token storage
                    new_token_id = self.storage_manager.store_token(
                        platform=platform,
                        user_id=user_id,
                        token=new_token,
                        metadata=token_info["metadata"]
                    )
                    
                    # Update tracking info
                    token_info.update({
                        "token_id": new_token_id,
                        "expires_at": new_token.expires_at,
                        "refresh_token": new_token.refresh_token,
                        "state": TokenState.ACTIVE,
                        "last_refresh": datetime.now(timezone.utc)
                    })
                    
                    # Update metrics
                    self.metrics.refreshed_tokens += 1
                    
                    # Log successful refresh
                    self.audit_logger.log_token_refresh(
                        user_id=user_id,
                        platform=platform,
                        old_token_id=token_info["token_id"],
                        new_token_id=new_token_id,
                        success=True
                    )
                    
                    # Trigger refresh handlers
                    self._trigger_lifecycle_handlers(LifecycleAction.REFRESH, {
                        "tracking_id": tracking_id,
                        "token_info": token_info,
                        "new_token": new_token
                    })
                    
                    logger.info(f"Token refreshed successfully: {tracking_id}")
                    return True
                else:
                    raise Exception("Token refresh returned None")
                
            except Exception as e:
                logger.error(f"Token refresh failed for {tracking_id}: {e}")
                
                # Update state based on retry policy
                if token_info["refresh_attempts"] >= self.policy.max_refresh_attempts:
                    token_info["state"] = TokenState.REFRESH_FAILED
                    self.metrics.failed_refreshes += 1
                    
                    # Log failed refresh
                    self.audit_logger.log_token_refresh(
                        user_id=token_info["user_id"],
                        platform=Platform(token_info["platform"]),
                        old_token_id=token_info["token_id"],
                        success=False,
                        error_message=str(e)
                    )
                else:
                    # Retry later
                    token_info["state"] = TokenState.EXPIRING_SOON
                    # Re-queue with delay
                    def delayed_retry():
                        time.sleep(self.policy.refresh_retry_delay)
                        with self._lock:
                            if tracking_id in self.tracked_tokens:
                                self.refresh_queue.add(tracking_id)
                    
                    self._executor.submit(delayed_retry)
                
                return False
    
    def _cleanup_expired_tokens(self):
        """Clean up expired tokens."""
        with self._lock:
            current_time = datetime.now(timezone.utc)
            cleanup_threshold = timedelta(hours=self.policy.cleanup_delay_hours)
            
            expired_tokens = []
            
            for tracking_id, token_info in self.tracked_tokens.items():
                # Check if token is expired and past cleanup threshold
                if (token_info["expires_at"] < current_time - cleanup_threshold or
                    token_info["state"] in [TokenState.EXPIRED, TokenState.REFRESH_FAILED]):
                    
                    expired_tokens.append(tracking_id)
            
            # Process cleanup in batches
            for i in range(0, len(expired_tokens), self.policy.cleanup_batch_size):
                batch = expired_tokens[i:i + self.policy.cleanup_batch_size]
                self._cleanup_token_batch(batch)
    
    def _cleanup_token_batch(self, tracking_ids: List[str]):
        """Clean up a batch of tokens."""
        def cleanup_worker():
            for tracking_id in tracking_ids:
                try:
                    self._cleanup_token(tracking_id)
                except Exception as e:
                    logger.error(f"Token cleanup failed for {tracking_id}: {e}")
        
        self._executor.submit(cleanup_worker)
    
    def _cleanup_token(self, tracking_id: str):
        """Clean up a specific token."""
        with self._lock:
            token_info = self.tracked_tokens.get(tracking_id)
            if not token_info:
                return
            
            try:
                platform = Platform(token_info["platform"])
                user_id = token_info["user_id"]
                
                # Archive token if policy requires
                if self.policy.archive_before_cleanup:
                    self._archive_token(token_info)
                
                # Revoke token if still valid
                if token_info["state"] != TokenState.REVOKED:
                    try:
                        oauth_client = self.oauth_manager.get_client(platform)
                        if oauth_client:
                            # Get current token from storage
                            current_token = self.storage_manager.get_token(platform, user_id)
                            if current_token:
                                oauth_client.revoke_token(current_token.access_token)
                    except Exception as revoke_error:
                        logger.warning(f"Token revocation failed during cleanup: {revoke_error}")
                
                # Remove from storage
                self.storage_manager.remove_token(platform, user_id)
                
                # Remove from tracking
                self.unregister_token(tracking_id)
                
                # Update metrics
                self.metrics.cleaned_tokens += 1
                
                # Trigger cleanup handlers
                self._trigger_lifecycle_handlers(LifecycleAction.CLEANUP, {
                    "tracking_id": tracking_id,
                    "token_info": token_info
                })
                
                logger.debug(f"Token cleaned up: {tracking_id}")
                
            except Exception as e:
                logger.error(f"Token cleanup failed: {e}")
    
    def _archive_token(self, token_info: Dict[str, Any]):
        """Archive token for compliance."""
        try:
            # Create archive directory
            archive_dir = Path.home() / ".dod_oauth_archive"
            archive_dir.mkdir(exist_ok=True, mode=0o700)
            
            # Create archive record (without sensitive data)
            archive_record = {
                "user_id": token_info["user_id"],
                "platform": token_info["platform"],
                "created_at": token_info["created_at"].isoformat(),
                "expires_at": token_info["expires_at"].isoformat(),
                "last_refresh": token_info["last_refresh"].isoformat() if token_info["last_refresh"] else None,
                "refresh_attempts": token_info["refresh_attempts"],
                "final_state": token_info["state"].value,
                "archived_at": datetime.now(timezone.utc).isoformat(),
                "metadata": token_info["metadata"]
            }
            
            # Save archive record
            archive_file = archive_dir / f"token_{int(time.time())}_{token_info['user_id']}.json"
            with open(archive_file, 'w') as f:
                json.dump(archive_record, f, indent=2)
            
            logger.debug(f"Token archived: {archive_file}")
            
        except Exception as e:
            logger.error(f"Token archival failed: {e}")
    
    def revoke_token(self, tracking_id: str, reason: str = "manual_revocation") -> bool:
        """
        Manually revoke a token.
        
        Args:
            tracking_id: Token tracking identifier
            reason: Revocation reason
            
        Returns:
            True if revocation successful
        """
        with self._lock:
            token_info = self.tracked_tokens.get(tracking_id)
            if not token_info:
                return False
            
            try:
                platform = Platform(token_info["platform"])
                user_id = token_info["user_id"]
                
                # Get OAuth client
                oauth_client = self.oauth_manager.get_client(platform)
                if not oauth_client:
                    return False
                
                # Get current token
                current_token = self.storage_manager.get_token(platform, user_id)
                if not current_token:
                    return False
                
                # Revoke token
                success = oauth_client.revoke_token(current_token.access_token)
                
                if success:
                    # Update state
                    token_info["state"] = TokenState.REVOKED
                    
                    # Remove from storage
                    self.storage_manager.remove_token(platform, user_id)
                    
                    # Update metrics
                    self.metrics.revoked_tokens += 1
                    
                    # Log revocation
                    self.audit_logger.log_oauth_event({
                        "event_type": OAuthAuditEventType.OAUTH_TOKEN_REVOCATION,
                        "user_id": user_id,
                        "platform": platform.value,
                        "success": True,
                        "additional_data": {"reason": reason}
                    })
                    
                    # Trigger revoke handlers
                    self._trigger_lifecycle_handlers(LifecycleAction.REVOKE, {
                        "tracking_id": tracking_id,
                        "token_info": token_info,
                        "reason": reason
                    })
                    
                    logger.info(f"Token revoked: {tracking_id} (reason: {reason})")
                    return True
                
            except Exception as e:
                logger.error(f"Token revocation failed: {e}")
                
            return False
    
    def _update_metrics(self):
        """Update lifecycle metrics."""
        with self._lock:
            # Count tokens by state
            active_count = 0
            expiring_count = 0
            expired_count = 0
            
            current_time = datetime.now(timezone.utc)
            
            for token_info in self.tracked_tokens.values():
                if token_info["state"] == TokenState.ACTIVE:
                    active_count += 1
                elif token_info["state"] == TokenState.EXPIRING_SOON:
                    expiring_count += 1
                elif token_info["expires_at"] < current_time:
                    expired_count += 1
            
            # Update metrics
            self.metrics.active_tokens = active_count
            self.metrics.expiring_tokens = expiring_count
            self.metrics.expired_tokens = expired_count
            
            # Calculate rates
            if self.metrics.refreshed_tokens + self.metrics.failed_refreshes > 0:
                self.metrics.refresh_success_rate = (
                    self.metrics.refreshed_tokens / 
                    (self.metrics.refreshed_tokens + self.metrics.failed_refreshes) * 100
                )
    
    def _daily_maintenance(self):
        """Perform daily maintenance tasks."""
        try:
            # Force cleanup of very old tokens
            self._cleanup_expired_tokens()
            
            # Update metrics
            self._update_metrics()
            
            # Check for tokens approaching max age
            self._check_max_age_policy()
            
            # Generate daily metrics report
            self._generate_daily_report()
            
            logger.info("Daily maintenance completed")
            
        except Exception as e:
            logger.error(f"Daily maintenance failed: {e}")
    
    def _check_max_age_policy(self):
        """Check for tokens exceeding maximum age policy."""
        if self.policy.max_token_age_days <= 0:
            return
        
        max_age = timedelta(days=self.policy.max_token_age_days)
        current_time = datetime.now(timezone.utc)
        
        for tracking_id, token_info in list(self.tracked_tokens.items()):
            token_age = current_time - token_info["created_at"]
            
            if token_age > max_age:
                logger.warning(f"Token exceeds max age policy: {tracking_id}")
                self.revoke_token(tracking_id, "max_age_policy")
    
    def _generate_daily_report(self):
        """Generate daily metrics report."""
        try:
            report = {
                "date": datetime.now(timezone.utc).date().isoformat(),
                "metrics": {
                    "total_tokens": self.metrics.total_tokens,
                    "active_tokens": self.metrics.active_tokens,
                    "expiring_tokens": self.metrics.expiring_tokens,
                    "expired_tokens": self.metrics.expired_tokens,
                    "refreshed_tokens": self.metrics.refreshed_tokens,
                    "failed_refreshes": self.metrics.failed_refreshes,
                    "revoked_tokens": self.metrics.revoked_tokens,
                    "cleaned_tokens": self.metrics.cleaned_tokens,
                    "refresh_success_rate": self.metrics.refresh_success_rate
                },
                "generated_at": datetime.now(timezone.utc).isoformat()
            }
            
            # Save report
            reports_dir = Path.home() / ".dod_oauth_reports"
            reports_dir.mkdir(exist_ok=True, mode=0o700)
            
            report_file = reports_dir / f"daily_report_{report['date']}.json"
            with open(report_file, 'w') as f:
                json.dump(report, f, indent=2)
            
            logger.info(f"Daily report generated: {report_file}")
            
        except Exception as e:
            logger.error(f"Daily report generation failed: {e}")
    
    def add_lifecycle_handler(self, action: LifecycleAction, 
                            handler: Callable[[Dict[str, Any]], None]):
        """Add handler for lifecycle events."""
        self.lifecycle_handlers[action].append(handler)
    
    def _trigger_lifecycle_handlers(self, action: LifecycleAction, data: Dict[str, Any]):
        """Trigger registered lifecycle handlers."""
        for handler in self.lifecycle_handlers[action]:
            try:
                handler(data)
            except Exception as e:
                logger.error(f"Lifecycle handler error: {e}")
    
    def get_token_status(self, tracking_id: str) -> Optional[Dict[str, Any]]:
        """Get current status of a tracked token."""
        with self._lock:
            token_info = self.tracked_tokens.get(tracking_id)
            if not token_info:
                return None
            
            return {
                "tracking_id": tracking_id,
                "user_id": token_info["user_id"],
                "platform": token_info["platform"],
                "state": token_info["state"].value,
                "created_at": token_info["created_at"].isoformat(),
                "expires_at": token_info["expires_at"].isoformat(),
                "refresh_attempts": token_info["refresh_attempts"],
                "last_refresh": token_info["last_refresh"].isoformat() if token_info["last_refresh"] else None,
                "time_to_expiry": str(token_info["expires_at"] - datetime.now(timezone.utc))
            }
    
    def get_metrics(self) -> TokenMetrics:
        """Get current lifecycle metrics."""
        self._update_metrics()
        return self.metrics
    
    def shutdown(self):
        """Shutdown lifecycle manager."""
        logger.info("Shutting down token lifecycle manager")
        
        # Signal shutdown
        self._shutdown_event.set()
        
        # Shutdown executor
        self._executor.shutdown(wait=True)
        
        logger.info("Token lifecycle manager shutdown complete")


# Convenience functions
def create_lifecycle_manager(policy: Optional[TokenLifecyclePolicy] = None) -> TokenLifecycleManager:
    """Create token lifecycle manager with default components."""
    return TokenLifecycleManager(policy=policy)


def setup_default_lifecycle_handlers(manager: TokenLifecycleManager):
    """Setup default lifecycle event handlers."""
    
    def log_refresh_handler(data: Dict[str, Any]):
        """Default refresh handler."""
        logger.info(f"Token refreshed: {data['tracking_id']}")
    
    def log_cleanup_handler(data: Dict[str, Any]):
        """Default cleanup handler."""
        logger.info(f"Token cleaned up: {data['tracking_id']}")
    
    def log_revoke_handler(data: Dict[str, Any]):
        """Default revoke handler."""
        logger.warning(f"Token revoked: {data['tracking_id']} (reason: {data.get('reason', 'unknown')})")
    
    manager.add_lifecycle_handler(LifecycleAction.REFRESH, log_refresh_handler)
    manager.add_lifecycle_handler(LifecycleAction.CLEANUP, log_cleanup_handler)
    manager.add_lifecycle_handler(LifecycleAction.REVOKE, log_revoke_handler)