"""
Cross-Platform Session Management with Synchronized State

Unified session handling across all platforms with synchronized state, real-time 
updates, and comprehensive session correlation for enterprise-grade session management.

This module provides:
- PlatformSessionManager: Centralized session management across platforms
- SessionSyncManager: Real-time session state synchronization
- Cross-platform session correlation and tracking
- Session security with timeout and validation
- Emergency session termination and cleanup
- Comprehensive session audit and monitoring

Classification: UNCLASSIFIED//FOR OFFICIAL USE ONLY
"""

import asyncio
import logging
import json
import time
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Set, Tuple
from uuid import UUID, uuid4
from dataclasses import dataclass, field, asdict
from enum import Enum
from concurrent.futures import ThreadPoolExecutor

# Import session management components
from ...sessions.session_manager import SessionManager
from ...sessions.session_security import SessionSecurity

# Import unified components
from .context import SessionInfo, PlatformContext, PlatformStatus
from .config import UnifiedAccessConfig

logger = logging.getLogger(__name__)


class SessionState(Enum):
    """Session state enumeration."""
    ACTIVE = "active"
    IDLE = "idle"
    EXPIRED = "expired"
    TERMINATED = "terminated"
    LOCKED = "locked"
    SUSPENDED = "suspended"


class SyncStatus(Enum):
    """Session synchronization status."""
    SYNCED = "synced"
    PENDING = "pending"
    FAILED = "failed"
    CONFLICT = "conflict"


@dataclass
class PlatformSession:
    """Platform-specific session information."""
    platform: str
    platform_session_id: str
    user_id: UUID
    status: SessionState = SessionState.ACTIVE
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_activity: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: Optional[datetime] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    oauth_token: Optional[str] = None
    oauth_expires_at: Optional[datetime] = None
    platform_attributes: Dict[str, Any] = field(default_factory=dict)
    access_count: int = 0
    last_sync: Optional[datetime] = None
    sync_status: SyncStatus = SyncStatus.PENDING
    
    def is_active(self) -> bool:
        """Check if platform session is active."""
        now = datetime.now(timezone.utc)
        
        # Check expiry
        if self.expires_at and now > self.expires_at:
            return False
        
        # Check OAuth token expiry
        if self.oauth_expires_at and now > self.oauth_expires_at:
            return False
        
        # Check activity timeout (default 2 hours for platform sessions)
        activity_timeout = timedelta(hours=2)
        if now - self.last_activity > activity_timeout:
            return False
        
        return self.status == SessionState.ACTIVE
    
    def update_activity(self):
        """Update last activity timestamp."""
        self.last_activity = datetime.now(timezone.utc)
        self.access_count += 1
        self.sync_status = SyncStatus.PENDING
    
    def mark_synced(self):
        """Mark session as synchronized."""
        self.last_sync = datetime.now(timezone.utc)
        self.sync_status = SyncStatus.SYNCED
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        result = asdict(self)
        result['status'] = self.status.value
        result['sync_status'] = self.sync_status.value
        result['user_id'] = str(self.user_id)
        
        # Convert datetime fields
        for field_name in ['created_at', 'last_activity', 'expires_at', 'oauth_expires_at', 'last_sync']:
            if hasattr(self, field_name):
                value = getattr(self, field_name)
                if value:
                    result[field_name] = value.isoformat()
        
        # Don't include sensitive tokens
        result.pop('oauth_token', None)
        
        return result


@dataclass
class UnifiedSession:
    """Unified session across all platforms."""
    session_id: str
    user_id: UUID
    master_session_id: str  # Core session manager session ID
    state: SessionState = SessionState.ACTIVE
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_activity: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: Optional[datetime] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    authentication_methods: List[str] = field(default_factory=list)
    platform_sessions: Dict[str, PlatformSession] = field(default_factory=dict)
    session_attributes: Dict[str, Any] = field(default_factory=dict)
    security_events: List[Dict[str, Any]] = field(default_factory=list)
    last_sync: Optional[datetime] = None
    
    def add_platform_session(self, platform: str, platform_session: PlatformSession):
        """Add platform session."""
        self.platform_sessions[platform] = platform_session
        self.last_activity = datetime.now(timezone.utc)
    
    def remove_platform_session(self, platform: str):
        """Remove platform session."""
        self.platform_sessions.pop(platform, None)
        self.last_activity = datetime.now(timezone.utc)
    
    def get_active_platforms(self) -> List[str]:
        """Get list of active platforms."""
        return [
            platform for platform, session in self.platform_sessions.items()
            if session.is_active()
        ]
    
    def get_expired_platforms(self) -> List[str]:
        """Get list of platforms with expired sessions."""
        return [
            platform for platform, session in self.platform_sessions.items()
            if not session.is_active()
        ]
    
    def is_active(self) -> bool:
        """Check if unified session is active."""
        now = datetime.now(timezone.utc)
        
        # Check expiry
        if self.expires_at and now > self.expires_at:
            return False
        
        # Check activity timeout (default 8 hours)
        activity_timeout = timedelta(hours=8)
        if now - self.last_activity > activity_timeout:
            return False
        
        # Must have at least one active platform session
        if not self.get_active_platforms():
            return False
        
        return self.state == SessionState.ACTIVE
    
    def update_activity(self, platform: str = None):
        """Update session activity."""
        self.last_activity = datetime.now(timezone.utc)
        
        if platform and platform in self.platform_sessions:
            self.platform_sessions[platform].update_activity()
    
    def add_security_event(self, event_type: str, details: Dict[str, Any]):
        """Add security event to session."""
        event = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'event_type': event_type,
            'details': details
        }
        self.security_events.append(event)
        
        # Keep only last 50 events
        if len(self.security_events) > 50:
            self.security_events = self.security_events[-50:]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        result = asdict(self)
        result['state'] = self.state.value
        result['user_id'] = str(self.user_id)
        
        # Convert datetime fields
        for field_name in ['created_at', 'last_activity', 'expires_at', 'last_sync']:
            if hasattr(self, field_name):
                value = getattr(self, field_name)
                if value:
                    result[field_name] = value.isoformat()
        
        # Convert platform sessions
        result['platform_sessions'] = {
            platform: session.to_dict()
            for platform, session in self.platform_sessions.items()
        }
        
        return result


class SessionSyncManager:
    """
    Real-time session state synchronization manager.
    
    Handles:
    - Real-time synchronization of session state across platforms
    - Conflict resolution for concurrent session updates
    - Session correlation and state consistency
    - Automatic retry and recovery for failed synchronizations
    """
    
    def __init__(self, config: UnifiedAccessConfig):
        """Initialize session sync manager."""
        self.config = config
        self.sync_interval = config.session_sync_interval
        self.max_sync_retries = 3
        self.sync_timeout = 30  # seconds
        
        # Sync tracking
        self._pending_syncs: Dict[str, datetime] = {}
        self._failed_syncs: Dict[str, int] = {}  # session_id -> retry_count
        self._sync_conflicts: List[Dict[str, Any]] = []
        
        # Background tasks
        self._sync_task: Optional[asyncio.Task] = None
        self._shutdown_event = asyncio.Event()
        
        logger.info("Session Sync Manager initialized")
    
    async def start(self):
        """Start background synchronization tasks."""
        if self._sync_task:
            return
        
        self._sync_task = asyncio.create_task(self._sync_loop())
        logger.info("Session synchronization started")
    
    async def stop(self):
        """Stop background synchronization tasks."""
        if self._sync_task:
            self._shutdown_event.set()
            self._sync_task.cancel()
            try:
                await self._sync_task
            except asyncio.CancelledError:
                pass
            self._sync_task = None
        
        logger.info("Session synchronization stopped")
    
    async def _sync_loop(self):
        """Background synchronization loop."""
        while not self._shutdown_event.is_set():
            try:
                await self._process_pending_syncs()
                await asyncio.sleep(self.sync_interval)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Session sync loop error: {e}")
                await asyncio.sleep(self.sync_interval)
    
    async def _process_pending_syncs(self):
        """Process pending session synchronizations."""
        current_time = datetime.now(timezone.utc)
        
        # Find sessions that need sync
        sessions_to_sync = []
        for session_id, pending_since in self._pending_syncs.items():
            if current_time - pending_since > timedelta(seconds=self.sync_interval):
                sessions_to_sync.append(session_id)
        
        # Process synchronizations
        for session_id in sessions_to_sync:
            try:
                await self._sync_session(session_id)
                self._pending_syncs.pop(session_id, None)
                self._failed_syncs.pop(session_id, None)
                
            except Exception as e:
                logger.error(f"Failed to sync session {session_id}: {e}")
                
                # Track retry count
                retry_count = self._failed_syncs.get(session_id, 0) + 1
                self._failed_syncs[session_id] = retry_count
                
                if retry_count >= self.max_sync_retries:
                    logger.error(f"Max sync retries exceeded for session {session_id}")
                    self._pending_syncs.pop(session_id, None)
                    self._failed_syncs.pop(session_id, None)
    
    async def _sync_session(self, session_id: str):
        """Synchronize a specific session."""
        # This would implement actual session synchronization logic
        # For now, we'll just mark as processed
        logger.debug(f"Syncing session: {session_id}")
    
    def queue_sync(self, session_id: str):
        """Queue session for synchronization."""
        self._pending_syncs[session_id] = datetime.now(timezone.utc)
    
    def get_sync_metrics(self) -> Dict[str, Any]:
        """Get synchronization metrics."""
        return {
            'pending_syncs': len(self._pending_syncs),
            'failed_syncs': len(self._failed_syncs),
            'sync_conflicts': len(self._sync_conflicts),
            'max_retry_count': max(self._failed_syncs.values()) if self._failed_syncs else 0
        }


class PlatformSessionManager:
    """
    Centralized session management across all platforms.
    
    Provides:
    - Unified session lifecycle management across platforms
    - Cross-platform session correlation and state tracking
    - Session security with timeout and validation
    - Real-time session synchronization
    - Emergency session termination procedures
    - Comprehensive session audit and monitoring
    """
    
    def __init__(self, config: UnifiedAccessConfig):
        """Initialize platform session manager."""
        self.config = config
        
        # Core session manager integration
        self.core_session_manager = SessionManager(config.database_connection)
        self.session_security = SessionSecurity()
        
        # Session storage
        self.unified_sessions: Dict[str, UnifiedSession] = {}
        self.user_sessions: Dict[UUID, Set[str]] = {}  # user_id -> session_ids
        self.platform_sessions: Dict[str, Dict[str, str]] = {}  # platform -> {platform_session_id -> unified_session_id}
        
        # Configuration
        self.session_timeout = timedelta(hours=config.session_timeout_hours)
        self.platform_timeout = timedelta(hours=2)  # Platform sessions timeout faster
        self.cleanup_interval = 300  # 5 minutes
        
        # Synchronization
        self.sync_manager = SessionSyncManager(config)
        
        # Background tasks
        self._cleanup_task: Optional[asyncio.Task] = None
        self._shutdown_event = asyncio.Event()
        
        # Metrics
        self._session_created_count = 0
        self._session_terminated_count = 0
        self._platform_session_count = 0
        
        logger.info("Platform Session Manager initialized")
    
    async def start(self):
        """Start session manager and background tasks."""
        # Start sync manager
        await self.sync_manager.start()
        
        # Start cleanup task
        if not self._cleanup_task:
            self._cleanup_task = asyncio.create_task(self._cleanup_loop())
        
        logger.info("Platform Session Manager started")
    
    async def stop(self):
        """Stop session manager and background tasks."""
        # Stop sync manager
        await self.sync_manager.stop()
        
        # Stop cleanup task
        if self._cleanup_task:
            self._shutdown_event.set()
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass
            self._cleanup_task = None
        
        logger.info("Platform Session Manager stopped")
    
    async def create_unified_session(self, user_id: UUID, ip_address: str = None,
                                   user_agent: str = None, 
                                   authentication_methods: List[str] = None) -> str:
        """
        Create new unified session across platforms.
        
        Args:
            user_id: User identifier
            ip_address: Client IP address
            user_agent: Client user agent
            authentication_methods: List of authentication methods used
            
        Returns:
            Unified session ID
        """
        try:
            # Create core session
            master_session_id = await asyncio.get_event_loop().run_in_executor(
                None,
                self.core_session_manager.create_session,
                user_id, ip_address, user_agent
            )
            
            # Generate unified session ID
            unified_session_id = str(uuid4())
            
            # Create unified session
            expires_at = datetime.now(timezone.utc) + self.session_timeout
            
            unified_session = UnifiedSession(
                session_id=unified_session_id,
                user_id=user_id,
                master_session_id=master_session_id,
                expires_at=expires_at,
                ip_address=ip_address,
                user_agent=user_agent,
                authentication_methods=authentication_methods or []
            )
            
            # Store session
            self.unified_sessions[unified_session_id] = unified_session
            
            # Track by user
            if user_id not in self.user_sessions:
                self.user_sessions[user_id] = set()
            self.user_sessions[user_id].add(unified_session_id)
            
            # Initialize platform session tracking
            for platform in self.config.platform_configs.keys():
                if platform not in self.platform_sessions:
                    self.platform_sessions[platform] = {}
            
            # Add security event
            unified_session.add_security_event('session_created', {
                'ip_address': ip_address,
                'user_agent': user_agent,
                'authentication_methods': authentication_methods
            })
            
            # Queue for synchronization
            self.sync_manager.queue_sync(unified_session_id)
            
            self._session_created_count += 1
            
            logger.info(f"Created unified session {unified_session_id} for user {user_id}")
            return unified_session_id
            
        except Exception as e:
            logger.error(f"Failed to create unified session for user {user_id}: {e}")
            raise
    
    async def add_platform_session(self, unified_session_id: str, platform: str,
                                 platform_session_id: str, oauth_token: str = None,
                                 oauth_expires_at: datetime = None,
                                 platform_attributes: Dict[str, Any] = None) -> bool:
        """
        Add platform session to unified session.
        
        Args:
            unified_session_id: Unified session identifier
            platform: Platform name
            platform_session_id: Platform-specific session identifier
            oauth_token: OAuth access token
            oauth_expires_at: OAuth token expiration
            platform_attributes: Platform-specific attributes
            
        Returns:
            True if successful
        """
        try:
            unified_session = self.unified_sessions.get(unified_session_id)
            if not unified_session or not unified_session.is_active():
                logger.warning(f"Invalid or inactive unified session: {unified_session_id}")
                return False
            
            # Create platform session
            platform_session = PlatformSession(
                platform=platform,
                platform_session_id=platform_session_id,
                user_id=unified_session.user_id,
                ip_address=unified_session.ip_address,
                user_agent=unified_session.user_agent,
                oauth_token=oauth_token,
                oauth_expires_at=oauth_expires_at,
                platform_attributes=platform_attributes or {}
            )
            
            # Add to unified session
            unified_session.add_platform_session(platform, platform_session)
            
            # Track platform session mapping
            if platform not in self.platform_sessions:
                self.platform_sessions[platform] = {}
            self.platform_sessions[platform][platform_session_id] = unified_session_id
            
            # Add security event
            unified_session.add_security_event('platform_session_added', {
                'platform': platform,
                'platform_session_id': platform_session_id
            })
            
            # Queue for synchronization
            self.sync_manager.queue_sync(unified_session_id)
            
            self._platform_session_count += 1
            
            logger.info(f"Added platform session {platform_session_id} ({platform}) to unified session {unified_session_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to add platform session: {e}")
            return False
    
    async def remove_platform_session(self, unified_session_id: str, platform: str) -> bool:
        """
        Remove platform session from unified session.
        
        Args:
            unified_session_id: Unified session identifier
            platform: Platform name
            
        Returns:
            True if successful
        """
        try:
            unified_session = self.unified_sessions.get(unified_session_id)
            if not unified_session:
                return False
            
            # Get platform session
            platform_session = unified_session.platform_sessions.get(platform)
            if not platform_session:
                return False
            
            # Remove from platform session mapping
            platform_session_id = platform_session.platform_session_id
            if platform in self.platform_sessions:
                self.platform_sessions[platform].pop(platform_session_id, None)
            
            # Remove from unified session
            unified_session.remove_platform_session(platform)
            
            # Add security event
            unified_session.add_security_event('platform_session_removed', {
                'platform': platform,
                'platform_session_id': platform_session_id
            })
            
            # Queue for synchronization
            self.sync_manager.queue_sync(unified_session_id)
            
            logger.info(f"Removed platform session from {platform} for unified session {unified_session_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to remove platform session: {e}")
            return False
    
    async def update_session_access(self, unified_session_id: str, platform: str,
                                  resource_type: str, action: str) -> bool:
        """
        Update session access tracking.
        
        Args:
            unified_session_id: Unified session identifier
            platform: Platform name
            resource_type: Resource type accessed
            action: Action performed
            
        Returns:
            True if successful
        """
        try:
            unified_session = self.unified_sessions.get(unified_session_id)
            if not unified_session or not unified_session.is_active():
                return False
            
            # Update session activity
            unified_session.update_activity(platform)
            
            # Add access event
            unified_session.add_security_event('resource_access', {
                'platform': platform,
                'resource_type': resource_type,
                'action': action
            })
            
            # Queue for synchronization
            self.sync_manager.queue_sync(unified_session_id)
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to update session access: {e}")
            return False
    
    async def get_session_info(self, unified_session_id: str) -> Optional[Dict[str, Any]]:
        """Get comprehensive session information."""
        unified_session = self.unified_sessions.get(unified_session_id)
        if not unified_session:
            return None
        
        return unified_session.to_dict()
    
    async def get_user_sessions(self, user_id: UUID) -> List[Dict[str, Any]]:
        """Get all sessions for a user."""
        session_ids = self.user_sessions.get(user_id, set())
        sessions = []
        
        for session_id in session_ids:
            unified_session = self.unified_sessions.get(session_id)
            if unified_session:
                sessions.append(unified_session.to_dict())
        
        return sessions
    
    async def terminate_session(self, unified_session_id: str, reason: str = "user_logout") -> bool:
        """
        Terminate unified session and all platform sessions.
        
        Args:
            unified_session_id: Unified session identifier
            reason: Termination reason
            
        Returns:
            True if successful
        """
        try:
            unified_session = self.unified_sessions.get(unified_session_id)
            if not unified_session:
                return False
            
            # Terminate core session
            await asyncio.get_event_loop().run_in_executor(
                None,
                self.core_session_manager.terminate_session,
                unified_session.master_session_id
            )
            
            # Remove platform session mappings
            for platform, platform_session in unified_session.platform_sessions.items():
                platform_session_id = platform_session.platform_session_id
                if platform in self.platform_sessions:
                    self.platform_sessions[platform].pop(platform_session_id, None)
            
            # Update session state
            unified_session.state = SessionState.TERMINATED
            unified_session.add_security_event('session_terminated', {
                'reason': reason,
                'terminated_at': datetime.now(timezone.utc).isoformat()
            })
            
            # Remove from user sessions
            user_id = unified_session.user_id
            if user_id in self.user_sessions:
                self.user_sessions[user_id].discard(unified_session_id)
                if not self.user_sessions[user_id]:
                    del self.user_sessions[user_id]
            
            # Remove from storage
            del self.unified_sessions[unified_session_id]
            
            self._session_terminated_count += 1
            
            logger.info(f"Terminated unified session {unified_session_id}, reason: {reason}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to terminate session {unified_session_id}: {e}")
            return False
    
    async def terminate_user_sessions(self, user_id: UUID, reason: str = "admin_action") -> int:
        """
        Terminate all sessions for a user.
        
        Args:
            user_id: User identifier
            reason: Termination reason
            
        Returns:
            Number of sessions terminated
        """
        session_ids = self.user_sessions.get(user_id, set()).copy()
        terminated_count = 0
        
        for session_id in session_ids:
            if await self.terminate_session(session_id, reason):
                terminated_count += 1
        
        logger.info(f"Terminated {terminated_count} sessions for user {user_id}")
        return terminated_count
    
    async def invalidate_user_sessions(self, user_id: UUID) -> int:
        """
        Invalidate all sessions for a user (marks as expired).
        
        Args:
            user_id: User identifier
            
        Returns:
            Number of sessions invalidated
        """
        session_ids = self.user_sessions.get(user_id, set()).copy()
        invalidated_count = 0
        
        for session_id in session_ids:
            unified_session = self.unified_sessions.get(session_id)
            if unified_session:
                unified_session.state = SessionState.EXPIRED
                unified_session.expires_at = datetime.now(timezone.utc)
                unified_session.add_security_event('session_invalidated', {
                    'reason': 'user_cache_invalidation'
                })
                invalidated_count += 1
        
        logger.info(f"Invalidated {invalidated_count} sessions for user {user_id}")
        return invalidated_count
    
    async def invalidate_platform_sessions(self, platform: str) -> int:
        """
        Invalidate all sessions for a platform.
        
        Args:
            platform: Platform name
            
        Returns:
            Number of sessions invalidated
        """
        invalidated_count = 0
        
        for unified_session in self.unified_sessions.values():
            if platform in unified_session.platform_sessions:
                platform_session = unified_session.platform_sessions[platform]
                platform_session.status = SessionState.EXPIRED
                platform_session.sync_status = SyncStatus.PENDING
                unified_session.add_security_event('platform_session_invalidated', {
                    'platform': platform,
                    'reason': 'platform_cache_invalidation'
                })
                invalidated_count += 1
        
        logger.info(f"Invalidated {invalidated_count} platform sessions for {platform}")
        return invalidated_count
    
    async def _cleanup_loop(self):
        """Background cleanup loop for expired sessions."""
        while not self._shutdown_event.is_set():
            try:
                await self._cleanup_expired_sessions()
                await asyncio.sleep(self.cleanup_interval)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Session cleanup error: {e}")
                await asyncio.sleep(self.cleanup_interval)
    
    async def _cleanup_expired_sessions(self):
        """Clean up expired sessions."""
        now = datetime.now(timezone.utc)
        expired_sessions = []
        
        for session_id, unified_session in self.unified_sessions.items():
            if not unified_session.is_active():
                expired_sessions.append(session_id)
        
        for session_id in expired_sessions:
            await self.terminate_session(session_id, "session_expired")
        
        if expired_sessions:
            logger.info(f"Cleaned up {len(expired_sessions)} expired sessions")
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get comprehensive session metrics."""
        active_sessions = len([s for s in self.unified_sessions.values() if s.is_active()])
        total_platform_sessions = sum(
            len(sessions) for sessions in self.platform_sessions.values()
        )
        
        platform_session_counts = {
            platform: len(sessions) 
            for platform, sessions in self.platform_sessions.items()
        }
        
        return {
            'session_manager': {
                'total_sessions': len(self.unified_sessions),
                'active_sessions': active_sessions,
                'total_users': len(self.user_sessions),
                'sessions_created': self._session_created_count,
                'sessions_terminated': self._session_terminated_count,
                'platform_sessions_total': total_platform_sessions,
                'platform_session_counts': platform_session_counts
            },
            'sync_manager': self.sync_manager.get_sync_metrics()
        }
    
    async def health_check(self) -> Dict[str, Any]:
        """Perform health check on session manager."""
        try:
            # Check active sessions
            active_sessions = len([s for s in self.unified_sessions.values() if s.is_active()])
            
            # Check sync manager
            sync_metrics = self.sync_manager.get_sync_metrics()
            
            # Check core session manager
            # (would perform actual health check on core session manager)
            
            return {
                'status': 'healthy',
                'active_sessions': active_sessions,
                'sync_pending': sync_metrics['pending_syncs'],
                'sync_failed': sync_metrics['failed_syncs'],
                'background_tasks_running': not self._cleanup_task.done() if self._cleanup_task else False
            }
            
        except Exception as e:
            return {
                'status': 'unhealthy',
                'error': str(e)
            }
    
    async def close(self):
        """Close session manager and cleanup resources."""
        await self.stop()
        
        # Close core session manager if it has a close method
        if hasattr(self.core_session_manager, 'close'):
            await self.core_session_manager.close()
        
        logger.info("Platform Session Manager closed")