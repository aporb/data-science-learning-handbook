"""
Key Rotation Policies and Procedures

This module implements comprehensive key rotation policies and automated procedures
for maintaining cryptographic key security throughout their lifecycle.

Features:
- Automated key rotation scheduling
- Policy-based rotation triggers
- Zero-downtime key transitions
- Key version management
- Rollback capabilities
- Compliance monitoring
- Performance optimization
"""

import asyncio
import logging
import threading
import time
from typing import Dict, List, Optional, Tuple, Any, Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
import json
import hashlib

from .key_manager import KeyManager, KeyType, KeyMetadata, KeyManagerError
from .fips_compliance import FIPSComplianceManager


class RotationTrigger(Enum):
    """Key rotation trigger types."""
    TIME_BASED = "time_based"
    USAGE_BASED = "usage_based"
    EVENT_BASED = "event_based"
    COMPLIANCE_BASED = "compliance_based"
    SECURITY_INCIDENT = "security_incident"
    MANUAL = "manual"


class RotationStatus(Enum):
    """Key rotation status."""
    SCHEDULED = "scheduled"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    ROLLBACK_REQUIRED = "rollback_required"


@dataclass
class RotationPolicy:
    """Key rotation policy configuration."""
    policy_id: str
    name: str
    description: str
    key_types: List[KeyType]
    triggers: List[RotationTrigger]
    max_age: Optional[timedelta] = None
    max_usage_count: Optional[int] = None
    rotation_schedule: Optional[str] = None  # Cron-like schedule
    grace_period: timedelta = timedelta(hours=24)
    backup_previous_versions: int = 3
    require_approval: bool = False
    notification_enabled: bool = True
    auto_rotate: bool = True
    priority: int = 1  # 1=high, 5=low
    compliance_requirements: List[str] = field(default_factory=list)
    
    def matches_key(self, key_metadata: KeyMetadata) -> bool:
        """Check if policy applies to a specific key."""
        return key_metadata.key_type in self.key_types


@dataclass
class RotationEvent:
    """Key rotation event record."""
    event_id: str
    key_id: str
    policy_id: str
    trigger: RotationTrigger
    status: RotationStatus
    scheduled_time: datetime
    started_time: Optional[datetime] = None
    completed_time: Optional[datetime] = None
    old_key_version: Optional[int] = None
    new_key_version: Optional[int] = None
    error_message: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class RotationMetrics:
    """Key rotation performance metrics."""
    total_rotations: int = 0
    successful_rotations: int = 0
    failed_rotations: int = 0
    average_rotation_time: float = 0.0
    last_rotation_time: Optional[datetime] = None
    keys_pending_rotation: int = 0
    compliance_violations: int = 0


class RotationError(Exception):
    """Base exception for key rotation operations."""
    pass


class PolicyError(RotationError):
    """Raised when rotation policy is invalid."""
    pass


class RotationFailure(RotationError):
    """Raised when key rotation fails."""
    pass


class KeyRotationManager:
    """
    Comprehensive key rotation management system.
    
    Provides automated key rotation with:
    - Policy-based rotation scheduling
    - Multiple rotation triggers
    - Zero-downtime transitions
    - Rollback capabilities
    - Compliance monitoring
    - Performance metrics
    """
    
    def __init__(self, 
                 key_manager: KeyManager,
                 fips_manager: Optional[FIPSComplianceManager] = None):
        """
        Initialize Key Rotation Manager.
        
        Args:
            key_manager: Key management system instance
            fips_manager: FIPS compliance manager instance
        """
        self.key_manager = key_manager
        self.fips_manager = fips_manager
        self.logger = logging.getLogger(__name__)
        
        # Thread safety
        self._lock = threading.RLock()
        
        # Rotation policies
        self._policies: Dict[str, RotationPolicy] = {}
        
        # Rotation events and history
        self._rotation_events: Dict[str, RotationEvent] = {}
        self._rotation_history: List[RotationEvent] = []
        
        # Active rotation tasks
        self._active_rotations: Dict[str, threading.Thread] = {}
        
        # Metrics
        self._metrics = RotationMetrics()
        
        # Callbacks for notifications
        self._notification_callbacks: List[Callable] = []
        
        # Background scheduler
        self._scheduler_running = False
        self._scheduler_thread: Optional[threading.Thread] = None
        
        # Default policies
        self._create_default_policies()
        
        self.logger.info("Key Rotation Manager initialized")
    
    def add_policy(self, policy: RotationPolicy):
        """
        Add a key rotation policy.
        
        Args:
            policy: Rotation policy to add
            
        Raises:
            PolicyError: If policy is invalid
        """
        with self._lock:
            self._validate_policy(policy)
            self._policies[policy.policy_id] = policy
            self.logger.info(f"Added rotation policy: {policy.name}")
    
    def remove_policy(self, policy_id: str):
        """
        Remove a key rotation policy.
        
        Args:
            policy_id: Policy identifier to remove
        """
        with self._lock:
            if policy_id in self._policies:
                del self._policies[policy_id]
                self.logger.info(f"Removed rotation policy: {policy_id}")
    
    def get_policies(self) -> List[RotationPolicy]:
        """Get all rotation policies."""
        with self._lock:
            return list(self._policies.values())
    
    def schedule_rotation(self, 
                         key_id: str, 
                         trigger: RotationTrigger,
                         scheduled_time: Optional[datetime] = None,
                         policy_id: Optional[str] = None) -> str:
        """
        Schedule a key rotation.
        
        Args:
            key_id: Key identifier to rotate
            trigger: Rotation trigger type
            scheduled_time: When to perform rotation (default: now)
            policy_id: Specific policy to use
            
        Returns:
            Rotation event ID
            
        Raises:
            RotationError: If scheduling fails
        """
        with self._lock:
            try:
                # Get key metadata
                key_metadata = self.key_manager.get_key_metadata(key_id)
                
                # Find applicable policy
                if policy_id:
                    if policy_id not in self._policies:
                        raise RotationError(f"Policy not found: {policy_id}")
                    policy = self._policies[policy_id]
                else:
                    policy = self._find_policy_for_key(key_metadata)
                
                if not policy:
                    raise RotationError(f"No applicable rotation policy for key: {key_id}")
                
                # Create rotation event
                event_id = f"rotation_{key_id}_{int(time.time())}"
                scheduled_time = scheduled_time or datetime.utcnow()
                
                rotation_event = RotationEvent(
                    event_id=event_id,
                    key_id=key_id,
                    policy_id=policy.policy_id,
                    trigger=trigger,
                    status=RotationStatus.SCHEDULED,
                    scheduled_time=scheduled_time,
                    old_key_version=key_metadata.version
                )
                
                self._rotation_events[event_id] = rotation_event
                
                # Schedule execution if immediate
                if scheduled_time <= datetime.utcnow():
                    self._execute_rotation(event_id)
                
                self.logger.info(f"Scheduled rotation for key {key_id} at {scheduled_time}")
                return event_id
                
            except Exception as e:
                self.logger.error(f"Failed to schedule rotation for key {key_id}: {e}")
                raise RotationError(f"Rotation scheduling failed: {e}")
    
    def rotate_key_now(self, key_id: str, policy_id: Optional[str] = None) -> str:
        """
        Perform immediate key rotation.
        
        Args:
            key_id: Key identifier to rotate
            policy_id: Specific policy to use
            
        Returns:
            New key ID
            
        Raises:
            RotationFailure: If rotation fails
        """
        event_id = self.schedule_rotation(
            key_id=key_id,
            trigger=RotationTrigger.MANUAL,
            scheduled_time=datetime.utcnow(),
            policy_id=policy_id
        )
        
        # Wait for completion
        event = self._rotation_events[event_id]
        while event.status == RotationStatus.IN_PROGRESS:
            time.sleep(0.1)
        
        if event.status != RotationStatus.COMPLETED:
            raise RotationFailure(f"Rotation failed: {event.error_message}")
        
        # Return new key ID
        new_key_id = f"{key_id}_v{event.new_key_version}"
        return new_key_id
    
    def cancel_rotation(self, event_id: str):
        """
        Cancel a scheduled rotation.
        
        Args:
            event_id: Rotation event ID to cancel
        """
        with self._lock:
            if event_id in self._rotation_events:
                event = self._rotation_events[event_id]
                if event.status == RotationStatus.SCHEDULED:
                    event.status = RotationStatus.CANCELLED
                    self.logger.info(f"Cancelled rotation event: {event_id}")
    
    def start_scheduler(self):
        """Start the background rotation scheduler."""
        if self._scheduler_running:
            return
        
        self._scheduler_running = True
        self._scheduler_thread = threading.Thread(target=self._scheduler_loop, daemon=True)
        self._scheduler_thread.start()
        self.logger.info("Key rotation scheduler started")
    
    def stop_scheduler(self):
        """Stop the background rotation scheduler."""
        self._scheduler_running = False
        if self._scheduler_thread:
            self._scheduler_thread.join(timeout=10)
        self.logger.info("Key rotation scheduler stopped")
    
    def check_keys_needing_rotation(self) -> List[Tuple[str, RotationTrigger, str]]:
        """
        Check which keys need rotation based on policies.
        
        Returns:
            List of (key_id, trigger, policy_id) tuples
        """
        keys_needing_rotation = []
        
        try:
            # Get all keys
            all_keys = self.key_manager.list_keys()
            
            for key_metadata in all_keys:
                # Find applicable policies
                for policy in self._policies.values():
                    if not policy.matches_key(key_metadata):
                        continue
                    
                    # Check time-based rotation
                    if RotationTrigger.TIME_BASED in policy.triggers and policy.max_age:
                        age = datetime.utcnow() - key_metadata.created_at
                        if age >= policy.max_age:
                            keys_needing_rotation.append((
                                key_metadata.key_id,
                                RotationTrigger.TIME_BASED,
                                policy.policy_id
                            ))
                            break
                    
                    # Check schedule-based rotation
                    if (RotationTrigger.TIME_BASED in policy.triggers and 
                        policy.rotation_schedule and
                        key_metadata.last_rotated):
                        if self._should_rotate_by_schedule(key_metadata, policy):
                            keys_needing_rotation.append((
                                key_metadata.key_id,
                                RotationTrigger.TIME_BASED,
                                policy.policy_id
                            ))
                            break
            
            return keys_needing_rotation
            
        except Exception as e:
            self.logger.error(f"Failed to check keys needing rotation: {e}")
            return []
    
    def get_rotation_status(self, event_id: str) -> Optional[RotationEvent]:
        """Get status of a rotation event."""
        return self._rotation_events.get(event_id)
    
    def get_rotation_history(self, key_id: Optional[str] = None) -> List[RotationEvent]:
        """
        Get rotation history.
        
        Args:
            key_id: Optional key ID filter
            
        Returns:
            List of rotation events
        """
        if key_id:
            return [event for event in self._rotation_history if event.key_id == key_id]
        return self._rotation_history.copy()
    
    def get_metrics(self) -> RotationMetrics:
        """Get rotation performance metrics."""
        with self._lock:
            # Update pending rotations count
            self._metrics.keys_pending_rotation = len([
                event for event in self._rotation_events.values()
                if event.status == RotationStatus.SCHEDULED
            ])
            return self._metrics
    
    def add_notification_callback(self, callback: Callable[[RotationEvent], None]):
        """
        Add callback for rotation notifications.
        
        Args:
            callback: Function to call on rotation events
        """
        self._notification_callbacks.append(callback)
    
    def _create_default_policies(self):
        """Create default rotation policies."""
        # High-security keys (daily rotation)
        high_security_policy = RotationPolicy(
            policy_id="high_security",
            name="High Security Keys",
            description="Daily rotation for high-security keys",
            key_types=[KeyType.MASTER_KEY, KeyType.TRANSPORT_KEY],
            triggers=[RotationTrigger.TIME_BASED],
            max_age=timedelta(days=1),
            priority=1,
            auto_rotate=True
        )
        self.add_policy(high_security_policy)
        
        # Data encryption keys (weekly rotation)
        dek_policy = RotationPolicy(
            policy_id="data_encryption",
            name="Data Encryption Keys",
            description="Weekly rotation for data encryption keys",
            key_types=[KeyType.DATA_ENCRYPTION_KEY],
            triggers=[RotationTrigger.TIME_BASED],
            max_age=timedelta(days=7),
            priority=2,
            auto_rotate=True
        )
        self.add_policy(dek_policy)
        
        # Signing keys (monthly rotation)
        signing_policy = RotationPolicy(
            policy_id="signing_keys",
            name="Signing Keys",
            description="Monthly rotation for signing keys",
            key_types=[KeyType.SIGNING_KEY],
            triggers=[RotationTrigger.TIME_BASED],
            max_age=timedelta(days=30),
            priority=3,
            auto_rotate=True
        )
        self.add_policy(signing_policy)
    
    def _validate_policy(self, policy: RotationPolicy):
        """Validate rotation policy."""
        if not policy.policy_id:
            raise PolicyError("Policy ID is required")
        
        if not policy.key_types:
            raise PolicyError("At least one key type must be specified")
        
        if not policy.triggers:
            raise PolicyError("At least one trigger must be specified")
        
        if RotationTrigger.TIME_BASED in policy.triggers:
            if not policy.max_age and not policy.rotation_schedule:
                raise PolicyError("Time-based rotation requires max_age or rotation_schedule")
        
        if RotationTrigger.USAGE_BASED in policy.triggers:
            if not policy.max_usage_count:
                raise PolicyError("Usage-based rotation requires max_usage_count")
    
    def _find_policy_for_key(self, key_metadata: KeyMetadata) -> Optional[RotationPolicy]:
        """Find the best policy for a key."""
        matching_policies = [
            policy for policy in self._policies.values()
            if policy.matches_key(key_metadata)
        ]
        
        if not matching_policies:
            return None
        
        # Return highest priority policy
        return min(matching_policies, key=lambda p: p.priority)
    
    def _execute_rotation(self, event_id: str):
        """Execute key rotation in a separate thread."""
        def rotation_worker():
            try:
                with self._lock:
                    event = self._rotation_events[event_id]
                    event.status = RotationStatus.IN_PROGRESS
                    event.started_time = datetime.utcnow()
                
                self._notify_callbacks(event)
                
                # Perform the actual rotation
                self._perform_key_rotation(event)
                
                with self._lock:
                    event.status = RotationStatus.COMPLETED
                    event.completed_time = datetime.utcnow()
                    self._rotation_history.append(event)
                    
                    # Update metrics
                    self._metrics.total_rotations += 1
                    self._metrics.successful_rotations += 1
                    self._metrics.last_rotation_time = event.completed_time
                    
                    # Calculate average rotation time
                    if event.started_time and event.completed_time:
                        rotation_time = (event.completed_time - event.started_time).total_seconds()
                        if self._metrics.average_rotation_time == 0:
                            self._metrics.average_rotation_time = rotation_time
                        else:
                            self._metrics.average_rotation_time = (
                                self._metrics.average_rotation_time + rotation_time
                            ) / 2
                
                self._notify_callbacks(event)
                self.logger.info(f"Key rotation completed: {event.key_id}")
                
            except Exception as e:
                with self._lock:
                    event = self._rotation_events[event_id]
                    event.status = RotationStatus.FAILED
                    event.error_message = str(e)
                    event.completed_time = datetime.utcnow()
                    self._rotation_history.append(event)
                    
                    # Update metrics
                    self._metrics.total_rotations += 1
                    self._metrics.failed_rotations += 1
                
                self._notify_callbacks(event)
                self.logger.error(f"Key rotation failed: {event.key_id} - {e}")
            
            finally:
                # Clean up active rotation tracking
                with self._lock:
                    self._active_rotations.pop(event_id, None)
        
        # Start rotation in background thread
        thread = threading.Thread(target=rotation_worker, daemon=True)
        self._active_rotations[event_id] = thread
        thread.start()
    
    def _perform_key_rotation(self, event: RotationEvent):
        """Perform the actual key rotation."""
        try:
            # Get the policy
            policy = self._policies[event.policy_id]
            
            # Perform FIPS compliance checks if available
            if self.fips_manager:
                self.fips_manager.validate_operator_access("system", "key_rotation")
            
            # Rotate the key using the key manager
            new_key_id = self.key_manager.rotate_key(event.key_id)
            
            # Extract version from new key ID
            if "_v" in new_key_id:
                event.new_key_version = int(new_key_id.split("_v")[-1])
            else:
                event.new_key_version = event.old_key_version + 1 if event.old_key_version else 2
            
            # Update event metadata
            event.metadata.update({
                "new_key_id": new_key_id,
                "rotation_method": "key_manager_rotate",
                "policy_applied": policy.name
            })
            
        except Exception as e:
            raise RotationFailure(f"Key rotation execution failed: {e}")
    
    def _should_rotate_by_schedule(self, key_metadata: KeyMetadata, policy: RotationPolicy) -> bool:
        """Check if key should be rotated based on schedule."""
        # Simplified schedule checking - in production, use a proper cron parser
        if not policy.rotation_schedule:
            return False
        
        if not key_metadata.last_rotated:
            return True
        
        # For demonstration, assume schedule is in format "every_X_hours"
        if policy.rotation_schedule.startswith("every_"):
            try:
                hours = int(policy.rotation_schedule.split("_")[1])
                time_since_rotation = datetime.utcnow() - key_metadata.last_rotated
                return time_since_rotation >= timedelta(hours=hours)
            except (ValueError, IndexError):
                return False
        
        return False
    
    def _scheduler_loop(self):
        """Background scheduler loop."""
        while self._scheduler_running:
            try:
                # Check for keys needing rotation
                keys_to_rotate = self.check_keys_needing_rotation()
                
                for key_id, trigger, policy_id in keys_to_rotate:
                    # Check if rotation is already scheduled or in progress
                    existing_rotation = any(
                        event.key_id == key_id and event.status in [
                            RotationStatus.SCHEDULED,
                            RotationStatus.IN_PROGRESS
                        ]
                        for event in self._rotation_events.values()
                    )
                    
                    if not existing_rotation:
                        policy = self._policies[policy_id]
                        if policy.auto_rotate:
                            self.schedule_rotation(key_id, trigger, policy_id=policy_id)
                
                # Sleep for a minute before next check
                time.sleep(60)
                
            except Exception as e:
                self.logger.error(f"Scheduler loop error: {e}")
                time.sleep(60)
    
    def _notify_callbacks(self, event: RotationEvent):
        """Notify registered callbacks of rotation events."""
        for callback in self._notification_callbacks:
            try:
                callback(event)
            except Exception as e:
                self.logger.error(f"Notification callback failed: {e}")


def create_rotation_policy(name: str,
                          key_types: List[KeyType],
                          max_age_days: Optional[int] = None,
                          max_usage_count: Optional[int] = None,
                          auto_rotate: bool = True) -> RotationPolicy:
    """
    Create a simple rotation policy.
    
    Args:
        name: Policy name
        key_types: Key types to apply policy to
        max_age_days: Maximum key age in days
        max_usage_count: Maximum usage count
        auto_rotate: Enable automatic rotation
        
    Returns:
        Rotation policy object
    """
    policy_id = name.lower().replace(" ", "_")
    triggers = []
    
    if max_age_days:
        triggers.append(RotationTrigger.TIME_BASED)
    if max_usage_count:
        triggers.append(RotationTrigger.USAGE_BASED)
    
    if not triggers:
        triggers.append(RotationTrigger.MANUAL)
    
    return RotationPolicy(
        policy_id=policy_id,
        name=name,
        description=f"Rotation policy for {', '.join([kt.value for kt in key_types])}",
        key_types=key_types,
        triggers=triggers,
        max_age=timedelta(days=max_age_days) if max_age_days else None,
        max_usage_count=max_usage_count,
        auto_rotate=auto_rotate
    )