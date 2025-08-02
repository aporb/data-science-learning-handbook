"""
Cross-Platform Permission Resolver

Advanced permission resolution that combines existing RBAC system with OAuth platform 
permissions, providing unified access control across all DoD platforms with intelligent
caching, conflict resolution, and real-time synchronization.

This resolver provides:
- Integration with existing PermissionResolver and ABAC policy engine
- OAuth scope to permission mapping across platforms
- Cross-platform permission aggregation and conflict resolution
- Real-time permission synchronization and cache invalidation
- Multi-classification support with Bell-LaPadula enforcement
- Emergency access procedures with comprehensive audit trails

Classification: UNCLASSIFIED//FOR OFFICIAL USE ONLY
"""

import asyncio
import logging
import time
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Set, Tuple, Union
from uuid import UUID
from enum import Enum
from dataclasses import dataclass, asdict
from concurrent.futures import ThreadPoolExecutor
from collections import defaultdict

# Import existing RBAC infrastructure
from ...rbac.models.resolver import PermissionResolver, PermissionContext, PermissionResolution
from ...rbac.models.abac import PolicyEngine, ABACContext, PolicyDecision
from ...rbac.models.user import User
from ...rbac.models.permission import Permission

# Import platform adapters
from ..platform_adapters.base_adapter import BasePlatformAdapter

# Import unified components
from .config import UnifiedAccessConfig

logger = logging.getLogger(__name__)


class ResolutionStrategy(Enum):
    """Permission resolution strategies."""
    UNION = "union"  # Union of all permissions (most permissive)
    INTERSECTION = "intersection"  # Intersection only (most restrictive) 
    PLATFORM_PRIORITY = "platform_priority"  # Platform-specific priority
    RBAC_FIRST = "rbac_first"  # RBAC takes precedence
    DENY_OVERRIDE = "deny_override"  # Any deny overrides permits


class ConflictResolution(Enum):
    """Conflict resolution policies."""
    MOST_RESTRICTIVE = "most_restrictive"
    MOST_PERMISSIVE = "most_permissive"
    RBAC_PRECEDENCE = "rbac_precedence"
    PLATFORM_PRECEDENCE = "platform_precedence"
    TEMPORAL_PRECEDENCE = "temporal_precedence"  # Most recent wins


@dataclass
class PlatformPermissionResult:
    """Result of platform-specific permission check."""
    platform: str
    granted: bool
    permissions: List[str]
    oauth_scopes: List[str]
    conditions: Dict[str, Any]
    reason: str
    response_time_ms: float
    cached: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class CrossPlatformResolution:
    """Result of cross-platform permission resolution."""
    granted: bool
    reason: str
    effective_permissions: List[Dict[str, Any]]
    platform_permissions: Dict[str, List[str]]
    oauth_scopes_granted: List[str]
    rbac_resolution: Optional[PermissionResolution]
    abac_decision: Optional[PolicyDecision]
    platform_decisions: Dict[str, PlatformPermissionResult]
    conditions_met: bool
    classification_verified: bool
    emergency_override: bool
    audit_required: bool
    resolution_strategy: ResolutionStrategy
    conflict_resolution: ConflictResolution
    response_time_ms: float
    
    def __post_init__(self):
        if self.effective_permissions is None:
            self.effective_permissions = []
        if self.platform_permissions is None:
            self.platform_permissions = {}
        if self.oauth_scopes_granted is None:
            self.oauth_scopes_granted = []
        if self.platform_decisions is None:
            self.platform_decisions = {}
    
    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        result['resolution_strategy'] = self.resolution_strategy.value
        result['conflict_resolution'] = self.conflict_resolution.value
        
        # Convert complex objects
        if self.rbac_resolution:
            result['rbac_resolution'] = self.rbac_resolution.to_dict()
        if self.abac_decision:
            result['abac_decision'] = self.abac_decision.to_dict()
        
        result['platform_decisions'] = {
            platform: decision.to_dict() 
            for platform, decision in self.platform_decisions.items()
        }
        
        return result


class PermissionCache:
    """High-performance cache for cross-platform permission results."""
    
    def __init__(self, ttl_seconds: int = 300, max_size: int = 10000):
        self.ttl_seconds = ttl_seconds
        self.max_size = max_size
        self._cache: Dict[str, Tuple[Any, datetime]] = {}
        self._access_times: Dict[str, datetime] = {}
        self._platform_keys: Dict[str, Set[str]] = defaultdict(set)
        self._user_keys: Dict[UUID, Set[str]] = defaultdict(set)
    
    def get(self, key: str) -> Optional[Any]:
        """Get cached result."""
        if key not in self._cache:
            return None
        
        result, cached_at = self._cache[key]
        
        # Check TTL
        if datetime.now(timezone.utc) - cached_at > timedelta(seconds=self.ttl_seconds):
            self._remove(key)
            return None
        
        # Update access time
        self._access_times[key] = datetime.now(timezone.utc)
        return result
    
    def put(self, key: str, result: Any, user_id: UUID = None, platform: str = None) -> None:
        """Cache result with metadata."""
        now = datetime.now(timezone.utc)
        
        # Evict LRU if at capacity
        if len(self._cache) >= self.max_size:
            self._evict_lru()
        
        self._cache[key] = (result, now)
        self._access_times[key] = now
        
        # Track by user and platform for targeted invalidation
        if user_id:
            self._user_keys[user_id].add(key)
        if platform:
            self._platform_keys[platform].add(key)
    
    def invalidate_user(self, user_id: UUID) -> None:
        """Invalidate all cached entries for a user."""
        keys_to_remove = self._user_keys.get(user_id, set()).copy()
        for key in keys_to_remove:
            self._remove(key)
        self._user_keys.pop(user_id, None)
    
    def invalidate_platform(self, platform: str) -> None:
        """Invalidate all cached entries for a platform."""
        keys_to_remove = self._platform_keys.get(platform, set()).copy()
        for key in keys_to_remove:
            self._remove(key)
        self._platform_keys.pop(platform, None)
    
    def clear(self) -> None:
        """Clear all cached entries."""
        self._cache.clear()
        self._access_times.clear()
        self._platform_keys.clear()
        self._user_keys.clear()
    
    def _remove(self, key: str) -> None:
        """Remove entry and cleanup metadata."""
        self._cache.pop(key, None)
        self._access_times.pop(key, None)
        
        # Remove from platform and user tracking
        for platform_keys in self._platform_keys.values():
            platform_keys.discard(key)
        for user_keys in self._user_keys.values():
            user_keys.discard(key)
    
    def _evict_lru(self) -> None:
        """Evict least recently used entry."""
        if not self._access_times:
            return
        
        lru_key = min(self._access_times.keys(), key=lambda k: self._access_times[k])
        self._remove(lru_key)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        return {
            'size': len(self._cache),
            'max_size': self.max_size,
            'ttl_seconds': self.ttl_seconds,
            'utilization': len(self._cache) / self.max_size if self.max_size > 0 else 0,
            'platforms_tracked': len(self._platform_keys),
            'users_tracked': len(self._user_keys)
        }


class CrossPlatformPermissionResolver:
    """
    Advanced permission resolver for cross-platform access control.
    
    Integrates:
    - Existing RBAC PermissionResolver with role hierarchy and inheritance
    - ABAC policy engine for fine-grained attribute-based control
    - OAuth platform permission mappers for platform-specific access
    - Multi-classification enforcement with Bell-LaPadula model
    - Real-time permission synchronization across platforms
    - Intelligent caching with targeted invalidation
    - Conflict resolution with configurable strategies
    - Emergency access procedures with audit trails
    
    Performance Features:
    - Sub-50ms resolution with intelligent caching
    - Concurrent platform permission checks
    - Optimized database queries with connection pooling
    - Async/await throughout for maximum concurrency
    - Targeted cache invalidation for real-time updates
    """
    
    def __init__(self, config: UnifiedAccessConfig, rbac_resolver: PermissionResolver,
                 abac_engine: PolicyEngine):
        """
        Initialize cross-platform permission resolver.
        
        Args:
            config: Unified access control configuration
            rbac_resolver: Existing RBAC permission resolver
            abac_engine: ABAC policy engine
        """
        self.config = config
        self.rbac_resolver = rbac_resolver
        self.abac_engine = abac_engine
        
        # High-performance caching
        self.cache = PermissionCache(
            ttl_seconds=config.cache_ttl,
            max_size=config.cache_size
        )
        
        # Platform adapters will be injected
        self.platform_adapters: Dict[str, BasePlatformAdapter] = {}
        
        # Resolution configuration
        self.default_resolution_strategy = ResolutionStrategy.RBAC_FIRST
        self.default_conflict_resolution = ConflictResolution.MOST_RESTRICTIVE
        
        # Performance tracking
        self._resolution_count = 0
        self._cache_hits = 0
        self._cache_misses = 0
        self._platform_check_times = defaultdict(list)
        
        # Thread pool for concurrent operations
        self.executor = ThreadPoolExecutor(
            max_workers=config.max_worker_threads,
            thread_name_prefix="CrossPlatformResolver"
        )
        
        logger.info("Cross-Platform Permission Resolver initialized")
    
    def register_platform_adapter(self, platform: str, adapter: BasePlatformAdapter):
        """Register platform adapter for cross-platform resolution."""
        self.platform_adapters[platform] = adapter
        logger.info(f"Registered platform adapter: {platform}")
    
    async def resolve_cross_platform_access(self, request, user_context) -> CrossPlatformResolution:
        """
        Resolve access across platforms with comprehensive conflict resolution.
        
        Args:
            request: UnifiedAccessRequest with access details
            user_context: UnifiedUserContext with user profile
            
        Returns:
            CrossPlatformResolution with unified decision
        """
        start_time = time.time()
        self._resolution_count += 1
        
        try:
            # Check cache first
            cache_key = self._generate_cache_key(request, user_context)
            cached_result = self.cache.get(cache_key)
            
            if cached_result and not request.emergency_access:
                self._cache_hits += 1
                cached_result.response_time_ms = (time.time() - start_time) * 1000
                return cached_result
            
            self._cache_misses += 1
            
            # Determine resolution strategy
            strategy = self._determine_resolution_strategy(request)
            conflict_resolution = self._determine_conflict_resolution(request)
            
            # Perform concurrent resolution
            resolution_tasks = []
            
            # 1. RBAC resolution
            rbac_task = asyncio.create_task(
                self._resolve_rbac_permission(request, user_context)
            )
            resolution_tasks.append(('rbac', rbac_task))
            
            # 2. ABAC policy evaluation
            abac_task = asyncio.create_task(
                self._evaluate_abac_policies(request, user_context)
            )
            resolution_tasks.append(('abac', abac_task))
            
            # 3. Platform-specific checks
            platform_tasks = {}
            if request.platform:
                platforms_to_check = [request.platform]
            else:
                # Check all platforms where user has context
                platforms_to_check = list(user_context.platform_contexts.keys())
            
            for platform in platforms_to_check:
                if platform in self.platform_adapters:
                    platform_task = asyncio.create_task(
                        self._resolve_platform_permission(platform, request, user_context)
                    )
                    platform_tasks[platform] = platform_task
            
            # Wait for all resolutions to complete
            rbac_resolution = await rbac_task
            abac_decision = await abac_task
            
            platform_decisions = {}
            for platform, task in platform_tasks.items():
                try:
                    platform_decisions[platform] = await task
                except Exception as e:
                    logger.error(f"Platform {platform} resolution failed: {e}")
                    platform_decisions[platform] = PlatformPermissionResult(
                        platform=platform,
                        granted=False,
                        permissions=[],
                        oauth_scopes=[],
                        conditions={},
                        reason=f"Platform check failed: {str(e)}",
                        response_time_ms=0.0
                    )
            
            # Apply resolution strategy and conflict resolution
            final_resolution = self._apply_resolution_strategy(
                strategy=strategy,
                conflict_resolution=conflict_resolution,
                rbac_resolution=rbac_resolution,
                abac_decision=abac_decision,
                platform_decisions=platform_decisions,
                request=request,
                user_context=user_context
            )
            
            # Set metadata
            final_resolution.resolution_strategy = strategy
            final_resolution.conflict_resolution = conflict_resolution
            final_resolution.response_time_ms = (time.time() - start_time) * 1000
            
            # Cache the result
            if not request.emergency_access:
                self.cache.put(
                    cache_key, 
                    final_resolution, 
                    user_id=request.user_id,
                    platform=request.platform
                )
            
            logger.debug(
                f"Cross-platform resolution completed in {final_resolution.response_time_ms:.2f}ms "
                f"- Decision: {final_resolution.granted}"
            )
            
            return final_resolution
            
        except Exception as e:
            logger.error(f"Cross-platform resolution failed: {e}", exc_info=True)
            
            # Return denial on error
            return CrossPlatformResolution(
                granted=False,
                reason=f"Cross-platform resolution failed: {str(e)}",
                effective_permissions=[],
                platform_permissions={},
                oauth_scopes_granted=[],
                rbac_resolution=None,
                abac_decision=None,
                platform_decisions={},
                conditions_met=False,
                classification_verified=False,
                emergency_override=False,
                audit_required=True,
                resolution_strategy=strategy if 'strategy' in locals() else self.default_resolution_strategy,
                conflict_resolution=conflict_resolution if 'conflict_resolution' in locals() else self.default_conflict_resolution,
                response_time_ms=(time.time() - start_time) * 1000
            )
    
    async def _resolve_rbac_permission(self, request, user_context) -> PermissionResolution:
        """Resolve permission using existing RBAC system."""
        try:
            permission_context = PermissionContext(
                user_id=request.user_id,
                resource_type=request.resource_type,
                action=request.action,
                resource_id=request.resource_id,
                classification_level=request.classification_level,
                ip_address=request.ip_address,
                session_id=request.session_id,
                emergency_access=request.emergency_access,
                additional_attributes=request.additional_attributes
            )
            
            # Run in thread pool to avoid blocking
            resolution = await asyncio.get_event_loop().run_in_executor(
                self.executor,
                self.rbac_resolver.check_access,
                permission_context
            )
            
            return resolution
            
        except Exception as e:
            logger.error(f"RBAC resolution error: {e}")
            return PermissionResolution(
                granted=False,
                reason=f"RBAC resolution failed: {str(e)}",
                audit_required=True
            )
    
    async def _evaluate_abac_policies(self, request, user_context) -> PolicyDecision:
        """Evaluate ABAC policies for the request."""
        try:
            # Create ABAC context
            abac_context = ABACContext(
                subject={
                    'user_id': str(request.user_id),
                    'roles': [role.role_name for role in user_context.roles],
                    'security_clearance': user_context.security_clearance,
                    'department': user_context.department,
                    'organization': user_context.organization
                },
                resource={
                    'resource_type': request.resource_type,
                    'resource_id': request.resource_id,
                    'classification_level': request.classification_level,
                    'platform': request.platform
                },
                action={
                    'action_type': request.action,
                    'oauth_scopes': request.oauth_scopes or []
                },
                environment={
                    'ip_address': request.ip_address,
                    'session_id': request.session_id,
                    'emergency_access': request.emergency_access,
                    'timestamp': datetime.now(timezone.utc).isoformat()
                }
            )
            
            # Run in thread pool
            decision = await asyncio.get_event_loop().run_in_executor(
                self.executor,
                self.abac_engine.evaluate,
                abac_context
            )
            
            return decision
            
        except Exception as e:
            logger.error(f"ABAC evaluation error: {e}")
            from ...rbac.models.abac import PolicyDecision, DecisionResult
            return PolicyDecision(
                decision=DecisionResult.DENY,
                evaluation_metadata={'error': str(e)}
            )
    
    async def _resolve_platform_permission(self, platform: str, request, 
                                         user_context) -> PlatformPermissionResult:
        """Resolve permission for a specific platform."""
        start_time = time.time()
        
        try:
            adapter = self.platform_adapters.get(platform)
            if not adapter:
                return PlatformPermissionResult(
                    platform=platform,
                    granted=False,
                    permissions=[],
                    oauth_scopes=[],
                    conditions={},
                    reason=f"No adapter found for platform {platform}",
                    response_time_ms=(time.time() - start_time) * 1000
                )
            
            # Get platform context
            platform_context = user_context.get_platform_context(platform)
            if not platform_context:
                return PlatformPermissionResult(
                    platform=platform,
                    granted=False,
                    permissions=[],
                    oauth_scopes=[],
                    conditions={},
                    reason=f"No platform context for {platform}",
                    response_time_ms=(time.time() - start_time) * 1000
                )
            
            # Check platform permission
            granted = await adapter.check_platform_permission(
                user_context.user_id,
                request.resource_type,
                request.action,
                request.resource_id
            )
            
            # Get platform permissions and scopes
            permissions = await adapter.get_user_permissions(user_context.user_id)
            available_scopes = await adapter.get_available_scopes(user_context.user_id)
            
            # Check OAuth scope requirements
            required_scope = await adapter.get_required_scope(
                request.resource_type,
                request.action
            )
            
            oauth_granted = True
            if required_scope and request.oauth_scopes:
                oauth_granted = required_scope in request.oauth_scopes
            elif required_scope:
                oauth_granted = required_scope in available_scopes
            
            final_granted = granted and oauth_granted
            
            # Build reason
            if not granted:
                reason = f"Platform permission denied for {platform}"
            elif not oauth_granted:
                reason = f"OAuth scope requirement not met: {required_scope}"
            else:
                reason = f"Platform access granted for {platform}"
            
            response_time = (time.time() - start_time) * 1000
            self._platform_check_times[platform].append(response_time)
            
            return PlatformPermissionResult(
                platform=platform,
                granted=final_granted,
                permissions=permissions,
                oauth_scopes=request.oauth_scopes or [],
                conditions=platform_context.conditions if hasattr(platform_context, 'conditions') else {},
                reason=reason,
                response_time_ms=response_time
            )
            
        except Exception as e:
            logger.error(f"Platform {platform} permission resolution error: {e}")
            return PlatformPermissionResult(
                platform=platform,
                granted=False,
                permissions=[],
                oauth_scopes=[],
                conditions={},
                reason=f"Platform check failed: {str(e)}",
                response_time_ms=(time.time() - start_time) * 1000
            )
    
    def _determine_resolution_strategy(self, request) -> ResolutionStrategy:
        """Determine resolution strategy based on request context."""
        if request.emergency_access:
            return ResolutionStrategy.UNION  # Most permissive for emergency
        elif request.platform and request.oauth_scopes:
            return ResolutionStrategy.PLATFORM_PRIORITY
        elif request.classification_level:
            return ResolutionStrategy.INTERSECTION  # Most restrictive for classified
        else:
            return self.default_resolution_strategy
    
    def _determine_conflict_resolution(self, request) -> ConflictResolution:
        """Determine conflict resolution policy based on request context."""
        if request.emergency_access:
            return ConflictResolution.MOST_PERMISSIVE
        elif request.classification_level:
            return ConflictResolution.MOST_RESTRICTIVE
        else:
            return self.default_conflict_resolution
    
    def _apply_resolution_strategy(self, strategy: ResolutionStrategy,
                                 conflict_resolution: ConflictResolution,
                                 rbac_resolution: PermissionResolution,
                                 abac_decision,
                                 platform_decisions: Dict[str, PlatformPermissionResult],
                                 request, user_context) -> CrossPlatformResolution:
        """Apply resolution strategy to combine decisions."""
        
        # Collect all decisions
        all_decisions = {
            'rbac': rbac_resolution.granted,
            'abac': abac_decision.is_permit() if abac_decision else True
        }
        
        for platform, decision in platform_decisions.items():
            all_decisions[f'platform_{platform}'] = decision.granted
        
        # Apply strategy
        if strategy == ResolutionStrategy.UNION:
            # Grant if ANY system grants access
            final_granted = any(all_decisions.values())
            reason = f"Union strategy - granted by: {[k for k, v in all_decisions.items() if v]}"
            
        elif strategy == ResolutionStrategy.INTERSECTION:
            # Grant only if ALL systems grant access
            final_granted = all(all_decisions.values())
            reason = f"Intersection strategy - all systems must grant: {all_decisions}"
            
        elif strategy == ResolutionStrategy.RBAC_FIRST:
            # RBAC takes precedence, platforms can only restrict further
            final_granted = rbac_resolution.granted
            if final_granted and platform_decisions:
                # Check if any platform denies
                platform_granted = all(d.granted for d in platform_decisions.values())
                final_granted = final_granted and platform_granted
            reason = f"RBAC-first strategy - RBAC: {rbac_resolution.granted}, Platforms: {platform_granted if 'platform_granted' in locals() else 'N/A'}"
            
        elif strategy == ResolutionStrategy.PLATFORM_PRIORITY:
            # Platform takes precedence for platform-specific requests
            if platform_decisions:
                platform_granted = any(d.granted for d in platform_decisions.values())
                # Still require RBAC permission as base
                final_granted = rbac_resolution.granted and platform_granted
                reason = f"Platform priority - RBAC: {rbac_resolution.granted}, Platform: {platform_granted}"
            else:
                final_granted = rbac_resolution.granted
                reason = f"Platform priority (no platforms) - RBAC: {rbac_resolution.granted}"
                
        elif strategy == ResolutionStrategy.DENY_OVERRIDE:
            # Any explicit deny overrides permits
            explicit_denies = []
            if not rbac_resolution.granted and rbac_resolution.reason != "No permission defined":
                explicit_denies.append('rbac')
            
            for platform, decision in platform_decisions.items():
                if not decision.granted and "not found" not in decision.reason.lower():
                    explicit_denies.append(f'platform_{platform}')
            
            if explicit_denies:
                final_granted = False
                reason = f"Deny override - explicit denies from: {explicit_denies}"
            else:
                final_granted = any(all_decisions.values())
                reason = f"Deny override - no explicit denies, granted by: {[k for k, v in all_decisions.items() if v]}"
        
        else:
            # Default to RBAC_FIRST
            final_granted = rbac_resolution.granted
            reason = f"Default strategy - RBAC: {rbac_resolution.granted}"
        
        # Handle emergency access
        emergency_override = False
        if request.emergency_access and not final_granted:
            emergency_override = True
            final_granted = True
            reason = f"Emergency override applied - {reason}"
        
        # Aggregate permissions and scopes
        effective_permissions = rbac_resolution.effective_permissions or []
        platform_permissions = {}
        oauth_scopes_granted = []
        
        for platform, decision in platform_decisions.items():
            if decision.granted:
                platform_permissions[platform] = decision.permissions
                oauth_scopes_granted.extend(decision.oauth_scopes)
        
        # Remove duplicates from OAuth scopes
        oauth_scopes_granted = list(set(oauth_scopes_granted))
        
        # Check conditions and classification
        conditions_met = rbac_resolution.conditions_met if hasattr(rbac_resolution, 'conditions_met') else True
        classification_verified = rbac_resolution.clearance_verified if hasattr(rbac_resolution, 'clearance_verified') else False
        
        # Determine audit requirement
        audit_required = (
            rbac_resolution.audit_required or
            any(d.platform == 'classified' for d in platform_decisions.values()) or
            emergency_override or
            request.classification_level is not None
        )
        
        return CrossPlatformResolution(
            granted=final_granted,
            reason=reason,
            effective_permissions=effective_permissions,
            platform_permissions=platform_permissions,
            oauth_scopes_granted=oauth_scopes_granted,
            rbac_resolution=rbac_resolution,
            abac_decision=abac_decision,
            platform_decisions=platform_decisions,
            conditions_met=conditions_met,
            classification_verified=classification_verified,
            emergency_override=emergency_override,
            audit_required=audit_required,
            resolution_strategy=strategy,
            conflict_resolution=conflict_resolution,
            response_time_ms=0.0  # Will be set by caller
        )
    
    def _generate_cache_key(self, request, user_context) -> str:
        """Generate cache key for cross-platform resolution."""
        import hashlib
        import json
        
        cache_data = {
            'user_id': str(request.user_id),
            'resource_type': request.resource_type,
            'action': request.action,
            'platform': request.platform,
            'classification_level': request.classification_level,
            'oauth_scopes': sorted(request.oauth_scopes or []),
            'user_roles': sorted([role.role_name for role in user_context.roles]),
            'platforms': sorted(user_context.platform_contexts.keys()),
            'emergency': request.emergency_access
        }
        
        cache_string = json.dumps(cache_data, sort_keys=True)
        return f"cross_platform_{hashlib.sha256(cache_string.encode()).hexdigest()}"
    
    async def invalidate_user_cache(self, user_id: UUID) -> None:
        """Invalidate cached resolutions for a user."""
        try:
            self.cache.invalidate_user(user_id)
            logger.info(f"Invalidated cross-platform cache for user {user_id}")
        except Exception as e:
            logger.error(f"Failed to invalidate user cache: {e}")
    
    async def invalidate_platform_cache(self, platform: str) -> None:
        """Invalidate cached resolutions for a platform."""
        try:
            self.cache.invalidate_platform(platform)
            logger.info(f"Invalidated cross-platform cache for platform {platform}")
        except Exception as e:
            logger.error(f"Failed to invalidate platform cache: {e}")
    
    def get_performance_metrics(self) -> Dict[str, Any]:
        """Get comprehensive performance metrics."""
        cache_hit_rate = (
            self._cache_hits / (self._cache_hits + self._cache_misses)
            if (self._cache_hits + self._cache_misses) > 0 else 0
        )
        
        # Platform performance statistics
        platform_stats = {}
        for platform, times in self._platform_check_times.items():
            if times:
                platform_stats[platform] = {
                    'avg_response_time_ms': sum(times) / len(times),
                    'min_response_time_ms': min(times),
                    'max_response_time_ms': max(times),
                    'check_count': len(times)
                }
        
        return {
            'cross_platform_resolver': {
                'total_resolutions': self._resolution_count,
                'cache_hits': self._cache_hits,
                'cache_misses': self._cache_misses,
                'cache_hit_rate': cache_hit_rate,
                'cache_stats': self.cache.get_stats(),
                'platform_performance': platform_stats
            }
        }
    
    def get_resolution_strategies(self) -> Dict[str, str]:
        """Get available resolution strategies."""
        return {strategy.value: strategy.name for strategy in ResolutionStrategy}
    
    def get_conflict_resolutions(self) -> Dict[str, str]:
        """Get available conflict resolution policies."""
        return {resolution.value: resolution.name for resolution in ConflictResolution}
    
    async def test_platform_connectivity(self) -> Dict[str, Any]:
        """Test connectivity to all registered platforms."""
        results = {}
        
        for platform, adapter in self.platform_adapters.items():
            try:
                start_time = time.time()
                
                if hasattr(adapter, 'health_check'):
                    health = await adapter.health_check()
                else:
                    # Basic connectivity test
                    health = {'status': 'unknown', 'note': 'No health check method'}
                
                response_time = (time.time() - start_time) * 1000
                
                results[platform] = {
                    'status': health.get('status', 'unknown'),
                    'response_time_ms': response_time,
                    'details': health
                }
                
            except Exception as e:
                results[platform] = {
                    'status': 'error',
                    'error': str(e),
                    'response_time_ms': 0.0
                }
        
        return results