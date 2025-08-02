"""
Production-Grade Error Handling and Recovery for Qlik OAuth Flows
Comprehensive error handling, recovery mechanisms, and resilience patterns.
"""

import json
import logging
import time
import traceback
from typing import Dict, List, Optional, Any, Callable, Union
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
import threading
from functools import wraps
import asyncio

# Import components
from .oauth_client import TokenResponse, Platform
from .enhanced_qlik_oauth import EnhancedQlikOAuthClient
from .enhanced_cac_oauth_binding import EnhancedCACOAuthBinder, BindingValidationResult
from .cac_piv_integration import CACCredentials
from .security_managers import AuditLogger, AuditEvent, AuditEventType

logger = logging.getLogger(__name__)


class ErrorSeverity(Enum):
    """Error severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ErrorCategory(Enum):
    """Error categories for classification."""
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    NETWORK = "network"
    TOKEN = "token"
    CAC = "cac"
    CONFIGURATION = "configuration"
    PLATFORM = "platform"
    SECURITY = "security"
    RATE_LIMIT = "rate_limit"
    TEMPORARY = "temporary"


class RecoveryStrategy(Enum):
    """Recovery strategy types."""
    RETRY = "retry"
    FALLBACK = "fallback"
    ESCALATE = "escalate"
    ABORT = "abort"
    MANUAL_INTERVENTION = "manual_intervention"


@dataclass
class ErrorContext:
    """Comprehensive error context information."""
    error_id: str
    timestamp: datetime
    category: ErrorCategory
    severity: ErrorSeverity
    message: str
    details: Dict[str, Any]
    stack_trace: Optional[str] = None
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    platform: Optional[Platform] = None
    recovery_attempts: int = 0
    max_recovery_attempts: int = 3
    recovery_strategy: Optional[RecoveryStrategy] = None
    
    def can_retry(self) -> bool:
        """Check if error can be retried."""
        return (self.recovery_attempts < self.max_recovery_attempts and 
                self.recovery_strategy == RecoveryStrategy.RETRY)


@dataclass
class RecoveryAction:
    """Recovery action definition."""
    name: str
    description: str
    action_func: Callable
    conditions: List[str]
    max_attempts: int = 3
    delay_seconds: float = 1.0
    exponential_backoff: bool = True


class QlikOAuthErrorHandler:
    """Production-grade error handler for Qlik OAuth flows."""
    
    # Error pattern definitions
    ERROR_PATTERNS = {
        # Authentication errors
        "invalid_client": {
            "category": ErrorCategory.AUTHENTICATION,
            "severity": ErrorSeverity.HIGH,
            "recovery": RecoveryStrategy.ABORT,
            "message": "OAuth client credentials are invalid"
        },
        "invalid_grant": {
            "category": ErrorCategory.AUTHENTICATION,
            "severity": ErrorSeverity.MEDIUM,
            "recovery": RecoveryStrategy.RETRY,
            "message": "Authorization grant is invalid or expired"
        },
        "access_denied": {
            "category": ErrorCategory.AUTHORIZATION,
            "severity": ErrorSeverity.MEDIUM,
            "recovery": RecoveryStrategy.ESCALATE,
            "message": "Access denied by authorization server"
        },
        
        # Token errors
        "invalid_token": {
            "category": ErrorCategory.TOKEN,
            "severity": ErrorSeverity.MEDIUM,
            "recovery": RecoveryStrategy.RETRY,
            "message": "Access token is invalid or expired"
        },
        "insufficient_scope": {
            "category": ErrorCategory.AUTHORIZATION,
            "severity": ErrorSeverity.MEDIUM,
            "recovery": RecoveryStrategy.ESCALATE,
            "message": "Insufficient OAuth scope for requested operation"
        },
        
        # Network errors
        "connection_timeout": {
            "category": ErrorCategory.NETWORK,
            "severity": ErrorSeverity.MEDIUM,
            "recovery": RecoveryStrategy.RETRY,
            "message": "Connection timeout to OAuth server"
        },
        "network_unreachable": {
            "category": ErrorCategory.NETWORK,
            "severity": ErrorSeverity.HIGH,
            "recovery": RecoveryStrategy.FALLBACK,
            "message": "Network unreachable"
        },
        
        # Rate limiting
        "rate_limit_exceeded": {
            "category": ErrorCategory.RATE_LIMIT,
            "severity": ErrorSeverity.MEDIUM,
            "recovery": RecoveryStrategy.RETRY,
            "message": "Rate limit exceeded"
        },
        
        # CAC errors
        "cac_validation_failed": {
            "category": ErrorCategory.CAC,
            "severity": ErrorSeverity.HIGH,
            "recovery": RecoveryStrategy.ABORT,
            "message": "CAC certificate validation failed"
        },
        "cac_binding_expired": {
            "category": ErrorCategory.CAC,
            "severity": ErrorSeverity.MEDIUM,
            "recovery": RecoveryStrategy.RETRY,
            "message": "CAC-OAuth binding has expired"
        },
        
        # Platform-specific errors
        "qlik_service_unavailable": {
            "category": ErrorCategory.PLATFORM,
            "severity": ErrorSeverity.HIGH,
            "recovery": RecoveryStrategy.FALLBACK,
            "message": "Qlik platform service is unavailable"
        },
        "qlik_maintenance": {
            "category": ErrorCategory.PLATFORM,
            "severity": ErrorSeverity.MEDIUM,
            "recovery": RecoveryStrategy.RETRY,
            "message": "Qlik platform is under maintenance"
        }
    }
    
    def __init__(self, max_retry_attempts: int = 3, base_retry_delay: float = 1.0):
        """
        Initialize error handler.
        
        Args:
            max_retry_attempts: Maximum retry attempts for recoverable errors
            base_retry_delay: Base delay for retry operations
        """
        self.max_retry_attempts = max_retry_attempts
        self.base_retry_delay = base_retry_delay
        self.error_history: List[ErrorContext] = []
        self.recovery_actions: Dict[str, RecoveryAction] = {}
        self.circuit_breakers: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.RLock()
        
        # Initialize recovery actions
        self._initialize_recovery_actions()
        
        logger.info("Qlik OAuth error handler initialized")
    
    def _initialize_recovery_actions(self):
        """Initialize recovery actions for different error types."""
        self.recovery_actions = {
            "token_refresh": RecoveryAction(
                name="token_refresh",
                description="Attempt to refresh expired OAuth token",
                action_func=self._refresh_token_recovery,
                conditions=["invalid_token", "token_expired"],
                max_attempts=2,
                delay_seconds=0.5
            ),
            "cac_rebind": RecoveryAction(
                name="cac_rebind",
                description="Re-establish CAC-OAuth binding",
                action_func=self._cac_rebind_recovery,
                conditions=["cac_binding_expired", "binding_validation_failed"],
                max_attempts=2,
                delay_seconds=1.0
            ),
            "network_retry": RecoveryAction(
                name="network_retry",
                description="Retry network operation with backoff",
                action_func=self._network_retry_recovery,
                conditions=["connection_timeout", "network_error"],
                max_attempts=3,
                delay_seconds=1.0,
                exponential_backoff=True
            ),
            "fallback_authentication": RecoveryAction(
                name="fallback_authentication",
                description="Use fallback authentication method",
                action_func=self._fallback_auth_recovery,
                conditions=["oauth_server_down", "qlik_service_unavailable"],
                max_attempts=1,
                delay_seconds=0.0
            )
        }
    
    def handle_error(self, error: Exception, context: Dict[str, Any]) -> ErrorContext:
        """
        Handle error with comprehensive analysis and recovery.
        
        Args:
            error: Exception that occurred
            context: Error context information
            
        Returns:
            ErrorContext with analysis and recovery information
        """
        with self._lock:
            try:
                # Classify error
                error_pattern = self._classify_error(error, context)
                
                # Create error context
                error_context = ErrorContext(
                    error_id=self._generate_error_id(),
                    timestamp=datetime.now(timezone.utc),
                    category=error_pattern["category"],
                    severity=error_pattern["severity"],
                    message=error_pattern["message"],
                    details=self._extract_error_details(error, context),
                    stack_trace=traceback.format_exc(),
                    user_id=context.get("user_id"),
                    session_id=context.get("session_id"),
                    platform=context.get("platform"),
                    recovery_strategy=error_pattern["recovery"]
                )
                
                # Store error in history
                self.error_history.append(error_context)
                
                # Log error
                self._log_error(error_context)
                
                # Check circuit breaker
                if self._check_circuit_breaker(error_context):
                    error_context.recovery_strategy = RecoveryStrategy.ABORT
                    return error_context
                
                # Attempt recovery if applicable
                if error_context.recovery_strategy == RecoveryStrategy.RETRY:
                    recovery_result = self._attempt_recovery(error_context, context)
                    error_context.recovery_attempts = recovery_result.get("attempts", 0)
                
                return error_context
                
            except Exception as handler_error:
                logger.error(f"Error handler failure: {handler_error}")
                # Return basic error context for handler failures
                return ErrorContext(
                    error_id=self._generate_error_id(),
                    timestamp=datetime.now(timezone.utc),
                    category=ErrorCategory.PLATFORM,
                    severity=ErrorSeverity.CRITICAL,
                    message=f"Error handler failure: {str(handler_error)}",
                    details={"original_error": str(error)},
                    recovery_strategy=RecoveryStrategy.MANUAL_INTERVENTION
                )
    
    def _classify_error(self, error: Exception, context: Dict[str, Any]) -> Dict[str, Any]:
        """Classify error based on type and context."""
        error_str = str(error).lower()
        error_type = type(error).__name__
        
        # Check for specific error patterns
        for pattern_name, pattern_config in self.ERROR_PATTERNS.items():
            if (pattern_name in error_str or 
                pattern_name.replace("_", " ") in error_str or
                pattern_name in context.get("error_code", "")):
                return pattern_config
        
        # Check by exception type
        if "timeout" in error_type.lower() or "timeout" in error_str:
            return self.ERROR_PATTERNS["connection_timeout"]
        elif "connection" in error_type.lower() or "network" in error_str:
            return self.ERROR_PATTERNS["network_unreachable"]
        elif "token" in error_str or "401" in str(error):
            return self.ERROR_PATTERNS["invalid_token"]
        elif "403" in str(error) or "forbidden" in error_str:
            return self.ERROR_PATTERNS["access_denied"]
        elif "429" in str(error) or "rate limit" in error_str:
            return self.ERROR_PATTERNS["rate_limit_exceeded"]
        elif "503" in str(error) or "service unavailable" in error_str:
            return self.ERROR_PATTERNS["qlik_service_unavailable"]
        
        # Default classification
        return {
            "category": ErrorCategory.PLATFORM,
            "severity": ErrorSeverity.MEDIUM,
            "recovery": RecoveryStrategy.RETRY,
            "message": f"Unclassified error: {str(error)}"
        }
    
    def _extract_error_details(self, error: Exception, context: Dict[str, Any]) -> Dict[str, Any]:
        """Extract detailed error information."""
        details = {
            "error_type": type(error).__name__,
            "error_message": str(error),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        
        # Add context information
        details.update(context)
        
        # Extract HTTP error details if available
        if hasattr(error, 'response'):
            response = error.response
            details.update({
                "http_status": getattr(response, 'status_code', None),
                "http_headers": dict(getattr(response, 'headers', {})),
                "response_body": getattr(response, 'text', '')[:1000]  # Limit size
            })
        
        # Extract OAuth error details
        if hasattr(error, 'error'):
            details["oauth_error"] = error.error
        if hasattr(error, 'error_description'):
            details["oauth_error_description"] = error.error_description
        
        return details
    
    def _check_circuit_breaker(self, error_context: ErrorContext) -> bool:
        """Check if circuit breaker should be triggered."""
        breaker_key = f"{error_context.category.value}_{error_context.user_id or 'global'}"
        
        # Get or create circuit breaker state
        if breaker_key not in self.circuit_breakers:
            self.circuit_breakers[breaker_key] = {
                "failure_count": 0,
                "last_failure": None,
                "state": "closed",  # closed, open, half_open
                "open_until": None
            }
        
        breaker = self.circuit_breakers[breaker_key]
        current_time = datetime.now(timezone.utc)
        
        # Update failure count
        breaker["failure_count"] += 1
        breaker["last_failure"] = current_time
        
        # Check if circuit should open
        failure_threshold = 5
        time_window = timedelta(minutes=5)
        
        if (breaker["failure_count"] >= failure_threshold and 
            breaker["state"] == "closed"):
            breaker["state"] = "open"
            breaker["open_until"] = current_time + timedelta(minutes=2)
            
            logger.warning(f"Circuit breaker opened for {breaker_key}")
            return True
        
        # Check if circuit should close
        if (breaker["state"] == "open" and 
            current_time > breaker.get("open_until", current_time)):
            breaker["state"] = "half_open"
            breaker["failure_count"] = 0
        
        return breaker["state"] == "open"
    
    def _attempt_recovery(self, error_context: ErrorContext, context: Dict[str, Any]) -> Dict[str, Any]:
        """Attempt error recovery based on strategy."""
        recovery_result = {"success": False, "attempts": 0}
        
        # Find applicable recovery actions
        applicable_actions = []
        for action_name, action in self.recovery_actions.items():
            for condition in action.conditions:
                if condition in error_context.message.lower() or condition in str(error_context.details):
                    applicable_actions.append(action)
                    break
        
        # Attempt recovery actions
        for action in applicable_actions:
            if recovery_result["attempts"] >= error_context.max_recovery_attempts:
                break
            
            try:
                recovery_result["attempts"] += 1
                
                # Calculate delay with exponential backoff
                delay = action.delay_seconds
                if action.exponential_backoff:
                    delay *= (2 ** (recovery_result["attempts"] - 1))
                
                if delay > 0:
                    time.sleep(delay)
                
                # Execute recovery action
                action_result = action.action_func(error_context, context)
                
                if action_result.get("success", False):
                    recovery_result["success"] = True
                    recovery_result["action"] = action.name
                    break
                    
            except Exception as recovery_error:
                logger.error(f"Recovery action {action.name} failed: {recovery_error}")
        
        return recovery_result
    
    def _refresh_token_recovery(self, error_context: ErrorContext, context: Dict[str, Any]) -> Dict[str, bool]:
        """Recovery action: Refresh OAuth token."""
        try:
            oauth_client = context.get("oauth_client")
            refresh_token = context.get("refresh_token")
            
            if not oauth_client or not refresh_token:
                return {"success": False, "reason": "missing_components"}
            
            # Attempt token refresh
            new_token = oauth_client.refresh_access_token(refresh_token)
            if new_token:
                context["new_token"] = new_token
                return {"success": True}
            
            return {"success": False, "reason": "refresh_failed"}
            
        except Exception as e:
            logger.error(f"Token refresh recovery failed: {e}")
            return {"success": False, "reason": str(e)}
    
    def _cac_rebind_recovery(self, error_context: ErrorContext, context: Dict[str, Any]) -> Dict[str, bool]:
        """Recovery action: Re-establish CAC-OAuth binding."""
        try:
            binder = context.get("cac_binder")
            cac_credentials = context.get("cac_credentials")
            oauth_token = context.get("oauth_token")
            
            if not all([binder, cac_credentials, oauth_token]):
                return {"success": False, "reason": "missing_components"}
            
            # Create new binding
            new_binding = binder.create_binding(cac_credentials, oauth_token)
            if new_binding:
                context["new_binding"] = new_binding
                return {"success": True}
            
            return {"success": False, "reason": "binding_failed"}
            
        except Exception as e:
            logger.error(f"CAC rebind recovery failed: {e}")
            return {"success": False, "reason": str(e)}
    
    def _network_retry_recovery(self, error_context: ErrorContext, context: Dict[str, Any]) -> Dict[str, bool]:
        """Recovery action: Retry network operation."""
        try:
            retry_func = context.get("retry_function")
            retry_args = context.get("retry_args", [])
            retry_kwargs = context.get("retry_kwargs", {})
            
            if not retry_func:
                return {"success": False, "reason": "no_retry_function"}
            
            # Execute retry function
            result = retry_func(*retry_args, **retry_kwargs)
            context["retry_result"] = result
            
            return {"success": True}
            
        except Exception as e:
            logger.error(f"Network retry recovery failed: {e}")
            return {"success": False, "reason": str(e)}
    
    def _fallback_auth_recovery(self, error_context: ErrorContext, context: Dict[str, Any]) -> Dict[str, bool]:
        """Recovery action: Use fallback authentication."""
        try:
            # In production, this might switch to CAC-only authentication
            # or use cached credentials
            fallback_method = context.get("fallback_auth_method")
            
            if not fallback_method:
                return {"success": False, "reason": "no_fallback_method"}
            
            # Execute fallback authentication
            result = fallback_method()
            context["fallback_result"] = result
            
            return {"success": True}
            
        except Exception as e:
            logger.error(f"Fallback auth recovery failed: {e}")
            return {"success": False, "reason": str(e)}
    
    def _log_error(self, error_context: ErrorContext):
        """Log error with appropriate severity level."""
        log_data = {
            "error_id": error_context.error_id,
            "category": error_context.category.value,
            "severity": error_context.severity.value,
            "message": error_context.message,
            "user_id": error_context.user_id,
            "platform": error_context.platform.value if error_context.platform else None
        }
        
        # Log to application logger
        if error_context.severity == ErrorSeverity.CRITICAL:
            logger.critical(f"Critical OAuth error: {error_context.message}", extra=log_data)
        elif error_context.severity == ErrorSeverity.HIGH:
            logger.error(f"High severity OAuth error: {error_context.message}", extra=log_data)
        elif error_context.severity == ErrorSeverity.MEDIUM:
            logger.warning(f"Medium severity OAuth error: {error_context.message}", extra=log_data)
        else:
            logger.info(f"Low severity OAuth error: {error_context.message}", extra=log_data)
        
        # Log to audit system
        AuditLogger.instance().log_event(AuditEvent(
            event_type=AuditEventType.ERROR_OCCURRED,
            timestamp=error_context.timestamp,
            user_id=error_context.user_id or "system",
            success=False,
            error_message=error_context.message,
            additional_data={
                "error_id": error_context.error_id,
                "category": error_context.category.value,
                "severity": error_context.severity.value,
                "recovery_strategy": error_context.recovery_strategy.value if error_context.recovery_strategy else None,
                "recovery_attempts": error_context.recovery_attempts
            }
        ))
    
    def _generate_error_id(self) -> str:
        """Generate unique error ID."""
        import uuid
        return str(uuid.uuid4())[:8]
    
    def get_error_statistics(self, time_window: timedelta = timedelta(hours=24)) -> Dict[str, Any]:
        """Get error statistics for monitoring."""
        with self._lock:
            cutoff_time = datetime.now(timezone.utc) - time_window
            recent_errors = [e for e in self.error_history if e.timestamp >= cutoff_time]
            
            if not recent_errors:
                return {"total_errors": 0, "error_categories": {}, "error_severity": {}}
            
            # Count by category
            category_counts = {}
            for error in recent_errors:
                category = error.category.value
                category_counts[category] = category_counts.get(category, 0) + 1
            
            # Count by severity
            severity_counts = {}
            for error in recent_errors:
                severity = error.severity.value
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            # Calculate recovery success rate
            recoverable_errors = [e for e in recent_errors if e.recovery_strategy == RecoveryStrategy.RETRY]
            successful_recoveries = [e for e in recoverable_errors if e.recovery_attempts > 0]
            recovery_rate = len(successful_recoveries) / len(recoverable_errors) if recoverable_errors else 0
            
            return {
                "total_errors": len(recent_errors),
                "error_categories": category_counts,
                "error_severity": severity_counts,
                "recovery_success_rate": recovery_rate,
                "circuit_breaker_status": {k: v["state"] for k, v in self.circuit_breakers.items()}
            }


def oauth_error_handler(error_handler: QlikOAuthErrorHandler):
    """Decorator for automatic error handling in OAuth operations."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                # Extract context from function arguments
                context = {
                    "function": func.__name__,
                    "args": str(args)[:200],  # Limit size
                    "kwargs": {k: str(v)[:100] for k, v in kwargs.items()}  # Limit size
                }
                
                # Handle error
                error_context = error_handler.handle_error(e, context)
                
                # Re-raise if no recovery was successful
                if error_context.recovery_strategy == RecoveryStrategy.ABORT:
                    raise
                
                # Return None or default value for failed operations
                return None
        
        return wrapper
    return decorator


class QlikOAuthHealthMonitor:
    """Health monitor for Qlik OAuth system."""
    
    def __init__(self, error_handler: QlikOAuthErrorHandler):
        """Initialize health monitor."""
        self.error_handler = error_handler
        self.last_health_check = datetime.now(timezone.utc)
        self.health_status = "healthy"
        
    def check_system_health(self) -> Dict[str, Any]:
        """Perform comprehensive system health check."""
        try:
            current_time = datetime.now(timezone.utc)
            
            # Get error statistics
            error_stats = self.error_handler.get_error_statistics(timedelta(hours=1))
            
            # Determine health status
            critical_errors = error_stats.get("error_severity", {}).get("critical", 0)
            total_errors = error_stats.get("total_errors", 0)
            recovery_rate = error_stats.get("recovery_success_rate", 1.0)
            
            if critical_errors > 0:
                health_status = "critical"
            elif total_errors > 10 or recovery_rate < 0.5:
                health_status = "degraded"
            elif total_errors > 5:
                health_status = "warning"
            else:
                health_status = "healthy"
            
            self.health_status = health_status
            self.last_health_check = current_time
            
            return {
                "status": health_status,
                "timestamp": current_time.isoformat(),
                "error_statistics": error_stats,
                "system_metrics": {
                    "uptime": str(current_time - self.last_health_check),
                    "circuit_breakers": error_stats.get("circuit_breaker_status", {}),
                    "recovery_rate": recovery_rate
                }
            }
            
        except Exception as e:
            logger.error(f"Health check failed: {e}")
            return {
                "status": "unknown",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "error": str(e)
            }