#!/usr/bin/env python3
"""
PKCS#11 Error Handling and Recovery Framework

Provides comprehensive error handling, classification, and recovery mechanisms
for PKCS#11 smart card operations. This module includes error code mapping,
severity classification, context preservation, and automated recovery strategies.

Author: AI Agent - PKCS#11 Infrastructure Implementation
Date: 2025-07-27
Classification: UNCLASSIFIED
"""

import logging
import time
import threading
from typing import Optional, Dict, List, Any, Callable, Union, Tuple
from dataclasses import dataclass, field
from enum import Enum, IntEnum, auto
from datetime import datetime, timedelta
import traceback
import json
from pathlib import Path

from .pkcs11_wrapper import PKCS11ErrorCode


class ErrorSeverity(Enum):
    """Error severity levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ErrorCategory(Enum):
    """Error categories for classification"""
    HARDWARE = "hardware"
    SOFTWARE = "software"
    NETWORK = "network"
    AUTHENTICATION = "authentication"
    PERMISSION = "permission"
    DATA = "data"
    CONFIGURATION = "configuration"
    UNKNOWN = "unknown"


class RecoveryAction(Enum):
    """Possible recovery actions"""
    NONE = "none"
    RETRY = "retry"
    RECONNECT = "reconnect"
    REINITIALIZE = "reinitialize"
    RELOAD_LIBRARY = "reload_library"
    USER_INTERVENTION = "user_intervention"
    SYSTEM_RESTART = "system_restart"


@dataclass
class ErrorContext:
    """Context information for error analysis"""
    operation: str
    slot_id: Optional[int] = None
    session_handle: Optional[int] = None
    object_handle: Optional[int] = None
    parameters: Dict[str, Any] = field(default_factory=dict)
    system_state: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.now)
    thread_id: int = field(default_factory=lambda: threading.current_thread().ident)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            'operation': self.operation,
            'slot_id': self.slot_id,
            'session_handle': self.session_handle,
            'object_handle': self.object_handle,
            'parameters': self.parameters,
            'system_state': self.system_state,
            'timestamp': self.timestamp.isoformat(),
            'thread_id': self.thread_id
        }


@dataclass
class ErrorCode:
    """Detailed error code information"""
    code: int
    name: str
    description: str
    severity: ErrorSeverity
    category: ErrorCategory
    recovery_action: RecoveryAction
    user_message: str
    technical_details: str = ""
    
    def __str__(self) -> str:
        return f"{self.name} (0x{self.code:08X}): {self.description}"


@dataclass
class ErrorInstance:
    """Instance of a specific error occurrence"""
    error_code: ErrorCode
    context: ErrorContext
    timestamp: datetime = field(default_factory=datetime.now)
    stack_trace: Optional[str] = None
    recovery_attempted: bool = False
    recovery_successful: bool = False
    occurrence_count: int = 1
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for logging/analysis"""
        return {
            'error_code': {
                'code': self.error_code.code,
                'name': self.error_code.name,
                'description': self.error_code.description,
                'severity': self.error_code.severity.value,
                'category': self.error_code.category.value,
                'recovery_action': self.error_code.recovery_action.value
            },
            'context': self.context.to_dict(),
            'timestamp': self.timestamp.isoformat(),
            'stack_trace': self.stack_trace,
            'recovery_attempted': self.recovery_attempted,
            'recovery_successful': self.recovery_successful,
            'occurrence_count': self.occurrence_count
        }


class PKCS11ErrorHandler:
    """
    Comprehensive PKCS#11 error handler with classification and recovery
    
    This class provides:
    - Error code mapping and classification
    - Context preservation and analysis
    - Automated recovery strategies
    - Error pattern detection
    - Comprehensive logging and reporting
    """
    
    def __init__(self, log_file: Optional[str] = None):
        """
        Initialize error handler
        
        Args:
            log_file: Optional log file for error persistence
        """
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        self._log_file = log_file
        
        # Thread safety
        self._lock = threading.RLock()
        
        # Error tracking
        self._error_history: List[ErrorInstance] = []
        self._error_patterns: Dict[str, int] = {}
        self._recovery_handlers: Dict[RecoveryAction, Callable] = {}
        
        # Statistics
        self._stats = {
            'total_errors': 0,
            'errors_by_severity': {s.value: 0 for s in ErrorSeverity},
            'errors_by_category': {c.value: 0 for c in ErrorCategory},
            'recovery_attempts': 0,
            'successful_recoveries': 0,
            'last_error_time': None
        }
        
        # Initialize error code mappings
        self._error_codes = self._initialize_error_codes()
        
        # Setup file logging if specified
        if self._log_file:
            self._setup_file_logging()
        
        self.logger.info("PKCS#11 error handler initialized")
    
    def _initialize_error_codes(self) -> Dict[int, ErrorCode]:
        """Initialize comprehensive error code mappings"""
        error_codes = {}
        
        # Success codes
        error_codes[PKCS11ErrorCode.CKR_OK] = ErrorCode(
            code=PKCS11ErrorCode.CKR_OK,
            name="CKR_OK",
            description="Operation completed successfully",
            severity=ErrorSeverity.LOW,
            category=ErrorCategory.SOFTWARE,
            recovery_action=RecoveryAction.NONE,
            user_message="Operation completed successfully"
        )
        
        # General errors
        error_codes[PKCS11ErrorCode.CKR_GENERAL_ERROR] = ErrorCode(
            code=PKCS11ErrorCode.CKR_GENERAL_ERROR,
            name="CKR_GENERAL_ERROR",
            description="General unspecified error",
            severity=ErrorSeverity.HIGH,
            category=ErrorCategory.UNKNOWN,
            recovery_action=RecoveryAction.RETRY,
            user_message="An unexpected error occurred. Please try again.",
            technical_details="General PKCS#11 error without specific cause"
        )
        
        error_codes[PKCS11ErrorCode.CKR_FUNCTION_FAILED] = ErrorCode(
            code=PKCS11ErrorCode.CKR_FUNCTION_FAILED,
            name="CKR_FUNCTION_FAILED",
            description="PKCS#11 function failed",
            severity=ErrorSeverity.HIGH,
            category=ErrorCategory.SOFTWARE,
            recovery_action=RecoveryAction.RETRY,
            user_message="Operation failed. Please try again.",
            technical_details="PKCS#11 function returned failure status"
        )
        
        # Hardware errors
        error_codes[PKCS11ErrorCode.CKR_DEVICE_ERROR] = ErrorCode(
            code=PKCS11ErrorCode.CKR_DEVICE_ERROR,
            name="CKR_DEVICE_ERROR",
            description="Device error occurred",
            severity=ErrorSeverity.CRITICAL,
            category=ErrorCategory.HARDWARE,
            recovery_action=RecoveryAction.RECONNECT,
            user_message="Smart card reader error. Please check connections.",
            technical_details="Hardware device reported an error condition"
        )
        
        error_codes[PKCS11ErrorCode.CKR_DEVICE_REMOVED] = ErrorCode(
            code=PKCS11ErrorCode.CKR_DEVICE_REMOVED,
            name="CKR_DEVICE_REMOVED",
            description="Device was removed",
            severity=ErrorSeverity.HIGH,
            category=ErrorCategory.HARDWARE,
            recovery_action=RecoveryAction.RECONNECT,
            user_message="Smart card or reader was disconnected. Please reconnect and try again.",
            technical_details="Hardware device is no longer present"
        )
        
        # Token errors
        error_codes[PKCS11ErrorCode.CKR_TOKEN_NOT_PRESENT] = ErrorCode(
            code=PKCS11ErrorCode.CKR_TOKEN_NOT_PRESENT,
            name="CKR_TOKEN_NOT_PRESENT",
            description="Token not present in slot",
            severity=ErrorSeverity.MEDIUM,
            category=ErrorCategory.HARDWARE,
            recovery_action=RecoveryAction.USER_INTERVENTION,
            user_message="Please insert a smart card and try again.",
            technical_details="No token detected in the specified slot"
        )
        
        error_codes[PKCS11ErrorCode.CKR_TOKEN_NOT_RECOGNIZED] = ErrorCode(
            code=PKCS11ErrorCode.CKR_TOKEN_NOT_RECOGNIZED,
            name="CKR_TOKEN_NOT_RECOGNIZED",
            description="Token not recognized",
            severity=ErrorSeverity.MEDIUM,
            category=ErrorCategory.HARDWARE,
            recovery_action=RecoveryAction.USER_INTERVENTION,
            user_message="Smart card is not recognized. Please use a valid CAC/PIV card.",
            technical_details="Token present but not recognized by middleware"
        )
        
        # Authentication errors
        error_codes[PKCS11ErrorCode.CKR_PIN_INCORRECT] = ErrorCode(
            code=PKCS11ErrorCode.CKR_PIN_INCORRECT,
            name="CKR_PIN_INCORRECT",
            description="Incorrect PIN provided",
            severity=ErrorSeverity.MEDIUM,
            category=ErrorCategory.AUTHENTICATION,
            recovery_action=RecoveryAction.USER_INTERVENTION,
            user_message="Incorrect PIN. Please try again.",
            technical_details="PIN verification failed"
        )
        
        error_codes[PKCS11ErrorCode.CKR_PIN_LOCKED] = ErrorCode(
            code=PKCS11ErrorCode.CKR_PIN_LOCKED,
            name="CKR_PIN_LOCKED",
            description="PIN is locked due to too many incorrect attempts",
            severity=ErrorSeverity.HIGH,
            category=ErrorCategory.AUTHENTICATION,
            recovery_action=RecoveryAction.USER_INTERVENTION,
            user_message="PIN is locked. Please contact your administrator to unlock.",
            technical_details="PIN retry counter exhausted"
        )
        
        error_codes[PKCS11ErrorCode.CKR_USER_NOT_LOGGED_IN] = ErrorCode(
            code=PKCS11ErrorCode.CKR_USER_NOT_LOGGED_IN,
            name="CKR_USER_NOT_LOGGED_IN",
            description="User not logged in",
            severity=ErrorSeverity.MEDIUM,
            category=ErrorCategory.AUTHENTICATION,
            recovery_action=RecoveryAction.USER_INTERVENTION,
            user_message="Please login with your PIN first.",
            technical_details="Operation requires user authentication"
        )
        
        # Session errors
        error_codes[PKCS11ErrorCode.CKR_SESSION_HANDLE_INVALID] = ErrorCode(
            code=PKCS11ErrorCode.CKR_SESSION_HANDLE_INVALID,
            name="CKR_SESSION_HANDLE_INVALID",
            description="Invalid session handle",
            severity=ErrorSeverity.MEDIUM,
            category=ErrorCategory.SOFTWARE,
            recovery_action=RecoveryAction.RECONNECT,
            user_message="Session expired. Reconnecting...",
            technical_details="Session handle is no longer valid"
        )
        
        error_codes[PKCS11ErrorCode.CKR_SESSION_CLOSED] = ErrorCode(
            code=PKCS11ErrorCode.CKR_SESSION_CLOSED,
            name="CKR_SESSION_CLOSED",
            description="Session is closed",
            severity=ErrorSeverity.MEDIUM,
            category=ErrorCategory.SOFTWARE,
            recovery_action=RecoveryAction.RECONNECT,
            user_message="Connection lost. Reconnecting...",
            technical_details="Session was closed unexpectedly"
        )
        
        # Slot errors
        error_codes[PKCS11ErrorCode.CKR_SLOT_ID_INVALID] = ErrorCode(
            code=PKCS11ErrorCode.CKR_SLOT_ID_INVALID,
            name="CKR_SLOT_ID_INVALID",
            description="Invalid slot ID",
            severity=ErrorSeverity.MEDIUM,
            category=ErrorCategory.CONFIGURATION,
            recovery_action=RecoveryAction.REINITIALIZE,
            user_message="Reader configuration error. Refreshing...",
            technical_details="Specified slot ID is not valid"
        )
        
        # Memory errors
        error_codes[PKCS11ErrorCode.CKR_HOST_MEMORY] = ErrorCode(
            code=PKCS11ErrorCode.CKR_HOST_MEMORY,
            name="CKR_HOST_MEMORY",
            description="Host memory allocation failed",
            severity=ErrorSeverity.CRITICAL,
            category=ErrorCategory.SYSTEM,
            recovery_action=RecoveryAction.SYSTEM_RESTART,
            user_message="Insufficient memory. Please close other applications and try again.",
            technical_details="Host system memory allocation failed"
        )
        
        # Library errors
        error_codes[PKCS11ErrorCode.CKR_CRYPTOKI_NOT_INITIALIZED] = ErrorCode(
            code=PKCS11ErrorCode.CKR_CRYPTOKI_NOT_INITIALIZED,
            name="CKR_CRYPTOKI_NOT_INITIALIZED",
            description="PKCS#11 library not initialized",
            severity=ErrorSeverity.HIGH,
            category=ErrorCategory.SOFTWARE,
            recovery_action=RecoveryAction.REINITIALIZE,
            user_message="Smart card system not ready. Initializing...",
            technical_details="PKCS#11 library requires initialization"
        )
        
        error_codes[PKCS11ErrorCode.CKR_CRYPTOKI_ALREADY_INITIALIZED] = ErrorCode(
            code=PKCS11ErrorCode.CKR_CRYPTOKI_ALREADY_INITIALIZED,
            name="CKR_CRYPTOKI_ALREADY_INITIALIZED",
            description="PKCS#11 library already initialized",
            severity=ErrorSeverity.LOW,
            category=ErrorCategory.SOFTWARE,
            recovery_action=RecoveryAction.NONE,
            user_message="Smart card system already initialized.",
            technical_details="PKCS#11 library is already initialized"
        )
        
        return error_codes
    
    def _setup_file_logging(self) -> None:
        """Setup file logging for error persistence"""
        try:
            log_path = Path(self._log_file)
            log_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Create file handler
            file_handler = logging.FileHandler(self._log_file)
            file_handler.setLevel(logging.ERROR)
            
            # Create formatter
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            file_handler.setFormatter(formatter)
            
            # Add to logger
            self.logger.addHandler(file_handler)
            
        except Exception as e:
            self.logger.warning(f"Failed to setup file logging: {e}")
    
    def handle_error(self, error: Union[Exception, int], 
                    context: Optional[ErrorContext] = None,
                    attempt_recovery: bool = True) -> Tuple[bool, Optional[str]]:
        """
        Handle an error with classification and optional recovery
        
        Args:
            error: Exception or PKCS#11 error code
            context: Error context information
            attempt_recovery: Whether to attempt automated recovery
            
        Returns:
            Tuple of (recovery_successful, recovery_message)
        """
        with self._lock:
            try:
                # Extract error code
                if isinstance(error, Exception):
                    error_code_value = getattr(error, 'rv', None)
                    if error_code_value is None:
                        error_code_value = PKCS11ErrorCode.CKR_GENERAL_ERROR
                    stack_trace = traceback.format_exc()
                else:
                    error_code_value = error
                    stack_trace = None
                
                # Get error code information
                error_code = self._get_error_code(error_code_value)
                
                # Create error instance
                error_instance = ErrorInstance(
                    error_code=error_code,
                    context=context or ErrorContext(operation="unknown"),
                    stack_trace=stack_trace
                )
                
                # Update statistics
                self._update_statistics(error_instance)
                
                # Log error
                self._log_error(error_instance)
                
                # Check for patterns
                self._analyze_error_patterns(error_instance)
                
                # Store error history
                self._error_history.append(error_instance)
                
                # Attempt recovery if requested
                recovery_successful = False
                recovery_message = None
                
                if attempt_recovery and error_code.recovery_action != RecoveryAction.NONE:
                    recovery_successful, recovery_message = self._attempt_recovery(
                        error_instance
                    )
                    error_instance.recovery_attempted = True
                    error_instance.recovery_successful = recovery_successful
                
                return recovery_successful, recovery_message
                
            except Exception as e:
                self.logger.error(f"Error in error handler: {e}")
                return False, f"Error handler failed: {e}"
    
    def _get_error_code(self, code_value: int) -> ErrorCode:
        """Get error code information"""
        if code_value in self._error_codes:
            return self._error_codes[code_value]
        
        # Create unknown error code
        return ErrorCode(
            code=code_value,
            name=f"UNKNOWN_ERROR_0x{code_value:08X}",
            description=f"Unknown PKCS#11 error code: 0x{code_value:08X}",
            severity=ErrorSeverity.MEDIUM,
            category=ErrorCategory.UNKNOWN,
            recovery_action=RecoveryAction.RETRY,
            user_message="An unknown error occurred. Please try again.",
            technical_details=f"Unrecognized PKCS#11 error code: 0x{code_value:08X}"
        )
    
    def _update_statistics(self, error_instance: ErrorInstance) -> None:
        """Update error statistics"""
        self._stats['total_errors'] += 1
        self._stats['errors_by_severity'][error_instance.error_code.severity.value] += 1
        self._stats['errors_by_category'][error_instance.error_code.category.value] += 1
        self._stats['last_error_time'] = error_instance.timestamp
    
    def _log_error(self, error_instance: ErrorInstance) -> None:
        """Log error with appropriate level"""
        error_dict = error_instance.to_dict()
        error_json = json.dumps(error_dict, indent=2)
        
        severity = error_instance.error_code.severity
        
        if severity == ErrorSeverity.CRITICAL:
            self.logger.critical(f"CRITICAL ERROR: {error_instance.error_code}\n{error_json}")
        elif severity == ErrorSeverity.HIGH:
            self.logger.error(f"HIGH SEVERITY ERROR: {error_instance.error_code}\n{error_json}")
        elif severity == ErrorSeverity.MEDIUM:
            self.logger.warning(f"MEDIUM SEVERITY ERROR: {error_instance.error_code}\n{error_json}")
        else:
            self.logger.info(f"LOW SEVERITY ERROR: {error_instance.error_code}\n{error_json}")
    
    def _analyze_error_patterns(self, error_instance: ErrorInstance) -> None:
        """Analyze error patterns for recurring issues"""
        pattern_key = f"{error_instance.error_code.name}_{error_instance.context.operation}"
        
        if pattern_key in self._error_patterns:
            self._error_patterns[pattern_key] += 1
        else:
            self._error_patterns[pattern_key] = 1
        
        # Alert on recurring patterns
        if self._error_patterns[pattern_key] >= 5:
            self.logger.warning(
                f"Recurring error pattern detected: {pattern_key} "
                f"({self._error_patterns[pattern_key]} occurrences)"
            )
    
    def _attempt_recovery(self, error_instance: ErrorInstance) -> Tuple[bool, str]:
        """Attempt automated recovery"""
        recovery_action = error_instance.error_code.recovery_action
        
        self._stats['recovery_attempts'] += 1
        
        try:
            if recovery_action in self._recovery_handlers:
                # Use custom recovery handler
                handler = self._recovery_handlers[recovery_action]
                success = handler(error_instance)
                message = f"Custom recovery {'succeeded' if success else 'failed'}"
            else:
                # Use default recovery logic
                success, message = self._default_recovery(recovery_action, error_instance)
            
            if success:
                self._stats['successful_recoveries'] += 1
                self.logger.info(f"Recovery successful for {error_instance.error_code.name}: {message}")
            else:
                self.logger.warning(f"Recovery failed for {error_instance.error_code.name}: {message}")
            
            return success, message
            
        except Exception as e:
            error_msg = f"Recovery attempt failed with exception: {e}"
            self.logger.error(error_msg)
            return False, error_msg
    
    def _default_recovery(self, action: RecoveryAction, 
                         error_instance: ErrorInstance) -> Tuple[bool, str]:
        """Default recovery implementation"""
        if action == RecoveryAction.RETRY:
            # For retry, just return success (caller should retry)
            return True, "Retry recommended"
        
        elif action == RecoveryAction.RECONNECT:
            # For reconnect, return guidance
            return True, "Reconnection required"
        
        elif action == RecoveryAction.REINITIALIZE:
            # For reinitialize, return guidance
            return True, "Reinitialization required"
        
        elif action == RecoveryAction.USER_INTERVENTION:
            # User intervention required
            return False, "User intervention required"
        
        elif action == RecoveryAction.SYSTEM_RESTART:
            # System restart required
            return False, "System restart required"
        
        else:
            return False, f"No recovery handler for action: {action}"
    
    def register_recovery_handler(self, action: RecoveryAction, 
                                 handler: Callable[[ErrorInstance], bool]) -> None:
        """
        Register custom recovery handler
        
        Args:
            action: Recovery action to handle
            handler: Handler function that returns success/failure
        """
        with self._lock:
            self._recovery_handlers[action] = handler
            self.logger.debug(f"Registered recovery handler for {action}")
    
    def get_error_statistics(self) -> Dict[str, Any]:
        """Get comprehensive error statistics"""
        with self._lock:
            stats = self._stats.copy()
            
            # Add pattern analysis
            stats['error_patterns'] = self._error_patterns.copy()
            stats['total_patterns'] = len(self._error_patterns)
            
            # Add recent errors
            recent_errors = [
                {
                    'error_code': e.error_code.name,
                    'operation': e.context.operation,
                    'timestamp': e.timestamp.isoformat(),
                    'severity': e.error_code.severity.value,
                    'recovery_attempted': e.recovery_attempted,
                    'recovery_successful': e.recovery_successful
                }
                for e in self._error_history[-10:]  # Last 10 errors
            ]
            stats['recent_errors'] = recent_errors
            
            # Calculate recovery rate
            if stats['recovery_attempts'] > 0:
                stats['recovery_rate'] = stats['successful_recoveries'] / stats['recovery_attempts']
            else:
                stats['recovery_rate'] = 0.0
            
            return stats
    
    def get_error_history(self, limit: Optional[int] = None,
                         severity_filter: Optional[ErrorSeverity] = None) -> List[ErrorInstance]:
        """
        Get error history with optional filtering
        
        Args:
            limit: Maximum number of errors to return
            severity_filter: Filter by severity level
            
        Returns:
            List of error instances
        """
        with self._lock:
            errors = self._error_history.copy()
            
            # Apply severity filter
            if severity_filter:
                errors = [e for e in errors if e.error_code.severity == severity_filter]
            
            # Apply limit
            if limit:
                errors = errors[-limit:]
            
            return errors
    
    def clear_error_history(self) -> None:
        """Clear error history and reset statistics"""
        with self._lock:
            self._error_history.clear()
            self._error_patterns.clear()
            
            # Reset statistics
            self._stats = {
                'total_errors': 0,
                'errors_by_severity': {s.value: 0 for s in ErrorSeverity},
                'errors_by_category': {c.value: 0 for c in ErrorCategory},
                'recovery_attempts': 0,
                'successful_recoveries': 0,
                'last_error_time': None
            }
            
            self.logger.info("Error history and statistics cleared")
    
    def export_error_report(self, file_path: str, 
                           include_stack_traces: bool = False) -> None:
        """
        Export comprehensive error report
        
        Args:
            file_path: Path to export file
            include_stack_traces: Include stack traces in report
        """
        with self._lock:
            try:
                report = {
                    'generated_at': datetime.now().isoformat(),
                    'statistics': self.get_error_statistics(),
                    'error_codes': {
                        str(code): {
                            'name': ec.name,
                            'description': ec.description,
                            'severity': ec.severity.value,
                            'category': ec.category.value,
                            'recovery_action': ec.recovery_action.value
                        }
                        for code, ec in self._error_codes.items()
                    },
                    'error_history': []
                }
                
                # Add error history
                for error_instance in self._error_history:
                    error_dict = error_instance.to_dict()
                    if not include_stack_traces:
                        error_dict.pop('stack_trace', None)
                    report['error_history'].append(error_dict)
                
                # Write report
                with open(file_path, 'w') as f:
                    json.dump(report, f, indent=2)
                
                self.logger.info(f"Error report exported to {file_path}")
                
            except Exception as e:
                self.logger.error(f"Failed to export error report: {e}")
                raise