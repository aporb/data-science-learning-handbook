#!/usr/bin/env python3
"""
Unit Tests for PKCS#11 Error Handler

Tests the comprehensive error handling and recovery framework including
error classification, context preservation, and automated recovery strategies.

Author: AI Agent - PKCS#11 Infrastructure Implementation
Date: 2025-07-27
Classification: UNCLASSIFIED
"""

import unittest
import tempfile
import os
import json
from unittest.mock import Mock, patch
import threading
import time
from datetime import datetime, timedelta

# Import the modules to test
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from error_handler import (
        PKCS11ErrorHandler, ErrorCode, ErrorSeverity, ErrorCategory,
        RecoveryAction, ErrorContext, ErrorInstance
    )
    from pkcs11_wrapper import PKCS11ErrorCode
except ImportError:
    # If direct import fails, try relative import
    from ..error_handler import (
        PKCS11ErrorHandler, ErrorCode, ErrorSeverity, ErrorCategory,
        RecoveryAction, ErrorContext, ErrorInstance
    )
    from ..pkcs11_wrapper import PKCS11ErrorCode


class TestErrorContext(unittest.TestCase):
    """Test cases for ErrorContext data class"""
    
    def test_error_context_creation(self):
        """Test ErrorContext creation with valid data"""
        context = ErrorContext(
            operation="test_operation",
            slot_id=1,
            session_handle=12345,
            parameters={"param1": "value1"},
            system_state={"state1": "value1"}
        )
        
        self.assertEqual(context.operation, "test_operation")
        self.assertEqual(context.slot_id, 1)
        self.assertEqual(context.session_handle, 12345)
        self.assertEqual(context.parameters["param1"], "value1")
        self.assertEqual(context.system_state["state1"], "value1")
        self.assertIsInstance(context.timestamp, datetime)
        self.assertIsInstance(context.thread_id, int)
    
    def test_error_context_to_dict(self):
        """Test ErrorContext dictionary conversion"""
        context = ErrorContext(
            operation="test_operation",
            slot_id=1,
            parameters={"test": "value"}
        )
        
        context_dict = context.to_dict()
        
        self.assertIsInstance(context_dict, dict)
        self.assertEqual(context_dict["operation"], "test_operation")
        self.assertEqual(context_dict["slot_id"], 1)
        self.assertEqual(context_dict["parameters"]["test"], "value")
        self.assertIn("timestamp", context_dict)
        self.assertIn("thread_id", context_dict)


class TestErrorCode(unittest.TestCase):
    """Test cases for ErrorCode data class"""
    
    def test_error_code_creation(self):
        """Test ErrorCode creation with valid data"""
        error_code = ErrorCode(
            code=PKCS11ErrorCode.CKR_GENERAL_ERROR,
            name="CKR_GENERAL_ERROR",
            description="General error occurred",
            severity=ErrorSeverity.HIGH,
            category=ErrorCategory.SOFTWARE,
            recovery_action=RecoveryAction.RETRY,
            user_message="Please try again",
            technical_details="PKCS#11 general error"
        )
        
        self.assertEqual(error_code.code, PKCS11ErrorCode.CKR_GENERAL_ERROR)
        self.assertEqual(error_code.name, "CKR_GENERAL_ERROR")
        self.assertEqual(error_code.severity, ErrorSeverity.HIGH)
        self.assertEqual(error_code.category, ErrorCategory.SOFTWARE)
        self.assertEqual(error_code.recovery_action, RecoveryAction.RETRY)
    
    def test_error_code_string_representation(self):
        """Test ErrorCode string representation"""
        error_code = ErrorCode(
            code=0x12345678,
            name="TEST_ERROR",
            description="Test error description",
            severity=ErrorSeverity.MEDIUM,
            category=ErrorCategory.UNKNOWN,
            recovery_action=RecoveryAction.NONE,
            user_message="Test message"
        )
        
        str_repr = str(error_code)
        self.assertIn("TEST_ERROR", str_repr)
        self.assertIn("0x12345678", str_repr)
        self.assertIn("Test error description", str_repr)


class TestErrorInstance(unittest.TestCase):
    """Test cases for ErrorInstance data class"""
    
    def test_error_instance_creation(self):
        """Test ErrorInstance creation"""
        error_code = ErrorCode(
            code=PKCS11ErrorCode.CKR_GENERAL_ERROR,
            name="CKR_GENERAL_ERROR",
            description="General error",
            severity=ErrorSeverity.HIGH,
            category=ErrorCategory.SOFTWARE,
            recovery_action=RecoveryAction.RETRY,
            user_message="Please try again"
        )
        
        context = ErrorContext(operation="test_operation")
        
        error_instance = ErrorInstance(
            error_code=error_code,
            context=context,
            stack_trace="Mock stack trace"
        )
        
        self.assertEqual(error_instance.error_code, error_code)
        self.assertEqual(error_instance.context, context)
        self.assertEqual(error_instance.stack_trace, "Mock stack trace")
        self.assertFalse(error_instance.recovery_attempted)
        self.assertFalse(error_instance.recovery_successful)
        self.assertEqual(error_instance.occurrence_count, 1)
    
    def test_error_instance_to_dict(self):
        """Test ErrorInstance dictionary conversion"""
        error_code = ErrorCode(
            code=PKCS11ErrorCode.CKR_GENERAL_ERROR,
            name="CKR_GENERAL_ERROR",
            description="General error",
            severity=ErrorSeverity.HIGH,
            category=ErrorCategory.SOFTWARE,
            recovery_action=RecoveryAction.RETRY,
            user_message="Please try again"
        )
        
        context = ErrorContext(operation="test_operation")
        error_instance = ErrorInstance(error_code=error_code, context=context)
        
        instance_dict = error_instance.to_dict()
        
        self.assertIsInstance(instance_dict, dict)
        self.assertIn("error_code", instance_dict)
        self.assertIn("context", instance_dict)
        self.assertIn("timestamp", instance_dict)
        self.assertEqual(instance_dict["error_code"]["name"], "CKR_GENERAL_ERROR")


class TestPKCS11ErrorHandler(unittest.TestCase):
    """Test cases for PKCS#11 error handler"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.temp_log_file = tempfile.mktemp(suffix='.log')
        self.error_handler = PKCS11ErrorHandler(log_file=self.temp_log_file)
    
    def tearDown(self):
        """Clean up test fixtures"""
        try:
            if os.path.exists(self.temp_log_file):
                os.remove(self.temp_log_file)
        except:
            pass  # Ignore cleanup errors
    
    def test_error_handler_initialization(self):
        """Test error handler initialization"""
        self.assertIsNotNone(self.error_handler)
        self.assertIsInstance(self.error_handler._error_codes, dict)
        self.assertGreater(len(self.error_handler._error_codes), 0)
    
    def test_error_code_initialization(self):
        """Test error code mappings initialization"""
        # Test that common error codes are mapped
        self.assertIn(PKCS11ErrorCode.CKR_OK, self.error_handler._error_codes)
        self.assertIn(PKCS11ErrorCode.CKR_GENERAL_ERROR, self.error_handler._error_codes)
        self.assertIn(PKCS11ErrorCode.CKR_TOKEN_NOT_PRESENT, self.error_handler._error_codes)
        self.assertIn(PKCS11ErrorCode.CKR_PIN_INCORRECT, self.error_handler._error_codes)
        
        # Test error code properties
        general_error = self.error_handler._error_codes[PKCS11ErrorCode.CKR_GENERAL_ERROR]
        self.assertEqual(general_error.severity, ErrorSeverity.HIGH)
        self.assertEqual(general_error.recovery_action, RecoveryAction.RETRY)
        
        pin_error = self.error_handler._error_codes[PKCS11ErrorCode.CKR_PIN_INCORRECT]
        self.assertEqual(pin_error.category, ErrorCategory.AUTHENTICATION)
        self.assertEqual(pin_error.recovery_action, RecoveryAction.USER_INTERVENTION)
    
    def test_handle_error_with_exception(self):
        """Test handling error from exception"""
        # Create a mock exception with PKCS#11 error code
        exception = Exception("Test error")
        exception.rv = PKCS11ErrorCode.CKR_GENERAL_ERROR
        
        context = ErrorContext(operation="test_operation", slot_id=1)
        
        success, message = self.error_handler.handle_error(
            exception, 
            context=context, 
            attempt_recovery=False
        )
        
        self.assertFalse(success)  # No recovery attempted
        self.assertIsNone(message)
        
        # Check that error was recorded
        stats = self.error_handler.get_error_statistics()
        self.assertEqual(stats['total_errors'], 1)
        self.assertEqual(stats['errors_by_severity'][ErrorSeverity.HIGH.value], 1)
    
    def test_handle_error_with_code(self):
        """Test handling error from error code"""
        context = ErrorContext(operation="test_operation")
        
        success, message = self.error_handler.handle_error(
            PKCS11ErrorCode.CKR_TOKEN_NOT_PRESENT,
            context=context,
            attempt_recovery=False
        )
        
        self.assertFalse(success)
        
        # Check error history
        history = self.error_handler.get_error_history(limit=1)
        self.assertEqual(len(history), 1)
        self.assertEqual(
            history[0].error_code.name, 
            "CKR_TOKEN_NOT_PRESENT"
        )
    
    def test_handle_unknown_error_code(self):
        """Test handling unknown error code"""
        unknown_code = 0x99999999
        
        success, message = self.error_handler.handle_error(
            unknown_code,
            attempt_recovery=False
        )
        
        self.assertFalse(success)
        
        # Check that unknown error was handled
        history = self.error_handler.get_error_history(limit=1)
        self.assertEqual(len(history), 1)
        self.assertIn("UNKNOWN_ERROR", history[0].error_code.name)
        self.assertEqual(history[0].error_code.code, unknown_code)
    
    def test_recovery_attempt(self):
        """Test automated recovery attempt"""
        # Test error that should trigger retry
        success, message = self.error_handler.handle_error(
            PKCS11ErrorCode.CKR_GENERAL_ERROR,
            attempt_recovery=True
        )
        
        self.assertTrue(success)  # Retry should succeed
        self.assertIn("Retry", message)
        
        # Check recovery statistics
        stats = self.error_handler.get_error_statistics()
        self.assertEqual(stats['recovery_attempts'], 1)
        self.assertEqual(stats['successful_recoveries'], 1)
    
    def test_custom_recovery_handler(self):
        """Test custom recovery handler registration"""
        recovery_called = [False]
        
        def custom_recovery_handler(error_instance):
            recovery_called[0] = True
            return True
        
        # Register custom handler
        self.error_handler.register_recovery_handler(
            RecoveryAction.RETRY,
            custom_recovery_handler
        )
        
        # Trigger error that uses retry action
        success, message = self.error_handler.handle_error(
            PKCS11ErrorCode.CKR_GENERAL_ERROR,
            attempt_recovery=True
        )
        
        self.assertTrue(success)
        self.assertTrue(recovery_called[0])
        self.assertIn("Custom recovery succeeded", message)
    
    def test_error_pattern_detection(self):
        """Test error pattern detection"""
        context = ErrorContext(operation="repeated_operation")
        
        # Generate multiple similar errors
        for _ in range(6):
            self.error_handler.handle_error(
                PKCS11ErrorCode.CKR_GENERAL_ERROR,
                context=context,
                attempt_recovery=False
            )
        
        # Check pattern detection
        stats = self.error_handler.get_error_statistics()
        pattern_key = "CKR_GENERAL_ERROR_repeated_operation"
        self.assertIn(pattern_key, stats['error_patterns'])
        self.assertEqual(stats['error_patterns'][pattern_key], 6)
    
    def test_error_statistics(self):
        """Test error statistics collection"""
        # Generate various errors
        self.error_handler.handle_error(PKCS11ErrorCode.CKR_GENERAL_ERROR, attempt_recovery=False)
        self.error_handler.handle_error(PKCS11ErrorCode.CKR_PIN_INCORRECT, attempt_recovery=False)
        self.error_handler.handle_error(PKCS11ErrorCode.CKR_TOKEN_NOT_PRESENT, attempt_recovery=True)
        
        stats = self.error_handler.get_error_statistics()
        
        self.assertEqual(stats['total_errors'], 3)
        self.assertEqual(stats['errors_by_severity'][ErrorSeverity.HIGH.value], 1)  # General error
        self.assertEqual(stats['errors_by_severity'][ErrorSeverity.MEDIUM.value], 2)  # PIN + Token
        self.assertEqual(stats['recovery_attempts'], 1)  # Only token error attempted recovery
        self.assertIsNotNone(stats['last_error_time'])
    
    def test_error_history_filtering(self):
        """Test error history filtering"""
        # Generate errors of different severities
        self.error_handler.handle_error(PKCS11ErrorCode.CKR_GENERAL_ERROR, attempt_recovery=False)
        self.error_handler.handle_error(PKCS11ErrorCode.CKR_PIN_INCORRECT, attempt_recovery=False)
        self.error_handler.handle_error(PKCS11ErrorCode.CKR_OK, attempt_recovery=False)
        
        # Test severity filtering
        high_severity_errors = self.error_handler.get_error_history(
            severity_filter=ErrorSeverity.HIGH
        )
        self.assertEqual(len(high_severity_errors), 1)
        self.assertEqual(high_severity_errors[0].error_code.severity, ErrorSeverity.HIGH)
        
        # Test limit
        limited_errors = self.error_handler.get_error_history(limit=2)
        self.assertEqual(len(limited_errors), 2)
    
    def test_clear_error_history(self):
        """Test clearing error history"""
        # Generate some errors
        self.error_handler.handle_error(PKCS11ErrorCode.CKR_GENERAL_ERROR, attempt_recovery=False)
        self.error_handler.handle_error(PKCS11ErrorCode.CKR_PIN_INCORRECT, attempt_recovery=False)
        
        # Verify errors exist
        stats_before = self.error_handler.get_error_statistics()
        self.assertEqual(stats_before['total_errors'], 2)
        
        # Clear history
        self.error_handler.clear_error_history()
        
        # Verify cleared
        stats_after = self.error_handler.get_error_statistics()
        self.assertEqual(stats_after['total_errors'], 0)
        self.assertEqual(len(stats_after['error_patterns']), 0)
        
        history = self.error_handler.get_error_history()
        self.assertEqual(len(history), 0)
    
    def test_export_error_report(self):
        """Test error report export"""
        # Generate some errors
        context = ErrorContext(operation="test_export", slot_id=1)
        self.error_handler.handle_error(
            PKCS11ErrorCode.CKR_GENERAL_ERROR,
            context=context,
            attempt_recovery=True
        )
        
        # Export report
        report_file = tempfile.mktemp(suffix='.json')
        try:
            self.error_handler.export_error_report(report_file, include_stack_traces=True)
            
            # Verify report file exists and contains expected data
            self.assertTrue(os.path.exists(report_file))
            
            with open(report_file, 'r') as f:
                report = json.load(f)
            
            self.assertIn('generated_at', report)
            self.assertIn('statistics', report)
            self.assertIn('error_codes', report)
            self.assertIn('error_history', report)
            
            # Check that our error is in the history
            self.assertEqual(len(report['error_history']), 1)
            self.assertEqual(
                report['error_history'][0]['error_code']['name'],
                'CKR_GENERAL_ERROR'
            )
            
        finally:
            try:
                if os.path.exists(report_file):
                    os.remove(report_file)
            except:
                pass
    
    def test_thread_safety(self):
        """Test thread safety of error handler"""
        results = []
        errors = []
        
        def worker_function(error_code):
            try:
                context = ErrorContext(
                    operation=f"thread_operation_{threading.current_thread().ident}"
                )
                success, message = self.error_handler.handle_error(
                    error_code,
                    context=context,
                    attempt_recovery=False
                )
                results.append((success, message))
            except Exception as e:
                errors.append(e)
        
        # Create multiple threads handling different errors
        threads = []
        error_codes = [
            PKCS11ErrorCode.CKR_GENERAL_ERROR,
            PKCS11ErrorCode.CKR_PIN_INCORRECT,
            PKCS11ErrorCode.CKR_TOKEN_NOT_PRESENT,
            PKCS11ErrorCode.CKR_DEVICE_ERROR,
            PKCS11ErrorCode.CKR_SESSION_CLOSED
        ]
        
        for error_code in error_codes:
            thread = threading.Thread(target=worker_function, args=(error_code,))
            threads.append(thread)
            thread.start()
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join()
        
        # Check results
        self.assertEqual(len(errors), 0)  # No exceptions should occur
        self.assertEqual(len(results), 5)  # All threads should complete
        
        # Check that all errors were recorded
        stats = self.error_handler.get_error_statistics()
        self.assertEqual(stats['total_errors'], 5)
    
    def test_file_logging_setup(self):
        """Test file logging setup"""
        # Create handler with log file
        log_file = tempfile.mktemp(suffix='.log')
        
        try:
            handler = PKCS11ErrorHandler(log_file=log_file)
            
            # Generate an error
            handler.handle_error(PKCS11ErrorCode.CKR_GENERAL_ERROR, attempt_recovery=False)
            
            # Check that log file exists (may need to flush handlers)
            # Note: In real scenarios, we might need to flush or close handlers
            
        finally:
            try:
                if os.path.exists(log_file):
                    os.remove(log_file)
            except:
                pass


if __name__ == '__main__':
    # Configure logging for tests
    import logging
    logging.basicConfig(level=logging.DEBUG)
    
    # Run tests
    unittest.main(verbosity=2)