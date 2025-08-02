#!/usr/bin/env python3
"""
Unit Tests for PKCS#11 Wrapper

Tests the core PKCS#11 wrapper functionality including library detection,
initialization, session management, and error handling.

Author: AI Agent - PKCS#11 Infrastructure Implementation
Date: 2025-07-27
Classification: UNCLASSIFIED
"""

import unittest
import tempfile
import os
from unittest.mock import Mock, patch, MagicMock
import threading
import time

# Import the modules to test
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from pkcs11_wrapper import (
        PKCS11Wrapper, PKCS11Error, PKCS11SessionError, 
        PKCS11TokenError, PKCS11SlotError, PKCS11LibraryDetector,
        SlotInfo, TokenInfo, SessionInfo, SessionState, UserType,
        PKCS11ErrorCode
    )
except ImportError:
    # If direct import fails, try relative import
    from ..pkcs11_wrapper import (
        PKCS11Wrapper, PKCS11Error, PKCS11SessionError, 
        PKCS11TokenError, PKCS11SlotError, PKCS11LibraryDetector,
        SlotInfo, TokenInfo, SessionInfo, SessionState, UserType,
        PKCS11ErrorCode
    )


class TestPKCS11LibraryDetector(unittest.TestCase):
    """Test cases for PKCS#11 library detection"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.detector = PKCS11LibraryDetector()
    
    def test_library_detector_initialization(self):
        """Test library detector initialization"""
        self.assertIsNotNone(self.detector)
        self.assertIsNotNone(self.detector.config)
    
    @patch('os.path.exists')
    @patch('os.access')
    def test_validate_library_success(self, mock_access, mock_exists):
        """Test successful library validation"""
        mock_exists.return_value = True
        mock_access.return_value = True
        
        # Mock PyKCS11 library loading
        with patch('pkcs11_wrapper.PyKCS11Lib') as mock_lib_class:
            mock_lib = Mock()
            mock_lib_class.return_value = mock_lib
            mock_lib.lib.C_Initialize.return_value = None
            mock_lib.lib.C_Finalize.return_value = None
            
            result = self.detector._validate_library("/fake/path/lib.so")
            self.assertTrue(result)
    
    @patch('os.path.exists')
    def test_validate_library_not_exists(self, mock_exists):
        """Test library validation when file doesn't exist"""
        mock_exists.return_value = False
        
        result = self.detector._validate_library("/nonexistent/path/lib.so")
        self.assertFalse(result)
    
    @patch('os.path.exists')
    @patch('os.access')
    def test_validate_library_not_readable(self, mock_access, mock_exists):
        """Test library validation when file is not readable"""
        mock_exists.return_value = True
        mock_access.return_value = False
        
        result = self.detector._validate_library("/fake/path/lib.so")
        self.assertFalse(result)
    
    @patch.dict(os.environ, {'PKCS11_LIB_PATH': '/custom/path/lib.so'})
    @patch('pkcs11_wrapper.PKCS11LibraryDetector._validate_library')
    def test_detect_libraries_with_env_var(self, mock_validate):
        """Test library detection with environment variable"""
        mock_validate.return_value = True
        
        libraries = self.detector.detect_libraries()
        
        # Environment variable path should be first
        self.assertIn('/custom/path/lib.so', libraries)
        # Should be called with environment path first
        mock_validate.assert_called()


class TestSlotInfo(unittest.TestCase):
    """Test cases for SlotInfo data class"""
    
    def test_slot_info_creation(self):
        """Test SlotInfo creation with valid data"""
        slot_info = SlotInfo(
            slot_id=1,
            description="Test Slot",
            manufacturer_id="Test Manufacturer",
            hardware_version="1.0",
            firmware_version="2.0",
            flags=0x01,
            token_present=True
        )
        
        self.assertEqual(slot_info.slot_id, 1)
        self.assertEqual(slot_info.description, "Test Slot")
        self.assertTrue(slot_info.token_present)


class TestTokenInfo(unittest.TestCase):
    """Test cases for TokenInfo data class"""
    
    def test_token_info_creation(self):
        """Test TokenInfo creation with valid data"""
        token_info = TokenInfo(
            label="Test Token",
            manufacturer_id="Test Manufacturer",
            model="Test Model",
            serial_number="12345",
            hardware_version="1.0",
            firmware_version="2.0",
            flags=0x01,
            max_session_count=10,
            session_count=0,
            max_rw_session_count=5,
            rw_session_count=0,
            max_pin_len=8,
            min_pin_len=4,
            total_public_memory=1024,
            free_public_memory=512,
            total_private_memory=512,
            free_private_memory=256
        )
        
        self.assertEqual(token_info.label, "Test Token")
        self.assertEqual(token_info.serial_number, "12345")
        self.assertEqual(token_info.max_pin_len, 8)


class TestSessionInfo(unittest.TestCase):
    """Test cases for SessionInfo data class"""
    
    def test_session_info_creation(self):
        """Test SessionInfo creation with valid data"""
        session_info = SessionInfo(
            session_handle=12345,
            slot_id=1,
            state=SessionState.OPEN_RO_PUBLIC,
            flags=0x01
        )
        
        self.assertEqual(session_info.session_handle, 12345)
        self.assertEqual(session_info.slot_id, 1)
        self.assertEqual(session_info.state, SessionState.OPEN_RO_PUBLIC)


class MockPyKCS11Lib:
    """Mock PyKCS11 library for testing"""
    
    def __init__(self):
        self.lib = Mock()
        self.lib.C_Initialize.return_value = None
        self.lib.C_Finalize.return_value = None
    
    def load(self, path):
        """Mock load method"""
        pass
    
    def getSlotList(self, tokenPresent=True):
        """Mock getSlotList method"""
        return [0, 1, 2] if tokenPresent else [0, 1, 2, 3, 4]
    
    def getSlotInfo(self, slot_id):
        """Mock getSlotInfo method"""
        mock_slot_info = Mock()
        mock_slot_info.slotDescription = f"Slot {slot_id}    "  # Padded string
        mock_slot_info.manufacturerID = "Test Manufacturer    "
        mock_slot_info.hardwareVersion = Mock()
        mock_slot_info.hardwareVersion.major = 1
        mock_slot_info.hardwareVersion.minor = 0
        mock_slot_info.firmwareVersion = Mock()
        mock_slot_info.firmwareVersion.major = 2
        mock_slot_info.firmwareVersion.minor = 0
        mock_slot_info.flags = 0x01
        return mock_slot_info
    
    def getTokenInfo(self, slot_id):
        """Mock getTokenInfo method"""
        mock_token_info = Mock()
        mock_token_info.label = f"Token {slot_id}    "
        mock_token_info.manufacturerID = "Test Manufacturer    "
        mock_token_info.model = "Test Model    "
        mock_token_info.serialNumber = f"SN{slot_id:04d}    "
        mock_token_info.hardwareVersion = Mock()
        mock_token_info.hardwareVersion.major = 1
        mock_token_info.hardwareVersion.minor = 0
        mock_token_info.firmwareVersion = Mock()
        mock_token_info.firmwareVersion.major = 2
        mock_token_info.firmwareVersion.minor = 0
        mock_token_info.flags = 0x01
        mock_token_info.ulMaxSessionCount = 10
        mock_token_info.ulSessionCount = 0
        mock_token_info.ulMaxRwSessionCount = 5
        mock_token_info.ulRwSessionCount = 0
        mock_token_info.ulMaxPinLen = 8
        mock_token_info.ulMinPinLen = 4
        mock_token_info.ulTotalPublicMemory = 1024
        mock_token_info.ulFreePublicMemory = 512
        mock_token_info.ulTotalPrivateMemory = 512
        mock_token_info.ulFreePrivateMemory = 256
        return mock_token_info
    
    def openSession(self, slot_id, flags):
        """Mock openSession method"""
        return 12345  # Mock session handle
    
    def closeSession(self, session_handle):
        """Mock closeSession method"""
        pass
    
    def getSessionInfo(self, session_handle):
        """Mock getSessionInfo method"""
        mock_session_info = Mock()
        mock_session_info.slotID = 1
        mock_session_info.state = 0  # CKS_RO_PUBLIC_SESSION
        mock_session_info.flags = 0x01
        mock_session_info.ulDeviceError = 0
        return mock_session_info
    
    def login(self, session_handle, user_type, pin):
        """Mock login method"""
        pass
    
    def logout(self, session_handle):
        """Mock logout method"""
        pass
    
    def findObjects(self, session_handle, template):
        """Mock findObjects method"""
        return [1, 2, 3]  # Mock object handles
    
    def getAttributeValue(self, session_handle, object_handle, attributes):
        """Mock getAttributeValue method"""
        return [b'test_value'] * len(attributes)


class TestPKCS11Wrapper(unittest.TestCase):
    """Test cases for PKCS#11 wrapper"""
    
    def setUp(self):
        """Set up test fixtures"""
        # Patch PyKCS11 imports
        self.patcher_lib = patch('pkcs11_wrapper.PyKCS11Lib', MockPyKCS11Lib)
        self.mock_lib_class = self.patcher_lib.start()
        
        # Patch library detection
        self.patcher_detector = patch('pkcs11_wrapper.PKCS11LibraryDetector')
        self.mock_detector_class = self.patcher_detector.start()
        self.mock_detector = Mock()
        self.mock_detector.detect_libraries.return_value = ['/fake/lib.so']
        self.mock_detector_class.return_value = self.mock_detector
    
    def tearDown(self):
        """Clean up test fixtures"""
        self.patcher_lib.stop()
        self.patcher_detector.stop()
    
    def test_wrapper_initialization(self):
        """Test PKCS#11 wrapper initialization"""
        wrapper = PKCS11Wrapper()
        
        self.assertTrue(wrapper.is_initialized)
        self.assertEqual(wrapper.library_path, '/fake/lib.so')
    
    def test_wrapper_initialization_with_path(self):
        """Test PKCS#11 wrapper initialization with explicit path"""
        wrapper = PKCS11Wrapper(library_path='/custom/lib.so')
        
        self.assertTrue(wrapper.is_initialized)
        self.assertEqual(wrapper.library_path, '/custom/lib.so')
    
    def test_get_slot_list(self):
        """Test getting slot list"""
        wrapper = PKCS11Wrapper()
        
        slots = wrapper.get_slot_list(token_present=True)
        
        self.assertIsInstance(slots, list)
        self.assertEqual(slots, [0, 1, 2])
    
    def test_get_slot_info(self):
        """Test getting slot information"""
        wrapper = PKCS11Wrapper()
        
        slot_info = wrapper.get_slot_info(slot_id=1)
        
        self.assertIsInstance(slot_info, SlotInfo)
        self.assertEqual(slot_info.slot_id, 1)
        self.assertEqual(slot_info.description, "Slot 1")
    
    def test_get_token_info(self):
        """Test getting token information"""
        wrapper = PKCS11Wrapper()
        
        token_info = wrapper.get_token_info(slot_id=1)
        
        self.assertIsInstance(token_info, TokenInfo)
        self.assertEqual(token_info.label, "Token 1")
        self.assertEqual(token_info.serial_number, "SN0001")
    
    def test_open_close_session(self):
        """Test opening and closing sessions"""
        wrapper = PKCS11Wrapper()
        
        # Open session
        session_handle = wrapper.open_session(slot_id=1, read_write=False)
        
        self.assertEqual(session_handle, 12345)
        self.assertIn(session_handle, wrapper.active_sessions)
        
        # Close session
        wrapper.close_session(session_handle)
        
        self.assertNotIn(session_handle, wrapper.active_sessions)
    
    def test_login_logout(self):
        """Test login and logout operations"""
        wrapper = PKCS11Wrapper()
        
        # Open session first
        session_handle = wrapper.open_session(slot_id=1, read_write=False)
        
        # Login
        wrapper.login(session_handle, UserType.CKU_USER, "123456")
        
        # Logout
        wrapper.logout(session_handle)
        
        # Close session
        wrapper.close_session(session_handle)
    
    def test_find_objects(self):
        """Test finding objects"""
        wrapper = PKCS11Wrapper()
        
        # Open session
        session_handle = wrapper.open_session(slot_id=1, read_write=False)
        
        # Find objects
        objects = wrapper.find_objects(session_handle, [])
        
        self.assertEqual(objects, [1, 2, 3])
        
        # Close session
        wrapper.close_session(session_handle)
    
    def test_get_attribute_value(self):
        """Test getting attribute values"""
        wrapper = PKCS11Wrapper()
        
        # Open session
        session_handle = wrapper.open_session(slot_id=1, read_write=False)
        
        # Get attribute values
        attributes = wrapper.get_attribute_value(session_handle, 1, [0x01, 0x02])
        
        self.assertIsInstance(attributes, dict)
        self.assertEqual(len(attributes), 2)
        
        # Close session
        wrapper.close_session(session_handle)
    
    def test_error_handling_not_initialized(self):
        """Test error handling when library not initialized"""
        # Create wrapper but don't initialize
        wrapper = PKCS11Wrapper.__new__(PKCS11Wrapper)
        wrapper._initialized = False
        
        with self.assertRaises(PKCS11Error):
            wrapper.get_slot_list()
    
    def test_finalize(self):
        """Test wrapper finalization"""
        wrapper = PKCS11Wrapper()
        
        # Open some sessions
        session1 = wrapper.open_session(slot_id=1)
        session2 = wrapper.open_session(slot_id=2)
        
        # Finalize
        wrapper.finalize()
        
        self.assertFalse(wrapper.is_initialized)
        self.assertEqual(len(wrapper.active_sessions), 0)
    
    def test_thread_safety(self):
        """Test thread safety of wrapper operations"""
        wrapper = PKCS11Wrapper()
        results = []
        errors = []
        
        def worker_function():
            try:
                # Each thread opens its own session
                session_handle = wrapper.open_session(slot_id=1)
                slots = wrapper.get_slot_list()
                wrapper.close_session(session_handle)
                results.append(len(slots))
            except Exception as e:
                errors.append(e)
        
        # Create multiple threads
        threads = []
        for i in range(5):
            thread = threading.Thread(target=worker_function)
            threads.append(thread)
            thread.start()
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join()
        
        # Check results
        self.assertEqual(len(errors), 0)
        self.assertEqual(len(results), 5)
        self.assertTrue(all(r == 3 for r in results))  # All should return 3 slots
    
    def test_cache_functionality(self):
        """Test caching functionality"""
        wrapper = PKCS11Wrapper()
        
        # First call should populate cache
        slot_info1 = wrapper.get_slot_info(slot_id=1, use_cache=True)
        
        # Second call should use cache
        slot_info2 = wrapper.get_slot_info(slot_id=1, use_cache=True)
        
        # Should be the same object (reference equality)
        self.assertIs(slot_info1, slot_info2)
        
        # Force refresh should create new object
        slot_info3 = wrapper.get_slot_info(slot_id=1, use_cache=False)
        
        # Should have same data but different object
        self.assertEqual(slot_info1.slot_id, slot_info3.slot_id)
    
    def test_clear_caches(self):
        """Test cache clearing functionality"""
        wrapper = PKCS11Wrapper()
        
        # Populate caches
        wrapper.get_slot_info(slot_id=1)
        wrapper.get_token_info(slot_id=1)
        
        # Clear caches
        wrapper.clear_caches()
        
        # Verify caches are empty (this is internal state, so we test behavior)
        # Getting info again should work (would fail if cache was corrupted)
        slot_info = wrapper.get_slot_info(slot_id=1)
        token_info = wrapper.get_token_info(slot_id=1)
        
        self.assertIsNotNone(slot_info)
        self.assertIsNotNone(token_info)


class TestPKCS11Errors(unittest.TestCase):
    """Test cases for PKCS#11 error classes"""
    
    def test_pkcs11_error_creation(self):
        """Test PKCS11Error creation"""
        error = PKCS11Error("Test error", error_code=123, context={"test": "value"})
        
        self.assertEqual(error.message, "Test error")
        self.assertEqual(error.error_code, 123)
        self.assertEqual(error.context["test"], "value")
    
    def test_pkcs11_session_error(self):
        """Test PKCS11SessionError inheritance"""
        error = PKCS11SessionError("Session error")
        
        self.assertIsInstance(error, PKCS11Error)
        self.assertEqual(error.message, "Session error")
    
    def test_pkcs11_token_error(self):
        """Test PKCS11TokenError inheritance"""
        error = PKCS11TokenError("Token error")
        
        self.assertIsInstance(error, PKCS11Error)
        self.assertEqual(error.message, "Token error")
    
    def test_pkcs11_slot_error(self):
        """Test PKCS11SlotError inheritance"""
        error = PKCS11SlotError("Slot error")
        
        self.assertIsInstance(error, PKCS11Error)
        self.assertEqual(error.message, "Slot error")


if __name__ == '__main__':
    # Configure logging for tests
    import logging
    logging.basicConfig(level=logging.DEBUG)
    
    # Run tests
    unittest.main(verbosity=2)