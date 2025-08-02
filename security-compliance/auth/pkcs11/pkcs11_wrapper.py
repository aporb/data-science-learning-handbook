#!/usr/bin/env python3
"""
Core PKCS#11 Wrapper Classes

Provides the fundamental PKCS#11 interface abstraction for smart card operations.
This module handles the low-level PKCS#11 library integration and provides a
clean, pythonic interface for smart card operations.

Author: AI Agent - PKCS#11 Infrastructure Implementation  
Date: 2025-07-27
Classification: UNCLASSIFIED
"""

import os
import sys
import platform
import logging
import threading
from typing import Optional, Dict, List, Any, Union, Callable
from dataclasses import dataclass, field
from enum import Enum, IntEnum
from contextlib import contextmanager
import time
from pathlib import Path

try:
    import PyKCS11
    from PyKCS11 import PyKCS11Error, PyKCS11Lib
except ImportError:
    raise ImportError(
        "PyKCS11 library not found. Install with: pip install PyKCS11"
    )

from ..cac_config import CACConfig

# Configure module logger
logger = logging.getLogger(__name__)


class PKCS11ErrorCode(IntEnum):
    """PKCS#11 error codes based on PKCS#11 standard"""
    CKR_OK = 0x00000000
    CKR_CANCEL = 0x00000001
    CKR_HOST_MEMORY = 0x00000002
    CKR_SLOT_ID_INVALID = 0x00000003
    CKR_GENERAL_ERROR = 0x00000005
    CKR_FUNCTION_FAILED = 0x00000006
    CKR_ARGUMENTS_BAD = 0x00000007
    CKR_NO_EVENT = 0x00000008
    CKR_NEED_TO_CREATE_THREADS = 0x00000009
    CKR_CANT_LOCK = 0x0000000A
    CKR_ATTRIBUTE_READ_ONLY = 0x00000010
    CKR_ATTRIBUTE_SENSITIVE = 0x00000011
    CKR_ATTRIBUTE_TYPE_INVALID = 0x00000012
    CKR_ATTRIBUTE_VALUE_INVALID = 0x00000013
    CKR_DATA_INVALID = 0x00000020
    CKR_DATA_LEN_RANGE = 0x00000021
    CKR_DEVICE_ERROR = 0x00000030
    CKR_DEVICE_MEMORY = 0x00000031
    CKR_DEVICE_REMOVED = 0x00000032
    CKR_ENCRYPTED_DATA_INVALID = 0x00000040
    CKR_ENCRYPTED_DATA_LEN_RANGE = 0x00000041
    CKR_FUNCTION_CANCELED = 0x00000050
    CKR_FUNCTION_NOT_PARALLEL = 0x00000051
    CKR_FUNCTION_NOT_SUPPORTED = 0x00000054
    CKR_KEY_HANDLE_INVALID = 0x00000060
    CKR_KEY_SIZE_RANGE = 0x00000062
    CKR_KEY_TYPE_INCONSISTENT = 0x00000063
    CKR_KEY_NOT_NEEDED = 0x00000064
    CKR_KEY_CHANGED = 0x00000065
    CKR_KEY_NEEDED = 0x00000066
    CKR_KEY_INDIGESTIBLE = 0x00000067
    CKR_KEY_FUNCTION_NOT_PERMITTED = 0x00000068
    CKR_KEY_NOT_WRAPPABLE = 0x00000069
    CKR_KEY_UNEXTRACTABLE = 0x0000006A
    CKR_MECHANISM_INVALID = 0x00000070
    CKR_MECHANISM_PARAM_INVALID = 0x00000071
    CKR_OBJECT_HANDLE_INVALID = 0x00000082
    CKR_OPERATION_ACTIVE = 0x00000090
    CKR_OPERATION_NOT_INITIALIZED = 0x00000091
    CKR_PIN_INCORRECT = 0x000000A0
    CKR_PIN_INVALID = 0x000000A1
    CKR_PIN_LEN_RANGE = 0x000000A2
    CKR_PIN_EXPIRED = 0x000000A3
    CKR_PIN_LOCKED = 0x000000A4
    CKR_SESSION_CLOSED = 0x000000B0
    CKR_SESSION_COUNT = 0x000000B1
    CKR_SESSION_HANDLE_INVALID = 0x000000B3
    CKR_SESSION_PARALLEL_NOT_SUPPORTED = 0x000000B4
    CKR_SESSION_READ_ONLY = 0x000000B5
    CKR_SESSION_EXISTS = 0x000000B6
    CKR_SESSION_READ_ONLY_EXISTS = 0x000000B7
    CKR_SESSION_READ_WRITE_SO_EXISTS = 0x000000B8
    CKR_SIGNATURE_INVALID = 0x000000C0
    CKR_SIGNATURE_LEN_RANGE = 0x000000C1
    CKR_TEMPLATE_INCOMPLETE = 0x000000D0
    CKR_TEMPLATE_INCONSISTENT = 0x000000D1
    CKR_TOKEN_NOT_PRESENT = 0x000000E0
    CKR_TOKEN_NOT_RECOGNIZED = 0x000000E1
    CKR_TOKEN_WRITE_PROTECTED = 0x000000E2
    CKR_UNWRAPPING_KEY_HANDLE_INVALID = 0x000000F0
    CKR_UNWRAPPING_KEY_SIZE_RANGE = 0x000000F1
    CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT = 0x000000F2
    CKR_USER_ALREADY_LOGGED_IN = 0x00000100
    CKR_USER_NOT_LOGGED_IN = 0x00000101
    CKR_USER_PIN_NOT_INITIALIZED = 0x00000102
    CKR_USER_TYPE_INVALID = 0x00000103
    CKR_USER_ANOTHER_ALREADY_LOGGED_IN = 0x00000104
    CKR_USER_TOO_MANY_TYPES = 0x00000105
    CKR_WRAPPED_KEY_INVALID = 0x00000110
    CKR_WRAPPED_KEY_LEN_RANGE = 0x00000112
    CKR_WRAPPING_KEY_HANDLE_INVALID = 0x00000113
    CKR_WRAPPING_KEY_SIZE_RANGE = 0x00000114
    CKR_WRAPPING_KEY_TYPE_INCONSISTENT = 0x00000115
    CKR_RANDOM_SEED_NOT_SUPPORTED = 0x00000120
    CKR_RANDOM_NO_RNG = 0x00000121
    CKR_DOMAIN_PARAMS_INVALID = 0x00000130
    CKR_BUFFER_TOO_SMALL = 0x00000150
    CKR_SAVED_STATE_INVALID = 0x00000160
    CKR_INFORMATION_SENSITIVE = 0x00000170
    CKR_STATE_UNSAVEABLE = 0x00000180
    CKR_CRYPTOKI_NOT_INITIALIZED = 0x00000190
    CKR_CRYPTOKI_ALREADY_INITIALIZED = 0x00000191
    CKR_MUTEX_BAD = 0x000001A0
    CKR_MUTEX_NOT_LOCKED = 0x000001A1


class SessionState(Enum):
    """PKCS#11 session states"""
    CLOSED = "closed"
    OPEN_RO_PUBLIC = "open_ro_public"
    OPEN_RW_PUBLIC = "open_rw_public"
    OPEN_RO_USER = "open_ro_user"
    OPEN_RW_USER = "open_rw_user"
    OPEN_RW_SO = "open_rw_so"


class UserType(IntEnum):
    """PKCS#11 user types"""
    CKU_SO = 0
    CKU_USER = 1


@dataclass
class SlotInfo:
    """Information about a PKCS#11 slot"""
    slot_id: int
    description: str
    manufacturer_id: str
    hardware_version: str
    firmware_version: str
    flags: int
    token_present: bool = False
    removable_device: bool = True
    hardware_slot: bool = True


@dataclass
class TokenInfo:
    """Information about a PKCS#11 token"""
    label: str
    manufacturer_id: str
    model: str
    serial_number: str
    hardware_version: str
    firmware_version: str
    flags: int
    max_session_count: int
    session_count: int
    max_rw_session_count: int
    rw_session_count: int
    max_pin_len: int
    min_pin_len: int
    total_public_memory: int
    free_public_memory: int
    total_private_memory: int
    free_private_memory: int
    utc_time: Optional[str] = None


@dataclass
class SessionInfo:
    """Information about a PKCS#11 session"""
    session_handle: int
    slot_id: int
    state: SessionState
    flags: int
    device_error: int = 0


class PKCS11Error(Exception):
    """Base PKCS#11 error"""
    def __init__(self, message: str, error_code: Optional[int] = None, 
                 context: Optional[Dict[str, Any]] = None):
        self.message = message
        self.error_code = error_code
        self.context = context or {}
        super().__init__(self.message)


class PKCS11SessionError(PKCS11Error):
    """PKCS#11 session related error"""
    pass


class PKCS11TokenError(PKCS11Error):
    """PKCS#11 token related error"""
    pass


class PKCS11SlotError(PKCS11Error):
    """PKCS#11 slot related error"""
    pass


class PKCS11LibraryDetector:
    """Detects and validates PKCS#11 libraries on the system"""
    
    def __init__(self):
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        self.config = CACConfig()
    
    def detect_libraries(self) -> List[str]:
        """
        Detect available PKCS#11 libraries on the system
        
        Returns:
            List of valid PKCS#11 library paths
        """
        system = platform.system().lower()
        paths = []
        
        # Get platform-specific paths
        if system in self.config.PKCS11_PATHS:
            paths.extend(self.config.PKCS11_PATHS[system])
        
        # Add environment variable path if set
        env_path = os.getenv('PKCS11_LIB_PATH')
        if env_path:
            paths.insert(0, env_path)  # Prioritize environment setting
        
        # Validate paths
        valid_paths = []
        for path in paths:
            if self._validate_library(path):
                valid_paths.append(path)
                self.logger.info(f"Found valid PKCS#11 library: {path}")
        
        if not valid_paths:
            self.logger.warning("No valid PKCS#11 libraries found on system")
        
        return valid_paths
    
    def _validate_library(self, path: str) -> bool:
        """
        Validate that a library path exists and is accessible
        
        Args:
            path: Path to PKCS#11 library
            
        Returns:
            True if library is valid
        """
        try:
            if not os.path.exists(path):
                return False
            
            if not os.access(path, os.R_OK):
                self.logger.warning(f"PKCS#11 library not readable: {path}")
                return False
            
            # Try to load the library
            test_lib = PyKCS11Lib()
            test_lib.load(path)
            test_lib.lib.C_Initialize()
            test_lib.lib.C_Finalize()
            return True
            
        except Exception as e:
            self.logger.debug(f"Failed to validate PKCS#11 library {path}: {e}")
            return False


class PKCS11Wrapper:
    """
    Core PKCS#11 wrapper providing pythonic interface to PKCS#11 operations
    
    This class provides thread-safe access to PKCS#11 functionality with
    proper error handling, logging, and resource management.
    """
    
    def __init__(self, library_path: Optional[str] = None):
        """
        Initialize PKCS#11 wrapper
        
        Args:
            library_path: Path to PKCS#11 library, auto-detected if None
        """
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        self._lock = threading.RLock()
        self._library_path = library_path
        self._lib: Optional[PyKCS11Lib] = None
        self._initialized = False
        self._sessions: Dict[int, SessionInfo] = {}
        self._slot_cache: Dict[int, SlotInfo] = {}
        self._token_cache: Dict[int, TokenInfo] = {}
        self._detector = PKCS11LibraryDetector()
        
        # Initialize library
        self._initialize_library()
    
    def _initialize_library(self) -> None:
        """Initialize the PKCS#11 library"""
        try:
            with self._lock:
                if self._initialized:
                    return
                
                # Auto-detect library if not provided
                if not self._library_path:
                    libraries = self._detector.detect_libraries()
                    if not libraries:
                        raise PKCS11Error("No PKCS#11 libraries found on system")
                    self._library_path = libraries[0]
                
                # Load and initialize library
                self._lib = PyKCS11Lib()
                self._lib.load(self._library_path)
                self._lib.lib.C_Initialize()
                self._initialized = True
                
                self.logger.info(f"PKCS#11 library initialized: {self._library_path}")
                
        except PyKCS11Error as e:
            raise PKCS11Error(f"Failed to initialize PKCS#11 library: {e}")
        except Exception as e:
            raise PKCS11Error(f"Unexpected error initializing PKCS#11: {e}")
    
    def finalize(self) -> None:
        """Finalize the PKCS#11 library and cleanup resources"""
        try:
            with self._lock:
                if not self._initialized:
                    return
                
                # Close all open sessions
                for session_handle in list(self._sessions.keys()):
                    try:
                        self.close_session(session_handle)
                    except Exception as e:
                        self.logger.warning(f"Error closing session {session_handle}: {e}")
                
                # Finalize library
                if self._lib:
                    self._lib.lib.C_Finalize()
                    self._lib = None
                
                self._initialized = False
                self._sessions.clear()
                self._slot_cache.clear()
                self._token_cache.clear()
                
                self.logger.info("PKCS#11 library finalized")
                
        except Exception as e:
            self.logger.error(f"Error finalizing PKCS#11 library: {e}")
    
    def __del__(self):
        """Destructor - ensure library is finalized"""
        try:
            self.finalize()
        except:
            pass  # Ignore errors during destruction
    
    @contextmanager
    def _error_context(self, operation: str, **context):
        """Context manager for consistent error handling"""
        try:
            yield
        except PyKCS11Error as e:
            error_code = getattr(e, 'rv', None)
            raise PKCS11Error(
                f"PKCS#11 error during {operation}: {e}",
                error_code=error_code,
                context=context
            )
        except Exception as e:
            raise PKCS11Error(
                f"Unexpected error during {operation}: {e}",
                context=context
            )
    
    def get_slot_list(self, token_present: bool = True) -> List[int]:
        """
        Get list of available slots
        
        Args:
            token_present: If True, only return slots with tokens present
            
        Returns:
            List of slot IDs
        """
        if not self._initialized:
            raise PKCS11Error("PKCS#11 library not initialized")
        
        with self._error_context("get_slot_list", token_present=token_present):
            slots = self._lib.getSlotList(tokenPresent=token_present)
            self.logger.debug(f"Found {len(slots)} slots (token_present={token_present})")
            return slots
    
    def get_slot_info(self, slot_id: int, use_cache: bool = True) -> SlotInfo:
        """
        Get information about a specific slot
        
        Args:
            slot_id: Slot identifier
            use_cache: Use cached information if available
            
        Returns:
            SlotInfo object
        """
        if not self._initialized:
            raise PKCS11Error("PKCS#11 library not initialized")
        
        # Check cache first
        if use_cache and slot_id in self._slot_cache:
            return self._slot_cache[slot_id]
        
        with self._error_context("get_slot_info", slot_id=slot_id):
            slot_info_raw = self._lib.getSlotInfo(slot_id)
            
            slot_info = SlotInfo(
                slot_id=slot_id,
                description=slot_info_raw.slotDescription.strip(),
                manufacturer_id=slot_info_raw.manufacturerID.strip(),
                hardware_version=f"{slot_info_raw.hardwareVersion.major}.{slot_info_raw.hardwareVersion.minor}",
                firmware_version=f"{slot_info_raw.firmwareVersion.major}.{slot_info_raw.firmwareVersion.minor}",
                flags=slot_info_raw.flags,
                token_present=bool(slot_info_raw.flags & PyKCS11.CKF_TOKEN_PRESENT),
                removable_device=bool(slot_info_raw.flags & PyKCS11.CKF_REMOVABLE_DEVICE),
                hardware_slot=bool(slot_info_raw.flags & PyKCS11.CKF_HW_SLOT)
            )
            
            # Cache the result
            self._slot_cache[slot_id] = slot_info
            return slot_info
    
    def get_token_info(self, slot_id: int, use_cache: bool = True) -> TokenInfo:
        """
        Get information about the token in a specific slot
        
        Args:
            slot_id: Slot identifier
            use_cache: Use cached information if available
            
        Returns:
            TokenInfo object
        """
        if not self._initialized:
            raise PKCS11Error("PKCS#11 library not initialized")
        
        # Check cache first
        if use_cache and slot_id in self._token_cache:
            return self._token_cache[slot_id]
        
        with self._error_context("get_token_info", slot_id=slot_id):
            token_info_raw = self._lib.getTokenInfo(slot_id)
            
            token_info = TokenInfo(
                label=token_info_raw.label.strip(),
                manufacturer_id=token_info_raw.manufacturerID.strip(),
                model=token_info_raw.model.strip(),
                serial_number=token_info_raw.serialNumber.strip(),
                hardware_version=f"{token_info_raw.hardwareVersion.major}.{token_info_raw.hardwareVersion.minor}",
                firmware_version=f"{token_info_raw.firmwareVersion.major}.{token_info_raw.firmwareVersion.minor}",
                flags=token_info_raw.flags,
                max_session_count=token_info_raw.ulMaxSessionCount,
                session_count=token_info_raw.ulSessionCount,
                max_rw_session_count=token_info_raw.ulMaxRwSessionCount,
                rw_session_count=token_info_raw.ulRwSessionCount,
                max_pin_len=token_info_raw.ulMaxPinLen,
                min_pin_len=token_info_raw.ulMinPinLen,
                total_public_memory=token_info_raw.ulTotalPublicMemory,
                free_public_memory=token_info_raw.ulFreePublicMemory,
                total_private_memory=token_info_raw.ulTotalPrivateMemory,
                free_private_memory=token_info_raw.ulFreePrivateMemory,
                utc_time=token_info_raw.utcTime.strip() if hasattr(token_info_raw, 'utcTime') else None
            )
            
            # Cache the result
            self._token_cache[slot_id] = token_info
            return token_info
    
    def open_session(self, slot_id: int, read_write: bool = False) -> int:
        """
        Open a session with a token
        
        Args:
            slot_id: Slot identifier
            read_write: If True, open read-write session
            
        Returns:
            Session handle
        """
        if not self._initialized:
            raise PKCS11Error("PKCS#11 library not initialized")
        
        flags = PyKCS11.CKF_SERIAL_SESSION
        if read_write:
            flags |= PyKCS11.CKF_RW_SESSION
        
        with self._error_context("open_session", slot_id=slot_id, read_write=read_write):
            session_handle = self._lib.openSession(slot_id, flags)
            
            # Store session info
            session_info = SessionInfo(
                session_handle=session_handle,
                slot_id=slot_id,
                state=SessionState.OPEN_RO_PUBLIC if not read_write else SessionState.OPEN_RW_PUBLIC,
                flags=flags
            )
            
            with self._lock:
                self._sessions[session_handle] = session_info
            
            self.logger.debug(f"Opened session {session_handle} on slot {slot_id}")
            return session_handle
    
    def close_session(self, session_handle: int) -> None:
        """
        Close a session
        
        Args:
            session_handle: Session handle to close
        """
        if not self._initialized:
            raise PKCS11Error("PKCS#11 library not initialized")
        
        with self._error_context("close_session", session_handle=session_handle):
            self._lib.closeSession(session_handle)
            
            with self._lock:
                if session_handle in self._sessions:
                    del self._sessions[session_handle]
            
            self.logger.debug(f"Closed session {session_handle}")
    
    def get_session_info(self, session_handle: int) -> SessionInfo:
        """
        Get information about a session
        
        Args:
            session_handle: Session handle
            
        Returns:
            SessionInfo object
        """
        if not self._initialized:
            raise PKCS11Error("PKCS#11 library not initialized")
        
        with self._lock:
            if session_handle in self._sessions:
                return self._sessions[session_handle]
        
        # Session not in cache, query from library
        with self._error_context("get_session_info", session_handle=session_handle):
            session_info_raw = self._lib.getSessionInfo(session_handle)
            
            # Map state
            state_map = {
                PyKCS11.CKS_RO_PUBLIC_SESSION: SessionState.OPEN_RO_PUBLIC,
                PyKCS11.CKS_RO_USER_FUNCTIONS: SessionState.OPEN_RO_USER,
                PyKCS11.CKS_RW_PUBLIC_SESSION: SessionState.OPEN_RW_PUBLIC,
                PyKCS11.CKS_RW_USER_FUNCTIONS: SessionState.OPEN_RW_USER,
                PyKCS11.CKS_RW_SO_FUNCTIONS: SessionState.OPEN_RW_SO
            }
            
            session_info = SessionInfo(
                session_handle=session_handle,
                slot_id=session_info_raw.slotID,
                state=state_map.get(session_info_raw.state, SessionState.CLOSED),
                flags=session_info_raw.flags,
                device_error=session_info_raw.ulDeviceError
            )
            
            with self._lock:
                self._sessions[session_handle] = session_info
            
            return session_info
    
    def login(self, session_handle: int, user_type: UserType, pin: str) -> None:
        """
        Login to a session
        
        Args:
            session_handle: Session handle
            user_type: Type of user (SO or USER)
            pin: PIN/password
        """
        if not self._initialized:
            raise PKCS11Error("PKCS#11 library not initialized")
        
        with self._error_context("login", session_handle=session_handle, user_type=user_type):
            self._lib.login(session_handle, user_type.value, pin)
            
            # Update session state in cache
            with self._lock:
                if session_handle in self._sessions:
                    session_info = self._sessions[session_handle]
                    if user_type == UserType.CKU_USER:
                        if session_info.flags & PyKCS11.CKF_RW_SESSION:
                            session_info.state = SessionState.OPEN_RW_USER
                        else:
                            session_info.state = SessionState.OPEN_RO_USER
                    elif user_type == UserType.CKU_SO:
                        session_info.state = SessionState.OPEN_RW_SO
            
            self.logger.debug(f"Successfully logged in to session {session_handle}")
    
    def logout(self, session_handle: int) -> None:
        """
        Logout from a session
        
        Args:
            session_handle: Session handle
        """
        if not self._initialized:
            raise PKCS11Error("PKCS#11 library not initialized")
        
        with self._error_context("logout", session_handle=session_handle):
            self._lib.logout(session_handle)
            
            # Update session state in cache
            with self._lock:
                if session_handle in self._sessions:
                    session_info = self._sessions[session_handle]
                    if session_info.flags & PyKCS11.CKF_RW_SESSION:
                        session_info.state = SessionState.OPEN_RW_PUBLIC
                    else:
                        session_info.state = SessionState.OPEN_RO_PUBLIC
            
            self.logger.debug(f"Successfully logged out from session {session_handle}")
    
    def find_objects(self, session_handle: int, template: List = None) -> List[int]:
        """
        Find objects matching template
        
        Args:
            session_handle: Session handle
            template: Search template (list of attribute tuples)
            
        Returns:
            List of object handles
        """
        if not self._initialized:
            raise PKCS11Error("PKCS#11 library not initialized")
        
        template = template or []
        
        with self._error_context("find_objects", session_handle=session_handle):
            objects = self._lib.findObjects(session_handle, template)
            self.logger.debug(f"Found {len(objects)} objects matching template")
            return objects
    
    def get_attribute_value(self, session_handle: int, object_handle: int, 
                          attributes: List[int]) -> Dict[int, Any]:
        """
        Get attribute values from an object
        
        Args:
            session_handle: Session handle
            object_handle: Object handle
            attributes: List of attribute types to retrieve
            
        Returns:
            Dictionary mapping attribute types to values
        """
        if not self._initialized:
            raise PKCS11Error("PKCS#11 library not initialized")
        
        with self._error_context("get_attribute_value", 
                                session_handle=session_handle, 
                                object_handle=object_handle):
            attr_values = self._lib.getAttributeValue(session_handle, object_handle, attributes)
            
            # Convert to dictionary
            result = {}
            for i, attr_type in enumerate(attributes):
                if i < len(attr_values):
                    result[attr_type] = attr_values[i]
            
            return result
    
    @property
    def is_initialized(self) -> bool:
        """Check if library is initialized"""
        return self._initialized
    
    @property
    def library_path(self) -> Optional[str]:
        """Get current library path"""
        return self._library_path
    
    @property
    def active_sessions(self) -> List[int]:
        """Get list of active session handles"""
        with self._lock:
            return list(self._sessions.keys())
    
    def clear_caches(self) -> None:
        """Clear all cached information"""
        with self._lock:
            self._slot_cache.clear()
            self._token_cache.clear()
            self.logger.debug("Cleared PKCS#11 caches")