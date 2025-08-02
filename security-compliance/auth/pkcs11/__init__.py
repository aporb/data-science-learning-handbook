#!/usr/bin/env python3
"""
PKCS#11 Infrastructure for CAC/PIV Smart Card Integration

This module provides the core PKCS#11 infrastructure for smart card operations
including card detection, reader management, and basic card communication.

Author: AI Agent - PKCS#11 Infrastructure Implementation
Date: 2025-07-27
Classification: UNCLASSIFIED
"""

from .pkcs11_wrapper import (
    PKCS11Wrapper,
    PKCS11Error,
    PKCS11SessionError,
    PKCS11TokenError,
    PKCS11SlotError
)

from .reader_manager import (
    SmartCardReaderManager,
    ReaderInfo,
    ReaderStatus,
    ReaderEvent,
    ReaderEventType
)

from .card_manager import (
    SmartCardManager,
    CardInfo,
    CardStatus,
    CardConnectionManager,
    CardEvent,
    CardEventType
)

from .communication import (
    CardCommunicator,
    APDUCommand,
    APDUResponse,
    CommunicationError,
    ResponseStatus
)

from .error_handler import (
    PKCS11ErrorHandler,
    ErrorCode,
    ErrorSeverity,
    ErrorContext,
    RecoveryAction
)

__version__ = "1.0.0"
__author__ = "AI Agent - PKCS#11 Infrastructure"
__classification__ = "UNCLASSIFIED"

__all__ = [
    # Core PKCS#11 wrapper
    'PKCS11Wrapper',
    'PKCS11Error',
    'PKCS11SessionError', 
    'PKCS11TokenError',
    'PKCS11SlotError',
    
    # Reader management
    'SmartCardReaderManager',
    'ReaderInfo',
    'ReaderStatus',
    'ReaderEvent',
    'ReaderEventType',
    
    # Card management
    'SmartCardManager',
    'CardInfo',
    'CardStatus',
    'CardConnectionManager',
    'CardEvent',
    'CardEventType',
    
    # Communication
    'CardCommunicator',
    'APDUCommand',
    'APDUResponse',
    'CommunicationError',
    'ResponseStatus',
    
    # Error handling
    'PKCS11ErrorHandler',
    'ErrorCode',
    'ErrorSeverity',
    'ErrorContext',
    'RecoveryAction'
]