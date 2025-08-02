#!/usr/bin/env python3
"""
Smart Card Communication Protocols

Provides base classes and protocols for smart card communication including
APDU command/response handling, protocol management, and communication error handling.

Author: AI Agent - PKCS#11 Infrastructure Implementation
Date: 2025-07-27
Classification: UNCLASSIFIED
"""

import logging
import struct
import time
from typing import Optional, Dict, List, Any, Union, Tuple, Callable
from dataclasses import dataclass, field
from enum import Enum, IntEnum, auto
from abc import ABC, abstractmethod
import threading
from datetime import datetime

from .pkcs11_wrapper import PKCS11Wrapper, PKCS11Error
from .card_manager import CardConnection, CardInfo


class ResponseStatus(IntEnum):
    """ISO 7816-4 response status codes"""
    # Normal processing
    SW_SUCCESS = 0x9000
    SW_SUCCESS_MORE_DATA = 0x6100
    SW_SUCCESS_WARNING = 0x6200
    SW_SUCCESS_CORRUPT_DATA = 0x6281
    SW_SUCCESS_EOF = 0x6282
    SW_SUCCESS_LESS_DATA = 0x6283
    SW_SUCCESS_NO_INFO = 0x6300
    SW_SUCCESS_FILE_FILLED = 0x6381
    
    # Execution errors
    SW_EXECUTION_ERROR = 0x6400
    SW_MEMORY_FAILURE = 0x6500
    SW_SECURITY_STATUS_NOT_SATISFIED = 0x6982
    SW_AUTH_METHOD_BLOCKED = 0x6983
    SW_DATA_INVALID = 0x6984
    SW_CONDITIONS_NOT_SATISFIED = 0x6985
    SW_COMMAND_NOT_ALLOWED = 0x6986
    SW_APPLET_SELECT_FAILED = 0x6999
    
    # Checking errors
    SW_WRONG_LENGTH = 0x6700
    SW_LOGICAL_CHANNEL_NOT_SUPPORTED = 0x6881
    SW_SECURE_MESSAGING_NOT_SUPPORTED = 0x6882
    SW_LAST_COMMAND_CHAINED = 0x6883
    SW_COMMAND_CHAINING_NOT_SUPPORTED = 0x6884
    SW_SECURITY_ENVIRONMENT_NOT_VALID = 0x6982
    SW_PIN_VERIFICATION_REQUIRED = 0x6982
    SW_REFERENCE_DATA_NOT_FOUND = 0x6A88
    
    # Wrong parameters
    SW_INCORRECT_P1P2 = 0x6A86
    SW_LC_INCONSISTENT_WITH_P1P2 = 0x6A87
    SW_REFERENCED_DATA_NOT_FOUND = 0x6A88
    SW_FILE_NOT_FOUND = 0x6A82
    SW_RECORD_NOT_FOUND = 0x6A83
    SW_INSUFFICIENT_MEMORY = 0x6A84
    SW_INCORRECT_P1P2_LENGTH = 0x6A86
    SW_WRONG_PARAMETERS_P1P2 = 0x6B00
    SW_WRONG_LE = 0x6C00
    SW_INSTRUCTION_NOT_SUPPORTED = 0x6D00
    SW_CLASS_NOT_SUPPORTED = 0x6E00
    SW_UNKNOWN = 0x6F00


class CommandClass(IntEnum):
    """ISO 7816-4 command classes"""
    CLA_ISO = 0x00
    CLA_PROPRIETARY = 0x80
    CLA_CHAIN = 0x10
    CLA_SECURE = 0x0C


class Instruction(IntEnum):
    """Common ISO 7816-4 instructions"""
    INS_SELECT = 0xA4
    INS_GET_RESPONSE = 0xC0
    INS_GET_DATA = 0xCA
    INS_PUT_DATA = 0xDA
    INS_VERIFY = 0x20
    INS_CHANGE_REFERENCE_DATA = 0x24
    INS_RESET_RETRY_COUNTER = 0x2C
    INS_GET_CHALLENGE = 0x84
    INS_INTERNAL_AUTHENTICATE = 0x88
    INS_EXTERNAL_AUTHENTICATE = 0x82
    INS_MANAGE_SECURITY_ENVIRONMENT = 0x22
    INS_PERFORM_SECURITY_OPERATION = 0x2A
    INS_READ_BINARY = 0xB0
    INS_UPDATE_BINARY = 0xD6
    INS_READ_RECORD = 0xB2
    INS_UPDATE_RECORD = 0xDC


@dataclass
class APDUCommand:
    """
    Application Protocol Data Unit (APDU) command
    
    Represents an ISO 7816-4 command APDU with proper formatting
    and validation.
    """
    cla: int  # Class byte
    ins: int  # Instruction byte
    p1: int   # Parameter 1
    p2: int   # Parameter 2
    data: bytes = b''  # Command data
    le: Optional[int] = None  # Expected response length
    
    def __post_init__(self):
        """Validate APDU command parameters"""
        # Validate byte ranges
        if not (0 <= self.cla <= 0xFF):
            raise ValueError(f"Invalid CLA: {self.cla}")
        if not (0 <= self.ins <= 0xFF):
            raise ValueError(f"Invalid INS: {self.ins}")
        if not (0 <= self.p1 <= 0xFF):
            raise ValueError(f"Invalid P1: {self.p1}")
        if not (0 <= self.p2 <= 0xFF):
            raise ValueError(f"Invalid P2: {self.p2}")
        
        # Validate data length
        if len(self.data) > 0xFFFF:
            raise ValueError(f"Data too long: {len(self.data)}")
        
        # Validate Le
        if self.le is not None and not (0 <= self.le <= 0x10000):
            raise ValueError(f"Invalid Le: {self.le}")
    
    def to_bytes(self, extended: bool = False) -> bytes:
        """
        Convert APDU command to bytes
        
        Args:
            extended: Use extended length encoding
            
        Returns:
            APDU command as bytes
        """
        apdu = bytearray([self.cla, self.ins, self.p1, self.p2])
        
        # Handle data and Le encoding
        data_len = len(self.data)
        has_data = data_len > 0
        has_le = self.le is not None
        
        if not has_data and not has_le:
            # Case 1: No data, no Le
            pass
        elif not has_data and has_le:
            # Case 2: No data, Le present
            if extended and self.le > 0xFF:
                apdu.extend([0x00, (self.le >> 8) & 0xFF, self.le & 0xFF])
            else:
                apdu.append(self.le & 0xFF if self.le < 0x100 else 0x00)
        elif has_data and not has_le:
            # Case 3: Data present, no Le
            if extended and data_len > 0xFF:
                apdu.extend([0x00, (data_len >> 8) & 0xFF, data_len & 0xFF])
            else:
                apdu.append(data_len & 0xFF)
            apdu.extend(self.data)
        else:
            # Case 4: Data and Le present
            if extended and (data_len > 0xFF or self.le > 0xFF):
                apdu.extend([0x00, (data_len >> 8) & 0xFF, data_len & 0xFF])
                apdu.extend(self.data)
                apdu.extend([(self.le >> 8) & 0xFF, self.le & 0xFF])
            else:
                apdu.append(data_len & 0xFF)
                apdu.extend(self.data)
                apdu.append(self.le & 0xFF if self.le < 0x100 else 0x00)
        
        return bytes(apdu)
    
    @classmethod
    def from_bytes(cls, data: bytes) -> 'APDUCommand':
        """
        Create APDU command from bytes
        
        Args:
            data: APDU command bytes
            
        Returns:
            APDUCommand instance
        """
        if len(data) < 4:
            raise ValueError("APDU too short")
        
        cla, ins, p1, p2 = data[:4]
        
        if len(data) == 4:
            # Case 1: No data, no Le
            return cls(cla, ins, p1, p2)
        
        # Parse remaining data
        remaining = data[4:]
        
        if len(remaining) == 1:
            # Case 2: Le only
            le = remaining[0] if remaining[0] != 0 else 0x100
            return cls(cla, ins, p1, p2, le=le)
        
        # Extended length or standard with data
        if remaining[0] == 0x00 and len(remaining) >= 3:
            # Extended length
            lc = (remaining[1] << 8) | remaining[2]
            if len(remaining) == 3 + lc:
                # Case 3: Extended data, no Le
                return cls(cla, ins, p1, p2, data=remaining[3:3+lc])
            elif len(remaining) == 3 + lc + 2:
                # Case 4: Extended data and Le
                cmd_data = remaining[3:3+lc]
                le = (remaining[3+lc] << 8) | remaining[3+lc+1]
                return cls(cla, ins, p1, p2, data=cmd_data, le=le)
        else:
            # Standard length
            lc = remaining[0]
            if len(remaining) == 1 + lc:
                # Case 3: Standard data, no Le
                return cls(cla, ins, p1, p2, data=remaining[1:1+lc])
            elif len(remaining) == 1 + lc + 1:
                # Case 4: Standard data and Le
                cmd_data = remaining[1:1+lc]
                le = remaining[1+lc] if remaining[1+lc] != 0 else 0x100
                return cls(cla, ins, p1, p2, data=cmd_data, le=le)
        
        raise ValueError("Invalid APDU format")
    
    def __str__(self) -> str:
        """String representation of APDU command"""
        parts = [f"CLA={self.cla:02X}", f"INS={self.ins:02X}", 
                f"P1={self.p1:02X}", f"P2={self.p2:02X}"]
        
        if self.data:
            parts.append(f"DATA({len(self.data)})={self.data.hex().upper()}")
        
        if self.le is not None:
            parts.append(f"Le={self.le:02X}")
        
        return f"APDU({', '.join(parts)})"


@dataclass
class APDUResponse:
    """
    Application Protocol Data Unit (APDU) response
    
    Represents an ISO 7816-4 response APDU with status word parsing
    and data extraction.
    """
    data: bytes = b''  # Response data
    sw1: int = 0  # Status word 1
    sw2: int = 0  # Status word 2
    
    def __post_init__(self):
        """Validate response parameters"""
        if not (0 <= self.sw1 <= 0xFF):
            raise ValueError(f"Invalid SW1: {self.sw1}")
        if not (0 <= self.sw2 <= 0xFF):
            raise ValueError(f"Invalid SW2: {self.sw2}")
    
    @property
    def sw(self) -> int:
        """Get combined status word"""
        return (self.sw1 << 8) | self.sw2
    
    @property
    def status(self) -> ResponseStatus:
        """Get response status enum"""
        try:
            return ResponseStatus(self.sw)
        except ValueError:
            return ResponseStatus.SW_UNKNOWN
    
    @property
    def is_success(self) -> bool:
        """Check if response indicates success"""
        return self.sw == ResponseStatus.SW_SUCCESS
    
    @property
    def is_warning(self) -> bool:
        """Check if response indicates warning"""
        return 0x6200 <= self.sw <= 0x63FF
    
    @property
    def is_error(self) -> bool:
        """Check if response indicates error"""
        return self.sw >= 0x6400
    
    @property
    def needs_get_response(self) -> bool:
        """Check if GET RESPONSE is needed"""
        return self.sw1 == 0x61
    
    @property
    def available_bytes(self) -> int:
        """Get number of bytes available with GET RESPONSE"""
        if self.needs_get_response:
            return self.sw2 if self.sw2 != 0 else 0x100
        return 0
    
    def to_bytes(self) -> bytes:
        """Convert response to bytes"""
        return self.data + bytes([self.sw1, self.sw2])
    
    @classmethod
    def from_bytes(cls, data: bytes) -> 'APDUResponse':
        """
        Create APDU response from bytes
        
        Args:
            data: Response bytes (must be at least 2 bytes for SW)
            
        Returns:
            APDUResponse instance
        """
        if len(data) < 2:
            raise ValueError("Response too short (no status word)")
        
        response_data = data[:-2]
        sw1, sw2 = data[-2:]
        
        return cls(data=response_data, sw1=sw1, sw2=sw2)
    
    def __str__(self) -> str:
        """String representation of APDU response"""
        status_name = self.status.name if self.status != ResponseStatus.SW_UNKNOWN else f"0x{self.sw:04X}"
        
        if self.data:
            return f"APDU Response: DATA({len(self.data)})={self.data.hex().upper()}, SW={status_name}"
        else:
            return f"APDU Response: SW={status_name}"


class CommunicationError(Exception):
    """Base communication error"""
    def __init__(self, message: str, response: Optional[APDUResponse] = None, 
                 context: Optional[Dict[str, Any]] = None):
        self.message = message
        self.response = response
        self.context = context or {}
        super().__init__(self.message)


class ProtocolError(CommunicationError):
    """Protocol-specific error"""
    pass


class TimeoutError(CommunicationError):
    """Communication timeout error"""
    pass


class CardCommunicator(ABC):
    """
    Abstract base class for smart card communication
    
    Defines the interface for card communication protocols with
    proper error handling, retry logic, and logging.
    """
    
    def __init__(self, connection: CardConnection, timeout: float = 30.0):
        """
        Initialize communicator
        
        Args:
            connection: Card connection instance
            timeout: Communication timeout in seconds
        """
        self.connection = connection
        self.timeout = timeout
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        
        # Communication statistics
        self._stats = {
            'commands_sent': 0,
            'responses_received': 0,
            'errors_encountered': 0,
            'bytes_sent': 0,
            'bytes_received': 0,
            'last_command_time': None,
            'total_communication_time': 0.0
        }
        
        # Thread safety
        self._lock = threading.RLock()
    
    @abstractmethod
    def send_command(self, command: APDUCommand) -> APDUResponse:
        """
        Send APDU command to card
        
        Args:
            command: APDU command to send
            
        Returns:
            APDU response
            
        Raises:
            CommunicationError: On communication failure
        """
        pass
    
    def send_command_with_retry(self, command: APDUCommand, 
                               max_retries: int = 3,
                               retry_delay: float = 1.0) -> APDUResponse:
        """
        Send command with retry logic
        
        Args:
            command: APDU command to send
            max_retries: Maximum number of retries
            retry_delay: Delay between retries in seconds
            
        Returns:
            APDU response
            
        Raises:
            CommunicationError: If all retries fail
        """
        last_error = None
        
        for attempt in range(max_retries + 1):
            try:
                return self.send_command(command)
                
            except CommunicationError as e:
                last_error = e
                self.logger.warning(f"Command failed (attempt {attempt + 1}/{max_retries + 1}): {e}")
                
                if attempt < max_retries:
                    time.sleep(retry_delay)
                    retry_delay *= 1.5  # Exponential backoff
        
        # All retries failed
        raise CommunicationError(
            f"Command failed after {max_retries + 1} attempts: {last_error}",
            response=getattr(last_error, 'response', None),
            context={'max_retries': max_retries, 'original_error': str(last_error)}
        )
    
    def get_response(self, length: int = 0) -> APDUResponse:
        """
        Send GET RESPONSE command
        
        Args:
            length: Expected response length (0 for maximum)
            
        Returns:
            APDU response
        """
        le = length if length > 0 else 0x100
        command = APDUCommand(
            cla=CommandClass.CLA_ISO,
            ins=Instruction.INS_GET_RESPONSE,
            p1=0x00,
            p2=0x00,
            le=le
        )
        
        return self.send_command(command)
    
    def select_application(self, aid: bytes) -> APDUResponse:
        """
        Select application by AID
        
        Args:
            aid: Application Identifier
            
        Returns:
            APDU response
        """
        command = APDUCommand(
            cla=CommandClass.CLA_ISO,
            ins=Instruction.INS_SELECT,
            p1=0x04,  # Select by AID
            p2=0x00,
            data=aid
        )
        
        return self.send_command(command)
    
    def verify_pin(self, pin_reference: int, pin: bytes) -> APDUResponse:
        """
        Verify PIN
        
        Args:
            pin_reference: PIN reference number
            pin: PIN data
            
        Returns:
            APDU response
        """
        command = APDUCommand(
            cla=CommandClass.CLA_ISO,
            ins=Instruction.INS_VERIFY,
            p1=0x00,
            p2=pin_reference,
            data=pin
        )
        
        return self.send_command(command)
    
    def get_data(self, tag: int) -> APDUResponse:
        """
        Get data object
        
        Args:
            tag: Data object tag
            
        Returns:
            APDU response
        """
        command = APDUCommand(
            cla=CommandClass.CLA_ISO,
            ins=Instruction.INS_GET_DATA,
            p1=(tag >> 8) & 0xFF,
            p2=tag & 0xFF,
            le=0x00
        )
        
        return self.send_command(command)
    
    def _update_stats(self, command: APDUCommand, response: APDUResponse, 
                     duration: float) -> None:
        """Update communication statistics"""
        with self._lock:
            self._stats['commands_sent'] += 1
            self._stats['responses_received'] += 1
            self._stats['bytes_sent'] += len(command.to_bytes())
            self._stats['bytes_received'] += len(response.to_bytes())
            self._stats['last_command_time'] = datetime.now()
            self._stats['total_communication_time'] += duration
    
    def _update_error_stats(self) -> None:
        """Update error statistics"""
        with self._lock:
            self._stats['errors_encountered'] += 1
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get communication statistics"""
        with self._lock:
            stats = self._stats.copy()
            
            # Calculate additional metrics
            if stats['commands_sent'] > 0:
                stats['average_response_time'] = (
                    stats['total_communication_time'] / stats['commands_sent']
                )
                stats['error_rate'] = (
                    stats['errors_encountered'] / stats['commands_sent']
                )
            else:
                stats['average_response_time'] = 0.0
                stats['error_rate'] = 0.0
            
            return stats
    
    def reset_statistics(self) -> None:
        """Reset communication statistics"""
        with self._lock:
            self._stats = {
                'commands_sent': 0,
                'responses_received': 0,
                'errors_encountered': 0,
                'bytes_sent': 0,
                'bytes_received': 0,
                'last_command_time': None,
                'total_communication_time': 0.0
            }


class BasicCardCommunicator(CardCommunicator):
    """
    Basic card communicator using PKCS#11 mechanisms
    
    Provides a simple implementation of card communication using
    the underlying PKCS#11 interface for command/response operations.
    """
    
    def send_command(self, command: APDUCommand) -> APDUResponse:
        """
        Send APDU command using PKCS#11 interface
        
        Args:
            command: APDU command to send
            
        Returns:
            APDU response
            
        Raises:
            CommunicationError: On communication failure
        """
        start_time = time.time()
        
        try:
            if not self.connection.is_connected:
                raise CommunicationError("Not connected to card")
            
            # Convert command to bytes
            command_bytes = command.to_bytes()
            
            self.logger.debug(f"Sending command: {command}")
            
            # Send command using PKCS#11 (this is a simplified implementation)
            # In a real implementation, this would use the appropriate PKCS#11
            # mechanism for APDU communication or direct card access
            
            # For now, we simulate a response based on the command
            response = self._simulate_response(command)
            
            duration = time.time() - start_time
            self._update_stats(command, response, duration)
            
            self.logger.debug(f"Received response: {response}")
            
            return response
            
        except Exception as e:
            self._update_error_stats()
            if isinstance(e, CommunicationError):
                raise
            else:
                raise CommunicationError(f"Failed to send command: {e}")
    
    def _simulate_response(self, command: APDUCommand) -> APDUResponse:
        """
        Simulate card response (for demonstration purposes)
        
        In a real implementation, this would interface with the actual
        card through PKCS#11 or platform-specific APIs.
        """
        # Simulate different responses based on command
        if command.ins == Instruction.INS_SELECT:
            # Simulate successful application selection
            return APDUResponse(
                data=b'\x6F\x10\x84\x08\xA0\x00\x00\x00\x03\x08\x00\x00\xA5\x04\x9F\x65\x01\x00',
                sw1=0x90,
                sw2=0x00
            )
        elif command.ins == Instruction.INS_VERIFY:
            # Simulate PIN verification
            return APDUResponse(sw1=0x90, sw2=0x00)
        elif command.ins == Instruction.INS_GET_DATA:
            # Simulate data retrieval
            return APDUResponse(
                data=b'\x30\x82\x01\x22\x30\x0D\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01\x01\x05\x00',
                sw1=0x90,
                sw2=0x00
            )
        else:
            # Default success response
            return APDUResponse(sw1=0x90, sw2=0x00)


# Utility functions for common operations

def parse_tlv(data: bytes) -> List[Tuple[int, bytes]]:
    """
    Parse TLV (Tag-Length-Value) encoded data
    
    Args:
        data: TLV encoded data
        
    Returns:
        List of (tag, value) tuples
    """
    tlv_objects = []
    offset = 0
    
    while offset < len(data):
        if offset >= len(data):
            break
        
        # Parse tag
        tag = data[offset]
        offset += 1
        
        # Extended tag
        if (tag & 0x1F) == 0x1F:
            tag = (tag << 8) | data[offset]
            offset += 1
        
        # Parse length
        if offset >= len(data):
            break
            
        length = data[offset]
        offset += 1
        
        # Extended length
        if length & 0x80:
            num_octets = length & 0x7F
            if num_octets > 0:
                length = 0
                for _ in range(num_octets):
                    if offset >= len(data):
                        break
                    length = (length << 8) | data[offset]
                    offset += 1
        
        # Parse value
        if offset + length > len(data):
            break
            
        value = data[offset:offset + length]
        offset += length
        
        tlv_objects.append((tag, value))
    
    return tlv_objects


def build_tlv(tag: int, value: bytes) -> bytes:
    """
    Build TLV encoded data
    
    Args:
        tag: Tag value
        value: Value data
        
    Returns:
        TLV encoded bytes
    """
    result = bytearray()
    
    # Encode tag
    if tag <= 0xFF:
        result.append(tag)
    else:
        result.extend([(tag >> 8) & 0xFF, tag & 0xFF])
    
    # Encode length
    length = len(value)
    if length < 0x80:
        result.append(length)
    else:
        # Extended length encoding
        length_bytes = []
        temp_length = length
        while temp_length > 0:
            length_bytes.insert(0, temp_length & 0xFF)
            temp_length >>= 8
        
        result.append(0x80 | len(length_bytes))
        result.extend(length_bytes)
    
    # Add value
    result.extend(value)
    
    return bytes(result)