#!/usr/bin/env python3
"""
Unit Tests for PKCS#11 Communication

Tests the smart card communication protocols including APDU command/response
handling, communication error handling, and protocol management.

Author: AI Agent - PKCS#11 Infrastructure Implementation
Date: 2025-07-27
Classification: UNCLASSIFIED
"""

import unittest
import os
import sys
from unittest.mock import Mock, patch
import time

# Import the modules to test
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from communication import (
        APDUCommand, APDUResponse, CardCommunicator, BasicCardCommunicator,
        CommunicationError, ProtocolError, TimeoutError,
        ResponseStatus, CommandClass, Instruction,
        parse_tlv, build_tlv
    )
    from card_manager import CardConnection, CardInfo, CardStatus
except ImportError:
    # If direct import fails, try relative import
    from ..communication import (
        APDUCommand, APDUResponse, CardCommunicator, BasicCardCommunicator,
        CommunicationError, ProtocolError, TimeoutError,
        ResponseStatus, CommandClass, Instruction,
        parse_tlv, build_tlv
    )
    from ..card_manager import CardConnection, CardInfo, CardStatus


class TestAPDUCommand(unittest.TestCase):
    """Test cases for APDU command handling"""
    
    def test_apdu_command_creation(self):
        """Test APDU command creation with valid parameters"""
        command = APDUCommand(
            cla=0x00,
            ins=0xA4,
            p1=0x04,
            p2=0x00,
            data=b'\xA0\x00\x00\x00\x03\x08\x00\x00',
            le=0x00
        )
        
        self.assertEqual(command.cla, 0x00)
        self.assertEqual(command.ins, 0xA4)
        self.assertEqual(command.p1, 0x04)
        self.assertEqual(command.p2, 0x00)
        self.assertEqual(command.data, b'\xA0\x00\x00\x00\x03\x08\x00\x00')
        self.assertEqual(command.le, 0x00)
    
    def test_apdu_command_validation(self):
        """Test APDU command parameter validation"""
        # Test invalid CLA
        with self.assertRaises(ValueError):
            APDUCommand(cla=256, ins=0xA4, p1=0x04, p2=0x00)
        
        # Test invalid INS
        with self.assertRaises(ValueError):
            APDUCommand(cla=0x00, ins=-1, p1=0x04, p2=0x00)
        
        # Test invalid P1
        with self.assertRaises(ValueError):
            APDUCommand(cla=0x00, ins=0xA4, p1=256, p2=0x00)
        
        # Test invalid P2
        with self.assertRaises(ValueError):
            APDUCommand(cla=0x00, ins=0xA4, p1=0x04, p2=-1)
        
        # Test data too long
        with self.assertRaises(ValueError):
            APDUCommand(cla=0x00, ins=0xA4, p1=0x04, p2=0x00, data=b'\x00' * 0x10001)
        
        # Test invalid Le
        with self.assertRaises(ValueError):
            APDUCommand(cla=0x00, ins=0xA4, p1=0x04, p2=0x00, le=0x10001)
    
    def test_apdu_command_to_bytes_case1(self):
        """Test APDU command Case 1: No data, no Le"""
        command = APDUCommand(cla=0x00, ins=0xA4, p1=0x04, p2=0x00)
        expected = b'\x00\xA4\x04\x00'
        
        self.assertEqual(command.to_bytes(), expected)
    
    def test_apdu_command_to_bytes_case2(self):
        """Test APDU command Case 2: No data, Le present"""
        command = APDUCommand(cla=0x00, ins=0xA4, p1=0x04, p2=0x00, le=0x10)
        expected = b'\x00\xA4\x04\x00\x10'
        
        self.assertEqual(command.to_bytes(), expected)
    
    def test_apdu_command_to_bytes_case3(self):
        """Test APDU command Case 3: Data present, no Le"""
        command = APDUCommand(
            cla=0x00, ins=0xA4, p1=0x04, p2=0x00,
            data=b'\xA0\x00\x00\x00\x03\x08\x00\x00'
        )
        expected = b'\x00\xA4\x04\x00\x08\xA0\x00\x00\x00\x03\x08\x00\x00'
        
        self.assertEqual(command.to_bytes(), expected)
    
    def test_apdu_command_to_bytes_case4(self):
        """Test APDU command Case 4: Data and Le present"""
        command = APDUCommand(
            cla=0x00, ins=0xA4, p1=0x04, p2=0x00,
            data=b'\xA0\x00\x00\x00\x03\x08\x00\x00',
            le=0x10
        )
        expected = b'\x00\xA4\x04\x00\x08\xA0\x00\x00\x00\x03\x08\x00\x00\x10'
        
        self.assertEqual(command.to_bytes(), expected)
    
    def test_apdu_command_from_bytes(self):
        """Test APDU command parsing from bytes"""
        # Case 1: No data, no Le
        data = b'\x00\xA4\x04\x00'
        command = APDUCommand.from_bytes(data)
        
        self.assertEqual(command.cla, 0x00)
        self.assertEqual(command.ins, 0xA4)
        self.assertEqual(command.p1, 0x04)
        self.assertEqual(command.p2, 0x00)
        self.assertEqual(command.data, b'')
        self.assertIsNone(command.le)
    
    def test_apdu_command_from_bytes_with_data(self):
        """Test APDU command parsing from bytes with data"""
        # Case 3: Data present, no Le
        data = b'\x00\xA4\x04\x00\x08\xA0\x00\x00\x00\x03\x08\x00\x00'
        command = APDUCommand.from_bytes(data)
        
        self.assertEqual(command.cla, 0x00)
        self.assertEqual(command.ins, 0xA4)
        self.assertEqual(command.data, b'\xA0\x00\x00\x00\x03\x08\x00\x00')
        self.assertIsNone(command.le)
    
    def test_apdu_command_string_representation(self):
        """Test APDU command string representation"""
        command = APDUCommand(
            cla=0x00, ins=0xA4, p1=0x04, p2=0x00,
            data=b'\xA0\x00',
            le=0x10
        )
        
        str_repr = str(command)
        self.assertIn("CLA=00", str_repr)
        self.assertIn("INS=A4", str_repr)
        self.assertIn("P1=04", str_repr)
        self.assertIn("P2=00", str_repr)
        self.assertIn("DATA(2)=A000", str_repr)
        self.assertIn("Le=10", str_repr)


class TestAPDUResponse(unittest.TestCase):
    """Test cases for APDU response handling"""
    
    def test_apdu_response_creation(self):
        """Test APDU response creation"""
        response = APDUResponse(
            data=b'\x6F\x10\x84\x08',
            sw1=0x90,
            sw2=0x00
        )
        
        self.assertEqual(response.data, b'\x6F\x10\x84\x08')
        self.assertEqual(response.sw1, 0x90)
        self.assertEqual(response.sw2, 0x00)
        self.assertEqual(response.sw, 0x9000)
    
    def test_apdu_response_validation(self):
        """Test APDU response parameter validation"""
        # Test invalid SW1
        with self.assertRaises(ValueError):
            APDUResponse(sw1=256, sw2=0x00)
        
        # Test invalid SW2
        with self.assertRaises(ValueError):
            APDUResponse(sw1=0x90, sw2=-1)
    
    def test_apdu_response_status_properties(self):
        """Test APDU response status properties"""
        # Success response
        response = APDUResponse(sw1=0x90, sw2=0x00)
        self.assertTrue(response.is_success)
        self.assertFalse(response.is_warning)
        self.assertFalse(response.is_error)
        self.assertEqual(response.status, ResponseStatus.SW_SUCCESS)
        
        # Warning response
        response = APDUResponse(sw1=0x62, sw2=0x00)
        self.assertFalse(response.is_success)
        self.assertTrue(response.is_warning)
        self.assertFalse(response.is_error)
        
        # Error response
        response = APDUResponse(sw1=0x6A, sw2=0x82)
        self.assertFalse(response.is_success)
        self.assertFalse(response.is_warning)
        self.assertTrue(response.is_error)
    
    def test_apdu_response_get_response_needed(self):
        """Test GET RESPONSE detection"""
        # Needs GET RESPONSE
        response = APDUResponse(sw1=0x61, sw2=0x10)
        self.assertTrue(response.needs_get_response)
        self.assertEqual(response.available_bytes, 0x10)
        
        # Doesn't need GET RESPONSE
        response = APDUResponse(sw1=0x90, sw2=0x00)
        self.assertFalse(response.needs_get_response)
        self.assertEqual(response.available_bytes, 0)
    
    def test_apdu_response_from_bytes(self):
        """Test APDU response parsing from bytes"""
        data = b'\x6F\x10\x84\x08\x90\x00'
        response = APDUResponse.from_bytes(data)
        
        self.assertEqual(response.data, b'\x6F\x10\x84\x08')
        self.assertEqual(response.sw1, 0x90)
        self.assertEqual(response.sw2, 0x00)
    
    def test_apdu_response_to_bytes(self):
        """Test APDU response conversion to bytes"""
        response = APDUResponse(
            data=b'\x6F\x10\x84\x08',
            sw1=0x90,
            sw2=0x00
        )
        
        expected = b'\x6F\x10\x84\x08\x90\x00'
        self.assertEqual(response.to_bytes(), expected)
    
    def test_apdu_response_string_representation(self):
        """Test APDU response string representation"""
        response = APDUResponse(
            data=b'\x6F\x10',
            sw1=0x90,
            sw2=0x00
        )
        
        str_repr = str(response)
        self.assertIn("DATA(2)=6F10", str_repr)
        self.assertIn("SW=SW_SUCCESS", str_repr)


class TestCommunicationErrors(unittest.TestCase):
    """Test cases for communication error classes"""
    
    def test_communication_error_creation(self):
        """Test CommunicationError creation"""
        response = APDUResponse(sw1=0x6A, sw2=0x82)
        context = {"operation": "test"}
        
        error = CommunicationError(
            "Test error",
            response=response,
            context=context
        )
        
        self.assertEqual(error.message, "Test error")
        self.assertEqual(error.response, response)
        self.assertEqual(error.context["operation"], "test")
    
    def test_protocol_error_inheritance(self):
        """Test ProtocolError inheritance"""
        error = ProtocolError("Protocol error")
        
        self.assertIsInstance(error, CommunicationError)
        self.assertEqual(error.message, "Protocol error")
    
    def test_timeout_error_inheritance(self):
        """Test TimeoutError inheritance"""
        error = TimeoutError("Timeout error")
        
        self.assertIsInstance(error, CommunicationError)
        self.assertEqual(error.message, "Timeout error")


class MockCardConnection:
    """Mock card connection for testing"""
    
    def __init__(self, connected=True):
        self._connected = connected
        self.card_info = CardInfo(
            slot_id=1,
            card_id="test_card",
            label="Test Card",
            manufacturer="Test Manufacturer",
            model="Test Model",
            serial_number="12345",
            status=CardStatus.CONNECTED
        )
    
    @property
    def is_connected(self):
        return self._connected


class TestBasicCardCommunicator(unittest.TestCase):
    """Test cases for basic card communicator"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.connection = MockCardConnection()
        self.communicator = BasicCardCommunicator(self.connection)
    
    def test_communicator_initialization(self):
        """Test communicator initialization"""
        self.assertEqual(self.communicator.connection, self.connection)
        self.assertEqual(self.communicator.timeout, 30.0)
        self.assertIsNotNone(self.communicator._stats)
    
    def test_send_command_success(self):
        """Test successful command sending"""
        command = APDUCommand(
            cla=CommandClass.CLA_ISO,
            ins=Instruction.INS_SELECT,
            p1=0x04,
            p2=0x00,
            data=b'\xA0\x00\x00\x00\x03\x08\x00\x00'
        )
        
        response = self.communicator.send_command(command)
        
        self.assertIsInstance(response, APDUResponse)
        self.assertTrue(response.is_success)
    
    def test_send_command_not_connected(self):
        """Test command sending when not connected"""
        self.connection._connected = False
        
        command = APDUCommand(cla=0x00, ins=0xA4, p1=0x04, p2=0x00)
        
        with self.assertRaises(CommunicationError):
            self.communicator.send_command(command)
    
    def test_send_command_with_retry(self):
        """Test command sending with retry logic"""
        command = APDUCommand(cla=0x00, ins=0xA4, p1=0x04, p2=0x00)
        
        # Mock send_command to fail first time, succeed second time
        original_send = self.communicator.send_command
        call_count = [0]
        
        def mock_send(cmd):
            call_count[0] += 1
            if call_count[0] == 1:
                raise CommunicationError("Simulated failure")
            return original_send(cmd)
        
        self.communicator.send_command = mock_send
        
        # Should succeed on retry
        response = self.communicator.send_command_with_retry(command, max_retries=2)
        
        self.assertIsInstance(response, APDUResponse)
        self.assertEqual(call_count[0], 2)  # Called twice
    
    def test_get_response(self):
        """Test GET RESPONSE command"""
        response = self.communicator.get_response(length=16)
        
        self.assertIsInstance(response, APDUResponse)
        self.assertTrue(response.is_success)
    
    def test_select_application(self):
        """Test SELECT application command"""
        aid = b'\xA0\x00\x00\x00\x03\x08\x00\x00'
        response = self.communicator.select_application(aid)
        
        self.assertIsInstance(response, APDUResponse)
        self.assertTrue(response.is_success)
    
    def test_verify_pin(self):
        """Test VERIFY PIN command"""
        pin = b'123456\xFF\xFF'  # Padded PIN
        response = self.communicator.verify_pin(pin_reference=0x80, pin=pin)
        
        self.assertIsInstance(response, APDUResponse)
        self.assertTrue(response.is_success)
    
    def test_get_data(self):
        """Test GET DATA command"""
        response = self.communicator.get_data(tag=0x5C00)
        
        self.assertIsInstance(response, APDUResponse)
        self.assertTrue(response.is_success)
    
    def test_statistics_tracking(self):
        """Test communication statistics tracking"""
        command = APDUCommand(cla=0x00, ins=0xA4, p1=0x04, p2=0x00)
        
        # Send a command
        self.communicator.send_command(command)
        
        stats = self.communicator.get_statistics()
        
        self.assertEqual(stats['commands_sent'], 1)
        self.assertEqual(stats['responses_received'], 1)
        self.assertEqual(stats['errors_encountered'], 0)
        self.assertGreater(stats['bytes_sent'], 0)
        self.assertGreater(stats['bytes_received'], 0)
        self.assertIsNotNone(stats['last_command_time'])
    
    def test_statistics_reset(self):
        """Test statistics reset functionality"""
        command = APDUCommand(cla=0x00, ins=0xA4, p1=0x04, p2=0x00)
        
        # Send a command
        self.communicator.send_command(command)
        
        # Reset statistics
        self.communicator.reset_statistics()
        
        stats = self.communicator.get_statistics()
        
        self.assertEqual(stats['commands_sent'], 0)
        self.assertEqual(stats['responses_received'], 0)
        self.assertEqual(stats['errors_encountered'], 0)


class TestTLVUtilities(unittest.TestCase):
    """Test cases for TLV utility functions"""
    
    def test_build_tlv_simple(self):
        """Test building simple TLV"""
        tag = 0x5C
        value = b'\x01\x02\x03'
        
        tlv_data = build_tlv(tag, value)
        expected = b'\x5C\x03\x01\x02\x03'
        
        self.assertEqual(tlv_data, expected)
    
    def test_build_tlv_extended_length(self):
        """Test building TLV with extended length"""
        tag = 0x5C
        value = b'\x00' * 200  # Long value
        
        tlv_data = build_tlv(tag, value)
        
        # Should have extended length encoding
        self.assertEqual(tlv_data[0], 0x5C)  # Tag
        self.assertEqual(tlv_data[1], 0x81)  # Extended length indicator
        self.assertEqual(tlv_data[2], 200)   # Length value
        self.assertEqual(len(tlv_data), 203)  # Tag + length encoding + data
    
    def test_build_tlv_two_byte_tag(self):
        """Test building TLV with two-byte tag"""
        tag = 0x5F2A
        value = b'\x01\x02'
        
        tlv_data = build_tlv(tag, value)
        expected = b'\x5F\x2A\x02\x01\x02'
        
        self.assertEqual(tlv_data, expected)
    
    def test_parse_tlv_simple(self):
        """Test parsing simple TLV"""
        tlv_data = b'\x5C\x03\x01\x02\x03'
        
        tlv_objects = parse_tlv(tlv_data)
        
        self.assertEqual(len(tlv_objects), 1)
        tag, value = tlv_objects[0]
        self.assertEqual(tag, 0x5C)
        self.assertEqual(value, b'\x01\x02\x03')
    
    def test_parse_tlv_multiple(self):
        """Test parsing multiple TLV objects"""
        tlv_data = b'\x5C\x02\x01\x02\x5D\x03\x03\x04\x05'
        
        tlv_objects = parse_tlv(tlv_data)
        
        self.assertEqual(len(tlv_objects), 2)
        
        tag1, value1 = tlv_objects[0]
        self.assertEqual(tag1, 0x5C)
        self.assertEqual(value1, b'\x01\x02')
        
        tag2, value2 = tlv_objects[1]
        self.assertEqual(tag2, 0x5D)
        self.assertEqual(value2, b'\x03\x04\x05')
    
    def test_parse_tlv_extended_length(self):
        """Test parsing TLV with extended length"""
        # Create TLV with 200-byte value
        value = b'\x00' * 200
        tlv_data = b'\x5C\x81\xC8' + value
        
        tlv_objects = parse_tlv(tlv_data)
        
        self.assertEqual(len(tlv_objects), 1)
        tag, parsed_value = tlv_objects[0]
        self.assertEqual(tag, 0x5C)
        self.assertEqual(len(parsed_value), 200)
        self.assertEqual(parsed_value, value)
    
    def test_tlv_roundtrip(self):
        """Test TLV build/parse roundtrip"""
        original_tag = 0x5C
        original_value = b'\x01\x02\x03\x04\x05'
        
        # Build TLV
        tlv_data = build_tlv(original_tag, original_value)
        
        # Parse TLV
        tlv_objects = parse_tlv(tlv_data)
        
        # Verify roundtrip
        self.assertEqual(len(tlv_objects), 1)
        parsed_tag, parsed_value = tlv_objects[0]
        self.assertEqual(parsed_tag, original_tag)
        self.assertEqual(parsed_value, original_value)


if __name__ == '__main__':
    # Configure logging for tests
    import logging
    logging.basicConfig(level=logging.DEBUG)
    
    # Run tests
    unittest.main(verbosity=2)