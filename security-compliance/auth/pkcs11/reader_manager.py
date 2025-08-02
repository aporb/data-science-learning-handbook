#!/usr/bin/env python3
"""
Smart Card Reader Management

Provides detection, enumeration, and monitoring of smart card readers.
This module handles reader discovery, status monitoring, and event handling
for CAC/PIV smart card operations.

Author: AI Agent - PKCS#11 Infrastructure Implementation
Date: 2025-07-27
Classification: UNCLASSIFIED
"""

import threading
import time
import logging
from typing import Optional, Dict, List, Callable, Any, Set
from dataclasses import dataclass, field
from enum import Enum, auto
from datetime import datetime, timedelta
import queue
from concurrent.futures import ThreadPoolExecutor, Future

from .pkcs11_wrapper import PKCS11Wrapper, PKCS11Error, SlotInfo, TokenInfo


class ReaderStatus(Enum):
    """Smart card reader status"""
    UNKNOWN = auto()
    AVAILABLE = auto()
    IN_USE = auto()
    ERROR = auto()
    DISCONNECTED = auto()
    CARD_PRESENT = auto()
    CARD_ABSENT = auto()


class ReaderEventType(Enum):
    """Reader event types"""
    READER_CONNECTED = auto()
    READER_DISCONNECTED = auto()
    CARD_INSERTED = auto()
    CARD_REMOVED = auto()
    READER_ERROR = auto()
    STATUS_CHANGED = auto()


@dataclass
class ReaderInfo:
    """Information about a smart card reader"""
    slot_id: int
    name: str
    description: str
    manufacturer: str
    status: ReaderStatus
    card_present: bool = False
    last_seen: datetime = field(default_factory=datetime.now)
    error_count: int = 0
    last_error: Optional[str] = None
    capabilities: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        """Post-initialization processing"""
        if self.card_present and self.status == ReaderStatus.AVAILABLE:
            self.status = ReaderStatus.CARD_PRESENT


@dataclass
class ReaderEvent:
    """Reader event information"""
    event_type: ReaderEventType
    reader_info: ReaderInfo
    timestamp: datetime = field(default_factory=datetime.now)
    details: Optional[Dict[str, Any]] = None
    
    def __str__(self) -> str:
        return f"{self.event_type.name}: {self.reader_info.name} at {self.timestamp}"


class ReaderEventHandler:
    """Base class for reader event handlers"""
    
    def on_reader_connected(self, event: ReaderEvent) -> None:
        """Called when a reader is connected"""
        pass
    
    def on_reader_disconnected(self, event: ReaderEvent) -> None:
        """Called when a reader is disconnected"""
        pass
    
    def on_card_inserted(self, event: ReaderEvent) -> None:
        """Called when a card is inserted"""
        pass
    
    def on_card_removed(self, event: ReaderEvent) -> None:
        """Called when a card is removed"""
        pass
    
    def on_reader_error(self, event: ReaderEvent) -> None:
        """Called when a reader error occurs"""
        pass
    
    def on_status_changed(self, event: ReaderEvent) -> None:
        """Called when reader status changes"""
        pass


class SmartCardReaderManager:
    """
    Smart card reader manager for detection, monitoring, and event handling
    
    This class provides comprehensive reader management including:
    - Automatic reader detection and enumeration
    - Real-time status monitoring
    - Event-driven notifications
    - Thread-safe operations
    - Error handling and recovery
    """
    
    def __init__(self, pkcs11_wrapper: Optional[PKCS11Wrapper] = None, 
                 monitoring_interval: float = 2.0):
        """
        Initialize reader manager
        
        Args:
            pkcs11_wrapper: PKCS#11 wrapper instance, auto-created if None
            monitoring_interval: Reader monitoring interval in seconds
        """
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        self._pkcs11 = pkcs11_wrapper or PKCS11Wrapper()
        self._monitoring_interval = monitoring_interval
        
        # Thread safety
        self._lock = threading.RLock()
        
        # Reader tracking
        self._readers: Dict[int, ReaderInfo] = {}
        self._previous_readers: Set[int] = set()
        
        # Event handling
        self._event_handlers: List[ReaderEventHandler] = []
        self._event_queue = queue.Queue()
        self._event_thread: Optional[threading.Thread] = None
        
        # Monitoring
        self._monitoring = False
        self._monitor_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        
        # Thread pool for async operations
        self._executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="reader_mgr")
        
        # Statistics
        self._stats = {
            'readers_detected': 0,
            'cards_detected': 0,
            'events_processed': 0,
            'errors_encountered': 0,
            'last_scan': None
        }
        
        self.logger.info("Smart card reader manager initialized")
    
    def start_monitoring(self) -> None:
        """Start reader monitoring"""
        with self._lock:
            if self._monitoring:
                self.logger.warning("Reader monitoring already started")
                return
            
            self._monitoring = True
            self._stop_event.clear()
            
            # Start event processing thread
            self._event_thread = threading.Thread(
                target=self._process_events,
                name="reader_events",
                daemon=True
            )
            self._event_thread.start()
            
            # Start monitoring thread
            self._monitor_thread = threading.Thread(
                target=self._monitor_readers,
                name="reader_monitor",
                daemon=True
            )
            self._monitor_thread.start()
            
            self.logger.info("Started reader monitoring")
    
    def stop_monitoring(self) -> None:
        """Stop reader monitoring"""
        with self._lock:
            if not self._monitoring:
                return
            
            self._monitoring = False
            self._stop_event.set()
            
            # Wait for threads to finish
            if self._monitor_thread and self._monitor_thread.is_alive():
                self._monitor_thread.join(timeout=5.0)
            
            if self._event_thread and self._event_thread.is_alive():
                # Send sentinel to stop event processing
                self._event_queue.put(None)
                self._event_thread.join(timeout=5.0)
            
            self.logger.info("Stopped reader monitoring")
    
    def __del__(self):
        """Destructor - ensure monitoring is stopped"""
        try:
            self.stop_monitoring()
            if self._executor:
                self._executor.shutdown(wait=False)
        except:
            pass  # Ignore errors during destruction
    
    def detect_readers(self, force_refresh: bool = False) -> List[ReaderInfo]:
        """
        Detect available smart card readers
        
        Args:
            force_refresh: Force refresh of reader cache
            
        Returns:
            List of detected readers
        """
        try:
            # Get all slots (including those without tokens)
            all_slots = self._pkcs11.get_slot_list(token_present=False)
            
            with self._lock:
                current_readers = {}
                
                for slot_id in all_slots:
                    try:
                        # Get slot information
                        slot_info = self._pkcs11.get_slot_info(slot_id, use_cache=not force_refresh)
                        
                        # Determine reader status
                        status = self._determine_reader_status(slot_info)
                        
                        # Create reader info
                        reader_info = ReaderInfo(
                            slot_id=slot_id,
                            name=slot_info.description,
                            description=slot_info.description,
                            manufacturer=slot_info.manufacturer_id,
                            status=status,
                            card_present=slot_info.token_present,
                            capabilities={
                                'removable_device': slot_info.removable_device,
                                'hardware_slot': slot_info.hardware_slot,
                                'hardware_version': slot_info.hardware_version,
                                'firmware_version': slot_info.firmware_version
                            }
                        )
                        
                        # If we have token info, enrich the reader info
                        if slot_info.token_present:
                            try:
                                token_info = self._pkcs11.get_token_info(slot_id, use_cache=not force_refresh)
                                reader_info.capabilities.update({
                                    'token_label': token_info.label,
                                    'token_manufacturer': token_info.manufacturer_id,
                                    'token_model': token_info.model,
                                    'token_serial': token_info.serial_number
                                })
                            except Exception as e:
                                self.logger.debug(f"Could not get token info for slot {slot_id}: {e}")
                        
                        current_readers[slot_id] = reader_info
                        
                    except Exception as e:
                        self.logger.warning(f"Error processing slot {slot_id}: {e}")
                        # Create error reader entry
                        current_readers[slot_id] = ReaderInfo(
                            slot_id=slot_id,
                            name=f"Slot {slot_id}",
                            description="Error reading slot information",
                            manufacturer="Unknown",
                            status=ReaderStatus.ERROR,
                            last_error=str(e)
                        )
                
                # Update stats
                self._stats['readers_detected'] = len(current_readers)
                self._stats['cards_detected'] = sum(1 for r in current_readers.values() if r.card_present)
                self._stats['last_scan'] = datetime.now()
                
                # Store current readers
                old_readers = self._readers.copy()
                self._readers = current_readers
                
                # Generate events for changes
                if self._monitoring:
                    self._generate_change_events(old_readers, current_readers)
                
                self.logger.debug(f"Detected {len(current_readers)} readers, "
                                f"{self._stats['cards_detected']} with cards")
                
                return list(current_readers.values())
                
        except Exception as e:
            self.logger.error(f"Error detecting readers: {e}")
            self._stats['errors_encountered'] += 1
            raise PKCS11Error(f"Failed to detect readers: {e}")
    
    def _determine_reader_status(self, slot_info: SlotInfo) -> ReaderStatus:
        """Determine reader status from slot info"""
        if slot_info.token_present:
            return ReaderStatus.CARD_PRESENT
        else:
            return ReaderStatus.CARD_ABSENT
    
    def _generate_change_events(self, old_readers: Dict[int, ReaderInfo], 
                              new_readers: Dict[int, ReaderInfo]) -> None:
        """Generate events for reader changes"""
        try:
            old_slots = set(old_readers.keys())
            new_slots = set(new_readers.keys())
            
            # Reader connected
            for slot_id in new_slots - old_slots:
                event = ReaderEvent(
                    event_type=ReaderEventType.READER_CONNECTED,
                    reader_info=new_readers[slot_id]
                )
                self._queue_event(event)
            
            # Reader disconnected
            for slot_id in old_slots - new_slots:
                event = ReaderEvent(
                    event_type=ReaderEventType.READER_DISCONNECTED,
                    reader_info=old_readers[slot_id]
                )
                self._queue_event(event)
            
            # Status changes for existing readers
            for slot_id in old_slots & new_slots:
                old_reader = old_readers[slot_id]
                new_reader = new_readers[slot_id]
                
                # Card insertion/removal
                if old_reader.card_present != new_reader.card_present:
                    if new_reader.card_present:
                        event = ReaderEvent(
                            event_type=ReaderEventType.CARD_INSERTED,
                            reader_info=new_reader
                        )
                    else:
                        event = ReaderEvent(
                            event_type=ReaderEventType.CARD_REMOVED,
                            reader_info=new_reader
                        )
                    self._queue_event(event)
                
                # Status changes
                if old_reader.status != new_reader.status:
                    event = ReaderEvent(
                        event_type=ReaderEventType.STATUS_CHANGED,
                        reader_info=new_reader,
                        details={
                            'old_status': old_reader.status,
                            'new_status': new_reader.status
                        }
                    )
                    self._queue_event(event)
                
                # Error conditions
                if (new_reader.status == ReaderStatus.ERROR and 
                    old_reader.status != ReaderStatus.ERROR):
                    event = ReaderEvent(
                        event_type=ReaderEventType.READER_ERROR,
                        reader_info=new_reader,
                        details={'error': new_reader.last_error}
                    )
                    self._queue_event(event)
                    
        except Exception as e:
            self.logger.error(f"Error generating change events: {e}")
    
    def _queue_event(self, event: ReaderEvent) -> None:
        """Queue an event for processing"""
        try:
            self._event_queue.put(event, timeout=1.0)
        except queue.Full:
            self.logger.warning("Event queue full, dropping event")
    
    def _process_events(self) -> None:
        """Process queued events"""
        self.logger.debug("Started event processing thread")
        
        while self._monitoring:
            try:
                # Get event with timeout
                event = self._event_queue.get(timeout=1.0)
                
                # Sentinel to stop processing
                if event is None:
                    break
                
                # Process event
                self._dispatch_event(event)
                self._stats['events_processed'] += 1
                
            except queue.Empty:
                continue  # Timeout, check if still monitoring
            except Exception as e:
                self.logger.error(f"Error processing event: {e}")
        
        self.logger.debug("Stopped event processing thread")
    
    def _dispatch_event(self, event: ReaderEvent) -> None:
        """Dispatch event to registered handlers"""
        for handler in self._event_handlers:
            try:
                if event.event_type == ReaderEventType.READER_CONNECTED:
                    handler.on_reader_connected(event)
                elif event.event_type == ReaderEventType.READER_DISCONNECTED:
                    handler.on_reader_disconnected(event)
                elif event.event_type == ReaderEventType.CARD_INSERTED:
                    handler.on_card_inserted(event)
                elif event.event_type == ReaderEventType.CARD_REMOVED:
                    handler.on_card_removed(event)
                elif event.event_type == ReaderEventType.READER_ERROR:
                    handler.on_reader_error(event)
                elif event.event_type == ReaderEventType.STATUS_CHANGED:
                    handler.on_status_changed(event)
                    
            except Exception as e:
                self.logger.error(f"Error in event handler {handler.__class__.__name__}: {e}")
    
    def _monitor_readers(self) -> None:
        """Monitor readers for changes"""
        self.logger.debug("Started reader monitoring thread")
        
        while self._monitoring and not self._stop_event.is_set():
            try:
                # Detect readers
                self.detect_readers()
                
                # Wait for next scan
                if self._stop_event.wait(self._monitoring_interval):
                    break  # Stop event was set
                    
            except Exception as e:
                self.logger.error(f"Error in reader monitoring: {e}")
                self._stats['errors_encountered'] += 1
                
                # Wait before retrying
                if self._stop_event.wait(min(self._monitoring_interval, 10.0)):
                    break
        
        self.logger.debug("Stopped reader monitoring thread")
    
    def add_event_handler(self, handler: ReaderEventHandler) -> None:
        """Add an event handler"""
        with self._lock:
            if handler not in self._event_handlers:
                self._event_handlers.append(handler)
                self.logger.debug(f"Added event handler: {handler.__class__.__name__}")
    
    def remove_event_handler(self, handler: ReaderEventHandler) -> None:
        """Remove an event handler"""
        with self._lock:
            if handler in self._event_handlers:
                self._event_handlers.remove(handler)
                self.logger.debug(f"Removed event handler: {handler.__class__.__name__}")
    
    def get_reader(self, slot_id: int) -> Optional[ReaderInfo]:
        """Get reader information by slot ID"""
        with self._lock:
            return self._readers.get(slot_id)
    
    def get_readers(self, status_filter: Optional[ReaderStatus] = None,
                   card_present_only: bool = False) -> List[ReaderInfo]:
        """
        Get readers matching criteria
        
        Args:
            status_filter: Filter by reader status
            card_present_only: Only return readers with cards present
            
        Returns:
            List of matching readers
        """
        with self._lock:
            readers = list(self._readers.values())
            
            if status_filter:
                readers = [r for r in readers if r.status == status_filter]
            
            if card_present_only:
                readers = [r for r in readers if r.card_present]
            
            return readers
    
    def get_available_readers(self) -> List[ReaderInfo]:
        """Get readers that are available for use"""
        return self.get_readers(status_filter=None, card_present_only=False)
    
    def get_readers_with_cards(self) -> List[ReaderInfo]:
        """Get readers with cards present"""
        return self.get_readers(card_present_only=True)
    
    def refresh_reader(self, slot_id: int) -> Optional[ReaderInfo]:
        """
        Refresh information for a specific reader
        
        Args:
            slot_id: Slot ID to refresh
            
        Returns:
            Updated reader info or None if not found
        """
        try:
            # Force refresh for this specific slot
            slot_info = self._pkcs11.get_slot_info(slot_id, use_cache=False)
            
            status = self._determine_reader_status(slot_info)
            
            reader_info = ReaderInfo(
                slot_id=slot_id,
                name=slot_info.description,
                description=slot_info.description,
                manufacturer=slot_info.manufacturer_id,
                status=status,
                card_present=slot_info.token_present
            )
            
            with self._lock:
                old_reader = self._readers.get(slot_id)
                self._readers[slot_id] = reader_info
                
                # Generate events if monitoring
                if self._monitoring and old_reader:
                    if old_reader.card_present != reader_info.card_present:
                        event_type = (ReaderEventType.CARD_INSERTED if reader_info.card_present 
                                    else ReaderEventType.CARD_REMOVED)
                        event = ReaderEvent(event_type=event_type, reader_info=reader_info)
                        self._queue_event(event)
            
            return reader_info
            
        except Exception as e:
            self.logger.error(f"Error refreshing reader {slot_id}: {e}")
            return None
    
    def wait_for_card(self, slot_id: Optional[int] = None, timeout: float = 30.0) -> Optional[ReaderInfo]:
        """
        Wait for a card to be inserted
        
        Args:
            slot_id: Specific slot to wait for, any slot if None
            timeout: Maximum time to wait in seconds
            
        Returns:
            Reader info with card, None if timeout
        """
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            readers = self.get_readers_with_cards()
            
            if slot_id is not None:
                # Wait for specific slot
                for reader in readers:
                    if reader.slot_id == slot_id:
                        return reader
            else:
                # Wait for any slot
                if readers:
                    return readers[0]
            
            # Wait before checking again
            time.sleep(0.5)
        
        return None
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get reader manager statistics"""
        with self._lock:
            stats = self._stats.copy()
            stats.update({
                'active_readers': len(self._readers),
                'monitoring_active': self._monitoring,
                'event_handlers': len(self._event_handlers),
                'event_queue_size': self._event_queue.qsize()
            })
            return stats
    
    @property
    def is_monitoring(self) -> bool:
        """Check if monitoring is active"""
        return self._monitoring
    
    @property
    def reader_count(self) -> int:
        """Get number of detected readers"""
        with self._lock:
            return len(self._readers)