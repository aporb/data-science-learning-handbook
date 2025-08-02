#!/usr/bin/env python3
"""
Smart Card Lifecycle Management

Handles card connection, disconnection, and lifecycle management for 
CAC/PIV smart cards. This module provides thread-safe card operations,
session management, and connection pooling.

Author: AI Agent - PKCS#11 Infrastructure Implementation
Date: 2025-07-27
Classification: UNCLASSIFIED
"""

import threading
import time
import logging
from typing import Optional, Dict, List, Any, Set, Callable
from dataclasses import dataclass, field
from enum import Enum, auto
from datetime import datetime, timedelta
from contextlib import contextmanager
import weakref
from concurrent.futures import ThreadPoolExecutor, Future

from .pkcs11_wrapper import (
    PKCS11Wrapper, PKCS11Error, PKCS11SessionError, 
    SessionInfo, SessionState, UserType, TokenInfo
)
from .reader_manager import ReaderInfo, ReaderStatus


class CardStatus(Enum):
    """Smart card status"""
    UNKNOWN = auto()
    PRESENT = auto()
    ABSENT = auto()
    CONNECTED = auto()
    AUTHENTICATED = auto()
    ERROR = auto()
    BUSY = auto()
    LOCKED = auto()


class CardEventType(Enum):
    """Card event types"""
    CARD_CONNECTED = auto()
    CARD_DISCONNECTED = auto()
    CARD_AUTHENTICATED = auto()
    CARD_LOCKED = auto()
    CARD_ERROR = auto()
    SESSION_OPENED = auto()
    SESSION_CLOSED = auto()
    STATUS_CHANGED = auto()


@dataclass
class CardInfo:
    """Information about a smart card"""
    slot_id: int
    card_id: str  # Unique identifier derived from serial number
    label: str
    manufacturer: str
    model: str
    serial_number: str
    status: CardStatus
    last_seen: datetime = field(default_factory=datetime.now)
    capabilities: Dict[str, Any] = field(default_factory=dict)
    error_count: int = 0
    last_error: Optional[str] = None
    
    def __post_init__(self):
        """Post-initialization processing"""
        if not self.card_id:
            # Generate card ID from serial number
            self.card_id = f"card_{self.serial_number}_{self.slot_id}"


@dataclass
class CardEvent:
    """Card event information"""
    event_type: CardEventType
    card_info: CardInfo
    timestamp: datetime = field(default_factory=datetime.now)
    session_handle: Optional[int] = None
    details: Optional[Dict[str, Any]] = None
    
    def __str__(self) -> str:
        return f"{self.event_type.name}: {self.card_info.label} at {self.timestamp}"


class CardConnection:
    """
    Represents a connection to a smart card
    
    This class manages the session lifecycle, authentication state,
    and provides a context manager interface for safe card operations.
    """
    
    def __init__(self, card_info: CardInfo, pkcs11_wrapper: PKCS11Wrapper, 
                 read_write: bool = False):
        """
        Initialize card connection
        
        Args:
            card_info: Information about the card
            pkcs11_wrapper: PKCS#11 wrapper instance
            read_write: Open read-write session if True
        """
        self.card_info = card_info
        self._pkcs11 = pkcs11_wrapper
        self._read_write = read_write
        self._session_handle: Optional[int] = None
        self._authenticated = False
        self._lock = threading.RLock()
        self._last_activity = datetime.now()
        self._reference_count = 0
        
        self.logger = logging.getLogger(f"{__name__}.CardConnection.{card_info.card_id}")
    
    def connect(self) -> None:
        """Connect to the card and open session"""
        with self._lock:
            if self._session_handle is not None:
                raise PKCS11Error("Connection already established")
            
            try:
                # Open session
                self._session_handle = self._pkcs11.open_session(
                    self.card_info.slot_id, 
                    read_write=self._read_write
                )
                
                self._last_activity = datetime.now()
                self.card_info.status = CardStatus.CONNECTED
                
                self.logger.debug(f"Connected to card {self.card_info.card_id}, "
                                f"session: {self._session_handle}")
                
            except Exception as e:
                self.card_info.status = CardStatus.ERROR
                self.card_info.last_error = str(e)
                self.card_info.error_count += 1
                raise PKCS11SessionError(f"Failed to connect to card: {e}")
    
    def disconnect(self) -> None:
        """Disconnect from the card and close session"""
        with self._lock:
            if self._session_handle is None:
                return
            
            try:
                # Logout if authenticated
                if self._authenticated:
                    try:
                        self._pkcs11.logout(self._session_handle)
                        self._authenticated = False
                    except Exception as e:
                        self.logger.warning(f"Error during logout: {e}")
                
                # Close session
                self._pkcs11.close_session(self._session_handle)
                self._session_handle = None
                
                self.card_info.status = CardStatus.PRESENT
                self.logger.debug(f"Disconnected from card {self.card_info.card_id}")
                
            except Exception as e:
                self.logger.error(f"Error during disconnect: {e}")
                self.card_info.status = CardStatus.ERROR
                self.card_info.last_error = str(e)
                self.card_info.error_count += 1
                raise PKCS11SessionError(f"Failed to disconnect from card: {e}")
    
    def authenticate(self, pin: str, user_type: UserType = UserType.CKU_USER) -> None:
        """
        Authenticate to the card
        
        Args:
            pin: PIN/password
            user_type: Type of user (USER or SO)
        """
        with self._lock:
            if self._session_handle is None:
                raise PKCS11SessionError("Not connected to card")
            
            if self._authenticated:
                self.logger.debug("Already authenticated")
                return
            
            try:
                self._pkcs11.login(self._session_handle, user_type, pin)
                self._authenticated = True
                self._last_activity = datetime.now()
                self.card_info.status = CardStatus.AUTHENTICATED
                
                self.logger.debug(f"Successfully authenticated to card {self.card_info.card_id}")
                
            except Exception as e:
                self.card_info.status = CardStatus.ERROR
                self.card_info.last_error = str(e)
                self.card_info.error_count += 1
                
                # Check for specific error conditions
                if "PIN_INCORRECT" in str(e) or "PIN_LOCKED" in str(e):
                    self.card_info.status = CardStatus.LOCKED
                
                raise PKCS11SessionError(f"Authentication failed: {e}")
    
    def logout(self) -> None:
        """Logout from the card"""
        with self._lock:
            if self._session_handle is None:
                raise PKCS11SessionError("Not connected to card")
            
            if not self._authenticated:
                return
            
            try:
                self._pkcs11.logout(self._session_handle)
                self._authenticated = False
                self.card_info.status = CardStatus.CONNECTED
                
                self.logger.debug(f"Logged out from card {self.card_info.card_id}")
                
            except Exception as e:
                self.logger.error(f"Error during logout: {e}")
                raise PKCS11SessionError(f"Logout failed: {e}")
    
    def get_session_info(self) -> Optional[SessionInfo]:
        """Get session information"""
        with self._lock:
            if self._session_handle is None:
                return None
            
            try:
                return self._pkcs11.get_session_info(self._session_handle)
            except Exception as e:
                self.logger.error(f"Error getting session info: {e}")
                return None
    
    def find_objects(self, template: List = None) -> List[int]:
        """Find objects on the card"""
        with self._lock:
            if self._session_handle is None:
                raise PKCS11SessionError("Not connected to card")
            
            self._update_activity()
            return self._pkcs11.find_objects(self._session_handle, template)
    
    def get_attribute_value(self, object_handle: int, attributes: List[int]) -> Dict[int, Any]:
        """Get attribute values from an object"""
        with self._lock:
            if self._session_handle is None:
                raise PKCS11SessionError("Not connected to card")
            
            self._update_activity()
            return self._pkcs11.get_attribute_value(
                self._session_handle, object_handle, attributes
            )
    
    def _update_activity(self) -> None:
        """Update last activity timestamp"""
        self._last_activity = datetime.now()
    
    def __enter__(self):
        """Context manager entry"""
        with self._lock:
            self._reference_count += 1
            if self._session_handle is None:
                self.connect()
            return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        with self._lock:
            self._reference_count -= 1
            # Only disconnect if no other references
            if self._reference_count <= 0:
                try:
                    self.disconnect()
                except Exception as e:
                    self.logger.error(f"Error during context exit: {e}")
    
    @property
    def is_connected(self) -> bool:
        """Check if connected to card"""
        with self._lock:
            return self._session_handle is not None
    
    @property
    def is_authenticated(self) -> bool:
        """Check if authenticated to card"""
        with self._lock:
            return self._authenticated
    
    @property
    def session_handle(self) -> Optional[int]:
        """Get session handle"""
        with self._lock:
            return self._session_handle
    
    @property
    def last_activity(self) -> datetime:
        """Get last activity timestamp"""
        with self._lock:
            return self._last_activity


class CardConnectionManager:
    """
    Manages card connections with pooling and lifecycle management
    
    This class provides:
    - Connection pooling for efficient resource usage
    - Automatic cleanup of idle connections
    - Thread-safe operations
    - Connection sharing and reference counting
    """
    
    def __init__(self, pkcs11_wrapper: PKCS11Wrapper, 
                 max_connections: int = 10,
                 idle_timeout: float = 300.0):
        """
        Initialize connection manager
        
        Args:
            pkcs11_wrapper: PKCS#11 wrapper instance
            max_connections: Maximum number of concurrent connections
            idle_timeout: Idle timeout in seconds
        """
        self._pkcs11 = pkcs11_wrapper
        self._max_connections = max_connections
        self._idle_timeout = idle_timeout
        
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        
        # Thread safety
        self._lock = threading.RLock()
        
        # Connection pool
        self._connections: Dict[str, CardConnection] = {}
        self._connection_refs: Dict[str, int] = {}
        
        # Cleanup thread
        self._cleanup_thread: Optional[threading.Thread] = None
        self._cleanup_stop = threading.Event()
        self._start_cleanup_thread()
    
    def _start_cleanup_thread(self) -> None:
        """Start connection cleanup thread"""
        self._cleanup_thread = threading.Thread(
            target=self._cleanup_idle_connections,
            name="card_connection_cleanup",
            daemon=True
        )
        self._cleanup_thread.start()
    
    def _cleanup_idle_connections(self) -> None:
        """Cleanup idle connections"""
        while not self._cleanup_stop.is_set():
            try:
                now = datetime.now()
                to_remove = []
                
                with self._lock:
                    for card_id, connection in self._connections.items():
                        # Check if connection is idle and not referenced
                        if (self._connection_refs.get(card_id, 0) == 0 and
                            (now - connection.last_activity).total_seconds() > self._idle_timeout):
                            to_remove.append(card_id)
                
                # Remove idle connections
                for card_id in to_remove:
                    self._remove_connection(card_id)
                
                # Wait before next cleanup cycle
                if self._cleanup_stop.wait(60.0):  # Check every minute
                    break
                    
            except Exception as e:
                self.logger.error(f"Error in cleanup thread: {e}")
                if self._cleanup_stop.wait(60.0):
                    break
    
    def _remove_connection(self, card_id: str) -> None:
        """Remove a connection from the pool"""
        with self._lock:
            if card_id in self._connections:
                connection = self._connections[card_id]
                try:
                    connection.disconnect()
                except Exception as e:
                    self.logger.warning(f"Error disconnecting card {card_id}: {e}")
                
                del self._connections[card_id]
                if card_id in self._connection_refs:
                    del self._connection_refs[card_id]
                
                self.logger.debug(f"Removed idle connection for card {card_id}")
    
    @contextmanager
    def get_connection(self, card_info: CardInfo, read_write: bool = False):
        """
        Get a connection to a card (context manager)
        
        Args:
            card_info: Card information
            read_write: Open read-write session if True
            
        Yields:
            CardConnection instance
        """
        connection = None
        try:
            connection = self._acquire_connection(card_info, read_write)
            yield connection
        finally:
            if connection:
                self._release_connection(connection)
    
    def _acquire_connection(self, card_info: CardInfo, read_write: bool = False) -> CardConnection:
        """Acquire a connection from the pool"""
        with self._lock:
            card_id = card_info.card_id
            
            # Check if we already have a connection
            if card_id in self._connections:
                connection = self._connections[card_id]
                
                # Verify connection is still valid
                if self._verify_connection(connection):
                    self._connection_refs[card_id] = self._connection_refs.get(card_id, 0) + 1
                    return connection
                else:
                    # Remove invalid connection
                    self._remove_connection(card_id)
            
            # Check connection limit
            if len(self._connections) >= self._max_connections:
                # Try to free up space by removing idle connections
                self._cleanup_oldest_idle()
                
                if len(self._connections) >= self._max_connections:
                    raise PKCS11Error("Maximum number of connections reached")
            
            # Create new connection
            connection = CardConnection(card_info, self._pkcs11, read_write)
            connection.connect()
            
            self._connections[card_id] = connection
            self._connection_refs[card_id] = 1
            
            self.logger.debug(f"Created new connection for card {card_id}")
            return connection
    
    def _release_connection(self, connection: CardConnection) -> None:
        """Release a connection back to the pool"""
        with self._lock:
            card_id = connection.card_info.card_id
            
            if card_id in self._connection_refs:
                self._connection_refs[card_id] -= 1
                
                # If no more references and connection has errors, remove it
                if (self._connection_refs[card_id] <= 0 and 
                    connection.card_info.status == CardStatus.ERROR):
                    self._remove_connection(card_id)
    
    def _verify_connection(self, connection: CardConnection) -> bool:
        """Verify that a connection is still valid"""
        try:
            if not connection.is_connected:
                return False
            
            # Try to get session info
            session_info = connection.get_session_info()
            return session_info is not None
            
        except Exception:
            return False
    
    def _cleanup_oldest_idle(self) -> None:
        """Cleanup oldest idle connection to make space"""
        oldest_card_id = None
        oldest_time = datetime.now()
        
        for card_id, connection in self._connections.items():
            if (self._connection_refs.get(card_id, 0) == 0 and
                connection.last_activity < oldest_time):
                oldest_time = connection.last_activity
                oldest_card_id = card_id
        
        if oldest_card_id:
            self._remove_connection(oldest_card_id)
    
    def disconnect_all(self) -> None:
        """Disconnect all connections"""
        with self._lock:
            card_ids = list(self._connections.keys())
            
            for card_id in card_ids:
                self._remove_connection(card_id)
    
    def get_connection_stats(self) -> Dict[str, Any]:
        """Get connection pool statistics"""
        with self._lock:
            active_connections = sum(1 for refs in self._connection_refs.values() if refs > 0)
            
            return {
                'total_connections': len(self._connections),
                'active_connections': active_connections,
                'idle_connections': len(self._connections) - active_connections,
                'max_connections': self._max_connections,
                'connection_details': {
                    card_id: {
                        'references': self._connection_refs.get(card_id, 0),
                        'last_activity': conn.last_activity.isoformat(),
                        'status': conn.card_info.status.name,
                        'is_authenticated': conn.is_authenticated
                    }
                    for card_id, conn in self._connections.items()
                }
            }
    
    def __del__(self):
        """Destructor - cleanup connections"""
        try:
            self._cleanup_stop.set()
            if self._cleanup_thread and self._cleanup_thread.is_alive():
                self._cleanup_thread.join(timeout=5.0)
            self.disconnect_all()
        except:
            pass  # Ignore errors during destruction


class SmartCardManager:
    """
    High-level smart card manager providing card discovery and operations
    
    This class combines reader management with card lifecycle management
    to provide a comprehensive smart card interface.
    """
    
    def __init__(self, pkcs11_wrapper: Optional[PKCS11Wrapper] = None):
        """
        Initialize smart card manager
        
        Args:
            pkcs11_wrapper: PKCS#11 wrapper instance, auto-created if None
        """
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        
        self._pkcs11 = pkcs11_wrapper or PKCS11Wrapper()
        self._connection_manager = CardConnectionManager(self._pkcs11)
        
        # Thread safety
        self._lock = threading.RLock()
        
        # Card tracking
        self._cards: Dict[str, CardInfo] = {}
        
        # Event handling
        self._event_handlers: List[Callable[[CardEvent], None]] = []
        
        self.logger.info("Smart card manager initialized")
    
    def discover_cards(self) -> List[CardInfo]:
        """
        Discover available smart cards
        
        Returns:
            List of discovered cards
        """
        try:
            # Get slots with tokens present
            slots_with_tokens = self._pkcs11.get_slot_list(token_present=True)
            
            cards = []
            for slot_id in slots_with_tokens:
                try:
                    card_info = self._create_card_info(slot_id)
                    if card_info:
                        cards.append(card_info)
                        
                        # Update card cache
                        with self._lock:
                            self._cards[card_info.card_id] = card_info
                        
                except Exception as e:
                    self.logger.warning(f"Error processing card in slot {slot_id}: {e}")
            
            self.logger.debug(f"Discovered {len(cards)} cards")
            return cards
            
        except Exception as e:
            self.logger.error(f"Error discovering cards: {e}")
            raise PKCS11Error(f"Failed to discover cards: {e}")
    
    def _create_card_info(self, slot_id: int) -> Optional[CardInfo]:
        """Create CardInfo from slot information"""
        try:
            # Get token information
            token_info = self._pkcs11.get_token_info(slot_id)
            
            card_info = CardInfo(
                slot_id=slot_id,
                card_id="",  # Will be set in __post_init__
                label=token_info.label,
                manufacturer=token_info.manufacturer_id,
                model=token_info.model,
                serial_number=token_info.serial_number,
                status=CardStatus.PRESENT,
                capabilities={
                    'hardware_version': token_info.hardware_version,
                    'firmware_version': token_info.firmware_version,
                    'max_pin_len': token_info.max_pin_len,
                    'min_pin_len': token_info.min_pin_len,
                    'total_public_memory': token_info.total_public_memory,
                    'free_public_memory': token_info.free_public_memory,
                    'total_private_memory': token_info.total_private_memory,
                    'free_private_memory': token_info.free_private_memory
                }
            )
            
            return card_info
            
        except Exception as e:
            self.logger.error(f"Error creating card info for slot {slot_id}: {e}")
            return None
    
    @contextmanager
    def connect_to_card(self, card_info: CardInfo, read_write: bool = False):
        """
        Connect to a card (context manager)
        
        Args:
            card_info: Card to connect to
            read_write: Open read-write session if True
            
        Yields:
            CardConnection instance
        """
        with self._connection_manager.get_connection(card_info, read_write) as connection:
            yield connection
    
    def get_card(self, card_id: str) -> Optional[CardInfo]:
        """Get card information by ID"""
        with self._lock:
            return self._cards.get(card_id)
    
    def get_cards(self, status_filter: Optional[CardStatus] = None) -> List[CardInfo]:
        """
        Get cards matching criteria
        
        Args:
            status_filter: Filter by card status
            
        Returns:
            List of matching cards
        """
        with self._lock:
            cards = list(self._cards.values())
            
            if status_filter:
                cards = [c for c in cards if c.status == status_filter]
            
            return cards
    
    def add_event_handler(self, handler: Callable[[CardEvent], None]) -> None:
        """Add an event handler"""
        with self._lock:
            if handler not in self._event_handlers:
                self._event_handlers.append(handler)
    
    def remove_event_handler(self, handler: Callable[[CardEvent], None]) -> None:
        """Remove an event handler"""
        with self._lock:
            if handler in self._event_handlers:
                self._event_handlers.remove(handler)
    
    def _fire_event(self, event: CardEvent) -> None:
        """Fire event to all handlers"""
        for handler in self._event_handlers:
            try:
                handler(event)
            except Exception as e:
                self.logger.error(f"Error in event handler: {e}")
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get manager statistics"""
        with self._lock:
            stats = {
                'total_cards': len(self._cards),
                'cards_by_status': {},
                'connection_stats': self._connection_manager.get_connection_stats()
            }
            
            # Count cards by status
            for card in self._cards.values():
                status_name = card.status.name
                stats['cards_by_status'][status_name] = stats['cards_by_status'].get(status_name, 0) + 1
            
            return stats
    
    def cleanup(self) -> None:
        """Cleanup resources"""
        self._connection_manager.disconnect_all()
        with self._lock:
            self._cards.clear()
            self._event_handlers.clear()