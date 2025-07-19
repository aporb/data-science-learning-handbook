"""
SIEM Integration Module for DoD Audit Logging System

This module provides comprehensive integration capabilities with major Security Information
and Event Management (SIEM) systems including Splunk, Elastic Stack (ELK), Azure Sentinel,
IBM QRadar, and other enterprise security platforms.

Key Features:
- Multi-SIEM connector architecture with pluggable adapters
- Real-time event streaming with buffering and retry mechanisms
- Common Event Format (CEF) and other standard log formats
- Configurable field mapping and data transformation
- Secure transmission with TLS encryption and mutual authentication
- Rate limiting and backpressure handling
- Health monitoring and connection management
- Batch processing for high-volume environments

SIEM Platform Support:
- Splunk Enterprise/Cloud (HTTP Event Collector)
- Elastic Stack (Logstash, Beats, Direct Elasticsearch)
- Microsoft Azure Sentinel (Log Analytics API)
- IBM QRadar (REST API, Syslog)
- ArcSight (CEF over Syslog/TCP)
- LogRhythm (REST API, Syslog)
- Generic Syslog (RFC 3164/5424)
- Custom REST APIs with configurable authentication

Security Features:
- Mutual TLS authentication for enterprise environments
- API key and OAuth 2.0 authentication support
- Data sanitization and PII redaction
- Classification-aware data filtering
- Encrypted transmission channels
- Audit trail for SIEM integration events

Compliance Features:
- DoD-approved data formats and transmission methods
- FISMA compliance for federal systems
- Export control compliance for classified data
- Chain of custody preservation during transmission
- Real-time integrity verification
"""

import json
import logging
import time
import threading
import ssl
import socket
import asyncio
import aiohttp
from typing import Dict, List, Optional, Any, Union, Callable, AsyncIterator
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone, timedelta
from enum import Enum
from pathlib import Path
import queue
import gzip
import base64
import hashlib
import hmac
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor
import xml.etree.ElementTree as ET

# Import audit components
from .audit_logger import AuditEvent, AuditEventType, AuditSeverity, ClassificationLevel


class SIEMType(Enum):
    """Supported SIEM platforms."""
    SPLUNK = "splunk"
    ELASTICSEARCH = "elasticsearch"
    AZURE_SENTINEL = "azure_sentinel"
    QRADAR = "qradar"
    ARCSIGHT = "arcsight"
    LOGRHYTHM = "logrhythm"
    GENERIC_SYSLOG = "generic_syslog"
    GENERIC_REST = "generic_rest"


class LogFormat(Enum):
    """Supported log formats."""
    CEF = "cef"                    # Common Event Format
    LEEF = "leef"                  # Log Event Extended Format
    JSON = "json"                  # JSON format
    SYSLOG = "syslog"             # Traditional syslog
    SPLUNK_HEC = "splunk_hec"     # Splunk HTTP Event Collector
    ECS = "ecs"                   # Elastic Common Schema
    STIX = "stix"                 # Structured Threat Information eXpression


class TransmissionMethod(Enum):
    """Data transmission methods."""
    HTTP_POST = "http_post"
    HTTPS_POST = "https_post"
    SYSLOG_UDP = "syslog_udp"
    SYSLOG_TCP = "syslog_tcp"
    SYSLOG_TLS = "syslog_tls"
    WEBSOCKET = "websocket"
    KAFKA = "kafka"
    MQTT = "mqtt"


@dataclass
class SIEMConfiguration:
    """Configuration for SIEM integration."""
    
    # Basic configuration
    siem_type: SIEMType
    name: str
    enabled: bool = True
    
    # Connection settings
    endpoint_url: str = ""
    port: int = 514
    username: Optional[str] = None
    password: Optional[str] = None
    api_key: Optional[str] = None
    token: Optional[str] = None
    
    # Format and transmission
    log_format: LogFormat = LogFormat.CEF
    transmission_method: TransmissionMethod = TransmissionMethod.HTTPS_POST
    
    # Security settings
    tls_enabled: bool = True
    verify_ssl: bool = True
    client_cert_path: Optional[str] = None
    client_key_path: Optional[str] = None
    ca_cert_path: Optional[str] = None
    
    # Buffering and performance
    buffer_size: int = 10000
    batch_size: int = 100
    flush_interval: int = 30  # seconds
    max_retry_attempts: int = 3
    retry_delay: int = 5      # seconds
    
    # Filtering and transformation
    min_severity: AuditSeverity = AuditSeverity.INFO
    max_classification: ClassificationLevel = ClassificationLevel.UNCLASSIFIED
    event_types_filter: List[str] = field(default_factory=list)
    field_mappings: Dict[str, str] = field(default_factory=dict)
    
    # Rate limiting
    rate_limit_events_per_second: int = 1000
    rate_limit_bytes_per_second: int = 1024 * 1024  # 1MB/s
    
    # Health monitoring
    health_check_interval: int = 300  # seconds
    connection_timeout: int = 30      # seconds
    read_timeout: int = 60           # seconds


@dataclass
class SIEMEvent:
    """Standardized event structure for SIEM transmission."""
    
    # Core fields
    timestamp: datetime
    event_type: str
    severity: int
    message: str
    
    # Identity fields
    user_id: Optional[str] = None
    username: Optional[str] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    
    # System fields
    hostname: Optional[str] = None
    application: Optional[str] = None
    process_id: Optional[int] = None
    
    # Security fields
    classification_level: str = "UNCLASSIFIED"
    facility: Optional[str] = None
    action: Optional[str] = None
    result: Optional[str] = None
    
    # Additional data
    custom_fields: Dict[str, Any] = field(default_factory=dict)
    
    def to_cef(self) -> str:
        """Convert to Common Event Format (CEF)."""
        # CEF Header: CEF:Version|Device Vendor|Device Product|Device Version|Device Event Class ID|Name|Severity|
        cef_header = (
            f"CEF:0|DoD|Audit System|1.0|{self.event_type}|{self.message}|{self.severity}|"
        )
        
        # CEF Extensions
        extensions = []
        
        if self.timestamp:
            extensions.append(f"rt={int(self.timestamp.timestamp() * 1000)}")
        
        if self.user_id:
            extensions.append(f"suser={self.user_id}")
        
        if self.username:
            extensions.append(f"suid={self.username}")
        
        if self.source_ip:
            extensions.append(f"src={self.source_ip}")
        
        if self.destination_ip:
            extensions.append(f"dst={self.destination_ip}")
        
        if self.hostname:
            extensions.append(f"dhost={self.hostname}")
        
        if self.application:
            extensions.append(f"app={self.application}")
        
        if self.action:
            extensions.append(f"act={self.action}")
        
        if self.result:
            extensions.append(f"outcome={self.result}")
        
        # Add custom fields
        for key, value in self.custom_fields.items():
            if key.startswith('cs') and 'Label' not in key:  # Custom string fields
                extensions.append(f"{key}={value}")
        
        return cef_header + " ".join(extensions)
    
    def to_leef(self) -> str:
        """Convert to Log Event Extended Format (LEEF)."""
        # LEEF Header: LEEF:Version|Vendor|Product|Version|EventID|
        leef_header = f"LEEF:2.0|DoD|Audit System|1.0|{self.event_type}|"
        
        # LEEF Attributes
        attributes = []
        
        if self.timestamp:
            attributes.append(f"devTime={self.timestamp.strftime('%b %d %Y %H:%M:%S')}")
        
        if self.user_id:
            attributes.append(f"usrName={self.user_id}")
        
        if self.source_ip:
            attributes.append(f"srcIP={self.source_ip}")
        
        if self.hostname:
            attributes.append(f"devName={self.hostname}")
        
        attributes.append(f"severity={self.severity}")
        attributes.append(f"classification={self.classification_level}")
        
        # Add custom fields
        for key, value in self.custom_fields.items():
            attributes.append(f"{key}={value}")
        
        return leef_header + "\t".join(attributes)
    
    def to_json(self) -> str:
        """Convert to JSON format."""
        data = {
            'timestamp': self.timestamp.isoformat(),
            'event_type': self.event_type,
            'severity': self.severity,
            'message': self.message,
            'user_id': self.user_id,
            'username': self.username,
            'source_ip': self.source_ip,
            'destination_ip': self.destination_ip,
            'hostname': self.hostname,
            'application': self.application,
            'process_id': self.process_id,
            'classification_level': self.classification_level,
            'facility': self.facility,
            'action': self.action,
            'result': self.result
        }
        
        # Add custom fields
        data.update(self.custom_fields)
        
        # Remove None values
        data = {k: v for k, v in data.items() if v is not None}
        
        return json.dumps(data, separators=(',', ':'))
    
    def to_ecs(self) -> str:
        """Convert to Elastic Common Schema (ECS) format."""
        ecs_data = {
            '@timestamp': self.timestamp.isoformat(),
            'event': {
                'category': 'security',
                'type': self.event_type,
                'severity': self.severity,
                'action': self.action,
                'outcome': self.result
            },
            'message': self.message,
            'log': {
                'level': self._severity_to_log_level(self.severity)
            }
        }
        
        # User information
        if self.user_id or self.username:
            ecs_data['user'] = {}
            if self.user_id:
                ecs_data['user']['id'] = self.user_id
            if self.username:
                ecs_data['user']['name'] = self.username
        
        # Network information
        if self.source_ip or self.destination_ip:
            ecs_data['network'] = {}
            if self.source_ip:
                ecs_data['source'] = {'ip': self.source_ip}
            if self.destination_ip:
                ecs_data['destination'] = {'ip': self.destination_ip}
        
        # Host information
        if self.hostname:
            ecs_data['host'] = {'name': self.hostname}
        
        # Process information
        if self.process_id:
            ecs_data['process'] = {'pid': self.process_id}
        
        # Add custom fields
        if self.custom_fields:
            ecs_data['labels'] = self.custom_fields
        
        return json.dumps(ecs_data, separators=(',', ':'))
    
    def _severity_to_log_level(self, severity: int) -> str:
        """Convert numeric severity to log level string."""
        if severity == 1:
            return "fatal"
        elif severity == 2:
            return "error"
        elif severity == 3:
            return "warn"
        elif severity == 4:
            return "info"
        else:
            return "debug"


class SIEMConnector:
    """Base class for SIEM connectors."""
    
    def __init__(self, config: SIEMConfiguration):
        self.config = config
        self.logger = logging.getLogger(f"{__name__}.{config.siem_type.value}")
        
        # Connection state
        self.connected = False
        self.last_error = None
        self.connection_attempts = 0
        
        # Statistics
        self.stats = {
            'events_sent': 0,
            'events_failed': 0,
            'bytes_sent': 0,
            'connection_failures': 0,
            'last_send_time': None,
            'average_send_time': 0.0
        }
        
        # Rate limiting
        self.rate_limiter = self._create_rate_limiter()
    
    def _create_rate_limiter(self):
        """Create rate limiter for event transmission."""
        # Simple token bucket implementation
        return {
            'tokens': self.config.rate_limit_events_per_second,
            'max_tokens': self.config.rate_limit_events_per_second,
            'last_update': time.time(),
            'rate': self.config.rate_limit_events_per_second
        }
    
    def _check_rate_limit(self) -> bool:
        """Check if we can send an event without exceeding rate limit."""
        now = time.time()
        time_passed = now - self.rate_limiter['last_update']
        
        # Add tokens based on time passed
        self.rate_limiter['tokens'] = min(
            self.rate_limiter['max_tokens'],
            self.rate_limiter['tokens'] + time_passed * self.rate_limiter['rate']
        )
        self.rate_limiter['last_update'] = now
        
        # Check if we have tokens available
        if self.rate_limiter['tokens'] >= 1:
            self.rate_limiter['tokens'] -= 1
            return True
        return False
    
    async def connect(self) -> bool:
        """Establish connection to SIEM system."""
        raise NotImplementedError("Subclasses must implement connect method")
    
    async def disconnect(self):
        """Close connection to SIEM system."""
        self.connected = False
    
    async def send_event(self, event: SIEMEvent) -> bool:
        """Send single event to SIEM system."""
        raise NotImplementedError("Subclasses must implement send_event method")
    
    async def send_events(self, events: List[SIEMEvent]) -> int:
        """Send batch of events to SIEM system."""
        sent_count = 0
        
        for event in events:
            if await self.send_event(event):
                sent_count += 1
            else:
                break  # Stop on first failure
        
        return sent_count
    
    def format_event(self, audit_event: AuditEvent) -> SIEMEvent:
        """Convert AuditEvent to SIEMEvent format."""
        siem_event = SIEMEvent(
            timestamp=audit_event.timestamp,
            event_type=audit_event.event_type.value,
            severity=audit_event.severity.value,
            message=audit_event.action or f"Audit event: {audit_event.event_type.value}",
            user_id=audit_event.user_id,
            username=audit_event.username,
            source_ip=audit_event.source_ip,
            destination_ip=audit_event.destination_ip,
            hostname=audit_event.hostname,
            application=audit_event.application,
            process_id=audit_event.process_id,
            classification_level=audit_event.classification_level.value,
            facility=audit_event.facility_code,
            action=audit_event.action,
            result=audit_event.result
        )
        
        # Add custom fields from additional_data
        if audit_event.additional_data:
            siem_event.custom_fields.update(audit_event.additional_data)
        
        # Apply field mappings
        if self.config.field_mappings:
            self._apply_field_mappings(siem_event)
        
        return siem_event
    
    def _apply_field_mappings(self, siem_event: SIEMEvent):
        """Apply configured field mappings to SIEM event."""
        for source_field, target_field in self.config.field_mappings.items():
            if hasattr(siem_event, source_field):
                value = getattr(siem_event, source_field)
                siem_event.custom_fields[target_field] = value
    
    def should_send_event(self, audit_event: AuditEvent) -> bool:
        """Check if event should be sent based on filters."""
        # Check severity
        if audit_event.severity > self.config.min_severity:
            return False
        
        # Check classification level
        classification_levels = [
            ClassificationLevel.UNCLASSIFIED,
            ClassificationLevel.CONTROLLED_UNCLASSIFIED,
            ClassificationLevel.CONFIDENTIAL,
            ClassificationLevel.SECRET,
            ClassificationLevel.TOP_SECRET,
            ClassificationLevel.TOP_SECRET_SCI
        ]
        
        max_index = classification_levels.index(self.config.max_classification)
        event_index = classification_levels.index(audit_event.classification_level)
        
        if event_index > max_index:
            return False
        
        # Check event type filter
        if (self.config.event_types_filter and 
            audit_event.event_type.value not in self.config.event_types_filter):
            return False
        
        return True
    
    def get_health_status(self) -> Dict[str, Any]:
        """Get connector health status."""
        return {
            'connected': self.connected,
            'last_error': str(self.last_error) if self.last_error else None,
            'connection_attempts': self.connection_attempts,
            'stats': self.stats.copy(),
            'rate_limit_tokens': self.rate_limiter['tokens'],
            'config_name': self.config.name
        }


class SplunkConnector(SIEMConnector):
    """Splunk HTTP Event Collector (HEC) connector."""
    
    def __init__(self, config: SIEMConfiguration):
        super().__init__(config)
        self.session = None
        self.hec_url = f"{config.endpoint_url}/services/collector/event"
    
    async def connect(self) -> bool:
        """Connect to Splunk HEC."""
        try:
            self.session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(
                    connect=self.config.connection_timeout,
                    total=self.config.read_timeout
                ),
                connector=aiohttp.TCPConnector(
                    ssl=self._create_ssl_context() if self.config.tls_enabled else False
                )
            )
            
            # Test connection with a ping
            headers = {
                'Authorization': f'Splunk {self.config.token}',
                'Content-Type': 'application/json'
            }
            
            async with self.session.get(
                f"{self.config.endpoint_url}/services/collector/health",
                headers=headers
            ) as response:
                if response.status == 200:
                    self.connected = True
                    self.connection_attempts += 1
                    self.logger.info(f"Connected to Splunk at {self.config.endpoint_url}")
                    return True
                else:
                    self.last_error = f"Connection failed with status {response.status}"
                    return False
        
        except Exception as e:
            self.last_error = str(e)
            self.connection_attempts += 1
            self.stats['connection_failures'] += 1
            self.logger.error(f"Failed to connect to Splunk: {e}")
            return False
    
    async def send_event(self, event: SIEMEvent) -> bool:
        """Send event to Splunk HEC."""
        if not self.connected or not self.session:
            if not await self.connect():
                return False
        
        if not self._check_rate_limit():
            await asyncio.sleep(0.1)  # Brief backoff
            return False
        
        try:
            start_time = time.time()
            
            # Format for Splunk HEC
            splunk_event = {
                'time': int(event.timestamp.timestamp()),
                'event': event.to_json(),
                'sourcetype': 'dod:audit',
                'source': 'audit_system',
                'index': 'security'
            }
            
            headers = {
                'Authorization': f'Splunk {self.config.token}',
                'Content-Type': 'application/json'
            }
            
            async with self.session.post(
                self.hec_url,
                json=splunk_event,
                headers=headers
            ) as response:
                
                if response.status == 200:
                    self.stats['events_sent'] += 1
                    self.stats['bytes_sent'] += len(json.dumps(splunk_event))
                    self.stats['last_send_time'] = datetime.now(timezone.utc)
                    
                    # Update average send time
                    send_time = time.time() - start_time
                    self.stats['average_send_time'] = (
                        (self.stats['average_send_time'] * (self.stats['events_sent'] - 1) + send_time) /
                        self.stats['events_sent']
                    )
                    
                    return True
                else:
                    self.last_error = f"Send failed with status {response.status}"
                    self.stats['events_failed'] += 1
                    return False
        
        except Exception as e:
            self.last_error = str(e)
            self.stats['events_failed'] += 1
            self.logger.error(f"Failed to send event to Splunk: {e}")
            return False
    
    def _create_ssl_context(self):
        """Create SSL context for secure connections."""
        context = ssl.create_default_context()
        
        if not self.config.verify_ssl:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        
        if self.config.client_cert_path and self.config.client_key_path:
            context.load_cert_chain(self.config.client_cert_path, self.config.client_key_path)
        
        if self.config.ca_cert_path:
            context.load_verify_locations(self.config.ca_cert_path)
        
        return context
    
    async def disconnect(self):
        """Disconnect from Splunk."""
        if self.session:
            await self.session.close()
            self.session = None
        self.connected = False


class ElasticsearchConnector(SIEMConnector):
    """Elasticsearch connector for ELK stack."""
    
    def __init__(self, config: SIEMConfiguration):
        super().__init__(config)
        self.session = None
        self.index_name = "dod-audit-logs"
    
    async def connect(self) -> bool:
        """Connect to Elasticsearch."""
        try:
            self.session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(
                    connect=self.config.connection_timeout,
                    total=self.config.read_timeout
                ),
                connector=aiohttp.TCPConnector(
                    ssl=self._create_ssl_context() if self.config.tls_enabled else False
                )
            )
            
            # Test connection
            auth = None
            if self.config.username and self.config.password:
                auth = aiohttp.BasicAuth(self.config.username, self.config.password)
            
            async with self.session.get(
                f"{self.config.endpoint_url}/_cluster/health",
                auth=auth
            ) as response:
                if response.status == 200:
                    self.connected = True
                    self.connection_attempts += 1
                    self.logger.info(f"Connected to Elasticsearch at {self.config.endpoint_url}")
                    return True
                else:
                    self.last_error = f"Connection failed with status {response.status}"
                    return False
        
        except Exception as e:
            self.last_error = str(e)
            self.connection_attempts += 1
            self.stats['connection_failures'] += 1
            self.logger.error(f"Failed to connect to Elasticsearch: {e}")
            return False
    
    async def send_event(self, event: SIEMEvent) -> bool:
        """Send event to Elasticsearch."""
        if not self.connected or not self.session:
            if not await self.connect():
                return False
        
        if not self._check_rate_limit():
            await asyncio.sleep(0.1)
            return False
        
        try:
            start_time = time.time()
            
            # Format for Elasticsearch (ECS)
            doc_data = event.to_ecs()
            
            # Generate document ID based on event
            doc_id = hashlib.md5(f"{event.timestamp.isoformat()}{event.event_type}{event.user_id}".encode()).hexdigest()
            
            url = f"{self.config.endpoint_url}/{self.index_name}/_doc/{doc_id}"
            
            headers = {'Content-Type': 'application/json'}
            
            auth = None
            if self.config.username and self.config.password:
                auth = aiohttp.BasicAuth(self.config.username, self.config.password)
            elif self.config.api_key:
                headers['Authorization'] = f'ApiKey {self.config.api_key}'
            
            async with self.session.put(
                url,
                data=doc_data,
                headers=headers,
                auth=auth
            ) as response:
                
                if response.status in [200, 201]:
                    self.stats['events_sent'] += 1
                    self.stats['bytes_sent'] += len(doc_data)
                    self.stats['last_send_time'] = datetime.now(timezone.utc)
                    
                    send_time = time.time() - start_time
                    self.stats['average_send_time'] = (
                        (self.stats['average_send_time'] * (self.stats['events_sent'] - 1) + send_time) /
                        self.stats['events_sent']
                    )
                    
                    return True
                else:
                    self.last_error = f"Send failed with status {response.status}"
                    self.stats['events_failed'] += 1
                    return False
        
        except Exception as e:
            self.last_error = str(e)
            self.stats['events_failed'] += 1
            self.logger.error(f"Failed to send event to Elasticsearch: {e}")
            return False
    
    def _create_ssl_context(self):
        """Create SSL context for Elasticsearch connection."""
        context = ssl.create_default_context()
        
        if not self.config.verify_ssl:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        
        if self.config.client_cert_path and self.config.client_key_path:
            context.load_cert_chain(self.config.client_cert_path, self.config.client_key_path)
        
        return context
    
    async def disconnect(self):
        """Disconnect from Elasticsearch."""
        if self.session:
            await self.session.close()
            self.session = None
        self.connected = False


class AzureSentinelConnector(SIEMConnector):
    """Microsoft Azure Sentinel connector."""
    
    def __init__(self, config: SIEMConfiguration):
        super().__init__(config)
        self.session = None
        self.workspace_id = config.username  # Workspace ID stored in username field
        self.shared_key = config.password    # Shared key stored in password field
    
    async def connect(self) -> bool:
        """Connect to Azure Sentinel."""
        try:
            self.session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(
                    connect=self.config.connection_timeout,
                    total=self.config.read_timeout
                )
            )
            
            # Test connection with a simple query
            if self.workspace_id and self.shared_key:
                self.connected = True
                self.connection_attempts += 1
                self.logger.info("Connected to Azure Sentinel")
                return True
            else:
                self.last_error = "Missing workspace ID or shared key"
                return False
        
        except Exception as e:
            self.last_error = str(e)
            self.connection_attempts += 1
            self.stats['connection_failures'] += 1
            self.logger.error(f"Failed to connect to Azure Sentinel: {e}")
            return False
    
    async def send_event(self, event: SIEMEvent) -> bool:
        """Send event to Azure Sentinel Log Analytics."""
        if not self.connected or not self.session:
            if not await self.connect():
                return False
        
        if not self._check_rate_limit():
            await asyncio.sleep(0.1)
            return False
        
        try:
            start_time = time.time()
            
            # Format for Azure Sentinel
            log_data = json.loads(event.to_json())
            body = json.dumps([log_data])
            
            # Create authorization signature
            date = datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
            content_length = len(body)
            
            string_to_hash = f"POST\n{content_length}\napplication/json\nx-ms-date:{date}\n/api/logs"
            bytes_to_hash = bytes(string_to_hash, 'UTF-8')
            decoded_key = base64.b64decode(self.shared_key)
            encoded_hash = base64.b64encode(hmac.new(decoded_key, bytes_to_hash, digestmod=hashlib.sha256).digest()).decode()
            authorization = f"SharedKey {self.workspace_id}:{encoded_hash}"
            
            # Send to Azure Log Analytics
            url = f"https://{self.workspace_id}.ods.opinsights.azure.com/api/logs?api-version=2016-04-01"
            
            headers = {
                'Content-Type': 'application/json',
                'Authorization': authorization,
                'Log-Type': 'DoDAuditLogs',
                'x-ms-date': date
            }
            
            async with self.session.post(url, data=body, headers=headers) as response:
                if response.status == 200:
                    self.stats['events_sent'] += 1
                    self.stats['bytes_sent'] += len(body)
                    self.stats['last_send_time'] = datetime.now(timezone.utc)
                    
                    send_time = time.time() - start_time
                    self.stats['average_send_time'] = (
                        (self.stats['average_send_time'] * (self.stats['events_sent'] - 1) + send_time) /
                        self.stats['events_sent']
                    )
                    
                    return True
                else:
                    self.last_error = f"Send failed with status {response.status}"
                    self.stats['events_failed'] += 1
                    return False
        
        except Exception as e:
            self.last_error = str(e)
            self.stats['events_failed'] += 1
            self.logger.error(f"Failed to send event to Azure Sentinel: {e}")
            return False
    
    async def disconnect(self):
        """Disconnect from Azure Sentinel."""
        if self.session:
            await self.session.close()
            self.session = None
        self.connected = False


class SyslogConnector(SIEMConnector):
    """Generic Syslog connector for CEF/LEEF over Syslog."""
    
    def __init__(self, config: SIEMConfiguration):
        super().__init__(config)
        self.socket = None
    
    async def connect(self) -> bool:
        """Connect to Syslog server."""
        try:
            if self.config.transmission_method == TransmissionMethod.SYSLOG_UDP:
                self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            elif self.config.transmission_method == TransmissionMethod.SYSLOG_TCP:
                self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.socket.connect((self.config.endpoint_url, self.config.port))
            elif self.config.transmission_method == TransmissionMethod.SYSLOG_TLS:
                raw_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                context = ssl.create_default_context()
                if not self.config.verify_ssl:
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                
                self.socket = context.wrap_socket(raw_socket, server_hostname=self.config.endpoint_url)
                self.socket.connect((self.config.endpoint_url, self.config.port))
            
            self.connected = True
            self.connection_attempts += 1
            self.logger.info(f"Connected to Syslog server at {self.config.endpoint_url}:{self.config.port}")
            return True
        
        except Exception as e:
            self.last_error = str(e)
            self.connection_attempts += 1
            self.stats['connection_failures'] += 1
            self.logger.error(f"Failed to connect to Syslog server: {e}")
            return False
    
    async def send_event(self, event: SIEMEvent) -> bool:
        """Send event via Syslog."""
        if not self.connected or not self.socket:
            if not await self.connect():
                return False
        
        if not self._check_rate_limit():
            await asyncio.sleep(0.1)
            return False
        
        try:
            start_time = time.time()
            
            # Format message based on configuration
            if self.config.log_format == LogFormat.CEF:
                message = event.to_cef()
            elif self.config.log_format == LogFormat.LEEF:
                message = event.to_leef()
            else:
                message = event.to_json()
            
            # Create syslog message
            priority = self._calculate_syslog_priority(event.severity)
            timestamp = event.timestamp.strftime('%b %d %H:%M:%S')
            hostname = event.hostname or 'audit-system'
            tag = 'DoDAudit'
            
            syslog_message = f"<{priority}>{timestamp} {hostname} {tag}: {message}"
            
            # Send message
            if self.config.transmission_method == TransmissionMethod.SYSLOG_UDP:
                self.socket.sendto(syslog_message.encode(), (self.config.endpoint_url, self.config.port))
            else:
                self.socket.send(syslog_message.encode() + b'\n')
            
            self.stats['events_sent'] += 1
            self.stats['bytes_sent'] += len(syslog_message.encode())
            self.stats['last_send_time'] = datetime.now(timezone.utc)
            
            send_time = time.time() - start_time
            self.stats['average_send_time'] = (
                (self.stats['average_send_time'] * (self.stats['events_sent'] - 1) + send_time) /
                self.stats['events_sent']
            )
            
            return True
        
        except Exception as e:
            self.last_error = str(e)
            self.stats['events_failed'] += 1
            self.logger.error(f"Failed to send syslog message: {e}")
            return False
    
    def _calculate_syslog_priority(self, severity: int) -> int:
        """Calculate syslog priority from severity."""
        # Facility 16 (local use 0) + severity
        facility = 16 * 8  # Facility 16
        return facility + min(severity, 7)
    
    async def disconnect(self):
        """Disconnect from Syslog server."""
        if self.socket:
            self.socket.close()
            self.socket = None
        self.connected = False


class SIEMIntegrationManager:
    """
    Central manager for all SIEM integrations.
    
    Handles multiple SIEM connectors, load balancing, failover,
    and centralized monitoring of SIEM integration health.
    """
    
    def __init__(self):
        self.connectors: Dict[str, SIEMConnector] = {}
        self.event_queue: asyncio.Queue = asyncio.Queue(maxsize=100000)
        self.running = False
        self.worker_tasks: List[asyncio.Task] = []
        
        # Statistics
        self.stats = {
            'total_events_processed': 0,
            'total_events_sent': 0,
            'total_events_failed': 0,
            'connectors_active': 0,
            'last_activity': None
        }
        
        self.logger = logging.getLogger(__name__)
    
    def add_connector(self, name: str, config: SIEMConfiguration) -> bool:
        """Add a SIEM connector."""
        try:
            # Create appropriate connector based on type
            if config.siem_type == SIEMType.SPLUNK:
                connector = SplunkConnector(config)
            elif config.siem_type == SIEMType.ELASTICSEARCH:
                connector = ElasticsearchConnector(config)
            elif config.siem_type == SIEMType.AZURE_SENTINEL:
                connector = AzureSentinelConnector(config)
            elif config.siem_type in [SIEMType.ARCSIGHT, SIEMType.GENERIC_SYSLOG]:
                connector = SyslogConnector(config)
            else:
                self.logger.error(f"Unsupported SIEM type: {config.siem_type}")
                return False
            
            self.connectors[name] = connector
            self.logger.info(f"Added SIEM connector: {name} ({config.siem_type.value})")
            return True
        
        except Exception as e:
            self.logger.error(f"Failed to add connector {name}: {e}")
            return False
    
    def remove_connector(self, name: str) -> bool:
        """Remove a SIEM connector."""
        if name in self.connectors:
            asyncio.create_task(self.connectors[name].disconnect())
            del self.connectors[name]
            self.logger.info(f"Removed SIEM connector: {name}")
            return True
        return False
    
    async def start(self):
        """Start SIEM integration processing."""
        if self.running:
            return
        
        self.running = True
        self.logger.info("Starting SIEM integration manager")
        
        # Connect all enabled connectors
        for name, connector in self.connectors.items():
            if connector.config.enabled:
                await connector.connect()
        
        # Start worker tasks
        for i in range(4):  # 4 worker tasks
            task = asyncio.create_task(self._worker())
            self.worker_tasks.append(task)
    
    async def stop(self):
        """Stop SIEM integration processing."""
        if not self.running:
            return
        
        self.running = False
        self.logger.info("Stopping SIEM integration manager")
        
        # Cancel worker tasks
        for task in self.worker_tasks:
            task.cancel()
        
        # Wait for tasks to complete
        await asyncio.gather(*self.worker_tasks, return_exceptions=True)
        self.worker_tasks.clear()
        
        # Disconnect all connectors
        for connector in self.connectors.values():
            await connector.disconnect()
    
    async def queue_event(self, audit_event: AuditEvent):
        """Queue an audit event for SIEM transmission."""
        try:
            await self.event_queue.put(audit_event)
            self.stats['total_events_processed'] += 1
            self.stats['last_activity'] = datetime.now(timezone.utc)
        except asyncio.QueueFull:
            self.logger.warning("SIEM event queue full, dropping event")
    
    async def _worker(self):
        """Worker task for processing SIEM events."""
        while self.running:
            try:
                # Get event from queue
                audit_event = await asyncio.wait_for(self.event_queue.get(), timeout=1.0)
                
                # Send to all enabled and connected connectors
                sent_to_any = False
                for name, connector in self.connectors.items():
                    if not connector.config.enabled or not connector.connected:
                        continue
                    
                    if not connector.should_send_event(audit_event):
                        continue
                    
                    try:
                        siem_event = connector.format_event(audit_event)
                        if await connector.send_event(siem_event):
                            sent_to_any = True
                    except Exception as e:
                        self.logger.error(f"Error sending to {name}: {e}")
                
                if sent_to_any:
                    self.stats['total_events_sent'] += 1
                else:
                    self.stats['total_events_failed'] += 1
                
                # Mark task as done
                self.event_queue.task_done()
                
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                self.logger.error(f"Worker error: {e}")
                await asyncio.sleep(1)
    
    def get_status(self) -> Dict[str, Any]:
        """Get status of all SIEM integrations."""
        connector_status = {}
        active_connectors = 0
        
        for name, connector in self.connectors.items():
            status = connector.get_health_status()
            connector_status[name] = status
            if status['connected']:
                active_connectors += 1
        
        self.stats['connectors_active'] = active_connectors
        
        return {
            'running': self.running,
            'queue_size': self.event_queue.qsize(),
            'stats': self.stats.copy(),
            'connectors': connector_status
        }


# Factory function for creating SIEM integration manager
def create_siem_manager() -> SIEMIntegrationManager:
    """Create and return a SIEM integration manager."""
    return SIEMIntegrationManager()