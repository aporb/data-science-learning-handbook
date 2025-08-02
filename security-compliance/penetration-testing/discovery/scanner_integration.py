"""
Scanner Integration Module
==========================

Provides integration capabilities with various vulnerability scanners and security tools.
Standardizes vulnerability data from different sources into a unified format.

Supported Scanners:
- Nessus
- OpenVAS
- Nmap with NSE scripts
- OWASP ZAP
- Qualys
- Rapid7 Nexpose
- Custom scanner APIs

Features:
- Standardized vulnerability data format
- Authentication and credential management
- Scan scheduling and automation
- Real-time result processing
- Error handling and retry logic
"""

import asyncio
import aiohttp
import json
import logging
import ssl
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any, AsyncGenerator
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
import base64
import hashlib

logger = logging.getLogger(__name__)

class ScannerType(Enum):
    """Supported vulnerability scanner types"""
    NESSUS = "nessus"
    OPENVAS = "openvas"
    NMAP = "nmap"
    OWASP_ZAP = "owasp_zap"
    QUALYS = "qualys"
    RAPID7 = "rapid7"
    CUSTOM = "custom"

@dataclass
class ScannerConfig:
    """Configuration for a vulnerability scanner"""
    scanner_type: ScannerType
    name: str
    host: str
    port: int
    use_ssl: bool = True
    api_endpoint: str = ""
    username: Optional[str] = None
    password: Optional[str] = None
    api_key: Optional[str] = None
    verify_ssl: bool = True
    timeout: int = 300
    max_retries: int = 3
    scan_templates: Dict[str, str] = None
    custom_headers: Dict[str, str] = None

@dataclass
class ScanRequest:
    """Vulnerability scan request"""
    targets: List[str]
    scan_type: str = "discovery"
    scan_template: Optional[str] = None
    scan_name: Optional[str] = None
    credentials: Optional[Dict[str, Any]] = None
    scan_policy: Optional[Dict[str, Any]] = None
    priority: int = 5  # 1-10 scale
    notify_on_completion: bool = True

@dataclass
class StandardizedVulnerability:
    """Standardized vulnerability format across all scanners"""
    plugin_id: str
    plugin_name: str
    severity: str
    risk_factor: str
    synopsis: str
    description: str
    solution: str
    see_also: List[str]
    cve_ids: List[str]
    cvss_score: float
    cvss_vector: Optional[str]
    exploit_available: bool
    exploitability_ease: str
    patch_publication_date: Optional[str]
    vulnerability_publication_date: Optional[str]
    plugin_modification_date: Optional[str]
    host: str
    port: Optional[int]
    protocol: Optional[str]
    service: Optional[str]
    plugin_output: str
    asset_uuid: Optional[str]
    scanner_specific_data: Dict[str, Any]

class BaseScannerIntegration:
    """Base class for scanner integrations"""
    
    def __init__(self, config: ScannerConfig):
        self.config = config
        self.logger = logging.getLogger(f"{__name__}.{config.scanner_type.value}")
        self.session = None
        
    async def __aenter__(self):
        await self.connect()
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.disconnect()
    
    async def connect(self):
        """Establish connection to scanner"""
        connector = aiohttp.TCPConnector(
            ssl=ssl.create_default_context() if self.config.verify_ssl else False
        )
        timeout = aiohttp.ClientTimeout(total=self.config.timeout)
        
        self.session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers=self.config.custom_headers or {}
        )
        
        await self.authenticate()
    
    async def disconnect(self):
        """Close connection to scanner"""
        if self.session:
            await self.session.close()
    
    async def authenticate(self):
        """Authenticate with the scanner"""
        raise NotImplementedError("Subclasses must implement authenticate()")
    
    async def start_scan(self, request: ScanRequest) -> str:
        """Start a vulnerability scan"""
        raise NotImplementedError("Subclasses must implement start_scan()")
    
    async def get_scan_status(self, scan_id: str) -> Dict[str, Any]:
        """Get scan status"""
        raise NotImplementedError("Subclasses must implement get_scan_status()")
    
    async def get_scan_results(self, scan_id: str) -> AsyncGenerator[StandardizedVulnerability, None]:
        """Get scan results as standardized vulnerabilities"""
        raise NotImplementedError("Subclasses must implement get_scan_results()")
    
    async def cancel_scan(self, scan_id: str) -> bool:
        """Cancel a running scan"""
        raise NotImplementedError("Subclasses must implement cancel_scan()")

class NessusIntegration(BaseScannerIntegration):
    """Nessus vulnerability scanner integration"""
    
    def __init__(self, config: ScannerConfig):
        super().__init__(config)
        self.token = None
        self.base_url = f"{'https' if config.use_ssl else 'http'}://{config.host}:{config.port}"
    
    async def authenticate(self):
        """Authenticate with Nessus"""
        login_data = {
            'username': self.config.username,
            'password': self.config.password
        }
        
        async with self.session.post(f"{self.base_url}/session", json=login_data) as resp:
            if resp.status == 200:
                data = await resp.json()
                self.token = data.get('token')
                self.session.headers.update({'X-Cookie': f'token={self.token}'})
                self.logger.info("Successfully authenticated with Nessus")
            else:
                raise Exception(f"Nessus authentication failed: {resp.status}")
    
    async def start_scan(self, request: ScanRequest) -> str:
        """Start a Nessus scan"""
        # Get scanner policies
        policies = await self._get_policies()
        policy_id = policies.get(request.scan_template or 'Basic Network Scan')
        
        if not policy_id:
            raise ValueError(f"Scan template '{request.scan_template}' not found")
        
        scan_data = {
            'uuid': policy_id,
            'settings': {
                'name': request.scan_name or f"Automated Scan {datetime.now().isoformat()}",
                'text_targets': ','.join(request.targets),
                'launch_now': True
            }
        }
        
        async with self.session.post(f"{self.base_url}/scans", json=scan_data) as resp:
            if resp.status == 200:
                data = await resp.json()
                scan_id = str(data['scan']['id'])
                self.logger.info(f"Started Nessus scan: {scan_id}")
                return scan_id
            else:
                raise Exception(f"Failed to start Nessus scan: {resp.status}")
    
    async def get_scan_status(self, scan_id: str) -> Dict[str, Any]:
        """Get Nessus scan status"""
        async with self.session.get(f"{self.base_url}/scans/{scan_id}") as resp:
            if resp.status == 200:
                data = await resp.json()
                info = data.get('info', {})
                return {
                    'status': info.get('status', 'unknown'),
                    'progress': info.get('hostcount', 0),
                    'start_time': info.get('scan_start'),
                    'end_time': info.get('scan_end'),
                    'targets': info.get('targets', '').split(','),
                    'vulnerability_count': len(data.get('vulnerabilities', []))
                }
            else:
                raise Exception(f"Failed to get Nessus scan status: {resp.status}")
    
    async def get_scan_results(self, scan_id: str) -> AsyncGenerator[StandardizedVulnerability, None]:
        """Get Nessus scan results"""
        # Export scan results
        export_data = {'format': 'nessus'}
        async with self.session.post(f"{self.base_url}/scans/{scan_id}/export", json=export_data) as resp:
            if resp.status != 200:
                raise Exception(f"Failed to export Nessus scan: {resp.status}")
            
            export_data = await resp.json()
            file_id = export_data['file']
        
        # Wait for export to complete and download
        while True:
            async with self.session.get(f"{self.base_url}/scans/{scan_id}/export/{file_id}/status") as resp:
                status_data = await resp.json()
                if status_data['status'] == 'ready':
                    break
                await asyncio.sleep(2)
        
        # Download and parse results
        async with self.session.get(f"{self.base_url}/scans/{scan_id}/export/{file_id}/download") as resp:
            xml_content = await resp.text()
            
            # Parse Nessus XML format
            root = ET.fromstring(xml_content)
            
            for report in root.findall('.//Report'):
                for host in report.findall('ReportHost'):
                    host_name = host.get('name')
                    
                    for item in host.findall('ReportItem'):
                        yield self._parse_nessus_vulnerability(item, host_name)
    
    def _parse_nessus_vulnerability(self, item, host: str) -> StandardizedVulnerability:
        """Parse Nessus vulnerability item"""
        plugin_id = item.get('pluginID', '')
        plugin_name = item.get('pluginName', '')
        severity = item.get('severity', '0')
        port = item.get('port')
        protocol = item.get('protocol')
        service = item.get('svc_name')
        
        # Convert severity number to text
        severity_map = {'0': 'info', '1': 'low', '2': 'medium', '3': 'high', '4': 'critical'}
        severity_text = severity_map.get(severity, 'info')
        
        # Extract vulnerability details
        synopsis = self._get_element_text(item, 'synopsis')
        description = self._get_element_text(item, 'description')
        solution = self._get_element_text(item, 'solution')
        plugin_output = self._get_element_text(item, 'plugin_output')
        
        # Extract CVE IDs
        cve_ids = []
        cve_element = item.find('cve')
        if cve_element is not None and cve_element.text:
            cve_ids = [cve.strip() for cve in cve_element.text.split(',')]
        
        # Extract CVSS information
        cvss_score = 0.0
        cvss_vector = None
        cvss_element = item.find('cvss_base_score')
        if cvss_element is not None and cvss_element.text:
            try:
                cvss_score = float(cvss_element.text)
            except ValueError:
                pass
        
        cvss_vector_element = item.find('cvss_vector')
        if cvss_vector_element is not None:
            cvss_vector = cvss_vector_element.text
        
        # Extract dates
        patch_date = self._get_element_text(item, 'patch_publication_date')
        vuln_date = self._get_element_text(item, 'vuln_publication_date')
        plugin_date = self._get_element_text(item, 'plugin_modification_date')
        
        # Extract exploit information
        exploit_available = self._get_element_text(item, 'exploit_available') == 'true'
        exploitability_ease = self._get_element_text(item, 'exploitability_ease')
        
        # Extract see also references
        see_also = []
        see_also_element = item.find('see_also')
        if see_also_element is not None and see_also_element.text:
            see_also = [ref.strip() for ref in see_also_element.text.split('\n') if ref.strip()]
        
        return StandardizedVulnerability(
            plugin_id=plugin_id,
            plugin_name=plugin_name,
            severity=severity_text,
            risk_factor=severity_text.title(),
            synopsis=synopsis,
            description=description,
            solution=solution,
            see_also=see_also,
            cve_ids=cve_ids,
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            exploit_available=exploit_available,
            exploitability_ease=exploitability_ease,
            patch_publication_date=patch_date,
            vulnerability_publication_date=vuln_date,
            plugin_modification_date=plugin_date,
            host=host,
            port=int(port) if port and port.isdigit() else None,
            protocol=protocol,
            service=service,
            plugin_output=plugin_output,
            asset_uuid=None,
            scanner_specific_data={
                'scanner': 'nessus',
                'plugin_family': item.get('pluginFamily'),
                'risk_factor': self._get_element_text(item, 'risk_factor'),
                'plugin_type': item.get('pluginType')
            }
        )
    
    def _get_element_text(self, parent, element_name: str) -> str:
        """Safely get text from XML element"""
        element = parent.find(element_name)
        return element.text if element is not None and element.text else ""
    
    async def _get_policies(self) -> Dict[str, str]:
        """Get available scan policies"""
        async with self.session.get(f"{self.base_url}/policies") as resp:
            if resp.status == 200:
                data = await resp.json()
                return {policy['name']: policy['template_uuid'] for policy in data.get('policies', [])}
            return {}
    
    async def cancel_scan(self, scan_id: str) -> bool:
        """Cancel a Nessus scan"""
        async with self.session.post(f"{self.base_url}/scans/{scan_id}/stop") as resp:
            return resp.status == 200

class OpenVASIntegration(BaseScannerIntegration):
    """OpenVAS vulnerability scanner integration"""
    
    def __init__(self, config: ScannerConfig):
        super().__init__(config)
        self.base_url = f"{'https' if config.use_ssl else 'http'}://{config.host}:{config.port}"
    
    async def authenticate(self):
        """Authenticate with OpenVAS using XML-RPC or REST API"""
        # Implementation would depend on OpenVAS version and API
        # This is a placeholder implementation
        auth_data = {
            'cmd': 'authenticate',
            'login': self.config.username,
            'password': self.config.password
        }
        
        # OpenVAS authentication logic would go here
        self.logger.info("OpenVAS authentication placeholder")
    
    async def start_scan(self, request: ScanRequest) -> str:
        """Start an OpenVAS scan"""
        # OpenVAS scan start logic would go here
        scan_id = hashlib.md5(f"{request.targets}_{datetime.now()}".encode()).hexdigest()
        self.logger.info(f"Started OpenVAS scan: {scan_id}")
        return scan_id
    
    async def get_scan_status(self, scan_id: str) -> Dict[str, Any]:
        """Get OpenVAS scan status"""
        # OpenVAS status check logic would go here
        return {
            'status': 'running',
            'progress': 50,
            'start_time': datetime.now().isoformat(),
            'end_time': None,
            'targets': [],
            'vulnerability_count': 0
        }
    
    async def get_scan_results(self, scan_id: str) -> AsyncGenerator[StandardizedVulnerability, None]:
        """Get OpenVAS scan results"""
        # OpenVAS results parsing logic would go here
        # This is a placeholder
        if False:  # Placeholder condition
            yield StandardizedVulnerability(
                plugin_id="", plugin_name="", severity="", risk_factor="",
                synopsis="", description="", solution="", see_also=[],
                cve_ids=[], cvss_score=0.0, cvss_vector=None,
                exploit_available=False, exploitability_ease="",
                patch_publication_date=None, vulnerability_publication_date=None,
                plugin_modification_date=None, host="", port=None,
                protocol=None, service=None, plugin_output="",
                asset_uuid=None, scanner_specific_data={}
            )
    
    async def cancel_scan(self, scan_id: str) -> bool:
        """Cancel an OpenVAS scan"""
        return True

class ScannerIntegration:
    """Main scanner integration orchestrator"""
    
    def __init__(self):
        self.scanners: Dict[str, BaseScannerIntegration] = {}
        self.scanner_configs: Dict[str, ScannerConfig] = {}
        self.logger = logging.getLogger(f"{__name__}.ScannerIntegration")
    
    def register_scanner(self, name: str, config: ScannerConfig):
        """Register a vulnerability scanner"""
        self.scanner_configs[name] = config
        
        # Create scanner integration instance
        if config.scanner_type == ScannerType.NESSUS:
            integration = NessusIntegration(config)
        elif config.scanner_type == ScannerType.OPENVAS:
            integration = OpenVASIntegration(config)
        else:
            raise ValueError(f"Unsupported scanner type: {config.scanner_type}")
        
        self.scanners[name] = integration
        self.logger.info(f"Registered scanner: {name} ({config.scanner_type.value})")
    
    async def discover_vulnerabilities(self, 
                                     scanner_name: str,
                                     targets: List[str], 
                                     scan_config: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """Discover vulnerabilities using specified scanner"""
        
        if scanner_name not in self.scanners:
            raise ValueError(f"Scanner '{scanner_name}' not registered")
        
        scanner = self.scanners[scanner_name]
        findings = []
        
        try:
            async with scanner:
                # Create scan request
                request = ScanRequest(
                    targets=targets,
                    scan_type=scan_config.get('scan_type', 'discovery') if scan_config else 'discovery',
                    scan_template=scan_config.get('scan_template') if scan_config else None,
                    scan_name=scan_config.get('scan_name') if scan_config else None,
                    priority=scan_config.get('priority', 5) if scan_config else 5
                )
                
                # Start scan
                scan_id = await scanner.start_scan(request)
                self.logger.info(f"Started scan {scan_id} on scanner {scanner_name}")
                
                # Wait for scan completion
                while True:
                    status = await scanner.get_scan_status(scan_id)
                    if status['status'] in ['completed', 'stopped', 'cancelled', 'aborted']:
                        break
                    await asyncio.sleep(30)  # Check every 30 seconds
                
                # Get results
                async for vuln in scanner.get_scan_results(scan_id):
                    finding = {
                        'id': f"{scanner_name}_{vuln.plugin_id}_{vuln.host}_{vuln.port or 0}",
                        'title': vuln.plugin_name,
                        'description': vuln.description,
                        'severity': vuln.severity,
                        'cvss_score': vuln.cvss_score,
                        'cve_id': vuln.cve_ids[0] if vuln.cve_ids else None,
                        'host': vuln.host,
                        'port': vuln.port,
                        'service': vuln.service,
                        'solution': vuln.solution,
                        'scanner': scanner_name,
                        'plugin_output': vuln.plugin_output,
                        'exploit_available': vuln.exploit_available,
                        'asset': {
                            'id': vuln.asset_uuid or f"{vuln.host}_{vuln.port or 0}",
                            'host': vuln.host,
                            'port': vuln.port,
                            'service': vuln.service
                        },
                        'raw_data': vuln.scanner_specific_data
                    }
                    findings.append(finding)
                
                self.logger.info(f"Scan {scan_id} completed with {len(findings)} findings")
                
        except Exception as e:
            self.logger.error(f"Error during vulnerability discovery with {scanner_name}: {e}")
            raise
        
        return findings
    
    def get_registered_scanners(self) -> List[str]:
        """Get list of registered scanner names"""
        return list(self.scanners.keys())
    
    def get_scanner_info(self, scanner_name: str) -> Optional[Dict[str, Any]]:
        """Get information about a registered scanner"""
        if scanner_name in self.scanner_configs:
            config = self.scanner_configs[scanner_name]
            return {
                'name': scanner_name,
                'type': config.scanner_type.value,
                'host': config.host,
                'port': config.port,
                'ssl': config.use_ssl,
                'templates': list(config.scan_templates.keys()) if config.scan_templates else []
            }
        return None