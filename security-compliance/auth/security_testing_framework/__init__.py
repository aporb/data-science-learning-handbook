"""
Security Testing Framework
Comprehensive security testing, vulnerability assessment, and penetration testing tools
for the Multi-Platform Authentication and Security Framework.

This module provides:
- Automated security scanning pipeline (SAST/DAST)
- Vulnerability assessment and prioritization
- Penetration testing tools and procedures
- Security test case management
- Continuous security monitoring
- Security metrics and KPI tracking
"""

from .scanner import SecurityScanner
from .vulnerability_assessor import VulnerabilityAssessor
from .penetration_tester import PenetrationTester
from .test_manager import SecurityTestManager
from .monitor import SecurityMonitor
from .metrics import SecurityMetrics

__version__ = "1.0.0"
__all__ = [
    "SecurityScanner",
    "VulnerabilityAssessor", 
    "PenetrationTester",
    "SecurityTestManager",
    "SecurityMonitor",
    "SecurityMetrics"
]