"""
Vulnerability Discovery Integration Module
==========================================

This module provides advanced vulnerability discovery capabilities that integrate
with existing security infrastructure and external vulnerability sources.

Components:
- VulnerabilityDiscoveryEngine: Main orchestration engine
- ScannerIntegration: Integration with external vulnerability scanners
- PentestResultProcessor: Processing of penetration testing results
- VulnerabilityFeedManager: Real-time vulnerability feed integration
- CustomRuleEngine: Custom vulnerability detection rules
"""

from .discovery_engine import VulnerabilityDiscoveryEngine
from .scanner_integration import ScannerIntegration
from .pentest_processor import PentestResultProcessor
from .feed_manager import VulnerabilityFeedManager
from .custom_rules import CustomRuleEngine

__all__ = [
    'VulnerabilityDiscoveryEngine',
    'ScannerIntegration', 
    'PentestResultProcessor',
    'VulnerabilityFeedManager',
    'CustomRuleEngine'
]