"""
Target System Simulation
=========================

Vulnerable application deployment and target system configuration
for realistic penetration testing scenarios.
"""

from .target_simulator import TargetSystemSimulator
from .vulnerable_apps import VulnerableApplications
from .network_services import NetworkServices
from .target_builder import TargetBuilder

__all__ = [
    'TargetSystemSimulator',
    'VulnerableApplications',
    'NetworkServices',
    'TargetBuilder'
]