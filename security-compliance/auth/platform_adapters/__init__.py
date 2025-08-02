#!/usr/bin/env python3
"""
Platform Adapters for CAC/PIV Authentication
Provides platform-specific authentication integrations
"""

from .base_adapter import BasePlatformAdapter, AuthenticationResult
from .advana_adapter import AdvanaAuthAdapter
from .qlik_adapter import QlikAuthAdapter
from .databricks_adapter import DatabricksAuthAdapter
from .navy_jupiter_adapter import NavyJupiterAuthAdapter

__all__ = [
    'BasePlatformAdapter',
    'AuthenticationResult',
    'AdvanaAuthAdapter',
    'QlikAuthAdapter',
    'DatabricksAuthAdapter',
    'NavyJupiterAuthAdapter'
]