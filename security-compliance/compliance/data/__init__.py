"""
Compliance Data Warehouse
========================

This module provides comprehensive data warehousing capabilities for
historical compliance data aggregation, trend analysis, and forecasting.

Module Components:
- compliance_data_warehouse.py: Main data warehouse implementation
- historical_data_aggregator.py: Historical data collection and aggregation
- trend_analyzer.py: Trend analysis and forecasting
- data_correlation_engine.py: Cross-domain data correlation

Classification: UNCLASSIFIED//FOR OFFICIAL USE ONLY
"""

from .compliance_data_warehouse import ComplianceDataWarehouse, DataWarehouseManager
from .historical_data_aggregator import HistoricalDataAggregator
from .trend_analyzer import TrendAnalyzer
from .data_correlation_engine import DataCorrelationEngine

__all__ = [
    'ComplianceDataWarehouse',
    'DataWarehouseManager',
    'HistoricalDataAggregator',
    'TrendAnalyzer',
    'DataCorrelationEngine'
]