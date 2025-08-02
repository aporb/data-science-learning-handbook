"""
Compliance Data Warehouse
=========================

This module provides comprehensive data warehousing capabilities for compliance
data with historical aggregation, trend analysis, forecasting, and performance
metrics storage with integration to existing monitoring and audit systems.

Key Features:
- Historical compliance data aggregation and storage
- Trend analysis and forecasting capabilities
- Data correlation across security domains
- Performance metrics storage and analysis
- Multi-dimensional compliance data modeling
- Scalable data warehouse architecture with time-series optimization

Integration Points:
- Enhanced monitoring system for real-time metrics collection
- Integrated audit orchestrator for audit data aggregation
- Enhanced log aggregator for event correlation
- Multi-classification engine for classified data handling
- Compliance dashboard for data visualization

Classification: UNCLASSIFIED//FOR OFFICIAL USE ONLY
Version: 1.0 - Comprehensive Data Warehousing
Author: Security Compliance Team
Date: 2025-07-28
"""

import asyncio
import json
import logging
import time
import sqlite3
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Tuple, Set, Union, AsyncGenerator
from uuid import UUID, uuid4
from dataclasses import dataclass, field, asdict
from enum import Enum
from concurrent.futures import ThreadPoolExecutor
from collections import defaultdict, deque
import aiofiles
import aiosqlite
from threading import Lock
import numpy as np
import pandas as pd
from pathlib import Path
import pickle
from scipy import stats
from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import PCA
from sklearn.cluster import KMeans

# Import existing infrastructure
from ...audits.integrated_audit_orchestrator import IntegratedAuditOrchestrator
from ...audits.enhanced_monitoring_system import EnhancedMonitoringSystem
from ...audits.enhanced_log_aggregator import EnhancedLogAggregator

# Import compliance data structures
from ..dashboards.compliance_dashboard import ComplianceMetric, ComplianceMetricType, ComplianceDataProvider

logger = logging.getLogger(__name__)


class DataAggregationLevel(Enum):
    """Levels of data aggregation."""
    RAW = "raw"                    # Individual data points
    HOURLY = "hourly"             # Hourly aggregates
    DAILY = "daily"               # Daily aggregates
    WEEKLY = "weekly"             # Weekly aggregates
    MONTHLY = "monthly"           # Monthly aggregates
    QUARTERLY = "quarterly"       # Quarterly aggregates
    ANNUALLY = "annually"         # Annual aggregates


class TrendDirection(Enum):
    """Trend direction indicators."""
    IMPROVING = "improving"
    DECLINING = "declining"
    STABLE = "stable"
    VOLATILE = "volatile"
    UNKNOWN = "unknown"


class ForecastAccuracy(Enum):
    """Forecast accuracy levels."""
    HIGH = "high"          # >90% accuracy
    MEDIUM = "medium"      # 70-90% accuracy
    LOW = "low"           # 50-70% accuracy
    UNRELIABLE = "unreliable"  # <50% accuracy


@dataclass
class HistoricalMetricPoint:
    """Historical compliance metric data point."""
    point_id: str = field(default_factory=lambda: str(uuid4()))
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    # Metric identification
    metric_type: ComplianceMetricType = ComplianceMetricType.OVERALL_POSTURE
    metric_name: str = ""
    
    # Metric values
    value: float = 0.0
    target_value: float = 100.0
    compliance_score: float = 0.0
    
    # Context and metadata
    framework: str = ""
    control_reference: str = ""
    data_source: str = ""
    collection_method: str = "automated"
    
    # Classification and handling
    classification_level: str = "UNCLASSIFIED"
    
    # Quality indicators
    confidence_level: float = 1.0
    data_quality_score: float = 1.0
    
    # Aggregation metadata
    aggregation_level: DataAggregationLevel = DataAggregationLevel.RAW
    aggregated_from_count: int = 1
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for storage."""
        return {
            "point_id": self.point_id,
            "timestamp": self.timestamp.isoformat(),
            "metric_type": self.metric_type.value,
            "metric_name": self.metric_name,
            "value": self.value,
            "target_value": self.target_value,
            "compliance_score": self.compliance_score,
            "framework": self.framework,
            "control_reference": self.control_reference,
            "data_source": self.data_source,
            "collection_method": self.collection_method,
            "classification_level": self.classification_level,
            "confidence_level": self.confidence_level,
            "data_quality_score": self.data_quality_score,
            "aggregation_level": self.aggregation_level.value,
            "aggregated_from_count": self.aggregated_from_count
        }


@dataclass
class TrendAnalysis:
    """Trend analysis results for compliance metrics."""
    analysis_id: str = field(default_factory=lambda: str(uuid4()))
    analysis_timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    # Analysis parameters
    metric_type: ComplianceMetricType = ComplianceMetricType.OVERALL_POSTURE
    time_period: Tuple[datetime, datetime] = field(default_factory=lambda: (
        datetime.now(timezone.utc) - timedelta(days=30),
        datetime.now(timezone.utc)
    ))
    
    # Trend results
    trend_direction: TrendDirection = TrendDirection.STABLE
    trend_strength: float = 0.0  # 0-1 scale
    trend_confidence: float = 0.0  # Statistical confidence
    
    # Statistical measures
    slope: float = 0.0
    correlation_coefficient: float = 0.0
    p_value: float = 1.0
    
    # Variance analysis
    mean_value: float = 0.0
    standard_deviation: float = 0.0
    coefficient_of_variation: float = 0.0
    
    # Change analysis
    percent_change: float = 0.0
    absolute_change: float = 0.0
    change_rate_per_day: float = 0.0
    
    # Seasonality detection
    has_seasonality: bool = False
    seasonal_period: Optional[int] = None
    seasonal_strength: float = 0.0
    
    # Anomaly detection
    anomalies_detected: int = 0
    anomaly_periods: List[Tuple[datetime, datetime]] = field(default_factory=list)
    
    # Data quality
    data_points_analyzed: int = 0
    missing_data_percentage: float = 0.0
    data_quality_score: float = 1.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "analysis_id": self.analysis_id,
            "analysis_timestamp": self.analysis_timestamp.isoformat(),
            "metric_type": self.metric_type.value,
            "time_period": {
                "start": self.time_period[0].isoformat(),
                "end": self.time_period[1].isoformat()
            },
            "trend_direction": self.trend_direction.value,
            "trend_strength": self.trend_strength,
            "trend_confidence": self.trend_confidence,
            "slope": self.slope,
            "correlation_coefficient": self.correlation_coefficient,
            "p_value": self.p_value,
            "mean_value": self.mean_value,
            "standard_deviation": self.standard_deviation,
            "coefficient_of_variation": self.coefficient_of_variation,
            "percent_change": self.percent_change,
            "absolute_change": self.absolute_change,
            "change_rate_per_day": self.change_rate_per_day,
            "has_seasonality": self.has_seasonality,
            "seasonal_period": self.seasonal_period,
            "seasonal_strength": self.seasonal_strength,
            "anomalies_detected": self.anomalies_detected,
            "anomaly_periods": [
                {"start": period[0].isoformat(), "end": period[1].isoformat()}
                for period in self.anomaly_periods
            ],
            "data_points_analyzed": self.data_points_analyzed,
            "missing_data_percentage": self.missing_data_percentage,
            "data_quality_score": self.data_quality_score
        }


@dataclass
class ForecastResult:
    """Forecast results for compliance metrics."""
    forecast_id: str = field(default_factory=lambda: str(uuid4()))
    forecast_timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    # Forecast parameters
    metric_type: ComplianceMetricType = ComplianceMetricType.OVERALL_POSTURE
    historical_period: Tuple[datetime, datetime] = field(default_factory=lambda: (
        datetime.now(timezone.utc) - timedelta(days=30),
        datetime.now(timezone.utc)
    ))
    forecast_period: Tuple[datetime, datetime] = field(default_factory=lambda: (
        datetime.now(timezone.utc),
        datetime.now(timezone.utc) + timedelta(days=30)
    ))
    
    # Forecast data
    forecasted_values: List[Tuple[datetime, float]] = field(default_factory=list)
    confidence_intervals: List[Tuple[datetime, float, float]] = field(default_factory=list)  # timestamp, lower, upper
    
    # Model information
    model_type: str = "linear_regression"
    model_parameters: Dict[str, Any] = field(default_factory=dict)
    
    # Accuracy metrics
    forecast_accuracy: ForecastAccuracy = ForecastAccuracy.MEDIUM
    mean_absolute_error: float = 0.0
    root_mean_square_error: float = 0.0
    accuracy_percentage: float = 0.0
    
    # Risk analysis
    risk_periods: List[Tuple[datetime, datetime, str]] = field(default_factory=list)  # start, end, risk_level
    projected_violations: int = 0
    
    # Scenarios
    best_case_scenario: List[Tuple[datetime, float]] = field(default_factory=list)
    worst_case_scenario: List[Tuple[datetime, float]] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "forecast_id": self.forecast_id,
            "forecast_timestamp": self.forecast_timestamp.isoformat(),
            "metric_type": self.metric_type.value,
            "historical_period": {
                "start": self.historical_period[0].isoformat(),
                "end": self.historical_period[1].isoformat()
            },
            "forecast_period": {
                "start": self.forecast_period[0].isoformat(),
                "end": self.forecast_period[1].isoformat()
            },
            "forecasted_values": [
                {"timestamp": ts.isoformat(), "value": val}
                for ts, val in self.forecasted_values
            ],
            "confidence_intervals": [
                {"timestamp": ts.isoformat(), "lower": lower, "upper": upper}
                for ts, lower, upper in self.confidence_intervals
            ],
            "model_type": self.model_type,
            "model_parameters": self.model_parameters,
            "forecast_accuracy": self.forecast_accuracy.value,
            "mean_absolute_error": self.mean_absolute_error,
            "root_mean_square_error": self.root_mean_square_error,
            "accuracy_percentage": self.accuracy_percentage,
            "risk_periods": [
                {"start": start.isoformat(), "end": end.isoformat(), "risk_level": risk}
                for start, end, risk in self.risk_periods
            ],
            "projected_violations": self.projected_violations,
            "best_case_scenario": [
                {"timestamp": ts.isoformat(), "value": val}
                for ts, val in self.best_case_scenario
            ],
            "worst_case_scenario": [
                {"timestamp": ts.isoformat(), "value": val}
                for ts, val in self.worst_case_scenario
            ]
        }


class DatabaseManager:
    """Manages database operations for the compliance data warehouse."""
    
    def __init__(self, database_path: str = "/tmp/compliance_warehouse.db"):
        """Initialize database manager."""
        self.database_path = database_path
        self.connection_pool_size = 10
        self.connections_lock = Lock()
        
        # Ensure database file directory exists
        Path(database_path).parent.mkdir(parents=True, exist_ok=True)
        
        logger.info(f"Database manager initialized with path: {database_path}")
    
    async def initialize_database(self):
        """Initialize database schema."""
        try:
            async with aiosqlite.connect(self.database_path) as db:
                # Create tables
                await self._create_tables(db)
                await self._create_indexes(db)
                await db.commit()
                
            logger.info("Database schema initialized successfully")
            
        except Exception as e:
            logger.error(f"Error initializing database: {e}")
            raise
    
    async def _create_tables(self, db: aiosqlite.Connection):
        """Create database tables."""
        # Historical metrics table
        await db.execute("""
            CREATE TABLE IF NOT EXISTS historical_metrics (
                point_id TEXT PRIMARY KEY,
                timestamp DATETIME NOT NULL,
                metric_type TEXT NOT NULL,
                metric_name TEXT NOT NULL,
                value REAL NOT NULL,
                target_value REAL NOT NULL,
                compliance_score REAL NOT NULL,
                framework TEXT,
                control_reference TEXT,
                data_source TEXT,
                collection_method TEXT,
                classification_level TEXT DEFAULT 'UNCLASSIFIED',
                confidence_level REAL DEFAULT 1.0,
                data_quality_score REAL DEFAULT 1.0,
                aggregation_level TEXT DEFAULT 'raw',
                aggregated_from_count INTEGER DEFAULT 1,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Trend analyses table
        await db.execute("""
            CREATE TABLE IF NOT EXISTS trend_analyses (
                analysis_id TEXT PRIMARY KEY,
                analysis_timestamp DATETIME NOT NULL,
                metric_type TEXT NOT NULL,
                time_period_start DATETIME NOT NULL,
                time_period_end DATETIME NOT NULL,
                trend_direction TEXT NOT NULL,
                trend_strength REAL NOT NULL,
                trend_confidence REAL NOT NULL,
                slope REAL,
                correlation_coefficient REAL,
                p_value REAL,
                mean_value REAL,
                standard_deviation REAL,
                coefficient_of_variation REAL,
                percent_change REAL,
                absolute_change REAL,
                change_rate_per_day REAL,
                has_seasonality BOOLEAN DEFAULT 0,
                seasonal_period INTEGER,
                seasonal_strength REAL,
                anomalies_detected INTEGER DEFAULT 0,
                data_points_analyzed INTEGER,
                missing_data_percentage REAL,
                data_quality_score REAL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Forecasts table
        await db.execute("""
            CREATE TABLE IF NOT EXISTS forecasts (
                forecast_id TEXT PRIMARY KEY,
                forecast_timestamp DATETIME NOT NULL,
                metric_type TEXT NOT NULL,
                historical_period_start DATETIME NOT NULL,
                historical_period_end DATETIME NOT NULL,
                forecast_period_start DATETIME NOT NULL,
                forecast_period_end DATETIME NOT NULL,
                model_type TEXT NOT NULL,
                model_parameters TEXT,
                forecast_accuracy TEXT,
                mean_absolute_error REAL,
                root_mean_square_error REAL,
                accuracy_percentage REAL,
                projected_violations INTEGER DEFAULT 0,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Forecast values table (for time series data)
        await db.execute("""
            CREATE TABLE IF NOT EXISTS forecast_values (
                forecast_id TEXT NOT NULL,
                timestamp DATETIME NOT NULL,
                forecasted_value REAL NOT NULL,
                confidence_lower REAL,
                confidence_upper REAL,
                scenario_type TEXT DEFAULT 'base',
                PRIMARY KEY (forecast_id, timestamp, scenario_type),
                FOREIGN KEY (forecast_id) REFERENCES forecasts (forecast_id)
            )
        """)
        
        # Aggregated metrics table (for performance optimization)
        await db.execute("""
            CREATE TABLE IF NOT EXISTS aggregated_metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                metric_type TEXT NOT NULL,
                aggregation_level TEXT NOT NULL,
                time_bucket DATETIME NOT NULL,
                avg_value REAL,
                min_value REAL,
                max_value REAL,
                std_value REAL,
                count_values INTEGER,
                avg_compliance_score REAL,
                framework TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(metric_type, aggregation_level, time_bucket, framework)
            )
        """)
        
        # System performance metrics table
        await db.execute("""
            CREATE TABLE IF NOT EXISTS performance_metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME NOT NULL,
                metric_name TEXT NOT NULL,
                metric_value REAL NOT NULL,
                component TEXT,
                tags TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
    
    async def _create_indexes(self, db: aiosqlite.Connection):
        """Create database indexes for performance."""
        indexes = [
            "CREATE INDEX IF NOT EXISTS idx_historical_timestamp ON historical_metrics(timestamp)",
            "CREATE INDEX IF NOT EXISTS idx_historical_metric_type ON historical_metrics(metric_type)",
            "CREATE INDEX IF NOT EXISTS idx_historical_framework ON historical_metrics(framework)",
            "CREATE INDEX IF NOT EXISTS idx_trend_timestamp ON trend_analyses(analysis_timestamp)",
            "CREATE INDEX IF NOT EXISTS idx_trend_metric_type ON trend_analyses(metric_type)",
            "CREATE INDEX IF NOT EXISTS idx_forecast_timestamp ON forecasts(forecast_timestamp)",
            "CREATE INDEX IF NOT EXISTS idx_forecast_metric_type ON forecasts(metric_type)",
            "CREATE INDEX IF NOT EXISTS idx_aggregated_time ON aggregated_metrics(time_bucket)",
            "CREATE INDEX IF NOT EXISTS idx_aggregated_type ON aggregated_metrics(metric_type, aggregation_level)",
            "CREATE INDEX IF NOT EXISTS idx_performance_timestamp ON performance_metrics(timestamp)"
        ]
        
        for index_sql in indexes:
            await db.execute(index_sql)
    
    async def store_historical_metric(self, metric_point: HistoricalMetricPoint):
        """Store a historical metric point."""
        try:
            async with aiosqlite.connect(self.database_path) as db:
                await db.execute("""
                    INSERT OR REPLACE INTO historical_metrics (
                        point_id, timestamp, metric_type, metric_name, value, target_value,
                        compliance_score, framework, control_reference, data_source,
                        collection_method, classification_level, confidence_level,
                        data_quality_score, aggregation_level, aggregated_from_count
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    metric_point.point_id,
                    metric_point.timestamp,
                    metric_point.metric_type.value,
                    metric_point.metric_name,
                    metric_point.value,
                    metric_point.target_value,
                    metric_point.compliance_score,
                    metric_point.framework,
                    metric_point.control_reference,
                    metric_point.data_source,
                    metric_point.collection_method,
                    metric_point.classification_level,
                    metric_point.confidence_level,
                    metric_point.data_quality_score,
                    metric_point.aggregation_level.value,
                    metric_point.aggregated_from_count
                ))
                await db.commit()
                
        except Exception as e:
            logger.error(f"Error storing historical metric: {e}")
            raise
    
    async def store_multiple_historical_metrics(self, metric_points: List[HistoricalMetricPoint]):
        """Store multiple historical metric points efficiently."""
        try:
            async with aiosqlite.connect(self.database_path) as db:
                data = []
                for point in metric_points:
                    data.append((
                        point.point_id,
                        point.timestamp,
                        point.metric_type.value,
                        point.metric_name,
                        point.value,
                        point.target_value,
                        point.compliance_score,
                        point.framework,
                        point.control_reference,
                        point.data_source,
                        point.collection_method,
                        point.classification_level,
                        point.confidence_level,
                        point.data_quality_score,
                        point.aggregation_level.value,
                        point.aggregated_from_count
                    ))
                
                await db.executemany("""
                    INSERT OR REPLACE INTO historical_metrics (
                        point_id, timestamp, metric_type, metric_name, value, target_value,
                        compliance_score, framework, control_reference, data_source,
                        collection_method, classification_level, confidence_level,
                        data_quality_score, aggregation_level, aggregated_from_count
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, data)
                await db.commit()
                
            logger.info(f"Stored {len(metric_points)} historical metrics")
            
        except Exception as e:
            logger.error(f"Error storing multiple historical metrics: {e}")
            raise
    
    async def get_historical_metrics(
        self,
        metric_type: Optional[ComplianceMetricType] = None,
        time_range: Optional[Tuple[datetime, datetime]] = None,
        framework: Optional[str] = None,
        limit: int = 10000
    ) -> List[HistoricalMetricPoint]:
        """Retrieve historical metrics with filtering."""
        try:
            async with aiosqlite.connect(self.database_path) as db:
                # Build query
                query = "SELECT * FROM historical_metrics WHERE 1=1"
                params = []
                
                if metric_type:
                    query += " AND metric_type = ?"
                    params.append(metric_type.value)
                
                if time_range:
                    query += " AND timestamp BETWEEN ? AND ?"
                    params.extend([time_range[0], time_range[1]])
                
                if framework:
                    query += " AND framework = ?"
                    params.append(framework)
                
                query += " ORDER BY timestamp DESC LIMIT ?"
                params.append(limit)
                
                # Execute query
                async with db.execute(query, params) as cursor:
                    rows = await cursor.fetchall()
                
                # Convert to objects
                metrics = []
                columns = [desc[0] for desc in cursor.description]
                
                for row in rows:
                    row_dict = dict(zip(columns, row))
                    
                    metric_point = HistoricalMetricPoint(
                        point_id=row_dict['point_id'],
                        timestamp=datetime.fromisoformat(row_dict['timestamp']),
                        metric_type=ComplianceMetricType(row_dict['metric_type']),
                        metric_name=row_dict['metric_name'],
                        value=row_dict['value'],
                        target_value=row_dict['target_value'],
                        compliance_score=row_dict['compliance_score'],
                        framework=row_dict['framework'] or "",
                        control_reference=row_dict['control_reference'] or "",
                        data_source=row_dict['data_source'] or "",
                        collection_method=row_dict['collection_method'] or "automated",
                        classification_level=row_dict['classification_level'] or "UNCLASSIFIED",
                        confidence_level=row_dict['confidence_level'] or 1.0,
                        data_quality_score=row_dict['data_quality_score'] or 1.0,
                        aggregation_level=DataAggregationLevel(row_dict['aggregation_level']),
                        aggregated_from_count=row_dict['aggregated_from_count'] or 1
                    )
                    
                    metrics.append(metric_point)
                
                return metrics
                
        except Exception as e:
            logger.error(f"Error retrieving historical metrics: {e}")
            return []
    
    async def store_trend_analysis(self, trend_analysis: TrendAnalysis):
        """Store trend analysis results."""
        try:
            async with aiosqlite.connect(self.database_path) as db:
                await db.execute("""
                    INSERT OR REPLACE INTO trend_analyses (
                        analysis_id, analysis_timestamp, metric_type, time_period_start,
                        time_period_end, trend_direction, trend_strength, trend_confidence,
                        slope, correlation_coefficient, p_value, mean_value, standard_deviation,
                        coefficient_of_variation, percent_change, absolute_change,
                        change_rate_per_day, has_seasonality, seasonal_period, seasonal_strength,
                        anomalies_detected, data_points_analyzed, missing_data_percentage,
                        data_quality_score
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    trend_analysis.analysis_id,
                    trend_analysis.analysis_timestamp,
                    trend_analysis.metric_type.value,
                    trend_analysis.time_period[0],
                    trend_analysis.time_period[1],
                    trend_analysis.trend_direction.value,
                    trend_analysis.trend_strength,
                    trend_analysis.trend_confidence,
                    trend_analysis.slope,
                    trend_analysis.correlation_coefficient,
                    trend_analysis.p_value,
                    trend_analysis.mean_value,
                    trend_analysis.standard_deviation,
                    trend_analysis.coefficient_of_variation,
                    trend_analysis.percent_change,
                    trend_analysis.absolute_change,
                    trend_analysis.change_rate_per_day,
                    trend_analysis.has_seasonality,
                    trend_analysis.seasonal_period,
                    trend_analysis.seasonal_strength,
                    trend_analysis.anomalies_detected,
                    trend_analysis.data_points_analyzed,
                    trend_analysis.missing_data_percentage,
                    trend_analysis.data_quality_score
                ))
                await db.commit()
                
        except Exception as e:
            logger.error(f"Error storing trend analysis: {e}")
            raise
    
    async def store_forecast(self, forecast: ForecastResult):
        """Store forecast results."""
        try:
            async with aiosqlite.connect(self.database_path) as db:
                # Store main forecast record
                await db.execute("""
                    INSERT OR REPLACE INTO forecasts (
                        forecast_id, forecast_timestamp, metric_type, historical_period_start,
                        historical_period_end, forecast_period_start, forecast_period_end,
                        model_type, model_parameters, forecast_accuracy, mean_absolute_error,
                        root_mean_square_error, accuracy_percentage, projected_violations
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    forecast.forecast_id,
                    forecast.forecast_timestamp,
                    forecast.metric_type.value,
                    forecast.historical_period[0],
                    forecast.historical_period[1],
                    forecast.forecast_period[0],
                    forecast.forecast_period[1],
                    forecast.model_type,
                    json.dumps(forecast.model_parameters),
                    forecast.forecast_accuracy.value,
                    forecast.mean_absolute_error,
                    forecast.root_mean_square_error,
                    forecast.accuracy_percentage,
                    forecast.projected_violations
                ))
                
                # Store forecast values
                forecast_value_data = []
                
                # Base forecast values
                for timestamp, value in forecast.forecasted_values:
                    forecast_value_data.append((
                        forecast.forecast_id, timestamp, value, None, None, 'base'
                    ))
                
                # Confidence intervals
                for timestamp, lower, upper in forecast.confidence_intervals:
                    # Update existing base record or create confidence record
                    existing_base = next(
                        (item for item in forecast_value_data 
                         if item[1] == timestamp and item[5] == 'base'), 
                        None
                    )
                    if existing_base:
                        # Update the base record with confidence intervals
                        idx = forecast_value_data.index(existing_base)
                        forecast_value_data[idx] = (
                            forecast.forecast_id, timestamp, existing_base[2], lower, upper, 'base'
                        )
                
                # Best case scenario
                for timestamp, value in forecast.best_case_scenario:
                    forecast_value_data.append((
                        forecast.forecast_id, timestamp, value, None, None, 'best_case'
                    ))
                
                # Worst case scenario
                for timestamp, value in forecast.worst_case_scenario:
                    forecast_value_data.append((
                        forecast.forecast_id, timestamp, value, None, None, 'worst_case'
                    ))
                
                if forecast_value_data:
                    await db.executemany("""
                        INSERT OR REPLACE INTO forecast_values (
                            forecast_id, timestamp, forecasted_value, confidence_lower,
                            confidence_upper, scenario_type
                        ) VALUES (?, ?, ?, ?, ?, ?)
                    """, forecast_value_data)
                
                await db.commit()
                
        except Exception as e:
            logger.error(f"Error storing forecast: {e}")
            raise
    
    async def cleanup_old_data(self, retention_days: int = 2555):  # 7 years default
        """Clean up old data beyond retention period."""
        try:
            cutoff_date = datetime.now(timezone.utc) - timedelta(days=retention_days)
            
            async with aiosqlite.connect(self.database_path) as db:
                # Clean up historical metrics
                await db.execute(
                    "DELETE FROM historical_metrics WHERE timestamp < ?",
                    (cutoff_date,)
                )
                
                # Clean up old trend analyses
                await db.execute(
                    "DELETE FROM trend_analyses WHERE analysis_timestamp < ?",
                    (cutoff_date,)
                )
                
                # Clean up old forecasts
                await db.execute(
                    "DELETE FROM forecasts WHERE forecast_timestamp < ?",
                    (cutoff_date,)
                )
                
                # Clean up orphaned forecast values
                await db.execute("""
                    DELETE FROM forecast_values 
                    WHERE forecast_id NOT IN (SELECT forecast_id FROM forecasts)
                """)
                
                await db.commit()
                
            logger.info(f"Cleaned up data older than {retention_days} days")
            
        except Exception as e:
            logger.error(f"Error cleaning up old data: {e}")


class ComplianceDataWarehouse:
    """
    Main compliance data warehouse providing historical data aggregation,
    trend analysis, and forecasting capabilities.
    """
    
    def __init__(
        self,
        data_provider: ComplianceDataProvider,
        audit_orchestrator: IntegratedAuditOrchestrator,
        monitoring_system: EnhancedMonitoringSystem,
        database_path: str = "/tmp/compliance_warehouse.db"
    ):
        """Initialize compliance data warehouse."""
        self.data_provider = data_provider
        self.audit_orchestrator = audit_orchestrator
        self.monitoring_system = monitoring_system
        
        # Database management
        self.db_manager = DatabaseManager(database_path)
        
        # Data collection and processing
        self.collection_enabled = False
        self.collection_tasks: List[asyncio.Task] = []
        self.collection_interval_seconds = 300  # 5 minutes
        
        # Cache for performance
        self.metric_cache = {}
        self.cache_timestamps = {}
        self.cache_ttl_seconds = 60
        
        # Statistics and analytics
        self.analytics_lock = Lock()
        
        logger.info("Compliance data warehouse initialized")
    
    async def initialize(self):
        """Initialize the data warehouse."""
        try:
            await self.db_manager.initialize_database()
            logger.info("Data warehouse initialized successfully")
        except Exception as e:
            logger.error(f"Error initializing data warehouse: {e}")
            raise
    
    async def start_collection(self):
        """Start automatic data collection."""
        if self.collection_enabled:
            return
        
        self.collection_enabled = True
        
        # Start collection tasks
        self.collection_tasks = [
            asyncio.create_task(self._metric_collection_worker()),
            asyncio.create_task(self._aggregation_worker()),
            asyncio.create_task(self._cleanup_worker())
        ]
        
        logger.info("Data collection started")
    
    async def stop_collection(self):
        """Stop automatic data collection."""
        self.collection_enabled = False
        
        # Cancel collection tasks
        for task in self.collection_tasks:
            if not task.done():
                task.cancel()
        
        if self.collection_tasks:
            await asyncio.gather(*self.collection_tasks, return_exceptions=True)
        
        logger.info("Data collection stopped")
    
    async def _metric_collection_worker(self):
        """Worker task for collecting compliance metrics."""
        while self.collection_enabled:
            try:
                # Collect current compliance metrics
                current_metrics = await self.data_provider.get_compliance_metrics()
                
                # Convert to historical metric points
                historical_points = []
                current_time = datetime.now(timezone.utc)
                
                for metric in current_metrics:
                    historical_point = HistoricalMetricPoint(
                        timestamp=current_time,
                        metric_type=metric.metric_type,
                        metric_name=metric.metric_name,
                        value=metric.current_value,
                        target_value=metric.target_value,
                        compliance_score=metric.calculate_compliance_score(),
                        framework=metric.framework,
                        control_reference=metric.control_reference,
                        data_source="compliance_data_provider",
                        classification_level=metric.classification_level,
                        confidence_level=1.0,  # Assume high confidence for real-time data
                        data_quality_score=1.0
                    )
                    historical_points.append(historical_point)
                
                # Store in database
                if historical_points:
                    await self.db_manager.store_multiple_historical_metrics(historical_points)
                    logger.debug(f"Collected {len(historical_points)} compliance metrics")
                
                # Wait for next collection interval
                await asyncio.sleep(self.collection_interval_seconds)
                
            except Exception as e:
                logger.error(f"Error in metric collection worker: {e}")
                await asyncio.sleep(60.0)  # Wait before retrying
    
    async def _aggregation_worker(self):
        """Worker task for creating aggregated data views."""
        while self.collection_enabled:
            try:
                # Create hourly aggregations
                await self._create_aggregations(DataAggregationLevel.HOURLY)
                
                # Create daily aggregations (run less frequently)
                current_hour = datetime.now(timezone.utc).hour
                if current_hour == 0:  # Run at midnight
                    await self._create_aggregations(DataAggregationLevel.DAILY)
                    await self._create_aggregations(DataAggregationLevel.WEEKLY)
                    await self._create_aggregations(DataAggregationLevel.MONTHLY)
                
                # Wait for next aggregation cycle (1 hour)
                await asyncio.sleep(3600.0)
                
            except Exception as e:
                logger.error(f"Error in aggregation worker: {e}")
                await asyncio.sleep(1800.0)  # 30 minute retry delay
    
    async def _create_aggregations(self, aggregation_level: DataAggregationLevel):
        """Create aggregated data for specified level."""
        try:
            # Determine time bucket size
            if aggregation_level == DataAggregationLevel.HOURLY:
                time_delta = timedelta(hours=1)
                bucket_format = "%Y-%m-%d %H:00:00"
            elif aggregation_level == DataAggregationLevel.DAILY:
                time_delta = timedelta(days=1)
                bucket_format = "%Y-%m-%d 00:00:00"
            elif aggregation_level == DataAggregationLevel.WEEKLY:
                time_delta = timedelta(weeks=1)
                bucket_format = "%Y-%W"
            elif aggregation_level == DataAggregationLevel.MONTHLY:
                time_delta = timedelta(days=30)  # Approximate
                bucket_format = "%Y-%m-01 00:00:00"
            else:
                return
            
            # Get time range for aggregation
            end_time = datetime.now(timezone.utc)
            start_time = end_time - time_delta * 24  # Last 24 periods
            
            # Aggregate data by metric type and framework
            async with aiosqlite.connect(self.db_manager.database_path) as db:
                # Get distinct metric types and frameworks
                async with db.execute("""
                    SELECT DISTINCT metric_type, framework 
                    FROM historical_metrics 
                    WHERE timestamp BETWEEN ? AND ?
                """, (start_time, end_time)) as cursor:
                    combinations = await cursor.fetchall()
                
                for metric_type, framework in combinations:
                    framework = framework or ""
                    
                    # Calculate aggregations for each time bucket
                    async with db.execute("""
                        SELECT 
                            strftime(?, timestamp) as time_bucket,
                            AVG(value) as avg_value,
                            MIN(value) as min_value,
                            MAX(value) as max_value,
                            AVG(compliance_score) as avg_compliance_score,
                            COUNT(*) as count_values
                        FROM historical_metrics
                        WHERE metric_type = ? AND framework = ? 
                            AND timestamp BETWEEN ? AND ?
                        GROUP BY strftime(?, timestamp)
                    """, (bucket_format, metric_type, framework, start_time, end_time, bucket_format)) as cursor:
                        
                        aggregation_data = await cursor.fetchall()
                    
                    # Store aggregations
                    for bucket, avg_val, min_val, max_val, avg_score, count_val in aggregation_data:
                        try:
                            # Calculate standard deviation
                            async with db.execute("""
                                SELECT 
                                    AVG(POWER(value - ?, 2)) as variance
                                FROM historical_metrics
                                WHERE metric_type = ? AND framework = ?
                                    AND strftime(?, timestamp) = ?
                            """, (avg_val, metric_type, framework, bucket_format, bucket)) as var_cursor:
                                variance_result = await var_cursor.fetchone()
                                std_value = np.sqrt(variance_result[0]) if variance_result[0] else 0.0
                            
                            await db.execute("""
                                INSERT OR REPLACE INTO aggregated_metrics (
                                    metric_type, aggregation_level, time_bucket, 
                                    avg_value, min_value, max_value, std_value,
                                    count_values, avg_compliance_score, framework
                                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                            """, (
                                metric_type, aggregation_level.value, bucket,
                                avg_val, min_val, max_val, std_value,
                                count_val, avg_score, framework
                            ))
                            
                        except Exception as e:
                            logger.warning(f"Error storing aggregation: {e}")
                            continue
                
                await db.commit()
            
            logger.debug(f"Created {aggregation_level.value} aggregations")
            
        except Exception as e:
            logger.error(f"Error creating aggregations: {e}")
    
    async def _cleanup_worker(self):
        """Worker task for data cleanup."""
        while self.collection_enabled:
            try:
                # Run cleanup daily
                await self.db_manager.cleanup_old_data()
                
                # Wait for next cleanup (24 hours)
                await asyncio.sleep(86400.0)
                
            except Exception as e:
                logger.error(f"Error in cleanup worker: {e}")
                await asyncio.sleep(3600.0)  # 1 hour retry delay
    
    async def get_historical_data(
        self,
        metric_type: ComplianceMetricType,
        time_range: Tuple[datetime, datetime],
        aggregation_level: DataAggregationLevel = DataAggregationLevel.RAW,
        framework: Optional[str] = None
    ) -> List[HistoricalMetricPoint]:
        """Get historical compliance data."""
        try:
            if aggregation_level == DataAggregationLevel.RAW:
                return await self.db_manager.get_historical_metrics(
                    metric_type=metric_type,
                    time_range=time_range,
                    framework=framework
                )
            else:
                # Get aggregated data
                return await self._get_aggregated_data(
                    metric_type, time_range, aggregation_level, framework
                )
                
        except Exception as e:
            logger.error(f"Error getting historical data: {e}")
            return []
    
    async def _get_aggregated_data(
        self,
        metric_type: ComplianceMetricType,
        time_range: Tuple[datetime, datetime],
        aggregation_level: DataAggregationLevel,
        framework: Optional[str] = None
    ) -> List[HistoricalMetricPoint]:
        """Get aggregated historical data."""
        try:
            async with aiosqlite.connect(self.db_manager.database_path) as db:
                query = """
                    SELECT * FROM aggregated_metrics 
                    WHERE metric_type = ? AND aggregation_level = ?
                        AND time_bucket BETWEEN ? AND ?
                """
                params = [metric_type.value, aggregation_level.value, time_range[0], time_range[1]]
                
                if framework:
                    query += " AND framework = ?"
                    params.append(framework)
                
                query += " ORDER BY time_bucket"
                
                async with db.execute(query, params) as cursor:
                    rows = await cursor.fetchall()
                
                # Convert to HistoricalMetricPoint objects
                historical_points = []
                for row in rows:
                    point = HistoricalMetricPoint(
                        timestamp=datetime.fromisoformat(row[3]),  # time_bucket
                        metric_type=metric_type,
                        metric_name=f"Aggregated {metric_type.value}",
                        value=row[4],  # avg_value
                        target_value=100.0,  # Default target
                        compliance_score=row[9] or 0.0,  # avg_compliance_score
                        framework=row[10] or "",  # framework
                        data_source="aggregated",
                        aggregation_level=aggregation_level,
                        aggregated_from_count=row[8] or 1  # count_values
                    )
                    historical_points.append(point)
                
                return historical_points
                
        except Exception as e:
            logger.error(f"Error getting aggregated data: {e}")
            return []
    
    async def analyze_trends(
        self,
        metric_type: ComplianceMetricType,
        time_range: Tuple[datetime, datetime],
        framework: Optional[str] = None
    ) -> TrendAnalysis:
        """Analyze trends for a compliance metric."""
        try:
            # Get historical data
            historical_data = await self.get_historical_data(
                metric_type, time_range, DataAggregationLevel.RAW, framework
            )
            
            if len(historical_data) < 2:
                # Not enough data for trend analysis
                return TrendAnalysis(
                    metric_type=metric_type,
                    time_period=time_range,
                    trend_direction=TrendDirection.UNKNOWN,
                    data_points_analyzed=len(historical_data)
                )
            
            # Prepare data for analysis
            timestamps = [point.timestamp for point in historical_data]
            values = [point.compliance_score for point in historical_data]
            
            # Convert timestamps to numeric values (days since first point)
            base_time = timestamps[0]
            time_numeric = [(ts - base_time).total_seconds() / 86400 for ts in timestamps]  # Days
            
            # Calculate linear regression
            slope, intercept, r_value, p_value, std_err = stats.linregress(time_numeric, values)
            
            # Determine trend direction
            if abs(slope) < 0.1:  # Very small slope
                trend_direction = TrendDirection.STABLE
                trend_strength = 0.0
            elif slope > 0:
                trend_direction = TrendDirection.IMPROVING
                trend_strength = min(1.0, abs(slope) / 10)  # Normalize to 0-1
            else:
                trend_direction = TrendDirection.DECLINING
                trend_strength = min(1.0, abs(slope) / 10)
            
            # Check for volatility
            cv = np.std(values) / np.mean(values) if np.mean(values) > 0 else 0
            if cv > 0.3:  # High coefficient of variation
                trend_direction = TrendDirection.VOLATILE
                trend_strength = cv
            
            # Calculate statistics
            mean_value = np.mean(values)
            std_dev = np.std(values)
            
            # Calculate changes
            first_value = values[0]
            last_value = values[-1]
            percent_change = ((last_value - first_value) / first_value * 100) if first_value != 0 else 0
            absolute_change = last_value - first_value
            
            # Calculate change rate per day
            total_days = (time_range[1] - time_range[0]).total_seconds() / 86400
            change_rate_per_day = absolute_change / total_days if total_days > 0 else 0
            
            # Simple anomaly detection (values beyond 2 standard deviations)
            anomalies = []
            anomaly_threshold = 2.0
            for i, value in enumerate(values):
                if abs(value - mean_value) > anomaly_threshold * std_dev:
                    anomaly_start = timestamps[i] - timedelta(hours=1)
                    anomaly_end = timestamps[i] + timedelta(hours=1)
                    anomalies.append((anomaly_start, anomaly_end))
            
            # Create trend analysis result
            trend_analysis = TrendAnalysis(
                metric_type=metric_type,
                time_period=time_range,
                trend_direction=trend_direction,
                trend_strength=trend_strength,
                trend_confidence=1 - p_value,  # Higher confidence = lower p-value
                slope=slope,
                correlation_coefficient=r_value,
                p_value=p_value,
                mean_value=mean_value,
                standard_deviation=std_dev,
                coefficient_of_variation=cv,
                percent_change=percent_change,
                absolute_change=absolute_change,
                change_rate_per_day=change_rate_per_day,
                anomalies_detected=len(anomalies),
                anomaly_periods=anomalies,
                data_points_analyzed=len(historical_data),
                missing_data_percentage=0.0,  # TODO: Calculate based on expected data points
                data_quality_score=1.0  # TODO: Calculate based on data quality indicators
            )
            
            # Store trend analysis
            await self.db_manager.store_trend_analysis(trend_analysis)
            
            return trend_analysis
            
        except Exception as e:
            logger.error(f"Error analyzing trends: {e}")
            return TrendAnalysis(
                metric_type=metric_type,
                time_period=time_range,
                trend_direction=TrendDirection.UNKNOWN
            )
    
    async def generate_forecast(
        self,
        metric_type: ComplianceMetricType,
        historical_period: Tuple[datetime, datetime],
        forecast_period: Tuple[datetime, datetime],
        framework: Optional[str] = None
    ) -> ForecastResult:
        """Generate forecast for a compliance metric."""
        try:
            # Get historical data
            historical_data = await self.get_historical_data(
                metric_type, historical_period, DataAggregationLevel.RAW, framework
            )
            
            if len(historical_data) < 10:  # Need minimum data for forecasting
                return ForecastResult(
                    metric_type=metric_type,
                    historical_period=historical_period,
                    forecast_period=forecast_period,
                    forecast_accuracy=ForecastAccuracy.UNRELIABLE,
                    forecasted_values=[],
                    model_type="insufficient_data"
                )
            
            # Prepare data
            timestamps = [point.timestamp for point in historical_data]
            values = [point.compliance_score for point in historical_data]
            
            # Convert timestamps to numeric (days since first point)
            base_time = timestamps[0]
            time_numeric = np.array([(ts - base_time).total_seconds() / 86400 for ts in timestamps])
            values_array = np.array(values)
            
            # Simple linear regression forecast
            slope, intercept, r_value, p_value, std_err = stats.linregress(time_numeric, values_array)
            
            # Generate forecast points
            forecast_start_days = (forecast_period[0] - base_time).total_seconds() / 86400
            forecast_end_days = (forecast_period[1] - base_time).total_seconds() / 86400
            
            # Generate daily forecast points
            forecast_days = np.arange(forecast_start_days, forecast_end_days, 1.0)
            forecast_timestamps = [base_time + timedelta(days=float(day)) for day in forecast_days]
            
            # Calculate forecasted values
            forecasted_vals = slope * forecast_days + intercept
            forecasted_values = list(zip(forecast_timestamps, forecasted_vals))
            
            # Calculate confidence intervals (using standard error)
            confidence_level = 1.96  # 95% confidence
            confidence_margin = confidence_level * std_err * np.ones_like(forecast_days)
            
            confidence_intervals = [
                (ts, val - margin, val + margin)
                for ts, val, margin in zip(forecast_timestamps, forecasted_vals, confidence_margin)
            ]
            
            # Generate scenarios
            # Best case: upper confidence bound
            best_case = [(ts, val + margin) for ts, val, margin in 
                        zip(forecast_timestamps, forecasted_vals, confidence_margin)]
            
            # Worst case: lower confidence bound
            worst_case = [(ts, val - margin) for ts, val, margin in 
                         zip(forecast_timestamps, forecasted_vals, confidence_margin)]
            
            # Assess forecast accuracy based on correlation
            if abs(r_value) > 0.8:
                accuracy = ForecastAccuracy.HIGH
                accuracy_pct = 90 + abs(r_value) * 10
            elif abs(r_value) > 0.6:
                accuracy = ForecastAccuracy.MEDIUM
                accuracy_pct = 70 + abs(r_value) * 20
            elif abs(r_value) > 0.3:
                accuracy = ForecastAccuracy.LOW
                accuracy_pct = 50 + abs(r_value) * 20
            else:
                accuracy = ForecastAccuracy.UNRELIABLE
                accuracy_pct = 25 + abs(r_value) * 25
            
            # Calculate error metrics (simplified)
            mae = np.mean(np.abs(values_array - (slope * time_numeric + intercept)))
            rmse = np.sqrt(np.mean((values_array - (slope * time_numeric + intercept)) ** 2))
            
            # Identify risk periods (forecast values below thresholds)
            risk_periods = []
            for ts, val in forecasted_values:
                if val < 75:  # Below acceptable threshold
                    risk_start = ts - timedelta(hours=12)
                    risk_end = ts + timedelta(hours=12)
                    risk_level = "critical" if val < 60 else "warning"
                    risk_periods.append((risk_start, risk_end, risk_level))
            
            # Count projected violations
            projected_violations = sum(1 for _, val in forecasted_values if val < 85)
            
            # Create forecast result
            forecast_result = ForecastResult(
                metric_type=metric_type,
                historical_period=historical_period,
                forecast_period=forecast_period,
                forecasted_values=forecasted_values,
                confidence_intervals=confidence_intervals,
                model_type="linear_regression",
                model_parameters={
                    "slope": slope,
                    "intercept": intercept,
                    "r_value": r_value,
                    "p_value": p_value,
                    "std_err": std_err
                },
                forecast_accuracy=accuracy,
                mean_absolute_error=mae,
                root_mean_square_error=rmse,
                accuracy_percentage=accuracy_pct,
                risk_periods=risk_periods,
                projected_violations=projected_violations,
                best_case_scenario=best_case,
                worst_case_scenario=worst_case
            )
            
            # Store forecast
            await self.db_manager.store_forecast(forecast_result)
            
            return forecast_result
            
        except Exception as e:
            logger.error(f"Error generating forecast: {e}")
            return ForecastResult(
                metric_type=metric_type,
                historical_period=historical_period,
                forecast_period=forecast_period,
                forecast_accuracy=ForecastAccuracy.UNRELIABLE,
                model_type="error"
            )
    
    async def get_compliance_summary(
        self,
        time_range: Tuple[datetime, datetime],
        aggregation_level: DataAggregationLevel = DataAggregationLevel.DAILY
    ) -> Dict[str, Any]:
        """Get comprehensive compliance summary for time range."""
        try:
            summary = {
                "time_range": {
                    "start": time_range[0].isoformat(),
                    "end": time_range[1].isoformat()
                },
                "aggregation_level": aggregation_level.value,
                "metrics_summary": {},
                "overall_trends": {},
                "forecasts": {},
                "risk_analysis": {}
            }
            
            # Get data for all metric types
            for metric_type in ComplianceMetricType:
                try:
                    # Get historical data
                    historical_data = await self.get_historical_data(
                        metric_type, time_range, aggregation_level
                    )
                    
                    if historical_data:
                        values = [point.compliance_score for point in historical_data]
                        
                        summary["metrics_summary"][metric_type.value] = {
                            "data_points": len(historical_data),
                            "current_value": values[-1] if values else 0,
                            "average_value": np.mean(values),
                            "min_value": np.min(values),
                            "max_value": np.max(values),
                            "std_deviation": np.std(values),
                            "trend": "improving" if len(values) > 1 and values[-1] > values[0] else "declining"
                        }
                        
                        # Generate trend analysis
                        trend_analysis = await self.analyze_trends(metric_type, time_range)
                        summary["overall_trends"][metric_type.value] = {
                            "direction": trend_analysis.trend_direction.value,
                            "strength": trend_analysis.trend_strength,
                            "confidence": trend_analysis.trend_confidence
                        }
                
                except Exception as e:
                    logger.warning(f"Error processing metric {metric_type}: {e}")
                    continue
            
            return summary
            
        except Exception as e:
            logger.error(f"Error generating compliance summary: {e}")
            return {"error": str(e)}
    
    async def health_check(self) -> Dict[str, Any]:
        """Perform health check of data warehouse."""
        try:
            async with aiosqlite.connect(self.db_manager.database_path) as db:
                # Count records in main tables
                async with db.execute("SELECT COUNT(*) FROM historical_metrics") as cursor:
                    historical_count = (await cursor.fetchone())[0]
                
                async with db.execute("SELECT COUNT(*) FROM trend_analyses") as cursor:
                    trends_count = (await cursor.fetchone())[0]
                
                async with db.execute("SELECT COUNT(*) FROM forecasts") as cursor:
                    forecasts_count = (await cursor.fetchone())[0]
                
                # Get latest data timestamp
                async with db.execute("SELECT MAX(timestamp) FROM historical_metrics") as cursor:
                    latest_data = (await cursor.fetchone())[0]
            
            return {
                "status": "healthy",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "collection_enabled": self.collection_enabled,
                "database_path": self.db_manager.database_path,
                "data_counts": {
                    "historical_metrics": historical_count,
                    "trend_analyses": trends_count,
                    "forecasts": forecasts_count
                },
                "latest_data_timestamp": latest_data,
                "collection_interval_seconds": self.collection_interval_seconds
            }
            
        except Exception as e:
            return {
                "status": "unhealthy",
                "error": str(e),
                "timestamp": datetime.now(timezone.utc).isoformat()
            }


# Data warehouse manager for easy initialization
class DataWarehouseManager:
    """Manager class for easy initialization of the data warehouse system."""
    
    def __init__(
        self,
        data_provider: ComplianceDataProvider,
        audit_orchestrator: IntegratedAuditOrchestrator,
        monitoring_system: EnhancedMonitoringSystem,
        database_path: str = "/tmp/compliance_warehouse.db"
    ):
        """Initialize data warehouse manager."""
        self.data_warehouse = ComplianceDataWarehouse(
            data_provider=data_provider,
            audit_orchestrator=audit_orchestrator,
            monitoring_system=monitoring_system,
            database_path=database_path
        )
        
        logger.info("Data warehouse manager initialized")
    
    async def start(self):
        """Start the data warehouse system."""
        await self.data_warehouse.initialize()
        await self.data_warehouse.start_collection()
        logger.info("Data warehouse system started")
    
    async def stop(self):
        """Stop the data warehouse system."""
        await self.data_warehouse.stop_collection()
        logger.info("Data warehouse system stopped")
    
    def get_data_warehouse(self) -> ComplianceDataWarehouse:
        """Get the data warehouse instance."""
        return self.data_warehouse


# Factory function
def create_data_warehouse_manager(
    data_provider: ComplianceDataProvider,
    audit_orchestrator: IntegratedAuditOrchestrator,
    monitoring_system: EnhancedMonitoringSystem,
    database_path: str = "/tmp/compliance_warehouse.db"
) -> DataWarehouseManager:
    """Create and initialize data warehouse manager."""
    return DataWarehouseManager(
        data_provider=data_provider,
        audit_orchestrator=audit_orchestrator,
        monitoring_system=monitoring_system,
        database_path=database_path
    )


if __name__ == "__main__":
    # Example usage
    print("Compliance Data Warehouse - see code for usage examples")