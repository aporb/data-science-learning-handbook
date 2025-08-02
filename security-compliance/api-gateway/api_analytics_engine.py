"""
API Analytics Engine for DoD Environments

This module provides comprehensive usage analytics, behavioral analysis, and business
intelligence for the DoD API Gateway Integration. It processes large volumes of API
request data to provide actionable insights for operational decisions.

Key Features:
- Real-time and batch analytics processing
- User behavior analysis and segmentation
- API usage pattern detection and forecasting
- Performance trend analysis and capacity planning
- Business intelligence reporting and dashboards
- Machine learning-based insights and predictions
- Geographic and temporal usage analysis

Security Standards:
- DoD analytics and data processing requirements
- NIST 800-53 analytics controls
- Privacy protection for user data
- Secure data aggregation and reporting
"""

import asyncio
import json
import logging
import time
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple, Union
from dataclasses import dataclass, asdict
from enum import Enum
from collections import defaultdict, deque
import statistics
import math

import pandas as pd
import numpy as np
from sklearn.cluster import KMeans, DBSCAN
from sklearn.preprocessing import StandardScaler, MinMaxScaler
from sklearn.ensemble import IsolationForest
from sklearn.decomposition import PCA
from scipy import stats
from scipy.signal import find_peaks
import aioredis

# Import from existing modules
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from audits.audit_logger import AuditLogger


class AnalyticsTimeframe(Enum):
    """Analytics timeframe options."""
    REAL_TIME = "real_time"
    HOURLY = "hourly"
    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"


class UserSegment(Enum):
    """User behavior segments."""
    LIGHT_USER = "light_user"
    MODERATE_USER = "moderate_user"
    HEAVY_USER = "heavy_user"
    POWER_USER = "power_user"
    IRREGULAR_USER = "irregular_user"


class TrendDirection(Enum):
    """Trend direction indicators."""
    INCREASING = "increasing"
    DECREASING = "decreasing"
    STABLE = "stable"
    VOLATILE = "volatile"


@dataclass
class UsagePattern:
    """API usage pattern definition."""
    pattern_id: str
    pattern_type: str
    description: str
    frequency: float
    confidence_score: float
    detected_at: datetime
    endpoints: List[str]
    user_segments: List[UserSegment]
    temporal_characteristics: Dict[str, Any]


@dataclass
class UserBehaviorProfile:
    """User behavior analysis profile."""
    user_id: str
    segment: UserSegment
    total_requests: int
    unique_endpoints: int
    average_session_duration: float
    peak_usage_hours: List[int]
    preferred_endpoints: List[str]
    request_patterns: Dict[str, Any]
    risk_score: float
    last_activity: datetime


@dataclass
class APIEndpointAnalytics:
    """Analytics for specific API endpoints."""
    endpoint: str
    total_requests: int
    unique_users: int
    average_response_time: float
    error_rate: float
    peak_usage_times: List[int]
    user_distribution: Dict[UserSegment, int]
    trend_direction: TrendDirection
    capacity_utilization: float
    business_value_score: float


@dataclass
class PredictiveInsight:
    """Predictive analytics insight."""
    insight_id: str
    insight_type: str
    title: str
    description: str
    confidence: float
    impact_level: str
    recommendations: List[str]
    predicted_timeframe: str
    supporting_data: Dict[str, Any]
    created_at: datetime


class RealTimeAnalyticsProcessor:
    """Real-time analytics processing engine."""
    
    def __init__(self, window_size: int = 300):  # 5 minutes
        self.window_size = window_size
        self.request_buffer = deque(maxlen=10000)
        self.metrics_cache = {}
        self.pattern_detector = APIPatternDetector()
        
    async def process_request(self, request_data: Dict[str, Any]) -> None:
        """Process incoming request for real-time analytics."""
        self.request_buffer.append(request_data)
        
        # Update real-time metrics
        await self._update_real_time_metrics(request_data)
        
        # Detect patterns if buffer is large enough
        if len(self.request_buffer) > 100:
            await self._detect_real_time_patterns()
    
    async def _update_real_time_metrics(self, request_data: Dict[str, Any]) -> None:
        """Update real-time metrics."""
        current_time = datetime.utcnow()
        window_start = current_time - timedelta(seconds=self.window_size)
        
        # Filter requests in current window
        window_requests = [
            req for req in self.request_buffer
            if req.get('timestamp', datetime.min) >= window_start
        ]
        
        # Calculate metrics
        self.metrics_cache.update({
            'requests_per_second': len(window_requests) / self.window_size,
            'unique_users': len(set(req.get('user_id') for req in window_requests if req.get('user_id'))),
            'error_rate': len([req for req in window_requests if req.get('status_code', 200) >= 400]) / len(window_requests) if window_requests else 0,
            'avg_response_time': statistics.mean([req.get('response_time', 0) for req in window_requests]) if window_requests else 0,
            'timestamp': current_time.isoformat()
        })
    
    async def _detect_real_time_patterns(self) -> None:
        """Detect patterns in real-time data."""
        try:
            recent_requests = list(self.request_buffer)[-1000:]  # Last 1000 requests
            patterns = await self.pattern_detector.detect_patterns(recent_requests)
            
            # Store patterns for further analysis
            for pattern in patterns:
                if pattern.confidence_score > 0.7:  # High confidence patterns only
                    await self._store_pattern(pattern)
                    
        except Exception as e:
            logging.error(f"Real-time pattern detection failed: {e}")
    
    async def _store_pattern(self, pattern: UsagePattern) -> None:
        """Store detected pattern."""
        # Implementation would store pattern in database/cache
        pass
    
    def get_real_time_metrics(self) -> Dict[str, Any]:
        """Get current real-time metrics."""
        return self.metrics_cache.copy()


class APIPatternDetector:
    """Advanced pattern detection for API usage."""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.scaler = StandardScaler()
        
    async def detect_patterns(self, request_data: List[Dict]) -> List[UsagePattern]:
        """Detect usage patterns in request data."""
        patterns = []
        
        try:
            if len(request_data) < 50:
                return patterns
            
            # Convert to DataFrame for analysis
            df = pd.DataFrame(request_data)
            
            # Detect temporal patterns
            temporal_patterns = await self._detect_temporal_patterns(df)
            patterns.extend(temporal_patterns)
            
            # Detect endpoint usage patterns
            endpoint_patterns = await self._detect_endpoint_patterns(df)
            patterns.extend(endpoint_patterns)
            
            # Detect user behavior patterns
            user_patterns = await self._detect_user_patterns(df)
            patterns.extend(user_patterns)
            
            # Detect anomalous patterns
            anomaly_patterns = await self._detect_anomaly_patterns(df)
            patterns.extend(anomaly_patterns)
            
        except Exception as e:
            self.logger.error(f"Pattern detection failed: {e}")
        
        return patterns
    
    async def _detect_temporal_patterns(self, df: pd.DataFrame) -> List[UsagePattern]:
        """Detect temporal usage patterns."""
        patterns = []
        
        try:
            if 'timestamp' not in df.columns:
                return patterns
            
            # Convert timestamp to datetime if it's not already
            df['timestamp'] = pd.to_datetime(df['timestamp'])
            
            # Hourly patterns
            hourly_counts = df.groupby(df['timestamp'].dt.hour).size()
            
            # Find peaks in hourly usage
            peaks, _ = find_peaks(hourly_counts.values, height=hourly_counts.mean())
            
            if len(peaks) > 0:
                peak_hours = [hourly_counts.index[i] for i in peaks]
                pattern = UsagePattern(
                    pattern_id=str(uuid.uuid4()),
                    pattern_type="temporal_peak",
                    description=f"Peak usage hours: {peak_hours}",
                    frequency=len(peaks) / 24,
                    confidence_score=0.8,
                    detected_at=datetime.utcnow(),
                    endpoints=df['endpoint'].unique().tolist() if 'endpoint' in df.columns else [],
                    user_segments=[],
                    temporal_characteristics={
                        'peak_hours': peak_hours,
                        'peak_intensity': float(hourly_counts.iloc[peaks].mean()),
                        'baseline': float(hourly_counts.mean())
                    }
                )
                patterns.append(pattern)
            
            # Daily patterns (if data spans multiple days)
            if df['timestamp'].dt.date.nunique() > 1:
                daily_counts = df.groupby(df['timestamp'].dt.date).size()
                
                # Detect weekly patterns
                if len(daily_counts) >= 7:
                    weekly_pattern = self._analyze_weekly_pattern(daily_counts)
                    if weekly_pattern:
                        patterns.append(weekly_pattern)
                        
        except Exception as e:
            self.logger.error(f"Temporal pattern detection failed: {e}")
        
        return patterns
    
    async def _detect_endpoint_patterns(self, df: pd.DataFrame) -> List[UsagePattern]:
        """Detect endpoint usage patterns."""
        patterns = []
        
        try:
            if 'endpoint' not in df.columns:
                return patterns
            
            endpoint_counts = df['endpoint'].value_counts()
            
            # Detect dominant endpoints (Pareto principle)
            total_requests = len(df)
            cumulative_percentage = (endpoint_counts.cumsum() / total_requests * 100)
            
            # Find endpoints that make up 80% of traffic
            dominant_endpoints = cumulative_percentage[cumulative_percentage <= 80].index.tolist()
            
            if len(dominant_endpoints) > 0:
                pattern = UsagePattern(
                    pattern_id=str(uuid.uuid4()),
                    pattern_type="endpoint_dominance",
                    description=f"Top {len(dominant_endpoints)} endpoints account for 80% of traffic",
                    frequency=len(dominant_endpoints) / endpoint_counts.nunique(),
                    confidence_score=0.9,
                    detected_at=datetime.utcnow(),
                    endpoints=dominant_endpoints,
                    user_segments=[],
                    temporal_characteristics={
                        'usage_distribution': endpoint_counts.head(10).to_dict()
                    }
                )
                patterns.append(pattern)
                
        except Exception as e:
            self.logger.error(f"Endpoint pattern detection failed: {e}")
        
        return patterns
    
    async def _detect_user_patterns(self, df: pd.DataFrame) -> List[UsagePattern]:
        """Detect user behavior patterns."""
        patterns = []
        
        try:
            if 'user_id' not in df.columns:
                return patterns
            
            user_activity = df.groupby('user_id').agg({
                'endpoint': 'nunique',
                'timestamp': 'count'
            }).rename(columns={'endpoint': 'unique_endpoints', 'timestamp': 'request_count'})
            
            # Cluster users based on activity
            if len(user_activity) > 10:
                features = user_activity[['unique_endpoints', 'request_count']].values
                scaled_features = self.scaler.fit_transform(features)
                
                # Use KMeans for user segmentation
                n_clusters = min(5, len(user_activity) // 3)
                if n_clusters >= 2:
                    kmeans = KMeans(n_clusters=n_clusters, random_state=42)
                    clusters = kmeans.fit_predict(scaled_features)
                    
                    # Analyze clusters
                    for cluster_id in range(n_clusters):
                        cluster_users = user_activity[clusters == cluster_id]
                        
                        pattern = UsagePattern(
                            pattern_id=str(uuid.uuid4()),
                            pattern_type="user_behavior_cluster",
                            description=f"User cluster {cluster_id}: {len(cluster_users)} users",
                            frequency=len(cluster_users) / len(user_activity),
                            confidence_score=0.7,
                            detected_at=datetime.utcnow(),
                            endpoints=[],
                            user_segments=[],
                            temporal_characteristics={
                                'cluster_id': cluster_id,
                                'user_count': len(cluster_users),
                                'avg_requests': float(cluster_users['request_count'].mean()),
                                'avg_endpoints': float(cluster_users['unique_endpoints'].mean())
                            }
                        )
                        patterns.append(pattern)
                        
        except Exception as e:
            self.logger.error(f"User pattern detection failed: {e}")
        
        return patterns
    
    async def _detect_anomaly_patterns(self, df: pd.DataFrame) -> List[UsagePattern]:
        """Detect anomalous usage patterns."""
        patterns = []
        
        try:
            if len(df) < 100:
                return patterns
            
            # Response time anomalies
            if 'response_time' in df.columns:
                response_times = df['response_time'].values.reshape(-1, 1)
                
                # Use Isolation Forest for anomaly detection
                isolation_forest = IsolationForest(contamination=0.1, random_state=42)
                anomalies = isolation_forest.fit_predict(response_times)
                
                anomaly_count = (anomalies == -1).sum()
                
                if anomaly_count > 0:
                    pattern = UsagePattern(
                        pattern_id=str(uuid.uuid4()),
                        pattern_type="response_time_anomaly",
                        description=f"{anomaly_count} response time anomalies detected",
                        frequency=anomaly_count / len(df),
                        confidence_score=0.8,
                        detected_at=datetime.utcnow(),
                        endpoints=[],
                        user_segments=[],
                        temporal_characteristics={
                            'anomaly_count': anomaly_count,
                            'anomaly_percentage': float(anomaly_count / len(df) * 100),
                            'avg_normal_response_time': float(df[anomalies == 1]['response_time'].mean()) if (anomalies == 1).any() else 0,
                            'avg_anomaly_response_time': float(df[anomalies == -1]['response_time'].mean()) if (anomalies == -1).any() else 0
                        }
                    )
                    patterns.append(pattern)
                    
        except Exception as e:
            self.logger.error(f"Anomaly pattern detection failed: {e}")
        
        return patterns
    
    def _analyze_weekly_pattern(self, daily_counts: pd.Series) -> Optional[UsagePattern]:
        """Analyze weekly usage patterns."""
        try:
            # Convert index to datetime if it's not already
            if not isinstance(daily_counts.index[0], pd.Timestamp):
                daily_counts.index = pd.to_datetime(daily_counts.index)
            
            # Group by day of week
            weekly_pattern = daily_counts.groupby(daily_counts.index.dayofweek).mean()
            
            # Calculate coefficient of variation to determine pattern strength
            cv = weekly_pattern.std() / weekly_pattern.mean()
            
            if cv > 0.2:  # Significant weekly variation
                return UsagePattern(
                    pattern_id=str(uuid.uuid4()),
                    pattern_type="weekly_pattern",
                    description="Weekly usage pattern detected",
                    frequency=1.0,  # Weekly pattern
                    confidence_score=min(cv, 1.0),
                    detected_at=datetime.utcnow(),
                    endpoints=[],
                    user_segments=[],
                    temporal_characteristics={
                        'weekly_distribution': weekly_pattern.to_dict(),
                        'coefficient_of_variation': float(cv),
                        'peak_day': int(weekly_pattern.idxmax()),
                        'low_day': int(weekly_pattern.idxmin())
                    }
                )
        except Exception as e:
            logging.error(f"Weekly pattern analysis failed: {e}")
        
        return None


class UserBehaviorAnalyzer:
    """Analyzes user behavior and creates user profiles."""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.user_profiles: Dict[str, UserBehaviorProfile] = {}
        
    async def analyze_user_behavior(self, request_data: List[Dict]) -> Dict[str, UserBehaviorProfile]:
        """Analyze user behavior and create profiles."""
        try:
            if not request_data:
                return {}
            
            df = pd.DataFrame(request_data)
            
            if 'user_id' not in df.columns:
                return {}
            
            # Filter out null user IDs
            df = df[df['user_id'].notna()]
            
            profiles = {}
            
            for user_id in df['user_id'].unique():
                user_data = df[df['user_id'] == user_id]
                profile = await self._create_user_profile(user_id, user_data)
                profiles[user_id] = profile
            
            self.user_profiles.update(profiles)
            return profiles
            
        except Exception as e:
            self.logger.error(f"User behavior analysis failed: {e}")
            return {}
    
    async def _create_user_profile(self, user_id: str, user_data: pd.DataFrame) -> UserBehaviorProfile:
        """Create detailed user behavior profile."""
        try:
            total_requests = len(user_data)
            unique_endpoints = user_data['endpoint'].nunique() if 'endpoint' in user_data.columns else 0
            
            # Calculate session duration (approximate)
            if 'timestamp' in user_data.columns:
                user_data['timestamp'] = pd.to_datetime(user_data['timestamp'])
                time_span = (user_data['timestamp'].max() - user_data['timestamp'].min()).total_seconds()
                sessions = self._estimate_sessions(user_data)
                avg_session_duration = time_span / len(sessions) if sessions else 0
                
                # Peak usage hours
                hourly_activity = user_data.groupby(user_data['timestamp'].dt.hour).size()
                peak_hours = hourly_activity.nlargest(3).index.tolist()
            else:
                avg_session_duration = 0
                peak_hours = []
            
            # Preferred endpoints
            if 'endpoint' in user_data.columns:
                endpoint_counts = user_data['endpoint'].value_counts()
                preferred_endpoints = endpoint_counts.head(5).index.tolist()
            else:
                preferred_endpoints = []
            
            # User segment classification
            segment = self._classify_user_segment(total_requests, unique_endpoints, avg_session_duration)
            
            # Risk score calculation
            risk_score = self._calculate_risk_score(user_data)
            
            # Request patterns
            request_patterns = await self._analyze_request_patterns(user_data)
            
            # Last activity
            last_activity = user_data['timestamp'].max() if 'timestamp' in user_data.columns else datetime.utcnow()
            
            return UserBehaviorProfile(
                user_id=user_id,
                segment=segment,
                total_requests=total_requests,
                unique_endpoints=unique_endpoints,
                average_session_duration=avg_session_duration,
                peak_usage_hours=peak_hours,
                preferred_endpoints=preferred_endpoints,
                request_patterns=request_patterns,
                risk_score=risk_score,
                last_activity=last_activity
            )
            
        except Exception as e:
            self.logger.error(f"User profile creation failed for {user_id}: {e}")
            return UserBehaviorProfile(
                user_id=user_id,
                segment=UserSegment.LIGHT_USER,
                total_requests=0,
                unique_endpoints=0,
                average_session_duration=0,
                peak_usage_hours=[],
                preferred_endpoints=[],
                request_patterns={},
                risk_score=0.0,
                last_activity=datetime.utcnow()
            )
    
    def _estimate_sessions(self, user_data: pd.DataFrame) -> List[Tuple[datetime, datetime]]:
        """Estimate user sessions based on request timing."""
        sessions = []
        
        try:
            if 'timestamp' not in user_data.columns:
                return sessions
            
            sorted_data = user_data.sort_values('timestamp')
            session_timeout = timedelta(minutes=30)  # 30 minutes of inactivity = new session
            
            session_start = sorted_data['timestamp'].iloc[0]
            last_request = session_start
            
            for timestamp in sorted_data['timestamp'].iloc[1:]:
                if timestamp - last_request > session_timeout:
                    # End current session, start new one
                    sessions.append((session_start, last_request))
                    session_start = timestamp
                last_request = timestamp
            
            # Add final session
            sessions.append((session_start, last_request))
            
        except Exception as e:
            logging.error(f"Session estimation failed: {e}")
        
        return sessions
    
    def _classify_user_segment(self, total_requests: int, unique_endpoints: int, 
                             avg_session_duration: float) -> UserSegment:
        """Classify user into behavior segment."""
        try:
            # Simple classification based on activity metrics
            activity_score = (total_requests * 0.4 + unique_endpoints * 0.3 + 
                            (avg_session_duration / 3600) * 0.3)  # Convert to hours
            
            if activity_score >= 100:
                return UserSegment.POWER_USER
            elif activity_score >= 50:
                return UserSegment.HEAVY_USER
            elif activity_score >= 20:
                return UserSegment.MODERATE_USER
            elif activity_score >= 5:
                return UserSegment.LIGHT_USER
            else:
                return UserSegment.IRREGULAR_USER
                
        except Exception:
            return UserSegment.LIGHT_USER
    
    def _calculate_risk_score(self, user_data: pd.DataFrame) -> float:
        """Calculate user risk score based on behavior."""
        risk_score = 0.0
        
        try:
            # High error rate
            if 'status_code' in user_data.columns:
                error_rate = len(user_data[user_data['status_code'] >= 400]) / len(user_data)
                risk_score += error_rate * 30
            
            # High request frequency
            if 'timestamp' in user_data.columns:
                time_span_hours = (user_data['timestamp'].max() - user_data['timestamp'].min()).total_seconds() / 3600
                if time_span_hours > 0:
                    requests_per_hour = len(user_data) / time_span_hours
                    if requests_per_hour > 1000:  # Very high frequency
                        risk_score += 20
                    elif requests_per_hour > 100:
                        risk_score += 10
            
            # Unusual endpoint access patterns
            if 'endpoint' in user_data.columns:
                unique_endpoints = user_data['endpoint'].nunique()
                if unique_endpoints > 50:  # Accessing many different endpoints
                    risk_score += 15
            
            # Large request/response sizes
            if 'request_size' in user_data.columns:
                avg_request_size = user_data['request_size'].mean()
                if avg_request_size > 1000000:  # > 1MB average
                    risk_score += 10
            
            return min(risk_score, 100.0)  # Cap at 100
            
        except Exception as e:
            logging.error(f"Risk score calculation failed: {e}")
            return 0.0
    
    async def _analyze_request_patterns(self, user_data: pd.DataFrame) -> Dict[str, Any]:
        """Analyze user's request patterns."""
        patterns = {}
        
        try:
            # Request timing patterns
            if 'timestamp' in user_data.columns:
                user_data['hour'] = pd.to_datetime(user_data['timestamp']).dt.hour
                hourly_distribution = user_data['hour'].value_counts().to_dict()
                patterns['hourly_distribution'] = hourly_distribution
                
                # Most active hour
                most_active_hour = max(hourly_distribution, key=hourly_distribution.get)
                patterns['most_active_hour'] = most_active_hour
            
            # Endpoint access patterns
            if 'endpoint' in user_data.columns:
                endpoint_counts = user_data['endpoint'].value_counts()
                patterns['endpoint_preferences'] = endpoint_counts.head(10).to_dict()
                patterns['endpoint_diversity'] = endpoint_counts.nunique()
            
            # Response time patterns
            if 'response_time' in user_data.columns:
                patterns['avg_response_time'] = float(user_data['response_time'].mean())
                patterns['response_time_variance'] = float(user_data['response_time'].var())
            
            # Error patterns
            if 'status_code' in user_data.columns:
                error_codes = user_data[user_data['status_code'] >= 400]['status_code'].value_counts()
                patterns['error_patterns'] = error_codes.to_dict()
                
        except Exception as e:
            logging.error(f"Request pattern analysis failed: {e}")
        
        return patterns


class BusinessIntelligenceEngine:
    """Business intelligence and reporting engine for API analytics."""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.report_cache = {}
        
    async def generate_executive_summary(self, timeframe: AnalyticsTimeframe, 
                                       analytics_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate executive summary report."""
        try:
            summary = {
                'timeframe': timeframe.value,
                'generated_at': datetime.utcnow().isoformat(),
                'key_metrics': {},
                'trends': {},
                'insights': [],
                'recommendations': []
            }
            
            # Extract key metrics
            if 'metrics_summary' in analytics_data:
                metrics = analytics_data['metrics_summary']
                summary['key_metrics'] = {
                    'total_api_calls': metrics.get('total_requests', 0),
                    'unique_users': metrics.get('peak_concurrent_users', 0),
                    'average_response_time': f"{metrics.get('average_response_time', 0):.2f}s",
                    'availability': f"{metrics.get('availability_percentage', 0):.2f}%",
                    'error_rate': f"{metrics.get('error_rate', 0) * 100:.2f}%",
                    'data_transferred': f"{metrics.get('total_data_transfer_gb', 0):.2f} GB"
                }
            
            # Analyze trends
            trends = await self._analyze_trends(analytics_data)
            summary['trends'] = trends
            
            # Generate insights
            insights = await self._generate_insights(analytics_data, trends)
            summary['insights'] = insights
            
            # Generate recommendations
            recommendations = await self._generate_recommendations(analytics_data, trends, insights)
            summary['recommendations'] = recommendations
            
            return summary
            
        except Exception as e:
            self.logger.error(f"Executive summary generation failed: {e}")
            return {'error': str(e)}
    
    async def _analyze_trends(self, analytics_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze usage trends."""
        trends = {}
        
        try:
            # Usage trend analysis
            if 'usage_patterns' in analytics_data:
                patterns = analytics_data['usage_patterns']
                
                # Peak usage analysis
                if 'peak_hours' in patterns:
                    peak_hours = patterns['peak_hours']
                    trends['peak_usage_trend'] = {
                        'primary_peak': max(peak_hours, key=peak_hours.get) if peak_hours else None,
                        'peak_intensity': max(peak_hours.values()) if peak_hours else 0,
                        'distribution': peak_hours
                    }
                
                # Endpoint popularity trends
                if 'top_endpoints' in patterns:
                    top_endpoints = patterns['top_endpoints']
                    trends['endpoint_popularity'] = {
                        'most_popular': max(top_endpoints, key=top_endpoints.get) if top_endpoints else None,
                        'concentration': self._calculate_concentration_ratio(top_endpoints),
                        'distribution': top_endpoints
                    }
            
            # Performance trends
            metrics = analytics_data.get('metrics_summary', {})
            error_rate = metrics.get('error_rate', 0)
            response_time = metrics.get('average_response_time', 0)
            
            trends['performance'] = {
                'error_rate_status': 'good' if error_rate < 0.01 else 'concerning' if error_rate < 0.05 else 'critical',
                'response_time_status': 'good' if response_time < 1.0 else 'concerning' if response_time < 3.0 else 'critical',
                'overall_health': 'healthy' if error_rate < 0.01 and response_time < 1.0 else 'degraded'
            }
            
        except Exception as e:
            self.logger.error(f"Trend analysis failed: {e}")
        
        return trends
    
    async def _generate_insights(self, analytics_data: Dict[str, Any], 
                               trends: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate business insights."""
        insights = []
        
        try:
            # Usage insights
            metrics = analytics_data.get('metrics_summary', {})
            
            # High-level usage insight
            total_requests = metrics.get('total_requests', 0)
            if total_requests > 0:
                insights.append({
                    'type': 'usage',
                    'title': 'API Usage Overview',
                    'description': f'Processed {total_requests:,} API requests with {metrics.get("peak_concurrent_users", 0)} peak concurrent users',
                    'impact': 'informational',
                    'confidence': 0.9
                })
            
            # Performance insights
            performance = trends.get('performance', {})
            if performance.get('overall_health') == 'degraded':
                insights.append({
                    'type': 'performance',
                    'title': 'Performance Degradation Detected',
                    'description': f'System showing signs of performance issues: {performance.get("error_rate_status")} error rate, {performance.get("response_time_status")} response times',
                    'impact': 'high',
                    'confidence': 0.8
                })
            
            # Capacity insights
            data_transfer = metrics.get('total_data_transfer_gb', 0)
            if data_transfer > 100:  # > 100GB
                insights.append({
                    'type': 'capacity',
                    'title': 'High Data Transfer Volume',
                    'description': f'Transferred {data_transfer:.1f} GB of data, indicating high API utilization',
                    'impact': 'medium',
                    'confidence': 0.9
                })
            
            # Security insights
            sla_data = analytics_data.get('sla_compliance', {})
            violations = sla_data.get('total_violations_count', 0)
            if violations > 0:
                insights.append({
                    'type': 'security',
                    'title': 'SLA Violations Detected',
                    'description': f'{violations} SLA violations detected, requiring attention',
                    'impact': 'high',
                    'confidence': 0.9
                })
            
        except Exception as e:
            self.logger.error(f"Insight generation failed: {e}")
        
        return insights
    
    async def _generate_recommendations(self, analytics_data: Dict[str, Any], 
                                      trends: Dict[str, Any], 
                                      insights: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Generate actionable recommendations."""
        recommendations = []
        
        try:
            # Performance recommendations
            performance = trends.get('performance', {})
            if performance.get('overall_health') == 'degraded':
                recommendations.append({
                    'type': 'performance',
                    'priority': 'high',
                    'title': 'Address Performance Issues',
                    'description': 'Investigate and resolve performance bottlenecks',
                    'actions': [
                        'Review slow-performing endpoints',
                        'Analyze error patterns',
                        'Consider scaling resources',
                        'Implement caching strategies'
                    ]
                })
            
            # Capacity recommendations
            metrics = analytics_data.get('metrics_summary', {})
            peak_users = metrics.get('peak_concurrent_users', 0)
            if peak_users > 1000:  # High concurrent users
                recommendations.append({
                    'type': 'capacity',
                    'priority': 'medium',
                    'title': 'Capacity Planning Review',
                    'description': 'High concurrent user count suggests need for capacity review',
                    'actions': [
                        'Analyze current capacity utilization',
                        'Plan for future growth',
                        'Consider auto-scaling implementation',
                        'Review load balancing configuration'
                    ]
                })
            
            # Security recommendations
            for insight in insights:
                if insight['type'] == 'security' and insight['impact'] == 'high':
                    recommendations.append({
                        'type': 'security',
                        'priority': 'high',
                        'title': 'Security Review Required',
                        'description': 'Security concerns identified requiring immediate attention',
                        'actions': [
                            'Review SLA violation details',
                            'Investigate security events',
                            'Update security policies if needed',
                            'Enhance monitoring and alerting'
                        ]
                    })
            
            # Optimization recommendations
            if 'usage_patterns' in analytics_data:
                patterns = analytics_data['usage_patterns']
                if 'top_endpoints' in patterns:
                    concentration = self._calculate_concentration_ratio(patterns['top_endpoints'])
                    if concentration > 0.8:  # High concentration
                        recommendations.append({
                            'type': 'optimization',
                            'priority': 'medium',
                            'title': 'API Usage Optimization',
                            'description': 'High concentration of traffic on few endpoints',
                            'actions': [
                                'Optimize high-traffic endpoints',
                                'Implement caching for popular endpoints',
                                'Consider API versioning strategy',
                                'Review endpoint design for efficiency'
                            ]
                        })
            
        except Exception as e:
            self.logger.error(f"Recommendation generation failed: {e}")
        
        return recommendations
    
    def _calculate_concentration_ratio(self, distribution: Dict[str, int]) -> float:
        """Calculate concentration ratio (how concentrated the distribution is)."""
        try:
            if not distribution:
                return 0.0
            
            total = sum(distribution.values())
            sorted_values = sorted(distribution.values(), reverse=True)
            
            # Calculate what percentage of total is made up by top 20% of items
            top_20_percent_count = max(1, len(sorted_values) // 5)
            top_20_percent_sum = sum(sorted_values[:top_20_percent_count])
            
            return top_20_percent_sum / total if total > 0 else 0.0
            
        except Exception:
            return 0.0


class APIAnalyticsEngine:
    """
    Comprehensive API Analytics Engine
    
    Provides advanced analytics processing, user behavior analysis, business intelligence,
    and predictive insights for the DoD API Gateway.
    """
    
    def __init__(self, redis_url: str = "redis://localhost:6379"):
        """Initialize API Analytics Engine."""
        self.logger = logging.getLogger(__name__)
        self.redis_client = None
        self.redis_url = redis_url
        
        # Analytics components
        self.real_time_processor = RealTimeAnalyticsProcessor()
        self.pattern_detector = APIPatternDetector()
        self.user_analyzer = UserBehaviorAnalyzer()
        self.bi_engine = BusinessIntelligenceEngine()
        
        # Audit integration
        self.audit_logger = None
        
        # Analytics cache
        self.analytics_cache = {}
        self.last_processed = {}
        
    async def initialize(self) -> None:
        """Initialize analytics engine."""
        try:
            # Initialize Redis client
            self.redis_client = await aioredis.from_url(self.redis_url)
            await self.redis_client.ping()
            
            # Initialize audit logger
            try:
                self.audit_logger = AuditLogger()
                await self.audit_logger.initialize()
            except Exception as e:
                self.logger.warning(f"Audit logger initialization failed: {e}")
            
            # Start background processing
            asyncio.create_task(self._background_analytics_processor())
            
            self.logger.info("API Analytics Engine initialized")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize analytics engine: {e}")
            raise
    
    async def process_request_data(self, request_data: Dict[str, Any]) -> None:
        """Process incoming request data for analytics."""
        try:
            # Add to real-time processor
            await self.real_time_processor.process_request(request_data)
            
            # Store for batch processing
            await self._store_request_for_batch_processing(request_data)
            
        except Exception as e:
            self.logger.error(f"Request data processing failed: {e}")
    
    async def _store_request_for_batch_processing(self, request_data: Dict[str, Any]) -> None:
        """Store request data for batch analytics processing."""
        try:
            # Store in Redis list for batch processing
            key = f"analytics_requests:{datetime.utcnow().strftime('%Y%m%d%H')}"
            await self.redis_client.lpush(key, json.dumps(request_data, default=str))
            await self.redis_client.expire(key, 86400 * 7)  # Keep for 7 days
            
        except Exception as e:
            self.logger.error(f"Failed to store request for batch processing: {e}")
    
    async def _background_analytics_processor(self) -> None:
        """Background processor for analytics tasks."""
        while True:
            try:
                await self._process_batch_analytics()
                await asyncio.sleep(300)  # Process every 5 minutes
                
            except Exception as e:
                self.logger.error(f"Background analytics processing error: {e}")
                await asyncio.sleep(300)
    
    async def _process_batch_analytics(self) -> None:
        """Process batch analytics."""
        try:
            current_hour = datetime.utcnow().strftime('%Y%m%d%H')
            previous_hour = (datetime.utcnow() - timedelta(hours=1)).strftime('%Y%m%d%H')
            
            # Process previous hour's data
            request_key = f"analytics_requests:{previous_hour}"
            request_data = await self.redis_client.lrange(request_key, 0, -1)
            
            if request_data:
                # Parse request data
                parsed_requests = []
                for data in request_data:
                    try:
                        parsed_requests.append(json.loads(data))
                    except Exception:
                        continue
                
                if parsed_requests:
                    # Run analytics
                    await self._run_comprehensive_analytics(parsed_requests, previous_hour)
                    
        except Exception as e:
            self.logger.error(f"Batch analytics processing failed: {e}")
    
    async def _run_comprehensive_analytics(self, request_data: List[Dict], time_key: str) -> None:
        """Run comprehensive analytics on request data."""
        try:
            # Pattern detection
            patterns = await self.pattern_detector.detect_patterns(request_data)
            
            # User behavior analysis
            user_profiles = await self.user_analyzer.analyze_user_behavior(request_data)
            
            # Store analytics results
            analytics_results = {
                'time_key': time_key,
                'processed_at': datetime.utcnow().isoformat(),
                'request_count': len(request_data),
                'patterns': [asdict(pattern) for pattern in patterns],
                'user_profiles': {uid: asdict(profile) for uid, profile in user_profiles.items()},
                'summary_stats': await self._calculate_summary_stats(request_data)
            }
            
            # Store results
            result_key = f"analytics_results:{time_key}"
            await self.redis_client.set(
                result_key, 
                json.dumps(analytics_results, default=str), 
                ex=86400 * 30  # Keep for 30 days
            )
            
            # Log to audit system
            if self.audit_logger:
                await self.audit_logger.log_event(
                    event_type="analytics_processing",
                    details={
                        'time_key': time_key,
                        'request_count': len(request_data),
                        'patterns_detected': len(patterns),
                        'users_analyzed': len(user_profiles)
                    }
                )
            
        except Exception as e:
            self.logger.error(f"Comprehensive analytics failed: {e}")
    
    async def _calculate_summary_stats(self, request_data: List[Dict]) -> Dict[str, Any]:
        """Calculate summary statistics for request data."""
        stats = {}
        
        try:
            df = pd.DataFrame(request_data)
            
            # Basic stats
            stats['total_requests'] = len(df)
            stats['unique_users'] = df['user_id'].nunique() if 'user_id' in df.columns else 0
            stats['unique_endpoints'] = df['endpoint'].nunique() if 'endpoint' in df.columns else 0
            
            # Performance stats
            if 'response_time' in df.columns:
                stats['avg_response_time'] = float(df['response_time'].mean())
                stats['p95_response_time'] = float(df['response_time'].quantile(0.95))
                stats['p99_response_time'] = float(df['response_time'].quantile(0.99))
            
            # Error stats
            if 'status_code' in df.columns:
                error_count = len(df[df['status_code'] >= 400])
                stats['error_count'] = error_count
                stats['error_rate'] = error_count / len(df) if len(df) > 0 else 0
            
            # Data transfer stats
            if 'request_size' in df.columns and 'response_size' in df.columns:
                total_data = (df['request_size'] + df['response_size']).sum()
                stats['total_data_bytes'] = int(total_data)
                stats['avg_request_size'] = float(df['request_size'].mean())
                stats['avg_response_size'] = float(df['response_size'].mean())
            
        except Exception as e:
            self.logger.error(f"Summary stats calculation failed: {e}")
        
        return stats
    
    async def get_real_time_analytics(self) -> Dict[str, Any]:
        """Get real-time analytics data."""
        try:
            # Get real-time metrics
            real_time_metrics = self.real_time_processor.get_real_time_metrics()
            
            # Get current user sessions
            current_time = datetime.utcnow()
            active_sessions = len([
                uid for uid, last_seen in self.user_analyzer.user_profiles.items()
                if (current_time - last_seen.last_activity).total_seconds() < 1800  # 30 minutes
            ])
            
            return {
                'timestamp': current_time.isoformat(),
                'real_time_metrics': real_time_metrics,
                'active_user_sessions': active_sessions,
                'analytics_status': 'operational'
            }
            
        except Exception as e:
            self.logger.error(f"Real-time analytics retrieval failed: {e}")
            return {'error': str(e)}
    
    async def get_comprehensive_report(self, timeframe: str = '24h') -> Dict[str, Any]:
        """Get comprehensive analytics report."""
        try:
            # Determine time range
            hours = {'1h': 1, '24h': 24, '7d': 168, '30d': 720}.get(timeframe, 24)
            start_time = datetime.utcnow() - timedelta(hours=hours)
            
            # Collect analytics results for timeframe
            analytics_data = await self._collect_analytics_data(start_time, datetime.utcnow())
            
            # Generate business intelligence report
            timeframe_enum = {
                '1h': AnalyticsTimeframe.HOURLY,
                '24h': AnalyticsTimeframe.DAILY,
                '7d': AnalyticsTimeframe.WEEKLY,
                '30d': AnalyticsTimeframe.MONTHLY
            }.get(timeframe, AnalyticsTimeframe.DAILY)
            
            executive_summary = await self.bi_engine.generate_executive_summary(
                timeframe_enum, analytics_data
            )
            
            return {
                'timeframe': timeframe,
                'data_period': {
                    'start': start_time.isoformat(),
                    'end': datetime.utcnow().isoformat()
                },
                'analytics_data': analytics_data,
                'executive_summary': executive_summary,
                'generated_at': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"Comprehensive report generation failed: {e}")
            return {'error': str(e)}
    
    async def _collect_analytics_data(self, start_time: datetime, end_time: datetime) -> Dict[str, Any]:
        """Collect analytics data for specified time range."""
        collected_data = {
            'patterns': [],
            'user_profiles': {},
            'summary_stats': {},
            'metrics_summary': {}
        }
        
        try:
            # Collect data from Redis
            pattern = "analytics_results:*"
            keys = await self.redis_client.keys(pattern)
            
            total_requests = 0
            all_patterns = []
            all_user_profiles = {}
            
            for key in keys:
                try:
                    # Parse time from key
                    time_key = key.decode().split(':')[1]
                    key_time = datetime.strptime(time_key, '%Y%m%d%H')
                    
                    if start_time <= key_time <= end_time:
                        data = await self.redis_client.get(key)
                        if data:
                            analytics_result = json.loads(data)
                            
                            total_requests += analytics_result.get('request_count', 0)
                            all_patterns.extend(analytics_result.get('patterns', []))
                            all_user_profiles.update(analytics_result.get('user_profiles', {}))
                            
                except Exception as e:
                    self.logger.warning(f"Failed to process analytics key {key}: {e}")
                    continue
            
            collected_data.update({
                'patterns': all_patterns,
                'user_profiles': all_user_profiles,
                'metrics_summary': {
                    'total_requests': total_requests,
                    'unique_users': len(all_user_profiles),
                    'time_range_hours': (end_time - start_time).total_seconds() / 3600
                }
            })
            
        except Exception as e:
            self.logger.error(f"Analytics data collection failed: {e}")
        
        return collected_data
    
    async def close(self) -> None:
        """Clean up analytics engine resources."""
        if self.redis_client:
            await self.redis_client.close()
        
        self.logger.info("API Analytics Engine closed")


if __name__ == "__main__":
    # Example usage
    async def main():
        engine = APIAnalyticsEngine()
        await engine.initialize()
        
        # Simulate processing some request data
        for i in range(100):
            await engine.process_request_data({
                'timestamp': datetime.utcnow(),
                'method': 'GET',
                'endpoint': f'/api/v1/data/{i % 5}',
                'status_code': 200 if i % 10 != 0 else 500,
                'response_time': 0.5 + (i % 3) * 0.1,
                'request_size': 1024 + (i % 100),
                'response_size': 2048 + (i % 200),
                'user_id': f'user_{i % 20}',
                'client_ip': f'192.168.1.{i % 254 + 1}'
            })
        
        # Get real-time analytics
        real_time = await engine.get_real_time_analytics()
        print(f"Real-time Analytics: {json.dumps(real_time, indent=2)}")
        
        # Wait a bit for processing
        await asyncio.sleep(2)
        
        # Get comprehensive report
        report = await engine.get_comprehensive_report('1h')
        print(f"Comprehensive Report: {json.dumps(report, indent=2)}")
        
        await engine.close()
    
    asyncio.run(main())