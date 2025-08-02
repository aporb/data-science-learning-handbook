"""
SLA Tracker and Reporting for DoD API Gateway

This module provides comprehensive Service Level Agreement (SLA) monitoring, tracking,
and reporting capabilities for the DoD API Gateway Integration. It ensures compliance
with established SLAs and provides detailed reporting for operational oversight.

Key Features:
- Multi-tier SLA definition and monitoring
- Real-time SLA compliance tracking
- Automated violation detection and alerting
- Comprehensive SLA reporting and dashboards
- Historical SLA performance analysis
- Predictive SLA breach detection
- Integration with monitoring and alerting systems

Security Standards:
- DoD service level requirements
- NIST 800-53 service monitoring controls
- Compliance reporting and audit trails
- Secure SLA data management
"""

import asyncio
import json
import logging
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple, Union
from dataclasses import dataclass, asdict
from enum import Enum
from collections import defaultdict, deque
import statistics
import math

import aioredis
import pandas as pd
import numpy as np
from scipy import stats

# Import from existing modules
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from audits.audit_logger import AuditLogger
from audits.compliance_reporter import ComplianceReporter


class SLAMetricType(Enum):
    """Types of SLA metrics."""
    AVAILABILITY = "availability"
    RESPONSE_TIME = "response_time"
    ERROR_RATE = "error_rate"
    THROUGHPUT = "throughput"
    UPTIME = "uptime"
    RECOVERY_TIME = "recovery_time"
    SECURITY_COMPLIANCE = "security_compliance"


class SLAPriority(Enum):
    """SLA priority levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class SLAStatus(Enum):
    """SLA compliance status."""
    COMPLIANT = "compliant"
    WARNING = "warning"
    VIOLATION = "violation"
    CRITICAL_VIOLATION = "critical_violation"


class ViolationSeverity(Enum):
    """SLA violation severity levels."""
    MINOR = "minor"
    MAJOR = "major"
    CRITICAL = "critical"
    CATASTROPHIC = "catastrophic"


class ReportingPeriod(Enum):
    """SLA reporting periods."""
    HOURLY = "hourly"
    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"
    QUARTERLY = "quarterly"
    ANNUALLY = "annually"


@dataclass
class SLATarget:
    """SLA target definition."""
    target_id: str
    name: str
    description: str
    metric_type: SLAMetricType
    target_value: float
    threshold_warning: float
    threshold_critical: float
    measurement_period: int  # in seconds
    priority: SLAPriority
    service_component: str
    customer_impact: str
    enabled: bool = True
    created_at: datetime = None
    
    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.utcnow()


@dataclass
class SLAMeasurement:
    """SLA measurement data point."""
    measurement_id: str
    target_id: str
    timestamp: datetime
    measured_value: float
    status: SLAStatus
    measurement_period_seconds: int
    additional_context: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.additional_context is None:
            self.additional_context = {}


@dataclass
class SLAViolation:
    """SLA violation record."""
    violation_id: str
    target_id: str
    start_time: datetime
    end_time: Optional[datetime]
    severity: ViolationSeverity
    measured_value: float
    target_value: float
    duration_seconds: int
    root_cause: Optional[str]
    impact_description: str
    resolution_actions: List[str]
    resolved: bool = False
    escalated: bool = False
    
    def __post_init__(self):
        if self.resolution_actions is None:
            self.resolution_actions = []


@dataclass
class SLAReport:
    """SLA compliance report."""
    report_id: str
    reporting_period: ReportingPeriod
    start_time: datetime
    end_time: datetime
    overall_compliance: float
    target_summaries: List[Dict[str, Any]]
    violations: List[SLAViolation]
    trends: Dict[str, Any]
    recommendations: List[str]
    generated_at: datetime
    
    def __post_init__(self):
        if self.target_summaries is None:
            self.target_summaries = []
        if self.violations is None:
            self.violations = []
        if self.recommendations is None:
            self.recommendations = []


class SLACalculator:
    """Calculates SLA metrics and compliance."""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    async def calculate_availability(self, measurements: List[Dict], 
                                   period_seconds: int) -> float:
        """Calculate availability percentage."""
        try:
            if not measurements:
                return 100.0
            
            # Calculate uptime vs downtime
            total_time = period_seconds
            downtime = 0
            
            for measurement in measurements:
                if measurement.get('status_code', 200) >= 500:  # Server errors count as downtime
                    downtime += 1  # Assuming 1 second per failed request (simplified)
            
            uptime = total_time - downtime
            availability = (uptime / total_time) * 100 if total_time > 0 else 100.0
            
            return min(100.0, max(0.0, availability))
            
        except Exception as e:
            self.logger.error(f"Availability calculation failed: {e}")
            return 0.0
    
    async def calculate_response_time(self, measurements: List[Dict], 
                                    percentile: float = 95.0) -> float:
        """Calculate response time percentile."""
        try:
            if not measurements:
                return 0.0
            
            response_times = [
                m.get('response_time', 0) for m in measurements
                if m.get('response_time') is not None
            ]
            
            if not response_times:
                return 0.0
            
            return float(np.percentile(response_times, percentile))
            
        except Exception as e:
            self.logger.error(f"Response time calculation failed: {e}")
            return 0.0
    
    async def calculate_error_rate(self, measurements: List[Dict]) -> float:
        """Calculate error rate percentage."""
        try:
            if not measurements:
                return 0.0
            
            total_requests = len(measurements)
            error_requests = len([
                m for m in measurements
                if m.get('status_code', 200) >= 400
            ])
            
            return (error_requests / total_requests) * 100 if total_requests > 0 else 0.0
            
        except Exception as e:
            self.logger.error(f"Error rate calculation failed: {e}")
            return 0.0
    
    async def calculate_throughput(self, measurements: List[Dict], 
                                 period_seconds: int) -> float:
        """Calculate throughput (requests per second)."""
        try:
            if not measurements or period_seconds <= 0:
                return 0.0
            
            return len(measurements) / period_seconds
            
        except Exception as e:
            self.logger.error(f"Throughput calculation failed: {e}")
            return 0.0
    
    async def calculate_recovery_time(self, incidents: List[Dict]) -> float:
        """Calculate mean time to recovery (MTTR)."""
        try:
            if not incidents:
                return 0.0
            
            recovery_times = []
            for incident in incidents:
                start_time = incident.get('start_time')
                end_time = incident.get('end_time')
                
                if start_time and end_time:
                    if isinstance(start_time, str):
                        start_time = datetime.fromisoformat(start_time)
                    if isinstance(end_time, str):
                        end_time = datetime.fromisoformat(end_time)
                    
                    recovery_time = (end_time - start_time).total_seconds()
                    recovery_times.append(recovery_time)
            
            return float(statistics.mean(recovery_times)) if recovery_times else 0.0
            
        except Exception as e:
            self.logger.error(f"Recovery time calculation failed: {e}")
            return 0.0


class SLAPredictor:
    """Predicts potential SLA violations using trend analysis."""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    async def predict_violations(self, historical_data: List[SLAMeasurement], 
                               targets: List[SLATarget], 
                               prediction_window_hours: int = 24) -> List[Dict[str, Any]]:
        """Predict potential SLA violations."""
        predictions = []
        
        try:
            for target in targets:
                target_measurements = [
                    m for m in historical_data
                    if m.target_id == target.target_id
                ]
                
                if len(target_measurements) < 10:  # Need minimum data points
                    continue
                
                # Analyze trend
                trend_analysis = await self._analyze_trend(target_measurements, target)
                
                if trend_analysis['risk_level'] > 0.7:  # High risk threshold
                    prediction = {
                        'target_id': target.target_id,
                        'target_name': target.name,
                        'predicted_violation_time': trend_analysis.get('predicted_breach_time'),
                        'risk_level': trend_analysis['risk_level'],
                        'confidence': trend_analysis.get('confidence', 0.0),
                        'current_trend': trend_analysis.get('trend_direction'),
                        'recommended_actions': await self._generate_preventive_actions(target, trend_analysis)
                    }
                    predictions.append(prediction)
                    
        except Exception as e:
            self.logger.error(f"SLA violation prediction failed: {e}")
        
        return predictions
    
    async def _analyze_trend(self, measurements: List[SLAMeasurement], 
                           target: SLATarget) -> Dict[str, Any]:
        """Analyze trend in SLA measurements."""
        analysis = {
            'risk_level': 0.0,
            'trend_direction': 'stable',
            'confidence': 0.0
        }
        
        try:
            # Sort measurements by timestamp
            sorted_measurements = sorted(measurements, key=lambda x: x.timestamp)
            
            # Extract values and timestamps
            values = [m.measured_value for m in sorted_measurements]
            timestamps = [(m.timestamp - sorted_measurements[0].timestamp).total_seconds() 
                         for m in sorted_measurements]
            
            if len(values) < 5:
                return analysis
            
            # Perform linear regression to detect trend
            slope, intercept, r_value, p_value, std_err = stats.linregress(timestamps, values)
            
            # Determine trend direction and strength
            if abs(r_value) > 0.5:  # Significant correlation
                if target.metric_type in [SLAMetricType.AVAILABILITY, SLAMetricType.THROUGHPUT]:
                    # For metrics where higher is better
                    if slope < 0:  # Decreasing trend
                        analysis['trend_direction'] = 'decreasing'
                        analysis['risk_level'] = min(abs(slope) * 0.1, 1.0)
                    else:
                        analysis['trend_direction'] = 'improving'
                else:
                    # For metrics where lower is better (response time, error rate)
                    if slope > 0:  # Increasing trend
                        analysis['trend_direction'] = 'increasing'
                        analysis['risk_level'] = min(slope * 0.1, 1.0)
                    else:
                        analysis['trend_direction'] = 'improving'
                
                analysis['confidence'] = abs(r_value)
            
            # Check if trend will lead to violation
            if analysis['risk_level'] > 0.5:
                # Predict when violation might occur
                current_value = values[-1]
                if target.metric_type in [SLAMetricType.AVAILABILITY, SLAMetricType.THROUGHPUT]:
                    time_to_breach = (current_value - target.threshold_warning) / slope if slope != 0 else float('inf')
                else:
                    time_to_breach = (target.threshold_warning - current_value) / slope if slope != 0 else float('inf')
                
                if 0 < time_to_breach < 86400:  # Within 24 hours
                    breach_time = datetime.utcnow() + timedelta(seconds=time_to_breach)
                    analysis['predicted_breach_time'] = breach_time.isoformat()
                    analysis['risk_level'] = min(analysis['risk_level'] * 1.5, 1.0)
                    
        except Exception as e:
            self.logger.error(f"Trend analysis failed: {e}")
        
        return analysis
    
    async def _generate_preventive_actions(self, target: SLATarget, 
                                         trend_analysis: Dict[str, Any]) -> List[str]:
        """Generate preventive actions for predicted violations."""
        actions = []
        
        try:
            risk_level = trend_analysis.get('risk_level', 0.0)
            trend_direction = trend_analysis.get('trend_direction', 'stable')
            
            if target.metric_type == SLAMetricType.AVAILABILITY:
                if trend_direction == 'decreasing':
                    actions.extend([
                        "Review system health and capacity",
                        "Check for infrastructure issues",
                        "Verify redundancy and failover mechanisms",
                        "Scale resources if needed"
                    ])
            
            elif target.metric_type == SLAMetricType.RESPONSE_TIME:
                if trend_direction == 'increasing':
                    actions.extend([
                        "Analyze performance bottlenecks",
                        "Review database query performance",
                        "Check network latency",
                        "Consider caching implementation",
                        "Scale compute resources"
                    ])
            
            elif target.metric_type == SLAMetricType.ERROR_RATE:
                if trend_direction == 'increasing':
                    actions.extend([
                        "Review recent code deployments",
                        "Check error logs for patterns",
                        "Verify external service dependencies",
                        "Review input validation",
                        "Check resource constraints"
                    ])
            
            elif target.metric_type == SLAMetricType.THROUGHPUT:
                if trend_direction == 'decreasing':
                    actions.extend([
                        "Check system capacity utilization",
                        "Review load balancing configuration",
                        "Analyze resource bottlenecks",
                        "Consider horizontal scaling",
                        "Review rate limiting settings"
                    ])
            
            # Add priority-based actions
            if risk_level > 0.8:
                actions.insert(0, "URGENT: Immediate investigation required")
                actions.append("Prepare incident response team")
            elif risk_level > 0.6:
                actions.insert(0, "HIGH PRIORITY: Schedule immediate review")
                
        except Exception as e:
            self.logger.error(f"Preventive action generation failed: {e}")
        
        return actions


class SLAReportGenerator:
    """Generates comprehensive SLA reports."""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    async def generate_compliance_report(self, targets: List[SLATarget],
                                       measurements: List[SLAMeasurement],
                                       violations: List[SLAViolation],
                                       period: ReportingPeriod,
                                       start_time: datetime,
                                       end_time: datetime) -> SLAReport:
        """Generate comprehensive SLA compliance report."""
        try:
            report_id = str(uuid.uuid4())
            
            # Calculate overall compliance
            overall_compliance = await self._calculate_overall_compliance(
                targets, measurements, start_time, end_time
            )
            
            # Generate target summaries
            target_summaries = []
            for target in targets:
                summary = await self._generate_target_summary(
                    target, measurements, violations, start_time, end_time
                )
                target_summaries.append(summary)
            
            # Analyze trends
            trends = await self._analyze_sla_trends(measurements, violations, period)
            
            # Generate recommendations
            recommendations = await self._generate_recommendations(
                targets, measurements, violations, trends
            )
            
            # Filter violations for the period
            period_violations = [
                v for v in violations
                if start_time <= v.start_time <= end_time
            ]
            
            return SLAReport(
                report_id=report_id,
                reporting_period=period,
                start_time=start_time,
                end_time=end_time,
                overall_compliance=overall_compliance,
                target_summaries=target_summaries,
                violations=period_violations,
                trends=trends,
                recommendations=recommendations,
                generated_at=datetime.utcnow()
            )
            
        except Exception as e:
            self.logger.error(f"SLA report generation failed: {e}")
            raise
    
    async def _calculate_overall_compliance(self, targets: List[SLATarget],
                                          measurements: List[SLAMeasurement],
                                          start_time: datetime,
                                          end_time: datetime) -> float:
        """Calculate overall SLA compliance percentage."""
        try:
            if not targets:
                return 100.0
            
            compliance_scores = []
            
            for target in targets:
                target_measurements = [
                    m for m in measurements
                    if m.target_id == target.target_id and start_time <= m.timestamp <= end_time
                ]
                
                if not target_measurements:
                    continue
                
                # Calculate compliance for this target
                compliant_measurements = [
                    m for m in target_measurements
                    if m.status in [SLAStatus.COMPLIANT, SLAStatus.WARNING]
                ]
                
                target_compliance = (len(compliant_measurements) / len(target_measurements)) * 100
                
                # Weight by priority
                weight = {
                    SLAPriority.CRITICAL: 4.0,
                    SLAPriority.HIGH: 3.0,
                    SLAPriority.MEDIUM: 2.0,
                    SLAPriority.LOW: 1.0
                }.get(target.priority, 1.0)
                
                compliance_scores.append(target_compliance * weight)
            
            if compliance_scores:
                return sum(compliance_scores) / len(compliance_scores)
            else:
                return 100.0
                
        except Exception as e:
            self.logger.error(f"Overall compliance calculation failed: {e}")
            return 0.0
    
    async def _generate_target_summary(self, target: SLATarget,
                                     measurements: List[SLAMeasurement],
                                     violations: List[SLAViolation],
                                     start_time: datetime,
                                     end_time: datetime) -> Dict[str, Any]:
        """Generate summary for a specific SLA target."""
        summary = {
            'target_id': target.target_id,
            'target_name': target.name,
            'metric_type': target.metric_type.value,
            'target_value': target.target_value,
            'priority': target.priority.value,
            'service_component': target.service_component
        }
        
        try:
            # Filter measurements for this target and period
            target_measurements = [
                m for m in measurements
                if m.target_id == target.target_id and start_time <= m.timestamp <= end_time
            ]
            
            # Filter violations for this target and period
            target_violations = [
                v for v in violations
                if v.target_id == target.target_id and start_time <= v.start_time <= end_time
            ]
            
            if target_measurements:
                # Calculate statistics
                values = [m.measured_value for m in target_measurements]
                summary.update({
                    'measurement_count': len(target_measurements),
                    'average_value': float(statistics.mean(values)),
                    'min_value': float(min(values)),
                    'max_value': float(max(values)),
                    'std_dev': float(statistics.stdev(values)) if len(values) > 1 else 0.0
                })
                
                # Compliance statistics
                compliant_count = len([
                    m for m in target_measurements
                    if m.status == SLAStatus.COMPLIANT
                ])
                warning_count = len([
                    m for m in target_measurements
                    if m.status == SLAStatus.WARNING
                ])
                violation_count = len([
                    m for m in target_measurements
                    if m.status in [SLAStatus.VIOLATION, SLAStatus.CRITICAL_VIOLATION]
                ])
                
                summary.update({
                    'compliance_percentage': (compliant_count / len(target_measurements)) * 100,
                    'warning_percentage': (warning_count / len(target_measurements)) * 100,
                    'violation_percentage': (violation_count / len(target_measurements)) * 100,
                    'total_violations': len(target_violations)
                })
                
                # Current status
                latest_measurement = max(target_measurements, key=lambda x: x.timestamp)
                summary['current_status'] = latest_measurement.status.value
                summary['current_value'] = latest_measurement.measured_value
                summary['last_measured'] = latest_measurement.timestamp.isoformat()
            else:
                summary.update({
                    'measurement_count': 0,
                    'compliance_percentage': 0.0,
                    'current_status': 'no_data',
                    'total_violations': len(target_violations)
                })
                
        except Exception as e:
            self.logger.error(f"Target summary generation failed for {target.target_id}: {e}")
            summary['error'] = str(e)
        
        return summary
    
    async def _analyze_sla_trends(self, measurements: List[SLAMeasurement],
                                violations: List[SLAViolation],
                                period: ReportingPeriod) -> Dict[str, Any]:
        """Analyze SLA trends over time."""
        trends = {}
        
        try:
            # Group measurements by target
            target_measurements = defaultdict(list)
            for measurement in measurements:
                target_measurements[measurement.target_id].append(measurement)
            
            # Analyze trends for each target
            target_trends = {}
            for target_id, target_data in target_measurements.items():
                if len(target_data) >= 5:  # Need minimum data points
                    target_trend = await self._calculate_target_trend(target_data)
                    target_trends[target_id] = target_trend
            
            trends['target_trends'] = target_trends
            
            # Violation trends
            if violations:
                violation_trend = await self._calculate_violation_trend(violations, period)
                trends['violation_trend'] = violation_trend
            
            # Overall health trend
            overall_trend = await self._calculate_overall_trend(measurements)
            trends['overall_health_trend'] = overall_trend
            
        except Exception as e:
            self.logger.error(f"SLA trend analysis failed: {e}")
        
        return trends
    
    async def _calculate_target_trend(self, measurements: List[SLAMeasurement]) -> Dict[str, Any]:
        """Calculate trend for a specific target."""
        try:
            # Sort by timestamp
            sorted_measurements = sorted(measurements, key=lambda x: x.timestamp)
            
            # Extract values
            values = [m.measured_value for m in sorted_measurements]
            
            # Calculate moving average
            window_size = min(5, len(values))
            moving_avg = []
            for i in range(len(values) - window_size + 1):
                window_avg = statistics.mean(values[i:i + window_size])
                moving_avg.append(window_avg)
            
            # Determine trend direction
            if len(moving_avg) >= 2:
                start_avg = statistics.mean(moving_avg[:len(moving_avg)//3])
                end_avg = statistics.mean(moving_avg[-len(moving_avg)//3:])
                
                change_percent = ((end_avg - start_avg) / start_avg) * 100 if start_avg != 0 else 0
                
                if abs(change_percent) < 5:
                    trend_direction = 'stable'
                elif change_percent > 0:
                    trend_direction = 'increasing'
                else:
                    trend_direction = 'decreasing'
            else:
                trend_direction = 'insufficient_data'
                change_percent = 0
            
            return {
                'trend_direction': trend_direction,
                'change_percentage': change_percent,
                'current_value': values[-1] if values else 0,
                'average_value': statistics.mean(values) if values else 0,
                'data_points': len(values)
            }
            
        except Exception as e:
            self.logger.error(f"Target trend calculation failed: {e}")
            return {'trend_direction': 'error', 'change_percentage': 0}
    
    async def _calculate_violation_trend(self, violations: List[SLAViolation],
                                       period: ReportingPeriod) -> Dict[str, Any]:
        """Calculate violation trends."""
        try:
            # Group violations by time periods
            violation_counts = defaultdict(int)
            
            for violation in violations:
                # Group by appropriate time period
                if period == ReportingPeriod.HOURLY:
                    time_key = violation.start_time.strftime('%Y%m%d%H')
                elif period == ReportingPeriod.DAILY:
                    time_key = violation.start_time.strftime('%Y%m%d')
                elif period == ReportingPeriod.WEEKLY:
                    time_key = violation.start_time.strftime('%Y%W')
                else:
                    time_key = violation.start_time.strftime('%Y%m')
                
                violation_counts[time_key] += 1
            
            if len(violation_counts) >= 2:
                counts = list(violation_counts.values())
                
                # Calculate trend
                start_count = statistics.mean(counts[:len(counts)//3])
                end_count = statistics.mean(counts[-len(counts)//3:])
                
                if start_count == 0:
                    trend = 'increasing' if end_count > 0 else 'stable'
                    change_percent = float('inf') if end_count > 0 else 0
                else:
                    change_percent = ((end_count - start_count) / start_count) * 100
                    if abs(change_percent) < 10:
                        trend = 'stable'
                    elif change_percent > 0:
                        trend = 'increasing'
                    else:
                        trend = 'decreasing'
            else:
                trend = 'insufficient_data'
                change_percent = 0
            
            return {
                'trend_direction': trend,
                'change_percentage': change_percent,
                'total_violations': len(violations),
                'avg_violations_per_period': statistics.mean(violation_counts.values()) if violation_counts else 0
            }
            
        except Exception as e:
            self.logger.error(f"Violation trend calculation failed: {e}")
            return {'trend_direction': 'error'}
    
    async def _calculate_overall_trend(self, measurements: List[SLAMeasurement]) -> Dict[str, Any]:
        """Calculate overall health trend."""
        try:
            if not measurements:
                return {'trend_direction': 'no_data'}
            
            # Group by time periods and calculate compliance rates
            hourly_compliance = defaultdict(list)
            
            for measurement in measurements:
                hour_key = measurement.timestamp.strftime('%Y%m%d%H')
                compliance_score = 1.0 if measurement.status == SLAStatus.COMPLIANT else 0.0
                hourly_compliance[hour_key].append(compliance_score)
            
            # Calculate hourly compliance rates
            compliance_rates = []
            for hour_scores in hourly_compliance.values():
                rate = statistics.mean(hour_scores) * 100
                compliance_rates.append(rate)
            
            if len(compliance_rates) >= 3:
                # Calculate trend
                start_rate = statistics.mean(compliance_rates[:len(compliance_rates)//3])
                end_rate = statistics.mean(compliance_rates[-len(compliance_rates)//3:])
                
                change_percent = end_rate - start_rate
                
                if abs(change_percent) < 2:
                    trend = 'stable'
                elif change_percent > 0:
                    trend = 'improving'
                else:
                    trend = 'declining'
                
                return {
                    'trend_direction': trend,
                    'change_percentage': change_percent,
                    'current_compliance_rate': compliance_rates[-1],
                    'average_compliance_rate': statistics.mean(compliance_rates)
                }
            else:
                return {'trend_direction': 'insufficient_data'}
                
        except Exception as e:
            self.logger.error(f"Overall trend calculation failed: {e}")
            return {'trend_direction': 'error'}
    
    async def _generate_recommendations(self, targets: List[SLATarget],
                                      measurements: List[SLAMeasurement],
                                      violations: List[SLAViolation],
                                      trends: Dict[str, Any]) -> List[str]:
        """Generate actionable recommendations."""
        recommendations = []
        
        try:
            # Check overall compliance
            total_measurements = len(measurements)
            violation_measurements = len([
                m for m in measurements
                if m.status in [SLAStatus.VIOLATION, SLAStatus.CRITICAL_VIOLATION]
            ])
            
            overall_violation_rate = (violation_measurements / total_measurements) * 100 if total_measurements > 0 else 0
            
            if overall_violation_rate > 10:
                recommendations.append(
                    "CRITICAL: Overall SLA violation rate exceeds 10%. Immediate systematic review required."
                )
            elif overall_violation_rate > 5:
                recommendations.append(
                    "HIGH: SLA violation rate is concerning. Review system performance and capacity."
                )
            
            # Check for recurring violations
            target_violation_counts = defaultdict(int)
            for violation in violations:
                target_violation_counts[violation.target_id] += 1
            
            for target_id, count in target_violation_counts.items():
                if count > 5:  # More than 5 violations
                    target = next((t for t in targets if t.target_id == target_id), None)
                    if target:
                        recommendations.append(
                            f"Target '{target.name}' has {count} violations. "
                            f"Consider reviewing {target.service_component} configuration."
                        )
            
            # Check trends
            overall_trend = trends.get('overall_health_trend', {})
            if overall_trend.get('trend_direction') == 'declining':
                recommendations.append(
                    "Overall system health is declining. Proactive investigation recommended."
                )
            
            # Check for unresolved violations
            unresolved_violations = [v for v in violations if not v.resolved]
            if unresolved_violations:
                recommendations.append(
                    f"{len(unresolved_violations)} violations remain unresolved. "
                    "Prioritize resolution activities."
                )
            
            # Performance-specific recommendations
            response_time_targets = [t for t in targets if t.metric_type == SLAMetricType.RESPONSE_TIME]
            for target in response_time_targets:
                target_measurements = [m for m in measurements if m.target_id == target.target_id]
                if target_measurements:
                    avg_response_time = statistics.mean([m.measured_value for m in target_measurements])
                    if avg_response_time > target.target_value * 1.5:
                        recommendations.append(
                            f"Response time for '{target.name}' is 50% above target. "
                            "Consider performance optimization."
                        )
            
            # If no specific recommendations, add general ones
            if not recommendations:
                recommendations.extend([
                    "SLA performance is within acceptable ranges.",
                    "Continue monitoring and maintain current service levels.",
                    "Consider reviewing SLA targets for optimization opportunities."
                ])
                
        except Exception as e:
            self.logger.error(f"Recommendation generation failed: {e}")
            recommendations.append("Error generating recommendations. Manual review recommended.")
        
        return recommendations


class SLATracker:
    """
    Comprehensive SLA Tracking and Monitoring System
    
    Provides real-time SLA monitoring, violation detection, reporting, and predictive
    analytics for the DoD API Gateway implementation.
    """
    
    def __init__(self, redis_url: str = "redis://localhost:6379"):
        """Initialize SLA Tracker."""
        self.logger = logging.getLogger(__name__)
        self.redis_client = None
        self.redis_url = redis_url
        
        # SLA components
        self.calculator = SLACalculator()
        self.predictor = SLAPredictor()
        self.report_generator = SLAReportGenerator()
        
        # Storage
        self.sla_targets: Dict[str, SLATarget] = {}
        self.measurements: deque = deque(maxlen=100000)  # Store recent measurements
        self.violations: deque = deque(maxlen=10000)     # Store recent violations
        
        # Audit integration
        self.audit_logger = None
        self.compliance_reporter = None
        
        # Monitoring state
        self.monitoring_active = False
        self.last_check_time = None
        
    async def initialize(self) -> None:
        """Initialize SLA tracker."""
        try:
            # Initialize Redis client
            self.redis_client = await aioredis.from_url(self.redis_url)
            await self.redis_client.ping()
            
            # Initialize audit integration
            try:
                self.audit_logger = AuditLogger()
                self.compliance_reporter = ComplianceReporter()
                await self.audit_logger.initialize()
            except Exception as e:
                self.logger.warning(f"Audit integration failed: {e}")
            
            # Load existing SLA targets
            await self._load_sla_targets()
            
            # Load recent measurements and violations
            await self._load_recent_data()
            
            # Setup default SLA targets if none exist
            if not self.sla_targets:
                await self._setup_default_targets()
            
            # Start monitoring
            asyncio.create_task(self._monitoring_loop())
            asyncio.create_task(self._violation_detection_loop())
            asyncio.create_task(self._predictive_analysis_loop())
            
            self.monitoring_active = True
            self.logger.info("SLA Tracker initialized successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize SLA tracker: {e}")
            raise
    
    async def _load_sla_targets(self) -> None:
        """Load SLA targets from storage."""
        try:
            targets_data = await self.redis_client.get("sla_targets")
            if targets_data:
                targets_dict = json.loads(targets_data)
                for target_id, target_data in targets_dict.items():
                    target = SLATarget(**target_data)
                    # Convert enum strings back to enums
                    target.metric_type = SLAMetricType(target_data['metric_type'])
                    target.priority = SLAPriority(target_data['priority'])
                    if target_data.get('created_at'):
                        target.created_at = datetime.fromisoformat(target_data['created_at'])
                    self.sla_targets[target_id] = target
                    
        except Exception as e:
            self.logger.error(f"Failed to load SLA targets: {e}")
    
    async def _load_recent_data(self) -> None:
        """Load recent measurements and violations."""
        try:
            # Load recent measurements
            measurements_data = await self.redis_client.lrange("sla_measurements", 0, 10000)
            for data in measurements_data:
                try:
                    measurement_dict = json.loads(data)
                    measurement = SLAMeasurement(**measurement_dict)
                    measurement.timestamp = datetime.fromisoformat(measurement_dict['timestamp'])
                    measurement.status = SLAStatus(measurement_dict['status'])
                    self.measurements.append(measurement)
                except Exception:
                    continue
            
            # Load recent violations
            violations_data = await self.redis_client.lrange("sla_violations", 0, 1000)
            for data in violations_data:
                try:
                    violation_dict = json.loads(data)
                    violation = SLAViolation(**violation_dict)
                    violation.start_time = datetime.fromisoformat(violation_dict['start_time'])
                    if violation_dict.get('end_time'):
                        violation.end_time = datetime.fromisoformat(violation_dict['end_time'])
                    violation.severity = ViolationSeverity(violation_dict['severity'])
                    self.violations.append(violation)
                except Exception:
                    continue
                    
        except Exception as e:
            self.logger.error(f"Failed to load recent data: {e}")
    
    async def _setup_default_targets(self) -> None:
        """Setup default SLA targets for common metrics."""
        default_targets = [
            SLATarget(
                target_id="availability_critical",
                name="API Availability - Critical Services",
                description="Availability target for critical API services",
                metric_type=SLAMetricType.AVAILABILITY,
                target_value=99.9,
                threshold_warning=99.5,
                threshold_critical=99.0,
                measurement_period=3600,  # 1 hour
                priority=SLAPriority.CRITICAL,
                service_component="API Gateway",
                customer_impact="High impact on all users"
            ),
            SLATarget(
                target_id="response_time_p95",
                name="Response Time 95th Percentile",
                description="95th percentile response time target",
                metric_type=SLAMetricType.RESPONSE_TIME,
                target_value=2.0,  # 2 seconds
                threshold_warning=3.0,
                threshold_critical=5.0,
                measurement_period=3600,
                priority=SLAPriority.HIGH,
                service_component="API Endpoints",
                customer_impact="User experience degradation"
            ),
            SLATarget(
                target_id="error_rate",
                name="API Error Rate",
                description="Overall API error rate target",
                metric_type=SLAMetricType.ERROR_RATE,
                target_value=1.0,  # 1%
                threshold_warning=2.0,
                threshold_critical=5.0,
                measurement_period=3600,
                priority=SLAPriority.HIGH,
                service_component="API Gateway",
                customer_impact="Service reliability issues"
            ),
            SLATarget(
                target_id="throughput",
                name="API Throughput",
                description="Minimum throughput target",
                metric_type=SLAMetricType.THROUGHPUT,
                target_value=100.0,  # 100 requests/second
                threshold_warning=80.0,
                threshold_critical=50.0,
                measurement_period=3600,
                priority=SLAPriority.MEDIUM,
                service_component="API Gateway",
                customer_impact="Capacity limitations"
            )
        ]
        
        for target in default_targets:
            await self.add_sla_target(target)
    
    async def add_sla_target(self, target: SLATarget) -> bool:
        """Add a new SLA target."""
        try:
            self.sla_targets[target.target_id] = target
            
            # Save to Redis
            await self._save_sla_targets()
            
            # Log to audit system
            if self.audit_logger:
                await self.audit_logger.log_event(
                    event_type="sla_target_created",
                    details=asdict(target),
                    severity="info"
                )
            
            self.logger.info(f"SLA target added: {target.name}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to add SLA target: {e}")
            return False
    
    async def _save_sla_targets(self) -> None:
        """Save SLA targets to Redis."""
        try:
            targets_dict = {}
            for target_id, target in self.sla_targets.items():
                target_data = asdict(target)
                target_data['metric_type'] = target.metric_type.value
                target_data['priority'] = target.priority.value
                if target.created_at:
                    target_data['created_at'] = target.created_at.isoformat()
                targets_dict[target_id] = target_data
            
            await self.redis_client.set("sla_targets", json.dumps(targets_dict))
            
        except Exception as e:
            self.logger.error(f"Failed to save SLA targets: {e}")
    
    async def record_measurement(self, target_id: str, measured_value: float,
                               measurement_period_seconds: int = 3600,
                               additional_context: Optional[Dict[str, Any]] = None) -> None:
        """Record an SLA measurement."""
        try:
            if target_id not in self.sla_targets:
                self.logger.warning(f"Unknown SLA target: {target_id}")
                return
            
            target = self.sla_targets[target_id]
            
            # Determine status
            status = await self._determine_status(target, measured_value)
            
            # Create measurement
            measurement = SLAMeasurement(
                measurement_id=str(uuid.uuid4()),
                target_id=target_id,
                timestamp=datetime.utcnow(),
                measured_value=measured_value,
                status=status,
                measurement_period_seconds=measurement_period_seconds,
                additional_context=additional_context or {}
            )
            
            # Store measurement
            self.measurements.append(measurement)
            
            # Save to Redis
            await self.redis_client.lpush(
                "sla_measurements",
                json.dumps({
                    **asdict(measurement),
                    'timestamp': measurement.timestamp.isoformat(),
                    'status': measurement.status.value
                })
            )
            await self.redis_client.ltrim("sla_measurements", 0, 100000)  # Keep recent 100k
            
            # Check for violations
            if status in [SLAStatus.VIOLATION, SLAStatus.CRITICAL_VIOLATION]:
                await self._handle_violation(target, measurement)
            
            self.logger.debug(f"SLA measurement recorded for {target.name}: {measured_value}")
            
        except Exception as e:
            self.logger.error(f"Failed to record SLA measurement: {e}")
    
    async def _determine_status(self, target: SLATarget, measured_value: float) -> SLAStatus:
        """Determine SLA status based on measured value."""
        try:
            if target.metric_type in [SLAMetricType.AVAILABILITY, SLAMetricType.THROUGHPUT]:
                # For metrics where higher is better
                if measured_value >= target.target_value:
                    return SLAStatus.COMPLIANT
                elif measured_value >= target.threshold_warning:
                    return SLAStatus.WARNING
                elif measured_value >= target.threshold_critical:
                    return SLAStatus.VIOLATION
                else:
                    return SLAStatus.CRITICAL_VIOLATION
            else:
                # For metrics where lower is better
                if measured_value <= target.target_value:
                    return SLAStatus.COMPLIANT
                elif measured_value <= target.threshold_warning:
                    return SLAStatus.WARNING
                elif measured_value <= target.threshold_critical:
                    return SLAStatus.VIOLATION
                else:
                    return SLAStatus.CRITICAL_VIOLATION
                    
        except Exception as e:
            self.logger.error(f"Status determination failed: {e}")
            return SLAStatus.VIOLATION
    
    async def _handle_violation(self, target: SLATarget, measurement: SLAMeasurement) -> None:
        """Handle SLA violation."""
        try:
            # Determine severity
            if measurement.status == SLAStatus.CRITICAL_VIOLATION:
                severity = ViolationSeverity.CRITICAL
            elif target.priority == SLAPriority.CRITICAL:
                severity = ViolationSeverity.MAJOR
            else:
                severity = ViolationSeverity.MINOR
            
            # Create violation record
            violation = SLAViolation(
                violation_id=str(uuid.uuid4()),
                target_id=target.target_id,
                start_time=measurement.timestamp,
                end_time=None,  # Will be set when resolved
                severity=severity,
                measured_value=measurement.measured_value,
                target_value=target.target_value,
                duration_seconds=0,  # Will be calculated when resolved
                root_cause=None,  # To be investigated
                impact_description=target.customer_impact,
                resolution_actions=[],
                resolved=False,
                escalated=severity in [ViolationSeverity.CRITICAL, ViolationSeverity.CATASTROPHIC]
            )
            
            # Store violation
            self.violations.append(violation)
            
            # Save to Redis
            await self.redis_client.lpush(
                "sla_violations",
                json.dumps({
                    **asdict(violation),
                    'start_time': violation.start_time.isoformat(),
                    'severity': violation.severity.value
                })
            )
            await self.redis_client.ltrim("sla_violations", 0, 10000)  # Keep recent 10k
            
            # Log to audit system
            if self.audit_logger:
                await self.audit_logger.log_event(
                    event_type="sla_violation",
                    details={
                        'target_name': target.name,
                        'measured_value': measurement.measured_value,
                        'target_value': target.target_value,
                        'severity': severity.value
                    },
                    severity="high" if severity == ViolationSeverity.CRITICAL else "medium"
                )
            
            self.logger.warning(f"SLA violation detected for {target.name}: {measurement.measured_value}")
            
        except Exception as e:
            self.logger.error(f"Violation handling failed: {e}")
    
    async def _monitoring_loop(self) -> None:
        """Background monitoring loop."""
        while True:
            try:
                if self.monitoring_active:
                    await self._check_sla_status()
                    self.last_check_time = datetime.utcnow()
                
                await asyncio.sleep(60)  # Check every minute
                
            except Exception as e:
                self.logger.error(f"Monitoring loop error: {e}")
                await asyncio.sleep(60)
    
    async def _violation_detection_loop(self) -> None:
        """Background violation detection loop."""
        while True:
            try:
                if self.monitoring_active:
                    await self._detect_ongoing_violations()
                
                await asyncio.sleep(300)  # Check every 5 minutes
                
            except Exception as e:
                self.logger.error(f"Violation detection loop error: {e}")
                await asyncio.sleep(300)
    
    async def _predictive_analysis_loop(self) -> None:
        """Background predictive analysis loop."""
        while True:
            try:
                if self.monitoring_active and len(self.measurements) > 100:
                    await self._run_predictive_analysis()
                
                await asyncio.sleep(1800)  # Run every 30 minutes
                
            except Exception as e:
                self.logger.error(f"Predictive analysis loop error: {e}")
                await asyncio.sleep(1800)
    
    async def _check_sla_status(self) -> None:
        """Check current SLA status."""
        try:
            current_time = datetime.utcnow()
            
            for target in self.sla_targets.values():
                if not target.enabled:
                    continue
                
                # Get recent measurements for this target
                recent_measurements = [
                    m for m in self.measurements
                    if (m.target_id == target.target_id and
                        (current_time - m.timestamp).total_seconds() < target.measurement_period)
                ]
                
                if recent_measurements:
                    # Check if any are in violation
                    violation_measurements = [
                        m for m in recent_measurements
                        if m.status in [SLAStatus.VIOLATION, SLAStatus.CRITICAL_VIOLATION]
                    ]
                    
                    if violation_measurements:
                        # Check if this is a new violation period
                        await self._check_new_violation_period(target, violation_measurements)
                        
        except Exception as e:
            self.logger.error(f"SLA status check failed: {e}")
    
    async def _detect_ongoing_violations(self) -> None:
        """Detect and update ongoing violations."""
        try:
            current_time = datetime.utcnow()
            
            # Check unresolved violations
            for violation in self.violations:
                if not violation.resolved and violation.end_time is None:
                    # Check if violation is still ongoing
                    target = self.sla_targets.get(violation.target_id)
                    if not target:
                        continue
                    
                    # Get recent measurements
                    recent_measurements = [
                        m for m in self.measurements
                        if (m.target_id == violation.target_id and
                            (current_time - m.timestamp).total_seconds() < 600)  # Last 10 minutes
                    ]
                    
                    if recent_measurements:
                        # Check if all recent measurements are compliant
                        all_compliant = all(
                            m.status in [SLAStatus.COMPLIANT, SLAStatus.WARNING]
                            for m in recent_measurements
                        )
                        
                        if all_compliant:
                            # Mark violation as resolved
                            await self._resolve_violation(violation, current_time)
                            
        except Exception as e:
            self.logger.error(f"Ongoing violation detection failed: {e}")
    
    async def _resolve_violation(self, violation: SLAViolation, end_time: datetime) -> None:
        """Resolve an SLA violation."""
        try:
            violation.end_time = end_time
            violation.duration_seconds = int((end_time - violation.start_time).total_seconds())
            violation.resolved = True
            
            # Log resolution
            if self.audit_logger:
                await self.audit_logger.log_event(
                    event_type="sla_violation_resolved",
                    details={
                        'violation_id': violation.violation_id,
                        'target_id': violation.target_id,
                        'duration_seconds': violation.duration_seconds
                    },
                    severity="info"
                )
            
            self.logger.info(f"SLA violation resolved: {violation.violation_id}")
            
        except Exception as e:
            self.logger.error(f"Violation resolution failed: {e}")
    
    async def _run_predictive_analysis(self) -> None:
        """Run predictive analysis for potential violations."""
        try:
            # Get recent measurements for analysis
            analysis_measurements = list(self.measurements)[-1000:]  # Last 1000 measurements
            
            if len(analysis_measurements) < 50:
                return
            
            # Run prediction
            predictions = await self.predictor.predict_violations(
                analysis_measurements,
                list(self.sla_targets.values()),
                prediction_window_hours=24
            )
            
            # Store predictions
            if predictions:
                prediction_data = {
                    'timestamp': datetime.utcnow().isoformat(),
                    'predictions': predictions
                }
                
                await self.redis_client.set(
                    "sla_predictions",
                    json.dumps(prediction_data),
                    ex=86400  # Expire after 24 hours
                )
                
                # Log high-risk predictions
                high_risk_predictions = [p for p in predictions if p.get('risk_level', 0) > 0.8]
                if high_risk_predictions and self.audit_logger:
                    await self.audit_logger.log_event(
                        event_type="sla_high_risk_prediction",
                        details={'predictions': high_risk_predictions},
                        severity="warning"
                    )
                    
        except Exception as e:
            self.logger.error(f"Predictive analysis failed: {e}")
    
    async def get_current_sla_status(self) -> Dict[str, Any]:
        """Get current SLA status overview."""
        try:
            current_time = datetime.utcnow()
            status = {
                'timestamp': current_time.isoformat(),
                'monitoring_active': self.monitoring_active,
                'total_targets': len(self.sla_targets),
                'target_status': {},
                'active_violations': 0,
                'overall_compliance': 0.0
            }
            
            compliant_targets = 0
            
            for target_id, target in self.sla_targets.items():
                if not target.enabled:
                    continue
                
                # Get recent measurements
                recent_measurements = [
                    m for m in self.measurements
                    if (m.target_id == target_id and
                        (current_time - m.timestamp).total_seconds() < target.measurement_period)
                ]
                
                if recent_measurements:
                    latest_measurement = max(recent_measurements, key=lambda x: x.timestamp)
                    target_status = {
                        'name': target.name,
                        'current_status': latest_measurement.status.value,
                        'current_value': latest_measurement.measured_value,
                        'target_value': target.target_value,
                        'last_measured': latest_measurement.timestamp.isoformat(),
                        'priority': target.priority.value
                    }
                    
                    if latest_measurement.status == SLAStatus.COMPLIANT:
                        compliant_targets += 1
                else:
                    target_status = {
                        'name': target.name,
                        'current_status': 'no_data',
                        'target_value': target.target_value,
                        'priority': target.priority.value
                    }
                
                status['target_status'][target_id] = target_status
            
            # Count active violations
            active_violations = len([v for v in self.violations if not v.resolved])
            status['active_violations'] = active_violations
            
            # Calculate overall compliance
            enabled_targets = len([t for t in self.sla_targets.values() if t.enabled])
            if enabled_targets > 0:
                status['overall_compliance'] = (compliant_targets / enabled_targets) * 100
            
            return status
            
        except Exception as e:
            self.logger.error(f"Failed to get SLA status: {e}")
            return {'error': str(e)}
    
    async def generate_sla_report(self, period: ReportingPeriod,
                                start_time: Optional[datetime] = None,
                                end_time: Optional[datetime] = None) -> SLAReport:
        """Generate comprehensive SLA report."""
        try:
            # Set default time range if not provided
            if end_time is None:
                end_time = datetime.utcnow()
            
            if start_time is None:
                if period == ReportingPeriod.HOURLY:
                    start_time = end_time - timedelta(hours=1)
                elif period == ReportingPeriod.DAILY:
                    start_time = end_time - timedelta(days=1)
                elif period == ReportingPeriod.WEEKLY:
                    start_time = end_time - timedelta(weeks=1)
                elif period == ReportingPeriod.MONTHLY:
                    start_time = end_time - timedelta(days=30)
                else:
                    start_time = end_time - timedelta(days=1)
            
            # Filter data for the period
            period_measurements = [
                m for m in self.measurements
                if start_time <= m.timestamp <= end_time
            ]
            
            period_violations = [
                v for v in self.violations
                if start_time <= v.start_time <= end_time
            ]
            
            # Generate report
            report = await self.report_generator.generate_compliance_report(
                list(self.sla_targets.values()),
                period_measurements,
                period_violations,
                period,
                start_time,
                end_time
            )
            
            # Store report
            report_key = f"sla_report:{report.report_id}"
            await self.redis_client.set(
                report_key,
                json.dumps({
                    **asdict(report),
                    'reporting_period': report.reporting_period.value,
                    'start_time': report.start_time.isoformat(),
                    'end_time': report.end_time.isoformat(),
                    'generated_at': report.generated_at.isoformat(),
                    'violations': [
                        {
                            **asdict(v),
                            'start_time': v.start_time.isoformat(),
                            'end_time': v.end_time.isoformat() if v.end_time else None,
                            'severity': v.severity.value
                        } for v in report.violations
                    ]
                }),
                ex=86400 * 30  # Keep for 30 days
            )
            
            # Log report generation
            if self.audit_logger:
                await self.audit_logger.log_event(
                    event_type="sla_report_generated",
                    details={
                        'report_id': report.report_id,
                        'period': period.value,
                        'overall_compliance': report.overall_compliance,
                        'violations_count': len(report.violations)
                    },
                    severity="info"
                )
            
            return report
            
        except Exception as e:
            self.logger.error(f"SLA report generation failed: {e}")
            raise
    
    async def get_predictions(self) -> Dict[str, Any]:
        """Get current SLA violation predictions."""
        try:
            predictions_data = await self.redis_client.get("sla_predictions")
            if predictions_data:
                return json.loads(predictions_data)
            else:
                return {'message': 'No predictions available'}
                
        except Exception as e:
            self.logger.error(f"Failed to get predictions: {e}")
            return {'error': str(e)}
    
    async def close(self) -> None:
        """Clean up SLA tracker resources."""
        self.monitoring_active = False
        
        if self.redis_client:
            await self.redis_client.close()
        
        self.logger.info("SLA Tracker closed")


if __name__ == "__main__":
    # Example usage
    async def main():
        tracker = SLATracker()
        await tracker.initialize()
        
        # Simulate some SLA measurements
        for i in range(50):
            # Availability measurement
            availability = 99.8 + (i % 5) * 0.1  # Varies between 99.8-100.2%
            await tracker.record_measurement("availability_critical", availability)
            
            # Response time measurement
            response_time = 1.5 + (i % 10) * 0.1  # Varies between 1.5-2.4 seconds
            await tracker.record_measurement("response_time_p95", response_time)
            
            # Error rate measurement
            error_rate = 0.5 + (i % 8) * 0.1  # Varies between 0.5-1.2%
            await tracker.record_measurement("error_rate", error_rate)
            
            await asyncio.sleep(0.1)  # Small delay between measurements
        
        # Get current status
        status = await tracker.get_current_sla_status()
        print(f"SLA Status: {json.dumps(status, indent=2)}")
        
        # Generate a report
        report = await tracker.generate_sla_report(ReportingPeriod.HOURLY)
        print(f"SLA Report: {json.dumps(asdict(report), indent=2, default=str)}")
        
        # Get predictions
        predictions = await tracker.get_predictions()
        print(f"Predictions: {json.dumps(predictions, indent=2)}")
        
        await tracker.close()
    
    asyncio.run(main())