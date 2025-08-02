#!/usr/bin/env python3
"""
Data Collector
===============

Centralized data collection service that coordinates gathering information
from audit, security testing, and monitoring systems with caching and
performance optimization.

Classification: UNCLASSIFIED//FOR OFFICIAL USE ONLY
Version: 1.0
Author: Security Compliance Team
Date: 2025-07-28
"""

import asyncio
import json
import hashlib
import logging
from pathlib import Path
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Tuple
import concurrent.futures

from .audit_integration import AuditIntegration
from .security_testing_integration import SecurityTestingIntegration
from .monitoring_integration import MonitoringIntegration

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class DataCollector:
    """
    Centralized Data Collector
    
    Coordinates data collection from multiple sources with caching,
    performance optimization, and error handling.
    """
    
    def __init__(self,
                 audit_integration: AuditIntegration,
                 testing_integration: SecurityTestingIntegration,
                 monitoring_integration: MonitoringIntegration,
                 cache_path: Optional[Path] = None,
                 cache_ttl_hours: int = 24):
        """
        Initialize Data Collector
        
        Args:
            audit_integration: Audit system integration
            testing_integration: Security testing integration
            monitoring_integration: Monitoring system integration
            cache_path: Path for cache storage (None to disable caching)
            cache_ttl_hours: Cache time-to-live in hours
        """
        self.audit_integration = audit_integration
        self.testing_integration = testing_integration
        self.monitoring_integration = monitoring_integration
        
        # Cache configuration
        self.cache_enabled = cache_path is not None
        self.cache_path = cache_path
        self.cache_ttl = timedelta(hours=cache_ttl_hours)
        
        if self.cache_enabled:
            self.cache_path.mkdir(parents=True, exist_ok=True)
        
        # Cache statistics
        self.cache_stats = {
            'cache_hits': 0,
            'cache_misses': 0,
            'total_requests': 0,
            'cache_size_mb': 0.0
        }
        
        logger.info(f"Data Collector initialized with cache {'enabled' if self.cache_enabled else 'disabled'}")
    
    def _generate_cache_key(self, system_id: str, data_type: str, **kwargs) -> str:
        """
        Generate cache key for a data request
        
        Args:
            system_id: System identifier
            data_type: Type of data being requested
            **kwargs: Additional parameters
            
        Returns:
            Cache key string
        """
        # Create a stable hash from the request parameters
        key_data = {
            'system_id': system_id,
            'data_type': data_type,
            'params': sorted(kwargs.items())
        }
        
        key_string = json.dumps(key_data, sort_keys=True)
        key_hash = hashlib.sha256(key_string.encode()).hexdigest()[:16]
        
        return f"{system_id}_{data_type}_{key_hash}"
    
    def _get_cache_file_path(self, cache_key: str) -> Path:
        """Get file path for cache key"""
        return self.cache_path / f"{cache_key}.json"
    
    def _is_cache_valid(self, cache_file: Path) -> bool:
        """Check if cache file is still valid"""
        if not cache_file.exists():
            return False
        
        # Check file age
        file_time = datetime.fromtimestamp(cache_file.stat().st_mtime, timezone.utc)
        return datetime.now(timezone.utc) - file_time < self.cache_ttl
    
    async def _get_from_cache(self, cache_key: str) -> Optional[Any]:
        """
        Get data from cache if available and valid
        
        Args:
            cache_key: Cache key
            
        Returns:
            Cached data or None if not available/valid
        """
        if not self.cache_enabled:
            return None
        
        cache_file = self._get_cache_file_path(cache_key)
        
        if not self._is_cache_valid(cache_file):
            return None
        
        try:
            with open(cache_file, 'r') as f:
                cache_data = json.load(f)
            
            self.cache_stats['cache_hits'] += 1
            logger.debug(f"Cache hit for key: {cache_key}")
            
            return cache_data['data']
            
        except Exception as e:
            logger.warning(f"Error reading cache file {cache_file}: {e}")
            return None
    
    async def _save_to_cache(self, cache_key: str, data: Any):
        """
        Save data to cache
        
        Args:
            cache_key: Cache key
            data: Data to cache
        """
        if not self.cache_enabled:
            return
        
        try:
            cache_file = self._get_cache_file_path(cache_key)
            
            cache_data = {
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'cache_key': cache_key,
                'data': data
            }
            
            with open(cache_file, 'w') as f:
                json.dump(cache_data, f, indent=2, default=str)
            
            logger.debug(f"Cached data for key: {cache_key}")
            
        except Exception as e:
            logger.warning(f"Error saving to cache: {e}")
    
    async def collect_audit_data(self,
                                system_id: str,
                                date_range_days: int = 30,
                                use_cache: bool = True) -> Dict[str, Any]:
        """
        Collect comprehensive audit data for a system
        
        Args:
            system_id: System identifier
            date_range_days: Number of days to collect data for
            use_cache: Whether to use cache
            
        Returns:
            Comprehensive audit data
        """
        cache_key = self._generate_cache_key(
            system_id, 'audit_data', 
            date_range_days=date_range_days
        )
        
        self.cache_stats['total_requests'] += 1
        
        # Try cache first
        if use_cache:
            cached_data = await self._get_from_cache(cache_key)
            if cached_data is not None:
                return cached_data
        
        self.cache_stats['cache_misses'] += 1
        logger.info(f"Collecting audit data for {system_id}")
        
        # Collect data from audit system
        try:
            start_date = datetime.now(timezone.utc) - timedelta(days=date_range_days)
            end_date = datetime.now(timezone.utc)
            
            # Collect all audit data concurrently
            tasks = [
                self.audit_integration.get_audit_events(system_id, start_date, end_date),
                self.audit_integration.get_compliance_findings(system_id, 'U'),
                self.audit_integration.get_compliance_status(system_id),
                self.audit_integration.get_control_assessments(system_id),
                self.audit_integration.get_evidence_artifacts(system_id)
            ]
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            audit_data = {
                'system_id': system_id,
                'collection_timestamp': datetime.now(timezone.utc).isoformat(),
                'date_range_days': date_range_days,
                'events': results[0] if not isinstance(results[0], Exception) else [],
                'findings': results[1] if not isinstance(results[1], Exception) else [],
                'compliance_status': results[2] if not isinstance(results[2], Exception) else {},
                'control_assessments': results[3] if not isinstance(results[3], Exception) else {},
                'evidence': results[4] if not isinstance(results[4], Exception) else [],
                'collection_errors': [str(r) for r in results if isinstance(r, Exception)]
            }
            
            # Cache the results
            await self._save_to_cache(cache_key, audit_data)
            
            logger.info(f"Collected audit data: {len(audit_data['events'])} events, "
                       f"{len(audit_data['findings'])} findings")
            
            return audit_data
            
        except Exception as e:
            logger.error(f"Error collecting audit data: {e}")
            return {
                'system_id': system_id,
                'collection_timestamp': datetime.now(timezone.utc).isoformat(),
                'events': [],
                'findings': [],
                'compliance_status': {},
                'control_assessments': {},
                'evidence': [],
                'collection_errors': [str(e)]
            }
    
    async def collect_security_testing_data(self,
                                           system_id: str,
                                           date_range_days: int = 30,
                                           use_cache: bool = True) -> Dict[str, Any]:
        """
        Collect comprehensive security testing data for a system
        
        Args:
            system_id: System identifier
            date_range_days: Number of days to collect data for
            use_cache: Whether to use cache
            
        Returns:
            Comprehensive security testing data
        """
        cache_key = self._generate_cache_key(
            system_id, 'security_testing_data',
            date_range_days=date_range_days
        )
        
        self.cache_stats['total_requests'] += 1
        
        # Try cache first
        if use_cache:
            cached_data = await self._get_cache_data(cache_key)
            if cached_data is not None:
                return cached_data
        
        self.cache_stats['cache_misses'] += 1
        logger.info(f"Collecting security testing data for {system_id}")
        
        try:
            # Collect all security testing data concurrently
            tasks = [
                self.testing_integration.get_recent_scans(system_id, date_range_days),
                self.testing_integration.get_control_test_results(system_id),
                self.testing_integration.get_penetration_test_results(system_id),
                self.testing_integration.get_security_assessments(system_id),
                self.testing_integration.get_vulnerability_trends(system_id, date_range_days)
            ]
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            testing_data = {
                'system_id': system_id,
                'collection_timestamp': datetime.now(timezone.utc).isoformat(),
                'date_range_days': date_range_days,
                'vulnerability_scans': results[0] if not isinstance(results[0], Exception) else [],
                'control_tests': results[1] if not isinstance(results[1], Exception) else {},
                'penetration_tests': results[2] if not isinstance(results[2], Exception) else [],
                'security_assessments': results[3] if not isinstance(results[3], Exception) else [],
                'vulnerability_trends': results[4] if not isinstance(results[4], Exception) else {},
                'collection_errors': [str(r) for r in results if isinstance(r, Exception)]
            }
            
            # Calculate summary statistics
            testing_data['test_results'] = self._calculate_test_summary(testing_data)
            
            # Cache the results
            await self._save_to_cache(cache_key, testing_data)
            
            logger.info(f"Collected security testing data: {len(testing_data['vulnerability_scans'])} scans, "
                       f"{len(testing_data['control_tests'])} control tests")
            
            return testing_data
            
        except Exception as e:
            logger.error(f"Error collecting security testing data: {e}")
            return {
                'system_id': system_id,
                'collection_timestamp': datetime.now(timezone.utc).isoformat(),
                'vulnerability_scans': [],
                'control_tests': {},
                'penetration_tests': [],
                'security_assessments': [],
                'vulnerability_trends': {},
                'test_results': {},
                'collection_errors': [str(e)]
            }
    
    async def collect_monitoring_data(self,
                                    system_id: str,
                                    date_range_days: int = 30,
                                    use_cache: bool = True) -> Dict[str, Any]:
        """
        Collect comprehensive monitoring data for a system
        
        Args:
            system_id: System identifier
            date_range_days: Number of days to collect data for
            use_cache: Whether to use cache
            
        Returns:
            Comprehensive monitoring data
        """
        cache_key = self._generate_cache_key(
            system_id, 'monitoring_data',
            date_range_days=date_range_days
        )
        
        self.cache_stats['total_requests'] += 1
        
        # Try cache first
        if use_cache:
            cached_data = await self._get_from_cache(cache_key)
            if cached_data is not None:
                return cached_data
        
        self.cache_stats['cache_misses'] += 1
        logger.info(f"Collecting monitoring data for {system_id}")
        
        try:
            # Collect all monitoring data concurrently
            tasks = [
                self.monitoring_integration.get_compliance_metrics(system_id, date_range_days),
                self.monitoring_integration.get_recent_alerts(system_id, date_range_days),
                self.monitoring_integration.get_security_incidents(system_id, date_range_days * 3),
                self.monitoring_integration.get_audit_log_metrics(system_id, date_range_days),
                self.monitoring_integration.get_performance_baseline(system_id)
            ]
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            monitoring_data = {
                'system_id': system_id,
                'collection_timestamp': datetime.now(timezone.utc).isoformat(),
                'date_range_days': date_range_days,
                'metrics': results[0] if not isinstance(results[0], Exception) else {},
                'alerts': results[1] if not isinstance(results[1], Exception) else [],
                'incidents': results[2] if not isinstance(results[2], Exception) else [],
                'audit_log_metrics': results[3] if not isinstance(results[3], Exception) else {},
                'performance_baseline': results[4] if not isinstance(results[4], Exception) else {},
                'collection_errors': [str(r) for r in results if isinstance(r, Exception)]
            }
            
            # Cache the results
            await self._save_to_cache(cache_key, monitoring_data)
            
            logger.info(f"Collected monitoring data: {len(monitoring_data['alerts'])} alerts, "
                       f"{len(monitoring_data['incidents'])} incidents")
            
            return monitoring_data
            
        except Exception as e:
            logger.error(f"Error collecting monitoring data: {e}")
            return {
                'system_id': system_id,
                'collection_timestamp': datetime.now(timezone.utc).isoformat(),
                'metrics': {},
                'alerts': [],
                'incidents': [],
                'audit_log_metrics': {},
                'performance_baseline': {},
                'collection_errors': [str(e)]
            }
    
    async def collect_all_data(self,
                             system_id: str,
                             date_range_days: int = 30,
                             use_cache: bool = True) -> Dict[str, Any]:
        """
        Collect all compliance data for a system
        
        Args:
            system_id: System identifier
            date_range_days: Number of days to collect data for
            use_cache: Whether to use cache
            
        Returns:
            All compliance data
        """
        logger.info(f"Collecting all compliance data for {system_id}")
        
        # Collect all data types concurrently
        tasks = [
            self.collect_audit_data(system_id, date_range_days, use_cache),
            self.collect_security_testing_data(system_id, date_range_days, use_cache),
            self.collect_monitoring_data(system_id, date_range_days, use_cache)
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        all_data = {
            'system_id': system_id,
            'collection_timestamp': datetime.now(timezone.utc).isoformat(),
            'date_range_days': date_range_days,
            'audit_data': results[0] if not isinstance(results[0], Exception) else {},
            'testing_data': results[1] if not isinstance(results[1], Exception) else {},
            'monitoring_data': results[2] if not isinstance(results[2], Exception) else {},
            'collection_summary': self._generate_collection_summary(results)
        }
        
        return all_data
    
    def _calculate_test_summary(self, testing_data: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate summary statistics for test results"""
        control_tests = testing_data.get('control_tests', {})
        
        if not control_tests:
            return {
                'total_tests': 0,
                'passed': 0,
                'failed': 0,
                'success_rate': 0.0
            }
        
        total_tests = len(control_tests)
        passed = sum(1 for test in control_tests.values() if test.get('result') == 'pass')
        failed = total_tests - passed
        success_rate = (passed / total_tests) * 100 if total_tests > 0 else 0
        
        return {
            'total_tests': total_tests,
            'passed': passed,
            'failed': failed,
            'success_rate': round(success_rate, 1)
        }
    
    def _generate_collection_summary(self, results: List[Any]) -> Dict[str, Any]:
        """Generate summary of data collection results"""
        successful_collections = sum(1 for r in results if not isinstance(r, Exception))
        total_collections = len(results)
        
        errors = [str(r) for r in results if isinstance(r, Exception)]
        
        return {
            'successful_collections': successful_collections,
            'total_collections': total_collections,
            'success_rate': (successful_collections / total_collections) * 100 if total_collections > 0 else 0,
            'collection_errors': errors
        }
    
    def get_cache_stats(self) -> Dict[str, Any]:
        """
        Get cache statistics
        
        Returns:
            Cache statistics
        """
        stats = self.cache_stats.copy()
        
        if self.cache_enabled and self.cache_path.exists():
            # Calculate cache size
            total_size = sum(f.stat().st_size for f in self.cache_path.glob('*.json'))
            stats['cache_size_mb'] = round(total_size / (1024 * 1024), 2)
            stats['cache_files_count'] = len(list(self.cache_path.glob('*.json')))
        else:
            stats['cache_size_mb'] = 0.0
            stats['cache_files_count'] = 0
        
        return stats
    
    async def clear_cache(self, older_than_hours: Optional[int] = None) -> int:
        """
        Clear cache files
        
        Args:
            older_than_hours: Only clear files older than this many hours (None for all)
            
        Returns:
            Number of files cleared
        """
        if not self.cache_enabled:
            return 0
        
        cleared_count = 0
        cutoff_time = None
        
        if older_than_hours is not None:
            cutoff_time = datetime.now(timezone.utc) - timedelta(hours=older_than_hours)
        
        for cache_file in self.cache_path.glob('*.json'):
            try:
                if cutoff_time is None or datetime.fromtimestamp(cache_file.stat().st_mtime, timezone.utc) < cutoff_time:
                    cache_file.unlink()
                    cleared_count += 1
            except Exception as e:
                logger.warning(f"Error clearing cache file {cache_file}: {e}")
        
        if cleared_count > 0:
            logger.info(f"Cleared {cleared_count} cache files")
        
        return cleared_count
    
    async def cleanup(self):
        """Cleanup resources"""
        if self.cache_enabled:
            # Clear old cache files
            await self.clear_cache(older_than_hours=self.cache_ttl.total_seconds() / 3600)
        
        logger.info("Data Collector cleanup completed")


if __name__ == "__main__":
    # Example usage
    import asyncio
    import tempfile
    
    async def main():
        # Initialize integrations
        audit_integration = AuditIntegration({})
        testing_integration = SecurityTestingIntegration({})
        monitoring_integration = MonitoringIntegration({})
        
        with tempfile.TemporaryDirectory() as temp_dir:
            cache_path = Path(temp_dir) / "cache"
            
            collector = DataCollector(
                audit_integration=audit_integration,
                testing_integration=testing_integration,
                monitoring_integration=monitoring_integration,
                cache_path=cache_path,
                cache_ttl_hours=1
            )
            
            # Test data collection
            all_data = await collector.collect_all_data('TEST-001', date_range_days=7)
            
            print(f"Collected data for {all_data['system_id']}")
            print(f"Collection summary: {all_data['collection_summary']}")
            
            # Test cache statistics
            cache_stats = collector.get_cache_stats()
            print(f"Cache stats: {cache_stats}")
            
            await collector.cleanup()
    
    asyncio.run(main())