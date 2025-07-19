"""
Transfer Validation Engine

This module provides comprehensive validation for cross-domain transfers,
including policy validation, content inspection, and security checks.
"""

import logging
import asyncio
import re
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from enum import Enum
import json
import magic
from pathlib import Path

# Import existing security components
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from models.classification_models import ClassificationLevel, DataItem
from engines.cross_domain_guard import NetworkDomain, TransferRequest, TransferDirection


class ValidationResult(Enum):
    """Validation result enumeration"""
    PASSED = "passed"
    FAILED = "failed"
    WARNING = "warning"
    REQUIRES_REVIEW = "requires_review"
    BLOCKED = "blocked"


@dataclass
class ValidationReport:
    """Validation report structure"""
    item_id: str
    timestamp: datetime
    result: ValidationResult
    score: float
    violations: List[str]
    warnings: List[str]
    metadata: Dict[str, Any]
    recommendations: List[str]
    reviewer_notes: Optional[str] = None


class PolicyValidator:
    """Validates transfers against organizational policies"""
    
    def __init__(self):
        self.policies = self._load_policies()
        self.exemptions = self._load_exemptions()
        
    def _load_policies(self) -> Dict[str, Any]:
        """Load transfer policies"""
        return {
            "classification_policies": {
                "mandatory_declassification": {
                    "enabled": True,
                    "authority_required": True,
                    "review_period_days": 30
                },
                "classification_marking": {
                    "required_markings": ["CLASSIFICATION", "HANDLING", "DISSEMINATION"],
                    "validate_markings": True
                },
                "derivative_classification": {
                    "source_tracking": True,
                    "authority_validation": True
                }
            },
            "content_policies": {
                "sensitive_data": {
                    "pii_detection": True,
                    "financial_data": True,
                    "health_data": True,
                    "legal_privileged": True
                },
                "technical_data": {
                    "export_controlled": True,
                    "proprietary": True,
                    "patent_pending": True
                },
                "operational_data": {
                    "mission_critical": True,
                    "time_sensitive": True,
                    "sources_methods": True
                }
            },
            "transfer_policies": {
                "time_restrictions": {
                    "business_hours_only": False,
                    "weekend_restrictions": True,
                    "holiday_restrictions": True
                },
                "volume_limits": {
                    "daily_limit_gb": 100,
                    "monthly_limit_gb": 1000,
                    "concurrent_transfers": 10
                },
                "retention_policies": {
                    "audit_retention_days": 2555,  # 7 years
                    "transfer_log_retention_days": 365,
                    "quarantine_retention_days": 30
                }
            },
            "network_policies": {
                "allowed_paths": {
                    (NetworkDomain.NIPR, NetworkDomain.SIPR): {"enabled": True, "restrictions": []},
                    (NetworkDomain.SIPR, NetworkDomain.JWICS): {"enabled": True, "restrictions": ["intel_only"]},
                    (NetworkDomain.SIPR, NetworkDomain.NIPR): {"enabled": True, "restrictions": ["declassification_required"]},
                    (NetworkDomain.JWICS, NetworkDomain.SIPR): {"enabled": True, "restrictions": ["declassification_required", "intel_review"]}
                },
                "blocked_paths": [
                    (NetworkDomain.JWICS, NetworkDomain.NIPR),
                    (NetworkDomain.NIPR, NetworkDomain.JWICS)
                ]
            }
        }
    
    def _load_exemptions(self) -> Dict[str, Any]:
        """Load policy exemptions"""
        return {
            "emergency_exemptions": {
                "enabled": True,
                "approval_authority": "security_officer",
                "duration_hours": 24,
                "review_required": True
            },
            "mission_critical_exemptions": {
                "enabled": True,
                "approval_authority": "mission_commander",
                "duration_hours": 72,
                "review_required": True
            },
            "technical_exemptions": {
                "enabled": True,
                "approval_authority": "technical_authority",
                "duration_hours": 168,  # 1 week
                "review_required": True
            }
        }
    
    async def validate_transfer_policy(self, request: TransferRequest) -> ValidationReport:
        """Validate transfer against organizational policies"""
        report = ValidationReport(
            item_id=request.id,
            timestamp=datetime.now(),
            result=ValidationResult.PASSED,
            score=100.0,
            violations=[],
            warnings=[],
            metadata={},
            recommendations=[]
        )
        
        try:
            # Validate network policy
            await self._validate_network_policy(request, report)
            
            # Validate classification policy
            await self._validate_classification_policy(request, report)
            
            # Validate content policy
            await self._validate_content_policy(request, report)
            
            # Validate transfer policy
            await self._validate_transfer_policy(request, report)
            
            # Calculate final score and result
            self._calculate_final_result(report)
            
        except Exception as e:
            report.result = ValidationResult.FAILED
            report.violations.append(f"Policy validation error: {str(e)}")
            logging.error(f"Policy validation error for {request.id}: {e}")
        
        return report
    
    async def _validate_network_policy(self, request: TransferRequest, report: ValidationReport):
        """Validate network transfer policy"""
        transfer_path = (request.source_domain, request.target_domain)
        
        # Check if path is blocked
        if transfer_path in self.policies["network_policies"]["blocked_paths"]:
            report.violations.append(f"Transfer path {transfer_path} is blocked by policy")
            report.score -= 100
            return
        
        # Check if path is allowed
        allowed_paths = self.policies["network_policies"]["allowed_paths"]
        if transfer_path not in allowed_paths:
            report.violations.append(f"Transfer path {transfer_path} is not explicitly allowed")
            report.score -= 50
            return
        
        # Check path restrictions
        path_config = allowed_paths[transfer_path]
        restrictions = path_config.get("restrictions", [])
        
        for restriction in restrictions:
            if restriction == "declassification_required":
                if not self._check_declassification_authority(request):
                    report.violations.append("Declassification authority required but not present")
                    report.score -= 30
            elif restriction == "intel_only":
                if not self._check_intelligence_clearance(request):
                    report.violations.append("Intelligence clearance required for this transfer")
                    report.score -= 30
            elif restriction == "intel_review":
                report.warnings.append("Intelligence review required for this transfer")
                report.score -= 10
    
    async def _validate_classification_policy(self, request: TransferRequest, report: ValidationReport):
        """Validate classification policy compliance"""
        classification_policies = self.policies["classification_policies"]
        
        # Check mandatory declassification
        if request.direction == TransferDirection.DOWNWARD:
            if classification_policies["mandatory_declassification"]["enabled"]:
                if not self._check_declassification_authority(request):
                    report.violations.append("Mandatory declassification authority required")
                    report.score -= 40
        
        # Validate classification markings
        if classification_policies["classification_marking"]["validate_markings"]:
            for data_item in request.data_items:
                if not self._validate_classification_markings(data_item):
                    report.violations.append(f"Invalid classification markings for item {data_item.id}")
                    report.score -= 20
        
        # Check derivative classification
        if classification_policies["derivative_classification"]["source_tracking"]:
            for data_item in request.data_items:
                if not self._validate_derivative_classification(data_item):
                    report.warnings.append(f"Derivative classification source not tracked for item {data_item.id}")
                    report.score -= 5
    
    async def _validate_content_policy(self, request: TransferRequest, report: ValidationReport):
        """Validate content policy compliance"""
        content_policies = self.policies["content_policies"]
        
        for data_item in request.data_items:
            # Check sensitive data policies
            if content_policies["sensitive_data"]["pii_detection"]:
                if self._contains_pii(data_item):
                    report.violations.append(f"PII detected in item {data_item.id}")
                    report.score -= 25
            
            # Check technical data policies
            if content_policies["technical_data"]["export_controlled"]:
                if self._is_export_controlled(data_item):
                    report.violations.append(f"Export controlled data in item {data_item.id}")
                    report.score -= 30
            
            # Check operational data policies
            if content_policies["operational_data"]["sources_methods"]:
                if self._contains_sources_methods(data_item):
                    report.violations.append(f"Sources and methods data in item {data_item.id}")
                    report.score -= 35
    
    async def _validate_transfer_policy(self, request: TransferRequest, report: ValidationReport):
        """Validate transfer-specific policies"""
        transfer_policies = self.policies["transfer_policies"]
        
        # Check time restrictions
        if transfer_policies["time_restrictions"]["business_hours_only"]:
            if not self._is_business_hours(request.timestamp):
                report.violations.append("Transfer requested outside business hours")
                report.score -= 15
        
        # Check volume limits
        total_size = sum(len(str(item.content)) for item in request.data_items)
        daily_limit = transfer_policies["volume_limits"]["daily_limit_gb"] * 1024 * 1024 * 1024
        
        if total_size > daily_limit:
            report.violations.append(f"Transfer size exceeds daily limit: {total_size} bytes")
            report.score -= 20
    
    def _check_declassification_authority(self, request: TransferRequest) -> bool:
        """Check if requester has declassification authority"""
        # This would check against actual authority database
        return request.requester_clearance.value >= ClassificationLevel.SECRET.value
    
    def _check_intelligence_clearance(self, request: TransferRequest) -> bool:
        """Check if requester has intelligence clearance"""
        # This would check against intelligence clearance database
        return request.metadata.get("intelligence_clearance", False)
    
    def _validate_classification_markings(self, data_item: DataItem) -> bool:
        """Validate classification markings on data item"""
        markings = data_item.metadata.get("classification_markings", {})
        required_markings = self.policies["classification_policies"]["classification_marking"]["required_markings"]
        
        return all(marking in markings for marking in required_markings)
    
    def _validate_derivative_classification(self, data_item: DataItem) -> bool:
        """Validate derivative classification source tracking"""
        return "derivative_source" in data_item.metadata
    
    def _contains_pii(self, data_item: DataItem) -> bool:
        """Check if data item contains PII"""
        content = str(data_item.content)
        
        # SSN pattern
        if re.search(r'\b\d{3}-\d{2}-\d{4}\b', content):
            return True
        
        # Credit card pattern
        if re.search(r'\b\d{4}\s?\d{4}\s?\d{4}\s?\d{4}\b', content):
            return True
        
        # Email pattern
        if re.search(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', content):
            return True
        
        return False
    
    def _is_export_controlled(self, data_item: DataItem) -> bool:
        """Check if data item is export controlled"""
        return data_item.metadata.get("export_controlled", False)
    
    def _contains_sources_methods(self, data_item: DataItem) -> bool:
        """Check if data item contains sources and methods"""
        content = str(data_item.content).lower()
        sources_methods_keywords = [
            "source", "method", "humint", "sigint", "imint", "masint", "osint",
            "collection", "intelligence", "asset", "operative", "surveillance"
        ]
        
        return any(keyword in content for keyword in sources_methods_keywords)
    
    def _is_business_hours(self, timestamp: datetime) -> bool:
        """Check if timestamp is within business hours"""
        # Assuming business hours are 8 AM to 6 PM, Monday to Friday
        weekday = timestamp.weekday()  # 0 = Monday, 6 = Sunday
        hour = timestamp.hour
        
        return weekday < 5 and 8 <= hour <= 18
    
    def _calculate_final_result(self, report: ValidationReport):
        """Calculate final validation result based on score and violations"""
        if report.violations:
            if report.score <= 0:
                report.result = ValidationResult.BLOCKED
            elif report.score <= 50:
                report.result = ValidationResult.FAILED
            elif report.score <= 70:
                report.result = ValidationResult.REQUIRES_REVIEW
            else:
                report.result = ValidationResult.WARNING
        else:
            if report.warnings:
                report.result = ValidationResult.WARNING
            else:
                report.result = ValidationResult.PASSED


class SecurityValidator:
    """Validates security aspects of transfers"""
    
    def __init__(self):
        self.threat_intel = self._load_threat_intelligence()
        self.security_rules = self._load_security_rules()
        
    def _load_threat_intelligence(self) -> Dict[str, Any]:
        """Load threat intelligence data"""
        return {
            "malicious_hashes": {
                "d41d8cd98f00b204e9800998ecf8427e": "Empty file hash",
                "e3b0c44298fc1c149afbf4c8996fb924": "SHA256 of empty string",
                "5d41402abc4b2a76b9719d911017c592": "Known malware hash"
            },
            "suspicious_domains": [
                "suspicious-domain.com",
                "malware-host.org",
                "phishing-site.net"
            ],
            "threat_signatures": {
                "powershell_obfuscation": r"powershell.*-enc.*[A-Za-z0-9+/]{20,}",
                "base64_executable": r"TVqQAAMAAAAEAAAA",
                "suspicious_registry": r"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
            },
            "behavioral_indicators": [
                "multiple_failed_logins",
                "unusual_access_patterns",
                "privilege_escalation_attempts",
                "data_exfiltration_patterns"
            ]
        }
    
    def _load_security_rules(self) -> Dict[str, Any]:
        """Load security validation rules"""
        return {
            "encryption_requirements": {
                "data_at_rest": True,
                "data_in_transit": True,
                "key_management": True,
                "algorithm_approval": ["AES-256", "RSA-2048", "ECC-P256"]
            },
            "integrity_checks": {
                "hash_verification": True,
                "digital_signatures": True,
                "checksum_validation": True
            },
            "access_controls": {
                "multi_factor_auth": True,
                "privilege_validation": True,
                "session_management": True
            },
            "network_security": {
                "protocol_validation": True,
                "certificate_validation": True,
                "traffic_analysis": True
            }
        }
    
    async def validate_security(self, request: TransferRequest) -> ValidationReport:
        """Validate security aspects of transfer"""
        report = ValidationReport(
            item_id=request.id,
            timestamp=datetime.now(),
            result=ValidationResult.PASSED,
            score=100.0,
            violations=[],
            warnings=[],
            metadata={},
            recommendations=[]
        )
        
        try:
            # Validate threat intelligence
            await self._validate_threat_intelligence(request, report)
            
            # Validate encryption requirements
            await self._validate_encryption(request, report)
            
            # Validate integrity checks
            await self._validate_integrity(request, report)
            
            # Validate access controls
            await self._validate_access_controls(request, report)
            
            # Validate network security
            await self._validate_network_security(request, report)
            
            # Calculate final result
            self._calculate_final_result(report)
            
        except Exception as e:
            report.result = ValidationResult.FAILED
            report.violations.append(f"Security validation error: {str(e)}")
            logging.error(f"Security validation error for {request.id}: {e}")
        
        return report
    
    async def _validate_threat_intelligence(self, request: TransferRequest, report: ValidationReport):
        """Validate against threat intelligence"""
        for data_item in request.data_items:
            content = str(data_item.content)
            content_hash = hashlib.md5(content.encode()).hexdigest()
            
            # Check malicious hashes
            if content_hash in self.threat_intel["malicious_hashes"]:
                report.violations.append(f"Malicious hash detected: {content_hash}")
                report.score -= 100
            
            # Check suspicious domains
            for domain in self.threat_intel["suspicious_domains"]:
                if domain in content:
                    report.violations.append(f"Suspicious domain detected: {domain}")
                    report.score -= 50
            
            # Check threat signatures
            for signature_name, pattern in self.threat_intel["threat_signatures"].items():
                if re.search(pattern, content, re.IGNORECASE):
                    report.violations.append(f"Threat signature detected: {signature_name}")
                    report.score -= 75
    
    async def _validate_encryption(self, request: TransferRequest, report: ValidationReport):
        """Validate encryption requirements"""
        encryption_rules = self.security_rules["encryption_requirements"]
        
        # Check data at rest encryption
        if encryption_rules["data_at_rest"]:
            for data_item in request.data_items:
                if not data_item.metadata.get("encrypted_at_rest", False):
                    report.violations.append(f"Data at rest not encrypted for item {data_item.id}")
                    report.score -= 30
        
        # Check data in transit encryption
        if encryption_rules["data_in_transit"]:
            if not request.metadata.get("encrypted_in_transit", False):
                report.violations.append("Data in transit encryption not enabled")
                report.score -= 40
        
        # Check approved algorithms
        encryption_algorithm = request.metadata.get("encryption_algorithm")
        if encryption_algorithm and encryption_algorithm not in encryption_rules["algorithm_approval"]:
            report.violations.append(f"Unapproved encryption algorithm: {encryption_algorithm}")
            report.score -= 25
    
    async def _validate_integrity(self, request: TransferRequest, report: ValidationReport):
        """Validate integrity checks"""
        integrity_rules = self.security_rules["integrity_checks"]
        
        # Check hash verification
        if integrity_rules["hash_verification"]:
            for data_item in request.data_items:
                if not data_item.metadata.get("content_hash"):
                    report.warnings.append(f"Missing content hash for item {data_item.id}")
                    report.score -= 5
        
        # Check digital signatures
        if integrity_rules["digital_signatures"]:
            if not request.metadata.get("digital_signature"):
                report.violations.append("Missing digital signature")
                report.score -= 35
    
    async def _validate_access_controls(self, request: TransferRequest, report: ValidationReport):
        """Validate access controls"""
        access_rules = self.security_rules["access_controls"]
        
        # Check multi-factor authentication
        if access_rules["multi_factor_auth"]:
            if not request.metadata.get("mfa_verified", False):
                report.violations.append("Multi-factor authentication not verified")
                report.score -= 40
        
        # Check privilege validation
        if access_rules["privilege_validation"]:
            if not request.metadata.get("privileges_validated", False):
                report.violations.append("User privileges not validated")
                report.score -= 30
    
    async def _validate_network_security(self, request: TransferRequest, report: ValidationReport):
        """Validate network security"""
        network_rules = self.security_rules["network_security"]
        
        # Check protocol validation
        if network_rules["protocol_validation"]:
            protocol = request.metadata.get("transfer_protocol")
            if protocol not in ["HTTPS", "SFTP", "FTPS"]:
                report.violations.append(f"Insecure transfer protocol: {protocol}")
                report.score -= 45
        
        # Check certificate validation
        if network_rules["certificate_validation"]:
            if not request.metadata.get("certificate_valid", False):
                report.violations.append("Invalid or expired certificate")
                report.score -= 35
    
    def _calculate_final_result(self, report: ValidationReport):
        """Calculate final validation result"""
        if report.violations:
            if report.score <= 0:
                report.result = ValidationResult.BLOCKED
            elif report.score <= 30:
                report.result = ValidationResult.FAILED
            elif report.score <= 60:
                report.result = ValidationResult.REQUIRES_REVIEW
            else:
                report.result = ValidationResult.WARNING
        else:
            if report.warnings:
                report.result = ValidationResult.WARNING
            else:
                report.result = ValidationResult.PASSED


class TransferValidationEngine:
    """Main transfer validation engine"""
    
    def __init__(self):
        self.policy_validator = PolicyValidator()
        self.security_validator = SecurityValidator()
        self.validation_cache = {}
        self.validation_history = []
        
    async def validate_transfer(self, request: TransferRequest) -> Dict[str, ValidationReport]:
        """Perform comprehensive transfer validation"""
        validation_results = {}
        
        try:
            # Policy validation
            policy_report = await self.policy_validator.validate_transfer_policy(request)
            validation_results["policy"] = policy_report
            
            # Security validation
            security_report = await self.security_validator.validate_security(request)
            validation_results["security"] = security_report
            
            # Store validation results
            self._store_validation_results(request.id, validation_results)
            
            logging.info(f"Transfer validation completed for {request.id}")
            
        except Exception as e:
            logging.error(f"Transfer validation error for {request.id}: {e}")
            raise
        
        return validation_results
    
    def _store_validation_results(self, request_id: str, results: Dict[str, ValidationReport]):
        """Store validation results"""
        self.validation_cache[request_id] = results
        self.validation_history.append({
            "request_id": request_id,
            "timestamp": datetime.now(),
            "results": results
        })
    
    def get_validation_results(self, request_id: str) -> Optional[Dict[str, ValidationReport]]:
        """Get validation results for a request"""
        return self.validation_cache.get(request_id)
    
    def get_overall_validation_result(self, request_id: str) -> ValidationResult:
        """Get overall validation result"""
        results = self.validation_cache.get(request_id)
        if not results:
            return ValidationResult.FAILED
        
        # Determine overall result based on individual validations
        all_results = [report.result for report in results.values()]
        
        if ValidationResult.BLOCKED in all_results:
            return ValidationResult.BLOCKED
        elif ValidationResult.FAILED in all_results:
            return ValidationResult.FAILED
        elif ValidationResult.REQUIRES_REVIEW in all_results:
            return ValidationResult.REQUIRES_REVIEW
        elif ValidationResult.WARNING in all_results:
            return ValidationResult.WARNING
        else:
            return ValidationResult.PASSED
    
    def clear_validation_cache(self, older_than_hours: int = 24):
        """Clear old validation results from cache"""
        cutoff_time = datetime.now() - timedelta(hours=older_than_hours)
        
        # Remove from cache
        expired_keys = [
            key for key, value in self.validation_cache.items()
            if any(report.timestamp < cutoff_time for report in value.values())
        ]
        
        for key in expired_keys:
            del self.validation_cache[key]
        
        # Remove from history
        self.validation_history = [
            entry for entry in self.validation_history
            if entry["timestamp"] > cutoff_time
        ]
        
        logging.info(f"Cleared {len(expired_keys)} expired validation results")
    
    def get_validation_statistics(self) -> Dict[str, Any]:
        """Get validation statistics"""
        if not self.validation_history:
            return {"total_validations": 0}
        
        total_validations = len(self.validation_history)
        result_counts = {}
        
        for entry in self.validation_history:
            for validation_type, report in entry["results"].items():
                result_key = f"{validation_type}_{report.result.value}"
                result_counts[result_key] = result_counts.get(result_key, 0) + 1
        
        return {
            "total_validations": total_validations,
            "result_counts": result_counts,
            "cache_size": len(self.validation_cache)
        }