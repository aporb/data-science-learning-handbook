"""
Cross-Domain Guard Simulation
============================

Simulates cross-domain security controls for development and testing environments.
Implements content inspection, transfer validation, and multi-party authorization.

Classification: UNCLASSIFIED//FOR OFFICIAL USE ONLY
Created: 2025-07-17
Version: 1.0
"""

import json
import logging
import hashlib
import uuid
from enum import Enum
from dataclasses import dataclass, field
from typing import List, Dict, Set, Optional, Any, Tuple
from datetime import datetime, timedelta
import re
import threading
from pathlib import Path

from ..models.bell_lapadula import SecurityLabel, ClassificationLevel, NetworkDomain
from .classification_engine import DataClassificationEngine

# Configure logging
logger = logging.getLogger(__name__)


class TransferStatus(Enum):
    """Status of cross-domain transfer."""
    PENDING = "PENDING"
    INSPECTING = "INSPECTING"
    SANITIZING = "SANITIZING"
    AWAITING_APPROVAL = "AWAITING_APPROVAL"
    APPROVED = "APPROVED"
    DENIED = "DENIED"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class InspectionResult(Enum):
    """Result of content inspection."""
    PASS = "PASS"
    FAIL = "FAIL"
    CONDITIONAL = "CONDITIONAL"
    MANUAL_REVIEW = "MANUAL_REVIEW"


class ApprovalType(Enum):
    """Types of approval required."""
    TECHNICAL_REVIEW = "TECHNICAL_REVIEW"
    SECURITY_OFFICER = "SECURITY_OFFICER"
    DATA_OWNER = "DATA_OWNER"
    FOREIGN_DISCLOSURE = "FOREIGN_DISCLOSURE"
    RELEASE_AUTHORITY = "RELEASE_AUTHORITY"


@dataclass
class DomainConfiguration:
    """Configuration for a security domain."""
    domain_id: str
    name: str
    network: NetworkDomain
    max_classification: ClassificationLevel
    allowed_compartments: Set[str] = field(default_factory=set)
    security_policies: Dict[str, Any] = field(default_factory=dict)
    active: bool = True


@dataclass
class TransferRequest:
    """Represents a cross-domain transfer request."""
    transfer_id: str
    source_domain: str
    target_domain: str
    requestor_id: str
    data_objects: List[Dict[str, Any]]
    justification: str
    urgency: str = "ROUTINE"
    created_at: datetime = field(default_factory=datetime.now)
    status: TransferStatus = TransferStatus.PENDING
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class InspectionReport:
    """Report from content inspection."""
    inspection_id: str
    transfer_id: str
    inspector: str
    result: InspectionResult
    findings: List[Dict[str, Any]] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    sanitization_required: bool = False
    manual_review_required: bool = False
    timestamp: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ApprovalRequest:
    """Approval request for transfer."""
    approval_id: str
    transfer_id: str
    approval_type: ApprovalType
    approver_id: Optional[str] = None
    status: str = "PENDING"
    comments: str = ""
    timestamp: datetime = field(default_factory=datetime.now)
    expires_at: Optional[datetime] = None


@dataclass
class SanitizationTask:
    """Task for data sanitization."""
    task_id: str
    transfer_id: str
    data_object_id: str
    sanitization_type: str
    original_classification: SecurityLabel
    target_classification: SecurityLabel
    status: str = "PENDING"
    assigned_to: Optional[str] = None
    completed_at: Optional[datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


class ContentInspector:
    """Performs automated content inspection for cross-domain transfers."""
    
    def __init__(self, classification_engine: DataClassificationEngine):
        self.classification_engine = classification_engine
        self.inspection_rules = self._load_inspection_rules()
        self.prohibited_patterns = self._load_prohibited_patterns()
    
    def _load_inspection_rules(self) -> List[Dict[str, Any]]:
        """Load content inspection rules."""
        return [
            {
                'rule_id': 'classification_mismatch',
                'name': 'Classification Level Mismatch',
                'description': 'Verify content classification matches transfer requirements',
                'severity': 'HIGH',
                'action': 'BLOCK'
            },
            {
                'rule_id': 'pii_detection',
                'name': 'Personal Information Detection',
                'description': 'Detect personally identifiable information',
                'severity': 'MEDIUM',
                'action': 'SANITIZE'
            },
            {
                'rule_id': 'foreign_disclosure',
                'name': 'Foreign Disclosure Controls',
                'description': 'Check foreign disclosure restrictions',
                'severity': 'HIGH',
                'action': 'REVIEW'
            },
            {
                'rule_id': 'source_code_detection',
                'name': 'Source Code Detection',
                'description': 'Detect embedded source code or algorithms',
                'severity': 'MEDIUM',
                'action': 'REVIEW'
            }
        ]
    
    def _load_prohibited_patterns(self) -> List[Dict[str, Any]]:
        """Load patterns that are prohibited in cross-domain transfers."""
        return [
            {
                'pattern': r'\b(?:password|passwd|pwd)\s*[:=]\s*\S+',
                'name': 'Password Pattern',
                'severity': 'HIGH',
                'action': 'BLOCK'
            },
            {
                'pattern': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
                'name': 'Email Address',
                'severity': 'MEDIUM',
                'action': 'SANITIZE'
            },
            {
                'pattern': r'\b\d{3}-\d{2}-\d{4}\b',
                'name': 'Social Security Number',
                'severity': 'HIGH',
                'action': 'SANITIZE'
            },
            {
                'pattern': r'\b(?:api[_-]?key|access[_-]?token|secret[_-]?key)\s*[:=]\s*\S+',
                'name': 'API Key/Token',
                'severity': 'HIGH',
                'action': 'BLOCK'
            }
        ]
    
    def inspect_content(self, content: str, transfer_request: TransferRequest) -> InspectionReport:
        """
        Perform comprehensive content inspection.
        
        Args:
            content: Content to inspect
            transfer_request: Transfer request context
            
        Returns:
            InspectionReport with findings and recommendations
        """
        inspection_id = str(uuid.uuid4())
        findings = []
        recommendations = []
        result = InspectionResult.PASS
        sanitization_required = False
        manual_review_required = False
        
        # Classify content
        classification_result = self.classification_engine.classify_content(content)
        
        # Check classification compatibility
        target_domain = self._get_domain_config(transfer_request.target_domain)
        if target_domain:
            if classification_result.recommended_classification.classification > target_domain.max_classification:
                findings.append({
                    'type': 'classification_violation',
                    'severity': 'HIGH',
                    'message': f"Content classification {classification_result.recommended_classification.classification.to_string()} exceeds target domain maximum {target_domain.max_classification.to_string()}",
                    'action': 'BLOCK'
                })
                result = InspectionResult.FAIL
        
        # Check for prohibited patterns
        for pattern_config in self.prohibited_patterns:
            matches = list(re.finditer(pattern_config['pattern'], content, re.IGNORECASE))
            if matches:
                finding = {
                    'type': 'prohibited_pattern',
                    'pattern_name': pattern_config['name'],
                    'severity': pattern_config['severity'],
                    'matches': len(matches),
                    'action': pattern_config['action']
                }
                findings.append(finding)
                
                if pattern_config['action'] == 'BLOCK':
                    result = InspectionResult.FAIL
                elif pattern_config['action'] == 'SANITIZE':
                    sanitization_required = True
                    if result == InspectionResult.PASS:
                        result = InspectionResult.CONDITIONAL
                elif pattern_config['action'] == 'REVIEW':
                    manual_review_required = True
                    if result == InspectionResult.PASS:
                        result = InspectionResult.MANUAL_REVIEW
        
        # Check compartment compatibility
        target_compartments = target_domain.allowed_compartments if target_domain else set()
        content_compartments = classification_result.recommended_classification.compartments
        
        if not content_compartments.issubset(target_compartments):
            unauthorized_compartments = content_compartments - target_compartments
            findings.append({
                'type': 'compartment_violation',
                'severity': 'HIGH',
                'message': f"Content contains unauthorized compartments: {', '.join(unauthorized_compartments)}",
                'compartments': list(unauthorized_compartments),
                'action': 'BLOCK'
            })
            result = InspectionResult.FAIL
        
        # Generate recommendations
        if sanitization_required:
            recommendations.append("Content requires sanitization before transfer")
        if manual_review_required:
            recommendations.append("Manual security review required")
        if result == InspectionResult.FAIL:
            recommendations.append("Transfer denied due to security violations")
        
        return InspectionReport(
            inspection_id=inspection_id,
            transfer_id=transfer_request.transfer_id,
            inspector="automated_inspector",
            result=result,
            findings=findings,
            recommendations=recommendations,
            sanitization_required=sanitization_required,
            manual_review_required=manual_review_required,
            metadata={
                'content_length': len(content),
                'classification_confidence': classification_result.confidence.value,
                'rules_evaluated': len(self.inspection_rules),
                'patterns_checked': len(self.prohibited_patterns)
            }
        )
    
    def _get_domain_config(self, domain_id: str) -> Optional[DomainConfiguration]:
        """Get domain configuration (placeholder)."""
        # In a real implementation, this would query a database
        domain_configs = {
            'NIPR': DomainConfiguration(
                domain_id='NIPR',
                name='Non-classified Internet Protocol Router',
                network=NetworkDomain.NIPR,
                max_classification=ClassificationLevel.UNCLASSIFIED,
                allowed_compartments={'CUI', 'FOUO'}
            ),
            'SIPR': DomainConfiguration(
                domain_id='SIPR',
                name='Secret Internet Protocol Router',
                network=NetworkDomain.SIPR,
                max_classification=ClassificationLevel.SECRET,
                allowed_compartments={'SI', 'ORCON', 'NOFORN'}
            ),
            'JWICS': DomainConfiguration(
                domain_id='JWICS',
                name='Joint Worldwide Intelligence Communications System',
                network=NetworkDomain.JWICS,
                max_classification=ClassificationLevel.TOP_SECRET,
                allowed_compartments={'TK', 'HCS', 'SI', 'ORCON', 'NOFORN'}
            )
        }
        return domain_configs.get(domain_id)


class DataSanitizer:
    """Handles data sanitization for cross-domain transfers."""
    
    def __init__(self):
        self.sanitization_rules = self._load_sanitization_rules()
        self.redaction_patterns = self._load_redaction_patterns()
    
    def _load_sanitization_rules(self) -> List[Dict[str, Any]]:
        """Load data sanitization rules."""
        return [
            {
                'rule_id': 'pii_redaction',
                'name': 'PII Redaction',
                'pattern': r'\b\d{3}-\d{2}-\d{4}\b',
                'replacement': '[REDACTED-SSN]',
                'confidence': 0.95
            },
            {
                'rule_id': 'email_redaction',
                'name': 'Email Address Redaction',
                'pattern': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
                'replacement': '[REDACTED-EMAIL]',
                'confidence': 0.9
            },
            {
                'rule_id': 'phone_redaction',
                'name': 'Phone Number Redaction',
                'pattern': r'\b\d{3}-\d{3}-\d{4}\b',
                'replacement': '[REDACTED-PHONE]',
                'confidence': 0.85
            }
        ]
    
    def _load_redaction_patterns(self) -> Dict[str, str]:
        """Load patterns for content redaction."""
        return {
            'passwords': r'\b(?:password|passwd|pwd)\s*[:=]\s*\S+',
            'api_keys': r'\b(?:api[_-]?key|access[_-]?token|secret[_-]?key)\s*[:=]\s*\S+',
            'credit_cards': r'\b(?:\d[ -]*?){13,16}\b',
            'ip_addresses': r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        }
    
    def sanitize_content(self, content: str, sanitization_task: SanitizationTask) -> Dict[str, Any]:
        """
        Sanitize content based on sanitization task requirements.
        
        Args:
            content: Original content to sanitize
            sanitization_task: Sanitization task details
            
        Returns:
            Sanitization result with cleaned content and metadata
        """
        sanitized_content = content
        applied_rules = []
        redaction_count = 0
        
        # Apply sanitization rules
        for rule in self.sanitization_rules:
            if self._should_apply_rule(rule, sanitization_task):
                original_content = sanitized_content
                sanitized_content = re.sub(
                    rule['pattern'],
                    rule['replacement'],
                    sanitized_content,
                    flags=re.IGNORECASE
                )
                
                if original_content != sanitized_content:
                    applied_rules.append(rule['rule_id'])
                    redaction_count += len(re.findall(rule['pattern'], original_content, re.IGNORECASE))
        
        # Apply additional redaction patterns if needed
        for pattern_name, pattern in self.redaction_patterns.items():
            if self._should_apply_pattern(pattern_name, sanitization_task):
                original_content = sanitized_content
                sanitized_content = re.sub(
                    pattern,
                    f'[REDACTED-{pattern_name.upper()}]',
                    sanitized_content,
                    flags=re.IGNORECASE
                )
                
                if original_content != sanitized_content:
                    applied_rules.append(f'pattern_{pattern_name}')
                    redaction_count += len(re.findall(pattern, original_content, re.IGNORECASE))
        
        # Calculate sanitization effectiveness
        original_words = len(content.split())
        sanitized_words = len(sanitized_content.split())
        retention_rate = sanitized_words / original_words if original_words > 0 else 1.0
        
        return {
            'sanitized_content': sanitized_content,
            'applied_rules': applied_rules,
            'redaction_count': redaction_count,
            'retention_rate': retention_rate,
            'original_length': len(content),
            'sanitized_length': len(sanitized_content),
            'sanitization_metadata': {
                'task_id': sanitization_task.task_id,
                'original_classification': sanitization_task.original_classification.to_dict(),
                'target_classification': sanitization_task.target_classification.to_dict(),
                'timestamp': datetime.now().isoformat()
            }
        }
    
    def _should_apply_rule(self, rule: Dict[str, Any], task: SanitizationTask) -> bool:
        """Determine if sanitization rule should be applied."""
        # Apply all rules for now - in practice, this would be more sophisticated
        return True
    
    def _should_apply_pattern(self, pattern_name: str, task: SanitizationTask) -> bool:
        """Determine if redaction pattern should be applied."""
        # Always apply security-sensitive patterns
        security_patterns = {'passwords', 'api_keys'}
        if pattern_name in security_patterns:
            return True
        
        # Apply PII patterns when going to lower classification
        pii_patterns = {'credit_cards', 'ip_addresses'}
        if pattern_name in pii_patterns:
            return task.target_classification.classification < task.original_classification.classification
        
        return False


class ApprovalWorkflow:
    """Manages approval workflow for cross-domain transfers."""
    
    def __init__(self):
        self.approval_matrix = self._load_approval_matrix()
        self.pending_approvals: Dict[str, List[ApprovalRequest]] = {}
    
    def _load_approval_matrix(self) -> Dict[str, List[ApprovalType]]:
        """Load approval requirements matrix."""
        return {
            'NIPR_to_SIPR': [ApprovalType.SECURITY_OFFICER],
            'SIPR_to_NIPR': [
                ApprovalType.TECHNICAL_REVIEW,
                ApprovalType.SECURITY_OFFICER,
                ApprovalType.DATA_OWNER
            ],
            'SIPR_to_JWICS': [ApprovalType.SECURITY_OFFICER],
            'JWICS_to_SIPR': [
                ApprovalType.TECHNICAL_REVIEW,
                ApprovalType.SECURITY_OFFICER,
                ApprovalType.DATA_OWNER,
                ApprovalType.RELEASE_AUTHORITY
            ],
            'JWICS_to_NIPR': [
                ApprovalType.TECHNICAL_REVIEW,
                ApprovalType.SECURITY_OFFICER,
                ApprovalType.DATA_OWNER,
                ApprovalType.FOREIGN_DISCLOSURE,
                ApprovalType.RELEASE_AUTHORITY
            ]
        }
    
    def get_required_approvals(self, transfer_request: TransferRequest) -> List[ApprovalType]:
        """Get list of required approvals for transfer."""
        transfer_type = f"{transfer_request.source_domain}_to_{transfer_request.target_domain}"
        return self.approval_matrix.get(transfer_type, [ApprovalType.SECURITY_OFFICER])
    
    def initiate_approval_workflow(self, transfer_request: TransferRequest) -> List[ApprovalRequest]:
        """Initiate approval workflow for transfer."""
        required_approvals = self.get_required_approvals(transfer_request)
        approval_requests = []
        
        for approval_type in required_approvals:
            approval_request = ApprovalRequest(
                approval_id=str(uuid.uuid4()),
                transfer_id=transfer_request.transfer_id,
                approval_type=approval_type,
                expires_at=datetime.now() + timedelta(days=7)  # 7 day expiration
            )
            approval_requests.append(approval_request)
        
        self.pending_approvals[transfer_request.transfer_id] = approval_requests
        return approval_requests
    
    def submit_approval(self, approval_id: str, approver_id: str, 
                       decision: str, comments: str = "") -> bool:
        """Submit approval decision."""
        for transfer_id, approvals in self.pending_approvals.items():
            for approval in approvals:
                if approval.approval_id == approval_id:
                    approval.approver_id = approver_id
                    approval.status = decision
                    approval.comments = comments
                    approval.timestamp = datetime.now()
                    return True
        
        return False
    
    def check_approval_status(self, transfer_id: str) -> Dict[str, Any]:
        """Check overall approval status for transfer."""
        approvals = self.pending_approvals.get(transfer_id, [])
        
        total_approvals = len(approvals)
        approved_count = sum(1 for a in approvals if a.status == "APPROVED")
        denied_count = sum(1 for a in approvals if a.status == "DENIED")
        pending_count = sum(1 for a in approvals if a.status == "PENDING")
        
        if denied_count > 0:
            overall_status = "DENIED"
        elif approved_count == total_approvals:
            overall_status = "APPROVED"
        else:
            overall_status = "PENDING"
        
        return {
            'transfer_id': transfer_id,
            'overall_status': overall_status,
            'total_approvals': total_approvals,
            'approved': approved_count,
            'denied': denied_count,
            'pending': pending_count,
            'approvals': [
                {
                    'approval_id': a.approval_id,
                    'type': a.approval_type.value,
                    'status': a.status,
                    'approver': a.approver_id,
                    'comments': a.comments,
                    'timestamp': a.timestamp.isoformat() if a.timestamp else None
                }
                for a in approvals
            ]
        }


class CrossDomainGuard:
    """
    Main Cross-Domain Guard system that coordinates all security controls.
    """
    
    def __init__(self, classification_engine: DataClassificationEngine):
        """
        Initialize Cross-Domain Guard.
        
        Args:
            classification_engine: Classification engine for content analysis
        """
        self.classification_engine = classification_engine
        self.content_inspector = ContentInspector(classification_engine)
        self.data_sanitizer = DataSanitizer()
        self.approval_workflow = ApprovalWorkflow()
        
        # Transfer tracking
        self.active_transfers: Dict[str, TransferRequest] = {}
        self.inspection_reports: Dict[str, InspectionReport] = {}
        self.sanitization_tasks: Dict[str, SanitizationTask] = {}
        
        # Audit logging
        self.audit_log: List[Dict[str, Any]] = []
        
        # Configuration
        self.config = {
            'max_transfer_size': 100 * 1024 * 1024,  # 100MB
            'auto_approval_threshold': 0.95,
            'inspection_timeout': 300,  # 5 minutes
            'transfer_expiration': 24 * 60 * 60,  # 24 hours
        }
    
    def initiate_transfer(self, source_domain: str, target_domain: str,
                         data_objects: List[Dict[str, Any]], requestor_id: str,
                         justification: str, urgency: str = "ROUTINE") -> TransferRequest:
        """
        Initiate a cross-domain transfer request.
        
        Args:
            source_domain: Source security domain
            target_domain: Target security domain
            data_objects: List of data objects to transfer
            requestor_id: ID of requesting user
            justification: Business justification for transfer
            urgency: Transfer urgency level
            
        Returns:
            TransferRequest object
        """
        transfer_id = str(uuid.uuid4())
        
        transfer_request = TransferRequest(
            transfer_id=transfer_id,
            source_domain=source_domain,
            target_domain=target_domain,
            requestor_id=requestor_id,
            data_objects=data_objects,
            justification=justification,
            urgency=urgency,
            metadata={
                'total_objects': len(data_objects),
                'estimated_size': sum(obj.get('size', 0) for obj in data_objects)
            }
        )
        
        self.active_transfers[transfer_id] = transfer_request
        
        # Log transfer initiation
        self._audit_log("TRANSFER_INITIATED", {
            'transfer_id': transfer_id,
            'source_domain': source_domain,
            'target_domain': target_domain,
            'requestor_id': requestor_id,
            'urgency': urgency
        })
        
        logger.info(f"Cross-domain transfer {transfer_id} initiated: {source_domain} -> {target_domain}")
        
        return transfer_request
    
    def inspect_transfer(self, transfer_id: str) -> InspectionReport:
        """
        Perform content inspection on transfer request.
        
        Args:
            transfer_id: Transfer request ID
            
        Returns:
            InspectionReport with findings
        """
        transfer_request = self.active_transfers.get(transfer_id)
        if not transfer_request:
            raise ValueError(f"Transfer {transfer_id} not found")
        
        # Update status
        transfer_request.status = TransferStatus.INSPECTING
        
        # Inspect each data object
        all_findings = []
        overall_result = InspectionResult.PASS
        
        for data_obj in transfer_request.data_objects:
            content = data_obj.get('content', '')
            if content:
                inspection = self.content_inspector.inspect_content(content, transfer_request)
                all_findings.extend(inspection.findings)
                
                # Determine overall result
                if inspection.result == InspectionResult.FAIL:
                    overall_result = InspectionResult.FAIL
                elif (inspection.result == InspectionResult.CONDITIONAL and 
                      overall_result == InspectionResult.PASS):
                    overall_result = InspectionResult.CONDITIONAL
                elif (inspection.result == InspectionResult.MANUAL_REVIEW and 
                      overall_result in [InspectionResult.PASS, InspectionResult.CONDITIONAL]):
                    overall_result = InspectionResult.MANUAL_REVIEW
        
        # Create comprehensive inspection report
        inspection_report = InspectionReport(
            inspection_id=str(uuid.uuid4()),
            transfer_id=transfer_id,
            inspector="cross_domain_guard",
            result=overall_result,
            findings=all_findings,
            sanitization_required=(overall_result == InspectionResult.CONDITIONAL),
            manual_review_required=(overall_result == InspectionResult.MANUAL_REVIEW),
            metadata={
                'objects_inspected': len(transfer_request.data_objects),
                'total_findings': len(all_findings),
                'high_severity_findings': len([f for f in all_findings if f.get('severity') == 'HIGH'])
            }
        )
        
        self.inspection_reports[transfer_id] = inspection_report
        
        # Update transfer status based on inspection result
        if overall_result == InspectionResult.FAIL:
            transfer_request.status = TransferStatus.DENIED
        elif overall_result == InspectionResult.CONDITIONAL:
            transfer_request.status = TransferStatus.SANITIZING
        else:
            transfer_request.status = TransferStatus.AWAITING_APPROVAL
        
        # Log inspection completion
        self._audit_log("INSPECTION_COMPLETED", {
            'transfer_id': transfer_id,
            'result': overall_result.value,
            'findings_count': len(all_findings),
            'sanitization_required': inspection_report.sanitization_required
        })
        
        logger.info(f"Inspection completed for transfer {transfer_id}: {overall_result.value}")
        
        return inspection_report
    
    def sanitize_data(self, transfer_id: str) -> Dict[str, Any]:
        """
        Perform data sanitization for transfer.
        
        Args:
            transfer_id: Transfer request ID
            
        Returns:
            Sanitization results
        """
        transfer_request = self.active_transfers.get(transfer_id)
        if not transfer_request:
            raise ValueError(f"Transfer {transfer_id} not found")
        
        inspection_report = self.inspection_reports.get(transfer_id)
        if not inspection_report or not inspection_report.sanitization_required:
            raise ValueError(f"Sanitization not required for transfer {transfer_id}")
        
        sanitization_results = []
        
        for i, data_obj in enumerate(transfer_request.data_objects):
            content = data_obj.get('content', '')
            if content:
                # Create sanitization task
                task = SanitizationTask(
                    task_id=str(uuid.uuid4()),
                    transfer_id=transfer_id,
                    data_object_id=data_obj.get('id', f'obj_{i}'),
                    sanitization_type='cross_domain_transfer',
                    original_classification=SecurityLabel(ClassificationLevel.SECRET),  # Placeholder
                    target_classification=SecurityLabel(ClassificationLevel.UNCLASSIFIED)  # Placeholder
                )
                
                # Perform sanitization
                result = self.data_sanitizer.sanitize_content(content, task)
                
                # Update data object with sanitized content
                data_obj['content'] = result['sanitized_content']
                data_obj['sanitization_metadata'] = result['sanitization_metadata']
                
                sanitization_results.append(result)
                self.sanitization_tasks[task.task_id] = task
        
        # Update transfer status
        transfer_request.status = TransferStatus.AWAITING_APPROVAL
        
        # Log sanitization completion
        self._audit_log("SANITIZATION_COMPLETED", {
            'transfer_id': transfer_id,
            'objects_sanitized': len(sanitization_results),
            'total_redactions': sum(r['redaction_count'] for r in sanitization_results)
        })
        
        logger.info(f"Sanitization completed for transfer {transfer_id}")
        
        return {
            'transfer_id': transfer_id,
            'sanitization_results': sanitization_results,
            'status': 'COMPLETED'
        }
    
    def request_approvals(self, transfer_id: str) -> List[ApprovalRequest]:
        """
        Request required approvals for transfer.
        
        Args:
            transfer_id: Transfer request ID
            
        Returns:
            List of approval requests
        """
        transfer_request = self.active_transfers.get(transfer_id)
        if not transfer_request:
            raise ValueError(f"Transfer {transfer_id} not found")
        
        approvals = self.approval_workflow.initiate_approval_workflow(transfer_request)
        
        # Log approval request
        self._audit_log("APPROVALS_REQUESTED", {
            'transfer_id': transfer_id,
            'approval_count': len(approvals),
            'approval_types': [a.approval_type.value for a in approvals]
        })
        
        logger.info(f"Approval workflow initiated for transfer {transfer_id}: {len(approvals)} approvals required")
        
        return approvals
    
    def submit_approval(self, approval_id: str, approver_id: str,
                       decision: str, comments: str = "") -> bool:
        """Submit approval decision."""
        success = self.approval_workflow.submit_approval(approval_id, approver_id, decision, comments)
        
        if success:
            self._audit_log("APPROVAL_SUBMITTED", {
                'approval_id': approval_id,
                'approver_id': approver_id,
                'decision': decision,
                'comments': comments
            })
        
        return success
    
    def finalize_transfer(self, transfer_id: str) -> Dict[str, Any]:
        """
        Finalize approved transfer.
        
        Args:
            transfer_id: Transfer request ID
            
        Returns:
            Transfer completion status
        """
        transfer_request = self.active_transfers.get(transfer_id)
        if not transfer_request:
            raise ValueError(f"Transfer {transfer_id} not found")
        
        # Check approval status
        approval_status = self.approval_workflow.check_approval_status(transfer_id)
        
        if approval_status['overall_status'] != 'APPROVED':
            return {
                'transfer_id': transfer_id,
                'status': 'FAILED',
                'reason': f"Transfer not approved: {approval_status['overall_status']}"
            }
        
        # Execute transfer (in real implementation, this would move/copy data)
        transfer_request.status = TransferStatus.COMPLETED
        
        # Log transfer completion
        self._audit_log("TRANSFER_COMPLETED", {
            'transfer_id': transfer_id,
            'source_domain': transfer_request.source_domain,
            'target_domain': transfer_request.target_domain,
            'completion_time': datetime.now().isoformat()
        })
        
        logger.info(f"Cross-domain transfer {transfer_id} completed successfully")
        
        return {
            'transfer_id': transfer_id,
            'status': 'COMPLETED',
            'completion_time': datetime.now().isoformat(),
            'approval_summary': approval_status
        }
    
    def get_transfer_status(self, transfer_id: str) -> Dict[str, Any]:
        """Get comprehensive transfer status."""
        transfer_request = self.active_transfers.get(transfer_id)
        if not transfer_request:
            return {'error': f'Transfer {transfer_id} not found'}
        
        status_info = {
            'transfer_id': transfer_id,
            'status': transfer_request.status.value,
            'source_domain': transfer_request.source_domain,
            'target_domain': transfer_request.target_domain,
            'requestor_id': transfer_request.requestor_id,
            'created_at': transfer_request.created_at.isoformat(),
            'data_objects_count': len(transfer_request.data_objects)
        }
        
        # Add inspection report if available
        if transfer_id in self.inspection_reports:
            inspection = self.inspection_reports[transfer_id]
            status_info['inspection'] = {
                'result': inspection.result.value,
                'findings_count': len(inspection.findings),
                'sanitization_required': inspection.sanitization_required,
                'manual_review_required': inspection.manual_review_required
            }
        
        # Add approval status if applicable
        if transfer_request.status in [TransferStatus.AWAITING_APPROVAL, TransferStatus.APPROVED, TransferStatus.DENIED]:
            status_info['approvals'] = self.approval_workflow.check_approval_status(transfer_id)
        
        return status_info
    
    def _audit_log(self, event_type: str, details: Dict[str, Any]):
        """Log audit event."""
        audit_entry = {
            'timestamp': datetime.now().isoformat(),
            'event_type': event_type,
            'details': details
        }
        self.audit_log.append(audit_entry)
        
        # In production, this would write to a secure audit database
        logger.info(f"AUDIT: {event_type} - {json.dumps(details)}")
    
    def get_audit_log(self, transfer_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get audit log entries, optionally filtered by transfer ID."""
        if transfer_id:
            return [
                entry for entry in self.audit_log
                if entry['details'].get('transfer_id') == transfer_id
            ]
        return self.audit_log.copy()


# Utility functions

def create_cross_domain_guard(classification_engine: DataClassificationEngine) -> CrossDomainGuard:
    """Create and configure a Cross-Domain Guard instance."""
    return CrossDomainGuard(classification_engine)


def simulate_transfer_workflow(guard: CrossDomainGuard, source: str, target: str,
                             content: str, requestor: str) -> str:
    """Simulate a complete transfer workflow for testing."""
    # Initiate transfer
    data_objects = [{'id': 'test_obj', 'content': content, 'size': len(content)}]
    transfer = guard.initiate_transfer(source, target, data_objects, requestor, "Test transfer")
    
    # Inspect content
    inspection = guard.inspect_transfer(transfer.transfer_id)
    
    # Sanitize if needed
    if inspection.sanitization_required:
        guard.sanitize_data(transfer.transfer_id)
    
    # Request approvals
    if inspection.result != InspectionResult.FAIL:
        approvals = guard.request_approvals(transfer.transfer_id)
        
        # Auto-approve for simulation
        for approval in approvals:
            guard.submit_approval(approval.approval_id, "auto_approver", "APPROVED", "Simulated approval")
    
    # Finalize transfer
    if inspection.result != InspectionResult.FAIL:
        result = guard.finalize_transfer(transfer.transfer_id)
        return f"Transfer {transfer.transfer_id}: {result['status']}"
    else:
        return f"Transfer {transfer.transfer_id}: DENIED due to inspection failures"


# Example usage
def example_usage():
    """Demonstrate Cross-Domain Guard usage."""
    from .classification_engine import DataClassificationEngine
    
    # Create classification engine and guard
    classification_engine = DataClassificationEngine()
    guard = CrossDomainGuard(classification_engine)
    
    # Simulate transfer with classified content
    classified_content = """
    This document contains SECRET information about national security.
    Contact: John Doe, SSN: 123-45-6789
    Password: secret123
    """
    
    result = simulate_transfer_workflow(
        guard, "SIPR", "NIPR", classified_content, "test_user"
    )
    
    print(f"Transfer result: {result}")


if __name__ == "__main__":
    example_usage()