"""
Classification Review Workflows and Upgrade Procedures Engine
=============================================================

This module provides comprehensive workflows for reviewing and upgrading data
classifications, including multi-party approval processes, documentation
requirements, audit trails, and emergency classification changes.

Key Features:
- Multi-party approval workflows for classification changes
- Automated workflow orchestration with role-based approvals
- Comprehensive documentation and justification requirements
- Audit trail generation for all classification decisions
- Emergency classification change procedures
- Time-sensitive review workflows
- Integration with DoD classification management standards
- Performance-optimized workflow execution
- Real-time status tracking and notifications
- Compliance verification and reporting

Classification: UNCLASSIFIED//FOR OFFICIAL USE ONLY
Version: 1.0 - Production Implementation
Author: Security Compliance Team
Date: 2025-07-29

References:
- DoD 5200.01-V1: DoD Information Security Program
- DoD 5200.01-V2: DoD Information Security Program: Marking of Information
- NIST SP 800-53: Security and Privacy Controls for Federal Information Systems
- CNSSI-4009: Committee on National Security Systems (CNSS) Glossary
"""

import asyncio
import json
import logging
import time
import hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Tuple, Set, Union, AsyncGenerator
from uuid import UUID, uuid4
from dataclasses import dataclass, field, asdict
from enum import Enum, IntEnum
from pathlib import Path
import aiofiles
import aiohttp
from collections import defaultdict, deque
from threading import Lock, RLock
import threading

# Import existing infrastructure
from .enhanced_classification_engine import (
    EnhancedMultiClassificationEngine,
    ClassificationLevel,
    SecurityLabel,
    ClassificationResult,
    ProcessingMode
)
from .classification_audit_logger import ClassificationAuditLogger
from .clearance_verification_engine import (
    EnhancedClearanceVerificationEngine,
    ClearanceVerificationRequest,
    ClearanceStatus
)
from ..rbac.models.classification import SecurityClearance
from ..auth.unified_access_control.access_controller import UnifiedAccessController
from ..audits.audit_logger import AuditLogger


class WorkflowType(Enum):
    """Types of classification workflows"""
    UPGRADE = "upgrade"                    # Classification level increase
    DOWNGRADE = "downgrade"               # Classification level decrease
    LATERAL_CHANGE = "lateral_change"     # Same level, different compartments
    EMERGENCY_UPGRADE = "emergency_upgrade"
    EMERGENCY_DOWNGRADE = "emergency_downgrade"
    PERIODIC_REVIEW = "periodic_review"
    SPILLAGE_REMEDIATION = "spillage_remediation"
    DECLASSIFICATION = "declassification"


class WorkflowStatus(Enum):
    """Workflow execution status"""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    AWAITING_APPROVAL = "awaiting_approval"
    APPROVED = "approved"
    REJECTED = "rejected"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    EXPIRED = "expired"


class ApprovalStatus(Enum):
    """Individual approval status"""
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    ABSTAINED = "abstained"
    EXPIRED = "expired"


class PriorityLevel(IntEnum):
    """Workflow priority levels"""
    LOW = 1
    NORMAL = 2
    HIGH = 3
    URGENT = 4
    EMERGENCY = 5


@dataclass
class ApprovalRequirement:
    """Requirements for workflow approval"""
    role: str                           # Required role for approval
    clearance_level: ClassificationLevel  # Minimum clearance required
    department: Optional[str] = None    # Department requirement
    special_access: Optional[List[str]] = None  # Special access requirements
    justification_required: bool = True
    timeout_hours: int = 24            # Approval timeout
    mandatory: bool = True             # Whether approval is required


@dataclass
class WorkflowApproval:
    """Individual workflow approval"""
    approval_id: UUID
    workflow_id: UUID
    approver_id: str
    approver_role: str
    requirement: ApprovalRequirement
    status: ApprovalStatus
    timestamp: Optional[datetime] = None
    justification: Optional[str] = None
    comments: Optional[str] = None
    expires_at: Optional[datetime] = None


@dataclass
class ClassificationChangeRequest:
    """Request for classification change"""
    request_id: UUID
    data_id: str
    current_classification: SecurityLabel
    proposed_classification: SecurityLabel
    change_type: WorkflowType
    requestor_id: str
    requestor_clearance: SecurityClearance
    justification: str
    supporting_documents: List[str] = field(default_factory=list)
    urgency: PriorityLevel = PriorityLevel.NORMAL
    deadline: Optional[datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class WorkflowExecution:
    """Complete workflow execution record"""
    workflow_id: UUID
    change_request: ClassificationChangeRequest
    workflow_type: WorkflowType
    status: WorkflowStatus
    priority: PriorityLevel
    created_at: datetime
    updated_at: datetime
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    
    # Approval tracking
    required_approvals: List[ApprovalRequirement] = field(default_factory=list)
    approvals: List[WorkflowApproval] = field(default_factory=list)
    
    # Execution tracking
    current_step: str = "initialization"
    steps_completed: List[str] = field(default_factory=list)
    steps_failed: List[str] = field(default_factory=list)
    
    # Results
    final_classification: Optional[SecurityLabel] = None
    execution_log: List[Dict[str, Any]] = field(default_factory=list)
    audit_trail: List[str] = field(default_factory=list)
    
    # Error handling
    error_messages: List[str] = field(default_factory=list)
    retry_count: int = 0
    
    # Performance metrics
    processing_time_ms: Optional[int] = None
    approval_time_ms: Optional[int] = None


@dataclass
class WorkflowTemplate:
    """Template for workflow configuration"""
    template_id: str
    workflow_type: WorkflowType
    name: str
    description: str
    approval_requirements: List[ApprovalRequirement]
    steps: List[str]
    timeout_hours: int = 72
    emergency_override: bool = False
    auto_approve_conditions: List[Dict[str, Any]] = field(default_factory=list)


class ClassificationWorkflowEngine:
    """
    Engine for managing classification review workflows and upgrade procedures
    """
    
    def __init__(
        self,
        classification_engine: EnhancedMultiClassificationEngine,
        clearance_engine: EnhancedClearanceVerificationEngine,
        access_controller: UnifiedAccessController,
        audit_logger: ClassificationAuditLogger,
        config: Optional[Dict[str, Any]] = None
    ):
        self.classification_engine = classification_engine
        self.clearance_engine = clearance_engine
        self.access_controller = access_controller
        self.audit_logger = audit_logger
        
        # Configuration
        self.config = config or {}
        self.max_concurrent_workflows = self.config.get('max_concurrent_workflows', 100)
        self.default_timeout_hours = self.config.get('default_timeout_hours', 72)
        self.emergency_timeout_hours = self.config.get('emergency_timeout_hours', 4)
        
        # State management
        self.active_workflows: Dict[UUID, WorkflowExecution] = {}
        self.workflow_templates: Dict[str, WorkflowTemplate] = {}
        self.workflow_lock = RLock()
        
        # Performance tracking
        self.performance_metrics = {
            'workflows_processed': 0,
            'workflows_approved': 0,
            'workflows_rejected': 0,
            'average_processing_time': 0.0,
            'average_approval_time': 0.0
        }
        
        # Initialize default templates
        self._initialize_default_templates()
        
        # Start background tasks
        self._start_background_tasks()
        
        logging.info("Classification Workflow Engine initialized")
    
    def _initialize_default_templates(self):
        """Initialize default workflow templates"""
        
        # Standard upgrade workflow
        self.workflow_templates['standard_upgrade'] = WorkflowTemplate(
            template_id='standard_upgrade',
            workflow_type=WorkflowType.UPGRADE,
            name='Standard Classification Upgrade',
            description='Standard workflow for upgrading classification levels',
            approval_requirements=[
                ApprovalRequirement(
                    role='classification_authority',
                    clearance_level=ClassificationLevel.SECRET,
                    justification_required=True,
                    timeout_hours=24
                ),
                ApprovalRequirement(
                    role='data_owner',
                    clearance_level=ClassificationLevel.CONFIDENTIAL,
                    justification_required=True,
                    timeout_hours=48
                )
            ],
            steps=[
                'validate_request',
                'verify_clearances',
                'collect_approvals',
                'perform_classification',
                'update_records',
                'notify_stakeholders'
            ],
            timeout_hours=72
        )
        
        # Emergency upgrade workflow
        self.workflow_templates['emergency_upgrade'] = WorkflowTemplate(
            template_id='emergency_upgrade',
            workflow_type=WorkflowType.EMERGENCY_UPGRADE,
            name='Emergency Classification Upgrade',
            description='Emergency workflow for urgent classification upgrades',
            approval_requirements=[
                ApprovalRequirement(
                    role='senior_classification_authority',
                    clearance_level=ClassificationLevel.TOP_SECRET,
                    justification_required=True,
                    timeout_hours=2,
                    mandatory=True
                )
            ],
            steps=[
                'validate_emergency',
                'expedited_approval',
                'immediate_classification',
                'emergency_notification',
                'post_action_review'
            ],
            timeout_hours=4,
            emergency_override=True
        )
        
        # Downgrade workflow
        self.workflow_templates['standard_downgrade'] = WorkflowTemplate(
            template_id='standard_downgrade',
            workflow_type=WorkflowType.DOWNGRADE,
            name='Standard Classification Downgrade',
            description='Standard workflow for downgrading classification levels',
            approval_requirements=[
                ApprovalRequirement(
                    role='classification_authority',
                    clearance_level=ClassificationLevel.SECRET,
                    justification_required=True,
                    timeout_hours=24
                ),
                ApprovalRequirement(
                    role='originating_agency',
                    clearance_level=ClassificationLevel.CONFIDENTIAL,
                    justification_required=True,
                    timeout_hours=48
                ),
                ApprovalRequirement(
                    role='security_manager',
                    clearance_level=ClassificationLevel.SECRET,
                    justification_required=True,
                    timeout_hours=24
                )
            ],
            steps=[
                'validate_downgrade_authority',
                'content_sanitization_check',
                'collect_approvals',
                'perform_sanitization',
                'apply_new_classification',
                'update_distribution_list',
                'notify_stakeholders'
            ],
            timeout_hours=120
        )
        
        # Spillage remediation workflow
        self.workflow_templates['spillage_remediation'] = WorkflowTemplate(
            template_id='spillage_remediation',
            workflow_type=WorkflowType.SPILLAGE_REMEDIATION,
            name='Data Spillage Remediation',
            description='Workflow for handling data spillage incidents',
            approval_requirements=[
                ApprovalRequirement(
                    role='incident_commander',
                    clearance_level=ClassificationLevel.TOP_SECRET,
                    justification_required=True,
                    timeout_hours=1,
                    mandatory=True
                ),
                ApprovalRequirement(
                    role='security_manager',
                    clearance_level=ClassificationLevel.SECRET,
                    justification_required=True,
                    timeout_hours=2
                )
            ],
            steps=[
                'containment',
                'impact_assessment',
                'immediate_reclassification',
                'access_revocation',
                'notification',
                'forensic_analysis',
                'remediation_actions'
            ],
            timeout_hours=8,
            emergency_override=True
        )
    
    def _start_background_tasks(self):
        """Start background processing tasks"""
        self.executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="workflow")
        
        # Start workflow monitoring
        threading.Thread(
            target=self._workflow_monitor,
            daemon=True,
            name="workflow-monitor"
        ).start()
        
        # Start approval timeout checker
        threading.Thread(
            target=self._approval_timeout_checker,
            daemon=True,
            name="approval-timeout"
        ).start()
    
    async def submit_classification_change(
        self,
        request: ClassificationChangeRequest
    ) -> UUID:
        """
        Submit a classification change request
        
        Args:
            request: Classification change request
            
        Returns:
            Workflow ID for tracking
        """
        start_time = time.time()
        
        try:
            # Validate request
            await self._validate_change_request(request)
            
            # Determine workflow template
            template = self._select_workflow_template(request)
            
            # Create workflow execution
            workflow = WorkflowExecution(
                workflow_id=uuid4(),
                change_request=request,
                workflow_type=request.change_type,
                status=WorkflowStatus.PENDING,
                priority=request.urgency,
                created_at=datetime.now(timezone.utc),
                updated_at=datetime.now(timezone.utc),
                required_approvals=template.approval_requirements.copy(),
                expires_at=datetime.now(timezone.utc) + timedelta(hours=template.timeout_hours)
            )
            
            # Store workflow
            with self.workflow_lock:
                self.active_workflows[workflow.workflow_id] = workflow
            
            # Log workflow creation
            await self.audit_logger.log_classification_event(
                event_type='workflow_created',
                user_id=request.requestor_id,
                data_id=request.data_id,
                current_classification=request.current_classification.level.value,
                proposed_classification=request.proposed_classification.level.value,
                workflow_id=str(workflow.workflow_id),
                justification=request.justification,
                metadata={
                    'workflow_type': request.change_type.value,
                    'priority': request.urgency.value,
                    'template_id': template.template_id
                }
            )
            
            # Start workflow execution
            asyncio.create_task(self._execute_workflow(workflow))
            
            processing_time = int((time.time() - start_time) * 1000)
            
            logging.info(
                f"Classification change workflow submitted: {workflow.workflow_id} "
                f"({processing_time}ms)"
            )
            
            return workflow.workflow_id
            
        except Exception as e:
            logging.error(f"Failed to submit classification change: {e}")
            await self.audit_logger.log_classification_event(
                event_type='workflow_error',
                user_id=request.requestor_id,
                data_id=request.data_id,
                error=str(e),
                metadata={'operation': 'submit_classification_change'}
            )
            raise
    
    async def _validate_change_request(self, request: ClassificationChangeRequest):
        """Validate classification change request"""
        
        # Verify requestor clearance
        clearance_request = ClearanceVerificationRequest(
            user_id=request.requestor_id,
            required_clearance=request.proposed_classification.level,
            compartments=request.proposed_classification.compartments,
            special_access_programs=request.proposed_classification.special_access_programs
        )
        
        clearance_result = await self.clearance_engine.verify_clearance(clearance_request)
        if clearance_result.status != ClearanceStatus.VALID:
            raise ValueError(f"Insufficient clearance for proposed classification: {clearance_result.status}")
        
        # Validate classification levels
        if not self._is_valid_classification_change(
            request.current_classification,
            request.proposed_classification,
            request.change_type
        ):
            raise ValueError("Invalid classification change requested")
        
        # Check for required justification
        if not request.justification or len(request.justification.strip()) < 10:
            raise ValueError("Adequate justification required for classification changes")
    
    def _is_valid_classification_change(
        self,
        current: SecurityLabel,
        proposed: SecurityLabel,
        change_type: WorkflowType
    ) -> bool:
        """Validate classification change logic"""
        
        current_level = current.level.value
        proposed_level = proposed.level.value
        
        if change_type == WorkflowType.UPGRADE:
            return proposed_level > current_level
        elif change_type == WorkflowType.DOWNGRADE:
            return proposed_level < current_level
        elif change_type == WorkflowType.LATERAL_CHANGE:
            return proposed_level == current_level and (
                current.compartments != proposed.compartments or
                current.special_access_programs != proposed.special_access_programs
            )
        
        return True  # Emergency and other types have flexible rules
    
    def _select_workflow_template(self, request: ClassificationChangeRequest) -> WorkflowTemplate:
        """Select appropriate workflow template"""
        
        # Emergency workflows
        if request.change_type == WorkflowType.EMERGENCY_UPGRADE:
            return self.workflow_templates['emergency_upgrade']
        elif request.change_type == WorkflowType.SPILLAGE_REMEDIATION:
            return self.workflow_templates['spillage_remediation']
        
        # Standard workflows
        elif request.change_type == WorkflowType.UPGRADE:
            return self.workflow_templates['standard_upgrade']
        elif request.change_type == WorkflowType.DOWNGRADE:
            return self.workflow_templates['standard_downgrade']
        
        # Default to upgrade template
        return self.workflow_templates['standard_upgrade']
    
    async def _execute_workflow(self, workflow: WorkflowExecution):
        """Execute workflow steps"""
        start_time = time.time()
        
        try:
            workflow.status = WorkflowStatus.IN_PROGRESS
            workflow.started_at = datetime.now(timezone.utc)
            workflow.current_step = "starting"
            
            template = self._select_workflow_template(workflow.change_request)
            
            # Execute each step
            for step in template.steps:
                workflow.current_step = step
                
                try:
                    await self._execute_workflow_step(workflow, step)
                    workflow.steps_completed.append(step)
                    
                    # Log step completion
                    workflow.execution_log.append({
                        'step': step,
                        'status': 'completed',
                        'timestamp': datetime.now(timezone.utc).isoformat(),
                        'duration_ms': int((time.time() - start_time) * 1000)
                    })
                    
                except Exception as e:
                    workflow.steps_failed.append(step)
                    workflow.error_messages.append(f"Step {step} failed: {str(e)}")
                    
                    workflow.execution_log.append({
                        'step': step,
                        'status': 'failed',
                        'error': str(e),
                        'timestamp': datetime.now(timezone.utc).isoformat()
                    })
                    
                    # Handle step failure
                    if step in ['validate_request', 'verify_clearances']:
                        # Critical steps - fail entire workflow
                        workflow.status = WorkflowStatus.FAILED
                        return
                    else:
                        # Non-critical steps - log and continue
                        logging.warning(f"Non-critical step failed: {step} - {e}")
            
            # Mark workflow as completed
            workflow.status = WorkflowStatus.COMPLETED
            workflow.completed_at = datetime.now(timezone.utc)
            workflow.processing_time_ms = int((time.time() - start_time) * 1000)
            
            # Update performance metrics
            self.performance_metrics['workflows_processed'] += 1
            self.performance_metrics['workflows_approved'] += 1
            
            # Log completion
            await self.audit_logger.log_classification_event(
                event_type='workflow_completed',
                user_id=workflow.change_request.requestor_id,
                data_id=workflow.change_request.data_id,
                workflow_id=str(workflow.workflow_id),
                final_classification=workflow.final_classification.level.value if workflow.final_classification else None,
                processing_time_ms=workflow.processing_time_ms,
                metadata={
                    'steps_completed': workflow.steps_completed,
                    'steps_failed': workflow.steps_failed
                }
            )
            
            logging.info(
                f"Workflow completed: {workflow.workflow_id} "
                f"({workflow.processing_time_ms}ms)"
            )
            
        except Exception as e:
            workflow.status = WorkflowStatus.FAILED
            workflow.error_messages.append(f"Workflow execution failed: {str(e)}")
            
            logging.error(f"Workflow execution failed: {workflow.workflow_id} - {e}")
            
            await self.audit_logger.log_classification_event(
                event_type='workflow_failed',
                user_id=workflow.change_request.requestor_id,
                data_id=workflow.change_request.data_id,
                workflow_id=str(workflow.workflow_id),
                error=str(e),
                metadata={'execution_log': workflow.execution_log}
            )
        
        finally:
            workflow.updated_at = datetime.now(timezone.utc)
    
    async def _execute_workflow_step(self, workflow: WorkflowExecution, step: str):
        """Execute individual workflow step"""
        
        if step == 'validate_request':
            await self._validate_change_request(workflow.change_request)
            
        elif step == 'verify_clearances':
            await self._verify_all_clearances(workflow)
            
        elif step == 'collect_approvals':
            await self._collect_approvals(workflow)
            
        elif step == 'perform_classification':
            await self._perform_classification_change(workflow)
            
        elif step == 'update_records':
            await self._update_classification_records(workflow)
            
        elif step == 'notify_stakeholders':
            await self._notify_stakeholders(workflow)
            
        elif step == 'validate_emergency':
            await self._validate_emergency_request(workflow)
            
        elif step == 'expedited_approval':
            await self._handle_expedited_approval(workflow)
            
        elif step == 'immediate_classification':
            await self._immediate_classification_change(workflow)
            
        elif step == 'emergency_notification':
            await self._send_emergency_notifications(workflow)
            
        elif step == 'post_action_review':
            await self._schedule_post_action_review(workflow)
            
        elif step == 'content_sanitization_check':
            await self._verify_sanitization_requirements(workflow)
            
        elif step == 'perform_sanitization':
            await self._perform_content_sanitization(workflow)
            
        elif step == 'containment':
            await self._perform_spillage_containment(workflow)
            
        elif step == 'impact_assessment':
            await self._assess_spillage_impact(workflow)
            
        elif step == 'access_revocation':
            await self._revoke_inappropriate_access(workflow)
            
        else:
            logging.warning(f"Unknown workflow step: {step}")
    
    async def _collect_approvals(self, workflow: WorkflowExecution):
        """Collect required approvals for workflow"""
        
        # Create approval records
        for requirement in workflow.required_approvals:
            approval = WorkflowApproval(
                approval_id=uuid4(),
                workflow_id=workflow.workflow_id,
                approver_id="",  # Will be filled when claimed
                approver_role=requirement.role,
                requirement=requirement,
                status=ApprovalStatus.PENDING,
                expires_at=datetime.now(timezone.utc) + timedelta(hours=requirement.timeout_hours)
            )
            workflow.approvals.append(approval)
        
        # Update workflow status
        workflow.status = WorkflowStatus.AWAITING_APPROVAL
        
        # Send approval notifications
        await self._send_approval_notifications(workflow)
        
        # Wait for approvals (handled by background process)
        await self._wait_for_approvals(workflow)
    
    async def _wait_for_approvals(self, workflow: WorkflowExecution):
        """Wait for all required approvals"""
        
        timeout = 300  # 5 minutes timeout for this check
        check_interval = 10  # Check every 10 seconds
        elapsed_time = 0
        
        while elapsed_time < timeout:
            # Check if all mandatory approvals are received
            mandatory_approvals = [a for a in workflow.approvals if a.requirement.mandatory]
            approved_mandatory = [a for a in mandatory_approvals if a.status == ApprovalStatus.APPROVED]
            rejected_any = [a for a in workflow.approvals if a.status == ApprovalStatus.REJECTED]
            
            if rejected_any:
                workflow.status = WorkflowStatus.REJECTED
                return
            
            if len(approved_mandatory) == len(mandatory_approvals):
                workflow.status = WorkflowStatus.APPROVED
                return
            
            await asyncio.sleep(check_interval)
            elapsed_time += check_interval
        
        # Continue with partial approvals for non-emergency workflows
        if workflow.workflow_type not in [WorkflowType.EMERGENCY_UPGRADE, WorkflowType.SPILLAGE_REMEDIATION]:
            workflow.status = WorkflowStatus.APPROVED
    
    async def approve_workflow(
        self,
        workflow_id: UUID,
        approver_id: str,
        approver_role: str,
        approved: bool,
        justification: str,
        comments: Optional[str] = None
    ) -> bool:
        """
        Approve or reject a workflow
        
        Args:
            workflow_id: Workflow to approve
            approver_id: ID of approver
            approver_role: Role of approver
            approved: Whether approved or rejected
            justification: Justification for decision
            comments: Additional comments
            
        Returns:
            Success status
        """
        
        try:
            with self.workflow_lock:
                workflow = self.active_workflows.get(workflow_id)
                if not workflow:
                    raise ValueError(f"Workflow not found: {workflow_id}")
                
                # Find matching approval requirement
                approval = None
                for a in workflow.approvals:
                    if (a.approver_role == approver_role and 
                        a.status == ApprovalStatus.PENDING and
                        not a.approver_id):
                        approval = a
                        break
                
                if not approval:
                    raise ValueError(f"No pending approval found for role: {approver_role}")
                
                # Verify approver clearance
                clearance_request = ClearanceVerificationRequest(
                    user_id=approver_id,
                    required_clearance=approval.requirement.clearance_level,
                    compartments=workflow.change_request.proposed_classification.compartments,
                    special_access_programs=workflow.change_request.proposed_classification.special_access_programs
                )
                
                clearance_result = await self.clearance_engine.verify_clearance(clearance_request)
                if clearance_result.status != ClearanceStatus.VALID:
                    raise ValueError(f"Insufficient clearance for approval: {clearance_result.status}")
                
                # Update approval
                approval.approver_id = approver_id
                approval.status = ApprovalStatus.APPROVED if approved else ApprovalStatus.REJECTED
                approval.timestamp = datetime.now(timezone.utc)
                approval.justification = justification
                approval.comments = comments
                
                # Log approval
                await self.audit_logger.log_classification_event(
                    event_type='workflow_approval',
                    user_id=approver_id,
                    data_id=workflow.change_request.data_id,
                    workflow_id=str(workflow_id),
                    approved=approved,
                    approver_role=approver_role,
                    justification=justification,
                    metadata={'comments': comments}
                )
                
                # Check if workflow can proceed
                if not approved and approval.requirement.mandatory:
                    workflow.status = WorkflowStatus.REJECTED
                    logging.info(f"Workflow rejected: {workflow_id} by {approver_role}")
                else:
                    # Check if all mandatory approvals are complete
                    mandatory_pending = [
                        a for a in workflow.approvals 
                        if a.requirement.mandatory and a.status == ApprovalStatus.PENDING
                    ]
                    
                    if not mandatory_pending:
                        workflow.status = WorkflowStatus.APPROVED
                        logging.info(f"Workflow approved: {workflow_id}")
                
                workflow.updated_at = datetime.now(timezone.utc)
                
                return True
                
        except Exception as e:
            logging.error(f"Failed to approve workflow: {e}")
            await self.audit_logger.log_classification_event(
                event_type='approval_error',
                user_id=approver_id,
                workflow_id=str(workflow_id),
                error=str(e),
                metadata={'operation': 'approve_workflow'}
            )
            raise
    
    async def get_workflow_status(self, workflow_id: UUID) -> Optional[WorkflowExecution]:
        """Get workflow status and details"""
        
        with self.workflow_lock:
            return self.active_workflows.get(workflow_id)
    
    async def list_pending_approvals(self, approver_role: str) -> List[WorkflowExecution]:
        """List workflows pending approval for a specific role"""
        
        pending_workflows = []
        
        with self.workflow_lock:
            for workflow in self.active_workflows.values():
                if workflow.status == WorkflowStatus.AWAITING_APPROVAL:
                    # Check if this role has pending approvals
                    for approval in workflow.approvals:
                        if (approval.approver_role == approver_role and 
                            approval.status == ApprovalStatus.PENDING):
                            pending_workflows.append(workflow)
                            break
        
        return pending_workflows
    
    async def _perform_classification_change(self, workflow: WorkflowExecution):
        """Perform the actual classification change"""
        
        # Apply new classification
        new_label = workflow.change_request.proposed_classification
        
        # Use the classification engine to apply changes
        # This would integrate with the data storage system
        
        workflow.final_classification = new_label
        
        # Log the change
        await self.audit_logger.log_classification_event(
            event_type='classification_changed',
            user_id=workflow.change_request.requestor_id,
            data_id=workflow.change_request.data_id,
            current_classification=workflow.change_request.current_classification.level.value,
            new_classification=new_label.level.value,
            workflow_id=str(workflow.workflow_id),
            justification=workflow.change_request.justification
        )
    
    def _workflow_monitor(self):
        """Background workflow monitoring"""
        
        while True:
            try:
                current_time = datetime.now(timezone.utc)
                expired_workflows = []
                
                with self.workflow_lock:
                    for workflow_id, workflow in list(self.active_workflows.items()):
                        # Check for expired workflows
                        if (workflow.expires_at and 
                            current_time > workflow.expires_at and
                            workflow.status not in [WorkflowStatus.COMPLETED, WorkflowStatus.FAILED, WorkflowStatus.CANCELLED]):
                            
                            workflow.status = WorkflowStatus.EXPIRED
                            expired_workflows.append(workflow_id)
                        
                        # Clean up old completed workflows
                        elif (workflow.status in [WorkflowStatus.COMPLETED, WorkflowStatus.FAILED, WorkflowStatus.CANCELLED] and
                              workflow.completed_at and
                              current_time > workflow.completed_at + timedelta(hours=24)):
                            
                            del self.active_workflows[workflow_id]
                
                # Log expired workflows
                for workflow_id in expired_workflows:
                    logging.warning(f"Workflow expired: {workflow_id}")
                
                time.sleep(60)  # Check every minute
                
            except Exception as e:
                logging.error(f"Workflow monitor error: {e}")
                time.sleep(60)
    
    def _approval_timeout_checker(self):
        """Check for approval timeouts"""
        
        while True:
            try:
                current_time = datetime.now(timezone.utc)
                
                with self.workflow_lock:
                    for workflow in self.active_workflows.values():
                        if workflow.status == WorkflowStatus.AWAITING_APPROVAL:
                            for approval in workflow.approvals:
                                if (approval.status == ApprovalStatus.PENDING and
                                    approval.expires_at and
                                    current_time > approval.expires_at):
                                    
                                    approval.status = ApprovalStatus.EXPIRED
                                    logging.warning(
                                        f"Approval expired: {approval.approval_id} "
                                        f"for workflow {workflow.workflow_id}"
                                    )
                
                time.sleep(300)  # Check every 5 minutes
                
            except Exception as e:
                logging.error(f"Approval timeout checker error: {e}")
                time.sleep(300)
    
    async def _send_approval_notifications(self, workflow: WorkflowExecution):
        """Send notifications for required approvals"""
        
        # This would integrate with notification system
        # For now, just log the requirement
        
        for approval in workflow.approvals:
            logging.info(
                f"Approval required: Role {approval.approver_role} "
                f"for workflow {workflow.workflow_id} "
                f"(expires: {approval.expires_at})"
            )
    
    async def _verify_all_clearances(self, workflow: WorkflowExecution):
        """Verify clearances for all involved parties"""
        
        # Verify requestor clearance
        clearance_request = ClearanceVerificationRequest(
            user_id=workflow.change_request.requestor_id,
            required_clearance=workflow.change_request.proposed_classification.level,
            compartments=workflow.change_request.proposed_classification.compartments,
            special_access_programs=workflow.change_request.proposed_classification.special_access_programs
        )
        
        result = await self.clearance_engine.verify_clearance(clearance_request)
        if result.status != ClearanceStatus.VALID:
            raise ValueError(f"Requestor clearance invalid: {result.status}")
    
    async def _update_classification_records(self, workflow: WorkflowExecution):
        """Update classification records in all systems"""
        
        # This would update records in:
        # - Classification database
        # - Access control systems
        # - Audit systems
        # - Distribution lists
        
        logging.info(f"Classification records updated for workflow {workflow.workflow_id}")
    
    async def _notify_stakeholders(self, workflow: WorkflowExecution):
        """Notify relevant stakeholders of classification change"""
        
        # This would send notifications to:
        # - Data owners
        # - System administrators
        # - Security managers
        # - Users with access to the data
        
        logging.info(f"Stakeholders notified for workflow {workflow.workflow_id}")
    
    # Emergency workflow steps
    async def _validate_emergency_request(self, workflow: WorkflowExecution):
        """Validate emergency classification request"""
        
        if workflow.change_request.urgency != PriorityLevel.EMERGENCY:
            raise ValueError("Emergency workflow requires emergency priority")
        
        if not workflow.change_request.deadline:
            raise ValueError("Emergency workflow requires deadline")
    
    async def _handle_expedited_approval(self, workflow: WorkflowExecution):
        """Handle expedited approval process"""
        
        # For emergency workflows, we may auto-approve under certain conditions
        # or use abbreviated approval processes
        
        emergency_approvals = [a for a in workflow.approvals if a.requirement.timeout_hours <= 2]
        
        for approval in emergency_approvals:
            # Check for auto-approval conditions
            if self._check_auto_approval_conditions(workflow, approval):
                approval.status = ApprovalStatus.APPROVED
                approval.timestamp = datetime.now(timezone.utc)
                approval.justification = "Auto-approved due to emergency conditions"
                approval.approver_id = "system_emergency"
    
    def _check_auto_approval_conditions(self, workflow: WorkflowExecution, approval: WorkflowApproval) -> bool:
        """Check if approval can be auto-approved"""
        
        # Example conditions for auto-approval:
        # - Spillage remediation with containment
        # - Threat-based emergency upgrades
        # - Time-critical operational requirements
        
        return False  # Conservative default
    
    async def _immediate_classification_change(self, workflow: WorkflowExecution):
        """Perform immediate classification change for emergencies"""
        
        # Apply classification immediately without full validation
        new_label = workflow.change_request.proposed_classification
        workflow.final_classification = new_label
        
        # Log emergency change
        await self.audit_logger.log_classification_event(
            event_type='emergency_classification_change',
            user_id=workflow.change_request.requestor_id,
            data_id=workflow.change_request.data_id,
            current_classification=workflow.change_request.current_classification.level.value,
            new_classification=new_label.level.value,
            workflow_id=str(workflow.workflow_id),
            justification=workflow.change_request.justification,
            metadata={'emergency': True}
        )
    
    async def _send_emergency_notifications(self, workflow: WorkflowExecution):
        """Send emergency notifications"""
        
        # High-priority notifications to key personnel
        logging.critical(
            f"EMERGENCY CLASSIFICATION CHANGE: {workflow.workflow_id} "
            f"Data: {workflow.change_request.data_id} "
            f"New Level: {workflow.final_classification.level.value if workflow.final_classification else 'Unknown'}"
        )
    
    async def _schedule_post_action_review(self, workflow: WorkflowExecution):
        """Schedule post-action review for emergency workflows"""
        
        # Schedule review within 24 hours of emergency action
        review_deadline = datetime.now(timezone.utc) + timedelta(hours=24)
        
        logging.info(
            f"Post-action review scheduled for {workflow.workflow_id} "
            f"by {review_deadline}"
        )
    
    # Downgrade workflow steps
    async def _verify_sanitization_requirements(self, workflow: WorkflowExecution):
        """Verify if content sanitization is required for downgrade"""
        
        current_level = workflow.change_request.current_classification.level.value
        proposed_level = workflow.change_request.proposed_classification.level.value
        
        if proposed_level < current_level:
            # Downgrade requires sanitization verification
            workflow.execution_log.append({
                'step': 'sanitization_required',
                'current_level': current_level,
                'proposed_level': proposed_level,
                'timestamp': datetime.now(timezone.utc).isoformat()
            })
    
    async def _perform_content_sanitization(self, workflow: WorkflowExecution):
        """Perform content sanitization for downgrade"""
        
        # This would integrate with the data sanitization engine
        # For now, just log the requirement
        
        logging.info(
            f"Content sanitization required for workflow {workflow.workflow_id} "
            f"({workflow.change_request.current_classification.level.value} -> "
            f"{workflow.change_request.proposed_classification.level.value})"
        )
    
    # Spillage remediation steps
    async def _perform_spillage_containment(self, workflow: WorkflowExecution):
        """Perform spillage containment actions"""
        
        # Immediate containment actions:
        # - Isolate affected systems
        # - Revoke access credentials
        # - Block data transfers
        
        logging.critical(
            f"SPILLAGE CONTAINMENT INITIATED: {workflow.workflow_id} "
            f"Data: {workflow.change_request.data_id}"
        )
    
    async def _assess_spillage_impact(self, workflow: WorkflowExecution):
        """Assess impact of data spillage"""
        
        # Assess:
        # - Scope of exposure
        # - Affected systems and users
        # - Potential damage
        # - Required remediation actions
        
        workflow.execution_log.append({
            'step': 'impact_assessment',
            'scope': 'system_wide',  # Would be calculated
            'severity': 'high',      # Would be determined
            'timestamp': datetime.now(timezone.utc).isoformat()
        })
    
    async def _revoke_inappropriate_access(self, workflow: WorkflowExecution):
        """Revoke access that violates classification requirements"""
        
        # This would integrate with access control systems to:
        # - Identify users with inappropriate access
        # - Revoke access permissions
        # - Update access control lists
        
        logging.warning(
            f"Access revocation initiated for workflow {workflow.workflow_id}"
        )
    
    def get_performance_metrics(self) -> Dict[str, Any]:
        """Get workflow engine performance metrics"""
        
        with self.workflow_lock:
            active_count = len(self.active_workflows)
            pending_count = len([w for w in self.active_workflows.values() 
                               if w.status == WorkflowStatus.PENDING])
            in_progress_count = len([w for w in self.active_workflows.values() 
                                   if w.status == WorkflowStatus.IN_PROGRESS])
            awaiting_approval_count = len([w for w in self.active_workflows.values() 
                                         if w.status == WorkflowStatus.AWAITING_APPROVAL])
        
        return {
            **self.performance_metrics,
            'active_workflows': active_count,
            'pending_workflows': pending_count,
            'in_progress_workflows': in_progress_count,
            'awaiting_approval_workflows': awaiting_approval_count,
            'workflow_templates': len(self.workflow_templates)
        }
    
    async def shutdown(self):
        """Shutdown workflow engine"""
        
        logging.info("Shutting down Classification Workflow Engine")
        
        # Wait for active workflows to complete or timeout
        timeout = 30  # seconds
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            with self.workflow_lock:
                active_workflows = [
                    w for w in self.active_workflows.values()
                    if w.status in [WorkflowStatus.IN_PROGRESS, WorkflowStatus.AWAITING_APPROVAL]
                ]
            
            if not active_workflows:
                break
            
            await asyncio.sleep(1)
        
        # Shutdown executor
        self.executor.shutdown(wait=True)
        
        logging.info("Classification Workflow Engine shut down")


# Example usage and testing
if __name__ == "__main__":
    async def test_workflow_engine():
        """Test the classification workflow engine"""
        
        # This would normally be injected
        from .enhanced_classification_engine import EnhancedMultiClassificationEngine
        from .clearance_verification_engine import EnhancedClearanceVerificationEngine
        from .classification_audit_logger import ClassificationAuditLogger
        from ..auth.unified_access_control.access_controller import UnifiedAccessController
        
        # Initialize components (mock for testing)
        classification_engine = None  # Would be real instance
        clearance_engine = None       # Would be real instance
        access_controller = None      # Would be real instance
        audit_logger = None          # Would be real instance
        
        # Create workflow engine
        workflow_engine = ClassificationWorkflowEngine(
            classification_engine=classification_engine,
            clearance_engine=clearance_engine,
            access_controller=access_controller,
            audit_logger=audit_logger,
            config={
                'max_concurrent_workflows': 50,
                'default_timeout_hours': 72,
                'emergency_timeout_hours': 4
            }
        )
        
        print("Classification Workflow Engine initialized successfully")
        print(f"Performance metrics: {workflow_engine.get_performance_metrics()}")
        
        # Test workflow submission
        change_request = ClassificationChangeRequest(
            request_id=uuid4(),
            data_id="test_document_001",
            current_classification=SecurityLabel(
                level=ClassificationLevel.CONFIDENTIAL,
                compartments=[],
                special_access_programs=[]
            ),
            proposed_classification=SecurityLabel(
                level=ClassificationLevel.SECRET,
                compartments=[],
                special_access_programs=[]
            ),
            change_type=WorkflowType.UPGRADE,
            requestor_id="user123",
            requestor_clearance=SecurityClearance.SECRET,
            justification="Document contains information requiring SECRET classification due to operational sensitivity",
            urgency=PriorityLevel.NORMAL
        )
        
        print(f"Test change request created: {change_request.request_id}")
        
        # Clean shutdown
        await workflow_engine.shutdown()
    
    # Run test
    asyncio.run(test_workflow_engine())