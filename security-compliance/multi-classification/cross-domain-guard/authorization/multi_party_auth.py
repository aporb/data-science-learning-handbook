"""
Multi-Party Authorization System

This module implements multi-party authorization workflows for cross-domain transfers,
including approval chains, voting mechanisms, and delegation management.
"""

import logging
import asyncio
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass, field
import uuid
import json
from pathlib import Path

# Import existing security components
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from models.classification_models import ClassificationLevel
from engines.cross_domain_guard import NetworkDomain, TransferRequest, TransferDirection


class AuthorizationStatus(Enum):
    """Authorization status enumeration"""
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    ESCALATED = "escalated"
    EXPIRED = "expired"
    DELEGATED = "delegated"


class ApprovalDecision(Enum):
    """Approval decision enumeration"""
    APPROVE = "approve"
    REJECT = "reject"
    ABSTAIN = "abstain"
    DELEGATE = "delegate"
    ESCALATE = "escalate"


class AuthorityLevel(Enum):
    """Authority level enumeration"""
    SUPERVISOR = "supervisor"
    SECURITY_OFFICER = "security_officer"
    CLASSIFICATION_AUTHORITY = "classification_authority"
    INTEL_OFFICER = "intel_officer"
    MISSION_COMMANDER = "mission_commander"
    SYSTEM_ADMINISTRATOR = "system_administrator"


@dataclass
class AuthorityRole:
    """Authority role definition"""
    level: AuthorityLevel
    permissions: List[str]
    clearance_required: ClassificationLevel
    domains: List[NetworkDomain]
    delegatable: bool = True
    max_delegation_days: int = 30


@dataclass
class ApprovalRequest:
    """Individual approval request"""
    id: str
    transfer_id: str
    approver_id: str
    authority_level: AuthorityLevel
    requested_by: str
    requested_at: datetime
    required_by: datetime
    status: AuthorizationStatus = AuthorizationStatus.PENDING
    decision: Optional[ApprovalDecision] = None
    decision_timestamp: Optional[datetime] = None
    comments: Optional[str] = None
    conditions: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ApprovalChain:
    """Approval chain configuration"""
    id: str
    name: str
    description: str
    required_approvals: List[AuthorityLevel]
    voting_rules: Dict[str, Any]
    escalation_rules: Dict[str, Any]
    time_limits: Dict[str, int]
    conditions: List[str] = field(default_factory=list)


@dataclass
class AuthorizationWorkflow:
    """Authorization workflow state"""
    id: str
    transfer_id: str
    chain_id: str
    status: AuthorizationStatus
    created_at: datetime
    updated_at: datetime
    approval_requests: List[ApprovalRequest] = field(default_factory=list)
    escalation_history: List[Dict[str, Any]] = field(default_factory=list)
    delegation_history: List[Dict[str, Any]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


class AuthorityManager:
    """Manages authority roles and permissions"""
    
    def __init__(self):
        self.authority_roles = self._initialize_authority_roles()
        self.user_authorities = {}
        self.delegation_records = {}
        
    def _initialize_authority_roles(self) -> Dict[AuthorityLevel, AuthorityRole]:
        """Initialize authority role definitions"""
        return {
            AuthorityLevel.SUPERVISOR: AuthorityRole(
                level=AuthorityLevel.SUPERVISOR,
                permissions=["approve_routine_transfer", "approve_upward_transfer"],
                clearance_required=ClassificationLevel.SECRET,
                domains=[NetworkDomain.NIPR, NetworkDomain.SIPR],
                delegatable=True,
                max_delegation_days=7
            ),
            AuthorityLevel.SECURITY_OFFICER: AuthorityRole(
                level=AuthorityLevel.SECURITY_OFFICER,
                permissions=[
                    "approve_routine_transfer", "approve_upward_transfer",
                    "approve_downward_transfer", "approve_security_exception",
                    "review_security_violations"
                ],
                clearance_required=ClassificationLevel.SECRET,
                domains=[NetworkDomain.NIPR, NetworkDomain.SIPR, NetworkDomain.JWICS],
                delegatable=True,
                max_delegation_days=14
            ),
            AuthorityLevel.CLASSIFICATION_AUTHORITY: AuthorityRole(
                level=AuthorityLevel.CLASSIFICATION_AUTHORITY,
                permissions=[
                    "approve_downward_transfer", "approve_declassification",
                    "modify_classification", "review_classification_decisions"
                ],
                clearance_required=ClassificationLevel.SECRET,
                domains=[NetworkDomain.NIPR, NetworkDomain.SIPR, NetworkDomain.JWICS],
                delegatable=False,
                max_delegation_days=0
            ),
            AuthorityLevel.INTEL_OFFICER: AuthorityRole(
                level=AuthorityLevel.INTEL_OFFICER,
                permissions=[
                    "approve_intel_transfer", "approve_jwics_transfer",
                    "review_sources_methods", "approve_compartmented_transfer"
                ],
                clearance_required=ClassificationLevel.TOP_SECRET,
                domains=[NetworkDomain.SIPR, NetworkDomain.JWICS],
                delegatable=True,
                max_delegation_days=3
            ),
            AuthorityLevel.MISSION_COMMANDER: AuthorityRole(
                level=AuthorityLevel.MISSION_COMMANDER,
                permissions=[
                    "approve_emergency_transfer", "approve_mission_critical",
                    "override_security_controls", "approve_exception_request"
                ],
                clearance_required=ClassificationLevel.SECRET,
                domains=[NetworkDomain.NIPR, NetworkDomain.SIPR, NetworkDomain.JWICS],
                delegatable=True,
                max_delegation_days=1
            ),
            AuthorityLevel.SYSTEM_ADMINISTRATOR: AuthorityRole(
                level=AuthorityLevel.SYSTEM_ADMINISTRATOR,
                permissions=[
                    "approve_system_transfer", "approve_maintenance_transfer",
                    "review_system_logs", "approve_technical_exception"
                ],
                clearance_required=ClassificationLevel.SECRET,
                domains=[NetworkDomain.NIPR, NetworkDomain.SIPR, NetworkDomain.JWICS],
                delegatable=True,
                max_delegation_days=7
            )
        }
    
    def assign_authority(self, user_id: str, authority_level: AuthorityLevel, 
                        granted_by: str, expires_at: Optional[datetime] = None):
        """Assign authority to user"""
        if user_id not in self.user_authorities:
            self.user_authorities[user_id] = {}
        
        self.user_authorities[user_id][authority_level] = {
            "granted_by": granted_by,
            "granted_at": datetime.now(),
            "expires_at": expires_at,
            "active": True
        }
        
        logging.info(f"Authority {authority_level.value} assigned to user {user_id}")
    
    def revoke_authority(self, user_id: str, authority_level: AuthorityLevel, revoked_by: str):
        """Revoke authority from user"""
        if user_id in self.user_authorities and authority_level in self.user_authorities[user_id]:
            self.user_authorities[user_id][authority_level]["active"] = False
            self.user_authorities[user_id][authority_level]["revoked_by"] = revoked_by
            self.user_authorities[user_id][authority_level]["revoked_at"] = datetime.now()
            
            logging.info(f"Authority {authority_level.value} revoked from user {user_id}")
    
    def check_user_authority(self, user_id: str, authority_level: AuthorityLevel) -> bool:
        """Check if user has specific authority"""
        if user_id not in self.user_authorities:
            return False
        
        authority_record = self.user_authorities[user_id].get(authority_level)
        if not authority_record or not authority_record["active"]:
            return False
        
        # Check expiration
        if authority_record["expires_at"] and authority_record["expires_at"] < datetime.now():
            authority_record["active"] = False
            return False
        
        return True
    
    def get_user_authorities(self, user_id: str) -> List[AuthorityLevel]:
        """Get all active authorities for user"""
        if user_id not in self.user_authorities:
            return []
        
        active_authorities = []
        for authority_level, record in self.user_authorities[user_id].items():
            if record["active"]:
                # Check expiration
                if record["expires_at"] and record["expires_at"] < datetime.now():
                    record["active"] = False
                    continue
                active_authorities.append(authority_level)
        
        return active_authorities
    
    def delegate_authority(self, delegator_id: str, delegate_id: str, 
                          authority_level: AuthorityLevel, expires_at: datetime,
                          reason: str) -> bool:
        """Delegate authority to another user"""
        # Check if delegator has authority
        if not self.check_user_authority(delegator_id, authority_level):
            return False
        
        # Check if authority is delegatable
        authority_role = self.authority_roles[authority_level]
        if not authority_role.delegatable:
            return False
        
        # Check delegation time limit
        max_delegation_time = timedelta(days=authority_role.max_delegation_days)
        if expires_at > datetime.now() + max_delegation_time:
            return False
        
        # Create delegation record
        delegation_id = str(uuid.uuid4())
        self.delegation_records[delegation_id] = {
            "delegator_id": delegator_id,
            "delegate_id": delegate_id,
            "authority_level": authority_level,
            "delegated_at": datetime.now(),
            "expires_at": expires_at,
            "reason": reason,
            "active": True
        }
        
        # Assign delegated authority
        self.assign_authority(delegate_id, authority_level, delegator_id, expires_at)
        
        logging.info(f"Authority {authority_level.value} delegated from {delegator_id} to {delegate_id}")
        return True
    
    def revoke_delegation(self, delegation_id: str, revoked_by: str) -> bool:
        """Revoke a delegation"""
        if delegation_id not in self.delegation_records:
            return False
        
        delegation = self.delegation_records[delegation_id]
        if not delegation["active"]:
            return False
        
        # Revoke delegated authority
        self.revoke_authority(delegation["delegate_id"], delegation["authority_level"], revoked_by)
        
        # Mark delegation as revoked
        delegation["active"] = False
        delegation["revoked_by"] = revoked_by
        delegation["revoked_at"] = datetime.now()
        
        logging.info(f"Delegation {delegation_id} revoked by {revoked_by}")
        return True


class ApprovalChainManager:
    """Manages approval chains and rules"""
    
    def __init__(self):
        self.approval_chains = self._initialize_approval_chains()
        
    def _initialize_approval_chains(self) -> Dict[str, ApprovalChain]:
        """Initialize predefined approval chains"""
        chains = {}
        
        # Standard upward transfer chain
        chains["upward_standard"] = ApprovalChain(
            id="upward_standard",
            name="Standard Upward Transfer",
            description="Standard approval chain for upward transfers",
            required_approvals=[AuthorityLevel.SUPERVISOR, AuthorityLevel.SECURITY_OFFICER],
            voting_rules={
                "type": "unanimous",
                "min_approvals": 2,
                "allow_abstain": False
            },
            escalation_rules={
                "timeout_hours": 24,
                "escalate_to": AuthorityLevel.MISSION_COMMANDER
            },
            time_limits={
                "supervisor": 8,  # hours
                "security_officer": 16
            }
        )
        
        # Downward transfer chain
        chains["downward_standard"] = ApprovalChain(
            id="downward_standard",
            name="Standard Downward Transfer",
            description="Standard approval chain for downward transfers",
            required_approvals=[
                AuthorityLevel.SUPERVISOR,
                AuthorityLevel.SECURITY_OFFICER,
                AuthorityLevel.CLASSIFICATION_AUTHORITY
            ],
            voting_rules={
                "type": "unanimous",
                "min_approvals": 3,
                "allow_abstain": False
            },
            escalation_rules={
                "timeout_hours": 48,
                "escalate_to": AuthorityLevel.MISSION_COMMANDER
            },
            time_limits={
                "supervisor": 8,
                "security_officer": 16,
                "classification_authority": 24
            }
        )
        
        # Intelligence transfer chain
        chains["intelligence_transfer"] = ApprovalChain(
            id="intelligence_transfer",
            name="Intelligence Transfer",
            description="Approval chain for intelligence data transfers",
            required_approvals=[
                AuthorityLevel.SUPERVISOR,
                AuthorityLevel.SECURITY_OFFICER,
                AuthorityLevel.INTEL_OFFICER
            ],
            voting_rules={
                "type": "unanimous",
                "min_approvals": 3,
                "allow_abstain": False
            },
            escalation_rules={
                "timeout_hours": 12,
                "escalate_to": AuthorityLevel.MISSION_COMMANDER
            },
            time_limits={
                "supervisor": 4,
                "security_officer": 8,
                "intel_officer": 12
            }
        )
        
        # Emergency transfer chain
        chains["emergency_transfer"] = ApprovalChain(
            id="emergency_transfer",
            name="Emergency Transfer",
            description="Expedited approval chain for emergency transfers",
            required_approvals=[AuthorityLevel.MISSION_COMMANDER],
            voting_rules={
                "type": "single",
                "min_approvals": 1,
                "allow_abstain": False
            },
            escalation_rules={
                "timeout_hours": 2,
                "escalate_to": AuthorityLevel.SYSTEM_ADMINISTRATOR
            },
            time_limits={
                "mission_commander": 1
            }
        )
        
        return chains
    
    def get_approval_chain(self, chain_id: str) -> Optional[ApprovalChain]:
        """Get approval chain by ID"""
        return self.approval_chains.get(chain_id)
    
    def select_approval_chain(self, transfer_request: TransferRequest) -> str:
        """Select appropriate approval chain for transfer"""
        # Emergency transfers
        if transfer_request.metadata.get("priority") == "emergency":
            return "emergency_transfer"
        
        # Intelligence transfers
        if (transfer_request.source_domain == NetworkDomain.JWICS or
            transfer_request.target_domain == NetworkDomain.JWICS):
            return "intelligence_transfer"
        
        # Downward transfers
        if transfer_request.direction == TransferDirection.DOWNWARD:
            return "downward_standard"
        
        # Default to upward standard
        return "upward_standard"


class MultiPartyAuthorizationEngine:
    """Main multi-party authorization engine"""
    
    def __init__(self):
        self.authority_manager = AuthorityManager()
        self.chain_manager = ApprovalChainManager()
        self.active_workflows = {}
        self.notification_callbacks = []
        
    def register_notification_callback(self, callback):
        """Register callback for authorization notifications"""
        self.notification_callbacks.append(callback)
    
    async def _notify_approvers(self, workflow: AuthorizationWorkflow, message: str):
        """Notify approvers of authorization events"""
        for callback in self.notification_callbacks:
            try:
                await callback(workflow, message)
            except Exception as e:
                logging.error(f"Notification callback error: {e}")
    
    async def initiate_authorization(self, transfer_request: TransferRequest) -> str:
        """Initiate authorization workflow for transfer"""
        try:
            # Select appropriate approval chain
            chain_id = self.chain_manager.select_approval_chain(transfer_request)
            chain = self.chain_manager.get_approval_chain(chain_id)
            
            if not chain:
                raise ValueError(f"Approval chain {chain_id} not found")
            
            # Create authorization workflow
            workflow = AuthorizationWorkflow(
                id=str(uuid.uuid4()),
                transfer_id=transfer_request.id,
                chain_id=chain_id,
                status=AuthorizationStatus.PENDING,
                created_at=datetime.now(),
                updated_at=datetime.now()
            )
            
            # Create approval requests
            await self._create_approval_requests(workflow, chain, transfer_request)
            
            # Store workflow
            self.active_workflows[workflow.id] = workflow
            
            # Notify approvers
            await self._notify_approvers(workflow, "New authorization request submitted")
            
            logging.info(f"Authorization workflow {workflow.id} initiated for transfer {transfer_request.id}")
            return workflow.id
            
        except Exception as e:
            logging.error(f"Error initiating authorization: {e}")
            raise
    
    async def _create_approval_requests(self, workflow: AuthorizationWorkflow, 
                                       chain: ApprovalChain, transfer_request: TransferRequest):
        """Create individual approval requests"""
        for authority_level in chain.required_approvals:
            # Find users with this authority
            approvers = self._find_approvers(authority_level, transfer_request)
            
            if not approvers:
                raise ValueError(f"No approvers found for authority level {authority_level.value}")
            
            # Create approval request for each approver
            for approver_id in approvers:
                time_limit_hours = chain.time_limits.get(authority_level.value, 24)
                required_by = datetime.now() + timedelta(hours=time_limit_hours)
                
                approval_request = ApprovalRequest(
                    id=str(uuid.uuid4()),
                    transfer_id=transfer_request.id,
                    approver_id=approver_id,
                    authority_level=authority_level,
                    requested_by=transfer_request.requester_id,
                    requested_at=datetime.now(),
                    required_by=required_by
                )
                
                workflow.approval_requests.append(approval_request)
    
    def _find_approvers(self, authority_level: AuthorityLevel, 
                       transfer_request: TransferRequest) -> List[str]:
        """Find users with required authority level"""
        approvers = []
        
        for user_id, authorities in self.authority_manager.user_authorities.items():
            if authority_level in authorities and authorities[authority_level]["active"]:
                # Check if authority is valid for this transfer
                if self._is_authority_valid_for_transfer(user_id, authority_level, transfer_request):
                    approvers.append(user_id)
        
        return approvers
    
    def _is_authority_valid_for_transfer(self, user_id: str, authority_level: AuthorityLevel,
                                        transfer_request: TransferRequest) -> bool:
        """Check if user's authority is valid for the transfer"""
        authority_role = self.authority_manager.authority_roles[authority_level]
        
        # Check domain permissions
        if (transfer_request.source_domain not in authority_role.domains and
            transfer_request.target_domain not in authority_role.domains):
            return False
        
        # Check clearance level
        max_classification = max(item.classification for item in transfer_request.data_items)
        if max_classification.value > authority_role.clearance_required.value:
            return False
        
        return True
    
    async def submit_approval_decision(self, workflow_id: str, approver_id: str,
                                      decision: ApprovalDecision, comments: str = "",
                                      conditions: List[str] = None) -> bool:
        """Submit approval decision"""
        try:
            workflow = self.active_workflows.get(workflow_id)
            if not workflow:
                raise ValueError(f"Workflow {workflow_id} not found")
            
            # Find approval request
            approval_request = None
            for request in workflow.approval_requests:
                if request.approver_id == approver_id and request.status == AuthorizationStatus.PENDING:
                    approval_request = request
                    break
            
            if not approval_request:
                raise ValueError(f"No pending approval request found for {approver_id}")
            
            # Validate authority
            if not self.authority_manager.check_user_authority(approver_id, approval_request.authority_level):
                raise ValueError(f"User {approver_id} does not have required authority")
            
            # Update approval request
            approval_request.decision = decision
            approval_request.decision_timestamp = datetime.now()
            approval_request.comments = comments
            approval_request.conditions = conditions or []
            
            # Update status based on decision
            if decision == ApprovalDecision.APPROVE:
                approval_request.status = AuthorizationStatus.APPROVED
            elif decision == ApprovalDecision.REJECT:
                approval_request.status = AuthorizationStatus.REJECTED
            elif decision == ApprovalDecision.DELEGATE:
                approval_request.status = AuthorizationStatus.DELEGATED
            elif decision == ApprovalDecision.ESCALATE:
                approval_request.status = AuthorizationStatus.ESCALATED
            
            # Update workflow
            workflow.updated_at = datetime.now()
            
            # Check if workflow is complete
            await self._check_workflow_completion(workflow)
            
            # Notify participants
            await self._notify_approvers(workflow, f"Approval decision received from {approver_id}")
            
            logging.info(f"Approval decision {decision.value} submitted by {approver_id} for workflow {workflow_id}")
            return True
            
        except Exception as e:
            logging.error(f"Error submitting approval decision: {e}")
            return False
    
    async def _check_workflow_completion(self, workflow: AuthorizationWorkflow):
        """Check if workflow is complete"""
        chain = self.chain_manager.get_approval_chain(workflow.chain_id)
        if not chain:
            return
        
        # Check voting rules
        voting_rules = chain.voting_rules
        required_authorities = set(chain.required_approvals)
        
        # Count approvals by authority level
        approvals_by_authority = {}
        rejections_by_authority = {}
        
        for request in workflow.approval_requests:
            authority = request.authority_level
            
            if request.status == AuthorizationStatus.APPROVED:
                approvals_by_authority[authority] = approvals_by_authority.get(authority, 0) + 1
            elif request.status == AuthorizationStatus.REJECTED:
                rejections_by_authority[authority] = rejections_by_authority.get(authority, 0) + 1
        
        # Check if all required authorities have approved
        if voting_rules["type"] == "unanimous":
            if all(authority in approvals_by_authority for authority in required_authorities):
                workflow.status = AuthorizationStatus.APPROVED
                logging.info(f"Workflow {workflow.id} approved unanimously")
            elif any(authority in rejections_by_authority for authority in required_authorities):
                workflow.status = AuthorizationStatus.REJECTED
                logging.info(f"Workflow {workflow.id} rejected")
        
        # Check minimum approvals
        elif voting_rules["type"] == "majority":
            total_approvals = sum(approvals_by_authority.values())
            if total_approvals >= voting_rules["min_approvals"]:
                workflow.status = AuthorizationStatus.APPROVED
                logging.info(f"Workflow {workflow.id} approved by majority")
    
    async def check_authorization_timeouts(self):
        """Check for authorization timeouts and escalate if needed"""
        current_time = datetime.now()
        
        for workflow in self.active_workflows.values():
            if workflow.status != AuthorizationStatus.PENDING:
                continue
            
            chain = self.chain_manager.get_approval_chain(workflow.chain_id)
            if not chain:
                continue
            
            # Check for expired approval requests
            for request in workflow.approval_requests:
                if (request.status == AuthorizationStatus.PENDING and
                    current_time > request.required_by):
                    
                    # Escalate if configured
                    if chain.escalation_rules.get("escalate_to"):
                        await self._escalate_approval_request(workflow, request, chain)
                    else:
                        request.status = AuthorizationStatus.EXPIRED
                        logging.warning(f"Approval request {request.id} expired")
    
    async def _escalate_approval_request(self, workflow: AuthorizationWorkflow,
                                        request: ApprovalRequest, chain: ApprovalChain):
        """Escalate approval request to higher authority"""
        escalation_authority = chain.escalation_rules["escalate_to"]
        
        # Find escalation approvers
        escalation_approvers = []
        for user_id, authorities in self.authority_manager.user_authorities.items():
            if (escalation_authority in authorities and
                authorities[escalation_authority]["active"]):
                escalation_approvers.append(user_id)
        
        if not escalation_approvers:
            logging.error(f"No escalation approvers found for {escalation_authority.value}")
            return
        
        # Create escalation request
        escalation_request = ApprovalRequest(
            id=str(uuid.uuid4()),
            transfer_id=workflow.transfer_id,
            approver_id=escalation_approvers[0],  # Use first available
            authority_level=escalation_authority,
            requested_by=request.requested_by,
            requested_at=datetime.now(),
            required_by=datetime.now() + timedelta(hours=chain.escalation_rules["timeout_hours"]),
            metadata={"escalated_from": request.id}
        )
        
        workflow.approval_requests.append(escalation_request)
        request.status = AuthorizationStatus.ESCALATED
        
        # Record escalation
        workflow.escalation_history.append({
            "original_request": request.id,
            "escalated_to": escalation_request.id,
            "escalated_at": datetime.now(),
            "reason": "timeout"
        })
        
        # Notify escalation approver
        await self._notify_approvers(workflow, f"Approval request escalated to {escalation_authority.value}")
        
        logging.info(f"Approval request {request.id} escalated to {escalation_authority.value}")
    
    def get_workflow_status(self, workflow_id: str) -> Optional[AuthorizationStatus]:
        """Get workflow status"""
        workflow = self.active_workflows.get(workflow_id)
        return workflow.status if workflow else None
    
    def get_workflow_details(self, workflow_id: str) -> Optional[AuthorizationWorkflow]:
        """Get workflow details"""
        return self.active_workflows.get(workflow_id)
    
    def get_pending_approvals(self, user_id: str) -> List[ApprovalRequest]:
        """Get pending approval requests for user"""
        pending_approvals = []
        
        for workflow in self.active_workflows.values():
            for request in workflow.approval_requests:
                if (request.approver_id == user_id and
                    request.status == AuthorizationStatus.PENDING):
                    pending_approvals.append(request)
        
        return pending_approvals
    
    def get_authorization_statistics(self) -> Dict[str, Any]:
        """Get authorization statistics"""
        total_workflows = len(self.active_workflows)
        
        status_counts = {}
        for workflow in self.active_workflows.values():
            status_counts[workflow.status.value] = status_counts.get(workflow.status.value, 0) + 1
        
        return {
            "total_workflows": total_workflows,
            "status_counts": status_counts,
            "active_authorities": len(self.authority_manager.user_authorities),
            "active_delegations": len([d for d in self.authority_manager.delegation_records.values() if d["active"]])
        }