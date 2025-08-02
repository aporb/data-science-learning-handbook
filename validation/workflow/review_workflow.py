#!/usr/bin/env python3
"""
Content Review Workflow Orchestration System
=============================================

A comprehensive multi-stage content review workflow system that provides:
- Multi-stage review pipeline (author → reviewer → approver → publisher)
- Role-based access control and permission management
- Automated workflow state management and progression
- Quality gate enforcement based on scoring systems
- Stakeholder assignment and notification integration
- Review deadline tracking and escalation
- Comprehensive audit logging and reporting

Author: Claude Code Implementation
Created: 2025-07-28
Version: 1.0.0
"""

import os
import sys
import json
import logging
import asyncio
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any, Set, Callable
from pathlib import Path
from dataclasses import dataclass, asdict, field
from enum import Enum
import yaml
import git
from collections import defaultdict
import smtplib
from email.mime.text import MimeText
from email.mime.multipart import MimeMultipart

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class WorkflowStage(Enum):
    """Workflow stage enumeration"""
    DRAFT = "draft"
    TECHNICAL_REVIEW = "technical_review"
    EDUCATIONAL_REVIEW = "educational_review"
    BIAS_ASSESSMENT = "bias_assessment"
    SECURITY_REVIEW = "security_review"
    FINAL_APPROVAL = "final_approval"
    PUBLISHED = "published"
    REJECTED = "rejected"
    ARCHIVED = "archived"


class ReviewerRole(Enum):
    """Reviewer role enumeration"""
    AUTHOR = "author"
    TECHNICAL_REVIEWER = "technical_reviewer"
    EDUCATIONAL_REVIEWER = "educational_reviewer"
    BIAS_ASSESSOR = "bias_assessor" 
    SECURITY_REVIEWER = "security_reviewer"
    CONTENT_APPROVER = "content_approver"
    PUBLISHER = "publisher"
    ADMINISTRATOR = "administrator"


class ReviewAction(Enum):
    """Review action enumeration"""
    APPROVE = "approve"
    REQUEST_CHANGES = "request_changes"
    REJECT = "reject" 
    ESCALATE = "escalate"
    DELEGATE = "delegate"
    SKIP = "skip"


class NotificationPriority(Enum):
    """Notification priority levels"""
    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    URGENT = "urgent"


@dataclass
class ReviewCriteria:
    """Review criteria definition"""
    name: str
    description: str
    weight: float
    required_score: float
    automated_check: bool = False
    check_function: Optional[str] = None


@dataclass
class StageConfiguration:
    """Workflow stage configuration"""
    stage: WorkflowStage
    required_roles: List[ReviewerRole]
    optional_roles: List[ReviewerRole]
    minimum_approvals: int
    maximum_duration_hours: int
    parallel_reviews: bool
    auto_advance_threshold: Optional[float]
    criteria: List[ReviewCriteria]
    notification_triggers: List[str]


@dataclass
class Reviewer:
    """Reviewer information"""
    user_id: str
    name: str
    email: str
    roles: List[ReviewerRole]
    expertise_areas: List[str]
    workload_capacity: int
    current_assignments: int = 0
    notification_preferences: Dict[str, bool] = field(default_factory=dict)
    last_active: Optional[str] = None


@dataclass
class ReviewAssignment:
    """Review assignment details"""
    assignment_id: str
    content_id: str
    reviewer: Reviewer
    stage: WorkflowStage
    role: ReviewerRole
    assigned_date: str
    due_date: str
    priority: NotificationPriority
    completed: bool = False
    completion_date: Optional[str] = None
    action: Optional[ReviewAction] = None
    score: Optional[float] = None
    comments: List[str] = field(default_factory=list)
    criteria_scores: Dict[str, float] = field(default_factory=dict)


@dataclass
class WorkflowInstance:
    """Workflow instance for content"""
    instance_id: str
    content_id: str
    content_path: str
    author: str
    current_stage: WorkflowStage
    stage_history: List[Dict[str, Any]] = field(default_factory=list)
    assignments: List[ReviewAssignment] = field(default_factory=list)
    created_date: str = field(default_factory=lambda: datetime.now().isoformat())
    deadline: Optional[str] = None
    overall_score: Optional[float] = None
    quality_gates_passed: Dict[str, bool] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    escalations: List[Dict[str, Any]] = field(default_factory=list)
    audit_log: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class QualityGate:
    """Quality gate definition"""
    gate_id: str
    name: str
    description: str
    stage: WorkflowStage
    required_score: float
    automated: bool
    blocking: bool
    check_function: Optional[Callable] = None


class WorkflowOrchestrator:
    """
    Comprehensive Content Review Workflow Orchestration System
    """
    
    def __init__(self, config_path: str, repo_path: Optional[str] = None):
        """
        Initialize the Workflow Orchestrator
        
        Args:
            config_path: Path to workflow configuration
            repo_path: Path to Git repository
        """
        self.config_path = Path(config_path)
        self.repo_path = Path(repo_path) if repo_path else Path.cwd()
        self.workflow_dir = self.repo_path / "validation" / "workflow"
        self.data_dir = self.workflow_dir / "data"
        
        # Ensure directories exist
        self.workflow_dir.mkdir(parents=True, exist_ok=True)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        
        # Load configuration
        self.config = self._load_configuration()
        
        # Initialize components
        self.stages = self._load_stage_configurations()
        self.reviewers = self._load_reviewers()
        self.quality_gates = self._load_quality_gates()
        self.workflows = self._load_active_workflows()
        
        # Initialize Git repo if available
        try:
            self.repo = git.Repo(self.repo_path)
        except git.InvalidGitRepositoryError:
            self.repo = None
            logger.warning("Git repository not found, some features may be limited")
        
        logger.info(f"Workflow Orchestrator initialized with {len(self.workflows)} active workflows")
    
    def _load_configuration(self) -> Dict[str, Any]:
        """Load workflow configuration"""
        default_config = {
            "workflow": {
                "max_parallel_workflows": 50,
                "default_deadline_days": 14,
                "escalation_threshold_hours": 48,
                "auto_assignment": True,
                "quality_gate_enforcement": True
            },
            "notifications": {
                "enabled": True,
                "smtp_server": "localhost",
                "smtp_port": 587,
                "from_email": "workflow@example.com",
                "reminder_intervals": [24, 6, 1]  # hours before deadline
            },
            "scoring": {
                "minimum_overall_score": 80.0,
                "bias_threshold": 0.3,
                "technical_accuracy_weight": 0.3,
                "educational_effectiveness_weight": 0.25,
                "bias_assessment_weight": 0.2,
                "security_compliance_weight": 0.15,
                "implementation_feasibility_weight": 0.1
            },
            "assignment": {
                "load_balancing": True,
                "expertise_matching": True,
                "max_assignments_per_reviewer": 5,
                "rotation_policy": "round_robin"
            }
        }
        
        if self.config_path.exists():
            try:
                with open(self.config_path, 'r') as f:
                    user_config = yaml.safe_load(f)
                    # Deep merge configuration
                    self._merge_config(default_config, user_config)
            except Exception as e:
                logger.warning(f"Failed to load config from {self.config_path}: {e}")
        
        return default_config
    
    def _merge_config(self, base: Dict, override: Dict):
        """Recursively merge configuration dictionaries"""
        for key, value in override.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                self._merge_config(base[key], value)
            else:
                base[key] = value
    
    def _load_stage_configurations(self) -> Dict[WorkflowStage, StageConfiguration]:
        """Load workflow stage configurations"""
        # Default stage configurations
        stages = {
            WorkflowStage.TECHNICAL_REVIEW: StageConfiguration(
                stage=WorkflowStage.TECHNICAL_REVIEW,
                required_roles=[ReviewerRole.TECHNICAL_REVIEWER],
                optional_roles=[ReviewerRole.AUTHOR],
                minimum_approvals=1,
                maximum_duration_hours=72,
                parallel_reviews=False,
                auto_advance_threshold=85.0,
                criteria=[
                    ReviewCriteria("technical_accuracy", "Technical correctness and implementation feasibility", 0.4, 75.0),
                    ReviewCriteria("code_quality", "Code examples and technical implementation quality", 0.3, 80.0),
                    ReviewCriteria("platform_compatibility", "Compatibility across target platforms", 0.3, 70.0)
                ],
                notification_triggers=["assignment", "reminder", "completion"]
            ),
            WorkflowStage.EDUCATIONAL_REVIEW: StageConfiguration(
                stage=WorkflowStage.EDUCATIONAL_REVIEW,
                required_roles=[ReviewerRole.EDUCATIONAL_REVIEWER],
                optional_roles=[ReviewerRole.AUTHOR],
                minimum_approvals=1,
                maximum_duration_hours=48,
                parallel_reviews=False,
                auto_advance_threshold=80.0,
                criteria=[
                    ReviewCriteria("learning_effectiveness", "Educational value and learning outcomes", 0.4, 75.0),
                    ReviewCriteria("content_structure", "Organization and flow of content", 0.3, 80.0),
                    ReviewCriteria("accessibility", "Content accessibility and inclusive design", 0.3, 75.0)
                ],
                notification_triggers=["assignment", "reminder", "completion"]
            ),
            WorkflowStage.BIAS_ASSESSMENT: StageConfiguration(
                stage=WorkflowStage.BIAS_ASSESSMENT,
                required_roles=[ReviewerRole.BIAS_ASSESSOR],
                optional_roles=[],
                minimum_approvals=1,
                maximum_duration_hours=24,
                parallel_reviews=False,
                auto_advance_threshold=None,  # Manual review required
                criteria=[
                    ReviewCriteria("methodology_bias", "Balance in methodology presentation", 0.4, 70.0),
                    ReviewCriteria("platform_neutrality", "Neutrality across platform implementations", 0.3, 70.0),
                    ReviewCriteria("demographic_inclusivity", "Inclusive examples and use cases", 0.3, 75.0)
                ],
                notification_triggers=["assignment", "reminder", "completion"]
            ),
            WorkflowStage.SECURITY_REVIEW: StageConfiguration(
                stage=WorkflowStage.SECURITY_REVIEW,
                required_roles=[ReviewerRole.SECURITY_REVIEWER],
                optional_roles=[],
                minimum_approvals=1,
                maximum_duration_hours=48,
                parallel_reviews=False,
                auto_advance_threshold=90.0,
                criteria=[
                    ReviewCriteria("security_compliance", "DoD and government security compliance", 0.5, 85.0),
                    ReviewCriteria("data_protection", "Data protection and privacy measures", 0.3, 80.0),
                    ReviewCriteria("vulnerability_assessment", "Security vulnerability assessment", 0.2, 75.0)
                ],
                notification_triggers=["assignment", "reminder", "completion"]
            ),
            WorkflowStage.FINAL_APPROVAL: StageConfiguration(
                stage=WorkflowStage.FINAL_APPROVAL,
                required_roles=[ReviewerRole.CONTENT_APPROVER],
                optional_roles=[ReviewerRole.PUBLISHER],
                minimum_approvals=1,
                maximum_duration_hours=24,
                parallel_reviews=False,
                auto_advance_threshold=None,  # Manual approval required
                criteria=[
                    ReviewCriteria("overall_quality", "Overall content quality assessment", 0.6, 80.0),
                    ReviewCriteria("readiness", "Readiness for publication", 0.4, 85.0)
                ],
                notification_triggers=["assignment", "reminder", "completion"]
            )
        }
        
        return stages
    
    def _load_reviewers(self) -> Dict[str, Reviewer]:
        """Load reviewer database"""
        reviewers_file = self.data_dir / "reviewers.json"
        reviewers = {}
        
        if reviewers_file.exists():
            try:
                with open(reviewers_file, 'r') as f:
                    data = json.load(f)
                    for reviewer_data in data.get('reviewers', []):
                        reviewer = Reviewer(
                            user_id=reviewer_data['user_id'],
                            name=reviewer_data['name'],
                            email=reviewer_data['email'],
                            roles=[ReviewerRole(role) for role in reviewer_data['roles']],
                            expertise_areas=reviewer_data.get('expertise_areas', []),
                            workload_capacity=reviewer_data.get('workload_capacity', 5),
                            current_assignments=reviewer_data.get('current_assignments', 0),
                            notification_preferences=reviewer_data.get('notification_preferences', {}),
                            last_active=reviewer_data.get('last_active')
                        )
                        reviewers[reviewer.user_id] = reviewer
            except Exception as e:
                logger.error(f"Failed to load reviewers: {e}")
        
        return reviewers
    
    def _save_reviewers(self):
        """Save reviewer database"""
        reviewers_file = self.data_dir / "reviewers.json"
        
        try:
            data = {
                "reviewers": [asdict(reviewer) for reviewer in self.reviewers.values()]
            }
            # Convert enums to strings
            for reviewer_data in data["reviewers"]:
                reviewer_data["roles"] = [role.value for role in reviewer_data["roles"]]
            
            with open(reviewers_file, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save reviewers: {e}")
    
    def _load_quality_gates(self) -> Dict[str, QualityGate]:
        """Load quality gate definitions"""
        gates = {
            "technical_accuracy": QualityGate(
                gate_id="technical_accuracy",
                name="Technical Accuracy Gate",
                description="Ensures technical content meets accuracy standards",
                stage=WorkflowStage.TECHNICAL_REVIEW,
                required_score=80.0,
                automated=True,
                blocking=True
            ),
            "bias_threshold": QualityGate(
                gate_id="bias_threshold",
                name="Bias Assessment Gate",
                description="Ensures content meets bias neutrality standards",
                stage=WorkflowStage.BIAS_ASSESSMENT,
                required_score=70.0,
                automated=False,
                blocking=True
            ),
            "security_compliance": QualityGate(
                gate_id="security_compliance",
                name="Security Compliance Gate",
                description="Ensures security and compliance requirements are met",
                stage=WorkflowStage.SECURITY_REVIEW,
                required_score=85.0,
                automated=True,
                blocking=True
            ),
            "overall_quality": QualityGate(
                gate_id="overall_quality",
                name="Overall Quality Gate",
                description="Ensures overall content quality meets publication standards",
                stage=WorkflowStage.FINAL_APPROVAL,
                required_score=self.config["scoring"]["minimum_overall_score"],
                automated=False,
                blocking=True
            )
        }
        
        return gates
    
    def _load_active_workflows(self) -> Dict[str, WorkflowInstance]:
        """Load active workflow instances"""
        workflows_file = self.data_dir / "workflows.json"
        workflows = {}
        
        if workflows_file.exists():
            try:
                with open(workflows_file, 'r') as f:
                    data = json.load(f)
                    for workflow_data in data.get('workflows', []):
                        # Reconstruct workflow instance
                        workflow = WorkflowInstance(
                            instance_id=workflow_data['instance_id'],
                            content_id=workflow_data['content_id'],
                            content_path=workflow_data['content_path'],
                            author=workflow_data['author'],
                            current_stage=WorkflowStage(workflow_data['current_stage']),
                            stage_history=workflow_data.get('stage_history', []),
                            assignments=[],  # Will be reconstructed
                            created_date=workflow_data.get('created_date', datetime.now().isoformat()),
                            deadline=workflow_data.get('deadline'),
                            overall_score=workflow_data.get('overall_score'),
                            quality_gates_passed=workflow_data.get('quality_gates_passed', {}),
                            metadata=workflow_data.get('metadata', {}),
                            escalations=workflow_data.get('escalations', []),
                            audit_log=workflow_data.get('audit_log', [])
                        )
                        
                        # Reconstruct assignments
                        for assignment_data in workflow_data.get('assignments', []):
                            reviewer_id = assignment_data['reviewer']['user_id']
                            if reviewer_id in self.reviewers:
                                assignment = ReviewAssignment(
                                    assignment_id=assignment_data['assignment_id'],
                                    content_id=assignment_data['content_id'],
                                    reviewer=self.reviewers[reviewer_id],
                                    stage=WorkflowStage(assignment_data['stage']),
                                    role=ReviewerRole(assignment_data['role']),
                                    assigned_date=assignment_data['assigned_date'],
                                    due_date=assignment_data['due_date'],
                                    priority=NotificationPriority(assignment_data['priority']),
                                    completed=assignment_data.get('completed', False),
                                    completion_date=assignment_data.get('completion_date'),
                                    action=ReviewAction(assignment_data['action']) if assignment_data.get('action') else None,
                                    score=assignment_data.get('score'),
                                    comments=assignment_data.get('comments', []),
                                    criteria_scores=assignment_data.get('criteria_scores', {})
                                )
                                workflow.assignments.append(assignment)
                        
                        workflows[workflow.instance_id] = workflow
            except Exception as e:
                logger.error(f"Failed to load workflows: {e}")
        
        return workflows
    
    def _save_workflows(self):
        """Save workflow instances"""
        workflows_file = self.data_dir / "workflows.json"
        
        try:
            data = {"workflows": []}
            
            for workflow in self.workflows.values():
                workflow_data = asdict(workflow)
                
                # Convert enums to strings
                workflow_data["current_stage"] = workflow_data["current_stage"].value
                
                # Process assignments
                assignments_data = []
                for assignment in workflow.assignments:
                    assignment_data = asdict(assignment)
                    assignment_data["stage"] = assignment_data["stage"].value
                    assignment_data["role"] = assignment_data["role"].value
                    assignment_data["priority"] = assignment_data["priority"].value
                    if assignment_data["action"]:
                        assignment_data["action"] = assignment_data["action"].value
                    assignments_data.append(assignment_data)
                
                workflow_data["assignments"] = assignments_data
                data["workflows"].append(workflow_data)
            
            with open(workflows_file, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save workflows: {e}")
    
    def create_workflow(self, content_id: str, content_path: str, author: str, 
                       deadline: Optional[datetime] = None, metadata: Optional[Dict] = None) -> str:
        """
        Create a new workflow instance
        
        Args:
            content_id: Unique content identifier
            content_path: Path to content file
            author: Content author
            deadline: Optional workflow deadline
            metadata: Additional metadata
        
        Returns:
            Workflow instance ID
        """
        instance_id = f"wf-{content_id}-{datetime.now().strftime('%Y%m%d%H%M%S')}"
        
        # Calculate deadline if not provided
        if deadline is None:
            deadline = datetime.now() + timedelta(days=self.config["workflow"]["default_deadline_days"])
        
        workflow = WorkflowInstance(
            instance_id=instance_id,
            content_id=content_id,
            content_path=content_path,
            author=author,
            current_stage=WorkflowStage.DRAFT,
            deadline=deadline.isoformat(),
            metadata=metadata or {}
        )
        
        # Add to audit log
        self._add_audit_entry(workflow, "workflow_created", {"author": author, "deadline": deadline.isoformat()})
        
        self.workflows[instance_id] = workflow
        self._save_workflows()
        
        logger.info(f"Created workflow {instance_id} for content {content_id}")
        return instance_id
    
    def start_review_stage(self, instance_id: str, stage: WorkflowStage) -> bool:
        """
        Start a review stage for a workflow
        
        Args:
            instance_id: Workflow instance ID
            stage: Review stage to start
        
        Returns:
            Success status
        """
        if instance_id not in self.workflows:
            logger.error(f"Workflow {instance_id} not found")
            return False
        
        workflow = self.workflows[instance_id]
        stage_config = self.stages.get(stage)
        
        if not stage_config:
            logger.error(f"Stage configuration not found for {stage}")
            return False
        
        # Update workflow stage
        workflow.current_stage = stage
        
        # Record stage transition
        stage_entry = {
            "stage": stage.value,
            "started": datetime.now().isoformat(),
            "assignments": []
        }
        workflow.stage_history.append(stage_entry)
        
        # Create assignments for required roles
        assignments_created = []
        for role in stage_config.required_roles:
            assignment_id = self._create_assignment(workflow, stage, role, required=True)
            if assignment_id:
                assignments_created.append(assignment_id)
        
        # Create assignments for optional roles if auto-assignment is enabled
        if self.config["workflow"]["auto_assignment"]:
            for role in stage_config.optional_roles:
                assignment_id = self._create_assignment(workflow, stage, role, required=False)
                if assignment_id:
                    assignments_created.append(assignment_id)
        
        # Add to audit log
        self._add_audit_entry(workflow, "stage_started", {
            "stage": stage.value,
            "assignments_created": assignments_created
        })
        
        self._save_workflows()
        
        logger.info(f"Started {stage.value} stage for workflow {instance_id}")
        return True
    
    def _create_assignment(self, workflow: WorkflowInstance, stage: WorkflowStage, 
                          role: ReviewerRole, required: bool = True) -> Optional[str]:
        """Create a review assignment"""
        # Find available reviewer
        reviewer = self._find_best_reviewer(role, workflow.content_id, workflow.metadata)
        
        if not reviewer:
            if required:
                logger.error(f"No available reviewer found for required role {role}")
                # Could trigger escalation here
            return None
        
        # Calculate due date
        stage_config = self.stages[stage]
        due_date = datetime.now() + timedelta(hours=stage_config.maximum_duration_hours)
        
        assignment_id = f"as-{workflow.instance_id}-{stage.value}-{role.value}-{datetime.now().strftime('%H%M%S')}"
        
        assignment = ReviewAssignment(
            assignment_id=assignment_id,
            content_id=workflow.content_id,
            reviewer=reviewer,
            stage=stage,
            role=role,
            assigned_date=datetime.now().isoformat(),
            due_date=due_date.isoformat(),
            priority=NotificationPriority.NORMAL
        )
        
        workflow.assignments.append(assignment)
        
        # Update reviewer workload
        reviewer.current_assignments += 1
        
        # Send notification (would integrate with notification system)
        self._schedule_assignment_notification(assignment)
        
        logger.info(f"Created assignment {assignment_id} for reviewer {reviewer.name}")
        return assignment_id
    
    def _find_best_reviewer(self, role: ReviewerRole, content_id: str, metadata: Dict) -> Optional[Reviewer]:
        """Find the best available reviewer for a role"""
        eligible_reviewers = [
            reviewer for reviewer in self.reviewers.values()
            if role in reviewer.roles and reviewer.current_assignments < reviewer.workload_capacity
        ]
        
        if not eligible_reviewers:
            return None
        
        # Apply selection algorithm
        if self.config["assignment"]["expertise_matching"]:
            # Score reviewers based on expertise match
            content_areas = metadata.get("platforms", []) + metadata.get("tags", [])
            scored_reviewers = []
            
            for reviewer in eligible_reviewers:
                expertise_score = len(set(reviewer.expertise_areas) & set(content_areas))
                workload_score = (reviewer.workload_capacity - reviewer.current_assignments) / reviewer.workload_capacity
                total_score = expertise_score * 0.7 + workload_score * 0.3
                scored_reviewers.append((reviewer, total_score))
            
            # Sort by score and return best match
            scored_reviewers.sort(key=lambda x: x[1], reverse=True)
            return scored_reviewers[0][0]
        
        else:
            # Simple round-robin or load balancing
            if self.config["assignment"]["load_balancing"]:
                return min(eligible_reviewers, key=lambda r: r.current_assignments)
            else:
                return eligible_reviewers[0]
    
    def submit_review(self, assignment_id: str, action: ReviewAction, score: Optional[float] = None,
                     criteria_scores: Optional[Dict[str, float]] = None, 
                     comments: Optional[List[str]] = None) -> bool:
        """
        Submit a review for an assignment
        
        Args:
            assignment_id: Assignment ID
            action: Review action taken
            score: Overall score (if applicable)
            criteria_scores: Scores for individual criteria
            comments: Review comments
        
        Returns:
            Success status
        """
        # Find assignment
        assignment = None
        workflow = None
        
        for wf in self.workflows.values():
            for assign in wf.assignments:
                if assign.assignment_id == assignment_id:
                    assignment = assign
                    workflow = wf
                    break
            if assignment:
                break
        
        if not assignment or not workflow:
            logger.error(f"Assignment {assignment_id} not found")
            return False
        
        if assignment.completed:
            logger.warning(f"Assignment {assignment_id} already completed")
            return False
        
        # Update assignment
        assignment.completed = True
        assignment.completion_date = datetime.now().isoformat()
        assignment.action = action
        assignment.score = score
        assignment.criteria_scores = criteria_scores or {}
        assignment.comments = comments or []
        
        # Update reviewer workload
        assignment.reviewer.current_assignments -= 1
        
        # Add to audit log
        self._add_audit_entry(workflow, "review_submitted", {
            "assignment_id": assignment_id,
            "reviewer": assignment.reviewer.user_id,
            "action": action.value,
            "score": score
        })
        
        # Check if stage can advance
        if self._check_stage_completion(workflow):
            next_stage = self._get_next_stage(workflow.current_stage)
            if next_stage:
                self.start_review_stage(workflow.instance_id, next_stage)
            else:
                # Workflow complete
                workflow.current_stage = WorkflowStage.PUBLISHED
                self._add_audit_entry(workflow, "workflow_completed", {})
        
        self._save_workflows()
        self._save_reviewers()
        
        logger.info(f"Review submitted for assignment {assignment_id}: {action.value}")
        return True
    
    def _check_stage_completion(self, workflow: WorkflowInstance) -> bool:
        """Check if current stage is complete and can advance"""
        stage_config = self.stages.get(workflow.current_stage)
        if not stage_config:
            return False
        
        # Get assignments for current stage
        current_assignments = [
            a for a in workflow.assignments 
            if a.stage == workflow.current_stage and not a.completed
        ]
        
        # Check if minimum approvals are met
        completed_approvals = [
            a for a in workflow.assignments
            if a.stage == workflow.current_stage and a.completed and a.action == ReviewAction.APPROVE
        ]
        
        if len(completed_approvals) < stage_config.minimum_approvals:
            return False
        
        # Check for blocking rejections
        rejections = [
            a for a in workflow.assignments
            if a.stage == workflow.current_stage and a.completed and a.action == ReviewAction.REJECT
        ]
        
        if rejections:
            # Handle rejection - could trigger revision workflow
            workflow.current_stage = WorkflowStage.REJECTED
            return False
        
        # Check quality gates
        if not self._check_quality_gates(workflow):
            return False
        
        # Check if auto-advance threshold is met
        if stage_config.auto_advance_threshold:
            stage_scores = [a.score for a in completed_approvals if a.score is not None]
            if stage_scores:
                avg_score = sum(stage_scores) / len(stage_scores)
                if avg_score < stage_config.auto_advance_threshold:
                    return False
        
        return True
    
    def _check_quality_gates(self, workflow: WorkflowInstance) -> bool:
        """Check quality gates for current stage"""
        if not self.config["workflow"]["quality_gate_enforcement"]:
            return True
        
        stage_gates = [gate for gate in self.quality_gates.values() if gate.stage == workflow.current_stage]
        
        for gate in stage_gates:
            if gate.blocking:
                # Check if gate has passed
                gate_passed = workflow.quality_gates_passed.get(gate.gate_id, False)
                
                if gate.automated and gate.check_function:
                    # Run automated check
                    try:
                        gate_passed = gate.check_function(workflow)
                        workflow.quality_gates_passed[gate.gate_id] = gate_passed
                    except Exception as e:
                        logger.error(f"Quality gate check failed for {gate.gate_id}: {e}")
                        gate_passed = False
                
                if not gate_passed:
                    logger.warning(f"Quality gate {gate.gate_id} not passed for workflow {workflow.instance_id}")
                    return False
        
        return True
    
    def _get_next_stage(self, current_stage: WorkflowStage) -> Optional[WorkflowStage]:
        """Get next stage in workflow progression"""
        stage_progression = [
            WorkflowStage.DRAFT,
            WorkflowStage.TECHNICAL_REVIEW,
            WorkflowStage.EDUCATIONAL_REVIEW,
            WorkflowStage.BIAS_ASSESSMENT,
            WorkflowStage.SECURITY_REVIEW,
            WorkflowStage.FINAL_APPROVAL,
            WorkflowStage.PUBLISHED
        ]
        
        try:
            current_index = stage_progression.index(current_stage)
            if current_index < len(stage_progression) - 1:
                return stage_progression[current_index + 1]
        except ValueError:
            pass
        
        return None
    
    def _add_audit_entry(self, workflow: WorkflowInstance, action: str, details: Dict[str, Any]):
        """Add entry to workflow audit log"""
        entry = {
            "timestamp": datetime.now().isoformat(),
            "action": action,
            "details": details
        }
        workflow.audit_log.append(entry)
    
    def _schedule_assignment_notification(self, assignment: ReviewAssignment):
        """Schedule notifications for assignment (placeholder)"""
        # This would integrate with the notification system
        logger.info(f"Notification scheduled for assignment {assignment.assignment_id}")
    
    def get_workflow_status(self, instance_id: str) -> Optional[Dict[str, Any]]:
        """Get comprehensive workflow status"""
        if instance_id not in self.workflows:
            return None
        
        workflow = self.workflows[instance_id]
        
        # Calculate progress
        total_stages = len([s for s in WorkflowStage if s not in [WorkflowStage.DRAFT, WorkflowStage.PUBLISHED, WorkflowStage.REJECTED, WorkflowStage.ARCHIVED]])
        completed_stages = len(workflow.stage_history)
        progress_percentage = (completed_stages / total_stages) * 100 if total_stages > 0 else 0
        
        # Get current assignments
        current_assignments = [
            {
                "assignment_id": a.assignment_id,
                "reviewer": a.reviewer.name,
                "role": a.role.value,
                "due_date": a.due_date,
                "completed": a.completed
            }
            for a in workflow.assignments if a.stage == workflow.current_stage
        ]
        
        # Calculate overall score
        all_scores = [a.score for a in workflow.assignments if a.completed and a.score is not None]
        overall_score = sum(all_scores) / len(all_scores) if all_scores else None
        
        status = {
            "instance_id": workflow.instance_id,
            "content_id": workflow.content_id,
            "content_path": workflow.content_path,
            "author": workflow.author,
            "current_stage": workflow.current_stage.value,
            "progress_percentage": progress_percentage,
            "overall_score": overall_score,
            "created_date": workflow.created_date,
            "deadline": workflow.deadline,
            "current_assignments": current_assignments,
            "quality_gates_passed": workflow.quality_gates_passed,
            "total_assignments": len(workflow.assignments),
            "completed_assignments": len([a for a in workflow.assignments if a.completed]),
            "stage_history": workflow.stage_history,
            "escalations": workflow.escalations
        }
        
        return status
    
    def list_active_workflows(self, author: Optional[str] = None, 
                             stage: Optional[WorkflowStage] = None) -> List[Dict[str, Any]]:
        """List active workflows with optional filtering"""
        workflows = []
        
        for workflow in self.workflows.values():
            if workflow.current_stage in [WorkflowStage.PUBLISHED, WorkflowStage.ARCHIVED]:
                continue
            
            if author and workflow.author != author:
                continue
            
            if stage and workflow.current_stage != stage:
                continue
            
            status = self.get_workflow_status(workflow.instance_id)
            if status:
                workflows.append(status)
        
        # Sort by creation date
        workflows.sort(key=lambda w: w["created_date"], reverse=True)
        return workflows
    
    def get_reviewer_workload(self, reviewer_id: Optional[str] = None) -> Dict[str, Any]:
        """Get reviewer workload information"""
        if reviewer_id:
            if reviewer_id not in self.reviewers:
                return {}
            
            reviewer = self.reviewers[reviewer_id]
            assignments = [
                a for workflow in self.workflows.values()
                for a in workflow.assignments
                if a.reviewer.user_id == reviewer_id and not a.completed
            ]
            
            return {
                "reviewer": {
                    "user_id": reviewer.user_id,
                    "name": reviewer.name,
                    "roles": [role.value for role in reviewer.roles]
                },
                "current_assignments": len(assignments),
                "capacity": reviewer.workload_capacity,
                "utilization": len(assignments) / reviewer.workload_capacity if reviewer.workload_capacity > 0 else 0,
                "assignments": [
                    {
                        "assignment_id": a.assignment_id,
                        "content_id": a.content_id,
                        "stage": a.stage.value,
                        "due_date": a.due_date,
                        "priority": a.priority.value
                    }
                    for a in assignments
                ]
            }
        else:
            # Return all reviewers' workload
            workloads = {}
            for reviewer_id in self.reviewers:
                workloads[reviewer_id] = self.get_reviewer_workload(reviewer_id)
            return workloads
    
    def escalate_assignment(self, assignment_id: str, reason: str) -> bool:
        """Escalate an overdue or problematic assignment"""
        # Find assignment and workflow
        assignment = None
        workflow = None
        
        for wf in self.workflows.values():
            for assign in wf.assignments:
                if assign.assignment_id == assignment_id:
                    assignment = assign
                    workflow = wf
                    break
            if assignment:
                break
        
        if not assignment or not workflow:
            return False
        
        escalation = {
            "timestamp": datetime.now().isoformat(),
            "assignment_id": assignment_id,
            "reason": reason,
            "original_reviewer": assignment.reviewer.user_id,
            "escalated_to": None  # Would be filled by escalation logic
        }
        
        workflow.escalations.append(escalation)
        
        # Add to audit log
        self._add_audit_entry(workflow, "assignment_escalated", escalation)
        
        # Could implement automatic reassignment or manager notification here
        
        self._save_workflows()
        logger.info(f"Assignment {assignment_id} escalated: {reason}")
        return True
    
    def generate_workflow_report(self, start_date: Optional[str] = None, 
                               end_date: Optional[str] = None) -> Dict[str, Any]:
        """Generate comprehensive workflow report"""
        report = {
            "generated": datetime.now().isoformat(),
            "period": {
                "start": start_date,
                "end": end_date
            },
            "summary": {
                "total_workflows": len(self.workflows),
                "active_workflows": len([w for w in self.workflows.values() if w.current_stage not in [WorkflowStage.PUBLISHED, WorkflowStage.ARCHIVED]]),
                "completed_workflows": len([w for w in self.workflows.values() if w.current_stage == WorkflowStage.PUBLISHED]),
                "rejected_workflows": len([w for w in self.workflows.values() if w.current_stage == WorkflowStage.REJECTED]),
            },
            "stage_distribution": {},
            "reviewer_performance": {},
            "quality_metrics": {
                "average_overall_score": 0.0,
                "quality_gate_pass_rate": {},
                "stage_completion_times": {}
            },
            "escalations": {
                "total": sum(len(w.escalations) for w in self.workflows.values()),
                "by_reason": defaultdict(int)
            }
        }
        
        # Calculate stage distribution
        for workflow in self.workflows.values():
            stage = workflow.current_stage.value
            report["stage_distribution"][stage] = report["stage_distribution"].get(stage, 0) + 1
        
        # Calculate reviewer performance
        for reviewer_id, reviewer in self.reviewers.items():
            completed_reviews = []
            for workflow in self.workflows.values():
                for assignment in workflow.assignments:
                    if assignment.reviewer.user_id == reviewer_id and assignment.completed:
                        completed_reviews.append(assignment)
            
            if completed_reviews:
                avg_score = sum(a.score for a in completed_reviews if a.score) / len([a for a in completed_reviews if a.score])
                
                report["reviewer_performance"][reviewer_id] = {
                    "name": reviewer.name,
                    "completed_reviews": len(completed_reviews),
                    "average_score": avg_score,
                    "approval_rate": len([a for a in completed_reviews if a.action == ReviewAction.APPROVE]) / len(completed_reviews)
                }
        
        # Calculate quality metrics
        all_scores = []
        for workflow in self.workflows.values():
            for assignment in workflow.assignments:
                if assignment.completed and assignment.score:
                    all_scores.append(assignment.score)
        
        if all_scores:
            report["quality_metrics"]["average_overall_score"] = sum(all_scores) / len(all_scores)
        
        # Quality gate pass rates
        for gate_id in self.quality_gates:
            total_workflows = len(self.workflows)
            passed_workflows = len([w for w in self.workflows.values() if w.quality_gates_passed.get(gate_id, False)])
            report["quality_metrics"]["quality_gate_pass_rate"][gate_id] = passed_workflows / total_workflows if total_workflows > 0 else 0
        
        return report

    def add_reviewer(self, user_id: str, name: str, email: str, roles: List[ReviewerRole],
                    expertise_areas: List[str] = None, workload_capacity: int = 5) -> bool:
        """Add a new reviewer to the system"""
        if user_id in self.reviewers:
            logger.warning(f"Reviewer {user_id} already exists")
            return False
        
        reviewer = Reviewer(
            user_id=user_id,
            name=name,
            email=email,
            roles=roles,
            expertise_areas=expertise_areas or [],
            workload_capacity=workload_capacity,
            notification_preferences={
                "assignment": True,
                "reminder": True,
                "escalation": True
            }
        )
        
        self.reviewers[user_id] = reviewer
        self._save_reviewers()
        
        logger.info(f"Added reviewer {name} ({user_id})")
        return True
    
    def update_reviewer(self, user_id: str, **kwargs) -> bool:
        """Update reviewer information"""
        if user_id not in self.reviewers:
            logger.error(f"Reviewer {user_id} not found")
            return False
        
        reviewer = self.reviewers[user_id]
        
        for field, value in kwargs.items():
            if hasattr(reviewer, field):
                setattr(reviewer, field, value)
        
        reviewer.last_active = datetime.now().isoformat()
        self._save_reviewers()
        
        logger.info(f"Updated reviewer {user_id}")
        return True


def main():
    """Main function for CLI usage"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Content Review Workflow Orchestrator")
    parser.add_argument("--config", required=True, help="Configuration file path")
    parser.add_argument("--repo", default=".", help="Repository path")
    parser.add_argument("--command", required=True,
                       choices=["create", "start", "submit", "status", "list", "report"],
                       help="Command to execute")
    
    # Command-specific arguments
    parser.add_argument("--content-id", help="Content ID")
    parser.add_argument("--content-path", help="Path to content file")
    parser.add_argument("--author", help="Content author")
    parser.add_argument("--instance-id", help="Workflow instance ID")
    parser.add_argument("--stage", help="Workflow stage")
    parser.add_argument("--assignment-id", help="Assignment ID")
    parser.add_argument("--action", help="Review action")
    parser.add_argument("--score", type=float, help="Review score")
    parser.add_argument("--output", help="Output file path")
    
    args = parser.parse_args()
    
    try:
        orchestrator = WorkflowOrchestrator(args.config, args.repo)
        
        if args.command == "create":
            if not all([args.content_id, args.content_path, args.author]):
                print("Error: content-id, content-path, and author are required for create command")
                return
            
            instance_id = orchestrator.create_workflow(args.content_id, args.content_path, args.author)
            print(f"Created workflow: {instance_id}")
        
        elif args.command == "start":
            if not all([args.instance_id, args.stage]):
                print("Error: instance-id and stage are required for start command")
                return
            
            stage = WorkflowStage(args.stage)
            success = orchestrator.start_review_stage(args.instance_id, stage)
            print(f"Started stage {args.stage}: {'Success' if success else 'Failed'}")
        
        elif args.command == "submit":
            if not all([args.assignment_id, args.action]):
                print("Error: assignment-id and action are required for submit command")
                return
            
            action = ReviewAction(args.action)
            success = orchestrator.submit_review(args.assignment_id, action, args.score)
            print(f"Submitted review: {'Success' if success else 'Failed'}")
        
        elif args.command == "status":
            if args.instance_id:
                status = orchestrator.get_workflow_status(args.instance_id)
                if status:
                    print(json.dumps(status, indent=2))
                else:
                    print(f"Workflow {args.instance_id} not found")
            else:
                print("Error: instance-id is required for status command")
        
        elif args.command == "list":
            workflows = orchestrator.list_active_workflows()
            print(f"Found {len(workflows)} active workflows:")
            for workflow in workflows:
                print(f"  {workflow['instance_id']}: {workflow['content_id']} ({workflow['current_stage']})")
        
        elif args.command == "report":
            report = orchestrator.generate_workflow_report()
            
            if args.output:
                with open(args.output, 'w') as f:
                    json.dump(report, f, indent=2)
                print(f"Report saved to {args.output}")
            else:
                print(json.dumps(report, indent=2))
    
    except Exception as e:
        logger.error(f"Command failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()