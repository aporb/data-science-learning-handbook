"""
Remediation Workflow Engine
===========================

Advanced workflow automation engine that orchestrates the complete vulnerability
remediation lifecycle from discovery to verification and closure.

Features:
- Automated remediation task generation and assignment
- SLA-based tracking and escalation procedures
- Integration with external ticketing and ITSM systems
- Real-time workflow monitoring and reporting
- Remediation verification and validation
- Audit trail generation for all activities
- Role-based access control and approval workflows
"""

import asyncio
import json
import logging
import sqlite3
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Callable, Set
from dataclasses import dataclass, field
from pathlib import Path
from enum import Enum
from uuid import uuid4
import hashlib

logger = logging.getLogger(__name__)

class WorkflowStatus(Enum):
    """Workflow status enumeration"""
    PENDING = "pending"
    ACTIVE = "active"
    IN_PROGRESS = "in_progress"
    WAITING_APPROVAL = "waiting_approval"
    ON_HOLD = "on_hold"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    FAILED = "failed"

class TaskType(Enum):
    """Remediation task types"""
    PATCH_DEPLOYMENT = "patch_deployment"
    CONFIGURATION_CHANGE = "configuration_change"
    SYSTEM_UPDATE = "system_update"
    ACCESS_CONTROL_UPDATE = "access_control_update"
    SECURITY_CONTROL_IMPLEMENTATION = "security_control_implementation"
    VULNERABILITY_MITIGATION = "vulnerability_mitigation"
    VERIFICATION_TASK = "verification_task"
    DOCUMENTATION_UPDATE = "documentation_update"
    APPROVAL_TASK = "approval_task"
    CUSTOM_TASK = "custom_task"

class TaskPriority(Enum):
    """Task priority levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

class TaskStatus(Enum):
    """Individual task status"""
    CREATED = "created"
    ASSIGNED = "assigned"
    IN_PROGRESS = "in_progress"
    WAITING_APPROVAL = "waiting_approval"
    BLOCKED = "blocked"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

@dataclass
class RemediationTask:
    """Individual remediation task"""
    task_id: str
    workflow_id: str
    task_type: TaskType
    title: str
    description: str
    priority: TaskPriority
    status: TaskStatus
    assigned_to: Optional[str] = None
    assigned_team: Optional[str] = None
    created_by: str = "system"
    estimated_effort: Optional[str] = None
    due_date: Optional[datetime] = None
    dependencies: List[str] = field(default_factory=list)
    prerequisites: List[str] = field(default_factory=list)
    verification_criteria: List[str] = field(default_factory=list)
    approval_required: bool = False
    approvers: List[str] = field(default_factory=list)
    automation_script: Optional[str] = None
    rollback_plan: Optional[str] = None
    risk_assessment: Optional[str] = None
    change_window: Optional[Dict[str, Any]] = None
    notifications: List[str] = field(default_factory=list)
    attachments: List[str] = field(default_factory=list)
    progress_notes: List[Dict[str, Any]] = field(default_factory=list)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class RemediationWorkflow:
    """Complete remediation workflow"""
    workflow_id: str
    vulnerability_id: str
    workflow_name: str
    workflow_type: str
    status: WorkflowStatus
    priority: TaskPriority
    created_by: str
    assigned_team: Optional[str] = None
    estimated_completion: Optional[datetime] = None
    actual_completion: Optional[datetime] = None
    tasks: List[RemediationTask] = field(default_factory=list)
    sla_requirements: Dict[str, Any] = field(default_factory=dict)
    business_justification: str = ""
    risk_acceptance_criteria: str = ""
    success_criteria: List[str] = field(default_factory=list)
    escalation_rules: List[Dict[str, Any]] = field(default_factory=list)
    approval_workflow: Optional[Dict[str, Any]] = None
    integration_config: Dict[str, Any] = field(default_factory=dict)
    audit_trail: List[Dict[str, Any]] = field(default_factory=list)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: Dict[str, Any] = field(default_factory=dict)

class RemediationWorkflowEngine:
    """
    Advanced remediation workflow orchestration engine
    
    Manages the complete vulnerability remediation lifecycle with automated
    task generation, assignment, tracking, and verification capabilities.
    """
    
    def __init__(self, db_path: str = "remediation_workflows.db"):
        self.db_path = Path(db_path)
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        
        # Initialize database
        self._initialize_database()
        
        # Workflow components
        self.task_generator = None      # TaskGenerator instance
        self.assignment_engine = None   # AssignmentEngine instance
        self.workflow_tracker = None    # WorkflowTracker instance
        self.sla_monitor = None        # SLAMonitor instance
        self.verification_engine = None # VerificationEngine instance
        self.integration_manager = None # IntegrationManager instance
        self.notification_service = None # NotificationService instance
        
        # Workflow templates and rules
        self.workflow_templates = {}
        self.assignment_rules = {}
        self.sla_policies = {}
        self.escalation_rules = {}
        
        # Active workflows and tasks
        self.active_workflows: Dict[str, RemediationWorkflow] = {}
        self.active_tasks: Dict[str, RemediationTask] = {}
        
        # Background processing
        self.running = False
        self.background_tasks = []
        
        # Event handlers
        self.event_handlers: Dict[str, List[Callable]] = {
            'workflow_created': [],
            'workflow_started': [],
            'workflow_completed': [],
            'task_created': [],
            'task_assigned': [],
            'task_completed': [],
            'sla_breach': [],
            'escalation_triggered': []
        }
    
    def _initialize_database(self):
        """Initialize remediation workflow database"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS remediation_workflows (
                    workflow_id TEXT PRIMARY KEY,
                    vulnerability_id TEXT NOT NULL,
                    workflow_name TEXT NOT NULL,
                    workflow_type TEXT,
                    status TEXT NOT NULL,
                    priority TEXT,
                    created_by TEXT,
                    assigned_team TEXT,
                    estimated_completion TEXT,
                    actual_completion TEXT,
                    sla_requirements TEXT,  -- JSON
                    business_justification TEXT,
                    risk_acceptance_criteria TEXT,
                    success_criteria TEXT,  -- JSON
                    escalation_rules TEXT,  -- JSON
                    approval_workflow TEXT, -- JSON
                    integration_config TEXT, -- JSON
                    audit_trail TEXT,       -- JSON
                    created_at TEXT,
                    updated_at TEXT,
                    metadata TEXT           -- JSON
                )
            """)
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS remediation_tasks (
                    task_id TEXT PRIMARY KEY,
                    workflow_id TEXT NOT NULL,
                    task_type TEXT NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT,
                    priority TEXT,
                    status TEXT NOT NULL,
                    assigned_to TEXT,
                    assigned_team TEXT,
                    created_by TEXT,
                    estimated_effort TEXT,
                    due_date TEXT,
                    dependencies TEXT,      -- JSON array
                    prerequisites TEXT,     -- JSON array
                    verification_criteria TEXT, -- JSON array
                    approval_required BOOLEAN,
                    approvers TEXT,         -- JSON array
                    automation_script TEXT,
                    rollback_plan TEXT,
                    risk_assessment TEXT,
                    change_window TEXT,     -- JSON
                    notifications TEXT,     -- JSON array
                    attachments TEXT,       -- JSON array
                    progress_notes TEXT,    -- JSON array
                    created_at TEXT,
                    updated_at TEXT,
                    metadata TEXT,          -- JSON
                    FOREIGN KEY (workflow_id) REFERENCES remediation_workflows (workflow_id)
                )
            """)
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS workflow_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    workflow_id TEXT NOT NULL,
                    task_id TEXT,
                    event_type TEXT NOT NULL,
                    event_data TEXT,        -- JSON
                    user_id TEXT,
                    timestamp TEXT NOT NULL,
                    created_at TEXT
                )
            """)
            
            # Create indexes
            conn.execute("CREATE INDEX IF NOT EXISTS idx_workflow_status ON remediation_workflows(status)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_workflow_priority ON remediation_workflows(priority)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_workflow_vuln ON remediation_workflows(vulnerability_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_task_status ON remediation_tasks(status)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_task_assigned ON remediation_tasks(assigned_to)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_task_workflow ON remediation_tasks(workflow_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_events_workflow ON workflow_events(workflow_id)")
    
    async def start(self):
        """Start the remediation workflow engine"""
        if self.running:
            return
        
        self.running = True
        
        # Load active workflows and tasks
        await self._load_active_workflows()
        
        # Start background monitoring tasks
        self.background_tasks = [
            asyncio.create_task(self._sla_monitoring_loop()),
            asyncio.create_task(self._workflow_processing_loop()),
            asyncio.create_task(self._notification_processing_loop())
        ]
        
        self.logger.info("Started remediation workflow engine")
    
    async def stop(self):
        """Stop the remediation workflow engine"""
        if not self.running:
            return
        
        self.running = False
        
        # Cancel background tasks
        for task in self.background_tasks:
            task.cancel()
        
        # Wait for tasks to complete
        if self.background_tasks:
            await asyncio.gather(*self.background_tasks, return_exceptions=True)
        
        self.logger.info("Stopped remediation workflow engine")
    
    async def create_remediation_workflow(self,
                                        vulnerability_id: str,
                                        risk_assessment: Dict[str, Any],
                                        workflow_template: Optional[str] = None,
                                        custom_config: Optional[Dict[str, Any]] = None) -> RemediationWorkflow:
        """Create a new remediation workflow for a vulnerability"""
        
        workflow_id = str(uuid4())
        
        try:
            # Determine workflow type and priority from risk assessment
            risk_level = risk_assessment.get('risk_level', 'medium')
            priority = TaskPriority(risk_level.lower()) if risk_level.lower() in [p.value for p in TaskPriority] else TaskPriority.MEDIUM
            
            # Generate workflow name
            vuln_title = risk_assessment.get('vulnerability_data', {}).get('title', f'Vulnerability {vulnerability_id[:8]}')
            workflow_name = f"Remediate: {vuln_title}"
            
            # Create workflow
            workflow = RemediationWorkflow(
                workflow_id=workflow_id,
                vulnerability_id=vulnerability_id,
                workflow_name=workflow_name,
                workflow_type=workflow_template or "standard_remediation",
                status=WorkflowStatus.PENDING,
                priority=priority,
                created_by="system",
                business_justification=risk_assessment.get('business_justification', ''),
                risk_acceptance_criteria=f"Risk level: {risk_level}",
                sla_requirements=await self._generate_sla_requirements(risk_level),
                success_criteria=await self._generate_success_criteria(risk_assessment),
                escalation_rules=await self._generate_escalation_rules(risk_level),
                metadata={
                    'risk_assessment': risk_assessment,
                    'custom_config': custom_config or {}
                }
            )
            
            # Generate remediation tasks
            if self.task_generator:
                tasks = await self.task_generator.generate_tasks(workflow, risk_assessment)
                workflow.tasks = tasks
            else:
                # Fallback task generation
                workflow.tasks = await self._generate_basic_tasks(workflow, risk_assessment)
            
            # Save workflow
            await self._save_workflow(workflow)
            
            # Add to active workflows
            self.active_workflows[workflow_id] = workflow
            
            # Log event
            await self._log_workflow_event(workflow_id, 'workflow_created', {
                'vulnerability_id': vulnerability_id,
                'workflow_name': workflow_name,
                'task_count': len(workflow.tasks)
            })
            
            # Trigger event handlers
            await self._trigger_event('workflow_created', workflow)
            
            self.logger.info(f"Created remediation workflow {workflow_id} for vulnerability {vulnerability_id}")
            
            return workflow
            
        except Exception as e:
            self.logger.error(f"Failed to create remediation workflow for {vulnerability_id}: {e}")
            raise
    
    async def start_workflow(self, workflow_id: str, assigned_team: Optional[str] = None) -> bool:
        """Start execution of a remediation workflow"""
        
        try:
            workflow = await self._get_workflow(workflow_id)
            if not workflow:
                raise ValueError(f"Workflow {workflow_id} not found")
            
            if workflow.status != WorkflowStatus.PENDING:
                raise ValueError(f"Workflow {workflow_id} is not in pending status")
            
            # Update workflow status
            workflow.status = WorkflowStatus.ACTIVE
            workflow.assigned_team = assigned_team
            workflow.updated_at = datetime.now(timezone.utc)
            
            # Start initial tasks (those without dependencies)
            for task in workflow.tasks:
                if not task.dependencies:
                    await self._start_task(task)
            
            # Save workflow
            await self._save_workflow(workflow)
            
            # Log event
            await self._log_workflow_event(workflow_id, 'workflow_started', {
                'assigned_team': assigned_team,
                'active_tasks': len([t for t in workflow.tasks if t.status == TaskStatus.IN_PROGRESS])
            })
            
            # Trigger event handlers
            await self._trigger_event('workflow_started', workflow)
            
            self.logger.info(f"Started workflow {workflow_id}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to start workflow {workflow_id}: {e}")
            return False
    
    async def complete_task(self, 
                          task_id: str, 
                          completion_notes: str = "",
                          completed_by: Optional[str] = None) -> bool:
        """Mark a task as completed"""
        
        try:
            task = await self._get_task(task_id)
            if not task:
                raise ValueError(f"Task {task_id} not found")
            
            # Update task status
            task.status = TaskStatus.COMPLETED
            task.updated_at = datetime.now(timezone.utc)
            
            # Add completion notes
            if completion_notes:
                task.progress_notes.append({
                    'timestamp': datetime.now(timezone.utc).isoformat(),
                    'type': 'completion',
                    'user': completed_by or 'system',
                    'note': completion_notes
                })
            
            # Save task
            await self._save_task(task)
            
            # Check if verification is required
            if task.verification_criteria and self.verification_engine:
                await self.verification_engine.schedule_verification(task)
            
            # Check for dependent tasks to start
            workflow = await self._get_workflow(task.workflow_id)
            if workflow:
                await self._check_dependent_tasks(workflow, task_id)
                await self._check_workflow_completion(workflow)
            
            # Log event
            await self._log_workflow_event(task.workflow_id, 'task_completed', {
                'task_id': task_id,
                'task_title': task.title,
                'completed_by': completed_by
            }, task_id=task_id)
            
            # Trigger event handlers
            await self._trigger_event('task_completed', task)
            
            self.logger.info(f"Completed task {task_id}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to complete task {task_id}: {e}")
            return False
    
    async def _generate_basic_tasks(self, workflow: RemediationWorkflow, risk_assessment: Dict[str, Any]) -> List[RemediationTask]:
        """Generate basic remediation tasks (fallback implementation)"""
        
        tasks = []
        vuln_data = risk_assessment.get('vulnerability_data', {})
        severity = vuln_data.get('severity', 'medium')
        
        # Analysis task
        analysis_task = RemediationTask(
            task_id=str(uuid4()),
            workflow_id=workflow.workflow_id,
            task_type=TaskType.VULNERABILITY_MITIGATION,
            title="Analyze Vulnerability",
            description=f"Analyze vulnerability {vuln_data.get('title', 'Unknown')} and determine remediation approach",
            priority=workflow.priority,
            status=TaskStatus.CREATED,
            estimated_effort="2-4 hours",
            verification_criteria=["Analysis documented", "Remediation plan approved"],
            approval_required=severity in ['critical', 'high']
        )
        tasks.append(analysis_task)
        
        # Remediation task
        remediation_task = RemediationTask(
            task_id=str(uuid4()),
            workflow_id=workflow.workflow_id,
            task_type=TaskType.PATCH_DEPLOYMENT,
            title="Apply Remediation",
            description="Apply the approved remediation solution",
            priority=workflow.priority,
            status=TaskStatus.CREATED,
            dependencies=[analysis_task.task_id],
            estimated_effort="4-8 hours",
            verification_criteria=["Remediation applied successfully", "System functionality verified"],
            rollback_plan="Rollback procedures documented in change management system"
        )
        tasks.append(remediation_task)
        
        # Verification task
        verification_task = RemediationTask(
            task_id=str(uuid4()),
            workflow_id=workflow.workflow_id,
            task_type=TaskType.VERIFICATION_TASK,
            title="Verify Remediation",
            description="Verify that the vulnerability has been successfully remediated",
            priority=workflow.priority,
            status=TaskStatus.CREATED,
            dependencies=[remediation_task.task_id],
            estimated_effort="1-2 hours",
            verification_criteria=["Vulnerability scan shows resolved", "Security controls verified"]
        )
        tasks.append(verification_task)
        
        return tasks
    
    async def _generate_sla_requirements(self, risk_level: str) -> Dict[str, Any]:
        """Generate SLA requirements based on risk level"""
        
        sla_mapping = {
            'critical': {'resolution_time': 24, 'response_time': 2},  # hours
            'high': {'resolution_time': 72, 'response_time': 8},
            'medium': {'resolution_time': 168, 'response_time': 24},  # 1 week
            'low': {'resolution_time': 720, 'response_time': 72}      # 30 days
        }
        
        return sla_mapping.get(risk_level, sla_mapping['medium'])
    
    async def _generate_success_criteria(self, risk_assessment: Dict[str, Any]) -> List[str]:
        """Generate success criteria for workflow"""
        
        criteria = [
            "Vulnerability successfully remediated",
            "No negative impact on system functionality",
            "Security controls verified and operational"
        ]
        
        # Add risk-specific criteria
        risk_level = risk_assessment.get('risk_level', 'medium')
        if risk_level in ['critical', 'high']:
            criteria.append("Independent security verification completed")
            criteria.append("Management approval for closure obtained")
        
        return criteria
    
    async def _generate_escalation_rules(self, risk_level: str) -> List[Dict[str, Any]]:
        """Generate escalation rules based on risk level"""
        
        base_rules = [
            {
                'trigger': 'sla_breach_50',
                'action': 'notify_manager',
                'delay_hours': 0
            },
            {
                'trigger': 'sla_breach_75',
                'action': 'escalate_to_senior_management',
                'delay_hours': 2
            }
        ]
        
        if risk_level in ['critical', 'high']:
            base_rules.insert(0, {
                'trigger': 'sla_breach_25',
                'action': 'notify_security_team',
                'delay_hours': 0
            })
        
        return base_rules
    
    async def _start_task(self, task: RemediationTask):
        """Start execution of a task"""
        
        # Check if task can be started (dependencies met)
        if not await self._dependencies_met(task):
            return
        
        # Assign task if assignment engine is available
        if self.assignment_engine:
            await self.assignment_engine.assign_task(task)
        
        # Update task status
        task.status = TaskStatus.IN_PROGRESS
        task.updated_at = datetime.now(timezone.utc)
        
        # Add to active tasks
        self.active_tasks[task.task_id] = task
        
        # Save task
        await self._save_task(task)
        
        # Send notifications
        if self.notification_service:
            await self.notification_service.notify_task_assigned(task)
    
    async def _dependencies_met(self, task: RemediationTask) -> bool:
        """Check if task dependencies are met"""
        
        if not task.dependencies:
            return True
        
        for dep_task_id in task.dependencies:
            dep_task = await self._get_task(dep_task_id)
            if not dep_task or dep_task.status != TaskStatus.COMPLETED:
                return False
        
        return True
    
    async def _check_dependent_tasks(self, workflow: RemediationWorkflow, completed_task_id: str):
        """Check for dependent tasks that can now be started"""
        
        for task in workflow.tasks:
            if (task.status == TaskStatus.CREATED and 
                completed_task_id in task.dependencies and
                await self._dependencies_met(task)):
                await self._start_task(task)
    
    async def _check_workflow_completion(self, workflow: RemediationWorkflow):
        """Check if workflow is complete"""
        
        # Check if all tasks are completed
        all_completed = all(task.status == TaskStatus.COMPLETED for task in workflow.tasks)
        
        if all_completed and workflow.status == WorkflowStatus.ACTIVE:
            workflow.status = WorkflowStatus.COMPLETED
            workflow.actual_completion = datetime.now(timezone.utc)
            workflow.updated_at = datetime.now(timezone.utc)
            
            # Save workflow
            await self._save_workflow(workflow)
            
            # Remove from active workflows
            self.active_workflows.pop(workflow.workflow_id, None)
            
            # Log event
            await self._log_workflow_event(workflow.workflow_id, 'workflow_completed', {
                'completion_time': workflow.actual_completion.isoformat(),
                'total_tasks': len(workflow.tasks)
            })
            
            # Trigger event handlers
            await self._trigger_event('workflow_completed', workflow)
            
            self.logger.info(f"Workflow {workflow.workflow_id} completed")
    
    async def _load_active_workflows(self):
        """Load active workflows from database"""
        
        with sqlite3.connect(self.db_path) as conn:
            # Load workflows
            cursor = conn.execute("""
                SELECT * FROM remediation_workflows 
                WHERE status IN ('pending', 'active', 'in_progress')
                ORDER BY priority, created_at
            """)
            
            for row in cursor.fetchall():
                workflow = self._row_to_workflow(row)
                self.active_workflows[workflow.workflow_id] = workflow
                
                # Load tasks for this workflow
                task_cursor = conn.execute("""
                    SELECT * FROM remediation_tasks 
                    WHERE workflow_id = ?
                    ORDER BY created_at
                """, (workflow.workflow_id,))
                
                for task_row in task_cursor.fetchall():
                    task = self._row_to_task(task_row)
                    workflow.tasks.append(task)
                    
                    if task.status in [TaskStatus.ASSIGNED, TaskStatus.IN_PROGRESS]:
                        self.active_tasks[task.task_id] = task
        
        self.logger.info(f"Loaded {len(self.active_workflows)} active workflows")
    
    async def _sla_monitoring_loop(self):
        """Background loop for SLA monitoring"""
        
        while self.running:
            try:
                if self.sla_monitor:
                    await self.sla_monitor.check_sla_compliance()
                
                await asyncio.sleep(300)  # Check every 5 minutes
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Error in SLA monitoring loop: {e}")
                await asyncio.sleep(60)
    
    async def _workflow_processing_loop(self):
        """Background loop for workflow processing"""
        
        while self.running:
            try:
                # Process workflow state changes
                for workflow in list(self.active_workflows.values()):
                    await self._process_workflow_state(workflow)
                
                await asyncio.sleep(60)  # Process every minute
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Error in workflow processing loop: {e}")
                await asyncio.sleep(60)
    
    async def _notification_processing_loop(self):
        """Background loop for notification processing"""
        
        while self.running:
            try:
                if self.notification_service:
                    await self.notification_service.process_pending_notifications()
                
                await asyncio.sleep(30)  # Process every 30 seconds
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Error in notification processing loop: {e}")
                await asyncio.sleep(60)
    
    async def _process_workflow_state(self, workflow: RemediationWorkflow):
        """Process workflow state and handle transitions"""
        
        try:
            # Check for stuck tasks
            for task in workflow.tasks:
                if task.status == TaskStatus.IN_PROGRESS:
                    # Check if task has been in progress too long
                    time_in_progress = datetime.now(timezone.utc) - task.updated_at
                    if time_in_progress > timedelta(hours=24):  # Configurable threshold
                        await self._handle_stuck_task(task)
            
            # Check workflow completion
            await self._check_workflow_completion(workflow)
            
        except Exception as e:
            self.logger.error(f"Error processing workflow {workflow.workflow_id}: {e}")
    
    async def _handle_stuck_task(self, task: RemediationTask):
        """Handle stuck tasks"""
        
        # Add progress note
        task.progress_notes.append({
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'type': 'system_alert',
            'user': 'system',
            'note': 'Task appears to be stuck - no progress for 24+ hours'
        })
        
        # Save task
        await self._save_task(task)
        
        # Send notification
        if self.notification_service:
            await self.notification_service.notify_stuck_task(task)
    
    async def _save_workflow(self, workflow: RemediationWorkflow):
        """Save workflow to database"""
        
        with sqlite3.connect(self.db_path) as conn:
            now = datetime.now(timezone.utc).isoformat()
            
            conn.execute("""
                INSERT OR REPLACE INTO remediation_workflows (
                    workflow_id, vulnerability_id, workflow_name, workflow_type,
                    status, priority, created_by, assigned_team, estimated_completion,
                    actual_completion, sla_requirements, business_justification,
                    risk_acceptance_criteria, success_criteria, escalation_rules,
                    approval_workflow, integration_config, audit_trail,
                    created_at, updated_at, metadata
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                workflow.workflow_id,
                workflow.vulnerability_id,
                workflow.workflow_name,
                workflow.workflow_type,
                workflow.status.value,
                workflow.priority.value,
                workflow.created_by,
                workflow.assigned_team,
                workflow.estimated_completion.isoformat() if workflow.estimated_completion else None,
                workflow.actual_completion.isoformat() if workflow.actual_completion else None,
                json.dumps(workflow.sla_requirements),
                workflow.business_justification,
                workflow.risk_acceptance_criteria,
                json.dumps(workflow.success_criteria),
                json.dumps(workflow.escalation_rules),
                json.dumps(workflow.approval_workflow) if workflow.approval_workflow else None,
                json.dumps(workflow.integration_config),
                json.dumps(workflow.audit_trail),
                workflow.created_at.isoformat(),
                workflow.updated_at.isoformat(),
                json.dumps(workflow.metadata)
            ))
    
    async def _save_task(self, task: RemediationTask):
        """Save task to database"""
        
        with sqlite3.connect(self.db_path) as conn:
            now = datetime.now(timezone.utc).isoformat()
            
            conn.execute("""
                INSERT OR REPLACE INTO remediation_tasks (
                    task_id, workflow_id, task_type, title, description,
                    priority, status, assigned_to, assigned_team, created_by,
                    estimated_effort, due_date, dependencies, prerequisites,
                    verification_criteria, approval_required, approvers,
                    automation_script, rollback_plan, risk_assessment,
                    change_window, notifications, attachments, progress_notes,
                    created_at, updated_at, metadata
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                task.task_id,
                task.workflow_id,
                task.task_type.value,
                task.title,
                task.description,
                task.priority.value,
                task.status.value,
                task.assigned_to,
                task.assigned_team,
                task.created_by,
                task.estimated_effort,
                task.due_date.isoformat() if task.due_date else None,
                json.dumps(task.dependencies),
                json.dumps(task.prerequisites),
                json.dumps(task.verification_criteria),
                task.approval_required,
                json.dumps(task.approvers),
                task.automation_script,
                task.rollback_plan,
                task.risk_assessment,
                json.dumps(task.change_window) if task.change_window else None,
                json.dumps(task.notifications),
                json.dumps(task.attachments),
                json.dumps(task.progress_notes),
                task.created_at.isoformat(),
                task.updated_at.isoformat(),
                json.dumps(task.metadata)
            ))
    
    async def _get_workflow(self, workflow_id: str) -> Optional[RemediationWorkflow]:
        """Get workflow by ID"""
        
        # Check active workflows first
        if workflow_id in self.active_workflows:
            return self.active_workflows[workflow_id]
        
        # Load from database
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("""
                SELECT * FROM remediation_workflows WHERE workflow_id = ?
            """, (workflow_id,))
            
            row = cursor.fetchone()
            if row:
                workflow = self._row_to_workflow(row)
                
                # Load tasks
                task_cursor = conn.execute("""
                    SELECT * FROM remediation_tasks WHERE workflow_id = ?
                """, (workflow_id,))
                
                for task_row in task_cursor.fetchall():
                    task = self._row_to_task(task_row)
                    workflow.tasks.append(task)
                
                return workflow
        
        return None
    
    async def _get_task(self, task_id: str) -> Optional[RemediationTask]:
        """Get task by ID"""
        
        # Check active tasks first
        if task_id in self.active_tasks:
            return self.active_tasks[task_id]
        
        # Load from database
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("""
                SELECT * FROM remediation_tasks WHERE task_id = ?
            """, (task_id,))
            
            row = cursor.fetchone()
            if row:
                return self._row_to_task(row)
        
        return None
    
    def _row_to_workflow(self, row: tuple) -> RemediationWorkflow:
        """Convert database row to RemediationWorkflow"""
        
        return RemediationWorkflow(
            workflow_id=row[0],
            vulnerability_id=row[1],
            workflow_name=row[2],
            workflow_type=row[3],
            status=WorkflowStatus(row[4]),
            priority=TaskPriority(row[5]) if row[5] else TaskPriority.MEDIUM,
            created_by=row[6],
            assigned_team=row[7],
            estimated_completion=datetime.fromisoformat(row[8]) if row[8] else None,
            actual_completion=datetime.fromisoformat(row[9]) if row[9] else None,
            sla_requirements=json.loads(row[10]) if row[10] else {},
            business_justification=row[11] or "",
            risk_acceptance_criteria=row[12] or "",
            success_criteria=json.loads(row[13]) if row[13] else [],
            escalation_rules=json.loads(row[14]) if row[14] else [],
            approval_workflow=json.loads(row[15]) if row[15] else None,
            integration_config=json.loads(row[16]) if row[16] else {},
            audit_trail=json.loads(row[17]) if row[17] else [],
            created_at=datetime.fromisoformat(row[18]),
            updated_at=datetime.fromisoformat(row[19]),
            metadata=json.loads(row[20]) if row[20] else {}
        )
    
    def _row_to_task(self, row: tuple) -> RemediationTask:
        """Convert database row to RemediationTask"""
        
        return RemediationTask(
            task_id=row[0],
            workflow_id=row[1],
            task_type=TaskType(row[2]),
            title=row[3],
            description=row[4] or "",
            priority=TaskPriority(row[5]) if row[5] else TaskPriority.MEDIUM,
            status=TaskStatus(row[6]),
            assigned_to=row[7],
            assigned_team=row[8],
            created_by=row[9] or "system",
            estimated_effort=row[10],
            due_date=datetime.fromisoformat(row[11]) if row[11] else None,
            dependencies=json.loads(row[12]) if row[12] else [],
            prerequisites=json.loads(row[13]) if row[13] else [],
            verification_criteria=json.loads(row[14]) if row[14] else [],
            approval_required=bool(row[15]) if row[15] is not None else False,
            approvers=json.loads(row[16]) if row[16] else [],
            automation_script=row[17],
            rollback_plan=row[18],
            risk_assessment=row[19],
            change_window=json.loads(row[20]) if row[20] else None,
            notifications=json.loads(row[21]) if row[21] else [],
            attachments=json.loads(row[22]) if row[22] else [],
            progress_notes=json.loads(row[23]) if row[23] else [],
            created_at=datetime.fromisoformat(row[24]),
            updated_at=datetime.fromisoformat(row[25]),
            metadata=json.loads(row[26]) if row[26] else {}
        )
    
    async def _log_workflow_event(self, 
                                workflow_id: str, 
                                event_type: str, 
                                event_data: Dict[str, Any],
                                task_id: Optional[str] = None,
                                user_id: Optional[str] = None):
        """Log workflow event"""
        
        with sqlite3.connect(self.db_path) as conn:
            now = datetime.now(timezone.utc).isoformat()
            
            conn.execute("""
                INSERT INTO workflow_events 
                (workflow_id, task_id, event_type, event_data, user_id, timestamp, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                workflow_id,
                task_id,
                event_type,
                json.dumps(event_data),
                user_id,
                now,
                now
            ))
    
    async def _trigger_event(self, event_type: str, data: Any):
        """Trigger event handlers"""
        
        if event_type in self.event_handlers:
            for handler in self.event_handlers[event_type]:
                try:
                    await handler(data)
                except Exception as e:
                    self.logger.error(f"Error in event handler for {event_type}: {e}")
    
    def register_event_handler(self, event_type: str, handler: Callable):
        """Register event handler"""
        
        if event_type not in self.event_handlers:
            self.event_handlers[event_type] = []
        
        self.event_handlers[event_type].append(handler)
    
    async def get_workflow_status(self, workflow_id: str) -> Optional[Dict[str, Any]]:
        """Get workflow status and progress"""
        
        workflow = await self._get_workflow(workflow_id)
        if not workflow:
            return None
        
        # Calculate progress
        total_tasks = len(workflow.tasks)
        completed_tasks = len([t for t in workflow.tasks if t.status == TaskStatus.COMPLETED])
        progress_percentage = (completed_tasks / total_tasks * 100) if total_tasks > 0 else 0
        
        return {
            'workflow_id': workflow_id,
            'status': workflow.status.value,
            'progress_percentage': round(progress_percentage, 2),
            'total_tasks': total_tasks,
            'completed_tasks': completed_tasks,
            'active_tasks': len([t for t in workflow.tasks if t.status == TaskStatus.IN_PROGRESS]),
            'created_at': workflow.created_at.isoformat(),
            'updated_at': workflow.updated_at.isoformat(),
            'estimated_completion': workflow.estimated_completion.isoformat() if workflow.estimated_completion else None,
            'actual_completion': workflow.actual_completion.isoformat() if workflow.actual_completion else None
        }
    
    async def get_dashboard_metrics(self, days: int = 30) -> Dict[str, Any]:
        """Get workflow dashboard metrics"""
        
        since_date = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        
        with sqlite3.connect(self.db_path) as conn:
            # Workflow status distribution 
            cursor = conn.execute("""
                SELECT status, COUNT(*) as count
                FROM remediation_workflows
                WHERE created_at > ?
                GROUP BY status
            """, (since_date,))
            workflow_status = dict(cursor.fetchall())
            
            # Task status distribution
            cursor = conn.execute("""
                SELECT t.status, COUNT(*) as count
                FROM remediation_tasks t
                JOIN remediation_workflows w ON t.workflow_id = w.workflow_id
                WHERE w.created_at > ?
                GROUP BY t.status
            """, (since_date,))
            task_status = dict(cursor.fetchall())
            
            # Average completion time
            cursor = conn.execute("""
                SELECT AVG(julianday(actual_completion) - julianday(created_at)) * 24 as avg_hours
                FROM remediation_workflows
                WHERE actual_completion IS NOT NULL AND created_at > ?
            """, (since_date,))
            avg_completion_time = cursor.fetchone()[0] or 0
            
            # SLA compliance
            cursor = conn.execute("""
                SELECT 
                    COUNT(*) as total,
                    SUM(CASE WHEN actual_completion IS NOT NULL AND 
                        julianday(actual_completion) - julianday(created_at) <= 
                        CAST(JSON_EXTRACT(sla_requirements, '$.resolution_time') AS REAL) / 24.0
                        THEN 1 ELSE 0 END) as on_time
                FROM remediation_workflows
                WHERE created_at > ?
            """, (since_date,))
            sla_row = cursor.fetchone()
            sla_compliance = (sla_row[1] / sla_row[0] * 100) if sla_row[0] > 0 else 0
            
            return {
                'period_days': days,
                'workflow_status_distribution': workflow_status,
                'task_status_distribution': task_status,
                'average_completion_time_hours': round(avg_completion_time, 2),
                'sla_compliance_percentage': round(sla_compliance, 2),
                'active_workflows': len(self.active_workflows),
                'active_tasks': len(self.active_tasks)
            }