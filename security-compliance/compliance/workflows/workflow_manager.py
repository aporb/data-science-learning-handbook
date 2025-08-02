#!/usr/bin/env python3
"""
Compliance Workflow Manager
============================

Comprehensive workflow management system for compliance documentation
with automated approval processes, digital signatures, and change management.

Key Features:
- Automated document review processes
- Multi-level approval workflows
- Digital signature integration
- Change management and version control
- Scheduled compliance report generation
- Integration with existing CMS workflows

Classification: UNCLASSIFIED//FOR OFFICIAL USE ONLY
Version: 1.0
Author: Security Compliance Team
Date: 2025-07-28
"""

import asyncio
import json
import logging
from pathlib import Path
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict
from enum import Enum

from .approval_workflow import ApprovalWorkflow
from .digital_signature_manager import DigitalSignatureManager
from .change_management import ChangeManagement

# Import integration components
from ..integration.compliance_integrator import ComplianceIntegrator, GenerationResult

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class WorkflowStatus(Enum):
    """Workflow status enumeration"""
    DRAFT = "draft"
    PENDING_REVIEW = "pending_review"
    IN_REVIEW = "in_review"
    PENDING_APPROVAL = "pending_approval"
    APPROVED = "approved"
    REJECTED = "rejected"
    PUBLISHED = "published"
    ARCHIVED = "archived"


class WorkflowType(Enum):
    """Workflow type enumeration"""
    DOCUMENT_GENERATION = "document_generation"
    PERIODIC_REVIEW = "periodic_review"
    CHANGE_REQUEST = "change_request"
    EMERGENCY_UPDATE = "emergency_update"
    SCHEDULED_REPORT = "scheduled_report"


@dataclass
class WorkflowInstance:
    """Workflow instance tracking"""
    workflow_id: str
    workflow_type: WorkflowType
    system_id: str
    document_paths: List[str]
    status: WorkflowStatus
    created_date: datetime
    created_by: str
    current_step: str
    next_action_date: Optional[datetime]
    approval_chain: List[str]
    approvers: Dict[str, Any]
    metadata: Dict[str, Any]
    history: List[Dict[str, Any]]
    
    def __post_init__(self):
        if not self.history:
            self.history = []
        if not self.approvers:
            self.approvers = {}


class WorkflowManager:
    """
    Compliance Workflow Manager
    
    Orchestrates compliance document workflows with automated processes,
    approval chains, and change management.
    """
    
    def __init__(self,
                 workflows_path: Path,
                 compliance_integrator: ComplianceIntegrator,
                 config: Optional[Dict[str, Any]] = None):
        """
        Initialize Workflow Manager
        
        Args:
            workflows_path: Path for workflow storage
            compliance_integrator: Compliance integrator instance
            config: Configuration dictionary
        """
        self.workflows_path = Path(workflows_path)
        self.compliance_integrator = compliance_integrator
        self.config = config or {}
        
        # Ensure directories exist
        self.workflows_path.mkdir(parents=True, exist_ok=True)
        (self.workflows_path / "active").mkdir(exist_ok=True)
        (self.workflows_path / "completed").mkdir(exist_ok=True)
        (self.workflows_path / "templates").mkdir(exist_ok=True)
        
        # Initialize sub-components
        self.approval_workflow = ApprovalWorkflow(
            config=self.config.get('approval', {})
        )
        
        self.signature_manager = DigitalSignatureManager(
            config=self.config.get('signatures', {})
        )
        
        self.change_management = ChangeManagement(
            config=self.config.get('change_management', {}),
            workflows_path=self.workflows_path
        )
        
        # Active workflows
        self.active_workflows = {}
        self._load_active_workflows()
        
        # Workflow templates
        self.workflow_templates = self._load_workflow_templates()
        
        logger.info("Workflow Manager initialized")
        logger.info(f"Active workflows: {len(self.active_workflows)}")
    
    def _load_active_workflows(self):
        """Load active workflows from storage"""
        active_dir = self.workflows_path / "active"
        
        for workflow_file in active_dir.glob("*.json"):
            try:
                with open(workflow_file, 'r') as f:
                    workflow_data = json.load(f)
                
                # Convert to WorkflowInstance
                workflow_data['created_date'] = datetime.fromisoformat(workflow_data['created_date'])
                if workflow_data.get('next_action_date'):
                    workflow_data['next_action_date'] = datetime.fromisoformat(workflow_data['next_action_date'])
                
                workflow_data['workflow_type'] = WorkflowType(workflow_data['workflow_type'])
                workflow_data['status'] = WorkflowStatus(workflow_data['status'])
                
                workflow = WorkflowInstance(**workflow_data)
                self.active_workflows[workflow.workflow_id] = workflow
                
            except Exception as e:
                logger.error(f"Error loading workflow {workflow_file}: {e}")
    
    def _load_workflow_templates(self) -> Dict[str, Dict[str, Any]]:
        """Load workflow templates"""
        templates = {
            WorkflowType.DOCUMENT_GENERATION: {
                "name": "Document Generation Workflow",
                "steps": [
                    {"name": "generate", "description": "Generate compliance documents", "automated": True},
                    {"name": "technical_review", "description": "Technical review", "role": "technical_reviewer"},
                    {"name": "compliance_review", "description": "Compliance review", "role": "compliance_officer"},
                    {"name": "approval", "description": "Final approval", "role": "authorizing_official"},
                    {"name": "publish", "description": "Publish documents", "automated": True}
                ],
                "approval_chain": ["technical_reviewer", "compliance_officer", "authorizing_official"],
                "auto_advance": ["generate", "publish"],
                "timeout_days": 30
            },
            WorkflowType.PERIODIC_REVIEW: {
                "name": "Periodic Compliance Review",
                "steps": [
                    {"name": "collect_data", "description": "Collect updated compliance data", "automated": True},
                    {"name": "generate", "description": "Generate updated documents", "automated": True},
                    {"name": "delta_review", "description": "Review changes", "role": "compliance_officer"},
                    {"name": "approval", "description": "Approve updates", "role": "authorizing_official"},
                    {"name": "publish", "description": "Publish updates", "automated": True}
                ],
                "approval_chain": ["compliance_officer", "authorizing_official"],
                "auto_advance": ["collect_data", "generate", "publish"],
                "timeout_days": 14
            },
            WorkflowType.EMERGENCY_UPDATE: {
                "name": "Emergency Compliance Update",
                "steps": [
                    {"name": "assess", "description": "Assess emergency changes", "role": "compliance_officer"},
                    {"name": "generate", "description": "Generate emergency updates", "automated": True},
                    {"name": "expedited_review", "description": "Expedited review", "role": "authorizing_official"},
                    {"name": "publish", "description": "Publish emergency updates", "automated": True}
                ],
                "approval_chain": ["compliance_officer", "authorizing_official"],
                "auto_advance": ["generate", "publish"],
                "timeout_days": 3
            }
        }
        
        return templates
    
    async def create_workflow(self,
                            workflow_type: WorkflowType,
                            system_id: str,
                            created_by: str,
                            metadata: Optional[Dict[str, Any]] = None) -> str:
        """
        Create a new compliance workflow
        
        Args:
            workflow_type: Type of workflow
            system_id: System identifier
            created_by: User creating the workflow
            metadata: Additional metadata
            
        Returns:
            Workflow ID
        """
        workflow_id = f"WF-{datetime.now().strftime('%Y%m%d-%H%M%S')}-{len(self.active_workflows)}"
        
        template = self.workflow_templates.get(workflow_type, {})
        approval_chain = template.get('approval_chain', [])
        
        workflow = WorkflowInstance(
            workflow_id=workflow_id,
            workflow_type=workflow_type,
            system_id=system_id,
            document_paths=[],
            status=WorkflowStatus.DRAFT,
            created_date=datetime.now(timezone.utc),
            created_by=created_by,
            current_step=template.get('steps', [{}])[0].get('name', 'start'),
            next_action_date=datetime.now(timezone.utc) + timedelta(hours=1),
            approval_chain=approval_chain,
            approvers={},
            metadata=metadata or {},
            history=[]
        )
        
        # Add creation event to history
        workflow.history.append({
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'action': 'created',
            'user': created_by,
            'details': f'Workflow created for system {system_id}'
        })
        
        self.active_workflows[workflow_id] = workflow
        await self._save_workflow(workflow)
        
        logger.info(f"Created workflow {workflow_id} for system {system_id}")
        
        return workflow_id
    
    async def execute_document_generation_workflow(self,
                                                 system_id: str,
                                                 template_types: List[str],
                                                 classification: str,
                                                 organization: str,
                                                 created_by: str) -> str:
        """
        Execute complete document generation workflow
        
        Args:
            system_id: System identifier
            template_types: Document templates to generate
            classification: Security classification
            organization: Organization name
            created_by: User initiating workflow
            
        Returns:
            Workflow ID
        """
        # Create workflow
        metadata = {
            'template_types': template_types,
            'classification': classification,
            'organization': organization,
            'generation_requested': datetime.now(timezone.utc).isoformat()
        }
        
        workflow_id = await self.create_workflow(
            WorkflowType.DOCUMENT_GENERATION,
            system_id,
            created_by,
            metadata
        )
        
        # Start execution
        await self._advance_workflow(workflow_id)
        
        return workflow_id
    
    async def _advance_workflow(self, workflow_id: str):
        """
        Advance workflow to next step
        
        Args:
            workflow_id: Workflow identifier
        """
        if workflow_id not in self.active_workflows:
            logger.error(f"Workflow {workflow_id} not found")
            return
        
        workflow = self.active_workflows[workflow_id]
        template = self.workflow_templates.get(workflow.workflow_type, {})
        steps = template.get('steps', [])
        
        # Find current step
        current_step_index = None
        for i, step in enumerate(steps):
            if step['name'] == workflow.current_step:
                current_step_index = i
                break
        
        if current_step_index is None:
            logger.error(f"Current step {workflow.current_step} not found in template")
            return
        
        current_step = steps[current_step_index]
        
        # Execute current step
        await self._execute_workflow_step(workflow, current_step)
        
        # Check if step can auto-advance
        auto_advance_steps = template.get('auto_advance', [])
        if current_step['name'] in auto_advance_steps:
            # Move to next step
            next_index = current_step_index + 1
            if next_index < len(steps):
                next_step = steps[next_index]
                workflow.current_step = next_step['name']
                workflow.status = WorkflowStatus.PENDING_REVIEW if not next_step.get('automated') else WorkflowStatus.IN_REVIEW
                
                # Add history entry
                workflow.history.append({
                    'timestamp': datetime.now(timezone.utc).isoformat(),
                    'action': 'advanced',
                    'step': next_step['name'],
                    'details': f'Auto-advanced to {next_step.get("description", next_step["name"])}'
                })
                
                await self._save_workflow(workflow)
                
                # Continue execution if next step is also automated
                if next_step.get('automated'):
                    await self._advance_workflow(workflow_id)
            else:
                # Workflow complete
                workflow.status = WorkflowStatus.PUBLISHED
                await self._complete_workflow(workflow_id)
    
    async def _execute_workflow_step(self, workflow: WorkflowInstance, step: Dict[str, Any]):
        """
        Execute a specific workflow step
        
        Args:
            workflow: Workflow instance
            step: Step definition
        """
        step_name = step['name']
        logger.info(f"Executing workflow step: {step_name} for {workflow.workflow_id}")
        
        try:
            if step_name == 'generate':
                await self._execute_generation_step(workflow)
            elif step_name == 'collect_data':
                await self._execute_data_collection_step(workflow)
            elif step_name == 'publish':
                await self._execute_publish_step(workflow)
            elif step_name in ['technical_review', 'compliance_review', 'delta_review']:
                await self._execute_review_step(workflow, step)
            elif step_name in ['approval', 'expedited_review']:
                await self._execute_approval_step(workflow, step)
            else:
                logger.warning(f"Unknown workflow step: {step_name}")
        
        except Exception as e:
            logger.error(f"Error executing workflow step {step_name}: {e}")
            workflow.status = WorkflowStatus.REJECTED
            workflow.history.append({
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'action': 'error',
                'step': step_name,
                'error': str(e)
            })
            await self._save_workflow(workflow)
    
    async def _execute_generation_step(self, workflow: WorkflowInstance):
        """Execute document generation step"""
        metadata = workflow.metadata
        
        # Generate documents using compliance integrator
        try:
            from ..templates.compliance_template_engine import TemplateType, ClassificationLevel
            
            # Convert template types
            template_types = []
            for template_name in metadata.get('template_types', ['SSP']):
                try:
                    template_types.append(TemplateType(template_name.lower().replace(' ', '_')))
                except ValueError:
                    template_types.append(TemplateType.SSP)  # Default fallback
            
            # Convert classification
            classification = ClassificationLevel.UNCLASSIFIED
            try:
                classification = ClassificationLevel(metadata.get('classification', 'U'))
            except ValueError:
                pass
            
            # Generate documents
            results = await self.compliance_integrator.generate_system_documentation(
                system_name=f"System {workflow.system_id}",
                system_id=workflow.system_id,
                classification=classification,
                organization=metadata.get('organization', 'Department of Defense'),
                template_types=template_types
            )
            
            # Update workflow with generated document paths
            workflow.document_paths = [r.document_path for r in results if r.success and r.document_path]
            
            # Add generation results to metadata
            workflow.metadata['generation_results'] = [asdict(r) for r in results]
            workflow.metadata['generation_completed'] = datetime.now(timezone.utc).isoformat()
            
            # Add history entry
            successful_docs = len([r for r in results if r.success])
            workflow.history.append({
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'action': 'generated',
                'details': f'Generated {successful_docs} documents successfully',
                'documents': workflow.document_paths
            })
            
        except Exception as e:
            logger.error(f"Document generation failed: {e}")
            raise
    
    async def _execute_data_collection_step(self, workflow: WorkflowInstance):
        """Execute data collection step"""
        # This would integrate with data collection systems
        workflow.history.append({
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'action': 'data_collected',
            'details': 'Compliance data collected and updated'
        })
    
    async def _execute_review_step(self, workflow: WorkflowInstance, step: Dict[str, Any]):
        """Execute review step"""
        required_role = step.get('role', 'reviewer')
        
        # Create review task
        review_task = {
            'workflow_id': workflow.workflow_id,
            'step_name': step['name'],
            'description': step.get('description', 'Review required'),
            'required_role': required_role,
            'documents': workflow.document_paths,
            'due_date': (datetime.now(timezone.utc) + timedelta(days=7)).isoformat(),
            'status': 'pending'
        }
        
        workflow.metadata[f'{step["name"]}_task'] = review_task
        workflow.status = WorkflowStatus.PENDING_REVIEW
        
        workflow.history.append({
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'action': 'review_requested',
            'step': step['name'],
            'required_role': required_role,
            'details': f'Review requested from {required_role}'
        })
    
    async def _execute_approval_step(self, workflow: WorkflowInstance, step: Dict[str, Any]):
        """Execute approval step"""
        required_role = step.get('role', 'approver')
        
        # Create approval task
        approval_task = {
            'workflow_id': workflow.workflow_id,
            'step_name': step['name'],
            'description': step.get('description', 'Approval required'),
            'required_role': required_role,
            'documents': workflow.document_paths,
            'due_date': (datetime.now(timezone.utc) + timedelta(days=3)).isoformat(),
            'status': 'pending'
        }
        
        workflow.metadata[f'{step["name"]}_task'] = approval_task
        workflow.status = WorkflowStatus.PENDING_APPROVAL
        
        workflow.history.append({
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'action': 'approval_requested',
            'step': step['name'],
            'required_role': required_role,
            'details': f'Approval requested from {required_role}'
        })
    
    async def _execute_publish_step(self, workflow: WorkflowInstance):
        """Execute publish step"""
        # Publish documents (this would integrate with document management systems)
        published_paths = []
        
        for doc_path in workflow.document_paths:
            if Path(doc_path).exists():
                # In real implementation, this would copy to publication directory
                published_paths.append(doc_path)
        
        workflow.metadata['published_documents'] = published_paths
        workflow.metadata['publication_date'] = datetime.now(timezone.utc).isoformat()
        
        workflow.history.append({
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'action': 'published',
            'details': f'Published {len(published_paths)} documents',
            'published_documents': published_paths
        })
    
    async def submit_review(self,
                          workflow_id: str,
                          reviewer: str,
                          decision: str,
                          comments: str = "") -> bool:
        """
        Submit review decision
        
        Args:
            workflow_id: Workflow identifier
            reviewer: Reviewer identifier
            decision: Review decision (approve/reject/request_changes)
            comments: Review comments
            
        Returns:
            Success status
        """
        if workflow_id not in self.active_workflows:
            return False
        
        workflow = self.active_workflows[workflow_id]
        
        # Record review decision
        review_entry = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'action': 'review_submitted',
            'reviewer': reviewer,
            'decision': decision,
            'comments': comments,
            'step': workflow.current_step
        }
        
        workflow.history.append(review_entry)
        
        if decision == 'approve':
            # Advance workflow
            await self._advance_workflow(workflow_id)
        elif decision == 'reject':
            workflow.status = WorkflowStatus.REJECTED
            await self._save_workflow(workflow)
        elif decision == 'request_changes':
            workflow.status = WorkflowStatus.DRAFT
            # Would typically send back to previous step
        
        logger.info(f"Review submitted for {workflow_id}: {decision}")
        return True
    
    async def submit_approval(self,
                            workflow_id: str,
                            approver: str,
                            decision: str,
                            comments: str = "",
                            digital_signature: str = "") -> bool:
        """
        Submit approval decision
        
        Args:
            workflow_id: Workflow identifier
            approver: Approver identifier
            decision: Approval decision (approve/reject)
            comments: Approval comments
            digital_signature: Digital signature
            
        Returns:
            Success status
        """
        if workflow_id not in self.active_workflows:
            return False
        
        workflow = self.active_workflows[workflow_id]
        
        # Record approval decision
        approval_entry = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'action': 'approval_submitted',
            'approver': approver,
            'decision': decision,
            'comments': comments,
            'step': workflow.current_step,
            'digital_signature': digital_signature
        }
        
        workflow.history.append(approval_entry)
        workflow.approvers[approver] = approval_entry
        
        if decision == 'approve':
            workflow.status = WorkflowStatus.APPROVED
            # Advance workflow
            await self._advance_workflow(workflow_id)
        elif decision == 'reject':
            workflow.status = WorkflowStatus.REJECTED
            await self._save_workflow(workflow)
        
        logger.info(f"Approval submitted for {workflow_id}: {decision}")
        return True
    
    async def _complete_workflow(self, workflow_id: str):
        """
        Complete workflow and move to archive
        
        Args:
            workflow_id: Workflow identifier
        """
        if workflow_id not in self.active_workflows:
            return
        
        workflow = self.active_workflows[workflow_id]
        workflow.status = WorkflowStatus.PUBLISHED
        
        # Add completion entry
        workflow.history.append({
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'action': 'completed',
            'details': 'Workflow completed successfully'
        })
        
        # Move to completed directory
        await self._archive_workflow(workflow)
        
        # Remove from active workflows
        del self.active_workflows[workflow_id]
        
        logger.info(f"Workflow {workflow_id} completed and archived")
    
    async def _save_workflow(self, workflow: WorkflowInstance):
        """Save workflow to storage"""
        workflow_file = self.workflows_path / "active" / f"{workflow.workflow_id}.json"
        
        # Convert to serializable format
        workflow_data = asdict(workflow)
        workflow_data['created_date'] = workflow.created_date.isoformat()
        if workflow.next_action_date:
            workflow_data['next_action_date'] = workflow.next_action_date.isoformat()
        workflow_data['workflow_type'] = workflow.workflow_type.value
        workflow_data['status'] = workflow.status.value
        
        with open(workflow_file, 'w') as f:
            json.dump(workflow_data, f, indent=2, default=str)
    
    async def _archive_workflow(self, workflow: WorkflowInstance):
        """Archive completed workflow"""
        archive_file = self.workflows_path / "completed" / f"{workflow.workflow_id}.json"
        
        # Convert to serializable format
        workflow_data = asdict(workflow)
        workflow_data['created_date'] = workflow.created_date.isoformat()
        if workflow.next_action_date:
            workflow_data['next_action_date'] = workflow.next_action_date.isoformat()
        workflow_data['workflow_type'] = workflow.workflow_type.value
        workflow_data['status'] = workflow.status.value
        workflow_data['archived_date'] = datetime.now(timezone.utc).isoformat()
        
        with open(archive_file, 'w') as f:
            json.dump(workflow_data, f, indent=2, default=str)
        
        # Remove from active
        active_file = self.workflows_path / "active" / f"{workflow.workflow_id}.json"
        if active_file.exists():
            active_file.unlink()
    
    def get_workflow_status(self, workflow_id: str) -> Optional[Dict[str, Any]]:
        """Get workflow status"""
        if workflow_id in self.active_workflows:
            workflow = self.active_workflows[workflow_id]
            return {
                'workflow_id': workflow.workflow_id,
                'status': workflow.status.value,
                'current_step': workflow.current_step,
                'system_id': workflow.system_id,
                'created_date': workflow.created_date.isoformat(),
                'document_count': len(workflow.document_paths),
                'approvers_count': len(workflow.approvers),
                'history_count': len(workflow.history)
            }
        
        return None
    
    def list_workflows(self, status_filter: Optional[WorkflowStatus] = None) -> List[Dict[str, Any]]:
        """List workflows with optional status filter"""
        workflows = []
        
        for workflow in self.active_workflows.values():
            if status_filter is None or workflow.status == status_filter:
                workflows.append({
                    'workflow_id': workflow.workflow_id,
                    'workflow_type': workflow.workflow_type.value,
                    'system_id': workflow.system_id,
                    'status': workflow.status.value,
                    'current_step': workflow.current_step,
                    'created_date': workflow.created_date.isoformat(),
                    'created_by': workflow.created_by
                })
        
        return sorted(workflows, key=lambda x: x['created_date'], reverse=True)


if __name__ == "__main__":
    # Example usage
    import asyncio
    import tempfile
    
    async def main():
        from ..integration.compliance_integrator import ComplianceIntegrator, IntegrationConfig
        
        with tempfile.TemporaryDirectory() as temp_dir:
            workflows_path = Path(temp_dir) / "workflows"
            
            # Mock compliance integrator
            integration_config = IntegrationConfig(
                audit_config={},
                testing_config={},
                monitoring_config={},
                templates_path=Path(temp_dir) / "templates",
                output_path=Path(temp_dir) / "output"
            )
            
            integrator = ComplianceIntegrator(integration_config)
            
            # Initialize workflow manager
            manager = WorkflowManager(workflows_path, integrator)
            
            # Create and execute workflow
            workflow_id = await manager.execute_document_generation_workflow(
                system_id="TEST-001",
                template_types=["SSP", "SAR"],
                classification="U",
                organization="Test Organization",
                created_by="test_user"
            )
            
            print(f"Created workflow: {workflow_id}")
            
            # Check status
            status = manager.get_workflow_status(workflow_id)
            print(f"Workflow status: {status}")
            
            # List all workflows
            workflows = manager.list_workflows()
            print(f"Total workflows: {len(workflows)}")
    
    asyncio.run(main())