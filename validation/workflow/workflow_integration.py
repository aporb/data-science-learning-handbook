#!/usr/bin/env python3
"""
Workflow Integration Layer
==========================

A comprehensive integration layer that connects all workflow components:
- Content Management System integration
- Review Workflow orchestration
- Git Branching Strategy management
- Notification System coordination
- Migration Tools integration
- End-to-end workflow automation

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
from typing import Dict, List, Optional, Tuple, Any, Set
from pathlib import Path
from dataclasses import dataclass, asdict
from enum import Enum
import yaml

# Import workflow components
from .review_workflow import (
    WorkflowOrchestrator, WorkflowStage, ReviewerRole, ReviewAction,
    NotificationPriority, WorkflowInstance
)
from .branching_strategy import (
    ContentBranchingStrategy, BranchType, BranchStatus, MergeStrategy
)
from .notification_system import (
    NotificationSystem, NotificationTrigger, NotificationChannel
)
from .migration_tools import (
    ContentMigrator, MigrationType, MigrationPlan
)

# Import existing CMS
sys.path.append(str(Path(__file__).parent.parent))
from content_management_system import (
    ContentManagementSystem, ContentStatus, ReviewStage
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class IntegrationStatus(Enum):
    """Integration status enumeration"""
    INITIALIZING = "initializing"
    ACTIVE = "active"
    ERROR = "error"
    MAINTENANCE = "maintenance"


@dataclass
class WorkflowContext:
    """Workflow execution context"""
    content_id: str
    content_path: str
    author: str
    workflow_instance_id: Optional[str] = None
    current_branch: Optional[str] = None
    review_assignments: List[str] = None
    notification_history: List[str] = None
    metadata: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.review_assignments is None:
            self.review_assignments = []
        if self.notification_history is None:
            self.notification_history = []
        if self.metadata is None:
            self.metadata = {}


@dataclass
class IntegrationMetrics:
    """Integration system metrics"""
    active_workflows: int
    active_branches: int
    pending_notifications: int
    recent_migrations: int
    error_count: int
    uptime_hours: float
    last_updated: str = None
    
    def __post_init__(self):
        if self.last_updated is None:
            self.last_updated = datetime.now().isoformat()


class WorkflowIntegrationManager:
    """
    Comprehensive Workflow Integration Manager
    
    Coordinates all workflow components to provide seamless content management
    """
    
    def __init__(self, repo_path: str, config_path: Optional[str] = None):
        """
        Initialize the Integration Manager
        
        Args:
            repo_path: Path to repository
            config_path: Path to configuration file
        """
        self.repo_path = Path(repo_path)
        self.config_path = config_path or self.repo_path / "validation" / "workflow" / "integration_config.yml"
        self.data_dir = self.repo_path / "validation" / "workflow" / "integration"
        
        # Ensure directories exist
        self.data_dir.mkdir(parents=True, exist_ok=True)
        
        # Load configuration
        self.config = self._load_configuration()
        
        # Initialize status
        self.status = IntegrationStatus.INITIALIZING
        self.start_time = datetime.now()
        
        # Initialize components
        try:
            self.cms = ContentManagementSystem(str(self.repo_path))
            self.workflow_orchestrator = WorkflowOrchestrator(
                str(self.repo_path / "validation" / "workflow" / "workflow_config.yml"),
                str(self.repo_path)
            )
            self.branching_strategy = ContentBranchingStrategy(
                str(self.repo_path),
                str(self.repo_path / "validation" / "workflow" / "branching_config.yml")
            )
            self.notification_system = NotificationSystem(
                str(self.repo_path / "validation" / "workflow" / "notification_config.yml")
            )
            self.migrator = ContentMigrator(
                str(self.repo_path),
                str(self.repo_path / "validation" / "workflow" / "migration_config.yml")
            )
            
            self.status = IntegrationStatus.ACTIVE
            logger.info("Workflow Integration Manager initialized successfully")
            
        except Exception as e:
            self.status = IntegrationStatus.ERROR
            logger.error(f"Failed to initialize components: {e}")
            raise
        
        # Load active contexts
        self.active_contexts = self._load_active_contexts()
        
        # Start notification scheduler
        if self.config.get("notifications", {}).get("auto_start_scheduler", True):
            self.notification_system.start_scheduler()
    
    def _load_configuration(self) -> Dict[str, Any]:
        """Load integration configuration"""
        default_config = {
            "integration": {
                "auto_create_branches": True,
                "auto_assign_reviewers": True,
                "auto_send_notifications": True,
                "parallel_processing": True,
                "max_concurrent_workflows": 20,
                "workflow_timeout_hours": 72
            },
            "workflow_mapping": {
                "draft_to_technical": {
                    "source_stage": "draft",
                    "target_stage": "technical_review",
                    "branch_type": "technical_review",
                    "required_roles": ["technical_reviewer"],
                    "notifications": ["assignment_created"]
                },
                "technical_to_educational": {
                    "source_stage": "technical_review", 
                    "target_stage": "educational_review",
                    "branch_type": "educational_review",
                    "required_roles": ["educational_reviewer"],
                    "notifications": ["review_submitted", "assignment_created"]
                },
                "educational_to_bias": {
                    "source_stage": "educational_review",
                    "target_stage": "bias_assessment",
                    "branch_type": "bias_assessment", 
                    "required_roles": ["bias_assessor"],
                    "notifications": ["review_submitted", "assignment_created"]
                },
                "bias_to_security": {
                    "source_stage": "bias_assessment",
                    "target_stage": "security_review",
                    "branch_type": "security_review",
                    "required_roles": ["security_reviewer"],
                    "notifications": ["review_submitted", "assignment_created"]
                },
                "security_to_final": {
                    "source_stage": "security_review",
                    "target_stage": "final_approval",
                    "branch_type": "final_approval",
                    "required_roles": ["content_approver"],
                    "notifications": ["review_submitted", "assignment_created"]
                }
            },
            "notifications": {
                "auto_start_scheduler": True,
                "reminder_intervals_hours": [24, 6, 1],
                "escalation_threshold_hours": 48
            },
            "quality_gates": {
                "enforce_quality_gates": True,
                "minimum_overall_score": 80.0,
                "auto_merge_threshold": 95.0
            },
            "migration": {
                "auto_migrate_templates": True,
                "backup_before_migration": True,
                "validate_after_migration": True
            }
        }
        
        if self.config_path.exists():
            try:
                with open(self.config_path, 'r') as f:
                    user_config = yaml.safe_load(f)
                    self._deep_merge(default_config, user_config)
            except Exception as e:
                logger.warning(f"Failed to load config from {self.config_path}: {e}")
        
        return default_config
    
    def _deep_merge(self, base: Dict, override: Dict):
        """Deep merge configuration dictionaries"""
        for key, value in override.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                self._deep_merge(base[key], value)
            else:
                base[key] = value
    
    def _load_active_contexts(self) -> Dict[str, WorkflowContext]:
        """Load active workflow contexts"""
        contexts_file = self.data_dir / "active_contexts.json"
        contexts = {}
        
        if contexts_file.exists():
            try:
                with open(contexts_file, 'r') as f:
                    data = json.load(f)
                    for context_data in data.get('contexts', []):
                        context = WorkflowContext(
                            content_id=context_data['content_id'],
                            content_path=context_data['content_path'],
                            author=context_data['author'],
                            workflow_instance_id=context_data.get('workflow_instance_id'),
                            current_branch=context_data.get('current_branch'),
                            review_assignments=context_data.get('review_assignments', []),
                            notification_history=context_data.get('notification_history', []),
                            metadata=context_data.get('metadata', {})
                        )
                        contexts[context.content_id] = context
            except Exception as e:
                logger.error(f"Failed to load active contexts: {e}")
        
        return contexts
    
    def _save_active_contexts(self):
        """Save active workflow contexts"""
        contexts_file = self.data_dir / "active_contexts.json"
        
        try:
            data = {
                "contexts": [asdict(context) for context in self.active_contexts.values()]
            }
            
            with open(contexts_file, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save active contexts: {e}")
    
    def start_content_workflow(self, content_id: str, content_path: str, author: str,
                             initial_metadata: Optional[Dict[str, Any]] = None) -> str:
        """
        Start a complete content workflow
        
        Args:
            content_id: Unique content identifier
            content_path: Path to content file
            author: Content author
            initial_metadata: Additional metadata
        
        Returns:
            Workflow instance ID
        """
        logger.info(f"Starting workflow for content: {content_id}")
        
        try:
            # Create workflow context
            context = WorkflowContext(
                content_id=content_id,
                content_path=content_path,
                author=author,
                metadata=initial_metadata or {}
            )
            
            # Create workflow instance
            workflow_instance_id = self.workflow_orchestrator.create_workflow(
                content_id=content_id,
                content_path=content_path,
                author=author,
                metadata=context.metadata
            )
            
            context.workflow_instance_id = workflow_instance_id
            
            # Create initial branch if configured
            if self.config["integration"]["auto_create_branches"]:
                branch_name = self.branching_strategy.create_content_branch(
                    branch_type=BranchType.CONTENT_DRAFT,
                    content_id=content_id,
                    author=author,
                    workflow_instance_id=workflow_instance_id
                )
                context.current_branch = branch_name
            
            # Send initial notifications
            if self.config["integration"]["auto_send_notifications"]:
                notification_ids = self.notification_system.create_notification(
                    trigger=NotificationTrigger.WORKFLOW_CREATED,
                    recipients=[author],
                    context={
                        "content_id": content_id,
                        "content_title": Path(content_path).stem,
                        "workflow_instance_id": workflow_instance_id,
                        "author_name": author,
                        "created_date": datetime.now().isoformat()
                    }
                )
                context.notification_history.extend(notification_ids)
            
            # Save context
            self.active_contexts[content_id] = context
            self._save_active_contexts()
            
            logger.info(f"Workflow started successfully: {workflow_instance_id}")
            return workflow_instance_id
            
        except Exception as e:
            logger.error(f"Failed to start workflow for {content_id}: {e}")
            raise
    
    def advance_workflow_stage(self, content_id: str, target_stage: str,
                             reviewer_feedback: Optional[Dict[str, Any]] = None) -> bool:
        """
        Advance workflow to next stage
        
        Args:
            content_id: Content identifier
            target_stage: Target workflow stage
            reviewer_feedback: Optional reviewer feedback
        
        Returns:
            Success status
        """
        if content_id not in self.active_contexts:
            logger.error(f"No active context found for content {content_id}")
            return False
        
        context = self.active_contexts[content_id]
        
        try:
            # Map target stage to workflow stage enum
            workflow_stage = WorkflowStage(target_stage)
            
            # Start the review stage
            success = self.workflow_orchestrator.start_review_stage(
                context.workflow_instance_id,
                workflow_stage
            )
            
            if not success:
                logger.error(f"Failed to start workflow stage {target_stage}")
                return False
            
            # Create branch for review stage if configured
            if self.config["integration"]["auto_create_branches"]:
                stage_mapping = self.config["workflow_mapping"].get(f"*_to_{target_stage}")
                if stage_mapping:
                    branch_type = BranchType(stage_mapping["branch_type"])
                    
                    # Create review branch from current branch
                    review_branch = self.branching_strategy.create_content_branch(
                        branch_type=branch_type,
                        content_id=content_id,
                        author=context.author,
                        workflow_instance_id=context.workflow_instance_id,
                        base_branch=context.current_branch
                    )
                    
                    # Switch to review branch
                    self.branching_strategy.switch_branch(review_branch)
                    context.current_branch = review_branch
            
            # Send notifications for stage transition
            if self.config["integration"]["auto_send_notifications"]:
                # Get workflow status to find assignments
                workflow_status = self.workflow_orchestrator.get_workflow_status(
                    context.workflow_instance_id
                )
                
                if workflow_status:
                    # Notify assigned reviewers
                    for assignment in workflow_status.get("current_assignments", []):
                        notification_ids = self.notification_system.create_notification(
                            trigger=NotificationTrigger.ASSIGNMENT_CREATED,
                            recipients=[assignment["reviewer"]],
                            context={
                                "content_id": content_id,
                                "content_title": Path(context.content_path).stem,
                                "reviewer_name": assignment["reviewer"],
                                "review_stage": target_stage,
                                "due_date": assignment["due_date"],
                                "workflow_url": f"/workflow/{context.workflow_instance_id}",
                                "content_path": context.content_path
                            }
                        )
                        context.notification_history.extend(notification_ids)
            
            # Update context
            self._save_active_contexts()
            
            logger.info(f"Advanced workflow for {content_id} to stage {target_stage}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to advance workflow stage for {content_id}: {e}")
            return False
    
    def submit_review(self, content_id: str, assignment_id: str, action: str,
                     score: Optional[float] = None, comments: Optional[List[str]] = None) -> bool:
        """
        Submit a review for content
        
        Args:
            content_id: Content identifier
            assignment_id: Review assignment ID
            action: Review action (approve, request_changes, reject)
            score: Review score
            comments: Review comments
        
        Returns:
            Success status
        """
        if content_id not in self.active_contexts:
            logger.error(f"No active context found for content {content_id}")
            return False
        
        context = self.active_contexts[content_id]
        
        try:
            # Submit review through workflow orchestrator
            review_action = ReviewAction(action)
            success = self.workflow_orchestrator.submit_review(
                assignment_id=assignment_id,
                action=review_action,
                score=score,
                comments=comments
            )
            
            if not success:
                logger.error(f"Failed to submit review for assignment {assignment_id}")
                return False
            
            # Commit review to current branch
            if context.current_branch:
                commit_message = f"Review submitted: {action}"
                if score:
                    commit_message += f" (score: {score})"
                if comments:
                    commit_message += f"\n\nComments:\n" + "\n".join(comments)
                
                self.branching_strategy.commit_changes(
                    branch_name=context.current_branch,
                    message=commit_message
                )
            
            # Send notifications
            if self.config["integration"]["auto_send_notifications"]:
                # Notify author of review completion
                notification_ids = self.notification_system.create_notification(
                    trigger=NotificationTrigger.REVIEW_SUBMITTED,
                    recipients=[context.author],
                    context={
                        "content_id": content_id,
                        "content_title": Path(context.content_path).stem,
                        "author_name": context.author,
                        "reviewer_name": "Reviewer",  # Would get from assignment
                        "review_action": action,
                        "review_score": score,
                        "review_comments": "\n".join(comments) if comments else "",
                        "workflow_url": f"/workflow/{context.workflow_instance_id}"
                    }
                )
                context.notification_history.extend(notification_ids)
            
            # Update context
            self._save_active_contexts()
            
            logger.info(f"Review submitted for {content_id}: {action}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to submit review for {content_id}: {e}")
            return False
    
    def complete_workflow(self, content_id: str) -> bool:
        """
        Complete workflow and publish content
        
        Args:
            content_id: Content identifier
        
        Returns:
            Success status
        """
        if content_id not in self.active_contexts:
            logger.error(f"No active context found for content {content_id}")
            return False
        
        context = self.active_contexts[content_id]
        
        try:
            # Get final workflow status
            workflow_status = self.workflow_orchestrator.get_workflow_status(
                context.workflow_instance_id
            )
            
            if not workflow_status or workflow_status["current_stage"] != "published":
                logger.error(f"Workflow {context.workflow_instance_id} not ready for completion")
                return False
            
            # Merge final branch to main
            if context.current_branch:
                success = self.branching_strategy.merge_branch(
                    source_branch=context.current_branch,
                    target_branch="main",
                    merge_strategy=MergeStrategy.SQUASH_MERGE
                )
                
                if not success:
                    logger.error(f"Failed to merge branch {context.current_branch}")
                    return False
            
            # Create publication tag
            tag_name = f"published/{content_id}/{datetime.now().strftime('%Y%m%d')}"
            self.branching_strategy.create_tag(
                tag_name=tag_name,
                message=f"Published content: {content_id}"
            )
            
            # Send completion notifications
            if self.config["integration"]["auto_send_notifications"]:
                notification_ids = self.notification_system.create_notification(
                    trigger=NotificationTrigger.WORKFLOW_COMPLETED,
                    recipients=[context.author],
                    context={
                        "content_id": content_id,
                        "content_title": Path(context.content_path).stem,
                        "author_name": context.author,
                        "final_score": workflow_status.get("overall_score"),
                        "publication_date": datetime.now().isoformat(),
                        "published_url": f"/content/{content_id}"
                    }
                )
                context.notification_history.extend(notification_ids)
            
            # Archive context
            context.metadata["completion_date"] = datetime.now().isoformat()
            context.metadata["final_status"] = "published"
            
            # Remove from active contexts
            del self.active_contexts[content_id]
            self._save_active_contexts()
            
            logger.info(f"Workflow completed successfully for {content_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to complete workflow for {content_id}: {e}")
            return False
    
    def migrate_content_batch(self, migration_plan_id: str, file_patterns: List[str],
                            dry_run: bool = True) -> Dict[str, Any]:
        """
        Execute batch content migration
        
        Args:
            migration_plan_id: Migration plan identifier
            file_patterns: File patterns to migrate
            dry_run: Whether to run in dry-run mode
        
        Returns:
            Migration results
        """
        try:
            # Create migration plan
            plan = self.migrator.create_migration_plan(
                plan_id=migration_plan_id,
                name=f"Batch Migration {migration_plan_id}",
                description="Automated batch content migration",
                rule_ids=["template_update", "metadata_update"],  # Would be configurable
                file_patterns=file_patterns,
                dry_run=dry_run
            )
            
            # Execute migration
            history = self.migrator.execute_migration_plan(plan, "integration_manager")
            
            # Send notification summary
            if self.config["integration"]["auto_send_notifications"] and not dry_run:
                # Get admin recipients
                admin_recipients = ["admin"]  # Would be configurable
                
                notification_ids = self.notification_system.create_notification(
                    trigger=NotificationTrigger.WORKFLOW_COMPLETED,  # Reusing for migration
                    recipients=admin_recipients,
                    context={
                        "migration_plan": migration_plan_id,
                        "total_files": history.total_files,
                        "successful_files": history.successful_files,
                        "failed_files": history.failed_files,
                        "duration": history.total_duration
                    }
                )
            
            return {
                "migration_id": history.migration_id,
                "total_files": history.total_files,
                "successful_files": history.successful_files,
                "failed_files": history.failed_files,
                "duration": history.total_duration,
                "rollback_available": history.rollback_available
            }
            
        except Exception as e:
            logger.error(f"Failed to execute batch migration: {e}")
            return {"error": str(e)}
    
    def get_system_status(self) -> Dict[str, Any]:
        """Get comprehensive system status"""
        try:
            # Get component metrics
            active_workflows = self.workflow_orchestrator.list_active_workflows()
            active_branches = self.branching_strategy.list_branches(status=BranchStatus.ACTIVE)
            
            # Calculate uptime
            uptime = (datetime.now() - self.start_time).total_seconds() / 3600
            
            metrics = IntegrationMetrics(
                active_workflows=len(active_workflows),
                active_branches=len(active_branches),
                pending_notifications=len(self.notification_system.message_queue),
                recent_migrations=len([m for m in self.migrator.migration_history 
                                     if datetime.fromisoformat(m.execution_date.replace('Z', '+00:00')).replace(tzinfo=None) 
                                     > datetime.now() - timedelta(days=7)]),
                error_count=0,  # Would track errors
                uptime_hours=uptime
            )
            
            return {
                "status": self.status.value,
                "metrics": asdict(metrics),
                "components": {
                    "cms": "active",
                    "workflow_orchestrator": "active",
                    "branching_strategy": "active", 
                    "notification_system": "active",
                    "migrator": "active"
                },
                "active_contexts": len(self.active_contexts),
                "configuration": {
                    "auto_create_branches": self.config["integration"]["auto_create_branches"],
                    "auto_assign_reviewers": self.config["integration"]["auto_assign_reviewers"],
                    "auto_send_notifications": self.config["integration"]["auto_send_notifications"],
                    "max_concurrent_workflows": self.config["integration"]["max_concurrent_workflows"]
                }
            }
            
        except Exception as e:
            logger.error(f"Failed to get system status: {e}")
            return {"status": "error", "error": str(e)}
    
    def generate_integration_report(self, start_date: Optional[str] = None,
                                  end_date: Optional[str] = None) -> Dict[str, Any]:
        """Generate comprehensive integration report"""
        try:
            # Get workflow report
            workflow_report = self.workflow_orchestrator.generate_workflow_report(start_date, end_date)
            
            # Get branching report
            branching_report = self.branching_strategy.generate_branching_report()
            
            # Get notification report
            notification_report = self.notification_system.generate_delivery_report(start_date, end_date)
            
            # Get migration report
            migration_report = self.migrator.generate_migration_report()
            
            # Combine reports
            integration_report = {
                "generated": datetime.now().isoformat(),
                "period": {
                    "start": start_date,
                    "end": end_date
                },
                "summary": {
                    "total_workflows": workflow_report.get("summary", {}).get("total_workflows", 0),
                    "total_branches": branching_report.get("summary", {}).get("total_branches", 0),
                    "total_notifications": asdict(notification_report).get("total_notifications", 0),
                    "total_migrations": migration_report.get("summary", {}).get("total_migrations", 0)
                },
                "workflows": workflow_report,
                "branching": branching_report,
                "notifications": asdict(notification_report),
                "migrations": migration_report,
                "system_status": self.get_system_status()
            }
            
            return integration_report
            
        except Exception as e:
            logger.error(f"Failed to generate integration report: {e}")
            return {"error": str(e)}
    
    def shutdown(self):
        """Shutdown the integration manager"""
        logger.info("Shutting down Workflow Integration Manager")
        
        try:
            # Stop notification scheduler
            self.notification_system.stop_scheduler()
            
            # Save final state
            self._save_active_contexts()
            
            # Update status
            self.status = IntegrationStatus.MAINTENANCE
            
            logger.info("Workflow Integration Manager shutdown complete")
            
        except Exception as e:
            logger.error(f"Error during shutdown: {e}")


async def main():
    """Main function for testing integration"""
    # Initialize integration manager
    integration_manager = WorkflowIntegrationManager(".")
    
    try:
        # Test workflow creation
        workflow_id = integration_manager.start_content_workflow(
            content_id="test-chapter-01",
            content_path="chapters/01-introduction/README.md",
            author="test-author",
            initial_metadata={"chapter": "01", "topic": "introduction"}
        )
        
        print(f"Created workflow: {workflow_id}")
        
        # Get system status
        status = integration_manager.get_system_status()
        print(f"System status: {status['status']}")
        print(f"Active workflows: {status['metrics']['active_workflows']}")
        
        # Generate report
        report = integration_manager.generate_integration_report()
        print(f"Integration report generated with {report['summary']['total_workflows']} workflows")
        
    except Exception as e:
        logger.error(f"Integration test failed: {e}")
    
    finally:
        # Shutdown
        integration_manager.shutdown()


if __name__ == "__main__":
    import asyncio
    asyncio.run(main())