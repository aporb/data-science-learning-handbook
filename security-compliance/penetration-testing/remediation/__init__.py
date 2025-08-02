"""
Remediation Workflow Engine Module
==================================

Advanced remediation workflow automation that provides intelligent task generation,
assignment, tracking, and verification for vulnerability remediation activities.

Components:
- RemediationWorkflowEngine: Main workflow orchestration engine
- TaskGenerator: Automated remediation task generation
- AssignmentEngine: Intelligent task assignment and routing
- WorkflowTracker: Task tracking and progress monitoring
- SLAMonitor: SLA monitoring and escalation management
- VerificationEngine: Remediation verification and validation
- IntegrationManager: External system integration (ticketing, ITSM)
- NotificationService: Real-time notifications and alerting
"""

from .workflow_engine import RemediationWorkflowEngine
from .task_generator import TaskGenerator
from .assignment_engine import AssignmentEngine
from .workflow_tracker import WorkflowTracker
from .sla_monitor import SLAMonitor
from .verification_engine import VerificationEngine
from .integration_manager import IntegrationManager
from .notification_service import NotificationService

__all__ = [
    'RemediationWorkflowEngine',
    'TaskGenerator',
    'AssignmentEngine',
    'WorkflowTracker',
    'SLAMonitor',
    'VerificationEngine',
    'IntegrationManager',
    'NotificationService'
]