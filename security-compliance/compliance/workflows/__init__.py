"""
Compliance Workflow Manager
===========================

Automated compliance workflow management with approval processes,
digital signatures, and change management integration.

Classification: UNCLASSIFIED//FOR OFFICIAL USE ONLY
Version: 1.0
Author: Security Compliance Team
"""

from .workflow_manager import WorkflowManager
from .approval_workflow import ApprovalWorkflow
from .digital_signature_manager import DigitalSignatureManager
from .change_management import ChangeManagement

__all__ = [
    'WorkflowManager',
    'ApprovalWorkflow',
    'DigitalSignatureManager',
    'ChangeManagement'
]