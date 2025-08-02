"""
Content Management System Core Module
====================================

Core functionality for the Git-based Chapter Content Management System.
Provides template management, content validation, and workflow automation.

Modules:
    cms_engine: Main CMS engine and orchestration
    template_manager: Template creation and management
    metadata_manager: Content metadata handling
    validation_engine: Content validation and quality checks
    workflow_manager: Git-based workflow management

Author: Claude Code Implementation
Version: 1.0.0
"""

from .cms_engine import ContentManagementEngine
from .template_manager import TemplateManager
from .metadata_manager import MetadataManager
from .validation_engine import ValidationEngine
from .workflow_manager import WorkflowManager

__version__ = "1.0.0"
__author__ = "Claude Code Implementation"

__all__ = [
    "ContentManagementEngine",
    "TemplateManager", 
    "MetadataManager",
    "ValidationEngine",
    "WorkflowManager"
]