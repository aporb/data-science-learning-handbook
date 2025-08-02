#!/usr/bin/env python3
"""
Content Management System Engine
===============================

Main orchestration engine for the Git-based Chapter Content Management System.
Coordinates template management, content validation, and workflow operations.

This module provides:
- Centralized CMS operations
- Template-based content generation
- Validation and quality assurance
- Git workflow integration
- Metadata management

Author: Claude Code Implementation
Version: 1.0.0
"""

import os
import json
import logging
from pathlib import Path
from typing import Dict, List, Optional, Any, Union
from datetime import datetime
from dataclasses import dataclass, asdict

from .template_manager import TemplateManager
from .metadata_manager import MetadataManager
from .validation_engine import ValidationEngine
from .workflow_manager import WorkflowManager

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@dataclass
class ContentSpec:
    """Content specification for generation"""
    template_type: str
    chapter_id: str
    title: str
    author: str
    platforms: List[str]
    learning_objectives: List[str]
    prerequisites: List[str]
    difficulty_level: str
    estimated_time: str
    tags: List[str]
    custom_sections: Optional[Dict[str, Any]] = None


@dataclass
class GenerationResult:
    """Result of content generation operation"""
    success: bool
    generated_files: List[Path]
    validation_results: Dict[str, Any]
    warnings: List[str]
    errors: List[str]
    metadata: Optional[Dict[str, Any]] = None


class ContentManagementEngine:
    """
    Main Content Management System Engine
    
    Orchestrates all CMS operations including template management,
    content generation, validation, and workflow integration.
    """
    
    def __init__(self, 
                 repo_path: Union[str, Path],
                 config_path: Optional[Union[str, Path]] = None):
        """
        Initialize the CMS Engine
        
        Args:
            repo_path: Path to the Git repository
            config_path: Optional path to configuration file
        """
        self.repo_path = Path(repo_path)
        self.cms_path = self.repo_path / "content-management"
        self.config_path = config_path or self.cms_path / "config.json"
        
        # Load configuration
        self.config = self._load_config()
        
        # Initialize managers
        self.template_manager = TemplateManager(self.cms_path, self.config)
        self.metadata_manager = MetadataManager(self.repo_path, self.config)
        self.validation_engine = ValidationEngine(self.repo_path, self.config)
        self.workflow_manager = WorkflowManager(self.repo_path, self.config)
        
        # Ensure directory structure
        self._ensure_directories()
        
        logger.info(f"CMS Engine initialized for repository: {self.repo_path}")
    
    def _load_config(self) -> Dict[str, Any]:
        """Load CMS configuration"""
        default_config = {
            "templates": {
                "base_path": "content-management/templates",
                "supported_types": ["chapter", "section", "exercise", "platform"],
                "auto_sync": True
            },
            "content": {
                "chapters_path": "chapters",
                "templates_path": "templates", 
                "validation_path": "validation",
                "supported_formats": [".md", ".ipynb", ".py", ".R", ".sql"]
            },
            "validation": {
                "auto_validate": True,
                "minimum_score": 80.0,
                "required_sections": ["learning_objectives", "content", "exercises"],
                "check_links": True,
                "check_code": True
            },
            "workflow": {
                "auto_branch": True,
                "branch_prefix": "content/",
                "review_required": True,
                "merge_strategy": "squash"
            },
            "metadata": {
                "required_fields": ["title", "chapter_id", "author", "platforms"],
                "auto_update": True,
                "track_changes": True
            }
        }
        
        if self.config_path.exists():
            try:
                with open(self.config_path, 'r') as f:
                    user_config = json.load(f)
                    # Deep merge configuration
                    for key, value in user_config.items():
                        if isinstance(value, dict) and key in default_config:
                            default_config[key].update(value)
                        else:
                            default_config[key] = value
            except Exception as e:
                logger.warning(f"Failed to load config from {self.config_path}: {e}")
        
        return default_config
    
    def _ensure_directories(self):
        """Ensure all required directories exist"""
        directories = [
            self.cms_path / "templates" / "chapter",
            self.cms_path / "templates" / "section", 
            self.cms_path / "templates" / "exercise",
            self.cms_path / "templates" / "platform",
            self.cms_path / "schemas",
            self.cms_path / "scripts",
            self.cms_path / "workflows",
            self.cms_path / "examples",
            self.repo_path / self.config["content"]["chapters_path"],
            self.repo_path / self.config["content"]["validation_path"] / "reports"
        ]
        
        for directory in directories:
            directory.mkdir(parents=True, exist_ok=True)
    
    def generate_content(self, spec: ContentSpec) -> GenerationResult:
        """
        Generate content from specification
        
        Args:
            spec: Content specification
            
        Returns:
            Generation result with files created and validation status
        """
        logger.info(f"Generating content: {spec.chapter_id} - {spec.title}")
        
        result = GenerationResult(
            success=False,
            generated_files=[],
            validation_results={},
            warnings=[],
            errors=[]
        )
        
        try:
            # Create Git branch if configured
            if self.config["workflow"]["auto_branch"]:
                branch_name = self.workflow_manager.create_content_branch(
                    spec.chapter_id, "feature"
                )
                logger.info(f"Created branch: {branch_name}")
            
            # Generate content from template
            template_result = self.template_manager.generate_from_template(
                spec.template_type,
                {
                    "chapter_id": spec.chapter_id,
                    "title": spec.title,
                    "author": spec.author,
                    "platforms": spec.platforms,
                    "learning_objectives": spec.learning_objectives,
                    "prerequisites": spec.prerequisites,
                    "difficulty_level": spec.difficulty_level,
                    "estimated_time": spec.estimated_time,
                    "tags": spec.tags,
                    "custom_sections": spec.custom_sections or {},
                    "generated_date": datetime.now().isoformat()
                }
            )
            
            if not template_result["success"]:
                result.errors.extend(template_result["errors"])
                return result
            
            result.generated_files = template_result["files"]
            
            # Create and update metadata
            metadata = self.metadata_manager.create_metadata(spec)
            
            # Update files with metadata
            for file_path in result.generated_files:
                if self.metadata_manager.update_file_metadata(file_path, metadata):
                    logger.info(f"Updated metadata for: {file_path}")
                else:
                    result.warnings.append(f"Failed to update metadata for: {file_path}")
            
            # Validate generated content if configured
            if self.config["validation"]["auto_validate"]:
                validation_results = {}
                for file_path in result.generated_files:
                    validation_result = self.validation_engine.validate_content(file_path)
                    validation_results[str(file_path)] = validation_result
                    
                    if not validation_result["passed"]:
                        result.warnings.extend(validation_result.get("warnings", []))
                        if validation_result.get("errors"):
                            result.errors.extend(validation_result["errors"])
                
                result.validation_results = validation_results
            
            # Set metadata in result
            result.metadata = asdict(metadata)
            result.success = len(result.errors) == 0
            
            logger.info(f"Content generation {'completed' if result.success else 'completed with errors'}")
            
        except Exception as e:
            result.errors.append(f"Content generation failed: {str(e)}")
            logger.error(f"Content generation failed: {e}")
        
        return result
    
    def validate_content(self, 
                        content_path: Union[str, Path],
                        validate_metadata: bool = True,
                        validate_structure: bool = True,
                        validate_links: bool = True) -> Dict[str, Any]:
        """
        Comprehensive content validation
        
        Args:
            content_path: Path to content to validate
            validate_metadata: Whether to validate metadata
            validate_structure: Whether to validate structure
            validate_links: Whether to validate links
            
        Returns:
            Comprehensive validation results
        """
        content_path = Path(content_path)
        logger.info(f"Validating content: {content_path}")
        
        validation_result = {
            "file_path": str(content_path),
            "timestamp": datetime.now().isoformat(),
            "overall_passed": False,
            "overall_score": 0.0,
            "checks": {},
            "warnings": [],
            "errors": []
        }
        
        try:
            # Structure validation
            if validate_structure:
                structure_result = self.validation_engine.validate_structure(content_path)
                validation_result["checks"]["structure"] = structure_result
                
                if not structure_result["passed"]:
                    validation_result["errors"].extend(structure_result.get("errors", []))
                    validation_result["warnings"].extend(structure_result.get("warnings", []))
            
            # Metadata validation
            if validate_metadata:
                metadata_result = self.validation_engine.validate_metadata(content_path)
                validation_result["checks"]["metadata"] = metadata_result
                
                if not metadata_result["passed"]:
                    validation_result["errors"].extend(metadata_result.get("errors", []))
                    validation_result["warnings"].extend(metadata_result.get("warnings", []))
            
            # Link validation
            if validate_links and self.config["validation"]["check_links"]:
                link_result = self.validation_engine.validate_links(content_path)
                validation_result["checks"]["links"] = link_result
                
                if not link_result["passed"]:
                    validation_result["warnings"].extend(link_result.get("warnings", []))
            
            # Calculate overall score and status
            check_scores = [
                check.get("score", 0.0) for check in validation_result["checks"].values()
            ]
            
            if check_scores:
                validation_result["overall_score"] = sum(check_scores) / len(check_scores)
                validation_result["overall_passed"] = (
                    validation_result["overall_score"] >= self.config["validation"]["minimum_score"]
                    and len(validation_result["errors"]) == 0
                )
            
        except Exception as e:
            validation_result["errors"].append(f"Validation failed: {str(e)}")
            logger.error(f"Content validation failed: {e}")
        
        return validation_result
    
    def update_templates(self, template_type: Optional[str] = None) -> Dict[str, Any]:
        """
        Update templates from source
        
        Args:
            template_type: Specific template type to update (None for all)
            
        Returns:
            Update operation results
        """
        logger.info(f"Updating templates: {template_type or 'all'}")
        
        return self.template_manager.sync_templates(template_type)
    
    def list_content(self, 
                    chapter_filter: Optional[str] = None,
                    status_filter: Optional[str] = None,
                    platform_filter: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        List content with optional filtering
        
        Args:
            chapter_filter: Filter by chapter ID
            status_filter: Filter by content status
            platform_filter: Filter by platform
            
        Returns:
            List of content items with metadata
        """
        return self.metadata_manager.list_content(
            chapter_filter=chapter_filter,
            status_filter=status_filter,
            platform_filter=platform_filter
        )
    
    def generate_report(self, report_type: str = "comprehensive") -> Dict[str, Any]:
        """
        Generate CMS report
        
        Args:
            report_type: Type of report to generate
            
        Returns:
            Generated report data
        """
        logger.info(f"Generating {report_type} report")
        
        report = {
            "timestamp": datetime.now().isoformat(),
            "report_type": report_type,
            "repository": str(self.repo_path),
            "cms_version": "1.0.0"
        }
        
        if report_type == "comprehensive":
            # Content summary
            content_list = self.list_content()
            report["content_summary"] = {
                "total_files": len(content_list),
                "by_chapter": {},
                "by_platform": {},
                "by_status": {}
            }
            
            for content in content_list:
                # By chapter
                chapter = content.get("chapter_id", "unknown")
                report["content_summary"]["by_chapter"][chapter] = (
                    report["content_summary"]["by_chapter"].get(chapter, 0) + 1
                )
                
                # By platform
                for platform in content.get("platforms", []):
                    report["content_summary"]["by_platform"][platform] = (
                        report["content_summary"]["by_platform"].get(platform, 0) + 1
                    )
                
                # By status
                status = content.get("status", "unknown")
                report["content_summary"]["by_status"][status] = (
                    report["content_summary"]["by_status"].get(status, 0) + 1
                )
            
            # Template summary
            report["template_summary"] = self.template_manager.get_template_summary()
            
            # Validation summary
            report["validation_summary"] = self.validation_engine.get_validation_summary()
            
            # Workflow summary
            report["workflow_summary"] = self.workflow_manager.get_workflow_summary()
        
        return report
    
    def migrate_content(self, migration_spec: Dict[str, Any]) -> Dict[str, Any]:
        """
        Migrate content based on specification
        
        Args:
            migration_spec: Migration specification
            
        Returns:
            Migration results
        """
        logger.info("Starting content migration")
        
        migration_result = {
            "success": False,
            "migrated_files": [],
            "warnings": [],
            "errors": [],
            "timestamp": datetime.now().isoformat()
        }
        
        try:
            # Implementation would depend on specific migration needs
            # This is a placeholder for the migration framework
            
            # Example migration operations:
            # - Template format updates
            # - Metadata schema changes
            # - Directory structure reorganization
            # - Platform-specific content updates
            
            migration_result["success"] = True
            logger.info("Content migration completed successfully")
            
        except Exception as e:
            migration_result["errors"].append(f"Migration failed: {str(e)}")
            logger.error(f"Content migration failed: {e}")
        
        return migration_result
    
    def cleanup_content(self, dry_run: bool = True) -> Dict[str, Any]:
        """
        Clean up orphaned or invalid content
        
        Args:
            dry_run: If True, only report what would be cleaned
            
        Returns:
            Cleanup operation results
        """
        logger.info(f"Starting content cleanup (dry_run={dry_run})")
        
        cleanup_result = {
            "dry_run": dry_run,
            "files_to_remove": [],
            "files_to_fix": [],
            "warnings": [],
            "errors": [],
            "timestamp": datetime.now().isoformat()
        }
        
        try:
            # Find orphaned files
            content_files = self.list_content()
            
            for content in content_files:
                file_path = Path(content.get("file_path", ""))
                
                # Check if file exists
                if not file_path.exists():
                    cleanup_result["files_to_remove"].append(str(file_path))
                    continue
                
                # Validate content
                validation_result = self.validate_content(file_path, validate_links=False)
                
                if not validation_result["overall_passed"]:
                    if validation_result["errors"]:
                        cleanup_result["files_to_fix"].append({
                            "file": str(file_path),
                            "issues": validation_result["errors"]
                        })
            
            # Perform cleanup if not dry run
            if not dry_run:
                # Remove orphaned files
                for file_path in cleanup_result["files_to_remove"]:
                    try:
                        Path(file_path).unlink()
                        logger.info(f"Removed orphaned file: {file_path}")
                    except Exception as e:
                        cleanup_result["warnings"].append(f"Failed to remove {file_path}: {e}")
                
                # Fix fixable issues (implementation specific)
                # This would involve automated fixes for common issues
            
            logger.info(f"Content cleanup completed")
            
        except Exception as e:
            cleanup_result["errors"].append(f"Cleanup failed: {str(e)}")
            logger.error(f"Content cleanup failed: {e}")
        
        return cleanup_result


def main():
    """Main function for CLI usage"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Content Management System Engine")
    parser.add_argument("--repo", default=".", help="Repository path")
    parser.add_argument("--config", help="Configuration file path")
    parser.add_argument("--command", required=True,
                       choices=["generate", "validate", "list", "report", "update-templates", "cleanup"],
                       help="Command to execute")
    parser.add_argument("--template-type", default="chapter", help="Template type for generation")
    parser.add_argument("--chapter-id", help="Chapter ID")
    parser.add_argument("--title", help="Content title")
    parser.add_argument("--author", help="Content author")
    parser.add_argument("--platforms", nargs="+", default=["python", "r"], help="Target platforms")
    parser.add_argument("--output", help="Output file path")
    parser.add_argument("--dry-run", action="store_true", help="Dry run mode")
    
    args = parser.parse_args()
    
    try:
        cms = ContentManagementEngine(args.repo, args.config)
        
        if args.command == "generate":
            if not args.chapter_id or not args.title or not args.author:
                print("Error: chapter-id, title, and author are required for generation")
                return
            
            spec = ContentSpec(
                template_type=args.template_type,
                chapter_id=args.chapter_id,
                title=args.title,
                author=args.author,
                platforms=args.platforms,
                learning_objectives=["To be defined"],
                prerequisites=["Basic understanding"],
                difficulty_level="Intermediate",
                estimated_time="2-3 hours",
                tags=["data-science", "tutorial"]
            )
            
            result = cms.generate_content(spec)
            print(f"Generation {'successful' if result.success else 'failed'}")
            print(f"Files created: {len(result.generated_files)}")
            
            if result.warnings:
                print(f"Warnings: {len(result.warnings)}")
                for warning in result.warnings:
                    print(f"  - {warning}")
            
            if result.errors:
                print(f"Errors: {len(result.errors)}")
                for error in result.errors:
                    print(f"  - {error}")
        
        elif args.command == "validate":
            if not args.chapter_id:
                print("Error: chapter-id is required for validation")
                return
            
            chapter_path = Path(args.repo) / "chapters" / args.chapter_id
            if not chapter_path.exists():
                print(f"Error: Chapter path does not exist: {chapter_path}")
                return
            
            # Validate all files in chapter
            for file_path in chapter_path.rglob("*.md"):
                result = cms.validate_content(file_path)
                status = "✓" if result["overall_passed"] else "✗"
                print(f"{status} {file_path.relative_to(Path(args.repo))}: {result['overall_score']:.1f}%")
                
                if result["errors"]:
                    for error in result["errors"]:
                        print(f"    ERROR: {error}")
        
        elif args.command == "list":
            content_list = cms.list_content()
            print(f"Found {len(content_list)} content files:")
            
            for content in content_list:
                print(f"  {content.get('chapter_id', 'N/A')}: {content.get('title', 'Untitled')} "
                      f"({content.get('status', 'unknown')})")
        
        elif args.command == "report":
            report = cms.generate_report()
            
            if args.output:
                with open(args.output, 'w') as f:
                    json.dump(report, f, indent=2)
                print(f"Report saved to {args.output}")
            else:
                print(json.dumps(report, indent=2))
        
        elif args.command == "update-templates":
            result = cms.update_templates(args.template_type)
            print(f"Template update {'successful' if result['success'] else 'failed'}")
            
            if result.get("updated"):
                print(f"Updated templates: {', '.join(result['updated'])}")
        
        elif args.command == "cleanup":
            result = cms.cleanup_content(dry_run=args.dry_run)
            mode = "Dry run" if result["dry_run"] else "Cleanup"
            print(f"{mode} completed")
            
            if result["files_to_remove"]:
                print(f"Files to remove: {len(result['files_to_remove'])}")
                for file_path in result["files_to_remove"]:
                    print(f"  - {file_path}")
            
            if result["files_to_fix"]:
                print(f"Files to fix: {len(result['files_to_fix'])}")
                for file_info in result["files_to_fix"]:
                    print(f"  - {file_info['file']}: {len(file_info['issues'])} issues")
    
    except Exception as e:
        logger.error(f"Command failed: {e}")
        print(f"Error: {e}")
        return 1


if __name__ == "__main__":
    exit(main())