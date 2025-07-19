#!/usr/bin/env python3
"""
Content Management System for Data Science Learning Handbook
============================================================

A comprehensive Git-based content management system that provides:
- Branch-based content review and approval workflows
- Automated content validation and quality checks
- Version control operations for educational content
- Content migration and deployment tools
- Integration with validation frameworks

Author: Claude Code Implementation
Created: 2025-07-18
Version: 1.0.0
"""

import os
import sys
import git
import json
import shutil
import logging
import subprocess
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
from pathlib import Path
from dataclasses import dataclass, asdict
from enum import Enum
import yaml
from jinja2 import Environment, FileSystemLoader, Template


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class ContentStatus(Enum):
    """Content status enumeration"""
    DRAFT = "draft"
    REVIEW = "review"
    APPROVED = "approved"
    PUBLISHED = "published"
    ARCHIVED = "archived"


class ReviewStage(Enum):
    """Review stage enumeration"""
    TECHNICAL = "technical"
    EDUCATIONAL = "educational"
    BIAS_ASSESSMENT = "bias_assessment"
    SECURITY = "security"
    FINAL_APPROVAL = "final_approval"


@dataclass
class ContentMetadata:
    """Content metadata structure"""
    title: str
    chapter_id: str
    content_type: str
    author: str
    created_date: str
    modified_date: str
    status: ContentStatus
    review_stage: Optional[ReviewStage]
    validation_score: Optional[float]
    bias_score: Optional[float]
    reviewers: List[str]
    platforms: List[str]
    tags: List[str]
    dependencies: List[str]


@dataclass
class ValidationResult:
    """Validation result structure"""
    overall_score: float
    technical_accuracy: float
    currency_relevance: float
    educational_effectiveness: float
    compliance_security: float
    implementation_feasibility: float
    passed: bool
    issues: List[str]
    recommendations: List[str]
    timestamp: str


class ContentManagementSystem:
    """
    Comprehensive Content Management System for educational content
    """
    
    def __init__(self, repo_path: str, config_path: Optional[str] = None):
        """
        Initialize the Content Management System
        
        Args:
            repo_path: Path to the Git repository
            config_path: Path to configuration file
        """
        self.repo_path = Path(repo_path)
        self.config_path = config_path or self.repo_path / "validation" / "cms_config.json"
        self.content_dir = self.repo_path / "chapters"
        self.validation_dir = self.repo_path / "validation"
        self.templates_dir = self.repo_path / "templates" / "chapter"
        
        # Initialize Git repository
        try:
            self.repo = git.Repo(self.repo_path)
        except git.InvalidGitRepositoryError:
            raise ValueError(f"Invalid Git repository at {self.repo_path}")
        
        # Load configuration
        self.config = self._load_config()
        
        # Initialize Jinja2 environment
        self.jinja_env = Environment(
            loader=FileSystemLoader(str(self.templates_dir)),
            autoescape=True
        )
        
        # Ensure required directories exist
        self._ensure_directories()
        
        logger.info(f"Content Management System initialized for {self.repo_path}")
    
    def _load_config(self) -> Dict[str, Any]:
        """Load CMS configuration"""
        default_config = {
            "validation": {
                "minimum_score": 80.0,
                "required_checks": ["technical", "educational", "bias", "security"],
                "auto_validation": True
            },
            "workflow": {
                "review_stages": ["technical", "educational", "bias_assessment", "security", "final_approval"],
                "required_approvals": 2,
                "auto_merge_threshold": 95.0
            },
            "content": {
                "supported_formats": [".md", ".ipynb", ".py"],
                "required_metadata": ["title", "chapter_id", "author", "platforms"],
                "template_validation": True
            },
            "branches": {
                "main_branch": "main",
                "content_prefix": "content/",
                "review_prefix": "review/",
                "hotfix_prefix": "hotfix/"
            }
        }
        
        if self.config_path.exists():
            try:
                with open(self.config_path, 'r') as f:
                    user_config = json.load(f)
                    # Merge with defaults
                    for key, value in user_config.items():
                        if isinstance(value, dict) and key in default_config:
                            default_config[key].update(value)
                        else:
                            default_config[key] = value
            except Exception as e:
                logger.warning(f"Failed to load config from {self.config_path}: {e}")
        
        return default_config
    
    def _ensure_directories(self):
        """Ensure required directories exist"""
        directories = [
            self.content_dir,
            self.validation_dir,
            self.templates_dir,
            self.validation_dir / "reports",
            self.validation_dir / "schemas",
            self.validation_dir / "workflows"
        ]
        
        for directory in directories:
            directory.mkdir(parents=True, exist_ok=True)
    
    def create_content_branch(self, chapter_id: str, content_type: str = "feature") -> str:
        """
        Create a new content branch for development
        
        Args:
            chapter_id: Chapter identifier
            content_type: Type of content change (feature, update, hotfix)
        
        Returns:
            Branch name created
        """
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        branch_name = f"{self.config['branches']['content_prefix']}{chapter_id}-{content_type}-{timestamp}"
        
        # Ensure we're on the main branch
        main_branch = self.config['branches']['main_branch']
        self.repo.git.checkout(main_branch)
        self.repo.git.pull('origin', main_branch)
        
        # Create new branch
        self.repo.git.checkout('-b', branch_name)
        
        logger.info(f"Created content branch: {branch_name}")
        return branch_name
    
    def create_review_branch(self, content_branch: str) -> str:
        """
        Create a review branch from content branch
        
        Args:
            content_branch: Source content branch
        
        Returns:
            Review branch name
        """
        review_branch = content_branch.replace(
            self.config['branches']['content_prefix'],
            self.config['branches']['review_prefix']
        )
        
        # Create review branch from content branch
        self.repo.git.checkout(content_branch)
        self.repo.git.checkout('-b', review_branch)
        
        logger.info(f"Created review branch: {review_branch}")
        return review_branch
    
    def get_content_metadata(self, file_path: Path) -> Optional[ContentMetadata]:
        """
        Extract metadata from content file
        
        Args:
            file_path: Path to content file
        
        Returns:
            ContentMetadata object or None
        """
        try:
            if file_path.suffix == '.md':
                return self._extract_markdown_metadata(file_path)
            elif file_path.suffix == '.ipynb':
                return self._extract_notebook_metadata(file_path)
            else:
                logger.warning(f"Unsupported file type for metadata extraction: {file_path}")
                return None
        except Exception as e:
            logger.error(f"Failed to extract metadata from {file_path}: {e}")
            return None
    
    def _extract_markdown_metadata(self, file_path: Path) -> Optional[ContentMetadata]:
        """Extract metadata from Markdown file frontmatter"""
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Look for YAML frontmatter
        if content.startswith('---'):
            try:
                frontmatter_end = content.find('---', 3)
                if frontmatter_end > 0:
                    frontmatter = content[3:frontmatter_end].strip()
                    metadata = yaml.safe_load(frontmatter)
                    
                    return ContentMetadata(
                        title=metadata.get('title', file_path.stem),
                        chapter_id=metadata.get('chapter_id', ''),
                        content_type=metadata.get('content_type', 'chapter'),
                        author=metadata.get('author', ''),
                        created_date=metadata.get('created_date', ''),
                        modified_date=metadata.get('modified_date', ''),
                        status=ContentStatus(metadata.get('status', 'draft')),
                        review_stage=ReviewStage(metadata.get('review_stage')) if metadata.get('review_stage') else None,
                        validation_score=metadata.get('validation_score'),
                        bias_score=metadata.get('bias_score'),
                        reviewers=metadata.get('reviewers', []),
                        platforms=metadata.get('platforms', []),
                        tags=metadata.get('tags', []),
                        dependencies=metadata.get('dependencies', [])
                    )
            except Exception as e:
                logger.error(f"Failed to parse YAML frontmatter in {file_path}: {e}")
        
        return None
    
    def _extract_notebook_metadata(self, file_path: Path) -> Optional[ContentMetadata]:
        """Extract metadata from Jupyter notebook"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                notebook = json.load(f)
            
            metadata = notebook.get('metadata', {}).get('handbook', {})
            
            return ContentMetadata(
                title=metadata.get('title', file_path.stem),
                chapter_id=metadata.get('chapter_id', ''),
                content_type='notebook',
                author=metadata.get('author', ''),
                created_date=metadata.get('created_date', ''),
                modified_date=metadata.get('modified_date', ''),
                status=ContentStatus(metadata.get('status', 'draft')),
                review_stage=ReviewStage(metadata.get('review_stage')) if metadata.get('review_stage') else None,
                validation_score=metadata.get('validation_score'),
                bias_score=metadata.get('bias_score'),
                reviewers=metadata.get('reviewers', []),
                platforms=metadata.get('platforms', []),
                tags=metadata.get('tags', []),
                dependencies=metadata.get('dependencies', [])
            )
        except Exception as e:
            logger.error(f"Failed to parse notebook metadata in {file_path}: {e}")
            return None
    
    def update_content_metadata(self, file_path: Path, metadata: ContentMetadata) -> bool:
        """
        Update content file metadata
        
        Args:
            file_path: Path to content file
            metadata: Updated metadata
        
        Returns:
            Success status
        """
        try:
            if file_path.suffix == '.md':
                return self._update_markdown_metadata(file_path, metadata)
            elif file_path.suffix == '.ipynb':
                return self._update_notebook_metadata(file_path, metadata)
            else:
                logger.warning(f"Unsupported file type for metadata update: {file_path}")
                return False
        except Exception as e:
            logger.error(f"Failed to update metadata in {file_path}: {e}")
            return False
    
    def _update_markdown_metadata(self, file_path: Path, metadata: ContentMetadata) -> bool:
        """Update Markdown file frontmatter"""
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Convert metadata to dict
        metadata_dict = asdict(metadata)
        metadata_dict['status'] = metadata_dict['status'].value
        if metadata_dict['review_stage']:
            metadata_dict['review_stage'] = metadata_dict['review_stage'].value
        
        # Create YAML frontmatter
        frontmatter = yaml.dump(metadata_dict, default_flow_style=False)
        
        # Remove existing frontmatter if present
        if content.startswith('---'):
            frontmatter_end = content.find('---', 3)
            if frontmatter_end > 0:
                content = content[frontmatter_end + 3:].lstrip('\n')
        
        # Add new frontmatter
        new_content = f"---\n{frontmatter}---\n\n{content}"
        
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(new_content)
        
        return True
    
    def _update_notebook_metadata(self, file_path: Path, metadata: ContentMetadata) -> bool:
        """Update Jupyter notebook metadata"""
        with open(file_path, 'r', encoding='utf-8') as f:
            notebook = json.load(f)
        
        # Convert metadata to dict
        metadata_dict = asdict(metadata)
        metadata_dict['status'] = metadata_dict['status'].value
        if metadata_dict['review_stage']:
            metadata_dict['review_stage'] = metadata_dict['review_stage'].value
        
        # Update notebook metadata
        if 'metadata' not in notebook:
            notebook['metadata'] = {}
        notebook['metadata']['handbook'] = metadata_dict
        
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(notebook, f, indent=2)
        
        return True
    
    def list_content_files(self, chapter_id: Optional[str] = None, status: Optional[ContentStatus] = None) -> List[Tuple[Path, ContentMetadata]]:
        """
        List content files with optional filtering
        
        Args:
            chapter_id: Filter by chapter ID
            status: Filter by content status
        
        Returns:
            List of (file_path, metadata) tuples
        """
        content_files = []
        
        for file_path in self.content_dir.rglob('*'):
            if file_path.is_file() and file_path.suffix in self.config['content']['supported_formats']:
                metadata = self.get_content_metadata(file_path)
                if metadata:
                    # Apply filters
                    if chapter_id and metadata.chapter_id != chapter_id:
                        continue
                    if status and metadata.status != status:
                        continue
                    
                    content_files.append((file_path, metadata))
        
        return content_files
    
    def validate_content_structure(self, file_path: Path) -> Dict[str, Any]:
        """
        Validate content file structure and format
        
        Args:
            file_path: Path to content file
        
        Returns:
            Validation result dictionary
        """
        validation_result = {
            "valid": True,
            "errors": [],
            "warnings": [],
            "metadata_check": False,
            "structure_check": False,
            "format_check": False
        }
        
        try:
            # Check file exists and is readable
            if not file_path.exists():
                validation_result["errors"].append(f"File does not exist: {file_path}")
                validation_result["valid"] = False
                return validation_result
            
            # Check file format
            if file_path.suffix not in self.config['content']['supported_formats']:
                validation_result["errors"].append(f"Unsupported file format: {file_path.suffix}")
                validation_result["valid"] = False
            else:
                validation_result["format_check"] = True
            
            # Check metadata
            metadata = self.get_content_metadata(file_path)
            if metadata:
                validation_result["metadata_check"] = True
                
                # Check required metadata fields
                for field in self.config['content']['required_metadata']:
                    if not getattr(metadata, field, None):
                        validation_result["warnings"].append(f"Missing required metadata: {field}")
            else:
                validation_result["errors"].append("Failed to extract metadata")
                validation_result["valid"] = False
            
            # Check content structure based on file type
            if file_path.suffix == '.md':
                validation_result["structure_check"] = self._validate_markdown_structure(file_path)
            elif file_path.suffix == '.ipynb':
                validation_result["structure_check"] = self._validate_notebook_structure(file_path)
            
        except Exception as e:
            validation_result["errors"].append(f"Validation error: {str(e)}")
            validation_result["valid"] = False
        
        return validation_result
    
    def _validate_markdown_structure(self, file_path: Path) -> bool:
        """Validate Markdown file structure"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Basic structure checks
            required_sections = ["# ", "## "]  # At least one H1 and one H2
            for section in required_sections:
                if section not in content:
                    return False
            
            return True
        except Exception:
            return False
    
    def _validate_notebook_structure(self, file_path: Path) -> bool:
        """Validate Jupyter notebook structure"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                notebook = json.load(f)
            
            # Check notebook format
            if 'cells' not in notebook:
                return False
            
            # Check for at least one markdown cell (introduction)
            has_markdown = any(cell.get('cell_type') == 'markdown' for cell in notebook['cells'])
            if not has_markdown:
                return False
            
            return True
        except Exception:
            return False
    
    def commit_changes(self, message: str, files: Optional[List[str]] = None) -> str:
        """
        Commit changes to the current branch
        
        Args:
            message: Commit message
            files: List of files to commit (None for all changes)
        
        Returns:
            Commit hash
        """
        try:
            if files:
                self.repo.index.add(files)
            else:
                self.repo.git.add('.')
            
            commit = self.repo.index.commit(message)
            
            logger.info(f"Committed changes: {commit.hexsha[:8]} - {message}")
            return commit.hexsha
        except Exception as e:
            logger.error(f"Failed to commit changes: {e}")
            raise
    
    def push_branch(self, branch_name: Optional[str] = None) -> bool:
        """
        Push branch to remote repository
        
        Args:
            branch_name: Branch to push (current branch if None)
        
        Returns:
            Success status
        """
        try:
            if branch_name:
                self.repo.git.push('origin', branch_name)
            else:
                current_branch = self.repo.active_branch.name
                self.repo.git.push('origin', current_branch)
            
            logger.info(f"Pushed branch to remote: {branch_name or current_branch}")
            return True
        except Exception as e:
            logger.error(f"Failed to push branch: {e}")
            return False
    
    def create_pull_request_info(self, source_branch: str, target_branch: str, metadata: ContentMetadata) -> Dict[str, Any]:
        """
        Generate pull request information
        
        Args:
            source_branch: Source branch name
            target_branch: Target branch name
            metadata: Content metadata
        
        Returns:
            Pull request information dictionary
        """
        pr_info = {
            "title": f"Content Update: {metadata.title} ({metadata.chapter_id})",
            "body": f"""
## Content Update Summary

**Chapter**: {metadata.chapter_id}
**Title**: {metadata.title}
**Author**: {metadata.author}
**Content Type**: {metadata.content_type}
**Status**: {metadata.status.value}

### Platforms Covered
{', '.join(metadata.platforms) if metadata.platforms else 'None specified'}

### Tags
{', '.join(metadata.tags) if metadata.tags else 'None specified'}

### Review Requirements
- [ ] Technical accuracy validation
- [ ] Educational effectiveness review
- [ ] Bias assessment completion
- [ ] Security compliance check
- [ ] Final approval sign-off

### Validation Scores
- **Overall Score**: {metadata.validation_score or 'Pending'}
- **Bias Score**: {metadata.bias_score or 'Pending'}

### Dependencies
{', '.join(metadata.dependencies) if metadata.dependencies else 'None'}

### Reviewers
{', '.join(metadata.reviewers) if metadata.reviewers else 'None assigned'}

---
*Generated by Content Management System*
            """.strip(),
            "head": source_branch,
            "base": target_branch,
            "draft": metadata.status != ContentStatus.APPROVED
        }
        
        return pr_info
    
    def merge_content(self, source_branch: str, target_branch: str, delete_source: bool = True) -> bool:
        """
        Merge content branch into target branch
        
        Args:
            source_branch: Source branch to merge
            target_branch: Target branch
            delete_source: Whether to delete source branch after merge
        
        Returns:
            Success status
        """
        try:
            # Switch to target branch
            self.repo.git.checkout(target_branch)
            self.repo.git.pull('origin', target_branch)
            
            # Merge source branch
            self.repo.git.merge(source_branch, '--no-ff')
            
            # Push merged changes
            self.repo.git.push('origin', target_branch)
            
            # Delete source branch if requested
            if delete_source:
                self.repo.git.branch('-d', source_branch)
                try:
                    self.repo.git.push('origin', '--delete', source_branch)
                except git.GitCommandError:
                    # Remote branch might not exist or already deleted
                    pass
            
            logger.info(f"Merged {source_branch} into {target_branch}")
            return True
        except Exception as e:
            logger.error(f"Failed to merge branches: {e}")
            return False
    
    def archive_content(self, file_path: Path) -> bool:
        """
        Archive content file
        
        Args:
            file_path: Path to content file to archive
        
        Returns:
            Success status
        """
        try:
            archive_dir = self.content_dir / "archived"
            archive_dir.mkdir(exist_ok=True)
            
            # Move file to archive with timestamp
            timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
            archive_name = f"{file_path.stem}-{timestamp}{file_path.suffix}"
            archive_path = archive_dir / archive_name
            
            shutil.move(str(file_path), str(archive_path))
            
            # Update metadata to archived status
            metadata = self.get_content_metadata(archive_path)
            if metadata:
                metadata.status = ContentStatus.ARCHIVED
                metadata.modified_date = datetime.now().isoformat()
                self.update_content_metadata(archive_path, metadata)
            
            logger.info(f"Archived content: {file_path} -> {archive_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to archive content {file_path}: {e}")
            return False
    
    def restore_content(self, archive_path: Path, restore_path: Path) -> bool:
        """
        Restore archived content
        
        Args:
            archive_path: Path to archived content
            restore_path: Path where to restore content
        
        Returns:
            Success status
        """
        try:
            shutil.move(str(archive_path), str(restore_path))
            
            # Update metadata status
            metadata = self.get_content_metadata(restore_path)
            if metadata:
                metadata.status = ContentStatus.DRAFT
                metadata.modified_date = datetime.now().isoformat()
                self.update_content_metadata(restore_path, metadata)
            
            logger.info(f"Restored content: {archive_path} -> {restore_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to restore content: {e}")
            return False
    
    def generate_content_report(self) -> Dict[str, Any]:
        """
        Generate comprehensive content report
        
        Returns:
            Content report dictionary
        """
        report = {
            "timestamp": datetime.now().isoformat(),
            "repository": str(self.repo_path),
            "total_files": 0,
            "by_status": {},
            "by_chapter": {},
            "validation_summary": {
                "total_validated": 0,
                "average_score": 0.0,
                "passing_threshold": self.config['validation']['minimum_score']
            },
            "bias_summary": {
                "total_assessed": 0,
                "average_bias_score": 0.0
            },
            "recent_activity": []
        }
        
        # Get all content files
        content_files = self.list_content_files()
        report["total_files"] = len(content_files)
        
        validation_scores = []
        bias_scores = []
        
        for file_path, metadata in content_files:
            # Count by status
            status = metadata.status.value
            report["by_status"][status] = report["by_status"].get(status, 0) + 1
            
            # Count by chapter
            chapter = metadata.chapter_id or "unknown"
            report["by_chapter"][chapter] = report["by_chapter"].get(chapter, 0) + 1
            
            # Collect validation scores
            if metadata.validation_score is not None:
                validation_scores.append(metadata.validation_score)
            
            # Collect bias scores
            if metadata.bias_score is not None:
                bias_scores.append(metadata.bias_score)
        
        # Calculate validation summary
        if validation_scores:
            report["validation_summary"]["total_validated"] = len(validation_scores)
            report["validation_summary"]["average_score"] = sum(validation_scores) / len(validation_scores)
            report["validation_summary"]["passing_count"] = sum(1 for score in validation_scores if score >= self.config['validation']['minimum_score'])
        
        # Calculate bias summary
        if bias_scores:
            report["bias_summary"]["total_assessed"] = len(bias_scores)
            report["bias_summary"]["average_bias_score"] = sum(bias_scores) / len(bias_scores)
        
        # Recent activity (last 30 days)
        try:
            since_date = datetime.now() - timedelta(days=30)
            recent_commits = list(self.repo.iter_commits(since=since_date, max_count=50))
            
            for commit in recent_commits:
                report["recent_activity"].append({
                    "commit_hash": commit.hexsha[:8],
                    "message": commit.message.strip(),
                    "author": str(commit.author),
                    "date": commit.committed_datetime.isoformat()
                })
        except Exception as e:
            logger.warning(f"Failed to get recent activity: {e}")
        
        return report
    
    def export_content_manifest(self, output_path: Optional[Path] = None) -> Dict[str, Any]:
        """
        Export content manifest for external systems
        
        Args:
            output_path: Optional path to save manifest file
        
        Returns:
            Content manifest dictionary
        """
        manifest = {
            "version": "1.0.0",
            "generated": datetime.now().isoformat(),
            "repository": str(self.repo_path),
            "content": []
        }
        
        # Get all content files
        content_files = self.list_content_files()
        
        for file_path, metadata in content_files:
            content_info = {
                "file_path": str(file_path.relative_to(self.repo_path)),
                "metadata": asdict(metadata)
            }
            
            # Convert enums to strings
            content_info["metadata"]["status"] = content_info["metadata"]["status"].value
            if content_info["metadata"]["review_stage"]:
                content_info["metadata"]["review_stage"] = content_info["metadata"]["review_stage"].value
            
            manifest["content"].append(content_info)
        
        # Save to file if path provided
        if output_path:
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(manifest, f, indent=2)
            logger.info(f"Content manifest exported to {output_path}")
        
        return manifest


def main():
    """Main function for CLI usage"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Content Management System")
    parser.add_argument("--repo", default=".", help="Repository path")
    parser.add_argument("--config", help="Configuration file path")
    parser.add_argument("--command", required=True, 
                       choices=["init", "list", "validate", "report", "manifest"],
                       help="Command to execute")
    parser.add_argument("--chapter", help="Chapter ID filter")
    parser.add_argument("--status", help="Status filter")
    parser.add_argument("--output", help="Output file path")
    
    args = parser.parse_args()
    
    try:
        cms = ContentManagementSystem(args.repo, args.config)
        
        if args.command == "init":
            print("Content Management System initialized successfully")
        
        elif args.command == "list":
            status_filter = ContentStatus(args.status) if args.status else None
            content_files = cms.list_content_files(args.chapter, status_filter)
            
            print(f"Found {len(content_files)} content files:")
            for file_path, metadata in content_files:
                print(f"  {file_path.relative_to(cms.repo_path)}: {metadata.title} ({metadata.status.value})")
        
        elif args.command == "validate":
            content_files = cms.list_content_files(args.chapter)
            
            for file_path, metadata in content_files:
                result = cms.validate_content_structure(file_path)
                print(f"{file_path.relative_to(cms.repo_path)}: {'✓' if result['valid'] else '✗'}")
                if result["errors"]:
                    for error in result["errors"]:
                        print(f"  ERROR: {error}")
                if result["warnings"]:
                    for warning in result["warnings"]:
                        print(f"  WARNING: {warning}")
        
        elif args.command == "report":
            report = cms.generate_content_report()
            
            if args.output:
                with open(args.output, 'w') as f:
                    json.dump(report, f, indent=2)
                print(f"Report saved to {args.output}")
            else:
                print(json.dumps(report, indent=2))
        
        elif args.command == "manifest":
            output_path = Path(args.output) if args.output else None
            manifest = cms.export_content_manifest(output_path)
            
            if not args.output:
                print(json.dumps(manifest, indent=2))
    
    except Exception as e:
        logger.error(f"Command failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()