#!/usr/bin/env python3
"""
Git-Based Version Control and Branching Strategy
================================================

A comprehensive Git-based version control system optimized for content workflows that provides:
- Intelligent branching strategies for different review stages
- Automated branch creation, management, and cleanup
- Content-specific merge strategies and conflict resolution
- Branch protection and access control integration
- Automated tagging and release management
- Content versioning and change tracking
- Integration with review workflow systems

Author: Claude Code Implementation
Created: 2025-07-28
Version: 1.0.0
"""

import os
import sys
import json
import logging
import shutil
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any, Set
from pathlib import Path
from dataclasses import dataclass, asdict, field
from enum import Enum
import yaml
import git
from git import Repo, GitCommandError
import fnmatch
import tempfile
import subprocess
from collections import defaultdict

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class BranchType(Enum):
    """Branch type enumeration"""
    MAIN = "main"
    DEVELOPMENT = "development"
    CONTENT_DRAFT = "content_draft"
    TECHNICAL_REVIEW = "technical_review"
    EDUCATIONAL_REVIEW = "educational_review"
    BIAS_ASSESSMENT = "bias_assessment"
    SECURITY_REVIEW = "security_review"
    FINAL_APPROVAL = "final_approval"
    HOTFIX = "hotfix"
    RELEASE = "release"
    ARCHIVE = "archive"


class MergeStrategy(Enum):
    """Merge strategy enumeration"""
    MERGE_COMMIT = "merge"
    SQUASH_MERGE = "squash"
    REBASE_MERGE = "rebase"
    FAST_FORWARD = "fast_forward"


class BranchStatus(Enum):
    """Branch status enumeration"""
    ACTIVE = "active"
    UNDER_REVIEW = "under_review"
    APPROVED = "approved"
    MERGED = "merged"
    ABANDONED = "abandoned"
    ARCHIVED = "archived"


@dataclass
class BranchConfiguration:
    """Branch configuration settings"""
    branch_type: BranchType
    naming_pattern: str
    base_branch: str
    merge_strategy: MergeStrategy
    auto_delete_after_merge: bool
    protection_rules: Dict[str, Any]
    required_reviews: int
    allow_force_push: bool
    max_lifetime_days: Optional[int]
    content_patterns: List[str]


@dataclass
class BranchMetadata:
    """Branch metadata information"""
    branch_name: str
    branch_type: BranchType
    content_id: Optional[str]
    workflow_instance_id: Optional[str]
    author: str
    reviewer: Optional[str]
    created_date: str
    last_activity: str
    status: BranchStatus
    merge_target: Optional[str]
    associated_pr: Optional[str]
    commit_count: int
    file_changes: Dict[str, int]  # {added, modified, deleted}
    tags: List[str]
    metadata: Dict[str, Any]


@dataclass
class ContentVersion:
    """Content version information"""
    version_id: str
    content_path: str
    branch_name: str
    commit_hash: str
    version_number: str
    author: str
    created_date: str
    change_summary: str
    validation_score: Optional[float]
    review_status: str
    tags: List[str]
    file_hash: str


@dataclass
class MergeConflict:
    """Merge conflict information"""
    file_path: str
    conflict_type: str
    base_content: str
    head_content: str
    merge_content: str
    resolution_strategy: Optional[str]
    resolved: bool
    resolved_by: Optional[str]
    resolved_date: Optional[str]


class ContentBranchingStrategy:
    """
    Git-Based Version Control and Branching Strategy for Content Management
    """
    
    def __init__(self, repo_path: str, config_path: Optional[str] = None):
        """
        Initialize the Branching Strategy Manager
        
        Args:
            repo_path: Path to Git repository
            config_path: Path to configuration file
        """
        self.repo_path = Path(repo_path)
        self.config_path = config_path or self.repo_path / "validation" / "workflow" / "branching_config.yml"
        self.branch_data_dir = self.repo_path / "validation" / "workflow" / "branches"
        
        # Ensure directories exist
        self.branch_data_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize Git repository
        try:
            self.repo = Repo(self.repo_path)
        except git.InvalidGitRepositoryError:
            raise ValueError(f"Invalid Git repository at {self.repo_path}")
        
        # Load configuration
        self.config = self._load_configuration()
        self.branch_configs = self._load_branch_configurations()
        
        # Load branch metadata
        self.branch_metadata = self._load_branch_metadata()
        self.content_versions = self._load_content_versions()
        
        logger.info(f"Content Branching Strategy initialized for {self.repo_path}")
    
    def _load_configuration(self) -> Dict[str, Any]:
        """Load branching configuration"""
        default_config = {
            "repository": {
                "main_branch": "main",
                "development_branch": "develop",
                "content_base_branch": "main",
                "auto_cleanup": True,
                "max_concurrent_branches": 20
            },
            "naming": {
                "content_prefix": "content",
                "review_prefix": "review",
                "hotfix_prefix": "hotfix",
                "release_prefix": "release",
                "separator": "/"
            },
            "protection": {
                "enable_branch_protection": True,
                "require_pr_reviews": True,
                "require_status_checks": True,
                "restrict_pushes": True,
                "allow_administrators": True
            },
            "merge": {
                "default_strategy": "squash",
                "auto_merge_threshold": 95.0,
                "delete_after_merge": True,
                "create_merge_commits": False
            },
            "versioning": {
                "version_format": "v{major}.{minor}.{patch}",
                "auto_version_increment": True,
                "track_file_versions": True,
                "create_version_tags": True
            },
            "cleanup": {
                "auto_cleanup_days": 30,
                "cleanup_merged_branches": True,
                "cleanup_abandoned_branches": True,
                "preserve_tagged_branches": True
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
    
    def _load_branch_configurations(self) -> Dict[BranchType, BranchConfiguration]:
        """Load branch type configurations"""
        configs = {
            BranchType.CONTENT_DRAFT: BranchConfiguration(
                branch_type=BranchType.CONTENT_DRAFT,
                naming_pattern=f"{self.config['naming']['content_prefix']}/{self.config['naming']['separator']}{{content_id}}-draft-{{timestamp}}",
                base_branch=self.config['repository']['content_base_branch'],
                merge_strategy=MergeStrategy.SQUASH_MERGE,
                auto_delete_after_merge=True,
                protection_rules={
                    "required_reviews": 0,
                    "dismiss_stale_reviews": False,
                    "require_code_owner_reviews": False
                },
                required_reviews=0,
                allow_force_push=True,
                max_lifetime_days=7,
                content_patterns=["chapters/**/*.md", "chapters/**/*.ipynb"]
            ),
            BranchType.TECHNICAL_REVIEW: BranchConfiguration(
                branch_type=BranchType.TECHNICAL_REVIEW,
                naming_pattern=f"{self.config['naming']['review_prefix']}/{self.config['naming']['separator']}{{content_id}}-technical-{{timestamp}}",
                base_branch=self.config['repository']['content_base_branch'],
                merge_strategy=MergeStrategy.MERGE_COMMIT,
                auto_delete_after_merge=True,
                protection_rules={
                    "required_reviews": 1,
                    "dismiss_stale_reviews": True,
                    "require_code_owner_reviews": True
                },
                required_reviews=1,
                allow_force_push=False,
                max_lifetime_days=14,
                content_patterns=["chapters/**/*.md", "chapters/**/*.ipynb", "code-examples/**/*"]
            ),
            BranchType.EDUCATIONAL_REVIEW: BranchConfiguration(
                branch_type=BranchType.EDUCATIONAL_REVIEW,
                naming_pattern=f"{self.config['naming']['review_prefix']}/{self.config['naming']['separator']}{{content_id}}-educational-{{timestamp}}",
                base_branch=self.config['repository']['content_base_branch'],
                merge_strategy=MergeStrategy.MERGE_COMMIT,
                auto_delete_after_merge=True,
                protection_rules={
                    "required_reviews": 1,
                    "dismiss_stale_reviews": True,
                    "require_code_owner_reviews": False
                },
                required_reviews=1,
                allow_force_push=False,
                max_lifetime_days=10,
                content_patterns=["chapters/**/*.md", "chapters/**/*.ipynb"]
            ),
            BranchType.BIAS_ASSESSMENT: BranchConfiguration(
                branch_type=BranchType.BIAS_ASSESSMENT,
                naming_pattern=f"{self.config['naming']['review_prefix']}/{self.config['naming']['separator']}{{content_id}}-bias-{{timestamp}}",
                base_branch=self.config['repository']['content_base_branch'],
                merge_strategy=MergeStrategy.MERGE_COMMIT,
                auto_delete_after_merge=True,
                protection_rules={
                    "required_reviews": 1,
                    "dismiss_stale_reviews": True,
                    "require_code_owner_reviews": True
                },
                required_reviews=1,
                allow_force_push=False,
                max_lifetime_days=5,
                content_patterns=["chapters/**/*.md", "chapters/**/*.ipynb"]
            ),
            BranchType.SECURITY_REVIEW: BranchConfiguration(
                branch_type=BranchType.SECURITY_REVIEW,
                naming_pattern=f"{self.config['naming']['review_prefix']}/{self.config['naming']['separator']}{{content_id}}-security-{{timestamp}}",
                base_branch=self.config['repository']['content_base_branch'],
                merge_strategy=MergeStrategy.MERGE_COMMIT,
                auto_delete_after_merge=True,
                protection_rules={
                    "required_reviews": 2,
                    "dismiss_stale_reviews": True,
                    "require_code_owner_reviews": True
                },
                required_reviews=2,
                allow_force_push=False,
                max_lifetime_days=7,
                content_patterns=["chapters/**/*.md", "chapters/**/*.ipynb", "security-compliance/**/*"]
            ),
            BranchType.FINAL_APPROVAL: BranchConfiguration(
                branch_type=BranchType.FINAL_APPROVAL,
                naming_pattern=f"{self.config['naming']['review_prefix']}/{self.config['naming']['separator']}{{content_id}}-final-{{timestamp}}",
                base_branch=self.config['repository']['content_base_branch'],
                merge_strategy=MergeStrategy.SQUASH_MERGE,
                auto_delete_after_merge=True,
                protection_rules={
                    "required_reviews": 2,
                    "dismiss_stale_reviews": True,
                    "require_code_owner_reviews": True
                },
                required_reviews=2,
                allow_force_push=False,
                max_lifetime_days=3,
                content_patterns=["chapters/**/*", "templates/**/*"]
            ),
            BranchType.HOTFIX: BranchConfiguration(
                branch_type=BranchType.HOTFIX,
                naming_pattern=f"{self.config['naming']['hotfix_prefix']}/{self.config['naming']['separator']}{{issue}}-{{timestamp}}",
                base_branch=self.config['repository']['main_branch'],
                merge_strategy=MergeStrategy.MERGE_COMMIT,
                auto_delete_after_merge=True,
                protection_rules={
                    "required_reviews": 1,
                    "dismiss_stale_reviews": False,
                    "require_code_owner_reviews": True
                },
                required_reviews=1,
                allow_force_push=False,
                max_lifetime_days=1,
                content_patterns=["**/*"]
            ),
            BranchType.RELEASE: BranchConfiguration(
                branch_type=BranchType.RELEASE,
                naming_pattern=f"{self.config['naming']['release_prefix']}/{self.config['naming']['separator']}{{version}}",
                base_branch=self.config['repository']['development_branch'],
                merge_strategy=MergeStrategy.MERGE_COMMIT,
                auto_delete_after_merge=False,
                protection_rules={
                    "required_reviews": 2,
                    "dismiss_stale_reviews": True,
                    "require_code_owner_reviews": True
                },
                required_reviews=2,
                allow_force_push=False,
                max_lifetime_days=None,
                content_patterns=["**/*"]
            )
        }
        
        return configs
    
    def _load_branch_metadata(self) -> Dict[str, BranchMetadata]:
        """Load branch metadata from storage"""
        metadata_file = self.branch_data_dir / "branch_metadata.json"
        metadata = {}
        
        if metadata_file.exists():
            try:
                with open(metadata_file, 'r') as f:
                    data = json.load(f)
                    for branch_name, branch_data in data.items():
                        metadata[branch_name] = BranchMetadata(
                            branch_name=branch_data['branch_name'],
                            branch_type=BranchType(branch_data['branch_type']),
                            content_id=branch_data.get('content_id'),
                            workflow_instance_id=branch_data.get('workflow_instance_id'),
                            author=branch_data['author'],
                            reviewer=branch_data.get('reviewer'),
                            created_date=branch_data['created_date'],
                            last_activity=branch_data['last_activity'],
                            status=BranchStatus(branch_data['status']),
                            merge_target=branch_data.get('merge_target'),
                            associated_pr=branch_data.get('associated_pr'),
                            commit_count=branch_data.get('commit_count', 0),
                            file_changes=branch_data.get('file_changes', {'added': 0, 'modified': 0, 'deleted': 0}),
                            tags=branch_data.get('tags', []),
                            metadata=branch_data.get('metadata', {})
                        )
            except Exception as e:
                logger.error(f"Failed to load branch metadata: {e}")
        
        return metadata
    
    def _save_branch_metadata(self):
        """Save branch metadata to storage"""
        metadata_file = self.branch_data_dir / "branch_metadata.json"
        
        try:
            data = {}
            for branch_name, metadata in self.branch_metadata.items():
                branch_data = asdict(metadata)
                branch_data['branch_type'] = branch_data['branch_type'].value
                branch_data['status'] = branch_data['status'].value
                data[branch_name] = branch_data
            
            with open(metadata_file, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save branch metadata: {e}")
    
    def _load_content_versions(self) -> Dict[str, List[ContentVersion]]:
        """Load content version history"""
        versions_file = self.branch_data_dir / "content_versions.json"
        versions = defaultdict(list)
        
        if versions_file.exists():
            try:
                with open(versions_file, 'r') as f:
                    data = json.load(f)
                    for content_path, version_list in data.items():
                        for version_data in version_list:
                            version = ContentVersion(
                                version_id=version_data['version_id'],
                                content_path=version_data['content_path'],
                                branch_name=version_data['branch_name'],
                                commit_hash=version_data['commit_hash'],
                                version_number=version_data['version_number'],
                                author=version_data['author'],
                                created_date=version_data['created_date'],
                                change_summary=version_data['change_summary'],
                                validation_score=version_data.get('validation_score'),
                                review_status=version_data['review_status'],
                                tags=version_data.get('tags', []),
                                file_hash=version_data['file_hash']
                            )
                            versions[content_path].append(version)
            except Exception as e:
                logger.error(f"Failed to load content versions: {e}")
        
        return dict(versions)
    
    def _save_content_versions(self):
        """Save content version history"""
        versions_file = self.branch_data_dir / "content_versions.json"
        
        try:
            data = {}
            for content_path, version_list in self.content_versions.items():
                data[content_path] = [asdict(version) for version in version_list]
            
            with open(versions_file, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save content versions: {e}")
    
    def create_content_branch(self, branch_type: BranchType, content_id: str, 
                            author: str, workflow_instance_id: Optional[str] = None,
                            base_branch: Optional[str] = None) -> str:
        """
        Create a new content branch
        
        Args:
            branch_type: Type of branch to create
            content_id: Content identifier
            author: Branch author
            workflow_instance_id: Associated workflow instance
            base_branch: Base branch (override default)
        
        Returns:
            Created branch name
        """
        if branch_type not in self.branch_configs:
            raise ValueError(f"Unsupported branch type: {branch_type}")
        
        config = self.branch_configs[branch_type]
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        
        # Generate branch name
        branch_name = config.naming_pattern.format(
            content_id=content_id,
            timestamp=timestamp,
            issue=content_id,  # For hotfix branches
            version=content_id  # For release branches
        )
        
        # Use specified base branch or config default
        source_branch = base_branch or config.base_branch
        
        try:
            # Ensure we're on the source branch and it's up to date
            self.repo.git.checkout(source_branch)
            try:
                self.repo.git.pull('origin', source_branch)
            except GitCommandError:
                logger.warning(f"Could not pull {source_branch}, continuing with local version")
            
            # Create new branch
            self.repo.git.checkout('-b', branch_name)
            
            # Create branch metadata
            metadata = BranchMetadata(
                branch_name=branch_name,
                branch_type=branch_type,
                content_id=content_id,
                workflow_instance_id=workflow_instance_id,
                author=author,
                reviewer=None,
                created_date=datetime.now().isoformat(),
                last_activity=datetime.now().isoformat(),
                status=BranchStatus.ACTIVE,
                merge_target=source_branch,
                associated_pr=None,
                commit_count=0,
                file_changes={'added': 0, 'modified': 0, 'deleted': 0},
                tags=[],
                metadata={}
            )
            
            self.branch_metadata[branch_name] = metadata
            self._save_branch_metadata()
            
            logger.info(f"Created {branch_type.value} branch: {branch_name}")
            return branch_name
            
        except GitCommandError as e:
            logger.error(f"Failed to create branch {branch_name}: {e}")
            raise
    
    def switch_branch(self, branch_name: str) -> bool:
        """
        Switch to specified branch
        
        Args:
            branch_name: Branch to switch to
        
        Returns:
            Success status
        """
        try:
            # Check if branch exists locally
            if branch_name not in [ref.name for ref in self.repo.refs]:
                # Try to fetch from remote
                try:
                    self.repo.git.fetch('origin', f"{branch_name}:{branch_name}")
                except GitCommandError:
                    logger.error(f"Branch {branch_name} not found locally or remotely")
                    return False
            
            self.repo.git.checkout(branch_name)
            
            # Update last activity if we have metadata
            if branch_name in self.branch_metadata:
                self.branch_metadata[branch_name].last_activity = datetime.now().isoformat()
                self._save_branch_metadata()
            
            logger.info(f"Switched to branch: {branch_name}")
            return True
            
        except GitCommandError as e:
            logger.error(f"Failed to switch to branch {branch_name}: {e}")
            return False
    
    def commit_changes(self, branch_name: str, message: str, files: Optional[List[str]] = None,
                      author_name: Optional[str] = None, author_email: Optional[str] = None) -> str:
        """
        Commit changes to branch
        
        Args:
            branch_name: Branch to commit to
            message: Commit message
            files: Files to commit (None for all changes)
            author_name: Override commit author name
            author_email: Override commit author email
        
        Returns:
            Commit hash
        """
        try:
            # Switch to branch if needed
            if self.repo.active_branch.name != branch_name:
                if not self.switch_branch(branch_name):
                    raise ValueError(f"Could not switch to branch {branch_name}")
            
            # Stage files
            if files:
                for file_path in files:
                    self.repo.index.add([file_path])
            else:
                self.repo.git.add('.')
            
            # Prepare commit kwargs
            commit_kwargs = {}
            if author_name and author_email:
                commit_kwargs['author'] = git.Actor(author_name, author_email)
            
            # Create commit
            commit = self.repo.index.commit(message, **commit_kwargs)
            
            # Update branch metadata
            if branch_name in self.branch_metadata:
                metadata = self.branch_metadata[branch_name]
                metadata.commit_count += 1
                metadata.last_activity = datetime.now().isoformat()
                
                # Update file change statistics
                stats = commit.stats.total
                metadata.file_changes['added'] += stats.get('insertions', 0)
                metadata.file_changes['modified'] += stats.get('files', 0)
                metadata.file_changes['deleted'] += stats.get('deletions', 0)
                
                self._save_branch_metadata()
            
            # Create content version if this affects content files
            self._create_content_version(branch_name, commit, message)
            
            logger.info(f"Committed to {branch_name}: {commit.hexsha[:8]} - {message}")
            return commit.hexsha
            
        except Exception as e:
            logger.error(f"Failed to commit to branch {branch_name}: {e}")
            raise
    
    def _create_content_version(self, branch_name: str, commit: git.Commit, change_summary: str):
        """Create content version entry for affected content files"""
        # Check if commit affects content files
        content_files = []
        
        for item in commit.stats.files:
            file_path = item
            if any(fnmatch.fnmatch(file_path, pattern) for pattern in ["chapters/**/*.md", "chapters/**/*.ipynb"]):
                content_files.append(file_path)
        
        # Create version entries for affected content files
        for content_path in content_files:
            version_id = f"v-{branch_name}-{commit.hexsha[:8]}"
            
            # Calculate version number (simplified)
            existing_versions = self.content_versions.get(content_path, [])
            version_number = f"1.{len(existing_versions)}.0"
            
            # Calculate file hash
            try:
                file_content = self.repo.git.show(f"{commit.hexsha}:{content_path}")
                import hashlib
                file_hash = hashlib.sha256(file_content.encode()).hexdigest()[:16]
            except GitCommandError:
                file_hash = "unknown"
            
            version = ContentVersion(
                version_id=version_id,
                content_path=content_path,
                branch_name=branch_name,
                commit_hash=commit.hexsha,
                version_number=version_number,
                author=str(commit.author),
                created_date=commit.committed_datetime.isoformat(),
                change_summary=change_summary,
                validation_score=None,
                review_status="pending",
                tags=[],
                file_hash=file_hash
            )
            
            self.content_versions[content_path].append(version)
        
        if content_files:
            self._save_content_versions()
    
    def push_branch(self, branch_name: str, force: bool = False) -> bool:
        """
        Push branch to remote repository
        
        Args:
            branch_name: Branch to push
            force: Force push (use with caution)
        
        Returns:
            Success status
        """
        try:
            # Check branch configuration for force push rules
            if branch_name in self.branch_metadata:
                metadata = self.branch_metadata[branch_name]
                config = self.branch_configs.get(metadata.branch_type)
                
                if force and config and not config.allow_force_push:
                    logger.error(f"Force push not allowed for branch type {metadata.branch_type}")
                    return False
            
            # Push branch
            push_args = ['origin', branch_name]
            if force:
                push_args.insert(1, '--force')
            
            self.repo.git.push(*push_args)
            
            logger.info(f"Pushed branch {branch_name} to remote")
            return True
            
        except GitCommandError as e:
            logger.error(f"Failed to push branch {branch_name}: {e}")
            return False
    
    def merge_branch(self, source_branch: str, target_branch: str, 
                    merge_strategy: Optional[MergeStrategy] = None,
                    delete_source: bool = None) -> bool:
        """
        Merge source branch into target branch
        
        Args:
            source_branch: Source branch to merge
            target_branch: Target branch
            merge_strategy: Override merge strategy
            delete_source: Override auto-delete setting
        
        Returns:
            Success status
        """
        try:
            # Get branch configuration
            config = None
            if source_branch in self.branch_metadata:
                metadata = self.branch_metadata[source_branch]
                config = self.branch_configs.get(metadata.branch_type)
            
            # Determine merge strategy
            strategy = merge_strategy or (config.merge_strategy if config else MergeStrategy.MERGE_COMMIT)
            should_delete = delete_source if delete_source is not None else (config.auto_delete_after_merge if config else True)
            
            # Switch to target branch and update
            self.repo.git.checkout(target_branch)
            try:
                self.repo.git.pull('origin', target_branch)
            except GitCommandError:
                logger.warning(f"Could not pull {target_branch}, continuing with local version")
            
            # Perform merge based on strategy
            if strategy == MergeStrategy.FAST_FORWARD:
                self.repo.git.merge(source_branch, '--ff-only')
            elif strategy == MergeStrategy.SQUASH_MERGE:
                self.repo.git.merge(source_branch, '--squash')
                # Need to create commit for squash merge
                self.repo.index.commit(f"Merge {source_branch} into {target_branch}")
            elif strategy == MergeStrategy.REBASE_MERGE:
                self.repo.git.rebase(source_branch)
            else:  # MERGE_COMMIT
                self.repo.git.merge(source_branch, '--no-ff')
            
            # Push merged changes
            self.repo.git.push('origin', target_branch)
            
            # Update branch metadata
            if source_branch in self.branch_metadata:
                self.branch_metadata[source_branch].status = BranchStatus.MERGED
                self.branch_metadata[source_branch].last_activity = datetime.now().isoformat()
            
            # Delete source branch if configured
            if should_delete:
                self.delete_branch(source_branch, force=True)
            
            self._save_branch_metadata()
            
            logger.info(f"Merged {source_branch} into {target_branch} using {strategy.value}")
            return True
            
        except GitCommandError as e:
            logger.error(f"Failed to merge {source_branch} into {target_branch}: {e}")
            return False
    
    def detect_merge_conflicts(self, source_branch: str, target_branch: str) -> List[MergeConflict]:
        """
        Detect potential merge conflicts between branches
        
        Args:
            source_branch: Source branch
            target_branch: Target branch
        
        Returns:
            List of potential conflicts
        """
        conflicts = []
        
        try:
            # Create temporary working directory
            with tempfile.TemporaryDirectory() as temp_dir:
                temp_repo_path = Path(temp_dir) / "temp_repo"
                
                # Clone repository to temporary location
                temp_repo = self.repo.clone(temp_repo_path)
                
                # Attempt merge in temporary repo
                temp_repo.git.checkout(target_branch)
                
                try:
                    temp_repo.git.merge(source_branch, '--no-commit')
                except GitCommandError as e:
                    if "conflict" in str(e).lower():
                        # Parse conflict information
                        status = temp_repo.git.status('--porcelain')
                        
                        for line in status.split('\n'):
                            if line.startswith('UU '):  # Both modified
                                file_path = line[3:].strip()
                                
                                # Get file contents from both branches
                                try:
                                    base_content = temp_repo.git.show(f"{target_branch}:{file_path}")
                                    head_content = temp_repo.git.show(f"{source_branch}:{file_path}")
                                    
                                    # Get conflicted content
                                    with open(temp_repo_path / file_path, 'r') as f:
                                        merge_content = f.read()
                                    
                                    conflict = MergeConflict(
                                        file_path=file_path,
                                        conflict_type="both_modified",
                                        base_content=base_content,
                                        head_content=head_content,
                                        merge_content=merge_content,
                                        resolution_strategy=None,
                                        resolved=False,
                                        resolved_by=None,
                                        resolved_date=None
                                    )
                                    conflicts.append(conflict)
                                    
                                except Exception as inner_e:
                                    logger.warning(f"Could not analyze conflict in {file_path}: {inner_e}")
        
        except Exception as e:
            logger.error(f"Failed to detect merge conflicts: {e}")
        
        return conflicts
    
    def resolve_merge_conflict(self, conflict: MergeConflict, resolution_content: str, 
                             resolved_by: str) -> bool:
        """
        Resolve a merge conflict
        
        Args:
            conflict: Merge conflict to resolve
            resolution_content: Resolved file content
            resolved_by: Person resolving the conflict
        
        Returns:
            Success status
        """
        try:
            # Write resolved content to file
            file_path = self.repo_path / conflict.file_path
            
            with open(file_path, 'w') as f:
                f.write(resolution_content)
            
            # Stage the resolved file
            self.repo.index.add([conflict.file_path])
            
            # Update conflict information
            conflict.resolved = True
            conflict.resolved_by = resolved_by
            conflict.resolved_date = datetime.now().isoformat()
            
            logger.info(f"Resolved merge conflict in {conflict.file_path}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to resolve merge conflict in {conflict.file_path}: {e}")
            return False
    
    def delete_branch(self, branch_name: str, force: bool = False) -> bool:
        """
        Delete a branch
        
        Args:
            branch_name: Branch to delete
            force: Force deletion even if not merged
        
        Returns:
            Success status
        """
        try:
            # Update metadata status
            if branch_name in self.branch_metadata:
                self.branch_metadata[branch_name].status = BranchStatus.ARCHIVED
                self.branch_metadata[branch_name].last_activity = datetime.now().isoformat()
            
            # Delete local branch
            delete_flag = '-D' if force else '-d'
            self.repo.git.branch(delete_flag, branch_name)
            
            # Delete remote branch if it exists
            try:
                self.repo.git.push('origin', '--delete', branch_name)
            except GitCommandError:
                # Remote branch might not exist
                pass
            
            self._save_branch_metadata()
            
            logger.info(f"Deleted branch: {branch_name}")
            return True
            
        except GitCommandError as e:
            logger.error(f"Failed to delete branch {branch_name}: {e}")
            return False
    
    def create_tag(self, tag_name: str, message: str, branch_name: Optional[str] = None) -> bool:
        """
        Create a Git tag
        
        Args:
            tag_name: Tag name
            message: Tag message
            branch_name: Branch to tag (current if None)
        
        Returns:
            Success status
        """
        try:
            if branch_name and self.repo.active_branch.name != branch_name:
                self.switch_branch(branch_name)
            
            # Create annotated tag
            self.repo.create_tag(tag_name, message=message)
            
            # Push tag to remote
            self.repo.git.push('origin', tag_name)
            
            logger.info(f"Created tag: {tag_name}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to create tag {tag_name}: {e}")
            return False
    
    def list_branches(self, branch_type: Optional[BranchType] = None, 
                     status: Optional[BranchStatus] = None) -> List[BranchMetadata]:
        """
        List branches with optional filtering
        
        Args:
            branch_type: Filter by branch type
            status: Filter by status
        
        Returns:
            List of branch metadata
        """
        branches = []
        
        for metadata in self.branch_metadata.values():
            if branch_type and metadata.branch_type != branch_type:
                continue
            
            if status and metadata.status != status:
                continue
            
            branches.append(metadata)
        
        # Sort by creation date (newest first)
        branches.sort(key=lambda b: b.created_date, reverse=True)
        return branches
    
    def get_branch_info(self, branch_name: str) -> Optional[Dict[str, Any]]:
        """
        Get comprehensive branch information
        
        Args:
            branch_name: Branch name
        
        Returns:
            Branch information dictionary
        """
        if branch_name not in self.branch_metadata:
            return None
        
        metadata = self.branch_metadata[branch_name]
        
        # Get Git information
        try:
            branch_ref = next((ref for ref in self.repo.refs if ref.name == branch_name), None)
            if branch_ref:
                last_commit = branch_ref.commit
                commit_info = {
                    "hash": last_commit.hexsha,
                    "message": last_commit.message.strip(),
                    "author": str(last_commit.author),
                    "date": last_commit.committed_datetime.isoformat()
                }
            else:
                commit_info = None
        except Exception:
            commit_info = None
        
        # Get branch age
        created_date = datetime.fromisoformat(metadata.created_date.replace('Z', '+00:00'))
        age_days = (datetime.now(created_date.tzinfo) - created_date).days
        
        # Check if branch is stale
        config = self.branch_configs.get(metadata.branch_type)
        is_stale = config and config.max_lifetime_days and age_days > config.max_lifetime_days
        
        info = {
            "metadata": asdict(metadata),
            "git_info": commit_info,
            "age_days": age_days,
            "is_stale": is_stale,
            "config": asdict(config) if config else None
        }
        
        # Convert enums to strings for JSON serialization
        info["metadata"]["branch_type"] = info["metadata"]["branch_type"].value
        info["metadata"]["status"] = info["metadata"]["status"].value
        
        if info["config"]:
            info["config"]["branch_type"] = info["config"]["branch_type"].value
            info["config"]["merge_strategy"] = info["config"]["merge_strategy"].value
        
        return info
    
    def cleanup_branches(self, dry_run: bool = True) -> Dict[str, List[str]]:
        """
        Clean up stale and merged branches
        
        Args:
            dry_run: Only report what would be cleaned, don't actually delete
        
        Returns:
            Dictionary of cleanup actions
        """
        cleanup_report = {
            "stale_branches": [],
            "merged_branches": [],
            "abandoned_branches": [],
            "errors": []
        }
        
        if not self.config["cleanup"]["auto_cleanup_days"]:
            return cleanup_report
        
        cutoff_date = datetime.now() - timedelta(days=self.config["cleanup"]["auto_cleanup_days"])
        
        for branch_name, metadata in self.branch_metadata.items():
            try:
                last_activity = datetime.fromisoformat(metadata.last_activity.replace('Z', '+00:00'))
                
                # Skip protected branches
                if metadata.branch_type in [BranchType.MAIN, BranchType.DEVELOPMENT, BranchType.RELEASE]:
                    continue
                
                # Skip branches with tags if configured to preserve them
                if self.config["cleanup"]["preserve_tagged_branches"] and metadata.tags:
                    continue
                
                # Check for stale branches
                config = self.branch_configs.get(metadata.branch_type)
                if config and config.max_lifetime_days:
                    max_age = timedelta(days=config.max_lifetime_days)
                    if datetime.now() - datetime.fromisoformat(metadata.created_date.replace('Z', '+00:00')) > max_age:
                        cleanup_report["stale_branches"].append(branch_name)
                        if not dry_run:
                            self.delete_branch(branch_name, force=True)
                
                # Check for merged branches
                if (metadata.status == BranchStatus.MERGED and 
                    self.config["cleanup"]["cleanup_merged_branches"] and
                    last_activity < cutoff_date):
                    cleanup_report["merged_branches"].append(branch_name)
                    if not dry_run:
                        self.delete_branch(branch_name, force=True)
                
                # Check for abandoned branches
                if (metadata.status in [BranchStatus.ACTIVE, BranchStatus.UNDER_REVIEW] and
                    self.config["cleanup"]["cleanup_abandoned_branches"] and
                    last_activity < cutoff_date):
                    cleanup_report["abandoned_branches"].append(branch_name)
                    if not dry_run:
                        metadata.status = BranchStatus.ABANDONED
            
            except Exception as e:
                cleanup_report["errors"].append(f"Error processing {branch_name}: {str(e)}")
        
        if not dry_run:
            self._save_branch_metadata()
        
        return cleanup_report
    
    def get_content_history(self, content_path: str) -> List[ContentVersion]:
        """
        Get version history for content file
        
        Args:
            content_path: Path to content file
        
        Returns:
            List of content versions
        """
        return self.content_versions.get(content_path, [])
    
    def generate_branching_report(self) -> Dict[str, Any]:
        """
        Generate comprehensive branching strategy report
        
        Returns:
            Branching report dictionary
        """
        report = {
            "generated": datetime.now().isoformat(),
            "repository": str(self.repo_path),
            "summary": {
                "total_branches": len(self.branch_metadata),
                "active_branches": len([b for b in self.branch_metadata.values() if b.status == BranchStatus.ACTIVE]),
                "merged_branches": len([b for b in self.branch_metadata.values() if b.status == BranchStatus.MERGED]),
                "abandoned_branches": len([b for b in self.branch_metadata.values() if b.status == BranchStatus.ABANDONED])
            },
            "by_type": {},
            "by_status": {},
            "age_distribution": {
                "0-7_days": 0,
                "8-30_days": 0,
                "31-90_days": 0,
                "90+_days": 0
            },
            "activity_summary": {
                "total_commits": sum(b.commit_count for b in self.branch_metadata.values()),
                "total_file_changes": {
                    "added": sum(b.file_changes.get('added', 0) for b in self.branch_metadata.values()),
                    "modified": sum(b.file_changes.get('modified', 0) for b in self.branch_metadata.values()),
                    "deleted": sum(b.file_changes.get('deleted', 0) for b in self.branch_metadata.values())
                }
            },
            "content_versions": {
                "total_content_files": len(self.content_versions),
                "total_versions": sum(len(versions) for versions in self.content_versions.values()),
                "by_content": {path: len(versions) for path, versions in self.content_versions.items()}
            },
            "recommendations": []
        }
        
        # Calculate statistics
        now = datetime.now()
        
        for metadata in self.branch_metadata.values():
            # By type
            branch_type = metadata.branch_type.value
            report["by_type"][branch_type] = report["by_type"].get(branch_type, 0) + 1
            
            # By status
            status = metadata.status.value
            report["by_status"][status] = report["by_status"].get(status, 0) + 1
            
            # Age distribution
            created_date = datetime.fromisoformat(metadata.created_date.replace('Z', '+00:00'))
            age_days = (now - created_date).days
            
            if age_days <= 7:
                report["age_distribution"]["0-7_days"] += 1
            elif age_days <= 30:
                report["age_distribution"]["8-30_days"] += 1
            elif age_days <= 90:
                report["age_distribution"]["31-90_days"] += 1
            else:
                report["age_distribution"]["90+_days"] += 1
        
        # Generate recommendations
        stale_count = report["age_distribution"]["90+_days"]
        if stale_count > 0:
            report["recommendations"].append(f"Consider cleaning up {stale_count} branches older than 90 days")
        
        abandoned_count = report["summary"]["abandoned_branches"]
        if abandoned_count > 5:
            report["recommendations"].append(f"High number of abandoned branches ({abandoned_count}) - review branch lifecycle")
        
        active_count = report["summary"]["active_branches"]
        if active_count > self.config["repository"]["max_concurrent_branches"]:
            report["recommendations"].append(f"Too many active branches ({active_count}) - consider merging or archiving")
        
        return report


def main():
    """Main function for CLI usage"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Content Branching Strategy Manager")
    parser.add_argument("--repo", default=".", help="Repository path")
    parser.add_argument("--config", help="Configuration file path")
    parser.add_argument("--command", required=True,
                       choices=["create", "switch", "commit", "merge", "delete", "list", "info", "cleanup", "report"],
                       help="Command to execute")
    
    # Command-specific arguments
    parser.add_argument("--branch-type", help="Branch type")
    parser.add_argument("--content-id", help="Content ID")
    parser.add_argument("--author", help="Author name")
    parser.add_argument("--branch-name", help="Branch name")
    parser.add_argument("--message", help="Commit message")
    parser.add_argument("--source-branch", help="Source branch for merge")
    parser.add_argument("--target-branch", help="Target branch for merge")
    parser.add_argument("--dry-run", action="store_true", help="Dry run mode")
    parser.add_argument("--force", action="store_true", help="Force operation")
    parser.add_argument("--output", help="Output file path")
    
    args = parser.parse_args()
    
    try:
        branching = ContentBranchingStrategy(args.repo, args.config)
        
        if args.command == "create":
            if not all([args.branch_type, args.content_id, args.author]):
                print("Error: branch-type, content-id, and author are required for create command")
                return
            
            branch_type = BranchType(args.branch_type)
            branch_name = branching.create_content_branch(branch_type, args.content_id, args.author)
            print(f"Created branch: {branch_name}")
        
        elif args.command == "switch":
            if not args.branch_name:
                print("Error: branch-name is required for switch command")
                return
            
            success = branching.switch_branch(args.branch_name)
            print(f"Switch to {args.branch_name}: {'Success' if success else 'Failed'}")
        
        elif args.command == "commit":
            if not all([args.branch_name, args.message]):
                print("Error: branch-name and message are required for commit command")
                return
            
            commit_hash = branching.commit_changes(args.branch_name, args.message)
            print(f"Committed: {commit_hash[:8]}")
        
        elif args.command == "merge":
            if not all([args.source_branch, args.target_branch]):
                print("Error: source-branch and target-branch are required for merge command")
                return
            
            success = branching.merge_branch(args.source_branch, args.target_branch)
            print(f"Merge {args.source_branch} into {args.target_branch}: {'Success' if success else 'Failed'}")
        
        elif args.command == "delete":
            if not args.branch_name:
                print("Error: branch-name is required for delete command")
                return
            
            success = branching.delete_branch(args.branch_name, args.force)
            print(f"Delete {args.branch_name}: {'Success' if success else 'Failed'}")
        
        elif args.command == "list":
            branches = branching.list_branches()
            print(f"Found {len(branches)} branches:")
            for branch in branches:
                print(f"  {branch.branch_name}: {branch.branch_type.value} ({branch.status.value})")
        
        elif args.command == "info":
            if not args.branch_name:
                print("Error: branch-name is required for info command")
                return
            
            info = branching.get_branch_info(args.branch_name)
            if info:
                print(json.dumps(info, indent=2))
            else:
                print(f"Branch {args.branch_name} not found")
        
        elif args.command == "cleanup":
            cleanup_report = branching.cleanup_branches(args.dry_run)
            print("Cleanup Report:")
            print(json.dumps(cleanup_report, indent=2))
        
        elif args.command == "report":
            report = branching.generate_branching_report()
            
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