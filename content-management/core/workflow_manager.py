#!/usr/bin/env python3
"""
Workflow Manager
===============

Git-based workflow manager for the Chapter Content Management System.
Provides Git workflow automation, branch management, and integration
with content review and approval processes.

This module provides:
- Git branch management and automation
- Content review workflow orchestration
- Pull request and merge management
- Automated quality gates and checks
- Integration with validation and metadata systems

Author: Claude Code Implementation
Version: 1.0.0
"""

import os
import json
import logging
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Any, Union, Tuple
from datetime import datetime, timedelta
import git
from git import Repo, GitCommandError

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class WorkflowManager:
    """
    Git-based Workflow Manager
    
    Manages Git workflows for content development, review, and deployment
    including branch management, automated checks, and integration processes.
    """
    
    def __init__(self, repo_path: Path, config: Dict[str, Any]):
        """
        Initialize Workflow Manager
        
        Args:
            repo_path: Path to the Git repository
            config: CMS configuration dictionary
        """
        self.repo_path = Path(repo_path)
        self.config = config
        self.workflow_config = config.get("workflow", {})
        
        # Initialize Git repository
        try:
            self.repo = Repo(self.repo_path)
        except git.InvalidGitRepositoryError:
            raise ValueError(f"Invalid Git repository at {self.repo_path}")
        
        # Workflow settings
        self.main_branch = self.workflow_config.get("main_branch", "main")
        self.branch_prefix = self.workflow_config.get("branch_prefix", "content/")
        self.review_prefix = self.workflow_config.get("review_prefix", "review/")
        self.auto_branch = self.workflow_config.get("auto_branch", True)
        self.merge_strategy = self.workflow_config.get("merge_strategy", "squash")
        
        # Cache for workflow state
        self.workflow_cache_path = self.repo_path / "content-management" / "cache" / "workflows.json"
        self.workflow_cache_path.parent.mkdir(parents=True, exist_ok=True)
        self.workflow_cache = self._load_workflow_cache()
        
        logger.info(f"Workflow Manager initialized for: {self.repo_path}")
    
    def _load_workflow_cache(self) -> Dict[str, Dict[str, Any]]:
        """Load workflow cache from disk"""
        if self.workflow_cache_path.exists():
            try:
                with open(self.workflow_cache_path, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception as e:
                logger.warning(f"Failed to load workflow cache: {e}")
        return {}
    
    def _save_workflow_cache(self):
        """Save workflow cache to disk"""
        try:
            with open(self.workflow_cache_path, 'w', encoding='utf-8') as f:
                json.dump(self.workflow_cache, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save workflow cache: {e}")
    
    def create_content_branch(self, chapter_id: str, branch_type: str = "feature") -> str:
        """
        Create a new content development branch
        
        Args:
            chapter_id: Chapter identifier
            branch_type: Type of branch (feature, update, hotfix)
            
        Returns:
            Created branch name
        """
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        branch_name = f"{self.branch_prefix}{chapter_id}-{branch_type}-{timestamp}"
        
        try:
            # Ensure we're on the main branch and up to date
            self.repo.git.checkout(self.main_branch)
            self.repo.git.pull('origin', self.main_branch)
            
            # Create new branch
            self.repo.git.checkout('-b', branch_name)
            
            # Cache branch information
            self.workflow_cache[branch_name] = {
                "created": datetime.now().isoformat(),
                "chapter_id": chapter_id,
                "branch_type": branch_type,
                "status": "active",
                "commits": [],
                "validations": []
            }
            self._save_workflow_cache()
            
            logger.info(f"Created content branch: {branch_name}")
            return branch_name
            
        except GitCommandError as e:
            logger.error(f"Failed to create branch {branch_name}: {e}")
            raise
    
    def create_review_branch(self, content_branch: str) -> str:
        """
        Create a review branch from content branch
        
        Args:
            content_branch: Source content branch name
            
        Returns:
            Review branch name
        """
        review_branch = content_branch.replace(self.branch_prefix, self.review_prefix)
        
        try:
            # Switch to content branch
            self.repo.git.checkout(content_branch)
            
            # Create review branch
            self.repo.git.checkout('-b', review_branch)
            
            # Update cache
            if content_branch in self.workflow_cache:
                self.workflow_cache[review_branch] = self.workflow_cache[content_branch].copy()
                self.workflow_cache[review_branch]["status"] = "review"
                self.workflow_cache[review_branch]["review_created"] = datetime.now().isoformat()
                self._save_workflow_cache()
            
            logger.info(f"Created review branch: {review_branch}")
            return review_branch
            
        except GitCommandError as e:
            logger.error(f"Failed to create review branch {review_branch}: {e}")
            raise
    
    def commit_changes(self, 
                      message: str,
                      files: Optional[List[str]] = None,
                      auto_validate: bool = True) -> str:
        """
        Commit changes with optional validation
        
        Args:
            message: Commit message
            files: List of files to commit (None for all changes)
            auto_validate: Whether to run validation before commit
            
        Returns:
            Commit hash
        """
        try:
            current_branch = self.repo.active_branch.name
            
            # Run validation if enabled
            validation_results = {}
            if auto_validate and self.config.get("validation", {}).get("auto_validate", True):
                validation_results = self._validate_changes(files)
                
                # Check if validation passes minimum requirements
                min_score = self.config.get("validation", {}).get("minimum_score", 80.0)
                for file_path, result in validation_results.items():
                    if result.get("overall_score", 0) < min_score:
                        logger.warning(f"Validation below threshold for {file_path}: {result['overall_score']}")
                        # Could block commit here if strict mode is enabled
            
            # Stage files
            if files:
                self.repo.index.add(files)
            else:
                self.repo.git.add('.')
            
            # Create commit
            commit = self.repo.index.commit(message)
            commit_hash = commit.hexsha
            
            # Update workflow cache
            if current_branch in self.workflow_cache:
                self.workflow_cache[current_branch]["commits"].append({
                    "hash": commit_hash[:8],
                    "message": message,
                    "timestamp": datetime.now().isoformat(),
                    "validation": validation_results
                })
                self._save_workflow_cache()
            
            logger.info(f"Committed changes: {commit_hash[:8]} - {message}")
            return commit_hash
            
        except Exception as e:
            logger.error(f"Failed to commit changes: {e}")
            raise
    
    def _validate_changes(self, files: Optional[List[str]] = None) -> Dict[str, Dict[str, Any]]:
        """
        Validate changes before commit
        
        Args:
            files: List of files to validate
            
        Returns:
            Validation results for each file
        """
        validation_results = {}
        
        try:
            # Import validation engine (avoid circular import)
            from .validation_engine import ValidationEngine
            
            validator = ValidationEngine(self.repo_path, self.config)
            
            # Determine files to validate
            if files is None:
                # Get all changed files
                changed_files = [item.a_path for item in self.repo.index.diff(self.repo.head.commit)]
                changed_files.extend([item.a_path for item in self.repo.index.diff(None)])
            else:
                changed_files = files
            
            # Filter for supported file types
            supported_extensions = self.config.get("content", {}).get("supported_formats", [".md", ".ipynb"])
            content_files = [f for f in changed_files 
                           if any(f.endswith(ext) for ext in supported_extensions)]
            
            # Validate each file
            for file_path in content_files:
                file_full_path = self.repo_path / file_path
                if file_full_path.exists():
                    result = validator.validate_content(file_full_path)
                    validation_results[file_path] = result
            
        except Exception as e:
            logger.error(f"Validation during commit failed: {e}")
            # Don't block commit on validation failure
        
        return validation_results
    
    def push_branch(self, 
                   branch_name: Optional[str] = None,
                   set_upstream: bool = True) -> bool:
        """
        Push branch to remote repository
        
        Args:
            branch_name: Branch to push (current branch if None)
            set_upstream: Whether to set upstream tracking
            
        Returns:
            Success status
        """
        try:
            if branch_name:
                self.repo.git.push('origin', branch_name, '-u' if set_upstream else '')
            else:
                current_branch = self.repo.active_branch.name
                self.repo.git.push('origin', current_branch, '-u' if set_upstream else '')
                branch_name = current_branch
            
            # Update cache
            if branch_name in self.workflow_cache:
                self.workflow_cache[branch_name]["last_pushed"] = datetime.now().isoformat()
                self._save_workflow_cache()
            
            logger.info(f"Pushed branch to remote: {branch_name}")
            return True
            
        except GitCommandError as e:
            logger.error(f"Failed to push branch {branch_name}: {e}")
            return False
    
    def create_pull_request_info(self, 
                                source_branch: str,
                                target_branch: str = None,
                                metadata: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Generate pull request information
        
        Args:
            source_branch: Source branch name
            target_branch: Target branch name (main if None)
            metadata: Content metadata for PR details
            
        Returns:
            Pull request information dictionary
        """
        if target_branch is None:
            target_branch = self.main_branch
        
        # Get branch information from cache
        branch_info = self.workflow_cache.get(source_branch, {})
        chapter_id = branch_info.get("chapter_id", "unknown")
        branch_type = branch_info.get("branch_type", "update")
        
        # Build PR title and description
        if metadata:
            title = f"Content {branch_type.title()}: {metadata.get('title', chapter_id)}"
            platforms = ", ".join(metadata.get("platforms", ["General"]))
            
            body = f"""## Content {branch_type.title()} Summary

**Chapter**: {chapter_id}
**Title**: {metadata.get('title', 'N/A')}
**Author**: {metadata.get('author', 'N/A')}
**Platforms**: {platforms}
**Difficulty**: {metadata.get('difficulty_level', 'N/A')}

### Learning Objectives
{self._format_list(metadata.get('learning_objectives', []))}

### Prerequisites  
{self._format_list(metadata.get('prerequisites', []))}

### Changes Summary
{self._get_branch_changes_summary(source_branch)}

### Validation Status
{self._get_validation_summary(source_branch)}

### Review Checklist
- [ ] Content accuracy and technical correctness
- [ ] Educational effectiveness and clarity
- [ ] Code examples test successfully
- [ ] Links and references are valid
- [ ] Metadata is complete and accurate
- [ ] Style and formatting consistency
- [ ] Accessibility considerations addressed

### Additional Notes
Please review the content changes and provide feedback on educational effectiveness and technical accuracy.

---
*Generated by Content Management System - Workflow Manager*"""
        
        else:
            title = f"Content {branch_type.title()}: {chapter_id}"
            body = f"""## Content {branch_type.title()}

**Branch**: {source_branch}
**Chapter**: {chapter_id}
**Type**: {branch_type}

### Changes Summary
{self._get_branch_changes_summary(source_branch)}

### Review Required
Please review the content changes in this pull request.

---
*Generated by Content Management System - Workflow Manager*"""
        
        pr_info = {
            "title": title,
            "body": body,
            "head": source_branch,
            "base": target_branch,
            "draft": branch_info.get("status") != "review_ready",
            "labels": self._get_pr_labels(source_branch, metadata),
            "reviewers": metadata.get("reviewers", []) if metadata else []
        }
        
        return pr_info
    
    def _format_list(self, items: List[str]) -> str:
        """Format list items for markdown"""
        if not items:
            return "None specified"
        return "\n".join(f"- {item}" for item in items)
    
    def _get_branch_changes_summary(self, branch_name: str) -> str:
        """Get summary of changes in branch"""
        try:
            # Get commits in branch
            commits = list(self.repo.iter_commits(f'{self.main_branch}..{branch_name}'))
            
            if not commits:
                return "No commits found"
            
            summary = f"**Commits**: {len(commits)}\n\n"
            
            for commit in commits[:5]:  # Show last 5 commits
                summary += f"- {commit.hexsha[:8]}: {commit.message.strip()}\n"
            
            if len(commits) > 5:
                summary += f"- ... and {len(commits) - 5} more commits\n"
            
            # Get file changes
            try:
                diff = self.repo.git.diff(f'{self.main_branch}...{branch_name}', '--name-status')
                if diff:
                    summary += f"\n**Files Changed**:\n```\n{diff}\n```"
            except:
                pass
            
            return summary
            
        except Exception as e:
            logger.warning(f"Failed to get branch changes summary: {e}")
            return "Unable to generate changes summary"
    
    def _get_validation_summary(self, branch_name: str) -> str:
        """Get validation summary for branch"""
        branch_info = self.workflow_cache.get(branch_name, {})
        
        # Get latest validation results from commits
        all_validations = []
        for commit in branch_info.get("commits", []):
            validation = commit.get("validation", {})
            all_validations.extend(validation.values())
        
        if not all_validations:
            return "No validation results available"
        
        # Calculate summary statistics
        total_files = len(all_validations)
        passed_files = sum(1 for v in all_validations if v.get("passed", False))
        avg_score = sum(v.get("overall_score", 0) for v in all_validations) / total_files
        
        total_errors = sum(len(v.get("errors", [])) for v in all_validations)
        total_warnings = sum(len(v.get("warnings", [])) for v in all_validations)
        
        status_emoji = "✅" if passed_files == total_files else "⚠️" if passed_files > 0 else "❌"
        
        summary = f"""{status_emoji} **Validation Results**:
- Files validated: {total_files}
- Files passing: {passed_files}/{total_files}
- Average score: {avg_score:.1f}%
- Total errors: {total_errors}
- Total warnings: {total_warnings}"""
        
        return summary
    
    def _get_pr_labels(self, branch_name: str, metadata: Optional[Dict[str, Any]] = None) -> List[str]:
        """Get appropriate labels for pull request"""
        labels = []
        
        # Add branch type label
        if "feature" in branch_name:
            labels.append("enhancement")
        elif "hotfix" in branch_name:
            labels.append("bug")
        elif "update" in branch_name:
            labels.append("documentation")
        
        # Add content type labels
        if metadata:
            content_type = metadata.get("content_type", "")
            if content_type:
                labels.append(f"content-{content_type}")
            
            # Add platform labels
            for platform in metadata.get("platforms", []):
                labels.append(f"platform-{platform}")
            
            # Add difficulty label
            difficulty = metadata.get("difficulty_level", "")
            if difficulty:
                labels.append(f"difficulty-{difficulty}")
        
        return labels
    
    def merge_branch(self, 
                    source_branch: str,
                    target_branch: str = None,
                    delete_source: bool = True,
                    strategy: str = None) -> bool:
        """
        Merge content branch into target branch
        
        Args:
            source_branch: Source branch to merge
            target_branch: Target branch (main if None)
            delete_source: Whether to delete source branch after merge
            strategy: Merge strategy (squash, merge, rebase)
            
        Returns:
            Success status
        """
        if target_branch is None:
            target_branch = self.main_branch
        
        if strategy is None:
            strategy = self.merge_strategy
        
        try:
            # Switch to target branch and update
            self.repo.git.checkout(target_branch)
            self.repo.git.pull('origin', target_branch)
            
            # Perform merge based on strategy
            if strategy == "squash":
                self.repo.git.merge(source_branch, '--squash', '--no-commit')
                # Create squash commit
                merge_message = f"Merge {source_branch} into {target_branch}"
                self.repo.index.commit(merge_message)
            elif strategy == "rebase":
                self.repo.git.rebase(source_branch)
            else:  # regular merge
                self.repo.git.merge(source_branch, '--no-ff')
            
            # Push merged changes
            self.repo.git.push('origin', target_branch)
            
            # Update workflow cache
            if source_branch in self.workflow_cache:
                self.workflow_cache[source_branch]["status"] = "merged"
                self.workflow_cache[source_branch]["merged_at"] = datetime.now().isoformat()
                self.workflow_cache[source_branch]["merged_into"] = target_branch
                self._save_workflow_cache()
            
            # Delete source branch if requested
            if delete_source:
                try:
                    self.repo.git.branch('-d', source_branch)
                    self.repo.git.push('origin', '--delete', source_branch)
                    
                    # Remove from cache
                    if source_branch in self.workflow_cache:
                        del self.workflow_cache[source_branch]
                        self._save_workflow_cache()
                        
                except GitCommandError as e:
                    logger.warning(f"Failed to delete branch {source_branch}: {e}")
            
            logger.info(f"Merged {source_branch} into {target_branch} using {strategy} strategy")
            return True
            
        except GitCommandError as e:
            logger.error(f"Failed to merge {source_branch} into {target_branch}: {e}")
            return False
    
    def cleanup_branches(self, older_than_days: int = 30) -> Dict[str, Any]:
        """
        Clean up old merged branches
        
        Args:
            older_than_days: Delete branches older than this many days
            
        Returns:
            Cleanup results
        """
        cleanup_result = {
            "branches_deleted": [],
            "branches_skipped": [],
            "errors": []
        }
        
        cutoff_date = datetime.now() - timedelta(days=older_than_days)
        
        try:
            # Get all branches
            branches = [ref.name.split('/')[-1] for ref in self.repo.refs if ref.name.startswith('refs/heads/')]
            
            for branch_name in branches:
                # Skip main branches
                if branch_name in [self.main_branch, 'master', 'develop']:
                    continue
                
                # Check if branch is tracked in cache
                if branch_name in self.workflow_cache:
                    branch_info = self.workflow_cache[branch_name]
                    
                    # Check if merged and old enough
                    if branch_info.get("status") == "merged":
                        merged_date_str = branch_info.get("merged_at")
                        if merged_date_str:
                            try:
                                merged_date = datetime.fromisoformat(merged_date_str)
                                if merged_date < cutoff_date:
                                    # Delete branch
                                    try:
                                        self.repo.git.branch('-D', branch_name)
                                        self.repo.git.push('origin', '--delete', branch_name)
                                        
                                        cleanup_result["branches_deleted"].append(branch_name)
                                        
                                        # Remove from cache
                                        del self.workflow_cache[branch_name]
                                        
                                    except GitCommandError as e:
                                        cleanup_result["errors"].append(f"Failed to delete {branch_name}: {str(e)}")
                                else:
                                    cleanup_result["branches_skipped"].append(f"{branch_name} (too recent)")
                            except ValueError:
                                cleanup_result["branches_skipped"].append(f"{branch_name} (invalid date)")
                    else:
                        cleanup_result["branches_skipped"].append(f"{branch_name} (not merged)")
                else:
                    cleanup_result["branches_skipped"].append(f"{branch_name} (not tracked)")
            
            # Save updated cache
            self._save_workflow_cache()
            
            logger.info(f"Branch cleanup completed: {len(cleanup_result['branches_deleted'])} deleted")
            
        except Exception as e:
            cleanup_result["errors"].append(f"Cleanup failed: {str(e)}")
            logger.error(f"Branch cleanup failed: {e}")
        
        return cleanup_result
    
    def get_workflow_status(self) -> Dict[str, Any]:
        """
        Get current workflow status
        
        Returns:
            Workflow status information
        """
        try:
            current_branch = self.repo.active_branch.name
            
            # Count branches by status  
            active_branches = sum(1 for info in self.workflow_cache.values() 
                                if info.get("status") == "active")
            review_branches = sum(1 for info in self.workflow_cache.values() 
                                if info.get("status") == "review")
            merged_branches = sum(1 for info in self.workflow_cache.values() 
                               if info.get("status") == "merged")
            
            # Get recent activity
            recent_commits = list(self.repo.iter_commits(max_count=10))
            
            status = {
                "current_branch": current_branch,
                "main_branch": self.main_branch,
                "repository_status": {
                    "dirty": self.repo.is_dirty(),
                    "untracked_files": len(self.repo.untracked_files),
                    "staged_files": len([item for item in self.repo.index.diff(self.repo.head.commit)])
                },
                "branch_summary": {
                    "active": active_branches,
                    "in_review": review_branches,
                    "merged": merged_branches,
                    "total_tracked": len(self.workflow_cache)
                },
                "recent_activity": [
                    {
                        "hash": commit.hexsha[:8],
                        "message": commit.message.strip(),
                        "author": str(commit.author),
                        "date": commit.committed_datetime.isoformat()
                    }
                    for commit in recent_commits
                ],
                "workflow_config": {
                    "auto_branch": self.auto_branch,
                    "merge_strategy": self.merge_strategy,
                    "branch_prefix": self.branch_prefix
                }
            }
            
            return status
            
        except Exception as e:
            logger.error(f"Failed to get workflow status: {e}")
            return {"error": str(e)}
    
    def get_workflow_summary(self) -> Dict[str, Any]:
        """
        Get workflow system summary
        
        Returns:
            Summary of workflow system
        """
        status = self.get_workflow_status()
        
        summary = {
            "total_branches_managed": len(self.workflow_cache),
            "active_workflows": status.get("branch_summary", {}).get("active", 0),
            "branches_in_review": status.get("branch_summary", {}).get("in_review", 0),
            "recent_merges": status.get("branch_summary", {}).get("merged", 0),
            "current_branch": status.get("current_branch"),
            "repository_clean": not status.get("repository_status", {}).get("dirty", True),
            "workflow_features": {
                "auto_branch_creation": self.auto_branch,
                "automated_validation": self.config.get("validation", {}).get("auto_validate", False),
                "merge_strategy": self.merge_strategy
            },
            "cache_path": str(self.workflow_cache_path),
            "last_updated": datetime.now().isoformat()
        }
        
        return summary


def main():
    """Main function for CLI usage"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Workflow Manager")
    parser.add_argument("--repo", default=".", help="Repository path")
    parser.add_argument("--command", required=True,
                       choices=["create-branch", "commit", "push", "merge", "pr-info", "status", "cleanup"],
                       help="Command to execute")
    parser.add_argument("--chapter-id", help="Chapter ID for branch creation")
    parser.add_argument("--branch-type", default="feature", help="Branch type")
    parser.add_argument("--message", help="Commit message")
    parser.add_argument("--source-branch", help="Source branch for operations")
    parser.add_argument("--target-branch", help="Target branch for operations")
    parser.add_argument("--cleanup-days", type=int, default=30, help="Days for cleanup threshold")
    
    args = parser.parse_args()
    
    try:
        config = {
            "workflow": {
                "main_branch": "main",
                "auto_branch": True,
                "merge_strategy": "squash"
            },
            "validation": {
                "auto_validate": True,
                "minimum_score": 80.0
            }
        }
        
        manager = WorkflowManager(Path(args.repo), config)
        
        if args.command == "create-branch":
            if not args.chapter_id:
                print("Error: chapter-id is required for branch creation")
                return
            
            branch_name = manager.create_content_branch(args.chapter_id, args.branch_type)
            print(f"Created branch: {branch_name}")
        
        elif args.command == "commit":
            if not args.message:
                print("Error: message is required for commit")
                return
            
            commit_hash = manager.commit_changes(args.message)
            print(f"Committed changes: {commit_hash[:8]}")
        
        elif args.command == "push":
            success = manager.push_branch(args.source_branch)
            if success:
                print(f"Successfully pushed branch: {args.source_branch or 'current'}")
            else:
                print("Failed to push branch")
        
        elif args.command == "merge":
            if not args.source_branch:
                print("Error: source-branch is required for merge")
                return
            
            success = manager.merge_branch(args.source_branch, args.target_branch)
            if success:
                print(f"Successfully merged {args.source_branch}")
            else:
                print("Failed to merge branch")
        
        elif args.command == "pr-info":
            if not args.source_branch:
                print("Error: source-branch is required for PR info")
                return
            
            pr_info = manager.create_pull_request_info(args.source_branch, args.target_branch)
            print(json.dumps(pr_info, indent=2))
        
        elif args.command == "status":
            status = manager.get_workflow_status()
            print(json.dumps(status, indent=2))
        
        elif args.command == "cleanup":
            result = manager.cleanup_branches(args.cleanup_days)
            print(f"Cleanup completed:")
            print(f"  Branches deleted: {len(result['branches_deleted'])}")
            print(f"  Branches skipped: {len(result['branches_skipped'])}")
            if result["errors"]:
                print(f"  Errors: {len(result['errors'])}")
    
    except Exception as e:
        logger.error(f"Command failed: {e}")
        print(f"Error: {e}")
        return 1


if __name__ == "__main__":
    exit(main())