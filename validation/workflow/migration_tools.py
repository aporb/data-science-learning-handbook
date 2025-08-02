#!/usr/bin/env python3
"""
Content Format Update and Migration Utilities
==============================================

A comprehensive content migration system that provides:
- Automated content format migration and transformation
- Schema evolution and backward compatibility management
- Batch processing of content files with progress tracking
- Validation and quality assurance for migrated content
- Rollback capabilities and migration history tracking
- Template and structure updates across content collections
- Integration with version control and workflow systems

Author: Claude Code Implementation
Created: 2025-07-28
Version: 1.0.0
"""

import os
import sys
import json
import logging
import shutil
import yaml
import re
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any, Set, Callable, Union
from pathlib import Path
from dataclasses import dataclass, asdict, field
from enum import Enum
import tempfile
import subprocess
from collections import defaultdict
import fnmatch
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
from abc import ABC, abstractmethod

# Third-party imports (with graceful handling)
try:
    import nbformat
    from nbformat.v4 import upgrade
except ImportError:
    nbformat = None
    logger.warning("nbformat not available - Jupyter notebook migrations may be limited")

try:
    import pandoc
except ImportError:
    pandoc = None
    logger.warning("pandoc not available - document format conversions may be limited")

try:
    from markdown import markdown
    from markdown.extensions import toc, codehilite, tables
except ImportError:
    markdown = None
    logger.warning("markdown not available - Markdown processing may be limited")

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class MigrationType(Enum):
    """Migration type enumeration"""
    SCHEMA_UPDATE = "schema_update"
    FORMAT_CONVERSION = "format_conversion"
    TEMPLATE_UPDATE = "template_update"
    CONTENT_RESTRUCTURE = "content_restructure"
    METADATA_UPDATE = "metadata_update"
    LINK_UPDATE = "link_update"
    ASSET_MIGRATION = "asset_migration"
    BATCH_UPDATE = "batch_update"


class MigrationStatus(Enum):
    """Migration status enumeration"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"
    CANCELLED = "cancelled"


class ValidationLevel(Enum):
    """Validation level enumeration"""
    NONE = "none"
    BASIC = "basic"
    COMPREHENSIVE = "comprehensive"
    STRICT = "strict"


@dataclass
class MigrationRule:
    """Migration rule definition"""
    rule_id: str
    name: str
    description: str
    migration_type: MigrationType
    source_pattern: str
    target_pattern: Optional[str]
    transformation_function: str
    conditions: Dict[str, Any] = field(default_factory=dict)
    validation_rules: List[str] = field(default_factory=list)
    rollback_function: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class MigrationPlan:
    """Migration execution plan"""
    plan_id: str
    name: str
    description: str
    rules: List[MigrationRule]
    target_files: List[str]
    dependencies: List[str] = field(default_factory=list)
    validation_level: ValidationLevel = ValidationLevel.BASIC
    dry_run: bool = False
    backup_strategy: str = "copy"
    parallel_execution: bool = True
    max_workers: int = 4
    created_date: str = field(default_factory=lambda: datetime.now().isoformat())
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class MigrationResult:
    """Migration execution result"""
    file_path: str
    rule_id: str
    status: MigrationStatus
    start_time: str
    end_time: Optional[str] = None
    error_message: Optional[str] = None
    validation_errors: List[str] = field(default_factory=list)
    changes_made: List[str] = field(default_factory=list)
    backup_path: Optional[str] = None
    metrics: Dict[str, Any] = field(default_factory=dict)


@dataclass
class MigrationHistory:
    """Migration history record"""
    migration_id: str
    plan_id: str
    plan_name: str
    execution_date: str
    total_files: int
    successful_files: int
    failed_files: int
    total_duration: float
    executed_by: str
    rollback_available: bool
    results: List[MigrationResult] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


class ContentTransformer(ABC):
    """Abstract base class for content transformers"""
    
    @abstractmethod
    def can_transform(self, file_path: Path) -> bool:
        """Check if transformer can handle the file"""
        pass
    
    @abstractmethod
    def transform(self, content: str, context: Dict[str, Any]) -> str:
        """Transform content"""
        pass
    
    @abstractmethod
    def validate(self, content: str, original_content: str) -> List[str]:
        """Validate transformed content"""
        pass


class MarkdownTransformer(ContentTransformer):
    """Transformer for Markdown content"""
    
    def can_transform(self, file_path: Path) -> bool:
        return file_path.suffix.lower() == '.md'
    
    def transform(self, content: str, context: Dict[str, Any]) -> str:
        """Transform Markdown content based on context"""
        transformed = content
        
        # Update frontmatter schema
        if 'frontmatter_updates' in context:
            transformed = self._update_frontmatter(transformed, context['frontmatter_updates'])
        
        # Update heading structure
        if 'heading_updates' in context:
            transformed = self._update_headings(transformed, context['heading_updates'])
        
        # Update link formats
        if 'link_updates' in context:
            transformed = self._update_links(transformed, context['link_updates'])
        
        # Update code block formats
        if 'code_block_updates' in context:
            transformed = self._update_code_blocks(transformed, context['code_block_updates'])
        
        return transformed
    
    def _update_frontmatter(self, content: str, updates: Dict[str, Any]) -> str:
        """Update YAML frontmatter"""
        if not content.startswith('---'):
            return content
        
        # Extract frontmatter
        frontmatter_end = content.find('---', 3)
        if frontmatter_end == -1:
            return content
        
        frontmatter_text = content[3:frontmatter_end].strip()
        body = content[frontmatter_end + 3:]
        
        try:
            frontmatter = yaml.safe_load(frontmatter_text) or {}
            
            # Apply updates
            for key, value in updates.items():
                if key.startswith('add_'):
                    field_name = key[4:]
                    frontmatter[field_name] = value
                elif key.startswith('remove_'):
                    field_name = key[7:]
                    frontmatter.pop(field_name, None)
                elif key.startswith('rename_'):
                    old_name, new_name = key[7:].split('_to_')
                    if old_name in frontmatter:
                        frontmatter[new_name] = frontmatter.pop(old_name)
                else:
                    frontmatter[key] = value
            
            # Rebuild content
            new_frontmatter = yaml.dump(frontmatter, default_flow_style=False).strip()
            return f"---\n{new_frontmatter}\n---{body}"
        
        except Exception as e:
            logger.warning(f"Failed to update frontmatter: {e}")
            return content
    
    def _update_headings(self, content: str, updates: Dict[str, Any]) -> str:
        """Update heading structure"""
        if 'level_shift' in updates:
            shift = updates['level_shift']
            lines = content.split('\n')
            
            for i, line in enumerate(lines):
                if line.strip().startswith('#'):
                    # Count current level
                    level = len(line) - len(line.lstrip('#'))
                    new_level = max(1, min(6, level + shift))
                    
                    # Update heading
                    heading_text = line.lstrip('#').strip()
                    lines[i] = f"{'#' * new_level} {heading_text}"
            
            content = '\n'.join(lines)
        
        return content
    
    def _update_links(self, content: str, updates: Dict[str, Any]) -> str:
        """Update link formats"""
        if 'base_url_change' in updates:
            old_base = updates['base_url_change']['old']
            new_base = updates['base_url_change']['new']
            content = content.replace(old_base, new_base)
        
        if 'link_patterns' in updates:
            for pattern, replacement in updates['link_patterns'].items():
                content = re.sub(pattern, replacement, content)
        
        return content
    
    def _update_code_blocks(self, content: str, updates: Dict[str, Any]) -> str:
        """Update code block formats"""
        if 'language_mapping' in updates:
            mapping = updates['language_mapping']
            
            # Update fenced code blocks
            def replace_language(match):
                lang = match.group(1)
                new_lang = mapping.get(lang, lang)
                return f"```{new_lang}"
            
            content = re.sub(r'```(\w+)', replace_language, content)
        
        return content
    
    def validate(self, content: str, original_content: str) -> List[str]:
        """Validate transformed Markdown content"""
        errors = []
        
        # Check for broken frontmatter
        if content.startswith('---'):
            frontmatter_end = content.find('---', 3)
            if frontmatter_end == -1:
                errors.append("Frontmatter is not properly closed")
            else:
                frontmatter_text = content[3:frontmatter_end].strip()
                try:
                    yaml.safe_load(frontmatter_text)
                except yaml.YAMLError as e:
                    errors.append(f"Invalid YAML frontmatter: {e}")
        
        # Check for broken links
        link_pattern = r'\[([^\]]+)\]\(([^)]+)\)'
        links = re.findall(link_pattern, content)
        
        for text, url in links:
            if not url or url.startswith('http') or url.startswith('#'):
                continue
            
            # Check for relative file links
            if not Path(url).exists() and not url.startswith('/'):
                errors.append(f"Potentially broken link: {url}")
        
        # Check heading structure
        heading_levels = []
        for line in content.split('\n'):
            if line.strip().startswith('#'):
                level = len(line) - len(line.lstrip('#'))
                heading_levels.append(level)
        
        # Check for heading level jumps
        for i in range(1, len(heading_levels)):
            if heading_levels[i] - heading_levels[i-1] > 1:
                errors.append(f"Large heading level jump detected (H{heading_levels[i-1]} to H{heading_levels[i]})")
        
        return errors


class NotebookTransformer(ContentTransformer):
    """Transformer for Jupyter notebooks"""
    
    def can_transform(self, file_path: Path) -> bool:
        return file_path.suffix.lower() == '.ipynb'
    
    def transform(self, content: str, context: Dict[str, Any]) -> str:
        """Transform Jupyter notebook content"""
        if not nbformat:
            logger.warning("nbformat not available - skipping notebook transformation")
            return content
        
        try:
            notebook = nbformat.reads(content, as_version=nbformat.NO_CONVERT)
            
            # Update metadata
            if 'metadata_updates' in context:
                self._update_notebook_metadata(notebook, context['metadata_updates'])
            
            # Update cell metadata
            if 'cell_metadata_updates' in context:
                self._update_cell_metadata(notebook, context['cell_metadata_updates'])
            
            # Update kernel spec
            if 'kernel_updates' in context:
                self._update_kernel_spec(notebook, context['kernel_updates'])
            
            # Clean outputs if requested
            if context.get('clean_outputs', False):
                self._clean_outputs(notebook)
            
            # Upgrade notebook version if needed
            if context.get('upgrade_version', False):
                notebook = upgrade(notebook)
            
            return nbformat.writes(notebook)
        
        except Exception as e:
            logger.error(f"Failed to transform notebook: {e}")
            return content
    
    def _update_notebook_metadata(self, notebook, updates: Dict[str, Any]):
        """Update notebook-level metadata"""
        if 'metadata' not in notebook:
            notebook['metadata'] = {}
        
        for key, value in updates.items():
            if key.startswith('add_'):
                field_name = key[4:]
                notebook['metadata'][field_name] = value
            elif key.startswith('remove_'):
                field_name = key[7:]
                notebook['metadata'].pop(field_name, None)
            else:
                notebook['metadata'][key] = value
    
    def _update_cell_metadata(self, notebook, updates: Dict[str, Any]):
        """Update cell-level metadata"""
        for cell in notebook['cells']:
            if 'metadata' not in cell:
                cell['metadata'] = {}
            
            # Apply updates based on cell type
            cell_type = cell.get('cell_type', 'code')
            cell_updates = updates.get(cell_type, {})
            
            for key, value in cell_updates.items():
                cell['metadata'][key] = value
    
    def _update_kernel_spec(self, notebook, updates: Dict[str, Any]):
        """Update kernel specification"""
        if 'kernelspec' not in notebook.get('metadata', {}):
            notebook['metadata']['kernelspec'] = {}
        
        kernel_spec = notebook['metadata']['kernelspec']
        
        for key, value in updates.items():
            kernel_spec[key] = value
    
    def _clean_outputs(self, notebook):
        """Clean cell outputs"""
        for cell in notebook['cells']:
            if cell.get('cell_type') == 'code':
                cell['outputs'] = []
                cell['execution_count'] = None
    
    def validate(self, content: str, original_content: str) -> List[str]:
        """Validate transformed notebook content"""
        errors = []
        
        if not nbformat:
            return ["nbformat not available for validation"]
        
        try:
            notebook = nbformat.reads(content, as_version=nbformat.NO_CONVERT)
            nbformat.validate(notebook)
        except nbformat.ValidationError as e:
            errors.append(f"Notebook validation failed: {e}")
        except Exception as e:
            errors.append(f"Failed to parse notebook: {e}")
        
        return errors


class ContentMigrator:
    """
    Comprehensive Content Format Update and Migration System
    """
    
    def __init__(self, repo_path: str, config_path: Optional[str] = None):
        """
        Initialize the Content Migrator
        
        Args:
            repo_path: Path to repository
            config_path: Path to configuration file
        """
        self.repo_path = Path(repo_path)
        self.config_path = config_path or self.repo_path / "validation" / "workflow" / "migration_config.yml"
        self.migration_dir = self.repo_path / "validation" / "workflow" / "migrations"
        self.backup_dir = self.migration_dir / "backups"
        self.history_dir = self.migration_dir / "history"
        
        # Ensure directories exist
        for directory in [self.migration_dir, self.backup_dir, self.history_dir]:
            directory.mkdir(parents=True, exist_ok=True)
        
        # Load configuration
        self.config = self._load_configuration()
        
        # Initialize transformers
        self.transformers = self._initialize_transformers()
        
        # Load migration rules and history
        self.migration_rules = self._load_migration_rules()
        self.migration_history = self._load_migration_history()
        
        # Thread safety
        self._lock = threading.Lock()
        
        logger.info(f"Content Migrator initialized for {self.repo_path}")
    
    def _load_configuration(self) -> Dict[str, Any]:
        """Load migration configuration"""
        default_config = {
            "migration": {
                "default_backup_strategy": "copy",
                "max_parallel_workers": 4,
                "validation_level": "basic",
                "auto_cleanup_days": 30,
                "max_history_entries": 100
            },
            "transformers": {
                "markdown": {
                    "enabled": True,
                    "extensions": [".md", ".markdown"],
                    "validate_links": True,
                    "validate_headings": True
                },
                "notebook": {
                    "enabled": True,
                    "extensions": [".ipynb"],
                    "auto_upgrade_version": False,
                    "clean_outputs": False
                }
            },
            "validation": {
                "enabled": True,
                "fail_on_validation_errors": False,
                "max_validation_errors": 10,
                "skip_validation_patterns": []
            },
            "backup": {
                "enabled": True,
                "compression": True,
                "retention_days": 90,
                "max_backup_size_mb": 100
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
    
    def _initialize_transformers(self) -> Dict[str, ContentTransformer]:
        """Initialize content transformers"""
        transformers = {}
        
        # Markdown transformer
        if self.config["transformers"]["markdown"]["enabled"]:
            transformers["markdown"] = MarkdownTransformer()
        
        # Notebook transformer
        if self.config["transformers"]["notebook"]["enabled"]:
            transformers["notebook"] = NotebookTransformer()
        
        return transformers
    
    def _load_migration_rules(self) -> Dict[str, MigrationRule]:
        """Load migration rules"""
        rules_file = self.migration_dir / "rules.json"
        rules = {}
        
        if rules_file.exists():
            try:
                with open(rules_file, 'r') as f:
                    data = json.load(f)
                    for rule_data in data.get('rules', []):
                        rule = MigrationRule(
                            rule_id=rule_data['rule_id'],
                            name=rule_data['name'],
                            description=rule_data['description'],
                            migration_type=MigrationType(rule_data['migration_type']),
                            source_pattern=rule_data['source_pattern'],
                            target_pattern=rule_data.get('target_pattern'),
                            transformation_function=rule_data['transformation_function'],
                            conditions=rule_data.get('conditions', {}),
                            validation_rules=rule_data.get('validation_rules', []),
                            rollback_function=rule_data.get('rollback_function'),
                            metadata=rule_data.get('metadata', {})
                        )
                        rules[rule.rule_id] = rule
            except Exception as e:
                logger.error(f"Failed to load migration rules: {e}")
        
        return rules
    
    def _save_migration_rules(self):
        """Save migration rules"""
        rules_file = self.migration_dir / "rules.json"
        
        try:
            data = {"rules": []}
            
            for rule in self.migration_rules.values():
                rule_data = asdict(rule)
                rule_data["migration_type"] = rule_data["migration_type"].value
                data["rules"].append(rule_data)
            
            with open(rules_file, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save migration rules: {e}")
    
    def _load_migration_history(self) -> List[MigrationHistory]:
        """Load migration history"""
        history_file = self.history_dir / "history.json"
        history = []
        
        if history_file.exists():
            try:
                with open(history_file, 'r') as f:
                    data = json.load(f)
                    for history_data in data.get('migrations', []):
                        # Reconstruct results
                        results = []
                        for result_data in history_data.get('results', []):
                            result = MigrationResult(
                                file_path=result_data['file_path'],
                                rule_id=result_data['rule_id'],
                                status=MigrationStatus(result_data['status']),
                                start_time=result_data['start_time'],
                                end_time=result_data.get('end_time'),
                                error_message=result_data.get('error_message'),
                                validation_errors=result_data.get('validation_errors', []),
                                changes_made=result_data.get('changes_made', []),
                                backup_path=result_data.get('backup_path'),
                                metrics=result_data.get('metrics', {})
                            )
                            results.append(result)
                        
                        migration = MigrationHistory(
                            migration_id=history_data['migration_id'],
                            plan_id=history_data['plan_id'],
                            plan_name=history_data['plan_name'],
                            execution_date=history_data['execution_date'],
                            total_files=history_data['total_files'],
                            successful_files=history_data['successful_files'],
                            failed_files=history_data['failed_files'],
                            total_duration=history_data['total_duration'],
                            executed_by=history_data['executed_by'],
                            rollback_available=history_data['rollback_available'],
                            results=results,
                            metadata=history_data.get('metadata', {})
                        )
                        history.append(migration)
            except Exception as e:
                logger.error(f"Failed to load migration history: {e}")
        
        return history
    
    def _save_migration_history(self):
        """Save migration history"""
        history_file = self.history_dir / "history.json"
        
        try:
            data = {"migrations": []}
            
            for migration in self.migration_history:
                migration_data = asdict(migration)
                
                # Convert result statuses
                for result_data in migration_data["results"]:
                    result_data["status"] = result_data["status"].value
                
                data["migrations"].append(migration_data)
            
            with open(history_file, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save migration history: {e}")
    
    def add_migration_rule(self, rule: MigrationRule) -> bool:
        """
        Add a new migration rule
        
        Args:
            rule: Migration rule to add
        
        Returns:
            Success status
        """
        if rule.rule_id in self.migration_rules:
            logger.warning(f"Migration rule {rule.rule_id} already exists")
            return False
        
        self.migration_rules[rule.rule_id] = rule
        self._save_migration_rules()
        
        logger.info(f"Added migration rule: {rule.name}")
        return True
    
    def create_migration_plan(self, plan_id: str, name: str, description: str,
                            rule_ids: List[str], file_patterns: List[str],
                            dry_run: bool = True) -> MigrationPlan:
        """
        Create a migration plan
        
        Args:
            plan_id: Unique plan identifier
            name: Plan name
            description: Plan description
            rule_ids: List of migration rule IDs
            file_patterns: File patterns to match
            dry_run: Whether to run in dry-run mode
        
        Returns:
            Migration plan
        """
        # Validate rules exist
        rules = []
        for rule_id in rule_ids:
            if rule_id not in self.migration_rules:
                raise ValueError(f"Migration rule {rule_id} not found")
            rules.append(self.migration_rules[rule_id])
        
        # Find target files
        target_files = []
        for pattern in file_patterns:
            for file_path in self.repo_path.rglob(pattern):
                if file_path.is_file():
                    target_files.append(str(file_path.relative_to(self.repo_path)))
        
        plan = MigrationPlan(
            plan_id=plan_id,
            name=name,
            description=description,
            rules=rules,
            target_files=target_files,
            dry_run=dry_run,
            validation_level=ValidationLevel(self.config["migration"]["validation_level"]),
            max_workers=self.config["migration"]["max_parallel_workers"]
        )
        
        logger.info(f"Created migration plan: {name} with {len(target_files)} target files")
        return plan
    
    def execute_migration_plan(self, plan: MigrationPlan, executor_name: str = "system") -> MigrationHistory:
        """
        Execute a migration plan
        
        Args:
            plan: Migration plan to execute
            executor_name: Name of executor
        
        Returns:
            Migration history record
        """
        migration_id = f"migration-{int(datetime.now().timestamp())}"
        start_time = datetime.now()
        
        logger.info(f"Starting migration: {plan.name} ({'dry-run' if plan.dry_run else 'live'})")
        
        # Initialize history record
        history = MigrationHistory(
            migration_id=migration_id,
            plan_id=plan.plan_id,
            plan_name=plan.name,
            execution_date=start_time.isoformat(),
            total_files=len(plan.target_files),
            successful_files=0,
            failed_files=0,
            total_duration=0.0,
            executed_by=executor_name,
            rollback_available=not plan.dry_run
        )
        
        # Execute migrations
        if plan.parallel_execution and plan.max_workers > 1:
            results = self._execute_parallel(plan)
        else:
            results = self._execute_sequential(plan)
        
        # Process results
        for result in results:
            history.results.append(result)
            if result.status == MigrationStatus.COMPLETED:
                history.successful_files += 1
            else:
                history.failed_files += 1
        
        # Calculate duration
        end_time = datetime.now()
        history.total_duration = (end_time - start_time).total_seconds()
        
        # Save history
        with self._lock:
            self.migration_history.append(history)
            self._save_migration_history()
        
        logger.info(f"Migration completed: {history.successful_files}/{history.total_files} files successful")
        return history
    
    def _execute_parallel(self, plan: MigrationPlan) -> List[MigrationResult]:
        """Execute migration plan in parallel"""
        results = []
        
        with ThreadPoolExecutor(max_workers=plan.max_workers) as executor:
            # Submit all file migration tasks
            future_to_file = {}
            
            for file_path in plan.target_files:
                for rule in plan.rules:
                    if self._file_matches_rule(file_path, rule):
                        future = executor.submit(self._migrate_file, file_path, rule, plan)
                        future_to_file[future] = (file_path, rule.rule_id)
            
            # Collect results
            for future in as_completed(future_to_file):
                file_path, rule_id = future_to_file[future]
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    logger.error(f"Migration failed for {file_path} with rule {rule_id}: {e}")
                    result = MigrationResult(
                        file_path=file_path,
                        rule_id=rule_id,
                        status=MigrationStatus.FAILED,
                        start_time=datetime.now().isoformat(),
                        error_message=str(e)
                    )
                    results.append(result)
        
        return results
    
    def _execute_sequential(self, plan: MigrationPlan) -> List[MigrationResult]:
        """Execute migration plan sequentially"""
        results = []
        
        for file_path in plan.target_files:
            for rule in plan.rules:
                if self._file_matches_rule(file_path, rule):
                    try:
                        result = self._migrate_file(file_path, rule, plan)
                        results.append(result)
                    except Exception as e:
                        logger.error(f"Migration failed for {file_path} with rule {rule.rule_id}: {e}")
                        result = MigrationResult(
                            file_path=file_path,
                            rule_id=rule.rule_id,
                            status=MigrationStatus.FAILED,
                            start_time=datetime.now().isoformat(),
                            error_message=str(e)
                        )
                        results.append(result)
        
        return results
    
    def _file_matches_rule(self, file_path: str, rule: MigrationRule) -> bool:
        """Check if file matches migration rule"""
        full_path = self.repo_path / file_path
        
        # Check source pattern
        if not fnmatch.fnmatch(file_path, rule.source_pattern):
            return False
        
        # Check conditions
        for condition, value in rule.conditions.items():
            if condition == "min_size_bytes":
                if full_path.stat().st_size < value:
                    return False
            elif condition == "max_size_bytes":
                if full_path.stat().st_size > value:
                    return False
            elif condition == "modified_after":
                modified_time = datetime.fromtimestamp(full_path.stat().st_mtime)
                if modified_time < datetime.fromisoformat(value):
                    return False
            elif condition == "contains_text":
                try:
                    with open(full_path, 'r', encoding='utf-8') as f:
                        content = f.read()
                        if value not in content:
                            return False
                except Exception:
                    return False
        
        return True
    
    def _migrate_file(self, file_path: str, rule: MigrationRule, plan: MigrationPlan) -> MigrationResult:
        """Migrate a single file"""
        start_time = datetime.now()
        full_path = self.repo_path / file_path
        
        result = MigrationResult(
            file_path=file_path,
            rule_id=rule.rule_id,
            status=MigrationStatus.RUNNING,
            start_time=start_time.isoformat()
        )
        
        try:
            # Read original content
            with open(full_path, 'r', encoding='utf-8') as f:
                original_content = f.read()
            
            # Create backup if not dry run
            backup_path = None
            if not plan.dry_run and self.config["backup"]["enabled"]:
                backup_path = self._create_backup(full_path)
                result.backup_path = str(backup_path)
            
            # Find appropriate transformer
            transformer = self._find_transformer(full_path)
            if not transformer:
                raise ValueError(f"No transformer available for file type: {full_path.suffix}")
            
            # Apply transformation
            context = rule.metadata.copy()
            context.update(rule.conditions)
            
            transformed_content = transformer.transform(original_content, context)
            
            # Validate transformed content
            validation_errors = []
            if plan.validation_level != ValidationLevel.NONE:
                validation_errors = transformer.validate(transformed_content, original_content)
                result.validation_errors = validation_errors
                
                if validation_errors and self.config["validation"]["fail_on_validation_errors"]:
                    raise ValueError(f"Validation failed: {'; '.join(validation_errors)}")
            
            # Write transformed content if not dry run
            if not plan.dry_run:
                with open(full_path, 'w', encoding='utf-8') as f:
                    f.write(transformed_content)
            
            # Record changes
            changes = self._analyze_changes(original_content, transformed_content)
            result.changes_made = changes
            
            # Calculate metrics
            result.metrics = {
                "original_size": len(original_content),
                "transformed_size": len(transformed_content),
                "size_diff": len(transformed_content) - len(original_content),
                "validation_errors_count": len(validation_errors)
            }
            
            result.status = MigrationStatus.COMPLETED
            result.end_time = datetime.now().isoformat()
            
            logger.debug(f"Successfully migrated {file_path} with rule {rule.rule_id}")
        
        except Exception as e:
            result.status = MigrationStatus.FAILED
            result.error_message = str(e)
            result.end_time = datetime.now().isoformat()
            
            logger.error(f"Failed to migrate {file_path} with rule {rule.rule_id}: {e}")
        
        return result
    
    def _find_transformer(self, file_path: Path) -> Optional[ContentTransformer]:
        """Find appropriate transformer for file"""
        for transformer in self.transformers.values():
            if transformer.can_transform(file_path):
                return transformer
        return None
    
    def _create_backup(self, file_path: Path) -> Path:
        """Create backup of file"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_name = f"{file_path.stem}_{timestamp}{file_path.suffix}"
        backup_path = self.backup_dir / backup_name
        
        shutil.copy2(file_path, backup_path)
        
        # Compress if enabled and file is large
        if self.config["backup"]["compression"] and file_path.stat().st_size > 1024 * 1024:  # 1MB
            import gzip
            compressed_path = backup_path.with_suffix(backup_path.suffix + '.gz')
            
            with open(backup_path, 'rb') as f_in:
                with gzip.open(compressed_path, 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)
            
            backup_path.unlink()
            backup_path = compressed_path
        
        return backup_path
    
    def _analyze_changes(self, original: str, transformed: str) -> List[str]:
        """Analyze changes between original and transformed content"""
        changes = []
        
        if len(transformed) != len(original):
            size_diff = len(transformed) - len(original)
            changes.append(f"Content size changed by {size_diff} characters")
        
        # Count line differences
        original_lines = original.split('\n')
        transformed_lines = transformed.split('\n')
        
        if len(transformed_lines) != len(original_lines):
            line_diff = len(transformed_lines) - len(original_lines)
            changes.append(f"Line count changed by {line_diff}")
        
        # Check for specific changes
        if original != transformed:
            # Calculate similarity (simple approach)
            common_chars = sum(1 for a, b in zip(original, transformed) if a == b)
            similarity = common_chars / max(len(original), len(transformed)) if max(len(original), len(transformed)) > 0 else 1.0
            changes.append(f"Content similarity: {similarity:.2%}")
        
        return changes
    
    def rollback_migration(self, migration_id: str) -> bool:
        """
        Rollback a completed migration
        
        Args:
            migration_id: Migration to rollback
        
        Returns:
            Success status
        """
        # Find migration in history
        migration = None
        for hist in self.migration_history:
            if hist.migration_id == migration_id:
                migration = hist
                break
        
        if not migration:
            logger.error(f"Migration {migration_id} not found in history")
            return False
        
        if not migration.rollback_available:
            logger.error(f"Migration {migration_id} is not rollback-capable")
            return False
        
        logger.info(f"Starting rollback of migration {migration_id}")
        
        rollback_successful = 0
        rollback_failed = 0
        
        for result in migration.results:
            if result.status == MigrationStatus.COMPLETED and result.backup_path:
                try:
                    backup_path = Path(result.backup_path)
                    target_path = self.repo_path / result.file_path
                    
                    # Handle compressed backups
                    if backup_path.suffix == '.gz':
                        import gzip
                        with gzip.open(backup_path, 'rb') as f_in:
                            with open(target_path, 'wb') as f_out:
                                shutil.copyfileobj(f_in, f_out)
                    else:
                        shutil.copy2(backup_path, target_path)
                    
                    rollback_successful += 1
                    logger.debug(f"Rolled back {result.file_path}")
                
                except Exception as e:
                    rollback_failed += 1
                    logger.error(f"Failed to rollback {result.file_path}: {e}")
        
        # Update migration history
        if rollback_successful > 0:
            migration.rollback_available = False
            migration.metadata['rollback_date'] = datetime.now().isoformat()
            migration.metadata['rollback_stats'] = {
                'successful': rollback_successful,
                'failed': rollback_failed
            }
            
            self._save_migration_history()
        
        logger.info(f"Rollback completed: {rollback_successful} files restored, {rollback_failed} failed")
        return rollback_failed == 0
    
    def cleanup_old_backups(self) -> Dict[str, int]:
        """Clean up old backup files"""
        cleanup_stats = {
            "files_removed": 0,
            "space_freed_mb": 0
        }
        
        if not self.config["backup"]["enabled"]:
            return cleanup_stats
        
        retention_days = self.config["backup"]["retention_days"]
        cutoff_date = datetime.now() - timedelta(days=retention_days)
        
        for backup_file in self.backup_dir.iterdir():
            if backup_file.is_file():
                try:
                    file_mtime = datetime.fromtimestamp(backup_file.stat().st_mtime)
                    
                    if file_mtime < cutoff_date:
                        file_size_mb = backup_file.stat().st_size / (1024 * 1024)
                        backup_file.unlink()
                        
                        cleanup_stats["files_removed"] += 1
                        cleanup_stats["space_freed_mb"] += file_size_mb
                
                except Exception as e:
                    logger.warning(f"Failed to remove old backup {backup_file}: {e}")
        
        logger.info(f"Cleanup completed: {cleanup_stats['files_removed']} files removed, "
                   f"{cleanup_stats['space_freed_mb']:.1f} MB freed")
        
        return cleanup_stats
    
    def generate_migration_report(self, migration_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Generate migration report
        
        Args:
            migration_id: Specific migration ID (None for all)
        
        Returns:
            Migration report
        """
        if migration_id:
            # Report for specific migration
            migration = None
            for hist in self.migration_history:
                if hist.migration_id == migration_id:
                    migration = hist
                    break
            
            if not migration:
                return {"error": f"Migration {migration_id} not found"}
            
            return {
                "migration_id": migration.migration_id,
                "plan_name": migration.plan_name,
                "execution_date": migration.execution_date,
                "total_files": migration.total_files,
                "successful_files": migration.successful_files,
                "failed_files": migration.failed_files,
                "success_rate": migration.successful_files / migration.total_files if migration.total_files > 0 else 0,
                "total_duration": migration.total_duration,
                "avg_time_per_file": migration.total_duration / migration.total_files if migration.total_files > 0 else 0,
                "rollback_available": migration.rollback_available,
                "results": [asdict(result) for result in migration.results]
            }
        else:
            # Summary report for all migrations
            total_migrations = len(self.migration_history)
            total_files_processed = sum(m.total_files for m in self.migration_history)
            total_successful = sum(m.successful_files for m in self.migration_history)
            total_failed = sum(m.failed_files for m in self.migration_history)
            
            # Recent activity (last 30 days)
            recent_date = datetime.now() - timedelta(days=30)
            recent_migrations = [
                m for m in self.migration_history
                if datetime.fromisoformat(m.execution_date.replace('Z', '+00:00')).replace(tzinfo=None) > recent_date
            ]
            
            # Migration types
            migration_types = defaultdict(int)
            for migration in self.migration_history:
                # Count by plan name (simplified)
                migration_types[migration.plan_name] += 1
            
            return {
                "generated": datetime.now().isoformat(),
                "summary": {
                    "total_migrations": total_migrations,
                    "total_files_processed": total_files_processed,
                    "total_successful": total_successful,
                    "total_failed": total_failed,
                    "overall_success_rate": total_successful / total_files_processed if total_files_processed > 0 else 0
                },
                "recent_activity": {
                    "migrations_last_30_days": len(recent_migrations),
                    "files_processed_last_30_days": sum(m.total_files for m in recent_migrations)
                },
                "migration_types": dict(migration_types),
                "available_rules": len(self.migration_rules),
                "backup_stats": {
                    "backup_files": len(list(self.backup_dir.iterdir())),
                    "backup_size_mb": sum(f.stat().st_size for f in self.backup_dir.iterdir() if f.is_file()) / (1024 * 1024)
                }
            }


def main():
    """Main function for CLI usage"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Content Migration Tool")
    parser.add_argument("--repo", default=".", help="Repository path")
    parser.add_argument("--config", help="Configuration file path")
    parser.add_argument("--command", required=True,
                       choices=["create-plan", "execute", "rollback", "report", "cleanup"],
                       help="Command to execute")
    
    # Command-specific arguments
    parser.add_argument("--plan-id", help="Migration plan ID")
    parser.add_argument("--name", help="Migration plan name")
    parser.add_argument("--description", help="Migration plan description")
    parser.add_argument("--rules", nargs="+", help="Migration rule IDs")
    parser.add_argument("--patterns", nargs="+", help="File patterns")
    parser.add_argument("--migration-id", help="Migration ID")
    parser.add_argument("--dry-run", action="store_true", help="Dry run mode")
    parser.add_argument("--output", help="Output file path")
    
    args = parser.parse_args()
    
    try:
        migrator = ContentMigrator(args.repo, args.config)
        
        if args.command == "create-plan":
            if not all([args.plan_id, args.name, args.rules, args.patterns]):
                print("Error: plan-id, name, rules, and patterns are required")
                return
            
            plan = migrator.create_migration_plan(
                args.plan_id, args.name, args.description or "",
                args.rules, args.patterns, args.dry_run
            )
            
            print(f"Created migration plan: {plan.name}")
            print(f"Target files: {len(plan.target_files)}")
            print(f"Rules: {[r.name for r in plan.rules]}")
        
        elif args.command == "execute":
            if not args.plan_id:
                print("Error: plan-id is required for execute command")
                return
            
            # This would need to load saved plans or create on the fly
            print("Execute command requires plan loading implementation")
        
        elif args.command == "rollback":
            if not args.migration_id:
                print("Error: migration-id is required for rollback command")
                return
            
            success = migrator.rollback_migration(args.migration_id)
            print(f"Rollback {'successful' if success else 'failed'}")
        
        elif args.command == "report":
            report = migrator.generate_migration_report(args.migration_id)
            
            if args.output:
                with open(args.output, 'w') as f:
                    json.dump(report, f, indent=2)
                print(f"Report saved to {args.output}")
            else:
                print(json.dumps(report, indent=2))
        
        elif args.command == "cleanup":
            stats = migrator.cleanup_old_backups()
            print(f"Cleanup completed: {stats['files_removed']} files removed, "
                  f"{stats['space_freed_mb']:.1f} MB freed")
    
    except Exception as e:
        logger.error(f"Command failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()