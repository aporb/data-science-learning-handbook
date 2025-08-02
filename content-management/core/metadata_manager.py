#!/usr/bin/env python3
"""
Metadata Manager
===============

Manages content metadata for the Git-based Chapter Content Management System.
Provides metadata extraction, validation, updating, and organization functionality.

This module provides:
- Content metadata extraction and parsing
- Metadata validation and compliance checking
- Metadata updating and synchronization
- Content organization and indexing
- Learning objective tracking

Author: Claude Code Implementation
Version: 1.0.0
"""

import os
import json
import logging
import yaml
from pathlib import Path
from typing import Dict, List, Optional, Any, Union, Tuple
from datetime import datetime
from dataclasses import dataclass, asdict, field
from enum import Enum
import hashlib

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


class DifficultyLevel(Enum):
    """Difficulty level enumeration"""
    BEGINNER = "beginner"
    INTERMEDIATE = "intermediate"
    ADVANCED = "advanced"
    EXPERT = "expert"


@dataclass
class ContentMetadata:
    """Comprehensive content metadata structure"""
    # Core identification
    title: str
    chapter_id: str
    content_type: str
    author: str
    
    # Timestamps
    created_date: str
    modified_date: str
    
    # Status and workflow
    status: ContentStatus = ContentStatus.DRAFT
    review_stage: Optional[str] = None
    
    # Educational attributes
    learning_objectives: List[str] = field(default_factory=list)
    prerequisites: List[str] = field(default_factory=list)
    difficulty_level: DifficultyLevel = DifficultyLevel.INTERMEDIATE
    estimated_time: str = "1-2 hours"
    
    # Platform and technical
    platforms: List[str] = field(default_factory=lambda: ["python"])
    tools_required: List[str] = field(default_factory=list)
    datasets: List[Dict[str, str]] = field(default_factory=list)
    
    # Organization
    tags: List[str] = field(default_factory=list)
    categories: List[str] = field(default_factory=list)
    dependencies: List[str] = field(default_factory=list)
    
    # Quality and validation
    validation_score: Optional[float] = None
    bias_score: Optional[float] = None
    reviewers: List[str] = field(default_factory=list)
    
    # Content tracking
    word_count: int = 0
    code_blocks: int = 0
    exercises: int = 0
    links: int = 0
    
    # Version control
    content_hash: Optional[str] = None
    last_validated: Optional[str] = None


@dataclass
class ContentIndex:
    """Content index for organization and navigation"""
    total_chapters: int
    total_sections: int
    total_exercises: int
    by_platform: Dict[str, int]
    by_difficulty: Dict[str, int]
    by_status: Dict[str, int]
    dependency_map: Dict[str, List[str]]
    learning_path: List[str]
    last_updated: str


class MetadataManager:
    """
    Metadata Manager for Content Management System
    
    Handles all metadata operations including extraction, validation,
    updating, and organization of educational content metadata.
    """
    
    def __init__(self, repo_path: Path, config: Dict[str, Any]):
        """
        Initialize Metadata Manager
        
        Args:
            repo_path: Path to the Git repository
            config: CMS configuration dictionary
        """
        self.repo_path = Path(repo_path)
        self.config = config
        self.content_path = self.repo_path / config.get("content", {}).get("chapters_path", "chapters")
        self.metadata_cache_path = self.repo_path / "content-management" / "cache" / "metadata.json"
        self.index_cache_path = self.repo_path / "content-management" / "cache" / "content_index.json"
        
        # Ensure cache directory exists
        self.metadata_cache_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Load cached metadata
        self.metadata_cache = self._load_metadata_cache()
        
        logger.info(f"Metadata Manager initialized for: {self.content_path}")
    
    def _load_metadata_cache(self) -> Dict[str, Dict[str, Any]]:
        """Load metadata cache from disk"""
        if self.metadata_cache_path.exists():
            try:
                with open(self.metadata_cache_path, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception as e:
                logger.warning(f"Failed to load metadata cache: {e}")
        return {}
    
    def _save_metadata_cache(self):
        """Save metadata cache to disk"""
        try:
            with open(self.metadata_cache_path, 'w', encoding='utf-8') as f:
                json.dump(self.metadata_cache, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save metadata cache: {e}")
    
    def extract_metadata(self, file_path: Path) -> Optional[ContentMetadata]:
        """
        Extract metadata from content file
        
        Args:
            file_path: Path to content file
            
        Returns:
            ContentMetadata object or None if extraction fails
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
        
        # Calculate content statistics
        word_count = len(content.split())
        code_blocks = content.count('```')
        exercises = content.lower().count('exercise')
        links = content.count('[') + content.count('](')
        
        # Generate content hash
        content_hash = hashlib.md5(content.encode()).hexdigest()
        
        # Look for YAML frontmatter
        if content.startswith('---'):
            try:
                frontmatter_end = content.find('---', 3)
                if frontmatter_end > 0:
                    frontmatter = content[3:frontmatter_end].strip()
                    metadata_dict = yaml.safe_load(frontmatter)
                    
                    # Create ContentMetadata from parsed YAML
                    return ContentMetadata(
                        title=metadata_dict.get('title', file_path.stem),
                        chapter_id=metadata_dict.get('chapter_id', ''),
                        content_type=metadata_dict.get('content_type', 'chapter'),
                        author=metadata_dict.get('author', ''),
                        created_date=metadata_dict.get('created_date', ''),
                        modified_date=metadata_dict.get('modified_date', ''),
                        status=ContentStatus(metadata_dict.get('status', 'draft')),
                        review_stage=metadata_dict.get('review_stage'),
                        learning_objectives=metadata_dict.get('learning_objectives', []),
                        prerequisites=metadata_dict.get('prerequisites', []),
                        difficulty_level=DifficultyLevel(metadata_dict.get('difficulty_level', 'intermediate')),
                        estimated_time=metadata_dict.get('estimated_time', '1-2 hours'),
                        platforms=metadata_dict.get('platforms', ['python']),
                        tools_required=metadata_dict.get('tools_required', []),
                        datasets=metadata_dict.get('datasets', []),
                        tags=metadata_dict.get('tags', []),
                        categories=metadata_dict.get('categories', []),
                        dependencies=metadata_dict.get('dependencies', []),
                        validation_score=metadata_dict.get('validation_score'),
                        bias_score=metadata_dict.get('bias_score'),
                        reviewers=metadata_dict.get('reviewers', []),
                        word_count=word_count,
                        code_blocks=code_blocks,
                        exercises=exercises,
                        links=links,
                        content_hash=content_hash,
                        last_validated=metadata_dict.get('last_validated')
                    )
            except Exception as e:
                logger.error(f"Failed to parse YAML frontmatter in {file_path}: {e}")
        
        # If no frontmatter, create basic metadata
        return ContentMetadata(
            title=file_path.stem.replace('-', ' ').replace('_', ' ').title(),
            chapter_id=file_path.parent.name,
            content_type='chapter',
            author='Unknown',
            created_date=datetime.now().isoformat(),
            modified_date=datetime.now().isoformat(),
            word_count=word_count,
            code_blocks=code_blocks,
            exercises=exercises,
            links=links,
            content_hash=content_hash
        )
    
    def _extract_notebook_metadata(self, file_path: Path) -> Optional[ContentMetadata]:
        """Extract metadata from Jupyter notebook"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                notebook = json.load(f)
            
            # Calculate notebook statistics
            cells = notebook.get('cells', [])
            code_cells = sum(1 for cell in cells if cell.get('cell_type') == 'code')
            markdown_cells = sum(1 for cell in cells if cell.get('cell_type') == 'markdown')
            
            # Count words in markdown cells
            word_count = 0
            for cell in cells:
                if cell.get('cell_type') == 'markdown':
                    source = ''.join(cell.get('source', []))
                    word_count += len(source.split())
            
            # Generate content hash
            content_str = json.dumps(notebook, sort_keys=True)
            content_hash = hashlib.md5(content_str.encode()).hexdigest()
            
            # Extract metadata from notebook metadata
            nb_metadata = notebook.get('metadata', {})
            handbook_metadata = nb_metadata.get('handbook', {})
            
            return ContentMetadata(
                title=handbook_metadata.get('title', file_path.stem),
                chapter_id=handbook_metadata.get('chapter_id', file_path.parent.name),
                content_type='notebook',
                author=handbook_metadata.get('author', ''),
                created_date=handbook_metadata.get('created_date', ''),
                modified_date=handbook_metadata.get('modified_date', ''),
                status=ContentStatus(handbook_metadata.get('status', 'draft')),
                review_stage=handbook_metadata.get('review_stage'),
                learning_objectives=handbook_metadata.get('learning_objectives', []),
                prerequisites=handbook_metadata.get('prerequisites', []),
                difficulty_level=DifficultyLevel(handbook_metadata.get('difficulty_level', 'intermediate')),
                estimated_time=handbook_metadata.get('estimated_time', '1-2 hours'),
                platforms=handbook_metadata.get('platforms', ['python']),
                tools_required=handbook_metadata.get('tools_required', []),
                datasets=handbook_metadata.get('datasets', []),
                tags=handbook_metadata.get('tags', []),
                categories=handbook_metadata.get('categories', []),
                dependencies=handbook_metadata.get('dependencies', []),
                validation_score=handbook_metadata.get('validation_score'),
                bias_score=handbook_metadata.get('bias_score'),
                reviewers=handbook_metadata.get('reviewers', []),
                word_count=word_count,
                code_blocks=code_cells,
                exercises=handbook_metadata.get('exercises', 0),
                links=0,  # Would need more sophisticated parsing
                content_hash=content_hash,
                last_validated=handbook_metadata.get('last_validated')
            )
        except Exception as e:
            logger.error(f"Failed to parse notebook metadata in {file_path}: {e}")
            return None
    
    def update_file_metadata(self, file_path: Path, metadata: ContentMetadata) -> bool:
        """
        Update content file with metadata
        
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
        
        # Convert metadata to dictionary
        metadata_dict = asdict(metadata)
        
        # Convert enums to strings
        metadata_dict['status'] = metadata_dict['status'].value
        metadata_dict['difficulty_level'] = metadata_dict['difficulty_level'].value
        
        # Remove None values and internal fields
        filtered_dict = {
            k: v for k, v in metadata_dict.items() 
            if v is not None and k not in ['content_hash', 'word_count', 'code_blocks', 'exercises', 'links']
        }
        
        # Create YAML frontmatter
        frontmatter = yaml.dump(filtered_dict, default_flow_style=False, sort_keys=False)
        
        # Remove existing frontmatter if present
        if content.startswith('---'):
            frontmatter_end = content.find('---', 3)
            if frontmatter_end > 0:
                content = content[frontmatter_end + 3:].lstrip('\n')
        
        # Add new frontmatter
        new_content = f"---\n{frontmatter}---\n\n{content}"
        
        # Write updated content
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(new_content)
        
        # Update cache
        self.metadata_cache[str(file_path)] = metadata_dict
        self._save_metadata_cache()
        
        return True
    
    def _update_notebook_metadata(self, file_path: Path, metadata: ContentMetadata) -> bool:
        """Update Jupyter notebook metadata"""
        with open(file_path, 'r', encoding='utf-8') as f:
            notebook = json.load(f)
        
        # Convert metadata to dictionary
        metadata_dict = asdict(metadata)
        metadata_dict['status'] = metadata_dict['status'].value
        metadata_dict['difficulty_level'] = metadata_dict['difficulty_level'].value
        
        # Remove internal tracking fields
        filtered_dict = {
            k: v for k, v in metadata_dict.items() 
            if k not in ['content_hash', 'word_count', 'code_blocks', 'exercises', 'links']
        }
        
        # Update notebook metadata
        if 'metadata' not in notebook:
            notebook['metadata'] = {}
        notebook['metadata']['handbook'] = filtered_dict
        
        # Write updated notebook
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(notebook, f, indent=2)
        
        # Update cache
        self.metadata_cache[str(file_path)] = metadata_dict
        self._save_metadata_cache()
        
        return True
    
    def create_metadata(self, spec) -> ContentMetadata:
        """
        Create metadata from content specification
        
        Args:
            spec: Content specification object
            
        Returns:
            ContentMetadata object
        """
        return ContentMetadata(
            title=spec.title,
            chapter_id=spec.chapter_id,
            content_type=spec.template_type,
            author=spec.author,
            created_date=datetime.now().isoformat(),
            modified_date=datetime.now().isoformat(),
            learning_objectives=spec.learning_objectives,
            prerequisites=spec.prerequisites,
            difficulty_level=DifficultyLevel(spec.difficulty_level.lower()),
            estimated_time=spec.estimated_time,
            platforms=spec.platforms,
            tags=spec.tags
        )
    
    def validate_metadata(self, metadata: ContentMetadata) -> Dict[str, Any]:
        """
        Validate metadata completeness and compliance
        
        Args:
            metadata: ContentMetadata object to validate
            
        Returns:
            Validation results
        """
        validation_result = {
            "valid": True,
            "score": 100.0,
            "errors": [],
            "warnings": [],
            "checks": {}
        }
        
        # Required fields check
        required_fields = self.config.get("metadata", {}).get("required_fields", [])
        for field in required_fields:
            value = getattr(metadata, field, None)
            if not value:
                validation_result["errors"].append(f"Missing required field: {field}")
                validation_result["valid"] = False
        
        # Learning objectives check
        if not metadata.learning_objectives:
            validation_result["warnings"].append("No learning objectives specified")
        elif len(metadata.learning_objectives) > 10:
            validation_result["warnings"].append("Too many learning objectives (>10)")
        
        # Prerequisites check
        if not metadata.prerequisites and metadata.difficulty_level != DifficultyLevel.BEGINNER:
            validation_result["warnings"].append("No prerequisites specified for non-beginner content")
        
        # Platform validation
        supported_platforms = ["python", "r", "sql", "scala", "julia", "spark"]
        for platform in metadata.platforms:
            if platform.lower() not in supported_platforms:
                validation_result["warnings"].append(f"Unsupported platform: {platform}")
        
        # Estimated time format check
        if metadata.estimated_time and not any(unit in metadata.estimated_time.lower() 
                                              for unit in ['hour', 'minute', 'day']):
            validation_result["warnings"].append("Estimated time should include time units")
        
        # Tags validation
        if len(metadata.tags) > 15:
            validation_result["warnings"].append("Too many tags (>15)")
        
        # Calculate validation score
        error_penalty = len(validation_result["errors"]) * 20
        warning_penalty = len(validation_result["warnings"]) * 5
        validation_result["score"] = max(0, 100 - error_penalty - warning_penalty)
        
        validation_result["checks"] = {
            "required_fields": len(validation_result["errors"]) == 0,
            "learning_objectives": len(metadata.learning_objectives) > 0,
            "platforms": len(metadata.platforms) > 0,
            "estimated_time": bool(metadata.estimated_time)
        }
        
        return validation_result
    
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
        content_list = []
        
        # Scan content directory
        for file_path in self.content_path.rglob('*'):
            if file_path.is_file() and file_path.suffix in ['.md', '.ipynb']:
                try:
                    metadata = self.extract_metadata(file_path)
                    if metadata:
                        # Apply filters
                        if chapter_filter and metadata.chapter_id != chapter_filter:
                            continue
                        if status_filter and metadata.status.value != status_filter:
                            continue
                        if platform_filter and platform_filter not in metadata.platforms:
                            continue
                        
                        content_item = {
                            "file_path": str(file_path),
                            "relative_path": str(file_path.relative_to(self.repo_path)),
                            **asdict(metadata)
                        }
                        
                        # Convert enums to strings for JSON serialization
                        content_item["status"] = content_item["status"].value
                        content_item["difficulty_level"] = content_item["difficulty_level"].value
                        
                        content_list.append(content_item)
                        
                except Exception as e:
                    logger.warning(f"Failed to process {file_path}: {e}")
        
        return content_list
    
    def build_content_index(self) -> ContentIndex:
        """
        Build comprehensive content index
        
        Returns:
            ContentIndex object with organization information
        """
        logger.info("Building content index")
        
        content_list = self.list_content()
        
        # Initialize counters
        by_platform = {}
        by_difficulty = {}
        by_status = {}
        dependency_map = {}
        
        chapters = set()
        sections = 0
        exercises = 0
        
        for content in content_list:
            # Count by type
            if content["content_type"] == "chapter":
                chapters.add(content["chapter_id"])
            elif content["content_type"] == "section":
                sections += 1
            elif content["content_type"] == "exercise":
                exercises += 1
            
            # Count by platform
            for platform in content["platforms"]:
                by_platform[platform] = by_platform.get(platform, 0) + 1
            
            # Count by difficulty
            difficulty = content["difficulty_level"]
            by_difficulty[difficulty] = by_difficulty.get(difficulty, 0) + 1
            
            # Count by status
            status = content["status"]
            by_status[status] = by_status.get(status, 0) + 1
            
            # Build dependency map
            chapter_id = content["chapter_id"]
            dependencies = content.get("dependencies", [])
            if dependencies:
                dependency_map[chapter_id] = dependencies
        
        # Create learning path (simplified - chapters in order)
        learning_path = sorted(list(chapters))
        
        index = ContentIndex(
            total_chapters=len(chapters),
            total_sections=sections,
            total_exercises=exercises,
            by_platform=by_platform,
            by_difficulty=by_difficulty,
            by_status=by_status,
            dependency_map=dependency_map,
            learning_path=learning_path,
            last_updated=datetime.now().isoformat()
        )
        
        # Save index to cache
        try:
            with open(self.index_cache_path, 'w', encoding='utf-8') as f:
                json.dump(asdict(index), f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save content index: {e}")
        
        return index
    
    def get_learning_path(self, platform: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Get recommended learning path
        
        Args:
            platform: Filter by platform
            
        Returns:
            Ordered list of content for learning path
        """
        content_list = self.list_content(platform_filter=platform)
        
        # Sort by chapter ID and difficulty
        def sort_key(content):
            chapter_num = 0
            try:
                # Extract number from chapter ID (e.g., "01-intro" -> 1)
                chapter_num = int(content["chapter_id"].split('-')[0])
            except (ValueError, IndexError):
                pass
            
            difficulty_order = {
                "beginner": 1,
                "intermediate": 2, 
                "advanced": 3,
                "expert": 4
            }
            
            return (chapter_num, difficulty_order.get(content["difficulty_level"], 2))
        
        sorted_content = sorted(content_list, key=sort_key)
        
        # Build learning path with prerequisites
        learning_path = []
        completed = set()
        
        for content in sorted_content:
            # Check if prerequisites are met
            prerequisites_met = True
            for dep in content.get("dependencies", []):
                if dep not in completed:
                    prerequisites_met = False
                    break
            
            if prerequisites_met:
                learning_path.append(content)
                completed.add(content["chapter_id"])
        
        return learning_path
    
    def get_metadata_summary(self) -> Dict[str, Any]:
        """
        Get metadata system summary
        
        Returns:
            Summary of metadata system status
        """
        content_list = self.list_content()
        
        # Validation summary
        validation_scores = [c.get("validation_score") for c in content_list if c.get("validation_score")]
        bias_scores = [c.get("bias_score") for c in content_list if c.get("bias_score")]
        
        summary = {
            "total_content_files": len(content_list),
            "cache_path": str(self.metadata_cache_path),
            "cache_entries": len(self.metadata_cache),
            "validation_summary": {
                "validated_files": len(validation_scores),
                "average_score": sum(validation_scores) / len(validation_scores) if validation_scores else 0,
                "high_quality": sum(1 for score in validation_scores if score >= 90),
            },
            "bias_assessment": {
                "assessed_files": len(bias_scores),
                "average_score": sum(bias_scores) / len(bias_scores) if bias_scores else 0,
                "low_bias": sum(1 for score in bias_scores if score <= 20),
            },
            "last_cache_update": datetime.now().isoformat()
        }
        
        return summary


def main():
    """Main function for CLI usage"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Metadata Manager")
    parser.add_argument("--repo", default=".", help="Repository path")
    parser.add_argument("--command", required=True,
                       choices=["extract", "validate", "list", "index", "path", "summary"],
                       help="Command to execute")
    parser.add_argument("--file-path", help="Path to specific file")
    parser.add_argument("--chapter-filter", help="Filter by chapter ID")
    parser.add_argument("--status-filter", help="Filter by status")
    parser.add_argument("--platform-filter", help="Filter by platform")
    parser.add_argument("--output", help="Output file path")
    
    args = parser.parse_args()
    
    try:
        config = {
            "content": {"chapters_path": "chapters"},
            "metadata": {"required_fields": ["title", "chapter_id", "author"]}
        }
        
        manager = MetadataManager(Path(args.repo), config)
        
        if args.command == "extract":
            if not args.file_path:
                print("Error: file-path is required for extraction")
                return
            
            metadata = manager.extract_metadata(Path(args.file_path))
            if metadata:
                metadata_dict = asdict(metadata)
                metadata_dict["status"] = metadata_dict["status"].value
                metadata_dict["difficulty_level"] = metadata_dict["difficulty_level"].value
                
                if args.output:
                    with open(args.output, 'w') as f:
                        json.dump(metadata_dict, f, indent=2)
                    print(f"Metadata saved to {args.output}")
                else:
                    print(json.dumps(metadata_dict, indent=2))
            else:
                print("Failed to extract metadata")
        
        elif args.command == "validate":
            if not args.file_path:
                print("Error: file-path is required for validation")
                return
            
            metadata = manager.extract_metadata(Path(args.file_path))
            if metadata:
                result = manager.validate_metadata(metadata)
                status = "✓" if result["valid"] else "✗"
                print(f"{status} {args.file_path}: {result['score']:.1f}%")
                
                if result["errors"]:
                    print("Errors:")
                    for error in result["errors"]:
                        print(f"  - {error}")
                
                if result["warnings"]:
                    print("Warnings:")
                    for warning in result["warnings"]:
                        print(f"  - {warning}")
            else:
                print("Failed to extract metadata for validation")
        
        elif args.command == "list":
            content_list = manager.list_content(
                chapter_filter=args.chapter_filter,
                status_filter=args.status_filter,
                platform_filter=args.platform_filter
            )
            
            print(f"Found {len(content_list)} content files:")
            for content in content_list:
                platforms = ", ".join(content["platforms"])
                print(f"  {content['chapter_id']}: {content['title']} "
                      f"({content['status']}) [{platforms}]")
        
        elif args.command == "index":
            index = manager.build_content_index()
            index_dict = asdict(index)
            
            if args.output:
                with open(args.output, 'w') as f:
                    json.dump(index_dict, f, indent=2)
                print(f"Content index saved to {args.output}")
            else:
                print(json.dumps(index_dict, indent=2))
        
        elif args.command == "path":
            learning_path = manager.get_learning_path(args.platform_filter)
            
            print(f"Learning path ({len(learning_path)} items):")
            for i, content in enumerate(learning_path, 1):
                print(f"  {i}. {content['chapter_id']}: {content['title']} "
                      f"({content['difficulty_level']})")
        
        elif args.command == "summary":
            summary = manager.get_metadata_summary()
            
            if args.output:
                with open(args.output, 'w') as f:
                    json.dump(summary, f, indent=2)
                print(f"Summary saved to {args.output}")
            else:
                print(json.dumps(summary, indent=2))
    
    except Exception as e:
        logger.error(f"Command failed: {e}")
        print(f"Error: {e}")
        return 1


if __name__ == "__main__":
    exit(main())