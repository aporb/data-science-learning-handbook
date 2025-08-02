#!/usr/bin/env python3
"""
Content Generation Script
=========================

Automation script for generating educational content from templates.
Provides command-line interface for content creation, template management,
and batch content operations.

Usage:
    python generate_content.py --init                    # Initialize CMS
    python generate_content.py --template chapter --chapter-id "14-advanced-ml"
    python generate_content.py --batch-generate config.json

Author: Claude Code Implementation
Version: 1.0.0
"""

import os
import sys
import json
import argparse
import logging
from pathlib import Path
from typing import Dict, List, Optional, Any

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.cms_engine import ContentManagementEngine, ContentSpec
from core.template_manager import TemplateManager

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def initialize_cms(repo_path: Path) -> bool:
    """
    Initialize the Content Management System
    
    Args:
        repo_path: Path to repository
        
    Returns:
        Success status
    """
    try:
        logger.info("Initializing Content Management System...")
        
        # Create CMS engine
        cms = ContentManagementEngine(repo_path)
        
        # Create base templates
        template_manager = cms.template_manager
        result = template_manager.create_base_templates()
        
        if result["success"]:
            logger.info(f"Created {len(result['created_templates'])} base templates")
            for template in result["created_templates"]:
                logger.info(f"  - {template}")
        else:
            logger.error("Failed to create base templates")
            for error in result["errors"]:
                logger.error(f"  - {error}")
            return False
        
        # Create sample configuration
        config_path = repo_path / "content-management" / "config.json"
        sample_config = {
            "templates": {
                "base_path": "content-management/templates",
                "supported_types": ["chapter", "section", "exercise", "platform"],
                "auto_sync": True
            },
            "content": {
                "chapters_path": "chapters",
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
        
        with open(config_path, 'w', encoding='utf-8') as f:
            json.dump(sample_config, f, indent=2)
        
        logger.info(f"Created configuration file: {config_path}")
        logger.info("Content Management System initialized successfully!")
        
        return True
        
    except Exception as e:
        logger.error(f"CMS initialization failed: {e}")
        return False


def generate_single_content(args: argparse.Namespace) -> bool:
    """
    Generate single content item from template
    
    Args:
        args: Command line arguments
        
    Returns:
        Success status
    """
    try:
        logger.info(f"Generating {args.template} content: {args.chapter_id}")
        
        # Create CMS engine
        cms = ContentManagementEngine(Path(args.repo), args.config)
        
        # Create content specification
        spec = ContentSpec(
            template_type=args.template,
            chapter_id=args.chapter_id,
            title=args.title or f"Chapter {args.chapter_id}",
            author=args.author or "Content Team",
            platforms=args.platforms or ["python"],
            learning_objectives=args.objectives or ["To be defined"],
            prerequisites=args.prerequisites or ["Basic understanding"],
            difficulty_level=args.difficulty or "intermediate",
            estimated_time=args.time or "2-3 hours",
            tags=args.tags or ["data-science", "tutorial"]
        )
        
        # Generate content
        result = cms.generate_content(spec)
        
        if result.success:
            logger.info("Content generation successful!")
            logger.info(f"Generated files ({len(result.generated_files)}):")
            for file_path in result.generated_files:
                logger.info(f"  - {file_path}")
            
            if result.validation_results:
                logger.info("Validation results:")
                for file_path, validation in result.validation_results.items():
                    status = "✓" if validation.get("passed", False) else "✗"
                    score = validation.get("overall_score", 0)
                    logger.info(f"  {status} {Path(file_path).name}: {score:.1f}%")
            
            if result.warnings:
                logger.warning(f"Warnings ({len(result.warnings)}):")
                for warning in result.warnings:
                    logger.warning(f"  - {warning}")
            
        else:
            logger.error("Content generation failed!")
            for error in result.errors:
                logger.error(f"  - {error}")
            return False
        
        return True
        
    except Exception as e:
        logger.error(f"Content generation failed: {e}")
        return False


def batch_generate_content(config_file: Path, repo_path: Path) -> bool:
    """
    Generate multiple content items from configuration
    
    Args:
        config_file: Path to batch configuration file
        repo_path: Path to repository
        
    Returns:
        Success status
    """
    try:
        logger.info(f"Batch generating content from: {config_file}")
        
        # Load batch configuration
        with open(config_file, 'r', encoding='utf-8') as f:
            batch_config = json.load(f)
        
        # Create CMS engine
        cms = ContentManagementEngine(repo_path)
        
        total_items = len(batch_config.get("content_items", []))
        successful = 0
        failed = 0
        
        for i, item_config in enumerate(batch_config.get("content_items", []), 1):
            logger.info(f"Processing item {i}/{total_items}: {item_config.get('chapter_id')}")
            
            try:
                # Create content specification from config
                spec = ContentSpec(
                    template_type=item_config.get("template_type", "chapter"),
                    chapter_id=item_config["chapter_id"],
                    title=item_config["title"],
                    author=item_config.get("author", "Content Team"),
                    platforms=item_config.get("platforms", ["python"]),
                    learning_objectives=item_config.get("learning_objectives", []),
                    prerequisites=item_config.get("prerequisites", []),
                    difficulty_level=item_config.get("difficulty_level", "intermediate"),
                    estimated_time=item_config.get("estimated_time", "2-3 hours"),
                    tags=item_config.get("tags", [])
                )
                
                # Generate content
                result = cms.generate_content(spec)
                
                if result.success:
                    logger.info(f"  ✓ Generated: {item_config['chapter_id']}")
                    successful += 1
                else:
                    logger.error(f"  ✗ Failed: {item_config['chapter_id']}")
                    for error in result.errors:
                        logger.error(f"    - {error}")
                    failed += 1
                    
            except Exception as e:
                logger.error(f"  ✗ Failed: {item_config.get('chapter_id', 'unknown')} - {e}")
                failed += 1
        
        logger.info(f"Batch generation completed: {successful} successful, {failed} failed")
        return failed == 0
        
    except Exception as e:
        logger.error(f"Batch generation failed: {e}")
        return False


def sync_templates(repo_path: Path, template_type: Optional[str] = None) -> bool:
    """
    Synchronize templates with latest versions
    
    Args:
        repo_path: Path to repository
        template_type: Specific template type to sync
        
    Returns:
        Success status
    """
    try:
        logger.info(f"Synchronizing templates: {template_type or 'all'}")
        
        # Create template manager
        config = {"content": {"chapters_path": "chapters"}}
        template_manager = TemplateManager(repo_path / "content-management", config)
        
        # Sync templates
        result = template_manager.sync_templates(template_type)
        
        if result["success"]:
            logger.info(f"Template sync successful!")
            if result["updated"]:
                logger.info(f"Updated templates ({len(result['updated'])}):")
                for template in result["updated"]:
                    logger.info(f"  - {template}")
            else:
                logger.info("No templates needed updating")
        else:
            logger.error("Template sync failed!")
            for error in result["errors"]:
                logger.error(f"  - {error}")
            return False
        
        return True
        
    except Exception as e:
        logger.error(f"Template sync failed: {e}")
        return False


def create_sample_batch_config(output_path: Path) -> bool:
    """
    Create sample batch configuration file
    
    Args:
        output_path: Path for sample configuration
        
    Returns:
        Success status
    """
    try:
        sample_config = {
            "description": "Sample batch content generation configuration",
            "content_items": [
                {
                    "template_type": "chapter",
                    "chapter_id": "14-advanced-ml",
                    "title": "Advanced Machine Learning Techniques",
                    "author": "ML Expert",
                    "platforms": ["python", "r"],
                    "learning_objectives": [
                        "Understand advanced ML algorithms",
                        "Implement ensemble methods",
                        "Apply hyperparameter optimization"
                    ],
                    "prerequisites": [
                        "Basic machine learning knowledge",
                        "Python/R programming experience",
                        "Statistics fundamentals"
                    ],
                    "difficulty_level": "advanced",
                    "estimated_time": "4-5 hours",
                    "tags": ["machine-learning", "advanced", "ensemble", "optimization"]
                },
                {
                    "template_type": "exercise",
                    "chapter_id": "14-advanced-ml",
                    "title": "Implementing Random Forest",
                    "author": "ML Expert",
                    "platforms": ["python"],
                    "learning_objectives": [
                        "Build random forest from scratch",
                        "Compare with scikit-learn implementation"
                    ],
                    "prerequisites": [
                        "Decision tree understanding",
                        "Python programming"
                    ],
                    "difficulty_level": "advanced",
                    "estimated_time": "2 hours",
                    "tags": ["exercise", "random-forest", "implementation"]
                }
            ]
        }
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(sample_config, f, indent=2)
        
        logger.info(f"Created sample batch configuration: {output_path}")
        return True
        
    except Exception as e:
        logger.error(f"Failed to create sample config: {e}")
        return False


def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description="Content Generation Script for CMS",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Initialize CMS
  python generate_content.py --init

  # Generate chapter
  python generate_content.py --template chapter --chapter-id "14-advanced-ml" \\
    --title "Advanced ML" --author "Expert" --platforms python r

  # Generate exercise
  python generate_content.py --template exercise --chapter-id "14-advanced-ml" \\
    --title "Random Forest Exercise"

  # Batch generation
  python generate_content.py --batch-generate batch_config.json

  # Sync templates
  python generate_content.py --sync-templates --template-type chapter

  # Create sample batch config
  python generate_content.py --create-sample-config sample_batch.json
        """
    )
    
    # Global options
    parser.add_argument("--repo", default=".", help="Repository path")
    parser.add_argument("--config", help="Configuration file path")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    
    # Commands
    parser.add_argument("--init", action="store_true", help="Initialize CMS")
    parser.add_argument("--sync-templates", action="store_true", help="Sync templates")
    parser.add_argument("--batch-generate", help="Batch generate from config file")
    parser.add_argument("--create-sample-config", help="Create sample batch config file")
    
    # Content generation options
    parser.add_argument("--template", choices=["chapter", "section", "exercise"], 
                       help="Template type to generate")
    parser.add_argument("--chapter-id", help="Chapter identifier")
    parser.add_argument("--title", help="Content title")
    parser.add_argument("--author", help="Content author")
    parser.add_argument("--platforms", nargs="+", help="Target platforms")
    parser.add_argument("--objectives", nargs="+", help="Learning objectives")
    parser.add_argument("--prerequisites", nargs="+", help="Prerequisites")
    parser.add_argument("--difficulty", choices=["beginner", "intermediate", "advanced", "expert"],
                       help="Difficulty level")
    parser.add_argument("--time", help="Estimated time")
    parser.add_argument("--tags", nargs="+", help="Content tags")
    
    # Template options
    parser.add_argument("--template-type", help="Specific template type to sync")
    
    args = parser.parse_args()
    
    # Set logging level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    try:
        repo_path = Path(args.repo).resolve()
        
        # Initialize CMS
        if args.init:
            success = initialize_cms(repo_path)
            sys.exit(0 if success else 1)
        
        # Sync templates
        elif args.sync_templates:
            success = sync_templates(repo_path, args.template_type)
            sys.exit(0 if success else 1)
        
        # Batch generation
        elif args.batch_generate:
            config_file = Path(args.batch_generate)
            if not config_file.exists():
                logger.error(f"Batch config file not found: {config_file}")
                sys.exit(1)
            
            success = batch_generate_content(config_file, repo_path)
            sys.exit(0 if success else 1)
        
        # Create sample config
        elif args.create_sample_config:
            output_path = Path(args.create_sample_config)
            success = create_sample_batch_config(output_path)
            sys.exit(0 if success else 1)
        
        # Single content generation
        elif args.template:
            if not args.chapter_id:
                logger.error("chapter-id is required for content generation")
                sys.exit(1)
            
            success = generate_single_content(args)
            sys.exit(0 if success else 1)
        
        else:
            parser.print_help()
            sys.exit(1)
    
    except KeyboardInterrupt:
        logger.info("Operation cancelled by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()