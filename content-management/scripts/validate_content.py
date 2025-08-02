#!/usr/bin/env python3
"""
Content Validation Script
=========================

Automation script for validating educational content.
Provides command-line interface for content validation, quality checking,
and compliance verification.

Usage:
    python validate_content.py --file chapter.md
    python validate_content.py --chapter "14-advanced-ml"
    python validate_content.py --all --output report.json

Author: Claude Code Implementation
Version: 1.0.0
"""

import os
import sys
import json
import argparse
import logging
from pathlib import Path
from typing import Dict, List, Optional, Any, Union

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.cms_engine import ContentManagementEngine
from core.validation_engine import ValidationEngine

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def validate_single_file(file_path: Path, engine: ValidationEngine, args: argparse.Namespace) -> Dict[str, Any]:
    """
    Validate a single content file
    
    Args:
        file_path: Path to file to validate
        engine: Validation engine instance
        args: Command line arguments
        
    Returns:
        Validation results
    """
    logger.info(f"Validating file: {file_path}")
    
    try:
        # Perform comprehensive validation
        result = engine.validate_content(file_path)
        
        # Print summary
        status = "✓ PASSED" if result["passed"] else "✗ FAILED"
        score = result["overall_score"]
        logger.info(f"{status} - {file_path.name}: {score:.1f}%")
        
        # Print detailed results if verbose
        if args.verbose or not result["passed"]:
            if result["errors"]:
                logger.error(f"Errors ({len(result['errors'])}):")
                for error in result["errors"]:
                    logger.error(f"  - {error}")
            
            if result["warnings"]:
                logger.warning(f"Warnings ({len(result['warnings'])}):")
                for warning in result["warnings"]:
                    logger.warning(f"  - {warning}")
            
            if result["recommendations"] and args.verbose:
                logger.info(f"Recommendations ({len(result['recommendations'])}):")
                for rec in result["recommendations"]:
                    logger.info(f"  - {rec}")
            
            # Show check details if verbose
            if args.verbose and result["checks"]:
                logger.info("Check Details:")
                for check_name, check_result in result["checks"].items():
                    check_status = "✓" if check_result.get("passed", False) else "✗"
                    check_score = check_result.get("score", 0)
                    logger.info(f"  {check_status} {check_name.title()}: {check_score:.1f}%")
        
        return result
        
    except Exception as e:
        logger.error(f"Validation failed for {file_path}: {e}")
        return {
            "file_path": str(file_path),
            "overall_score": 0.0,
            "passed": False,
            "errors": [f"Validation error: {str(e)}"],
            "warnings": [],
            "recommendations": [],
            "checks": {}
        }


def validate_chapter(chapter_id: str, repo_path: Path, engine: ValidationEngine, args: argparse.Namespace) -> List[Dict[str, Any]]:
    """
    Validate all files in a chapter
    
    Args:
        chapter_id: Chapter identifier
        repo_path: Repository path
        engine: Validation engine instance
        args: Command line arguments
        
    Returns:
        List of validation results
    """
    logger.info(f"Validating chapter: {chapter_id}")
    
    chapter_path = repo_path / "chapters" / chapter_id
    if not chapter_path.exists():
        logger.error(f"Chapter directory not found: {chapter_path}")
        return []
    
    results = []
    supported_extensions = [".md", ".ipynb"]
    
    # Find all content files in chapter
    for file_path in chapter_path.rglob("*"):
        if file_path.is_file() and file_path.suffix in supported_extensions:
            result = validate_single_file(file_path, engine, args)
            results.append(result)
    
    # Print chapter summary
    if results:
        total_files = len(results)
        passed_files = sum(1 for r in results if r["passed"])
        avg_score = sum(r["overall_score"] for r in results) / total_files
        
        logger.info(f"Chapter Summary - {chapter_id}:")
        logger.info(f"  Files validated: {total_files}")
        logger.info(f"  Files passed: {passed_files}/{total_files}")
        logger.info(f"  Average score: {avg_score:.1f}%")
        logger.info(f"  Pass rate: {(passed_files/total_files)*100:.1f}%")
    
    return results


def validate_all_content(repo_path: Path, engine: ValidationEngine, args: argparse.Namespace) -> List[Dict[str, Any]]:
    """
    Validate all content in repository
    
    Args:
        repo_path: Repository path
        engine: Validation engine instance
        args: Command line arguments
        
    Returns:
        List of all validation results
    """
    logger.info("Validating all content...")
    
    chapters_path = repo_path / "chapters"
    if not chapters_path.exists():
        logger.error(f"Chapters directory not found: {chapters_path}")
        return []
    
    all_results = []
    chapter_summaries = []
    
    # Process each chapter
    for chapter_dir in chapters_path.iterdir():
        if chapter_dir.is_dir():
            chapter_results = validate_chapter(chapter_dir.name, repo_path, engine, args)
            all_results.extend(chapter_results)
            
            if chapter_results:
                total_files = len(chapter_results)
                passed_files = sum(1 for r in chapter_results if r["passed"])
                avg_score = sum(r["overall_score"] for r in chapter_results) / total_files
                
                chapter_summaries.append({
                    "chapter_id": chapter_dir.name,
                    "total_files": total_files,
                    "passed_files": passed_files,
                    "average_score": avg_score,
                    "pass_rate": (passed_files/total_files)*100
                })
    
    # Print overall summary
    if all_results:
        total_files = len(all_results)
        total_passed = sum(1 for r in all_results if r["passed"])
        overall_avg = sum(r["overall_score"] for r in all_results) / total_files
        
        logger.info("Overall Summary:")
        logger.info(f"  Total files validated: {total_files}")
        logger.info(f"  Total files passed: {total_passed}/{total_files}")
        logger.info(f"  Overall average score: {overall_avg:.1f}%")
        logger.info(f"  Overall pass rate: {(total_passed/total_files)*100:.1f}%")
        
        # Show chapter breakdown
        if args.verbose and chapter_summaries:
            logger.info("Chapter Breakdown:")
            for summary in sorted(chapter_summaries, key=lambda x: x["chapter_id"]):
                logger.info(f"  {summary['chapter_id']}: "
                          f"{summary['passed_files']}/{summary['total_files']} passed "
                          f"({summary['pass_rate']:.1f}%, avg: {summary['average_score']:.1f}%)")
    
    return all_results


def run_specific_validation(file_path: Path, check_type: str, engine: ValidationEngine, args: argparse.Namespace) -> Dict[str, Any]:
    """
    Run specific validation check
    
    Args:
        file_path: Path to file to validate
        check_type: Type of validation check
        engine: Validation engine instance
        args: Command line arguments
        
    Returns:
        Validation results
    """
    logger.info(f"Running {check_type} validation on: {file_path}")
    
    try:
        if check_type == "structure":
            content_type = args.content_type or "chapter"
            result = engine.validate_structure(file_path, content_type)
        elif check_type == "quality":
            content_type = args.content_type or "chapter"
            result = engine.validate_quality(file_path, content_type)
        elif check_type == "links":
            result = engine.validate_links(file_path)
        elif check_type == "code":
            result = engine.validate_code(file_path)
        elif check_type == "metadata":
            result = engine.validate_metadata(file_path)
        else:
            raise ValueError(f"Unknown validation type: {check_type}")
        
        # Print results
        status = "✓ PASSED" if result["passed"] else "✗ FAILED"
        score = result["score"]
        logger.info(f"{status} - {check_type.title()} validation: {score:.1f}%")
        
        if result["errors"]:
            logger.error(f"Errors ({len(result['errors'])}):")
            for error in result["errors"]:
                logger.error(f"  - {error}")
        
        if result["warnings"]:
            logger.warning(f"Warnings ({len(result['warnings'])}):")
            for warning in result["warnings"]:
                logger.warning(f"  - {warning}")
        
        if result.get("recommendations") and args.verbose:
            logger.info(f"Recommendations ({len(result['recommendations'])}):")
            for rec in result["recommendations"]:
                logger.info(f"  - {rec}")
        
        return result
        
    except Exception as e:
        logger.error(f"Validation failed: {e}")
        return {
            "score": 0.0,
            "passed": False,
            "errors": [str(e)],
            "warnings": [],
            "recommendations": []
        }


def generate_validation_report(results: List[Dict[str, Any]], output_path: Path) -> bool:
    """
    Generate comprehensive validation report
    
    Args:
        results: List of validation results  
        output_path: Path for output report
        
    Returns:
        Success status
    """
    try:
        if not results:
            logger.warning("No results to generate report from")
            return False
        
        # Calculate summary statistics
        total_files = len(results)
        passed_files = sum(1 for r in results if r.get("passed", False))
        failed_files = total_files - passed_files
        
        scores = [r.get("overall_score", 0) for r in results]
        avg_score = sum(scores) / len(scores) if scores else 0
        min_score = min(scores) if scores else 0
        max_score = max(scores) if scores else 0
        
        # Count errors and warnings
        total_errors = sum(len(r.get("errors", [])) for r in results)
        total_warnings = sum(len(r.get("warnings", [])) for r in results)
        
        # Generate report
        report = {
            "validation_report": {
                "generated_at": "2025-01-28T00:00:00Z",  # Would use actual timestamp
                "summary": {
                    "total_files": total_files,
                    "passed_files": passed_files,
                    "failed_files": failed_files,
                    "pass_rate": (passed_files / total_files * 100) if total_files > 0 else 0,
                    "average_score": avg_score,
                    "min_score": min_score,
                    "max_score": max_score,
                    "total_errors": total_errors,
                    "total_warnings": total_warnings
                },
                "results": results,
                "failed_files": [
                    {
                        "file_path": r["file_path"],
                        "score": r.get("overall_score", 0),
                        "errors": r.get("errors", []),
                        "warnings": r.get("warnings", [])
                    }
                    for r in results if not r.get("passed", False)
                ],
                "recommendations": {
                    "high_priority": [],
                    "medium_priority": [],
                    "low_priority": []
                }
            }
        }
        
        # Add recommendations based on common issues
        if failed_files > total_files * 0.5:
            report["validation_report"]["recommendations"]["high_priority"].append(
                "More than 50% of files failed validation - review content standards"
            )
        
        if avg_score < 70:
            report["validation_report"]["recommendations"]["high_priority"].append(
                f"Average validation score is low ({avg_score:.1f}%) - improve content quality"
            )
        
        if total_errors > 0:
            report["validation_report"]["recommendations"]["medium_priority"].append(
                f"Fix all {total_errors} validation errors before publishing"
            )
        
        # Save report
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2)
        
        logger.info(f"Validation report generated: {output_path}")
        logger.info(f"Summary: {passed_files}/{total_files} files passed ({(passed_files/total_files)*100:.1f}%)")
        
        return True
        
    except Exception as e:
        logger.error(f"Failed to generate validation report: {e}")
        return False


def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description="Content Validation Script for CMS",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Validate single file
  python validate_content.py --file chapters/01-intro/README.md

  # Validate entire chapter
  python validate_content.py --chapter "01-intro"

  # Validate all content
  python validate_content.py --all

  # Run specific validation
  python validate_content.py --file chapter.md --check structure

  # Generate detailed report
  python validate_content.py --all --output validation_report.json --verbose
        """
    )
    
    # Global options
    parser.add_argument("--repo", default=".", help="Repository path")
    parser.add_argument("--config", help="Configuration file path")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    parser.add_argument("--output", "-o", help="Output report file path")
    
    # Validation targets
    parser.add_argument("--file", help="Validate specific file")
    parser.add_argument("--chapter", help="Validate specific chapter")
    parser.add_argument("--all", action="store_true", help="Validate all content")
    
    # Validation options
    parser.add_argument("--check", 
                       choices=["structure", "quality", "links", "code", "metadata"],
                       help="Run specific validation check")
    parser.add_argument("--content-type", 
                       choices=["chapter", "section", "exercise"],
                       help="Content type for validation")
    parser.add_argument("--min-score", type=float, default=80.0,
                       help="Minimum passing score")
    parser.add_argument("--fail-on-warnings", action="store_true",
                       help="Treat warnings as failures")
    
    args = parser.parse_args()
    
    # Set logging level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    try:
        repo_path = Path(args.repo).resolve()
        
        # Create validation engine
        config = {
            "validation": {
                "minimum_score": args.min_score,
                "check_links": True,
                "check_code": True
            },
            "metadata": {
                "required_fields": ["title", "chapter_id", "author", "platforms"]
            }
        }
        
        if args.config:
            config_path = Path(args.config)
            if config_path.exists():
                with open(config_path, 'r') as f:
                    user_config = json.load(f)
                    config.update(user_config)
        
        engine = ValidationEngine(repo_path, config)
        
        results = []
        
        # Validate single file
        if args.file:
            file_path = Path(args.file)
            if not file_path.is_absolute():
                file_path = repo_path / file_path
            
            if not file_path.exists():
                logger.error(f"File not found: {file_path}")
                sys.exit(1)
            
            if args.check:
                result = run_specific_validation(file_path, args.check, engine, args)
                results = [result]
            else:
                result = validate_single_file(file_path, engine, args)
                results = [result]
        
        # Validate chapter
        elif args.chapter:
            results = validate_chapter(args.chapter, repo_path, engine, args)
        
        # Validate all content
        elif args.all:
            results = validate_all_content(repo_path, engine, args)
        
        else:
            parser.print_help()
            sys.exit(1)
        
        # Generate report if requested
        if args.output and results:
            success = generate_validation_report(results, Path(args.output))
            if not success:
                sys.exit(1)
        
        # Determine exit code
        if results:
            failed_results = [r for r in results if not r.get("passed", False)]
            
            if args.fail_on_warnings:
                # Also fail on warnings
                warning_results = [r for r in results if r.get("warnings", [])]
                if warning_results:
                    logger.warning(f"Failing due to warnings in {len(warning_results)} files")
                    sys.exit(1)
            
            if failed_results:
                logger.error(f"Validation failed for {len(failed_results)} files")
                sys.exit(1)
            else:
                logger.info("All validations passed!")
                sys.exit(0)
        else:
            logger.warning("No files validated")
            sys.exit(1)
    
    except KeyboardInterrupt:
        logger.info("Validation cancelled by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()