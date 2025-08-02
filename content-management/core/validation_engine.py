#!/usr/bin/env python3
"""
Validation Engine
================

Content validation engine for the Git-based Chapter Content Management System.
Provides comprehensive validation of educational content including structure,
quality, links, code, and compliance checking.

This module provides:
- Content structure validation
- Code syntax and execution validation  
- Link and reference checking
- Educational quality assessment
- Compliance and accessibility validation
- Multi-platform content validation

Author: Claude Code Implementation
Version: 1.0.0
"""

import os
import re
import json
import logging
import subprocess
import requests
from pathlib import Path
from typing import Dict, List, Optional, Any, Union, Tuple
from datetime import datetime
from urllib.parse import urlparse, urljoin
import ast
import yaml

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class ValidationEngine:
    """
    Content Validation Engine
    
    Provides comprehensive validation capabilities for educational content
    including structure, quality, links, code, and compliance checking.
    """
    
    def __init__(self, repo_path: Path, config: Dict[str, Any]):
        """
        Initialize Validation Engine
        
        Args:
            repo_path: Path to the Git repository
            config: CMS configuration dictionary
        """
        self.repo_path = Path(repo_path)
        self.config = config
        self.validation_config = config.get("validation", {})
        self.cache_path = self.repo_path / "content-management" / "cache" / "validation.json"
        
        # Ensure cache directory exists
        self.cache_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Load validation cache
        self.validation_cache = self._load_validation_cache()
        
        # Validation rules
        self.structure_rules = self._load_structure_rules()
        self.quality_rules = self._load_quality_rules()
        
        logger.info(f"Validation Engine initialized for: {self.repo_path}")
    
    def _load_validation_cache(self) -> Dict[str, Dict[str, Any]]:
        """Load validation cache from disk"""
        if self.cache_path.exists():
            try:
                with open(self.cache_path, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception as e:
                logger.warning(f"Failed to load validation cache: {e}")
        return {}
    
    def _save_validation_cache(self):
        """Save validation cache to disk"""
        try:
            with open(self.cache_path, 'w', encoding='utf-8') as f:
                json.dump(self.validation_cache, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save validation cache: {e}")
    
    def _load_structure_rules(self) -> Dict[str, Any]:
        """Load content structure validation rules"""
        return {
            "chapter": {
                "required_sections": [
                    "# ",  # Title
                    "## Chapter Overview",
                    "### Learning Objectives", 
                    "## Introduction",
                    "## Summary"
                ],
                "recommended_sections": [
                    "### Prerequisites",
                    "## Practical Examples",
                    "## Hands-on Exercises",
                    "## Best Practices"
                ],
                "max_heading_depth": 4,
                "min_word_count": 500,
                "max_word_count": 10000
            },
            "section": {
                "required_sections": [
                    "## ",  # Section title
                    "### Overview"
                ],
                "min_word_count": 100,
                "max_word_count": 3000
            },
            "exercise": {
                "required_sections": [
                    "# Exercise:",
                    "## Objective",
                    "## Instructions",
                    "## Expected Output"
                ],
                "recommended_sections": [
                    "## Solution",
                    "## Common Pitfalls"
                ],
                "min_word_count": 200,
                "max_word_count": 2000
            }
        }
    
    def _load_quality_rules(self) -> Dict[str, Any]:
        """Load content quality validation rules"""
        return {
            "readability": {
                "max_sentence_length": 25,
                "max_paragraph_length": 150,
                "min_paragraph_count": 3
            },
            "educational": {
                "min_learning_objectives": 1,
                "max_learning_objectives": 8,
                "min_examples": 1,
                "max_examples": 10
            },
            "technical": {
                "code_comment_ratio": 0.2,  # 20% comments
                "max_code_block_lines": 50,
                "required_code_explanation": True
            },
            "accessibility": {
                "alt_text_required": True,
                "heading_hierarchy": True,
                "color_contrast": True
            }
        }
    
    def validate_content(self, file_path: Path) -> Dict[str, Any]:
        """
        Perform comprehensive content validation
        
        Args:
            file_path: Path to content file
            
        Returns:
            Comprehensive validation results
        """
        logger.info(f"Validating content: {file_path}")
        
        validation_result = {
            "file_path": str(file_path),
            "timestamp": datetime.now().isoformat(),
            "overall_score": 0.0,
            "passed": False,
            "checks": {},
            "errors": [],
            "warnings": [],
            "recommendations": []
        }
        
        try:
            # Check if file exists
            if not file_path.exists():
                validation_result["errors"].append("File does not exist")
                return validation_result
            
            # Load content
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Determine content type from metadata or path
            content_type = self._determine_content_type(file_path, content)
            
            # Run validation checks
            checks = []
            
            # Structure validation
            structure_result = self.validate_structure(file_path, content_type)
            checks.append(("structure", structure_result))
            validation_result["checks"]["structure"] = structure_result
            
            # Quality validation
            quality_result = self.validate_quality(file_path, content_type)
            checks.append(("quality", quality_result))
            validation_result["checks"]["quality"] = quality_result
            
            # Link validation (if enabled)
            if self.validation_config.get("check_links", True):
                link_result = self.validate_links(file_path)
                checks.append(("links", link_result))
                validation_result["checks"]["links"] = link_result
            
            # Code validation (if content has code)
            if "```" in content:
                code_result = self.validate_code(file_path)
                checks.append(("code", code_result))
                validation_result["checks"]["code"] = code_result
            
            # Metadata validation
            metadata_result = self.validate_metadata(file_path)
            checks.append(("metadata", metadata_result))
            validation_result["checks"]["metadata"] = metadata_result
            
            # Calculate overall score
            scores = [check[1].get("score", 0) for check in checks]
            validation_result["overall_score"] = sum(scores) / len(scores) if scores else 0
            
            # Collect errors and warnings
            for check_name, check_result in checks:
                validation_result["errors"].extend(check_result.get("errors", []))
                validation_result["warnings"].extend(check_result.get("warnings", []))
                validation_result["recommendations"].extend(check_result.get("recommendations", []))
            
            # Determine pass/fail
            minimum_score = self.validation_config.get("minimum_score", 80.0)
            validation_result["passed"] = (
                validation_result["overall_score"] >= minimum_score and
                len(validation_result["errors"]) == 0
            )
            
            # Cache results
            self.validation_cache[str(file_path)] = validation_result
            self._save_validation_cache()
            
        except Exception as e:
            validation_result["errors"].append(f"Validation failed: {str(e)}")
            logger.error(f"Content validation failed for {file_path}: {e}")
        
        return validation_result
    
    def _determine_content_type(self, file_path: Path, content: str) -> str:
        """Determine content type from file path and content"""
        # Check metadata first
        if content.startswith('---'):
            try:
                frontmatter_end = content.find('---', 3)
                if frontmatter_end > 0:
                    frontmatter = content[3:frontmatter_end].strip()
                    metadata = yaml.safe_load(frontmatter)
                    if metadata and 'content_type' in metadata:
                        return metadata['content_type']
            except:
                pass
        
        # Infer from path
        if 'exercise' in str(file_path).lower():
            return 'exercise'
        elif file_path.name.lower() in ['readme.md', 'index.md']:
            return 'chapter'
        else:
            return 'section'
    
    def validate_structure(self, file_path: Path, content_type: str = "chapter") -> Dict[str, Any]:
        """
        Validate content structure
        
        Args:
            file_path: Path to content file
            content_type: Type of content (chapter, section, exercise)
            
        Returns:
            Structure validation results
        """
        result = {
            "score": 100.0,
            "passed": True,
            "errors": [],
            "warnings": [],
            "recommendations": [],
            "content_type": content_type
        }
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            rules = self.structure_rules.get(content_type, {})
            
            # Check required sections
            required_sections = rules.get("required_sections", [])
            for section in required_sections:
                if section not in content:
                    result["errors"].append(f"Missing required section: {section}")
                    result["score"] -= 20
            
            # Check recommended sections
            recommended_sections = rules.get("recommended_sections", [])
            missing_recommended = 0
            for section in recommended_sections:
                if section not in content:
                    result["warnings"].append(f"Missing recommended section: {section}")
                    missing_recommended += 1
            
            if missing_recommended > 0:
                result["score"] -= missing_recommended * 5
            
            # Check heading hierarchy
            headings = re.findall(r'^(#{1,6})\s+(.+)$', content, re.MULTILINE)
            if headings:
                prev_level = 0
                for heading_match in headings:
                    current_level = len(heading_match[0])
                    if current_level > prev_level + 1:
                        result["warnings"].append(f"Heading hierarchy skip: {heading_match[1]}")
                        result["score"] -= 2
                    prev_level = current_level
            
            # Check word count
            word_count = len(content.split())
            min_words = rules.get("min_word_count", 0)
            max_words = rules.get("max_word_count", float('inf'))
            
            if word_count < min_words:
                result["errors"].append(f"Content too short: {word_count} words (minimum: {min_words})")
                result["score"] -= 15
            elif word_count > max_words:
                result["warnings"].append(f"Content very long: {word_count} words (maximum: {max_words})")
                result["score"] -= 5
            
            # Check for frontmatter
            if not content.startswith('---'):
                result["warnings"].append("Missing YAML frontmatter")
                result["score"] -= 10
            
            # Ensure score is within bounds
            result["score"] = max(0, min(100, result["score"]))
            result["passed"] = result["score"] >= 70 and len(result["errors"]) == 0
            
        except Exception as e:
            result["errors"].append(f"Structure validation failed: {str(e)}")
            result["score"] = 0
            result["passed"] = False
        
        return result
    
    def validate_quality(self, file_path: Path, content_type: str = "chapter") -> Dict[str, Any]:
        """
        Validate content quality
        
        Args:
            file_path: Path to content file
            content_type: Type of content
            
        Returns:
            Quality validation results
        """
        result = {
            "score": 100.0,
            "passed": True,
            "errors": [],
            "warnings": [],
            "recommendations": []
        }
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            rules = self.quality_rules
            
            # Readability checks
            sentences = re.split(r'[.!?]+', content)
            long_sentences = sum(1 for s in sentences if len(s.split()) > rules["readability"]["max_sentence_length"])
            
            if long_sentences > len(sentences) * 0.2:  # More than 20% long sentences
                result["warnings"].append(f"Many long sentences detected ({long_sentences})")
                result["score"] -= 5
            
            # Paragraph analysis
            paragraphs = [p.strip() for p in content.split('\n\n') if p.strip()]
            content_paragraphs = [p for p in paragraphs if not p.startswith('#') and not p.startswith('```')]
            
            if len(content_paragraphs) < rules["readability"]["min_paragraph_count"]:
                result["warnings"].append("Very few paragraphs - content may be too brief")
                result["score"] -= 10
            
            # Long paragraphs check
            long_paragraphs = sum(1 for p in content_paragraphs 
                                if len(p.split()) > rules["readability"]["max_paragraph_length"])
            if long_paragraphs > 0:
                result["recommendations"].append(f"Consider breaking up {long_paragraphs} long paragraphs")
                result["score"] -= long_paragraphs * 2
            
            # Educational content checks
            if content_type == "chapter":
                # Learning objectives
                objectives_match = re.search(r'### Learning Objectives.*?(?=\n###|\n##|$)', content, re.DOTALL)
                if objectives_match:
                    objectives = re.findall(r'^[-*]\s+(.+)$', objectives_match.group(), re.MULTILINE)
                    obj_count = len(objectives)
                    
                    min_obj = rules["educational"]["min_learning_objectives"]
                    max_obj = rules["educational"]["max_learning_objectives"]
                    
                    if obj_count < min_obj:
                        result["errors"].append(f"Too few learning objectives: {obj_count} (minimum: {min_obj})")
                        result["score"] -= 15
                    elif obj_count > max_obj:
                        result["warnings"].append(f"Many learning objectives: {obj_count} (maximum: {max_obj})")
                        result["score"] -= 5
                
                # Examples check
                examples = content.count('```') // 2  # Count code blocks
                examples += len(re.findall(r'### Example \d+|#### Example', content))
                
                min_examples = rules["educational"]["min_examples"]
                if examples < min_examples:
                    result["warnings"].append(f"Few examples found: {examples} (minimum: {min_examples})")
                    result["score"] -= 10
            
            # Technical content checks
            code_blocks = re.findall(r'```[\s\S]*?```', content)
            if code_blocks:
                total_code_lines = sum(len(block.split('\n')) - 2 for block in code_blocks)  # -2 for ``` lines
                comment_lines = sum(block.count('#') + block.count('//') + block.count('/*') 
                                  for block in code_blocks)
                
                if total_code_lines > 0:
                    comment_ratio = comment_lines / total_code_lines
                    required_ratio = rules["technical"]["code_comment_ratio"]
                    
                    if comment_ratio < required_ratio:
                        result["recommendations"].append(
                            f"Low code comment ratio: {comment_ratio:.2f} (recommended: {required_ratio})"
                        )
                        result["score"] -= 5
                
                # Check for very long code blocks
                max_lines = rules["technical"]["max_code_block_lines"]
                long_blocks = sum(1 for block in code_blocks 
                                if len(block.split('\n')) > max_lines)
                if long_blocks > 0:
                    result["recommendations"].append(f"Consider breaking up {long_blocks} long code blocks")
                    result["score"] -= long_blocks * 3
            
            # Accessibility checks
            # Check for images without alt text
            images = re.findall(r'!\[([^\]]*)\]', content)
            images_without_alt = sum(1 for alt in images if not alt.strip())
            if images_without_alt > 0:
                result["warnings"].append(f"Images without alt text: {images_without_alt}")
                result["score"] -= images_without_alt * 5
            
            # Ensure score is within bounds
            result["score"] = max(0, min(100, result["score"]))
            result["passed"] = result["score"] >= 75 and len(result["errors"]) == 0
            
        except Exception as e:
            result["errors"].append(f"Quality validation failed: {str(e)}")
            result["score"] = 0
            result["passed"] = False
        
        return result
    
    def validate_links(self, file_path: Path) -> Dict[str, Any]:
        """
        Validate links and references
        
        Args:
            file_path: Path to content file
            
        Returns:
            Link validation results
        """
        result = {
            "score": 100.0,
            "passed": True,
            "errors": [],
            "warnings": [],
            "recommendations": [],
            "links_checked": 0,
            "broken_links": 0
        }
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Find all links
            links = re.findall(r'\[([^\]]+)\]\(([^)]+)\)', content)  # [text](url)
            links.extend(re.findall(r'<(https?://[^>]+)>', content))  # <url>
            
            # Convert second format to tuple format
            processed_links = []
            for link in links:
                if isinstance(link, tuple):
                    processed_links.append(link)
                else:
                    processed_links.append(("", link))
            
            result["links_checked"] = len(processed_links)
            
            for text, url in processed_links:
                if not url.strip():
                    result["warnings"].append(f"Empty link: {text}")
                    continue
                
                # Check internal links (relative paths)
                if not url.startswith(('http://', 'https://', 'mailto:', 'ftp://')):
                    internal_path = file_path.parent / url
                    if not internal_path.exists():
                        result["errors"].append(f"Broken internal link: {url}")
                        result["broken_links"] += 1
                        result["score"] -= 10
                    continue
                
                # Check external links (with timeout and basic validation)
                try:
                    parsed_url = urlparse(url)
                    if not parsed_url.netloc:
                        result["warnings"].append(f"Invalid URL format: {url}")
                        result["score"] -= 2
                        continue
                    
                    # Basic HTTP check (with timeout)
                    response = requests.head(url, timeout=5, allow_redirects=True)
                    if response.status_code >= 400:
                        result["warnings"].append(f"Link may be broken: {url} (status: {response.status_code})")
                        result["score"] -= 5
                        
                except requests.RequestException:
                    result["warnings"].append(f"Could not verify external link: {url}")
                    result["score"] -= 2
                except Exception as e:
                    result["warnings"].append(f"Link check error for {url}: {str(e)}")
            
            # Calculate broken link percentage
            if result["links_checked"] > 0:
                broken_percentage = (result["broken_links"] / result["links_checked"]) * 100
                if broken_percentage > 10:
                    result["errors"].append(f"High broken link rate: {broken_percentage:.1f}%")
                    result["score"] -= 20
            
            # Ensure score is within bounds
            result["score"] = max(0, min(100, result["score"]))
            result["passed"] = result["score"] >= 80 and len(result["errors"]) == 0
            
        except Exception as e:
            result["errors"].append(f"Link validation failed: {str(e)}")
            result["score"] = 0
            result["passed"] = False
        
        return result
    
    def validate_code(self, file_path: Path) -> Dict[str, Any]:
        """
        Validate code blocks and examples
        
        Args:
            file_path: Path to content file
            
        Returns:
            Code validation results
        """
        result = {
            "score": 100.0,
            "passed": True,
            "errors": [],
            "warnings": [],
            "recommendations": [],
            "code_blocks": 0,
            "syntax_errors": 0
        }
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Find all code blocks
            code_blocks = re.findall(r'```(\w+)?\n(.*?)\n```', content, re.DOTALL)
            result["code_blocks"] = len(code_blocks)
            
            for language, code in code_blocks:
                language = language.lower() if language else "text"
                
                # Skip non-executable code
                if language in ["text", "bash", "shell", "output", "yaml", "json", "xml"]:
                    continue
                
                # Python code validation
                if language in ["python", "py"]:
                    try:
                        ast.parse(code)
                    except SyntaxError as e:
                        result["errors"].append(f"Python syntax error: {str(e)}")
                        result["syntax_errors"] += 1
                        result["score"] -= 15
                    except Exception as e:
                        result["warnings"].append(f"Python code issue: {str(e)}")
                        result["score"] -= 5
                
                # R code validation (basic check)
                elif language in ["r", "R"]:
                    # Basic R syntax checks
                    if code.count('(') != code.count(')'):
                        result["warnings"].append("R code: Unmatched parentheses")
                        result["score"] -= 5
                    if code.count('{') != code.count('}'):
                        result["warnings"].append("R code: Unmatched braces")
                        result["score"] -= 5
                
                # SQL validation (basic)
                elif language in ["sql", "SQL"]:
                    # Check for common SQL patterns
                    sql_keywords = ["SELECT", "FROM", "WHERE", "INSERT", "UPDATE", "DELETE"]
                    if not any(keyword in code.upper() for keyword in sql_keywords):
                        result["warnings"].append("SQL code: No recognizable SQL keywords")
                        result["score"] -= 3
                
                # Check for code explanation
                # Look for comments or surrounding text
                has_comments = '#' in code or '//' in code or '/*' in code
                if not has_comments and len(code.strip().split('\n')) > 5:
                    result["recommendations"].append(f"Add comments to explain {language} code block")
                    result["score"] -= 2
            
            # Check for code without language specification
            unspecified_blocks = content.count('```\n') - content.count('```text\n')
            if unspecified_blocks > 0:
                result["warnings"].append(f"Code blocks without language specification: {unspecified_blocks}")
                result["score"] -= unspecified_blocks * 3
            
            # Ensure score is within bounds
            result["score"] = max(0, min(100, result["score"]))
            result["passed"] = result["score"] >= 75 and len(result["errors"]) == 0
            
        except Exception as e:
            result["errors"].append(f"Code validation failed: {str(e)}")
            result["score"] = 0
            result["passed"] = False
        
        return result
    
    def validate_metadata(self, file_path: Path) -> Dict[str, Any]:
        """
        Validate content metadata
        
        Args:
            file_path: Path to content file
            
        Returns:
            Metadata validation results
        """
        result = {
            "score": 100.0,
            "passed": True,
            "errors": [],
            "warnings": [],
            "recommendations": []
        }
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Check for frontmatter
            if not content.startswith('---'):
                result["errors"].append("Missing YAML frontmatter")
                result["score"] = 0
                result["passed"] = False
                return result
            
            # Parse frontmatter
            try:
                frontmatter_end = content.find('---', 3)
                if frontmatter_end > 0:
                    frontmatter = content[3:frontmatter_end].strip()
                    metadata = yaml.safe_load(frontmatter)
                else:
                    result["errors"].append("Invalid YAML frontmatter format")
                    result["score"] = 0
                    result["passed"] = False
                    return result
            except yaml.YAMLError as e:
                result["errors"].append(f"YAML parsing error: {str(e)}")
                result["score"] = 0
                result["passed"] = False
                return result
            
            # Check required fields
            required_fields = self.config.get("metadata", {}).get("required_fields", [])
            for field in required_fields:
                if field not in metadata or not metadata[field]:
                    result["errors"].append(f"Missing required metadata field: {field}")
                    result["score"] -= 20
            
            # Check field types and values
            if "platforms" in metadata:
                if not isinstance(metadata["platforms"], list):
                    result["warnings"].append("Platforms should be a list")
                    result["score"] -= 5
                elif not metadata["platforms"]:
                    result["warnings"].append("Empty platforms list")
                    result["score"] -= 5
            
            if "learning_objectives" in metadata:
                if not isinstance(metadata["learning_objectives"], list):
                    result["warnings"].append("Learning objectives should be a list")
                    result["score"] -= 5
                elif len(metadata["learning_objectives"]) == 0:
                    result["warnings"].append("No learning objectives specified")
                    result["score"] -= 10
            
            if "status" in metadata:
                valid_statuses = ["draft", "review", "approved", "published", "archived"]
                if metadata["status"] not in valid_statuses:
                    result["warnings"].append(f"Invalid status: {metadata['status']}")
                    result["score"] -= 5
            
            # Check date formats
            date_fields = ["created_date", "modified_date"]
            for field in date_fields:
                if field in metadata and metadata[field]:
                    try:
                        datetime.fromisoformat(metadata[field].replace('Z', '+00:00'))
                    except ValueError:
                        result["warnings"].append(f"Invalid date format in {field}")
                        result["score"] -= 3
            
            # Ensure score is within bounds
            result["score"] = max(0, min(100, result["score"]))
            result["passed"] = result["score"] >= 80 and len(result["errors"]) == 0
            
        except Exception as e:
            result["errors"].append(f"Metadata validation failed: {str(e)}")
            result["score"] = 0
            result["passed"] = False
        
        return result
    
    def get_validation_summary(self) -> Dict[str, Any]:
        """
        Get validation system summary
        
        Returns:
            Summary of validation system status
        """
        cache_entries = len(self.validation_cache)
        
        # Analyze cached results
        scores = []
        passed_count = 0
        error_count = 0
        
        for file_path, result in self.validation_cache.items():
            scores.append(result.get("overall_score", 0))
            if result.get("passed", False):
                passed_count += 1
            error_count += len(result.get("errors", []))
        
        summary = {
            "cache_entries": cache_entries,
            "average_score": sum(scores) / len(scores) if scores else 0,
            "passing_rate": (passed_count / cache_entries * 100) if cache_entries > 0 else 0,
            "total_errors": error_count,
            "validation_rules": {
                "structure_types": list(self.structure_rules.keys()),
                "quality_categories": list(self.quality_rules.keys()),
                "minimum_score": self.validation_config.get("minimum_score", 80)
            },
            "last_updated": datetime.now().isoformat()
        }
        
        return summary


def main():
    """Main function for CLI usage"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Validation Engine")
    parser.add_argument("--repo", default=".", help="Repository path")
    parser.add_argument("--command", required=True,
                       choices=["validate", "structure", "quality", "links", "code", "metadata", "summary"],
                       help="Command to execute")
    parser.add_argument("--file-path", help="Path to specific file")
    parser.add_argument("--content-type", default="chapter", help="Content type for validation")
    parser.add_argument("--output", help="Output file path")
    
    args = parser.parse_args()
    
    try:
        config = {
            "validation": {
                "minimum_score": 80.0,
                "check_links": True
            },
            "metadata": {
                "required_fields": ["title", "chapter_id", "author"]
            }
        }
        
        engine = ValidationEngine(Path(args.repo), config)
        
        if args.command == "validate":
            if not args.file_path:
                print("Error: file-path is required for validation")
                return
            
            result = engine.validate_content(Path(args.file_path))
            status = "✓" if result["passed"] else "✗"
            print(f"{status} {args.file_path}: {result['overall_score']:.1f}%")
            
            if result["errors"]:
                print("Errors:")
                for error in result["errors"]:
                    print(f"  - {error}")
            
            if result["warnings"]:
                print("Warnings:")
                for warning in result["warnings"]:
                    print(f"  - {warning}")
            
            if args.output:
                with open(args.output, 'w') as f:
                    json.dump(result, f, indent=2)
                print(f"Results saved to {args.output}")
        
        elif args.command in ["structure", "quality", "links", "code", "metadata"]:
            if not args.file_path:
                print(f"Error: file-path is required for {args.command} validation")
                return
            
            file_path = Path(args.file_path)
            
            if args.command == "structure":
                result = engine.validate_structure(file_path, args.content_type)
            elif args.command == "quality":
                result = engine.validate_quality(file_path, args.content_type)
            elif args.command == "links":
                result = engine.validate_links(file_path)
            elif args.command == "code":
                result = engine.validate_code(file_path)
            elif args.command == "metadata":
                result = engine.validate_metadata(file_path)
            
            status = "✓" if result["passed"] else "✗"
            print(f"{status} {args.command.title()} validation: {result['score']:.1f}%")
            
            if result["errors"]:
                print("Errors:")
                for error in result["errors"]:
                    print(f"  - {error}")
            
            if result["warnings"]:
                print("Warnings:")
                for warning in result["warnings"]:
                    print(f"  - {warning}")
        
        elif args.command == "summary":
            summary = engine.get_validation_summary()
            
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