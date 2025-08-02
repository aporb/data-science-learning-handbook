#!/usr/bin/env python3
"""
Template Manager
===============

Manages standardized chapter templates for the Content Management System.
Provides template creation, generation, validation, and synchronization.

This module provides:
- Template creation and management
- Content generation from templates
- Template validation and compliance
- Multi-platform template support
- Template synchronization and updates

Author: Claude Code Implementation
Version: 1.0.0
"""

import os
import json
import logging
import shutil
from pathlib import Path
from typing import Dict, List, Optional, Any, Union
from datetime import datetime
from jinja2 import Environment, FileSystemLoader, Template, TemplateError
import yaml

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class TemplateManager:
    """
    Template Manager for CMS Templates
    
    Handles creation, validation, and generation of standardized templates
    for educational content including chapters, sections, exercises, and
    platform-specific content.
    """
    
    def __init__(self, cms_path: Path, config: Dict[str, Any]):
        """
        Initialize Template Manager
        
        Args:
            cms_path: Path to CMS directory
            config: CMS configuration dictionary
        """
        self.cms_path = Path(cms_path)
        self.config = config
        self.templates_path = self.cms_path / "templates"
        self.schemas_path = self.cms_path / "schemas"
        
        # Initialize Jinja2 environment
        self.jinja_env = Environment(
            loader=FileSystemLoader(str(self.templates_path)),
            autoescape=False,  # Allow HTML in templates
            trim_blocks=True,
            lstrip_blocks=True
        )
        
        # Add custom filters
        self._add_custom_filters()
        
        # Ensure template directories exist
        self._ensure_template_directories()
        
        logger.info(f"Template Manager initialized: {self.templates_path}")
    
    def _add_custom_filters(self):
        """Add custom Jinja2 filters for templates"""
        
        def format_date(date_string: str, format_string: str = "%Y-%m-%d") -> str:
            """Format date string"""
            if isinstance(date_string, str):
                try:
                    date_obj = datetime.fromisoformat(date_string.replace('Z', '+00:00'))
                    return date_obj.strftime(format_string)
                except ValueError:
                    return date_string
            return str(date_string)
        
        def join_platforms(platforms: List[str]) -> str:
            """Join platforms with proper formatting"""
            if not platforms:
                return "General"
            if len(platforms) == 1:
                return platforms[0].title()
            elif len(platforms) == 2:
                return f"{platforms[0].title()} and {platforms[1].title()}"
            else:
                return f"{', '.join(p.title() for p in platforms[:-1])}, and {platforms[-1].title()}"
        
        def generate_toc(sections: List[str]) -> str:
            """Generate table of contents from sections"""
            toc_lines = []
            for i, section in enumerate(sections, 1):
                # Convert section name to anchor
                anchor = section.lower().replace(' ', '-').replace('_', '-')
                toc_lines.append(f"{i}. [{section}](#{anchor})")
            return '\n'.join(toc_lines)
        
        def code_block(code: str, language: str = "python") -> str:
            """Format code block with syntax highlighting"""
            return f"```{language}\n{code}\n```"
        
        # Register filters
        self.jinja_env.filters['format_date'] = format_date
        self.jinja_env.filters['join_platforms'] = join_platforms
        self.jinja_env.filters['generate_toc'] = generate_toc
        self.jinja_env.filters['code_block'] = code_block
    
    def _ensure_template_directories(self):
        """Ensure all template directories exist"""
        template_dirs = [
            self.templates_path / "chapter",
            self.templates_path / "section", 
            self.templates_path / "exercise",
            self.templates_path / "platform",
            self.templates_path / "shared"
        ]
        
        for directory in template_dirs:
            directory.mkdir(parents=True, exist_ok=True)
    
    def create_base_templates(self) -> Dict[str, Any]:
        """
        Create base template files
        
        Returns:
            Creation results
        """
        logger.info("Creating base templates")
        
        result = {
            "success": True,
            "created_templates": [],
            "errors": []
        }
        
        try:
            # Create chapter template
            chapter_result = self._create_chapter_template()
            if chapter_result["success"]:
                result["created_templates"].extend(chapter_result["files"])
            else:
                result["errors"].extend(chapter_result["errors"])
            
            # Create section template
            section_result = self._create_section_template()
            if section_result["success"]:
                result["created_templates"].extend(section_result["files"])
            else:
                result["errors"].extend(section_result["errors"])
            
            # Create exercise template
            exercise_result = self._create_exercise_template()
            if exercise_result["success"]:
                result["created_templates"].extend(exercise_result["files"])
            else:
                result["errors"].extend(exercise_result["errors"])
            
            # Create platform templates
            platform_result = self._create_platform_templates()
            if platform_result["success"]:
                result["created_templates"].extend(platform_result["files"])
            else:
                result["errors"].extend(platform_result["errors"])
            
            result["success"] = len(result["errors"]) == 0
            
        except Exception as e:
            result["errors"].append(f"Failed to create base templates: {str(e)}")
            result["success"] = False
            logger.error(f"Base template creation failed: {e}")
        
        return result
    
    def _create_chapter_template(self) -> Dict[str, Any]:
        """Create chapter template"""
        chapter_template = """---
title: "{{ title }}"
chapter_id: "{{ chapter_id }}"
author: "{{ author }}"
created_date: "{{ generated_date | format_date }}"
modified_date: "{{ generated_date | format_date }}"
status: "draft"
content_type: "chapter"
platforms: {{ platforms | tojson }}
learning_objectives: {{ learning_objectives | tojson }}
prerequisites: {{ prerequisites | tojson }}
difficulty_level: "{{ difficulty_level }}"
estimated_time: "{{ estimated_time }}"
tags: {{ tags | tojson }}
dependencies: []
reviewers: []
validation_score: null
bias_score: null
---

# {{ title }}

## Chapter Overview

{{ title }} provides comprehensive coverage of {{ platforms | join_platforms }} for data science applications. This chapter is designed for {{ difficulty_level.lower() }} learners and should take approximately {{ estimated_time }} to complete.

### Learning Objectives

By the end of this chapter, you will be able to:

{% for objective in learning_objectives %}
- {{ objective }}
{% endfor %}

### Prerequisites

Before starting this chapter, you should have:

{% for prerequisite in prerequisites %}
- {{ prerequisite }}
{% endfor %}

### Chapter Structure

This chapter is organized into the following sections:

1. [Introduction](#introduction)
2. [Conceptual Foundation](#conceptual-foundation)
3. [Platform Implementation](#platform-implementation)
4. [Practical Examples](#practical-examples)
5. [Hands-on Exercises](#hands-on-exercises)
6. [Advanced Topics](#advanced-topics)
7. [Best Practices](#best-practices)
8. [Summary and Next Steps](#summary-and-next-steps)

---

## Introduction

<!-- Introduction content goes here -->

### What You'll Learn

This section provides an overview of the key concepts and skills covered in this chapter.

### Why This Matters

Explain the relevance and importance of the chapter content in the broader context of data science.

---

## Conceptual Foundation

<!-- Core concepts and theory -->

### Key Concepts

#### Concept 1

Description and explanation of the first key concept.

#### Concept 2

Description and explanation of the second key concept.

### Theoretical Background

Provide the theoretical foundation necessary for understanding the practical implementations.

---

## Platform Implementation

This section demonstrates how to implement the concepts across different platforms.

{% for platform in platforms %}
### {{ platform.title() }} Implementation

#### Setup and Environment

```{{ platform.lower() }}
# Platform-specific setup code
```

#### Core Implementation

```{{ platform.lower() }}
# Main implementation code for {{ platform }}
```

#### Platform-Specific Considerations

Key points and considerations specific to {{ platform }}.

{% endfor %}

---

## Practical Examples

### Example 1: Basic Implementation

```python
# Example code with detailed comments
def example_function():
    \"\"\"
    Example function demonstrating key concepts.
    \"\"\"
    pass
```

**Explanation:** Detailed explanation of the example.

### Example 2: Advanced Implementation

```python
# More complex example
class ExampleClass:
    \"\"\"
    Example class showing advanced concepts.
    \"\"\"
    pass
```

**Explanation:** Detailed explanation of the advanced example.

---

## Hands-on Exercises

### Exercise 1: Basic Practice

**Objective:** Apply basic concepts learned in this chapter.

**Instructions:**
1. Step 1 description
2. Step 2 description
3. Step 3 description

**Expected Output:**
Description of what the learner should achieve.

**Solution:**
```python
# Solution code here
```

### Exercise 2: Applied Challenge

**Objective:** Solve a realistic data science problem using chapter concepts.

**Instructions:**
1. Detailed step-by-step instructions
2. Include data sources and requirements
3. Specify deliverables

**Evaluation Criteria:**
- Criterion 1
- Criterion 2
- Criterion 3

---

## Advanced Topics

### Topic 1: Extended Concepts

For learners who want to dive deeper, explore these advanced concepts.

### Topic 2: Integration Patterns

How to integrate these concepts with other data science workflows.

### Topic 3: Performance Optimization

Best practices for optimizing performance in production environments.

---

## Best Practices

### Do's and Don'ts

#### Do's
- Best practice 1
- Best practice 2
- Best practice 3

#### Don'ts
- Common mistake 1
- Common mistake 2
- Common mistake 3

### Performance Considerations

Key performance considerations and optimization strategies.

### Security and Ethics

Important security and ethical considerations when applying these concepts.

---

## Summary and Next Steps

### Key Takeaways

- Summary point 1
- Summary point 2
- Summary point 3

### Further Reading

Recommended resources for continued learning:

- [Resource 1](url)
- [Resource 2](url)
- [Resource 3](url)

### Next Chapter Preview

Brief preview of the next chapter and how it builds on current concepts.

---

## Appendix

### Additional Resources

- Code repositories
- Datasets
- Tools and libraries

### Troubleshooting

Common issues and solutions.

### Glossary

Key terms and definitions used in this chapter."""

        try:
            template_path = self.templates_path / "chapter" / "base_chapter.md"
            with open(template_path, 'w', encoding='utf-8') as f:
                f.write(chapter_template)
            
            return {
                "success": True,
                "files": [template_path],
                "errors": []
            }
        except Exception as e:
            return {
                "success": False,
                "files": [],
                "errors": [f"Failed to create chapter template: {str(e)}"]
            }
    
    def _create_section_template(self) -> Dict[str, Any]:
        """Create section template"""
        section_template = """---
title: "{{ section_title }}"
chapter_id: "{{ chapter_id }}"
section_id: "{{ section_id }}"
section_type: "{{ section_type }}"
author: "{{ author }}"
created_date: "{{ generated_date | format_date }}"
platforms: {{ platforms | tojson }}
learning_objectives: {{ learning_objectives | tojson }}
estimated_time: "{{ estimated_time }}"
---

## {{ section_title }}

### Overview

Brief overview of what this section covers and its role in the chapter.

### Learning Objectives

{% for objective in learning_objectives %}
- {{ objective }}
{% endfor %}

### Content

<!-- Section content goes here -->

{% if section_type == "conceptual" %}
#### Key Concepts

Explanation of key concepts.

#### Theoretical Background

Supporting theory and background information.

{% elif section_type == "practical" %}
#### Implementation Steps

1. Step 1
2. Step 2
3. Step 3

#### Code Examples

```python
# Example code
```

{% elif section_type == "exercise" %}
#### Exercise Instructions

Detailed instructions for the exercise.

#### Expected Outcome

What learners should achieve.

#### Solution

```python
# Solution code
```

{% endif %}

### Summary

Key points covered in this section.

### Next Steps

Connection to the next section or chapter."""

        try:
            template_path = self.templates_path / "section" / "base_section.md"
            with open(template_path, 'w', encoding='utf-8') as f:
                f.write(section_template)
            
            return {
                "success": True,
                "files": [template_path],
                "errors": []
            }
        except Exception as e:
            return {
                "success": False,
                "files": [],
                "errors": [f"Failed to create section template: {str(e)}"]
            }
    
    def _create_exercise_template(self) -> Dict[str, Any]:
        """Create exercise template"""
        exercise_template = """---
title: "{{ exercise_title }}"
chapter_id: "{{ chapter_id }}"
exercise_id: "{{ exercise_id }}"
exercise_type: "{{ exercise_type }}"
difficulty_level: "{{ difficulty_level }}"
estimated_time: "{{ estimated_time }}"
platforms: {{ platforms | tojson }}
learning_objectives: {{ learning_objectives | tojson }}
prerequisites: {{ prerequisites | tojson }}
datasets: {{ datasets | tojson if datasets else [] }}
tools_required: {{ tools_required | tojson if tools_required else [] }}
---

# Exercise: {{ exercise_title }}

## Objective

{{ objective | default("Apply the concepts learned in this chapter to solve a practical problem.") }}

## Background

{{ background | default("This exercise reinforces the key concepts through hands-on practice.") }}

## Prerequisites

Before starting this exercise, ensure you have:

{% for prerequisite in prerequisites %}
- {{ prerequisite }}
{% endfor %}

## Required Tools and Libraries

{% for tool in tools_required %}
- {{ tool }}
{% endfor %}

## Dataset Information

{% if datasets %}
{% for dataset in datasets %}
### {{ dataset.name }}
- **Source:** {{ dataset.source }}
- **Description:** {{ dataset.description }}
- **Format:** {{ dataset.format }}
- **Size:** {{ dataset.size }}
{% endfor %}
{% else %}
No external datasets required for this exercise.
{% endif %}

## Instructions

### Part 1: Setup

1. Set up your environment
2. Import required libraries
3. Load necessary data

{% for platform in platforms %}
#### {{ platform.title() }} Setup

```{{ platform.lower() }}
# {{ platform }} specific setup code
```
{% endfor %}

### Part 2: Core Exercise

{% if exercise_type == "coding" %}
#### Task 1: Implementation

Implement the following functionality:

```python
# Your code here
```

#### Task 2: Analysis

Analyze your results and answer the following questions:

1. Question 1
2. Question 2
3. Question 3

{% elif exercise_type == "analysis" %}
#### Data Exploration

1. Load and examine the dataset
2. Identify key patterns and insights
3. Document your findings

#### Analysis Tasks

1. Task 1 description
2. Task 2 description
3. Task 3 description

{% elif exercise_type == "project" %}
#### Project Requirements

Create a complete solution that includes:

1. Data preprocessing and cleaning
2. Analysis and modeling
3. Visualization and reporting
4. Documentation

#### Deliverables

- [ ] Cleaned dataset
- [ ] Analysis code
- [ ] Visualizations
- [ ] Written report
- [ ] Presentation (optional)

{% endif %}

### Part 3: Extension (Optional)

For additional challenge, try these extension tasks:

1. Extension task 1
2. Extension task 2
3. Extension task 3

## Expected Output

Describe what a successful completion should look like:

- Output format
- Key insights or results
- Performance metrics (if applicable)

## Evaluation Criteria

Your work will be evaluated based on:

- **Correctness** (40%): Does the solution work as intended?
- **Code Quality** (30%): Is the code well-structured and documented?
- **Analysis** (20%): Are insights meaningful and well-supported?
- **Presentation** (10%): Is the work clearly communicated?

## Solution

<details>
<summary>Click to reveal solution</summary>

### Complete Solution

```python
# Complete solution code with comments
```

### Explanation

Detailed explanation of the solution approach and key decisions.

### Alternative Approaches

Discussion of alternative solutions and their trade-offs.

</details>

## Common Pitfalls

Watch out for these common mistakes:

1. Pitfall 1 and how to avoid it
2. Pitfall 2 and how to avoid it
3. Pitfall 3 and how to avoid it

## Further Exploration

To deepen your understanding:

- Try the extension tasks
- Explore the additional resources
- Apply these concepts to your own data

### Additional Resources

- [Resource 1](url)
- [Resource 2](url)
- [Resource 3](url)"""

        try:
            template_path = self.templates_path / "exercise" / "base_exercise.md"
            with open(template_path, 'w', encoding='utf-8') as f:
                f.write(exercise_template)
            
            return {
                "success": True,
                "files": [template_path],
                "errors": []
            }
        except Exception as e:
            return {
                "success": False,
                "files": [],
                "errors": [f"Failed to create exercise template: {str(e)}"]
            }
    
    def _create_platform_templates(self) -> Dict[str, Any]:
        """Create platform-specific templates"""
        platforms = ["python", "r", "sql", "scala", "julia"]
        created_files = []
        errors = []
        
        for platform in platforms:
            try:
                platform_template = f"""---
platform: "{platform}"
template_type: "platform_implementation"
version: "1.0.0"
---

# {platform.title()} Implementation Guide

## Environment Setup

### Required Packages

```{platform.lower()}
# {platform.title()}-specific package installations
```

### Configuration

```{platform.lower()}
# Environment configuration
```

## Core Implementation

### Basic Template

```{platform.lower()}
# Basic implementation template for {platform}
```

### Advanced Template

```{platform.lower()}
# Advanced implementation template for {platform}
```

## Best Practices

### Code Style

- {platform.title()}-specific style guidelines
- Naming conventions
- Documentation standards

### Performance

- Performance optimization techniques
- Memory management
- Parallel processing considerations

## Common Patterns

### Data Loading

```{platform.lower()}
# Standard data loading patterns
```

### Data Processing

```{platform.lower()}
# Common data processing operations
```

### Visualization

```{platform.lower()}
# Visualization code patterns
```

## Integration

### With Other Platforms

How to integrate {platform} code with other platforms.

### Deployment Considerations

Best practices for deploying {platform} solutions.

## Troubleshooting

Common issues and solutions for {platform} implementations."""

                template_path = self.templates_path / "platform" / f"{platform}_template.md"
                with open(template_path, 'w', encoding='utf-8') as f:
                    f.write(platform_template)
                
                created_files.append(template_path)
                
            except Exception as e:
                errors.append(f"Failed to create {platform} template: {str(e)}")
        
        return {
            "success": len(errors) == 0,
            "files": created_files,
            "errors": errors
        }
    
    def generate_from_template(self, 
                             template_type: str, 
                             context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate content from template
        
        Args:
            template_type: Type of template to use
            context: Template context variables
            
        Returns:
            Generation results with created files
        """
        logger.info(f"Generating content from {template_type} template")
        
        result = {
            "success": False,
            "files": [],
            "errors": [],
            "context_used": context
        }
        
        try:
            # Determine template file
            template_map = {
                "chapter": "chapter/base_chapter.md",
                "section": "section/base_section.md", 
                "exercise": "exercise/base_exercise.md"
            }
            
            if template_type not in template_map:
                result["errors"].append(f"Unknown template type: {template_type}")
                return result
            
            template_file = template_map[template_type]
            
            # Check if template exists
            template_path = self.templates_path / template_file
            if not template_path.exists():
                # Create base templates if they don't exist
                self.create_base_templates()
            
            # Load and render template
            template = self.jinja_env.get_template(template_file)
            rendered_content = template.render(**context)
            
            # Determine output path
            if template_type == "chapter":
                output_dir = Path(self.config.get("content", {}).get("chapters_path", "chapters"))
                output_dir = self.cms_path.parent / output_dir / context.get("chapter_id", "unknown")
                output_file = output_dir / "README.md"
            elif template_type == "section":
                chapter_id = context.get("chapter_id", "unknown")
                section_id = context.get("section_id", "section")
                output_dir = Path(self.config.get("content", {}).get("chapters_path", "chapters"))
                output_dir = self.cms_path.parent / output_dir / chapter_id
                output_file = output_dir / f"{section_id}.md"
            elif template_type == "exercise":
                chapter_id = context.get("chapter_id", "unknown")
                exercise_id = context.get("exercise_id", "exercise")
                output_dir = Path(self.config.get("content", {}).get("chapters_path", "chapters"))
                output_dir = self.cms_path.parent / output_dir / chapter_id / "exercises"
                output_file = output_dir / f"{exercise_id}.md"
            else:
                output_file = self.cms_path.parent / f"generated_{template_type}.md"
            
            # Create output directory
            output_file.parent.mkdir(parents=True, exist_ok=True)
            
            # Write generated content
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(rendered_content)
            
            result["files"].append(output_file)
            result["success"] = True
            
            logger.info(f"Generated content: {output_file}")
            
        except TemplateError as e:
            result["errors"].append(f"Template error: {str(e)}")
            logger.error(f"Template generation failed: {e}")
        except Exception as e:
            result["errors"].append(f"Generation failed: {str(e)}")
            logger.error(f"Content generation failed: {e}")
        
        return result
    
    def validate_template(self, template_path: Path) -> Dict[str, Any]:
        """
        Validate template structure and syntax
        
        Args:
            template_path: Path to template file
            
        Returns:
            Validation results
        """
        validation_result = {
            "valid": True,
            "errors": [],
            "warnings": [],
            "template_path": str(template_path)
        }
        
        try:
            if not template_path.exists():
                validation_result["errors"].append("Template file does not exist")
                validation_result["valid"] = False
                return validation_result
            
            # Load template content
            with open(template_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Check for YAML frontmatter
            if not content.startswith('---'):
                validation_result["warnings"].append("Template missing YAML frontmatter")
            
            # Try to parse as Jinja2 template
            try:
                template = Template(content)
                # Basic syntax validation
                template.render()
            except TemplateError as e:
                validation_result["errors"].append(f"Template syntax error: {str(e)}")
                validation_result["valid"] = False
            
            # Check for required sections (template-specific)
            template_name = template_path.name
            if "chapter" in template_name:
                required_sections = ["# ", "## Learning Objectives", "## Summary"]
                for section in required_sections:
                    if section not in content:
                        validation_result["warnings"].append(f"Missing recommended section: {section}")
            
        except Exception as e:
            validation_result["errors"].append(f"Validation failed: {str(e)}")
            validation_result["valid"] = False
        
        return validation_result
    
    def sync_templates(self, template_type: Optional[str] = None) -> Dict[str, Any]:
        """
        Synchronize templates with latest versions
        
        Args:
            template_type: Specific template type to sync (None for all)
            
        Returns:
            Synchronization results
        """
        logger.info(f"Synchronizing templates: {template_type or 'all'}")
        
        result = {
            "success": True,
            "updated": [],
            "errors": [],
            "warnings": []
        }
        
        try:
            # For now, this recreates base templates
            # In a real implementation, this would sync from a template repository
            
            if template_type is None or template_type == "chapter":
                chapter_result = self._create_chapter_template()
                if chapter_result["success"]:
                    result["updated"].extend([str(f) for f in chapter_result["files"]])
                else:
                    result["errors"].extend(chapter_result["errors"])
            
            if template_type is None or template_type == "section":
                section_result = self._create_section_template()
                if section_result["success"]:
                    result["updated"].extend([str(f) for f in section_result["files"]])
                else:
                    result["errors"].extend(section_result["errors"])
            
            if template_type is None or template_type == "exercise":
                exercise_result = self._create_exercise_template()
                if exercise_result["success"]:
                    result["updated"].extend([str(f) for f in exercise_result["files"]])
                else:
                    result["errors"].extend(exercise_result["errors"])
            
            if template_type is None or template_type == "platform":
                platform_result = self._create_platform_templates()
                if platform_result["success"]:
                    result["updated"].extend([str(f) for f in platform_result["files"]])
                else:
                    result["errors"].extend(platform_result["errors"])
            
            result["success"] = len(result["errors"]) == 0
            
        except Exception as e:
            result["errors"].append(f"Template sync failed: {str(e)}")
            result["success"] = False
            logger.error(f"Template synchronization failed: {e}")
        
        return result
    
    def list_templates(self) -> Dict[str, List[str]]:
        """
        List available templates by category
        
        Returns:
            Dictionary of template categories and files
        """
        templates = {
            "chapter": [],
            "section": [],
            "exercise": [], 
            "platform": [],
            "shared": []
        }
        
        for category in templates.keys():
            category_path = self.templates_path / category
            if category_path.exists():
                for template_file in category_path.glob("*.md"):
                    templates[category].append(template_file.name)
        
        return templates
    
    def get_template_summary(self) -> Dict[str, Any]:
        """
        Get summary of template system
        
        Returns:
            Template system summary
        """
        templates = self.list_templates()
        
        summary = {
            "total_templates": sum(len(files) for files in templates.values()),
            "by_category": {cat: len(files) for cat, files in templates.items()},
            "template_path": str(self.templates_path),
            "jinja_version": "2.11+",
            "custom_filters": len(self.jinja_env.filters) - len(Environment().filters)
        }
        
        return summary


def main():
    """Main function for CLI usage"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Template Manager")
    parser.add_argument("--cms-path", default="content-management", help="CMS directory path")
    parser.add_argument("--command", required=True,
                       choices=["create", "generate", "validate", "sync", "list"],
                       help="Command to execute")
    parser.add_argument("--template-type", help="Template type")
    parser.add_argument("--context-file", help="JSON file with template context")
    parser.add_argument("--template-path", help="Path to specific template")
    
    args = parser.parse_args()
    
    try:
        # Basic config for CLI usage
        config = {
            "content": {
                "chapters_path": "chapters"
            }
        }
        
        manager = TemplateManager(Path(args.cms_path), config)
        
        if args.command == "create":
            result = manager.create_base_templates()
            print(f"Template creation {'successful' if result['success'] else 'failed'}")
            if result["created_templates"]:
                print(f"Created templates: {len(result['created_templates'])}")
                for template in result["created_templates"]:
                    print(f"  - {template}")
            if result["errors"]:
                print("Errors:")
                for error in result["errors"]:
                    print(f"  - {error}")
        
        elif args.command == "generate":
            if not args.template_type or not args.context_file:
                print("Error: template-type and context-file are required for generation")
                return
            
            with open(args.context_file, 'r') as f:
                context = json.load(f)
            
            result = manager.generate_from_template(args.template_type, context)
            print(f"Generation {'successful' if result['success'] else 'failed'}")
            if result["files"]:
                print(f"Generated files: {len(result['files'])}")
                for file_path in result["files"]:
                    print(f"  - {file_path}")
            if result["errors"]:
                print("Errors:")
                for error in result["errors"]:
                    print(f"  - {error}")
        
        elif args.command == "validate":
            if not args.template_path:
                print("Error: template-path is required for validation")
                return
            
            result = manager.validate_template(Path(args.template_path))
            status = "✓" if result["valid"] else "✗"
            print(f"{status} {args.template_path}")
            
            if result["errors"]:
                print("Errors:")
                for error in result["errors"]:
                    print(f"  - {error}")
            
            if result["warnings"]:
                print("Warnings:")
                for warning in result["warnings"]:
                    print(f"  - {warning}")
        
        elif args.command == "sync":
            result = manager.sync_templates(args.template_type)
            print(f"Template sync {'successful' if result['success'] else 'failed'}")
            if result["updated"]:
                print(f"Updated templates: {len(result['updated'])}")
                for template in result["updated"]:
                    print(f"  - {template}")
        
        elif args.command == "list":
            templates = manager.list_templates()
            print("Available templates:")
            for category, files in templates.items():
                if files:
                    print(f"  {category.title()}:")
                    for file_name in files:
                        print(f"    - {file_name}")
    
    except Exception as e:
        logger.error(f"Command failed: {e}")
        print(f"Error: {e}")
        return 1


if __name__ == "__main__":
    exit(main())