# Getting Started with the Chapter Content Management System

## Overview

This tutorial will guide you through setting up and using the Chapter Content Management System (CMS) for creating, managing, and maintaining educational content for the Data Science Learning Handbook.

## Prerequisites

- Python 3.8 or higher
- Git repository access
- Basic understanding of Markdown and YAML

## Installation and Setup

### Step 1: Initialize the CMS

Navigate to your repository root and run:

```bash
cd /path/to/data-science-learning-handbook
python content-management/scripts/generate_content.py --init
```

This will:
- Create the CMS directory structure
- Generate base templates for chapters, sections, and exercises
- Create a sample configuration file
- Set up validation schemas

### Step 2: Verify Installation

Check that the CMS was initialized correctly:

```bash
# List available templates
python -m content-management.core.template_manager list

# Check CMS status
python -m content-management.core.cms_engine --command report
```

## Creating Your First Chapter

### Step 1: Generate Chapter Structure

```bash
python content-management/scripts/generate_content.py \
  --template chapter \
  --chapter-id "15-custom-chapter" \
  --title "Your Custom Chapter" \
  --author "Your Name" \
  --platforms python r \
  --difficulty intermediate
```

This creates:
- `chapters/15-custom-chapter/README.md` - Main chapter file
- Proper YAML frontmatter with metadata
- Standard chapter structure with all required sections

### Step 2: Customize Content

Edit the generated chapter file:

1. **Update Learning Objectives**: Replace placeholder objectives with specific, measurable goals
2. **Add Prerequisites**: List what readers should know before starting
3. **Fill Content Sections**: Add your educational content following the template structure
4. **Include Code Examples**: Add practical examples for each platform

### Step 3: Validate Content

```bash
# Validate your chapter
python content-management/scripts/validate_content.py --chapter "15-custom-chapter"

# Check for specific issues
python content-management/scripts/validate_content.py \
  --file chapters/15-custom-chapter/README.md \
  --check structure
```

## Git Workflow Integration

### Step 1: Create Content Branch

```bash
python -m content-management.core.workflow_manager \
  --command create-branch \
  --chapter-id "15-custom-chapter" \
  --branch-type feature
```

### Step 2: Commit Changes

```bash
python -m content-management.core.workflow_manager \
  --command commit \
  --message "Add custom chapter on advanced topics"
```

### Step 3: Generate Pull Request Information

```bash
python -m content-management.core.workflow_manager \
  --command pr-info \
  --source-branch "content/15-custom-chapter-feature-20250128-120000"
```

## Advanced Usage

### Batch Content Generation

Create multiple chapters at once using a configuration file:

```bash
# Create sample batch configuration
python content-management/scripts/generate_content.py \
  --create-sample-config batch_chapters.json

# Edit the configuration file to match your needs
# Then run batch generation:
python content-management/scripts/generate_content.py \
  --batch-generate batch_chapters.json
```

### Template Customization

To customize templates:

1. Copy base templates from `content-management/templates/`
2. Modify the template files as needed
3. Update the configuration to use your custom templates

### Automated Validation Pipeline

Set up automated validation for all content:

```bash
# Validate all content and generate report
python content-management/scripts/validate_content.py \
  --all \
  --output validation_report.json \
  --verbose

# Set up as a Git pre-commit hook
cp content-management/workflows/pre-commit-validation .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
```

## Configuration Options

### CMS Configuration

Edit `content-management/config.json`:

```json
{
  "templates": {
    "base_path": "content-management/templates",
    "supported_types": ["chapter", "section", "exercise", "platform"],
    "auto_sync": true
  },
  "validation": {
    "auto_validate": true,
    "minimum_score": 80.0,
    "check_links": true,
    "check_code": true
  },
  "workflow": {
    "auto_branch": true,
    "branch_prefix": "content/",
    "merge_strategy": "squash"
  }
}
```

### Metadata Requirements

Ensure all content includes required metadata:

```yaml
---
title: "Chapter Title"
chapter_id: "XX-chapter-id"
author: "Author Name"
platforms: ["python", "r"]
learning_objectives:
  - "Objective 1"
  - "Objective 2"
difficulty_level: "intermediate"
estimated_time: "2-3 hours"
tags: ["tag1", "tag2"]
---
```

## Best Practices

### Content Creation

1. **Follow Template Structure**: Use the provided templates as starting points
2. **Write Clear Objectives**: Make learning objectives specific and measurable
3. **Include Diverse Examples**: Provide examples for different skill levels
4. **Test Code Examples**: Ensure all code examples work correctly
5. **Cross-Reference Content**: Link to related chapters and external resources

### Quality Assurance

1. **Validate Early and Often**: Run validation checks during development
2. **Peer Review**: Have colleagues review content before publishing
3. **Test Learning Path**: Ensure chapters build logically on each other
4. **Update Dependencies**: Keep track of chapter dependencies

### Git Workflow

1. **Use Feature Branches**: Create separate branches for each chapter or major update
2. **Descriptive Commits**: Write clear commit messages describing changes
3. **Regular Validation**: Run validation before each commit
4. **Review Process**: Use pull requests for content review

## Troubleshooting

### Common Issues

**Template Not Found**
```bash
# Sync templates to latest version
python content-management/scripts/generate_content.py --sync-templates
```

**Validation Failures**
```bash
# Get detailed validation report
python content-management/scripts/validate_content.py \
  --file problematic_file.md \
  --verbose
```

**Git Workflow Issues**
```bash
# Check workflow status
python -m content-management.core.workflow_manager --command status

# Clean up old branches
python -m content-management.core.workflow_manager --command cleanup
```

**Metadata Errors**
- Ensure YAML frontmatter is properly formatted
- Check that all required fields are present
- Validate date formats (use ISO 8601)

### Getting Help

1. **Check Documentation**: Review README files in each module
2. **Run Help Commands**: Use `--help` flag with any script
3. **Examine Examples**: Look at sample chapters in `examples/`
4. **Validation Reports**: Use detailed validation output to identify issues

## Next Steps

Once you're comfortable with the basics:

1. **Explore Advanced Features**: Learn about batch operations and automation
2. **Customize Templates**: Create templates specific to your content needs
3. **Set Up CI/CD**: Integrate validation into your continuous integration pipeline
4. **Contribute Improvements**: Help improve the CMS by contributing enhancements

## Additional Resources

- [Template Guide](template_guide.md) - Detailed template customization
- [Validation Reference](validation_reference.md) - Complete validation rules
- [Workflow Integration](workflow_integration.md) - Advanced Git workflows
- [API Documentation](../api/) - Programmatic interface documentation