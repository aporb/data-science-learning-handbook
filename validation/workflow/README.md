# Content Review Workflow and Version Control System

A comprehensive workflow management system for the Data Science Learning Handbook that provides multi-stage content review, Git-based version control, automated notifications, and content migration capabilities.

## Overview

This system implements a complete content management workflow with the following key components:

1. **Multi-Stage Review Workflow** - Orchestrates content through technical, educational, bias, and security reviews
2. **Git-Based Branching Strategy** - Manages content versions with specialized branching for each review stage  
3. **Automated Notification System** - Sends notifications via email, Slack, and webhooks
4. **Content Migration Tools** - Handles format updates and content transformations
5. **Integration Layer** - Coordinates all components for seamless workflow execution

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    Integration Manager                          │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │              Workflow Orchestrator                      │    │
│  │  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐      │    │
│  │  │Technical│ │Education│ │  Bias   │ │Security │      │    │
│  │  │ Review  │ │ Review  │ │Assessmt │ │ Review  │      │    │
│  │  └─────────┘ └─────────┘ └─────────┘ └─────────┘      │    │
│  └─────────────────────────────────────────────────────────┘    │
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │              Branching Strategy                         │    │
│  │  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐      │    │
│  │  │ Content │ │ Review  │ │  Bias   │ │  Final  │      │    │
│  │  │  Draft  │ │ Branch  │ │ Branch  │ │Approval │      │    │
│  │  └─────────┘ └─────────┘ └─────────┘ └─────────┘      │    │
│  └─────────────────────────────────────────────────────────┘    │
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │            Notification System                          │    │
│  │  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐      │    │
│  │  │  Email  │ │  Slack  │ │Webhooks │ │ In-App  │      │    │
│  │  └─────────┘ └─────────┘ └─────────┘ └─────────┘      │    │
│  └─────────────────────────────────────────────────────────┘    │
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │             Migration Tools                             │    │
│  │  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐      │    │
│  │  │Template │ │Metadata │ │  Link   │ │ Format  │      │    │
│  │  │Updates  │ │Updates  │ │Updates  │ │Conversion│      │    │
│  │  └─────────┘ └─────────┘ └─────────┘ └─────────┘      │    │
│  └─────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────┘
```

## Components

### 1. Review Workflow (`review_workflow.py`)

**Purpose**: Orchestrates multi-stage content review process with role-based assignments and quality gates.

**Key Features**:
- Multi-stage workflow progression (Draft → Technical → Educational → Bias → Security → Final → Published)
- Automated reviewer assignment based on expertise and workload
- Quality gate enforcement with configurable thresholds
- Escalation handling for overdue assignments
- Comprehensive audit logging

**Configuration**: `workflow_config.yml`

**Usage Example**:
```python
from review_workflow import WorkflowOrchestrator

orchestrator = WorkflowOrchestrator("workflow_config.yml")

# Create new workflow
workflow_id = orchestrator.create_workflow(
    content_id="chapter-01",
    content_path="chapters/01-introduction/README.md", 
    author="john.doe"
)

# Start technical review stage
orchestrator.start_review_stage(workflow_id, WorkflowStage.TECHNICAL_REVIEW)
```

### 2. Branching Strategy (`branching_strategy.py`)

**Purpose**: Manages Git-based version control with content-optimized branching strategies.

**Key Features**:
- Specialized branch types for each review stage
- Automated branch creation, merging, and cleanup
- Content versioning with change tracking
- Merge conflict detection and resolution
- Branch lifecycle management with configurable retention

**Configuration**: `branching_config.yml`

**Usage Example**:
```python
from branching_strategy import ContentBranchingStrategy

branching = ContentBranchingStrategy(".", "branching_config.yml")

# Create content branch
branch_name = branching.create_content_branch(
    BranchType.TECHNICAL_REVIEW,
    content_id="chapter-01",
    author="john.doe"
)

# Commit changes
commit_hash = branching.commit_changes(
    branch_name, 
    "Updated technical content based on review feedback"
)
```

### 3. Notification System (`notification_system.py`)

**Purpose**: Manages automated stakeholder communications across multiple channels.

**Key Features**:
- Multi-channel delivery (Email, Slack, Webhooks, Teams)
- Template-based message generation with personalization
- Delivery tracking and retry mechanisms
- Role-based notification preferences
- Deadline reminders and escalation notifications

**Configuration**: `notification_config.yml`

**Usage Example**:
```python
from notification_system import NotificationSystem

notifications = NotificationSystem("notification_config.yml")

# Send assignment notification
message_ids = notifications.create_notification(
    trigger=NotificationTrigger.ASSIGNMENT_CREATED,
    recipients=["reviewer@example.com"],
    context={
        "content_title": "Introduction to Data Science",
        "reviewer_name": "Jane Smith",
        "due_date": "2024-08-15"
    }
)
```

### 4. Migration Tools (`migration_tools.py`)

**Purpose**: Handles content format updates and batch transformations.

**Key Features**:
- Rule-based content transformation
- Batch processing with progress tracking
- Backup and rollback capabilities
- Validation and quality assurance
- Support for Markdown, Notebook, and YAML formats

**Configuration**: `migration_config.yml`

**Usage Example**:
```python
from migration_tools import ContentMigrator

migrator = ContentMigrator(".", "migration_config.yml")

# Create migration plan
plan = migrator.create_migration_plan(
    plan_id="frontmatter_update",
    name="Update Chapter Frontmatter",
    description="Update all chapter frontmatter to v2.0 schema",
    rule_ids=["frontmatter_update_v2"],
    file_patterns=["chapters/**/*.md"]
)

# Execute migration
history = migrator.execute_migration_plan(plan)
```

### 5. Integration Layer (`workflow_integration.py`)

**Purpose**: Coordinates all workflow components for seamless end-to-end automation.

**Key Features**:
- Unified workflow management API
- Component orchestration and synchronization
- Status monitoring and health checks
- Error handling and recovery
- Comprehensive reporting

**Configuration**: `integration_config.yml`

**Usage Example**:
```python
from workflow_integration import WorkflowIntegrationManager

integration = WorkflowIntegrationManager(".")

# Start complete workflow
workflow_id = integration.start_content_workflow(
    content_id="chapter-01",
    content_path="chapters/01-introduction/README.md",
    author="john.doe"
)

# Advance to next stage
integration.advance_workflow_stage("chapter-01", "technical_review")
```

## Configuration

The system uses YAML configuration files for each component:

### Core Configuration Files

- **`workflow_config.yml`** - Review workflow settings, stages, and quality gates
- **`branching_config.yml`** - Git branching strategy and branch lifecycle rules
- **`notification_config.yml`** - Notification channels, templates, and delivery settings
- **`migration_config.yml`** - Content migration rules and transformation settings
- **`integration_config.yml`** - Integration layer coordination and automation rules

### Configuration Management

All configuration files support:
- Environment variable substitution
- Hierarchical configuration merging
- Runtime configuration updates
- Validation and schema checking

## Setup and Installation

### Prerequisites

- Python 3.8+
- Git repository with proper permissions
- SMTP server for email notifications (optional)
- Slack/Teams webhooks (optional)

### Installation Steps

1. **Install dependencies**:
```bash
pip install -r requirements.txt
```

2. **Initialize workflow directories**:
```bash
mkdir -p validation/workflow/{data,backups,history,templates}
```

3. **Configure components**:
```bash
# Copy and customize configuration files
cp validation/workflow/workflow_config.yml.example validation/workflow/workflow_config.yml
cp validation/workflow/notification_config.yml.example validation/workflow/notification_config.yml
# Edit configurations as needed
```

4. **Set up reviewers**:
```bash
# Add reviewers to the system
python -m validation.workflow.review_workflow --command add-reviewer \
    --user-id john.smith \
    --name "John Smith" \
    --email john.smith@example.com \
    --roles technical_reviewer
```

5. **Start notification scheduler**:
```bash
python -m validation.workflow.notification_system --command start-scheduler \
    --config validation/workflow/notification_config.yml
```

## Usage Workflows

### Basic Content Review Workflow

1. **Create content**:
```bash
# Author creates new content
touch chapters/01-introduction/new-section.md
```

2. **Start workflow**:
```python
integration = WorkflowIntegrationManager(".")
workflow_id = integration.start_content_workflow(
    content_id="new-section",
    content_path="chapters/01-introduction/new-section.md",
    author="author@example.com"
)
```

3. **Automated process**:
   - System creates draft branch
   - Sends notification to author
   - Waits for content completion

4. **Submit for review**:
```python
integration.advance_workflow_stage("new-section", "technical_review")
```

5. **Review process**:
   - System creates review branch
   - Assigns technical reviewer
   - Sends assignment notification
   - Reviewer provides feedback
   - Process continues through all stages

6. **Publication**:
   - Final approval stage
   - Content merged to main branch
   - Publication notification sent
   - Workflow archived

### Content Migration Workflow

1. **Create migration plan**:
```python
migrator = ContentMigrator(".")
plan = migrator.create_migration_plan(
    plan_id="modernization-2024",
    name="Content Modernization",
    description="Update all content to latest standards",
    rule_ids=["frontmatter_update", "link_format_update"],
    file_patterns=["chapters/**/*.md"],
    dry_run=True  # Test first
)
```

2. **Execute dry run**:
```python
history = migrator.execute_migration_plan(plan)
print(f"Migration would affect {history.total_files} files")
```

3. **Execute actual migration**:
```python
plan.dry_run = False
history = migrator.execute_migration_plan(plan)
```

4. **Monitor and validate**:
```python
report = migrator.generate_migration_report(history.migration_id)
```

### Branch Management Workflow

1. **Create feature branch**:
```python
branching = ContentBranchingStrategy(".")
branch_name = branching.create_content_branch(
    BranchType.CONTENT_DRAFT,
    content_id="new-feature",
    author="developer@example.com"
)
```

2. **Work on content**:
```python
# Make changes, then commit
commit_hash = branching.commit_changes(
    branch_name,
    "Added new examples and exercises"
)
```

3. **Create review branch**:
```python
review_branch = branching.create_content_branch(
    BranchType.TECHNICAL_REVIEW,
    content_id="new-feature",
    author="developer@example.com",
    base_branch=branch_name
)
```

4. **Merge after approval**:
```python
success = branching.merge_branch(
    source_branch=review_branch,
    target_branch="main",
    merge_strategy=MergeStrategy.SQUASH_MERGE
)
```

## Monitoring and Maintenance

### System Monitoring

The integration manager provides comprehensive monitoring:

```python
# Get system status
status = integration.get_system_status()
print(f"Active workflows: {status['metrics']['active_workflows']}")
print(f"System uptime: {status['metrics']['uptime_hours']} hours")

# Generate integration report
report = integration.generate_integration_report()
```

### Health Checks

Regular health checks ensure system reliability:

```python
# Component health check
health = {
    "workflow_orchestrator": orchestrator.health_check(),
    "branching_strategy": branching.health_check(), 
    "notification_system": notifications.health_check(),
    "migrator": migrator.health_check()
}
```

### Cleanup and Maintenance

Automated cleanup routines maintain system performance:

```python
# Cleanup old branches
cleanup_report = branching.cleanup_branches(dry_run=False)

# Cleanup old backups  
migrator.cleanup_old_backups()

# Archive completed workflows
integration.archive_completed_workflows()
```

## Quality Gates and Scoring

The system enforces quality through configurable gates:

### Quality Gate Types

1. **Technical Accuracy Gate** (80% threshold)
   - Code correctness and implementation feasibility
   - Platform compatibility verification
   - Technical review approval required

2. **Educational Effectiveness Gate** (75% threshold)
   - Learning objectives alignment
   - Content structure and flow
   - Accessibility compliance

3. **Bias Assessment Gate** (70% threshold)
   - Methodology neutrality
   - Platform-agnostic presentation
   - Inclusive examples and language

4. **Security Compliance Gate** (85% threshold)
   - DoD/government compliance
   - Data protection measures
   - Vulnerability assessment

5. **Overall Quality Gate** (80% threshold)
   - Combined scoring across all dimensions
   - Publication readiness assessment
   - Final approval sign-off

### Scoring Calculation

The system calculates composite scores using weighted criteria:

```
Overall Score = (Technical × 0.30) + (Educational × 0.25) + 
                (Bias × 0.20) + (Security × 0.15) + 
                (Implementation × 0.10)
```

## Error Handling and Recovery

### Error Categories

1. **Workflow Errors**
   - Assignment failures
   - Review submission issues
   - Stage progression problems

2. **Git Operations Errors**
   - Branch creation failures
   - Merge conflicts
   - Repository access issues

3. **Notification Errors**
   - Delivery failures
   - Template rendering issues
   - Channel connectivity problems

4. **Migration Errors**
   - Transformation failures
   - Validation errors
   - Backup/rollback issues

### Recovery Strategies

The system implements several recovery mechanisms:

- **Automatic Retry** - Failed operations are retried with exponential backoff
- **Graceful Degradation** - System continues operating with reduced functionality
- **Manual Intervention** - Administrative tools for manual recovery
- **Rollback Capabilities** - Automatic rollback for failed migrations
- **Circuit Breakers** - Prevent cascade failures in distributed components

## API Reference

### Integration Manager API

```python
class WorkflowIntegrationManager:
    def start_content_workflow(content_id, content_path, author) -> str
    def advance_workflow_stage(content_id, target_stage) -> bool
    def submit_review(content_id, assignment_id, action, score, comments) -> bool
    def complete_workflow(content_id) -> bool
    def get_system_status() -> Dict[str, Any]
    def generate_integration_report() -> Dict[str, Any]
```

### Workflow Orchestrator API

```python
class WorkflowOrchestrator:
    def create_workflow(content_id, content_path, author) -> str
    def start_review_stage(instance_id, stage) -> bool
    def submit_review(assignment_id, action, score, comments) -> bool
    def get_workflow_status(instance_id) -> Dict[str, Any]
    def list_active_workflows() -> List[Dict[str, Any]]
```

### Branching Strategy API

```python
class ContentBranchingStrategy:
    def create_content_branch(branch_type, content_id, author) -> str
    def switch_branch(branch_name) -> bool
    def commit_changes(branch_name, message) -> str
    def merge_branch(source_branch, target_branch) -> bool
    def list_branches() -> List[BranchMetadata]
```

### Notification System API

```python
class NotificationSystem:
    def create_notification(trigger, recipients, context) -> List[str]
    def get_message_status(message_id) -> Dict[str, Any]
    def add_recipient(user_id, name, email) -> bool
    def generate_delivery_report() -> DeliveryReport
```

### Migration Tools API

```python
class ContentMigrator:
    def create_migration_plan(plan_id, name, description, rule_ids, file_patterns) -> MigrationPlan
    def execute_migration_plan(plan) -> MigrationHistory
    def rollback_migration(migration_id) -> bool
    def generate_migration_report() -> Dict[str, Any]
```

## Best Practices

### Content Development

1. **Use descriptive branch names** - Include content ID and purpose
2. **Write clear commit messages** - Explain what changed and why
3. **Update metadata consistently** - Keep frontmatter current
4. **Test changes locally** - Validate content before submission
5. **Follow review feedback** - Address reviewer comments promptly

### Review Process

1. **Assign appropriate reviewers** - Match expertise to content
2. **Provide constructive feedback** - Be specific and actionable
3. **Use scoring guidelines** - Follow established criteria
4. **Document decisions** - Explain rationale for major changes
5. **Respect deadlines** - Complete reviews within assigned timeframes

### System Administration

1. **Monitor system health** - Regular status checks and reporting
2. **Maintain configurations** - Keep settings current and documented
3. **Backup data regularly** - Protect against data loss
4. **Update dependencies** - Keep libraries and tools current
5. **Train users properly** - Ensure team understands workflows

### Migration Management

1. **Test migrations thoroughly** - Always dry-run first
2. **Backup before migration** - Enable rollback capabilities
3. **Validate results** - Check content integrity after migration
4. **Document changes** - Maintain migration history and rationale
5. **Plan migration windows** - Minimize disruption to ongoing work

## Troubleshooting

### Common Issues

1. **Workflow stuck in stage**
   - Check reviewer assignments
   - Verify quality gate status
   - Look for blocking conditions

2. **Branch merge conflicts**
   - Use conflict resolution tools
   - Communicate with other authors
   - Consider rebasing strategy

3. **Notifications not delivered**
   - Verify channel configurations
   - Check recipient settings
   - Review message queue status

4. **Migration failures**
   - Check file permissions
   - Verify transformation rules
   - Review validation errors

### Diagnostic Commands

```bash
# Check system status
python -m validation.workflow.workflow_integration --command status

# View active workflows
python -m validation.workflow.review_workflow --command list

# Check notification queue
python -m validation.workflow.notification_system --command queue-status

# View migration history
python -m validation.workflow.migration_tools --command report
```

### Log Analysis

System components log to separate files:

- `workflow_orchestrator.log` - Workflow operations and status
- `branching_strategy.log` - Git operations and branch management
- `notification_system.log` - Message delivery and channel status
- `migration_tools.log` - Content transformation and validation
- `integration.log` - Overall system coordination

## Contributing

### Development Setup

1. **Fork the repository**
2. **Create feature branch**
3. **Implement changes**
4. **Add tests**
5. **Update documentation**
6. **Submit pull request**

### Testing

The system includes comprehensive test suites:

```bash
# Run all tests
python -m pytest validation/workflow/tests/

# Run specific component tests
python -m pytest validation/workflow/tests/test_review_workflow.py
python -m pytest validation/workflow/tests/test_branching_strategy.py
python -m pytest validation/workflow/tests/test_notification_system.py
python -m pytest validation/workflow/tests/test_migration_tools.py
```

### Code Style

Follow established conventions:
- PEP 8 for Python code formatting
- Type hints for function signatures
- Comprehensive docstrings
- Meaningful variable names
- Error handling and logging

## Support and Documentation

### Additional Resources

- **Configuration Reference** - Detailed parameter documentation
- **API Documentation** - Complete method reference
- **Migration Guides** - Step-by-step upgrade procedures
- **Troubleshooting Guide** - Common issues and solutions
- **Best Practices** - Recommended usage patterns

### Getting Help

1. **Check documentation** - Review relevant sections
2. **Search issues** - Look for similar problems
3. **Enable debug logging** - Increase verbosity for diagnosis
4. **Contact support** - Reach out to system administrators
5. **Submit bug reports** - Provide detailed reproduction steps

---

This comprehensive workflow system provides the foundation for high-quality, collaborative content development with automated quality assurance, version control, and stakeholder communication.