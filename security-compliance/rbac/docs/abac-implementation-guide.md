# ABAC Policy Engine Implementation Guide

**Classification:** UNCLASSIFIED//FOR OFFICIAL USE ONLY  
**Version:** 1.0  
**Author:** Security Compliance Team  
**Date:** 2025-07-17  

## Overview

This document provides a comprehensive guide for implementing and using the Attribute-Based Access Control (ABAC) policy engine for the Data Science Learning Handbook platform. The implementation follows NIST SP 800-162 standards and DoD security requirements.

## Architecture

### Core Components

The ABAC implementation consists of several key components:

1. **ABACContext** - Manages attribute contexts for evaluation
2. **PolicyCondition** - Evaluates individual policy conditions
3. **ABACPolicy** - Represents and manages ABAC policies
4. **PolicyEngine** - Main evaluation engine
5. **PolicyDecision** - Encapsulates evaluation results

### Database Integration

The system integrates with the existing PostgreSQL database schema:

- **abac_policies** - Stores policy definitions in JSON format
- **abac_subject_attributes** - User-specific attributes
- **abac_resource_attributes** - Resource metadata
- **abac_environment_attributes** - Environmental context definitions

## Quick Start

### Basic Usage

```python
from models.abac import evaluate_request, check_permission

# Simple permission check
user_id = "123e4567-e89b-12d3-a456-426614174000"
is_authorized = check_permission(
    user_id=user_id,
    resource_type="dataset",
    action_type="read",
    resource_id="sensitive-dataset-001"
)

# Detailed authorization request
resource = {
    'resource_type': 'notebook',
    'classification_level': 'C',
    'classification_level_numeric': 80,
    'project_id': 'intelligence-analysis'
}

action = {
    'action_type': 'execute',
    'risk_level': 'medium'
}

decision = evaluate_request(user_id, resource, action)
print(f"Decision: {decision.decision.value}")
print(f"Obligations: {decision.obligations}")
```

### Creating Contexts

```python
from models.abac import create_context, PolicyEngine

# Create context with environment overrides
environment = {
    'business_hours': 'true',
    'network_classification': 'siprnet',
    'location_zone': 'secure_facility'
}

engine = PolicyEngine()
context = engine.create_context(
    user_id=user_id,
    resource=resource,
    action=action,
    environment=environment
)

# Evaluate with full control
decision = engine.evaluate(context)
```

## Policy Definition

### Policy Structure

ABAC policies are stored in JSON format with the following structure:

```json
{
    "policy_name": "Business Hours Access Control",
    "policy_description": "Restrict high-risk operations to business hours",
    "policy_effect": "DENY",
    "priority": 50,
    "classification_required": "C",
    "policy_rule": {
        "target": {
            "actions": [
                {"attribute": "risk_level", "operator": "in", "value": "high,critical"}
            ]
        },
        "condition": {
            "type": "any",
            "conditions": [
                {"source": "environment", "attribute": "business_hours", "operator": "eq", "value": "false"},
                {"source": "environment", "attribute": "time_of_day", "operator": "lt", "value": "06:00"},
                {"source": "environment", "attribute": "time_of_day", "operator": "gt", "value": "22:00"}
            ]
        },
        "obligations": [
            {"type": "audit", "level": "high"},
            {"type": "notification", "recipient": "security_team"}
        ]
    }
}
```

### Creating Policies

```python
from models.abac import ABACPolicy

# Create a new policy
policy = ABACPolicy(
    policy_name="Clearance Level Access Control",
    policy_description="Users can only access resources at or below their clearance level",
    policy_effect="DENY",
    priority=5,
    policy_rule={
        "condition": {
            "source": "subject",
            "attribute": "clearance_level_numeric",
            "operator": "gt",
            "value": "@resource.classification_level_numeric"
        }
    }
)

# Validate and save
errors = policy.validate()
if not errors:
    policy.save(user_id=admin_user_id)
```

## Condition Operators

### Basic Operators

| Operator | Description | Example |
|----------|-------------|---------|
| `eq` | Equals | `{"source": "subject", "attribute": "department", "operator": "eq", "value": "Intelligence"}` |
| `ne` | Not equals | `{"source": "action", "attribute": "type", "operator": "ne", "value": "delete"}` |
| `gt` | Greater than | `{"source": "environment", "attribute": "time_hour", "operator": "gt", "value": "8"}` |
| `lt` | Less than | `{"source": "environment", "attribute": "time_hour", "operator": "lt", "value": "18"}` |
| `gte` | Greater than or equal | `{"source": "subject", "attribute": "clearance_numeric", "operator": "gte", "value": "70"}` |
| `lte` | Less than or equal | `{"source": "resource", "attribute": "sensitivity_level", "operator": "lte", "value": "5"}` |

### List and Pattern Operators

| Operator | Description | Example |
|----------|-------------|---------|
| `in` | In list | `{"source": "subject", "attribute": "roles", "operator": "in", "value": "ADMIN,ANALYST"}` |
| `not_in` | Not in list | `{"source": "environment", "attribute": "network_zone", "operator": "not_in", "value": "external,dmz"}` |
| `contains` | Contains substring | `{"source": "resource", "attribute": "tags", "operator": "contains", "value": "sensitive"}` |
| `regex` | Regular expression | `{"source": "subject", "attribute": "email", "operator": "regex", "value": ".*@dod\\.mil$"}` |
| `exists` | Attribute exists | `{"source": "subject", "attribute": "security_clearance", "operator": "exists"}` |
| `range` | Numeric range | `{"source": "environment", "attribute": "hour", "operator": "range", "value": "9,17"}` |

### Logical Operators

#### ALL (AND) Logic
```json
{
    "type": "all",
    "conditions": [
        {"source": "subject", "attribute": "clearance", "operator": "gte", "value": "S"},
        {"source": "environment", "attribute": "business_hours", "operator": "eq", "value": "true"},
        {"source": "environment", "attribute": "location", "operator": "eq", "value": "secure_facility"}
    ]
}
```

#### ANY (OR) Logic
```json
{
    "type": "any",
    "conditions": [
        {"source": "subject", "attribute": "role", "operator": "eq", "value": "EMERGENCY_RESPONDER"},
        {"source": "environment", "attribute": "emergency_declared", "operator": "eq", "value": "true"}
    ]
}
```

## Attribute Management

### Subject Attributes

Subject attributes are automatically populated from user records and include:

```python
# Core identity
user_id, username, email, dod_id, cac_id, piv_id

# Security clearance
security_clearance, clearance_level_numeric, sci_compartments, 
caveat_codes, clearance_verified, investigation_type

# Training and certification
security_training_current, platform_certified, training_level

# Organizational
organization, unit, supervisor_id, project_assignments

# Session context
session_classification, session_start_time, last_activity
```

### Resource Attributes

Resource attributes describe the data or services being accessed:

```python
# Classification and sensitivity
classification_level, classification_level_numeric, control_markings,
sensitivity_level, compartment_required

# Data characteristics
data_type, format, size_bytes, pii_contains, phi_contains,
export_controlled, retention_period

# Ownership and project
owner_id, project_id, created_by, organization, sharing_level

# Technical metadata
location, storage_type, encryption_status, version, checksum
```

### Environment Attributes

Environment attributes provide contextual information:

```python
# Temporal context
request_time, time_of_day, day_of_week, business_hours,
holiday, emergency_period

# Network and location
ip_address, network_classification, network_zone, geographic_location,
facility_type, vpn_connection

# Device and security
device_type, device_id, os_type, device_encrypted, device_managed,
authentication_method, session_encrypted, threat_level
```

## Sample Policies

### 1. Business Hours Restriction

```python
policy = ABACPolicy(
    policy_name="Business Hours Operations Only",
    policy_effect="DENY",
    priority=50,
    policy_rule={
        "target": {
            "actions": [{"attribute": "risk_level", "operator": "in", "value": "high,critical"}]
        },
        "condition": {
            "type": "any",
            "conditions": [
                {"source": "environment", "attribute": "business_hours", "operator": "eq", "value": "false"},
                {"source": "environment", "attribute": "day_of_week", "operator": "in", "value": "saturday,sunday"}
            ]
        }
    }
)
```

### 2. Clearance-Based Access

```python
policy = ABACPolicy(
    policy_name="Security Clearance Access Control",
    policy_effect="DENY",
    priority=5,
    policy_rule={
        "condition": {
            "source": "subject",
            "attribute": "clearance_level_numeric",
            "operator": "gt",
            "value": "@resource.classification_level_numeric"
        }
    }
)
```

### 3. Network Security

```python
policy = ABACPolicy(
    policy_name="Classified Data Network Restriction",
    policy_effect="DENY",
    priority=10,
    policy_rule={
        "target": {
            "resources": [
                {"attribute": "classification_level", "operator": "in", "value": "C,S,TS,TS_SCI"}
            ]
        },
        "condition": {
            "source": "environment",
            "attribute": "network_classification",
            "operator": "not_in",
            "value": "siprnet,jwics"
        }
    }
)
```

### 4. Emergency Override

```python
policy = ABACPolicy(
    policy_name="Emergency Access Override",
    policy_effect="PERMIT",
    priority=1,
    policy_rule={
        "target": {
            "subjects": [
                {"attribute": "emergency_authorized", "operator": "eq", "value": "true"}
            ]
        },
        "condition": {
            "type": "all",
            "conditions": [
                {"source": "environment", "attribute": "emergency_period", "operator": "eq", "value": "true"},
                {"source": "subject", "attribute": "emergency_justification", "operator": "exists"}
            ]
        },
        "obligations": [
            {"type": "audit", "level": "critical", "notification": "immediate"},
            {"type": "time_limit", "duration": "PT4H"},
            {"type": "supervisor_notification", "immediate": "true"}
        ]
    }
)
```

## Decision Algorithm

The ABAC engine follows this evaluation process:

1. **Policy Discovery** - Find applicable policies based on target criteria
2. **Condition Evaluation** - Evaluate each policy's conditions against context
3. **Decision Combination** - Apply DENY-first logic:
   - If any DENY policy matches → DENY
   - If no DENY and any PERMIT policy matches → PERMIT
   - If no policies match → DENY (default)
4. **Obligation Processing** - Collect obligations from matching PERMIT policies

### Priority Handling

Policies are evaluated in priority order (lower numbers = higher priority):
- Priority 1-10: Critical security policies (emergency, network security)
- Priority 11-50: Standard security policies (clearance, time-based)
- Priority 51-100: Application-specific policies

## Obligation Processing

Obligations specify additional requirements when access is granted:

### Audit Obligations
```json
{
    "type": "audit",
    "level": "high",
    "retention": "7_years",
    "notification": "immediate"
}
```

### Time-Based Obligations
```json
{
    "type": "session_timeout",
    "duration": "PT8H"
},
{
    "type": "time_limit",
    "duration": "PT4H",
    "action": "revoke_access"
}
```

### Notification Obligations
```json
{
    "type": "notification",
    "recipient": "security_team",
    "trigger": "immediate"
},
{
    "type": "supervisor_notification",
    "delay": "PT15M"
}
```

## Performance Considerations

### Policy Optimization

1. **Order policies by priority** - Most restrictive first
2. **Use specific target criteria** - Reduce unnecessary evaluations
3. **Minimize complex conditions** - Simple conditions evaluate faster
4. **Cache frequently used attributes** - Reduce database queries

### Attribute Caching

```python
# Enable attribute caching in PolicyEngine
engine = PolicyEngine()
engine._cache_timeout = 300  # 5 minutes

# Clear cache when needed
engine.clear_cache()

# Get cache statistics
stats = engine.get_cache_stats()
```

### Database Indexing

Ensure proper indexes on:
- `abac_policies(active, priority)`
- `abac_subject_attributes(user_id, attribute_name)`
- `abac_resource_attributes(resource_type, resource_id)`

## Error Handling

### Policy Validation

```python
policy = ABACPolicy(**policy_data)
errors = policy.validate()

if errors:
    for error in errors:
        logger.error(f"Policy validation error: {error}")
    raise ValueError(f"Invalid policy: {'; '.join(errors)}")
```

### Evaluation Errors

The engine follows fail-secure principles:
- Invalid conditions → evaluate to False
- Missing attributes → evaluate to False  
- Evaluation exceptions → DENY decision
- Database errors → DENY decision

### Logging and Monitoring

```python
import logging

# Configure ABAC logging
logging.getLogger('models.abac').setLevel(logging.INFO)

# Monitor evaluation metrics
decision = engine.evaluate(context)
eval_time = decision.evaluation_metadata.get('evaluation_time_ms')
policies_checked = decision.evaluation_metadata.get('policies_evaluated')
```

## Security Considerations

### Policy Security

1. **Validate all policy inputs** - Prevent injection attacks
2. **Restrict policy modification** - Require administrative privileges
3. **Audit policy changes** - Log all policy modifications
4. **Test policies thoroughly** - Validate in staging environment

### Attribute Security

1. **Encrypt sensitive attributes** - Use database encryption
2. **Validate attribute sources** - Ensure data integrity
3. **Monitor attribute access** - Log sensitive attribute queries
4. **Implement attribute RBAC** - Control who can view attributes

### Decision Audit

All authorization decisions are logged with:
- Complete context snapshot
- Evaluated policies
- Final decision and reason
- Performance metrics
- User and session information

## Testing

### Unit Testing

```python
# Test individual components
def test_policy_condition():
    condition = PolicyCondition({
        'source': 'subject',
        'attribute': 'clearance_level',
        'operator': 'gte',
        'value': 'SECRET'
    })
    
    context = ABACContext(subject={'clearance_level': 'TOP_SECRET'})
    assert condition.evaluate(context) == True
```

### Integration Testing

```python
# Test complete policy evaluation
def test_clearance_policy():
    policy = ABACPolicy.get_by_policy_name("Clearance Access Control")
    
    context = create_context(
        user_id=test_user_id,
        resource={'classification_level': 'SECRET'},
        action={'action_type': 'read'}
    )
    
    decision = engine.evaluate(context)
    assert decision.is_permit()
```

### Load Testing

Monitor performance under load:
- Evaluation time < 100ms for 95% of requests
- Cache hit rate > 80%
- Policy evaluation throughput > 1000 requests/second

## Deployment

### Database Setup

1. Run schema migrations:
```sql
-- Execute 03_abac_functions.sql
\i schemas/03_abac_functions.sql
```

2. Load default policies:
```python
from models.abac import ABACPolicy

# Load sample policies
for policy_data in sample_policies:
    policy = ABACPolicy(**policy_data)
    policy.save(user_id=system_user_id)
```

### Configuration

Set environment variables:
```bash
export RBAC_DB_HOST=localhost
export RBAC_DB_PORT=5432
export RBAC_DB_NAME=rbac_system
export RBAC_DB_USER=rbac_user
export RBAC_DB_PASSWORD=secure_password
```

### Monitoring

Implement monitoring for:
- Authorization decision rates
- Policy evaluation performance
- Attribute availability
- Error rates and types
- Security events and anomalies

## Troubleshooting

### Common Issues

1. **Policy not applying**
   - Check target criteria matching
   - Verify policy is active
   - Review condition logic

2. **Performance issues**
   - Check database indexes
   - Review complex conditions
   - Monitor cache hit rates

3. **Attribute resolution failures**
   - Verify attribute existence
   - Check data types and formats
   - Review attribute source configuration

### Debug Mode

Enable detailed logging:
```python
import logging
logging.getLogger('models.abac').setLevel(logging.DEBUG)

# Get detailed evaluation metadata
decision = engine.evaluate(context)
print(json.dumps(decision.evaluation_metadata, indent=2))
```

## Migration from RBAC

To integrate ABAC with existing RBAC:

1. **Parallel deployment** - Run both systems simultaneously
2. **Gradual migration** - Move policies incrementally
3. **Validation testing** - Compare decisions between systems
4. **Fallback capability** - Maintain RBAC as backup

## Future Enhancements

Planned improvements:
- Machine learning for policy optimization
- Real-time threat intelligence integration
- Advanced attribute inference
- Policy conflict detection and resolution
- Dynamic policy adaptation

---

**Document Control:**
- **Classification:** UNCLASSIFIED//FOR OFFICIAL USE ONLY
- **Distribution:** Development Team, Security Team, System Administrators
- **Review Cycle:** Quarterly
- **Next Review:** 2025-10-17
- **Approval Authority:** Chief Information Security Officer