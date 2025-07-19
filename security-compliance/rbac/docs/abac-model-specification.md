# Attribute-Based Access Control (ABAC) Model Specification

**Classification:** UNCLASSIFIED//FOR OFFICIAL USE ONLY  
**Version:** 1.0  
**Author:** Security Compliance Team  
**Date:** 2025-07-17  

## Executive Summary

This document specifies the Attribute-Based Access Control (ABAC) model for the Data Science Learning Handbook platform. The ABAC model provides fine-grained access control by evaluating policies based on attributes of subjects (users), resources, actions, and environmental context. This approach complements the Role-Based Access Control (RBAC) system to provide comprehensive security enforcement.

## ABAC Architecture Overview

### Core Components

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Policy        │    │   Attribute     │    │   Decision      │
│   Engine        │◄───┤   Store         │───►│   Engine        │
│                 │    │                 │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         ▲                        ▲                        │
         │                        │                        ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Policy        │    │   Context       │    │   Authorization │
│   Repository    │    │   Handler       │    │   Response      │
│                 │    │                 │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

### ABAC Model (NIST SP 800-162)

The implementation follows the NIST ABAC model with four primary attribute categories:

1. **Subject Attributes:** Characteristics of the requesting entity (user)
2. **Resource Attributes:** Characteristics of the resource being accessed
3. **Action Attributes:** Characteristics of the requested operation
4. **Environment Attributes:** Contextual information about the access request

## Attribute Categories and Definitions

### Subject Attributes

Subject attributes describe characteristics of the user making the access request.

#### Core Identity Attributes
```json
{
  "user_id": "UUID of the user",
  "username": "Login identifier",
  "dod_id": "DoD ID number",
  "cac_id": "Common Access Card identifier",
  "piv_id": "Personal Identity Verification card identifier"
}
```

#### Clearance and Authorization Attributes
```json
{
  "security_clearance": "U|CUI|C|S|TS|TS_SCI",
  "clearance_level_numeric": "50-100 (lower = higher clearance)",
  "sci_compartments": ["SI", "TK", "G", "HCS"],
  "caveat_codes": ["NOFORN", "ORCON", "PROPIN"],
  "clearance_expiry": "ISO 8601 timestamp",
  "clearance_verified": "boolean",
  "investigation_type": "BI|SSBI|SSBI-PR"
}
```

#### Organizational Attributes
```json
{
  "organization": "User's organization code",
  "unit": "Organizational unit",
  "duty_position": "Official duty position",
  "supervisor_id": "UUID of supervisor",
  "project_assignments": ["project1", "project2"],
  "need_to_know": ["intelligence", "operations", "research"]
}
```

#### Training and Certification Attributes
```json
{
  "security_training_current": "boolean",
  "security_training_expiry": "ISO 8601 timestamp",
  "platform_certified": "boolean",
  "specialized_training": ["data_science", "ml_ops", "classified_handling"],
  "training_level": "basic|intermediate|advanced|expert"
}
```

#### Session and Temporal Attributes
```json
{
  "session_classification": "U|CUI|C|S|TS",
  "session_start_time": "ISO 8601 timestamp",
  "last_activity": "ISO 8601 timestamp",
  "session_duration": "seconds",
  "concurrent_sessions": "number",
  "failed_login_attempts": "number"
}
```

### Resource Attributes

Resource attributes describe characteristics of the data, systems, or services being accessed.

#### Classification and Sensitivity Attributes
```json
{
  "classification_level": "U|CUI|C|S|TS|TS_SCI",
  "classification_level_numeric": "50-100",
  "control_markings": ["NOFORN", "ORCON", "FOUO"],
  "sensitivity_level": "low|moderate|high|critical",
  "compartment_required": ["SI", "TK"],
  "declassification_date": "ISO 8601 timestamp",
  "originator": "Organization code"
}
```

#### Data Characteristics Attributes
```json
{
  "data_type": "notebook|dataset|model|report|configuration",
  "format": "csv|json|parquet|pickle|pdf|html",
  "size_bytes": "number",
  "record_count": "number",
  "pii_contains": "boolean",
  "phi_contains": "boolean",
  "financial_data": "boolean",
  "export_controlled": "boolean",
  "retention_period": "days"
}
```

#### Ownership and Project Attributes
```json
{
  "owner_id": "UUID of resource owner",
  "project_id": "Associated project identifier",
  "created_by": "UUID of creator",
  "organization": "Owning organization",
  "sharing_level": "private|team|organization|inter_agency",
  "collaboration_allowed": "boolean",
  "external_sharing": "boolean"
}
```

#### Technical Attributes
```json
{
  "location": "on_premise|cloud|hybrid",
  "storage_type": "database|file_system|object_store",
  "encryption_status": "encrypted|unencrypted|unknown",
  "backup_status": "backed_up|not_backed_up",
  "version": "Resource version number",
  "checksum": "Data integrity checksum",
  "last_modified": "ISO 8601 timestamp"
}
```

### Action Attributes

Action attributes describe the type of operation being requested.

#### Basic Operations
```json
{
  "action_type": "read|write|execute|delete|share|export|import",
  "action_scope": "metadata|content|full",
  "bulk_operation": "boolean",
  "modification_type": "create|update|append|truncate",
  "output_format": "csv|json|pdf|excel",
  "destination": "local|network|external"
}
```

#### Risk Level Attributes
```json
{
  "risk_level": "low|medium|high|critical",
  "audit_required": "boolean",
  "approval_required": "boolean",
  "notification_required": "boolean",
  "reversible": "boolean",
  "automated": "boolean"
}
```

### Environment Attributes

Environment attributes provide contextual information about the access request.

#### Temporal Context
```json
{
  "request_time": "ISO 8601 timestamp",
  "time_of_day": "HH:MM",
  "day_of_week": "monday|tuesday|...|sunday",
  "business_hours": "boolean",
  "holiday": "boolean",
  "emergency_period": "boolean",
  "maintenance_window": "boolean"
}
```

#### Network and Location Context
```json
{
  "ip_address": "IPv4/IPv6 address",
  "network_classification": "niprnet|siprnet|jwics|unclassified",
  "network_zone": "dmz|internal|secure|external",
  "geographic_location": "country_code",
  "facility_type": "secure_facility|office|remote|public",
  "vpn_connection": "boolean",
  "proxy_used": "boolean"
}
```

#### Device and Technical Context
```json
{
  "device_type": "workstation|laptop|tablet|mobile|server",
  "device_id": "Unique device identifier",
  "os_type": "windows|linux|macos|ios|android",
  "browser_type": "chrome|firefox|safari|edge",
  "device_encrypted": "boolean",
  "device_managed": "boolean",
  "antivirus_status": "current|outdated|disabled",
  "patch_level": "current|outdated|unknown"
}
```

#### Security Context
```json
{
  "authentication_method": "cac|piv|username_password|mfa",
  "authentication_strength": "weak|moderate|strong",
  "session_encrypted": "boolean",
  "threat_level": "low|medium|high|critical",
  "incident_active": "boolean",
  "security_alert_level": "green|yellow|orange|red"
}
```

## Policy Expression Language

### JSON-Based Policy Structure

Policies are expressed in JSON format with the following structure:

```json
{
  "policy_id": "unique_policy_identifier",
  "policy_name": "Human-readable policy name",
  "description": "Policy description and purpose",
  "effect": "PERMIT|DENY",
  "priority": 100,
  "target": {
    "subjects": [/* subject matching criteria */],
    "resources": [/* resource matching criteria */],
    "actions": [/* action matching criteria */],
    "environments": [/* environment matching criteria */]
  },
  "condition": {
    "type": "all|any|condition",
    "conditions": [/* array of condition objects */]
  },
  "obligations": [/* additional requirements if permitted */]
}
```

### Condition Operators

| Operator | Description | Example |
|----------|-------------|---------|
| `eq` | Equals | `{"source": "subject", "attribute": "clearance", "operator": "eq", "value": "TS"}` |
| `ne` | Not equals | `{"source": "resource", "attribute": "classification", "operator": "ne", "value": "U"}` |
| `gt` | Greater than | `{"source": "environment", "attribute": "time_of_day", "operator": "gt", "value": "08:00"}` |
| `lt` | Less than | `{"source": "environment", "attribute": "time_of_day", "operator": "lt", "value": "18:00"}` |
| `gte` | Greater than or equal | `{"source": "subject", "attribute": "clearance_level_numeric", "operator": "gte", "value": "70"}` |
| `lte` | Less than or equal | `{"source": "resource", "attribute": "classification_level_numeric", "operator": "lte", "value": "80"}` |
| `in` | In list | `{"source": "action", "attribute": "action_type", "operator": "in", "value": "read,write"}` |
| `not_in` | Not in list | `{"source": "environment", "attribute": "network_zone", "operator": "not_in", "value": "external"}` |
| `contains` | Contains substring | `{"source": "resource", "attribute": "data_type", "operator": "contains", "value": "sensitive"}` |
| `regex` | Regular expression | `{"source": "subject", "attribute": "organization", "operator": "regex", "value": "^(DOD\|NSA\|CIA).*"}` |
| `exists` | Attribute exists | `{"source": "subject", "attribute": "security_clearance", "operator": "exists"}` |
| `range` | Numeric range | `{"source": "environment", "attribute": "request_hour", "operator": "range", "value": "8,17"}` |

### Logical Operators

#### ALL (AND) Condition
All sub-conditions must be true:
```json
{
  "type": "all",
  "conditions": [
    {"source": "subject", "attribute": "clearance", "operator": "gte", "value": "S"},
    {"source": "environment", "attribute": "business_hours", "operator": "eq", "value": "true"},
    {"source": "resource", "attribute": "classification", "operator": "lte", "value": "S"}
  ]
}
```

#### ANY (OR) Condition
At least one sub-condition must be true:
```json
{
  "type": "any",
  "conditions": [
    {"source": "subject", "attribute": "role", "operator": "eq", "value": "SYSADMIN"},
    {"source": "subject", "attribute": "role", "operator": "eq", "value": "SECADMIN"},
    {"source": "environment", "attribute": "emergency_period", "operator": "eq", "value": "true"}
  ]
}
```

## Sample Policy Implementations

### Policy 1: Business Hours Restriction for High-Risk Operations

```json
{
  "policy_id": "POL_BH_001",
  "policy_name": "Business Hours High Risk Operations",
  "description": "Restrict high-risk operations to business hours only",
  "effect": "DENY",
  "priority": 50,
  "target": {
    "actions": [
      {"attribute": "risk_level", "operator": "in", "value": "high,critical"}
    ]
  },
  "condition": {
    "type": "any",
    "conditions": [
      {"source": "environment", "attribute": "time_of_day", "operator": "lt", "value": "06:00"},
      {"source": "environment", "attribute": "time_of_day", "operator": "gt", "value": "22:00"},
      {"source": "environment", "attribute": "day_of_week", "operator": "in", "value": "saturday,sunday"}
    ]
  }
}
```

### Policy 2: Classified Data Network Restriction

```json
{
  "policy_id": "POL_NET_001",
  "policy_name": "Classified Data Network Restriction",
  "description": "Classified data can only be accessed from secure networks",
  "effect": "DENY",
  "priority": 10,
  "target": {
    "resources": [
      {"attribute": "classification_level", "operator": "in", "value": "C,S,TS,TS_SCI"}
    ]
  },
  "condition": {
    "type": "condition",
    "source": "environment",
    "attribute": "network_classification",
    "operator": "not_in",
    "value": "siprnet,jwics"
  }
}
```

### Policy 3: PII Export Restriction

```json
{
  "policy_id": "POL_PII_001",
  "policy_name": "PII Export Restriction",
  "description": "Datasets containing PII cannot be exported without special authorization",
  "effect": "DENY",
  "priority": 20,
  "target": {
    "resources": [
      {"attribute": "pii_contains", "operator": "eq", "value": "true"}
    ],
    "actions": [
      {"attribute": "action_type", "operator": "eq", "value": "export"}
    ]
  },
  "condition": {
    "type": "all",
    "conditions": [
      {"source": "subject", "attribute": "pii_export_authorized", "operator": "ne", "value": "true"},
      {"source": "environment", "attribute": "emergency_period", "operator": "ne", "value": "true"}
    ]
  }
}
```

### Policy 4: Clearance-Based Access Control

```json
{
  "policy_id": "POL_CLEAR_001",
  "policy_name": "Security Clearance Access Control",
  "description": "Users can only access resources at or below their clearance level",
  "effect": "DENY",
  "priority": 5,
  "target": {
    "resources": [
      {"attribute": "classification_level_numeric", "operator": "exists"}
    ]
  },
  "condition": {
    "type": "condition",
    "source": "subject",
    "attribute": "clearance_level_numeric",
    "operator": "gt",
    "value": "@resource.classification_level_numeric"
  }
}
```

### Policy 5: Emergency Override

```json
{
  "policy_id": "POL_EMERG_001",
  "policy_name": "Emergency Access Override",
  "description": "Allow emergency access with proper authorization",
  "effect": "PERMIT",
  "priority": 1,
  "target": {
    "subjects": [
      {"attribute": "emergency_authorized", "operator": "eq", "value": "true"}
    ]
  },
  "condition": {
    "type": "all",
    "conditions": [
      {"source": "environment", "attribute": "emergency_period", "operator": "eq", "value": "true"},
      {"source": "subject", "attribute": "emergency_justification", "operator": "exists"},
      {"source": "environment", "attribute": "emergency_authorization_valid", "operator": "eq", "value": "true"}
    ]
  },
  "obligations": [
    {
      "type": "audit",
      "level": "high",
      "notification": "immediate"
    },
    {
      "type": "time_limit",
      "duration": "PT4H"
    }
  ]
}
```

## Decision Engine Architecture

### Policy Evaluation Algorithm

```
1. Policy Discovery
   ├── Filter policies by target criteria
   ├── Sort by priority (ascending)
   └── Group by effect type

2. Condition Evaluation
   ├── Evaluate each condition against context
   ├── Apply logical operators (ALL/ANY)
   └── Determine policy match result

3. Decision Combination
   ├── Process DENY policies first
   ├── If any DENY matches, return DENY
   ├── Process PERMIT policies
   ├── If any PERMIT matches, return PERMIT
   └── Default to DENY if no matches

4. Obligation Processing
   ├── Collect obligations from matching PERMIT policies
   ├── Validate obligation feasibility
   └── Return obligations with decision
```

### Context Assembly

```python
def assemble_context(user_id, resource, action, environment):
    context = {
        "subject": get_subject_attributes(user_id),
        "resource": get_resource_attributes(resource),
        "action": get_action_attributes(action),
        "environment": get_environment_attributes(environment)
    }
    
    # Enrich with dynamic attributes
    context["subject"].update(get_session_attributes(user_id))
    context["environment"].update(get_network_context())
    
    return context
```

### Performance Optimization

1. **Attribute Caching:** Cache frequently accessed attributes
2. **Policy Indexing:** Index policies by target criteria
3. **Lazy Evaluation:** Only evaluate conditions when needed
4. **Parallel Processing:** Evaluate independent conditions in parallel
5. **Result Caching:** Cache decision results for identical contexts

## Integration with RBAC

### Hybrid Authorization Model

The ABAC system works in conjunction with RBAC to provide comprehensive access control:

```
Authorization Decision = RBAC_Decision AND ABAC_Decision

Where:
- RBAC_Decision: Traditional role-based permission check
- ABAC_Decision: Attribute-based policy evaluation
- Final access granted only if BOTH return PERMIT
```

### RBAC-ABAC Interaction Patterns

#### Pattern 1: RBAC Primary, ABAC Refinement
```
1. Check RBAC permissions
2. If RBAC denies, return DENY
3. If RBAC permits, evaluate ABAC policies
4. Return final ABAC decision
```

#### Pattern 2: ABAC Override
```
1. Evaluate high-priority ABAC policies
2. If explicit DENY, return DENY
3. If no high-priority match, check RBAC
4. Evaluate remaining ABAC policies
```

## Audit and Monitoring

### Decision Audit Trail

Every authorization decision generates an audit record:

```json
{
  "decision_id": "UUID",
  "timestamp": "ISO 8601",
  "subject_id": "user_id",
  "resource": "resource_identifier",
  "action": "requested_action",
  "decision": "PERMIT|DENY",
  "rbac_result": "PERMIT|DENY",
  "abac_result": "PERMIT|DENY",
  "policies_evaluated": ["policy_id_1", "policy_id_2"],
  "matching_policies": ["policy_id_x"],
  "context": {/* full context at time of decision */},
  "obligations": [/* any obligations attached */],
  "performance_metrics": {
    "evaluation_time_ms": 50,
    "policies_checked": 25,
    "cache_hits": 15
  }
}
```

### Monitoring Metrics

1. **Performance Metrics:**
   - Average decision time
   - Policy evaluation throughput
   - Cache hit rates

2. **Security Metrics:**
   - Access denial rates by policy
   - Emergency override usage
   - Failed authorization attempts

3. **Operational Metrics:**
   - Policy conflict detection
   - Attribute availability rates
   - System error rates

## Administration and Maintenance

### Policy Lifecycle Management

1. **Policy Development:**
   - Policy requirements analysis
   - Policy design and specification
   - Security review and approval

2. **Policy Testing:**
   - Unit testing with sample contexts
   - Integration testing with RBAC
   - Performance testing under load

3. **Policy Deployment:**
   - Staged deployment process
   - Rollback capability
   - Impact monitoring

4. **Policy Maintenance:**
   - Regular policy review
   - Performance optimization
   - Conflict resolution

### Attribute Management

1. **Attribute Sources:**
   - Authoritative data sources
   - Synchronization schedules
   - Validation procedures

2. **Attribute Quality:**
   - Completeness monitoring
   - Accuracy validation
   - Freshness tracking

3. **Attribute Security:**
   - Encryption requirements
   - Access control for attributes
   - Audit trail maintenance

---

**Document Control:**
- **Classification:** UNCLASSIFIED//FOR OFFICIAL USE ONLY
- **Distribution:** Security Team, Development Team, Architecture Board
- **Review Cycle:** Semi-annual
- **Next Review:** 2026-01-17
- **Approval Authority:** Chief Information Security Officer