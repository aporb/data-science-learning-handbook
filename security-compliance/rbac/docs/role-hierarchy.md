# DoD-Compliant Role Hierarchy Documentation

**Classification:** UNCLASSIFIED//FOR OFFICIAL USE ONLY  
**Version:** 1.0  
**Author:** Security Compliance Team  
**Date:** 2025-07-17  

## Overview

This document defines the role hierarchy for the Data Science Learning Handbook platform, designed to comply with Department of Defense (DoD) security standards and NIST guidelines. The hierarchy implements a principle of least privilege with proper separation of duties and clear escalation paths.

## Role Hierarchy Structure

### Administrative Tier (Tier 1)
**Highest privilege level - System and security administration**

```
System Administrator (SYSADMIN)
├── Security Administrator (SECADMIN)
├── Database Administrator (DBADMIN)
└── Security Officer (SECURITY_OFF)
```

#### System Administrator (SYSADMIN)
- **Clearance Requirement:** Top Secret (TS)
- **Max Classification Access:** Top Secret//SCI
- **Approval Required:** Yes
- **Responsibilities:**
  - Full system administration privileges
  - Infrastructure management and maintenance
  - Platform deployment and configuration
  - Emergency system recovery
- **Key Permissions:**
  - SYS_ADMIN, USER_MGMT, ROLE_MGMT, SEC_CONFIG
  - AUDIT_ACCESS, LOG_ACCESS

#### Security Administrator (SECADMIN)
- **Clearance Requirement:** Top Secret (TS)
- **Max Classification Access:** Top Secret//SCI
- **Approval Required:** Yes
- **Responsibilities:**
  - Security policy implementation and enforcement
  - Access control management
  - Security incident response coordination
  - Compliance monitoring and reporting
- **Key Permissions:**
  - SEC_CONFIG, SEC_MONITOR, INCIDENT_RESP, VULN_SCAN
  - AUDIT_ACCESS, USER_MGMT, ROLE_MGMT

#### Database Administrator (DBADMIN)
- **Clearance Requirement:** Secret (S)
- **Max Classification Access:** Top Secret (TS)
- **Approval Required:** Yes
- **Responsibilities:**
  - Database system administration
  - Data backup and recovery
  - Performance optimization
  - Database security configuration

### Management Tier (Tier 2)
**Operational oversight and program management**

```
Operations Manager (OPS_MGR)
├── Platform Operator (OPERATOR)
└── System Monitor (MONITOR)

Research Lead (RESEARCH_LEAD)
├── Senior Intelligence Analyst (SR_ANALYST)
├── Senior Data Scientist (SR_DATA_SCI)
└── Project Manager (PROJ_MGR)
```

#### Operations Manager (OPS_MGR)
- **Clearance Requirement:** Secret (S)
- **Max Classification Access:** Top Secret (TS)
- **Approval Required:** Yes
- **Responsibilities:**
  - Platform operations oversight
  - Resource allocation and planning
  - Operational procedures development
  - Team coordination and scheduling

#### Research Lead (RESEARCH_LEAD)
- **Clearance Requirement:** Secret (S)
- **Max Classification Access:** Top Secret (TS)
- **Approval Required:** Yes
- **Responsibilities:**
  - Research program leadership
  - Strategic analysis direction
  - Cross-functional coordination
  - Technical oversight and guidance

### Senior Practitioner Tier (Tier 3)
**Subject matter experts and technical leaders**

```
Senior Data Scientist (SR_DATA_SCI)
├── Data Scientist (DATA_SCI)
└── Junior Data Scientist (JR_DATA_SCI)

Senior Intelligence Analyst (SR_ANALYST)
├── Intelligence Analyst (ANALYST)
└── Junior Analyst (JR_ANALYST)

Technical Lead (TECH_LEAD)
├── ML Engineer (ML_ENG)
└── Data Engineer (DATA_ENG)
```

#### Senior Data Scientist (SR_DATA_SCI)
- **Clearance Requirement:** Secret (S)
- **Max Classification Access:** Top Secret (TS)
- **Approval Required:** Yes
- **Responsibilities:**
  - Advanced data science research and development
  - Team technical leadership
  - Model development and validation
  - Cross-project collaboration coordination
- **Key Permissions:**
  - Full notebook and dataset management
  - Model deployment capabilities
  - Project administration
  - Team collaboration and sharing

#### Senior Intelligence Analyst (SR_ANALYST)
- **Clearance Requirement:** Top Secret (TS)
- **Max Classification Access:** Top Secret//SCI
- **Approval Required:** Yes
- **Responsibilities:**
  - Senior-level intelligence analysis
  - Report writing and briefing preparation
  - Junior analyst mentoring
  - Multi-source intelligence integration

### Practitioner Tier (Tier 4)
**Core operational roles with specialized functions**

```
Data Scientist (DATA_SCI)
Intelligence Analyst (ANALYST)
ML Engineer (ML_ENG)
Data Engineer (DATA_ENG)
Platform Operator (OPERATOR)
Training Administrator (TRAIN_ADMIN)
Compliance Officer (COMPLIANCE_OFF)
```

#### Data Scientist (DATA_SCI)
- **Clearance Requirement:** Confidential (C)
- **Max Classification Access:** Secret (S)
- **Approval Required:** No
- **Responsibilities:**
  - Data analysis and modeling
  - Notebook development and execution
  - Dataset preparation and processing
  - Collaborative research participation

#### Intelligence Analyst (ANALYST)
- **Clearance Requirement:** Secret (S)
- **Max Classification Access:** Top Secret (TS)
- **Approval Required:** No
- **Responsibilities:**
  - Intelligence data analysis
  - Report generation
  - Pattern identification
  - Threat assessment support

### User Tier (Tier 5)
**Standard and specialized user access levels**

```
Power User (POWER_USER)
├── Standard User (USER)
└── Guest User (GUEST)

Junior Data Scientist (JR_DATA_SCI)
Junior Analyst (JR_ANALYST)
System Monitor (MONITOR)
```

#### Power User (POWER_USER)
- **Clearance Requirement:** Confidential (C)
- **Max Classification Access:** Secret (S)
- **Approval Required:** No
- **Responsibilities:**
  - Advanced platform usage
  - Multi-project participation
  - Resource creation and management
  - Limited administrative functions

#### Standard User (USER)
- **Clearance Requirement:** CUI
- **Max Classification Access:** Confidential (C)
- **Approval Required:** No
- **Responsibilities:**
  - Basic platform access
  - Training completion
  - Read-only data access
  - Personal progress tracking

#### Guest User (GUEST)
- **Clearance Requirement:** Unclassified (U)
- **Max Classification Access:** CUI
- **Approval Required:** No
- **Responsibilities:**
  - Limited platform access
  - Training materials access
  - Basic functionality demonstration
  - Evaluation and assessment

## Permission Inheritance Model

### Inheritance Rules

1. **Hierarchical Inheritance:** Child roles automatically inherit permissions from parent roles
2. **Additive Model:** Permissions are cumulative - child roles retain all parent permissions plus their own
3. **Override Capability:** Specific permissions can be explicitly denied at child level if required
4. **Clearance Enforcement:** All inherited permissions are still subject to clearance level restrictions

### Classification Level Constraints

```
Classification Hierarchy (Higher → Lower Access):
TS/SCI (50) → TS (60) → S (70) → C (80) → CUI (90) → U (100)

Access Rule: Users can access their clearance level and below
Example: Secret clearance (70) can access Secret, Confidential, CUI, and Unclassified
```

### Permission Escalation Paths

#### Technical Escalation
```
JR_DATA_SCI → DATA_SCI → SR_DATA_SCI → RESEARCH_LEAD
JR_ANALYST → ANALYST → SR_ANALYST → RESEARCH_LEAD
```

#### Administrative Escalation
```
MONITOR → OPERATOR → OPS_MGR → SYSADMIN
USER → POWER_USER → TRAIN_ADMIN → SECADMIN
```

#### Specialized Paths
```
ML_ENG → TECH_LEAD → SR_DATA_SCI
DATA_ENG → TECH_LEAD → SR_DATA_SCI
SECURITY_OFF → SECADMIN → SYSADMIN
```

## Security Clearance Integration

### Clearance-Role Mapping

| Role Level | Minimum Clearance | Typical Clearance | Maximum Access |
|------------|-------------------|-------------------|----------------|
| Administrative | TS | TS/SCI | TS/SCI |
| Management | S | TS | TS |
| Senior Practitioner | S | TS | TS |
| Practitioner | C | S | S |
| User | U | CUI | C |

### Clearance Verification Requirements

1. **Initial Verification:** All clearances must be verified before role assignment
2. **Periodic Re-verification:** Annual verification for TS/SCI, bi-annual for S and below
3. **Continuous Monitoring:** Integration with security office for clearance status updates
4. **Automatic Suspension:** Role suspension upon clearance expiration or revocation

### Special Access Programs (SAP)

- **SCI Compartments:** Handled through additional attribute-based controls
- **SAR Programs:** Require specific approval workflow
- **Caveats:** NOFORN, ORCON, etc. implemented as user attributes

## Role Assignment Workflow

### Standard Assignment Process

1. **Request Submission:** User or manager submits role assignment request
2. **Clearance Verification:** Automated check against security clearance database
3. **Approval Workflow:**
   - **Auto-approval:** User-tier roles with adequate clearance
   - **Manager Approval:** Practitioner and Senior Practitioner roles
   - **Security Approval:** Administrative and Management roles
4. **Activation:** Role becomes active upon approval
5. **Notification:** User and relevant stakeholders notified

### Emergency Assignment

- **Temporary Elevation:** 72-hour emergency access with required justification
- **Immediate Approval:** Security Administrator or higher can grant temporary access
- **Audit Trail:** All emergency assignments logged and reviewed
- **Automatic Expiration:** Emergency roles expire automatically

### Role Termination

- **Automatic Triggers:** Employee separation, clearance revocation, security incident
- **Grace Period:** 24-hour deactivation period for knowledge transfer
- **Access Revocation:** Immediate removal of all system access
- **Audit Requirements:** Full activity review for administrative roles

## Compliance and Audit

### DoD Standards Compliance

- **DoDI 8510.01:** Risk Management Framework compliance
- **CNSSI-1253:** Security categorization alignment
- **FIPS 199:** Impact level assessment integration
- **NIST SP 800-53:** Control family implementation

### Audit Requirements

1. **Role Assignment Audits:** Quarterly review of all role assignments
2. **Permission Reviews:** Semi-annual review of role-permission mappings
3. **Access Pattern Analysis:** Monthly analysis of user access patterns
4. **Compliance Reporting:** Automated compliance status reporting

### Key Performance Indicators

- **Role Assignment Time:** Target < 24 hours for standard roles
- **Clearance Verification Time:** Target < 4 hours during business hours
- **Role Coverage:** Minimum 95% of users assigned appropriate roles
- **Security Incident Response:** Emergency role assignment within 2 hours

## Integration Points

### External Systems

- **CAC/PIV Integration:** Automated clearance and identity verification
- **DEERS Integration:** DoD personnel database synchronization
- **Security Training System:** Training completion status integration
- **Incident Response System:** Automated role suspension capabilities

### Platform Integration

- **Vault Integration:** Policy-based secret access control
- **Jupyter Hub:** Notebook access and resource allocation
- **MLflow:** Model deployment and versioning control
- **Grafana:** Monitoring and alerting based on role permissions

## Maintenance and Updates

### Role Definition Updates

- **Change Control:** All role changes require security administrator approval
- **Impact Assessment:** Analysis of role changes on existing assignments
- **Notification Requirements:** 30-day advance notice for role privilege reductions
- **Rollback Procedures:** Documented procedures for role change rollback

### Clearance Updates

- **Automatic Sync:** Daily synchronization with authoritative clearance sources
- **Manual Override:** Security administrator override capability for urgent cases
- **Validation Requirements:** Quarterly validation of all clearance mappings
- **Exception Handling:** Documented procedures for clearance discrepancies

---

**Document Control:**
- **Classification:** UNCLASSIFIED//FOR OFFICIAL USE ONLY
- **Distribution:** Security Team, System Administrators, Compliance Office
- **Review Cycle:** Quarterly
- **Next Review:** 2025-10-17
- **Approval Authority:** Chief Information Security Officer