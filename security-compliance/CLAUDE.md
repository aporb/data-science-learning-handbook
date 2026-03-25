# Security Compliance — Agent Context

14 modules covering federal security architecture. ~311 Python/config files total. These are reference implementations for DoD-compliant systems, NOT chapter code examples.

**Read `security-policy.md` first** for the high-level policy framework (classification levels, auth controls, encryption standards, compliance standards).

## Module Classification

### Reference Implementations
Study these and adapt patterns. Do not run as-is without configuration.

| Module | Key Files | What It Implements |
|--------|-----------|-------------------|
| `rbac/` | `rbac_system.py`, `role_hierarchy.py`, `rbac_system_manager.py` | Full MAC/DAC/RBAC/ABAC system with database layer |
| `encryption/` | `encryption_manager.py`, `fips_compliance.py`, `key_rotation.py` | AES-256 at rest, TLS in transit, FIPS compliance, key management |
| `auth/` | `oauth_cac_bridge.py` (+ platform-specific OAuth files) | CAC/PIV to OAuth bridge for Databricks, Qlik |
| `sessions/` | Session management files | Classification-aware session policies |
| `credential-management/` | Vault integration files | HashiCorp Vault integration, disaster recovery |

### Operational Tools
Designed to run against live systems. Require environment configuration.

| Module | What It Does |
|--------|-------------|
| `monitoring/` | Prometheus integration, compliance reporting, security alerting |
| `compliance/` | NIST 800-53 controls, integrated compliance platform |
| `api-gateway/` | DoD API gateway, lifecycle management, SLA tracking |

### Configuration-Heavy Modules
Not runnable without specific infrastructure. Study for patterns only.

| Module | What It Covers |
|--------|---------------|
| `multi-classification/` | Cross-domain transfer engine, spillage detection |
| `penetration-testing/` | Pentest platform (requires target environment) |
| `tls/` | TLS configuration (requires certificate infrastructure) |
| `security-testing/` | Security validation suite |
| `audits/` | Audit log management with 7-year retention |
| `backup/` | Backup and recovery procedures |

## Architecture Flow

```
CAC/PIV → auth/ (OAuth bridge) → sessions/ (classification-aware)
  → rbac/ (permission resolution: MAC + RBAC + ABAC)
  → encryption/ (data access: AES-256 at rest, TLS 1.3 in transit)
  → monitoring/ (audit log) → compliance/ (control verification)
```

## Key Files for Code Generation

| Task | Reference File |
|------|---------------|
| Federal auth code | `auth/oauth_cac_bridge.py` |
| RBAC implementation | `rbac/rbac_system.py` + `rbac/role_hierarchy.py` |
| Encryption patterns | `encryption/encryption_manager.py` |
| FIPS compliance | `encryption/fips_compliance.py` |
| Compliance checking | `compliance/integrated_compliance_platform.py` |
| Session management | `sessions/` (classification-aware policies) |

## Common Agent Tasks

- **`/compliance-check` invokes this directory** — the command reads `security-policy.md` and `compliance/` as primary sources
- **"Is my code compliant with [standard]?"** → Read `security-policy.md` + `compliance/` module
- **"Show me a DoD RBAC implementation"** → `rbac/rbac_system.py`
- **"How does CAC auth work with [platform]?"** → `auth/` directory, look for platform-specific OAuth file
- **"What encryption standard for federal data?"** → `encryption/` + `security-policy.md` §Data Encryption

## Do Not Modify

These are reference implementations. If generating security code, use these as patterns but create new files — do not edit the reference implementations.
