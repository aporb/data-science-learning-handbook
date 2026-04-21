# Security & Compliance — Federal Data Science Handbook

Reference implementations for federal security patterns. Not toy examples — working code for CAC/PIV auth, RBAC, encryption, compliance, and audit logging.

## Module index

| Module | Directory | Purpose |
|--------|-----------|---------|
| Authentication | `security-compliance/auth/` | CAC/PIV smart card integration, OAuth bridging, PKCS#11 |
| RBAC | `security-compliance/rbac/` | Role hierarchy, MAC (Bell-LaPadula), database-backed permissions |
| Encryption | `security-compliance/encryption/` | AES-256 at rest, TLS 1.3 in transit, HSM key management, FIPS 140-2 |
| Compliance | `security-compliance/compliance/` | NIST 800-53 automated assessment, evidence collection, reporting |
| Audit logging | `security-compliance/audits/` | Immutable audit trails, 7-year retention |
| API gateway | `security-compliance/api-gateway/` | DoD API patterns, rate limiting, auth proxy |
| Sessions | `security-compliance/sessions/` | Secure session management, timeout policies |
| Credentials | `security-compliance/credential-management/` | Secret rotation, vault integration |
| Monitoring | `security-compliance/monitoring/` | Security event monitoring, alerting |
| Multi-classification | `security-compliance/multi-classification/` | Cross-IL data handling |
| Penetration testing | `security-compliance/penetration-testing/` | Security validation tools |
| TLS | `security-compliance/tls/` | TLS configuration and certificate management |

## When generating security code

1. ALWAYS reference existing patterns in `security-compliance/` — do not invent compliance patterns
2. Read `security-compliance/security-policy.md` for classification levels and encryption standards
3. Read `security-compliance/CLAUDE.md` for module-by-module classification of runability
4. IL4+ requires: AES-256 at rest, TLS 1.3 in transit, CAC/PIV auth, audit logging for all data access
5. Never hardcode tokens, passwords, or credentials — use env vars or platform secret management
