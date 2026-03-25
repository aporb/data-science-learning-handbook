# Federal Compliance Review

Review code or architecture against federal data science compliance requirements from this handbook.

## Input

$ARGUMENTS

If no arguments provided, review the most recently discussed code or the current file in context.

## Instructions

### Step 1: Identify what's being reviewed

Classify the code/architecture:
- **Data handling** → check classification levels and encryption requirements
- **Authentication/access** → check CAC/PIV and RBAC patterns
- **ML/model code** → check DoD AI Ethics and NIST AI RMF requirements
- **Deployment** → check ATO requirements and container security
- **API/integration** → check network security and data boundary rules
- **GenAI/LLM** → check IL-level authorization and self-hosting requirements

### Step 2: Read the relevant compliance sources

ALWAYS read:
- `security-compliance/security-policy.md` — classification levels, auth controls, encryption standards

Then read based on code type:
- **ML/AI code**: `chapters/12-ethics-governance/README.md` (DoD AI Ethics, NIST AI RMF, bias audit requirements)
- **Auth code**: `security-compliance/auth/oauth_cac_bridge.py` and `security-compliance/rbac/rbac_system.py` for reference patterns
- **Deployment code**: `chapters/11-deployment/README.md` (ATO process, container security, artifact registries)
- **Encryption/data handling**: `security-compliance/encryption/encryption_manager.py` and `security-compliance/encryption/fips_compliance.py`
- **GenAI/RAG**: `chapters/13-advanced-topics/README.md` (LLM authorization matrix, IL-level constraints)
- **API code**: `security-compliance/api-gateway/` for DoD API patterns

### Step 3: Generate the compliance report

Use this exact format:

```
## Compliance Review — [brief description of what was reviewed]

### Findings

| # | Finding | Severity | Standard | Remediation |
|---|---------|----------|----------|-------------|
| 1 | [what's wrong] | Critical/High/Medium/Low | [which standard] | [specific fix + handbook reference] |

### Compliant Patterns Found
- [list what the code does correctly — reinforce good practices]

### Priority Fixes
1. [most critical fix with specific code suggestion]
2. [second priority]
3. [third priority]

### Handbook References
- [specific file paths in this repo with relevant patterns and guidance]
```

### Severity Definitions

- **Critical**: Data could leak across classification boundaries, credentials exposed, no auth on sensitive endpoints
- **High**: Missing encryption, hardcoded credentials, external API calls with government data at IL4+, no audit logging
- **Medium**: Incomplete RBAC, missing model card for production AI, no drift monitoring, weak session management
- **Low**: Style issues, missing docstring headers, non-standard platform patterns, missing error handling

### Key Rules to Check

1. **No hardcoded credentials** — must use env vars or platform secret management
2. **No external API calls with government data** at IL4+ (this includes OpenAI, Anthropic, HuggingFace hosted models)
3. **Self-hosted models only** at IL4+ for ML inference and embeddings
4. **AES-256 at rest, TLS 1.3 in transit** for all data handling
5. **CAC/PIV authentication** required — no username/password auth for federal systems
6. **RBAC with least privilege** — check role assignments against `security-compliance/rbac/role_hierarchy.py`
7. **Audit logging** for all data access and model inference
8. **Model cards required** for any production ML model (see `chapters/12-ethics-governance/code-examples/python/02_model_card.py`)
9. **Bias audit required** before production deployment of classifiers (see `chapters/12-ethics-governance/code-examples/python/01_bias_audit.py`)
10. **NIST AI RMF documentation** for AI systems (see `chapters/12-ethics-governance/code-examples/python/03_nist_rmf_workflow.py`)
