---
description: Review code against federal compliance rules (NIST 800-53, DoD AI Ethics, FedRAMP, IL requirements)
---

# Federal Compliance Review

Review code or architecture against federal data science compliance requirements from this handbook.

## Input

$ARGUMENTS

If no arguments provided, review the most recently discussed code or the current file in context.

## What to read first

ALWAYS read these files:
- @security-compliance/security-policy.md

Then based on code type:
- ML/AI code: @chapters/12-ethics-governance/README.md
- Deployment: @chapters/11-deployment/README.md
- GenAI/RAG: @chapters/13-advanced-topics/README.md

## What to check

1. No hardcoded credentials — must use env vars or platform secret management
2. No external API calls with government data at IL4+
3. Self-hosted models only at IL4+ for inference and embeddings
4. AES-256 at rest, TLS 1.3 in transit for all data handling
5. CAC/PIV authentication — no username/password auth
6. RBAC with least privilege
7. Audit logging for all data access and model inference
8. Model cards required for production ML (see `chapters/12-ethics-governance/code-examples/python/02_model_card.py`)
9. Bias audit required before production classifiers (see `chapters/12-ethics-governance/code-examples/python/01_bias_audit.py`)
10. NIST AI RMF documentation for AI systems

## Output format

Generate a compliance report with:
- Findings table (Finding | Severity: Critical/High/Medium/Low | Standard | Remediation)
- Compliant patterns found (what's done correctly)
- Top 3 priority fixes with specific code suggestions
- Handbook references (specific file paths with relevant patterns)
