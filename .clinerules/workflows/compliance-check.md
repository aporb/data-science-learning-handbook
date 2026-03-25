# Federal Compliance Check

Review code against federal data science compliance requirements from this handbook.

## Step 1: Identify what's being reviewed

Look at the code provided by the user (or the current file in context). Classify it:
- **Data handling** → check classification and encryption
- **Auth/access** → check CAC/PIV and RBAC patterns
- **ML/model** → check DoD AI Ethics and NIST AI RMF
- **Deployment** → check ATO and container security
- **GenAI/LLM** → check IL-level authorization and self-hosting

## Step 2: Read the compliance policy

<read_file>
<path>security-compliance/security-policy.md</path>
</read_file>

This is the high-level policy: classification levels, auth controls, encryption standards, compliance standards.

## Step 3: Read type-specific compliance sources

Based on the code type identified in Step 1, read the relevant sources:
- For ML/AI code: read `chapters/12-ethics-governance/README.md`
- For deployment code: read `chapters/11-deployment/README.md`
- For auth code: read `security-compliance/auth/oauth_cac_bridge.py` and `security-compliance/rbac/rbac_system.py`
- For encryption: read `security-compliance/encryption/encryption_manager.py`
- For GenAI/RAG: read `chapters/13-advanced-topics/README.md`

## Step 4: Check against key compliance rules

Review the code against these rules:
1. No hardcoded credentials — must use env vars or platform secret management
2. No external API calls with government data at IL4+
3. Self-hosted models only at IL4+ for inference and embeddings
4. AES-256 at rest, TLS 1.3 in transit
5. CAC/PIV authentication — no username/password auth
6. RBAC with least privilege
7. Audit logging for all data access and model inference
8. Model cards required for production ML models
9. Bias audit required before production classifiers
10. NIST AI RMF documentation for AI systems

## Step 5: Generate compliance report

Output a structured report with:
- **Findings table**: Finding | Severity (Critical/High/Medium/Low) | Standard | Remediation
- **Compliant patterns found**: what the code does correctly
- **Top 3 priority fixes**: with specific code suggestions
- **Handbook references**: specific file paths with relevant patterns
