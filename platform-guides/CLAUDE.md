# Platform Guides — Agent Context

5 platform guides covering the federal data science platforms where the work actually happens. Each has a README.md (primary guide) and cac-piv-integration.md (auth-specific details).

## Platform Selection Matrix

| Use Case | Recommended Platform | Why |
|----------|---------------------|-----|
| DoD-wide enterprise analytics | **Advana** | 100K+ users, 3000+ NIPRNet data sources, JupyterHub + Qlik |
| Navy/Marine Corps operations | **Navy Jupiter** | DON subtenant of Advana, bronze/silver/gold data tiers |
| ML pipelines, heavy compute | **Databricks** | AWS GovCloud or Azure Gov, Unity Catalog, Delta Lake, Spark |
| BI dashboards, associative analytics | **Qlik** | FedRAMP Moderate, NIPRNet or Advana-hosted, associative engine |
| Ontology-backed AI, LLM workflows | **Palantir AIP/Foundry** | IL4-IL6, FedStart, Pipeline Builder, AIP Logic |

### Cost Considerations

| Platform | Cost Model | Notes |
|----------|-----------|-------|
| Advana (WDP) | Program-funded (BAH prime) | Transitioning to WDP budget lines; no per-unit billing to users |
| Databricks | Consumption (DBU-based) | Carahsoft GSA Schedule or JWCC Marketplace; watch idle cluster costs |
| Navy Jupiter | Program-funded | Inherits WDP infrastructure; no separate billing |
| Palantir | Enterprise contract | Army EA up to $10B/10yr; consumption-based for other agencies |
| Qlik | License-based | FedRAMP Moderate tier; JWCC Marketplace available |

## Classification Level Coverage

| Platform | IL2 | IL4 | IL5 | IL6 | JWICS | FedRAMP |
|----------|-----|-----|-----|-----|-------|---------|
| Advana (WDP) | Yes | Yes | Yes | Yes | Yes | Inherits DoD |
| Databricks | Yes | Yes | Yes (SaaS) | - | Expected early 2027 | Moderate+ |
| Navy Jupiter | Yes | Yes | Yes | Yes | Yes (shared with WDP) | Inherits DoD |
| Palantir | Yes | Yes | Yes | Yes | Yes | FedStart |
| Qlik | Yes | Yes | - | - | - | Moderate |

## Guide Structure (consistent across all 5)

Each platform guide README follows this structure:
1. **Getting Access** — what you need, the actual process, timeline expectations
2. **Platform Overview** — architecture, what it is, organizational context
3. **Development Environment** — where code runs, available tools, pre-installed packages
4. **Core Workflows** — the tasks you'll actually do day-to-day
5. **Platform-Specific Code Patterns** — how to write code for this environment
6. **Integration Points** — how this platform connects to others
7. **Current State** — org changes, recent developments (as of early 2026)

## CAC/PIV Integration

All five platforms require CAC/PIV authentication. Details in `PLATFORM/cac-piv-integration.md`.

Reference implementations for OAuth-to-CAC bridging are in `../security-compliance/auth/` and `../security-compliance/rbac/`.

## Common Agent Tasks

- **"How do I get access to [platform]?"** → Read platform guide "Getting Access" section
- **"What's the auth model for [platform]?"** → Read `PLATFORM/cac-piv-integration.md`
- **"What code patterns work on [platform]?"** → Check chapter code-examples with matching `Platform:` tag
- **"Compare [platform A] and [platform B]"** → Use selection matrix above, then read both READMEs
- **"Which platform for [task]?"** → Use selection matrix above
