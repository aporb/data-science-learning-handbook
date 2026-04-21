# Platform Guides — Federal Data Science Handbook

Content in `platform-guides/*/README.md` is QA-signed-off and frozen. Do NOT modify.

## When working with platform guides

Each platform guide is self-contained with: access instructions, setup, development environment, code patterns, and deployment notes.

### Platform-specific constraints

- **Advana** (`platform-guides/advana/`): JupyterHub on shared cluster. No sudo. Use conda environments. 100+ data sources via Qlik and Jupyter.
- **Databricks** (`platform-guides/databricks/`): No `pip install` in notebook cells. Use cluster-installed libraries. Use `dbutils.secrets` for credentials. Unity Catalog for governance.
- **Navy Jupiter** (`platform-guides/navy-jupiter/`): DON subtenant of Advana. Bronze/silver/gold data tiers. Navy-specific constraints on data movement.
- **Palantir AIP/Foundry** (`platform-guides/palantir-aip-foundry/`): Use `palantir_models` for model publishing. No direct file I/O — use transforms. Pipeline Builder for orchestration. AIP Logic for LLM workflows.
- **Qlik** (`platform-guides/qlik/`): Server-side scripts only. No direct Python execution in dashboards. Associative engine for federal BI.

### Cross-platform references

- CAC/PIV integration patterns: `platform-guides/*/cac-piv-integration.md` (per-platform)
- Platform config files: `platform-guides/*/config/`
- Platform test scripts: `platform-guides/*/scripts/`

## Platform selection guide

Read `platform-guides/CLAUDE.md` for the full selection matrix mapping use cases to platforms.
