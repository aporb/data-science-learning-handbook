# Federal Data Science Handbook

A completed practitioner's guide to data science on federal government platforms. 96,000+ words across 13 chapters, 5 platform guides, 43 Python code examples, and a reference security implementation. All content is QA-signed-off and frozen.

**This is a reference repository, not a project to build.** Use it to look things up, generate compliant code, and teach concepts.

## How To Use This Repo

### Mode 1: REFERENCE
User is coding on a federal platform and needs a quick answer.
- Chapter READMEs: `chapters/01-introduction/README.md` through `chapters/13-advanced-topics/README.md`
- Platform guides: `platform-guides/advana/README.md`, `platform-guides/databricks/README.md`, `platform-guides/navy-jupiter/README.md`, `platform-guides/palantir-aip-foundry/README.md`, `platform-guides/qlik/README.md`
- Code patterns: `chapters/01-introduction/code-examples/python/` through `chapters/13-advanced-topics/code-examples/python/`
- Security patterns: `security-compliance/auth/`, `security-compliance/rbac/`, `security-compliance/encryption/`

### Mode 2: CODE GENERATION
User wants boilerplate for a federal context.
- Use `/generate-federal-code` command
- ALWAYS read `chapters/02-python-r-foundations/code-examples/python/02_platform_specific_imports.py` first for platform constraints
- Match the docstring header format: `Platform:` and `Usage:` fields required
- Never hardcode credentials — every platform uses env vars or secret management

### Mode 3: TEACHING
User wants to understand a concept.
- Use `/teach` command
- Walk through chapter README narrative + corresponding code examples together
- Anchor explanations in federal context, not generic data science

## Content Map

| Ch | Directory | Key Topics | Key Code Files |
|----|-----------|-----------|---------------|
| 01 | `chapters/01-introduction/` | Clearances, CAC auth, Impact Levels, ATO | `code-examples/python/01_platform_connections.py`, `code-examples/python/02_authentication_patterns.py`, `code-examples/python/03_environment_verification.py` |
| 02 | `chapters/02-python-r-foundations/` | Air-gapped pip, conda on IL4/IL5, platform imports | `code-examples/python/01_environment_setup.py`, `code-examples/python/02_platform_specific_imports.py`, `code-examples/python/03_data_structures.py` |
| 03 | `chapters/03-data-acquisition/` | USASpending, SAM.gov, data.gov | `code-examples/python/01_api_connections.py`, `code-examples/python/02_government_data_sources.py`, `code-examples/python/03_platform_data_catalogs.py` |
| 04 | `chapters/04-data-wrangling/` | pandas at scale, PySpark, Delta Lake | `code-examples/python/01_pandas_cleaning.py`, `code-examples/python/02_spark_transforms.py`, `code-examples/python/03_palantir_pipeline_builder.py` |
| 05 | `chapters/05-exploratory-analysis/` | Headless EDA, statistical profiling | `code-examples/python/01_statistical_profiling.py`, `code-examples/python/02_visualization_eda.py`, `code-examples/python/03_platform_eda_workflows.py` |
| 06 | `chapters/06-supervised-ml/` | XGBoost, classification on DoD data | `code-examples/python/01_classification_pipeline.py`, `code-examples/python/02_regression_and_xgboost.py`, `code-examples/python/03_mlflow_and_batch_scoring.py` |
| 07 | `chapters/07-unsupervised-ml/` | Anomaly detection, clustering readiness | `code-examples/python/01_clustering.py`, `code-examples/python/02_anomaly_detection.py`, `code-examples/python/03_topic_modeling.py` |
| 08 | `chapters/08-deep-learning/` | CNN on drone video, 400ms inference | `code-examples/python/01_tabular_neural_net.py`, `code-examples/python/02_cnn_satellite_imagery.py`, `code-examples/python/04_operational_inference_pipeline.py` |
| 09 | `chapters/09-mlops/` | MLflow tracking, model registries, drift | `code-examples/python/01_experiment_tracking.py`, `code-examples/python/02_model_registry_deployment.py`, `code-examples/python/03_pipeline_orchestration.py` |
| 10 | `chapters/10-visualization/` | Qlik, Advana dashboards, briefing-ready design | `code-examples/python/01_matplotlib_seaborn_charts.py`, `code-examples/python/02_plotly_interactive.py`, `code-examples/python/03_platform_dashboards.py` |
| 11 | `chapters/11-deployment/` | Containers, artifact registries, ATO | `code-examples/python/01_deployment_patterns.py`, `code-examples/python/02_api_serving.py`, `code-examples/python/03_platform_deployment.py` |
| 12 | `chapters/12-ethics-governance/` | DoD AI Ethics, NIST AI RMF, bias auditing | `code-examples/python/01_bias_audit.py`, `code-examples/python/02_model_card.py`, `code-examples/python/03_nist_rmf_workflow.py` |
| 13 | `chapters/13-advanced-topics/` | RAG at IL4/IL5, Palantir AIP Logic, LLMs | `code-examples/python/01_llm_integration.py`, `code-examples/python/02_rag_pipeline.py`, `code-examples/python/03_aip_agents.py` |

### Platform Guides

| Platform | Directory | IL Levels | Primary Use Case |
|----------|-----------|-----------|-----------------|
| Advana | `platform-guides/advana/` | IL4, IL5 | DoD enterprise analytics — JupyterHub, Qlik, 100+ data sources |
| Databricks | `platform-guides/databricks/` | IL2, IL4, IL5 | ML pipelines, lakehouse, Unity Catalog on GovCloud |
| Navy Jupiter | `platform-guides/navy-jupiter/` | IL4, IL5 | Dept of Navy — bronze/silver/gold data tiers |
| Palantir AIP/Foundry | `platform-guides/palantir-aip-foundry/` | IL4, IL5, IL6 | Ontology-based analytics, AIP Logic for LLMs |
| Qlik | `platform-guides/qlik/` | IL2, IL4 | Associative analytics, federal BI |

## Code Quality Indicators

Each of the 43 Python code examples has a docstring header with `Platform:` and `Usage:` fields. Follow those exactly.

**Runnable locally** (with Docker stack or standard Python):
- `chapters/01-introduction/code-examples/python/03_environment_verification.py`
- `chapters/05-exploratory-analysis/code-examples/python/01_statistical_profiling.py`
- `chapters/12-ethics-governance/code-examples/python/01_bias_audit.py`
- `chapters/12-ethics-governance/code-examples/python/02_model_card.py`
- `chapters/12-ethics-governance/code-examples/python/03_nist_rmf_workflow.py`

**Platform-specific** (paste into platform notebook/workspace):
- Files with `Platform: Databricks` header → Databricks notebook cell
- Files with `Platform: Foundry Code Workspace` header → Foundry terminal
- Files with `Platform: Advana` header → Advana JupyterHub

**Security modules** — mixed runability. See `security-compliance/CLAUDE.md` for module-by-module classification.

## Docker Development Environment

`docker-compose.yml` runs 13 services mirroring federal platform constraints:

```bash
cp .env.example .env && docker compose up -d
```

Quick verification after startup:

```bash
docker compose ps --format "table {{.Name}}\t{{.Status}}\t{{.Ports}}"
```

Full setup instructions: `docs/LOCAL_ENVIRONMENT.md`

## Agent Commands

| Command | Purpose |
|---------|---------|
| `/compliance-check` | Review code against federal compliance rules (NIST 800-53, DoD AI Ethics, FedRAMP, IL requirements) |
| `/generate-federal-code` | Generate platform-appropriate Python with correct headers and security patterns |
| `/teach` | Interactive tutor — walks through handbook content with narrative + code |

## Cross-Repo Reference

**Companion site**: `site/` submodule → https://aporb.github.io/federal-ds-handbook-site/
- Site has rendered HTML versions of all chapters and platform guides
- When working on site content, switch to `../site/` and read site `CLAUDE.md`

**Section-level context** (auto-loaded when working in these directories):
- `chapters/CLAUDE.md` — chapter index, code file mapping, learning objectives
- `platform-guides/CLAUDE.md` — platform selection matrix, guide structure
- `security-compliance/CLAUDE.md` — module classification, architecture flow

## Content Rules

- **Do NOT modify** chapter READMEs, platform guide READMEs, or exercise files — content is QA-signed-off
- **Style guide**: `docs/STYLE_GUIDE.md` — practitioner voice, specific details, scenes not thesis statements
- **Writing spec**: `docs/CHAPTER_WRITING_SPEC.md`
- **Code header format** — every generated code file must include:
  ```
  Title
  Description
  Platform: [Databricks | Foundry | Advana | Local | Any]
  Usage: [how to run]
  ```
- **Security**: never hardcode credentials, never send government data to external APIs, self-hosted models only at IL4+

## Model Configuration

When generating code for this handbook, use `claude-sonnet-4-20250514` with standard effort. The 96K+ words of domain content require careful grounding — avoid rushing through platform-specific constraints.
