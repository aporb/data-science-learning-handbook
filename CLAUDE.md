# Federal Data Science Handbook

A completed practitioner's guide to data science on federal government platforms. 96,000+ words across 13 chapters, 5 platform guides, 43 Python code examples, and a reference security implementation. All content is QA-signed-off and frozen.

**This is a reference repository, not a project to build.** Use it to look things up, generate compliant code, and teach concepts.

## How To Use This Repo

### Mode 1: REFERENCE
User is coding on a federal platform and needs a quick answer.
- Chapter READMEs: `chapters/NN-name/README.md`
- Platform guides: `platform-guides/PLATFORM/README.md`
- Code patterns: `chapters/NN-name/code-examples/python/`
- Security patterns: `security-compliance/MODULE/`

### Mode 2: CODE GENERATION
User wants boilerplate for a federal context.
- Use `/generate-federal-code` command
- ALWAYS check platform constraints in `chapters/02-python-r-foundations/` first
- Match the existing docstring header format (see Code Quality section below)
- Never hardcode credentials — every platform uses env vars or secret management

### Mode 3: TEACHING
User wants to understand a concept.
- Use `/teach` command
- Walk through chapter README narrative + corresponding code examples together
- Anchor explanations in federal context, not generic data science

## Content Map

| Ch | Title | Key Topics | Platforms |
|----|-------|-----------|-----------|
| 01 | Introduction to Data Science in Government | Clearances, CAC auth, Impact Levels, ATO, platform overview | All 5 |
| 02 | Python and R Foundations | Air-gapped pip, conda on IL4/IL5, platform-specific imports | All 5 |
| 03 | Data Acquisition | USASpending, SAM.gov, data.gov, platform data catalogs | Advana, Jupiter, Foundry |
| 04 | Data Wrangling | pandas at scale, PySpark, Delta Lake, 47M-row procurement data | Databricks, Jupiter, Advana |
| 05 | Exploratory Analysis | Headless EDA, statistical profiling, no-notebook platforms | All 5 |
| 06 | Supervised ML | XGBoost, classification on DoD data, MILSTRIP feature engineering | Databricks, Advana |
| 07 | Unsupervised ML | Anomaly detection on GFEBS, clustering readiness data | Databricks, Advana |
| 08 | Deep Learning | CNN on drone video, 400ms inference budget, PyTorch/ONNX | Databricks, local Docker |
| 09 | MLOps | MLflow tracking, model registries, drift detection, ATO implications | Databricks, Foundry |
| 10 | Visualization | Qlik, Advana dashboards, Databricks SQL, briefing-ready design | Qlik, Advana |
| 11 | Deployment | Containers, artifact registries, API gateways, ATO as risk event | All 5 |
| 12 | Ethics and Governance | DoD AI Ethics Principles, NIST AI RMF, bias auditing, model cards | All 5 |
| 13 | Advanced Topics — GenAI | RAG at IL4/IL5, Palantir AIP Logic, fine-tuning classified data | Foundry, Databricks |

### Platform Guides

| Platform | IL Levels | Auth | Primary Use Case |
|----------|-----------|------|-----------------|
| Advana | IL4, IL5 | CAC/PIV | DoD enterprise analytics — JupyterHub, Qlik, 100+ data sources |
| Databricks | IL2, IL4, IL5 | CAC + OAuth | ML pipelines, lakehouse, Unity Catalog on AWS GovCloud / Azure Gov |
| Navy Jupiter | IL4, IL5 | CAC/PIV | Dept of Navy — bronze/silver/gold data tiers, DON subtenant of Advana |
| Palantir AIP/Foundry | IL4, IL5, IL6 | CAC + OAuth | Ontology-based analytics, Pipeline Builder, AIP Logic for LLMs |
| Qlik | IL2, IL4 | CAC/PIV | Associative analytics, federal BI — NIPRNet and Advana-hosted |

## Code Quality Indicators

Each of the 43 Python code examples has a docstring header with `Platform:` and `Usage:` fields. Follow those exactly.

**Runnable locally** (with Docker stack or standard Python):
- `chapters/01-*/code-examples/python/03_environment_verification.py`
- `chapters/05-*/code-examples/python/01_statistical_profiling.py`
- `chapters/12-*/code-examples/python/` (all three — bias audit, model card, NIST RMF)
- Most files marked `Platform: Local` or `Platform: Any`

**Platform-specific** (paste into platform notebook/workspace):
- Files marked `Platform: Databricks` → Databricks notebook cell
- Files marked `Platform: Foundry Code Workspace` → Foundry terminal
- Files marked `Platform: Advana` → Advana JupyterHub

**Security-compliance/** — mixed runability. See `security-compliance/CLAUDE.md` for module-by-module classification.

## Docker Development Environment

`docker-compose.yml` runs 13 services mirroring federal platform constraints:

| Service | Port | Purpose |
|---------|------|---------|
| Jupyter | 8888 | Development notebooks (+ Streamlit:8501, Dash:8050) |
| MLflow | 5000 | Experiment tracking and model registry |
| PostgreSQL | 5432 | Relational database |
| Redis | 6379 | Caching and session store |
| Nginx | 80/443 | Reverse proxy with TLS |
| Prometheus | 9090 | Metrics collection |
| Grafana | 3000 | Monitoring dashboards |
| Vault | 8200 | Secret management |
| Consul | 8500 | Service discovery |
| CAC-auth | 8001 | CAC/PIV authentication simulator |

Quick start: `cp .env.example .env && docker compose up -d`

Full setup: `docs/LOCAL_ENVIRONMENT.md`

## Agent Commands

| Command | Purpose |
|---------|---------|
| `/compliance-check` | Review code against federal compliance rules (NIST 800-53, DoD AI Ethics, FedRAMP, IL requirements) |
| `/generate-federal-code` | Generate platform-appropriate Python with correct headers and security patterns |
| `/teach` | Interactive tutor — walks through handbook content with narrative + code |

## Cross-Repo Reference

**Companion site**: `site/` submodule → https://aporb.github.io/federal-ds-handbook-site/
- Site has rendered HTML versions of all chapters and platform guides
- When working on site content, switch to `../site/` and read `site/CLAUDE.md`

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
  """
  Title
  Description
  Platform: [Databricks | Foundry | Advana | Local | Any]
  Usage: [how to run]
  """
  ```
- **Security**: never hardcode credentials, never send government data to external APIs, self-hosted models only at IL4+
