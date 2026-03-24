# Federal Data Science Handbook

A practitioner's guide to data science on federal government platforms. Thirteen chapters covering the full data science lifecycle — environment setup through generative AI — grounded in how the work actually gets done on Advana, Qlik, Databricks, Navy Jupiter, and Palantir AIP/Foundry.

This is the book a senior practitioner would hand to someone on their first day on a DoD contract and say: read this, everything you need is in here.

---

## About This Project

There is no good open-source resource for doing data science on federal government platforms. Commercial tutorials assume you have pip install, unrestricted internet access, and a cloud account you control. None of that is true in a DoD environment where CAC authentication, Impact Level restrictions, ATO processes, and air-gapped networks shape every technical decision.

This handbook fills that gap. It covers the full data science lifecycle — from getting access to data through deploying models in production — on the five platforms where federal data science actually happens. Every code example is written to run in the constrained environments it describes, not on a local machine with unconstrained internet.

The handbook also ships with a Docker-based local development environment that mirrors federal platform constraints, and a reference security implementation covering CAC/PIV authentication, RBAC, and federal compliance patterns.

---

## Table of Contents

### Chapters

| # | Title | Summary |
|---|-------|---------|
| [01](chapters/01-introduction/README.md) | Introduction to Data Science in Government | Clearances, CAC auth, Impact Levels, ATO — everything that shapes the work before you write code |
| [02](chapters/02-python-r-foundations/README.md) | Python and R Foundations | Air-gapped pip mirrors, conda on IL4/IL5, and the reality of getting a working environment on each platform |
| [03](chapters/03-data-acquisition/README.md) | Data Acquisition | Where federal data lives — USASpending, SAM.gov, data.gov — and how to pull it programmatically |
| [04](chapters/04-data-wrangling/README.md) | Data Wrangling and Cleaning | 47 million rows of procurement data that a program office called "analysis-ready" — pandas, Spark, and Delta Lake at scale |
| [05](chapters/05-exploratory-analysis/README.md) | Exploratory Data Analysis | EDA without a data dictionary, on a platform that may not support interactive notebooks |
| [06](chapters/06-supervised-ml/README.md) | Supervised Machine Learning | Building classifiers on DoD data: feature engineering on MILSTRIP, XGBoost on Databricks, and what accuracy means in a briefing |
| [07](chapters/07-unsupervised-ml/README.md) | Unsupervised Machine Learning | Anomaly detection on GFEBS transactions, clustering readiness data, and turning unsupervised results into actionable findings |
| [08](chapters/08-deep-learning/README.md) | Deep Learning and Neural Networks | Object detection on drone video at 30fps with a 400ms inference budget — deep learning in constrained federal environments |
| [09](chapters/09-mlops/README.md) | MLOps and Production Pipelines | MLflow, model registries, drift detection, and the ATO implications of updating a production model |
| [10](chapters/10-visualization/README.md) | Visualization and Dashboards | Qlik, Advana dashboards, Databricks SQL — design principles that separate briefing-ready visuals from data art |
| [11](chapters/11-deployment/README.md) | Deployment and Scaling | Containers, artifact registries, API gateways, and an ATO process that treats every deployment as a risk event |
| [12](chapters/12-ethics-governance/README.md) | Ethics, Governance, and Compliance | DoD AI Ethics Principles, NIST AI RMF, bias auditing, and what responsible AI governance looks like on an active program |
| [13](chapters/13-advanced-topics/README.md) | Advanced Topics — GenAI, RAG, and LLMs | RAG at IL4/IL5, Palantir AIP Logic, fine-tuning on classified data, and the gap between commercial LLMs and federal deployments |

### Platform Guides

| Platform | Summary |
|----------|---------|
| [Advana](platform-guides/advana/README.md) | DoD Enterprise Analytics — JupyterHub, Qlik, 100+ data sources under one IL4/IL5 roof |
| [Qlik](platform-guides/qlik/README.md) | Associative engine analytics for federal BI — NIPRNet, Advana-hosted, and GovCloud deployments |
| [Databricks](platform-guides/databricks/README.md) | Unity Catalog, Delta Lake, MLflow on AWS GovCloud and Azure Government |
| [Navy Jupiter](platform-guides/navy-jupiter/README.md) | Department of the Navy — bronze/silver/gold data tiers, Navy-specific data sources and constraints |
| [Palantir AIP / Foundry](platform-guides/palantir-aip-foundry/README.md) | Ontology-based analytics, Pipeline Builder, AIP Logic for LLM workflows |

---

## Quick Start

**New to federal data science?** Read chapters 1 through 4 in order. They cover the environment, access model, where data lives, and how to work with it.

**Switching platforms?** Go directly to the platform guide for your new environment. Each is self-contained — setup through deployment.

**Need a specific capability?** Jump to the relevant chapter (ML, MLOps, visualization, deployment, ethics). Each includes platform-specific implementation notes.

**Building an AI/LLM application?** Chapter 13 and the Palantir AIP guide cover the current landscape. Read chapter 12 (Ethics and Governance) in parallel.

Every chapter includes working Python code examples and hands-on exercises with solutions.

---

## Local Development Environment

This handbook ships with a Docker Compose stack that mirrors federal platform constraints locally — Jupyter, MLflow, PostgreSQL, Redis, Nginx, Prometheus, Grafana, and CAC/PIV authentication services.

See [docs/LOCAL_ENVIRONMENT.md](docs/LOCAL_ENVIRONMENT.md) for setup instructions.

---

## Technology Stack

Python (pandas, scikit-learn, XGBoost, PyTorch, MLflow, Delta Lake) · R (where platform-supported) · Docker and Docker Compose · MLflow · Delta Lake · GitHub Actions · CAC/PIV authentication · DoD Impact Level compliance (IL2, IL4, IL5) · NIST AI RMF · DoD AI Ethics Principles

---

## Contributing

Contributions that improve accuracy, add platform-specific detail, or extend coverage are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## License

This repository uses a dual license structure:

- **Code** (`.py`, `.sh`, `.yml`, `.yaml`, `Dockerfile*`): [MIT License](LICENSE)
- **Written content** (`chapters/`, `platform-guides/`, `docs/` — `.md` files): [Creative Commons Attribution 4.0 International (CC BY 4.0)](LICENSE)

You can use the code freely; you can share, adapt, and build on the written content with attribution. See [LICENSE](LICENSE) for full terms.

Content is based on publicly available information about the platforms it covers. Nothing in this repository is classified or export-controlled. Platform-specific details reflect publicly documented capabilities as of early 2026.
