# Data Science Learning Handbook

A practitioner's guide to data science on federal government platforms. Thirteen chapters covering the full data science lifecycle — environment setup through generative AI — grounded in how the work actually gets done on Advana, Qlik, Databricks, Navy Jupiter, and Palantir AIP/Foundry.

This is the book a senior practitioner would hand to someone on their first day on a DoD contract and say: read this, everything you need is in here.

---

## Table of Contents

### Chapters

| # | Title | Words |
|---|-------|------:|
| [01](chapters/01-introduction/README.md) | Introduction to Data Science in Government | 5,127 |
| [02](chapters/02-python-r-foundations/README.md) | Python and R Foundations for Federal Platforms | 4,908 |
| [03](chapters/03-data-acquisition/README.md) | Data Acquisition and Government Data Sources | 5,614 |
| [04](chapters/04-data-wrangling/README.md) | Data Wrangling and Cleaning | 5,193 |
| [05](chapters/05-exploratory-analysis/README.md) | Exploratory Data Analysis | 4,343 |
| [06](chapters/06-supervised-ml/README.md) | Supervised Machine Learning on Federal Platforms | 4,462 |
| [07](chapters/07-unsupervised-ml/README.md) | Unsupervised Machine Learning | 5,012 |
| [08](chapters/08-deep-learning/README.md) | Deep Learning and Neural Networks | 7,092 |
| [09](chapters/09-mlops/README.md) | MLOps and Production Pipelines | 5,951 |
| [10](chapters/10-visualization/README.md) | Visualization and Dashboards | 4,996 |
| [11](chapters/11-deployment/README.md) | Deployment and Scaling | 4,593 |
| [12](chapters/12-ethics-governance/README.md) | Ethics, Governance, and Compliance for Federal AI | 5,722 |
| [13](chapters/13-advanced-topics/README.md) | Advanced Topics — GenAI, RAG, and LLMs on Federal Platforms | 4,933 |

### Platform Guides

| Platform | Words |
|----------|------:|
| [Advana](platform-guides/advana/README.md) | 5,041 |
| [Qlik](platform-guides/qlik/README.md) | 6,398 |
| [Databricks](platform-guides/databricks/README.md) | 5,805 |
| [Navy Jupiter](platform-guides/navy-jupiter/README.md) | 5,322 |
| [Palantir AIP / Foundry](platform-guides/palantir-aip-foundry/README.md) | 5,864 |

---

## Chapter Summaries

**Chapter 01 — Introduction to Data Science in Government** (5,127 words)
The federal data environment is not commercial: clearances, CAC authentication, Impact Levels, ATO processes, and ITAR constraints shape everything before you write a single line of code. This chapter orients practitioners who are new to government work or new to DoD specifically.

**Chapter 02 — Python and R Foundations for Federal Platforms** (4,908 words)
Package approval queues, air-gapped pip mirrors, conda environments on IL4/IL5 systems, and R setup on platforms that barely tolerate it. Covers the practical realities of getting a working Python or R environment on each of the five platforms.

**Chapter 03 — Data Acquisition and Government Data Sources** (5,614 words)
Where federal data actually lives — USASpending, GCSS-Army, DMDC, MILSTRIP, GFEBS — and how to get to it. REST APIs, JDBC connections, Advana's data catalog, and the reality of 847-Excel-file data drops from SharePoint. Platform-specific ingestion patterns for all five environments.

**Chapter 04 — Data Wrangling and Cleaning** (5,193 words)
Forty-seven million rows of DoD procurement data and a program office that called it "analysis-ready." Covers pandas, Spark, and Databricks Delta Lake at scale, with platform-specific patterns for schema inference failures, null handling in classified columns, and the fiscal year boundary problem every government analyst eventually hits.

**Chapter 05 — Exploratory Data Analysis** (4,343 words)
EDA without a data dictionary, with columns whose definitions changed mid-dataset, on a platform that may not let you run a Jupyter notebook interactively. Profiling tools, anomaly detection as a first-pass QA step, and how to present findings to a program office that has never seen a box plot.

**Chapter 06 — Supervised Machine Learning on Federal Platforms** (4,462 words)
Building a binary classifier on Navy supply requisitions: feature engineering on MILSTRIP data, gradient-boosted trees on Databricks, and what "94% accuracy" actually means when the program manager puts it in the admiral's briefing slides. Covers scikit-learn, XGBoost, and platform-specific ML runtimes across all five environments.

**Chapter 07 — Unsupervised Machine Learning** (5,012 words)
Anomaly detection on GFEBS financial transactions, k-means clustering on readiness data, and the problem with an isolation forest that flags the same nineteen transactions every morning. Covers the operational framing that turns an unsupervised result into an actionable finding rather than a pile of cluster numbers.

**Chapter 08 — Deep Learning and Neural Networks** (7,092 words)
Object detection on drone video at 30 fps across four simultaneous feeds with a 400ms inference budget — this is the chapter for practitioners who need deep learning in constrained, real-time federal environments. GPU access patterns on each platform, model compression, ONNX export, and compliance constraints on neural network deployment at IL4/IL5.

**Chapter 09 — MLOps and Production Pipelines** (5,951 words)
The model got its ATO on Tuesday. By Wednesday of the following week, the maintenance chief was on a conference call asking why it was confidently wrong. Covers MLflow, model registries, drift detection, retraining triggers, and the specific ATO implications of updating a model that is already in production on a federal system.

**Chapter 10 — Visualization and Dashboards** (4,996 words)
A lieutenant commander spent three days building the dashboard that was supposed to change how the admiral thought about readiness. He had forty minutes and asked one question the dashboard couldn't answer. This chapter covers Qlik, Advana dashboards, Databricks SQL, and the design principles that separate briefing-ready visualizations from data art.

**Chapter 11 — Deployment and Scaling** (4,593 words)
Getting a model from a notebook into production on a federal platform means containers, artifact registries, API gateways, and an ATO process that treats every deployment as a new risk event. Docker, Kubernetes on GovCloud, Advana's deployment patterns, and Databricks Model Serving — with the compliance documentation that each platform requires.

**Chapter 12 — Ethics, Governance, and Compliance for Federal AI** (5,722 words)
An attrition prediction model ran for eleven months before anyone asked whether it should have been deployed in the first place. Covers DoD AI Ethics Principles, NIST AI RMF, bias auditing on sensitive demographic attributes, Executive Order 13960/14110 compliance requirements, and what responsible AI governance looks like on an active DoD program — not just in the policy document.

**Chapter 13 — Advanced Topics: GenAI, RAG, and LLMs on Federal Platforms** (4,933 words)
Eleven intelligence summaries from eleven theater commands, none of them searchable the way CTRL+F is not a retrieval strategy. Covers retrieval-augmented generation at IL4/IL5, Palantir AIP Logic, fine-tuning constraints on classified data, and the practical gap between what commercial LLMs can do and what federal programs can actually deploy.

---

## Platform Guides

**[Advana](platform-guides/advana/README.md)** (5,041 words)
The DoD Enterprise Data Analytics platform — JupyterHub, Qlik, and over 100 integrated DoD data sources under one IL4/IL5 roof. Setup, CAC/PIV authentication, data catalog navigation, analytics environments, and the access request process that new contractors consistently underestimate.

**[Qlik](platform-guides/qlik/README.md)** (6,398 words)
Associative engine analytics for federal BI — why selecting a dimension in Qlik reveals relationships instead of filtering rows, how Qlik Sense apps are structured, data load scripting, and deployment patterns across on-premise NIPRNet, Advana-hosted, and GovCloud environments.

**[Databricks](platform-guides/databricks/README.md)** (5,805 words)
Unified analytics on AWS GovCloud and Azure Government: Unity Catalog, Delta Lake, MLflow, and the row-level security behavior that changed in 2025 and cost one Navy program a compliance exposure. Covers cluster configuration, notebook workflows, and the migration patterns from legacy Hive Metastore.

**[Navy Jupiter](platform-guides/navy-jupiter/README.md)** (5,322 words)
The Department of the Navy's enterprise data platform — access patterns, data tier structure (bronze/silver/gold), Navy-specific data sources (MILSTRIP, OPNAV, maintenance records), and the platform constraints that make commercial analytics patterns fail in ways that are hard to debug without this guide.

**[Palantir AIP / Foundry](platform-guides/palantir-aip-foundry/README.md)** (5,864 words)
Foundry's Ontology model is a different mental model than any other analytics platform: objects, properties, links, and actions replace tables and joins. Covers Foundry data integration, Pipeline Builder, AIP Logic for LLM-powered workflows, and the access control model that makes Palantir the choice for programs with complex multi-classification data requirements.

---

## Quick Start

**If you are new to federal data science:** Read chapters 1 through 4 in order. They cover the environment, the access model, where data lives, and how to work with it. Everything downstream builds on those foundations.

**If you are switching platforms:** Go directly to the platform guide for your new environment. Platform guides are self-contained references — setup through deployment, with code examples for the patterns you will use most.

**If you need a specific capability:** The chapter on that topic (ML, MLOps, visualization, deployment, ethics) is the right entry point. Each chapter includes platform-specific implementation notes so you can apply the concept in your actual environment.

**If you are building an AI or LLM application on a federal platform:** Chapter 13 and the Palantir AIP guide cover the current landscape. Read chapter 12 (Ethics and Governance) in parallel — compliance requirements for AI applications are not an afterthought in this environment.

Every chapter includes working Python code examples and a hands-on exercises directory with solutions. The code is written to run on the platforms it describes, not on a local machine with unconstrained internet access.

---

## Project Stats

| Metric | Count |
|--------|------:|
| Chapters | 13 |
| Platform guides | 5 |
| Total words (chapters) | 67,946 |
| Total words (platform guides) | 28,430 |
| Exercise / solution content | included |
| **Total words** | **96,376** |
| Python files | 41 |
| Exercise sets with solutions | 13 (67 exercises total) |
| Platforms covered | 5 |

---

## Technology Stack

**Languages**
- Python (primary) — pandas, scikit-learn, XGBoost, PyTorch, MLflow, Delta Lake
- R (secondary) — covered where platform-supported

**Platforms**
- Advana (DoD Enterprise, IL4/IL5)
- Qlik Sense (government deployment patterns)
- Databricks (AWS GovCloud / Azure Government)
- Navy Jupiter (Department of the Navy)
- Palantir AIP / Foundry

**Infrastructure**
- Docker and Docker Compose (local development environments mirroring platform constraints)
- MLflow (experiment tracking and model registry)
- Delta Lake (lakehouse storage format)
- GitHub Actions (CI/CD for content validation)

**Security and Compliance**
- CAC/PIV authentication integration examples
- DoD Impact Level constraint documentation (IL2, IL4, IL5)
- ATO process guidance for model deployment
- NIST AI RMF and DoD AI Ethics compliance patterns

**Validation**
- Automated content validation framework (`validation/`)
- Style guide enforcement (AI writing anti-pattern detection)
- Cross-reference link checking

---

## Contributing

This handbook is written for practitioners in federal data science environments. Contributions that improve accuracy, add platform-specific detail, or extend coverage to new topics are welcome.

Before contributing content:
1. Read `docs/STYLE_GUIDE.md` — the voice guide is non-negotiable. Content that reads like a blog post or a textbook does not fit this handbook.
2. Read `docs/CHAPTER_WRITING_SPEC.md` — covers structure, code example requirements, and exercise format.
3. Run the validation framework against your contribution: `python validation/validate_content.py`

Pull requests that introduce placeholder text, banned phrases from the style guide, or generic examples disconnected from federal platform realities will be rejected at review.

---

## License

This repository uses a dual license structure:

- **Code** (`.py`, `.sh`, `.yml`, `.yaml`, `Dockerfile*`): [MIT License](LICENSE)
- **Written content** (`chapters/`, `platform-guides/`, `docs/` — `.md` files): [Creative Commons Attribution 4.0 International (CC BY 4.0)](LICENSE)

In short: you can use the code in your own projects freely; you can share, adapt, and build on the written content as long as you give attribution. See [LICENSE](LICENSE) for full terms and the complete text of both licenses.

Content in this handbook is based on publicly available information about the platforms it covers. Nothing in this repository is classified or export-controlled. Platform-specific implementation details reflect publicly documented capabilities as of early 2026.
