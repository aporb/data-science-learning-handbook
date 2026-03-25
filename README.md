[![License: MIT + CC BY 4.0](https://img.shields.io/badge/License-MIT%20%2B%20CC%20BY%204.0-blue.svg)](LICENSE)
[![Stars](https://img.shields.io/github/stars/aporb/data-science-learning-handbook?style=social)](https://github.com/aporb/data-science-learning-handbook)
[![Last Commit](https://img.shields.io/github/last-commit/aporb/data-science-learning-handbook)](https://github.com/aporb/data-science-learning-handbook/commits/main)
[![Python 3.11+](https://img.shields.io/badge/Python-3.11%2B-3776AB?logo=python&logoColor=white)](https://python.org)
[![Agent-Ready](https://img.shields.io/badge/Agent--Ready-Claude%20%7C%20Cursor%20%7C%20OpenCode%20%7C%20Cline-00B87C?logo=robot&logoColor=white)](#-agent-ready--works-with-your-ai-coding-agent)

# Federal Data Science Handbook

**A practitioner's guide to data science on federal government platforms — and the first reference resource for a regulated domain designed to work natively with AI coding agents.**

**[Read online](https://aporb.github.io/federal-ds-handbook-site/)** · **[Chapters](#chapters)** · **[Platform Guides](#platform-guides)** · **[Agent Commands](#-agent-ready--works-with-your-ai-coding-agent)** · **[Docker Environment](#local-development-environment)**

---

<table>
<tr>
<td align="center"><strong>96K+</strong><br>Words</td>
<td align="center"><strong>13</strong><br>Chapters</td>
<td align="center"><strong>43</strong><br>Python Files</td>
<td align="center"><strong>5</strong><br>Platforms</td>
<td align="center"><strong>4</strong><br>Agent Platforms</td>
<td align="center"><strong>67</strong><br>Exercises</td>
</tr>
</table>

---

## The Problem

We spend billions on federal data platforms. We hire analysts with degrees and certifications. And then we hand them a login and tell them to figure it out.

Commercial tutorials assume you have `pip install`, unrestricted internet access, and a cloud account you control. None of that is true in a DoD environment where CAC authentication, Impact Level restrictions, ATO processes, and air-gapped networks shape every technical decision.

The average federal data analyst spends their first six months learning the platform, not doing the mission work. That's a capability gap and an absurd waste of money.

**This handbook closes it.** Thirteen chapters covering the full data science lifecycle — environment setup through generative AI — grounded in how the work actually gets done on the five platforms where federal data science happens. Every code example is written to run in the constrained environments it describes, not on a local machine with unconstrained internet.

---

## 🤖 Agent-Ready — Works With Your AI Coding Agent

Clone this repo. Open it in Claude Code, Cursor, OpenCode, or Cline. Your AI agent now understands clearances, platform constraints, and compliance requirements — without you explaining them.

We believe this is the first reference resource for a regulated industry domain that ships native, multi-platform AI agent configuration — slash commands, workflow definitions, and structured context files — alongside the knowledge itself. If we're wrong, [we want to know](https://github.com/aporb/data-science-learning-handbook/issues).

### What your agent gets

| Capability | What It Does |
|-----------|-------------|
| **`/compliance-check`** | Reviews your code against NIST 800-53, DoD AI Ethics, FedRAMP, and IL requirements. Outputs a structured severity table with remediation pointing to specific handbook sections. |
| **`/generate-federal-code`** | Generates platform-appropriate Python with correct headers, security patterns, and IL-level constraints. Knows that Databricks doesn't allow pip install in cells, that Foundry uses `palantir_models`, and that IL4+ means no external API calls. |
| **`/teach`** | Interactive tutor mode. Opens with the chapter's narrative hook, walks through concepts with code, tracks which learning objectives you've covered. |

### Supported platforms

| AI Coding Agent | Config File | Auto-loaded? |
|----------------|-------------|-------------|
| **Claude Code** | `CLAUDE.md` + `.claude/commands/` | Yes — on session start |
| **Cursor** | `.cursorrules` | Yes — on project open |
| **OpenCode** | `.opencode/config.yaml` + `.opencode/commands/` | Yes — on project open |
| **Cline** | `.clinerules/` + `.clinerules/workflows/` | Yes — on session start |
| **Any agent** | `AGENTS.md` | Read on first query |

**How it works:** The agent interface layer encodes 96,000 words of non-inferable federal domain knowledge into structured context files — what Impact Level means, why IL4+ prohibits external API calls, what CAC/PIV authentication requires, which packages are available on each platform. Your agent doesn't need to hallucinate or ask you to explain your environment. It reads the handbook.

---

## Chapters

| # | Title | What You'll Learn |
|---|-------|-------------------|
| [01](chapters/01-introduction/README.md) | **Introduction to Data Science in Government** | Clearances, CAC auth, Impact Levels, ATO — everything that shapes the work before you write code |
| [02](chapters/02-python-r-foundations/README.md) | **Python and R Foundations** | Air-gapped pip mirrors, conda on IL4/IL5, and the reality of getting a working environment on each platform |
| [03](chapters/03-data-acquisition/README.md) | **Data Acquisition** | Where federal data lives — USASpending, SAM.gov, data.gov — and how to pull it programmatically |
| [04](chapters/04-data-wrangling/README.md) | **Data Wrangling and Cleaning** | 47 million rows of procurement data that a program office called "analysis-ready" — pandas, Spark, and Delta Lake at scale |
| [05](chapters/05-exploratory-analysis/README.md) | **Exploratory Data Analysis** | EDA without a data dictionary, on a platform that may not support interactive notebooks |
| [06](chapters/06-supervised-ml/README.md) | **Supervised Machine Learning** | Building classifiers on DoD data: feature engineering on MILSTRIP, XGBoost on Databricks, and what accuracy means in a briefing |
| [07](chapters/07-unsupervised-ml/README.md) | **Unsupervised Machine Learning** | Anomaly detection on GFEBS transactions, clustering readiness data, and turning unsupervised results into actionable findings |
| [08](chapters/08-deep-learning/README.md) | **Deep Learning and Neural Networks** | Object detection on drone video at 30fps with a 400ms inference budget — deep learning in constrained federal environments |
| [09](chapters/09-mlops/README.md) | **MLOps and Production Pipelines** | MLflow, model registries, drift detection, and the ATO implications of updating a production model |
| [10](chapters/10-visualization/README.md) | **Visualization and Dashboards** | Qlik, Advana dashboards, Databricks SQL — design principles that separate briefing-ready visuals from data art |
| [11](chapters/11-deployment/README.md) | **Deployment and Scaling** | Containers, artifact registries, API gateways, and an ATO process that treats every deployment as a risk event |
| [12](chapters/12-ethics-governance/README.md) | **Ethics, Governance, and Compliance** | DoD AI Ethics Principles, NIST AI RMF, bias auditing, and what responsible AI governance looks like on an active program |
| [13](chapters/13-advanced-topics/README.md) | **Advanced Topics — GenAI, RAG, and LLMs** | RAG at IL4/IL5, Palantir AIP Logic, fine-tuning on classified data, and the gap between commercial LLMs and federal deployments |

Every chapter includes working Python code examples and hands-on exercises with solutions.

---

## Platform Guides

| Platform | IL Levels | What It Covers |
|----------|-----------|---------------|
| [**Advana**](platform-guides/advana/README.md) | IL4, IL5 | DoD enterprise analytics — JupyterHub, Qlik, 100+ data sources, 100K+ users |
| [**Databricks**](platform-guides/databricks/README.md) | IL2–IL5 | Unity Catalog, Delta Lake, MLflow on AWS GovCloud and Azure Government |
| [**Navy Jupiter**](platform-guides/navy-jupiter/README.md) | IL4, IL5 | Department of the Navy — bronze/silver/gold data tiers, Navy-specific constraints |
| [**Palantir AIP / Foundry**](platform-guides/palantir-aip-foundry/README.md) | IL4–IL6 | Ontology-based analytics, Pipeline Builder, AIP Logic for LLM workflows |
| [**Qlik**](platform-guides/qlik/README.md) | IL2, IL4 | Associative engine for federal BI — NIPRNet, Advana-hosted, and GovCloud |

Each guide is self-contained: access, setup, development environment, code patterns, and deployment.

---

## Quick Start

**New to federal data science?** Read chapters 1 through 4 in order. They cover the environment, access model, where data lives, and how to work with it.

**Switching platforms?** Go directly to the platform guide for your new environment. Each is self-contained.

**Need a specific capability?** Jump to the relevant chapter (ML, MLOps, visualization, deployment, ethics). Each includes platform-specific implementation notes.

**Building an AI/LLM application?** Chapter 13 and the Palantir AIP guide cover the current landscape. Read chapter 12 (Ethics and Governance) in parallel.

**Using an AI coding agent?** Clone this repo, open it in your agent's IDE, and use the [pre-built commands](#-agent-ready--works-with-your-ai-coding-agent) above. The agent picks up context automatically.

---

## Local Development Environment

This handbook ships with a Docker Compose stack that mirrors federal platform constraints locally:

| Service | Port | Purpose |
|---------|------|---------|
| Jupyter | 8888 | Development notebooks (+ Streamlit, Dash) |
| MLflow | 5000 | Experiment tracking and model registry |
| PostgreSQL | 5432 | Relational database |
| Redis | 6379 | Caching and session store |
| Nginx | 80/443 | Reverse proxy with TLS |
| Prometheus | 9090 | Metrics collection |
| Grafana | 3000 | Monitoring dashboards |
| Vault | 8200 | Secret management |
| CAC-auth | 8001 | CAC/PIV authentication simulator |

```bash
cp .env.example .env && docker compose up -d
```

See [docs/LOCAL_ENVIRONMENT.md](docs/LOCAL_ENVIRONMENT.md) for full setup instructions.

---

## Security Compliance Reference

The `security-compliance/` directory contains reference implementations for federal security patterns — not toy examples, but working code for:

- **CAC/PIV authentication** with PKCS#11 smart card integration and OAuth bridging
- **RBAC/ABAC** with MAC enforcement (Bell-LaPadula), role hierarchies, and database-backed permission resolution
- **FIPS 140-2 encryption** with AES-256 at rest, TLS 1.3 in transit, and HSM key management
- **NIST 800-53 compliance** with automated control assessment, evidence collection, and reporting
- **Audit logging** with immutable trails and 7-year retention policies

See [security-compliance/CLAUDE.md](security-compliance/CLAUDE.md) for a module-by-module guide.

---

## Who This Is For

- **Junior analysts** onboarding to any of the five platforms — skip the 18-month learning curve
- **Team leads** building data science practices inside DoD programs
- **GovCon firms** winning data task orders and needing to stand up teams fast
- **AI coding agent users** who want their agent to understand federal constraints without re-explaining them every session
- **Anyone** who's ever said "I can't find good training for [federal platform]"

---

## Contributing

Contributions that improve accuracy, add platform-specific detail, or extend coverage are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## License

- **Code** (`.py`, `.sh`, `.yml`, `.yaml`, `Dockerfile*`): [MIT License](LICENSE)
- **Written content** (`chapters/`, `platform-guides/`, `docs/`): [Creative Commons Attribution 4.0 International (CC BY 4.0)](LICENSE)

Content is based on publicly available information. Nothing in this repository is classified or export-controlled. Platform-specific details reflect publicly documented capabilities as of early 2026.

---

**[Read online](https://aporb.github.io/federal-ds-handbook-site/)** · **[Star this repo](https://github.com/aporb/data-science-learning-handbook)** · **[Report an issue](https://github.com/aporb/data-science-learning-handbook/issues)**
