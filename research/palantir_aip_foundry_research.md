# Palantir AIP and Foundry: Government/Federal Research Report
**Compiled:** March 2026
**Scope:** Publicly available information only

---

## Table of Contents

1. [Palantir Foundry Overview](#1-palantir-foundry-overview)
2. [Palantir AIP (Artificial Intelligence Platform)](#2-palantir-aip-artificial-intelligence-platform)
3. [Government Deployment: Security Authorizations](#3-government-deployment-security-authorizations)
4. [Government Contracts and Agency Adoption](#4-government-contracts-and-agency-adoption)
5. [Data Science Workflows in Foundry](#5-data-science-workflows-in-foundry)
6. [Public Documentation and Learning Resources](#6-public-documentation-and-learning-resources)
7. [Platform Comparisons](#7-platform-comparisons)
8. [Recent Developments (2025–2026)](#8-recent-developments-20252026)
9. [Key Takeaways for Data Scientists](#9-key-takeaways-for-data-scientists)
10. [Sources](#10-sources)

---

## 1. Palantir Foundry Overview

### What Is Foundry?

Palantir Foundry is described as the "operating system for the modern enterprise." It is a data integration, analytics, and operational platform designed for the most complex environments in the world — including commercial enterprises, civil government, and (alongside Gotham) defense/intelligence. Foundry serves as the central data integration backbone for organizations.

Foundry creates a central system for an organization's data, enabling:
- Seamless data integration from disparate sources
- Flexible analytics and visualization
- Model building and ML deployment
- Operational decision-making (not just reporting)

### Foundry vs. Gotham

Palantir has two core platforms aimed at different user bases:

| Dimension | Palantir Foundry | Palantir Gotham |
|---|---|---|
| Primary market | Commercial enterprises, civil government | Defense, intelligence, law enforcement |
| Core use case | Data integration, enterprise analytics, program management | Intelligence fusion, targeting, counter-terrorism analysis |
| Launched | ~2016 | 2008 |
| Government examples | DHS, HHS, NIH, NASA, Justice Dept | DoD, IC (classified) |
| Data metaphor | Datasets, pipelines, ontology layer | Linked intelligence profiles, graph networks |

**Note:** Both platforms share the Ontology layer, AIP, and Apollo delivery infrastructure. The $10B Army Enterprise Agreement (2025) covers both Foundry and Gotham under one framework.

---

### The Ontology: Foundry's Core Concept

The **Palantir Ontology** is the semantic/operational layer at the heart of Foundry. It sits on top of integrated data assets (datasets, virtual tables, models) and connects them to their real-world counterparts.

**Components of the Ontology:**

- **Object Types** — Schema definitions of real-world entities (e.g., "Aircraft," "Patient," "Supplier"). Analogous to a table definition in a relational database.
- **Objects** — Individual instances of an object type. Analogous to a row in a table.
- **Properties** — Characteristics of object types (e.g., an Airport has `name`, `IATA_code`, `country`). Analogous to columns.
- **Link Types** — Relationships between object types (e.g., "Pilot flies Aircraft"). Analogous to a foreign-key join between tables.
- **Links** — Instances of those relationships (e.g., "Lt. Smith flew F-35 #104 on 2025-01-15").
- **Actions** — Defined sets of changes or edits to the Ontology that users can trigger (e.g., "Approve Purchase Order"). Actions enable writeback and decision capture.
- **Functions** — Business logic authored in TypeScript that can run arbitrary computations on Ontology data.

**Why it matters:** The Ontology creates a "digital twin" of the organization. When an LLM (via AIP) interacts with your data, it does so through the Ontology — grounded in semantics defined by your organization, not hallucinating from raw tables. This is Palantir's core architectural differentiator.

---

### Data Integration

Foundry supports all types of source systems:
- **Structure types:** Structured, unstructured, and semi-structured data
- **Transfer patterns:** Batch, micro-batch, and streaming
- **Connectors:** 200+ prebuilt connectors to ERP systems, IoT feeds, databases, and APIs
- **Pipeline management:** Change management, data quality, and data loading features combined

**Pipeline Builder** is the primary no-code/low-code interface for building and managing data pipelines:
- Provides a visual node-based interface for transforms
- Supports join, union, filter, cast, rename, and geospatial transform nodes
- As of May 2025: new expressions for media set transforms (convert images to documents, split PDFs, etc.)
- Can invoke LLMs directly in a pipeline via the "Use LLM" node
- Backed by full scheduling, versioning, and lineage tracking

---

### Foundry Applications Layer

After data is integrated and modeled in the Ontology, Foundry provides several user-facing applications:

- **Object Explorer** — Search and browse Ontology objects; starting point for investigations
- **Quiver** — Point-and-click analytics on object and time-series data; no-code charts, filters, parameterized analyses; integrates with a proprietary time-series database for high-frequency signals
- **Workshop** — Low-code operational application builder; builds dashboards and decision-support tools backed by the Ontology; supports writeback via Actions
- **Slate** — Custom HTML/CSS/JavaScript application builder for advanced UX needs
- **Foundry Maps** — Geospatial visualization and analysis

---

## 2. Palantir AIP (Artificial Intelligence Platform)

### What Is AIP?

Palantir's **Artificial Intelligence Platform (AIP)** connects AI — specifically large language models and AI agents — to real organizational data and operations. AIP is not a standalone product; it is a layer on top of Foundry (and Gotham), integrating LLMs into the Ontology-based data environment.

AIP is described as powering "real-time, AI-driven decision-making in the most critical commercial and government contexts around the world."

### Key AIP Components

#### AIP Logic

AIP Logic is a no-code development environment for building LLM-powered functions without writing API calls or managing model infrastructure.

- **Use LLM Block:** The core building block; supports any LLM available on the platform (Palantir's "k-LLM philosophy" means model-agnostic)
- **Tools:** The mechanism by which AIP Logic lets the LLM interact with the Ontology:
  - **Data tools** — Read from the Ontology (query objects, properties, links)
  - **Logic tools** — Execute Foundry Functions
  - **Action tools** — Write back to the Ontology (take real-world actions safely)
- AIP Logic enables testing, iteration, and release of LLM-powered functions integrated into Workshop applications

#### AIP Agent Studio

AIP Agent Studio allows users to build **interactive AI agents** (conversational assistants with memory, tools, and context) that are:
- Equipped with enterprise-specific data and tools from the Ontology
- Deployable internally within Foundry applications
- Deployable externally via the Ontology SDK (OSDK) and platform APIs

Agents can be embedded into Workshop applications for dynamic, context-aware workflows that automate tasks and reduce manual work.

#### AIP Machinery (February 2025)

A process automation tool. Users create multi-step automated processes in Machinery, then build custom Workshop applications to:
- Supervise AIP workflows in real time
- Bring humans into the loop for manual decision points
- Iterate on process inefficiencies to increase automation over time

#### AI FDE — AI Forward Deployed Engineer (November 2025, Beta)

A conversational agent that operates Foundry itself through natural language. AI FDE allows users to:
- Write transforms and build datasets
- Create and modify Ontology object types, link types, action types, and interfaces
- Write, preview, and publish Functions
- Perform complex multi-step Foundry operations through continuous feedback loops

AI FDE requires AIP to be enabled on the Foundry enrollment. This represents Palantir's push toward LLM-native platform interaction.

---

### LLM Support and the k-LLM Philosophy

Palantir's AIP is deliberately **model-agnostic**. It supports multiple LLMs simultaneously (hence "k-LLM"), including:
- OpenAI GPT-4 and variants (via Azure OpenAI Service in classified environments)
- Anthropic Claude (noted as the AI model underlying Maven Smart System)
- Other LLMs available on the platform

This allows government customers to select models appropriate for their classification level and policy requirements, and to swap models without rewriting their AIP Logic or agent implementations.

---

### AIP Bootcamp

A primary go-to-market mechanism for AIP adoption. The **AIP Bootcamp** is a 5-day intensive workshop where prospective customers build functional AI use cases on their own data, with Palantir engineers present.

- Achieves approximately 75% conversion rate to paid contracts
- Compresses sales cycles from ~12 months to days
- Available for both commercial and federal government customers
- Carahsoft (a major federal IT distributor) offers AIP Bootcamp scheduling for government agencies

---

## 3. Government Deployment: Security Authorizations

### FedRAMP Authorization History

| Authorization | Date | Notes |
|---|---|---|
| FedRAMP Moderate | Prior to 2024 | Earlier baseline |
| DoD IL4 | Prior to 2024 | On Microsoft Azure |
| DoD IL5 | Prior to 2024 | On Microsoft Azure |
| **FedRAMP High** | **December 2024** | Full product suite coverage |
| IL6 (in progress via FedStart) | Planned | Ongoing |

**December 2024: FedRAMP High Baseline Authorization**

Palantir received FedRAMP High Authorization for:
- **Palantir Federal Cloud Service (PFCS)** — Covers AIP, Apollo, Foundry, Gotham, and supporting products for federal government customers as a cloud service
- **Palantir Federal Cloud Service - Supporting Services (PFCS-SS)** — Best-of-breed commercial software delivered at FedRAMP High to federal customers

This single authorization covers the **entirety of Palantir's product offerings**: AIP, Apollo, Foundry, Gotham, FedStart, and Mission Manager.

---

### Microsoft Partnership for Classified Networks (August 2024)

In August 2024, Palantir and Microsoft announced a landmark partnership to bring AI and analytics to classified government networks:

- Palantir deploys **Foundry, Gotham, Apollo, and AIP** in:
  - Microsoft Azure Government
  - Azure Government Secret (DoD IL5 equivalent)
  - Azure Government Top Secret (DoD IL6)
- Palantir became the **first industry partner** to deploy Microsoft Azure OpenAI Service in classified environments
- Enables operators to use GPT-4 and other models within AIP in Secret and Top Secret environments for workloads like logistics, contracting, prioritization, and action planning

---

### Palantir FedStart Program

**FedStart** is a SaaS offering that allows third-party software companies (ISVs) to deploy their products to the federal government using Palantir's existing security accreditations — without needing to pursue their own separate FedRAMP or IL5 authorization.

- Runs ISV software within Palantir's secure, accredited environment
- Can reduce ATO (Authority to Operate) timelines from years to weeks or months
- Unlocks: FedRAMP Moderate, IL5 currently; FedRAMP High and IL6 in progress

**2025 FedStart Expansions:**
- **April 2025:** Anthropic joined FedStart to deploy Claude in government environments
- **April 2025:** Google Cloud announced integration with FedStart, streamlining FedRAMP High/IL5 accreditation for ISVs built on Google Cloud
- **August 2025:** Unstructured.io joined FedStart for AI-ready data solutions at FedRAMP High and IL5
- FedStart is available on both AWS Marketplace and Microsoft Azure Marketplace

---

## 4. Government Contracts and Agency Adoption

### U.S. Army — $10 Billion Enterprise Agreement (July/August 2025)

The single largest and most significant Palantir government contract to date:

- **Value:** Up to $10 billion over 10 years
- **Scope:** Consolidated 75 separate contracts (15 prime + 60 related) into one enterprise framework
- **Platforms covered:** Foundry, Gotham, and related data/AI capabilities
- **Benefits:** Volume-based discounts; available to other DoD components beyond Army
- Managed under a new "Enterprise Service Agreement" model that accelerates software delivery to warfighters while removing contractor pass-through fees

---

### Pentagon — Maven Smart System Program of Record (March 2026)

Palantir's **Maven Smart System** was designated a Pentagon "Program of Record" in March 2026, per a memo from Deputy Defense Secretary Steve Feinberg:

- Provides stable, long-term funding and resourcing for development and integration
- Transfers oversight from the National Geospatial-Intelligence Agency to the DoD Chief Digital and Artificial Intelligence Office (CDAO)

**Maven Smart System capabilities (publicly known):**
- Command-and-control AI software platform
- Processes large volumes of battlefield data from satellites, radars, drones, sensors, and intelligence reports
- Identifies potential targets and threats (military vehicles, buildings, weapons stockpiles)
- Provides an operational map with friendly and enemy positions
- Supports natural language queries (e.g., "show me self-propelled artillery detections in this sector")
- Integrates ISR data fusion, asset tracking, and AI conversational agents

**NATO Adoption (March/April 2025):** NATO Communications and Information Agency (NCIA) acquired Palantir Maven Smart System NATO (MSS NATO) for employment within Allied Command Operations.

---

### Maven Smart System — DoD Contract Expansion

- DEVCOM Army Research Laboratory (ARL) awarded Palantir a contract to expand Maven Smart System access across Army, Air Force, Space Force, Navy, and Marine Corps
- May 2025: DoD boosted Maven Smart Systems contract by $795 million for AI capabilities
- January 2026: Palantir awarded a $240 million DoD contract for battlefield decision support

---

### U.S. Navy — ShipOS Contract ($448M, December 2025)

Palantir secured a $448 million contract to modernize shipbuilding supply chains, using Foundry and AI capabilities to accelerate Navy shipbuilding production.

---

### Additional Federal Civilian Agencies (2025)

Under the Trump administration, Palantir expanded into several civilian agencies:
- **National Institutes of Health (NIH)**
- **Department of Justice**
- **NASA**
- **Department of Health and Human Services (HHS)** — previously one of the earliest Foundry adopters
- **Department of Homeland Security (DHS)**

As of mid-2025, at least four U.S. federal agencies were using Foundry, including DHS and HHS.

---

### Accenture Federal Services Partnership (June 2025)

Palantir named Accenture Federal Services a preferred implementation partner for U.S. federal government customers:
- 1,000 Accenture Federal Data & AI professionals trained and certified on Foundry and AIP
- Creates a scaled delivery capability for federal agency deployments
- Focuses on deploying commercial-grade AI-powered solutions for federal operations

---

### Revenue Context

| Metric | Value |
|---|---|
| Q4 2025 U.S. Government Revenue | $570 million (66% YoY growth) |
| Full Year 2025 Government Revenue Growth | 53.1% YoY |
| FY2026 Total Revenue Guidance | 61% YoY growth |
| AIP Revenue Growth (2025 peak) | 74% YoY |

---

## 5. Data Science Workflows in Foundry

### Overview of Coding Environments

Foundry provides three distinct code-based development environments, each suited to different workflows:

| Environment | Best For | Languages | Notes |
|---|---|---|---|
| **Code Workbook** (Legacy) | Exploratory analysis, ad-hoc work | Python, R, SQL | Notebook-style; being deprecated in favor of Code Workspaces |
| **Code Repositories** | Production pipelines, data engineering | Python, Java, SQL | Full Git version control; production-grade transforms |
| **Code Workspaces** | ML model development, Jupyter workflows | Python (JupyterLab), R (RStudio) | Full IDE experience in the browser |

---

### Code Workbook (Legacy)

Code Workbook is a graphical, notebook-style interface for analyzing and transforming data in code. Note: Palantir documentation marks Code Workbook as "[Legacy]," signaling a transition to Code Workspaces.

**Supported languages:** Python 3.10, R, SQL (Spark SQL)

**Key features:**
- Pandas DataFrames as inputs/outputs for Python nodes
- Configurable Conda environments (can add packages like TensorFlow, Keras, etc.)
- Profile-based environment configuration for different team needs
- Every workbook is backed by a hidden Code Repository for version history
- Python and SQL code can be exported to a proper Code Repository for production use

---

### Code Repositories

The primary environment for production data engineering and pipeline work in Foundry.

**Supported languages:** Python, Java, SQL

**Key features:**
- Full Git version control (branches, commits, pull requests)
- Advanced pipelining tools (scheduling, dependencies, lineage)
- Integrates with Foundry's transform framework for dataset-backed pipelines
- Preferred for robust production ETL/ELT pipelines
- Can publish trained ML models to the Ontology

---

### Code Workspaces (JupyterLab / RStudio)

The modern, IDE-based data science environment in Foundry. Provides JupyterLab and RStudio within the browser.

**Key features:**
- **Jupyter Notebook support:** Train, develop, and publish ML models directly from notebooks
- **Model publishing:** Use the Models sidebar to create new models, register aliases, and generate code snippets for publishing
- **Foundry dataset access:** Import existing Foundry datasets as training data directly into the workspace
- **AIP Agent sidebar (November 2025):** An AI coding assistant accessible from the workspace sidebar, backed by any supported LLM, to help develop and deploy code
- **Snowflake integration (November 2025):** Read and write Snowflake tables, including Iceberg tables cataloged in Polaris

---

### ML Model Framework

Palantir has transitioned its model framework:
- **Deprecated (as of October 31, 2025):** `foundry_ml` library and dataset-backed models — no longer available
- **Current framework:** `palantir_models` library — all new ML work should use this

**Model workflow:**
1. Develop and train model in Code Workspaces (Jupyter) or Code Repositories
2. Publish model using `palantir_models` library
3. Model registered in Foundry's model management system
4. Model integrated into Ontology as a resource
5. Model can be called from AIP Logic, Functions, or downstream pipelines

---

### Data Science Workflow Summary

A typical data science workflow in Foundry looks like:

```
1. Data Integration (Pipeline Builder / Code Repositories)
   └─ Connect source systems → build transform pipelines → produce datasets

2. Ontology Modeling
   └─ Map datasets to object types, properties, and links
   └─ Define Actions and Functions for business logic

3. Exploratory Analysis
   └─ Object Explorer → search/browse objects
   └─ Quiver → no-code analytics and time-series analysis
   └─ Code Workspaces (Jupyter) → custom Python/R analysis

4. Model Development
   └─ Code Workspaces → train model with palantir_models
   └─ Publish model to Foundry model registry
   └─ Integrate model into Ontology or AIP Logic

5. AI/LLM Integration (AIP)
   └─ AIP Logic → build LLM-powered functions
   └─ Agent Studio → build conversational agents
   └─ Deploy via Workshop applications

6. Operational Application (Workshop)
   └─ Build dashboards and decision tools
   └─ Enable writeback via Actions
   └─ Deploy to end users
```

---

### Supported Analytical Patterns

- **Batch analytics:** Traditional aggregation and reporting on historical datasets
- **Streaming analytics:** Near-real-time data from event streams
- **Time-series analysis:** Quiver's dedicated time-series library with sensor/signal processing functions; proprietary high-frequency time-series database
- **Geospatial analytics:** Foundry Maps + Pipeline Builder geospatial transforms
- **ML inference:** Model hosting and serving within Foundry
- **LLM-powered analysis:** Via AIP Logic and Agent Studio

---

## 6. Public Documentation and Learning Resources

### Primary Documentation Site

**https://www.palantir.com/docs/foundry** — The main public documentation portal for Foundry, AIP, Apollo, and all platform components.

Major documentation sections (all publicly accessible):
- **Platform overview** — Architecture, core concepts, terminology
- **Data integration** — Connectors, pipeline management, ingestion patterns
- **Ontology** — Object types, link types, actions, functions, properties
- **AIP** — AIP Logic, Agent Studio, AIP features overview, capabilities
- **Code development** — Code Repositories, Code Workspaces, Code Workbook (legacy)
- **App building** — Workshop, Quiver, Object Explorer, Slate
- **API Reference** — REST API using OAuth 2.0; JSON request/response pattern
- **Administration** — Security, governance, enrollment settings
- **Announcements** — Monthly release notes (e.g., `palantir.com/docs/foundry/announcements/2025-11`)

### Learning Resources

- **learn.palantir.com** — Official Palantir learning platform with courses, tutorials, and speedruns (e.g., "Speedrun: Your First Agentic AIP Workflow")
- **Palantir Developer Community** — Community forums for technical questions
- **AIPCon** — Palantir's annual AI conference (palantir.com/aipcon)
- **Palantir Blog** — Technical deep-dives on platform capabilities and use cases
- Third-party resources: Unit8 (consulting firm with Foundry 101 guides), Medium/technical blog posts from practitioners

### API Access

The Foundry API is a REST API using OAuth 2.0 authentication. Key API capabilities:
- Ontology SDK (OSDK) for building external applications against the Ontology
- Dataset APIs for programmatic data access
- Action APIs for triggering write-back operations from external systems
- AIPCon Agent APIs for embedding agents in external applications

---

## 7. Platform Comparisons

### Palantir Foundry vs. Databricks

**Current relationship:** Strategic partners (as of March 2025) — not purely competitors.

| Dimension | Palantir Foundry | Databricks |
|---|---|---|
| Core metaphor | Ontology (semantic layer, objects, actions) | Lakehouse (Delta Lake tables, open format) |
| Primary strength | Deploying AI into operational workflows | Building and training AI/ML models at scale |
| Data format | Proprietary datasets + Virtual Tables | Open Delta Lake format (any tool can access) |
| Government presence | Deep FedRAMP, IL5, IL6 authorizations | Advana (DoD's large Databricks deployment) |
| No-code/low-code | Strong (Pipeline Builder, Workshop, AIP Logic) | Moderate (notebooks primary, some low-code features) |
| LLM integration | AIP (native, Ontology-grounded) | Mosaic AI (separate tooling) |

**March 2025 Partnership:** Databricks and Palantir announced zero-copy, bidirectional data integration:
- **Unity Catalog + Palantir Virtual Tables:** Data governed in Databricks registers directly in Foundry without ETL or duplication
- Joint customers include DoD, Dept. of Treasury, HHS, and commercial enterprises like bp
- Presented at Data + AI Summit 2025: "Bridging Ontologies & Lakehouses: Palantir AIP + Databricks for Secure Autonomous AI"

**Analyst perspective (William Blair):** Palantir and Databricks "rarely see each other in bidding situations" due to different use cases — Databricks for building AI, Palantir for deploying AI into operations.

---

### Palantir Foundry vs. Advana (DoD)

**Advana** is the DoD's Chief Digital and Artificial Intelligence Office (CDAO)-managed analytics platform, built on Databricks and other tools. It has approximately 80,000 DoD users.

| Dimension | Palantir Foundry/Gotham | Advana |
|---|---|---|
| Owner | Private company (Palantir) | DoD CDAO (government-managed) |
| Built on | Palantir's proprietary stack | Databricks + ecosystem tools |
| Primary purpose | AI-enabled decision-making, intelligence | Data analytics, enterprise reporting |
| Scale | Agency/mission-specific deployments | Enterprise DoD (~80K users) |
| Current strategy | Enterprise agreements (Army $10B deal) | Open DAGIR (multi-vendor) |

**Open DAGIR (DoD strategy):** DoD's "Open Data, Analytics, and AI/ML Government-wide Integration Repository" initiative explicitly promotes multi-vendor interoperability — meaning Palantir and Advana/Databricks are expected to coexist and integrate rather than compete for a single winner.

---

### Palantir Foundry vs. Qlik

| Dimension | Palantir Foundry | Qlik |
|---|---|---|
| Primary purpose | Data integration + AI operations platform | Data integration, analytics, BI |
| Target market | Government, defense, large enterprise | Broader enterprise (all industries) |
| Gartner rating | 4.6/5 (61 reviews) | 4.4/5 (465 reviews) |
| Government focus | Deep (FedRAMP High, IL5, IL6) | Limited government security authorizations |
| Operational AI | Core capability (AIP) | Limited |
| Data integration | Strong (200+ connectors, Pipeline Builder) | Strong (Qlik Talend Cloud ETL) |

**Key difference:** Qlik is primarily a BI/analytics tool; Palantir is an end-to-end data-to-decision platform with deep AI integration. Qlik does not have the Ontology/semantic layer or the defense-grade security infrastructure.

---

## 8. Recent Developments (2025–2026)

### 2024 (Foundation Setting)

- **August 2024:** Palantir + Microsoft classified networks partnership — Foundry, Gotham, AIP deployed in Azure Government Secret (IL5) and Top Secret (IL6); first deployment of Azure OpenAI in classified environments
- **December 2024:** FedRAMP High Baseline Authorization granted — covers all Palantir products (AIP, Apollo, Foundry, Gotham, FedStart, Mission Manager)

---

### Early 2025

- **February 2025:** AIP Machinery launched — process automation tool for creating supervised AI workflows with human-in-the-loop capabilities
- **March 2025:** Palantir + Databricks strategic partnership announced — zero-copy Unity Catalog integration; endorsed by DoD customers

---

### Mid-2025

- **April 2025:** Anthropic joins FedStart program; Google Cloud integration with FedStart announced
- **April 2025:** NATO finalizes acquisition of Maven Smart System NATO (MSS NATO)
- **May 2025:** Pipeline Builder adds media set transform expressions (image/PDF manipulation without Python)
- **May 2025:** DoD boosts Maven Smart Systems contract by $795 million
- **June 2025:** Palantir + Accenture Federal Services partnership — 1,000 certified professionals for federal deployments
- **July 2025:** U.S. Army $10 billion Enterprise Agreement signed — consolidates 75 contracts
- **August 2025:** Unstructured.io joins FedStart; Palantir secures $448M Navy ShipOS contract (reported December 2025)

---

### Late 2025

- **November 2025:** AI FDE (AI Forward Deployed Engineer) enters beta — natural language interface for operating Foundry
- **November 2025:** Code Workspaces adds AIP agent sidebar + Snowflake Iceberg table read/write support
- **October 31, 2025:** `foundry_ml` library fully deprecated; all workflows must use `palantir_models`
- **Q4 2025:** Palantir reports 70% YoY revenue growth; U.S. government segment at 66% YoY growth

---

### Early 2026

- **January 2026:** $240 million DoD contract for battlefield decision support
- **February 2026:** Palantir issues FY2026 guidance of 61% revenue growth
- **March 2026:** Pentagon designates Maven Smart System as a "Program of Record" (stable permanent funding); oversight transferred to CDAO
- **March 2026:** Reports of AIP Bootcamp strategy "cementing dominance in enterprise AI" as enterprise AI market shifts from experimentation to large-scale deployment

---

### Anticipated Developments

- **AIP Marketplace:** Palantir has signaled intent to allow third-party developers to build and sell AI agents on the platform — described as potentially analogous to the Apple App Store for industrial AI
- **Warfighter OS expansion:** Autonomous supply-chain agents capable of predicting and mitigating logistics failures before they occur in theater (in testing as of early 2026)
- **FedStart IL6 support:** On track within the near term

---

## 9. Key Takeaways for Data Scientists

### What Makes Palantir Different

1. **The Ontology is the central abstraction.** Unlike platforms where data scientists work directly with tables, Palantir encourages modeling data as objects with semantic meaning. This is both a strength (enables AI grounding, operational apps, security policies) and a learning curve.

2. **Foundry is designed for operational AI, not just analytics.** The platform's goal is to get AI-powered decisions into the hands of frontline users — it is not primarily a model training platform. Model training happens here, but deployment into human workflows is the emphasis.

3. **Multiple coding environments exist; know which to use.** Code Workspaces (Jupyter) is best for exploratory ML work. Code Repositories is best for production pipelines. Code Workbook is legacy.

4. **Python is the primary language for data science.** Python 3.10, Pandas, Spark (PySpark), and the `palantir_models` library are the main tools. Java is available in Code Repositories for data engineering pipelines. TypeScript is used for Functions in the Ontology.

5. **Security isolation is native.** Working in a Foundry environment — especially a government enrollment — means data access controls are enforced at the object/property level by the Ontology, not just at the dataset level. Data scientists work within these boundaries.

6. **AIP is not just a chatbot.** AIP Logic and Agent Studio are development tools for building LLM-powered applications that can read from and write to real organizational data. The Ontology grounding is what prevents hallucination on business-critical data.

7. **Foundry + Databricks can coexist.** The 2025 partnership means data managed in a Databricks Lakehouse can be surfaced in Foundry without ETL, using Virtual Tables + Unity Catalog. Government data scientists may encounter hybrid architectures.

8. **FedRAMP High (December 2024) unlocked full government adoption.** All Palantir products — including AIP — are now authorized for civilian agencies at the FedRAMP High baseline and for DoD at IL5. The platform is fully cleared for sensitive government data in the cloud (below classified thresholds).

---

## 10. Sources

### Official Palantir Documentation

- [Palantir Foundry Platform Overview](https://www.palantir.com/docs/foundry/platform-overview/overview)
- [Palantir Foundry Platform](https://www.palantir.com/platforms/foundry/)
- [AIP Overview — Palantir Docs](https://www.palantir.com/docs/foundry/aip/overview)
- [AIP Features — Palantir Docs](https://www.palantir.com/docs/foundry/aip/aip-features)
- [AIP Logic Overview](https://www.palantir.com/docs/foundry/logic/overview)
- [AIP Logic Core Concepts](https://www.palantir.com/docs/foundry/logic/core-concepts)
- [AIP Logic Blocks](https://www.palantir.com/docs/foundry/logic/blocks)
- [AIP Agent Studio Overview](https://www.palantir.com/docs/foundry/agent-studio/overview)
- [AIP Agent Studio Core Concepts](https://www.palantir.com/docs/foundry/agent-studio/core-concepts)
- [Ontology Overview — Palantir Docs](https://www.palantir.com/docs/foundry/ontology/overview)
- [Ontology Core Concepts](https://www.palantir.com/docs/foundry/ontology/core-concepts)
- [Object and Link Types Overview](https://www.palantir.com/docs/foundry/object-link-types/object-types-overview)
- [Action Types Overview](https://www.palantir.com/docs/foundry/action-types/overview)
- [Data Integration Overview](https://www.palantir.com/docs/foundry/data-integration/overview)
- [Pipeline Builder Overview](https://www.palantir.com/docs/foundry/pipeline-builder/overview)
- [Pipeline Builder Transforms Overview](https://www.palantir.com/docs/foundry/pipeline-builder/transforms-overview)
- [Pipeline Builder Use LLM Node](https://www.palantir.com/docs/foundry/pipeline-builder/pipeline-builder-llm)
- [Code Repositories Overview](https://www.palantir.com/docs/foundry/code-repositories/overview)
- [Code Workbook Overview (Legacy)](https://www.palantir.com/docs/foundry/code-workbook/overview)
- [Code Workbook Supported Languages](https://www.palantir.com/docs/foundry/code-workbook/workbooks-languages)
- [Code Products Comparison](https://www.palantir.com/docs/foundry/code-workbook/code-products-comparison)
- [Code Workspaces — Train Models](https://www.palantir.com/docs/foundry/code-workspaces/training-models)
- [Code Workspaces — JupyterLab](https://www.palantir.com/docs/foundry/code-workspaces/jupyterlab)
- [Workshop Overview](https://www.palantir.com/docs/foundry/workshop/overview)
- [Quiver Overview](https://www.palantir.com/docs/foundry/quiver/overview)
- [AI FDE Overview](https://www.palantir.com/docs/foundry/ai-fde/overview)
- [November 2025 Announcements](https://www.palantir.com/docs/foundry/announcements/2025-11)
- [May 2025 Announcements](https://www.palantir.com/docs/foundry/announcements/2025-05)
- [Palantir FedStart](https://www.palantir.com/offerings/fedstart/)
- [Palantir Apollo Overview](https://www.palantir.com/platforms/apollo/)
- [Palantir Gotham](https://www.palantir.com/platforms/gotham/)
- [Palantir AIP Bootcamp](https://www.palantir.com/platforms/aip/bootcamp/)

### Government Authorization and Security

- [Palantir Granted FedRAMP High Baseline Authorization (Investors)](https://investors.palantir.com/news-details/2024/Palantir-Granted-FedRAMP-High-Baseline-Authorization/)
- [Palantir FedRAMP High — Business Wire](https://www.businesswire.com/news/home/20241203054493/en)
- [Palantir FedRAMP High — Nasdaq](https://www.nasdaq.com/press-release/palantir-granted-fedramp-high-baseline-authorization-2024-12-03)
- [Palantir FedRAMP High — ExecutiveBiz](https://www.executivebiz.com/articles/palantir-fedramp-high-baseline-authorization)

### Government Contracts and Partnerships

- [U.S. Army $10B Enterprise Agreement — Army.mil](https://www.army.mil/article/287506/u_s_army_awards_enterprise_service_agreement_to_enhance_military_readiness_and_drive_operational_efficiency)
- [Army Palantir $10B Contract — Breaking Defense](https://breakingdefense.com/2025/08/army-consolidates-dozens-of-palantir-software-contracts-into-one-deal-worth-up-to-10-billion/)
- [Palantir $10B Army Contract — CNBC](https://www.cnbc.com/2025/08/01/palantir-lands-10-billion-army-software-and-data-contract)
- [Pentagon Maven Smart System Program of Record — Bloomberg](https://www.bloomberg.com/news/articles/2026-03-21/palantir-ai-system-wins-key-pentagon-status-reuters-reports)
- [Pentagon Designates Maven as Program of Record — GovConWire](https://www.govconwire.com/articles/pentagon-palantir-maven-ai-program-of-record)
- [NATO Maven Smart System — DefenseScoop](https://defensescoop.com/2025/04/14/nato-palantir-maven-smart-system-contract/)
- [NATO Maven Smart System — NATO SHAPE](https://shape.nato.int/news-releases/nato-acquires-aienabled-warfighting-system-)
- [Palantir + Microsoft Classified Networks — Microsoft Source](https://news.microsoft.com/source/2024/08/08/palantir-and-microsoft-partner-to-deliver-enhanced-analytics-and-ai-services-to-classified-networks-for-critical-national-security-operations/)
- [Palantir + Microsoft — FedScoop](https://fedscoop.com/microsoft-palantir-ai-analytics-products-intelligence-defense-natsec/)
- [Palantir + Accenture Federal Services — Accenture Newsroom](https://newsroom.accenture.com/news/2025/palantir-and-accenture-federal-services-join-forces-to-help-federal-government-agencies-reinvent-operations-with-ai)
- [Palantir CDAO CJADC2 Contract](https://investors.palantir.com/news-details/2024/Palantir-Selected-by-Chief-Digital-and-Artificial-Intelligence-Office-CDAO-to-Participate-in-Scaling-Data-Analytics-and-AI-Capabilities-Across-the-Department-of-Defense-in-Support-of-CJADC2-Strategy/)
- [Anthropic joins FedStart — Nasdaq](https://www.nasdaq.com/press-release/anthropic-joins-palantirs-fedstart-program-deploy-claude-application-2025-04-17)
- [Google Cloud + FedStart — Google Cloud Blog](https://cloud.google.com/blog/topics/public-sector/google-public-sector-and-palantir-collaborate-to-bring-google-cloud-to-fedstart)
- [Unstructured.io joins FedStart — Yahoo Finance](https://finance.yahoo.com/news/unstructured-io-joins-palantir-fedstart-130000722.html)

### Platform Comparisons and Industry Analysis

- [Palantir + Databricks Partnership — Databricks](https://www.databricks.com/company/newsroom/press-releases/palantir-and-databricks-announce-strategic-product-partnership)
- [Databricks + Palantir Customers — Databricks Blog](https://www.databricks.com/blog/beyond-partnership-how-100-customers-are-already-transforming-business-databricks-and-palantir)
- [Databricks vs Palantir — LatentView](https://www.latentview.com/blog/databricks-vs-palantir/)
- [Palantir Foundry vs Databricks — G2](https://www.g2.com/compare/databricks-data-intelligence-platform-vs-palantir-foundry)
- [Advana Analytics Multi-Vendor — Breaking Defense](https://breakingdefense.com/2024/07/cdao-opens-advana-analytics-to-multiple-vendors-in-a-push-to-scale-up/)
- [Make Advana Great Again — DefenseScoop](https://defensescoop.com/2025/03/17/make-advana-great-again/)
- [Palantir vs Qlik — Gartner Peer Insights](https://www.gartner.com/reviews/market/data-integration-tools/compare/palantir-technologies-vs-qlik)
- [Palantir Foundry vs Qlik — PeerSpot](https://www.peerspot.com/products/comparisons/palantir-foundry_vs_qlik-talend-cloud)
- [Foundry & Gotham Explained — Yahoo Finance](https://finance.yahoo.com/news/foundry-gotham-engines-driving-palantirs-164300736.html)

### Revenue and Business Context

- [Palantir Q4 2025 Earnings — Investors](https://investors.palantir.com/news-details/2026/Palantir-Reports-Q4-2025-U-S--Comm-Revenue-Growth-of-137-YY-and-Revenue-Growth-of-70-YY-Issues-FY-2026-Revenue-Guidance-of-61-YY-and-U-S--Comm-Revenue-Guidance-of-115-YY-Crushing-Consensus-Expectations/)
- [Palantir Q4 2025 — CNBC](https://www.cnbc.com/2026/02/02/palantir-pltr-q4-2025-earnings.html)
- [AIP Bootcamp Strategy — FinancialContent](https://markets.financialcontent.com/stocks/article/marketminute-2026-3-6-palantir-shares-surge-as-aip-bootcamp-strategy-cementing-dominance-in-enterprise-ai)
- [AIP Bootcamp Blog — Palantir](https://blog.palantir.com/deploying-full-spectrum-ai-in-days-how-aip-bootcamps-work-21829ec8d560)
- [Palantir FedSavvy Federal Growth Analysis](https://www.fedsavvystrategies.com/palantir-federal/)
- [The Government's Embrace of Palantir — FedScoop](https://fedscoop.com/palantir-federal-agencies-government-data/)

---

*This report is based entirely on publicly available information as of March 2026. It does not contain or speculate about classified capabilities, non-public contracts, or sensitive government programs beyond what has been officially disclosed.*
