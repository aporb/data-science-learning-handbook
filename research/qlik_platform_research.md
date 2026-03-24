# Qlik for Government: Comprehensive Research Report
**Research Date:** March 2026
**Scope:** Publicly available information on Qlik for federal/government data science and analytics (2025-2026)

---

## Table of Contents
1. [Platform Overview: Qlik's Core Offerings](#1-platform-overview)
2. [Government-Specific Offerings](#2-government-specific-offerings)
3. [How Data Scientists and Analysts Use Qlik](#3-how-data-scientists-and-analysts-use-qlik)
4. [Security and Compliance](#4-security-and-compliance)
5. [Recent Developments: 2025-2026](#5-recent-developments-2025-2026)
6. [Comparison with Other Federal Analytics Platforms](#6-comparison-with-other-federal-analytics-platforms)
7. [Procurement and Access](#7-procurement-and-access)
8. [Key Sources](#8-key-sources)

---

## 1. Platform Overview

### Qlik's Product Portfolio

Qlik is a data integration and analytics company. Following its acquisition of **Talend** in May 2023 and **Attunity** (now Qlik Replicate) in 2019, Qlik operates a comprehensive data platform spanning data movement, transformation, governance, and visualization. The platform now positions itself as an end-to-end data and analytics solution with the following major product lines:

---

### 1a. Analytics: Qlik Sense / Qlik Cloud Analytics

**Qlik Sense** is the flagship analytics product, available as:
- **Qlik Cloud Analytics** (SaaS) — the primary and preferred delivery model
- **Qlik Sense Enterprise on Windows** (on-premises or customer-managed)
- **Qlik Sense Enterprise on Kubernetes** (containerized deployment)
- **Qlik Cloud Government** (US public sector SaaS, see Section 2)

**The QIX Engine (Associative Engine)**

The core differentiator in Qlik's analytics stack is the **QIX Engine** — Qlik's proprietary in-memory, associative analytics engine representing more than 30 years of R&D. Key properties:

- Every data point is aware of its relationship to every other data point in the data model
- Selections made by a user instantly highlight related data (white/active) and unrelated data (gray/excluded) across all charts simultaneously — without re-querying a database
- This associative approach makes it easy to discover unexpected patterns and relationships — a user selecting "denied claims" immediately sees all correlated dimensions light up or gray out across the entire dashboard
- The engine handles large, complex data models entirely in memory at query time

This is a fundamental architectural difference from SQL-based BI tools (Tableau, Power BI, Looker) that execute queries sequentially. Qlik's associative engine is purpose-built for **exploratory, hypothesis-driven analysis** rather than just reporting.

**Qlik Sense Key Capabilities**

- Self-service analytics and interactive dashboards
- Insight Advisor: AI-assisted chart recommendations, anomaly detection, and associative insights
- Qlik Answers: conversational AI interface combining structured and unstructured data (see Section 5)
- Mobile analytics
- Embedded analytics via APIs and mashup development
- Custom extensions via the Visualization Extensions API

---

### 1b. Data Integration: Qlik Talend Cloud / Qlik Replicate

Qlik's data integration layer (formerly Attunity + Talend) covers:

**Qlik Replicate (formerly Attunity)**
- Change Data Capture (CDC)-based data replication from relational databases (Oracle, SQL Server, DB2, PostgreSQL), SaaS applications, SAP, and mainframe systems
- Agentless, high-performance streaming pipelines
- Direct delivery to data lakes, warehouses, and streaming platforms
- Widely used for real-time data ingestion into government data platforms

**Qlik Talend Cloud**
- Full ETL/ELT data transformation
- Data quality and profiling
- Master data management
- Cloud-native data pipelines
- Recognized as a Gartner Magic Quadrant Leader in Data Integration Tools **for the 10th consecutive year in 2025**

**Qlik Data Gateway — Direct Access**
A secure, lightweight gateway allowing Qlik Cloud to query on-premises and network-restricted data sources without moving data to the cloud. Critical for government environments where data residency and network segmentation requirements restrict direct cloud connectivity.

---

### 1c. Application Automation

**Qlik Application Automation** provides no-code workflow automation capabilities, connecting Qlik analytics to downstream business systems (ServiceNow, Salesforce, email, etc.) to orchestrate actions triggered by data insights.

---

## 2. Government-Specific Offerings

### Qlik Cloud Government

**Qlik Cloud Government** is a purpose-built SaaS instance dedicated exclusively to U.S. public sector customers. It is hosted on AWS GovCloud infrastructure, separate from Qlik's commercial cloud.

Key attributes:
- Governed by stricter security protocols compared to the commercial Qlik Cloud
- Hosted in AWS GovCloud (US)
- Sponsoring agency: **U.S. Environmental Protection Agency (EPA)** — the EPA worked with Qlik during the FedRAMP authorization process
- Available to U.S. Federal, State, and local government agencies, contractors, and educational institutions

**FedRAMP-Certified Components in Qlik Cloud Government**
- Qlik Sense Enterprise SaaS (analytics)
- Qlik Cloud Data Integration
- Qlik Application Automation
- Direct Query
- Qlik Data Gateway — Direct Access

### Qlik Cloud Government — DoD

A separate, higher-security instance specifically for U.S. Department of Defense organizations. As of **February 2026**, this offering became available in AWS Marketplace via **JWCC (Joint Warfighting Cloud Capability)** procurement pathways.

JWCC is the DoD's primary multi-cloud contract vehicle (AWS, Azure, Google, Oracle), enabling DoD organizations to procure commercial cloud services including Qlik through a standardized, streamlined process.

---

## 3. How Data Scientists and Analysts Use Qlik

### 3a. Data Load Scripting

Qlik Sense's **Data Load Script** (written in the Qlik Script language) is how data scientists and power users connect to data sources, transform data, and build the in-memory data model. It is more code-centric than drag-and-drop and gives practitioners granular control over:

- Connecting to databases, files (CSV, Excel, JSON, Parquet), REST APIs, and cloud data warehouses
- Joins, transformations, and data cleaning in script
- Creating derived fields and variables
- Incrementally loading new data
- Building multi-table data models with key-field associations

The Data Load Editor is the primary scripting interface in Qlik Sense. Government analysts who understand ETL or SQL find the scripting approach familiar.

**Key scripting concepts:**
- `LOAD` and `SELECT` statements to bring in data
- `Mapping LOAD` for lookups
- Resident LOAD for iterating over already-loaded tables
- Variable containers for static values or computed metrics
- Incremental load patterns using QVD files (Qlik's proprietary binary format) for performance

### 3b. Server-Side Extensions (SSE)

**Server-Side Extensions (SSE)** is a gRPC-based protocol enabling Qlik to call external computation engines for advanced analytics. Data scientists use SSE to bring Python (scikit-learn, statsmodels, Prophet) or R into Qlik visualizations and load scripts without leaving the Qlik environment.

**Architecture:**
- SSE uses Remote Procedure Calls (RPCs) to send Qlik data to an external server running Python or R
- The external engine performs computation (ML scoring, statistical analysis, forecasting) and returns results
- Results appear as expressions in Qlik charts or load script outputs

**Practical use cases in government:**
- Running scikit-learn classification or regression models on procurement data
- Applying ARIMA or Prophet forecasting to budget or demand data
- Natural language processing on free-text fields

**qlik-py-tools** (open source): A community-built Python SSE plugin providing data science algorithms (supervised ML, time series, NLP) implemented for Qlik, using scikit-learn.

**Note on SSE deprecation path:** With Qlik's growing native AI capabilities (Qlik Predict, Qlik Answers), the SSE pattern is becoming less the primary path for ML integration. However, it remains available and widely used in on-premises deployments where cloud-native AI features are not accessible.

### 3c. Insight Advisor and Conversational Analytics

**Insight Advisor** provides AI-assisted analytics within Qlik Sense:
- Automatically builds recommended charts from natural language queries ("Show me revenue by region last quarter")
- Highlights key drivers and explains relationships behind data
- Associative Insights: surfaces blind spots by comparing contributions of selected vs. excluded values
- Available in both Qlik Cloud and Qlik Sense Enterprise on Windows (with some feature differences)

### 3d. Qlik Answers (Agentic Analytics)

See Section 5 for the 2025-2026 development. Qlik Answers represents the next evolution of analytics interaction — a conversational AI interface that combines Qlik's structured data analytics with unstructured content and LLM reasoning.

### 3e. Qlik Predict (formerly AutoML)

**Qlik Predict** (rebranded from AutoML) provides no-code/low-code machine learning within the Qlik Cloud environment:
- Automated model training and selection
- **AI Trust Score** (introduced July 2025): helps users assess data readiness and model reliability before deploying predictions
- Multivariate forecasting: models full business complexity with multiple input variables, not just single-variable projections
- Real-time API access for scoring new data
- What-if analysis and scenario planning
- Full model explainability in the analytics UI (SHAP values, feature importance)
- Enhanced security for model artifacts

The July 2025 AI Trust Score addition is especially relevant for government contexts where explainability and auditability of model decisions are often mandated.

### 3f. Custom Extensions and Mashups

For advanced visualization needs, Qlik supports:
- **Visualization Extensions:** custom chart types built with D3.js, Leaflet, or other JavaScript libraries
- **Mashup API:** embedding Qlik objects into external web applications or government portals
- These require JavaScript development skills and are used by agencies building custom geospatial dashboards, interactive maps, or embedded analytics in citizen-facing applications

---

## 4. Security and Compliance

### FedRAMP Authorization

| Authorization | Level | Status |
|--------------|-------|--------|
| FedRAMP Moderate (Qlik Cloud Government) | Moderate IL | **Authorized** |
| DoD IL2 | IL2 | **Authorized** |
| DoD IL4 | IL4 | **Authorized** |
| DoD IL5 | IL5 | Not confirmed as of research date |

**Sponsoring Agency:** U.S. Environmental Protection Agency (EPA)
**Third-Party Assessor (3PAO):** Coalfire
**FedRAMP Marketplace listing:** Qlik Cloud Government is listed as an authorized product in the FedRAMP Marketplace

**Scope:** The FedRAMP authorization covers the full Qlik Cloud Government SaaS platform including data integration, analytics, automation, and machine learning components.

### StateRAMP

Qlik Cloud Government has achieved **StateRAMP Moderate Authorization**, enabling U.S. state and local government and public educational institutions to procure Qlik Cloud under a standardized cloud security framework. Additional state-specific certifications include:
- **TX-RAMP Level 2** (Texas-specific cloud security)

### ITAR

Qlik Cloud Government supports **International Traffic in Arms Regulations (ITAR)** compliance, relevant for defense contractors and agencies working with controlled technical data.

### Deployment Options and Security Architecture

**SaaS (Qlik Cloud Government)**
The primary offering. Data is hosted on AWS GovCloud infrastructure in the US. Qlik manages security controls, patching, and compliance maintenance.

**Customer-Managed (Qlik Sense Enterprise on Windows)**
Organizations requiring full data custody can deploy Qlik Sense on their own infrastructure (on-premises or in a government cloud region they manage). This is available as a licensed product and is relevant for:
- Environments with network segmentation that prevents cloud connectivity
- Higher-classification data environments (though Qlik does not hold IL6 authorization for classified systems)
- Agencies with existing investment in on-premises Qlik deployments

**Qlik Data Gateway — Direct Access**
For hybrid scenarios, the Data Gateway allows Qlik Cloud Government to query on-premises data sources in real time without requiring data migration to the cloud.

**Qlik DataTransfer**
A lightweight Windows application allowing upload of data from on-premises sources to Qlik Cloud Government without firewall tunneling. Used where the Data Gateway is not practical.

---

## 5. Recent Developments: 2025-2026

### Qlik Connect 2025 (May 2025) — Agentic AI Focus

The annual Qlik Connect conference in May 2025 centered on **agentic AI** — the theme "Answers for Agentic AI." Key announcements:

**Qlik Answers (Preview → GA)**
Qlik Answers combines:
- Qlik's associative engine (structured analytics)
- Unstructured content (documents, reports, knowledge bases)
- LLM reasoning
...into a single conversational interface. Users ask natural language questions and receive answers with citations and explanations. As of **February 2026**, Qlik Answers reached **general availability** for Qlik Cloud.

**Discovery Agent**
Announced at Qlik Connect 2025 — an AI agent that continuously monitors data to identify important trends, anomalies, and outliers. Delivers personalized digests to users so they can act on emerging issues without manually building queries.

**Automation Agents**
Orchestrate actions in downstream systems (ServiceNow, Salesforce, email) automatically or in collaboration with users, based on analytics-driven triggers.

### Qlik MCP Server — General Availability (February 2026)

Qlik launched the **Qlik Model Context Protocol (MCP) Server**, enabling third-party AI assistants — including **Anthropic Claude** and others — to securely access Qlik's analytical capabilities and trusted data products. This allows organizations to integrate Qlik's governed data and analytics into broader AI agent workflows.

This was announced simultaneously with Qlik Answers GA in February 2026.

### JWCC AWS Marketplace Launch (February 2026)

Qlik launched availability of **Qlik Cloud Government - DoD, Qlik Sense Enterprise, and Qlik Data Integration** in **AWS Marketplace** for U.S. DoD JWCC customers. Benefits:
- Faster, standardized procurement path
- Consolidated billing within AWS Marketplace accounts
- Flexibility to choose between SaaS (Qlik Cloud Government - DoD) or customer-managed deployment
- Relevant to all JWCC-eligible DoD organizations

### Qlik Expands Integration with Databricks (June 2025)

In June 2025, Qlik announced significant expansions to its integration with the Databricks Data Intelligence Platform:

- **Real-time UniForm table streaming:** Qlik Replicate streams CDC from enterprise data sources directly into Unity Catalog's managed Apache Iceberg tables
- **Automated Apache Iceberg optimization** via Qlik Open Lakehouse (automated compaction, partitioning, pruning)
- **High-quality data products:** creation and provisioning of AI-ready data directly into Databricks Lakehouse
- Upcoming: schema inference, Databricks notebook import, native Spark debugging within Qlik workflows

This integration is significant for government organizations adopting Databricks as their AI/ML platform while relying on Qlik for data ingestion pipelines.

### Qlik Predict Enhancements (2025)

- **AI Trust Score** (July 2025): New metric helping government analysts understand data preparedness for AI/ML before deploying predictions — addresses explainability requirements common in federal data governance policies
- **Multivariate forecasting** in Qlik Predict: models multiple input variables for more realistic operational forecasting
- Rebranding of AutoML to **Qlik Predict** throughout the product

### Qlik 2025 Agentic AI Study

Qlik published a 2025 Agentic AI Study finding that while **AI budgets are surging**, organizations report that **data readiness delays scale** — only 12% of large enterprise executives say their data is of sufficient quality and accessibility to support AI at scale. This is relevant for government agencies planning AI adoption and highlights the importance of Qlik's data integration (Qlik Talend Cloud, Qlik Replicate) as a prerequisite to AI deployment.

### Qlik Connect 2025 — AI Certification

A new **AI Certification** was introduced at Qlik Connect 2025 to help organizations verify that their analytics and AI implementations meet production-grade standards.

### Gartner Magic Quadrant 2025

Qlik retained its position as a **Leader in Gartner Magic Quadrant for Data Integration Tools** for the **10th consecutive year** in 2025, indicating sustained recognition for Qlik Talend Cloud and Qlik Replicate.

---

## 6. Comparison with Other Federal Analytics Platforms

### Qlik Cloud Government vs. Tableau (Salesforce)

| Dimension | Qlik Cloud Government | Tableau |
|-----------|----------------------|---------|
| Core differentiator | Associative engine, data exploration | Visual storytelling, ease of use |
| FedRAMP | Moderate Authorized | Tableau Government (FedRAMP Moderate) |
| DoD IL | IL2, IL4 | Varies |
| Data integration | Comprehensive (Talend, Replicate) | Limited native; relies on connectors |
| ML/AI | Qlik Predict, Qlik Answers | Einstein AI (Salesforce) |
| Scripting/code | Load Script (SQL-like), SSE | Limited (calculated fields) |
| On-premises option | Yes (Qlik Sense Enterprise) | Yes (Tableau Server) |
| Government history | Strong, legacy presence | Strong, widely deployed |

### Qlik Cloud Government vs. Microsoft Power BI

| Dimension | Qlik Cloud Government | Power BI |
|-----------|----------------------|---------|
| Core differentiator | Associative engine | Microsoft ecosystem integration |
| FedRAMP | Moderate Authorized | Power BI Government (High authorized via Azure) |
| Cost | Higher per-user cost | Very competitive ($14/user/month as of April 2025) |
| Microsoft integration | Limited | Seamless (Teams, Azure, Office 365) |
| Data integration | Comprehensive | Power Query/Dataflows; limited vs. Talend |
| ML/AI | Qlik Predict, Qlik Answers | Copilot, Azure ML integration |
| On-premises | Yes | Power BI Report Server |
| Government adoption | Established in federal | Rapidly growing, lowest cost |

**Key insight:** Power BI has been aggressively expanding government FedRAMP coverage (including High authorization via Azure Government) and offers the lowest cost per user of the major BI tools. For agencies heavily invested in Microsoft Azure Government ecosystems, Power BI often wins on cost and integration. Qlik's advantage remains its associative engine for complex, exploratory analysis and its stronger data integration capabilities.

### Qlik Cloud Government vs. Looker (Google)

| Dimension | Qlik Cloud Government | Looker |
|-----------|----------------------|--------|
| Core differentiator | Associative exploration | Governed semantic layer (LookML) |
| FedRAMP | Moderate Authorized | Looker Government (Moderate) |
| Data integration | Comprehensive (Talend, Replicate) | Limited native |
| Governance | Strong | Very strong (LookML semantic layer) |
| AI features | Qlik Predict, Qlik Answers | Gemini-powered features |
| Google Cloud dependency | None (AWS GovCloud hosted) | Tightly coupled to Google Cloud |

### Qlik vs. Databricks for Government

Qlik and Databricks serve different primary functions and are increasingly **complementary** rather than competitive:

| Dimension | Qlik | Databricks |
|-----------|------|-----------|
| Primary use | Analytics, BI, data visualization | Data engineering, ML, AI |
| FedRAMP High | Not achieved (Moderate only) | Achieved (AWS + Azure Gov) |
| DoD IL5 | Not confirmed | Yes |
| Data integration | Comprehensive ETL/CDC | Delta Lake, structured streaming |
| ML/AI | Qlik Predict (no-code), Qlik Answers | Mosaic AI (full MLOps suite) |
| Target users | Analysts, business users | Data engineers, data scientists |
| Partnership | Official Qlik-Databricks integration (June 2025) | Official Qlik-Databricks integration |

Agencies increasingly use **Qlik Replicate as the ingestion layer feeding Databricks** for AI/ML workflows, while using **Qlik Sense as the analytics/reporting layer** consuming processed outputs from Databricks.

### Summary: When to Use Qlik vs. Alternatives in Federal Contexts

**Choose Qlik when:**
- Analysts need exploratory, associative data discovery (not just fixed dashboards)
- The agency has complex, multi-source data models requiring CDC-based real-time ingestion
- Legacy Qlik investments exist (QlikView → Qlik Sense migration path)
- Mixed structured/unstructured data analysis is required (Qlik Answers)
- FedRAMP Moderate is sufficient (Qlik does not yet hold FedRAMP High)
- JWCC procurement for DoD is available

**Consider alternatives when:**
- FedRAMP High or IL5 is required for analytics layer (Power BI / Azure, or Databricks SQL)
- Deep Microsoft 365/Teams integration is a priority (Power BI)
- Cost per user is a primary constraint at large scale (Power BI)
- Advanced ML/AI beyond no-code AutoML is needed (Databricks Mosaic AI)

---

## 7. Procurement and Access

### JWCC (Joint Warfighting Cloud Capability)

As of February 2026, Qlik Cloud Government - DoD is available via **AWS Marketplace** under JWCC. JWCC is the DoD's preferred multi-cloud contract vehicle, covering AWS, Azure, Google Cloud, and Oracle Cloud. DoD organizations can procure Qlik through:
1. AWS Marketplace private listings via JWCC pathways
2. Customer-managed deployment options (Qlik Sense Enterprise licensed)

### FedRAMP Marketplace

Qlik Cloud Government is listed as an **authorized product** in the FedRAMP Marketplace at https://marketplace.fedramp.gov, making it visible to civilian agency procurement officers and enabling rapid ATO inheritance.

### StateRAMP

State and local government agencies can procure Qlik Cloud Government under StateRAMP Moderate authorization, eliminating the need for individual state security reviews.

### EPA as Sponsoring Agency

The U.S. EPA sponsored Qlik through the FedRAMP authorization process and is a production user of Qlik Cloud Government — providing a reference implementation for other federal agencies. Qlik's EPA deployment documentation is publicly available (see epa.gov Qlik PDF).

---

## 8. Key Sources

- [Qlik Cloud Government FedRAMP Moderate Authorization (Press Release)](https://www.qlik.com/us/news/company/press-room/press-releases/qlik-achieves-fedramp-authorization-for-cloud-analytics-platform)
- [Qlik Achieves Full FedRAMP Authorization (Blog)](https://www.qlik.com/blog/qlik-achieves-full-fedramp-authorization)
- [Qlik FedRAMP Milestone Community Post](https://community.qlik.com/t5/Product-Innovation/Qlik-reaches-milestone-with-FedRAMP-Moderate-Authorization-for/ba-p/1991886)
- [Qlik Cloud Government Takes Big Step Forward with FedRAMP Features (Blog)](https://www.qlik.com/blog/qlik-cloud-government-takes-big-step-forward-with-new-fedramp-certified-capabilities)
- [Qlik Achieves StateRAMP Authorization (Press Release)](https://www.qlik.com/us/news/company/press-room/press-releases/qlik-achieves-stateramp-authorization-for-qlik-cloud-government)
- [Qlik Launches Qlik Cloud Government – DoD in AWS Marketplace for JWCC (BusinessWire)](https://www.businesswire.com/news/home/20260218897353/en/Qlik-Launches-Qlik-Cloud-Government-Gov-DoD-Qlik-Sense-Enterprise-and-Qlik-Data-Integration-in-AWS-Marketplace-for-JWCC-Customers)
- [Qlik Cloud Government DoD AWS Marketplace (Qlik Press Release)](https://www.qlik.com/us/news/company/press-room/press-releases/qlik-launches-qlik-cloud-government-gov-dod-qlik-sense-enterprise-and-qlik-data-integration-in-aws-marketplace-for-jwcc-customers)
- [Qlik Sense Enterprise SaaS Government Overview (Help Docs)](https://help.qlik.com/en-US/cloud-services/Content/Sense_Helpsites/about-qs-government.htm)
- [Qlik Cloud Government Help Docs](https://help.qlik.com/en-US/cloud-services/Subsystems/Hub/Content/Global_Common/HelpSites/about-qcg.htm)
- [Qlik Debuts Agentic Experience; MCP Opens Qlik to Third-Party Assistants (Press Release)](https://www.qlik.com/us/news/company/press-room/press-releases/qlik-debuts-agentic-experience)
- [Qlik Brings Agentic Analytics to GA and Launches MCP Server (BusinessWire, Feb 2026)](https://www.businesswire.com/news/home/20260210837577/en/Qlik-Brings-Agentic-Analytics-to-General-Availability-and-Launches-MCP-Server-for-Third-Party-Assistants)
- [A Vision for the Future: Qlik's New Agentic AI Experience (Blog)](https://www.qlik.com/blog/a-vision-for-the-future-qliks-new-agentic-ai-experience)
- [Qlik Connect 2025: Answers for Agentic AI (LinkedIn)](https://www.linkedin.com/pulse/qlik-connect-2025-answers-agentic-ai-jim-czuprynski-vehsc)
- [Qlik Expands Integration with the Databricks Data Intelligence Platform (BusinessWire, June 2025)](https://www.businesswire.com/news/home/20250610295577/en/Qlik-Expands-Integration-with-the-Databricks-Data-Intelligence-Platform)
- [Qlik Expands Integration with Databricks (Qlik Press Release)](https://www.qlik.com/us/news/company/press-room/press-releases/qlik-expands-integration-with-the-databricks-data-intelligence-platform)
- [Building Trust in AI: Qlik AutoML Enhancements (Press Release)](https://www.qlik.com/us/news/company/press-room/press-releases/building-trust-in-ai-qliks-latest-automl-enhancements)
- [Qlik 2026 Trends – Powering the Future of AI (Blog)](https://www.qlik.com/blog/qlik-2026-trends-powering-the-future-of-ai)
- [Qlik Agentic AI 2025 Study (Press Release)](https://www.qlik.com/us/news/company/press-room/press-releases/qlik-2025-agentic-ai-study-budgets-surge-but-data-readiness-delays-scale)
- [GitHub: Qlik Server-Side Extension Protocol](https://github.com/qlik-oss/server-side-extension)
- [GitHub: qlik-py-tools Data Science Python SSE](https://github.com/nabeel-oz/qlik-py-tools)
- [GitHub: Qlik SSE R Plugin](https://github.com/qlik-oss/sse-r-plugin)
- [SSE Syntax Docs (Qlik Cloud Help)](https://help.qlik.com/en-US/cloud-services/Subsystems/Hub/Content/Sense_Hub/LoadData/sse-syntax.htm)
- [Loading and Transforming Data with Scripting (Qlik Cloud Help)](https://help.qlik.com/en-US/cloud-services/Subsystems/Hub/Content/Sense_Hub/Scripting/introduction-data-modeling.htm)
- [Qlik Public Sector Solutions](https://www.qlik.com/us/solutions/industries/public-sector)
- [Qlik US Public Sector Analytics](https://www.qlik.com/us/solutions/industries/public-sector/us-public-sector)
- [Bridging the AI Readiness Gap in Government – Qlik (FedScoop)](https://fedscoop.com/bridging-the-ai-readiness-gap-in-government-begins-with-trusted-data/)
- [EPA Qlik Documentation (epa.gov)](https://www.epa.gov/system/files/documents/2023-11/qlik.pdf)
- [Qlik 2025 Agentic AI Launches (TechTarget)](https://www.techtarget.com/searchbusinessanalytics/news/366638938/Qlik-launches-agentic-experience-to-fuel-AI-powered-analysis)
- [Qlik Rolls Out Governed Agentic AI & MCP for Qlik Cloud (ITBrief Asia)](https://itbrief.asia/story/qlik-rolls-out-governed-agentic-ai-mcp-for-qlik-cloud)
