# Advana (Advancing Analytics) Platform Research
**Research Date:** March 2026
**Classification:** Based on publicly available information only
**Primary URL:** https://advana.data.mil (CAC required)

---

## 1. What Advana Is

Advana — a portmanteau of "Advancing Analytics" — is the Department of Defense's enterprise-wide, multi-domain data, analytics, and artificial intelligence platform. It originated inside the Office of the Secretary of Defense (Comptroller) as a tool to aggregate data from thousands of incompatible DoD business systems in order to pass financial audits. Over time it grew into the DoD's primary decision-support and data science platform, serving all military services, combatant commands, the Joint Staff, and Principal Staff Assistants to the SecDef.

**Original builder:** Booz Allen Hamilton, under a five-year, $674M GSA contract awarded in 2021
**Managing office:** Chief Digital and Artificial Intelligence Office (CDAO), which became operational in 2022 and subsumed earlier efforts from the Joint Artificial Intelligence Center (JAIC) and Defense Digital Service
**Official designation:** Named by the Deputy Secretary of Defense as "the single enterprise authoritative data management and analytics platform" for the OSD and all DoD components

Advana serves as the foundation for the Pentagon's Open DAGIR (Open Data and Applications Government-owned Interoperable Repositories) framework — a multi-vendor ecosystem intended to protect both industry IP and government data ownership while scaling AI, data, and analytics capabilities.

---

## 2. Current Capabilities

### Scale (as of 2024-2025)
- **Users:** Grew from ~7,000 (early deployments) to 28,000+ (2022) to 80,000–100,000+ (2024)
- **Data sources:** 3,000+ NIPR sources ingested; 400+ Pentagon business systems connected; over 1,200 systems consolidated onto one platform
- **Applications:** 250–300+ applications in production
- **Organizations served:** 55+ DoD organizations; covers 10 community spaces

### Data Domains Covered
- Financial management and audit readiness
- Procurement and contract data
- Logistics and supply chain
- Personnel and health
- Readiness and training
- Infrastructure tracking
- Global force management and campaign planning
- COVID-19 response (demonstrated cross-agency real-time tracking of PPE stockpiles across HHS, FEMA, and DoD during the pandemic)

### Analytics and Data Science Tools Available on Advana
Documented public sources confirm the following tools are available within the Advana ecosystem:

| Tool/Platform | Category |
|---|---|
| Qlik Sense | Primary visualization/BI layer; enables dashboard creation, mashups, SSE (Server-Side Extensions) |
| Tableau | Visualization/BI (referenced in DoD pipeline documentation) |
| Power BI | Visualization/BI |
| Databricks | Data lakehouse / ML platform |
| MLflow | ML experiment tracking (via Databricks) |
| DataRobot | Automated ML |
| C3 AI | Enterprise AI applications |
| Amazon SageMaker | ML model training and deployment |
| Collibra | Data governance / data catalog |
| APIgee | API management |
| GitLab | Source code management / CI/CD |
| Perceptor | Analytics (DoD-specific tool) |
| Python | Supported via Qlik SSE and Databricks notebooks |
| R | Referenced in DoD data analytics documentation |

**Key capability detail:** Qlik's Server-Side Extensions (SSE) allow the analytics layer to simultaneously process Python, C++, or Java code, enabling data scientists to embed advanced computations directly into dashboards.

### AI/ML Capabilities
- Predictive analytics models (movement timelines, route optimization, readiness forecasting)
- AI query systems enabling multi-step questions to be answered in one or two clicks
- Real-time streaming data replication (millisecond-level latency from Army source systems GFEBS and GCSS-Army)
- Campaign planning and feasibility assessment support
- Critical capabilities assessment tool for operational status and risk characterization
- Data Science as a Service (DSaaS) function led internally by CDAO
- Agentic AI integration planned under War Data Platform restructuring

### Architecture
- **Architecture type:** Enterprise data warehouse with a staging environment for common data model conversion; web-based (no local installation required)
- **Cloud direction:** Transitioning toward cloud environment for greater scale, more powerful analytics, and advanced automation
- **Data pipeline:** Data ingests from source systems, aligned to category (logistics, medical, finance), converted to common data model, placed in workspaces for analytics
- **Real-time feeds:** Army SAP/SLT services create real-time feeds into Advana/MySQL/S3, with planned federation to SAP HANA layer
- **Data monitoring:** ARES/ADVANA monitors data quality and alerts on anomalies in real time

---

## 3. How Data Scientists Use Advana

### Accessing the Platform
1. Navigate to **https://advana.data.mil**
2. Authenticate with your **CAC (Common Access Card) certificate**
3. If first-time access: submit a **DD Form 2875** (System Authorization Access Request) and contact the Advana Help Desk to initiate a ticket
4. Access is granted to both DoD military/civilian employees and contractors with appropriate credentials and clearances

### Workflow for Data Scientists
The platform supports multiple tiers of users:

**Consumers/Analysts:** Access pre-built Qlik dashboards and curated applications covering their functional area (logistics, finance, HR, etc.). Use natural language discovery for data exploration. Self-service analytics without coding.

**Intermediate Analysts:** Build custom dashboards in Qlik using the mashup API to combine data across multiple sources into unified interfaces. Use Advana's common data models as starting points.

**Data Scientists/Builders:** Work in Databricks notebooks (Python/PySpark/SQL), use MLflow for experiment tracking, DataRobot or C3 AI for automated ML, and SageMaker for model deployment. Access to Collibra for data governance and lineage. GitLab for version control.

**Data Engineers:** Build data pipelines, set up real-time replication feeds, and manage data quality using ARES/ADVANA monitoring. Work with MySQL, S3, and SAP HANA integration layers.

### Training Resources
**Advana University** — A self-service, web-based training program that provides:
- Overview of foundational data, analytics, and AI concepts
- Applied training using specific tools and products on the platform
- Accessible to all registered Advana users

Additional resources:
- DAU (Defense Acquisition University) at dau.edu hosts Advana documentation and training materials
- DAU Media hosts the official "Advana Defense Analytics Platform" video overview

---

## 4. Security and Compliance

### Network Classifications
Advana is accredited and operates on **multiple DoD networks**:

| Network | Classification Level | Use |
|---|---|---|
| NIPRNET | Unclassified (CUI/FOUO) | Primary business operations; 3,000+ NIPR data sources |
| SIPRNET | Secret | Classified analytics (Secret and below) |
| Additional networks | Referenced as "5 accredited networks" total in some DoD briefings |

### Impact Levels
Based on DoD cloud security frameworks:
- **IL4:** Controlled Unclassified Information (CUI) — applicable to most Advana NIPR operations; requires U.S.-territory data residency and NIPRNET connectivity
- **IL5:** For data requiring higher protection than IL4 (National Security System data); requires U.S. citizen-only access and physical/logical separation

### Access Requirements
- **CAC or PIV card** required for all platform access
- **DD Form 2875** (System Authorization Access Request) for initial account creation
- **Clearance:** Varies by community/data space; SIPR access requires at minimum a Secret clearance
- **Contractor access:** Available with proper sponsorship and credentialing

### Audit Status
- The DoD has failed seven consecutive independent audits despite Advana being built partly to solve this problem
- FY 2025 SOC-1 audit of Advana produced an **adverse result** (specific control deficiencies classified as CUI, not publicly released)
- Remediation of deficiencies is a primary driver of the January 2026 restructuring

---

## 5. Recent Developments (2024–2026)

### Timeline of Key Events

**July 2024:** CDAO announces Open DAGIR framework — a multi-vendor ecosystem to open Advana's analytics to competing vendors. Development paused temporarily for infrastructure improvements.

**September 2024:** CDAO unveils a 10-year, $15 billion Advana recompete plan (the Advancing Artificial Intelligence Multiple Award Contract, or AAMAC) to expand access to small businesses and diversify vendor support.

**January 2025:** Program officer Alex O'Toole departs for Databricks as Trump administration installs new Pentagon leadership. Future of CDAO and Advana declared uncertain.

**February–March 2025:** Defense Secretary Hegseth announces 5–8% civilian workforce cuts; CDAO loses approximately **60% of its workforce**, including two top architects. Contracted staff reduced by approximately 80%.

**March 13, 2025:** Under Secretary for Acquisition and Sustainment Steven Morani signs a memo directing evaluation of whether Advana should become a **formal Program of Record**. Requires 30-day capability needs statement and 60-day acquisition pathway review.

**March 2025:** DefenseScoop publishes "Make Advana Great Again" — noting the platform lost its way as it expanded beyond financial management and has failed to help DoD pass audits despite ~$1 billion invested.

**April 2025:** Officials state intention to decide Advana's next moves by mid-June 2025.

**May 2025:** Multiple top CDAO leaders and tech staff depart; CDAO's future declared uncertain.

**July 2025:** Pentagon **formally halts the AAMAC/Advana recompete solicitation**: "This draft solicitation has been canceled as the Advancing Artificial Intelligence Multiple Award Contract (AAMAC) program is currently on hold." Booz Allen Hamilton's existing $647M contract continues.

**August 2025:** CDAO relocated under the Under Secretary of Defense for Research and Engineering (Emil Michael). Michael given a **120-day clock** to recommend a path forward for both Advana and Maven Smart System. Pentagon officials describe data reverting to silos, intelligence sharing returning to "phone calls and PDFs."

**December 2025:** Emil Michael outlines aggressive plan to push AI capabilities to all 3 million DoD users across classification levels. Rebuilding talent within CDAO through "recruiting Tuesdays."

**January 9, 2026:** Defense Secretary Hegseth issues the "**Transforming Advana to Accelerate Artificial Intelligence and Enhance Auditability**" memo, ordering a three-way restructuring of Advana:

### The January 2026 Restructuring

The Hegseth memo divides Advana into three components:

**1. War Data Platform (WDP)**
- Expands the core data integration layer into a DoD-wide standardized data access infrastructure
- Enables rapid AI application development across all DoD components
- Led by senior technical officials within CDAO/Research & Engineering
- Designed to support "agentic AI" use cases

**2. Advana for Financial Management**
- Returns financial data management to the Office of the Under Secretary of Defense (Comptroller)
- Focuses on audit remediation
- Goals: Clean audit on FY 2027 Defense Working Capital Fund; clean audit on FY 2028 agency-wide financial statements

**3. War Data Platform Application Services**
- Consolidates all non-audit Advana applications
- Manages migrations from legacy Advana to new WDP
- Enables self-service integration of new AI tools

**Implementation milestones:**
- 30 days: Reassign Advana personnel; stand up dedicated FM control plane
- 60 days: Deliver WDP expansion plan; review and divest legacy tools
- 120 days: Formalize WDP requirements
- 45-day intervals: Status updates to Deputy Secretary until full operational capability
- 270 days after FOC: Recommend Programs of Record as needed

**January 2026:** Advana omitted from FY 2025 Agency Financial Report for the first time since the platform's inception — raising transparency questions. FY 2025 SOC-1 audit result is adverse.

### Other Notable 2025–2026 Developments
- **Maven Smart System** placed under same 120-day review as Advana; Palantir's Maven AI being considered as Program of Record
- **Pentagon designated "Department of War"** under Hegseth administration; this terminology appears in official documents
- Emil Michael consolidating all tech offices under CTO role within Research & Engineering Directorate

---

## 6. Public Documentation and Resources

| Resource | URL/Location |
|---|---|
| Official Advana portal | https://advana.data.mil (CAC required) |
| CDAO AI initiatives page | https://www.ai.mil/Initiatives/Analytic-Tools/ |
| Advana Defense Analytics Platform video (DAU) | https://media.dau.edu/media/t/1_bqg1km0j |
| Advana U Introduction document (DAU) | https://www.dau.edu/sites/default/files/webform/documents/26871/ |
| Jan 2026 Hegseth Restructuring Memo | https://media.defense.gov/2026/Jan/12/2003855667/-1/-1/0/TRANSFORMING-ADVANA-TO-ACCELERATE-ARTIFICIAL-INTELLIGENCE-AND-ENHANCE-AUDITABILITY.PDF |
| DAU Product Support Data Analytics (Acquipedia) | https://www.dau.edu/acquipedia-article/product-support-data-analytics |
| Army data pipeline article | https://www.army.mil/article/270109/ |
| Booz Allen Advana overview | https://www.boozallen.com/d/insight/thought-leadership/advanced-enterprise-analytics-at-the-defense-department.html |
| DoD Procurement Toolbox (Advana access guide) | https://dodprocurementtoolbox.com/site-pages/advana-simplified-onboarding |
| WARU tools page | https://www.waru.edu/tools/advana |
| Collibra OSD case study | https://www.collibra.com/customer-stories/office-of-the-secretary-of-defense |
| DefenseScoop coverage | https://defensescoop.com (search "Advana") |
| Breaking Defense coverage | https://breakingdefense.com (search "Advana") |
| Defense One coverage | https://www.defenseone.com (search "Advana") |

### Advana Help Desk
For access requests and technical support: Submit a Help Desk ticket through the Advana portal. Initial access requires DD Form 2875 submission.

---

## 7. Summary Assessment

**Strengths (as of research date):**
- Massive scope: 100,000+ users, 400+ connected systems, covers every major DoD data domain
- Demonstrated real-world use in logistics, force planning, financial management, and readiness
- Rich tool ecosystem: Qlik, Databricks, Collibra, DataRobot, SageMaker, GitLab all accessible
- Real-time streaming data pipelines from major Army ERP systems
- Advana University provides training at no cost to authorized users
- Foundation for Open DAGIR multi-vendor ecosystem

**Significant risks and challenges (2025–2026):**
- Severe workforce reduction (~60% of CDAO staff lost in 2025)
- AAMAC recompete halted; future contracting vehicle uncertain
- Platform reverting to data silos due to staffing shortfalls
- Architecture described as unable to meet demand for advanced analytic tools
- Seven consecutive failed DoD audits despite the platform's original audit mission
- FY 2025 SOC-1 audit produced adverse result
- Ongoing restructuring into three separate tracks adds organizational complexity
- Significant leadership turnover from January 2025 onward

**Bottom line:** Advana remains the DoD's central data and analytics platform and continues to serve 100,000+ users, but is in a period of significant institutional turbulence. The January 2026 restructuring into War Data Platform and Financial Management tracks signals a major strategic pivot. Data scientists working in DoD environments should track the War Data Platform development, as it is intended to become the standardized foundation for AI application development across the department.

---

*Sources: DefenseScoop, Breaking Defense, Defense One, MeriTalk, Federal News Network, Army.mil, DAU/WARU, media.defense.gov, Booz Allen Hamilton, Government Technology Insider, FedScoop, DoD Procurement Toolbox, Collibra, GovCIO Media*
