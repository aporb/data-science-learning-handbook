# Navy Jupiter Platform Research
**Research Date:** March 2026
**Classification:** Based on publicly available information only
**Primary URL:** https://jupiter.data.mil (CAC required)
**Contact:** DON_Data@navy.mil

---

## 1. What Navy Jupiter Is

Jupiter is the **Department of the Navy (DON) enterprise data environment** — an analytics and data management platform launched in April 2020 to make DON data widely discoverable, accessible, understandable, and usable across the Naval enterprise.

Structurally, **Jupiter is the DON subtenant of Advana** (the DoD-wide platform managed by CDAO). This means Jupiter operates within the broader Advana/CDAO infrastructure while serving Navy and Marine Corps-specific data and analytics needs. It sits one layer below the DoD enterprise platform and provides DON-specific data governance, tooling, and community spaces.

Jupiter supports the Department of the Navy's mission across three pillars:
- **Warfighting** — readiness, maintenance, operations data
- **Business** — financial management, procurement, contracts
- **Readiness** — personnel, training, health

**Origin and ownership:** Managed by the Department of the Navy Chief Information Officer (DON CIO) and Chief Data Officer (CDO) function within the broader DON digital infrastructure.

**Name significance:** Named for the largest planet in the solar system, symbolizing the platform's role as a gravitational center for Naval data — with other tools (Collibra, Databricks, iQuery, etc.) orbiting as part of the ecosystem.

---

## 2. Current Capabilities

### Scale
- **Users:** Over 4,000 DON users as of early reporting; the platform has grown since launch in 2020
- **Audience:** Navy and Marine Corps military, civilian, and contractor personnel
- **Networks:** Operational on NIPRNET, SIPRNET, and JWICS (three separate classification tiers)
- **Data sensitivity:** Approved to process PII/PHI; approved for business-sensitive data

### Core Capability Areas

**Data Discovery and Catalog**
A searchable and collaborative data catalog (built on Collibra) that provides metadata on all Naval data assets within Jupiter and the broader Advana/CDAO technical ecosystem. Ensures data quality, stewardship, and stakeholder collaboration. Enables users to find datasets before starting projects — addressing a critical gap where previously personnel could not locate what data existed.

**Data Warehousing and Integration**
Cloud-based data storage and pipeline orchestration. Supports ingestion from DON source systems across finance, personnel, readiness, logistics, and operations. Common data models link enterprise-wide data sources to provide DON-wide visibility and cross-functional analytics.

**Advanced Analytics and Data Science**
A web-based toolkit for performing:
- Massive queries across enterprise datasets
- Data wrangling and preparation
- Business intelligence and reporting
- Advanced data science using "state of practice tools and languages"

**AI/ML Development**
Data-warehousing tools and applications for developing and deploying AI and ML models. Support for condition-based and predictive maintenance use cases. Integration with ML frameworks for algorithm development against DON data.

**Visualization**
Tableau (DON Tableau Day is a documented DON community event). Organizations can automate data source feeds and create repeatable visual products.

### Tool Ecosystem (Documented)

| Tool | Category | Notes |
|---|---|---|
| **iQuery** | Query/exploration | DON-specific data query interface |
| **Qlik** | Business intelligence/visualization | Part of Advana ecosystem |
| **Databricks** | Data engineering / ML platform | Used for AI model development |
| **Collibra** | Data governance / data catalog | Primary metadata and data discovery tool |
| **Tableau** | Visualization / BI | Featured at DON Tableau Day events |
| **Data Catalog** (Jupiter-native) | Metadata / discovery | Comprehensive catalog of DON data assets |
| Python | Data science language | Available via Databricks and other tools |
| SQL | Query language | Standard across query and warehouse tools |

### Data Tiering: Bronze / Silver / Gold

Jupiter implements a three-tier data classification system for data quality:

| Tier | Description | Use |
|---|---|---|
| **Bronze** | Raw, unprocessed data as ingested from source systems | Development, exploration |
| **Silver** | Organized, structured, and cleaned data | Intermediate analytics |
| **Gold** | Verified, validated, authoritative data | Official reporting and decision dashboards |

**Example:** The CNO Executive Metrics Dashboard (built by Naval Information Warfare Center Atlantic, launched January 2025) uses only **gold-tier data** from Jupiter. The dashboard updates automatically and provides Admiral Franchetti with real-time readiness, manning, and maintenance metrics used in Pentagon, congressional, and White House briefings.

---

## 3. How Data Scientists Use Jupiter

### Access Process
1. Navigate to **https://jupiter.data.mil**
2. Authenticate with a **valid Common Access Card (CAC)** or **Personal Identity Verification (PIV) token**
3. Any DON personnel (Navy or Marine Corps military, civilian, or contractor with DON sponsorship) with a valid CAC/PIV can access Jupiter and selected data sets — this is the **Baseline Access** policy announced via DON CDO policy memo
4. Granular access control exists for more sensitive data spaces and higher classification tiers (SIPR, JWICS)

### User Tiers and Workflows

**Decision-Maker / Consumer**
- Access pre-built dashboards and reports for their functional area
- Use the CNO Executive Metrics Dashboard or command-level readiness dashboards
- Interact with gold-tier, verified data

**Analyst**
- Use iQuery for direct data querying
- Build Qlik or Tableau reports and dashboards
- Access the Collibra data catalog to discover datasets relevant to their mission
- Pull data across multiple DON source systems using common data models

**Data Scientist / ML Practitioner**
- Work in Databricks notebooks (Python/PySpark/SQL)
- Use the Data Catalog (Collibra) to identify and access authoritative datasets
- Build and test AI/ML models against bronze/silver data; validate against gold
- Leverage the "federated model" approach: central data governance (catalog + standards) with decentralized AI/ML development nodes at locations where domain expertise exists (surface force, reserve, logistics, etc.)
- Deploy models for use cases including predictive maintenance, personnel behavior analysis, readiness forecasting

**Data Engineer**
- Build automated data pipelines from DON source systems
- Manage data quality through Collibra governance workflows
- Create repeatable ingestion and transformation processes using Databricks

### Collaboration Model
Jupiter emphasizes the co-production model where **operators/warfighters collaborate alongside data scientists** in every step of problem framing, data access, and model development — moving away from traditional contractor-only development cycles.

### Community and Training
- DON Tableau Day — community event for sharing visualizations and best practices
- Jupiter enables "community growth and collaboration" through shared data spaces
- Shared development environments allow multiple teams to build on common data assets

---

## 4. Security and Compliance

### Network Accreditation
Jupiter maintains **Authority to Operate (ATO)** on all three major DoD classification networks:

| Network | Classification | Access |
|---|---|---|
| **NIPRNET** | Unclassified (including CUI/FOUO/PII/PHI) | Standard CAC/PIV access for all DON personnel |
| **SIPRNET** | Secret | Requires Secret clearance; separate SIPR access |
| **JWICS** | Top Secret / SCI | Requires TS/SCI access; most sensitive data |

This tri-network accreditation is a significant differentiator — Jupiter can support analytics workflows that span from unclassified business data through classified operational and intelligence data.

### Data Sensitivity Approvals
- **PII (Personally Identifiable Information):** Approved for processing — enables personnel analytics, HR management, behavioral data tools
- **PHI (Protected Health Information):** Approved for processing — enables medical and health readiness analytics
- **Business Sensitive data:** Approved
- **Granular access control:** Defined access points and permission tiers allow fine-grained data access management

### Access Policy
The DON CDO released a policy memo streamlining access to Jupiter: **any DON personnel with a valid CAC or PIV token can access Jupiter and selected baseline datasets** without additional approval steps. For more sensitive data spaces or higher classification tiers, additional access controls apply.

### Data Governance
- Collibra serves as the authoritative metadata and data governance platform
- Data stewardship roles assigned to ensure quality and accountability
- Bronze/Silver/Gold tiering enforces data quality before data enters decision-making pipelines

---

## 5. Recent Developments (2024–2026)

### Neptune Cloud Management Office (2023–2025)
The Department of the Navy established the **Neptune Cloud Management Office** in 2023 (formally stood up by PEO Digital) to serve as the DON's cloud management function. Neptune operates as a "concierge service" for digital offerings across the enterprise. Jupiter is one of the enterprise services managed within Neptune's portfolio, alongside:
- Naval Identity Services (ICAM)
- Naval Integrated Modeling Environment (MBSE)
- Marine Corps Bolt (USMC equivalent)

In fiscal 2025, Neptune was scaling up its operations, with two components: one Navy-focused, one Marine Corps-focused. The office manages not just infrastructure-as-a-service and platform-as-a-service but also enterprise application services.

### Task Force Hopper and Surface Fleet AI (2021–2024)
**Task Force Hopper** (named for Admiral Grace Hopper) was launched in summer 2021 to operationalize AI/ML across the Naval Surface Force. Key developments:
- Selected **Advana-Jupiter as its primary common development environment** for data storage, cleaning, model development, and deployment
- Devising a **comprehensive data catalog** to address the surface force's fragmented data landscape: "Our data landscape is so vast and complex. There's no common data ecosystem, no data catalog, and not enough clean data"
- Adopted a **federated model** for data governance: centralized catalog and standards, decentralized AI development nodes at the fleet level
- Use cases include: predictive maintenance (condition-based maintenance for surface ships), readiness analytics, administrative efficiency, operational lethality improvements
- Published a surface force data and AI plan in 2023–2024

### CNO Executive Metrics Dashboard (January 2025)
Built by Naval Information Warfare Center (NIWC) Atlantic, the CNO dashboard:
- Feeds from Jupiter's gold-tier data
- Provides real-time readiness, manning, and maintenance metrics
- Features clickable graphics across ~12+ automatically updated metrics
- Used weekly by the CNO for high-level briefings
- Demonstrates Jupiter's role in senior leadership decision-making at the highest Navy level

### Navy Reserve Adoption
The U.S. Navy Reserve (approximately 59,000 personnel) formally adopted Jupiter in 2021:
- Established a Force Data Officer (FDO) role in 2021 (Capt. Kathleen Powell)
- Uses Jupiter to manage high-variability training budget allocations across selected reservists
- Transitions data science "from R&D setting through pilot" into production environments
- Operationalizes warfighting readiness assessments and training analytics

### DON Financial Management Integration (2024)
- Jupiter connected to DON financial systems to support audit readiness — paralleling Advana's broader DoD financial management mission
- Navy Comptroller referenced ERP software and big data analytics (including Jupiter) as the path to a clean DoD audit

---

## 6. Relationship to Advana and Other DoD Platforms

### Jupiter as DON Subtenant of Advana

The relationship between Jupiter and Advana is hierarchical and federated:

```
DoD Enterprise Layer
└── Advana (CDAO)
    ├── DoD-wide data integration and analytics infrastructure
    ├── DoD-wide applications (finance, logistics, readiness)
    └── DON Subtenant: Jupiter
        ├── DON-specific data governance (Collibra)
        ├── DON-specific data sources and pipelines
        ├── DON community spaces and dashboards
        └── Navy/USMC ML development environments (Databricks)
    Other Service Subtenants:
    ├── Army data spaces
    ├── Air Force data spaces
    └── Combatant command spaces
```

**Key implications for users:**
- Data scientists working in Jupiter can access both DON-specific data and DoD-wide data available through Advana
- The same tool ecosystem (Databricks, Qlik, Collibra) available DoD-wide on Advana is also accessible through Jupiter's DON tenant
- Jupiter's metadata catalog (Collibra) covers data within Jupiter and "in the wider Advana technical ecosystem"

### Relationship to Neptune (Cloud Management)
Neptune is the DON cloud management and delivery office. Jupiter is one of Neptune's managed enterprise services — Neptune provides the cloud infrastructure and management layer on which Jupiter (and other DON enterprise tools) run.

### Relationship to War Data Platform (2026 and beyond)
The January 2026 Hegseth memo restructuring Advana into a War Data Platform will directly affect Jupiter:
- Jupiter, as the DON subtenant of Advana, would transition to operate under the **War Data Platform** structure
- The WDP aims to standardize data access across all DoD components — Jupiter's federated model aligns with this vision
- The financial management track of the restructuring mirrors DON's own Jupiter-supported audit readiness work

### Comparison to Other DoD Data Platforms

| Platform | Scope | Relationship to Jupiter |
|---|---|---|
| **Advana (CDAO)** | DoD enterprise | Jupiter is the DON subtenant |
| **Neptune** | DON cloud management | Manages Jupiter's infrastructure |
| **Maven Smart System** | Intelligence/ISR analytics | Separate DoD AI platform; parallel effort |
| **Marine Corps Bolt** | USMC-specific | Marine Corps equivalent within Neptune/DON structure |
| **Navy Data Environment (NDE)** | Earlier Navy data initiative | Predecessor/complementary to Jupiter |

---

## 7. Public Documentation and Resources

| Resource | URL |
|---|---|
| Jupiter portal | https://jupiter.data.mil (CAC required) |
| DON CIO CHIPS article: "Jupiter: Bringing the Power of Data Analytics to the DON" | https://www.doncio.navy.mil/chips/ArticleDetails.aspx?ID=13804 |
| CHIPS article: "Streamlining Access to Jupiter" | https://www.doncio.navy.mil/chips/ArticleDetails.aspx?ID=15370 |
| CHIPS article: Jupiter and COVID-19 tracing | https://www.doncio.navy.mil/chips/ArticleDetails.aspx?ID=14362 |
| CHIPS article: Jupiter and Navy Reserve operations | https://www.doncio.navy.mil/chips/ArticleDetails.aspx?ID=14589 |
| DAU "What is Jupiter?" PDF | https://www.dau.edu/cop/DM/documents/what-jupiter |
| DVIDS video: "What is Jupiter?" | https://www.dvidshub.net/video/920290/jupiter |
| DAU Data Analytics and Management CoP | https://www.dau.edu/cop/DM |
| PEO Digital Neptune article | https://www.peodigital.navy.mil/News/Article/3498240/ |
| FedScoop: Task Force Hopper data catalog | https://fedscoop.com/ai-task-force-for-navy-surface-fleet-devising-comprehensive-data-catalog/ |
| Defense One: CNO dashboard article | https://www.defenseone.com/defense-systems/2025/01/new-dashboard-helping-cno-keep-tabs-readiness-manning-and-more/402062/ |
| MeriTalk: Jupiter at Navy Reserve | https://meritalk.com/articles/jupiter-platform-democratizing-data-at-u-s-navy-reserve/ |
| Navy Data Environment (DAU) | https://www.dau.edu/tools/navy-data-environment-nde |
| Contact for Jupiter access | DON_Data@navy.mil |

---

## 8. Summary Assessment

**Strengths:**
- Tri-network accreditation (NIPRNET/SIPRNET/JWICS) — rare and operationally significant capability
- PII/PHI approval enables personnel analytics that many platforms cannot support
- Strong data governance via Collibra with bronze/silver/gold tiering
- Proven use cases from Navy Reserve to CNO's office to Task Force Hopper surface fleet operations
- Natural integration point with DoD-wide Advana ecosystem — data scientists get both DON-specific and enterprise-wide access
- Baseline CAC-only access policy lowers barrier to entry for all DON personnel
- Neptune provides managed cloud infrastructure, reducing operational burden on users
- Federated model supports both centralized governance and distributed innovation

**Limitations and gaps (based on public information):**
- User base (4,000+) much smaller than Advana's 100,000+ — still scaling
- Surface fleet data described as fragmented with "no common data ecosystem" as recently as 2022
- Limited public documentation on specific ML workflows and model deployment processes
- No public information on specific Python/R versions, compute resources, or GPU availability for model training
- Platform impact from the 2025 Advana restructuring (CDAO staff losses of ~60%) unclear — Jupiter's operations may be affected through its dependency on Advana infrastructure

**Bottom line:** Jupiter is a mature, multi-network DON enterprise platform well-suited for Navy and Marine Corps data science work. Its Advana/CDAO integration means data scientists get access to both DON-specific data and the broader DoD tool ecosystem. The tri-network accreditation (including JWICS) and PII/PHI approval make it particularly powerful for sensitive operational and personnel analytics. The CNO dashboard use case and Task Force Hopper adoption demonstrate real production-level deployment, not just pilot programs. Data scientists in DON organizations should treat Jupiter as the standard starting point for enterprise analytics projects.

---

*Sources: DONCIO CHIPS Magazine, DAU/WARU, DVIDS, DefenseScoop, Defense One, FedScoop, MeriTalk, PEO Digital, Federal News Network, USNI News, National Defense Magazine, Surface Warfare Magazine, Issuu/COMNAVSURFPAC*
