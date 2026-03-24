# Chapter 01 Exercises: Introduction to Data Science in Government

These exercises are designed to be completed during your first two weeks on a federal data science contract, or as practice scenarios if you are preparing for one. They do not require classified systems access — all exercises use publicly available data, local environments, or simulation.

---

## Exercise 1: Platform Selection Decision Tree

**Estimated time:** 30–45 minutes
**What you need:** Pen and paper or any text editor; no platform access required

You have just been assigned to three different hypothetical projects. For each scenario below, determine:

1. Which of the five platforms is the primary fit (Advana, Jupiter, Databricks, Qlik, Palantir Foundry)
2. What Impact Level or FedRAMP tier your data processing environment needs
3. One reason another platform would be the wrong choice for this scenario

**Scenario A — The Readiness Dashboard**

A Marine Corps logistics officer needs a weekly dashboard showing equipment readiness rates for three battalions, broken down by equipment category and geographic location. The data comes from two DON source systems, both on NIPRNET. The output will be viewed by O-5 and above officers who are not technical users. Interactivity is important — they want to click on a unit and drill into specific equipment failures.

**Scenario B — The Predictive Maintenance Model**

The Naval Surface Forces are building a model to predict which shipboard components will fail within the next 30 days. Training data includes 5 years of maintenance records, sensor readings from ship systems, and supply chain delivery logs — approximately 200 million rows total. The model will score new records nightly and feed an alert system. The data is CUI (IL4). The team includes two data engineers and three data scientists who write Python and PySpark.

**Scenario C — The Battlefield Decision Tool**

An Army command needs an application that integrates intelligence reports, asset tracking data, and logistics feeds to generate a real-time operational picture. The application must allow analysts to ask natural language questions about enemy position data and receive grounded answers (not hallucinations). Some data is at the Secret level. The output is an operational tool used by soldiers, not a report for leadership.

**Submit your answers as:**
- Three structured responses, one per scenario
- Each with: Platform choice, IL/FedRAMP requirement, wrong platform + reason

---

## Exercise 2: Your First Week Onboarding Plan

**Estimated time:** 45–60 minutes
**What you need:** The checklist from Chapter 01 + any publicly available contract opportunity document from SAM.gov for a data analytics role

Federal onboarding has a sequence. Get it wrong and you spend week three waiting for access you should have requested in week one.

**Part A:** Using the Practical Takeaway checklist from Chapter 01, identify which five items on the list you believe would take the longest to complete, and explain why each one is slow. (Examples: "DD Form 2875 requires a supervisor signature and a help desk ticket — two dependencies I don't control.")

**Part B:** Build a realistic Day 1 through Day 10 onboarding plan. Structure it as a table with:
- Day (1–10)
- What you do
- What you are waiting on (external dependencies)
- What you do if the wait is longer than expected

**Part C:** The scenario — you are starting a new contract on Monday. You will need access to: Advana (NIPRNET), a Databricks workspace on that Advana tenant, and GitLab for version control. Based on what you read in Chapter 01 and the public documentation available at advana.data.mil (CAC required), dodprocurementtoolbox.com/site-pages/advana-simplified-onboarding, and the DAU resources linked in the research notes:

Write the first email you would send to your program manager on Day 1, requesting the information and support you need to begin your access request process. Keep it under 150 words. Be specific about what you are asking for.

---

## Exercise 3: Collibra Data Catalog Simulation

**Estimated time:** 60 minutes
**What you need:** Python 3.9+, pandas, Jupyter notebook or any Python environment

You do not have access to a live Collibra instance. This exercise simulates what searching a data catalog should tell you before you write a single line of data analysis code.

**Setup:** Create a local Python environment and run the simulation notebook below. (Copy this code into a `.py` file or Jupyter notebook.)

```python
"""
Simulated data catalog entries — mimicking what Collibra would return
for a search on "ship_maintenance" in a DON Jupiter environment.

Real Collibra catalog metadata includes: name, data tier, steward,
known quality issues, lineage, and access requirements.
"""

import pandas as pd

SIMULATED_CATALOG = [
    {
        "name": "ship_maintenance_events_raw",
        "data_tier": "Bronze",
        "steward": "NIWC Atlantic - Data Management Team",
        "description": "Raw maintenance event records from SAMS-E (Surface Ship system). Ingested daily.",
        "known_issues": [
            "Duplicate records present when SAMS-E pushes retry batches (approximately 3-5% of rows)",
            "date_completed field is NULL for approximately 12% of records with status=CLOSED — confirmed data entry gap in source system",
            "unit_code field uses two different encoding schemes before/after FY2022 transition"
        ],
        "row_count_approx": 22_000_000,
        "last_updated": "2026-03-22",
        "access_required": "Jupiter NIPR Baseline"
    },
    {
        "name": "ship_maintenance_events_cleaned",
        "data_tier": "Silver",
        "steward": "NIWC Atlantic - Data Management Team",
        "description": "Deduplicated, NULL-handled version of raw maintenance events. unit_code normalized.",
        "known_issues": [
            "Deduplication does not resolve cases where two legitimate events have same hull/date/type",
            "12% NULL issue in date_completed inherited from Bronze — not resolvable without source system fix"
        ],
        "row_count_approx": 21_120_000,
        "last_updated": "2026-03-22",
        "access_required": "Jupiter NIPR Baseline"
    },
    {
        "name": "ship_maintenance_metrics_official",
        "data_tier": "Gold",
        "steward": "SURFPAC N4 Data Office",
        "description": "Validated, auditable readiness metrics derived from silver data. Used in CNO dashboard.",
        "known_issues": [],
        "row_count_approx": 18_400_000,
        "last_updated": "2026-03-22",
        "access_required": "Jupiter NIPR + SURFPAC N4 Data Space approval"
    }
]

def display_catalog_entry(entry):
    print(f"\n{'='*60}")
    print(f"  [{entry['data_tier']}] {entry['name']}")
    print(f"  Steward: {entry['steward']}")
    print(f"  Rows (approx): {entry['row_count_approx']:,}")
    print(f"  Last updated: {entry['last_updated']}")
    print(f"  Access: {entry['access_required']}")
    print(f"  Description: {entry['description']}")
    if entry['known_issues']:
        print("  Known issues:")
        for issue in entry['known_issues']:
            print(f"    - {issue}")
    else:
        print("  No known issues on file.")

for entry in SIMULATED_CATALOG:
    display_catalog_entry(entry)
```

**Questions to answer after running the simulation:**

1. You are building a predictive maintenance model. Which tier of the `ship_maintenance_events` data should you use for initial development (exploration and feature engineering), and which should you use for your final training set? Explain the tradeoff.

2. The date_completed NULL problem affects 12% of records at both Bronze and Silver tier. List three possible strategies for handling this in a predictive model. For each strategy, describe the scenario in which it is the right choice.

3. The gold-tier data (`ship_maintenance_metrics_official`) requires additional access beyond your baseline Jupiter credentials. Write a short justification message (3-4 sentences) you would send to the SURFPAC N4 Data Office explaining why you need access to gold-tier data, what you will use it for, and what safeguards are in your planned analysis.

4. Based on the known issues in the Bronze tier data, estimate (with reasoning) the percentage of training examples that might be incorrectly labeled if you use Bronze data to train a binary classifier that predicts whether maintenance events are completed on time. This is a logic exercise — not a calculation.

---

## Exercise 4: Security Constraint Mapping

**Estimated time:** 30–40 minutes
**What you need:** The Impact Level table from Chapter 01, publicly available FedRAMP marketplace information

The following datasets have been assigned to your new analytics project. For each dataset, determine:
- The minimum authorization level required to process it
- Which of the five platforms can legally host the analysis
- Any specific handling requirement that changes your architecture

**Dataset 1:** Personnel records for 12,000 active duty Navy sailors, including name, SSN, medical fitness categories, and deployment history. Classification: Unclassified CUI/PII/PHI.

**Dataset 2:** Aggregate financial obligation data showing total contract spend by NAICS code and fiscal year, sourced from USASpending.gov. Classification: Public/Unclassified.

**Dataset 3:** Maintenance records for a specific class of submarines, including sensor readings from sonar systems. Classification: CONFIDENTIAL//NOFORN.

**Dataset 4:** Procurement records for IT equipment purchases, including vendor names, contract numbers, dollar values. Classification: CUI/FOUO.

Build a table with columns: Dataset | Min IL/FedRAMP | Approved Platforms | Special Handling

Then answer: If your project requires combining datasets 1 and 4 in a single analysis, what is the resulting classification requirement for the combined dataset, and which platforms can host it?

---

## Exercise 5: End-to-End Workflow Design

**Estimated time:** 60–90 minutes
**What you need:** Python environment, the code in `01_platform_connections.py`

Design and partially implement a minimal end-to-end analytics workflow for the following scenario using the tools and patterns from the chapter code examples.

**The scenario:** A Navy program office wants to monitor contract performance for a set of maintenance contractors. They want a weekly report showing which vendors have the highest proportion of overdue work orders. The data comes from two sources: a maintenance tracking system (time-based work order data) and a contract registry (vendor information). Both are NIPRNET/IL4.

**Part 1: Architecture diagram** — Draw (or write in pseudocode/markdown) a data flow showing:
- Where data comes from
- What platform handles each stage (ingest, transform, model/analyze, visualize)
- Who sees the final output and in what form

**Part 2: Python implementation** — Using only standard Python libraries plus pandas, numpy, and scikit-learn (no platform access required), implement the data transformation logic:

```python
# Starter code — complete the TODOs
import pandas as pd
import numpy as np
from datetime import datetime, timedelta

# Simulated maintenance work order data
np.random.seed(99)
n_orders = 2000
vendors = ["Huntington Ingalls", "General Dynamics", "BAE Systems", "L3Harris", "Textron"]

work_orders = pd.DataFrame({
    "work_order_id": range(1, n_orders + 1),
    "vendor_id": np.random.choice(range(len(vendors)), n_orders),
    "scheduled_completion": [
        datetime(2025, 1, 1) + timedelta(days=int(x))
        for x in np.random.uniform(0, 365, n_orders)
    ],
    "actual_completion": [
        datetime(2025, 1, 1) + timedelta(days=int(x))
        for x in np.random.uniform(0, 400, n_orders)
    ]
})

vendor_registry = pd.DataFrame({
    "vendor_id": range(len(vendors)),
    "vendor_name": vendors,
    "contract_type": ["CPFF", "FFP", "T&M", "CPFF", "FFP"]
})

# TODO 1: Join work orders to vendor names

# TODO 2: Create a boolean column "is_overdue" where actual_completion > scheduled_completion

# TODO 3: Calculate per-vendor: total orders, overdue count, overdue rate (%)

# TODO 4: Sort by overdue rate descending

# TODO 5: Print a formatted summary table

# TODO 6: Write a function that takes a threshold (e.g., 0.25 = 25%) and returns
#          a list of vendor names whose overdue rate exceeds that threshold.
#          This function would be called from a Qlik SSE endpoint or a
#          Databricks workflow step.
```

**Part 3: Platform annotation** — Add comments to your implementation indicating, for each section:
- Which platform would own this step in a production DoD deployment
- What the compliance/governance checkpoint is (data catalog check? audit log? gold-tier validation?)
