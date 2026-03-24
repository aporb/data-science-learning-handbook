# Chapter 01 Solutions: Introduction to Data Science in Government

---

## Exercise 1 Solutions: Platform Selection Decision Tree

### Scenario A — The Readiness Dashboard

**Primary platform: Qlik (via Advana/Jupiter)**

The deliverable is an interactive dashboard for non-technical senior officers. Qlik is the correct choice because:
- The QIX associative engine handles the click-and-drill pattern naturally — when an officer clicks a battalion, all related charts update instantly without SQL round-trips
- Qlik is the visualization layer that program managers and command staff already use on both Advana and Jupiter
- DON source systems on NIPRNET feed directly into Jupiter, which exposes Qlik as a visualization tool

**IL/FedRAMP requirement:** IL4 (data is NIPRNET CUI; Qlik Cloud Government - DoD is authorized at IL4 via JWCC/AWS)

**Wrong platform and reason:** Databricks is wrong here. Databricks notebooks produce outputs suited for data scientists, not for an O-5 looking at a weekly readiness report. Databricks has no native dashboard publication path for non-technical users; every output requires a technical intermediary to interpret. Use Databricks for the underlying data pipeline that feeds the Qlik dashboard, not for the dashboard itself.

---

### Scenario B — The Predictive Maintenance Model

**Primary platform: Databricks (on Advana or standalone DoD GovCloud tenant)**

The requirements point directly to Databricks:
- 200 million rows requires distributed processing — pandas on a single machine will run out of memory at this scale; PySpark on a Databricks cluster handles it without redesigning your code
- MLflow (native to Databricks) handles the nightly batch scoring pipeline and tracks every training run automatically
- DoD IL5 authorization on AWS GovCloud means the CUI data can be processed within compliance boundaries
- The team writes PySpark — Databricks is their natural environment

**IL/FedRAMP requirement:** IL4 minimum (CUI data); IL5 recommended for scale and to allow higher-sensitivity CUI categories that might appear in maintenance records

**Wrong platform and reason:** Qlik is wrong for this use case. Qlik Predict (AutoML) can build basic ML models, but it is a no-code tool designed for analysts, not a production MLOps platform for a team of five engineers building a system that scores 200 million rows nightly. SSE (Server-Side Extension) could run the scoring function from within Qlik, but the model development and training should happen in Databricks. Qlik is the dashboard consumer of the model's outputs, not the development environment.

---

### Scenario C — The Battlefield Decision Tool

**Primary platform: Palantir AIP/Foundry**

This scenario has three signals that point to Palantir, not the other platforms:
1. Natural language questions answered by grounded AI: this is AIP's core function — LLM interaction through the Ontology, connected to real operational data, preventing hallucinations
2. Secret-level data: Palantir deploys on Azure Government Top Secret (equivalent to DoD IL6) via its Microsoft partnership — the only platform in this handbook that handles classified data at that level
3. The output is an operational tool, not a report — users take actions, not just read charts. Foundry's Workshop + Actions pattern is built for this; Qlik and Databricks are not

**IL/FedRAMP requirement:** IL6/Secret (SIPRNET minimum, or classified network based on specific data); Palantir's Azure Government Secret deployment covers this

**Wrong platform and reason:** Databricks is wrong. Databricks has strong ML capabilities but has no publicly documented IL6 authorization and no operational application layer — it does not support writeback actions, does not support classified network deployment, and is not designed to surface a natural language interface to field operators. It belongs upstream as a data pipeline tool feeding a Foundry Ontology, not as the operational endpoint itself.

---

## Exercise 2 Solutions: First-Week Onboarding Plan

### Part A: Five Slowest Items (with reasoning)

1. **DD Form 2875 submission** — requires three inputs you may not control: your supervisor's signature, the data owner's signature, and a help desk ticket submission. Any one of these can take 2-5 business days each, and they often need to happen in sequence.

2. **Clearance verification against specific data spaces** — your clearance may be on file, but each data space on Advana/Jupiter may have its own access control list. Verifying that your clearance maps to a specific community requires the platform's admin team to confirm, which goes through a ticketing system with its own queue.

3. **GitLab access for the program repository** — GitLab access on government-managed instances requires the repository owner to manually add your account. If the team lead is traveling or if the repository is managed by a separate contractor, this can sit unresolved for a week.

4. **Databricks workspace provisioning** — a Databricks workspace tied to Advana is not automatically available when you have Advana platform access. It requires a separate provisioning request, often through the program's platform admin team.

5. **VPN or NIPRNET access configuration** — if your machine is not government-furnished equipment (GFE), getting a government-approved configuration may require your agency's IT desk to provision your device, which has its own queue. On GFE, configuration is faster but still requires a service ticket.

---

### Part B: Day 1–10 Onboarding Plan

| Day | Actions | Waiting On | Contingency |
|-----|---------|------------|-------------|
| 1 | Submit all access request forms; install CAC middleware; DoD cert bundle; meet team lead | Supervisor signature on DD Form 2875 | Review existing code/docs while waiting |
| 2 | Submit GitLab access request; review any documentation the team has shared; attend stand-up | DD Form 2875 in transit | Shadow a team member on existing tasks |
| 3 | Test CAC auth on a non-classified DoD site (dau.edu, doncio.navy.mil); review platform access docs | All pending requests | Access Advana University (available without DD Form 2875) |
| 4 | Follow up on all open access requests; identify data steward for primary dataset | Platform admin ticket resolution | Begin reading research docs in the program's knowledge base |
| 5 | Confirm Advana access status; if granted, log in and run test query | GitLab access pending | Write initial project documentation from what you know so far |
| 6 | If GitLab access granted, clone repo and review codebase; identify open issues | Databricks workspace provisioning | Explore Advana University training |
| 7 | First Databricks notebook run (if provisioned); validate data catalog access in Collibra | Data space approval for target datasets | Explore existing notebooks others have built |
| 8 | Identify first dataset by searching Collibra; review its lineage and known issues | Data space access if still pending | Build local simulation using public data to test your pipeline logic |
| 9 | Begin exploratory analysis on approved dataset; log findings in the team's shared documentation | None expected at this point | — |
| 10 | Present first findings to team; confirm model development plan; close any remaining access gaps | — | — |

---

### Part C: Day 1 Access Request Email

**Subject:** Access Request Support — Advana, Databricks, GitLab [Your Name]

Marcus,

I am starting today and need your help initiating platform access. To meet the week-two timeline, I need to submit the following by end of day: DD Form 2875 for Advana NIPRNET access (requires your countersignature), a Databricks workspace provisioning request (please send me the template or the admin contact), and the GitLab repository URL with the username of the owner who can grant access.

Can you send me those three items before noon? I can handle the DD Form 2875 and Advana Help Desk ticket myself once I have your signature.

[Your Name]

---

## Exercise 3 Solutions: Collibra Data Catalog Simulation

### Question 1: Which data tier for development vs. training?

**Development (exploration, feature engineering):** Use Silver tier (`ship_maintenance_events_cleaned`). It is deduplicated and has normalized codes, which means your exploratory work produces insights that are not distorted by the 3-5% duplicate rate in Bronze. You are not yet doing anything that goes into production — you are understanding the data. Silver is the right working tier for this phase.

**Final training set:** Use Gold tier (`ship_maintenance_metrics_official`) if your access request is approved. Gold data is what goes into the CNO dashboard. If you train on anything less, the model may learn patterns from noise or from data that was later corrected. The 12% NULL issue in Silver's `date_completed` is still present, but at Gold tier the data steward (SURFPAC N4 Data Office) has made specific decisions about how to handle it — and those decisions are what you should train against.

The tradeoff: Gold requires additional approval and may take a week to obtain. Use Silver to build and validate your pipeline, but get the Gold access request in on day one.

---

### Question 2: Three strategies for the date_completed NULL problem

**Strategy 1: Impute from related fields (regression imputation)**
Use other fields in the record (scheduled_completion, event_type, priority_code, maintenance_category) to predict what `date_completed` should be, train a regression imputer on the 88% of complete records, and fill NULLs. Right choice when: the records with NULLs are similar in distribution to complete records, and the imputed value is good enough for feature engineering (e.g., "days late") without needing exact precision.

**Strategy 2: Treat NULL as a category**
For classification models, create a binary feature `completion_date_known` (1/0) and either drop `date_completed` from features or replace NULLs with a sentinel value (e.g., far-future date or -1 in a delta-days field). Right choice when: you suspect the NULLs are not random — if the 12% of records with NULL completion dates are systematically associated with a particular event type or source system, the missingness itself is informative signal.

**Strategy 3: Exclude NULL records and document the exclusion**
Drop the 12% of records with NULL `date_completed` and document this explicitly in your model card. Right choice when: your model is predicting time-to-completion and a NULL target makes the training row unusable; or when the records with NULLs are confirmed to be data entry errors that would poison the model (e.g., maintenance events that were never properly closed). This is the most honest approach but reduces your training data.

---

### Question 3: Justification message to SURFPAC N4 Data Office

> I am a data scientist on [program name], developing a predictive maintenance risk model for surface fleet readiness. I am requesting access to the gold-tier `ship_maintenance_metrics_official` dataset because this data is the validated, auditable source used in CNO-level briefings, and training my model against it ensures my predictions align with the data standard that operational decisions are based on.
>
> My planned analysis involves training a binary classifier to predict maintenance event overruns at the ship-hull level. I will access this dataset within the Jupiter NIPRNET environment only, will not export raw records, and will document all data access in my model card and MLflow experiment log. The model output will be reviewed by [sponsor/program manager name] before any deployment.

---

### Question 4: Estimating mislabeled examples in Bronze data

**Reasoning:**

If you use Bronze data to train a binary classifier predicting whether maintenance events are completed on time, here are the contamination sources:

- **Duplicates (~3-5%):** Each duplicate row is an identical copy of a real event. If the original is labeled correctly, the duplicate is also labeled correctly — duplicates inflate your dataset but do not introduce mislabeled examples. However, they inflate your confidence in common patterns and underrepresent rare patterns. Effective mislabeling from duplicates: low (near 0%).

- **NULL `date_completed` for 12% of CLOSED records:** If your label is "completed on time" and you define on-time as `date_completed <= scheduled_completion`, then any record where `date_completed` is NULL cannot be correctly labeled. If you default NULL closed records to "on time" (because status=CLOSED, so it must be done), you may mislabel events that were closed administratively but were actually late. If you default them to "late," you mislabel events that were on time. **Estimated mislabeled rate from this source: up to 12% of records labeled as CLOSED.**

- **Unit code encoding inconsistency (pre/post FY2022):** This affects feature quality, not labels — assuming your labels come from the completion dates, not from unit codes.

**Bottom-line estimate:** Up to 12% of training records could have unreliable labels due to the NULL completion date issue, with near-zero additional mislabeling from duplicates. The actual proportion depends on what percentage of your training set is CLOSED-status records — which is likely a substantial majority. Recommend: use Silver or Gold tier data to avoid this problem entirely.

---

## Exercise 4 Solutions: Security Constraint Mapping

| Dataset | Min IL/FedRAMP | Approved Platforms | Special Handling |
|---------|---------------|-------------------|-----------------|
| 1 — Sailor PII/PHI | IL4 (CUI/PII/PHI) | Advana (NIPR), Jupiter (NIPR, explicit PII/PHI approval), Databricks IL4/IL5, Palantir IL4+ | Must comply with Privacy Act; access restricted to need-to-know; no export without data steward approval |
| 2 — Public USASpending.gov aggregate data | IL2 (public) | Any platform | No restrictions; confirm no re-identification risk if combined with other data |
| 3 — Submarine maintenance with sonar data | IL6 / CONFIDENTIAL | Jupiter (JWICS), Palantir (Azure Gov Top Secret) | SIPRNET or higher required; NOFORN — no foreign nationals; need CONFIDENTIAL clearance minimum |
| 4 — IT procurement CUI/FOUO | IL4 | Advana, Jupiter (NIPR), Databricks IL4, Qlik IL4, Palantir IL4+ | CUI handling requirements; limited dissemination |

**Combining Datasets 1 and 4:**

The combined dataset is CUI/PII — the higher of the two classifications governs. The minimum processing environment is **IL4**. Platforms that can host this combined analysis: Advana (NIPRNET), Jupiter (NIPRNET), Databricks (IL4 or IL5 on GovCloud), Palantir Foundry (IL4+).

Qlik Cloud Government is authorized at IL4 and could be used for visualizing combined outputs — but the underlying data storage and processing should happen on IL4-authorized infrastructure (Advana/Jupiter/Databricks) with Qlik consuming aggregated, non-raw outputs.

**Additional consideration:** Combining a dataset containing SSNs (Dataset 1) with a dataset containing IT purchase records (Dataset 4) creates a combined dataset with re-identification risk (could link a person's identity to specific purchases). This combination may require a Privacy Impact Assessment (PIA) before you can proceed, even though each individual dataset is already CUI.

---

## Exercise 5 Solutions: End-to-End Workflow Design

### Part 1: Architecture Diagram

```
Data Sources (NIPRNET, IL4)
├── Maintenance Tracking System (work orders, timestamps, vendor ID)
└── Contract Registry (vendor names, contract types, dollar values)
        │
        ▼
[Databricks on Advana/Jupiter — Ingest + Transform]
  - Qlik Replicate or Databricks Auto Loader: CDC from source systems to Delta Lake
  - Bronze table: raw ingested records
  - Silver table: deduplicated, joined to vendor registry, date fields normalized
  - Gold table: weekly overdue rate metrics by vendor (aggregated, no raw PII)
        │
        ▼
[Qlik — Visualization Layer]
  - Weekly dashboard: overdue rate by vendor, trend lines, contract type breakdown
  - SSE endpoint: Python function for threshold alerting (call from Qlik expression)
  - Audience: program managers and contracting officers (non-technical)
        │
        ▼
[Output: Weekly Report]
  - Qlik dashboard accessible via browser (CAC auth)
  - Optional: scheduled PDF export to program SharePoint
```

---

### Part 2: Python Implementation (Completed)

```python
import pandas as pd
import numpy as np
from datetime import datetime, timedelta

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
# Platform: Databricks Silver transform step — joins happen in PySpark
# Governance checkpoint: Both source tables must be in data catalog before join
df = work_orders.merge(vendor_registry, on="vendor_id", how="left")

# TODO 2: Create "is_overdue" boolean column
# Platform: Databricks Silver transform
# Governance: date fields must be in consistent format (Bronze → Silver normalization)
df["is_overdue"] = df["actual_completion"] > df["scheduled_completion"]

# TODO 3: Per-vendor aggregation
# Platform: Databricks Gold transform step
# Governance checkpoint: Gold-tier validation before loading to the analytics layer
vendor_summary = (
    df.groupby(["vendor_name", "contract_type"])
    .agg(
        total_orders=("work_order_id", "count"),
        overdue_count=("is_overdue", "sum")
    )
    .reset_index()
)
vendor_summary["overdue_rate_pct"] = (
    vendor_summary["overdue_count"] / vendor_summary["total_orders"] * 100
).round(1)

# TODO 4: Sort by overdue rate descending
vendor_summary = vendor_summary.sort_values("overdue_rate_pct", ascending=False)

# TODO 5: Print formatted summary table
print("Vendor Contract Performance — Overdue Work Orders")
print("=" * 65)
print(f"{'Vendor':<25} {'Type':<8} {'Total':>8} {'Overdue':>8} {'Rate':>8}")
print("-" * 65)
for _, row in vendor_summary.iterrows():
    print(
        f"{row['vendor_name']:<25} {row['contract_type']:<8} "
        f"{row['total_orders']:>8,} {row['overdue_count']:>8,} "
        f"{row['overdue_rate_pct']:>7.1f}%"
    )
print("=" * 65)

# TODO 6: Threshold function — this is the callable from Qlik SSE or Databricks workflow
# Platform: This function runs as a Python SSE endpoint called from Qlik
# Governance: The input data must be gold-tier before this function is called
def get_vendors_exceeding_overdue_threshold(
    df_summary: pd.DataFrame,
    threshold: float = 0.25
) -> list:
    """
    Returns list of vendor names whose overdue rate exceeds the threshold.

    Args:
        df_summary: vendor summary DataFrame with 'vendor_name' and 'overdue_rate_pct'
        threshold: fraction (0.0 to 1.0) — e.g., 0.25 = 25%

    Returns:
        List of vendor names. Empty list if no vendors exceed threshold.

    Called from: Qlik SSE expression or Databricks workflow alert step.
    Governance: Input data must be gold-tier validated before this call.
    """
    threshold_pct = threshold * 100
    flagged = df_summary[df_summary["overdue_rate_pct"] > threshold_pct]["vendor_name"].tolist()
    return flagged

at_risk = get_vendors_exceeding_overdue_threshold(vendor_summary, threshold=0.25)
if at_risk:
    print(f"\nVendors exceeding 25% overdue threshold: {', '.join(at_risk)}")
else:
    print("\nNo vendors currently exceed the 25% overdue threshold.")
```

---

### Part 3: Platform Annotation (already embedded in comments above)

Key annotations:
- **Databricks** owns the Bronze → Silver → Gold transformation pipeline
- **Collibra data catalog** is the governance checkpoint before any join or aggregation is done against source data
- **Gold tier validation** is required before data flows to the Qlik visualization layer
- **Qlik SSE** is the mechanism for calling the Python threshold function from within a dashboard expression
- **Audit logging** is automatic in Databricks via Unity Catalog; every query against the gold-tier Delta table is logged
