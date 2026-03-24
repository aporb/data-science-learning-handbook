# Chapter 12 Solutions: Ethics, Governance, and Compliance

---

## Exercise 1 — The 4/5ths Rule in Practice

### Step 1: Flag rates

| Group    | N scored | Flagged | Flag rate         |
|----------|----------|---------|-------------------|
| White    | 3,200    | 352     | 352/3200 = **11.00%** |
| Black    | 820      | 107     | 107/820 = **13.05%**  |
| Hispanic | 610      | 73      | 73/610 = **11.97%**   |

### Step 2: Dominant group (highest flag rate)

Black sailors have the highest flag rate at 13.05%.

### Step 3: Disparity ratios (each group vs. the dominant group)

| Group    | Flag rate | Ratio vs. Black (13.05%) | 4/5ths threshold |
|----------|-----------|--------------------------|------------------|
| White    | 11.00%    | 11.00 / 13.05 = **0.843** | ≥ 0.80           |
| Hispanic | 11.97%    | 11.97 / 13.05 = **0.917** | ≥ 0.80           |

### Step 4: Conclusion

The model passes the 4/5ths rule. Both non-dominant groups (White: 0.84, Hispanic: 0.92) exceed the 0.80 threshold. In a briefing: "The attrition model flags Black, White, and Hispanic sailors at rates of 13.1%, 11.0%, and 12.0% respectively. The lowest-flagged group (White) is flagged at 84% the rate of the highest-flagged group (Black), which exceeds the EEOC 4/5ths minimum of 80%. The model passes the demographic parity check."

### Step 5: Remediation options if the model had failed

**Option A — Per-group threshold calibration.** Lower the classification threshold for the over-flagged group so its flag rate falls to within 80% of the dominant group's rate. This is fast to implement and does not require retraining. The risk: calibrating thresholds post-hoc can reduce overall predictive performance (precision/recall trade-off shifts), and it does not fix the underlying cause of the disparity — it adjusts outputs rather than causes.

**Option B — Feature removal or reweighting.** Identify which features drive the disparity (via SHAP or proxy correlation scan) and either remove the offending feature or reduce its influence through regularization. This requires retraining and may reduce AUC if the correlated feature was predictive. The benefit: it addresses the root cause rather than masking it, which produces more defensible and stable fairness properties over time.

---

## Exercise 2 — Proxy Correlation Scan

### Question 1: Features with highest correlation

When running `run_full_bias_audit(inject_bias=True)`, the proxy scan will typically surface:

- `unit_assignment_code` — Cramér's V > 0.30 with race, because the synthetic data generator assigns certain unit codes disproportionately to minority sailors
- `deployment_days_ytd` — point-biserial correlation with race ~0.28, reflecting the injected pattern that minority sailors receive higher-risk deployments in the biased synthetic dataset
- `performance_score` — eta correlation with race ~0.22, reflecting the injected performance penalty

### Question 2: Why point-biserial rather than Pearson correlation

Point-biserial correlation is the correct choice when one variable is continuous and the other is binary, because it is mathematically equivalent to computing Pearson correlation after treating the binary variable as 0/1 — but it makes that assumption explicit and uses the appropriate formula that accounts for the binary variable's variance being `p(1-p)`. Pearson correlation can be used on the raw numbers and will give the same numeric result, but the point-biserial framing correctly signals to the reader that we are measuring the association between a continuous feature and a dichotomous group membership, rather than implying both variables are continuous.

### Question 3: Recommendation memo (Cramér's V = 0.30, SHAP rank #1)

---

**MEMORANDUM FOR:** N13 Analytics Director
**FROM:** Dr. Sarah Okafor, Navy People Analytics
**SUBJECT:** Proxy Correlation Finding — `unit_assignment_code` Feature

The automated proxy correlation scan identified that `unit_assignment_code` has a Cramér's V of 0.30 with race, indicating a moderate association. This same feature ranks first by mean absolute SHAP value in the current model.

Before removing this feature, we need two additional pieces of information: first, whether the correlation reflects current systemic assignment patterns (which would mean the feature is acting as a proxy now) or historical patterns that are no longer present in the current force structure; second, whether the feature's predictive power can be replicated by an alternative operationally-grounded feature (such as `occupational_specialty_attrition_rate`) that lacks the same demographic correlation.

This decision should be made by the program sponsor (N13 director) in coordination with the JAG Equal Opportunity advisor, not by the analytics team alone, because it involves a legal equity question and an operational trade-off between model accuracy and fairness.

Regardless of the decision, we will document the finding in the model card under "Proxy Correlation Findings" with the Cramér's V value, the alternative features considered, the decision made, and the rationale. This documentation will be included in the next RAI assessment submission.

---

---

## Exercise 3 — Write a Validation Method

Add the following block inside `validate()` in `02_model_card.py`, between the "Data lineage" and "Flagged performance slices" comment blocks:

```python
# PII sources must have lineage verified
all_pii_sources = [
    s for s in (self.training_data_sources + self.evaluation_data_sources)
    if s.pii_classified
]
unverified_pii = [s.name for s in all_pii_sources if not s.lineage_verified]
if unverified_pii:
    self._validation_errors.append(
        f"PII-classified data sources with unverified lineage: {unverified_pii}. "
        "Lineage must be verified via Unity Catalog or Foundry before model deployment."
    )
```

**Testing the check:**

```python
from chapters.code_examples.python.model_card_02 import ModelCard, DataSource, ...
# Create a DataSource with pii_classified=True but lineage_verified=False
bad_source = DataSource(
    name="Personnel Extract",
    platform="Unity Catalog",
    catalog="advana_silver",
    schema="personnel",
    table="navy_enlisted_fy23",
    pii_classified=True,
    classification_level="UNCLASSIFIED//FOUO",
    record_count_approx=45_000,
    date_range_start=date(2022, 10, 1),
    date_range_end=date(2023, 9, 30),
    lineage_verified=False,  # <-- this should trigger the error
)
card = build_attrition_model_card()
card.evaluation_data_sources = [bad_source]
passed, errors = card.validate()
assert not passed
assert any("lineage" in e.lower() for e in errors)
print("Test passed — validation correctly caught unverified PII source")
```

**Stretch goal — cross-referencing Unity Catalog governance check:**

```python
# After the unverified_pii check, add:
for source in all_pii_sources:
    if source.platform == "Unity Catalog" and all([source.catalog, source.schema, source.table]):
        uc_result = check_unity_catalog_pii_policies(
            catalog=source.catalog,
            schema=source.schema,
            table=source.table,
        )
        if not uc_result["policy_compliant"]:
            for issue in uc_result["issues"]:
                self._validation_errors.append(
                    f"Unity Catalog policy issue for '{source.name}': {issue}"
                )
```

Note: In local/dev mode `check_unity_catalog_pii_policies()` returns no issues because the Spark queries are commented out. This cross-reference only runs meaningfully on a live Databricks cluster with Unity Catalog enabled.

---

## Exercise 4 — NIST AI RMF Risk Register

### Question 1: Severity reasoning

RISK-004 has the higher severity score (9 vs. 8 for RISK-002). However, RISK-002 (misuse for involuntary separation) may warrant equal or greater attention in a federal HR context for two reasons. First, the impact category CRITICAL (4) reflects potential legal liability, Title VII exposure, and reputational harm to the Department — consequences that are qualitatively different from model accuracy degradation. Second, in HR decision support systems, low-probability high-impact risks are often treated with extra caution because the harm is to individual people and is difficult to reverse. A sailor wrongfully separated because of a model's misuse has suffered a real, personal injury. Risk scoring matrices are starting points; the nature of the harm matters as much as the numeric score.

### Question 2: New risk entry

```python
AIRisk(
    risk_id="RISK-005",
    title="Overprivileged service account with cross-schema read access",
    description=(
        "The personnel extract ETL pipeline runs as a shared service account "
        "(svc-personnel-etl) that has read access to all schemas in advana_silver, "
        "not only the 'personnel' schema it requires. If the account is compromised "
        "or misused, it provides unauthorized access to health, legal, and finance data."
    ),
    rmf_function=RMFFunction.GOVERN,
    likelihood=RiskLikelihood.LOW,
    impact=RiskImpact.CRITICAL,
    status=RiskStatus.OPEN,
    owner="gs13.mehta.infosec@navy.mil",
    mitigation_plan=(
        "Submit Unity Catalog privilege change request to reduce svc-personnel-etl "
        "to SELECT grants on advana_silver.personnel schema only. "
        "Review all other ETL service accounts for similar over-provisioning. "
        "Implement quarterly privilege review as part of ATO renewal checklist."
    ),
    created_date=date(2024, 6, 10),
),
```

### Question 3: MANAGE message for PSI WARNING + flag_rate_ok

---

Hi [Model Owner name],

Our weekly automated check for the attrition model flagged something worth looking at. The model's output distribution has shifted moderately compared to last quarter's baseline — not enough to trigger an automatic pause, but enough that a human should take a look within the next five business days.

What this means in plain terms: the model is scoring sailors somewhat differently than it did when we first validated it, but the overall percentage of sailors being flagged as high-risk hasn't changed significantly. That's a partial reassurance, but the shift in how scores are distributed internally is the kind of thing that, if left unexamined, can turn into a bigger problem.

I'd like to schedule 30 minutes with you this week to walk through the latest batch results and confirm whether there's a known operational reason for the shift — for example, a change in deployment tempo or a new fiscal year's worth of data being included. If we can't identify a clear cause, we'll escalate to a retraining assessment.

No action is needed from you today; I just want to make sure you're aware before the next quarterly review.

---

---

## Exercise 5 — Pre-Deployment Ethics Review Summary

---

**PRE-DEPLOYMENT ETHICS REVIEW SUMMARY**
**Navy Enlisted Attrition Predictor, Version 2.1.0**
**Prepared for: RDML Dana Whitfield, Deputy CNP for Analytics**
**Date: June 1, 2024**

---

**Purpose**

The Navy Enlisted Attrition Predictor estimates the probability that an active-duty enlisted sailor (E1–E9) will voluntarily separate within twelve months, given their current assignment and career profile. Career counselors at commands use the score to prioritize retention interviews — not to make separation or administrative decisions. The model runs on Advana (Navy Jupiter tenant) and scores the full active-duty enlisted force weekly.

---

**Key Performance Metrics**

| Metric             | Value  | Threshold | Status |
|--------------------|--------|-----------|--------|
| AUC (FY23 holdout) | 0.823  | ≥ 0.78    | PASS   |
| Average Precision  | 0.612  | ≥ 0.55    | PASS   |
| Brier Score        | 0.148  | ≤ 0.18    | PASS   |
| Flag rate — White  | 11.0%  | —         | —      |
| Flag rate — Black  | 12.8%  | —         | —      |
| Flag rate — Hispanic | 12.1% | —        | —      |

*All metrics computed on FY23 holdout set (n=45,000), excluding training data.*

---

**Fairness Findings**

- The EEOC 4/5ths rule is satisfied: the lowest-rate group (White, 11.0%) flags at 86% the rate of the highest-rate group (Black, 12.8%), exceeding the 80% minimum.
- False positive rates by racial group are within ±1.3 percentage points of the overall rate (11.5%), meeting the equalized-odds tolerance of ±3 pp.
- Per-group threshold calibration was applied separately to E1–E4 and E5–E9 pay-grade bands to equalize false positive rates across career stages.
- Proxy correlation scan identified `pcs_moves_count` with Cramér's V = 0.18 with race — below the 0.25 flagging threshold; retained with documentation.
- Race, gender, religion, and national origin are explicitly excluded from the feature set. This was verified by the bias audit team on May 20, 2024.
- Bias audit: PASSED. Conducted by OPNAV N13 RAI Assessment Team. Report on file at SharePoint N13 Analytics/ModelAudits.

---

**Open Risks**

- **RISK-003 (HIGH):** Model performance degradation after force structure change — in OPEN status. Automated weekly drift monitoring is in place; emergency retrain runbook is documented. Owner: LT Reyes.
- **RISK-001 (MEDIUM, in mitigation):** Proxy discrimination via PCS-correlated features — quarterly proxy scan in place. Owner: Dr. Okafor.
- **RISK-002 (HIGH, in mitigation):** Misuse for involuntary separation decisions — out-of-scope use documented in model card, access restricted by role in Unity Catalog row-level security. Owner: RDML Whitfield.

---

**Conditions for Deployment**

- Weekly automated monitoring job must be active before first production scoring run — batch job ID to be confirmed by LT Reyes.
- Unity Catalog row-level security filters on `advana_gold.personnel.attrition_scores` must restrict score access to personnel with the `retention_counselor` role; access reviewed quarterly.
- Career counselor training on permissible use of scores must be completed by all commands within 30 days of deployment.
- Model sunset date set for September 30, 2025; retraining or formal extension required before that date.
- Any change to the feature set, threshold, or scoring population requires a new bias audit before the change goes to production.

---

*Prepared by: Dr. Sarah Okafor, LT James Reyes, GS-13 Priya Mehta — OPNAV N13 People Analytics*
*Contact: sarah.okafor@navy.mil*
