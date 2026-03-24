# Chapter 12 Exercises: Ethics, Governance, and Compliance

These exercises build on the attrition model scenario from Chapter 12 and the code examples in `code-examples/python/`. Each exercise mirrors decisions you will face on federal platforms — Advana, Navy Jupiter, Databricks, and Foundry.

---

## Exercise 1 — The 4/5ths Rule in Practice

**Scenario:** A command receives a new Navy attrition risk report. Before the model goes to production, your team is asked to certify that it passes the EEOC 4/5ths rule.

You have prediction data for three racial groups:

| Group    | N scored | Flagged as high-risk |
|----------|----------|----------------------|
| White    | 3,200    | 352                  |
| Black    | 820      | 107                  |
| Hispanic | 610      | 73                   |

**Tasks:**

1. Compute the flag rate for each group.
2. Identify which group has the highest flag rate.
3. Compute the disparity ratio for each non-dominant group.
4. Determine whether the model passes the 4/5ths rule. State your conclusion in plain English, as you would in a briefing to a flag officer.
5. If the model fails, propose two concrete remediation approaches. Describe what each approach changes and what it risks losing (hint: think about threshold calibration vs. retraining vs. feature removal).

**No code required.** Show your arithmetic and write 2–3 sentences for question 5.

---

## Exercise 2 — Proxy Correlation Scan

**Background:** The `proxy_correlation_scan()` function in `01_bias_audit.py` checks whether model features correlate with protected attributes. A feature that predicts race or gender can act as a proxy even when those attributes are excluded from the model.

**Tasks:**

Open `01_bias_audit.py` and run `run_full_bias_audit()` with `inject_bias=True`. Look at the proxy correlation output.

1. Which features show the highest correlation with the protected attribute in the biased dataset?
2. For a continuous feature correlated with a binary protected attribute (e.g., a numeric column correlated with a binary gender indicator), the function uses point-biserial correlation. Explain in 2 sentences why this is the correct statistic rather than Pearson correlation.
3. The function flags features with `|correlation| > 0.25`. Suppose a feature has a Cramér's V of 0.30 with race but is the most predictive feature in the model (SHAP rank #1). Write a 4–6 sentence recommendation memo explaining how you would handle this trade-off. Address: what information you need to make the decision, who the decision-maker should be, and what documentation you would produce.

---

## Exercise 3 — Write a Validation Method

**Background:** The `ModelCard` class in `02_model_card.py` has a `validate()` method that checks pre-deployment requirements. It currently checks for `.mil` email, protected attribute leakage, bias audit status, approver presence, and monitoring documentation.

**Your task:** The current `validate()` method does not check whether any `DataSource` has `pii_classified=True` without a corresponding column mask entry. A model trained on unmasked PII — even if PII is not in the feature list — violates DoD data handling requirements.

Add a validation check that:
1. For each training and evaluation `DataSource` where `pii_classified=True`, verifies that `lineage_verified=True`.
2. Appends an appropriate error message to `self._validation_errors` if the check fails.
3. (Optional stretch goal) Cross-references the `DataSource.table` name against the Unity Catalog governance check result from `check_unity_catalog_pii_policies()`.

Add your check inside the `validate()` method in `02_model_card.py`, between the "Data lineage" and "Flagged performance slices" blocks.

---

## Exercise 4 — NIST AI RMF Risk Register

**Background:** The `build_attrition_risk_register()` function in `03_nist_rmf_workflow.py` defines four risks for the attrition model.

**Tasks:**

1. **Severity scoring:** The `AIRisk.severity_score` property multiplies likelihood × impact on a 1–4 scale. RISK-002 has likelihood=MEDIUM (2) and impact=CRITICAL (4), giving a score of 8. RISK-004 has likelihood=HIGH (3) and impact=HIGH (3), giving a score of 9. Which risk is higher severity? Why might a risk with lower likelihood but higher impact sometimes deserve more attention in a federal HR context?

2. **Add a new risk:** A data engineer notices that the personnel extract pipeline runs as a shared service account with read access to all schemas, not just the `personnel` schema it needs. Add a new `AIRisk` entry to the register for this finding. Choose appropriate values for `likelihood`, `impact`, `rmf_function`, and `mitigation_plan`. Assign it to a plausible owner.

3. **MANAGE response:** The `detect_prediction_drift()` function returns a `recommended_action` of either MONITOR, INVESTIGATE, or QUARANTINE. Suppose a scoring job returns `psi_severity="WARNING"` but `flag_rate_ok=True`. Write the 3–5 sentences you would put in a Slack/Teams message to the model owner explaining the finding and what they should do next. Avoid technical jargon — write as if the model owner is a GS-14 program manager, not a data scientist.

---

## Exercise 5 — Pre-Deployment Ethics Review Package

**Scenario:** Your team is one week away from deploying the attrition model to production on Advana (Navy Jupiter tenant). The approving official is RDML Whitfield. She asks for a one-page summary of the ethics review findings.

Using the `ModelCard`, `MeasurementRecord`, and `AIRisk` structures from this chapter's code examples, draft the text of a pre-deployment ethics review summary that includes:

1. **Purpose statement** (2–3 sentences): What the model does, who uses it, and what decisions it supports.
2. **Key performance metrics** (table format): AUC, Average Precision, flag rates by racial group.
3. **Fairness findings** (bullet list): What the bias audit found, whether the 4/5ths rule is satisfied, what threshold calibration was applied.
4. **Open risks** (bullet list): List any risks from the register with status=OPEN or status=IN_MITIGATION.
5. **Conditions for deployment** (bullet list): What monitoring, retraining triggers, and sunset conditions must be in place before go-live.

You may write this as prose with tables and bullets — no Python code required. Aim for 400–600 words.

---

## Submission Checklist

Before considering these exercises complete:

- [ ] Exercise 1: Arithmetic shown, disparity ratios computed, remediation options described
- [ ] Exercise 2: Proxy scan run with `inject_bias=True`, memo written
- [ ] Exercise 3: Validation check added to `02_model_card.py`, tested by calling `validate()` on a card with an unverified PII source
- [ ] Exercise 4: Risk register severity reasoning written, new risk added in code, MANAGE message drafted
- [ ] Exercise 5: One-page review summary drafted with all five sections
