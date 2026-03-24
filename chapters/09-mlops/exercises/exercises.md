# Chapter 09 Exercises: MLOps and Production Pipelines

These exercises build on the concepts in Chapter 09. Each exercise targets a specific MLOps skill you will need on federal programs. Complete them in order — later exercises build on earlier ones.

---

## Exercise 1: Experiment Tracking Audit

**Scenario:** You have inherited a model in production on an Advana (Databricks) workspace. The model scores logistics work orders for a Navy program. It was deployed eight months ago. A GS-14 program analyst has asked for documentation to support the model's ATO renewal. You need to reconstruct as much provenance information as possible from the MLflow experiment history.

**Setup:** Use the MLflow tracking patterns from `code-examples/python/01_experiment_tracking.py`. If you have a Databricks environment available, run the example to create experiment data. If not, the exercises below work against the local file-based tracking server that the example creates in `/tmp/mlflow_demo`.

**Tasks:**

1. **Retrieve run metadata.** Write a Python function called `audit_production_model(model_name: str) -> dict` that queries the MLflow client and returns:
   - The current Production model version number
   - The run ID that produced the Production model
   - The training data version logged on that run
   - The Git commit hash logged on that run
   - The test accuracy logged on that run
   - The date and time the model was transitioned to Production

2. **Identify gaps.** Call `audit_production_model()` on a test model and identify which of the above fields are missing or recorded as "unknown". List two specific changes to the training pipeline that would fill each gap.

3. **Write the ATO summary.** Using the data from task 1, write a two-paragraph plain-English summary of the model's provenance that an ATO reviewer (not a data scientist) could read and act on. The summary should include: what data the model was trained on, when it was trained, what its evaluated performance is, and who approved it for production.

**What you're practicing:** The gap between what engineers log and what compliance reviewers need is large on most government programs. This exercise forces you to walk through the reviewer's perspective, not the engineer's.

---

## Exercise 2: The Performance Gate

**Scenario:** Your team is setting up CI/CD for a maintenance prioritization model. The current Production model has an accuracy of 0.91 and a weighted F1 of 0.89. A new candidate model has been trained. You need to build the performance gate that decides whether the candidate is safe to promote.

**Tasks:**

1. **Implement the gate function.** Write a function `evaluate_promotion_gate(candidate_metrics: dict, production_metrics: dict, config: dict) -> tuple[bool, str]` that:
   - Checks that the candidate meets absolute minimum thresholds defined in `config`
   - Checks that the candidate does not regress more than `config["max_regression"]` on the composite score versus production
   - Returns `(True, "All gates passed: ...")` or `(False, "Gate failed: ...")`
   - The reason string must be specific enough for an engineer to understand exactly what failed

2. **Test with three scenarios.** Write tests for:
   - Scenario A: Candidate that improves on all metrics (should pass)
   - Scenario B: Candidate with high accuracy but poor F1 on the critical class (should fail)
   - Scenario C: Candidate with acceptable absolute metrics but 3% composite score regression vs. production (should fail based on your `max_regression` setting)

3. **Configure the gate for your program.** Explain in a short paragraph why you set the `min_f1_critical` threshold higher than `min_accuracy`. What is the operational cost of false negatives on the critical class in a maintenance work order routing system?

**What you're practicing:** Performance gates are where MLOps stops being abstract and starts requiring domain judgment. The thresholds you set reflect the real-world consequences of model errors — you cannot set them without understanding the business context.

---

## Exercise 3: Drift Detection and Alert Triage

**Scenario:** Your drift monitoring pipeline has fired an alert at 6 AM: 38% of features are drifting compared to the training baseline. The program manager is on the call in 90 minutes. You need to triage the alert, determine whether it warrants an emergency retrain, and communicate the situation clearly.

**Setup:** Use the drift monitoring code from `code-examples/python/03_pipeline_orchestration.py`. The `run_monitoring_pipeline()` function simulates a drift scenario.

**Tasks:**

1. **Run the drift pipeline.** Execute the monitoring pipeline code and examine the drift report. Identify which specific features are flagged as drifting and in which direction (mean shift up or down, distribution widening or narrowing).

2. **Classify the drift.** For each drifting feature, classify it as either:
   - **Operational drift**: Normal operational variation (e.g., seasonal maintenance cycles, scheduled fleet-wide maintenance events) that does not necessarily indicate model degradation
   - **Structural drift**: A genuine change in the underlying data-generating process that likely degrades model performance

   Write your classification for each drifted feature and explain your reasoning in two sentences per feature.

3. **Recommendation memo.** Write a 150-word memo to the program manager that:
   - States clearly whether you recommend an immediate retrain, a scheduled retrain, or continued monitoring
   - Explains the reasoning without using the words "drift," "distribution," or "model degradation" (force yourself to explain it in terms a non-data-scientist understands)
   - States what additional data or time you need to confirm your recommendation

4. **Extend the monitoring code.** Add a `classify_drift_type()` function to the monitoring pipeline that takes the evidently report output and returns a dict mapping each drifted feature to either `"operational"` or `"structural"` based on simple heuristic rules you define.

**What you're practicing:** Drift alerts are only valuable if someone can act on them. This exercise forces you to translate statistical outputs into operational recommendations — the communication gap that causes most monitoring systems to be ignored after the first few false alarms.

---

## Exercise 4: Palantir Foundry Model Integration

**Scenario:** Your team has trained a model in a Databricks Jupyter notebook. The program manager wants analysts to see the model's predictions directly in the Workshop application they already use for maintenance scheduling — alongside the equipment records, not in a separate tool. This requires deploying the model into Palantir Foundry and connecting its outputs to the Ontology.

**Tasks:**

1. **Write the model adapter.** Using the `palantir_models` pattern from `code-examples/python/02_model_registry_deployment.py`, write a `MaintenancePriorityModel` class that:
   - Accepts a DataFrame with the seven feature columns from Chapter 09's examples
   - Returns a DataFrame that includes the original columns plus `priority_label` (string: standard/elevated/critical), `confidence_critical` (float), and `model_version` (hardcoded string for this exercise)
   - Raises a `ValueError` with a descriptive message if required feature columns are missing
   - Includes a docstring that describes the model's intended use, input schema, and output schema

2. **Handle unknown work order types.** The model was trained on work order types 0, 1, and 2. Starting next quarter, type 3 (depot-level maintenance) will appear in the data. Modify the `predict()` method to:
   - Detect records with `work_order_type == 3`
   - For those records, set `priority_label` to `"requires_review"`, `confidence_critical` to `None`, and `model_version` to `"out_of_distribution"`
   - Log a count of out-of-distribution records for monitoring purposes

3. **Write the Ontology integration specification.** In plain English (not code), describe how you would connect this model's outputs to the `Vessel` object type in a Foundry Ontology. Specifically:
   - What properties would you add to the `Vessel` object type to surface model predictions?
   - What Pipeline Builder transform would you write to call the model on a schedule and write outputs back to those properties?
   - What would an analyst see when they open a vessel record in Workshop after this integration is complete?

**What you're practicing:** The gap between "model works in a notebook" and "model outputs appear in operational tools" is where most government AI deployments stall. Exercise 4 forces you through the last mile.

---

## Exercise 5: The Full MLOps Readiness Checklist

**Scenario:** You are the ML engineer on a six-month-old project that is about to enter an ATO re-review. The program security officer has asked for a signed attestation that the production ML system meets the operational standards in the program's System Security Plan (SSP). Before you sign anything, you need to audit the actual state of the system.

**Tasks:**

1. **Conduct the audit.** Using the checklist from the "Practical Takeaway" section of Chapter 09, evaluate a model of your choice (if you have a Databricks environment, use a real model; otherwise, use the models you created in Exercises 1-3). For each checklist item:
   - Record its current status: Complete, Partial, or Missing
   - If Partial or Missing, describe specifically what is missing
   - Estimate the effort to close the gap (hours, days, or weeks)

2. **Prioritize the gaps.** Of the Missing or Partial items, rank them by risk severity: which gaps are most likely to cause a production incident, and which are most likely to cause an ATO finding? These are not always the same ranking.

3. **Write the remediation plan.** For the top three gaps by risk severity, write a one-paragraph remediation plan for each that includes: what needs to be done, who is responsible, and how you will verify it is complete.

4. **The one you will not fix.** Identify one checklist item that you believe is genuinely not worth the effort on this particular program (perhaps a small, low-stakes analytical product) and write two paragraphs defending that judgment. Explain what risk you are accepting, who accepts that risk, and under what conditions you would reverse the decision.

**What you're practicing:** Risk-based decision making. Not every program needs the same MLOps maturity level. Exercise 5 forces you to make and defend tradeoffs rather than treating every checklist item as equally urgent.

---

## Stretch Exercise: End-to-End Pipeline

**For teams that want to build the complete system:**

Build an end-to-end MLOps pipeline for the maintenance work order classifier that includes all of the following, connected in sequence:

1. A Databricks Workflow (or equivalent scheduled pipeline) that refreshes features from a source table and writes them to a feature table
2. A weekly retraining job that pulls from the feature table, trains a GradientBoostingClassifier, logs all required metadata to MLflow, and registers the best model to Staging
3. An automated performance gate check that runs on every new Staging model and blocks promotion if it fails the criteria from Exercise 2
4. A daily drift monitoring job that compares the last 7 days of inference data against the training baseline and writes a drift summary to a Delta table
5. A GitHub Actions workflow that runs unit tests and integration tests on every pull request and deploys updated pipeline code on merge to main

Document each component with a one-paragraph README section that explains what it does, what triggers it, and what happens when it fails.

---

See `exercises/solutions/solutions.md` for worked solutions and discussion.
