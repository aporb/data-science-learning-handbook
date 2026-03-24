# Chapter 09 Exercise Solutions: MLOps and Production Pipelines

---

## Exercise 1 Solutions: Experiment Tracking Audit

### Task 1: `audit_production_model()` function

```python
import mlflow
from mlflow.tracking import MlflowClient
from datetime import datetime
from typing import Optional


def audit_production_model(model_name: str) -> dict:
    """
    Retrieve provenance information for the current Production model version.

    Returns a dict with all available metadata. Fields that were not logged
    are returned as None with a descriptive explanation.
    """
    client = MlflowClient()

    # Find the production model version
    production_versions = client.get_latest_versions(
        name=model_name, stages=["Production"]
    )
    if not production_versions:
        return {"error": f"No Production model found for '{model_name}'"}

    version_obj = production_versions[0]
    version_number = version_obj.version
    run_id = version_obj.run_id

    # Retrieve the run that produced this model
    run = client.get_run(run_id)
    params = run.data.params
    metrics = run.data.metrics
    tags = run.data.tags

    # Find the Production transition event for the approval timestamp
    transition_history = client.get_model_version_activities(
        name=model_name, version=version_number
    )
    production_transition_date = None
    for event in transition_history:
        if getattr(event, "to_stage", None) == "Production":
            production_transition_date = datetime.fromtimestamp(
                event.timestamp / 1000
            ).isoformat()
            break

    return {
        "model_name": model_name,
        "production_version": version_number,
        "run_id": run_id,
        "training_data_version": params.get("training_data_version", None),
        "git_commit_hash": params.get("git_commit_hash", None),
        "test_accuracy": metrics.get("test_accuracy", None),
        "roc_auc_macro": metrics.get("test_roc_auc_macro", None),
        "f1_critical": metrics.get("test_f1_2", None),  # class 2 = critical
        "training_date": params.get("training_data_cutoff_date", None),
        "production_approval_date": production_transition_date,
        "model_description": version_obj.description,
        "n_training_samples": params.get("n_train_samples", None),
        "sklearn_pipeline": params.get("sklearn_pipeline", None),
    }


# Usage
audit_result = audit_production_model("navy_logistics.maintenance.priority_classifier")
for key, value in audit_result.items():
    status = "OK" if value is not None else "MISSING"
    print(f"  [{status}] {key}: {value}")
```

### Task 2: Gap analysis

Common missing fields and how to fix them:

| Missing field | Fix |
|---|---|
| `training_data_version` | Add `mlflow.log_param("training_data_version", delta_table_version)` before `model.fit()` |
| `git_commit_hash` | Add `mlflow.log_param("git_commit_hash", get_git_commit_hash())` at run start |
| `production_approval_date` | Ensure `client.transition_model_version_stage()` is used rather than the UI; the API logs the timestamp; also add `client.update_model_version(description=...)` with approver name |
| `test_accuracy` | Ensure evaluation runs on a held-out test set, not just validation; log with `mlflow.log_metric("test_accuracy", ...)` |

### Task 3: Sample ATO summary

> **Model Provenance Summary — Maintenance Work Order Priority Classifier**
>
> This model was trained on maintenance work order data from the Naval Maintenance Management System (NMMS) ingested through Advana as of [DATE]. The training dataset comprised approximately 47,000 records spanning 18 months of operational history. The model predicts the priority classification (standard, elevated, or critical) for incoming maintenance work orders to support technician routing decisions.
>
> The model was evaluated on a held-out test set of 9,400 records before deployment, achieving an accuracy of 91.2% and a macro-averaged ROC-AUC of 0.943. Performance on the critical priority class — the highest-stakes classification — achieved an F1 score of 0.87. The model was reviewed and approved for production deployment by [APPROVER NAME] on [DATE] and has been in production since that date with daily drift monitoring in place. The current version will be evaluated for retraining if drift monitoring detects degradation exceeding 25% of input features, or if critical class F1 drops below 0.75 on the weekly evaluation window.

---

## Exercise 2 Solutions: The Performance Gate

### Task 1: Gate function implementation

```python
def evaluate_promotion_gate(
    candidate_metrics: dict,
    production_metrics: dict,
    config: dict,
) -> tuple[bool, str]:
    """
    Determine if a candidate model is safe to promote to Production.

    Parameters
    ----------
    candidate_metrics : dict
        Metrics from evaluating the candidate model on the fixed test set.
        Keys: accuracy, f1_weighted, f1_per_class (list), composite_score
    production_metrics : dict
        Same metrics for the current Production model.
        Pass {} or None if there is no current Production model.
    config : dict
        Gate configuration with keys:
        - min_accuracy: float
        - min_f1_critical: float (applies to class index 2)
        - min_composite: float
        - max_regression: float (max allowed regression vs. production)
    """
    # Absolute minimum: accuracy
    if candidate_metrics["accuracy"] < config.get("min_accuracy", 0.85):
        return False, (
            f"Candidate accuracy {candidate_metrics['accuracy']:.4f} "
            f"< minimum {config['min_accuracy']:.4f}"
        )

    # Absolute minimum: critical class F1
    f1_critical = candidate_metrics["f1_per_class"][2] if len(
        candidate_metrics.get("f1_per_class", [])) > 2 else 0.0
    if f1_critical < config.get("min_f1_critical", 0.70):
        return False, (
            f"Candidate F1 on critical class {f1_critical:.4f} "
            f"< minimum {config['min_f1_critical']:.4f}"
        )

    # Absolute minimum: composite score
    if candidate_metrics.get("composite_score", 0) < config.get("min_composite", 0.80):
        return False, (
            f"Candidate composite score {candidate_metrics['composite_score']:.4f} "
            f"< minimum {config['min_composite']:.4f}"
        )

    # Regression check vs. production (skip if no production model)
    if production_metrics:
        regression = (
            production_metrics.get("composite_score", 0)
            - candidate_metrics.get("composite_score", 0)
        )
        if regression > config.get("max_regression", 0.02):
            return False, (
                f"Candidate composite score {candidate_metrics['composite_score']:.4f} "
                f"regresses vs. production {production_metrics['composite_score']:.4f} "
                f"by {regression:.4f} > allowed {config['max_regression']:.4f}"
            )

    return True, (
        f"All gates passed — "
        f"accuracy={candidate_metrics['accuracy']:.4f}, "
        f"f1_critical={f1_critical:.4f}, "
        f"composite={candidate_metrics.get('composite_score', 0):.4f}"
    )


# Test configuration
gate_config = {
    "min_accuracy": 0.88,
    "min_f1_critical": 0.75,
    "min_composite": 0.82,
    "max_regression": 0.02,
}

production_baseline = {
    "accuracy": 0.91,
    "f1_weighted": 0.89,
    "f1_per_class": [0.92, 0.88, 0.87],
    "composite_score": 0.893,
}

# Scenario A: Improving candidate
candidate_a = {
    "accuracy": 0.93, "f1_weighted": 0.91,
    "f1_per_class": [0.94, 0.90, 0.88], "composite_score": 0.905,
}
result_a = evaluate_promotion_gate(candidate_a, production_baseline, gate_config)
assert result_a[0] == True, f"Expected pass: {result_a[1]}"
print(f"Scenario A: {result_a}")

# Scenario B: High accuracy, poor critical class F1
candidate_b = {
    "accuracy": 0.94, "f1_weighted": 0.88,
    "f1_per_class": [0.96, 0.91, 0.62], "composite_score": 0.872,
}
result_b = evaluate_promotion_gate(candidate_b, production_baseline, gate_config)
assert result_b[0] == False, f"Expected fail: {result_b[1]}"
print(f"Scenario B: {result_b}")

# Scenario C: Acceptable absolute metrics, 3% regression vs. production
candidate_c = {
    "accuracy": 0.89, "f1_weighted": 0.86,
    "f1_per_class": [0.90, 0.85, 0.78], "composite_score": 0.858,
}
result_c = evaluate_promotion_gate(candidate_c, production_baseline, gate_config)
assert result_c[0] == False, f"Expected fail: {result_c[1]}"
print(f"Scenario C: {result_c}")
```

### Task 3: Why `min_f1_critical > min_accuracy`

Setting `min_f1_critical` higher than `min_accuracy` reflects the operational cost structure of this specific problem. In a maintenance work order routing system, failing to route a critical work order as critical (a false negative on the critical class) means a technician with inadequate resources receives an emergency task — which results in extended equipment downtime, mission capability degradation, or in the worst case, a safety event. Misclassifying a standard order as elevated is annoying but correctable. Misclassifying a critical order as standard can be catastrophic.

The model accuracy metric pools all errors equally. A model with 94% accuracy could have 0% recall on the critical class and still pass an accuracy gate — if critical orders are rare enough. The `min_f1_critical` threshold prevents that failure mode by requiring the model to demonstrate adequate performance specifically on the class that matters most operationally.

---

## Exercise 3 Solutions: Drift Detection and Alert Triage

### Task 1 and 2: Feature drift classification

After running `run_monitoring_pipeline()`, the drifted features and their classifications:

| Feature | Direction of drift | Classification | Reasoning |
|---|---|---|---|
| `failure_code_severity` | Mean shifted up (toward severity 4-5) | **Structural** | Increased failure severity across the fleet indicates a real change in equipment condition, not seasonal variation. The model's learned thresholds for routing may be calibrated to a healthier fleet. |
| `work_order_type` | More emergency orders (type 2 increasing) | **Structural** | A sustained increase in emergency work orders suggests an operational tempo or fleet maintenance posture change. The model was trained when emergency orders were 15% of volume; at 25%, its scoring logic for elevated vs. critical may be under-calibrated. |
| `parts_availability_score` | Mean shifted down (parts scarcer) | **Operational (monitor)** | Supply chain variability causes short-term parts availability fluctuations. If the trend persists beyond 30 days, reclassify as structural. |
| `equipment_age_years` | Slight upward shift | **Operational** | Fleet aging is gradual and continuous. A small shift in average equipment age after 8 months is expected. Check again at the 12-month mark. |

### Task 3: Sample recommendation memo

> **RE: Maintenance Classifier Alert — 38% of Input Factors Showing Changes**
>
> Our automated monitoring system flagged changes in the patterns of data the maintenance classifier is reading — specifically, we are seeing more high-severity failures and a higher rate of emergency work orders than when the system was configured. Two of the four flagged changes appear to reflect genuine shifts in fleet condition (more frequent high-severity failures and a rising share of emergency dispatches), not just normal month-to-month variation.
>
> **Recommendation:** We do not recommend a disruptive emergency reconfig this week, but we recommend scheduling a targeted review by end of next week and a planned update to the classifier's calibration within 30 days. The system will continue routing work correctly for most orders; the risk area is the boundary between elevated and critical — those borderline cases may be under-elevated given current fleet conditions.
>
> To confirm this recommendation, we need two weeks of outcome data: specifically, whether technicians are overriding the classifier's routing on emergency work orders more than usual. If override rates have increased, that confirms the classifier needs updating sooner.

### Task 4: `classify_drift_type()` function

```python
def classify_drift_type(drift_report_dict: dict, feature_metadata: dict) -> dict:
    """
    Classify each drifted feature as 'operational' or 'structural' based on
    heuristic rules.

    Parameters
    ----------
    drift_report_dict : dict
        The evidently report dict (from report.as_dict())
    feature_metadata : dict
        Program-specific metadata about each feature, including:
        - 'expected_seasonal': bool — does this feature have normal seasonal swings?
        - 'operational_impact': str — 'high', 'medium', or 'low'
        - 'max_expected_shift': float — maximum expected mean shift as fraction of std

    Returns
    -------
    dict mapping feature_name -> {'classification': 'operational'|'structural', 'reason': str}
    """
    classifications = {}

    # Extract per-feature drift results from the evidently report
    for metric in drift_report_dict.get("metrics", []):
        if metric.get("metric") != "ColumnDriftMetric":
            continue

        result = metric.get("result", {})
        feature_name = result.get("column_name")
        if not feature_name:
            continue

        drift_score = result.get("drift_score", 0)
        drift_detected = result.get("drift_detected", False)

        if not drift_detected:
            continue

        meta = feature_metadata.get(feature_name, {})

        # Heuristic rule 1: features with known seasonal patterns are likely operational
        if meta.get("expected_seasonal", False) and drift_score < 0.4:
            classifications[feature_name] = {
                "classification": "operational",
                "reason": f"Known seasonal feature; drift score {drift_score:.3f} within seasonal range",
            }
            continue

        # Heuristic rule 2: high operational impact features with large drift -> structural
        if meta.get("operational_impact") == "high" and drift_score > 0.5:
            classifications[feature_name] = {
                "classification": "structural",
                "reason": f"High-impact feature with drift score {drift_score:.3f} exceeding 0.5 threshold",
            }
            continue

        # Default: flag for manual review (treat as structural to be safe)
        classifications[feature_name] = {
            "classification": "structural",
            "reason": f"Drift score {drift_score:.3f} requires manual review; defaulting to structural",
        }

    return classifications
```

---

## Exercise 4 Solutions: Palantir Foundry Model Integration

### Task 1 and 2: Model adapter with OOD handling

```python
import palantir_models as pm
import pandas as pd
import logging

logger = logging.getLogger(__name__)

REQUIRED_COLS = [
    "equipment_age_years",
    "days_since_last_service",
    "failure_code_severity",
    "parts_availability_score",
    "crew_qualification_level",
    "work_order_type",
    "historical_completion_rate",
]

KNOWN_WORK_ORDER_TYPES = {0, 1, 2}
MODEL_VERSION = "3.2"


class MaintenancePriorityModel(pm.AutoTransformModel):
    """
    Maintenance work order priority classifier for Navy logistics.

    Predicts work order priority class to support technician routing decisions.

    Intended use: Score incoming maintenance work orders and surface the
    priority label in the Workshop maintenance scheduling application.
    Not intended for use in personnel decisions or procurement actions.

    Input schema (required columns):
    - equipment_age_years (float): Age of equipment in years
    - days_since_last_service (float): Days elapsed since last service action
    - failure_code_severity (int): Reported failure severity 1-5
    - parts_availability_score (float): Fraction of required parts available (0.0-1.0)
    - crew_qualification_level (float): Mean crew qualification level 1.0-5.0
    - work_order_type (int): 0=scheduled, 1=corrective, 2=emergency (3=depot, OOD)
    - historical_completion_rate (float): Historical on-time completion rate (0.0-1.0)

    Output columns added:
    - priority_label (str): 'standard', 'elevated', 'critical', or 'requires_review'
    - confidence_critical (float or None): Model confidence in critical classification
    - prediction_confidence (float or None): Max confidence across all classes
    - model_version (str): Version identifier for audit trail
    """

    def __init__(self, sklearn_pipeline):
        self.pipeline = sklearn_pipeline

    def predict(self, df: pd.DataFrame) -> pd.DataFrame:
        # Validate required columns
        missing = [c for c in REQUIRED_COLS if c not in df.columns]
        if missing:
            raise ValueError(
                f"Missing required feature columns: {missing}. "
                f"Required columns are: {REQUIRED_COLS}"
            )

        result = df.copy()

        # Split into in-distribution and OOD records
        ood_mask = ~df["work_order_type"].isin(KNOWN_WORK_ORDER_TYPES)
        ood_count = ood_mask.sum()
        in_dist_mask = ~ood_mask

        if ood_count > 0:
            logger.warning(
                f"Found {ood_count} out-of-distribution records "
                f"(work_order_type not in {KNOWN_WORK_ORDER_TYPES}). "
                f"These records will be flagged for manual review."
            )

        # Score in-distribution records
        if in_dist_mask.sum() > 0:
            X_in = df.loc[in_dist_mask, REQUIRED_COLS]
            predictions = self.pipeline.predict(X_in)
            probabilities = self.pipeline.predict_proba(X_in)

            result.loc[in_dist_mask, "priority_label"] = pd.Series(
                predictions, index=df.index[in_dist_mask]
            ).map({0: "standard", 1: "elevated", 2: "critical"})
            result.loc[in_dist_mask, "confidence_critical"] = probabilities[:, 2]
            result.loc[in_dist_mask, "prediction_confidence"] = probabilities.max(axis=1)
            result.loc[in_dist_mask, "model_version"] = MODEL_VERSION

        # Handle OOD records
        if ood_count > 0:
            result.loc[ood_mask, "priority_label"] = "requires_review"
            result.loc[ood_mask, "confidence_critical"] = None
            result.loc[ood_mask, "prediction_confidence"] = None
            result.loc[ood_mask, "model_version"] = "out_of_distribution"

        return result
```

### Task 3: Ontology integration specification

**Properties to add to the `Vessel` object type:**

- `maintenance_priority_score` (float): Composite score from 0 to 1 representing overall maintenance urgency
- `top_priority_work_order_label` (string): "standard", "elevated", "critical", or "requires_review"
- `critical_work_order_count` (integer): Number of open work orders currently scored as critical
- `priority_last_scored` (timestamp): When the model last ran against this vessel's open work orders
- `model_version_used` (string): The model version that produced the current scores

**Pipeline Builder transform to populate these properties:**

A scheduled transform in a Code Repository runs daily at 3 AM. The transform reads the `open_work_orders_features` dataset (produced by an upstream feature engineering transform), calls the model for each open work order, aggregates per-vessel (max priority label, count of criticals), and writes the aggregated results to the `vessel_priority_scores` dataset. A separate Ontology sync transform reads `vessel_priority_scores` and writes the values to the corresponding Vessel object properties.

**What an analyst sees in Workshop:**

When an analyst opens a Vessel record in the maintenance scheduling Workshop application, the Vessel detail panel shows a "Maintenance Priority" section alongside the vessel's operational status and location. This section displays the current top priority label (color-coded: green/yellow/red), the count of open critical work orders, and a "last scored" timestamp. If any work orders are flagged as "requires_review" (OOD), a callout banner appears prompting the analyst to manually review those records. The analyst does not need to know the model exists — they see the priority information as naturally as they see any other vessel property.

---

## Exercise 5 Solutions: MLOps Readiness Checklist

This exercise is program-specific and does not have a single correct answer. The framework below guides the assessment.

### Audit findings interpretation

When conducting the audit, a common pattern in government programs:

**Frequently Missing:**
- Training data version logged per run (teams use notebooks that were never updated to add this log step)
- Fixed test set evaluation (teams report validation metrics, not test set metrics)
- Inference logging (model serving was set up without configuring the inference table)
- Model card (considered documentation, often deferred and never written)

**Frequently Partial:**
- Performance gate (gate exists but is set to thresholds that have never been calibrated against operational requirements)
- Monitoring dashboard (dashboard exists but is only checked reactively, not routinely)

### Risk prioritization discussion

The highest-risk gaps from an operational perspective are typically: missing inference logging (cannot diagnose production issues), missing performance gate (bad models can be promoted accidentally), and absent monitoring job (drift goes undetected). From an ATO perspective: missing model card, missing data version logging, and missing approval documentation are the top findings because they are directly reviewable artifacts that auditors will look for.

### The one you will not fix

A reasonable example: on a low-stakes research notebook that produces an exploratory analysis product reviewed by two analysts and not used in any automated decision process, the full inference logging and Prometheus monitoring infrastructure may not be worth building. The risk is that if the model's outputs are ever promoted to production use without being re-evaluated, those gaps become real vulnerabilities. The appropriate safeguard is not building all the infrastructure, but documenting clearly that this model is not authorized for production decision support, and having a governance process that prevents that quiet promotion from happening.

---

*These solutions demonstrate the expected direction of each exercise. The specific code and reasoning will vary based on your program context. The goal is not to match these solutions exactly — it is to work through the reasoning that connects technical implementation choices to operational and compliance requirements.*
