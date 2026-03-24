"""
Chapter 06: Supervised Machine Learning on Federal Platforms
Code Example 03: MLflow Experiment Tracking and Production Batch Scoring

Use case: Log a trained classifier to MLflow, promote to Production stage,
          run batch scoring as a scheduled Databricks Workflow job.
Platform: Databricks (Advana / Jupiter)

Key concepts:
    - MLflow experiment setup and run logging
    - Model signature inference for input validation
    - Model Registry stages (None → Staging → Production)
    - Batch scoring from Production model with safe loading
    - Output table write pattern with Delta replaceWhere

Run order:
    1. Run 01_classification_pipeline.py to get a trained model
    2. Run this file to log, register, and score with it
    3. Schedule this file as a Databricks Workflow task for production
"""

import numpy as np
import pandas as pd
import mlflow
import mlflow.sklearn
from mlflow.tracking import MlflowClient
from datetime import date, datetime
import warnings
warnings.filterwarnings("ignore")


# ===========================================================================
# SECTION 1: MLFLOW EXPERIMENT SETUP
# ===========================================================================

def setup_mlflow_experiment(experiment_path: str) -> str:
    """
    Create or retrieve an MLflow experiment.

    On Databricks, experiments live at user paths (/Users/...) or
    shared paths (/Shared/...). Use a consistent naming convention:
        /Users/{email}/{project_name}/{model_name}

    Args:
        experiment_path: Full Databricks path for the experiment

    Returns:
        experiment_id
    """
    mlflow.set_experiment(experiment_path)
    experiment = mlflow.get_experiment_by_name(experiment_path)

    if experiment:
        print(f"Using experiment: {experiment_path}")
        print(f"  Experiment ID: {experiment.experiment_id}")
        return experiment.experiment_id
    else:
        raise RuntimeError(f"Could not create/find experiment at {experiment_path}")


# ===========================================================================
# SECTION 2: COMPREHENSIVE MODEL LOGGING
# ===========================================================================

def log_classification_model(
    model,
    X_train: pd.DataFrame,
    X_test: pd.DataFrame,
    y_test: np.ndarray,
    y_proba: np.ndarray,
    numeric_features: list,
    categorical_features: list,
    model_name: str,
    data_source: str,
    run_name: str,
    extra_params: dict = None,
    slice_metrics: dict = None,
) -> str:
    """
    Log a complete classification model run to MLflow.

    Logs: parameters, metrics (overall + per-slice), model artifact,
    input signature, and a small input example for validation.

    Args:
        model: Fitted sklearn Pipeline
        X_train, X_test: Feature DataFrames
        y_test: True test labels
        y_proba: Predicted probabilities (positive class)
        numeric_features, categorical_features: Feature name lists
        model_name: Name to register in Model Registry
        data_source: Fully-qualified table name used for training
        run_name: Descriptive name for this training run
        extra_params: Additional params to log (e.g., threshold, outlier clip)
        slice_metrics: Dict of {slice_label: {n: int, auc: float}} from stratified report

    Returns:
        run_id string
    """
    from sklearn.metrics import (
        roc_auc_score, average_precision_score,
        f1_score, precision_score, recall_score,
    )

    with mlflow.start_run(run_name=run_name) as run:
        # ---- Parameters ----
        clf = model.named_steps["clf"]
        mlflow.log_param("model_class",          type(clf).__name__)
        mlflow.log_param("n_estimators",         getattr(clf, "n_estimators", None))
        mlflow.log_param("max_depth",            getattr(clf, "max_depth", None))
        mlflow.log_param("learning_rate",        getattr(clf, "learning_rate", None))
        mlflow.log_param("subsample",            getattr(clf, "subsample", None))
        mlflow.log_param("training_rows",        len(X_train))
        mlflow.log_param("test_rows",            len(X_test))
        mlflow.log_param("numeric_features",     ",".join(numeric_features))
        mlflow.log_param("categorical_features", ",".join(categorical_features))
        mlflow.log_param("data_source",          data_source)
        mlflow.log_param("training_date",        date.today().isoformat())

        if extra_params:
            for k, v in extra_params.items():
                mlflow.log_param(k, v)

        # ---- Overall metrics ----
        y_pred_default = (y_proba >= 0.50).astype(int)
        mlflow.log_metric("test_roc_auc",          roc_auc_score(y_test, y_proba))
        mlflow.log_metric("test_avg_precision",    average_precision_score(y_test, y_proba))
        mlflow.log_metric("test_f1_default_thresh", f1_score(y_test, y_pred_default))
        mlflow.log_metric("test_precision_default", precision_score(y_test, y_pred_default))
        mlflow.log_metric("test_recall_default",    recall_score(y_test, y_pred_default))
        mlflow.log_metric("test_positive_rate",     float(y_test.mean()))

        # ---- Per-slice metrics ----
        if slice_metrics:
            for slice_label, metrics in slice_metrics.items():
                safe_label = slice_label.lower().replace(" ", "_").replace("/", "_")
                mlflow.log_metric(f"slice_{safe_label}_auc", metrics["auc"])
                mlflow.log_metric(f"slice_{safe_label}_n",   metrics["n"])

        # ---- Model artifact ----
        signature    = mlflow.models.infer_signature(X_test, y_proba)
        input_example = X_test.head(5)

        mlflow.sklearn.log_model(
            model,
            artifact_path="model",
            registered_model_name=model_name,
            signature=signature,
            input_example=input_example,
        )

        run_id = run.info.run_id
        print(f"\nMLflow run logged:")
        print(f"  Run ID    : {run_id}")
        print(f"  Model     : {model_name}")
        print(f"  Test AUC  : {roc_auc_score(y_test, y_proba):.4f}")

    return run_id


# ===========================================================================
# SECTION 3: MODEL REGISTRY PROMOTION
# ===========================================================================

def promote_model_to_staging(
    model_name: str,
    run_id: str,
    min_auc_threshold: float = 0.75,
) -> int:
    """
    Promote the model version registered in a specific run to Staging.

    Includes a quality gate: the model must meet the minimum AUC threshold
    before promotion. This prevents accidentally promoting a degraded model.

    Args:
        model_name: Registered model name in MLflow
        run_id: The run that logged the model
        min_auc_threshold: Minimum test AUC required for promotion

    Returns:
        Version number promoted, or raises ValueError if gate fails
    """
    client = MlflowClient()

    # Find the version registered from this run
    versions = client.search_model_versions(f"name='{model_name}'")
    run_versions = [v for v in versions if v.run_id == run_id]

    if not run_versions:
        raise ValueError(f"No version found for run_id={run_id} in model '{model_name}'")

    version = run_versions[0]
    version_number = int(version.version)

    # Check the quality gate
    run_data = client.get_run(run_id).data
    test_auc = run_data.metrics.get("test_roc_auc", 0.0)

    if test_auc < min_auc_threshold:
        raise ValueError(
            f"Quality gate failed: test AUC {test_auc:.4f} < threshold {min_auc_threshold}. "
            f"Do not promote version {version_number} to Staging."
        )

    client.transition_model_version_stage(
        name=model_name,
        version=str(version_number),
        stage="Staging",
        archive_existing_versions=False,  # keep prior Staging for comparison
    )

    print(f"Model '{model_name}' version {version_number} promoted to Staging")
    print(f"  Test AUC: {test_auc:.4f} (gate: {min_auc_threshold})")
    return version_number


def promote_staging_to_production(
    model_name: str,
    version: int,
    approver: str,
    rationale: str,
) -> None:
    """
    Promote a Staging model to Production.

    This should be called after human review, not automatically.
    The approver and rationale are stored as model version tags for audit trail.

    Args:
        model_name: Registered model name
        version: Version number to promote
        approver: Name/email of person approving the promotion
        rationale: Short text explaining why this version is ready for production
    """
    client = MlflowClient()

    # Tag the version with approval metadata
    client.set_model_version_tag(
        name=model_name,
        version=str(version),
        key="approved_by",
        value=approver,
    )
    client.set_model_version_tag(
        name=model_name,
        version=str(version),
        key="approval_date",
        value=date.today().isoformat(),
    )
    client.set_model_version_tag(
        name=model_name,
        version=str(version),
        key="approval_rationale",
        value=rationale,
    )

    # Promote — archives current Production version automatically
    client.transition_model_version_stage(
        name=model_name,
        version=str(version),
        stage="Production",
        archive_existing_versions=True,  # archive old Production
    )

    print(f"Model '{model_name}' version {version} is now Production")
    print(f"  Approved by: {approver}")
    print(f"  Rationale  : {rationale}")


# ===========================================================================
# SECTION 4: PRODUCTION BATCH SCORING JOB
# ===========================================================================

def run_batch_scoring_job(
    spark,
    model_name: str,
    input_table: str,
    output_table: str,
    feature_cols: list,
    score_date: str = None,
    operational_threshold: float = 0.65,
) -> dict:
    """
    Load Production model and score a Spark table. Write results to Delta.

    This function is designed to run as a Databricks Workflow task:
        - Reads from input_table (silver-tier)
        - Loads Production model from MLflow Registry
        - Writes scores to output_table (gold-tier)
        - Returns a summary dict for downstream monitoring

    Args:
        spark: Active SparkSession
        model_name: MLflow registered model name
        input_table: Fully-qualified source table (catalog.schema.table)
        output_table: Fully-qualified output table for scores
        feature_cols: List of column names to pass as model features
        score_date: Date string (YYYY-MM-DD) for this batch; defaults to today
        operational_threshold: Probability threshold for binary flag

    Returns:
        Summary dict with row counts and flag rates
    """
    import mlflow.pyfunc
    from pyspark.sql import functions as F

    score_date = score_date or date.today().isoformat()

    # ---- Load model ----
    # Always load by stage alias, never by version number in production jobs
    model_uri = f"models:/{model_name}/Production"
    model     = mlflow.pyfunc.load_model(model_uri)
    print(f"Loaded model: {model_uri}")

    # ---- Read and prepare input data ----
    input_df = spark.table(input_table)

    # Only score records not yet scored today (idempotent pattern)
    pending = (
        input_df
        .filter(F.col("completion_date").isNull())
        .select(["requisition_id"] + feature_cols)
        .toPandas()
    )

    if len(pending) == 0:
        print(f"No pending records to score for {score_date}. Exiting.")
        return {"scored": 0, "flagged": 0}

    print(f"Scoring {len(pending):,} records...")

    # ---- Score ----
    scores = model.predict(pending[feature_cols])
    pending["late_delivery_probability"] = scores.round(4)
    pending["late_delivery_flag"]        = (scores >= operational_threshold).astype(int)
    pending["scored_date"]               = score_date
    pending["model_name"]                = model_name
    pending["model_stage"]               = "Production"
    pending["score_threshold"]           = operational_threshold

    # ---- Write to Delta output table ----
    output_spark = spark.createDataFrame(
        pending[["requisition_id", "late_delivery_probability",
                 "late_delivery_flag", "scored_date",
                 "model_name", "model_stage", "score_threshold"]]
    )

    (
        output_spark
        .write
        .format("delta")
        .mode("overwrite")
        .option("replaceWhere", f"scored_date = '{score_date}'")
        .saveAsTable(output_table)
    )

    summary = {
        "score_date":       score_date,
        "scored":           len(pending),
        "flagged":          int(pending["late_delivery_flag"].sum()),
        "flag_rate_pct":    round(pending["late_delivery_flag"].mean() * 100, 2),
        "mean_probability": round(float(pending["late_delivery_probability"].mean()), 4),
    }

    print(f"Batch scoring complete:")
    print(f"  Scored  : {summary['scored']:,}")
    print(f"  Flagged : {summary['flagged']:,} ({summary['flag_rate_pct']:.1f}%)")
    print(f"  Written : {output_table}")

    return summary


# ===========================================================================
# SECTION 5: DRIFT MONITORING
# ===========================================================================

def check_prediction_drift(
    spark,
    scores_table: str,
    lookback_days: int = 30,
    baseline_days: int = 90,
) -> dict:
    """
    Check whether the model's output distribution has drifted recently.

    Compares flag rate and mean probability over the recent window (lookback_days)
    to the baseline window (baseline_days). If the recent flag rate has shifted
    by more than 20% relative to baseline, something has changed — either the data
    distribution, the real-world behavior, or both. That warrants investigation.

    Args:
        spark: Active SparkSession
        scores_table: Table where batch scores are written
        lookback_days: Recent window for drift check
        baseline_days: Historical window for baseline

    Returns:
        Dict with drift metrics and flag/no-flag recommendation
    """
    from pyspark.sql import functions as F

    scores = spark.table(scores_table)

    recent = (
        scores
        .filter(F.col("scored_date") >= F.date_sub(F.current_date(), lookback_days))
        .agg(
            F.mean("late_delivery_probability").alias("mean_prob"),
            F.mean("late_delivery_flag").alias("flag_rate"),
            F.count("requisition_id").alias("n"),
        )
        .toPandas()
        .iloc[0]
    )

    baseline = (
        scores
        .filter(F.col("scored_date") >= F.date_sub(F.current_date(), baseline_days))
        .filter(F.col("scored_date") <  F.date_sub(F.current_date(), lookback_days))
        .agg(
            F.mean("late_delivery_probability").alias("mean_prob"),
            F.mean("late_delivery_flag").alias("flag_rate"),
            F.count("requisition_id").alias("n"),
        )
        .toPandas()
        .iloc[0]
    )

    # Relative change in flag rate
    flag_rate_change = abs(recent["flag_rate"] - baseline["flag_rate"]) / (
        baseline["flag_rate"] + 1e-8
    )
    drift_detected = bool(flag_rate_change > 0.20)

    result = {
        "recent_flag_rate":   round(float(recent["flag_rate"]) * 100, 2),
        "baseline_flag_rate": round(float(baseline["flag_rate"]) * 100, 2),
        "flag_rate_change_pct": round(flag_rate_change * 100, 1),
        "drift_detected":     drift_detected,
        "action":             "INVESTIGATE — retrain candidate" if drift_detected
                              else "No action required",
    }

    print(f"Drift monitoring results:")
    print(f"  Baseline flag rate (last {baseline_days}d): {result['baseline_flag_rate']:.2f}%")
    print(f"  Recent flag rate   (last {lookback_days}d): {result['recent_flag_rate']:.2f}%")
    print(f"  Relative change: {result['flag_rate_change_pct']:.1f}%")
    print(f"  Status: {result['action']}")

    return result


# ===========================================================================
# DEMO: Simulate the full MLflow workflow without Databricks
# ===========================================================================

def demo_mlflow_workflow_local():
    """
    Demonstrate the MLflow workflow using a local tracking server.
    In production on Databricks, the tracking server is managed — no setup needed.
    """
    import tempfile, os
    from sklearn.ensemble import GradientBoostingClassifier
    from sklearn.pipeline import Pipeline
    from sklearn.preprocessing import StandardScaler
    from sklearn.compose import ColumnTransformer
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import roc_auc_score

    # Local tracking URI — replace with Databricks managed URI in production
    tracking_dir = tempfile.mkdtemp()
    mlflow.set_tracking_uri(f"file://{tracking_dir}")
    mlflow.set_experiment("chapter_06_demo")

    # Simple dataset
    np.random.seed(42)
    n = 2000
    X = pd.DataFrame({
        "vendor_reliability": np.random.beta(5, 2, n),
        "days_to_required":   np.random.randint(1, 60, n),
        "stock_on_hand":      np.random.randint(0, 20, n),
        "is_priority_high":   np.random.binomial(1, 0.15, n),
    })
    logit = (-1.5 + (1 - X["vendor_reliability"]) * 3
             - np.log1p(X["days_to_required"]) * 0.4
             + X["is_priority_high"] * 0.8
             + (X["stock_on_hand"] == 0).astype(float) * 1.0)
    y = (np.random.random(n) < 1 / (1 + np.exp(-logit))).astype(int)

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    numeric_features = list(X.columns)
    preprocessor = ColumnTransformer([
        ("num", StandardScaler(), numeric_features),
    ])
    pipeline = Pipeline([
        ("prep", preprocessor),
        ("clf", GradientBoostingClassifier(n_estimators=100, max_depth=3, random_state=42))
    ])
    pipeline.fit(X_train, y_train)
    y_proba = pipeline.predict_proba(X_test)[:, 1]
    auc     = roc_auc_score(y_test, y_proba)

    with mlflow.start_run(run_name="demo_run") as run:
        mlflow.log_param("n_estimators", 100)
        mlflow.log_param("max_depth", 3)
        mlflow.log_metric("test_roc_auc", auc)
        mlflow.sklearn.log_model(
            pipeline,
            artifact_path="model",
            signature=mlflow.models.infer_signature(X_test, y_proba),
            input_example=X_test.head(3),
        )
        print(f"Demo run logged. Run ID: {run.info.run_id}")
        print(f"Test AUC: {auc:.4f}")
        print(f"MLflow tracking dir: {tracking_dir}")

    return run.info.run_id


if __name__ == "__main__":
    print("Running MLflow demo with local tracking server...")
    print("(On Databricks, tracking server is managed — no local setup needed)\n")
    demo_mlflow_workflow_local()
    print("\nIn production on Databricks:")
    print("  1. Call log_classification_model() after training")
    print("  2. Call promote_model_to_staging() with AUC quality gate")
    print("  3. After human review, call promote_staging_to_production()")
    print("  4. Schedule run_batch_scoring_job() as a Databricks Workflow")
    print("  5. Schedule check_prediction_drift() weekly to monitor output distribution")
