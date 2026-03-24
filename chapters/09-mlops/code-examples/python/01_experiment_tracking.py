"""
Chapter 09: MLOps and Production Pipelines
Example 01: Experiment Tracking with MLflow on Databricks

Scenario: Training a maintenance work order priority classifier for a Navy
logistics program. This example shows what to log and why — not just the
obvious metrics, but the metadata that makes an experiment reproducible
and auditable months later.

Platform: Databricks (Advana / GovCloud workspace)
MLflow version: 3.0+ (native on Databricks)
"""

import subprocess
import hashlib
import json
from datetime import datetime

import mlflow
import mlflow.sklearn
import numpy as np
import pandas as pd
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline


# ---------------------------------------------------------------------------
# 1. Configuration — define experiment metadata upfront, not as afterthoughts
# ---------------------------------------------------------------------------

EXPERIMENT_NAME = "navy_logistics/maintenance_priority_classifier"
MODEL_REGISTRY_NAME = "navy_logistics.maintenance.priority_classifier"  # Unity Catalog path

# On Databricks GovCloud, the tracking server is managed — no URI needed.
# In a standalone MLflow server, you would set:
# mlflow.set_tracking_uri("https://your-mlflow-server")
mlflow.set_experiment(EXPERIMENT_NAME)


# ---------------------------------------------------------------------------
# 2. Load and version training data
#
# On Databricks, training data typically comes from a Delta table.
# The key practice: record the exact table version you trained on.
# Delta's time-travel capability means you can always reconstruct this data.
# ---------------------------------------------------------------------------

def load_training_data_from_delta(spark, table_name: str) -> tuple[pd.DataFrame, int]:
    """
    Load training data from a Delta table and return the table version number.

    The version number is critical for reproducibility — log it with every run.
    Without it, you cannot reconstruct the exact training dataset months later
    when an auditor or ATO reviewer asks.
    """
    # Read the current version of the table
    df_spark = spark.table(table_name)
    df = df_spark.toPandas()

    # Get the current Delta table version
    history = spark.sql(f"DESCRIBE HISTORY {table_name} LIMIT 1")
    table_version = history.collect()[0]["version"]

    return df, table_version


def create_synthetic_maintenance_data(n_samples: int = 10_000) -> pd.DataFrame:
    """
    Create synthetic maintenance work order data for local testing.

    In production on Advana or a Databricks GovCloud workspace, replace this
    with a call to load_training_data_from_delta() pointing at the actual
    maintenance work order feature table.

    Features represent typical Naval maintenance work orders:
    - equipment_age_years: Age of the equipment in the work order
    - days_since_last_service: Days since prior service action
    - failure_code_severity: Encoded severity of the reported failure code (1-5)
    - parts_availability_score: Availability of required parts (0.0-1.0)
    - crew_qualification_level: Average qualification level of assigned technicians
    - work_order_type: Type of maintenance action (0=scheduled, 1=corrective, 2=emergency)
    - historical_completion_rate: Historical on-time completion rate for this equipment class

    Target:
    - priority_class: 0=standard, 1=elevated, 2=critical
    """
    np.random.seed(42)

    equipment_age = np.random.exponential(scale=5, size=n_samples).clip(0.5, 30)
    days_since_service = np.random.exponential(scale=60, size=n_samples).clip(1, 500)
    failure_severity = np.random.choice([1, 2, 3, 4, 5], size=n_samples,
                                        p=[0.35, 0.25, 0.20, 0.12, 0.08])
    parts_availability = np.random.beta(5, 2, size=n_samples)
    crew_qualification = np.random.normal(3.2, 0.8, size=n_samples).clip(1, 5)
    work_order_type = np.random.choice([0, 1, 2], size=n_samples, p=[0.5, 0.35, 0.15])
    completion_rate = np.random.beta(7, 2, size=n_samples)

    # Priority class derived from a combination of factors (simplified)
    priority_score = (
        0.25 * (failure_severity / 5)
        + 0.20 * (days_since_service / 500)
        + 0.15 * (equipment_age / 30)
        + 0.15 * (1 - parts_availability)
        + 0.15 * (work_order_type / 2)
        + 0.10 * (1 - completion_rate)
    )
    noise = np.random.normal(0, 0.05, size=n_samples)
    priority_score = (priority_score + noise).clip(0, 1)

    priority_class = np.where(priority_score < 0.35, 0,
                     np.where(priority_score < 0.65, 1, 2))

    return pd.DataFrame({
        "equipment_age_years": equipment_age,
        "days_since_last_service": days_since_service,
        "failure_code_severity": failure_severity,
        "parts_availability_score": parts_availability,
        "crew_qualification_level": crew_qualification,
        "work_order_type": work_order_type,
        "historical_completion_rate": completion_rate,
        "priority_class": priority_class,
    })


def compute_data_hash(df: pd.DataFrame) -> str:
    """
    Compute a SHA-256 hash of a DataFrame for data versioning when a Delta
    table version number is not available (e.g., during local development).

    In production on Databricks, use the Delta table version number instead.
    """
    data_bytes = pd.util.hash_pandas_object(df, index=True).values.tobytes()
    return hashlib.sha256(data_bytes).hexdigest()[:16]


def get_git_commit_hash() -> str:
    """Return the current Git commit hash, or 'unknown' if not in a repo."""
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        return result.stdout.strip() if result.returncode == 0 else "unknown"
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return "unknown"


# ---------------------------------------------------------------------------
# 3. Training function with comprehensive MLflow logging
# ---------------------------------------------------------------------------

def train_and_log(
    df: pd.DataFrame,
    data_version: str,
    hyperparams: dict,
    tags: dict | None = None,
) -> str:
    """
    Train a gradient boosting classifier and log everything to MLflow.

    Returns the MLflow run ID for reference.

    Parameters
    ----------
    df : pd.DataFrame
        Training dataset (features + target).
    data_version : str
        Version identifier for the training data (Delta table version number
        or SHA-256 hash of the dataset).
    hyperparams : dict
        Hyperparameters to train with and log.
    tags : dict, optional
        Additional key-value tags to attach to the run (e.g., program name,
        contract number, model purpose).
    """
    feature_cols = [
        "equipment_age_years",
        "days_since_last_service",
        "failure_code_severity",
        "parts_availability_score",
        "crew_qualification_level",
        "work_order_type",
        "historical_completion_rate",
    ]
    target_col = "priority_class"

    X = df[feature_cols]
    y = df[target_col]

    # Fixed test set split — the same random_state means the same split every
    # time, which is required for the performance gate in CI to be meaningful.
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )

    with mlflow.start_run() as run:
        run_id = run.info.run_id

        # -----------------------------------------------------------------
        # Log parameters — hyperparameters and training configuration
        # -----------------------------------------------------------------
        mlflow.log_params(hyperparams)
        mlflow.log_param("n_train_samples", len(X_train))
        mlflow.log_param("n_test_samples", len(X_test))
        mlflow.log_param("feature_count", len(feature_cols))
        mlflow.log_param("target_classes", sorted(y.unique().tolist()))
        mlflow.log_param("sklearn_pipeline", "StandardScaler + GradientBoostingClassifier")

        # -----------------------------------------------------------------
        # Log data provenance — the most commonly skipped logging step
        # -----------------------------------------------------------------
        mlflow.log_param("training_data_version", data_version)
        mlflow.log_param("training_data_cutoff_date", datetime.now().strftime("%Y-%m-%d"))
        mlflow.log_param("git_commit_hash", get_git_commit_hash())

        # -----------------------------------------------------------------
        # Build and train the model
        # -----------------------------------------------------------------
        pipeline = Pipeline([
            ("scaler", StandardScaler()),
            ("classifier", GradientBoostingClassifier(
                n_estimators=hyperparams["n_estimators"],
                learning_rate=hyperparams["learning_rate"],
                max_depth=hyperparams["max_depth"],
                min_samples_leaf=hyperparams["min_samples_leaf"],
                subsample=hyperparams["subsample"],
                random_state=42,
            )),
        ])

        pipeline.fit(X_train, y_train)

        # -----------------------------------------------------------------
        # Evaluate on the held-out test set
        #
        # Important: log test set metrics, not just validation metrics.
        # Validation metrics guided hyperparameter selection and are optimistic.
        # Test set metrics are what you report to the ATO reviewer.
        # -----------------------------------------------------------------
        y_pred = pipeline.predict(X_test)
        y_prob = pipeline.predict_proba(X_test)

        accuracy = accuracy_score(y_test, y_pred)
        roc_auc = roc_auc_score(y_test, y_prob, multi_class="ovr", average="macro")

        mlflow.log_metric("test_accuracy", accuracy)
        mlflow.log_metric("test_roc_auc_macro", roc_auc)

        # Per-class metrics — a 94% accuracy on an imbalanced dataset might mean
        # 0% recall on the minority class. Log the full picture.
        report = classification_report(y_test, y_pred, output_dict=True)
        for class_label, class_metrics in report.items():
            if isinstance(class_metrics, dict):
                label_str = str(class_label).replace(" ", "_")
                mlflow.log_metric(f"test_precision_{label_str}", class_metrics["precision"])
                mlflow.log_metric(f"test_recall_{label_str}", class_metrics["recall"])
                mlflow.log_metric(f"test_f1_{label_str}", class_metrics["f1-score"])

        # -----------------------------------------------------------------
        # Log artifacts — files that make the run interpretable later
        # -----------------------------------------------------------------

        # Confusion matrix as JSON (more useful than a plot for programmatic review)
        cm = confusion_matrix(y_test, y_pred)
        cm_dict = {
            "confusion_matrix": cm.tolist(),
            "class_labels": sorted(y.unique().tolist()),
            "class_names": {0: "standard", 1: "elevated", 2: "critical"},
        }
        with open("/tmp/confusion_matrix.json", "w") as f:
            json.dump(cm_dict, f, indent=2)
        mlflow.log_artifact("/tmp/confusion_matrix.json", artifact_path="evaluation")

        # Feature importance — the scaler does not have importances, access the classifier
        classifier = pipeline.named_steps["classifier"]
        importance_dict = dict(zip(feature_cols, classifier.feature_importances_))
        importance_sorted = dict(sorted(importance_dict.items(),
                                        key=lambda x: x[1], reverse=True))
        with open("/tmp/feature_importance.json", "w") as f:
            json.dump(importance_sorted, f, indent=2)
        mlflow.log_artifact("/tmp/feature_importance.json", artifact_path="evaluation")

        # Full classification report as text
        report_text = classification_report(y_test, y_pred,
                                            target_names=["standard", "elevated", "critical"])
        with open("/tmp/classification_report.txt", "w") as f:
            f.write(report_text)
        mlflow.log_artifact("/tmp/classification_report.txt", artifact_path="evaluation")

        # -----------------------------------------------------------------
        # Log the model itself with input/output schema (signature)
        # The signature enables runtime input validation — MLflow checks
        # that inference requests match the expected schema.
        # -----------------------------------------------------------------
        from mlflow.models.signature import infer_signature
        signature = infer_signature(X_train, y_pred[:5])

        mlflow.sklearn.log_model(
            sk_model=pipeline,
            artifact_path="model",
            signature=signature,
            registered_model_name=None,  # Register separately after evaluation
            input_example=X_test.head(3),
        )

        # -----------------------------------------------------------------
        # Apply tags for filtering and governance
        # -----------------------------------------------------------------
        default_tags = {
            "program": "navy_logistics_maintenance",
            "model_type": "multiclass_classification",
            "target_variable": "work_order_priority",
            "training_framework": "scikit-learn",
            "mlops_maturity": "production_candidate",
        }
        if tags:
            default_tags.update(tags)
        mlflow.set_tags(default_tags)

        print(f"Run ID: {run_id}")
        print(f"Test accuracy: {accuracy:.4f}")
        print(f"Test ROC-AUC (macro): {roc_auc:.4f}")
        print(f"Model logged to experiment: {EXPERIMENT_NAME}")

    return run_id


# ---------------------------------------------------------------------------
# 4. Model registry promotion — register the best run as a versioned model
# ---------------------------------------------------------------------------

def register_model_to_staging(run_id: str, model_name: str) -> str:
    """
    Register a completed MLflow run's model to the Model Registry at Staging.

    In the full CI/CD pipeline, this step is gated by a performance check
    comparing the candidate against the current production model baseline.
    (See 02_model_registry_deployment.py for the full promotion workflow.)

    Returns the model version number.
    """
    client = mlflow.MlflowClient()

    # Register the model — this creates a new version in the registry
    model_uri = f"runs:/{run_id}/model"
    model_version = mlflow.register_model(
        model_uri=model_uri,
        name=model_name,
    )

    version_number = model_version.version
    print(f"Registered model '{model_name}' version {version_number}")

    # Transition to Staging and add a comment documenting why
    client.transition_model_version_stage(
        name=model_name,
        version=version_number,
        stage="Staging",
        archive_existing_versions=False,
    )

    client.update_model_version(
        name=model_name,
        version=version_number,
        description=(
            f"Candidate model from run {run_id}. "
            f"Promoted to Staging after passing automated evaluation gate. "
            f"Awaiting human review and approval before Production promotion."
        ),
    )

    print(f"Version {version_number} transitioned to Staging")
    return version_number


# ---------------------------------------------------------------------------
# 5. Main execution
# ---------------------------------------------------------------------------

def main():
    # Load data — in production, call load_training_data_from_delta()
    print("Loading training data...")
    df = create_synthetic_maintenance_data(n_samples=10_000)
    data_version = compute_data_hash(df)
    print(f"Dataset: {len(df):,} rows | Data version hash: {data_version}")

    # Hyperparameter configuration — vary these across runs to find the best model
    hyperparams = {
        "n_estimators": 300,
        "learning_rate": 0.05,
        "max_depth": 5,
        "min_samples_leaf": 20,
        "subsample": 0.8,
    }

    # Train and log
    print(f"\nStarting MLflow run in experiment: {EXPERIMENT_NAME}")
    run_id = train_and_log(
        df=df,
        data_version=data_version,
        hyperparams=hyperparams,
        tags={"contract_number": "N00024-25-C-XXXX", "environment": "development"},
    )

    # Register to staging (in CI, this step is preceded by a performance gate)
    print(f"\nRegistering model to registry...")
    version = register_model_to_staging(
        run_id=run_id,
        model_name=MODEL_REGISTRY_NAME,
    )

    print(f"\nDone. Model '{MODEL_REGISTRY_NAME}' v{version} is in Staging.")
    print(f"Next: Review evaluation artifacts in MLflow UI, then approve for Production.")


if __name__ == "__main__":
    main()
