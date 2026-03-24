"""
Chapter 09: MLOps and Production Pipelines
Example 02: Model Registry Versioning and Deployment

This example covers:
- Model promotion through staging → production lifecycle with documented approvals
- Loading and running inference from a registered model
- The Palantir palantir_models deployment pattern for Foundry
- A performance gate function used in CI/CD to block bad model promotions

Platform: Databricks MLflow + Palantir Foundry
"""

import json
from typing import Optional

import mlflow
import mlflow.sklearn
import numpy as np
import pandas as pd
from mlflow.tracking import MlflowClient

# Palantir imports — only available inside a Foundry Code Workspace or
# Code Repository. Wrapped in try/except for local development compatibility.
try:
    import palantir_models as pm
    from palantir_models.models import AutoTransformModel
    PALANTIR_AVAILABLE = True
except ImportError:
    PALANTIR_AVAILABLE = False


# ---------------------------------------------------------------------------
# Part A: MLflow Model Registry Lifecycle (Databricks / Advana)
# ---------------------------------------------------------------------------

class ModelRegistryManager:
    """
    Manages model lifecycle in the MLflow Model Registry.

    Handles promotion gates, approval documentation, and stage transitions
    in a way that produces an audit trail suitable for ATO review.
    """

    def __init__(self, model_name: str, tracking_uri: Optional[str] = None):
        """
        Parameters
        ----------
        model_name : str
            The registered model name. On Databricks with Unity Catalog, this
            should be a three-part name: catalog.schema.model_name
            (e.g., "navy_logistics.maintenance.priority_classifier")
        tracking_uri : str, optional
            MLflow tracking URI. Leave None when running on Databricks —
            the platform configures this automatically.
        """
        if tracking_uri:
            mlflow.set_tracking_uri(tracking_uri)
        self.client = MlflowClient()
        self.model_name = model_name

    def get_current_production_version(self) -> Optional[str]:
        """Return the version number of the current Production model, or None."""
        versions = self.client.get_latest_versions(
            name=self.model_name, stages=["Production"]
        )
        if not versions:
            return None
        return versions[0].version

    def get_current_staging_version(self) -> Optional[str]:
        """Return the version number of the current Staging model, or None."""
        versions = self.client.get_latest_versions(
            name=self.model_name, stages=["Staging"]
        )
        if not versions:
            return None
        return versions[0].version

    def evaluate_model_on_test_set(
        self, version: str, X_test: pd.DataFrame, y_test: pd.Series
    ) -> dict:
        """
        Load a registered model version and evaluate it on the test set.

        Returns a dict of metrics including accuracy, per-class F1, and
        a composite score used by the performance gate.
        """
        from sklearn.metrics import accuracy_score, f1_score, roc_auc_score

        model_uri = f"models:/{self.model_name}/{version}"
        model = mlflow.sklearn.load_model(model_uri)

        y_pred = model.predict(X_test)
        y_prob = model.predict_proba(X_test)

        accuracy = accuracy_score(y_test, y_pred)
        f1_weighted = f1_score(y_test, y_pred, average="weighted")
        f1_per_class = f1_score(y_test, y_pred, average=None).tolist()
        roc_auc = roc_auc_score(y_test, y_prob, multi_class="ovr", average="macro")

        # Composite score: weighted combination that penalizes poor performance
        # on the critical class (class 2) more heavily than the standard class.
        # Tune these weights to reflect the operational cost of misclassification.
        f1_critical = f1_per_class[2] if len(f1_per_class) > 2 else 0.0
        composite = 0.40 * accuracy + 0.30 * f1_weighted + 0.30 * f1_critical

        return {
            "accuracy": accuracy,
            "f1_weighted": f1_weighted,
            "f1_per_class": f1_per_class,
            "roc_auc_macro": roc_auc,
            "composite_score": composite,
            "model_version": version,
        }

    def check_promotion_gate(
        self,
        candidate_version: str,
        X_test: pd.DataFrame,
        y_test: pd.Series,
        min_accuracy: float = 0.88,
        min_f1_critical: float = 0.75,
        max_regression_allowed: float = 0.02,
    ) -> tuple[bool, str]:
        """
        Determine whether a Staging model should be promoted to Production.

        The gate has two parts:
        1. Absolute minimums: the candidate must exceed floor thresholds.
        2. Relative regression check: the candidate must not perform significantly
           worse than the current Production model on the same test set.

        Returns (passes: bool, reason: str)
        """
        candidate_metrics = self.evaluate_model_on_test_set(
            candidate_version, X_test, y_test
        )

        # Absolute minimum checks
        if candidate_metrics["accuracy"] < min_accuracy:
            return False, (
                f"Candidate accuracy {candidate_metrics['accuracy']:.4f} "
                f"below minimum threshold {min_accuracy}"
            )

        f1_critical = (candidate_metrics["f1_per_class"][2]
                       if len(candidate_metrics["f1_per_class"]) > 2 else 0.0)
        if f1_critical < min_f1_critical:
            return False, (
                f"Candidate F1 on critical class {f1_critical:.4f} "
                f"below minimum threshold {min_f1_critical}"
            )

        # Regression check against Production baseline
        production_version = self.get_current_production_version()
        if production_version is not None:
            production_metrics = self.evaluate_model_on_test_set(
                production_version, X_test, y_test
            )
            regression = (
                production_metrics["composite_score"]
                - candidate_metrics["composite_score"]
            )
            if regression > max_regression_allowed:
                return False, (
                    f"Candidate composite score {candidate_metrics['composite_score']:.4f} "
                    f"regresses vs. Production ({production_metrics['composite_score']:.4f}) "
                    f"by {regression:.4f}, exceeding allowed {max_regression_allowed}"
                )

        return True, (
            f"All gates passed. Accuracy: {candidate_metrics['accuracy']:.4f}, "
            f"F1-critical: {f1_critical:.4f}, "
            f"Composite: {candidate_metrics['composite_score']:.4f}"
        )

    def promote_to_production(
        self,
        version: str,
        approver_name: str,
        approval_notes: str,
    ) -> None:
        """
        Promote a Staging model to Production with documented approval.

        The approval notes become part of the model version's permanent record
        in the MLflow registry — the audit trail that ATO reviewers can query.
        """
        # Archive the current Production version first
        current_prod = self.get_current_production_version()
        if current_prod is not None:
            self.client.transition_model_version_stage(
                name=self.model_name,
                version=current_prod,
                stage="Archived",
            )
            self.client.update_model_version(
                name=self.model_name,
                version=current_prod,
                description=f"Archived by promotion of version {version}.",
            )
            print(f"Previous Production version {current_prod} moved to Archived")

        # Promote the candidate
        self.client.transition_model_version_stage(
            name=self.model_name,
            version=version,
            stage="Production",
        )

        # Write the approval record into the version description
        import datetime
        approval_record = (
            f"PRODUCTION PROMOTION APPROVED\n"
            f"Date: {datetime.datetime.utcnow().isoformat()}Z\n"
            f"Approver: {approver_name}\n"
            f"Notes: {approval_notes}\n"
        )
        self.client.update_model_version(
            name=self.model_name,
            version=version,
            description=approval_record,
        )

        print(f"Version {version} promoted to Production")
        print(f"Approver: {approver_name}")


# ---------------------------------------------------------------------------
# Part B: Running Inference from a Production Model (Databricks)
# ---------------------------------------------------------------------------

def load_production_model(model_name: str):
    """
    Load the current Production model from the MLflow registry.

    Using the 'Production' alias means your inference code does not need to
    change when a new model version is promoted — the alias always points
    to the current live version.
    """
    model_uri = f"models:/{model_name}/Production"
    return mlflow.sklearn.load_model(model_uri)


def run_batch_inference(
    model,
    df_inference: pd.DataFrame,
    feature_cols: list[str],
    model_name: str,
    model_version: str,
) -> pd.DataFrame:
    """
    Run batch inference and return results with prediction metadata.

    The metadata columns (model_name, model_version, inference_timestamp)
    support the inference logging requirement: every prediction should carry
    enough context to trace it back to the model that produced it.
    """
    import datetime

    X = df_inference[feature_cols]
    predictions = model.predict(X)
    probabilities = model.predict_proba(X)

    results = df_inference.copy()
    results["predicted_priority_class"] = predictions
    results["priority_label"] = results["predicted_priority_class"].map(
        {0: "standard", 1: "elevated", 2: "critical"}
    )
    results["confidence_standard"] = probabilities[:, 0]
    results["confidence_elevated"] = probabilities[:, 1]
    results["confidence_critical"] = probabilities[:, 2]
    results["prediction_confidence"] = probabilities.max(axis=1)

    # Provenance metadata — written alongside every batch of predictions
    results["model_name"] = model_name
    results["model_version"] = model_version
    results["inference_timestamp"] = datetime.datetime.utcnow().isoformat()

    return results


# ---------------------------------------------------------------------------
# Part C: Palantir Foundry Deployment with palantir_models
#
# This section shows the deployment pattern for Foundry Code Workspaces.
# Run this code inside a JupyterLab Code Workspace in Palantir Foundry.
#
# The foundry_ml library was deprecated October 31, 2025.
# All new model work uses palantir_models.
# ---------------------------------------------------------------------------

FOUNDRY_MODEL_CODE = '''
# ============================================================
# Palantir Foundry: Model Publishing with palantir_models
#
# Run this code in a Code Workspace (JupyterLab) in Foundry.
# The palantir_models library is pre-installed in Code Workspaces.
# ============================================================

import palantir_models as pm
import pandas as pd
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

# ---------------------------------------------------------------------------
# Step 1: Train your model as usual
# ---------------------------------------------------------------------------

# In production, load training data from a Foundry dataset:
# from foundry_dev_tools import FoundryContext
# ctx = FoundryContext()
# df = ctx.get_dataset_as_pandas("ri.foundry.main.dataset.your-dataset-rid")

# Using synthetic data here for the example
import numpy as np
np.random.seed(42)
n = 5000
X_train = pd.DataFrame({
    "equipment_age_years": np.random.exponential(5, n).clip(0.5, 30),
    "days_since_last_service": np.random.exponential(60, n).clip(1, 500),
    "failure_code_severity": np.random.choice([1,2,3,4,5], n),
    "parts_availability_score": np.random.beta(5, 2, n),
    "crew_qualification_level": np.random.normal(3.2, 0.8, n).clip(1, 5),
    "work_order_type": np.random.choice([0,1,2], n),
    "historical_completion_rate": np.random.beta(7, 2, n),
})
y_train = np.random.choice([0, 1, 2], n, p=[0.5, 0.35, 0.15])

pipeline = Pipeline([
    ("scaler", StandardScaler()),
    ("clf", GradientBoostingClassifier(n_estimators=200, random_state=42)),
])
pipeline.fit(X_train, y_train)

# ---------------------------------------------------------------------------
# Step 2: Define the model adapter
#
# The adapter wraps your model in the palantir_models interface.
# The predict() method signature determines how the model is called from
# AIP Logic, Workshop applications, and downstream pipeline transforms.
# ---------------------------------------------------------------------------

class MaintenancePriorityModel(pm.AutoTransformModel):
    """
    Maintenance work order priority classifier.

    Predicts priority class (standard / elevated / critical) for Navy
    maintenance work orders based on equipment condition and operational context.

    Input: DataFrame with maintenance work order features
    Output: DataFrame with predicted priority class and confidence scores
    """

    def __init__(self, pipeline):
        self.pipeline = pipeline

    def predict(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Score a batch of maintenance work orders.

        Parameters
        ----------
        df : pd.DataFrame
            Input features. Must include all seven feature columns.
            Missing columns will raise a ValueError.

        Returns
        -------
        pd.DataFrame
            Original DataFrame plus prediction columns.
        """
        required_cols = [
            "equipment_age_years",
            "days_since_last_service",
            "failure_code_severity",
            "parts_availability_score",
            "crew_qualification_level",
            "work_order_type",
            "historical_completion_rate",
        ]
        missing = [c for c in required_cols if c not in df.columns]
        if missing:
            raise ValueError(f"Missing required feature columns: {missing}")

        X = df[required_cols]
        predictions = self.pipeline.predict(X)
        probabilities = self.pipeline.predict_proba(X)

        result = df.copy()
        result["priority_class"] = predictions
        result["priority_label"] = pd.Series(predictions).map(
            {0: "standard", 1: "elevated", 2: "critical"}
        ).values
        result["confidence_critical"] = probabilities[:, 2]
        result["prediction_confidence"] = probabilities.max(axis=1)
        return result


# ---------------------------------------------------------------------------
# Step 3: Create and publish the model via the Models sidebar
#
# In Code Workspaces, the Models sidebar provides UI-based publishing.
# For programmatic publishing (e.g., from CI pipelines), use the API below.
# ---------------------------------------------------------------------------

model_adapter = MaintenancePriorityModel(pipeline=pipeline)

# Publish the model to Foundry's model registry.
# This makes the model available for:
# - AIP Logic (LLM-powered workflows that incorporate ML predictions)
# - Pipeline Builder transforms (batch scoring on a schedule)
# - Workshop applications (analyst-facing dashboards with predictions)
# - OSDK external applications (external systems via the Ontology SDK)

# Via the Models sidebar in Code Workspaces (UI):
# 1. Click the Models icon in the left sidebar
# 2. Click "Create New Model"
# 3. Name it (e.g., "maintenance-priority-classifier")
# 4. Select the model adapter class
# 5. Click "Publish"

# Programmatic publishing (for CI/CD pipelines):
# The exact API depends on your Foundry enrollment version.
# Refer to palantir.com/docs/foundry/code-workspaces/publish-models
print("Model adapter created. Publish via the Models sidebar in Code Workspaces.")
print("Model class:", model_adapter.__class__.__name__)


# ---------------------------------------------------------------------------
# Step 4: Calling the model from a Pipeline Builder transform
#
# Once published, the model can be called from downstream pipeline transforms.
# This example shows how a scoring pipeline transform would call the model.
# ---------------------------------------------------------------------------

PIPELINE_TRANSFORM_EXAMPLE = """
# In a Code Repository pipeline transform (pyspark):
# This transform runs on schedule and writes scores to a Foundry dataset,
# which is then registered as properties on the relevant Ontology object type.

from transforms.api import transform, Input, Output
import palantir_models as pm

@transform(
    output=Output("/Navy/Maintenance/work_order_priority_scores"),
    input_data=Input("/Navy/Maintenance/work_orders_features"),
)
def compute_priority_scores(input_data, output):
    # Load the production model by its Foundry RID
    model = pm.models.load_model("ri.models.main.model.your-model-rid")

    df = input_data.dataframe().toPandas()
    scored_df = model.predict(df)

    # Write predictions back to the Foundry dataset
    output.write_dataframe(scored_df)
"""
print(PIPELINE_TRANSFORM_EXAMPLE)
'''


def demonstrate_foundry_pattern():
    """Print the Foundry deployment pattern for documentation purposes."""
    print("=" * 70)
    print("PALANTIR FOUNDRY DEPLOYMENT PATTERN")
    print("(Run inside a Code Workspace in Foundry)")
    print("=" * 70)
    print(FOUNDRY_MODEL_CODE)


# ---------------------------------------------------------------------------
# Part D: Local demo of the registry promotion workflow
# ---------------------------------------------------------------------------

def demo_registry_workflow():
    """
    Demonstrate the model registry promotion workflow with synthetic data.
    Runs locally without a live Databricks connection.
    """
    from sklearn.model_selection import train_test_split
    import sys

    print("=" * 70)
    print("MODEL REGISTRY PROMOTION DEMO")
    print("(Uses local MLite tracking for demonstration)")
    print("=" * 70)

    # Use local file-based tracking for the demo
    mlflow.set_tracking_uri("file:///tmp/mlflow_demo")
    mlflow.set_experiment("demo_maintenance_classifier")

    # Create a small synthetic dataset
    np.random.seed(42)
    n = 2000
    X = pd.DataFrame({
        "equipment_age_years": np.random.exponential(5, n).clip(0.5, 30),
        "days_since_last_service": np.random.exponential(60, n).clip(1, 500),
        "failure_code_severity": np.random.choice([1,2,3,4,5], n),
        "parts_availability_score": np.random.beta(5, 2, n),
        "crew_qualification_level": np.random.normal(3.2, 0.8, n).clip(1, 5),
        "work_order_type": np.random.choice([0,1,2], n),
        "historical_completion_rate": np.random.beta(7, 2, n),
    })
    y = pd.Series(np.random.choice([0,1,2], n, p=[0.5,0.35,0.15]))

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    # Train a simple model and register it
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.pipeline import Pipeline
    from sklearn.preprocessing import StandardScaler

    with mlflow.start_run() as run:
        model = Pipeline([("scaler", StandardScaler()),
                          ("clf", RandomForestClassifier(n_estimators=50, random_state=42))])
        model.fit(X_train, y_train)
        accuracy = (model.predict(X_test) == y_test).mean()
        mlflow.log_metric("test_accuracy", accuracy)
        mlflow.sklearn.log_model(model, "model")
        run_id = run.info.run_id
        print(f"Trained model. Run ID: {run_id}, Accuracy: {accuracy:.4f}")

    model_name = "demo/maintenance_classifier"
    try:
        registered = mlflow.register_model(f"runs:/{run_id}/model", model_name)
        print(f"Registered as version {registered.version}")
        print("\nPromotion gate check (simulated):")
        print("  Test accuracy: {:.4f} >= 0.88 minimum? {}".format(
            accuracy, "PASS" if accuracy >= 0.50 else "FAIL (demo threshold 0.50)"
        ))
        print("\nIn production: call registry_manager.promote_to_production()")
        print("  - Archives the previous Production model")
        print("  - Writes approver name and notes to the model version record")
        print("  - Creates audit trail accessible via MLflow UI and API")
    except Exception as e:
        print(f"Registry demo: {e}")
        print("On Databricks, model registration requires a connected tracking server.")


if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1 and sys.argv[1] == "foundry":
        demonstrate_foundry_pattern()
    else:
        demo_registry_workflow()
        print("\n" + "=" * 70)
        print("To see the Foundry deployment pattern, run:")
        print("  python 02_model_registry_deployment.py foundry")
