"""
Chapter 01: Platform Connections
=================================
Connecting to each of the five federal data science platforms.

All examples use authentication patterns compatible with CAC/PIV-based
government environments. Never hardcode credentials. Use environment
variables or platform-native authentication.

Platform coverage:
  1. Advana (via Databricks on Advana)
  2. Navy Jupiter (via Databricks on Jupiter)
  3. Databricks standalone (direct GovCloud workspace)
  4. Qlik Cloud Government (REST API + SSE)
  5. Palantir Foundry (Code Workspace pattern + dataset access)

Note: Import paths for platform-specific SDKs (e.g., advana_sdk,
palantir_models) are illustrative. Actual package names vary by
program. The Databricks dbutils and spark contexts shown here are
accurate for Databricks notebook environments.
"""

import os
import json
import pandas as pd
from datetime import datetime, timedelta
from typing import Optional

# ============================================================
# 1. DATABRICKS — Standard Notebook Environment
#    (applies to Advana, Jupiter, and standalone Databricks
#    GovCloud workspaces; the spark context is pre-initialized)
# ============================================================

def databricks_connect_and_query():
    """
    In a Databricks notebook, spark and dbutils are pre-initialized.
    This function shows the patterns you use to interact with Unity Catalog
    and Delta tables from within a notebook cell.
    """
    # In a real notebook, `spark` is already available in the global namespace.
    # The line below is for running this as a standalone script via
    # Databricks Connect (for local development against a remote cluster).
    try:
        from databricks.connect import DatabricksSession
        spark = DatabricksSession.builder.getOrCreate()
        print("Running via Databricks Connect (local dev mode)")
    except ImportError:
        # Inside a Databricks notebook: spark is pre-injected
        # This try/except is standard defensive coding for portability
        print("Running inside Databricks notebook — spark context pre-initialized")

    # Unity Catalog path format: catalog.schema.table
    # On Advana/Jupiter, catalog names map to organizational tenants
    catalog = "don_jupiter"          # DON tenant catalog
    schema = "readiness_silver"      # silver-tier readiness data
    table = "ship_maintenance_events"

    full_table_path = f"{catalog}.{schema}.{table}"

    # Read a Delta table into a Spark DataFrame
    df = spark.table(full_table_path)

    # Quick sanity check: row count and schema inspection
    print(f"Table: {full_table_path}")
    print(f"Rows: {df.count():,}")
    print(f"Columns: {len(df.columns)}")
    df.printSchema()

    return df


def databricks_pandas_workflow():
    """
    Data scientists often use PySpark to filter large datasets down to
    a working size, then convert to pandas for modeling.

    Pattern: Spark for filtering at scale → pandas for analysis and modeling.
    """
    # Assume spark is available (notebook context)
    # Filter large maintenance dataset to ships with open work orders
    # in the last 90 days — a common first-pass filter
    ninety_days_ago = (datetime.now() - timedelta(days=90)).strftime("%Y-%m-%d")

    df_spark = (
        spark.table("don_jupiter.readiness_silver.ship_maintenance_events")
        .filter(f"event_date >= '{ninety_days_ago}'")
        .filter("work_order_status = 'OPEN'")
        .select(
            "hull_number",
            "ship_class",
            "event_type",
            "event_date",
            "days_open",
            "priority_code"
        )
    )

    # Convert to pandas for downstream sklearn/statsmodels work
    # Only do this after filtering — never .toPandas() on a full large table
    df_pd = df_spark.toPandas()
    print(f"Working dataset: {len(df_pd):,} rows, {df_pd['hull_number'].nunique()} unique hulls")

    # Basic data quality check — procurement and readiness data frequently
    # has duplicates and inconsistent codes
    dup_count = df_pd.duplicated(subset=["hull_number", "event_date", "event_type"]).sum()
    if dup_count > 0:
        print(f"WARNING: {dup_count:,} duplicate rows detected. Check source system.")
    else:
        print("Duplicate check passed.")

    return df_pd


def databricks_mlflow_experiment():
    """
    MLflow experiment tracking is automatic in Databricks notebooks — every
    call to mlflow.log_* is captured. This pattern shows how to name
    experiments following DoD program conventions.

    Experiment naming convention: /program/model_type/version
    This makes experiments discoverable by other team members.
    """
    import mlflow
    import mlflow.sklearn
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import classification_report
    import numpy as np

    # In a real workflow this data comes from a Delta table
    # Using synthetic data here for illustration
    np.random.seed(42)
    n_samples = 5000
    X = pd.DataFrame({
        "days_since_last_maintenance": np.random.exponential(45, n_samples),
        "open_work_orders": np.random.poisson(2, n_samples),
        "mission_capable_pct_30d": np.random.beta(7, 2, n_samples) * 100,
        "operational_tempo_score": np.random.normal(65, 15, n_samples).clip(0, 100)
    })
    y = (
        (X["days_since_last_maintenance"] > 60) |
        (X["open_work_orders"] > 4) |
        (X["mission_capable_pct_30d"] < 75)
    ).astype(int)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # Set the experiment — use a naming convention your team agrees on
    mlflow.set_experiment("/task_force_hopper/maintenance_risk/v1")

    with mlflow.start_run(run_name="rf_baseline_90day_filter"):
        # Log input parameters
        mlflow.log_param("n_estimators", 100)
        mlflow.log_param("max_depth", 8)
        mlflow.log_param("training_data_filter", "last_90_days_open_orders")
        mlflow.log_param("n_training_rows", len(X_train))

        # Train
        model = RandomForestClassifier(
            n_estimators=100,
            max_depth=8,
            random_state=42,
            class_weight="balanced"   # readiness datasets are often imbalanced
        )
        model.fit(X_train, y_train)

        # Evaluate
        y_pred = model.predict(X_test)
        report = classification_report(y_test, y_pred, output_dict=True)

        mlflow.log_metric("test_accuracy", report["accuracy"])
        mlflow.log_metric("precision_at_risk", report["1"]["precision"])
        mlflow.log_metric("recall_at_risk", report["1"]["recall"])

        # Log the model artifact
        mlflow.sklearn.log_model(
            model,
            artifact_path="maintenance_risk_model",
            registered_model_name="ship_maintenance_risk_classifier"
        )

        print(f"Accuracy: {report['accuracy']:.3f}")
        print(f"Precision (at-risk class): {report['1']['precision']:.3f}")
        print(f"Recall (at-risk class): {report['1']['recall']:.3f}")

    return model


# ============================================================
# 2. QLIK — REST API and Server-Side Extension (SSE) Pattern
#    FedRAMP Moderate | IL4 authorized
#    Primary use: dashboards, executive reporting, analytics
# ============================================================

def qlik_rest_api_connection():
    """
    Qlik Cloud Government exposes a REST API for managing apps,
    spaces, and data loads programmatically. This is useful for
    automation: triggering reloads, exporting data, checking app status.

    Authentication uses Bearer tokens from the Qlik API key mechanism.
    In government environments, tokens are managed through Qlik Cloud
    Government's tenant administration.

    NOTE: Replace QLIK_TENANT_URL and QLIK_API_KEY with your program's
    actual values. Never commit these to version control.
    """
    import requests

    tenant_url = os.environ.get("QLIK_TENANT_URL")
    api_key = os.environ.get("QLIK_API_KEY")

    if not tenant_url or not api_key:
        raise EnvironmentError(
            "Set QLIK_TENANT_URL and QLIK_API_KEY environment variables. "
            "Do not hardcode credentials."
        )

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }

    # List all apps the authenticated user can access
    response = requests.get(
        f"{tenant_url}/api/v1/items?resourceType=app",
        headers=headers,
        timeout=30
    )
    response.raise_for_status()

    apps = response.json().get("data", [])
    print(f"Found {len(apps)} accessible apps")
    for app in apps[:5]:
        print(f"  - {app['name']} (id: {app['resourceId']})")

    return apps


def qlik_sse_python_scoring_function():
    """
    Server-Side Extension (SSE) allows Qlik to call Python computation
    from within a chart expression or data load script.

    This shows the server-side Python function that would be called from
    a Qlik SSE plugin (such as qlik-py-tools). The function receives
    procurement data as a pandas DataFrame from Qlik and returns
    anomaly scores.

    The SSE server runs as a separate process (typically on the same
    network segment as the Qlik server). Qlik sends data via gRPC;
    the plugin returns the result as a series or value.

    See: https://github.com/qlik-oss/server-side-extension
    """
    from sklearn.ensemble import IsolationForest

    def score_procurement_anomalies(df: pd.DataFrame) -> pd.Series:
        """
        Receives a DataFrame with procurement contract data from Qlik.
        Returns an anomaly score per row: higher is more anomalous.

        Expected input columns (as sent from Qlik's data model):
          - obligation_amount: float — contract dollar value
          - days_to_award: int — days from solicitation to award
          - vendor_award_count: int — number of awards to this vendor this FY
          - competition_type_code: int — encoded from competition category
        """
        feature_cols = [
            "obligation_amount",
            "days_to_award",
            "vendor_award_count",
            "competition_type_code"
        ]

        # Guard against missing columns
        missing = [c for c in feature_cols if c not in df.columns]
        if missing:
            raise ValueError(f"Missing required columns: {missing}")

        # Drop rows with nulls in features (returns NaN for those in output)
        df_clean = df[feature_cols].dropna()

        model = IsolationForest(contamination=0.05, random_state=42)
        raw_scores = model.fit_predict(df_clean)
        anomaly_scores = model.score_samples(df_clean)

        # Map scores back to original index, fill dropped rows with NaN
        result = pd.Series(index=df.index, dtype=float)
        result.loc[df_clean.index] = -anomaly_scores  # negate: higher = more anomalous

        return result

    # Demonstration: create sample procurement data
    sample_data = pd.DataFrame({
        "obligation_amount": [450000, 1200000, 3400, 87000000, 225000],
        "days_to_award": [45, 90, 12, 180, 55],
        "vendor_award_count": [3, 1, 15, 2, 7],
        "competition_type_code": [1, 2, 1, 3, 2]
    })

    scores = score_procurement_anomalies(sample_data)
    sample_data["anomaly_score"] = scores
    print("Procurement anomaly scores:")
    print(sample_data.sort_values("anomaly_score", ascending=False).to_string(index=False))

    return scores


# ============================================================
# 3. PALANTIR FOUNDRY — Code Workspace / Dataset Access
#    FedRAMP High | IL4/IL5 | IL6 via Azure Gov Top Secret
#    Primary use: operational AI, ontology-backed applications
# ============================================================

def palantir_foundry_dataset_read():
    """
    In Palantir Foundry Code Workspaces (JupyterLab), datasets are
    accessed through the Foundry dataset API. The `foundry_dev_tools`
    package provides local development connectivity; in a live Code
    Workspace the context is pre-configured.

    Current framework: palantir_models (foundry_ml is deprecated as
    of October 31, 2025 — do not use it in new projects).

    This shows the dataset read pattern used in Code Workspaces.
    """
    # In a Foundry Code Workspace, the transforms context provides
    # dataset access. For local development, use foundry-dev-tools.
    # See: https://github.com/palantir/foundry-dev-tools

    try:
        from foundry_dev_tools import FoundryContext
        ctx = FoundryContext()
        print("Connected via foundry-dev-tools (local dev mode)")
    except ImportError:
        print(
            "foundry-dev-tools not available. "
            "In a Foundry Code Workspace, use the transforms context directly."
        )
        return None

    # Read a dataset by its Resource Identifier (RID)
    # RIDs look like: ri.foundry.main.dataset.abc123...
    # Find them in Foundry's Data Catalog or dataset settings
    dataset_rid = os.environ.get("FOUNDRY_DATASET_RID_SHIP_SUPPLY_CHAIN")
    if not dataset_rid:
        print("Set FOUNDRY_DATASET_RID_SHIP_SUPPLY_CHAIN to run this example.")
        return None

    df = ctx.get_dataset(dataset_rid).to_pandas()
    print(f"Dataset loaded: {len(df):,} rows x {len(df.columns)} columns")
    return df


def palantir_foundry_publish_model():
    """
    Publishing a trained ML model to Foundry's model registry using
    the palantir_models library (current framework as of late 2025).

    Once published, the model can be:
    - Called from AIP Logic in a Workshop application
    - Integrated into an AIP Agent for automated decision support
    - Scheduled as a batch inference job via Foundry Pipelines

    This is the correct pattern for new Foundry ML work.
    Note: foundry_ml is deprecated — use palantir_models.
    """
    try:
        import palantir_models as pm
        from sklearn.ensemble import GradientBoostingClassifier
        import numpy as np
    except ImportError:
        print("palantir_models not installed. Available inside Foundry Code Workspaces.")
        return None

    # Train a sample model (in practice, this comes from your actual data pipeline)
    np.random.seed(42)
    X_train = pd.DataFrame({
        "component_age_days": np.random.exponential(200, 1000),
        "failure_count_12m": np.random.poisson(1.2, 1000),
        "temperature_delta_avg": np.random.normal(5, 3, 1000)
    })
    y_train = ((X_train["component_age_days"] > 300) |
               (X_train["failure_count_12m"] > 3)).astype(int)

    model = GradientBoostingClassifier(n_estimators=100, max_depth=4, random_state=42)
    model.fit(X_train, y_train)

    # Publish to Foundry's model registry
    # This makes the model available to AIP Logic and Workshop applications
    published_model = pm.ModelRegistry.publish(
        model=model,
        model_name="ship_component_failure_risk",
        description="Predicts component failure risk for surface fleet CBM program",
        tags={"program": "task_force_hopper", "version": "1.0", "il_level": "IL4"}
    )

    print(f"Model published: {published_model.rid}")
    print("Model is now accessible from AIP Logic in Workshop applications.")
    return published_model


# ============================================================
# 4. COLLIBRA DATA CATALOG
#    Used on both Advana and Jupiter for data discovery
#    Always check the catalog before writing any data pipeline
# ============================================================

def collibra_search_dataset(search_term: str, base_url: Optional[str] = None):
    """
    Search the Collibra data catalog for datasets matching a term.
    On Advana and Jupiter, Collibra is the authoritative source for
    dataset metadata, lineage, data quality, and ownership.

    Before building any pipeline or model, search for your dataset here:
    1. Verify the dataset exists and is documented
    2. Check its data tier (Bronze/Silver/Gold on Jupiter)
    3. Confirm the data steward contact
    4. Review any known quality issues
    5. Check access permissions before requesting data

    Authentication uses the same CAC-based SSO as other DoD platforms.
    """
    import requests

    base_url = base_url or os.environ.get("COLLIBRA_BASE_URL")
    if not base_url:
        raise EnvironmentError("Set COLLIBRA_BASE_URL environment variable.")

    # Collibra REST API v2 search endpoint
    search_url = f"{base_url}/rest/2.0/assets"
    params = {
        "name": f"%{search_term}%",          # SQL LIKE-style pattern
        "nameMatchMode": "ANYWHERE",
        "typeName": "Data Set",               # Asset type filter
        "limit": 20,
        "offset": 0
    }

    # CAC-authenticated environments often use certificate-based auth
    # rather than username/password. In practice, session tokens from
    # your browser SSO session can be reused via the REST API.
    response = requests.get(
        search_url,
        params=params,
        auth=(
            os.environ.get("COLLIBRA_USER"),
            os.environ.get("COLLIBRA_TOKEN")
        ),
        timeout=30
    )
    response.raise_for_status()

    results = response.json().get("results", [])
    print(f"Found {len(results)} datasets matching '{search_term}':")
    for asset in results:
        tier = asset.get("attributes", {}).get("data_tier", "Unknown")
        steward = asset.get("responsibilities", [{}])[0].get("user", {}).get("fullName", "Unassigned")
        print(f"  [{tier}] {asset['name']} — Steward: {steward}")

    return results


# ============================================================
# 5. UTILITY: ENVIRONMENT VALIDATION
#    Run this on day one to check your setup is correct
# ============================================================

def validate_environment():
    """
    Checks that required environment variables and packages are available.
    Run this at the start of any new session to catch configuration issues
    before they surface mid-analysis.

    Add this to a cell at the top of your standard notebook template.
    """
    import importlib
    import sys

    print(f"Python version: {sys.version}")
    print(f"Timestamp: {datetime.now().isoformat()}")
    print()

    # Required packages by platform
    platform_packages = {
        "Databricks / General ML": [
            "pyspark", "pandas", "numpy", "scikit-learn",
            "mlflow", "matplotlib", "seaborn"
        ],
        "Qlik SSE": [
            "grpc", "pandas", "numpy", "scikit-learn"
        ],
        "Palantir Foundry": [
            "palantir_models"
        ]
    }

    for platform, packages in platform_packages.items():
        print(f"[{platform}]")
        for pkg in packages:
            try:
                importlib.import_module(pkg)
                print(f"  OK  {pkg}")
            except ImportError:
                print(f"  MISSING  {pkg}")
        print()

    # Check for required environment variables
    print("[Environment Variables]")
    env_vars = [
        "DATABRICKS_HOST",
        "DATABRICKS_TOKEN",
        "QLIK_TENANT_URL",
        "QLIK_API_KEY",
        "COLLIBRA_BASE_URL",
    ]
    for var in env_vars:
        value = os.environ.get(var)
        if value:
            # Show only that it's set, not the value — never log credentials
            print(f"  SET  {var}")
        else:
            print(f"  NOT SET  {var}")


# ============================================================
# MAIN: Run all demonstrations
# ============================================================

if __name__ == "__main__":
    print("=" * 60)
    print("Chapter 01: Platform Connection Examples")
    print("=" * 60)
    print()

    print("--- Environment Validation ---")
    validate_environment()

    print("\n--- Qlik Anomaly Scoring Demo (no external connection required) ---")
    qlik_sse_python_scoring_function()

    print("\n--- MLflow Experiment Demo (no external connection required) ---")
    # MLflow demo uses synthetic data; works without a Databricks cluster
    # For full functionality, run inside a Databricks notebook
    try:
        import mlflow
        databricks_mlflow_experiment()
    except ImportError:
        print("mlflow not installed locally. Run inside a Databricks notebook for full demo.")

    print("\nTo run platform-specific examples, set the required environment variables")
    print("and run the individual functions from within the appropriate platform environment.")
