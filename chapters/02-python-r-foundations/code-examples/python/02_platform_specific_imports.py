"""
Chapter 02: Python and R Foundations for Federal Platforms
Code Example 02: Platform-Specific Import Patterns and Authentication

Purpose:
    Working import patterns and authentication boilerplate for each of the
    five federal platforms. Copy the section relevant to your platform and
    adapt to your project.

    This file is organized by platform. Skip to the section you need.

Sections:
    1. Databricks (Advana / Navy Jupiter / Databricks GovCloud)
    2. Palantir Foundry (Code Workspaces and Transforms)
    3. Databricks SDK (automation / MLOps workflows)
    4. Cross-platform utilities
    5. Authentication anti-patterns (what NOT to do)

IMPORTANT: Never hardcode tokens, passwords, or credentials in source files.
Every authentication example below uses environment variables or platform
secret management. This is not optional — it is a security requirement on
all five platforms.
"""

# ===========================================================================
# SECTION 1: DATABRICKS (ADVANA / NAVY JUPITER / DATABRICKS GOVCLOUD)
# ===========================================================================
#
# On Databricks, SparkSession is pre-initialized. You do not create it —
# you get the active one. The cluster already has PySpark, pandas, numpy,
# scikit-learn, and MLflow available without any import magic.
#
# Run this in a Databricks notebook cell. The cluster must be attached.

def databricks_standard_imports():
    """
    Standard import block for Databricks notebook work.
    Paste this at the top of every new Databricks notebook.
    """
    from pyspark.sql import SparkSession
    from pyspark.sql import functions as F
    from pyspark.sql import types as T
    from pyspark.sql.window import Window
    import pandas as pd
    import numpy as np
    import mlflow
    import mlflow.sklearn
    import matplotlib.pyplot as plt
    import seaborn as sns
    from datetime import datetime, date
    import os

    # Get the active SparkSession — never create a new one on Databricks
    spark = SparkSession.getActiveSession()
    assert spark is not None, "No active SparkSession. Is a cluster attached?"

    print(f"Spark version : {spark.version}")
    print(f"MLflow version: {mlflow.__version__}")
    print(f"pandas version: {pd.__version__}")

    return spark


def databricks_read_delta_table(spark, catalog: str, schema: str, table: str):
    """
    Read a Delta table using Unity Catalog three-part naming.

    Unity Catalog format: catalog.schema.table
    Example paths on government Databricks:
        advana_catalog.procurement.contract_actions
        jupiter_catalog.silver.maintenance_work_orders

    Args:
        spark: Active SparkSession
        catalog: Unity Catalog catalog name (e.g., "jupiter_catalog")
        schema: Schema name (e.g., "silver")
        table: Table name (e.g., "maintenance_work_orders")

    Returns:
        Spark DataFrame
    """
    full_table_name = f"{catalog}.{schema}.{table}"
    df = spark.table(full_table_name)
    print(f"Loaded: {full_table_name}")
    print(f"  Schema: {len(df.columns)} columns")
    print(f"  Partitions: {df.rdd.getNumPartitions()}")
    # Avoid .count() here — it triggers a full scan. Use show() for a quick peek.
    df.show(3, truncate=False)
    return df


def databricks_secure_token_access():
    """
    Access a secret token stored in Databricks Secret Scope.

    Secret Scopes are managed through the Databricks CLI or API.
    Tokens stored here are not accessible to other users and are
    not visible in notebook output even if accidentally printed.

    Setup (run once via Databricks CLI):
        databricks secrets create-scope --scope my-project-scope
        databricks secrets put --scope my-project-scope --key api-token

    Usage in notebook:
        token = dbutils.secrets.get(scope="my-project-scope", key="api-token")
    """
    # Note: dbutils is injected by Databricks and available in notebook scope.
    # This function shows the pattern but cannot run outside a Databricks notebook.
    #
    # In a notebook, you would write:
    #   token = dbutils.secrets.get(scope="my-project-scope", key="api-token")
    #   headers = {"Authorization": f"Bearer {token}"}
    #
    # The token value is redacted in notebook output — if you print it,
    # Databricks shows "[REDACTED]". Do not try to work around this.
    pass


def databricks_mlflow_experiment_setup(experiment_name: str, run_name: str):
    """
    Set up MLflow experiment tracking for a training run.

    On Advana and Jupiter Databricks, MLflow is pre-configured to log
    to the workspace's managed MLflow tracking server. You do not need
    to set a tracking URI.

    Args:
        experiment_name: Full path including leading slash (e.g., "/Users/you/maintenance_model")
        run_name: Descriptive name for this run (e.g., "rf_baseline_v1")
    """
    import mlflow

    # Set or create the experiment
    mlflow.set_experiment(experiment_name)

    # Start a run — use as a context manager so it closes on exit even if code fails
    with mlflow.start_run(run_name=run_name) as run:
        # Log hyperparameters
        mlflow.log_param("model_type", "RandomForest")
        mlflow.log_param("n_estimators", 100)
        mlflow.log_param("max_depth", 5)
        mlflow.log_param("data_version", "silver_2024q4")

        # Your training code goes here
        # ...

        # Log metrics
        mlflow.log_metric("val_auc", 0.84)
        mlflow.log_metric("val_f1", 0.79)

        print(f"Run ID: {run.info.run_id}")
        print(f"Experiment: {experiment_name}")
        print(f"View in workspace: Experiments > {experiment_name}")


# ===========================================================================
# SECTION 2: PALANTIR FOUNDRY
# ===========================================================================
#
# Foundry has two Python contexts:
#   A. Code Workspaces — interactive VS Code IDE with SDK access
#   B. Transforms — production data pipeline functions
#
# The import patterns are different. Know which one you're in.

def foundry_code_workspace_example():
    """
    Example: Accessing a Foundry dataset from a Code Workspace.

    In Code Workspaces, you use the Foundry SDK directly.
    The environment already has foundry-sdk installed in its conda env.
    Authentication is handled via your CAC login to the workspace.
    """
    # foundry-sdk provides Dataset, Transform, and Ontology access
    from foundry import FoundryRestClient

    # In a Code Workspace, authentication is ambient (your CAC session)
    # No token needed for interactive use
    client = FoundryRestClient()

    # Read a dataset as a pandas DataFrame
    # Replace with your actual dataset path
    dataset_path = "/path/to/your/dataset"
    df = client.get_dataset_as_pandas(dataset_path)

    print(f"Dataset shape: {df.shape}")
    print(df.head())
    return df


def foundry_transform_example():
    """
    Foundry Transform pattern — the standard for production data pipelines.

    Key rules:
    1. The function signature uses @transform_df decorator
    2. Inputs and outputs are declared in the decorator, not as function args
    3. The function receives and returns Spark DataFrames
    4. Lineage tracking is automatic — every upstream dataset is recorded

    This is pseudocode — actual paths must match your Foundry enrollment.
    """
    # This shows the pattern; actual execution happens inside Foundry
    transform_code = '''
from transforms.api import transform_df, Input, Output
from pyspark.sql import functions as F

@transform_df(
    Output("/analytics/silver/maintenance_features"),
    raw=Input("/data/bronze/maintenance_work_orders"),
    ship_registry=Input("/data/reference/ship_registry"),
)
def compute_maintenance_features(raw, ship_registry):
    """
    Build silver-tier maintenance features from bronze raw data.
    Joins with ship registry to enrich with hull class and commission year.
    """
    return (
        raw
        # Drop obvious duplicates on the primary key
        .dropDuplicates(["work_order_id"])
        # Remove orders with no completion date (still open or data error)
        .filter(F.col("completion_date").isNotNull())
        # Compute days to complete
        .withColumn(
            "days_to_complete",
            F.datediff(F.col("completion_date"), F.col("start_date"))
        )
        # Drop negative values — these are data errors, not fast completions
        .filter(F.col("days_to_complete") >= 0)
        # Enrich with ship metadata
        .join(
            ship_registry.select("hull_number", "hull_class", "commission_year"),
            on="hull_number",
            how="left"
        )
    )
'''
    print("Foundry Transform pattern:")
    print(transform_code)


def foundry_r_transform_example():
    """
    R is available in Foundry Transforms through the `foundry` R package.
    This shows the equivalent R transform pattern.
    """
    r_code = '''
# Foundry Transform in R
library(foundry)
library(dplyr)
library(lubridate)

# Declare the transform using Foundry R API
transform(
  output = output("/analytics/silver/maintenance_features_r"),
  raw = input("/data/bronze/maintenance_work_orders"),
  {
    # raw is a Spark DataFrame accessible via SparkR/sparklyr
    raw_df <- collect(raw)  # convert to R data.frame for analysis

    result <- raw_df %>%
      distinct(work_order_id, .keep_all = TRUE) %>%
      filter(!is.na(completion_date)) %>%
      mutate(
        days_to_complete = as.numeric(
          difftime(completion_date, start_date, units = "days")
        )
      ) %>%
      filter(days_to_complete >= 0)

    # Return as Spark DataFrame
    to_spark(result)
  }
)
'''
    print("Foundry R Transform pattern:")
    print(r_code)


# ===========================================================================
# SECTION 3: DATABRICKS SDK (AUTOMATION AND MLOPS)
# ===========================================================================
#
# The databricks-sdk package lets you automate workspace operations from Python.
# Use this for CI/CD pipelines, job orchestration, and MLOps automation.
# NOT for interactive notebook work — that uses the native notebook environment.

def databricks_sdk_setup():
    """
    Setting up the Databricks SDK for workspace automation.

    Authentication options (in order of preference for government environments):
    1. Environment variables: DATABRICKS_HOST and DATABRICKS_TOKEN
    2. ~/.databrickscfg file (for local dev; do not commit this file)
    3. Service principal with OAuth M2M (recommended for automated pipelines)

    Install: pip install databricks-sdk
    Docs: https://databricks-sdk-py.readthedocs.io/
    """
    # Authentication via environment variables (recommended for CI/CD)
    # Set these in your pipeline secrets, not in the code
    #
    # export DATABRICKS_HOST=https://your-workspace.azuredatabricks.net
    # export DATABRICKS_TOKEN=dapi...
    #
    # Then WorkspaceClient() picks them up automatically:

    try:
        from databricks.sdk import WorkspaceClient

        # WorkspaceClient reads DATABRICKS_HOST and DATABRICKS_TOKEN from environment
        w = WorkspaceClient()

        # List active clusters
        print("Active clusters:")
        for cluster in w.clusters.list():
            if hasattr(cluster, 'state') and str(cluster.state) == "ClusterState.RUNNING":
                print(f"  {cluster.cluster_id}: {cluster.cluster_name} | DBR {cluster.spark_version}")

    except ImportError:
        print("databricks-sdk not installed. Install with: pip install databricks-sdk")
    except Exception as e:
        print(f"Could not connect: {e}")
        print("Check DATABRICKS_HOST and DATABRICKS_TOKEN environment variables")


def databricks_sdk_model_promotion(model_name: str, version: int, stage: str):
    """
    Promote a model in the MLflow Model Registry using the Databricks SDK.

    This is the kind of operation you'd run in a CI/CD pipeline after
    automated evaluation passes — not manually in a notebook.

    Args:
        model_name: Registered model name (e.g., "maintenance_failure_predictor")
        version: Model version number (integer)
        stage: Target stage — "Staging" or "Production"
    """
    import mlflow
    from mlflow.tracking import MlflowClient

    client = MlflowClient()

    # Transition the model version to the target stage
    client.transition_model_version_stage(
        name=model_name,
        version=str(version),
        stage=stage,
        archive_existing_versions=True  # archive previous Production/Staging versions
    )

    print(f"Model '{model_name}' version {version} moved to {stage}")
    print(f"Previous {stage} versions archived")


# ===========================================================================
# SECTION 4: CROSS-PLATFORM UTILITIES
# ===========================================================================

def safe_read_env_variable(key: str, required: bool = True) -> str:
    """
    Safely read an environment variable.

    Use this instead of os.environ[key] directly — it gives a clear error
    message that tells you what variable is missing and why you need it.

    Args:
        key: Environment variable name
        required: If True, raise an error when the variable is missing.
                  If False, return None when missing.

    Returns:
        The variable value, or None if not required and not set.
    """
    import os
    value = os.environ.get(key)

    if value is None and required:
        raise EnvironmentError(
            f"Required environment variable '{key}' is not set.\n"
            f"Set it in your platform's secret management:\n"
            f"  Databricks: dbutils.secrets.get(scope='...', key='{key}')\n"
            f"  Foundry: Configure in Code Workspace settings\n"
            f"  CI/CD: Set as pipeline secret, not hardcoded value"
        )

    return value


def spark_dataframe_quality_report(df, table_name: str = "unnamed") -> dict:
    """
    Generate a quick quality report for a Spark DataFrame.

    Useful for documenting bronze-tier data quality at the start of
    a project, or for checking silver-tier data before model training.

    Args:
        df: Spark DataFrame
        table_name: Descriptive name for the output

    Returns:
        dict with quality metrics (also prints a summary)
    """
    from pyspark.sql import functions as F
    import pandas as pd

    print(f"\n[Data Quality Report: {table_name}]")
    print(f"  Columns   : {len(df.columns)}")

    # Row count — triggers a Spark action
    n_rows = df.count()
    print(f"  Row count : {n_rows:,}")

    # Null rates per column — one Spark pass
    null_exprs = [
        (F.sum(F.col(c).isNull().cast("int")) / F.lit(n_rows) * 100).alias(c)
        for c in df.columns
    ]
    null_rates = df.select(null_exprs).toPandas().T
    null_rates.columns = ["null_pct"]
    null_rates["null_pct"] = null_rates["null_pct"].round(1)

    # Report columns with significant nulls
    high_null = null_rates[null_rates["null_pct"] > 5.0]
    if len(high_null) > 0:
        print(f"\n  Columns with >5% nulls ({len(high_null)} of {len(df.columns)}):")
        for col_name, row in high_null.sort_values("null_pct", ascending=False).iterrows():
            print(f"    {col_name:<40} {row['null_pct']:.1f}%")
    else:
        print(f"\n  All columns have <5% nulls")

    return {
        "table_name": table_name,
        "n_rows": n_rows,
        "n_cols": len(df.columns),
        "null_rates": null_rates["null_pct"].to_dict(),
    }


# ===========================================================================
# SECTION 5: AUTHENTICATION ANTI-PATTERNS (DO NOT DO THESE)
# ===========================================================================

# The examples below show what NOT to do.
# They are commented out precisely because they are wrong.

# WRONG — hardcoded token in source code
# token = "dapi1234567890abcdef"  # This token is now compromised.
# headers = {"Authorization": f"Bearer {token}"}

# WRONG — reading from a local file you forgot to exclude from git
# with open("~/.my_platform_token") as f:
#     token = f.read().strip()  # Will fail on the platform. Will leak on your laptop.

# WRONG — printing the token for "debugging"
# print(f"Using token: {token}")  # This will appear in notebook output and logs.

# RIGHT — use platform secret management
# On Databricks:
#   token = dbutils.secrets.get(scope="project-scope", key="platform-token")
#
# In environment variables (for SDK/automation use):
#   token = safe_read_env_variable("PLATFORM_TOKEN")
#
# In Foundry Code Workspaces:
#   Configure secrets in the workspace settings; access via environment


if __name__ == "__main__":
    print("Platform-Specific Import Patterns")
    print("This file is a reference — import individual functions as needed.")
    print("")
    print("Available functions:")
    print("  databricks_standard_imports()         - Standard notebook imports")
    print("  databricks_read_delta_table()         - Read a Unity Catalog table")
    print("  databricks_mlflow_experiment_setup()  - MLflow tracking setup")
    print("  foundry_transform_example()           - Foundry Transform pattern")
    print("  databricks_sdk_setup()                - Workspace automation SDK")
    print("  spark_dataframe_quality_report()      - Quick data quality check")
    print("  safe_read_env_variable()              - Secure config reading")
