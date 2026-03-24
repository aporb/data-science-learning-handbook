"""
Chapter 09: MLOps and Production Pipelines
Example 03: Pipeline Orchestration, Feature Stores, and Model Monitoring

This example covers:
- Databricks Feature Store: creating and using feature tables
- End-to-end MLOps pipeline orchestration with Databricks Workflows (config)
- Model monitoring with evidently and drift alerting
- Prometheus metrics for model observability

Platform: Databricks (Advana / GovCloud workspace)
"""

import json
import logging
from datetime import datetime, timedelta
from typing import Optional

import numpy as np
import pandas as pd

# Databricks Feature Store — available in Databricks Runtime ML
# In a GovCloud Databricks workspace, import as:
#   from databricks.feature_store import FeatureStoreClient
# Wrapped for local dev compatibility
try:
    from databricks.feature_store import FeatureStoreClient, FeatureLookup
    DATABRICKS_FS_AVAILABLE = True
except ImportError:
    DATABRICKS_FS_AVAILABLE = False

# evidently for drift detection — install with: pip install evidently
try:
    from evidently.report import Report
    from evidently.metric_preset import DataDriftPreset
    from evidently.metrics import DatasetDriftMetric, ColumnDriftMetric
    EVIDENTLY_AVAILABLE = True
except ImportError:
    EVIDENTLY_AVAILABLE = False

# prometheus_client for metrics exposure — install with: pip install prometheus_client
try:
    from prometheus_client import Gauge, Counter, start_http_server, CollectorRegistry
    PROMETHEUS_AVAILABLE = True
except ImportError:
    PROMETHEUS_AVAILABLE = False

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Part A: Databricks Feature Store
#
# The Feature Store centralizes feature computation so multiple models share
# the same feature logic. A feature computed for the maintenance priority
# classifier should be identical to the same feature used in a maintenance
# scheduling optimizer — same code, same output.
# ---------------------------------------------------------------------------

FEATURE_TABLE_NAME = "navy_logistics.maintenance.vessel_maintenance_features"


def create_vessel_maintenance_feature_table(spark) -> None:
    """
    Create a Feature Store table for vessel maintenance features.

    In production on Databricks, this runs once (table creation) and then
    the feature computation pipeline runs on a schedule to refresh the table.

    The primary key is vessel_id — feature lookups join on this key when
    creating training datasets or running inference.
    """
    if not DATABRICKS_FS_AVAILABLE:
        logger.warning("Databricks Feature Store not available. Skipping table creation.")
        return

    fs = FeatureStoreClient()

    # Define the feature table schema
    # This schema describes one row per vessel: aggregated maintenance features
    # computed from the full maintenance event history for that vessel.
    feature_table_schema = {
        "vessel_id": "string",          # Primary key
        "avg_days_between_service": "double",
        "rolling_90d_work_order_count": "integer",
        "critical_event_rate_12m": "double",
        "mean_equipment_age_years": "double",
        "parts_backorder_rate_30d": "double",
        "crew_certification_coverage": "double",
        "last_updated": "timestamp",
    }

    try:
        fs.create_table(
            name=FEATURE_TABLE_NAME,
            primary_keys=["vessel_id"],
            schema=spark.createDataFrame([], _build_spark_schema(feature_table_schema)).schema,
            description=(
                "Aggregated maintenance features for Navy vessels. "
                "Primary key: vessel_id. "
                "Refreshed daily from the maintenance event history table. "
                "Source: Navy Maintenance Management System (NMMS) via Advana ingestion pipeline."
            ),
        )
        logger.info(f"Created feature table: {FEATURE_TABLE_NAME}")
    except Exception as e:
        if "already exists" in str(e).lower():
            logger.info(f"Feature table already exists: {FEATURE_TABLE_NAME}")
        else:
            raise


def _build_spark_schema(schema_dict: dict):
    """Build a PySpark schema from a simple type dictionary."""
    from pyspark.sql.types import (
        StructType, StructField, StringType, DoubleType, IntegerType, TimestampType
    )
    type_map = {
        "string": StringType(),
        "double": DoubleType(),
        "integer": IntegerType(),
        "timestamp": TimestampType(),
    }
    fields = [
        StructField(name, type_map[dtype], True)
        for name, dtype in schema_dict.items()
    ]
    return StructType(fields)


def write_features_to_store(spark, df_features: pd.DataFrame) -> None:
    """
    Write computed features to the Feature Store table.

    This function is called by the scheduled feature refresh pipeline.
    The Feature Store handles Delta Lake writes, schema validation,
    and update/insert (upsert) semantics.
    """
    if not DATABRICKS_FS_AVAILABLE:
        logger.warning("Feature Store not available. Features not written.")
        return

    fs = FeatureStoreClient()
    df_spark = spark.createDataFrame(df_features)

    fs.write_table(
        name=FEATURE_TABLE_NAME,
        df=df_spark,
        mode="merge",  # Upsert: update existing rows, insert new ones
    )
    logger.info(f"Wrote {len(df_features):,} feature rows to {FEATURE_TABLE_NAME}")


def create_training_dataset_with_feature_lookup(
    spark,
    df_labels: pd.DataFrame,
    feature_table_name: str,
) -> pd.DataFrame:
    """
    Create a training dataset by joining labels with features from the Feature Store.

    This is the correct way to create training data when using the Feature Store.
    The FeatureLookup handles point-in-time joins automatically, preventing
    label leakage — a subtle but critical data science error where future
    information contaminates the training set.

    Parameters
    ----------
    df_labels : pd.DataFrame
        Label dataset with 'vessel_id', 'event_date', and 'priority_class'.
    feature_table_name : str
        Name of the Feature Store table to look up features from.
    """
    if not DATABRICKS_FS_AVAILABLE:
        logger.warning("Feature Store not available. Returning labels only.")
        return df_labels

    fs = FeatureStoreClient()

    feature_lookups = [
        FeatureLookup(
            table_name=feature_table_name,
            feature_names=[
                "avg_days_between_service",
                "rolling_90d_work_order_count",
                "critical_event_rate_12m",
                "mean_equipment_age_years",
                "parts_backorder_rate_30d",
                "crew_certification_coverage",
            ],
            lookup_key="vessel_id",
            # timestamp_lookup_key="event_date" enables point-in-time lookup:
            # features are joined as of the event_date, not as of today.
            # This prevents the training set from containing features
            # that were not available at the time of the label event.
            timestamp_lookup_key="event_date",
        )
    ]

    training_set = fs.create_training_set(
        df=spark.createDataFrame(df_labels),
        feature_lookups=feature_lookups,
        label="priority_class",
        exclude_columns=["vessel_id", "event_date"],
    )

    return training_set.load_df().toPandas()


# ---------------------------------------------------------------------------
# Part B: Drift Monitoring with evidently
# ---------------------------------------------------------------------------

def compute_drift_report(
    reference_df: pd.DataFrame,
    production_df: pd.DataFrame,
    feature_cols: list[str],
    output_path: str = "/tmp/drift_report.html",
) -> dict:
    """
    Generate an evidently drift report comparing production data against
    the training baseline.

    Returns a summary dict with drift status and per-feature drift flags.
    The HTML report is written to output_path for human review.

    Parameters
    ----------
    reference_df : pd.DataFrame
        Training data baseline (or a representative historical window).
    production_df : pd.DataFrame
        Recent production inference data to compare against baseline.
    feature_cols : list[str]
        Feature columns to include in the drift analysis.
    output_path : str
        Path to write the HTML drift report.
    """
    if not EVIDENTLY_AVAILABLE:
        logger.warning("evidently not installed. Install with: pip install evidently")
        return {"error": "evidently not available", "drift_detected": None}

    ref = reference_df[feature_cols]
    prod = production_df[feature_cols]

    report = Report(metrics=[
        DataDriftPreset(),
        DatasetDriftMetric(),
        # Per-feature drift for the most operationally important features
        ColumnDriftMetric(column_name="failure_code_severity"),
        ColumnDriftMetric(column_name="work_order_type"),
        ColumnDriftMetric(column_name="parts_availability_score"),
    ])

    report.run(reference_data=ref, current_data=prod)
    report.save_html(output_path)
    logger.info(f"Drift report written to {output_path}")

    result = report.as_dict()

    # Extract summary from the report dict
    dataset_drift_result = next(
        (m["result"] for m in result["metrics"]
         if m["metric"] == "DatasetDriftMetric"),
        {}
    )

    drift_detected = dataset_drift_result.get("dataset_drift", False)
    drifted_feature_count = dataset_drift_result.get("number_of_drifted_columns", 0)
    total_features = dataset_drift_result.get("number_of_columns", len(feature_cols))
    drift_share = drifted_feature_count / total_features if total_features > 0 else 0.0

    summary = {
        "drift_detected": drift_detected,
        "drifted_feature_count": drifted_feature_count,
        "total_features": total_features,
        "drift_share": drift_share,
        "report_path": output_path,
        "timestamp": datetime.utcnow().isoformat(),
    }

    logger.info(
        f"Drift summary: detected={drift_detected}, "
        f"features_drifted={drifted_feature_count}/{total_features} "
        f"({drift_share:.0%})"
    )
    return summary


def run_monitoring_pipeline(
    spark,
    training_data_table: str,
    inference_log_table: str,
    lookback_days: int = 7,
    drift_threshold: float = 0.25,
) -> dict:
    """
    Production monitoring pipeline that runs on a daily schedule.

    Compares recent inference data against training baseline to detect drift.
    Writes the drift summary to a monitoring table for historical tracking.
    Triggers an alert if drift exceeds the threshold.

    In Databricks Workflows, this function is called as a task in the
    monitoring job, scheduled independently of the retraining pipeline.
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

    # Load reference data (training baseline)
    # In production: spark.table(training_data_table)
    # For the demo: generate synthetic reference data
    logger.info("Loading training baseline for drift comparison...")
    np.random.seed(42)
    n_ref = 5000
    reference_df = pd.DataFrame({
        "equipment_age_years": np.random.exponential(5, n_ref).clip(0.5, 30),
        "days_since_last_service": np.random.exponential(60, n_ref).clip(1, 500),
        "failure_code_severity": np.random.choice([1,2,3,4,5], n_ref, p=[0.35,0.25,0.2,0.12,0.08]),
        "parts_availability_score": np.random.beta(5, 2, n_ref),
        "crew_qualification_level": np.random.normal(3.2, 0.8, n_ref).clip(1, 5),
        "work_order_type": np.random.choice([0,1,2], n_ref, p=[0.5,0.35,0.15]),
        "historical_completion_rate": np.random.beta(7, 2, n_ref),
    })

    # Load recent inference data — represents 7 days of production traffic
    # In production: query the inference log table with a date filter:
    # cutoff = (datetime.now() - timedelta(days=lookback_days)).strftime("%Y-%m-%d")
    # production_df = spark.table(inference_log_table).filter(f"inference_date >= '{cutoff}'")
    logger.info(f"Loading last {lookback_days} days of inference data...")
    n_prod = 800

    # Simulate mild drift: failure_code_severity shifts toward higher values
    # and work_order_type sees more emergency orders (type 2)
    # This represents a real scenario: operational tempo increases, more failures
    production_df = pd.DataFrame({
        "equipment_age_years": np.random.exponential(5.5, n_prod).clip(0.5, 30),  # slightly older
        "days_since_last_service": np.random.exponential(55, n_prod).clip(1, 500),
        "failure_code_severity": np.random.choice([1,2,3,4,5], n_prod, p=[0.20,0.20,0.22,0.20,0.18]),  # drifted
        "parts_availability_score": np.random.beta(4, 2, n_prod),  # parts getting scarcer
        "crew_qualification_level": np.random.normal(3.0, 0.9, n_prod).clip(1, 5),
        "work_order_type": np.random.choice([0,1,2], n_prod, p=[0.40,0.35,0.25]),  # more emergencies
        "historical_completion_rate": np.random.beta(6, 2, n_prod),
    })

    # Compute drift report
    drift_summary = compute_drift_report(
        reference_df=reference_df,
        production_df=production_df,
        feature_cols=feature_cols,
    )

    # Trigger alert if drift exceeds threshold
    if drift_summary.get("drift_detected") and drift_summary.get("drift_share", 0) > drift_threshold:
        alert_message = (
            f"DRIFT ALERT: {drift_summary['drifted_feature_count']} of "
            f"{drift_summary['total_features']} features are drifting "
            f"({drift_summary['drift_share']:.0%}). "
            f"Review drift report and consider retraining."
        )
        logger.warning(alert_message)
        # In production: trigger a Databricks notification, send to Slack/Teams,
        # or write to an alert table that a Databricks SQL alert query monitors.
        drift_summary["alert_triggered"] = True
        drift_summary["alert_message"] = alert_message
    else:
        drift_summary["alert_triggered"] = False

    return drift_summary


# ---------------------------------------------------------------------------
# Part C: Prometheus Metrics for Model Monitoring
# ---------------------------------------------------------------------------

def setup_model_metrics(registry=None) -> dict:
    """
    Set up Prometheus metric objects for model observability.

    These metrics are updated by the model serving code and the monitoring
    pipeline. Prometheus scrapes them at the configured interval, and Grafana
    renders them in dashboards alongside infrastructure metrics.

    In Databricks, the monitoring job writes to a Prometheus push gateway.
    In Kubernetes-based deployments, the model server exposes these directly.
    """
    if not PROMETHEUS_AVAILABLE:
        logger.warning("prometheus_client not installed. Install with: pip install prometheus_client")
        return {}

    reg = registry or CollectorRegistry()

    metrics = {
        "model_accuracy": Gauge(
            "ml_model_accuracy",
            "Current model accuracy on recent evaluation window",
            ["model_name", "model_version", "environment"],
            registry=reg,
        ),
        "predictions_total": Counter(
            "ml_predictions_total",
            "Total number of predictions served",
            ["model_name", "model_version", "priority_class"],
            registry=reg,
        ),
        "feature_drift_score": Gauge(
            "ml_feature_drift_score",
            "Per-feature drift score vs. training baseline (0=no drift, 1=max drift)",
            ["model_name", "feature_name"],
            registry=reg,
        ),
        "dataset_drift_share": Gauge(
            "ml_dataset_drift_share",
            "Fraction of features currently drifting",
            ["model_name"],
            registry=reg,
        ),
        "inference_latency_ms": Gauge(
            "ml_inference_latency_ms",
            "Model inference latency in milliseconds (p50/p95/p99)",
            ["model_name", "percentile"],
            registry=reg,
        ),
    }

    return metrics


def update_model_metrics(
    metrics: dict,
    model_name: str,
    model_version: str,
    accuracy: float,
    drift_summary: dict,
    prediction_counts: dict[str, int],
) -> None:
    """
    Update Prometheus metric gauges from monitoring pipeline outputs.

    In production, this runs as the final step of the daily monitoring job.
    The push gateway URL is configured in your Databricks cluster environment.
    """
    if not metrics or not PROMETHEUS_AVAILABLE:
        return

    env = "production"

    metrics["model_accuracy"].labels(
        model_name=model_name,
        model_version=model_version,
        environment=env,
    ).set(accuracy)

    for priority_class, count in prediction_counts.items():
        metrics["predictions_total"].labels(
            model_name=model_name,
            model_version=model_version,
            priority_class=priority_class,
        ).inc(count)

    if "drift_share" in drift_summary:
        metrics["dataset_drift_share"].labels(
            model_name=model_name,
        ).set(drift_summary["drift_share"])

    logger.info(f"Prometheus metrics updated for {model_name} v{model_version}")


def push_metrics_to_gateway(registry, gateway_url: str, job_name: str) -> None:
    """
    Push metrics to a Prometheus push gateway from a batch monitoring job.

    Use this pattern when running monitoring as a Databricks Workflow task
    rather than a long-running server. The push gateway stores the most
    recent values until the next push or until the retention window expires.
    """
    if not PROMETHEUS_AVAILABLE:
        return
    from prometheus_client import push_to_gateway
    push_to_gateway(gateway_url, job=job_name, registry=registry)
    logger.info(f"Pushed metrics to Prometheus gateway: {gateway_url}")


# ---------------------------------------------------------------------------
# Part D: Databricks Workflows Configuration
#
# This section shows the structure of a Databricks Workflows job for the
# complete MLOps pipeline. In practice, you configure this via the Databricks
# SDK (databricks-sdk Python package) or the Workflows UI.
# ---------------------------------------------------------------------------

DATABRICKS_WORKFLOW_CONFIG = {
    "name": "navy_maintenance_mlops_pipeline",
    "schedule": {
        "quartz_cron_expression": "0 0 2 * * ?",  # Daily at 2 AM UTC
        "timezone_id": "America/New_York",
        "pause_status": "UNPAUSED",
    },
    "email_notifications": {
        "on_failure": ["ml-ops-oncall@agency.mil"],
        "on_success": [],
    },
    "tasks": [
        {
            "task_key": "feature_refresh",
            "description": "Recompute vessel maintenance features from source tables",
            "notebook_task": {
                "notebook_path": "/Repos/mlops/navy_maintenance/01_feature_refresh",
                "base_parameters": {
                    "lookback_days": "30",
                    "feature_table": FEATURE_TABLE_NAME,
                },
            },
            "job_cluster_key": "feature_compute_cluster",
            "timeout_seconds": 3600,
            "max_retries": 2,
            "retry_on_timeout": True,
        },
        {
            "task_key": "drift_monitoring",
            "description": "Compare recent inference data against training baseline",
            "depends_on": [{"task_key": "feature_refresh"}],
            "notebook_task": {
                "notebook_path": "/Repos/mlops/navy_maintenance/03_monitoring",
                "base_parameters": {
                    "lookback_days": "7",
                    "drift_threshold": "0.25",
                },
            },
            "job_cluster_key": "monitoring_cluster",
            "timeout_seconds": 1800,
            "max_retries": 1,
        },
        {
            "task_key": "weekly_retraining",
            "description": "Retrain model on latest features (runs weekly on Sundays)",
            "depends_on": [{"task_key": "feature_refresh"}],
            "notebook_task": {
                "notebook_path": "/Repos/mlops/navy_maintenance/02_training",
                "base_parameters": {
                    "register_model": "true",
                    "promote_to_staging": "true",
                },
            },
            "job_cluster_key": "training_cluster",
            "timeout_seconds": 7200,
            "max_retries": 1,
            # This task runs only on Sundays — the feature_refresh runs daily
            # but retraining is weekly. Use run_if to conditionally skip tasks.
            "run_if": "AT_LEAST_ONE_SUCCESS",
        },
    ],
    "job_clusters": [
        {
            "job_cluster_key": "feature_compute_cluster",
            "new_cluster": {
                "spark_version": "15.4.x-scala2.12",  # Databricks Runtime (non-ML)
                "node_type_id": "i3.xlarge",
                "num_workers": 4,
                "aws_attributes": {"zone_id": "us-gov-west-1a"},
                "spark_conf": {
                    "spark.databricks.delta.preview.enabled": "true",
                },
            },
        },
        {
            "job_cluster_key": "training_cluster",
            "new_cluster": {
                "spark_version": "15.4.x-ml-scala2.12",  # Databricks Runtime ML for MLflow
                "node_type_id": "m5.2xlarge",
                "num_workers": 2,
                "aws_attributes": {"zone_id": "us-gov-west-1a"},
            },
        },
        {
            "job_cluster_key": "monitoring_cluster",
            "new_cluster": {
                "spark_version": "15.4.x-scala2.12",
                "node_type_id": "m5.xlarge",
                "num_workers": 1,
                "aws_attributes": {"zone_id": "us-gov-west-1a"},
            },
        },
    ],
    "tags": {
        "program": "navy_logistics_maintenance",
        "environment": "production",
        "classification": "unclassified_cui",
        "contract": "N00024-25-C-XXXX",
    },
}


def create_workflow_via_sdk(config: dict) -> None:
    """
    Create or update a Databricks Workflow using the Databricks SDK.

    In CI/CD pipelines, this function is called when the workflow
    configuration changes (stored in version control as JSON/YAML).
    This ensures the production workflow stays synchronized with the
    repository rather than being manually configured in the UI.

    Requires: pip install databricks-sdk
    """
    try:
        from databricks.sdk import WorkspaceClient

        # The SDK reads DATABRICKS_HOST and DATABRICKS_TOKEN from environment
        w = WorkspaceClient()

        # Check if the job already exists
        existing_jobs = list(w.jobs.list(name=config["name"]))

        if existing_jobs:
            job_id = existing_jobs[0].job_id
            w.jobs.reset(job_id=job_id, new_settings=config)
            logger.info(f"Updated workflow '{config['name']}' (job_id={job_id})")
        else:
            created = w.jobs.create(**config)
            logger.info(f"Created workflow '{config['name']}' (job_id={created.job_id})")

    except ImportError:
        logger.info("Databricks SDK not available. Showing workflow config:")
        logger.info(json.dumps(config, indent=2))
    except Exception as e:
        logger.error(f"Failed to create workflow: {e}")
        logger.info("Workflow config:")
        logger.info(json.dumps(config, indent=2))


# ---------------------------------------------------------------------------
# Main demonstration
# ---------------------------------------------------------------------------

def main():
    print("=" * 70)
    print("PIPELINE ORCHESTRATION DEMO")
    print("Chapter 09: MLOps and Production Pipelines")
    print("=" * 70)

    # --- Feature store demo (local simulation) ---
    print("\n[1] Feature Store Pattern")
    print("Feature table name:", FEATURE_TABLE_NAME)
    print("Primary key: vessel_id")
    print("In Databricks: FeatureStoreClient().write_table() handles Delta upserts")
    print("Training dataset creation uses point-in-time joins to prevent label leakage")

    if not DATABRICKS_FS_AVAILABLE:
        print("(Databricks Feature Store requires a Databricks workspace environment)")

    # --- Drift monitoring demo ---
    print("\n[2] Running Drift Monitoring Pipeline...")
    drift_summary = run_monitoring_pipeline(
        spark=None,
        training_data_table="navy_logistics.maintenance.training_features_v3",
        inference_log_table="navy_logistics.maintenance.inference_log",
        lookback_days=7,
        drift_threshold=0.25,
    )

    print(f"\nDrift monitoring result:")
    print(f"  Drift detected: {drift_summary.get('drift_detected')}")
    print(f"  Features drifted: {drift_summary.get('drifted_feature_count')}/{drift_summary.get('total_features')}")
    print(f"  Drift share: {drift_summary.get('drift_share', 0):.0%}")
    print(f"  Alert triggered: {drift_summary.get('alert_triggered')}")
    if drift_summary.get("alert_triggered"):
        print(f"  Alert: {drift_summary.get('alert_message')}")

    # --- Prometheus metrics demo ---
    print("\n[3] Prometheus Metrics Setup")
    if PROMETHEUS_AVAILABLE:
        registry = CollectorRegistry()
        metrics = setup_model_metrics(registry=registry)
        update_model_metrics(
            metrics=metrics,
            model_name="navy_logistics.maintenance.priority_classifier",
            model_version="7",
            accuracy=0.912,
            drift_summary=drift_summary,
            prediction_counts={"standard": 420, "elevated": 290, "critical": 90},
        )
        print("Metrics updated. In production, push to Prometheus gateway:")
        print("  push_metrics_to_gateway(registry, 'https://prometheus.agency.mil', 'ml_monitoring')")
    else:
        print("Install prometheus_client: pip install prometheus_client")

    # --- Databricks Workflows config ---
    print("\n[4] Databricks Workflows Configuration")
    print("Workflow name:", DATABRICKS_WORKFLOW_CONFIG["name"])
    print("Schedule:", DATABRICKS_WORKFLOW_CONFIG["schedule"]["quartz_cron_expression"])
    print("Tasks:", [t["task_key"] for t in DATABRICKS_WORKFLOW_CONFIG["tasks"]])
    print("\nTo deploy this workflow, call create_workflow_via_sdk(DATABRICKS_WORKFLOW_CONFIG)")
    print("(Requires DATABRICKS_HOST and DATABRICKS_TOKEN environment variables)")

    print("\n" + "=" * 70)
    print("See README.md for Palantir Pipeline Builder scheduling patterns")
    print("and the Palantir Foundry deployment workflow.")
    print("=" * 70)


if __name__ == "__main__":
    main()
