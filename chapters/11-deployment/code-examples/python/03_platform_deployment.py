"""
Chapter 11: Deployment & Scaling
Code Examples: Platform-Specific Deployment Patterns

This module covers deployment and monitoring on each of the five federal platforms:
  1. Databricks Model Serving — endpoint lifecycle, A/B traffic, cost monitoring
  2. Palantir Foundry — model registry, AIP Logic, live deployment, Ontology-backed scoring
  3. Qlik SSE — gRPC server for embedding model scoring in Qlik dashboards
  4. Advana / Navy Jupiter — batch scoring on the shared Spark environment
  5. Model drift monitoring — production health checks that apply to all platforms

Each section is self-contained. Sections with platform-specific imports
gracefully degrade to descriptive output if the SDK is not installed.

Platform targets: Databricks (FedRAMP High/IL5), Palantir Foundry (FedRAMP High/IL5),
                  Qlik (FedRAMP Moderate/IL4), Advana/Jupiter (IL2-IL5 by classification)
"""

import json
import os
import time
from datetime import datetime, timedelta, timezone
from typing import Any

import numpy as np
import pandas as pd
from scipy import stats

# ---------------------------------------------------------------------------
# Section 1: Databricks — Endpoint Lifecycle and Cost Management
# ---------------------------------------------------------------------------
# Databricks charges for Model Serving by the compute-second. An always-on
# "Small" endpoint runs ~$200-350/month depending on region and cloud.
# For a program with 10 models, that's $2,000-3,500/month in serving costs —
# before any training or notebook compute.
#
# Two patterns to control this:
# 1. Scale-to-zero for non-real-time workloads (accept cold start latency)
# 2. A/B traffic splitting to route a percentage of traffic to a cheaper model
#    variant while validating the new version
#
# Cost tracking matters for ATO budgeting. IL5 GovCloud has different pricing
# from commercial AWS/Azure, and programs need to report compute costs quarterly.


def manage_databricks_endpoint_lifecycle(
    endpoint_name: str,
    workspace_host: str | None = None,
    workspace_token: str | None = None,
) -> dict[str, Any]:
    """
    Full endpoint lifecycle management: create, update, monitor, cost estimate.

    This uses the databricks-sdk (pip install databricks-sdk).
    In a Databricks notebook you can also use the REST API directly.
    """
    host = workspace_host or os.environ.get("DATABRICKS_HOST", "https://adb-example.azuredatabricks.net")
    token = workspace_token or os.environ.get("DATABRICKS_TOKEN", "demo-token")

    try:
        from databricks.sdk import WorkspaceClient
        from databricks.sdk.service.serving import (
            EndpointCoreConfigInput,
            ServedModelInput,
            ServedModelInputWorkloadSize,
            TrafficConfig,
            Route,
        )

        w = WorkspaceClient(host=host, token=token)

        # Check if endpoint already exists
        try:
            existing = w.serving_endpoints.get(endpoint_name)
            print(f"Endpoint exists: {endpoint_name} (state: {existing.state.config_update})")
            return {"action": "found", "endpoint": endpoint_name}
        except Exception:
            pass

        # Create with scale-to-zero for budget control
        config = EndpointCoreConfigInput(
            served_models=[
                ServedModelInput(
                    model_name="gov_analytics.don_maintenance.maintenance_risk_v1",
                    model_version="2",
                    workload_size=ServedModelInputWorkloadSize.SMALL,
                    scale_to_zero_enabled=True,
                )
            ],
            traffic_config=TrafficConfig(
                routes=[Route(
                    served_model_name="maintenance_risk_v1-2",
                    traffic_percentage=100,
                )]
            ),
        )

        endpoint = w.serving_endpoints.create_and_wait(
            name=endpoint_name, config=config
        )
        print(f"Created endpoint: {endpoint_name}")
        return {"action": "created", "endpoint": endpoint_name}

    except ImportError:
        print("databricks-sdk not installed — showing endpoint configuration:")
        config_preview = {
            "name": endpoint_name,
            "config": {
                "served_models": [{
                    "model_name": "gov_analytics.don_maintenance.maintenance_risk_v1",
                    "model_version": "2",
                    "workload_size": "Small",
                    "scale_to_zero_enabled": True,
                }]
            }
        }
        print(json.dumps(config_preview, indent=2))
        return {"action": "preview", "config": config_preview}


def estimate_serving_endpoint_cost(
    workload_size: str = "Small",
    scale_to_zero: bool = True,
    avg_requests_per_hour: float = 50.0,
    avg_request_duration_ms: float = 50.0,
    operational_hours_per_day: float = 10.0,
) -> dict[str, float]:
    """
    Rough monthly cost estimate for a Databricks Model Serving endpoint.

    Pricing is approximate — actual GovCloud pricing differs from commercial.
    Use this for budgeting conversations, not invoicing. Always confirm with
    your cloud program office for FedRAMP/IL5 actual rates.

    For IL5 Azure Government: multiply commercial rate by ~1.1-1.3x.
    """
    # Approximate DBU (Databricks Unit) rates per workload size
    # These are ballpark commercial numbers — IL5 rates will differ
    dbu_per_hour = {"Small": 4.0, "Medium": 8.0, "Large": 16.0}.get(workload_size, 4.0)
    dbu_cost_usd = 0.10  # approximate commercial $/DBU — IL5 ~$0.12-0.14

    if scale_to_zero:
        # Scale-to-zero: pay only for active request processing + scale-up time
        # Approximate: each request costs ~50ms of compute
        requests_per_day = avg_requests_per_hour * operational_hours_per_day
        active_seconds_per_day = (requests_per_day * avg_request_duration_ms) / 1000
        # Add cold start overhead: ~60s warm-up once per day
        active_seconds_per_day += 60
        active_hours_per_day = active_seconds_per_day / 3600
        monthly_dbu = dbu_per_hour * active_hours_per_day * 30
    else:
        # Always-on: pay for full runtime regardless of traffic
        monthly_dbu = dbu_per_hour * 24 * 30

    monthly_cost = monthly_dbu * dbu_cost_usd
    annual_cost = monthly_cost * 12

    result = {
        "workload_size": workload_size,
        "scale_to_zero": scale_to_zero,
        "avg_requests_per_hour": avg_requests_per_hour,
        "estimated_monthly_dbu": round(monthly_dbu, 1),
        "estimated_monthly_cost_usd": round(monthly_cost, 2),
        "estimated_annual_cost_usd": round(annual_cost, 2),
    }

    print(f"Endpoint cost estimate ({workload_size}, scale_to_zero={scale_to_zero}):")
    print(f"  Monthly: ~${monthly_cost:.0f} USD")
    print(f"  Annual:  ~${annual_cost:.0f} USD")
    if scale_to_zero and avg_requests_per_hour < 10:
        print("  Note: Very low traffic — scale-to-zero is highly recommended.")

    return result


def configure_ab_traffic_split(
    endpoint_name: str,
    stable_model_version: str,
    candidate_model_version: str,
    candidate_traffic_pct: int = 10,
) -> dict:
    """
    Configure A/B traffic split between two model versions on a Databricks endpoint.

    Use this pattern when you want to validate a new model version on real traffic
    before fully promoting it. The ops team sees both versions' metrics side-by-side
    in Databricks endpoint monitoring.

    This is the Databricks equivalent of Kubernetes canary deployment, but managed
    entirely within the Databricks control plane — no Kubernetes required.
    """
    if candidate_traffic_pct > 30:
        raise ValueError(
            f"Candidate traffic {candidate_traffic_pct}% exceeds 30% safety limit. "
            "Start with 5-10% and increase after validating metrics."
        )

    config = {
        "name": endpoint_name,
        "config": {
            "served_models": [
                {
                    "name": f"{endpoint_name}-stable",
                    "model_version": stable_model_version,
                    "workload_size": "Small",
                    "scale_to_zero_enabled": False,  # Always-on for production traffic
                },
                {
                    "name": f"{endpoint_name}-candidate",
                    "model_version": candidate_model_version,
                    "workload_size": "Small",
                    "scale_to_zero_enabled": False,
                },
            ],
            "traffic_config": {
                "routes": [
                    {
                        "served_model_name": f"{endpoint_name}-stable",
                        "traffic_percentage": 100 - candidate_traffic_pct,
                    },
                    {
                        "served_model_name": f"{endpoint_name}-candidate",
                        "traffic_percentage": candidate_traffic_pct,
                    },
                ]
            },
        },
    }

    print(f"A/B split configured: {100 - candidate_traffic_pct}% stable / {candidate_traffic_pct}% candidate")
    return config


# ---------------------------------------------------------------------------
# Section 2: Palantir Foundry — Live Deployment and Ontology-Backed Scoring
# ---------------------------------------------------------------------------
# Palantir Foundry has two deployment modes for ML models:
#
# 1. **Batch pipeline** (@transform): Run on a schedule or when upstream data changes.
#    Good for nightly scoring of large datasets.
#
# 2. **Live deployment** (AIP Logic / Ontology Action): Run in real-time when a user
#    triggers an Action in Workshop or AIP Agent. The model is invoked synchronously
#    as part of the Action's execution.
#
# The Ontology integration is what makes Foundry different from other platforms.
# In Foundry, your model doesn't just score a row of data — it scores an Object
# (a ShipHull, a ContractAction, a WorkOrder) with all its linked Objects available.
# This means the feature pipeline can pull data from multiple linked Object Types
# automatically, rather than you assembling a feature matrix manually.


FOUNDRY_TRANSFORM_EXAMPLE = '''
# Foundry Code Repository — transforms/score_maintenance_risk.py
# Runs nightly or on upstream data change.
# This is pseudocode for Foundry's execution environment.

from transforms.api import transform, Input, Output
from palantir_models.transforms import ModelInput
from pyspark.sql import functions as F


@transform(
    output=Output("/don-data/maintenance/risk_scores"),
    work_orders=Input("/don-data/maintenance/work_orders_current"),
    hulls=Input("/don-data/ships/hull_registry"),
    model=ModelInput("/models/maintenance_risk_v2"),
)
def compute_risk_scores(output, work_orders, hulls, model):
    """
    Score all active work orders for maintenance failure risk.

    Foundry automatically tracks data lineage here:
    - Which version of work_orders_current produced these scores?
    - Which model version was used?
    All of this is queryable in the Foundry lineage graph without any
    additional logging code.
    """
    df = work_orders.dataframe()
    hull_df = hulls.dataframe().select("hull_id", "hull_age_years", "hull_class")

    # Join with hull registry to enrich features
    enriched = df.join(hull_df, on="hull_id", how="left")

    # Filter to active work orders only
    active = enriched.filter(F.col("status") == "ACTIVE")

    # Model scoring — Foundry's ModelInput handles feature extraction
    scored = model.transform(
        active,
        input_columns=[
            "days_since_last_maintenance",
            "hull_age_years",
            "operational_hours_30d",
            "deficiency_count_ytd",
            "fy_quarter",
        ],
        output_column="failure_probability",
    )

    result = scored.withColumn(
        "risk_tier",
        F.when(F.col("failure_probability") < 0.20, "LOW")
         .when(F.col("failure_probability") < 0.55, "MEDIUM")
         .otherwise("HIGH")
    ).withColumn("scored_date", F.current_date())

    output.write_dataframe(result)
'''


FOUNDRY_AIP_LOGIC_EXAMPLE = '''
# Foundry AIP Logic — live scoring when a maintenance officer submits a work order
# This function runs inside Foundry's AIP Logic runtime, not in standard Python.
# It's invoked by a Workshop Action or an AIP Agent.

from aip_logic import action, inputs, outputs
from palantir_models import ModelClient


@action(
    inputs=[
        inputs.object("work_order", object_type="WorkOrder"),
    ],
    outputs=[
        outputs.modify_object("work_order"),
    ],
)
def score_work_order_risk(work_order):
    """
    Score a new work order the moment it's submitted, before routing to a planner.

    The Ontology gives us the linked ShipHull object automatically.
    No manual join needed — Foundry resolves the object relationship.
    """
    # Access linked object through the Ontology relationship
    hull = work_order.linked_ship_hull  # Ontology-defined relationship

    client = ModelClient.for_model("/models/maintenance_risk_v2")

    features = {
        "days_since_last_maintenance": work_order.days_since_last_maintenance,
        "component_age_years": hull.age_years,
        "operational_hours_30d": hull.operational_hours_last_30d,
        "deficiency_count_ytd": hull.deficiency_count_ytd,
        "fy_quarter": work_order.fiscal_quarter,
    }

    result = client.score(features)
    failure_prob = result["failure_probability"]
    risk_tier = "HIGH" if failure_prob >= 0.55 else ("MEDIUM" if failure_prob >= 0.20 else "LOW")

    # Write back to the WorkOrder object — visible in Workshop immediately
    work_order.risk_score = round(failure_prob, 4)
    work_order.risk_tier = risk_tier
    work_order.risk_scored_at = now()

    # Route HIGH-risk work orders to senior planner queue automatically
    if risk_tier == "HIGH":
        work_order.routing_queue = "SENIOR_PLANNER"
    else:
        work_order.routing_queue = "STANDARD"
'''


def print_foundry_deployment_patterns():
    """Print Foundry deployment pattern examples with explanatory context."""
    print("=== Foundry Deployment Pattern 1: Batch @transform ===")
    print(FOUNDRY_TRANSFORM_EXAMPLE)
    print()
    print("=== Foundry Deployment Pattern 2: AIP Logic (live scoring) ===")
    print(FOUNDRY_AIP_LOGIC_EXAMPLE)


# ---------------------------------------------------------------------------
# Section 3: Qlik SSE — Embedding Model Scoring in Dashboards
# ---------------------------------------------------------------------------
# Qlik Server-Side Extensions (SSE) let you call external functions from
# Qlik expressions. When a Qlik user selects a ship class, filters by date,
# or loads a dashboard, Qlik calls your SSE server over gRPC to compute
# model scores and return them as chart values.
#
# The SSE server is a Python gRPC service. It runs alongside your Qlik
# Sense server (on-prem or in FedRAMP cloud) and receives calls defined
# by the Qlik SSE protobuf API.
#
# The pattern:
# 1. Install grpcio and the Qlik SSE proto definitions
# 2. Implement the EvaluateScript or ExecuteFunction RPC methods
# 3. Register the SSE plugin in Qlik's config
# 4. Call your functions from Qlik load scripts or chart expressions


QLIK_SSE_SERVER_EXAMPLE = '''
# qlik_sse_server.py — Run this alongside Qlik Sense in a Docker container
# Requirements: pip install grpcio grpcio-tools mlflow scikit-learn pandas

import grpc
from concurrent import futures
import pandas as pd
import mlflow.pyfunc
import ServerSideExtension_pb2 as SSE
import ServerSideExtension_pb2_grpc as SSE_grpc

MODEL_URI = "models:/maintenance_risk/Production"
model = mlflow.pyfunc.load_model(MODEL_URI)


class ExtensionService(SSE_grpc.ConnectorServicer):
    """
    Implements the Qlik SSE gRPC interface.

    Qlik calls EvaluateScript when a Qlik load script invokes an SSE function.
    ExecuteFunction is called from chart expressions with bound parameters.
    """

    def GetCapabilities(self, request, context):
        """Tell Qlik what functions this SSE server provides."""
        return SSE.Capabilities(
            allowScript=True,
            pluginIdentifier="MaintenanceRiskPlugin",
            pluginVersion="1.0.0",
            functions=[
                SSE.FunctionDefinition(
                    name="ScoreMaintenanceRisk",
                    functionId=0,
                    functionType=SSE.TENSOR,  # processes arrays of values
                    returnType=SSE.NUMERIC,
                    params=[
                        SSE.Parameter(name="days_since_maint", dataType=SSE.NUMERIC),
                        SSE.Parameter(name="component_age", dataType=SSE.NUMERIC),
                        SSE.Parameter(name="op_hours_30d", dataType=SSE.NUMERIC),
                        SSE.Parameter(name="deficiency_count", dataType=SSE.NUMERIC),
                        SSE.Parameter(name="fy_quarter", dataType=SSE.NUMERIC),
                    ],
                )
            ],
        )

    def ExecuteFunction(self, request_iterator, context):
        """
        Handle a function call from a Qlik chart expression.
        Qlik sends rows of data as a stream of BundledRows.
        We score them and return the predictions.
        """
        rows = []
        for request in request_iterator:
            for row in request.rows:
                rows.append([dual.numData for dual in row.duals])

        if not rows:
            return

        df = pd.DataFrame(rows, columns=[
            "days_since_last_maintenance",
            "component_age_years",
            "operational_hours_30d",
            "deficiency_count_ytd",
            "fy_quarter",
        ])

        predictions = model.predict(df)

        # Return as a stream of BundledRows
        yield SSE.BundledRows(rows=[
            SSE.Row(duals=[SSE.Dual(numData=float(p))]) for p in predictions
        ])


def serve(port=50051):
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    SSE_grpc.add_ConnectorServicer_to_server(ExtensionService(), server)
    server.add_insecure_port(f"[::]:{port}")
    server.start()
    print(f"Qlik SSE server listening on port {port}")
    server.wait_for_termination()


if __name__ == "__main__":
    serve()
'''

# Corresponding Qlik load script to call the SSE
QLIK_LOAD_SCRIPT_EXAMPLE = '''
// Qlik load script — loads maintenance data and scores via SSE
// The SSE plugin is registered in QMC as "MaintenanceRisk" pointing to localhost:50051

LET vSSEPlugin = "MaintenanceRisk";

MaintenanceScores:
LOAD
    component_id,
    days_since_last_maintenance,
    component_age_years,
    operational_hours_30d,
    deficiency_count_ytd,
    fy_quarter,
    // SSE function call — returns the ML model score for each row
    $(vSSEPlugin).ScoreMaintenanceRisk(
        days_since_last_maintenance,
        component_age_years,
        operational_hours_30d,
        deficiency_count_ytd,
        fy_quarter
    ) AS failure_probability
FROM [lib://MaintenanceDB/components.qvd] (qvd);
'''


def print_qlik_sse_patterns():
    print("=== Qlik SSE Server Pattern ===")
    print(QLIK_SSE_SERVER_EXAMPLE)
    print()
    print("=== Qlik Load Script (SSE call) ===")
    print(QLIK_LOAD_SCRIPT_EXAMPLE)


# ---------------------------------------------------------------------------
# Section 4: Model Drift Monitoring
# ---------------------------------------------------------------------------
# A deployed model is not done. Two things will degrade its performance over time:
#
# 1. **Data drift**: The distribution of input features shifts. Personnel rotation
#    changes operational patterns. New maintenance procedures change how deficiency
#    counts are reported. The FY2022 vs FY2023 encoding change we saw in Chapter 05
#    is a real example.
#
# 2. **Concept drift**: The relationship between features and outcomes changes.
#    The model learned that >400 op-hours predicts failure. If the fleet upgrades
#    to higher-endurance components, that threshold becomes wrong.
#
# For DoD programs, there's a third consideration: the model's ATO may require
# periodic revalidation (every 6 or 12 months). Drift monitoring gives you the
# evidence to either confirm the model is still valid or trigger retraining.


def compute_psi(
    reference: pd.Series,
    current: pd.Series,
    n_bins: int = 10,
) -> float:
    """
    Compute Population Stability Index (PSI) between reference and current distributions.

    PSI is the standard metric for measuring input feature drift in production ML systems.
    Originally from credit risk modeling, it's widely used in government analytics.

    Interpretation:
    - PSI < 0.10: No significant change — model is stable
    - PSI 0.10-0.25: Some shift — monitor closely, consider retraining
    - PSI > 0.25: Major shift — retrain required, model may be unreliable

    The two-bucket boundary rule: if any single bucket has 0 actual or expected
    frequency, PSI becomes infinite. The 1/n_samples floor prevents this.
    """
    # Build bins from reference distribution
    bins = np.percentile(reference.dropna(), np.linspace(0, 100, n_bins + 1))
    bins = np.unique(bins)  # deduplicate near-equal percentiles for low-cardinality features

    # Compute frequencies in each bin
    ref_counts, _ = np.histogram(reference.dropna(), bins=bins)
    cur_counts, _ = np.histogram(current.dropna(), bins=bins)

    # Normalize to proportions, with floor to avoid log(0)
    n_ref = max(len(reference.dropna()), 1)
    n_cur = max(len(current.dropna()), 1)
    floor = 1e-6

    ref_pct = np.maximum(ref_counts / n_ref, floor)
    cur_pct = np.maximum(cur_counts / n_cur, floor)

    psi = np.sum((cur_pct - ref_pct) * np.log(cur_pct / ref_pct))
    return float(psi)


def compute_ks_test(reference: pd.Series, current: pd.Series) -> dict[str, float]:
    """
    Two-sample Kolmogorov-Smirnov test for distribution shift.

    Returns the KS statistic (0-1) and p-value.
    - High KS statistic + low p-value: significant distribution shift
    - Rule of thumb: KS > 0.10 with p < 0.01 warrants investigation

    KS test is more sensitive to changes in the tails than PSI — useful for
    detecting rare event distribution changes (exactly the type that matter
    for maintenance failure prediction).
    """
    ks_stat, p_value = stats.ks_2samp(
        reference.dropna().values, current.dropna().values
    )
    return {"ks_statistic": round(float(ks_stat), 4), "p_value": round(float(p_value), 6)}


def monitor_model_drift(
    reference_df: pd.DataFrame,
    current_df: pd.DataFrame,
    feature_columns: list[str],
    psi_threshold: float = 0.10,
    ks_threshold: float = 0.10,
) -> dict[str, Any]:
    """
    Full drift report comparing reference (training) and current (production) distributions.

    Returns a drift report with per-feature PSI, KS statistics, and an overall
    recommendation. In production, run this weekly against the last 30 days of
    production scoring data compared to training data.

    Attach this report to your quarterly ATO revalidation package.
    """
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "n_reference_rows": len(reference_df),
        "n_current_rows": len(current_df),
        "features": {},
        "overall_drift": False,
        "recommendation": "STABLE",
    }

    drift_flags = []

    for col in feature_columns:
        if col not in reference_df.columns or col not in current_df.columns:
            continue

        psi = compute_psi(reference_df[col], current_df[col])
        ks = compute_ks_test(reference_df[col], current_df[col])

        drifted = psi > psi_threshold or ks["ks_statistic"] > ks_threshold
        if drifted:
            drift_flags.append(col)

        report["features"][col] = {
            "psi": round(psi, 4),
            "ks_statistic": ks["ks_statistic"],
            "ks_p_value": ks["p_value"],
            "drifted": drifted,
            "severity": (
                "CRITICAL" if psi > 0.25
                else "WARNING" if psi > 0.10
                else "OK"
            ),
        }

    if len(drift_flags) >= 3:
        report["overall_drift"] = True
        report["recommendation"] = "RETRAIN_REQUIRED"
        report["drift_summary"] = f"{len(drift_flags)} features drifted: {drift_flags}"
    elif drift_flags:
        report["overall_drift"] = True
        report["recommendation"] = "MONITOR_CLOSELY"
        report["drift_summary"] = f"{len(drift_flags)} features showing drift: {drift_flags}"
    else:
        report["recommendation"] = "STABLE"
        report["drift_summary"] = "No significant drift detected"

    return report


def generate_synthetic_drift_scenario() -> tuple[pd.DataFrame, pd.DataFrame]:
    """
    Generate reference and current DataFrames that simulate FY-end operational tempo shift.

    This mimics a real scenario: training data was from a normal operational period,
    but the current scoring window includes September FY-end surge where op hours
    spike and maintenance gets deferred, shifting the feature distributions.
    """
    rng = np.random.default_rng(42)
    n = 5_000

    # Reference: normal operational period (training data)
    reference = pd.DataFrame({
        "days_since_last_maintenance": rng.integers(0, 365, n),
        "component_age_years": rng.uniform(0.5, 12.0, n),
        "operational_hours_30d": rng.integers(100, 450, n),  # normal range
        "deficiency_count_ytd": rng.integers(0, 8, n),
        "fy_quarter": rng.choice([1, 2, 3, 4], n),
    })

    # Current: FY-end surge — op hours spike, maintenance deferred, deficiencies up
    current = pd.DataFrame({
        "days_since_last_maintenance": rng.integers(60, 730, n),  # maintenance deferred
        "component_age_years": rng.uniform(0.5, 12.0, n),         # no change
        "operational_hours_30d": rng.integers(350, 700, n),        # SPIKE — shifted distribution
        "deficiency_count_ytd": rng.integers(3, 15, n),           # higher deficiency counts
        "fy_quarter": rng.choice([4, 4, 4, 3], n),               # mostly Q4
    })

    return reference, current


def run_production_health_check(
    endpoint_url: str | None = None,
    reference_df: pd.DataFrame | None = None,
    current_df: pd.DataFrame | None = None,
) -> dict[str, Any]:
    """
    Combined production health check: endpoint availability + model drift.

    Run this weekly from a scheduled Databricks Job or Foundry transform.
    Write results to a monitoring Delta table for dashboarding.
    """
    health_report: dict[str, Any] = {
        "check_time": datetime.now(timezone.utc).isoformat(),
        "endpoint_status": "skipped",
        "drift_status": "skipped",
    }

    # 1. Endpoint availability check
    if endpoint_url:
        try:
            import requests
            resp = requests.get(
                endpoint_url.replace("/invocations", "/health"),
                timeout=10,
            )
            health_report["endpoint_status"] = "healthy" if resp.status_code == 200 else "degraded"
            health_report["endpoint_response_ms"] = resp.elapsed.total_seconds() * 1000
        except Exception as exc:
            health_report["endpoint_status"] = "unreachable"
            health_report["endpoint_error"] = str(exc)

    # 2. Drift check
    if reference_df is not None and current_df is not None:
        features = [
            "days_since_last_maintenance",
            "component_age_years",
            "operational_hours_30d",
            "deficiency_count_ytd",
            "fy_quarter",
        ]
        drift_report = monitor_model_drift(reference_df, current_df, features)
        health_report["drift_status"] = drift_report["recommendation"]
        health_report["drift_summary"] = drift_report.get("drift_summary", "")
        health_report["feature_drift"] = drift_report["features"]

    # Determine overall status
    statuses = [health_report["endpoint_status"], health_report["drift_status"]]
    if "unreachable" in statuses or "RETRAIN_REQUIRED" in statuses:
        health_report["overall"] = "CRITICAL"
    elif "degraded" in statuses or "MONITOR_CLOSELY" in statuses:
        health_report["overall"] = "WARNING"
    else:
        health_report["overall"] = "OK"

    return health_report


# ---------------------------------------------------------------------------
# Demo runner
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("=== Chapter 11: Platform Deployment Patterns Demo ===\n")

    # 1. Databricks cost estimation
    print("--- Databricks Endpoint Cost Estimates ---")
    estimate_serving_endpoint_cost(
        workload_size="Small", scale_to_zero=True,
        avg_requests_per_hour=30, operational_hours_per_day=10
    )
    estimate_serving_endpoint_cost(
        workload_size="Small", scale_to_zero=False,
        avg_requests_per_hour=30, operational_hours_per_day=10
    )
    print()

    # 2. A/B traffic split config
    print("--- A/B Traffic Split Configuration ---")
    ab_config = configure_ab_traffic_split(
        "don-maintenance-risk", "2", "3", candidate_traffic_pct=10
    )
    print()

    # 3. Foundry patterns
    print("--- Palantir Foundry Deployment Patterns ---")
    print("Batch @transform and AIP Logic examples shown in module docstrings.")
    print("See FOUNDRY_TRANSFORM_EXAMPLE and FOUNDRY_AIP_LOGIC_EXAMPLE strings.")
    print()

    # 4. Qlik SSE
    print("--- Qlik SSE Pattern ---")
    print("See QLIK_SSE_SERVER_EXAMPLE and QLIK_LOAD_SCRIPT_EXAMPLE strings.")
    print()

    # 5. Drift monitoring with simulated FY-end drift
    print("--- Model Drift Monitoring: FY-End Surge Scenario ---")
    reference_df, current_df = generate_synthetic_drift_scenario()
    features = [
        "days_since_last_maintenance",
        "component_age_years",
        "operational_hours_30d",
        "deficiency_count_ytd",
        "fy_quarter",
    ]
    drift_report = monitor_model_drift(reference_df, current_df, features)
    print(f"Overall recommendation: {drift_report['recommendation']}")
    print(f"Summary: {drift_report['drift_summary']}")
    print("\nPer-feature drift:")
    for feat, stats_dict in drift_report["features"].items():
        flag = "DRIFT" if stats_dict["drifted"] else "OK"
        print(f"  {feat:35s} PSI={stats_dict['psi']:.3f}  [{flag}] ({stats_dict['severity']})")

    # 6. Production health check
    print("\n--- Combined Production Health Check ---")
    health = run_production_health_check(
        reference_df=reference_df,
        current_df=current_df,
    )
    print(f"Overall status: {health['overall']}")
    print(f"Drift status: {health['drift_status']}")
    print(f"Endpoint status: {health['endpoint_status']}")
