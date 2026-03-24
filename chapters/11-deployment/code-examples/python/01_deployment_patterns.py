"""
Chapter 11: Deployment & Scaling
Code Examples: Deployment Patterns for Federal Data Science Platforms

This module covers four deployment patterns used across DoD/federal platforms:
  1. MLflow model packaging with signature validation
  2. Databricks Model Serving endpoint management and invocation
  3. FastAPI inference service with audit logging (production-grade)
  4. Palantir Foundry batch scoring pipeline with @transform
  5. Pandas UDF distributed scoring in Spark (Databricks/Jupiter)

Platform targets: Databricks (FedRAMP High/IL5), Palantir Foundry (FedRAMP High/IL5),
                  Navy Jupiter (Advana subtenant), Advana
"""

import json
import logging
import os
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import mlflow
import mlflow.pyfunc
import mlflow.sklearn
import numpy as np
import pandas as pd
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

# ---------------------------------------------------------------------------
# Section 1: MLflow Model Packaging
# ---------------------------------------------------------------------------
# Packaging is not an afterthought. The mlflow.models.signature captures
# input/output schema and makes inference contract explicit — critical when
# different teams consume your model months after training.


def build_and_log_maintenance_model(experiment_name: str = "ch11-maintenance-risk") -> str:
    """
    Train a maintenance risk model and log it to MLflow with a full model signature.
    Returns the run_id so downstream steps can retrieve the model.

    In Databricks (FedRAMP/IL5), this writes to the workspace-managed MLflow
    tracking server backed by Unity Catalog. In Advana/Jupiter, you'd point
    MLFLOW_TRACKING_URI to the Advana-managed tracking server.
    """
    mlflow.set_experiment(experiment_name)

    # Synthetic DoN maintenance dataset — realistic enough to demonstrate the pattern
    rng = np.random.default_rng(42)
    n = 2_000
    df = pd.DataFrame({
        "days_since_last_maintenance": rng.integers(0, 730, n),
        "component_age_years": rng.uniform(0.5, 15.0, n),
        "operational_hours_30d": rng.integers(0, 600, n),
        "deficiency_count_ytd": rng.integers(0, 12, n),
        "fy_quarter": rng.integers(1, 5, n),  # 4 = Q4 September crunch
    })
    # Label: high deficiency + old age + high usage → more likely to fail
    prob = (
        0.05
        + 0.3 * (df["deficiency_count_ytd"] > 5).astype(float)
        + 0.25 * (df["component_age_years"] > 10).astype(float)
        + 0.2 * (df["operational_hours_30d"] > 400).astype(float)
    )
    df["failure_within_90d"] = (rng.uniform(0, 1, n) < prob).astype(int)

    features = [c for c in df.columns if c != "failure_within_90d"]
    X = df[features]
    y = df["failure_within_90d"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    with mlflow.start_run() as run:
        # Build pipeline: scaler + gradient booster
        pipeline = Pipeline([
            ("scaler", StandardScaler()),
            ("model", GradientBoostingClassifier(n_estimators=200, max_depth=4, random_state=42)),
        ])
        pipeline.fit(X_train, y_train)

        train_score = pipeline.score(X_train, y_train)
        test_score = pipeline.score(X_test, y_test)

        mlflow.log_params({
            "n_estimators": 200,
            "max_depth": 4,
            "features": features,
        })
        mlflow.log_metrics({
            "train_accuracy": train_score,
            "test_accuracy": test_score,
        })

        # Build an explicit model signature — this is what makes deployment safe.
        # If a caller sends the wrong column names or types, MLflow catches it before
        # your model produces silently wrong outputs.
        from mlflow.models.signature import infer_signature
        signature = infer_signature(X_train, pipeline.predict_proba(X_train)[:, 1])

        # Input example: one realistic record. Stored in the model artifact.
        # Databricks Model Serving uses this to auto-generate a test payload.
        input_example = X_train.head(3)

        mlflow.sklearn.log_model(
            sk_model=pipeline,
            artifact_path="maintenance_risk_model",
            signature=signature,
            input_example=input_example,
            # registered_model_name triggers automatic registration in the model registry.
            # In Unity Catalog (Databricks Dec 2025+), use three-level namespace:
            #   catalog.schema.model_name
            registered_model_name="gov_analytics.don_maintenance.maintenance_risk_v1",
        )

        print(f"Run ID: {run.info.run_id}")
        print(f"Test accuracy: {test_score:.3f}")
        print(f"Model registered: gov_analytics.don_maintenance.maintenance_risk_v1")

        return run.info.run_id


# ---------------------------------------------------------------------------
# Section 2: Databricks Model Serving — Endpoint Management
# ---------------------------------------------------------------------------
# Databricks Model Serving (Mosaic AI Gateway) runs behind a load balancer in
# FedRAMP/IL5. Endpoints are HTTP REST — any client with the right token can call.
# The key scaling decision: SCALE_TO_ZERO vs always-on.
# Scale-to-zero saves budget but adds 30-90s cold start. For batch overnight jobs,
# fine. For an operations dashboard that someone checks during an incident, a 60s
# wait is a failure mode.


def create_serving_endpoint(
    endpoint_name: str,
    model_name: str,
    model_version: str,
    scale_to_zero: bool = True,
) -> dict:
    """
    Create or update a Databricks Model Serving endpoint.
    Requires databricks-sdk installed: pip install databricks-sdk

    In practice on IL5 Databricks, you authenticate with a PAT (Personal Access Token)
    stored in Databricks Secrets, not hardcoded. The SDK picks up DATABRICKS_HOST
    and DATABRICKS_TOKEN from environment or ~/.databrickscfg.
    """
    try:
        from databricks.sdk import WorkspaceClient
        from databricks.sdk.service.serving import (
            EndpointCoreConfigInput,
            ServedModelInput,
            ServedModelInputWorkloadSize,
        )
    except ImportError:
        raise ImportError("Install databricks-sdk: pip install databricks-sdk")

    w = WorkspaceClient()

    served_model = ServedModelInput(
        model_name=model_name,
        model_version=model_version,
        workload_size=ServedModelInputWorkloadSize.SMALL,  # 4 concurrent requests
        scale_to_zero_enabled=scale_to_zero,
    )

    config = EndpointCoreConfigInput(served_models=[served_model])

    try:
        # Try to update if exists
        endpoint = w.serving_endpoints.update_config(name=endpoint_name, served_models=[served_model])
        print(f"Updated endpoint: {endpoint_name}")
    except Exception:
        # Create new
        endpoint = w.serving_endpoints.create(name=endpoint_name, config=config)
        print(f"Created endpoint: {endpoint_name}")

    return {"endpoint_name": endpoint_name, "model": f"{model_name}:{model_version}"}


def invoke_serving_endpoint(
    endpoint_name: str,
    records: list[dict],
    databricks_host: str | None = None,
    databricks_token: str | None = None,
) -> list[float]:
    """
    Score records against a Databricks Model Serving endpoint.

    For operational dashboards in IL5 environments, this call goes to an HTTPS
    endpoint within the GovCloud VPC. Latency is typically 20-80ms for small
    payloads on warmed endpoints.

    Returns a list of probabilities (one per input record).
    """
    import requests

    host = databricks_host or os.environ["DATABRICKS_HOST"]
    token = databricks_token or os.environ["DATABRICKS_TOKEN"]

    url = f"{host}/serving-endpoints/{endpoint_name}/invocations"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }

    # Databricks expects this exact payload structure
    payload = {"dataframe_records": records}

    response = requests.post(url, headers=headers, json=payload, timeout=30)
    response.raise_for_status()

    result = response.json()
    # predictions is a list of floats (probability scores)
    return result["predictions"]


def demonstrate_endpoint_invocation():
    """End-to-end demo: package -> register -> invoke."""
    print("=== Databricks Model Serving Demo ===\n")

    # 1. Train and log the model
    run_id = build_and_log_maintenance_model()

    # 2. In production you'd wait for the model registration to complete,
    #    then retrieve the version number. Here we simulate that.
    print("\nSimulating endpoint invocation (skipping actual Databricks calls in demo)...")

    # 3. Payload structure for a real invocation
    sample_records = [
        {
            "days_since_last_maintenance": 180,
            "component_age_years": 8.5,
            "operational_hours_30d": 520,
            "deficiency_count_ytd": 3,
            "fy_quarter": 4,
        },
        {
            "days_since_last_maintenance": 30,
            "component_age_years": 2.0,
            "operational_hours_30d": 200,
            "deficiency_count_ytd": 0,
            "fy_quarter": 1,
        },
    ]

    print("Sample payload:")
    print(json.dumps({"dataframe_records": sample_records}, indent=2))

    # In a real IL5 environment:
    # scores = invoke_serving_endpoint("don-maintenance-risk-prod", sample_records)
    # print(f"Failure probabilities: {scores}")


# ---------------------------------------------------------------------------
# Section 3: FastAPI Inference Service with Audit Logging
# ---------------------------------------------------------------------------
# When you can't use a managed endpoint (Palantir SaaS isn't available at your
# classification level, or the system needs to call your model from a non-cloud
# network segment), you run your own FastAPI container.
#
# The non-negotiables for government deployments:
#   - Request/response audit log with user identity
#   - Input validation before the model ever sees data
#   - Health check endpoint for container orchestrator liveness probes
#   - Non-root user in the Dockerfile


from pydantic import BaseModel, Field, field_validator


class MaintenanceRiskRequest(BaseModel):
    """
    Input validation for the maintenance risk model.
    Pydantic enforces types and constraints before any ML code runs.
    Bad data returned from upstream systems gets caught here, not silently scored.
    """
    days_since_last_maintenance: int = Field(..., ge=0, le=3650, description="0-3650 days")
    component_age_years: float = Field(..., ge=0.0, le=50.0)
    operational_hours_30d: int = Field(..., ge=0, le=744)  # max hours in 31 days
    deficiency_count_ytd: int = Field(..., ge=0, le=100)
    fy_quarter: int = Field(..., ge=1, le=4)
    # Optional: requestor identity for audit trail. CAC-authenticated callers
    # should pass their DoD ID; downstream services pass a service account identifier.
    requestor_id: str = Field(default="anonymous", max_length=64)

    @field_validator("fy_quarter")
    @classmethod
    def validate_quarter(cls, v: int) -> int:
        if v not in (1, 2, 3, 4):
            raise ValueError("fy_quarter must be 1, 2, 3, or 4")
        return v


class MaintenanceRiskResponse(BaseModel):
    request_id: str
    failure_probability: float = Field(..., ge=0.0, le=1.0)
    risk_tier: str  # LOW / MEDIUM / HIGH
    model_version: str
    scored_at_utc: str


def classify_risk(probability: float) -> str:
    """Map raw probability to a risk tier that operations staff can act on."""
    if probability < 0.20:
        return "LOW"
    elif probability < 0.55:
        return "MEDIUM"
    else:
        return "HIGH"


# Structured audit logger — writes JSON lines so SIEM tools can ingest directly
audit_logger = logging.getLogger("audit")
audit_logger.setLevel(logging.INFO)
_handler = logging.StreamHandler()
_handler.setFormatter(logging.Formatter("%(message)s"))
audit_logger.addHandler(_handler)


def log_inference_event(
    request_id: str,
    requestor_id: str,
    input_data: dict,
    prediction: float,
    risk_tier: str,
    latency_ms: float,
    model_version: str,
) -> None:
    """
    Write a structured audit record for every inference request.

    ATO requirements typically mandate that ML model predictions be traceable
    back to the input that produced them. This log ties the prediction to the
    request ID, the caller, and the exact input values — so if someone questions
    a maintenance priority decision three months later, you can reconstruct it.
    """
    audit_record = {
        "event_type": "model_inference",
        "request_id": request_id,
        "requestor_id": requestor_id,
        "model_version": model_version,
        "input": input_data,
        "prediction": prediction,
        "risk_tier": risk_tier,
        "latency_ms": round(latency_ms, 2),
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
    }
    audit_logger.info(json.dumps(audit_record))


def create_fastapi_app(model_path: str | None = None):
    """
    Build and return a FastAPI application for serving the maintenance risk model.

    In production this function is called once at module load time. The model
    is loaded into memory at startup; inference is CPU-bound for sklearn pipelines
    (sub-millisecond per record at this scale).

    Usage:
        app = create_fastapi_app("models/maintenance_risk_v1")
        uvicorn.run(app, host="0.0.0.0", port=8080)
    """
    try:
        from fastapi import FastAPI, HTTPException, Request
        from fastapi.middleware.cors import CORSMiddleware
    except ImportError:
        raise ImportError("Install fastapi + uvicorn: pip install fastapi uvicorn")

    app = FastAPI(
        title="DoN Maintenance Risk Scoring API",
        description="Predicts 90-day maintenance failure probability for Navy components",
        version="1.0.0",
    )

    # In IL4/IL5 environments, CORS is usually locked down to specific origins.
    # For an internal-only API behind a reverse proxy, you can omit CORS middleware
    # entirely. The allow_origins list here is intentionally restrictive.
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["https://dashboard.internal.navy.mil"],
        allow_methods=["POST"],
        allow_headers=["Authorization", "Content-Type"],
    )

    # Load model at startup. If model_path is None, skip (for unit testing).
    _model = None
    if model_path:
        _model = mlflow.pyfunc.load_model(model_path)

    @app.get("/health")
    async def health_check():
        """Container liveness probe. Returns 200 when model is loaded and ready."""
        return {"status": "healthy", "model_loaded": _model is not None}

    @app.get("/readiness")
    async def readiness_check():
        """
        Kubernetes readiness probe. Distinguishes 'container started' from
        'model loaded and ready to serve traffic'. Important if model loading
        takes 10-30s on startup.
        """
        if _model is None and model_path is not None:
            raise HTTPException(status_code=503, detail="Model not yet loaded")
        return {"status": "ready"}

    @app.post("/score", response_model=MaintenanceRiskResponse)
    async def score_record(request: MaintenanceRiskRequest):
        """
        Score a single component for 90-day maintenance failure risk.

        All inputs are validated by Pydantic before this function runs.
        Every call is logged to the structured audit trail.
        """
        request_id = str(uuid.uuid4())
        start_time = time.perf_counter()

        # Build input DataFrame matching the model's expected schema
        input_df = pd.DataFrame([{
            "days_since_last_maintenance": request.days_since_last_maintenance,
            "component_age_years": request.component_age_years,
            "operational_hours_30d": request.operational_hours_30d,
            "deficiency_count_ytd": request.deficiency_count_ytd,
            "fy_quarter": request.fy_quarter,
        }])

        if _model is not None:
            predictions = _model.predict(input_df)
            # MLflow pyfunc predict returns an array; take the first element
            failure_prob = float(predictions[0])
        else:
            # Demo mode when no model is loaded
            failure_prob = 0.42

        risk_tier = classify_risk(failure_prob)
        latency_ms = (time.perf_counter() - start_time) * 1000

        log_inference_event(
            request_id=request_id,
            requestor_id=request.requestor_id,
            input_data=request.model_dump(exclude={"requestor_id"}),
            prediction=failure_prob,
            risk_tier=risk_tier,
            latency_ms=latency_ms,
            model_version="1.0.0",
        )

        return MaintenanceRiskResponse(
            request_id=request_id,
            failure_probability=round(failure_prob, 4),
            risk_tier=risk_tier,
            model_version="1.0.0",
            scored_at_utc=datetime.now(timezone.utc).isoformat(),
        )

    @app.post("/score/batch", response_model=list[MaintenanceRiskResponse])
    async def score_batch(records: list[MaintenanceRiskRequest]):
        """
        Score multiple records in one call. Useful for dashboard refresh scenarios
        where you need 50-200 records scored in a single round trip.
        Capped at 500 records per request to prevent memory exhaustion.
        """
        if len(records) > 500:
            raise HTTPException(
                status_code=400,
                detail=f"Batch size {len(records)} exceeds limit of 500"
            )

        results = []
        for record in records:
            # Reuse single-record logic — could vectorize for production optimization
            single_result = await score_record(record)
            results.append(single_result)

        return results

    return app


# ---------------------------------------------------------------------------
# Section 4: Foundry Batch Scoring Transform
# ---------------------------------------------------------------------------
# Palantir Foundry transforms are the native way to run batch scoring.
# A @transform function reads from one or more Foundry datasets, processes data,
# and writes to an output dataset. Foundry handles lineage, versioning, and
# incremental computation automatically.


def write_foundry_batch_scoring_transform():
    """
    Illustrates the Foundry @transform pattern for batch scoring.
    This code would live in a Foundry Code Repository, not a standalone Python file.
    It's shown here for reference — you cannot run it outside of Foundry.

    The key constraint: Foundry transforms must be deterministic and side-effect-free.
    They cannot write to external systems or call external APIs.
    """
    # This is pseudocode for Foundry — the actual imports come from the Foundry environment
    transform_code = '''
# Foundry Code Repository — maintenance_risk_scoring/transforms/score_components.py
# This transform runs on a schedule (nightly) or on upstream dataset change.

from transforms.api import transform, Input, Output
from palantir_models.transforms import ModelInput  # Foundry model deployment API


@transform(
    output=Output("/don-data/maintenance/component_risk_scores"),
    components=Input("/don-data/maintenance/components_current"),
    model=ModelInput("/models/maintenance_risk_v1"),  # Foundry-managed model
)
def score_components(output, components, model):
    """
    Score every active Navy component for 90-day failure risk.
    Runs nightly at 0200 local time. Results feed the CNO maintenance dashboard.

    Foundry automatically tracks which version of the model produced which scores.
    If the model is retrained and the transform is re-run, the lineage graph shows
    exactly which score rows came from which model version.
    """
    df = components.dataframe()

    # Filter to active components only — don't score decommissioned assets
    active = df.filter(df["status"] == "ACTIVE")

    # Foundry's ModelInput handles the mlflow / foundry_ml loading internally.
    # You call model.transform() and it scores the DataFrame using the registered model.
    scored = model.transform(
        active,
        input_columns=[
            "days_since_last_maintenance",
            "component_age_years",
            "operational_hours_30d",
            "deficiency_count_ytd",
            "fy_quarter",
        ],
        output_column="failure_probability",
    )

    # Add derived columns for dashboard consumption
    from pyspark.sql import functions as F

    result = scored.withColumn(
        "risk_tier",
        F.when(F.col("failure_probability") < 0.20, "LOW")
         .when(F.col("failure_probability") < 0.55, "MEDIUM")
         .otherwise("HIGH")
    ).withColumn(
        "scored_date", F.current_date()
    ).withColumn(
        "model_version", F.lit("v1")
    )

    output.write_dataframe(result)
'''
    print("Foundry @transform pattern (pseudocode):")
    print(transform_code)


# ---------------------------------------------------------------------------
# Section 5: Pandas UDF for Distributed Spark Scoring
# ---------------------------------------------------------------------------
# When your model needs to score millions of records in Databricks or Jupiter,
# running pandas `.predict()` in a loop is not viable. Pandas UDFs let you
# broadcast the model to every Spark executor and score partitions in parallel.
#
# The broadcast pattern is important: model files can be 50-500MB. Without
# broadcast(), each executor would re-download from the driver — network
# saturation on a 10-node cluster means your "distributed" job becomes a
# bottleneck at the model artifact store.


def create_distributed_scoring_udf():
    """
    Create a Pandas UDF that scores records using a broadcasted model artifact.

    Run this in a Databricks or Spark-enabled notebook after loading a SparkSession.
    The pattern works the same way on Navy Jupiter (Advana's Spark environment).
    """
    try:
        from pyspark.sql import SparkSession
        from pyspark.sql import functions as F
        from pyspark.sql.types import DoubleType
    except ImportError:
        print("PySpark not available — this pattern runs in Databricks/Jupiter only")
        return None

    spark = SparkSession.builder.getOrCreate()

    # Load model once on the driver, then broadcast to all executors.
    # This is the critical step that prevents the network saturation problem.
    model_uri = "models:/gov_analytics.don_maintenance.maintenance_risk_v1/1"

    print(f"Loading model from: {model_uri}")
    model = mlflow.pyfunc.load_model(model_uri)

    # Broadcast the model artifact — now each executor has a local copy
    broadcast_model = spark.sparkContext.broadcast(model)

    # Define the Pandas UDF. Each Spark partition becomes a pandas DataFrame,
    # scored in bulk by the broadcast model. Return type must be declared.
    import pandas as pd
    from pyspark.sql.functions import pandas_udf

    @pandas_udf(DoubleType())
    def score_maintenance_risk(
        days_since_maint: pd.Series,
        component_age: pd.Series,
        op_hours: pd.Series,
        deficiency_count: pd.Series,
        fy_quarter: pd.Series,
    ) -> pd.Series:
        """
        Pandas UDF: scores one Spark partition at a time.
        Called with column Series by the Spark executor — not by your driver code.
        """
        input_df = pd.DataFrame({
            "days_since_last_maintenance": days_since_maint,
            "component_age_years": component_age,
            "operational_hours_30d": op_hours,
            "deficiency_count_ytd": deficiency_count,
            "fy_quarter": fy_quarter,
        })

        # Use the broadcast copy — no network call on the executor
        local_model = broadcast_model.value
        predictions = local_model.predict(input_df)
        return pd.Series(predictions)

    return score_maintenance_risk


def run_distributed_scoring_pipeline():
    """
    Full distributed scoring pipeline: load data, score with UDF, write Delta table.

    In Databricks/IL5, this runs as a scheduled Job (not an always-on cluster).
    Scheduling batch overnight avoids competing with interactive users for cluster
    resources and fits the government workday rhythm — ops staff check scores
    first thing in the morning.
    """
    try:
        from pyspark.sql import SparkSession
        from pyspark.sql import functions as F
    except ImportError:
        print("Spark not available — illustrative pseudocode follows:")
        _print_scoring_pseudocode()
        return

    spark = SparkSession.builder.getOrCreate()

    score_udf = create_distributed_scoring_udf()
    if score_udf is None:
        return

    # Read source data from Unity Catalog Delta table
    components_df = spark.read.table("gov_analytics.don_maintenance.components_current")

    # Score all active components in parallel across Spark executors
    scored_df = components_df.filter(F.col("status") == "ACTIVE").withColumn(
        "failure_probability",
        score_udf(
            F.col("days_since_last_maintenance"),
            F.col("component_age_years"),
            F.col("operational_hours_30d"),
            F.col("deficiency_count_ytd"),
            F.col("fy_quarter"),
        )
    ).withColumn(
        "risk_tier",
        F.when(F.col("failure_probability") < 0.20, "LOW")
         .when(F.col("failure_probability") < 0.55, "MEDIUM")
         .otherwise("HIGH")
    ).withColumn("scored_date", F.current_date())

    # MERGE INTO pattern: update existing scores, insert new components.
    # Avoids full table rewrites — important for large tables that downstream
    # dashboards query continuously.
    scored_df.createOrReplaceTempView("new_scores")

    spark.sql("""
        MERGE INTO gov_analytics.don_maintenance.component_risk_scores AS target
        USING new_scores AS source
        ON target.component_id = source.component_id
        WHEN MATCHED THEN UPDATE SET
            target.failure_probability = source.failure_probability,
            target.risk_tier = source.risk_tier,
            target.scored_date = source.scored_date
        WHEN NOT MATCHED THEN INSERT *
    """)

    print("Scoring pipeline complete.")


def _print_scoring_pseudocode():
    """Print the scoring pipeline structure for environments without Spark."""
    print("""
Distributed Scoring Pipeline (Databricks/Jupiter):

1. spark.read.table("gov_analytics.don_maintenance.components_current")
   → Load all components from Unity Catalog

2. .filter(F.col("status") == "ACTIVE")
   → ~450K active components in a typical DoN fleet

3. .withColumn("failure_probability", score_udf(col1, col2, ...))
   → Broadcast model scores partitions in parallel
   → Typical throughput: 2-5M records/minute on a 4-node cluster

4. MERGE INTO component_risk_scores
   → Incremental update — no full table rewrite
   → Downstream Qlik dashboards see fresh scores without caching issues
""")


# ---------------------------------------------------------------------------
# Demo runner
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("=== Chapter 11: Deployment Patterns Demo ===\n")

    # 1. Build and log a model with MLflow
    print("--- Step 1: MLflow Model Packaging ---")
    run_id = build_and_log_maintenance_model()
    print(f"Model logged with run_id: {run_id}\n")

    # 2. Show the endpoint invocation payload structure
    print("--- Step 2: Databricks Endpoint Invocation ---")
    demonstrate_endpoint_invocation()
    print()

    # 3. Demo the FastAPI app without Databricks
    print("--- Step 3: FastAPI Inference Service ---")
    app = create_fastapi_app()  # No model path — demo mode
    print("FastAPI app created. Endpoints: GET /health, GET /readiness, POST /score, POST /score/batch")
    print()

    # 4. Show the Foundry transform pattern
    print("--- Step 4: Foundry Batch Scoring Transform ---")
    write_foundry_batch_scoring_transform()
    print()

    # 5. Show distributed scoring pattern
    print("--- Step 5: Distributed Spark Scoring ---")
    _print_scoring_pseudocode()
