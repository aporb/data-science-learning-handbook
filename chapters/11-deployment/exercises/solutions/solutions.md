# Chapter 11 Exercise Solutions

---

## Exercise 1: Deployment Pattern Selection — Solution

**Architecture decision**:

```
Unity Catalog (contracts_current)
         │
         ├──[0200 nightly batch]──→ Databricks Job (Pandas UDF) ──→ Delta: contract_risk_scores
         │
         └──[on-demand query]──→ Databricks Model Serving endpoint ──→ Qlik Server-Side Extension
```

**Answer 1 — Batch pattern**:

Databricks scheduled Job using a Pandas UDF. The data already lives in Unity Catalog, so there's no network hop to move it. A 4-node cluster can score 2 million records in 8-15 minutes at 0200 — well before the 0700 briefing. Write results to a Delta table (`contract_risk_scores`) with `MERGE INTO` for incremental updates.

Why not Palantir Foundry for this? The data source is Unity Catalog. Moving 2 million rows across platforms nightly just to use Foundry's `@transform` adds unnecessary latency and egress costs. Use the platform where the data lives.

**Answer 2 — On-demand pattern**:

Databricks Model Serving endpoint with `scale_to_zero_enabled=False` (always-on). The Qlik dashboard calls the endpoint via a Server-Side Extension (SSE). The 5-second latency budget makes scale-to-zero a non-starter — 45-90 second cold starts would break the UX. One always-on endpoint for IL4 Databricks runs approximately $200-400/month depending on workload size; that's the right cost trade-off for an operational dashboard.

**Answer 3 — Shared artifacts**:

Both patterns use the same model artifact registered in Unity Catalog (`gov_analytics.procurement.contract_anomaly_v2`). The batch job and the serving endpoint both reference the same version. When the model is retrained, you bump the version in both the Job configuration and the serving endpoint config in a single change — not two separate updates that could drift out of sync.

**Answer 4 — Full architecture**:

```
Unity Catalog: contracts_current (Delta)
        │
        ├─ Databricks Job (0200 nightly)
        │   ├─ Pandas UDF scores 2M records
        │   └─ MERGE INTO → contract_risk_scores (Delta)
        │
        └─ Model Serving Endpoint (always-on)
            └─ Qlik SSE calls endpoint on filter/selection
                └─ Qlik Dashboard (contracting officers)
                    ├─ Reads contract_risk_scores for batch scores
                    └─ Calls endpoint for real-time score on new contracts
```

The dashboard reads pre-computed batch scores for most queries (fast) and calls the live endpoint only for contracts created after the last batch run (real-time, slightly slower but small volume).

---

## Exercise 2: FastAPI Authentication — Solution

```python
import os
from fastapi import Depends, HTTPException, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

security = HTTPBearer()

def verify_token(credentials: HTTPAuthorizationCredentials = Security(security)) -> str:
    """
    Verify the Bearer token and return the requestor identity.
    """
    expected_token = os.environ.get("INFERENCE_API_TOKEN")

    if expected_token is None:
        # Server misconfiguration — INFERENCE_API_TOKEN not set.
        # Raise 500, not 401 or 403 — this is a server problem, not a client problem.
        raise HTTPException(
            status_code=500,
            detail="Server authentication not configured"
        )

    token = credentials.credentials

    if token != expected_token:
        # Token present but wrong — 403 Forbidden (authenticated but not authorized).
        # The distinction from 401: the client did authenticate (sent a Bearer token),
        # but the credential is not valid for this resource.
        raise HTTPException(
            status_code=403,
            detail="Invalid token"
        )

    # Return the token as a stand-in for requestor identity.
    # In production with JWTs, you'd decode the token to get the user's DoD ID
    # or service account name from the payload claims.
    return token
```

Then update the `/score` endpoint signature to require the token:

```python
@app.post("/score", response_model=MaintenanceRiskResponse)
async def score_record(
    request: MaintenanceRiskRequest,
    requestor_token: str = Depends(verify_token),  # enforces auth
):
    # requestor_token is now available for audit logging
    ...
```

**Extension answer — 401 vs 403**:

HTTP 401 means "I don't know who you are — authenticate yourself." The `WWW-Authenticate` header in a 401 response tells the client what authentication scheme to use. HTTPBearer already handles the case where no Authorization header is present by returning 401 automatically.

HTTP 403 means "I know who you are (or you provided credentials), but you're not allowed to do this." When a client sends a Bearer token that doesn't match, returning 403 communicates that the credentials were received and evaluated — they just aren't valid.

For a SIEM system, this distinction is valuable: a flood of 401s means unauthenticated probing (potentially a scan). A flood of 403s with the same IP and a token means a compromised or stolen token being reused after revocation. The response code alone tells the SOC analyst which incident response playbook to run.

---

## Exercise 3: ATO Evidence Package — Solution

| Area | Evidence Item | Artifact Location | Responsible Party |
|------|--------------|------------------|-------------------|
| **Model documentation** | Model card: training data provenance, evaluation metrics, intended use, known limitations | MLflow model registry metadata + Git README | Data Scientist |
| | Model signature: input/output schema with types and value constraints | MLflow model artifact (`MLmodel` file) | Data Scientist |
| **Data handling** | Data classification documentation: what IL level is the training data, what columns contain PII or controlled data | System Security Plan (SSP) appendix | ISSO + Data Scientist |
| | Data retention policy: how long are inference request logs retained, where, under what access controls | Kubernetes logging config + SSP | Platform Engineer + ISSO |
| **Access control** | Kubernetes RBAC policy: which service accounts can deploy/update the inference pod | Kubernetes manifest in Git | Platform Engineer |
| | API authentication configuration: Bearer token rotation policy, service account management | Secrets management config (Vault/k8s Secrets) + runbook | Platform Engineer + ISSO |
| **Monitoring & audit** | Inference audit log samples showing request_id, requestor_id, input, prediction, timestamp | Centralized log system (Splunk, ELK) | Data Scientist + Platform Engineer |
| | Model performance monitoring: scheduled evaluation against ground truth, drift detection | MLflow experiment runs + dashboard | Data Scientist |

**Bonus — `log_inference_event()` review**:

The existing function logs: `event_type`, `request_id`, `requestor_id`, `model_version`, `input`, `prediction`, `risk_tier`, `latency_ms`, `timestamp_utc`.

This is close but has two gaps:

1. **Source IP / caller context**: The requestor_id comes from the request body (self-reported). You should also log the actual client IP from the HTTP request headers (`X-Forwarded-For` behind a proxy). A requestor can misidentify themselves in the body; the network address is harder to spoof.

2. **Model version hash**: `model_version: "1.0.0"` is a human-assigned string that could be reused across retraining cycles. Log the MLflow run_id or the SHA of the model artifact instead — that's immutable and lets you reconstruct the exact model that produced any prediction.

Updated log record:
```python
{
    "event_type": "model_inference",
    "request_id": request_id,
    "requestor_id": requestor_id,
    "client_ip": client_ip,           # from HTTP header
    "model_version": model_version,
    "model_run_id": MLFLOW_RUN_ID,    # module-level constant, set at startup
    "input": input_data,
    "prediction": prediction,
    "risk_tier": risk_tier,
    "latency_ms": round(latency_ms, 2),
    "timestamp_utc": datetime.now(timezone.utc).isoformat(),
}
```

---

## Exercise 4: Keep-Warm Script — Solution

```python
import os
import time
import requests
import logging
from datetime import datetime

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s"
)
logger = logging.getLogger("keep_warm")

ENDPOINT_URL = (
    f"https://{os.environ['DATABRICKS_HOST']}"
    "/serving-endpoints/don-maintenance-risk-prod/invocations"
)
DATABRICKS_TOKEN = os.environ["DATABRICKS_TOKEN"]

WARMUP_PAYLOAD = {
    "dataframe_records": [{
        "days_since_last_maintenance": 90,
        "component_age_years": 5.0,
        "operational_hours_30d": 300,
        "deficiency_count_ytd": 1,
        "fy_quarter": 2,
    }]
}

def warm_endpoint(url: str, token: str, max_retries: int = 8) -> bool:
    """
    Send a warmup request, retrying with exponential backoff on 503.
    Returns True on first 200 response, False after max_retries.
    """
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }

    wait_seconds = 10  # Start with 10s, double each retry

    for attempt in range(1, max_retries + 1):
        try:
            logger.info(f"Warmup attempt {attempt}/{max_retries}")
            response = requests.post(url, headers=headers, json=WARMUP_PAYLOAD, timeout=15)

            if response.status_code == 200:
                logger.info(f"Endpoint warm on attempt {attempt}")
                return True

            if response.status_code == 503:
                # Endpoint still spinning up — expected during cold start
                logger.warning(f"Endpoint returning 503 (starting up), waiting {wait_seconds}s")
                time.sleep(wait_seconds)
                wait_seconds = min(wait_seconds * 2, 120)  # Cap at 2 minutes
                continue

            # Any other error (4xx, 5xx) is unexpected — log and stop
            logger.error(
                f"Unexpected response {response.status_code}: {response.text[:200]}"
            )
            return False

        except requests.exceptions.Timeout:
            logger.warning(f"Request timed out on attempt {attempt}, waiting {wait_seconds}s")
            time.sleep(wait_seconds)
            wait_seconds = min(wait_seconds * 2, 120)

        except requests.exceptions.ConnectionError as e:
            logger.error(f"Connection error: {e}")
            return False

    logger.error(f"Endpoint did not warm after {max_retries} attempts")
    return False


if __name__ == "__main__":
    logger.info(f"Starting warmup at {datetime.now().isoformat()}")
    success = warm_endpoint(ENDPOINT_URL, DATABRICKS_TOKEN)

    if success:
        logger.info("Endpoint warm — dashboard ready for 0700 briefing")
    else:
        logger.error("Endpoint failed to warm — escalate to platform team")
        # In production: send alert to ops channel (PagerDuty, Slack, Teams)
        # pagerduty_alert("don-maintenance-dashboard", "Endpoint failed warmup at 0645")
        exit(1)
```

**Note on the cron schedule**: This runs at 0645 local (15 minutes before the 0700 dashboard check). Set it in Databricks Workflows using a cron expression `45 6 * * 1-5` (weekdays only — no one checks the dashboard at 0700 on Saturday). The warmup job itself runs on a single-node cluster, not the full scoring cluster — keep the cost minimal.

---

## Exercise 5: Distributed Scoring Performance Analysis — Solution

**Given data**:
- Sample size: 100K records
- Without broadcast: 4 min 20 sec = 260 seconds
- With broadcast: 38 seconds
- Cluster: 4 nodes × 4 executors = 16 executors
- Model size: 180MB

**Answer 1 — Network overhead per executor**:

The time difference is `260 - 38 = 222 seconds` for 100K records on 16 executors.

Without broadcast, each executor downloads the 180MB model artifact for every partition it processes. If each executor processes ~5 partitions during the 100K-record job, each executor downloads the model 5 times: `5 × 180MB = 900MB per executor`.

At 222 seconds saved across 16 executors, each executor saves roughly `222/16 ≈ 14 seconds` on model loading overhead. That implies a download rate of roughly `900MB / 14s ≈ 64 MB/s` per executor — consistent with shared cluster network.

**Answer 2 — Full-scale extrapolation**:

100K records → 5M records is 50x the data.

- Without broadcast: `260s × 50 = 13,000s ≈ 3.6 hours`
- With broadcast: `38s × 50 = 1,900s ≈ 32 minutes`

(Real-world speedup will be somewhat worse without broadcast at scale because more executors competing for the artifact store creates contention. The broadcast advantage grows with cluster size.)

**Answer 3 — Annual cost**:

At $8/hour:

- Without broadcast: 3.6 hours/night × $8 × 365 = **$10,512/year**
- With broadcast: 32 min/night = 0.53 hours × $8 × 365 = **$1,562/year**
- **Annual savings: ~$8,950**

For a single model on one program. Multiply across a fleet of models and programs and the broadcast pattern pays for itself many times over.

**Answer 4 — When NOT to use broadcast**:

1. **Very large models (>2GB)**: Broadcasting a 2GB model to 32 executors means 64GB of memory is consumed just for model artifacts. On a cluster where worker nodes have 16GB RAM, this kills the job. Evaluate model size before broadcasting — if it's over 1GB, consider model quantization or a different deployment pattern (shared model server).

2. **Highly parallel clusters with fast artifact stores**: If you're running on a 64-node cluster where the artifact store is a co-located S3-compatible store with sub-second download times, the broadcast overhead (serializing a large object through the driver) can exceed the download time. Profile before assuming broadcast always wins.

**Answer 5 — Partition size tuning**:

The default partition size in Spark is controlled by `spark.sql.files.maxPartitionBytes` (default: 128MB). For Pandas UDF workloads, the overhead of calling a Python function once per partition means you want fewer, larger partitions.

```python
spark.conf.set("spark.sql.files.maxPartitionBytes", "512m")  # 4x default
# or for existing DataFrames:
df = df.repartition(200)  # Explicitly coalesce into 200 partitions
```

**Trade-off**: Larger partitions mean each executor holds more data in memory per task. If you have 16 executors and 200 partitions, peak memory per executor is proportionally higher. On clusters with limited memory per worker, oversized partitions cause OOM errors. The right size is typically `total_data_size / (num_executors × desired_tasks_per_executor)` where `desired_tasks_per_executor` is 2-4.

---

## Exercise 6: Cross-Platform Model Deployment — Solution

| Pattern | Runtime | Auth | Audit storage | Retraining update mechanism |
|---------|---------|------|--------------|----------------------------|
| **Qlik dashboard** | Databricks Model Serving endpoint (always-on, invoked via Qlik SSE) | PAT stored in Qlik Server environment variables; SSE calls endpoint with Bearer token | Inference logs written to Delta table `audit.inference_log` via the FastAPI app running alongside the endpoint | Update serving endpoint config to point to new model version number; zero-downtime swap in Databricks endpoint management |
| **Foundry investigation** | Palantir Foundry pipeline (`@transform`) invoked via ModelInput | Foundry service account token; investigators authenticate to Foundry via CAC/SSO | Foundry lineage graph records which model version produced each scored dataset; Foundry Action log captures investigator queries | Update the ModelInput reference in the transform to the new registered model version; re-run transform to regenerate scored dataset |
| **Advana batch audit** | Databricks Job (Pandas UDF) on Unity Catalog data | Databricks PAT for the Job service account; Unity Catalog governs table-level access | Write scored records with `model_version` column to Delta table; Delta time travel enables point-in-time reconstruction | Update the `model_uri` in the Job configuration; trigger a backfill run for any records scored under the old version if needed |

**Bonus — Version consistency problem**:

The gap scenario: the batch job runs at 0200 with model v2. At 0800, a contracting officer queries a contract that was created at 0400 (after the batch run). The Qlik SSE calls the serving endpoint, which now runs model v3 (just deployed at 0700 after retraining). The batch score and the live score come from different models.

**Detection**: Include a `model_version` field in both the batch score table and the live endpoint response. In Qlik, display the model version alongside the score. If a user sees "Batch score: 0.72 (v2) | Live score: 0.68 (v3)", the discrepancy is visible. Add a Qlik alert for cases where `|batch_score - live_score| > 0.15` — that threshold triggers a review.

**Handling**: Two options depending on acceptable staleness:

1. **Batch-first policy**: The authoritative score for official actions (contract holds, audit flags) is always the batch score. Live endpoint scores are marked "preliminary" in the UI until the next batch run replaces them. Simple, clear, but introduces up to 24 hours of staleness.

2. **Rolling update policy**: When a new model is deployed to the serving endpoint, trigger a partial batch re-score of contracts created since the last batch run. This closes the gap but adds complexity — you need to track which records were scored by which model and when.

Most government programs use option 1. The batch score goes into the official record; the live score helps officers prioritize their queue but carries a "preliminary" label.
