# Chapter 11 Exercises: Deployment & Scaling

These exercises simulate decisions you'll face getting ML models into production on federal platforms. The scenarios are drawn from real patterns in DoN and DoD analytics programs — you won't find answers in the first Google result.

---

## Exercise 1: Deployment Pattern Selection

**Scenario**: Your team built a supply chain disruption model for a Navy logistics program. You need to choose a deployment pattern. Here are the constraints:

- The model needs to score ~2 million records nightly (all active contracts)
- Logistics officers also need to query individual contracts on demand from a Qlik dashboard (latency budget: under 5 seconds)
- The environment is IL4 (Databricks FedRAMP Moderate is available; Palantir Foundry IL4 is available)
- The contract data lives in Databricks Unity Catalog
- Budget allows for one always-on resource OR two scale-to-zero resources

**Task**: Design the deployment architecture. Answer:

1. What pattern handles the nightly 2-million-record batch scoring? Where does it run and why?
2. What pattern handles the on-demand single-contract queries from Qlik? What's your cold-start strategy?
3. How do the two patterns share model artifacts, or do they use separate copies?
4. Draw a simple architecture diagram (can be text-based) showing data flow from Unity Catalog → model → Qlik dashboard.

**Starter for diagram**:
```
Unity Catalog (contracts_current)
         │
         ├──[batch nightly]──→ ??? ──→ ???
         │
         └──[on-demand query]──→ ??? ──→ Qlik Dashboard
```

---

## Exercise 2: FastAPI Inference Service with Authentication

The FastAPI app in `code-examples/python/01_deployment_patterns.py` has a working `/score` endpoint, but it's missing authentication. In a DoD IL4 environment, every API must verify the caller's identity.

**Task**: Extend the FastAPI app to add token-based authentication using HTTP Bearer tokens. Your implementation must:

1. Read a valid token from an environment variable (`INFERENCE_API_TOKEN`)
2. Reject requests without a valid Authorization header with HTTP 401
3. Reject requests with an invalid token with HTTP 403 (not 401 — this distinction matters for logging)
4. Continue to log the requestor identity (from the token or the `requestor_id` field) in the audit trail

**Starter code** — implement the `verify_token` function:

```python
from fastapi import Depends, HTTPException, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

security = HTTPBearer()

def verify_token(credentials: HTTPAuthorizationCredentials = Security(security)) -> str:
    """
    Verify the Bearer token and return the requestor identity.

    Rules:
    - No Authorization header → 401 (HTTPBearer handles this automatically)
    - Token present but wrong → 403
    - Token valid → return the token value as requestor identity

    In production this would validate against a token store or verify a JWT.
    For this exercise, treat any token matching INFERENCE_API_TOKEN as valid.
    """
    # TODO: Implement token verification
    # Hint: os.environ.get("INFERENCE_API_TOKEN") gives you the expected token
    # Hint: credentials.credentials is the token string from the Authorization header
    pass
```

**Extension question**: Why does this exercise distinguish between 401 and 403? What does each status code communicate to the caller and to your SIEM system?

---

## Exercise 3: ATO Evidence Package Checklist

You've built a maintenance risk model and deployed it as a FastAPI container on an IL4 Kubernetes cluster. Your ISSO has asked for evidence to support the ATO package.

**Task**: Create an ATO evidence checklist for this deployment. The checklist should cover these four areas (at minimum two specific evidence items per area):

| Area | Evidence Items |
|------|---------------|
| Model documentation | |
| Data handling | |
| Access control | |
| Monitoring & audit | |

For each evidence item, note:
- What artifact or record provides the evidence
- Where that artifact lives (code repo, MLflow, Kubernetes manifest, etc.)
- Who is responsible for maintaining it (data scientist, platform engineer, ISSO)

**Bonus**: One of the most common ATO findings for ML systems is "model inputs and outputs are not logged with sufficient detail to reconstruct a prediction." Review the `log_inference_event()` function in the code examples. Is it sufficient? What would you add?

---

## Exercise 4: Cold Start Mitigation for Scale-to-Zero Endpoints

Your Databricks Model Serving endpoint is deployed with `scale_to_zero_enabled=True` to save costs. The endpoint starts up in 45-90 seconds after a period of inactivity. Operations staff check the maintenance dashboard every morning at 0700 and complain about slow load times.

**Task**: Write a Python "keep-warm" script that:

1. Runs as a scheduled cron job at 0645 (15 minutes before the first daily use)
2. Sends a minimal valid request to the endpoint
3. Handles the case where the endpoint returns a 503 (still spinning up) by retrying with backoff
4. Logs success/failure for ops visibility

```python
import time
import requests
import logging
from datetime import datetime

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("keep_warm")

ENDPOINT_URL = "https://{databricks_host}/serving-endpoints/don-maintenance-risk-prod/invocations"
DATABRICKS_TOKEN = os.environ["DATABRICKS_TOKEN"]

# Minimal valid payload — one record that exercises the full scoring path
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
    Send a warmup request to the endpoint, retrying if it's still starting up.
    Returns True if the endpoint warmed successfully, False if max retries exceeded.

    TODO: Implement with exponential backoff.
    - First retry after 10 seconds
    - Double wait time on each subsequent retry (10, 20, 40, 80...)
    - Log each attempt with attempt number and wait time
    - Return True on first 200 response
    - Return False after max_retries without a 200
    """
    pass

if __name__ == "__main__":
    success = warm_endpoint(ENDPOINT_URL, DATABRICKS_TOKEN)
    if success:
        logger.info("Endpoint warm — dashboard ready for 0700 briefing")
    else:
        logger.error("Endpoint failed to warm — escalate to platform team")
```

---

## Exercise 5: Distributed Scoring Performance Analysis

You need to score 5 million records using a Pandas UDF in Databricks. Before running on the full dataset, you run a benchmark on a 100K-record sample.

**Benchmark results**:
- Without broadcast: 4 minutes 20 seconds (model artifact is 180MB)
- With broadcast: 38 seconds

**Task**: Answer these questions using the numbers above:

1. **Calculate the network overhead**: How much time per executor is being spent on model artifact retrieval without broadcast? Assume a 4-node cluster where each node runs 4 executors.

2. **Extrapolate to full scale**: If the linear scaling holds (it won't perfectly, but use it for estimation), what would you expect the full 5M-record job to take with and without broadcast?

3. **Budget impact**: If your Databricks cluster costs $8/hour and the job runs nightly, what is the annual cost difference between the two approaches?

4. **When would you NOT use broadcast?** Identify two scenarios where the broadcast pattern creates problems rather than solving them.

5. **Partition size tuning**: The default Spark partition size is often too small for Pandas UDF workloads because function call overhead dominates. What Spark configuration would you change to increase partition size, and what's the trade-off?

---

## Exercise 6: Cross-Platform Model Deployment Scenario

**Scenario**: You're a senior data scientist on an Advana program. Your team has trained a contract anomaly detection model that flags potentially fraudulent procurement actions. The model needs to be available in three different contexts:

- **Contracting officers** use a Qlik dashboard for day-to-day review
- **Investigators** use Palantir Foundry for deep-dive analysis with ontology context
- **Batch audit** runs nightly on the full Advana data lake (Databricks)

The model artifact is stored in the Advana MLflow registry.

**Task**: Design the deployment architecture for all three consumption patterns.

For each pattern, specify:
1. Where the model runs (Databricks endpoint, Foundry pipeline, Qlik SSE, etc.)
2. How it authenticates
3. How prediction audit records are stored
4. What happens when the model is retrained — how does each deployment get updated?

Present your answer as a table:

| Pattern | Runtime | Auth | Audit storage | Retraining update mechanism |
|---------|---------|------|--------------|----------------------------|
| Qlik dashboard | | | | |
| Foundry investigation | | | | |
| Advana batch audit | | | | |

**Bonus**: This architecture has a consistency problem. When the model is retrained between the nightly batch run and a contracting officer's daytime query, they might see different scores for the same contract. Describe how you'd detect and handle this discrepancy.
