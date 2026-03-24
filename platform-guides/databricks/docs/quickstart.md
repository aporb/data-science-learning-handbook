# Databricks Quickstart Guide

This guide supplements [`cac-piv-integration.md`](../cac-piv-integration.md)
with a condensed getting-started walkthrough for Databricks on DoD networks.

## Prerequisites

- CAC/PIV card and reader
- Databricks workspace URL and cluster access
- Python 3.9+ with packages from `requirements.txt`
- `databricks-sdk` or `databricks-connect` installed
- Environment variables configured (see [`config/databricks_config.yaml`](../config/databricks_config.yaml))

## 1. Install Databricks CLI and SDK

```bash
pip install databricks-sdk databricks-connect
```

Verify installation:

```bash
databricks --version
```

## 2. Configure environment variables

```bash
export DATABRICKS_HOST=https://adb-XXXXXXXX.azuredatabricks.net
export DATABRICKS_TOKEN=dapi...
export DATABRICKS_CLUSTER_ID=XXXX-XXXXXX-XXXXXXXX
export PKCS11_LIB_PATH=/usr/lib/opensc-pkcs11.so
export CAC_CA_BUNDLE_PATH=/etc/pki/dod-ca-bundle.pem
```

## 3. Authenticate with CAC/PIV

```python
import sys
sys.path.insert(0, "security-compliance")  # from repo root

from auth.platform_adapters.databricks_adapter import DatabricksAdapter

adapter = DatabricksAdapter(
    config_path="platform-guides/databricks/config/databricks_config.yaml"
)
auth_result = adapter.authenticate()

if auth_result.success:
    print(f"Authenticated as: {auth_result.user_info['email']}")
else:
    print(f"Authentication failed: {auth_result.error}")
```

## 4. Run a notebook or job

```python
from databricks.sdk import WorkspaceClient

client = WorkspaceClient(
    host=auth_result.workspace_url,
    token=auth_result.access_token,
)

# List available clusters
clusters = client.clusters.list()
for c in clusters:
    print(f"{c.cluster_id}: {c.cluster_name} [{c.state}]")
```

## 5. Use with pandas / MLflow

```python
import mlflow
import pandas as pd

mlflow.set_tracking_uri("databricks")
mlflow.set_experiment("/Shared/handbook-experiments")

with mlflow.start_run():
    df = pd.read_csv("data/sample.csv")
    mlflow.log_param("rows", len(df))
    mlflow.log_metric("mean_value", df["value"].mean())
```

## Troubleshooting

| Symptom | Likely cause | Fix |
|---------|-------------|-----|
| `RESOURCE_DOES_NOT_EXIST` | Wrong cluster ID | Verify `DATABRICKS_CLUSTER_ID` in workspace |
| `INVALID_STATE` cluster | Cluster is terminated | Start cluster in UI or via API |
| `403 Forbidden` | Token lacks permissions | Generate new PAT with correct scopes |
| SSL errors | CA bundle missing | Set `REQUESTS_CA_BUNDLE` env var |

## Next Steps

- Read the full [CAC/PIV integration guide](../cac-piv-integration.md)
- See [Databricks adapter source](../../../security-compliance/auth/platform_adapters/databricks_adapter.py)
- Review [MLflow tracking setup](../../../chapters/09-mlops/README.md) for experiment tracking patterns
