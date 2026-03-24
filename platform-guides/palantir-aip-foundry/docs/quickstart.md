# Palantir AIP / Foundry Quickstart Guide

This guide provides a condensed getting-started path. See the main
[README](../README.md) for full conceptual context on Foundry's architecture.

## Prerequisites

- Access to a Foundry tenant (IL4/IL5/IL6 or commercial)
- Foundry Multipass token or service account credentials
- Python 3.9+
- Environment variables configured (see [`config/palantir_config.yaml`](../config/palantir_config.yaml))

## 1. Install the Foundry SDK

```bash
# Core SDK
pip install foundry-platform-sdk

# If using palantir_models for ML
pip install palantir-models
```

## 2. Configure environment variables

```bash
export FOUNDRY_HOSTNAME=your-tenant.palantirfoundry.com
export FOUNDRY_TOKEN=your-multipass-token
export FOUNDRY_ONTOLOGY_RID=ri.ontology.main.object-type.XXXX
```

For CAC/PIV authentication through a DoD IdP:

```bash
export PKCS11_LIB_PATH=/usr/lib/opensc-pkcs11.so
export CAC_CA_BUNDLE_PATH=/etc/pki/dod-ca-bundle.pem
export PALANTIR_CLIENT_ID=your-client-id
export PALANTIR_AUTH_ENDPOINT=https://sso.example.mil/oauth/authorize
```

## 3. Connect to Foundry

```python
import os
from foundry import FoundryClient
from foundry.auth import UserTokenAuth

client = FoundryClient(
    auth=UserTokenAuth(token=os.environ["FOUNDRY_TOKEN"]),
    hostname=os.environ["FOUNDRY_HOSTNAME"],
)
print("Connected to Foundry:", os.environ["FOUNDRY_HOSTNAME"])
```

## 4. Load a dataset

```python
# By Compass path
dataset = client.datasets.get_by_path("/path/to/dataset")
df = dataset.read_table().to_pandas()
print(df.shape)

# By RID
dataset = client.datasets.get("ri.foundry.main.dataset.XXXX")
```

## 5. Write a transform (Code Repository)

Transforms in Foundry are written in Python using the `transforms` library:

```python
from transforms.api import transform_df, Input, Output

@transform_df(
    Output("/output/dataset"),
    source=Input("/input/dataset"),
)
def compute(source):
    """Filter and aggregate source dataset."""
    return source.filter(source["status"] == "active").groupBy("category").count()
```

## 6. Work with the Ontology

```python
from foundry.ontology import OntologyClient

ontology = OntologyClient(
    auth=UserTokenAuth(token=os.environ["FOUNDRY_TOKEN"]),
    hostname=os.environ["FOUNDRY_HOSTNAME"],
)

# List object types
for ot in ontology.object_types.list():
    print(f"  {ot.api_name}: {ot.plural_display_name}")

# Query objects
objects = ontology.objects.search(object_type="Aircraft", limit=10)
for obj in objects:
    print(obj.properties)
```

## 7. Use AIP Logic (LLM integration)

```python
from foundry.aip import AIPClient

aip = AIPClient(
    auth=UserTokenAuth(token=os.environ["FOUNDRY_TOKEN"]),
    hostname=os.environ["FOUNDRY_HOSTNAME"],
)

response = aip.complete(
    model_rid=os.environ.get("AIP_MODEL_RID"),
    prompt="Summarize the key trends in this dataset: ...",
    max_tokens=500,
)
print(response.text)
```

## Troubleshooting

| Symptom | Likely cause | Fix |
|---------|-------------|-----|
| `401 Unauthorized` | Token expired | Refresh Multipass token in Foundry UI |
| `403 Forbidden` | No access to dataset/object | Request permissions from catalog owner |
| `Dataset not found` | Wrong Compass path | Verify path in Foundry Catalog |
| SSL errors | Missing CA bundle | Set `REQUESTS_CA_BUNDLE` env var |
| Transform build failure | Dependency issue | Check `build.gradle` or `setup.py` in code repo |

## Next Steps

- Read the full [platform guide](../README.md) for Ontology design patterns
- Review [MLOps chapter](../../../chapters/09-mlops/README.md) for model lifecycle patterns
- See [penetration testing framework](../../../security-compliance/penetration-testing/) for security testing approaches
