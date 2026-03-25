---
description: Generate platform-appropriate Python following handbook patterns for federal contexts
---

# Generate Federal-Compliant Code

Generate Python code following this handbook's patterns for federal platform contexts.

## Input

$ARGUMENTS

If no arguments provided, ask: What are you building, which platform, and what classification level?

## Always read first

@chapters/02-python-r-foundations/code-examples/python/02_platform_specific_imports.py

## Platform constraints

- **Databricks**: No pip install in cells, use cluster libraries, `dbutils.secrets` for credentials
- **Foundry**: Use `palantir_models` for publishing, Pipeline Builder for orchestration, no direct file I/O
- **Advana/Jupiter**: JupyterHub shared cluster, no sudo, conda environments
- **All IL4+**: No external API calls with data, self-hosted models only
- **All**: Env vars or secret management for credentials, never hardcode

## Required code header format

Every generated file must start with:
```python
"""
Title
Description
Platform: [Databricks | Foundry | Advana | Local | Any]
Usage: [how to run]
"""
```

## Template files by task type

Find the closest match and use it as a pattern:
- Auth: `security-compliance/auth/oauth_cac_bridge.py`
- Data ingestion: `chapters/03-data-acquisition/code-examples/python/01_api_connections.py`
- Spark/Delta: `chapters/04-data-wrangling/code-examples/python/02_spark_transforms.py`
- ML classifier: `chapters/06-supervised-ml/code-examples/python/01_classification_pipeline.py`
- Anomaly detection: `chapters/07-unsupervised-ml/code-examples/python/02_anomaly_detection.py`
- Deep learning: `chapters/08-deep-learning/code-examples/python/01_neural_network_fundamentals.py`
- MLflow: `chapters/09-mlops/code-examples/python/01_experiment_tracking.py`
- API serving: `chapters/11-deployment/code-examples/python/02_api_serving.py`
- Bias audit: `chapters/12-ethics-governance/code-examples/python/01_bias_audit.py`
- RAG pipeline: `chapters/13-advanced-topics/code-examples/python/02_rag_pipeline.py`
- LLM integration: `chapters/13-advanced-topics/code-examples/python/01_llm_integration.py`

After generating, point to 2-3 related handbook sections for deeper context.
