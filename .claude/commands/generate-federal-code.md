# Generate Federal-Compliant Code

Generate Python code following this handbook's patterns for federal platform contexts.

## Input

$ARGUMENTS

If no arguments provided, ask: What are you building, which platform, and what classification level?

## Instructions

### Step 1: Clarify requirements (if not specified)

Determine these three things:
1. **What** — classifier, pipeline, dashboard, API, RAG system, data ingestion, etc.
2. **Platform** — Databricks, Foundry, Advana/JupyterHub, Navy Jupiter, Qlik, local, or multi-platform
3. **Classification level** — CUI, IL2, IL4, IL5 (affects what external services are available)

### Step 2: Load platform constraints

ALWAYS read first:
- `chapters/02-python-r-foundations/code-examples/python/02_platform_specific_imports.py` — the standard platform detection and import pattern used across all chapters

Then load the most relevant existing code example as a template:

| Task Type | Template File |
|-----------|--------------|
| Authentication/access | `security-compliance/auth/oauth_cac_bridge.py` |
| Data ingestion/API | `chapters/03-data-acquisition/code-examples/python/01_api_connections.py` |
| Data cleaning/wrangling | `chapters/04-data-wrangling/code-examples/python/01_pandas_cleaning.py` |
| Spark/Delta Lake transforms | `chapters/04-data-wrangling/code-examples/python/02_spark_transforms.py` |
| Palantir Pipeline Builder | `chapters/04-data-wrangling/code-examples/python/03_palantir_pipeline_builder.py` |
| Statistical profiling/EDA | `chapters/05-exploratory-analysis/code-examples/python/01_statistical_profiling.py` |
| ML classification pipeline | `chapters/06-supervised-ml/code-examples/python/01_classification_pipeline.py` |
| XGBoost/regression | `chapters/06-supervised-ml/code-examples/python/02_regression_and_xgboost.py` |
| Anomaly detection | `chapters/07-unsupervised-ml/code-examples/python/02_anomaly_detection.py` |
| Clustering | `chapters/07-unsupervised-ml/code-examples/python/01_clustering.py` |
| Neural network/deep learning | `chapters/08-deep-learning/code-examples/python/01_neural_network_fundamentals.py` |
| CNN/image classification | `chapters/08-deep-learning/code-examples/python/02_cnn_image_classification.py` |
| NLP/transformers | `chapters/08-deep-learning/code-examples/python/03_transformer_nlp.py` |
| MLflow experiment tracking | `chapters/09-mlops/code-examples/python/01_experiment_tracking.py` |
| Model registry/deployment | `chapters/09-mlops/code-examples/python/02_model_registry_deployment.py` |
| Visualization/charts | `chapters/10-visualization/code-examples/python/01_matplotlib_seaborn_charts.py` |
| Interactive dashboards | `chapters/10-visualization/code-examples/python/02_plotly_interactive.py` |
| API serving | `chapters/11-deployment/code-examples/python/02_api_serving.py` |
| Container deployment | `chapters/11-deployment/code-examples/python/03_platform_deployment.py` |
| Bias audit | `chapters/12-ethics-governance/code-examples/python/01_bias_audit.py` |
| Model card | `chapters/12-ethics-governance/code-examples/python/02_model_card.py` |
| LLM integration | `chapters/13-advanced-topics/code-examples/python/01_llm_integration.py` |
| RAG pipeline | `chapters/13-advanced-topics/code-examples/python/02_rag_pipeline.py` |
| AIP/agent workflows | `chapters/13-advanced-topics/code-examples/python/03_aip_agents.py` |

### Step 3: Generate code with required format

Every generated file MUST start with this docstring header:
```python
"""
[Descriptive Title]
[What this code does and the use case it serves]
Platform: [Databricks | Foundry | Advana | Local | Any]
Usage: [exactly how to run it — notebook cell, python command, etc.]
"""
```

### Platform constraints to enforce

**Databricks:**
- SparkSession is pre-initialized — get it, don't create it
- No `pip install` in notebook cells — use cluster-installed libraries
- Use `dbutils.secrets.get(scope, key)` for credentials
- Use Unity Catalog for data governance

**Foundry:**
- Use `palantir_models` for model publishing
- Use Pipeline Builder or `@transform_df` decorators for data pipelines
- No direct file I/O — use Foundry datasets
- Use Foundry's built-in secret management

**Advana / Navy Jupiter:**
- JupyterHub on shared cluster — no sudo, no system installs
- Use conda environments for package management
- Shared file system — be careful with paths and permissions

**All platforms at IL4+:**
- No external API calls with data (no OpenAI, no HuggingFace hosted inference)
- Self-hosted models only — use platform-provided or locally deployed models
- Self-hosted embeddings for RAG (see ch13 RAG pipeline example)
- All data must stay within the classification boundary

**All platforms:**
- Environment variables or platform secret management for credentials — never hardcode
- Logging over print statements for production code
- Include error handling for platform-specific failure modes

### Step 4: After generating code

Point to 2-3 related handbook sections for deeper context:
- The chapter README that covers the concept
- Related code examples that show alternative approaches
- Security patterns from `security-compliance/` if auth or compliance is involved
