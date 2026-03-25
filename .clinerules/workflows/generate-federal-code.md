# Generate Federal-Compliant Code

Generate Python code following handbook patterns for federal platform contexts.

## Step 1: Clarify requirements

<ask_followup_question>
<question>What are you building?</question>
<options>["ML classifier/model", "Data pipeline/ETL", "RAG/LLM integration", "API/deployment", "Dashboard/visualization", "Other"]</options>
</ask_followup_question>

## Step 2: Identify target platform

<ask_followup_question>
<question>Which platform?</question>
<options>["Databricks", "Palantir Foundry", "Advana/JupyterHub", "Navy Jupiter", "Local/Docker", "Multi-platform"]</options>
</ask_followup_question>

## Step 3: Identify classification level

<ask_followup_question>
<question>What classification level?</question>
<options>["IL2 (public/CUI)", "IL4 (controlled)", "IL5 (higher controlled)", "Not sure"]</options>
</ask_followup_question>

## Step 4: Load platform constraints

<read_file>
<path>chapters/02-python-r-foundations/code-examples/python/02_platform_specific_imports.py</path>
</read_file>

This file shows the standard platform detection and import pattern used across all chapters. Use it as the foundation.

## Step 5: Load the most relevant code template

Find the closest matching existing code example based on what the user is building:
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

Read the template file to understand the pattern.

## Step 6: Generate code

Generate the code with these requirements:
- Start with the required docstring header: Title, Description, `Platform:`, `Usage:`
- Follow the platform detection pattern from Step 4
- Apply platform constraints: no pip install in Databricks cells, use dbutils.secrets, etc.
- At IL4+: no external API calls with data, self-hosted models only
- Never hardcode credentials
- Include error handling for platform-specific failure modes

## Step 7: Point to related handbook sections

After generating code, point to 2-3 related handbook sections:
- The chapter README that covers the concept
- Related code examples showing alternative approaches
- Security patterns from `security-compliance/` if auth or compliance is involved
