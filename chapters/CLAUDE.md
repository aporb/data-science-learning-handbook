# Chapters — Agent Context

13 chapters covering the full data science lifecycle on federal platforms. Each chapter has a README.md (prose content) and code-examples/python/ (working Python files). Content is QA-signed-off — do not modify.

## Chapter Index

| Ch | Directory | Code Files | Key Libraries | Key Topics |
|----|-----------|-----------|---------------|------------|
| 01 | `01-introduction/` | 3 (platform_connections, authentication_patterns, environment_verification) | stdlib, requests | CAC, IL levels, 5 platforms, ATO |
| 02 | `02-python-r-foundations/` | 3 (environment_setup, platform_specific_imports, data_structures) | importlib, platform | Air-gapped pip, conda, platform imports |
| 03 | `03-data-acquisition/` | 3 (api_connections, government_data_sources, platform_data_catalogs) | requests, pandas | USASpending, SAM.gov, data.gov |
| 04 | `04-data-wrangling/` | 3 (pandas_cleaning, spark_transforms, palantir_pipeline_builder) | pandas, pyspark, delta | 47M-row procurement data, Delta Lake |
| 05 | `05-exploratory-analysis/` | 3 (statistical_profiling, visualization_eda, platform_eda_workflows) | pandas, scipy, matplotlib | Headless EDA, no-notebook platforms |
| 06 | `06-supervised-ml/` | 3 (classification_pipeline, regression_and_xgboost, mlflow_and_batch_scoring) | sklearn, xgboost, mlflow | MILSTRIP features, DoD classifiers |
| 07 | `07-unsupervised-ml/` | 4 (clustering, anomaly_detection, dimensionality_reduction, topic_modeling) | sklearn, scipy | GFEBS anomaly detection, readiness clustering |
| 08 | `08-deep-learning/` | 6 (neural_net_fundamentals, tabular_neural_net, cnn_image_classification, cnn_satellite_imagery, transformer_nlp, operational_inference_pipeline) | torch, torchvision, onnx | Drone video CNN, 400ms inference budget |
| 09 | `09-mlops/` | 3 (experiment_tracking, model_registry_deployment, pipeline_orchestration) | mlflow, sklearn, evidently | MLflow, model registry, drift detection |
| 10 | `10-visualization/` | 3 (matplotlib_seaborn_charts, plotly_interactive, platform_dashboards) | plotly, matplotlib, seaborn | Qlik, Advana dashboards, briefing design |
| 11 | `11-deployment/` | 3 (deployment_patterns, api_serving, platform_deployment) | fastapi, mlflow | Containers, API gateways, ATO process |
| 12 | `12-ethics-governance/` | 3 (bias_audit, model_card, nist_rmf_workflow) | sklearn, fairlearn | DoD AI Ethics, NIST AI RMF, bias auditing |
| 13 | `13-advanced-topics/` | 3 (llm_integration, rag_pipeline, aip_agents) | transformers, faiss, langchain | RAG at IL5, AIP Logic, classified fine-tuning |

**Total: 43 Python files across 13 chapters.**

## Code Example Format

Every code file starts with a docstring header:
```python
"""
Title
Description
Platform: [Databricks | Foundry | Advana | Local | Any]
Usage: [how to run]
"""
```

When generating new code, match this format exactly.

## Learning Objective Cross-Map

| Learning Goal | Primary Chapter | Supporting Chapters |
|---------------|----------------|-------------------|
| Understand ATO and compliance | 01 | 09, 11, 12 |
| Set up Python environment on a platform | 02 | Platform guides |
| Access federal data sources | 03 | 04 |
| Clean and wrangle data at scale | 04 | 05 |
| Build ML classifiers on DoD data | 06 | 07, 09 |
| Deploy models in federal environments | 11 | 09, 12 |
| Audit models for ethics/bias | 12 | 06, 13 |
| Build GenAI/RAG at IL4+ | 13 | 09, 12 |

## Common Agent Tasks

- **"Explain chapter N"** → Read `NN-name/README.md`, summarize the "What You'll Build" section + first 3 major sections
- **"Show me code for X"** → Identify the chapter from the index above, find the matching code file, show the docstring first then walk through sections
- **"Generate code for Y on [platform]"** → Use `/generate-federal-code`, reference ch02 platform constraints first
- **"What exercises are available?"** → Each chapter has an `exercises/` directory with problems and solutions
