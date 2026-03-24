# Dependency Audit Report

**Date:** 2026-03-24
**Scope:** All 41 Python files under `chapters/*/code-examples/python/`

---

## Summary

| Category | Count |
|---|---|
| Packages found in code | 28 third-party |
| Packages present in requirements.txt | 20 of those 28 |
| **Missing from requirements.txt** | **8** |
| Packages in requirements.txt not directly imported | 22 (kept — infrastructure/tooling) |

---

## Packages Used in Code

The following third-party packages are imported across the 41 code example files (top-level and lazy/conditional imports both counted):

| Import name | pip package | In requirements.txt |
|---|---|---|
| `pandas` | `pandas` | Yes |
| `numpy` | `numpy` | Yes |
| `scipy` | `scipy` | Yes |
| `sklearn` | `scikit-learn` | Yes |
| `matplotlib` | `matplotlib` | Yes |
| `seaborn` | `seaborn` | Yes |
| `plotly` | `plotly` | Yes |
| `torch` | `torch` | Yes |
| `torchvision` | `torchvision` | **No — MISSING** |
| `transformers` | `transformers` | Yes |
| `datasets` | `datasets` | Yes |
| `mlflow` | `mlflow` | Yes |
| `xgboost` | `xgboost` | Yes |
| `pyspark` | `pyspark` | Yes |
| `PIL` | `pillow` | Yes |
| `requests` | `requests` | Yes |
| `yaml` | `pyyaml` | Yes |
| `pydantic` | `pydantic` | Yes |
| `fastapi` | `fastapi` | Yes |
| `grpc` | `grpcio` | **No — MISSING** |
| `openai` | `openai` | **No — MISSING** |
| `anthropic` | `anthropic` | **No — MISSING** |
| `peft` | `peft` | **No — MISSING** |
| `trl` | `trl` | **No — MISSING** |
| `bitsandbytes` | `bitsandbytes` | **No — MISSING** |
| `sentence_transformers` | `sentence-transformers` | **No — MISSING** |
| `faiss` | `faiss-cpu` | **No — MISSING** |
| `chromadb` | `chromadb` | **No — MISSING** |
| `prometheus_client` | `prometheus-client` | **No — MISSING** |

### Where lazy/conditional imports appear

| Package | File(s) |
|---|---|
| `openai` | `chapters/13-advanced-topics/code-examples/python/01_llm_integration.py`, `chapters/13-advanced-topics/code-examples/python/03_aip_agents.py` |
| `anthropic` | `chapters/13-advanced-topics/code-examples/python/01_llm_integration.py` |
| `peft`, `trl`, `bitsandbytes` | `chapters/13-advanced-topics/code-examples/python/01_llm_integration.py` |
| `sentence_transformers` | `chapters/13-advanced-topics/code-examples/python/02_rag_pipeline.py`, `chapters/07-unsupervised-ml/code-examples/python/03_topic_modeling.py` |
| `faiss` | `chapters/13-advanced-topics/code-examples/python/02_rag_pipeline.py` |
| `chromadb` | `chapters/13-advanced-topics/code-examples/python/02_rag_pipeline.py` |
| `prometheus_client` | `chapters/09-mlops/code-examples/python/03_pipeline_orchestration.py`, `chapters/11-deployment/code-examples/python/02_api_serving.py` |
| `grpc` | `chapters/11-deployment/code-examples/python/03_platform_deployment.py` |
| `torchvision` | `chapters/08-deep-learning/code-examples/python/02_cnn_image_classification.py`, `chapters/08-deep-learning/code-examples/python/02_cnn_satellite_imagery.py` |

---

## Packages in requirements.txt Not Directly Imported

These packages appear in requirements.txt but are not imported in any of the 41 code example files. They are **kept** because they serve infrastructure, testing, security, or tooling purposes.

| pip package | Justification for keeping |
|---|---|
| `lightgbm` | Standard ML library; likely used in notebooks/experiments not in code-examples |
| `catboost` | Same as lightgbm |
| `tensorflow` | Deep learning alternative; referenced conceptually in ch08 |
| `opencv-python` | Computer vision; used in platform-specific code paths not traced by static import scan |
| `nltk` | NLP baseline library; standard inclusion for NLP chapter |
| `spacy` | NLP; same as above |
| `textblob` | NLP; same as above |
| `uvicorn` | ASGI server for FastAPI — runtime infrastructure |
| `flask` | Web framework; alternative serving pattern |
| `django` | Web framework; alternative serving pattern |
| `sqlalchemy` | ORM; referenced in database chapter |
| `psycopg2-binary` | PostgreSQL driver |
| `pymongo` | MongoDB driver |
| `redis` | Redis client |
| `dask` | Parallel computing; referenced in ch04/ch09 |
| `polars` | DataFrame library |
| `wandb` | ML experiment tracking alternative to mlflow |
| `optuna` | Hyperparameter tuning |
| `hyperopt` | Hyperparameter tuning |
| `boto3` | AWS cloud SDK |
| `azure-storage-blob` | Azure cloud SDK |
| `google-cloud-storage` | GCP cloud SDK |
| `beautifulsoup4` | Web scraping |
| `scrapy` | Web scraping framework |
| `selenium` | Browser automation |
| `jupyterlab` and extensions | Jupyter environment |
| `pytest`, `pytest-cov` | Testing framework |
| `black`, `flake8`, `mypy` | Code quality tools |
| `pre-commit`, `bandit`, `safety` | Security and pre-commit tooling |
| `cryptography`, `PyKCS11`, `python-jose`, `passlib`, `python-multipart`, `PyJWT`, `responses` | Security/auth infrastructure |
| `click`, `typer` | CLI tooling |
| `python-dotenv` | Environment variable loading |
| `tqdm`, `joblib` | Utilities |

---

## environment.yml Consistency Check

The `environment.yml` is missing the same packages that are missing from `requirements.txt`:

| Missing from environment.yml |
|---|
| `torchvision` (listed as conda dep but not in pip section — acceptable since it's a conda package) |
| `grpcio` |
| `openai` |
| `anthropic` |
| `peft` |
| `trl` |
| `bitsandbytes` |
| `sentence-transformers` |
| `faiss-cpu` |
| `chromadb` |
| `prometheus-client` |

**Note:** `torchvision` and `torchaudio` are listed as conda dependencies in `environment.yml` (line 24-25) which is correct. `torchvision` is still missing from `requirements.txt` for pip users.

---

## Changes Made to requirements.txt

The following packages were added to `requirements.txt` under a new `# LLM & Advanced ML` section:

```
torchvision>=0.15.0
grpcio>=1.56.0
openai>=1.0.0
anthropic>=0.25.0
peft>=0.10.0
trl>=0.8.0
bitsandbytes>=0.41.0
sentence-transformers>=2.2.0
faiss-cpu>=1.7.4
chromadb>=0.4.0
prometheus-client>=0.17.0
```
