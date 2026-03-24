# Chapter 09: MLOps and Production Pipelines

The model had 94% accuracy on the holdout set. The ATO reviewer stamped it on a Tuesday.

By Friday, the model was in production on a Navy logistics platform, scoring incoming maintenance work orders and routing high-priority items to senior technicians. By the following Wednesday, the maintenance chief was in a conference call with the contracting officer, the data scientist, and two program managers, asking why the model was routing items it had never seen before to the wrong queue with complete confidence.

Sarah Chen had built a solid model. Her training data covered eighteen months of work orders from two Naval stations. Her validation pipeline was clean. Her metrics looked good in every notebook she had written. What she had not built was any mechanism to detect when the model encountered work order categories introduced after her training cutoff. The model did not degrade gracefully. It did not raise a flag. It just scored unfamiliar records with the same quiet confidence it applied to familiar ones, and the routing errors accumulated silently until a human noticed.

That is not a modeling problem. That is a production problem. And it is the exact problem this chapter addresses.

Shipping a model is not the end of the work. It is the beginning of a different kind of work. Training gets you a model that performs on data from the past. Production means keeping it performing on data from the present — data that drifts, distributions that shift, pipelines that break, and environments that change around the model even when no one touches the code. In federal environments, add audit requirements, authority to operate renewal cycles, and the expectation that every prediction touching an operational decision has a traceable, reviewable history.

MLOps — machine learning operations — is the discipline of building systems that make production ML reliable, reproducible, and maintainable. This chapter covers how to do it on the platforms you are actually working on.

## What You'll Build

By the end of this chapter, you will be able to:

- Track experiments with MLflow on Databricks and understand what metadata is worth logging
- Version models through staging, integration testing, and production promotion using the MLflow Model Registry
- Deploy models with the `palantir_models` framework in Foundry and surface predictions as Ontology-backed objects
- Build CI/CD pipelines for ML code using GitHub Actions, including automated model evaluation gates
- Set up feature stores on Databricks Feature Store and understand how Palantir Pipeline Builder pipelines serve the same function
- Detect data drift and model degradation using evidently and Prometheus, and know the difference between the two
- Orchestrate multi-step ML pipelines with Databricks Workflows and Palantir Pipeline Builder scheduling
- Produce model cards and audit trails that satisfy ATO reviewers, not just your own conscience

## The Production Gap

Here is the hard truth: most data scientists are trained to build models, not to operate them. Academic programs teach train-test splits, not model monitoring. Kaggle teaches feature engineering, not pipeline versioning. The gap between a well-performing notebook and a reliable production system is enormous, and it is filled with problems that do not appear in any training dataset.

The production gap shows up differently on different platforms, but it always shows up. On Databricks, it looks like a notebook that runs fine manually but fails silently on a scheduled job because a library version changed. On Palantir Foundry, it looks like a model that publishes successfully but whose outputs are never actually read by downstream pipeline consumers because the Ontology integration was never configured. On any platform, it looks like drift: the world changes, and no one told the model.

Before covering tooling, understand the four problems MLOps solves.

**Reproducibility.** Can you retrain the exact model that is currently in production? Not approximately — exactly. Same hyperparameters, same data version, same random seeds. On a government program, an auditor may ask you this question eighteen months after you deployed the model. If you cannot answer it, that is a compliance finding.

**Reliability.** Does the pipeline run on schedule without human intervention? Does it fail loudly when something goes wrong, or silently produce bad outputs? Reliability is not about writing perfect code. It is about building systems that surface failures quickly enough that humans can respond before those failures become production incidents.

**Governance.** Who approved this model for production? When was it last evaluated? What data was it trained on, and are there any usage restrictions on that data? In federal environments, these questions have legal and regulatory consequences, not just engineering ones.

**Drift management.** Model performance degrades over time because the world changes. Input feature distributions shift. The relationship between features and targets changes. Categories that did not exist at training time appear in inference requests. Drift management is the ongoing work of detecting these changes and deciding when to retrain.

## Experiment Tracking with MLflow

MLflow is the de facto standard for experiment tracking in Python-based ML, and it ships natively inside Databricks. If you are working in the Databricks environment on Advana, or in any Databricks GovCloud workspace, MLflow is already available — you do not need to install or configure it separately.

The core concept is simple: every training run writes metadata to a central store. That metadata includes parameters (the things you set before training), metrics (the things you measure during and after training), artifacts (the files the run produces — model files, plots, feature importance tables), and tags (arbitrary key-value pairs for annotations).

Here is what a minimal MLflow training run looks like in practice:

```python
# See code-examples/python/01_experiment_tracking.py for the full implementation
```

The part most practitioners underestimate is what to log. Logging accuracy and loss is obvious. The less obvious items are what separate a useful experiment history from a useless one:

- **The training data version or hash.** If you can't identify exactly which data produced a given model, you cannot reproduce it.
- **The scikit-learn or framework version.** Model serialization is not always backwards-compatible. A model serialized with scikit-learn 1.3 may not load correctly under scikit-learn 1.5.
- **Evaluation on a held-out test set, not just validation.** The validation metrics guide hyperparameter selection and are optimistic by construction. The test set metrics are what you report to the ATO reviewer.
- **Confusion matrices and per-class metrics for classification tasks.** A 94% accuracy on an imbalanced dataset might mean 0% recall on the minority class. Log the full picture.
- **Data drift scores from your current production model.** If you are retraining because of drift, log the drift metrics that triggered the retrain. This creates a feedback loop you can audit later.

### Platform Spotlight: Databricks MLflow on GovCloud

Databricks on AWS GovCloud (FedRAMP High, IL5 authorized as of February 2025) runs MLflow in managed mode: the tracking server is fully managed by Databricks, and all experiment artifacts are stored in your workspace's S3 bucket under your agency's AWS account. You do not operate the tracking server. The compliance posture inherits from the Databricks workspace authorization.

As of late 2025, **MLflow 3.0** is the version running on Databricks. It adds enhanced observability for generative AI and agentic workflows — you can track LLM prompt/response pairs, token counts, and evaluation scores with the same API you use for traditional ML. If your team is building RAG pipelines or GenAI features alongside traditional ML models, a single MLflow workspace can track everything.

One GovCloud-specific behavior: the MLflow UI in AWS GovCloud workspaces respects Unity Catalog access controls. Experiments are owned by the user who creates them and inherit workspace-level permissions. If you are on a multi-team project and need to share experiment results across teams, configure experiment permissions explicitly — they do not inherit automatically.

## The Model Registry

Logging experiments is the easy part. The harder discipline is the model registry: a centralized catalog of trained models with explicit lifecycle states, promotion approvals, and version history.

The MLflow Model Registry uses four stages: **None** (freshly registered, not yet under review), **Staging** (candidate for production, undergoing integration tests), **Production** (the live model serving inference), and **Archived** (retired from active use but retained for audit purposes).

The key practice is treating stage transitions as deliberate, gate-protected events — not just a button you click when you feel good about a model. A production-grade registry workflow looks like this:

1. Training run completes, metrics exceed your defined thresholds, model is registered to the registry at stage None.
2. An automated CI step runs a standardized evaluation suite against the candidate model and a recent sample of production data. If it passes, the model transitions to Staging.
3. A human reviewer (the ML engineer, the program manager, or both depending on your governance structure) reviews the evaluation report and approves the Staging-to-Production transition.
4. The previous Production model is transitioned to Archived. The new model begins serving.

That approval step in stage 3 is where government MLOps diverges from startup MLOps. On a commercial product, you might automate the entire promotion pipeline. On a DoD system with an ATO, you need a documented human approval in the audit trail. The MLflow registry handles this via registry model version comments and transition events, all of which are logged and retrievable.

> **Note:** The MLflow Model Registry and the Databricks Unity Catalog are now integrated. As of December 2025, all new Databricks workspaces use Unity Catalog as the underlying governance layer. Models registered via the MLflow API appear in Unity Catalog under `catalog.schema.model_name`. This means Unity Catalog access controls, lineage tracking, and audit logs apply to your models automatically. For ATO documentation, this is significant: Unity Catalog produces audit logs suitable for compliance reporting without any additional configuration.

## Model Deployment on Palantir Foundry

Palantir's approach to model deployment is architecturally different from the MLflow/registry pattern. Rather than registering a model artifact and pointing an inference server at it, Foundry integrates the model into the Ontology — making model outputs first-class objects in the same semantic layer that governs all other data assets.

As of October 31, 2025, the `foundry_ml` library is fully deprecated. All new model development in Foundry uses the `palantir_models` library. If you are working on a Foundry environment and see legacy code using `foundry_ml`, do not follow that pattern — port it forward.

The deployment workflow using `palantir_models` in a Code Workspace (JupyterLab):

```python
# See code-examples/python/02_model_registry_deployment.py for the full implementation
```

Once a model is published via `palantir_models`, Foundry registers it in the platform's model management system. From there, the model can be:

- Called directly from AIP Logic blocks (to power LLM-assisted workflows that incorporate ML predictions)
- Integrated into Pipeline Builder transforms that call the model on schedule and write outputs as Foundry datasets
- Surfaced via Workshop applications where analysts see predictions alongside other Ontology data
- Exposed through the Ontology SDK (OSDK) for external applications

The Ontology integration is what makes Palantir's deployment story genuinely different. A model deployed via `palantir_models` does not just return a score — its predictions can become properties of Ontology objects. If you train a model that predicts maintenance failure probability for ships, you can surface that probability as a property on the `Vessel` object type. Every downstream application, analyst, and workflow that touches `Vessel` objects then sees the model's predictions as naturally as they see the vessel's hull number or home port.

That also means the audit trail for model predictions is built into Foundry's lineage tracking. Every prediction that writes to an Ontology object is traceable back to the model version, the input data, and the pipeline run that produced it. For programs requiring ATO-level documentation, this lineage is available without custom instrumentation.

### Model Cards in Foundry

Palantir's recommended practice for high-stakes model deployments includes a model card — a structured document describing the model's intended use, performance characteristics, known limitations, training data sources, and evaluation results. In Foundry, the model card is typically stored as a dataset resource alongside the model artifact, linked in the model management system.

For ATO reviewers and accreditation bodies, the model card answers the questions that technical documentation does not: What is this model for? Who validated it? What happens when it encounters out-of-distribution inputs? If the model supports a decision affecting personnel, procurement, or operations, expect the ATO reviewer to ask for the model card. Write it before they ask.

## CI/CD for Machine Learning

A CI/CD pipeline for ML code does more than run tests on pull requests. It provides automated evidence that new code does not break existing models, that updated models still meet performance requirements, and that the production environment stays synchronized with the repository. In government programs, that evidence is part of your audit trail.

The core components of an ML CI/CD pipeline:

1. **Unit tests** for data transformations, feature engineering functions, and model evaluation utilities
2. **Integration tests** that run the full training pipeline on a small sample dataset and verify the output model meets minimum thresholds
3. **Model evaluation gates** that compare a candidate model against the current production model and block promotion if performance regresses
4. **Artifact publishing** that registers passing models to the MLflow registry or Palantir model management system
5. **Deployment automation** that updates the serving environment once a model clears all gates

```yaml
# See code-examples/ directory — GitHub Actions workflow shown inline below
```

A GitHub Actions workflow for an ML pipeline might look like this:

```yaml
name: ML Pipeline CI

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  test-and-evaluate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python 3.11
        uses: actions/setup-python@v4
        with:
          python-version: "3.11"

      - name: Install dependencies
        run: pip install -r requirements.txt

      - name: Run unit tests
        run: pytest tests/unit/ -v --tb=short

      - name: Run integration test (small sample)
        run: python scripts/train_evaluate.py --sample-size 5000 --output-dir artifacts/

      - name: Check model performance gate
        run: |
          python scripts/check_performance_gate.py \
            --candidate-metrics artifacts/metrics.json \
            --baseline-metrics s3://your-agency-bucket/production/metrics.json \
            --threshold-config config/performance_thresholds.yaml

      - name: Register model to staging (main branch only)
        if: github.ref == 'refs/heads/main'
        run: |
          python scripts/register_model.py \
            --model-path artifacts/model/ \
            --stage Staging \
            --experiment-name "maintenance-priority-classifier"
        env:
          DATABRICKS_HOST: ${{ secrets.DATABRICKS_HOST }}
          DATABRICKS_TOKEN: ${{ secrets.DATABRICKS_TOKEN }}
```

The performance gate in that workflow is where most teams cut corners. The gate should compare the candidate model against the current production model on a fixed evaluation dataset — not a random sample. If you evaluate on a random sample, evaluation noise can cause a worse model to pass the gate when you get lucky with the sample. Fix the evaluation dataset. Version it. Log it.

> **Sanity check:** "We don't need a performance gate — we'll just run the tests and review the metrics manually." That works for the first three months, when the team is small and everyone knows the model. It fails when the team grows, when turnover happens, or when someone deploys at 4 PM on a Friday before a holiday weekend. Automate the gate and encode your performance standards in code, not in judgment calls.

## Feature Stores

Feature stores solve a coordination problem that emerges at scale: multiple models, across multiple teams, needing access to the same features, computed from the same source data, with the same transformations applied consistently. Without a feature store, you get feature drift — subtle inconsistencies in how the same concept (say, "30-day rolling average of maintenance events for a given vessel class") is computed by different teams, leading to models that cannot be compared or composed.

### Databricks Feature Store

The Databricks Feature Store (part of the Mosaic AI platform) provides:

- A centralized catalog of feature tables with lineage tracking back to source data
- Automatic point-in-time joins for training data creation, preventing label leakage
- Consistent feature computation between training and inference — the same function runs at training time and at serving time
- Integration with the MLflow Model Registry so that models and their required features are tracked together

The key concept in the Databricks Feature Store is the **feature table**: a Delta Lake table with a primary key that serves as the join key for feature lookups. Feature tables are versioned, and Unity Catalog governance applies to them just as it does to any other Delta table.

```python
# See code-examples/python/03_pipeline_orchestration.py for feature store integration example
```

For government programs on Advana, which runs on Databricks, the Feature Store is available in the standard environment. Teams working across multiple analytical products — say, a readiness scoring model and a maintenance prioritization model that both need vessel operational history features — should centralize those features in the Feature Store rather than computing them independently in each pipeline.

### Feature Engineering in Palantir Foundry

Foundry does not have a dedicated feature store product, but the Pipeline Builder achieves the same outcome through a different mechanism. In Foundry, feature engineering pipelines are scheduled transforms that produce Foundry datasets. Those datasets are versioned, lineage-tracked, and governed by the same access controls as any other Foundry dataset.

The Ontology layer provides the semantic context: a dataset of vessel maintenance event features maps to properties of the `Vessel` object type. Models that need those features reference the same Ontology objects. This creates a de facto feature catalog without a separate product: the Ontology itself documents what features exist, what objects they describe, and how they were produced.

The practical implication: if you are working on Foundry, build your feature engineering as scheduled Pipeline Builder transforms producing consistently-named datasets, and register those datasets to the relevant object type properties. Do not compute features inline in your training notebooks. The models that follow you will thank you.

## Model Monitoring and Drift Detection

Sarah Chen's problem from the opening scene was a monitoring problem. The model was wrong. Nobody knew. That is the worst possible production outcome, and it is distressingly common.

Effective model monitoring requires distinguishing between two different types of degradation.

**Data drift** means the distribution of model inputs has changed. Features that were rare in training become common in production. Categories that did not exist in training start appearing. Numerical features shift their mean or variance. The model itself has not changed — but the data it is seeing has, and if the drift is significant enough, the model's predictions become unreliable even if it is still technically computing the right answer for its training distribution.

**Concept drift** means the relationship between inputs and outcomes has changed. The world has changed in a way that makes the model's learned patterns obsolete. A model trained on pre-pandemic logistics data will misperform on post-pandemic logistics patterns because the underlying operational realities changed, not just the data distributions.

Detecting data drift is tractable with standard statistical tools. Detecting concept drift requires outcome labels, which means you need a feedback loop from production outputs back to the monitoring system — often the hardest piece to build.

### Drift Detection with evidently

The `evidently` library (open source, Python) is the most practical tool for drift monitoring on tabular ML models. It generates reports that compare a reference dataset (typically training data or a baseline production window) against a production window (recent inference data):

```python
from evidently.report import Report
from evidently.metric_preset import DataDriftPreset, TargetDriftPreset
from evidently.metrics import DatasetDriftMetric

# Compare recent production data against training baseline
report = Report(metrics=[
    DataDriftPreset(),
    DatasetDriftMetric(),
])

report.run(reference_data=training_df, current_data=recent_production_df)
report.save_html("drift_report.html")

# For programmatic access in a monitoring pipeline
result = report.as_dict()
drift_detected = result["metrics"][1]["result"]["dataset_drift"]
drift_share = result["metrics"][1]["result"]["share_of_drifted_columns"]

if drift_detected and drift_share > 0.3:
    # More than 30% of features are drifting — trigger alert
    send_alert(f"Significant drift detected: {drift_share:.0%} of features")
```

The output of evidently can be written to a Databricks Delta table for historical tracking, surfaced in a Databricks SQL dashboard, or exported to Prometheus as a metric gauge for integration with existing infrastructure monitoring.

### Prometheus and Grafana for Model Monitoring

For teams that already run Prometheus and Grafana for infrastructure monitoring, adding model metrics to the same stack keeps all operational signals in one place. The `prometheus_client` Python library exposes model metrics as HTTP endpoints that Prometheus can scrape:

```python
from prometheus_client import Gauge, Counter, start_http_server

model_accuracy_gauge = Gauge('ml_model_accuracy', 'Current model accuracy on evaluation window', ['model_name', 'model_version'])
prediction_counter = Counter('ml_predictions_total', 'Total predictions served', ['model_name', 'outcome_bucket'])
drift_gauge = Gauge('ml_feature_drift_score', 'Feature drift score vs. training baseline', ['model_name', 'feature_name'])

# Update these from your monitoring job
model_accuracy_gauge.labels(model_name='maintenance_classifier', model_version='v3.2').set(0.912)
```

In a Databricks environment, the monitoring job runs as a scheduled Workflow that queries the inference table (Databricks logs all model serving requests and responses to an inference table by default), computes drift metrics, and pushes them to Prometheus via the push gateway. The Grafana dashboard then visualizes model performance, drift scores, and prediction volume over time alongside infrastructure metrics.

For programs with a dedicated platform engineering team, this Prometheus/Grafana pattern integrates cleanly with existing site reliability engineering practices. For smaller programs, the evidently HTML reports written to an S3 bucket and reviewed weekly is a more realistic starting point.

## Pipeline Orchestration

A model in production is not a single script. It is a pipeline: data extraction, feature computation, batch inference or model serving, output writing, monitoring checks, alerting. These steps have dependencies, schedules, and failure modes. Orchestration is how you manage all of that.

### Databricks Workflows

Databricks Workflows is the native orchestration layer. You define jobs as directed acyclic graphs (DAGs) of tasks, where each task is a notebook, a Python script, a Delta Live Tables pipeline, or a SQL query. Tasks run on separate compute clusters, pass parameters to each other via job parameters and task return values, and retry on failure according to configurable policies.

```python
# See code-examples/python/03_pipeline_orchestration.py for a full Workflows configuration
```

A typical MLOps pipeline on Databricks Workflows:

```
feature_refresh (daily, 2 AM)
    └── model_training (triggered by feature_refresh success, weekly)
        └── model_evaluation (triggered by training success)
            └── staging_promotion (if evaluation passes gate)
                └── monitoring_job (daily, 6 AM, independent of training)
```

Workflows integrates with Unity Catalog for access control: the service principal running the job needs explicit permissions on the input tables, output tables, and model registry. On GovCloud workspaces, service principals are the correct approach — do not use personal access tokens for production jobs.

One practical concern for government programs: Databricks Workflows runs jobs on ephemeral clusters by default. Cluster startup time (typically 4 to 6 minutes for a standard cluster) adds latency to every job. For latency-sensitive pipelines, pre-configured job clusters with specific instance types reduce startup variance. For monitoring jobs that run hourly, serverless compute is now available in GovCloud and eliminates cluster startup entirely.

### Palantir Pipeline Builder Scheduling

In Foundry, pipelines run as scheduled builds on the Pipeline Builder's build graph. Every dataset in Foundry has a build schedule: it can be triggered manually, on a cron schedule, or as a downstream dependency of upstream dataset builds.

The scheduling model in Foundry is pull-based rather than push-based. You do not define a job that runs a script. You define a transform (a code-based or no-code-based function) that reads inputs and writes outputs, and you schedule that transform to run when its inputs are updated. Foundry handles the dependency graph automatically.

This architecture has an important implication: if your feature engineering pipeline produces a dataset that feeds a model scoring pipeline, and the feature pipeline runs late or fails, the downstream model scoring pipeline does not run. The dependency is explicit in the build graph, and build failures propagate correctly. You cannot accidentally run a model scoring job on stale features because Foundry knows which inputs have updated.

For government programs that need clear audit trails of "this prediction was produced by this model version using this version of this feature dataset on this date," Foundry's build history provides exactly that lineage without additional instrumentation.

## Reproducibility and Audit Trails for Government Programs

ATO reviewers have a specific question that most MLOps tutorials do not address: "If something goes wrong with a decision supported by this model, can you reconstruct exactly what the model saw, what it predicted, and why?" The answer needs to be yes, and the evidence needs to be accessible without heroic effort from the engineering team.

The components of a reproducible, auditable ML system:

**Data versioning.** Delta Lake's time-travel capability means that every Databricks Delta table has a complete, queriable history. You can reconstruct the exact version of a training dataset as it existed on any date by querying the table at a specific timestamp or version number: `SELECT * FROM feature_table VERSION AS OF 42` or `SELECT * FROM feature_table TIMESTAMP AS OF '2025-08-15'`. Log the table version numbers at training time — that is all you need to reconstruct the training dataset months later.

**Code versioning.** Every training run should be associated with a Git commit hash. MLflow's autologging captures the Git hash when it is available. If it is not, log it explicitly. The commit hash, combined with the data version, is sufficient to reproduce a training run given the same compute environment.

**Environment versioning.** The `pip freeze` output for your training environment, or a `conda env export`, should be logged as an MLflow artifact. Library versions change. A model trained on PyTorch 2.1 may produce different numeric outputs on PyTorch 2.3. Log the environment. Better, use Databricks Runtime ML images, which are versioned and immutable — a notebook run on Databricks Runtime 15.4 ML will behave the same way next year as it did today.

**Prediction logging.** Every inference request served by a production model should be logged: the input features (or a hash of them), the prediction output, the model version that produced it, and the timestamp. In Databricks Model Serving, inference tables capture this automatically. In custom serving setups, you need to instrument this explicitly. Do not skip it — it is the evidence trail the ATO reviewer wants, and it is also your primary resource for monitoring and debugging.

In Palantir Foundry, all four of these are handled at the platform level: dataset versioning is built in, code changes in Code Repositories create versioned commits, the build graph records which transform version ran on which data version to produce each output, and prediction outputs written to the Ontology carry full lineage back to their source pipeline.

> **Note:** Federal programs often have data retention requirements that specify minimum retention periods for operational records. If model predictions inform operational decisions — routing, prioritization, personnel actions — those predictions may be subject to the same retention requirements as the underlying decisions. Confirm the retention requirement with your program's records management officer before choosing where and how long to store inference logs.

## Where This Goes Wrong

### Failure Mode 1: The Stale Model Problem

**The mistake:** The team deploys a model, the model works well, and nobody sets up a retraining schedule or monitoring. Six months later the model is silently underperforming on current data, and the degradation is only discovered when a downstream decision-maker notices the outputs look wrong.

**Why smart people make it:** Setting up monitoring is extra work that seems low-priority when the model is performing well at deployment time. The team has momentum toward the next project. The model "works," so there is no immediate pressure.

**How to recognize you're making it:**
- The model in production was trained more than six months ago with no documented evaluation since deployment
- There is no scheduled job that checks model performance against recent data
- The team cannot say what the current production accuracy is without running a new evaluation from scratch
- No one has reviewed the training data cutoff date relative to current operational conditions

**What to do instead:** Before a model goes to production, define the monitoring contract: what metrics to track, what thresholds trigger a retrain, and who owns the response. Build the monitoring job at the same time as the model. Schedule it. Make the monitoring dashboard visible to the program manager, not just the engineering team.

### Failure Mode 2: The Namespace Collision

**The mistake:** Two engineers independently register models with the same name to the MLflow registry, overwriting each other's production versions without realizing it.

**Why smart people make it:** MLflow model names are global within a workspace by default. When two teams are working on related models, or when an engineer creates a quick experiment that inadvertently shadows a production model name, the registry does not warn you.

**How to recognize you're making it:**
- Model names in the registry are not namespaced by team, project, or capability area
- Multiple engineers have registry write access with no documented naming convention
- A model in production was recently modified by someone who does not own that production system

**What to do instead:** Establish a naming convention before the first model is registered: `{project}-{model-type}-{version-intent}` (e.g., `maintenance-priority-classifier-prod`). With Unity Catalog enforcement in Databricks, use catalog and schema namespacing: `navy_logistics.maintenance.priority_classifier`. The Unity Catalog layer enforces access control at the model level — only the owning team's service principal can promote models in their schema.

### Failure Mode 3: Treating CI/CD as Optional

**The mistake:** The team builds a manual deployment process — a Confluence page with steps to follow when deploying a new model — and treats automated CI/CD as a "nice to have" they will add later.

**Why smart people make it:** CI/CD setup takes time upfront. On a short-engagement contract, it is tempting to defer it. The manual process works fine when the team is small and change is infrequent.

**How to recognize you're making it:**
- Deploying a new model version requires following a checklist rather than merging a pull request
- There is no automated record of what model is currently in production and when it was last deployed
- A deployment failed because someone skipped a step in the manual process

**What to do instead:** Set up the GitHub Actions workflow (or equivalent) during the first sprint, before the first model is trained. The setup cost is a few days. The payoff is years of reliable, auditable deployments. For ATO purposes, an automated deployment pipeline with version-controlled approval gates is more defensible than a manual checklist process.

## Practical Takeaway: The MLOps Readiness Checklist

Before any model goes to production on a federal program, verify these items. This is not aspirational — it is the minimum that makes a production deployment defensible.

**Experiment tracking**
- [ ] All training runs logged to a shared MLflow experiment, not a local tracking server
- [ ] Training data version (Delta table version or S3 object version) logged per run
- [ ] Git commit hash logged per run
- [ ] Evaluation metrics on a fixed test set logged (not just validation metrics)
- [ ] Environment (`pip freeze` or Databricks Runtime version) logged per run

**Model registry**
- [ ] Model registered with a namespaced name (not a generic name that could collide)
- [ ] Stage transitions documented with approval comments
- [ ] Previous production model moved to Archived before new model activated
- [ ] Model card written and stored alongside model artifact

**CI/CD**
- [ ] Unit tests for data transformations run on every pull request
- [ ] Integration test with sample data runs on every merge to main
- [ ] Performance gate compares candidate model against production baseline
- [ ] Secrets (API keys, tokens) stored in CI/CD environment variables, not in code

**Monitoring**
- [ ] Inference logging configured (Databricks inference tables or custom logging)
- [ ] Drift detection job scheduled and running
- [ ] Alert thresholds defined and documented
- [ ] Monitoring dashboard accessible to program manager, not just engineers

**Audit trail**
- [ ] Prediction logs retained per program data retention policy
- [ ] Training data retention policy confirmed with records management
- [ ] Model lineage (data version + code version + environment) reproducible

A "no" on any of these items is a risk. Some of them are acceptable risks at early development stages. None of them are acceptable risks in production on a system that informs operational decisions.

## Platform Comparison

How the five federal platforms handle the core MLOps concerns:

| Capability | Advana (Databricks) | Palantir Foundry | Qlik | Navy Jupiter | Notes |
|---|---|---|---|---|---|
| Experiment tracking | MLflow (native, managed) | Build graph history | Not applicable | Not applicable | MLflow is the standard on Databricks |
| Model registry | MLflow + Unity Catalog | palantir_models system | Not applicable | Not applicable | Unity Catalog enforces access control |
| Model deployment | Mosaic AI Model Serving | palantir_models + Ontology | Not applicable | Via upstream platforms | Palantir integrates predictions into Ontology objects |
| Feature store | Databricks Feature Store | Pipeline Builder datasets | Not applicable | Not applicable | Foundry uses Ontology properties as feature catalog |
| Pipeline orchestration | Databricks Workflows | Pipeline Builder scheduling | Qlik Talend ETL | Platform-dependent | |
| Drift monitoring | Mosaic AI inference tables + evidently | Build lineage + custom monitoring | No native capability | Dependent on platform | |
| Audit trail | Unity Catalog lineage | Full build/transform lineage | Limited | Limited | Both Databricks and Palantir strong here |
| CI/CD integration | GitHub Actions + Databricks SDK | Code Repositories (Git-backed) | N/A | N/A | Both support pull-request-driven deployment |
| ATO support | FedRAMP High (Feb 2025), IL5 | FedRAMP High (Dec 2024), IL5, IL6 | FedRAMP Moderate | Internal DoN | Palantir supports classified (IL6) environments |

Qlik and Navy Jupiter appear in this table with limited MLOps capability for a reason: they are not ML platforms. Qlik is a BI and analytics tool — it surfaces model outputs built elsewhere, but it does not train, register, or monitor models. Navy Jupiter is a data environment layer; the ML workloads running on it depend on the underlying compute and platform tools the program has provisioned.

The real platform choice for government MLOps is between Databricks and Palantir Foundry, and they solve slightly different problems. Databricks is where you build and train models — the open ecosystem, the native MLflow integration, the distributed compute for large training runs. Foundry is where you deploy models into operations — the Ontology integration, the writeback to object properties, the connection to Workshop-based decision tools that operators actually use. The March 2025 Databricks-Palantir partnership, which enables zero-copy Unity Catalog integration, formalizes what forward-leaning programs are already doing: train on Databricks, deploy into Foundry.

## Exercises

See `exercises/exercises.md` for hands-on practice with the concepts in this chapter.

## Chapter Close

**The one thing to remember:** A model in production is a system, not a file — and systems require monitoring, governance, and maintenance that begin the day you deploy, not the day something breaks.

**What to do Monday morning:** Audit one model that is currently in production on your program. Confirm you can answer these three questions without running a new evaluation: (1) What training data version produced this model? (2) What is the current accuracy on a recent production sample? (3) Who last reviewed and approved this model for production use? If you cannot answer all three, you have your first MLOps project.

**What comes next:** Models do not exist in isolation — they are one component of a larger analytical product that decision-makers need to see, understand, and act on. Chapter 10 covers visualization and dashboards: how to surface model outputs, feature importance, monitoring trends, and analytical results to the stakeholders who need them, on the BI platforms those stakeholders already use.
