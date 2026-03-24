# Chapter 06: Supervised Machine Learning on Federal Platforms

The model was 94% accurate. The program manager loved the number. He put it in the briefing slide deck for the admiral's Thursday review.

Marcus had built it over six weeks — a binary classifier that flagged Navy supply requisitions likely to result in late delivery. The training data was 2.8 million requisitions from FY2020 through FY2023, pulled from Jupiter's silver-tier MILSTRIP records. The features were solid: supplier historical on-time rate, requisition priority code, days until required delivery date, item National Stock Number demand frequency, and current stock on hand at the servicing supply point. The model was a gradient-boosted tree trained on Databricks. AUC of 0.91. That 94% accuracy figure came from a hold-out test set.

Thursday came. The admiral asked one question: "What's your false positive rate on Priority 01 requisitions?"

Marcus didn't know. He hadn't stratified his assessment by priority code. Priority 01 meant mission-critical — parts needed within 24 hours, aircraft down, ship can't sail. If the model flagged a Priority 01 incorrectly as late-risk, the supply officer would expedite it at significant cost and operational disruption. If the model missed a Priority 01 that genuinely was late-risk, the aircraft stayed down.

"That 94% number," the admiral said, "is meaningless to me without that breakdown."

He was right. The model was good. The measurement framework was incomplete.

This chapter is about building models that can actually answer the admiral's question — not just produce a number that looks good in a briefing slide.

## What You'll Build

By the end of this chapter, you'll be able to:

- Train classification and regression models using scikit-learn and XGBoost on Databricks and Palantir Foundry
- Design measurement strategies that account for class imbalance, priority-stratified performance, and operational cost asymmetry — the realities of government data
- Persist trained models in MLflow Model Registry and the Foundry Ontology
- Run batch scoring pipelines on Databricks Workflows
- Interpret model predictions for non-technical stakeholders using SHAP values
- Recognize the three ways government ML projects fail after the model is "done"

---

## The Supervised Learning Frame

Supervised learning has one job: given labeled historical examples, learn a function that maps inputs to outputs accurately enough to be useful on new data you haven't seen.

That sentence contains three things that matter operationally. "Labeled historical examples" — government data is often labeled inconsistently, late, or wrong. "Accurately enough" — accurate enough for what? For a $50 decision or a $50 million one? "Useful on new data" — useful to whom, under what constraints, with what tolerance for error?

Every supervised ML project you run in a federal context involves answering these questions explicitly, usually in a document called a model card or an AI impact assessment. The algorithm choice — Random Forest vs. XGBoost vs. logistic regression — is the least consequential decision you'll make. Getting the problem framing, the label quality, and the measurement strategy right is where the real work lives.

Two problem types dominate federal data science:

**Classification** — predicting a categorical outcome. Will this contract be protested? Will this service member separate before their commitment ends? Will this component fail within 90 days? The output is a class label or a probability score.

**Regression** — predicting a continuous value. What will this program cost at completion? How many days until this work order is closed? What is the predicted readiness score for this unit at the end of the quarter? The output is a number.

Most practitioners reach for classification first because binary outcomes are easy to explain. Resist that instinct when the underlying problem is continuous. Binning a cost prediction into "over budget / under budget" throws away information and forces you to pick a threshold that is always wrong for someone.

---

## Classification on Federal Platforms

### The Readiness Prediction Problem

The most common classification problem in DoD data science: predict whether a unit, system, or asset will be in a required operational state at some future point. Readiness prediction shows up across all five platforms covered in this handbook.

On Jupiter, Task Force Hopper built readiness classifiers for the surface fleet. On Advana, CDAO's Data Science as a Service function built readiness models for personnel and equipment. On Palantir Foundry at various commands, readiness pipelines run inside the Ontology feeding operational dashboards. The problem is the same across contexts — the data sources, compliance constraints, and deployment targets differ.

Here is what a production-realistic classification pipeline looks like on Databricks:

```python
# Platform: Databricks (Advana / Jupiter)
# Use case: Binary classification — will this ship maintenance work order
#           exceed its estimated completion days?
#
# Features: ship age, hull class, maintenance category, prior work order count,
#           season, labor hours estimated, days since last availability period
# Label:    exceeded_estimate (1 = took longer than estimated, 0 = on time or early)

from pyspark.sql import SparkSession, functions as F
from pyspark.sql.window import Window
import pandas as pd
import numpy as np
from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import StratifiedKFold, cross_validate
from sklearn.preprocessing import StandardScaler, OrdinalEncoder
from sklearn.pipeline import Pipeline
from sklearn.compose import ColumnTransformer
from sklearn.metrics import (
    classification_report, roc_auc_score, average_precision_score,
    confusion_matrix
)
import mlflow
import mlflow.sklearn
import matplotlib.pyplot as plt

spark = SparkSession.getActiveSession()

# ---- Step 1: Feature extraction from silver-tier data ----
# Filter and aggregate in Spark before collecting to driver
raw   = spark.table("jupiter_catalog.silver.maintenance_work_orders")
ships = spark.table("jupiter_catalog.reference.ship_registry")

# Window function: count prior work orders per ship (historical load indicator)
prior_wo_window = (
    Window.partitionBy("hull_number")
          .orderBy("start_date")
          .rowsBetween(Window.unboundedPreceding, -1)
)

features_spark = (
    raw
    .filter(F.col("days_to_complete").isNotNull())    # completed orders only
    .filter(F.col("estimated_completion_days") > 0)   # valid estimates only
    .withColumn(
        "exceeded_estimate",
        (F.col("days_to_complete") > F.col("estimated_completion_days")).cast("int")
    )
    .withColumn(
        "prior_work_order_count",
        F.count("work_order_id").over(prior_wo_window)
    )
    .withColumn("start_month", F.month("start_date"))
    .join(ships.select("hull_number", "hull_class", "commission_year"), "hull_number", "left")
    .withColumn("ship_age_years",
        F.year(F.current_date()) - F.col("commission_year"))
    .select(
        "work_order_id", "hull_class", "maintenance_category",
        "labor_hours_estimated", "estimated_completion_days",
        "ship_age_years", "prior_work_order_count", "start_month",
        "data_quality_score", "exceeded_estimate"
    )
    .filter(F.col("ship_age_years").between(0, 60))   # remove data entry outliers
)

# Bring to driver — aggregated to model-ready size
df = features_spark.toPandas()
print(f"Training set: {len(df):,} work orders | "
      f"Exceeded estimate: {df['exceeded_estimate'].mean()*100:.1f}%")
```

That last print line is the first thing you should look at. If 95% of work orders exceeded their estimate, you have a labeling problem, not a modeling problem. If 0.3% exceeded, you have a severe class imbalance and your baseline accuracy of "predict everything as on-time" will be 99.7% — which is useless.

```python
# ---- Step 2: Preprocessing pipeline ----
# Government data has categoricals that need encoding and numerics that need scaling.
# Use sklearn Pipeline + ColumnTransformer to keep preprocessing reproducible.

numeric_features = [
    "labor_hours_estimated", "estimated_completion_days",
    "ship_age_years", "prior_work_order_count", "start_month",
    "data_quality_score"
]
categorical_features = ["hull_class", "maintenance_category"]
target = "exceeded_estimate"

X = df[numeric_features + categorical_features]
y = df[target].values

preprocessor = ColumnTransformer([
    ("num", StandardScaler(), numeric_features),
    ("cat", OrdinalEncoder(handle_unknown="use_encoded_value", unknown_value=-1),
     categorical_features),
])

# ---- Step 3: Model selection ----
# Three candidates — each has a different strength profile

models = {
    "logistic_regression": Pipeline([
        ("prep", preprocessor),
        ("clf", LogisticRegression(
            class_weight="balanced",
            C=0.1,
            max_iter=1000,
            random_state=42,
        ))
    ]),
    "random_forest": Pipeline([
        ("prep", preprocessor),
        ("clf", RandomForestClassifier(
            n_estimators=200,
            max_depth=8,
            class_weight="balanced",
            n_jobs=-1,
            random_state=42,
        ))
    ]),
    "gradient_boosting": Pipeline([
        ("prep", preprocessor),
        ("clf", GradientBoostingClassifier(
            n_estimators=200,
            max_depth=4,
            learning_rate=0.05,
            subsample=0.8,
            random_state=42,
        ))
    ]),
}

# ---- Step 4: Cross-validation ----
# Stratified K-Fold preserves class balance in each fold.
# This matters when the positive class is rare.

cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
scoring = ["roc_auc", "average_precision", "f1_weighted"]

cv_results = {}
for name, model in models.items():
    scores = cross_validate(model, X, y, cv=cv, scoring=scoring, n_jobs=-1)
    cv_results[name] = {
        "roc_auc":   scores["test_roc_auc"].mean(),
        "avg_prec":  scores["test_average_precision"].mean(),
        "f1":        scores["test_f1_weighted"].mean(),
    }
    print(f"{name:<25}  AUC={cv_results[name]['roc_auc']:.3f}  "
          f"AP={cv_results[name]['avg_prec']:.3f}  "
          f"F1={cv_results[name]['f1']:.3f}")
```

### Platform Spotlight: MLflow on Databricks

Once you've selected a model, you log it. This is not optional on a federal platform — it is how you prove what you trained, when, on what data, with what parameters. MLflow is the mechanism on Databricks, and it is pre-configured in every Databricks workspace on Advana and Jupiter.

```python
# ---- Step 5: Train final model and log to MLflow ----

from sklearn.model_selection import train_test_split

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, stratify=y, random_state=42
)

mlflow.set_experiment("/Users/marcus.chen@navy.mil/maintenance-overrun-classifier")

with mlflow.start_run(run_name="gradient_boosting_v1") as run:
    mlflow.log_param("model_type", "GradientBoostingClassifier")
    mlflow.log_param("n_estimators", 200)
    mlflow.log_param("max_depth", 4)
    mlflow.log_param("learning_rate", 0.05)
    mlflow.log_param("training_rows", len(X_train))
    mlflow.log_param("data_source", "jupiter_catalog.silver.maintenance_work_orders")
    mlflow.log_param("label_column", "exceeded_estimate")
    mlflow.log_param("feature_count", len(numeric_features + categorical_features))

    final_model = models["gradient_boosting"]
    final_model.fit(X_train, y_train)

    y_pred  = final_model.predict(X_test)
    y_proba = final_model.predict_proba(X_test)[:, 1]

    test_auc = roc_auc_score(y_test, y_proba)
    test_ap  = average_precision_score(y_test, y_proba)

    mlflow.log_metric("test_roc_auc", test_auc)
    mlflow.log_metric("test_avg_precision", test_ap)

    # Priority-stratified measurement — this is the admiral's question
    priority_results = {}
    for priority in X_test["maintenance_category"].unique():
        mask = X_test["maintenance_category"] == priority
        if mask.sum() < 20:
            continue
        slice_auc = roc_auc_score(y_test[mask], y_proba[mask])
        mlflow.log_metric(f"auc_{priority.lower().replace(' ', '_')}", slice_auc)
        priority_results[priority] = {"n": int(mask.sum()), "auc": slice_auc}

    print("\nPer-category AUC:")
    for cat, res in sorted(priority_results.items(), key=lambda x: x[1]["auc"]):
        print(f"  {cat:<30} n={res['n']:>5,}  AUC={res['auc']:.3f}")

    mlflow.sklearn.log_model(
        final_model,
        artifact_path="model",
        registered_model_name="maintenance_overrun_classifier",
        input_example=X_test.head(5),
        signature=mlflow.models.infer_signature(X_test, y_proba),
    )

    print(f"\nRun ID: {run.info.run_id}")
    print(f"Test AUC: {test_auc:.4f}  |  Avg Precision: {test_ap:.4f}")
```

### Platform Spotlight: Palantir Foundry

On Palantir Foundry, model training happens in Code Workspaces (interactive) or Transforms (production pipelines). The output is a model artifact stored in Foundry's versioned dataset system, not in MLflow. The model connects to the Ontology, which means it can be called from Workshop dashboards or AIP Logic functions.

```python
# Foundry Transform: train and persist a scikit-learn classifier
# This runs as a production pipeline inside Foundry
from transforms.api import transform, Input, Output
from palantir_models import Model, ModelVersion
import pandas as pd
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler, OrdinalEncoder
from sklearn.compose import ColumnTransformer

@transform(
    model_output=Output("/models/maintenance_overrun_classifier"),
    training_data=Input("/analytics/silver/maintenance_features"),
)
def train_maintenance_classifier(training_data, model_output):
    df = training_data.dataframe().toPandas()

    numeric_features     = [
        "labor_hours_estimated", "estimated_completion_days",
        "ship_age_years", "prior_work_order_count", "start_month",
    ]
    categorical_features = ["hull_class", "maintenance_category"]
    target               = "exceeded_estimate"

    X = df[numeric_features + categorical_features]
    y = df[target].values

    preprocessor = ColumnTransformer([
        ("num", StandardScaler(), numeric_features),
        ("cat", OrdinalEncoder(handle_unknown="use_encoded_value", unknown_value=-1),
         categorical_features),
    ])

    pipeline = Pipeline([
        ("prep", preprocessor),
        ("clf", GradientBoostingClassifier(
            n_estimators=200, max_depth=4, learning_rate=0.05, random_state=42
        ))
    ])

    pipeline.fit(X, y)

    # Foundry wraps models in its own versioned container
    foundry_model = Model(pipeline, Stage.PRODUCTION)
    model_output.write_model(foundry_model)
```

---

## Regression on Federal Platforms

### When Continuous Outputs Matter

The Army's Program Executive Office runs cost-to-complete forecasting on Advana. The question is never "will this program go over budget" — it's "by how much, and when will we know." That's a regression problem.

Regression gets used less than it should in government contexts because program managers want a red/yellow/green status light, not a dollar figure with confidence intervals. Push back on this. A model that says "this program will finish at $847M ± $62M" is more useful than one that says "red" — even if red is harder to put in a slide.

```python
# Platform: Databricks (Advana)
# Use case: Predict contract cost growth ratio
#           (final obligation / original obligation) - 1
# This is a regression problem — we want the magnitude, not just the direction.

import xgboost as xgb
from sklearn.metrics import mean_absolute_error, r2_score
from sklearn.model_selection import train_test_split
import numpy as np

def build_cost_growth_model(df: pd.DataFrame):
    """
    Train an XGBoost regressor to predict contract cost growth ratio.

    Cost growth is right-skewed with outliers. We log-transform the target
    to reduce the impact of massive overruns on the loss function.
    Programs with >10x cost growth are real but should not dominate training.
    """
    target = "cost_growth_ratio"

    # Clip extreme outliers — keep up to 99th percentile
    # Document this decision; someone will ask about it
    p99 = df[target].quantile(0.99)
    df  = df[df[target] <= p99].copy()
    print(f"Clipped to 99th percentile ({p99:.2f}x cost growth).")

    # Log1p transform — handles the right skew, invertible with expm1
    df["log_cost_growth"] = np.log1p(df[target].clip(lower=-0.99))

    feature_cols = [
        "log_base_obligation",        # log of original contract value
        "contract_type_code",         # FFP, CPFF, T&M (encoded)
        "competition_type_code",      # competitive vs. sole source (encoded)
        "naics_sector",               # industry sector
        "period_of_performance_days",
        "vendor_prior_award_count",   # vendor experience proxy
        "modification_count_prior",   # prior mods on this award
        "is_defense_acquisition",     # FAR Part 11 applicability
        "fiscal_year",
    ]

    X = df[feature_cols].values
    y = df["log_cost_growth"].values

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42
    )

    model = xgb.XGBRegressor(
        n_estimators=500,
        max_depth=5,
        learning_rate=0.03,
        subsample=0.8,
        colsample_bytree=0.8,
        min_child_weight=10,      # regularization
        reg_alpha=0.1,
        reg_lambda=1.0,
        random_state=42,
        n_jobs=-1,
        early_stopping_rounds=20,
    )

    model.fit(
        X_train, y_train,
        eval_set=[(X_test, y_test)],
        verbose=False,
    )

    # Report on original scale — undo the log transform
    y_pred_log = model.predict(X_test)
    y_pred     = np.expm1(y_pred_log)
    y_true     = np.expm1(y_test)

    mae  = mean_absolute_error(y_true, y_pred)
    r2   = r2_score(y_true, y_pred)
    mape = np.abs((y_true - y_pred) / (y_true + 1e-8)).mean() * 100

    print(f"Test set performance:")
    print(f"  MAE : {mae:.3f}x  (mean absolute error in cost growth ratio)")
    print(f"  MAPE: {mape:.1f}%")
    print(f"  R²  : {r2:.3f}")
    print(f"\n  On average, predictions are off by {mae:.2f}x the original contract value.")

    return model
```

XGBoost is the right choice here over scikit-learn's `GradientBoostingClassifier` for one practical reason: early stopping. When you're fitting on hundreds of thousands of contracts, you don't want to hand-tune `n_estimators`. Set it high, give XGBoost a validation set, and let it stop when performance plateaus. The `early_stopping_rounds=20` parameter does this automatically.

> **Note:** XGBoost is pre-installed on Databricks Runtime ML (DBR 13.x ML and newer). On non-ML runtime clusters, confirm your cluster image before assuming it's available. On government Databricks GovCloud, verify your cluster is running a DBR ML variant — the plain DBR runtime omits it.

---

## Measurement That Actually Matters

The 94% accuracy number that Marcus put in the briefing slide failed the admiral's test for a reason that statistics textbooks describe but practitioners forget: aggregate metrics hide the performance that matters most.

Federal ML projects need three things that standard tutorials skip.

### Stratified Performance

You need performance metrics broken out by the subgroups that matter operationally — not just overall AUC. For readiness models: by hull class, by homeport, by command. For personnel models: by grade, by rating, by years of service. For contract models: by competition type, by NAICS sector, by contract vehicle.

```python
def stratified_eval_report(model, X_test: pd.DataFrame, y_test: np.ndarray,
                            stratify_col: str, min_slice_size: int = 50) -> pd.DataFrame:
    """
    Compute performance metrics separately for each value of a stratification column.

    Args:
        model: Fitted sklearn-compatible model
        X_test: Test features DataFrame (must include stratify_col)
        y_test: True labels
        stratify_col: Column name to slice on
        min_slice_size: Minimum samples required to compute metrics on a slice

    Returns:
        DataFrame with per-slice metrics sorted by AUC ascending
        (worst-performing slices first — that's what you need to present)
    """
    y_proba = model.predict_proba(X_test)[:, 1]
    results = []

    for value in X_test[stratify_col].unique():
        mask = X_test[stratify_col] == value
        n    = int(mask.sum())
        if n < min_slice_size:
            continue

        slice_auc     = roc_auc_score(y_test[mask], y_proba[mask])
        slice_ap      = average_precision_score(y_test[mask], y_proba[mask])
        positive_rate = float(y_test[mask].mean())

        results.append({
            "slice":         value,
            "n":             n,
            "positive_rate": round(positive_rate, 3),
            "auc":           round(slice_auc, 3),
            "avg_precision": round(slice_ap, 3),
        })

    results_df = pd.DataFrame(results).sort_values("auc", ascending=True)
    print(f"\nStratified report by '{stratify_col}' (worst first):")
    print(results_df.to_string(index=False))
    return results_df
```

The worst-performing slice is what you present to the decision-maker first. If your model performs at AUC 0.91 overall but 0.61 on the hull class that makes up 40% of the fleet, you do not have a deployable model. You have a model that works on some ships and is nearly random on others.

### Threshold Selection for Asymmetric Costs

Classification models output probabilities. At some threshold — typically 0.5 by default — you convert those probabilities to binary predictions. The default threshold is almost always wrong for government use cases.

The cost of a false positive (flagging a good contract as risky, expediting a supply item unnecessarily) is not the same as the cost of a false negative (missing a failing contract, leaving a Priority 01 item in the standard queue). Setting the threshold requires knowing that ratio.

```python
def find_operational_threshold(y_true: np.ndarray, y_proba: np.ndarray,
                                cost_fp: float, cost_fn: float) -> float:
    """
    Find the classification threshold that minimizes total operational cost.

    Args:
        y_true:   True binary labels
        y_proba:  Predicted probabilities for positive class
        cost_fp:  Cost of a false positive (flagging a non-event)
        cost_fn:  Cost of a false negative (missing a real event)

    Returns:
        Optimal threshold value
    """
    from sklearn.metrics import confusion_matrix

    thresholds   = np.linspace(0.05, 0.95, 91)
    total_costs  = []

    for t in thresholds:
        y_pred = (y_proba >= t).astype(int)
        tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel()
        total_costs.append(fp * cost_fp + fn * cost_fn)

    optimal_idx       = int(np.argmin(total_costs))
    optimal_threshold = thresholds[optimal_idx]

    print(f"Cost ratio FP:FN = {cost_fp}:{cost_fn}")
    print(f"Optimal threshold: {optimal_threshold:.2f}")
    print(f"  Default 0.50 total cost : {total_costs[45]:,.0f}")
    print(f"  Optimal {optimal_threshold:.2f} total cost : {total_costs[optimal_idx]:,.0f}")

    return float(optimal_threshold)

# Example: expediting a supply item costs $2,000 (false positive)
# A Priority 01 item delayed costs $50,000 (false negative)
# threshold = find_operational_threshold(y_test, y_proba, cost_fp=2_000, cost_fn=50_000)
```

### Model Interpretability with SHAP

On every federal platform that deploys a model affecting operational or administrative decisions, someone will ask "why did it predict this?" SHAP (SHapley Additive exPlanations) is the standard answer. It assigns each feature a contribution value for each individual prediction.

```python
import shap

def explain_model_predictions(model_pipeline, X_sample: pd.DataFrame,
                               feature_names: list) -> None:
    """
    Generate SHAP explanations for a fitted sklearn Pipeline.

    Args:
        model_pipeline: Fitted Pipeline with named steps "prep" and "clf"
        X_sample: Sample of test data (100-500 rows is sufficient for plots)
        feature_names: Human-readable names for the plot labels
    """
    preprocessor = model_pipeline.named_steps["prep"]
    classifier   = model_pipeline.named_steps["clf"]
    X_transformed = preprocessor.transform(X_sample)

    # TreeExplainer works with tree-based models (RF, GBT, XGBoost)
    explainer   = shap.TreeExplainer(classifier)
    shap_values = explainer.shap_values(X_transformed)

    # For binary classification, shap_values is a list [class_0, class_1]
    if isinstance(shap_values, list):
        shap_values = shap_values[1]

    # Summary plot — overall feature importance across all predictions
    plt.figure(figsize=(10, 6))
    shap.summary_plot(
        shap_values,
        X_transformed,
        feature_names=feature_names,
        show=False,
        max_display=10,
    )
    plt.title("Feature Impact on Maintenance Overrun Prediction")
    plt.tight_layout()
    plt.savefig("/tmp/shap_summary.png", dpi=150, bbox_inches="tight")
    plt.show()
```

SHAP waterfall plots are the answer to "why did the model flag this contract?" You show a supply officer: "This requisition was flagged because the vendor's historical on-time rate is 62% (pushes toward late), it's Priority 01 (pushes toward scrutiny), and the item's demand frequency is low (harder to source quickly)." That explanation lands. "The model said so" doesn't.

---

## Hyperparameter Tuning on Databricks

Manual grid search is slow and unsophisticated. On Databricks, you have two better options.

**Hyperopt** is built into Databricks Runtime ML. It uses Bayesian optimization — smarter than grid search because it learns from previous trials which parameter regions are promising. Combined with SparkTrials, it runs trials in parallel across your cluster.

```python
from hyperopt import fmin, tpe, hp, SparkTrials, STATUS_OK
from sklearn.model_selection import cross_val_score

def objective(params):
    """Hyperopt objective — minimize negative AUC."""
    model = Pipeline([
        ("prep", preprocessor),
        ("clf", GradientBoostingClassifier(
            n_estimators=int(params["n_estimators"]),
            max_depth=int(params["max_depth"]),
            learning_rate=params["learning_rate"],
            subsample=params["subsample"],
            random_state=42,
        ))
    ])
    auc = cross_val_score(
        model, X_train, y_train, cv=3, scoring="roc_auc", n_jobs=-1
    ).mean()
    return {"loss": -auc, "status": STATUS_OK}

search_space = {
    "n_estimators":  hp.quniform("n_estimators", 100, 500, 50),
    "max_depth":     hp.quniform("max_depth", 3, 8, 1),
    "learning_rate": hp.loguniform("learning_rate", np.log(0.01), np.log(0.2)),
    "subsample":     hp.uniform("subsample", 0.6, 1.0),
}

spark_trials = SparkTrials(parallelism=4)

with mlflow.start_run(run_name="hyperopt_search"):
    best_params = fmin(
        fn=objective,
        space=search_space,
        algo=tpe.suggest,
        max_evals=50,
        trials=spark_trials,
    )

print(f"Best parameters: {best_params}")
```

Each Hyperopt trial is automatically logged to MLflow. After the search, you can compare all 50 trials in the MLflow UI and trace exactly which parameter combination produced the best result.

---

## Batch Scoring in Production

Training a model is 20% of the work. Getting it to score new data reliably, on schedule, with monitoring, is the other 80%. On Databricks, production batch scoring runs as a Workflow job.

```python
# This script runs as a Databricks Workflow task (scheduled job)
# Not run interactively — triggered on a schedule or by an upstream pipeline

import mlflow.pyfunc
from pyspark.sql import SparkSession, functions as F
import pandas as pd
from datetime import date

spark = SparkSession.getActiveSession()

# Load production model — always use stage alias, never hardcode a version number
model_name = "maintenance_overrun_classifier"
model      = mlflow.pyfunc.load_model(f"models:/{model_name}/Production")

# Score all open work orders from the last 90 days
pending = (
    spark.table("jupiter_catalog.silver.maintenance_work_orders")
    .filter(F.col("completion_date").isNull())
    .filter(F.col("start_date") >= F.date_sub(F.current_date(), 90))
    .join(
        spark.table("jupiter_catalog.reference.ship_registry")
             .select("hull_number", "hull_class", "commission_year"),
        "hull_number", "left"
    )
    .withColumn("ship_age_years",
        F.year(F.current_date()) - F.col("commission_year"))
    .withColumn("start_month", F.month("start_date"))
    .select(
        "work_order_id", "hull_number", "hull_class",
        "maintenance_category", "labor_hours_estimated",
        "estimated_completion_days", "ship_age_years",
        "prior_work_order_count", "start_month", "data_quality_score"
    )
    .toPandas()
)

print(f"Scoring {len(pending):,} pending work orders as of {date.today()}")

feature_cols = [
    "labor_hours_estimated", "estimated_completion_days", "ship_age_years",
    "prior_work_order_count", "start_month", "data_quality_score",
    "hull_class", "maintenance_category"
]
scores = model.predict(pending[feature_cols])

pending["overrun_probability"] = scores
pending["overrun_flag"]        = (scores >= 0.65).astype(int)  # operational threshold
pending["scored_date"]         = date.today().isoformat()
pending["model_version"]       = "Production"

output_spark = spark.createDataFrame(
    pending[["work_order_id", "overrun_probability",
             "overrun_flag", "scored_date", "model_version"]]
)
(
    output_spark
    .write.format("delta")
    .mode("overwrite")
    .option("replaceWhere", f"scored_date = '{date.today().isoformat()}'")
    .saveAsTable("jupiter_catalog.gold.maintenance_overrun_scores")
)

print(f"Written {len(pending):,} scores to gold layer")
print(f"Flagged {pending['overrun_flag'].sum():,} "
      f"({pending['overrun_flag'].mean()*100:.1f}%) as overrun-risk")
```

---

## Where This Goes Wrong

**Failure Mode 1: The Data Cutoff Problem**

**The mistake:** Training on all available years without accounting for the fact that labels from recent periods are incomplete.

**Why smart people make it:** You have data. More data is better for training. Why not use it all?

**How to recognize you're making it:**
- Your training label is defined by an event that takes time to resolve (contract completion, failure, separation)
- Records from the last 6-12 months in your training set have unusually low positive rates
- Your model underperforms on recent hold-out data compared to older data
- Your feature list includes the record date and the model gives it high importance

**What to do instead:** Establish a label cutoff — any record where the outcome has not yet resolved gets excluded from training. For a contract cost growth model, only include contracts that completed at least 12 months ago.

---

**Failure Mode 2: Leaking the Future Into the Past**

**The mistake:** Including features that were calculated using information available only after the event you're trying to predict.

**Why smart people make it:** Feature engineering is done on the full dataset. It's easy to accidentally compute a feature that uses future data — especially aggregated features like "this vendor's average cost growth across all their contracts."

**How to recognize you're making it:**
- Model AUC is unrealistically high (> 0.98 on a hard problem)
- Feature importance puts an aggregated feature at the top by a large margin
- Performance degrades sharply when tested on a time-based hold-out vs. a random split

**What to do instead:** Always compute aggregated features using only data available at prediction time. Use temporal cross-validation (train on years 1-3, test on year 4) rather than random splits for time-series-dependent problems.

---

**Failure Mode 3: Deploying Without a Monitoring Plan**

**The mistake:** Getting model approval, deploying to production, and moving on to the next contract.

**Why smart people make it:** Deployment feels like the finish line. The model is scoring. You're done.

**How to recognize you're making it:**
- There is no scheduled job checking whether predictions match outcomes
- Nobody knows what the model's current false positive rate is
- The training data is now two years old and the operational environment has changed
- When someone asks "is the model still working?", nobody has a ready answer

**What to do instead:** At deployment time, define three things in writing: a drift detection metric, a performance monitoring query, and a retraining trigger. On Databricks, this is a scheduled Workflow job. On Foundry, it's a monitoring Transform. Schedule it before you close the project.

---

## Practical Takeaway: Model Readiness Assessment

Before you present a model to a program manager or request authorization to deploy, score it against this checklist.

**Data quality:**
- [ ] Is the label defined clearly and documented in writing?
- [ ] Have you verified the label is assigned consistently across the training period?
- [ ] Is there a data cutoff that excludes incomplete label resolutions?
- [ ] Have you checked for temporal leakage using a time-based hold-out?

**Performance:**
- [ ] Have you measured performance on the subgroups that matter operationally?
- [ ] Have you calculated performance at the operational threshold, not just AUC?
- [ ] Do you know the false positive and false negative rates at the decision threshold?
- [ ] Do you know the cost ratio of a false positive vs. false negative for this use case?

**Interpretability:**
- [ ] Can you explain an individual prediction in plain English to a non-statistician?
- [ ] Have you generated SHAP values and reviewed the top driving features?
- [ ] Are any top features potentially proxies for protected characteristics?

**Operations:**
- [ ] Is the model logged in MLflow (Databricks) or a Foundry versioned dataset?
- [ ] Is there a batch scoring job that runs on a defined schedule?
- [ ] Is there a monitoring job that checks for prediction drift?
- [ ] Is there a retraining trigger defined in writing?
- [ ] Who is the model owner when you roll off this contract?

---

## Platform Comparison

| Dimension | Advana (Databricks) | Palantir Foundry | Databricks GovCloud | Navy Jupiter |
|---|---|---|---|---|
| Primary ML framework | scikit-learn, XGBoost, MLflow | scikit-learn via Code Workspaces | scikit-learn, XGBoost, MLflow | scikit-learn, XGBoost, MLflow |
| Experiment tracking | MLflow (native) | Foundry versioned artifacts | MLflow (native) | MLflow (native) |
| Model registry | MLflow Model Registry | Foundry datasets + Ontology | MLflow Model Registry | MLflow Model Registry |
| Hyperparameter tuning | Hyperopt + SparkTrials | Custom loops in Code Workspaces | Hyperopt + SparkTrials | Hyperopt + SparkTrials |
| Batch scoring | Databricks Workflows | Foundry Transforms (scheduled) | Databricks Workflows | Databricks Workflows |
| Real-time serving | Mosaic AI Model Serving | AIP Logic + Foundry Functions | Mosaic AI Model Serving | Limited |
| SHAP interpretability | Pre-installed (DBR ML) | Available via conda | Pre-installed (DBR ML) | Pre-installed (DBR ML) |
| IL5 support | Yes | Yes | Yes | Yes (SIPR) |

---

## Exercises

See [exercises/exercises.md](./exercises/exercises.md) for hands-on problems.

---

## Chapter Close

**The one thing to remember:** A model's aggregate accuracy number is almost always misleading — the subgroup where it performs worst is usually the operationally critical one, and that number is what you present first.

**What to do Monday morning:** Take the last model you trained or inherited. Run a stratified performance breakdown against the most operationally relevant subgroup column. Look at the worst-performing slice. If you can't explain why it underperforms there, you are not ready to brief it to anyone above the GS-13 level.

**What comes next:** Chapter 07 covers unsupervised learning — clustering, anomaly detection, and dimensionality reduction. The connection to supervised learning is direct: before you can train a readiness or contract risk classifier, you often need to understand the structure of your data well enough to define a meaningful label in the first place. Clustering anomalous maintenance patterns before you build a failure predictor is not optional cleanup — it is the work that makes the predictor meaningful.
