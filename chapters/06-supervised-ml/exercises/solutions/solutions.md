# Chapter 06 Exercise Solutions

---

## Exercise 1 Solution: The Admiral's Question

```python
import numpy as np
import pandas as pd
import sys
sys.path.insert(0, "../../code-examples/python")
from classification_pipeline import (
    generate_requisition_data, engineer_features,
    build_and_train_pipeline, stratified_eval_report
)
from sklearn.model_selection import train_test_split

# Generate data and train
raw_df = generate_requisition_data(n=25_000)
feat_df, num_cols, cat_cols = engineer_features(raw_df)

# Keep vendor_name in features for vendor-level stratification
feat_df_with_vendor = feat_df.copy()
feat_df_with_vendor["vendor_name"] = raw_df["vendor_name"]

X = feat_df[num_cols + cat_cols]
y = feat_df["late_delivery"].values

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, stratify=y, random_state=42
)

model = build_and_train_pipeline(X_train, y_train, num_cols, cat_cols)

# Stratified reports
X_test_with_raw = X_test.copy()
X_test_with_raw["vendor_name"] = raw_df.loc[X_test.index, "vendor_name"].values

# Priority code breakdown
priority_report = stratified_eval_report(model, X_test, y_test, "priority_code")

# Supply class breakdown (add supply_class back to X_test)
X_test_supply = X_test.copy()
X_test_supply["supply_class"] = raw_df.loc[X_test.index, "supply_class"].values
supply_report = stratified_eval_report(model, X_test_supply, y_test, "supply_class")

# Vendor breakdown
vendor_report = stratified_eval_report(model, X_test_with_raw, y_test, "vendor_name")

print(priority_report)
print(supply_report)
print(vendor_report)
```

**Why the worst slice underperforms (example reasoning):**

Priority code "01" often underperforms because it represents a small fraction of total requisitions (around 5%) — the model sees very few examples of Priority 01 requisitions during training, so it learns the pattern less reliably than for Priority 08-15 codes, which dominate the training distribution. Additionally, Priority 01 requisitions may have different vendor and routing behaviors that don't generalize well from the broader training distribution.

Supply class "I" (subsistence) may underperform because its supply chain characteristics (perishability, different vendor relationships, different depot routing) are structurally different from repair parts (class IX), which dominates the training data.

**Rewrite of the briefing statement:**

"The model achieves AUC of 0.87 across all requisitions. Performance varies by priority: AUC is [X] for Priority 01-02 mission-critical requisitions and [Y] for Priority 08-15 routine requisitions. The model is most reliable for [best-performing category] and least reliable for [worst-performing category], which represents [Z]% of depot volume. Operational use should account for this performance difference at the priority level."

---

## Exercise 2 Solution: Threshold Optimization

```python
import numpy as np
import pandas as pd
from sklearn.metrics import confusion_matrix
from sklearn.model_selection import train_test_split

# Generate and train
raw_df = generate_requisition_data(n=25_000)
feat_df, num_cols, cat_cols = engineer_features(raw_df)
X = feat_df[num_cols + cat_cols]
y = feat_df["late_delivery"].values

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, stratify=y, random_state=42
)
model = build_and_train_pipeline(X_train, y_train, num_cols, cat_cols)
y_proba = model.predict_proba(X_test)[:, 1]

# Blended FN cost: Priority 01 = $45,000 / Priority 08-15 = $800
# Priority 01/02 rate in test set ≈ 15%
priority_high_rate = 0.15
blended_fn_cost = priority_high_rate * 45_000 + (1 - priority_high_rate) * 800
fp_cost = 1_800

print(f"Blended FN cost: ${blended_fn_cost:,.0f}")
print(f"FP cost: ${fp_cost:,.0f}")

from classification_pipeline import find_operational_threshold
optimal_threshold = find_operational_threshold(
    y_test, y_proba, cost_fp=fp_cost, cost_fn=blended_fn_cost
)

def threshold_cost_analysis(y_true, y_proba, threshold, cost_fp, cost_fn, label):
    """Compute operational metrics at a given threshold."""
    y_pred = (y_proba >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel()
    total_cost = fp * cost_fp + fn * cost_fn
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0

    print(f"\n{label} (threshold={threshold:.2f}):")
    print(f"  False Positive Rate : {fpr*100:.1f}%  ({fp:,} FPs)")
    print(f"  False Negative Rate : {fnr*100:.1f}%  ({fn:,} FNs)")
    print(f"  Total estimated cost: ${total_cost:,.0f}")
    return {"threshold": threshold, "fpr": fpr, "fnr": fnr, "total_cost": total_cost}

r_default  = threshold_cost_analysis(y_test, y_proba, 0.50,
                                      fp_cost, blended_fn_cost, "Default")
r_optimal  = threshold_cost_analysis(y_test, y_proba, optimal_threshold,
                                      fp_cost, blended_fn_cost, "Optimal")
r_conserv  = threshold_cost_analysis(y_test, y_proba, 0.30,
                                      fp_cost, blended_fn_cost, "Conservative")

savings = r_default["total_cost"] - r_optimal["total_cost"]
print(f"\nSavings vs. default threshold: ${savings:,.0f}")
```

**Recommendation to the operations officer (example):**

"We recommend using a classification threshold of [optimal value] rather than the statistical default of 0.50. At the optimal threshold, the model flags approximately [X]% of requisitions for expediting review, compared to [Y]% at the default setting. Given the cost asymmetry between an unnecessary expedite ($1,800) and a missed Priority 01 delay ($45,000), the optimal threshold reduces total estimated daily operating cost by approximately $[Z] per [N] requisitions scored. The conservative threshold (0.30) flags even more requisitions but produces diminishing returns — it costs more in unnecessary expediting than it saves by catching additional Priority 01 delays."

---

## Exercise 3 Solution: Temporal Leakage Detection

```python
import numpy as np
import pandas as pd
import xgboost as xgb
from sklearn.metrics import mean_absolute_error, r2_score
from sklearn.model_selection import train_test_split

# Generate data
from regression_and_xgboost import (
    generate_contract_data, prepare_regression_features,
    temporal_train_test_split, evaluate_regression_model
)

df = generate_contract_data(n=15_000)

# ---- Model A: Random split ----
train_rnd, test_rnd = train_test_split(df, test_size=0.2, random_state=42)
X_a, y_a, feat_names, encoder_a, _ = prepare_regression_features(train_rnd)
# Prepare test with same encoder
test_rnd = test_rnd.copy()
test_rnd["log_cost_growth"] = np.log1p(test_rnd["cost_growth_ratio"].clip(-0.99))
test_rnd["log_base_obligation"] = np.log1p(test_rnd["base_obligation"])
test_rnd["log_pop_days"]        = np.log1p(test_rnd["period_of_performance_days"])
test_rnd["log_vendor_awards"]   = np.log1p(test_rnd["vendor_prior_awards"])

numeric_features     = ["log_base_obligation", "log_pop_days", "prior_modifications",
                         "log_vendor_awards", "is_defense_acquisition", "fiscal_year"]
categorical_features = ["contract_type", "competition_type", "naics_sector"]
from sklearn.preprocessing import OrdinalEncoder
cat_test = encoder_a.transform(test_rnd[categorical_features])
X_test_a = np.hstack([test_rnd[numeric_features].values, cat_test])
y_test_a = test_rnd["log_cost_growth"].values

X_tr_a, X_val_a, y_tr_a, y_val_a = train_test_split(X_a, y_a, test_size=0.15, random_state=42)

model_a = xgb.XGBRegressor(
    n_estimators=500, max_depth=5, learning_rate=0.03, subsample=0.8,
    min_child_weight=15, early_stopping_rounds=30, random_state=42
)
model_a.fit(X_tr_a, y_tr_a, eval_set=[(X_val_a, y_val_a)], verbose=False)
print("Model A (Random split):")
evaluate_regression_model(model_a, X_test_a, y_test_a, "Random hold-out")

# ---- Model B: Temporal split ----
train_t, test_t = temporal_train_test_split(
    df, train_years=list(range(2018, 2023)), test_years=[2023, 2024]
)
X_b, y_b, feat_names_b, encoder_b, p_clip = prepare_regression_features(train_t)

test_t = test_t.copy()
test_t["log_cost_growth"] = np.log1p(test_t["cost_growth_ratio"].clip(-0.99, p_clip))
test_t["log_base_obligation"] = np.log1p(test_t["base_obligation"])
test_t["log_pop_days"]        = np.log1p(test_t["period_of_performance_days"])
test_t["log_vendor_awards"]   = np.log1p(test_t["vendor_prior_awards"])
cat_test_b = encoder_b.transform(test_t[categorical_features])
X_test_b   = np.hstack([test_t[numeric_features].values, cat_test_b])
y_test_b   = test_t["log_cost_growth"].values

X_tr_b, X_val_b, y_tr_b, y_val_b = train_test_split(X_b, y_b, test_size=0.15, random_state=42)

model_b = xgb.XGBRegressor(
    n_estimators=500, max_depth=5, learning_rate=0.03, subsample=0.8,
    min_child_weight=15, early_stopping_rounds=30, random_state=42
)
model_b.fit(X_tr_b, y_tr_b, eval_set=[(X_val_b, y_val_b)], verbose=False)
print("\nModel B (Temporal split):")
evaluate_regression_model(model_b, X_test_b, y_test_b, "Temporal hold-out")

# ---- Model A with leaky feature ----
# vendor_lifetime_avg_growth = mean cost_growth across ALL contracts for this vendor
# This is leaky — at prediction time, future contracts haven't happened yet
vendor_avg = df.groupby("contract_type")["cost_growth_ratio"].mean()  # simplified leakage
df_leaky = df.copy()
df_leaky["vendor_lifetime_avg_growth"] = df_leaky["contract_type"].map(vendor_avg)

train_leaky, test_leaky = train_test_split(df_leaky, test_size=0.2, random_state=42)
# The leaked feature correlates perfectly with cost_growth at the contract_type level
# Performance will appear artificially inflated
print("\nModel with leaky feature — compare R² to Model A:")
# (full implementation follows same pattern as Model A above, adding vendor_lifetime_avg_growth)
```

**Written explanation of temporal leakage:**

The leaky `vendor_lifetime_avg_growth` feature improves Model A's performance on the random split because some training contracts and their matched test contracts share the same vendor, and the aggregate feature was computed using both past and future contracts. The model learns to essentially look up the vendor's overall average, which is strongly correlated with individual contract outcomes — but this information wasn't available at the time any individual contract was awarded.

In production, the model would fail because the `vendor_lifetime_avg_growth` computed at scoring time would only include contracts that had already completed — not the future contracts that made the aggregate so predictive during training. The feature distribution would shift, and the model would degrade in ways that are hard to diagnose from monitoring alone.

Temporal cross-validation catches this because it trains only on past contracts and tests on future ones. In this regime, any feature computed using future data simply isn't present in the training set, making leakage impossible. The gap between Model A's R² and Model B's R² is a direct measurement of how much the random split was inflated by leakage.

---

## Exercise 4 Solution: MLflow Experiment Tracking

```python
import mlflow
from mlflow.tracking import MlflowClient
import numpy as np
import pandas as pd
from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler, OrdinalEncoder
from sklearn.compose import ColumnTransformer
from sklearn.model_selection import train_test_split
from sklearn.metrics import roc_auc_score, average_precision_score, f1_score

# Local tracking for testing
mlflow.set_tracking_uri("./mlruns")
mlflow.set_experiment("readiness_classifier_v2")

# Generate data (reuse from earlier exercises)
from classification_pipeline import generate_requisition_data, engineer_features

raw_df = generate_requisition_data(n=20_000)
feat_df, num_cols, cat_cols = engineer_features(raw_df)
X = feat_df[num_cols + cat_cols]
y = feat_df["late_delivery"].values

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, stratify=y, random_state=42
)

preprocessor = ColumnTransformer([
    ("num", StandardScaler(), num_cols),
    ("cat", OrdinalEncoder(handle_unknown="use_encoded_value", unknown_value=-1), cat_cols),
])

# Three runs
runs_config = [
    ("lr_baseline",   LogisticRegression(class_weight="balanced", C=0.1, max_iter=1000, random_state=42)),
    ("rf_200trees",   RandomForestClassifier(n_estimators=200, max_depth=8, class_weight="balanced", n_jobs=-1, random_state=42)),
    ("gbt_final",     GradientBoostingClassifier(n_estimators=300, max_depth=4, learning_rate=0.05, random_state=42)),
]

for run_name, clf in runs_config:
    pipeline = Pipeline([("prep", preprocessor), ("clf", clf)])
    pipeline.fit(X_train, y_train)
    y_proba = pipeline.predict_proba(X_test)[:, 1]
    y_pred  = (y_proba >= 0.5).astype(int)

    with mlflow.start_run(run_name=run_name):
        # Log model params
        clf_params = clf.get_params()
        for k, v in list(clf_params.items())[:6]:  # limit to first 6 params
            mlflow.log_param(k, v)
        mlflow.log_param("model_class", type(clf).__name__)

        # Log metrics
        auc = roc_auc_score(y_test, y_proba)
        ap  = average_precision_score(y_test, y_proba)
        f1  = f1_score(y_test, y_pred)
        mlflow.log_metric("test_roc_auc",       auc)
        mlflow.log_metric("test_avg_precision", ap)
        mlflow.log_metric("test_f1",            f1)

        # Stratified slice: supply_class
        for sc in feat_df["supply_class"].unique() if "supply_class" in feat_df.columns else []:
            mask = X_test.index.isin(
                feat_df[feat_df["supply_class"] == sc].index
            )
            if mask.sum() > 30:
                sc_auc = roc_auc_score(y_test[mask], y_proba[mask])
                mlflow.log_metric(f"auc_class_{sc}", sc_auc)

        mlflow.sklearn.log_model(pipeline, artifact_path="model",
                                  registered_model_name="readiness_classifier_v2",
                                  signature=mlflow.models.infer_signature(X_test, y_proba))
        print(f"{run_name:<20} AUC={auc:.4f}  AP={ap:.4f}  F1={f1:.4f}")


def select_best_run(experiment_name: str, metric: str = "test_roc_auc") -> str:
    """Return the run_id of the highest-scoring run in the experiment."""
    client  = MlflowClient()
    exp     = client.get_experiment_by_name(experiment_name)
    runs    = client.search_runs(
        experiment_ids=[exp.experiment_id],
        order_by=[f"metrics.{metric} DESC"],
    )

    rows = []
    for r in runs:
        rows.append({
            "run_id":   r.info.run_id,
            "run_name": r.data.tags.get("mlflow.runName", "unnamed"),
            metric:     r.data.metrics.get(metric, 0.0),
        })

    comparison = pd.DataFrame(rows).sort_values(metric, ascending=False)
    print(f"\nAll runs sorted by {metric}:")
    print(comparison.to_string(index=False))

    best_run_id = runs[0].info.run_id
    print(f"\nBest run: {runs[0].data.tags.get('mlflow.runName')} ({best_run_id})")
    return best_run_id


best_run_id = select_best_run("readiness_classifier_v2")

# Attempt promotion with tight quality gate (will fail intentionally)
try:
    from mlflow_and_batch_scoring import promote_model_to_staging
    promote_model_to_staging(
        model_name="readiness_classifier_v2",
        run_id=best_run_id,
        min_auc_threshold=0.99,   # intentionally too high
    )
except ValueError as e:
    print(f"\nQuality gate correctly blocked promotion: {e}")
    print("Rerun with min_auc_threshold=0.75 to promote the real best model.")
```

---

## Exercise 5 Solution: Build the Monitoring Job

```python
import numpy as np
import pandas as pd
from datetime import date, timedelta


def simulate_scoring_history(
    n_days: int = 60,
    baseline_flag_rate: float = 0.18,
    drift_start_day: int = 30,
    drift_rate_final: float = 0.32,
    n_per_day: int = 500,
    seed: int = 42,
) -> pd.DataFrame:
    """
    Simulate daily scoring history with distribution drift after drift_start_day.
    Flag rate rises linearly from baseline_flag_rate to drift_rate_final
    between drift_start_day and n_days.
    """
    rng    = np.random.default_rng(seed)
    rows   = []
    today  = date.today()

    for day_offset in range(n_days, 0, -1):
        scoring_date = today - timedelta(days=day_offset)
        day_num      = n_days - day_offset

        # Flag rate drifts after drift_start_day
        if day_num <= drift_start_day:
            flag_rate = baseline_flag_rate
        else:
            drift_progress = (day_num - drift_start_day) / (n_days - drift_start_day)
            flag_rate      = baseline_flag_rate + drift_progress * (drift_rate_final - baseline_flag_rate)

        flags  = rng.binomial(1, flag_rate, size=n_per_day)
        probs  = flags * rng.beta(7, 2, size=n_per_day) + (1 - flags) * rng.beta(2, 7, size=n_per_day)

        # Vendor reliability also drifts (simulates input feature shift)
        vendor_on_time = (
            rng.beta(8, 2, size=n_per_day)
            if day_num <= drift_start_day
            else rng.beta(4, 3, size=n_per_day)   # reliability degrades
        )

        for i in range(n_per_day):
            rows.append({
                "requisition_id":       f"REQ{day_offset}_{i:04d}",
                "scored_date":          scoring_date.isoformat(),
                "late_delivery_probability": round(float(probs[i]), 4),
                "late_delivery_flag":        int(flags[i]),
                "vendor_on_time_rate":       round(float(vendor_on_time[i]), 3),
            })

    return pd.DataFrame(rows)


def check_output_drift(
    history: pd.DataFrame,
    recent_days: int = 14,
    baseline_days: int = 30,
    drift_threshold_relative: float = 0.20,
) -> dict:
    """Check if the predicted flag rate has shifted significantly."""
    today   = pd.to_datetime(history["scored_date"]).max()
    cutoff  = today - pd.Timedelta(days=recent_days)
    base_start = cutoff - pd.Timedelta(days=baseline_days)

    recent   = history[pd.to_datetime(history["scored_date"]) > cutoff]
    baseline = history[
        (pd.to_datetime(history["scored_date"]) > base_start) &
        (pd.to_datetime(history["scored_date"]) <= cutoff)
    ]

    recent_rate   = recent["late_delivery_flag"].mean()
    baseline_rate = baseline["late_delivery_flag"].mean()
    rel_change    = abs(recent_rate - baseline_rate) / (baseline_rate + 1e-8)
    drifted       = bool(rel_change > drift_threshold_relative)

    return {
        "check": "output_drift",
        "recent_flag_rate":   round(float(recent_rate) * 100, 2),
        "baseline_flag_rate": round(float(baseline_rate) * 100, 2),
        "relative_change_pct": round(rel_change * 100, 1),
        "drifted":            drifted,
    }


def check_input_feature_drift(
    history: pd.DataFrame,
    feature_col: str = "vendor_on_time_rate",
    recent_days: int = 14,
    baseline_days: int = 30,
    abs_threshold: float = 0.05,
) -> dict:
    """Check if an input feature's mean has shifted beyond the threshold."""
    today   = pd.to_datetime(history["scored_date"]).max()
    cutoff  = today - pd.Timedelta(days=recent_days)
    base_start = cutoff - pd.Timedelta(days=baseline_days)

    recent   = history[pd.to_datetime(history["scored_date"]) > cutoff]
    baseline = history[
        (pd.to_datetime(history["scored_date"]) > base_start) &
        (pd.to_datetime(history["scored_date"]) <= cutoff)
    ]

    recent_mean   = recent[feature_col].mean()
    baseline_mean = baseline[feature_col].mean()
    abs_change    = abs(recent_mean - baseline_mean)
    drifted       = bool(abs_change > abs_threshold)

    return {
        "check":          f"input_drift_{feature_col}",
        "recent_mean":    round(float(recent_mean), 4),
        "baseline_mean":  round(float(baseline_mean), 4),
        "abs_change":     round(float(abs_change), 4),
        "threshold":      abs_threshold,
        "drifted":        drifted,
    }


def monitoring_report(history: pd.DataFrame) -> dict:
    """Run all drift checks and return unified report with action recommendation."""
    output_check  = check_output_drift(history)
    feature_check = check_input_feature_drift(history)

    both_drifted   = output_check["drifted"] and feature_check["drifted"]
    either_drifted = output_check["drifted"] or feature_check["drifted"]

    if both_drifted:
        action = "retrain required"
    elif either_drifted:
        action = "investigate"
    else:
        action = "no action"

    report = {
        "output_drift":          output_check,
        "input_feature_drift":   feature_check,
        "recommended_action":    action,
    }

    print("\n=== Weekly Monitoring Report ===")
    print(f"Output drift detected : {output_check['drifted']}")
    print(f"  Recent flag rate : {output_check['recent_flag_rate']}%")
    print(f"  Baseline rate    : {output_check['baseline_flag_rate']}%")
    print(f"  Change           : {output_check['relative_change_pct']}%")
    print(f"\nInput feature drift detected: {feature_check['drifted']}")
    print(f"  Recent mean vendor reliability : {feature_check['recent_mean']:.3f}")
    print(f"  Baseline mean vendor reliability: {feature_check['baseline_mean']:.3f}")
    print(f"  Absolute change: {feature_check['abs_change']:.4f}")
    print(f"\nRecommended action: {action.upper()}")

    return report


# Run the monitoring demo
history = simulate_scoring_history(n_days=60, drift_start_day=30)
report  = monitoring_report(history)
```

**Why you need both input and output monitoring:**

Output monitoring (tracking the flag rate and mean probability over time) tells you when the model's predictions have changed, but it cannot tell you why. A rising flag rate could mean the real world has actually changed (more late deliveries are genuinely happening), the input feature distribution has shifted (vendor reliability has degraded across the board), or the model has developed a bug. Input feature monitoring distinguishes between these cases by checking whether the data the model is receiving has changed before the model's predictions change — often the early warning arrives in the input features 1-2 weeks before it shows up in the output scores. Catching input drift early gives the team time to investigate and retrain proactively rather than reacting after the model has already been producing bad predictions for weeks.

---

*Solutions represent one valid approach. If your code produces the same stratified analysis, cost calculations, or drift detections with different implementation, it is equally correct. The criteria that matter: did you stratify by operationally meaningful categories, did you account for asymmetric costs, and did you distinguish input drift from output drift?*
