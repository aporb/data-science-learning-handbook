"""
Chapter 06: Supervised Machine Learning on Federal Platforms
Code Example 01: End-to-End Classification Pipeline

Use case: Predict whether a Navy supply requisition will result in late delivery.
Platform: Databricks (Advana / Jupiter)

This file is structured as a standalone script. On Databricks, paste sections
into notebook cells in order. The synthetic data generator replaces
spark.table() calls so this can be tested locally without platform access.

Sections:
    1. Synthetic data generation (replaces live platform data)
    2. Feature engineering
    3. Model training with scikit-learn Pipeline
    4. Stratified performance reporting
    5. Threshold optimization
    6. SHAP interpretability
    7. MLflow logging
"""

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import StratifiedKFold, cross_validate, train_test_split
from sklearn.preprocessing import StandardScaler, OrdinalEncoder
from sklearn.pipeline import Pipeline
from sklearn.compose import ColumnTransformer
from sklearn.metrics import (
    roc_auc_score, average_precision_score,
    confusion_matrix, classification_report,
)
import warnings
warnings.filterwarnings("ignore", category=UserWarning)


# ===========================================================================
# SECTION 1: SYNTHETIC DATA (replaces spark.table() on live platform)
# ===========================================================================

def generate_requisition_data(n: int = 20_000, seed: int = 42) -> pd.DataFrame:
    """
    Generate synthetic supply requisition data mimicking MILSTRIP records.

    Real data would come from:
        spark.table("jupiter_catalog.silver.milstrip_requisitions")
        .filter(F.col("fiscal_year").between(2021, 2024))
        .toPandas()

    Args:
        n: Number of requisitions to generate
        seed: Random seed for reproducibility

    Returns:
        DataFrame with requisition features and late_delivery label
    """
    rng = np.random.default_rng(seed)

    # Priority codes — Priority 01/02 are mission-critical
    priority_codes = ["01", "02", "03", "04", "06", "08", "13", "15"]
    priority_weights = [0.05, 0.10, 0.15, 0.20, 0.15, 0.15, 0.10, 0.10]

    # Vendors with varying reliability profiles
    vendors = {
        "V-Alpha":   0.85,   # reliable
        "V-Beta":    0.72,   # moderate
        "V-Gamma":   0.61,   # poor
        "V-Delta":   0.90,   # very reliable
        "V-Epsilon": 0.55,   # unreliable
        "V-Zeta":    0.78,   # moderate
        "V-Eta":     0.68,   # below average
        "V-Theta":   0.82,   # good
    }
    vendor_names   = list(vendors.keys())
    vendor_rates   = np.array(list(vendors.values()))

    n_vendors   = len(vendor_names)
    vendor_idx  = rng.choice(n_vendors, size=n)
    vendor_col  = [vendor_names[i] for i in vendor_idx]
    on_time_rate = vendor_rates[vendor_idx]

    priority_col = rng.choice(priority_codes, size=n, p=priority_weights)

    # Days until required delivery — shorter = harder to meet
    days_to_required = rng.integers(1, 60, size=n)

    # Demand frequency of the NSN — lower = harder to source
    nsn_demand_frequency = rng.lognormal(mean=2.0, sigma=1.2, size=n).clip(0.1, 200)

    # Current stock on hand (0 = out of stock, must order)
    stock_on_hand = rng.integers(0, 20, size=n)

    # Supply class — I (subsistence), II (clothing), III (fuels), VIII (medical), IX (repair parts)
    supply_class = rng.choice(["I", "II", "III", "VIII", "IX"], size=n,
                               p=[0.05, 0.10, 0.05, 0.10, 0.70])

    # Fiscal year quarter
    fy_quarter = rng.choice([1, 2, 3, 4], size=n)

    # Generate label: late_delivery
    # Probability increases with: lower vendor on-time rate, higher priority (paradoxically
    # harder to fulfill fast), shorter time to required date, out-of-stock items
    logit = (
        - 1.5                                          # base rate ~18% late
        + (1 - on_time_rate) * 4.0                    # vendor reliability
        + (priority_col <= "02").astype(float) * 0.4  # high-priority orders
        - np.log1p(days_to_required) * 0.3            # more time = less likely late
        - np.log1p(nsn_demand_frequency) * 0.2        # common parts easier to get
        + (stock_on_hand == 0).astype(float) * 1.2   # out of stock = often late
        + rng.normal(0, 0.5, size=n)                  # noise
    )
    prob_late     = 1 / (1 + np.exp(-logit))
    late_delivery = (rng.random(size=n) < prob_late).astype(int)

    df = pd.DataFrame({
        "requisition_id":       [f"REQ{i:07d}" for i in range(n)],
        "vendor_name":          vendor_col,
        "vendor_on_time_rate":  on_time_rate.round(3),
        "priority_code":        priority_col,
        "days_to_required":     days_to_required,
        "nsn_demand_frequency": nsn_demand_frequency.round(2),
        "stock_on_hand":        stock_on_hand,
        "supply_class":         supply_class,
        "fy_quarter":           fy_quarter,
        "late_delivery":        late_delivery,
    })

    print(f"Generated {n:,} requisitions | Late rate: {late_delivery.mean()*100:.1f}%")
    print(f"Priority 01/02 late rate: "
          f"{df[df['priority_code'] <= '02']['late_delivery'].mean()*100:.1f}%")
    return df


# ===========================================================================
# SECTION 2: FEATURE ENGINEERING
# ===========================================================================

def engineer_features(df: pd.DataFrame) -> tuple[pd.DataFrame, list, list]:
    """
    Build model-ready features from raw requisition records.

    Returns:
        Tuple of (feature_df, numeric_feature_names, categorical_feature_names)
    """
    feat = df.copy()

    # Log-transform skewed numerics
    feat["log_nsn_demand"]   = np.log1p(feat["nsn_demand_frequency"])
    feat["log_days_required"] = np.log1p(feat["days_to_required"])

    # Binary indicators
    feat["is_out_of_stock"]     = (feat["stock_on_hand"] == 0).astype(int)
    feat["is_mission_critical"] = feat["priority_code"].isin(["01", "02"]).astype(int)

    # Stock quantile bucket (0 = none, 1 = low, 2 = medium, 3 = high)
    feat["stock_bucket"] = pd.cut(
        feat["stock_on_hand"], bins=[-1, 0, 3, 9, 20],
        labels=["none", "low", "medium", "high"]
    ).astype(str)

    numeric_features = [
        "vendor_on_time_rate",
        "log_nsn_demand",
        "log_days_required",
        "stock_on_hand",
        "is_out_of_stock",
        "is_mission_critical",
        "fy_quarter",
    ]
    categorical_features = [
        "supply_class",
        "stock_bucket",
    ]

    return feat, numeric_features, categorical_features


# ===========================================================================
# SECTION 3: PIPELINE TRAINING
# ===========================================================================

def build_and_train_pipeline(
    X_train: pd.DataFrame,
    y_train: np.ndarray,
    numeric_features: list,
    categorical_features: list,
) -> Pipeline:
    """
    Build and fit an sklearn Pipeline for the late delivery classifier.
    Returns fitted pipeline ready for prediction and SHAP explanation.
    """
    preprocessor = ColumnTransformer([
        ("num", StandardScaler(), numeric_features),
        ("cat", OrdinalEncoder(
            handle_unknown="use_encoded_value", unknown_value=-1
        ), categorical_features),
    ], remainder="drop")

    pipeline = Pipeline([
        ("prep", preprocessor),
        ("clf", GradientBoostingClassifier(
            n_estimators=300,
            max_depth=4,
            learning_rate=0.05,
            subsample=0.8,
            min_samples_leaf=20,
            random_state=42,
        ))
    ])

    pipeline.fit(X_train, y_train)
    return pipeline


def cross_validate_models(
    X: pd.DataFrame,
    y: np.ndarray,
    preprocessor: ColumnTransformer,
    cv_folds: int = 5,
) -> pd.DataFrame:
    """
    Compare multiple model architectures using stratified cross-validation.
    Returns a DataFrame of mean CV scores, sorted by ROC-AUC descending.
    """
    candidate_models = {
        "Logistic Regression": LogisticRegression(
            class_weight="balanced", C=0.1, max_iter=1000, random_state=42
        ),
        "Random Forest": RandomForestClassifier(
            n_estimators=200, max_depth=8, class_weight="balanced",
            n_jobs=-1, random_state=42
        ),
        "Gradient Boosting": GradientBoostingClassifier(
            n_estimators=300, max_depth=4, learning_rate=0.05,
            subsample=0.8, random_state=42
        ),
    }

    cv = StratifiedKFold(n_splits=cv_folds, shuffle=True, random_state=42)
    rows = []

    for name, clf in candidate_models.items():
        pipeline = Pipeline([("prep", preprocessor), ("clf", clf)])
        scores   = cross_validate(
            pipeline, X, y, cv=cv,
            scoring=["roc_auc", "average_precision", "f1_weighted"],
            n_jobs=-1,
        )
        rows.append({
            "model":       name,
            "roc_auc":     scores["test_roc_auc"].mean().round(4),
            "avg_prec":    scores["test_average_precision"].mean().round(4),
            "f1_weighted": scores["test_f1_weighted"].mean().round(4),
        })
        print(f"  {name:<25} AUC={rows[-1]['roc_auc']:.3f}  "
              f"AP={rows[-1]['avg_prec']:.3f}  F1={rows[-1]['f1_weighted']:.3f}")

    return pd.DataFrame(rows).sort_values("roc_auc", ascending=False)


# ===========================================================================
# SECTION 4: STRATIFIED PERFORMANCE REPORTING
# ===========================================================================

def stratified_eval_report(
    model: Pipeline,
    X_test: pd.DataFrame,
    y_test: np.ndarray,
    stratify_col: str,
    min_slice_size: int = 30,
) -> pd.DataFrame:
    """
    Compute AUC and average precision for each value of stratify_col.
    Returns results sorted by AUC ascending — worst slices first.
    """
    y_proba = model.predict_proba(X_test)[:, 1]
    rows    = []

    for value in sorted(X_test[stratify_col].unique()):
        mask = X_test[stratify_col] == value
        n    = int(mask.sum())
        if n < min_slice_size:
            continue

        try:
            slice_auc = roc_auc_score(y_test[mask], y_proba[mask])
            slice_ap  = average_precision_score(y_test[mask], y_proba[mask])
        except ValueError:
            continue  # only one class present in this slice

        rows.append({
            "slice":         str(value),
            "n":             n,
            "positive_pct":  round(float(y_test[mask].mean()) * 100, 1),
            "auc":           round(slice_auc, 3),
            "avg_precision": round(slice_ap, 3),
        })

    report = pd.DataFrame(rows).sort_values("auc", ascending=True)
    print(f"\nStratified report by '{stratify_col}' (worst AUC first):")
    print(report.to_string(index=False))
    return report


# ===========================================================================
# SECTION 5: THRESHOLD OPTIMIZATION
# ===========================================================================

def find_operational_threshold(
    y_true: np.ndarray,
    y_proba: np.ndarray,
    cost_fp: float,
    cost_fn: float,
    verbose: bool = True,
) -> float:
    """
    Find the probability threshold that minimizes total operational cost.
    Default 0.50 threshold ignores the asymmetric cost of FP vs FN.

    Args:
        y_true:   True labels
        y_proba:  Predicted probabilities (positive class)
        cost_fp:  Cost per false positive
        cost_fn:  Cost per false negative
        verbose:  Print cost comparison table

    Returns:
        Optimal threshold as float
    """
    thresholds  = np.linspace(0.05, 0.95, 91)
    total_costs = []

    for t in thresholds:
        y_pred              = (y_proba >= t).astype(int)
        tn, fp, fn, tp      = confusion_matrix(y_true, y_pred).ravel()
        total_costs.append(fp * cost_fp + fn * cost_fn)

    optimal_idx       = int(np.argmin(total_costs))
    optimal_threshold = float(thresholds[optimal_idx])

    if verbose:
        default_idx = np.searchsorted(thresholds, 0.50)
        print(f"\nThreshold optimization (cost_fp=${cost_fp:,.0f}, cost_fn=${cost_fn:,.0f}):")
        print(f"  Default 0.50  →  total cost: ${total_costs[default_idx]:,.0f}")
        print(f"  Optimal {optimal_threshold:.2f}  →  total cost: ${total_costs[optimal_idx]:,.0f}")
        savings = total_costs[default_idx] - total_costs[optimal_idx]
        print(f"  Potential savings vs. default: ${savings:,.0f}")

    return optimal_threshold


# ===========================================================================
# SECTION 6: SHAP INTERPRETABILITY
# ===========================================================================

def compute_shap_importance(
    model_pipeline: Pipeline,
    X_sample: pd.DataFrame,
    feature_names: list,
    top_n: int = 10,
) -> pd.DataFrame:
    """
    Compute mean absolute SHAP values as a feature importance ranking.
    Requires shap package (pre-installed on Databricks Runtime ML).

    Args:
        model_pipeline: Fitted Pipeline with steps "prep" and "clf"
        X_sample: Sample of data (200-500 rows is sufficient)
        feature_names: Names corresponding to transformed feature columns
        top_n: Number of top features to display

    Returns:
        DataFrame with feature names and mean |SHAP| values
    """
    try:
        import shap
    except ImportError:
        print("shap not available. Install with: pip install shap")
        return pd.DataFrame()

    preprocessor = model_pipeline.named_steps["prep"]
    classifier   = model_pipeline.named_steps["clf"]
    X_transformed = preprocessor.transform(X_sample)

    explainer   = shap.TreeExplainer(classifier)
    shap_values = explainer.shap_values(X_transformed)

    if isinstance(shap_values, list):
        shap_values = shap_values[1]

    mean_abs_shap = np.abs(shap_values).mean(axis=0)

    importance_df = (
        pd.DataFrame({"feature": feature_names, "mean_abs_shap": mean_abs_shap})
        .sort_values("mean_abs_shap", ascending=False)
        .head(top_n)
        .reset_index(drop=True)
    )

    print(f"\nTop {top_n} features by mean |SHAP| value:")
    for _, row in importance_df.iterrows():
        bar = "█" * int(row["mean_abs_shap"] * 100)
        print(f"  {row['feature']:<35} {row['mean_abs_shap']:.4f}  {bar}")

    return importance_df


# ===========================================================================
# MAIN: Run full pipeline
# ===========================================================================

def run_full_pipeline():
    print("=" * 60)
    print("Chapter 06: Late Delivery Classification Pipeline")
    print("=" * 60)

    # 1. Data
    raw_df = generate_requisition_data(n=25_000)

    # 2. Feature engineering
    feat_df, num_cols, cat_cols = engineer_features(raw_df)
    feature_cols = num_cols + cat_cols
    X = feat_df[feature_cols]
    y = feat_df["late_delivery"].values

    # 3. Train/test split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=42
    )
    print(f"\nTrain: {len(X_train):,}  |  Test: {len(X_test):,}")

    # 4. Cross-validate candidates
    print("\nCross-validating model candidates (5-fold stratified CV):")
    preprocessor = ColumnTransformer([
        ("num", StandardScaler(), num_cols),
        ("cat", OrdinalEncoder(handle_unknown="use_encoded_value", unknown_value=-1), cat_cols),
    ], remainder="drop")
    cv_results = cross_validate_models(X, y, preprocessor)

    # 5. Train final model
    print("\nTraining final Gradient Boosting model...")
    pipeline = build_and_train_pipeline(X_train, y_train, num_cols, cat_cols)

    y_pred  = pipeline.predict(X_test)
    y_proba = pipeline.predict_proba(X_test)[:, 1]

    overall_auc = roc_auc_score(y_test, y_proba)
    overall_ap  = average_precision_score(y_test, y_proba)
    print(f"\nOverall test AUC: {overall_auc:.4f}  |  Avg Precision: {overall_ap:.4f}")
    print(f"\n{classification_report(y_test, y_pred, target_names=['On Time', 'Late'])}")

    # 6. Stratified breakdown by priority code
    stratified_eval_report(pipeline, X_test, y_test, "priority_code")

    # 7. Threshold optimization
    # Cost assumptions: expediting a non-late item costs $500 (FP)
    # Missing a Priority 01 late item costs $15,000 (FN)
    optimal_threshold = find_operational_threshold(
        y_test, y_proba, cost_fp=500, cost_fn=15_000
    )

    # 8. SHAP importance
    sample_idx = np.random.default_rng(42).choice(len(X_test), size=300, replace=False)
    compute_shap_importance(
        pipeline,
        X_test.iloc[sample_idx].reset_index(drop=True),
        feature_names=num_cols + cat_cols,
        top_n=8,
    )

    print("\n" + "=" * 60)
    print("Pipeline complete.")
    print("=" * 60)
    return pipeline, optimal_threshold


if __name__ == "__main__":
    run_full_pipeline()
