"""
Chapter 12: Ethics, Governance, and Compliance for Federal AI
Code Example 01: Bias Audit and Fairness Testing

Use case: Audit a personnel attrition prediction model for demographic bias
          before deployment on a DoD platform.

Platform: Runs locally or on Databricks (Advana / Jupiter).
          On Databricks, replace generate_synthetic_personnel_data()
          with spark.table("jupiter_catalog.silver.personnel_records").toPandas()

Key concepts:
    - Demographic parity ratio (4/5ths rule from EEOC guidelines)
    - Equalized odds (TPR and FPR parity across groups)
    - Proxy correlation scan (detecting race-adjacent features)
    - Threshold calibration per group (post-processing fairness)
    - Reporting format suitable for RAI assessment documentation

References:
    - DoD AI Ethical Principle: Equitable
    - NIST AI RMF: MEASURE function
    - EEOC Uniform Guidelines on Employee Selection Procedures (4/5ths rule)
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler, OrdinalEncoder
from sklearn.compose import ColumnTransformer
from sklearn.metrics import roc_auc_score, confusion_matrix


# ===========================================================================
# SECTION 1: SYNTHETIC DATA GENERATION
# ===========================================================================

def generate_synthetic_personnel_data(n: int = 15_000, seed: int = 42,
                                       inject_bias: bool = True) -> pd.DataFrame:
    """
    Generate synthetic enlisted personnel records for attrition prediction testing.

    The inject_bias parameter controls whether the synthetic data contains
    a demographic-correlated pattern in the outcome (simulating a real bias
    problem). This is used to demonstrate that the bias audit catches it.

    Real data would come from:
        spark.table("jupiter_catalog.silver.personnel_retention_cohort")
        .filter(F.col("service_branch") == "NAVY")
        .filter(F.col("cohort_year").between(2019, 2023))
        .toPandas()

    Args:
        n: Number of records
        seed: Random seed
        inject_bias: If True, inject a demographic-correlated bias pattern

    Returns:
        DataFrame with personnel features and attrition label
    """
    rng = np.random.default_rng(seed)

    # Demographics (approximate proportions from DoD demographics reports)
    race_eth_groups = ["White", "Black", "Hispanic", "Asian", "Other"]
    race_eth_props  = [0.54, 0.19, 0.16, 0.05, 0.06]
    gender_groups   = ["Male", "Female"]
    gender_props    = [0.82, 0.18]

    race_eth = rng.choice(race_eth_groups, size=n, p=race_eth_props)
    gender   = rng.choice(gender_groups, size=n, p=gender_props)

    # Service characteristics
    paygrade = rng.choice(
        ["E1", "E2", "E3", "E4", "E5", "E6", "E7"],
        size=n, p=[0.05, 0.10, 0.15, 0.25, 0.25, 0.15, 0.05]
    )
    paygrade_num = {"E1": 1, "E2": 2, "E3": 3, "E4": 4, "E5": 5, "E6": 6, "E7": 7}
    grade_num = np.array([paygrade_num[g] for g in paygrade])

    years_of_service = rng.uniform(0.5, 12, size=n)
    performance_mark = rng.beta(6, 2, size=n) * 4 + 1   # 1.0–5.0 scale
    prt_score        = rng.beta(4, 2, size=n) * 100       # physical readiness 0-100
    deployment_count = rng.poisson(1.5, size=n)
    reenlistment_bonus = (rng.random(size=n) < 0.35).astype(float)

    # Rating (Navy job specialty) — encoded as a number here for simplicity
    rating_code = rng.integers(1, 30, size=n)

    # Base attrition probability — legitimate factors
    logit = (
        - 1.8                                      # base rate ~14%
        + (years_of_service < 2).astype(float) * 1.5   # early separators
        + (grade_num < 4).astype(float) * 0.8     # junior enlisted
        - performance_mark * 0.4                   # better performers stay
        - reenlistment_bonus * 1.2                 # bonus works
        + (deployment_count > 3).astype(float) * 0.5  # high deployment tempo
        + rng.normal(0, 0.6, size=n)
    )

    if inject_bias:
        # Inject a correlation between race/ethnicity and attrition
        # that is NOT explained by the legitimate features above.
        # This represents systemic factors (command climate, opportunity gaps)
        # that the model will learn if not caught.
        race_bias = np.where(race_eth == "Black",    0.45,
                   np.where(race_eth == "Hispanic",  0.30, 0.0))
        logit += race_bias

    prob_attrition = 1 / (1 + np.exp(-logit))
    attrition      = (rng.random(size=n) < prob_attrition).astype(int)

    df = pd.DataFrame({
        "service_member_id": [f"SM{i:07d}" for i in range(n)],
        "race_ethnicity":    race_eth,
        "gender":            gender,
        "paygrade":          paygrade,
        "years_of_service":  years_of_service.round(2),
        "performance_mark":  performance_mark.round(2),
        "prt_score":         prt_score.round(1),
        "deployment_count":  deployment_count,
        "reenlistment_bonus_offered": reenlistment_bonus.astype(int),
        "rating_code":       rating_code,
        "attrition":         attrition,
    })

    print(f"Generated {n:,} personnel records")
    print(f"  Overall attrition rate: {attrition.mean()*100:.1f}%")
    print(f"  Attrition by race/ethnicity:")
    for group in race_eth_groups:
        mask = df["race_ethnicity"] == group
        rate = df.loc[mask, "attrition"].mean() * 100
        print(f"    {group:<12} {rate:.1f}%")

    return df


# ===========================================================================
# SECTION 2: TRAIN A MODEL (WITH THE BIAS BAKED IN)
# ===========================================================================

def train_attrition_model(df: pd.DataFrame) -> tuple:
    """
    Train a GBT classifier on personnel data.
    Deliberately excludes race_ethnicity and gender from features —
    but the bias can still appear through proxy correlations.
    """
    # Features — race and gender are NOT included as direct features
    numeric_features = [
        "years_of_service", "performance_mark", "prt_score",
        "deployment_count", "reenlistment_bonus_offered",
    ]
    categorical_features = ["paygrade", "rating_code"]

    # Convert rating_code to string for OrdinalEncoder
    df = df.copy()
    df["rating_code"] = df["rating_code"].astype(str)

    X = df[numeric_features + categorical_features]
    y = df["attrition"].values

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, stratify=y, random_state=42
    )

    preprocessor = ColumnTransformer([
        ("num", StandardScaler(), numeric_features),
        ("cat", OrdinalEncoder(handle_unknown="use_encoded_value", unknown_value=-1),
         categorical_features),
    ])

    pipeline = Pipeline([
        ("prep", preprocessor),
        ("clf", GradientBoostingClassifier(
            n_estimators=200, max_depth=4, learning_rate=0.05,
            subsample=0.8, random_state=42
        ))
    ])
    pipeline.fit(X_train, y_train)

    y_proba = pipeline.predict_proba(X_test)[:, 1]
    overall_auc = roc_auc_score(y_test, y_proba)
    print(f"\nModel trained. Overall AUC: {overall_auc:.4f}")

    return pipeline, X_test, y_test, y_proba, df.loc[X_test.index, "race_ethnicity"]


# ===========================================================================
# SECTION 3: BIAS AUDIT
# ===========================================================================

def bias_audit_report(
    y_true: np.ndarray,
    y_pred_proba: np.ndarray,
    sensitive_attr: pd.Series,
    threshold: float = 0.50,
    reference_group: str = None,
) -> pd.DataFrame:
    """Compare group metrics for a synthetic adverse-outcome demonstration.

    A positive prediction means an adverse flag in this example. favorable_rate
    is 1 - positive_rate. dp_ratio compares favorable rates, not adverse rates.
    The 0.80 screen is illustrative, not a legal conclusion or universal rule.
    Confirm the actual decision and outcome direction with domain/legal experts.
    Undefined denominators remain NaN. Small slices are reported as excluded.
    """
    y_true = np.asarray(y_true)
    scores = np.asarray(y_pred_proba, dtype=float)
    groups = pd.Series(sensitive_attr).reset_index(drop=True)
    if y_true.ndim != 1 or scores.ndim != 1 or len(y_true) != len(scores) or len(groups) != len(scores):
        raise ValueError("Inputs must be one-dimensional and equally sized")
    if not 0 <= threshold <= 1 or not np.isin(y_true, [0, 1]).all():
        raise ValueError("Use binary labels and a threshold between zero and one")
    if not np.isfinite(scores).all() or ((scores < 0) | (scores > 1)).any() or groups.isna().any():
        raise ValueError("Use finite probabilities and nonmissing group labels")
    predicted = (scores >= threshold).astype(int)
    columns = ["group", "n", "positive_rate", "favorable_rate", "tpr", "fpr", "auc"]
    rows = []
    excluded = []
    for group in groups.unique():
        mask = (groups == group).to_numpy()
        n = int(mask.sum())
        if n < 30:
            excluded.append(str(group))
            continue
        tn, fp, fn, tp = confusion_matrix(y_true[mask], predicted[mask], labels=[0, 1]).ravel()
        positive_rate = float((tp + fp) / n)
        rows.append({
            "group": group, "n": n, "positive_rate": positive_rate,
            "favorable_rate": 1 - positive_rate,
            "tpr": float(tp / (tp + fn)) if tp + fn else np.nan,
            "fpr": float(fp / (fp + tn)) if fp + tn else np.nan,
            "auc": float(roc_auc_score(y_true[mask], scores[mask]))
                   if len(np.unique(y_true[mask])) == 2 else np.nan,
        })
    result = pd.DataFrame(rows, columns=columns)
    result.attrs["excluded_groups"] = excluded
    if result.empty:
        return result.assign(dp_ratio=pd.Series(dtype=float), fpr_ratio=pd.Series(dtype=float))
    if reference_group is None:
        reference_group = result.loc[result["favorable_rate"].idxmax(), "group"]
    reference = result.loc[result["group"] == reference_group]
    if reference.empty:
        raise ValueError("Reference group is missing or below the sample-size threshold")
    ref = reference.iloc[0]
    result["dp_ratio"] = result["favorable_rate"] / ref["favorable_rate"] if ref["favorable_rate"] else np.nan
    result["fpr_ratio"] = result["fpr"] / ref["fpr"] if ref["fpr"] > 0 else np.nan
    return result.sort_values("positive_rate", ascending=False).reset_index(drop=True)


def equalized_odds_check(
    bias_df: pd.DataFrame,
    tpr_tolerance: float = 0.05,
    fpr_tolerance: float = 0.05,
) -> bool:
    """
    Check approximate equalized odds.
    Returns True if both TPR and FPR range across groups is within tolerance.
    """
    if len(bias_df) < 2 or bias_df[["tpr", "fpr"]].isna().any().any():
        return False  # Insufficient evidence is not a passing fairness check.
    valid = bias_df
    tpr_range   = float(valid["tpr"].max() - valid["tpr"].min())
    fpr_range   = float(valid["fpr"].max() - valid["fpr"].min())
    tpr_ok      = tpr_range <= tpr_tolerance
    fpr_ok      = fpr_range <= fpr_tolerance

    print(f"\nEqualized Odds Check:")
    print(f"  TPR range: {tpr_range:.4f}  (tolerance ≤{tpr_tolerance})  "
          f"{'PASS' if tpr_ok else 'FAIL ← investigate'}")
    print(f"  FPR range: {fpr_range:.4f}  (tolerance ≤{fpr_tolerance})  "
          f"{'PASS' if fpr_ok else 'FAIL ← investigate'}")

    return tpr_ok and fpr_ok


# ===========================================================================
# SECTION 4: PROXY CORRELATION SCAN
# ===========================================================================

def proxy_correlation_scan(
    df: pd.DataFrame,
    feature_cols: list,
    protected_cols: list,
    threshold: float = 0.10,
) -> pd.DataFrame:
    """
    Scan for features correlated with protected attributes.
    Flags features above the threshold for documentation.

    Uses Pearson correlation for numeric-numeric pairs.
    Uses point-biserial for numeric-binary pairs.
    Uses Cramér's V for categorical-categorical pairs.

    Correlation above threshold does NOT mean the feature must be excluded.
    It means it must be documented and monitored.
    """
    from scipy.stats import pointbiserialr
    from scipy.stats import chi2_contingency

    def cramers_v(x: pd.Series, y: pd.Series) -> float:
        ct   = pd.crosstab(x, y)
        chi2 = chi2_contingency(ct, correction=False)[0]
        n    = ct.sum().sum()
        k    = min(ct.shape) - 1
        return float(np.sqrt(chi2 / (n * k))) if (n * k) > 0 else 0.0

    results = []

    for feat in feature_cols:
        for prot in protected_cols:
            if df[feat].nunique() < 2 or df[prot].nunique() < 2:
                continue

            feat_numeric = pd.api.types.is_numeric_dtype(df[feat])
            prot_binary  = df[prot].nunique() == 2

            if feat_numeric and prot_binary:
                prot_encoded = (df[prot] == df[prot].unique()[0]).astype(float)
                corr, _      = pointbiserialr(prot_encoded, df[feat].astype(float))
                abs_corr     = abs(corr)
                method       = "point-biserial"
            elif feat_numeric and not prot_binary:
                # Eta correlation approximation
                groups   = df[prot].unique()
                group_means = [df.loc[df[prot] == g, feat].mean() for g in groups]
                overall_mean = df[feat].mean()
                ss_between  = sum(
                    (df[prot] == g).sum() * (m - overall_mean) ** 2
                    for g, m in zip(groups, group_means)
                )
                ss_total  = ((df[feat] - overall_mean) ** 2).sum()
                abs_corr  = float(np.sqrt(ss_between / ss_total)) if ss_total > 0 else 0.0
                method    = "eta"
            else:
                abs_corr = cramers_v(df[feat].astype(str), df[prot].astype(str))
                method   = "cramers_v"

            if abs_corr >= threshold:
                results.append({
                    "feature":    feat,
                    "protected":  prot,
                    "corr":       round(abs_corr, 4),
                    "method":     method,
                    "action":     "Document in model card — review for proxy risk",
                })

    report = pd.DataFrame(results).sort_values("corr", ascending=False)

    if len(report) > 0:
        print(f"\nProxy Correlation Scan (threshold={threshold}):")
        print(f"  {len(report)} feature-attribute pair(s) above threshold:")
        print(report.to_string(index=False))
    else:
        print(f"\nProxy scan: No correlations above threshold ({threshold}).")

    return report


# ===========================================================================
# SECTION 5: PER-GROUP THRESHOLD CALIBRATION (POST-PROCESSING)
# ===========================================================================

def calibrate_thresholds_by_group(
    y_true: np.ndarray,
    y_pred_proba: np.ndarray,
    sensitive_attr: pd.Series,
    target_fpr: float = 0.10,
) -> dict:
    """
    Find per-group thresholds that equalize FPR across groups.

    This is a post-processing fairness intervention: rather than retraining
    the model, we apply different decision thresholds to different groups
    so that each group experiences the same false positive rate.

    Use with caution — this approach is legally and ethically contested
    in some personnel decision contexts. Document the rationale in the
    model card if applied.

    Args:
        y_true: True labels
        y_pred_proba: Predicted probabilities
        sensitive_attr: Group labels
        target_fpr: Target false positive rate to achieve for all groups

    Returns:
        Dict mapping group label to calibrated threshold
    """
    from sklearn.metrics import roc_curve

    thresholds = {}

    print(f"\nPer-group threshold calibration (target FPR = {target_fpr}):")
    for group in sorted(sensitive_attr.unique()):
        mask = (sensitive_attr == group).values
        if mask.sum() < 30:
            continue

        fpr_curve, tpr_curve, thresh_curve = roc_curve(
            y_true[mask], y_pred_proba[mask]
        )
        # Find the threshold where FPR is closest to target
        idx       = int(np.argmin(np.abs(fpr_curve - target_fpr)))
        best_thr  = float(thresh_curve[idx])
        actual_fpr = float(fpr_curve[idx])

        thresholds[group] = best_thr
        print(f"  {group:<12} threshold={best_thr:.3f}  achieved FPR={actual_fpr:.3f}")

    return thresholds


# ===========================================================================
# MAIN
# ===========================================================================

def run_full_bias_audit():
    print("=" * 70)
    print("Chapter 12: Bias Audit — Personnel Attrition Prediction")
    print("=" * 70)

    # 1. Generate biased data
    df = generate_synthetic_personnel_data(n=15_000, inject_bias=True)

    # 2. Train model (race/gender excluded as direct features)
    pipeline, X_test, y_test, y_proba, race_test = train_attrition_model(df)

    # 3. Proxy scan — check whether legitimate features correlate with race
    feature_cols_for_scan = [
        "years_of_service", "performance_mark", "prt_score",
        "deployment_count", "reenlistment_bonus_offered"
    ]
    proxy_report = proxy_correlation_scan(
        df=df,
        feature_cols=feature_cols_for_scan,
        protected_cols=["race_ethnicity", "gender"],
        threshold=0.10,
    )

    # 4. Bias audit — compute demographic parity and equalized odds
    bias_df = bias_audit_report(y_test, y_proba, race_test, threshold=0.50)

    # 5. Equalized odds check
    equalized_odds_check(bias_df)

    # 6. Per-group threshold calibration
    thresholds = calibrate_thresholds_by_group(y_test, y_proba, race_test, target_fpr=0.10)

    # 7. Re-run bias audit with calibrated thresholds
    print("\nBias audit AFTER per-group threshold calibration:")
    y_pred_calibrated = np.zeros_like(y_test)
    for group, thr in thresholds.items():
        mask = (race_test == group).values
        y_pred_calibrated[mask] = (y_proba[mask] >= thr).astype(int)

    # Report FPR parity after calibration
    print("\nFPR after calibration:")
    for group, thr in thresholds.items():
        mask = (race_test == group).values
        tn, fp, fn, tp = confusion_matrix(
            y_test[mask], y_pred_calibrated[mask], labels=[0, 1]
        ).ravel()
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        print(f"  {group:<12} FPR={fpr:.3f}")

    print("\n" + "=" * 70)
    print("Bias audit complete.")
    print("Document all findings in model card before requesting deployment authorization.")
    print("=" * 70)


if __name__ == "__main__":
    run_full_bias_audit()
