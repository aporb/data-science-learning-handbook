"""
Chapter 06: Supervised Machine Learning on Federal Platforms
Code Example 02: Regression with XGBoost — Contract Cost Growth Prediction

Use case: Predict the cost growth ratio for DoD contracts
          (final obligation / original obligation - 1)
Platform: Databricks (Advana), runs locally with synthetic data

Key concepts demonstrated:
    - Log-transform regression targets to handle right skew
    - XGBoost with early stopping on a validation set
    - Temporal cross-validation (train on past, test on future)
    - Prediction intervals via quantile regression
    - Feature importance from XGBoost native API
    - MLflow experiment tracking for regression runs
"""

import numpy as np
import pandas as pd
import xgboost as xgb
from sklearn.metrics import mean_absolute_error, r2_score, mean_squared_error
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import OrdinalEncoder
import matplotlib.pyplot as plt
import warnings
warnings.filterwarnings("ignore")


# ===========================================================================
# SECTION 1: SYNTHETIC CONTRACT DATA
# ===========================================================================

def generate_contract_data(n: int = 15_000, seed: int = 42) -> pd.DataFrame:
    """
    Generate synthetic DoD contract records with cost growth outcomes.

    Real data source on Advana:
        spark.table("advana_catalog.procurement.gold.contract_modifications")
        .filter("contract_status = 'COMPLETED'")
        .filter("base_obligation > 100000")
        .toPandas()

    Cost growth ratio = (final_obligation - base_obligation) / base_obligation
    A value of 0.0 means on-budget. 0.5 means 50% over budget. -0.1 means under.
    """
    rng = np.random.default_rng(seed)

    n_contracts = n

    # Contract types — FFP contracts tend to have lower cost growth than CPFF
    contract_types = {
        "FFP":   {"mean_growth": 0.05,  "std": 0.15},   # Firm Fixed Price
        "CPFF":  {"mean_growth": 0.25,  "std": 0.40},   # Cost Plus Fixed Fee
        "T&M":   {"mean_growth": 0.35,  "std": 0.50},   # Time & Materials
        "CPAF":  {"mean_growth": 0.20,  "std": 0.35},   # Cost Plus Award Fee
        "FPIF":  {"mean_growth": 0.10,  "std": 0.20},   # Fixed Price Incentive
    }
    contract_type_names    = list(contract_types.keys())
    contract_type_weights  = [0.45, 0.20, 0.15, 0.10, 0.10]
    type_col               = rng.choice(contract_type_names, size=n_contracts,
                                        p=contract_type_weights)

    # Competition — sole source contracts show higher cost growth on average
    competition_types = ["Full & Open", "8(a)", "Sole Source", "SDVOSB", "HUBZone"]
    competition_col   = rng.choice(competition_types, size=n_contracts,
                                   p=[0.45, 0.15, 0.20, 0.12, 0.08])

    # Base obligation (log-normal distributed)
    base_obligation = rng.lognormal(mean=14.0, sigma=2.0, size=n_contracts).clip(100_000, 1e9)

    # Period of performance in days
    pop_days = rng.integers(90, 1825, size=n_contracts)  # 3 months to 5 years

    # Number of prior modifications
    prior_mods = rng.poisson(lam=2.5, size=n_contracts)

    # Vendor prior award count (experience proxy)
    vendor_prior_awards = rng.integers(0, 500, size=n_contracts)

    # NAICS sector (simplified)
    naics_sectors = ["54", "33", "81", "56", "61", "72"]  # professional, mfg, repair, etc.
    naics_col     = rng.choice(naics_sectors, size=n_contracts)

    # Fiscal year (2018-2024)
    fiscal_year = rng.integers(2018, 2025, size=n_contracts)

    # Defense acquisition flag
    is_defense = rng.random(size=n_contracts) < 0.65

    # Generate cost growth ratios
    # Sole source + long PoP + CPFF + many prior mods = higher growth
    type_mean = np.array([
        contract_types[t]["mean_growth"] for t in type_col
    ])
    type_std = np.array([
        contract_types[t]["std"] for t in type_col
    ])

    sole_source_adj = (np.array(competition_col) == "Sole Source").astype(float) * 0.15
    pop_adj         = np.log1p(pop_days) * 0.03
    mods_adj        = np.log1p(prior_mods) * 0.08
    size_adj        = np.log1p(base_obligation) * -0.01  # larger contracts scrutinized more

    mean_growth = type_mean + sole_source_adj + pop_adj + mods_adj + size_adj
    noise       = rng.normal(0, type_std, size=n_contracts)
    raw_growth  = mean_growth + noise

    # Clip: allow some contracts to come in under budget but cap extreme outliers
    cost_growth_ratio = raw_growth.clip(-0.5, 10.0)

    df = pd.DataFrame({
        "contract_id":            [f"N{i:06d}" for i in range(n_contracts)],
        "contract_type":          type_col,
        "competition_type":       competition_col,
        "base_obligation":        base_obligation.round(2),
        "period_of_performance_days": pop_days,
        "prior_modifications":    prior_mods,
        "vendor_prior_awards":    vendor_prior_awards,
        "naics_sector":           naics_col,
        "fiscal_year":            fiscal_year,
        "is_defense_acquisition": is_defense.astype(int),
        "cost_growth_ratio":      cost_growth_ratio.round(4),
    })

    print(f"Generated {n_contracts:,} contracts")
    print(f"  Mean cost growth : {df['cost_growth_ratio'].mean():.3f}x")
    print(f"  Median cost growth: {df['cost_growth_ratio'].median():.3f}x")
    print(f"  Contracts over budget: {(df['cost_growth_ratio'] > 0).mean()*100:.1f}%")
    print(f"  Contracts > 50% over : {(df['cost_growth_ratio'] > 0.5).mean()*100:.1f}%")

    return df


# ===========================================================================
# SECTION 2: FEATURE PREPARATION
# ===========================================================================

def prepare_regression_features(
    df: pd.DataFrame,
    clip_percentile: float = 0.99,
) -> tuple:
    """
    Prepare features and target for XGBoost regression.

    Steps:
        1. Clip extreme cost growth outliers at the specified percentile
        2. Log1p-transform the target (handles right skew)
        3. Engineer numeric and categorical features
        4. Encode categoricals

    Returns:
        (X_array, y_array, feature_names, encoder, p99_clip_value)
    """
    feat = df.copy()

    # Clip outliers — document the percentile used
    p_clip    = float(feat["cost_growth_ratio"].quantile(clip_percentile))
    n_clipped = int((feat["cost_growth_ratio"] > p_clip).sum())
    feat      = feat[feat["cost_growth_ratio"] <= p_clip].copy()
    print(f"Outlier clip at {clip_percentile:.0%} percentile ({p_clip:.2f}x). "
          f"Removed {n_clipped} contracts.")

    # Log1p target transform — invertible with expm1
    feat["log_cost_growth"] = np.log1p(feat["cost_growth_ratio"].clip(lower=-0.99))

    # Numeric features
    feat["log_base_obligation"] = np.log1p(feat["base_obligation"])
    feat["log_pop_days"]        = np.log1p(feat["period_of_performance_days"])
    feat["log_vendor_awards"]   = np.log1p(feat["vendor_prior_awards"])

    numeric_features = [
        "log_base_obligation",
        "log_pop_days",
        "prior_modifications",
        "log_vendor_awards",
        "is_defense_acquisition",
        "fiscal_year",
    ]

    # Encode categoricals
    categorical_features = ["contract_type", "competition_type", "naics_sector"]
    encoder              = OrdinalEncoder(handle_unknown="use_encoded_value", unknown_value=-1)
    cat_encoded          = encoder.fit_transform(feat[categorical_features])

    num_array  = feat[numeric_features].values
    cat_array  = cat_encoded
    X          = np.hstack([num_array, cat_array])
    y          = feat["log_cost_growth"].values

    all_feature_names = numeric_features + categorical_features

    return X, y, all_feature_names, encoder, p_clip


# ===========================================================================
# SECTION 3: TEMPORAL CROSS-VALIDATION
# ===========================================================================

def temporal_train_test_split(
    df: pd.DataFrame,
    train_years: list,
    test_years: list,
) -> tuple:
    """
    Split data by fiscal year — train on past, test on future.

    Why this matters: Random splits allow future information to leak into
    training data for time-dependent features like vendor reputation scores
    or market rate changes. Temporal splits prevent this.

    Args:
        df: Full dataset with fiscal_year column
        train_years: List of fiscal years to train on
        test_years: List of fiscal years to test on

    Returns:
        (train_df, test_df)
    """
    train = df[df["fiscal_year"].isin(train_years)].copy()
    test  = df[df["fiscal_year"].isin(test_years)].copy()

    print(f"Temporal split:")
    print(f"  Train: FY{min(train_years)}-FY{max(train_years)} "
          f"({len(train):,} contracts)")
    print(f"  Test:  FY{min(test_years)}-FY{max(test_years)} "
          f"({len(test):,} contracts)")

    return train, test


# ===========================================================================
# SECTION 4: XGBOOST MODEL WITH EARLY STOPPING
# ===========================================================================

def train_xgboost_regressor(
    X_train: np.ndarray,
    y_train: np.ndarray,
    X_val: np.ndarray,
    y_val: np.ndarray,
    feature_names: list,
) -> xgb.XGBRegressor:
    """
    Train XGBoost regressor with early stopping.

    Early stopping prevents overfitting without manual n_estimators tuning:
    training stops when validation MAE hasn't improved for 30 rounds.

    Returns fitted model.
    """
    model = xgb.XGBRegressor(
        n_estimators=1000,          # high ceiling — early stopping decides the real count
        max_depth=5,
        learning_rate=0.03,
        subsample=0.8,
        colsample_bytree=0.8,
        min_child_weight=15,        # regularization: prevents fitting individual contracts
        reg_alpha=0.05,             # L1 regularization
        reg_lambda=1.0,             # L2 regularization
        random_state=42,
        n_jobs=-1,
        early_stopping_rounds=30,
        eval_metric="mae",
    )

    model.fit(
        X_train, y_train,
        eval_set=[(X_val, y_val)],
        verbose=100,                # print every 100 rounds
    )

    print(f"\nBest iteration: {model.best_iteration}")
    print(f"Best validation MAE (log scale): {model.best_score:.4f}")

    return model


def evaluate_regression_model(
    model: xgb.XGBRegressor,
    X_test: np.ndarray,
    y_test_log: np.ndarray,
    label: str = "Test",
) -> dict:
    """
    Evaluate on the original (non-log) scale.
    Log scale metrics are technically correct but hard to interpret operationally.
    "Our MAE is 0.12" means nothing to a program manager.
    "We're off by an average of 12% of the original contract value" does.
    """
    y_pred_log  = model.predict(X_test)
    y_pred_orig = np.expm1(y_pred_log)
    y_true_orig = np.expm1(y_test_log)

    mae   = mean_absolute_error(y_true_orig, y_pred_orig)
    rmse  = np.sqrt(mean_squared_error(y_true_orig, y_pred_orig))
    r2    = r2_score(y_true_orig, y_pred_orig)
    mape  = np.abs((y_true_orig - y_pred_orig) / (np.abs(y_true_orig) + 1e-6)).mean() * 100

    print(f"\n{label} performance (original cost growth ratio scale):")
    print(f"  MAE  : {mae:.4f}x  (off by this fraction of original obligation on average)")
    print(f"  RMSE : {rmse:.4f}x")
    print(f"  R²   : {r2:.4f}   (higher = better; 1.0 = perfect)")
    print(f"  MAPE : {mape:.1f}%")

    return {"mae": mae, "rmse": rmse, "r2": r2, "mape": mape}


# ===========================================================================
# SECTION 5: FEATURE IMPORTANCE
# ===========================================================================

def plot_xgboost_importance(
    model: xgb.XGBRegressor,
    feature_names: list,
    top_n: int = 10,
) -> pd.DataFrame:
    """
    Display XGBoost's native feature importance scores.

    XGBoost provides three importance types:
        "weight"  — number of times feature used in splits (fast, but biased to
                    features with many possible split points)
        "gain"    — average information gain from splits using the feature
                    (more reliable than weight)
        "cover"   — average number of samples affected by splits on this feature

    Use "gain" for interpretability reporting.
    """
    importance_dict = model.get_booster().get_score(importance_type="gain")

    # Map XGBoost's internal feature names (f0, f1, ...) to real names
    rows = []
    for fname, imp in importance_dict.items():
        idx = int(fname[1:])  # strip 'f' prefix
        if idx < len(feature_names):
            rows.append({"feature": feature_names[idx], "gain": imp})

    importance_df = (
        pd.DataFrame(rows)
        .sort_values("gain", ascending=False)
        .head(top_n)
        .reset_index(drop=True)
    )
    importance_df["gain_normalized"] = (
        importance_df["gain"] / importance_df["gain"].sum() * 100
    ).round(1)

    print(f"\nTop {top_n} features by XGBoost gain importance:")
    for _, row in importance_df.iterrows():
        bar = "█" * int(row["gain_normalized"] / 2)
        print(f"  {row['feature']:<35} {row['gain_normalized']:>5.1f}%  {bar}")

    return importance_df


# ===========================================================================
# SECTION 6: PREDICTION INTERVALS (QUANTILE REGRESSION)
# ===========================================================================

def train_quantile_models(
    X_train: np.ndarray,
    y_train: np.ndarray,
    X_val: np.ndarray,
    y_val: np.ndarray,
    quantiles: list = [0.10, 0.50, 0.90],
) -> dict:
    """
    Train separate XGBoost models for different quantiles of the target distribution.

    This gives you prediction intervals instead of point estimates.
    "Our model predicts 15% cost growth, with 80% confidence interval of 5% to 35%"
    is far more useful to a program manager than just "15%."

    Args:
        quantiles: List of quantiles to estimate (e.g., [0.10, 0.50, 0.90])

    Returns:
        Dict mapping quantile to fitted model
    """
    models = {}

    for q in quantiles:
        print(f"Training q={q:.0%} quantile model...", end=" ")
        qmodel = xgb.XGBRegressor(
            n_estimators=500,
            max_depth=4,
            learning_rate=0.05,
            subsample=0.8,
            objective="reg:quantileerror",
            quantile_alpha=q,       # XGBoost quantile regression parameter
            random_state=42,
            n_jobs=-1,
            early_stopping_rounds=20,
        )
        qmodel.fit(
            X_train, y_train,
            eval_set=[(X_val, y_val)],
            verbose=False,
        )
        models[q] = qmodel
        print(f"done (best iter: {qmodel.best_iteration})")

    return models


def predict_with_intervals(
    quantile_models: dict,
    X_new: np.ndarray,
    lower_q: float = 0.10,
    upper_q: float = 0.90,
) -> pd.DataFrame:
    """
    Generate point estimates and prediction intervals for new contracts.

    Returns DataFrame with: point_estimate, lower_bound, upper_bound (all on original scale).
    """
    median_preds = np.expm1(quantile_models[0.50].predict(X_new))
    lower_preds  = np.expm1(quantile_models[lower_q].predict(X_new))
    upper_preds  = np.expm1(quantile_models[upper_q].predict(X_new))

    return pd.DataFrame({
        "point_estimate": median_preds.round(3),
        f"lower_{int(lower_q*100)}pct": lower_preds.round(3),
        f"upper_{int(upper_q*100)}pct": upper_preds.round(3),
        "interval_width": (upper_preds - lower_preds).round(3),
    })


# ===========================================================================
# MAIN
# ===========================================================================

def run_regression_pipeline():
    print("=" * 60)
    print("Chapter 06: Contract Cost Growth Regression")
    print("=" * 60)

    # 1. Generate data
    df = generate_contract_data(n=15_000)

    # 2. Temporal split — train FY2018-2022, test FY2023-2024
    train_df, test_df = temporal_train_test_split(
        df,
        train_years=list(range(2018, 2023)),
        test_years=[2023, 2024],
    )

    # 3. Prepare features
    X_train, y_train, feature_names, encoder, p_clip = prepare_regression_features(train_df)

    # For test set: apply same encoder (fitted on train only)
    test_feat = test_df.copy()
    test_feat["log_cost_growth"] = np.log1p(
        test_feat["cost_growth_ratio"].clip(-0.99, p_clip)
    )
    test_feat["log_base_obligation"] = np.log1p(test_feat["base_obligation"])
    test_feat["log_pop_days"]        = np.log1p(test_feat["period_of_performance_days"])
    test_feat["log_vendor_awards"]   = np.log1p(test_feat["vendor_prior_awards"])

    numeric_features     = [
        "log_base_obligation", "log_pop_days", "prior_modifications",
        "log_vendor_awards", "is_defense_acquisition", "fiscal_year"
    ]
    categorical_features = ["contract_type", "competition_type", "naics_sector"]
    cat_test             = encoder.transform(test_feat[categorical_features])
    num_test             = test_feat[numeric_features].values
    X_test               = np.hstack([num_test, cat_test])
    y_test               = test_feat["log_cost_growth"].values

    # 4. Internal validation split from train set
    X_tr, X_val, y_tr, y_val = train_test_split(
        X_train, y_train, test_size=0.15, random_state=42
    )

    # 5. Train point estimate model
    print("\nTraining XGBoost point estimate model (with early stopping):")
    model = train_xgboost_regressor(X_tr, y_tr, X_val, y_val, feature_names)

    # 6. Evaluate
    evaluate_regression_model(model, X_test, y_test, label="Temporal Hold-Out Test")

    # 7. Feature importance
    plot_xgboost_importance(model, feature_names)

    # 8. Quantile models for prediction intervals
    print("\nTraining quantile models for prediction intervals...")
    quantile_models = train_quantile_models(X_tr, y_tr, X_val, y_val)

    # Show example predictions with intervals on 5 test contracts
    sample_X    = X_test[:5]
    sample_true = np.expm1(y_test[:5])
    intervals   = predict_with_intervals(quantile_models, sample_X)
    intervals["true_growth"] = sample_true.round(3)
    print(f"\nExample predictions with 80% prediction intervals:")
    print(intervals.to_string(index=False))

    print("\n" + "=" * 60)
    print("Regression pipeline complete.")
    print("=" * 60)
    return model


if __name__ == "__main__":
    run_regression_pipeline()
