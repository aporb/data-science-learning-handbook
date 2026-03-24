"""
Chapter 07: Unsupervised ML - Anomaly Detection
=================================================
Isolation Forest, One-Class SVM, and autoencoder-based anomaly detection
on federal financial and logistics data. Includes the fiscal-calendar
adaptation that prevents flagging normal quarter-end activity.

Requirements:
    pip install scikit-learn pandas numpy
    pip install torch  # For autoencoder (optional)
"""

import warnings
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.svm import OneClassSVM
from sklearn.preprocessing import RobustScaler
from typing import Optional

warnings.filterwarnings("ignore")


# ---------------------------------------------------------------------------
# 1. Fiscal-calendar-aware Isolation Forest
# ---------------------------------------------------------------------------

# DoD fiscal year starts October 1.
# Q1: Oct, Nov, Dec  |  Q2: Jan, Feb, Mar  |  Q3: Apr, May, Jun  |  Q4: Jul, Aug, Sep
MONTH_TO_FISCAL_QUARTER = {
    10: "Q1", 11: "Q1", 12: "Q1",
    1: "Q2",  2: "Q2",  3: "Q2",
    4: "Q3",  5: "Q3",  6: "Q3",
    7: "Q4",  8: "Q4",  9: "Q4",
}


def fiscal_year_from_date(d: pd.Timestamp) -> int:
    """Return the DoD fiscal year for a given date."""
    return d.year + 1 if d.month >= 10 else d.year


def build_fiscal_aware_anomaly_detector(
    df: pd.DataFrame,
    feature_cols: list[str],
    date_col: str,
    contamination: float = 0.01,
    n_estimators: int = 100,
    random_state: int = 42,
) -> pd.DataFrame:
    """
    Isolation forest trained within fiscal quarters.

    The core insight: DoD fiscal year runs October-September.
    Q4 (July-September) has structurally higher obligation volumes.
    Training a single model across all quarters will flag Q4 surges
    as anomalies. Train-within-quarter removes that seasonal noise.

    Args:
        df: Transaction DataFrame
        feature_cols: Numeric features for anomaly scoring
        date_col: Column with transaction dates
        contamination: Expected fraction of true anomalies
        n_estimators: Number of trees in the isolation forest
        random_state: For reproducibility

    Returns:
        DataFrame with added columns:
            anomaly_score: Raw score (lower = more anomalous)
            anomaly_score_normalized: 0-1 scale (higher = more anomalous)
            is_anomaly: Boolean flag
            fiscal_quarter: Q1/Q2/Q3/Q4
    """
    df = df.copy()
    df[date_col] = pd.to_datetime(df[date_col], errors="coerce")

    date_missing = df[date_col].isna()
    if date_missing.sum() > 0:
        print(f"  Dropping {date_missing.sum()} rows with unparseable dates")
    df = df[~date_missing].copy()

    df["fiscal_quarter"] = df[date_col].dt.month.map(MONTH_TO_FISCAL_QUARTER)
    df["fiscal_year"] = df[date_col].apply(fiscal_year_from_date)

    # Impute missing feature values with column medians before scaling
    for col in feature_cols:
        df[col] = pd.to_numeric(df[col], errors="coerce")
        df[col] = df[col].fillna(df[col].median())

    scaler = RobustScaler()
    X_all = scaler.fit_transform(df[feature_cols])

    df["anomaly_score"] = np.nan
    df["is_anomaly"] = False

    for quarter in ["Q1", "Q2", "Q3", "Q4"]:
        mask = df["fiscal_quarter"] == quarter
        n_in_quarter = mask.sum()

        if n_in_quarter < 20:
            print(f"  Skipping {quarter}: only {n_in_quarter} records (need >= 20)")
            continue

        X_q = X_all[mask.values]

        model = IsolationForest(
            contamination=contamination,
            n_estimators=n_estimators,
            random_state=random_state,
            n_jobs=-1,
        )
        model.fit(X_q)

        scores = model.score_samples(X_q)
        preds = model.predict(X_q)

        df.loc[mask, "anomaly_score"] = scores
        df.loc[mask, "is_anomaly"] = preds == -1

        n_flagged = (preds == -1).sum()
        print(f"  {quarter}: {n_in_quarter:,} records, {n_flagged} flagged "
              f"({n_flagged / n_in_quarter * 100:.1f}%)")

    # Normalize score to 0-1 range (higher = more anomalous)
    raw_scores = df["anomaly_score"].dropna()
    score_min = raw_scores.min()
    score_range = raw_scores.max() - score_min
    if score_range > 0:
        df["anomaly_score_normalized"] = 1 - (df["anomaly_score"] - score_min) / score_range
    else:
        df["anomaly_score_normalized"] = 0.0

    return df


# ---------------------------------------------------------------------------
# 2. Organization-stratified anomaly detection
# ---------------------------------------------------------------------------

def org_stratified_anomaly_detection(
    df: pd.DataFrame,
    feature_cols: list[str],
    org_col: str,
    contamination: float = 0.01,
    min_org_records: int = 50,
) -> pd.DataFrame:
    """
    Train separate anomaly models per organization.

    A $50M quarterly obligation is normal for NAVSEA and anomalous for a
    small program office. A global model generates constant false positives
    for large organizations and misses real anomalies in small ones.

    Args:
        df: Transaction DataFrame
        feature_cols: Numeric features
        org_col: Column identifying the organization
        contamination: Expected anomaly fraction per organization
        min_org_records: Organizations below this threshold use global model

    Returns:
        DataFrame with anomaly_score and is_anomaly columns
    """
    df = df.copy()
    for col in feature_cols:
        df[col] = pd.to_numeric(df[col], errors="coerce")

    X_imputed = df[feature_cols].fillna(df[feature_cols].median())
    scaler = RobustScaler()
    X_scaled = scaler.fit_transform(X_imputed)

    df["anomaly_score"] = np.nan
    df["is_anomaly"] = False

    org_counts = df[org_col].value_counts()
    large_orgs = org_counts[org_counts >= min_org_records].index.tolist()
    small_org_mask = ~df[org_col].isin(large_orgs)

    print(f"  {len(large_orgs)} orgs with >= {min_org_records} records -> org-specific models")
    print(f"  {df[org_col].nunique() - len(large_orgs)} small orgs -> global model")

    for org in large_orgs:
        mask = df[org_col] == org
        X_org = X_scaled[mask.values]

        model = IsolationForest(
            contamination=contamination,
            n_estimators=100,
            random_state=42,
            n_jobs=-1,
        )
        model.fit(X_org)
        scores = model.score_samples(X_org)
        preds = model.predict(X_org)

        df.loc[mask, "anomaly_score"] = scores
        df.loc[mask, "is_anomaly"] = preds == -1

    # Global fallback model for small organizations
    if small_org_mask.sum() >= 20:
        X_small = X_scaled[small_org_mask.values]
        global_model = IsolationForest(
            contamination=contamination,
            n_estimators=100,
            random_state=42,
            n_jobs=-1,
        )
        global_model.fit(X_small)
        scores = global_model.score_samples(X_small)
        preds = global_model.predict(X_small)

        df.loc[small_org_mask, "anomaly_score"] = scores
        df.loc[small_org_mask, "is_anomaly"] = preds == -1

    total_flagged = df["is_anomaly"].sum()
    print(f"\n  Total flagged: {total_flagged:,} of {len(df):,} records "
          f"({total_flagged / len(df) * 100:.1f}%)")

    return df


# ---------------------------------------------------------------------------
# 3. One-Class SVM (for smaller, clean datasets)
# ---------------------------------------------------------------------------

def one_class_svm_detector(
    df_normal: pd.DataFrame,
    df_test: pd.DataFrame,
    feature_cols: list[str],
    nu: float = 0.01,
    kernel: str = "rbf",
    gamma: str = "scale",
) -> pd.DataFrame:
    """
    One-Class SVM trained on known-normal transactions.
    Use this when you have a validated sample of normal records to train on,
    such as transactions that have been audited and cleared.

    This does not scale above ~100K training records (training is O(n^2)).
    For larger datasets, use Isolation Forest.

    Args:
        df_normal: DataFrame of known-normal records (training set)
        df_test: DataFrame to score
        feature_cols: Numeric features
        nu: Upper bound on the fraction of training outliers
        kernel: "rbf", "linear", "poly", "sigmoid"
        gamma: Kernel coefficient

    Returns:
        df_test with anomaly_score and is_anomaly columns added
    """
    X_train = df_normal[feature_cols].fillna(df_normal[feature_cols].median())
    train_medians = X_train.median()

    scaler = RobustScaler()
    X_train_scaled = scaler.fit_transform(X_train)

    model = OneClassSVM(nu=nu, kernel=kernel, gamma=gamma)
    model.fit(X_train_scaled)

    X_test = df_test[feature_cols].fillna(train_medians)
    X_test_scaled = scaler.transform(X_test)

    scores = model.score_samples(X_test_scaled)
    preds = model.predict(X_test_scaled)

    result = df_test.copy()
    result["anomaly_score"] = scores
    result["is_anomaly"] = preds == -1

    n_flagged = (preds == -1).sum()
    print(f"  One-Class SVM: {n_flagged} of {len(df_test):,} flagged "
          f"({n_flagged / len(df_test) * 100:.1f}%)")

    return result


# ---------------------------------------------------------------------------
# 4. Autoencoder anomaly detection (PyTorch)
# ---------------------------------------------------------------------------

def build_autoencoder_detector(
    df: pd.DataFrame,
    feature_cols: list[str],
    epochs: int = 50,
    batch_size: int = 256,
    latent_dim: int = 8,
    threshold_percentile: float = 95.0,
) -> pd.DataFrame:
    """
    Autoencoder-based anomaly detection.
    The network learns to reconstruct normal data; anomalies have high
    reconstruction error.

    Useful for equipment telemetry, network traffic, and financial
    workflow sequences where linear methods miss non-linear patterns.

    Requires: pip install torch

    Args:
        df: Input DataFrame
        feature_cols: Numeric features
        epochs: Training epochs
        batch_size: Mini-batch size
        latent_dim: Bottleneck dimension
        threshold_percentile: Errors above this percentile are flagged

    Returns:
        DataFrame with reconstruction_error and is_anomaly columns
    """
    try:
        import torch
        import torch.nn as nn
        from torch.utils.data import DataLoader, TensorDataset
    except ImportError:
        raise ImportError("pip install torch")

    X = df[feature_cols].fillna(df[feature_cols].median())
    scaler = RobustScaler()
    X_scaled = scaler.fit_transform(X).astype(np.float32)
    input_dim = X_scaled.shape[1]

    class Autoencoder(nn.Module):
        def __init__(self):
            super().__init__()
            hidden_dim = max(input_dim // 2, latent_dim * 2)
            self.encoder = nn.Sequential(
                nn.Linear(input_dim, hidden_dim),
                nn.ReLU(),
                nn.Linear(hidden_dim, latent_dim),
                nn.ReLU(),
            )
            self.decoder = nn.Sequential(
                nn.Linear(latent_dim, hidden_dim),
                nn.ReLU(),
                nn.Linear(hidden_dim, input_dim),
            )

        def forward(self, x):
            return self.decoder(self.encoder(x))

    device = "cuda" if torch.cuda.is_available() else "cpu"
    net = Autoencoder().to(device)
    optimizer = torch.optim.Adam(net.parameters(), lr=1e-3)
    criterion = nn.MSELoss()

    tensor_data = torch.tensor(X_scaled).to(device)
    loader = DataLoader(
        TensorDataset(tensor_data, tensor_data),
        batch_size=batch_size,
        shuffle=True,
    )

    print(f"  Training autoencoder on {device}: "
          f"{input_dim}d -> {latent_dim}d -> {input_dim}d")

    for epoch in range(epochs):
        net.train()
        total_loss = 0.0
        for X_batch, y_batch in loader:
            optimizer.zero_grad()
            reconstructed = net(X_batch)
            loss = criterion(reconstructed, y_batch)
            loss.backward()
            optimizer.step()
            total_loss += loss.item()

        if (epoch + 1) % 10 == 0:
            avg_loss = total_loss / len(loader)
            print(f"  Epoch {epoch + 1}/{epochs}: loss={avg_loss:.6f}")

    net.train(False)
    with torch.no_grad():
        reconstructed = net(tensor_data).cpu().numpy()

    reconstruction_errors = np.mean((X_scaled - reconstructed) ** 2, axis=1)
    threshold = float(np.percentile(reconstruction_errors, threshold_percentile))

    result = df.copy()
    result["reconstruction_error"] = reconstruction_errors
    result["is_anomaly"] = reconstruction_errors > threshold

    n_flagged = result["is_anomaly"].sum()
    print(f"  Threshold (p{threshold_percentile:.0f}): {threshold:.6f}")
    print(f"  Flagged: {n_flagged:,} of {len(result):,} records")

    return result


# ---------------------------------------------------------------------------
# 5. Domain expert validation sample
# ---------------------------------------------------------------------------

def anomaly_validation_sample(
    df_flagged: pd.DataFrame,
    label_cols: list[str],
    score_col: str = "anomaly_score_normalized",
    sample_size: int = 50,
    random_state: int = 42,
) -> pd.DataFrame:
    """
    Generate a stratified sample of flagged anomalies for domain expert review.

    Samples from both the top-scored anomalies and random anomalies.
    The mixed sample prevents anchoring experts only on extreme cases
    and helps calibrate the signal-to-noise ratio.

    Add a blank 'expert_verdict' column to the returned DataFrame,
    then have the expert fill in: TRUE_ANOMALY, FALSE_POSITIVE, or UNCLEAR.

    Args:
        df_flagged: DataFrame with is_anomaly column
        label_cols: Record identifier columns to include in the review sheet
        score_col: Anomaly score column for sorting
        sample_size: Total records to include in the review
        random_state: For reproducibility

    Returns:
        Formatted review DataFrame
    """
    anomalies = df_flagged[df_flagged["is_anomaly"]].copy()

    if len(anomalies) == 0:
        print("  No anomalies flagged.")
        return pd.DataFrame()

    actual_sample = min(sample_size, len(anomalies))
    top_n = actual_sample // 2
    random_n = actual_sample - top_n

    if score_col in anomalies.columns:
        top_sample = anomalies.nlargest(top_n, score_col)
    else:
        top_sample = anomalies.head(top_n)

    remaining = anomalies.drop(top_sample.index)
    random_sample = remaining.sample(
        min(random_n, len(remaining)), random_state=random_state
    )

    review_sample = pd.concat([top_sample, random_sample]).drop_duplicates()

    if score_col in review_sample.columns:
        review_sample = review_sample.sort_values(score_col, ascending=False)

    review_sample["expert_verdict"] = ""
    review_sample["expert_notes"] = ""

    output_cols = (
        label_cols
        + ([score_col] if score_col in review_sample.columns else [])
        + ["expert_verdict", "expert_notes"]
    )
    output_cols = [c for c in output_cols if c in review_sample.columns]

    print(f"  Review sample: {len(review_sample)} records "
          f"({top_n} top-scored + {len(random_sample)} random)")
    print("  Fill 'expert_verdict': TRUE_ANOMALY / FALSE_POSITIVE / UNCLEAR")

    return review_sample[output_cols]


# ---------------------------------------------------------------------------
# Demo
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    np.random.seed(42)

    n_normal = 5_000
    n_anomaly = 50

    dates = pd.date_range("2023-10-01", "2024-09-30", periods=n_normal)
    normal_df = pd.DataFrame({
        "transaction_date": dates,
        "obligation_amount": np.random.lognormal(11, 1.0, n_normal),
        "line_item_count": np.random.poisson(5, n_normal),
        "days_to_close": np.random.normal(45, 15, n_normal).clip(1, 365),
        "modification_count": np.random.poisson(2, n_normal),
    })

    anomaly_dates = pd.to_datetime(
        np.random.choice(
            pd.date_range("2023-10-01", "2024-09-30"), n_anomaly
        )
    )
    anomaly_df = pd.DataFrame({
        "transaction_date": anomaly_dates,
        "obligation_amount": np.random.lognormal(16, 0.5, n_anomaly),
        "line_item_count": np.random.poisson(50, n_anomaly),
        "days_to_close": np.random.normal(200, 30, n_anomaly),
        "modification_count": np.random.poisson(20, n_anomaly),
    })

    df = pd.concat([normal_df, anomaly_df], ignore_index=True)
    df["log_obligation"] = np.log1p(df["obligation_amount"])

    features = ["log_obligation", "line_item_count", "days_to_close", "modification_count"]

    print("=== Fiscal-Calendar-Aware Anomaly Detection ===\n")
    df_scored = build_fiscal_aware_anomaly_detector(
        df,
        feature_cols=features,
        date_col="transaction_date",
        contamination=0.01,
    )

    total_flagged = df_scored["is_anomaly"].sum()
    print(f"\nTotal flagged: {total_flagged:,}")

    print("\n=== Top 10 Anomalies ===")
    top_anomalies = df_scored[df_scored["is_anomaly"]].nlargest(
        10, "anomaly_score_normalized"
    )
    print(top_anomalies[[
        "transaction_date", "obligation_amount",
        "modification_count", "anomaly_score_normalized", "fiscal_quarter"
    ]].to_string(index=False))

    print("\n=== Expert Review Sample ===")
    review = anomaly_validation_sample(
        df_scored,
        label_cols=["transaction_date", "obligation_amount", "modification_count"],
        sample_size=20,
    )
    print(review.head(5).to_string(index=False))
