"""
Chapter 07: Unsupervised ML - Clustering
==========================================
K-means, DBSCAN, and hierarchical clustering on federal procurement
and maintenance data. Includes parameter selection, validation, and
Databricks PySpark ML implementation for distributed workloads.

Requirements:
    pip install scikit-learn pandas numpy scipy matplotlib
    pip install umap-learn  # For UMAP visualization
"""

import warnings
import numpy as np
import pandas as pd
from sklearn.cluster import KMeans, DBSCAN, AgglomerativeClustering
from sklearn.metrics import silhouette_score, davies_bouldin_score
from sklearn.preprocessing import RobustScaler
from sklearn.neighbors import NearestNeighbors
from scipy.cluster.hierarchy import dendrogram, linkage
from typing import Optional

warnings.filterwarnings("ignore", category=UserWarning)


# ---------------------------------------------------------------------------
# 1. K-means with parameter selection
# ---------------------------------------------------------------------------

def kmeans_with_selection(
    df: pd.DataFrame,
    feature_cols: list[str],
    k_range: range = range(2, 16),
    random_state: int = 42,
) -> tuple[pd.DataFrame, dict]:
    """
    Run K-means across a range of k values and return the best model
    based on silhouette score. Also returns selection diagnostics
    (inertia, silhouette, Davies-Bouldin) for manual review.

    Best practice: never pick k without looking at these diagnostics AND
    asking a domain expert whether the chosen grouping makes sense.

    Args:
        df: Input DataFrame
        feature_cols: Columns to cluster on (must be numeric)
        k_range: Range of k values to try
        random_state: For reproducibility

    Returns:
        (df_with_cluster_column, diagnostics_dict)
    """
    X = df[feature_cols].copy()

    # Drop rows with any missing values — clustering requires complete cases
    missing_mask = X.isna().any(axis=1)
    if missing_mask.sum() > 0:
        print(f"  Dropping {missing_mask.sum()} rows with missing values "
              f"({missing_mask.mean()*100:.1f}%)")
    X = X.dropna()

    # Scale: RobustScaler handles the extreme outliers common in federal
    # financial data better than StandardScaler
    scaler = RobustScaler()
    X_scaled = scaler.fit_transform(X)

    diagnostics = {}
    best_k = None
    best_score = -1

    print(f"  Testing k = {list(k_range)}")

    for k in k_range:
        model = KMeans(n_clusters=k, random_state=random_state, n_init=10, max_iter=300)
        labels = model.fit_predict(X_scaled)

        # Silhouette score: -1 to 1, higher is better
        # Computationally expensive for >50K rows — subsample if needed
        if len(X) > 50_000:
            sample_idx = np.random.choice(len(X), 50_000, replace=False)
            sil = silhouette_score(X_scaled[sample_idx], labels[sample_idx])
        else:
            sil = silhouette_score(X_scaled, labels)

        db = davies_bouldin_score(X_scaled, labels)
        inertia = model.inertia_

        diagnostics[k] = {
            "inertia": inertia,
            "silhouette": sil,
            "davies_bouldin": db,
            "model": model,
        }

        print(f"    k={k:2d}: inertia={inertia:,.0f}  silhouette={sil:.3f}  "
              f"davies_bouldin={db:.3f}")

        if sil > best_score:
            best_score = sil
            best_k = k

    print(f"\n  Best k by silhouette: {best_k} (score={best_score:.3f})")
    print("  Review diagnostics — the 'best' k by metric may not be the most "
          "interpretable for domain experts.")

    # Apply the best model
    best_model = diagnostics[best_k]["model"]
    cluster_labels = best_model.predict(X_scaled)

    result = df.loc[X.index].copy()
    result["cluster"] = cluster_labels

    return result, diagnostics


def characterize_clusters(
    df_clustered: pd.DataFrame,
    feature_cols: list[str],
    cluster_col: str = "cluster",
) -> pd.DataFrame:
    """
    Generate per-cluster summary statistics.
    This is what you show the domain expert: "Here is what each cluster looks
    like in terms the data — what do you call these groups?"

    Returns a DataFrame with mean, median, and std for each feature per cluster.
    """
    stats = []
    for cluster_id in sorted(df_clustered[cluster_col].unique()):
        mask = df_clustered[cluster_col] == cluster_id
        cluster_data = df_clustered.loc[mask, feature_cols]

        row = {"cluster": cluster_id, "n_records": mask.sum()}
        for col in feature_cols:
            row[f"{col}_mean"] = cluster_data[col].mean()
            row[f"{col}_median"] = cluster_data[col].median()
        stats.append(row)

    return pd.DataFrame(stats)


# ---------------------------------------------------------------------------
# 2. DBSCAN with eps estimation
# ---------------------------------------------------------------------------

def run_dbscan(
    df: pd.DataFrame,
    feature_cols: list[str],
    min_samples: int = 5,
    eps: Optional[float] = None,
) -> pd.DataFrame:
    """
    DBSCAN clustering. Points labeled -1 are noise/outliers — in many
    government analytics use cases, these are the records most worth
    investigating.

    If eps is not provided, estimates it using the k-distance graph method.

    Args:
        df: Input DataFrame
        feature_cols: Columns to cluster on
        min_samples: Core point neighborhood minimum size (5-20 is typical)
        eps: Neighborhood radius. If None, auto-estimated.

    Returns:
        DataFrame with cluster column (-1 = noise/outlier)
    """
    X = df[feature_cols].dropna()
    scaler = RobustScaler()
    X_scaled = scaler.fit_transform(X)

    if eps is None:
        # k-distance graph: sort distances to k-th nearest neighbor
        # The elbow is a reasonable eps estimate
        nbrs = NearestNeighbors(n_neighbors=min_samples).fit(X_scaled)
        distances, _ = nbrs.kneighbors(X_scaled)
        k_distances = np.sort(distances[:, -1])

        # Simple elbow detection: max second derivative
        diffs = np.diff(k_distances)
        elbow_idx = np.argmax(np.diff(diffs)) + 1
        eps = float(k_distances[elbow_idx])
        print(f"  Auto-estimated eps = {eps:.4f}")

    model = DBSCAN(eps=eps, min_samples=min_samples, n_jobs=-1)
    labels = model.fit_predict(X_scaled)

    result = df.loc[X.index].copy()
    result["cluster"] = labels

    n_clusters = len(set(labels)) - (1 if -1 in labels else 0)
    n_noise = (labels == -1).sum()
    print(f"  DBSCAN: {n_clusters} clusters, {n_noise} noise points "
          f"({n_noise/len(labels)*100:.1f}% of records)")

    return result


# ---------------------------------------------------------------------------
# 3. Hierarchical clustering with dendrogram
# ---------------------------------------------------------------------------

def hierarchical_cluster(
    df: pd.DataFrame,
    feature_cols: list[str],
    n_clusters: int = 5,
    linkage_method: str = "ward",
    max_samples: int = 5_000,
) -> tuple[pd.DataFrame, np.ndarray]:
    """
    Hierarchical (agglomerative) clustering.
    Returns cluster assignments and the linkage matrix for dendrogram plotting.

    Ward linkage minimizes within-cluster variance and is the most common
    choice for government analytics data. Use 'complete' linkage if your
    clusters tend to be non-convex or chain-shaped.

    Args:
        df: Input DataFrame
        feature_cols: Columns to cluster on
        n_clusters: Number of clusters to cut the tree into
        linkage_method: "ward", "complete", "average", or "single"
        max_samples: Cap for dendrogram computation (hierarchical is O(n²))

    Returns:
        (df_with_cluster, linkage_matrix)
    """
    X = df[feature_cols].dropna()

    # Cap samples for computational feasibility
    if len(X) > max_samples:
        print(f"  Sampling {max_samples} records for hierarchical clustering "
              f"(full dataset: {len(X):,})")
        sample_idx = np.random.choice(len(X), max_samples, replace=False)
        X_sample = X.iloc[sample_idx]
    else:
        X_sample = X

    scaler = RobustScaler()
    X_scaled = scaler.fit_transform(X_sample)

    # Build linkage matrix for dendrogram
    Z = linkage(X_scaled, method=linkage_method)

    # Assign cluster labels using AgglomerativeClustering (cleaner API)
    model = AgglomerativeClustering(
        n_clusters=n_clusters,
        linkage=linkage_method,
        metric="euclidean",
    )
    labels = model.fit_predict(X_scaled)

    result = df.loc[X_sample.index].copy()
    result["cluster"] = labels

    print(f"  Hierarchical clustering: {n_clusters} clusters via {linkage_method} linkage")
    for c in range(n_clusters):
        print(f"    Cluster {c}: {(labels == c).sum()} records")

    return result, Z


# ---------------------------------------------------------------------------
# 4. Cluster validation — the domain expert bridge
# ---------------------------------------------------------------------------

def cluster_validation_report(
    df_clustered: pd.DataFrame,
    feature_cols: list[str],
    label_col: Optional[str] = None,
    cluster_col: str = "cluster",
) -> str:
    """
    Generate a text report suitable for presenting to domain experts.
    The goal: give experts something they can read in 5 minutes and respond to
    with "yes, cluster 2 is what we call X" or "these groups don't make sense."

    Args:
        df_clustered: DataFrame with cluster assignments
        feature_cols: Features used for clustering
        label_col: Optional column with record identifiers (contract ID, etc.)
        cluster_col: Column containing cluster labels

    Returns:
        Formatted string report
    """
    lines = ["=" * 60, "CLUSTER VALIDATION REPORT", "=" * 60, ""]
    lines.append(f"Total records: {len(df_clustered):,}")
    lines.append(f"Number of clusters: {df_clustered[cluster_col].nunique()}")
    lines.append("")

    for cluster_id in sorted(df_clustered[cluster_col].unique()):
        if cluster_id == -1:
            cluster_name = "OUTLIERS / NOISE"
        else:
            cluster_name = f"Cluster {cluster_id}"

        mask = df_clustered[cluster_col] == cluster_id
        cluster_data = df_clustered.loc[mask]

        lines.append(f"--- {cluster_name} ---")
        lines.append(f"  Records: {mask.sum():,} ({mask.sum()/len(df_clustered)*100:.1f}%)")

        for col in feature_cols[:6]:  # Cap at 6 features for readability
            col_data = cluster_data[col].dropna()
            if col_data.empty:
                continue
            lines.append(
                f"  {col}: median={col_data.median():.2f}, "
                f"mean={col_data.mean():.2f}, "
                f"range=[{col_data.min():.2f}, {col_data.max():.2f}]"
            )

        # Show example records if label column provided
        if label_col and label_col in df_clustered.columns:
            examples = cluster_data[label_col].head(3).tolist()
            lines.append(f"  Example records: {examples}")

        lines.append("")

    lines.append("=" * 60)
    lines.append("REVIEW QUESTIONS FOR DOMAIN EXPERT:")
    lines.append("1. Do these groups match any categories you recognize?")
    lines.append("2. Are there obvious patterns here that should NOT be grouped together?")
    lines.append("3. What would you name each group?")
    lines.append("4. Are the 'outlier' records worth investigating, or expected?")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# 5. Demo on synthetic federal procurement data
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    np.random.seed(42)
    n = 2_000

    # Synthetic contract award data with four natural groups:
    # Small IT services, Large IT services, Construction, Professional services
    groups = {
        "small_it": {
            "n": 800,
            "obligation": np.random.lognormal(12, 0.8, 800),    # ~$160K median
            "mods": np.random.poisson(2, 800),
            "period_days": np.random.normal(365, 90, 800),
        },
        "large_it": {
            "n": 400,
            "obligation": np.random.lognormal(15.5, 0.6, 400),  # ~$5.4M median
            "mods": np.random.poisson(8, 400),
            "period_days": np.random.normal(1460, 180, 400),    # ~4 year contracts
        },
        "construction": {
            "n": 300,
            "obligation": np.random.lognormal(14, 1.0, 300),
            "mods": np.random.poisson(5, 300),
            "period_days": np.random.normal(540, 120, 300),
        },
        "professional_svcs": {
            "n": 500,
            "obligation": np.random.lognormal(13, 0.7, 500),
            "mods": np.random.poisson(3, 500),
            "period_days": np.random.normal(730, 60, 500),
        },
    }

    records = []
    for group_name, g in groups.items():
        for i in range(g["n"]):
            records.append({
                "contract_id": f"{group_name}_{i:04d}",
                "true_group": group_name,
                "obligation_amount": max(g["obligation"][i], 1000),
                "modification_count": max(g["mods"][i], 0),
                "period_of_performance_days": max(g["period_days"][i], 30),
                "log_obligation": np.log1p(max(g["obligation"][i], 1000)),
            })

    df = pd.DataFrame(records)
    print(f"Dataset: {len(df):,} contracts\n")

    features = ["log_obligation", "modification_count", "period_of_performance_days"]

    # K-means with selection
    print("=== K-means Cluster Selection ===")
    df_clustered, diagnostics = kmeans_with_selection(df, features, k_range=range(2, 9))

    print("\n=== Cluster Characterization ===")
    summary = characterize_clusters(df_clustered, features)
    print(summary.to_string(index=False))

    # DBSCAN to find outliers
    print("\n=== DBSCAN: Finding Outliers ===")
    df_dbscan = run_dbscan(df, features, min_samples=5)
    outliers = df_dbscan[df_dbscan["cluster"] == -1]
    print(f"  Outlier contracts: {len(outliers)}")
    if not outliers.empty:
        print(outliers[["contract_id", "obligation_amount",
                          "modification_count"]].head(5).to_string(index=False))

    # Validation report
    print("\n" + cluster_validation_report(df_clustered, features, label_col="contract_id"))
