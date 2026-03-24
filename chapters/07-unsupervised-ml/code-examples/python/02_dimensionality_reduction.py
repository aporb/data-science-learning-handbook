"""
Chapter 07: Unsupervised ML - Dimensionality Reduction
========================================================
PCA, t-SNE, and UMAP for visualizing and compressing high-dimensional
government datasets. Covers federal procurement portfolios, workforce
data, and sensor telemetry from DoD logistics systems.

Why dimensionality reduction matters in government analytics:
- DoD supply chain datasets routinely have 100-400 features per NSN
- Personnel readiness data combines dozens of training, deployment,
  and qualification fields per service member
- K-means and Isolation Forest degrade in high-dimensional space
  (curse of dimensionality) — reduce first, then cluster

Requirements:
    pip install scikit-learn pandas numpy matplotlib
    pip install umap-learn     # UMAP
    # t-SNE is included in scikit-learn — no extra install needed
"""

import numpy as np
import pandas as pd
from sklearn.decomposition import PCA, NMF, TruncatedSVD
from sklearn.manifold import TSNE
from sklearn.preprocessing import RobustScaler, StandardScaler
from typing import Optional


# ---------------------------------------------------------------------------
# 1. PCA — linear dimensionality reduction
# ---------------------------------------------------------------------------

def pca_with_diagnostics(
    df: pd.DataFrame,
    feature_cols: list[str],
    n_components: int = 30,
    variance_targets: list[float] = (0.80, 0.90, 0.95),
) -> tuple[np.ndarray, pd.DataFrame, "PCA"]:
    """
    Run PCA with explained variance diagnostics.

    For government financial data, 80% of variance is typically captured in
    the first 5-15 components out of hundreds. Run this before any clustering
    or anomaly detection on high-dimensional data.

    Args:
        df: Input DataFrame
        feature_cols: Numeric columns to reduce
        n_components: Number of components to compute
        variance_targets: Report how many components reach each threshold

    Returns:
        (X_pca, loadings_df, fitted_pca_model)
        - X_pca: transformed data, shape (n_samples, n_components)
        - loadings_df: component loadings — which features drive each PC
        - fitted_pca_model: for applying the same transform to new data
    """
    X = df[feature_cols].dropna()

    # RobustScaler handles the extreme outliers common in government financial data
    scaler = RobustScaler()
    X_scaled = scaler.fit_transform(X)

    n_components = min(n_components, len(feature_cols), len(X))
    pca = PCA(n_components=n_components, random_state=42)
    X_pca = pca.fit_transform(X_scaled)

    # Explained variance report
    cumvar = np.cumsum(pca.explained_variance_ratio_)
    print("PCA Explained Variance:")
    for target in variance_targets:
        n_needed = int(np.argmax(cumvar >= target)) + 1
        print(f"  {target*100:.0f}% variance: {n_needed} components "
              f"(out of {len(feature_cols)})")

    # Component loadings — which original features drive each component
    loadings = pd.DataFrame(
        pca.components_.T,
        index=feature_cols,
        columns=[f"PC{i+1}" for i in range(n_components)],
    )

    print("\nTop 5 features driving PC1 (magnitude):")
    top_pc1 = loadings["PC1"].abs().sort_values(ascending=False).head(5)
    for feat, loading in top_pc1.items():
        direction = "+" if loadings.loc[feat, "PC1"] > 0 else "-"
        print(f"  {direction}{feat}: {loading:.3f}")

    return X_pca, loadings, pca


def pca_biplot_data(
    X_pca: np.ndarray,
    loadings: pd.DataFrame,
    n_loading_arrows: int = 10,
) -> tuple[pd.DataFrame, pd.DataFrame]:
    """
    Prepare data for a PCA biplot: scores (sample positions) and
    loading vectors (feature directions) on PC1 vs PC2.

    A biplot is the most useful PCA visualization for domain experts:
    they can see both which samples cluster together AND which features
    pull in which direction.

    Returns:
        (scores_df, arrows_df)
        scores_df: PC1, PC2 coordinates per sample
        arrows_df: PC1, PC2 endpoint coordinates for top loading features
    """
    scores = pd.DataFrame({"PC1": X_pca[:, 0], "PC2": X_pca[:, 1]})

    # Select top loading features by combined magnitude on PC1 and PC2
    combined_loading = (loadings["PC1"] ** 2 + loadings["PC2"] ** 2).sqrt()
    top_features = combined_loading.nlargest(n_loading_arrows).index

    arrows = pd.DataFrame({
        "feature": top_features,
        "PC1": loadings.loc[top_features, "PC1"].values,
        "PC2": loadings.loc[top_features, "PC2"].values,
    })

    # Scale arrows to fit within the score range for readability
    scale = max(scores["PC1"].abs().max(), scores["PC2"].abs().max())
    arrow_scale = max(arrows["PC1"].abs().max(), arrows["PC2"].abs().max())
    if arrow_scale > 0:
        factor = scale * 0.8 / arrow_scale
        arrows["PC1"] = arrows["PC1"] * factor
        arrows["PC2"] = arrows["PC2"] * factor

    return scores, arrows


# ---------------------------------------------------------------------------
# 2. t-SNE — non-linear 2D/3D visualization
# ---------------------------------------------------------------------------

def run_tsne(
    df: pd.DataFrame,
    feature_cols: list[str],
    n_components: int = 2,
    perplexity: float = 30.0,
    n_iter: int = 1000,
    pca_preprocess: bool = True,
    pca_components: int = 50,
    max_samples: int = 10_000,
    random_state: int = 42,
) -> pd.DataFrame:
    """
    t-SNE projection for visualizing high-dimensional government data.

    t-SNE is expensive: O(n^2) without Barnes-Hut approximation.
    For datasets over 10,000 records:
    1. Pre-reduce with PCA to 50 components (set pca_preprocess=True)
    2. Subsample to max_samples before running t-SNE
    3. Use the Barnes-Hut approximation (default in scikit-learn)

    t-SNE preserves local structure but distorts global distances.
    Clusters that appear close in a t-SNE plot may be far apart globally.
    Use UMAP when global structure matters.

    Perplexity guidance for government datasets:
    - Small datasets (< 500 records): perplexity 5-15
    - Medium (500-5000): perplexity 30-50 (default is usually fine)
    - Large (> 5000): perplexity 50-100

    Args:
        df: Input DataFrame
        feature_cols: Numeric columns to reduce
        n_components: 2 (standard) or 3 (for 3D visualizations)
        perplexity: Controls effective neighborhood size
        n_iter: Optimization iterations (1000 minimum recommended)
        pca_preprocess: Apply PCA before t-SNE (strongly recommended)
        pca_components: PCA dimensions before t-SNE
        max_samples: Subsample cap for computational feasibility
        random_state: For reproducibility

    Returns:
        DataFrame with tsne_1, tsne_2 (and tsne_3 if n_components=3) columns
    """
    X = df[feature_cols].dropna()

    if len(X) > max_samples:
        print(f"  Subsampling to {max_samples:,} records for t-SNE "
              f"(full dataset: {len(X):,})")
        sample_idx = np.random.RandomState(random_state).choice(
            len(X), max_samples, replace=False
        )
        X = X.iloc[sample_idx]

    scaler = RobustScaler()
    X_scaled = scaler.fit_transform(X)

    # PCA preprocessing: reduces noise and speeds up t-SNE substantially
    if pca_preprocess and X_scaled.shape[1] > pca_components:
        pca = PCA(n_components=min(pca_components, X_scaled.shape[1]), random_state=random_state)
        X_scaled = pca.fit_transform(X_scaled)
        var_retained = pca.explained_variance_ratio_.sum()
        print(f"  PCA pre-processing: {X_scaled.shape[1]} components, "
              f"{var_retained*100:.1f}% variance retained")

    print(f"  Running t-SNE: {len(X):,} records, "
          f"perplexity={perplexity}, n_iter={n_iter}")

    tsne = TSNE(
        n_components=n_components,
        perplexity=perplexity,
        n_iter=n_iter,
        random_state=random_state,
        learning_rate="auto",
        init="pca",   # Better initialization than random for most data
        n_jobs=-1,
    )
    embedding = tsne.fit_transform(X_scaled)

    result = df.loc[X.index].copy()
    for i in range(n_components):
        result[f"tsne_{i+1}"] = embedding[:, i]

    print(f"  t-SNE KL divergence: {tsne.kl_divergence_:.4f} "
          "(lower = better fit; above 5 may indicate parameter mismatch)")

    return result


# ---------------------------------------------------------------------------
# 3. UMAP — non-linear, preserves global structure
# ---------------------------------------------------------------------------

def run_umap(
    df: pd.DataFrame,
    feature_cols: list[str],
    n_components: int = 2,
    n_neighbors: int = 15,
    min_dist: float = 0.1,
    metric: str = "euclidean",
    random_state: int = 42,
) -> pd.DataFrame:
    """
    UMAP projection. Preferred over t-SNE for:
    - Datasets > 10,000 records (UMAP scales linearly, t-SNE quadratically)
    - Cases where global cluster relationships matter
    - Pre-processing before clustering (UMAP + HDBSCAN is the BERTopic pipeline)

    Parameter guidance:
    n_neighbors (local vs global tradeoff):
        5-15:   Fine local structure, ignores global layout
        30-100: Global structure, less local detail
        15:     Good default for most government datasets

    min_dist (cluster compactness):
        0.0-0.1:  Tight, discrete clusters — good before K-means
        0.5-1.0:  Spread out — good for continuous gradients

    Determinism note: UMAP is not fully deterministic even with fixed random_state
    when run with n_jobs > 1. Set n_jobs=1 for exact reproducibility.

    Args:
        df: Input DataFrame
        feature_cols: Numeric columns to reduce
        n_components: Output dimensions (2 for visualization, 10-50 for pre-clustering)
        n_neighbors: Size of local neighborhood
        min_dist: Minimum distance between points in the embedding
        metric: Distance metric ("euclidean", "cosine" for text embeddings)
        random_state: For reproducibility

    Returns:
        DataFrame with umap_1, umap_2 (etc.) columns added

    Requires: pip install umap-learn
    """
    try:
        import umap as umap_lib
    except ImportError:
        raise ImportError("pip install umap-learn")

    X = df[feature_cols].dropna()
    scaler = RobustScaler()
    X_scaled = scaler.fit_transform(X)

    print(f"  Running UMAP: {len(X):,} records -> {n_components}D "
          f"(n_neighbors={n_neighbors}, min_dist={min_dist})")

    reducer = umap_lib.UMAP(
        n_components=n_components,
        n_neighbors=n_neighbors,
        min_dist=min_dist,
        metric=metric,
        random_state=random_state,
        n_jobs=1,    # n_jobs=1 for determinism; increase for speed if reproducibility is less critical
        verbose=False,
    )
    embedding = reducer.fit_transform(X_scaled)

    result = df.loc[X.index].copy()
    for i in range(n_components):
        result[f"umap_{i+1}"] = embedding[:, i]

    return result


def umap_for_clustering_preprocess(
    df: pd.DataFrame,
    feature_cols: list[str],
    n_components: int = 10,
    n_neighbors: int = 30,
) -> tuple[np.ndarray, "umap.UMAP"]:
    """
    UMAP configured for pre-clustering rather than visualization.

    When using UMAP before K-means or HDBSCAN:
    - Use more components (10-50) rather than 2 — captures more structure
    - Use larger n_neighbors — emphasizes global structure
    - Do NOT use min_dist=0 (can cause degenerate embeddings)

    This is the approach BERTopic uses: embed -> UMAP(n_components=5) -> HDBSCAN.

    Returns:
        (X_reduced, fitted_reducer) — X_reduced ready for clustering
    """
    try:
        import umap as umap_lib
    except ImportError:
        raise ImportError("pip install umap-learn")

    X = df[feature_cols].dropna()
    scaler = RobustScaler()
    X_scaled = scaler.fit_transform(X)

    reducer = umap_lib.UMAP(
        n_components=n_components,
        n_neighbors=n_neighbors,
        min_dist=0.1,
        random_state=42,
        n_jobs=1,
        verbose=False,
    )
    X_reduced = reducer.fit_transform(X_scaled)
    print(f"  UMAP: {X_scaled.shape[1]}D -> {n_components}D "
          f"({len(X):,} records)")
    return X_reduced, reducer


# ---------------------------------------------------------------------------
# 4. NMF — non-negative matrix factorization (for count/frequency data)
# ---------------------------------------------------------------------------

def run_nmf(
    df: pd.DataFrame,
    feature_cols: list[str],
    n_components: int = 10,
    random_state: int = 42,
) -> tuple[np.ndarray, np.ndarray]:
    """
    Non-negative Matrix Factorization for non-negative data.

    NMF is particularly useful for:
    - Document-term matrices (word counts are non-negative)
    - Spending data by category (obligations are non-negative)
    - Parts usage counts in maintenance records

    Unlike PCA, NMF components are additive and parts-based: each component
    represents a "topic" or "pattern" that adds to the original signal.
    This produces more interpretable components than PCA for count data.

    Args:
        df: Input DataFrame (all values must be >= 0)
        feature_cols: Non-negative numeric columns
        n_components: Number of components (equivalent to "topics")
        random_state: For reproducibility

    Returns:
        (W, H) where:
            W shape (n_samples, n_components): sample loadings
            H shape (n_components, n_features): component-feature loadings
    """
    X = df[feature_cols].fillna(0).clip(lower=0)

    # NMF requires non-negative input and no scaling that introduces negatives
    # MinMaxScaler or just raw counts work; StandardScaler does not
    scaler = StandardScaler(with_mean=False)  # Scale variance but not mean
    X_scaled = scaler.fit_transform(X).clip(min=0)

    model = NMF(
        n_components=n_components,
        random_state=random_state,
        max_iter=500,
        init="nndsvd",   # Better initialization for sparse data
    )
    W = model.fit_transform(X_scaled)

    print(f"  NMF: reconstruction error = {model.reconstruction_err_:.4f}")
    print(f"  Top features per component:")
    for i in range(n_components):
        top_idx = model.components_[i].argsort()[-5:][::-1]
        top_feats = [feature_cols[j] for j in top_idx]
        print(f"    Component {i}: {', '.join(top_feats)}")

    return W, model.components_


# ---------------------------------------------------------------------------
# 5. Truncated SVD — for sparse matrices (large document-term matrices)
# ---------------------------------------------------------------------------

def run_truncated_svd(
    sparse_matrix,
    n_components: int = 100,
    random_state: int = 42,
) -> tuple[np.ndarray, "TruncatedSVD"]:
    """
    Truncated SVD (LSA — Latent Semantic Analysis) for sparse matrices.

    Use this instead of PCA when:
    - Your input is a sparse matrix (e.g., TF-IDF document-term matrix)
    - The matrix is too large to densify in memory
    - You want to apply LSA to government document corpora before clustering

    TruncatedSVD does NOT center the data (unlike PCA), which is correct
    behavior for sparse matrices.

    Args:
        sparse_matrix: scipy sparse matrix (e.g., from CountVectorizer)
        n_components: Number of SVD components (100 is typical for LSA)
        random_state: For reproducibility

    Returns:
        (X_reduced, fitted_svd_model)
    """
    svd = TruncatedSVD(n_components=n_components, random_state=random_state)
    X_reduced = svd.fit_transform(sparse_matrix)

    cumvar = np.cumsum(svd.explained_variance_ratio_)
    print(f"  SVD {n_components} components: "
          f"{cumvar[-1]*100:.1f}% variance retained")

    return X_reduced, svd


# ---------------------------------------------------------------------------
# Demo
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    np.random.seed(42)

    # Synthetic high-dimensional DoD supply chain dataset
    # 5,000 National Stock Numbers, 80 features per NSN
    n = 5_000
    n_features = 80

    # Four natural groups: electronics, mechanical parts, consumables, equipment
    group_sizes = [1500, 1200, 1500, 800]
    group_means = [
        np.random.uniform(0, 5, n_features),
        np.random.uniform(3, 8, n_features),
        np.random.uniform(1, 3, n_features),
        np.random.uniform(5, 10, n_features),
    ]

    rows = []
    labels = []
    for gid, (size, mean) in enumerate(zip(group_sizes, group_means)):
        noise = np.random.normal(0, 1, (size, n_features))
        rows.append(noise + mean)
        labels.extend([gid] * size)

    X_raw = np.vstack(rows)
    df = pd.DataFrame(X_raw, columns=[f"f{i:03d}" for i in range(n_features)])
    df["true_group"] = labels

    feature_cols = [c for c in df.columns if c != "true_group"]

    print("=== PCA Diagnostics ===\n")
    X_pca, loadings, pca_model = pca_with_diagnostics(df, feature_cols, n_components=30)

    print("\n=== UMAP for Clustering Pre-processing ===\n")
    X_umap_10d, umap_model = umap_for_clustering_preprocess(
        df, feature_cols, n_components=10
    )
    print(f"  Ready for clustering: {X_umap_10d.shape}")

    print("\n=== UMAP 2D Visualization ===\n")
    df_umap2d = run_umap(df, feature_cols, n_components=2, n_neighbors=15)
    print(df_umap2d[["umap_1", "umap_2", "true_group"]].head(5).to_string(index=False))

    print("\n=== t-SNE 2D (with PCA pre-processing) ===\n")
    df_tsne = run_tsne(
        df, feature_cols, perplexity=30, n_iter=500, pca_preprocess=True,
        max_samples=2000
    )
    print(df_tsne[["tsne_1", "tsne_2", "true_group"]].head(5).to_string(index=False))
