"""
Chapter 02: Python and R Foundations for Federal Platforms
Code Example 03: Data Structures for Federal Data Science

Purpose:
    Practical examples of the data structures you'll use most on federal
    platforms, with patterns specific to government data characteristics:
    - Large tables that don't fit in memory
    - Data with PII that needs column-level access controls
    - Time-series operational data (maintenance, readiness, financials)
    - Hierarchical data with Bronze/Silver/Gold quality tiers

Structures covered:
    1. pandas DataFrames — for manageable, in-memory analysis
    2. PySpark DataFrames — for distributed, large-scale work
    3. numpy arrays — for model inputs and numeric computation
    4. The pandas <-> Spark conversion boundary (where to draw the line)

Platform compatibility:
    - Sections 1-3: Works everywhere Python runs
    - Section 2 (Spark): Requires Databricks cluster
    - Section 4: Databricks-specific
"""

# ===========================================================================
# SECTION 1: PANDAS DATAFRAMES — IN-MEMORY ANALYSIS
# ===========================================================================

import pandas as pd
import numpy as np
from typing import Tuple


def build_sample_procurement_dataframe() -> pd.DataFrame:
    """
    Build a sample procurement DataFrame representing a realistic DoD dataset.

    In production, this data comes from:
        spark.table("advana_catalog.procurement.contract_actions").toPandas()
    or a SQL query filtered to a manageable size.

    This function creates synthetic data that mirrors real procurement data
    characteristics: skewed dollar amounts, categorical NAICS codes,
    missing values in optional fields.
    """
    np.random.seed(42)
    n = 5_000

    # Fiscal year quarters for date-range selection
    fy_quarters = ["2024-Q1", "2024-Q2", "2024-Q3", "2024-Q4", "2025-Q1"]

    # Defense NAICS codes (real codes used in DoD contracting)
    naics_codes = {
        "541330": "Engineering Services",
        "541511": "Custom Computer Programming",
        "541512": "Computer Systems Design",
        "336411": "Aircraft Manufacturing",
        "336413": "Aircraft Parts/Equipment",
        "811310": "Commercial Industrial Machinery Maintenance",
        "561210": "Facilities Support Services",
        "541690": "Other Scientific and Technical Consulting",
    }

    df = pd.DataFrame({
        "contract_id": [f"N{np.random.randint(10000, 99999):05d}-{i:05d}" for i in range(n)],
        "vendor_name": np.random.choice(
            ["Booz Allen Hamilton", "SAIC", "Leidos", "CACI", "Peraton",
             "ManTech", "Jacobs", "L3 Harris", "Northrop Grumman", "Raytheon"],
            size=n
        ),
        "obligation_amount": np.random.lognormal(mean=13.5, sigma=2.0, size=n).clip(1_000, 500_000_000),
        "naics_code": np.random.choice(list(naics_codes.keys()), size=n),
        "fiscal_year": np.random.choice([2022, 2023, 2024], size=n),
        "fy_quarter": np.random.choice(fy_quarters, size=n),
        "awarding_agency": np.random.choice(
            ["Navy", "Army", "Air Force", "DARPA", "DLA", "DCSA"],
            size=n, p=[0.30, 0.25, 0.20, 0.05, 0.15, 0.05]
        ),
        "competition_type": np.random.choice(
            ["Full and Open", "8(a) Set-Aside", "SDVOSB", "HUBZone", "Sole Source"],
            size=n, p=[0.45, 0.15, 0.12, 0.08, 0.20]
        ),
        # Optional field — often missing for older awards
        "parent_award_id": pd.array(
            [f"N00039-{np.random.randint(10000, 99999)}" if np.random.random() > 0.3 else None
             for _ in range(n)],
            dtype=pd.StringDtype()
        ),
    })

    # Add NAICS description for readability
    df["naics_description"] = df["naics_code"].map(naics_codes)

    return df


def pandas_exploration_patterns(df: pd.DataFrame) -> None:
    """
    Standard EDA patterns for procurement DataFrames.
    These patterns work whether the data came from Advana, Jupiter, or a local file.
    """
    print("=== Basic Characterization ===")
    print(f"Shape: {df.shape[0]:,} rows × {df.shape[1]} columns")
    print(f"\nDtypes:\n{df.dtypes}")

    print("\n=== Missing Values ===")
    null_counts = df.isnull().sum()
    null_pct = (null_counts / len(df) * 100).round(1)
    missing = pd.DataFrame({"count": null_counts, "pct": null_pct})
    missing = missing[missing["count"] > 0].sort_values("pct", ascending=False)
    if len(missing) > 0:
        print(missing)
    else:
        print("No missing values")

    print("\n=== Obligation Amount Distribution ===")
    print(df["obligation_amount"].describe().apply(lambda x: f"${x:,.2f}"))

    print("\n=== Awards by Agency and Competition Type ===")
    pivot = (
        df.groupby(["awarding_agency", "competition_type"])["obligation_amount"]
        .sum()
        .unstack(fill_value=0)
        .applymap(lambda x: f"${x/1e6:.1f}M")
    )
    print(pivot)

    print("\n=== Sole Source vs. Competitive (by obligation) ===")
    competitive_flag = df["competition_type"] != "Sole Source"
    summary = df.groupby(competitive_flag)["obligation_amount"].agg(["count", "sum", "mean"])
    summary.index = ["Sole Source", "Competitive"]
    summary["sum"] = summary["sum"].apply(lambda x: f"${x/1e9:.2f}B")
    summary["mean"] = summary["mean"].apply(lambda x: f"${x/1e6:.1f}M")
    print(summary)


def pandas_feature_engineering(df: pd.DataFrame) -> pd.DataFrame:
    """
    Build model-ready features from procurement DataFrame.

    Demonstrates common pandas feature engineering patterns for
    government contract data.
    """
    features = df.copy()

    # Log-transform obligation amount — dollar amounts are highly right-skewed
    features["log_obligation"] = np.log1p(features["obligation_amount"])

    # Flag for large contracts (above $10M threshold — common DoD oversight tier)
    features["is_large_contract"] = (features["obligation_amount"] >= 10_000_000).astype(int)

    # Encode competition type as binary — competitive vs. sole source
    features["is_competitive"] = (features["competition_type"] != "Sole Source").astype(int)

    # Vendor concentration — how many times does this vendor appear?
    vendor_counts = features["vendor_name"].value_counts()
    features["vendor_award_count"] = features["vendor_name"].map(vendor_counts)
    features["log_vendor_award_count"] = np.log1p(features["vendor_award_count"])

    # Has a parent award (task order vs. new contract)
    features["has_parent_award"] = features["parent_award_id"].notna().astype(int)

    # One-hot encode agency (top 4 + other)
    top_agencies = features["awarding_agency"].value_counts().nlargest(4).index
    for agency in top_agencies:
        features[f"agency_{agency.lower().replace(' ', '_')}"] = (
            features["awarding_agency"] == agency
        ).astype(int)

    # Keep only feature columns suitable for model training
    model_cols = [
        "log_obligation", "is_large_contract", "is_competitive",
        "log_vendor_award_count", "has_parent_award",
    ] + [c for c in features.columns if c.startswith("agency_")]

    return features[model_cols]


# ===========================================================================
# SECTION 2: PYSPARK DATAFRAMES — DISTRIBUTED COMPUTATION
# ===========================================================================

def pyspark_patterns_for_large_data():
    """
    PySpark patterns for working with large government datasets.

    These patterns are optimized for Databricks on Advana/Jupiter.
    They assume Unity Catalog with three-part table naming.

    IMPORTANT: This function prints the code patterns — it doesn't run them
    because PySpark requires an active Databricks cluster.
    On Databricks, use these patterns directly in notebook cells.
    """

    spark_patterns = '''
from pyspark.sql import SparkSession, functions as F, types as T
from pyspark.sql.window import Window

spark = SparkSession.getActiveSession()

# ----- Pattern 1: Filter before collect -----
# DO THIS: filter at the Spark level, then bring to driver
maintenance_summary = (
    spark.table("jupiter_catalog.silver.maintenance_work_orders")
    .filter(F.col("hull_class") == "DDG")
    .filter(F.col("fiscal_year").between(2022, 2024))
    .groupBy("hull_number", "work_category")
    .agg(
        F.count("work_order_id").alias("order_count"),
        F.sum("cost_dollars").alias("total_cost"),
        F.avg("days_to_complete").alias("avg_completion_days")
    )
    .filter(F.col("order_count") >= 5)  # Remove noise from small samples
    .toPandas()  # Only convert at the end
)

# ----- Pattern 2: Window functions for time-series analysis -----
# Compute rolling average of readiness score per ship
readiness_df = spark.table("jupiter_catalog.silver.readiness_assessments")

window_spec = Window.partitionBy("hull_number").orderBy("assessment_date")

readiness_with_lag = (
    readiness_df
    .withColumn("prev_score", F.lag("readiness_score", 1).over(window_spec))
    .withColumn("score_delta", F.col("readiness_score") - F.col("prev_score"))
    .withColumn(
        "rolling_avg_3",
        F.avg("readiness_score").over(window_spec.rowsBetween(-2, 0))
    )
)

# ----- Pattern 3: Joining bronze to reference data -----
# Enrich raw records with ship registry metadata
raw_orders = spark.table("jupiter_catalog.bronze.work_orders_raw")
ship_ref = spark.table("jupiter_catalog.reference.ship_registry")

enriched = (
    raw_orders
    .join(
        ship_ref.select("hull_number", "hull_class", "homeport", "commission_year"),
        on="hull_number",
        how="left"  # Keep all orders, add NULLs where ship not in registry
    )
    .withColumn(
        "ship_age_years",
        F.year(F.current_date()) - F.col("commission_year")
    )
)

# ----- Pattern 4: Writing results to Delta -----
# Save processed results back to a silver-tier table
(
    enriched
    .write
    .format("delta")
    .mode("overwrite")
    .option("overwriteSchema", "true")
    .saveAsTable("jupiter_catalog.silver.work_orders_enriched")
)

print("Written to jupiter_catalog.silver.work_orders_enriched")
'''
    print(spark_patterns)


def pyspark_to_pandas_boundary_guide():
    """
    Decision guide: when to stay in Spark vs. when to convert to pandas.
    """
    guidance = """
STAY IN SPARK (PySpark DataFrame) when:
  - Data has more than ~1 million rows before your final aggregation
  - You are joining large tables together
  - You need to write results back to a Delta table
  - You're in a production pipeline (Databricks Workflow, Foundry Transform)
  - The computation is parallelizable (groupBy/agg, filter, join, withColumn)

CONVERT TO PANDAS (.toPandas()) when:
  - Your data has been filtered/aggregated to under ~500K rows
  - You need scikit-learn, statsmodels, or matplotlib
  - You're doing interactive EDA that benefits from pandas indexing
  - You need rich string operations or complex reshaping (stack/unstack/pivot_table)
  - You're building a model feature matrix for training

NEVER convert to pandas when:
  - You haven't filtered yet ("let me just get it into pandas first")
  - The table is billions of rows with no aggregation in sight
  - You're in a scheduled job that needs to scale

RULE OF THUMB: If your .toPandas() call takes more than 30 seconds,
you haven't filtered enough. Go back to Spark.
"""
    print(guidance)


# ===========================================================================
# SECTION 3: NUMPY ARRAYS — MODEL INPUTS AND NUMERIC COMPUTATION
# ===========================================================================

def numpy_model_prep_patterns(df: pd.DataFrame) -> Tuple[np.ndarray, np.ndarray]:
    """
    Prepare numpy arrays from a pandas DataFrame for scikit-learn training.

    Demonstrates the standard pandas -> numpy conversion at the model boundary,
    with attention to the issues that appear in government data:
    - Class imbalance (rare events like contract failures)
    - Missing values that survived feature engineering
    - Mixed dtypes that need explicit handling

    Args:
        df: Feature DataFrame (already engineered, should have no raw columns)

    Returns:
        Tuple of (X, y) numpy arrays ready for sklearn fit()
    """
    from sklearn.preprocessing import StandardScaler
    from sklearn.model_selection import train_test_split

    # Assume the target is the last column for this example
    # In practice, specify explicitly — never use position-based indexing for target
    target_col = "is_large_contract"  # example target
    feature_cols = [c for c in df.columns if c != target_col]

    # Check for any remaining nulls — sklearn will fail with NaN in input
    null_count = df[feature_cols].isnull().sum().sum()
    if null_count > 0:
        print(f"WARNING: {null_count} nulls remain in feature matrix after engineering.")
        print("Fill or drop before training — sklearn will raise ValueError on NaN.")
        # For this example, fill with median — in production, fit imputer on train set only
        df = df.copy()
        df[feature_cols] = df[feature_cols].fillna(df[feature_cols].median())

    # Convert to numpy
    X = df[feature_cols].to_numpy(dtype=np.float64)  # explicit dtype avoids surprises
    y = df[target_col].to_numpy(dtype=np.int32)

    print(f"Feature matrix X: shape {X.shape}, dtype {X.dtype}")
    print(f"Target vector y:  shape {y.shape}, dtype {y.dtype}")
    print(f"Class balance: {np.bincount(y)} (class 0, class 1)")

    # Class imbalance check — common in government data (rare events)
    minority_pct = np.sum(y) / len(y) * 100
    if minority_pct < 10:
        print(f"\nWARNING: Minority class is {minority_pct:.1f}% of data.")
        print("Consider: class_weight='balanced' in sklearn, SMOTE, or adjusted threshold.")

    return X, y


def numpy_batch_inference(X_all: np.ndarray, model, batch_size: int = 10_000) -> np.ndarray:
    """
    Run inference on a large array in batches to avoid memory spikes.

    On federal platforms, you often need to score large datasets.
    Loading the entire array into memory for inference can crash the driver node.
    Batch inference keeps memory usage predictable.

    Args:
        X_all: Full feature matrix (n_samples, n_features)
        model: Fitted sklearn-compatible model with .predict_proba()
        batch_size: Rows per batch (tune based on feature count and driver memory)

    Returns:
        Full prediction array (n_samples,)
    """
    n_samples = len(X_all)
    predictions = np.zeros(n_samples, dtype=np.float32)

    for start in range(0, n_samples, batch_size):
        end = min(start + batch_size, n_samples)
        batch = X_all[start:end]
        # .predict_proba returns (n, 2) — take positive class probability
        predictions[start:end] = model.predict_proba(batch)[:, 1]

        if (start // batch_size) % 10 == 0:
            pct = end / n_samples * 100
            print(f"  Batch {start // batch_size + 1}: rows {start:,}-{end:,} ({pct:.0f}%)")

    return predictions


# ===========================================================================
# SECTION 4: PUTTING IT TOGETHER — FULL PIPELINE EXAMPLE
# ===========================================================================

def full_pipeline_example():
    """
    End-to-end example combining pandas, numpy, and sklearn on
    a realistic government data science problem.

    Scenario: Build a model to flag high-risk procurement actions
    (probability of cost overrun > $1M) using contract award features.

    In production on Databricks, the spark.table() call replaces
    build_sample_procurement_dataframe().
    """
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.model_selection import train_test_split, cross_val_score
    from sklearn.metrics import classification_report, roc_auc_score

    print("=== Full Pipeline: Procurement Risk Classifier ===\n")

    # Step 1: Load data (synthetic here; on Databricks use spark.table())
    print("Step 1: Loading procurement data...")
    raw_df = build_sample_procurement_dataframe()
    print(f"  Loaded {len(raw_df):,} contract actions")

    # Step 2: Explore
    print("\nStep 2: Quick quality check...")
    print(f"  Null rates: {raw_df.isnull().mean().round(3).to_dict()}")
    print(f"  Obligation range: ${raw_df['obligation_amount'].min():,.0f} "
          f"to ${raw_df['obligation_amount'].max():,.0f}")

    # Step 3: Feature engineering
    print("\nStep 3: Engineering features...")
    feature_df = pandas_feature_engineering(raw_df)
    print(f"  Feature columns: {list(feature_df.columns)}")

    # Step 4: Prepare train/test split
    print("\nStep 4: Preparing model inputs...")
    X, y = numpy_model_prep_patterns(feature_df)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y,
        test_size=0.2,
        random_state=42,
        stratify=y  # preserve class balance in both splits
    )
    print(f"  Train: {len(X_train):,} | Test: {len(X_test):,}")

    # Step 5: Train
    print("\nStep 5: Training Random Forest classifier...")
    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=6,
        class_weight="balanced",  # handles class imbalance
        random_state=42,
        n_jobs=-1  # use all available cores
    )
    model.fit(X_train, y_train)

    # Step 6: Evaluate
    print("\nStep 6: Evaluating model performance...")
    y_pred = model.predict(X_test)
    y_proba = model.predict_proba(X_test)[:, 1]

    auc = roc_auc_score(y_test, y_proba)
    print(f"  ROC-AUC: {auc:.4f}")
    print(f"\n  Classification Report:")
    print(classification_report(y_test, y_pred, target_names=["Low Risk", "High Risk"],
                                 indent=4))

    # Step 7: Feature importance
    print("\nStep 7: Feature importance (top features):")
    feature_names = feature_df.columns.tolist()
    importances = pd.Series(model.feature_importances_, index=feature_names)
    importances = importances.sort_values(ascending=False)
    for feat, imp in importances.head(5).items():
        print(f"  {feat:<40} {imp:.4f}")

    print("\n=== Pipeline complete ===")
    return model


if __name__ == "__main__":
    # Run the full pipeline example
    # On Databricks, this would be run as a notebook cell, not as __main__
    print("Running data structures examples...\n")

    # Build sample data
    df = build_sample_procurement_dataframe()
    print(f"Sample DataFrame: {df.shape}")

    # Run EDA
    pandas_exploration_patterns(df)

    # Show conversion boundary guidance
    print("\n")
    pyspark_to_pandas_boundary_guide()

    # Run full pipeline
    print("\n")
    full_pipeline_example()
