"""
Chapter 05: Platform-Specific EDA Workflows
=============================================
EDA patterns for Databricks, Palantir Foundry, and Qlik SSE.

Each section shows the full workflow for that platform:
  - How to access data
  - How to profile at scale
  - How to log findings
  - How to hand off results to the next stage

Platform sections:
  1. Databricks — PySpark EDA at scale + MLflow logging
  2. Palantir Foundry — Code Workspace EDA with Ontology data
  3. Qlik SSE — Python scoring function callable from Qlik expressions

All code is written to run without external connections where possible.
Platform-specific sections are wrapped in try/except to allow the file
to be read and reviewed on any machine.
"""

import os
import json
import warnings
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import pandas as pd

warnings.filterwarnings("ignore")


# ============================================================
# SECTION 1: DATABRICKS — PYSPARK EDA AT SCALE
# ============================================================

class DatabricksEDAWorkflow:
    """
    EDA workflow for large datasets on Databricks (Advana, Jupiter,
    or standalone DoD GovCloud workspace).

    Designed for datasets where pandas would be inadequate:
    - 10M+ rows for complex operations
    - 50M+ rows for aggregations
    - Any dataset that does not fit on the driver node

    Usage in a Databricks notebook:
        workflow = DatabricksEDAWorkflow(spark, catalog="don_jupiter")
        profile = workflow.profile_spark_table("readiness_silver.ship_maintenance_events")
        sample = workflow.stratified_sample_to_pandas(...)
        workflow.log_eda_to_mlflow(profile)
    """

    def __init__(self, spark=None, catalog: str = "don_jupiter"):
        self.catalog = catalog
        self._spark = spark
        if spark is None:
            try:
                from databricks.connect import DatabricksSession
                self._spark = DatabricksSession.builder.getOrCreate()
                print("Connected via Databricks Connect")
            except ImportError:
                print("Note: spark not available. Patterns shown with pandas fallback.")

    @property
    def spark(self):
        if self._spark is None:
            raise RuntimeError(
                "No SparkSession available. Run inside a Databricks notebook "
                "or configure Databricks Connect for local dev."
            )
        return self._spark

    def profile_spark_table(self, table_path: str) -> Dict[str, Any]:
        """
        Full statistical profile of a Spark table using distributed computation.

        Uses Spark aggregations for exact statistics across the full dataset.
        Much faster than converting to pandas first.

        Args:
            table_path: "schema.table" or "catalog.schema.table"

        Returns:
            Profile dictionary with Spark-computed statistics
        """
        full_path = (
            f"{self.catalog}.{table_path}"
            if table_path.count(".") < 2
            else table_path
        )

        print(f"Profiling: {full_path}")
        df = self.spark.table(full_path)

        from pyspark.sql import functions as F

        numeric_cols = [
            f.name for f in df.schema.fields
            if str(f.dataType) in ("LongType", "DoubleType", "IntegerType", "FloatType")
        ]
        string_cols = [
            f.name for f in df.schema.fields
            if str(f.dataType) == "StringType"
        ]

        total_rows = df.count()
        print(f"  Total rows: {total_rows:,}")

        # Null counts in one pass
        null_aggs = [
            F.sum(F.col(c).isNull().cast("int")).alias(f"{c}_nulls")
            for c in df.columns
        ]
        null_counts = df.agg(*null_aggs).collect()[0].asDict()
        null_summary = {
            k.replace("_nulls", ""): round(v / total_rows * 100, 2)
            for k, v in null_counts.items()
        }

        # Cardinality for string columns
        card_aggs = [F.countDistinct(c).alias(f"{c}_card") for c in string_cols[:10]]
        cardinality = {}
        if card_aggs:
            cardinality = {
                k.replace("_card", ""): v
                for k, v in df.agg(*card_aggs).collect()[0].asDict().items()
            }

        # Numeric stats
        num_stats = {}
        if numeric_cols:
            stat_aggs = []
            for c in numeric_cols[:15]:  # cap to avoid Spark plan explosion
                stat_aggs.extend([
                    F.min(c).alias(f"{c}_min"),
                    F.max(c).alias(f"{c}_max"),
                    F.avg(c).alias(f"{c}_mean"),
                    F.stddev(c).alias(f"{c}_std"),
                    F.sum((F.col(c) < 0).cast("int")).alias(f"{c}_neg"),
                ])
            stats_row = df.agg(*stat_aggs).collect()[0].asDict()
            for c in numeric_cols[:15]:
                num_stats[c] = {
                    "min": stats_row.get(f"{c}_min"),
                    "max": stats_row.get(f"{c}_max"),
                    "mean": stats_row.get(f"{c}_mean"),
                    "std": stats_row.get(f"{c}_std"),
                    "negative_count": stats_row.get(f"{c}_neg", 0)
                }

        profile = {
            "table": full_path,
            "profiled_at": datetime.now().isoformat(),
            "total_rows": total_rows,
            "total_columns": len(df.columns),
            "null_pct_by_column": null_summary,
            "cardinality_by_string_col": cardinality,
            "numeric_stats": num_stats
        }

        # Print summary of issues
        high_null = {k: v for k, v in null_summary.items() if v > 5}
        if high_null:
            print("  High-null columns (> 5%):")
            for col, pct in sorted(high_null.items(), key=lambda x: -x[1]):
                print(f"    {col}: {pct:.1f}%")

        neg_cols = {c: s for c, s in num_stats.items() if s["negative_count"] > 0}
        if neg_cols:
            print("  Columns with negative values (domain violation):")
            for col, s in neg_cols.items():
                print(f"    {col}: {s['negative_count']:,} records")

        return profile

    def stratified_sample_to_pandas(
        self,
        table_path: str,
        strata_col: str,
        sample_frac: float = 0.01,
        min_per_stratum: int = 100,
        max_pandas_rows: int = 500_000
    ) -> pd.DataFrame:
        """
        Stratified sample from a Spark table to pandas for local analysis.

        NEVER call .toPandas() on a full large Spark DataFrame.
        Always filter or sample first. This function enforces that constraint.

        Args:
            table_path: Spark table path
            strata_col: Column to stratify on (e.g., "ship_class", "fiscal_year")
            sample_frac: Target fraction per stratum
            min_per_stratum: Minimum rows from each stratum
            max_pandas_rows: Hard cap on total rows (safety guard)
        """
        from pyspark.sql import functions as F

        full_path = (
            f"{self.catalog}.{table_path}"
            if table_path.count(".") < 2
            else table_path
        )
        df = self.spark.table(full_path)
        total_rows = df.count()

        stratum_counts = (
            df.groupBy(strata_col)
            .count()
            .withColumn(
                "sample_n",
                F.greatest(
                    F.lit(min_per_stratum),
                    (F.col("count") * sample_frac).cast("int")
                )
            )
            .collect()
        )

        total_sample = sum(row["sample_n"] for row in stratum_counts)
        if total_sample > max_pandas_rows:
            scale = max_pandas_rows / total_sample
            print(f"Warning: capping sample from {total_sample:,} to {max_pandas_rows:,} rows.")
        else:
            scale = 1.0

        fractions = {
            row[strata_col]: min(1.0, (row["sample_n"] * scale) / max(1, row["count"]))
            for row in stratum_counts
        }

        sampled_df = df.sampleBy(strata_col, fractions=fractions, seed=42)
        pandas_df = sampled_df.toPandas()

        print(f"Stratified sample: {len(pandas_df):,} rows from {total_rows:,} total "
              f"({len(pandas_df)/total_rows*100:.2f}%)")
        print(f"Strata covered: {pandas_df[strata_col].nunique()} unique '{strata_col}' values")

        return pandas_df

    def log_eda_to_mlflow(self, profile: Dict[str, Any],
                           experiment_name: Optional[str] = None) -> str:
        """
        Log EDA findings to MLflow for audit trail and team sharing.

        Logging EDA to MLflow serves two purposes:
        1. Creates a reproducible record of what the data looked like
           when you started — invaluable when data quality problems surface later
        2. Attaches data quality metadata to the experiment that trains
           on this data, enabling model cards to reference it

        Returns MLflow run ID.
        """
        try:
            import mlflow
        except ImportError:
            print("mlflow not installed. Run: pip install mlflow")
            return ""

        exp_name = experiment_name or f"/eda/{profile['table'].split('.')[-1]}"
        mlflow.set_experiment(exp_name)

        with mlflow.start_run(
            run_name=f"eda_profile_{datetime.now().strftime('%Y%m%d_%H%M')}"
        ):
            mlflow.log_metric("total_rows", profile["total_rows"])
            mlflow.log_metric("total_columns", profile["total_columns"])

            for col, null_pct in profile.get("null_pct_by_column", {}).items():
                safe_col = col.replace("/", "_").replace(" ", "_")[:50]
                mlflow.log_metric(f"null_pct.{safe_col}", null_pct)

            for col, stats in profile.get("numeric_stats", {}).items():
                if stats.get("negative_count", 0) > 0:
                    mlflow.log_metric(f"neg_count.{col}", stats["negative_count"])

            with open("/tmp/eda_profile.json", "w") as f:
                json.dump(profile, f, indent=2, default=str)
            mlflow.log_artifact("/tmp/eda_profile.json", "eda")

            mlflow.set_tag("run_type", "eda")
            mlflow.set_tag("table", profile["table"])
            mlflow.set_tag("profiled_at", profile["profiled_at"])

            run_id = mlflow.active_run().info.run_id
            print(f"EDA profile logged to MLflow run: {run_id}")

        return run_id

    def detect_encoding_drift(
        self,
        table_path: str,
        col: str,
        time_col: str,
        split_year: int = 2022
    ) -> pd.DataFrame:
        """
        Detect encoding scheme changes in a categorical column over time.

        When a DoD source system changes its code set (e.g., maintenance
        type codes), historical and recent data cannot be joined on that
        column without a mapping table. This function surfaces the evidence.

        Compares top-20 values before and after split_year and reports overlap.
        Low overlap (< 50%) signals an encoding scheme change.
        """
        from pyspark.sql import functions as F

        full_path = (
            f"{self.catalog}.{table_path}"
            if table_path.count(".") < 2
            else table_path
        )
        df = self.spark.table(full_path)

        before = (
            df.filter(F.year(time_col) < split_year)
            .groupBy(col).count()
            .orderBy("count", ascending=False)
            .limit(20)
            .toPandas()
        )
        before["period"] = f"Before FY{split_year}"

        after = (
            df.filter(F.year(time_col) >= split_year)
            .groupBy(col).count()
            .orderBy("count", ascending=False)
            .limit(20)
            .toPandas()
        )
        after["period"] = f"FY{split_year} and after"

        combined = pd.concat([before, after], ignore_index=True)

        before_values = set(before[col].tolist())
        after_values = set(after[col].tolist())
        overlap = before_values & after_values
        overlap_pct = len(overlap) / max(len(before_values | after_values), 1) * 100

        print(f"Encoding drift: '{col}' split at FY{split_year}")
        print(f"  Top-20 overlap: {len(overlap)}/{len(before_values | after_values)} ({overlap_pct:.0f}%)")
        if overlap_pct < 50:
            print(f"  WARNING: Encoding scheme likely changed after FY{split_year}.")
            print(f"  ACTION: Request mapping table from data steward before joining.")
        else:
            print(f"  Encoding appears consistent across the split.")

        return combined


# ============================================================
# SECTION 2: PALANTIR FOUNDRY — CODE WORKSPACE EDA
# ============================================================

class FoundryEDAWorkflow:
    """
    EDA workflow for Palantir Foundry Code Workspaces (JupyterLab).

    Key difference from Databricks EDA: data access goes through
    the Foundry dataset API, not a direct table path. The Ontology
    provides semantic metadata — property descriptions, allowed values,
    link types — that standard profiling tools ignore.

    Usage in a Foundry Code Workspace:
        workflow = FoundryEDAWorkflow()
        df = workflow.read_dataset("ri.foundry.main.dataset.abc123")
        profile = workflow.profile_with_ontology_context(df, "ShipMaintenanceEvent")
    """

    def __init__(self, use_dev_tools: bool = False):
        self._ctx = None
        if use_dev_tools:
            try:
                from foundry_dev_tools import FoundryContext
                self._ctx = FoundryContext()
                print("Connected via foundry-dev-tools (local dev)")
            except ImportError:
                print("foundry-dev-tools not installed. "
                      "Install: pip install foundry-dev-tools")

    def read_dataset(self, dataset_rid: str,
                     branch: str = "master",
                     max_rows: Optional[int] = None) -> pd.DataFrame:
        """
        Read a Foundry dataset into pandas.

        Args:
            dataset_rid: Resource Identifier (ri.foundry.main.dataset.xxx)
            branch: Dataset branch (usually 'master')
            max_rows: Row limit for initial exploration

        Returns:
            pandas DataFrame
        """
        if self._ctx:
            df = self._ctx.get_dataset(dataset_rid).to_pandas()
            if max_rows:
                df = df.head(max_rows)
            print(f"Loaded (dev tools): {len(df):,} rows")
            return df

        try:
            from foundry.transforms import Dataset
            dataset = Dataset.get(dataset_rid, branch=branch)
            df = dataset.to_pandas(limit=max_rows) if max_rows else dataset.to_pandas()
            print(f"Loaded (Foundry SDK): {len(df):,} rows")
            return df
        except ImportError:
            print("Not in a Foundry environment — using demo data.")
            return self._get_demo_data()

    def _get_demo_data(self) -> pd.DataFrame:
        rng = np.random.default_rng(42)
        n = 5_000
        return pd.DataFrame({
            "object_rid": [f"ri.foundry.main.object.{i:06d}" for i in range(n)],
            "ship_class": rng.choice(["DDG", "CG", "LHD", "LPD"], n),
            "maintenance_type": rng.choice(["PM", "CM", "INSP"], n),
            "days_to_complete": np.abs(rng.normal(20, 8, n)).astype(int),
            "cost_usd": np.exp(rng.normal(11, 2, n)),
            "is_overdue": rng.random(n) < 0.18,
        })

    def profile_with_ontology_context(
        self,
        df: pd.DataFrame,
        object_type: str,
        property_definitions: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        """
        Profile a DataFrame using Foundry Ontology property definitions.

        The Ontology provides human-readable descriptions, allowed values,
        and link type metadata that standard profiling ignores. This makes
        EDA findings directly actionable: columns without Ontology definitions
        are flagged for data steward review.

        Args:
            df: DataFrame from read_dataset()
            object_type: Ontology Object Type name (e.g., "ShipMaintenanceEvent")
            property_definitions: Optional override dict {col: description}
        """
        print(f"\n[Foundry EDA: {object_type}]")
        print(f"  Rows: {len(df):,}  |  Columns: {len(df.columns)}")

        if property_definitions is None:
            property_definitions = self._fetch_ontology_definitions(object_type)

        profile: Dict[str, Any] = {
            "object_type": object_type,
            "row_count": len(df),
            "column_count": len(df.columns),
            "columns": {}
        }

        undefined_props = []
        for col in df.columns:
            s = df[col]
            col_profile: Dict[str, Any] = {
                "dtype": str(s.dtype),
                "null_pct": round(s.isnull().mean() * 100, 2),
                "description": property_definitions.get(col, "")
            }

            if pd.api.types.is_numeric_dtype(s):
                s_valid = s.dropna()
                col_profile.update({
                    "min": float(s_valid.min()) if len(s_valid) > 0 else None,
                    "max": float(s_valid.max()) if len(s_valid) > 0 else None,
                    "median": float(s_valid.median()) if len(s_valid) > 0 else None,
                    "has_negatives": bool((s_valid < 0).any())
                })
            elif pd.api.types.is_object_dtype(s):
                col_profile.update({
                    "unique_count": int(s.nunique()),
                    "top_3_values": s.value_counts().head(3).to_dict()
                })

            if not property_definitions.get(col):
                undefined_props.append(col)

            profile["columns"][col] = col_profile

        if undefined_props:
            print(f"  Columns without Ontology definitions ({len(undefined_props)}):")
            for p in undefined_props:
                print(f"    {p} — add to {object_type} object type schema in Foundry")
        else:
            print(f"  All {len(df.columns)} columns have Ontology definitions.")

        return profile

    def _fetch_ontology_definitions(self, object_type: str) -> Dict[str, str]:
        """Fetch property descriptions from the Foundry Ontology API."""
        try:
            from foundry.ontology import OntologyClient
            client = OntologyClient()
            obj_schema = client.get_object_type(object_type)
            return {
                prop.api_name: prop.description
                for prop in obj_schema.properties.values()
            }
        except (ImportError, Exception):
            # Demo fallback
            return {
                "ship_class": "Class designation of the vessel (DDG, CG, LHD, LPD)",
                "maintenance_type": "PM=Preventive, CM=Corrective, INSP=Inspection",
                "days_to_complete": "Elapsed days from work order open to close",
                "cost_usd": "Total cost of maintenance event in USD",
                "is_overdue": "True if actual completion exceeded scheduled completion"
            }

    def quiver_summary_for_export(
        self,
        df: pd.DataFrame,
        dimensions: List[str],
        metric: str
    ) -> pd.DataFrame:
        """
        Prepare an aggregated summary table for Foundry Quiver analysis.

        Quiver works best with pre-aggregated data exposed as a Foundry
        dataset. This function prepares that summary for publishing back
        to Foundry, where it feeds a Quiver analysis for point-and-click
        EDA by non-technical stakeholders.

        Args:
            df: Source DataFrame
            dimensions: Categorical columns to group by
            metric: Numeric column to aggregate

        Returns:
            Aggregated DataFrame — publish to Foundry as a dataset
        """
        summary = (
            df.groupby(dimensions, observed=True)[metric]
            .agg(["count", "mean", "median", "std", "min", "max"])
            .reset_index()
        )
        summary.columns = (
            dimensions +
            [f"{metric}_count", f"{metric}_mean", f"{metric}_median",
             f"{metric}_std", f"{metric}_min", f"{metric}_max"]
        )
        print(f"Quiver-ready summary: {len(summary)} rows x {len(summary.columns)} cols")
        print("Publish as a Foundry dataset. Connect to Quiver for point-and-click EDA.")
        return summary


# ============================================================
# SECTION 3: QLIK SSE — EDA FUNCTIONS CALLABLE FROM QLIK
# ============================================================

class QlikSSEEDAFunctions:
    """
    Python functions designed to be called from Qlik via Server-Side Extensions.

    These run on the SSE server and receive data from Qlik's data model.
    They return results that Qlik renders in chart expressions or load scripts.

    Architecture:
        Qlik chart expression:
            =SSEProvider.ScoreAnomalies(contract_value, days_to_award)
        → gRPC call to this Python SSE server
        → score_multivariate_anomalies() receives data
        → Returns anomaly scores as Series
        → Qlik renders as a chart measure

    See: https://github.com/qlik-oss/server-side-extension
    For qlik-py-tools integration: https://github.com/nabeel-oz/qlik-py-tools
    """

    @staticmethod
    def score_multivariate_anomalies(
        df: pd.DataFrame,
        feature_cols: List[str],
        contamination: float = 0.05
    ) -> pd.Series:
        """
        Isolation Forest anomaly scoring for Qlik SSE.

        Called from a Qlik chart expression with feature columns as arguments.
        Returns a normalized anomaly score per row (higher = more anomalous).

        Qlik expression:
            =SSEProvider.ScoreAnomaly(contract_value, days_to_award, vendor_award_count)

        Args:
            df: DataFrame with feature columns (from Qlik data model via SSE)
            feature_cols: Columns to use as features
            contamination: Expected fraction of anomalies

        Returns:
            Series of scores normalized 0-1 (1 = most anomalous)
        """
        from sklearn.ensemble import IsolationForest
        from sklearn.preprocessing import StandardScaler

        missing = [c for c in feature_cols if c not in df.columns]
        if missing:
            raise ValueError(f"Missing columns: {missing}")

        X = df[feature_cols].copy()
        original_index = X.index
        X_clean = X.dropna()

        if len(X_clean) < 50:
            return pd.Series(np.nan, index=original_index)

        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X_clean)

        model = IsolationForest(
            contamination=contamination,
            n_estimators=100,
            random_state=42,
            n_jobs=-1
        )
        model.fit(X_scaled)
        raw_scores = model.score_samples(X_scaled)

        # Normalize to 0-1 (1 = most anomalous)
        score_range = raw_scores.max() - raw_scores.min()
        if score_range == 0:
            normalized = np.zeros(len(raw_scores))
        else:
            normalized = 1 - (raw_scores - raw_scores.min()) / score_range

        result = pd.Series(np.nan, index=original_index, dtype=float)
        result.loc[X_clean.index] = normalized
        return result

    @staticmethod
    def compute_distribution_stats(series: pd.Series) -> Dict[str, Any]:
        """
        Compute distribution statistics callable from Qlik SSE.

        Returns metrics usable as Qlik chart measures:
            mean, median, std, IQR, skewness, kurtosis,
            normality test p-value, log-normality indicator

        Qlik expression examples:
            =SSEProvider.GetMean(contract_value)
            =SSEProvider.GetSkewness(contract_value)
        """
        from scipy import stats as scipy_stats

        s = series.dropna()
        if len(s) < 10:
            return {"error": "Insufficient data (< 10 non-null values)"}

        q1, q3 = s.quantile([0.25, 0.75])
        iqr = q3 - q1

        # Normality: Shapiro-Wilk for n <= 5000, KS test otherwise
        sample = s.sample(min(500, len(s)), random_state=42)
        if len(s) <= 5000:
            _, p_normal = scipy_stats.shapiro(sample)
        else:
            _, p_normal = scipy_stats.kstest(s, "norm", args=(s.mean(), s.std()))

        # Log-normality (financial data)
        s_pos = s[s > 0]
        if len(s_pos) > 10:
            log_sample = np.log(s_pos).sample(min(500, len(s_pos)), random_state=42)
            _, p_lognormal = scipy_stats.shapiro(log_sample)
        else:
            p_lognormal = 0.0

        return {
            "mean": float(s.mean()),
            "median": float(s.median()),
            "std": float(s.std()),
            "iqr": float(iqr),
            "skewness": float(scipy_stats.skew(s)),
            "kurtosis": float(scipy_stats.kurtosis(s)),
            "p_value_normal": round(float(p_normal), 4),
            "p_value_lognormal": round(float(p_lognormal), 4),
            "is_likely_lognormal": bool(p_lognormal > 0.05),
            "iqr_outlier_count": int(
                ((s < q1 - 1.5 * iqr) | (s > q3 + 1.5 * iqr)).sum()
            ),
            "negative_count": int((s < 0).sum())
        }

    @staticmethod
    def fiscal_year_month_index(date_series: pd.Series) -> pd.Series:
        """
        Compute fiscal year month index from a date series.
        Returns 1 (October = FY start) through 12 (September = FY end).

        Use in a Qlik load script to add an FY-aligned month dimension:
            FY_MONTH: SSEProvider.FiscalYearMonth(order_date);
        """
        def to_fy_month(m: int) -> int:
            return m - 9 if m >= 10 else m + 3

        return pd.to_datetime(date_series).dt.month.map(to_fy_month)

    @staticmethod
    def fy_end_flag(date_series: pd.Series) -> pd.Series:
        """
        Returns 1 if a date falls in September (FY end), 0 otherwise.

        Use as a Qlik set analysis dimension to separate FY-end spike
        records from normal operational data:
            =Sum({<FY_END_FLAG={1}>} contract_value) / Sum(contract_value)
        """
        return (pd.to_datetime(date_series).dt.month == 9).astype(int)


# ============================================================
# DEMO: Run all workflow patterns without platform connections
# ============================================================

def demo_pandas_eda_workflow():
    """
    Demonstrates all three workflow patterns using pandas.
    No platform credentials required. Run this on any machine.
    """
    print("\n" + "=" * 65)
    print("DEMO: EDA Workflows (Platform-Independent Demonstration)")
    print("=" * 65)

    # Generate synthetic procurement data
    rng = np.random.default_rng(42)
    n = 10_000
    df = pd.DataFrame({
        "contract_value": np.exp(rng.normal(11.5, 2.2, n)),
        "days_to_award": rng.integers(1, 400, n),
        "vendor_award_count": rng.poisson(3, n),
        "competition_type": rng.choice(
            ["Full", "Sole Source", "Set-Aside", "Limited"],
            n, p=[0.45, 0.25, 0.20, 0.10]
        ),
        "fiscal_year": rng.choice([2020, 2021, 2022, 2023, 2024], n),
        "award_month": rng.choice(range(1, 13), n),
    })
    # Inject anomalies
    df.loc[rng.choice(n, 50, replace=False), "contract_value"] *= 50
    df.loc[rng.choice(n, 30, replace=False), "days_to_award"] = -rng.integers(1, 10, 30)

    print(f"Dataset: {len(df):,} rows — synthetic procurement with injected anomalies")

    # --- Qlik SSE anomaly scoring ---
    qlik_fns = QlikSSEEDAFunctions()
    feature_cols = ["contract_value", "days_to_award", "vendor_award_count"]
    scores = qlik_fns.score_multivariate_anomalies(df, feature_cols)
    df["anomaly_score"] = scores

    print(f"\nTop 5 anomalies by Isolation Forest score:")
    top5 = df.nlargest(5, "anomaly_score")[feature_cols + ["anomaly_score", "competition_type"]]
    print(top5.to_string(index=False))

    # --- Distribution stats ---
    stats = qlik_fns.compute_distribution_stats(df["contract_value"])
    print(f"\nContract value distribution stats:")
    for k, v in stats.items():
        if not isinstance(v, str):
            print(f"  {k}: {v}")

    # --- Fiscal year flags ---
    base = datetime(2020, 1, 1)
    dates = pd.Series([
        base + timedelta(days=int(x))
        for x in rng.integers(0, 365 * 5, n)
    ])
    df["fy_month_index"] = qlik_fns.fiscal_year_month_index(dates)
    df["is_fy_end"] = qlik_fns.fy_end_flag(dates)

    sept_vol = df[df["is_fy_end"] == 1]["contract_value"].sum()
    total_vol = df["contract_value"].sum()
    sept_share = sept_vol / total_vol * 100
    sept_row_pct = df["is_fy_end"].mean() * 100
    print(f"\nFY-end (September): {sept_row_pct:.1f}% of records, "
          f"{sept_share:.1f}% of total contract value")
    print("If September share >> September row %, expect an obligation spike model.")

    # --- Foundry Quiver summary ---
    foundry_wf = FoundryEDAWorkflow()
    demo_df = foundry_wf._get_demo_data()
    quiver_summary = foundry_wf.quiver_summary_for_export(
        demo_df,
        dimensions=["ship_class", "maintenance_type"],
        metric="days_to_complete"
    )
    print(f"\nQuiver-ready summary ({len(quiver_summary)} rows):")
    print(quiver_summary.head().to_string(index=False))

    # --- Foundry Ontology profile ---
    profile = foundry_wf.profile_with_ontology_context(
        demo_df,
        object_type="ShipMaintenanceEvent"
    )
    print(f"\nFoundry profile complete for {profile['object_type']}: "
          f"{profile['row_count']:,} rows")


if __name__ == "__main__":
    print("Chapter 05: Platform EDA Workflows")
    demo_pandas_eda_workflow()

    print("\n\nFor platform-specific execution:")
    print("  Databricks: DatabricksEDAWorkflow(spark) inside a notebook")
    print("  Foundry:    FoundryEDAWorkflow() inside a Code Workspace")
    print("  Qlik SSE:   Deploy QlikSSEEDAFunctions via qlik-py-tools or custom SSE server")
