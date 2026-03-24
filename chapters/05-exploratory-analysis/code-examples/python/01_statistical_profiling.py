"""
Chapter 05: Statistical Profiling for Government Datasets
==========================================================
A systematic profiling toolkit for federal data science work.

This module implements the full EDA profiling sequence described
in Chapter 05's README. Run these functions on every new dataset
before writing a single model or joining a single table.

Functions:
    profile_dataframe()         -- Full profile: shape, dtypes, nulls, cardinality
    detect_duplicates()         -- True duplicates + near-duplicates by business key
    validate_domain_ranges()    -- Physical constraint checking
    analyze_null_patterns()     -- Clustered vs random null detection
    check_fiscal_year_effects() -- FY seasonality in temporal columns
    stratified_sample()         -- Stratified sampling for large datasets
    generate_quality_report()   -- Structured data quality assessment output

All functions return DataFrames suitable for logging to MLflow
or writing to a Collibra data quality assessment.
"""

import os
import warnings
from datetime import datetime, date
from typing import Any, Dict, List, Optional, Tuple, Union

import numpy as np
import pandas as pd
from scipy import stats

warnings.filterwarnings("ignore", category=FutureWarning)


# ============================================================
# SYNTHETIC GOVERNMENT DATASET
# Representative of a DoD maintenance + personnel record mix.
# Includes realistic quality problems: duplicates, nulls,
# impossible dates, fiscal-year spikes, and encoding drift.
# ============================================================

def generate_synthetic_don_dataset(n_rows: int = 50_000, seed: int = 42) -> pd.DataFrame:
    """
    Generates a synthetic Department of the Navy maintenance dataset
    with deliberately injected data quality problems.

    Injected problems (for EDA practice):
    - 3% true duplicates
    - 8% null COMPLETION_DATE for closed work orders
    - 1.2% records with DAYS_ELAPSED < 0 (impossible: completion before start)
    - Fiscal year end spike in September (3.5x normal volume)
    - Two distinct UNIT_CODE encoding schemes (pre/post FY2022)
    - 0.8% records with CONTRACT_VALUE < 0
    """
    rng = np.random.default_rng(seed)
    n = n_rows

    # Temporal range: FY2020 through FY2024
    start_date = datetime(2019, 10, 1)
    end_date = datetime(2024, 9, 30)
    date_range_days = (end_date - start_date).days

    # Base dates — add September spike
    base_dates = pd.to_datetime(
        start_date + pd.to_timedelta(
            rng.integers(0, date_range_days, n), unit="D"
        )
    )
    # Inject FY end-of-year spike: replace 12% of records with September dates
    sept_mask = rng.random(n) < 0.12
    sept_dates = pd.to_datetime(
        [datetime(rng.integers(2020, 2025), 9, rng.integers(1, 30))
         for _ in range(sept_mask.sum())]
    )
    base_dates = base_dates.copy()
    base_dates.values[sept_mask] = sept_dates.values

    ship_classes = ["Arleigh Burke", "Ticonderoga", "Nimitz", "Wasp", "San Antonio"]
    event_types = ["PM", "CM", "INSP", "MOD", "OVERHAUL", "EMRG"]
    maint_codes_old = [f"MC{i:03d}" for i in range(1, 50)]   # pre-FY2022 scheme
    maint_codes_new = [f"MNT-{i:04d}" for i in range(1, 80)] # post-FY2022 scheme
    source_systems = ["SAMS-E", "SMCS", "DPAS", "NALCOMIS"]

    fiscal_year = base_dates.year.where(base_dates.month >= 10, base_dates.year - 1)

    # Unit codes: old scheme for FY2019-2021, new scheme for FY2022+
    maint_code = np.where(
        fiscal_year <= 2021,
        rng.choice(maint_codes_old, n),
        rng.choice(maint_codes_new, n)
    )

    days_elapsed = rng.exponential(scale=25, size=n).astype(int)
    # Inject impossible negative elapsed days (~1.2%)
    neg_mask = rng.random(n) < 0.012
    days_elapsed[neg_mask] = -rng.integers(1, 15, neg_mask.sum())

    completion_date = base_dates + pd.to_timedelta(days_elapsed, unit="D")
    # Inject null completion dates for ~8% of records (simulating SAMS-E retry gap)
    null_mask = rng.random(n) < 0.08
    completion_date = completion_date.where(~null_mask, other=pd.NaT)

    contract_value = np.exp(rng.normal(12, 2.5, n))  # log-normal
    # Inject negative contract values (~0.8%)
    neg_val_mask = rng.random(n) < 0.008
    contract_value[neg_val_mask] = -contract_value[neg_val_mask]

    df = pd.DataFrame({
        "work_order_id": [f"WO-{i:08d}" for i in range(1, n + 1)],
        "hull_number": rng.choice([f"DDG-{i}" for i in range(51, 130)] +
                                   [f"CG-{i}" for i in range(47, 74)], n),
        "ship_class": rng.choice(ship_classes, n, p=[0.45, 0.12, 0.18, 0.10, 0.15]),
        "event_type": rng.choice(event_types, n, p=[0.35, 0.30, 0.15, 0.08, 0.05, 0.07]),
        "maint_code": maint_code,
        "source_system": rng.choice(source_systems, n, p=[0.50, 0.20, 0.18, 0.12]),
        "start_date": base_dates,
        "completion_date": completion_date,
        "days_elapsed": days_elapsed,
        "contract_value": contract_value,
        "fiscal_year": fiscal_year,
        "work_order_status": rng.choice(["OPEN", "CLOSED", "DEFERRED"], n, p=[0.25, 0.68, 0.07]),
        "priority_code": rng.choice([1, 2, 3, 4], n, p=[0.08, 0.22, 0.45, 0.25]),
    })

    # Inject 3% true duplicates
    n_dups = int(n * 0.03)
    dup_indices = rng.choice(df.index, n_dups, replace=False)
    df = pd.concat([df, df.loc[dup_indices]], ignore_index=True)

    return df


# ============================================================
# CORE PROFILING FUNCTIONS
# ============================================================

def profile_dataframe(df: pd.DataFrame, name: str = "dataset") -> Dict[str, Any]:
    """
    Full statistical profile of a DataFrame.

    Returns a structured dictionary with all profile results,
    suitable for logging to MLflow or writing to a data quality report.

    Args:
        df: DataFrame to profile
        name: Human-readable dataset name for reporting

    Returns:
        Dict with keys: shape, dtypes, nulls, numeric_stats,
        categorical_stats, date_stats
    """
    print(f"\n{'='*65}")
    print(f"  DATA PROFILE: {name}")
    print(f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*65}")

    profile = {"dataset_name": name, "generated_at": datetime.now().isoformat()}

    # --- Shape ---
    profile["shape"] = {"rows": len(df), "columns": len(df.columns)}
    print(f"\n[Shape]\n  Rows: {len(df):,}  |  Columns: {len(df.columns)}")

    # --- Data Types ---
    dtype_summary = df.dtypes.value_counts().to_dict()
    dtype_summary = {str(k): v for k, v in dtype_summary.items()}
    profile["dtype_summary"] = dtype_summary
    print(f"\n[Data Types]")
    for dtype, count in dtype_summary.items():
        print(f"  {dtype}: {count} column(s)")

    # --- Null Analysis ---
    null_counts = df.isnull().sum()
    null_pct = (null_counts / len(df) * 100).round(2)
    null_df = pd.DataFrame({
        "null_count": null_counts,
        "null_pct": null_pct
    }).sort_values("null_pct", ascending=False)
    null_df = null_df[null_df["null_count"] > 0]

    profile["null_analysis"] = null_df.to_dict()
    print(f"\n[Null Analysis]")
    if len(null_df) == 0:
        print("  No null values found.")
    else:
        for col, row in null_df.iterrows():
            print(f"  {col}: {row['null_count']:,} nulls ({row['null_pct']:.1f}%)")

    # --- Numeric Column Stats ---
    numeric_cols = df.select_dtypes(include=[np.number]).columns.tolist()
    if numeric_cols:
        num_stats = df[numeric_cols].describe(percentiles=[0.01, 0.05, 0.25, 0.5, 0.75, 0.95, 0.99])
        profile["numeric_stats"] = num_stats.to_dict()
        print(f"\n[Numeric Columns — Key Stats]")
        for col in numeric_cols:
            s = df[col].dropna()
            neg_count = (s < 0).sum()
            print(f"  {col}:")
            print(f"    range: [{s.min():.2f}, {s.max():.2f}]  "
                  f"median: {s.median():.2f}  "
                  f"negative values: {neg_count:,}")

    # --- Categorical Column Stats ---
    cat_cols = df.select_dtypes(include=["object", "category"]).columns.tolist()
    cat_summary = {}
    print(f"\n[Categorical Columns — Cardinality]")
    for col in cat_cols:
        n_unique = df[col].nunique()
        top_val = df[col].value_counts().index[0] if n_unique > 0 else "N/A"
        top_pct = df[col].value_counts().iloc[0] / len(df) * 100 if n_unique > 0 else 0
        cat_summary[col] = {"unique_values": n_unique, "top_value": top_val, "top_pct": round(top_pct, 1)}
        print(f"  {col}: {n_unique:,} unique | top='{top_val}' ({top_pct:.1f}%)")
    profile["categorical_stats"] = cat_summary

    # --- Date Columns ---
    date_cols = df.select_dtypes(include=["datetime64[ns]", "datetime"]).columns.tolist()
    if date_cols:
        print(f"\n[Date Columns]")
        date_summary = {}
        for col in date_cols:
            s = df[col].dropna()
            date_summary[col] = {
                "min": str(s.min()),
                "max": str(s.max()),
                "null_count": int(df[col].isnull().sum())
            }
            print(f"  {col}: [{s.min().date()} → {s.max().date()}]  "
                  f"nulls: {df[col].isnull().sum():,}")
        profile["date_stats"] = date_summary

    return profile


def detect_duplicates(
    df: pd.DataFrame,
    business_key_cols: Optional[List[str]] = None
) -> Dict[str, Any]:
    """
    Detect true duplicates (all columns) and near-duplicates (business key only).

    True duplicates are safe to drop. Near-duplicates require human review
    to determine which version is authoritative.

    Args:
        df: DataFrame to check
        business_key_cols: columns that together define a unique record.
            If None, checks all-column duplicates only.

    Returns:
        Dict with true_dup_count, near_dup_count, near_dup_sample
    """
    print(f"\n[Duplicate Analysis]")

    # True duplicates: identical on every column
    true_dup_mask = df.duplicated(keep=False)
    true_dup_count = true_dup_mask.sum() // 2  # pairs, not total rows
    true_dup_pct = true_dup_count / len(df) * 100

    print(f"  True duplicates: {true_dup_count:,} pairs ({true_dup_pct:.1f}% of dataset)")
    if true_dup_count > 0:
        print(f"  Action: Drop one of each pair (keep='last' to retain most recent ingest)")

    result = {
        "true_dup_count": int(true_dup_count),
        "true_dup_pct": round(true_dup_pct, 2),
    }

    # Near-duplicates: same business key, different on some columns
    if business_key_cols:
        near_dup_mask = df.duplicated(subset=business_key_cols, keep=False)
        near_dup_groups = near_dup_mask.sum()
        near_dup_pct = near_dup_groups / len(df) * 100

        print(f"  Near-duplicates (on {business_key_cols}): "
              f"{near_dup_groups:,} rows ({near_dup_pct:.1f}% of dataset)")

        if near_dup_groups > 0:
            # Show a sample of near-dup records to aid manual review
            near_dup_sample = (
                df[near_dup_mask]
                .sort_values(business_key_cols)
                .head(10)
            )
            print(f"  Sample near-duplicate records (first 10):")
            print(near_dup_sample[business_key_cols].to_string(index=False))
            print(f"  Action: Review — take most recent by audit timestamp, "
                  f"or highest completion status. Document decision.")

            result["near_dup_count"] = int(near_dup_groups)
            result["near_dup_pct"] = round(near_dup_pct, 2)
            result["near_dup_sample"] = near_dup_sample.to_dict()

    return result


def validate_domain_ranges(
    df: pd.DataFrame,
    domain_rules: Dict[str, Dict[str, Any]]
) -> pd.DataFrame:
    """
    Apply domain validation rules to detect physically impossible values.

    Unlike statistical outlier detection, domain validation flags values
    that are wrong regardless of the distribution — not just unlikely.

    Args:
        df: DataFrame to validate
        domain_rules: Dict mapping column name to rule specification.
            Rule keys: 'min', 'max', 'allowed_values', 'not_null'
            Example:
                {
                    "days_elapsed": {"min": 0, "max": 3650},
                    "contract_value": {"min": 0},
                    "work_order_status": {"allowed_values": ["OPEN","CLOSED","DEFERRED"]},
                    "completion_date": {"not_null_when": "work_order_status == 'CLOSED'"}
                }

    Returns:
        DataFrame of violations: column, rule, violation_count, violation_pct, sample_values
    """
    print(f"\n[Domain Validation]")
    violations = []

    for col, rules in domain_rules.items():
        if col not in df.columns:
            print(f"  WARNING: Column '{col}' not found in dataset — skipping")
            continue

        series = df[col]

        if "min" in rules:
            violation_mask = series.dropna() < rules["min"]
            n_violations = violation_mask.sum()
            if n_violations > 0:
                sample = series[violation_mask].head(5).tolist()
                violations.append({
                    "column": col,
                    "rule": f"min >= {rules['min']}",
                    "violation_count": int(n_violations),
                    "violation_pct": round(n_violations / len(df) * 100, 2),
                    "sample_values": str(sample)
                })
                print(f"  VIOLATION  {col} < {rules['min']}: "
                      f"{n_violations:,} records ({n_violations/len(df)*100:.1f}%)")

        if "max" in rules:
            violation_mask = series.dropna() > rules["max"]
            n_violations = violation_mask.sum()
            if n_violations > 0:
                violations.append({
                    "column": col,
                    "rule": f"max <= {rules['max']}",
                    "violation_count": int(n_violations),
                    "violation_pct": round(n_violations / len(df) * 100, 2),
                    "sample_values": str(series[violation_mask].head(5).tolist())
                })
                print(f"  VIOLATION  {col} > {rules['max']}: "
                      f"{n_violations:,} records")

        if "allowed_values" in rules:
            allowed = set(rules["allowed_values"])
            violation_mask = ~series.dropna().isin(allowed)
            n_violations = violation_mask.sum()
            if n_violations > 0:
                unexpected = series[violation_mask].value_counts().head(5).to_dict()
                violations.append({
                    "column": col,
                    "rule": f"allowed values: {rules['allowed_values']}",
                    "violation_count": int(n_violations),
                    "violation_pct": round(n_violations / len(df) * 100, 2),
                    "sample_values": str(unexpected)
                })
                print(f"  VIOLATION  {col} unexpected values: "
                      f"{n_violations:,} records — {unexpected}")

    if not violations:
        print("  All domain validation rules passed.")

    return pd.DataFrame(violations) if violations else pd.DataFrame(
        columns=["column", "rule", "violation_count", "violation_pct", "sample_values"]
    )


def analyze_null_patterns(
    df: pd.DataFrame,
    null_col: str,
    group_cols: List[str]
) -> pd.DataFrame:
    """
    Check whether nulls in a column cluster along group dimensions.

    Random nulls: roughly uniform null rate across all groups.
    Clustered nulls: one or more groups have dramatically higher null rates
        — signals a data collection or pipeline failure specific to that group.

    Args:
        df: DataFrame
        null_col: column to check for nulls
        group_cols: columns to group by (e.g., ["source_system", "fiscal_year"])

    Returns:
        DataFrame with null rates per group, sorted by null_pct descending
    """
    print(f"\n[Null Pattern Analysis: '{null_col}' by {group_cols}]")

    overall_null_rate = df[null_col].isnull().mean() * 100
    print(f"  Overall null rate: {overall_null_rate:.1f}%")

    result = (
        df.groupby(group_cols, observed=True)
        .agg(
            total_rows=(null_col, "count"),
            null_rows=(null_col, lambda x: x.isnull().sum())
        )
        .reset_index()
    )
    result["null_pct"] = (result["null_rows"] / result["total_rows"] * 100).round(1)
    result = result.sort_values("null_pct", ascending=False)

    # Flag groups with null rate more than 2x the overall rate
    threshold = overall_null_rate * 2
    flagged = result[result["null_pct"] > threshold]

    print(f"\n  Groups with null rate > {threshold:.1f}% (2x overall):")
    if len(flagged) == 0:
        print(f"  None — nulls appear randomly distributed. Safe to impute or drop.")
    else:
        print(flagged.to_string(index=False))
        print(f"\n  ACTION: Clustered nulls detected. Contact data steward for "
              f"{flagged[group_cols[0]].tolist()} — do not impute without understanding cause.")

    return result


def check_fiscal_year_effects(
    df: pd.DataFrame,
    date_col: str,
    value_col: Optional[str] = None
) -> pd.DataFrame:
    """
    Check for fiscal year end-of-year effects in temporal data.

    The U.S. government fiscal year ends September 30. A spike in
    activity during September is a process artifact, not a signal.
    Any model using temporal features must account for this.

    Args:
        df: DataFrame with a datetime column
        date_col: name of the datetime column
        value_col: optional column to aggregate (default: row counts)

    Returns:
        DataFrame with monthly volume, FY month label, and spike indicator
    """
    print(f"\n[Fiscal Year Effect Check: '{date_col}']")

    df = df.copy()
    df["_month"] = pd.to_datetime(df[date_col]).dt.month
    df["_fy_month"] = df["_month"].map({
        10: "FY-01 Oct", 11: "FY-02 Nov", 12: "FY-03 Dec",
        1: "FY-04 Jan", 2: "FY-05 Feb", 3: "FY-06 Mar",
        4: "FY-07 Apr", 5: "FY-08 May", 6: "FY-09 Jun",
        7: "FY-10 Jul", 8: "FY-11 Aug", 9: "FY-12 Sep (FY End)"
    })

    if value_col:
        monthly = df.groupby("_fy_month", observed=True)[value_col].sum().reset_index()
        monthly.columns = ["fy_month", "total_value"]
    else:
        monthly = df.groupby("_fy_month", observed=True).size().reset_index(name="row_count")

    # Sort by FY month order
    fy_order = [f"FY-{i:02d}" for i in range(1, 12)] + ["FY-12 Sep (FY End)"]
    monthly["_sort_key"] = monthly.iloc[:, 0].str[:5]
    monthly = monthly.sort_values("_sort_key").drop(columns=["_sort_key"])

    metric_col = "total_value" if value_col else "row_count"
    mean_val = monthly[metric_col].mean()
    monthly["vs_monthly_avg"] = (monthly[metric_col] / mean_val).round(2)
    monthly["is_fy_end_spike"] = monthly["vs_monthly_avg"] > 2.0

    sep_row = monthly[monthly.iloc[:, 0].str.contains("Sep")]
    if len(sep_row) > 0:
        sep_ratio = sep_row["vs_monthly_avg"].values[0]
        if sep_ratio > 2.0:
            print(f"  FY END SPIKE DETECTED: September volume is {sep_ratio:.1f}x the monthly average.")
            print(f"  ACTION: Add fiscal_year_end indicator feature to any model using this data.")
            print(f"  ACTION: Consider whether September records should be weighted differently.")
        else:
            print(f"  No significant FY end spike detected (September = {sep_ratio:.1f}x average).")

    print(f"\n  Monthly distribution:")
    print(monthly.to_string(index=False))

    return monthly


def stratified_sample(
    df: pd.DataFrame,
    strata_cols: List[str],
    sample_frac: float = 0.01,
    min_per_stratum: int = 50,
    random_state: int = 42
) -> pd.DataFrame:
    """
    Stratified sample that preserves representation of rare groups.

    Simple random sampling on imbalanced government data will
    under-represent rare event types, source systems, or fiscal years.
    This function ensures each stratum is represented.

    Args:
        df: Full DataFrame (can be very large; designed for use before .toPandas())
        strata_cols: columns to stratify on
        sample_frac: target fraction of total rows to sample
        min_per_stratum: minimum rows to include from each stratum,
            even if the stratum is smaller than sample_frac would yield
        random_state: for reproducibility

    Returns:
        Stratified sample DataFrame
    """
    print(f"\n[Stratified Sampling]")
    print(f"  Total rows: {len(df):,}  |  Target fraction: {sample_frac:.1%}")
    print(f"  Strata: {strata_cols}  |  Min per stratum: {min_per_stratum}")

    samples = []
    strata_groups = df.groupby(strata_cols, observed=True)

    for name, group in strata_groups:
        n_target = max(min_per_stratum, int(len(group) * sample_frac))
        n_actual = min(n_target, len(group))
        sample = group.sample(n=n_actual, random_state=random_state)
        samples.append(sample)

    result = pd.concat(samples, ignore_index=True)
    actual_frac = len(result) / len(df)
    print(f"  Sampled: {len(result):,} rows ({actual_frac:.2%} of original)")
    print(f"  Strata covered: {len(samples)}")

    return result


def generate_quality_report(
    profile: Dict[str, Any],
    violations_df: pd.DataFrame,
    null_pattern_findings: str,
    fy_spike_detected: bool,
    duplicate_summary: Dict[str, Any],
    data_tier: str = "Silver",
    steward_name: str = "Unknown — contact Collibra"
) -> pd.DataFrame:
    """
    Generates a structured data quality assessment.

    This is the deliverable you give to your program manager
    and data steward before moving from EDA to modeling.

    Returns a summary DataFrame and prints the full report.
    """
    print(f"\n{'='*65}")
    print(f"  DATA QUALITY ASSESSMENT")
    print(f"  Dataset: {profile['dataset_name']}")
    print(f"  Data Tier: {data_tier}")
    print(f"  Data Steward: {steward_name}")
    print(f"  Assessment Date: {datetime.now().strftime('%Y-%m-%d')}")
    print(f"{'='*65}")

    findings = []

    # Shape
    findings.append({
        "category": "Scale",
        "finding": f"{profile['shape']['rows']:,} rows x {profile['shape']['columns']} columns",
        "severity": "INFO",
        "action": "None"
    })

    # Duplicates
    if duplicate_summary.get("true_dup_count", 0) > 0:
        findings.append({
            "category": "Duplicates",
            "finding": f"{duplicate_summary['true_dup_count']:,} true duplicate pairs "
                       f"({duplicate_summary['true_dup_pct']:.1f}%)",
            "severity": "MEDIUM",
            "action": "Drop duplicates (keep='last') in Silver transform pipeline"
        })

    # Domain violations
    for _, vrow in violations_df.iterrows():
        findings.append({
            "category": "Domain Violation",
            "finding": f"{vrow['column']}: {vrow['violation_count']:,} records violate "
                       f"rule '{vrow['rule']}' ({vrow['violation_pct']:.1f}%)",
            "severity": "HIGH",
            "action": "Correct or exclude in Bronze→Silver transform. Do not use for model training without remediation."
        })

    # Null patterns
    findings.append({
        "category": "Null Patterns",
        "finding": null_pattern_findings,
        "severity": "MEDIUM" if "clustered" in null_pattern_findings.lower() else "LOW",
        "action": "Contact data steward if clustered; impute or exclude if random"
    })

    # Fiscal year effects
    if fy_spike_detected:
        findings.append({
            "category": "Temporal Pattern",
            "finding": "FY end-of-year spike detected in September",
            "severity": "MEDIUM",
            "action": "Add is_fy_end_month feature to model; consider separate model for FY-end records"
        })

    report_df = pd.DataFrame(findings)

    print(f"\n{'Category':<20} {'Severity':<10} {'Finding'}")
    print("-" * 65)
    for _, row in report_df.iterrows():
        print(f"  {row['category']:<18} {row['severity']:<10} {row['finding']}")
        print(f"  {'':18} {'':10} → {row['action']}")
        print()

    high_count = (report_df["severity"] == "HIGH").sum()
    medium_count = (report_df["severity"] == "MEDIUM").sum()

    print(f"Summary: {high_count} HIGH severity | {medium_count} MEDIUM severity")
    if high_count > 0:
        print("RECOMMENDATION: Resolve HIGH severity findings before training any model.")
    else:
        print("RECOMMENDATION: Proceed to modeling with documented MEDIUM findings.")

    return report_df


# ============================================================
# MAIN: Run the full EDA profiling sequence
# ============================================================

if __name__ == "__main__":
    print("Chapter 05: Statistical Profiling Demo")
    print("Generating synthetic DoN maintenance dataset...")

    df = generate_synthetic_don_dataset(n_rows=50_000)
    print(f"Dataset generated: {len(df):,} rows (includes injected duplicates)")

    # Step 1: Full profile
    profile = profile_dataframe(df, name="DON Maintenance Events FY2020-FY2024")

    # Step 2: Duplicate detection
    dup_summary = detect_duplicates(
        df,
        business_key_cols=["work_order_id", "hull_number", "start_date"]
    )

    # Step 3: Domain validation
    domain_rules = {
        "days_elapsed": {"min": 0, "max": 1825},         # no job takes > 5 years
        "contract_value": {"min": 0},                    # no negative contracts
        "work_order_status": {
            "allowed_values": ["OPEN", "CLOSED", "DEFERRED"]
        },
        "priority_code": {"min": 1, "max": 4},
    }
    violations = validate_domain_ranges(df, domain_rules)

    # Step 4: Null pattern analysis — completion_date by source system
    null_patterns = analyze_null_patterns(
        df,
        null_col="completion_date",
        group_cols=["source_system"]
    )
    null_finding = (
        "Clustered nulls detected in completion_date by source_system"
        if null_patterns["null_pct"].std() > 5
        else "Nulls appear randomly distributed"
    )

    # Step 5: Fiscal year check
    fy_results = check_fiscal_year_effects(df, date_col="start_date")
    fy_spike = bool((fy_results["vs_monthly_avg"] > 2.0).any())

    # Step 6: Stratified sample for visualization
    sample_df = stratified_sample(
        df,
        strata_cols=["ship_class", "event_type"],
        sample_frac=0.02,
        min_per_stratum=30
    )
    print(f"\nStratified sample ready: {len(sample_df):,} rows for visualization EDA")

    # Step 7: Quality report
    quality_report = generate_quality_report(
        profile=profile,
        violations_df=violations,
        null_pattern_findings=null_finding,
        fy_spike_detected=fy_spike,
        duplicate_summary=dup_summary,
        data_tier="Bronze",
        steward_name="NIWC Atlantic — Data Management Team (via Collibra)"
    )

    print("\n\nEDA profiling complete. Next step: visualization EDA (02_visualization_eda.py)")
    print("Sample dataset saved to memory for use in visualization notebook.")
