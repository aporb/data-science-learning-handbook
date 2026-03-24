# Chapter 04: Data Wrangling and Cleaning

The data drop landed in Priya Menon's Databricks workspace at 6:14 AM on a Tuesday. Forty-seven million rows. DoD procurement obligations spanning FY2019 through FY2024, pulled from USASpending.gov and supplemented with internal contracting system exports from three separate agencies.

She'd been waiting three weeks for this dataset. The program office had called it "analysis-ready."

By 8 AM she'd found the problem. Vendor names that should be identical were listed forty-seven different ways: "Lockheed Martin Corp," "Lockheed Martin Corporation," "Lockheed-Martin," "LOCKHEED MARTIN," "LMC," and thirty-nine other variants. Contract IDs had mixed formats — some zero-padded, some not, some with dashes, some without. NAICS codes ranged from 4-digit legacy entries to the correct 6-digit current codes. And DUNS numbers — the 9-digit vendor identifiers that were supposed to be unique — appeared in two different columns depending on the source agency, with a third subset using SAM.gov's newer UEI codes that replaced DUNS in April 2022.

She had $180,000 worth of analysis to deliver in six weeks and a dataset that would lie to her every step of the way if she didn't fix it first.

This chapter is about what Priya did next.

*Note: Priya is a composite character representing common patterns in DoD data science engagements. No single individual is depicted.*

Data cleaning is not a preliminary step you knock out before the real work begins. It is the real work — especially in federal government contexts where data comes from dozens of legacy systems, no two agencies standardize the same fields the same way, and "authoritative" sources disagree with each other by hundreds of millions of dollars in obligation amounts. The tools you choose, the order in which you apply them, and the quality rules you enforce will determine whether your downstream analysis is right or wrong. There is no fixing a flawed foundation after the model is built.

## What You'll Build

By the end of this chapter you will be able to:

- Clean messy procurement and government contract data with pandas, including null handling, deduplication, type coercion, and string normalization
- Understand when Polars outperforms pandas and how to apply its key transforms
- Write PySpark DataFrames for wrangling federal datasets too large for a single machine
- Build Palantir Pipeline Builder transforms for no-code/low-code ETL in Foundry
- Use Databricks notebooks for interactive, iterative cleaning workflows
- Standardize government-specific identifiers: CAGE codes, UEI/DUNS codes, NAICS codes, and agency names
- Define and enforce data quality metrics before data reaches any analysis layer
- Handle PII and PHI correctly through masking, tokenization, and anonymization

## Pandas: The First Line of Defense

If your dataset fits in memory — and on a modern workstation, "fits in memory" means roughly anything under 10 million rows of mixed types — pandas is where you start. Not because it's perfect, but because it's the lingua franca. Every platform you'll work on (Databricks, Advana, Jupiter) has Python available. Every data scientist you'll pair with knows pandas. And the operations you need for government data cleaning — nulls, deduplication, string normalization — map directly to its API.

### Null Handling That Doesn't Lie to You

The first mistake most analysts make with government data is calling `df.dropna()` on the whole DataFrame and walking away. That drops real records.

```python
import pandas as pd
import numpy as np

df = pd.read_csv("procurement_obligations_fy2024.csv", low_memory=False)

# Understand what you're dealing with before removing anything
null_summary = pd.DataFrame({
    "null_count": df.isnull().sum(),
    "null_pct": (df.isnull().sum() / len(df) * 100).round(2),
    "dtype": df.dtypes
}).sort_values("null_pct", ascending=False)

print(null_summary[null_summary["null_count"] > 0])
```

That printout will tell you something important: not all nulls are equal. A null in `recipient_uei` might mean the record predates the April 2022 UEI transition and still has a DUNS number. A null in `naics_code` might mean the action was a modification to an existing contract where NAICS was already recorded. A null in `base_and_all_options_value` is a data entry error.

Treat them differently.

```python
# Nulls in UEI: fill from DUNS column for pre-2022 records
df["recipient_uei"] = df["recipient_uei"].fillna(df["recipient_duns_number"])

# Nulls in modification records: forward-fill from parent award
# (requires sorting by contract_award_unique_key and action_date first)
df = df.sort_values(["contract_award_unique_key", "action_date"])
df["naics_code"] = df.groupby("contract_award_unique_key")["naics_code"].ffill()

# Nulls in dollar values are errors — flag them, don't silently drop
df["data_quality_flag"] = df["base_and_all_options_value"].isnull().map(
    {True: "MISSING_DOLLAR_VALUE", False: None}
)
```

### Deduplication: Government Data's Most Persistent Problem

Government procurement data is routinely duplicated across source systems. The same obligation appears in the agency's contracting system, in FPDS-NG, and in the USASpending.gov aggregation — sometimes with slightly different values because they were captured at different points in time.

```python
# Step 1: Identify your true primary key
# In FPDS/USASpending: contract_award_unique_key + modification_number
pk_cols = ["contract_award_unique_key", "modification_number"]
duplicates = df[df.duplicated(subset=pk_cols, keep=False)]
print(f"Duplicate records: {len(duplicates):,} ({len(duplicates)/len(df)*100:.1f}% of data)")

# Step 2: When duplicates exist, keep the most recently updated record
df = (df
    .sort_values("last_modified_date", ascending=False)
    .drop_duplicates(subset=pk_cols, keep="first")
    .reset_index(drop=True)
)

# Step 3: Validate — do dollar totals still make sense after dedup?
total_obligations_before = 47_832_491_203.00  # from source metadata
total_obligations_after = df["federal_action_obligation"].sum()
variance_pct = abs(total_obligations_after - total_obligations_before) / total_obligations_before * 100
print(f"Obligation total variance after dedup: {variance_pct:.2f}%")
# If this is above 0.5%, you dropped records you should have kept
```

### Type Coercion

Government data files are full of columns that should be numeric but arrive as strings because someone exported them with dollar signs, or as objects because one row has "N/A" and pandas refuses to infer float.

```python
# Coerce dollar fields — strip formatting, convert
def clean_dollar_field(series: pd.Series) -> pd.Series:
    return (series
        .astype(str)
        .str.replace(r"[$,\s]", "", regex=True)
        .str.replace(r"\((.+)\)", r"-\1", regex=True)  # (100.00) → -100.00
        .replace({"nan": np.nan, "N/A": np.nan, "": np.nan})
        .astype(float)
    )

dollar_cols = [
    "federal_action_obligation",
    "base_and_all_options_value",
    "base_exercised_options_value"
]
for col in dollar_cols:
    df[col] = clean_dollar_field(df[col])

# Coerce dates — government systems produce at least four date formats
from dateutil.parser import parse as dateutil_parse

def safe_parse_date(val):
    if pd.isnull(val) or str(val).strip() in ("", "nan", "N/A"):
        return pd.NaT
    try:
        return pd.to_datetime(val)
    except Exception:
        return pd.NaT

date_cols = ["action_date", "period_of_performance_start_date", "last_modified_date"]
for col in date_cols:
    df[col] = df[col].apply(safe_parse_date)
```

### String Normalization for Agency Names and Vendor Names

This is where most procurement analysis goes wrong. "Lockheed Martin" in 47 variants will produce 47 separate rows in any aggregation. The fix is not glamorous.

```python
import re
import unicodedata

def normalize_vendor_name(name: str) -> str:
    if pd.isnull(name):
        return ""
    # Normalize unicode (handles accented chars in company names)
    name = unicodedata.normalize("NFKD", str(name))
    # Remove non-ASCII
    name = name.encode("ascii", "ignore").decode("ascii")
    # Uppercase, strip whitespace
    name = name.upper().strip()
    # Remove legal suffixes that vary across records
    legal_suffixes = r"\b(INC|INCORPORATED|CORP|CORPORATION|LLC|LLP|LP|CO|COMPANY|LTD|LIMITED|PLC|GROUP|HOLDINGS|HOLDING|TECHNOLOGIES|TECHNOLOGY|SERVICES|SOLUTIONS|SYSTEMS|INTERNATIONAL|INT'L|INTL)\.?\b"
    name = re.sub(legal_suffixes, "", name)
    # Remove punctuation (except hyphens between name parts)
    name = re.sub(r"[,\.\(\)&/\\]", " ", name)
    # Collapse whitespace
    name = re.sub(r"\s+", " ", name).strip()
    return name

df["vendor_name_normalized"] = df["awardee_or_recipient_legal_entity_name"].apply(normalize_vendor_name)

# After normalization, how many unique vendors do we actually have?
print(f"Raw unique vendors: {df['awardee_or_recipient_legal_entity_name'].nunique():,}")
print(f"Normalized unique vendors: {df['vendor_name_normalized'].nunique():,}")
# Typical result: 30-40% reduction in cardinality
```

**What this means for you:** The full pandas cleaning workflow above — null handling, dedup, type coercion, string normalization — takes three to six hours to write correctly on a new government dataset. It will save you three to six weeks of downstream errors. Run it once, save the cleaned output to Parquet, and never touch the source CSVs again.

## Polars: When Pandas Runs Out of Memory

You have a 40-million-row dataset, 12GB of CSV files, a MacBook Pro with 16GB of RAM, and pandas is about to swap to disk. This is the moment Polars was built for.

Polars is a DataFrame library written in Rust, built on Apache Arrow's columnar memory format. It runs all operations in parallel by default, evaluates lazily (meaning it plans the entire query before executing any of it), and uses memory far more efficiently than pandas for large datasets.

The honest comparison: on a 10-million-row DataFrame, pandas takes roughly 4x longer than Polars for typical groupby-and-aggregate operations. At 100 million rows, you may simply not finish the pandas job before it OOMs. The Polars job completes in minutes.

```python
import polars as pl

# Polars lazy evaluation — nothing executes until .collect()
# This allows it to push down predicates (filter early) and optimize the whole plan
df_lazy = pl.scan_csv(
    "procurement_obligations_fy2024.csv",
    infer_schema_length=10000,
    null_values=["N/A", "null", "", "None"]
)

# Build the entire transform plan without executing
cleaned = (
    df_lazy
    .filter(pl.col("federal_action_obligation").is_not_null())
    .filter(pl.col("action_date") >= "2024-01-01")
    .with_columns([
        # Polars string operations are vectorized and fast
        pl.col("awardee_or_recipient_legal_entity_name")
          .str.to_uppercase()
          .str.strip_chars()
          .alias("vendor_name_upper"),
        # Type cast inside the transform plan
        pl.col("naics_code")
          .cast(pl.Utf8)
          .str.zfill(6)  # Pad NAICS to 6 digits
          .alias("naics_code_std"),
    ])
    .with_columns([
        # Compute derived columns after normalization
        pl.col("federal_action_obligation")
          .cast(pl.Float64)
          .alias("obligation_dollars"),
    ])
    .select([
        "contract_award_unique_key",
        "modification_number",
        "vendor_name_upper",
        "naics_code_std",
        "obligation_dollars",
        "action_date",
        "awarding_agency_name"
    ])
)

# Execute and collect — now it actually runs
result = cleaned.collect()
print(f"Rows: {len(result):,}")
```

When should you reach for Polars instead of pandas? The signal is simple: if your dataset requires more than 25% of your available RAM to load in pandas, switch. If you're running the same aggregation more than once per analysis session on data over 5 million rows, switch. If you're on Databricks and writing a local notebook against a data file rather than a Spark cluster, and the file is over 2GB, switch.

When should you stick with pandas? When your team is unfamiliar with Polars and you're under time pressure. When the downstream library you're feeding data into (scikit-learn, statsmodels, most ML frameworks) expects a pandas DataFrame and the conversion overhead matters. When the data is small enough that performance doesn't matter. Polars is better for large-scale column operations; pandas has a wider ecosystem of compatible libraries.

> **Note:** Polars' API differs meaningfully from pandas. Column selection, filtering, and groupby syntax are similar but not identical. Budget time to read the migration guide if your team is transitioning an existing pandas codebase. The performance gains are real — but the rewrite is not free.

## PySpark on Databricks: When the Data Won't Fit on One Machine

Priya's 47-million-row dataset would technically fit in memory with Polars. But her production pipeline — which needs to join that dataset against three other tables totaling another 300 million rows — won't. For that, she runs PySpark on Databricks.

Spark distributes data across a cluster of machines. Each machine processes its partition independently. The driver node coordinates. The result is a DataFrame abstraction that looks similar to pandas or SQL, but executes in parallel across potentially hundreds of machines.

### Platform Spotlight: Databricks

On Databricks, your PySpark code runs in a notebook attached to a cluster. The cluster can be an all-purpose cluster (always-on, shared across users) or a job cluster (spun up for a single pipeline run, then destroyed). For cleaning workloads, an all-purpose cluster is fine. For production scheduled pipelines, use job clusters to reduce cost.

```python
from pyspark.sql import SparkSession
from pyspark.sql import functions as F
from pyspark.sql.types import DoubleType, DateType, StringType
from pyspark.sql.window import Window

# On Databricks, SparkSession already exists as `spark`
# The line below is for local development:
# spark = SparkSession.builder.appName("procurement_cleaning").getOrCreate()

# Read from Unity Catalog — the right pattern in Databricks post-2025
df = spark.read.table("procurement_catalog.raw.usaspending_fy2024")
print(f"Row count: {df.count():,}")

# Null handling — same logic as pandas, different syntax
df_cleaned = (df
    # Fill UEI from DUNS for pre-2022 records
    .withColumn(
        "recipient_uei",
        F.coalesce(F.col("recipient_uei"), F.col("recipient_duns_number"))
    )
    # Cast dollar fields
    .withColumn(
        "federal_action_obligation",
        F.regexp_replace(F.col("federal_action_obligation"), r"[$,\s]", "")
         .cast(DoubleType())
    )
    # Parse dates
    .withColumn(
        "action_date",
        F.to_date(F.col("action_date"), "yyyy-MM-dd")
    )
    # Normalize vendor names
    .withColumn(
        "vendor_name_upper",
        F.upper(F.trim(F.col("awardee_or_recipient_legal_entity_name")))
    )
    # Standardize NAICS to 6-digit string
    .withColumn(
        "naics_code_std",
        F.lpad(F.col("naics_code").cast(StringType()), 6, "0")
    )
)

# Deduplication using a window function — pick most recently modified record
window = Window.partitionBy(
    "contract_award_unique_key", "modification_number"
).orderBy(F.desc("last_modified_date"))

df_deduped = (df_cleaned
    .withColumn("row_rank", F.row_number().over(window))
    .filter(F.col("row_rank") == 1)
    .drop("row_rank")
)

# Write cleaned output to Delta table with Unity Catalog governance
(df_deduped
    .write
    .format("delta")
    .mode("overwrite")
    .option("overwriteSchema", "true")
    .saveAsTable("procurement_catalog.silver.usaspending_fy2024_clean")
)
```

The Bronze/Silver/Gold pattern you see on Navy Jupiter is not Jupiter-specific — it comes from Databricks' recommended lakehouse architecture, and Databricks itself promotes it. Raw data lands in Bronze (untouched, as ingested). Cleaned and standardized data goes to Silver. Validated, business-rule-enforced data becomes Gold. When you write your cleaned procurement data to `silver.usaspending_fy2024_clean`, you're honoring that contract.

### Platform Spotlight: Advana and Navy Jupiter

Both Advana and Jupiter have Databricks available within their tool ecosystems. When you're working on DoD data through Advana's CDAO infrastructure, your PySpark notebook runs on a managed Databricks workspace within the DoD IL5 boundary. The code above is portable — the same PySpark cleaning logic runs on your local Databricks cluster, on Advana, and on Jupiter.

One Jupiter-specific consideration: because Jupiter's data catalog is Collibra-backed, your gold-tier output should be registered in Collibra with data lineage metadata attached. That's not automated by Databricks alone — your team's data engineer or data steward will need to complete that registration step. The cleaning work you do in PySpark does not automatically become "authoritative" on Jupiter; it becomes authoritative when a data steward reviews it, tags it, and promotes it to the gold tier in the catalog.

## Palantir Foundry: Pipeline Builder vs. Code Repositories

On platforms like Palantir Foundry — used across DoD, DHS, HHS, and NASA — the data cleaning conversation takes a different shape. Foundry gives you two tools for building transforms: **Pipeline Builder** and **Code Repositories**. Choosing between them is a real decision that shapes how your team maintains the pipeline.

**Pipeline Builder** is a visual, node-based interface. You drag nodes onto a canvas — join, filter, cast, rename, union — connect them, configure their parameters, and Foundry generates the underlying Spark code. No Python required. A business analyst can build and maintain it without a data scientist's involvement.

**Code Repositories** are Git-backed Python environments where you write transforms directly in PySpark (via Foundry's `@transform_df` decorator) or SQL. Full programmatic control. Version controlled. Testable.

Here is where most teams get this wrong: they reach for Code Repositories by default because they're engineers who prefer code. That is bad judgment. Use Pipeline Builder when:

- The transform is a standard set of joins, filters, and casts
- The business owner or a less-technical team member needs to modify it without a developer
- You want visual lineage that non-engineers can read
- The pipeline is in production and maintenance cost matters more than flexibility

Use Code Repositories when:
- You need complex conditional logic or custom functions
- You're invoking ML models or doing inference inside the pipeline
- You need unit tests against transform logic
- The transform has edge cases that require careful handling

The code in `code-examples/python/03_palantir_pipeline_builder.py` shows both patterns for the same government data cleaning task — standardizing vendor names and NAICS codes in a Foundry dataset.

### Platform Spotlight: Palantir Foundry

One Foundry capability worth calling out explicitly: its Ontology layer changes how you think about data cleaning. In pandas or Spark, you clean a dataset and output another dataset. In Foundry, you clean data and potentially promote it to an **Object Type** — a semantic entity that links to other objects in the Ontology.

When you clean a `Vendor` dataset in Foundry and define `Vendor` as an Object Type with properties like `uei`, `normalized_name`, and `cage_code`, every other dataset that references that vendor is now navigable through the Ontology. An analyst querying contracts can jump directly to the vendor record, to all related awards, to the vendor's past performance data, without writing a join. The cleaning step isn't just cleaning — it's building the semantic graph that makes everything downstream faster.

This is architecturally different from a Spark lakehouse. It's not better or worse universally — it depends on your use case. For operational decision-making at scale, Foundry's Ontology approach is genuinely powerful. For pure analytical work where you're running statistical models, the overhead of Ontology modeling may not be worth it.

## Government-Specific Wrangling

General-purpose data cleaning tutorials use toy datasets. The government context introduces problems you won't find in those tutorials.

### CAGE Codes, UEI/DUNS, and the SAM.gov Transition

In April 2022, the federal government replaced DUNS (Data Universal Numbering System, a Dun & Bradstreet proprietary identifier) with UEI (Unique Entity Identifier), administered by SAM.gov. Any dataset covering pre-2022 procurement will have DUNS numbers. Post-2022 will have UEIs. Datasets that span both periods — which is most longitudinal analyses — will have both, inconsistently.

CAGE codes (Commercial and Government Entity codes) are a separate 5-character alphanumeric identifier assigned by DoD for defense contracting. They are not the same as UEIs. A single large contractor will have multiple CAGE codes for different operating divisions. The entity-level UEI is more useful for company-level analysis; the CAGE code is more useful for tracking specific performance locations.

```python
def standardize_vendor_identifiers(df: pd.DataFrame) -> pd.DataFrame:
    """
    Standardize CAGE codes, UEI, and legacy DUNS numbers.
    Handles the April 2022 SAM.gov UEI transition period.
    """
    # CAGE codes: always uppercase, 5 characters, alphanumeric
    df["cage_code"] = (df["cage_code"]
        .astype(str)
        .str.upper()
        .str.strip()
        .str.replace(r"[^A-Z0-9]", "", regex=True)  # remove non-alphanumeric
    )
    # Validate CAGE format: 5 chars, first char not I, O, or Q (reserved)
    valid_cage = df["cage_code"].str.match(r"^[A-HJ-NP-Z0-9][A-Z0-9]{4}$")
    df.loc[~valid_cage & (df["cage_code"] != ""), "data_quality_flag"] = "INVALID_CAGE_FORMAT"

    # UEI: 12-character alphanumeric, SAM.gov format
    df["recipient_uei"] = (df["recipient_uei"]
        .astype(str)
        .str.upper()
        .str.strip()
        .str.replace(r"[^A-Z0-9]", "", regex=True)
    )
    valid_uei = df["recipient_uei"].str.match(r"^[A-Z0-9]{12}$")
    # Only flag as invalid if this is a post-2022 record (should have UEI, not DUNS)
    post_2022 = df["action_date"] >= "2022-04-04"
    df.loc[post_2022 & ~valid_uei & (df["recipient_uei"].str.len() > 0), "data_quality_flag"] = "INVALID_UEI_FORMAT"

    # DUNS: 9-digit numeric (legacy, keep for historical records)
    df["recipient_duns_number"] = (df["recipient_duns_number"]
        .astype(str)
        .str.strip()
        .str.replace(r"[^0-9]", "", regex=True)
        .str.zfill(9)  # DUNS numbers are zero-padded to 9 digits
    )

    return df
```

### NAICS Code Standardization

NAICS (North American Industry Classification System) codes are 6-digit codes that classify businesses by industry. The federal government updates NAICS codes every five years. The current version is NAICS 2022. Pre-2022 contracts use earlier versions, and some older codes don't map 1:1 to current codes.

For most analyses, truncating to 2-digit or 3-digit NAICS gives you the sector-level grouping you actually want for any aggregate comparison. The full 6-digit code is only needed for contractor-specific analysis.

```python
# NAICS sector lookup table — top-level 2-digit sectors
NAICS_SECTORS = {
    "11": "Agriculture/Forestry/Fishing/Hunting",
    "21": "Mining/Quarrying/Oil/Gas",
    "22": "Utilities",
    "23": "Construction",
    "31": "Manufacturing",
    "32": "Manufacturing",
    "33": "Manufacturing",
    "42": "Wholesale Trade",
    "44": "Retail Trade",
    "45": "Retail Trade",
    "48": "Transportation/Warehousing",
    "49": "Transportation/Warehousing",
    "51": "Information",
    "52": "Finance/Insurance",
    "53": "Real Estate",
    "54": "Professional/Scientific/Technical Services",
    "55": "Management of Companies/Enterprises",
    "56": "Administrative/Support/Waste Services",
    "61": "Educational Services",
    "62": "Health Care/Social Assistance",
    "71": "Arts/Entertainment/Recreation",
    "72": "Accommodation/Food Services",
    "81": "Other Services",
    "92": "Public Administration",
}

def standardize_naics(df: pd.DataFrame) -> pd.DataFrame:
    # Zero-pad to 6 digits
    df["naics_code"] = (df["naics_code"]
        .astype(str)
        .str.strip()
        .str.replace(r"[^0-9]", "", regex=True)
        .str.zfill(6)
    )
    # Flag codes that aren't 6 digits after cleaning
    df.loc[df["naics_code"].str.len() != 6, "data_quality_flag"] = "INVALID_NAICS_LENGTH"

    # Derive 2-digit sector
    df["naics_sector_code"] = df["naics_code"].str[:2]
    df["naics_sector_desc"] = df["naics_sector_code"].map(NAICS_SECTORS).fillna("Unknown")

    return df
```

### Agency Name Standardization

The federal government has approximately 450 named components across 15 cabinet departments and dozens of independent agencies. Any dataset that spans multiple source systems will have agency names in multiple formats: abbreviations ("DON"), full names ("Department of the Navy"), legacy names ("Department of War"), and internal codes that mean nothing to an outsider.

The only reliable fix is a lookup table. Build one from the official OMB A-11 agency list and join against it.

```python
# Agency standardization via lookup table
# Source: OMB A-11 Appendix C, supplemented with FPDS agency codes
AGENCY_LOOKUP = {
    "DEPT OF DEFENSE": "Department of Defense",
    "DOD": "Department of Defense",
    "DON": "Department of the Navy",
    "DEPT OF THE NAVY": "Department of the Navy",
    "DEPARTMENT OF THE NAVY": "Department of the Navy",
    "USMC": "U.S. Marine Corps",
    "MARINE CORPS": "U.S. Marine Corps",
    "USAF": "U.S. Air Force",
    "DEPARTMENT OF THE AIR FORCE": "U.S. Air Force",
    # ... extend to all 450+ agency variants
}

df["awarding_agency_std"] = (df["awarding_agency_name"]
    .str.upper()
    .str.strip()
    .map(AGENCY_LOOKUP)
    .fillna(df["awarding_agency_name"])  # Keep original if no match found
)

# Flag unmapped agencies for manual review
unmapped = df[df["awarding_agency_std"] == df["awarding_agency_name"]]["awarding_agency_name"].unique()
print(f"Unmapped agency variants requiring lookup table additions: {len(unmapped)}")
```

## Data Quality Metrics and Validation Rules

Cleaning data without measuring it is guesswork. You need numbers.

```python
def compute_quality_metrics(df: pd.DataFrame, table_name: str) -> dict:
    """
    Compute a standard set of data quality metrics for any government dataset.
    Returns a dict suitable for logging to MLflow or writing to a quality table.
    """
    n_rows = len(df)
    metrics = {
        "table_name": table_name,
        "row_count": n_rows,
        "completeness": {},
        "uniqueness": {},
        "validity": {},
    }

    # Completeness: % non-null per critical column
    critical_cols = ["contract_award_unique_key", "recipient_uei", "federal_action_obligation", "action_date"]
    for col in critical_cols:
        if col in df.columns:
            metrics["completeness"][col] = round((1 - df[col].isnull().mean()) * 100, 2)

    # Uniqueness: are primary keys actually unique?
    pk = ["contract_award_unique_key", "modification_number"]
    if all(c in df.columns for c in pk):
        dup_pct = df.duplicated(subset=pk).mean() * 100
        metrics["uniqueness"]["primary_key_duplicate_pct"] = round(dup_pct, 2)

    # Validity: NAICS codes should be 6 digits
    if "naics_code" in df.columns:
        valid_naics = df["naics_code"].str.match(r"^\d{6}$").mean() * 100
        metrics["validity"]["naics_6digit_pct"] = round(valid_naics, 2)

    # Validity: UEI should be 12 alphanumeric characters (for post-2022 records)
    if "recipient_uei" in df.columns:
        valid_uei = df["recipient_uei"].str.match(r"^[A-Z0-9]{12}$").mean() * 100
        metrics["validity"]["uei_format_valid_pct"] = round(valid_uei, 2)

    return metrics
```

On Databricks, log these metrics to MLflow after every cleaning run. That gives you a timestamped record of data quality over time — the kind of audit trail that matters when a contracting officer asks you why your analysis shows different numbers than the official report.

```python
import mlflow

metrics = compute_quality_metrics(df_cleaned, "usaspending_fy2024_clean")

with mlflow.start_run(run_name="procurement_data_quality_check"):
    mlflow.log_param("source_table", "procurement_catalog.raw.usaspending_fy2024")
    mlflow.log_param("cleaning_run_date", "2026-03-23")
    for col, val in metrics["completeness"].items():
        mlflow.log_metric(f"completeness_{col}", val)
    for check, val in metrics["validity"].items():
        mlflow.log_metric(f"validity_{check}", val)
    mlflow.log_metric("uniqueness_pk_dup_pct", metrics["uniqueness"]["primary_key_duplicate_pct"])
```

## Handling PII and PHI

Government datasets routinely contain personally identifiable information (PII) and protected health information (PHI). Veterans' health records on the VA's systems. Personnel files on Jupiter's SIPRNET tier. Beneficiary data flowing through HHS. The rule is simple: you do not analyze raw PII. You mask it, tokenize it, or anonymize it before any analysis layer touches it.

This is not a compliance box to check. It is an engineering constraint that shapes how you build your pipelines.

### Masking vs. Tokenization vs. Anonymization

**Masking** replaces sensitive values with a fixed or partially redacted substitute. It's irreversible. `SSN: 123-45-6789` becomes `SSN: XXX-XX-6789`. Use masking when you need to retain format for display purposes but the actual value must not be visible.

**Tokenization** replaces a sensitive value with a reversible token. `SSN: 123-45-6789` becomes `SSN: TKN_8472af3b`. The original value is stored in a separate token vault. Use tokenization when you need to re-identify records for authorized downstream operations (like sending a payment or mailing a notice) but want to protect the value during intermediate processing.

**Anonymization** removes or generalizes identifying information to the point where re-identification is not feasible. Age `34` becomes `30-35`. ZIP code `22201` becomes `222`. Use anonymization for datasets that will be shared across organizational boundaries or used for aggregate statistical analysis.

```python
import hashlib
import hmac

# Tokenization via HMAC-SHA256 with a secret key
# The token is deterministic (same SSN always produces same token) but not reversible
# without the key
TOKENIZATION_KEY = b"use_a_real_secret_from_your_vault_here"  # store in a secrets manager

def tokenize_field(value: str, key: bytes = TOKENIZATION_KEY) -> str:
    if pd.isnull(value) or str(value).strip() == "":
        return ""
    token = hmac.new(key, str(value).encode("utf-8"), hashlib.sha256).hexdigest()[:16]
    return f"TKN_{token}"

# Apply to PII columns before any analysis DataFrame is created
pii_columns = ["ssn", "date_of_birth", "home_address", "personal_email"]
for col in pii_columns:
    if col in df.columns:
        df[f"{col}_token"] = df[col].apply(tokenize_field)
        df = df.drop(columns=[col])  # Remove raw PII from the working DataFrame

# For aggregation use cases: age binning instead of raw age
if "age" in df.columns:
    df["age_band"] = pd.cut(
        df["age"],
        bins=[0, 25, 35, 45, 55, 65, 120],
        labels=["<25", "25-34", "35-44", "45-54", "55-64", "65+"],
        right=False
    )
    df = df.drop(columns=["age"])
```

> **Sanity check:** "We don't have PII in our procurement dataset." You might be surprised. Sole-source contracts with individual consultants often include SSNs in place of EINs. Small business records can tie directly to individuals' personal tax IDs. Veteran-owned small business certifications include personal background information. Run a pattern-match scan on your string columns before assuming you're clean.

```python
import re

def scan_for_pii_patterns(df: pd.DataFrame) -> pd.DataFrame:
    """
    Scan string columns for likely PII patterns.
    Returns a DataFrame of (column, sample_count) for manual review.
    """
    patterns = {
        "SSN": r"\b\d{3}-\d{2}-\d{4}\b",
        "phone": r"\b\d{3}[-.\s]\d{3}[-.\s]\d{4}\b",
        "email": r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b",
        "credit_card": r"\b(?:\d{4}[-\s]?){3}\d{4}\b",
    }
    results = []
    for col in df.select_dtypes(include="object").columns:
        sample = df[col].dropna().astype(str).head(10000)
        for label, pattern in patterns.items():
            matches = sample.str.contains(pattern, regex=True).sum()
            if matches > 0:
                results.append({"column": col, "pattern": label, "matches_in_sample": int(matches)})
    return pd.DataFrame(results)

pii_scan = scan_for_pii_patterns(df_raw)
if len(pii_scan) > 0:
    print("PII patterns detected — review before proceeding:")
    print(pii_scan)
```

## Where This Goes Wrong

**Failure Mode 1: Treating Cleaning as a One-Time Event**

**The mistake:** You clean the dataset once, save the Parquet file, and move on. Six months later the pipeline updates and the raw data now includes new records with new formatting quirks you've never seen.

**Why smart people make it:** Cleaning is tedious. Once it works, you want to declare victory and never touch it again. This is a rational emotional response. It is also wrong.

**How to recognize you're making it:**
- Your cleaning script has no tests
- The "cleaned" Parquet file has a date in the filename (`cleaned_2024_03.parquet`)
- New records are loaded directly into analysis without passing through the cleaning pipeline
- Quality metrics are measured once, not tracked over time

**What to do instead:** Treat the cleaning pipeline as production code. Write unit tests for each transform function. Run quality metric checks on every new data load. Set thresholds — if completeness on `recipient_uei` drops below 92%, fail the pipeline and alert someone.

---

**Failure Mode 2: Normalizing Away Real Signal**

**The mistake:** You normalize vendor names too aggressively and collapse distinct entities into one.

**Why smart people make it:** The instinct to reduce cardinality is correct. The execution goes too far. "Boeing" and "Boeing Defense Space and Security" are both cleaned to "BOEING" — but they are separate legal entities with different contract vehicles, different performance histories, and different rates.

**How to recognize you're making it:**
- Your normalized vendor column has fewer unique values than the CAGE code column
- You're using UEI-level identifiers for parent-company analysis and ignoring subsidiary distinctions
- A data quality review catches aggregated dollar amounts that exceed what any single entity should hold

**What to do instead:** Normalize for display purposes (dashboards, reports) but preserve the original field. Join against SAM.gov's entity hierarchy data to get official parent/child entity relationships rather than guessing them from name similarity.

---

**Failure Mode 3: Skipping PII Review on "Non-Sensitive" Datasets**

**The mistake:** The dataset is labeled "procurement data," you assume it's clean of PII, and you load it into a shared analytics workspace accessible to 200 analysts.

**Why smart people make it:** The dataset title and metadata say nothing about PII content. The original data owner often doesn't know what's in their own export. And the time pressure to deliver analysis is real.

**How to recognize you're making it:**
- You have never run a PII scan on your input data
- The raw data files are accessible by more people than the sensitivity warrants
- No one on your team has asked the question "could this field contain personal information?"

**What to do instead:** Run `scan_for_pii_patterns()` before loading any new dataset into a shared workspace. Escalate immediately if it finds hits. This is not optional, and getting it wrong has career consequences.

## Platform Comparison

How the five federal platforms handle the data wrangling workflow:

| Capability | Advana (Databricks) | Navy Jupiter (Databricks) | Palantir Foundry | Qlik | Databricks (standalone) |
|---|---|---|---|---|---|
| Primary cleaning interface | PySpark notebooks | PySpark notebooks | Pipeline Builder + Code Repositories | Qlik Data Manager | PySpark notebooks |
| No-code ETL | Limited (via other tools) | Limited | Strong (Pipeline Builder) | Strong (Data Manager) | Limited |
| Handles 100M+ rows | Yes (Spark clusters) | Yes (Spark clusters) | Yes (Spark-backed) | No (memory-bound) | Yes |
| Built-in data lineage | Via Unity Catalog | Via Collibra + Unity Catalog | Native (full Ontology lineage) | Partial | Unity Catalog |
| PII masking support | Via Delta RBAC | Via Delta RBAC | Built into Actions/Transforms | Limited | Unity Catalog column masking |
| Quality metric tracking | MLflow | MLflow | Pipeline health dashboards | Built-in data profiling | MLflow |
| Government data catalogs | Collibra (integrated) | Collibra (primary) | Ontology Object Explorer | Partial | Unity Catalog |
| Semantic entity layer | No | No | Yes (Ontology) | No | No |

The honest read on this table: Databricks (whether via Advana, Jupiter, or standalone) is the best choice for large-scale, code-driven data engineering. Palantir Foundry is the best choice when the downstream use is operational decision-making and you want the Ontology's navigability. Qlik Data Manager is useful for business analysts building smaller dashboards but is not the right tool for production-scale cleaning pipelines.

## Putting It Together

Priya's solution to the 47-million-row procurement dataset looked like this: she wrote a pandas cleaning notebook that she used interactively to understand the data quality problems and develop the transform logic. Once the logic was stable, she ported it to a PySpark notebook on Databricks. The cleaned output wrote to a Delta table in the Silver tier of her Unity Catalog. She logged data quality metrics to MLflow on every run. She registered the output table in the agency's Collibra data catalog with a lineage note pointing to the original raw source.

The vendor name normalization reduced 47 variants of Lockheed Martin to one. The CAGE code validation flagged 3,204 records with malformed identifiers for manual review. The PII scan found 47 records where sole-source contractors had used SSNs as EINs — she masked those before loading to the shared workspace and escalated to the data steward.

The analysis she delivered six weeks later was right. Not because she got lucky, but because she built the infrastructure to make it impossible to be accidentally wrong.

## Exercises

See the [exercises](./exercises/exercises.md) directory for hands-on practice problems.

---

**The one thing to remember:** Government data is not dirty by accident — it reflects decades of incompatible systems, agency-specific conventions, and evolving federal standards. Cleaning it correctly requires knowing the domain as much as knowing the tools. The code handles the mechanics. The domain knowledge tells you which nulls to fill and which to flag, which duplicates to drop and which represent legitimate modifications.

**What to do Monday morning:** Take the most recent government dataset your team is working with and run the `compute_quality_metrics()` function against it before doing any other analysis. Print the completeness and validity numbers. If any critical column is below 95% complete, that is the first problem to solve — not the model, not the visualization, not the report structure. Fix the data.

**What comes next:** Chapter 05 covers exploratory data analysis — how to ask the right questions of a dataset you've just cleaned, how to spot distributional problems that cleaning didn't catch, and how to build the summary statistics and visualizations that translate raw data into defensible findings. Everything in that chapter assumes you've done the work in this one.
