"""
Chapter 04 — Data Wrangling and Cleaning
Example 02: PySpark transforms for large-scale government datasets

Target platform: Databricks (Advana, Navy Jupiter, or standalone)
Classification: UNCLASSIFIED // runs on FedRAMP High environments (IL4/IL5 capable)

This script demonstrates a full PySpark cleaning pipeline for a USASpending.gov
procurement dataset at scale — the kind of 40-100M+ row dataset that won't fit
in pandas memory and requires distributed processing.

On Databricks, SparkSession (`spark`) is pre-configured and available in notebooks.
For local testing with a small PySpark installation, the __main__ block below
creates a local SparkSession.

Key concepts:
    - Reading from Unity Catalog (Databricks best practice post-2025)
    - Schema enforcement for government identifier columns
    - Window functions for deduplication
    - Broadcast joins for NAICS and agency lookup tables
    - Writing to Delta Lake (Bronze → Silver tier pattern)
    - Logging quality metrics to MLflow
"""

from pyspark.sql import SparkSession, DataFrame
from pyspark.sql import functions as F
from pyspark.sql.types import (
    StructType, StructField,
    StringType, DoubleType, DateType, TimestampType, IntegerType,
    LongType
)
from pyspark.sql.window import Window

import mlflow

# ---------------------------------------------------------------------------
# Schema definition
# Enforce schema explicitly on load — don't trust CSV inference for
# government identifier columns (leading zeros in NAICS/DUNS will be truncated
# if inferred as integer types).
# ---------------------------------------------------------------------------

PROCUREMENT_SCHEMA = StructType([
    StructField("contract_award_unique_key", StringType(), nullable=False),
    StructField("award_id_piid", StringType(), nullable=True),
    StructField("modification_number", StringType(), nullable=True),
    StructField("parent_award_id_piid", StringType(), nullable=True),
    StructField("awardee_or_recipient_legal_entity_name", StringType(), nullable=True),
    StructField("cage_code", StringType(), nullable=True),
    StructField("recipient_uei", StringType(), nullable=True),
    StructField("recipient_duns_number", StringType(), nullable=True),
    StructField("federal_action_obligation", StringType(), nullable=True),   # String first; coerce later
    StructField("base_and_all_options_value", StringType(), nullable=True),
    StructField("base_exercised_options_value", StringType(), nullable=True),
    StructField("action_date", StringType(), nullable=True),
    StructField("period_of_performance_start_date", StringType(), nullable=True),
    StructField("period_of_performance_current_end_date", StringType(), nullable=True),
    StructField("last_modified_date", StringType(), nullable=True),
    StructField("awarding_agency_name", StringType(), nullable=True),
    StructField("awarding_agency_code", StringType(), nullable=True),
    StructField("funding_agency_name", StringType(), nullable=True),
    StructField("naics_code", StringType(), nullable=True),
    StructField("product_or_service_code", StringType(), nullable=True),
    StructField("type_of_contract_pricing", StringType(), nullable=True),
])

# NAICS sector lookup — broadcast-joined onto the main DataFrame
NAICS_SECTOR_DATA = [
    ("11", "Agriculture, Forestry, Fishing, and Hunting"),
    ("21", "Mining, Quarrying, and Oil and Gas Extraction"),
    ("22", "Utilities"),
    ("23", "Construction"),
    ("31", "Manufacturing"), ("32", "Manufacturing"), ("33", "Manufacturing"),
    ("42", "Wholesale Trade"),
    ("44", "Retail Trade"), ("45", "Retail Trade"),
    ("48", "Transportation and Warehousing"), ("49", "Transportation and Warehousing"),
    ("51", "Information"),
    ("52", "Finance and Insurance"),
    ("53", "Real Estate and Rental and Leasing"),
    ("54", "Professional, Scientific, and Technical Services"),
    ("55", "Management of Companies and Enterprises"),
    ("56", "Administrative and Support and Waste Management"),
    ("61", "Educational Services"),
    ("62", "Health Care and Social Assistance"),
    ("71", "Arts, Entertainment, and Recreation"),
    ("72", "Accommodation and Food Services"),
    ("81", "Other Services (except Public Administration)"),
    ("92", "Public Administration"),
]

NAICS_SECTOR_SCHEMA = StructType([
    StructField("naics_sector_code", StringType(), nullable=False),
    StructField("naics_sector_desc", StringType(), nullable=False),
])


# ---------------------------------------------------------------------------
# Step 1: Ingest raw data
# ---------------------------------------------------------------------------

def load_from_unity_catalog(spark: SparkSession, table_path: str) -> DataFrame:
    """
    Load a Delta table from Unity Catalog.
    Table path format: <catalog>.<schema>.<table>
    Example: procurement_catalog.raw.usaspending_fy2024

    Preferred over direct CSV reads in production — Delta provides ACID
    guarantees and enables time travel for audit purposes.
    """
    df = spark.read.table(table_path)
    row_count = df.count()
    print(f"Loaded {row_count:,} rows from {table_path}")
    return df


def load_from_csv(spark: SparkSession, path: str) -> DataFrame:
    """
    Load from CSV when Unity Catalog is not available (e.g., initial ingest
    of a raw USASpending.gov export before it has been registered as a table).
    """
    df = spark.read.csv(
        path,
        schema=PROCUREMENT_SCHEMA,
        header=True,
        nullValue="",
        nanValue="N/A",
    )
    print(f"Loaded {df.count():,} rows from {path}")
    return df


# ---------------------------------------------------------------------------
# Step 2: Null handling
# ---------------------------------------------------------------------------

def handle_nulls(df: DataFrame) -> DataFrame:
    """
    Handle nulls with domain context:
    - UEI nulls: fill from DUNS (legacy pre-2022 records)
    - NAICS nulls on modifications: carry forward from parent award
    - Dollar value nulls: flag for review
    """
    # Fill UEI from DUNS for pre-2022 records
    df = df.withColumn(
        "recipient_uei",
        F.coalesce(
            F.when(
                F.col("recipient_uei").isNotNull() & (F.trim(F.col("recipient_uei")) != ""),
                F.col("recipient_uei")
            ),
            F.col("recipient_duns_number")
        )
    )

    # Forward-fill NAICS from parent award on modification records
    # Window: partition by award key, order by action date ascending
    naics_fill_window = Window.partitionBy("contract_award_unique_key").orderBy(
        F.asc("action_date")
    ).rowsBetween(Window.unboundedPreceding, 0)

    df = df.withColumn(
        "naics_code",
        F.last(F.col("naics_code"), ignorenulls=True).over(naics_fill_window)
    )

    # Flag records with null dollar values
    df = df.withColumn(
        "data_quality_flag",
        F.when(
            F.col("federal_action_obligation").isNull(),
            F.lit("MISSING_OBLIGATION_VALUE")
        ).otherwise(F.lit(None).cast(StringType()))
    )

    return df


# ---------------------------------------------------------------------------
# Step 3: Deduplication via window function
# ---------------------------------------------------------------------------

def deduplicate(df: DataFrame) -> DataFrame:
    """
    Remove duplicates on the natural primary key (award key + modification number),
    retaining the most recently modified record.

    Window function approach is preferred over DataFrame.dropDuplicates() because:
    1. It gives us control over which record to keep (most recent)
    2. It is transparent — we can inspect the row_rank column before filtering
    3. It preserves all records in the intermediate output for auditing
    """
    dedup_window = Window.partitionBy(
        "contract_award_unique_key", "modification_number"
    ).orderBy(F.desc("last_modified_date"))

    df_ranked = df.withColumn("_row_rank", F.row_number().over(dedup_window))

    df_deduped = df_ranked.filter(F.col("_row_rank") == 1).drop("_row_rank")

    return df_deduped


# ---------------------------------------------------------------------------
# Step 4: Type coercion
# ---------------------------------------------------------------------------

def coerce_types(df: DataFrame) -> DataFrame:
    """
    Coerce all dollar and date columns from string to their proper types.

    Dollar coercion:
    - Strips $ and commas
    - Handles accounting negatives: (100.00) → -100.00
    - Casts to DoubleType

    Date coercion:
    - Handles the most common government date formats
    - Fails gracefully to null on unparseable values
    """
    # Dollar fields: strip formatting characters and cast to double
    dollar_cols = [
        "federal_action_obligation",
        "base_and_all_options_value",
        "base_exercised_options_value",
    ]

    for col in dollar_cols:
        if col in [f.name for f in df.schema.fields]:
            df = df.withColumn(
                col,
                F.regexp_replace(
                    F.regexp_replace(
                        F.regexp_replace(F.col(col), r"[$,\s]", ""),
                        r"^\((.+)\)$", "-$1"   # (100.00) → -100.00
                    ),
                    r"^-$", ""                  # lone dash → null
                ).cast(DoubleType())
            )

    # Date fields
    date_cols = [
        "action_date",
        "period_of_performance_start_date",
        "period_of_performance_current_end_date",
    ]
    for col in date_cols:
        if col in [f.name for f in df.schema.fields]:
            df = df.withColumn(
                col,
                F.coalesce(
                    F.to_date(F.col(col), "yyyy-MM-dd"),
                    F.to_date(F.col(col), "MM/dd/yyyy"),
                    F.to_date(F.col(col), "yyyyMMdd"),
                )
            )

    if "last_modified_date" in [f.name for f in df.schema.fields]:
        df = df.withColumn(
            "last_modified_date",
            F.coalesce(
                F.to_timestamp(F.col("last_modified_date"), "yyyy-MM-dd'T'HH:mm:ss"),
                F.to_timestamp(F.col("last_modified_date"), "yyyy-MM-dd HH:mm:ss"),
                F.to_date(F.col("last_modified_date"), "yyyy-MM-dd").cast(TimestampType()),
            )
        )

    return df


# ---------------------------------------------------------------------------
# Step 5: Government identifier standardization
# ---------------------------------------------------------------------------

def standardize_naics(spark: SparkSession, df: DataFrame) -> DataFrame:
    """
    Standardize NAICS codes and join sector descriptions via a broadcast join.
    Broadcast join is appropriate here because the lookup table is small (~25 rows).
    """
    # Normalize NAICS: strip non-numeric chars, zero-pad to 6 digits
    df = df.withColumn(
        "naics_code",
        F.lpad(
            F.regexp_replace(F.col("naics_code").cast(StringType()), r"[^0-9]", ""),
            6, "0"
        )
    )

    # Flag invalid NAICS codes (not exactly 6 digits after normalization)
    df = df.withColumn(
        "naics_code",
        F.when(
            F.col("naics_code").rlike(r"^\d{6}$"),
            F.col("naics_code")
        ).otherwise(F.lit(None))
    )

    # Extract 2-digit sector code
    df = df.withColumn("naics_sector_code", F.col("naics_code").substr(1, 2))

    # Build lookup table and broadcast-join for sector descriptions
    naics_lookup = spark.createDataFrame(NAICS_SECTOR_DATA, schema=NAICS_SECTOR_SCHEMA)
    df = df.join(
        F.broadcast(naics_lookup),
        on="naics_sector_code",
        how="left"
    )

    return df


def standardize_identifiers(df: DataFrame) -> DataFrame:
    """
    Standardize CAGE codes, UEI, and DUNS identifiers.
    """
    # CAGE: uppercase, 5 alphanumeric characters
    df = df.withColumn(
        "cage_code",
        F.upper(F.trim(F.regexp_replace(F.col("cage_code"), r"[^A-Za-z0-9]", "")))
    )

    # UEI: uppercase, 12 alphanumeric characters
    df = df.withColumn(
        "recipient_uei",
        F.upper(F.trim(F.regexp_replace(F.col("recipient_uei"), r"[^A-Za-z0-9]", "")))
    )

    # DUNS: 9 digits, zero-padded
    df = df.withColumn(
        "recipient_duns_number",
        F.lpad(
            F.regexp_replace(F.col("recipient_duns_number"), r"[^0-9]", ""),
            9, "0"
        )
    )

    return df


# ---------------------------------------------------------------------------
# Step 6: Vendor name normalization
# ---------------------------------------------------------------------------

def normalize_vendor_names(df: DataFrame) -> DataFrame:
    """
    Normalize vendor names for deduplication and consistent grouping.
    Creates a `vendor_name_normalized` column — the original field is preserved
    for display purposes.

    PySpark regex operations are applied as a chain of withColumn transforms.
    """
    # Legal suffixes to strip (space-separated pattern for use in regexp_replace)
    legal_suffix_pattern = (
        r"(?i)\b(INC|INCORPORATED|CORP|CORPORATION|LLC|LLP|LP|"
        r"CO|COMPANY|LTD|LIMITED|PLC|GROUP|HOLDINGS|HOLDING|"
        r"TECHNOLOGIES|TECHNOLOGY|SERVICES|SOLUTIONS|SYSTEMS|"
        r"INTERNATIONAL|INTL|GLOBAL|ASSOCIATES|PARTNERS|"
        r"ENTERPRISES|VENTURES|INDUSTRIES|CONSULTING)\.?\b"
    )

    df = df.withColumn(
        "vendor_name_normalized",
        F.upper(F.trim(F.col("awardee_or_recipient_legal_entity_name")))
    )
    df = df.withColumn(
        "vendor_name_normalized",
        F.regexp_replace(F.col("vendor_name_normalized"), legal_suffix_pattern, " ")
    )
    df = df.withColumn(
        "vendor_name_normalized",
        F.regexp_replace(F.col("vendor_name_normalized"), r"[,\.&/\\']", " ")
    )
    df = df.withColumn(
        "vendor_name_normalized",
        F.trim(F.regexp_replace(F.col("vendor_name_normalized"), r"\s+", " "))
    )

    return df


# ---------------------------------------------------------------------------
# Step 7: Data quality metrics (Spark-native)
# ---------------------------------------------------------------------------

def compute_spark_quality_metrics(df: DataFrame) -> dict:
    """
    Compute quality metrics using Spark aggregations (distributed).
    Returns a flat dict suitable for MLflow logging.

    Note: This function calls df.count() and multiple aggregations. Cache
    the DataFrame before calling this if you plan to reuse it after.
    """
    total_rows = df.count()

    # Completeness: % non-null for critical columns
    critical_cols = [
        "contract_award_unique_key", "recipient_uei",
        "federal_action_obligation", "action_date", "naics_code"
    ]
    agg_exprs = []
    for col in critical_cols:
        if col in [f.name for f in df.schema.fields]:
            agg_exprs.append(
                (F.count(F.col(col)) / total_rows * 100).alias(f"completeness_{col}")
            )

    # Validity: NAICS format
    if "naics_code" in [f.name for f in df.schema.fields]:
        agg_exprs.append(
            (F.sum(
                F.when(F.col("naics_code").rlike(r"^\d{6}$"), 1).otherwise(0)
            ) / total_rows * 100).alias("validity_naics_6digit_pct")
        )

    # Validity: UEI format
    if "recipient_uei" in [f.name for f in df.schema.fields]:
        agg_exprs.append(
            (F.sum(
                F.when(
                    F.col("recipient_uei").rlike(r"^[A-Z0-9]{12}$"), 1
                ).otherwise(0)
            ) / total_rows * 100).alias("validity_uei_format_pct")
        )

    # Uniqueness: primary key duplicates
    agg_exprs.append(
        (total_rows - F.countDistinct(
            "contract_award_unique_key", "modification_number"
        )).alias("pk_duplicate_count")
    )

    if not agg_exprs:
        return {"total_rows": total_rows}

    results_row = df.agg(*agg_exprs).collect()[0]
    metrics = {"total_rows": total_rows}
    metrics.update(results_row.asDict())

    # Round percentages
    for k, v in metrics.items():
        if isinstance(v, float):
            metrics[k] = round(v, 2)

    return metrics


def log_metrics_to_mlflow(metrics: dict, run_name: str = "procurement_data_quality") -> None:
    """
    Log quality metrics to MLflow experiment tracking.
    On Databricks, MLflow is pre-configured — no setup needed.
    Metrics appear in the MLflow Experiments UI and can be compared across runs.
    """
    with mlflow.start_run(run_name=run_name):
        # Log scalar metrics
        for key, value in metrics.items():
            if isinstance(value, (int, float)):
                mlflow.log_metric(key, value)
            else:
                mlflow.log_param(key, str(value))

        print(f"Quality metrics logged to MLflow run: {run_name}")


# ---------------------------------------------------------------------------
# Step 8: Write to Delta Lake (Silver tier)
# ---------------------------------------------------------------------------

def write_to_delta_silver(df: DataFrame, output_table: str) -> None:
    """
    Write cleaned DataFrame to Unity Catalog Delta table (Silver tier).

    Mode is 'overwrite' for full reloads. For incremental append scenarios,
    use Delta Lake MERGE (upsert) instead.

    overwriteSchema=true allows schema evolution as new columns are added
    to the cleaning pipeline.
    """
    (df
        .write
        .format("delta")
        .mode("overwrite")
        .option("overwriteSchema", "true")
        # Partition by action_date for efficient date-range queries
        .partitionBy("naics_sector_code")
        .saveAsTable(output_table)
    )
    print(f"Cleaned data written to Delta table: {output_table}")


# ---------------------------------------------------------------------------
# Master pipeline
# ---------------------------------------------------------------------------

def run_cleaning_pipeline(
    spark: SparkSession,
    source_table: str,
    output_table: str,
) -> dict:
    """
    End-to-end PySpark cleaning pipeline for USASpending.gov procurement data.

    Args:
        spark: Active SparkSession (pre-existing on Databricks)
        source_table: Unity Catalog path to raw Bronze table
        output_table: Unity Catalog path for Silver output table

    Returns:
        Quality metrics dictionary
    """
    print(f"Pipeline start: {source_table} → {output_table}")

    # Load
    df = load_from_unity_catalog(spark, source_table)

    # Handle nulls
    df = handle_nulls(df)

    # Coerce types before dedup (need dates for window ordering)
    df = coerce_types(df)

    # Deduplicate
    df = deduplicate(df)

    # Standardize identifiers and codes
    df = standardize_identifiers(df)
    df = standardize_naics(spark, df)
    df = normalize_vendor_names(df)

    # Cache before metrics computation (avoids recomputing the full pipeline twice)
    df.cache()

    # Compute and log quality metrics
    metrics = compute_spark_quality_metrics(df)
    log_metrics_to_mlflow(metrics, run_name=f"quality_check_{output_table.split('.')[-1]}")

    # Write Silver output
    write_to_delta_silver(df, output_table)

    df.unpersist()

    print("Pipeline complete.")
    print(f"Metrics: {metrics}")

    return metrics


# ---------------------------------------------------------------------------
# Local testing entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    """
    Local test run using a minimal SparkSession.
    On Databricks, this __main__ block is not needed — run the notebook cells
    that call run_cleaning_pipeline() directly.
    """
    spark = (SparkSession.builder
        .appName("procurement_cleaning_test")
        .master("local[*]")
        .config("spark.sql.shuffle.partitions", "4")  # Low for local testing
        .getOrCreate()
    )

    spark.sparkContext.setLogLevel("WARN")

    # Create a small test DataFrame (mimics the USASpending schema)
    test_data = [
        ("AWARD_000001", "0", "Lockheed Martin Corp", "1BEL1", "LKA2B3C4D5E6",
         "$1,234,567.89", "541512", "2024-01-15", "2024-01-15T10:30:00", "DEPT OF DEFENSE"),
        ("AWARD_000001", "P00001", "Lockheed Martin Corp", "1BEL1", "LKA2B3C4D5E6",
         "$250,000.00", "541512", "2024-03-20", "2024-03-20T14:00:00", "DEPT OF DEFENSE"),
        ("AWARD_000001", "0", "Lockheed Martin Corporation", "1BEL1", "LKA2B3C4D5E6",
         "$1,234,567.89", "541512", "2024-01-14", "2024-01-14T09:00:00", "DEPT OF DEFENSE"),  # Duplicate
        ("AWARD_000002", "0", "Raytheon Technologies Inc", "47272", None,
         "(50000.00)", "336411", "2024-02-01", "2024-02-01T11:00:00", "DON"),  # Accounting negative
        ("AWARD_000003", "0", "General Dynamics Corp", "ABCD1", "ZXW9Y8X7W6V5",
         None, "N/A", "2024-03-10", "2024-03-10T16:00:00", "USMC"),  # Null dollar, bad NAICS
    ]

    schema = StructType([
        StructField("contract_award_unique_key", StringType()),
        StructField("modification_number", StringType()),
        StructField("awardee_or_recipient_legal_entity_name", StringType()),
        StructField("cage_code", StringType()),
        StructField("recipient_uei", StringType()),
        StructField("federal_action_obligation", StringType()),
        StructField("naics_code", StringType()),
        StructField("action_date", StringType()),
        StructField("last_modified_date", StringType()),
        StructField("awarding_agency_name", StringType()),
    ])

    df_raw = spark.createDataFrame(test_data, schema=schema)
    df_raw = df_raw.withColumn("recipient_duns_number", F.lit(None).cast(StringType()))

    print("=== Raw Data ===")
    df_raw.show(truncate=False)

    # Run individual steps (not the full pipeline, since that requires Unity Catalog)
    df = handle_nulls(df_raw)
    df = coerce_types(df)
    df = deduplicate(df)
    df = standardize_identifiers(df)
    df = standardize_naics(spark, df)
    df = normalize_vendor_names(df)

    print("=== Cleaned Data ===")
    df.select(
        "contract_award_unique_key",
        "modification_number",
        "vendor_name_normalized",
        "federal_action_obligation",
        "naics_code",
        "naics_sector_desc",
        "cage_code",
        "recipient_uei",
        "action_date",
        "data_quality_flag"
    ).show(truncate=False)

    spark.stop()
