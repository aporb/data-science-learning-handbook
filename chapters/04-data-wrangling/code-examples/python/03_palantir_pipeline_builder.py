"""
Chapter 04 — Data Wrangling and Cleaning
Example 03: Palantir Foundry — Pipeline Builder vs. Code Repositories

Platform: Palantir Foundry (FedRAMP High / IL4 / IL5)
Public documentation: https://www.palantir.com/docs/foundry/

This file demonstrates both approaches for the same cleaning task:
1. What Pipeline Builder does automatically (annotated pseudocode showing the
   visual node operations and the Spark code Foundry generates from them)
2. The Code Repository transform equivalent (actual PySpark using Foundry's
   @transform_df decorator pattern)

Use Case: Standardizing vendor entity data before Ontology Object Type creation.
In Foundry, cleaned data often becomes the backing dataset for an Object Type
(e.g., a "Vendor" object). The Ontology then enables analysts to navigate from
any contract to its associated vendor, past performance, and related awards —
without writing join queries.

IMPORTANT: Foundry's Code Repositories use a specific `transforms` package
(@transform_df, @transform, Input, Output) that is not pip-installable outside
Foundry. The code below is written for a Foundry environment. The comments
explain each decorator and its behavior for readers learning the platform.
"""

# =============================================================================
# PART 1: PIPELINE BUILDER — What the visual interface generates
# =============================================================================
#
# Pipeline Builder is a drag-and-drop interface in Foundry for building data
# transforms without code. Below is a description of the node graph you would
# build for vendor name standardization, followed by the PySpark Foundry
# generates internally when you run it.
#
# Pipeline Builder node graph for vendor standardization:
#
#   [Input: raw_vendor_entities]
#       |
#       v
#   [Filter node]
#       - Remove records where "uei" is blank
#       - Remove records where "cage_code" length < 5
#       |
#       v
#   [Rename node]
#       - "entity_name" → "vendor_name_raw"
#       - "unique_entity_id" → "recipient_uei"
#       |
#       v
#   [Cast node]
#       - "cage_code": string → string (trim and upper)
#       - "registration_date": string → date
#       |
#       v
#   [Expression node — "Upper and trim vendor name"]
#       - vendor_name_upper = UPPER(TRIM(vendor_name_raw))
#       |
#       v
#   [Output: silver_vendor_entities]
#
# The Foundry Pipeline Builder generates something equivalent to this
# PySpark internally (you can view it in the "Code Preview" pane):
#
#   from pyspark.sql import functions as F
#
#   df = input_df
#   df = df.filter(F.col("uei").isNotNull() & (F.length(F.trim(F.col("uei"))) > 0))
#   df = df.filter(F.length(F.trim(F.col("cage_code"))) >= 5)
#   df = df.withColumnRenamed("entity_name", "vendor_name_raw")
#   df = df.withColumnRenamed("unique_entity_id", "recipient_uei")
#   df = df.withColumn("cage_code", F.upper(F.trim(F.col("cage_code"))))
#   df = df.withColumn("registration_date", F.to_date(F.col("registration_date")))
#   df = df.withColumn("vendor_name_upper", F.upper(F.trim(F.col("vendor_name_raw"))))
#
# When to use Pipeline Builder:
#   - Standard operations: filter, rename, cast, simple expressions
#   - Your business owner or data steward will maintain this pipeline
#   - You want visual lineage that non-engineers can understand
#   - You're in early exploration mode and want fast iteration
#
# When NOT to use Pipeline Builder:
#   - You need conditional logic more complex than a simple CASE WHEN
#   - You're calling Python UDFs, invoking ML models, or using external libraries
#   - You need unit tests on transform logic
#   - The pipeline has edge cases (e.g., the NAICS/DUNS transition logic in Example 01)
#     that require careful, reviewable code


# =============================================================================
# PART 2: CODE REPOSITORY TRANSFORMS — Full programmatic control
# =============================================================================
#
# Code Repositories in Foundry use Git-backed Python environments.
# Transforms are defined as Python functions decorated with @transform_df
# or @transform (for lower-level control).
#
# The `transforms` package provides:
#   - @transform_df: Simplest pattern. Input → DataFrame → Output.
#   - @transform: Lower-level. Access input/output datasets as objects.
#   - Input("rid://...") or Input("dataset_path"): Dataset reference
#   - Output("rid://...") or Output("dataset_path"): Output dataset
#
# Functions decorated with @transform_df receive PySpark DataFrames and must
# return a PySpark DataFrame. Foundry handles execution, scheduling, and lineage.

import re
from pyspark.sql import DataFrame
from pyspark.sql import functions as F
from pyspark.sql.types import StringType, DateType

# In a Foundry Code Repository, these imports come from the `transforms` package:
# from transforms.api import transform_df, Input, Output, configure
#
# For this example file (outside Foundry), we define stub decorators so the
# code is readable and understandable without a live Foundry connection.

def _stub_decorator(*args, **kwargs):
    """Stub for Foundry's @transform_df decorator — used for documentation only."""
    def decorator(fn):
        return fn
    return decorator

transform_df = _stub_decorator
Input = str      # In Foundry: Input("dataset/path") — dataset reference
Output = str     # In Foundry: Output("dataset/path") — output reference


# ---------------------------------------------------------------------------
# Transform 1: Standardize vendor entity records from SAM.gov extract
# ---------------------------------------------------------------------------
#
# In production Foundry code, this would look like:
#
#   @transform_df(
#       Output("/procurement/silver/vendor_entities_clean"),
#       source=Input("/procurement/bronze/sam_gov_entity_extract"),
#   )
#   def standardize_vendor_entities(source: DataFrame) -> DataFrame:
#       ...

def standardize_vendor_entities(source: DataFrame) -> DataFrame:
    """
    Foundry Code Repository transform: standardize vendor entity records.

    Input dataset: SAM.gov entity extract (Bronze tier)
    Output dataset: Vendor entities clean (Silver tier)

    This transform backs the "Vendor" Object Type in the Ontology.
    The Ontology Object Type definition references the UEI as its primary key.
    """

    # Legal suffix pattern for vendor name normalization
    legal_suffix_pattern = (
        r"(?i)\b(INC|INCORPORATED|CORP|CORPORATION|LLC|LLP|LP|"
        r"CO|COMPANY|LTD|LIMITED|PLC|GROUP|HOLDINGS|HOLDING|"
        r"TECHNOLOGIES|TECHNOLOGY|SERVICES|SOLUTIONS|SYSTEMS|"
        r"INTERNATIONAL|INTL|GLOBAL|ASSOCIATES|PARTNERS|"
        r"ENTERPRISES|VENTURES|INDUSTRIES|CONSULTING)\.?\b"
    )

    df = source

    # Step 1: Standardize UEI (12-character alphanumeric, SAM.gov format)
    df = df.withColumn(
        "recipient_uei",
        F.upper(F.trim(F.regexp_replace(F.col("uei"), r"[^A-Za-z0-9]", "")))
    )

    # Step 2: Standardize CAGE code (5-character alphanumeric)
    df = df.withColumn(
        "cage_code",
        F.upper(F.trim(F.regexp_replace(F.col("cage_code"), r"[^A-Za-z0-9]", "")))
    )

    # Step 3: Normalize entity name for matching
    # Preserve original name in vendor_name_display; create normalized key
    df = df.withColumnRenamed("legal_business_name", "vendor_name_display")
    df = df.withColumn(
        "vendor_name_normalized",
        F.upper(F.trim(F.col("vendor_name_display")))
    )
    df = df.withColumn(
        "vendor_name_normalized",
        F.regexp_replace(F.col("vendor_name_normalized"), legal_suffix_pattern, " ")
    )
    df = df.withColumn(
        "vendor_name_normalized",
        F.trim(F.regexp_replace(
            F.regexp_replace(F.col("vendor_name_normalized"), r"[,\.&/\\']", " "),
            r"\s+", " "
        ))
    )

    # Step 4: Parse registration and expiration dates
    df = df.withColumn(
        "registration_date",
        F.to_date(F.col("registration_date"), "yyyy-MM-dd")
    )
    df = df.withColumn(
        "expiration_date",
        F.to_date(F.col("expiration_date"), "yyyy-MM-dd")
    )

    # Step 5: Derive a "registration_active" flag
    df = df.withColumn(
        "registration_active",
        F.col("expiration_date") > F.current_date()
    )

    # Step 6: Keep only records with valid UEI (drop records that can't be keyed)
    df = df.filter(
        F.col("recipient_uei").rlike(r"^[A-Z0-9]{12}$")
    )

    # Step 7: Select final output columns (what the Ontology Object Type will use)
    df = df.select(
        "recipient_uei",          # Primary key for Vendor Object Type
        "cage_code",              # Secondary identifier
        "vendor_name_display",    # Human-readable name
        "vendor_name_normalized", # Normalization key for dedup and grouping
        "registration_date",
        "expiration_date",
        "registration_active",
        "physical_address_state",
        "business_type_desc",
        "naics_codes_list",       # List of NAICS codes the vendor is registered under
        "socioeconomic_categories",
    )

    return df


# ---------------------------------------------------------------------------
# Transform 2: Join contracts to vendor entities (Ontology backing dataset)
# ---------------------------------------------------------------------------
#
# In production Foundry code:
#
#   @transform_df(
#       Output("/procurement/silver/contracts_with_vendor_detail"),
#       contracts=Input("/procurement/silver/usaspending_fy2024_clean"),
#       vendors=Input("/procurement/silver/vendor_entities_clean"),
#   )
#   def enrich_contracts_with_vendor(contracts: DataFrame, vendors: DataFrame) -> DataFrame:
#       ...

def enrich_contracts_with_vendor(contracts: DataFrame, vendors: DataFrame) -> DataFrame:
    """
    Foundry Code Repository transform: enrich contract records with vendor detail.

    This creates the enriched contract dataset that backs the contract-to-vendor
    link in the Foundry Ontology. After this transform runs, analysts using
    Object Explorer can navigate from any contract directly to the associated
    Vendor object and see all its properties — without writing a join.

    Note on Foundry Ontology terminology:
    - Object Type: schema for a real-world entity (Vendor, Contract, Agency)
    - Link Type: a defined relationship between Object Types
    - This transform backs the "Contract" Object Type's link to "Vendor"
    """
    # Select only the vendor fields we want to carry into the contract dataset
    vendor_cols = vendors.select(
        F.col("recipient_uei"),
        F.col("vendor_name_normalized"),
        F.col("registration_active"),
        F.col("business_type_desc"),
        F.col("socioeconomic_categories"),
    )

    # Left join — keep all contract records, add vendor detail where available
    df = contracts.join(
        F.broadcast(vendor_cols),   # Broadcast hint: vendor table is small relative to contracts
        on="recipient_uei",
        how="left"
    )

    # Flag contracts where vendor could not be matched to SAM.gov entity
    df = df.withColumn(
        "vendor_sam_match",
        F.when(F.col("business_type_desc").isNotNull(), True).otherwise(False)
    )

    return df


# ---------------------------------------------------------------------------
# Transform 3: Data quality check transform
# ---------------------------------------------------------------------------
#
# In production Foundry code:
#
#   @transform_df(
#       Output("/procurement/quality/contracts_quality_report"),
#       contracts=Input("/procurement/silver/usaspending_fy2024_clean"),
#   )
#   def generate_quality_report(contracts: DataFrame) -> DataFrame:
#       ...

def generate_quality_report(contracts: DataFrame) -> DataFrame:
    """
    Foundry Code Repository transform: generate a data quality report.

    Output is a small summary DataFrame (one row per quality dimension).
    In Foundry, this output dataset can back a Workshop dashboard that
    displays current data quality metrics to the data steward team.

    This keeps quality monitoring visible to non-technical stakeholders
    without them needing to run notebooks or query tables directly.
    """
    total = contracts.count()

    quality_checks = [
        # (check_name, pass_count_expression)
        ("completeness_contract_key",
            contracts.filter(F.col("contract_award_unique_key").isNotNull()).count()),
        ("completeness_uei",
            contracts.filter(F.col("recipient_uei").isNotNull()).count()),
        ("completeness_obligation",
            contracts.filter(F.col("federal_action_obligation").isNotNull()).count()),
        ("validity_naics_6digit",
            contracts.filter(F.col("naics_code").rlike(r"^\d{6}$")).count()),
        ("validity_uei_format",
            contracts.filter(F.col("recipient_uei").rlike(r"^[A-Z0-9]{12}$")).count()),
    ]

    rows = []
    for check_name, pass_count in quality_checks:
        rows.append({
            "check_name": check_name,
            "total_records": total,
            "passing_records": pass_count,
            "pass_rate_pct": round(pass_count / total * 100, 2) if total > 0 else 0.0,
            "status": "PASS" if pass_count / total >= 0.95 else "FAIL",
        })

    spark = contracts.sparkSession
    return spark.createDataFrame(rows)


# ---------------------------------------------------------------------------
# Foundry-specific patterns: using AIP Logic within a pipeline
# ---------------------------------------------------------------------------
#
# As of 2025, Palantir Pipeline Builder includes a "Use LLM" node that can
# invoke an LLM directly within a transform pipeline. This is useful for:
#   - Extracting structured information from unstructured text fields
#     (e.g., contract descriptions, performance narratives)
#   - Classifying records where rule-based logic is insufficient
#   - Standardizing free-text fields that are too variable for regex
#
# The "Use LLM" node in Pipeline Builder calls AIP Logic functions under the
# hood. You configure the LLM prompt directly in the node's parameter panel.
#
# For Code Repositories, you would invoke AIP Logic via Foundry Functions
# (TypeScript-authored) or through AIP's Python SDK.
#
# Example scenario: classifying unstructured contract descriptions into
# standardized procurement categories. This would look like:
#
#   # In Pipeline Builder:
#   # Node: "Use LLM"
#   # Input column: "contract_description_text"
#   # Prompt template:
#   #   "Classify the following government contract description into one of these
#   #    categories: [IT Services, Professional Services, Construction,
#   #    Equipment/Supplies, Research & Development, Other].
#   #    Description: {contract_description_text}
#   #    Return only the category name."
#   # Output column: "contract_category_llm"
#
# This is particularly useful for contracts with PSC (Product/Service Code)
# values that are ambiguous or missing, where rule-based NAICS mapping fails.
# The LLM inference runs within Foundry's accredited boundary — the data
# never leaves the IL4/IL5 environment.


# ---------------------------------------------------------------------------
# Platform decision guide
# ---------------------------------------------------------------------------
#
# Use this to decide Pipeline Builder vs. Code Repositories for a given task:
#
# +-----------------------------------------------------------------------+
# | Task                                   | Recommended Approach         |
# +-----------------------------------------------------------------------+
# | Filter rows by column value            | Pipeline Builder             |
# | Rename columns                         | Pipeline Builder             |
# | Cast column types                      | Pipeline Builder             |
# | Join two datasets on a single key      | Pipeline Builder             |
# | UPPER() / TRIM() normalization         | Pipeline Builder             |
# | Classify text with an LLM             | Pipeline Builder (Use LLM)   |
# | Complex conditional logic (DUNS/UEI   | Code Repository              |
# |   transition rules, multi-step fills)  |                              |
# | Custom Python UDFs                     | Code Repository              |
# | Unit-tested transform logic            | Code Repository              |
# | ML inference inside a pipeline        | Code Repository              |
# | Building Ontology Object Types        | Either (backing dataset)     |
# +-----------------------------------------------------------------------+


# ---------------------------------------------------------------------------
# Local demonstration (runs without Foundry)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    """
    Demonstrate the transform logic locally using PySpark.
    In production Foundry, these functions are invoked by the @transform_df
    decorator system — not by a __main__ block.
    """
    from pyspark.sql import SparkSession

    spark = (SparkSession.builder
        .appName("foundry_transforms_demo")
        .master("local[*]")
        .config("spark.sql.shuffle.partitions", "4")
        .getOrCreate()
    )
    spark.sparkContext.setLogLevel("WARN")

    # Simulate a SAM.gov entity extract
    sam_data = [
        ("LKA2B3C4D5E6", "1BEL1", "Lockheed Martin Corporation",
         "2018-03-01", "2025-03-01", "VA", "Large Business", "N/A"),
        ("RTN4X5Y6Z7W8", "47272", "Raytheon Technologies Inc",
         "2019-06-15", "2025-06-15", "MA", "Large Business", "N/A"),
        ("GD9A8B7C6D5E", "ABCD1", "General Dynamics Corp",
         "2017-01-10", "2024-12-31", "VA", "Large Business", "N/A"),
        ("INVALID_UEI",  "XXXXX", "Bad Record Inc",
         "2020-01-01", "2023-01-01", "DC", "Small Business", "WOSB"),
    ]

    from pyspark.sql.types import StructType, StructField

    sam_schema = StructType([
        StructField("uei", StringType()),
        StructField("cage_code", StringType()),
        StructField("legal_business_name", StringType()),
        StructField("registration_date", StringType()),
        StructField("expiration_date", StringType()),
        StructField("physical_address_state", StringType()),
        StructField("business_type_desc", StringType()),
        StructField("socioeconomic_categories", StringType()),
    ])
    sam_schema_full = sam_schema.add("naics_codes_list", StringType())

    sam_df = spark.createDataFrame(
        [row + ("541512,541519",) for row in sam_data],
        schema=sam_schema_full
    )

    print("=== SAM.gov Entity Extract (Raw) ===")
    sam_df.show(truncate=False)

    cleaned_vendors = standardize_vendor_entities(sam_df)
    print("=== Cleaned Vendor Entities ===")
    cleaned_vendors.show(truncate=False)

    # Quality report demonstration
    # (Uses a minimal contracts DataFrame for illustration)
    contracts_data = [
        ("AWARD_001", "0", "LKA2B3C4D5E6", 1_200_000.0, "541512"),
        ("AWARD_002", "0", "RTN4X5Y6Z7W8", 3_400_000.0, "336411"),
        ("AWARD_003", "0", None,            500_000.0,  "54"),      # Bad NAICS, null UEI
        ("AWARD_004", "0", "GD9A8B7C6D5E", None,        "541330"),  # Null dollar
    ]

    contracts_schema = StructType([
        StructField("contract_award_unique_key", StringType()),
        StructField("modification_number", StringType()),
        StructField("recipient_uei", StringType()),
        StructField("federal_action_obligation", StringType()),
        StructField("naics_code", StringType()),
    ])

    # Cast obligation to float for the quality check
    contracts_df = spark.createDataFrame(
        [(a, m, u, str(o) if o is not None else None, n) for a, m, u, o, n in contracts_data],
        schema=contracts_schema
    ).withColumn("federal_action_obligation", F.col("federal_action_obligation").cast("double"))

    quality_report = generate_quality_report(contracts_df)
    print("=== Data Quality Report ===")
    quality_report.show(truncate=False)

    spark.stop()
