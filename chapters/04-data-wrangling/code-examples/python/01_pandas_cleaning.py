"""
Chapter 04 — Data Wrangling and Cleaning
Example 01: Pandas-based cleaning pipeline for federal procurement data

Target dataset: USASpending.gov procurement obligations export (CSV)
Platform: Any Python environment — local, Databricks notebook, Advana, Jupiter
Dependencies: pandas, numpy, python-dateutil

Usage:
    python 01_pandas_cleaning.py

Or import into a notebook:
    from 01_pandas_cleaning import clean_procurement_dataframe, compute_quality_metrics
"""

import re
import hashlib
import hmac
import unicodedata
import logging
from pathlib import Path
from datetime import datetime

import numpy as np
import pandas as pd

logging.basicConfig(level=logging.INFO, format="%(asctime)s  %(levelname)s  %(message)s")
log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Column names as they appear in the USASpending.gov bulk download format
RAW_DOLLAR_COLS = [
    "federal_action_obligation",
    "base_and_all_options_value",
    "base_exercised_options_value",
    "total_outlayed_amount",
]

RAW_DATE_COLS = [
    "action_date",
    "period_of_performance_start_date",
    "period_of_performance_current_end_date",
    "last_modified_date",
]

PRIMARY_KEY_COLS = ["contract_award_unique_key", "modification_number"]

# Minimum acceptable completeness for critical fields (as a decimal)
QUALITY_THRESHOLDS = {
    "contract_award_unique_key": 1.00,   # Must be 100% present — it's the PK
    "recipient_uei": 0.90,               # Allow 10% for legacy pre-2022 DUNS-only records
    "federal_action_obligation": 0.99,
    "action_date": 0.99,
    "naics_code": 0.85,                  # NAICS missing on some modifications
}

NAICS_SECTORS = {
    "11": "Agriculture, Forestry, Fishing, and Hunting",
    "21": "Mining, Quarrying, and Oil and Gas Extraction",
    "22": "Utilities",
    "23": "Construction",
    "31": "Manufacturing",
    "32": "Manufacturing",
    "33": "Manufacturing",
    "42": "Wholesale Trade",
    "44": "Retail Trade",
    "45": "Retail Trade",
    "48": "Transportation and Warehousing",
    "49": "Transportation and Warehousing",
    "51": "Information",
    "52": "Finance and Insurance",
    "53": "Real Estate and Rental and Leasing",
    "54": "Professional, Scientific, and Technical Services",
    "55": "Management of Companies and Enterprises",
    "56": "Administrative and Support and Waste Management",
    "61": "Educational Services",
    "62": "Health Care and Social Assistance",
    "71": "Arts, Entertainment, and Recreation",
    "72": "Accommodation and Food Services",
    "81": "Other Services (except Public Administration)",
    "92": "Public Administration",
}

# Legal entity suffixes that vary across records and should be stripped
# for normalization. Keep the base name for deduplication.
LEGAL_SUFFIXES_PATTERN = (
    r"\b("
    r"INC|INCORPORATED|CORP|CORPORATION|LLC|LLP|LP|"
    r"CO|COMPANY|LTD|LIMITED|PLC|GROUP|HOLDINGS|HOLDING|"
    r"TECHNOLOGIES|TECHNOLOGY|SERVICES|SOLUTIONS|SYSTEMS|"
    r"INTERNATIONAL|INT'L|INTL|GLOBAL|ASSOCIATES|PARTNERS|"
    r"ENTERPRISES|VENTURES|INDUSTRIES|CONSULTING"
    r")\.?\b"
)

# Tokenization key — in production, load this from a secrets manager
# (AWS Secrets Manager, Azure Key Vault, HashiCorp Vault, Databricks secrets)
_TOKENIZATION_KEY = b"replace_with_secret_from_vault_in_production"


# ---------------------------------------------------------------------------
# Step 1: Load and initial inspection
# ---------------------------------------------------------------------------

def load_raw_data(filepath: str) -> pd.DataFrame:
    """
    Load a USASpending.gov CSV export with appropriate dtype hints.
    Forces string types on identifier columns to prevent silent coercion
    (e.g., leading-zero NAICS codes truncated to int).
    """
    string_cols = [
        "contract_award_unique_key",
        "award_id_piid",
        "parent_award_id_piid",
        "naics_code",
        "product_or_service_code",
        "cage_code",
        "recipient_uei",
        "recipient_duns_number",
        "awarding_agency_code",
        "funding_agency_code",
        "modification_number",
    ]

    dtype_hints = {col: str for col in string_cols}

    df = pd.read_csv(
        filepath,
        dtype=dtype_hints,
        low_memory=False,
        na_values=["N/A", "n/a", "null", "NULL", "None", "(none)", ""],
    )

    log.info("Loaded %s rows, %s columns from %s", f"{len(df):,}", len(df.columns), filepath)
    return df


def summarize_nulls(df: pd.DataFrame) -> pd.DataFrame:
    """Print a null-count summary sorted by severity. Returns the summary DataFrame."""
    summary = pd.DataFrame({
        "null_count": df.isnull().sum(),
        "null_pct": (df.isnull().sum() / len(df) * 100).round(2),
        "dtype": df.dtypes,
    }).sort_values("null_pct", ascending=False)

    cols_with_nulls = summary[summary["null_count"] > 0]
    log.info("Columns with nulls:\n%s", cols_with_nulls.to_string())
    return summary


# ---------------------------------------------------------------------------
# Step 2: Null handling — context-aware, not blind dropna
# ---------------------------------------------------------------------------

def handle_nulls(df: pd.DataFrame) -> pd.DataFrame:
    """
    Address nulls with domain knowledge:
    - UEI nulls: fill from legacy DUNS column (pre-April 2022 records)
    - NAICS nulls on modifications: forward-fill from parent award record
    - Dollar value nulls: flag as data quality issue, do not fill
    """
    df = df.copy()

    # Fill UEI from DUNS for pre-2022 records
    if "recipient_uei" in df.columns and "recipient_duns_number" in df.columns:
        filled = df["recipient_uei"].isnull() & df["recipient_duns_number"].notnull()
        df.loc[filled, "recipient_uei"] = df.loc[filled, "recipient_duns_number"]
        log.info("Filled %s UEI nulls from DUNS column", filled.sum())

    # Forward-fill NAICS on modification records (sort by award + date first)
    if all(c in df.columns for c in ["contract_award_unique_key", "action_date", "naics_code"]):
        df = df.sort_values(["contract_award_unique_key", "action_date"])
        before = df["naics_code"].isnull().sum()
        df["naics_code"] = df.groupby("contract_award_unique_key")["naics_code"].ffill()
        after = df["naics_code"].isnull().sum()
        log.info("Forward-filled %s NAICS nulls from parent award", before - after)

    # Flag missing dollar values — do not fill, flag for review
    if "federal_action_obligation" in df.columns:
        null_dollar_mask = df["federal_action_obligation"].isnull()
        if null_dollar_mask.any():
            df.loc[null_dollar_mask, "data_quality_flag"] = "MISSING_OBLIGATION_VALUE"
            log.warning("%s records flagged for missing obligation value", null_dollar_mask.sum())

    return df


# ---------------------------------------------------------------------------
# Step 3: Deduplication
# ---------------------------------------------------------------------------

def deduplicate(df: pd.DataFrame, pk_cols: list = PRIMARY_KEY_COLS) -> pd.DataFrame:
    """
    Remove duplicate records by primary key, keeping the most recently
    modified version. Government exports routinely duplicate records across
    source systems with different timestamps.
    """
    if not all(c in df.columns for c in pk_cols):
        log.warning("Primary key columns %s not all present — skipping dedup", pk_cols)
        return df

    n_before = len(df)
    dups = df.duplicated(subset=pk_cols, keep=False).sum()
    log.info("Duplicate PK records before dedup: %s", f"{dups:,}")

    if "last_modified_date" in df.columns:
        df = (df
            .sort_values("last_modified_date", ascending=False)
            .drop_duplicates(subset=pk_cols, keep="first")
            .reset_index(drop=True)
        )
    else:
        df = df.drop_duplicates(subset=pk_cols, keep="last").reset_index(drop=True)

    n_after = len(df)
    log.info("Dedup: %s → %s rows (removed %s)", f"{n_before:,}", f"{n_after:,}", f"{n_before - n_after:,}")
    return df


# ---------------------------------------------------------------------------
# Step 4: Type coercion
# ---------------------------------------------------------------------------

def clean_dollar_field(series: pd.Series) -> pd.Series:
    """
    Parse a dollar amount field that may contain:
    - Dollar signs and commas: "$1,234,567.89"
    - Accounting negatives: "(1234567.89)"
    - Text nulls already converted: NaN (from na_values in read_csv)
    """
    return (series
        .astype(str)
        .str.replace(r"[$,\s]", "", regex=True)
        .str.replace(r"^\((.+)\)$", r"-\1", regex=True)   # (100) → -100
        .replace({"nan": np.nan, "N/A": np.nan, "": np.nan, "None": np.nan})
        .astype(float)
    )


def safe_parse_date(val) -> pd.Timestamp:
    """Parse a date value tolerantly — returns NaT on parse failure."""
    if pd.isnull(val) or str(val).strip() in ("", "nan", "N/A", "None"):
        return pd.NaT
    try:
        return pd.to_datetime(val, infer_datetime_format=True)
    except Exception:
        return pd.NaT


def coerce_types(df: pd.DataFrame) -> pd.DataFrame:
    """Apply type coercion to dollar, date, and identifier columns."""
    df = df.copy()

    for col in RAW_DOLLAR_COLS:
        if col in df.columns:
            df[col] = clean_dollar_field(df[col])
            log.info("Coerced %s to float", col)

    for col in RAW_DATE_COLS:
        if col in df.columns:
            df[col] = df[col].apply(safe_parse_date)
            log.info("Coerced %s to datetime", col)

    return df


# ---------------------------------------------------------------------------
# Step 5: Government identifier standardization
# ---------------------------------------------------------------------------

def standardize_naics(df: pd.DataFrame) -> pd.DataFrame:
    """
    Standardize NAICS codes to 6-digit zero-padded strings.
    Derive 2-digit sector code and sector description.
    """
    df = df.copy()

    if "naics_code" not in df.columns:
        return df

    # Strip non-numeric characters, zero-pad to 6 digits
    df["naics_code"] = (df["naics_code"]
        .astype(str)
        .str.strip()
        .str.replace(r"[^0-9]", "", regex=True)
        .str.zfill(6)
    )

    # Flag codes that don't look valid after normalization
    invalid_naics = ~df["naics_code"].str.match(r"^\d{6}$")
    df.loc[invalid_naics, "data_quality_flag"] = "INVALID_NAICS_CODE"
    if invalid_naics.sum():
        log.warning("%s records with invalid NAICS codes flagged", invalid_naics.sum())

    # Derive sector fields
    df["naics_sector_code"] = df["naics_code"].str[:2]
    df["naics_sector_desc"] = df["naics_sector_code"].map(NAICS_SECTORS).fillna("Unknown Sector")

    return df


def standardize_cage_and_uei(df: pd.DataFrame) -> pd.DataFrame:
    """
    Standardize CAGE codes and UEI/DUNS identifiers.

    CAGE codes: 5-character alphanumeric, uppercase
    UEI: 12-character alphanumeric, uppercase (post-April 2022)
    DUNS: 9-digit numeric, zero-padded (legacy, pre-April 2022)
    """
    df = df.copy()

    # CAGE: uppercase, strip, remove non-alphanumeric
    if "cage_code" in df.columns:
        df["cage_code"] = (df["cage_code"]
            .astype(str)
            .str.upper()
            .str.strip()
            .str.replace(r"[^A-Z0-9]", "", regex=True)
        )
        # Validate: 5 chars, first char not I/O/Q (reserved by DLA)
        valid_cage = (
            df["cage_code"].str.match(r"^[A-HJ-NP-Z0-9][A-Z0-9]{4}$") |
            (df["cage_code"] == "")  # blank is acceptable (not all records have CAGE)
        )
        df.loc[~valid_cage, "data_quality_flag"] = (
            df.loc[~valid_cage, "data_quality_flag"].fillna("INVALID_CAGE_FORMAT")
        )

    # UEI: uppercase, strip, remove non-alphanumeric
    if "recipient_uei" in df.columns:
        df["recipient_uei"] = (df["recipient_uei"]
            .astype(str)
            .str.upper()
            .str.strip()
            .str.replace(r"[^A-Z0-9]", "", regex=True)
        )
        # Flag post-2022 records with invalid UEI format
        uei_transition_date = pd.Timestamp("2022-04-04")
        if "action_date" in df.columns:
            post_transition = df["action_date"] >= uei_transition_date
            invalid_uei = ~df["recipient_uei"].str.match(r"^[A-Z0-9]{12}$")
            problem_mask = post_transition & invalid_uei & (df["recipient_uei"].str.len() > 0)
            if problem_mask.sum():
                df.loc[problem_mask, "data_quality_flag"] = "INVALID_UEI_POST_TRANSITION"
                log.warning("%s post-2022 records with invalid UEI format", problem_mask.sum())

    # DUNS: 9 digits, zero-padded
    if "recipient_duns_number" in df.columns:
        df["recipient_duns_number"] = (df["recipient_duns_number"]
            .astype(str)
            .str.strip()
            .str.replace(r"[^0-9]", "", regex=True)
            .str.zfill(9)
        )

    return df


# ---------------------------------------------------------------------------
# Step 6: Vendor name normalization
# ---------------------------------------------------------------------------

def normalize_vendor_name(name: str) -> str:
    """
    Normalize a vendor/entity name for deduplication and matching.
    Strips legal suffixes, punctuation, and formatting that varies
    across government data systems.

    Note: This produces a normalized KEY for matching — preserve the
    original `awardee_or_recipient_legal_entity_name` field for display.
    """
    if pd.isnull(name) or str(name).strip() == "":
        return ""

    # Normalize unicode encoding (handles foreign characters in registered names)
    name = unicodedata.normalize("NFKD", str(name))
    name = name.encode("ascii", "ignore").decode("ascii")

    # Uppercase and strip
    name = name.upper().strip()

    # Remove legal suffixes
    name = re.sub(LEGAL_SUFFIXES_PATTERN, " ", name)

    # Remove punctuation (keep internal hyphens — "Booz-Allen" is different from "BoozAllen")
    name = re.sub(r"[,\.\(\)&/\\']", " ", name)

    # Collapse whitespace
    name = re.sub(r"\s+", " ", name).strip()

    return name


def apply_vendor_normalization(df: pd.DataFrame) -> pd.DataFrame:
    """Apply vendor name normalization, creating a new column for the key."""
    df = df.copy()

    if "awardee_or_recipient_legal_entity_name" in df.columns:
        df["vendor_name_normalized"] = df["awardee_or_recipient_legal_entity_name"].apply(
            normalize_vendor_name
        )
        raw_unique = df["awardee_or_recipient_legal_entity_name"].nunique()
        norm_unique = df["vendor_name_normalized"].nunique()
        reduction_pct = (1 - norm_unique / raw_unique) * 100 if raw_unique > 0 else 0
        log.info(
            "Vendor name normalization: %s raw unique → %s normalized unique (%.1f%% reduction)",
            f"{raw_unique:,}", f"{norm_unique:,}", reduction_pct
        )

    return df


# ---------------------------------------------------------------------------
# Step 7: PII detection and masking
# ---------------------------------------------------------------------------

PII_PATTERNS = {
    "SSN": r"\b\d{3}-\d{2}-\d{4}\b",
    "EIN_AS_SSN": r"\b\d{2}-\d{7}\b",  # EINs sometimes formatted as SSNs by mistake
    "phone_number": r"\b\d{3}[-.\s]\d{3}[-.\s]\d{4}\b",
    "email_address": r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b",
}


def scan_for_pii_patterns(df: pd.DataFrame, sample_size: int = 10000) -> pd.DataFrame:
    """
    Scan string columns for PII patterns. Returns a report of findings.
    Always run this on new datasets before loading to shared workspaces.
    """
    results = []
    string_cols = df.select_dtypes(include="object").columns

    for col in string_cols:
        sample = df[col].dropna().astype(str).head(sample_size)
        for label, pattern in PII_PATTERNS.items():
            match_count = sample.str.contains(pattern, regex=True, na=False).sum()
            if match_count > 0:
                results.append({
                    "column": col,
                    "pii_pattern": label,
                    "matches_in_sample": int(match_count),
                    "estimated_total": int(match_count * len(df) / min(sample_size, len(df))),
                })

    report = pd.DataFrame(results)
    if len(report) > 0:
        log.warning("PII patterns found — masking required before shared access:\n%s", report.to_string())
    else:
        log.info("No PII patterns detected in string columns")

    return report


def tokenize_field(value: str, key: bytes = _TOKENIZATION_KEY) -> str:
    """
    Replace a sensitive value with a deterministic HMAC-SHA256 token.
    The token is consistent (same input → same token) but not reversible
    without the key. The key must be stored in a secrets vault, not in code.
    """
    if pd.isnull(value) or str(value).strip() == "":
        return ""
    token = hmac.new(key, str(value).encode("utf-8"), hashlib.sha256).hexdigest()[:16]
    return f"TKN_{token}"


def mask_pii_columns(df: pd.DataFrame, pii_columns: list) -> pd.DataFrame:
    """
    Tokenize known PII columns and remove originals from the working DataFrame.
    Returns the DataFrame with tokenized versions of each PII column.
    """
    df = df.copy()
    for col in pii_columns:
        if col in df.columns:
            df[f"{col}_token"] = df[col].apply(tokenize_field)
            df = df.drop(columns=[col])
            log.info("PII column '%s' tokenized and removed from working DataFrame", col)
    return df


# ---------------------------------------------------------------------------
# Step 8: Data quality metrics
# ---------------------------------------------------------------------------

def compute_quality_metrics(df: pd.DataFrame, table_name: str = "unnamed") -> dict:
    """
    Compute standard data quality metrics for any government dataset.
    Returns a metrics dictionary suitable for logging to MLflow or a
    quality tracking table.
    """
    n_rows = len(df)
    metrics = {
        "table_name": table_name,
        "row_count": n_rows,
        "run_timestamp": datetime.utcnow().isoformat(),
        "completeness": {},
        "uniqueness": {},
        "validity": {},
        "quality_flags": {},
    }

    # Completeness: non-null percentage for critical columns
    for col, threshold in QUALITY_THRESHOLDS.items():
        if col in df.columns:
            pct = round((1 - df[col].isnull().mean()) * 100, 2)
            metrics["completeness"][col] = pct
            if pct / 100 < threshold:
                log.warning(
                    "QUALITY THRESHOLD BREACH: %s completeness %.1f%% < threshold %.0f%%",
                    col, pct, threshold * 100
                )

    # Uniqueness: primary key duplicate rate
    if all(c in df.columns for c in PRIMARY_KEY_COLS):
        dup_pct = round(df.duplicated(subset=PRIMARY_KEY_COLS).mean() * 100, 2)
        metrics["uniqueness"]["primary_key_dup_pct"] = dup_pct
        if dup_pct > 0:
            log.warning("Primary key has %.2f%% duplicates — dedup may have missed records", dup_pct)

    # Validity: NAICS format
    if "naics_code" in df.columns:
        valid_naics_pct = round(df["naics_code"].str.match(r"^\d{6}$").mean() * 100, 2)
        metrics["validity"]["naics_6digit_pct"] = valid_naics_pct

    # Validity: UEI format (for records where UEI should be present)
    if "recipient_uei" in df.columns:
        has_uei = df["recipient_uei"].notnull() & (df["recipient_uei"].str.len() > 0)
        valid_uei = has_uei & df["recipient_uei"].str.match(r"^[A-Z0-9]{12}$")
        if has_uei.sum() > 0:
            valid_uei_pct = round(valid_uei.sum() / has_uei.sum() * 100, 2)
            metrics["validity"]["uei_format_valid_pct"] = valid_uei_pct

    # Quality flag summary
    if "data_quality_flag" in df.columns:
        flag_counts = df["data_quality_flag"].value_counts().to_dict()
        metrics["quality_flags"] = {str(k): int(v) for k, v in flag_counts.items()}

    return metrics


def assert_quality_thresholds(metrics: dict) -> bool:
    """
    Return True if all quality thresholds are met, False otherwise.
    Use this as a pipeline gate — fail the job if data quality is below standard.
    """
    all_pass = True
    for col, threshold in QUALITY_THRESHOLDS.items():
        if col in metrics["completeness"]:
            actual = metrics["completeness"][col] / 100
            if actual < threshold:
                log.error(
                    "QUALITY GATE FAILED: %s completeness %.2f < threshold %.2f",
                    col, actual, threshold
                )
                all_pass = False
    return all_pass


# ---------------------------------------------------------------------------
# Master pipeline function
# ---------------------------------------------------------------------------

def clean_procurement_dataframe(df: pd.DataFrame) -> tuple[pd.DataFrame, dict]:
    """
    Run the full cleaning pipeline on a USASpending.gov procurement DataFrame.

    Returns:
        (cleaned_df, quality_metrics)

    Steps:
        1. Handle nulls with domain context
        2. Deduplicate on primary key
        3. Coerce types (dollars, dates)
        4. Standardize NAICS codes
        5. Standardize CAGE codes and UEI/DUNS identifiers
        6. Normalize vendor names
        7. Scan for PII patterns
        8. Compute quality metrics
    """
    log.info("=== Starting procurement data cleaning pipeline ===")

    df = handle_nulls(df)
    df = deduplicate(df)
    df = coerce_types(df)
    df = standardize_naics(df)
    df = standardize_cage_and_uei(df)
    df = apply_vendor_normalization(df)

    # PII scan — alerts only, does not modify DataFrame
    # If you know your dataset has PII columns, call mask_pii_columns() explicitly:
    # df = mask_pii_columns(df, pii_columns=["ssn", "date_of_birth"])
    pii_report = scan_for_pii_patterns(df)
    if len(pii_report) > 0:
        log.warning(
            "PII patterns detected — call mask_pii_columns() before sharing this DataFrame"
        )

    metrics = compute_quality_metrics(df, table_name="procurement_obligations_cleaned")
    passed = assert_quality_thresholds(metrics)

    log.info("=== Cleaning pipeline complete. Quality gate: %s ===", "PASS" if passed else "FAIL")
    return df, metrics


# ---------------------------------------------------------------------------
# Example run
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    # For testing: generate a small synthetic dataset that mimics USASpending format
    np.random.seed(42)
    n = 1000

    sample_vendors = [
        "Lockheed Martin Corp", "Lockheed Martin Corporation", "LOCKHEED MARTIN",
        "Lockheed-Martin", "LMC", "Raytheon Technologies Inc", "Raytheon Technologies",
        "RAYTHEON CO", "General Dynamics Corp", "General Dynamics Corporation",
    ]

    df_raw = pd.DataFrame({
        "contract_award_unique_key": [f"AWARD_{i:06d}" for i in range(n)],
        "modification_number": np.random.choice(["0", "1", "2", "P00001"], size=n),
        "awardee_or_recipient_legal_entity_name": np.random.choice(sample_vendors, size=n),
        "federal_action_obligation": [f"${np.random.uniform(50_000, 5_000_000):.2f}" for _ in range(n)],
        "base_and_all_options_value": np.random.uniform(100_000, 10_000_000, size=n),
        "naics_code": np.random.choice(["541512", "54151200", "33641", "336411", "N/A"], size=n),
        "cage_code": np.random.choice(["1BEL1", "47272", "ABCD1", "INVALID_CAGE_XYZ", ""], size=n),
        "recipient_uei": [
            f"{''.join(np.random.choice(list('ABCDEFGHIJKLMNPQRSTUVWXYZ0123456789'), size=12))}"
            if np.random.random() > 0.08 else None
            for _ in range(n)
        ],
        "recipient_duns_number": [f"{np.random.randint(100000000, 999999999):09d}" for _ in range(n)],
        "action_date": pd.date_range("2023-01-01", periods=n, freq="6H"),
        "last_modified_date": pd.date_range("2023-06-01", periods=n, freq="3H"),
        "awarding_agency_name": np.random.choice(
            ["DEPT OF DEFENSE", "Department of the Navy", "DON", "USAF", "ARMY", ""], size=n
        ),
    })

    # Introduce a few duplicates
    df_raw = pd.concat([df_raw, df_raw.sample(50, random_state=1)], ignore_index=True)

    print(f"\nRaw DataFrame: {len(df_raw):,} rows\n")

    df_clean, metrics = clean_procurement_dataframe(df_raw)

    print(f"\nCleaned DataFrame: {len(df_clean):,} rows")
    print(f"\nQuality Metrics:\n{pd.json_normalize(metrics).T.to_string()}")

    # Show normalization results
    print(f"\nVendor name normalization sample:")
    print(
        df_clean[["awardee_or_recipient_legal_entity_name", "vendor_name_normalized"]]
        .drop_duplicates()
        .head(10)
        .to_string(index=False)
    )
