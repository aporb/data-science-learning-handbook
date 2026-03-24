# Chapter 04 Exercise Solutions

Reference implementations for all exercises. These show one correct approach — not the only approach. The important parts are the decisions: why each null is handled differently, why the dedup keeps the most recent record, why PII is tokenized rather than just dropped.

---

## Exercise 1 Solutions: Null Handling and Type Coercion

### 1a — Fill UEI from DUNS

```python
import pandas as pd
import numpy as np

# Build the test dataset (from exercise)
np.random.seed(99)
n = 500
df = pd.DataFrame({
    "contract_award_unique_key": [f"N00024FY{i:05d}" for i in range(n)],
    "modification_number": np.random.choice(["0", "1", "P00001", "P00002"], size=n),
    "recipient_uei": [
        f"{''.join(np.random.choice(list('ABCDEFGHJKLMNPQRSTUVWXYZ0123456789'), size=12))}"
        if i >= 55 else None
        for i in range(n)
    ],
    "recipient_duns_number": [f"{np.random.randint(100000000, 999999999):09d}" for _ in range(n)],
    "base_exercised_options_value": [
        f"${np.random.uniform(500_000, 25_000_000):,.2f}" if np.random.random() > 0.04 else None
        for _ in range(n)
    ],
    "period_of_performance_start_date": (
        list(pd.date_range("2021-01-01", periods=250, freq="4D").strftime("%Y-%m-%d")) +
        list(pd.date_range("2022-06-01", periods=250, freq="4D").strftime("%m/%d/%Y"))
    ),
    "action_date": pd.date_range("2021-01-01", periods=n, freq="3D"),
})

null_before = df["recipient_uei"].isnull().sum()
print(f"Null UEI before fill: {null_before}")

# Fill: where UEI is null, use DUNS
# This handles pre-April 2022 records — their DUNS is the best available identifier
mask = df["recipient_uei"].isnull() & df["recipient_duns_number"].notnull()
df.loc[mask, "recipient_uei"] = df.loc[mask, "recipient_duns_number"]

null_after = df["recipient_uei"].isnull().sum()
print(f"Null UEI after fill: {null_after}")
# Expected: 0 (all nulls were filled from DUNS)
```

**Why this approach:** We don't fill blindly. We only fill from DUNS where DUNS is available, and we preserve the distinction by keeping both columns. Records that had UEIs already are untouched.

---

### 1b — Dollar field coercion

```python
def clean_dollar_field(series: pd.Series) -> pd.Series:
    """
    Parse dollar amounts from string format to float.
    Handles: "$1,234,567.89", "(100.00)" (accounting negative), null values.
    """
    return (series
        .astype(str)
        .str.replace(r"[$,\s]", "", regex=True)
        .str.replace(r"^\((.+)\)$", r"-\1", regex=True)  # (100) → -100
        .replace({"nan": np.nan, "N/A": np.nan, "None": np.nan, "": np.nan})
        .astype(float)
    )

df["base_exercised_options_value"] = clean_dollar_field(df["base_exercised_options_value"])

print(f"dtype: {df['base_exercised_options_value'].dtype}")   # float64
print(f"min: ${df['base_exercised_options_value'].min():,.2f}")
print(f"max: ${df['base_exercised_options_value'].max():,.2f}")
print(f"null count: {df['base_exercised_options_value'].isnull().sum()}")
```

---

### 1c — Date parsing with mixed formats

```python
def parse_mixed_dates(series: pd.Series) -> pd.Series:
    """
    Parse dates that appear in both %Y-%m-%d and %m/%d/%Y formats.
    Returns NaT where parsing fails.
    """
    parsed = pd.to_datetime(series, infer_datetime_format=True, errors="coerce")
    return parsed

df["period_of_performance_start_date"] = parse_mixed_dates(
    df["period_of_performance_start_date"]
)

parse_success_pct = df["period_of_performance_start_date"].notnull().mean() * 100
print(f"Successfully parsed: {parse_success_pct:.1f}%")
print(f"Min date: {df['period_of_performance_start_date'].min().date()}")
print(f"Max date: {df['period_of_performance_start_date'].max().date()}")
```

**Note:** `infer_datetime_format=True` handles both formats automatically for most cases. If you have truly exotic formats, use `dateutil.parser.parse` in an `.apply()` with `errors='coerce'`.

---

### 1d — Flag missing values

```python
# Create the flag column — only set where dollar value is null
df["data_quality_flag"] = None
df.loc[df["base_exercised_options_value"].isnull(), "data_quality_flag"] = "MISSING_OPTION_VALUE"

flagged_count = (df["data_quality_flag"] == "MISSING_OPTION_VALUE").sum()
print(f"Records flagged for missing option value: {flagged_count}")
# Should be approximately 4% of 500 rows = ~20 records
```

---

## Exercise 2 Solutions: Government Identifier Standardization

### 2a — CAGE code standardization

```python
df_vendors = pd.DataFrame({
    "vendor_name": [
        "Lockheed Martin Corp", "LOCKHEED MARTIN CORPORATION", "Lockheed Martin",
        "Raytheon Co", "Raytheon Technologies Inc", "RAYTHEON TECHNOLOGIES",
        "General Dynamics Corp", "GENERAL DYNAMICS CORPORATION", "General Dynamics",
        "BAE Systems Inc", "BAE SYSTEMS INC.", "bae systems incorporated",
        "L3Harris Technologies Inc", "L3HARRIS TECHNOLOGIES", "l3harris technologies llc",
    ],
    "cage_code": [
        "1bel1", " 47272 ", "1BEL1",
        "47272", "4T272", "47272",
        "abcd1", "ABCD1", "ABCD1",
        "u0hf9", "U0HF9", "U0HF9",
        "5wpp1", "5WPP1", "5WPP1",
    ],
    "naics_code": [
        "336411", "33641", "3364",
        "541512", "54151", "5415",
        "541330", "54133", "5413",
        "336413", "33641", "3364",
        "334511", "33451", "3345",
    ],
    "uei": [
        "LKA2B3C4D5E6", None, "LKA2B3C4D5E6",
        "RTN4X5Y6Z7W8", None, "RTN4X5Y6Z7W8",
        "GD9A8B7C6D5E", None, "GD9A8B7C6D5E",
        "BAE1A2B3C4D5", None, "BAE1A2B3C4D5",
        "L3H9Z8Y7X6W5", None, "L3H9Z8Y7X6W5",
    ],
})

import re

df_vendors["cage_code"] = (df_vendors["cage_code"]
    .astype(str)
    .str.upper()
    .str.strip()
    .str.replace(r"[^A-Z0-9]", "", regex=True)
)

print(f"Unique CAGE codes after standardization: {df_vendors['cage_code'].nunique()}")
# Expected: 5 unique valid codes (1BEL1, 47272, ABCD1, U0HF9, 5WPP1)
```

---

### 2b — NAICS standardization

```python
df_vendors["naics_code"] = (df_vendors["naics_code"]
    .astype(str)
    .str.strip()
    .str.replace(r"[^0-9]", "", regex=True)
    .str.zfill(6)
)

# Flag codes that aren't 6 digits (this catches the ones that were 4 digits before padding)
# After zfill(6): "3364" → "003364", "5415" → "005415" — these are now 6 chars but wrong codes
# Real validation: check that the code maps to a known NAICS sector
invalid_mask = ~df_vendors["naics_code"].str.match(r"^\d{6}$")
print(f"Invalid NAICS after standardization: {invalid_mask.sum()}")

# Better: flag codes that started with fewer than 5 digits (likely truncated)
# We can detect this by checking if the leading zeros we added are suspicious
# A 6-digit NAICS starting with "00" is almost certainly invalid
zero_padded_short = df_vendors["naics_code"].str.startswith("00")
print(f"Suspiciously short NAICS codes (padded to 6 from <4 digits): {zero_padded_short.sum()}")
```

---

### 2c and 2d — Vendor name normalization and deduplication

```python
import unicodedata

LEGAL_SUFFIX_PATTERN = (
    r"\b(INC|INCORPORATED|CORP|CORPORATION|LLC|LLP|LP|"
    r"CO|COMPANY|LTD|LIMITED|PLC|GROUP|HOLDINGS|HOLDING|"
    r"TECHNOLOGIES|TECHNOLOGY|SERVICES|SOLUTIONS|SYSTEMS|"
    r"INTERNATIONAL|INTL|GLOBAL|ASSOCIATES|PARTNERS|"
    r"ENTERPRISES|VENTURES|INDUSTRIES|CONSULTING)\.?\b"
)

def normalize_vendor_name(name: str) -> str:
    if pd.isnull(name) or str(name).strip() == "":
        return ""
    name = unicodedata.normalize("NFKD", str(name))
    name = name.encode("ascii", "ignore").decode("ascii")
    name = name.upper().strip()
    name = re.sub(LEGAL_SUFFIX_PATTERN, " ", name)
    name = re.sub(r"[,\.\(\)&/\\']", " ", name)
    name = re.sub(r"\s+", " ", name).strip()
    return name

df_vendors["vendor_name_normalized"] = df_vendors["vendor_name"].apply(normalize_vendor_name)

raw_unique = df_vendors["vendor_name"].nunique()
norm_unique = df_vendors["vendor_name_normalized"].nunique()
print(f"Raw unique names: {raw_unique}")       # 15
print(f"Normalized unique names: {norm_unique}")  # Should be 5

# 2d: Deduplicate — keep rows with non-null UEI
df_deduped = (df_vendors
    .sort_values("uei", na_position="last")  # non-null UEI rows sort first
    .drop_duplicates(subset="vendor_name_normalized", keep="first")
    .reset_index(drop=True)
)
print(f"Rows after dedup: {len(df_deduped)}")  # Should be 5
print(df_deduped[["vendor_name_normalized", "uei", "cage_code"]].to_string())
```

---

## Exercise 3 Solutions: PySpark Cleaning

### 3a–3e — PySpark cleaning pipeline

```python
from pyspark.sql import SparkSession
from pyspark.sql import functions as F
from pyspark.sql.types import *
import random, string

spark = SparkSession.builder.appName("ex3_solution").master("local[*]").getOrCreate()
spark.sparkContext.setLogLevel("WARN")

random.seed(42)

def random_uei():
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=12))

n = 50_000
data = [
    (
        f"GFEBS_OBLIG_{i:07d}",
        str(random.choice([0, 1, 2])),
        random.choice(["DEPT OF DEFENSE", "DON", "USAF", "ARMY", "USMC"]),
        random.choice(["541512", "336411", "541330", "33451", "5415"]),
        f"${random.uniform(10_000, 2_000_000):,.2f}",
        random.choice([random_uei(), None]),
        f"2024-{random.randint(1,12):02d}-{random.randint(1,28):02d}",
    )
    for i in range(n)
]
dupes = random.sample(data, n // 20)
data.extend(dupes)
random.shuffle(data)

schema = StructType([
    StructField("obligation_id", StringType()),
    StructField("modification_number", StringType()),
    StructField("awarding_agency", StringType()),
    StructField("naics_code", StringType()),
    StructField("obligation_amount", StringType()),
    StructField("recipient_uei", StringType()),
    StructField("action_date", StringType()),
])

df_raw = spark.createDataFrame(data, schema=schema)
raw_count = df_raw.count()
print(f"Raw rows: {raw_count:,}")

# 3a: Coerce obligation_amount to double
df = df_raw.withColumn(
    "obligation_amount",
    F.regexp_replace(F.col("obligation_amount"), r"[$,\s]", "").cast(DoubleType())
)
df.select(F.min("obligation_amount"), F.max("obligation_amount"), F.avg("obligation_amount")).show()

# 3b: Parse action_date
df = df.withColumn("action_date", F.to_date(F.col("action_date"), "yyyy-MM-dd"))
null_dates = df.filter(F.col("action_date").isNull()).count()
print(f"Null dates after parsing: {null_dates:,}")

# 3c: Standardize NAICS
df = df.withColumn(
    "naics_code",
    F.lpad(F.regexp_replace(F.col("naics_code"), r"[^0-9]", ""), 6, "0")
)
df = df.withColumn(
    "naics_valid",
    F.col("naics_code").rlike(r"^\d{6}$")
)
invalid_naics = df.filter(~F.col("naics_valid")).count()
print(f"Records with invalid NAICS (non-6-digit after pad): {invalid_naics:,}")
# Note: "33451" zero-padded → "033451" which IS 6 digits but semantically wrong.
# "5415" → "005415" — same issue. Real validation requires checking against the NAICS code list.

# 3d: Deduplicate
from pyspark.sql.window import Window

dedup_window = Window.partitionBy("obligation_id", "modification_number").orderBy(
    F.desc("action_date")
)
df_deduped = (df
    .withColumn("_rank", F.row_number().over(dedup_window))
    .filter(F.col("_rank") == 1)
    .drop("_rank")
)
deduped_count = df_deduped.count()
print(f"Rows after dedup: {deduped_count:,} (removed {raw_count - deduped_count:,} duplicates)")

# 3e: Quality metrics DataFrame
df_deduped.cache()
total = df_deduped.count()

uei_completeness = df_deduped.filter(F.col("recipient_uei").isNotNull()).count() / total * 100
obligation_completeness = df_deduped.filter(F.col("obligation_amount").isNotNull()).count() / total * 100
valid_naics_pct = df_deduped.filter(F.col("naics_valid")).count() / total * 100

quality_rows = [
    ("completeness_recipient_uei",  round(uei_completeness, 2),  90.0, "PASS" if uei_completeness >= 90 else "FAIL"),
    ("completeness_obligation_amount", round(obligation_completeness, 2), 99.0, "PASS" if obligation_completeness >= 99 else "FAIL"),
    ("validity_naics_6digit",       round(valid_naics_pct, 2),    85.0, "PASS" if valid_naics_pct >= 85 else "FAIL"),
]

quality_schema = StructType([
    StructField("metric_name", StringType()),
    StructField("value", DoubleType()),
    StructField("threshold", DoubleType()),
    StructField("status", StringType()),
])

quality_df = spark.createDataFrame(quality_rows, schema=quality_schema)
quality_df.show(truncate=False)

df_deduped.unpersist()
spark.stop()
```

---

## Exercise 4 Solutions: Integration Challenge

### 4a — Clean contracts

```python
import pandas as pd
import numpy as np
import re, hashlib, hmac, unicodedata
from datetime import date

np.random.seed(7)
n = 200

df_contracts = pd.DataFrame({
    "contract_id": [f"VA797-{i:04d}" for i in range(n)],
    "modification_number": np.random.choice(["0", "1", "P00001"], size=n),
    "recipient_uei": [
        f"{''.join(np.random.choice(list('ABCDEFGHJKLMNPQRSTUVWXYZ0123456789'), size=12))}"
        if np.random.random() > 0.06 else None
        for _ in range(n)
    ],
    "obligation_amount": [f"${np.random.uniform(5_000, 500_000):,.2f}" for _ in range(n)],
    "naics_code": np.random.choice(["339112", "33911", "3391", "339113", "621498"], size=n),
    "action_date": pd.date_range("2022-01-01", periods=n, freq="4D").strftime("%Y-%m-%d").tolist(),
    "last_modified_date": pd.date_range("2022-06-01", periods=n, freq="2D").strftime("%Y-%m-%d").tolist(),
})
df_contracts = pd.concat([df_contracts, df_contracts.sample(20, random_state=1)], ignore_index=True)

# Clean obligation_amount
df_contracts["obligation_amount"] = (df_contracts["obligation_amount"]
    .astype(str)
    .str.replace(r"[$,\s]", "", regex=True)
    .astype(float)
)

# Parse dates
df_contracts["action_date"] = pd.to_datetime(df_contracts["action_date"], errors="coerce")
df_contracts["last_modified_date"] = pd.to_datetime(df_contracts["last_modified_date"], errors="coerce")

# Deduplicate — keep most recently modified
contracts_clean = (df_contracts
    .sort_values("last_modified_date", ascending=False)
    .drop_duplicates(subset=["contract_id", "modification_number"], keep="first")
    .reset_index(drop=True)
)
print(f"Contracts: {len(df_contracts):,} raw → {len(contracts_clean):,} after dedup")

# Standardize NAICS
contracts_clean["naics_code"] = (contracts_clean["naics_code"]
    .astype(str)
    .str.replace(r"[^0-9]", "", regex=True)
    .str.zfill(6)
)

print(contracts_clean[["contract_id", "obligation_amount", "naics_code", "action_date"]].head())
```

---

### 4b — Clean vendors

```python
vendor_ueis = contracts_clean["recipient_uei"].dropna().unique()[:40]
df_vendors = pd.DataFrame({
    "uei": vendor_ueis,
    "legal_name": [f"Medical Supplier {i} Inc" for i in range(len(vendor_ueis))],
    "cage_code": [f"{''.join(np.random.choice(list('ABCDEFGHJKLMNPQRSTUVWXYZ0123456789'), size=5))}" for _ in range(len(vendor_ueis))],
    "expiration_date": ["2025-12-31"] * len(vendor_ueis),
    "state": np.random.choice(["VA", "MD", "DC", "TX", "CA"], size=len(vendor_ueis)),
})

# Standardize UEI
df_vendors["uei"] = (df_vendors["uei"]
    .astype(str)
    .str.upper()
    .str.strip()
    .str.replace(r"[^A-Z0-9]", "", regex=True)
)

# Standardize CAGE
df_vendors["cage_code"] = (df_vendors["cage_code"]
    .astype(str)
    .str.upper()
    .str.strip()
    .str.replace(r"[^A-Z0-9]", "", regex=True)
)

# Normalize legal_name
LEGAL_SUFFIX_PATTERN = r"\b(INC|INCORPORATED|CORP|CORPORATION|LLC|LLP|LP|CO|COMPANY|LTD|LIMITED)\b\.?"
df_vendors["vendor_name_normalized"] = (df_vendors["legal_name"]
    .str.upper()
    .str.strip()
    .apply(lambda x: re.sub(LEGAL_SUFFIX_PATTERN, " ", x, flags=re.IGNORECASE))
    .str.strip()
)

# Parse expiration date and compute days until expiration
df_vendors["expiration_date"] = pd.to_datetime(df_vendors["expiration_date"])
today = pd.Timestamp(date.today())
df_vendors["days_until_expiration"] = (df_vendors["expiration_date"] - today).dt.days

vendors_clean = df_vendors
print(f"Vendors: {len(vendors_clean)} records")
print(vendors_clean[["uei", "vendor_name_normalized", "cage_code", "days_until_expiration"]].head())
```

---

### 4c — Join contracts to vendors

```python
merged = contracts_clean.merge(
    vendors_clean.rename(columns={"uei": "recipient_uei"}),
    on="recipient_uei",
    how="left",
    suffixes=("", "_vendor")
)

match_pct = merged["legal_name"].notnull().mean() * 100
print(f"Contract-to-vendor match rate: {match_pct:.1f}%")

matched_obligations = merged.loc[merged["legal_name"].notnull(), "obligation_amount"].sum()
unmatched_obligations = merged.loc[merged["legal_name"].isnull(), "obligation_amount"].sum()
print(f"Matched obligations: ${matched_obligations:,.2f}")
print(f"Unmatched obligations: ${unmatched_obligations:,.2f}")
```

---

### 4d — PII detection and removal from patient sample

```python
df_patients = pd.DataFrame({
    "equipment_category": np.random.choice(["wheelchair", "prosthetic", "hearing_aid", "cpap"], size=50),
    "dispensed_date": pd.date_range("2023-01-01", periods=50, freq="7D").strftime("%Y-%m-%d").tolist(),
    "patient_age": np.random.randint(30, 90, size=50),
    "patient_ssn": [f"{np.random.randint(100,999)}-{np.random.randint(10,99)}-{np.random.randint(1000,9999)}" for _ in range(50)],
    "va_facility_code": np.random.choice(["526", "528", "630", "695"], size=50),
})

# Step 1: PII scan
PII_PATTERNS = {
    "SSN": r"\b\d{3}-\d{2}-\d{4}\b",
    "phone_number": r"\b\d{3}[-.\s]\d{3}[-.\s]\d{4}\b",
    "email_address": r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b",
}

def scan_for_pii(df: pd.DataFrame) -> None:
    for col in df.select_dtypes(include="object").columns:
        for label, pattern in PII_PATTERNS.items():
            matches = df[col].astype(str).str.contains(pattern, regex=True, na=False).sum()
            if matches > 0:
                print(f"PII detected: column='{col}', pattern='{label}', matches={matches}")

scan_for_pii(df_patients)
# Expected: "PII detected: column='patient_ssn', pattern='SSN', matches=50"

# Step 2: Tokenize patient_ssn
TOKENIZATION_KEY = b"va_health_analytics_secret_key_2024"

def tokenize_field(value: str, key: bytes = TOKENIZATION_KEY) -> str:
    if pd.isnull(value) or str(value).strip() == "":
        return ""
    token = hmac.new(key, str(value).encode("utf-8"), hashlib.sha256).hexdigest()[:16]
    return f"TKN_{token}"

df_patients["patient_ssn_token"] = df_patients["patient_ssn"].apply(tokenize_field)
df_patients = df_patients.drop(columns=["patient_ssn"])

# Step 3: Anonymize age into 10-year bands
df_patients["age_band"] = pd.cut(
    df_patients["patient_age"],
    bins=[0, 40, 50, 60, 70, 80, 120],
    labels=["<40", "40-49", "50-59", "60-69", "70-79", "80+"],
    right=False
)
df_patients = df_patients.drop(columns=["patient_age"])

# Verify: no raw SSN values remain
assert "patient_ssn" not in df_patients.columns, "Raw SSN column should have been dropped"
ssn_pattern_found = df_patients.select_dtypes(include="object").apply(
    lambda col: col.str.contains(r"\b\d{3}-\d{2}-\d{4}\b", regex=True, na=False).any()
).any()
assert not ssn_pattern_found, "SSN pattern found in cleaned DataFrame — check tokenization"

print("PII removed successfully. Patient sample columns:", list(df_patients.columns))
print(df_patients.head())
```

---

### 4e — Data quality report

```python
def quality_report(df: pd.DataFrame, name: str, critical_cols: list) -> None:
    print(f"\n=== Quality Report: {name} ===")
    print(f"Row count: {len(df):,}")
    for col in critical_cols:
        if col in df.columns:
            completeness = (1 - df[col].isnull().mean()) * 100
            status = "PASS" if completeness >= 95 else "WARN" if completeness >= 85 else "FAIL"
            print(f"  {col}: {completeness:.1f}% complete [{status}]")
    if "data_quality_flag" in df.columns:
        flags = df["data_quality_flag"].value_counts()
        if len(flags) > 0:
            print(f"  Quality flags: {flags.to_dict()}")

quality_report(
    contracts_clean, "VA Contracts (cleaned)",
    critical_cols=["contract_id", "recipient_uei", "obligation_amount", "action_date", "naics_code"]
)

quality_report(
    vendors_clean, "VA Vendors (cleaned)",
    critical_cols=["uei", "cage_code", "expiration_date"]
)

quality_report(
    df_patients, "VA Patient Sample (cleaned/anonymized)",
    critical_cols=["equipment_category", "dispensed_date", "age_band", "patient_ssn_token"]
)
```

**Expected output:**
```
=== Quality Report: VA Contracts (cleaned) ===
Row count: 200
  contract_id: 100.0% complete [PASS]
  recipient_uei: 94.0% complete [WARN]   ← ~6% were null from the generator
  obligation_amount: 100.0% complete [PASS]
  action_date: 100.0% complete [PASS]
  naics_code: 100.0% complete [PASS]

=== Quality Report: VA Vendors (cleaned) ===
Row count: 40
  uei: 100.0% complete [PASS]
  cage_code: 100.0% complete [PASS]
  expiration_date: 100.0% complete [PASS]

=== Quality Report: VA Patient Sample (cleaned/anonymized) ===
Row count: 50
  equipment_category: 100.0% complete [PASS]
  dispensed_date: 100.0% complete [PASS]
  age_band: 100.0% complete [PASS]
  patient_ssn_token: 100.0% complete [PASS]
```

---

## Key Lessons Across All Exercises

**On null handling:** The right question is always "why is this null?" not "should I drop it?" Context changes the answer every time.

**On deduplication:** Always verify that your dollar totals remain consistent after dedup. Government data has intentional duplicate records (modifications, amendments) that are not errors — knowing the primary key is the only safe way to deduplicate correctly.

**On normalization:** Over-normalizing is as dangerous as under-normalizing. Stripping every variant down to the bare root can collapse distinct legal entities. Preserve the original field. Build the normalized version as a separate key.

**On PII:** Scan first. Always. The cost of discovering PII in a shared workspace after it's been there for six months is much higher than the cost of running a 30-line pattern scan before loading.

**On quality metrics:** Measure before you analyze. If you run quality checks only at the end when your results don't match expectations, you're doing the work twice.
