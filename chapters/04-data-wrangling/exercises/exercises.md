# Chapter 04 Exercises: Data Wrangling and Cleaning

These exercises use realistic government procurement and personnel data scenarios. Each exercise includes a context that matches work you'll encounter on federal analytics platforms.

Complete the exercises in order — they build on each other. Exercise 4 is the integration challenge that combines everything.

---

## Exercise 1: Null Handling and Type Coercion (Pandas)

**Context:** You've received a DoD contract modification export from FPDS-NG. The export contains four years of modifications (FY2021–FY2024) for Navy ship repair contracts. Three columns are causing problems: `base_exercised_options_value` arrived with dollar signs and commas, `period_of_performance_start_date` is stored as strings in two different date formats, and `recipient_uei` is null for 11% of records (which you suspect are pre-2022 records that still carry DUNS numbers).

**Dataset:** Use this snippet to generate test data:

```python
import pandas as pd
import numpy as np

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
        # Mix of date formats
        list(pd.date_range("2021-01-01", periods=250, freq="4D").strftime("%Y-%m-%d")) +
        list(pd.date_range("2022-06-01", periods=250, freq="4D").strftime("%m/%d/%Y"))
    ),
    "action_date": pd.date_range("2021-01-01", periods=n, freq="3D"),
})
```

**Tasks:**

**1a.** Without using `dropna()`, fill the null `recipient_uei` values with the corresponding `recipient_duns_number`. After filling, how many records still have null UEI?

**1b.** Write a function `clean_dollar_field(series)` that:
- Strips dollar signs and commas
- Converts the result to float
- Returns `NaN` for null inputs

Apply it to `base_exercised_options_value` and verify the column is now float dtype.

**1c.** Parse `period_of_performance_start_date` to datetime, handling both formats (`%Y-%m-%d` and `%m/%d/%Y`). Verify: what percentage of dates successfully parsed? What's the min and max date in the column?

**1d.** Flag the records where `base_exercised_options_value` is null with a `data_quality_flag` value of `"MISSING_OPTION_VALUE"`. How many records are flagged?

---

## Exercise 2: Government Identifier Standardization (Pandas)

**Context:** You're building an aggregate analysis of defense contracts by vendor. The dataset spans FY2019–FY2024, mixing pre- and post-UEI records. Your NAICS codes include 4-digit legacy entries, 5-digit codes, and valid 6-digit codes — all for the same analysis. Your CAGE codes include lowercase, have extra spaces, and several obviously invalid values.

**Dataset:**

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
```

**Tasks:**

**2a.** Standardize `cage_code`: uppercase, strip whitespace, remove non-alphanumeric characters. After standardization, how many unique CAGE codes remain?

**2b.** Standardize `naics_code`: strip non-numeric characters, zero-pad to 6 digits. Flag codes that are still not exactly 6 digits after standardization. How many flags?

**2c.** Write a `normalize_vendor_name(name)` function that strips legal suffixes (Inc, Corp, Corporation, LLC, etc.), converts to uppercase, removes punctuation, and collapses whitespace. Apply it to `vendor_name` to create `vendor_name_normalized`. How many unique normalized names result from the 15 raw names?

**2d.** After normalization, deduplicate the DataFrame on `vendor_name_normalized`, keeping the row with a non-null `uei`. How many rows remain?

---

## Exercise 3: PySpark Cleaning on a Larger Dataset

**Context:** You're working on Databricks on a logistics dataset from an Army financial system (GFEBS). The dataset has 2 million rows of obligation line items. You need to clean it, deduplicate it, and write it to a Delta table.

**Setup:** This exercise requires PySpark. If you're in a Databricks notebook, `spark` is already available. For local testing, create a local SparkSession.

**Dataset generation:**

```python
from pyspark.sql import SparkSession
from pyspark.sql import functions as F
from pyspark.sql.types import *
import random, string

# In Databricks: spark is already defined
spark = SparkSession.builder.appName("ex3").master("local[*]").getOrCreate()

random.seed(42)

def random_uei():
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=12))

n = 50_000  # Use 50k for local; 2M is a Databricks-scale example

data = [
    (
        f"GFEBS_OBLIG_{i:07d}",
        str(random.choice([0, 1, 2])),
        random.choice(["DEPT OF DEFENSE", "DON", "USAF", "ARMY", "USMC"]),
        random.choice(["541512", "336411", "541330", "33451", "5415"]),  # Some invalid
        f"${random.uniform(10_000, 2_000_000):,.2f}",
        random.choice([random_uei(), None]),
        f"2024-{random.randint(1,12):02d}-{random.randint(1,28):02d}",
    )
    for i in range(n)
]

# Add 5% duplicates
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
df_raw.cache()
print(f"Raw rows: {df_raw.count():,}")
```

**Tasks:**

**3a.** Using PySpark, coerce `obligation_amount` from string to double (strip `$` and commas). Show the min, max, and mean obligation using `.describe()`.

**3b.** Parse `action_date` from string to date type using `F.to_date()`. How many records have null dates after parsing?

**3c.** Standardize `naics_code`: strip non-numeric characters, left-pad to 6 digits. Flag codes that don't match `^\d{6}$` after standardization. Count the flagged records.

**3d.** Deduplicate on `(obligation_id, modification_number)` using a window function that keeps the last record (by `action_date`). Compare row counts before and after dedup.

**3e.** Compute the following quality metrics using Spark aggregations:
- Completeness of `recipient_uei` (% non-null)
- Completeness of `obligation_amount` (% non-null after coercion)
- % of records with valid 6-digit NAICS

Write the results to a DataFrame with columns: `metric_name`, `value`, `threshold`, `status`.

---

## Exercise 4: Integration Challenge — End-to-End Federal Dataset Pipeline

**Context:** You've received three datasets from a health analytics project at the Veterans Administration:

1. **`va_contracts.csv`** — Contract awards for VA medical equipment (FY2022–FY2024)
2. **`va_vendors.csv`** — SAM.gov vendor registrations for VA contract recipients
3. **`va_patients_sample.csv`** — A small anonymized sample of equipment usage records that accidentally includes a `patient_ssn` column that should not be there

You need to build a complete cleaning pipeline that:
- Cleans and standardizes all three datasets
- Joins contracts to vendors on UEI
- Detects and removes PII from the patient sample before analysis
- Outputs quality metrics

**Setup:**

```python
import pandas as pd
import numpy as np
import re, hashlib, hmac

np.random.seed(7)
n = 200

# Simulate VA contracts
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
# Add duplicates
df_contracts = pd.concat([df_contracts, df_contracts.sample(20, random_state=1)], ignore_index=True)

# Simulate vendor records
vendor_ueis = df_contracts["recipient_uei"].dropna().unique()[:40]
df_vendors = pd.DataFrame({
    "uei": vendor_ueis,
    "legal_name": [f"Medical Supplier {i} Inc" for i in range(len(vendor_ueis))],
    "cage_code": [f"{''.join(np.random.choice(list('ABCDEFGHJKLMNPQRSTUVWXYZ0123456789'), size=5))}" for _ in range(len(vendor_ueis))],
    "expiration_date": ["2025-12-31"] * len(vendor_ueis),
    "state": np.random.choice(["VA", "MD", "DC", "TX", "CA"], size=len(vendor_ueis)),
})

# Simulate patient sample WITH accidental PII
df_patients = pd.DataFrame({
    "equipment_category": np.random.choice(["wheelchair", "prosthetic", "hearing_aid", "cpap"], size=50),
    "dispensed_date": pd.date_range("2023-01-01", periods=50, freq="7D").strftime("%Y-%m-%d").tolist(),
    "patient_age": np.random.randint(30, 90, size=50),
    "patient_ssn": [f"{np.random.randint(100,999)}-{np.random.randint(10,99)}-{np.random.randint(1000,9999)}" for _ in range(50)],
    "va_facility_code": np.random.choice(["526", "528", "630", "695"], size=50),
})
```

**Tasks:**

**4a.** Clean `df_contracts`:
- Handle UEI nulls (fill from any available identifier)
- Coerce `obligation_amount` to float and `action_date` / `last_modified_date` to datetime
- Deduplicate on `(contract_id, modification_number)` keeping the most recent record
- Standardize `naics_code` to 6 digits

**4b.** Clean `df_vendors`:
- Standardize `cage_code` and `uei`
- Normalize `legal_name` by stripping legal suffixes
- Parse `expiration_date` to datetime and compute `days_until_expiration` from today

**4c.** Join `df_contracts` (cleaned) to `df_vendors` (cleaned) on `recipient_uei` = `uei`. What percentage of contract records matched to a vendor? What's the total obligation for matched vs. unmatched contracts?

**4d.** For `df_patients`:
- Run a PII pattern scan (the function in Example 01) to confirm `patient_ssn` contains SSN-format data
- Tokenize the `patient_ssn` column using HMAC-SHA256
- Anonymize `patient_age` by converting to 10-year age bands
- Verify the output DataFrame contains no raw SSN values

**4e.** Compute and print a data quality report covering all three datasets (post-cleaning). For each dataset, report: row count, completeness of key fields, and any quality flags.

---

## Submission Format

For each exercise, write your solution in a Python file or Jupyter notebook. Include:

1. The working code
2. A comment for each non-obvious decision explaining *why* you made that choice (not just *what* the code does)
3. The printed output showing the before/after row counts, quality metrics, or validation results

See [solutions/solutions.md](./solutions/solutions.md) for reference implementations.
