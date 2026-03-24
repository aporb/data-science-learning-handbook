# Chapter 03 Exercise Solutions

---

## Solution: Exercise 1 — USAspending API

```python
import time
import requests
import pandas as pd

USASPENDING_BASE = "https://api.usaspending.gov/api/v2"


def fetch_navy_it_contracts(fiscal_year: int = 2023) -> pd.DataFrame:
    """Pull all Navy NAICS 541512 definitive contracts for a fiscal year."""
    url = f"{USASPENDING_BASE}/search/spending_by_award/"

    payload = {
        "subawards": False,
        "limit": 100,
        "page": 1,
        "sort": "Award Amount",
        "order": "desc",
        "filters": {
            "time_period": [
                {
                    "start_date": f"{fiscal_year - 1}-10-01",
                    "end_date": f"{fiscal_year}-09-30"
                }
            ],
            "award_type_codes": ["A", "B", "C", "D"],
            "awarding_agency_names": ["Department of the Navy"],
            "naics_codes": ["541512"],
        },
        "fields": [
            "Award ID",
            "Recipient Name",
            "Award Amount",
            "NAICS Code",
            "NAICS Description",
            "Awarding Sub Agency",
            "Period of Performance Start Date",
            "Period of Performance Current End Date",
            "recipient_location_state_code",
        ],
    }

    all_records = []
    page = 1

    # Get first page to learn the total record count
    response = requests.post(url, json=payload, timeout=30)
    response.raise_for_status()
    data = response.json()

    total = data.get("page_metadata", {}).get("total", 0)
    total_pages = -(-total // payload["limit"])  # Ceiling division

    print(f"Total records: {total:,} | Pages: {total_pages}")

    if total > 5000:
        print(
            "WARNING: More than 5,000 records found. "
            "Consider using the bulk download endpoint at "
            f"{USASPENDING_BASE}/download/awards/ for better performance."
        )

    all_records.extend(data.get("results", []))

    # Paginate through remaining pages
    for page_num in range(2, total_pages + 1):
        payload["page"] = page_num
        response = requests.post(url, json=payload, timeout=30)
        response.raise_for_status()
        all_records.extend(response.json().get("results", []))

        if page_num % 10 == 0:
            print(f"  Page {page_num}/{total_pages}, {len(all_records):,}/{total:,} records")

        time.sleep(0.2)  # Stay well under 1,000 req/hr

    df = pd.json_normalize(all_records)
    print(f"\nFinal count: {len(df):,} records")
    return df


if __name__ == "__main__":
    df = fetch_navy_it_contracts(fiscal_year=2023)

    # Top 10 recipients by total obligations
    top10 = (
        df.groupby("Recipient Name")
        .agg(
            total_obligations=("Award Amount", "sum"),
            award_count=("Award ID", "count"),
        )
        .sort_values("total_obligations", ascending=False)
        .head(10)
        .reset_index()
    )

    print("\nTop 10 Navy IT Contract Recipients (NAICS 541512, FY2023):")
    print(top10.to_string(index=False))
```

**Key points in this solution:**

The ceiling division `-(- total // limit)` avoids importing `math.ceil` and handles edge cases cleanly. The 5,000-record warning threshold is a judgment call — at that point the bulk download API saves roughly 10× the API quota. The 200ms delay is more conservative than the 1,000 req/hr limit requires, but network jitter on government infrastructure makes aggressive pacing unreliable.

---

## Solution: Exercise 2 — Census API Join

```python
import os
import requests
import pandas as pd

CENSUS_BASE = "https://api.census.gov/data"


def fetch_acs_county(state_fips: str, year: int = 2022) -> pd.DataFrame:
    """Fetch ACS 5-year education variables at county level for one state."""
    api_key = os.environ.get("CENSUS_API_KEY", "DEMO_KEY")

    variables = ["B01003_001E", "B15003_022E", "B15003_023E", "B08301_001E"]
    params = {
        "get": "NAME," + ",".join(variables),
        "for": "county:*",
        "in": f"state:{state_fips}",
        "key": api_key,
    }

    url = f"{CENSUS_BASE}/{year}/acs/acs5"
    response = requests.get(url, params=params, timeout=60)
    response.raise_for_status()

    raw = response.json()
    df = pd.DataFrame(raw[1:], columns=raw[0])

    # FIPS codes: keep as string with leading zeros preserved
    df["state_fips"] = df["state"].str.zfill(2)
    df["county_fips"] = df["county"].str.zfill(3)
    df["full_fips"] = df["state_fips"] + df["county_fips"]

    # Cast numeric columns
    for col in variables:
        df[col] = pd.to_numeric(df[col], errors="coerce")

    # Calculate degree holder rate
    df["degree_holders"] = df["B15003_022E"] + df["B15003_023E"]
    df["degree_holder_rate"] = df["degree_holders"] / df["B01003_001E"]

    return df[["NAME", "full_fips", "state_fips", "B01003_001E",
               "degree_holders", "degree_holder_rate"]].rename(
        columns={"B01003_001E": "population", "NAME": "county_name"}
    )


# Fetch both states
va = fetch_acs_county("51")  # Virginia
md = fetch_acs_county("24")  # Maryland

census_df = pd.concat([va, md], ignore_index=True)
print(f"Census records: {len(census_df)}")
print(census_df.sort_values("degree_holder_rate", ascending=False).head(5)[
    ["county_name", "degree_holder_rate", "population"]
].to_string(index=False))
```

**Why FIPS codes must stay as strings:** The county FIPS for Arlington, VA is "013". Cast to integer and it becomes 13. Now it no longer matches "013" in another dataset. One silent bug, weeks of confusion. Always `.str.zfill()` before joining on FIPS.

---

## Solution: Exercise 3 — Data Classification Decision Tree

**Dataset A: Navy civilian employee salary data (names, grades, pay, locations)**

Classification: **PII, within CUI**

Salary data for named individuals is PII under OMB M-07-16 ("any information about an individual...that can be used to distinguish or trace an individual's identity") and the Privacy Act of 1974 (5 U.S.C. § 552a). Name + duty station + pay grade is a combination that uniquely identifies individuals.

Authorized processing environments: Advana (NIPR, with PII workspace authorization), Jupiter (approved for PII/PHI processing). Cannot be processed on personal machines, commercial cloud accounts, or unaccredited government systems.

Access request: DD Form 2875 + data use agreement specifying the purpose and authorized recipients. Contact the data steward to confirm the specific workspace authorization.

---

**Dataset B: SAM.gov contract award data (formerly FPDS) (vendors, amounts, periods of performance)**

Classification: **Unclassified / Public**

Contract award data is published publicly through SAM.gov (formerly at fpds.gov, retired Feb 2026) and through the USAspending API under the DATA Act. Vendor names, CAGE codes, award amounts, and performance dates for awarded contracts are a matter of public record. No CUI or PII markings apply.

Authorized processing environments: Any network and any tool. You can pull this data from a personal laptop on home Wi-Fi without any security implications.

Access request: None required for the public data. If you are querying contract data via SAM.gov on a government system, standard network access and CAC authentication apply.

---

**Dataset C: Ship maintenance records labeled SIPR**

Classification: **Secret (or at minimum CUI pending review)**

The SIPR label means this data is processed on SIPRNET and requires at minimum a Secret clearance to access. Operational readiness flags and equipment status on naval vessels can reveal mission capability — this is precisely the type of data that classification protects.

Authorized processing environments: Advana SIPR, Palantir Foundry at IL5 (Azure Government Secret), or other SIPR-authorized enclaves. Cannot touch NIPR systems, commercial cloud, or personal equipment under any circumstances.

Access request: SIPR access requires a current Secret clearance (at minimum), a SIPR account provisioned by your sponsor, and a DD 2875 for the specific system. The data steward will likely require a formal data sharing agreement and command sponsorship.

---

## Solution: Exercise 4 — Messy File Handling

```python
import io
import os
import zipfile
from pathlib import Path
from typing import Optional
import pandas as pd


def parse_government_dates(series: pd.Series) -> pd.Series:
    """Multi-format date parser for government data."""
    formats = [
        "%d%b%Y",    # 14MAR2021
        "%m/%d/%Y",  # 03/14/2021
        "%Y%m%d",    # 20210314
        "%Y-%m-%d",  # 2021-03-14
        "%d-%b-%Y",  # 14-MAR-2021
        "%d-%b-%y",  # 14-MAR-21
        "%m-%d-%Y",  # 03-14-2021
        "%b %d, %Y", # Mar 14, 2021
        "%B %d, %Y", # March 14, 2021
        "%Y/%m/%d",  # 2021/03/14
    ]

    result = pd.Series(pd.NaT, index=series.index)

    for fmt in formats:
        mask = result.isna() & series.notna()
        if not mask.any():
            break
        parsed = pd.to_datetime(series[mask], format=fmt, errors="coerce")
        result[parsed.notna()] = parsed[parsed.notna()]

    # Final flexible parse for anything remaining
    still_missing = result.isna() & series.notna()
    if still_missing.any():
        flexible = pd.to_datetime(series[still_missing], errors="coerce",
                                   infer_datetime_format=True)
        result[flexible.notna()] = flexible[flexible.notna()]

    return result


def process_foia_zip(zip_path: str) -> dict[str, pd.DataFrame]:
    """
    Process a FOIA response ZIP archive.
    Returns a dict of {filename: DataFrame} for all parseable files.
    """
    parseable = {}
    skipped = []

    with zipfile.ZipFile(zip_path, "r") as zf:
        all_files = zf.namelist()
        print(f"Archive contains {len(all_files)} files")

        for filename in all_files:
            ext = Path(filename).suffix.lower()

            if ext not in (".csv", ".xlsx", ".xls"):
                skipped.append(f"{filename} (non-tabular: {ext})")
                continue

            try:
                with zf.open(filename) as f:
                    content = f.read()

                if ext == ".csv":
                    df = None
                    for sep in ["|", ",", "\t"]:
                        for encoding in ["utf-8", "latin-1", "cp1252"]:
                            try:
                                candidate = pd.read_csv(
                                    io.BytesIO(content),
                                    sep=sep,
                                    encoding=encoding,
                                    dtype=str,
                                    low_memory=False,
                                    on_bad_lines="skip",
                                )
                                if candidate.shape[1] > 1:
                                    df = candidate
                                    break
                            except Exception:
                                continue
                        if df is not None:
                            break

                    if df is None:
                        skipped.append(f"{filename} (could not parse CSV)")
                        continue

                    # Parse award_date if present
                    if "award_date" in df.columns:
                        original_null_count = df["award_date"].isna().sum()
                        df["award_date_parsed"] = parse_government_dates(df["award_date"])
                        new_null_count = df["award_date_parsed"].isna().sum()
                        parse_failures = new_null_count - original_null_count
                        if parse_failures > 0:
                            print(f"  {filename}: {parse_failures} dates could not be parsed")

                elif ext in (".xlsx", ".xls"):
                    # Try to handle multi-row headers
                    raw = pd.read_excel(
                        io.BytesIO(content), header=None, dtype=str, engine="openpyxl"
                    )
                    # Assume first non-empty row after row 0 is the real header
                    header_row = 0
                    for i, row in raw.iterrows():
                        if row.notna().sum() > raw.shape[1] * 0.5:  # >50% populated
                            header_row = i
                            break

                    if header_row > 0:
                        df = raw.iloc[header_row + 1:].copy()
                        df.columns = raw.iloc[header_row].tolist()
                    else:
                        df = pd.read_excel(io.BytesIO(content), dtype=str)

                    df = df.dropna(how="all")

                parseable[filename] = df
                print(f"  Parsed: {filename} → {df.shape[0]:,} rows × {df.shape[1]} cols")

            except Exception as e:
                skipped.append(f"{filename} (error: {e})")

    print(f"\nSummary: {len(parseable)} files parsed, {len(skipped)} skipped")
    for s in skipped:
        print(f"  Skipped: {s}")

    return parseable


# For encoding detection without prior knowledge, use the `chardet` library:
# pip install chardet
#
# import chardet
# with open(filepath, "rb") as f:
#     raw_bytes = f.read(100_000)  # sample first 100KB
# result = chardet.detect(raw_bytes)
# encoding = result["encoding"]  # e.g. "latin-1", "utf-8", "cp1252"
# confidence = result["confidence"]  # 0.0 to 1.0
#
# Practical note: chardet is useful but not perfect. If confidence < 0.8,
# try latin-1 as a fallback — it will not throw errors on any byte sequence,
# though some characters may render incorrectly.
```

---

## Solution: Exercise 5 — Rate Limit Simulation

```python
import time
import math
import random
import requests


def paginated_pull(
    base_url: str,
    params: dict,
    total_records: int,
    page_size: int = 500,
    rate_limit_per_minute: int = 100,
    max_retries: int = 5,
) -> list[dict]:
    """
    Pull all records from a paginated API with rate limiting and backoff.

    Theoretical minimum time to pull 150,000 records at 100 req/min:
        300 requests × (60 sec / 100 req) = 180 seconds = 3 minutes

    Realistic estimate with retries and network latency:
        Add 20-40% for retries and latency → 4-6 minutes

    When to request a bulk dump instead of paging:
        When you have >50,000 records AND the pull is scheduled to run
        regularly (daily/weekly). At 100 req/min, a 500K-record pull
        takes ~50 minutes and consumes all your daily quota. A bulk dump
        takes ~2 minutes and uses zero API quota.

    Args:
        base_url: API base URL
        params: Query parameters (will add page/offset)
        total_records: Known total from a prior metadata call
        page_size: Records per page
        rate_limit_per_minute: API rate limit
        max_retries: Max retries per page on 429/503

    Returns:
        List of all retrieved records
    """
    total_pages = math.ceil(total_records / page_size)
    min_interval = 60.0 / rate_limit_per_minute  # Minimum seconds between requests

    print(f"Pulling {total_records:,} records across {total_pages} pages")
    print(f"Theoretical minimum time: {total_pages * min_interval / 60:.1f} minutes")

    all_records = []
    last_request_time = 0.0

    for page_num in range(total_pages):
        page_params = {**params, "page": page_num + 1, "per_page": page_size}

        retries = 0
        backoff = 1.0

        while retries <= max_retries:
            # Rate limit: ensure minimum interval between requests
            elapsed = time.time() - last_request_time
            if elapsed < min_interval:
                time.sleep(min_interval - elapsed)

            try:
                response = requests.get(base_url, params=page_params, timeout=30)
                last_request_time = time.time()

                if response.status_code == 200:
                    records = response.json().get("results", response.json())
                    all_records.extend(records if isinstance(records, list) else [records])
                    break

                elif response.status_code in (429, 503):
                    retries += 1
                    if retries > max_retries:
                        raise RuntimeError(
                            f"Page {page_num + 1} failed after {max_retries} retries"
                        )
                    jitter = random.uniform(-backoff * 0.1, backoff * 0.1)
                    wait = backoff + jitter
                    print(f"  HTTP {response.status_code}, retry {retries}/{max_retries} "
                          f"in {wait:.1f}s")
                    time.sleep(wait)
                    backoff *= 2  # Exponential backoff

                else:
                    response.raise_for_status()

            except requests.RequestException as e:
                retries += 1
                if retries > max_retries:
                    raise
                print(f"  Request error: {e}, retry {retries}/{max_retries}")
                time.sleep(backoff)
                backoff *= 2

        # Progress logging every 10 pages
        if (page_num + 1) % 10 == 0:
            print(f"  Page {page_num + 1}/{total_pages}, "
                  f"{len(all_records):,}/{total_records:,} records retrieved")

    print(f"Complete: {len(all_records):,} records retrieved")
    return all_records
```

---

## Solution: Exercise 6 — Unity Catalog Exploration

```python
# Run in a Databricks notebook (Python cell)

from pyspark.sql import SparkSession
import pandas as pd
import re

spark = SparkSession.builder.getOrCreate()

# 1. List all accessible catalogs
catalogs = spark.sql("SHOW CATALOGS").toPandas()
print("Available catalogs:")
print(catalogs.to_string(index=False))

# 2. List schemas in sandbox catalog
# If sandbox doesn't exist, use whichever catalog you have access to
try:
    schemas = spark.sql("SHOW SCHEMAS IN sandbox").toPandas()
    target_catalog = "sandbox"
except Exception:
    target_catalog = catalogs.iloc[0]["catalog"]
    schemas = spark.sql(f"SHOW SCHEMAS IN {target_catalog}").toPandas()

print(f"\nSchemas in {target_catalog}:")
print(schemas.to_string(index=False))

# 3. List tables and row counts in first schema
if not schemas.empty:
    target_schema = schemas.iloc[0]["databaseName"]
    tables = spark.sql(f"SHOW TABLES IN {target_catalog}.{target_schema}").toPandas()

    # Get row count for each accessible table
    table_info = []
    for _, row in tables.iterrows():
        table_name = f"{target_catalog}.{target_schema}.{row['tableName']}"
        try:
            count = spark.sql(f"SELECT COUNT(*) as cnt FROM {table_name}").collect()[0]["cnt"]
            table_info.append({"table": table_name, "row_count": count, "accessible": True})
        except Exception as e:
            table_info.append({"table": table_name, "row_count": None, "accessible": False})

    df_tables = pd.DataFrame(table_info)
    print(f"\nTables in {target_catalog}.{target_schema}:")
    print(df_tables.to_string(index=False))

    # 4. Describe one accessible table and detect PII columns
    accessible = df_tables[df_tables["accessible"]]["table"].tolist()
    if accessible:
        target_table = accessible[0]
        schema_df = spark.sql(f"DESCRIBE TABLE EXTENDED {target_table}").toPandas()

        # PII heuristics — column names that suggest personal information
        PII_PATTERNS = [
            r"\bssn\b", r"\bsocial.?sec", r"\bfirst.?name\b", r"\blast.?name\b",
            r"\bfull.?name\b", r"\bemail\b", r"\bphone\b", r"\bdob\b",
            r"\bdate.?of.?birth\b", r"\baddress\b", r"\bzip\b", r"\bpassport\b",
            r"\bbiometric\b", r"\bfingerprint\b", r"\bmedical\b", r"\bdiagnosis\b",
        ]
        pii_regex = re.compile("|".join(PII_PATTERNS), re.IGNORECASE)

        schema_df["likely_pii"] = schema_df["col_name"].apply(
            lambda name: bool(pii_regex.search(str(name)))
        )

        print(f"\nSchema for {target_table}:")
        print(schema_df[["col_name", "data_type", "comment", "likely_pii"]].to_string(index=False))

        pii_cols = schema_df[schema_df["likely_pii"]]["col_name"].tolist()
        if pii_cols:
            print(f"\nPotential PII columns detected: {pii_cols}")
            print("Confirm classification with data steward before processing.")
        else:
            print("\nNo obvious PII column names detected. Still confirm with data steward.")
```

**Note on permission errors:** If `SHOW CATALOGS` succeeds but `DESCRIBE TABLE` on a specific table throws an `AnalysisException: Permission denied`, that is the Unity Catalog RBAC working as intended. Log the table name and the permission error, and submit an access request to the catalog owner. Do not attempt to work around permission controls.
