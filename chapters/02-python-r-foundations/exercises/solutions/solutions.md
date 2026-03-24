# Chapter 02 Exercise Solutions

---

## Exercise 1 Solution: Environment Audit

```python
import importlib
import sys


def check_project_requirements(requirements: dict) -> list:
    """
    Check whether project-required packages are installed and meet version requirements.

    Args:
        requirements: dict mapping importable package name to minimum version string
                      Use None for "any version is fine"
                      Example: {"pandas": "1.5.0", "prophet": None}

    Returns:
        List of package names that are missing or below minimum version.
        Empty list means all requirements are satisfied.
    """
    IMPORT_NAME_MAP = {
        # Some packages have different install names vs. import names
        "sklearn": "scikit-learn",
        "cv2": "opencv-python",
        "PIL": "Pillow",
    }

    problems = []

    print(f"\n{'Package':<30} {'Required':<15} {'Installed':<15} {'Status'}")
    print(f"{'-'*30} {'-'*15} {'-'*15} {'-'*20}")

    for package_import_name, min_version in requirements.items():
        display_name = IMPORT_NAME_MAP.get(package_import_name, package_import_name)
        required_str = min_version if min_version else "any"

        try:
            mod = importlib.import_module(package_import_name)
            installed_version = getattr(mod, "__version__", "unknown")

            if min_version and installed_version != "unknown":
                # Simple string comparison — adequate for typical semver
                if installed_version < min_version:
                    status = "VERSION TOO OLD"
                    problems.append(package_import_name)
                else:
                    status = "OK"
            else:
                status = "OK"

            print(f"{display_name:<30} {required_str:<15} {installed_version:<15} {status}")

        except ImportError:
            status = "MISSING"
            problems.append(package_import_name)
            print(f"{display_name:<30} {required_str:<15} {'---':<15} {status}")

    print()
    if problems:
        print(f"Action required for {len(problems)} package(s): {', '.join(problems)}")
    else:
        print("All requirements satisfied.")

    return problems


# Test against the scenario requirements
scenario_requirements = {
    "pandas":       "1.5.0",
    "sklearn":      "1.2.0",
    "prophet":      None,       # any version; prophet may not exist under this name
    "pyarrow":      "10.0.0",
    "statsmodels":  "0.13.0",
}

missing = check_project_requirements(scenario_requirements)
```

**Package request process for air-gapped Databricks GovCloud:**

For any package on the `missing` list:

1. Identify the exact version needed and its dependencies:
   ```
   pip download prophet --dest /tmp/wheels/ --no-deps
   # Repeat for each dependency (check requirements with: pip show prophet)
   ```

2. Transfer wheel files through your organization's approved data transfer process (typically a secure file upload portal or your security officer's data transfer workflow).

3. Upload to DBFS in your Databricks workspace:
   ```python
   dbutils.fs.cp("file:/local/path/prophet-1.1.4-py3-none-any.whl",
                  "dbfs:/shared/approved_packages/prophet-1.1.4-py3-none-any.whl")
   ```

4. Install in your notebook session:
   ```python
   %pip install /dbfs/shared/approved_packages/prophet-1.1.4-py3-none-any.whl
   ```

5. Document the package, version, and approval ticket number in your project README.

---

## Exercise 2 Solution: The Spark/pandas Boundary

```python
from pyspark.sql import functions as F


def safe_topandas(spark_df, max_rows: int = 500_000):
    """
    Convert a Spark DataFrame to pandas with a row count guard.
    Raises ValueError if the DataFrame exceeds the safe threshold.
    """
    count = spark_df.count()
    if count > max_rows:
        raise ValueError(
            f"DataFrame has {count:,} rows — exceeds safe threshold of {max_rows:,}. "
            f"Apply additional filters before converting to pandas."
        )
    return spark_df.toPandas()


def analyze_navy_contract_awards_corrected(spark):
    """
    Corrected version of the teammate's notebook code.
    All filtering and aggregation happens in Spark before collection.
    """
    contract_actions = spark.table("procurement.gold.contract_actions_fy2024")

    # Step 1: Filter in Spark (not pandas)
    navy_only = contract_actions.filter(F.col("awarding_agency") == "Navy")

    # Step 2: Aggregate in Spark — this produces at most ~60 rows (12 months x 5 types)
    monthly_summary_spark = (
        navy_only
        .groupBy("fy_month", "competition_type")
        .agg(
            F.sum("obligation_amount").alias("total_obligation"),
            F.count("contract_id").alias("award_count"),
            F.avg("obligation_amount").alias("avg_obligation")
        )
        .orderBy("fy_month", "competition_type")
    )

    # Step 3: Convert the tiny result to pandas — safe because it's aggregated
    monthly_summary_pd = safe_topandas(monthly_summary_spark, max_rows=500_000)

    print(monthly_summary_pd)
    return monthly_summary_pd


# Local test version using synthetic data
def test_with_synthetic_data():
    from pyspark.sql import SparkSession
    import sys
    sys.path.insert(0, "../../code-examples/python")
    from data_structures import build_sample_procurement_dataframe

    spark = SparkSession.getActiveSession()
    if spark is None:
        print("No Spark session — run this on Databricks or a local Spark installation")
        return

    # Convert synthetic pandas df to Spark for testing
    pdf = build_sample_procurement_dataframe()
    pdf = pdf.rename(columns={"contract_id": "contract_id"})
    spark_df = spark.createDataFrame(pdf)

    # Apply the corrected pattern
    result = (
        spark_df
        .filter(F.col("awarding_agency") == "Navy")
        .groupBy("awarding_agency", "competition_type")
        .agg(F.sum("obligation_amount").alias("total_obligation"))
    )

    pd_result = safe_topandas(result)
    print(pd_result)
    return pd_result
```

**Explanation of Spark query optimizer behavior:**

When you call `.filter()` before `.toPandas()`, Spark's Catalyst optimizer includes the filter condition in the physical execution plan. The underlying Delta file reader applies partition pruning and predicate pushdown — it reads only the Parquet files and row groups that could contain rows matching `awarding_agency == "Navy"`, skipping the rest entirely. When you filter after `.toPandas()`, the entire 18-million-row table is transferred to the driver node as a pandas DataFrame, then filtered in Python — which means 18 million rows were read, transferred, and held in memory for the sole purpose of discarding 70-80% of them immediately afterward.

---

## Exercise 3 Solution: CAC-Aware Authentication Design

```python
import os
import logging
from typing import Optional

logger = logging.getLogger(__name__)


def get_api_token() -> str:
    """
    Retrieve the DoD logistics API bearer token from secure storage.

    Primary source: Databricks Secret Scope (production)
    Fallback: LOGISTICS_API_TOKEN environment variable (development/testing)

    Returns:
        Bearer token string

    Raises:
        EnvironmentError: If the token is missing or fails the length sanity check
    """
    token: Optional[str] = None

    # Try Databricks Secret Scope first (production path)
    try:
        # dbutils is injected by Databricks — unavailable outside notebooks
        # We try to import it; if it fails, we fall through to env var
        import IPython
        ip = IPython.get_ipython()
        if ip and "dbutils" in ip.user_ns:
            dbutils = ip.user_ns["dbutils"]
            token = dbutils.secrets.get(scope="logistics-api", key="bearer-token")
    except Exception:
        pass  # Not in a Databricks notebook context

    # Fall back to environment variable (local dev / CI testing)
    if not token:
        token = os.environ.get("LOGISTICS_API_TOKEN")

    # Validate
    if not token:
        raise EnvironmentError(
            "API token not found. To fix this:\n"
            "  Production (Databricks): Run the following in a notebook cell:\n"
            "    dbutils.secrets.createScope('logistics-api')  # if scope doesn't exist\n"
            "    # Then add the token via Databricks CLI:\n"
            "    # databricks secrets put --scope logistics-api --key bearer-token\n"
            "  Local development: Set environment variable:\n"
            "    export LOGISTICS_API_TOKEN='your_token_here'\n"
        )

    if len(token) < 80:
        raise EnvironmentError(
            f"Token appears invalid: expected >= 80 characters, got {len(token)}. "
            "Contact your identity management office to issue a new token."
        )

    return token


def make_authenticated_request(endpoint: str, params: dict) -> dict:
    """
    Make an authenticated GET request to an internal DoD API.

    Args:
        endpoint: Full URL of the API endpoint (internal network only)
        params: Query parameters dict

    Returns:
        Parsed JSON response as dict

    Raises:
        ConnectionError: If the request fails after retry
        ValueError: If the response is not valid JSON
    """
    import requests
    from requests.exceptions import ConnectionError as RequestsConnectionError, Timeout

    token = get_api_token()
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
        "X-Request-Source": "logistics-analytics-pipeline",
    }

    # Log request without token value
    logger.info(f"GET {endpoint} | params={list(params.keys())}")

    try:
        response = requests.get(
            endpoint,
            headers=headers,
            params=params,
            timeout=30,  # internal DoD APIs can be slow
        )
        logger.info(f"Response: {response.status_code}")
        response.raise_for_status()
        return response.json()

    except (RequestsConnectionError, Timeout) as e:
        raise ConnectionError(
            f"Could not reach {endpoint}. "
            "Check that you are on the DoD network (VPN or on-prem). "
            f"Original error: {e}"
        )
    except ValueError as e:
        raise ValueError(
            f"API response from {endpoint} was not valid JSON. "
            f"Status: {response.status_code} | Content: {response.text[:200]}"
        ) from e


# Local test: verify the env var fallback works
def test_auth_locally():
    """
    Test that authentication works with an environment variable set.
    Run this locally before deploying to the platform.
    """
    os.environ["LOGISTICS_API_TOKEN"] = "a" * 90  # synthetic token of correct length

    token = get_api_token()
    assert len(token) >= 80, "Token length check failed"
    print("Local auth test passed — token retrieval works via environment variable")

    del os.environ["LOGISTICS_API_TOKEN"]  # clean up

    try:
        get_api_token()
        print("ERROR: Should have raised EnvironmentError with no token set")
    except EnvironmentError as e:
        print(f"Missing token raises correct error:\n  {str(e)[:100]}...")
    print("All auth tests passed")


if __name__ == "__main__":
    test_auth_locally()
```

---

## Exercise 4 Solution: Bronze/Silver Data Promotion

```python
from pyspark.sql import SparkSession, functions as F, types as T
from pyspark.sql.window import Window


def bronze_to_silver_maintenance(raw_df):
    """
    Promote raw bronze maintenance work orders to silver tier.

    Cleaning steps applied (in order):
    1. Standardize date formats to DateType
    2. Standardize maintenance_category to uppercase
    3. Drop records with null hull_number or start_date
    4. Deduplicate on work_order_id (keep latest start_date)
    5. Drop records with negative labor_hours
    6. Compute days_to_complete
    7. Compute data_quality_score

    Returns:
        Silver-tier Spark DataFrame with clean schema
    """

    # Step 1: Parse both date formats into DateType
    # coalesce tries the first non-null result of the expressions provided
    date_expr_start = F.coalesce(
        F.to_date(F.col("start_date"), "MM/dd/yyyy"),
        F.to_date(F.col("start_date"), "yyyy-MM-dd"),
    )
    date_expr_completion = F.coalesce(
        F.to_date(F.col("completion_date"), "MM/dd/yyyy"),
        F.to_date(F.col("completion_date"), "yyyy-MM-dd"),
    )

    df = (
        raw_df
        .withColumn("start_date_parsed", date_expr_start)
        .withColumn("completion_date_parsed", date_expr_completion)
    )

    # Step 2: Standardize categorical fields
    df = df.withColumn("maintenance_category", F.upper(F.trim(F.col("maintenance_category"))))

    # Step 3: Drop records with null required fields
    df = df.filter(
        F.col("hull_number").isNotNull() &
        F.col("start_date_parsed").isNotNull()
    )

    # Step 4: Deduplicate — keep the row with the latest start_date for each work_order_id
    window_dedup = Window.partitionBy("work_order_id").orderBy(
        F.col("start_date_parsed").desc()
    )
    df = (
        df
        .withColumn("row_rank", F.row_number().over(window_dedup))
        .filter(F.col("row_rank") == 1)
        .drop("row_rank")
    )

    # Step 5: Drop negative labor hours
    df = df.filter(F.col("labor_hours") >= 0)

    # Step 6: Compute days_to_complete (null if completion_date is null)
    df = df.withColumn(
        "days_to_complete",
        F.when(
            F.col("completion_date_parsed").isNotNull(),
            F.datediff(F.col("completion_date_parsed"), F.col("start_date_parsed"))
        ).otherwise(F.lit(None).cast(T.IntegerType()))
    )

    # Step 7: Compute data quality score
    df = df.withColumn(
        "data_quality_score",
        (
            F.when(F.col("cost_dollars").isNotNull(), 25).otherwise(0) +
            F.when(F.col("technician_nec").isNotNull(), 25).otherwise(0) +
            F.when(
                F.col("days_to_complete").isNotNull() &
                (F.col("days_to_complete").between(1, 365)),
                25
            ).otherwise(0) +
            F.when(F.col("completion_date_parsed").isNotNull(), 25).otherwise(0)
        ).cast(T.IntegerType())
    )

    # Final column selection — clean silver schema, no raw date strings or notes
    silver_df = df.select(
        "work_order_id",
        "hull_number",
        "start_date_parsed",
        "completion_date_parsed",
        "maintenance_category",
        "labor_hours",
        "cost_dollars",
        "technician_nec",
        "days_to_complete",
        "data_quality_score",
    ).withColumnRenamed("start_date_parsed", "start_date") \
     .withColumnRenamed("completion_date_parsed", "completion_date")

    return silver_df


def test_bronze_to_silver():
    """
    Test bronze_to_silver_maintenance with synthetic rows covering all edge cases.
    """
    spark = SparkSession.getActiveSession()
    if spark is None:
        print("Requires active SparkSession")
        return

    schema = T.StructType([
        T.StructField("work_order_id", T.StringType()),
        T.StructField("hull_number", T.StringType()),
        T.StructField("start_date", T.StringType()),
        T.StructField("completion_date", T.StringType()),
        T.StructField("maintenance_category", T.StringType()),
        T.StructField("labor_hours", T.DoubleType()),
        T.StructField("cost_dollars", T.DoubleType()),
        T.StructField("technician_nec", T.StringType()),
        T.StructField("notes", T.StringType()),
    ])

    test_data = [
        # Valid records
        ("WO001", "DDG-51", "2024-01-10", "2024-01-25", "PLANNED", 40.0, 15000.0, "EM3", "Normal"),
        ("WO002", "DDG-52", "01/15/2024", "02/01/2024", "planned", 80.0, None, "EN2", "No cost"),
        ("WO003", "LCS-1",  "2024-02-01", "2024-02-15", "Unplanned", 20.0, 5000.0, None, "No NEC"),
        ("WO004", "DDG-51", "2024-03-01", None, "PLANNED", 10.0, None, None, "Still open"),
        # Duplicates (WO001 appears again with older date — should keep original)
        ("WO001", "DDG-51", "2023-12-01", "2023-12-20", "PLANNED", 30.0, 12000.0, "EM3", "Older dup"),
        # Duplicate (WO002 with same date — keep one)
        ("WO002", "DDG-52", "01/15/2024", "02/01/2024", "planned", 80.0, None, "EN2", "Exact dup"),
        # Null hull_number — should be dropped
        (None,    None,     "2024-01-01", "2024-01-10", "PLANNED", 10.0, 1000.0, "EM2", "No ship"),
        # Null start_date — should be dropped
        ("WO005", "CG-47", None, "2024-02-01", "PLANNED", 25.0, 8000.0, "MM1", "No start"),
        # Negative labor hours — should be dropped
        ("WO006", "DDG-53", "2024-03-01", "2024-03-05", "PLANNED", -5.0, 2000.0, "EN3", "Neg hours"),
        # Both date formats in same batch
        ("WO007", "LCS-2",  "04/01/2024", "04/10/2024", "planned", 16.0, 3000.0, "IC1", "MM/DD format"),
        ("WO008", "DDG-54", "2024-04-15", "2024-04-30", "UNPLANNED", 60.0, 25000.0, "EN1", "YYYY-MM format"),
        # Category capitalization variants
        ("WO009", "DDG-55", "2024-05-01", "2024-05-20", "planned",    50.0, 18000.0, "EM2", "lowercase"),
        ("WO010", "DDG-56", "2024-05-15", "2024-06-01", "Planned",    45.0, 16000.0, "EN3", "Titlecase"),
        ("WO011", "DDG-57", "2024-06-01", "2024-06-10", "UNPLANNED",  35.0, 12000.0, "MM2", "UPPER"),
        # Full quality record (should score 100)
        ("WO012", "DDG-58", "2024-06-15", "2024-07-01", "PLANNED",    70.0, 30000.0, "EN1", "Full data"),
        # Zero-quality record
        ("WO013", "DDG-59", "2024-07-01", None, "PLANNED", 5.0, None, None, "Minimal"),
    ]

    raw_df = spark.createDataFrame(test_data, schema)

    print(f"Input rows: {raw_df.count()}")
    silver_df = bronze_to_silver_maintenance(raw_df)
    print(f"Output rows: {silver_df.count()}")

    # Collect for assertions
    result = silver_df.toPandas()

    # Assertion 1: No duplicate work_order_ids
    assert result["work_order_id"].nunique() == len(result), \
        "Duplicate work_order_ids found in silver output"

    # Assertion 2: No null hull_number or start_date
    assert result["hull_number"].isnull().sum() == 0, "Null hull_number in silver"
    assert result["start_date"].isnull().sum() == 0, "Null start_date in silver"

    # Assertion 3: No negative labor_hours
    assert (result["labor_hours"] >= 0).all(), "Negative labor_hours in silver"

    # Assertion 4: data_quality_score in valid range
    assert result["data_quality_score"].between(0, 100).all(), \
        "data_quality_score out of range [0, 100]"

    # Assertion 5: All maintenance categories are uppercase
    non_upper = result[result["maintenance_category"] != result["maintenance_category"].str.upper()]
    assert len(non_upper) == 0, f"Non-uppercase categories found: {non_upper['maintenance_category'].tolist()}"

    print("\nAll assertions passed.")
    print(result[["work_order_id", "hull_number", "maintenance_category",
                   "days_to_complete", "data_quality_score"]].to_string())
```

---

## Exercise 5 Solution: Platform Comparison Table

| Criterion | Databricks | Palantir Foundry | Advantage |
|---|---|---|---|
| Python environment | Pre-configured cluster (DBR) | Conda in Code Workspaces | **Tie** — different UX, same capability |
| R support | Yes (DBR natively) | Yes (Transforms + Code Workspaces) | **Tie** |
| Notebook experience | Browser-based, Jupyter-like | VS Code IDE (Code Workspaces) | **Foundry** for serious development |
| Version control | GitLab integration | Foundry branching system | **Tie** — both support code review workflows |
| Collaboration (co-editing) | Yes — real-time co-authoring | No notebook co-editing | **Databricks** |
| Package management flexibility | Cluster libs + approved wheels | Conda environments per workspace | **Foundry** (more flexible per-project) |
| ML deployment | MLflow + Workflows (native) | Transforms + AIP Logic | **Databricks** (more mature open tooling) |
| Analyst self-service | Databricks SQL + dashboards | Workshop (no-code apps) | **Foundry** (richer non-coder experience) |
| New-user learning curve | Low (familiar notebook UX) | Medium (Ontology is novel) | **Databricks** |
| IL4 availability | Yes (AWS GovCloud DoD, IL5) | Yes (FedRAMP High Dec 2024) | **Tie** |

**Recommendation:** For a 6-person team that is new to both platforms, with analysts who need visualization and a data scientist team running scikit-learn models on a schedule, start on Databricks. The lower learning curve means your team becomes productive in weeks rather than months, the MLflow integration handles your deployment requirement natively, and the real-time co-authoring makes collaborative EDA sessions practical. Switch to Palantir Foundry when — and only when — you need the Ontology's operational writeback capabilities (taking actions from data, not just reporting on it), or when your analysts need no-code application building that goes beyond dashboards.

**One open question:** Does your organization already have an existing Advana Databricks workspace provisioned, or does this project need to negotiate its own compute environment? The answer changes the procurement timeline significantly — an existing Advana workspace means you could start in days; a new standalone GovCloud workspace takes weeks to stand up.

---

*These solutions represent one correct approach. If your solution produces the same outputs with different code, it is equally valid. The key correctness criteria are: does it handle the specified edge cases, does it follow government platform security constraints, and would it actually run on the target platform?*
