# Chapter 02 Exercises: Python and R Foundations for Federal Platforms

These exercises are designed to be completed on a real platform (Databricks or Palantir Foundry) where possible, or locally using the synthetic data generators in the code examples directory when platform access is not available.

Each exercise has a defined platform context. If you don't have access to the specified platform, use the fallback instructions.

---

## Exercise 1: Environment Audit

**Difficulty:** Beginner
**Platform:** Any (Databricks preferred)
**Time:** 15-20 minutes

### Scenario

You've just been onboarded to a new analytics contract supporting a DoD logistics office. Your platform team has provisioned a Databricks workspace on AWS GovCloud (DoD). Before your first technical standup, your senior analyst asks: "Do we have everything we need installed to run the supply chain forecasting model from the last contract?"

The model requires: `pandas >= 1.5`, `scikit-learn >= 1.2`, `prophet`, `pyarrow >= 10.0`, and `statsmodels >= 0.13`.

### Task

1. Using the environment setup script from `code-examples/python/01_environment_setup.py` as a reference, write a function `check_project_requirements(requirements: dict) -> list` that:
   - Takes a dictionary mapping package names to minimum versions (e.g., `{"pandas": "1.5.0", "prophet": None}`)
   - Returns a list of packages that are either missing or below the minimum version
   - Prints a clear summary of what's available, what's missing, and what needs a version upgrade

2. Run it against the requirements listed in the scenario.

3. For any missing packages, write out the exact steps you would take to request them on a government Databricks GovCloud environment (no internet access). Include the wheel file path pattern you would use.

**Deliverable:** A working Python function plus a written package request process for any missing items.

**Fallback (no Databricks access):** Run in a local virtual environment and note which packages would be unavailable in an air-gapped government Databricks runtime.

---

## Exercise 2: The Spark/pandas Boundary

**Difficulty:** Intermediate
**Platform:** Databricks
**Time:** 30-45 minutes

### Scenario

A teammate hands you a Databricks notebook they wrote to analyze DoD contract awards. The notebook works fine on small samples but crashes with an `OutOfMemoryError` on the driver when run against the full fiscal year 2024 contract actions table (approximately 18 million rows).

Here is the problematic code:

```python
# Their original code — this will crash on large tables
df = spark.table("procurement.gold.contract_actions_fy2024").toPandas()

# Then they filter and aggregate in pandas
navy_df = df[df["awarding_agency"] == "Navy"]
monthly_summary = navy_df.groupby(["fy_month", "competition_type"])["obligation_amount"].sum()
print(monthly_summary)
```

### Task

1. Rewrite this code to keep computation in Spark as long as possible. The final result should be a pandas DataFrame with fewer than 100 rows (monthly × competition type combinations for Navy awards).

2. Add a row count check before the `.toPandas()` call that raises a `ValueError` if the Spark DataFrame has more than 500,000 rows — this protects against future modifications that accidentally re-introduce the memory issue.

3. Test your solution with the synthetic procurement data from `code-examples/python/03_data_structures.py` by treating it as if it were a Spark DataFrame. You'll need to create a Spark DataFrame from the pandas DataFrame using `spark.createDataFrame(df)`.

4. Explain in 2-3 sentences what the Spark query optimizer does differently when you filter before `.toPandas()` vs. after.

**Deliverable:** Corrected notebook code plus your explanation of the query optimizer behavior.

**Fallback (no Databricks access):** Complete the pandas version using the synthetic data and write out the Spark equivalent with comments explaining what each Spark operation replaces.

---

## Exercise 3: CAC-Aware Authentication Design

**Difficulty:** Intermediate
**Platform:** Any (design exercise, no platform required)
**Time:** 20-30 minutes

### Scenario

You are building a Python script that runs as a scheduled Databricks Workflow (not interactive). The script needs to:
- Read a Delta table from Unity Catalog (fine — handled by cluster permissions)
- Call an internal API hosted within the DoD network that requires a bearer token for authentication
- Write results back to a Delta table (fine — cluster permissions)

The API token is 90 characters long, expires every 30 days, and is issued by your organization's identity management system.

### Task

1. Write a Python function `get_api_token()` that safely retrieves the token using Databricks Secret Scopes. The function should:
   - Read the token from a secret scope named `"logistics-api"` with key `"bearer-token"`
   - Validate that the token is non-empty and has at least 80 characters (a length sanity check, not real validation)
   - Raise a clear, actionable error message if the token is missing or invalid — the error should tell the operator exactly what to do to fix it

2. Write a second function `make_authenticated_request(endpoint: str, params: dict) -> dict` that:
   - Calls `get_api_token()` internally
   - Makes a GET request to the endpoint with the token in the Authorization header
   - Handles connection errors gracefully (the internal network can be flaky)
   - Logs the request and response status (but never logs the token value)

3. The secret scope doesn't exist in your test environment. Write a local test version using environment variables that your `get_api_token()` function falls back to when `dbutils` is not available.

**Deliverable:** Working Python code with both functions plus the local test version using environment variables.

---

## Exercise 4: Bronze/Silver Data Promotion

**Difficulty:** Intermediate-Advanced
**Platform:** Databricks (or local with synthetic data)
**Time:** 45-60 minutes

### Scenario

You've been asked to build a PySpark transformation that promotes raw maintenance work order data from bronze tier to silver tier on Jupiter. The bronze data is messy: duplicate work order IDs, nulls in required fields, negative completion times (data entry errors), and free-text fields with inconsistent capitalization.

Here is the bronze-tier schema you're working with:

| Column | Type | Notes |
|---|---|---|
| work_order_id | string | Should be unique — but isn't always |
| hull_number | string | Ship identifier (e.g., "DDG-51") |
| start_date | string | Sometimes "MM/DD/YYYY", sometimes "YYYY-MM-DD" |
| completion_date | string | Same inconsistency as start_date |
| maintenance_category | string | Free text: "PLANNED", "Planned", "planned", "UNPLANNED", etc. |
| labor_hours | double | Should be positive — sometimes negative due to data entry |
| cost_dollars | double | Nullable — missing for some older records |
| technician_nec | string | Navy Enlisted Classification code |
| notes | string | Free text — irrelevant for structured analysis |

### Task

1. Write a PySpark transformation function `bronze_to_silver_maintenance(raw_df)` that:
   - Deduplicates on `work_order_id`, keeping the record with the latest `start_date` when there are duplicates
   - Standardizes both date columns to `DateType` (handle both input formats)
   - Standardizes `maintenance_category` to uppercase
   - Drops records where `start_date` or `hull_number` is null (these are required fields)
   - Drops records where `labor_hours` is negative
   - Computes a `days_to_complete` integer column (null if completion_date is null)
   - Adds a `data_quality_score` integer column (0-100) based on: +25 if cost_dollars is not null, +25 if technician_nec is not null, +25 if days_to_complete is between 1 and 365, +25 if completion_date is not null

2. Write a test for your function using `spark.createDataFrame()` with at least 15 synthetic rows that include: 3 duplicates, 2 null required fields, 2 negative labor hours, both date formats, and at least 3 different category capitalizations.

3. Assert that your output DataFrame:
   - Has no duplicate `work_order_id` values
   - Has no null `start_date` or `hull_number` values
   - Has no negative `labor_hours` values
   - Has a `data_quality_score` column with values between 0 and 100

**Deliverable:** Working PySpark function plus test DataFrame and assertions.

---

## Exercise 5: Platform Comparison Table

**Difficulty:** Beginner-Intermediate
**Platform:** None required (research/analysis exercise)
**Time:** 30-40 minutes

### Scenario

Your program office is evaluating whether to do Python-based data science work on Databricks (currently available through Advana) or stand up Palantir Foundry Code Workspaces for a new predictive readiness project. Your program manager asks you to produce a one-page technical comparison.

The project requirements are:
- 3 data scientists, 1 data engineer, 2 analysts
- Data at IL4 (CUI, no classified data)
- Need Python and R
- Need version-controlled code
- Need to share notebooks between team members
- Will build scikit-learn models and deploy them on a schedule
- Analysts need visualization (non-coding users)
- Team is new to both platforms

### Task

1. Using the platform research from this chapter and your own reasoning, fill in the following comparison table. For each cell, write 1-3 words or a very short phrase — this is a decision aid, not an essay.

| Criterion | Databricks | Palantir Foundry | Advantage |
|---|---|---|---|
| Python environment | | | |
| R support | | | |
| Notebook experience | | | |
| Version control | | | |
| Collaboration (co-editing) | | | |
| Package management flexibility | | | |
| ML deployment | | | |
| Analyst self-service | | | |
| New-user learning curve | | | |
| IL4 availability | | | |

2. Based on your completed table, write a 2-3 sentence recommendation for the program manager. Take a position — do not hedge.

3. What is the one piece of information you would want before finalizing your recommendation that is not answerable from the platform research alone?

**Deliverable:** Completed comparison table, recommendation paragraph, and your one open question.

---

## Solutions

Solutions to all five exercises are in [solutions/solutions.md](./solutions/solutions.md).

Attempt each exercise before reading the solutions. The solutions show one correct approach — your solution may be different and equally valid. The questions to ask about your own solution: Does it work correctly? Is it readable? Does it handle the specific government context (security, data quality, platform constraints)?
