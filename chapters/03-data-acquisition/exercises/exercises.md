# Chapter 03 Exercises: Data Acquisition and Government Data Sources

These exercises use only publicly available APIs and synthetic data. No CAC required, no credentials beyond free API key registration. Work through them in order — each one builds on the last.

---

## Exercise 1: USAspending API — Procurement Analysis

**Scenario:** Your program office wants to understand which vendors received the most Navy IT services contracts (NAICS 541512 — Computer Systems Design Services) in FY2023. Before building any model or dashboard, you need to pull the underlying data.

**Task:**

Write a Python script that:

1. Calls the USAspending `/api/v2/search/spending_by_award/` endpoint
2. Filters for: award type codes A–D (definitive contracts), awarding agency "Department of the Navy", NAICS code 541512, fiscal year 2023
3. Paginates through all available records (do not stop at the first page)
4. Saves the result to a DataFrame
5. Prints the top 10 recipients by total obligated amount

**Acceptance criteria:**
- Your script handles pagination correctly and does not silently miss records
- The top 10 output includes recipient name, total obligations, and number of awards
- If the API returns more than 5,000 records, your script prints a warning and recommends switching to the bulk download endpoint

**Hints:**
- Check the `page_metadata.total` field in the first response to know how many records exist
- Group by recipient name after pulling all records, not inside the API query
- USAspending rate limit is 1,000 requests/hour for unauthenticated users

---

## Exercise 2: Census API — Joining to Procurement Data

**Scenario:** Your analysis team wants to understand whether Navy contract awards in NAICS 541512 correlate with regional tech workforce availability. Specifically, do counties with higher STEM employment concentrations receive more contract awards?

**Task:**

1. Using the Census ACS API (year 2022, 5-year estimates), pull the following variables at the county level for Virginia (FIPS state code: 51) and Maryland (FIPS state code: 24):
   - `B01003_001E` — Total population
   - `B15003_022E` — Bachelor's degree holders
   - `B15003_023E` — Master's degree holders
   - `B08301_001E` — Total commuters (proxy for workforce size)

2. Calculate a "degree holder rate" per county: `(bachelor's + master's) / population`

3. From your USAspending pull in Exercise 1, attempt to match awards to counties by recipient address state. USAspending returns a `recipient_location_state_code` field.

4. Summarize: for the top 5 states by award count in your Navy IT contracts pull, what is the average degree holder rate (using Census state-level estimates)?

**Acceptance criteria:**
- FIPS codes are kept as strings, not integers
- The Census API response is parsed correctly (first row is headers, not data)
- You handle the case where a county in the Census data has no matching contracts

---

## Exercise 3: Data Classification Decision Tree

**Scenario:** You have been asked to analyze three different datasets for a Navy analytics project. Before touching any of the data, you need to classify each one and identify the authorized processing environment.

**For each dataset below, determine:**
a) The likely classification level (Public / CUI / PII / PHI / Secret)
b) Which of the five platforms could process this data
c) What access request process is required

**Dataset A:** A FOIA request response containing salary data for 5,000 Navy civilian employees, including names, job titles, GS grades, base pay, and duty station locations.

**Dataset B:** Quarterly contract award data exported from SAM.gov Contract Data (formerly FPDS) for Navy IT contracts, containing vendor names, CAGE codes, award amounts, and period of performance dates. No individual names present.

**Dataset C:** Ship maintenance work order records from a classified Navy ERP system, containing equipment status codes, maintenance due dates, and operational readiness flags. The data is labeled SIPR.

Write your analysis as a structured response addressing each dataset. Your answer should cite the relevant regulation or definition for each classification determination.

**Hints:**
- PII definition: OMB Memorandum M-07-16 and Privacy Act of 1974
- CUI definition: Executive Order 13556 and the CUI Registry at archives.gov
- Secret classification: Executive Order 13526

---

## Exercise 4: Messy File Handling

**Scenario:** You receive a ZIP file as part of a FOIA response. It contains the following files:
- `awards_fy2022.csv` (pipe-delimited, latin-1 encoding)
- `awards_fy2021.csv` (comma-delimited, UTF-8)
- `metadata.xlsx` (3-row header, 2-row footer)
- `data_dictionary.pdf` (machine-generated)
- `scanned_cover_letter.pdf` (scanned image)
- `notes.docx` (Word document, not relevant to analysis)

The awards CSV files contain a `award_date` column with mixed date formats: some rows use `DDMMMYYYY`, others use `MM/DD/YYYY`, and a handful use `YYYYMMDD`.

**Task:**

1. Write a function `process_foia_zip(zip_path)` that:
   - Opens the zip
   - Reads each CSV and Excel file into a DataFrame
   - Attempts to parse the `award_date` column in the CSV files using the multi-format parser from the chapter code examples
   - Returns a dict of `{filename: DataFrame}` for parseable files and prints a summary of what could not be parsed

2. For the combined awards data (FY2021 + FY2022), calculate:
   - Total number of records
   - Date range covered
   - Number of rows where `award_date` could not be parsed

3. What encoding detection approach would you use if you did not know in advance whether a file was latin-1 or UTF-8?

**Acceptance criteria:**
- Your function does not crash if a file in the ZIP is unparseable
- The date parser handles at least 5 format variants
- Output includes a clear count of parsing failures

---

## Exercise 5: API Rate Limit Simulation

**Scenario:** You need to pull 150,000 records from a government API that enforces a rate limit of 100 requests per minute. Each request returns a maximum of 500 records. The API occasionally returns HTTP 429 (Too Many Requests) and HTTP 503 (Service Unavailable) errors.

**Task:**

Write a function `paginated_pull(base_url, params, total_records, page_size=500)` that:

1. Calculates the minimum number of requests required
2. Implements exponential backoff with jitter for 429 and 503 responses
3. Logs progress every 10 pages (e.g., "Page 10/300, 5,000/150,000 records retrieved")
4. Returns a list of all response JSON objects

Then answer the following questions in comments within your code:
- What is the theoretical minimum time to pull all 150,000 records at 100 req/min?
- What is a realistic estimate including the 429 retries?
- At what point does it make sense to request a bulk data dump instead of using the API?

**Acceptance criteria:**
- Backoff starts at 1 second and doubles on each retry (with ±10% jitter)
- The function gives up after 5 consecutive failures on the same page
- Progress logging does not spam the terminal on every request

---

## Exercise 6: Unity Catalog Schema Exploration

**Context:** This exercise is designed for execution within a Databricks notebook in a government cloud environment (Databricks GovCloud DoD or Community, or Azure Databricks). If you do not have access to a Databricks environment, complete the code structure and submit it with the comment `# Would execute in Databricks environment`.

**Task:**

In a Databricks SQL cell or Python notebook, write queries that:

1. List all catalogs available to your account: `SHOW CATALOGS`
2. For a catalog named `sandbox` (or any catalog you have read access to), list all schemas
3. For one schema, list all tables and their row counts
4. For one table, describe the schema including column names, types, and any comments

Then convert the `DESCRIBE TABLE` output to a Pandas DataFrame and add a column indicating which fields appear to contain PII (based on column name heuristics: `ssn`, `name`, `email`, `dob`, `address`, etc.)

**Acceptance criteria:**
- All four SQL queries are correct and execute without error
- The PII detection heuristic covers at least 8 common PII field names
- The output clearly distinguishes between tables you can read and tables that return permission errors

---

See [solutions/solutions.md](solutions/solutions.md) for worked solutions to all exercises.
