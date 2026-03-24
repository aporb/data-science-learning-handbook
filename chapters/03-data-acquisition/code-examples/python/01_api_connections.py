"""
Chapter 03: Data Acquisition - API Connections
=================================================
Federal open data API patterns: USAspending, SAM.gov, Census Bureau.

All APIs used here are publicly accessible with free registration or no
authentication. No CAC required. Safe to run from any network.

Requirements:
    pip install requests pandas python-dotenv

Environment variables (optional, for SAM/Census API keys):
    SAM_API_KEY     - From api.sam.gov (free registration)
    CENSUS_API_KEY  - From api.census.gov/data/key_signup.html (free)
"""

import os
import time
import requests
import pandas as pd
from typing import Optional

# ---------------------------------------------------------------------------
# 1. USAspending.gov — No authentication required
# ---------------------------------------------------------------------------

USASPENDING_BASE = "https://api.usaspending.gov/api/v2"


def fetch_agency_spending(
    agency_name: str,
    fiscal_year: int = 2024,
    limit: int = 100,
) -> pd.DataFrame:
    """
    Pull contract spending by awarding agency from USAspending.
    Returns a DataFrame with contract awards.

    Args:
        agency_name: Partial name match (e.g. "Department of the Navy")
        fiscal_year: FY to query (2004-present)
        limit: Records per page (max 100 for this endpoint)

    Returns:
        DataFrame with contract awards
    """
    url = f"{USASPENDING_BASE}/search/spending_by_award/"

    payload = {
        "subawards": False,
        "limit": limit,
        "page": 1,
        "sort": "Award Amount",
        "order": "desc",
        "filters": {
            "time_period": [
                {"start_date": f"{fiscal_year - 1}-10-01", "end_date": f"{fiscal_year}-09-30"}
            ],
            "award_type_codes": ["A", "B", "C", "D"],  # Definitive contracts
            "awarding_agency_names": [agency_name],
        },
        "fields": [
            "Award ID",
            "Recipient Name",
            "Award Amount",
            "Awarding Agency",
            "Awarding Sub Agency",
            "Award Type",
            "NAICS Code",
            "NAICS Description",
            "Period of Performance Start Date",
            "Period of Performance Current End Date",
        ],
    }

    all_records = []
    total_pages = None

    while True:
        response = requests.post(url, json=payload, timeout=30)
        response.raise_for_status()
        data = response.json()

        results = data.get("results", [])
        all_records.extend(results)

        if total_pages is None:
            total = data.get("page_metadata", {}).get("total", 0)
            total_pages = -(-total // limit)  # Ceiling division
            print(f"  Total records: {total:,} across {total_pages} pages")

        # Stop if we have retrieved all pages or hit 500 records (demo limit)
        if len(all_records) >= min(total, 500) or payload["page"] >= total_pages:
            break

        payload["page"] += 1
        time.sleep(0.2)  # Polite delay — 1,000 req/hr rate limit

    df = pd.json_normalize(all_records)
    return df


def fetch_award_detail(award_id: str) -> dict:
    """
    Fetch full detail for a single USAspending award.

    Args:
        award_id: The Award ID from a prior search (e.g. "CONT_AWD_N0002421C0001")

    Returns:
        Dict with full award metadata
    """
    url = f"{USASPENDING_BASE}/awards/{award_id}/"
    response = requests.get(url, timeout=30)
    response.raise_for_status()
    return response.json()


def download_spending_file(
    agency_code: str,
    fiscal_year: int = 2024,
    output_path: str = "spending_download.zip",
) -> str:
    """
    Request a bulk spending data file download.
    USAspending generates the file asynchronously — this polls until ready.

    Args:
        agency_code: 3-digit agency identifier (e.g. "017" for Navy)
        fiscal_year: FY to download
        output_path: Local path to save the zip file

    Returns:
        Path to downloaded file
    """
    # Step 1: Submit download request
    request_url = f"{USASPENDING_BASE}/download/awards/"
    payload = {
        "filters": {
            "time_period": [
                {"start_date": f"{fiscal_year - 1}-10-01", "end_date": f"{fiscal_year}-09-30"}
            ],
            "award_type_codes": ["A", "B", "C", "D"],
            "agency": agency_code,
        },
        "columns": [],
        "file_format": "csv",
    }

    response = requests.post(request_url, json=payload, timeout=30)
    response.raise_for_status()
    file_url = response.json()["file_url"]
    status_url = response.json()["status_url"]

    # Step 2: Poll until the file is ready
    print("  Waiting for file generation...", end="", flush=True)
    for attempt in range(60):
        status_response = requests.get(status_url, timeout=30)
        status_data = status_response.json()
        if status_data.get("status") == "finished":
            print(" done.")
            break
        print(".", end="", flush=True)
        time.sleep(5)
    else:
        raise TimeoutError("Download did not complete within 5 minutes")

    # Step 3: Download the file
    file_response = requests.get(file_url, stream=True, timeout=120)
    file_response.raise_for_status()
    with open(output_path, "wb") as f:
        for chunk in file_response.iter_content(chunk_size=8192):
            f.write(chunk)

    print(f"  Saved to: {output_path}")
    return output_path


# ---------------------------------------------------------------------------
# 2. SAM.gov — Requires free API key
# ---------------------------------------------------------------------------

SAM_BASE = "https://api.sam.gov/entity-information/v3"


def fetch_sam_entity(cage_code: str, api_key: str) -> dict:
    """
    Look up a vendor's SAM registration by CAGE code.

    The entity registration includes business size, socioeconomic status
    (8(a), SDVOSB, WOSB), primary NAICS, active/inactive status, and
    whether the entity has any active exclusions.

    Args:
        cage_code: 5-character CAGE code (e.g. "7V490" for Booz Allen)
        api_key: Your SAM.gov API key from api.sam.gov

    Returns:
        Dict with entity registration data
    """
    params = {
        "api_key": api_key,
        "cageCode": cage_code,
        "includeSections": "entityRegistration,coreData,assertions,repsAndCerts",
    }

    response = requests.get(f"{SAM_BASE}/entities", params=params, timeout=30)
    response.raise_for_status()

    data = response.json()
    entities = data.get("entityData", [])
    if not entities:
        return {}

    return entities[0]


def search_sam_entities(
    naics_code: str,
    business_size: str = "S",  # "S" = small, "O" = other than small
    api_key: Optional[str] = None,
    max_results: int = 100,
) -> pd.DataFrame:
    """
    Search SAM for active vendors in a NAICS code.
    Useful for building competitive landscape analysis.

    Args:
        naics_code: 6-digit NAICS code (e.g. "541511" for Custom Computer Programming)
        business_size: "S" for small, "O" for other-than-small
        api_key: SAM API key — falls back to env var SAM_API_KEY
        max_results: Maximum records to retrieve

    Returns:
        DataFrame with matching entities
    """
    api_key = api_key or os.environ.get("SAM_API_KEY", "")
    if not api_key:
        raise ValueError(
            "SAM API key required. Set SAM_API_KEY env var or pass api_key argument. "
            "Register at https://api.sam.gov"
        )

    params = {
        "api_key": api_key,
        "primaryNaics": naics_code,
        "businessTypeCode": "2L" if business_size == "S" else "",  # 2L = Small Business
        "registrationStatus": "A",  # Active only
        "includeSections": "entityRegistration,coreData",
        "pageSize": min(max_results, 100),
        "pageNumber": 0,
    }

    all_entities = []

    while len(all_entities) < max_results:
        response = requests.get(f"{SAM_BASE}/entities", params=params, timeout=30)
        response.raise_for_status()
        data = response.json()

        entities = data.get("entityData", [])
        all_entities.extend(entities)

        total_records = data.get("totalRecords", 0)
        if len(all_entities) >= total_records or not entities:
            break

        params["pageNumber"] += 1
        time.sleep(0.1)  # SAM rate limit: 10 req/sec, 10,000 req/day

    # Flatten the nested entity structure
    rows = []
    for entity in all_entities:
        reg = entity.get("entityRegistration", {})
        core = entity.get("coreData", {})
        address = core.get("physicalAddress", {})
        rows.append(
            {
                "legal_business_name": reg.get("legalBusinessName"),
                "cage_code": reg.get("cageCode"),
                "uei": reg.get("ueiSAM"),
                "registration_status": reg.get("registrationStatus"),
                "registration_expiry": reg.get("registrationExpirationDate"),
                "state": address.get("stateOrProvinceCode"),
                "city": address.get("city"),
                "primary_naics": reg.get("primaryNaics"),
            }
        )

    return pd.DataFrame(rows)


# ---------------------------------------------------------------------------
# 3. Census Bureau API — Requires free API key
# ---------------------------------------------------------------------------

CENSUS_BASE = "https://api.census.gov/data"


def fetch_acs_data(
    variables: list[str],
    geography: str = "county",
    state_fips: str = "*",
    year: int = 2022,
    dataset: str = "acs/acs5",
    api_key: Optional[str] = None,
) -> pd.DataFrame:
    """
    Fetch American Community Survey data from Census API.

    Variables use Census API codes — look them up at:
    https://api.census.gov/data/2022/acs/acs5/variables.html

    Common variables:
        B01003_001E - Total population
        B19013_001E - Median household income
        B15003_022E - Bachelor's degree count
        B25001_001E - Total housing units

    Args:
        variables: List of Census variable codes (without "NAME")
        geography: "county", "state", "tract", "block group"
        state_fips: 2-digit state FIPS or "*" for all states
        year: Survey year (ACS 5-year: 2009-2022 typical range)
        dataset: "acs/acs5" (5-year) or "acs/acs1" (1-year, larger geographies only)
        api_key: Census API key — falls back to env var CENSUS_API_KEY

    Returns:
        DataFrame with requested variables and FIPS codes
    """
    api_key = api_key or os.environ.get("CENSUS_API_KEY", "DEMO_KEY")

    # Census API returns NAME (human-readable label) + requested variables
    get_vars = ",".join(["NAME"] + variables)

    params = {
        "get": get_vars,
        "for": f"{geography}:*",
        "key": api_key,
    }

    # Add state filter for sub-state geographies
    if geography in ("county", "tract", "block group") and state_fips != "*":
        params["in"] = f"state:{state_fips}"
    elif geography in ("tract", "block group"):
        # Tract and block group require a specific state
        params["in"] = f"state:{state_fips}"

    url = f"{CENSUS_BASE}/{year}/{dataset}"
    response = requests.get(url, params=params, timeout=60)
    response.raise_for_status()

    # Census returns a JSON array: first row is headers, rest is data
    raw = response.json()
    headers = raw[0]
    rows = raw[1:]

    df = pd.DataFrame(rows, columns=headers)

    # Build a full FIPS code — must be kept as string to preserve leading zeros
    if geography == "county":
        df["fips"] = df["state"].str.zfill(2) + df["county"].str.zfill(3)
    elif geography == "tract":
        df["fips"] = (
            df["state"].str.zfill(2) + df["county"].str.zfill(3) + df["tract"].str.zfill(6)
        )

    # Convert numeric columns — Census stores numbers as strings
    for col in variables:
        if col.endswith("E"):  # Estimate columns (vs M = margin of error)
            df[col] = pd.to_numeric(df[col], errors="coerce")

    return df


# ---------------------------------------------------------------------------
# 4. Retry / backoff wrapper — applies to any requests call
# ---------------------------------------------------------------------------

def get_with_backoff(
    url: str,
    params: Optional[dict] = None,
    max_retries: int = 5,
    initial_wait: float = 1.0,
    **kwargs,
) -> requests.Response:
    """
    GET request with exponential backoff on 429 and 5xx responses.

    Federal APIs are rate-limited more aggressively than commercial APIs.
    This wrapper handles transient failures without manual intervention.

    Args:
        url: Request URL
        params: Query parameters
        max_retries: Maximum retry attempts
        initial_wait: Initial wait in seconds (doubles each retry, + jitter)
        **kwargs: Additional arguments passed to requests.get()

    Returns:
        Response object

    Raises:
        requests.HTTPError: If max_retries exceeded
    """
    import random

    wait = initial_wait
    for attempt in range(max_retries):
        response = requests.get(url, params=params, timeout=30, **kwargs)

        if response.status_code == 200:
            return response

        if response.status_code == 429 or response.status_code >= 500:
            if attempt < max_retries - 1:
                jitter = random.uniform(0, wait * 0.1)
                actual_wait = wait + jitter
                print(f"  HTTP {response.status_code}, retrying in {actual_wait:.1f}s "
                      f"(attempt {attempt + 1}/{max_retries})")
                time.sleep(actual_wait)
                wait *= 2  # Exponential backoff
            else:
                response.raise_for_status()
        else:
            response.raise_for_status()

    response.raise_for_status()
    return response  # Unreachable but satisfies type checker


# ---------------------------------------------------------------------------
# Demo / usage example
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("=== USAspending: DoN Contract Awards FY2024 ===")
    df_awards = fetch_agency_spending(
        agency_name="Department of the Navy",
        fiscal_year=2024,
        limit=100,
    )
    print(f"Records retrieved: {len(df_awards):,}")
    if not df_awards.empty:
        print("\nTop 5 awards by amount:")
        top5 = df_awards.nlargest(5, "Award Amount")[
            ["Award ID", "Recipient Name", "Award Amount", "NAICS Description"]
        ]
        print(top5.to_string(index=False))

    print("\n=== Census ACS: Median Household Income by Maryland County ===")
    df_census = fetch_acs_data(
        variables=["B19013_001E", "B01003_001E"],
        geography="county",
        state_fips="24",  # Maryland
        year=2022,
    )
    df_census.columns = [c.replace("B19013_001E", "median_income")
                          .replace("B01003_001E", "population")
                          for c in df_census.columns]
    print(df_census[["NAME", "fips", "median_income", "population"]].head(10).to_string(index=False))
