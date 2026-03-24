"""
Chapter 03: Data Acquisition - Platform Data Catalogs
========================================================
Working with data catalogs on the five federal platforms:
  - Databricks Unity Catalog (SQL-based discovery)
  - Palantir Foundry Ontology (REST API discovery)
  - Generic CAC-authenticated HTTP client pattern

Note on platform-specific code:
  The Advana and Jupiter catalog interfaces (Collibra) are accessed via
  web browser and require a CAC. Programmatic Collibra access uses the
  Collibra REST API, which requires credentials provisioned by your
  Collibra administrator. The patterns below show how that works.

  Palantir Foundry's REST APIs are publicly documented at:
  https://www.palantir.com/docs/foundry/

  Databricks Unity Catalog is documented at:
  https://docs.databricks.com/en/data-governance/unity-catalog/

Requirements:
    pip install databricks-sdk requests pandas
"""

import os
import requests
import pandas as pd
from typing import Optional


# ---------------------------------------------------------------------------
# 1. Databricks Unity Catalog — Discovery and Access
# ---------------------------------------------------------------------------

def list_unity_catalog_assets(
    workspace_url: str,
    token: str,
    catalog_name: Optional[str] = None,
    schema_name: Optional[str] = None,
) -> pd.DataFrame:
    """
    List data assets in Databricks Unity Catalog via the REST API.
    Works in any Databricks environment: GovCloud DoD, GovCloud Community,
    Azure Government, or commercial.

    In a government Databricks workspace, your token comes from your
    workspace personal access token or a service principal — never
    hardcode it. Use environment variables or Databricks secrets.

    Args:
        workspace_url: e.g. "https://adb-1234567890.azuredatabricks.net"
        token: Databricks personal access token or service principal token
        catalog_name: Filter to a specific catalog (None = list all catalogs)
        schema_name: Filter to a specific schema within the catalog

    Returns:
        DataFrame listing available data assets
    """
    headers = {"Authorization": f"Bearer {token}"}
    base = workspace_url.rstrip("/")

    if catalog_name is None:
        # List all catalogs this token has access to
        url = f"{base}/api/2.1/unity-catalog/catalogs"
        response = requests.get(url, headers=headers, timeout=30)
        response.raise_for_status()
        catalogs = response.json().get("catalogs", [])
        return pd.DataFrame(
            [
                {
                    "name": c["name"],
                    "comment": c.get("comment", ""),
                    "owner": c.get("owner", ""),
                    "created_at": c.get("created_at", ""),
                }
                for c in catalogs
            ]
        )

    if schema_name is None:
        # List schemas in the specified catalog
        url = f"{base}/api/2.1/unity-catalog/schemas"
        params = {"catalog_name": catalog_name}
        response = requests.get(url, headers=headers, params=params, timeout=30)
        response.raise_for_status()
        schemas = response.json().get("schemas", [])
        return pd.DataFrame(
            [
                {
                    "catalog": s["catalog_name"],
                    "schema": s["name"],
                    "comment": s.get("comment", ""),
                    "owner": s.get("owner", ""),
                }
                for s in schemas
            ]
        )

    # List tables in the specified schema
    url = f"{base}/api/2.1/unity-catalog/tables"
    params = {"catalog_name": catalog_name, "schema_name": schema_name}
    response = requests.get(url, headers=headers, params=params, timeout=30)
    response.raise_for_status()
    tables = response.json().get("tables", [])

    return pd.DataFrame(
        [
            {
                "catalog": t["catalog_name"],
                "schema": t["schema_name"],
                "table": t["name"],
                "table_type": t.get("table_type", ""),
                "comment": t.get("comment", ""),
                "owner": t.get("owner", ""),
                "updated_at": t.get("updated_at", ""),
                "columns": len(t.get("columns", [])),
            }
            for t in tables
        ]
    )


def get_table_schema(
    workspace_url: str,
    token: str,
    full_table_name: str,
) -> pd.DataFrame:
    """
    Get column-level schema for a Unity Catalog table.
    Includes column names, data types, nullable flags, and comments.

    full_table_name format: "catalog.schema.table"
    Example: "navy_logistics.maintenance.work_orders"

    Returns:
        DataFrame with column metadata
    """
    catalog, schema, table = full_table_name.split(".")
    headers = {"Authorization": f"Bearer {token}"}
    base = workspace_url.rstrip("/")

    url = f"{base}/api/2.1/unity-catalog/tables/{full_table_name}"
    response = requests.get(url, headers=headers, timeout=30)
    response.raise_for_status()

    table_info = response.json()
    columns = table_info.get("columns", [])

    return pd.DataFrame(
        [
            {
                "column_name": c["name"],
                "data_type": c.get("type_name", ""),
                "nullable": c.get("nullable", True),
                "comment": c.get("comment", ""),
                "position": c.get("position", i),
            }
            for i, c in enumerate(columns)
        ]
    )


def read_unity_catalog_table(spark, full_table_name: str, limit: Optional[int] = None):
    """
    Read a Unity Catalog table into a Spark DataFrame.
    Run this from within a Databricks notebook.

    The Unity Catalog enforces row-level security and column masking
    transparently — you will only see rows and columns you are authorized
    to see. No special code is needed to respect these controls.

    Args:
        spark: SparkSession (available as `spark` in Databricks notebooks)
        full_table_name: "catalog.schema.table" format
        limit: Optional row limit for exploration

    Returns:
        Spark DataFrame

    Example (in Databricks notebook):
        df = read_unity_catalog_table(spark, "navy_logistics.maintenance.work_orders", limit=1000)
        df.show(5)
    """
    df = spark.table(full_table_name)
    if limit:
        df = df.limit(limit)
    return df


def search_unity_catalog_by_tag(
    workspace_url: str,
    token: str,
    tag_key: str,
    tag_value: Optional[str] = None,
) -> list[dict]:
    """
    Search Unity Catalog for tables tagged with a specific key/value.
    Tags are how data classification and data domain are typically
    labeled in well-managed government Unity Catalog deployments.

    Example tag conventions (agency-specific, but common patterns):
        classification: "CUI", "FOUO", "Unclassified"
        data_domain: "Logistics", "Finance", "Personnel"
        pii_contains: "true", "false"
        data_steward: "firstname.lastname@navy.mil"

    Args:
        workspace_url: Databricks workspace URL
        token: Auth token
        tag_key: Tag key to search for
        tag_value: Optional tag value to match (None matches any value)

    Returns:
        List of table references matching the tag
    """
    headers = {"Authorization": f"Bearer {token}"}
    base = workspace_url.rstrip("/")

    # Unity Catalog search endpoint
    url = f"{base}/api/2.1/unity-catalog/search"
    payload = {
        "query": tag_value if tag_value else "*",
        "asset_types": ["TABLE"],
        "tags": [{"key": tag_key, "value": tag_value}] if tag_value else [{"key": tag_key}],
    }

    response = requests.post(url, json=payload, headers=headers, timeout=30)
    response.raise_for_status()
    return response.json().get("results", [])


# ---------------------------------------------------------------------------
# 2. Palantir Foundry REST API — Ontology Discovery
# ---------------------------------------------------------------------------

def list_foundry_object_types(
    foundry_url: str,
    token: str,
    ontology_rid: str,
) -> pd.DataFrame:
    """
    List all Object Types in a Palantir Foundry Ontology.
    This is the starting point for data discovery in Foundry —
    equivalent to listing tables in a database, but with semantic context.

    Object Types represent real-world concepts (Aircraft, Maintenance Work Order,
    Contract, Supplier) rather than raw table names. Each has properties
    (columns) and link types (relationships to other object types).

    Args:
        foundry_url: Base URL of Foundry instance (e.g. "https://agency.palantirfoundry.com")
        token: Bearer token from Foundry authentication
        ontology_rid: Resource identifier of the ontology
                      (find in Foundry's Ontology Manager or ask your admin)

    Returns:
        DataFrame with object type names, API names, and property counts

    Docs: https://www.palantir.com/docs/foundry/api/ontology-resources/object-types/
    """
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }

    url = f"{foundry_url}/api/v2/ontologies/{ontology_rid}/objectTypes"
    response = requests.get(url, headers=headers, timeout=30)
    response.raise_for_status()

    object_types = response.json().get("data", [])

    return pd.DataFrame(
        [
            {
                "api_name": ot.get("apiName"),
                "display_name": ot.get("displayName", ""),
                "description": ot.get("description", ""),
                "primary_key": ot.get("primaryKey", ""),
                "rid": ot.get("rid", ""),
            }
            for ot in object_types
        ]
    )


def get_foundry_object_type_properties(
    foundry_url: str,
    token: str,
    ontology_rid: str,
    object_type_api_name: str,
) -> pd.DataFrame:
    """
    Get all properties (columns) for a specific Foundry Object Type.
    Properties include type information, descriptions, and whether they
    are indexed for search.

    Args:
        foundry_url: Base Foundry URL
        token: Bearer token
        ontology_rid: Ontology RID
        object_type_api_name: The apiName from list_foundry_object_types()
                               (e.g. "MaintenanceWorkOrder", "Aircraft")

    Returns:
        DataFrame with property names, types, and descriptions
    """
    headers = {"Authorization": f"Bearer {token}"}
    url = (
        f"{foundry_url}/api/v2/ontologies/{ontology_rid}/"
        f"objectTypes/{object_type_api_name}/properties"
    )
    response = requests.get(url, headers=headers, timeout=30)
    response.raise_for_status()

    properties = response.json().get("data", [])
    return pd.DataFrame(
        [
            {
                "property_name": p.get("apiName"),
                "display_name": p.get("displayName", ""),
                "data_type": p.get("dataType", {}).get("type", ""),
                "description": p.get("description", ""),
                "is_indexed": p.get("indexed", False),
            }
            for p in properties
        ]
    )


def search_foundry_objects(
    foundry_url: str,
    token: str,
    ontology_rid: str,
    object_type_api_name: str,
    filters: Optional[dict] = None,
    page_size: int = 1000,
    max_records: int = 10000,
) -> pd.DataFrame:
    """
    Search for and retrieve objects from Foundry's Ontology.
    This is the primary way to pull data from Foundry for analysis.

    The Ontology SDK (OSDK) is the recommended approach for production use,
    but the REST API works for ad hoc queries and smaller datasets.

    filters format: {"property_name": "value"} or {"property_name": {"gte": value}}
    See Foundry docs for full filter syntax:
    https://www.palantir.com/docs/foundry/api/ontology-resources/objects/search/

    Args:
        foundry_url: Base Foundry URL
        token: Bearer token
        ontology_rid: Ontology RID
        object_type_api_name: Object type to query
        filters: Property filters (None = all objects)
        page_size: Records per page (max 1000 for REST API)
        max_records: Stop after this many records

    Returns:
        DataFrame with object properties as columns
    """
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }

    url = (
        f"{foundry_url}/api/v2/ontologies/{ontology_rid}/"
        f"objects/{object_type_api_name}/search"
    )

    payload = {
        "pageSize": min(page_size, 1000),
    }

    if filters:
        # Build a simple equality filter for each key-value pair
        filter_clauses = [
            {"type": "eq", "field": k, "value": v}
            for k, v in filters.items()
        ]
        payload["where"] = (
            filter_clauses[0]
            if len(filter_clauses) == 1
            else {"type": "and", "value": filter_clauses}
        )

    all_objects = []
    next_page_token = None

    while len(all_objects) < max_records:
        if next_page_token:
            payload["pageToken"] = next_page_token

        response = requests.post(url, json=payload, headers=headers, timeout=60)
        response.raise_for_status()
        data = response.json()

        objects = data.get("data", [])
        all_objects.extend(objects)

        next_page_token = data.get("nextPageToken")
        if not next_page_token or not objects:
            break

    if not all_objects:
        return pd.DataFrame()

    # Flatten object properties — Foundry returns {"properties": {...}} per object
    rows = [obj.get("properties", {}) for obj in all_objects]
    df = pd.DataFrame(rows)

    print(f"  Retrieved {len(df):,} {object_type_api_name} objects")
    return df


# ---------------------------------------------------------------------------
# 3. CAC-authenticated HTTP client
# ---------------------------------------------------------------------------

class CACSession(requests.Session):
    """
    A requests Session pre-configured for CAC (Common Access Card) authentication
    against .mil endpoints.

    CAC authentication uses mutual TLS: your CAC holds an X.509 certificate
    and private key. The server validates your certificate against the DoD PKI.

    The DoD root CA bundle is available at:
    https://public.cyber.mil/pki-pke/pkipke-document-library/

    Download "certificates_pkcs7_DoD.zip", extract, and convert to PEM:
        openssl pkcs7 -in DoD_PKE_CA_chain.pem.p7b -print_certs -out dod_ca_bundle.pem

    Usage:
        session = CACSession(
            cert_path="/path/to/cac_cert.pem",
            key_path="/path/to/cac_key.pem",
            dod_ca_bundle="/path/to/dod_ca_bundle.pem",
        )
        response = session.get("https://some-internal-api.mil/data")
    """

    def __init__(
        self,
        cert_path: str,
        key_path: str,
        dod_ca_bundle: Optional[str] = None,
    ):
        """
        Args:
            cert_path: Path to PEM-encoded CAC certificate
            key_path: Path to PEM-encoded CAC private key
            dod_ca_bundle: Path to DoD root CA bundle PEM file.
                           Required for .mil endpoints; without it, you will
                           get SSL certificate verification errors.
        """
        super().__init__()
        self.cert = (cert_path, key_path)
        self.verify = dod_ca_bundle or True  # True = use system CA store

    def request(self, method, url, **kwargs):
        # Inject cert into every request made by this session
        kwargs.setdefault("cert", self.cert)
        kwargs.setdefault("verify", self.verify)
        return super().request(method, url, **kwargs)


def get_collibra_datasets(
    collibra_url: str,
    username: str,
    password: str,
    community_name: Optional[str] = None,
    domain_name: Optional[str] = None,
    limit: int = 100,
) -> pd.DataFrame:
    """
    Query the Collibra data catalog REST API for datasets.
    Collibra is the catalog layer for both Advana and Jupiter.
    This requires Collibra API credentials — contact your data steward
    or the Advana/Jupiter Help Desk to request API access.

    Collibra docs: https://developer.collibra.com/

    Args:
        collibra_url: Base Collibra URL (e.g. "https://collibra.advana.data.mil")
        username: Collibra username
        password: Collibra password
        community_name: Filter to a specific community (data domain)
        domain_name: Filter to a specific domain within the community
        limit: Max records per page

    Returns:
        DataFrame with dataset names, descriptions, owners, and classification
    """
    session = requests.Session()
    session.auth = (username, password)
    session.headers.update({"Content-Type": "application/json"})

    # Search for data assets (Collibra calls them "assets")
    url = f"{collibra_url}/rest/2.0/assets"
    params = {
        "typePublicIds": "DataSet",  # The asset type for datasets in Collibra
        "name": "",
        "limit": limit,
        "offset": 0,
    }

    if community_name:
        params["communityName"] = community_name
    if domain_name:
        params["domainName"] = domain_name

    all_assets = []

    while True:
        response = session.get(url, params=params, timeout=30)
        response.raise_for_status()
        data = response.json()

        assets = data.get("results", [])
        all_assets.extend(assets)

        total = data.get("total", 0)
        if len(all_assets) >= total or not assets:
            break

        params["offset"] += limit

    return pd.DataFrame(
        [
            {
                "asset_id": a.get("id"),
                "name": a.get("name"),
                "display_name": a.get("displayName", ""),
                "status": a.get("status", {}).get("name", ""),
                "domain": a.get("domain", {}).get("name", ""),
                "community": a.get("domain", {}).get("community", {}).get("name", ""),
                "modified": a.get("lastModified", ""),
            }
            for a in all_assets
        ]
    )


# ---------------------------------------------------------------------------
# Demo / usage — uses environment variables for all credentials
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    # Unity Catalog discovery
    workspace_url = os.environ.get("DATABRICKS_HOST", "")
    token = os.environ.get("DATABRICKS_TOKEN", "")

    if workspace_url and token:
        print("=== Unity Catalog: Available Catalogs ===")
        catalogs_df = list_unity_catalog_assets(workspace_url, token)
        print(catalogs_df.to_string(index=False))

        if not catalogs_df.empty:
            # Drill into the first catalog
            first_catalog = catalogs_df.iloc[0]["name"]
            print(f"\n=== Schemas in catalog: {first_catalog} ===")
            schemas_df = list_unity_catalog_assets(workspace_url, token, catalog_name=first_catalog)
            print(schemas_df.to_string(index=False))
    else:
        print("Set DATABRICKS_HOST and DATABRICKS_TOKEN environment variables to run the demo.")
        print("Example catalog hierarchy for a Navy analytics environment:")
        print()
        print("  Catalog: navy_logistics")
        print("    Schema: maintenance")
        print("      Table: work_orders           (Gold tier, 847K rows)")
        print("      Table: parts_requisitions    (Gold tier, 2.1M rows)")
        print("      Table: equipment_registry    (Silver tier, 24K rows)")
        print("    Schema: supply_chain")
        print("      Table: inventory_snapshot    (Gold tier, updated daily)")
        print("      Table: vendor_contracts      (Gold tier, from FPDS feed)")
        print()
        print("  Catalog: navy_personnel")
        print("    Schema: readiness")
        print("      Table: manning_summary       (Gold tier, PII-masked aggregate)")
        print("      Table: training_completion   (Silver tier, unit level)")
