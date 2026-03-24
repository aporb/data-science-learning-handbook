"""
Chapter 10: Visualization and Dashboards
Example 3: Platform-Specific Dashboard Patterns

Covers:
  - Databricks Lakeview Dashboards: writing analysis results to Delta,
    SQL query patterns for dashboard backing tables
  - Qlik Load Script patterns for government data models
  - Palantir Foundry: Workshop application backing data patterns
  - Dashboard design principles for each platform

Platform sections are labeled clearly. Code that requires an active
platform connection is clearly marked and shows the correct access
pattern. All sections have platform-independent demo fallbacks.
"""

import json
import warnings
from datetime import datetime
from typing import Any, Dict, List, Optional

import numpy as np
import pandas as pd

warnings.filterwarnings("ignore")


# ============================================================
# SECTION 1: DATABRICKS — LAKEVIEW DASHBOARD PATTERNS
# ============================================================

class DatabricksDashboardWriter:
    """
    Writes analysis outputs to Delta tables for Databricks Lakeview Dashboards.

    Architecture: Analysis Notebook → Delta Table → SQL Warehouse → Dashboard
    The dashboard runs SQL queries against the Delta table, not against
    your Python analysis directly.

    Usage in a Databricks notebook:
        writer = DatabricksDashboardWriter(spark, catalog="gov_data")
        writer.write_readiness_summary(readiness_df)
        writer.write_anomaly_flags(procurement_df, anomaly_scores)
        print("Tables ready. Build Lakeview Dashboard against gov_data.dashboards.*")
    """

    def __init__(self, spark=None, catalog: str = "gov_data",
                  schema: str = "dashboards"):
        self.catalog = catalog
        self.schema = schema
        self._spark = spark

    @property
    def spark(self):
        if self._spark is None:
            try:
                from pyspark.sql import SparkSession
                return SparkSession.builder.getOrCreate()
            except ImportError:
                raise RuntimeError(
                    "PySpark not available. Run inside a Databricks notebook "
                    "or install pyspark."
                )
        return self._spark

    def _write_delta(self, df: pd.DataFrame, table_name: str,
                      mode: str = "overwrite"):
        """Write pandas DataFrame to Delta table via Unity Catalog."""
        full_table = f"{self.catalog}.{self.schema}.{table_name}"
        spark_df = self.spark.createDataFrame(df)
        (spark_df
            .write
            .format("delta")
            .mode(mode)
            .option("overwriteSchema", "true")
            .saveAsTable(full_table))
        row_count = len(df)
        print(f"Written {row_count:,} rows → {full_table}")
        return full_table

    def write_readiness_summary(
        self,
        df: pd.DataFrame,
        unit_col: str = "unit",
        date_col: str = "date",
        readiness_col: str = "readiness",
        threshold: float = 0.75,
    ) -> str:
        """
        Compute and write readiness summary table for the dashboard.

        Output table columns:
          unit, period, readiness_rate, threshold, is_below_threshold,
          trend_3m (3-month change), status_label, updated_at

        The dashboard SQL queries this table — it does not recompute
        anything from the raw data. Pre-aggregate here so the dashboard
        is fast and the SQL stays simple.
        """
        df = df.copy()
        df[date_col] = pd.to_datetime(df[date_col])
        df = df.sort_values([unit_col, date_col])

        # Compute 3-month rolling trend per unit
        df["readiness_lag3"] = df.groupby(unit_col)[readiness_col].shift(3)
        df["trend_3m"] = df[readiness_col] - df["readiness_lag3"]

        df["threshold"] = threshold
        df["is_below_threshold"] = df[readiness_col] < threshold
        df["status_label"] = df[readiness_col].apply(
            lambda v: "BELOW THRESHOLD" if v < threshold
            else ("NEAR THRESHOLD" if v < threshold * 1.05 else "MET")
        )
        df["updated_at"] = datetime.now().isoformat()

        output = df[[unit_col, date_col, readiness_col, "threshold",
                      "is_below_threshold", "trend_3m", "status_label",
                      "updated_at"]].copy()
        output.columns = ["unit", "period", "readiness_rate", "threshold",
                           "is_below_threshold", "trend_3m", "status_label",
                           "updated_at"]

        return self._write_delta(output, "readiness_summary")

    def write_anomaly_flags(
        self,
        df: pd.DataFrame,
        anomaly_score_col: str = "anomaly_score",
        flag_threshold: float = 0.70,
        id_col: str = "contract_id",
    ) -> str:
        """
        Write anomaly-flagged procurement records to Delta for the dashboard.

        The dashboard shows only flagged records — the anomaly score computation
        happens in the analysis notebook (Python/scikit-learn), not in SQL.
        This table is the bridge between the model and the dashboard.
        """
        flagged = df[df[anomaly_score_col] >= flag_threshold].copy()
        flagged["flag_timestamp"] = datetime.now().isoformat()
        flagged["flag_threshold_used"] = flag_threshold
        flagged["review_status"] = "PENDING"  # default; dashboard users update this

        print(f"Flagged records: {len(flagged):,} "
              f"(score ≥ {flag_threshold:.1f}, {len(flagged)/len(df)*100:.1f}% of total)")
        return self._write_delta(flagged, "procurement_anomaly_flags")

    def write_fy_spending_summary(
        self,
        df: pd.DataFrame,
        fy_col: str = "fiscal_year",
        month_col: str = "award_month",
        value_col: str = "obligation_amount",
        agency_col: str = "agency",
    ) -> str:
        """
        Write fiscal year spending summary for budget execution dashboard.

        Aggregates by FY, month (for seasonality), and agency.
        Computes running total, monthly average, and vs-prior-year comparison.
        """
        # Monthly totals
        monthly = (
            df.groupby([fy_col, month_col, agency_col])[value_col]
            .sum()
            .reset_index()
        )

        # FY totals for YoY comparison
        fy_totals = (
            df.groupby([fy_col, agency_col])[value_col]
            .sum()
            .reset_index()
            .rename(columns={value_col: "fy_total"})
        )
        fy_totals["fy_total_prior_year"] = fy_totals.groupby(agency_col)["fy_total"].shift(1)
        fy_totals["yoy_pct_change"] = (
            (fy_totals["fy_total"] - fy_totals["fy_total_prior_year"])
            / fy_totals["fy_total_prior_year"]
        )

        monthly = monthly.merge(fy_totals[[fy_col, agency_col, "fy_total",
                                            "fy_total_prior_year", "yoy_pct_change"]],
                                  on=[fy_col, agency_col], how="left")
        monthly["updated_at"] = datetime.now().isoformat()

        return self._write_delta(monthly, "fy_spending_summary")


# ============================================================
# QLIK LOAD SCRIPT REFERENCE PATTERNS
# ============================================================
# These are Qlik Script snippets — not Python.
# They are shown as string constants for reference.
# Copy into the Qlik Data Load Editor in your Qlik Sense app.
# ============================================================

QLIK_PROCUREMENT_LOAD_SCRIPT = """
// ==========================================================
// Qlik Load Script: DoD Procurement Dashboard Data Model
// For use in Qlik Sense on Advana or Qlik Cloud Government
// ==========================================================

// ---- Table 1: Contract Awards ----
// Source: FPDS-NG data via Advana data catalog
// Key fields: award_key (unique contract ID), vendor_uei, naics_code

CONTRACT_AWARDS:
LOAD
    contract_award_unique_key                   AS award_key,
    award_id_piid                               AS piid,
    recipient_uei                               AS vendor_uei,
    recipient_name                              AS vendor_name,
    awarding_agency_name                        AS agency,
    awarding_sub_agency_name                    AS sub_agency,
    naics_code,
    product_or_service_code                     AS psc_code,
    type_of_contract_pricing                    AS contract_type,
    extent_competed                             AS competition_type,
    number_of_offers_received                   AS n_competitors,
    obligation_amount,
    Date(action_date, 'YYYY-MM-DD')             AS award_date,
    Year(action_date)                           AS calendar_year,
    // U.S. Fiscal Year: Oct-Dec of year N is FY N+1
    If(Month(action_date) >= 10,
       Year(action_date) + 1,
       Year(action_date))                       AS fiscal_year,
    // Fiscal quarter (FY-relative)
    If(Month(action_date) >= 10, 1,
    If(Month(action_date) <= 3,  2,
    If(Month(action_date) <= 6,  3, 4)))        AS fiscal_quarter,
    // FY end-of-year flag for anomaly detection
    If(Month(action_date) = 9, 1, 0)            AS is_fy_end_month
FROM [lib://AdvanaDataCatalog/procurement_awards_fy2020_fy2024.qvd]
(qvd)
WHERE obligation_amount > 0
  AND naics_code <> ''
;

// ---- Table 2: NAICS Code Descriptions ----
// Join key: naics_code (auto-associated by Qlik QIX engine)

NAICS_DESCRIPTIONS:
LOAD
    naics_code,
    naics_description,
    naics_sector_code,
    naics_sector_description
FROM [lib://AdvanaDataCatalog/naics_reference_2022.qvd]
(qvd)
;

// ---- Table 3: Vendor Profile Data ----
// Join key: vendor_uei (auto-associated because field name matches CONTRACT_AWARDS)

VENDOR_PROFILES:
LOAD
    uei                                         AS vendor_uei,
    legal_business_name                         AS vendor_legal_name,
    business_type_description                   AS business_type,
    If(small_business = 'Yes', 1, 0)            AS is_small_business,
    If(sba_8a_certified = 'Yes', 1, 0)          AS is_8a_certified,
    entity_state_of_incorporation               AS vendor_state,
    registration_date                           AS sam_registration_date,
    renewal_date                                AS sam_renewal_date
FROM [lib://AdvanaDataCatalog/sam_vendor_profiles_current.qvd]
(qvd)
;

// ---- Table 4: Anomaly Scores (from Python analysis) ----
// Pre-computed in Databricks, exported to QVD for Qlik consumption
// Join key: award_key

ANOMALY_SCORES:
LOAD
    award_key,
    anomaly_score,
    If(anomaly_score >= 0.70, 'FLAGGED', 'NORMAL')  AS anomaly_flag,
    anomaly_score_date
FROM [lib://AdvanaDataCatalog/procurement_anomaly_scores_latest.qvd]
(qvd)
;
"""

QLIK_READINESS_LOAD_SCRIPT = """
// ==========================================================
// Qlik Load Script: Fleet Readiness Dashboard Data Model
// ==========================================================

// ---- Table 1: Ship Readiness (from SAMS-E via Advana) ----
SHIP_READINESS:
LOAD
    hull_number,
    ship_class,
    report_date,
    Year(report_date)                               AS calendar_year,
    If(Month(report_date) >= 10,
       Year(report_date) + 1,
       Year(report_date))                           AS fiscal_year,
    mc_rate                                         AS readiness_rate,
    If(mc_rate >= 0.75, 'MET',
       If(mc_rate >= 0.70, 'NEAR', 'BELOW'))        AS threshold_status,
    maintenance_backlog_hours,
    open_work_orders,
    homeport                                        AS installation_name
FROM [lib://AdvanaDataCatalog/ship_readiness_monthly.qvd]
(qvd)
WHERE mc_rate >= 0   // exclude records with missing rate
;

// ---- Table 2: Installation Data ----
// Join key: installation_name (auto-associated)
INSTALLATIONS:
LOAD
    installation_name,
    installation_command,
    installation_state,
    installation_lat,
    installation_lon,
    fleet_area                                      AS fleet_designation
FROM [lib://AdvanaDataCatalog/installation_reference.qvd]
(qvd)
;
"""


def explain_qlik_associative_model():
    """
    Print an explanation of how Qlik's associative data model works
    and why it matters for dashboard design.

    The QIX engine's behavior is not intuitive for SQL-trained analysts.
    This explanation bridges the conceptual gap.
    """
    explanation = """
QLIK ASSOCIATIVE DATA MODEL — HOW IT WORKS
===========================================

In SQL or pandas, a filter narrows a result set:
  SELECT * FROM contracts WHERE fiscal_year = 2024

In Qlik, a selection propagates through the entire data model:
  User clicks "FY2024" in a filter panel →
    → All FY2024 contracts are highlighted (white/active)
    → All non-FY2024 contracts are grayed out (excluded)
    → All vendor names, NAICS codes, and agencies associated with FY2024 contracts
       turn white (active) instantly
    → No other records turn white — Qlik knows which vendors only appear in other FYs

This is not re-querying. The QIX engine holds the entire data model in memory
and maintains association state. Selection updates are sub-second regardless
of data model size (up to the memory limit of the server node).

DESIGN IMPLICATION:
  Don't build separate charts for "FY2024 contracts" and "FY2023 contracts."
  Build ONE chart for all contracts. The user selects the fiscal year they care about.
  The chart updates. That's the Qlik design pattern.

  If you find yourself duplicating charts with different hardcoded date filters,
  you're using Qlik like a static report generator. Stop. Use selections.

ASSOCIATION VS. JOIN:
  In SQL, you write: SELECT * FROM contracts JOIN vendors ON contracts.uei = vendors.uei
  In Qlik, you load both tables with a matching field name (both have "vendor_uei")
  and Qlik handles the association automatically. No JOIN needed.

  When the user selects a vendor in the vendor chart, Qlik instantly knows
  which contracts belong to that vendor and updates all charts accordingly.
  This is the associative model.

MEMORY LIMITS ON ADVANA:
  The QIX engine loads the full data model into memory.
  For very large datasets (>50M rows of mixed types), pre-aggregate in Databricks
  before loading into Qlik. A 50M-row raw dataset can often be pre-aggregated
  to 500K meaningful analytical rows without losing decision-relevant detail.
  Write the aggregated QVD, load that into Qlik, not the raw data.
"""
    print(explanation)


# ============================================================
# SECTION 3: PALANTIR FOUNDRY — WORKSHOP BACKING DATA
# ============================================================

class FoundryWorkshopDataPreparer:
    """
    Prepares data for Palantir Foundry Workshop applications.

    Workshop applications are backed by Foundry Ontology objects.
    The data scientist's role: compute derived properties and
    write them back to the Ontology as object properties.
    The Workshop developer then builds the UI on top of those properties.

    Architecture:
      Raw data → Code Workbook (Python) → Transform → Ontology property
      Ontology property → Workshop component → Decision-maker UI
    """

    def compute_maintenance_priority_scores(
        self,
        df: pd.DataFrame,
        days_overdue_col: str = "days_overdue",
        criticality_col: str = "criticality_code",
        cost_estimate_col: str = "estimated_cost",
    ) -> pd.DataFrame:
        """
        Compute maintenance priority scores for Workshop queue application.

        The Workshop application displays work orders ranked by this score.
        The maintenance officer sees the score, not the formula — they
        make decisions based on the ranked list.

        Score = weighted combination of overdue days, criticality, and cost impact.
        Range: 0 (low priority) to 100 (urgent).

        In a real Foundry deployment:
        - This function runs as a Foundry Code Workbook transform
        - Output is written to the WorkOrder object type's priority_score property
        - Workshop reads that property to populate the ranked queue UI
        """
        df = df.copy()

        # Normalize each component to 0-1
        # Overdue days: longer overdue = higher urgency
        max_days = df[days_overdue_col].clip(lower=0).quantile(0.95)
        days_norm = df[days_overdue_col].clip(lower=0, upper=max_days) / max(max_days, 1)

        # Criticality: map categorical codes to numeric weights
        criticality_weights = {"MISSION_CRITICAL": 1.0, "HIGH": 0.75,
                                "MEDIUM": 0.45, "LOW": 0.20, "ROUTINE": 0.10}
        crit_norm = df[criticality_col].map(criticality_weights).fillna(0.30)

        # Cost: log-normalize (higher cost = higher priority)
        cost_norm = np.log1p(df[cost_estimate_col].clip(lower=0))
        cost_norm = (cost_norm - cost_norm.min()) / max(cost_norm.max() - cost_norm.min(), 1)

        # Weighted composite score (weights sum to 1)
        w_days, w_crit, w_cost = 0.45, 0.40, 0.15
        df["priority_score"] = (
            w_days * days_norm + w_crit * crit_norm + w_cost * cost_norm
        ) * 100

        df["priority_label"] = pd.cut(
            df["priority_score"],
            bins=[0, 25, 50, 75, 100],
            labels=["ROUTINE", "MEDIUM", "HIGH", "URGENT"],
            include_lowest=True
        )

        print(f"Priority scores computed for {len(df):,} work orders")
        print(df["priority_label"].value_counts().sort_index().to_string())
        return df

    def prepare_workshop_kpi_summary(
        self,
        df: pd.DataFrame,
        group_col: str,
        metric_cols: List[str],
        threshold_map: Dict[str, float],
    ) -> pd.DataFrame:
        """
        Aggregate metrics for Workshop KPI tile components.

        Workshop KPI tiles typically show:
        - Current value
        - Status (above/below threshold)
        - Delta from prior period

        This function computes those three things for a group of entities.
        In Foundry, this output would be written as object properties.

        Args:
            df: Source data (must have a period column sortable by time)
            group_col: Entity column (e.g., "unit", "installation")
            metric_cols: Metrics to aggregate
            threshold_map: {metric_col: threshold_value} for status calculation
        """
        results = []
        for group_val in df[group_col].unique():
            group_df = df[df[group_col] == group_val]
            row = {group_col: group_val}
            for col in metric_cols:
                current = group_df[col].iloc[-1] if len(group_df) > 0 else np.nan
                prior = group_df[col].iloc[-2] if len(group_df) > 1 else np.nan
                delta = current - prior if not (np.isnan(current) or np.isnan(prior)) else np.nan
                threshold = threshold_map.get(col)
                status = (
                    "ABOVE" if (threshold and current >= threshold)
                    else "BELOW" if (threshold and current < threshold)
                    else "UNKNOWN"
                )
                row[f"{col}_current"] = current
                row[f"{col}_delta"] = delta
                row[f"{col}_status"] = status
            results.append(row)
        return pd.DataFrame(results)

    def generate_slate_data_schema(self, df: pd.DataFrame,
                                    object_type: str) -> Dict[str, Any]:
        """
        Generate a data schema description suitable for sharing with
        a Slate application developer.

        The data scientist computes the analysis. The Slate developer
        builds the UI. This function produces the schema documentation
        that bridges those two roles.

        Returns a dict that can be serialized to JSON and shared with
        the Slate developer as a data contract.
        """
        schema = {
            "object_type": object_type,
            "generated_at": datetime.now().isoformat(),
            "row_count": len(df),
            "properties": []
        }

        for col in df.columns:
            series = df[col]
            prop = {
                "property_name": col,
                "data_type": str(series.dtype),
                "nullable": bool(series.isnull().any()),
                "example_values": series.dropna().head(3).tolist(),
            }
            if pd.api.types.is_numeric_dtype(series):
                s = series.dropna()
                prop["range"] = [float(s.min()), float(s.max())]
            elif pd.api.types.is_object_dtype(series):
                prop["unique_count"] = int(series.nunique())
                prop["top_values"] = series.value_counts().head(5).index.tolist()
            schema["properties"].append(prop)

        print(f"Schema generated for {object_type}: {len(schema['properties'])} properties")
        print(json.dumps(schema, indent=2, default=str)[:1000] + "...")
        return schema


# ============================================================
# SECTION 4: DASHBOARD DESIGN DECISION GUIDE
# ============================================================

def print_dashboard_tool_selection_guide():
    """
    Print the dashboard tool selection decision guide.
    Covers when to use each platform and the key tradeoffs.
    """
    guide = """
VISUALIZATION TOOL SELECTION GUIDE — GOVERNMENT DATA SCIENCE
=============================================================

DECISION FRAMEWORK:
  Ask these questions before choosing a tool:
  1. Who is the audience? (analyst / operator / decision-maker)
  2. Will the output be consumed interactively or as a static artifact?
  3. Does the user need to ACT (write-back) or just OBSERVE (read-only)?
  4. What classification level is the data?
  5. What platforms can the audience actually access?

TOOL MATRIX:

  matplotlib/seaborn
  ├── Use when: output is a PDF, slide deck, or printed report
  ├── Use when: the audience cannot run code or access a dashboard
  ├── Audience: decision-makers, non-technical briefing recipients
  ├── Classification: runs wherever Python runs (up to classification of runtime)
  └── NOT for: interactive exploration, analyst tools, real-time monitoring

  Plotly (HTML export or notebook)
  ├── Use when: audience is an analyst who benefits from hover/zoom
  ├── Use when: distributing to team members who have browser access
  ├── Use when: building in Databricks notebooks for team sharing
  ├── Audience: analysts, data scientists, technical staff
  ├── Classification: depends on Databricks workspace classification
  └── NOT for: final briefing slides (screenshot or export to PNG first)

  Databricks Lakeview Dashboards
  ├── Use when: monitoring operational metrics that update regularly
  ├── Use when: audience can access the Databricks workspace
  ├── Use when: data lives in Delta tables on Unity Catalog
  ├── Audience: analysts, program office staff with workspace access
  ├── Classification: up to IL5 (AWS GovCloud DoD workspace)
  ├── Requires: SQL warehouse endpoint (serverless or pro tier)
  └── NOT for: write-back, end users outside the Databricks workspace

  Qlik Sense (Advana or Qlik Cloud Government)
  ├── Use when: audience is a broad DoD user base on Advana
  ├── Use when: exploratory association-driven analysis is the goal
  ├── Use when: existing Qlik data model can be extended
  ├── Audience: all Advana-authorized users (100K+ DoD staff)
  ├── Classification: NIPR/SIPR on Advana; FedRAMP Moderate/IL4 on Cloud Gov
  ├── Key strength: associative engine — click to select, everything updates
  └── NOT for: write-back to source systems, statistical computation

  Palantir Foundry Slate
  ├── Use when: users need to TAKE ACTIONS, not just view data
  ├── Use when: the workflow involves decisions that modify records
  ├── Use when: the Foundry Ontology already models the operational domain
  ├── Audience: operators, supervisors, logistics officers
  ├── Classification: up to IL5/IL6 depending on deployment environment
  ├── Requires: JavaScript developer for UI; data scientist for backing data
  └── NOT for: read-only reporting, audiences without Foundry access

QUICK RULES:
  → Briefing to admiral → matplotlib PDF
  → Analyst self-service on Advana → Qlik
  → Analyst self-service in Databricks → Plotly HTML or Lakeview Dashboard
  → Operator needs to approve/assign/update → Foundry Slate
  → Monitoring dashboard for ops team → Databricks Lakeview or Qlik
  → Screenshottable chart for a ticket or email → matplotlib PNG
"""
    print(guide)


# ============================================================
# DEMO
# ============================================================

def generate_demo_data():
    """Synthetic maintenance and readiness data for dashboard demos."""
    rng = np.random.default_rng(42)
    n = 200

    work_orders = pd.DataFrame({
        "work_order_id": [f"WO-{i:06d}" for i in range(n)],
        "hull_number": rng.choice([f"DDG-{x}" for x in range(51, 80)], n),
        "criticality_code": rng.choice(
            ["MISSION_CRITICAL", "HIGH", "MEDIUM", "LOW", "ROUTINE"],
            n, p=[0.05, 0.15, 0.35, 0.30, 0.15]
        ),
        "days_overdue": np.maximum(0, rng.normal(10, 15, n)).astype(int),
        "estimated_cost": np.exp(rng.normal(10, 2, n)),
        "ship_class": rng.choice(["Arleigh Burke", "Ticonderoga", "San Antonio"], n),
    })

    readiness_data = []
    units = [f"CVN-{x}" for x in [68, 69, 70, 71, 72]]
    dates = pd.date_range("2023-01-01", periods=12, freq="ME")
    for unit in units:
        base = rng.uniform(0.68, 0.88)
        for dt in dates:
            readiness_data.append({
                "unit": unit,
                "date": dt,
                "readiness": float(np.clip(base + rng.normal(0, 0.03), 0.5, 1.0)),
                "maintenance_backlog": int(rng.integers(50, 300))
            })
    readiness_df = pd.DataFrame(readiness_data)

    return work_orders, readiness_df


if __name__ == "__main__":
    work_orders, readiness_df = generate_demo_data()

    print("=" * 60)
    print("Chapter 10: Platform Dashboard Patterns Demo")
    print("=" * 60)

    # Databricks writer (demo without live Spark)
    print("\n--- Databricks: Analysis-to-Delta Pattern ---")
    print("(Requires live Databricks environment for actual write)")
    writer = DatabricksDashboardWriter()
    # Show what would be written
    readiness_summary = readiness_df.copy()
    readiness_summary["is_below"] = readiness_summary["readiness"] < 0.75
    print(f"Readiness summary shape: {readiness_summary.shape}")
    print(readiness_summary.groupby("unit")["readiness"].agg(["mean", "min", "max"]).to_string())

    # Foundry Workshop data preparer
    print("\n--- Palantir Foundry: Workshop Priority Scores ---")
    preparer = FoundryWorkshopDataPreparer()
    scored_df = preparer.compute_maintenance_priority_scores(work_orders)
    print("\nTop 5 highest priority work orders:")
    print(scored_df.nlargest(5, "priority_score")[
        ["work_order_id", "hull_number", "criticality_code",
         "days_overdue", "priority_score", "priority_label"]
    ].to_string(index=False))

    # KPI summary for Workshop tiles
    print("\n--- Foundry: Workshop KPI Summary ---")
    kpi = preparer.prepare_workshop_kpi_summary(
        readiness_df,
        group_col="unit",
        metric_cols=["readiness", "maintenance_backlog"],
        threshold_map={"readiness": 0.75}
    )
    print(kpi.to_string(index=False))

    # Slate schema
    print("\n--- Foundry: Slate Data Schema ---")
    schema = preparer.generate_slate_data_schema(
        scored_df[["work_order_id", "hull_number", "criticality_code",
                    "days_overdue", "priority_score", "priority_label"]],
        object_type="MaintenanceWorkOrder"
    )

    # Qlik load script reference
    print("\n--- Qlik: Load Script Reference ---")
    print("Procurement data model script (copy into Qlik Data Load Editor):")
    print(QLIK_PROCUREMENT_LOAD_SCRIPT[:800] + "\n... (truncated, see full script above)")

    # Associative model explanation
    print("\n--- Qlik: Associative Model Explanation ---")
    explain_qlik_associative_model()

    # Selection guide
    print("\n--- Platform Selection Guide ---")
    print_dashboard_tool_selection_guide()
