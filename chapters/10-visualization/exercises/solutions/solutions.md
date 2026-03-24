# Chapter 10: Visualization & Dashboards — Solutions

These solutions represent one defensible approach to each exercise. Your implementation
may differ — what matters is that your design choices hold up under scrutiny and your
code produces clear, accessible output.

---

## Solution 1: Government Briefing Chart (matplotlib)

### Complete Code

```python
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np
import pandas as pd

# ── Data setup ────────────────────────────────────────────────────────────────
np.random.seed(42)
services = ["Army", "Navy", "Air Force", "Marines"]
fy_years = [2021, 2022, 2023, 2024, 2025]
baselines = {"Army": 0.81, "Navy": 0.84, "Air Force": 0.87, "Marines": 0.79}
trend = {"Army": 0.012, "Navy": 0.008, "Air Force": 0.005, "Marines": 0.015}

records = []
for svc in services:
    for i, fy in enumerate(fy_years):
        rate = baselines[svc] + trend[svc] * i + np.random.normal(0, 0.01)
        records.append({"service": svc, "fiscal_year": fy, "fill_rate": min(rate, 1.0)})

fill_rates = pd.DataFrame(records)
threshold = 0.85

# ── Style constants (Okabe-Ito palette) ──────────────────────────────────────
COLORS = {
    "Army":      "#0072B2",  # blue
    "Navy":      "#E69F00",  # orange
    "Air Force": "#009E73",  # green
    "Marines":   "#D55E00",  # vermillion
}
# Distinct markers — works in black-and-white print
MARKERS = {
    "Army":      "o",   # circle
    "Navy":      "s",   # square
    "Air Force": "D",   # diamond
    "Marines":   "^",   # triangle up
}

# ── Apply government style ────────────────────────────────────────────────────
plt.rcParams.update({
    "font.family": "DejaVu Sans",
    "font.size": 10,
    "axes.spines.top": False,
    "axes.spines.right": False,
    "axes.grid": True,
    "axes.grid.axis": "y",
    "grid.alpha": 0.3,
    "grid.color": "#CCCCCC",
    "figure.dpi": 150,
})

fig, ax = plt.subplots(figsize=(9, 5.5))

# ── Plot each service ─────────────────────────────────────────────────────────
for svc in services:
    svc_data = fill_rates[fill_rates["service"] == svc].sort_values("fiscal_year")
    ax.plot(
        svc_data["fiscal_year"],
        svc_data["fill_rate"],
        color=COLORS[svc],
        marker=MARKERS[svc],
        markersize=7,
        linewidth=2,
        label=svc,
    )

# ── Threshold line ────────────────────────────────────────────────────────────
ax.axhline(
    threshold,
    color="#333333",
    linestyle="--",
    linewidth=1.5,
    zorder=1,
)
ax.text(
    2025.05, threshold + 0.003,
    "85% Contract Threshold",
    fontsize=9,
    color="#333333",
    va="bottom",
)

# ── Annotate lowest point ─────────────────────────────────────────────────────
# Find the point most below threshold
below = fill_rates[fill_rates["fill_rate"] < threshold].copy()
if not below.empty:
    worst = below.loc[below["fill_rate"].idxmin()]
    gap = threshold - worst["fill_rate"]
    ax.annotate(
        f"{worst['service']}, FY{int(worst['fiscal_year'])}\n"
        f"{gap:.1%} below threshold",
        xy=(worst["fiscal_year"], worst["fill_rate"]),
        xytext=(worst["fiscal_year"] - 0.4, worst["fill_rate"] - 0.025),
        fontsize=8.5,
        color="#D55E00",
        arrowprops=dict(arrowstyle="->", color="#D55E00", lw=1.2),
        bbox=dict(boxstyle="round,pad=0.3", fc="white", ec="#D55E00", alpha=0.9),
    )

# ── Labels and formatting ─────────────────────────────────────────────────────
ax.set_title(
    "Aviation Spare Parts Fill Rate by Service Branch, FY2021–FY2025",
    fontsize=12,
    fontweight="bold",
    pad=12,
)
ax.text(
    0.0, 1.01,
    "Contract threshold: 85%  |  Source: DLA Enterprise Business System",
    transform=ax.transAxes,
    fontsize=9,
    color="#555555",
)
ax.set_xlabel("Fiscal Year", fontsize=10)
ax.set_ylabel("Fill Rate", fontsize=10)
ax.set_xticks(fy_years)
ax.set_xticklabels([f"FY{y}" for y in fy_years])
ax.set_ylim(0.75, 0.97)
ax.yaxis.set_major_formatter(plt.FuncFormatter(lambda v, _: f"{v:.0%}"))

ax.legend(loc="lower right", framealpha=0.9, fontsize=9)

plt.tight_layout()
plt.savefig("output/ex1_fill_rates.png", dpi=300, bbox_inches="tight")
plt.savefig("output/ex1_fill_rates.pdf", bbox_inches="tight")
plt.show()
```

### Question Responses

**a. Marker assignment reasoning**

The markers are not arbitrary. Circle (Army) and square (Navy) are the two most
visually distinct shapes at small sizes — readers with color blindness can tell them
apart in any reproduction. Diamond (Air Force) and triangle (Marines) are secondary
choices. The logic is that branch size (Army and Navy represent the largest data
populations in the chart) gets the most universally recognizable shapes.

**b. Red for worst performer**

Using color alone to signal performance quality creates two problems. First, roughly 8%
of male readers have red-green color blindness; a red/green system is literally
invisible to them. Second, and more importantly in a briefing context, color that encodes
value judgment (red = bad) is politically charged — service branches do not appreciate
being literally marked in red for senior leadership. The better approach is what this
solution does: use a neutral color palette plus a threshold line so the data speaks for
itself. If Marines fall below the line, the line does the editorial work, not the color.

**c. Dual Y-axis risk**

Dual Y-axes are one of the most common chart integrity failures in government briefings.
The problem is that the two Y-axes can be scaled independently, making it trivially easy
(intentionally or accidentally) to make any correlation look strong or weak. A 5%
correlation can look like lock-step movement if the scales are chosen carelessly. The
conditions under which a dual axis is acceptable: the two metrics are in genuinely
different units (fill rate % and unit count), the audience is technically literate, and
both axes are labeled with explicit scale ranges so the reader can verify the scaling
is not manipulative. Even then, a better alternative is usually a second panel below
the first.

---

## Solution 2: Interactive Analyst Dashboard (Plotly)

### Complete Code

```python
import pandas as pd
import numpy as np
import plotly.graph_objects as go
from plotly.subplots import make_subplots

# ── Data setup ────────────────────────────────────────────────────────────────
np.random.seed(7)
n = 300
aircraft_types = ["C-17", "C-5", "KC-135"]
quarters = ["Q1", "Q2", "Q3", "Q4"]

missions = pd.DataFrame({
    "aircraft": np.random.choice(aircraft_types, n),
    "fy_quarter": np.random.choice(quarters, n),
    "sorties_planned": np.random.randint(8, 25, n),
    "on_time_pct": np.random.beta(8, 2, n) * 100,
    "cargo_utilization_pct": np.random.beta(6, 2, n) * 100,
    "fuel_per_ton_mile": np.random.normal(0.45, 0.06, n).clip(0.30, 0.65),
})
missions["sorties_flown"] = (
    missions["sorties_planned"] * np.random.uniform(0.75, 1.0, n)
).astype(int)
missions["execution_rate"] = missions["sorties_flown"] / missions["sorties_planned"]

# ── Color palette ─────────────────────────────────────────────────────────────
COLORS = {
    "C-17":   "#0072B2",
    "C-5":    "#E69F00",
    "KC-135": "#009E73",
}
QUARTER_ORDER = ["Q1", "Q2", "Q3", "Q4"]

# ── Build figure with subplots ────────────────────────────────────────────────
fig = make_subplots(
    rows=2, cols=2,
    subplot_titles=[
        "Sorties Flown vs. Planned by Aircraft",
        "On-Time Departure Rate Distribution",
        "Cargo Utilization vs. Fuel Efficiency",
        "Execution Rate by Aircraft and Quarter",
    ],
    vertical_spacing=0.15,
    horizontal_spacing=0.10,
)

# Panel 1: Grouped bar — sorties flown vs planned
for ac in aircraft_types:
    subset = missions[missions["aircraft"] == ac]
    planned = subset["sorties_planned"].sum()
    flown = subset["sorties_flown"].sum()
    fig.add_trace(
        go.Bar(
            name=f"{ac} — Planned",
            x=[ac],
            y=[planned],
            marker_color=COLORS[ac],
            opacity=0.4,
            legendgroup=ac,
            showlegend=True,
            hovertemplate=f"Aircraft: {ac}<br>Planned: {planned}<extra></extra>",
        ),
        row=1, col=1,
    )
    fig.add_trace(
        go.Bar(
            name=f"{ac} — Flown",
            x=[ac],
            y=[flown],
            marker_color=COLORS[ac],
            opacity=1.0,
            legendgroup=ac,
            showlegend=False,
            hovertemplate=f"Aircraft: {ac}<br>Flown: {flown}<extra></extra>",
        ),
        row=1, col=1,
    )

# Panel 2: Box plots — on-time rate
for ac in aircraft_types:
    subset = missions[missions["aircraft"] == ac]
    fig.add_trace(
        go.Box(
            name=ac,
            y=subset["on_time_pct"],
            marker_color=COLORS[ac],
            legendgroup=ac,
            showlegend=False,
            hovertemplate=f"Aircraft: {ac}<br>On-Time %%: %{{y:.1f}}<extra></extra>",
        ),
        row=1, col=2,
    )

# Panel 3: Scatter — cargo utilization vs fuel
fleet_avg_fuel = missions["fuel_per_ton_mile"].mean()
for ac in aircraft_types:
    subset = missions[missions["aircraft"] == ac]
    fig.add_trace(
        go.Scatter(
            name=ac,
            x=subset["cargo_utilization_pct"],
            y=subset["fuel_per_ton_mile"],
            mode="markers",
            marker=dict(color=COLORS[ac], size=6, opacity=0.65),
            legendgroup=ac,
            showlegend=False,
            hovertemplate=(
                f"Aircraft: {ac}<br>"
                "Cargo Util: %{x:.1f}%%<br>"
                "Fuel/Ton-Mile: %{y:.3f}<extra></extra>"
            ),
        ),
        row=2, col=1,
    )
# Fleet average fuel reference line
fig.add_hline(
    y=fleet_avg_fuel,
    line_dash="dash",
    line_color="#555555",
    annotation_text=f"Fleet avg: {fleet_avg_fuel:.3f}",
    annotation_position="bottom right",
    row=2, col=1,
)

# Panel 4: Grouped bar — execution rate by aircraft and quarter
for ac in aircraft_types:
    rates = []
    for q in QUARTER_ORDER:
        subset = missions[(missions["aircraft"] == ac) & (missions["fy_quarter"] == q)]
        rates.append(subset["execution_rate"].mean() if len(subset) > 0 else 0)
    fig.add_trace(
        go.Bar(
            name=ac,
            x=QUARTER_ORDER,
            y=rates,
            marker_color=COLORS[ac],
            legendgroup=ac,
            showlegend=False,
            hovertemplate=(
                f"Aircraft: {ac}<br>"
                "Quarter: %{x}<br>"
                "Execution Rate: %{y:.1%%}<extra></extra>"
            ),
        ),
        row=2, col=2,
    )

# ── Layout ────────────────────────────────────────────────────────────────────
fig.update_layout(
    title=dict(
        text="TRANSCOM Airlift Mission Performance — Interactive Analysis",
        font=dict(size=16, color="#1a1a1a"),
    ),
    height=750,
    paper_bgcolor="white",
    plot_bgcolor="#F8F8F8",
    barmode="group",
    legend=dict(
        orientation="h",
        y=-0.08,
        x=0.5,
        xanchor="center",
    ),
    font=dict(family="Arial, sans-serif", size=11),
)

# ── Export ────────────────────────────────────────────────────────────────────
# NOTE: include_plotlyjs='cdn' loads Plotly from cdn.plot.ly at runtime.
# On classified or air-gapped networks this WILL FAIL — the network cannot reach
# external CDNs. Use include_plotlyjs=True (embeds ~3MB of JS inline) or
# include_plotlyjs='directory' (saves plotly.min.js alongside the HTML file).
fig.write_html(
    "output/ex2_transcom_dashboard.html",
    include_plotlyjs=True,  # safe for air-gapped; use 'cdn' only on unclass internet
)
fig.show()
```

### Question Responses

**a. Dropdown filter limitation**

The `updatemenus` visibility toggle is not a data filter — it hides and shows pre-rendered
traces. When a quarterly filter is applied, the "fleet average" reference line on the
scatter plot still reflects the full dataset, not the filtered quarter. Similarly, any
aggregated bar heights (Panel 4 averages) are baked in at render time. To fix this for
production: pre-compute a separate set of traces for every filter combination, render
them all invisible, and toggle the correct set on selection. Alternatively, use Dash
(Plotly's callback framework) where a real Python function re-queries data on each filter
change — this is the right approach for any dashboard with calculated metrics.

**b. Box plot vs. mean**

A mean alone hides the shape of the distribution. On-time departure rate can average
88% in two very different situations: a stable system centered at 88%, or a bimodal
system that runs perfectly (95%+) most of the time but suffers periodic catastrophic
failures (60%). These look identical as means but completely differently as box plots.
For an operations briefing, the commander cares most about the worst-case tail —
how bad does it get? — which the box plot's whiskers and outlier dots make visible.

**c. Air-gapped Plotly export strategies**

1. `include_plotlyjs=True`: Embeds the entire Plotly JavaScript library inline in the
   HTML file, making it fully self-contained at roughly 3.5 MB. Works anywhere a browser
   works. This is the standard choice for classified SharePoint.
2. `include_plotlyjs='directory'`: Saves `plotly.min.js` in the same directory as the
   HTML file and references it with a relative path. Smaller file per chart, but the JS
   file must travel with the HTML. Good for batch-generated report packages.

---

## Solution 3: Databricks Lakeview Dashboard Design

### Part A — SQL Queries

**Query 1: Stock Status with Alert Levels**

```sql
-- Most recent snapshot date only
WITH latest AS (
    SELECT MAX(snapshot_date) AS max_date
    FROM health.dha.mtf_supply_utilization
),
stock_status AS (
    SELECT
        u.item_id,
        u.category,
        u.current_stock,
        u.par_level,
        ROUND(u.current_stock * 100.0 / NULLIF(u.par_level, 0), 1) AS stock_pct,
        CASE
            WHEN u.current_stock * 1.0 / NULLIF(u.par_level, 0) < 0.20 THEN 'CRITICAL'
            WHEN u.current_stock * 1.0 / NULLIF(u.par_level, 0) < 0.50 THEN 'WARNING'
            ELSE 'OK'
        END AS alert_status
    FROM health.dha.mtf_supply_utilization u
    INNER JOIN latest ON u.snapshot_date = latest.max_date
)
SELECT *
FROM stock_status
ORDER BY
    CASE alert_status
        WHEN 'CRITICAL' THEN 1
        WHEN 'WARNING'  THEN 2
        ELSE 3
    END,
    stock_pct ASC;
```

**Query 2: Category Rollup**

```sql
WITH latest AS (
    SELECT MAX(snapshot_date) AS max_date
    FROM health.dha.mtf_supply_utilization
)
SELECT
    u.category,
    SUM(u.par_level)                                              AS total_par_capacity,
    SUM(u.current_stock)                                          AS total_current_stock,
    ROUND(SUM(u.current_stock) * 100.0 / NULLIF(SUM(u.par_level), 0), 1) AS category_stock_pct,
    COUNT_IF(u.current_stock * 1.0 / NULLIF(u.par_level, 0) < 0.20) AS critical_count,
    COUNT_IF(
        u.current_stock * 1.0 / NULLIF(u.par_level, 0) BETWEEN 0.20 AND 0.50
    )                                                             AS warning_count,
    COUNT(*)                                                      AS total_items
FROM health.dha.mtf_supply_utilization u
INNER JOIN latest ON u.snapshot_date = latest.max_date
GROUP BY u.category
ORDER BY category_stock_pct ASC;
```

**Query 3: 30-Day Rolling Average Consumption by Category**

```sql
-- Note: window function requires ordering; Delta supports this natively
SELECT
    snapshot_date,
    category,
    SUM(daily_consumption)                               AS daily_total_consumption,
    AVG(SUM(daily_consumption)) OVER (
        PARTITION BY category
        ORDER BY snapshot_date
        ROWS BETWEEN 6 PRECEDING AND CURRENT ROW
    )                                                    AS rolling_7day_avg
FROM health.dha.mtf_supply_utilization
WHERE snapshot_date >= CURRENT_DATE - INTERVAL 30 DAYS
GROUP BY snapshot_date, category
ORDER BY category, snapshot_date;
```

### Part B — Dashboard Design Document

**Panels (4 total)**

- **Panel 1 — Alert Summary Table**: Backed by Query 1. Shows all items with CRITICAL
  or WARNING status, their stock-to-par ratio, and an alert badge. Filters: category
  dropdown, alert status (CRITICAL/WARNING/OK/All).

- **Panel 2 — Category Stock Gauge**: Backed by Query 2. Bar chart showing category-level
  stock percentage with a 20% and 50% reference line. Color encoding: below 20% = solid
  fill, 20-50% = medium fill, above 50% = light fill.

- **Panel 3 — Consumption Trend Lines**: Backed by Query 3. Line chart, one line per
  category, showing 7-day rolling average over 30 days. Filters: date range picker.

- **Panel 4 — KPI Counter Row**: Small counter tiles showing: total items CRITICAL,
  total items WARNING, overall facility stock percentage. Always unfiltered (full
  facility picture).

**Filters exposed**: Date range (defaults to last 30 days), category multi-select,
alert status radio (All / CRITICAL+WARNING only / OK only).

**Why Delta table rather than live source query**

Medical supply systems (often SAP or legacy ERP) cannot handle concurrent analytical
queries without impacting transactional performance — an analyst refreshing a dashboard
could slow down actual supply orders. The Delta table is a copy written once per refresh
cycle (nightly or twice daily), decoupling analytical load from operational systems.
Delta also provides time travel: if an analyst needs yesterday's snapshot for a
discrepancy review, Delta handles it natively with `VERSION AS OF` or `TIMESTAMP AS OF`.

**Unity Catalog permission**

`GRANT SELECT ON TABLE health.dha.mtf_supply_utilization TO GROUP dha_clinical_analysts;`

Grant read-only access to the analytics group, not to individual users. This ensures
analyst onboarding/offboarding is managed at the group level and that analysts cannot
accidentally modify or delete the source table.

### Part C — Refresh Strategy

Configure a **Databricks Workflow** (not a standalone notebook) with:

- **Trigger**: Scheduled, daily at 05:30 local time (buffer before 07:00 arrival)
- **Cluster**: Job cluster (auto-terminates, cost-efficient; not an all-purpose cluster)
- **Task 1 — Ingest**: Notebook that reads from the source ERP system via JDBC or an
  approved data transfer, appends new daily records to the Delta table with
  `MERGE INTO` to avoid duplicates
- **Task 2 — Validate**: A short notebook that checks: row count > 0 for today's
  date, no nulls in `item_id` or `par_level`, stock values within plausible range
- **Task 3 — Optimize**: `OPTIMIZE health.dha.mtf_supply_utilization ZORDER BY
  (snapshot_date, category)` to keep query performance fast as the table grows

**Failure handling**: Configure email/PagerDuty alert on task failure. Task 2
(validation) uses `dbutils.notebook.exit("VALIDATION_FAILED")` on data quality
failure, which marks the workflow run as failed without running Task 3, and the
dashboard continues showing the previous day's data rather than corrupt data.

---

## Solution 4: Qlik Data Model Design

### Part A — Data Model Diagram

```
┌─────────────────────────┐
│       budget_lines       │
│─────────────────────────│
│ PE_code  (KEY)          │──────────────────────────┐
│ PE_name                 │                           │
│ appropriation           │                           │
│ authorized_amount       │                           │
│ fy                      │                           │
└─────────────────────────┘                           │
                                                       │ 1:many
             ┌─────────────────────────┐               │
             │       obligations        │               │
             │─────────────────────────│               │
             │ obligation_id           │◄──────────────┘
             │ PE_code  (FK → budget)  │
             │ contract_id  (KEY)      │──────────────┐
             │ obligated_amount        │               │ 1:many
             │ obligation_date         │               │
             │ obligation_fy  (renamed)│               │
             └─────────────────────────┘               │
                                                        │
             ┌─────────────────────────┐               │
             │    contract_actions      │               │
             │─────────────────────────│               │
             │ contract_id  (FK→oblig) │◄──────────────┘
             │ vendor_name             │
             │ award_date              │
             │ action_type             │
             │ action_value            │
             │ naics_code              │
             └─────────────────────────┘
```

**Cardinality**: `budget_lines` to `obligations` is 1:many (one PE has many obligations).
`obligations` to `contract_actions` is 1:many (one contract can have multiple action
records — modifications, options exercised, etc.).

**Synthetic key risk**: If `fy` is not renamed in `obligations`, both `budget_lines.fy`
and `obligations.fy` share the same name. Qlik would create a synthetic key on
`(PE_code, fy)` rather than joining cleanly on `PE_code` alone. The synthetic key
creates a hidden concatenated join field that breaks the associative filtering.

### Part B — Load Script

```qlik
// ── budget_lines ──────────────────────────────────────────────────────────────
budget_lines:
LOAD
    PE_code,
    PE_name,
    appropriation,
    authorized_amount,
    fy AS budget_fy
FROM [lib://GovData/budget_lines.qvd] (qvd);

// ── obligations ───────────────────────────────────────────────────────────────
obligations:
LOAD
    obligation_id,
    PE_code,
    contract_id,
    obligated_amount,
    obligation_date,
    fy AS obligation_fy,   // renamed to avoid synthetic key with budget_lines.fy
    'Q' & Ceil(Month(obligation_date) / 3) AS obligation_quarter
FROM [lib://GovData/obligations.qvd] (qvd);

// ── contract_actions ─────────────────────────────────────────────────────────
contract_actions:
LOAD
    contract_id,
    vendor_name,
    award_date,
    action_type,
    action_value,
    naics_code,
    // Procurement threshold classification (FAR Part 13 thresholds)
    IF(action_value < 10000,      'Micro-Purchase',
    IF(action_value <= 250000,    'Simplified Acquisition',
                                  'Above SAT'
    )) AS procurement_threshold_band
FROM [lib://GovData/contract_actions.qvd] (qvd);
```

### Part C — Circular Reference Explanation and Fix

A circular reference occurs when three or more tables form a loop of key relationships:
`budget_lines` → (via PE_code) → `obligations` → (via contract_id) → `contract_actions`
→ (via PE_code) → `budget_lines`. The QIX associative engine cannot determine which path
to follow when filtering — clicking a PE_code would propagate associations through both
paths simultaneously, producing ambiguous or incorrect results. Qlik surfaces this as a
warning and may create a synthetic key attempting (poorly) to resolve it.

**Fix — Link Table**: Create an explicit link table that holds only the key fields,
breaking the direct association between `contract_actions` and `budget_lines`:

```qlik
// Remove PE_code from contract_actions load (do not load it directly)
// Create a link table that connects the three tables safely
LinkTable:
LOAD DISTINCT
    obligation_id,
    PE_code,
    contract_id
FROM [lib://GovData/obligations.qvd] (qvd);

// budget_lines joins via PE_code to LinkTable
// contract_actions joins via contract_id to LinkTable
// Associations flow through the link table, not directly between outer tables
```

This pattern — the Link Table — is the standard Qlik solution for many-to-many or
circular associations.

### Part D — Associative Model vs. SQL for a New Analyst

In SQL, a WHERE clause is explicit: you write the filter conditions yourself before the
query runs, and the result set contains only the rows matching your condition. When you
write a new query, you start fresh — nothing carries over from your last query. In Qlik,
clicking a value does not run a query. Instead, Qlik's QIX engine immediately classifies
every value in every field across every table as either "selected" (white), "associated"
(light gray), or "excluded" (dark gray) — and it does this in memory at sub-second speed.
If you click "Army" in a service branch list, every related contract, obligation, vendor,
and PE code across all tables instantly shows which ones are associated with Army and
which are not, without you writing a single line. The key insight is that in Qlik you are
not filtering data — you are making a selection that propagates associatively through
the entire data model simultaneously, revealing relationships you did not explicitly ask
for.

---

## Solution 5: Platform Selection Scenario

### Team A — Intelligence Fusion Cell (SECRET//REL TO FIVE EYES)

**Platform**: Custom Python tool + Grafana (on-premise, air-gapped)

The five platforms discussed in this chapter are all cloud-based or require internet
connectivity in some form. A SECRET//REL enclave with classified feeds cannot use
Advana/Qlik (FedRAMP Moderate, unclassified), Databricks (AWS GovCloud, but the
dashboard layer requires internet for assets), or Palantir Foundry (cloud-hosted even at
IL5). The right answer for a classified enclave is a self-hosted stack: Python ETL
pipelines that pull from classified data sources, write to a local PostgreSQL or InfluxDB
instance, and feed a Grafana instance deployed on-premise within the enclave.

**What it looks like**:
- Choropleth map of INDOPACOM AOR with hex-binned sighting density, updated via
  automated Python ingestion every 4 hours
- Time-series panel showing sighting frequency by equipment category and region,
  with anomaly spike annotations
- Analyst alert panel: items exceeding baseline sighting rate by more than 2 standard
  deviations, flagged for intelligence review
- Access control via Grafana LDAP integration tied to the enclave's Active Directory

**Biggest risk**: Data pipeline reliability in air-gapped environments. Classified feeds
change formats frequently and have no SLA. Mitigate by building a pipeline validation
layer that alerts on schema drift before the dashboard shows stale or malformed data.

**What I would NOT build**: A predictive model embedded in the dashboard. The intelligence
cell wants to see what happened, not have the tool tell them what it means. Embedding
ML predictions in a classified ops tool without rigorous validation and analyst override
is a significant analytical integrity risk.

---

### Team B — Acquisition Reform Working Group

**Platform**: Advana with Qlik Sense

Two hundred non-data-literate users across 15 agencies, exploring contract awards
associatively — this is exactly the use case Qlik's associative engine was designed for.
Advana already hosts DoD-wide contract data (USASpending feeds, FPDS-NG), and Qlik's
point-and-click filtering requires no SQL knowledge from end users. FedRAMP Moderate
covers unclassified SBU data.

**What it looks like**:
- Landing screen: total obligations by agency (bar chart, click-to-filter)
- Vendor relationship network: top 50 vendors by award value, with drill-down to
  individual contract actions and NAICS codes
- Anomaly flagging panel: contracts exceeding historical vendor averages by 3σ, surfaced
  automatically via a Qlik expression using aggregated comparison
- Procurement threshold distribution: stacked bar showing micro-purchase vs. simplified
  acquisition vs. above-SAT by agency and FY

**Biggest risk**: Data freshness. If FPDS-NG data in Advana lags by 30+ days, anomaly
flags will be stale and contracting officers will lose trust in the tool. Mitigate by
displaying a "data last refreshed" timestamp prominently on every sheet.

**What I would NOT build**: A direct workflow integration that lets officers submit
anomaly reports through the Qlik app. Qlik is a read-only analytics tool; mixing
workflow into it creates a support nightmare. Send anomaly flags to email or a ticketing
system via Qlik's NPrinting or API layer, not through the Qlik UI itself.

---

### Team C — Maintenance Operations Cell

**Platform**: Palantir Foundry with Slate

This is the only scenario where the tool is explicitly read-write with workflow:
maintenance crews submit status updates, supervisors approve, commanders view. That
description is a Palantir Foundry Action and Slate operational app, not a dashboard.
Palantir's Ontology defines Equipment as an Object Type with properties (status, location,
last maintenance date); Actions define the allowed writes (submit update, approve work
order); Slate surfaces all of this in a point-and-click interface without requiring
analysts to write application code.

**What it looks like**:
- Maintenance crew view: their assigned equipment objects, current status, a form-based
  Action to submit a status update with free-text notes and a status enum (FMC, PMC, NMC)
- Supervisor view: pending approvals queue, one-click approve/reject Action, automatic
  rollup of equipment readiness by unit
- Commander view: readiness dashboard by unit and equipment category, pulling live from
  Ontology object properties (not a query — the objects update in real time as Actions
  are applied)

**Biggest risk**: Ontology design lock-in. Palantir Ontology schemas are expensive to
change once analysts build workflows on top of them. Mitigate by spending significant
time in the schema design phase with domain experts before building any Slate application.

**What I would NOT build**: Custom notification emails from Slate. Palantir has its own
notification system; custom email integrations with government mail servers (CAC/PIV
authentication, DISA SMTP restrictions) are a significant integration burden. Use the
built-in Foundry notification system instead.

---

## Solution 6: Accessibility and Annotation Audit

### Part A — Written Audit

**Accessibility failures**

- **Red and green color encoding without backup**: Approximately 8% of men have
  red-green color blindness; the three lines are indistinguishable to them, making the
  chart completely uninterpretable.
- **7-point footnote font**: Government accessibility standards (Section 508) and
  common briefing standards require minimum 10-point font for all text. At 7pt, the
  footnotes are unreadable in print and borderline for screen display.
- **No markers on lines**: In black-and-white print or photocopy, three lines with no
  markers are indistinguishable regardless of color, failing any reader using a
  monochrome reproduction.

**Clarity failures**

- **X-axis labeled 1–12 instead of month names**: The numeric labels force the reader
  to mentally translate "6" → "June," adding unnecessary cognitive load; labeled months
  eliminate this entirely.
- **Y-axis labeled "Pct" ranging 0 to 1**: The label "Pct" implies percentage (0–100%)
  but the axis range is 0–1, creating an ambiguous read. Use "Invoice Accuracy Rate"
  with values displayed as percentages (90%, 91%, etc.) or use a 0–100 axis.
- **Legend overlapping data**: Placing the legend inside the data area forces the reader
  to decode around it; a right-side or bottom external legend keeps data area clean.
- **No threshold line**: The 90% standard is the entire point of the chart — the IG
  audience needs to see whether performance is above or below it. Omitting it makes the
  chart decorative rather than analytical.
- **No annotation for June–July dip**: The largest feature in the data has no
  explanation; readers will speculate about a scandal or data error rather than
  understanding the systemic cause.

**Professionalism failures**

- **Title "Invoice Accuracy" without time period**: A chart title without a time period
  ("FY2024") cannot stand alone; a reader who detaches the slide from its deck has no
  context.
- **No source attribution**: In an IG briefing, all data must be traceable. No source
  means the chart cannot be independently verified and undermines credibility.
- **7-point footnotes signal disregard for the audience**: Small footnotes in formal
  government briefings communicate that the analyst wants to include information without
  the audience actually reading it — the opposite of transparency.

### Part B — Corrected Chart

```python
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

months = list(range(1, 13))
month_labels = ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
                "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]

accuracy = pd.DataFrame({
    "month": months,
    "month_label": month_labels,
    "dod_wide": [0.91, 0.92, 0.91, 0.93, 0.92, 0.84,
                 0.83, 0.89, 0.93, 0.94, 0.93, 0.95],
    "army":    [0.89, 0.91, 0.90, 0.92, 0.91, 0.81,
                0.80, 0.87, 0.92, 0.93, 0.92, 0.94],
    "navy":    [0.93, 0.94, 0.92, 0.94, 0.93, 0.86,
                0.85, 0.91, 0.94, 0.95, 0.94, 0.96],
})

threshold = 0.90

# ── Style ─────────────────────────────────────────────────────────────────────
plt.rcParams.update({
    "font.family": "DejaVu Sans",
    "font.size": 10,
    "axes.spines.top": False,
    "axes.spines.right": False,
})

fig, ax = plt.subplots(figsize=(10, 5.5))

# Distinct color + marker pairs (colorblind-safe Okabe-Ito)
series = [
    ("dod_wide", "DoD-Wide",  "#0072B2", "o"),   # blue, circle
    ("army",     "Army",      "#E69F00", "s"),   # orange, square
    ("navy",     "Navy",      "#009E73", "D"),   # green, diamond
]

for col, label, color, marker in series:
    ax.plot(
        accuracy["month_label"],
        accuracy[col],
        color=color,
        marker=marker,
        markersize=7,
        linewidth=2,
        label=label,
    )

# ── Threshold line ────────────────────────────────────────────────────────────
ax.axhline(threshold, color="#333333", linestyle="--", linewidth=1.5, zorder=1)
ax.text(
    11.6, threshold + 0.002,
    "90% Standard",
    fontsize=9.5,
    color="#333333",
    ha="right",
    va="bottom",
)

# ── Annotate the Jun–Jul dip ─────────────────────────────────────────────────
# Find midpoint of dip at index 5 (June) on DoD-wide line
dip_x = 5   # index for "Jun" in month_labels
ax.annotate(
    "Jun–Jul: Q3 invoice\nprocessing backlog\n(systemic pattern)",
    xy=(accuracy["month_label"].iloc[dip_x], accuracy["dod_wide"].iloc[dip_x]),
    xytext=(3.8, 0.815),
    fontsize=8.5,
    color="#555555",
    arrowprops=dict(arrowstyle="->", color="#555555", lw=1.0),
    bbox=dict(boxstyle="round,pad=0.3", fc="white", ec="#AAAAAA", alpha=0.95),
)

# ── Labels ────────────────────────────────────────────────────────────────────
ax.set_title(
    "Contractor Invoice Accuracy Rate by Component, FY2024",
    fontsize=12,
    fontweight="bold",
    pad=10,
)
ax.text(
    0.0, 1.01,
    "Source: Defense Contract Audit Agency (DCAA) Invoice Accuracy Database",
    transform=ax.transAxes,
    fontsize=9,
    color="#555555",
)
ax.set_xlabel("Month (FY2024)", fontsize=10)
ax.set_ylabel("Invoice Accuracy Rate", fontsize=10)
ax.yaxis.set_major_formatter(plt.FuncFormatter(lambda v, _: f"{v:.0%}"))
ax.set_ylim(0.77, 0.98)

# Legend outside data area
ax.legend(loc="lower right", framealpha=0.9, fontsize=10, bbox_to_anchor=(1.0, 0.02))

ax.grid(axis="y", alpha=0.3, color="#CCCCCC")

plt.tight_layout()
plt.savefig("output/ex6_invoice_accuracy_corrected.png", dpi=300, bbox_inches="tight")
plt.show()
```

### Part C — Annotation Decision

**Annotation text**:
> "Jun–Jul: Q3 invoice processing backlog (systemic pattern across FY)"

**Placement**: Inline callout near the dip, not a footnote.

**Reasoning**: This dip is the most important feature in the chart — it is the thing
the IG audience will immediately ask about. A footnote buries the explanation at the
bottom of the slide, where it may not be read before a question is asked. An inline
annotation forces the explanation onto the data itself, eliminating the ambiguity before
it arises. Footnotes are appropriate for caveats and methodological notes; explanations
of major data features belong on the chart next to the feature they explain.

---

*Chapter 10: Visualization & Dashboards*
*Data Science Learning Handbook*
