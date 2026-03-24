# Chapter 10: Visualization & Dashboards — Exercises

These exercises use real patterns from federal data work. Each one asks you to build
something a government analyst would actually need, on platforms they would actually use.
You will make design decisions that have no single right answer — the point is to defend
your choices with reasoning.

---

## Exercise 1: Government Briefing Chart (matplotlib)

**Difficulty**: Beginner
**Time estimate**: 30–45 minutes
**Skills**: matplotlib, government style guide, annotation

### Scenario

You support the Defense Logistics Agency (DLA) supply chain analytics team. Your director
needs a slide-ready chart for a briefing to the Deputy Assistant Secretary of Defense next
Tuesday. The chart must show aviation spare parts fill rates by service branch (Army, Navy,
Air Force, Marines) over fiscal years 2021–2025, with a horizontal line at the 85% contract
threshold.

The chart will be printed in black and white and also projected in a conference room with
fluorescent lighting. Accessibility for colorblind viewers is required.

### Data

```python
import pandas as pd
import numpy as np

np.random.seed(42)

services = ["Army", "Navy", "Air Force", "Marines"]
fy_years = [2021, 2022, 2023, 2024, 2025]

# Baseline fill rates with realistic variation
baselines = {"Army": 0.81, "Navy": 0.84, "Air Force": 0.87, "Marines": 0.79}
trend = {"Army": 0.012, "Navy": 0.008, "Air Force": 0.005, "Marines": 0.015}

records = []
for svc in services:
    for i, fy in enumerate(fy_years):
        rate = baselines[svc] + trend[svc] * i + np.random.normal(0, 0.01)
        records.append({"service": svc, "fiscal_year": fy, "fill_rate": min(rate, 1.0)})

fill_rates = pd.DataFrame(records)
threshold = 0.85
```

### Requirements

1. Apply the government briefing style from `01_matplotlib_seaborn_charts.py`:
   - Use the Okabe-Ito colorblind-safe palette
   - 10-point minimum font size
   - No chartjunk (no top/right spines, no unnecessary gridlines)

2. Plot fill rates as line chart with markers. Each service gets a distinct color **and**
   a distinct marker shape (circle, square, diamond, triangle) so the chart reads in
   black and white print.

3. Add the 85% threshold line as a dashed horizontal line with a label.

4. Annotate the single lowest data point — the service and year where fill rate was
   furthest below threshold — with a text callout explaining the gap.

5. Title format: `"Aviation Spare Parts Fill Rate by Service Branch, FY2021–FY2025"`
   Subtitle: `"Contract threshold: 85% | Source: DLA Enterprise Business System"`

6. Export as both PNG (300 DPI) and a clean PDF suitable for slide embedding.

### Questions to Answer

After completing the chart, write 2–3 sentences responding to each:

a. You chose specific marker shapes for each service branch. Explain why you assigned
   markers the way you did. Was the assignment arbitrary, or is there logic to it?

b. A colleague suggests using red for the Marines line because their fill rate is lowest.
   What is the problem with using color alone to encode performance quality in a
   government briefing? How does your design handle this differently?

c. The deputy asks you to add a second Y-axis showing absolute unit counts. What is the
   risk of dual-axis charts in briefings, and under what conditions would you agree
   to add it?

---

## Exercise 2: Interactive Analyst Dashboard (Plotly)

**Difficulty**: Intermediate
**Time estimate**: 60–90 minutes
**Skills**: Plotly, interactive filtering, multi-panel layout

### Scenario

Your team at U.S. Transportation Command (TRANSCOM) maintains a Python-based analyst
portal that runs in a government-issued browser (Chrome, no JavaScript framework
restrictions, but no external CDN calls). Analysts need an interactive dashboard to
explore airlift mission performance: sorties flown vs. planned, on-time departure rate,
cargo utilization rate, and fuel consumption per ton-mile.

The dashboard will be saved as a self-contained HTML file and shared via SharePoint.
Analysts must be able to filter by aircraft type (C-17, C-5, KC-135) and fiscal quarter
without writing code.

### Data

```python
import pandas as pd
import numpy as np

np.random.seed(7)

n = 300
aircraft_types = ["C-17", "C-5", "KC-135"]
quarters = ["Q1", "Q2", "Q3", "Q4"]

missions = pd.DataFrame({
    "aircraft": np.random.choice(aircraft_types, n),
    "fy_quarter": np.random.choice(quarters, n),
    "sorties_planned": np.random.randint(8, 25, n),
    "sorties_flown": lambda df: (df["sorties_planned"] * np.random.uniform(0.75, 1.0, n)).astype(int),
    "on_time_pct": np.random.beta(8, 2, n) * 100,
    "cargo_utilization_pct": np.random.beta(6, 2, n) * 100,
    "fuel_per_ton_mile": np.random.normal(0.45, 0.06, n).clip(0.30, 0.65),
})
missions["sorties_flown"] = (missions["sorties_planned"] * np.random.uniform(0.75, 1.0, n)).astype(int)
missions["execution_rate"] = missions["sorties_flown"] / missions["sorties_planned"]
```

### Requirements

1. Build a four-panel Plotly dashboard using `make_subplots`:
   - **Panel 1 (top-left)**: Bar chart — sorties flown vs. planned, grouped by aircraft type
   - **Panel 2 (top-right)**: Box plot — on-time departure rate distribution by aircraft type
   - **Panel 3 (bottom-left)**: Scatter plot — cargo utilization vs. fuel per ton-mile,
     colored by aircraft type, with a reference line at the fleet average fuel efficiency
   - **Panel 4 (bottom-right)**: Grouped bar — execution rate by aircraft type and
     fiscal quarter

2. Add Plotly dropdown menus to filter by fiscal quarter (all quarters + individual
   selection). When a quarter is selected, all four panels update.

3. Use the government color palette from `02_plotly_interactive.py`. Every trace must
   have a meaningful hover template showing at least: aircraft type, metric value,
   fiscal quarter.

4. Export as a self-contained HTML file using `include_plotlyjs='cdn'` — then explain
   in a comment why this choice creates a problem for a classified network and what
   you would use instead.

5. Title the dashboard: `"TRANSCOM Airlift Mission Performance — Interactive Analysis"`

### Questions to Answer

a. A Plotly dropdown filter using `updatemenus` works differently from a true data filter
   — it toggles trace visibility rather than recomputing data. Explain the limitation
   this creates when you have aggregated metrics (like averages) and how you would work
   around it for production use.

b. Your manager asks why you used box plots for on-time departure rate instead of just
   showing the mean. Write 2–3 sentences defending the box plot choice in terms of what
   it reveals that a mean alone hides.

c. The classified network constraint you identified in requirement 4 comes up constantly
   in government work. Describe two other Plotly export or deployment strategies that
   would work in an air-gapped environment.

---

## Exercise 3: Databricks Lakeview Dashboard Design

**Difficulty**: Intermediate
**Time estimate**: 45–60 minutes
**Skills**: SQL, Delta Lake, Lakeview Dashboard concepts, Unity Catalog

### Scenario

You are a data engineer at the Defense Health Agency (DHA). Your team ingests daily
medical supply utilization data from military treatment facilities (MTFs) into a Delta
table in Databricks on AWS GovCloud. A clinical operations team needs a dashboard showing:
supply consumption rate vs. par level by item category, reorder alerts (items below 20%
of par), and a 30-day consumption trend.

You cannot share the actual Databricks workspace, so you will write the SQL and Python
that would back the dashboard, then design the dashboard schema on paper.

### Data Setup

```python
# Run this in a Databricks notebook to set up demo data
# (or adapt for local SQLite/DuckDB to test the SQL)

import pandas as pd
import numpy as np
from datetime import date, timedelta

np.random.seed(99)

categories = ["Surgical Supplies", "Pharmaceuticals", "Diagnostic Equipment", "PPE"]
items_per_cat = 8
n_items = len(categories) * items_per_cat
n_days = 45

items = []
for cat in categories:
    for i in range(items_per_cat):
        items.append({
            "item_id": f"{cat[:3].upper()}-{i+1:03d}",
            "item_name": f"{cat} Item {i+1}",
            "category": cat,
            "par_level": np.random.randint(50, 500),
            "unit": "EA",
        })

items_df = pd.DataFrame(items)

records = []
start_date = date(2025, 11, 1)
for day_offset in range(n_days):
    day = start_date + timedelta(days=day_offset)
    for _, item in items_df.iterrows():
        daily_use = np.random.poisson(item["par_level"] * 0.04)
        current_stock = max(0, item["par_level"] - int(day_offset * item["par_level"] * 0.03)
                           + np.random.randint(-10, 20))
        records.append({
            "snapshot_date": day,
            "item_id": item["item_id"],
            "category": item["category"],
            "par_level": item["par_level"],
            "current_stock": current_stock,
            "daily_consumption": daily_use,
        })

utilization_df = pd.DataFrame(records)
```

### Requirements

**Part A — SQL Queries**

Write three SQL queries that would back the dashboard panels. Write them as if targeting
a Delta table named `health.dha.mtf_supply_utilization` in Unity Catalog:

1. **Stock status query**: For the most recent snapshot date, return each item with its
   category, current stock, par level, stock-to-par ratio (as a percentage), and a
   derived column `alert_status` with values `"CRITICAL"` (below 20%), `"WARNING"`
   (20%–50%), or `"OK"` (above 50%). Sort by alert status (CRITICAL first), then ratio.

2. **Category rollup query**: Aggregate by category for the most recent date — total par
   capacity, total current stock, category-level stock percentage, and count of items
   in CRITICAL or WARNING status.

3. **30-day trend query**: For each category, compute the 7-day rolling average of total
   daily consumption. Return one row per (date, category). This powers the trend line
   panel.

**Part B — Dashboard Design Document**

Write a short design document (bullet points are fine) covering:

- How many panels the dashboard needs and what each shows
- Which query backs each panel
- What filters the dashboard exposes (date range, category, alert status)
- Why you would use a Delta table as the data source rather than a live query against
  the source system
- One Unity Catalog permission you would set and why

**Part C — Refresh Strategy**

The clinical team wants data updated every morning by 07:00 local time. Describe the
Databricks job or workflow you would configure to ensure the Delta table is refreshed
before analysts arrive. Include: trigger type, what the job does, and how you would
handle failures.

---

## Exercise 4: Qlik Data Model Design

**Difficulty**: Intermediate–Advanced
**Time estimate**: 60–75 minutes
**Skills**: Qlik associative model, QVD layer, load script, circular reference avoidance

### Scenario

You are building a Qlik Sense application on Advana for the Army's budget execution
analysts. The app will let analysts click any program element (PE) and immediately see
its obligations, expenditures, and contract actions — filtered associatively across all
panels without writing a single filter expression.

You have three source tables:

- **budget_lines**: `PE_code`, `PE_name`, `appropriation`, `authorized_amount`, `fy`
- **obligations**: `obligation_id`, `PE_code`, `contract_id`, `obligated_amount`,
  `obligation_date`, `fy`
- **contract_actions**: `contract_id`, `vendor_name`, `award_date`, `action_type`,
  `action_value`, `naics_code`

### Requirements

**Part A — Data Model Diagram**

Draw (in ASCII or Mermaid) a data model showing how the three tables link. Label:
- Which fields are key fields (join fields in Qlik)
- The cardinality of each relationship (1:many, many:many, etc.)
- Where synthetic keys would occur if you loaded naively

**Part B — Load Script**

Write a Qlik load script that:

1. Loads `budget_lines` from a QVD file path `[lib://GovData/budget_lines.qvd]`
2. Loads `obligations`, renaming `fy` to `obligation_fy` to avoid a synthetic key with
   `budget_lines.fy`
3. Loads `contract_actions` from QVD
4. Adds a derived field `obligation_quarter` computed from `obligation_date`
   (format: `"Q" & Ceil(Month(obligation_date)/3)` in Qlik script syntax)
5. Adds a `procurement_threshold_band` field to `contract_actions` based on `action_value`:
   - `"Micro-Purchase"` if below $10,000
   - `"Simplified Acquisition"` if $10,000–$250,000
   - `"Above SAT"` if above $250,000

**Part C — Circular Reference Check**

Explain what a circular reference in a Qlik data model is, why it breaks the associative
engine, and how you would restructure the three tables above if `contract_actions` also
contained a `PE_code` field (creating a loop: budget_lines → obligations → contract_actions
→ budget_lines).

**Part D — Reflection**

The Qlik QIX engine's associative model is fundamentally different from SQL JOINs or
Pandas merges. Write a short paragraph (4–6 sentences) explaining this difference to a
new analyst who has only used SQL before. Focus on what happens when a user clicks a
value in Qlik versus running a WHERE clause.

---

## Exercise 5: Platform Selection Scenario

**Difficulty**: Advanced
**Time estimate**: 45–60 minutes
**Skills**: Platform trade-offs, audience analysis, classification constraints

### Scenario

You are a senior data scientist supporting the Joint Artificial Intelligence Center (JAIC,
now part of CDAO). Three teams come to you with visualization needs in the same week:

**Team A — Intelligence Fusion Cell (SECRET//REL TO FIVE EYES)**
Needs a dashboard showing adversary equipment sighting frequency by geographic region,
updated every 4 hours from classified feeds. Must support 12 simultaneous analysts.
Data must never leave the classified enclave.

**Team B — Acquisition Reform Working Group (UNCLASSIFIED, SBU)**
Needs an interactive tool where contracting officers can explore DoD-wide contract
awards, drill into vendor relationships, and flag potential anomalies for review.
Tool must support occasional users who are not data-literate. Expected 200+ users
across 15 agencies.

**Team C — Maintenance Operations Cell (UNCLASSIFIED, CUI)**
Needs a read-write operational app: maintenance crews submit status updates, supervisors
approve work orders, and commanders see a live equipment readiness picture. Not a
dashboard — this is a decision-support tool with workflow.

### Requirements

For each team, write a recommendation covering:

1. **Platform choice**: Which of the five platforms (Advana/Qlik, Databricks Lakeview,
   Palantir Foundry/Slate, Grafana, or a custom Python tool) you recommend, and **why
   this specific platform** fits their needs better than the alternatives.

2. **What the tool looks like**: 2–4 bullet points describing the key panels, features,
   or interactions. Be specific — not "show a map" but "choropleth map of INDOPACOM AOR
   with hex-binned sighting density, click-to-filter by equipment category."

3. **One risk**: The single biggest technical or organizational risk for your recommendation,
   and how you would mitigate it.

4. **One thing you would NOT build**: A feature request that sounds reasonable but that
   you would push back on, with your reasoning.

### Constraint

You may not recommend the same platform for more than two of the three teams. Force
yourself to use at least three different platforms.

---

## Exercise 6: Accessibility and Annotation Audit

**Difficulty**: Beginner–Intermediate
**Time estimate**: 30–45 minutes
**Skills**: Chart critique, accessibility, annotation standards

### Scenario

A junior analyst on your team produced the following chart for an Inspector General
briefing on contractor invoice accuracy. The chart exists only as a description below —
your job is to audit it and rewrite it correctly.

**Original chart description:**

> Line chart. Title: "Invoice Accuracy." X-axis: months (Jan–Dec 2024, labeled 1–12).
> Y-axis: "Pct" ranging from 0 to 1. Three lines: red (DoD-wide), green (Army), blue
> (Navy). No markers. No threshold line. Legend placed over the data in the upper-right.
> No source attribution. Footnotes in 7-point font. No annotation explaining the dip
> in months 6–7.

### Requirements

**Part A — Written Audit**

List every problem with the original chart. Organize your audit into three categories:

- **Accessibility failures**: Problems that make the chart unusable for some audiences
- **Clarity failures**: Problems that make the chart harder to understand than it should be
- **Professionalism failures**: Problems that would undermine credibility in a formal briefing

For each problem, write one sentence explaining the specific harm it causes.

**Part B — Corrected Chart**

Write Python code (matplotlib) that produces a corrected version of this chart using
the data below. Your corrected chart must address every problem you identified in Part A.

```python
import pandas as pd
import numpy as np

months = list(range(1, 13))
month_labels = ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
                "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]

# FY2024 invoice accuracy rates (0–1 scale)
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

threshold = 0.90  # DoD invoice accuracy standard
```

**Part C — Annotation Decision**

The dip in June–July corresponds to end-of-fiscal-Q3 invoice processing backlogs, a
known systemic pattern. Write the annotation text you would add to the chart, and
explain whether you would place it as an inline label near the dip or as a footnote,
and why.

---

## Submission Notes

- Save your charts as PNG files in a `output/` directory
- Write your question responses in a separate `responses.md` file
- For exercises involving SQL or Qlik load script, you may test locally using DuckDB
  (`pip install duckdb`) as a substitute for Delta or QVD sources
- Solutions are in `exercises/solutions/solutions.md` — attempt each exercise before
  checking

---

*Chapter 10: Visualization & Dashboards*
*Data Science Learning Handbook*
