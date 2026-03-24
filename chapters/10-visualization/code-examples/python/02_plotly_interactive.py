"""
Chapter 10: Visualization and Dashboards
Example 2: Plotly Interactive Charts for Analyst Tools

Plotly produces interactive HTML charts that run in:
  - Databricks notebooks (use display(fig) or fig.show())
  - Palantir Foundry Code Workspaces (fig.show())
  - Local Jupyter notebooks (fig.show())
  - Standalone HTML files for sharing via email or file server
  - Embedded in web applications via Dash

When NOT to use Plotly:
  - When the output is a PDF or PowerPoint slide (use matplotlib instead)
  - When the consumer cannot run JavaScript (email clients, some government
    document management systems)
  - When the chart will be printed

In those cases, use matplotlib/seaborn from 01_matplotlib_seaborn_charts.py.

Scenario: Procurement anomaly investigation dashboard and readiness
monitoring tool for analyst self-service on Advana/Databricks.
"""

import warnings
from typing import Dict, List, Optional, Tuple

import numpy as np
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots

warnings.filterwarnings("ignore")


# ============================================================
# STYLE CONFIGURATION
# ============================================================

# Government-appropriate Plotly template
# Clean white background, readable fonts, colorblind-safe colors
GOVT_PLOTLY_COLORS = [
    "#0072B2",  # blue
    "#E69F00",  # orange
    "#009E73",  # green
    "#D55E00",  # red
    "#CC79A7",  # purple
    "#56B4E9",  # sky blue
    "#F0E442",  # yellow
    "#000000",  # black
]

PLOTLY_LAYOUT_DEFAULTS = dict(
    font=dict(family="Arial, sans-serif", size=12, color="#333333"),
    plot_bgcolor="white",
    paper_bgcolor="white",
    colorway=GOVT_PLOTLY_COLORS,
    legend=dict(
        orientation="h",
        yanchor="bottom",
        y=1.02,
        xanchor="right",
        x=1,
        bgcolor="rgba(255,255,255,0.8)"
    ),
    margin=dict(l=60, r=40, t=60, b=60),
    hoverlabel=dict(bgcolor="white", font_size=11),
)


def govt_fig_layout(fig: go.Figure, title: str = None,
                     height: int = 500) -> go.Figure:
    """Apply standard government layout to a Plotly figure."""
    updates = {**PLOTLY_LAYOUT_DEFAULTS, "height": height}
    if title:
        updates["title"] = dict(text=title, font=dict(size=14, color="#222222"),
                                 x=0, xanchor="left")
    fig.update_layout(**updates)
    fig.update_xaxes(showgrid=True, gridcolor="#eeeeee", linecolor="#cccccc")
    fig.update_yaxes(showgrid=True, gridcolor="#eeeeee", linecolor="#cccccc")
    return fig


# ============================================================
# SECTION 1: MULTI-METRIC READINESS DASHBOARD
# ============================================================

def build_readiness_dashboard(
    df: pd.DataFrame,
    date_col: str,
    unit_col: str,
    readiness_col: str,
    mc_threshold: float = 0.75,
    title: str = "Fleet Readiness Dashboard",
) -> go.Figure:
    """
    Interactive readiness monitoring dashboard.

    Four panels:
    - Top left: Trend lines per unit over time
    - Top right: Current readiness by unit (horizontal bar)
    - Bottom left: Units below threshold count over time
    - Bottom right: Distribution of current-period readiness

    Args:
        df: Long-format DataFrame
        date_col: Date column
        unit_col: Unit identifier column
        readiness_col: Readiness rate column (0.0–1.0)
        mc_threshold: Mission-capable threshold
        title: Dashboard title
    """
    fig = make_subplots(
        rows=2, cols=2,
        subplot_titles=[
            "Readiness Trend by Unit",
            "Current Period Readiness (Latest)",
            "Units Below Threshold Over Time",
            "Readiness Rate Distribution"
        ],
        vertical_spacing=0.14,
        horizontal_spacing=0.10,
        row_heights=[0.55, 0.45],
    )

    units = sorted(df[unit_col].unique())
    latest_period = df[date_col].max()
    latest_df = df[df[date_col] == latest_period].copy()

    # --- Panel 1: Trend lines ---
    for i, unit in enumerate(units[:12]):  # cap at 12 for readability
        unit_df = df[df[unit_col] == unit].sort_values(date_col)
        color = GOVT_PLOTLY_COLORS[i % len(GOVT_PLOTLY_COLORS)]
        fig.add_trace(
            go.Scatter(
                x=unit_df[date_col],
                y=unit_df[readiness_col],
                name=str(unit),
                mode="lines+markers",
                line=dict(color=color, width=1.8),
                marker=dict(size=4),
                hovertemplate=(
                    f"<b>{unit}</b><br>"
                    "Date: %{x|%b %Y}<br>"
                    "Readiness: %{y:.1%}<extra></extra>"
                ),
                showlegend=True,
            ),
            row=1, col=1
        )

    # Threshold line on trend panel
    fig.add_hline(
        y=mc_threshold, line_dash="dash",
        line_color="#D55E00", line_width=1.5,
        annotation_text=f"Required {mc_threshold:.0%}",
        annotation_position="bottom right",
        row=1, col=1
    )

    # --- Panel 2: Current period horizontal bars ---
    latest_sorted = latest_df.sort_values(readiness_col)
    bar_colors = [
        "#009E73" if v >= mc_threshold else "#D55E00"
        for v in latest_sorted[readiness_col]
    ]
    fig.add_trace(
        go.Bar(
            x=latest_sorted[readiness_col],
            y=latest_sorted[unit_col].astype(str),
            orientation="h",
            marker_color=bar_colors,
            text=[f"{v:.1%}" for v in latest_sorted[readiness_col]],
            textposition="outside",
            hovertemplate="%{y}: %{x:.1%}<extra></extra>",
            showlegend=False,
        ),
        row=1, col=2
    )
    fig.add_vline(
        x=mc_threshold, line_dash="dash",
        line_color="#D55E00", line_width=1.5,
        row=1, col=2
    )

    # --- Panel 3: Units below threshold count ---
    below = (
        df[df[readiness_col] < mc_threshold]
        .groupby(date_col)[unit_col].nunique()
        .reset_index()
        .rename(columns={unit_col: "n_below"})
    )
    fig.add_trace(
        go.Bar(
            x=below[date_col],
            y=below["n_below"],
            marker_color="#D55E00",
            opacity=0.75,
            name="Units below threshold",
            hovertemplate="Date: %{x|%b %Y}<br>Units below threshold: %{y}<extra></extra>",
            showlegend=False,
        ),
        row=2, col=1
    )

    # --- Panel 4: Distribution ---
    current_vals = latest_df[readiness_col].dropna()
    fig.add_trace(
        go.Histogram(
            x=current_vals,
            nbinsx=20,
            marker_color="#0072B2",
            opacity=0.75,
            name="Distribution",
            hovertemplate="Readiness: %{x:.1%}<br>Count: %{y}<extra></extra>",
            showlegend=False,
        ),
        row=2, col=2
    )
    fig.add_vline(
        x=mc_threshold, line_dash="dash",
        line_color="#D55E00", line_width=1.5,
        annotation_text=f"Threshold {mc_threshold:.0%}",
        annotation_position="top left",
        row=2, col=2
    )

    # Axis formatting
    fig.update_xaxes(tickformat=".0%", row=1, col=1)
    fig.update_yaxes(tickformat=".0%", row=1, col=1)
    fig.update_xaxes(tickformat=".0%", row=1, col=2, range=[0, 1.1])
    fig.update_xaxes(tickformat=".0%", row=2, col=2)

    govt_fig_layout(fig, title=title, height=750)

    return fig


# ============================================================
# SECTION 2: PROCUREMENT ANOMALY SCATTER
# ============================================================

def build_anomaly_scatter(
    df: pd.DataFrame,
    x_col: str,
    y_col: str,
    anomaly_score_col: str,
    label_col: str,
    x_label: str,
    y_label: str,
    title: str,
    score_threshold: float = 0.7,
) -> go.Figure:
    """
    Interactive scatter plot with anomaly score as color and size encoding.

    Used for procurement anomaly investigation: each point is a contract.
    Hovering shows vendor name, contract value, and anomaly drivers.
    Anomalous contracts are visually prominent (large, dark red).

    Args:
        df: DataFrame with at least x_col, y_col, anomaly_score_col, label_col
        x_col: X-axis variable (e.g., "obligation_amount")
        y_col: Y-axis variable (e.g., "days_to_award")
        anomaly_score_col: 0-1 score (1 = most anomalous)
        label_col: Hover label column (e.g., vendor name)
        score_threshold: Score above which to label points as anomalous
    """
    df = df.copy()
    df["is_anomaly"] = df[anomaly_score_col] >= score_threshold
    df["marker_size"] = 4 + df[anomaly_score_col] * 16  # 4–20 px range

    # Color: continuous scale from blue (normal) to red (anomalous)
    fig = go.Figure()

    # Normal points
    normal = df[~df["is_anomaly"]]
    fig.add_trace(go.Scatter(
        x=normal[x_col],
        y=normal[y_col],
        mode="markers",
        marker=dict(
            size=normal["marker_size"],
            color="#0072B2",
            opacity=0.4,
            line=dict(width=0)
        ),
        text=normal[label_col],
        customdata=normal[anomaly_score_col].round(3),
        hovertemplate=(
            "<b>%{text}</b><br>"
            f"{x_label}: %{{x:,.0f}}<br>"
            f"{y_label}: %{{y:.0f}}<br>"
            "Anomaly score: %{customdata}<extra></extra>"
        ),
        name="Normal",
        showlegend=True,
    ))

    # Anomalous points
    anomalous = df[df["is_anomaly"]]
    if len(anomalous) > 0:
        fig.add_trace(go.Scatter(
            x=anomalous[x_col],
            y=anomalous[y_col],
            mode="markers+text",
            marker=dict(
                size=anomalous["marker_size"],
                color="#D55E00",
                opacity=0.85,
                line=dict(width=1, color="#8B1A00")
            ),
            text=anomalous[label_col],
            textposition="top center",
            textfont=dict(size=8, color="#D55E00"),
            customdata=anomalous[anomaly_score_col].round(3),
            hovertemplate=(
                "<b>%{text}</b><br>"
                f"{x_label}: %{{x:,.0f}}<br>"
                f"{y_label}: %{{y:.0f}}<br>"
                "Anomaly score: %{customdata} ← FLAG<extra></extra>"
            ),
            name=f"Flagged (score ≥ {score_threshold:.1f})",
            showlegend=True,
        ))

    fig.update_xaxes(title_text=x_label, type="log")
    fig.update_yaxes(title_text=y_label)
    govt_fig_layout(fig, title=title, height=550)

    return fig


# ============================================================
# SECTION 3: FISCAL YEAR SPENDING WATERFALL
# ============================================================

def build_fy_spending_waterfall(
    categories: List[str],
    values: List[float],
    title: str,
    yaxis_label: str = "Obligations ($M)",
) -> go.Figure:
    """
    Waterfall chart for fiscal year budget execution analysis.

    Waterfall charts show incremental changes (increases and decreases)
    from a baseline — ideal for showing how a budget built up or was
    modified over the course of a fiscal year.

    Args:
        categories: Labels for each bar (e.g., ["Base Budget", "Supplemental",
                    "Rescission", "Emergency", "Final Enacted"])
        values: Dollar values — positive for additions, negative for reductions.
                First value is the baseline (absolute, not incremental).
        title: Chart title
    """
    # Plotly waterfall: "relative" for incremental, "total" for final sum
    measure = ["absolute"] + ["relative"] * (len(values) - 2) + ["total"]

    # Color: positive increments green, negative red, total/absolute blue
    colors = []
    for m, v in zip(measure, values):
        if m in ("absolute", "total"):
            colors.append(GOVT_PLOTLY_COLORS[0])
        elif v >= 0:
            colors.append(GOVT_PLOTLY_COLORS[2])
        else:
            colors.append(GOVT_PLOTLY_COLORS[3])

    fig = go.Figure(go.Waterfall(
        name="Budget execution",
        orientation="v",
        measure=measure,
        x=categories,
        y=[v / 1e6 for v in values],  # convert to $M
        connector=dict(line=dict(color="#aaaaaa", width=1)),
        decreasing=dict(marker=dict(color=GOVT_PLOTLY_COLORS[3])),
        increasing=dict(marker=dict(color=GOVT_PLOTLY_COLORS[2])),
        totals=dict(marker=dict(color=GOVT_PLOTLY_COLORS[0])),
        text=[f"${v/1e6:+.1f}M" for v in values],
        textposition="outside",
        hovertemplate="%{x}: %{y:.1f}M<extra></extra>",
    ))

    fig.update_yaxes(title_text=yaxis_label,
                     ticksuffix="M",
                     tickprefix="$")
    govt_fig_layout(fig, title=title, height=480)

    return fig


# ============================================================
# SECTION 4: GEOSPATIAL — BASE/INSTALLATION READINESS MAP
# ============================================================

def build_installation_map(
    df: pd.DataFrame,
    lat_col: str,
    lon_col: str,
    label_col: str,
    value_col: str,
    threshold: float,
    title: str,
    value_label: str = "Readiness Rate",
) -> go.Figure:
    """
    Mapbox scatter map showing readiness by installation.
    Color-coded by status relative to threshold.

    Requires: pip install plotly (no separate mapbox token needed for
    basic scatter_mapbox — uses open-source map tiles).

    Args:
        df: DataFrame with lat/lon and readiness values
        lat_col, lon_col: Coordinate columns
        label_col: Installation name column
        value_col: Readiness value column
        threshold: Threshold for red/green coloring
    """
    df = df.copy()
    df["status"] = df[value_col].apply(
        lambda v: "Above Threshold" if v >= threshold else "Below Threshold"
    )
    df["color"] = df["status"].map({
        "Above Threshold": "#009E73",
        "Below Threshold": "#D55E00",
    })
    df["size"] = 12 + (1 - abs(df[value_col] - threshold)) * 8

    fig = px.scatter_mapbox(
        df,
        lat=lat_col,
        lon=lon_col,
        hover_name=label_col,
        hover_data={
            value_col: ":.1%",
            "status": True,
            lat_col: False,
            lon_col: False,
        },
        color="status",
        color_discrete_map={
            "Above Threshold": "#009E73",
            "Below Threshold": "#D55E00",
        },
        size="size",
        size_max=20,
        zoom=3,
        center=dict(lat=38, lon=-96),
        mapbox_style="carto-positron",
        title=title,
        height=550,
    )
    govt_fig_layout(fig, title=title, height=550)
    return fig


# ============================================================
# SECTION 5: EXPORT UTILITIES
# ============================================================

def save_for_databricks(fig: go.Figure, display_in_notebook: bool = True):
    """
    Display a Plotly figure in a Databricks notebook.

    In Databricks, use display(fig) or fig.show() depending on
    the notebook's displayHTML capability. Both work in standard
    Python notebooks on Databricks Runtime 12+.
    """
    try:
        # Databricks built-in display function
        display(fig)  # noqa: F821 — 'display' is a Databricks built-in
    except NameError:
        # Fall back to standard Plotly show (works in Jupyter)
        fig.show()


def export_to_html(fig: go.Figure, output_path: str, include_plotlyjs: bool = True):
    """
    Export a Plotly figure to a self-contained HTML file.

    Self-contained means all JavaScript is embedded — the file can be
    sent by email and opened without internet access. File size ~3-5 MB.

    For lighter weight sharing (requires internet), use include_plotlyjs="cdn".

    Args:
        output_path: Path for the .html file
        include_plotlyjs: True = embedded JS (~3MB), "cdn" = linked JS (tiny)
    """
    fig.write_html(
        output_path,
        include_plotlyjs=include_plotlyjs,
        full_html=True,
        config={
            "displayModeBar": True,
            "toImageButtonOptions": {
                "format": "png",
                "filename": "government_chart",
                "width": 1200,
                "height": 700,
                "scale": 2,
            },
            "modeBarButtonsToRemove": ["sendDataToCloud"],
        }
    )
    print(f"Saved interactive HTML: {output_path}")


def export_to_png(fig: go.Figure, output_path: str,
                   width: int = 1200, height: int = 700, scale: int = 2):
    """
    Export Plotly figure to high-resolution PNG for briefing decks.

    Requires kaleido: pip install kaleido
    This produces better output than screenshotting the browser.

    scale=2 produces a 2400×1400 image — crisp on retina displays and
    when embedded in 4K slide decks.
    """
    try:
        fig.write_image(output_path, width=width, height=height, scale=scale)
        print(f"Saved PNG: {output_path} ({width*scale}×{height*scale}px)")
    except ImportError:
        print("kaleido not installed. Run: pip install kaleido")
        print("Alternatively, use fig.write_html() and screenshot the browser.")


# ============================================================
# DEMO
# ============================================================

def generate_demo_data():
    """Synthetic readiness and procurement data for dashboard demos."""
    rng = np.random.default_rng(42)

    # Readiness by unit over 18 months
    units = [f"CVN-{i}" for i in [68, 69, 70, 71, 72, 73, 74, 75]]
    dates = pd.date_range("2023-01-01", periods=18, freq="ME")
    rows = []
    for unit in units:
        base = rng.uniform(0.65, 0.90)
        for i, dt in enumerate(dates):
            rows.append({
                "date": dt,
                "unit": unit,
                "readiness": float(np.clip(
                    base + rng.normal(0, 0.04) + i * 0.003, 0.5, 1.0
                ))
            })
    readiness_df = pd.DataFrame(rows)

    # Procurement anomaly data
    n = 400
    contract_values = np.exp(rng.normal(12, 2.5, n))
    days_to_award = rng.integers(5, 500, n).astype(float)
    n_competitors = rng.poisson(2.8, n).astype(float)

    # Inject 15 anomalous contracts: very high value, short award timeline, 0 competitors
    anomaly_idx = rng.choice(n, 15, replace=False)
    contract_values[anomaly_idx] *= 8
    days_to_award[anomaly_idx] = rng.integers(2, 15, 15)
    n_competitors[anomaly_idx] = 0

    # Compute simple anomaly score (for demo: based on distance from median)
    from scipy.stats import zscore
    z_val = np.abs(zscore(np.log1p(contract_values)))
    z_days = np.abs(zscore(days_to_award))
    z_comp = np.abs(zscore(n_competitors))
    raw_score = (z_val + z_days + z_comp) / 3
    anomaly_scores = (raw_score - raw_score.min()) / (raw_score.max() - raw_score.min())

    vendor_names = [f"Vendor_{rng.integers(1, 80):03d}" for _ in range(n)]
    procurement_df = pd.DataFrame({
        "vendor": vendor_names,
        "obligation_amount": contract_values,
        "days_to_award": days_to_award,
        "n_competitors": n_competitors,
        "anomaly_score": anomaly_scores,
    })

    # Budget waterfall
    fy_categories = [
        "FY2024 Enacted", "Supplemental (Jan)", "Rescission (Mar)",
        "Emergency Supp (Jun)", "Reprogramming (Aug)", "FY2024 Final"
    ]
    fy_values = [
        4_200_000_000,
        +350_000_000,
        -120_000_000,
        +580_000_000,
        +75_000_000,
        5_085_000_000,
    ]

    # Installation map
    installations = pd.DataFrame({
        "installation": ["NAS Oceana", "NAS Lemoore", "NAS Whidbey Island",
                          "NAS Jacksonville", "NAS Fallon", "MCAS Cherry Point",
                          "NAS North Island", "NAS Patuxent River"],
        "lat": [36.82, 36.33, 48.35, 30.23, 39.42, 34.90, 32.70, 38.28],
        "lon": [-76.03, -119.95, -122.66, -81.68, -118.70, -76.88, -117.21, -76.41],
        "readiness": [0.82, 0.71, 0.88, 0.69, 0.79, 0.84, 0.73, 0.91],
    })

    return readiness_df, procurement_df, fy_categories, fy_values, installations


if __name__ == "__main__":
    readiness_df, proc_df, fy_cats, fy_vals, install_df = generate_demo_data()

    print("Building interactive Plotly dashboards...\n")

    # Dashboard 1: Readiness monitoring
    fig1 = build_readiness_dashboard(
        readiness_df, "date", "unit", "readiness",
        mc_threshold=0.75,
        title="Carrier Readiness Dashboard — FY2023"
    )
    export_to_html(fig1, "/tmp/readiness_dashboard.html")
    print("Dashboard 1: Readiness monitoring → /tmp/readiness_dashboard.html")

    # Chart 2: Anomaly scatter
    fig2 = build_anomaly_scatter(
        proc_df, "obligation_amount", "days_to_award", "anomaly_score", "vendor",
        x_label="Contract Obligation ($, log scale)",
        y_label="Days to Award",
        title="Procurement Anomaly Investigation — Obligation vs. Award Timeline",
        score_threshold=0.70,
    )
    export_to_html(fig2, "/tmp/anomaly_scatter.html")
    print("Chart 2: Anomaly scatter → /tmp/anomaly_scatter.html")

    # Chart 3: FY spending waterfall
    fig3 = build_fy_spending_waterfall(
        fy_cats, fy_vals,
        title="FY2024 Budget Execution — From Enacted to Final ($M)",
    )
    export_to_html(fig3, "/tmp/fy_waterfall.html")
    print("Chart 3: FY waterfall → /tmp/fy_waterfall.html")

    # Chart 4: Installation map
    fig4 = build_installation_map(
        install_df, "lat", "lon", "installation", "readiness",
        threshold=0.75,
        title="Naval Aviation Readiness by Installation — Q4 FY2023",
        value_label="Mission Capable Rate",
    )
    export_to_html(fig4, "/tmp/installation_map.html")
    print("Chart 4: Installation map → /tmp/installation_map.html")

    print("\nAll interactive charts written to /tmp/. Open HTML files in a browser.")
    print("For Databricks: call display(fig) inside a notebook cell.")
    print("For PDF briefings: use export_to_png() (requires kaleido).")
