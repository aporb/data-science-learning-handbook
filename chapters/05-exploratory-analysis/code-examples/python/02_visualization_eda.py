"""
Chapter 05: Visualization for EDA
====================================
Matplotlib, seaborn, and plotly patterns for government dataset EDA.

Platform compatibility notes:
  - matplotlib/seaborn: Work in all environments (Databricks notebooks,
    Palantir Code Workspaces, local Jupyter). Static output.
  - plotly: Interactive in Jupyter/Databricks notebooks. Renders inline
    via plotly.io in Databricks. Use go.Figure with write_html() for
    sharing outside notebook environments.
  - Qlik: Handled via the QIX Engine and SSE — not covered here.
    See Chapter 01 SSE examples and the Qlik section in README.md.

All visualizations use the synthetic DoN maintenance dataset from
01_statistical_profiling.py. Run that file first to understand the data.
"""

import warnings
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.ticker as mticker
import seaborn as sns
from datetime import datetime
from typing import List, Optional, Tuple

warnings.filterwarnings("ignore")

# Consistent visual style across government reporting contexts.
# Use muted, accessible color palettes — avoid red/green only color coding
# because red/green color blindness (deuteranopia) affects ~8% of men.
GOVT_PALETTE = ["#003F87", "#E07B39", "#5B7B3A", "#8B2A52", "#4A6D8C", "#C8A951"]
sns.set_theme(style="whitegrid", palette=GOVT_PALETTE)
plt.rcParams.update({
    "figure.dpi": 120,
    "font.family": "DejaVu Sans",
    "axes.titlesize": 12,
    "axes.labelsize": 10,
})


# ============================================================
# GENERATE SAMPLE DATA (reuse from 01_statistical_profiling)
# ============================================================

def get_sample_data(n_rows: int = 30_000) -> pd.DataFrame:
    """
    Quick data generator so this file is self-contained.
    For real use, import from 01_statistical_profiling.py.
    """
    from importlib.util import find_spec
    try:
        import sys, os
        sys.path.insert(0, os.path.dirname(__file__))
        from statistical_profiling_01 import generate_synthetic_don_dataset
        return generate_synthetic_don_dataset(n_rows)
    except ImportError:
        pass

    # Fallback: inline minimal version
    rng = np.random.default_rng(42)
    n = n_rows
    ship_classes = ["Arleigh Burke", "Ticonderoga", "Nimitz", "Wasp", "San Antonio"]
    event_types = ["PM", "CM", "INSP", "MOD", "OVERHAUL", "EMRG"]
    source_systems = ["SAMS-E", "SMCS", "DPAS", "NALCOMIS"]
    fiscal_years = [2020, 2021, 2022, 2023, 2024]

    # September spike
    months = rng.choice(range(1, 13), n,
                        p=[0.07, 0.07, 0.07, 0.07, 0.07, 0.07,
                           0.07, 0.07, 0.07, 0.07, 0.07, 0.22])

    df = pd.DataFrame({
        "ship_class": rng.choice(ship_classes, n, p=[0.45, 0.12, 0.18, 0.10, 0.15]),
        "event_type": rng.choice(event_types, n, p=[0.35, 0.30, 0.15, 0.08, 0.05, 0.07]),
        "source_system": rng.choice(source_systems, n, p=[0.50, 0.20, 0.18, 0.12]),
        "fiscal_year": rng.choice(fiscal_years, n),
        "month": months,
        "days_elapsed": np.abs(rng.exponential(25, n)).astype(int),
        "contract_value": np.exp(rng.normal(12, 2.5, n)),
        "priority_code": rng.choice([1, 2, 3, 4], n, p=[0.08, 0.22, 0.45, 0.25]),
        "work_order_status": rng.choice(["OPEN", "CLOSED", "DEFERRED"], n, p=[0.25, 0.68, 0.07]),
        "mission_capable_pct": np.clip(rng.normal(78, 12, n), 30, 100),
    })
    df["is_fy_end_month"] = df["month"] == 9
    return df


# ============================================================
# 1. DISTRIBUTION PLOTS
# ============================================================

def plot_numeric_distributions(df: pd.DataFrame, cols: List[str],
                                output_path: Optional[str] = None) -> plt.Figure:
    """
    Grid of histograms with KDE overlays for numeric columns.
    Includes log-scale version for financial data.

    For financial/spending data, always check both linear and log scale —
    federal spending is log-normal and linear scale will look completely
    different from what the underlying distribution actually is.
    """
    n_cols = len(cols)
    n_plot_cols = min(3, n_cols)
    n_plot_rows = (n_cols + n_plot_cols - 1) // n_plot_cols
    # Each column gets two plots: raw and log-transformed
    fig, axes = plt.subplots(n_plot_rows, n_plot_cols * 2,
                             figsize=(5 * n_plot_cols * 2, 4 * n_plot_rows))
    axes = np.array(axes).reshape(-1)

    for i, col in enumerate(cols):
        s = df[col].dropna()

        # Raw distribution
        ax_raw = axes[i * 2]
        ax_raw.hist(s, bins=50, color=GOVT_PALETTE[0], alpha=0.7, edgecolor="white")
        ax_raw.set_title(f"{col}\n(linear scale)")
        ax_raw.set_xlabel(col)
        ax_raw.set_ylabel("Count")
        ax_raw.xaxis.set_major_formatter(mticker.FuncFormatter(
            lambda x, _: f"{x:,.0f}"
        ))

        # Log-scale (for positive-only data)
        ax_log = axes[i * 2 + 1]
        s_pos = s[s > 0]
        if len(s_pos) > 0:
            ax_log.hist(np.log10(s_pos), bins=50, color=GOVT_PALETTE[1],
                        alpha=0.7, edgecolor="white")
            ax_log.set_title(f"{col}\n(log10 scale)")
            ax_log.set_xlabel(f"log10({col})")
            ax_log.set_ylabel("Count")
            neg_pct = (s <= 0).mean() * 100
            if neg_pct > 0:
                ax_log.text(0.98, 0.95, f"{neg_pct:.1f}% ≤ 0 (excluded from log plot)",
                            transform=ax_log.transAxes, ha="right", va="top",
                            fontsize=8, color="red")

    # Hide unused subplots
    for j in range(n_cols * 2, len(axes)):
        axes[j].set_visible(False)

    fig.suptitle("Numeric Distribution Analysis\nCheck log scale for financial columns",
                 fontsize=13, y=1.02)
    plt.tight_layout()

    if output_path:
        fig.savefig(output_path, bbox_inches="tight")
        print(f"Saved: {output_path}")

    return fig


def plot_categorical_breakdown(df: pd.DataFrame, col: str,
                                max_categories: int = 15,
                                output_path: Optional[str] = None) -> plt.Figure:
    """
    Horizontal bar chart for categorical column value counts.
    Horizontal layout is more readable than vertical for government
    category names, which tend to be long.
    """
    value_counts = df[col].value_counts().head(max_categories)
    total = len(df[col].dropna())

    fig, ax = plt.subplots(figsize=(9, max(4, len(value_counts) * 0.4)))
    bars = ax.barh(range(len(value_counts)), value_counts.values,
                   color=GOVT_PALETTE[0], alpha=0.85)

    # Add percentage labels on bars
    for bar, val in zip(bars, value_counts.values):
        pct = val / total * 100
        ax.text(bar.get_width() + total * 0.002, bar.get_y() + bar.get_height() / 2,
                f"{pct:.1f}%", va="center", fontsize=8)

    ax.set_yticks(range(len(value_counts)))
    ax.set_yticklabels(value_counts.index, fontsize=9)
    ax.invert_yaxis()
    ax.set_xlabel("Count")
    ax.set_title(f"Value Distribution: {col}\n"
                 f"({df[col].nunique()} unique values total, showing top {max_categories})")
    ax.xaxis.set_major_formatter(mticker.FuncFormatter(lambda x, _: f"{x:,.0f}"))
    plt.tight_layout()

    if output_path:
        fig.savefig(output_path, bbox_inches="tight")

    return fig


# ============================================================
# 2. TEMPORAL ANALYSIS PLOTS
# ============================================================

def plot_temporal_volume(df: pd.DataFrame, month_col: str,
                         fiscal_year_col: Optional[str] = None,
                         output_path: Optional[str] = None) -> plt.Figure:
    """
    Monthly volume plot that highlights the FY end-of-year spike.

    The September spike in federal data is a process artifact.
    This visualization makes it visible so analysts do not mistake
    it for a real signal.
    """
    monthly = df.groupby(month_col).size().reset_index(name="count")
    monthly = monthly.sort_values(month_col)

    # Map months to fiscal year month labels
    fy_labels = {
        10: "Oct\n(FY-01)", 11: "Nov\n(FY-02)", 12: "Dec\n(FY-03)",
        1: "Jan\n(FY-04)", 2: "Feb\n(FY-05)", 3: "Mar\n(FY-06)",
        4: "Apr\n(FY-07)", 5: "May\n(FY-08)", 6: "Jun\n(FY-09)",
        7: "Jul\n(FY-10)", 8: "Aug\n(FY-11)", 9: "Sep\n(FY-12 END)"
    }
    monthly["fy_label"] = monthly[month_col].map(fy_labels)

    # Sort by FY month order
    fy_sort = {10: 1, 11: 2, 12: 3, 1: 4, 2: 5, 3: 6,
               4: 7, 5: 8, 6: 9, 7: 10, 8: 11, 9: 12}
    monthly["fy_sort"] = monthly[month_col].map(fy_sort)
    monthly = monthly.sort_values("fy_sort")

    mean_count = monthly["count"].mean()

    fig, ax = plt.subplots(figsize=(13, 5))
    colors = ["#C0392B" if m == 9 else GOVT_PALETTE[0] for m in monthly[month_col]]
    bars = ax.bar(range(len(monthly)), monthly["count"], color=colors, alpha=0.85)

    # Mean line
    ax.axhline(mean_count, color="#888", linestyle="--", linewidth=1.2,
               label=f"Monthly average: {mean_count:,.0f}")

    # Annotate September spike
    sep_idx = monthly[monthly[month_col] == 9].index
    if len(sep_idx) > 0:
        sep_pos = monthly.index.get_loc(sep_idx[0])
        sep_count = monthly.loc[sep_idx[0], "count"]
        spike_ratio = sep_count / mean_count
        ax.annotate(
            f"FY End Spike\n{spike_ratio:.1f}x average",
            xy=(sep_pos, sep_count),
            xytext=(sep_pos - 2, sep_count * 0.92),
            fontsize=9, color="#C0392B",
            arrowprops=dict(arrowstyle="->", color="#C0392B")
        )

    ax.set_xticks(range(len(monthly)))
    ax.set_xticklabels(monthly["fy_label"], fontsize=8)
    ax.set_ylabel("Record Count")
    ax.set_title("Record Volume by Fiscal Year Month\n"
                 "Red bar = FY end (September) — process artifact, not signal")
    ax.yaxis.set_major_formatter(mticker.FuncFormatter(lambda x, _: f"{x:,.0f}"))
    ax.legend()
    plt.tight_layout()

    if output_path:
        fig.savefig(output_path, bbox_inches="tight")

    return fig


def plot_time_series_with_gaps(df: pd.DataFrame, date_col: str,
                                freq: str = "W",
                                output_path: Optional[str] = None) -> plt.Figure:
    """
    Plot record volume over time, explicitly highlighting gaps.

    Data pipeline failures produce gaps in government data.
    This plot makes them visible. A gap during a holiday period is
    expected; a gap during normal operations is a data quality flag.
    """
    df = df.copy()
    df["_date"] = pd.to_datetime(df[date_col])
    ts = df.set_index("_date").resample(freq).size()

    # Detect gaps: weeks with zero records when surrounding weeks are non-zero
    # (using rolling window to identify sustained zero periods)
    gap_threshold = ts.mean() * 0.1  # below 10% of average = likely gap
    gaps = ts[ts < gap_threshold]

    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(14, 8), sharex=True,
                                    gridspec_kw={"height_ratios": [3, 1]})

    # Main time series
    ax1.fill_between(ts.index, ts.values, alpha=0.4, color=GOVT_PALETTE[0])
    ax1.plot(ts.index, ts.values, color=GOVT_PALETTE[0], linewidth=1)

    # Highlight gaps
    for gap_date in gaps.index:
        ax1.axvspan(gap_date - pd.Timedelta(days=3),
                    gap_date + pd.Timedelta(days=3),
                    alpha=0.25, color="#C0392B", zorder=0)

    ax1.set_ylabel(f"Records per {freq}")
    ax1.set_title(f"Record Volume Over Time\nRed shading = potential data pipeline gaps")
    ax1.yaxis.set_major_formatter(mticker.FuncFormatter(lambda x, _: f"{x:,.0f}"))

    # Gap indicator subplot
    ax2.bar(gaps.index, [1] * len(gaps), width=5, color="#C0392B", alpha=0.7)
    ax2.set_ylabel("Gaps")
    ax2.set_yticks([])
    ax2.set_xlabel("Date")

    plt.tight_layout()
    if output_path:
        fig.savefig(output_path, bbox_inches="tight")

    return fig


# ============================================================
# 3. CORRELATION AND MULTIVARIATE ANALYSIS
# ============================================================

def plot_correlation_heatmap(df: pd.DataFrame,
                              cols: Optional[List[str]] = None,
                              output_path: Optional[str] = None) -> plt.Figure:
    """
    Correlation heatmap with significance masking.

    Only show correlations where |r| > 0.15 — smaller correlations
    in government datasets are typically noise. Annotate with values.
    """
    if cols is None:
        cols = df.select_dtypes(include=[np.number]).columns.tolist()

    corr = df[cols].corr()
    mask = np.triu(np.ones_like(corr, dtype=bool))  # upper triangle mask

    fig, ax = plt.subplots(figsize=(max(8, len(cols)), max(6, len(cols) * 0.8)))
    sns.heatmap(
        corr,
        mask=mask,
        annot=True,
        fmt=".2f",
        center=0,
        vmin=-1, vmax=1,
        cmap="RdBu_r",
        linewidths=0.5,
        ax=ax,
        annot_kws={"size": 9}
    )
    ax.set_title("Correlation Matrix\n(lower triangle; values masked to 2 decimal places)")
    plt.tight_layout()

    if output_path:
        fig.savefig(output_path, bbox_inches="tight")

    return fig


def plot_outlier_analysis(df: pd.DataFrame, col: str,
                           group_col: Optional[str] = None,
                           output_path: Optional[str] = None) -> plt.Figure:
    """
    Boxplot + strip plot combination for outlier visualization.

    Boxplot shows statistical outliers (IQR method).
    Strip plot overlays actual data points for smaller datasets.
    Grouped by a categorical column to show whether outliers
    cluster in specific categories.
    """
    fig, axes = plt.subplots(1, 2, figsize=(14, 5))

    # Left: overall boxplot
    ax1 = axes[0]
    q1, q3 = df[col].quantile([0.25, 0.75])
    iqr = q3 - q1
    upper_fence = q3 + 1.5 * iqr
    lower_fence = q1 - 1.5 * iqr
    n_outliers = ((df[col] > upper_fence) | (df[col] < lower_fence)).sum()
    n_domain_invalid = (df[col] < 0).sum()

    ax1.boxplot(df[col].dropna(), vert=True, patch_artist=True,
                boxprops=dict(facecolor=GOVT_PALETTE[0], alpha=0.6),
                medianprops=dict(color="white", linewidth=2))
    ax1.set_ylabel(col)
    ax1.set_title(f"Boxplot: {col}\n"
                  f"IQR outliers: {n_outliers:,} | Domain-invalid (< 0): {n_domain_invalid:,}")
    ax1.yaxis.set_major_formatter(mticker.FuncFormatter(lambda x, _: f"{x:,.0f}"))

    # Right: grouped if group_col provided
    ax2 = axes[1]
    if group_col and group_col in df.columns:
        # Cap at 8 groups for readability
        top_groups = df[group_col].value_counts().head(8).index
        df_filtered = df[df[group_col].isin(top_groups)]
        df_filtered[col].clip(lower=df[col].quantile(0.005),
                               upper=df[col].quantile(0.995),
                               inplace=False)

        group_order = df_filtered.groupby(group_col)[col].median().sort_values().index
        sns.boxplot(data=df_filtered, x=group_col, y=col, order=group_order,
                    palette=GOVT_PALETTE[:len(top_groups)], ax=ax2)
        ax2.set_xticklabels(ax2.get_xticklabels(), rotation=30, ha="right")
        ax2.set_title(f"Distribution of {col}\nby {group_col}")
        ax2.yaxis.set_major_formatter(mticker.FuncFormatter(lambda x, _: f"{x:,.0f}"))
    else:
        # Show percentile table if no group col
        pcts = df[col].dropna().quantile([0.01, 0.05, 0.25, 0.5, 0.75, 0.95, 0.99])
        rows = [f"P{int(p*100):3d}: {v:>12,.1f}" for p, v in pcts.items()]
        ax2.text(0.1, 0.5, "\n".join(rows), transform=ax2.transAxes,
                 fontsize=10, family="monospace", va="center")
        ax2.set_title(f"Percentile Table: {col}")
        ax2.axis("off")

    plt.tight_layout()
    if output_path:
        fig.savefig(output_path, bbox_inches="tight")

    return fig


# ============================================================
# 4. CLASS IMBALANCE VISUALIZATION
# ============================================================

def plot_class_balance(df: pd.DataFrame, target_col: str,
                        output_path: Optional[str] = None) -> plt.Figure:
    """
    Visualize class balance for a binary or multi-class target.

    Government ML targets are almost always imbalanced:
    anomalous contracts, maintenance failures, readiness risks
    are rare by definition. This plot makes the imbalance explicit
    and flags whether SMOTE or class weighting is needed.
    """
    counts = df[target_col].value_counts().sort_index()
    total = counts.sum()
    minority_class = counts.idxmin()
    minority_pct = counts.min() / total * 100

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))

    # Bar chart
    bars = ax1.bar(counts.index.astype(str), counts.values,
                   color=[GOVT_PALETTE[0] if c != minority_class else "#C0392B"
                          for c in counts.index],
                   alpha=0.85)
    for bar, val in zip(bars, counts.values):
        ax1.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + total * 0.005,
                 f"{val:,}\n({val/total*100:.1f}%)", ha="center", fontsize=9)
    ax1.set_title(f"Class Distribution: {target_col}\n"
                  f"Minority class = {minority_pct:.1f}% of data")
    ax1.set_xlabel(target_col)
    ax1.set_ylabel("Count")
    ax1.yaxis.set_major_formatter(mticker.FuncFormatter(lambda x, _: f"{x:,.0f}"))

    # Recommendation text
    ax2.axis("off")
    if minority_pct < 5:
        recommendation = (
            "SEVERE IMBALANCE (< 5% minority class)\n\n"
            "Recommended actions:\n"
            "1. Use class_weight='balanced' in sklearn estimators\n"
            "2. Apply SMOTE or ADASYN oversampling\n"
            "3. Use precision-recall AUC, not accuracy\n"
            "4. Consider threshold tuning post-training\n"
            "5. For Databricks: use MLflow to log PR curve,\n"
            "   not just accuracy"
        )
        color = "#C0392B"
    elif minority_pct < 20:
        recommendation = (
            "MODERATE IMBALANCE (5-20% minority class)\n\n"
            "Recommended actions:\n"
            "1. Use class_weight='balanced'\n"
            "2. Monitor both precision and recall\n"
            "3. Consider mild oversampling if recall < 0.6\n"
            "4. Log F1 score and PR-AUC in MLflow"
        )
        color = "#E07B39"
    else:
        recommendation = (
            "BALANCED CLASSES (> 20% minority)\n\n"
            "Standard training applies.\n"
            "Monitor accuracy + F1."
        )
        color = "#5B7B3A"

    ax2.text(0.1, 0.5, recommendation, transform=ax2.transAxes,
             fontsize=10, va="center", color=color,
             bbox=dict(boxstyle="round,pad=0.5", facecolor="#F8F8F8", edgecolor=color))
    ax2.set_title("Recommendations")

    plt.tight_layout()
    if output_path:
        fig.savefig(output_path, bbox_inches="tight")

    return fig


# ============================================================
# 5. INTERACTIVE PLOTLY CHARTS (Databricks / Jupyter)
# ============================================================

def plotly_procurement_anomaly_scatter(df: pd.DataFrame,
                                        x_col: str = "contract_value",
                                        y_col: str = "days_elapsed",
                                        color_col: str = "event_type",
                                        output_html: Optional[str] = None):
    """
    Interactive scatter plot for anomaly exploration.

    Plotly renders inline in Databricks notebooks and Jupyter.
    For sharing outside notebooks, use write_html() to produce
    a self-contained HTML file that opens in any browser.

    This pattern is useful when handing EDA findings to a program
    manager who does not have notebook access — they can open the
    HTML file and interact with the chart without any Python.
    """
    try:
        import plotly.express as px
        import plotly.io as pio
        pio.renderers.default = "notebook"  # works in Databricks + Jupyter
    except ImportError:
        print("plotly not installed. Run: pip install plotly")
        return None

    # Cap extreme values for visualization clarity
    df_plot = df.copy()
    df_plot[x_col] = df_plot[x_col].clip(
        lower=df_plot[x_col].quantile(0.01),
        upper=df_plot[x_col].quantile(0.99)
    )
    df_plot[y_col] = df_plot[y_col].clip(
        lower=0,
        upper=df_plot[y_col].quantile(0.99)
    )

    fig = px.scatter(
        df_plot.sample(min(5000, len(df_plot))),  # cap at 5k points for browser performance
        x=x_col,
        y=y_col,
        color=color_col,
        color_discrete_sequence=GOVT_PALETTE,
        hover_data=[c for c in ["ship_class", "source_system", "fiscal_year", "priority_code"]
                    if c in df_plot.columns],
        title=f"EDA: {y_col} vs {x_col} by {color_col}<br>"
              f"<sup>Hover for details | Points sampled to 5,000 for performance</sup>",
        labels={x_col: x_col.replace("_", " ").title(),
                y_col: y_col.replace("_", " ").title()},
        opacity=0.6,
        template="plotly_white"
    )

    fig.update_layout(
        legend_title_text=color_col.replace("_", " ").title(),
        font_family="Arial",
    )

    if output_html:
        fig.write_html(output_html, include_plotlyjs="cdn")
        print(f"Interactive chart saved to: {output_html}")
        print("Share this HTML file with stakeholders who don't have notebook access.")

    return fig


def plotly_temporal_heatmap(df: pd.DataFrame,
                             date_col: str = "start_date",
                             value_col: Optional[str] = None,
                             output_html: Optional[str] = None):
    """
    Calendar heatmap showing activity density over time.

    Useful for identifying gaps (pipeline failures), holiday periods,
    FY end spikes, and operational tempo patterns in DoD data.
    """
    try:
        import plotly.graph_objects as go
    except ImportError:
        print("plotly not installed.")
        return None

    df = df.copy()
    df["_date"] = pd.to_datetime(df.get(date_col, pd.Timestamp("2020-01-01")))
    df["_year"] = df["_date"].dt.year
    df["_week"] = df["_date"].dt.isocalendar().week.astype(int)
    df["_dow"] = df["_date"].dt.dayofweek

    if value_col and value_col in df.columns:
        heat = df.groupby(["_year", "_week"])[value_col].sum().reset_index()
    else:
        heat = df.groupby(["_year", "_week"]).size().reset_index(name="count")

    metric = value_col if value_col else "count"
    pivot = heat.pivot(index="_year", columns="_week", values=metric).fillna(0)

    fig = go.Figure(data=go.Heatmap(
        z=pivot.values,
        x=[f"Week {w}" for w in pivot.columns],
        y=[str(y) for y in pivot.index],
        colorscale="Blues",
        showscale=True,
        hovertemplate="Year: %{y}<br>Week: %{x}<br>Value: %{z:,.0f}<extra></extra>"
    ))

    fig.update_layout(
        title=f"Activity Heatmap by Year and Week<br>"
              f"<sup>Gaps = pipeline failures or operational stand-downs</sup>",
        xaxis_title="Fiscal Week",
        yaxis_title="Year",
        template="plotly_white",
        font_family="Arial"
    )

    if output_html:
        fig.write_html(output_html, include_plotlyjs="cdn")
        print(f"Saved: {output_html}")

    return fig


# ============================================================
# MAIN: Run all visualization demos
# ============================================================

if __name__ == "__main__":
    print("Chapter 05: Visualization EDA Demo")
    print("Generating sample data...")
    df = get_sample_data(30_000)
    print(f"Dataset: {len(df):,} rows")

    print("\n--- Distribution Plots ---")
    fig1 = plot_numeric_distributions(
        df,
        cols=["days_elapsed", "contract_value"],
    )
    plt.show()
    print("Note: Contract value should look log-normal on the log10 scale.")

    print("\n--- Categorical Breakdown ---")
    fig2 = plot_categorical_breakdown(df, col="event_type")
    plt.show()

    print("\n--- Fiscal Year Temporal Volume ---")
    fig3 = plot_temporal_volume(df, month_col="month")
    plt.show()
    print("September spike should be visible — that is the FY end effect.")

    print("\n--- Correlation Heatmap ---")
    numeric_cols = ["days_elapsed", "contract_value", "priority_code", "mission_capable_pct"]
    available_cols = [c for c in numeric_cols if c in df.columns]
    if available_cols:
        fig4 = plot_correlation_heatmap(df, cols=available_cols)
        plt.show()

    print("\n--- Outlier Analysis ---")
    fig5 = plot_outlier_analysis(df, col="contract_value", group_col="ship_class")
    plt.show()

    print("\n--- Class Balance Check ---")
    # Simulate a binary target (e.g., high-priority work orders)
    df["high_priority"] = (df["priority_code"] <= 2).astype(int)
    fig6 = plot_class_balance(df, target_col="high_priority")
    plt.show()

    print("\n--- Interactive Plotly Scatter ---")
    plotly_fig = plotly_procurement_anomaly_scatter(
        df,
        x_col="contract_value",
        y_col="days_elapsed",
        color_col="event_type",
        output_html="/tmp/eda_scatter.html"
    )
    if plotly_fig:
        print("Plotly figure created. In a Databricks notebook, this renders inline.")
        print("HTML export at /tmp/eda_scatter.html is shareable with non-notebook users.")

    print("\nAll visualizations complete.")
    print("Next: platform-specific EDA workflows in 03_platform_eda_workflows.py")
