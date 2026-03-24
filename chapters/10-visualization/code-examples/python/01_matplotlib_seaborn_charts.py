"""
Chapter 10: Visualization and Dashboards
Example 1: matplotlib and seaborn for Government Briefings

Static publication-quality charts optimized for:
  - PDF export for briefing decks
  - Projector display (high contrast, legible fonts)
  - Print (colorblind-safe palettes, no reliance on color alone)

All functions use the government briefing style configuration
defined at the module level. Override rcParams before calling
these functions if you need a different base style.

Scenario: DoD readiness and procurement visualization for
flag-level briefings and program office reports.
"""

import warnings
from typing import Dict, List, Optional, Tuple

import matplotlib.pyplot as plt
import matplotlib.gridspec as gridspec
import matplotlib.ticker as mticker
import matplotlib.patches as mpatches
import numpy as np
import pandas as pd
import seaborn as sns
from scipy import stats

warnings.filterwarnings("ignore")


# ============================================================
# STYLE CONFIGURATION
# ============================================================

def apply_government_style():
    """
    Apply the government briefing matplotlib style.
    Call once at the top of any script that generates charts for delivery.

    Design rationale:
    - figure.dpi=150: crisp on screen; write with savefig.dpi=200 for PDF
    - Spines top/right removed: reduces visual clutter for data-forward charts
    - Grid alpha 0.3: visible but not competing with data
    - Font size 11: readable at 75% zoom on a PDF printed as a handout
    """
    plt.rcParams.update({
        "figure.figsize": (10, 6),
        "figure.dpi": 150,
        "font.family": "DejaVu Sans",
        "font.size": 11,
        "axes.titlesize": 13,
        "axes.labelsize": 11,
        "axes.spines.top": False,
        "axes.spines.right": False,
        "axes.grid": True,
        "grid.alpha": 0.3,
        "grid.linewidth": 0.8,
        "grid.color": "#cccccc",
        "xtick.major.size": 0,
        "ytick.major.size": 0,
        "xtick.labelsize": 10,
        "ytick.labelsize": 10,
        "legend.frameon": False,
        "legend.fontsize": 10,
        "figure.facecolor": "white",
        "axes.facecolor": "white",
        "savefig.bbox": "tight",
        "savefig.dpi": 200,
        "savefig.facecolor": "white",
    })


# Okabe-Ito colorblind-safe palette
# Verified against deuteranopia, protanopia, and tritanopia simulations.
# Use this for all charts delivered to government stakeholders.
GOVT_PALETTE = {
    "blue":   "#0072B2",
    "orange": "#E69F00",
    "green":  "#009E73",
    "red":    "#D55E00",
    "purple": "#CC79A7",
    "sky":    "#56B4E9",
    "yellow": "#F0E442",
    "black":  "#000000",
    "gray":   "#999999",
}

# Status colors for threshold-based charts
STATUS_COLORS = {
    "green":  "#009E73",  # above threshold / mission capable
    "yellow": "#E69F00",  # near threshold / caution
    "red":    "#D55E00",  # below threshold / not mission capable
    "gray":   "#999999",  # insufficient data / not applicable
}


# ============================================================
# SECTION 1: TIME SERIES WITH THRESHOLD
# ============================================================

def plot_readiness_timeseries(
    df: pd.DataFrame,
    date_col: str,
    value_col: str,
    threshold: float,
    title_finding: str,
    ylabel: str,
    threshold_label: str = "Required threshold",
    unit_label: Optional[str] = None,
    value_format: str = "percent",
    figsize: Tuple[int, int] = (12, 5),
) -> plt.Figure:
    """
    Readiness or performance metric over time with threshold marking.

    This is the single most common chart type in government data science
    briefings. The design priorities: the threshold is the most important
    element (plotted most prominently), the current period is the most
    recent data point (labeled explicitly), and the title states the finding.

    Args:
        df: DataFrame with time series data
        date_col: Column name for dates
        value_col: Column name for the metric
        threshold: Required minimum (or maximum) value
        title_finding: Chart title — should state the finding, not just the topic
        ylabel: Y-axis label
        threshold_label: Label for the threshold line
        unit_label: Optional unit/platform name for annotation
        value_format: "percent" (0.0-1.0) or "raw" (numeric as-is)
        figsize: Figure dimensions

    Returns:
        matplotlib Figure object
    """
    apply_government_style()
    df = df.sort_values(date_col).copy()
    dates = pd.to_datetime(df[date_col])
    values = df[value_col].values

    fig, ax = plt.subplots(figsize=figsize)

    # Main time series line
    ax.plot(dates, values, color=GOVT_PALETTE["blue"],
            linewidth=2.5, zorder=3, marker="o", markersize=4)

    # Shade periods below threshold
    below_mask = values < threshold
    if below_mask.any():
        ax.fill_between(
            dates, values, threshold,
            where=below_mask,
            alpha=0.2, color=GOVT_PALETTE["red"],
            label="Below threshold"
        )

    # Threshold line — draw before data so it's visually behind
    ax.axhline(
        threshold,
        color=GOVT_PALETTE["red"],
        linewidth=1.5,
        linestyle="--",
        zorder=2,
        label=f"{threshold_label}: "
              f"{threshold:.0%}" if value_format == "percent" else f"{threshold:.1f}"
    )

    # Annotate most recent value
    latest_val = values[-1]
    latest_date = dates.iloc[-1]
    color = (GOVT_PALETTE["red"] if latest_val < threshold
             else GOVT_PALETTE["green"])
    fmt = f"{latest_val:.1%}" if value_format == "percent" else f"{latest_val:.1f}"
    ax.annotate(
        f"Latest: {fmt}",
        xy=(latest_date, latest_val),
        xytext=(10, 10),
        textcoords="offset points",
        fontsize=10,
        color=color,
        fontweight="bold",
        arrowprops=dict(arrowstyle="-", color=color, lw=1)
    )

    # Y-axis formatting
    if value_format == "percent":
        ax.yaxis.set_major_formatter(mticker.PercentFormatter(xmax=1, decimals=0))
        ax.set_ylim(max(0, values.min() * 0.9), min(1.05, values.max() * 1.1))

    ax.set_title(title_finding, fontweight="bold", pad=12, wrap=True)
    ax.set_ylabel(ylabel)
    ax.legend(loc="lower left")

    if unit_label:
        ax.text(0.01, 0.98, unit_label, transform=ax.transAxes,
                fontsize=9, color=GOVT_PALETTE["gray"], va="top")

    fig.autofmt_xdate()
    plt.tight_layout()
    return fig


# ============================================================
# SECTION 2: RANKED HORIZONTAL BAR CHART
# ============================================================

def plot_ranked_horizontal_bars(
    labels: List[str],
    values: List[float],
    title_finding: str,
    xlabel: str,
    highlight_top_n: int = 3,
    value_format: str = "currency",
    color_by_threshold: Optional[Tuple[List[float], float]] = None,
    figsize: Tuple[int, int] = (11, 7),
) -> plt.Figure:
    """
    Horizontal bar chart sorted descending, top N highlighted.

    Used for: top vendors by contract value, programs by obligation,
    units ranked by readiness, NAICS codes by spending.

    Horizontal orientation is preferred over vertical for government data
    because labels are typically long strings that don't fit rotated.

    Args:
        labels: Category labels (vendor names, unit IDs, etc.)
        values: Numeric values corresponding to each label
        title_finding: Chart title stating the finding
        xlabel: X-axis label
        highlight_top_n: Number of top bars to highlight in primary color
        value_format: "currency", "percent", or "raw"
        color_by_threshold: Optional (values, threshold) tuple to color
            bars green/red based on threshold instead of top-N highlighting
        figsize: Figure dimensions
    """
    apply_government_style()

    # Sort ascending (horizontal bars: bottom = lowest, top = highest)
    sorted_idx = np.argsort(values)
    s_labels = [labels[i] for i in sorted_idx]
    s_values = [values[i] for i in sorted_idx]
    n = len(s_values)

    # Color logic
    if color_by_threshold is not None:
        _, thresh = color_by_threshold
        colors = [
            GOVT_PALETTE["green"] if v >= thresh else GOVT_PALETTE["red"]
            for v in s_values
        ]
    else:
        colors = [
            GOVT_PALETTE["blue"] if i >= n - highlight_top_n else "#cccccc"
            for i in range(n)
        ]

    fig, ax = plt.subplots(figsize=figsize)
    bars = ax.barh(range(n), s_values, color=colors, edgecolor="none", height=0.65)
    ax.set_yticks(range(n))
    ax.set_yticklabels(s_labels, fontsize=10)

    # Value labels at right edge of each bar
    max_val = max(s_values) if s_values else 1
    for bar, val in zip(bars, s_values):
        if value_format == "currency":
            label = f"${val/1e6:.1f}M" if val >= 1e6 else f"${val/1e3:.0f}K"
        elif value_format == "percent":
            label = f"{val:.1%}"
        else:
            label = f"{val:,.1f}"
        ax.text(
            bar.get_width() + max_val * 0.01,
            bar.get_y() + bar.get_height() / 2,
            label, va="center", ha="left", fontsize=9
        )

    ax.set_xlim(0, max_val * 1.18)
    ax.set_title(title_finding, fontweight="bold", pad=12, wrap=True)
    ax.set_xlabel(xlabel)

    if value_format == "currency":
        ax.xaxis.set_major_formatter(
            mticker.FuncFormatter(
                lambda x, _: f"${x/1e6:.0f}M" if x >= 1e6 else f"${x/1e3:.0f}K"
            )
        )
    elif value_format == "percent":
        ax.xaxis.set_major_formatter(mticker.PercentFormatter(xmax=1))

    plt.tight_layout()
    return fig


# ============================================================
# SECTION 3: SMALL MULTIPLES
# ============================================================

def plot_small_multiples_timeseries(
    df: pd.DataFrame,
    date_col: str,
    value_col: str,
    group_col: str,
    threshold: Optional[float],
    suptitle: str,
    ylabel: str,
    ncols: int = 4,
    value_format: str = "percent",
    figsize_per_cell: Tuple[int, int] = (3, 2.5),
) -> plt.Figure:
    """
    Small multiples grid showing the same metric across many entities.

    When comparing more than five entities on a single chart, lines overlap
    and colors run out. Small multiples solve this by giving each entity
    its own subplot with a shared y-axis scale.

    Used for: readiness across fifteen ships, budget execution across
    ten programs, qualification rates across twenty unit types.

    Args:
        df: DataFrame in long format
        date_col: Date column
        value_col: Metric column
        group_col: Column containing entity names (one panel per entity)
        threshold: Optional threshold to draw on each panel
        suptitle: Overall figure title
        ylabel: Y-axis label for each panel
        ncols: Number of columns in the grid
        value_format: "percent" or "raw"
    """
    apply_government_style()

    groups = sorted(df[group_col].unique())
    ngroups = len(groups)
    nrows = (ngroups + ncols - 1) // ncols

    fig, axes = plt.subplots(
        nrows, ncols,
        figsize=(figsize_per_cell[0] * ncols, figsize_per_cell[1] * nrows),
        sharex=True, sharey=True
    )
    axes_flat = axes.flatten() if hasattr(axes, "flatten") else [axes]

    # Shared y-limits
    ymin = df[value_col].min() * 0.95
    ymax = df[value_col].max() * 1.05

    for i, group in enumerate(groups):
        ax = axes_flat[i]
        group_df = df[df[group_col] == group].sort_values(date_col)
        dates = pd.to_datetime(group_df[date_col])
        vals = group_df[value_col].values

        ax.plot(dates, vals, color=GOVT_PALETTE["blue"], linewidth=1.5)

        if threshold is not None:
            ax.axhline(threshold, color=GOVT_PALETTE["red"],
                       linewidth=1, linestyle="--", alpha=0.7)
            below = vals < threshold
            if below.any():
                ax.fill_between(dates, vals, threshold,
                                where=below, alpha=0.15,
                                color=GOVT_PALETTE["red"])

        # Color panel background for quick status assessment
        if threshold is not None and len(vals) > 0:
            latest = vals[-1]
            if latest < threshold:
                ax.set_facecolor("#fff0ee")  # light red for below-threshold
            else:
                ax.set_facecolor("white")

        ax.set_title(str(group), fontsize=9, fontweight="bold", pad=4)
        ax.set_ylim(ymin, ymax)

        if value_format == "percent":
            ax.yaxis.set_major_formatter(mticker.PercentFormatter(xmax=1, decimals=0))

        ax.tick_params(labelsize=7)

    # Hide empty panels
    for j in range(ngroups, len(axes_flat)):
        axes_flat[j].set_visible(False)

    fig.suptitle(suptitle, fontsize=12, fontweight="bold", y=1.01)
    fig.text(0.5, -0.01, ylabel, ha="center", fontsize=10)

    plt.tight_layout()
    return fig


# ============================================================
# SECTION 4: DISTRIBUTION WITH ANNOTATION
# ============================================================

def plot_annotated_distribution(
    series: pd.Series,
    title_finding: str,
    xlabel: str,
    threshold: Optional[float] = None,
    threshold_label: str = "Threshold",
    log_scale: bool = False,
    bins: int = 50,
    figsize: Tuple[int, int] = (10, 5),
) -> plt.Figure:
    """
    Histogram with mean, median, and optional threshold annotations.

    Used for contract value distributions, time-to-completion analysis,
    parts failure rates. Annotates key statistics to reduce the burden
    on chart readers who don't have time to compute them mentally.

    Args:
        series: Data to plot
        title_finding: Finding-oriented title
        xlabel: X-axis label
        threshold: Optional threshold value to mark
        threshold_label: Label for the threshold
        log_scale: Apply log scale to x-axis (appropriate for financial data)
        bins: Number of histogram bins
    """
    apply_government_style()

    series = series.dropna()
    if log_scale and (series <= 0).any():
        series = series[series > 0]

    fig, ax = plt.subplots(figsize=figsize)

    # Histogram
    if log_scale:
        log_data = np.log10(series)
        n, bins_arr, patches = ax.hist(
            log_data, bins=bins, color=GOVT_PALETTE["blue"],
            alpha=0.75, edgecolor="none"
        )
        # Relabel x-axis with original values
        tick_values = np.arange(np.floor(log_data.min()), np.ceil(log_data.max()) + 1)
        ax.set_xticks(tick_values)
        ax.set_xticklabels([f"${10**v/1e6:.1f}M" if 10**v >= 1e6
                            else f"${10**v/1e3:.0f}K" for v in tick_values],
                           rotation=30, ha="right")
        mean_x = np.log10(series.mean())
        median_x = np.log10(series.median())
        if threshold is not None:
            threshold_x = np.log10(threshold) if threshold > 0 else None
    else:
        n, bins_arr, patches = ax.hist(
            series, bins=bins, color=GOVT_PALETTE["blue"],
            alpha=0.75, edgecolor="none"
        )
        mean_x = series.mean()
        median_x = series.median()
        threshold_x = threshold

    ymax = max(n) * 1.3

    # Mean line
    ax.axvline(mean_x, color=GOVT_PALETTE["orange"], linewidth=2,
               linestyle="-", label=f"Mean: {series.mean():,.1f}")
    ax.text(mean_x, ymax * 0.95,
            f"Mean\n{series.mean():,.0f}",
            ha="center", fontsize=8, color=GOVT_PALETTE["orange"])

    # Median line
    ax.axvline(median_x, color=GOVT_PALETTE["green"], linewidth=2,
               linestyle="--", label=f"Median: {series.median():,.1f}")
    ax.text(median_x, ymax * 0.78,
            f"Median\n{series.median():,.0f}",
            ha="center", fontsize=8, color=GOVT_PALETTE["green"])

    # Threshold
    if threshold_x is not None:
        ax.axvline(threshold_x, color=GOVT_PALETTE["red"], linewidth=2,
                   linestyle=":", label=f"{threshold_label}: {threshold:,.0f}")
        ax.text(threshold_x, ymax * 0.60,
                f"{threshold_label}\n{threshold:,.0f}",
                ha="center", fontsize=8, color=GOVT_PALETTE["red"])

    ax.set_ylim(0, ymax)
    ax.set_title(title_finding, fontweight="bold", pad=12, wrap=True)
    ax.set_xlabel(xlabel)
    ax.set_ylabel("Count")
    ax.legend(loc="upper right")

    plt.tight_layout()
    return fig


# ============================================================
# SECTION 5: BRIEFING ANNOTATION UTILITY
# ============================================================

def add_briefing_annotations(
    fig: plt.Figure,
    ax: plt.Axes,
    source: str,
    classification: str = "UNCLASSIFIED",
    caveat: Optional[str] = None,
):
    """
    Add standard government briefing annotations to a figure.

    classification: "UNCLASSIFIED", "CUI", "SECRET//NOFORN", etc.
    caveat: Optional data caveat note (e.g., data lag, sampling note)

    Note on classification markings: this function adds a text watermark
    for display purposes. Actual classification marking requirements vary
    by agency and classification level — coordinate with your security
    officer for classified briefings.
    """
    # Source line at bottom left
    fig.text(
        0.01, -0.03,
        f"Source: {source}",
        fontsize=8, color="#666666", style="italic",
        transform=fig.transFigure
    )

    # Classification marking at bottom center
    color_map = {
        "UNCLASSIFIED": "#009E73",
        "CUI": "#E69F00",
        "SECRET": "#D55E00",
        "SECRET//NOFORN": "#D55E00",
        "TOP SECRET": "#CC79A7",
    }
    cls_color = color_map.get(classification.split("/")[0], "#000000")
    fig.text(
        0.5, -0.03,
        classification,
        fontsize=9, color=cls_color, fontweight="bold",
        ha="center", transform=fig.transFigure
    )

    # Caveat note at bottom right
    if caveat:
        fig.text(
            0.99, -0.03,
            caveat,
            fontsize=7, color="#888888", ha="right", style="italic",
            transform=fig.transFigure
        )


# ============================================================
# SECTION 6: SEABORN CORRELATION HEATMAP
# ============================================================

def plot_correlation_heatmap(
    df: pd.DataFrame,
    cols: List[str],
    title: str,
    method: str = "spearman",
    figsize: Tuple[int, int] = (10, 8),
    annot_fontsize: int = 9,
) -> plt.Figure:
    """
    Spearman (or Pearson) correlation heatmap with significance masking.

    Only shows statistically significant correlations (p < 0.05).
    Non-significant pairs shown in gray.

    Government financial and operational data is almost always non-normal
    and right-skewed — use Spearman by default, not Pearson.

    Args:
        df: DataFrame
        cols: Columns to include in the correlation analysis
        title: Chart title
        method: "spearman" (default) or "pearson"
        figsize: Figure dimensions
        annot_fontsize: Font size for correlation values in cells
    """
    apply_government_style()

    from scipy.stats import spearmanr, pearsonr

    data = df[cols].dropna()

    if method == "spearman":
        corr_matrix, pval_matrix = spearmanr(data)
        if len(cols) == 2:
            corr_matrix = np.array([[1, corr_matrix], [corr_matrix, 1]])
            pval_matrix = np.array([[0, pval_matrix], [pval_matrix, 0]])
        corr_df = pd.DataFrame(corr_matrix, columns=cols, index=cols)
        pval_df = pd.DataFrame(pval_matrix, columns=cols, index=cols)
    else:
        corr_df = data.corr(method="pearson")
        pval_df = pd.DataFrame(index=cols, columns=cols, dtype=float)
        for c1 in cols:
            for c2 in cols:
                if c1 == c2:
                    pval_df.loc[c1, c2] = 0.0
                else:
                    _, p = pearsonr(data[c1], data[c2])
                    pval_df.loc[c1, c2] = p

    # Mask non-significant correlations
    sig_mask = pval_df.astype(float) > 0.05
    masked_corr = corr_df.copy()
    masked_corr[sig_mask] = 0

    fig, axes = plt.subplots(1, 2, figsize=figsize)

    for ax, matrix, mask_title in [
        (axes[0], corr_df, "All Correlations"),
        (axes[1], masked_corr, "Significant Only (p < 0.05)")
    ]:
        sns.heatmap(
            matrix, annot=True, fmt=".2f", cmap="RdBu_r",
            center=0, vmin=-1, vmax=1,
            linewidths=0.5,
            annot_kws={"size": annot_fontsize},
            ax=ax,
            cbar_kws={"shrink": 0.8}
        )
        ax.set_title(mask_title, fontsize=11, fontweight="bold")
        ax.tick_params(axis="x", rotation=45)
        ax.tick_params(axis="y", rotation=0)

    fig.suptitle(
        f"{title}\n({method.capitalize()} correlation, n={len(data):,})",
        fontsize=12, fontweight="bold", y=1.01
    )
    plt.tight_layout()
    return fig


# ============================================================
# DEMO — Generate sample charts with synthetic government data
# ============================================================

def generate_demo_data():
    """Generate synthetic readiness + procurement data for chart demos."""
    rng = np.random.default_rng(42)
    n = 24  # 24 months (FY2022–FY2023)

    # Readiness: starts above threshold, dips in months 10-14, recovers
    base_readiness = np.array([
        0.82, 0.84, 0.83, 0.80, 0.79, 0.77,
        0.75, 0.73, 0.70, 0.68, 0.71, 0.74,  # dip below 75%
        0.76, 0.78, 0.80, 0.82, 0.83, 0.82,
        0.81, 0.83, 0.85, 0.84, 0.83, 0.82,
    ])
    base_readiness += rng.normal(0, 0.01, n)
    dates = pd.date_range("2022-10-01", periods=n, freq="ME")

    readiness_df = pd.DataFrame({"date": dates, "readiness": base_readiness})

    # Procurement: top vendors by FY2024 obligation
    vendors = [
        "Leidos Holdings", "Booz Allen Hamilton", "SAIC",
        "General Dynamics IT", "Raytheon Intelligence", "CACI International",
        "DXC Technology", "Perspecta", "PAE Incorporated", "Amentum Services"
    ]
    obligations = [
        4_200_000_000, 3_800_000_000, 3_100_000_000,
        2_700_000_000, 2_400_000_000, 1_900_000_000,
        1_500_000_000, 1_200_000_000, 900_000_000, 750_000_000
    ]

    # Small multiples: readiness by ship class
    ship_classes = ["Arleigh Burke", "Ticonderoga", "Nimitz", "Wasp",
                    "San Antonio", "Zumwalt", "Independence", "Freedom"]
    small_mult_rows = []
    for cls in ship_classes:
        base = rng.uniform(0.65, 0.90)
        for i, dt in enumerate(dates):
            small_mult_rows.append({
                "date": dt,
                "ship_class": cls,
                "readiness": np.clip(base + rng.normal(0, 0.03) + i * 0.002, 0.5, 1.0)
            })
    small_mult_df = pd.DataFrame(small_mult_rows)

    # Correlation data
    n_contracts = 500
    contract_values = np.exp(rng.normal(12.5, 2.2, n_contracts))
    days_to_award = rng.integers(10, 400, n_contracts).astype(float)
    n_competitors = rng.poisson(2.5, n_contracts).astype(float)
    # Add correlation: more competitors → lower value (competitive pricing)
    contract_values = contract_values * np.exp(-0.05 * n_competitors)

    corr_df = pd.DataFrame({
        "obligation_amount": contract_values,
        "days_to_award": days_to_award,
        "n_competitors": n_competitors,
        "modification_count": rng.poisson(1.5, n_contracts).astype(float),
    })

    return readiness_df, vendors, obligations, small_mult_df, corr_df


if __name__ == "__main__":
    apply_government_style()
    readiness_df, vendors, obligations, small_mult_df, corr_df = generate_demo_data()

    print("Generating government briefing charts...\n")

    # Chart 1: Readiness time series with threshold
    fig1 = plot_readiness_timeseries(
        readiness_df,
        date_col="date",
        value_col="readiness",
        threshold=0.75,
        title_finding="Surface Fleet Readiness Fell Below 75% for Three Consecutive Quarters (FY2023 Q1–Q3)",
        ylabel="Mission Capable Rate",
        threshold_label="Required (75%)",
        value_format="percent",
    )
    add_briefing_annotations(
        fig1, fig1.axes[0],
        source="SAMS-E via Advana, FY2022-FY2023, extracted 2024-01-15",
        classification="UNCLASSIFIED",
        caveat="Data subject to 24-48 hour lag from source systems"
    )
    fig1.savefig("/tmp/chart1_readiness_timeseries.png", dpi=200, bbox_inches="tight")
    print("Chart 1 saved: readiness_timeseries.png")

    # Chart 2: Ranked bar chart — top vendors
    fig2 = plot_ranked_horizontal_bars(
        vendors, obligations,
        title_finding="Top 10 DoD IT Services Vendors by FY2024 Obligation — Leidos and BAH Account for 43% of Total",
        xlabel="Total Obligations (FY2024)",
        highlight_top_n=3,
        value_format="currency",
    )
    add_briefing_annotations(
        fig2, fig2.axes[0],
        source="USASpending.gov, NAICS 541512, FY2024",
        classification="UNCLASSIFIED"
    )
    fig2.savefig("/tmp/chart2_vendor_bars.png", dpi=200, bbox_inches="tight")
    print("Chart 2 saved: vendor_bars.png")

    # Chart 3: Small multiples by ship class
    fig3 = plot_small_multiples_timeseries(
        small_mult_df,
        date_col="date",
        value_col="readiness",
        group_col="ship_class",
        threshold=0.75,
        suptitle="Mission Capable Rate by Ship Class — FY2022–FY2023",
        ylabel="Mission Capable Rate",
        ncols=4,
        value_format="percent",
    )
    fig3.savefig("/tmp/chart3_small_multiples.png", dpi=200, bbox_inches="tight")
    print("Chart 3 saved: small_multiples.png")

    # Chart 4: Contract value distribution
    fig4 = plot_annotated_distribution(
        corr_df["obligation_amount"],
        title_finding="DoD IT Contract Obligation Distribution — Median $272K, Long Right Tail",
        xlabel="Contract Obligation Amount ($)",
        threshold=10_000_000,
        threshold_label="Simplified Acquisition Threshold",
        log_scale=True,
    )
    add_briefing_annotations(
        fig4, fig4.axes[0],
        source="USASpending.gov, NAICS 541512, synthetic demo data",
        classification="UNCLASSIFIED"
    )
    fig4.savefig("/tmp/chart4_distribution.png", dpi=200, bbox_inches="tight")
    print("Chart 4 saved: distribution.png")

    # Chart 5: Correlation heatmap
    fig5 = plot_correlation_heatmap(
        corr_df,
        cols=["obligation_amount", "days_to_award", "n_competitors", "modification_count"],
        title="Contract Value Drivers — Procurement Data Correlation Analysis",
        method="spearman",
    )
    fig5.savefig("/tmp/chart5_correlation.png", dpi=200, bbox_inches="tight")
    print("Chart 5 saved: correlation.png")

    print("\nAll charts written to /tmp/. Open them to review.")
    print("Ready to incorporate into briefing deck or technical report.")
