# Chapter 12: Ethics, Governance, and Compliance for Federal AI

The model had been running in production for eleven months before anyone asked the question that should have been asked on day one.

Dr. Sarah Okafor pulled up the attrition prediction scores on her laptop in the Pentagon conference room while the briefer described the personnel retention program. The model had been trained on three years of Air Force enlisted records and was used to flag airmen at high risk of separating before their commitment ended — the idea being that commanders could intervene early with retention incentives. It was flagging roughly 18% of the enlisted force each quarter, and the program was being held up as a success. Retention had improved 4 percentage points since deployment.

"What's the false positive rate broken out by AFSC?" she asked. Air Force Specialty Code — the job classification system. The briefer didn't have that number. She asked a second question: "What percentage of the flagged population is non-white?" The briefer checked his phone. He said he'd have to get back to her.

He came back the next day. The model was flagging Black and Hispanic airmen at roughly 2.4 times the rate of white airmen with comparable service records and performance ratings. The retention program — well-intentioned, leadership-backed, showing positive aggregate results — was effectively concentrating command attention on minority service members based on predictions the model was producing partly through correlations with race-adjacent features the team had never examined. Nobody had run the bias analysis. The technical documentation mentioned "demographic balance" as a future work item. Eleven months had passed.

The model was suspended pending review. The program office had to answer questions from congressional staffers. The data scientists who built it were not bad people. They had simply never been required to answer questions their training hadn't covered.

This chapter covers those questions.

## What You'll Build

By the end of this chapter, you'll be able to:

- Apply the DoD AI Ethical Principles and NIST AI Risk Management Framework to a real project
- Run quantitative bias tests against protected characteristics before a model goes to production
- Write a model card that satisfies federal oversight requirements
- Map your ML project to the appropriate governance tier and compliance checklist
- Use Unity Catalog (Databricks) and Foundry's data lineage tools to produce audit-ready data provenance records
- Recognize the difference between what the law requires, what DoD policy requires, and what good practice requires — because they are not the same list

---

## The Policy Stack

Before you write a line of code on a federal AI project, you are operating inside a layered policy environment. Understanding the layers tells you which requirements are negotiable and which will get your ATO revoked.

### Executive Order 13960 and Its Successors

Executive Order 13960 (December 2020) established the first federal policy framework for AI use in government. It required agencies to inventory AI systems, adhere to nine principles for trustworthy AI, and issue governance plans. The Biden administration's EO 14110 (October 2023) expanded on this substantially — adding requirements for safety testing, red-teaming for dual-use AI systems, and transparency reports. The Trump administration's EO 14179 (January 2025) modified the federal approach again, removing some of the prescriptive testing requirements while maintaining the core framework for defense AI applications.

The practical effect: the specific paperwork has changed across administrations, but the underlying obligations — document your systems, assess their risks, test for adverse impacts — have not. Regardless of which administration is in office when you're reading this, the DoD AI Ethical Principles (published 2020, reaffirmed through subsequent policy changes) remain the operative framework for defense AI work.

### DoD AI Ethical Principles

The Department of Defense adopted five AI Ethical Principles in February 2020, following a year-long study led by the Defense Innovation Board. They are not aspirational. They are the standard against which DoD AI systems are assessed during Responsible AI assessments and acquisition reviews.

**Responsible** — There is always a human accountable for DoD AI decisions and outcomes. The system cannot be the accountable party. A named person or office is responsible.

**Equitable** — DoD takes deliberate steps to minimize unintended bias in AI systems. This explicitly includes testing for differential performance across demographic groups, mission contexts, and operational conditions the system was not trained on.

**Traceable** — DoD's AI systems are developed and deployed with transparent methodologies, data sources, and design decisions. Traceability means you can reconstruct why the model produced a given output.

**Reliable** — DoD AI operates reliably within the parameters of its intended mission and degrades safely when conditions fall outside those parameters. The system doesn't silently produce bad predictions — it signals uncertainty.

**Governable** — DoD humans can monitor, assess, and retrain AI systems. There are defined mechanisms to correct, retrain, or disengage an AI system when problems are detected.

These five principles map directly to technical requirements. "Equitable" means bias testing, not just declaring good intentions. "Traceable" means data lineage, feature documentation, and SHAP values — not just a PDF describing the model architecture. "Governable" means a monitoring job and a defined retraining trigger, not a promise to "check in periodically."

### NIST AI RMF

The National Institute of Standards and Technology published the AI Risk Management Framework (AI RMF 1.0) in January 2023. DoD Instruction 5000.90 (AI Acquisition) references it as the standard framework for AI risk management in acquisition programs. If you're on a program that will go through a Major Capability Acquisition milestone or an AI-specific ATO process, you will encounter AI RMF language.

The AI RMF organizes risk management into four functions:

```mermaid
graph LR
    A[GOVERN] --> B[MAP]
    B --> C[MEASURE]
    C --> D[MANAGE]
    D --> A
    style A fill:#1a3a5c,color:#fff
    style B fill:#1a5c3a,color:#fff
    style C fill:#5c3a1a,color:#fff
    style D fill:#3a1a5c,color:#fff
```

*Figure: NIST AI RMF core functions form a continuous cycle. GOVERN establishes organizational policies; MAP identifies risks for a specific AI system; MEASURE assesses those risks quantitatively; MANAGE implements mitigations and monitors them.*

**GOVERN** — Policies, roles, and accountability structures. Who is responsible for AI risk? What policies apply? What training is required?

**MAP** — Identify the risks that apply to a specific AI system. What could go wrong? Who is affected? What is the impact if it does go wrong?

**MEASURE** — Quantify the identified risks. Bias testing, adversarial red-teaming, performance under distribution shift.

**MANAGE** — Mitigate and monitor. Implement the fixes, track whether they work, define when to escalate.

The practical entry point for most data scientists is the MEASURE function — you're the one who runs the bias tests and generates the performance reports. But understanding MAP (the risk identification step) tells you which tests to run and why.

### The DoD Responsible AI (RAI) Assessment

DoD Instruction 5000.90 requires AI systems used in acquisition programs to undergo a Responsible AI assessment before deployment. The RAI assessment is not a checkbox exercise — it requires documented evidence of:

- Intended use scope and known limitations
- Bias testing results with methodology
- Human-machine interface design rationale
- Data provenance and quality documentation
- Monitoring and intervention plan

The assessment is reviewed by the program's Responsible AI Champion (a role created by the DoD Chief Digital and Artificial Intelligence Office). On programs using Advana or Jupiter, the CDAO's own data scientists may be part of the review.

> **Note:** The RAI process has been evolving since 2022. The CDAO's AI Assurance team publishes updated guidance at ai.mil. Check the current version before citing specific procedural requirements in program documentation, as the intake forms and review timelines have changed multiple times.

---

## Bias Testing in Practice

The attrition model in the opening scenario failed because no one ran the analysis. The analysis itself is not complicated. What makes it hard is organizational, not technical — someone has to require it, and someone has to have the authority to stop a deployment when it fails.

Here is what the technical work looks like.

### Demographic Parity and Equalized Odds

Two bias metrics are most commonly cited in federal AI guidance:

**Demographic parity** — The model's positive prediction rate is approximately equal across demographic groups. If the model flags 18% of white airmen and 43% of Black airmen as attrition risks, it does not have demographic parity.

**Equalized odds** — The model's true positive rate AND false positive rate are approximately equal across groups. Demographic parity alone can be achieved by a model that is equally wrong about everyone. Equalized odds is the stricter standard — it requires the model to be equally accurate at identifying genuine risk across groups, not just equally likely to flag people.

For government personnel decisions, equalized odds is the appropriate standard. Demographic parity by itself is insufficient because it doesn't distinguish between a model that is correctly identifying real risk differentials and one that is fabricating risk from demographic proxies.

```python
# Platform: Databricks (Advana / Jupiter) or local
# Use case: Bias audit for a personnel attrition prediction model
# Requires: fitted model, test DataFrame with protected characteristics

import numpy as np
import pandas as pd
from sklearn.metrics import (
    confusion_matrix, roc_auc_score,
    true_positive_rate, false_positive_rate
)


def bias_audit_report(
    y_true: np.ndarray,
    y_pred_proba: np.ndarray,
    sensitive_attr: pd.Series,
    threshold: float = 0.50,
    reference_group: str = None,
) -> pd.DataFrame:
    """
    Compute bias metrics across groups defined by a sensitive attribute.

    Metrics computed for each group:
        - n: sample size
        - positive_rate: fraction of positive predictions at threshold
        - tpr: true positive rate (recall) — P(predicted positive | actually positive)
        - fpr: false positive rate — P(predicted positive | actually negative)
        - auc: ROC-AUC (if ≥10 positive samples in group)
        - dp_ratio: demographic parity ratio vs. reference group
        - odds_ratio: equalized odds ratio (FPR ratio vs. reference group)

    Args:
        y_true: True labels (0/1)
        y_pred_proba: Predicted probabilities (positive class)
        sensitive_attr: Series with group label for each sample
        threshold: Classification threshold for binary predictions
        reference_group: Group to use as ratio denominator.
                         Defaults to the group with the highest positive rate.

    Returns:
        DataFrame with one row per group, sorted by positive_rate descending.
    """
    y_pred = (y_pred_proba >= threshold).astype(int)
    groups = sensitive_attr.unique()
    rows   = []

    for group in groups:
        mask  = (sensitive_attr == group).values
        n     = int(mask.sum())
        n_pos = int(y_true[mask].sum())

        if n < 20:
            continue  # skip tiny slices — metrics are unreliable

        tn, fp, fn, tp = confusion_matrix(
            y_true[mask], y_pred[mask], labels=[0, 1]
        ).ravel()

        positive_rate = float((tp + fp) / n)
        tpr  = float(tp / (tp + fn)) if (tp + fn) > 0 else np.nan
        fpr  = float(fp / (fp + tn)) if (fp + tn) > 0 else np.nan

        auc = np.nan
        if n_pos >= 10 and n_pos < n:
            try:
                auc = roc_auc_score(y_true[mask], y_pred_proba[mask])
            except Exception:
                pass

        rows.append({
            "group":         str(group),
            "n":             n,
            "n_positive":    n_pos,
            "positive_rate": round(positive_rate, 4),
            "tpr":           round(tpr, 4) if not np.isnan(tpr) else np.nan,
            "fpr":           round(fpr, 4) if not np.isnan(fpr) else np.nan,
            "auc":           round(auc, 4) if not np.isnan(auc) else np.nan,
        })

    result = pd.DataFrame(rows).sort_values("positive_rate", ascending=False)

    # Compute ratios relative to reference group
    if reference_group is None:
        # Default: group with the lowest positive rate (most favorable treatment)
        reference_group = result.iloc[-1]["group"]

    ref_row = result[result["group"] == reference_group].iloc[0]
    result["dp_ratio"]    = (result["positive_rate"] / ref_row["positive_rate"]).round(3)
    result["fpr_ratio"]   = (result["fpr"] / ref_row["fpr"]).round(3)

    print(f"\nBias Audit Report  |  Threshold: {threshold}  |  Reference: {reference_group}")
    print("=" * 70)
    print(result.to_string(index=False))
    print()

    # Flag groups exceeding 4/5ths rule (80% rule from EEOC guidelines)
    # dp_ratio < 0.8 indicates potential disparate impact
    flagged = result[result["dp_ratio"] < 0.80]
    if len(flagged) > 0:
        print(f"POTENTIAL DISPARATE IMPACT (dp_ratio < 0.80):")
        for _, row in flagged.iterrows():
            print(f"  Group '{row['group']}': positive_rate={row['positive_rate']:.3f}, "
                  f"dp_ratio={row['dp_ratio']:.3f}")
        print(f"\nAction required: Review feature set for proxies, adjust threshold,")
        print(f"or apply post-processing fairness constraint before deployment.")
    else:
        print("No groups below 4/5ths threshold. Continue to equalized odds review.")

    return result


def equalized_odds_check(bias_df: pd.DataFrame, tpr_tolerance: float = 0.05,
                          fpr_tolerance: float = 0.05) -> bool:
    """
    Check whether the model satisfies approximate equalized odds.

    A model satisfies equalized odds if TPR and FPR are within tolerance
    of the reference group for all protected groups.

    Args:
        bias_df: Output DataFrame from bias_audit_report()
        tpr_tolerance: Maximum allowed absolute difference in TPR across groups
        fpr_tolerance: Maximum allowed absolute difference in FPR across groups

    Returns:
        True if equalized odds is approximately satisfied, False otherwise
    """
    tpr_range = bias_df["tpr"].max() - bias_df["tpr"].min()
    fpr_range = bias_df["fpr"].max() - bias_df["fpr"].min()

    tpr_ok = bool(tpr_range <= tpr_tolerance)
    fpr_ok = bool(fpr_range <= fpr_tolerance)

    print(f"Equalized Odds Check:")
    print(f"  TPR range: {tpr_range:.4f}  (tolerance: {tpr_tolerance})  "
          f"{'PASS' if tpr_ok else 'FAIL'}")
    print(f"  FPR range: {fpr_range:.4f}  (tolerance: {fpr_tolerance})  "
          f"{'PASS' if fpr_ok else 'FAIL'}")

    if not (tpr_ok and fpr_ok):
        print("\n  Equalized odds NOT satisfied.")
        print("  Options: threshold calibration per group, re-feature-engineering,")
        print("  adversarial debiasing, or escalate to RAI review.")
    else:
        print("\n  Equalized odds approximately satisfied within tolerance.")

    return tpr_ok and fpr_ok
```

### The Proxy Problem

The bias analysis above catches direct demographic disparities. It does not automatically catch proxy discrimination — when a model uses features that are highly correlated with protected characteristics without using the characteristic directly.

Common proxies in government datasets:

- **Zip code / installation** correlates with race and socioeconomic status
- **Prior disciplinary record** may reflect biased policing or command culture rather than individual behavior
- **MOS/AFSC specialty** correlates with gender and race due to historical assignment patterns
- **Years of education** correlates with socioeconomic background

The right approach is not to exclude all correlated features. That would destroy model performance and is often impossible — installation is a legitimate feature for readiness prediction. The right approach is to document the correlations, include them in the RAI assessment, and monitor whether removing or transforming the feature changes the bias metric.

```python
def proxy_correlation_scan(
    X: pd.DataFrame,
    protected_cols: list,
    feature_cols: list,
    correlation_threshold: float = 0.15,
) -> pd.DataFrame:
    """
    Identify features with potentially concerning correlations to protected attributes.

    Uses Cramér's V for categorical-categorical associations and
    point-biserial correlation for numeric-binary associations.
    Returns a DataFrame of (feature, protected_attribute, correlation) pairs
    above the threshold, sorted by correlation descending.

    This does not mean flagged features must be excluded. It means
    they require documentation and monitoring.
    """
    from scipy.stats import pointbiserialr
    import itertools

    results = []

    for feat_col in feature_cols:
        for prot_col in protected_cols:
            # Skip if either column has no variation
            if X[feat_col].nunique() < 2 or X[prot_col].nunique() < 2:
                continue

            if X[feat_col].dtype in [np.float64, np.float32, np.int64, np.int32]:
                # Numeric feature vs. binary protected attribute
                if X[prot_col].nunique() == 2:
                    corr, pval = pointbiserialr(
                        X[prot_col].astype(float), X[feat_col].astype(float)
                    )
                    abs_corr = abs(corr)
                else:
                    # Use eta-squared approximation for multi-class
                    from sklearn.feature_selection import f_classif
                    f_stat, pval = f_classif(
                        X[[feat_col]].fillna(0),
                        X[prot_col].astype("category").cat.codes
                    )
                    # Normalize to [0,1] range as rough effect size
                    abs_corr = min(float(f_stat[0]) / (float(f_stat[0]) + len(X)), 1.0)
            else:
                # Categorical feature — use Cramér's V
                contingency = pd.crosstab(X[feat_col], X[prot_col])
                from scipy.stats import chi2_contingency
                chi2, _, _, _ = chi2_contingency(contingency)
                n = contingency.sum().sum()
                k = min(contingency.shape) - 1
                abs_corr = float(np.sqrt(chi2 / (n * k))) if (n * k) > 0 else 0.0

            if abs_corr >= correlation_threshold:
                results.append({
                    "feature":             feat_col,
                    "protected_attribute": prot_col,
                    "correlation":         round(abs_corr, 4),
                    "note":                "Review for proxy discrimination risk",
                })

    report = pd.DataFrame(results).sort_values("correlation", ascending=False)

    if len(report) > 0:
        print(f"Proxy correlation scan — {len(report)} feature-attribute pairs "
              f"above threshold ({correlation_threshold}):")
        print(report.to_string(index=False))
    else:
        print(f"No features above correlation threshold ({correlation_threshold}).")

    return report
```

---

## Data Governance on Federal Platforms

Bias testing addresses the model. Data governance addresses everything the model depends on — where the training data came from, who modified it, what access controls apply to it, and whether the version you used for training is the version you'd use if you had to reproduce the results under an audit.

### Unity Catalog on Databricks

Unity Catalog is Databricks' centralized governance layer, and it is mandatory on all new Databricks accounts created after December 2025. For federal data scientists on Advana and Jupiter, Unity Catalog provides the technical infrastructure for compliance:

- **Column-level security** — PII fields (SSN, DOB, home address) can be masked or restricted to specific service accounts, even within otherwise accessible tables
- **Row-level security** — Policies can restrict which rows a given user or group can see, enforced at the query layer regardless of how the user constructs their query
- **Data lineage** — Unity Catalog tracks which tables produced which outputs, which notebooks read which tables, and which queries wrote to which Delta tables. This lineage is queryable via the Unity Catalog REST API.
- **Audit logs** — Every data access, schema change, and permission grant is logged to audit tables that are queryable by compliance officers

```python
# Platform: Databricks (Advana / Jupiter)
# Query Unity Catalog data lineage for a model's training data

from databricks.sdk import WorkspaceClient
from databricks.sdk.service.catalog import LineageDirection

w = WorkspaceClient()

def get_table_lineage(table_full_name: str) -> dict:
    """
    Retrieve upstream lineage for a Delta table using Unity Catalog API.

    Returns a dict with upstream tables and the notebooks/queries that
    wrote to this table. Use this to document training data provenance
    in a model card or RAI assessment.

    Args:
        table_full_name: Three-part name (catalog.schema.table)

    Returns:
        Dict with 'upstream_tables' and 'written_by' lists
    """
    lineage = w.lineage_tracking.table_lineage(
        table_name=table_full_name,
        direction=LineageDirection.UPSTREAM,
    )

    upstream_tables = []
    written_by      = []

    for node in lineage.upstreams or []:
        if hasattr(node, "table_info") and node.table_info:
            upstream_tables.append({
                "table":   node.table_info.full_name,
                "catalog": node.table_info.catalog_name,
            })
        if hasattr(node, "notebook_info") and node.notebook_info:
            written_by.append({
                "type": "notebook",
                "path": node.notebook_info.path,
            })
        if hasattr(node, "query_info") and node.query_info:
            written_by.append({
                "type":     "query",
                "query_id": node.query_info.query_id,
            })

    result = {
        "table":           table_full_name,
        "upstream_tables": upstream_tables,
        "written_by":      written_by,
    }

    print(f"Lineage for {table_full_name}:")
    print(f"  Upstream tables: {len(upstream_tables)}")
    for t in upstream_tables:
        print(f"    - {t['table']}")
    print(f"  Written by: {len(written_by)} notebook(s)/query(ies)")

    return result


def check_pii_column_policies(table_full_name: str) -> list:
    """
    List column-level masking policies on a table.
    Verifies that PII columns have masking applied before the table
    is used for model training.
    """
    catalog, schema, table = table_full_name.split(".")
    table_info = w.tables.get(full_name=table_full_name)

    masked_cols = []
    unmasked_pii_candidates = []

    # Known PII column name patterns (customize for your data dictionary)
    pii_patterns = [
        "ssn", "social_security", "dob", "date_of_birth",
        "home_address", "personal_email", "phone_number",
        "full_name", "first_name", "last_name"
    ]

    for col in table_info.columns or []:
        col_lower = col.name.lower()
        has_mask  = col.mask is not None

        if has_mask:
            masked_cols.append(col.name)
        elif any(pii in col_lower for pii in pii_patterns):
            unmasked_pii_candidates.append(col.name)

    if unmasked_pii_candidates:
        print(f"WARNING — possible unmasked PII columns in {table_full_name}:")
        for c in unmasked_pii_candidates:
            print(f"  {c} — verify masking policy or exclude from training data")
    else:
        print(f"No unmasked PII candidates detected in {table_full_name}")

    return unmasked_pii_candidates
```

### Platform Spotlight: Palantir Foundry

Foundry's data governance model is built into the Ontology. Every dataset in Foundry has an owner, a steward, and a set of access policies defined at the Ontology layer — not enforced by table-level permissions that can be worked around, but at the semantic object level.

For ethics and compliance work, Foundry's most relevant feature is **data lineage through Transforms**. Every Transform declares its inputs and outputs explicitly (see Chapter 04). This means Foundry's data catalog automatically knows which datasets fed your training data, which Transforms cleaned them, and which model artifacts were produced from them. You don't have to reconstruct this manually for a RAI assessment — it's already captured in the platform.

The tradeoff: Foundry's governance model is tightly coupled to the Ontology. Data that isn't modeled in the Ontology (external files, ad-hoc imports, data brought in outside the connector framework) doesn't get the same lineage guarantees. If your training data includes anything imported outside the standard pipeline, document it separately.

---

## Writing a Model Card

A model card is the document that tells anyone who inherits your deployed model what it does, how it was built, what it should and shouldn't be used for, and what its known failure modes are. The term comes from Google's 2019 paper proposing standardized ML model reporting, but federal programs are increasingly requiring something equivalent under various names: AI system documentation, algorithm impact assessment, responsible AI documentation.

The DoD CDAO's AI Assurance guidance references model cards as a best practice. On programs going through the RAI assessment, a completed model card substantially reduces the review burden.

A minimal federal model card covers nine items:

1. **Model description** — What does it predict? What is the output format? What decision does it inform?
2. **Intended use** — Which populations, contexts, and decisions is it approved for?
3. **Out-of-scope uses** — What should it NOT be used for? This section is as important as intended use.
4. **Training data** — Source, time period, geographic scope, known gaps, data quality tier.
5. **Evaluation data** — How does the test set differ from training? Is it a temporal hold-out?
6. **Performance metrics** — Overall AND stratified by the operationally relevant subgroups.
7. **Bias and fairness analysis** — Results of demographic parity and equalized odds checks.
8. **Limitations and risks** — What conditions cause the model to underperform? What happens when it fails?
9. **Monitoring plan** — Who is responsible? How often is it reviewed? What triggers a retrain?

```python
import json
from datetime import date
from dataclasses import dataclass, asdict, field
from typing import Optional


@dataclass
class ModelCard:
    """
    Structured model card for federal AI deployments.
    Serializes to JSON for storage in MLflow or Foundry documentation.
    """
    # Identity
    model_name:        str
    model_version:     str
    created_date:      str = field(default_factory=lambda: date.today().isoformat())
    created_by:        str = ""
    organization:      str = ""

    # Model description
    description:       str = ""
    model_type:        str = ""           # classification / regression / clustering
    output_format:     str = ""           # e.g., "probability score 0-1, threshold 0.65"
    decision_informed: str = ""           # what human decision does this support

    # Use
    intended_use:      str = ""
    out_of_scope_use:  str = ""
    deployment_platform: str = ""         # Databricks / Foundry / Advana / Jupiter

    # Data
    training_data_source:    str = ""
    training_data_period:    str = ""
    training_data_size_rows: int = 0
    training_data_quality_tier: str = ""  # bronze / silver / gold
    evaluation_data_source:  str = ""
    evaluation_strategy:     str = ""     # random split / temporal / stratified

    # Performance — overall
    primary_metric:      str = ""
    primary_metric_value: float = 0.0
    secondary_metrics:   dict = field(default_factory=dict)

    # Bias and fairness
    bias_analysis_performed: bool = False
    bias_analysis_methodology: str = ""
    bias_findings:       str = ""
    disparate_impact_detected: bool = False
    disparate_impact_groups:   list = field(default_factory=list)

    # Limitations
    known_limitations:   str = ""
    failure_modes:       str = ""
    distribution_shift_risk: str = ""

    # Governance
    monitoring_owner:    str = ""
    monitoring_frequency: str = ""
    retraining_trigger:  str = ""
    rai_assessment_status: str = ""  # not started / in progress / approved / waived
    rai_assessment_date:   str = ""

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(asdict(self), indent=indent)

    def to_markdown(self) -> str:
        """Render the model card as a Markdown document."""
        lines = [
            f"# Model Card: {self.model_name} v{self.model_version}",
            f"",
            f"**Created:** {self.created_date} | **By:** {self.created_by} "
            f"| **Org:** {self.organization}",
            f"",
            f"## Model Description",
            f"{self.description}",
            f"",
            f"- **Type:** {self.model_type}",
            f"- **Output:** {self.output_format}",
            f"- **Informs decision:** {self.decision_informed}",
            f"- **Deployment platform:** {self.deployment_platform}",
            f"",
            f"## Intended Use",
            f"{self.intended_use}",
            f"",
            f"## Out-of-Scope Use",
            f"{self.out_of_scope_use}",
            f"",
            f"## Training Data",
            f"- **Source:** {self.training_data_source}",
            f"- **Period:** {self.training_data_period}",
            f"- **Rows:** {self.training_data_size_rows:,}",
            f"- **Quality tier:** {self.training_data_quality_tier}",
            f"- **Evaluation strategy:** {self.evaluation_strategy}",
            f"",
            f"## Performance",
            f"- **{self.primary_metric}:** {self.primary_metric_value:.4f}",
        ]
        for metric, value in self.secondary_metrics.items():
            lines.append(f"- **{metric}:** {value}")

        lines += [
            f"",
            f"## Bias and Fairness",
            f"- **Analysis performed:** {self.bias_analysis_performed}",
            f"- **Methodology:** {self.bias_analysis_methodology}",
            f"- **Findings:** {self.bias_findings}",
            f"- **Disparate impact detected:** {self.disparate_impact_detected}",
        ]
        if self.disparate_impact_groups:
            lines.append(f"- **Affected groups:** {', '.join(self.disparate_impact_groups)}")

        lines += [
            f"",
            f"## Limitations",
            f"{self.known_limitations}",
            f"",
            f"**Known failure modes:** {self.failure_modes}",
            f"",
            f"**Distribution shift risk:** {self.distribution_shift_risk}",
            f"",
            f"## Governance",
            f"- **Monitoring owner:** {self.monitoring_owner}",
            f"- **Monitoring frequency:** {self.monitoring_frequency}",
            f"- **Retraining trigger:** {self.retraining_trigger}",
            f"- **RAI assessment status:** {self.rai_assessment_status}",
        ]
        if self.rai_assessment_date:
            lines.append(f"- **RAI assessment date:** {self.rai_assessment_date}")

        return "\n".join(lines)

    def validate(self) -> list:
        """
        Check that required fields are populated.
        Returns list of missing field names (empty = card is complete).
        """
        required_fields = [
            "model_name", "model_version", "created_by", "organization",
            "description", "intended_use", "out_of_scope_use",
            "training_data_source", "training_data_period",
            "evaluation_strategy", "primary_metric",
            "bias_analysis_performed",
            "known_limitations", "monitoring_owner",
            "retraining_trigger", "rai_assessment_status",
        ]
        missing = [f for f in required_fields if not getattr(self, f, None)]
        if missing:
            print(f"Incomplete model card — missing: {', '.join(missing)}")
        else:
            print("Model card complete — all required fields populated.")
        return missing
```

---

## NIST AI RMF in Practice: A Worked Example

The NIST AI RMF sounds like a compliance framework. It is also a practical engineering checklist. Here is how it maps to a personnel readiness prediction project.

### MAP: Identify Risks

For the readiness model, the relevant risk categories are:

- **Accuracy risk** — Model underperforms for specific hull classes, fiscal year ranges, or operational tempos outside the training distribution
- **Fairness risk** — Model produces differential predictions for protected-characteristic groups without corresponding legitimate operational justification
- **Misuse risk** — Model outputs are used for decisions beyond the stated intended use (e.g., using a readiness prediction model to inform personnel assignments)
- **Data freshness risk** — Training data is from a period that no longer reflects current equipment or doctrine; model degrades silently
- **Dependency risk** — Model depends on data sources that can be modified or discontinued by parties outside the project team's control

### MEASURE: Quantify

For each risk, you need a number:

| Risk | Metric | Target | Measured |
|---|---|---|---|
| Accuracy | Overall AUC on temporal hold-out | ≥ 0.80 | 0.84 |
| Fairness | Max demographic parity ratio across hull classes | ≤ 1.25 | 1.19 |
| Fairness | Max FPR ratio across hull classes | ≤ 1.30 | 1.41 — **FLAG** |
| Data freshness | Training data recency (months to cutoff) | ≤ 18 months | 14 months |
| Coverage | Fraction of current fleet covered by training data | ≥ 90% | 88% — **MONITOR** |

The FPR ratio flag means hull class X is receiving false positive readiness alerts at 1.41 times the rate of the reference class. That's within the range that requires documentation and justification in the RAI assessment — not automatic disqualification, but not something to ignore.

### MANAGE: Mitigate

For each flagged metric:

- FPR ratio flag → Investigate hull class X's training data volume. If underrepresented, consider oversampling or separate threshold calibration for that class.
- Coverage flag → Document which hull classes are underrepresented. Add a prediction confidence flag that's set to "low coverage" for asset types with fewer than 50 training examples.

The MANAGE function doesn't always mean "fix the model." Sometimes it means "add a warning label." A model that produces less reliable predictions for DDG-51 Flight I ships because there are only 12 of them and half are in planned decommission is not a failed model — it's a model with a documented limitation that operators know about.

---

## Where This Goes Wrong

**Failure Mode 1: Ethics as a Checklist at the End**

**The mistake:** Treating the RAI assessment and bias testing as documentation tasks to complete after the model is built, tested, and already running in a pilot.

**Why smart people make it:** The schedule pressure to show results is real. Bias testing feels like it can be done at the end. The program manager needs a demo in two weeks.

**How to recognize you're making it:**
- Bias analysis is scheduled for "Sprint 6" and the model is being shown to stakeholders in Sprint 4
- The model card template is listed as a deliverable in the final phase of the project plan
- Nobody on the team has asked about protected characteristics in the training data
- You've never seen the word "equalized odds" in a project document

**What to do instead:** Run the proxy correlation scan before feature selection. Run the preliminary bias audit before model selection. Include bias metrics in the Sprint 4 demo alongside AUC. It takes four hours to do a basic bias audit. Do it while the model is still malleable.

---

**Failure Mode 2: Documenting Intent Instead of Results**

**The mistake:** Writing "the model was designed to be fair and unbiased" rather than reporting the actual demographic parity ratio.

**Why smart people make it:** Documenting good intentions is easy. Running the bias analysis and reporting that one group has a demographic parity ratio of 1.47 is uncomfortable — it creates a finding that someone has to respond to.

**How to recognize you're making it:**
- The model card says "bias was considered" without quantitative results
- The RAI documentation uses words like "efforts were made" and "steps were taken"
- There are no numbers in the fairness section of any project document
- When asked for the FPR breakdown, nobody has a table

**What to do instead:** The number is the document. "The model's false positive rate for Group A is 12.3% and for Group B is 8.1%, a ratio of 1.52. This was reviewed during RAI assessment and determined to be within acceptable range because [specific technical reason]. It will be monitored monthly and will trigger a review if it exceeds 1.75." That is a real document. "Fairness was considered" is not.

---

**Failure Mode 3: One-Time Compliance vs. Ongoing Governance**

**The mistake:** Treating the approved RAI assessment as permanent authorization. The model got approved 18 months ago; therefore it is currently approved.

**Why smart people make it:** The approval process was hard. You worked for four months to get it. It seems unfair to have to revisit it. The model hasn't changed.

**How to recognize you're making it:**
- The monitoring job hasn't run in 90 days
- Training data is now more than 24 months old
- The operational context has changed (new equipment, doctrine change, force structure change) but the model card hasn't been updated
- Nobody on the current team knows who the original RAI approver was

**What to do instead:** The RAI assessment approval is for the model at a specific point in time, on specific data, in a specific operational context. When any of those change materially, the assessment needs to be revisited. Set a calendar reminder for 12 months after approval. At that point, re-run the bias metrics, check the monitoring data, and determine whether a re-review is required. This takes a day. Not doing it for eighteen months and then having a congressional inquiry takes considerably longer.

---

## Practical Takeaway: Pre-Deployment Ethics Checklist

This checklist represents the minimum bar for deploying a model that affects people in a federal context. Use it as a go/no-go gate before requesting ATO or deployment authorization.

**Data governance:**
- [ ] Training data source is documented with table names, time period, and row count
- [ ] Data lineage is captured in Unity Catalog or Foundry's catalog
- [ ] PII columns are masked or excluded from training features
- [ ] Column-level security policies are applied to the training dataset
- [ ] Access to the training data requires documented authorization

**Bias and fairness:**
- [ ] Protected characteristics relevant to the use case are identified
- [ ] Proxy correlation scan has been run against all training features
- [ ] Demographic parity ratio has been computed for all protected groups
- [ ] Equalized odds check (TPR and FPR parity) has been run
- [ ] Disparate impact findings are documented with quantitative results
- [ ] Bias findings have been reviewed by someone with authority to approve or block deployment

**Model card:**
- [ ] Intended use is defined specifically enough to identify out-of-scope uses
- [ ] Out-of-scope uses are explicitly listed (not just implied)
- [ ] Performance metrics include stratified results, not just overall
- [ ] Known limitations are documented, not just hinted at
- [ ] Monitoring owner is a named person, not a team or office
- [ ] Retraining trigger is a specific metric threshold, not "as needed"

**RAI assessment:**
- [ ] NIST AI RMF MAP step is documented (risk identification)
- [ ] NIST AI RMF MEASURE step has quantitative results for each identified risk
- [ ] NIST AI RMF MANAGE mitigations are documented for any flagged risks
- [ ] RAI Champion review is scheduled or completed

---

## Platform Comparison

| Dimension | Advana (Databricks) | Palantir Foundry | Databricks GovCloud | Qlik | Navy Jupiter |
|---|---|---|---|---|---|
| Data lineage | Unity Catalog (automatic) | Foundry Transforms (automatic) | Unity Catalog (automatic) | Limited (Qlik lineage view) | Unity Catalog via Databricks |
| Column-level masking | Unity Catalog policies | Ontology access policies | Unity Catalog policies | Not applicable | Unity Catalog policies |
| Row-level security | Unity Catalog RLS | Ontology object-level | Unity Catalog RLS | Qlik section access | Unity Catalog RLS |
| Audit logging | UC audit tables | Foundry audit events | UC audit tables | Qlik audit log | UC audit tables |
| Model documentation | MLflow model cards | Foundry code repos | MLflow model cards | Qlik Predict reports | MLflow model cards |
| Bias testing tools | DIY (scikit-learn, fairlearn) | DIY (Code Workspaces) | DIY (scikit-learn, fairlearn) | Qlik AI Trust Score | DIY (scikit-learn, fairlearn) |
| RAI process integration | Manual + MLflow tags | Foundry documentation | Manual + MLflow tags | None native | Manual + MLflow tags |

The honest comparison: no platform does bias testing automatically. Qlik's AI Trust Score (released July 2025) helps assess data readiness for AI, but it is not a fairness audit. On all five platforms, bias testing is the data scientist's responsibility — the platform provides the data infrastructure and the logging, but the analysis is yours.

---

## Exercises

See [exercises/exercises.md](./exercises/exercises.md) for hands-on problems.

---

## Chapter Close

**The one thing to remember:** Documenting intent is not documentation — the bias audit number is the document, the monitoring owner's name is the document, the specific retraining trigger threshold is the document. Everything else is a promise.

**What to do Monday morning:** Pull the last model you own or inherited. Find the model card or its equivalent. Check whether it has: a demographic parity ratio for each relevant protected group, a named monitoring owner, and a specific retraining trigger threshold. If any of those three are missing, write them down today. Not this sprint. Today.

**What comes next:** Chapter 13 covers generative AI, RAG pipelines, and large language models in federal contexts — the fastest-moving area in the handbook and the one where the governance frameworks are least settled. The ethics principles in this chapter apply directly: an LLM that produces biased outputs for protected groups, a RAG pipeline that cites classified documents it shouldn't access, an agent that takes irreversible real-world actions without human review — these are the same problems in a new form. The frameworks transfer. The stakes escalate.
