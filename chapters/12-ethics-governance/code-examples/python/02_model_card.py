"""
Chapter 12: Ethics, Governance, and Compliance
Code Example 02 — Model Cards and Data Governance

Demonstrates:
- Structured ModelCard dataclass with validation and Markdown export
- Unity Catalog lineage and PII policy checks via Databricks SDK
- Foundry dataset provenance lookup patterns
- Audit-trail generation for pre-deployment review packages
"""

from __future__ import annotations

import json
import textwrap
from dataclasses import dataclass, field
from datetime import date, datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Section 1 — ModelCard dataclass
# ---------------------------------------------------------------------------


class RiskTier(str, Enum):
    """DoD AI risk classification tiers."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class UseCategory(str, Enum):
    """Broad intended-use categories aligned with DoD AI Ethical Principles."""
    OPERATIONAL_SUPPORT = "operational_support"
    HUMAN_RESOURCE = "human_resource"
    LOGISTICS = "logistics"
    INTELLIGENCE = "intelligence"
    ACQUISITION = "acquisition"
    HEALTH = "health"


@dataclass
class ModelPerformanceSlice:
    """Performance on a specific demographic or operational subgroup."""
    slice_name: str          # e.g. "pay_grade_E1_E4", "race_Black"
    n_samples: int
    metric_name: str         # e.g. "AUC", "FPR", "Recall"
    metric_value: float
    baseline_value: float    # overall population metric for comparison
    flagged: bool = False    # True when disparity exceeds threshold

    @property
    def disparity_ratio(self) -> float:
        """Slice metric / baseline metric.  <0.8 or >1.25 typically flagged."""
        if self.baseline_value == 0:
            return float("inf")
        return self.metric_value / self.baseline_value


@dataclass
class DataSource:
    """Structured record of a single input dataset."""
    name: str
    platform: str            # e.g. "Unity Catalog", "Foundry", "DCPDS"
    catalog: Optional[str]
    schema: Optional[str]
    table: Optional[str]
    pii_classified: bool
    classification_level: str  # e.g. "UNCLASSIFIED//FOUO", "SECRET"
    record_count_approx: int
    date_range_start: Optional[date]
    date_range_end: Optional[date]
    lineage_verified: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "platform": self.platform,
            "full_table_path": f"{self.catalog}.{self.schema}.{self.table}"
            if all([self.catalog, self.schema, self.table])
            else "N/A",
            "pii_classified": self.pii_classified,
            "classification_level": self.classification_level,
            "record_count_approx": self.record_count_approx,
            "date_range": f"{self.date_range_start} to {self.date_range_end}",
            "lineage_verified": self.lineage_verified,
        }


@dataclass
class ModelCard:
    """
    Structured model card for federal AI deployments.

    Captures the information required by DoD RAI assessments and supports
    the NIST AI RMF GOVERN and DOCUMENT functions.  Produces a Markdown
    document ready for insertion into a SharePoint library, a Confluence
    page, or a Foundry dataset description.
    """

    # --- Identity ---
    model_name: str
    model_version: str
    created_date: date
    last_updated: date
    authors: List[str]
    organization: str
    point_of_contact: str   # government email

    # --- Purpose and scope ---
    intended_use: str
    use_category: UseCategory
    risk_tier: RiskTier
    out_of_scope_uses: List[str]

    # --- Data ---
    training_data_sources: List[DataSource]
    evaluation_data_sources: List[DataSource]
    preprocessing_steps: List[str]

    # --- Model details ---
    model_type: str          # e.g. "Gradient Boosting Classifier"
    framework: str           # e.g. "scikit-learn 1.3.2 / Databricks ML Runtime 14.3"
    hyperparameters: Dict[str, Any]
    feature_list: List[str]
    explicitly_excluded_features: List[str]  # protected attributes removed

    # --- Performance ---
    overall_metrics: Dict[str, float]       # {"AUC": 0.87, "F1": 0.74, ...}
    performance_slices: List[ModelPerformanceSlice]

    # --- Ethics and fairness ---
    fairness_constraints: List[str]         # plain-English statements
    bias_audit_passed: bool
    bias_audit_date: Optional[date]
    bias_auditor: Optional[str]
    bias_audit_report_location: Optional[str]

    # --- Governance ---
    approver_name: Optional[str] = None
    approver_title: Optional[str] = None
    approval_date: Optional[date] = None
    authority_to_operate: Optional[str] = None  # ATO number or "pending"
    mlflow_run_id: Optional[str] = None
    mlflow_model_version: Optional[int] = None

    # --- Monitoring ---
    monitoring_plan: str = ""
    retraining_trigger: str = ""
    sunset_date: Optional[date] = None

    # --- Validation errors ---
    _validation_errors: List[str] = field(default_factory=list, init=False, repr=False)

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------

    def validate(self) -> Tuple[bool, List[str]]:
        """
        Run pre-deployment validation checks.

        Returns (passed: bool, errors: List[str]).
        Raises no exceptions — caller decides how to handle failures.
        """
        self._validation_errors = []

        # Identity checks
        if not self.point_of_contact.endswith(".mil"):
            self._validation_errors.append(
                "point_of_contact must be a .mil email address"
            )

        # Protected attributes
        protected = {"race", "ethnicity", "gender", "religion", "national_origin",
                     "age", "disability_status", "sex"}
        leaked = protected.intersection({f.lower() for f in self.feature_list})
        if leaked:
            self._validation_errors.append(
                f"Protected attributes present in feature_list: {leaked}. "
                "Move to explicitly_excluded_features."
            )

        # Bias audit
        if self.risk_tier in (RiskTier.HIGH, RiskTier.CRITICAL):
            if not self.bias_audit_passed:
                self._validation_errors.append(
                    f"Bias audit required and not passed for risk_tier={self.risk_tier.value}"
                )
            if not self.bias_audit_date:
                self._validation_errors.append("bias_audit_date required for HIGH/CRITICAL tier")
            if not self.bias_audit_report_location:
                self._validation_errors.append(
                    "bias_audit_report_location required for HIGH/CRITICAL tier"
                )

        # Approval
        if not self.approver_name:
            self._validation_errors.append("approver_name required before deployment")
        if not self.approval_date:
            self._validation_errors.append("approval_date required before deployment")

        # Monitoring
        if not self.monitoring_plan:
            self._validation_errors.append("monitoring_plan must be documented")
        if not self.retraining_trigger:
            self._validation_errors.append("retraining_trigger must be documented")

        # Data lineage
        all_sources = self.training_data_sources + self.evaluation_data_sources
        unverified = [s.name for s in all_sources if not s.lineage_verified]
        if unverified:
            self._validation_errors.append(
                f"Lineage not verified for: {unverified}"
            )

        # Flagged performance slices
        flagged_slices = [s.slice_name for s in self.performance_slices if s.flagged]
        if flagged_slices:
            self._validation_errors.append(
                f"Flagged disparity slices require remediation: {flagged_slices}"
            )

        passed = len(self._validation_errors) == 0
        return passed, list(self._validation_errors)

    # ------------------------------------------------------------------
    # Markdown export
    # ------------------------------------------------------------------

    def to_markdown(self) -> str:
        """
        Render the model card as a GitHub-flavored Markdown document.

        The output is designed to paste directly into Confluence, SharePoint,
        or a Foundry dataset description.
        """
        passed, errors = self.validate()
        status_badge = "APPROVED" if (passed and self.approval_date) else "PENDING REVIEW"

        lines: List[str] = []

        def h1(text: str) -> None:
            lines.append(f"# {text}\n")

        def h2(text: str) -> None:
            lines.append(f"\n## {text}\n")

        def h3(text: str) -> None:
            lines.append(f"\n### {text}\n")

        def kv(key: str, val: Any) -> None:
            lines.append(f"**{key}:** {val}  ")

        def bullet(items: List[str], indent: int = 0) -> None:
            prefix = "  " * indent
            for item in items:
                lines.append(f"{prefix}- {item}")

        h1(f"Model Card: {self.model_name} v{self.model_version}")
        lines.append(f"> Status: **{status_badge}**  \n")

        # --- Section 1: Identity ---
        h2("1. Model Identity")
        kv("Model Name", self.model_name)
        kv("Version", self.model_version)
        kv("Risk Tier", self.risk_tier.value.upper())
        kv("Use Category", self.use_category.value)
        kv("Organization", self.organization)
        kv("Point of Contact", self.point_of_contact)
        kv("Authors", ", ".join(self.authors))
        kv("Created", str(self.created_date))
        kv("Last Updated", str(self.last_updated))
        if self.mlflow_run_id:
            kv("MLflow Run ID", f"`{self.mlflow_run_id}`")
        if self.mlflow_model_version:
            kv("MLflow Model Version", self.mlflow_model_version)

        # --- Section 2: Purpose ---
        h2("2. Intended Use")
        h3("Intended Use")
        lines.append(textwrap.fill(self.intended_use, width=100))
        lines.append("")
        h3("Out-of-Scope Uses")
        bullet(self.out_of_scope_uses)

        # --- Section 3: Data ---
        h2("3. Training and Evaluation Data")
        h3("Training Data Sources")
        for src in self.training_data_sources:
            d = src.to_dict()
            lines.append(f"**{src.name}**")
            for k, v in d.items():
                if k != "name":
                    lines.append(f"  - {k}: {v}")
            lines.append("")

        h3("Evaluation Data Sources")
        for src in self.evaluation_data_sources:
            d = src.to_dict()
            lines.append(f"**{src.name}**")
            for k, v in d.items():
                if k != "name":
                    lines.append(f"  - {k}: {v}")
            lines.append("")

        h3("Preprocessing Steps")
        bullet(self.preprocessing_steps)

        # --- Section 4: Model ---
        h2("4. Model Details")
        kv("Model Type", self.model_type)
        kv("Framework", self.framework)
        lines.append("")
        h3("Hyperparameters")
        lines.append("```json")
        lines.append(json.dumps(self.hyperparameters, indent=2))
        lines.append("```")
        h3("Features Used")
        bullet(self.feature_list)
        h3("Explicitly Excluded Features (Protected Attributes)")
        bullet(self.explicitly_excluded_features)

        # --- Section 5: Performance ---
        h2("5. Performance Metrics")
        h3("Overall Performance")
        for metric, value in self.overall_metrics.items():
            lines.append(f"- **{metric}**: {value:.4f}")
        lines.append("")
        h3("Performance by Subgroup")
        lines.append("| Slice | N | Metric | Value | Baseline | Ratio | Flagged |")
        lines.append("|-------|---|--------|-------|----------|-------|---------|")
        for sl in self.performance_slices:
            flag_str = "YES" if sl.flagged else "no"
            lines.append(
                f"| {sl.slice_name} | {sl.n_samples:,} | {sl.metric_name} "
                f"| {sl.metric_value:.3f} | {sl.baseline_value:.3f} "
                f"| {sl.disparity_ratio:.2f} | {flag_str} |"
            )

        # --- Section 6: Fairness ---
        h2("6. Ethics and Fairness")
        kv("Bias Audit Passed", "Yes" if self.bias_audit_passed else "No")
        if self.bias_audit_date:
            kv("Bias Audit Date", str(self.bias_audit_date))
        if self.bias_auditor:
            kv("Bias Auditor", self.bias_auditor)
        if self.bias_audit_report_location:
            kv("Bias Audit Report", self.bias_audit_report_location)
        lines.append("")
        h3("Fairness Constraints Applied")
        bullet(self.fairness_constraints)

        # --- Section 7: Governance ---
        h2("7. Governance and Approval")
        if self.approver_name:
            kv("Approved By", self.approver_name)
        if self.approver_title:
            kv("Approver Title", self.approver_title)
        if self.approval_date:
            kv("Approval Date", str(self.approval_date))
        if self.authority_to_operate:
            kv("Authority to Operate", self.authority_to_operate)

        # --- Section 8: Monitoring ---
        h2("8. Monitoring and Maintenance")
        kv("Retraining Trigger", self.retraining_trigger)
        if self.sunset_date:
            kv("Sunset Date", str(self.sunset_date))
        lines.append("")
        lines.append(textwrap.fill(self.monitoring_plan, width=100))

        # --- Section 9: Validation ---
        h2("9. Pre-Deployment Validation")
        if passed:
            lines.append("**All validation checks passed.**")
        else:
            lines.append(f"**{len(errors)} validation issue(s) require resolution:**")
            for err in errors:
                lines.append(f"- {err}")

        lines.append(f"\n---\n*Generated {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC*")

        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Section 2 — Unity Catalog governance checks
# ---------------------------------------------------------------------------


def check_unity_catalog_pii_policies(
    catalog: str,
    schema: str,
    table: str,
) -> Dict[str, Any]:
    """
    Inspect a Unity Catalog table for column masking and row-level security.

    On a live Databricks cluster this calls the information_schema views.
    The function returns a structured result you can embed in a model card
    or log to an audit table.

    Parameters
    ----------
    catalog : str
        Unity Catalog catalog name, e.g. "advana_gold"
    schema : str
        Schema name, e.g. "personnel"
    table : str
        Table name, e.g. "enlisted_records"

    Returns
    -------
    dict with keys:
        table_path          : "catalog.schema.table"
        column_masks        : list of {column, mask_function}
        row_filters         : list of {filter_name, filter_function}
        owner               : table owner
        pii_tag_columns     : columns tagged with PII system tag
        classification_tag  : data classification tag value
        lineage_upstream    : list of upstream table names
        policy_compliant    : bool
        issues              : list of compliance issues found
    """
    result: Dict[str, Any] = {
        "table_path": f"{catalog}.{schema}.{table}",
        "column_masks": [],
        "row_filters": [],
        "owner": None,
        "pii_tag_columns": [],
        "classification_tag": None,
        "lineage_upstream": [],
        "policy_compliant": False,
        "issues": [],
    }

    # --- Real implementation on Databricks ---
    # Uncomment and run inside a Databricks notebook or cluster job.
    #
    # from pyspark.sql import SparkSession
    # spark = SparkSession.getActiveSession()
    #
    # # Column masks
    # masks_df = spark.sql(f"""
    #     SELECT column_name, mask_function_name
    #     FROM   {catalog}.information_schema.column_masks
    #     WHERE  table_catalog = '{catalog}'
    #       AND  table_schema  = '{schema}'
    #       AND  table_name    = '{table}'
    # """)
    # result["column_masks"] = [row.asDict() for row in masks_df.collect()]
    #
    # # Row filters
    # filters_df = spark.sql(f"""
    #     SELECT filter_name, filter_function_name
    #     FROM   {catalog}.information_schema.row_filters
    #     WHERE  table_catalog = '{catalog}'
    #       AND  table_schema  = '{schema}'
    #       AND  table_name    = '{table}'
    # """)
    # result["row_filters"] = [row.asDict() for row in filters_df.collect()]
    #
    # # Tags (PII and classification)
    # tags_df = spark.sql(f"""
    #     SELECT tag_name, tag_value, column_name
    #     FROM   {catalog}.information_schema.tags
    #     WHERE  table_catalog = '{catalog}'
    #       AND  table_schema  = '{schema}'
    #       AND  table_name    = '{table}'
    # """)
    # for row in tags_df.collect():
    #     if row.tag_name == "pii":
    #         result["pii_tag_columns"].append(row.column_name)
    #     if row.tag_name == "classification":
    #         result["classification_tag"] = row.tag_value
    #
    # # Owner
    # detail = spark.sql(f"DESCRIBE DETAIL {catalog}.{schema}.{table}").collect()[0]
    # result["owner"] = detail.owner
    #
    # # Lineage (requires Unity Catalog lineage enabled)
    # from databricks.sdk import WorkspaceClient
    # w = WorkspaceClient()
    # lineage = w.lineage_tracking.get_table_lineage(table_name=f"{catalog}.{schema}.{table}")
    # result["lineage_upstream"] = [t.name for t in lineage.upstreams or []]

    # --- Compliance checks ---
    # (These run against the populated result dict in live usage)
    pii_columns_without_masks = [
        col for col in result["pii_tag_columns"]
        if col not in [m.get("column_name") for m in result["column_masks"]]
    ]
    if pii_columns_without_masks:
        result["issues"].append(
            f"PII columns without column masks: {pii_columns_without_masks}"
        )

    if not result["row_filters"] and schema == "personnel":
        result["issues"].append(
            "Personnel schema table has no row-level security filters — "
            "verify that need-to-know access control is enforced upstream"
        )

    if result["classification_tag"] is None:
        result["issues"].append("No classification tag found — tag required before MLflow logging")

    result["policy_compliant"] = len(result["issues"]) == 0
    return result


def verify_lineage_chain(
    upstream_tables: List[str],
    expected_bronze_prefix: str = "bronze_",
) -> Dict[str, Any]:
    """
    Verify that a model's upstream lineage traces to approved Bronze sources.

    Federal data governance requires that production models consume data from
    governed Delta tables (Bronze/Silver/Gold tiers on Jupiter, or equivalent
    canonical datasets on Foundry).  A training pipeline that pulls from an
    ad-hoc notebook export or a personal scratch schema is a governance gap.

    Parameters
    ----------
    upstream_tables : list of str
        Fully-qualified table names returned by Unity Catalog lineage.
    expected_bronze_prefix : str
        Naming convention prefix for approved source tables.

    Returns
    -------
    dict with compliance summary.
    """
    unrecognized = []
    recognized = []

    for table in upstream_tables:
        parts = table.split(".")
        table_name = parts[-1] if parts else table
        schema_name = parts[-2] if len(parts) >= 2 else ""

        # Heuristic: Bronze-tier tables start with bronze_ or live in a bronze schema
        if table_name.startswith(expected_bronze_prefix) or "bronze" in schema_name:
            recognized.append(table)
        elif "silver" in schema_name or "gold" in schema_name:
            recognized.append(table)  # derived from governed tier — acceptable
        else:
            unrecognized.append(table)

    return {
        "recognized_tables": recognized,
        "unrecognized_tables": unrecognized,
        "lineage_clean": len(unrecognized) == 0,
        "issues": [
            f"Unrecognized upstream table: {t} — verify it is a governed data product"
            for t in unrecognized
        ],
    }


# ---------------------------------------------------------------------------
# Section 3 — Demo: building a model card for the attrition model
# ---------------------------------------------------------------------------


def build_attrition_model_card() -> ModelCard:
    """
    Construct a ModelCard for the Navy enlisted attrition classifier.

    This mirrors the scenario from Chapter 12's opening vignette — Dr. Okafor's
    model that was found to have disparate impact after eleven months in production.
    The card documents the remediated version after bias mitigation.
    """
    training_source = DataSource(
        name="Navy DCPDS Personnel Extract — FY19-FY22",
        platform="Unity Catalog",
        catalog="advana_silver",
        schema="personnel",
        table="navy_enlisted_fy19_fy22",
        pii_classified=True,
        classification_level="UNCLASSIFIED//FOUO",
        record_count_approx=180_000,
        date_range_start=date(2019, 10, 1),
        date_range_end=date(2022, 9, 30),
        lineage_verified=True,
    )

    eval_source = DataSource(
        name="Navy DCPDS Personnel Extract — FY23",
        platform="Unity Catalog",
        catalog="advana_silver",
        schema="personnel",
        table="navy_enlisted_fy23",
        pii_classified=True,
        classification_level="UNCLASSIFIED//FOUO",
        record_count_approx=45_000,
        date_range_start=date(2022, 10, 1),
        date_range_end=date(2023, 9, 30),
        lineage_verified=True,
    )

    performance_slices = [
        ModelPerformanceSlice("overall", 45_000, "AUC", 0.823, 0.823, flagged=False),
        ModelPerformanceSlice("pay_grade_E1_E4", 18_200, "AUC", 0.801, 0.823, flagged=False),
        ModelPerformanceSlice("pay_grade_E5_E9", 26_800, "AUC", 0.841, 0.823, flagged=False),
        ModelPerformanceSlice("race_White", 28_000, "FPR", 0.112, 0.115, flagged=False),
        ModelPerformanceSlice("race_Black", 7_200, "FPR", 0.128, 0.115, flagged=False),
        ModelPerformanceSlice("race_Hispanic", 5_400, "FPR", 0.121, 0.115, flagged=False),
        ModelPerformanceSlice("gender_Male", 37_000, "FPR", 0.113, 0.115, flagged=False),
        ModelPerformanceSlice("gender_Female", 8_000, "FPR", 0.119, 0.115, flagged=False),
    ]

    card = ModelCard(
        model_name="Navy Enlisted Attrition Predictor",
        model_version="2.1.0",
        created_date=date(2024, 3, 15),
        last_updated=date(2024, 6, 1),
        authors=["Dr. Sarah Okafor", "LT James Reyes", "GS-13 Priya Mehta"],
        organization="OPNAV N13 / Navy People Analytics",
        point_of_contact="sarah.okafor@navy.mil",

        intended_use=(
            "Predict within-12-month voluntary attrition risk for active-duty Navy enlisted "
            "personnel (E1-E9) to support retention counseling prioritization. "
            "Output is a risk score (0–1); commands use the score to schedule retention interviews, "
            "not to make involuntary separation decisions."
        ),
        use_category=UseCategory.HUMAN_RESOURCE,
        risk_tier=RiskTier.HIGH,
        out_of_scope_uses=[
            "Involuntary separation or reduction-in-force decisions",
            "Performance evaluation or promotion recommendations",
            "Application to officers (O-1 through O-10) — model was not trained on officer data",
            "Prediction horizons beyond 18 months",
            "Use outside the Navy (other service branches have different attrition dynamics)",
        ],

        training_data_sources=[training_source],
        evaluation_data_sources=[eval_source],
        preprocessing_steps=[
            "Remove PII identifiers (SSN, name, DOB) before feature engineering",
            "Encode race and gender as control variables for fairness auditing only — not included as model features",
            "Impute missing duty_station with most-frequent value by NEC code",
            "Log-transform continuous skewed features: years_in_service, deployment_days_ytd",
            "OrdinalEncode pay_grade (E1=1 ... E9=9)",
            "Temporal train/eval split: train FY19-FY22, evaluate FY23 to prevent data leakage",
        ],

        model_type="Gradient Boosting Classifier (scikit-learn GradientBoostingClassifier)",
        framework="scikit-learn 1.3.2 / Databricks ML Runtime 14.3 LTS",
        hyperparameters={
            "n_estimators": 400,
            "learning_rate": 0.05,
            "max_depth": 4,
            "min_samples_leaf": 50,
            "subsample": 0.8,
            "max_features": "sqrt",
        },
        feature_list=[
            "pay_grade_ordinal",
            "years_in_service",
            "mos_at_current_duty_station",
            "deployment_days_ytd",
            "reenlistment_eligible_flag",
            "nec_code_encoded",
            "prior_attrition_rate_by_nec",
            "family_separation_days_ytd",
            "pcs_moves_count",
        ],
        explicitly_excluded_features=[
            "race",
            "ethnicity",
            "gender",
            "religion",
            "national_origin",
            "ssn",
            "name",
            "dob",
        ],

        overall_metrics={
            "AUC": 0.823,
            "Average_Precision": 0.612,
            "F1_at_threshold_0.35": 0.581,
            "Brier_Score": 0.148,
        },
        performance_slices=performance_slices,

        fairness_constraints=[
            "4/5ths rule: flag rate for any racial/gender subgroup must be ≥80% of highest-flag-rate group",
            "Equalized FPR: false positive rate for any subgroup must be within ±3 percentage points of overall rate",
            "Threshold calibrated separately by pay-grade band to equalize FPR across E1-E4 and E5-E9",
        ],
        bias_audit_passed=True,
        bias_audit_date=date(2024, 5, 20),
        bias_auditor="OPNAV N13 RAI Assessment Team",
        bias_audit_report_location="sharepoint.navy.mil/sites/N13Analytics/ModelAudits/AttritionV2_BiasAudit.docx",

        approver_name="RDML Dana Whitfield",
        approver_title="Deputy Chief of Naval Personnel for Analytics",
        approval_date=date(2024, 6, 1),
        authority_to_operate="ATO-N13-2024-0042",
        mlflow_run_id="a3f8c2e1d4b7901f",
        mlflow_model_version=12,

        monitoring_plan=(
            "Weekly batch job checks flag rate by racial and gender subgroup against FY23 baseline. "
            "Alert if any group's flag rate drifts more than 5 percentage points. "
            "Quarterly manual review by N13 RAI team. "
            "Automated MLflow metric logging to advana_gold.ml_monitoring.attrition_drift."
        ),
        retraining_trigger=(
            "Retrain when: (1) AUC on rolling 90-day holdout drops below 0.78, "
            "(2) any subgroup FPR ratio exceeds 1.3x baseline, or "
            "(3) annual fiscal year boundary (scheduled for October each year)."
        ),
        sunset_date=date(2025, 9, 30),
    )

    return card


def run_model_card_demo() -> None:
    """
    Build the attrition model card, validate it, and print the Markdown.
    """
    print("=" * 70)
    print("MODEL CARD DEMO — Navy Enlisted Attrition Predictor v2.1.0")
    print("=" * 70)

    card = build_attrition_model_card()

    passed, errors = card.validate()
    print(f"\nValidation: {'PASSED' if passed else 'FAILED'}")
    if errors:
        for err in errors:
            print(f"  ERROR: {err}")
    else:
        print("  All pre-deployment checks passed.")

    print("\n" + "─" * 70)
    print("GENERATED MARKDOWN (first 60 lines):")
    print("─" * 70)
    md = card.to_markdown()
    lines = md.split("\n")
    for line in lines[:60]:
        print(line)
    if len(lines) > 60:
        print(f"  ... ({len(lines) - 60} more lines) ...")

    print("\n" + "─" * 70)
    print("UNITY CATALOG GOVERNANCE CHECK (simulated):")
    print("─" * 70)
    uc_result = check_unity_catalog_pii_policies(
        catalog="advana_silver",
        schema="personnel",
        table="navy_enlisted_fy23",
    )
    # In local demo, no Spark session — show structure
    print(f"  Table: {uc_result['table_path']}")
    print(f"  Policy compliant: {uc_result['policy_compliant']}")
    print(f"  Issues: {uc_result['issues'] or 'none'}")

    print("\n" + "─" * 70)
    print("LINEAGE CHAIN VERIFICATION:")
    print("─" * 70)
    # Simulated upstream tables returned by Unity Catalog lineage API
    upstream = [
        "advana_bronze.personnel.dcpds_raw_extract",
        "advana_silver.reference.nec_codes",
        "analyst_scratch.jsmith.temp_attrition_features",   # non-governed — should flag
    ]
    lineage_result = verify_lineage_chain(upstream)
    print(f"  Lineage clean: {lineage_result['lineage_clean']}")
    for issue in lineage_result["issues"]:
        print(f"  WARNING: {issue}")
    if lineage_result["lineage_clean"]:
        print("  All upstream tables trace to governed data products.")


if __name__ == "__main__":
    run_model_card_demo()
