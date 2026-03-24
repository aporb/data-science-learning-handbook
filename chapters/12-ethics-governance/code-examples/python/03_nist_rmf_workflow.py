"""
Chapter 12: Ethics, Governance, and Compliance
Code Example 03 — NIST AI RMF Workflow and Audit Logging

Demonstrates:
- Structured GOVERN/MAP/MEASURE/MANAGE documentation
- Automated measurement collection for NIST AI RMF MEASURE function
- Audit event logging to a Delta table (Unity Catalog)
- Drift detection triggering MANAGE-phase response actions
- Risk register pattern for tracking open AI risks

This file is designed to run locally (no Spark cluster required) using
simulated data, while comments show the Databricks/Foundry production path.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import asdict, dataclass, field
from datetime import date, datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import pandas as pd


# ---------------------------------------------------------------------------
# Section 1 — GOVERN: risk context and policy documentation
# ---------------------------------------------------------------------------


class RMFFunction(str, Enum):
    """NIST AI RMF core functions."""
    GOVERN = "GOVERN"
    MAP = "MAP"
    MEASURE = "MEASURE"
    MANAGE = "MANAGE"


class RiskLikelihood(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    VERY_HIGH = "very_high"


class RiskImpact(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RiskStatus(str, Enum):
    OPEN = "open"
    IN_MITIGATION = "in_mitigation"
    ACCEPTED = "accepted"
    CLOSED = "closed"


@dataclass
class AIRisk:
    """
    A single entry in the AI Risk Register.

    The risk register is the central artifact of the GOVERN function.
    Each risk gets a unique ID, an owner, a severity rating, a mitigation
    plan, and a current status.  You review this register in the quarterly
    RAI assessment and update it before any model promotion.
    """
    risk_id: str
    title: str
    description: str
    rmf_function: RMFFunction
    likelihood: RiskLikelihood
    impact: RiskImpact
    status: RiskStatus
    owner: str
    mitigation_plan: str
    residual_likelihood: Optional[RiskLikelihood] = None
    residual_impact: Optional[RiskImpact] = None
    created_date: date = field(default_factory=date.today)
    last_reviewed: Optional[date] = None
    review_notes: str = ""

    # Severity score: likelihood * impact on a 1-4 scale
    _SEVERITY_MAP = {
        RiskLikelihood.LOW: 1, RiskLikelihood.MEDIUM: 2,
        RiskLikelihood.HIGH: 3, RiskLikelihood.VERY_HIGH: 4,
    }
    _IMPACT_MAP = {
        RiskImpact.LOW: 1, RiskImpact.MEDIUM: 2,
        RiskImpact.HIGH: 3, RiskImpact.CRITICAL: 4,
    }

    @property
    def severity_score(self) -> int:
        return self._SEVERITY_MAP[self.likelihood] * self._IMPACT_MAP[self.impact]

    @property
    def severity_label(self) -> str:
        s = self.severity_score
        if s <= 2:
            return "LOW"
        if s <= 6:
            return "MEDIUM"
        if s <= 9:
            return "HIGH"
        return "CRITICAL"


def build_attrition_risk_register() -> List[AIRisk]:
    """
    Construct a risk register for the Navy enlisted attrition model.

    A real risk register lives in a shared system of record — Confluence,
    SharePoint, or a Foundry dataset.  This function shows the structure
    for the attrition model scenario from Chapter 12.
    """
    return [
        AIRisk(
            risk_id="RISK-001",
            title="Proxy discrimination via correlated features",
            description=(
                "Features like 'pcs_moves_count' and 'family_separation_days_ytd' may "
                "correlate with race/ethnicity at the unit level due to historical "
                "assignment patterns, producing disparate outcomes even without direct "
                "protected-attribute inputs."
            ),
            rmf_function=RMFFunction.MAP,
            likelihood=RiskLikelihood.MEDIUM,
            impact=RiskImpact.HIGH,
            status=RiskStatus.IN_MITIGATION,
            owner="sarah.okafor@navy.mil",
            mitigation_plan=(
                "Quarterly proxy correlation scan (Cramér's V, point-biserial) on all "
                "features vs. race/gender.  Remove any feature with |correlation| > 0.25 "
                "that lacks a compelling operational justification."
            ),
            residual_likelihood=RiskLikelihood.LOW,
            residual_impact=RiskImpact.MEDIUM,
            last_reviewed=date(2024, 5, 20),
        ),
        AIRisk(
            risk_id="RISK-002",
            title="Model score used for involuntary separation",
            description=(
                "The model is designed to trigger retention counseling.  Misuse by "
                "a command as justification for adverse administrative action is a "
                "use-category violation and potential Title VII / DoD Directive exposure."
            ),
            rmf_function=RMFFunction.GOVERN,
            likelihood=RiskLikelihood.MEDIUM,
            impact=RiskImpact.CRITICAL,
            status=RiskStatus.IN_MITIGATION,
            owner="rdml.whitfield@navy.mil",
            mitigation_plan=(
                "Out-of-scope use explicitly documented in model card. "
                "Annual training for command career counselors on permissible use. "
                "Row-level security prevents access to raw scores by O-6 and below "
                "without retention counselor role."
            ),
            last_reviewed=date(2024, 6, 1),
        ),
        AIRisk(
            risk_id="RISK-003",
            title="Concept drift after force structure change",
            description=(
                "A major force structure realignment (e.g., end-strength reduction, "
                "new deployment patterns) will shift the attrition distribution in ways "
                "the model has not seen, causing precision/recall degradation."
            ),
            rmf_function=RMFFunction.MANAGE,
            likelihood=RiskLikelihood.LOW,
            impact=RiskImpact.HIGH,
            status=RiskStatus.OPEN,
            owner="lt.reyes@navy.mil",
            mitigation_plan=(
                "Automated weekly drift monitoring.  If flag-rate shift > 5pp "
                "or AUC on holdout < 0.78, alert triggers and model is quarantined "
                "pending analyst review.  Emergency retrain path documented in runbook."
            ),
        ),
        AIRisk(
            risk_id="RISK-004",
            title="Training data reflects historical systemic bias",
            description=(
                "FY19-FY22 attrition outcomes reflect commands that may have had "
                "unequal retention support by demographic group.  The model may learn "
                "to predict who historically left rather than who is at genuine risk."
            ),
            rmf_function=RMFFunction.MAP,
            likelihood=RiskLikelihood.HIGH,
            impact=RiskImpact.HIGH,
            status=RiskStatus.IN_MITIGATION,
            owner="sarah.okafor@navy.mil",
            mitigation_plan=(
                "Per-group threshold calibration equalizes FPR across racial groups. "
                "SHAP analysis confirms top features are operationally justified "
                "(years_in_service, reenlistment_eligible_flag, deployment_days). "
                "Annual review of label quality (were outcomes influenced by unequal access?)."
            ),
            residual_likelihood=RiskLikelihood.MEDIUM,
            residual_impact=RiskImpact.MEDIUM,
            last_reviewed=date(2024, 5, 20),
        ),
    ]


# ---------------------------------------------------------------------------
# Section 2 — MEASURE: automated metrics collection
# ---------------------------------------------------------------------------


@dataclass
class MeasurementRecord:
    """
    A single measurement taken during the NIST AI RMF MEASURE function.

    Logged to an audit table after each batch scoring run.
    """
    record_id: str
    model_name: str
    model_version: str
    measurement_date: datetime
    metric_category: str       # "fairness", "performance", "drift", "data_quality"
    metric_name: str
    metric_value: float
    threshold: Optional[float]
    passed: bool
    group_name: Optional[str]  # None for aggregate metrics
    notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["measurement_date"] = self.measurement_date.isoformat()
        return d


def collect_rmf_measurements(
    y_true: np.ndarray,
    y_pred_proba: np.ndarray,
    group_labels: pd.Series,
    threshold: float,
    model_name: str = "navy_attrition_v2",
    model_version: str = "2.1.0",
) -> Tuple[List[MeasurementRecord], bool]:
    """
    Collect all NIST AI RMF MEASURE function metrics in one pass.

    Combines performance metrics, fairness metrics, and calibration checks
    into a list of MeasurementRecord objects that can be:
      1. Written to an audit Delta table
      2. Included in the quarterly RAI assessment report
      3. Compared against the previous run to detect drift

    Parameters
    ----------
    y_true       : ground-truth binary labels (1 = attrited)
    y_pred_proba : model probability scores
    group_labels : demographic group per record (e.g., race)
    threshold    : classification threshold for binary predictions
    model_name   : name logged in MLflow / Unity Catalog
    model_version: version string

    Returns
    -------
    (records, all_passed) — list of measurements, bool for overall gate
    """
    from sklearn.metrics import (
        average_precision_score,
        brier_score_loss,
        roc_auc_score,
    )

    records: List[MeasurementRecord] = []
    now = datetime.utcnow()
    all_passed = True

    def add(
        category: str,
        name: str,
        value: float,
        threshold_val: Optional[float],
        pass_condition: bool,
        group: Optional[str] = None,
        notes: str = "",
    ) -> None:
        nonlocal all_passed
        if not pass_condition:
            all_passed = False
        records.append(MeasurementRecord(
            record_id=str(uuid.uuid4()),
            model_name=model_name,
            model_version=model_version,
            measurement_date=now,
            metric_category=category,
            metric_name=name,
            metric_value=round(float(value), 6),
            threshold=threshold_val,
            passed=pass_condition,
            group_name=group,
            notes=notes,
        ))

    y_pred = (y_pred_proba >= threshold).astype(int)

    # --- Overall performance ---
    auc = roc_auc_score(y_true, y_pred_proba)
    ap = average_precision_score(y_true, y_pred_proba)
    brier = brier_score_loss(y_true, y_pred_proba)
    add("performance", "AUC", auc, 0.78, auc >= 0.78)
    add("performance", "Average_Precision", ap, 0.55, ap >= 0.55)
    add("performance", "Brier_Score", brier, 0.18, brier <= 0.18,
        notes="lower is better")

    # --- Fairness by group ---
    groups = group_labels.unique()
    fp_rates = {}
    flag_rates = {}

    for g in groups:
        mask = group_labels == g
        n = mask.sum()
        if n < 30:
            continue  # skip groups too small for reliable metrics

        gt = y_true[mask]
        pp = y_pred_proba[mask]
        pred = y_pred[mask]

        g_auc = roc_auc_score(gt, pp) if len(np.unique(gt)) == 2 else float("nan")
        if not np.isnan(g_auc):
            add("fairness", "AUC", g_auc, None, True, group=str(g))

        tn = ((pred == 0) & (gt == 0)).sum()
        fp = ((pred == 1) & (gt == 0)).sum()
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        fp_rates[g] = fpr
        add("fairness", "FPR", fpr, None, True, group=str(g))

        flag_rate = pred.mean()
        flag_rates[g] = flag_rate
        add("fairness", "flag_rate", flag_rate, None, True, group=str(g))

    # Demographic parity (4/5ths rule on flag rates)
    if flag_rates:
        max_rate = max(flag_rates.values())
        for g, rate in flag_rates.items():
            ratio = rate / max_rate if max_rate > 0 else 1.0
            passed = ratio >= 0.80
            add("fairness", "demographic_parity_ratio", ratio, 0.80, passed,
                group=str(g),
                notes=f"flag_rate={rate:.3f}, max_group_rate={max_rate:.3f}")

    # FPR equalization (within 3 pp of overall)
    if fp_rates:
        overall_fpr = np.array(list(fp_rates.values())).mean()
        for g, fpr in fp_rates.items():
            diff = abs(fpr - overall_fpr)
            passed = diff <= 0.03
            add("fairness", "FPR_deviation_from_overall", diff, 0.03, passed,
                group=str(g),
                notes=f"group_fpr={fpr:.3f}, overall_fpr={overall_fpr:.3f}")

    return records, all_passed


# ---------------------------------------------------------------------------
# Section 3 — Audit event logging
# ---------------------------------------------------------------------------


@dataclass
class AuditEvent:
    """
    Immutable audit log entry for AI system actions.

    Federal systems need an audit trail for every consequential action:
    model promotion, batch scoring runs, bias audit results, threshold
    changes, and human-override decisions.  Writing these to a governed
    Delta table gives you the append-only log that survives notebook
    restarts, provides lineage for future investigations, and satisfies
    NIST AI RMF GOVERN traceability requirements.
    """
    event_id: str
    event_type: str        # "batch_score", "model_promote", "bias_audit", "threshold_change"
    event_timestamp: datetime
    actor: str             # email or service account
    model_name: str
    model_version: str
    payload: Dict[str, Any]
    outcome: str           # "success", "failure", "warning"
    notes: str = ""

    # SHA-256 hash of the payload for tamper-detection
    payload_hash: str = field(init=False)

    def __post_init__(self) -> None:
        payload_bytes = json.dumps(self.payload, sort_keys=True, default=str).encode()
        self.payload_hash = hashlib.sha256(payload_bytes).hexdigest()[:16]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "event_type": self.event_type,
            "event_timestamp": self.event_timestamp.isoformat(),
            "actor": self.actor,
            "model_name": self.model_name,
            "model_version": self.model_version,
            "payload": json.dumps(self.payload, default=str),
            "outcome": self.outcome,
            "notes": self.notes,
            "payload_hash": self.payload_hash,
        }


class AuditLogger:
    """
    Write audit events to a Delta table (or local buffer in dev mode).

    In production on Databricks, call `flush_to_delta()` after accumulating
    events in a batch scoring job.  In local development or Foundry, the
    buffer lets you inspect events without a running cluster.
    """

    def __init__(
        self,
        delta_table_path: Optional[str] = None,
        dev_mode: bool = True,
    ) -> None:
        """
        Parameters
        ----------
        delta_table_path : str, optional
            Unity Catalog path, e.g. "advana_gold.ml_governance.audit_log"
        dev_mode : bool
            When True, accumulates events in memory instead of writing to Delta.
        """
        self.delta_table_path = delta_table_path
        self.dev_mode = dev_mode
        self._buffer: List[AuditEvent] = []

    def log(
        self,
        event_type: str,
        actor: str,
        model_name: str,
        model_version: str,
        payload: Dict[str, Any],
        outcome: str = "success",
        notes: str = "",
    ) -> AuditEvent:
        """Create and store a single audit event."""
        event = AuditEvent(
            event_id=str(uuid.uuid4()),
            event_type=event_type,
            event_timestamp=datetime.utcnow(),
            actor=actor,
            model_name=model_name,
            model_version=model_version,
            payload=payload,
            outcome=outcome,
            notes=notes,
        )
        self._buffer.append(event)

        if not self.dev_mode:
            self._write_single_to_delta(event)

        return event

    def _write_single_to_delta(self, event: AuditEvent) -> None:
        """
        Append one event to the Unity Catalog audit Delta table.

        Requires an active SparkSession and appropriate Unity Catalog permissions.
        The table schema must match AuditEvent.to_dict() keys.
        """
        # Production implementation:
        #
        # from pyspark.sql import SparkSession
        # spark = SparkSession.getActiveSession()
        # row = event.to_dict()
        # df = spark.createDataFrame([row])
        # (df.write
        #    .format("delta")
        #    .mode("append")
        #    .option("mergeSchema", "false")
        #    .saveAsTable(self.delta_table_path))
        pass

    def flush_to_delta(self) -> int:
        """
        Write all buffered events to Delta in a single batch append.

        More efficient than _write_single_to_delta for end-of-job flushing.
        Returns the count of events written.
        """
        if not self._buffer:
            return 0

        # Production implementation:
        #
        # from pyspark.sql import SparkSession
        # spark = SparkSession.getActiveSession()
        # rows = [e.to_dict() for e in self._buffer]
        # df = spark.createDataFrame(rows)
        # (df.write
        #    .format("delta")
        #    .mode("append")
        #    .saveAsTable(self.delta_table_path))
        # count = len(self._buffer)
        # self._buffer.clear()
        # return count

        count = len(self._buffer)
        self._buffer.clear()
        return count

    def get_buffer_as_dataframe(self) -> pd.DataFrame:
        """Return buffered events as a pandas DataFrame for local inspection."""
        if not self._buffer:
            return pd.DataFrame()
        return pd.DataFrame([e.to_dict() for e in self._buffer])

    def summary(self) -> None:
        """Print a summary of buffered audit events."""
        df = self.get_buffer_as_dataframe()
        if df.empty:
            print("Audit buffer is empty.")
            return
        print(f"\nAudit Log Buffer ({len(df)} events)")
        print("─" * 50)
        for _, row in df.iterrows():
            ts = row["event_timestamp"][:19]
            print(f"  [{ts}] {row['event_type']:<20} {row['outcome']:<10} {row['actor']}")


# ---------------------------------------------------------------------------
# Section 4 — MANAGE: drift detection and response
# ---------------------------------------------------------------------------


def detect_prediction_drift(
    current_scores: np.ndarray,
    baseline_scores: np.ndarray,
    threshold: float,
    drift_thresholds: Optional[Dict[str, float]] = None,
) -> Dict[str, Any]:
    """
    Detect distribution drift in model prediction scores.

    Compares a current scoring window against a baseline (e.g., the FY23
    evaluation set) using population stability index (PSI) and flag-rate
    comparison.  PSI is the industry-standard metric for model deployment
    monitoring: PSI < 0.1 means no meaningful change, 0.1–0.25 is a
    moderate shift requiring investigation, > 0.25 signals major drift.

    Parameters
    ----------
    current_scores  : probability scores from the current scoring window
    baseline_scores : probability scores from the approved baseline period
    threshold       : the classification threshold in use
    drift_thresholds: override PSI/flag-rate thresholds if needed

    Returns
    -------
    dict with drift metrics and recommended actions.
    """
    if drift_thresholds is None:
        drift_thresholds = {
            "psi_warning": 0.10,
            "psi_critical": 0.25,
            "flag_rate_max_delta_pp": 0.05,  # 5 percentage points
        }

    # Compute PSI
    def _compute_psi(current: np.ndarray, baseline: np.ndarray, n_bins: int = 10) -> float:
        bins = np.percentile(baseline, np.linspace(0, 100, n_bins + 1))
        bins[0] = 0.0
        bins[-1] = 1.0 + 1e-6
        current_counts = np.histogram(current, bins=bins)[0]
        baseline_counts = np.histogram(baseline, bins=bins)[0]
        # Avoid division by zero and log(0)
        current_pct = np.maximum(current_counts / len(current), 1e-6)
        baseline_pct = np.maximum(baseline_counts / len(baseline), 1e-6)
        psi = np.sum((current_pct - baseline_pct) * np.log(current_pct / baseline_pct))
        return float(psi)

    psi = _compute_psi(current_scores, baseline_scores)

    current_flag_rate = (current_scores >= threshold).mean()
    baseline_flag_rate = (baseline_scores >= threshold).mean()
    flag_rate_delta = abs(current_flag_rate - baseline_flag_rate)

    # Determine severity
    if psi > drift_thresholds["psi_critical"]:
        psi_severity = "CRITICAL"
    elif psi > drift_thresholds["psi_warning"]:
        psi_severity = "WARNING"
    else:
        psi_severity = "OK"

    flag_rate_ok = flag_rate_delta <= drift_thresholds["flag_rate_max_delta_pp"]

    # Recommended action
    if psi_severity == "CRITICAL" or not flag_rate_ok:
        action = "QUARANTINE — halt batch scoring, notify model owner, begin retraining assessment"
    elif psi_severity == "WARNING":
        action = "INVESTIGATE — analyst review required within 5 business days"
    else:
        action = "MONITOR — continue regular schedule"

    return {
        "psi": round(psi, 4),
        "psi_severity": psi_severity,
        "current_flag_rate": round(float(current_flag_rate), 4),
        "baseline_flag_rate": round(float(baseline_flag_rate), 4),
        "flag_rate_delta_pp": round(float(flag_rate_delta * 100), 2),
        "flag_rate_ok": flag_rate_ok,
        "recommended_action": action,
        "drift_detected": psi_severity != "OK" or not flag_rate_ok,
    }


# ---------------------------------------------------------------------------
# Section 5 — End-to-end demo
# ---------------------------------------------------------------------------


def run_rmf_workflow_demo() -> None:
    """
    Demonstrate a complete NIST AI RMF MEASURE + MANAGE cycle.

    Uses synthetic data to show what the workflow looks like at the end
    of a batch scoring job: collect measurements, log audit events, check
    for drift, and take the appropriate MANAGE action.
    """
    rng = np.random.default_rng(42)
    n = 2_000

    # Synthetic ground truth and scores
    y_true = rng.integers(0, 2, size=n)
    # Scores that are reasonably calibrated
    y_pred_proba = np.clip(
        y_true * 0.6 + rng.normal(0.2, 0.15, size=n),
        0.01, 0.99
    )

    # Synthetic group labels — four racial categories
    groups = rng.choice(["White", "Black", "Hispanic", "Asian/PI"],
                        size=n, p=[0.62, 0.16, 0.13, 0.09])
    group_series = pd.Series(groups)

    threshold = 0.35
    audit_logger = AuditLogger(dev_mode=True)

    # --- MEASURE ---
    print("=" * 70)
    print("NIST AI RMF WORKFLOW DEMO")
    print("=" * 70)
    print("\n[MEASURE] Collecting metrics for batch scoring run...")

    records, all_passed = collect_rmf_measurements(
        y_true=y_true,
        y_pred_proba=y_pred_proba,
        group_labels=group_series,
        threshold=threshold,
    )

    # Summarize
    categories = {}
    for r in records:
        categories.setdefault(r.metric_category, {"total": 0, "failed": 0})
        categories[r.metric_category]["total"] += 1
        if not r.passed:
            categories[r.metric_category]["failed"] += 1

    for cat, counts in categories.items():
        status = "PASS" if counts["failed"] == 0 else f"FAIL ({counts['failed']} issues)"
        print(f"  {cat:<15} {counts['total']:>3} metrics  |  {status}")

    print(f"\n  Overall gate: {'PASSED' if all_passed else 'FAILED'}")

    # Log measurement event
    audit_logger.log(
        event_type="rmf_measurement",
        actor="batch-scoring-svc@advana.mil",
        model_name="navy_attrition_v2",
        model_version="2.1.0",
        payload={
            "n_records_scored": n,
            "threshold": threshold,
            "metrics_collected": len(records),
            "all_passed": all_passed,
        },
        outcome="success" if all_passed else "warning",
    )

    # --- MANAGE: drift check ---
    print("\n[MANAGE] Checking for prediction drift...")

    # Baseline: slightly different distribution to simulate a healthy system
    baseline_scores = np.clip(
        y_true * 0.6 + rng.normal(0.2, 0.14, size=n),
        0.01, 0.99
    )
    drift_result = detect_prediction_drift(
        current_scores=y_pred_proba,
        baseline_scores=baseline_scores,
        threshold=threshold,
    )

    print(f"  PSI:                {drift_result['psi']:.4f}  ({drift_result['psi_severity']})")
    print(f"  Current flag rate:  {drift_result['current_flag_rate']:.3f}")
    print(f"  Baseline flag rate: {drift_result['baseline_flag_rate']:.3f}")
    print(f"  Flag rate delta:    {drift_result['flag_rate_delta_pp']:.2f} pp")
    print(f"  Action:             {drift_result['recommended_action']}")

    # Log drift check
    audit_logger.log(
        event_type="drift_check",
        actor="batch-scoring-svc@advana.mil",
        model_name="navy_attrition_v2",
        model_version="2.1.0",
        payload=drift_result,
        outcome="success" if not drift_result["drift_detected"] else "warning",
        notes="Weekly drift check — automated",
    )

    # --- GOVERN: risk register summary ---
    print("\n[GOVERN] Risk register summary...")
    risks = build_attrition_risk_register()
    for risk in sorted(risks, key=lambda r: -r.severity_score):
        print(f"  {risk.risk_id}  {risk.severity_label:<8}  {risk.status.value:<15}  {risk.title}")

    # --- Audit log ---
    print("\n[AUDIT LOG]")
    audit_logger.summary()

    # In production: flush to Delta
    # count = audit_logger.flush_to_delta()
    # print(f"  Flushed {count} events to advana_gold.ml_governance.audit_log")


if __name__ == "__main__":
    run_rmf_workflow_demo()
