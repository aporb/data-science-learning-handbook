"""
Chapter 08 — Deep Learning and Neural Networks
Example 04: Operational inference pipeline for DoD AI systems

Use case: Wraps any classification model for compliant operational deployment
Platform: Palantir Foundry (AIP Logic), Databricks Mosaic AI Model Serving

Key concepts:
    - Confidence threshold enforcement (DoD Directive 3000.09 compliance)
    - Mandatory audit logging for every inference
    - Human-in-the-loop routing for low-confidence predictions
    - Expected Calibration Error (ECE) computation
    - Per-class false positive rate for safety-critical classes
    - Confusion matrix and reliability diagram generation

This module is platform-agnostic. The OperationalInferencePipeline class can be:
    - Called directly in a Python service
    - Wrapped in a Palantir AIP Logic function
    - Deployed via Databricks Mosaic AI Model Serving with a custom wrapper

Dependencies: torch, numpy, scikit-learn, pandas
"""

import json
import logging
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Optional, Any

import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    roc_auc_score,
    average_precision_score,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Inference record — every prediction produces one of these
# ---------------------------------------------------------------------------

@dataclass
class InferenceRecord:
    """
    Structured record of a single model inference.
    Stored in the audit log — must capture everything needed for
    post-hoc review under DoD Directive 3000.09.
    """
    inference_id: str
    context_id: str               # External ID linking to the input (e.g., frame ID, record ID)
    model_name: str
    model_version: str
    timestamp_utc: str
    predicted_class: Optional[str]  # None if requires_human_review=True
    confidence: float
    requires_human_review: bool
    top_k_predictions: list        # List of (class_name, confidence) tuples
    human_override: Optional[str] = None
    human_reviewer_id: Optional[str] = None
    review_timestamp_utc: Optional[str] = None
    additional_context: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


# ---------------------------------------------------------------------------
# Audit logger — pluggable backend
# ---------------------------------------------------------------------------

class InMemoryAuditLogger:
    """
    Simple in-memory audit logger for testing and development.
    In production, replace with:
        - MLflow logging (Databricks): mlflow.log_dict(record.to_dict(), ...)
        - Palantir Foundry Ontology: write to DetectedObject Object Type via Actions
        - Database: INSERT into an audit table with row-level security
    """

    def __init__(self):
        self.records: list[InferenceRecord] = []

    def log(self, record: InferenceRecord) -> None:
        self.records.append(record)

    def get_all(self) -> pd.DataFrame:
        return pd.DataFrame([r.to_dict() for r in self.records])

    def get_requiring_review(self) -> pd.DataFrame:
        return self.get_all().query("requires_human_review == True")

    def record_human_override(
        self,
        inference_id: str,
        override_class: str,
        reviewer_id: str,
    ) -> bool:
        """Record a human analyst's override decision."""
        for record in self.records:
            if record.inference_id == inference_id:
                record.human_override = override_class
                record.human_reviewer_id = reviewer_id
                record.review_timestamp_utc = datetime.now(timezone.utc).isoformat()
                return True
        return False


class MLflowAuditLogger:
    """
    Production audit logger that writes inference records to MLflow.
    On Databricks, these appear in the MLflow experiment as logged artifacts.
    Use MLflow inference tables for structured query access.
    """

    def __init__(self, experiment_name: str, model_name: str):
        import mlflow
        self.mlflow = mlflow
        self.experiment_name = experiment_name
        self.model_name = model_name
        self._batch: list[dict] = []
        self._batch_size = 100  # Flush every 100 records

    def log(self, record: InferenceRecord) -> None:
        self._batch.append(record.to_dict())
        if len(self._batch) >= self._batch_size:
            self._flush()

    def _flush(self) -> None:
        if not self._batch:
            return
        with self.mlflow.start_run(
            run_name=f"inference_audit_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            nested=True
        ):
            self.mlflow.log_dict(
                {"inference_records": self._batch},
                "inference_audit.json"
            )
            self.mlflow.log_metrics({
                "n_inferences": len(self._batch),
                "pct_requiring_review": sum(
                    r["requires_human_review"] for r in self._batch
                ) / len(self._batch) * 100,
            })
        self._batch.clear()


# ---------------------------------------------------------------------------
# Operational inference pipeline
# ---------------------------------------------------------------------------

class OperationalInferencePipeline:
    """
    Wraps any PyTorch classification model with compliance requirements
    for DoD operational AI deployment.

    Enforces:
        1. Confidence threshold: below threshold → requires_human_review = True
        2. Audit logging: every inference is recorded with full probability distribution
        3. No silent failures: all exceptions are caught and logged
        4. Structured output: InferenceRecord, not raw tensors

    This class can be used in:
        - A Palantir Foundry Code Repository as a Functions backing
        - A Databricks Mosaic AI Model Serving custom wrapper
        - A standalone Python inference service

    DoD Directive 3000.09 compliance:
        - predicted_class is None for low-confidence predictions (no automated action)
        - requires_human_review flag routes to analyst queue
        - audit_logger captures every inference for post-hoc review
    """

    def __init__(
        self,
        model: nn.Module,
        class_names: list,
        model_name: str,
        model_version: str,
        confidence_threshold: float = 0.85,
        audit_logger=None,
        device: str = None,
    ):
        self.model = model
        self.class_names = class_names
        self.model_name = model_name
        self.model_version = model_version
        self.confidence_threshold = confidence_threshold
        self.audit_logger = audit_logger or InMemoryAuditLogger()
        self.device = device or ("cuda" if torch.cuda.is_available() else "cpu")
        self.model = self.model.to(self.device)
        self.model.train(False)   # Set to inference mode

        log.info(
            "OperationalInferencePipeline initialized: model=%s v%s, threshold=%.2f, device=%s",
            model_name, model_version, confidence_threshold, self.device
        )

    def predict(
        self,
        inputs: torch.Tensor,
        context_id: str,
        additional_context: dict = None,
    ) -> InferenceRecord:
        """
        Make a single prediction with mandatory confidence check and audit logging.

        Args:
            inputs: Preprocessed input tensor (batch size = 1)
            context_id: External ID linking this inference to the input source
                        (e.g., imagery frame ID, contract record ID)
            additional_context: Optional metadata to attach to the audit record

        Returns:
            InferenceRecord with prediction, confidence, and review flag
        """
        inference_id = str(uuid.uuid4())

        try:
            inputs = inputs.to(self.device)
            if inputs.dim() == 1:
                inputs = inputs.unsqueeze(0)

            with torch.no_grad():
                logits = self.model(inputs)
                if isinstance(logits, tuple):
                    logits = logits[0]  # Some HuggingFace models return (logits, ...)
                probs = torch.softmax(logits, dim=-1)[0].cpu().numpy()

            confidence = float(probs.max())
            pred_idx = int(probs.argmax())

            # Top-3 predictions for context
            top3_idx = np.argsort(probs)[::-1][:3]
            top_k = [(self.class_names[i], float(probs[i])) for i in top3_idx]

            requires_review = confidence < self.confidence_threshold

            record = InferenceRecord(
                inference_id=inference_id,
                context_id=context_id,
                model_name=self.model_name,
                model_version=self.model_version,
                timestamp_utc=datetime.now(timezone.utc).isoformat(),
                # Key compliance behavior: predicted_class is None when uncertain
                # The downstream system MUST check requires_human_review before acting
                predicted_class=self.class_names[pred_idx] if not requires_review else None,
                confidence=confidence,
                requires_human_review=requires_review,
                top_k_predictions=top_k,
                additional_context=additional_context or {},
            )

        except Exception as exc:
            log.error("Inference failed for context_id=%s: %s", context_id, exc)
            record = InferenceRecord(
                inference_id=inference_id,
                context_id=context_id,
                model_name=self.model_name,
                model_version=self.model_version,
                timestamp_utc=datetime.now(timezone.utc).isoformat(),
                predicted_class=None,
                confidence=0.0,
                requires_human_review=True,
                top_k_predictions=[],
                additional_context={"error": str(exc)},
            )

        self.audit_logger.log(record)
        return record

    def predict_batch(
        self,
        inputs_list: list,
        context_ids: list,
        additional_contexts: list = None,
    ) -> list:
        """
        Run inference on a batch of inputs. Returns list of InferenceRecords.
        """
        if additional_contexts is None:
            additional_contexts = [{}] * len(inputs_list)

        return [
            self.predict(inp, ctx_id, ctx)
            for inp, ctx_id, ctx in zip(inputs_list, context_ids, additional_contexts)
        ]

    def review_statistics(self) -> dict:
        """
        Summary statistics of the inference log.
        Report this in status briefings: what fraction of predictions
        required human review? What is the confidence distribution?
        """
        df = self.audit_logger.get_all()
        if len(df) == 0:
            return {"total_inferences": 0}

        total = len(df)
        review_pct = df["requires_human_review"].mean() * 100
        avg_confidence = df["confidence"].mean()
        override_pct = df["human_override"].notna().mean() * 100

        # Confidence distribution by decile
        conf_deciles = np.percentile(df["confidence"].values, [10, 25, 50, 75, 90])

        return {
            "total_inferences": total,
            "pct_requiring_human_review": round(review_pct, 2),
            "average_confidence": round(avg_confidence, 4),
            "pct_with_human_override": round(override_pct, 2),
            "confidence_p10": round(conf_deciles[0], 4),
            "confidence_p25": round(conf_deciles[1], 4),
            "confidence_p50": round(conf_deciles[2], 4),
            "confidence_p75": round(conf_deciles[3], 4),
            "confidence_p90": round(conf_deciles[4], 4),
        }


# ---------------------------------------------------------------------------
# Evaluation framework for operational AI review
# ---------------------------------------------------------------------------

def evaluate_operational_model(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    y_prob: np.ndarray,
    class_names: list,
    safety_critical_class_idx: int,
    confidence_threshold: float = 0.85,
) -> dict:
    """
    Comprehensive evaluation for DoD operational AI model review.

    Metrics returned are designed for the compliance documentation package:
        - Overall accuracy and F1 (standard performance)
        - FPR on safety-critical class (policy constraint, not just metric)
        - Expected Calibration Error (does confidence = accuracy?)
        - Human review burden (% predictions below threshold)

    Args:
        y_true: Ground truth class indices
        y_pred: Predicted class indices (from argmax of probabilities)
        y_prob: Full probability distributions, shape (n_samples, n_classes)
        class_names: List of class name strings
        safety_critical_class_idx: Index of the class where false positives are most dangerous
        confidence_threshold: The threshold used in production (for review burden calc)

    Returns:
        Metrics dict suitable for MLflow logging and report generation
    """
    # Standard classification metrics
    report = classification_report(y_true, y_pred, target_names=class_names, output_dict=True)
    cm = confusion_matrix(y_true, y_pred)

    # False positive rate on the safety-critical class
    sc = safety_critical_class_idx
    # True negatives: correctly classified as NOT the safety-critical class
    # False positives: incorrectly classified AS the safety-critical class
    tn = cm.sum() - cm[sc, :].sum() - cm[:, sc].sum() + cm[sc, sc]
    fp = cm[:, sc].sum() - cm[sc, sc]
    fpr_critical = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0

    # Expected Calibration Error (ECE)
    # Tests whether a model that says "85% confidence" is right 85% of the time
    max_probs = y_prob.max(axis=1)  # Confidence for each prediction
    n_bins = 10
    bin_edges = np.linspace(0.0, 1.0, n_bins + 1)
    ece = 0.0
    calibration_data = []

    for i in range(n_bins):
        lo, hi = bin_edges[i], bin_edges[i + 1]
        in_bin = (max_probs >= lo) & (max_probs < hi)
        n_in_bin = in_bin.sum()
        if n_in_bin > 0:
            bin_acc = (y_pred[in_bin] == y_true[in_bin]).mean()
            bin_conf = max_probs[in_bin].mean()
            ece += (n_in_bin / len(y_true)) * abs(bin_acc - bin_conf)
            calibration_data.append({
                "bin_lo": lo, "bin_hi": hi,
                "n_samples": int(n_in_bin),
                "avg_confidence": float(bin_conf),
                "accuracy": float(bin_acc),
                "calibration_gap": float(abs(bin_acc - bin_conf)),
            })

    # Human review burden at the given threshold
    review_pct = (max_probs < confidence_threshold).mean() * 100

    return {
        "overall_accuracy": float(report["accuracy"]),
        "macro_f1": float(report["macro avg"]["f1-score"]),
        "weighted_f1": float(report["weighted avg"]["f1-score"]),
        "fpr_safety_critical_class": fpr_critical,
        "safety_critical_class_name": class_names[safety_critical_class_idx],
        "expected_calibration_error": float(ece),
        "pct_requiring_review_at_threshold": float(review_pct),
        "confidence_threshold_used": confidence_threshold,
        "n_samples": len(y_true),
        "per_class_precision": {c: float(report[c]["precision"])
                                 for c in class_names if c in report},
        "per_class_recall": {c: float(report[c]["recall"])
                              for c in class_names if c in report},
        "per_class_f1": {c: float(report[c]["f1-score"])
                          for c in class_names if c in report},
        "confusion_matrix": cm.tolist(),
        "calibration_data": calibration_data,
    }


def print_evaluation_report(metrics: dict) -> None:
    """Print a human-readable evaluation report for the program review."""
    print("\n" + "=" * 60)
    print("OPERATIONAL AI MODEL EVALUATION REPORT")
    print("=" * 60)
    print(f"Samples evaluated:     {metrics['n_samples']:,}")
    print(f"Overall accuracy:      {metrics['overall_accuracy']:.1%}")
    print(f"Macro F1:              {metrics['macro_f1']:.4f}")
    print(f"Weighted F1:           {metrics['weighted_f1']:.4f}")
    print()
    print("SAFETY METRICS (DoD Directive 3000.09)")
    print(f"  Safety-critical class:   {metrics['safety_critical_class_name']}")
    print(f"  False positive rate:     {metrics['fpr_safety_critical_class']:.4f}  "
          f"({'WITHIN SPEC' if metrics['fpr_safety_critical_class'] < 0.003 else 'EXCEEDS SPEC — DO NOT DEPLOY'})")
    print(f"  Calibration error (ECE): {metrics['expected_calibration_error']:.4f}  "
          f"({'WELL CALIBRATED' if metrics['expected_calibration_error'] < 0.05 else 'NEEDS RECALIBRATION'})")
    print()
    print("OPERATIONAL BURDEN")
    print(f"  Confidence threshold:    {metrics['confidence_threshold_used']:.0%}")
    print(f"  Predictions to human:    {metrics['pct_requiring_review_at_threshold']:.1f}%")
    print()
    print("PER-CLASS F1 SCORES")
    for cls, f1 in metrics["per_class_f1"].items():
        bar = "█" * int(f1 * 20)
        print(f"  {cls:30s} {f1:.3f} {bar}")
    print("=" * 60)


# ---------------------------------------------------------------------------
# Demo: simulated vehicle detection pipeline
# ---------------------------------------------------------------------------

class MockVehicleDetector(nn.Module):
    """
    Minimal mock model for demonstrating the pipeline without real imagery data.
    Returns random logits shaped for vehicle classification.
    """
    VEHICLE_CLASSES = ["civilian_vehicle", "military_vehicle", "unknown", "background"]

    def __init__(self, n_features: int = 64):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(n_features, 32),
            nn.ReLU(),
            nn.Linear(32, len(self.VEHICLE_CLASSES)),
        )

    def forward(self, x):
        return self.net(x)


if __name__ == "__main__":
    # -----------------------------------------------------------------------
    # Demo 1: Operational inference pipeline with audit logging
    # -----------------------------------------------------------------------
    log.info("=== Demo: Operational Inference Pipeline ===")

    vehicle_classes = MockVehicleDetector.VEHICLE_CLASSES
    model = MockVehicleDetector(n_features=64)

    # Initialize pipeline with 85% confidence threshold
    pipeline = OperationalInferencePipeline(
        model=model,
        class_names=vehicle_classes,
        model_name="vehicle_detector_yolov8",
        model_version="1.0.3",
        confidence_threshold=0.85,
        device="cpu",
    )

    # Simulate 200 inference calls
    n_inferences = 200
    torch.manual_seed(42)
    context_ids = [f"FRAME_{i:05d}" for i in range(n_inferences)]
    inputs = [torch.randn(64) for _ in range(n_inferences)]

    log.info("Running %s inferences...", n_inferences)
    records = pipeline.predict_batch(
        inputs,
        context_ids,
        additional_contexts=[{"altitude_ft": int(np.random.uniform(500, 5000))}
                              for _ in range(n_inferences)]
    )

    # Show review statistics
    stats = pipeline.review_statistics()
    print("\nInference Statistics:")
    for k, v in stats.items():
        print(f"  {k}: {v}")

    # Show sample records
    print("\nSample Inference Records (first 5):")
    for record in records[:5]:
        flag = " [→ HUMAN REVIEW]" if record.requires_human_review else ""
        print(f"  {record.context_id}: {record.predicted_class or 'PENDING REVIEW'}"
              f" ({record.confidence:.1%}){flag}")

    # -----------------------------------------------------------------------
    # Demo 2: Evaluation framework
    # -----------------------------------------------------------------------
    log.info("\n=== Demo: Operational Model Evaluation ===")

    # Simulate ground truth and predictions for evaluation
    n_test = 1_000
    rng = np.random.RandomState(42)

    # Simulate a model with good overall accuracy but higher FPR on class 0 (civilian)
    y_true = rng.choice(len(vehicle_classes), size=n_test,
                        p=[0.40, 0.30, 0.20, 0.10])  # Civilian-heavy distribution

    # Simulate predictions: mostly correct but with some FP on civilian class
    y_prob = np.zeros((n_test, len(vehicle_classes)))
    for i, true_label in enumerate(y_true):
        base = np.ones(len(vehicle_classes)) * 0.05
        base[true_label] = 0.75 + rng.uniform(0, 0.20)
        # Inject some civilian false positives (the dangerous error mode)
        if true_label != 0 and rng.random() < 0.015:
            base[0] = base[true_label] + 0.05  # Model incorrectly favors civilian
        base /= base.sum()
        y_prob[i] = base

    y_pred = y_prob.argmax(axis=1)

    metrics = evaluate_operational_model(
        y_true=y_true,
        y_pred=y_pred,
        y_prob=y_prob,
        class_names=vehicle_classes,
        safety_critical_class_idx=0,   # civilian_vehicle — most dangerous false positives
        confidence_threshold=0.85,
    )

    print_evaluation_report(metrics)
    print(f"\nFull metrics keys: {list(metrics.keys())}")
