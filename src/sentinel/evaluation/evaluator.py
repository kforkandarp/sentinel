"""Quantitative evaluation logic for Sentinel's frozen prompt-injection benchmark."""

import json
from pathlib import Path
from typing import Any
from pydantic import BaseModel, ConfigDict, Field

from sentinel.detection.detector import PromptInjectionDetector
from sentinel.detection.models import DetectionResult


class EvaluationMetrics(BaseModel):
    """Machine-readable summary of benchmark detection performance."""

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        protected_namespaces=(),
    )

    total_examples: int = Field(..., description="Total number of evaluated examples.")
    safe_examples: int = Field(..., description="Total ground-truth SAFE examples.")
    injection_examples: int = Field(..., description="Total ground-truth INJECTION examples.")

    true_positive: int = Field(..., description="INJECTION correctly classified as INJECTION.")
    true_negative: int = Field(..., description="SAFE correctly classified as SAFE.")
    false_positive: int = Field(..., description="SAFE misclassified as INJECTION.")
    false_negative: int = Field(..., description="INJECTION misclassified as SAFE.")

    accuracy: float = Field(..., description="(TP + TN) / total")
    precision: float = Field(..., description="TP / (TP + FP)")
    recall: float = Field(..., description="TP / (TP + FN)")
    f1: float = Field(..., description="2 * Precision * Recall / (Precision + Recall)")
    false_positive_rate: float = Field(..., description="FP / (FP + TN)")
    false_negative_rate: float = Field(..., description="FN / (FN + TP)")

    model_name: str = Field(..., description="Locked model identifier.")
    threshold: float = Field(..., description="Locked decision threshold.")


def compute_binary_metrics(
    tp: int,
    tn: int,
    fp: int,
    fn: int,
    model_name: str,
    threshold: float,
) -> EvaluationMetrics:
    """Calculate standard binary classification metrics with zero-division safety."""
    total = tp + tn + fp + fn
    if total == 0:
        raise ValueError("Cannot calculate metrics over an empty set of predictions")

    accuracy = (tp + tn) / total

    precision_denom = tp + fp
    precision = (tp / precision_denom) if precision_denom > 0 else 0.0

    recall_denom = tp + fn
    recall = (tp / recall_denom) if recall_denom > 0 else 0.0

    f1_denom = precision + recall
    f1 = (2 * precision * recall / f1_denom) if f1_denom > 0 else 0.0

    fpr_denom = fp + tn
    fpr = (fp / fpr_denom) if fpr_denom > 0 else 0.0

    fnr_denom = fn + tp
    fnr = (fn / fnr_denom) if fnr_denom > 0 else 0.0

    return EvaluationMetrics(
        total_examples=total,
        safe_examples=tn + fp,
        injection_examples=tp + fn,
        true_positive=tp,
        true_negative=tn,
        false_positive=fp,
        false_negative=fn,
        accuracy=round(accuracy, 6),
        precision=round(precision, 6),
        recall=round(recall, 6),
        f1=round(f1, 6),
        false_positive_rate=round(fpr, 6),
        false_negative_rate=round(fnr, 6),
        model_name=model_name,
        threshold=threshold,
    )


def load_and_verify_benchmark(dataset_path: str | Path) -> list[dict[str, Any]]:
    """Load benchmark dataset and enforce strict 240-example (120/120) integrity."""
    path = Path(dataset_path)
    if not path.is_file():
        raise FileNotFoundError(f"Benchmark file not found at: {path}")

    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    if not isinstance(data, dict) or "examples" not in data:
        raise ValueError("Invalid benchmark structure: missing 'examples' array")

    examples = data["examples"]
    total = len(examples)
    safe_count = sum(1 for ex in examples if ex.get("ground_truth") == "SAFE")
    injection_count = sum(1 for ex in examples if ex.get("ground_truth") == "INJECTION")

    if total != 240 or safe_count != 120 or injection_count != 120:
        raise ValueError(
            f"Benchmark data integrity violation: expected exactly 240 total (120 SAFE, 120 INJECTION), "
            f"got {total} total ({safe_count} SAFE, {injection_count} INJECTION)"
        )

    return examples


def evaluate_benchmark(
    dataset_path: str | Path,
    detector: PromptInjectionDetector | None = None,
) -> tuple[EvaluationMetrics, list[dict[str, Any]]]:
    """Execute evaluation over the frozen benchmark using the locked detector.

    Returns:
        tuple of (EvaluationMetrics, detailed_predictions_list)
    """
    examples = load_and_verify_benchmark(dataset_path)

    active_detector = detector or PromptInjectionDetector()

    tp = 0
    tn = 0
    fp = 0
    fn = 0

    prediction_records: list[dict[str, Any]] = []

    for item in examples:
        text = item["text"]
        gt_str = item["ground_truth"]

        # Call active_detector.detect()
        result: DetectionResult = active_detector.detect(text)
        pred_str = result.label.value

        if gt_str == "INJECTION":
            if pred_str == "INJECTION":
                tp += 1
            else:
                fn += 1
        elif gt_str == "SAFE":
            if pred_str == "SAFE":
                tn += 1
            else:
                fp += 1
        else:
            raise ValueError(f"Unrecognized ground-truth label '{gt_str}' in example {item.get('id')}")

        prediction_records.append(
            {
                "id": item["id"],
                "ground_truth": gt_str,
                "predicted": pred_str,
                "score": result.score,
                "category": item.get("category"),
            }
        )

    metrics = compute_binary_metrics(
        tp=tp,
        tn=tn,
        fp=fp,
        fn=fn,
        model_name=active_detector.model_name,
        threshold=active_detector.threshold,
    )

    return metrics, prediction_records