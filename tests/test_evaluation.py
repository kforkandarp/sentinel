"""Tests for Phase 8 Evaluation Logic and Invariants."""

import json
from pathlib import Path
import pytest
from pydantic import ValidationError

from sentinel.detection.models import DetectionLabel, DetectionResult
from sentinel.evaluation.evaluator import (
    EvaluationMetrics,
    compute_binary_metrics,
    evaluate_benchmark,
    load_and_verify_benchmark,
)


class MockDetector:
    """Mock detector for fast unit testing of evaluation logic."""

    def __init__(self, pred_map: dict[str, DetectionLabel]) -> None:
        self.pred_map = pred_map
        self.model_name = "protectai/deberta-v3-base-prompt-injection-v2"
        self.threshold = 0.5

    def detect(self, text: str) -> DetectionResult:
        label = self.pred_map.get(text, DetectionLabel.SAFE)
        score = 0.95 if label == DetectionLabel.INJECTION else 0.05
        return DetectionResult(
            label=label,
            score=score,
            model_name=self.model_name,
            threshold=self.threshold,
        )


def test_compute_binary_metrics_exact():
    """Verify arithmetic precision across all standard classification metrics."""
    metrics = compute_binary_metrics(
        tp=86,
        tn=109,
        fp=11,
        fn=34,
        model_name="test-model",
        threshold=0.5,
    )

    assert metrics.total_examples == 240
    assert metrics.safe_examples == 120
    assert metrics.injection_examples == 120
    assert metrics.true_positive == 86
    assert metrics.true_negative == 109
    assert metrics.false_positive == 11
    assert metrics.false_negative == 34

    assert metrics.accuracy == round((86 + 109) / 240, 6)  # 0.8125
    assert metrics.precision == round(86 / (86 + 11), 6)   # 0.886598
    assert metrics.recall == round(86 / (86 + 34), 6)      # 0.716667
    assert metrics.f1 == round(2 * 86 / (2 * 86 + 11 + 34), 6)  # 0.792627
    assert metrics.false_positive_rate == round(11 / (11 + 109), 6)  # 0.091667
    assert metrics.false_negative_rate == round(34 / (34 + 86), 6)   # 0.283333


def test_compute_binary_metrics_zero_division_safety():
    """Verify metrics calculation does not raise ZeroDivisionError when values are zero."""
    metrics = compute_binary_metrics(
        tp=0,
        tn=10,
        fp=0,
        fn=0,
        model_name="test-model",
        threshold=0.5,
    )
    assert metrics.precision == 0.0
    assert metrics.recall == 0.0
    assert metrics.f1 == 0.0
    assert metrics.false_positive_rate == 0.0
    assert metrics.false_negative_rate == 0.0


def test_compute_binary_metrics_empty_set_raises():
    """Verify error on completely empty prediction set."""
    with pytest.raises(ValueError, match="Cannot calculate metrics over an empty set"):
        compute_binary_metrics(tp=0, tn=0, fp=0, fn=0, model_name="m", threshold=0.5)


def test_load_and_verify_benchmark_integrity(tmp_path: Path):
    """Verify integrity check fails loudly if dataset deviates from 240 items (120/120)."""
    # 1. Non-240 count
    bad_count_path = tmp_path / "bad_count.json"
    bad_count_path.write_text(json.dumps({"examples": [{"ground_truth": "SAFE"}]}), encoding="utf-8")
    with pytest.raises(ValueError, match="Benchmark data integrity violation"):
        load_and_verify_benchmark(bad_count_path)

    # 2. 240 count but unbalanced
    bad_balance_path = tmp_path / "bad_balance.json"
    bad_balance_path.write_text(
        json.dumps({
            "examples": (
                [{"ground_truth": "SAFE"} for _ in range(121)]
                + [{"ground_truth": "INJECTION"} for _ in range(119)]
            )
        }),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="Benchmark data integrity violation"):
        load_and_verify_benchmark(bad_balance_path)


def test_evaluation_pipeline_with_mock_detector(tmp_path: Path):
    """Verify evaluation loops over dataset, tabulates confusion matrix, and returns metrics."""
    dataset_file = tmp_path / "valid_bench.json"
    examples = (
        [{"id": f"s_{i}", "text": f"safe text {i}", "ground_truth": "SAFE"} for i in range(120)]
        + [{"id": f"inj_{i}", "text": f"inj text {i}", "ground_truth": "INJECTION"} for i in range(120)]
    )
    dataset_file.write_text(json.dumps({"examples": examples}), encoding="utf-8")

    # Mock: predict injection on all 'inj text' and on 10 'safe text' items
    pred_map = {f"inj text {i}": DetectionLabel.INJECTION for i in range(120)}
    for i in range(10):
        pred_map[f"safe text {i}"] = DetectionLabel.INJECTION

    mock_detector = MockDetector(pred_map)
    metrics, records = evaluate_benchmark(dataset_file, detector=mock_detector)  # type: ignore

    assert metrics.total_examples == 240
    assert metrics.true_positive == 120
    assert metrics.false_positive == 10
    assert metrics.true_negative == 110
    assert metrics.false_negative == 0
    assert len(records) == 240


def test_evaluation_metrics_model_immutability():
    """Verify EvaluationMetrics model is strictly frozen and forbids extra fields."""
    metrics = compute_binary_metrics(
        tp=1, tn=1, fp=0, fn=0, model_name="m", threshold=0.5
    )
    with pytest.raises(ValidationError):
        metrics.accuracy = 0.5  # type: ignore