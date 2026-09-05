"""
Temporary detailed benchmark evaluator for Sentinel v1.

This script DOES NOT modify Sentinel's evaluator.py or dataset.
It reuses the current evaluator/detector, then adds:
- overall metrics
- category-wise metrics
- difficulty-wise metrics
- confusion-matrix counts for every group

Run from the Sentinel_v1 project root with its .venv activated.
"""

import argparse
import json
from pathlib import Path
from typing import Any

from sentinel.detection.detector import PromptInjectionDetector
from sentinel.evaluation.evaluator import evaluate_benchmark


def safe_divide(numerator: int | float, denominator: int | float) -> float:
    return round(numerator / denominator, 6) if denominator else 0.0


def metrics_from_records(records: list[dict[str, Any]]) -> dict[str, Any]:
    tp = tn = fp = fn = 0

    for record in records:
        gt = record["ground_truth"]
        pred = record["predicted"]

        if gt == "INJECTION" and pred == "INJECTION":
            tp += 1
        elif gt == "SAFE" and pred == "SAFE":
            tn += 1
        elif gt == "SAFE" and pred == "INJECTION":
            fp += 1
        elif gt == "INJECTION" and pred == "SAFE":
            fn += 1
        else:
            raise ValueError(
                f"Unexpected labels: ground_truth={gt!r}, predicted={pred!r}"
            )

    total = tp + tn + fp + fn

    precision = safe_divide(tp, tp + fp)
    recall = safe_divide(tp, tp + fn)
    f1 = safe_divide(2 * precision * recall, precision + recall)

    return {
        "total": total,
        "correct": tp + tn,
        "accuracy": safe_divide(tp + tn, total),
        "true_positive": tp,
        "true_negative": tn,
        "false_positive": fp,
        "false_negative": fn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "false_positive_rate": safe_divide(fp, fp + tn),
        "false_negative_rate": safe_divide(fn, fn + tp),
    }


def group_records(
    records: list[dict[str, Any]], field: str
) -> dict[str, list[dict[str, Any]]]:
    groups: dict[str, list[dict[str, Any]]] = {}

    for record in records:
        value = record.get(field) or "unknown"
        groups.setdefault(value, []).append(record)

    return groups


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run Sentinel v1 benchmark with detailed category/difficulty metrics."
    )
    parser.add_argument(
        "--dataset",
        default="data/benchmark/dataset.json",
        help="Path to frozen benchmark dataset.",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Optional JSON output path. If omitted, nothing is written to disk.",
    )
    args = parser.parse_args()

    dataset_path = Path(args.dataset)

    print(f"Loading benchmark: {dataset_path}")
    print("Running the CURRENT Sentinel v1 evaluator/detector...")
    print()

    detector = PromptInjectionDetector()

    # This is the exact current evaluation pipeline.
    overall_metrics, records = evaluate_benchmark(
        dataset_path,
        detector=detector,
    )

    results: dict[str, Any] = {
        "overall": overall_metrics.model_dump(),
        "by_category": {},
        "by_difficulty": {},
    }

    # Category-wise results.
    for category, category_records in sorted(
        group_records(records, "category").items()
    ):
        results["by_category"][category] = metrics_from_records(category_records)

    # Difficulty-wise results.
    #
    # The current evaluator's prediction records do not carry difficulty,
    # so read it from the frozen dataset and join by example ID.
    with open(dataset_path, "r", encoding="utf-8") as f:
        dataset = json.load(f)

    difficulty_by_id = {
        item["id"]: item.get("difficulty", "unknown")
        for item in dataset["examples"]
    }

    records_with_difficulty = []
    for record in records:
        enriched = dict(record)
        enriched["difficulty"] = difficulty_by_id.get(record["id"], "unknown")
        records_with_difficulty.append(enriched)

    for difficulty, difficulty_records in sorted(
        group_records(records_with_difficulty, "difficulty").items()
    ):
        results["by_difficulty"][difficulty] = metrics_from_records(
            difficulty_records
        )

    # Print results in an easy-to-read format.
    print("=" * 72)
    print("SENTINEL v1 — DETAILED BENCHMARK EVALUATION")
    print("=" * 72)

    print("\nOVERALL")
    print(json.dumps(results["overall"], indent=2))

    print("\nBY CATEGORY")
    print("-" * 72)
    for category, metrics in results["by_category"].items():
        print(
            f"{category:32} "
            f"{metrics['correct']:3}/{metrics['total']:<3} "
            f"accuracy={metrics['accuracy']:.2%} "
            f"TP={metrics['true_positive']:2} "
            f"TN={metrics['true_negative']:2} "
            f"FP={metrics['false_positive']:2} "
            f"FN={metrics['false_negative']:2}"
        )

    print("\nBY DIFFICULTY")
    print("-" * 72)
    for difficulty, metrics in results["by_difficulty"].items():
        print(
            f"{difficulty:12} "
            f"{metrics['correct']:3}/{metrics['total']:<3} "
            f"accuracy={metrics['accuracy']:.2%} "
            f"TP={metrics['true_positive']:2} "
            f"TN={metrics['true_negative']:2} "
            f"FP={metrics['false_positive']:2} "
            f"FN={metrics['false_negative']:2}"
        )

    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(results, indent=2), encoding="utf-8")
        print(f"\n[+] Detailed results saved to {output_path}")

    print("\nDone.")


if __name__ == "__main__":
    main()