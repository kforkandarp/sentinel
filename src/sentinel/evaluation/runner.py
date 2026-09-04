"""CLI runner for quantitative evaluation of the Sentinel frozen benchmark."""

import argparse
import json
import sys
from pathlib import Path

from sentinel.detection.detector import PromptInjectionDetector
from sentinel.evaluation.evaluator import evaluate_benchmark


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate Sentinel detector on frozen benchmark.")
    parser.add_argument(
        "--dataset",
        type=str,
        default="data/benchmark/dataset.json",
        help="Path to the frozen benchmark dataset.json",
    )
    parser.add_argument(
        "--output",
        type=str,
        default="data/benchmark/results.json",
        help="Path to output JSON metrics (defaults to data/benchmark/results.json)",
    )
    args = parser.parse_args()

    dataset_path = Path(args.dataset)
    if not dataset_path.exists():
        print(f"Error: Dataset not found at {dataset_path}", file=sys.stderr)
        sys.exit(1)

    print(f"Loading detector and evaluating benchmark from: {dataset_path}...")
    detector = PromptInjectionDetector()
    metrics, _ = evaluate_benchmark(dataset_path, detector=detector)

    output_data = metrics.model_dump()
    formatted_json = json.dumps(output_data, indent=2)

    print("\n=== SENTINEL DETECTOR BENCHMARK EVALUATION RESULTS ===")
    print(formatted_json)
    print("======================================================")

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(formatted_json)
    print(f"\n[+] Results successfully saved to {out_path}")


if __name__ == "__main__":
    main()