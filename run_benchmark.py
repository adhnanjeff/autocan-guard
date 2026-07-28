#!/usr/bin/env python3
"""CLI entry point for the standard CAN intrusion-detection benchmark.

Examples:
    python run_benchmark.py --dataset car_hacking --fixtures
    python run_benchmark.py --dataset otids --data-dir /path/to/otids_files
    python run_benchmark.py --dataset can_fd --data-dir /path/to/canfd --max-frames 50000
"""

from __future__ import annotations

import argparse
import glob
import os
import sys
from typing import Dict, Optional

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from benchmark.benchmark_runner import BenchmarkRunner  # noqa: E402
from benchmark.config import REPORT_ROOT  # noqa: E402
from benchmark.loaders.base import DatasetName  # noqa: E402

# Keyword -> canonical attack_type, checked in filename (case-insensitive).
# Order matters: more specific keywords should be checked before generic ones.
_ATTACK_KEYWORDS = [
    ("attack_free", "normal"),
    ("attack-free", "normal"),
    ("normal", "normal"),
    ("dos", "dos"),
    ("fuzzy", "fuzzy"),
    ("fuzzing", "fuzzy"),
    ("gear", "gear"),
    ("rpm", "rpm"),
    ("impersonation", "impersonation"),
    ("flooding", "flooding"),
    ("malfunction", "malfunction"),
    ("spoofing", "spoofing"),
]


def _infer_attack_type(filename: str) -> Optional[str]:
    lower = filename.lower()
    for keyword, attack_type in _ATTACK_KEYWORDS:
        if keyword in lower:
            return attack_type
    return None


def resolve_files(dataset: DatasetName, data_dir: str) -> Dict[str, str]:
    """Glob ``data_dir`` and map attack_type -> file path by filename keyword."""
    candidates = sorted(
        p for p in glob.glob(os.path.join(data_dir, "*"))
        if os.path.isfile(p)
    )
    files: Dict[str, str] = {}
    unmatched = []
    for path in candidates:
        filename = os.path.basename(path)
        attack_type = _infer_attack_type(filename)
        if attack_type is None:
            unmatched.append(filename)
            continue
        # If multiple files map to the same attack_type, keep the first and
        # warn — callers should keep one file per attack_type in the dir.
        if attack_type in files:
            print(
                f"warning: multiple files matched attack_type={attack_type!r} "
                f"({files[attack_type]!r} and {filename!r}); keeping the first",
                file=sys.stderr,
            )
            continue
        files[attack_type] = path

    if unmatched:
        print(
            f"warning: could not infer attack_type for: {unmatched} "
            "(skipped; expected keywords like dos/fuzzy/gear/rpm/impersonation/"
            "flooding/malfunction/normal in the filename)",
            file=sys.stderr,
        )

    return files


def fixtures_dir(dataset: DatasetName) -> str:
    here = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(here, "benchmark", "fixtures", dataset.value)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Run the standard CAN intrusion-detection benchmark."
    )
    parser.add_argument(
        "--dataset",
        required=True,
        choices=[d.value for d in DatasetName],
        help="Which standard dataset to benchmark.",
    )
    source_group = parser.add_mutually_exclusive_group(required=True)
    source_group.add_argument(
        "--data-dir",
        help="Directory containing this dataset's raw files.",
    )
    source_group.add_argument(
        "--fixtures",
        action="store_true",
        help="Use the small format-accurate fixtures under benchmark/fixtures/<dataset>/.",
    )
    parser.add_argument(
        "--max-frames",
        type=int,
        default=None,
        help="Optional cap on frames loaded per file.",
    )
    parser.add_argument(
        "--features",
        choices=["full", "paper5"],
        default="full",
        help="Feature set: 'full' (14 CAN-IDS features) or 'paper5' "
             "(the paper's 5 normalized features).",
    )
    args = parser.parse_args(argv)

    dataset = DatasetName(args.dataset)
    data_dir = fixtures_dir(dataset) if args.fixtures else args.data_dir

    if not os.path.isdir(data_dir):
        print(f"error: data directory does not exist: {data_dir}", file=sys.stderr)
        return 2

    files = resolve_files(dataset, data_dir)
    if not files:
        print(f"error: no recognizable dataset files found in {data_dir}", file=sys.stderr)
        return 2

    print(f"Dataset:    {dataset.value}")
    print(f"Source dir: {data_dir}")
    print("Files resolved:")
    for attack_type, path in sorted(files.items()):
        print(f"  {attack_type:15s} -> {path}")
    print()

    runner = BenchmarkRunner(dataset=dataset, files=files, max_frames=args.max_frames,
                             feature_set=args.features)
    report = runner.run(save=True)
    print(f"Feature set: {report['feature_set']} ({len(report['feature_names'])} features, normalized)")

    cm = report["classification_metrics"]
    lat = report["latency_throughput"]

    print("=" * 60)
    print(f"RESULTS — {dataset.value}")
    print("=" * 60)
    print(f"  Frames:      {report['n_frames']} (train={report['n_train']}, test={report['n_test']})")
    print(f"  Class bal.:  {report['class_balance']}")
    print("-" * 60)
    print("  Six required metrics:")
    print(f"    Precision:            {cm['precision']:.4f}")
    print(f"    Recall:               {cm['recall']:.4f}")
    print(f"    Accuracy:             {cm['accuracy']:.4f}")
    print(f"    F1:                   {cm['f1']:.4f}")
    print(f"    Latency (mean, ms):   {lat['mean_ms']:.4f}")
    print(f"    Throughput (msgs/s):  {lat['throughput_msgs_per_sec']:.2f}")
    print("-" * 60)
    print(f"  Specificity: {cm['specificity']:.4f}   FPR: {cm['fpr']:.4f}")
    print(f"  Confusion:   {cm['confusion']}")
    print(f"  Latency:     median={lat['median_ms']:.4f}ms  "
          f"p95={lat['p95_ms']:.4f}ms  p99={lat['p99_ms']:.4f}ms")
    print("-" * 60)
    print("  Per-attack recall:")
    for attack_type, stats in sorted(report["per_attack_breakdown"].items()):
        if attack_type == "normal":
            continue
        print(f"    {attack_type:15s} n={stats['n']:6d}  detected={stats['detected']:6d}  recall={stats['recall']:.4f}")
    normal_stats = report["per_attack_breakdown"].get("normal", {})
    if normal_stats:
        print(f"    {'normal':15s} n={normal_stats['n']:6d}  false_positives={normal_stats['false_positives']:6d}  fpr={normal_stats['fpr']:.4f}")
    print("=" * 60)

    out_dir = os.path.join(REPORT_ROOT, dataset.value)
    print(f"Report + graphs saved to: {out_dir}")
    print(f"  - report.json")
    print(f"  - confusion_matrix.png")
    print(f"  - per_attack_recall.png")
    print(f"  - latency_histogram.png")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
