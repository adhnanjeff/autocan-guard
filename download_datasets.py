#!/usr/bin/env python3
"""Helper: print download instructions for the three standard CAN datasets and
verify that the expected files exist under the benchmark data root.

HCRL gates these datasets behind a request form / Dropbox, so this script does
NOT auto-download them (doing so reliably is not possible and would risk
fabricating data). It tells you exactly where to get each dataset, where to put
the files, and checks your layout.

Usage:
    python download_datasets.py            # print guide + verify default root
    CAN_BENCHMARK_DATA=/path python download_datasets.py
"""

from __future__ import annotations

import os
import sys

from benchmark import config

SOURCES = {
    "car_hacking": {
        "url": "https://ocslab.hksecurity.net/Datasets/car-hacking-dataset",
        "expected": [
            "DoS_dataset.csv",
            "Fuzzy_dataset.csv",
            "gear_dataset.csv",
            "RPM_dataset.csv",
            "normal_run_data.txt",
        ],
    },
    "otids": {
        "url": "https://ocslab.hksecurity.net/Dataset/CAN-intrusion-dataset",
        "expected": [
            "Attack_free_dataset.txt",
            "DoS_attack_dataset.txt",
            "Fuzzy_attack_dataset.txt",
            "Impersonation_attack_dataset.txt",
        ],
    },
    "can_fd": {
        "url": "https://ocslab.hksecurity.net/Datasets/can-fd-intrusion-dataset",
        "expected": [
            "Flooding_dataset.csv",
            "Fuzzing_dataset.csv",
            "Malfunction_dataset.csv",
        ],
    },
}


def main() -> int:
    root = config.DATA_ROOT
    print("=" * 72)
    print("Standard CAN datasets — download guide & layout check")
    print("=" * 72)
    print(f"Data root (CAN_BENCHMARK_DATA): {root}\n")

    all_present = True
    for name, info in SOURCES.items():
        subdir = os.path.join(root, name)
        print(f"[{name}]  download: {info['url']}")
        print(f"          place files in: {subdir}")
        present_any = False
        for fname in info["expected"]:
            # keyword-tolerant existence check: accept any file whose name
            # contains the distinctive stem (datasets often ship with variant names)
            stem = fname.split("_")[0].lower()
            found = os.path.isdir(subdir) and any(
                stem in existing.lower() for existing in os.listdir(subdir)
            )
            present_any = present_any or found
            mark = "OK " if found else "-- "
            print(f"            [{mark}] {fname}")
            if not found:
                all_present = False
        if not present_any:
            print("            (nothing found yet — download & extract here)")
        print()

    print("-" * 72)
    if all_present:
        print("All expected files found. Run e.g.:")
        print("  python run_benchmark.py --dataset car_hacking "
              f"--data-dir {os.path.join(root, 'car_hacking')}")
    else:
        print("Some files missing. You can still verify the pipeline on shipped")
        print("fixtures without downloading anything:")
        print("  python run_benchmark.py --dataset car_hacking --fixtures")
    print("-" * 72)
    return 0


if __name__ == "__main__":
    sys.exit(main())
