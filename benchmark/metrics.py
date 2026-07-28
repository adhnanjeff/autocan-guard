"""Evaluation metrics for the CAN intrusion-detection benchmark.

Pure functions only — no I/O, no plotting. Consumed by
``benchmark.benchmark_runner.BenchmarkRunner`` and by
``run_benchmark.py`` to print the six required headline metrics
(precision, recall, accuracy, F1, latency, throughput).
"""

from __future__ import annotations

from typing import Iterable, List, Sequence

import numpy as np
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)

from .can_frame import CanFrame


def classification_metrics(y_true: Sequence[int], y_pred: Sequence[int]) -> dict:
    """Compute standard binary classification metrics.

    Returns a dict with keys: accuracy, precision, recall, f1, specificity,
    fpr, confusion = {tp, tn, fp, fn}. All zero-division cases return 0.0
    instead of raising/NaN.
    """
    y_true = np.asarray(y_true).astype(int)
    y_pred = np.asarray(y_pred).astype(int)

    if y_true.size == 0:
        return {
            "accuracy": 0.0,
            "precision": 0.0,
            "recall": 0.0,
            "f1": 0.0,
            "specificity": 0.0,
            "fpr": 0.0,
            "confusion": {"tp": 0, "tn": 0, "fp": 0, "fn": 0},
        }

    # Force a full 2x2 matrix even if one class is absent from this batch.
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel()

    accuracy = accuracy_score(y_true, y_pred)
    precision = precision_score(y_true, y_pred, labels=[0, 1], pos_label=1, zero_division=0)
    recall = recall_score(y_true, y_pred, labels=[0, 1], pos_label=1, zero_division=0)
    f1 = f1_score(y_true, y_pred, labels=[0, 1], pos_label=1, zero_division=0)

    specificity = float(tn) / float(tn + fp) if (tn + fp) > 0 else 0.0
    fpr = float(fp) / float(fp + tn) if (fp + tn) > 0 else 0.0

    return {
        "accuracy": float(accuracy),
        "precision": float(precision),
        "recall": float(recall),
        "f1": float(f1),
        "specificity": float(specificity),
        "fpr": float(fpr),
        "confusion": {"tp": int(tp), "tn": int(tn), "fp": int(fp), "fn": int(fn)},
    }


def latency_throughput(per_msg_seconds: Iterable[float]) -> dict:
    """Compute latency percentiles (ms) and throughput (msgs/sec).

    Guards empty input and zero total time.
    """
    values = np.asarray(list(per_msg_seconds), dtype=float)

    if values.size == 0:
        return {
            "mean_ms": 0.0,
            "median_ms": 0.0,
            "p95_ms": 0.0,
            "p99_ms": 0.0,
            "throughput_msgs_per_sec": 0.0,
        }

    ms = values * 1000.0
    total_seconds = float(values.sum())
    throughput = float(len(values)) / total_seconds if total_seconds > 0 else 0.0

    return {
        "mean_ms": float(np.mean(ms)),
        "median_ms": float(np.median(ms)),
        "p95_ms": float(np.percentile(ms, 95)),
        "p99_ms": float(np.percentile(ms, 99)),
        "throughput_msgs_per_sec": throughput,
    }


def per_attack_breakdown(frames: List[CanFrame], y_pred: Sequence[int]) -> dict:
    """Per-attack-type recall/detection breakdown, plus normal-class FPR.

    ``frames`` and ``y_pred`` must be aligned (same order/length). For every
    attack_type present among label==1 frames (excluding 'normal'), reports
    the count, number detected (predicted 1) and recall. Also reports the
    false positive rate on 'normal' frames under the key 'normal'.
    """
    y_pred = np.asarray(y_pred).astype(int)
    if len(frames) != len(y_pred):
        raise ValueError("frames and y_pred must be the same length")

    result: dict = {}

    attack_types = sorted({f.attack_type for f in frames if f.attack_type != "normal"})
    for attack_type in attack_types:
        idx = [i for i, f in enumerate(frames) if f.attack_type == attack_type]
        n = len(idx)
        if n == 0:
            continue
        detected = int(sum(1 for i in idx if y_pred[i] == 1))
        recall = float(detected) / float(n) if n > 0 else 0.0
        result[attack_type] = {"n": n, "detected": detected, "recall": recall}

    normal_idx = [i for i, f in enumerate(frames) if f.attack_type == "normal"]
    n_normal = len(normal_idx)
    if n_normal > 0:
        false_positives = int(sum(1 for i in normal_idx if y_pred[i] == 1))
        fpr = float(false_positives) / float(n_normal)
    else:
        false_positives = 0
        fpr = 0.0
    result["normal"] = {"n": n_normal, "false_positives": false_positives, "fpr": fpr}

    return result
