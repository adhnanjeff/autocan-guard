"""Unit tests for benchmark.metrics."""

from __future__ import annotations

import math

import pytest

from benchmark.can_frame import CanFrame
from benchmark.metrics import (
    classification_metrics,
    latency_throughput,
    per_attack_breakdown,
)


# ---------------------------------------------------------------------------
# classification_metrics
# ---------------------------------------------------------------------------

def test_classification_metrics_known_confusion_matrix():
    # Hand-built confusion matrix:
    #   tp=3, tn=4, fp=2, fn=1  (total 10)
    y_true = [1, 1, 1, 1, 0, 0, 0, 0, 0, 0]
    y_pred = [1, 1, 1, 0, 1, 1, 0, 0, 0, 0]
    # true: [1,1,1,1,0,0,0,0,0,0]
    # pred: [1,1,1,0,1,1,0,0,0,0]
    # tp (true=1,pred=1): idx0,1,2 -> 3
    # fn (true=1,pred=0): idx3 -> 1
    # fp (true=0,pred=1): idx4,5 -> 2
    # tn (true=0,pred=0): idx6,7,8,9 -> 4
    result = classification_metrics(y_true, y_pred)

    tp, tn, fp, fn = 3, 4, 2, 1
    expected_accuracy = (tp + tn) / 10
    expected_precision = tp / (tp + fp)
    expected_recall = tp / (tp + fn)
    expected_f1 = 2 * expected_precision * expected_recall / (expected_precision + expected_recall)
    expected_specificity = tn / (tn + fp)
    expected_fpr = fp / (fp + tn)

    assert result["confusion"] == {"tp": tp, "tn": tn, "fp": fp, "fn": fn}
    assert result["accuracy"] == pytest.approx(expected_accuracy)
    assert result["precision"] == pytest.approx(expected_precision)
    assert result["recall"] == pytest.approx(expected_recall)
    assert result["f1"] == pytest.approx(expected_f1)
    assert result["specificity"] == pytest.approx(expected_specificity)
    assert result["fpr"] == pytest.approx(expected_fpr)


def test_classification_metrics_perfect_predictions():
    y_true = [0, 1, 0, 1, 1]
    y_pred = [0, 1, 0, 1, 1]
    result = classification_metrics(y_true, y_pred)
    assert result["accuracy"] == 1.0
    assert result["precision"] == 1.0
    assert result["recall"] == 1.0
    assert result["f1"] == 1.0
    assert result["specificity"] == 1.0
    assert result["fpr"] == 0.0
    assert result["confusion"] == {"tp": 3, "tn": 2, "fp": 0, "fn": 0}


def test_classification_metrics_all_negative_predictions_zero_division_guard():
    # No positive predictions at all -> precision would be 0/0 without guard.
    y_true = [1, 1, 0, 0]
    y_pred = [0, 0, 0, 0]
    result = classification_metrics(y_true, y_pred)
    assert result["precision"] == 0.0
    assert result["recall"] == 0.0
    assert result["f1"] == 0.0
    assert result["confusion"] == {"tp": 0, "tn": 2, "fp": 0, "fn": 2}


def test_classification_metrics_empty_input():
    result = classification_metrics([], [])
    assert result["accuracy"] == 0.0
    assert result["precision"] == 0.0
    assert result["recall"] == 0.0
    assert result["f1"] == 0.0
    assert result["specificity"] == 0.0
    assert result["fpr"] == 0.0
    assert result["confusion"] == {"tp": 0, "tn": 0, "fp": 0, "fn": 0}


def test_classification_metrics_no_negatives_specificity_guard():
    # No true negatives at all present -> specificity/fpr denominator 0.
    y_true = [1, 1, 1]
    y_pred = [1, 0, 1]
    result = classification_metrics(y_true, y_pred)
    assert result["specificity"] == 0.0
    assert result["fpr"] == 0.0


# ---------------------------------------------------------------------------
# latency_throughput
# ---------------------------------------------------------------------------

def test_latency_throughput_known_values():
    # 4 messages, each taking 1ms, 2ms, 3ms, 4ms -> total 10ms = 0.01s
    per_msg_seconds = [0.001, 0.002, 0.003, 0.004]
    result = latency_throughput(per_msg_seconds)

    assert result["mean_ms"] == pytest.approx(2.5)
    assert result["median_ms"] == pytest.approx(2.5)
    assert result["throughput_msgs_per_sec"] == pytest.approx(4 / 0.01)
    # p95/p99 should be within [median, max]
    assert 2.5 <= result["p95_ms"] <= 4.0
    assert 2.5 <= result["p99_ms"] <= 4.0
    assert all(math.isfinite(v) for v in result.values())


def test_latency_throughput_empty_list_guard():
    result = latency_throughput([])
    assert result["mean_ms"] == 0.0
    assert result["median_ms"] == 0.0
    assert result["p95_ms"] == 0.0
    assert result["p99_ms"] == 0.0
    assert result["throughput_msgs_per_sec"] == 0.0


def test_latency_throughput_single_value():
    result = latency_throughput([0.005])
    assert result["mean_ms"] == pytest.approx(5.0)
    assert result["median_ms"] == pytest.approx(5.0)
    assert result["p95_ms"] == pytest.approx(5.0)
    assert result["p99_ms"] == pytest.approx(5.0)
    assert result["throughput_msgs_per_sec"] == pytest.approx(1 / 0.005)


# ---------------------------------------------------------------------------
# per_attack_breakdown
# ---------------------------------------------------------------------------

def _make_frame(attack_type, label, timestamp=0.0):
    return CanFrame(
        timestamp=timestamp,
        can_id=0x100,
        dlc=8,
        data=bytes(8),
        label=label,
        attack_type=attack_type,
    )


def test_per_attack_breakdown_synthetic_set():
    frames = [
        _make_frame("normal", 0, 0.0),
        _make_frame("normal", 0, 0.1),
        _make_frame("normal", 0, 0.2),
        _make_frame("dos", 1, 0.3),
        _make_frame("dos", 1, 0.4),
        _make_frame("dos", 1, 0.5),
        _make_frame("dos", 1, 0.6),
        _make_frame("fuzzy", 1, 0.7),
        _make_frame("fuzzy", 1, 0.8),
    ]
    # Predictions: detect 3/4 dos, 1/2 fuzzy, 1 false positive on normal.
    y_pred = [
        0, 0, 1,   # normal: 1 false positive
        1, 1, 1, 0,  # dos: 3 detected out of 4
        1, 0,        # fuzzy: 1 detected out of 2
    ]

    result = per_attack_breakdown(frames, y_pred)

    assert result["dos"] == {"n": 4, "detected": 3, "recall": pytest.approx(0.75)}
    assert result["fuzzy"] == {"n": 2, "detected": 1, "recall": pytest.approx(0.5)}
    assert result["normal"]["n"] == 3
    assert result["normal"]["false_positives"] == 1
    assert result["normal"]["fpr"] == pytest.approx(1 / 3)


def test_per_attack_breakdown_no_attacks_present():
    frames = [_make_frame("normal", 0, float(i)) for i in range(5)]
    y_pred = [0, 0, 0, 1, 0]
    result = per_attack_breakdown(frames, y_pred)
    assert "dos" not in result
    assert result["normal"]["n"] == 5
    assert result["normal"]["false_positives"] == 1
    assert result["normal"]["fpr"] == pytest.approx(0.2)


def test_per_attack_breakdown_length_mismatch_raises():
    frames = [_make_frame("normal", 0, 0.0)]
    with pytest.raises(ValueError):
        per_attack_breakdown(frames, [0, 1])


def test_per_attack_breakdown_perfect_detection():
    frames = [
        _make_frame("gear", 1, 0.0),
        _make_frame("gear", 1, 0.1),
    ]
    y_pred = [1, 1]
    result = per_attack_breakdown(frames, y_pred)
    assert result["gear"] == {"n": 2, "detected": 2, "recall": 1.0}
