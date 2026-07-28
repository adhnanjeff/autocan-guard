"""End-to-end test for BenchmarkRunner using synthetic CanFrame objects.

Builds ~400 synthetic frames directly (no dependency on loaders or fixture
files) so this test is independent of the loaders subagent's work. ~70% are
normal (label 0, spaced timestamps, varied ids); ~30% are a 'dos' attack
(label 1, rapid repeated-id flood).

The real ``benchmark.features.CanFeatureExtractor`` may not exist yet (it is
implemented by a parallel subagent). We guard with
``pytest.importorskip`` for the "real extractor" path, but ALSO exercise the
runner/metrics logic unconditionally via a tiny local ``_MiniExtractor`
monkeypatched into ``benchmark.benchmark_runner`` — this validates
BenchmarkRunner regardless of whether features.py exists yet.
"""

from __future__ import annotations

import math
import os
import random
import shutil

import numpy as np
import pytest

from benchmark.can_frame import CanFrame
from benchmark.benchmark_runner import BenchmarkRunner
from benchmark.loaders.base import DatasetName


# ---------------------------------------------------------------------------
# Synthetic frame construction
# ---------------------------------------------------------------------------

def _build_synthetic_frames(n_total: int = 400, seed: int = 42):
    rng = random.Random(seed)
    frames = []

    n_attack = int(n_total * 0.30)
    n_normal = n_total - n_attack

    t = 0.0
    normal_ids = [0x100, 0x200, 0x300, 0x400, 0x123, 0x321]
    for _ in range(n_normal):
        t += rng.uniform(0.005, 0.02)  # spaced timestamps (5-20ms)
        can_id = rng.choice(normal_ids)
        dlc = 8
        data = bytes(rng.randint(0, 255) for _ in range(dlc))
        frames.append(
            CanFrame(
                timestamp=t,
                can_id=can_id,
                dlc=dlc,
                data=data,
                label=0,
                attack_type="normal",
            )
        )

    # DoS-style flood: rapid same-id frames (small IAT), interleaved in time
    # with the normal traffic so sorting by timestamp mixes them.
    attack_id = 0x000
    t_attack = 0.0
    for _ in range(n_attack):
        t_attack += rng.uniform(0.00005, 0.0002)  # rapid flood (<1ms)
        data = bytes([0x00] * 8)
        frames.append(
            CanFrame(
                timestamp=t_attack,
                can_id=attack_id,
                dlc=8,
                data=data,
                label=1,
                attack_type="dos",
            )
        )

    frames.sort(key=lambda f: f.timestamp)
    return frames


def test_synthetic_frames_composition():
    frames = _build_synthetic_frames()
    assert len(frames) == 400
    n_normal = sum(1 for f in frames if f.label == 0)
    n_attack = sum(1 for f in frames if f.label == 1)
    assert n_normal == 280
    assert n_attack == 120
    # Sorted by timestamp.
    timestamps = [f.timestamp for f in frames]
    assert timestamps == sorted(timestamps)


# ---------------------------------------------------------------------------
# Mini fallback extractor — always available, used to exercise the runner
# even when benchmark.features doesn't exist yet.
# ---------------------------------------------------------------------------

class _MiniExtractor:
    """Fixed-length feature vector: iat, dlc, entropy, id_norm."""

    feature_names = ["iat", "dlc", "entropy", "id_norm"]

    def __init__(self, window_sec: float = 0.02):
        self.window_sec = window_sec
        self._last_seen: dict[int, float] = {}

    def reset(self) -> None:
        self._last_seen = {}

    def extract(self, frame: CanFrame) -> np.ndarray:
        last_t = self._last_seen.get(frame.can_id)
        iat = 0.0 if last_t is None else max(0.0, frame.timestamp - last_t)
        self._last_seen[frame.can_id] = frame.timestamp

        dlc = float(frame.dlc)

        if len(frame.data) == 0:
            entropy = 0.0
        else:
            counts = np.bincount(np.frombuffer(frame.data, dtype=np.uint8), minlength=256)
            probs = counts[counts > 0] / len(frame.data)
            entropy = float(-(probs * np.log2(probs)).sum())

        id_norm = float(frame.can_id) / float(0x1FFFFFFF)

        return np.array([iat, dlc, entropy, id_norm], dtype=np.float64)

    def extract_batch(self, frames) -> np.ndarray:
        self.reset()
        if not frames:
            return np.zeros((0, len(self.feature_names)), dtype=np.float64)
        return np.vstack([self.extract(f) for f in frames])


def _assert_report_valid(report: dict):
    cm = report["classification_metrics"]
    lat = report["latency_throughput"]

    # Six required metrics present and finite / in valid ranges.
    for key in ("precision", "recall", "accuracy", "f1"):
        val = cm[key]
        assert math.isfinite(val)
        assert 0.0 <= val <= 1.0

    assert math.isfinite(lat["mean_ms"])
    assert lat["mean_ms"] >= 0.0
    assert math.isfinite(lat["throughput_msgs_per_sec"])
    assert lat["throughput_msgs_per_sec"] > 0.0

    assert 0.0 <= cm["specificity"] <= 1.0
    assert 0.0 <= cm["fpr"] <= 1.0

    assert report["n_frames"] == report["n_train"] + report["n_test"]
    assert report["feature_names"]
    assert isinstance(report["model_description"], str) and report["model_description"]

    assert "per_attack_breakdown" in report
    assert "normal" in report["per_attack_breakdown"]


# ---------------------------------------------------------------------------
# Fallback path: always runs, regardless of benchmark.features availability.
# ---------------------------------------------------------------------------

def test_benchmark_runner_end_to_end_with_mini_extractor(monkeypatch, tmp_path):
    frames = _build_synthetic_frames()

    runner = BenchmarkRunner(
        dataset=DatasetName.CAR_HACKING,
        files={},  # unused: we call train_eval directly with our own frames
        max_frames=None,
    )

    # Monkeypatch build_matrix to use the always-available mini extractor,
    # so this test exercises the full runner/metrics pipeline even if
    # benchmark.features doesn't exist yet.
    def fake_build_matrix(self, frames):
        extractor = _MiniExtractor(window_sec=self.window_sec)
        X = extractor.extract_batch(frames)
        y = np.array([f.label for f in frames], dtype=int)
        return X, y, extractor

    monkeypatch.setattr(BenchmarkRunner, "build_matrix", fake_build_matrix)

    # Redirect REPORT_ROOT so this test doesn't pollute the real reports dir.
    import benchmark.benchmark_runner as br_module
    fake_report_root = str(tmp_path / "reports")
    monkeypatch.setattr(br_module, "REPORT_ROOT", fake_report_root)

    X, y, extractor = runner.build_matrix(frames)
    report = runner.train_eval(frames, X, y, extractor)
    clean_report = {k: v for k, v in report.items() if not k.startswith("_")}

    _assert_report_valid(clean_report)
    assert clean_report["feature_names"] == ["iat", "dlc", "entropy", "id_norm"]

    # per_attack_breakdown should include 'dos' since attack frames use that tag.
    assert "dos" in clean_report["per_attack_breakdown"]
    assert clean_report["per_attack_breakdown"]["dos"]["n"] > 0

    # Now exercise run()/save via the stashed report path, using the same
    # monkeypatched build_matrix (avoids load_frames() which needs real
    # loader files).
    def fake_run(self, save=True):
        frames_ = _build_synthetic_frames()
        X_, y_, extractor_ = self.build_matrix(frames_)
        report_ = self.train_eval(frames_, X_, y_, extractor_)
        if save:
            self._save_report(report_)
        return {k: v for k, v in report_.items() if not k.startswith("_")}

    monkeypatch.setattr(BenchmarkRunner, "run", fake_run)
    saved_report = runner.run(save=True)
    _assert_report_valid(saved_report)

    out_dir = os.path.join(fake_report_root, "car_hacking")
    assert os.path.isfile(os.path.join(out_dir, "report.json"))
    assert os.path.isfile(os.path.join(out_dir, "confusion_matrix.png"))
    assert os.path.isfile(os.path.join(out_dir, "per_attack_recall.png"))
    assert os.path.isfile(os.path.join(out_dir, "latency_histogram.png"))


# ---------------------------------------------------------------------------
# Real extractor path: skips cleanly if benchmark.features isn't available.
# ---------------------------------------------------------------------------

def test_benchmark_runner_end_to_end_with_real_features(monkeypatch, tmp_path):
    pytest.importorskip("benchmark.features")
    from benchmark.features import CanFeatureExtractor  # noqa: F401  (existence check)

    frames = _build_synthetic_frames()

    runner = BenchmarkRunner(dataset=DatasetName.CAR_HACKING, files={})

    import benchmark.benchmark_runner as br_module
    fake_report_root = str(tmp_path / "reports_real")
    monkeypatch.setattr(br_module, "REPORT_ROOT", fake_report_root)

    X, y, extractor = runner.build_matrix(frames)
    report = runner.train_eval(frames, X, y, extractor)
    clean_report = {k: v for k, v in report.items() if not k.startswith("_")}

    _assert_report_valid(clean_report)
    runner._save_report(report)

    out_dir = os.path.join(fake_report_root, "car_hacking")
    assert os.path.isfile(os.path.join(out_dir, "report.json"))


def test_build_matrix_raises_clear_error_when_features_missing(monkeypatch):
    """If benchmark.features truly can't be imported, build_matrix should
    raise a clear, actionable ImportError rather than a cryptic failure."""
    import sys

    # Simulate "module not available" by removing it from sys.modules and
    # making a fresh import of it fail, regardless of whether the parallel
    # features subagent has landed benchmark/features.py in this checkout.
    monkeypatch.setitem(sys.modules, "benchmark.features", None)

    runner = BenchmarkRunner(dataset=DatasetName.CAR_HACKING, files={})
    with pytest.raises(ImportError):
        runner.build_matrix([])
