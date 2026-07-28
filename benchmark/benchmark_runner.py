"""Benchmark runner: load -> extract features -> train -> evaluate -> report.

Owns a small, dimension-agnostic ``BenchmarkModel`` (RandomForest +
GradientBoosting ensemble, optionally an IsolationForest anomaly score) that
is completely independent of ``anomaly_detector.py``. The existing runtime
detector is hardwired to a fixed 48-dim steering/speed/brake feature vector
and must stay untouched; this benchmark operates on whatever feature length
``benchmark.features.CanFeatureExtractor`` produces for CAN-IDS datasets.
"""

from __future__ import annotations

import json
import os
import time
from typing import Dict, List, Optional

import numpy as np

from .can_frame import CanFrame
from .config import (
    DEFAULT_RANDOM_STATE,
    DEFAULT_TEST_SIZE,
    DEFAULT_WINDOW_SEC,
    REPORT_ROOT,
)
from .loaders.base import DatasetName, get_loader
from .metrics import classification_metrics, latency_throughput, per_attack_breakdown


class BenchmarkModel:
    """Small dimension-agnostic ensemble classifier.

    Wraps sklearn's RandomForestClassifier (primary) and
    GradientBoostingClassifier, averaging predicted attack-class
    probabilities and thresholding at 0.5. Also fits an IsolationForest on
    the normal (label==0) training rows and exposes its anomaly score, but
    the IsolationForest does NOT drive the final prediction — RF+GB do.

    This class is local to the benchmark package and intentionally does not
    import or reuse ``anomaly_detector.py``.
    """

    def __init__(self, random_state: int = DEFAULT_RANDOM_STATE) -> None:
        from sklearn.ensemble import (
            GradientBoostingClassifier,
            IsolationForest,
            RandomForestClassifier,
        )

        self.random_state = random_state
        self.rf = RandomForestClassifier(
            n_estimators=200,
            max_depth=None,
            random_state=random_state,
            n_jobs=-1,
            class_weight="balanced",
        )
        self.gb = GradientBoostingClassifier(random_state=random_state)
        self.iso = IsolationForest(random_state=random_state, contamination="auto")
        self._fitted = False

    def fit(self, X: np.ndarray, y: np.ndarray) -> "BenchmarkModel":
        X = np.asarray(X, dtype=float)
        y = np.asarray(y, dtype=int)

        self.rf.fit(X, y)
        self.gb.fit(X, y)

        normal_rows = X[y == 0]
        if normal_rows.shape[0] >= 2:
            self.iso.fit(normal_rows)
        else:
            # Not enough normal rows to fit a meaningful IsolationForest;
            # fall back to fitting on everything so predict_anomaly_score
            # still works without raising.
            self.iso.fit(X)

        self._fitted = True
        return self

    def predict_proba_row(self, x_row: np.ndarray) -> float:
        """Predicted probability of the attack class (1) for one row."""
        x_row = np.asarray(x_row, dtype=float).reshape(1, -1)
        rf_proba = self._positive_proba(self.rf, x_row)
        gb_proba = self._positive_proba(self.gb, x_row)
        return float((rf_proba + gb_proba) / 2.0)

    def predict_row(self, x_row: np.ndarray, threshold: float = 0.5) -> int:
        return int(self.predict_proba_row(x_row) >= threshold)

    def predict(self, X: np.ndarray, threshold: float = 0.5) -> np.ndarray:
        X = np.asarray(X, dtype=float)
        rf_proba = self._positive_proba(self.rf, X)
        gb_proba = self._positive_proba(self.gb, X)
        avg = (rf_proba + gb_proba) / 2.0
        return (avg >= threshold).astype(int)

    def anomaly_score(self, X: np.ndarray) -> np.ndarray:
        """Higher = more anomalous (sklearn's score_samples is inverted)."""
        X = np.asarray(X, dtype=float)
        return -self.iso.score_samples(X)

    @staticmethod
    def _positive_proba(clf, X: np.ndarray) -> np.ndarray:
        proba = clf.predict_proba(X)
        classes = list(clf.classes_)
        if 1 in classes:
            return proba[:, classes.index(1)]
        # Degenerate case: classifier only ever saw one class during fit.
        return np.zeros(proba.shape[0], dtype=float)

    def describe(self) -> str:
        return (
            "BenchmarkModel: average of RandomForestClassifier(n_estimators=200, "
            "class_weight=balanced) and GradientBoostingClassifier probabilities, "
            "threshold=0.5. IsolationForest fitted on normal training rows for an "
            "auxiliary anomaly score (not used in the final prediction)."
        )


class BenchmarkRunner:
    """Runs the full load -> feature -> train -> eval -> report pipeline."""

    def __init__(
        self,
        dataset: DatasetName,
        files: Dict[str, str],
        window_sec: Optional[float] = None,
        test_size: Optional[float] = None,
        random_state: Optional[int] = None,
        max_frames: Optional[int] = None,
        feature_set: str = "full",
    ) -> None:
        self.dataset = DatasetName(dataset)
        self.files = files
        self.window_sec = window_sec if window_sec is not None else DEFAULT_WINDOW_SEC
        self.test_size = test_size if test_size is not None else DEFAULT_TEST_SIZE
        self.random_state = random_state if random_state is not None else DEFAULT_RANDOM_STATE
        self.max_frames = max_frames
        # "full" = 14-feature CanFeatureExtractor; "paper5" = the paper's
        # 5-feature vector (PaperFeatureExtractor).
        self.feature_set = feature_set

    # ------------------------------------------------------------------
    # Loading
    # ------------------------------------------------------------------
    def load_frames(self) -> List[CanFrame]:
        """Load frames for every (attack_type, path) entry and sort by time."""
        all_frames: List[CanFrame] = []
        for attack_type, path in self.files.items():
            kwargs = {}
            # 'normal' / 'attack_free' entries carry no attack_type tag.
            if attack_type not in ("normal", "attack_free"):
                kwargs["attack_type"] = attack_type
            if self.max_frames is not None:
                kwargs["max_frames"] = self.max_frames
            loader = get_loader(self.dataset, path, **kwargs)
            all_frames.extend(loader.load())

        all_frames.sort(key=lambda f: f.timestamp)
        return all_frames

    # ------------------------------------------------------------------
    # Feature extraction
    # ------------------------------------------------------------------
    def build_matrix(self, frames: List[CanFrame]):
        """Extract features for ``frames`` (in order). Returns (X, y, extractor)."""
        try:
            from .features import CanFeatureExtractor, PaperFeatureExtractor
        except ImportError as exc:  # pragma: no cover - exercised via tests
            raise ImportError(
                "benchmark.features is not available. The runner requires the "
                "feature-extraction module to build the training matrix."
            ) from exc

        if self.feature_set == "paper5":
            extractor = PaperFeatureExtractor(window_sec=self.window_sec)
        else:
            extractor = CanFeatureExtractor(window_sec=self.window_sec)
        X = extractor.extract_batch(frames)
        y = np.array([f.label for f in frames], dtype=int)
        return np.asarray(X, dtype=float), y, extractor

    # ------------------------------------------------------------------
    # Train + evaluate
    # ------------------------------------------------------------------
    def train_eval(self, frames: List[CanFrame], X: np.ndarray, y: np.ndarray, extractor) -> dict:
        from sklearn.model_selection import train_test_split
        from sklearn.preprocessing import StandardScaler

        n = len(frames)
        indices = np.arange(n)

        strat = y if len(np.unique(y)) > 1 else None
        idx_train, idx_test = train_test_split(
            indices,
            test_size=self.test_size,
            random_state=self.random_state,
            stratify=strat,
        )

        X_train, X_test = X[idx_train], X[idx_test]
        y_train, y_test = y[idx_train], y[idx_test]
        frames_test = [frames[i] for i in idx_test]

        # Normalize features ("normalized feature vector"): fit the scaler on the
        # TRAINING split only, then transform both splits, so no test-set
        # statistics leak into training.
        scaler = StandardScaler()
        X_train = scaler.fit_transform(X_train)
        X_test = scaler.transform(X_test)

        model = BenchmarkModel(random_state=self.random_state)
        model.fit(X_train, y_train)

        # Per-message inference latency: time model.predict on one
        # precomputed feature row at a time (timed section = model
        # inference only; feature extraction is precomputed above).
        y_pred = np.empty(len(idx_test), dtype=int)
        per_msg_seconds: List[float] = []
        for i in range(len(idx_test)):
            row = X_test[i]
            start = time.perf_counter()
            pred = model.predict_row(row)
            elapsed = time.perf_counter() - start
            per_msg_seconds.append(elapsed)
            y_pred[i] = pred

        cls_metrics = classification_metrics(y_test.tolist(), y_pred.tolist())
        lat_metrics = latency_throughput(per_msg_seconds)
        attack_breakdown = per_attack_breakdown(frames_test, y_pred.tolist())

        class_balance = {
            "normal": int(np.sum(y == 0)),
            "attack": int(np.sum(y == 1)),
        }

        feature_names = getattr(extractor, "feature_names", None)
        if feature_names is None:
            feature_names = [f"f{i}" for i in range(X.shape[1])]

        report = {
            "dataset": self.dataset.value,
            "n_frames": n,
            "n_train": len(idx_train),
            "n_test": len(idx_test),
            "class_balance": class_balance,
            "classification_metrics": cls_metrics,
            "latency_throughput": lat_metrics,
            "per_attack_breakdown": attack_breakdown,
            "feature_names": list(feature_names),
            "feature_set": self.feature_set,
            "normalized": True,
            "model_description": model.describe(),
        }

        # Stash intermediate artifacts for run()/graphing without
        # recomputing them.
        report["_test_frames"] = frames_test
        report["_y_test"] = y_test
        report["_y_pred"] = y_pred
        report["_per_msg_seconds"] = per_msg_seconds
        return report

    # ------------------------------------------------------------------
    # Orchestration + persistence
    # ------------------------------------------------------------------
    def run(self, save: bool = True) -> dict:
        frames = self.load_frames()
        X, y, extractor = self.build_matrix(frames)
        report = self.train_eval(frames, X, y, extractor)

        if save:
            self._save_report(report)

        # Strip internal-only keys before returning to the caller so the
        # report stays JSON-clean; graphs are already written by _save_report
        # using the stashed data.
        clean_report = {k: v for k, v in report.items() if not k.startswith("_")}
        return clean_report

    def _save_report(self, report: dict) -> None:
        out_dir = os.path.join(REPORT_ROOT, self.dataset.value)
        os.makedirs(out_dir, exist_ok=True)

        clean_report = {k: v for k, v in report.items() if not k.startswith("_")}
        report_path = os.path.join(out_dir, "report.json")
        with open(report_path, "w") as fh:
            json.dump(clean_report, fh, indent=2)

        self._save_graphs(report, out_dir)

    @staticmethod
    def _save_graphs(report: dict, out_dir: str) -> None:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt

        # --- Confusion matrix heatmap ---
        confusion = report["classification_metrics"]["confusion"]
        cm = np.array([
            [confusion["tn"], confusion["fp"]],
            [confusion["fn"], confusion["tp"]],
        ])
        fig, ax = plt.subplots(figsize=(4, 4))
        im = ax.imshow(cm, cmap="Blues")
        ax.set_xticks([0, 1])
        ax.set_yticks([0, 1])
        ax.set_xticklabels(["Pred Normal", "Pred Attack"])
        ax.set_yticklabels(["True Normal", "True Attack"])
        for i in range(2):
            for j in range(2):
                ax.text(j, i, str(cm[i, j]), ha="center", va="center", color="black")
        ax.set_title("Confusion Matrix")
        fig.colorbar(im, ax=ax)
        fig.tight_layout()
        fig.savefig(os.path.join(out_dir, "confusion_matrix.png"))
        plt.close(fig)

        # --- Per-attack recall bar chart ---
        breakdown = {k: v for k, v in report["per_attack_breakdown"].items() if k != "normal"}
        fig, ax = plt.subplots(figsize=(max(4, len(breakdown) * 1.2), 4))
        if breakdown:
            labels = list(breakdown.keys())
            recalls = [breakdown[k]["recall"] for k in labels]
            ax.bar(labels, recalls, color="tab:orange")
            ax.set_ylim(0, 1)
            ax.set_ylabel("Recall")
            ax.set_title("Per-Attack Recall")
            plt.setp(ax.get_xticklabels(), rotation=30, ha="right")
        else:
            ax.text(0.5, 0.5, "No attack types in test set", ha="center", va="center")
        fig.tight_layout()
        fig.savefig(os.path.join(out_dir, "per_attack_recall.png"))
        plt.close(fig)

        # --- Latency histogram ---
        per_msg_seconds = report.get("_per_msg_seconds", [])
        fig, ax = plt.subplots(figsize=(5, 4))
        if per_msg_seconds:
            ms = np.asarray(per_msg_seconds) * 1000.0
            ax.hist(ms, bins=30, color="tab:green")
        ax.set_xlabel("Inference latency (ms)")
        ax.set_ylabel("Count")
        ax.set_title("Per-Message Latency")
        fig.tight_layout()
        fig.savefig(os.path.join(out_dir, "latency_histogram.png"))
        plt.close(fig)
