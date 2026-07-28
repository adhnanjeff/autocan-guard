"""
Context-Aware Adaptive Mahalanobis Anomaly Detector

A lightweight, fast pre-filter that runs on every CAN message BEFORE the
heavier ensemble in anomaly_detector.py (IsolationForest/SVM/RandomForest/
GradientBoosting). It contributes its own anomaly score alongside the
ensemble rather than gating/skipping it, so detection recall is never
reduced by this addition - it only adds an extra, cheap, independent signal.

Design
------
* Context-aware: normal feature statistics are learned separately per driving
  regime (speed bucket), because "normal" jitter/variance while idle differs
  from "normal" while cruising. Each (signal_name, context_bucket) pair keeps
  its own mean vector and covariance matrix over the same 16-dim feature
  space used by feature_extractor.py / anomaly_detector.py.
* Adaptive: mean/covariance are updated online (Welford's algorithm,
  generalized to the multivariate case) as new normal traffic arrives, with a
  bounded effective sample size so the baseline can track slow legitimate
  drift (an exponential-forgetting behaviour once warmed up), rather than
  being permanently anchored to the first N samples.
* Poisoning-resistant: callers should only feed samples back into the
  baseline when they are not already suspected anomalous (see
  `observe_and_update`), so an ongoing attack cannot corrupt what "normal"
  means for that bucket.

The Mahalanobis distance D^2 of a feature vector from its bucket's mean,
under the (bucket-local) Gaussian assumption, follows a chi-squared
distribution with d degrees of freedom during normal operation. Converting
D^2 through the chi-squared CDF gives a principled anomaly score in [0, 1]:
the fraction of normal traffic expected to be at least this close to the
mean, i.e. score = 1 means "further from normal than virtually all normal
traffic in this context."
"""

from __future__ import annotations

from typing import Dict, Optional, Tuple

import numpy as np
from scipy.stats import chi2

# Same 16-dim feature space as feature_extractor.py / anomaly_detector.py, so
# a signal's feature dict can be passed through unchanged.
FEATURE_NAMES = [
    "frequency", "delta", "jitter", "value_variance", "rate_of_change",
    "max_deviation", "z_score", "freq_deviation", "entropy", "kurtosis",
    "skewness", "autocorr", "peak_density", "mad", "value_range", "cv",
]

# Driving-context speed buckets (km/h). Each bucket gets its own baseline.
DEFAULT_CONTEXT_BUCKETS = (
    ("idle", 0.0, 5.0),
    ("low", 5.0, 30.0),
    ("cruise", 30.0, 70.0),
    ("high", 70.0, float("inf")),
)


class _BucketBaseline:
    """Online mean/covariance for one (signal, context bucket) pair."""

    def __init__(self, dim: int, max_effective_n: int, reg_eps: float):
        self.dim = dim
        self.max_effective_n = max_effective_n
        self.reg_eps = reg_eps
        self.n = 0
        self.mean = np.zeros(dim, dtype=float)
        self.m2 = np.zeros((dim, dim), dtype=float)

    def update(self, x: np.ndarray) -> None:
        """Welford-style online mean/covariance update with bounded memory.

        Once ``n`` reaches ``max_effective_n`` it is held there, so each new
        sample carries a constant weight (~1/max_effective_n) going forward -
        an exponential-forgetting behaviour that lets the baseline track slow
        legitimate drift instead of being frozen at the first N samples.
        """
        self.n = min(self.n + 1, self.max_effective_n)
        delta = x - self.mean
        self.mean += delta / self.n
        delta2 = x - self.mean
        self.m2 += np.outer(delta, delta2)

    def is_ready(self, min_samples: int) -> bool:
        return self.n >= min_samples

    def covariance(self) -> np.ndarray:
        denom = max(self.n - 1, 1)
        cov = self.m2 / denom
        # Shrinkage regularization: keeps the matrix invertible even with few
        # samples or near-constant features, without materially distorting a
        # well-conditioned covariance once enough data has accumulated.
        return cov + self.reg_eps * np.eye(self.dim)

    def mahalanobis_sq(self, x: np.ndarray) -> float:
        cov = self.covariance()
        try:
            inv_cov = np.linalg.inv(cov)
        except np.linalg.LinAlgError:
            inv_cov = np.linalg.pinv(cov)
        delta = x - self.mean
        d2 = float(delta @ inv_cov @ delta)
        return max(0.0, d2)


class AdaptiveMahalanobisDetector:
    """Fast, context-aware, adaptive Mahalanobis pre-filter.

    Usage per message (mirrors anomaly_detector.AnomalyDetector's contract):
        score = detector.observe_and_update(signal_name, features_dict, speed)
    """

    def __init__(
        self,
        min_samples: int = 25,
        max_effective_n: int = 1500,
        reg_eps: float = 1e-3,
        poisoning_score_threshold: float = 0.9,
        context_buckets: Tuple[Tuple[str, float, float], ...] = DEFAULT_CONTEXT_BUCKETS,
        tau0: Optional[float] = None,
        alpha: float = 2.0,
        beta: float = 3.0,
    ) -> None:
        self.min_samples = min_samples
        self.max_effective_n = max_effective_n
        self.reg_eps = reg_eps
        self.poisoning_score_threshold = poisoning_score_threshold
        self.context_buckets = context_buckets
        self.dim = len(FEATURE_NAMES)
        self._baselines: Dict[Tuple[str, str], _BucketBaseline] = {}

        # --- Adaptive-threshold parameters (paper Eq. 1) --------------------
        # τ(t) = τ0 + α·T(t) + β·σ̂s(t), a threshold on the Mahalanobis DISTANCE
        # D_M (not the CDF score). τ0 is the base threshold; α scales the trust
        # term (a more-trusted sender gets a more lenient threshold); β scales
        # the normalized recent-state variability σ̂s (during rash but legitimate
        # driving, state variability rises, so the threshold rises to suppress
        # false alarms). Both added terms are non-negative, so τ never drops
        # below τ0 — the threshold only relaxes, which is the intended behavior.
        if tau0 is None:
            # Default base = distance at the chi-squared 0.99 quantile for this
            # feature dimension (D_M is chi-distributed with `dim` dof under normal).
            tau0 = float(np.sqrt(chi2.ppf(0.99, df=self.dim)))
        self.tau0 = tau0
        self.alpha = alpha
        self.beta = beta

    def context_bucket(self, speed: float) -> str:
        for name, low, high in self.context_buckets:
            if low <= speed < high:
                return name
        return self.context_buckets[-1][0]

    def _vector(self, features: Dict[str, float]) -> np.ndarray:
        return np.array(
            [float(features.get(name, 0.0)) for name in FEATURE_NAMES], dtype=float
        )

    def _baseline(self, signal_name: str, bucket: str) -> _BucketBaseline:
        key = (signal_name, bucket)
        if key not in self._baselines:
            self._baselines[key] = _BucketBaseline(
                dim=self.dim,
                max_effective_n=self.max_effective_n,
                reg_eps=self.reg_eps,
            )
        return self._baselines[key]

    def score(self, signal_name: str, features: Dict[str, float], speed: float) -> float:
        """Anomaly score in [0, 1] without updating the baseline.

        Returns 0.0 during warm-up (fewer than ``min_samples`` observations
        for this signal/context bucket), matching the "not trained -> 0.0"
        convention used elsewhere in the pipeline.
        """
        if not features:
            return 0.0
        bucket = self.context_bucket(speed)
        baseline = self._baseline(signal_name, bucket)
        if not baseline.is_ready(self.min_samples):
            return 0.0
        x = self._vector(features)
        d2 = baseline.mahalanobis_sq(x)
        return float(chi2.cdf(d2, df=self.dim))

    def mahalanobis_distance(self, signal_name: str, features: Dict[str, float], speed: float) -> float:
        """Raw Mahalanobis distance D_M of a message from its context baseline.

        Returns 0.0 during warm-up (baseline not yet ready), matching the
        "not trained -> no anomaly" convention. This is the quantity compared
        against the adaptive threshold in ``adaptive_decision``.
        """
        if not features:
            return 0.0
        bucket = self.context_bucket(speed)
        baseline = self._baseline(signal_name, bucket)
        if not baseline.is_ready(self.min_samples):
            return 0.0
        d2 = baseline.mahalanobis_sq(self._vector(features))
        return float(np.sqrt(d2))

    def adaptive_threshold(self, trust: float, state_variability: float) -> float:
        """Context-aware adaptive threshold τ(t) = τ0 + α·T(t) + β·σ̂s(t).

        Args:
            trust: current trust score T(t) in [0, 1].
            state_variability: normalized recent vehicle-state variability
                σ̂s(t) in [0, 1] (e.g. rescaled variance/std of recent speeds).
        Both terms are clamped to [0, 1] so the threshold rises above τ0 by a
        bounded amount and never falls below it.
        """
        t = min(1.0, max(0.0, float(trust)))
        s = min(1.0, max(0.0, float(state_variability)))
        return self.tau0 + self.alpha * t + self.beta * s

    def adaptive_decision(
        self, signal_name: str, features: Dict[str, float], speed: float,
        trust: float, state_variability: float,
    ) -> Dict[str, float]:
        """Evaluate a message against the adaptive Mahalanobis threshold.

        Returns a dict with the distance ``D_M``, the adaptive threshold
        ``tau``, a boolean-as-float ``is_anomaly`` (D_M > tau), and the
        chi-squared-CDF ``score`` in [0, 1] (kept for fusion/reporting).
        During warm-up D_M is 0.0, so ``is_anomaly`` is False.
        """
        d_m = self.mahalanobis_distance(signal_name, features, speed)
        tau = self.adaptive_threshold(trust, state_variability)
        return {
            "distance": d_m,
            "threshold": tau,
            "is_anomaly": 1.0 if d_m > tau else 0.0,
            "score": self.score(signal_name, features, speed),
        }

    def observe_and_update(
        self, signal_name: str, features: Dict[str, float], speed: float
    ) -> float:
        """Score a message, then fold it into the baseline unless it looks
        anomalous (poisoning defense: don't let a live attack redefine
        "normal"). Returns the score computed BEFORE the update.
        """
        if not features:
            return 0.0
        score = self.score(signal_name, features, speed)
        if score < self.poisoning_score_threshold:
            bucket = self.context_bucket(speed)
            baseline = self._baseline(signal_name, bucket)
            baseline.update(self._vector(features))
        return score

    def get_status(self) -> Dict[str, Dict[str, float]]:
        """Per (signal, bucket) sample counts - useful for dashboards/debugging."""
        return {
            f"{signal}:{bucket}": {"samples": baseline.n, "ready": baseline.is_ready(self.min_samples)}
            for (signal, bucket), baseline in self._baselines.items()
        }
