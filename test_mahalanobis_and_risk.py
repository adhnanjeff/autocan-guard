#!/usr/bin/env python3
"""
Quick test for the Mahalanobis pre-filter and risk-index additions.

Verifies:
  1. Mahalanobis score is 0.0 during warm-up, then discriminates normal vs.
     clearly anomalous feature vectors once warmed up.
  2. Context buckets are isolated from each other (an idle baseline doesn't
     wrongly flag cruise-speed traffic as anomalous).
  3. Poisoning resistance: samples the detector itself scores as anomalous
     are not folded into the baseline.
  4. Risk index responds to trust/anomaly/context inputs and to per-signal
     criticality weighting (steering > speed for the same inputs).
"""

import sys
sys.path.insert(0, '/Users/adhnanjeff/Desktop/Final Project')

from mahalanobis_detector import AdaptiveMahalanobisDetector, FEATURE_NAMES
from risk_index import compute_risk_index, risk_level

print("=" * 60)
print("Testing Mahalanobis Pre-Filter + Risk Index")
print("=" * 60)

# ---------------------------------------------------------------------------
# 1 & 3: warm-up, discrimination, poisoning resistance
# ---------------------------------------------------------------------------
detector = AdaptiveMahalanobisDetector(min_samples=20, poisoning_score_threshold=0.9)

normal_features = {name: 1.0 for name in FEATURE_NAMES}
normal_features["frequency"] = 10.0
normal_features["jitter"] = 0.1

print("\n📊 Warm-up phase (< min_samples)...")
warm_up_scores = []
for i in range(20):
    # Small deterministic jitter around the normal baseline
    features = dict(normal_features)
    features["value_variance"] = 1.0 + (i % 3) * 0.01
    score = detector.observe_and_update("steering", features, speed=50.0)
    warm_up_scores.append(score)

assert all(s == 0.0 for s in warm_up_scores), f"Expected all-zero warm-up scores, got {warm_up_scores}"
print(f"✅ All {len(warm_up_scores)} warm-up scores are 0.0")

print("\n🔍 Post-warm-up: normal vs. attack feature vectors...")
# Feed a few more in-distribution samples so the covariance is non-degenerate
for i in range(10):
    features = dict(normal_features)
    features["value_variance"] = 1.0 + (i % 3) * 0.01
    detector.observe_and_update("steering", features, speed=50.0)

normal_score = detector.score("steering", normal_features, speed=50.0)
print(f"   Normal feature vector score: {normal_score:.4f}")

attack_features = dict(normal_features)
attack_features["frequency"] = 500.0     # extreme flood-like frequency
attack_features["jitter"] = 80.0         # wildly irregular timing
attack_features["z_score"] = 12.0        # far outlier
attack_score = detector.score("steering", attack_features, speed=50.0)
print(f"   Attack feature vector score:  {attack_score:.4f}")

assert normal_score < 0.5, f"Normal traffic scored too high: {normal_score}"
assert attack_score > normal_score, "Attack score should exceed normal score"
print("✅ Detector discriminates normal vs. anomalous traffic")

print("\n🛡️ Poisoning resistance...")
status_before = detector.get_status()[("steering", "cruise") if False else "steering:cruise"]["samples"]
detector.observe_and_update("steering", attack_features, speed=50.0)  # should NOT be folded in
status_after = detector.get_status()["steering:cruise"]["samples"]
assert status_before == status_after, "Anomalous sample should not update the baseline"
print(f"✅ Baseline sample count unchanged after anomalous input ({status_before} -> {status_after})")

# ---------------------------------------------------------------------------
# 2: context buckets are isolated
# ---------------------------------------------------------------------------
print("\n🚦 Context bucket isolation...")
idle_detector = AdaptiveMahalanobisDetector(min_samples=15)
idle_features = {name: 0.1 for name in FEATURE_NAMES}
for _ in range(20):
    idle_detector.observe_and_update("speed", idle_features, speed=0.0)  # idle bucket

# A cruise-speed message with very different (but internally consistent)
# feature values should not inherit the idle bucket's tight baseline, since
# the "cruise" bucket has no samples yet -> warm-up -> score 0.0
cruise_features = {name: 5.0 for name in FEATURE_NAMES}
cruise_score = idle_detector.score("speed", cruise_features, speed=50.0)
assert cruise_score == 0.0, f"Expected warm-up 0.0 for untrained cruise bucket, got {cruise_score}"
print("✅ Cruise-speed bucket is untouched by the idle-speed baseline (warm-up score 0.0)")

assert idle_detector.context_bucket(0.0) == "idle"
assert idle_detector.context_bucket(20.0) == "low"
assert idle_detector.context_bucket(50.0) == "cruise"
assert idle_detector.context_bucket(90.0) == "high"
print("✅ context_bucket() maps speeds to the expected regimes")

# ---------------------------------------------------------------------------
# 4: risk index
# ---------------------------------------------------------------------------
print("\n⚠️  Risk index...")
low_risk = compute_risk_index(trust_score=1.0, anomaly_severity=0.0, contextual_violation_score=0.0, signal_name="steering")
high_risk_steering = compute_risk_index(trust_score=0.2, anomaly_severity=0.9, contextual_violation_score=0.8, signal_name="steering")
high_risk_speed = compute_risk_index(trust_score=0.2, anomaly_severity=0.9, contextual_violation_score=0.8, signal_name="speed")

print(f"   Fully trusted, no anomaly (steering): {low_risk:.4f}")
print(f"   Low trust + high anomaly (steering):  {high_risk_steering:.4f}")
print(f"   Low trust + high anomaly (speed):     {high_risk_speed:.4f}")

assert low_risk == 0.0, f"Expected 0.0 risk for perfect trust/no anomaly, got {low_risk}"
assert high_risk_steering > 0.5, "High anomaly + low trust on steering should be high risk"
assert high_risk_speed < high_risk_steering, "Speed (lower criticality) should score below steering for identical inputs"
assert 0.0 <= low_risk <= 1.0 and 0.0 <= high_risk_steering <= 1.0 and 0.0 <= high_risk_speed <= 1.0
print("✅ Risk index responds correctly to inputs and per-signal criticality weighting")

assert risk_level(0.0) == "LOW"
assert risk_level(0.9) == "SEVERE"
print("✅ risk_level() categorization correct")

print("\n" + "=" * 60)
print("All Mahalanobis + Risk Index tests passed!")
print("=" * 60)
