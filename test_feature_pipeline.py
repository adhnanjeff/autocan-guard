#!/usr/bin/env python3
"""
Quick test to verify feature extraction pipeline is working correctly
"""

import sys
import time
sys.path.insert(0, '/Users/adhnanjeff/Desktop/Final Project')

from feature_extractor import FeatureExtractor
from anomaly_detector import AnomalyDetector

print("=" * 60)
print("Testing Feature Extraction Pipeline")
print("=" * 60)

# Initialize components
extractor = FeatureExtractor()
detector = AnomalyDetector()

# Simulate some CAN messages
print("\n📊 Generating test features...")
base_time = time.time()
for i in range(30):
    t = base_time + i * 0.05  # 50ms intervals
    # Simulate steering, speed, brake messages
    extractor.add_message("steering", t, 50 + (i % 10))
    extractor.add_message("speed", t, 60 + (i * 2 % 40))
    extractor.add_message("brake", t, 10 + (i * 3 % 30))

# Get features
features = extractor.get_all_features()
print(f"\n✅ Extracted features for signals: {list(features.keys())}")

# Check feature count per signal
for signal, signal_features in features.items():
    print(f"   {signal}: {len(signal_features)} features")
    print(f"      Features: {list(signal_features.keys())}")

# Test prepare_features
print("\n🔧 Testing prepare_features()...")
feature_vector = detector.prepare_features(features)
if feature_vector is not None:
    print(f"✅ Feature vector shape: {feature_vector.shape}")
    print(f"   Expected: (1, {len(detector.feature_names) * len(detector.signal_order)})")
    print(f"   Actual: {feature_vector.shape}")
    
    if feature_vector.shape[1] == len(detector.feature_names) * len(detector.signal_order):
        print("✅ FEATURE DIMENSIONS MATCH!")
    else:
        print(f"❌ MISMATCH: Got {feature_vector.shape[1]}, expected {len(detector.feature_names) * len(detector.signal_order)}")
else:
    print("❌ Feature vector is None!")

# Test training
print("\n📚 Testing training...")
training_data = []
for i in range(25):
    training_data.append(features)  # Use same features as baseline

success = detector.train(training_data)
if success:
    print("✅ TRAINING SUCCESSFUL!")
else:
    print("❌ Training failed")

# Test detection
if detector.is_trained:
    print("\n🔍 Testing detection...")
    anomaly_score = detector.detect_anomaly(features)
    print(f"   Normal features anomaly score: {anomaly_score:.4f}")
    
    # Test with modified features (simulated attack)
    attack_features = features.copy()
    for signal in attack_features:
        if isinstance(attack_features[signal], dict):
            attack_features[signal]['frequency'] = 100.0  # Abnormal frequency
            attack_features[signal]['jitter'] = 50.0  # Abnormal jitter
    
    attack_score = detector.detect_anomaly(attack_features)
    print(f"   Attack features anomaly score: {attack_score:.4f}")

print("\n" + "=" * 60)
print("Test Complete!")
print("=" * 60)
