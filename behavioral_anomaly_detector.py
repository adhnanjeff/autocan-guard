"""
Phase 5: Behavioral Anomaly Detection
ML-based detection using sender behavioral features
"""

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from collections import defaultdict, deque
import time
from typing import Dict, List, Tuple

class BehavioralAnomalyDetector:
    def __init__(self):
        # Per-sender models and scalers
        self.sender_models = {}
        self.sender_scalers = {}
        self.sender_training_data = defaultdict(list)
        self.sender_training_mode = defaultdict(lambda: True)
        
        # Training parameters
        self.min_training_samples = 30
        self.max_training_samples = 100
        
        # Statistical baselines for fallback
        self.sender_baselines = defaultdict(lambda: {
            'mean': defaultdict(float),
            'std': defaultdict(float),
            'samples': 0
        })
        
    def add_training_sample(self, device_id: str, features: Dict[str, float]):
        """Add training sample for a sender"""
        if not self.sender_training_mode[device_id]:
            return
            
        feature_vector = self._features_to_vector(features)
        self.sender_training_data[device_id].append(feature_vector)
        
        # Update statistical baseline
        baseline = self.sender_baselines[device_id]
        baseline['samples'] += 1
        for key, value in features.items():
            # Running mean and variance
            n = baseline['samples']
            old_mean = baseline['mean'][key]
            baseline['mean'][key] = old_mean + (value - old_mean) / n
            if n > 1:
                baseline['std'][key] = np.sqrt(
                    ((n - 2) * baseline['std'][key]**2 + (value - old_mean) * (value - baseline['mean'][key])) / (n - 1)
                )
        
        # Train model when enough samples
        if len(self.sender_training_data[device_id]) >= self.min_training_samples:
            self._train_sender_model(device_id)
            
    def _train_sender_model(self, device_id: str):
        """Train Isolation Forest for a sender"""
        training_data = np.array(self.sender_training_data[device_id])
        
        if len(training_data) < self.min_training_samples:
            return
            
        try:
            # Standardize features
            scaler = StandardScaler()
            scaled_data = scaler.fit_transform(training_data)
            
            # Train Isolation Forest
            model = IsolationForest(
                contamination=0.1,  # Expect 10% anomalies
                random_state=42,
                n_estimators=50
            )
            model.fit(scaled_data)
            
            # Store model and scaler
            self.sender_models[device_id] = model
            self.sender_scalers[device_id] = scaler
            self.sender_training_mode[device_id] = False
            
            print(f"✅ Behavioral model trained for {device_id} with {len(training_data)} samples")
            
        except Exception as e:
            print(f"❌ Failed to train model for {device_id}: {e}")
            
    def detect_anomaly(self, device_id: str, features: Dict[str, float]) -> Tuple[float, str]:
        """Detect behavioral anomaly for a sender"""
        # If still in training mode, add sample and return normal
        if self.sender_training_mode[device_id]:
            self.add_training_sample(device_id, features)
            return 0.0, "training"
            
        # Try ML model first
        if device_id in self.sender_models:
            try:
                return self._ml_detection(device_id, features)
            except Exception as e:
                print(f"ML detection failed for {device_id}: {e}")
                
        # Fallback to statistical detection
        return self._statistical_detection(device_id, features)
        
    def _ml_detection(self, device_id: str, features: Dict[str, float]) -> Tuple[float, str]:
        """ML-based anomaly detection"""
        model = self.sender_models[device_id]
        scaler = self.sender_scalers[device_id]
        
        feature_vector = self._features_to_vector(features).reshape(1, -1)
        scaled_features = scaler.transform(feature_vector)
        
        # Get anomaly score
        anomaly_score = model.decision_function(scaled_features)[0]
        is_anomaly = model.predict(scaled_features)[0] == -1
        
        # Convert to [0,1] range (higher = more anomalous)
        normalized_score = max(0.0, min(1.0, (0.5 - anomaly_score) / 1.0))
        
        reason = "ml_anomaly" if is_anomaly else "ml_normal"
        return normalized_score, reason
        
    def _statistical_detection(self, device_id: str, features: Dict[str, float]) -> Tuple[float, str]:
        """Statistical baseline detection"""
        baseline = self.sender_baselines[device_id]
        
        if baseline['samples'] < 5:
            return 0.0, "insufficient_data"
            
        max_z_score = 0.0
        anomalous_feature = ""
        
        for key, value in features.items():
            mean = baseline['mean'][key]
            std = baseline['std'][key]
            
            if std > 0:
                z_score = abs(value - mean) / std
                if z_score > max_z_score:
                    max_z_score = z_score
                    anomalous_feature = key
                    
        # Convert z-score to [0,1] anomaly score
        anomaly_score = min(1.0, max_z_score / 3.0)  # 3-sigma rule
        
        reason = f"statistical_{anomalous_feature}" if anomaly_score > 0.5 else "statistical_normal"
        return anomaly_score, reason
        
    def _features_to_vector(self, features: Dict[str, float]) -> np.ndarray:
        """Convert feature dict to numpy vector with enhanced features"""
        # Enhanced feature order with control energy and context
        feature_order = [
            'message_rate', 'value_entropy', 'delta_pattern', 'timing_jitter', 'topic_distribution',
            'steering_energy', 'steering_jerk', 'oscillation_rate', 'control_aggression', 
            'context_violation', 'context_violation_count'
        ]
        return np.array([features.get(key, 0.0) for key in feature_order])
        
    def get_sender_status(self, device_id: str) -> Dict[str, any]:
        """Get training/detection status for a sender"""
        return {
            'training_mode': self.sender_training_mode[device_id],
            'training_samples': len(self.sender_training_data[device_id]),
            'has_model': device_id in self.sender_models,
            'baseline_samples': self.sender_baselines[device_id]['samples']
        }
        
    def get_all_senders(self) -> List[str]:
        """Get all tracked senders"""
        all_senders = set()
        all_senders.update(self.sender_training_data.keys())
        all_senders.update(self.sender_models.keys())
        all_senders.update(self.sender_baselines.keys())
        return list(all_senders)