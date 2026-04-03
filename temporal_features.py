"""
Temporal Feature Extractor
Extracts rate-of-change and temporal dynamics for ML enhancement
"""

import numpy as np
from collections import deque
from typing import Dict, List
import time

class TemporalFeatureExtractor:
    def __init__(self, window_size=10):
        self.window_size = window_size
        
        # Signal histories
        self.speed_history = deque(maxlen=window_size)
        self.steering_history = deque(maxlen=window_size)
        self.timestamp_history = deque(maxlen=window_size)
        
        # Command tracking
        self.last_command_time = 0.0
        self.command_intervals = deque(maxlen=20)
        
    def add_signal(self, speed: float, steering: float, timestamp: float, is_command: bool = False):
        """Add new signal data point"""
        self.speed_history.append(speed)
        self.steering_history.append(steering)
        self.timestamp_history.append(timestamp)
        
        # Track command timing
        if is_command:
            if self.last_command_time > 0:
                interval = timestamp - self.last_command_time
                self.command_intervals.append(interval)
            self.last_command_time = timestamp
    
    def extract_temporal_features(self) -> Dict[str, float]:
        """Extract temporal dynamics features"""
        if len(self.speed_history) < 3:
            return self._default_features()
        
        features = {}
        
        # Speed dynamics
        speed_features = self._extract_speed_dynamics()
        features.update(speed_features)
        
        # Steering dynamics  
        steering_features = self._extract_steering_dynamics()
        features.update(steering_features)
        
        # Command timing features
        timing_features = self._extract_timing_features()
        features.update(timing_features)
        
        # Cross-signal features
        cross_features = self._extract_cross_signal_features()
        features.update(cross_features)
        
        return features
    
    def _extract_speed_dynamics(self) -> Dict[str, float]:
        """Extract speed rate-of-change features"""
        speeds = np.array(list(self.speed_history))
        times = np.array(list(self.timestamp_history))
        
        if len(speeds) < 3:
            return {'speed_delta': 0.0, 'acceleration': 0.0, 'jerk': 0.0}
        
        # Calculate derivatives
        dt = np.diff(times)
        dt[dt == 0] = 0.001  # Avoid division by zero
        
        # Speed delta (km/h per timestep)
        speed_deltas = np.diff(speeds)
        avg_speed_delta = np.mean(np.abs(speed_deltas))
        
        # Acceleration (m/s²)
        accelerations = (speed_deltas / 3.6) / dt  # Convert km/h to m/s
        avg_acceleration = np.mean(np.abs(accelerations))
        
        # Jerk (m/s³) - rate of change of acceleration
        if len(accelerations) >= 2:
            dt_accel = dt[1:]
            dt_accel[dt_accel == 0] = 0.001
            jerk_values = np.diff(accelerations) / dt_accel
            avg_jerk = np.mean(np.abs(jerk_values))
        else:
            avg_jerk = 0.0
        
        # Speed variance (stability indicator)
        speed_variance = np.var(speeds) if len(speeds) > 1 else 0.0
        
        return {
            'speed_delta': float(avg_speed_delta),
            'acceleration': float(avg_acceleration),
            'jerk': float(avg_jerk),
            'speed_variance': float(speed_variance)
        }
    
    def _extract_steering_dynamics(self) -> Dict[str, float]:
        """Extract steering rate-of-change features"""
        steering = np.array(list(self.steering_history))
        times = np.array(list(self.timestamp_history))
        
        if len(steering) < 3:
            return {'steering_rate': 0.0, 'steering_jerk': 0.0}
        
        dt = np.diff(times)
        dt[dt == 0] = 0.001
        
        # Steering rate (degrees per second)
        steering_deltas = np.diff(steering)
        steering_rates = steering_deltas / dt
        avg_steering_rate = np.mean(np.abs(steering_rates))
        
        # Steering jerk (degrees per second²)
        if len(steering_rates) >= 2:
            dt_rate = dt[1:]
            dt_rate[dt_rate == 0] = 0.001
            steering_jerk_values = np.diff(steering_rates) / dt_rate
            avg_steering_jerk = np.mean(np.abs(steering_jerk_values))
        else:
            avg_steering_jerk = 0.0
        
        return {
            'steering_rate': float(avg_steering_rate),
            'steering_jerk': float(avg_steering_jerk)
        }
    
    def _extract_timing_features(self) -> Dict[str, float]:
        """Extract command timing and latency features"""
        if len(self.command_intervals) < 2:
            return {'command_latency': 0.0, 'timing_regularity': 1.0}
        
        intervals = np.array(list(self.command_intervals))
        
        # Average command latency
        avg_latency = np.mean(intervals)
        
        # Timing regularity (lower variance = more regular)
        timing_variance = np.var(intervals)
        timing_regularity = 1.0 / (1.0 + timing_variance)  # Normalize to [0,1]
        
        return {
            'command_latency': float(avg_latency),
            'timing_regularity': float(timing_regularity)
        }
    
    def _extract_cross_signal_features(self) -> Dict[str, float]:
        """Extract cross-signal correlation features"""
        if len(self.speed_history) < 5:
            return {'speed_steering_correlation': 0.0}
        
        speeds = np.array(list(self.speed_history))
        steering = np.array(list(self.steering_history))
        
        # Speed-steering correlation
        try:
            # Check for valid data before correlation
            if len(speeds) > 1 and len(steering) > 1:
                speed_var = np.var(speeds)
                steering_var = np.var(np.abs(steering))
                
                # Only calculate correlation if there's variance
                if speed_var > 0 and steering_var > 0:
                    correlation = np.corrcoef(speeds, np.abs(steering))[0, 1]
                    if np.isnan(correlation) or np.isinf(correlation):
                        correlation = 0.0
                else:
                    correlation = 0.0
            else:
                correlation = 0.0
        except Exception:
            correlation = 0.0
        
        return {
            'speed_steering_correlation': float(correlation)
        }
    
    def _default_features(self) -> Dict[str, float]:
        """Default features when insufficient data"""
        return {
            'speed_delta': 0.0,
            'acceleration': 0.0,
            'jerk': 0.0,
            'speed_variance': 0.0,
            'steering_rate': 0.0,
            'steering_jerk': 0.0,
            'command_latency': 0.0,
            'timing_regularity': 1.0,
            'speed_steering_correlation': 0.0
        }
    
    def detect_temporal_anomalies(self) -> Dict[str, any]:
        """Detect temporal-based anomalies with enhanced sensitivity"""
        features = self.extract_temporal_features()
        
        anomalies = []
        anomaly_score = 0.0
        
        # High acceleration anomaly - more sensitive thresholds
        if features['acceleration'] > 2.5:  # Lowered from 3.0 m/s²
            severity = min(1.0, features['acceleration'] / 5.0)  # Scale to severity
            anomalies.append(f"high_acceleration:{features['acceleration']:.1f}")
            anomaly_score = max(anomaly_score, 0.6 + 0.35 * severity)
        
        # High jerk anomaly (sudden acceleration changes) - more sensitive
        if features['jerk'] > 6.0:  # Lowered from 8.0 m/s³
            severity = min(1.0, features['jerk'] / 12.0)
            anomalies.append(f"high_jerk:{features['jerk']:.1f}")
            anomaly_score = max(anomaly_score, 0.65 + 0.3 * severity)
        
        # Irregular timing
        if features['timing_regularity'] < 0.4:  # More sensitive
            anomalies.append("irregular_timing")
            anomaly_score = max(anomaly_score, 0.5)
        
        # High steering rate - more sensitive and higher score
        if features['steering_rate'] > 20.0:  # Lowered from 25.0 deg/s
            severity = min(1.0, features['steering_rate'] / 40.0)
            anomalies.append(f"high_steering_rate:{features['steering_rate']:.1f}")
            anomaly_score = max(anomaly_score, 0.6 + 0.35 * severity)
        
        # NEW: High speed variance indicates erratic behavior
        if features['speed_variance'] > 30.0:  # Lowered threshold
            severity = min(1.0, features['speed_variance'] / 100.0)
            anomalies.append(f"speed_variance:{features['speed_variance']:.1f}")
            anomaly_score = max(anomaly_score, 0.55 + 0.3 * severity)
        
        # NEW: Sustained high delta (continuous change)
        if features['speed_delta'] > 2.5:  # Lowered threshold
            severity = min(1.0, features['speed_delta'] / 8.0)
            anomalies.append(f"sustained_delta:{features['speed_delta']:.1f}")
            anomaly_score = max(anomaly_score, 0.5 + 0.3 * severity)
        
        return {
            'temporal_anomaly_score': anomaly_score,
            'temporal_anomalies': anomalies,
            'features': features
        }