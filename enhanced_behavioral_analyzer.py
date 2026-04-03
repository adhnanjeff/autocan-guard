"""
Enhanced Behavioral Analyzer - Phase 5+
Adds control energy, jerk, and contextual validation features
"""

import time
import numpy as np
from collections import defaultdict, deque
from typing import Dict, List, Any, Tuple
from contextual_validator import ContextualValidator

class EnhancedBehavioralAnalyzer:
    def __init__(self, window_size=30):
        self.window_size = window_size
        self.sender_windows = defaultdict(lambda: {
            'messages': deque(maxlen=1000),
            'timestamps': deque(maxlen=1000),
            'values': deque(maxlen=1000),
            'topics': deque(maxlen=1000),
            # Enhanced tracking
            'steering_values': deque(maxlen=200),
            'steering_timestamps': deque(maxlen=200),
            'speed_values': deque(maxlen=200),
            'speed_timestamps': deque(maxlen=200),
            'brake_values': deque(maxlen=200)
        })
        
        # Contextual validator
        self.contextual_validator = ContextualValidator()
        
    def add_message(self, device_id: str, timestamp: float, value: Any, topic: str, 
                   signal_type: str = None, speed: float = 0.0, brake: float = 0.0):
        """Add message with enhanced tracking"""
        window = self.sender_windows[device_id]
        window['messages'].append({'timestamp': timestamp, 'value': value, 'topic': topic})
        window['timestamps'].append(timestamp)
        window['values'].append(value)
        window['topics'].append(topic)
        
        # Track specific signals for control analysis
        if isinstance(value, (int, float)):
            if 'steering' in topic.lower() or signal_type == 'steering':
                window['steering_values'].append(float(value))
                window['steering_timestamps'].append(timestamp)
                # Add to contextual validator
                self.contextual_validator.add_vehicle_state(device_id, timestamp, speed, float(value), brake)
            elif 'speed' in topic.lower() or signal_type == 'speed':
                window['speed_values'].append(float(value))
                window['speed_timestamps'].append(timestamp)
            elif 'brake' in topic.lower() or signal_type == 'brake':
                window['brake_values'].append(float(value))
                
    def extract_features(self, device_id: str) -> Dict[str, float]:
        """Extract enhanced behavioral features"""
        window = self.sender_windows[device_id]
        
        if len(window['messages']) < 5:
            return self._default_features()
            
        current_time = time.time()
        recent_messages = [
            msg for msg in window['messages'] 
            if current_time - msg['timestamp'] <= self.window_size
        ]
        
        if len(recent_messages) < 3:
            return self._default_features()
            
        timestamps = [msg['timestamp'] for msg in recent_messages]
        values = [msg['value'] for msg in recent_messages if isinstance(msg['value'], (int, float))]
        topics = [msg['topic'] for msg in recent_messages]
        
        # Base features
        base_features = {
            'message_rate': self._calculate_message_rate(timestamps),
            'value_entropy': self._calculate_value_entropy(values),
            'delta_pattern': self._calculate_delta_pattern(values),
            'timing_jitter': self._calculate_timing_jitter(timestamps),
            'topic_distribution': self._calculate_topic_distribution(topics)
        }
        
        # Control energy features
        control_features = self._calculate_control_energy_features(device_id, current_time)
        
        # Contextual validation
        context_score, context_violations = self.contextual_validator.validate_context(device_id)
        context_features = {
            'context_violation': context_score,
            'context_violation_count': len(context_violations)
        }
        
        return {**base_features, **control_features, **context_features}
    
    def _calculate_control_energy_features(self, device_id: str, current_time: float) -> Dict[str, float]:
        """Calculate control energy, jerk, and oscillation features"""
        window = self.sender_windows[device_id]
        
        # Get recent steering data
        recent_steering = []
        recent_steering_times = []
        for i, timestamp in enumerate(window['steering_timestamps']):
            if current_time - timestamp <= self.window_size:
                recent_steering.append(window['steering_values'][i])
                recent_steering_times.append(timestamp)
                
        if len(recent_steering) < 3:
            return {
                'steering_energy': 0.0,
                'steering_jerk': 0.0,
                'oscillation_rate': 0.0,
                'control_aggression': 0.0
            }
            
        steering_array = np.array(recent_steering)
        time_array = np.array(recent_steering_times)
        
        # CRITICAL: Steering Energy (sum of squared changes)
        steering_deltas = np.diff(steering_array)
        steering_energy = np.sum(steering_deltas ** 2) if len(steering_deltas) > 0 else 0.0
        
        # CRITICAL: Steering Jerk (2nd derivative - smoothness)
        steering_jerk = 0.0
        if len(steering_deltas) >= 2:
            steering_jerk = np.sum(np.abs(np.diff(steering_deltas)))
            
        # CRITICAL: Oscillation Rate (control hijack detection)
        oscillation_rate = 0.0
        if len(steering_deltas) >= 2:
            sign_changes = np.sum(np.diff(np.sign(steering_deltas)) != 0)
            time_span = time_array[-1] - time_array[0]
            oscillation_rate = sign_changes / max(time_span, 1.0)
            
        # CRITICAL: Control Aggression (high-frequency energy)
        control_aggression = 0.0
        if len(steering_array) >= 5:
            rapid_changes = np.abs(steering_array[2:] - steering_array[:-2])
            control_aggression = np.mean(rapid_changes) if len(rapid_changes) > 0 else 0.0
            
        return {
            'steering_energy': min(steering_energy / 10.0, 20.0),    # Aggressive normalization
            'steering_jerk': min(steering_jerk / 5.0, 20.0),        # Aggressive normalization
            'oscillation_rate': min(oscillation_rate * 2.0, 10.0),  # Amplify oscillations
            'control_aggression': min(control_aggression / 2.0, 15.0) # Amplify aggression
        }
    
    def _default_features(self) -> Dict[str, float]:
        """Default features for insufficient data"""
        return {
            'message_rate': 0.0,
            'value_entropy': 0.0,
            'delta_pattern': 0.0,
            'timing_jitter': 0.0,
            'topic_distribution': 0.0,
            'steering_energy': 0.0,
            'steering_jerk': 0.0,
            'oscillation_rate': 0.0,
            'control_aggression': 0.0,
            'context_violation': 0.0,
            'context_violation_count': 0.0
        }
    
    def _calculate_message_rate(self, timestamps: List[float]) -> float:
        if len(timestamps) < 2:
            return 0.0
        time_span = max(timestamps) - min(timestamps)
        rate = len(timestamps) / max(time_span, 1.0)
        return min(rate * 2.0, 50.0)  # Amplify rate anomalies
    
    def _calculate_value_entropy(self, values: List[float]) -> float:
        if len(values) < 2:
            return 0.0
        try:
            hist, _ = np.histogram(values, bins=min(10, len(values)))
            hist = hist[hist > 0]
            if len(hist) == 0:
                return 0.0
            probs = hist / hist.sum()
            entropy = -np.sum(probs * np.log2(probs))
            return min(entropy * 1.5, 10.0)  # Amplify entropy
        except:
            return 0.0
    
    def _calculate_delta_pattern(self, values: List[float]) -> float:
        if len(values) < 3:
            return 0.0
        try:
            deltas = np.diff(values)
            if len(deltas) == 0:
                return 0.0
            mean_delta = np.mean(np.abs(deltas))
            max_delta = np.max(np.abs(deltas))
            ratio = max_delta / max(mean_delta, 0.1)
            return min(ratio * 1.5, 20.0)  # Amplify sudden changes
        except:
            return 0.0
    
    def _calculate_timing_jitter(self, timestamps: List[float]) -> float:
        if len(timestamps) < 3:
            return 0.0
        try:
            intervals = np.diff(sorted(timestamps))
            if len(intervals) == 0:
                return 0.0
            mean_interval = np.mean(intervals)
            std_interval = np.std(intervals)
            jitter = std_interval / max(mean_interval, 0.01)
            return min(jitter * 3.0, 15.0)  # Amplify timing irregularities
        except:
            return 0.0
    
    def _calculate_topic_distribution(self, topics: List[str]) -> float:
        if len(topics) == 0:
            return 0.0
        unique_topics = len(set(topics))
        total_topics = len(topics)
        diversity = unique_topics / max(total_topics, 1.0)
        return min(diversity * 5.0, 5.0)  # Amplify topic anomalies
    
    def get_all_senders(self) -> List[str]:
        return list(self.sender_windows.keys())
    
    def get_context_violations(self, device_id: str) -> Tuple[float, List[str]]:
        """Get contextual violations for a sender"""
        return self.contextual_validator.validate_context(device_id)
    
    def cleanup_old_data(self, max_age=300):
        current_time = time.time()
        for device_id in list(self.sender_windows.keys()):
            window = self.sender_windows[device_id]
            recent_messages = deque([
                msg for msg in window['messages']
                if current_time - msg['timestamp'] <= max_age
            ], maxlen=1000)
            
            if len(recent_messages) == 0:
                del self.sender_windows[device_id]
            else:
                window['messages'] = recent_messages
                window['timestamps'] = deque([msg['timestamp'] for msg in recent_messages], maxlen=1000)
                window['values'] = deque([msg['value'] for msg in recent_messages], maxlen=1000)
                window['topics'] = deque([msg['topic'] for msg in recent_messages], maxlen=1000)