import time
from collections import defaultdict, deque
import numpy as np

class FeatureExtractor:
    def __init__(self, window_size=1.0):
        self.window_size = window_size  # seconds
        self.message_history = defaultdict(deque)  # per signal
        self.last_values = {}
        
    def add_message(self, signal_name, timestamp, value):
        """Add CAN message for feature extraction"""
        # Store message with timestamp
        self.message_history[signal_name].append((timestamp, value))
        
        # Clean old messages outside window
        cutoff_time = timestamp - self.window_size
        while (self.message_history[signal_name] and 
               self.message_history[signal_name][0][0] < cutoff_time):
            self.message_history[signal_name].popleft()
    
    def extract_features(self, signal_name):
        """Extract features for a signal"""
        if signal_name not in self.message_history:
            return None
            
        messages = list(self.message_history[signal_name])
        if len(messages) < 2:
            return None
            
        # Extract timestamps and values
        timestamps = [msg[0] for msg in messages]
        values = [msg[1] for msg in messages]
        
        # Feature 1: Frequency (messages/sec)
        frequency = len(messages) / self.window_size
        
        # Feature 2: Delta (change in value)
        delta = abs(values[-1] - values[0]) if len(values) > 1 else 0
        
        # Feature 3: Jitter (timing irregularity)
        if len(timestamps) > 2:
            intervals = np.diff(timestamps)
            expected_interval = self.window_size / len(messages)
            jitter = np.std(intervals) / expected_interval if expected_interval > 0 else 0
        else:
            jitter = 0
            
        return {
            "signal": signal_name,
            "frequency": frequency,
            "delta": delta,
            "jitter": jitter
        }
    
    def get_all_features(self):
        """Get features for all signals"""
        features = {}
        for signal_name in self.message_history:
            feature = self.extract_features(signal_name)
            if feature:
                features[signal_name] = feature
        return features