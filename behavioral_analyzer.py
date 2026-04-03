"""
Phase 5: Behavioral Feature Aggregation (Sender-centric)
Analyzes Kafka telemetry for behavioral patterns per device_id
"""

import time
import numpy as np
from collections import defaultdict, deque
from typing import Dict, List, Any
import math

class BehavioralAnalyzer:
    def __init__(self, window_size=30):
        self.window_size = window_size  # seconds
        self.sender_windows = defaultdict(lambda: {
            'messages': deque(maxlen=1000),
            'timestamps': deque(maxlen=1000),
            'values': deque(maxlen=1000),
            'topics': deque(maxlen=1000)
        })
        
    def add_message(self, device_id: str, timestamp: float, value: Any, topic: str):
        """Add message to sender's sliding window"""
        window = self.sender_windows[device_id]
        window['messages'].append({'timestamp': timestamp, 'value': value, 'topic': topic})
        window['timestamps'].append(timestamp)
        window['values'].append(value)
        window['topics'].append(topic)
        
    def extract_features(self, device_id: str) -> Dict[str, float]:
        """Extract behavioral features for a sender"""
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
        
        return {
            'message_rate': self._calculate_message_rate(timestamps),
            'value_entropy': self._calculate_value_entropy(values),
            'delta_pattern': self._calculate_delta_pattern(values),
            'timing_jitter': self._calculate_timing_jitter(timestamps),
            'topic_distribution': self._calculate_topic_distribution(topics)
        }
    
    def _default_features(self) -> Dict[str, float]:
        """Default features for insufficient data"""
        return {
            'message_rate': 0.0,
            'value_entropy': 0.0,
            'delta_pattern': 0.0,
            'timing_jitter': 0.0,
            'topic_distribution': 0.0
        }
    
    def _calculate_message_rate(self, timestamps: List[float]) -> float:
        """Messages per second"""
        if len(timestamps) < 2:
            return 0.0
        time_span = max(timestamps) - min(timestamps)
        return len(timestamps) / max(time_span, 1.0)
    
    def _calculate_value_entropy(self, values: List[float]) -> float:
        """Payload variability using entropy"""
        if len(values) < 2:
            return 0.0
            
        # Discretize values into bins
        try:
            hist, _ = np.histogram(values, bins=min(10, len(values)))
            hist = hist[hist > 0]  # Remove zero bins
            if len(hist) == 0:
                return 0.0
            probs = hist / hist.sum()
            return -np.sum(probs * np.log2(probs))
        except:
            return 0.0
    
    def _calculate_delta_pattern(self, values: List[float]) -> float:
        """Sudden changes in values"""
        if len(values) < 3:
            return 0.0
            
        try:
            deltas = np.diff(values)
            if len(deltas) == 0:
                return 0.0
            mean_delta = np.mean(np.abs(deltas))
            max_delta = np.max(np.abs(deltas))
            return max_delta / max(mean_delta, 0.1)  # Ratio of max to mean change
        except:
            return 0.0
    
    def _calculate_timing_jitter(self, timestamps: List[float]) -> float:
        """Irregular intervals between messages"""
        if len(timestamps) < 3:
            return 0.0
            
        try:
            intervals = np.diff(sorted(timestamps))
            if len(intervals) == 0:
                return 0.0
            mean_interval = np.mean(intervals)
            std_interval = np.std(intervals)
            return std_interval / max(mean_interval, 0.01)  # Coefficient of variation
        except:
            return 0.0
    
    def _calculate_topic_distribution(self, topics: List[str]) -> float:
        """Unexpected topic usage"""
        if len(topics) == 0:
            return 0.0
            
        # Count unique topics
        unique_topics = len(set(topics))
        total_topics = len(topics)
        
        # Higher score for more topic diversity (potentially suspicious)
        return unique_topics / max(total_topics, 1.0)
    
    def get_all_senders(self) -> List[str]:
        """Get all tracked sender IDs"""
        return list(self.sender_windows.keys())
    
    def cleanup_old_data(self, max_age=300):
        """Remove old data beyond max_age seconds"""
        current_time = time.time()
        for device_id in list(self.sender_windows.keys()):
            window = self.sender_windows[device_id]
            # Keep only recent messages
            recent_messages = deque([
                msg for msg in window['messages']
                if current_time - msg['timestamp'] <= max_age
            ], maxlen=1000)
            
            if len(recent_messages) == 0:
                # Remove inactive senders
                del self.sender_windows[device_id]
            else:
                # Update window with recent data
                window['messages'] = recent_messages
                window['timestamps'] = deque([msg['timestamp'] for msg in recent_messages], maxlen=1000)
                window['values'] = deque([msg['value'] for msg in recent_messages], maxlen=1000)
                window['topics'] = deque([msg['topic'] for msg in recent_messages], maxlen=1000)