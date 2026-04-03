import time
from collections import defaultdict, deque
import numpy as np
from scipy import stats as scipy_stats

class FeatureExtractor:
    def __init__(self, window_size=1.0):
        self.window_size = window_size  # seconds
        self.message_history = defaultdict(deque)  # per signal
        self.last_values = {}
        self.baseline_stats = defaultdict(lambda: {'mean': 0, 'std': 1, 'samples': 0, 'values_history': deque(maxlen=100)})
        
    def add_message(self, signal_name, timestamp, value):
        """Add CAN message for feature extraction"""
        # Store message with timestamp
        self.message_history[signal_name].append((timestamp, value))
        
        # Update baseline statistics (running mean/std)
        stats = self.baseline_stats[signal_name]
        stats['samples'] += 1
        n = stats['samples']
        old_mean = stats['mean']
        stats['mean'] = old_mean + (value - old_mean) / n
        if n > 1:
            stats['std'] = np.sqrt(((n - 2) * stats['std']**2 + (value - old_mean) * (value - stats['mean'])) / (n - 1))
        
        # Store value for entropy calculation
        stats['values_history'].append(value)
        
        # Clean old messages outside window
        cutoff_time = timestamp - self.window_size
        while (self.message_history[signal_name] and 
               self.message_history[signal_name][0][0] < cutoff_time):
            self.message_history[signal_name].popleft()
    
    def extract_features(self, signal_name):
        """Extract enhanced features for a signal"""
        if signal_name not in self.message_history:
            return None
            
        messages = list(self.message_history[signal_name])
        if len(messages) < 2:
            return None
            
        # Extract timestamps and values
        timestamps = np.array([msg[0] for msg in messages])
        values = np.array([msg[1] for msg in messages])
        
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
        
        # Feature 4: Value variance (data stability)
        value_variance = np.var(values) if len(values) > 1 else 0
        
        # Feature 5: Rate of change (velocity)
        if len(timestamps) > 1 and len(values) > 1:
            time_diffs = np.diff(timestamps)
            time_diffs[time_diffs == 0] = 0.001
            value_diffs = np.diff(values)
            rates = value_diffs / time_diffs
            rate_of_change = np.mean(np.abs(rates))
        else:
            rate_of_change = 0
        
        # Feature 6: Max value deviation from mean
        mean_value = np.mean(values)
        max_deviation = np.max(np.abs(values - mean_value)) if len(values) > 0 else 0
        
        # Feature 7: Z-score for outlier detection
        stats = self.baseline_stats[signal_name]
        if stats['std'] > 0 and len(values) > 0:
            current_value = values[-1]
            z_score = abs((current_value - stats['mean']) / stats['std'])
        else:
            z_score = 0
        
        # Feature 8: Frequency deviation from baseline
        if stats['samples'] > 10:
            expected_freq = stats['samples'] / (timestamps[-1] - timestamps[0] + self.window_size) if len(timestamps) > 0 else frequency
            freq_deviation = abs(frequency - expected_freq) / (expected_freq + 1e-6)
        else:
            freq_deviation = 0
        
        # NEW Feature 9: Entropy (measure of randomness/predictability)
        entropy = 0.0
        if len(values) > 5:
            # Discretize values into bins for entropy calculation
            try:
                hist, _ = np.histogram(values, bins=min(10, len(values)//2))
                hist = hist[hist > 0]  # Remove zero bins
                probabilities = hist / hist.sum()
                entropy = -np.sum(probabilities * np.log2(probabilities + 1e-10))
            except:
                entropy = 0.0
        
        # NEW Feature 10: Kurtosis (measure of tail heaviness/outliers)
        kurtosis = 0.0
        if len(values) > 3:
            try:
                kurtosis = abs(scipy_stats.kurtosis(values))
            except:
                kurtosis = 0.0
        
        # NEW Feature 11: Skewness (measure of asymmetry)
        skewness = 0.0
        if len(values) > 2:
            try:
                skewness = abs(scipy_stats.skew(values))
            except:
                skewness = 0.0
        
        # NEW Feature 12: Autocorrelation (measure of self-similarity)
        autocorr = 0.0
        if len(values) > 5:
            try:
                # Lag-1 autocorrelation
                mean_val = np.mean(values)
                var_val = np.var(values)
                if var_val > 0:
                    autocorr = np.corrcoef(values[:-1], values[1:])[0, 1]
                    autocorr = abs(autocorr) if not np.isnan(autocorr) else 0.0
            except:
                autocorr = 0.0
        
        # NEW Feature 13: Peak count (sudden changes)
        peak_count = 0
        if len(values) > 3:
            # Count local maxima/minima
            for i in range(1, len(values) - 1):
                if (values[i] > values[i-1] and values[i] > values[i+1]) or \
                   (values[i] < values[i-1] and values[i] < values[i+1]):
                    peak_count += 1
        peak_density = peak_count / len(values) if len(values) > 0 else 0
        
        # NEW Feature 14: Median absolute deviation (robust variance measure)
        mad = 0.0
        if len(values) > 1:
            median_val = np.median(values)
            mad = np.median(np.abs(values - median_val))
        
        # NEW Feature 15: Range (max - min)
        value_range = np.max(values) - np.min(values) if len(values) > 0 else 0
        
        # NEW Feature 16: Coefficient of variation (normalized std)
        cv = (np.std(values) / (np.mean(values) + 1e-6)) if len(values) > 0 else 0
            
        return {
            "signal": signal_name,
            "frequency": frequency,
            "delta": delta,
            "jitter": jitter,
            "value_variance": value_variance,
            "rate_of_change": rate_of_change,
            "max_deviation": max_deviation,
            "z_score": z_score,
            "freq_deviation": freq_deviation,
            "entropy": entropy,
            "kurtosis": kurtosis,
            "skewness": skewness,
            "autocorr": autocorr,
            "peak_density": peak_density,
            "mad": mad,
            "value_range": value_range,
            "cv": cv
        }
    
    def get_all_features(self):
        """Get features for all signals"""
        features = {}
        for signal_name in self.message_history:
            feature = self.extract_features(signal_name)
            if feature:
                features[signal_name] = feature
        return features