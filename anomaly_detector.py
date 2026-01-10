import numpy as np
from sklearn.ensemble import IsolationForest
import pickle
import os

class AnomalyDetector:
    def __init__(self, contamination=0.1):
        self.model = IsolationForest(contamination=contamination, random_state=42)
        self.is_trained = False
        self.feature_names = ['frequency', 'delta', 'jitter']
        
    def prepare_features(self, features_dict):
        """Convert features dict to numpy array"""
        if not features_dict:
            return None
            
        # Create fixed-size feature vector
        feature_vector = []
        
        # Always include features for steering, speed, brake in fixed order
        for signal_name in ['steering', 'speed', 'brake']:
            if signal_name in features_dict:
                features = features_dict[signal_name]
                feature_vector.extend([
                    features['frequency'],
                    features['delta'], 
                    features['jitter']
                ])
            else:
                # Fill with zeros if signal not present
                feature_vector.extend([0.0, 0.0, 0.0])
        
        return np.array(feature_vector).reshape(1, -1)
    
    def train(self, training_features_list):
        """Train on normal CAN data"""
        if not training_features_list:
            return False
            
        # Convert list of feature dicts to training matrix
        X_train = []
        for features_dict in training_features_list:
            feature_vector = self.prepare_features(features_dict)
            if feature_vector is not None and feature_vector.shape[1] == 9:  # 3 signals * 3 features
                X_train.append(feature_vector.flatten())
        
        if len(X_train) < 10:  # Need minimum samples
            return False
            
        X_train = np.array(X_train)
        self.model.fit(X_train)
        self.is_trained = True
        return True
    
    def detect_anomaly(self, features_dict):
        """Detect anomaly and return score [0,1]"""
        if not self.is_trained:
            return 0.0  # No anomaly if not trained
            
        feature_vector = self.prepare_features(features_dict)
        if feature_vector is None:
            return 0.0
            
        # Get anomaly score (-1 to 1, where -1 is most anomalous)
        raw_score = self.model.decision_function(feature_vector)[0]
        
        # More sensitive conversion for ECU compromise detection
        if raw_score < -0.1:  # Clearly anomalous - aggressive threshold
            normalized_score = 0.8 + (abs(raw_score) - 0.1) * 2.0
        elif raw_score < -0.02:  # Suspicious - very sensitive
            normalized_score = 0.5 + (abs(raw_score) - 0.02) * 3.0
        elif raw_score < 0.02:  # Borderline - catch subtle changes
            normalized_score = 0.2 + abs(raw_score) * 10.0
        else:  # Normal
            normalized_score = 0.0
        
        return min(1.0, normalized_score)
    
    def save_model(self, filepath):
        """Save trained model"""
        if self.is_trained:
            with open(filepath, 'wb') as f:
                pickle.dump(self.model, f)
    
    def load_model(self, filepath):
        """Load trained model"""
        if os.path.exists(filepath):
            with open(filepath, 'rb') as f:
                self.model = pickle.load(f)
                self.is_trained = True
                return True
        return False