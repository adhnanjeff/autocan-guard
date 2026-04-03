import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier, GradientBoostingClassifier
from sklearn.svm import OneClassSVM
from sklearn.preprocessing import StandardScaler
import pickle
import os

class AnomalyDetector:
    def __init__(self, contamination=0.12):  # Optimized contamination rate
        # Enhanced ensemble of models for superior detection
        self.isolation_forest = IsolationForest(
            contamination=contamination, 
            random_state=42, 
            n_estimators=300,  # Increased from 200
            max_samples='auto',  # Better than fixed 256
            max_features=1.0,  # Use all features
            bootstrap=True
        )
        self.one_class_svm = OneClassSVM(nu=contamination, kernel='rbf', gamma='scale')  # scale > auto
        
        # Add supervised Random Forest for better classification
        self.random_forest = RandomForestClassifier(
            n_estimators=200,
            max_depth=15,
            min_samples_split=5,
            min_samples_leaf=2,
            random_state=42,
            class_weight='balanced'  # Handle imbalanced data
        )
        
        # Add Gradient Boosting for enhanced performance
        self.gradient_boost = GradientBoostingClassifier(
            n_estimators=150,
            learning_rate=0.1,
            max_depth=7,
            min_samples_split=5,
            random_state=42
        )
        
        self.scaler = StandardScaler()
        self.is_trained = False
        self.rf_trained = False  # Track supervised model training
        self.gb_trained = False
        self.feature_names = ['frequency', 'delta', 'jitter', 'value_variance', 'rate_of_change', 'max_deviation', 'z_score', 'freq_deviation', 'entropy', 'kurtosis', 'skewness', 'autocorr', 'peak_density', 'mad', 'value_range', 'cv']
        self.signal_order = ['steering', 'speed', 'brake']
        
    def prepare_features(self, features_dict):
        """Convert features dict to numpy array with enhanced features"""
        if not features_dict:
            return None
            
        # Support both:
        # 1) nested per-signal input: {"speed": {"frequency": ...}, ...}
        # 2) flat single-signal input: {"signal": "speed", "frequency": ...}
        feature_vector = []
        has_nested_signals = any(signal in features_dict for signal in self.signal_order)

        if has_nested_signals:
            for signal_name in self.signal_order:
                signal_features = features_dict.get(signal_name)
                if isinstance(signal_features, dict):
                    feature_vector.extend([
                        float(signal_features.get('frequency', 0.0)),
                        float(signal_features.get('delta', 0.0)),
                        float(signal_features.get('jitter', 0.0)),
                        float(signal_features.get('value_variance', 0.0)),
                        float(signal_features.get('rate_of_change', 0.0)),
                        float(signal_features.get('max_deviation', 0.0)),
                        float(signal_features.get('z_score', 0.0)),
                        float(signal_features.get('freq_deviation', 0.0))
                    ])
                else:
                    feature_vector.extend([0.0] * len(self.feature_names))
        else:
            # Single-signal payload fallback.
            single_signal_features = [float(features_dict.get(fname, 0.0)) for fname in self.feature_names]
            signal_name = features_dict.get('signal') or features_dict.get('signal_name')
            if signal_name in self.signal_order:
                for signal in self.signal_order:
                    feature_vector.extend(single_signal_features if signal == signal_name else [0.0] * len(self.feature_names))
            else:
                # If signal name is absent, replicate across signals to avoid silent all-zero vectors.
                for _ in self.signal_order:
                    feature_vector.extend(single_signal_features)
        
        return np.array(feature_vector, dtype=float).reshape(1, -1)
    
    def train(self, training_features_list, labels=None):
        """Train ensemble models on CAN data with optional labels for supervised learning"""
        if not training_features_list:
            return False
            
        # Convert list of feature dicts to training matrix
        X_train = []
        for features_dict in training_features_list:
            feature_vector = self.prepare_features(features_dict)
            if feature_vector is not None and feature_vector.shape[1] == len(self.feature_names) * len(self.signal_order):
                X_train.append(feature_vector.flatten())
        
        if len(X_train) < 10:  # Need minimum samples
            return False
            
        X_train = np.array(X_train)
        
        # Fit scaler on training data
        self.scaler.fit(X_train)
        X_scaled = self.scaler.transform(X_train)
        
        # Train unsupervised models on scaled data
        self.isolation_forest.fit(X_scaled)
        try:
            self.one_class_svm.fit(X_scaled)
        except:
            pass  # SVM might fail on some data distributions
        
        # Train supervised models if labels provided
        if labels is not None and len(labels) == len(X_train):
            try:
                self.random_forest.fit(X_scaled, labels)
                self.rf_trained = True
                print("✅ Random Forest trained successfully")
            except Exception as e:
                print(f"⚠️ Random Forest training failed: {e}")
            
            try:
                self.gradient_boost.fit(X_scaled, labels)
                self.gb_trained = True
                print("✅ Gradient Boosting trained successfully")
            except Exception as e:
                print(f"⚠️ Gradient Boosting training failed: {e}")
        
        self.is_trained = True
        return True
    
    def detect_anomaly(self, features_dict):
        """Detect anomaly using advanced ensemble and return score [0,1]"""
        if not self.is_trained:
            return 0.0  # No anomaly if not trained
            
        feature_vector = self.prepare_features(features_dict)
        if feature_vector is None:
            return 0.0
        
        # Scale features
        feature_vector_scaled = self.scaler.transform(feature_vector)
        
        # Collect scores from all models
        scores = []
        weights = []
        
        # 1. Isolation Forest score (weight: 0.20)
        if_score = self.isolation_forest.decision_function(feature_vector_scaled)[0]
        # Improved normalization using sigmoid-like transformation
        if_normalized = 1.0 / (1.0 + np.exp(if_score * 2.5))  # More aggressive sigmoid
        scores.append(if_normalized)
        weights.append(0.20)
        
        # 2. One-Class SVM score (weight: 0.15)
        try:
            svm_pred = self.one_class_svm.predict(feature_vector_scaled)[0]
            svm_decision = self.one_class_svm.decision_function(feature_vector_scaled)[0]
            # Normalize SVM decision to [0, 1]
            svm_normalized = 1.0 / (1.0 + np.exp(svm_decision * 4.0))  # Stronger sigmoid
            scores.append(svm_normalized)
            weights.append(0.15)
        except:
            pass
        
        # 3. Random Forest probability (weight: 0.35 - highest weight for best model)
        if self.rf_trained:
            try:
                rf_proba = self.random_forest.predict_proba(feature_vector_scaled)[0]
                rf_score = rf_proba[1] if len(rf_proba) > 1 else rf_proba[0]
                scores.append(rf_score)
                weights.append(0.35)
            except:
                pass
        
        # 4. Gradient Boosting probability (weight: 0.30)
        if self.gb_trained:
            try:
                gb_proba = self.gradient_boost.predict_proba(feature_vector_scaled)[0]
                gb_score = gb_proba[1] if len(gb_proba) > 1 else gb_proba[0]
                scores.append(gb_score)
                weights.append(0.30)
            except:
                pass
        
        # Weighted ensemble average
        if scores:
            weights_sum = sum(weights[:len(scores)])
            weights_normalized = [w / weights_sum for w in weights[:len(scores)]]
            ensemble_score = sum(s * w for s, w in zip(scores, weights_normalized))
        else:
            ensemble_score = if_normalized
        
        # Enhanced feature-based heuristics with optimized thresholds for high accuracy
        feature_boost = 0.0
        critical_anomaly_count = 0
        moderate_anomaly_count = 0
        
        if isinstance(features_dict, dict):
            for signal in self.signal_order:
                if signal in features_dict and isinstance(features_dict[signal], dict):
                    sf = features_dict[signal]
                    
                    # Critical anomalies (high confidence indicators)
                    if sf.get('z_score', 0) > 3.0:  # Very strong statistical outlier
                        feature_boost += 0.18
                        critical_anomaly_count += 1
                    if sf.get('freq_deviation', 0) > 0.6:  # Major frequency anomaly
                        feature_boost += 0.15
                        critical_anomaly_count += 1
                    if sf.get('rate_of_change', 0) > 80:  # Extreme rate of change
                        feature_boost += 0.14
                        critical_anomaly_count += 1
                    if sf.get('kurtosis', 0) > 4.0:  # Heavy tails indicating outliers
                        feature_boost += 0.12
                        critical_anomaly_count += 1
                    if sf.get('entropy', 0) > 2.5:  # High randomness
                        feature_boost += 0.10
                        critical_anomaly_count += 1
                    
                    # Moderate anomalies (medium confidence indicators)
                    if 2.0 < sf.get('z_score', 0) <= 3.0:
                        feature_boost += 0.09
                        moderate_anomaly_count += 1
                    if 0.4 < sf.get('freq_deviation', 0) <= 0.6:
                        feature_boost += 0.08
                        moderate_anomaly_count += 1
                    if sf.get('jitter', 0) > 1.5:
                        feature_boost += 0.07
                        moderate_anomaly_count += 1
                    if 50 < sf.get('rate_of_change', 0) <= 80:
                        feature_boost += 0.07
                        moderate_anomaly_count += 1
                    if sf.get('value_variance', 0) > 150:
                        feature_boost += 0.06
                        moderate_anomaly_count += 1
                    if sf.get('peak_density', 0) > 0.4:  # Many fluctuations
                        feature_boost += 0.06
                        moderate_anomaly_count += 1
                    if sf.get('cv', 0) > 0.5:  # High coefficient of variation
                        feature_boost += 0.05
                        moderate_anomaly_count += 1
        
        # Multiplicative boost for multiple concurrent anomalies (correlation effect)
        if critical_anomaly_count >= 2:
            feature_boost *= 1.4  # 40% boost for multiple critical anomalies
        elif critical_anomaly_count >= 1 and moderate_anomaly_count >= 2:
            feature_boost *= 1.25  # 25% boost for mixed anomalies
        elif moderate_anomaly_count >= 3:
            feature_boost *= 1.15  # 15% boost for multiple moderate anomalies
        
        # Combine ensemble and feature-based scores with cap
        combined_score = min(0.98, ensemble_score + feature_boost)
        
        # Apply power transformation for better discrimination (pushes extremes)
        final_score = combined_score ** 0.9  # Gentler power for better balance
        
        return final_score
    
    def save_model(self, filepath):
        """Save all trained models"""
        if self.is_trained:
            with open(filepath, 'wb') as f:
                pickle.dump({
                    'if': self.isolation_forest,
                    'svm': self.one_class_svm,
                    'rf': self.random_forest if self.rf_trained else None,
                    'gb': self.gradient_boost if self.gb_trained else None,
                    'scaler': self.scaler,
                    'rf_trained': self.rf_trained,
                    'gb_trained': self.gb_trained
                }, f)
    
    def load_model(self, filepath):
        """Load all trained models"""
        if os.path.exists(filepath):
            with open(filepath, 'rb') as f:
                models = pickle.load(f)
                if isinstance(models, dict):
                    self.isolation_forest = models.get('if', self.isolation_forest)
                    self.one_class_svm = models.get('svm', self.one_class_svm)
                    if models.get('rf') is not None:
                        self.random_forest = models['rf']
                        self.rf_trained = models.get('rf_trained', True)
                    if models.get('gb') is not None:
                        self.gradient_boost = models['gb']
                        self.gb_trained = models.get('gb_trained', True)
                    if 'scaler' in models:
                        self.scaler = models['scaler']
                else:
                    # Backward compatibility
                    self.isolation_forest = models
                self.is_trained = True
                return True
        return False
