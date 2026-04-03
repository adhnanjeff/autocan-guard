import time
from storage import get_storage_manager

class TrustEngine:
    def __init__(self, alpha=0.1, beta=0.2, gamma=0.05, vehicle_id="vehicleA"):
        # Trust decay parameters (less aggressive)
        self.alpha = alpha  # anomaly weight
        self.beta = beta    # auth weight  
        self.gamma = gamma  # temporal weight
        
        # Vehicle identification
        self.vehicle_id = vehicle_id
        
        # Trust state
        self.trust_score = 1.0  # Start with full trust
        self.last_update = time.time()
        
        # Trust bounds
        self.min_trust = 0.0
        self.max_trust = 1.0
        
        # Recovery rate (normal recovery)
        self.recovery_rate = 0.01
        
        # ML Toggle - centralized control
        self.ml_enabled = True  # Default: ML ON
        
        # Storage integration
        self.storage = get_storage_manager()
        
    def update_trust(self, anomaly_score, auth_result=1.0, temporal_score=1.0):
        """Update trust score based on inputs"""
        current_time = time.time()
        
        # Apply ML toggle - ignore ML anomaly score when disabled
        effective_anomaly_score = anomaly_score if self.ml_enabled else 0.0
        
        # Trust decay formula from Phase 0.5
        trust_delta = (
            - self.alpha * effective_anomaly_score  # ML influence controlled by toggle
            - self.beta * (1 - auth_result)         # Crypto always active
            - self.gamma * (1 - temporal_score)     # Temporal always active
        )
        
        # Add small recovery when no anomaly
        if effective_anomaly_score < 0.1:
            trust_delta += self.recovery_rate
        
        # Update trust
        self.trust_score += trust_delta
        
        # Clamp to bounds
        self.trust_score = max(self.min_trust, min(self.max_trust, self.trust_score))
        
        self.last_update = current_time
        
        # Log to storage (async, non-blocking)
        try:
            self.storage.log_trust_update(
                self.vehicle_id, 
                self.trust_score, 
                self.ml_enabled, 
                anomaly_score
            )
        except Exception as e:
            # Silently ignore storage errors to prevent API crashes
            pass
        
        return self.trust_score
    
    def get_trust_score(self):
        """Get current trust score"""
        return self.trust_score
    
    def get_trust_level(self):
        """Get trust level category"""
        if self.trust_score > 0.8:
            return "HIGH"
        elif self.trust_score > 0.6:
            return "MEDIUM" 
        elif self.trust_score > 0.4:
            return "LOW"
        else:
            return "CRITICAL"
    
    def reset_trust(self):
        """Reset trust to maximum"""
        self.trust_score = self.max_trust
        self.last_update = time.time()
    
    def set_ml_enabled(self, enabled):
        """Toggle ML behavioral analysis on/off"""
        self.ml_enabled = enabled
        
    def is_ml_enabled(self):
        """Check if ML is enabled"""
        return self.ml_enabled
        
    def get_security_mode(self):
        """Get current security mode"""
        return "CRYPTO_PLUS_ML" if self.ml_enabled else "CRYPTO_ONLY"
    
    def set_ips_active(self, active: bool):
        """Set IPS active status to control trust recovery"""
        self._ips_active = active
        
    def get_status(self):
        """Get trust engine status"""
        return {
            "trust_score": self.trust_score,
            "trust_level": self.get_trust_level(),
            "last_update": self.last_update,
            "ml_enabled": self.ml_enabled,
            "security_mode": self.get_security_mode(),
            "parameters": {
                "alpha": self.alpha,
                "beta": self.beta, 
                "gamma": self.gamma
            }
        }