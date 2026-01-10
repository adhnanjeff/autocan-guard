import time
from dataclasses import dataclass
from typing import Dict, Any, Optional

@dataclass
class IPSState:
    enabled: bool = True  # Enable IPS by default
    mode: str = "OFF"  # OFF, SOFT_LIMIT, SAFE_MODE, CRITICAL
    last_safe_speed: float = 30.0
    last_safe_steering: float = 0.0
    recovery_timer: float = 0.0
    sustained_anomaly_start: Optional[float] = None

class IPSPolicyEngine:
    def __init__(self):
        self.state = IPSState()
        self.SUSTAINED_ANOMALY_THRESHOLD = 3.0  # seconds
        self.MAX_SAFE_SPEED = 40.0
        self.MAX_ACCEL = 5.0  # km/h per second
        self.RECOVERY_TIME = 10.0  # seconds
        
    def set_enabled(self, enabled: bool):
        """Toggle IPS on/off"""
        self.state.enabled = enabled
        if not enabled:
            self.state.mode = "OFF"
            self.state.recovery_timer = 0.0
            self.state.sustained_anomaly_start = None
    
    def update_policy(self, trust_score: float, anomaly_score: float = 0.0, attack_active: bool = False) -> Dict[str, Any]:
        """Update IPS policy based ONLY on trust score from IDS"""
        current_time = time.time()
        
        if not self.state.enabled:
            return {"mode": "OFF", "action": "ALLOW", "speed_limit": None, "steering_limit": None}
        
        # IPS triggers ONLY on trust score thresholds (industry standard)
        if trust_score < 0.8:  # Trust below 0.8 triggers IPS (more aggressive)
            # Determine IPS mode based on trust score
            if trust_score >= 0.7:
                self.state.mode = "SOFT_LIMIT"
            elif trust_score >= 0.5:
                self.state.mode = "SAFE_MODE"
            else:
                self.state.mode = "CRITICAL"
            self.state.recovery_timer = 0.0  # Reset recovery
        else:
            # Recovery logic - only when trust is high enough
            if self.state.mode != "OFF":
                if self.state.recovery_timer == 0:
                    self.state.recovery_timer = current_time
                elif current_time - self.state.recovery_timer > 5.0:  # 5 second recovery (faster)
                    self.state.mode = "OFF"
                    self.state.recovery_timer = 0.0
        
        return self._get_policy_limits()
    
    def _get_policy_limits(self) -> Dict[str, Any]:
        """Get control limits based on current IPS mode"""
        if self.state.mode == "OFF":
            return {
                "mode": "OFF",
                "action": "ALLOW",
                "speed_limit": None,
                "steering_limit": None,
                "max_accel": None
            }
        elif self.state.mode == "SOFT_LIMIT":
            return {
                "mode": "SOFT_LIMIT",
                "action": "CLAMP",
                "speed_limit": 40.0,  # Allow up to 40 km/h
                "steering_limit": 15.0,  # ±15°
                "max_accel": self.MAX_ACCEL
            }
        elif self.state.mode == "SAFE_MODE":
            return {
                "mode": "SAFE_MODE", 
                "action": "RESTRICT",
                "speed_limit": 35.0,  # Reduce to 35 km/h
                "steering_limit": 10.0,  # ±10°
                "max_accel": 2.0
            }
        else:  # CRITICAL
            return {
                "mode": "CRITICAL",
                "action": "MINIMAL",
                "speed_limit": 25.0,  # Minimum safe speed
                "steering_limit": 5.0,  # ±5°
                "max_accel": 1.0
            }
    
    def sanitize_speed(self, requested_speed: float, current_speed: float) -> float:
        """Apply speed sanitization - OVERRIDE with safe values during attack"""
        policy = self._get_policy_limits()
        
        if policy["mode"] == "OFF":
            self.state.last_safe_speed = requested_speed
            return requested_speed
        
        # IPS ACTIVE: Override with safe speed instead of requested speed
        if policy["mode"] in ["SOFT_LIMIT", "SAFE_MODE", "CRITICAL"]:
            # Use policy speed limit as maximum allowed speed
            safe_speed = min(policy["speed_limit"], current_speed + 2.0)  # Allow max 2 km/h increase
            safe_speed = max(safe_speed, 10.0)  # Minimum safe speed
            print(f"🛡️ IPS OVERRIDE: Speed {requested_speed:.1f} → {safe_speed:.1f} km/h ({policy['mode']})")
            return safe_speed
        
        return requested_speed
    
    def sanitize_steering(self, requested_steering: float) -> float:
        """Apply steering sanitization - OVERRIDE with safe values during attack"""
        policy = self._get_policy_limits()
        
        if policy["mode"] == "OFF":
            self.state.last_safe_steering = requested_steering
            return requested_steering
        
        # IPS ACTIVE: Override with safe steering - gradually return to center
        if policy["mode"] in ["SOFT_LIMIT", "SAFE_MODE", "CRITICAL"]:
            # Override with gradual return to center (0°)
            safe_steering = self.state.last_safe_steering * 0.9  # Gradually reduce to 0
            safe_steering = max(-policy["steering_limit"], min(policy["steering_limit"], safe_steering))
            print(f"🛡️ IPS OVERRIDE: Steering {requested_steering:.1f}° → {safe_steering:.1f}° ({policy['mode']})")
            return safe_steering
        
        return requested_steering
    
    def get_status(self) -> Dict[str, Any]:
        """Get IPS status for UI"""
        policy = self._get_policy_limits()
        return {
            "enabled": self.state.enabled,
            "mode": self.state.mode,
            "policy": policy,
            "last_safe_speed": self.state.last_safe_speed,
            "last_safe_steering": self.state.last_safe_steering,
            "recovery_active": self.state.recovery_timer > 0
        }