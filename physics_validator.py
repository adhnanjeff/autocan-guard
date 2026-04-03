"""
Physics-Based Constraint Validator
Mandatory safety checks based on vehicle physics - non-negotiable rules
"""

import time
from typing import Dict, Tuple, List
from collections import deque

class PhysicsValidator:
    def __init__(self):
        # Physics constraints (industry standard)
        self.MAX_ACCELERATION = 4.0  # m/s² (2-4 typical)
        self.MAX_DECELERATION = 9.0  # m/s² (6-9 typical) 
        self.MAX_SPEED_DELTA_PER_CYCLE = 5.0  # km/h per 100ms
        self.MAX_STEERING_RATE = 30.0  # degrees per second
        
        # Vehicle state history
        self.speed_history = deque(maxlen=10)
        self.steering_history = deque(maxlen=10)
        self.timestamp_history = deque(maxlen=10)
        
        # Current state
        self.last_speed = 0.0
        self.last_steering = 0.0
        self.last_timestamp = time.time()
        
    def validate_speed_physics(self, speed: float, timestamp: float) -> Tuple[bool, str, float]:
        """Validate speed change against physics constraints"""
        if not self.speed_history:
            self._update_history(speed, 0.0, timestamp)
            return True, "initial", 1.0
        
        # Calculate time delta
        dt = timestamp - self.last_timestamp
        if dt <= 0:
            return True, "no_time_delta", 1.0
        
        # Calculate acceleration
        speed_delta = speed - self.last_speed  # km/h
        acceleration = (speed_delta / 3.6) / dt  # Convert to m/s²
        
        # Physics violation score (0=valid, 1=impossible)
        violation_score = 0.0
        violations = []
        
        # Check maximum acceleration
        if acceleration > self.MAX_ACCELERATION:
            violation_score = min(1.0, acceleration / self.MAX_ACCELERATION - 1.0)
            violations.append(f"accel:{acceleration:.1f}m/s²")
        
        # Check maximum deceleration  
        if acceleration < -self.MAX_DECELERATION:
            violation_score = min(1.0, abs(acceleration) / self.MAX_DECELERATION - 1.0)
            violations.append(f"decel:{acceleration:.1f}m/s²")
        
        # Check speed delta per cycle
        if abs(speed_delta) > self.MAX_SPEED_DELTA_PER_CYCLE and dt < 0.2:
            violation_score = max(violation_score, 0.8)
            violations.append(f"delta:{speed_delta:.1f}km/h")
        
        # Update history
        self._update_history(speed, 0.0, timestamp)
        
        is_valid = violation_score < 0.5
        reason = f"physics_violation: {', '.join(violations)}" if violations else "physics_valid"
        
        return is_valid, reason, 1.0 - violation_score
    
    def validate_steering_physics(self, steering: float, timestamp: float) -> Tuple[bool, str, float]:
        """Validate steering change against physics constraints"""
        if not self.steering_history:
            self._update_history(0.0, steering, timestamp)
            return True, "initial", 1.0
        
        dt = timestamp - self.last_timestamp
        if dt <= 0:
            return True, "no_time_delta", 1.0
        
        # Calculate steering rate
        steering_delta = abs(steering - self.last_steering)
        steering_rate = steering_delta / dt  # degrees per second
        
        violation_score = 0.0
        violations = []
        
        # Check maximum steering rate
        if steering_rate > self.MAX_STEERING_RATE:
            violation_score = min(1.0, steering_rate / self.MAX_STEERING_RATE - 1.0)
            violations.append(f"rate:{steering_rate:.1f}°/s")
        
        is_valid = violation_score < 0.5
        reason = f"steering_physics: {', '.join(violations)}" if violations else "steering_valid"
        
        return is_valid, reason, 1.0 - violation_score
    
    def validate_correlation(self, speed: float, steering: float, brake: float) -> Tuple[bool, str, float]:
        """Cross-signal correlation validation"""
        violations = []
        violation_score = 0.0
        
        # Rule: Speed increase while braking is suspicious
        if len(self.speed_history) >= 2:
            speed_increasing = speed > self.last_speed + 1.0  # +1 km/h threshold
            if speed_increasing and brake > 10.0:  # Brake applied
                violation_score = max(violation_score, 0.7)
                violations.append("speed_up_while_braking")
        
        # Rule: High speed with zero steering for extended time
        if speed > 80.0 and abs(steering) < 1.0:
            if len([s for s in self.steering_history if abs(s) < 1.0]) > 8:
                violation_score = max(violation_score, 0.3)
                violations.append("high_speed_no_steering")
        
        # Rule: Extreme steering at high speed
        if speed > 60.0 and abs(steering) > 25.0:
            violation_score = max(violation_score, 0.6)
            violations.append("extreme_steering_high_speed")
        
        is_valid = violation_score < 0.5
        reason = f"correlation: {', '.join(violations)}" if violations else "correlation_valid"
        
        return is_valid, reason, 1.0 - violation_score
    
    def _update_history(self, speed: float, steering: float, timestamp: float):
        """Update internal state history"""
        self.speed_history.append(speed)
        self.steering_history.append(steering)
        self.timestamp_history.append(timestamp)
        
        self.last_speed = speed
        self.last_steering = steering
        self.last_timestamp = timestamp
    
    def get_physics_score(self, speed: float, steering: float, brake: float, timestamp: float) -> Dict[str, any]:
        """Get comprehensive physics validation score"""
        speed_valid, speed_reason, speed_score = self.validate_speed_physics(speed, timestamp)
        steering_valid, steering_reason, steering_score = self.validate_steering_physics(steering, timestamp)
        corr_valid, corr_reason, corr_score = self.validate_correlation(speed, steering, brake)
        
        # Combined physics score (weighted average)
        combined_score = (0.5 * speed_score + 0.3 * steering_score + 0.2 * corr_score)
        
        return {
            'physics_score': combined_score,
            'speed_valid': speed_valid,
            'steering_valid': steering_valid,
            'correlation_valid': corr_valid,
            'violations': {
                'speed': speed_reason if not speed_valid else None,
                'steering': steering_reason if not steering_valid else None,
                'correlation': corr_reason if not corr_valid else None
            },
            'overall_valid': speed_valid and steering_valid and corr_valid
        }