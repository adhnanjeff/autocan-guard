"""
Contextual Consistency Validator
Detects violations of vehicle dynamics relationships - catches signed attacks
"""

import numpy as np
from collections import deque
from typing import Dict, List, Tuple

class ContextualValidator:
    def __init__(self, window_size=20):
        self.window_size = window_size
        
        # Vehicle state windows per sender
        self.sender_windows = {}
        
        # Physics thresholds (real ECU values)
        self.STEER_HIGH_AT_SPEED = 15.0  # degrees at >60 km/h
        self.MAX_STEER_RATE = 30.0       # degrees/second
        self.MAX_OSCILLATION_RATE = 3.0  # sign flips/second
        self.BRAKE_STEER_THRESHOLD = 10.0 # steering while braking hard
        
    def add_vehicle_state(self, sender_id: str, timestamp: float, speed: float, 
                         steering: float, brake: float = 0.0):
        """Add vehicle state for contextual analysis"""
        if sender_id not in self.sender_windows:
            self.sender_windows[sender_id] = {
                'timestamps': deque(maxlen=self.window_size),
                'speeds': deque(maxlen=self.window_size),
                'steerings': deque(maxlen=self.window_size),
                'brakes': deque(maxlen=self.window_size)
            }
            
        window = self.sender_windows[sender_id]
        window['timestamps'].append(timestamp)
        window['speeds'].append(speed)
        window['steerings'].append(steering)
        window['brakes'].append(brake)
        
    def validate_context(self, sender_id: str) -> Tuple[float, List[str]]:
        """Validate contextual consistency - returns violation score [0,1] and reasons"""
        if sender_id not in self.sender_windows:
            return 0.0, []
            
        window = self.sender_windows[sender_id]
        if len(window['timestamps']) < 3:
            return 0.0, []
            
        violations = []
        violation_score = 0.0
        
        # Convert to numpy arrays for analysis
        timestamps = np.array(window['timestamps'])
        speeds = np.array(window['speeds'])
        steerings = np.array(window['steerings'])
        brakes = np.array(window['brakes'])
        
        # VIOLATION 1: Large steering at high speed
        current_speed = speeds[-1]
        current_steering = steerings[-1]
        if len(steerings) >= 2:
            steering_delta = abs(steerings[-1] - steerings[-2])
            
            if current_speed > 60 and steering_delta > self.STEER_HIGH_AT_SPEED:
                violations.append(f"unsafe_physics: {steering_delta:.1f}° at {current_speed:.1f}km/h")
                violation_score += 0.8  # Critical violation
                
        # VIOLATION 2: Rapid steering oscillation (control hijack)
        if len(steerings) >= 5:
            steering_changes = np.diff(steerings[-5:])
            sign_flips = np.sum(np.diff(np.sign(steering_changes)) != 0)
            time_span = timestamps[-1] - timestamps[-5]
            
            if time_span > 0:
                oscillation_rate = sign_flips / time_span
                if oscillation_rate > self.MAX_OSCILLATION_RATE:
                    violations.append(f"control_hijack: {oscillation_rate:.1f} flips/sec")
                    violation_score += 0.7
                    
        # VIOLATION 3: Steering without speed response (signal injection)
        if len(speeds) >= 5 and len(steerings) >= 5:
            steering_variance = np.var(steerings[-5:])
            speed_variance = np.var(speeds[-5:])
            
            # High steering activity but no speed change
            if steering_variance > 25 and speed_variance < 1.0:  # Steering active, speed stable
                violations.append(f"signal_injection: steering_var={steering_variance:.1f}, speed_var={speed_variance:.1f}")
                violation_score += 0.6
                
        # VIOLATION 4: Steering during hard braking (context mismatch)
        current_brake = brakes[-1]
        if current_brake > 50 and abs(current_steering) > self.BRAKE_STEER_THRESHOLD:
            violations.append(f"context_mismatch: {current_steering:.1f}° while braking {current_brake:.1f}%")
            violation_score += 0.5
            
        # VIOLATION 5: Excessive steering rate
        if len(steerings) >= 2 and len(timestamps) >= 2:
            time_delta = timestamps[-1] - timestamps[-2]
            if time_delta > 0:
                steering_rate = abs(steerings[-1] - steerings[-2]) / time_delta
                if steering_rate > self.MAX_STEER_RATE:
                    violations.append(f"excessive_rate: {steering_rate:.1f}°/sec")
                    violation_score += 0.4
                    
        # Clamp violation score
        violation_score = min(1.0, violation_score)
        
        return violation_score, violations
        
    def get_sender_context_summary(self, sender_id: str) -> Dict[str, any]:
        """Get contextual analysis summary for a sender"""
        if sender_id not in self.sender_windows:
            return {'has_data': False}
            
        window = self.sender_windows[sender_id]
        if len(window['timestamps']) < 2:
            return {'has_data': False}
            
        # Calculate current context metrics
        speeds = np.array(window['speeds'])
        steerings = np.array(window['steerings'])
        
        current_speed = speeds[-1]
        current_steering = steerings[-1]
        
        # Steering activity
        steering_activity = np.std(steerings) if len(steerings) > 1 else 0.0
        
        # Speed stability
        speed_stability = 1.0 / (1.0 + np.std(speeds)) if len(speeds) > 1 else 1.0
        
        return {
            'has_data': True,
            'current_speed': current_speed,
            'current_steering': current_steering,
            'steering_activity': steering_activity,
            'speed_stability': speed_stability,
            'samples': len(window['timestamps'])
        }