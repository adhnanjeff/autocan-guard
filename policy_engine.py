class PolicyEngine:
    def __init__(self):
        # Containment thresholds
        self.warning_threshold = 0.8
        self.clamp_threshold = 0.6
        self.ignore_threshold = 0.4
        
        # Safety limits
        self.max_steering_angle = 15.0  # degrees
        self.max_speed = 50.0  # km/h
        
    def get_containment_action(self, trust_score):
        """Determine containment action based on trust"""
        if trust_score > self.warning_threshold:
            return "NONE"
        elif trust_score > self.clamp_threshold:
            return "WARNING"
        elif trust_score > self.ignore_threshold:
            return "CLAMP"
        else:
            return "IGNORE"
    
    def apply_steering_policy(self, steering_angle, trust_score):
        """Apply steering containment policy"""
        action = self.get_containment_action(trust_score)
        
        if action == "IGNORE":
            return 0.0  # Ignore malicious steering
        elif action == "CLAMP":
            # Clamp to safe range
            return max(-self.max_steering_angle, 
                      min(self.max_steering_angle, steering_angle))
        else:
            return steering_angle  # No modification
    
    def apply_speed_policy(self, speed, trust_score):
        """Apply speed containment policy"""
        action = self.get_containment_action(trust_score)
        
        if action == "IGNORE":
            return min(speed, 10.0)  # Emergency crawl speed
        elif action == "CLAMP":
            return min(speed, self.max_speed)  # Speed limit
        else:
            return speed  # No modification
    
    def should_ignore_message(self, trust_score):
        """Check if message should be ignored"""
        return trust_score < self.ignore_threshold
    
    def get_policy_decision(self, trust_score):
        """Get policy decision based on trust score"""
        action = self.get_containment_action(trust_score)
        
        return {
            "action": action,
            "trust_score": trust_score,
            "steering_limit": self.max_steering_angle if action in ["CLAMP", "IGNORE"] else None,
            "speed_limit": self.max_speed if action in ["CLAMP", "IGNORE"] else None,
            "message_filtering": action == "IGNORE"
        }
    
    def get_policy_status(self, trust_score):
        """Get current policy status"""
        action = self.get_containment_action(trust_score)
        
        return {
            "action": action,
            "trust_score": trust_score,
            "steering_limit": self.max_steering_angle if action in ["CLAMP", "IGNORE"] else None,
            "speed_limit": self.max_speed if action in ["CLAMP", "IGNORE"] else None,
            "message_filtering": action == "IGNORE"
        }