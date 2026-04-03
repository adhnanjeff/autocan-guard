"""
Phase 5: Trust Engine with Per-Sender Trust Scores
Manages trust scores for individual device IDs based on behavioral analysis
"""

import time
from collections import defaultdict
from typing import Dict, List, Tuple

class SenderTrustEngine:
    def __init__(self):
        # Per-sender trust scores
        self.sender_trust = defaultdict(lambda: 1.0)  # Start with full trust
        self.sender_last_update = defaultdict(lambda: time.time())
        
        # Trust decay parameters
        self.alpha = 0.3  # Anomaly decay factor
        self.beta = 0.2   # Policy violation decay factor
        self.gamma = 0.1  # Temporal decay factor
        
        # Recovery parameters
        self.recovery_rate = 0.01  # Slow recovery
        self.min_trust = 0.0
        self.max_trust = 1.0
        
        # Trust level thresholds
        self.trust_thresholds = {
            'CRITICAL': 0.3,
            'LOW': 0.5,
            'MEDIUM': 0.7,
            'HIGH': 0.8
        }
        
        # Sender history for analysis
        self.sender_history = defaultdict(list)
        self.max_history = 100
        
    def update_trust(self, device_id: str, anomaly_score: float, policy_violation: bool = False, 
                    auth_failure: bool = False) -> float:
        """Update trust score for a sender"""
        current_time = time.time()
        current_trust = self.sender_trust[device_id]
        last_update = self.sender_last_update[device_id]
        
        # Temporal decay (trust degrades over time without updates)
        time_delta = current_time - last_update
        temporal_decay = self.gamma * min(time_delta / 3600, 1.0)  # Max 1 hour decay
        
        # Calculate trust decay
        anomaly_decay = self.alpha * anomaly_score
        policy_decay = self.beta if policy_violation else 0.0
        auth_decay = 0.5 if auth_failure else 0.0  # Severe penalty for auth failures
        
        # Apply decay
        new_trust = current_trust - anomaly_decay - policy_decay - temporal_decay - auth_decay
        
        # Apply recovery for good behavior (anomaly_score < 0.1)
        if anomaly_score < 0.1 and not policy_violation and not auth_failure:
            recovery = self.recovery_rate * (self.max_trust - current_trust)
            new_trust = current_trust + recovery
            
        # Clamp to valid range
        new_trust = max(self.min_trust, min(self.max_trust, new_trust))
        
        # Update state
        self.sender_trust[device_id] = new_trust
        self.sender_last_update[device_id] = current_time
        
        # Record history
        self.sender_history[device_id].append({
            'timestamp': current_time,
            'trust_score': new_trust,
            'anomaly_score': anomaly_score,
            'policy_violation': policy_violation,
            'auth_failure': auth_failure
        })
        
        # Limit history size
        if len(self.sender_history[device_id]) > self.max_history:
            self.sender_history[device_id] = self.sender_history[device_id][-self.max_history:]
            
        return new_trust
        
    def get_trust_score(self, device_id: str) -> float:
        """Get current trust score for a sender"""
        return self.sender_trust[device_id]
        
    def get_trust_level(self, device_id: str) -> str:
        """Get trust level category for a sender"""
        trust_score = self.sender_trust[device_id]
        
        if trust_score >= self.trust_thresholds['HIGH']:
            return 'HIGH'
        elif trust_score >= self.trust_thresholds['MEDIUM']:
            return 'MEDIUM'
        elif trust_score >= self.trust_thresholds['LOW']:
            return 'LOW'
        elif trust_score >= self.trust_thresholds['CRITICAL']:
            return 'CRITICAL'
        else:
            return 'BLOCKED'
            
    def get_all_senders(self) -> List[str]:
        """Get all tracked senders"""
        return list(self.sender_trust.keys())
        
    def get_sender_summary(self, device_id: str) -> Dict[str, any]:
        """Get comprehensive sender trust summary"""
        trust_score = self.sender_trust[device_id]
        trust_level = self.get_trust_level(device_id)
        last_update = self.sender_last_update[device_id]
        
        # Recent history analysis
        history = self.sender_history[device_id][-10:]  # Last 10 events
        recent_anomalies = sum(1 for h in history if h['anomaly_score'] > 0.5)
        recent_violations = sum(1 for h in history if h['policy_violation'])
        
        return {
            'device_id': device_id,
            'trust_score': trust_score,
            'trust_level': trust_level,
            'last_update': last_update,
            'recent_anomalies': recent_anomalies,
            'recent_violations': recent_violations,
            'history_length': len(self.sender_history[device_id])
        }
        
    def get_fleet_trust_summary(self) -> Dict[str, any]:
        """Get fleet-wide trust summary"""
        all_senders = self.get_all_senders()
        
        if not all_senders:
            return {
                'total_senders': 0,
                'average_trust': 1.0,
                'trust_distribution': {},
                'suspicious_senders': []
            }
            
        trust_scores = [self.sender_trust[sender] for sender in all_senders]
        average_trust = sum(trust_scores) / len(trust_scores)
        
        # Trust level distribution
        trust_distribution = defaultdict(int)
        suspicious_senders = []
        
        for sender in all_senders:
            level = self.get_trust_level(sender)
            trust_distribution[level] += 1
            
            if level in ['LOW', 'CRITICAL', 'BLOCKED']:
                suspicious_senders.append({
                    'device_id': sender,
                    'trust_score': self.sender_trust[sender],
                    'trust_level': level
                })
                
        return {
            'total_senders': len(all_senders),
            'average_trust': average_trust,
            'trust_distribution': dict(trust_distribution),
            'suspicious_senders': suspicious_senders
        }
        
    def reset_sender_trust(self, device_id: str):
        """Reset trust score for a sender (admin function)"""
        self.sender_trust[device_id] = 1.0
        self.sender_last_update[device_id] = time.time()
        self.sender_history[device_id] = []
        
    def should_block_sender(self, device_id: str) -> bool:
        """Check if sender should be blocked"""
        return self.get_trust_level(device_id) == 'BLOCKED'