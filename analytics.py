"""
Analytics Layer - Trust Timeline and Attack Correlation
Processes existing data without modifying core system
"""

import pandas as pd
import numpy as np
from typing import Dict, List, Any, Tuple
from storage import get_storage_manager
import time

class SecurityAnalytics:
    def __init__(self):
        self.storage = get_storage_manager()
    
    def get_trust_timeline(self, vehicle_id: str, hours: int = 24) -> pd.DataFrame:
        """Get trust score timeline for visualization"""
        try:
            # Get trust history from storage
            history = self.storage.get_trust_history(vehicle_id, limit=1000)
            
            if not history:
                return pd.DataFrame()
            
            # Convert to DataFrame
            df = pd.DataFrame(history)
            df['datetime'] = pd.to_datetime(df['timestamp'], unit='s')
            
            # Filter by time window
            cutoff = time.time() - (hours * 3600)
            df = df[df['timestamp'] > cutoff]
            
            return df.sort_values('timestamp')
        except Exception as e:
            print(f"Trust timeline error: {e}")
            return pd.DataFrame()
    
    def get_attack_windows(self, vehicle_id: str, hours: int = 24) -> List[Dict[str, Any]]:
        """Identify attack periods from alerts"""
        try:
            alerts = self.storage.get_alerts(vehicle_id, limit=100)
            
            if not alerts:
                return []
            
            # Filter by time and severity
            cutoff = time.time() - (hours * 3600)
            attack_alerts = [
                alert for alert in alerts 
                if alert.get('timestamp', 0) > cutoff 
                and alert.get('severity') in ['HIGH', 'CRITICAL']
            ]
            
            # Group alerts into attack windows (within 60 seconds)
            windows = []
            for alert in sorted(attack_alerts, key=lambda x: x.get('timestamp', 0)):
                timestamp = alert.get('timestamp', 0)
                
                # Check if this alert extends an existing window
                extended = False
                for window in windows:
                    if timestamp - window['end'] < 60:  # Within 60 seconds
                        window['end'] = timestamp + 30  # Extend window
                        window['alerts'].append(alert)
                        extended = True
                        break
                
                if not extended:
                    # Create new attack window
                    windows.append({
                        'start': timestamp - 10,
                        'end': timestamp + 30,
                        'alerts': [alert]
                    })
            
            return windows
        except Exception as e:
            print(f"Attack windows error: {e}")
            return []
    
    def get_ml_comparison_stats(self, vehicle_id: str) -> Dict[str, Any]:
        """Compare ML ON vs OFF performance from historical data"""
        try:
            # Get trust history
            history = self.storage.get_trust_history(vehicle_id, limit=500)
            alerts = self.storage.get_alerts(vehicle_id, limit=50)
            
            if not history:
                return {}
            
            # Separate ML ON vs OFF periods
            ml_on_data = [h for h in history if h.get('ml_enabled', True)]
            ml_off_data = [h for h in history if not h.get('ml_enabled', True)]
            
            # Calculate stats
            stats = {
                'ml_on': {
                    'avg_trust': np.mean([h['trust_score'] for h in ml_on_data]) if ml_on_data else 1.0,
                    'min_trust': np.min([h['trust_score'] for h in ml_on_data]) if ml_on_data else 1.0,
                    'samples': len(ml_on_data)
                },
                'ml_off': {
                    'avg_trust': np.mean([h['trust_score'] for h in ml_off_data]) if ml_off_data else 1.0,
                    'min_trust': np.min([h['trust_score'] for h in ml_off_data]) if ml_off_data else 1.0,
                    'samples': len(ml_off_data)
                },
                'total_alerts': len(alerts),
                'high_severity_alerts': len([a for a in alerts if a.get('severity') in ['HIGH', 'CRITICAL']])
            }
            
            return stats
        except Exception as e:
            print(f"ML comparison error: {e}")
            return {}
    
    def get_alert_analytics(self, vehicle_id: str, hours: int = 24) -> Dict[str, Any]:
        """Get alert statistics and trends"""
        try:
            alerts = self.storage.get_alerts(vehicle_id, limit=200)
            
            if not alerts:
                return {'total': 0, 'by_severity': {}, 'by_type': {}}
            
            # Filter by time window
            cutoff = time.time() - (hours * 3600)
            recent_alerts = [a for a in alerts if a.get('timestamp', 0) > cutoff]
            
            # Count by severity
            severity_counts = {}
            for alert in recent_alerts:
                severity = alert.get('severity', 'UNKNOWN')
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            # Count by type
            type_counts = {}
            for alert in recent_alerts:
                event_type = alert.get('event_type', 'unknown')
                type_counts[event_type] = type_counts.get(event_type, 0) + 1
            
            return {
                'total': len(recent_alerts),
                'by_severity': severity_counts,
                'by_type': type_counts,
                'timeline': [
                    {
                        'timestamp': alert.get('timestamp', 0),
                        'severity': alert.get('severity', 'UNKNOWN'),
                        'type': alert.get('event_type', 'unknown')
                    }
                    for alert in sorted(recent_alerts, key=lambda x: x.get('timestamp', 0))
                ]
            }
        except Exception as e:
            print(f"Alert analytics error: {e}")
            return {'total': 0, 'by_severity': {}, 'by_type': {}}
    
    def get_system_health_score(self, vehicle_id: str) -> float:
        """Calculate overall system health score (0-100)"""
        try:
            # Get current vehicle status
            status = self.storage.get_vehicle_status(vehicle_id)
            if not status:
                return 0.0
            
            # Base score from trust
            trust_score = status.get('trust_score', 0.0)
            health_score = trust_score * 70  # 70% weight for trust
            
            # Penalty for recent alerts
            recent_alerts = status.get('recent_alerts', 0)
            alert_penalty = min(recent_alerts * 5, 20)  # Max 20 point penalty
            health_score -= alert_penalty
            
            # Bonus for ML enabled
            if status.get('ml_enabled', False):
                health_score += 10
            
            return max(0.0, min(100.0, health_score))
        except Exception as e:
            print(f"Health score error: {e}")
            return 0.0