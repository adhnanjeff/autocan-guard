"""
MongoDB Analytics Database
Stores aggregated security events and patterns for online analytics
"""

import time
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
from pymongo import MongoClient, DESCENDING
from pymongo.errors import ConnectionFailure
import threading

class AnalyticsDB:
    def __init__(self, connection_string="mongodb://localhost:27017/", db_name="canpro_analytics"):
        self.connection_string = connection_string
        self.db_name = db_name
        self.client = None
        self.db = None
        self.connected = False
        self._connect()
    
    def _connect(self):
        """Connect to MongoDB"""
        try:
            self.client = MongoClient(self.connection_string, serverSelectionTimeoutMS=5000)
            self.client.admin.command('ping')  # Test connection
            self.db = self.client[self.db_name]
            self.connected = True
            print(f"✅ MongoDB Analytics connected: {self.db_name}")
            self._create_indexes()
        except ConnectionFailure:
            print("⚠️ MongoDB not available - analytics disabled")
            self.connected = False
    
    def _create_indexes(self):
        """Create indexes for efficient querying"""
        if not self.connected:
            return
        
        # Security events indexes
        self.db.security_events.create_index([("vehicle_id", 1), ("timestamp", -1)])
        self.db.security_events.create_index([("event_type", 1), ("timestamp", -1)])
        
        # Trust patterns indexes
        self.db.trust_patterns.create_index([("vehicle_id", 1), ("hour", -1)])
        
        # Attack analytics indexes
        self.db.attack_analytics.create_index([("attack_type", 1), ("date", -1)])
    
    def log_security_event(self, vehicle_id: str, event_type: str, trust_score: float, 
                          anomaly_score: float, details: Dict[str, Any]):
        """Log security event for analytics"""
        if not self.connected:
            return
        
        try:
            event = {
                "vehicle_id": vehicle_id,
                "timestamp": datetime.utcnow(),
                "event_type": event_type,  # "anomaly", "attack", "recovery"
                "trust_score": trust_score,
                "anomaly_score": anomaly_score,
                "details": details
            }
            self.db.security_events.insert_one(event)
        except Exception as e:
            print(f"Analytics DB error: {e}")
    
    def update_trust_pattern(self, vehicle_id: str, trust_score: float):
        """Update hourly trust patterns"""
        if not self.connected:
            return
        
        try:
            now = datetime.utcnow()
            hour_key = now.replace(minute=0, second=0, microsecond=0)
            
            self.db.trust_patterns.update_one(
                {"vehicle_id": vehicle_id, "hour": hour_key},
                {
                    "$inc": {"count": 1},
                    "$push": {"trust_scores": {"$each": [trust_score], "$slice": -100}},
                    "$set": {"last_update": now}
                },
                upsert=True
            )
        except Exception as e:
            print(f"Trust pattern error: {e}")
    
    def log_attack_event(self, vehicle_id: str, attack_type: str, severity: str, 
                        duration: float, ips_triggered: bool):
        """Log attack for pattern analysis"""
        if not self.connected:
            return
        
        try:
            attack = {
                "vehicle_id": vehicle_id,
                "timestamp": datetime.utcnow(),
                "date": datetime.utcnow().strftime('%Y-%m-%d'),  # Store as string
                "attack_type": attack_type,  # "flood", "replay", "malicious"
                "severity": severity,  # "low", "medium", "high", "critical"
                "duration": duration,
                "ips_triggered": ips_triggered
            }
            self.db.attack_analytics.insert_one(attack)
        except Exception as e:
            print(f"Attack analytics error: {e}")
    
    def get_security_summary(self, vehicle_id: str, hours: int = 24) -> Dict[str, Any]:
        """Get security summary for dashboard"""
        if not self.connected:
            return {}
        
        try:
            since = datetime.utcnow() - timedelta(hours=hours)
            
            # Count events by type
            pipeline = [
                {"$match": {"vehicle_id": vehicle_id, "timestamp": {"$gte": since}}},
                {"$group": {"_id": "$event_type", "count": {"$sum": 1}}},
                {"$sort": {"count": -1}}
            ]
            event_counts = list(self.db.security_events.aggregate(pipeline))
            
            # Average trust score
            trust_pipeline = [
                {"$match": {"vehicle_id": vehicle_id, "timestamp": {"$gte": since}}},
                {"$group": {"_id": None, "avg_trust": {"$avg": "$trust_score"}}}
            ]
            trust_result = list(self.db.security_events.aggregate(trust_pipeline))
            avg_trust = trust_result[0]["avg_trust"] if trust_result else 1.0
            
            return {
                "event_counts": {item["_id"]: item["count"] for item in event_counts},
                "avg_trust_score": round(avg_trust, 3),
                "period_hours": hours
            }
        except Exception as e:
            print(f"Security summary error: {e}")
            return {}
    
    def get_attack_trends(self, days: int = 7) -> List[Dict[str, Any]]:
        """Get attack trends for analytics"""
        if not self.connected:
            return []
        
        try:
            since = datetime.utcnow().date() - timedelta(days=days)
            
            pipeline = [
                {"$match": {"date": {"$gte": since}}},
                {"$group": {
                    "_id": {"date": "$date", "attack_type": "$attack_type"},
                    "count": {"$sum": 1},
                    "avg_duration": {"$avg": "$duration"}
                }},
                {"$sort": {"_id.date": -1}}
            ]
            return list(self.db.attack_analytics.aggregate(pipeline))
        except Exception as e:
            print(f"Attack trends error: {e}")
            return []

# Global analytics instance
analytics_db = AnalyticsDB()