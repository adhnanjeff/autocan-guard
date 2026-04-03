#!/usr/bin/env python3
"""
MongoDB Test Data Populator
Adds 5 sample records to each collection for testing
"""

from analytics_db import analytics_db
from datetime import datetime, timedelta
import time

def populate_test_data():
    print("🔄 Populating MongoDB with test data...")
    
    # 1. Security Events (5 samples)
    security_events = [
        ("vehicleA", "anomaly", 0.85, 0.65, {"signal_name": "steering", "signal_value": 25.5, "detection_layers": ["ML:0.65"], "physics_valid": True}),
        ("vehicleA", "physics_violation", 0.45, 0.85, {"signal_name": "speed", "signal_value": 120.0, "detection_layers": ["PHYSICS:speed_limit"], "physics_valid": False}),
        ("vehicleB", "anomaly", 0.72, 0.55, {"signal_name": "brake", "signal_value": 95.0, "detection_layers": ["Energy:6.2"], "physics_valid": True}),
        ("vehicleA", "anomaly", 0.91, 0.35, {"signal_name": "steering", "signal_value": 12.0, "detection_layers": ["ML:0.35", "Jerk:2.1"], "physics_valid": True}),
        ("vehicleC", "physics_violation", 0.25, 0.95, {"signal_name": "steering", "signal_value": 60.0, "detection_layers": ["PHYSICS:steering_limit"], "physics_valid": False})
    ]
    
    for vehicle_id, event_type, trust_score, anomaly_score, details in security_events:
        analytics_db.log_security_event(vehicle_id, event_type, trust_score, anomaly_score, details)
        print(f"✅ Security event: {vehicle_id} - {event_type}")
    
    # 2. Trust Patterns (5 samples)
    trust_scores = [0.95, 0.87, 0.72, 0.91, 0.83]
    for i, trust_score in enumerate(trust_scores):
        analytics_db.update_trust_pattern("vehicleA", trust_score)
        if i < 2:  # Add some for vehicleB too
            analytics_db.update_trust_pattern("vehicleB", trust_score + 0.05)
        print(f"✅ Trust pattern: vehicleA - {trust_score}")
        time.sleep(0.1)  # Small delay to create different timestamps
    
    # 3. Attack Analytics (5 samples)
    attack_events = [
        ("vehicleA", "flood", "high", 12.5, True),
        ("vehicleB", "replay", "medium", 8.2, False),
        ("vehicleA", "ecu_compromise", "critical", 25.0, True),
        ("vehicleC", "behavioral_anomaly", "medium", 6.8, True),
        ("vehicleA", "flood", "low", 3.2, False)
    ]
    
    for vehicle_id, attack_type, severity, duration, ips_triggered in attack_events:
        analytics_db.log_attack_event(vehicle_id, attack_type, severity, duration, ips_triggered)
        print(f"✅ Attack event: {vehicle_id} - {attack_type} ({severity})")
    
    print("\n🎉 Test data populated successfully!")
    print("📊 Collections populated:")
    print("   - security_events: 5 records")
    print("   - trust_patterns: 7 records") 
    print("   - attack_analytics: 5 records")
    
    # Test analytics queries
    print("\n🔍 Testing analytics queries...")
    
    summary = analytics_db.get_security_summary("vehicleA", 24)
    print(f"Security Summary: {summary}")
    
    trends = analytics_db.get_attack_trends(7)
    print(f"Attack Trends: {len(trends)} trend records")

if __name__ == "__main__":
    populate_test_data()