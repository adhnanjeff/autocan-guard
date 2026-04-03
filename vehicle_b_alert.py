#!/usr/bin/env python3
"""
Vehicle B Alert Sender
Sends V2V security alert to Vehicle A
"""

import time
import json
from kafka import KafkaProducer
from security import MessageSigner

def send_vehicle_b_alert():
    print("🚗 Vehicle B: Sending security alert to Vehicle A...")
    
    # Create Kafka producer
    try:
        producer = KafkaProducer(
            bootstrap_servers=['localhost:9092'],
            value_serializer=lambda x: json.dumps(x).encode('utf-8')
        )
    except Exception as e:
        print(f"❌ Kafka connection failed: {e}")
        return
    
    # Create signer for Vehicle B
    signer = MessageSigner("vehicleB-v2v")
    
    # Create alert data
    alert_data = {
        "vehicle_id": "vehicleB",
        "timestamp": time.time(),
        "trust_score": 0.2,  # Low trust (compromised)
        "threat_type": "ECU_COMPROMISE",
        "confidence": 0.9,  # High confidence
        "location": {"lat": 0.0, "lon": 0.0},
        "alert_type": "SECURITY_INCIDENT"
    }
    
    # Sign the alert
    signed_alert = signer.sign_message("v2v_alert", json.dumps(alert_data).encode())
    
    # Send to Kafka
    try:
        producer.send('v2v.alerts', signed_alert)
        producer.flush()
        print("✅ V2V Alert sent successfully!")
        print(f"   From: Vehicle B")
        print(f"   Threat: ECU_COMPROMISE")
        print(f"   Confidence: 90%")
        print(f"   Vehicle A should receive this alert")
    except Exception as e:
        print(f"❌ Failed to send alert: {e}")
    finally:
        producer.close()

if __name__ == "__main__":
    send_vehicle_b_alert()