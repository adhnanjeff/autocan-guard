import time
import json
from typing import Dict, Any
from security import MessageSigner

class V2VAlertSystem:
    def __init__(self, vehicle_id: str):
        self.vehicle_id = vehicle_id
        self.signer = MessageSigner(f"{vehicle_id}-v2v")
        self.last_alert_time = 0
        self.cooldown_period = 10.0  # 10 second cooldown
        
        # Try to initialize Kafka producer
        try:
            from kafka import KafkaProducer
            self.producer = KafkaProducer(
                bootstrap_servers=['localhost:9092'],
                value_serializer=lambda x: json.dumps(x).encode('utf-8')
            )
            self.kafka_available = True
            print(f"✅ V2V Publisher connected: {vehicle_id}")
        except:
            self.producer = None
            self.kafka_available = False
            print("⚠️ V2V: Kafka not available, using mock system")
    
    def should_publish_alert(self, trust_score: float, ips_active: bool) -> bool:
        """Check if we should publish a V2V alert"""
        current_time = time.time()
        
        # Cooldown check
        if current_time - self.last_alert_time < self.cooldown_period:
            return False
        
        # Trigger condition: trust < 0.4 and IPS active
        return trust_score < 0.4 and ips_active
    
    def publish_v2v_alert(self, trust_score: float, threat_type: str, confidence: float) -> bool:
        """Publish V2V security alert"""
        current_time = time.time()
        
        # Build alert message
        alert_data = {
            "vehicle_id": self.vehicle_id,
            "timestamp": current_time,
            "trust_score": trust_score,
            "threat_type": threat_type,
            "confidence": confidence,
            "location": {"lat": 0.0, "lon": 0.0},  # Placeholder
            "alert_type": "SECURITY_INCIDENT"
        }
        
        # Sign the alert
        signed_alert = self.signer.sign_message("v2v_alert", json.dumps(alert_data).encode())
        
        # Publish to Kafka if available
        if self.kafka_available and self.producer:
            try:
                self.producer.send('v2v.alerts', signed_alert)
                self.producer.flush()
                print(f"📡 V2V ALERT SENT: {threat_type} (confidence: {confidence:.2f})")
                self.last_alert_time = current_time
                return True
            except Exception as e:
                print(f"❌ V2V publish failed: {e}")
                return False
        else:
            # Log alert locally
            print(f"📝 V2V ALERT (local): {threat_type} (confidence: {confidence:.2f})")
            self.last_alert_time = current_time
            return True
    
    def get_status(self) -> Dict[str, Any]:
        """Get V2V system status"""
        return {
            "kafka_available": self.kafka_available,
            "last_alert": self.last_alert_time,
            "cooldown_remaining": max(0, self.cooldown_period - (time.time() - self.last_alert_time))
        }