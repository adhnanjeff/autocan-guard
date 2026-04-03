import time
import json
import threading
from typing import Dict, Any, List
from security import MessageVerifier

class V2VAlertConsumer:
    def __init__(self, vehicle_id: str):
        self.vehicle_id = vehicle_id
        self.verifier = MessageVerifier()
        self.running = False
        self.consumer_thread = None
        
        # Security state
        self.security_mode = "NORMAL"  # NORMAL, HEIGHTENED
        self.received_alerts = []
        self.alert_count = 0
        
        # Try to initialize Kafka consumer
        try:
            from kafka import KafkaConsumer
            self.consumer = KafkaConsumer(
                'v2v.alerts',
                bootstrap_servers=['localhost:9092'],
                value_deserializer=lambda m: json.loads(m.decode('utf-8')),
                auto_offset_reset='latest'
            )
            self.kafka_available = True
            print(f"✅ V2V Consumer connected: {vehicle_id}")
        except:
            self.consumer = None
            self.kafka_available = False
            print("⚠️ V2V Consumer: Kafka not available")
    
    def start_consuming(self):
        """Start consuming V2V alerts"""
        if not self.kafka_available:
            return
            
        self.running = True
        self.consumer_thread = threading.Thread(target=self._consume_loop)
        self.consumer_thread.daemon = True
        self.consumer_thread.start()
        print("📡 V2V Consumer started")
    
    def _consume_loop(self):
        """Main consumption loop"""
        while self.running:
            try:
                if self.kafka_available and self.consumer:
                    message_batch = self.consumer.poll(timeout_ms=1000)
                    for topic_partition, messages in message_batch.items():
                        for message in messages:
                            if not self.running:
                                break
                            self.process_v2v_alert(message.value)
                else:
                    time.sleep(1.0)
            except Exception as e:
                print(f"V2V consume error: {e}")
                time.sleep(5.0)
    
    def process_v2v_alert(self, alert_data: Dict[str, Any]) -> bool:
        """Process incoming V2V alert"""
        try:
            # Handle both signed and direct messages
            if isinstance(alert_data, dict) and 'payload' in alert_data:
                # Signed message - decode hex payload
                payload_hex = alert_data['payload']
                payload_bytes = bytes.fromhex(payload_hex)
                payload = json.loads(payload_bytes.decode('utf-8'))
            elif isinstance(alert_data, dict):
                # Direct JSON message
                payload = alert_data
            else:
                # String JSON
                payload = json.loads(alert_data)
            
            sender_id = payload.get('vehicle_id')
            confidence = payload.get('confidence', 0.0)
            threat_type = payload.get('threat_type', 'unknown')
            timestamp = payload.get('timestamp', 0)
            
            # Check timestamp freshness (within 30 seconds)
            if time.time() - timestamp > 30.0:
                print(f"⏰ V2V Alert expired from {sender_id}")
                return False
            
            # Check confidence threshold
            if confidence < 0.8:
                print(f"📊 V2V Alert low confidence ({confidence:.2f}) from {sender_id}")
                return False
            
            # Valid alert - react
            self._react_to_alert(sender_id, threat_type, confidence)
            return True
            
        except Exception as e:
            print(f"❌ V2V Alert processing error: {e}")
            return False
    
    def _react_to_alert(self, sender_id: str, threat_type: str, confidence: float):
        """React to valid V2V alert"""
        print(f"🚨 V2V ALERT RECEIVED: {threat_type} from {sender_id} (confidence: {confidence:.2f})")
        
        # Soft defensive actions only
        if confidence > 0.8:
            self.security_mode = "HEIGHTENED"
            print("🛡️ Security mode: HEIGHTENED (increased ML sensitivity)")
        
        # Store alert
        alert_record = {
            "sender": sender_id,
            "threat_type": threat_type,
            "confidence": confidence,
            "timestamp": time.time()
        }
        self.received_alerts.append(alert_record)
        self.received_alerts = self.received_alerts[-10:]  # Keep last 10
        self.alert_count += 1
    
    def get_security_adjustment(self) -> float:
        """Get ML sensitivity adjustment based on V2V alerts"""
        if self.security_mode == "HEIGHTENED":
            # Increase ML sensitivity by reducing anomaly threshold
            return 0.1  # Subtract from anomaly threshold
        return 0.0
    
    def get_status(self) -> Dict[str, Any]:
        """Get V2V consumer status"""
        return {
            "kafka_available": self.kafka_available,
            "security_mode": self.security_mode,
            "alerts_received": self.alert_count,
            "recent_alerts": self.received_alerts[-5:],  # Last 5 alerts
            "running": self.running
        }
    
    def stop(self):
        """Stop consuming"""
        self.running = False
        if self.consumer_thread:
            self.consumer_thread.join()