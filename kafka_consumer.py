"""
Kafka Consumer for SDV Network
Consumes vehicle telemetry and security events for digital twin visualization
"""

import json
import threading
import time
from kafka import KafkaConsumer
from kafka.errors import KafkaError
import ssl
from collections import defaultdict, deque

class SDVKafkaConsumer:
    def __init__(self, vehicle_id="vehicleA", consumer_group="digital-twin"):
        self.vehicle_id = vehicle_id
        self.consumer_group = consumer_group
        self.consumer = None
        self.running = False
        self.thread = None
        
        # Data storage
        self.latest_telemetry = {}
        self.security_events = deque(maxlen=100)
        self.system_alerts = deque(maxlen=50)
        self.message_count = 0
        
        self._setup_consumer()
    
    def _setup_consumer(self):
        """Setup Kafka consumer with TLS/mTLS security"""
        try:
            # SSL context for mTLS
            ssl_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_REQUIRED
            ssl_context.load_verify_locations('kafka/certs/ca-cert')
            ssl_context.load_cert_chain(
                f'kafka/certs/{self.vehicle_id}-cert',
                f'kafka/certs/{self.vehicle_id}-key'
            )
            
            # Subscribe to vehicle-specific topics
            topics = [
                f'vehicle.{self.vehicle_id}.telemetry',
                f'vehicle.{self.vehicle_id}.security',
                'alerts.system'
            ]
            
            self.consumer = KafkaConsumer(
                *topics,
                bootstrap_servers=['localhost:9093'],
                security_protocol='SSL',
                ssl_context=ssl_context,
                group_id=self.consumer_group,
                value_deserializer=lambda m: json.loads(m.decode('utf-8')),
                key_deserializer=lambda k: k.decode('utf-8') if k else None,
                auto_offset_reset='latest',
                enable_auto_commit=True,
                consumer_timeout_ms=1000
            )
            print(f"✅ Kafka consumer connected for {self.vehicle_id}")
            
        except Exception as e:
            print(f"❌ Failed to setup Kafka consumer: {e}")
            self.consumer = None
    
    def start_consuming(self):
        """Start consuming messages in background thread"""
        if not self.consumer:
            return False
            
        self.running = True
        self.thread = threading.Thread(target=self._consume_loop, daemon=True)
        self.thread.start()
        return True
    
    def _consume_loop(self):
        """Main consumption loop"""
        while self.running and self.consumer:
            try:
                message_batch = self.consumer.poll(timeout_ms=1000)
                
                for topic_partition, messages in message_batch.items():
                    for message in messages:
                        self._process_message(message)
                        self.message_count += 1
                        
            except Exception as e:
                print(f"❌ Kafka consumption error: {e}")
                time.sleep(1)
    
    def _process_message(self, message):
        """Process individual Kafka message"""
        try:
            topic = message.topic
            data = message.value
            
            if topic.endswith('.telemetry'):
                self._handle_telemetry(data)
            elif topic.endswith('.security'):
                self._handle_security_event(data)
            elif topic == 'alerts.system':
                self._handle_system_alert(data)
                
        except Exception as e:
            print(f"❌ Message processing error: {e}")
    
    def _handle_telemetry(self, data):
        """Handle telemetry message"""
        payload = data.get('payload', {})
        self.latest_telemetry = {
            'timestamp': data.get('kafka_timestamp', time.time()),
            'vehicle_id': data.get('vehicle_id'),
            'can_id': payload.get('can_id'),
            'device_id': payload.get('device_id'),
            'signature': payload.get('signature'),
            'data': payload.get('data', {})
        }
    
    def _handle_security_event(self, data):
        """Handle security event"""
        self.security_events.append({
            'timestamp': data.get('kafka_timestamp', time.time()),
            'vehicle_id': data.get('vehicle_id'),
            'event': data.get('payload', {})
        })
    
    def _handle_system_alert(self, data):
        """Handle system alert"""
        self.system_alerts.append({
            'timestamp': data.get('kafka_timestamp', time.time()),
            'source': data.get('source_vehicle'),
            'alert': data.get('payload', {})
        })
    
    def get_latest_telemetry(self):
        """Get latest telemetry data"""
        return self.latest_telemetry.copy()
    
    def get_security_events(self, limit=10):
        """Get recent security events"""
        return list(self.security_events)[-limit:]
    
    def get_system_alerts(self, limit=5):
        """Get recent system alerts"""
        return list(self.system_alerts)[-limit:]
    
    def get_message_count(self):
        """Get total message count"""
        return self.message_count
    
    def is_connected(self):
        """Check if consumer is connected and running"""
        return self.running and self.consumer is not None
    
    def stop(self):
        """Stop consuming messages"""
        self.running = False
        if self.thread:
            self.thread.join(timeout=5)
        if self.consumer:
            self.consumer.close()
            print(f"🔌 Kafka consumer closed for {self.vehicle_id}")