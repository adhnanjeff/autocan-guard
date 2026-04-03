"""
Kafka Producer for SDV Network
Publishes signed CAN messages to vehicle-specific topics

Topic Design:
- vehicle.{}.telemetry (vehicle telemetry data)
- vehicle.{}.security (vehicle security events) 
- alerts.system (system-wide alerts)
"""

import json
import time
from kafka import KafkaProducer
from kafka.errors import KafkaError
import ssl
import logging

class SDVKafkaProducer:
    def __init__(self, vehicle_id="vehicleA"):
        self.vehicle_id = vehicle_id
        self.producer = None
        self._setup_producer()
    
    def _setup_producer(self):
        """Setup Kafka producer with TLS/mTLS security"""
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
            
            self.producer = KafkaProducer(
                bootstrap_servers=['localhost:9093'],
                security_protocol='SSL',
                ssl_context=ssl_context,
                value_serializer=lambda v: json.dumps(v).encode('utf-8'),
                key_serializer=lambda k: k.encode('utf-8') if k else None,
                acks='all',
                retries=3,
                batch_size=16384,
                linger_ms=10
            )
            print(f"✅ Kafka producer connected for {self.vehicle_id}")
            
        except Exception as e:
            print(f"❌ Failed to setup Kafka producer: {e}")
            self.producer = None
    
    def publish_telemetry(self, message_data):
        """Publish telemetry message to vehicle.{id}.telemetry topic"""
        if not self.producer:
            return False
            
        topic = f"vehicle.{self.vehicle_id}.telemetry"
        
        try:
            # Add Kafka metadata
            kafka_message = {
                'vehicle_id': self.vehicle_id,
                'kafka_timestamp': time.time(),
                'message_type': 'telemetry',
                'payload': message_data
            }
            
            future = self.producer.send(topic, value=kafka_message, key=self.vehicle_id)
            future.get(timeout=10)  # Block for success
            return True
            
        except KafkaError as e:
            print(f"❌ Kafka publish failed: {e}")
            return False
    
    def publish_security_event(self, event_data):
        """Publish security event to vehicle.{id}.security topic"""
        if not self.producer:
            return False
            
        topic = f"vehicle.{self.vehicle_id}.security"
        
        try:
            kafka_message = {
                'vehicle_id': self.vehicle_id,
                'kafka_timestamp': time.time(),
                'message_type': 'security',
                'payload': event_data
            }
            
            future = self.producer.send(topic, value=kafka_message, key=self.vehicle_id)
            future.get(timeout=10)
            return True
            
        except KafkaError as e:
            print(f"❌ Security event publish failed: {e}")
            return False
    
    def publish_system_alert(self, alert_data):
        """Publish system alert to alerts.system topic"""
        if not self.producer:
            return False
            
        try:
            kafka_message = {
                'source_vehicle': self.vehicle_id,
                'kafka_timestamp': time.time(),
                'message_type': 'alert',
                'payload': alert_data
            }
            
            future = self.producer.send('alerts.system', value=kafka_message, key='system')
            future.get(timeout=10)
            return True
            
        except KafkaError as e:
            print(f"❌ System alert publish failed: {e}")
            return False
    
    def close(self):
        """Close producer connection"""
        if self.producer:
            self.producer.close()
            print(f"🔌 Kafka producer closed for {self.vehicle_id}")