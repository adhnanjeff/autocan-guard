"""
Simple Kafka Producer (No TLS)
For testing Kafka integration without security setup
"""

import json
import time
from kafka import KafkaProducer
from kafka.errors import KafkaError

class SimpleKafkaProducer:
    def __init__(self, vehicle_id="vehicleA"):
        self.vehicle_id = vehicle_id
        self.producer = None
        self._setup_producer()
    
    def _setup_producer(self):
        """Setup simple Kafka producer (no TLS)"""
        try:
            self.producer = KafkaProducer(
                bootstrap_servers=['localhost:9092'],
                value_serializer=lambda v: json.dumps(v).encode('utf-8'),
                key_serializer=lambda k: k.encode('utf-8') if k else None,
                acks='all',
                retries=3,
                batch_size=0,  # Send immediately
                linger_ms=0    # No batching delay
            )
            print(f"✅ Simple Kafka producer connected for {self.vehicle_id}")
            
        except Exception as e:
            print(f"❌ Failed to setup Kafka producer: {e}")
            self.producer = None
    
    def publish_telemetry(self, message_data):
        """Publish telemetry to vehicle.{id}.telemetry"""
        if not self.producer:
            return False
            
        topic = f"vehicle.{self.vehicle_id}.telemetry"
        
        try:
            kafka_message = {
                'vehicle_id': self.vehicle_id,
                'kafka_timestamp': time.time(),
                'message_type': 'telemetry',
                'payload': message_data
            }
            
            future = self.producer.send(topic, value=kafka_message, key=self.vehicle_id)
            future.get(timeout=10)
            return True
            
        except KafkaError as e:
            print(f"❌ Kafka publish failed: {e}")
            return False
    
    def close(self):
        """Close producer"""
        if self.producer:
            self.producer.close()
            print(f"🔌 Simple Kafka producer closed for {self.vehicle_id}")