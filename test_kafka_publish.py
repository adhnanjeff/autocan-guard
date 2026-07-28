"""Quick test to publish a sample message to Kafka"""
from simple_kafka_producer import SimpleKafkaProducer
import time

producer = SimpleKafkaProducer(vehicle_id="vehicleA")
time.sleep(1)

# Publish a test telemetry message
test_msg = {
    "can_id": 0x123,
    "data": [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
    "timestamp": time.time(),
    "vehicle_id": "vehicleA",
    "trust_score": 0.95,
    "anomaly_score": 0.12
}

print("Publishing test message...")
producer.publish_telemetry(test_msg)
print("✅ Message published to vehicle.vehicleA.telemetry")

producer.stop()
