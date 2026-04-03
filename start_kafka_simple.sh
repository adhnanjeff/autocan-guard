#!/bin/bash

echo "🚀 Starting Kafka for V2V Communication..."

# Start Zookeeper
echo "🔧 Starting Zookeeper..."
brew services start zookeeper

# Wait for Zookeeper
sleep 3

# Start Kafka
echo "📡 Starting Kafka..."
brew services start kafka

# Wait for Kafka to start
sleep 5

# Create V2V topic
echo "📋 Creating v2v.alerts topic..."
kafka-topics --create --topic v2v.alerts --bootstrap-server localhost:9092 --partitions 1 --replication-factor 1 2>/dev/null || echo "Topic already exists"

echo "✅ Kafka started successfully!"
echo "📡 Broker: localhost:9092"
echo "📋 V2V Topic: v2v.alerts"