#!/bin/bash
# Start Kafka Message Viewer
# Real-time display of all Kafka messages for demonstration

echo "🔍 Starting Kafka Message Viewer..."
echo "This will display all messages from vehicle topics in real-time"
echo ""

# Check if Kafka is running
if ! nc -z localhost 9092 2>/dev/null; then
    echo "❌ Kafka is not running on localhost:9092"
    echo "Start Kafka first with: ./start_kafka_simple.sh"
    exit 1
fi

# Start viewer with color output
python3 kafka_message_viewer.py --vehicle-id vehicleA

echo ""
echo "✅ Viewer stopped"
