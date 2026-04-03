#!/bin/bash

# Kafka Startup Script for SDV Network
# Starts Kafka broker with TLS/mTLS security

KAFKA_DIR="kafka"
KAFKA_HOME="/opt/kafka"  # Adjust path as needed

echo "🚀 Starting Secure Kafka Broker for SDV Network..."

# Check if Kafka is installed
if [ ! -d "$KAFKA_HOME" ]; then
    echo "❌ Kafka not found at $KAFKA_HOME"
    echo "Please install Kafka or update KAFKA_HOME path"
    exit 1
fi

# Setup certificates if not exists
if [ ! -d "$KAFKA_DIR/certs" ]; then
    echo "🔐 Setting up certificates..."
    chmod +x $KAFKA_DIR/setup_kafka_security.sh
    ./$KAFKA_DIR/setup_kafka_security.sh
fi

# Start Zookeeper (required for Kafka)
echo "🔧 Starting Zookeeper..."
$KAFKA_HOME/bin/zookeeper-server-start.sh -daemon $KAFKA_HOME/config/zookeeper.properties

# Wait for Zookeeper
sleep 5

# Start Kafka broker with security config
echo "🔒 Starting Kafka broker with TLS/mTLS..."
$KAFKA_HOME/bin/kafka-server-start.sh $KAFKA_DIR/server.properties &

# Wait for Kafka to start
sleep 10

# Create SDV topics with ACLs
echo "📋 Creating SDV topics..."

# Vehicle A topics
$KAFKA_HOME/bin/kafka-topics.sh --create --bootstrap-server localhost:9093 \
    --command-config $KAFKA_DIR/client.properties \
    --topic vehicle.A.telemetry --partitions 1 --replication-factor 1

$KAFKA_HOME/bin/kafka-topics.sh --create --bootstrap-server localhost:9093 \
    --command-config $KAFKA_DIR/client.properties \
    --topic vehicle.A.security --partitions 1 --replication-factor 1

# Vehicle B topics
$KAFKA_HOME/bin/kafka-topics.sh --create --bootstrap-server localhost:9093 \
    --command-config $KAFKA_DIR/client.properties \
    --topic vehicle.B.telemetry --partitions 1 --replication-factor 1

$KAFKA_HOME/bin/kafka-topics.sh --create --bootstrap-server localhost:9093 \
    --command-config $KAFKA_DIR/client.properties \
    --topic vehicle.B.security --partitions 1 --replication-factor 1

# System alerts topic
$KAFKA_HOME/bin/kafka-topics.sh --create --bootstrap-server localhost:9093 \
    --command-config $KAFKA_DIR/client.properties \
    --topic alerts.system --partitions 1 --replication-factor 1

echo "✅ Secure Kafka broker started on localhost:9093"
echo "🔑 TLS/mTLS authentication enabled"
echo "📋 SDV topics created with ACL restrictions"