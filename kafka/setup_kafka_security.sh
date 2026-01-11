#!/bin/bash

# Kafka Security Setup Script
# Creates TLS certificates and mTLS authentication for SDV network

KAFKA_DIR="kafka"
CERTS_DIR="$KAFKA_DIR/certs"

echo "🔐 Setting up Kafka Security Infrastructure..."

# Create directories
mkdir -p $CERTS_DIR

# Generate CA certificate
openssl req -new -x509 -keyout $CERTS_DIR/ca-key -out $CERTS_DIR/ca-cert -days 365 -nodes \
    -subj "/C=US/ST=CA/L=SF/O=SDV/OU=Security/CN=kafka-ca"

# Generate Kafka broker certificate
openssl req -keyout $CERTS_DIR/kafka-server-key -out $CERTS_DIR/kafka-server-req -nodes \
    -subj "/C=US/ST=CA/L=SF/O=SDV/OU=Broker/CN=localhost"
openssl x509 -req -CA $CERTS_DIR/ca-cert -CAkey $CERTS_DIR/ca-key -in $CERTS_DIR/kafka-server-req \
    -out $CERTS_DIR/kafka-server-cert -days 365 -CAcreateserial

# Generate Vehicle A client certificate
openssl req -keyout $CERTS_DIR/vehicleA-key -out $CERTS_DIR/vehicleA-req -nodes \
    -subj "/C=US/ST=CA/L=SF/O=SDV/OU=Vehicle/CN=vehicleA"
openssl x509 -req -CA $CERTS_DIR/ca-cert -CAkey $CERTS_DIR/ca-key -in $CERTS_DIR/vehicleA-req \
    -out $CERTS_DIR/vehicleA-cert -days 365 -CAcreateserial

# Generate Vehicle B client certificate
openssl req -keyout $CERTS_DIR/vehicleB-key -out $CERTS_DIR/vehicleB-req -nodes \
    -subj "/C=US/ST=CA/L=SF/O=SDV/OU=Vehicle/CN=vehicleB"
openssl x509 -req -CA $CERTS_DIR/ca-cert -CAkey $CERTS_DIR/ca-key -in $CERTS_DIR/vehicleB-req \
    -out $CERTS_DIR/vehicleB-cert -days 365 -CAcreateserial

# Set permissions
chmod 600 $CERTS_DIR/*-key
chmod 644 $CERTS_DIR/*-cert $CERTS_DIR/ca-cert

echo "✅ Kafka security certificates generated"
echo "📁 Certificates stored in: $CERTS_DIR"