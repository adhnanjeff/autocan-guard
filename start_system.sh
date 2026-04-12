#!/bin/bash
# Startup script for AutoCAN Guard system

echo "🚀 Starting AutoCAN Guard System"
echo "=================================="

# Clean old data
echo "🧹 Cleaning old message files..."
rm -f /tmp/can_messages.pkl /tmp/secure_messages.pkl /tmp/ecu_commands.pkl
rm -f data/trust_log.json

# Create data directory if needed
mkdir -p data

echo "✅ Ready to start"
echo ""
echo "Now run in separate terminals:"
echo "  Terminal 1: python can_generator.py"
echo "  Terminal 2: python can_listener.py"
echo "  Terminal 3: ./start_react_app.sh"
echo ""
