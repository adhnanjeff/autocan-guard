#!/bin/bash

echo "🚗 Vehicle Digital Twin - Phase 1 Setup"
echo "======================================"

# Check if running on macOS
if [[ "$OSTYPE" == "darwin"* ]]; then
    echo "📱 Detected macOS - Using simulated CAN interface"
    echo "✅ CAN simulation ready (no kernel modules needed)"
else
    echo "Setting up virtual CAN interface (vcan0)..."
    sudo modprobe vcan
    sudo ip link add dev vcan0 type vcan
    sudo ip link set up vcan0
    
    if [ $? -eq 0 ]; then
        echo "✅ Virtual CAN interface created successfully"
    else
        echo "❌ Failed to create virtual CAN interface"
        exit 1
    fi
fi

# Install dependencies
echo "Installing Python dependencies..."
pip install -r requirements.txt

echo ""
echo "🎯 Setup Complete! Now run:"
echo ""
echo "Terminal 1 (CAN Generator):"
echo "python can_generator.py"
echo ""
echo "Terminal 2 (Digital Twin Visualizer):"
echo "streamlit run digital_twin_app.py"
echo ""
echo "The system will show:"
echo "• Moving vehicle on 2D road"
echo "• Real-time speed & steering gauges"  
echo "• Vehicle position updates from CAN messages"