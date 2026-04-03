#!/bin/bash

echo "🚗 Starting Vehicle Digital Twin React App"

# Install Python dependencies
echo "📦 Installing Python dependencies..."
pip install -r requirements.txt

# Install React dependencies
echo "📦 Installing React dependencies..."
cd react-app
npm install
cd ..

# Start Flask API in background
echo "🔧 Starting Flask API..."
python react_api.py &
API_PID=$!

# Wait for API to start
echo "⏳ Waiting for API to initialize..."
sleep 5

# Test API connectivity
echo "🧪 Testing API..."
curl -s http://localhost:5000/api/vehicle-state > /dev/null
if [ $? -eq 0 ]; then
    echo "✅ Flask API is running"
else
    echo "❌ Flask API failed to start"
fi

# Start React app
echo "🚀 Starting React app..."
cd react-app
npm start &
REACT_PID=$!
cd ..

echo "✅ Vehicle Digital Twin is running!"
echo "🌐 React App: http://localhost:3000"
echo "🔧 Flask API: http://localhost:5000"
echo ""
echo "📝 Make sure to also run:"
echo "   python can_generator.py  (in another terminal)"
echo ""
echo "Press Ctrl+C to stop all services"

# Wait for user interrupt
trap "echo 'Stopping services...'; kill $API_PID $REACT_PID 2>/dev/null; exit" INT
wait