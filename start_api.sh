#!/bin/bash

echo "🔧 Starting Flask API for React App"

# Install dependencies if needed
pip install flask flask-cors > /dev/null 2>&1

# Start Flask API
echo "🚀 Starting API on http://localhost:5000"
python react_api.py