#!/bin/bash
# Vehicle Security API - cURL Commands
# Usage: ./api_curl.sh [command]

BASE_URL="http://localhost:8000"

case "$1" in
  "health")
    echo "🔍 Health Check"
    curl -X GET "$BASE_URL/health" | jq
    ;;
  
  "status")
    echo "📊 System Status"
    curl -X GET "$BASE_URL/system/status" | jq
    ;;
  
  "mode")
    echo "🎯 Current ML Mode"
    curl -X GET "$BASE_URL/system/mode" | jq
    ;;
  
  "ml-off")
    echo "🔴 Toggle ML OFF (Crypto Only)"
    curl -X POST "$BASE_URL/system/mode" \
      -H "Content-Type: application/json" \
      -d '{"ml_enabled": false}' | jq
    ;;
  
  "ml-on")
    echo "🟢 Toggle ML ON (Crypto + ML)"
    curl -X POST "$BASE_URL/system/mode" \
      -H "Content-Type: application/json" \
      -d '{"ml_enabled": true}' | jq
    ;;
  
  "vehicles")
    echo "🚗 All Vehicles"
    curl -X GET "$BASE_URL/vehicles" | jq
    ;;
  
  "trust")
    echo "🔒 Vehicle Trust"
    curl -X GET "$BASE_URL/vehicles/vehicleA/trust" | jq
    ;;
  
  "alerts")
    echo "⚠️ Vehicle Alerts"
    curl -X GET "$BASE_URL/vehicles/vehicleA/alerts" | jq
    ;;
  
  "history")
    echo "📈 Trust History"
    curl -X GET "$BASE_URL/vehicles/vehicleA/trust/history?limit=10" | jq
    ;;
  
  "demo")
    echo "🎯 ML Toggle Demo"
    echo "Current mode:"
    curl -s -X GET "$BASE_URL/system/mode" | jq .security_mode
    
    echo "Switching to CRYPTO_ONLY..."
    curl -s -X POST "$BASE_URL/system/mode" \
      -H "Content-Type: application/json" \
      -d '{"ml_enabled": false}' | jq .security_mode
    
    sleep 1
    
    echo "Switching to CRYPTO_PLUS_ML..."
    curl -s -X POST "$BASE_URL/system/mode" \
      -H "Content-Type: application/json" \
      -d '{"ml_enabled": true}' | jq .security_mode
    ;;
  
  *)
    echo "🚀 Vehicle Security API - cURL Commands"
    echo "Usage: $0 [command]"
    echo ""
    echo "Commands:"
    echo "  health    - Health check"
    echo "  status    - System status"
    echo "  mode      - Current ML mode"
    echo "  ml-off    - Toggle ML OFF"
    echo "  ml-on     - Toggle ML ON"
    echo "  vehicles  - List vehicles"
    echo "  trust     - Vehicle trust"
    echo "  alerts    - Vehicle alerts"
    echo "  history   - Trust history"
    echo "  demo      - ML toggle demo"
    echo ""
    echo "Example: $0 demo"
    ;;
esac