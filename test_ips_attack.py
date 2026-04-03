#!/usr/bin/env python3
"""
Simple attack test to verify IPS prevention
"""

import time
import requests
import json

def test_ips_prevention():
    print("🔥 Testing IPS Prevention System")
    
    # Enable IPS first
    print("1. Enabling IPS...")
    response = requests.post('http://localhost:5001/api/toggle-ips', 
                           json={'enabled': True})
    if response.status_code == 200:
        print("   ✅ IPS enabled")
    else:
        print("   ❌ Failed to enable IPS")
        return
    
    # Check initial state
    print("2. Checking initial state...")
    response = requests.get('http://localhost:5001/api/vehicle-state')
    if response.status_code == 200:
        data = response.json()
        trust_score = data['security_status']['trust']['trust_score']
        ips_mode = data['security_status']['ips']['mode']
        print(f"   Trust Score: {trust_score:.2f}")
        print(f"   IPS Mode: {ips_mode}")
    
    # Simulate speed attack
    print("3. Simulating speed attack...")
    for i in range(10):
        # Send aggressive speed increase
        response = requests.post('http://localhost:5001/api/ecu-command',
                               json={'speed_delta': 5.0})  # +5 km/h each time
        
        if response.status_code == 200:
            print(f"   Attack {i+1}: Speed increase sent")
        
        # Check system response
        response = requests.get('http://localhost:5001/api/vehicle-state')
        if response.status_code == 200:
            data = response.json()
            trust_score = data['security_status']['trust']['trust_score']
            ips_mode = data['security_status']['ips']['mode']
            current_speed = data['vehicle_state']['speed']
            
            print(f"   Trust: {trust_score:.2f}, IPS: {ips_mode}, Speed: {current_speed:.1f} km/h")
            
            if ips_mode != 'OFF':
                print(f"   🛡️ IPS ACTIVATED: {ips_mode}")
                break
        
        time.sleep(0.5)
    
    print("4. Final state check...")
    response = requests.get('http://localhost:5001/api/vehicle-state')
    if response.status_code == 200:
        data = response.json()
        trust_score = data['security_status']['trust']['trust_score']
        ips_mode = data['security_status']['ips']['mode']
        ips_policy = data['security_status']['ips']['policy']
        
        print(f"   Final Trust Score: {trust_score:.2f}")
        print(f"   Final IPS Mode: {ips_mode}")
        if ips_policy.get('speed_limit'):
            print(f"   Speed Limit Applied: {ips_policy['speed_limit']} km/h")
        if ips_policy.get('steering_limit'):
            print(f"   Steering Limit Applied: ±{ips_policy['steering_limit']}°")
    
    print("✅ IPS Prevention Test Complete")

if __name__ == "__main__":
    test_ips_prevention()