# #!/usr/bin/env python3
# """
# ECU Compromise Attack
# Simulates an attacker who has compromised the CAN generator ECU
# These attacks will be ACCEPTED because they use legitimate ECU keys
# """

# import time
# import sys
# import os
# import pickle
# sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# from can_generator import send_ecu_command

# def attack_1_speed_manipulation():
#     """Attack 1: Continuous speed increase until stopped"""
#     print("🔥 ATTACK 1: Continuous Speed Acceleration via Compromised ECU")
#     print("   Sending continuous speed increases using legitimate ECU commands...")
    
#     # Continuously increase speed until user stops
#     try:
#         speed_increase = 0
#         while True:
#             send_ecu_command(speed_delta=+3.0)  # +3 km/h each time
#             speed_increase += 3
#             print(f"   💨 Speed increased by {speed_increase} km/h (Press Ctrl+C to stop)")
#             time.sleep(0.5)  # Every 0.5 seconds = 6 km/h per second
#     except KeyboardInterrupt:
#         print(f"\n   ✅ Attack stopped: Total speed increase = {speed_increase} km/h")
#         print("   🔑 Status: ALL ACCEPTED (legitimate ECU signature)")
#     print()

# def attack_2_steering_chaos():
#     """Attack 2: Chaotic steering commands (DISABLED)"""
#     print("🔥 ATTACK 2: Steering Chaos (DISABLED for speed-only demo)")
#     print("   Skipping steering attack to focus on speed...")
#     print()

# def attack_3_kafka_pollution():
#     """Attack 3: Speed-only Kafka pollution (DISABLED)"""
#     print("🔥 ATTACK 3: Kafka Data Pollution (DISABLED for speed-only demo)")
#     print("   Skipping to focus on continuous speed attack...")
#     print()

# def attack_4_persistent_compromise():
#     """Attack 4: Persistent speed increase only (DISABLED)"""
#     print("🔥 ATTACK 4: Persistent ECU Compromise (DISABLED for speed-only demo)")
#     print("   Use Attack 1 for continuous speed increase...")
#     print()

# def main():
#     print("⚔️  ECU COMPROMISE ATTACK SIMULATION")
#     print("=" * 60)
#     print()
    
#     print("🎯 ATTACK SCENARIO:")
#     print("   An attacker has compromised the CAN generator ECU")
#     print("   The ECU has legitimate signing keys")
#     print("   All attacks will be ACCEPTED by the security system")
#     print()
    
#     print("🔍 WHAT TO WATCH:")
#     print("   • CAN Listener: All messages show '✅ CRYPTO VERIFIED'")
#     print("   • UI: Trust score stays HIGH (1.0)")
#     print("   • Kafka: Contains signed malicious telemetry")
#     print("   • Vehicle: Responds to all malicious commands")
#     print()
    
#     print("🚨 SECURITY IMPLICATION:")
#     print("   Cryptographic security alone cannot detect compromised ECUs")
#     print("   Need behavioral analysis (ML) to detect anomalous patterns")
#     print()
    
#     input("Press Enter to start ECU compromise attacks...")
#     print()
    
#     attack_1_speed_manipulation()
    
#     print("=" * 60)
#     print("🎯 ATTACK SUMMARY:")
#     print("✅ Speed attack uses legitimate ECU signatures")
#     print("📡 All speed commands accepted by security system")
#     print("🔑 Trust score behavior depends on ML detection")
#     print()
#     print("🚨 CONCLUSION:")
#     print("   ECU compromise bypasses cryptographic security")
#     print("   Behavioral ML detection needed to detect speed anomalies")

# if __name__ == "__main__":
#     main()

#!/usr/bin/env python3
"""
ECU Compromise Attack
Simulates an attacker who has compromised the CAN generator ECU
These attacks will be ACCEPTED because they use legitimate ECU keys
"""

import time
import sys
import os
import pickle
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from can_generator import send_ecu_command

def attack_1_speed_manipulation():
    """Attack 1: Manipulate speed to dangerous levels"""
    print("🔥 ATTACK 1: Speed Manipulation via Compromised ECU")
    print("   Sending legitimate ECU commands to reach dangerous speeds...")
    
    # Rapidly increase speed using legitimate ECU commands
    for i in range(20):
        send_ecu_command(speed_delta=+5.0)  # +5 km/h each time
        time.sleep(0.1)
    
    print("   ✅ Attack sent: Speed increased by 100 km/h")
    print("   🔑 Status: WILL BE ACCEPTED (legitimate ECU signature)")
    print()

def attack_2_steering_chaos():
    """Attack 2: Chaotic steering commands"""
    print("🔥 ATTACK 2: Steering Chaos via Compromised ECU")
    print("   Sending rapid steering changes using legitimate ECU...")
    
    # Rapid steering changes
    for i in range(10):
        send_ecu_command(steering_delta=+15.0 if i % 2 == 0 else -15.0)
        time.sleep(0.2)
    
    print("   ✅ Attack sent: Chaotic steering commands")
    print("   🔑 Status: WILL BE ACCEPTED (legitimate ECU signature)")
    print()

def attack_3_kafka_pollution():
    """Attack 3: Pollute Kafka with malicious but signed data"""
    print("🔥 ATTACK 3: Kafka Data Pollution")
    print("   Compromised ECU publishing malicious data to Kafka...")
    
    # This will use the ECU's legitimate Kafka producer
    # The data will be signed and published to Kafka
    send_ecu_command(speed_delta=+50.0)  # Sudden speed spike
    time.sleep(0.5)
    send_ecu_command(steering_delta=+30.0)  # Max steering
    time.sleep(0.5)
    send_ecu_command(speed_delta=-100.0)  # Emergency brake
    
    print("   ✅ Attack sent: Malicious data in Kafka")
    print("   🔑 Status: WILL BE ACCEPTED (legitimate ECU keys)")
    print("   📡 Kafka: Contains signed malicious telemetry")
    print()

def attack_4_persistent_compromise():
    """Attack 4: Persistent malicious behavior"""
    print("🔥 ATTACK 4: Persistent ECU Compromise")
    print("   Simulating ongoing malicious ECU behavior...")
    
    print("   Running for 30 seconds with malicious patterns...")
    start_time = time.time()
    
    while time.time() - start_time < 30:
        # Oscillating dangerous behavior
        send_ecu_command(speed_delta=+10.0)
        time.sleep(1)
        send_ecu_command(steering_delta=+20.0)
        time.sleep(1)
        send_ecu_command(speed_delta=-5.0)
        time.sleep(1)
        send_ecu_command(steering_delta=-20.0)
        time.sleep(1)
    
    print("   ✅ Attack completed: 30 seconds of malicious ECU behavior")
    print("   🔑 Status: ALL ACCEPTED (compromised but legitimate ECU)")
    print()

def main():
    print("⚔️  ECU COMPROMISE ATTACK SIMULATION")
    print("=" * 60)
    print()
    
    print("🎯 ATTACK SCENARIO:")
    print("   An attacker has compromised the CAN generator ECU")
    print("   The ECU has legitimate signing keys")
    print("   All attacks will be ACCEPTED by the security system")
    print()
    
    print("🔍 WHAT TO WATCH:")
    print("   • CAN Listener: All messages show '✅ CRYPTO VERIFIED'")
    print("   • UI: Trust score stays HIGH (1.0)")
    print("   • Kafka: Contains signed malicious telemetry")
    print("   • Vehicle: Responds to all malicious commands")
    print()
    
    print("🚨 SECURITY IMPLICATION:")
    print("   Cryptographic security alone cannot detect compromised ECUs")
    print("   Need behavioral analysis (ML) to detect anomalous patterns")
    print()
    
    input("Press Enter to start ECU compromise attacks...")
    print()
    
    attack_1_speed_manipulation()
    time.sleep(3)
    
    attack_2_steering_chaos()
    time.sleep(3)
    
    attack_3_kafka_pollution()
    time.sleep(3)
    
    print("🔥 FINAL ATTACK: Persistent Compromise")
    print("   This will run for 30 seconds...")
    print("   Watch the UI and Kafka for malicious but signed data")
    print()
    
    attack_4_persistent_compromise()
    
    print("=" * 60)
    print("🎯 ATTACK SUMMARY:")
    print("✅ All attacks ACCEPTED (legitimate ECU signatures)")
    print("📡 Kafka contains signed malicious telemetry")
    print("🔑 Trust score remains HIGH despite malicious behavior")
    print()
    print("🚨 CONCLUSION:")
    print("   ECU compromise bypasses cryptographic security")
    print("   Behavioral ML detection needed for Phase 5")

if __name__ == "__main__":
    main()