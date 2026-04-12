"""
Comprehensive Attack Suite - Demonstrates all attack types shown in UI
- Message Injection Attack: Unauthorized messages
- Replay Attack: Previously captured messages resent  
- Denial-of-Service (DoS): Flooding the bus
- Fuzz Testing: Random/malformed data injection
"""

import time
import pickle
import os
import random
from datetime import datetime, timedelta
from security import MessageSigner
from can_messages import CANMessage

# Shared message file for communication
MESSAGE_FILE = "/tmp/can_messages.pkl"

class ComprehensiveAttackSuite:
    def __init__(self):
        self.attack_count = 0
        
        # Legitimate signers for some attacks
        self.speed_signer = MessageSigner("vehicleA-speed-ecu")
        self.steering_signer = MessageSigner("vehicleA-steering-ecu")
        self.brake_signer = MessageSigner("vehicleA-brake-ecu")
        
        # Track attack statistics
        self.injection_count = 0
        self.replay_count = 0
        self.dos_count = 0
        self.fuzz_count = 0
        
        print("🔥 Comprehensive Attack Suite initialized")
        print("   Simulates: Injection, Replay, DoS, and Fuzz attacks")
        print("=" * 70)
    
    def send_can_message(self, secure_msg: dict):
        """Send a message via pickle file"""
        with open(MESSAGE_FILE, 'wb') as f:
            pickle.dump(secure_msg, f)
        time.sleep(0.1)  # Small delay for listener to process
    
    # ========================================================================
    # ATTACK 1: Message Injection Attack
    # ========================================================================
    def injection_attack(self):
        """
        Message Injection Attack: Unauthorized messages inserted
        Sends malicious commands without valid signatures
        """
        print("\n" + "=" * 70)
        print("🚨 ATTACK 1: MESSAGE INJECTION ATTACK")
        print("=" * 70)
        print("Description: Injecting unauthorized speed commands without valid crypto")
        
        # Inject malicious speed increase
        malicious_speed = 180.0  # Way too fast
        data = int(malicious_speed * 10).to_bytes(2, 'big') + b'\x00' * 6
        
        injection_msg = {
            'can_id': 0x130,
            'device_id': 'attacker-injector',
            'payload': data.hex(),
            'signature': 'INJECTED_FAKE_SIG_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX',
            'timestamp': datetime.utcnow().isoformat()
        }
        
        print(f"   → Injecting malicious speed: {malicious_speed} km/h")
        print(f"   → Device: {injection_msg['device_id']}")
        print(f"   → Expected: Detected as 'Message Injection Attack'")
        
        self.send_can_message(injection_msg)
        self.injection_count += 1
        self.attack_count += 1
        
        time.sleep(1)
        
        # Inject malicious steering
        malicious_angle = 45.0  # Extreme turn
        data = int((malicious_angle + 45) * 10).to_bytes(2, 'big') + b'\x00' * 6
        
        injection_msg = {
            'can_id': 0x120,
            'device_id': 'attacker-steering-override',
            'payload': data.hex(),
            'signature': 'UNAUTHORIZED_STEERING_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXX',
            'timestamp': datetime.utcnow().isoformat()
        }
        
        print(f"   → Injecting malicious steering: {malicious_angle}°")
        print(f"   → Device: {injection_msg['device_id']}")
        
        self.send_can_message(injection_msg)
        self.injection_count += 1
        self.attack_count += 1
        
        print("   ✓ Injection attacks sent\n")
    
    # ========================================================================
    # ATTACK 2: Replay Attack
    # ========================================================================
    def replay_attack(self):
        """
        Replay Attack: Previously captured messages resent
        Captures a valid message and replays it multiple times
        """
        print("\n" + "=" * 70)
        print("🚨 ATTACK 2: REPLAY ATTACK")
        print("=" * 70)
        print("Description: Capturing and replaying valid messages multiple times")
        
        # Capture a "valid" message with signature
        captured_speed = 50.0
        data = int(captured_speed * 10).to_bytes(2, 'big') + b'\x00' * 6
        
        # Sign it properly
        captured_msg = self.speed_signer.sign_message(0x130, data)
        original_timestamp = captured_msg['timestamp']
        
        print(f"   → Captured legitimate speed message: {captured_speed} km/h")
        print(f"   → Original timestamp: {original_timestamp}")
        
        # Now replay it 3 times with same signature
        for i in range(3):
            time.sleep(0.8)
            
            replayed_msg = {
                'can_id': 0x130,
                'device_id': captured_msg['device_id'],
                'payload': captured_msg['payload'],
                'signature': captured_msg['signature'],  # Same signature
                'timestamp': original_timestamp  # Old timestamp - key indicator
            }
            
            print(f"   → Replay #{i+1}: Resending captured message")
            self.send_can_message(replayed_msg)
            self.replay_count += 1
            self.attack_count += 1
        
        print("   ✓ Replay attacks sent (same message 3x with old timestamp)\n")
    
    # ========================================================================
    # ATTACK 3: Denial-of-Service (DoS) Attack
    # ========================================================================
    def dos_attack(self):
        """
        Denial-of-Service (DoS): Flooding the bus with high-priority frames
        Overwhelms the CAN bus with rapid messages
        """
        print("\n" + "=" * 70)
        print("🚨 ATTACK 3: DENIAL-OF-SERVICE (DoS) ATTACK")
        print("=" * 70)
        print("Description: Flooding CAN bus with rapid-fire messages")
        
        flood_count = 15  # Send 15 rapid messages
        print(f"   → Flooding bus with {flood_count} messages in rapid succession")
        
        for i in range(flood_count):
            # Send random CAN messages rapidly
            random_can_id = random.choice([0x130, 0x120, 0x140, 0x150, 0x160])
            random_value = random.randint(0, 255)
            data = random_value.to_bytes(2, 'big') + b'\x00' * 6
            
            flood_msg = {
                'can_id': random_can_id,
                'device_id': f'dos-attacker-{i}',
                'payload': data.hex(),
                'signature': f'DOS_FLOOD_{i:03d}_XXXXXXXXXXXXXXXXXXXXXXXXXXXX',
                'timestamp': datetime.utcnow().isoformat()
            }
            
            self.send_can_message(flood_msg)
            self.dos_count += 1
            self.attack_count += 1
            
            # Minimal delay - creates flood effect
            time.sleep(0.05)
        
        print(f"   ✓ DoS attack complete: {flood_count} messages flooded\n")
    
    # ========================================================================
    # ATTACK 4: Fuzz Testing
    # ========================================================================
    def fuzz_attack(self):
        """
        Fuzz Testing: Random or malformed data injection
        Sends random/malformed payloads to test system robustness
        """
        print("\n" + "=" * 70)
        print("🚨 ATTACK 4: FUZZ TESTING ATTACK")
        print("=" * 70)
        print("Description: Injecting random and malformed data payloads")
        
        fuzz_tests = [
            # Malformed data - all zeros
            {
                'can_id': 0x130,
                'device_id': 'fuzzer-zeros',
                'payload': '0000000000000000',
                'signature': 'FUZZ_ZEROS_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX',
                'description': 'All zeros payload'
            },
            # Malformed data - all FFs
            {
                'can_id': 0x120,
                'device_id': 'fuzzer-max',
                'payload': 'ffffffffffffffff',
                'signature': 'FUZZ_MAX_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX',
                'description': 'Maximum value payload'
            },
            # Random garbage data
            {
                'can_id': 0x140,
                'device_id': 'fuzzer-random',
                'payload': ''.join([f'{random.randint(0,255):02x}' for _ in range(8)]),
                'signature': 'FUZZ_RANDOM_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXX',
                'description': 'Random garbage data'
            },
            # Invalid length payload
            {
                'can_id': 0x130,
                'device_id': 'fuzzer-short',
                'payload': '1234',  # Too short
                'signature': 'FUZZ_SHORT_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX',
                'description': 'Invalid length payload'
            },
            # Special characters attempt
            {
                'can_id': 0x120,
                'device_id': 'fuzzer-<script>',
                'payload': 'deadbeefcafebabe',
                'signature': '../../../etc/passwd',  # Path traversal attempt
                'description': 'Special chars/injection attempt'
            }
        ]
        
        for i, fuzz in enumerate(fuzz_tests):
            print(f"   → Fuzz test #{i+1}: {fuzz['description']}")
            print(f"      Payload: {fuzz['payload'][:32]}...")
            
            fuzz_msg = {
                'can_id': fuzz['can_id'],
                'device_id': fuzz['device_id'],
                'payload': fuzz['payload'],
                'signature': fuzz['signature'],
                'timestamp': datetime.utcnow().isoformat()
            }
            
            self.send_can_message(fuzz_msg)
            self.fuzz_count += 1
            self.attack_count += 1
            time.sleep(0.5)
        
        print(f"   ✓ Fuzz testing complete: {len(fuzz_tests)} malformed payloads sent\n")
    
    # ========================================================================
    # Attack Execution Modes
    # ========================================================================
    
    def run_all_attacks(self):
        """Run all attack types sequentially"""
        print("\n🔥 EXECUTING ALL ATTACK TYPES")
        print("=" * 70)
        
        self.injection_attack()
        time.sleep(2)
        
        self.replay_attack()
        time.sleep(2)
        
        self.dos_attack()
        time.sleep(2)
        
        self.fuzz_attack()
        
        self.print_summary()
    
    def continuous_attack_cycle(self):
        """Run attacks in continuous cycle"""
        print("\n🔥 STARTING CONTINUOUS ATTACK CYCLE")
        print("   Press Ctrl+C to stop")
        print("=" * 70)
        
        try:
            while True:
                attacks = [
                    ("Injection", self.injection_attack),
                    ("Replay", self.replay_attack),
                    ("DoS", self.dos_attack),
                    ("Fuzz", self.fuzz_attack)
                ]
                
                for name, attack_func in attacks:
                    print(f"\n🎯 Launching {name} Attack...")
                    attack_func()
                    time.sleep(3)
                
                print("\n✅ Attack cycle complete!")
                self.print_summary()
                print("\n⏳ Waiting 5 seconds before next cycle...")
                time.sleep(5)
                
        except KeyboardInterrupt:
            print("\n\n🛑 Attack cycle stopped by user")
            self.print_summary()
    
    def rapid_mixed_attack(self):
        """Rapid-fire mixed attacks for demo purposes"""
        print("\n💥 RAPID MIXED ATTACK MODE")
        print("   Sending all attack types in quick succession")
        print("=" * 70)
        
        # Quick injection
        self.injection_attack()
        
        # Quick replay (just 1 replay)
        captured_speed = 50.0
        data = int(captured_speed * 10).to_bytes(2, 'big') + b'\x00' * 6
        captured_msg = self.speed_signer.sign_message(0x130, data)
        replayed_msg = {
            'can_id': 0x130,
            'device_id': captured_msg['device_id'],
            'payload': captured_msg['payload'],
            'signature': captured_msg['signature'],
            'timestamp': (datetime.utcnow() - timedelta(minutes=5)).isoformat()
        }
        print("\n🚨 Quick Replay Attack")
        self.send_can_message(replayed_msg)
        self.replay_count += 1
        
        # Quick DoS burst
        print("\n🚨 Quick DoS Burst")
        for i in range(5):
            flood_msg = {
                'can_id': 0x130,
                'device_id': f'dos-{i}',
                'payload': '012c000000000000',
                'signature': f'FLOOD_{i}',
                'timestamp': datetime.utcnow().isoformat()
            }
            self.send_can_message(flood_msg)
            self.dos_count += 1
        
        # Quick fuzz
        print("\n🚨 Quick Fuzz Attack")
        self.send_can_message({
            'can_id': 0x130,
            'device_id': 'fuzzer',
            'payload': 'ffffffffffffffff',
            'signature': 'FUZZ_ATTACK',
            'timestamp': datetime.utcnow().isoformat()
        })
        self.fuzz_count += 1
        
        print("\n✅ Rapid attack complete!")
        self.print_summary()
    
    def print_summary(self):
        """Print attack statistics"""
        print("\n" + "=" * 70)
        print("📊 ATTACK SUMMARY")
        print("=" * 70)
        print(f"💉 Injection Attacks:  {self.injection_count}")
        print(f"🔁 Replay Attacks:     {self.replay_count}")
        print(f"💣 DoS Attacks:        {self.dos_count}")
        print(f"🎲 Fuzz Tests:         {self.fuzz_count}")
        print(f"📈 Total Attacks:      {self.attack_count}")
        print("=" * 70)
        print("\n💡 Check UI for attack detection logs:")
        print("   • Message Injection Attack: Unauthorized messages inserted")
        print("   • Replay Attack: Previously captured messages resent")
        print("   • Denial-of-Service (DoS): Flooding the bus")
        print("   • Fuzz Testing: Random or malformed data injection")
        print("=" * 70 + "\n")


def main():
    suite = ComprehensiveAttackSuite()
    
    print("\n🎯 Choose attack mode:")
    print("1. Run All Attacks (sequential, comprehensive)")
    print("2. Injection Attack only")
    print("3. Replay Attack only")
    print("4. DoS Attack only")
    print("5. Fuzz Testing only")
    print("6. Continuous Attack Cycle (repeats forever)")
    print("7. Rapid Mixed Attack (quick demo)")
    
    try:
        choice = input("\nEnter choice (1-7): ").strip()
        
        if choice == "1":
            suite.run_all_attacks()
            
        elif choice == "2":
            suite.injection_attack()
            suite.print_summary()
            
        elif choice == "3":
            suite.replay_attack()
            suite.print_summary()
            
        elif choice == "4":
            suite.dos_attack()
            suite.print_summary()
            
        elif choice == "5":
            suite.fuzz_attack()
            suite.print_summary()
            
        elif choice == "6":
            suite.continuous_attack_cycle()
            
        elif choice == "7":
            suite.rapid_mixed_attack()
            
        else:
            print("❌ Invalid choice. Running all attacks...")
            suite.run_all_attacks()
    
    except KeyboardInterrupt:
        print("\n\n🛑 Stopped by user")
        suite.print_summary()
    except Exception as e:
        print(f"\n❌ Error: {e}")
        suite.print_summary()


if __name__ == "__main__":
    main()
