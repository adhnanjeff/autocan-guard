"""
Mixed Signature Attack - Shows both VERIFIED and REJECTED messages
Demonstrates valid signatures, invalid signatures, and unsigned messages
"""

import time
import pickle
import os
from security import MessageSigner
from can_generator import _mock_bus
from can_messages import CANMessage

# Shared files used by the CAN generator/listener pipeline
SECURE_MESSAGE_FILE = "/tmp/secure_messages.pkl"

class MixedSignatureAttack:
    def __init__(self):
        self.attack_count = 0
        self.verified_count = 0
        self.rejected_count = 0
        
        # Create legitimate signers for valid messages
        self.speed_signer = MessageSigner("vehicleA-speed-ecu")
        self.steering_signer = MessageSigner("vehicleA-steering-ecu")
        self.brake_signer = MessageSigner("vehicleA-brake-ecu")
        
        print("🎭 Mixed Signature Attack Simulator initialized")
        print("   Will show both VERIFIED ✓ and REJECTED ✗ messages")
        print("   UI comments will include 'Valid HMAC signature' and 'Invalid HMAC signature'")
        print("=" * 70)

    def _encode_signal_data(self, signal_name: str, value: float) -> bytes:
        """Encode a signal value into the 8-byte CAN payload format used by the ECU."""
        if signal_name == "speed":
            return int(value * 10).to_bytes(2, 'big') + b'\x00' * 6
        if signal_name == "steering":
            return int((value + 45) * 10).to_bytes(2, 'big') + b'\x00' * 6
        if signal_name == "brake":
            return int(value * 10).to_bytes(2, 'big') + b'\x00' * 6
        return int(value * 10).to_bytes(2, 'big') + b'\x00' * 6

    def _get_signer(self, signal_name: str) -> MessageSigner:
        signers = {
            "speed": self.speed_signer,
            "steering": self.steering_signer,
            "brake": self.brake_signer,
        }
        return signers.get(signal_name, self.speed_signer)

    def _store_secure_message(self, secure_msg: dict):
        """Append the secure envelope so the listener can verify and log it."""
        secure_messages = []
        if os.path.exists(SECURE_MESSAGE_FILE):
            try:
                with open(SECURE_MESSAGE_FILE, 'rb') as f:
                    loaded = pickle.load(f)
                    if isinstance(loaded, list):
                        secure_messages = loaded
            except Exception:
                secure_messages = []

        secure_messages.append(secure_msg)
        secure_messages = secure_messages[-10:]

        with open(SECURE_MESSAGE_FILE, 'wb') as f:
            pickle.dump(secure_messages, f)

    def _send_to_listener(self, can_id: int, data: bytes, secure_msg: dict):
        """Use the same path as ECU/UI traffic so the React log updates."""
        self._store_secure_message(secure_msg)
        _mock_bus.send(CANMessage(arbitration_id=can_id, data=data))

    def _build_invalid_message(self, can_id: int, data: bytes, attack_type: str, signal_name: str):
        """Create a malformed secure envelope that still reaches signature verification."""
        signer = self._get_signer(signal_name)
        invalid_msg = signer.sign_message(can_id, data)

        if attack_type == "forged":
            invalid_msg['signature'] = '0' * 64
            attack_desc = "Forged Signature"
            expected_reason = "Invalid HMAC signature"

        elif attack_type == "tampered":
            tampered_payload = bytearray(data)
            tampered_payload[0] ^= 0x0F
            invalid_msg['payload'] = bytes(tampered_payload).hex()
            attack_desc = "Tampered Payload"
            expected_reason = "Invalid HMAC signature"

        elif attack_type == "wrong_device":
            spoofed_device = "vehicleA-brake-ecu" if signal_name != "brake" else "vehicleA-speed-ecu"
            invalid_msg['device_id'] = spoofed_device
            attack_desc = "Wrong ECU Identity"
            expected_reason = "Invalid HMAC signature"

        elif attack_type == "unsigned":
            invalid_msg['signature'] = ""
            attack_desc = "Missing Signature"
            expected_reason = "Missing required fields"

        else:
            invalid_msg['signature'] = 'f' * 64
            attack_desc = "Invalid Signature"
            expected_reason = "Invalid HMAC signature"

        return invalid_msg, attack_desc, expected_reason
    
    def send_valid_message(self, can_id: int, value: float, signer: MessageSigner, signal_name: str):
        """Send a VALID message with correct signature (should be VERIFIED)"""
        data = self._encode_signal_data(signal_name, value)
        
        # Sign with proper cryptographic signature
        secure_msg = signer.sign_message(can_id, data)

        self._send_to_listener(can_id, data, secure_msg)
        
        self.verified_count += 1
        print(f"✅ VALID: {signal_name.capitalize()} = {value} | CAN: 0x{can_id:03x} | Status: VERIFIED")
    
    def send_invalid_message(self, can_id: int, value: float, attack_type: str, signal_name: str):
        """Send an INVALID message with forged/wrong signature (should be REJECTED)"""
        data = self._encode_signal_data(signal_name, value)
        invalid_msg, attack_desc, expected_reason = self._build_invalid_message(
            can_id, data, attack_type, signal_name
        )

        self._send_to_listener(can_id, data, invalid_msg)
        
        self.rejected_count += 1
        print(
            f"❌ ATTACK: {signal_name.capitalize()} = {value} | CAN: 0x{can_id:03x} "
            f"| Type: {attack_desc} | Expected UI: REJECTED / {expected_reason}"
        )
    
    def mixed_scenario_1(self):
        """Scenario 1: Alternating valid and invalid speed messages"""
        print("\n" + "=" * 70)
        print("📍 SCENARIO 1: Alternating Valid/Invalid Speed Messages")
        print("=" * 70)
        
        # Valid speed
        self.send_valid_message(0x130, 50.0, self.speed_signer, "speed")
        time.sleep(1)
        
        # Invalid speed (forged signature)
        self.send_invalid_message(0x130, 120.0, "forged", "speed")
        time.sleep(1)
        
        # Valid speed
        self.send_valid_message(0x130, 55.0, self.speed_signer, "speed")
        time.sleep(1)
        
        # Invalid speed (tampered)
        self.send_invalid_message(0x130, 150.0, "tampered", "speed")
        time.sleep(1)
        
        # Valid speed
        self.send_valid_message(0x130, 60.0, self.speed_signer, "speed")
        time.sleep(1)
    
    def mixed_scenario_2(self):
        """Scenario 2: Mix of valid and invalid across all ECUs"""
        print("\n" + "=" * 70)
        print("📍 SCENARIO 2: Mixed Valid/Invalid Across All ECUs")
        print("=" * 70)
        
        # Valid steering
        self.send_valid_message(0x120, -10.0, self.steering_signer, "steering")
        time.sleep(0.5)
        
        # Invalid brake (wrong device)
        self.send_invalid_message(0x140, 80.0, "wrong_device", "brake")
        time.sleep(0.5)
        
        # Valid speed
        self.send_valid_message(0x130, 45.0, self.speed_signer, "speed")
        time.sleep(0.5)
        
        # Invalid steering (unsigned)
        self.send_invalid_message(0x120, 30.0, "unsigned", "steering")
        time.sleep(0.5)
        
        # Valid brake
        self.send_valid_message(0x140, 20.0, self.brake_signer, "brake")
        time.sleep(0.5)
        
        # Invalid speed (forged)
        self.send_invalid_message(0x130, 200.0, "forged", "speed")
        time.sleep(0.5)
    
    def mixed_scenario_3(self):
        """Scenario 3: Burst of mixed messages"""
        print("\n" + "=" * 70)
        print("📍 SCENARIO 3: Rapid Burst (10 messages - 5 valid, 5 invalid)")
        print("=" * 70)
        
        messages = [
            ("valid", 0x130, 40.0, self.speed_signer, "speed"),
            ("invalid", 0x130, 180.0, None, "speed"),
            ("valid", 0x120, 5.0, self.steering_signer, "steering"),
            ("invalid", 0x120, 45.0, None, "steering"),
            ("valid", 0x140, 0.0, self.brake_signer, "brake"),
            ("invalid", 0x140, 100.0, None, "brake"),
            ("valid", 0x130, 50.0, self.speed_signer, "speed"),
            ("invalid", 0x130, 220.0, None, "speed"),
            ("valid", 0x120, -15.0, self.steering_signer, "steering"),
            ("invalid", 0x120, 40.0, None, "steering"),
        ]
        
        attack_types = ["forged", "tampered", "wrong_device", "unsigned"]
        attack_idx = 0
        
        for msg_type, can_id, value, signer, signal_name in messages:
            if msg_type == "valid":
                self.send_valid_message(can_id, value, signer, signal_name)
            else:
                attack_type = attack_types[attack_idx % len(attack_types)]
                self.send_invalid_message(can_id, value, attack_type, signal_name)
                attack_idx += 1
            time.sleep(0.3)
    
    def continuous_mixed_attack(self, interval=3):
        """Run continuous mixed attack showing both verified and rejected"""
        print("\n🔥 Starting Continuous Mixed Attack")
        print("   Will alternate between VERIFIED and REJECTED messages")
        print("   Press Ctrl+C to stop\n")
        
        scenarios = [
            self.mixed_scenario_1,
            self.mixed_scenario_2,
            self.mixed_scenario_3
        ]
        
        try:
            while True:
                for scenario in scenarios:
                    scenario()
                    time.sleep(interval)
                
                print(f"\n✅ Cycle complete!")
                print(f"   📊 VERIFIED: {self.verified_count} | REJECTED: {self.rejected_count}")
                print(f"   📈 Total: {self.verified_count + self.rejected_count} messages")
                print("   Check UI logs for both green VERIFIED and red REJECTED entries\n")
                time.sleep(2)
                
        except KeyboardInterrupt:
            print(f"\n\n🛑 Attack simulation stopped")
    
    def demo_mode(self):
        """Demo mode: Show clear examples of both types"""
        print("\n🎬 DEMO MODE: Showcasing VERIFIED vs REJECTED")
        print("=" * 70)
        
        print("\n📗 Part 1: LEGITIMATE MESSAGES (Should be VERIFIED)")
        print("-" * 70)
        self.send_valid_message(0x130, 30.0, self.speed_signer, "speed")
        time.sleep(1)
        self.send_valid_message(0x120, 0.0, self.steering_signer, "steering")
        time.sleep(1)
        self.send_valid_message(0x140, 0.0, self.brake_signer, "brake")
        time.sleep(2)
        
        print("\n📕 Part 2: MALICIOUS MESSAGES (Should be REJECTED)")
        print("-" * 70)
        print("   Screenshot target: red REJECTED rows with comment 'Invalid HMAC signature'")
        self.send_invalid_message(0x130, 150.0, "forged", "speed")
        time.sleep(1)
        self.send_invalid_message(0x120, 45.0, "tampered", "steering")
        time.sleep(1)
        self.send_invalid_message(0x140, 100.0, "wrong_device", "brake")
        time.sleep(2)
        
        print("\n📙 Part 3: MIXED MESSAGES")
        print("-" * 70)
        self.send_valid_message(0x130, 40.0, self.speed_signer, "speed")
        time.sleep(0.5)
        self.send_invalid_message(0x130, 180.0, "unsigned", "speed")
        time.sleep(0.5)
        self.send_valid_message(0x130, 45.0, self.speed_signer, "speed")
        time.sleep(0.5)
        self.send_invalid_message(0x130, 200.0, "forged", "speed")
        time.sleep(0.5)
        
        print("\n" + "=" * 70)
        print("✅ DEMO COMPLETE!")
        print(f"   📊 VERIFIED: {self.verified_count} (green in UI)")
        print(f"   📊 REJECTED: {self.rejected_count} (red in UI)")
        print("=" * 70)


def main():
    attacker = MixedSignatureAttack()
    
    print("\n🎯 Choose attack scenario:")
    print("1. Demo Mode (clear examples of both types)")
    print("2. Scenario 1 (alternating speed messages)")
    print("3. Scenario 2 (mixed across all ECUs)")
    print("4. Scenario 3 (rapid burst)")
    print("5. Continuous Mixed Attack (runs forever)")
    print("6. All Scenarios (run 1-3 sequentially)")
    
    try:
        choice = input("\nEnter choice (1-6): ").strip()
        
        if choice == "1":
            attacker.demo_mode()
            
        elif choice == "2":
            attacker.mixed_scenario_1()
            print(f"\n✅ Scenario complete! VERIFIED: {attacker.verified_count} | REJECTED: {attacker.rejected_count}")
            
        elif choice == "3":
            attacker.mixed_scenario_2()
            print(f"\n✅ Scenario complete! VERIFIED: {attacker.verified_count} | REJECTED: {attacker.rejected_count}")
            
        elif choice == "4":
            attacker.mixed_scenario_3()
            print(f"\n✅ Scenario complete! VERIFIED: {attacker.verified_count} | REJECTED: {attacker.rejected_count}")
            
        elif choice == "5":
            attacker.continuous_mixed_attack(interval=3)
            
        elif choice == "6":
            print("\n🚀 Running all scenarios...")
            attacker.mixed_scenario_1()
            time.sleep(2)
            attacker.mixed_scenario_2()
            time.sleep(2)
            attacker.mixed_scenario_3()
            print(f"\n✅ All scenarios complete! VERIFIED: {attacker.verified_count} | REJECTED: {attacker.rejected_count}")
            
        else:
            print("❌ Invalid choice. Running demo mode...")
            attacker.demo_mode()
    
    except KeyboardInterrupt:
        print("\n\n🛑 Stopped by user")
    
    print("\n" + "=" * 70)
    print("📊 FINAL SUMMARY")
    print("=" * 70)
    print(f"✅ VERIFIED messages: {attacker.verified_count}")
    print(f"❌ REJECTED messages: {attacker.rejected_count}")
    print(f"📈 Total messages: {attacker.verified_count + attacker.rejected_count}")
    print("\n💡 Check UI Message Security Log:")
    print("   • Green 'VERIFIED' badges = Valid HMAC signatures")
    print("   • Red 'REJECTED' badges = Invalid/forged signatures")
    print("   • Best report screenshot: one green VERIFIED row next to one red REJECTED / Invalid HMAC signature row")
    print("=" * 70 + "\n")


if __name__ == "__main__":
    main()
