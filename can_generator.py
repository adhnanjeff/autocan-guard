import time
import threading
from dataclasses import dataclass
from typing import Optional
import pickle
import os
import json
from security import MessageSigner
from can_messages import CANMessage, ECUCommand

# Shared message file for communication
MESSAGE_FILE = "/tmp/can_messages.pkl"
COMMAND_FILE = "/tmp/ecu_commands.pkl"

# CAN availability flag for compatibility
try:
    import can
    CAN_AVAILABLE = True
except ImportError:
    CAN_AVAILABLE = False



class MockCANBus:
    def __init__(self):
        self._lock = threading.Lock()

    def send(self, message: CANMessage):
        message.timestamp = time.time()
        print(f"📤 MockBus: Sending message ID=0x{message.arbitration_id:03x}, Data={message.data.hex()}")
        with self._lock:
            messages = []
            if os.path.exists(MESSAGE_FILE):
                try:
                    with open(MESSAGE_FILE, 'rb') as f:
                        messages = pickle.load(f)
                except:
                    pass
            messages.append(message)
            messages = messages[-10:]
            with open(MESSAGE_FILE, 'wb') as f:
                pickle.dump(messages, f)
            print(f"📝 MockBus: Queue now has {len(messages)} messages")

    def recv(self, timeout=1.0) -> Optional[CANMessage]:
        start = time.time()
        while time.time() - start < timeout:
            with self._lock:
                if os.path.exists(MESSAGE_FILE):
                    try:
                        with open(MESSAGE_FILE, 'rb') as f:
                            messages = pickle.load(f)
                        if messages:
                            msg = messages.pop(0)
                            with open(MESSAGE_FILE, 'wb') as f:
                                pickle.dump(messages, f)
                            print(f"📨 MockBus: Retrieved message ID=0x{msg.arbitration_id:03x}, {len(messages)} remaining")
                            return msg
                    except Exception as e:
                        print(f"⚠️ MockBus recv error: {e}")
            time.sleep(0.01)
        print("⏳ MockBus: No messages available (timeout)")
        return None

    def shutdown(self):
        for f in [MESSAGE_FILE, COMMAND_FILE]:
            if os.path.exists(f):
                os.remove(f)

_mock_bus = MockCANBus()

class CANMessageGenerator:
    def __init__(self):
        self.bus = _mock_bus
        self.running = False

        # ECU authoritative state
        self.target_speed = 30.0
        self.target_steering = 0.0
        self.target_brake = 0.0
        self.speed_control_active = True  # Track if ECU should control speed
        
        # Cryptographic signers for each ECU
        self.speed_signer = MessageSigner("vehicleA-speed-ecu")
        self.steering_signer = MessageSigner("vehicleA-steering-ecu")
        self.brake_signer = MessageSigner("vehicleA-brake-ecu")
        
        # Kafka producer for SDV network (optional)
        try:
            from simple_kafka_producer import SimpleKafkaProducer
            self.kafka_producer = SimpleKafkaProducer("A")
            if self.kafka_producer.producer:
                print("✅ Kafka producer ready for publishing")
            else:
                print("❌ Kafka producer failed to initialize")
                self.kafka_producer = None
        except Exception as e:
            print(f"⚠️  Kafka unavailable: {e}")
            print("📡 Running in CAN-only mode")
            self.kafka_producer = None

    def start_simulation(self):
        self.running = True
        print("ECU started at 30 km/h, steering 0°")

        while self.running:
            self._apply_commands()
            if self.speed_control_active:
                self._send_speed()
            self._send_steering()
            self._send_brake()
            time.sleep(0.1)

    def _apply_commands(self):
        if not os.path.exists(COMMAND_FILE):
            return

        try:
            with open(COMMAND_FILE, 'rb') as f:
                cmd: ECUCommand = pickle.load(f)
            os.remove(COMMAND_FILE)

            if cmd.reset:
                self.target_speed = 30.0
                self.target_steering = 0.0
                self.target_brake = 0.0
                self.speed_control_active = True  # Re-enable ECU speed cool
                print(f"🔄 RESET: Speed={self.target_speed:.1f} km/h, Steering={self.target_steering:.1f}°, Brake={self.target_brake:.1f}%")
            else:
                # Handle target_speed override (from UI speed up/down)
                if hasattr(cmd, 'target_speed') and cmd.target_speed is not None:
                    self.target_speed = cmd.target_speed
                    self.speed_control_active = True  # Re-enable ECU control with new target
                    print(f"🎯 ECU adopts new target speed: {self.target_speed:.1f} km/h")
                else:
                    self.target_speed += cmd.speed_delta
                    
                self.target_steering += cmd.steering_delta
                if cmd.brake_pressure > 0:
                    self.target_brake = cmd.brake_pressure
                elif cmd.brake_pressure == 0 and self.target_brake > 0:
                    # Brake released - update target to match current vehicle speed
                    self.target_brake = 0.0
                    if hasattr(cmd, 'target_speed') and cmd.target_speed is not None:
                        self.target_speed = cmd.target_speed
                        print(f"🛑 Brake released - ECU target updated to {self.target_speed:.1f} km/h")
                    else:
                        print(f"🛑 Brake released - maintaining ECU target at {self.target_speed:.1f} km/h")

            self.target_speed = max(0, min(self.target_speed, 120))
            self.target_steering = max(-30, min(self.target_steering, 30))
            self.target_brake = max(0, min(self.target_brake, 100))

            print(
                f"ECU → Speed={self.target_speed:.1f}, "
                f"Steering={self.target_steering:.1f}, "
                f"Brake={self.target_brake:.1f}%"
            )
        except Exception as e:
            print("Command error:", e)

    def _send_speed(self):
        # Don't send speed messages while braking (let vehicle slow down naturally)
        if self.target_brake > 0:
            return
            
        # Only send if speed control is active
        if not self.speed_control_active:
            return
            
        val = int(self.target_speed * 10)
        data = val.to_bytes(2, 'big') + b'\x00' * 6
        
        print(f"📤 Sending Speed: {self.target_speed:.1f} km/h (CAN ID: 0x130, Data: {data.hex()})")
        
        # Sign the message
        secure_msg = self.speed_signer.sign_message(0x130, data)
        
        # Publish to Kafka SDV network (if available)
        if self.kafka_producer:
            print(f"📡 Attempting to publish speed {self.target_speed} to Kafka...")
            success = self.kafka_producer.publish_telemetry({
                'can_id': '0x130',
                'device_id': 'vehicleA-speed-ecu',
                'signature': secure_msg['signature'],
                'data': {'speed': self.target_speed}
            })
            if success:
                print(f"✅ Kafka: Speed {self.target_speed} published successfully")
            else:
                print(f"❌ Kafka: Speed publish failed")
        else:
            print("⚠️  No Kafka producer available")
        
        # Store secure message for listener
        secure_messages = []
        if os.path.exists('/tmp/secure_messages.pkl'):
            try:
                with open('/tmp/secure_messages.pkl', 'rb') as f:
                    loaded = pickle.load(f)
                    if isinstance(loaded, list):
                        secure_messages = loaded
            except:
                pass
        
        secure_messages.append(secure_msg)
        secure_messages = secure_messages[-10:]  # Keep last 10
        
        with open('/tmp/secure_messages.pkl', 'wb') as f:
            pickle.dump(secure_messages, f)
        
        # Send original CAN message
        self.bus.send(CANMessage(0x130, data))

    def _send_steering(self):
        # Only send steering if it has changed or initially
        if not hasattr(self, '_last_sent_steering') or self._last_sent_steering != self.target_steering:
            val = int((self.target_steering + 45) * 10)
            data = val.to_bytes(2, 'big') + b'\x00' * 6
            
            print(f"📤 Sending Steering: {self.target_steering:.1f}° (CAN ID: 0x120, Data: {data.hex()})")
            
            # Sign the message
            secure_msg = self.steering_signer.sign_message(0x120, data)
            
            # Publish to Kafka SDV network (if available)
            if self.kafka_producer:
                success = self.kafka_producer.publish_telemetry({
                    'can_id': '0x120',
                    'device_id': 'vehicleA-steering-ecu',
                    'signature': secure_msg['signature'],
                    'data': {'steering_angle': self.target_steering}
                })
                if success:
                    print(f"📡 Kafka: Steering {self.target_steering} published")
                else:
                    print(f"❌ Kafka: Steering publish failed")
            
            # Store secure message for listener
            secure_messages = []
            if os.path.exists('/tmp/secure_messages.pkl'):
                try:
                    with open('/tmp/secure_messages.pkl', 'rb') as f:
                        loaded = pickle.load(f)
                        if isinstance(loaded, list):
                            secure_messages = loaded
                except:
                    pass
            
            secure_messages.append(secure_msg)
            secure_messages = secure_messages[-10:]  # Keep last 10
            
            with open('/tmp/secure_messages.pkl', 'wb') as f:
                pickle.dump(secure_messages, f)
            
            # Send original CAN message
            self.bus.send(CANMessage(0x120, data))
            self._last_sent_steering = self.target_steering

    def _send_brake(self):
        # Only send brake if pressure > 0 or has changed
        if not hasattr(self, '_last_sent_brake') or self._last_sent_brake != self.target_brake:
            val = int(self.target_brake * 10)
            data = val.to_bytes(2, 'big') + b'\x00' * 6
            
            print(f"📤 Sending Brake: {self.target_brake:.1f}% (CAN ID: 0x140, Data: {data.hex()})")
            
            # Sign the message
            secure_msg = self.brake_signer.sign_message(0x140, data)
            
            # Publish to Kafka SDV network (if available)
            if self.kafka_producer:
                success = self.kafka_producer.publish_telemetry({
                    'can_id': '0x140',
                    'device_id': 'vehicleA-brake-ecu',
                    'signature': secure_msg['signature'],
                    'data': {'brake_pressure': self.target_brake}
                })
                if success:
                    print(f"📡 Kafka: Brake {self.target_brake} published")
                else:
                    print(f"❌ Kafka: Brake publish failed")
            
            # Store secure message for listener
            secure_messages = []
            if os.path.exists('/tmp/secure_messages.pkl'):
                try:
                    with open('/tmp/secure_messages.pkl', 'rb') as f:
                        loaded = pickle.load(f)
                        if isinstance(loaded, list):
                            secure_messages = loaded
                except:
                    pass
            
            secure_messages.append(secure_msg)
            secure_messages = secure_messages[-10:]  # Keep last 10
            
            with open('/tmp/secure_messages.pkl', 'wb') as f:
                pickle.dump(secure_messages, f)
            
            # Send original CAN message
            self.bus.send(CANMessage(0x140, data))
            self._last_sent_brake = self.target_brake

    def stop(self):
        self.running = False
        if hasattr(self, 'kafka_producer'):
            self.kafka_producer.close()
        self.bus.shutdown()

def send_ecu_command(speed_delta=0.0, steering_delta=0.0, brake_pressure=0.0, reset=False, target_speed=None):
    cmd = ECUCommand(
        speed_delta=speed_delta,
        steering_delta=steering_delta,
        brake_pressure=brake_pressure,
        reset=reset
    )
    # Add target_speed as a dynamic attribute
    cmd.target_speed = target_speed
    with open(COMMAND_FILE, 'wb') as f:
        pickle.dump(cmd, f)

if __name__ == "__main__":
    gen = CANMessageGenerator()
    try:
        gen.start_simulation()
    except KeyboardInterrupt:
        gen.stop()
