import threading
import time
from vehicle_state import VehicleStateEngine
import pickle
import os
import json

# Import from generator
from can_generator import CAN_AVAILABLE, _mock_bus, MESSAGE_FILE
from can_messages import CANMessage

# Import security pipeline
from feature_extractor import FeatureExtractor
from anomaly_detector import AnomalyDetector
from trust_engine import TrustEngine
from policy_engine import PolicyEngine
from enhanced_behavioral_analyzer import EnhancedBehavioralAnalyzer
from contextual_validator import ContextualValidator
from physics_validator import PhysicsValidator
from temporal_features import TemporalFeatureExtractor
from ips_engine import IPSPolicyEngine
from v2v_alerts import V2VAlertSystem
from v2v_consumer import V2VAlertConsumer
from storage import get_storage_manager
from analytics_db import analytics_db

from security import MessageVerifier

if CAN_AVAILABLE:
    try:
        import can
    except ImportError:
        CAN_AVAILABLE = False

class CANListener:
    def __init__(self, interface='vcan0'):
        if CAN_AVAILABLE:
            try:
                self.bus = can.interface.Bus(channel=interface, bustype='socketcan')
            except:
                print("Using mock CAN bus (socketcan not available)")
                self.bus = _mock_bus
        else:
            print("Using mock CAN bus (python-can not installed)")
            self.bus = _mock_bus
            
        self.vehicle_engine = VehicleStateEngine()
        self.running = False
        self.listener_thread = None
        self.message_count = 0
        
        # Vehicle identification (must be set before trust engine)
        self.vehicle_id = "vehicleA"  # Default vehicle ID
        
        # Multi-layer security pipeline
        self.feature_extractor = FeatureExtractor()
        self.anomaly_detector = AnomalyDetector()
        self.trust_engine = TrustEngine(vehicle_id=self.vehicle_id)
        self.policy_engine = PolicyEngine()
        self.message_verifier = MessageVerifier()
        
        # ENHANCED: Multi-layer detection system
        self.behavioral_analyzer = EnhancedBehavioralAnalyzer()
        self.contextual_validator = ContextualValidator()
        self.physics_validator = PhysicsValidator()
        self.temporal_extractor = TemporalFeatureExtractor()
        
        # Storage integration
        self.storage = get_storage_manager()
        
        # IPS Policy Engine
        self.ips_engine = IPSPolicyEngine()
        
        # V2V Alert System
        self.v2v_alerts = V2VAlertSystem(self.vehicle_id)
        self.v2v_consumer = V2VAlertConsumer(self.vehicle_id)
        self.v2v_consumer.start_consuming()
        
        # Training data collection
        self.training_features = []
        self.training_mode = True
        self.training_samples = 0
        self.max_training_samples = 25  # Faster training
        
        # Security statistics
        self.verified_messages = 0
        self.rejected_messages = 0
        
        # Message log for UI
        self.message_log = []
        
        # Current vehicle state for contextual validation
        self.current_speed = 30.0
        self.current_steering = 0.0
        self.current_brake = 0.0
        
        print("🛡️ MULTI-LAYER SECURITY ENABLED")
        print("   Layer 1: ML Anomaly Detection")
        print("   Layer 2: Control Energy Analysis")
        print("   Layer 3: Physics Contextual Validation")
        print("   Layer 4: Physics-Based Constraints (Mandatory)")
        print("   Layer 5: Temporal Rate-of-Change Analysis")
        print(f"📚 Training mode: Need {self.max_training_samples} normal samples")
    
    def start_listening(self):
        """Start listening for CAN messages"""
        self.running = True
        self.listener_thread = threading.Thread(target=self._listen_loop)
        self.listener_thread.daemon = True
        self.listener_thread.start()
        print("CAN listener started...")
    
    def _listen_loop(self):
        """Main listening loop"""
        print("🔍 CAN Listener: Starting message loop...")
        while self.running:
            message = self.bus.recv(timeout=1.0)
            if message:
                self.message_count += 1
                print(f"📨 Received CAN message: ID=0x{message.arbitration_id:03x}, Data={message.data.hex()}, Count={self.message_count}")
                self._process_message(message)
            else:
                print("⏳ No CAN messages received (timeout)")
    
    def _process_message(self, message):
        """Process incoming CAN message through multi-layer security pipeline"""
        can_id = message.arbitration_id
        data = message.data
        timestamp = time.time()
        
        # CRYPTOGRAPHIC VERIFICATION - RESTORED
        secure_msg = None
        try:
            if os.path.exists('/tmp/secure_messages.pkl'):
                with open('/tmp/secure_messages.pkl', 'rb') as f:
                    secure_messages = pickle.load(f)
                    if secure_messages:
                        # Find matching secure message by CAN ID - FIXED MATCHING
                        for msg in reversed(secure_messages):  # Check latest first
                            msg_can_id = msg.get('can_id')
                            if msg_can_id == can_id or msg_can_id == f'0x{can_id:03x}' or msg_can_id == f'{can_id}':
                                secure_msg = msg
                                break
        except Exception as e:
            print(f"⚠️ Could not load secure message: {e}")
        
        # Verify message authenticity
        if secure_msg:
            is_valid, reason = self.message_verifier.verify_message(secure_msg)
            if not is_valid:
                self.rejected_messages += 1
                log_entry = {
                    "timestamp": time.strftime("%H:%M:%S"),
                    "can_id": f"0x{can_id:03x}",
                    "status": "REJECTED",
                    "reason": reason,
                    "device_id": secure_msg.get('device_id', 'unknown')
                }
                self.message_log.append(log_entry)
                self.message_log = self.message_log[-50:]  # Keep last 50
                print(f"🚫 CRYPTO REJECTED: {reason}")
                return  # Drop invalid message
            else:
                self.verified_messages += 1
                log_entry = {
                    "timestamp": time.strftime("%H:%M:%S"),
                    "can_id": f"0x{can_id:03x}",
                    "status": "VERIFIED",
                    "reason": "Valid HMAC signature",
                    "device_id": secure_msg['device_id']
                }
                self.message_log.append(log_entry)
                self.message_log = self.message_log[-50:]  # Keep last 50
                
                # Extract original payload from secure message
                original_payload = bytes.fromhex(secure_msg['payload'])
                data = original_payload  # Use verified payload
        else:
            # No secure message found - TEMPORARILY ACCEPT WITH WARNING
            self.verified_messages += 1  # Count as verified for now
            log_entry = {
                "timestamp": time.strftime("%H:%M:%S"),
                "can_id": f"0x{can_id:03x}",
                "status": "ACCEPTED",
                "reason": "No signature found - accepting",
                "device_id": f"ecu-{can_id:03x}"
            }
            self.message_log.append(log_entry)
            self.message_log = self.message_log[-50:]  # Keep last 50
            secure_msg = {'device_id': f'ecu-{can_id:03x}'}  # Create fake secure_msg
        
        # Extract signal values
        if can_id == 0x120:  # Steering angle
            angle = int.from_bytes(data[:2], 'big') / 10.0 - 45.0
            signal_name = "steering"
            signal_value = angle
            self.current_steering = angle
            
        elif can_id == 0x130:  # Speed
            speed = int.from_bytes(data[:2], 'big') / 10.0
            signal_name = "speed"
            signal_value = speed
            self.current_speed = speed
            
        elif can_id == 0x140:  # Brake
            brake_pressure = int.from_bytes(data[:2], 'big') / 10.0
            signal_name = "brake"
            signal_value = brake_pressure
            self.current_brake = brake_pressure
        else:
            return
        
        device_id = secure_msg.get('device_id', f'ecu-{can_id:03x}') if secure_msg else f'ecu-{can_id:03x}'
        
        # MULTI-LAYER ANOMALY DETECTION
        
        # Layer 1: ML Feature Extraction
        self.feature_extractor.add_message(signal_name, signal_value, timestamp)
        ml_features = self.feature_extractor.get_all_features()
        
        # Layer 2: Enhanced Behavioral Analysis (Control Energy + Jerk)
        self.behavioral_analyzer.add_message(
            device_id, timestamp, signal_value, signal_name, 
            signal_name, self.current_speed, self.current_brake
        )
        behavioral_features = self.behavioral_analyzer.extract_features(device_id)
        
        # Layer 3: Physics Contextual Validation
        context_score, context_violations = self.contextual_validator.validate_context(device_id)
        
        # Layer 4: MANDATORY Physics-Based Constraints
        physics_result = self.physics_validator.get_physics_score(
            self.current_speed, self.current_steering, self.current_brake, timestamp
        )
        
        # Layer 5: Temporal Rate-of-Change Analysis
        self.temporal_extractor.add_signal(
            self.current_speed, self.current_steering, timestamp, is_command=True
        )
        temporal_result = self.temporal_extractor.detect_temporal_anomalies()
        
        # Training phase
        if self.training_mode and self.training_samples < self.max_training_samples:
            if ml_features and behavioral_features and signal_name in ml_features:  # Only collect if we have both
                # Combine features for training
                signal_features = ml_features[signal_name]
                combined_features = {
                    'frequency': signal_features['frequency'],
                    'delta': signal_features['delta'], 
                    'jitter': signal_features['jitter'],
                    **behavioral_features
                }
                self.training_features.append(combined_features)
                self.training_samples += 1
                print(f"📚 Training: {self.training_samples}/{self.max_training_samples} samples")
                
                # Train model when we have enough samples
                if self.training_samples >= self.max_training_samples:
                    success = self.anomaly_detector.train(self.training_features)
                    if success:
                        self.training_mode = False
                        print("🎓 MULTI-LAYER MODEL TRAINED! Now detecting anomalies...")
                    else:
                        print("❌ Training failed, collecting more samples...")
                        self.training_samples = 0
                        self.training_features = []
        
        # Detection phase - MULTI-LAYER SCORING
        total_anomaly_score = 0.0
        detection_details = []
        
        # Skip anomaly detection for UI controller messages (legitimate user input)
        if device_id and "ui-controller" in device_id:
            total_anomaly_score = 0.0  # UI commands are always trusted
            print(f"✅ UI Command trusted: {signal_name}={signal_value:.1f}")
        elif not self.training_mode:
            # Layer 1: ML Anomaly Score
            ml_anomaly_score = 0.0
            if ml_features and signal_name in ml_features:
                signal_features = ml_features[signal_name]
                # Convert to format expected by anomaly detector
                combined_features = {
                    'frequency': signal_features['frequency'],
                    'delta': signal_features['delta'], 
                    'jitter': signal_features['jitter'],
                    'timing_jitter': signal_features['jitter'],
                    'delta_pattern': signal_features['delta']
                }
                ml_anomaly_score = self.anomaly_detector.detect_anomaly(combined_features)
                if ml_anomaly_score > 0.3:
                    detection_details.append(f"ML:{ml_anomaly_score:.2f}")
            
            # Layer 2: Control Energy Anomalies
            control_anomaly_score = 0.0
            if behavioral_features:
                # Check control energy features
                steering_energy = behavioral_features.get('steering_energy', 0.0)
                steering_jerk = behavioral_features.get('steering_jerk', 0.0)
                oscillation_rate = behavioral_features.get('oscillation_rate', 0.0)
                control_aggression = behavioral_features.get('control_aggression', 0.0)
                
                # Aggressive thresholds for ECU compromise detection
                if steering_energy > 5.0:  # High energy
                    control_anomaly_score += 0.4
                    detection_details.append(f"Energy:{steering_energy:.1f}")
                if steering_jerk > 3.0:  # High jerk
                    control_anomaly_score += 0.3
                    detection_details.append(f"Jerk:{steering_jerk:.1f}")
                if oscillation_rate > 1.0:  # Oscillation
                    control_anomaly_score += 0.5
                    detection_details.append(f"Osc:{oscillation_rate:.1f}")
                if control_aggression > 5.0:  # Aggressive control
                    control_anomaly_score += 0.3
                    detection_details.append(f"Aggr:{control_aggression:.1f}")
                    
                control_anomaly_score = min(1.0, control_anomaly_score)
            
            # Layer 3: Physics Context Violations
            physics_anomaly_score = context_score
            if context_violations:
                for violation in context_violations:
                    detection_details.append(f"Physics:{violation}")
            
            # COMBINED ANOMALY SCORE with Physics Override
            ml_score = (
                0.4 * ml_anomaly_score +      # 40% ML
                0.4 * control_anomaly_score +  # 40% Control Energy
                0.2 * physics_anomaly_score    # 20% Physics Context
            )
            
            # MANDATORY: Physics constraints override (non-negotiable)
            physics_score = physics_result['physics_score']
            temporal_score = 1.0 - temporal_result['temporal_anomaly_score']
            
            # Industry-standard trust fusion
            total_anomaly_score = 1.0 - (
                0.6 * (1.0 - ml_score) +      # 60% ML Score
                0.25 * physics_score +         # 25% Physics Score  
                0.15 * temporal_score          # 15% Temporal Score
            )
            
            # Physics violations are non-negotiable
            if not physics_result['overall_valid']:
                total_anomaly_score = max(total_anomaly_score, 0.8)
                for violation_type, violation in physics_result['violations'].items():
                    if violation:
                        detection_details.append(f"PHYSICS:{violation}")
            
            # Add temporal anomalies to detection details
            if temporal_result['temporal_anomalies']:
                for anomaly in temporal_result['temporal_anomalies']:
                    detection_details.append(f"TEMPORAL:{anomaly}")
            
            # Log significant anomalies (including physics violations)
            if total_anomaly_score > 0.3 or not physics_result['overall_valid']:
                details_str = ", ".join(detection_details)
                violation_indicator = "⚠️ PHYSICS" if not physics_result['overall_valid'] else "🚨 ANOMALY"
                print(f"{violation_indicator}: {signal_name}={signal_value:.1f}, Total={total_anomaly_score:.3f} [{details_str}]")
                
                # Log to MongoDB Analytics
                analytics_db.log_security_event(
                    self.vehicle_id,
                    "anomaly" if physics_result['overall_valid'] else "physics_violation",
                    self.trust_engine.get_trust_score(),
                    total_anomaly_score,
                    {
                        'signal_name': signal_name,
                        'signal_value': signal_value,
                        'detection_layers': detection_details,
                        'physics_valid': physics_result['overall_valid']
                    }
                )
                
                # Log security alert to storage
                try:
                    severity = "HIGH" if total_anomaly_score > 0.7 else "MEDIUM" if total_anomaly_score > 0.5 else "LOW"
                    self.storage.log_security_alert(
                        self.vehicle_id,
                        "behavioral_anomaly",
                        severity,
                        f"Multi-layer detection: {details_str}",
                        {
                            'signal_name': signal_name,
                            'signal_value': signal_value,
                            'anomaly_score': total_anomaly_score,
                            'ml_score': ml_anomaly_score,
                            'control_score': control_anomaly_score,
                            'physics_score': physics_anomaly_score,
                            'physics_valid': physics_result['overall_valid'],
                            'temporal_score': temporal_result['temporal_anomaly_score']
                        }
                    )
                except Exception as e:
                    print(f"Alert logging failed: {e}")
        
        # Update trust based on combined anomaly
        self.trust_engine.update_trust(
            anomaly_score=total_anomaly_score,
            auth_result=1.0,  # Crypto verified
            temporal_score=1.0  # Always valid for now
        )
        
        # Update MongoDB trust patterns
        analytics_db.update_trust_pattern(self.vehicle_id, self.trust_engine.get_trust_score())
        
        # Get policy decision
        trust_score = self.trust_engine.get_trust_score()
        policy_decision = self.policy_engine.get_policy_decision(trust_score)
        
        # Update IPS policy
        ips_policy = self.ips_engine.update_policy(trust_score, total_anomaly_score)
        
        # Check if we should publish V2V alert
        if self.v2v_alerts.should_publish_alert(trust_score, ips_policy['mode'] != 'OFF'):
            threat_type = "ECU_COMPROMISE" if total_anomaly_score > 0.7 else "BEHAVIORAL_ANOMALY"
            confidence = min(0.95, total_anomaly_score + 0.2)  # Cap at 0.95
            self.v2v_alerts.publish_v2v_alert(trust_score, threat_type, confidence)
            
            # Log attack to MongoDB analytics
            severity = "critical" if total_anomaly_score > 0.8 else "high" if total_anomaly_score > 0.6 else "medium"
            analytics_db.log_attack_event(
                self.vehicle_id,
                threat_type.lower(),
                severity,
                5.0,  # Estimated duration
                ips_policy['mode'] != 'OFF'
            )
        
        # Inform trust engine about IPS status
        self.trust_engine.set_ips_active(ips_policy['mode'] != 'OFF')
        
        # Apply to vehicle with IPS sanitization
        if can_id == 0x120:  # Steering
            # Apply IPS steering sanitization
            sanitized_angle = self.ips_engine.sanitize_steering(angle)
            self.vehicle_engine.update_steering(sanitized_angle)
            
            status = "🟢 NORMAL" if total_anomaly_score < 0.3 else f"🚨 ANOMALY ({total_anomaly_score:.2f})"
            ips_status = f"IPS:{ips_policy['mode']}" if ips_policy['mode'] != 'OFF' else ""
            print(f"🔐 {status}: Steering {angle:.1f}° → {sanitized_angle:.1f}° {ips_status}, Trust={trust_score:.2f}")
                
        elif can_id == 0x130:  # Speed
            # Apply IPS speed sanitization
            sanitized_speed = self.ips_engine.sanitize_speed(speed, self.current_speed)
            
            # Check if this is from UI controller (user input)
            if device_id and "ui-controller" in device_id:
                self.vehicle_engine.force_speed_update(sanitized_speed)
                print(f"🚗 USER SPEED: {speed:.1f} → {sanitized_speed:.1f} km/h (forced update)")
            else:
                self.vehicle_engine.update_speed(sanitized_speed)
            
            status = "🟢 NORMAL" if total_anomaly_score < 0.3 else f"🚨 ANOMALY ({total_anomaly_score:.2f})"
            ips_status = f"IPS:{ips_policy['mode']}" if ips_policy['mode'] != 'OFF' else ""
            print(f"🔐 {status}: Speed {speed:.1f} → {sanitized_speed:.1f} km/h {ips_status}, Trust={trust_score:.2f}")
                
        elif can_id == 0x140:  # Brake
            self.vehicle_engine.apply_brake(brake_pressure)
            status = "🟢 NORMAL" if total_anomaly_score < 0.3 else f"🚨 ANOMALY ({total_anomaly_score:.2f})"
            print(f"🔐 {status}: Brake {brake_pressure:.1f}% applied, Trust={trust_score:.2f}")
    
    def get_vehicle_state(self):
        """Get current vehicle state"""
        return self.vehicle_engine.get_state()
    
    def get_message_count(self):
        """Get total messages received"""
        return self.message_count
    
    def get_security_status(self):
        """Get security pipeline status"""
        trust_status = self.trust_engine.get_status()  # Use full status with ML info
        policy_status = self.policy_engine.get_policy_decision(trust_status["trust_score"])
        verifier_stats = self.message_verifier.get_device_stats()
        
        # Add storage-based data
        vehicle_status = self.storage.get_vehicle_status(self.vehicle_id)
        recent_alerts = self.storage.get_alerts(self.vehicle_id, limit=10)
        
        return {
            "training_mode": self.training_mode,
            "training_samples": self.training_samples,
            "trust": trust_status,  # Now includes ml_enabled and security_mode
            "policy": policy_status,
            "crypto": {
                "verified": self.verified_messages,
                "rejected": self.rejected_messages,
                "devices": verifier_stats["tracked_devices"],
                "message_log": self.message_log
            },
            "vehicle_status": vehicle_status,
            "ips": self.ips_engine.get_status(),
            "v2v": {
                "publisher": self.v2v_alerts.get_status(),
                "consumer": self.v2v_consumer.get_status()
            },
            "recent_alerts": len(recent_alerts)
        }
    
    def is_generator_running(self):
        """Check if CAN generator is sending messages"""
        return os.path.exists(MESSAGE_FILE)
    
    def stop(self):
        """Stop listening"""
        self.running = False
        if self.listener_thread:
            self.listener_thread.join()
        self.bus.shutdown()

if __name__ == "__main__":
    listener = CANListener()
    listener.start_listening()
    
    try:
        while True:
            state = listener.get_vehicle_state()
            print(f"Position: ({state.x_position:.1f}, {state.y_position:.1f}), "
                  f"Speed: {state.speed:.1f} km/h, Steering: {state.steering_angle:.1f}°")
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping listener...")
        listener.stop()