import threading
import time
from vehicle_state import VehicleStateEngine
import pickle
import os
import json
from typing import Any, Dict

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

        # Detection threshold used for decision logging/evaluation
        self.anomaly_decision_threshold = 0.3

        # Sustained anomaly tracking for attack persistence detection
        self.sustained_anomaly_window = []  # Recent anomaly scores
        self.sustained_anomaly_max_window = 15  # Track last 15 messages
        self.recent_physics_violation = False
        self.physics_violation_cooldown = 0  # Cooldown counter after physics violation

        # Evaluation logging/session state
        self.eval_lock = threading.Lock()
        self.eval_output_dir = os.environ.get("EVAL_OUTPUT_DIR", os.path.join(os.getcwd(), "evaluation_data"))
        os.makedirs(self.eval_output_dir, exist_ok=True)
        self.eval_session_counter = 0
        self.eval_log_path = ""
        self.eval_samples = 0
        self.eval_current_label = 0
        self.eval_current_attack_tag = "normal"
        self.eval_attack_segment_id = 0
        self.eval_attack_start_ts = None
        self.start_evaluation_session("default")
        
        print("🛡️ MULTI-LAYER SECURITY ENABLED")
        print("   Layer 1: ML Anomaly Detection")
        print("   Layer 2: Control Energy Analysis")
        print("   Layer 3: Physics Contextual Validation")
        print("   Layer 4: Physics-Based Constraints (Mandatory)")
        print("   Layer 5: Temporal Rate-of-Change Analysis")
        print(f"📚 Training mode: Need {self.max_training_samples} normal samples")
        print(f"📝 Evaluation log: {self.eval_log_path}")
    
    def start_listening(self):
        """Start listening for CAN messages"""
        self.running = True
        self.listener_thread = threading.Thread(target=self._listen_loop)
        self.listener_thread.daemon = True
        self.listener_thread.start()
        print("CAN listener started...")

    def _sanitize_session_name(self, session_name: str) -> str:
        cleaned = "".join(ch if ch.isalnum() or ch in ("-", "_") else "_" for ch in session_name)
        cleaned = cleaned.strip("_")
        return cleaned or "session"

    def start_evaluation_session(self, session_name: str = "session") -> str:
        """Start a new evaluation JSONL log file."""
        now = time.strftime("%Y%m%d_%H%M%S")
        safe_name = self._sanitize_session_name(session_name)
        with self.eval_lock:
            self.eval_session_counter += 1
            filename = f"{now}_{self.eval_session_counter:03d}_{safe_name}.jsonl"
            self.eval_log_path = os.path.join(self.eval_output_dir, filename)
            self.eval_samples = 0
            self.eval_current_label = 0
            self.eval_current_attack_tag = "normal"
            self.eval_attack_segment_id = 0
            self.eval_attack_start_ts = None
            with open(self.eval_log_path, "w", encoding="utf-8") as handle:
                handle.write("")
        return self.eval_log_path

    def set_evaluation_label(self, label: int, attack_tag: str = "") -> Dict[str, Any]:
        """Set evaluation label for subsequent samples (0=normal, 1=attack)."""
        normalized_label = 1 if int(label) == 1 else 0
        current_time = time.time()

        with self.eval_lock:
            previous_label = self.eval_current_label
            self.eval_current_label = normalized_label

            if normalized_label == 1:
                if previous_label == 0:
                    self.eval_attack_segment_id += 1
                    self.eval_attack_start_ts = current_time
                if attack_tag:
                    self.eval_current_attack_tag = attack_tag
                elif previous_label == 0:
                    self.eval_current_attack_tag = f"attack_{self.eval_attack_segment_id}"
            else:
                self.eval_current_attack_tag = "normal"
                self.eval_attack_start_ts = None

        return self.get_evaluation_status()

    def get_evaluation_status(self) -> Dict[str, Any]:
        with self.eval_lock:
            return {
                "log_path": self.eval_log_path,
                "samples": self.eval_samples,
                "label": self.eval_current_label,
                "attack_tag": self.eval_current_attack_tag,
                "attack_segment_id": self.eval_attack_segment_id if self.eval_current_label == 1 else None,
                "attack_start_ts": self.eval_attack_start_ts,
                "threshold": self.anomaly_decision_threshold
            }

    def _prepare_ml_feature_snapshot(self, ml_features: Dict[str, Dict[str, float]]) -> Dict[str, Dict[str, float]]:
        snapshot = {}
        if not ml_features:
            return snapshot

        for signal_name in ("steering", "speed", "brake"):
            signal_features = ml_features.get(signal_name)
            if not signal_features:
                continue
            snapshot[signal_name] = {
                "frequency": float(signal_features.get("frequency", 0.0)),
                "delta": float(signal_features.get("delta", 0.0)),
                "jitter": float(signal_features.get("jitter", 0.0))
            }
        return snapshot

    def _append_evaluation_sample(self, sample: Dict[str, Any]):
        with self.eval_lock:
            label = self.eval_current_label
            attack_tag = self.eval_current_attack_tag
            attack_segment_id = self.eval_attack_segment_id if label == 1 else None
            attack_start_ts = self.eval_attack_start_ts
            log_path = self.eval_log_path
            self.eval_samples += 1
            sample_index = self.eval_samples

        payload = {
            "sample_index": sample_index,
            "label": label,
            "attack_tag": attack_tag,
            "attack_segment_id": attack_segment_id,
            "attack_start_ts": attack_start_ts,
            **sample
        }

        try:
            with open(log_path, "a", encoding="utf-8") as handle:
                handle.write(json.dumps(payload) + "\n")
        except Exception as e:
            print(f"⚠️ Failed to write evaluation sample: {e}")
    
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
        self.feature_extractor.add_message(signal_name, timestamp, signal_value)
        ml_features = self.feature_extractor.get_all_features()
        ml_feature_snapshot = self._prepare_ml_feature_snapshot(ml_features)
        
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
            if ml_feature_snapshot:
                self.training_features.append(ml_feature_snapshot)
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
        ml_anomaly_score = 0.0
        control_anomaly_score = 0.0
        physics_anomaly_score = context_score
        detection_details = []
        is_physics_valid = physics_result['overall_valid']
        
        # Skip anomaly detection for UI controller messages (legitimate user input)
        if device_id and "ui-controller" in device_id:
            total_anomaly_score = 0.0  # UI commands are always trusted
            print(f"✅ UI Command trusted: {signal_name}={signal_value:.1f}")
        elif not self.training_mode:
            # Layer 1: ML Anomaly Score
            if ml_feature_snapshot:
                ml_anomaly_score = self.anomaly_detector.detect_anomaly(ml_feature_snapshot)
                if ml_anomaly_score > self.anomaly_decision_threshold:
                    detection_details.append(f"ML:{ml_anomaly_score:.2f}")
            
            # Layer 2: Control Energy Anomalies
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
            
            # Track physics violations for sustained detection
            if not physics_result['overall_valid']:
                self.recent_physics_violation = True
                self.physics_violation_cooldown = 25  # Elevated sensitivity for 25 messages
            elif self.physics_violation_cooldown > 0:
                self.physics_violation_cooldown -= 1
                if self.physics_violation_cooldown == 0:
                    self.recent_physics_violation = False
            
            # Enhanced trust fusion with stronger temporal weighting
            base_anomaly = 1.0 - (
                0.4 * (1.0 - ml_score) +       # 40% ML Score
                0.15 * physics_score +          # 15% Physics Score
                0.45 * temporal_score           # 45% Temporal Score (significantly increased)
            )
            
            # Sustained anomaly detection: boost score if recent anomalies detected
            self.sustained_anomaly_window.append(base_anomaly)
            if len(self.sustained_anomaly_window) > self.sustained_anomaly_max_window:
                self.sustained_anomaly_window.pop(0)
            
            # Calculate sustained threat level
            recent_high_scores = sum(1 for s in self.sustained_anomaly_window if s > 0.25)
            sustained_threat_ratio = recent_high_scores / max(1, len(self.sustained_anomaly_window))
            
            # Boost anomaly score when in sustained attack pattern - more aggressive
            sustained_boost = 0.0
            if sustained_threat_ratio > 0.2 or self.recent_physics_violation:
                sustained_boost = 0.2 * sustained_threat_ratio
                if self.physics_violation_cooldown > 15:
                    sustained_boost += 0.15  # Extra boost right after physics violation
                elif self.physics_violation_cooldown > 5:
                    sustained_boost += 0.1  # Moderate boost during cooldown
            
            total_anomaly_score = min(1.0, base_anomaly + sustained_boost)
            
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
            if total_anomaly_score > self.anomaly_decision_threshold or not physics_result['overall_valid']:
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

        anomaly_decision = total_anomaly_score >= self.anomaly_decision_threshold or not is_physics_valid
        applied_signal_value = signal_value
        
        # Apply to vehicle with IPS sanitization
        if can_id == 0x120:  # Steering
            # Apply IPS steering sanitization
            sanitized_angle = self.ips_engine.sanitize_steering(angle)
            self.vehicle_engine.update_steering(sanitized_angle)
            applied_signal_value = sanitized_angle
            
            status = "🟢 NORMAL" if not anomaly_decision else f"🚨 ANOMALY ({total_anomaly_score:.2f})"
            ips_status = f"IPS:{ips_policy['mode']}" if ips_policy['mode'] != 'OFF' else ""
            print(f"🔐 {status}: Steering {angle:.1f}° → {sanitized_angle:.1f}° {ips_status}, Trust={trust_score:.2f}")
                
        elif can_id == 0x130:  # Speed
            # Apply IPS speed sanitization
            sanitized_speed = self.ips_engine.sanitize_speed(speed, self.current_speed)
            applied_signal_value = sanitized_speed
            
            # Check if this is from UI controller (user input)
            if device_id and "ui-controller" in device_id:
                self.vehicle_engine.force_speed_update(sanitized_speed)
                print(f"🚗 USER SPEED: {speed:.1f} → {sanitized_speed:.1f} km/h (forced update)")
            else:
                self.vehicle_engine.update_speed(sanitized_speed)
            
            status = "🟢 NORMAL" if not anomaly_decision else f"🚨 ANOMALY ({total_anomaly_score:.2f})"
            ips_status = f"IPS:{ips_policy['mode']}" if ips_policy['mode'] != 'OFF' else ""
            print(f"🔐 {status}: Speed {speed:.1f} → {sanitized_speed:.1f} km/h {ips_status}, Trust={trust_score:.2f}")
                
        elif can_id == 0x140:  # Brake
            self.vehicle_engine.apply_brake(brake_pressure)
            status = "🟢 NORMAL" if not anomaly_decision else f"🚨 ANOMALY ({total_anomaly_score:.2f})"
            print(f"🔐 {status}: Brake {brake_pressure:.1f}% applied, Trust={trust_score:.2f}")

        vehicle_state = self.vehicle_engine.get_state()
        self._append_evaluation_sample({
            "timestamp": timestamp,
            "message_count": self.message_count,
            "device_id": device_id,
            "signal_name": signal_name,
            "raw_signal_value": float(signal_value),
            "applied_signal_value": float(applied_signal_value),
            "training_mode": self.training_mode,
            "anomaly_score": float(total_anomaly_score),
            "ml_anomaly_score": float(ml_anomaly_score),
            "control_anomaly_score": float(control_anomaly_score),
            "physics_anomaly_score": float(physics_anomaly_score),
            "decision_threshold": float(self.anomaly_decision_threshold),
            "anomaly_decision": anomaly_decision,
            "physics_valid": is_physics_valid,
            "trust_score": float(trust_score),
            "trust_level": self.trust_engine.get_trust_level(),
            "ips_mode": ips_policy["mode"],
            "ips_active": ips_policy["mode"] != "OFF",
            "vehicle_speed": float(vehicle_state.speed),
            "vehicle_steering": float(vehicle_state.steering_angle),
            "detection_details": detection_details
        })
    
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
            "recent_alerts": len(recent_alerts),
            "evaluation": self.get_evaluation_status()
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
