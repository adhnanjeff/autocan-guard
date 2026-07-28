import threading
import time
from collections import deque
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
from mahalanobis_detector import AdaptiveMahalanobisDetector
from risk_index import compute_attack_severity_index, severity_grade
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

        # Layer 0: fast context-aware adaptive Mahalanobis pre-filter (runs
        # on every message, contributes to detection, never gates the
        # heavier ensemble above). Uses an adaptive threshold tau(t) driven by
        # trust and recent-state variability (paper Eq. 1).
        self.mahalanobis_detector = AdaptiveMahalanobisDetector()
        # Recent vehicle speeds -> normalized state variability sigma_s(t).
        self._recent_speeds = deque(maxlen=20)
        self._state_var_ref = 15.0  # km/h std that maps to sigma_s = 1.0

        # Latest Attack Severity Index (paper Eq. 3) - reporting only; does not
        # affect policy/IPS decisions (those remain trust-driven).
        self.last_asi = 0.0
        self.last_asi_grade = "LOW"

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
        # Calibration size: number of authenticated normal samples used to
        # establish the behavioral baseline. Configurable via CALIBRATION_SAMPLES
        # (default 200 - a far more defensible baseline than the previous 25).
        self.max_training_samples = int(os.environ.get("CALIBRATION_SAMPLES", "200"))
        
        # Startup grace period - ignore first N messages to avoid false positives during initialization
        self.startup_grace_period = 50  # Ignore first 50 messages
        self.messages_since_startup = 0
        
        # Security statistics
        self.verified_messages = 0
        self.rejected_messages = 0
        
        # Message log for UI
        self.message_log = []
        
        # Current vehicle state for contextual validation
        self.current_speed = 30.0
        self.current_steering = 0.0
        self.current_brake = 0.0

        # Detection threshold used for decision logging/evaluation (raised to reduce false positives)
        self.anomaly_decision_threshold = 0.5  # Raised from 0.3 to 0.5

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
            # Include all features expected by anomaly_detector
            snapshot[signal_name] = {
                "frequency": float(signal_features.get("frequency", 0.0)),
                "delta": float(signal_features.get("delta", 0.0)),
                "jitter": float(signal_features.get("jitter", 0.0)),
                "value_variance": float(signal_features.get("value_variance", 0.0)),
                "rate_of_change": float(signal_features.get("rate_of_change", 0.0)),
                "max_deviation": float(signal_features.get("max_deviation", 0.0)),
                "z_score": float(signal_features.get("z_score", 0.0)),
                "freq_deviation": float(signal_features.get("freq_deviation", 0.0)),
                "entropy": float(signal_features.get("entropy", 0.0)),
                "kurtosis": float(signal_features.get("kurtosis", 0.0)),
                "skewness": float(signal_features.get("skewness", 0.0)),
                "autocorr": float(signal_features.get("autocorr", 0.0)),
                "peak_density": float(signal_features.get("peak_density", 0.0)),
                "mad": float(signal_features.get("mad", 0.0)),
                "value_range": float(signal_features.get("value_range", 0.0)),
                "cv": float(signal_features.get("cv", 0.0))
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
                # Record the authentication failure so message trust (T_msg) and
                # the ASI HMAC term reflect it, even though the frame is dropped.
                self.trust_engine.record_auth_outcome(False)
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
            # FAIL CLOSED: no valid signature => the message is unauthenticated
            # (spoofed/injected) and is discarded, per the methodology
            # ("messages failing authentication are immediately discarded").
            # Authenticated-but-malicious traffic still reaches the ML/behavioral
            # layers below; only unsigned/forged frames are dropped here.
            self.rejected_messages += 1
            self.trust_engine.record_auth_outcome(False)
            log_entry = {
                "timestamp": time.strftime("%H:%M:%S"),
                "can_id": f"0x{can_id:03x}",
                "status": "REJECTED",
                "reason": "No valid signature - message discarded (fail-closed)",
                "device_id": f"ecu-{can_id:03x}"
            }
            self.message_log.append(log_entry)
            self.message_log = self.message_log[-50:]  # Keep last 50
            print(f"🚫 CRYPTO REJECTED: unauthenticated 0x{can_id:03x} (no valid signature)")
            return  # Drop unauthenticated message

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

        # Layer 0: context-aware adaptive Mahalanobis detection (paper Eq. 1).
        # The decision uses an adaptive threshold tau(t) = tau0 + a*T(t) +
        # b*sigma_s(t): T(t) is the current trust score and sigma_s(t) the
        # normalized recent-speed variability. Both raise the threshold, so
        # legitimate rash driving relaxes it and suppresses false alarms.
        self._recent_speeds.append(self.current_speed)
        if len(self._recent_speeds) >= 2:
            import numpy as _np
            state_variability = float(_np.std(self._recent_speeds)) / self._state_var_ref
        else:
            state_variability = 0.0
        state_variability = min(1.0, max(0.0, state_variability))

        mahalanobis_score = 0.0
        mahal_is_anomaly = False
        mahal_distance = 0.0
        mahal_threshold = 0.0
        if ml_feature_snapshot.get(signal_name):
            trust_now = self.trust_engine.get_trust_score()
            decision = self.mahalanobis_detector.adaptive_decision(
                signal_name, ml_feature_snapshot[signal_name], self.current_speed,
                trust=trust_now, state_variability=state_variability,
            )
            mahalanobis_score = decision["score"]
            mahal_is_anomaly = bool(decision["is_anomaly"])
            mahal_distance = decision["distance"]
            mahal_threshold = decision["threshold"]
            # Update the per-context baseline (poisoning-resistant: skips update
            # when the message already scores as anomalous).
            self.mahalanobis_detector.observe_and_update(
                signal_name, ml_feature_snapshot[signal_name], self.current_speed
            )

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
        
        # Increment message counter
        self.messages_since_startup += 1
        
        # Skip anomaly detection for UI controller messages (legitimate user input)
        if device_id and "ui-controller" in device_id:
            total_anomaly_score = 0.0  # UI commands are always trusted
            print(f"✅ UI Command trusted: {signal_name}={signal_value:.1f}")
        elif self.messages_since_startup <= self.startup_grace_period:
            # Grace period - allow system to stabilize, no anomaly detection
            total_anomaly_score = 0.0
            if self.messages_since_startup == self.startup_grace_period:
                print(f"✅ Startup grace period complete ({self.startup_grace_period} messages)")
        elif not self.training_mode:
            # Layer 1: ML Anomaly Score
            if ml_feature_snapshot:
                ml_anomaly_score = self.anomaly_detector.detect_anomaly(ml_feature_snapshot)
                if ml_anomaly_score > self.anomaly_decision_threshold:
                    detection_details.append(f"ML:{ml_anomaly_score:.2f}")
            
            # Layer 2: Control Energy Anomalies (relaxed thresholds for normal operation)
            if behavioral_features:
                # Check control energy features
                steering_energy = behavioral_features.get('steering_energy', 0.0)
                steering_jerk = behavioral_features.get('steering_jerk', 0.0)
                oscillation_rate = behavioral_features.get('oscillation_rate', 0.0)
                control_aggression = behavioral_features.get('control_aggression', 0.0)
                
                # Higher thresholds to reduce false positives during normal operation
                if steering_energy > 8.0:  # High energy (raised from 5.0)
                    control_anomaly_score += 0.3  # Reduced from 0.4
                    detection_details.append(f"Energy:{steering_energy:.1f}")
                if steering_jerk > 5.0:  # High jerk (raised from 3.0)
                    control_anomaly_score += 0.2  # Reduced from 0.3
                    detection_details.append(f"Jerk:{steering_jerk:.1f}")
                if oscillation_rate > 1.5:  # Oscillation (raised from 1.0)
                    control_anomaly_score += 0.3  # Reduced from 0.5
                    detection_details.append(f"Osc:{oscillation_rate:.1f}")
                if control_aggression > 8.0:  # Aggressive control (raised from 5.0)
                    control_anomaly_score += 0.2  # Reduced from 0.3
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
            
            # Adaptive Mahalanobis: independent OR-gate signal. Fires when the
            # Mahalanobis distance exceeds the adaptive threshold tau(t) (paper
            # Eq. 1). It can only raise the combined score, never suppress what
            # the heavier ensemble already found, so it cannot regress recall.
            if mahal_is_anomaly:
                total_anomaly_score = max(total_anomaly_score, mahalanobis_score)
                detection_details.append(
                    f"Mahalanobis:D={mahal_distance:.1f}>tau={mahal_threshold:.1f}"
                )

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
        # Real auth/temporal inputs (previously hardcoded to 1.0). This message
        # authenticated to reach here (auth_result=1.0); failures are folded in
        # via record_auth_outcome on the drop paths. Temporal trust reflects the
        # temporal rate-of-change analysis.
        temporal_trust = 1.0 - temporal_result['temporal_anomaly_score']
        self.trust_engine.update_trust(
            anomaly_score=total_anomaly_score,
            auth_result=1.0,
            temporal_score=temporal_trust,
        )

        # Update MongoDB trust patterns
        analytics_db.update_trust_pattern(self.vehicle_id, self.trust_engine.get_trust_score())

        # Get policy decision
        trust_score = self.trust_engine.get_trust_score()
        policy_decision = self.policy_engine.get_policy_decision(trust_score)

        # Attack Severity Index (paper Eq. 3): ASI = w1*D_M(norm) +
        # w2*(1-T_overall) + w3*H. D_M is normalized against its adaptive
        # threshold; H is the HMAC failure rate (1 - message trust). Reporting
        # only - it does not alter policy/IPS decisions.
        d_norm = min(1.0, mahal_distance / mahal_threshold) if mahal_threshold > 0 else 0.0
        hmac_failure_rate = 1.0 - self.trust_engine.get_component_trusts()["t_msg"]
        asi = compute_attack_severity_index(
            mahalanobis_norm=d_norm,
            trust_overall=trust_score,
            hmac_failure_rate=hmac_failure_rate,
        )
        self.last_asi = asi
        self.last_asi_grade = severity_grade(asi)
        
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
            "mahalanobis_score": float(mahalanobis_score),
            "mahalanobis_distance": float(mahal_distance),
            "mahalanobis_threshold": float(mahal_threshold),
            "attack_severity_index": float(self.last_asi),
            "asi_grade": self.last_asi_grade,
            "trust_components": self.trust_engine.get_component_trusts(),
            "prevention_action": policy_decision.get("prevention_action"),
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
            "asi": {
                "index": self.last_asi,
                "grade": self.last_asi_grade
            },
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
