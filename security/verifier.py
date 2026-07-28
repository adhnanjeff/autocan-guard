import hmac
import hashlib
import time
from collections import defaultdict
from .keys import get_device_key, TIMESTAMP_WINDOW_MS

class MessageVerifier:
    def __init__(self):
        # Track last seen sequence per device
        self.last_sequences = defaultdict(int)
        # Track message timestamps for replay detection
        self.message_history = defaultdict(list)
        
    def verify_message(self, secure_msg):
        """Verify HMAC signature and message integrity"""
        try:
            # Extract fields
            device_id = secure_msg.get("device_id")
            timestamp = secure_msg.get("timestamp")
            sequence = secure_msg.get("sequence")
            can_id = secure_msg.get("can_id")
            payload = secure_msg.get("payload")
            signature = secure_msg.get("signature")
            
            # Presence check by None, not truthiness: can_id 0x000 and sequence 0
            # are valid values that must not be rejected as "missing".
            if any(field is None for field in
                   (device_id, timestamp, sequence, can_id, payload, signature)):
                return False, "Missing required fields"
            
            # 1. Device ID validation
            key = get_device_key(device_id)
            if not key:
                return False, f"Unknown device: {device_id}"
            
            # 2. Timestamp validation (replay protection)
            current_time = int(time.time() * 1000)
            if abs(current_time - timestamp) > TIMESTAMP_WINDOW_MS:
                return False, f"Message too old: {current_time - timestamp}ms"
            
            # 3. Sequence number validation - strictly monotonic (replay/reorder
            #    protection). A non-increasing sequence is rejected. The only
            #    permitted "reset" is a genuine fresh start (sequence <= 2, which
            #    the signer emits after its persisted sequence file is cleared);
            #    the earlier "accept anything >100 below last_seq" rule is removed
            #    because it let an attacker force a reset and replay old frames.
            #    The 5-second timestamp window above remains the outer bound.
            last_seq = self.last_sequences[device_id]
            if sequence <= last_seq:
                if last_seq > 0 and sequence <= 2:
                    # Device restarted with a fresh sequence file; accept and
                    # re-anchor. Timestamp freshness (checked above) still applies.
                    self.last_sequences[device_id] = sequence
                else:
                    return False, f"Sequence replay: {sequence} <= {last_seq}"
            
            # 4. HMAC signature validation
            message_data = f"{device_id}:{timestamp}:{sequence}:{can_id}:{payload}"
            expected_signature = hmac.new(
                key.encode('utf-8'),
                message_data.encode('utf-8'),
                hashlib.sha256
            ).hexdigest()
            
            if not hmac.compare_digest(signature, expected_signature):
                return False, "Invalid HMAC signature"
            
            # 5. Update tracking
            self.last_sequences[device_id] = sequence
            self.message_history[device_id].append(timestamp)
            
            # Clean old timestamps
            cutoff = current_time - TIMESTAMP_WINDOW_MS
            self.message_history[device_id] = [
                ts for ts in self.message_history[device_id] if ts > cutoff
            ]
            
            return True, "Valid message"
            
        except Exception as e:
            return False, f"Verification error: {str(e)}"
    
    def get_device_stats(self):
        """Get verification statistics"""
        return {
            "tracked_devices": len(self.last_sequences),
            "last_sequences": dict(self.last_sequences),
            "message_counts": {
                device: len(timestamps) 
                for device, timestamps in self.message_history.items()
            }
        }