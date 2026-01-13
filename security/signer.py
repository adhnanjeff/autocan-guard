import hmac
import hashlib
import time
import json
import os
from .keys import get_device_key, CURRENT_KEY_VERSION

class MessageSigner:
    def __init__(self, device_id):
        self.device_id = device_id
        self.sequence_file = f"/tmp/{device_id}_sequence.txt"
        self.key = get_device_key(device_id)
        
        if not self.key:
            raise ValueError(f"No key found for device: {device_id}")
        
        # Load or initialize sequence
        self.sequence = self._load_sequence()
    
    def _load_sequence(self):
        """Load sequence from file or start fresh"""
        try:
            if os.path.exists(self.sequence_file):
                with open(self.sequence_file, 'r') as f:
                    return int(f.read().strip())
        except:
            pass
        return 1  # Start from 1 for clean sequences
    
    def _save_sequence(self):
        """Save sequence to file"""
        try:
            with open(self.sequence_file, 'w') as f:
                f.write(str(self.sequence))
        except:
            pass
    
    def sign_message(self, can_id, payload):
        """Sign CAN message with HMAC"""
        # Increment sequence
        self.sequence += 1
        self._save_sequence()
        
        # Create secure message structure
        timestamp = int(time.time() * 1000)  # milliseconds
        
        secure_msg = {
            "device_id": self.device_id,
            "timestamp": timestamp,
            "sequence": self.sequence,
            "key_version": CURRENT_KEY_VERSION,
            "can_id": can_id,
            "payload": payload.hex() if isinstance(payload, bytes) else str(payload)
        }
        
        # Create signature over all fields
        message_data = f"{self.device_id}:{timestamp}:{self.sequence}:{can_id}:{secure_msg['payload']}"
        signature = hmac.new(
            self.key.encode('utf-8'),
            message_data.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
        
        secure_msg["signature"] = signature
        
        return secure_msg
    
    def get_sequence(self):
        """Get current sequence number"""
        return self.sequence