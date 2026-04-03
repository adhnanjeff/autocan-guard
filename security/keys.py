# Device keys and identities
DEVICE_KEYS = {
    "vehicleA-steering-ecu": "steering_key_v1_secret_2024",
    "vehicleA-speed-ecu": "speed_key_v1_secret_2024", 
    "vehicleA-brake-ecu": "brake_key_v1_secret_2024",
    "vehicleA-ui-controller": "ui_key_v1_secret_2024",
    "vehicleA-v2v": "v2v_key_v1_secret_2024",
    "vehicleB-v2v": "v2v_key_v1_secret_2024",
    "attacker-unknown": "fake_key_attempt_2024"  # Attackers won't have real keys
}

# Key version for rotation
CURRENT_KEY_VERSION = 1
PREVIOUS_KEY_VERSION = 0  # For backward compatibility

# Timing constraints
TIMESTAMP_WINDOW_MS = 5000  # 5 second window for replay protection
SEQUENCE_RESET_THRESHOLD = 1000000  # Reset sequence after this many messages

def get_device_key(device_id, key_version=CURRENT_KEY_VERSION):
    """Get cryptographic key for device"""
    if device_id in DEVICE_KEYS:
        return DEVICE_KEYS[device_id]
    return None

def is_valid_device(device_id):
    """Check if device ID is authorized"""
    return device_id in DEVICE_KEYS