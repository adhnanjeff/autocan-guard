from flask import Flask, jsonify, request
from flask_cors import CORS
import json
import time
from can_listener import CANListener
from can_generator import send_ecu_command, CANMessage, _mock_bus
from simple_kafka_consumer import SimpleKafkaConsumer
import os
import pickle
from security import MessageSigner

# OAuth imports
import jwt
import bcrypt
import sqlite3
from datetime import datetime, timedelta
from functools import wraps

app = Flask(__name__)
CORS(app, origins=["http://localhost:3000"], supports_credentials=True)

# JWT Configuration
JWT_SECRET = "autocan-guard-secret-key-2024"
JWT_ALGORITHM = "HS256"
JWT_EXPIRY_MINUTES = 30

class AuthManager:
    def __init__(self, db_path="vehicle_security.db"):
        self.db_path = db_path
        self._init_users_table()
        self._create_default_users()
    
    def _init_users_table(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'viewer'
            )
        ''')
        conn.commit()
        conn.close()
    
    def _create_default_users(self):
        users = [("admin", "admin123", "admin"), ("viewer", "viewer123", "viewer")]
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        for username, password, role in users:
            cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
            if not cursor.fetchone():
                password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
                cursor.execute("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)", (username, password_hash, role))
        conn.commit()
        conn.close()
    
    def authenticate(self, username, password):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT password_hash, role FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()
        conn.close()
        if not result:
            return None
        password_hash, role = result
        if bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8')):
            payload = {"sub": username, "role": role, "iss": "autocan-guard", "exp": datetime.utcnow() + timedelta(minutes=JWT_EXPIRY_MINUTES)}
            token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
            return {"token": token, "role": role}
        return None
    
    def verify_token(self, token):
        try:
            return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        except:
            return None

auth_manager = AuthManager()

def require_auth(required_role=None):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            auth_header = request.headers.get('Authorization')
            if not auth_header or not auth_header.startswith('Bearer '):
                return jsonify({"error": "Missing authorization"}), 401
            token = auth_header.split(' ')[1]
            payload = auth_manager.verify_token(token)
            if not payload:
                return jsonify({"error": "Invalid token"}), 401
            if required_role and payload.get('role') != required_role:
                return jsonify({"error": "Insufficient permissions"}), 403
            request.user = payload
            return f(*args, **kwargs)
        return decorated_function
    return decorator

@app.route('/auth/login', methods=['POST'])
def login():
    try:
        data = request.json
        print(f"Login attempt: {data.get('username')}")
        result = auth_manager.authenticate(data['username'], data['password'])
        if not result:
            print("Authentication failed")
            return jsonify({"error": "Invalid credentials"}), 401
        print("Authentication successful")
        return jsonify(result)
    except Exception as e:
        print(f"Login error: {e}")
        return jsonify({"error": "Login failed"}), 500

# Initialize systems
can_listener = None
kafka_consumer = None

def init_systems():
    global can_listener, kafka_consumer
    try:
        can_listener = CANListener()
        can_listener.start_listening()
        
        try:
            kafka_consumer = SimpleKafkaConsumer("A")
            kafka_consumer.start_consuming()
        except:
            kafka_consumer = None
            
    except Exception as e:
        print(f"System initialization error: {e}")



@app.route('/api/vehicle-state')
@require_auth()
def get_vehicle_state():
    try:
        if not can_listener:
            init_systems()
            
        state = can_listener.get_vehicle_state()
        security_status = can_listener.get_security_status()
        
        # Check Kafka connection
        kafka_connected = kafka_consumer and kafka_consumer.is_connected() if kafka_consumer else False
        message_count = kafka_consumer.get_message_count() if kafka_connected else can_listener.get_message_count()
        
        # Safe data extraction with defaults
        trust_data = security_status.get('trust', {})
        policy_data = security_status.get('policy', {})
        crypto_data = security_status.get('crypto', {})
        
        return jsonify({
            'vehicle_state': {
                'speed': float(getattr(state, 'speed', 0)),
                'x_position': float(getattr(state, 'x_position', 0)),
                'y_position': float(getattr(state, 'y_position', 0)),
                'heading': float(getattr(state, 'heading', 0)),
                'steering_angle': float(getattr(state, 'steering_angle', 0)),
                'brake_pressure': float(getattr(state, 'brake_pressure', 0))
            },
            'security_status': {
                'trust': {
                    'trust_score': float(trust_data.get('trust_score', 1.0)),
                    'trust_level': trust_data.get('trust_level', 'HIGH'),
                    'security_mode': trust_data.get('security_mode', 'CRYPTO_PLUS_ML'),
                    'ml_enabled': trust_data.get('ml_enabled', True)
                },
                'policy': {
                    'action': policy_data.get('action', 'ALLOW')
                },
                'crypto': {
                    'verified': crypto_data.get('verified', 0),
                    'rejected': crypto_data.get('rejected', 0),
                    'message_log': crypto_data.get('message_log', [])[-10:]
                },
                'ips': {
                    'enabled': security_status.get('ips', {}).get('enabled', False),
                    'mode': security_status.get('ips', {}).get('mode', 'OFF'),
                    'policy': security_status.get('ips', {}).get('policy', {})
                },
                'v2v': security_status.get('v2v', {
                    'publisher': {'kafka_available': False, 'last_alert': 0},
                    'consumer': {'security_mode': 'NORMAL', 'alerts_received': 0}
                }),
                'evaluation': security_status.get('evaluation', {})
            },
            'kafka_connected': kafka_connected,
            'message_count': message_count,
            'timestamp': time.time()
        })
    except Exception as e:
        print(f"API Error: {e}")
        # Return minimal working data on error
        return jsonify({
            'vehicle_state': {
                'speed': 30.0,
                'x_position': 0.0,
                'y_position': 0.0,
                'heading': 0.0,
                'steering_angle': 0.0,
                'brake_pressure': 0.0
            },
            'security_status': {
                'trust': {
                    'trust_score': 1.0,
                    'trust_level': 'HIGH',
                    'security_mode': 'CRYPTO_PLUS_ML',
                    'ml_enabled': True
                },
                'policy': {'action': 'ALLOW'},
                'crypto': {'verified': 0, 'rejected': 0, 'message_log': []},
                'evaluation': {}
            },
            'kafka_connected': False,
            'message_count': 0,
            'timestamp': time.time()
        })

@app.route('/api/send-can', methods=['POST'])
def send_can():
    try:
        data = request.json
        can_id = data['can_id']
        can_data = data['data']
        
        # Convert array to bytes if needed
        if isinstance(can_data, list):
            can_data = bytes(can_data)
        
        # Create CAN message
        msg = CANMessage(arbitration_id=can_id, data=can_data)
        
        # Create signer for UI controller
        ui_signer = MessageSigner("vehicleA-ui-controller")
        
        # Sign the message
        secure_msg = ui_signer.sign_message(can_id, can_data)
        
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
        
        # Send to the same mock bus that CAN listener is using
        if can_listener:
            can_listener.bus.send(msg)
        else:
            _mock_bus.send(msg)
        
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/ecu-command', methods=['POST'])
def ecu_command():
    try:
        data = request.json
        
        # Handle speed delta commands - update ECU target and re-enable control
        if 'speed_delta' in data and can_listener:
            current_speed = can_listener.get_vehicle_state().speed
            new_speed = current_speed + data['speed_delta']
            new_speed = max(0, min(new_speed, 120))  # Clamp to realistic limits
            
            # Send ECU command with explicit target_speed to re-enable ECU control
            send_ecu_command(speed_delta=0, target_speed=new_speed)
            
            print(f"🚗 Speed button pressed: {current_speed:.1f} + {data['speed_delta']:.1f} = {new_speed:.1f} km/h (ECU target updated)")
        else:
            # Use normal ECU command for other operations
            send_ecu_command(**data)
        
        # Also reset vehicle state if needed
        if data.get('reset') and can_listener:
            can_listener.vehicle_engine.reset_vehicle()
            
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/brake-command', methods=['POST'])
def brake_command():
    try:
        data = request.json
        brake_pressure = data.get('brake_pressure', 50.0)
        
        # When releasing brake, capture current vehicle speed as new ECU target
        if brake_pressure == 0 and can_listener:
            current_speed = can_listener.get_vehicle_state().speed
            send_ecu_command(brake_pressure=brake_pressure, target_speed=current_speed)
            print(f"🛑 Brake released - ECU target set to current speed: {current_speed:.1f} km/h")
        else:
            # Send brake command via ECU
            send_ecu_command(brake_pressure=brake_pressure)
        
        return jsonify({'success': True, 'brake_pressure': brake_pressure})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/toggle-ml', methods=['POST'])
@require_auth('admin')
def toggle_ml():
    try:
        data = request.json
        enabled = data['enabled']
        
        if can_listener:
            trust_engine = can_listener.trust_engine
            trust_engine.set_ml_enabled(enabled)
        
        return jsonify({'success': True, 'ml_enabled': enabled})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/analytics', methods=['GET'])
def get_analytics():
    try:
        from analytics_db import analytics_db
        
        vehicle_id = request.args.get('vehicle_id', 'vehicleA')
        hours = int(request.args.get('hours', 24))
        
        # Get security summary
        security_summary = analytics_db.get_security_summary(vehicle_id, hours)
        
        # Get attack trends
        attack_trends = analytics_db.get_attack_trends(7)
        
        return jsonify({
            'security_summary': security_summary,
            'attack_trends': attack_trends,
            'mongodb_connected': analytics_db.connected
        })
    except Exception as e:
        return jsonify({'error': str(e), 'mongodb_connected': False}), 500

@app.route('/api/toggle-ips', methods=['POST'])
@require_auth('admin')
def toggle_ips():
    try:
        data = request.json
        enabled = data['enabled']
        
        if can_listener:
            can_listener.ips_engine.set_enabled(enabled)
        
        return jsonify({'success': True, 'ips_enabled': enabled})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/evaluation/session', methods=['POST'])
@require_auth('admin')
def start_evaluation_session():
    try:
        if not can_listener:
            init_systems()

        data = request.json or {}
        session_name = data.get('session_name', 'session')
        log_path = can_listener.start_evaluation_session(session_name)
        return jsonify({
            'success': True,
            'log_path': log_path,
            'status': can_listener.get_evaluation_status()
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/evaluation/label', methods=['POST'])
@require_auth('admin')
def set_evaluation_label():
    try:
        if not can_listener:
            init_systems()

        data = request.json or {}
        label = int(data.get('label', 0))
        attack_tag = data.get('attack_tag', '')
        status = can_listener.set_evaluation_label(label, attack_tag)
        return jsonify({'success': True, 'status': status})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/evaluation/status', methods=['GET'])
@require_auth('admin')
def get_evaluation_status():
    try:
        if not can_listener:
            init_systems()
        return jsonify({'success': True, 'status': can_listener.get_evaluation_status()})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    print("🚀 Starting Flask API for Vehicle Digital Twin")
    init_systems()
    app.run(debug=False, port=5001, host='0.0.0.0')
